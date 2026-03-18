//! P2P networking loop and per-peer stream handling.
//!
//! Extracted from main.rs per connection-lifecycle.md.
//! Owns the ConnectionManager, Governor, and all protocol dispatch.
//!
//! Spec: seed-drill/specs/connection-lifecycle.md, network-protocol.md §2-§5

use actix_web::web;
use cordelia_core::NodeId;

/// Governor events sent from spawned tasks back to the p2p_loop.
pub enum GovEvent {
    ItemsDelivered(NodeId, u64),
}

/// Open a bidirectional QUIC stream with a standard 10s timeout.
async fn open_bi(
    conn: &quinn::Connection,
) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
    match tokio::time::timeout(cordelia_network::codec::STREAM_TIMEOUT, conn.open_bi()).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(format!("open_bi failed: {e}")),
        Err(_) => Err("open_bi timed out".into()),
    }
}

/// Store a network Item into the local SQLite database.
/// Shared between push receive and pull-sync paths (deduplicated per connection-lifecycle.md).
pub fn store_item(
    db: &rusqlite::Connection,
    item: &cordelia_network::messages::Item,
    node_role: &str,
) -> Result<bool, ()> {
    if !cordelia_network::item_sync::verify_content_hash(item) {
        tracing::warn!(item = %item.item_id, "content hash mismatch");
        return Err(());
    }

    // Relay: ensure channel row exists (no FK violation, BV-21)
    if node_role == "relay" {
        let _ = db.execute(
            "INSERT OR IGNORE INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at) VALUES (?1, 'named', 'realtime', 'open', X'00', datetime('now'), datetime('now'))",
            rusqlite::params![item.channel_id],
        );
    }

    let author: [u8; 32] = match item.author_id.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return Err(()),
    };
    let hash: [u8; 32] = match item.content_hash.as_slice().try_into() {
        Ok(h) => h,
        Err(_) => return Err(()),
    };
    let sig: [u8; 64] = match item.signature.as_slice().try_into() {
        Ok(s) => s,
        Err(_) => return Err(()),
    };

    let new_item = cordelia_storage::items::NewItem {
        item_id: &item.item_id,
        channel_id: &item.channel_id,
        author_id: &author,
        item_type: &item.item_type,
        published_at: &item.published_at,
        parent_id: item.parent_id.as_deref(),
        key_version: item.key_version as i64,
        content_hash: &hash,
        signature: &sig,
        encrypted_blob: &item.encrypted_blob,
    };

    match cordelia_storage::items::insert_item(db, &new_item) {
        Ok(inserted) => Ok(inserted),
        Err(e) => {
            tracing::debug!(item = %item.item_id, error = %e, "store failed");
            Err(())
        }
    }
}

/// Canonical post-connection sequence (connection-lifecycle.md §1.2).
/// ALL connection paths MUST call this after successful connection.
#[allow(clippy::too_many_arguments)]
pub fn post_connect(
    node_id: &NodeId,
    conn_mgr: &cordelia_network::connection::ConnectionManager,
    governor: &mut cordelia_network::governor::Governor,
    shared_peers: &std::sync::Arc<std::sync::RwLock<Vec<cordelia_network::messages::PeerAddress>>>,
    state: &web::Data<cordelia_api::state::AppState>,
    node_role: &str,
    relay_push_tx: &tokio::sync::mpsc::UnboundedSender<cordelia_api::state::PushItem>,
    delivery_tx: &tokio::sync::mpsc::UnboundedSender<(NodeId, u64)>,
    peer_rates: &std::sync::Arc<
        std::sync::Mutex<
            std::collections::HashMap<NodeId, cordelia_network::rate_limit::PeerRateLimiter>,
        >,
    >,
    peer_states: &std::sync::Arc<std::sync::RwLock<std::collections::HashMap<NodeId, u8>>>,
) {
    // Step 1: Extract peer roles from handshake
    let is_relay = conn_mgr
        .get_peer(node_id)
        .map(|pc| {
            let roles = &pc.handshake.peer_roles;
            tracing::info!(peer = %node_id, roles = ?roles, "post_connect: checking peer roles");
            roles.contains(&"relay".to_string())
        })
        .unwrap_or_else(|| {
            tracing::warn!(peer = %node_id, "post_connect: get_peer returned None");
            false
        });

    // Step 2: Add to governor
    governor.add_peer(node_id.clone(), vec![], vec![]);

    // Step 3: Mark relay role
    if is_relay {
        governor.set_peer_relay(node_id, true);
        tracing::info!(peer = %node_id, "peer identified as relay");
    }

    // Step 4: Mark connected (triggers Hot/Warm promotion)
    governor.mark_connected(node_id);

    // Step 5: Update shared peer list
    if let Ok(mut peers) = shared_peers.write() {
        *peers = conn_mgr.known_peer_addresses();
    }

    // Step 6: Update counters
    let (hot, warm, _, _) = governor.counts();
    state
        .peers_hot
        .store(hot as u64, std::sync::atomic::Ordering::Relaxed);
    state
        .peers_warm
        .store(warm as u64, std::sync::atomic::Ordering::Relaxed);

    // Step 6b: Sync peer states for protocol gating (§2.1)
    // Without this, push handler rejects items from peers promoted during
    // bootstrap/accept (before first governor tick syncs peer_states).
    if let Ok(mut states) = peer_states.write() {
        for peer in governor.all_peers() {
            let state_byte = match peer.state {
                cordelia_network::governor::PeerState::Cold => 0u8,
                cordelia_network::governor::PeerState::Warm => 1,
                cordelia_network::governor::PeerState::Hot => 2,
                cordelia_network::governor::PeerState::Banned { .. } => 0,
            };
            states.insert(peer.node_id.clone(), state_byte);
        }
    }

    // Step 7: Spawn stream handler
    if let Some(conn) = conn_mgr.get_connection(node_id) {
        let conn = conn.clone();
        let peer_id = node_id.clone();
        let db_state = state.clone();
        let peers_ref = shared_peers.clone();
        let role = node_role.to_string();
        let ptx = relay_push_tx.clone();
        let dtx = delivery_tx.clone();
        let rates = peer_rates.clone();
        let states = peer_states.clone();
        tokio::spawn(async move {
            handle_peer_streams(
                conn, peer_id, db_state, peers_ref, role, ptx, dtx, rates, states,
            )
            .await;
        });
    }
}

/// Background task that accepts incoming QUIC connections, handles
/// outbound item pushes, and manages peer lifecycle.
pub async fn p2p_loop(
    mut conn_mgr: cordelia_network::connection::ConnectionManager,
    state: web::Data<cordelia_api::state::AppState>,
    mut push_rx: tokio::sync::mpsc::UnboundedReceiver<cordelia_api::state::PushItem>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    allow_private_addresses: bool,
    node_role: String,
    gov_config: cordelia_core::config::GovernorConfig,
) {
    tracing::info!(role = %node_role, "P2P loop started (accept + push + peer-sharing)");

    // Create a push sender for handle_peer_streams (relay re-push)
    let relay_push_tx: tokio::sync::mpsc::UnboundedSender<cordelia_api::state::PushItem> = state
        .push_tx
        .as_ref()
        .expect("push_tx must be set when P2P is running")
        .clone();

    // Shared peer list
    let shared_peers: std::sync::Arc<
        std::sync::RwLock<Vec<cordelia_network::messages::PeerAddress>>,
    > = std::sync::Arc::new(std::sync::RwLock::new(conn_mgr.known_peer_addresses()));

    let our_node_id = NodeId(state.identity.public_key());

    // Governor
    let gov_targets = cordelia_network::governor::GovernorTargets::from_config(&gov_config);
    let gov_timeouts = cordelia_network::governor::GovernorTimeouts::from_config(&gov_config);
    let mut governor =
        cordelia_network::governor::Governor::new(gov_targets, vec![]).with_timeouts(gov_timeouts);

    // Connection tracker (§3.1): per-IP, per-subnet, global limits
    let mut conn_tracker = cordelia_network::rate_limit::ConnectionTracker::new();

    // Per-peer rate limiters, shared with handle_peer_streams tasks
    let peer_rates: std::sync::Arc<
        std::sync::Mutex<
            std::collections::HashMap<NodeId, cordelia_network::rate_limit::PeerRateLimiter>,
        >,
    > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    // Shared peer state map for protocol gating (connection-lifecycle.md §2.2 Option A).
    // Governor tick updates this; handle_peer_streams reads it to gate protocols by state.
    // 0=Cold, 1=Warm, 2=Hot
    let peer_states: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<NodeId, u8>>> =
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));

    // Delivery feedback channel
    let (delivery_tx, mut delivery_rx) = tokio::sync::mpsc::unbounded_channel::<(NodeId, u64)>();

    // Register bootstrap peers using canonical sequence
    for peer_id in conn_mgr.connected_peers() {
        post_connect(
            &peer_id,
            &conn_mgr,
            &mut governor,
            &shared_peers,
            &state,
            &node_role,
            &relay_push_tx,
            &delivery_tx,
            &peer_rates,
            &peer_states,
        );
    }
    governor.tick();

    // P2P loop timers. Peer-share and sync run at their protocol intervals
    // (from protocol.rs). Governor tick uses the config value.
    const P2P_PEER_SHARE_CHECK_SECS: u64 = 5; // How often to check for connect candidates
    const P2P_SYNC_CHECK_SECS: u64 = 10;

    // Peer-share connect timeout: short ceiling for speculative connects.
    // Typical connects complete in <100ms; 2s handles slow cross-region links.
    // Sequential (not spawned), so only 1 per cycle to keep the select loop
    // responsive for inbound connections and governor ticks.
    const P2P_PEER_SHARE_CONNECT_TIMEOUT_SECS: u64 = 2;
    let p2p_gov_tick_secs = gov_config.tick_interval_secs as u64;

    let mut peer_share_interval =
        tokio::time::interval(std::time::Duration::from_secs(P2P_PEER_SHARE_CHECK_SECS));
    peer_share_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    peer_share_interval.tick().await;

    let mut sync_interval =
        tokio::time::interval(std::time::Duration::from_secs(P2P_SYNC_CHECK_SECS));
    sync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    sync_interval.tick().await;

    let mut gov_interval = tokio::time::interval(std::time::Duration::from_secs(p2p_gov_tick_secs));
    gov_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    gov_interval.tick().await;

    // Governor event channel
    let (gov_tx, mut gov_rx) = tokio::sync::mpsc::unbounded_channel::<GovEvent>();

    // Push retry queue: sender-side retry with exponential backoff.
    // Spawned push tasks report failures via retry_fail_tx. The select loop
    // drains failures into retry_queue and re-attempts on a 2s timer.
    // Max 3 retries (2s, 4s, 8s backoff). After that, pull-sync is the safety net.
    // Silent drop on receiver side stays -- no NACK (DoS amplification vector).
    const PUSH_RETRY_MAX: u8 = 3;
    struct RetryEntry {
        item: cordelia_network::messages::Item,
        peer_id: NodeId,
        channel_id: String,
        exclude_peer: Option<NodeId>,
        attempt: u8,
        retry_at: tokio::time::Instant,
    }
    let (retry_fail_tx, mut retry_fail_rx) =
        tokio::sync::mpsc::unbounded_channel::<RetryEntry>();
    let mut retry_queue: Vec<RetryEntry> = Vec::new();
    let mut retry_interval =
        tokio::time::interval(std::time::Duration::from_secs(2));
    retry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    retry_interval.tick().await;

    // Peer-share has two independent concerns:
    // (a) Request addresses from peers (subject to per-peer cooldown for rate limits)
    // (b) Connect to discovered candidates (every cycle from cached addresses)
    //
    // Address cache persists between cycles so connects continue even when
    // all peers are on cooldown (critical during early mesh formation with few peers).
    let mut peer_share_rotation: usize = 0;
    let mut peer_share_target_idx: usize = 0;
    let mut peer_share_last_request: std::collections::HashMap<NodeId, std::time::Instant> =
        std::collections::HashMap::new();
    let peer_share_cooldown = std::time::Duration::from_secs(
        cordelia_core::protocol::RATE_WINDOW_SECS
            / cordelia_core::protocol::PEER_SHARES_PER_PEER_PER_MINUTE as u64,
    );
    let mut peer_share_cache: Vec<cordelia_network::messages::PeerAddress> = Vec::new();

    loop {
        tokio::select! {
            // ── Accept incoming connection ─────────────────────────────
            result = conn_mgr.accept_incoming() => {
                match result {
                    Ok(node_id) => {
                        // Connection limit check (§3.1) -- post-handshake for now
                        let remote_ip = conn_mgr.get_connection(&node_id)
                            .map(|c| c.remote_address().ip());
                        if let Some(ip) = remote_ip {
                            if !conn_tracker.would_allow(ip) {
                                tracing::warn!(peer = %node_id, ip = %ip, "rejecting: connection limit exceeded");
                                conn_mgr.disconnect(&node_id);
                                continue;
                            }
                            conn_tracker.add(ip);
                        }

                        let count = conn_mgr.connection_count() as u64;
                        state.peers_hot.store(count, std::sync::atomic::Ordering::Relaxed);
                        tracing::info!(peer = %node_id, peers = count, "accepted inbound connection");
                        post_connect(
                            &node_id, &conn_mgr, &mut governor, &shared_peers,
                            &state, &node_role, &relay_push_tx, &delivery_tx, &peer_rates, &peer_states,
                        );
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "inbound connection failed");
                    }
                }
            }

            // ── Peer-sharing ──────────────────────────────────────────
            // (a) Request addresses from a peer whose cooldown has expired
            //     and merge into the persistent cache.
            // (b) Try to connect to 1 candidate from the cache (every cycle,
            //     even when all peers are on cooldown).
            _ = peer_share_interval.tick() => {
                let peers = conn_mgr.connected_peers();
                if peers.is_empty() { continue; }

                // (a) Discovery: find a peer whose cooldown has expired
                let now = std::time::Instant::now();
                let mut target = None;
                for offset in 0..peers.len() {
                    let idx = (peer_share_target_idx + offset) % peers.len();
                    let candidate = &peers[idx];
                    let elapsed = peer_share_last_request
                        .get(candidate)
                        .map(|t| now.duration_since(*t))
                        .unwrap_or(peer_share_cooldown);
                    if elapsed >= peer_share_cooldown {
                        target = Some(candidate.clone());
                        peer_share_target_idx = idx + 1;
                        break;
                    }
                }
                if let Some(target) = target {
                    peer_share_last_request.insert(target.clone(), now);
                    if let Some(conn) = conn_mgr.get_connection(&target) {
                        let conn = conn.clone();
                        if let Ok((mut send, mut recv)) = open_bi(&conn).await {
                            let mut stream = tokio::io::join(&mut recv, &mut send);
                            if let Ok(discovered) = cordelia_network::peer_sharing::request_peers(
                                &mut stream, cordelia_core::protocol::DEFAULT_MAX_PEERS_SHARE,
                            ).await {
                                let own_addr = conn_mgr.local_addr().ok();
                                let valid = if allow_private_addresses {
                                    discovered
                                } else {
                                    cordelia_network::peer_sharing::filter_valid_addresses(&discovered, own_addr.as_ref())
                                };
                                // Merge into cache (deduplicate by node_id)
                                for pa in valid {
                                    let nid = NodeId(pa.node_id.as_slice().try_into().unwrap_or([0u8; 32]));
                                    if nid != our_node_id && !peer_share_cache.iter().any(|c| c.node_id == pa.node_id) {
                                        peer_share_cache.push(pa);
                                    }
                                }
                            }
                        }
                    }
                }

                // (b) Connect: pick 1 candidate from cache and connect (every cycle).
                // Sequential connect blocks the select loop, so we limit to 1
                // per cycle to keep inbound processing and governor ticks responsive.
                let candidates: Vec<_> = peer_share_cache.iter()
                    .filter(|pa| {
                        let nid = NodeId(pa.node_id.as_slice().try_into().unwrap_or([0u8; 32]));
                        nid != our_node_id && !conn_mgr.is_connected(&nid)
                    })
                    .collect();
                if !candidates.is_empty() {
                    let idx = peer_share_rotation % candidates.len();
                    peer_share_rotation = peer_share_rotation.wrapping_add(1);
                    let peer_addr = candidates[idx];
                    if let Some(addr_str) = peer_addr.addrs.first() {
                        if let Ok(addr) = addr_str.parse() {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(P2P_PEER_SHARE_CONNECT_TIMEOUT_SECS),
                                conn_mgr.connect_to(addr),
                            ).await {
                                Ok(Ok(new_id)) => {
                                    tracing::info!(peer = %new_id, peers = conn_mgr.connection_count(), "connected via peer-sharing");
                                    post_connect(
                                        &new_id, &conn_mgr, &mut governor, &shared_peers,
                                        &state, &node_role, &relay_push_tx, &delivery_tx, &peer_rates, &peer_states,
                                    );
                                }
                                Ok(Err(e)) => { tracing::debug!(addr = %addr_str, error = %e, "peer-share connect failed"); }
                                Err(_) => { tracing::debug!(addr = %addr_str, "peer-share connect timed out ({}s)", P2P_PEER_SHARE_CONNECT_TIMEOUT_SECS); }
                            }
                        }
                    }
                }
            }

            // ── Push items to hot peers ───────────────────────────────
            Some(push_item) = push_rx.recv() => {
                let item = cordelia_network::messages::Item {
                    item_id: push_item.item_id.clone(),
                    channel_id: push_item.channel_id.clone(),
                    item_type: push_item.item_type,
                    encrypted_blob: push_item.encrypted_blob,
                    content_hash: push_item.content_hash,
                    content_length: 0,
                    author_id: push_item.author_id,
                    signature: push_item.signature,
                    key_version: push_item.key_version,
                    published_at: push_item.published_at,
                    is_tombstone: push_item.is_tombstone,
                    parent_id: push_item.parent_id,
                };

                let exclude = push_item.exclude_peer;
                // Gate 1: push only to peers carrying this channel (§7.1)
                let all_peers = governor.hot_peers_for_channel(&push_item.channel_id);
                let mut push_count = 0u32;
                let mut skip_count = 0u32;
                for peer_id in &all_peers {
                    if exclude.as_ref() == Some(peer_id) {
                        skip_count += 1;
                        continue;
                    }
                    if let Some(conn) = conn_mgr.get_connection(peer_id) {
                        let conn = conn.clone();
                        let items = vec![item.clone()];
                        let pid = peer_id.clone();
                        push_count += 1;
                        let iid = push_item.item_id.clone();
                        let rtx = retry_fail_tx.clone();
                        let retry_item = item.clone();
                        let retry_ch = push_item.channel_id.clone();
                        let retry_ex = exclude.clone();
                        tracing::debug!(peer = %pid, item = %iid, "spawning push task");
                        tokio::spawn(async move {
                            let (mut send, mut recv) = match open_bi(&conn).await {
                                Ok(s) => s,
                                Err(e) => {
                                    tracing::debug!(peer = %pid, error = %e, "push open_bi, queuing retry");
                                    let _ = rtx.send(RetryEntry {
                                        item: retry_item, peer_id: pid, channel_id: retry_ch,
                                        exclude_peer: retry_ex, attempt: 0,
                                        retry_at: tokio::time::Instant::now() + std::time::Duration::from_secs(2),
                                    });
                                    return;
                                }
                            };
                            let mut stream = tokio::io::join(&mut recv, &mut send);
                            match cordelia_network::item_sync::send_push(&mut stream, &items).await {
                                Ok(ack) => tracing::debug!(peer = %pid, stored = ack.stored, "push delivered"),
                                Err(e) => {
                                    tracing::debug!(peer = %pid, error = %e, "push send failed, queuing retry");
                                    let _ = rtx.send(RetryEntry {
                                        item: retry_item, peer_id: pid, channel_id: retry_ch,
                                        exclude_peer: retry_ex, attempt: 0,
                                        retry_at: tokio::time::Instant::now() + std::time::Duration::from_secs(2),
                                    });
                                }
                            }
                        });
                    } else {
                        tracing::warn!(peer = %peer_id, "push skipped: get_connection returned None");
                    }
                }
                tracing::debug!(
                    channel = %push_item.channel_id,
                    item = %push_item.item_id,
                    total_peers = all_peers.len(),
                    pushed = push_count,
                    excluded = skip_count,
                    "item pushed to peers"
                );
            }

            // ── Push retry processing ─────────────────────────────────
            _ = retry_interval.tick() => {
                // Drain failure reports into retry queue
                while let Ok(entry) = retry_fail_rx.try_recv() {
                    retry_queue.push(entry);
                }
                if retry_queue.is_empty() { continue; }

                let now = tokio::time::Instant::now();
                let mut remaining = Vec::new();
                for entry in retry_queue.drain(..) {
                    if entry.retry_at > now {
                        remaining.push(entry);
                        continue;
                    }
                    if entry.attempt >= PUSH_RETRY_MAX {
                        tracing::warn!(
                            peer = %entry.peer_id, channel = %entry.channel_id,
                            attempts = entry.attempt, "push retry exhausted, relying on pull-sync"
                        );
                        continue;
                    }
                    // Only retry if peer is still hot
                    if !governor.hot_peers().contains(&entry.peer_id) {
                        tracing::debug!(
                            peer = %entry.peer_id, "push retry skipped: peer no longer hot"
                        );
                        continue;
                    }
                    if let Some(conn) = conn_mgr.get_connection(&entry.peer_id) {
                        let conn = conn.clone();
                        let items = vec![entry.item.clone()];
                        let pid = entry.peer_id.clone();
                        let attempt = entry.attempt + 1;
                        let rtx = retry_fail_tx.clone();
                        let retry_item = entry.item;
                        let retry_ch = entry.channel_id;
                        let retry_ex = entry.exclude_peer;
                        tracing::debug!(peer = %pid, attempt, "push retry");
                        tokio::spawn(async move {
                            let (mut send, mut recv) = match open_bi(&conn).await {
                                Ok(s) => s,
                                Err(e) => {
                                    tracing::debug!(peer = %pid, attempt, error = %e, "push retry open_bi failed");
                                    let backoff = std::time::Duration::from_secs(2u64.pow(attempt as u32));
                                    let _ = rtx.send(RetryEntry {
                                        item: retry_item, peer_id: pid, channel_id: retry_ch,
                                        exclude_peer: retry_ex, attempt,
                                        retry_at: tokio::time::Instant::now() + backoff,
                                    });
                                    return;
                                }
                            };
                            let mut stream = tokio::io::join(&mut recv, &mut send);
                            match cordelia_network::item_sync::send_push(&mut stream, &items).await {
                                Ok(ack) => tracing::debug!(peer = %pid, attempt, stored = ack.stored, "push retry delivered"),
                                Err(e) => {
                                    tracing::debug!(peer = %pid, attempt, error = %e, "push retry failed");
                                    let backoff = std::time::Duration::from_secs(2u64.pow(attempt as u32));
                                    let _ = rtx.send(RetryEntry {
                                        item: retry_item, peer_id: pid, channel_id: retry_ch,
                                        exclude_peer: retry_ex, attempt,
                                        retry_at: tokio::time::Instant::now() + backoff,
                                    });
                                }
                            }
                        });
                    }
                }
                retry_queue = remaining;
            }

            // ── Pull-sync from hot peers ──────────────────────────────
            _ = sync_interval.tick() => {
                if node_role == "bootnode" { continue; }
                let peers = conn_mgr.connected_peers();
                if peers.is_empty() { continue; }
                let channels: Vec<String> = {
                    let db = match state.db.lock() {
                        Ok(db) => db,
                        Err(_) => continue,
                    };
                    let pk = state.identity.public_key();
                    cordelia_storage::channels::list_for_entity(&db, &pk)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|c| c.channel_id)
                        .collect()
                };
                if channels.is_empty() { continue; }

                let hot = governor.hot_peers();
                tracing::debug!(hot_peers = hot.len(), total_peers = peers.len(), channels = channels.len(), "pull-sync cycle");
                for target in &hot {
                    if let Some(conn) = conn_mgr.get_connection(target) {
                    let conn = conn.clone();
                    let sync_state = state.clone();
                    let sync_channels = channels.clone();
                    let target = target.clone();
                    let gtx = gov_tx.clone();
                    let role = node_role.clone();
                    tracing::debug!(peer = %target, channels = sync_channels.len(), "pull-sync starting");
                    tokio::spawn(async move {
                        for ch_id in &sync_channels {
                            let (mut send, mut recv) = match open_bi(&conn).await {
                                Ok(s) => s,
                                Err(e) => { tracing::debug!(peer = %target, channel = %ch_id, error = %e, "sync open_bi"); break; }
                            };
                            let mut stream = tokio::io::join(&mut recv, &mut send);
                            tracing::debug!(peer = %target, channel = %ch_id, "sync request sent");
                            let resp = match cordelia_network::item_sync::send_sync_request(&mut stream, ch_id, None, cordelia_core::protocol::DEFAULT_SYNC_LIMIT).await {
                                Ok(r) => r,
                                Err(e) => { tracing::debug!(peer = %target, channel = %ch_id, error = %e, "sync request failed"); continue; }
                            };
                            tracing::debug!(peer = %target, channel = %ch_id, headers = resp.items.len(), "sync response received");
                            if resp.items.is_empty() { continue; }

                            let known = {
                                let db = match sync_state.db.lock() {
                                    Ok(db) => db,
                                    Err(_) => continue,
                                };
                                let stored = cordelia_storage::items::query_listen(&db, ch_id, None, cordelia_core::protocol::MAX_LISTEN_LIMIT).unwrap_or_default();
                                stored.into_iter()
                                    .map(|si| (si.item_id, (si.content_hash, si.published_at)))
                                    .collect::<std::collections::HashMap<_, _>>()
                            };
                            let fetch_ids = cordelia_network::item_sync::compute_fetch_list(&resp.items, &known);
                            if fetch_ids.is_empty() { continue; }

                            if let Err(e) = cordelia_network::item_sync::send_fetch_request(&mut send, &fetch_ids).await {
                                tracing::debug!(error = %e, "fetch request failed");
                                continue;
                            }
                            let items = match cordelia_network::item_sync::read_fetch_response(&mut recv).await {
                                Ok(items) => items,
                                Err(e) => { tracing::debug!(peer = %target, error = %e, "fetch response failed"); continue; }
                            };

                            let mut stored_count = 0u32;
                            {
                                let db = match sync_state.db.lock() {
                                    Ok(db) => db,
                                    Err(_) => continue,
                                };
                                for item in &items {
                                    if let Ok(true) = store_item(&db, item, &role) {
                                        stored_count += 1;
                                    }
                                }
                            }
                            if stored_count > 0 {
                                tracing::info!(channel = %ch_id, fetched = fetch_ids.len(), stored = stored_count, "pull-sync complete");
                                let _ = gtx.send(GovEvent::ItemsDelivered(target.clone(), stored_count as u64));
                            }
                        }
                    });
                    }
                }
            }

            // ── Governor tick ─────────────────────────────────────────
            _ = gov_interval.tick() => {
                // Drain event channels
                while let Ok(GovEvent::ItemsDelivered(peer_id, count)) = gov_rx.try_recv() {
                    governor.record_items_delivered(&peer_id, count);
                }
                while let Ok((peer_id, count)) = delivery_rx.try_recv() {
                    governor.record_items_delivered(&peer_id, count);
                    // If we're a relay, items delivered to us are items that peer relayed
                    if node_role == "relay" {
                        governor.record_items_relayed(&peer_id, count);
                    }
                }
                // Sync with connection manager
                let connected = conn_mgr.connected_peers();
                for peer_id in &connected {
                    governor.record_activity(peer_id, None);
                }
                let gov_active: Vec<_> = governor.hot_peers();
                for peer_id in &gov_active {
                    if !connected.contains(peer_id) {
                        governor.mark_disconnected(peer_id);
                    }
                }
                let (hot, warm, _cold, _banned) = governor.counts();
                state.peers_hot.store(hot as u64, std::sync::atomic::Ordering::Relaxed);
                state.peers_warm.store(warm as u64, std::sync::atomic::Ordering::Relaxed);

                let actions = governor.tick();
                if !actions.transitions.is_empty() {
                    for (node_id, from, to) in &actions.transitions {
                        tracing::info!(peer = %node_id, from, to, "gov: state transition");
                    }
                }
                for node_id in &actions.disconnect {
                    conn_mgr.disconnect(node_id);
                }
                for node_id in &actions.connect {
                    if let Some(peer) = governor.peer_info(node_id)
                        && let Some(addr_str) = peer.addrs.first()
                            && let Ok(addr) = addr_str.parse() {
                                match tokio::time::timeout(
                                    cordelia_network::codec::STREAM_TIMEOUT,
                                    conn_mgr.connect_to(addr),
                                ).await {
                                    Ok(Ok(new_id)) => {
                                        tracing::info!(peer = %new_id, "gov: connected (promotion)");
                                        post_connect(
                                            &new_id, &conn_mgr, &mut governor, &shared_peers,
                                            &state, &node_role, &relay_push_tx, &delivery_tx, &peer_rates, &peer_states,
                                        );
                                    }
                                    Ok(Err(e)) => {
                                        governor.mark_dial_failed(node_id);
                                        tracing::debug!(peer = %node_id, error = %e, "gov: connect failed");
                                    }
                                    Err(_) => {
                                        governor.mark_dial_failed(node_id);
                                        tracing::debug!(peer = %node_id, "gov: connect timed out (10s)");
                                    }
                                }
                            }
                }
                let (hot, warm, cold, banned) = governor.counts();
                state.peers_hot.store(hot as u64, std::sync::atomic::Ordering::Relaxed);

                // Sync peer states for protocol gating (§2.2)
                if let Ok(mut states) = peer_states.write() {
                    states.clear();
                    for peer in governor.all_peers() {
                        let state_byte = match peer.state {
                            cordelia_network::governor::PeerState::Cold => 0u8,
                            cordelia_network::governor::PeerState::Warm => 1,
                            cordelia_network::governor::PeerState::Hot => 2,
                            cordelia_network::governor::PeerState::Banned { .. } => 0,
                        };
                        states.insert(peer.node_id.clone(), state_byte);
                    }
                }

                tracing::debug!(hot, warm, cold, banned, "gov: tick complete");
            }

            // ── Shutdown ──────────────────────────────────────────────
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("P2P loop shutting down");
                    if tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        conn_mgr.shutdown_and_wait(),
                    ).await.is_err() {
                        tracing::warn!("shutdown_and_wait timed out (30s), forcing close");
                    }
                    break;
                }
            }
        }
    }
}

/// Handle inbound protocol streams from a connected peer.
/// Runs until the connection closes.
#[allow(clippy::too_many_arguments)]
pub async fn handle_peer_streams(
    conn: quinn::Connection,
    peer_id: NodeId,
    state: web::Data<cordelia_api::state::AppState>,
    shared_peers: std::sync::Arc<std::sync::RwLock<Vec<cordelia_network::messages::PeerAddress>>>,
    node_role: String,
    push_tx: tokio::sync::mpsc::UnboundedSender<cordelia_api::state::PushItem>,
    delivery_tx: tokio::sync::mpsc::UnboundedSender<(NodeId, u64)>,
    peer_rates: std::sync::Arc<
        std::sync::Mutex<
            std::collections::HashMap<NodeId, cordelia_network::rate_limit::PeerRateLimiter>,
        >,
    >,
    peer_states: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<NodeId, u8>>>,
) {
    let mut stream_count: u64 = 0;
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                let reason = match &e {
                    quinn::ConnectionError::TimedOut => "idle_timeout",
                    quinn::ConnectionError::Reset => "reset",
                    quinn::ConnectionError::ApplicationClosed(_) => "shutdown",
                    quinn::ConnectionError::LocallyClosed => "local_close",
                    _ => "error",
                };
                tracing::info!(peer = %peer_id, reason, streams = stream_count, error = %e, "peer connection closed");
                break;
            }
        };

        stream_count += 1;

        let protocol = match cordelia_network::codec::read_protocol_byte(&mut recv).await {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(peer = %peer_id, error = %e, "failed to read protocol byte");
                continue;
            }
        };

        let proto_name = match protocol {
            cordelia_network::messages::Protocol::ItemPush => "item_push",
            cordelia_network::messages::Protocol::ItemSync => "item_sync",
            cordelia_network::messages::Protocol::PeerSharing => "peer_share",
            _ => "other",
        };
        tracing::debug!(peer = %peer_id, protocol = proto_name, stream = stream_count, "stream opened (inbound)");
        let stream_start = std::time::Instant::now();

        // Per-peer rate limit check (§9.2)
        {
            let mut rates = peer_rates.lock().unwrap_or_else(|e| e.into_inner());
            let limiter = rates.entry(peer_id.clone()).or_default();
            let allowed = match protocol {
                cordelia_network::messages::Protocol::ItemPush => limiter.writes.check_and_record(),
                cordelia_network::messages::Protocol::ItemSync => limiter.syncs.check_and_record(),
                cordelia_network::messages::Protocol::PeerSharing => {
                    limiter.peer_shares.check_and_record()
                }
                _ => true,
            };
            if !allowed {
                let should_ban = limiter.record_breach();
                tracing::warn!(peer = %peer_id, protocol = proto_name, ban = should_ban, "rate limit exceeded");
                if should_ban {
                    // Ban handled by governor on next tick (peer removed from hot set)
                    tracing::warn!(peer = %peer_id, "banning peer for repeated rate limit breaches");
                }
                continue;
            }
        }

        // Protocol gating by peer state (connection-lifecycle.md §2.1)
        let peer_state = peer_states
            .read()
            .ok()
            .and_then(|s| s.get(&peer_id).copied())
            .unwrap_or(1); // default Warm if not yet synced
        let is_hot = peer_state == 2;

        match protocol {
            cordelia_network::messages::Protocol::ItemPush
            | cordelia_network::messages::Protocol::ItemSync
                if !is_hot =>
            {
                tracing::debug!(peer = %peer_id, protocol = proto_name, "rejected: data protocol from non-hot peer");
                continue;
            }
            cordelia_network::messages::Protocol::ItemPush => {
                handle_inbound_push(
                    &mut send,
                    &mut recv,
                    &peer_id,
                    &state,
                    &node_role,
                    &push_tx,
                    &delivery_tx,
                )
                .await;
            }
            cordelia_network::messages::Protocol::ItemSync => {
                handle_inbound_sync(&mut send, &mut recv, &peer_id, &state, &node_role).await;
            }
            cordelia_network::messages::Protocol::PeerSharing => {
                // Allowed on Warm + Hot (§2.1)
                handle_inbound_peer_share(&mut send, &mut recv, &peer_id, &shared_peers).await;
            }
            other => {
                tracing::debug!(peer = %peer_id, protocol = ?other, "ignoring unhandled protocol");
            }
        }
        tracing::debug!(
            peer = %peer_id, protocol = proto_name, stream = stream_count,
            duration_ms = stream_start.elapsed().as_millis() as u64,
            "stream closed"
        );
    }
}

// ── Protocol handlers (extracted from handle_peer_streams) ───────

async fn handle_inbound_push(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    peer_id: &NodeId,
    state: &web::Data<cordelia_api::state::AppState>,
    node_role: &str,
    push_tx: &tokio::sync::mpsc::UnboundedSender<cordelia_api::state::PushItem>,
    delivery_tx: &tokio::sync::mpsc::UnboundedSender<(NodeId, u64)>,
) {
    let msg = match cordelia_network::codec::read_frame(recv).await {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(peer = %peer_id, error = %e, "failed to read push frame");
            return;
        }
    };

    let payload = match msg {
        cordelia_network::messages::WireMessage::PushPayload(p) => p,
        _ => return,
    };

    let (stored, dedup) = {
        let db = match state.db.lock() {
            Ok(db) => db,
            Err(_) => return,
        };
        let mut stored = 0u32;
        let mut dedup = 0u32;
        for item in &payload.items {
            match store_item(&db, item, node_role) {
                Ok(true) => stored += 1,
                Ok(false) => dedup += 1,
                Err(_) => {}
            }
        }
        (stored, dedup)
    };

    tracing::debug!(peer = %peer_id, stored, dedup, items = payload.items.len(), "processed inbound push");

    if stored > 0 {
        let _ = delivery_tx.send((peer_id.clone(), stored as u64));
    }

    // Relay re-push: forward received items to other peers
    if node_role == "relay" && stored > 0 {
        for item in &payload.items {
            let _ = push_tx.send(cordelia_api::state::PushItem {
                channel_id: item.channel_id.clone(),
                item_id: item.item_id.clone(),
                encrypted_blob: item.encrypted_blob.clone(),
                content_hash: item.content_hash.clone(),
                author_id: item.author_id.clone(),
                signature: item.signature.clone(),
                key_version: item.key_version,
                published_at: item.published_at.clone(),
                item_type: item.item_type.clone(),
                is_tombstone: item.is_tombstone,
                parent_id: item.parent_id.clone(),
                exclude_peer: Some(peer_id.clone()),
            });
        }
        tracing::debug!(peer = %peer_id, stored, "relay re-push queued");
    }

    let ack =
        cordelia_network::messages::WireMessage::PushAck(cordelia_network::messages::PushAck {
            stored,
            dedup_dropped: dedup,
            policy_rejected: 0,
            verification_failed: 0,
        });
    let _ = cordelia_network::codec::write_frame(send, &ack).await;
}

async fn handle_inbound_sync(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    peer_id: &NodeId,
    state: &web::Data<cordelia_api::state::AppState>,
    _node_role: &str,
) {
    let msg = match cordelia_network::codec::read_frame(recv).await {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(peer = %peer_id, error = %e, "sync request read failed");
            return;
        }
    };

    let req = match msg {
        cordelia_network::messages::WireMessage::SyncRequest(r) => r,
        _ => return,
    };

    // Build sync response headers
    let (headers, has_more) = {
        let db = match state.db.lock() {
            Ok(db) => db,
            Err(_) => return,
        };
        let items = cordelia_storage::items::query_listen(
            &db,
            &req.channel_id,
            req.since.as_deref(),
            req.limit,
        )
        .unwrap_or_default();
        let has_more = items.len() as u32 >= req.limit;
        let headers: Vec<cordelia_network::messages::ItemHeader> = items
            .iter()
            .map(|si| cordelia_network::messages::ItemHeader {
                item_id: si.item_id.clone(),
                channel_id: si.channel_id.clone(),
                item_type: si.item_type.clone(),
                content_hash: si.content_hash.clone(),
                author_id: si.author_id.clone(),
                signature: si.signature.clone(),
                key_version: si.key_version as u32,
                published_at: si.published_at.clone(),
                is_tombstone: si.is_tombstone,
                parent_id: si.parent_id.clone(),
            })
            .collect();
        (headers, has_more)
    };

    let resp = cordelia_network::messages::WireMessage::SyncResponse(
        cordelia_network::messages::SyncResponse {
            items: headers,
            has_more,
        },
    );
    let _ = cordelia_network::codec::write_frame(send, &resp).await;
    tracing::debug!(peer = %peer_id, channel = %req.channel_id, "served sync request");

    // Optional fetch phase: peer may request full items
    if let Ok(fetch_msg) = cordelia_network::codec::read_frame(recv).await
        && let cordelia_network::messages::WireMessage::FetchRequest(freq) = fetch_msg
    {
        let fetch_items = {
            let db = match state.db.lock() {
                Ok(db) => db,
                Err(_) => return,
            };
            cordelia_storage::items::query_listen(&db, &req.channel_id, None, 1000)
                .unwrap_or_default()
                .into_iter()
                .filter(|si| freq.item_ids.contains(&si.item_id))
                .map(|si| cordelia_network::messages::Item {
                    item_id: si.item_id,
                    channel_id: si.channel_id,
                    item_type: si.item_type,
                    content_length: si.encrypted_blob.len() as u32,
                    encrypted_blob: si.encrypted_blob,
                    content_hash: si.content_hash,
                    author_id: si.author_id,
                    signature: si.signature,
                    key_version: si.key_version as u32,
                    published_at: si.published_at,
                    is_tombstone: si.is_tombstone,
                    parent_id: si.parent_id,
                })
                .collect::<Vec<_>>()
        };
        let fresp = cordelia_network::messages::WireMessage::FetchResponse(
            cordelia_network::messages::FetchResponse { items: fetch_items },
        );
        let _ = cordelia_network::codec::write_frame(send, &fresp).await;
        tracing::debug!(peer = %peer_id, fetched = freq.item_ids.len(), "served fetch request");
    }
}

async fn handle_inbound_peer_share(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    peer_id: &NodeId,
    shared_peers: &std::sync::Arc<std::sync::RwLock<Vec<cordelia_network::messages::PeerAddress>>>,
) {
    let msg = match cordelia_network::codec::read_frame(recv).await {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(peer = %peer_id, error = %e, "peer-share read failed");
            return;
        }
    };

    if let cordelia_network::messages::WireMessage::PeerShareRequest(req) = msg {
        let max = req.max_peers as usize;
        let current_peers = shared_peers
            .read()
            .map(|p| p.iter().take(max).cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let count = current_peers.len();
        let resp = cordelia_network::messages::WireMessage::PeerShareResponse(
            cordelia_network::messages::PeerShareResponse {
                peers: current_peers,
            },
        );
        let _ = cordelia_network::codec::write_frame(send, &resp).await;
        tracing::debug!(peer = %peer_id, count, "served peer-share request");
    }
}
