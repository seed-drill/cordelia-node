//! P2P networking loop and per-peer stream handling.
//!
//! Extracted from main.rs per connection-lifecycle.md.
//! Owns the ConnectionManager, Governor, and all protocol dispatch.
//!
//! Spec: seed-drill/specs/connection-lifecycle.md, network-protocol.md §2-§5

use actix_web::web;
use cordelia_core::NodeId;
use cordelia_network::connection::Direction;

/// Governor events sent from spawned tasks back to the p2p_loop.
pub enum GovEvent {
    ItemsDelivered(NodeId, u64),
    ChannelAnnounced(NodeId, String),
    ChannelWithdrawn(NodeId, String),
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
    repush_tx: &tokio::sync::mpsc::UnboundedSender<(cordelia_network::messages::Item, NodeId)>,
    delivery_tx: &tokio::sync::mpsc::UnboundedSender<(NodeId, u64)>,
    peer_rates: &std::sync::Arc<
        std::sync::Mutex<
            std::collections::HashMap<NodeId, cordelia_network::rate_limit::PeerRateLimiter>,
        >,
    >,
    peer_states: &std::sync::Arc<std::sync::RwLock<std::collections::HashMap<NodeId, u8>>>,
    peer_relays: &std::sync::Arc<std::sync::RwLock<std::collections::HashSet<NodeId>>>,
    gov_tx: &tokio::sync::mpsc::UnboundedSender<GovEvent>,
) {
    // Step 1: Extract peer roles from handshake
    let (is_relay, is_bootnode) = conn_mgr
        .get_peer(node_id)
        .map(|pc| {
            let roles = &pc.handshake.peer_roles;
            tracing::info!(peer = %node_id, roles = ?roles, "post_connect: checking peer roles");
            (
                roles.contains(&"relay".to_string()),
                roles.contains(&"bootnode".to_string()),
            )
        })
        .unwrap_or_else(|| {
            tracing::warn!(peer = %node_id, "post_connect: get_peer returned None");
            (false, false)
        });

    // Step 2: Add to governor
    governor.add_peer(node_id.clone(), vec![], vec![]);

    // Step 3: Mark relay role
    if is_relay {
        governor.set_peer_relay(node_id, true);
        tracing::info!(peer = %node_id, "peer identified as relay");
    }
    // Mark bootnode role (prevents Hot promotion, §8.3)
    if is_bootnode {
        governor.set_peer_bootnode(node_id, true);
        tracing::info!(peer = %node_id, "peer identified as bootnode");
    }

    // Step 4: Mark connected (triggers Hot/Warm promotion -- bootnodes stay Warm)
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

    // Step 6c: Sync relay peer set for single-hop re-push (§7.2)
    if let Ok(mut relays) = peer_relays.write() {
        for peer in governor.all_peers() {
            if peer.is_relay {
                relays.insert(peer.node_id.clone());
            }
        }
    }

    // Step 7: Send channel announcements if peer promoted to Hot and we're not a relay
    // (relays are receive-only for channel-announce per §4.4)
    let peer_is_hot = governor
        .peer_info(node_id)
        .map(|p| p.state == cordelia_network::governor::PeerState::Hot)
        .unwrap_or(false);
    if peer_is_hot && node_role != "relay" {
        if let Some(conn) = conn_mgr.get_connection(node_id) {
            let conn = conn.clone();
            let announce_state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = send_channel_announcements(&conn, &announce_state).await {
                    tracing::debug!(error = %e, "channel announcements failed on connect");
                }
            });
        }
    }

    // Step 8: Spawn stream handler
    if let Some(conn) = conn_mgr.get_connection(node_id) {
        let conn = conn.clone();
        let peer_id = node_id.clone();
        let db_state = state.clone();
        let peers_ref = shared_peers.clone();
        let role = node_role.to_string();
        let rtx = repush_tx.clone();
        let dtx = delivery_tx.clone();
        let rates = peer_rates.clone();
        let states = peer_states.clone();
        let relays = peer_relays.clone();
        let gtx = gov_tx.clone();
        tokio::spawn(async move {
            handle_peer_streams(
                conn, peer_id, db_state, peers_ref, role, rtx, dtx, rates, states, relays, gtx,
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
    mut announce_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    allow_private_addresses: bool,
    node_role: String,
    gov_config: cordelia_core::config::GovernorConfig,
) {
    tracing::info!(role = %node_role, "P2P loop started (accept + push + peer-sharing)");

    // Relay re-push channel: items queued here by handle_inbound_push,
    // flushed in batches (de-duped by item_id) every REPUSH_INTERVAL_SECS.
    let (repush_tx, mut repush_rx) =
        tokio::sync::mpsc::unbounded_channel::<(cordelia_network::messages::Item, NodeId)>();

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

    // Shared set of relay peer IDs. Used by handle_inbound_push for single-hop
    // re-push check (§7.2: only re-push items from non-relay senders).
    let peer_relays: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<NodeId>>> =
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new()));

    // Delivery feedback channel
    let (delivery_tx, mut delivery_rx) = tokio::sync::mpsc::unbounded_channel::<(NodeId, u64)>();

    // Governor event channel (created before bootstrap so post_connect can pass it)
    let (gov_tx, mut gov_rx) = tokio::sync::mpsc::unbounded_channel::<GovEvent>();

    // Register bootstrap peers using canonical sequence
    for peer_id in conn_mgr.connected_peers() {
        post_connect(
            &peer_id,
            &conn_mgr,
            &mut governor,
            &shared_peers,
            &state,
            &node_role,
            &repush_tx,
            &delivery_tx,
            &peer_rates,
            &peer_states,
            &peer_relays,
            &gov_tx,
        );
    }
    governor.tick();

    // P2P loop timers. Peer-share and sync run at their protocol intervals
    // (from protocol.rs). Governor tick uses the config value.
    const P2P_PEER_SHARE_CHECK_SECS: u64 = 5; // How often to check for connect candidates
    let p2p_sync_check_secs = cordelia_core::protocol::REALTIME_SYNC_INTERVAL_SECS;

    let p2p_gov_tick_secs = gov_config.tick_interval_secs as u64;

    let mut peer_share_interval =
        tokio::time::interval(std::time::Duration::from_secs(P2P_PEER_SHARE_CHECK_SECS));
    peer_share_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    peer_share_interval.tick().await;

    let mut sync_interval =
        tokio::time::interval(std::time::Duration::from_secs(p2p_sync_check_secs));
    sync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    sync_interval.tick().await;

    let mut gov_interval = tokio::time::interval(std::time::Duration::from_secs(p2p_gov_tick_secs));
    gov_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    gov_interval.tick().await;

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

    // Relay re-push flush timer: batch + de-dupe items before forwarding.
    // Jittered start so relays don't all flush simultaneously (§7.2).
    let repush_base = cordelia_core::protocol::REPUSH_INTERVAL_SECS;
    let repush_jitter = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        our_node_id.0.hash(&mut h);
        (h.finish() % (repush_base * 1000)) as u64 // ms jitter within interval
    };
    let repush_start = std::time::Duration::from_millis(repush_jitter);
    tokio::time::sleep(repush_start).await;
    let mut repush_interval =
        tokio::time::interval(std::time::Duration::from_secs(repush_base));
    repush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    repush_interval.tick().await;

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

    // Non-blocking connect infrastructure (cordelia-node#8).
    // Spawned tasks send results back via channels; the select loop
    // registers connections and updates governor state inline.
    let endpoint = conn_mgr.endpoint();
    let connect_ctx = conn_mgr.connect_context();
    type ConnectMsg = Result<
        cordelia_network::connection::ConnectOutcome,
        (std::net::SocketAddr, String),
    >;
    let (connect_tx, mut connect_rx) = tokio::sync::mpsc::unbounded_channel::<ConnectMsg>();
    let (discovery_tx, mut discovery_rx) =
        tokio::sync::mpsc::unbounded_channel::<Vec<cordelia_network::messages::PeerAddress>>();
    let mut in_flight: std::collections::HashSet<std::net::SocketAddr> =
        std::collections::HashSet::new();
    let mut gov_pending: std::collections::HashMap<std::net::SocketAddr, NodeId> =
        std::collections::HashMap::new();
    const MAX_IN_FLIGHT: usize = 10;
    const CONNECTS_PER_CYCLE: usize = 3;

    loop {
        tokio::select! {
            // ── Accept incoming connection (non-blocking) ─────────────
            result = endpoint.accept() => {
                match result {
                    Some(incoming) => {
                        let ctx = connect_ctx.clone();
                        let tx = connect_tx.clone();
                        tokio::spawn(async move {
                            match cordelia_network::connection::inbound_accept(&ctx, incoming).await {
                                Ok(outcome) => { let _ = tx.send(Ok(outcome)); }
                                Err(e) => {
                                    tracing::debug!(error = %e, "inbound accept failed");
                                }
                            }
                        });
                    }
                    None => {
                        tracing::warn!("QUIC endpoint closed");
                    }
                }
            }

            // ── Connect/accept results ───────────────────────────────
            Some(result) = connect_rx.recv() => {
                match result {
                    Ok(outcome) => {
                        let addr = outcome.addr;
                        let direction = outcome.direction;

                        if direction == Direction::Outbound {
                            in_flight.remove(&addr);
                        }

                        // Personal nodes are outbound-only (§8.2), except from
                        // trusted_peers (§8.2.2 Personal Area Network).
                        if direction == Direction::Inbound && node_role == "personal" {
                            // TODO: check trusted_peers config for PAN exception
                            tracing::debug!(peer = %outcome.node_id, "rejecting inbound: personal nodes are outbound-only");
                            outcome.conn.close(0u32.into(), b"outbound-only");
                            continue;
                        }

                        // Connection tracker check (inbound only, §3.1)
                        if direction == Direction::Inbound {
                            let ip = outcome.conn.remote_address().ip();
                            if !conn_tracker.would_allow(ip) {
                                tracing::warn!(peer = %outcome.node_id, ip = %ip, "rejecting: connection limit exceeded");
                                outcome.conn.close(0u32.into(), b"limit");
                                continue;
                            }
                            conn_tracker.add(ip);
                        }

                        if direction == Direction::Outbound {
                            gov_pending.remove(&addr);
                        }

                        match conn_mgr.register(outcome) {
                            Ok(node_id) => {
                                let count = conn_mgr.connection_count() as u64;
                                state.peers_hot.store(count, std::sync::atomic::Ordering::Relaxed);
                                let dir_label = if direction == Direction::Inbound {
                                    "accepted inbound connection"
                                } else {
                                    "connected via peer-sharing"
                                };
                                tracing::info!(peer = %node_id, peers = count, "{}", dir_label);
                                post_connect(
                                    &node_id, &conn_mgr, &mut governor, &shared_peers,
                                    &state, &node_role, &repush_tx, &delivery_tx, &peer_rates, &peer_states,
                                    &peer_relays, &gov_tx,
                                );
                            }
                            Err(e) => {
                                tracing::debug!(addr = %addr, error = %e, "register failed");
                            }
                        }
                    }
                    Err((addr, error)) => {
                        in_flight.remove(&addr);
                        if let Some(nid) = gov_pending.remove(&addr) {
                            governor.mark_dial_failed(&nid);
                        }
                        tracing::debug!(addr = %addr, error = %error, "outbound connect failed");
                    }
                }
            }

            // ── Discovery results ────────────────────────────────────
            Some(discovered) = discovery_rx.recv() => {
                for pa in discovered {
                    let nid = NodeId(pa.node_id.as_slice().try_into().unwrap_or([0u8; 32]));
                    if nid != our_node_id && !peer_share_cache.iter().any(|c| c.node_id == pa.node_id) {
                        peer_share_cache.push(pa);
                    }
                }
            }

            // ── Peer-sharing (spawn discovery + connects) ─────────────
            // (a) Request addresses from a peer whose cooldown has expired (spawned).
            // (b) Spawn up to CONNECTS_PER_CYCLE candidates from the cache.
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
                        let own_addr = conn_mgr.local_addr().ok();
                        let dtx = discovery_tx.clone();
                        let allow_private = allow_private_addresses;
                        tokio::spawn(async move {
                            if let Ok((mut send, mut recv)) = open_bi(&conn).await {
                                let mut stream = tokio::io::join(&mut recv, &mut send);
                                if let Ok(discovered) = cordelia_network::peer_sharing::request_peers(
                                    &mut stream, cordelia_core::protocol::DEFAULT_MAX_PEERS_SHARE,
                                ).await {
                                    let valid = if allow_private {
                                        discovered
                                    } else {
                                        cordelia_network::peer_sharing::filter_valid_addresses(&discovered, own_addr.as_ref())
                                    };
                                    let _ = dtx.send(valid);
                                }
                            }
                        });
                    }
                }

                // (b) Connect: spawn candidates from cache (non-blocking).
                // During bootstrap (hot < hot_min), peers come from trusted
                // bootnodes -- connect as fast as MAX_IN_FLIGHT allows.
                // Post-bootstrap, rate-limit to CONNECTS_PER_CYCLE per tick.
                let (hot, _, _, _) = governor.counts();
                let bootstrap_urgent = hot < gov_config.hot_min as usize;
                let max_connects = if bootstrap_urgent {
                    MAX_IN_FLIGHT
                } else {
                    CONNECTS_PER_CYCLE
                };
                let candidates: Vec<_> = peer_share_cache.iter()
                    .filter(|pa| {
                        let nid = NodeId(pa.node_id.as_slice().try_into().unwrap_or([0u8; 32]));
                        nid != our_node_id && !conn_mgr.is_connected(&nid)
                    })
                    .collect();
                if !candidates.is_empty() {
                    let mut spawned = 0usize;
                    for offset in 0..candidates.len() {
                        if spawned >= max_connects || in_flight.len() >= MAX_IN_FLIGHT {
                            break;
                        }
                        let idx = (peer_share_rotation + offset) % candidates.len();
                        let peer_addr = candidates[idx];
                        if let Some(addr_str) = peer_addr.addrs.first() {
                            if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
                                if in_flight.contains(&addr) { continue; }
                                in_flight.insert(addr);
                                let ctx = connect_ctx.clone();
                                let tx = connect_tx.clone();
                                tokio::spawn(async move {
                                    match cordelia_network::connection::outbound_connect(&ctx, addr).await {
                                        Ok(outcome) => { let _ = tx.send(Ok(outcome)); }
                                        Err(e) => {
                                            tracing::debug!(addr = %addr, error = %e, "peer-share connect failed");
                                            let _ = tx.send(Err((addr, e.to_string())));
                                        }
                                    }
                                });
                                spawned += 1;
                            }
                        }
                    }
                    peer_share_rotation = peer_share_rotation.wrapping_add(spawned);
                }
            }

            // ── Push items to hot relay peers (batched, §7.1) ─────────
            // Originator push: personal/keeper writes go to hot relay peers
            // only. Relays handle distribution. Non-relay peers pull (§4.5).
            Some(first_push) = push_rx.recv() => {
                let mut all_pushes = vec![first_push];
                while let Ok(more) = push_rx.try_recv() {
                    all_pushes.push(more);
                }

                // Target: hot relay peers only (§8.2.1)
                let relay_targets: Vec<NodeId> = governor.hot_peers().into_iter()
                    .filter(|p| governor.peer_info(p).map(|i| i.is_relay).unwrap_or(false))
                    .collect();

                let mut peer_batches: std::collections::HashMap<
                    NodeId,
                    Vec<cordelia_network::messages::Item>,
                > = std::collections::HashMap::new();

                let item_count = all_pushes.len();
                for push_item in all_pushes {
                    let exclude = push_item.exclude_peer;
                    let item = cordelia_network::messages::Item {
                        item_id: push_item.item_id,
                        channel_id: push_item.channel_id,
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

                    for peer_id in &relay_targets {
                        if exclude.as_ref() == Some(peer_id) {
                            continue;
                        }
                        peer_batches
                            .entry(peer_id.clone())
                            .or_default()
                            .push(item.clone());
                    }
                }

                if peer_batches.is_empty() { continue; }
                tracing::debug!(
                    items = item_count,
                    peers = peer_batches.len(),
                    "push batch assembled"
                );

                // One push stream per peer, all items batched
                for (peer_id, items) in peer_batches {
                    if let Some(conn) = conn_mgr.get_connection(&peer_id) {
                        let conn = conn.clone();
                        let pid = peer_id;
                        let batch_size = items.len();
                        let rtx = retry_fail_tx.clone();
                        tokio::spawn(async move {
                            let (mut send, mut recv) = match open_bi(&conn).await {
                                Ok(s) => s,
                                Err(e) => {
                                    tracing::debug!(peer = %pid, items = batch_size, error = %e, "push batch open_bi failed");
                                    for item in items {
                                        let ch = item.channel_id.clone();
                                        let _ = rtx.send(RetryEntry {
                                            item, peer_id: pid.clone(), channel_id: ch,
                                            exclude_peer: None, attempt: 0,
                                            retry_at: tokio::time::Instant::now() + std::time::Duration::from_secs(2),
                                        });
                                    }
                                    return;
                                }
                            };
                            let mut stream = tokio::io::join(&mut recv, &mut send);
                            match cordelia_network::item_sync::send_push(&mut stream, &items).await {
                                Ok(ack) => {
                                    tracing::debug!(peer = %pid, items = batch_size, stored = ack.stored, "push batch delivered");
                                }
                                Err(e) => {
                                    tracing::debug!(peer = %pid, items = batch_size, error = %e, "push batch failed");
                                    for item in items {
                                        let ch = item.channel_id.clone();
                                        let _ = rtx.send(RetryEntry {
                                            item, peer_id: pid.clone(), channel_id: ch,
                                            exclude_peer: None, attempt: 0,
                                            retry_at: tokio::time::Instant::now() + std::time::Duration::from_secs(2),
                                        });
                                    }
                                }
                            }
                        });
                    }
                }
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

            // ── Relay re-push flush (batched, de-duped) ───────────────
            _ = repush_interval.tick() => {
                // Drain and de-dupe by item_id
                let mut pending: std::collections::HashMap<
                    String,
                    (cordelia_network::messages::Item, NodeId),
                > = std::collections::HashMap::new();
                while let Ok((item, source)) = repush_rx.try_recv() {
                    pending.entry(item.item_id.clone()).or_insert((item, source));
                }
                if pending.is_empty() { continue; }

                // Build per-peer batches -- relay peers only (§7.2: single-hop,
                // relay-to-relay broadcast). Exclude the sender of each item.
                let relay_peers: Vec<NodeId> = governor.hot_peers().into_iter()
                    .filter(|p| governor.peer_info(p).map(|i| i.is_relay).unwrap_or(false))
                    .collect();
                let mut peer_batches: std::collections::HashMap<
                    NodeId,
                    Vec<cordelia_network::messages::Item>,
                > = std::collections::HashMap::new();
                for (_, (item, source)) in &pending {
                    for peer_id in &relay_peers {
                        if peer_id == source { continue; }
                        peer_batches
                            .entry(peer_id.clone())
                            .or_default()
                            .push(item.clone());
                    }
                }

                if peer_batches.is_empty() { continue; }
                let deduped = pending.len();
                tracing::debug!(items = deduped, peers = peer_batches.len(), "relay repush flush");

                for (peer_id, items) in peer_batches {
                    if let Some(conn) = conn_mgr.get_connection(&peer_id) {
                        let conn = conn.clone();
                        let pid = peer_id;
                        let count = items.len();
                        let rtx = retry_fail_tx.clone();
                        tokio::spawn(async move {
                            let (mut send, mut recv) = match open_bi(&conn).await {
                                Ok(s) => s,
                                Err(e) => {
                                    tracing::debug!(peer = %pid, items = count, error = %e, "repush open_bi failed");
                                    for item in items {
                                        let ch = item.channel_id.clone();
                                        let _ = rtx.send(RetryEntry {
                                            item, peer_id: pid.clone(), channel_id: ch,
                                            exclude_peer: None, attempt: 0,
                                            retry_at: tokio::time::Instant::now() + std::time::Duration::from_secs(2),
                                        });
                                    }
                                    return;
                                }
                            };
                            let mut stream = tokio::io::join(&mut recv, &mut send);
                            match cordelia_network::item_sync::send_push(&mut stream, &items).await {
                                Ok(ack) => tracing::debug!(peer = %pid, items = count, stored = ack.stored, "repush delivered"),
                                Err(e) => {
                                    tracing::debug!(peer = %pid, items = count, error = %e, "repush failed");
                                    for item in items {
                                        let ch = item.channel_id.clone();
                                        let _ = rtx.send(RetryEntry {
                                            item, peer_id: pid.clone(), channel_id: ch,
                                            exclude_peer: None, attempt: 0,
                                            retry_at: tokio::time::Instant::now() + std::time::Duration::from_secs(2),
                                        });
                                    }
                                }
                            }
                        });
                    }
                }
            }

            // ── Channel-announce on local subscribe ──────────────────
            // API subscribe handler sends channel_id here; we announce
            // to all hot peers so they add us to their push routing.
            Some(_channel_id) = announce_rx.recv() => {
                // Drain all pending announces (batch subscribes)
                while let Ok(_) = announce_rx.try_recv() {}
                // Send full channel list to all hot peers (simpler than
                // incremental per-channel -- reconnect-safe too)
                if node_role != "relay" {
                    for peer_id in governor.hot_peers() {
                        if let Some(conn) = conn_mgr.get_connection(&peer_id) {
                            let conn = conn.clone();
                            let announce_state = state.clone();
                            tokio::spawn(async move {
                                if let Err(e) = send_channel_announcements(&conn, &announce_state).await {
                                    tracing::debug!(error = %e, "channel announcements failed on subscribe");
                                }
                            });
                        }
                    }
                }
            }

            // ── Pull-sync from hot peers (§4.5) ─────────────────────
            // "The node MUST sync from all hot peers each cycle."
            // Relays: Phase 0 channel discovery + stored channels (relay_learned_channels).
            // Personal nodes: subscribed channels (list_for_entity), skip Phase 0.
            _ = sync_interval.tick() => {
                if node_role == "bootnode" { continue; }
                let peers = conn_mgr.connected_peers();
                if peers.is_empty() { continue; }

                // Personal nodes: get subscribed channels, skip if empty
                let local_channels: Vec<String> = {
                    let db = match state.db.lock() {
                        Ok(db) => db,
                        Err(_) => continue,
                    };
                    if node_role == "relay" {
                        cordelia_storage::channels::list_stored_channel_ids(&db)
                            .unwrap_or_default()
                    } else {
                        let pk = state.identity.public_key();
                        cordelia_storage::channels::list_for_entity(&db, &pk)
                            .unwrap_or_default()
                            .into_iter()
                            .map(|c| c.channel_id)
                            .collect()
                    }
                };
                // Personal nodes with no subscribed channels: nothing to sync
                if local_channels.is_empty() && node_role != "relay" { continue; }

                let is_relay = node_role == "relay";
                let hot = governor.hot_peers();
                tracing::debug!(hot_peers = hot.len(), total_peers = peers.len(), local_channels = local_channels.len(), "pull-sync cycle");
                for target in &hot {
                    if let Some(conn) = conn_mgr.get_connection(target) {
                    let conn = conn.clone();
                    let sync_state = state.clone();
                    let sync_local = local_channels.clone();
                    let target = target.clone();
                    let gtx = gov_tx.clone();
                    let role = node_role.clone();
                    let do_phase0 = is_relay;
                    tokio::spawn(async move {
                        // Phase 0: relay channel discovery (§4.5)
                        // Ask peer "what channels do you have?", merge with local.
                        let sync_channels = if do_phase0 {
                            let (mut send, mut recv) = match open_bi(&conn).await {
                                Ok(s) => s,
                                Err(e) => { tracing::debug!(peer = %target, error = %e, "phase0 open_bi failed"); return; }
                            };
                            // Write protocol byte
                            if let Err(e) = cordelia_network::codec::write_protocol_byte(&mut send, cordelia_network::messages::Protocol::ItemSync).await {
                                tracing::debug!(peer = %target, error = %e, "phase0 protocol byte failed");
                                return;
                            }
                            let discovered = match cordelia_network::item_sync::send_channel_list_request(&mut send, &mut recv).await {
                                Ok(resp) => resp.channel_ids,
                                Err(e) => {
                                    tracing::debug!(peer = %target, error = %e, "phase0 channel list request failed");
                                    Vec::new()
                                }
                            };
                            if !discovered.is_empty() {
                                tracing::debug!(peer = %target, discovered = discovered.len(), "phase0: discovered channels");
                            }
                            // Merge: local stored + peer discovered (deduplicated)
                            let mut merged: std::collections::HashSet<String> = sync_local.into_iter().collect();
                            for ch in discovered {
                                merged.insert(ch);
                            }
                            merged.into_iter().collect::<Vec<_>>()
                        } else {
                            sync_local
                        };

                        if sync_channels.is_empty() { return; }
                        tracing::debug!(peer = %target, channels = sync_channels.len(), "pull-sync starting");

                        for ch_id in &sync_channels {
                            let (mut send, mut recv) = match open_bi(&conn).await {
                                Ok(s) => s,
                                Err(e) => { tracing::debug!(peer = %target, channel = %ch_id, error = %e, "sync open_bi"); break; }
                            };
                            let mut stream = tokio::io::join(&mut recv, &mut send);
                            let resp = match cordelia_network::item_sync::send_sync_request(&mut stream, ch_id, None, cordelia_core::protocol::DEFAULT_SYNC_LIMIT).await {
                                Ok(r) => r,
                                Err(e) => { tracing::debug!(peer = %target, channel = %ch_id, error = %e, "sync request failed"); continue; }
                            };
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
                while let Ok(event) = gov_rx.try_recv() {
                    match event {
                        GovEvent::ItemsDelivered(peer_id, count) => {
                            governor.record_items_delivered(&peer_id, count);
                        }
                        GovEvent::ChannelAnnounced(peer_id, channel_id) => {
                            governor.add_peer_channel(&peer_id, &channel_id);
                            tracing::debug!(peer = %peer_id, channel = %channel_id, "gov: added peer channel");
                        }
                        GovEvent::ChannelWithdrawn(peer_id, channel_id) => {
                            governor.remove_peer_channel(&peer_id, &channel_id);
                            tracing::debug!(peer = %peer_id, channel = %channel_id, "gov: removed peer channel");
                        }
                    }
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

                        // Send channel announcements on warm->hot promotion (non-relay only, §4.4)
                        if from == "warm" && to == "hot" && node_role != "relay" {
                            if let Some(conn) = conn_mgr.get_connection(node_id) {
                                let conn = conn.clone();
                                let announce_state = state.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = send_channel_announcements(&conn, &announce_state).await {
                                        tracing::debug!(error = %e, "channel announcements failed on promotion");
                                    }
                                });
                            }
                        }
                    }
                }
                for node_id in &actions.disconnect {
                    conn_mgr.disconnect(node_id);
                }
                for node_id in &actions.connect {
                    if let Some(peer) = governor.peer_info(node_id)
                        && let Some(addr_str) = peer.addrs.first()
                        && let Ok(addr) = addr_str.parse::<std::net::SocketAddr>()
                    {
                        if in_flight.len() >= MAX_IN_FLIGHT || in_flight.contains(&addr) {
                            continue;
                        }
                        in_flight.insert(addr);
                        gov_pending.insert(addr, node_id.clone());
                        let ctx = connect_ctx.clone();
                        let tx = connect_tx.clone();
                        tokio::spawn(async move {
                            match cordelia_network::connection::outbound_connect(&ctx, addr).await {
                                Ok(outcome) => { let _ = tx.send(Ok(outcome)); }
                                Err(e) => {
                                    tracing::debug!(addr = %addr, error = %e, "gov: connect failed");
                                    let _ = tx.send(Err((addr, e.to_string())));
                                }
                            }
                        });
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

                // Sync relay peer set for single-hop re-push check (§7.2)
                if let Ok(mut relays) = peer_relays.write() {
                    relays.clear();
                    for peer in governor.all_peers() {
                        if peer.is_relay {
                            relays.insert(peer.node_id.clone());
                        }
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
    repush_tx: tokio::sync::mpsc::UnboundedSender<(cordelia_network::messages::Item, NodeId)>,
    delivery_tx: tokio::sync::mpsc::UnboundedSender<(NodeId, u64)>,
    peer_rates: std::sync::Arc<
        std::sync::Mutex<
            std::collections::HashMap<NodeId, cordelia_network::rate_limit::PeerRateLimiter>,
        >,
    >,
    peer_states: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<NodeId, u8>>>,
    peer_relays: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<NodeId>>>,
    gov_tx: tokio::sync::mpsc::UnboundedSender<GovEvent>,
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
            cordelia_network::messages::Protocol::ChannelAnnounce => "channel_announce",
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
            | cordelia_network::messages::Protocol::ChannelAnnounce
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
                    &repush_tx,
                    &delivery_tx,
                    &peer_relays,
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
            cordelia_network::messages::Protocol::ChannelAnnounce => {
                handle_inbound_channel_announce(&mut recv, &peer_id, &gov_tx).await;
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
    repush_tx: &tokio::sync::mpsc::UnboundedSender<(cordelia_network::messages::Item, NodeId)>,
    delivery_tx: &tokio::sync::mpsc::UnboundedSender<(NodeId, u64)>,
    peer_relays: &std::sync::Arc<std::sync::RwLock<std::collections::HashSet<NodeId>>>,
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

    // Track which items are newly stored (for selective re-push)
    let mut newly_stored: Vec<cordelia_network::messages::Item> = Vec::new();
    let (stored, dedup) = {
        let db = match state.db.lock() {
            Ok(db) => db,
            Err(_) => return,
        };
        let mut stored = 0u32;
        let mut dedup = 0u32;
        for item in &payload.items {
            match store_item(&db, item, node_role) {
                Ok(true) => {
                    stored += 1;
                    newly_stored.push(item.clone());
                }
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

    // Relay single-hop re-push (§7.2):
    // - Only re-push items received from non-relay peers (first hop only)
    // - Only queue items that were newly stored (not duplicates)
    // - Repush flush targets relay peers only
    if node_role == "relay" && !newly_stored.is_empty() {
        let sender_is_relay = peer_relays
            .read()
            .ok()
            .map(|r| r.contains(peer_id))
            .unwrap_or(false);
        if !sender_is_relay {
            for item in &newly_stored {
                let _ = repush_tx.send((item.clone(), peer_id.clone()));
            }
            tracing::debug!(peer = %peer_id, queued = newly_stored.len(), "relay repush queued (single-hop)");
        }
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

    // Phase 0: channel list discovery (§4.5). If the first message is
    // SyncChannelListRequest, respond with our stored channel IDs and
    // then read the next message as a normal SyncRequest.
    let req = match msg {
        cordelia_network::messages::WireMessage::SyncChannelListRequest(_) => {
            let channel_ids = {
                let db = match state.db.lock() {
                    Ok(db) => db,
                    Err(_) => return,
                };
                cordelia_storage::channels::list_stored_channel_ids(&db).unwrap_or_default()
            };
            tracing::debug!(peer = %peer_id, channels = channel_ids.len(), "served channel list request");
            let resp = cordelia_network::messages::WireMessage::SyncChannelListResponse(
                cordelia_network::messages::SyncChannelListResponse { channel_ids },
            );
            let _ = cordelia_network::codec::write_frame(send, &resp).await;

            // Now read the actual SyncRequest
            match cordelia_network::codec::read_frame(recv).await {
                Ok(cordelia_network::messages::WireMessage::SyncRequest(r)) => r,
                Ok(_) => return,
                Err(_) => return, // Peer may close after Phase 0 (no channels to sync)
            }
        }
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
            .map(|p| {
                // Shuffle before returning (§4.3): each requester gets a random
                // subset in a random order, distributing load across the relay mesh.
                let mut peers: Vec<_> = p.clone();
                // Mix nanos + peer_id for per-request entropy
                let seed = {
                    use std::hash::{Hash, Hasher};
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                        .hash(&mut h);
                    peer_id.0.hash(&mut h);
                    h.finish() as usize
                };
                for i in (1..peers.len()).rev() {
                    let j = (seed.wrapping_mul(i + 1).wrapping_add(7)) % (i + 1);
                    peers.swap(i, j);
                }
                peers.into_iter().take(max).collect::<Vec<_>>()
            })
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

/// Handle inbound ChannelAnnounce (0x04) stream.
/// Reads frames until EOF/error, dispatches ChannelJoined/ChannelLeft to governor.
async fn handle_inbound_channel_announce(
    recv: &mut quinn::RecvStream,
    peer_id: &NodeId,
    gov_tx: &tokio::sync::mpsc::UnboundedSender<GovEvent>,
) {
    loop {
        let msg = match cordelia_network::codec::read_frame(recv).await {
            Ok(m) => m,
            Err(_) => break, // EOF or error -- stream done
        };
        match msg {
            cordelia_network::messages::WireMessage::ChannelJoined(joined) => {
                if let Err(e) =
                    cordelia_network::channel_announce::validate_descriptor(&joined.descriptor)
                {
                    tracing::warn!(
                        peer = %peer_id,
                        channel = %joined.channel_id,
                        error = %e,
                        "channel-announce: invalid descriptor"
                    );
                    continue;
                }
                tracing::info!(
                    peer = %peer_id,
                    channel = %joined.channel_id,
                    "peer announced channel"
                );
                let _ = gov_tx.send(GovEvent::ChannelAnnounced(
                    peer_id.clone(),
                    joined.channel_id,
                ));
            }
            cordelia_network::messages::WireMessage::ChannelLeft(left) => {
                tracing::info!(
                    peer = %peer_id,
                    channel = %left.channel_id,
                    "peer withdrew channel"
                );
                let _ = gov_tx.send(GovEvent::ChannelWithdrawn(
                    peer_id.clone(),
                    left.channel_id,
                ));
            }
            _ => {
                tracing::debug!(peer = %peer_id, "channel-announce: unexpected message type");
                break;
            }
        }
    }
}

/// Send ChannelJoined announcements for all our subscribed channels.
/// Opens a 0x04 stream and sends one ChannelJoined per channel.
async fn send_channel_announcements(
    conn: &quinn::Connection,
    state: &web::Data<cordelia_api::state::AppState>,
) -> Result<(), String> {
    let channels = {
        let db = state
            .db
            .lock()
            .map_err(|e| format!("db lock: {e}"))?;
        let pk = state.identity.public_key();
        cordelia_storage::channels::list_for_entity(&db, &pk).unwrap_or_default()
    };
    if channels.is_empty() {
        return Ok(());
    }

    let (mut send, _recv) = open_bi(conn).await?;

    // Write protocol byte for ChannelAnnounce (0x04)
    send.write_all(&[cordelia_network::messages::Protocol::ChannelAnnounce as u8])
        .await
        .map_err(|e| format!("write protocol byte: {e}"))?;

    for ch in &channels {
        let psk_hash: [u8; 32] = ch
            .psk_hash
            .as_ref()
            .and_then(|h| h.as_slice().try_into().ok())
            .unwrap_or([0u8; 32]);
        let descriptor = cordelia_network::channel_announce::create_signed_descriptor(
            &state.identity,
            &ch.channel_id,
            ch.channel_name.as_deref(),
            &ch.access,
            &ch.mode,
            &psk_hash,
            ch.key_version as u32,
            &ch.created_at,
        );
        if let Err(e) =
            cordelia_network::channel_announce::send_channel_joined(&mut send, &ch.channel_id, &descriptor).await
        {
            tracing::debug!(channel = %ch.channel_id, error = %e, "channel announce send failed");
            break;
        }
    }

    let _ = send.finish();
    tracing::debug!(channels = channels.len(), "sent channel announcements");
    Ok(())
}
