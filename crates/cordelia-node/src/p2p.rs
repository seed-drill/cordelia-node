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
    /// The peer kept going over its rate limits, from this address. Its
    /// connection has been closed.
    OverLimit(NodeId, std::net::IpAddr),
}

/// What each connection, and each address, has sent lately (§9.2).
///
/// A connection has its own allowance. All the connections from one address
/// share MAX_CONNECTIONS_PER_IP times that, which is what makes the limits
/// hold against a peer that reconnects or comes back under another key.
#[derive(Default)]
pub struct Rates {
    by_peer: std::collections::HashMap<NodeId, cordelia_network::rate_limit::PeerRateLimiter>,
    by_address:
        std::collections::HashMap<std::net::IpAddr, cordelia_network::rate_limit::PeerRateLimiter>,
}

/// A request that is over a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverLimit {
    /// This is one breach too many: the peer is to be cut off.
    pub cut_off: bool,
}

impl Rates {
    fn both(
        &mut self,
        peer: &NodeId,
        address: std::net::IpAddr,
    ) -> [&mut cordelia_network::rate_limit::PeerRateLimiter; 2] {
        use cordelia_network::rate_limit::PeerRateLimiter;
        let per_address = cordelia_core::protocol::MAX_CONNECTIONS_PER_IP as u32;
        [
            self.by_peer.entry(peer.clone()).or_default(),
            self.by_address
                .entry(address)
                .or_insert_with(|| PeerRateLimiter::for_connections(per_address)),
        ]
    }

    fn over(limiters: [&mut cordelia_network::rate_limit::PeerRateLimiter; 2]) -> OverLimit {
        let mut cut_off = false;
        for limiter in limiters {
            cut_off |= limiter.record_breach();
        }
        OverLimit { cut_off }
    }

    /// Count one stream of `protocol` opened by `peer` from `address`. A
    /// request that is refused counts against neither allowance.
    ///
    /// The streams of entries of channels from their secrets are counted
    /// together, whichever of them a request is on (decision 2026-10-04
    /// §16): a show, a proof, a pull, a push, and what is asked on the
    /// stream between relays.
    pub fn request(
        &mut self,
        peer: &NodeId,
        address: std::net::IpAddr,
        protocol: cordelia_network::messages::Protocol,
    ) -> Result<(), OverLimit> {
        use cordelia_network::messages::Protocol;
        use cordelia_network::rate_limit::{PeerRateLimiter, RateCounter};
        fn counter(limiter: &mut PeerRateLimiter, protocol: Protocol) -> Option<&mut RateCounter> {
            match protocol {
                Protocol::ItemPush => Some(&mut limiter.writes),
                Protocol::ItemSync => Some(&mut limiter.syncs),
                Protocol::PeerSharing => Some(&mut limiter.peer_shares),
                Protocol::EntryShow
                | Protocol::ChannelProve
                | Protocol::EntryPull
                | Protocol::EntryPush
                | Protocol::RelayEntries => Some(&mut limiter.entry_requests),
                _ => None,
            }
        }
        let mut limiters = self.both(peer, address);
        let over = limiters
            .iter_mut()
            .any(|limiter| counter(limiter, protocol).is_some_and(|c| c.would_exceed()));
        if over {
            return Err(Self::over(limiters));
        }
        for limiter in &mut limiters {
            if let Some(counter) = counter(limiter, protocol) {
                counter.check_and_record();
            }
        }
        Ok(())
    }

    /// Count `bytes` of entries pushed by `peer` from `address`. A push
    /// that is refused counts against neither allowance.
    pub fn pushed(
        &mut self,
        peer: &NodeId,
        address: std::net::IpAddr,
        bytes: u64,
    ) -> Result<(), OverLimit> {
        self.may_push(peer, address, bytes)?;
        self.count_pushed(peer, address, bytes);
        Ok(())
    }

    /// Whether `peer` at `address` may push `bytes` of entries now: a
    /// breach where either allowance has no room for them. Counts nothing
    /// else. What is then taken is counted once it is written
    /// ([`Self::count_pushed`]).
    pub fn may_push(
        &mut self,
        peer: &NodeId,
        address: std::net::IpAddr,
        bytes: u64,
    ) -> Result<(), OverLimit> {
        let mut limiters = self.both(peer, address);
        if limiters
            .iter_mut()
            .any(|limiter| limiter.write_bytes.room() < bytes)
        {
            return Err(Self::over(limiters));
        }
        Ok(())
    }

    /// Count `bytes` of entries that `peer` at `address` pushed, and that
    /// [`Self::may_push`] allowed, against both allowances: whatever has
    /// been counted against them since.
    pub fn count_pushed(&mut self, peer: &NodeId, address: std::net::IpAddr, bytes: u64) {
        for limiter in self.both(peer, address) {
            limiter.write_bytes.record(bytes);
        }
    }

    /// Whether anything is kept for `peer`: a count of what it sent.
    #[cfg(test)]
    pub fn is_counting(&self, peer: &NodeId) -> bool {
        self.by_peer.contains_key(peer)
    }

    /// What is counted for `peer`, where anything is: its breaches among
    /// it.
    #[cfg(test)]
    pub fn breaches_of_peer(
        &self,
        peer: &NodeId,
    ) -> Option<&cordelia_network::rate_limit::PeerRateLimiter> {
        self.by_peer.get(peer)
    }

    /// What is counted for `address`, where anything is.
    #[cfg(test)]
    pub fn breaches_of_address(
        &self,
        address: std::net::IpAddr,
    ) -> Option<&cordelia_network::rate_limit::PeerRateLimiter> {
        self.by_address.get(&address)
    }

    /// The bytes that `peer` was handed, or that a relay fetched from it,
    /// within the minute: also where they are more than it may be.
    #[cfg(test)]
    pub fn fetched_of_peer(&mut self, peer: &NodeId) -> u64 {
        self.by_peer
            .get_mut(peer)
            .map_or(0, |limiter| limiter.fetch_bytes.total())
    }

    /// How many bytes of entries `peer` at `address` may still push in this
    /// window, for the connection and for its address.
    #[cfg(test)]
    pub fn push_room(&mut self, peer: &NodeId, address: std::net::IpAddr) -> u64 {
        self.both(peer, address)
            .iter_mut()
            .map(|limiter| limiter.write_bytes.room())
            .min()
            .unwrap_or(0)
    }

    /// How many bytes of entries a relay may still fetch from `peer` at
    /// `address` in this window: as many as the peer may push in one, for
    /// the connection and for its address.
    pub fn fetch_room(&mut self, peer: &NodeId, address: std::net::IpAddr) -> u64 {
        self.both(peer, address)
            .iter_mut()
            .map(|limiter| limiter.fetch_bytes.room())
            .min()
            .unwrap_or(0)
    }

    /// How many bytes of a page of a channel from its secret `peer` at
    /// `address` may still be handed in this window (decision 2026-10-04
    /// §16): what [`Self::fetch_room`] says, less the room that is left
    /// in both allowances for the answer to a show
    /// (SHOW_ANSWER_ROOM_BYTES). A pull never uses that room: only the
    /// entry that answers a show does.
    pub fn pull_room(&mut self, peer: &NodeId, address: std::net::IpAddr) -> u64 {
        self.fetch_room(peer, address)
            .saturating_sub(cordelia_core::protocol::SHOW_ANSWER_ROOM_BYTES)
    }

    /// Count `bytes` of a page of a channel from its secret that `peer` at
    /// `address` asked for and is to be handed (decision 2026-10-04 §2.4
    /// item 3). They count against the bytes that may be fetched in a
    /// minute, for the connection and for its address: the allowance that
    /// what a relay fetches from the peer is counted against, so that the
    /// two kinds of channel are bounded by it together.
    ///
    /// Returns whether the page may be handed. Where either allowance has
    /// no room for it beside the room that is left for the answer to a
    /// show ([`Self::pull_room`]), nothing is counted, and the caller
    /// hands nothing. That is no breach (§16): the relay sized the page,
    /// and the asker cannot know its room. Nothing is kept of a request
    /// that hands nothing.
    pub fn handed(&mut self, peer: &NodeId, address: std::net::IpAddr, bytes: u64) -> bool {
        if bytes == 0 {
            return true;
        }
        if self.pull_room(peer, address) < bytes {
            return false;
        }
        for limiter in self.both(peer, address) {
            limiter.fetch_bytes.record(bytes);
        }
        true
    }

    /// Count `bytes` of the entry that `peer` at `address` is answered
    /// with when it showed one (decision 2026-10-04 §2.4 item 5), against
    /// the bytes that may be fetched in a minute, as a page is counted.
    ///
    /// The answer to a show is handed while the asker is not over either
    /// allowance already, and is always counted, though it take the asker
    /// over by that one entry (§16): a device that is near its bytes for
    /// the minute must still hear of a removal. Whoever calls this has
    /// asked [`Self::fetch_room`] first. What the asker is over by, it
    /// waits out before it is handed an entry again.
    pub fn answered(&mut self, peer: &NodeId, address: std::net::IpAddr, bytes: u64) {
        for limiter in self.both(peer, address) {
            limiter.fetch_bytes.record(bytes);
        }
    }

    /// Forget peers that are no longer connected, and addresses that have
    /// no connection and no recent breach.
    pub fn prune(&mut self, connected: &[NodeId], open: &[std::net::IpAddr]) {
        self.by_peer.retain(|peer, _| connected.contains(peer));
        // An address is forgotten only once it has nothing left in any
        // window. Forgetting it as soon as its connections close would hand
        // it a fresh allowance for the price of connecting again.
        self.by_address.retain(|address, limiter| {
            open.contains(address) || limiter.has_recent_breach() || !limiter.is_idle()
        });
    }
}

/// The budget, across all a node's connections, for reading a frame from
/// an unlisted peer that is longer than a small message (decision
/// 2026-10-22 (memory), rule 2). At most `LARGE_MESSAGES_AT_ONCE` are held
/// at once, and at most one for each /24 (IPv4) or /48 (IPv6) of the
/// peers' addresses: a peer needs that many subnets to hold them all.
///
/// A device of this version never needs one: every frame it sends fits a
/// small message (rules 3 and 5). So no number of slow peers of the
/// version before holds up an honest device of this version by holding
/// permits.
pub struct LargePermits {
    inner: std::sync::Mutex<Permits>,
    /// Woken when a permit is let go, a subnet's hold is let go, or a
    /// waiter leaves the queue: every waiter then re-checks.
    freed: tokio::sync::Notify,
}

struct Permits {
    /// How many of `LARGE_MESSAGES_AT_ONCE` are free.
    free: usize,
    /// The subnets that hold a permit: at most one each.
    held: std::collections::HashSet<String>,
    /// The waiters, each a ticket and the subnet it waits for, in the
    /// order they asked. The first to ask is the first served (decision
    /// 2026-10-22 (memory), rule 2): a waiter is granted a free permit
    /// only when no earlier waiter's subnet is free, so a holder that
    /// lets go and asks again (a new ticket at the back) cannot jump an
    /// older waiter.
    waiting: std::collections::VecDeque<(u64, String)>,
    /// The next ticket to hand out.
    next_ticket: u64,
}

impl Permits {
    /// Whether the waiter `ticket` for `subnet` may take a permit now: one
    /// is free, its subnet holds none, and no waiter that asked earlier
    /// has a free subnet (so the earlier one goes first).
    fn may_grant(&self, ticket: u64, subnet: &str) -> bool {
        self.free > 0
            && !self.held.contains(subnet)
            && !self
                .waiting
                .iter()
                .any(|(t, s)| *t < ticket && !self.held.contains(s))
    }

    fn drop_waiter(&mut self, ticket: u64) {
        self.waiting.retain(|(t, _)| *t != ticket);
    }
}

/// A held large permit. Dropping it gives the permit back and lets go of
/// its subnet's hold, whether the stream was answered or failed (decision
/// 2026-10-22 (memory), rule 2).
pub struct LargePermit<'a> {
    permits: &'a LargePermits,
    subnet: String,
}

impl Drop for LargePermit<'_> {
    fn drop(&mut self) {
        {
            let mut p = self.permits.inner.lock().unwrap_or_else(|e| e.into_inner());
            p.free += 1;
            p.held.remove(&self.subnet);
        }
        // Every waiter re-checks: the earliest eligible one takes it.
        self.permits.freed.notify_waiters();
    }
}

impl LargePermits {
    pub fn new(budget: usize) -> Self {
        Self {
            inner: std::sync::Mutex::new(Permits {
                free: budget,
                held: std::collections::HashSet::new(),
                waiting: std::collections::VecDeque::new(),
                next_ticket: 0,
            }),
            freed: tokio::sync::Notify::new(),
        }
    }

    /// Take a permit for the subnet of `address`, waiting at most
    /// `STREAM_TIMEOUT` for one. `None` where none came in time: the
    /// caller refuses the stream with `ERR_LARGE_MESSAGE_LATER`, and
    /// counts no breach. A permit is given for a subnet that holds none,
    /// while one of `LARGE_MESSAGES_AT_ONCE` is free and no earlier waiter
    /// is eligible; a waiter whose subnet already holds a permit waits for
    /// that one.
    pub(crate) async fn take(&self, address: std::net::IpAddr) -> Option<LargePermit<'_>> {
        let subnet = cordelia_network::rate_limit::subnet_key(address);
        // Join the queue, in the order of asking.
        let ticket = {
            let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let ticket = p.next_ticket;
            p.next_ticket += 1;
            p.waiting.push_back((ticket, subnet.clone()));
            ticket
        };
        // Leave the queue if this future is dropped before the ticket is
        // granted (decision 2026-10-22 (memory), rule 2). A `take` can be
        // cancelled by an outer `timeout`, a `select!`, a task abort or a
        // runtime shutdown; without this, the ticket would stay, and
        // `may_grant` would hold every later waiter back for good even with
        // permits free. The guard also serves the plain timeout below, in
        // place of the cleanup that path once did on its own.
        struct Leave<'a> {
            permits: &'a LargePermits,
            ticket: u64,
            granted: bool,
        }
        impl Drop for Leave<'_> {
            fn drop(&mut self) {
                if self.granted {
                    return;
                }
                {
                    let mut p = self.permits.inner.lock().unwrap_or_else(|e| e.into_inner());
                    p.drop_waiter(self.ticket);
                }
                // Let a waiter this one was holding back re-check.
                self.permits.freed.notify_waiters();
            }
        }
        let mut leave = Leave {
            permits: self,
            ticket,
            granted: false,
        };
        let wait = tokio::time::timeout(cordelia_network::codec::STREAM_TIMEOUT, async {
            loop {
                // Register for a wake before the state is read, so a
                // permit let go between the read and the wait is not
                // missed.
                let woken = self.freed.notified();
                tokio::pin!(woken);
                woken.as_mut().enable();
                {
                    let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                    if p.may_grant(ticket, &subnet) {
                        p.free -= 1;
                        p.held.insert(subnet.clone());
                        p.drop_waiter(ticket);
                        // Another permit may now be free for a later
                        // waiter; let them re-check.
                        drop(p);
                        self.freed.notify_waiters();
                        return;
                    }
                }
                woken.await;
            }
        })
        .await;
        match wait {
            Ok(()) => {
                // Granted: the grant already took the ticket out of the
                // queue, so the guard must leave it alone.
                leave.granted = true;
                Some(LargePermit {
                    permits: self,
                    subnet,
                })
            }
            // Timed out: the guard leaves the queue and wakes a waiter this
            // one was holding back.
            Err(_) => None,
        }
    }
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

/// Whether a node answers a request for peers with the peers it knows. A
/// personal node answers with an empty list, whatever it is connected to:
/// a person's relays are theirs, and a device is never the way that one
/// relay learns of another (decision 2026-10-14). It still answers, as
/// Peer-Sharing runs on every warm and hot peer.
fn shares_peers(node_role: &str) -> bool {
    node_role != "personal"
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
    peer_rates: &std::sync::Arc<std::sync::Mutex<Rates>>,
    peer_states: &std::sync::Arc<std::sync::RwLock<std::collections::HashMap<NodeId, u8>>>,
    peer_relays: &std::sync::Arc<std::sync::RwLock<std::collections::HashSet<NodeId>>>,
    gov_tx: &tokio::sync::mpsc::UnboundedSender<GovEvent>,
    relay_addrs: &RelayAddrs,
    relay_entries: &Option<std::sync::Arc<crate::relay_entries::RelayEntries>>,
    large_permits: &std::sync::Arc<LargePermits>,
) {
    // Step 1: Extract peer roles from handshake
    let (says_relay, is_bootnode) = conn_mgr
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

    // A node's relays are the ones it was configured with: being a relay
    // is a property of a configured key (or, for a relay configured without
    // one, of its address), never of what a peer says about itself in the
    // handshake. A stranger that says "relay" is an ordinary peer.
    let is_relay = is_configured_relay(relay_addrs, conn_mgr, node_id, says_relay);
    if says_relay && !is_relay {
        tracing::info!(peer = %node_id, "peer says it is a relay but is not one of ours; treating it as an ordinary peer");
    }

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

    // Step 6a: the connected peers, as the local API says them. They
    // are said at each tick of the governor: said here too, a command
    // that asks what is still to send to a relay straight after the
    // relay was reached is not answered from a list that was made before
    // the connection, in which no relay is connected and so nothing
    // waits anywhere (decision 2026-10-04 §8, §9).
    let connected: Vec<&cordelia_network::governor::PeerInfo> = governor
        .all_peers()
        .filter(|p| {
            matches!(
                p.state,
                cordelia_network::governor::PeerState::Hot
                    | cordelia_network::governor::PeerState::Warm
            )
        })
        .collect();
    publish_peers(state, &connected, conn_mgr);

    // Step 6b: Sync peer states for protocol gating (§2.1)
    // Without this, a stream handler rejects requests from peers promoted
    // during bootstrap/accept (before first governor tick syncs peer_states).
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

    // Step 6c: Sync relay peer set, which keeps a node from cutting off a
    // relay of its own on any stream
    if let Ok(mut relays) = peer_relays.write() {
        for peer in governor.all_peers() {
            if peer.is_relay {
                relays.insert(peer.node_id.clone());
            }
        }
    }

    // Step 8: Spawn stream handler
    if let Some(conn) = conn_mgr.get_connection(node_id) {
        let conn = conn.clone();
        let peer_id = node_id.clone();
        // The address that the peer's requests are counted under, for as
        // long as the connection lasts: the one it was made from, read
        // once (decision 2026-10-04 §16).
        let made_from = conn_mgr
            .address_of(node_id)
            .unwrap_or_else(|| conn.remote_address().ip());
        let db_state = state.clone();
        let peers_ref = shared_peers.clone();
        let role = node_role.to_string();
        let rates = peer_rates.clone();
        let states = peer_states.clone();
        let relays = peer_relays.clone();
        let gtx = gov_tx.clone();
        let entries = relay_entries.clone();
        let permits = large_permits.clone();
        tokio::spawn(async move {
            handle_peer_streams(
                conn, peer_id, made_from, db_state, peers_ref, role, rates, states, relays, gtx,
                entries, permits,
            )
            .await;
        });
    }
}

/// Background task that accepts incoming QUIC connections, runs a
/// device's and a relay's passes, and manages peer lifecycle.
#[expect(
    clippy::too_many_arguments,
    reason = "config args move into a struct when the relay work reshapes this loop"
)]
pub async fn p2p_loop(
    mut conn_mgr: cordelia_network::connection::ConnectionManager,
    state: web::Data<cordelia_api::state::AppState>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    allow_private_addresses: bool,
    node_role: String,
    gov_config: cordelia_core::config::GovernorConfig,
    relays_set_up: Vec<cordelia_network::bootstrap::Relay>,
    relay_addrs: RelayAddrs,
    max_storage_bytes: u64,
    relay_ask_again: std::time::Duration,
    most_proved: usize,
    reach: Option<std::sync::Arc<cordelia_node::device_entries::Reach>>,
    members_read: std::time::Duration,
) {
    tracing::info!(role = %node_role, "P2P loop started (accept + passes + peer-sharing)");

    // Shared peer list
    let shared_peers: std::sync::Arc<
        std::sync::RwLock<Vec<cordelia_network::messages::PeerAddress>>,
    > = std::sync::Arc::new(std::sync::RwLock::new(conn_mgr.known_peer_addresses()));

    let our_node_id = NodeId(state.identity.public_key());

    // The node's counters (decision 2026-10-22 §7.3): its connections, the
    // closures of the link to each relay it is set up with, and its
    // governor count in them.
    conn_mgr.count_into(state.load.connections.clone());
    for key in relays_set_up.iter().filter_map(|relay| relay.key) {
        state.load.connections.counts_relay(&key);
    }
    let mut governor = governor_for(&node_role, &gov_config).counting(state.load.governor.clone());

    // Connection tracker (§3.1): per-IP, per-subnet, global limits

    // Per-peer rate limiters, shared with handle_peer_streams tasks
    let peer_rates: std::sync::Arc<std::sync::Mutex<Rates>> =
        std::sync::Arc::new(std::sync::Mutex::new(Rates::default()));
    // Addresses refused for a time, after a peer there kept going over its
    // limits. An address, since a key costs nothing to replace.
    let mut refused_addresses: std::collections::HashMap<std::net::IpAddr, std::time::Instant> =
        std::collections::HashMap::new();
    // Inbound connections that have arrived and not finished their
    // handshake. They count towards the limits for an address at once.
    let arriving: std::sync::Arc<std::sync::Mutex<Vec<std::net::IpAddr>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    // Shared peer state map for protocol gating (connection-lifecycle.md §2.2 Option A).
    // Governor tick updates this; handle_peer_streams reads it to gate protocols by state.
    // 0=Cold, 1=Warm, 2=Hot
    let peer_states: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<NodeId, u8>>> =
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));

    // Shared set of relay peer IDs. Used for relay detection after handshake (§7.2).
    let peer_relays: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<NodeId>>> =
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new()));

    // Governor event channel (created before bootstrap so post_connect can pass it)
    let (gov_tx, mut gov_rx) = tokio::sync::mpsc::unbounded_channel::<GovEvent>();

    // What a relay holds for the entries of channels from their secrets
    // (decision 2026-10-04 §2.4, §2.5): its room for them, with a cap of
    // the size of the older kind's, and the relays it works with. A node
    // of any other role has none, and answers none of their streams.
    let relay_entries: Option<std::sync::Arc<crate::relay_entries::RelayEntries>> =
        crate::relay_entries::kept_by(&node_role).then(|| {
            std::sync::Arc::new(
                crate::relay_entries::RelayEntries::new(
                    max_storage_bytes,
                    relay_addrs.clone(),
                    relay_ask_again,
                )
                .remembering_at_most(most_proved)
                .counting(state.load.streams.clone()),
            )
        });
    // The large permits, across all this node's connections (decision
    // 2026-10-22 (memory), rule 2): under them a frame longer than a small
    // message from an unlisted peer is read. Every node keeps them; a
    // device of this version never needs one.
    let large_permits = std::sync::Arc::new(LargePermits::new(
        cordelia_core::protocol::LARGE_MESSAGES_AT_ONCE,
    ));
    // The cap is read here, when the node starts, and at no other time:
    // a relay whose cap came down drops its newest channels now.
    if let Some(entries) = &relay_entries {
        entries.make_room(&state.db);
    }
    // How many relays the node is set up with is said here, from the list
    // that every pass is made of: the two cannot come to differ.
    // Each relay once: a name given the same key as one before it is that
    // relay (decision 2026-10-17 §1). Each pass says it again, from the
    // connections there are then.
    {
        let none: Vec<Option<NodeId>> = vec![None; relays_set_up.len()];
        let addrs: Vec<Option<std::net::SocketAddr>> = vec![None; relays_set_up.len()];
        let one = one_relay_each(&relays_set_up, &none, &addrs, &|_| None);
        let counted = one
            .iter()
            .filter(|one| !matches!(one, OneRelay::SameAs(_)))
            .count();
        state.own_channels.set_up_with(counted);
    }
    // A device's side of its relays, for the channels of its own
    // (decision 2026-10-04 §4.6): the show, the leave it gives, and the
    // passes that prove, pull and push. Only a personal node has one, and
    // it does nothing on a device that follows no phrase.
    let device_entries = (node_role == "personal").then(|| {
        let clock = cordelia_node::device_entries::Clock::system();
        let reach = reach
            .clone()
            .unwrap_or_else(|| cordelia_node::device_entries::Reach::new(clock.clone()));
        cordelia_node::device_entries::DeviceEntries::reaching(
            state.clone().into_inner(),
            clock,
            most_proved,
            reach,
        )
    });
    // Whether each relay can be reached (decision 2026-10-19 §1): the
    // dial loop says when it dials, and a relay that lacks the change is
    // dialled at the pace of a node that is cut off (rule 3).
    let reach = device_entries.as_ref().map(|device| device.reach().clone());

    // Register bootstrap peers using canonical sequence
    for peer_id in conn_mgr.connected_peers() {
        post_connect(
            &peer_id,
            &conn_mgr,
            &mut governor,
            &shared_peers,
            &state,
            &node_role,
            &peer_rates,
            &peer_states,
            &peer_relays,
            &gov_tx,
            &relay_addrs,
            &relay_entries,
            &large_permits,
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

    // The send pass of a device, every OUTBOX_FLUSH_INTERVAL_SECS.
    let mut outbox_interval = tokio::time::interval(std::time::Duration::from_secs(
        cordelia_core::protocol::OUTBOX_FLUSH_INTERVAL_SECS,
    ));
    outbox_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    outbox_interval.tick().await;

    // Expired keyed tombstones (decision 2026-09-30 §4.4), on every node.
    let mut gc_interval = tokio::time::interval(std::time::Duration::from_secs(
        cordelia_core::protocol::TOMBSTONE_GC_INTERVAL_SECS,
    ));
    gc_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // The channels of entries that nobody uses (decision 2026-10-04 §2.5),
    // on a relay: when it starts, and each hour after.
    let mut entry_sweep_interval = tokio::time::interval(std::time::Duration::from_secs(
        cordelia_core::protocol::ENTRY_CHANNEL_SWEEP_INTERVAL_SECS,
    ));
    entry_sweep_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The uses of channels that a relay keeps in memory (issue #214): a
    // proof and a show are reads, and the uses are written once a minute.
    let mut relay_uses_interval = tokio::time::interval(std::time::Duration::from_secs(
        cordelia_core::protocol::RELAY_USES_WRITE_INTERVAL_SECS,
    ));
    relay_uses_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The checkpoint of a relay's store (issue #224), in a take of the
    // lock of its own: its connection has SQLite's automatic checkpoint
    // off. A tick each second from when it starts, which checkpoints once
    // the log holds RELAY_CHECKPOINT_LOG_PAGES.
    let mut relay_checkpoint_interval = tokio::time::interval(std::time::Duration::from_secs(
        cordelia_core::protocol::RELAY_CHECKPOINT_INTERVAL_SECS,
    ));
    relay_checkpoint_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The hourly task of messages (decision 2026-10-09 §7.1), on a
    // personal node: when it starts, and each hour after.
    let mut messages_interval = tokio::time::interval(std::time::Duration::from_secs(
        cordelia_core::protocol::AGENT_MESSAGE_CLEAR_INTERVAL_SECS,
    ));
    messages_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The read of each repository's list the device follows (decision
    // 2026-11-06 (joining), rules 3 and 4), on a personal node: when it
    // starts, and every MEMBERS_READ_INTERVAL_SECS after: a test sets it
    // lower (`[members] read_interval_secs`).
    let mut members_interval = tokio::time::interval(members_read);
    members_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Entries between relays that work together (§2.4 item 6): what a
    // relay took is passed on, and what it lacks is pulled.
    let mut entry_offer_interval = tokio::time::interval(std::time::Duration::from_secs(
        cordelia_core::protocol::ENTRY_OFFER_INTERVAL_SECS,
    ));
    entry_offer_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    entry_offer_interval.tick().await;
    let mut entry_pull_interval = tokio::time::interval(std::time::Duration::from_secs(
        cordelia_core::protocol::RELAY_ENTRY_PULL_INTERVAL_SECS,
    ));
    entry_pull_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    entry_pull_interval.tick().await;

    // P2P telemetry counters
    let mut select_iterations: u64 = 0;
    let mut heartbeat_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat_interval.tick().await;

    // The loop begins after a wait of up to REPUSH_INTERVAL_SECS, set by the
    // node's key, as it did while it re-pushed the older kind (decision
    // 2026-11-10 (older kind), rule 3). So nodes do not all begin at once,
    // and a device's whole pass keeps its place apart from its reads of the
    // lists it follows, whose timer starts with the loop: a read that types
    // a key again while a pass asks for it leaves it unasked.
    let start_after = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        our_node_id.0.hash(&mut h);
        h.finish() % (cordelia_core::protocol::REPUSH_INTERVAL_SECS * 1000)
    };
    tokio::time::sleep(std::time::Duration::from_millis(start_after)).await;

    // The configured relays: each one that is not connected is dialled
    // again, at a slowing pace (see `relay_backoff`).
    let mut relay_interval = tokio::time::interval(std::time::Duration::from_secs(1));
    relay_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut relay_tries: std::collections::HashMap<TriedRelay, RelayTry> =
        std::collections::HashMap::new();
    // The relays that each dial in flight was begun for.
    let mut dialling: Dialling = Default::default();
    // The relays that a wake has yet to have dialled.
    let mut wake_dials = WakeDials::default();

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
    // A dial that failed: its address, its error, and how it ended
    // (decision 2026-10-24 (removal), section 8).
    type ConnectMsg = Result<
        cordelia_network::connection::ConnectOutcome,
        (std::net::SocketAddr, String, DialEnd),
    >;
    let (connect_tx, mut connect_rx) = tokio::sync::mpsc::unbounded_channel::<ConnectMsg>();
    let (discovery_tx, mut discovery_rx) =
        tokio::sync::mpsc::unbounded_channel::<Vec<cordelia_network::messages::PeerAddress>>();
    let mut sightings = Sightings::default();
    let mut in_flight: std::collections::HashSet<std::net::SocketAddr> =
        std::collections::HashSet::new();
    let mut gov_pending: std::collections::HashMap<std::net::SocketAddr, NodeId> =
        std::collections::HashMap::new();
    const MAX_IN_FLIGHT: usize = 10;
    const CONNECTS_PER_CYCLE: usize = 3;

    loop {
        select_iterations += 1;
        tokio::select! {
            // ── P2P heartbeat (30s telemetry) ────────────────────────
            _ = heartbeat_interval.tick() => {
                let (hot, warm, _cold, _banned) = governor.counts();
                tracing::info!(
                    iterations = select_iterations,
                    hot_peers = hot,
                    warm_peers = warm,
                    "p2p heartbeat"
                );
            }

            // ── Accept incoming connection (non-blocking) ─────────────
            result = endpoint.accept() => {
                match result {
                    Some(incoming) => {
                        // Counted as it arrives, before the cost of a
                        // handshake: an address that is refused for a time,
                        // or already has its share of connections (open or
                        // still arriving), is turned away here.
                        let address = incoming.remote_address().ip();
                        let refused = refused_addresses
                            .get(&address)
                            .is_some_and(|until| *until > std::time::Instant::now());
                        let turned_away = match refused {
                            true => Some(cordelia_core::load::TurnedAway::RefusedForATime),
                            false => {
                                let arriving = arriving.lock().unwrap_or_else(|e| e.into_inner());
                                cordelia_network::rate_limit::ConnectionTracker::from_ips(
                                    conn_mgr
                                        .inbound_ips(&NodeId([0u8; 32]))
                                        .into_iter()
                                        .chain(arriving.iter().copied()),
                                )
                                .turns_away(address)
                            }
                        };
                        if let Some(why) = turned_away {
                            // Counted by why (decision 2026-10-22 §1.2).
                            state.load.connections.turned_away(why);
                            tracing::debug!(%address, refused, "turning an inbound connection away before the handshake");
                            incoming.refuse();
                            continue;
                        }
                        arriving.lock().unwrap_or_else(|e| e.into_inner()).push(address);
                        let ctx = connect_ctx.clone();
                        let tx = connect_tx.clone();
                        let arriving = arriving.clone();
                        let relays = relay_addrs.clone();
                        tokio::spawn(async move {
                            let accepted = accept_incoming(&ctx, incoming, &relays).await;
                            {
                                let mut arriving = arriving.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(at) = arriving.iter().position(|a| *a == address) {
                                    arriving.swap_remove(at);
                                }
                            }
                            match accepted {
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
                            // A configured relay must answer with its key:
                            // each one at this address is judged by the key
                            // that answered (decision 2026-10-17 §1).
                            let dialled = relay_addrs
                                .read()
                                .map(|relays| relays.clone())
                                .unwrap_or_default();
                            let any_connected = any_relay_connected(&relays_set_up, &relay_addrs, &conn_mgr);
                            let waking = is_waking(&device_entries);
                            let (answers, refused) = dial_answered(
                                &mut relay_tries,
                                &mut dialling,
                                (&relays_set_up, &dialled),
                                (addr, &outcome.node_id.0),
                                (p2p_gov_tick_secs, any_connected),
                                reach.as_deref(),
                            );
                            if let Some(device) = &device_entries {
                                device.dial_failed(waking);
                            }
                            if answers.is_empty() && !refused.is_empty() {
                                outcome.conn.close(0u32.into(), b"not the relay");
                                continue;
                            }
                        }

                        // Connection tracker check FIRST (inbound only, §3.1).
                        // The limits count the inbound connections open now.
                        if direction == Direction::Inbound {
                            let ip = outcome.addr.ip();
                            let open = cordelia_network::rate_limit::ConnectionTracker::from_ips(
                                conn_mgr.inbound_ips(&outcome.node_id),
                            );
                            if let Some(why) = open.turns_away(ip) {
                                state.load.connections.turned_away(why);
                                tracing::warn!(peer = %outcome.node_id, ip = %ip, "rejecting: connection limit exceeded");
                                outcome.conn.close(0u32.into(), b"limit");
                                continue;
                            }
                        }

                        // Personal nodes are outbound-only (§8.2).
                        if direction == Direction::Inbound && node_role == "personal" {
                            tracing::debug!(peer = %outcome.node_id, "rejecting inbound: personal nodes are outbound-only");
                            outcome.conn.close(0u32.into(), b"outbound-only");
                            continue;
                        }

                        if direction == Direction::Outbound {
                            gov_pending.remove(&addr);
                        }
                        // A peer that was cut off for going over its limits
                        // is not taken back until its time is up, whichever
                        // address it comes from.
                        if direction == Direction::Inbound
                            && governor
                                .peer_info(&outcome.node_id)
                                .is_some_and(|peer| peer.state.is_banned())
                        {
                            tracing::debug!(peer = %outcome.node_id, "refusing a peer that was cut off");
                            outcome.conn.close(
                                quinn::VarInt::from_u32(cordelia_core::protocol::ERR_RATE_LIMIT),
                                b"refused for a time",
                            );
                            continue;
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
                                // Which relay the connection is, before the
                                // peers list it (decision 2026-10-24, rule 2).
                                publish_relays_now(&state, &relays_set_up, &relay_addrs, &relay_tries, &conn_mgr);
                                post_connect(
                                    &node_id, &conn_mgr, &mut governor, &shared_peers,
                                    &state, &node_role, &peer_rates, &peer_states, &peer_relays, &gov_tx,
                                    &relay_addrs, &relay_entries, &large_permits,
                                );
                            }
                            Err(e) => {
                                tracing::debug!(addr = %addr, error = %e, "register failed");
                            }
                        }
                    }
                    Err((addr, error, ended)) => {
                        in_flight.remove(&addr);
                        if let Some(nid) = gov_pending.remove(&addr) {
                            governor.mark_dial_failed(&nid);
                        }
                        tracing::debug!(addr = %addr, error = %error, "outbound connect failed");
                        let dialled = relay_addrs
                            .read()
                            .map(|relays| relays.clone())
                            .unwrap_or_default();
                        let any_connected = any_relay_connected(&relays_set_up, &relay_addrs, &conn_mgr);
                        let waking = is_waking(&device_entries);
                        dial_errored(
                            &mut relay_tries,
                            &mut dialling,
                            (&relays_set_up, &dialled),
                            (addr, error, ended),
                            (p2p_gov_tick_secs, any_connected),
                            reach.as_deref(),
                        );
                        // A wake waits no more for a relay whose dial
                        // failed since it began (decision 2026-10-24
                        // (removal), section 8): where this ends it, a
                        // whole pass is made at once.
                        if let Some(device) = &device_entries {
                            device.dial_failed(waking);
                        }
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

            // ── Configured relays ─────────────────────────────────────
            // Dial each configured relay that is not connected and is due
            // another attempt, and publish where each one stands.
            _ = relay_interval.tick() => {
                let relays = relay_addrs.read().map(|r| r.clone()).unwrap_or_default();
                let now = std::time::Instant::now();
                let settled = std::time::Duration::from_secs(p2p_gov_tick_secs.max(1));
                with_tick(&relays_set_up, &relays, &conn_mgr, |at| {
                let any_connected = any_connected_as_itself(at);
                // A relay that came to lack the change is dialled within
                // BACKOFF_BASE_SECS, whatever wait was set (rule 3).
                if let Some(reach) = &reach {
                    cut_waits(&mut relay_tries, &reach.came_to_lack(), now);
                    // A device that woke dials each relay that it does
                    // not reach at once: one that is down is then known
                    // to be by a dial that timed out since the wake
                    // began, and one that came back is asked within the
                    // wake (decision 2026-10-24 (removal), section 8).
                    if reach.dials_at_wake() {
                        wake_dials.woke(&relays, now);
                    }
                }
                for relay in &relays {
                    wake_dials.cut(&mut relay_tries, relay, now);
                    let tick = Tick {
                        now,
                        settled,
                        secs: p2p_gov_tick_secs,
                        any_connected,
                        busy: in_flight.contains(&relay.addr) || in_flight.len() >= MAX_IN_FLIGHT,
                    };
                    let dials = relay_turn(
                        &mut relay_tries,
                        &mut dialling,
                        (at, relay),
                        tick,
                        reach.as_deref(),
                    );
                    if !dials {
                        continue;
                    }
                    wake_dials.dialled(relay);
                    in_flight.insert(relay.addr);
                    let ctx = connect_ctx.clone();
                    let tx = connect_tx.clone();
                    let addr = relay.addr;
                    let relay = relay.clone();
                    let keys = keys_to_answer(&relays, addr);
                    tracing::debug!(relay = %relay.host, %addr, "dialling relay");
                    tokio::spawn(async move {
                        let _ = tx.send(dial_configured(&ctx, &relay, keys.as_deref()).await);
                    });
                }
                });
                publish_relays(&state, &relays_set_up, &relays, &relay_tries, &conn_mgr);
            }

            // ── Peer-sharing (spawn discovery + connects) ─────────────
            // (a) Request addresses from a peer whose cooldown has expired (spawned).
            // (b) Spawn up to CONNECTS_PER_CYCLE candidates from the cache.
            //
            // Not for a personal node or a relay: their network is the
            // relays they were configured with, and they dial no address a
            // peer hands them.
            _ = peer_share_interval.tick(), if node_role != "personal" && node_role != "relay" => {
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
                        if let Some(addr_str) = peer_addr.addrs.first()
                            && let Ok(addr) = addr_str.parse::<std::net::SocketAddr>()
                        {
                            if in_flight.contains(&addr) { continue; }
                            in_flight.insert(addr);
                            let ctx = connect_ctx.clone();
                            let tx = connect_tx.clone();
                            tokio::spawn(async move {
                                match cordelia_network::connection::outbound_connect(&ctx, addr).await {
                                    Ok(outcome) => { let _ = tx.send(Ok(outcome)); }
                                    Err(e) => {
                                        tracing::debug!(addr = %addr, error = %e, "peer-share connect failed");
                                        let _ = tx.send(Err((addr, e.to_string(), DialEnd::of(&e))));
                                    }
                                }
                            });
                            spawned += 1;
                        }
                    }
                    peer_share_rotation = peer_share_rotation.wrapping_add(spawned);
                }
            }

            // What waits in a channel of the device's own is sent on this
            // timer, through the leave that a show gives.
            _ = outbox_interval.tick(), if device_entries.is_some() => {
                device_pass(&device_entries, &relays_set_up, &relay_addrs, &conn_mgr, &state.own_channels, cordelia_node::device_entries::Pass::Send);
            }

            // Something was written in a channel of the device's own: it
            // is sent without waiting for the timer, through that leave.
            _ = state.own_channels.wait_written(), if device_entries.is_some() => {
                device_pass(&device_entries, &relays_set_up, &relay_addrs, &conn_mgr, &state.own_channels, cordelia_node::device_entries::Pass::Send);
            }

            // A command asked for a whole pass: the show to each relay,
            // and the fetch, before it prepares a change; the first show
            // of a new phrase; the asking for what a typed key's device
            // hands over (decision 2026-10-04 §5.1, §5.2, §7.1).
            _ = state.own_channels.wait_asked(), if device_entries.is_some() => {
                device_pass(&device_entries, &relays_set_up, &relay_addrs, &conn_mgr, &state.own_channels, cordelia_node::device_entries::Pass::Whole);
            }

            // A command's work asked something through the door for a
            // carry: a channel of a generation that the device has left
            // or never followed, read at each relay (decision 2026-10-04
            // §7.3, §9). Off the select loop: it waits on the relays.
            ask = state.own_channels.wait_door(), if device_entries.is_some() => {
                let relays = relays_with_links(&relays_set_up, &relay_addrs, &conn_mgr, &state.own_channels);
                match (ask, device_entries.clone()) {
                    // The connection to a relay is made again (decision
                    // 2026-10-04 §16): a read of a generation that was
                    // left has no room there for another proof, and a
                    // relay remembers the proofs of a connection for
                    // that connection alone. It is closed here, and the
                    // relay is dialled anew as any relay that is not
                    // connected is: nothing is kept of the tries before.
                    (cordelia_api::state::DoorAsk::Remake { relay, peer, answer }, _) => {
                        let peer = to_make_again(peer, &relay, &relays, &|peer| conn_mgr.is_connected(peer));
                        if let Some(peer) = &peer {
                            tracing::info!(%relay, "the connection to a relay is made again: it has no room left for a proof");
                            let addr = conn_mgr.get_connection(peer).map(|conn| conn.remote_address());
                            conn_mgr.disconnect(peer);
                            let resolved = relay_addrs.read().map(|r| r.clone()).unwrap_or_default();
                            forget_tries(&mut relay_tries, &resolved, peer, addr);
                        }
                        let _ = answer.send(peer.is_some());
                    }
                    (ask, Some(device)) => {
                        tokio::spawn(async move { device.door(&relays, ask).await });
                    }
                    (_, None) => {}
                }
            }

            // A command's work asked for a read of a channel of the
            // device's own with places of its own: the read before a
            // carried name is let go (decision 2026-10-17 §4.2). Off the
            // select loop: it waits on the relays.
            ask = state.own_channels.wait_own(), if device_entries.is_some() => {
                let relays = relays_with_links(&relays_set_up, &relay_addrs, &conn_mgr, &state.own_channels);
                if let Some(device) = device_entries.clone() {
                    tokio::spawn(async move { device.own(&relays, ask).await });
                }
            }

            // ── Messages between the person's own agents, on a device ─
            // What has expired goes from the index, written over first,
            // and the log is truncated (decision 2026-10-09 §7.1). Off
            // the select loop: it writes under the db lock.
            _ = messages_interval.tick(), if device_entries.is_some() => {
                if let Some(device) = device_entries.clone() {
                    tokio::task::spawn_blocking(move || device.messages_hourly());
                }
            }

            // ── The lists of the repositories the device follows ─────
            // Each clone is read with git, and what each list says is done
            // (decision 2026-11-06 (joining), rules 3 and 4). Off the
            // select loop: git may take seconds, and each read writes
            // under the db lock.
            _ = members_interval.tick(), if device_entries.is_some() => {
                if let Some(device) = device_entries.clone() {
                    tokio::task::spawn_blocking(move || device.read_members());
                }
            }

            // A person followed a repository: its list is read now, not at
            // the next tick.
            _ = state.own_channels.wait_members_read(), if device_entries.is_some() => {
                if let Some(device) = device_entries.clone() {
                    tokio::task::spawn_blocking(move || device.read_members());
                }
            }

            // ── Entries of channels from their secrets, on a relay ────
            // What nobody uses goes after 90 days (decision 2026-10-04
            // §2.5). Off the select loop: it writes under the db lock.
            _ = entry_sweep_interval.tick(), if relay_entries.is_some() => {
                if let Some(entries) = relay_entries.clone() {
                    let sweep_state = state.clone();
                    tokio::task::spawn_blocking(move || entries.sweep(&sweep_state.db));
                }
            }

            // The uses of channels it kept are written, in one
            // transaction (issue #214). Off the select loop: it writes
            // under the db lock.
            _ = relay_uses_interval.tick(), if relay_entries.is_some() => {
                if let Some(entries) = relay_entries.clone() {
                    let uses_state = state.clone();
                    tokio::task::spawn_blocking(move || entries.write_uses(&uses_state.db));
                }
            }

            // The store's log is written back once it is long enough
            // (issue #224). Off the select loop: it writes under the db
            // lock. A tick that finds the last still running does nothing.
            _ = relay_checkpoint_interval.tick(), if relay_entries.is_some() => {
                if let Some(entries) = relay_entries.clone() {
                    let checkpoint_state = state.clone();
                    tokio::task::spawn_blocking(move || entries.checkpoint(&checkpoint_state.db));
                }
            }

            // What this relay took is passed on to the relays it works
            // with that are connected (§2.4 item 6).
            _ = entry_offer_interval.tick(), if relay_entries.is_some() => {
                if let Some(entries) = &relay_entries {
                    let relays = crate::relay_entries::listed_and_connected(entries, &conn_mgr);
                    entries.pass_on(&state.db, relays);
                }
            }

            // And it asks each of them what it holds, and pulls what it
            // lacks.
            _ = entry_pull_interval.tick(), if relay_entries.is_some() => {
                if let Some(entries) = &relay_entries {
                    let relays = crate::relay_entries::listed_links(entries, &conn_mgr);
                    crate::relay_entries::pull_from_each(entries, &state, relays);
                }
            }

            // ── Old deletes (§4.4; decision 2026-10-04 §2.3, §7.3) ────
            // One timer, and one length of time, for a relay and a
            // device. Off the select loop: each writes under the db lock.
            _ = gc_interval.tick() => {
                // Of the entries of channels from their secrets: a relay
                // sweeps what it holds, and a device its own store.
                if let Some(entries) = relay_entries.clone() {
                    let sweep_state = state.clone();
                    tokio::task::spawn_blocking(move || entries.sweep_deletes(&sweep_state.db));
                }
                if let Some(device) = device_entries.clone() {
                    tokio::task::spawn_blocking(move || device.sweep_deletes());
                }
            }

            // ── A device's whole pass ───────────────────────────────
            // Its own channels, at each relay it is set up with: it shows
            // its change entry, and then proves, pulls and pushes where the
            // answer gives it leave. That is all a node fetches (decision
            // 2026-11-10 (older kind), rule 7).
            _ = sync_interval.tick() => {
                if node_role == "bootnode" { continue; }
                device_pass(&device_entries, &relays_set_up, &relay_addrs, &conn_mgr, &state.own_channels, cordelia_node::device_entries::Pass::Whole);
            }

            // ── Events from the stream handlers ───────────────────────
            // Taken as they arrive: a peer that is cut off must find its
            // address refused at once, not at the next tick.
            Some(event) = gov_rx.recv() => {
                apply_gov_event(event, &mut governor, &mut conn_mgr, &mut refused_addresses);
            }

            // ── Governor tick ─────────────────────────────────────────
            _ = gov_interval.tick() => {
                while let Ok(event) = gov_rx.try_recv() {
                    apply_gov_event(event, &mut governor, &mut conn_mgr, &mut refused_addresses);
                }
                // Forget addresses whose time is up, and the allowances of
                // peers and addresses that have gone.
                let now = std::time::Instant::now();
                refused_addresses.retain(|_, until| *until > now);
                {
                    let connected = conn_mgr.connected_peers();
                    let open = conn_mgr.inbound_ips(&NodeId([0u8; 32]));
                    peer_rates
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .prune(&connected, &open);
                }
                // Sync with connection manager. Closed connections go first,
                // so a peer that has gone is seen as gone and redialled.
                for peer_id in conn_mgr.reap_closed() {
                    tracing::info!(peer = %peer_id, "connection closed; peer removed");
                }
                let connected = conn_mgr.connected_peers();
                for peer_id in &connected {
                    governor.record_activity(peer_id, None);
                }
                let gov_active: Vec<_> = governor
                    .all_peers()
                    .filter(|p| p.state.is_active())
                    .map(|p| p.node_id.clone())
                    .collect();
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
                                    let _ = tx.send(Err((addr, e.to_string(), DialEnd::of(&e))));
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

                // Sync relay peer set, which keeps a node from cutting off
                // a relay of its own on any stream
                if let Ok(mut relays) = peer_relays.write() {
                    relays.clear();
                    for peer in governor.all_peers() {
                        if peer.is_relay {
                            relays.insert(peer.node_id.clone());
                        }
                    }
                }

                // Connected peers, for `cordelia peers` and the usage counts.
                let connected: Vec<&cordelia_network::governor::PeerInfo> = governor
                    .all_peers()
                    .filter(|p| {
                        matches!(
                            p.state,
                            cordelia_network::governor::PeerState::Hot
                                | cordelia_network::governor::PeerState::Warm
                        )
                    })
                    .collect();
                // Which relay each connection is, before the peers list it
                // or drop it (decision 2026-10-24, rule 2).
                publish_relays_now(&state, &relays_set_up, &relay_addrs, &relay_tries, &conn_mgr);
                publish_peers(&state, &connected, &conn_mgr);
                sightings.note(&state, &connected);

                tracing::info!(hot, warm, cold, banned, "gov: tick complete");
            }

            // ── Shutdown ──────────────────────────────────────────────
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("P2P loop shutting down");
                    // Peers are told, and given one stream timeout to hear
                    // it. One that does not is left to time out.
                    if tokio::time::timeout(
                        std::time::Duration::from_secs(cordelia_core::protocol::STREAM_TIMEOUT_SECS),
                        conn_mgr.shutdown_and_wait(),
                    ).await.is_err() {
                        tracing::warn!("closing the connections took longer than a stream timeout; not waiting for it");
                    }
                    // A relay writes the uses of channels it kept since
                    // its last sweep (issue #214), once no stream asks,
                    // and then checkpoints its store (issue #224).
                    if let Some(entries) = relay_entries.clone() {
                        let stop_state = state.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            entries.write_uses(&stop_state.db);
                            if entries.checkpoint_at_stop(&stop_state.db) {
                                tracing::info!("the store's log was written back and truncated");
                            }
                        })
                        .await;
                    }
                    break;
                }
            }
        }
    }
}

/// The roles a node says in its handshake: the role it is configured
/// with, and, for a relay, the role RELAY_ROLE_HEADS (decision 2026-10-24
/// (removal), rule 18): it keeps every head in a slot and hands each, so a
/// device shows it every head it keeps. A node of the version before reads
/// only "relay" and "bootnode" there, and passes the other over.
pub(crate) fn handshake_roles(role: &str) -> Vec<String> {
    let mut roles = vec![role.to_string()];
    if role == "relay" {
        roles.push(cordelia_core::protocol::RELAY_ROLE_HEADS.to_string());
    }
    roles
}

/// Publish the connected peers to the shared state, for `cordelia peers`.
fn publish_peers(
    state: &cordelia_api::state::AppState,
    connected: &[&cordelia_network::governor::PeerInfo],
    conn_mgr: &cordelia_network::connection::ConnectionManager,
) {
    use cordelia_network::governor::PeerState;
    let mut list: Vec<cordelia_api::state::PeerSnapshot> = connected
        .iter()
        .map(|p| cordelia_api::state::PeerSnapshot {
            key: cordelia_crypto::bech32::encode_public_key(&p.node_id.0).unwrap_or_default(),
            role: if p.is_relay {
                "relay"
            } else if p.is_bootnode {
                "bootnode"
            } else {
                "node"
            }
            .into(),
            state: if p.state == PeerState::Hot {
                "hot"
            } else {
                "warm"
            }
            .into(),
            address: conn_mgr
                .get_connection(&p.node_id)
                .map(|c| c.remote_address().to_string())
                .or_else(|| p.addrs.first().cloned())
                .unwrap_or_default(),
            connected_secs: p.connected_since.map_or(0, |t| t.elapsed().as_secs()),
            idle_secs: p.last_activity.elapsed().as_secs(),
        })
        .collect();
    list.sort_by(|a, b| a.key.cmp(&b.key));
    if let Ok(mut peers) = state.peers.write() {
        *peers = list;
    }
}

/// Notes which peers are connected, for the aggregate usage counts
/// (`cordelia_storage::usage`): each as a hash made with a secret that
/// stays on this node, refreshed every `SIGHTING_REFRESH_SECS` and
/// forgotten `SIGHTING_RETENTION_DAYS` after the peer was last seen.
#[derive(Default)]
struct Sightings {
    secret: Option<[u8; 32]>,
    noted: std::collections::HashMap<NodeId, std::time::Instant>,
    pruned: Option<std::time::Instant>,
}

impl Sightings {
    fn note(
        &mut self,
        state: &cordelia_api::state::AppState,
        connected: &[&cordelia_network::governor::PeerInfo],
    ) {
        use cordelia_core::protocol::{SIGHTING_REFRESH_SECS, SIGHTING_RETENTION_DAYS};
        use cordelia_storage::{meta, usage};

        let refresh = std::time::Duration::from_secs(SIGHTING_REFRESH_SECS);
        let due: Vec<_> = connected
            .iter()
            .filter(|p| {
                self.noted
                    .get(&p.node_id)
                    .is_none_or(|t| t.elapsed() >= refresh)
            })
            .collect();
        let prune_due = self
            .pruned
            .is_none_or(|t| t.elapsed() >= std::time::Duration::from_secs(3600));
        if due.is_empty() && !prune_due {
            return;
        }
        let Ok(db) = state.db.lock() else { return };

        if self.secret.is_none() {
            let stored = meta::get(&db, meta::USAGE_SIGHTING_SECRET)
                .ok()
                .flatten()
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| <[u8; 32]>::try_from(b).ok());
            self.secret = stored.or_else(|| {
                let fresh = cordelia_crypto::generate_psk().ok()?;
                meta::set(&db, meta::USAGE_SIGHTING_SECRET, &hex::encode(fresh)).ok()?;
                Some(fresh)
            });
        }
        let Some(secret) = self.secret else { return };

        let now = chrono::Utc::now().timestamp();
        let seen: Vec<([u8; 32], bool)> = due
            .iter()
            .map(|p| {
                let mut keyed = secret.to_vec();
                keyed.extend_from_slice(&p.node_id.0);
                (cordelia_crypto::sha256(&keyed), p.is_relay)
            })
            .collect();
        let prune_before = prune_due.then(|| now - SIGHTING_RETENTION_DAYS * 86_400);
        // One write for every peer due, and the prune (issue #221).
        let written = usage::record_sightings(&db, &seen, now, prune_before).is_ok();
        drop(db);
        if written {
            for p in due {
                self.noted
                    .insert(p.node_id.clone(), std::time::Instant::now());
            }
        }
        if prune_due {
            self.noted.retain(|_, t| t.elapsed() < refresh);
            self.pruned = Some(std::time::Instant::now());
        }
    }
}

/// The relays a node was configured with, resolved to addresses. The P2P
/// loop dials each one that is not connected; [`keep_relays_resolved`] keeps
/// the addresses current.
pub type RelayAddrs =
    std::sync::Arc<std::sync::RwLock<Vec<cordelia_network::bootstrap::RelayAddr>>>;

/// Look up the relays' names now, then again every
/// `BOOTNODE_RESOLVE_INTERVAL_SECS` (every `BOOTNODE_RESOLVE_RETRY_SECS`
/// while none resolves), and publish the addresses to `addrs`. Names, not
/// addresses, are the configuration: a node that started offline, or whose
/// relay changed address, still reaches it. The last good list is kept
/// while lookups fail.
///
/// **On a device, each name that does not resolve is a failed attempt at
/// its relay** (decision 2026-10-19 §1), and while a relay that lacks the
/// change has a name that does not resolve, the names are looked up every
/// `BOOTNODE_RESOLVE_RETRY_SECS`. A relay that comes to lack the change
/// has them looked up at once (rule 3).
pub async fn keep_relays_resolved(
    relays: Vec<cordelia_network::bootstrap::Relay>,
    addrs: RelayAddrs,
    reach: Option<std::sync::Arc<cordelia_node::device_entries::Reach>>,
) {
    loop {
        let resolved = cordelia_network::bootstrap::resolve_relays(&relays).await;
        let have_any = if resolved.is_empty() {
            addrs.read().map(|a| !a.is_empty()).unwrap_or(false)
        } else {
            if let Some(warnings) = addresses_found(&addrs, &resolved) {
                let list: Vec<String> = resolved
                    .iter()
                    .map(|r| format!("{}={}", r.host, r.addr))
                    .collect();
                tracing::info!(addrs = ?list, "relay addresses updated");
                for warning in warnings {
                    tracing::warn!("{warning}");
                }
            }
            true
        };
        let wait = after_lookup(&relays, &resolved, have_any, reach.as_deref());
        match &reach {
            Some(reach) => tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = reach.lookups().notified() => {}
            },
            None => tokio::time::sleep(wait).await,
        }
    }
}

/// Publish `resolved` to `addrs` where it is not what they hold. Returns
/// what the node warns of in its log then ([`address_warnings`]), or
/// `None` where nothing changed.
fn addresses_found(
    addrs: &RelayAddrs,
    resolved: &[cordelia_network::bootstrap::RelayAddr],
) -> Option<Vec<String>> {
    let mut current = addrs.write().ok()?;
    if *current == resolved {
        return None;
    }
    *current = resolved.to_vec();
    Some(address_warnings(resolved))
}

/// What the node warns of in its log of the relays that share an address,
/// as their names resolve (decision 2026-10-17 §1): each is kept and
/// dialled, and one key answers at an address.
///
/// - Two relays given keys: only one key can answer there, and a relay
///   given another is shown with the wrong key.
/// - A relay given no key at the address of one given a key: it is never
///   taken for that relay, and what to do.
/// - Two relays given no key: they are two relays on one connection,
///   never counted as one, and what to do.
fn address_warnings(resolved: &[cordelia_network::bootstrap::RelayAddr]) -> Vec<String> {
    use cordelia_network::bootstrap::{keyless_at_keyed, sharing_an_address};
    let keyless = |host: &str| {
        resolved
            .iter()
            .any(|relay| relay.host == host && relay.key.is_none())
    };
    let mut said = Vec::new();
    for (relay, first) in sharing_an_address(resolved) {
        match (keyless(relay), keyless(first)) {
            (false, false) => said.push(format!(
                "{relay} and {first} resolve to one address: only one key can answer there, and \
                 a relay given another key is shown with the wrong key"
            )),
            (true, true) => said.push(format!(
                "{relay} and {first} are given no key, and resolve to one address: they are two \
                 relays on one connection, never counted as one, so this device never says that \
                 it has sent what it carried. Give the one name only"
            )),
            _ => {}
        }
    }
    for (relay, keyed) in keyless_at_keyed(resolved) {
        said.push(format!(
            "{relay} is given no key, and resolves to the address of {keyed}: it is never taken \
             for that relay, and is not reached. Give it that relay's key, or remove it from your \
             configuration"
        ));
    }
    said
}

/// What a lookup of the names of `relays` that found `resolved` says, and
/// how long to wait before the next (decision 2026-10-19 §1, rule 3):
/// each relay whose name did not resolve is a failed attempt at it, in
/// `reach`. The wait is `BOOTNODE_RESOLVE_INTERVAL_SECS` while some name
/// resolves (`have_any`), and `BOOTNODE_RESOLVE_RETRY_SECS` while none
/// does, or while a relay that lacks the change has a name that does not.
fn after_lookup(
    relays: &[cordelia_network::bootstrap::Relay],
    resolved: &[cordelia_network::bootstrap::RelayAddr],
    have_any: bool,
    reach: Option<&cordelia_node::device_entries::Reach>,
) -> std::time::Duration {
    use cordelia_core::protocol::{BOOTNODE_RESOLVE_INTERVAL_SECS, BOOTNODE_RESOLVE_RETRY_SECS};
    let mut lacking = false;
    for relay in relays {
        let found = resolved
            .iter()
            .any(|resolved| resolved.host == relay.host && resolved.key == relay.key);
        if let (false, Some(reach)) = (found, reach) {
            let relay = reach_id(&(relay.host.clone(), relay.key));
            reach.failed(&relay);
            lacking |= reach.lacks(&relay);
        }
    }
    let wait = if have_any && !lacking {
        BOOTNODE_RESOLVE_INTERVAL_SECS
    } else {
        BOOTNODE_RESOLVE_RETRY_SECS
    };
    std::time::Duration::from_secs(wait)
}

/// Where a node stands with one configured relay that is not connected.
#[derive(Debug, Default)]
struct RelayTry {
    /// Failures in a row.
    failures: u32,
    /// Not before this.
    next_try: Option<std::time::Instant>,
    last_tried: Option<std::time::Instant>,
    /// When the failures in a row began.
    since: Option<std::time::Instant>,
    error: Option<String>,
    /// The last failure was another key answering at the relay's address.
    wrong_key: bool,
    /// When the latest connection was made, until it has lasted a tick.
    connected_at: Option<std::time::Instant>,
}

impl RelayTry {
    fn failed(&mut self, error: String, wrong_key: bool, tick_secs: u64, another_connected: bool) {
        let now = std::time::Instant::now();
        self.failures = self.failures.saturating_add(1);
        self.since.get_or_insert(now);
        self.error = Some(error);
        self.wrong_key = wrong_key;
        self.next_try = Some(now + relay_backoff(self.failures, tick_secs, another_connected));
    }
}

// The pace below needs the cut-off cap to be the shorter one.
const _: () =
    assert!(cordelia_core::protocol::BACKOFF_BASE_SECS < cordelia_core::protocol::BACKOFF_MAX_SECS);

/// How long to wait before dialling a configured relay again after
/// `failures` failures in a row: one governor tick, doubling each time.
///
/// While another relay is connected nothing is waiting on this one, so the
/// wait grows to BACKOFF_MAX_SECS. While none is, the node is cut off and
/// keeps trying at least every BACKOFF_BASE_SECS.
fn relay_backoff(failures: u32, tick_secs: u64, another_connected: bool) -> std::time::Duration {
    use cordelia_core::protocol::{BACKOFF_BASE_SECS, BACKOFF_MAX_SECS};
    let cap = if another_connected {
        BACKOFF_MAX_SECS
    } else {
        BACKOFF_BASE_SECS
    };
    let doubled = tick_secs
        .max(1)
        .saturating_mul(1u64 << failures.saturating_sub(1).min(16));
    std::time::Duration::from_secs(doubled.min(cap).max(1))
}

/// A relay that the node is set up with, as what is known of its reach is
/// kept: by its name and key together, as its tries are.
fn reach_id(tried: &TriedRelay) -> cordelia_api::at_relays::known::RelayId {
    cordelia_api::at_relays::known::RelayId {
        name: tried.0.clone(),
        key: tried.1,
    }
}

/// Whether the dials of `relay` are paced as those of a node that has
/// another relay connected: only where another is, and the relay does
/// not lack the change the device keeps (decision 2026-10-19, rule 3).
/// A relay that lacks it is dialled at the pace of a node that is cut
/// off, whether or not another is connected.
fn paced_with_another(
    any_connected: bool,
    reach: Option<&cordelia_node::device_entries::Reach>,
    relay: &TriedRelay,
) -> bool {
    any_connected && !reach.is_some_and(|reach| reach.lacks(&reach_id(relay)))
}

/// Whether the dial loop passes `relay`, which is not connected in its own
/// right ([`connected_as_itself`]), over at this tick: a connection is
/// open at its address, where only one key answers, and it is not this
/// relay's (decision 2026-10-17 §1). It stands as its last dial left it,
/// and is not dialled: a second connection to that relay would only
/// replace the first. **Each tick that passes it over is an attempt at
/// it in `reach`, begun and failed at once** (decision 2026-10-19 §1): so
/// it can be out of reach though it is never dialled.
fn passed_over(
    relays: &[cordelia_network::bootstrap::RelayAddr],
    relay: &cordelia_network::bootstrap::RelayAddr,
    connected: &dyn Fn(&cordelia_network::bootstrap::RelayAddr) -> bool,
    reach: Option<&cordelia_node::device_entries::Reach>,
) -> bool {
    let over = relays
        .iter()
        .any(|other| other.addr == relay.addr && connected(other));
    if let (true, Some(reach)) = (over, reach) {
        reach.failed(&reach_id(&tried_relay(relay)));
    }
    over
}

/// A dial of `relay` failed with `error`: by another key answering at its
/// address (`wrong_key`), by a timeout (`timed_out`), or otherwise. Its
/// next dial waits as [`relay_backoff`] says for `tick_secs`, paced as a
/// node that has another relay connected only where
/// [`paced_with_another`] says (decision 2026-10-19, rule 3), and the
/// dial is an attempt at it that failed, in `reach`. **Only a timeout is
/// one that a wake reads** (decision 2026-10-24 (removal), section 8).
fn dial_failed(
    tries: &mut std::collections::HashMap<TriedRelay, RelayTry>,
    (relay, timed_out): (TriedRelay, bool),
    error: String,
    (wrong_key, tick_secs, any_connected): (bool, u64, bool),
    reach: Option<&cordelia_node::device_entries::Reach>,
) {
    let another = paced_with_another(any_connected, reach, &relay);
    if let Some(reach) = reach {
        match timed_out {
            true => reach.dial_timed_out(&reach_id(&relay)),
            false => reach.dial_ends(&reach_id(&relay), false),
        }
    }
    let tried = tries.entry(relay).or_default();
    tried.failed(error, wrong_key, tick_secs, another);
}

/// The configured relays that a dial at each address was begun for, as the
/// list stood when it began: a lookup that moves an address, or drops it,
/// while the dial is in flight changes nothing of whom the dial ends for.
type Dialling = std::collections::HashMap<std::net::SocketAddr, Vec<TriedRelay>>;

/// What a tick of the dial loop goes by.
#[derive(Debug, Clone, Copy)]
struct Tick {
    now: std::time::Instant,
    /// How long a connection lasts before its failures are forgotten.
    settled: std::time::Duration,
    /// The governor's tick, in seconds, which the waits start from.
    secs: u64,
    /// Whether any relay is connected.
    any_connected: bool,
    /// Whether no dial can be begun at the relay's address now: one is in
    /// flight there, or as many as may be anywhere.
    busy: bool,
}

/// What a tick of the dial loop sees of the relays: `set_up`, the relays
/// of the configuration; `relays`, those whose names resolve, as they
/// resolve now; whether a connection reaches a relay (`connected`: by its
/// key, or for one given none at its address); and the key that answers
/// on the connection open at an address, where one is (`key_at`).
#[derive(Clone, Copy)]
struct AtTick<'a> {
    set_up: &'a [cordelia_network::bootstrap::Relay],
    relays: &'a [cordelia_network::bootstrap::RelayAddr],
    connected: &'a dyn Fn(&cordelia_network::bootstrap::RelayAddr) -> bool,
    key_at: &'a dyn Fn(std::net::SocketAddr) -> Option<[u8; 32]>,
}

/// The turn of `relay` at a tick of the dial loop. Returns whether it is
/// dialled now. A relay connected in its own right
/// ([`connected_as_itself`]) is not, and its earlier failures are
/// forgotten once its connection has lasted. Any other is not connected,
/// and has its tick ([`relay_tick`]): so a relay given no key at a keyed
/// relay's place is passed over while a connection is open at its
/// address, each tick a failed attempt at it (decision 2026-10-17 §1,
/// decision 2026-10-19 §1).
fn relay_turn(
    tries: &mut std::collections::HashMap<TriedRelay, RelayTry>,
    dialling: &mut Dialling,
    (at, relay): (&AtTick, &cordelia_network::bootstrap::RelayAddr),
    tick: Tick,
    reach: Option<&cordelia_node::device_entries::Reach>,
) -> bool {
    if connected_as_itself(at, relay) {
        let id = tried_relay(relay);
        if tries
            .get(&id)
            .is_some_and(|t| t.connected_at.is_none_or(|at| at.elapsed() >= tick.settled))
        {
            tries.remove(&id);
        }
        return false;
    }
    relay_tick(
        tries,
        dialling,
        (at.relays, relay),
        at.connected,
        tick,
        reach,
    )
}

/// One tick of the dial loop for `relay`, which is not connected, among
/// `relays`, the relays as their names resolve now. Returns whether it is
/// dialled now: where it is, the dial has begun, and is kept in `dialling`
/// for every relay at that address.
///
/// - A relay that another relay answers for at its address is passed
///   over, which is an attempt at it ([`passed_over`]).
/// - With no connection, a dial that connected and waited for a show has
///   failed (decision 2026-10-19 §1).
/// - A connection that was gone again at once is a failure, paced as
///   [`paced_with_another`] says (rule 3).
fn relay_tick(
    tries: &mut std::collections::HashMap<TriedRelay, RelayTry>,
    dialling: &mut Dialling,
    (relays, relay): (
        &[cordelia_network::bootstrap::RelayAddr],
        &cordelia_network::bootstrap::RelayAddr,
    ),
    connected: &dyn Fn(&cordelia_network::bootstrap::RelayAddr) -> bool,
    tick: Tick,
    reach: Option<&cordelia_node::device_entries::Reach>,
) -> bool {
    // It has no connection of its own: where it was reached on one, it is
    // reached no more, also where it is passed over.
    let id = tried_relay(relay);
    if let Some(reach) = reach {
        reach.connection(&reach_id(&id), None);
    }
    if passed_over(relays, relay, connected, reach) {
        return false;
    }
    if tick.busy {
        return false;
    }
    let another = paced_with_another(tick.any_connected, reach, &id);
    let tried = tries.entry(id.clone()).or_default();
    if let Some(at) = tried.connected_at.take()
        && tick.now.saturating_duration_since(at) < tick.settled
    {
        // It connected and was gone again at once: a failure like any
        // other, so the pace keeps slowing.
        let closed = "the relay closed the connection at once".into();
        tried.failed(closed, false, tick.secs, another);
    }
    if tried.next_try.is_some_and(|at| tick.now < at) {
        return false;
    }
    tried.last_tried = Some(tick.now);
    if let Some(reach) = reach {
        reach.dial_begins(&reach_id(&id));
    }
    let at_its_address = relays.iter().filter(|other| other.addr == relay.addr);
    dialling.insert(relay.addr, at_its_address.map(tried_relay).collect());
    true
}

/// A dial at `addr` was answered by the key `answered`: each configured
/// relay at that address, among `relays` as their names resolve now, is
/// judged by it (decision 2026-10-17 §1). Returns the relays that it
/// reaches, and those that another key answered for.
///
/// Each relay that the dial was begun for ([`Dialling`]) and that is no
/// longer at that address is a dial that failed: its address moved, or
/// its name stopped resolving, while the dial was in flight.
fn dial_answered(
    tries: &mut std::collections::HashMap<TriedRelay, RelayTry>,
    dialling: &mut Dialling,
    (set_up, relays): (
        &[cordelia_network::bootstrap::Relay],
        &[cordelia_network::bootstrap::RelayAddr],
    ),
    (addr, answered): (std::net::SocketAddr, &[u8; 32]),
    (tick_secs, any_connected): (u64, bool),
    reach: Option<&cordelia_node::device_entries::Reach>,
) -> (
    Vec<cordelia_network::bootstrap::RelayAddr>,
    Vec<cordelia_network::bootstrap::RelayAddr>,
) {
    let begun = dialling.remove(&addr).unwrap_or_default();
    let (answers, refused, passed) = answered_at(set_up, relays, addr, answered);
    // A relay given no key at a keyed relay's place: the connection is
    // not its own, and the dial ended with none (decision 2026-10-17 §1).
    for (relay, other) in &passed {
        dial_failed(
            tries,
            (tried_relay(relay), false),
            no_key_at(other),
            (false, tick_secs, any_connected),
            reach,
        );
    }
    for relay in &refused {
        tracing::warn!(
            relay = %relay.host,
            "another key answered at a relay's address; refusing it for that relay"
        );
        let wrong_key = (true, tick_secs, any_connected);
        dial_failed(
            tries,
            (tried_relay(relay), false),
            ANOTHER_KEY_ANSWERED.into(),
            wrong_key,
            reach,
        );
    }
    // Keep the count of failures until the connection has lasted (see the
    // relay tick), so a relay that accepts and drops at once is not
    // redialled every second.
    for relay in &answers {
        tries.entry(tried_relay(relay)).or_default().connected_at = Some(std::time::Instant::now());
        if let Some(reach) = reach {
            reach.dial_ends(&reach_id(&tried_relay(relay)), true);
        }
    }
    let judged: Vec<TriedRelay> = answers
        .iter()
        .chain(&refused)
        .chain(passed.iter().map(|(relay, _)| relay))
        .map(tried_relay)
        .collect();
    for moved in begun.into_iter().filter(|tried| !judged.contains(tried)) {
        let moved_away = "its address changed while it was dialled".into();
        dial_failed(
            tries,
            (moved, false),
            moved_away,
            (false, tick_secs, any_connected),
            reach,
        );
    }
    (answers, refused)
}

/// A dial at `addr` failed with `error`, as `ended` says: each configured
/// relay at that address, among `relays` as their names resolve now, and
/// each that the dial was begun for ([`Dialling`]), wherever its name
/// resolves now. **One that the dial was begun for and that is no longer
/// at that address is credited no timeout** (decision 2026-10-24
/// (removal), section 8): its address changed while it was dialled, which
/// a spoofed lookup can cause, as [`dial_answered`] has it.
///
/// Where another key answered, each relay at the address now is judged by
/// that key ([`answered_at`]), as [`dial_answered`] judges it: only one
/// given another key is shown with the wrong key. One that the key answers
/// for came to the address while the dial was in flight, and the dial was
/// closed by the keys from before; it fails as one whose address changed.
fn dial_errored(
    tries: &mut std::collections::HashMap<TriedRelay, RelayTry>,
    dialling: &mut Dialling,
    (set_up, relays): (
        &[cordelia_network::bootstrap::Relay],
        &[cordelia_network::bootstrap::RelayAddr],
    ),
    (addr, error, ended): (std::net::SocketAddr, String, DialEnd),
    (tick_secs, any_connected): (u64, bool),
    reach: Option<&cordelia_node::device_entries::Reach>,
) {
    let here: Vec<TriedRelay> = relays
        .iter()
        .filter(|relay| relay.addr == addr)
        .map(tried_relay)
        .collect();
    let judged = match ended {
        DialEnd::AnotherKey(answered) => Some(answered_at(set_up, relays, addr, &answered)),
        _ => None,
    };
    let mut failed = here.clone();
    for begun in dialling.remove(&addr).unwrap_or_default() {
        if !failed.contains(&begun) {
            failed.push(begun);
        }
    }
    for tried in failed {
        if !here.contains(&tried) {
            dial_failed(
                tries,
                (tried, false),
                "its address changed while it was dialled".into(),
                (false, tick_secs, any_connected),
                reach,
            );
            continue;
        }
        let (error, wrong_key) = match &judged {
            Some((_, refused, _)) if refused.iter().any(|relay| tried_relay(relay) == tried) => {
                (ANOTHER_KEY_ANSWERED.to_string(), true)
            }
            Some((_, _, passed)) => {
                match passed.iter().find(|(relay, _)| tried_relay(relay) == tried) {
                    Some((_, other)) => (no_key_at(other), false),
                    None => ("its address changed while it was dialled".into(), false),
                }
            }
            None => (error.clone(), false),
        };
        dial_failed(
            tries,
            (tried, ended == DialEnd::TimedOut),
            error,
            (wrong_key, tick_secs, any_connected),
            reach,
        );
    }
}

/// Cut the wait already set to dial each of `came`, the relays that came
/// to lack the change, to no later than BACKOFF_BASE_SECS from `now`
/// (decision 2026-10-19, rule 3). The failures they counted stand.
fn cut_waits(
    tries: &mut std::collections::HashMap<TriedRelay, RelayTry>,
    came: &[cordelia_api::at_relays::known::RelayId],
    now: std::time::Instant,
) {
    let latest = now + std::time::Duration::from_secs(cordelia_core::protocol::BACKOFF_BASE_SECS);
    for relay in came {
        let tried = tries.get_mut(&(relay.name.clone(), relay.key));
        if let Some(next) = tried.and_then(|tried| tried.next_try.as_mut()) {
            *next = (*next).min(latest);
        }
    }
}

/// The relays that a wake has yet to have dialled (decision 2026-10-24
/// (removal), section 8): each relay the node is set up with whose name
/// resolves, from the moment the device wakes. **A relay is owed its dial
/// until a dial of it begins,** within WAKE_WAIT_SECS of the wake: one
/// that is busy at the wake, its dial in flight from before, is dialled
/// at the first tick after that dial ends, whatever wait its failures
/// set. A dial begun before the wake is not one that the wake reads, so
/// without this a relay that was being dialled as the device woke would
/// be waited for to the end of the wait. A relay connected or passed over
/// is owed nothing more than that it is not dialled.
#[derive(Debug, Default)]
struct WakeDials {
    owed: std::collections::HashSet<TriedRelay>,
    /// Until when the dials are owed: the wake's wait.
    until: Option<std::time::Instant>,
}

impl WakeDials {
    /// The device woke at `now`: each of `relays` is owed a dial.
    fn woke(&mut self, relays: &[cordelia_network::bootstrap::RelayAddr], now: std::time::Instant) {
        self.owed = relays.iter().map(tried_relay).collect();
        self.until =
            Some(now + std::time::Duration::from_secs(cordelia_core::protocol::WAKE_WAIT_SECS));
    }

    /// Where `relay` is owed its dial at `now`, cut the wait already set
    /// to dial it to `now`. The failures it counted stand, and so the pace
    /// after this dial. Past the wait, nothing is owed.
    fn cut(
        &mut self,
        tries: &mut std::collections::HashMap<TriedRelay, RelayTry>,
        relay: &cordelia_network::bootstrap::RelayAddr,
        now: std::time::Instant,
    ) {
        if self.until.is_some_and(|until| now >= until) {
            self.owed.clear();
            self.until = None;
        }
        let id = tried_relay(relay);
        if !self.owed.contains(&id) {
            return;
        }
        if let Some(next) = tries.get_mut(&id).and_then(|tried| tried.next_try.as_mut()) {
            *next = (*next).min(now);
        }
    }

    /// A dial of `relay` began: it is owed nothing more.
    fn dialled(&mut self, relay: &cordelia_network::bootstrap::RelayAddr) {
        self.owed.remove(&tried_relay(relay));
    }
}

/// Whether the device's side of its relays, where the node has one, is
/// waking: taken before a dial's end is judged, so that one that ends the
/// wake has a whole pass made at once.
fn is_waking(
    device: &Option<std::sync::Arc<cordelia_node::device_entries::DeviceEntries>>,
) -> bool {
    device
        .as_ref()
        .is_some_and(|device| device.leave().is_waking())
}

/// The connection that an asking to make one again names (decision
/// 2026-10-17 §4): by the relay's key where it gives one, which holds
/// whatever name the relay is listed under now; otherwise by the name it
/// gives, among `relays`, the relays a pass is given. `None` where there
/// is no such connection: the asking is then answered that none was
/// closed.
fn to_make_again(
    peer: Option<[u8; 32]>,
    relay: &str,
    relays: &[cordelia_node::device_entries::Relay],
    connected: &dyn Fn(&NodeId) -> bool,
) -> Option<NodeId> {
    match peer {
        Some(key) => Some(NodeId(key)).filter(|peer| connected(peer)),
        None => relays
            .iter()
            .find(|set_up| set_up.name == relay)
            .and_then(|set_up| set_up.link.as_ref())
            .map(|link| link.relay().clone()),
    }
}

/// Forget the tries of each configured relay that the connection to
/// `peer`, at `addr`, reached, when it is made again (decision 2026-10-17
/// §4): by the key that found the connection, or for a relay given no
/// key, by its address. The tries of any other relay are kept, whatever
/// it is called.
fn forget_tries(
    tries: &mut std::collections::HashMap<TriedRelay, RelayTry>,
    resolved: &[cordelia_network::bootstrap::RelayAddr],
    peer: &NodeId,
    addr: Option<std::net::SocketAddr>,
) {
    let reached: Vec<TriedRelay> = resolved
        .iter()
        .filter(|relay| relay.key.is_none() && Some(relay.addr) == addr)
        .map(tried_relay)
        .collect();
    tries.retain(|tried, _| tried.1 != Some(peer.0) && !reached.contains(tried));
}

/// The governor of a node of `role`, with its targets and timeouts from
/// `gov_config`: the one place where a node's role decides it.
///
/// - Its dial policy (§8.2.2): a personal node dials only relays, and a
///   relay or a bootnode any peer.
/// - **A personal node keeps its relays** (decision 2026-10-17 §2):
///   every relay it is set up with is one the person chose, and churn
///   closes none of them. A relay and a bootnode churn as before.
fn governor_for(
    role: &str,
    gov_config: &cordelia_core::config::GovernorConfig,
) -> cordelia_network::governor::Governor {
    use cordelia_network::governor::{DialPolicy, Governor, GovernorTargets, GovernorTimeouts};
    let personal = role == "personal";
    let dial_policy = if personal {
        DialPolicy::RelaysOnly
    } else {
        DialPolicy::All
    };
    let targets = GovernorTargets::from_config(gov_config);
    let governor = Governor::with_dial_policy(targets, vec![], dial_policy)
        .with_timeouts(GovernorTimeouts::from_config(gov_config));
    match personal {
        true => governor.keeping_its_relays(),
        false => governor,
    }
}

/// What the key that answered a dial at `addr` says of each configured
/// relay there (decision 2026-10-17 §1). Of the relays of `relays` at that
/// address:
///
/// - those whose key answered are reached by the connection, and so are
///   those given none, but for one at a keyed relay's place;
/// - each that was given another key failed its own handshake, and is
///   shown with the wrong key;
/// - each given no key at a keyed relay's place ([`keyed_relay_at`]) is
///   not reached by it, and is given with the name of that relay: the
///   connection is not its own.
///
/// Two relays may share an address, and only one key answers at one.
#[allow(clippy::type_complexity)]
fn answered_at(
    set_up: &[cordelia_network::bootstrap::Relay],
    relays: &[cordelia_network::bootstrap::RelayAddr],
    addr: std::net::SocketAddr,
    answered: &[u8; 32],
) -> (
    Vec<cordelia_network::bootstrap::RelayAddr>,
    Vec<cordelia_network::bootstrap::RelayAddr>,
    Vec<(cordelia_network::bootstrap::RelayAddr, String)>,
) {
    let (mut answers, mut refused, mut passed) = (Vec::new(), Vec::new(), Vec::new());
    for relay in relays.iter().filter(|relay| relay.addr == addr) {
        match relay.key {
            Some(key) if key == *answered => answers.push(relay.clone()),
            Some(_) => refused.push(relay.clone()),
            None => match keyed_relay_at(set_up, relays, addr, Some(*answered)) {
                Some(other) => passed.push((relay.clone(), set_up[other].host.clone())),
                None => answers.push(relay.clone()),
            },
        }
    }
    (answers, refused, passed)
}

/// The relay of `set_up` given a key at whose place a relay given no key
/// at `addr` is (decision 2026-10-17 §1): the first whose name resolves
/// to `addr`, among `resolved`, or whose key is `answered`, the key that
/// answers on the connection at `addr`. A relay given no key is never
/// taken for such a relay. Only a relay given a key is one: two names
/// given no key at one address are two relays on the one connection.
fn keyed_relay_at(
    set_up: &[cordelia_network::bootstrap::Relay],
    resolved: &[cordelia_network::bootstrap::RelayAddr],
    addr: std::net::SocketAddr,
    answered: Option<[u8; 32]>,
) -> Option<usize> {
    set_up.iter().position(|relay| {
        relay.key.is_some_and(|key| {
            answered == Some(key)
                || resolved.iter().any(|resolved| {
                    resolved.host == relay.host
                        && resolved.key == relay.key
                        && resolved.addr == addr
                })
        })
    })
}

/// The key that answers on the connection open at `addr`, where one is.
fn key_at(
    conn_mgr: &cordelia_network::connection::ConnectionManager,
    addr: std::net::SocketAddr,
) -> Option<[u8; 32]> {
    conn_mgr
        .connected_peers()
        .into_iter()
        .find(|peer| {
            conn_mgr
                .get_connection(peer)
                .is_some_and(|conn| conn.remote_address() == addr)
        })
        .map(|peer| peer.0)
}

/// The keys of the relays configured by key at `from` (decision
/// 2026-10-22 (memory), rule 12): a connection that arrives from there is
/// accepted with the transport settings between relays listed by key, and
/// closed after TLS unless it proves one of these keys. Empty for any
/// other address. Matched by address and port, as a relay dials from the
/// port it listens on; an IPv4 address that a dual-stack socket shows
/// mapped into IPv6 is the same address.
fn keys_listed_at(
    relays: &[cordelia_network::bootstrap::RelayAddr],
    from: std::net::SocketAddr,
) -> Vec<[u8; 32]> {
    let canonical = |addr: std::net::SocketAddr| {
        std::net::SocketAddr::new(addr.ip().to_canonical(), addr.port())
    };
    let mut keys: Vec<[u8; 32]> = relays
        .iter()
        .filter(|relay| canonical(relay.addr) == canonical(from))
        .filter_map(|relay| relay.key)
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Accept `incoming` (decision 2026-10-22 (memory), rule 12): from the
/// address of a relay configured by key, with the transport settings
/// between relays listed by key, and closed after TLS where the key is
/// not that relay's; from any other, with every peer's.
async fn accept_incoming(
    ctx: &cordelia_network::connection::ConnectContext,
    incoming: quinn::Incoming,
    relays: &RelayAddrs,
) -> Result<
    cordelia_network::connection::ConnectOutcome,
    cordelia_network::connection::ConnectionError,
> {
    let keys = relays
        .read()
        .map(|relays| keys_listed_at(&relays, incoming.remote_address()))
        .unwrap_or_default();
    if keys.is_empty() {
        cordelia_network::connection::inbound_accept(ctx, incoming).await
    } else {
        cordelia_network::connection::inbound_accept_from_listed(ctx, incoming, &keys).await
    }
}

/// How a dial ended with no connection (decision 2026-10-24 (removal),
/// section 8). Only a timeout ends a wake's wait for a relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DialEnd {
    /// QUIC's handshake, or Cordelia's after it, timed out.
    TimedOut,
    /// Another key answered at the address of relays configured by key,
    /// as TLS gave it (the key that answered): the dial was closed there.
    AnotherKey([u8; 32]),
    /// Refused, closed, or answered wrongly in any other way.
    Failed,
}

impl DialEnd {
    fn of(error: &cordelia_network::connection::ConnectionError) -> Self {
        match error {
            cordelia_network::connection::ConnectionError::NotTheRelay(answered) => {
                Self::AnotherKey(answered.0)
            }
            error if error.timed_out() => Self::TimedOut,
            _ => Self::Failed,
        }
    }
}

/// The keys that may answer a dial at `addr`, among `relays` as their
/// names resolve now: those of the relays configured there, where each has
/// one. `None` where one configured there has none, which any key may
/// answer for (decision 2026-10-17 §1), or none is configured there.
fn keys_to_answer(
    relays: &[cordelia_network::bootstrap::RelayAddr],
    addr: std::net::SocketAddr,
) -> Option<Vec<[u8; 32]>> {
    let at: Vec<_> = relays.iter().filter(|relay| relay.addr == addr).collect();
    if at.is_empty() || at.iter().any(|relay| relay.key.is_none()) {
        return None;
    }
    Some(at.iter().filter_map(|relay| relay.key).collect())
}

/// Dial a configured relay, `keys` being those that may answer at its
/// address ([`keys_to_answer`]), and say how it ended: what the dial loop
/// is sent.
async fn dial_configured(
    ctx: &cordelia_network::connection::ConnectContext,
    relay: &cordelia_network::bootstrap::RelayAddr,
    keys: Option<&[[u8; 32]]>,
) -> Result<cordelia_network::connection::ConnectOutcome, (std::net::SocketAddr, String, DialEnd)> {
    dial_relay(ctx, relay, keys)
        .await
        .map_err(|e| (relay.addr, e.to_string(), DialEnd::of(&e)))
}

/// Dial a configured relay (decision 2026-10-22 (memory), rule 12): one
/// configured by key with the transport settings between relays listed by
/// key, one configured by address alone with every peer's. A key that
/// answers and is not among `keys` ends the dial once TLS gives it.
async fn dial_relay(
    ctx: &cordelia_network::connection::ConnectContext,
    relay: &cordelia_network::bootstrap::RelayAddr,
    keys: Option<&[[u8; 32]]>,
) -> Result<
    cordelia_network::connection::ConnectOutcome,
    cordelia_network::connection::ConnectionError,
> {
    if relay.key.is_some() {
        cordelia_network::connection::outbound_connect_to_listed(ctx, relay.addr, keys).await
    } else {
        cordelia_network::connection::outbound_connect(ctx, relay.addr).await
    }
}

/// Whether a configured relay is connected: by its key if one is
/// configured, otherwise by the address it was dialled at.
fn relay_connected(
    conn_mgr: &cordelia_network::connection::ConnectionManager,
    relay: &cordelia_network::bootstrap::RelayAddr,
) -> bool {
    match relay.key {
        Some(key) => conn_mgr.is_connected(&NodeId(key)),
        None => conn_mgr.connected_peers().iter().any(|p| {
            conn_mgr
                .get_connection(p)
                .is_some_and(|c| c.remote_address() == relay.addr)
        }),
    }
}

/// The relays this node is set up with, each with its connection where
/// there is one: by its key if one is configured, otherwise by the address
/// that its name resolves to.
///
/// **Every relay of the configuration is here, by its name, whether or not
/// the name resolves** (decision 2026-10-04 §4.6): `set_up` is what the
/// node was configured with, and `relay_addrs` the addresses that those
/// names resolve to now. A relay whose name has not resolved has no
/// connection, like one that is down, and is a relay that the device is
/// set up with all the same. It is waited for when the device wakes, it is
/// named as not heard from, and it is one of the relays that a command
/// says does not hold a change.
///
/// **One relay is here once** (decision 2026-10-17 §1): a relay that is
/// the same relay as one before it ([`one_relay_each`]) is left out. So
/// one relay is counted once, paced once and passed once, and the node
/// says how many relays the device is set up with from this list
/// (`own`). A relay that another key answers for at its address is here,
/// with no connection, as a relay that is out of reach is: so the device
/// never takes every relay for connected while it fails. So is a relay
/// given no key whose name resolves to the address of another: it is
/// never taken for that relay, and the connection there is not its own.
fn relays_with_links(
    set_up: &[cordelia_network::bootstrap::Relay],
    relay_addrs: &RelayAddrs,
    conn_mgr: &cordelia_network::connection::ConnectionManager,
    own: &cordelia_api::state::OwnChannels,
) -> Vec<cordelia_node::device_entries::Relay> {
    use cordelia_node::device_entries::{Link, Relay};
    // Where the addresses cannot be read, a relay is still known by its
    // key, and by its name.
    let resolved = relay_addrs
        .read()
        .map(|resolved| resolved.clone())
        .unwrap_or_default();
    let (peers, one) = one_relay_each_now(set_up, &resolved, conn_mgr);
    let relays: Vec<Relay> = set_up
        .iter()
        .zip(peers)
        .zip(one)
        .filter(|(_, one)| !matches!(one, OneRelay::SameAs(_)))
        .map(|((relay, peer), _)| {
            // Whether the relay keeps every head is what it said in its
            // handshake (decision 2026-10-24 (removal), rule 18).
            let link = peer.and_then(|peer| {
                let at = conn_mgr.get_peer(&peer)?;
                let roles = at.handshake.peer_roles.clone();
                let link = Link::new(relay.host.clone(), peer.clone(), at.conn.clone());
                Some(link.naming(&roles))
            });
            Relay {
                name: relay.host.clone(),
                key: relay.key,
                link,
            }
        })
        .collect();
    own.set_up_with(relays.len());
    own.set_up_as(relays.iter().map(Relay::id).collect());
    relays
}

/// What one relay that a node is set up with is among the others
/// (decision 2026-10-17 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OneRelay {
    /// A relay of its own: listed, counted, paced and passed.
    Itself,
    /// The same relay as the one at this place in the configuration: the
    /// configuration gave it the same key, or the same name with the same
    /// key, or none. It is listed as that, and nothing else.
    SameAs(usize),
    /// A relay given no key at the place of the relay given a key at this
    /// place: its name resolves to that relay's address, or that relay's
    /// key answers on the connection at its own. No connection answers for
    /// it by its own name. It is listed as unreachable, never as connected,
    /// and counted as a relay out of reach is, with no connection.
    KeylessAt(usize),
    /// Another key answers at its address, on the connection of the relay
    /// at this place: it is listed with the wrong key, and counted as a
    /// relay that is out of reach, with no connection.
    WrongKeyAt(usize),
}

/// Which of the relays in `set_up` are one relay (decision 2026-10-17
/// §1). `peers` is, for each, the peer whose connection reaches it, where
/// one does: by its key, or for a relay given none by its address.
/// `addrs` is the address its name resolves to, where it does, and
/// `at` the address of a peer's connection.
///
/// - A relay given the same key as one before it, or the same name and no
///   key twice, is the same relay as that one: the first in the
///   configuration is the one counted. Only the configuration makes two
///   relays one: a connection that answers for both does not.
/// - A relay given no key, whose name resolves to the address of a relay
///   of `set_up` given a key, or whose connection that relay's key
///   answers, is a relay of its own that no connection reaches
///   ([`OneRelay::KeylessAt`]): one connection there cannot tell which
///   name it answers for. Two names given no key at one address are two
///   relays on the one connection, whichever key answers there, but for a
///   key given to a relay.
/// - A relay that no connection reaches, at the address of a connection
///   that reaches another relay, is one that another key answers for
///   there: only one key answers at an address.
/// - Every other relay is a relay of its own, reached or not.
fn one_relay_each(
    set_up: &[cordelia_network::bootstrap::Relay],
    peers: &[Option<NodeId>],
    addrs: &[Option<std::net::SocketAddr>],
    at: &dyn Fn(&NodeId) -> Option<std::net::SocketAddr>,
) -> Vec<OneRelay> {
    let mut one = vec![OneRelay::Itself; set_up.len()];
    let named_alike = |i: usize, j: usize| set_up[i].host == set_up[j].host;
    for i in 0..set_up.len() {
        let same = (0..i).find(|&j| {
            let key = set_up[i].key;
            one[j] == OneRelay::Itself
                && key == set_up[j].key
                && (key.is_some() || named_alike(i, j))
        });
        if let Some(j) = same {
            one[i] = OneRelay::SameAs(j);
        }
    }
    for i in 0..set_up.len() {
        if one[i] != OneRelay::Itself || set_up[i].key.is_some() {
            continue;
        }
        let keyed = (0..set_up.len()).find(|&j| {
            set_up[j].key.is_some_and(|key| {
                peers[i] == Some(NodeId(key)) || (addrs[i].is_some() && addrs[j] == addrs[i])
            })
        });
        if let Some(j) = keyed {
            one[i] = OneRelay::KeylessAt(j);
        }
    }
    for i in 0..set_up.len() {
        if one[i] != OneRelay::Itself || peers[i].is_some() {
            continue;
        }
        let Some(addr) = addrs[i] else {
            continue;
        };
        let answered = (0..set_up.len()).find(|&j| {
            j != i
                && one[j] == OneRelay::Itself
                && peers[j].as_ref().is_some_and(|peer| at(peer) == Some(addr))
        });
        if let Some(j) = answered {
            one[i] = OneRelay::WrongKeyAt(j);
        }
    }
    one
}

/// [`one_relay_each`] now: for each relay in `set_up`, the peer whose
/// connection reaches it, and what it is among the others. A relay is
/// found among `resolved` by its name and its key.
fn one_relay_each_now(
    set_up: &[cordelia_network::bootstrap::Relay],
    resolved: &[cordelia_network::bootstrap::RelayAddr],
    conn_mgr: &cordelia_network::connection::ConnectionManager,
) -> (Vec<Option<NodeId>>, Vec<OneRelay>) {
    let addrs: Vec<Option<std::net::SocketAddr>> = set_up
        .iter()
        .map(|relay| {
            let found = resolved
                .iter()
                .find(|resolved| resolved.host == relay.host && resolved.key == relay.key);
            found.map(|resolved| resolved.addr)
        })
        .collect();
    let peers: Vec<Option<NodeId>> = set_up
        .iter()
        .zip(&addrs)
        .map(|(relay, addr)| match relay.key {
            Some(key) => conn_mgr.get_connection(&NodeId(key)).map(|_| NodeId(key)),
            None => addr.and_then(|addr| {
                conn_mgr.connected_peers().into_iter().find(|peer| {
                    conn_mgr
                        .get_connection(peer)
                        .is_some_and(|conn| conn.remote_address() == addr)
                })
            }),
        })
        .collect();
    let at = |peer: &NodeId| conn_mgr.get_connection(peer).map(|c| c.remote_address());
    let one = one_relay_each(set_up, &peers, &addrs, &at);
    // A relay given no key at another's address is reached by no
    // connection there.
    let peers = peers
        .into_iter()
        .zip(&one)
        .map(|(peer, one)| peer.filter(|_| !matches!(one, OneRelay::KeylessAt(_))))
        .collect();
    (peers, one)
}

/// Start a pass of a device's side of its relays, where this node has
/// one: off the select loop, since it waits on the relays. Each relay has
/// its turn in a pass by itself: at a relay where an earlier pass is
/// still at its turn, this one does nothing, and it goes on at every
/// other relay; except a whole pass behind a pass that sends, which
/// waits for that turn where no other whole pass waits. Only while the device wakes does one pass ask every
/// relay, and a second that finds it doing so does nothing.
fn device_pass(
    device: &Option<std::sync::Arc<cordelia_node::device_entries::DeviceEntries>>,
    set_up: &[cordelia_network::bootstrap::Relay],
    relay_addrs: &RelayAddrs,
    conn_mgr: &cordelia_network::connection::ConnectionManager,
    own: &cordelia_api::state::OwnChannels,
    kind: cordelia_node::device_entries::Pass,
) {
    let Some(device) = device.clone() else {
        return;
    };
    let relays = relays_with_links(set_up, relay_addrs, conn_mgr, own);
    tokio::spawn(async move { device.pass(&relays, kind).await });
}

/// Whether the requests that a peer makes on a stream of `protocol` are
/// counted against what a connection, and its address, may ask in a
/// minute.
///
/// `own_relay` is whether this node is a relay and the peer is one that
/// the governor calls a relay of this node's: by its key where one is
/// configured, and otherwise by its address, or by its address and its
/// own word. `listed_by_key` is whether the operator lists the peer by
/// key ([`crate::relay_entries::RelayEntries::lists`]).
///
/// For the older kind of channel, the requests of this node's own relays
/// are not counted. For the streams of entries of channels from their
/// secrets, only those of a relay that is listed by key are not: the
/// address a connection comes from is no key.
fn requests_are_counted(
    protocol: cordelia_network::messages::Protocol,
    own_relay: bool,
    listed_by_key: bool,
) -> bool {
    use cordelia_network::messages::Protocol;
    match protocol {
        Protocol::EntryShow
        | Protocol::ChannelProve
        | Protocol::EntryPull
        | Protocol::EntryPush
        | Protocol::RelayEntries => !listed_by_key,
        _ => !own_relay,
    }
}

fn any_relay_connected(
    set_up: &[cordelia_network::bootstrap::Relay],
    relay_addrs: &RelayAddrs,
    conn_mgr: &cordelia_network::connection::ConnectionManager,
) -> bool {
    relay_addrs
        .read()
        .map(|relays| with_tick(set_up, &relays, conn_mgr, any_connected_as_itself))
        .unwrap_or(false)
}

/// Do `work` with what a tick of the dial loop sees of the relays now
/// ([`AtTick`]): `set_up`, `relays` as their names resolve, and the
/// connections of `conn_mgr`, by a relay's key or at its address, with the
/// key that answers on each.
fn with_tick<R>(
    set_up: &[cordelia_network::bootstrap::Relay],
    relays: &[cordelia_network::bootstrap::RelayAddr],
    conn_mgr: &cordelia_network::connection::ConnectionManager,
    work: impl FnOnce(&AtTick) -> R,
) -> R {
    let connected =
        |relay: &cordelia_network::bootstrap::RelayAddr| relay_connected(conn_mgr, relay);
    let key_at = |addr| key_at(conn_mgr, addr);
    work(&AtTick {
        set_up,
        relays,
        connected: &connected,
        key_at: &key_at,
    })
}

/// Whether any relay of `at` is connected in its own right
/// ([`connected_as_itself`]): what the dial loop paces by.
fn any_connected_as_itself(at: &AtTick) -> bool {
    at.relays.iter().any(|relay| connected_as_itself(at, relay))
}

/// Whether `relay`, one of `at.relays`, is connected in its own right:
/// a connection reaches it ([`relay_connected`]), and, for a relay given
/// no key, it is not at a keyed relay's place ([`keyed_relay_at`]: that
/// relay's name resolves to its address, or that relay's key answers on
/// the connection there). Such a relay is not (decision 2026-10-17 §1):
/// the connection is not known to answer for it by its own name. The
/// dial loop passes it over while that connection is open
/// ([`passed_over`]), each tick a failed attempt at it, so it comes to be
/// out of reach (decision 2026-10-19 §1). Two names given no key at one
/// address are each connected on the one connection.
fn connected_as_itself(at: &AtTick, relay: &cordelia_network::bootstrap::RelayAddr) -> bool {
    let at_a_keyed = relay.key.is_none()
        && keyed_relay_at(at.set_up, at.relays, relay.addr, (at.key_at)(relay.addr)).is_some();
    !at_a_keyed && (at.connected)(relay)
}

/// Whether `node_id` is one of the relays this node was configured with.
///
/// With a key configured, the relay is the node with that key. Without one
/// it can only be told by address: the node at the relay's address, or one
/// that connected from the relay's IP and says it is a relay (a relay
/// behind address translation does not keep its port). That weaker rule is
/// why a relay configured without a key is warned about at start.
fn is_configured_relay(
    relay_addrs: &RelayAddrs,
    conn_mgr: &cordelia_network::connection::ConnectionManager,
    node_id: &NodeId,
    says_relay: bool,
) -> bool {
    let Ok(relays) = relay_addrs.read() else {
        return false;
    };
    let remote = conn_mgr.get_connection(node_id).map(|c| c.remote_address());
    relays.iter().any(|r| match r.key {
        Some(key) => key == node_id.0,
        None => remote
            .is_some_and(|remote| remote == r.addr || (says_relay && remote.ip() == r.addr.ip())),
    })
}

/// What is said of a relay whose name does not resolve, where its
/// standing is listed.
const NAME_DOES_NOT_RESOLVE: &str = "its name does not resolve";

/// The state of a relay that is the same relay as one before it in the
/// configuration (decision 2026-10-17 §1): never "connected", so that one
/// relay is counted once wherever relays are counted.
const SAME_RELAY: &str = "same relay";

/// What is said of a relay that another key answered for at its address.
const ANOTHER_KEY_ANSWERED: &str = "another key answered at this address";

/// What is said of a relay given no key at the place of `other`, a relay
/// given a key (decision 2026-10-17 §1): why it is not reached, and what
/// the person can do.
fn no_key_at(other: &str) -> String {
    format!(
        "given no key, at the address of {other}: give it that relay's key, or remove it from \
         your configuration"
    )
}

/// A relay that the node is set up with, as its tries are kept: by its
/// name and its key, since one name may be given twice, with two keys.
type TriedRelay = (String, Option<[u8; 32]>);

/// How the tries of `relay` are kept.
fn tried_relay(relay: &cordelia_network::bootstrap::RelayAddr) -> TriedRelay {
    (relay.host.clone(), relay.key)
}

/// Where each relay that the node is set up with stands, for `cordelia
/// peers` and `cordelia status`.
///
/// **Every relay of the configuration is here, by its name, whether or
/// not the name resolves** (decision 2026-10-04 §16): `set_up` is what
/// the node was configured with, `resolved` the addresses that those
/// names resolve to now, and `connected` whether a relay at one of those
/// is connected. A relay whose name has not resolved cannot be dialled:
/// it is unreachable, and its line says why.
///
/// A relay is found among `resolved` and `tries` by its name and its key:
/// one name may be given twice, with two keys. `one` says what each is
/// among the others ([`one_relay_each`], decision 2026-10-17 §1): one
/// that is the same relay as another says so, and is not connected in
/// its own right; one that another key answers for at its address has
/// the wrong key.
fn relay_snapshots(
    set_up: &[cordelia_network::bootstrap::Relay],
    resolved: &[cordelia_network::bootstrap::RelayAddr],
    tries: &std::collections::HashMap<TriedRelay, RelayTry>,
    one: &[OneRelay],
    connected: &dyn Fn(&cordelia_network::bootstrap::RelayAddr) -> bool,
) -> Vec<cordelia_api::state::RelaySnapshot> {
    let key_of = |key: Option<[u8; 32]>| {
        key.and_then(|k| cordelia_crypto::bech32::encode_public_key(&k).ok())
    };
    set_up
        .iter()
        .enumerate()
        .map(|(at, named)| {
            let one = one.get(at).copied().unwrap_or(OneRelay::Itself);
            if let OneRelay::SameAs(first) = one {
                return cordelia_api::state::RelaySnapshot {
                    host: named.host.clone(),
                    key: key_of(named.key),
                    state: SAME_RELAY.into(),
                    unreachable_secs: None,
                    last_tried_secs: None,
                    error: Some(format!("the same relay as {}", set_up[first].host)),
                    tried: Default::default(),
                    connection: None,
                };
            }
            let found = resolved
                .iter()
                .find(|relay| relay.host == named.host && relay.key == named.key);
            let Some(relay) = found else {
                return cordelia_api::state::RelaySnapshot {
                    host: named.host.clone(),
                    key: key_of(named.key),
                    state: "unreachable".into(),
                    unreachable_secs: None,
                    last_tried_secs: None,
                    error: Some(NAME_DOES_NOT_RESOLVE.into()),
                    tried: cordelia_api::state::Tried::LookedUp,
                    connection: None,
                };
            };
            let tried = tries.get(&tried_relay(relay));
            let wrong_key_at = matches!(one, OneRelay::WrongKeyAt(_));
            // A relay given no key at another's address is never connected
            // in its own right: where a connection is open there, it is
            // passed over, and not dialled.
            let keyless_at = match one {
                OneRelay::KeylessAt(other) => Some(&set_up[other].host),
                _ => None,
            };
            let passed_over = keyless_at.is_some() && connected(relay);
            let connected = !wrong_key_at && keyless_at.is_none() && connected(relay);
            let failing = tried.filter(|t| t.failures > 0 && !connected);
            let state = if connected {
                "connected"
            } else if wrong_key_at {
                "wrong key"
            } else if passed_over {
                "unreachable"
            } else {
                match failing {
                    Some(t) if t.wrong_key => "wrong key",
                    Some(_) => "unreachable",
                    None => "connecting",
                }
            };
            cordelia_api::state::RelaySnapshot {
                host: relay.host.clone(),
                key: key_of(relay.key),
                state: state.into(),
                unreachable_secs: failing.and_then(|t| t.since).map(|t| t.elapsed().as_secs()),
                last_tried_secs: tried
                    .filter(|_| !connected)
                    .and_then(|t| t.last_tried)
                    .map(|t| t.elapsed().as_secs()),
                error: match keyless_at {
                    Some(other) if passed_over => Some(no_key_at(other)),
                    _ => failing
                        .and_then(|t| t.error.clone())
                        .or_else(|| wrong_key_at.then(|| ANOTHER_KEY_ANSWERED.to_string())),
                },
                // A relay with the wrong key, where another answers at its
                // address, is not dialled (decision 2026-10-19 §5, S9); one
                // given no key at a keyed relay's place is never reached.
                tried: match (wrong_key_at, keyless_at.is_some()) {
                    (true, _) => cordelia_api::state::Tried::NotDialled,
                    (false, true) => cordelia_api::state::Tried::NoKey,
                    (false, false) => cordelia_api::state::Tried::Dialled,
                },
                connection: None,
            }
        })
        .collect()
}

/// Where each relay that the node is set up with stands now
/// ([`relay_snapshots`]), with the connection that the dial loop made to
/// it and that is its own, where one is (decision 2026-10-24, rule 2): the
/// one that a pass is given for it ([`one_relay_each_now`]). So each
/// connection says the configured relay it was made to, a relay given no
/// key among them, and what waits there is said by that relay's name. A
/// relay that is the same relay as one before it has none: the first is
/// the one named.
fn relays_now(
    set_up: &[cordelia_network::bootstrap::Relay],
    resolved: &[cordelia_network::bootstrap::RelayAddr],
    tries: &std::collections::HashMap<TriedRelay, RelayTry>,
    conn_mgr: &cordelia_network::connection::ConnectionManager,
) -> Vec<cordelia_api::state::RelaySnapshot> {
    let (peers, one) = one_relay_each_now(set_up, resolved, conn_mgr);
    let mut list = relay_snapshots(set_up, resolved, tries, &one, &|relay| {
        relay_connected(conn_mgr, relay)
    });
    for ((relay, peer), one) in list.iter_mut().zip(peers).zip(&one) {
        if !matches!(one, OneRelay::SameAs(_)) {
            relay.connection = peer.map(|peer| peer.0);
        }
    }
    list
}

/// [`publish_relays`], with the relays as their names resolve now: at a
/// connection, and at the governor's tick, so that the connection that
/// each relay has as its own is known before the peers that list it are
/// (decision 2026-10-24, rule 2).
fn publish_relays_now(
    state: &cordelia_api::state::AppState,
    set_up: &[cordelia_network::bootstrap::Relay],
    relay_addrs: &RelayAddrs,
    tries: &std::collections::HashMap<TriedRelay, RelayTry>,
    conn_mgr: &cordelia_network::connection::ConnectionManager,
) {
    let resolved = relay_addrs
        .read()
        .map(|resolved| resolved.clone())
        .unwrap_or_default();
    publish_relays(state, set_up, &resolved, tries, conn_mgr);
}

/// Publish where each relay that the node is set up with stands
/// ([`relays_now`]).
fn publish_relays(
    state: &cordelia_api::state::AppState,
    set_up: &[cordelia_network::bootstrap::Relay],
    resolved: &[cordelia_network::bootstrap::RelayAddr],
    tries: &std::collections::HashMap<TriedRelay, RelayTry>,
    conn_mgr: &cordelia_network::connection::ConnectionManager,
) {
    let list = relays_now(set_up, resolved, tries, conn_mgr);
    // Which of them are connected now: the node keeps since when each
    // has been, and since when none has, by its own clock.
    let connected: Vec<&str> = list
        .iter()
        .filter(|relay| relay.state == "connected")
        .map(|relay| relay.host.as_str())
        .collect();
    state
        .own_channels
        .relays_connected(&connected, std::time::Instant::now());
    if let Ok(mut current) = state.relays.write()
        && *current != list
    {
        *current = list;
    }
}

/// Act on an event from a stream handler.
fn apply_gov_event(
    event: GovEvent,
    governor: &mut cordelia_network::governor::Governor,
    conn_mgr: &mut cordelia_network::connection::ConnectionManager,
    refused_addresses: &mut std::collections::HashMap<std::net::IpAddr, std::time::Instant>,
) {
    match event {
        GovEvent::OverLimit(peer_id, address) => {
            governor.ban_peer(
                &peer_id,
                "over the rate limit".into(),
                cordelia_network::governor::BanTier::Transient,
            );
            conn_mgr.disconnect(&peer_id);
            refused_addresses.insert(
                address,
                std::time::Instant::now()
                    + std::time::Duration::from_secs(cordelia_core::protocol::BAN_TRANSIENT_SECS),
            );
        }
    }
}

/// Refuse a stream that is over a limit: both halves are ended with
/// ERR_RATE_LIMIT, so the peer fails at once.
fn refuse_stream(send: &mut quinn::SendStream, recv: &mut quinn::RecvStream) {
    let code = quinn::VarInt::from_u32(cordelia_core::protocol::ERR_RATE_LIMIT);
    let _ = send.reset(code);
    let _ = recv.stop(code);
}

/// Close the connection of a peer that kept going over its limits, and
/// tell the loop, which refuses its address for a time.
fn cut_off(
    conn: &quinn::Connection,
    peer_id: &NodeId,
    address: std::net::IpAddr,
    gov_tx: &tokio::sync::mpsc::UnboundedSender<GovEvent>,
) {
    tracing::warn!(peer = %peer_id, %address, "over its rate limits again and again; closing the connection and refusing the address for a time");
    conn.close(
        quinn::VarInt::from_u32(cordelia_core::protocol::ERR_RATE_LIMIT),
        b"over the rate limit",
    );
    let _ = gov_tx.send(GovEvent::OverLimit(peer_id.clone(), address));
}

/// Handle inbound protocol streams from a connected peer.
/// Runs until the connection closes.
///
/// `made_from` is the address that the connection was made from. Every
/// limit by address counts the peer under it, whatever address the connection has moved to since: one that was read
/// at each stream would hand a peer that moves a new address's allowance.
#[allow(clippy::too_many_arguments)]
pub async fn handle_peer_streams(
    conn: quinn::Connection,
    peer_id: NodeId,
    made_from: std::net::IpAddr,
    state: web::Data<cordelia_api::state::AppState>,
    shared_peers: std::sync::Arc<std::sync::RwLock<Vec<cordelia_network::messages::PeerAddress>>>,
    node_role: String,
    peer_rates: std::sync::Arc<std::sync::Mutex<Rates>>,
    peer_states: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<NodeId, u8>>>,
    peer_relays: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<NodeId>>>,
    gov_tx: tokio::sync::mpsc::UnboundedSender<GovEvent>,
    relay_entries: Option<std::sync::Arc<crate::relay_entries::RelayEntries>>,
    large_permits: std::sync::Arc<LargePermits>,
) {
    let mut stream_count: u64 = 0;
    // The channels of entries whose keys were proved on this connection
    // (decision 2026-10-04 §2.4 item 3). It is this connection's, and is
    // gone when the connection closes.
    let mut proved = crate::relay_entries::Proved::default();
    // And what this connection showed whole, by author's slot (§2.4 item
    // 5): gone with it, as what it proved is.
    let mut shown_whole = crate::relay_entries::ShownWhole::default();
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
            cordelia_network::messages::Protocol::EntryShow => "entry_show",
            cordelia_network::messages::Protocol::ChannelProve => "channel_prove",
            cordelia_network::messages::Protocol::EntryPull => "entry_pull",
            cordelia_network::messages::Protocol::EntryPush => "entry_push",
            cordelia_network::messages::Protocol::RelayEntries => "relay_entries",
            _ => "other",
        };
        tracing::debug!(peer = %peer_id, protocol = proto_name, stream = stream_count, "stream opened (inbound)");
        let stream_start = std::time::Instant::now();

        // Rate limits (§9.2): this connection's allowance, and its
        // address's. A request over either is refused at once, so the peer
        // does not wait for an answer that is not coming. A peer that keeps
        // going over is cut off, and its address refused for a time.
        //
        // A relay this node was configured with is never cut off. Between
        // two relays that list each other there is no limit at all: they
        // are one operator's, and each passes on everything its devices
        // send. A device still counts what its relay asks of it.
        //
        // On the streams of entries of channels from their secrets, the
        // only peer whose requests are not counted is a relay that the
        // operator lists by key (decision 2026-10-04 §2.4 item 6). A
        // relay that is configured by address alone is known by where it
        // connected from, or by that and its own word: whoever came from
        // that address would otherwise ask without a count.
        let address = made_from;
        let own_relay = peer_relays
            .read()
            .ok()
            .is_some_and(|relays| relays.contains(&peer_id));
        let unlimited = own_relay && node_role == "relay";
        // Whether the peer is a relay this node lists by key, which is
        // outside rule 2 (rule 7). Only a relay keeps `relay_entries`, so
        // on a bootnode or a personal node this is always false and
        // nothing is exempt from the permits. That does not matter: a
        // bootnode answers only peer-sharing (small).
        let listed_by_key = relay_entries
            .as_ref()
            .is_some_and(|entries| entries.lists(&peer_id));
        let over = if !requests_are_counted(protocol, unlimited, listed_by_key) {
            None
        } else {
            peer_rates
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .request(&peer_id, address, protocol)
                .err()
        };
        if let Some(over) = over {
            tracing::warn!(peer = %peer_id, protocol = proto_name, cut_off = over.cut_off, "rate limit exceeded");
            refuse_stream(&mut send, &mut recv);
            if over.cut_off && !own_relay {
                cut_off(&conn, &peer_id, address, &gov_tx);
                break;
            }
            continue;
        }

        // Protocol gating by peer state (§5.4.2, §7.2): a relay serves the
        // streams of entries to peers that are warm or hot.
        let peer_state = peer_states
            .read()
            .ok()
            .and_then(|s| s.get(&peer_id).copied())
            .unwrap_or(1); // default Warm if not yet synced
        let is_warm_or_hot = peer_state >= 1;

        match protocol {
            // No node carries a channel of the older kind (decision
            // 2026-11-10 (older kind), rule 7). What a peer asks of that
            // kind is answered with nothing, as a device that holds no
            // such channel would (decision 2026-10-04 §10.1): an alpha.19
            // relay asks each of its devices, and each relay it lists,
            // which channels it holds, and one that is answered asks again
            // at its usual pace, where one that is refused takes that for a
            // failure and asks again within the minute.
            cordelia_network::messages::Protocol::ItemSync => {
                answer_sync_with_nothing(&mut send, &mut recv, &peer_id).await;
                continue;
            }
            // It takes no push of that kind, and hears no announcement of
            // one. Each is refused at once, so that the peer does not
            // wait for an answer that is not coming.
            cordelia_network::messages::Protocol::ItemPush
            | cordelia_network::messages::Protocol::ChannelAnnounce => {
                tracing::debug!(peer = %peer_id, protocol = proto_name, "refused: no node carries a channel of the older kind");
                refuse_stream(&mut send, &mut recv);
                continue;
            }
            cordelia_network::messages::Protocol::PeerSharing => {
                // Allowed on Warm + Hot (§2.1)
                handle_inbound_peer_share(
                    &mut send,
                    &mut recv,
                    &peer_id,
                    &shared_peers,
                    &node_role,
                )
                .await;
            }
            // The streams of entries of channels from their secrets
            // (decision 2026-10-04 §2.4), which a relay serves. A node of
            // any other role holds nothing to serve them with, and they
            // fall through to what it does with a stream it does not
            // serve. A relay serves them to peers that are warm or hot.
            cordelia_network::messages::Protocol::EntryShow
            | cordelia_network::messages::Protocol::ChannelProve
            | cordelia_network::messages::Protocol::EntryPull
            | cordelia_network::messages::Protocol::EntryPush
            | cordelia_network::messages::Protocol::RelayEntries
                if relay_entries.is_some() =>
            {
                if !is_warm_or_hot {
                    tracing::debug!(peer = %peer_id, protocol = ?protocol, state = peer_state, "rejected: data protocol below required state");
                    continue;
                }
                let Some(entries) = &relay_entries else {
                    continue;
                };
                let serving = crate::relay_entries::Serving {
                    conn: Some(&conn),
                    peer: &peer_id,
                    address,
                    db: &state.db,
                    rates: &peer_rates,
                    permits: Some(&large_permits),
                };
                let over = entries
                    .serve(
                        protocol,
                        &mut send,
                        &mut recv,
                        &serving,
                        &mut proved,
                        &mut shown_whole,
                    )
                    .await;
                if over.is_some_and(|over| over.cut_off) && !own_relay {
                    cut_off(&conn, &peer_id, address, &gov_tx);
                    break;
                }
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

/// Refuse a stream whose frame is longer than a small message, when no
/// large permit came for it within STREAM_TIMEOUT_SECS (decision
/// 2026-10-22 (memory), rule 2). The receive side is stopped and the send
/// side reset with ERR_LARGE_MESSAGE_LATER, so a peer of the version
/// before, blocked in its write, learns to send the same frame again
/// later. No breach is counted: the peer did nothing over a limit.
pub(crate) fn refuse_large_later(
    send: &mut impl crate::relay_entries::Refuse,
    recv: &mut impl crate::relay_entries::Refuse,
) {
    let code = quinn::VarInt::from_u32(cordelia_core::protocol::ERR_LARGE_MESSAGE_LATER);
    send.refuse(code);
    recv.refuse(code);
}

/// One outcome of reading a frame on a stream from a peer (decision
/// 2026-10-22 (memory), rules 2 and 7).
pub(crate) enum Framed<'p> {
    /// The frame's bytes, with the large permit held for it (None where it
    /// is within a small message, where the peer is a listed relay, or
    /// where the node keeps no budget). The caller drops the permit once
    /// it has written the answer, before it reads the next frame.
    Frame(Vec<u8>, Option<LargePermit<'p>>),
    /// No permit came within STREAM_TIMEOUT: the caller refuses the stream
    /// with ERR_LARGE_MESSAGE_LATER and counts no breach.
    LargeLater,
    /// The stream ended, or its read failed.
    Ended,
}

/// Read one frame from `recv`, taking a large permit where the frame is
/// longer than a small message and the peer is not a listed relay
/// (decision 2026-10-22 (memory), rules 2 and 7). The permit is taken
/// before the payload is read or allocated (CLAUDE.md: a node never
/// allocates by a length a peer chose without a bound). `listed` is
/// whether the peer is a relay listed by key, whose frames are read at
/// once whatever their size; `permits` is `None` for a node that keeps no
/// budget, or a test that does not exercise one.
pub(crate) async fn read_under_permit<'p, R>(
    recv: &mut R,
    permits: Option<&'p LargePermits>,
    address: std::net::IpAddr,
    listed: bool,
) -> Framed<'p>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let len = match cordelia_network::codec::read_frame_len(recv).await {
        Ok(len) => len,
        Err(_) => return Framed::Ended,
    };
    let permit = if len > cordelia_core::protocol::SMALL_MESSAGE_BYTES && !listed {
        match permits {
            Some(permits) => match permits.take(address).await {
                Some(permit) => Some(permit),
                None => return Framed::LargeLater,
            },
            None => None,
        }
    } else {
        None
    };
    match cordelia_network::codec::read_frame_body(recv, len).await {
        Ok(body) => Framed::Frame(body, permit),
        Err(_) => Framed::Ended,
    }
}

/// The most requests of one stream that [`answer_sync_with_nothing`]
/// answers: a peer that goes on asking on one stream is left there.
const NOTHING_ANSWERED_AT_MOST: usize = 64;

/// What a node that holds no channel of the older kind answers to one
/// message of a sync of that kind (decision 2026-10-04 §10.1): to the
/// question which channels it holds, that it holds none; to a request for
/// a channel's items, that the channel holds nothing. `None` for a
/// message that asks neither: nothing is answered, and the stream ends.
fn nothing_for(
    asked: &cordelia_network::messages::WireMessage,
) -> Option<cordelia_network::messages::WireMessage> {
    use cordelia_network::messages::{SyncChannelListResponse, SyncResponse, WireMessage};
    match asked {
        WireMessage::SyncChannelListRequest(_) => Some(WireMessage::SyncChannelListResponse(
            SyncChannelListResponse {
                channel_ids: Vec::new(),
            },
        )),
        WireMessage::SyncRequest(_) => Some(WireMessage::SyncResponse(SyncResponse {
            items: Vec::new(),
            has_more: false,
            last_seq: None,
        })),
        _ => None,
    }
}

/// Answer a sync of the older kind as a node that holds no channel of
/// that kind does ([`nothing_for`]): each request on the stream, until
/// the peer has no more. The node's database is not read: a personal
/// node carries no channel of that kind, whatever its database once
/// held.
async fn answer_sync_with_nothing<W, R>(send: &mut W, recv: &mut R, peer_id: &NodeId)
where
    W: tokio::io::AsyncWrite + Unpin + cordelia_network::codec::GiveUp,
    R: tokio::io::AsyncRead + Unpin,
{
    for _ in 0..NOTHING_ANSWERED_AT_MOST {
        // No honest older-kind request to a node that carries none is over
        // a small message (rule 2): a longer frame is refused at its
        // length, before its body is read.
        let Ok(asked) = cordelia_network::codec::read_small_frame(
            recv,
            cordelia_network::messages::Protocol::ItemSync,
        )
        .await
        else {
            break;
        };
        let nothing = nothing_for(&asked);
        // What was asked is dropped before the answer is written: the
        // request (a channel's ID of up to a message, as the peer wrote
        // it) is not held through `write_frame`, which may wait up to
        // STREAM_TIMEOUT for a peer that does not read. It is untested: a
        // test would need a counting allocator and a stream whose write
        // waits.
        drop(asked);
        let Some(nothing) = nothing else {
            break;
        };
        if cordelia_network::codec::write_frame(send, &nothing)
            .await
            .is_err()
        {
            break;
        }
    }
    tracing::debug!(peer = %peer_id, "answered a sync of the older kind with nothing: no node carries a channel of that kind");
    send.finish_up();
}

async fn handle_inbound_peer_share<W, R>(
    send: &mut W,
    recv: &mut R,
    peer_id: &NodeId,
    shared_peers: &std::sync::Arc<std::sync::RwLock<Vec<cordelia_network::messages::PeerAddress>>>,
    node_role: &str,
) where
    W: tokio::io::AsyncWrite + Unpin + cordelia_network::codec::GiveUp,
    R: tokio::io::AsyncRead + Unpin,
{
    // A peer-share request is tiny (a count of peers), so no honest frame
    // is over a small message (rule 2): a longer one is refused at its
    // length.
    let msg = match cordelia_network::codec::read_small_frame(
        recv,
        cordelia_network::messages::Protocol::PeerSharing,
    )
    .await
    {
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
            .ok()
            .filter(|_| shares_peers(node_role))
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
        // Encoded, and the message dropped, before the write (rule 4).
        let written = cordelia_network::codec::encode_message(&resp);
        drop(resp);
        if let Ok(written) = written {
            let _ = cordelia_network::codec::write_raw_frame(send, &written).await;
        }
        tracing::debug!(peer = %peer_id, count, "served peer-share request");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test over real QUIC, bounded as a whole: one that waits for what
    /// never comes fails here on this assertion, with its name, and does
    /// not hold the run of the suite until CI gives up on it. Each test
    /// wrapped in it bounds its own waits as well; this is the bound over
    /// all of them.
    async fn within<T>(test: &str, secs: u64, run: impl std::future::Future<Output = T>) -> T {
        match tokio::time::timeout(std::time::Duration::from_secs(secs), run).await {
            Ok(done) => done,
            Err(_) => panic!("{test} did not end within {secs} s"),
        }
    }

    /// Every relay that a node is set up with is listed for `cordelia
    /// peers` and `cordelia status`, by its name, whether or not the name
    /// resolves (decision 2026-10-04 §16): one that does not is
    /// unreachable, and its line says why.
    #[test]
    fn a_relay_whose_name_does_not_resolve_is_listed_with_the_others() {
        use cordelia_network::bootstrap::{Relay, RelayAddr};
        let named = |host: &str, key: Option<[u8; 32]>| Relay {
            host: host.into(),
            key,
        };
        let set_up = [
            named("relay1.example:9474", Some([7; 32])),
            named("no-such-name.example:9474", Some([8; 32])),
            named("relay3.example:9474", None),
        ];
        let at = |host: &str, last: u8, key: Option<[u8; 32]>| RelayAddr {
            host: host.into(),
            addr: std::net::SocketAddr::from(([127, 0, 0, last], 9474)),
            key,
        };
        let resolved = [
            at("relay1.example:9474", 1, Some([7; 32])),
            at("relay3.example:9474", 3, None),
        ];
        let tries = std::collections::HashMap::new();
        let listed = relay_snapshots(&set_up, &resolved, &tries, &[], &|relay| {
            relay.host == "relay1.example:9474"
        });
        let stands: Vec<(&str, &str, Option<&str>)> = listed
            .iter()
            .map(|relay| {
                (
                    relay.host.as_str(),
                    relay.state.as_str(),
                    relay.error.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            stands,
            [
                ("relay1.example:9474", "connected", None),
                (
                    "no-such-name.example:9474",
                    "unreachable",
                    Some("its name does not resolve")
                ),
                ("relay3.example:9474", "connecting", None),
            ]
        );
        // Its key is said as any relay's is.
        let key = cordelia_crypto::bech32::encode_public_key(&[8; 32]).unwrap();
        assert_eq!(listed[1].key.as_deref(), Some(key.as_str()));
        // The one whose name does not resolve is looked up; the others are
        // dialled (decision 2026-10-19 §5, S9).
        use cordelia_api::state::Tried;
        let tried: Vec<Tried> = listed.iter().map(|relay| relay.tried).collect();
        assert_eq!(tried, [Tried::Dialled, Tried::LookedUp, Tried::Dialled]);
        // With no name resolved, every relay is still listed.
        let none = relay_snapshots(&set_up, &[], &tries, &[], &|_| true);
        assert_eq!(none.len(), 3);
        assert!(none.iter().all(|relay| relay.state == "unreachable"));
    }

    /// Two relays that a node is set up with resolve to one address, each
    /// given a key of its own, beside a third there that was given none
    /// (decision 2026-10-17 §1). The key that answers a dial there
    /// reaches the relay that was given it, and answers at the address of
    /// the one given none; the other fails its own handshake. Each is listed by its name: the one
    /// whose key did not answer with the wrong key, the one given that
    /// key as connected, and the one given none as unreachable, at the
    /// address of another: it is never taken for another relay. None of
    /// them is dropped, and one relay is connected once.
    #[test]
    fn two_relays_at_one_address_are_each_listed_and_a_wrong_key_is_their_own() {
        use cordelia_network::bootstrap::{Relay, RelayAddr};
        let shared = std::net::SocketAddr::from(([127, 0, 0, 1], 9474));
        let at = |host: &str, addr, key| RelayAddr {
            host: host.into(),
            addr,
            key,
        };
        let other = std::net::SocketAddr::from(([127, 0, 0, 2], 9474));
        let resolved = [
            at("one.example:9474", shared, Some([7; 32])),
            at("two.example:9474", shared, Some([8; 32])),
            at("three.example:9474", shared, None),
            at("other.example:9474", other, Some([9; 32])),
        ];
        let hosts = |relays: &[RelayAddr]| -> Vec<String> {
            relays.iter().map(|relay| relay.host.clone()).collect()
        };
        let set_up: Vec<Relay> = resolved
            .iter()
            .map(|relay| Relay {
                host: relay.host.clone(),
                key: relay.key,
            })
            .collect();
        let passed_of = |passed: &[(RelayAddr, String)]| -> Vec<(String, String)> {
            let hosts = passed
                .iter()
                .map(|(relay, other)| (relay.host.clone(), other.clone()));
            hosts.collect()
        };
        let three_at_one = vec![(
            "three.example:9474".to_string(),
            "one.example:9474".to_string(),
        )];
        let (answers, refused, passed) = answered_at(&set_up, &resolved, shared, &[8; 32]);
        assert_eq!(hosts(&answers), ["two.example:9474"]);
        assert_eq!(hosts(&refused), ["one.example:9474"]);
        // The relay given none is at a keyed relay's place: the connection
        // is not its own.
        assert_eq!(passed_of(&passed), three_at_one);
        // A key that none was given reaches none of them: the relay given
        // none is still at the place of the relays given keys.
        let (stranger, both, passed) = answered_at(&set_up, &resolved, shared, &[5; 32]);
        assert!(stranger.is_empty());
        assert_eq!(hosts(&both), ["one.example:9474", "two.example:9474"]);
        assert_eq!(passed_of(&passed), three_at_one);
        let elsewhere = "127.0.0.3:9474".parse().unwrap();
        let (none, nothing, passed) = answered_at(&set_up, &resolved, elsewhere, &[8; 32]);
        assert!(none.is_empty() && nothing.is_empty() && passed.is_empty());

        // As the loop does with that answer: the relay whose key did not
        // answer failed, with the wrong key.
        let mut tries: std::collections::HashMap<TriedRelay, RelayTry> = Default::default();
        for relay in &refused {
            let tried = tries.entry(tried_relay(relay)).or_default();
            tried.failed(
                "another key answered at this address".into(),
                true,
                10,
                true,
            );
        }
        let connected =
            |relay: &RelayAddr| relay.addr == shared && relay.key.is_none_or(|key| key == [8; 32]);
        // The connection is the second relay's, by its key; the third is
        // reached by it at its address.
        let peers = [None, Some(NodeId([8; 32])), Some(NodeId([8; 32])), None];
        let addrs: Vec<_> = resolved.iter().map(|relay| Some(relay.addr)).collect();
        let at = |peer: &NodeId| (peer.0 == [8; 32]).then_some(shared);
        let one = one_relay_each(&set_up, &peers, &addrs, &at);
        let listed = relay_snapshots(&set_up, &resolved, &tries, &one, &connected);
        assert_eq!(
            stands_of(&listed),
            [
                (
                    "one.example:9474",
                    "wrong key",
                    Some("another key answered at this address")
                ),
                ("two.example:9474", "connected", None),
                (
                    "three.example:9474",
                    "unreachable",
                    Some(
                        "given no key, at the address of one.example:9474: give it that \
                         relay's key, or remove it from your configuration"
                    )
                ),
                ("other.example:9474", "connecting", None),
            ]
        );
        // The one given none is never reached, a connection open there or
        // not: what the wait after a change says of it (decision
        // 2026-10-19 §5, S9). With none open, it is not connected either.
        use cordelia_api::state::Tried;
        assert_eq!(listed[2].tried, Tried::NoKey);
        let listed = relay_snapshots(&set_up, &resolved, &tries, &one, &|_| false);
        assert_eq!(
            (listed[2].state.as_str(), listed[2].tried),
            ("connecting", Tried::NoKey)
        );
    }

    /// Each relay's name, state and what is said of it.
    fn stands_of(listed: &[cordelia_api::state::RelaySnapshot]) -> Vec<(&str, &str, Option<&str>)> {
        listed
            .iter()
            .map(|relay| {
                let error = relay.error.as_deref();
                (relay.host.as_str(), relay.state.as_str(), error)
            })
            .collect()
    }

    /// The connection that an asking to make one again names is found by
    /// the relay's key where the asking gives one (decision 2026-10-17
    /// §4): whatever name the relay is listed under now, or none. Where
    /// that key is not connected, there is none to close. An asking with
    /// no key, a carry's, is found by its name among the relays a pass is
    /// given.
    #[test]
    fn a_connection_to_make_again_is_found_by_its_key() {
        use cordelia_node::device_entries::Relay;
        let key = [7; 32];
        let connected = |peer: &NodeId| peer.0 == key;
        // Listed under another name now, or under none.
        let listed = [Relay {
            name: "keyless.example:9474".into(),
            key: None,
            link: None,
        }];
        for relays in [&listed[..], &[]] {
            let found = to_make_again(Some(key), "keyed.example:9474", relays, &connected);
            assert_eq!(found, Some(NodeId(key)));
        }
        assert_eq!(
            to_make_again(Some([8; 32]), "keyed.example:9474", &listed, &connected),
            None
        );
        assert_eq!(
            to_make_again(None, "keyed.example:9474", &listed, &connected),
            None
        );
        assert_eq!(
            to_make_again(None, "keyless.example:9474", &listed, &connected),
            None,
            "listed with no connection"
        );
    }

    /// When a connection is made again, the tries forgotten are those of
    /// each relay it reached (decision 2026-10-17 §4): by the key that
    /// found it, and for a relay given no key, by its address. A relay of
    /// the same name with another key, and a relay elsewhere, keep theirs.
    #[test]
    fn the_tries_forgotten_are_those_of_the_relays_the_connection_reached() {
        use cordelia_network::bootstrap::RelayAddr;
        let here = std::net::SocketAddr::from(([127, 0, 0, 1], 9474));
        let elsewhere = std::net::SocketAddr::from(([127, 0, 0, 2], 9474));
        let at = |host: &str, addr, key| RelayAddr {
            host: host.into(),
            addr,
            key,
        };
        let resolved = [
            at("keyed.example:9474", here, Some([7; 32])),
            at("keyless.example:9474", here, None),
            at("keyed.example:9474", here, Some([8; 32])),
            at("other.example:9474", elsewhere, Some([9; 32])),
            at("far.example:9474", elsewhere, None),
        ];
        let mut tries: std::collections::HashMap<TriedRelay, RelayTry> = resolved
            .iter()
            .map(|relay| (tried_relay(relay), RelayTry::default()))
            .collect();
        forget_tries(&mut tries, &resolved, &NodeId([7; 32]), Some(here));
        let mut kept: Vec<TriedRelay> = tries.into_keys().collect();
        kept.sort();
        assert_eq!(
            kept,
            [
                ("far.example:9474".to_string(), None),
                ("keyed.example:9474".to_string(), Some([8; 32])),
                ("other.example:9474".to_string(), Some([9; 32])),
            ]
        );
    }

    /// A node's governor goes by its role (decision 2026-10-17 §2): built
    /// as the node builds it, a personal node's keeps the three relays it
    /// is connected to through several churn intervals, while a fourth
    /// has gone and is cold. A relay's and a bootnode's, with the same
    /// peers, close a warm one at the first.
    #[test]
    fn a_nodes_governor_keeps_its_relays_through_churn_only_on_a_personal_node() {
        let config = cordelia_core::config::GovernorConfig {
            hot_min: 1,
            hot_max: 2,
            hot_min_relays: 1,
            warm_min: 1,
            churn_interval_secs: 0,
            churn_jitter_secs: 0,
            churn_fraction: 0.2,
            ..Default::default()
        };
        let three: Vec<NodeId> = (1..=3u8).map(|n| NodeId([n; 32])).collect();
        // What a governor closes over `intervals` churn intervals, with
        // three relays connected and a fourth gone.
        let closes = |role: &str, intervals: usize| -> Vec<NodeId> {
            let mut governor = governor_for(role, &config);
            for n in 1..=4u8 {
                let id = NodeId([n; 32]);
                governor.add_peer(id.clone(), vec![], vec![]);
                governor.set_peer_relay(&id, true);
                governor.mark_connected(&id);
            }
            governor.mark_disconnected(&NodeId([4; 32]));
            assert_eq!(governor.counts(), (1, 2, 1, 0), "{role}");
            (0..intervals)
                .flat_map(|_| governor.tick().disconnect)
                .collect()
        };
        assert!(closes("personal", 5).is_empty());
        for role in ["relay", "bootnode"] {
            let closed = closes(role, 1);
            assert_eq!(closed.len(), 1, "{role}: {closed:?}");
            assert!(three.contains(&closed[0]), "{role}");
        }
    }

    /// One relay is one relay, under however many names the configuration
    /// gives the same key (decision 2026-10-17 §1): the first is counted,
    /// and each other is the same relay as it, whether or not the relay is
    /// reached. So is one name given twice with no key. A name given no
    /// key is never the same relay as another: at the address of a relay
    /// given a key it is one of its own that no connection reaches,
    /// whether the connection there reaches it or not, and whether it
    /// comes first or not; beside another name given none it is a relay
    /// of its own. A relay that no connection reaches at the address of one that
    /// another key answers is one with the wrong key; one at an address of
    /// its own is a relay of its own, reached or not.
    #[test]
    fn one_relay_under_two_names_is_one_relay() {
        use cordelia_network::bootstrap::Relay;
        let named = |host: &str, key: Option<[u8; 32]>| Relay {
            host: host.into(),
            key,
        };
        let shared = std::net::SocketAddr::from(([127, 0, 0, 1], 9474));
        let elsewhere = std::net::SocketAddr::from(([127, 0, 0, 2], 9474));
        let set_up = [
            named("keyed.example:9474", Some([7; 32])),
            named("keyless.example:9474", None),
            named("again.example:9474", Some([7; 32])),
            named("wrong.example:9474", Some([8; 32])),
            named("own.example:9474", Some([9; 32])),
        ];
        let addrs = [
            Some(shared),
            Some(shared),
            Some(elsewhere),
            Some(shared),
            Some(elsewhere),
        ];
        let at = |peer: &NodeId| (peer.0 == [7; 32]).then_some(shared);
        let reached = Some(NodeId([7; 32]));
        let peers = [reached.clone(), reached.clone(), reached, None, None];
        let one = one_relay_each(&set_up, &peers, &addrs, &at);
        assert_eq!(
            one,
            [
                OneRelay::Itself,
                OneRelay::KeylessAt(0),
                OneRelay::SameAs(0),
                OneRelay::WrongKeyAt(0),
                OneRelay::Itself,
            ]
        );
        // Unreached: the names given one key are still one relay, and
        // the others are relays of their own.
        let none = [None, None, None, None, None];
        let one = one_relay_each(&set_up, &none, &addrs, &|_| None);
        assert_eq!(
            one,
            [
                OneRelay::Itself,
                OneRelay::KeylessAt(0),
                OneRelay::SameAs(0),
                OneRelay::Itself,
                OneRelay::Itself,
            ]
        );
        // The name given no key, first: the one given the key is a relay
        // of its own, and the one given none is still at its address.
        let first = [set_up[1].clone(), set_up[0].clone()];
        let peers = [Some(NodeId([7; 32])), Some(NodeId([7; 32]))];
        let one = one_relay_each(&first, &peers, &[Some(shared); 2], &at);
        assert_eq!(one, [OneRelay::KeylessAt(1), OneRelay::Itself]);
        // Two names given no key at one address are two relays of their
        // own; one name given twice with none is one relay.
        let two = [
            named("keyless.example:9474", None),
            named("other.example:9474", None),
            named("keyless.example:9474", None),
        ];
        let one = one_relay_each(&two, &[None, None, None], &[Some(shared); 3], &|_| None);
        assert_eq!(
            one,
            [OneRelay::Itself, OneRelay::Itself, OneRelay::SameAs(0)]
        );
    }

    /// One name given twice, with two keys (decision 2026-10-17 §1): each
    /// entry is found by its name and its key, where it resolved and in
    /// its tries. The key of the first answers: the first is connected,
    /// with its own key, and the second has the wrong key, with its own.
    #[test]
    fn one_name_given_twice_with_two_keys_is_listed_by_its_key() {
        use cordelia_network::bootstrap::{Relay, RelayAddr};
        let shared = std::net::SocketAddr::from(([127, 0, 0, 1], 9474));
        let resolved: Vec<RelayAddr> = [[7; 32], [8; 32]]
            .into_iter()
            .map(|key| RelayAddr {
                host: "h.example:9474".into(),
                addr: shared,
                key: Some(key),
            })
            .collect();
        let set_up: Vec<Relay> = resolved
            .iter()
            .map(|relay| Relay {
                host: relay.host.clone(),
                key: relay.key,
            })
            .collect();
        let (answers, refused, passed) = answered_at(&set_up, &resolved, shared, &[7; 32]);
        assert_eq!((answers.len(), refused.len(), passed.len()), (1, 1, 0));
        let mut tries: std::collections::HashMap<TriedRelay, RelayTry> = Default::default();
        for relay in &answers {
            tries.entry(tried_relay(relay)).or_default().connected_at =
                Some(std::time::Instant::now());
        }
        for relay in &refused {
            let tried = tries.entry(tried_relay(relay)).or_default();
            tried.failed(ANOTHER_KEY_ANSWERED.into(), true, 10, true);
        }
        assert_eq!(tries.len(), 2, "one try for each name and key");
        let peers = [Some(NodeId([7; 32])), None];
        let addrs = [Some(shared), Some(shared)];
        let at = |peer: &NodeId| (peer.0 == [7; 32]).then_some(shared);
        let one = one_relay_each(&set_up, &peers, &addrs, &at);
        // As the node tells: by the key that is connected.
        let connected = |relay: &RelayAddr| relay.key == Some([7; 32]);
        let listed = relay_snapshots(&set_up, &resolved, &tries, &one, &connected);
        assert_eq!(
            stands_of(&listed),
            [
                ("h.example:9474", "connected", None),
                ("h.example:9474", "wrong key", Some(ANOTHER_KEY_ANSWERED)),
            ]
        );
        let key = |k: [u8; 32]| cordelia_crypto::bech32::encode_public_key(&k).ok();
        assert_eq!(listed[0].key, key([7; 32]));
        assert_eq!(listed[1].key, key([8; 32]));
        // The one with the wrong key, where another answers at its
        // address, is not dialled (decision 2026-10-19 §5, S9).
        use cordelia_api::state::Tried;
        assert_eq!(listed[0].tried, Tried::Dialled);
        assert_eq!(listed[1].tried, Tried::NotDialled);
        // And without what the connections say, by its tries alone: it
        // was dialled, and another key answered.
        let itself = [OneRelay::Itself; 2];
        let listed = relay_snapshots(&set_up, &resolved, &tries, &itself, &connected);
        assert_eq!(listed[1].state, "wrong key");
        assert_eq!(listed[1].tried, Tried::Dialled);
    }

    /// A device answers a request of the older kind with nothing, as a
    /// device that holds no such channel would (decision 2026-10-04
    /// §10.1): it holds no channel, and a channel that it is asked for
    /// holds nothing. Anything else on such a stream is not answered.
    #[test]
    fn a_request_of_the_older_kind_is_answered_with_nothing() {
        use cordelia_network::messages::{SyncChannelListRequest, SyncRequest, WireMessage};
        let which = WireMessage::SyncChannelListRequest(SyncChannelListRequest {});
        match nothing_for(&which) {
            Some(WireMessage::SyncChannelListResponse(held)) => {
                assert!(held.channel_ids.is_empty())
            }
            other => panic!("{other:?}"),
        }
        let items = WireMessage::SyncRequest(SyncRequest {
            channel_id: "grp_lab".into(),
            since: None,
            limit: 100,
            after_seq: None,
        });
        match nothing_for(&items) {
            Some(WireMessage::SyncResponse(held)) => {
                assert!(held.items.is_empty() && !held.has_more && held.last_seq.is_none())
            }
            other => panic!("{other:?}"),
        }
        let answer = nothing_for(&which).unwrap();
        assert!(nothing_for(&answer).is_none());
    }

    /// What this thread holds (`crate::counting`).
    /// A node's state over a database in memory, with no network.
    fn a_state() -> web::Data<cordelia_api::state::AppState> {
        web::Data::new(cordelia_api::state::AppState {
            load: Default::default(),
            db: cordelia_core::lock::TimedLock::new(
                cordelia_storage::db::open_in_memory().unwrap(),
            ),
            identity: cordelia_crypto::identity::NodeIdentity::generate().unwrap(),
            bearer_token: "t".into(),
            home_dir: std::env::temp_dir().join("cordelia-p2p-test-no-such-directory"),
            started_at: std::time::Instant::now(),
            sync_errors: Default::default(),
            peers_hot: Default::default(),
            peers_warm: Default::default(),
            networked: false,
            peers: Default::default(),
            relays: Default::default(),
            sync_control: Default::default(),
            own_channels: Default::default(),
            held: Default::default(),
            history: Default::default(),
        })
    }

    // ── The large permits (decision 2026-10-22 (memory), rule 2) ──────

    /// A large permit is one for each /24 (or /48), not one for each
    /// connection: a second address in a subnet that already holds one
    /// waits, although permits are free, and takes it once the first is
    /// let go.
    #[tokio::test(start_paused = true)]
    async fn a_large_permit_is_one_for_each_subnet() {
        use std::net::IpAddr;
        let permits = LargePermits::new(cordelia_core::protocol::LARGE_MESSAGES_AT_ONCE);
        // One connection of a /24 takes a permit; three are still free.
        let first = permits
            .take(IpAddr::from([203, 0, 113, 1]))
            .await
            .expect("the first of a subnet takes a permit");
        // A second address in the same /24 gets none, though permits are
        // free: the subnet holds one already.
        assert!(
            permits.take(IpAddr::from([203, 0, 113, 9])).await.is_none(),
            "two connections of one /24 held two permits"
        );
        // Once the first is let go, the subnet may take one again.
        drop(first);
        assert!(
            permits.take(IpAddr::from([203, 0, 113, 9])).await.is_some(),
            "the /24's permit was not free again once let go"
        );
    }

    /// At most `LARGE_MESSAGES_AT_ONCE` are held across all connections,
    /// and each is given back when it is dropped, whether the stream was
    /// answered or failed.
    #[tokio::test(start_paused = true)]
    async fn large_permits_are_bounded_and_given_back() {
        use std::net::IpAddr;
        let budget = cordelia_core::protocol::LARGE_MESSAGES_AT_ONCE;
        let permits = LargePermits::new(budget);
        // One subnet for each permit fills the budget.
        let mut held: Vec<_> = (0..budget)
            .map(|n| {
                futures_lite_block(permits.take(IpAddr::from([10, n as u8, 0, 1])))
                    .expect("within budget")
            })
            .collect();
        // One subnet more gets none: the budget is spent.
        assert!(
            permits.take(IpAddr::from([10, 250, 0, 1])).await.is_none(),
            "a permit was given past the budget of {budget}"
        );
        // Dropping one (as a failed stream does) gives it back.
        held.pop();
        assert!(
            permits.take(IpAddr::from([10, 250, 0, 1])).await.is_some(),
            "a permit was not given back when it was dropped"
        );
    }

    /// Take a permit now, on this paused clock, without awaiting a timer:
    /// used where the take must succeed at once.
    fn futures_lite_block<F: std::future::Future>(fut: F) -> F::Output {
        // The future resolves without yielding to a timer when a permit is
        // free; a tiny executor turns it once.
        let mut fut = Box::pin(fut);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        loop {
            if let std::task::Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
        }
    }

    /// The first to ask is the first served (decision 2026-10-22 (memory),
    /// rule 2): when a permit frees, the waiter that asked earliest, whose
    /// subnet holds none, takes it, not a later asker.
    /// Take a permit in a task, report through `tx` whether one came, and
    /// hold it (so a permit a task wins is not let go while the test reads
    /// who won).
    fn asks_and_holds(
        permits: std::sync::Arc<LargePermits>,
        address: &str,
        tx: tokio::sync::oneshot::Sender<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let address: std::net::IpAddr = address.parse().unwrap();
        tokio::spawn(async move {
            let got = permits.take(address).await;
            let _ = tx.send(got.is_some());
            if got.is_some() {
                // Hold the permit until the task is dropped at test end.
                std::future::pending::<()>().await;
            }
        })
    }

    /// The first to ask is the first served (decision 2026-10-22 (memory),
    /// rule 2): when a permit frees, the waiter that asked earliest, whose
    /// subnet holds none, takes it, not a later asker.
    #[tokio::test(start_paused = true)]
    async fn a_waiter_that_asked_first_is_served_first() {
        use std::net::IpAddr;
        let permits = std::sync::Arc::new(LargePermits::new(1));
        let held = permits
            .take("10.0.0.1".parse::<IpAddr>().unwrap())
            .await
            .expect("the one permit");
        // B asks first, then C; each from a subnet of its own.
        let (btx, brx) = tokio::sync::oneshot::channel();
        let _b = asks_and_holds(permits.clone(), "198.51.100.1", btx);
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        let (ctx, crx) = tokio::sync::oneshot::channel();
        let _c = asks_and_holds(permits.clone(), "203.0.113.1", ctx);
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        // One permit frees: B, which asked first, takes it; C, with none
        // left, waits and times out.
        drop(held);
        assert!(brx.await.unwrap(), "the earliest waiter was not served");
        assert!(!crx.await.unwrap(), "a later asker took the permit");
    }

    /// A holder that lets go and at once asks again does not starve a
    /// waiter that asked earlier (decision 2026-10-22 (memory), rule 2):
    /// its new ask joins the back of the queue. The holder retakes in a
    /// tight loop that never yields to the waiter of its own accord, so
    /// without the queue it would take a free permit on the spot every
    /// time, before the woken waiter runs, and starve it. With the queue
    /// its first re-take must wait behind the waiter, which then runs and
    /// is served.
    #[tokio::test(start_paused = true)]
    async fn a_holder_that_retakes_does_not_starve_a_waiter() {
        use std::net::IpAddr;
        let permits = std::sync::Arc::new(LargePermits::new(1));
        let mut held = Some(
            permits
                .take("10.0.0.1".parse::<IpAddr>().unwrap())
                .await
                .expect("the one permit"),
        );
        // The waiter asks from a subnet of its own and signals when served.
        let (served_tx, mut served_rx) = tokio::sync::oneshot::channel();
        let pw = permits.clone();
        let waiter = tokio::spawn(async move {
            let got = pw.take("198.51.100.1".parse().unwrap()).await;
            let _ = served_tx.send(got.is_some());
        });
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        // The holder retakes in a tight loop, never yielding to the waiter
        // on its own.
        for _ in 0..10 {
            drop(held.take());
            held = permits.take("10.0.0.1".parse().unwrap()).await;
            if held.is_none() {
                break;
            }
        }
        drop(held.take());
        assert_eq!(
            served_rx.try_recv(),
            Ok(true),
            "a retaking holder starved the waiter that asked first"
        );
        let _ = waiter.await;
    }

    /// A frame longer than a small message from an unlisted peer is not
    /// read until a permit is free (decision 2026-10-22 (memory), rule 2):
    /// the permit is taken before the payload is read or allocated, so
    /// while none is free the node reads none of the body, and the peer,
    /// which cannot push it all through the stream's window, waits. Once a
    /// permit is free, the body is read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_large_frame_from_an_unlisted_peer_is_not_read_without_a_permit() {
        use std::sync::atomic::{AtomicBool, Ordering};
        // The only permit, held from another subnet.
        let permits = std::sync::Arc::new(LargePermits::new(1));
        let held = permits
            .take("203.0.113.1".parse().unwrap())
            .await
            .expect("the one permit");

        // A pipe too small to hold the whole frame, so the peer's write
        // cannot finish until the node reads the body.
        let (mut peer_w, node_r) = tokio::io::duplex(64 * 1024);

        let np = permits.clone();
        let node = tokio::spawn(async move {
            let mut node_r = node_r;
            // An unlisted peer (listed = false), with the budget full.
            matches!(
                read_under_permit(
                    &mut node_r,
                    Some(&np),
                    "198.51.100.1".parse().unwrap(),
                    false,
                )
                .await,
                Framed::Frame(..)
            )
        });

        // The peer writes a frame of 200,000 bytes: longer than a small
        // message, no message of the stream.
        let done = std::sync::Arc::new(AtomicBool::new(false));
        let wrote = done.clone();
        let writer = tokio::spawn(async move {
            use cordelia_network::codec::write_raw_frame;
            let _ = write_raw_frame(&mut peer_w, &vec![0x5a; 200_000]).await;
            wrote.store(true, Ordering::SeqCst);
            // Keep the pipe open until the node is done.
            peer_w
        });

        // While the permit is held, the body is not read: the peer cannot
        // finish writing it through the window.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !done.load(Ordering::SeqCst),
            "the body was read with no permit free"
        );
        // Letting the permit go lets the node read the body.
        drop(held);
        let read_body = tokio::time::timeout(std::time::Duration::from_secs(5), node)
            .await
            .expect("the node did not read the body once a permit was free")
            .unwrap();
        assert!(read_body, "the frame was not read whole");
        let _ = writer.await;
    }

    /// A relay listed by key is outside rule 2 (rule 7): its frame longer
    /// than a small message is read at once, with every permit held.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_listed_relays_large_frame_is_read_with_every_permit_held() {
        let permits = std::sync::Arc::new(LargePermits::new(1));
        let _held = permits
            .take("203.0.113.1".parse().unwrap())
            .await
            .expect("the one permit");
        let (mut peer_w, node_r) = tokio::io::duplex(64 * 1024);
        let np = permits.clone();
        let node = tokio::spawn(async move {
            let mut node_r = node_r;
            // Listed by key (rule 7): read at once.
            read_under_permit(
                &mut node_r,
                Some(&np),
                "198.51.100.1".parse().unwrap(),
                true,
            )
            .await;
        });
        let writer = tokio::spawn(async move {
            use cordelia_network::codec::write_raw_frame;
            let _ = write_raw_frame(&mut peer_w, &vec![0x5a; 200_000]).await;
            peer_w
        });
        // The node reads the frame although the only permit is held: it
        // ends without waiting for one.
        tokio::time::timeout(std::time::Duration::from_secs(5), node)
            .await
            .expect("a listed relay's large frame was not read with the permit held")
            .unwrap();
        let _ = writer.await;
    }

    /// A push of entries longer than a small message, for which no permit
    /// comes within STREAM_TIMEOUT, is refused with ERR_LARGE_MESSAGE_LATER and
    /// counts no breach (decision 2026-10-22 (memory), rule 2): the node
    /// stops its receive side with 0x05, which the peer sees, and the
    /// peer's push allowance is untouched. (This waits out the stream
    /// timeout, about ten seconds.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_large_frame_with_no_permit_is_refused_later_and_counts_no_breach() {
        within("a_large_frame_with_no_permit_is_refused_later_and_counts_no_breach", 60, async move {
        use cordelia_network::codec::write_protocol_byte;
        use cordelia_network::messages::Protocol;
        use cordelia_network::{connection, transport};

        let id = |seed: u8| {
            std::sync::Arc::new(
                cordelia_crypto::identity::NodeIdentity::from_seed([seed; 32]).unwrap(),
            )
        };
        let here: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (node_id_key, client_key) = (id(1), id(2));
        let node_end = transport::create_endpoint(&node_id_key, here).unwrap();
        let node_addr = node_end.local_addr().unwrap();
        let node_mgr = connection::ConnectionManager::new(
            node_id_key.clone(),
            node_end,
            vec![],
            vec!["relay".into()],
            node_addr.port(),
        );
        let (accepts, as_node) = (node_mgr.endpoint(), node_mgr.connect_context());

        // Every permit held, from four other subnets.
        let permits = std::sync::Arc::new(LargePermits::new(
            cordelia_core::protocol::LARGE_MESSAGES_AT_ONCE,
        ));
        let mut _held = Vec::new();
        for n in 0..cordelia_core::protocol::LARGE_MESSAGES_AT_ONCE {
            _held.push(
                permits
                    .take(std::net::IpAddr::from([10, n as u8, 0, 1]))
                    .await
                    .expect("budget"),
            );
        }

        let state = a_state();
        let rates = std::sync::Arc::new(std::sync::Mutex::new(Rates::default()));
        let peer = NodeId(client_key.public_key());
        let address: std::net::IpAddr = "198.51.100.7".parse().unwrap();

        // A relay that serves the streams of entries, with the permits.
        let entries = crate::relay_entries::RelayEntries::new(
            u64::MAX,
            Default::default(),
            std::time::Duration::from_secs(600),
        );

        let serving = {
            let (state, rates, permits, peer) =
                (state.clone(), rates.clone(), permits.clone(), peer.clone());
            tokio::spawn(async move {
                let incoming = accepts.accept().await.unwrap();
                let conn = connection::inbound_accept(&as_node, incoming)
                    .await
                    .unwrap()
                    .conn;
                let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                let _ = cordelia_network::codec::read_protocol_byte(&mut recv)
                    .await
                    .unwrap();
                let over = {
                    let serving = crate::relay_entries::Serving {
                        conn: Some(&conn),
                        peer: &peer,
                        address,
                        db: &state.db,
                        rates: &rates,
                        permits: Some(&permits),
                    };
                    entries
                        .serve(
                            Protocol::EntryPush,
                            &mut send,
                            &mut recv,
                            &serving,
                            &mut crate::relay_entries::Proved::default(),
                            &mut crate::relay_entries::ShownWhole::default(),
                        )
                        .await
                };
                // Keep the connection alive so the reset reaches the peer
                // before the connection closes.
                (over, conn)
            })
        };

        let mut client_mgr = connection::ConnectionManager::new(
            client_key.clone(),
            transport::create_endpoint(&client_key, here).unwrap(),
            vec![],
            vec![],
            9474,
        );
        client_mgr.connect_to(node_addr).await.unwrap();
        let conn = client_mgr
            .get_connection(&NodeId(node_id_key.public_key()))
            .unwrap()
            .clone();
        let (mut csend, mut crecv) = conn.open_bi().await.unwrap();
        write_protocol_byte(&mut csend, Protocol::EntryPush)
            .await
            .unwrap();
        // A frame of a megabyte: longer than a small message, and than the
        // stream's window, so the write waits while the node reads none of
        // the body, as a device of the version before waits in its write,
        // until the node stops the receive side. The send is left open
        // (not finished), so the stop is seen on it.
        //
        // The peer waits in its write for longer than the node waits for a
        // permit, so that the node's refusal is what ends it. Written with
        // the codec, the write gave up at its own STREAM_TIMEOUT, the same
        // 10 s as the node's wait and begun a little before it; where it
        // gave up first, it reset its own send side, the node's stop was
        // never seen on it, and `stopped` below waited for ever (about one
        // run in four with ten at once).
        let frame = vec![0x5a; 1_000_000];
        let written = tokio::time::timeout(2 * cordelia_network::codec::STREAM_TIMEOUT, async {
            csend.write_all(&(frame.len() as u32).to_be_bytes()).await?;
            csend.write_all(&frame).await
        })
        .await
        .expect("the node did not stop the stream of a frame it had no permit for");
        let later = quinn::VarInt::from_u32(cordelia_core::protocol::ERR_LARGE_MESSAGE_LATER);
        assert!(
            matches!(written, Err(quinn::WriteError::Stopped(code)) if code == later),
            "the peer's write was not stopped with ERR_LARGE_MESSAGE_LATER: {written:?}"
        );

        // The node resets the send side with ERR_LARGE_MESSAGE_LATER
        // (0x05), which the peer learns when it reads the stream.
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            crecv.read_to_end(1 << 20),
        )
        .await
        .expect("the node never refused the frame");
        match read {
            Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code))) => assert_eq!(
                code,
                quinn::VarInt::from_u32(cordelia_core::protocol::ERR_LARGE_MESSAGE_LATER),
                "the stream was reset with another code"
            ),
            other => panic!("the stream was not reset with ERR_LARGE_MESSAGE_LATER: {other:?}"),
        }
        // The node also stops the receive side with the same code, which
        // the peer learns as its own send being stopped.
        let stopped = tokio::time::timeout(std::time::Duration::from_secs(5), csend.stopped())
            .await
            .expect("the peer's send was never said to be stopped");
        match stopped {
            Ok(Some(code)) => assert_eq!(
                code,
                quinn::VarInt::from_u32(cordelia_core::protocol::ERR_LARGE_MESSAGE_LATER),
                "the receive side was stopped with another code"
            ),
            other => {
                panic!("the receive side was not stopped with ERR_LARGE_MESSAGE_LATER: {other:?}")
            }
        }
        // It was refused, not stored, and counts no breach.
        let (over, _conn) = tokio::time::timeout(std::time::Duration::from_secs(5), serving)
            .await
            .expect("the node's handler did not end once it had refused the frame")
            .unwrap();
        assert!(over.is_none(), "a refused large frame counted a breach");
        assert!(
            !rates.lock().unwrap().is_counting(&peer),
            "a refused large frame was counted against the peer's push allowance"
        );
        })
        .await;
    }

    /// Which inbound handler to run over a pair of pipes.
    enum Handler {
        PeerShare,
        SyncNothing,
    }

    /// Whether the handler reads the body of a frame larger than a small
    /// message (decision 2026-10-22 (memory), rule 2): the pipe is too
    /// small to hold the frame, so the peer's write finishes only if the
    /// handler drains the body. A handler that refuses at the length
    /// leaves it blocked. `false` means the body was not read.
    async fn handler_drains_a_large_frame(which: Handler) -> bool {
        let (mut peer_w, mut node_r) = tokio::io::duplex(64 * 1024);
        let (mut node_w, _peer_r) = tokio::io::duplex(64 * 1024);
        let peer = NodeId([9; 32]);
        // 200,000 bytes: longer than a small message (147,456).
        let frame = vec![0x5au8; 200_000];
        let wrote = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let w = wrote.clone();
        let writer = async {
            let _ = cordelia_network::codec::write_raw_frame(&mut peer_w, &frame).await;
            w.store(true, std::sync::atomic::Ordering::SeqCst);
        };
        let handler = async {
            match which {
                Handler::PeerShare => {
                    let shared = std::sync::Arc::new(std::sync::RwLock::new(Vec::new()));
                    handle_inbound_peer_share(&mut node_w, &mut node_r, &peer, &shared, "relay")
                        .await;
                }
                Handler::SyncNothing => {
                    answer_sync_with_nothing(&mut node_w, &mut node_r, &peer).await;
                }
            }
        };
        // The handler that refuses at the length returns at once and the
        // write stays blocked, so the join never finishes: the timeout
        // then leaves `wrote` false. A handler that drains the body lets
        // the write finish, and the join returns with `wrote` true.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(400), async {
            tokio::join!(handler, writer)
        })
        .await;
        wrote.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The peer-share and older-kind-sync handlers read a frame only
    /// within a small message (decision 2026-10-22 (memory),
    /// rule 2): no honest message of any version on these streams is
    /// larger, so a longer frame is refused at its length and its body is
    /// not read.
    #[tokio::test]
    async fn the_small_streams_do_not_read_a_frame_over_a_small_message() {
        within(
            "the_small_streams_do_not_read_a_frame_over_a_small_message",
            60,
            async move {
                assert!(
                    !handler_drains_a_large_frame(Handler::PeerShare).await,
                    "peer-share read a frame over a small message"
                );
                assert!(
                    !handler_drains_a_large_frame(Handler::SyncNothing).await,
                    "the older kind's answer-nothing read a frame over a small message"
                );
            },
        )
        .await;
    }

    /// Whether a relay reads and answers a large push (longer than a small
    /// message) from a client, run through the live inbound loop
    /// (`handle_peer_streams`), on the stream `EntryPush` (0x13), whose
    /// permits the loop hands to `serve` in the `Serving` it builds. The
    /// client is listed by key iff `listed`, and is in `peer_relays` (a
    /// relay configured by address alone) iff `addressed`; the large-permit
    /// budget is `budget`. A permit is read and answered within two seconds,
    /// or it is not.
    async fn large_push_answered(listed: bool, addressed: bool, budget: usize) -> bool {
        use cordelia_network::bootstrap::RelayAddr;
        use cordelia_network::messages::{EntryPush, Protocol, WireMessage};
        use cordelia_network::{codec, connection, transport};
        use std::collections::{HashMap, HashSet};
        use std::net::SocketAddr;
        use std::sync::{Arc, RwLock};

        let id =
            |s: u8| Arc::new(cordelia_crypto::identity::NodeIdentity::from_seed([s; 32]).unwrap());
        let here: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (node, client) = (id(1), id(2));
        let client_key = NodeId(client.public_key());
        let node_end = transport::create_endpoint(&node, here).unwrap();
        let node_addr = node_end.local_addr().unwrap();
        let node_mgr = connection::ConnectionManager::new(
            node.clone(),
            node_end,
            vec![],
            vec!["relay".into()],
            node_addr.port(),
        );
        let (accepts, as_node) = (node_mgr.endpoint(), node_mgr.connect_context());

        // The relay lists the client by key iff `listed`.
        let relays = if listed {
            vec![RelayAddr {
                host: "listed.example:9474".into(),
                addr: SocketAddr::new("127.0.0.1".parse().unwrap(), 9474),
                key: Some(client_key.0),
            }]
        } else {
            vec![]
        };
        let relay_entries = Some(Arc::new(crate::relay_entries::RelayEntries::new(
            u64::MAX,
            Arc::new(RwLock::new(relays)),
            std::time::Duration::from_secs(600),
        )));
        // It is a relay configured by address alone (in peer_relays, not
        // listed by key) iff `addressed`.
        let peer_relays = Arc::new(RwLock::new(HashSet::new()));
        if addressed {
            peer_relays.write().unwrap().insert(client_key.clone());
        }
        let peer_states = Arc::new(RwLock::new(HashMap::from([(client_key.clone(), 1u8)])));
        let permits = Arc::new(LargePermits::new(budget));
        let state = a_state();
        let (gov_tx, _g) = tokio::sync::mpsc::unbounded_channel();
        let shared_peers = Arc::new(RwLock::new(Vec::new()));
        let peer_rates = Arc::new(std::sync::Mutex::new(Rates::default()));

        let node_conn = {
            let as_node = as_node.clone();
            tokio::spawn(async move {
                let incoming = accepts.accept().await.unwrap();
                connection::inbound_accept(&as_node, incoming)
                    .await
                    .unwrap()
                    .conn
            })
        };
        let mut client_mgr = connection::ConnectionManager::new(
            client.clone(),
            transport::create_endpoint(&client, here).unwrap(),
            vec![],
            vec![],
            9474,
        );
        client_mgr.connect_to(node_addr).await.unwrap();
        let conn = client_mgr
            .get_connection(&NodeId(node.public_key()))
            .unwrap()
            .clone();
        let node_conn = node_conn.await.unwrap();

        let loop_task = tokio::spawn(handle_peer_streams(
            node_conn,
            client_key,
            "127.0.0.1".parse().unwrap(),
            state,
            shared_peers,
            "relay".into(),
            peer_rates,
            peer_states,
            peer_relays,
            gov_tx,
            relay_entries,
            permits,
        ));

        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        codec::write_protocol_byte(&mut send, Protocol::EntryPush)
            .await
            .unwrap();
        // A push of one big entry: a valid message, so a relay that reads
        // it answers (the per-entry word), and a relay that does not read
        // it does not.
        let push = WireMessage::EntryPush(EntryPush {
            entries: vec![serde_bytes::ByteBuf::from(vec![0u8; 200_000])],
        });
        let frame = codec::encode_message(&push).unwrap();
        assert!(
            frame.len() > cordelia_core::protocol::SMALL_MESSAGE_BYTES as usize,
            "the push was meant to be over a small message"
        );
        let _ = codec::write_raw_frame(&mut send, &frame).await;
        // An answer within two seconds means it was read.
        let answered = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            codec::read_frame(&mut recv, Protocol::EntryPush),
        )
        .await
        .is_ok_and(|r| r.is_ok());
        loop_task.abort();
        answered
    }

    /// The live inbound loop hands the permits to the streams of entries
    /// (decision 2026-10-22 (memory), rules 2 and 7; the high finding), and
    /// exempts a relay listed by key alone, not one configured by address.
    /// On a 0x13 EntryPush stream the loop builds a `Serving` with the
    /// permits: with no permit free, a listed relay's large push is read,
    /// an unlisted peer's and a relay-by-address's are not; with a permit
    /// free, an unlisted peer's is read. This catches `permits: None` in
    /// that `Serving`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_inbound_loop_takes_permits_on_the_streams_of_entries() {
        within(
            "the_inbound_loop_takes_permits_on_the_streams_of_entries",
            60,
            async move {
                // A relay listed by key: read though no permit is free (rule 7).
                assert!(
                    large_push_answered(true, false, 0).await,
                    "a listed relay's large entry push was not read"
                );
                // An unlisted peer: not read with no permit (rule 2).
                assert!(
                    !large_push_answered(false, false, 0).await,
                    "an unlisted peer's large entry push was read with no permit"
                );
                // A relay configured by address alone is unlisted: it waits.
                assert!(
                    !large_push_answered(false, true, 0).await,
                    "a relay configured by address alone was exempted"
                );
                // With a permit free, an unlisted peer's entry push is read.
                assert!(
                    large_push_answered(false, false, 1).await,
                    "an unlisted peer's large entry push was not read when a permit was free"
                );
            },
        )
        .await;
    }

    /// A permit a stream held and then failed on is given back (decision
    /// 2026-10-22 (memory), rule 2): five streams fail in turn, and then
    /// four permits can be taken at once.
    #[tokio::test(start_paused = true)]
    async fn a_permit_a_failed_stream_held_is_given_back() {
        use std::net::IpAddr;
        let permits = std::sync::Arc::new(LargePermits::new(
            cordelia_core::protocol::LARGE_MESSAGES_AT_ONCE,
        ));
        // Five streams each take a permit and fail, one after another.
        for n in 0..5u8 {
            let g = permits
                .take(IpAddr::from([10, n, 0, 1]))
                .await
                .expect("a permit for a failing stream");
            drop(g);
        }
        // All four permits are free again.
        let mut held = Vec::new();
        for n in 0..cordelia_core::protocol::LARGE_MESSAGES_AT_ONCE as u8 {
            held.push(
                permits
                    .take(IpAddr::from([172, 16, n, 1]))
                    .await
                    .expect("four permits after five failed"),
            );
        }
        assert!(
            permits.take(IpAddr::from([192, 0, 2, 1])).await.is_none(),
            "a fifth permit was held past the budget"
        );
    }

    /// A waiter whose `take` is cancelled leaves the queue, so a later
    /// asker is still served (decision 2026-10-22 (memory), rule 2). The
    /// waiter is cancelled by an outer timeout while the one permit is
    /// held; once it is free, a take from a third subnet is granted, which
    /// it could not be if the cancelled ticket stayed to hold it back.
    #[tokio::test]
    async fn a_cancelled_waiter_does_not_stall_the_queue() {
        use std::net::IpAddr;
        let permits = std::sync::Arc::new(LargePermits::new(1));
        // The one permit is held by the first subnet.
        let held = permits
            .take(IpAddr::from([10, 0, 0, 1]))
            .await
            .expect("the one permit");
        // A waiter from a second subnet asks, and is cancelled by an outer
        // timeout before any permit frees: its `take` future is dropped.
        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            permits.take(IpAddr::from([198, 51, 100, 1])),
        )
        .await;
        assert!(cancelled.is_err(), "the waiter was meant to be cancelled");
        // The permit is freed.
        drop(held);
        // A take from a third subnet is granted: the cancelled waiter left
        // no ticket behind to hold it back.
        let got = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            permits.take(IpAddr::from([203, 0, 113, 1])),
        )
        .await;
        assert!(
            matches!(got, Ok(Some(_))),
            "a later asker was not served after a cancelled waiter: the queue stalled"
        );
    }

    /// Over QUIC, a large frame that waited for a permit is read and
    /// answered once one frees, not refused (decision 2026-10-22 (memory),
    /// rule 2; the let-go half of the record's test 2). The one permit is
    /// held, the client sends a push of entries longer than a small
    /// message, the permit is let go well within the stream timeout, and
    /// the push is answered rather than refused with
    /// ERR_LARGE_MESSAGE_LATER.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_large_frame_is_read_once_a_permit_frees_over_quic() {
        within(
            "a_large_frame_is_read_once_a_permit_frees_over_quic",
            60,
            async move {
                use cordelia_network::codec::{read_frame, write_protocol_byte, write_raw_frame};
                use cordelia_network::messages::{EntryPush, Protocol, WireMessage};
                use cordelia_network::{connection, transport};

                let id = |seed: u8| {
                    std::sync::Arc::new(
                        cordelia_crypto::identity::NodeIdentity::from_seed([seed; 32]).unwrap(),
                    )
                };
                let here: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
                let (node_id_key, client_key) = (id(1), id(2));
                let node_end = transport::create_endpoint(&node_id_key, here).unwrap();
                let node_addr = node_end.local_addr().unwrap();
                let node_mgr = connection::ConnectionManager::new(
                    node_id_key.clone(),
                    node_end,
                    vec![],
                    vec!["relay".into()],
                    node_addr.port(),
                );
                let (accepts, as_node) = (node_mgr.endpoint(), node_mgr.connect_context());

                // One permit, held from another subnet, so the push must wait.
                let permits = std::sync::Arc::new(LargePermits::new(1));
                let held = permits
                    .take(std::net::IpAddr::from([10, 0, 0, 1]))
                    .await
                    .expect("the one permit");

                let state = a_state();
                let rates = std::sync::Arc::new(std::sync::Mutex::new(Rates::default()));
                let peer = NodeId(client_key.public_key());
                let address: std::net::IpAddr = "198.51.100.7".parse().unwrap();
                // A relay that serves the streams of entries, with the permits.
                let entries = crate::relay_entries::RelayEntries::new(
                    u64::MAX,
                    Default::default(),
                    std::time::Duration::from_secs(600),
                );

                let serving = {
                    let (state, rates, permits, peer) =
                        (state.clone(), rates.clone(), permits.clone(), peer.clone());
                    tokio::spawn(async move {
                        let incoming = accepts.accept().await.unwrap();
                        let conn = connection::inbound_accept(&as_node, incoming)
                            .await
                            .unwrap()
                            .conn;
                        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                        let _ = cordelia_network::codec::read_protocol_byte(&mut recv)
                            .await
                            .unwrap();
                        {
                            let serving = crate::relay_entries::Serving {
                                conn: Some(&conn),
                                peer: &peer,
                                address,
                                db: &state.db,
                                rates: &rates,
                                permits: Some(&permits),
                            };
                            entries
                                .serve(
                                    Protocol::EntryPush,
                                    &mut send,
                                    &mut recv,
                                    &serving,
                                    &mut crate::relay_entries::Proved::default(),
                                    &mut crate::relay_entries::ShownWhole::default(),
                                )
                                .await;
                        }
                        // Keep the connection alive while the client reads the answer.
                        conn
                    })
                };

                let mut client_mgr = connection::ConnectionManager::new(
                    client_key.clone(),
                    transport::create_endpoint(&client_key, here).unwrap(),
                    vec![],
                    vec![],
                    9474,
                );
                client_mgr.connect_to(node_addr).await.unwrap();
                let conn = client_mgr
                    .get_connection(&NodeId(node_id_key.public_key()))
                    .unwrap()
                    .clone();
                let (mut csend, mut crecv) = conn.open_bi().await.unwrap();
                write_protocol_byte(&mut csend, Protocol::EntryPush)
                    .await
                    .unwrap();
                // A valid push longer than a small message: one big entry.
                let push = WireMessage::EntryPush(EntryPush {
                    entries: vec![serde_bytes::ByteBuf::from(vec![0u8; 200_000])],
                });
                let frame = cordelia_network::codec::encode_message(&push).unwrap();
                assert!(
                    frame.len() > cordelia_core::protocol::SMALL_MESSAGE_BYTES as usize,
                    "the push was meant to be over a small message"
                );
                // The frame is longer than the stream's window, so its write waits
                // while the node waits for a permit, as a device of the version
                // before waits in its write.
                let writing = tokio::spawn(async move {
                    let _ = write_raw_frame(&mut csend, &frame).await;
                    csend
                });

                // The node is parked, waiting for a permit. Let the held one go,
                // well within the stream timeout.
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                drop(held);

                // The push is answered, not refused.
                let answered = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    read_frame(&mut crecv, Protocol::EntryPush),
                )
                .await;
                assert!(
                    answered.is_ok_and(|r| r.is_ok()),
                    "the large frame was not answered once a permit freed"
                );
                let _ = writing.await;
                let _ = serving.await;
            },
        )
        .await;
    }

    /// The peer-share answer is encoded and the message dropped before the
    /// write (decision 2026-10-22 (memory), rule 4): while the write waits
    /// for a peer that does not read, the node holds the encoding alone,
    /// not the list of peers beside it. The node has many peers to share;
    /// the answer is written to a pipe the client never drains.
    #[tokio::test]
    async fn a_peer_share_answer_is_not_held_through_its_write() {
        use crate::counting;
        use cordelia_network::codec::write_raw_frame;
        use cordelia_network::messages::{PeerAddress, PeerShareRequest, WireMessage};

        // Many peers: enough that the answer is a few hundred KB, so the
        // difference between holding the encoding alone and the list beside
        // it is plain.
        let peers: Vec<PeerAddress> = (0..5000u32)
            .map(|n| PeerAddress {
                node_id: vec![(n % 256) as u8; 32],
                addrs: vec![format!("203.0.113.{}:{}", n % 256, 9000 + (n % 1000))],
                last_seen: n as u64,
                exclude: false,
            })
            .collect();
        let shared = std::sync::Arc::new(std::sync::RwLock::new(peers));

        // A pipe wide for the small request, too small for the answer: the
        // answer's write blocks while the client does not read it.
        let (mut client_w, mut node_r) = tokio::io::duplex(64 * 1024);
        let (mut node_w, client_r) = tokio::io::duplex(64 * 1024);
        let peer = NodeId([7; 32]);
        let node = handle_inbound_peer_share(&mut node_w, &mut node_r, &peer, &shared, "relay");
        tokio::pin!(node);

        let client = async {
            let req = cordelia_network::codec::encode_message(&WireMessage::PeerShareRequest(
                PeerShareRequest { max_peers: 65535 },
            ))
            .unwrap();
            let before = counting::live();
            // The request is tiny; the node builds the answer of all the
            // peers and begins to write it. The client does not read, so
            // the write waits.
            write_raw_frame(&mut client_w, &req).await.unwrap();
            for _ in 0..50 {
                tokio::task::yield_now().await;
            }
            counting::live() - before
        };

        let held = tokio::select! {
            _ = &mut node => panic!("the handler ended without blocking in its write"),
            held = client => held,
        };
        println!("held while the peer-share answer is written: {held} bytes");
        // The encoded answer is about 590 KB. Holding the list of peers as a
        // message beside its encoding is about 1.28 MB (measured), so the
        // window below tells the two apart with room to spare.
        assert!(
            held > 300_000,
            "the answer of all the peers was not built: {held} bytes"
        );
        assert!(
            held < 900_000,
            "the node holds {held} bytes: the answer is held as a message through its write"
        );
        drop(client_r);
    }

    // ── A relay out of reach (decision 2026-10-19) ──────────────────

    /// What a device knows of whether it can reach `relays`, each with
    /// whether it holds the change entry it keeps, on a clock that the
    /// test moves.
    fn reach_of(
        relays: &[(&TriedRelay, cordelia_api::state::Holds)],
    ) -> (
        std::sync::Arc<cordelia_node::device_entries::Reach>,
        cordelia_node::device_entries::Clock,
    ) {
        let clock = cordelia_node::device_entries::Clock::system();
        let reach = cordelia_node::device_entries::Reach::new(clock.clone());
        knows(&reach, [1; 32], relays);
        (reach, clock)
    }

    /// The device keeps the change entry `kept`, and each of `relays`
    /// holds it as said.
    fn knows(
        reach: &cordelia_node::device_entries::Reach,
        kept: [u8; 32],
        relays: &[(&TriedRelay, cordelia_api::state::Holds)],
    ) {
        let each: Vec<_> = relays
            .iter()
            .map(|(relay, holds)| (reach_id(relay), *holds, None))
            .collect();
        reach.observe(Some(kept), true, &each);
    }

    /// The wait before the next dial that a failure leaves.
    fn wait_after(tried: &RelayTry) -> u64 {
        let next = tried.next_try.unwrap();
        next.saturating_duration_since(std::time::Instant::now())
            .as_secs_f64()
            .round() as u64
    }

    /// A relay that lacks the change is dialled at the pace of a node that
    /// is cut off (decision 2026-10-19, rule 3): with another relay
    /// connected its wait doubles up to 30 s, not 900 s. Once it holds
    /// the change its next wait is as before, at the cap, with the
    /// failures it counted. A relay in the third state, and every relay
    /// of a node that keeps nothing of reach, is dialled as before.
    #[test]
    fn a_relay_that_lacks_the_change_is_dialled_at_the_pace_of_a_node_cut_off() {
        use cordelia_api::state::Holds;
        use cordelia_core::protocol::{BACKOFF_BASE_SECS, BACKOFF_MAX_SECS};
        let (lacks, holds, third) = (
            ("b.example:9474".to_string(), Some([2; 32])),
            ("a.example:9474".to_string(), Some([1; 32])),
            ("c.example:9474".to_string(), None),
        );
        let (reach, clock) = reach_of(&[
            (&lacks, Holds::Lacks),
            (&holds, Holds::Holds),
            (&third, Holds::Neither),
        ]);
        let (known, reach) = (&*reach, Some(&*reach));
        let mut tries: std::collections::HashMap<TriedRelay, RelayTry> = Default::default();
        // The dials are a while after the start, so that a dial left in
        // flight would be in flight still when the five minutes are over.
        let second = std::time::Duration::from_secs(1);
        clock.run_ahead(100 * second);
        for _ in 0..40 {
            for relay in [&lacks, &holds, &third] {
                known.dial_begins(&reach_id(relay));
                dial_failed(
                    &mut tries,
                    (relay.clone(), false),
                    "down".into(),
                    (false, 10, true),
                    reach,
                );
            }
            assert!(wait_after(&tries[&lacks]) <= BACKOFF_BASE_SECS);
        }
        // Each dial was an attempt, and failed: none is in flight five
        // minutes after the start.
        clock.run_ahead(200 * second);
        assert!(known.is_out_of_reach(&reach_id(&lacks)));
        assert_eq!(wait_after(&tries[&lacks]), BACKOFF_BASE_SECS);
        assert_eq!(wait_after(&tries[&holds]), BACKOFF_MAX_SECS);
        assert_eq!(wait_after(&tries[&third]), BACKOFF_MAX_SECS);
        // It takes the change: the next wait is at the cap, with the
        // failures it counted.
        knows(
            known,
            [1; 32],
            &[(&lacks, Holds::Holds), (&holds, Holds::Holds)],
        );
        dial_failed(
            &mut tries,
            (lacks.clone(), false),
            "down".into(),
            (false, 10, true),
            reach,
        );
        assert_eq!(tries[&lacks].failures, 41);
        assert_eq!(wait_after(&tries[&lacks]), BACKOFF_MAX_SECS);
        // With no relay connected, every relay is paced as cut off.
        assert!(!paced_with_another(false, reach, &holds));
        // A node that keeps nothing of reach: as before.
        assert!(paced_with_another(true, None, &lacks));
    }

    /// A wait already set is cut when the relay comes to lack the change
    /// (decision 2026-10-19, rule 3): a next try 900 s ahead becomes 30 s
    /// ahead, a shorter one stands, the failures counted stand, and the
    /// lookups of names are woken.
    #[tokio::test]
    async fn a_wait_already_set_is_cut_when_the_relay_comes_to_lack_the_change() {
        use cordelia_api::state::Holds;
        use cordelia_core::protocol::{BACKOFF_BASE_SECS, BACKOFF_MAX_SECS};
        let (far, near) = (
            ("b.example:9474".to_string(), Some([2; 32])),
            ("a.example:9474".to_string(), None),
        );
        let (reach, _clock) = reach_of(&[(&far, Holds::Holds), (&near, Holds::Holds)]);
        let now = std::time::Instant::now();
        let mut tries: std::collections::HashMap<TriedRelay, RelayTry> = Default::default();
        for (relay, wait) in [(&far, BACKOFF_MAX_SECS), (&near, 5)] {
            let tried = tries.entry(relay.clone()).or_default();
            tried.failures = 9;
            tried.next_try = Some(now + std::time::Duration::from_secs(wait));
        }
        // Nothing has come to lack the change: nothing is cut.
        cut_waits(&mut tries, &reach.came_to_lack(), now);
        assert_eq!(wait_after(&tries[&far]), BACKOFF_MAX_SECS);
        // A new kept entry, which both lack.
        knows(
            &reach,
            [3; 32],
            &[(&far, Holds::Lacks), (&near, Holds::Lacks)],
        );
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            reach.lookups().notified(),
        )
        .await
        .expect("the lookups are woken");
        cut_waits(&mut tries, &reach.came_to_lack(), now);
        assert_eq!(wait_after(&tries[&far]), BACKOFF_BASE_SECS);
        assert_eq!(wait_after(&tries[&near]), 5);
        assert_eq!((tries[&far].failures, tries[&near].failures), (9, 9));
    }

    /// A device that wakes dials each relay that it does not reach at
    /// once (decision 2026-10-24 (removal), section 8): every wait already
    /// set is cut to now, the failures counted stand, and the relay is
    /// dialled at the tick. **A relay busy at the wake, its dial in flight
    /// from before, is owed its dial:** once that dial has failed and set
    /// a long wait, it is dialled at the next tick. After the wake's dial,
    /// and past the wait, nothing is owed, and the pace stands.
    #[test]
    fn a_wake_has_each_relay_dialled_at_once() {
        use cordelia_core::protocol::{BACKOFF_MAX_SECS, WAKE_WAIT_SECS};
        use std::time::Duration;
        let relay = cordelia_network::bootstrap::RelayAddr {
            host: "b.example:9474".into(),
            addr: std::net::SocketAddr::from(([127, 0, 0, 2], 9474)),
            key: Some([2; 32]),
        };
        let id = tried_relay(&relay);
        let relays = [relay.clone()];
        let now = std::time::Instant::now();
        let mut tries: std::collections::HashMap<TriedRelay, RelayTry> = Default::default();
        let tried = tries.entry(id.clone()).or_default();
        tried.failures = 9;
        tried.next_try = Some(now + Duration::from_secs(BACKOFF_MAX_SECS));
        let mut dialling = Dialling::default();
        // One tick of the dial loop at `now`, with the relay `busy` or not.
        let mut wake = WakeDials::default();
        let mut tick_at = |tries: &mut std::collections::HashMap<TriedRelay, RelayTry>,
                           wake: &mut WakeDials,
                           now: std::time::Instant,
                           busy: bool| {
            wake.cut(tries, &relay, now);
            let tick = Tick {
                now,
                settled: Duration::from_secs(2),
                secs: 2,
                any_connected: true,
                busy,
            };
            let dials = relay_tick(
                tries,
                &mut dialling,
                (&relays, &relay),
                &|_| false,
                tick,
                None,
            );
            if dials {
                wake.dialled(&relay);
            }
            dials
        };
        // With no wake, the wait stands.
        assert!(!tick_at(&mut tries, &mut wake, now, false));

        // It wakes: the relay is dialled at once.
        wake.woke(&relays, now);
        assert!(tick_at(&mut tries, &mut wake, now, false));
        assert_eq!(tries[&id].next_try, Some(now));
        assert_eq!(tries[&id].failures, 9);
        // That dial fails and sets a long wait: the wake owes no more.
        tries
            .get_mut(&id)
            .unwrap()
            .failed("down".into(), false, 2, true);
        let later = now + Duration::from_secs(1);
        assert!(!tick_at(&mut tries, &mut wake, later, false));

        // It wakes again, with a dial of the relay in flight from before.
        wake.woke(&relays, later);
        assert!(!tick_at(&mut tries, &mut wake, later, true));
        // That dial fails, and its wait is long: the relay is still owed
        // the wake's dial, and has it at the next tick.
        tries
            .get_mut(&id)
            .unwrap()
            .failed("down".into(), false, 2, true);
        assert!(tries[&id].next_try.unwrap() > later + Duration::from_secs(60));
        let next = later + Duration::from_secs(1);
        assert!(tick_at(&mut tries, &mut wake, next, false));

        // Past the wait, a relay busy at the wake is owed nothing.
        wake.woke(&relays, next);
        assert!(!tick_at(&mut tries, &mut wake, next, true));
        tries
            .get_mut(&id)
            .unwrap()
            .failed("down".into(), false, 2, true);
        let past = next + Duration::from_secs(WAKE_WAIT_SECS);
        assert!(!tick_at(&mut tries, &mut wake, past, false));
    }

    /// While a relay that lacks the change has a name that does not
    /// resolve, the names are looked up every half minute (decision
    /// 2026-10-19, rule 3); otherwise every five minutes while some name
    /// resolves, as before.
    #[test]
    fn names_are_looked_up_every_half_minute_while_a_relay_that_lacks_the_change_does_not_resolve()
    {
        use cordelia_api::state::Holds;
        use cordelia_core::protocol::{
            BOOTNODE_RESOLVE_INTERVAL_SECS, BOOTNODE_RESOLVE_RETRY_SECS,
        };
        use cordelia_network::bootstrap::{Relay, RelayAddr};
        let set_up = [
            Relay {
                host: "a.example:9474".into(),
                key: None,
            },
            Relay {
                host: "b.example:9474".into(),
                key: Some([2; 32]),
            },
        ];
        let resolved = [RelayAddr {
            host: "a.example:9474".into(),
            addr: "127.0.0.1:9474".parse().unwrap(),
            key: None,
        }];
        let b = ("b.example:9474".to_string(), Some([2; 32]));
        let a = ("a.example:9474".to_string(), None);
        let wait = |reach: Option<&cordelia_node::device_entries::Reach>, have_any| {
            after_lookup(&set_up, &resolved, have_any, reach).as_secs()
        };
        let (reach, _clock) = reach_of(&[(&a, Holds::Holds), (&b, Holds::Holds)]);
        assert_eq!(wait(Some(&reach), true), BOOTNODE_RESOLVE_INTERVAL_SECS);
        assert_eq!(wait(None, true), BOOTNODE_RESOLVE_INTERVAL_SECS);
        assert_eq!(wait(Some(&reach), false), BOOTNODE_RESOLVE_RETRY_SECS);
        knows(&reach, [3; 32], &[(&a, Holds::Holds), (&b, Holds::Lacks)]);
        assert_eq!(wait(Some(&reach), true), BOOTNODE_RESOLVE_RETRY_SECS);
        // A relay that lacks it and resolves does not make the lookups
        // faster.
        knows(&reach, [3; 32], &[(&a, Holds::Lacks), (&b, Holds::Holds)]);
        assert_eq!(wait(Some(&reach), true), BOOTNODE_RESOLVE_INTERVAL_SECS);
    }

    /// A lookup of a relay's name that resolves is no attempt by itself,
    /// and one that does not is a failed attempt (decision 2026-10-19
    /// §1): over ten minutes of lookups every half minute, the relay whose
    /// name does not resolve is out of reach after five, and the one whose
    /// name resolves, and that is not dialled, is not.
    #[test]
    fn a_lookup_that_resolves_is_no_attempt() {
        use cordelia_api::state::Holds;
        use cordelia_network::bootstrap::{Relay, RelayAddr};
        let set_up = [
            Relay {
                host: "a.example:9474".into(),
                key: None,
            },
            Relay {
                host: "b.example:9474".into(),
                key: None,
            },
        ];
        let resolved = [RelayAddr {
            host: "a.example:9474".into(),
            addr: "127.0.0.1:9474".parse().unwrap(),
            key: None,
        }];
        let (a, b) = (
            ("a.example:9474".to_string(), None),
            ("b.example:9474".to_string(), None),
        );
        let (reach, clock) = reach_of(&[(&a, Holds::Lacks), (&b, Holds::Lacks)]);
        for half_minute in 0..=20 {
            if half_minute > 0 {
                clock.run_ahead(std::time::Duration::from_secs(30));
            }
            after_lookup(&set_up, &resolved, true, Some(&reach));
            let out = half_minute >= 10;
            assert_eq!(reach.is_out_of_reach(&reach_id(&b)), out, "{half_minute}");
            assert!(!reach.is_out_of_reach(&reach_id(&a)), "{half_minute}");
        }
    }

    /// A relay given another key, at the address where another relay is
    /// connected, is not dialled: each tick of the dial loop that passes it
    /// over is a failed attempt at it, so it is out of reach after five
    /// minutes with no dial (decision 2026-10-19 §1). The relay that is
    /// connected there is not.
    #[test]
    fn a_relay_with_the_wrong_key_where_another_is_connected_is_out_of_reach_with_no_dial() {
        use cordelia_api::state::Holds;
        use cordelia_network::bootstrap::RelayAddr;
        let at: std::net::SocketAddr = "127.0.0.1:9474".parse().unwrap();
        let relays = [
            RelayAddr {
                host: "a.example:9474".into(),
                addr: at,
                key: Some([1; 32]),
            },
            RelayAddr {
                host: "b.example:9474".into(),
                addr: at,
                key: Some([2; 32]),
            },
            RelayAddr {
                host: "c.example:9474".into(),
                addr: "127.0.0.1:9475".parse().unwrap(),
                key: Some([3; 32]),
            },
        ];
        let connected = |relay: &RelayAddr| relay.key == Some([1; 32]);
        let (a, b, c) = (
            tried_relay(&relays[0]),
            tried_relay(&relays[1]),
            tried_relay(&relays[2]),
        );
        let (reach, clock) =
            reach_of(&[(&a, Holds::Holds), (&b, Holds::Lacks), (&c, Holds::Lacks)]);
        for tick in 0..=300 {
            if tick > 0 {
                clock.run_ahead(std::time::Duration::from_secs(1));
            }
            assert!(passed_over(&relays, &relays[1], &connected, Some(&reach)));
            assert!(!passed_over(&relays, &relays[2], &connected, Some(&reach)));
            assert_eq!(reach.is_out_of_reach(&reach_id(&b)), tick >= 300, "{tick}");
        }
        // The relay at another address is not passed over, and with no
        // attempt is not out of reach.
        assert!(!reach.is_out_of_reach(&reach_id(&c)));
        // With nothing connected there, it is dialled.
        assert!(!passed_over(&relays, &relays[1], &|_| false, Some(&reach)));
    }

    /// A relay given no key at a keyed relay's place is never connected in
    /// its own right (decision 2026-10-17 §1), whether that relay's name
    /// resolves to its address, or that relay's key answers on the
    /// connection there, with the keyed relay's name missing from the
    /// lookup or moved. Through the dial loop's turn: while a connection
    /// is open there, each tick passes it over, a failed attempt at it,
    /// so it is out of reach after five minutes with no dial (decision
    /// 2026-10-19 §1), and it is not one that makes another relay
    /// connected. The relay given the key there, and a relay given no key
    /// at an address of its own, are connected.
    #[test]
    fn a_relay_given_no_key_at_a_keyed_relays_place_is_passed_over_and_comes_to_be_out_of_reach() {
        use cordelia_api::state::Holds;
        use cordelia_network::bootstrap::{Relay, RelayAddr};
        let (here, apart) = (
            "127.0.0.1:9474".parse().unwrap(),
            "127.0.0.1:9475".parse().unwrap(),
        );
        let named = |host: &str, key| Relay {
            host: host.into(),
            key,
        };
        let at = |host: &str, addr, key| RelayAddr {
            host: host.into(),
            addr,
            key,
        };
        let set_up = [
            named("keyed.example:9474", Some([1; 32])),
            named("keyless.example:9474", None),
            named("alone.example:9474", None),
        ];
        let relays = [
            at("keyed.example:9474", here, Some([1; 32])),
            at("keyless.example:9474", here, None),
            at("alone.example:9474", apart, None),
        ];
        // As the node tells: by its key, or by the address alone; the key
        // given to the first answers here, and a key given to none apart.
        let connected = |relay: &RelayAddr| relay.key.is_none_or(|key| key == [1; 32]);
        let key_at = |addr| match addr == here {
            true => Some([1; 32]),
            false => Some([5; 32]),
        };
        let tick = AtTick {
            set_up: &set_up,
            relays: &relays,
            connected: &connected,
            key_at: &key_at,
        };
        let itself: Vec<bool> = relays
            .iter()
            .map(|relay| connected_as_itself(&tick, relay))
            .collect();
        assert_eq!(itself, [true, false, true]);
        // The keyed relay's name missing from the lookup, or moved, while
        // its key answers on the connection at the other's address.
        let missing = [relays[1].clone(), relays[2].clone()];
        let moved = [
            at(
                "keyed.example:9474",
                "127.0.0.1:1".parse().unwrap(),
                Some([1; 32]),
            ),
            relays[1].clone(),
            relays[2].clone(),
        ];
        for listed in [&missing[..], &moved[..]] {
            let tick = AtTick {
                relays: listed,
                ..tick
            };
            assert!(!connected_as_itself(&tick, &relays[1]), "{listed:?}");
            assert!(connected_as_itself(&tick, &relays[2]), "{listed:?}");
        }
        // Alone, with a key given to none answering at its address, a relay
        // given no key is connected.
        let alone = [relays[1].clone()];
        let only = AtTick {
            set_up: &set_up[1..2],
            relays: &alone,
            ..tick
        };
        assert!(connected_as_itself(&only, &alone[0]));

        // Its turns over five minutes: never dialled, and out of reach at
        // the end; the relays connected in their own right are not dialled
        // either, and are not out of reach.
        let (keyed, keyless, own) = (
            tried_relay(&relays[0]),
            tried_relay(&relays[1]),
            tried_relay(&relays[2]),
        );
        let (reach, clock) = reach_of(&[
            (&keyed, Holds::Holds),
            (&keyless, Holds::Lacks),
            (&own, Holds::Holds),
        ]);
        let mut tries: std::collections::HashMap<TriedRelay, RelayTry> = Default::default();
        let mut dialling = Dialling::default();
        let now = std::time::Instant::now();
        for second in 0..=300 {
            if second > 0 {
                clock.run_ahead(std::time::Duration::from_secs(1));
            }
            let at_second = tick_at(now + std::time::Duration::from_secs(second), true);
            for relay in &relays {
                let dials = relay_turn(
                    &mut tries,
                    &mut dialling,
                    (&tick, relay),
                    at_second,
                    Some(&reach),
                );
                assert!(!dials, "{second} {relay:?}");
            }
            let out = reach.is_out_of_reach(&reach_id(&keyless));
            assert_eq!(out, second >= 300, "{second}");
        }
        assert!(!reach.is_out_of_reach(&reach_id(&own)));
        assert!(dialling.is_empty());

        // Where the keyed relay is not connected, another key answering
        // there, the relay given no key does not make a relay connected:
        // the dial loop paces as a node that is cut off.
        let stranger = |addr| (addr == here).then_some([9; 32]);
        let keyless_only = |relay: &RelayAddr| relay.key.is_none() && relay.addr == here;
        let cut_off = AtTick {
            relays: &relays[..2],
            connected: &keyless_only,
            key_at: &stranger,
            ..tick
        };
        assert!(!any_connected_as_itself(&cut_off));
        assert!(any_connected_as_itself(&tick));
    }

    /// Two names given no key at one address are two relays on the one
    /// connection, whichever key answers there (decision 2026-10-17 §1):
    /// each is connected in its own right, and neither is passed over. A
    /// key given to a relay of the configuration, answering there, makes
    /// both relays at that relay's place.
    #[test]
    fn two_names_given_no_key_at_one_address_are_two_relays_on_one_connection() {
        use cordelia_network::bootstrap::{Relay, RelayAddr};
        let here: std::net::SocketAddr = "127.0.0.1:9474".parse().unwrap();
        let set_up = [
            Relay {
                host: "localhost:9474".into(),
                key: None,
            },
            Relay {
                host: "127.0.0.1:9474".into(),
                key: None,
            },
            Relay {
                host: "keyed.example:9474".into(),
                key: Some([1; 32]),
            },
        ];
        let relays: Vec<RelayAddr> = set_up[..2]
            .iter()
            .map(|relay| RelayAddr {
                host: relay.host.clone(),
                addr: here,
                key: None,
            })
            .collect();
        let connected = |_: &RelayAddr| true;
        let stranger = |_| Some([5; 32]);
        let tick = AtTick {
            set_up: &set_up,
            relays: &relays,
            connected: &connected,
            key_at: &stranger,
        };
        let itself: Vec<bool> = relays
            .iter()
            .map(|r| connected_as_itself(&tick, r))
            .collect();
        assert_eq!(itself, [true, true]);
        let peer = Some(NodeId([5; 32]));
        let one = one_relay_each(
            &set_up,
            &[peer.clone(), peer, None],
            &[Some(here), Some(here), None],
            &|_| Some(here),
        );
        assert_eq!(one, [OneRelay::Itself, OneRelay::Itself, OneRelay::Itself]);
        // The key given to the third answers there.
        let keyed = |_| Some([1; 32]);
        let tick = AtTick {
            key_at: &keyed,
            ..tick
        };
        let itself: Vec<bool> = relays
            .iter()
            .map(|r| connected_as_itself(&tick, r))
            .collect();
        assert_eq!(itself, [false, false]);
        let peer = Some(NodeId([1; 32]));
        let one = one_relay_each(
            &set_up,
            &[peer.clone(), peer.clone(), peer],
            &[Some(here), Some(here), None],
            &|_| Some(here),
        );
        assert_eq!(
            one,
            [
                OneRelay::KeylessAt(2),
                OneRelay::KeylessAt(2),
                OneRelay::Itself
            ]
        );
    }

    /// A default relay named without a key takes the key compiled into the
    /// node (decision 2026-10-17 §1), so it is a relay given a key: another
    /// name given that key is the same relay, and a name given no key at
    /// its address is not. A default relay named with no key is never at
    /// another's address as one given none is.
    #[test]
    fn a_default_relay_named_without_a_key_takes_the_compiled_key() {
        use cordelia_network::bootstrap::{default_relay_key, relays_dialled};
        let default = cordelia_core::protocol::FALLBACK_PEERS[0].to_string();
        let its_key = cordelia_core::protocol::FALLBACK_PEER_KEYS[0].to_string();
        let set_up = relays_dialled(
            "personal",
            &[
                (default.clone(), None),
                ("mine.example:9474".into(), Some(its_key)),
                ("keyless.example:9474".into(), None),
            ],
        )
        .unwrap();
        assert_eq!(set_up[0].key, default_relay_key(&default));
        assert!(set_up[0].key.is_some());
        let shared = std::net::SocketAddr::from(([127, 0, 0, 1], 9474));
        let one = one_relay_each(&set_up, &[None, None, None], &[Some(shared); 3], &|_| None);
        assert_eq!(
            one,
            [
                OneRelay::Itself,
                OneRelay::SameAs(0),
                OneRelay::KeylessAt(0),
            ]
        );
    }

    /// A configured relay at `addr`, with the key `key`.
    fn relay_at(host: &str, addr: &str, key: u8) -> cordelia_network::bootstrap::RelayAddr {
        cordelia_network::bootstrap::RelayAddr {
            host: host.into(),
            addr: addr.parse().unwrap(),
            key: Some([key; 32]),
        }
    }

    /// A tick of the dial loop at `now`, with no other relay connected
    /// unless `any_connected`, and room for a dial.
    fn tick_at(now: std::time::Instant, any_connected: bool) -> Tick {
        Tick {
            now,
            settled: std::time::Duration::from_secs(10),
            secs: 10,
            any_connected,
            busy: false,
        }
    }

    /// A dial ends for the relays it was begun for, whatever the lookups
    /// did to the list of addresses meanwhile (decision 2026-10-19 §1): a
    /// relay whose address moved, or whose name stopped resolving, while
    /// its dial was in flight is a dial that failed, ended once, and it
    /// comes to a class: out of reach, five minutes on.
    #[test]
    fn a_dial_ends_for_the_relays_it_was_begun_for() {
        use cordelia_api::state::{Class, Holds};
        let b = relay_at("b.example:9474", "127.0.0.1:9474", 2);
        let tried = tried_relay(&b);
        for (answered, moved) in [(true, true), (true, false), (false, true), (false, false)] {
            let (reach, clock) = reach_of(&[(&tried, Holds::Lacks)]);
            let mut tries: std::collections::HashMap<TriedRelay, RelayTry> = Default::default();
            let mut dialling = Dialling::default();
            let now = std::time::Instant::now();
            let dials = relay_tick(
                &mut tries,
                &mut dialling,
                (std::slice::from_ref(&b), &b),
                &|_| false,
                tick_at(now, false),
                Some(&reach),
            );
            assert!(dials);
            assert_eq!(dialling[&b.addr], vec![tried.clone()]);
            // A lookup moves its address, or drops its name.
            let now_listed = match moved {
                true => vec![relay_at("b.example:9474", "127.0.0.1:9475", 2)],
                false => Vec::new(),
            };
            match answered {
                true => {
                    let (answers, refused) = dial_answered(
                        &mut tries,
                        &mut dialling,
                        (&[], &now_listed),
                        (b.addr, &[2; 32]),
                        (10, false),
                        Some(&reach),
                    );
                    assert!(answers.is_empty() && refused.is_empty());
                }
                false => dial_errored(
                    &mut tries,
                    &mut dialling,
                    (&[], &now_listed),
                    (b.addr, "timed out".into(), DialEnd::TimedOut),
                    (10, false),
                    Some(&reach),
                ),
            }
            assert!(dialling.is_empty());
            assert_eq!(tries[&tried].failures, 1, "ended once");
            clock.run_ahead(std::time::Duration::from_secs(
                cordelia_core::protocol::OUT_OF_REACH_SECS,
            ));
            reach.failed(&reach_id(&tried));
            let of = reach.of(&reach_id(&tried));
            assert_eq!(of.class, Some(Class::OutLacking), "{answered} {moved}");
        }
    }

    /// A failed dial is credited as a timeout, which ends a wake's wait
    /// for the relay, only where it timed out and the relay is still at
    /// the address dialled (decision 2026-10-24 (removal), section 8; the
    /// review of the removal build into main, its M2 and its lows on the
    /// wake): another key answering is recorded as that, and a relay whose
    /// address moved while it was dialled is credited no timeout.
    #[test]
    fn a_failed_dial_counts_for_the_wake_only_where_it_timed_out_at_the_relays_address() {
        use cordelia_api::state::Holds;
        let b = relay_at("b.example:9474", "127.0.0.1:9474", 2);
        let tried = tried_relay(&b);
        for (ended, moved, counts) in [
            (DialEnd::TimedOut, false, true),
            (DialEnd::TimedOut, true, false),
            (DialEnd::AnotherKey([3; 32]), false, false),
            (DialEnd::Failed, false, false),
        ] {
            let (reach, clock) = reach_of(&[(&tried, Holds::Lacks)]);
            let since = clock.now();
            let mut tries: std::collections::HashMap<TriedRelay, RelayTry> = Default::default();
            let mut dialling = Dialling::default();
            let dials = relay_tick(
                &mut tries,
                &mut dialling,
                (std::slice::from_ref(&b), &b),
                &|_| false,
                tick_at(std::time::Instant::now(), false),
                Some(&reach),
            );
            assert!(dials);
            let now_listed = match moved {
                true => vec![relay_at("b.example:9474", "127.0.0.1:9475", 2)],
                false => vec![b.clone()],
            };
            dial_errored(
                &mut tries,
                &mut dialling,
                (&[], &now_listed),
                (b.addr, "it ended".into(), ended),
                (10, true),
                Some(&reach),
            );
            assert_eq!(
                reach.dial_failed_since(&tried.0, since),
                counts,
                "{ended:?}, moved {moved}"
            );
            let wrong_key = matches!(ended, DialEnd::AnotherKey(_));
            assert_eq!(tries[&tried].wrong_key, wrong_key, "{ended:?}");
            if wrong_key {
                assert_eq!(tries[&tried].error.as_deref(), Some(ANOTHER_KEY_ANSWERED));
            }
        }
    }

    /// Another key that closed a dial judges the relays at the address as
    /// they resolve when the dial ends, by that key (the review of the
    /// removal build into main, its low 1): a relay that came to the
    /// address while the dial was in flight, with the key that answered or
    /// with none, is not shown with the wrong key; the one dialled is.
    #[test]
    fn another_key_that_closed_a_dial_is_judged_against_the_relays_there_now() {
        let b = relay_at("b.example:9474", "127.0.0.1:9474", 2);
        let mut tries: std::collections::HashMap<TriedRelay, RelayTry> = Default::default();
        let mut dialling = Dialling::default();
        assert!(relay_tick(
            &mut tries,
            &mut dialling,
            (std::slice::from_ref(&b), &b),
            &|_| false,
            tick_at(std::time::Instant::now(), false),
            None,
        ));
        // A lookup puts two more relays at the address: one with the key
        // that then answers, one with none.
        let came = relay_at("c.example:9474", "127.0.0.1:9474", 3);
        let no_key = cordelia_network::bootstrap::RelayAddr {
            key: None,
            ..relay_at("d.example:9474", "127.0.0.1:9474", 0)
        };
        let now_listed = vec![b.clone(), came.clone(), no_key.clone()];
        dial_errored(
            &mut tries,
            &mut dialling,
            (&[], &now_listed),
            (b.addr, "another key".into(), DialEnd::AnotherKey([3; 32])),
            (10, false),
            None,
        );
        let of = |relay| &tries[&tried_relay(relay)];
        assert!(of(&b).wrong_key);
        assert_eq!(of(&b).error.as_deref(), Some(ANOTHER_KEY_ANSWERED));
        for relay in [&came, &no_key] {
            assert!(!of(relay).wrong_key, "{}", relay.host);
            assert_ne!(of(relay).error.as_deref(), Some(ANOTHER_KEY_ANSWERED));
        }
    }

    /// The wiring of a dial of a configured relay (the review of the
    /// removal build into main, its M2): a host at the relay's address with
    /// another key, that finishes QUIC and then sends nothing, ends the
    /// dial as another key, at once, and not as a timeout; the relay's own
    /// key that stalls Cordelia's handshake ends it as a timeout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dial_answered_by_another_key_ends_at_once_and_not_as_a_timeout() {
        within(
            "a_dial_answered_by_another_key_ends_at_once_and_not_as_a_timeout",
            60,
            async move {
                use cordelia_network::bootstrap::RelayAddr;
                use cordelia_network::{connection, transport};
                let id = |seed: u8| {
                    std::sync::Arc::new(
                        cordelia_crypto::identity::NodeIdentity::from_seed([seed; 32]).unwrap(),
                    )
                };
                let here: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
                let manager = |key: &std::sync::Arc<cordelia_crypto::identity::NodeIdentity>| {
                    let end = transport::create_endpoint(key, here).unwrap();
                    let port = end.local_addr().unwrap().port();
                    connection::ConnectionManager::new(
                        key.clone(),
                        end,
                        vec![],
                        vec!["relay".into()],
                        port,
                    )
                };
                let (node_key, relay_key, stranger_key) = (id(31), id(32), id(33));
                let node = manager(&node_key);
                for (answers, ended) in [
                    (
                        &stranger_key,
                        DialEnd::AnotherKey(stranger_key.public_key()),
                    ),
                    (&relay_key, DialEnd::TimedOut),
                ] {
                    // It takes QUIC and TLS, and then holds the connection silent.
                    let host = manager(answers);
                    let host_end = host.endpoint();
                    let held = tokio::spawn(async move {
                        let incoming = host_end.accept().await.unwrap();
                        let conn = incoming.await.unwrap();
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                        drop(conn);
                    });
                    let relays = vec![RelayAddr {
                        host: "relay.test:9474".into(),
                        addr: host.local_addr().unwrap(),
                        key: Some(relay_key.public_key()),
                    }];
                    let keys = keys_to_answer(&relays, relays[0].addr);
                    assert_eq!(keys, Some(vec![relay_key.public_key()]));
                    let began = std::time::Instant::now();
                    let dialled =
                        dial_configured(&node.connect_context(), &relays[0], keys.as_deref()).await;
                    let took = began.elapsed();
                    match dialled {
                        Err((addr, _, end)) => {
                            assert_eq!(addr, relays[0].addr);
                            assert_eq!(end, ended);
                        }
                        Ok(outcome) => panic!("the dial connected to {}", outcome.node_id),
                    }
                    if matches!(ended, DialEnd::AnotherKey(_)) {
                        assert!(
                            took < std::time::Duration::from_secs(5),
                            "another key ended the dial only after {took:?}"
                        );
                    }
                    held.abort();
                }
            },
        )
        .await;
    }

    /// The dial loop's tick begins an attempt at a relay where it dials
    /// it (decision 2026-10-19 §1): while that dial is in flight the
    /// relay is not out of reach, though its five minutes are over.
    #[test]
    fn a_dial_that_the_loop_begins_is_in_flight() {
        use cordelia_api::state::Holds;
        let b = relay_at("b.example:9474", "127.0.0.1:9474", 2);
        let tried = tried_relay(&b);
        let (reach, clock) = reach_of(&[(&tried, Holds::Lacks)]);
        reach.failed(&reach_id(&tried));
        clock.run_ahead(std::time::Duration::from_secs(100));
        let (mut tries, mut dialling) = (Default::default(), Dialling::default());
        let now = std::time::Instant::now();
        let relays = std::slice::from_ref(&b);
        let tick = tick_at(now, false);
        assert!(relay_tick(
            &mut tries,
            &mut dialling,
            (relays, &b),
            &|_| false,
            tick,
            Some(&reach)
        ));
        clock.run_ahead(std::time::Duration::from_secs(200));
        assert!(
            !reach.is_out_of_reach(&reach_id(&tried)),
            "its dial is in flight"
        );
    }

    /// A dial that connected waits for a show on its connection, and a
    /// connection gone before one ends it as failed (decision 2026-10-19
    /// §1): the next tick of the loop finds it not connected, and the
    /// relay is out of reach five minutes after its reference.
    #[test]
    fn a_dial_that_connected_ends_when_its_connection_goes_before_a_show() {
        use cordelia_api::state::Holds;
        let b = relay_at("b.example:9474", "127.0.0.1:9474", 2);
        let tried = tried_relay(&b);
        let (reach, clock) = reach_of(&[(&tried, Holds::Lacks)]);
        let (mut tries, mut dialling) = (Default::default(), Dialling::default());
        let relays = std::slice::from_ref(&b);
        let now = std::time::Instant::now();
        clock.run_ahead(std::time::Duration::from_secs(100));
        let tick = tick_at(now, false);
        assert!(relay_tick(
            &mut tries,
            &mut dialling,
            (relays, &b),
            &|_| false,
            tick,
            Some(&reach)
        ));
        let (answers, _) = dial_answered(
            &mut tries,
            &mut dialling,
            (&[], relays),
            (b.addr, &[2; 32]),
            (10, false),
            Some(&reach),
        );
        assert_eq!(answers, vec![b.clone()]);
        // It closes at once: the next tick finds it not connected.
        let tick = tick_at(now + std::time::Duration::from_secs(1), false);
        relay_tick(
            &mut tries,
            &mut dialling,
            (relays, &b),
            &|_| false,
            tick,
            Some(&reach),
        );
        clock.run_ahead(std::time::Duration::from_secs(200));
        assert!(reach.is_out_of_reach(&reach_id(&tried)));
    }

    /// A relay that lacks the change and closed its connection at once is
    /// paced as a node that is cut off, with another relay connected
    /// (decision 2026-10-19, rule 3): its next dial is within 30 s.
    #[test]
    fn a_relay_that_lacks_the_change_and_closed_at_once_is_dialled_within_half_a_minute() {
        use cordelia_api::state::Holds;
        use cordelia_core::protocol::BACKOFF_BASE_SECS;
        let b = relay_at("b.example:9474", "127.0.0.1:9474", 2);
        let tried = tried_relay(&b);
        let (reach, _clock) = reach_of(&[(&tried, Holds::Lacks)]);
        let now = std::time::Instant::now();
        let mut tries: std::collections::HashMap<TriedRelay, RelayTry> = Default::default();
        let earlier = tries.entry(tried.clone()).or_default();
        earlier.failures = 20;
        earlier.connected_at = Some(now);
        let mut dialling = Dialling::default();
        let relays = std::slice::from_ref(&b);
        let tick = tick_at(now, true);
        relay_tick(
            &mut tries,
            &mut dialling,
            (relays, &b),
            &|_| false,
            tick,
            Some(&reach),
        );
        assert_eq!(tries[&tried].failures, 21);
        assert!(wait_after(&tries[&tried]) <= BACKOFF_BASE_SECS);
    }

    /// A relay listed as "same relay" is not one (decision 2026-10-19 §1,
    /// decision 2026-10-17 §1): it is not among the relays a pass is
    /// given, nor among those a mark is written for. A relay whose name
    /// does not resolve is one.
    #[tokio::test]
    async fn a_same_relay_name_is_never_one() {
        use cordelia_network::bootstrap::Relay;
        use cordelia_network::transport;
        let identity = std::sync::Arc::new(
            cordelia_crypto::identity::NodeIdentity::from_seed([1; 32]).unwrap(),
        );
        let end = transport::create_endpoint(&identity, "127.0.0.1:0".parse().unwrap()).unwrap();
        let conn_mgr = cordelia_network::connection::ConnectionManager::new(
            identity,
            end,
            vec![],
            vec![],
            9474,
        );
        let set_up = [
            Relay {
                host: "a.example:9474".into(),
                key: Some([7; 32]),
            },
            Relay {
                host: "a-again.example:9474".into(),
                key: Some([7; 32]),
            },
            Relay {
                host: "b.example:9474".into(),
                key: None,
            },
        ];
        let own = cordelia_api::state::OwnChannels::default();
        let relays = relays_with_links(&set_up, &Default::default(), &conn_mgr, &own);
        let names: Vec<&str> = relays.iter().map(|relay| relay.name.as_str()).collect();
        assert_eq!(names, ["a.example:9474", "b.example:9474"]);
        let ids = own.relays_set_up_as();
        assert_eq!(
            ids,
            relays.iter().map(|relay| relay.id()).collect::<Vec<_>>()
        );
        assert_eq!(ids[0].key, Some([7; 32]));
    }

    /// A relay that keeps failing is dialled less and less often: up to a
    /// quarter of an hour apart while another relay is connected, and at
    /// least every half minute while none is.
    #[test]
    fn a_failing_relay_is_dialled_at_a_slowing_pace() {
        use cordelia_core::protocol::{BACKOFF_BASE_SECS, BACKOFF_MAX_SECS};
        let secs = |failures, another| relay_backoff(failures, 10, another).as_secs();
        assert_eq!(secs(1, true), 10);
        assert_eq!(secs(2, true), 20);
        assert_eq!(secs(3, true), 40);
        assert_eq!(secs(40, true), BACKOFF_MAX_SECS);
        assert_eq!(secs(1, false), 10);
        assert_eq!(secs(40, false), BACKOFF_BASE_SECS);
        // Never zero, whatever the tick.
        assert_eq!(relay_backoff(1, 0, true).as_secs(), 1);
    }

    /// Every relay that a node is configured with is one of the relays a
    /// pass is given, by its name, whether or not the name resolves
    /// (decision 2026-10-04 §4.6). One whose name has not resolved has no
    /// connection, as one that is down has none: it is still waited for
    /// when the device wakes, and named as not heard from. A relay with a
    /// key is found by its key, and one with none by the address that its
    /// name resolves to.
    #[tokio::test]
    async fn a_relay_whose_name_does_not_resolve_is_still_one_the_node_is_set_up_with() {
        use cordelia_network::bootstrap::{Relay, RelayAddr};
        use cordelia_network::{connection, transport};
        let identity = |seed: u8| {
            std::sync::Arc::new(
                cordelia_crypto::identity::NodeIdentity::from_seed([seed; 32]).unwrap(),
            )
        };
        let here: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (device, relay) = (identity(1), identity(2));
        let relay_end = transport::create_endpoint(&relay, here).unwrap();
        let relay_addr = relay_end.local_addr().unwrap();
        let relay_mgr =
            connection::ConnectionManager::new(relay.clone(), relay_end, vec![], vec![], 9474);
        let (accepts, as_relay) = (relay_mgr.endpoint(), relay_mgr.connect_context());
        let accepted = tokio::spawn(async move {
            let incoming = accepts.accept().await.unwrap();
            connection::inbound_accept(&as_relay, incoming)
                .await
                .unwrap()
        });
        let device_end = transport::create_endpoint(&device, here).unwrap();
        let mut conn_mgr =
            connection::ConnectionManager::new(device.clone(), device_end, vec![], vec![], 9474);
        conn_mgr.connect_to(relay_addr).await.unwrap();
        let _accepted = accepted.await.unwrap();

        // Four relays in the configuration. Only the first two have names
        // that resolve: the one that is connected, and one that is down.
        let named = |host: &str, key: Option<[u8; 32]>| Relay {
            host: host.into(),
            key,
        };
        let down: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        let set_up = [
            named("reached.test:9474", None),
            named("down.test:9474", None),
            named("no-such-name.test:9474", None),
            named("no-such-name-with-a-key.test:9474", Some([7; 32])),
        ];
        let resolved = |host: &str, addr| RelayAddr {
            host: host.into(),
            addr,
            key: None,
        };
        let addrs: RelayAddrs = std::sync::Arc::new(std::sync::RwLock::new(vec![
            resolved("reached.test:9474", relay_addr),
            resolved("down.test:9474", down),
        ]));

        let own = cordelia_api::state::OwnChannels::default();
        let relays = relays_with_links(&set_up, &addrs, &conn_mgr, &own);
        let names: Vec<&str> = relays.iter().map(|relay| relay.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "reached.test:9474",
                "down.test:9474",
                "no-such-name.test:9474",
                "no-such-name-with-a-key.test:9474"
            ]
        );
        let linked: Vec<bool> = relays.iter().map(|relay| relay.link.is_some()).collect();
        assert_eq!(linked, [true, false, false, false]);
        let link = relays[0].link.as_ref().unwrap();
        assert_eq!(
            (link.name(), link.relay().0),
            ("reached.test:9474", relay.public_key())
        );

        // With no name resolved at all, every relay is still listed, and
        // none has a connection: a relay with no key is known only by
        // the address its name resolves to.
        let none: RelayAddrs = Default::default();
        let relays = relays_with_links(&set_up, &none, &conn_mgr, &own);
        assert_eq!(relays.len(), set_up.len());
        assert_eq!(own.relays_set_up(), Some(set_up.len()));
        assert!(relays.iter().all(|relay| relay.link.is_none()));

        // A relay with a key is found by its key, whatever its name
        // resolves to, and whether or not it resolves.
        let keyed = [named(
            "no-such-name-with-a-key.test:9474",
            Some(relay.public_key()),
        )];
        let relays = relays_with_links(&keyed, &none, &conn_mgr, &own);
        assert_eq!(relays.len(), 1);
        assert!(relays[0].link.is_some());

        // One relay under two names given its key (decision 2026-10-17
        // §1): a pass is given it once, under the first name, and the
        // device is set up with one relay.
        let twice = [
            named("keyed.test:9474", Some(relay.public_key())),
            named("again.test:9474", Some(relay.public_key())),
        ];
        let relays = relays_with_links(&twice, &addrs, &conn_mgr, &own);
        let names: Vec<&str> = relays.iter().map(|relay| relay.name.as_str()).collect();
        assert_eq!(names, ["keyed.test:9474"]);
        assert!(relays[0].link.is_some());
        assert_eq!(own.relays_set_up(), Some(1));
        let by_key = cordelia_node::device_entries::every_relay_by_key;
        assert_eq!(
            by_key(&relays, own.relays_set_up()),
            Some(vec![relay.public_key()])
        );

        // Two relays at that one address, each given a key of its own,
        // and the relay's answers there (decision 2026-10-17 §1). The one
        // whose key did not answer is given to a pass with no connection,
        // as one out of reach is, and counted: so the device is not set
        // up by key, and forgets nothing of it and says no "sent".
        let wrong_key = [9; 32];
        let two_keys = [
            named("keyed.test:9474", Some(relay.public_key())),
            named("wrong.test:9474", Some(wrong_key)),
        ];
        let at_one_address: RelayAddrs = std::sync::Arc::new(std::sync::RwLock::new(
            two_keys
                .iter()
                .map(|named| RelayAddr {
                    host: named.host.clone(),
                    addr: relay_addr,
                    key: named.key,
                })
                .collect(),
        ));
        let relays = relays_with_links(&two_keys, &at_one_address, &conn_mgr, &own);
        let names: Vec<&str> = relays.iter().map(|relay| relay.name.as_str()).collect();
        assert_eq!(names, ["keyed.test:9474", "wrong.test:9474"]);
        let linked: Vec<bool> = relays.iter().map(|relay| relay.link.is_some()).collect();
        assert_eq!(linked, [true, false]);
        assert_eq!(own.relays_set_up(), Some(2));
        assert_eq!(by_key(&relays, own.relays_set_up()), None);
        conn_mgr.shutdown();
    }

    /// A device connected to one relay of the test's own: the device's
    /// connections, the relay's key and its address. The relay's side is
    /// kept alive by what is returned with it.
    async fn connected_to_a_relay() -> (
        cordelia_network::connection::ConnectionManager,
        [u8; 32],
        std::net::SocketAddr,
        impl Sized,
    ) {
        connected_to_a_relay_saying(vec![]).await
    }

    /// [`connected_to_a_relay`], to a relay that says `roles` in its
    /// handshake.
    async fn connected_to_a_relay_saying(
        roles: Vec<String>,
    ) -> (
        cordelia_network::connection::ConnectionManager,
        [u8; 32],
        std::net::SocketAddr,
        impl Sized,
    ) {
        use cordelia_network::{connection, transport};
        let identity = |seed: u8| {
            std::sync::Arc::new(
                cordelia_crypto::identity::NodeIdentity::from_seed([seed; 32]).unwrap(),
            )
        };
        let here: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (device, relay) = (identity(1), identity(2));
        let relay_end = transport::create_endpoint(&relay, here).unwrap();
        let relay_addr = relay_end.local_addr().unwrap();
        let relay_mgr =
            connection::ConnectionManager::new(relay.clone(), relay_end, vec![], roles, 9474);
        let (accepts, as_relay) = (relay_mgr.endpoint(), relay_mgr.connect_context());
        let accepted = tokio::spawn(async move {
            let incoming = accepts.accept().await.unwrap();
            connection::inbound_accept(&as_relay, incoming)
                .await
                .unwrap()
        });
        let device_end = transport::create_endpoint(&device, here).unwrap();
        let mut conn_mgr =
            connection::ConnectionManager::new(device.clone(), device_end, vec![], vec![], 9474);
        conn_mgr.connect_to(relay_addr).await.unwrap();
        let accepted = accepted.await.unwrap();
        (
            conn_mgr,
            relay.public_key(),
            relay_addr,
            (relay_mgr, accepted),
        )
    }

    /// A relay of this version names the role `heads` in its handshake,
    /// beside "relay", and a device's connection to it keeps that it does
    /// (decision 2026-10-24 (removal), rule 18): it shows such a relay every
    /// head it keeps. A connection to a relay that says "relay" alone, as a
    /// relay of the version before does, keeps that it does not. A node of
    /// another role names none.
    #[tokio::test]
    async fn a_connection_keeps_whether_its_relay_names_the_role_heads() {
        use cordelia_network::bootstrap::{Relay, RelayAddr};
        assert_eq!(handshake_roles("relay"), ["relay", "heads"]);
        assert_eq!(handshake_roles("personal"), ["personal"]);
        assert_eq!(handshake_roles("bootnode"), ["bootnode"]);
        for (roles, heads) in [
            (handshake_roles("relay"), true),
            (vec!["relay".to_string()], false),
        ] {
            let (conn_mgr, key, addr, _relay) = connected_to_a_relay_saying(roles.clone()).await;
            let peer = NodeId(key);
            assert_eq!(
                conn_mgr.get_peer(&peer).unwrap().handshake.peer_roles,
                roles
            );
            let set_up = [Relay {
                host: "reached.test:9474".into(),
                key: None,
            }];
            let addrs: RelayAddrs = std::sync::Arc::new(std::sync::RwLock::new(vec![RelayAddr {
                host: "reached.test:9474".into(),
                addr,
                key: None,
            }]));
            let own = cordelia_api::state::OwnChannels::default();
            let relays = relays_with_links(&set_up, &addrs, &conn_mgr, &own);
            let link = relays[0].link.as_ref().expect("the relay is connected");
            assert_eq!(link.keeps_heads(), heads, "{roles:?}");
        }
    }

    /// A relay given no key is never taken for another relay (decision
    /// 2026-10-17 §1). Its name resolves to the address of a relay given
    /// a key, whose key answers there: it stays a relay of its own among
    /// the relays a pass is given and the device counts, and the
    /// connection there is not its own, so it is given with none. So the
    /// device is not set up by key, forgets nothing of it, and says no
    /// "sent".
    #[tokio::test]
    async fn a_relay_given_no_key_at_another_relays_address_is_a_relay_of_its_own() {
        use cordelia_network::bootstrap::{Relay, RelayAddr};
        let (mut conn_mgr, key, addr, _relay) = connected_to_a_relay().await;
        let set_up = [
            Relay {
                host: "keyed.test:9474".into(),
                key: Some(key),
            },
            Relay {
                host: "keyless.test:9474".into(),
                key: None,
            },
        ];
        let resolved = set_up
            .iter()
            .map(|relay| RelayAddr {
                host: relay.host.clone(),
                addr,
                key: relay.key,
            })
            .collect();
        let addrs: RelayAddrs = std::sync::Arc::new(std::sync::RwLock::new(resolved));
        let own = cordelia_api::state::OwnChannels::default();
        let relays = relays_with_links(&set_up, &addrs, &conn_mgr, &own);
        let names: Vec<&str> = relays.iter().map(|relay| relay.name.as_str()).collect();
        assert_eq!(names, ["keyed.test:9474", "keyless.test:9474"]);
        let linked: Vec<bool> = relays.iter().map(|relay| relay.link.is_some()).collect();
        assert_eq!(linked, [true, false]);
        assert_eq!(own.relays_set_up(), Some(2));
        let by_key = cordelia_node::device_entries::every_relay_by_key;
        assert_eq!(by_key(&relays, own.relays_set_up()), None);
        // The name given no key first: it is still not given the
        // connection that the other's key answers on.
        let first = [set_up[1].clone(), set_up[0].clone()];
        let relays = relays_with_links(&first, &addrs, &conn_mgr, &own);
        let linked: Vec<(&str, bool)> = relays
            .iter()
            .map(|relay| (relay.name.as_str(), relay.link.is_some()))
            .collect();
        assert_eq!(
            linked,
            [("keyless.test:9474", false), ("keyed.test:9474", true)]
        );
        // The keyed name missing from the lookup, or moved, while its
        // connection stays open: its key answers on the connection at the
        // other's address, which is still not that one's.
        let keyless_only = RelayAddr {
            host: "keyless.test:9474".into(),
            addr,
            key: None,
        };
        let moved = RelayAddr {
            host: "keyed.test:9474".into(),
            addr: "127.0.0.1:1".parse().unwrap(),
            key: Some(key),
        };
        for listed in [vec![keyless_only.clone()], vec![moved, keyless_only]] {
            let addrs: RelayAddrs = std::sync::Arc::new(std::sync::RwLock::new(listed));
            let relays = relays_with_links(&set_up, &addrs, &conn_mgr, &own);
            let linked: Vec<bool> = relays.iter().map(|relay| relay.link.is_some()).collect();
            assert_eq!(linked, [true, false]);
            assert_eq!(by_key(&relays, own.relays_set_up()), None);
            let (_, one) = one_relay_each_now(&set_up, &addrs.read().unwrap(), &conn_mgr);
            assert_eq!(one, [OneRelay::Itself, OneRelay::KeylessAt(0)]);
        }
        conn_mgr.shutdown();
    }

    /// Two names given no key at one address are two relays on the one
    /// connection (decision 2026-10-17 §1): each is given to a pass with
    /// that connection, and the device counts two. One connection that
    /// serves two relays never counts as two: the device is not set up by
    /// key, so it forgets nothing and says no "sent".
    #[tokio::test]
    async fn one_connection_that_serves_two_relays_never_counts_as_two() {
        use cordelia_network::bootstrap::{Relay, RelayAddr};
        let (mut conn_mgr, _key, addr, _relay) = connected_to_a_relay().await;
        let set_up = [
            Relay {
                host: "localhost.test:9474".into(),
                key: None,
            },
            Relay {
                host: "loopback.test:9474".into(),
                key: None,
            },
        ];
        let resolved = set_up
            .iter()
            .map(|relay| RelayAddr {
                host: relay.host.clone(),
                addr,
                key: None,
            })
            .collect();
        let addrs: RelayAddrs = std::sync::Arc::new(std::sync::RwLock::new(resolved));
        let own = cordelia_api::state::OwnChannels::default();
        let relays = relays_with_links(&set_up, &addrs, &conn_mgr, &own);
        let linked: Vec<bool> = relays.iter().map(|relay| relay.link.is_some()).collect();
        assert_eq!(linked, [true, true]);
        assert_eq!(own.relays_set_up(), Some(2));
        let by_key = cordelia_node::device_entries::every_relay_by_key;
        assert_eq!(by_key(&relays, own.relays_set_up()), None);
        // One of them alone is one relay, by its key.
        let one = relays_with_links(&set_up[..1], &addrs, &conn_mgr, &own);
        assert!(by_key(&one, own.relays_set_up()).is_some());
        conn_mgr.shutdown();
    }

    /// **Each connection says the configured relay it was made to**
    /// (decision 2026-10-24, rule 2): where each relay stands names the
    /// connection that is its own, the one a pass is given for it. A relay
    /// given no key has its connection by the address its name resolves
    /// to; one that is down has none; a relay that is the same relay as one
    /// before it has none, and the first is the one named; and a relay
    /// given no key at a keyed relay's place has none, for the connection
    /// there is that relay's.
    #[tokio::test]
    async fn each_connection_says_the_configured_relay_it_was_made_to() {
        use cordelia_network::bootstrap::{Relay, RelayAddr};
        let (mut conn_mgr, key, addr, _relay) = connected_to_a_relay().await;
        let named = |host: &str, key: Option<[u8; 32]>| Relay {
            host: host.into(),
            key,
        };
        let at = |relay: &Relay, addr| RelayAddr {
            host: relay.host.clone(),
            addr,
            key: relay.key,
        };
        let tries = std::collections::HashMap::new();
        let made_to =
            |set_up: &[Relay], resolved: &[RelayAddr]| -> Vec<(String, Option<[u8; 32]>)> {
                relays_now(set_up, resolved, &tries, &conn_mgr)
                    .into_iter()
                    .map(|relay| (relay.host, relay.connection))
                    .collect()
            };
        let keyless = named("localhost.test:9474", None);
        let down = named("down.test:9474", None);
        let resolved = [
            at(&keyless, addr),
            at(&down, "127.0.0.1:9".parse().unwrap()),
        ];
        assert_eq!(
            made_to(&[keyless.clone(), down.clone()], &resolved),
            [
                ("localhost.test:9474".to_string(), Some(key)),
                ("down.test:9474".to_string(), None),
            ]
        );
        let keyed = named("keyed.test:9474", Some(key));
        let again = named("again.test:9474", Some(key));
        assert_eq!(
            made_to(&[keyed.clone(), again], &[]),
            [
                ("keyed.test:9474".to_string(), Some(key)),
                ("again.test:9474".to_string(), None),
            ]
        );
        let set_up = [keyed.clone(), keyless.clone()];
        let resolved = [at(&keyed, addr), at(&keyless, addr)];
        assert_eq!(
            made_to(&set_up, &resolved),
            [
                ("keyed.test:9474".to_string(), Some(key)),
                ("localhost.test:9474".to_string(), None),
            ]
        );
        conn_mgr.shutdown();
    }

    /// The dial loop reads the key that answers on the connection at a
    /// relay's address (decision 2026-10-17 §1): with a real connection,
    /// whose key is a keyed relay's, and that relay's name missing from the
    /// lookup or moved, the relay given no key at that address is not
    /// connected in its own right. It makes no relay connected for the
    /// loop's pace (only the keyed relay, by its key, where it is listed),
    /// its turns pass it over, and it is out of reach after five minutes.
    /// With the keyed relay's name resolved there, that relay is connected
    /// by its key.
    #[tokio::test]
    async fn the_dial_loop_reads_the_key_that_answers_at_an_address() {
        use cordelia_api::state::Holds;
        use cordelia_network::bootstrap::{Relay, RelayAddr};
        let (mut conn_mgr, key, addr, _relay) = connected_to_a_relay().await;
        let set_up = [
            Relay {
                host: "keyed.test:9474".into(),
                key: Some(key),
            },
            Relay {
                host: "keyless.test:9474".into(),
                key: None,
            },
        ];
        let keyless = RelayAddr {
            host: "keyless.test:9474".into(),
            addr,
            key: None,
        };
        let keyed_at = |addr| RelayAddr {
            host: "keyed.test:9474".into(),
            addr,
            key: Some(key),
        };
        let moved = keyed_at("127.0.0.1:1".parse().unwrap());
        for listed in [vec![keyless.clone()], vec![moved, keyless.clone()]] {
            let at_keyless = |at: &AtTick| connected_as_itself(at, &keyless);
            assert!(!with_tick(&set_up, &listed, &conn_mgr, at_keyless));
            let addrs: RelayAddrs = std::sync::Arc::new(std::sync::RwLock::new(listed.clone()));
            // Only the keyed relay, listed where it moved, is connected, by
            // its key: the relay given no key never is.
            let keyed_listed = listed.len() == 2;
            assert_eq!(
                any_relay_connected(&set_up, &addrs, &conn_mgr),
                keyed_listed
            );
            let id = tried_relay(&keyless);
            let (reach, clock) = reach_of(&[(&id, Holds::Lacks)]);
            let mut tries: std::collections::HashMap<TriedRelay, RelayTry> = Default::default();
            let mut dialling = Dialling::default();
            let now = std::time::Instant::now();
            for second in 0..=300 {
                if second > 0 {
                    clock.run_ahead(std::time::Duration::from_secs(1));
                }
                let tick = tick_at(now + std::time::Duration::from_secs(second), false);
                let dials = with_tick(&set_up, &listed, &conn_mgr, |at| {
                    relay_turn(
                        &mut tries,
                        &mut dialling,
                        (at, &keyless),
                        tick,
                        Some(&reach),
                    )
                });
                assert!(!dials, "{second}");
            }
            assert!(reach.is_out_of_reach(&reach_id(&id)));
        }
        let both = vec![keyed_at(addr), keyless.clone()];
        let addrs: RelayAddrs = std::sync::Arc::new(std::sync::RwLock::new(both.clone()));
        assert!(any_relay_connected(&set_up, &addrs, &conn_mgr));
        assert!(with_tick(&set_up, &both, &conn_mgr, |at| {
            connected_as_itself(at, &both[0])
        }));
        conn_mgr.shutdown();
    }

    /// A dial answered at a keyed relay's place, by that relay's key
    /// (decision 2026-10-17 §1): the relay given no key there is not
    /// answered, and its dial ends once, failed, with what to do; the
    /// relay given the key is answered. So too where the keyed relay's
    /// name is missing from the lookup, and only its key tells.
    #[test]
    fn a_dial_answered_at_a_keyed_relays_place_ends_the_relay_given_no_key_once() {
        use cordelia_api::state::Holds;
        use cordelia_network::bootstrap::{Relay, RelayAddr};
        let here: std::net::SocketAddr = "127.0.0.1:9474".parse().unwrap();
        let set_up = [
            Relay {
                host: "keyed.example:9474".into(),
                key: Some([1; 32]),
            },
            Relay {
                host: "keyless.example:9474".into(),
                key: None,
            },
        ];
        let resolved: Vec<RelayAddr> = set_up
            .iter()
            .map(|relay| RelayAddr {
                host: relay.host.clone(),
                addr: here,
                key: relay.key,
            })
            .collect();
        let (keyed, keyless) = (tried_relay(&resolved[0]), tried_relay(&resolved[1]));
        for listed in [resolved.clone(), resolved[1..].to_vec()] {
            let (reach, _clock) = reach_of(&[(&keyless, Holds::Lacks)]);
            let mut tries: std::collections::HashMap<TriedRelay, RelayTry> = Default::default();
            let mut dialling = Dialling::default();
            dialling.insert(here, listed.iter().map(tried_relay).collect());
            reach.dial_begins(&reach_id(&keyless));
            let (answers, refused) = dial_answered(
                &mut tries,
                &mut dialling,
                (&set_up, &listed),
                (here, &[1; 32]),
                (10, true),
                Some(&reach),
            );
            let hosts: Vec<&str> = answers.iter().map(|relay| relay.host.as_str()).collect();
            let keyed_listed = listed.len() == 2;
            assert_eq!(
                hosts,
                if keyed_listed {
                    vec!["keyed.example:9474"]
                } else {
                    vec![]
                }
            );
            assert!(refused.is_empty());
            let tried = &tries[&keyless];
            assert_eq!(tried.failures, 1, "{listed:?}");
            assert_eq!(
                tried.error.as_deref(),
                Some(no_key_at("keyed.example:9474").as_str())
            );
            assert_eq!(tries.contains_key(&keyed), keyed_listed);
        }
    }

    /// What the node warns of in its log when the addresses change
    /// (decision 2026-10-17 §1), written by the call that publishes them:
    /// two relays given keys at one address, a relay given no key at a
    /// keyed relay's address, and two names given no key at one address,
    /// each with what to do. Addresses that do not change are not
    /// published again, and warn of nothing.
    #[test]
    fn the_addresses_found_warn_of_relays_at_one_address_with_what_to_do() {
        use cordelia_network::bootstrap::RelayAddr;
        let at = |host: &str, addr: &str, key: Option<[u8; 32]>| RelayAddr {
            host: host.into(),
            addr: addr.parse().unwrap(),
            key,
        };
        let resolved = vec![
            at("one.example:9474", "127.0.0.1:9474", Some([1; 32])),
            at("two.example:9474", "127.0.0.1:9474", Some([2; 32])),
            at("keyed.example:9474", "127.0.0.2:9474", Some([3; 32])),
            at("keyless.example:9474", "127.0.0.2:9474", None),
            at("localhost:9474", "127.0.0.3:9474", None),
            at("127.0.0.3:9474", "127.0.0.3:9474", None),
        ];
        let addrs: RelayAddrs = Default::default();
        let warnings = addresses_found(&addrs, &resolved);
        assert_eq!(
            warnings,
            Some(vec![
                "two.example:9474 and one.example:9474 resolve to one address: only one key can \
                 answer there, and a relay given another key is shown with the wrong key"
                    .to_string(),
                "127.0.0.3:9474 and localhost:9474 are given no key, and resolve to one address: \
                 they are two relays on one connection, never counted as one, so this device \
                 never says that it has sent what it carried. Give the one name only"
                    .to_string(),
                "keyless.example:9474 is given no key, and resolves to the address of \
                 keyed.example:9474: it is never taken for that relay, and is not reached. Give \
                 it that relay's key, or remove it from your configuration"
                    .to_string(),
            ])
        );
        assert_eq!(*addrs.read().unwrap(), resolved);
        assert_eq!(addresses_found(&addrs, &resolved), None);
    }

    /// A relay given no key that was reached on a connection while it was
    /// alone at its address, and is then found at a keyed relay's place,
    /// is reached no more at its first turn, though it is passed over
    /// (decision 2026-10-17 §1, decision 2026-10-19 §1).
    #[tokio::test]
    async fn a_relay_found_at_a_keyed_relays_place_is_reached_no_more_at_once() {
        use cordelia_api::state::Holds;
        use cordelia_network::bootstrap::{Relay, RelayAddr};
        let (mut conn_mgr, key, addr, _relay) = connected_to_a_relay().await;
        let keyless = RelayAddr {
            host: "keyless.test:9474".into(),
            addr,
            key: None,
        };
        let id = tried_relay(&keyless);
        let (reach, _clock) = reach_of(&[(&id, Holds::Holds)]);
        let peer = NodeId(key);
        let conn = conn_mgr.get_connection(&peer).unwrap().clone();
        let link = cordelia_node::device_entries::Link::new(keyless.host.clone(), peer, conn);
        reach.show_begins(&reach_id(&id));
        let said = cordelia_node::device_entries::Said::Holds;
        reach.show_ends(&reach_id(&id), link.id(), said, Holds::Holds);
        assert!(reach.is_reached(&reach_id(&id)));
        // A relay given its key is set up at that address too.
        let set_up = [
            Relay {
                host: "keyed.test:9474".into(),
                key: Some(key),
            },
            Relay {
                host: keyless.host.clone(),
                key: None,
            },
        ];
        let relays = [
            RelayAddr {
                host: "keyed.test:9474".into(),
                addr,
                key: Some(key),
            },
            keyless.clone(),
        ];
        let connected = |relay: &RelayAddr| relay_connected(&conn_mgr, relay);
        let key_at = |at| key_at(&conn_mgr, at);
        let tick = AtTick {
            set_up: &set_up,
            relays: &relays,
            connected: &connected,
            key_at: &key_at,
        };
        let mut tries: std::collections::HashMap<TriedRelay, RelayTry> = Default::default();
        let mut dialling = Dialling::default();
        let now = tick_at(std::time::Instant::now(), true);
        let dials = relay_turn(
            &mut tries,
            &mut dialling,
            (&tick, &keyless),
            now,
            Some(&reach),
        );
        assert!(!dials);
        assert!(!reach.is_reached(&reach_id(&id)));
        conn_mgr.shutdown();
    }

    /// T3. An address's allowance lasts as long as what was counted against
    /// it, whether or not its connections do. Otherwise closing every
    /// connection and connecting again, under new keys, would start it
    /// afresh. An address that has used nothing is forgotten.
    #[test]
    fn an_addresss_allowance_outlasts_its_connections() {
        use cordelia_core::protocol::{MAX_CONNECTIONS_PER_IP, PUSH_BYTES_PER_PEER_PER_MINUTE};
        let peer = |n: u8| NodeId([n; 32]);
        let address: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        let quiet: std::net::IpAddr = "192.0.2.8".parse().unwrap();
        let mut rates = Rates::default();

        // The address's connections push all it is allowed in a minute.
        for n in 1..=MAX_CONNECTIONS_PER_IP as u8 {
            assert_eq!(
                rates.pushed(&peer(n), address, PUSH_BYTES_PER_PEER_PER_MINUTE),
                Ok(()),
                "{n}"
            );
        }
        // Another address connects and pushes nothing.
        assert_eq!(rates.pushed(&peer(50), quiet, 0), Ok(()));

        // Every connection closes, and the allowances are tidied.
        rates.prune(&[], &[]);

        // A new connection from the first address, under a new key, finds
        // the address's allowance used.
        assert!(rates.pushed(&peer(60), address, 1).is_err());
        // The quiet address was forgotten.
        assert!(!rates.by_address.contains_key(&quiet));
    }

    /// What a peer is handed of channels from their secrets counts against
    /// the bytes that may be fetched in a minute: one allowance, for the
    /// connection and for its address, that the answers to its shows count
    /// against too. A page that either has no room for
    /// is not handed, and nothing is counted for it: no breach either,
    /// however often it is asked for. A page leaves room in both for the
    /// answer to a show, and only that answer uses it (decision
    /// 2026-10-04 §16). The entry that answers a show is always counted,
    /// and takes the allowance over. What a peer pushes is counted apart.
    #[test]
    fn what_a_peer_is_handed_counts_against_one_allowance() {
        use cordelia_core::protocol::{
            BAN_THRESHOLD, MAX_CONNECTIONS_PER_IP, PUSH_BYTES_PER_PEER_PER_MINUTE,
        };
        const MINUTE: u64 = PUSH_BYTES_PER_PEER_PER_MINUTE;
        // The room that a page leaves for the answer to a show.
        const SHOW: u64 = cordelia_core::protocol::SHOW_ANSWER_ROOM_BYTES;
        let address: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        let peer = |n: u8| NodeId([n; 32]);
        let mut rates = Rates::default();
        assert_eq!(rates.pull_room(&peer(1), address), MINUTE - SHOW);

        // Handed, and answered, and handed: one count.
        assert!(rates.handed(&peer(1), address, MINUTE / 2));
        assert_eq!(rates.fetch_room(&peer(1), address), MINUTE / 2);
        assert_eq!(rates.pull_room(&peer(1), address), MINUTE / 2 - SHOW);
        rates.answered(&peer(1), address, MINUTE / 4);
        assert_eq!(rates.fetch_room(&peer(1), address), MINUTE / 4);
        // A byte more than there is room for beside the answer to a
        // show: it is not handed, and nothing is counted for it.
        assert!(!rates.handed(&peer(1), address, MINUTE / 4 - SHOW + 1));
        assert_eq!(rates.fetch_room(&peer(1), address), MINUTE / 4);
        // What fits to the byte is handed, and the room for the answer
        // to a show is what is left.
        assert!(rates.handed(&peer(1), address, MINUTE / 4 - SHOW));
        assert_eq!(rates.fetch_room(&peer(1), address), SHOW);
        assert_eq!(rates.pull_room(&peer(1), address), 0);
        // A page that is not handed is no breach, asked for many more
        // times than cut a peer off: the next request of another kind
        // that goes over is the first breach.
        for _ in 0..3 * BAN_THRESHOLD {
            assert!(!rates.handed(&peer(1), address, 1));
        }
        assert_eq!(rates.by_peer[&peer(1)].breach_count, 0);
        assert_eq!(rates.by_address[&address].breach_count, 0);
        // What it pushes is another allowance.
        assert_eq!(rates.pushed(&peer(1), address, MINUTE), Ok(()));
        assert_eq!(
            rates.pushed(&peer(1), address, 1),
            Err(OverLimit { cut_off: false })
        );

        // The entry that answers a show is counted always, and takes the
        // connection over by that entry: nothing is handed it in a page
        // until the minute has let all of it go.
        let mut rates = Rates::default();
        assert!(rates.handed(&peer(1), address, MINUTE - SHOW));
        assert!(!rates.handed(&peer(1), address, 1));
        rates.answered(&peer(1), address, SHOW - 1000);
        assert_eq!(rates.fetch_room(&peer(1), address), 1000);
        rates.answered(&peer(1), address, 5000);
        assert_eq!(rates.fetch_room(&peer(1), address), 0);
        assert_eq!(
            rates.by_peer.get_mut(&peer(1)).unwrap().fetch_bytes.total(),
            MINUTE + 4000
        );
        assert!(!rates.handed(&peer(1), address, 1));
        rates.answered(&peer(1), address, 5000);
        assert_eq!(
            rates.by_peer.get_mut(&peer(1)).unwrap().fetch_bytes.total(),
            MINUTE + 9000
        );
        // It counts for the address too, and is no breach.
        assert_eq!(
            rates
                .by_address
                .get_mut(&address)
                .unwrap()
                .fetch_bytes
                .total(),
            MINUTE + 9000
        );
        assert_eq!(rates.by_peer[&peer(1)].breach_count, 0);

        // The address: its connections are handed in pages, between
        // them, what five may be, less the room for one answer to a show.
        // Five keys at it are each handed all that a key may be in pages;
        // a sixth, which has a connection's allowance of its own, is
        // handed what the address has left for pages, and then nothing.
        let home: std::net::IpAddr = "192.0.2.8".parse().unwrap();
        for n in 10..10 + MAX_CONNECTIONS_PER_IP as u8 {
            assert!(!rates.handed(&peer(n), home, MINUTE - SHOW + 1), "{n}");
            assert!(rates.handed(&peer(n), home, MINUTE - SHOW), "{n}");
        }
        let left = u64::from(MAX_CONNECTIONS_PER_IP as u32 - 1) * SHOW;
        assert_eq!(rates.pull_room(&peer(20), home), left);
        assert!(rates.handed(&peer(20), home, left));
        assert!(!rates.handed(&peer(20), home, 1));
        // The room that is left at that address is the one for the
        // answer to a show, under whichever key.
        assert_eq!(rates.fetch_room(&peer(21), home), SHOW);
        assert_eq!(rates.pull_room(&peer(21), home), 0);

        // A request that hands nothing counts for nothing, also where
        // there is no room, and leaves nothing kept for an address.
        assert!(rates.handed(&peer(1), address, 0));
        assert!(rates.handed(&peer(20), home, 0));
        let quiet: std::net::IpAddr = "192.0.2.9".parse().unwrap();
        assert!(rates.handed(&peer(30), quiet, 0));
        assert!(!rates.by_address.contains_key(&quiet));
        assert!(!rates.by_peer.contains_key(&peer(30)));
    }

    /// T3. A connection has an allowance, and so does its address: the
    /// connections from one address share five times what one may send,
    /// in requests on the streams of entries and in bytes. A peer that
    /// reconnects, or comes back under another key, does not start again
    /// from nothing. Going over three times cuts a peer off.
    #[test]
    fn limits_are_counted_for_a_connection_and_for_its_address() {
        use cordelia_core::protocol::{
            BAN_THRESHOLD, ENTRY_REQUESTS_PER_PEER_PER_MINUTE, MAX_CONNECTIONS_PER_IP,
            PUSH_BYTES_PER_PEER_PER_MINUTE,
        };
        use cordelia_network::messages::Protocol;
        let address: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        let mut rates = Rates::default();
        let peer = |n: u8| NodeId([n; 32]);

        // One connection: its own allowance, then refusals, then cut off.
        for _ in 0..ENTRY_REQUESTS_PER_PEER_PER_MINUTE {
            assert_eq!(
                rates.request(&peer(1), address, Protocol::EntryPush),
                Ok(())
            );
        }
        for breach in 1..=BAN_THRESHOLD {
            let over = rates
                .request(&peer(1), address, Protocol::EntryPush)
                .unwrap_err();
            assert_eq!(over.cut_off, breach == BAN_THRESHOLD, "breach {breach}");
        }

        // The same address under new keys: each has its own allowance, until
        // the address's share is used up.
        let mut allowed = u64::from(ENTRY_REQUESTS_PER_PEER_PER_MINUTE);
        let mut key = 2u8;
        'address: loop {
            for _ in 0..ENTRY_REQUESTS_PER_PEER_PER_MINUTE {
                if rates
                    .request(&peer(key), address, Protocol::EntryPush)
                    .is_err()
                {
                    break 'address;
                }
                allowed += 1;
            }
            key += 1;
            assert!(key < 50, "the address is never refused");
        }
        assert_eq!(
            allowed,
            u64::from(ENTRY_REQUESTS_PER_PEER_PER_MINUTE) * MAX_CONNECTIONS_PER_IP as u64
        );
        // Another address is not affected.
        let elsewhere: std::net::IpAddr = "192.0.2.8".parse().unwrap();
        assert_eq!(
            rates.request(&peer(9), elsewhere, Protocol::EntryPush),
            Ok(())
        );

        // Bytes: a connection may push so many in a minute.
        let mut rates = Rates::default();
        assert_eq!(
            rates.pushed(&peer(1), address, PUSH_BYTES_PER_PEER_PER_MINUTE),
            Ok(())
        );
        assert!(rates.pushed(&peer(1), address, 1).is_err());
        // A peer that has gone is forgotten; its address's count is not.
        rates.prune(&[], &[address]);
        assert!(
            rates
                .pushed(&peer(1), address, PUSH_BYTES_PER_PEER_PER_MINUTE)
                .is_ok(),
            "a new connection has its own allowance"
        );
        assert!(
            rates
                .pushed(&peer(2), address, 4 * PUSH_BYTES_PER_PEER_PER_MINUTE)
                .is_err(),
            "the address's share is five connections' worth"
        );
    }

    /// On the streams of entries, the only peer whose requests are not
    /// counted is a relay that the operator lists by key. One that the
    /// governor calls a relay of this node's by its address, or by its
    /// address and its word, is counted as any peer is. The older kind's
    /// requests are counted as they were: not for a relay of this node's
    /// own.
    #[test]
    fn requests_on_the_streams_of_entries_are_counted_but_for_a_relay_listed_by_key() {
        use cordelia_network::messages::Protocol;
        for of_entries in [
            Protocol::EntryShow,
            Protocol::ChannelProve,
            Protocol::EntryPull,
            Protocol::EntryPush,
            Protocol::RelayEntries,
        ] {
            // Called a relay by the governor, and not listed by key.
            assert!(
                requests_are_counted(of_entries, true, false),
                "{of_entries:?}"
            );
            assert!(requests_are_counted(of_entries, false, false));
            // Listed by key, whatever the governor calls it.
            assert!(!requests_are_counted(of_entries, true, true));
            assert!(!requests_are_counted(of_entries, false, true));
        }
        for older in [
            Protocol::ItemPush,
            Protocol::ItemSync,
            Protocol::PeerSharing,
            Protocol::ChannelAnnounce,
        ] {
            assert!(!requests_are_counted(older, true, false), "{older:?}");
            assert!(!requests_are_counted(older, true, true));
            assert!(requests_are_counted(older, false, false));
            assert!(requests_are_counted(older, false, true));
        }
    }

    /// Requests on the streams of entries of channels from their secrets
    /// are counted, all of them together: a connection may make 3,000 in
    /// a minute, whichever of the five streams each is on. One more is
    /// refused, and is a breach, and as many breaches as cut a peer off
    /// cut it off. The connections of one address share five times that.
    /// The older kind's requests are counted apart, as they were.
    #[test]
    fn requests_on_the_streams_of_entries_are_counted_together() {
        use cordelia_core::protocol::{
            BAN_THRESHOLD, ENTRY_REQUESTS_PER_PEER_PER_MINUTE, MAX_CONNECTIONS_PER_IP,
            WRITES_PER_PEER_PER_MINUTE,
        };
        use cordelia_network::messages::Protocol;
        const OF_ENTRIES: [Protocol; 5] = [
            Protocol::EntryShow,
            Protocol::ChannelProve,
            Protocol::EntryPull,
            Protocol::EntryPush,
            Protocol::RelayEntries,
        ];
        assert_eq!(ENTRY_REQUESTS_PER_PEER_PER_MINUTE, 3_000);
        let address: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        let mut rates = Rates::default();
        let peer = |n: u8| NodeId([n; 32]);

        // One connection: 3,000 requests, on the five streams in turn.
        for n in 0..ENTRY_REQUESTS_PER_PEER_PER_MINUTE as usize {
            assert_eq!(
                rates.request(&peer(1), address, OF_ENTRIES[n % 5]),
                Ok(()),
                "request {n}"
            );
        }
        // One more on any of them is refused, and is a breach: the last
        // of as many as cut a peer off says so.
        for breach in 1..=BAN_THRESHOLD {
            let on = OF_ENTRIES[breach as usize % 5];
            let over = rates.request(&peer(1), address, on).unwrap_err();
            assert_eq!(over.cut_off, breach == BAN_THRESHOLD, "breach {breach}");
        }
        // A request that was refused was not counted: the count is as it
        // was, and so is the address's.
        assert!(rates.is_counting(&peer(1)));

        // The older kind's requests are counted apart: the connection may
        // still push items, as many as it could before.
        for _ in 0..WRITES_PER_PEER_PER_MINUTE {
            assert_eq!(rates.request(&peer(1), address, Protocol::ItemPush), Ok(()));
        }
        assert!(
            rates
                .request(&peer(1), address, Protocol::ItemPush)
                .is_err()
        );
        // And a stream that is counted nowhere is not counted here.
        for _ in 0..10 {
            assert_eq!(
                rates.request(&peer(1), address, Protocol::KeepAlive),
                Ok(())
            );
        }

        // The same address under new keys: each has its own count, until
        // the address's share is used up, which is five connections'.
        let mut rates = Rates::default();
        let mut allowed = 0u64;
        let mut key = 1u8;
        'address: loop {
            for n in 0..ENTRY_REQUESTS_PER_PEER_PER_MINUTE as usize {
                if rates
                    .request(&peer(key), address, OF_ENTRIES[n % 5])
                    .is_err()
                {
                    break 'address;
                }
                allowed += 1;
            }
            key += 1;
            assert!(key < 50, "the address is never refused");
        }
        assert_eq!(
            allowed,
            u64::from(ENTRY_REQUESTS_PER_PEER_PER_MINUTE) * MAX_CONNECTIONS_PER_IP as u64
        );
        // Another address is not affected, and nor are the older kind's
        // requests from this one.
        let elsewhere: std::net::IpAddr = "192.0.2.8".parse().unwrap();
        assert_eq!(
            rates.request(&peer(40), elsewhere, Protocol::EntryPull),
            Ok(())
        );
        assert_eq!(
            rates.request(&peer(41), address, Protocol::ItemSync),
            Ok(())
        );

        // An address whose only count is of these requests is not
        // forgotten while that count stands: its connections cannot close
        // and come back to a new one.
        let mut rates = Rates::default();
        assert_eq!(
            rates.request(&peer(1), address, Protocol::EntryShow),
            Ok(())
        );
        rates.prune(&[], &[]);
        assert!(!rates.is_counting(&peer(1)));
        assert!(
            rates.by_address.contains_key(&address),
            "the address's count was forgotten when its connections closed"
        );
    }

    /// A personal node answers a request for peers with an empty list,
    /// whatever it is connected to; a relay and a bootnode answer with the
    /// relays they know, as before (decision 2026-10-14). The node here is
    /// connected to two relays, and one of them asks it, once for each
    /// role.
    #[tokio::test]
    async fn a_personal_node_answers_a_request_for_peers_with_none() {
        use cordelia_network::messages::{PeerShareRequest, Protocol, WireMessage};
        use cordelia_network::{codec, connection, transport};
        type Shared =
            std::sync::Arc<std::sync::RwLock<Vec<cordelia_network::messages::PeerAddress>>>;
        let identity = |seed: u8| {
            std::sync::Arc::new(
                cordelia_crypto::identity::NodeIdentity::from_seed([seed; 32]).unwrap(),
            )
        };
        let here: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

        // The node, connected to two relays that listen.
        let node = identity(1);
        let node_end = transport::create_endpoint(&node, here).unwrap();
        let mut conn_mgr =
            connection::ConnectionManager::new(node.clone(), node_end, vec![], vec![], 9474);
        let mut relays = Vec::new();
        for seed in [2, 3] {
            let relay = identity(seed);
            let end = transport::create_endpoint(&relay, here).unwrap();
            let addr = end.local_addr().unwrap();
            let roles = vec!["relay".to_string()];
            let mgr =
                connection::ConnectionManager::new(relay.clone(), end, vec![], roles, addr.port());
            let (accepts, as_relay) = (mgr.endpoint(), mgr.connect_context());
            let accepted = tokio::spawn(async move {
                let incoming = accepts.accept().await.unwrap();
                connection::inbound_accept(&as_relay, incoming)
                    .await
                    .unwrap()
            });
            conn_mgr.connect_to(addr).await.unwrap();
            let conn = accepted.await.unwrap().conn;
            relays.push((NodeId(relay.public_key()), conn, mgr));
        }
        let shared: Shared =
            std::sync::Arc::new(std::sync::RwLock::new(conn_mgr.known_peer_addresses()));
        let mut both: Vec<Vec<u8>> = relays.iter().map(|(id, ..)| id.0.to_vec()).collect();
        both.sort();

        // The keys of the peers that the node answers the first relay with,
        // as a node of `role`.
        let (asker_id, asker, _) = &relays[0];
        let node_side = conn_mgr.get_connection(asker_id).unwrap().clone();
        let answered = |role: &'static str| {
            let (asker, node_side, asker_id, shared) = (
                asker.clone(),
                node_side.clone(),
                asker_id.clone(),
                shared.clone(),
            );
            async move {
                let (mut send, mut recv) = asker.open_bi().await.unwrap();
                codec::write_protocol_byte(&mut send, Protocol::PeerSharing)
                    .await
                    .unwrap();
                let ask = WireMessage::PeerShareRequest(PeerShareRequest { max_peers: 20 });
                codec::write_frame(&mut send, &ask).await.unwrap();
                let (mut out, mut into) = node_side.accept_bi().await.unwrap();
                let protocol = codec::read_protocol_byte(&mut into).await.unwrap();
                assert_eq!(protocol, Protocol::PeerSharing);
                handle_inbound_peer_share(&mut out, &mut into, &asker_id, &shared, role).await;
                let _ = out.finish();
                match codec::read_frame(&mut recv, Protocol::PeerSharing).await {
                    Ok(WireMessage::PeerShareResponse(answer)) => {
                        let mut keys: Vec<Vec<u8>> =
                            answer.peers.into_iter().map(|p| p.node_id).collect();
                        keys.sort();
                        keys
                    }
                    other => panic!("a {role} node did not answer with peers: {other:?}"),
                }
            }
        };

        assert!(
            answered("personal").await.is_empty(),
            "a personal node told a relay of the relays it is connected to"
        );
        assert_eq!(
            answered("relay").await,
            both,
            "a relay shares the relays it knows"
        );
        assert_eq!(
            answered("bootnode").await,
            both,
            "a bootnode shares the relays it knows"
        );
    }

    /// Decision 2026-10-22 (memory), rule 12. The keys listed at an
    /// address are those of the relays configured by key at that address
    /// and port; an IPv4 address that a dual-stack socket shows mapped into
    /// IPv6 is the same address. Another port, and a relay configured by
    /// address alone, list nothing.
    #[test]
    fn a_listed_relays_address_is_found_when_shown_mapped_into_ipv6() {
        use cordelia_network::bootstrap::RelayAddr;
        let at = |addr: &str, key: Option<[u8; 32]>| RelayAddr {
            host: "relay.test:9474".into(),
            addr: addr.parse().unwrap(),
            key,
        };
        let relays = [
            at("192.0.2.7:9474", Some([7; 32])),
            at("192.0.2.8:9474", None),
        ];
        let from = |addr: &str| keys_listed_at(&relays, addr.parse().unwrap());
        assert_eq!(from("192.0.2.7:9474"), vec![[7; 32]]);
        assert_eq!(
            from("[::ffff:192.0.2.7]:9474"),
            vec![[7; 32]],
            "a listed relay's address shown mapped into IPv6 was not found"
        );
        assert!(from("192.0.2.7:9475").is_empty());
        assert!(from("[::ffff:192.0.2.8]:9474").is_empty());
    }

    /// What the end at `writer` may send the other end of its connection,
    /// which reads nothing: the bytes one stream takes, and how many
    /// streams it may have open at once, `held` of them before this.
    ///
    /// The end that dialled holds one already: the stream of the
    /// connection's handshake, which the other end does not count as
    /// closed for as long as the connection lasts (quinn frees a stream
    /// that a peer opened once both its halves are done, and the half the
    /// accepting end writes is stopped by the dialler after its handle has
    /// gone, and so never is).
    async fn what_it_may_send(writer: &quinn::Connection, held: usize) -> (usize, usize) {
        // A write or an opening waits for credit; one that waits this long
        // has none.
        let brief = std::time::Duration::from_millis(1500);
        let (mut send, recv) = writer.open_bi().await.unwrap();
        let chunk = vec![0u8; 16 * 1024];
        let mut taken = 0usize;
        while taken < 8 << 20 {
            match tokio::time::timeout(brief, send.write(&chunk)).await {
                Ok(Ok(n)) => taken += n,
                Ok(Err(e)) => panic!("a write failed: {e}"),
                Err(_) => break,
            }
        }
        let mut open = vec![(send, recv)];
        while open.len() < 256 {
            match tokio::time::timeout(brief, writer.open_bi()).await {
                Ok(Ok((mut send, recv))) => {
                    send.write_all(b"x").await.unwrap();
                    open.push((send, recv));
                }
                _ => break,
            }
        }
        (taken, held + open.len())
    }

    /// Decision 2026-10-22 (memory), rule 12. A connection with a relay
    /// configured by key keeps today's windows and streams in both
    /// directions: dialled to it, and accepted from its address with its
    /// key, the relay may send 1 MiB unread on a stream and have 64
    /// streams open. A peer accepted from another address may send
    /// QUIC_STREAM_RECEIVE_WINDOW on a stream and have
    /// QUIC_MAX_BIDI_STREAMS open. One
    /// accepted from the relay's address with another key is closed once
    /// its TLS completes, before its handshake is read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_relay_listed_by_key_keeps_todays_windows_and_streams() {
        within("a_relay_listed_by_key_keeps_todays_windows_and_streams", 60, async move {
        use cordelia_core::protocol::{
            QUIC_LISTED_MAX_BIDI_STREAMS, QUIC_LISTED_STREAM_RECEIVE_WINDOW, QUIC_MAX_BIDI_STREAMS,
            QUIC_STREAM_RECEIVE_WINDOW,
        };
        use cordelia_network::bootstrap::RelayAddr;
        use cordelia_network::{connection, transport};

        let id = |seed: u8| {
            std::sync::Arc::new(
                cordelia_crypto::identity::NodeIdentity::from_seed([seed; 32]).unwrap(),
            )
        };
        let here: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let manager = |key: &std::sync::Arc<cordelia_crypto::identity::NodeIdentity>| {
            let end = transport::create_endpoint(key, here).unwrap();
            let port = end.local_addr().unwrap().port();
            connection::ConnectionManager::new(key.clone(), end, vec![], vec!["relay".into()], port)
        };
        let (node_key, relay_key, other_key, impostor_key) = (id(21), id(22), id(23), id(24));
        let node = manager(&node_key);
        let node_addr = node.local_addr().unwrap();
        let (node_end, node_ctx) = (node.endpoint(), node.connect_context());
        // The relay sends with today's send window, so that only what the
        // node lets it send holds it back.
        let relay = manager(&relay_key);
        let relay_addr = relay.local_addr().unwrap();
        let (relay_end, mut relay_ctx) = (relay.endpoint(), relay.connect_context());
        let listed = transport::listed_configs(&relay_key).unwrap();
        relay_end.set_server_config(Some((*listed.server).clone()));
        relay_ctx
            .endpoint
            .set_default_client_config(listed.client.clone());
        let relays: RelayAddrs = std::sync::Arc::new(std::sync::RwLock::new(vec![RelayAddr {
            host: "relay.test:9474".into(),
            addr: relay_addr,
            key: Some(relay_key.public_key()),
        }]));
        let listed_window = QUIC_LISTED_STREAM_RECEIVE_WINDOW as usize;
        let listed_streams = QUIC_LISTED_MAX_BIDI_STREAMS as usize;

        // Dialled: the node dials the relay as a relay configured by key.
        let at_relay = tokio::spawn({
            let (relay_end, relay_ctx) = (relay_end.clone(), relay_ctx.clone());
            async move {
                let incoming = relay_end.accept().await.unwrap();
                connection::inbound_accept(&relay_ctx, incoming)
                    .await
                    .unwrap()
            }
        });
        let configured = relays.read().unwrap()[0].clone();
        let dialled = dial_relay(&node_ctx, &configured, None).await.unwrap();
        let relays_end = at_relay.await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            what_it_may_send(&relays_end.conn, 0).await,
            (listed_window, listed_streams),
            "a connection dialled to a relay configured by key has another's windows"
        );
        assert!(
            dialled.listed_settings,
            "a dial to a relay configured by key does not say it has the listed settings"
        );
        drop(dialled);

        // Accepted from the relay's address, with its key.
        let at_node = tokio::spawn({
            let (node_end, node_ctx, relays) = (node_end.clone(), node_ctx.clone(), relays.clone());
            async move {
                let incoming = node_end.accept().await.unwrap();
                accept_incoming(&node_ctx, incoming, &relays).await
            }
        });
        let from_relay = connection::outbound_connect(&relay_ctx, node_addr)
            .await
            .unwrap();
        let accepted = at_node.await.unwrap().unwrap();
        assert!(
            accepted.listed_settings,
            "a connection accepted from a listed relay does not say it has the listed settings"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            what_it_may_send(&from_relay.conn, 1).await,
            (listed_window, listed_streams),
            "a connection accepted from a relay listed by key has another's windows"
        );

        // Accepted from another address: every peer's windows.
        let other = manager(&other_key);
        let at_node = tokio::spawn({
            let (node_end, node_ctx, relays) = (node_end.clone(), node_ctx.clone(), relays.clone());
            async move {
                let incoming = node_end.accept().await.unwrap();
                accept_incoming(&node_ctx, incoming, &relays).await
            }
        });
        let from_other = connection::outbound_connect(&other.connect_context(), node_addr).await;
        let accepted = at_node.await.unwrap();
        assert!(
            from_other.is_ok() && accepted.is_ok(),
            "a peer from another address than a listed relay's was not accepted: {:?}",
            accepted.err()
        );
        assert!(
            !accepted.as_ref().unwrap().listed_settings,
            "a peer from another address is said to have the listed settings"
        );
        let from_other = from_other.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            what_it_may_send(&from_other.conn, 1).await,
            (
                QUIC_STREAM_RECEIVE_WINDOW as usize,
                QUIC_MAX_BIDI_STREAMS as usize
            ),
            "a peer from another address has the windows of a relay listed by key"
        );

        // From the relay's address with another key: here the relay is
        // configured at the address the impostor dials from.
        let impostor = manager(&impostor_key);
        let at_impostor: RelayAddrs =
            std::sync::Arc::new(std::sync::RwLock::new(vec![RelayAddr {
                host: "relay.test:9474".into(),
                addr: impostor.local_addr().unwrap(),
                key: Some(relay_key.public_key()),
            }]));
        let at_node = tokio::spawn({
            let (node_end, node_ctx) = (node_end.clone(), node_ctx.clone());
            async move {
                let incoming = node_end.accept().await.unwrap();
                accept_incoming(&node_ctx, incoming, &at_impostor).await
            }
        });
        let dialled_by_impostor =
            connection::outbound_connect(&impostor.connect_context(), node_addr).await;
        let accepted = at_node.await.unwrap();
        assert!(
            matches!(accepted, Err(connection::ConnectionError::NotTheRelay(_))),
            "a connection from a listed relay's address with another key was accepted: {:?}",
            accepted.map(|outcome| outcome.node_id)
        );
        assert!(
            dialled_by_impostor.is_err(),
            "the impostor's handshake was read"
        );
        })
        .await;
    }

    /// Decision 2026-10-22 (memory), rule 12, the check's NAT case: relay B
    /// dials relay A by key from an address that A has not configured. B's
    /// end of their connection carries the listed settings, and A's every
    /// peer's. A receive window bounds what the other end may send, so each
    /// asks for its pages by its own end's settings: A for pages whose
    /// worst case is a small page, B for full ones.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn behind_a_nat_each_relay_asks_for_pages_by_its_own_ends_settings() {
        within(
            "behind_a_nat_each_relay_asks_for_pages_by_its_own_ends_settings",
            60,
            async move {
                use cordelia_network::bootstrap::RelayAddr;
                use cordelia_network::{connection, transport};

                let id = |seed: u8| {
                    std::sync::Arc::new(
                        cordelia_crypto::identity::NodeIdentity::from_seed([seed; 32]).unwrap(),
                    )
                };
                let here: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
                let manager = |key: &std::sync::Arc<cordelia_crypto::identity::NodeIdentity>| {
                    let end = transport::create_endpoint(key, here).unwrap();
                    let port = end.local_addr().unwrap().port();
                    connection::ConnectionManager::new(
                        key.clone(),
                        end,
                        vec![],
                        vec!["relay".into()],
                        port,
                    )
                };
                let listing = |addr: std::net::SocketAddr, key: [u8; 32]| -> RelayAddrs {
                    std::sync::Arc::new(std::sync::RwLock::new(vec![RelayAddr {
                        host: "relay.test:9474".into(),
                        addr,
                        key: Some(key),
                    }]))
                };
                let (a_key, b_key) = (id(31), id(32));
                let (mut a, mut b) = (manager(&a_key), manager(&b_key));
                // A lists B by key at an address that B does not dial from: B is
                // behind a NAT. B lists A by key at A's address.
                let at_a = listing("127.0.0.1:9".parse().unwrap(), b_key.public_key());
                let at_b = listing(a.local_addr().unwrap(), a_key.public_key());

                let accepting = tokio::spawn({
                    let (end, ctx, relays) = (a.endpoint(), a.connect_context(), at_a.clone());
                    async move {
                        let incoming = end.accept().await.unwrap();
                        accept_incoming(&ctx, incoming, &relays).await
                    }
                });
                let configured = at_b.read().unwrap()[0].clone();
                let dialled = dial_relay(&b.connect_context(), &configured, None)
                    .await
                    .unwrap();
                let accepted = accepting.await.unwrap().unwrap();
                b.register(dialled).unwrap();
                a.register(accepted).unwrap();

                let entries_with = |relays: &RelayAddrs| {
                    crate::relay_entries::RelayEntries::new(
                        u64::MAX,
                        relays.clone(),
                        std::time::Duration::from_secs(600),
                    )
                };
                let at_a = crate::relay_entries::listed_links(&entries_with(&at_a), &a);
                let at_b = crate::relay_entries::listed_links(&entries_with(&at_b), &b);
                assert_eq!(
                    at_a.iter()
                        .map(|(relay, _)| relay.clone())
                        .collect::<Vec<_>>(),
                    [NodeId(b_key.public_key())]
                );
                assert!(
                    at_a[0].1.small_windows,
                    "A, on every peer's windows, would ask B for full pages"
                );
                assert_eq!(
                    at_b.iter()
                        .map(|(relay, _)| relay.clone())
                        .collect::<Vec<_>>(),
                    [NodeId(a_key.public_key())]
                );
                assert!(
                    !at_b[0].1.small_windows,
                    "B, which carries the listed settings, would ask A for small pages"
                );
            },
        )
        .await;
    }
}
