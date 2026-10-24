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
    /// The peer kept going over its rate limits, from this address. Its
    /// connection has been closed.
    OverLimit(NodeId, std::net::IpAddr),
}

/// What each connection, and each address, has sent lately (§9.2).
///
/// A connection has its own allowance. All the connections from one address
/// share MAX_CONNECTIONS_PER_IP times that, which is what makes the limits
/// hold against a peer that reconnects or comes back under another key.
pub struct Rates {
    by_peer: std::collections::HashMap<NodeId, cordelia_network::rate_limit::PeerRateLimiter>,
    by_address:
        std::collections::HashMap<std::net::IpAddr, cordelia_network::rate_limit::PeerRateLimiter>,
    /// When each address made a relay hold a channel it did not hold
    /// before, within the last hour.
    new_channels:
        std::collections::HashMap<std::net::IpAddr, std::collections::VecDeque<std::time::Instant>>,
    /// The channels a relay dropped to make room: when, and how many times
    /// running.
    dropped: std::collections::HashMap<String, (std::time::Instant, u32)>,
    /// How long a relay leaves a channel it dropped before it takes it
    /// again, the first time.
    ask_again: std::time::Duration,
    /// The most a relay may hold of the older kind of channel (its
    /// operator's setting), as its items are counted.
    relay_max_bytes: u64,
}

impl Default for Rates {
    fn default() -> Self {
        Self {
            by_peer: Default::default(),
            by_address: Default::default(),
            new_channels: Default::default(),
            dropped: Default::default(),
            ask_again: std::time::Duration::from_secs(
                cordelia_core::protocol::RELAY_ASK_AGAIN_SECS,
            ),
            relay_max_bytes: 0,
        }
    }
}

/// A request that is over a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverLimit {
    /// This is one breach too many: the peer is to be cut off.
    pub cut_off: bool,
}

impl Rates {
    /// For a node that, if it is a relay, may hold `relay_max_bytes` of the
    /// older kind of channel.
    pub fn new(relay_max_bytes: u64) -> Self {
        Self {
            relay_max_bytes,
            ..Self::default()
        }
    }

    /// With `ask_again` as the wait before a relay takes again a channel it
    /// dropped.
    pub fn ask_again(mut self, ask_again: std::time::Duration) -> Self {
        self.ask_again = ask_again;
        self
    }

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

    /// Count `bytes` of entries a relay fetched from `peer`. It is the
    /// relay that asked, so going over is no breach by the peer.
    ///
    /// Against its address, a connection counts for no more than its own
    /// allowance had room for. An answer can hold more than was asked for:
    /// if all of it counted against the address, a few connections could
    /// use up, with their answers, what every device at their address may
    /// be fetched from.
    pub fn fetched(&mut self, peer: &NodeId, address: std::net::IpAddr, bytes: u64) {
        let [of_peer, of_address] = self.both(peer, address);
        let share = bytes.min(of_peer.fetch_bytes.room());
        of_peer.fetch_bytes.record(bytes);
        of_address.fetch_bytes.record(share);
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

    /// Whether `address` may make a relay hold a channel it does not hold:
    /// false if it has had its share for the hour
    /// (NEW_CHANNELS_PER_ADDRESS_PER_HOUR). Counts nothing.
    pub fn may_add_channel(&mut self, address: std::net::IpAddr) -> bool {
        let hour = std::time::Duration::from_secs(3600);
        let Some(made) = self.new_channels.get_mut(&address) else {
            return true;
        };
        while made.front().is_some_and(|at| at.elapsed() >= hour) {
            made.pop_front();
        }
        made.len() < cordelia_core::protocol::NEW_CHANNELS_PER_ADDRESS_PER_HOUR
    }

    /// Count a channel that `address` is making a relay hold for the first
    /// time. False, counting nothing, if the address has had its share for
    /// the hour. A channel costs nothing to make, so without this one
    /// address could make a relay hold any number of them.
    pub fn new_channel(&mut self, address: std::net::IpAddr) -> bool {
        if !self.may_add_channel(address) {
            return false;
        }
        self.new_channels
            .entry(address)
            .or_default()
            .push_back(std::time::Instant::now());
        true
    }

    /// A relay dropped `channel` to make room.
    pub fn dropped(&mut self, channel: &str) {
        let times = self.dropped.get(channel).map_or(0, |(_, times)| *times);
        self.dropped.insert(
            channel.to_string(),
            (std::time::Instant::now(), times.saturating_add(1)),
        );
    }

    /// How long a channel that was dropped `times` times running is left
    /// before it is taken again: `ask_again`, doubled each time, up to
    /// RELAY_DROPPED_WAIT_DOUBLINGS times.
    fn dropped_wait(&self, times: u32) -> std::time::Duration {
        let doublings = times
            .saturating_sub(1)
            .min(cordelia_core::protocol::RELAY_DROPPED_WAIT_DOUBLINGS);
        self.ask_again.saturating_mul(1 << doublings)
    }

    /// Whether a relay dropped `channel` to make room too lately to take it
    /// again. Without the wait, a relay at its cap would fetch the channel
    /// from a peer, drop it, and fetch it again, without end. A channel
    /// that is dropped again each time it is taken does not fit, so the
    /// wait doubles each time.
    pub fn dropped_lately(&mut self, channel: &str) -> bool {
        self.dropped
            .get(channel)
            .is_some_and(|(at, times)| at.elapsed() < self.dropped_wait(*times))
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
        let hour = std::time::Duration::from_secs(3600);
        self.new_channels
            .retain(|_, made| made.back().is_some_and(|at| at.elapsed() < hour));
        // A dropped channel is remembered for twice its longest wait, so
        // that one dropped again soon after it was taken counts as running.
        let longest = self.dropped_wait(u32::MAX).saturating_mul(2);
        self.dropped.retain(|_, (at, _)| at.elapsed() < longest);
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

/// Store a network Item into the local SQLite database.
/// Shared between push receive and pull-sync paths (deduplicated per connection-lifecycle.md).
///
/// `Ok(false)` means the node already holds it. `Err` carries the reason it
/// was refused, as the code a push's answer gives the sender.
///
/// A relay stores whatever is valid. A device (`node_role` "personal",
/// with key `own`) stores only what belongs in its own channels: an entry
/// in a channel it is a member of, written by a member of that channel;
/// and what is sent to its own inbox.
#[cfg(test)]
pub fn store_item(
    db: &rusqlite::Connection,
    item: &cordelia_network::messages::Item,
    node_role: &str,
    own: &[u8; 32],
) -> Result<bool, &'static str> {
    let mut room = RelayRoom::new(u64::MAX, None, None);
    let room = (node_role == "relay").then_some(&mut room);
    store_checked(db, item, &check_item(item)?, node_role, own, room)
}

/// What a relay needs to decide whether it has room for an item (decision
/// 2026-09-30 §4.6). A relay is a cache with a cap, and the cap is set
/// against what its items are counted at
/// ([`cordelia_storage::items::stored_cost`]): this kind's own rows, and
/// nothing of the entries of channels from their secrets, which have a
/// room and a cap of their own (decision 2026-10-04 §2.5, §16). Neither
/// kind is refused or dropped for what the relay holds of the other.
///
/// - At its cap it takes no channel that it does not already hold.
/// - A write that takes it over its cap makes it drop the channels it
///   came to hold most recently, until it is under. If the channel written
///   to is the newest, that is the one dropped, and the write is refused.
///   So what was there first is never pushed out by what came later, and
///   a flood of new channels cannot displace anyone's.
/// - One channel may hold only so much, and one address may make it hold
///   only so many new channels in an hour.
///
/// A relay fetches again what it dropped, or had no room for, once it has
/// room. Each device answers its relay with the channels it holds, and the
/// relay asks every device connected to it, when it connects and every
/// RELAY_ASK_AGAIN_SECS after. A channel it dropped is left for that long
/// before it is taken again, and is then listed again from the start.
pub struct RelayRoom<'a> {
    /// The most the relay may hold of this kind of channel, in bytes as
    /// its items are counted.
    pub max_bytes: u64,
    /// The most one channel may hold, in bytes of entries.
    pub max_channel_bytes: u64,
    /// The relay's counts: the new channels of each address, and the
    /// channels dropped lately.
    pub rates: Option<&'a std::sync::Mutex<Rates>>,
    /// The address the item came from. `None` when it came from a relay
    /// this one lists, which is not limited.
    pub address: Option<std::net::IpAddr>,
    /// What each channel holds, for the channels met while handling one
    /// batch, so that it is added up once a batch and not once an item.
    pub channel_bytes: std::collections::HashMap<String, u64>,
    /// The channels dropped while handling this batch. The caller has them
    /// listed again from the start, from every peer.
    pub dropped: Vec<String>,
}

impl<'a> RelayRoom<'a> {
    pub fn new(
        max_bytes: u64,
        rates: Option<&'a std::sync::Mutex<Rates>>,
        address: Option<std::net::IpAddr>,
    ) -> Self {
        Self {
            max_bytes,
            max_channel_bytes: cordelia_core::protocol::MAX_CHANNEL_BYTES_AT_RELAY,
            rates,
            address,
            channel_bytes: std::collections::HashMap::new(),
            dropped: Vec::new(),
        }
    }

    fn rates(&self) -> Option<std::sync::MutexGuard<'a, Rates>> {
        self.rates
            .map(|rates| rates.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Whether the relay would take `channel_id`, which it does not hold,
    /// as far as room goes. Counts nothing, so a relay can ask before it
    /// fetches what it would then refuse.
    pub fn takes_new_channel(
        &self,
        db: &rusqlite::Connection,
        channel_id: &str,
    ) -> Result<(), &'static str> {
        use cordelia_network::messages::{REFUSED_FULL, REFUSED_STORAGE};
        let used = cordelia_storage::items::stored_cost(db).map_err(|_| REFUSED_STORAGE)?;
        if used >= self.max_bytes {
            tracing::debug!(channel = %channel_id, used, "at the storage cap; not taking a channel this relay does not hold");
            return Err(REFUSED_FULL);
        }
        let Some(mut rates) = self.rates() else {
            return Ok(());
        };
        if rates.dropped_lately(channel_id) {
            tracing::debug!(channel = %channel_id, "dropped to make room a short while ago; not taking it again yet");
            return Err(REFUSED_FULL);
        }
        if let Some(address) = self.address
            && !rates.may_add_channel(address)
        {
            tracing::debug!(channel = %channel_id, %address, "this address has made the relay hold enough new channels for now");
            return Err(REFUSED_FULL);
        }
        Ok(())
    }

    /// Whether the relay takes this item, as far as room goes: if it does,
    /// what the channel will hold once the item is stored. Makes the
    /// channel's row if it is a channel the relay will now hold.
    ///
    /// What the channel holds is not counted here. An item that is then not
    /// stored (a revision no newer than the one held) changes nothing, and
    /// must not make the channel look emptier than it is: see
    /// [`RelayRoom::stored`]. A channel the relay does not hold is counted
    /// against the address here, and its row made, as before: an item that
    /// is then not stored leaves an empty channel.
    fn admit(
        &mut self,
        db: &rusqlite::Connection,
        item: &cordelia_network::messages::Item,
        checked: &Checked,
    ) -> Result<u64, &'static str> {
        use cordelia_network::messages::{REFUSED_FULL, REFUSED_STORAGE};
        use cordelia_storage::{channels, items};
        // What the entry takes, not only its ciphertext: or a channel of
        // small entries could hold any number of them.
        let bytes = cordelia_core::protocol::entry_cost(item.encrypted_blob.len());

        if !channels::exists(db, &item.channel_id).map_err(|_| REFUSED_STORAGE)? {
            // A channel the relay does not hold: only if there is room, it
            // was not dropped a moment ago, and the address has not made
            // the relay hold too many lately.
            self.takes_new_channel(db, &item.channel_id)?;
            if let (Some(address), Some(mut rates)) = (self.address, self.rates())
                && !rates.new_channel(address)
            {
                return Err(REFUSED_FULL);
            }
            // Relay: ensure channel row exists (no FK violation, BV-21)
            let _ = db.execute(
                "INSERT OR IGNORE INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at) VALUES (?1, 'named', 'realtime', 'open', X'00', datetime('now'), datetime('now'))",
                rusqlite::params![item.channel_id],
            );
            self.channel_bytes.insert(item.channel_id.clone(), 0);
        }

        // What the channel would hold with this item, less what the item
        // replaces (the same author's older revision of the same name).
        let held = match self.channel_bytes.get(&item.channel_id) {
            Some(held) => *held,
            None => {
                let held =
                    items::channel_cost(db, &item.channel_id).map_err(|_| REFUSED_STORAGE)?;
                self.channel_bytes.insert(item.channel_id.clone(), held);
                held
            }
        };
        let replaced = match &checked.slot {
            Some(slot) => {
                items::author_slot_cost(db, &item.channel_id, slot, &checked.author).unwrap_or(0)
            }
            None => 0,
        };
        let after = held.saturating_sub(replaced) + bytes;
        // A write that does not make the channel hold more is always
        // taken: a newer revision, by the device that wrote the one it
        // replaces, that is no larger. So in a channel that is over its
        // share (it was counted another way when it was written) a device
        // can still edit and delete what it wrote there, and the channel
        // can shrink.
        if after > self.max_channel_bytes && after > held {
            tracing::debug!(channel = %item.channel_id, held, "this channel holds as much as one channel may");
            return Err(REFUSED_FULL);
        }
        Ok(after)
    }

    /// An item that [`RelayRoom::admit`] took has been stored: its channel
    /// now holds `holds`.
    fn stored(&mut self, channel_id: &str, holds: u64) {
        self.channel_bytes.insert(channel_id.to_string(), holds);
    }

    /// After a write to `written`: if the relay is over its cap, drop the
    /// channels it came to hold most recently until it is not. Returns
    /// false if `written` was itself among them: it was the newest, so the
    /// write did not stay.
    fn make_room(&mut self, db: &rusqlite::Connection, written: &str) -> bool {
        use cordelia_storage::channels;
        let mut kept = true;
        while cordelia_storage::items::stored_cost(db).is_ok_and(|used| used > self.max_bytes) {
            let Ok(Some(newest)) = channels::newest_stored(db) else {
                break;
            };
            match channels::drop_stored(db, &newest) {
                Ok(items) => tracing::warn!(
                    channel = %newest,
                    items,
                    "over the storage cap: dropped the channel this relay came to hold most recently"
                ),
                Err(e) => {
                    tracing::warn!(channel = %newest, error = %e, "could not drop a channel to make room");
                    break;
                }
            }
            self.channel_bytes.remove(&newest);
            if let Some(mut rates) = self.rates() {
                rates.dropped(&newest);
            }
            kept &= newest != written;
            self.dropped.push(newest);
        }
        kept
    }
}

/// The peers a relay asks this cycle which channels they hold, beyond its
/// hot peers: each connected peer whose time has come, which is at once
/// for one that has just connected. When a fetch from a peer ends, it says
/// when the peer is asked next ([`next_ask`]). Peers that have gone are
/// forgotten.
///
/// A relay fetches from its hot peers every cycle. Two relays that list
/// each other are each other's hot peer, so every device is warm at both.
/// Without this, such a relay would never ask a device what it holds, and
/// what both relays lost, or dropped to make room, would not come back to
/// them though their devices hold it (decision 2026-09-30 §4.6).
fn peers_to_ask(
    connected: &[NodeId],
    hot: &[NodeId],
    ask_next: &mut std::collections::HashMap<NodeId, std::time::Instant>,
    now: std::time::Instant,
) -> Vec<NodeId> {
    ask_next.retain(|peer, _| connected.contains(peer));
    connected
        .iter()
        .filter(|peer| !hot.contains(peer))
        .filter(|peer| ask_next.get(*peer).is_none_or(|at| now >= *at))
        .cloned()
        .collect()
}

/// What a node keeps for one channel of a peer it fetches from.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Place {
    /// Its place in the peer's list of the channel: the peer's arrival
    /// sequence of the last entry it has been through (§4.4a).
    after: u64,
    /// The size of page it asks for there: an index into SYNC_PAGE_STEPS.
    /// It moves down when a fetch fails (the page's entries did not fit in
    /// one message) and goes back once the channel is caught up.
    step: usize,
    /// Whether the channel was caught up there. A place that is still
    /// being fetched is kept before one that is caught up.
    done: bool,
}

impl Place {
    /// The start of a channel, with nothing kept for it.
    fn is_start(&self) -> bool {
        self.after == 0 && self.step == 0
    }
}

/// When something was read from [`Kept`]. What is kept later is kept only
/// if nothing it rests on has been forgotten since.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Mark {
    peer: u64,
    relisted: u64,
}

/// What a node keeps for one peer.
#[derive(Default)]
struct KeptForPeer {
    /// The number of the forgetting that last emptied this: 0 if none has.
    since: u64,
    /// Counts each place kept, to tell which was kept longest ago.
    kept: u64,
    places: std::collections::HashMap<String, (Place, u64)>,
}

/// What a node keeps for the peers it fetches from: a [`Place`] for each
/// channel of each peer. In memory, and for one connection: after a
/// restart, or when a peer connects again, each channel is listed again
/// from the start, and only unknown entries fetched.
///
/// It is bounded for each peer, and forgotten when the peer goes. What a
/// peer lists is the peer's to write: without the bound a peer could list
/// new names in every pass, and have a relay keep something for each.
#[derive(Default)]
struct Kept {
    by_peer: std::collections::HashMap<NodeId, KeptForPeer>,
    /// Counts each time a peer's places are forgotten, so that each time
    /// has a number of its own.
    forgettings: u64,
    /// Counts each time channels are forgotten for every peer, to be listed
    /// again from the start.
    relisted: u64,
}

impl Kept {
    /// What is kept for `peer` and `channel` (the start, if nothing is),
    /// and the mark to keep its successor with.
    fn get(&self, peer: &NodeId, channel: &str) -> (Place, Mark) {
        let kept = self.by_peer.get(peer);
        let place = kept
            .and_then(|kept| kept.places.get(channel))
            .map_or_else(Place::default, |(place, _)| *place);
        let mark = Mark {
            peer: kept.map_or(0, |kept| kept.since),
            relisted: self.relisted,
        };
        (place, mark)
    }

    /// Keep `place` for `peer` and `channel`, unless the peer's places, or
    /// any channel's, have been forgotten since `mark` was taken: a fetch
    /// that was under way when that happened does not put its place back.
    /// Returns whether it was kept.
    ///
    /// A peer has at most `most` channels kept. When it has that many, one
    /// is forgotten to make room: a caught-up channel's before one that is
    /// still being fetched, and of those the one kept longest ago. So a
    /// long channel keeps its place from one pass to the next, unless more
    /// than `most` of the peer's channels are being fetched at once. The
    /// start is not kept: it is what a channel with nothing kept has.
    fn keep(
        &mut self,
        peer: &NodeId,
        channel: &str,
        place: Place,
        most: usize,
        mark: Mark,
    ) -> bool {
        let since = self.by_peer.get(peer).map_or(0, |kept| kept.since);
        if since != mark.peer || self.relisted != mark.relisted {
            return false;
        }
        if place.is_start() {
            if let Some(kept) = self.by_peer.get_mut(peer) {
                kept.places.remove(channel);
            }
            return true;
        }
        if most == 0 {
            return false;
        }
        let kept = self.by_peer.entry(peer.clone()).or_default();
        if !kept.places.contains_key(channel) && kept.places.len() >= most {
            let oldest = kept
                .places
                .iter()
                .min_by_key(|(_, (place, when))| (!place.done, *when))
                .map(|(channel, _)| channel.clone());
            if let Some(oldest) = oldest {
                kept.places.remove(&oldest);
            }
        }
        kept.kept += 1;
        kept.places.insert(channel.to_string(), (place, kept.kept));
        true
    }

    /// Bring a fetch under way up to date, before it asks for a page: its
    /// place `at`, and the `mark` it keeps its places with. If nothing has
    /// been forgotten since it last looked, it goes on from `at`. Otherwise
    /// it goes on from what is kept for its channel now: its own last place,
    /// if this channel's was not among what was forgotten; the start, if it
    /// was (the channel is to be listed again from the start, or the peer
    /// has connected again). Either way it takes a fresh mark. So one
    /// channel's being forgotten costs a fetch in another at most the page
    /// it had in flight, whose place could not be kept.
    fn catch_up(&self, peer: &NodeId, channel: &str, at: &mut Place, mark: &mut Mark) {
        let (kept, now) = self.get(peer, channel);
        if now != *mark {
            *at = kept;
            *mark = now;
        }
    }

    /// Forget everything kept for `peer`: it has connected again, and may
    /// have lost or replaced its store since, so that its sequence starts
    /// again.
    fn forget_peer(&mut self, peer: &NodeId) {
        self.forgettings += 1;
        self.by_peer.insert(
            peer.clone(),
            KeptForPeer {
                since: self.forgettings,
                ..KeptForPeer::default()
            },
        );
    }

    /// Forget everything kept for peers that are no longer connected.
    fn forget_gone(&mut self, connected: &[NodeId]) {
        let here: std::collections::HashSet<&NodeId> = connected.iter().collect();
        self.by_peer.retain(|peer, _| here.contains(peer));
    }

    /// Forget what is kept for `channels`, for every peer: they are to be
    /// listed again from the start.
    fn forget_channels(&mut self, channels: &[String]) {
        for kept in self.by_peer.values_mut() {
            kept.places.retain(|channel, _| !channels.contains(channel));
        }
        self.relisted += 1;
    }

    /// How many channels are kept for `peer`.
    #[cfg(test)]
    fn kept_for(&self, peer: &NodeId) -> usize {
        self.by_peer.get(peer).map_or(0, |kept| kept.places.len())
    }

    /// How many are kept in all.
    fn total(&self) -> usize {
        self.by_peer.values().map(|kept| kept.places.len()).sum()
    }
}

/// How a fetch from a peer ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fetched {
    /// Everything the peer lists was gone through.
    All,
    /// The peer's allowance for the minute is used: there is more to
    /// fetch when it has room again.
    AllowanceUsed,
    /// There is more to fetch now: a channel with more pages than one pass
    /// takes, or a page that has to be asked for in smaller parts.
    More,
    /// The peer did not answer, or not as it should.
    Failed,
}

/// When a relay asks a peer again which channels it holds, after a fetch
/// from it that ended as `fetched`. `None` is the next cycle.
///
/// - All of it fetched: after `every`. A device sends what it writes as it
///   writes it, so this is only for what the relay lost, dropped or had no
///   room for.
/// - Its allowance used, or no proper answer: after one rate window, which
///   is when the allowance has room again.
/// - More to fetch now: the next cycle, or a channel of many small entries
///   would come back a few hundred entries every `every`.
fn next_ask(
    fetched: Fetched,
    every: std::time::Duration,
    now: std::time::Instant,
) -> Option<std::time::Instant> {
    let window = std::time::Duration::from_secs(cordelia_core::protocol::RATE_WINDOW_SECS);
    match fetched {
        Fetched::All => Some(now + every),
        Fetched::AllowanceUsed | Fetched::Failed => Some(now + window),
        Fetched::More => None,
    }
}

/// The channels to fetch from a peer: this node's `own`, and those the
/// peer `listed`, each once.
///
/// What a peer lists is the peer's to write, so it is bounded here: only
/// IDs that could be a channel's (of the size an ID may be, and printable),
/// and at most `most` of them. A peer could otherwise have a relay ask
/// about, and keep a place in, any number of channels with names of any
/// length. A peer with more channels than `most` is asked about a
/// different part of them each time, since a set has no order.
///
/// To ask about a channel is to send its ID, so a channel whose ID may not
/// be told to a peer is not asked about, whoever listed it.
fn channels_to_ask(own: Vec<String>, listed: Vec<String>, most: usize) -> Vec<String> {
    let mut channels: std::collections::HashSet<String> = own.into_iter().collect();
    let listed: std::collections::HashSet<String> = listed
        .into_iter()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= cordelia_core::protocol::MAX_CHANNEL_ID_LEN
                && id.bytes().all(|b| b.is_ascii_graphic())
                && cordelia_storage::naming::may_be_told_to_a_peer(id)
        })
        .collect();
    channels.extend(listed.into_iter().take(most));
    channels.into_iter().collect()
}

/// The channels a node fetches from its peers, whatever they list: a
/// relay's are those it holds items for, and a device's those it is a
/// member of. A device's local channels are among them: who is served a
/// local channel is decided where it is served (§8.2.2).
///
/// To fetch a channel is to ask for it by its ID, so a channel whose ID
/// may not be told to a peer is not among them.
///
/// The inbox comes first. A device that removes another publishes again
/// what that device last wrote, and then sends the removal. Fetching the
/// removal before the channels means that whenever it is seen, those
/// entries are fetched in the same pass, before it is applied.
fn channels_to_fetch(db: &rusqlite::Connection, node_role: &str, own: &[u8; 32]) -> Vec<String> {
    use cordelia_storage::naming::{ChannelType, may_be_told_to_a_peer};
    let mut channels: Vec<String> = if node_role == "relay" {
        cordelia_storage::channels::list_stored_channel_ids(db).unwrap_or_default()
    } else {
        cordelia_storage::channels::list_for_entity(db, own)
            .unwrap_or_default()
            .into_iter()
            .map(|c| c.channel_id)
            .collect()
    };
    channels.retain(|id| may_be_told_to_a_peer(id));
    channels.sort_by_key(|id| ChannelType::from_id(id) != ChannelType::Inbox);
    channels
}

/// The channels this node announces to a peer: its network-scope channels
/// (§8.2.2: local channels never leave the PAN) whose IDs may be told to
/// one.
fn channels_to_announce(db: &rusqlite::Connection, own: &[u8; 32]) -> Vec<String> {
    cordelia_storage::channels::list_network_channels(db, own)
        .unwrap_or_default()
        .into_iter()
        .map(|c| c.channel_id)
        .filter(|id| cordelia_storage::naming::may_be_told_to_a_peer(id))
        .collect()
}

/// The channels a node answers with when one of its own relays asks which
/// it holds (§4.5): those it has items for whose IDs may be told to a
/// peer. Local-scope channels are told to a swarm peer and to no other
/// (§8.2.2).
fn channels_it_lists(db: &rusqlite::Connection, to_a_swarm_peer: bool) -> Vec<String> {
    let mut ids = cordelia_storage::channels::list_stored_channel_ids(db).unwrap_or_default();
    ids.retain(|id| {
        cordelia_storage::naming::may_be_told_to_a_peer(id)
            && (to_a_swarm_peer
                || !cordelia_storage::channels::is_local_scope(db, id).unwrap_or(false))
    });
    ids
}

/// Whether a node answers a peer that asks for a channel's items: not for
/// a local-scope channel unless a swarm peer asks (§8.2.2), and not for a
/// channel whose ID may not be told to a peer, since each item it would
/// list carries that ID.
fn answers_for(db: &rusqlite::Connection, channel_id: &str, to_a_swarm_peer: bool) -> bool {
    cordelia_storage::naming::may_be_told_to_a_peer(channel_id)
        && (to_a_swarm_peer
            || !cordelia_storage::channels::is_local_scope(db, channel_id).unwrap_or(false))
}

/// Whether a relay passes an item of `channel_id` on to the relays it
/// lists: not an item of a local-scope channel (§8.2.2: it never leaves
/// the PAN), and not one of a channel whose ID may not be told to a peer,
/// since an item carries its channel's ID. Without the database, which
/// says what a channel's scope is, only the second is known.
fn passed_on(db: Option<&rusqlite::Connection>, channel_id: &str) -> bool {
    cordelia_storage::naming::may_be_told_to_a_peer(channel_id)
        && !db.is_some_and(|db| {
            cordelia_storage::channels::is_local_scope(db, channel_id).unwrap_or(false)
        })
}

/// A fetch running from one peer. While it lives, no other is started
/// from that peer.
struct Fetching {
    peers: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<NodeId>>>,
    peer: NodeId,
}

impl Fetching {
    /// `None` if a fetch from `peer` is already running.
    fn begin(
        peers: &std::sync::Arc<std::sync::Mutex<std::collections::HashSet<NodeId>>>,
        peer: &NodeId,
    ) -> Option<Self> {
        peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(peer.clone())
            .then(|| Self {
                peers: peers.clone(),
                peer: peer.clone(),
            })
    }
}

impl Drop for Fetching {
    fn drop(&mut self) {
        self.peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.peer);
    }
}

/// The most a page can cost: what it is fetched in is one message, and it
/// holds DEFAULT_SYNC_LIMIT entries at most.
const FULL_PAGE_COST: u64 = cordelia_core::protocol::MAX_MESSAGE_BYTES as u64
    + cordelia_core::protocol::entry_cost(0) * cordelia_core::protocol::DEFAULT_SYNC_LIMIT as u64;

// Checked at compile time. A whole page is asked for only while the
// allowance has room for the most it can cost, so that must be within what
// a connection may be fetched from in a minute, or none would ever be.
const _: () = assert!(FULL_PAGE_COST <= cordelia_core::protocol::PUSH_BYTES_PER_PEER_PER_MINUTE);

/// What a fetch from one peer needs, beyond its connection.
struct FetchFrom {
    target: NodeId,
    state: web::Data<cordelia_api::state::AppState>,
    role: String,
    /// The channels to fetch whatever the peer lists: a device's own, and
    /// a relay's when it fetches from a relay it lists.
    channels: Vec<String>,
    /// A relay first asks the peer which channels it holds.
    ask_what_it_holds: bool,
    /// A relay's fetch from a peer that is not a relay it lists: bounded
    /// as what the peer may push is, and held to what was asked for.
    limited: bool,
    address: std::net::IpAddr,
    rates: std::sync::Arc<std::sync::Mutex<Rates>>,
    kept: std::sync::Arc<std::sync::Mutex<Kept>>,
    repush_tx: tokio::sync::mpsc::UnboundedSender<(cordelia_network::messages::Item, NodeId)>,
    seen_table: std::sync::Arc<std::sync::RwLock<cordelia_network::seen_table::SeenTable>>,
    /// The node's large permits, under which an answer longer than a small
    /// message is read (decision 2026-10-22 (memory), rule 6). `None` for
    /// a test that does not exercise them.
    permits: Option<std::sync::Arc<LargePermits>>,
    /// Whether the peer is a relay this node lists by key, whose answers
    /// are read whole whatever their size (rule 7). A relay configured by
    /// address alone is not: it is not `limited`, but its large answers
    /// still wait for a permit, since an address is not an identity.
    listed_by_key: bool,
}

/// One answer read on the relay's own fetch (decision 2026-10-22 (memory),
/// rule 6).
#[expect(
    clippy::large_enum_variant,
    reason = "one answer at a time, taken apart where it is read: a box would cost an allocation an answer"
)]
enum Answer<'p> {
    /// The answer, with the large permit held for a frame longer than a
    /// small message. The caller lets the permit go once it is done with
    /// the answer, before it writes its next request: one for the stream at
    /// a time.
    Message(
        cordelia_network::messages::WireMessage,
        Option<LargePermit<'p>>,
    ),
    /// A frame longer than a small message, and no permit within
    /// STREAM_TIMEOUT: the fetch fails, and the peer is asked again as
    /// after any failed fetch.
    LargeLater,
    /// The request could not be written.
    Unsent,
    /// The answer could not be read, or decoded.
    Failed,
}

/// Write one request of the relay's own fetch, and read its answer by its
/// length (decision 2026-10-22 (memory), rule 6), as rule 2 reads a
/// request: a frame within a small message is read at once; a longer one,
/// from a peer that is not a relay listed by key, only under a large
/// permit, the stream waiting unread meanwhile. The request is encoded and
/// dropped before it is written, and the encoding dropped before the
/// answer is waited for: through each wait the fetch holds the frame being
/// read, a small message, or nothing while it waits for a permit.
async fn ask<'p, W, R>(
    send: &mut W,
    recv: &mut R,
    request: cordelia_network::messages::WireMessage,
    permits: Option<&'p LargePermits>,
    address: std::net::IpAddr,
    listed_by_key: bool,
) -> Answer<'p>
where
    W: tokio::io::AsyncWrite + Unpin + cordelia_network::codec::GiveUp,
    R: tokio::io::AsyncRead + Unpin,
{
    let written = cordelia_network::codec::encode_message(&request);
    drop(request);
    let Ok(written) = written else {
        return Answer::Unsent;
    };
    if cordelia_network::codec::write_raw_frame(send, &written)
        .await
        .is_err()
    {
        return Answer::Unsent;
    }
    drop(written);
    let (frame, permit) = match read_under_permit(recv, permits, address, listed_by_key).await {
        Framed::Frame(frame, permit) => (frame, permit),
        Framed::LargeLater => return Answer::LargeLater,
        Framed::Ended => return Answer::Failed,
    };
    match cordelia_network::codec::decode_message(
        cordelia_network::messages::Protocol::ItemSync,
        &frame,
    ) {
        Ok(answer) => Answer::Message(answer, permit),
        Err(_) => Answer::Failed,
    }
}

/// Fetch from one peer what this node lacks: one stream, every channel in
/// turn (§4.5). Returns how it ended, and how many items were stored.
async fn fetch_from(conn: quinn::Connection, from: FetchFrom) -> (Fetched, u64) {
    let (mut send, mut recv) = match open_bi(&conn).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(peer = %from.target, error = %e, "sync open_bi failed");
            return (Fetched::Failed, 0);
        }
    };
    let fetched = fetch_on(&mut send, &mut recv, from).await;
    // FIN: signal end of batch to server
    let _ = send.finish();
    fetched
}

/// The fetch of [`fetch_from`], on a stream it has opened.
///
/// Each channel is paged by the peer's arrival sequence from this node's
/// place in it (§4.4a), at most `PAGES` pages a pass. The place moves when
/// a page has been gone through, whether or not what it listed could be
/// stored. A page that could not be fetched, or stored as a whole, is asked
/// for again.
///
/// What it holds while it waits on the peer is bounded
/// (parameter-rationale.md §1): the channels it has still to go through,
/// and, while it fetches a page's entries, what it took out of the page
/// (the IDs to fetch, the place the page ends at, and whether it listed
/// anything and has more). The page itself is dropped before the fetch is
/// sent: a peer can make each wait up to STREAM_TIMEOUT_SECS on the length
/// and as long again on the rest, and be asked again at the next cycle.
///
/// Each answer is read by its length (decision 2026-10-22 (memory), rule
/// 6, [`ask`]): within a small message at once, and a longer one, from a
/// peer that is not a relay listed by key, only under a large permit. So
/// through a wait the fetch holds the frame of a small message at most, or
/// nothing while it waits for a permit; a large answer is in G, the
/// permits' budget. Where no permit comes within STREAM_TIMEOUT, the
/// stream is refused with ERR_LARGE_MESSAGE_LATER, as rule 2 refuses a
/// request, and the fetch fails: the peer is asked again as after any
/// failed fetch ([`next_ask`]). It asks as before: up to 100 headers a
/// page, and the entries of a page in one fetch, since a header carries no
/// size to fit a request to.
async fn fetch_on<W, R>(send: &mut W, recv: &mut R, from: FetchFrom) -> (Fetched, u64)
where
    W: tokio::io::AsyncWrite
        + Unpin
        + cordelia_network::codec::GiveUp
        + crate::relay_entries::Refuse,
    R: tokio::io::AsyncRead + Unpin + crate::relay_entries::Refuse,
{
    use cordelia_core::protocol::{MAX_ITEM_BYTES, SYNC_PAGE_STEPS, entry_cost};
    use cordelia_network::item_sync;
    use cordelia_network::messages::{
        FetchRequest, SyncChannelListRequest, SyncRequest, WireMessage,
    };
    const PAGES: usize = 10;

    let FetchFrom {
        target,
        state,
        role,
        channels,
        ask_what_it_holds,
        limited,
        address,
        rates,
        kept,
        repush_tx,
        seen_table,
        permits,
        listed_by_key,
    } = from;
    let permits = permits.as_deref();
    let is_relay_node = role == "relay";
    let lock_rates = || rates.lock().unwrap_or_else(|e| e.into_inner());
    let lock_kept = || kept.lock().unwrap_or_else(|e| e.into_inner());
    // How many channels of this peer are asked about, and a place and a
    // page size kept for. A relay it lists holds as many channels as this
    // node does.
    let most = if limited {
        cordelia_core::protocol::MAX_CHANNELS_ASKED_OF_A_PEER
    } else {
        usize::MAX
    };

    if let Err(e) = cordelia_network::codec::write_protocol_byte(
        &mut *send,
        cordelia_network::messages::Protocol::ItemSync,
    )
    .await
    {
        tracing::debug!(peer = %target, error = %e, "sync protocol byte failed");
        return (Fetched::Failed, 0);
    }

    // Phase 0 (§4.5): a relay asks the peer which channels it holds. An
    // honest peer lists every channel it holds, which can be over a small
    // message: read under a permit, its first `most` are kept (rule 6).
    let channels = if ask_what_it_holds {
        let request = WireMessage::SyncChannelListRequest(SyncChannelListRequest {});
        let (listed, permit) = match ask(send, recv, request, permits, address, listed_by_key).await
        {
            Answer::Message(WireMessage::SyncChannelListResponse(resp), permit) => {
                (resp.channel_ids, permit)
            }
            // A list with no permit fails the whole fetch, whoever the
            // peer: also a relay configured by address alone, which is not
            // `limited` and whose list that could not be read otherwise
            // leaves the fetch to go on with this node's own channels. The
            // stream has been refused, so nothing more can be asked on it;
            // the peer is asked again a rate window later.
            Answer::LargeLater => {
                tracing::debug!(peer = %target, "a channel list over a small message, and no permit for now; the fetch fails");
                refuse_large_later(send, recv);
                return (Fetched::Failed, 0);
            }
            _ => {
                tracing::debug!(peer = %target, "phase0 channel list request failed");
                if limited {
                    return (Fetched::Failed, 0);
                }
                (Vec::new(), None)
            }
        };
        let channels = channels_to_ask(channels, listed, most);
        // The list is let go, and its permit with it, before the first
        // page is asked for.
        drop(permit);
        channels
    } else {
        channels
    };
    if channels.is_empty() {
        return (Fetched::All, 0);
    }
    tracing::debug!(peer = %target, channels = channels.len(), "pull-sync starting");

    let max_bytes = lock_rates().relay_max_bytes;
    let mut fetched = Fetched::All;
    let mut total_stored: u64 = 0;
    // Each channel's ID is let go once it has been gone through.
    'channels: for ch_id in channels {
        let ch_id: &str = &ch_id;
        // A relay does not ask for a channel it does not hold while it has
        // no room for it, so it does not fetch what it would then refuse.
        if is_relay_node {
            let Ok(db) = state.db.lock() else {
                fetched = Fetched::Failed;
                break 'channels;
            };
            let room = RelayRoom::new(max_bytes, Some(&*rates), limited.then_some(address));
            if !cordelia_storage::channels::exists(&db, ch_id).unwrap_or(true)
                && room.takes_new_channel(&db, ch_id).is_err()
            {
                continue 'channels;
            }
        }
        // This node's place in the peer's list of the channel, and the
        // size of page it asks for there. Both move with each page of this
        // pass, whatever is kept of them. If this channel's place is
        // forgotten while it is fetched (the peer connected again, or the
        // channel is to be listed again from the start), the fetch starts
        // it again; another channel's being forgotten costs it at most the
        // page it had in flight.
        let (mut here, mut mark) = lock_kept().get(&target, ch_id);
        let mut caught_up = false;
        for _page in 0..PAGES {
            lock_kept().catch_up(&target, ch_id, &mut here, &mut mark);
            let after = here.after;
            let mut step = here.step.min(SYNC_PAGE_STEPS.len() - 1);
            // How many entries the peer's allowance has room for now: a
            // whole page if it has room for the most a page can cost, and
            // otherwise as many as would fit if each were of the largest
            // size. An entry's size is not known until it is fetched.
            let fit = if limited {
                let room = lock_rates().fetch_room(&target, address);
                if room >= FULL_PAGE_COST {
                    u64::MAX
                } else {
                    room / entry_cost(MAX_ITEM_BYTES)
                }
            } else {
                u64::MAX
            };
            if fit == 0 {
                fetched = Fetched::AllowanceUsed;
                break 'channels;
            }
            let limit = SYNC_PAGE_STEPS[step].min(u32::try_from(fit).unwrap_or(u32::MAX));
            let request = WireMessage::SyncRequest(SyncRequest {
                channel_id: ch_id.to_string(),
                since: None,
                limit,
                after_seq: Some(after),
            });
            let (resp, permit) = match ask(send, recv, request, permits, address, listed_by_key)
                .await
            {
                Answer::Message(WireMessage::SyncResponse(resp), permit) => (resp, permit),
                Answer::LargeLater => {
                    tracing::debug!(peer = %target, channel = %ch_id, "a page over a small message, and no permit for now; the fetch fails");
                    refuse_large_later(send, recv);
                    fetched = Fetched::Failed;
                    break 'channels;
                }
                _ => {
                    tracing::debug!(peer = %target, channel = %ch_id, "sync request failed");
                    fetched = Fetched::Failed;
                    break 'channels;
                }
            };
            // A peer that is held to what was asked for answers with no
            // more than the page asked for, and with that channel's
            // entries only.
            if limited
                && (resp.items.len() > limit as usize
                    || resp.items.iter().any(|h| h.channel_id != *ch_id))
            {
                tracing::debug!(peer = %target, channel = %ch_id, listed = resp.items.len(), asked = limit, "a page that was not the one asked for");
                fetched = Fetched::Failed;
                break 'channels;
            }

            // What follows needs no more of the page than this: the IDs to
            // fetch, the place it ends at, and whether it listed anything
            // and has more. The page is dropped before the fetch is sent.
            let listed_any = !resp.items.is_empty();
            let (last_seq, has_more) = (resp.last_seq, resp.has_more);
            let mut fetch_ids: Vec<String> = Vec::new();
            if listed_any {
                let known = {
                    let Ok(db) = state.db.lock() else {
                        fetched = Fetched::Failed;
                        break 'channels;
                    };
                    let offered: Vec<String> =
                        resp.items.iter().map(|h| h.item_id.clone()).collect();
                    cordelia_storage::items::known_items(&db, &offered).unwrap_or_default()
                };
                fetch_ids = item_sync::compute_fetch_list(&resp.items, &known);
                // An entry that would be refused for the size of a field is
                // not fetched.
                fetch_ids.retain(|id| {
                    resp.items
                        .iter()
                        .find(|h| &h.item_id == id)
                        .is_some_and(|h| {
                            cordelia_core::protocol::entry_fields_fit(
                                &h.item_id,
                                &h.channel_id,
                                &h.item_type,
                                &h.published_at,
                                h.parent_id.as_deref(),
                            )
                        })
                });
                // A device can tell from an entry's header whether it will
                // store it, and does not fetch the rest of one it will not.
                if role == "personal" {
                    let own = state.identity.public_key();
                    if let Ok(db) = state.db.lock() {
                        fetch_ids.retain(|id| {
                            resp.items
                                .iter()
                                .find(|h| &h.item_id == id)
                                .is_some_and(|h| {
                                    <[u8; 32]>::try_from(h.author_id.as_slice()).is_ok_and(
                                        |author| {
                                            wanted_by_a_device(&db, &h.channel_id, &author, &own)
                                        },
                                    )
                                })
                        });
                    }
                }
            }
            // The page's permit, where it was over a small message, goes
            // with it: one for the stream at a time.
            drop(resp);
            drop(permit);
            fetch_ids.shrink_to_fit();

            // The page is not passed if the relay had no room for the
            // channel: it is asked for again.
            let mut not_taken = false;
            if !fetch_ids.is_empty() {
                // The entries of the page in one fetch, however many: a
                // fetch of small entries is one small message, and only a
                // large answer waits for a permit (rule 6).
                let request = WireMessage::FetchRequest(FetchRequest {
                    item_ids: fetch_ids.clone(),
                });
                // The permit, where the answer is over a small message, is
                // held while its entries are stored, and let go at the end
                // of this block, before the next page is asked for.
                let (mut items, _permit) = match ask(
                    send,
                    recv,
                    request,
                    permits,
                    address,
                    listed_by_key,
                )
                .await
                {
                    Answer::Message(WireMessage::FetchResponse(answer), permit) => {
                        (answer.items, permit)
                    }
                    Answer::Unsent => {
                        tracing::debug!(peer = %target, "fetch request failed");
                        fetched = Fetched::Failed;
                        break 'channels; // Stream corrupted
                    }
                    Answer::LargeLater => {
                        tracing::debug!(peer = %target, channel = %ch_id, asked = fetch_ids.len(), "a fetch answer over a small message, and no permit for now; the fetch fails");
                        refuse_large_later(send, recv);
                        fetched = Fetched::Failed;
                        break 'channels;
                    }
                    _ => {
                        // The page's entries could not be fetched in
                        // one message: ask for fewer next time.
                        tracing::debug!(peer = %target, channel = %ch_id, asked = fetch_ids.len(), "fetch response failed; asking for fewer next time");
                        step = (step + 1).min(SYNC_PAGE_STEPS.len() - 1);
                        let place = Place {
                            after,
                            step,
                            done: false,
                        };
                        lock_kept().keep(&target, ch_id, place, most, mark);
                        fetched = Fetched::More;
                        break 'channels;
                    }
                };

                // Every entry the peer sent counts against its
                // allowance, asked for or not.
                if limited {
                    let cost: u64 = items
                        .iter()
                        .map(|i| entry_cost(i.encrypted_blob.len()))
                        .sum();
                    lock_rates().fetched(&target, address, cost);
                }
                // Only what was asked for is looked at: those entries,
                // of this channel, each once.
                {
                    let mut wanted: std::collections::HashSet<&str> =
                        fetch_ids.iter().map(String::as_str).collect();
                    items.retain(|i| i.channel_id == *ch_id && wanted.remove(i.item_id.as_str()));
                }

                let mut stored_count = 0u32;
                let mut newly_stored_items: Vec<cordelia_network::messages::Item> = Vec::new();
                // Checked before the database is held.
                let checked: Vec<Result<Checked, &'static str>> =
                    items.iter().map(check_item).collect();
                {
                    let Ok(db) = state.db.lock() else {
                        fetched = Fetched::Failed;
                        break 'channels;
                    };
                    let own = state.identity.public_key();
                    let mut room =
                        RelayRoom::new(max_bytes, Some(&*rates), limited.then_some(address));
                    let mut no_room = false;
                    // One transaction for the page, as for a push.
                    let Ok(batch) = db.unchecked_transaction() else {
                        fetched = Fetched::Failed;
                        break 'channels;
                    };
                    for (item, checked) in items.iter().zip(checked) {
                        let room = is_relay_node.then_some(&mut room);
                        let outcome = checked.and_then(|checked| {
                            store_checked(&db, item, &checked, &role, &own, room)
                        });
                        match outcome {
                            Ok(true) => {
                                stored_count += 1;
                                if is_relay_node {
                                    newly_stored_items.push(item.clone());
                                }
                            }
                            Err(why) if why == cordelia_network::messages::REFUSED_FULL => {
                                no_room = true
                            }
                            _ => {}
                        }
                    }
                    let holds = cordelia_storage::channels::exists(&db, ch_id).unwrap_or(true);
                    // A page that could not be stored is not passed: it
                    // is asked for again.
                    if let Err(e) = batch.commit() {
                        tracing::warn!(peer = %target, error = %e, "could not store a fetched page");
                        fetched = Fetched::Failed;
                        break 'channels;
                    }
                    if is_relay_node {
                        not_taken = no_room && !holds;
                        // What the relay dropped to make room is listed
                        // again from the start, from every peer.
                        if !room.dropped.is_empty()
                            && let Ok(mut relist) = state.relist.lock()
                        {
                            relist.extend(room.dropped.drain(..));
                        }
                    }
                }
                // Epidemic forwarding: a relay queues what it fetched
                // to be pushed on, with where it came from.
                if is_relay_node && !newly_stored_items.is_empty() {
                    if let Ok(mut st) = seen_table.write() {
                        for item in &newly_stored_items {
                            let hash: [u8; 32] =
                                item.content_hash.as_slice().try_into().unwrap_or([0u8; 32]);
                            st.record_sender(&hash, &target);
                        }
                    }
                    for item in newly_stored_items {
                        let _ = repush_tx.send((item, target.clone()));
                    }
                }
                if stored_count > 0 {
                    // Which channel is said for debugging only.
                    tracing::info!(peer = %target, fetched = fetch_ids.len(), stored = stored_count, "pull-sync page complete");
                    tracing::debug!(peer = %target, channel = %ch_id, stored = stored_count, "pull-sync page stored");
                    total_stored += stored_count as u64;
                }
            }

            if not_taken {
                continue 'channels;
            }
            // A peer without arrival paging answers once, the old way.
            let Some(last_seq) = last_seq else {
                caught_up = true;
                break;
            };
            // The page is passed, whether or not what it listed could be
            // stored, so that what follows is reached; what this node will
            // not store it does not ask for again in this part of the list.
            // A page with nothing in it moves no place, so a name that lists
            // nothing has nothing kept for it.
            let after = if listed_any { last_seq } else { after };
            // A page with nothing in it is the end, whatever it says.
            let end = !has_more || !listed_any;
            if end {
                // Caught up here: back to full pages.
                step = 0;
            }
            here = Place {
                after,
                step,
                done: end,
            };
            lock_kept().keep(&target, ch_id, here, most, mark);
            if end {
                caught_up = true;
                break;
            }
        }
        // More pages than one pass takes: the rest in the next.
        if !caught_up && fetched == Fetched::All {
            fetched = Fetched::More;
        }
    }
    (fetched, total_stored)
}

/// An item that has passed every check that needs no database: its size,
/// its hash, its signature and its shape.
pub struct Checked {
    author: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    slot: Option<[u8; 32]>,
}

/// Check an item before the database is touched: the checks cost a hash
/// and a signature for each item, and a node that did them while holding
/// its database would stop everything else for as long as a peer cared to
/// keep it busy.
pub fn check_item(item: &cordelia_network::messages::Item) -> Result<Checked, &'static str> {
    use cordelia_network::messages::{REFUSED_INVALID, REFUSED_TOO_LARGE};

    // One size for every entry, at every hop: a relay and a device both
    // refuse a larger one, whoever sends it.
    if item.encrypted_blob.len() > cordelia_core::protocol::MAX_ITEM_BYTES {
        tracing::warn!(
            bytes = item.encrypted_blob.len(),
            "item over the size limit"
        );
        return Err(REFUSED_TOO_LARGE);
    }
    // And one size means every field: an entry's ID, channel, type, time
    // and parent each have a size they must fit in, or they could carry
    // what its content may not.
    if !cordelia_core::protocol::entry_fields_fit(
        &item.item_id,
        &item.channel_id,
        &item.item_type,
        &item.published_at,
        item.parent_id.as_deref(),
    ) {
        tracing::warn!("item with a field over its size limit");
        return Err(REFUSED_TOO_LARGE);
    }
    if !cordelia_network::item_sync::verify_content_hash(item) {
        tracing::warn!(item = %item.item_id, "content hash mismatch");
        return Err(REFUSED_INVALID);
    }
    // Relays too: storage keeps the newest revision per (slot, author), which
    // only holds if the author cannot be forged (decision 2026-09-30 §4.3).
    if !cordelia_network::item_sync::verify_item_signature(item) {
        tracing::warn!(item = %item.item_id, "invalid item signature");
        return Err(REFUSED_INVALID);
    }
    let (Ok(author), Ok(hash), Ok(signature)) = (
        <[u8; 32]>::try_from(item.author_id.as_slice()),
        <[u8; 32]>::try_from(item.content_hash.as_slice()),
        <[u8; 64]>::try_from(item.signature.as_slice()),
    ) else {
        return Err(REFUSED_INVALID);
    };
    // Well-formed after verify_item_signature: 32 bytes, set with rev.
    let slot: Option<[u8; 32]> = item
        .slot
        .as_ref()
        .and_then(|s| s.as_slice().try_into().ok());
    Ok(Checked {
        author,
        hash,
        signature,
        slot,
    })
}

/// Store an item that [`check_item`] has passed. A relay passes its
/// [`RelayRoom`]; a device passes none.
///
/// A relay stores nothing of a channel whose ID may not be told to a peer.
/// It would hold, under an ID that holds a name, what it never lists,
/// serves or passes on. Such an item is refused as one that is not valid,
/// before anything is made for its channel.
pub fn store_checked(
    db: &rusqlite::Connection,
    item: &cordelia_network::messages::Item,
    checked: &Checked,
    node_role: &str,
    own: &[u8; 32],
    mut room: Option<&mut RelayRoom>,
) -> Result<bool, &'static str> {
    use cordelia_network::messages::{
        REFUSED_INVALID, REFUSED_NOT_MEMBER, REFUSED_STORAGE, REFUSED_TOO_LARGE,
    };

    if node_role == "relay" && !cordelia_storage::naming::may_be_told_to_a_peer(&item.channel_id) {
        tracing::debug!(item = %item.item_id, channel = %item.channel_id, "an item of a channel whose ID is not told to a peer; a relay does not store it");
        return Err(REFUSED_INVALID);
    }

    let will_hold = match room.as_deref_mut() {
        Some(room) => Some(room.admit(db, item, checked)?),
        None => None,
    };

    if node_role == "personal" && !wanted_by_a_device(db, &item.channel_id, &checked.author, own) {
        tracing::debug!(item = %item.item_id, channel = %item.channel_id, "not written by a member of one of this device's channels; not stored");
        return Err(REFUSED_NOT_MEMBER);
    }

    let new_item = cordelia_storage::items::NewItem {
        item_id: &item.item_id,
        channel_id: &item.channel_id,
        author_id: &checked.author,
        item_type: &item.item_type,
        published_at: &item.published_at,
        parent_id: item.parent_id.as_deref(),
        key_version: item.key_version as i64,
        content_hash: &checked.hash,
        signature: &checked.signature,
        encrypted_blob: &item.encrypted_blob,
        is_tombstone: item.is_tombstone,
        slot: checked.slot.as_ref(),
        rev: item.rev,
    };

    match cordelia_storage::items::insert_item(db, &new_item) {
        Ok(inserted) => {
            if inserted && let (Some(room), Some(will_hold)) = (room, will_hold) {
                // Counted only now that it is stored.
                room.stored(&item.channel_id, will_hold);
                if !room.make_room(db, &item.channel_id) {
                    return Err(cordelia_network::messages::REFUSED_FULL);
                }
            }
            Ok(inserted)
        }
        Err(e) => {
            tracing::debug!(item = %item.item_id, error = %e, "store failed");
            Err(match e {
                cordelia_core::CordeliaError::Validation(_) => REFUSED_INVALID,
                cordelia_core::CordeliaError::TooLarge { .. } => REFUSED_TOO_LARGE,
                _ => REFUSED_STORAGE,
            })
        }
    }
}

/// Whether a device with key `own` stores an item of `channel_id` written
/// by `author` (decision 2026-09-30 §4.6).
///
/// - One of its own channels: both it and the author are members now. A
///   relay stores what anyone sends to a channel, so without this a
///   stranger who knows the channel's ID could fill the device's disk
///   through the relay.
/// - Its own inbox: anything, since an invitation comes from a key that is
///   in no channel with it yet.
/// - Another node's inbox: nothing. A device writes to those, and has no
///   use for what others write there.
/// - The older kinds of channel (named and direct), which have no member
///   list of this kind: as before.
fn wanted_by_a_device(
    db: &rusqlite::Connection,
    channel_id: &str,
    author: &[u8; 32],
    own: &[u8; 32],
) -> bool {
    use cordelia_storage::channels::is_member;
    use cordelia_storage::naming::ChannelType;
    match ChannelType::from_id(channel_id) {
        ChannelType::Group => {
            is_member(db, channel_id, own).unwrap_or(false)
                && is_member(db, channel_id, author).unwrap_or(false)
        }
        ChannelType::Inbox => channel_id == cordelia_storage::naming::inbox_channel_id(own),
        _ => true,
    }
}

/// Outbox items that a relay refused, and relays that refused something
/// without saying what. Both wait before they are tried again, a little
/// longer each time, so that one item no relay will take, or one relay
/// that takes nothing, costs a small push now and then and holds up
/// nothing else.
#[derive(Default)]
struct OutboxRefusals {
    items: std::collections::HashMap<String, RefusedItem>,
    relays: std::collections::HashMap<NodeId, (u32, std::time::Instant)>,
    /// What has been pushed to each relay in the last minute. A device
    /// with a lot to send paces itself to OUTBOX_BYTES_PER_MINUTE, which is
    /// under what a relay allows one connection, so that it is never the
    /// one refused for going over.
    sent: std::collections::HashMap<NodeId, cordelia_network::rate_limit::ByteCounter>,
}

/// How many bytes may go to a relay in the next push, given what went to
/// it in the last minute: nothing if there is not room for one entry of
/// the largest size, else up to a full batch.
fn outbox_room(sent: &mut cordelia_network::rate_limit::ByteCounter) -> Option<usize> {
    use cordelia_core::protocol::{MAX_ITEM_BYTES, OUTBOX_BATCH_MAX_BYTES, entry_cost};
    let room = sent.room();
    (room >= entry_cost(MAX_ITEM_BYTES)).then(|| OUTBOX_BATCH_MAX_BYTES.min(room as usize))
}

struct RefusedItem {
    refusals: u32,
    next_try: std::time::Instant,
    why: String,
}

/// How long to wait after the `refusals`-th refusal in a row: the flush
/// interval doubled each time, up to OUTBOX_REFUSED_RETRY_MAX_SECS.
fn refused_wait(refusals: u32) -> std::time::Duration {
    let secs = cordelia_core::protocol::OUTBOX_FLUSH_INTERVAL_SECS
        .saturating_mul(1u64 << refusals.min(16))
        .min(cordelia_core::protocol::OUTBOX_REFUSED_RETRY_MAX_SECS);
    std::time::Duration::from_secs(secs)
}

/// What a relay's answer to an outbox push means for the items sent.
#[derive(Debug, PartialEq, Eq)]
enum Pushed {
    /// The relay stored `delivered` or already held them, and refused
    /// `refused`.
    Answered {
        delivered: Vec<String>,
        refused: Vec<cordelia_network::messages::Refusal>,
    },
    /// The relay did not account for every item, or refused some without
    /// saying which (a relay from before the list existed). Nothing in the
    /// push can be taken as delivered.
    Unknown,
}

/// Read a relay's answer to a push of `ids`. An item counts as delivered
/// only if the relay stored it or already held it: a refusal is not
/// delivery, whatever the reason.
fn outbox_outcome(ids: &[String], ack: &cordelia_network::messages::PushAck) -> Pushed {
    let rejected = u64::from(ack.policy_rejected) + u64::from(ack.verification_failed);
    let accounted = u64::from(ack.stored) + u64::from(ack.dedup_dropped) + rejected;
    let mut refused: Vec<cordelia_network::messages::Refusal> = Vec::new();
    for r in &ack.refused {
        if ids.contains(&r.item_id) && !refused.iter().any(|seen| seen.item_id == r.item_id) {
            refused.push(r.clone());
        }
    }
    if accounted != ids.len() as u64 || refused.len() as u64 != rejected {
        return Pushed::Unknown;
    }
    let delivered = ids
        .iter()
        .filter(|id| !refused.iter().any(|r| &r.item_id == *id))
        .cloned()
        .collect();
    Pushed::Answered { delivered, refused }
}

/// Tell status which outbox items relays are refusing.
fn publish_refused(state: &cordelia_api::state::AppState, refusals: &OutboxRefusals) {
    let mut refused: Vec<cordelia_api::state::RefusedSnapshot> = refusals
        .items
        .iter()
        .map(|(item_id, item)| cordelia_api::state::RefusedSnapshot {
            item_id: item_id.clone(),
            why: item.why.clone(),
            refusals: item.refusals,
        })
        .collect();
    refused.sort_by(|a, b| a.item_id.cmp(&b.item_id));
    if let Ok(mut shown) = state.outbox_refused.write() {
        *shown = refused;
    }
}

/// Send this node's outbox (own items no relay has stored yet) to one hot
/// relay as a single push, and mark as relayed the items that relay stored
/// or already held (decision 2026-09-30 §4.4a). Relays forward to each
/// other, so one relay storing an item is enough.
///
/// - An item the relay refused stays in the outbox, and is offered again
///   after a wait, to the next relay in turn. A refusal is never taken for
///   delivery: a relay that cannot store (a full disk) must not make this
///   device believe its writes are safe.
/// - A relay that refused something without saying what is left alone for
///   a while, and the others are used.
/// - Anything not answered for is simply sent again on a later flush.
fn flush_outbox(
    state: &web::Data<cordelia_api::state::AppState>,
    governor: &cordelia_network::governor::Governor,
    conn_mgr: &cordelia_network::connection::ConnectionManager,
    in_flight: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    rotation: &mut usize,
    refusals: &std::sync::Arc<std::sync::Mutex<OutboxRefusals>>,
) {
    use std::sync::atomic::Ordering;

    let relays: Vec<NodeId> = governor
        .hot_peers()
        .into_iter()
        .filter(|p| governor.peer_info(p).map(|i| i.is_relay).unwrap_or(false))
        .collect();
    if relays.is_empty() {
        return;
    }
    let now = std::time::Instant::now();
    let (target, skip, room) = {
        let mut held = refusals.lock().unwrap_or_else(|e| e.into_inner());
        // The next relay in turn that is not being left alone.
        let Some(target) = (0..relays.len())
            .map(|i| &relays[(*rotation + i) % relays.len()])
            .find(|relay| {
                held.relays
                    .get(*relay)
                    .is_none_or(|(_, until)| *until <= now)
            })
            .cloned()
        else {
            return;
        };
        let skip: std::collections::HashSet<String> = held
            .items
            .iter()
            .filter(|(_, item)| item.next_try > now)
            .map(|(id, _)| id.clone())
            .collect();
        // Paced: nothing more goes to a relay that has had its share for
        // the minute.
        let sent = held.sent.entry(target.clone()).or_insert_with(|| {
            cordelia_network::rate_limit::ByteCounter::new(
                std::time::Duration::from_secs(cordelia_core::protocol::RATE_WINDOW_SECS),
                cordelia_core::protocol::OUTBOX_BYTES_PER_MINUTE,
            )
        });
        let Some(room) = outbox_room(sent) else {
            return;
        };
        (target, skip, room)
    };
    let Some(conn) = conn_mgr.get_connection(&target).cloned() else {
        return;
    };
    if in_flight.swap(true, Ordering::AcqRel) {
        return; // previous flush still running
    }

    let batch = {
        let Ok(db) = state.db.lock() else {
            in_flight.store(false, Ordering::Release);
            return;
        };
        let pk = state.identity.public_key();
        // Forget refusals of items that are no longer waiting: replaced by
        // a newer revision, or removed.
        let mut held = refusals.lock().unwrap_or_else(|e| e.into_inner());
        if !held.items.is_empty() {
            let ids: Vec<String> = held.items.keys().cloned().collect();
            let waiting =
                cordelia_storage::items::still_in_outbox(&db, &pk, &ids).unwrap_or_default();
            held.items.retain(|id, _| waiting.contains(id));
            publish_refused(state, &held);
        }
        drop(held);
        cordelia_storage::items::outbox(
            &db,
            &pk,
            cordelia_core::protocol::OUTBOX_BATCH_MAX_ITEMS,
            room,
            &skip,
        )
        .unwrap_or_default()
    };
    if batch.is_empty() {
        in_flight.store(false, Ordering::Release);
        return;
    }
    *rotation = rotation.wrapping_add(1);
    {
        let bytes: u64 = batch
            .iter()
            .map(|i| cordelia_core::protocol::entry_cost(i.encrypted_blob.len()))
            .sum();
        let mut held = refusals.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(sent) = held.sent.get_mut(&target) {
            // Recorded even if it is over (an entry from before the size
            // limit): the relay counts it too.
            if !sent.check_and_record(bytes) {
                let rest = sent.room();
                sent.check_and_record(rest);
            }
        }
    }

    let ids: Vec<String> = batch.iter().map(|i| i.item_id.clone()).collect();
    let items: Vec<cordelia_network::messages::Item> = batch
        .into_iter()
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
            slot: si.slot,
            rev: si.rev,
        })
        .collect();

    let state = state.clone();
    let in_flight = in_flight.clone();
    let refusals = refusals.clone();
    tokio::spawn(async move {
        let result = async {
            let (mut send, mut recv) = open_bi(&conn).await?;
            let mut stream = tokio::io::join(&mut recv, &mut send);
            cordelia_network::item_sync::send_push(&mut stream, &items)
                .await
                .map_err(|e| e.to_string())
        }
        .await;
        match result {
            Ok(ack) => match outbox_outcome(&ids, &ack) {
                Pushed::Answered { delivered, refused } => {
                    if let Ok(db) = state.db.lock() {
                        let _ = cordelia_storage::items::mark_relayed(&db, &delivered);
                    }
                    let mut held = refusals.lock().unwrap_or_else(|e| e.into_inner());
                    held.relays.remove(&target);
                    for id in &delivered {
                        held.items.remove(id);
                    }
                    for refusal in refused {
                        let item =
                            held.items
                                .entry(refusal.item_id.clone())
                                .or_insert(RefusedItem {
                                    refusals: 0,
                                    next_try: std::time::Instant::now(),
                                    why: String::new(),
                                });
                        item.refusals += 1;
                        item.next_try = std::time::Instant::now() + refused_wait(item.refusals);
                        item.why = refusal.why;
                        tracing::warn!(
                            relay = %target,
                            item = %refusal.item_id,
                            why = %item.why,
                            refusals = item.refusals,
                            "a relay refused an item; it stays in the outbox and is offered again"
                        );
                    }
                    publish_refused(&state, &held);
                    tracing::debug!(relay = %target, items = ids.len(), delivered = delivered.len(), stored = ack.stored, "outbox answered");
                }
                Pushed::Unknown => {
                    let mut held = refusals.lock().unwrap_or_else(|e| e.into_inner());
                    let refusals_in_a_row = held.relays.get(&target).map_or(0, |(n, _)| *n) + 1;
                    held.relays.insert(
                        target.clone(),
                        (
                            refusals_in_a_row,
                            std::time::Instant::now() + refused_wait(refusals_in_a_row),
                        ),
                    );
                    tracing::warn!(
                        relay = %target,
                        items = ids.len(),
                        stored = ack.stored,
                        held = ack.dedup_dropped,
                        refused = u64::from(ack.policy_rejected) + u64::from(ack.verification_failed),
                        "a relay did not say which items it stored; nothing is taken as delivered, and it is left alone for a while"
                    );
                }
            },
            Err(e) => {
                tracing::debug!(relay = %target, items = ids.len(), error = %e, "outbox push failed; will resend")
            }
        }
        in_flight.store(false, Ordering::Release);
    });
}

/// Whether a node of this role carries channels of the older kind
/// (decision 2026-10-04 §10): a relay does, for the one version that
/// carries both kinds, and so does a bootnode or a keeper. **A personal
/// node carries none.** Its channels are those of its own, from a secret
/// (`device_entries`): it pushes no item of the older kind, fetches no
/// channel of it, announces none, serves none, and takes none from a
/// peer.
fn carries_older_kind(node_role: &str) -> bool {
    node_role != "personal"
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
    repush_tx: &tokio::sync::mpsc::UnboundedSender<(cordelia_network::messages::Item, NodeId)>,
    delivery_tx: &tokio::sync::mpsc::UnboundedSender<(NodeId, u64)>,
    peer_rates: &std::sync::Arc<std::sync::Mutex<Rates>>,
    peer_states: &std::sync::Arc<std::sync::RwLock<std::collections::HashMap<NodeId, u8>>>,
    peer_relays: &std::sync::Arc<std::sync::RwLock<std::collections::HashSet<NodeId>>>,
    gov_tx: &tokio::sync::mpsc::UnboundedSender<GovEvent>,
    swarm_members: &std::sync::Arc<std::sync::RwLock<std::collections::HashSet<NodeId>>>,
    seen_table: &std::sync::Arc<std::sync::RwLock<cordelia_network::seen_table::SeenTable>>,
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

    // Step 3b: Mark swarm member (HKDF-verified, always Hot, exempt from hot_max)
    let is_swarm = swarm_members
        .read()
        .ok()
        .map(|m| m.contains(node_id))
        .unwrap_or(false);
    if is_swarm {
        governor.set_peer_swarm(node_id);
    }

    // Step 4: Mark connected (triggers Hot/Warm promotion -- bootnodes stay Warm, swarm always Hot)
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
    // (relays are receive-only for channel-announce per §4.4). A personal
    // node has no channel of the older kind to announce ([`carries_older_kind`]).
    let peer_is_hot = governor
        .peer_info(node_id)
        .map(|p| p.state == cordelia_network::governor::PeerState::Hot)
        .unwrap_or(false);
    if peer_is_hot
        && node_role != "relay"
        && carries_older_kind(node_role)
        && let Some(conn) = conn_mgr.get_connection(node_id)
    {
        let conn = conn.clone();
        let announce_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = send_channel_announcements(&conn, &announce_state).await {
                tracing::debug!(error = %e, "channel announcements failed on connect");
            }
        });
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
        let rtx = repush_tx.clone();
        let dtx = delivery_tx.clone();
        let rates = peer_rates.clone();
        let states = peer_states.clone();
        let relays = peer_relays.clone();
        let gtx = gov_tx.clone();
        let sm = swarm_members.clone();
        let st = seen_table.clone();
        let entries = relay_entries.clone();
        let permits = large_permits.clone();
        // Whether a listed relay's connection carries the listed settings
        // at this end, by which it is given full pages (rule 12).
        let listed_settings = conn_mgr.carries_listed_settings(node_id);
        tokio::spawn(async move {
            handle_peer_streams(
                conn,
                peer_id,
                made_from,
                db_state,
                peers_ref,
                role,
                rtx,
                dtx,
                rates,
                states,
                relays,
                gtx,
                sm,
                st,
                entries,
                permits,
                listed_settings,
            )
            .await;
        });
    }
}

/// How many times an item of the older kind is pushed again to a peer
/// after a push of it failed (2 s, 4 s and 8 s apart). After that, the
/// pull is the safety net.
const PUSH_RETRY_MAX: u8 = 3;

/// An item of the older kind whose push to a peer failed, waiting to be
/// pushed to it again.
struct RetryEntry {
    item: cordelia_network::messages::Item,
    peer_id: NodeId,
    channel_id: String,
    exclude_peer: Option<NodeId>,
    /// The tries made of it so far.
    attempt: u8,
    retry_at: tokio::time::Instant,
}

/// The older kind's push retries: sender-side, one stream for each item,
/// with backoff. A push that fails reports each of its items through
/// [`PushRetries::failed`], and each round tries again those that are due.
/// Silent drop on the receiver's side stays: no NACK (a DoS amplification
/// vector).
///
/// **At most `PUSH_RETRY_STREAMS_AT_ONCE` to one peer at once** (decision
/// 2026-10-22 (memory), rule 9). A failed repush of up to
/// `MAX_PUSHED_ITEMS` items would otherwise open a stream for each at
/// once, and against a peer that lets a few streams be open, most of them
/// would wait for a stream, time out and use up their tries. An item held
/// back stays waiting for a later round, and is not counted as a try
/// until it is tried.
struct PushRetries {
    waiting: Vec<RetryEntry>,
    failed_tx: tokio::sync::mpsc::UnboundedSender<RetryEntry>,
    failed_rx: tokio::sync::mpsc::UnboundedReceiver<RetryEntry>,
    /// How many retries are running to each peer.
    running: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<NodeId, usize>>>,
}

/// One retry running to a peer, counted for as long as it runs.
struct RetryRunning {
    peer: NodeId,
    running: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<NodeId, usize>>>,
}

impl Drop for RetryRunning {
    fn drop(&mut self) {
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = running.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                running.remove(&self.peer);
            }
        }
    }
}

impl PushRetries {
    fn new() -> Self {
        let (failed_tx, failed_rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            waiting: Vec::new(),
            failed_tx,
            failed_rx,
            running: Default::default(),
        }
    }

    /// Where a push that failed reports each of its items.
    fn failed(&self) -> tokio::sync::mpsc::UnboundedSender<RetryEntry> {
        self.failed_tx.clone()
    }

    /// One round, at `now`: each item that is due is pushed again on a
    /// stream of its own, to its peer if `hot` holds of it and it has a
    /// connection (`connection_of`), within `PUSH_RETRY_STREAMS_AT_ONCE`
    /// running to that peer. One that has had its tries, or whose peer is
    /// no longer hot or connected, is dropped.
    fn round(
        &mut self,
        now: tokio::time::Instant,
        hot: &dyn Fn(&NodeId) -> bool,
        connection_of: &dyn Fn(&NodeId) -> Option<quinn::Connection>,
    ) {
        while let Ok(entry) = self.failed_rx.try_recv() {
            self.waiting.push(entry);
        }
        if self.waiting.is_empty() {
            return;
        }
        let mut to_try = Vec::new();
        {
            let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
            let mut remaining = Vec::new();
            for entry in self.waiting.drain(..) {
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
                if !hot(&entry.peer_id) {
                    tracing::debug!(
                        peer = %entry.peer_id, "push retry skipped: peer no longer hot"
                    );
                    continue;
                }
                let Some(conn) = connection_of(&entry.peer_id) else {
                    continue;
                };
                // Held back for a later round, its tries unspent.
                let at_once = running.entry(entry.peer_id.clone()).or_default();
                if *at_once >= cordelia_core::protocol::PUSH_RETRY_STREAMS_AT_ONCE {
                    remaining.push(entry);
                    continue;
                }
                *at_once += 1;
                to_try.push((conn, entry));
            }
            self.waiting = remaining;
        }
        for (conn, entry) in to_try {
            let running = RetryRunning {
                peer: entry.peer_id.clone(),
                running: self.running.clone(),
            };
            tokio::spawn(push_again(conn, entry, self.failed_tx.clone(), running));
        }
    }

    /// Whether no item waits and no retry runs.
    #[cfg(test)]
    fn is_idle(&self) -> bool {
        self.waiting.is_empty()
            && self.failed_rx.is_empty()
            && self
                .running
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
    }
}

/// Push `entry`'s item to its peer again, on a stream of its own, as its
/// next try; where it fails, report it to `failed` with a backoff that
/// doubles with each try.
async fn push_again(
    conn: quinn::Connection,
    entry: RetryEntry,
    failed: tokio::sync::mpsc::UnboundedSender<RetryEntry>,
    _running: RetryRunning,
) {
    let pid = entry.peer_id;
    let attempt = entry.attempt + 1;
    let again = |item, peer_id, channel_id, exclude_peer| {
        let backoff = std::time::Duration::from_secs(2u64.pow(attempt as u32));
        let _ = failed.send(RetryEntry {
            item,
            peer_id,
            channel_id,
            exclude_peer,
            attempt,
            retry_at: tokio::time::Instant::now() + backoff,
        });
    };
    tracing::debug!(peer = %pid, attempt, "push retry");
    let (mut send, mut recv) = match open_bi(&conn).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(peer = %pid, attempt, error = %e, "push retry open_bi failed");
            again(entry.item, pid, entry.channel_id, entry.exclude_peer);
            return;
        }
    };
    let mut stream = tokio::io::join(&mut recv, &mut send);
    let items = std::slice::from_ref(&entry.item);
    match cordelia_network::item_sync::send_push(&mut stream, items).await {
        Ok(ack) => {
            tracing::debug!(peer = %pid, attempt, stored = ack.stored, "push retry delivered")
        }
        Err(e) => {
            tracing::debug!(peer = %pid, attempt, error = %e, "push retry failed");
            again(entry.item, pid, entry.channel_id, entry.exclude_peer);
        }
    }
}

/// Background task that accepts incoming QUIC connections, handles
/// outbound item pushes, and manages peer lifecycle.
#[expect(
    clippy::too_many_arguments,
    reason = "config args move into a struct when the relay work reshapes this loop"
)]
pub async fn p2p_loop(
    mut conn_mgr: cordelia_network::connection::ConnectionManager,
    state: web::Data<cordelia_api::state::AppState>,
    mut push_rx: tokio::sync::mpsc::UnboundedReceiver<cordelia_api::state::PushItem>,
    mut announce_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    allow_private_addresses: bool,
    node_role: String,
    gov_config: cordelia_core::config::GovernorConfig,
    relays_set_up: Vec<cordelia_network::bootstrap::Relay>,
    relay_addrs: RelayAddrs,
    trusted_peer_ids: Vec<NodeId>,
    max_storage_bytes: u64,
    relay_ask_again: std::time::Duration,
    most_proved: usize,
    reach: Option<std::sync::Arc<cordelia_node::device_entries::Reach>>,
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

    let mut governor = governor_for(&node_role, &gov_config, &trusted_peer_ids);

    // Connection tracker (§3.1): per-IP, per-subnet, global limits

    // Per-peer rate limiters, shared with handle_peer_streams tasks
    let peer_rates: std::sync::Arc<std::sync::Mutex<Rates>> = std::sync::Arc::new(
        std::sync::Mutex::new(Rates::new(max_storage_bytes).ask_again(relay_ask_again)),
    );
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

    // Epidemic forwarding seen table (§7.2). Shared between inbound push
    // (records senders) and repush flush (computes forward targets).
    let seen_table: std::sync::Arc<std::sync::RwLock<cordelia_network::seen_table::SeenTable>> =
        std::sync::Arc::new(std::sync::RwLock::new(
            cordelia_network::seen_table::SeenTable::new(),
        ));

    // Verified swarm members (§8.2.2). Peers whose NodeId matches an HKDF-derived
    // child key from the lead's seed. Populated on inbound verification.
    let swarm_members: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<NodeId>>> =
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new()));

    // What this node keeps for each peer and channel it fetches from: its
    // place in the peer's list of the channel (§4.4a), and the size of page
    // it asks for there.
    let sync_kept: std::sync::Arc<std::sync::Mutex<Kept>> =
        std::sync::Arc::new(std::sync::Mutex::new(Kept::default()));

    // When a relay next asks each peer that is not one of its hot peers
    // which channels it holds (see `peers_to_ask`).
    let ask_next: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<NodeId, std::time::Instant>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    // The peers a fetch is running from. One at a time from each: a peer
    // that answers slowly must not have fetches pile up behind it.
    let fetching: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<NodeId>>> =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));

    // Delivery feedback channel
    let (delivery_tx, mut delivery_rx) = tokio::sync::mpsc::unbounded_channel::<(NodeId, u64)>();

    // Governor event channel (created before bootstrap so post_connect can pass it)
    let (gov_tx, mut gov_rx) = tokio::sync::mpsc::unbounded_channel::<GovEvent>();

    // What a relay holds for the entries of channels from their secrets
    // (decision 2026-10-04 §2.4, §2.5): its room for them, with a cap of
    // the size of the older kind's, and the relays it works with. A node
    // of any other role has none, and answers none of their streams.
    let relay_entries: Option<std::sync::Arc<crate::relay_entries::RelayEntries>> =
        (node_role == "relay").then(|| {
            std::sync::Arc::new(
                crate::relay_entries::RelayEntries::new(
                    max_storage_bytes,
                    relay_addrs.clone(),
                    relay_ask_again,
                )
                .remembering_at_most(most_proved),
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
            &repush_tx,
            &delivery_tx,
            &peer_rates,
            &peer_states,
            &peer_relays,
            &gov_tx,
            &swarm_members,
            &seen_table,
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

    // Push retries (`PushRetries`): spawned pushes report failures to it,
    // and the select loop tries them again on a 2s timer.
    let mut push_retries = PushRetries::new();
    let retry_fail_tx = push_retries.failed();
    let mut retry_interval = tokio::time::interval(std::time::Duration::from_secs(2));
    retry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    retry_interval.tick().await;

    // Outbox flush state (§4.4a): one flush in flight at a time, spaced by
    // OUTBOX_FLUSH_INTERVAL_SECS, rotating across hot relays.
    let outbox_interval_dur =
        std::time::Duration::from_secs(cordelia_core::protocol::OUTBOX_FLUSH_INTERVAL_SECS);
    let mut outbox_interval = tokio::time::interval(outbox_interval_dur);
    outbox_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    outbox_interval.tick().await;
    let mut last_outbox_flush = std::time::Instant::now() - outbox_interval_dur;
    let outbox_in_flight = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let outbox_refusals = std::sync::Arc::new(std::sync::Mutex::new(OutboxRefusals::default()));
    let mut outbox_rotation: usize = 0;

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
    // The hourly task of messages (decision 2026-10-09 §7.1), on a
    // personal node: when it starts, and each hour after.
    let mut messages_interval = tokio::time::interval(std::time::Duration::from_secs(
        cordelia_core::protocol::AGENT_MESSAGE_CLEAR_INTERVAL_SECS,
    ));
    messages_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
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
    let mut sync_cycles_completed: u64 = 0;
    let mut heartbeat_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat_interval.tick().await;

    // Relay re-push flush timer: batch + de-dupe items before forwarding.
    // Jittered start so relays don't all flush simultaneously (§7.2).
    let repush_base = cordelia_core::protocol::REPUSH_INTERVAL_SECS;
    let repush_jitter = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        our_node_id.0.hash(&mut h);
        h.finish() % (repush_base * 1000) // ms jitter within interval
    };
    let repush_start = std::time::Duration::from_millis(repush_jitter);
    tokio::time::sleep(repush_start).await;
    let mut repush_interval = tokio::time::interval(std::time::Duration::from_secs(repush_base));
    repush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    repush_interval.tick().await;

    // The configured relays: each one that is not connected is dialled
    // again, at a slowing pace (see `relay_backoff`).
    let mut relay_interval = tokio::time::interval(std::time::Duration::from_secs(1));
    relay_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut relay_tries: std::collections::HashMap<TriedRelay, RelayTry> =
        std::collections::HashMap::new();
    // The relays that each dial in flight was begun for.
    let mut dialling: Dialling = Default::default();

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
    type ConnectMsg =
        Result<cordelia_network::connection::ConnectOutcome, (std::net::SocketAddr, String)>;
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
                    sync_cycles = sync_cycles_completed,
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
                        let room = {
                            let arriving = arriving.lock().unwrap_or_else(|e| e.into_inner());
                            cordelia_network::rate_limit::ConnectionTracker::from_ips(
                                conn_mgr
                                    .inbound_ips(&NodeId([0u8; 32]))
                                    .into_iter()
                                    .chain(arriving.iter().copied()),
                            )
                            .would_allow(address)
                        };
                        if refused || !room {
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
                            let (answers, refused) = dial_answered(
                                &mut relay_tries,
                                &mut dialling,
                                (&relays_set_up, &dialled),
                                (addr, &outcome.node_id.0),
                                (p2p_gov_tick_secs, any_connected),
                                reach.as_deref(),
                            );
                            if answers.is_empty() && !refused.is_empty() {
                                outcome.conn.close(0u32.into(), b"not the relay");
                                continue;
                            }
                        }

                        // Connection tracker check FIRST (inbound only, §3.1).
                        // Must run before HKDF verification to prevent attackers
                        // from bypassing per-IP limits to force CPU-expensive derivations.
                        // The limits count the inbound connections open now.
                        if direction == Direction::Inbound {
                            let ip = outcome.addr.ip();
                            let open = cordelia_network::rate_limit::ConnectionTracker::from_ips(
                                conn_mgr.inbound_ips(&outcome.node_id),
                            );
                            if !open.would_allow(ip) {
                                tracing::warn!(peer = %outcome.node_id, ip = %ip, "rejecting: connection limit exceeded");
                                outcome.conn.close(0u32.into(), b"limit");
                                continue;
                            }
                        }

                        // Personal nodes are outbound-only (§8.2), except from
                        // trusted_peers or verified swarm children (§8.2.2 PAN).
                        if direction == Direction::Inbound && node_role == "personal" {
                            let is_trusted = trusted_peer_ids.contains(&outcome.node_id);
                            // Check swarm_members cache first (avoids re-deriving on reconnect)
                            let already_verified = swarm_members.read().ok()
                                .map(|m| m.contains(&outcome.node_id))
                                .unwrap_or(false);
                            let is_swarm_child = if !is_trusted && !already_verified {
                                // On-demand HKDF verification. CPU-bound (~2.5ms worst case),
                                // run on blocking thread to avoid stalling the select loop.
                                let seed = *state.identity.seed();
                                let peer_pk = outcome.node_id.0;
                                let verified = tokio::task::block_in_place(|| {
                                    cordelia_crypto::verify_swarm_child(&seed, &peer_pk, 256)
                                });
                                match verified {
                                    Some(idx) => {
                                        tracing::info!(peer = %outcome.node_id, index = idx, "verified swarm child via HKDF (PAN §8.2.2)");
                                        if let Ok(mut members) = swarm_members.write() {
                                            members.insert(outcome.node_id.clone());
                                        }
                                        true
                                    }
                                    None => false,
                                }
                            } else {
                                already_verified
                            };

                            if !is_trusted && !is_swarm_child {
                                tracing::debug!(peer = %outcome.node_id, "rejecting inbound: personal nodes are outbound-only");
                                outcome.conn.close(0u32.into(), b"outbound-only");
                                continue;
                            }
                            if is_trusted {
                                tracing::info!(peer = %outcome.node_id, "accepted inbound from trusted peer (PAN §8.2.2)");
                            }
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
                                // The peer may have lost or replaced its database
                                // since the last connection (a relay that was
                                // rebuilt). Its arrival sequence then starts again,
                                // and a position kept from before would skip
                                // everything it stores from now on.
                                sync_kept
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .forget_peer(&node_id);
                                // A relay asks a peer that has just connected
                                // which channels it holds.
                                if let Ok(mut ask_next) = ask_next.lock() {
                                    ask_next.remove(&node_id);
                                }
                                post_connect(
                                    &node_id, &conn_mgr, &mut governor, &shared_peers,
                                    &state, &node_role, &repush_tx, &delivery_tx, &peer_rates, &peer_states,
                                    &peer_relays, &gov_tx, &swarm_members, &seen_table,
                                    &relay_addrs, &relay_entries, &large_permits,
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
                        let dialled = relay_addrs
                            .read()
                            .map(|relays| relays.clone())
                            .unwrap_or_default();
                        let any_connected = any_relay_connected(&relays_set_up, &relay_addrs, &conn_mgr);
                        dial_errored(
                            &mut relay_tries,
                            &mut dialling,
                            &dialled,
                            (addr, error),
                            (p2p_gov_tick_secs, any_connected),
                            reach.as_deref(),
                        );
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
                }
                for relay in &relays {
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
                    in_flight.insert(relay.addr);
                    let ctx = connect_ctx.clone();
                    let tx = connect_tx.clone();
                    let addr = relay.addr;
                    let relay = relay.clone();
                    tracing::debug!(relay = %relay.host, %addr, "dialling relay");
                    tokio::spawn(async move {
                        match dial_relay(&ctx, &relay).await {
                            Ok(outcome) => { let _ = tx.send(Ok(outcome)); }
                            Err(e) => { let _ = tx.send(Err((addr, e.to_string()))); }
                        }
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
                                        let _ = tx.send(Err((addr, e.to_string())));
                                    }
                                }
                            });
                            spawned += 1;
                        }
                    }
                    peer_share_rotation = peer_share_rotation.wrapping_add(spawned);
                }
            }

            // ── Outbox (§7.1, decision 2026-09-30 §4.4a) ───────────────
            // Local writes notify here. Our own items stay in the outbox
            // until a relay acknowledges them, and go out as one batched
            // push per flush: at most one flush per OUTBOX_FLUSH_INTERVAL_SECS,
            // so a burst of writes cannot trip a relay's per-peer write limit.
            // A personal node writes no item of the older kind, and
            // flushes none.
            Some(_) = push_rx.recv() => {
                while push_rx.try_recv().is_ok() {}
                if carries_older_kind(&node_role) && last_outbox_flush.elapsed() >= outbox_interval_dur {
                    last_outbox_flush = std::time::Instant::now();
                    flush_outbox(&state, &governor, &conn_mgr, &outbox_in_flight, &mut outbox_rotation, &outbox_refusals);
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

            // ── Entries of channels from their secrets, on a relay ────
            // What nobody uses goes after 90 days (decision 2026-10-04
            // §2.5). Off the select loop: it writes under the db lock.
            _ = entry_sweep_interval.tick(), if relay_entries.is_some() => {
                if let Some(entries) = relay_entries.clone() {
                    let sweep_state = state.clone();
                    tokio::task::spawn_blocking(move || entries.sweep(&sweep_state.db));
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
                    let relays = crate::relay_entries::listed_and_connected(entries, &conn_mgr);
                    crate::relay_entries::pull_from_each(entries, &state, relays);
                }
            }

            // ── Old deletes (§4.4; decision 2026-10-04 §2.3, §7.3) ────
            // One timer, and one length of time, for both kinds. Off the
            // select loop: each writes under the db lock.
            _ = gc_interval.tick() => {
                // Of the older kind's items, on the nodes that carry
                // them. No such node holds a channel's member list, so it
                // sweeps a key only when every author has deleted it.
                if carries_older_kind(&node_role) {
                    let gc_state = state.clone();
                    let members_known = false;
                    tokio::task::spawn_blocking(move || {
                        let Ok(db) = gc_state.db.lock() else { return };
                        match cordelia_storage::items::gc_keyed_tombstones(
                            &db,
                            cordelia_core::protocol::KEYED_TOMBSTONE_RETENTION_DAYS,
                            members_known,
                        ) {
                            Ok(0) => {}
                            Ok(n) => tracing::info!(items = n, "collected expired deleted keys"),
                            Err(e) => tracing::warn!(error = %e, "tombstone gc failed"),
                        }
                    });
                }
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

            // ── Push retry processing ─────────────────────────────────
            _ = retry_interval.tick() => {
                let hot = governor.hot_peers();
                push_retries.round(
                    tokio::time::Instant::now(),
                    &|peer| hot.contains(peer),
                    &|peer| conn_mgr.get_connection(peer).cloned(),
                );
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

                // Filter out what a relay does not pass on: local-scope items
                // (§8.2.2: never leave the PAN), and the items of a channel
                // whose ID may not be told to a peer.
                {
                    let db = state.db.lock();
                    let db = db.as_deref().ok();
                    pending.retain(|_, (item, _)| passed_on(db, &item.channel_id));
                }
                if pending.is_empty() { continue; }

                // Build per-peer batches using seen table (§7.2 epidemic forwarding).
                // Forward to all hot relay peers that haven't seen each item.
                let relay_peers: Vec<NodeId> = governor.hot_peers().into_iter()
                    .filter(|p| governor.peer_info(p).map(|i| i.is_relay).unwrap_or(false))
                    .collect();
                let mut peer_batches: std::collections::HashMap<
                    NodeId,
                    Vec<cordelia_network::messages::Item>,
                > = std::collections::HashMap::new();
                let seen_len = {
                    let mut st = seen_table.write().unwrap_or_else(|e| e.into_inner());
                    st.evict(); // TTL sweep piggy-backed on 5s timer
                    for (item, _source) in pending.values() {
                        let hash: [u8; 32] = item.content_hash.as_slice().try_into().unwrap_or([0u8; 32]);
                        let targets = st.forward_targets(&hash, &relay_peers);
                        if !targets.is_empty() {
                            st.record_targets(&hash, &targets);
                            for peer_id in targets {
                                peer_batches.entry(peer_id).or_default().push(item.clone());
                            }
                        }
                    }
                    st.len()
                };

                if peer_batches.is_empty() { continue; }
                let deduped = pending.len();
                tracing::debug!(items = deduped, peers = peer_batches.len(), seen_table = seen_len, "relay repush flush (epidemic)");

                for (peer_id, items) in peer_batches {
                    let Some(conn) = conn_mgr.get_connection(&peer_id) else {
                        continue;
                    };
                    for items in in_pushes(items) {
                        let conn = conn.clone();
                        let pid = peer_id.clone();
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
                while announce_rx.try_recv().is_ok() {}
                // Send full channel list to all hot peers (simpler than
                // incremental per-channel -- reconnect-safe too)
                if node_role != "relay" && carries_older_kind(&node_role) {
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

                // A device's own channels, at each relay it is set up
                // with: it shows its change entry, and then proves, pulls
                // and pushes where the answer gives it leave.
                device_pass(&device_entries, &relays_set_up, &relay_addrs, &conn_mgr, &state.own_channels, cordelia_node::device_entries::Pass::Whole);

                // That is all a personal node fetches: it holds no channel
                // of the older kind, and asks no peer for one.
                if !carries_older_kind(&node_role) { continue; }

                // Channels whose members changed since the last pass are listed
                // again from the start, from every peer: this device may have
                // refused entries by a member it had not heard of yet.
                let changed: Vec<String> = state
                    .relist
                    .lock()
                    .map(|mut relist| relist.drain().collect())
                    .unwrap_or_default();
                let peers = conn_mgr.connected_peers();
                // A place, and a page size, is kept only for peers that are
                // connected. Without this a peer could connect under key
                // after key and leave a relay holding a place for each.
                let places = {
                    let mut kept = sync_kept.lock().unwrap_or_else(|e| e.into_inner());
                    if !changed.is_empty() {
                        kept.forget_channels(&changed);
                    }
                    kept.forget_gone(&peers);
                    kept.total()
                };
                if peers.is_empty() { continue; }

                // Personal nodes: get ALL subscribed channels (including local).
                // Scope filtering happens on the serving side (§8.2.2):
                // handle_inbound_sync rejects local-scope requests from non-swarm peers.
                // Swarm nodes need to sync local channels from their lead.
                // The inbox comes first (see `channels_to_fetch`).
                let local_channels: Vec<String> = {
                    let db = match state.db.lock() {
                        Ok(db) => db,
                        Err(_) => continue,
                    };
                    channels_to_fetch(&db, &node_role, &state.identity.public_key())
                };
                // Personal nodes with no subscribed channels: nothing to sync
                if local_channels.is_empty() && node_role != "relay" { continue; }

                let is_relay = node_role == "relay";
                let hot = governor.hot_peers();
                // A relay also asks the peers that are not among its hot
                // peers, which is where its devices are: less often, since
                // a device sends what it writes as it writes it.
                let others = if is_relay {
                    let mut ask_next = ask_next.lock().unwrap_or_else(|e| e.into_inner());
                    peers_to_ask(&peers, &hot, &mut ask_next, std::time::Instant::now())
                } else {
                    Vec::new()
                };
                sync_cycles_completed += 1;
                tracing::info!(hot_peers = hot.len(), asked = others.len(), total_peers = peers.len(), local_channels = local_channels.len(), places, cycle = sync_cycles_completed, "pull-sync cycle");
                for target in hot.iter().chain(&others) {
                    let Some(conn) = conn_mgr.get_connection(target) else {
                        continue;
                    };
                    // One fetch at a time from each peer.
                    let Some(fetch) = Fetching::begin(&fetching, target) else {
                        continue;
                    };
                    // What a relay this node lists hands over is not counted
                    // against an address.
                    let from_listed_relay = governor
                        .peer_info(target)
                        .is_some_and(|peer| peer.is_relay);
                    // What a relay fetches from any other peer is bounded as
                    // what that peer may push is, and is only what the peer
                    // says it holds.
                    let limited = is_relay && !from_listed_relay;
                    let from = FetchFrom {
                        target: target.clone(),
                        state: state.clone(),
                        role: node_role.clone(),
                        channels: if limited { Vec::new() } else { local_channels.clone() },
                        ask_what_it_holds: is_relay,
                        limited,
                        address: conn_mgr
                            .address_of(target)
                            .unwrap_or_else(|| conn.remote_address().ip()),
                        rates: peer_rates.clone(),
                        kept: sync_kept.clone(),
                        repush_tx: repush_tx.clone(),
                        seen_table: seen_table.clone(),
                        // Its answers longer than a small message are read
                        // under the large permits, unless it is a relay
                        // listed by key (decision 2026-10-22 (memory),
                        // rules 6 and 7).
                        permits: Some(large_permits.clone()),
                        listed_by_key: relay_entries
                            .as_ref()
                            .is_some_and(|entries| entries.lists(target)),
                    };
                    let conn = conn.clone();
                    let gtx = gov_tx.clone();
                    let ask_next = ask_next.clone();
                    tokio::spawn(async move {
                        let _fetch = fetch;
                        let target = from.target.clone();
                        let (fetched, stored) = fetch_from(conn, from).await;
                        // When a relay asks this peer again.
                        if is_relay && let Ok(mut ask_next) = ask_next.lock() {
                            match next_ask(fetched, relay_ask_again, std::time::Instant::now()) {
                                Some(at) => ask_next.insert(target.clone(), at),
                                None => ask_next.remove(&target),
                            };
                        }
                        // One GovEvent per peer (not per channel)
                        if stored > 0 {
                            let _ = gtx.send(GovEvent::ItemsDelivered(target, stored));
                        }
                    });
                }
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
                while let Ok((peer_id, count)) = delivery_rx.try_recv() {
                    governor.record_items_delivered(&peer_id, count);
                    // If we're a relay, items delivered to us are items that peer relayed
                    if node_role == "relay" {
                        governor.record_items_relayed(&peer_id, count);
                    }
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
                        // Clean up swarm member tracking on disconnect (§8.2.2)
                        if let Ok(mut members) = swarm_members.write() {
                            members.remove(peer_id);
                        }
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
                        if from == "warm"
                            && to == "hot"
                            && node_role != "relay"
                            && carries_older_kind(&node_role)
                            && let Some(conn) = conn_mgr.get_connection(node_id)
                        {
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
                    break;
                }
            }
        }
    }
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
        for p in due {
            let mut keyed = secret.to_vec();
            keyed.extend_from_slice(&p.node_id.0);
            let hash = cordelia_crypto::sha256(&keyed);
            if usage::record_sighting(&db, &hash, p.is_relay, now).is_ok() {
                self.noted
                    .insert(p.node_id.clone(), std::time::Instant::now());
            }
        }
        if prune_due {
            let _ = usage::prune_sightings(&db, now - SIGHTING_RETENTION_DAYS * 86_400);
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
/// address (`wrong_key`), or otherwise. Its next dial waits as
/// [`relay_backoff`] says for `tick_secs`, paced as a node that has
/// another relay connected only where [`paced_with_another`] says
/// (decision 2026-10-19, rule 3), and the dial is an attempt at it that
/// failed, in `reach`.
fn dial_failed(
    tries: &mut std::collections::HashMap<TriedRelay, RelayTry>,
    relay: TriedRelay,
    error: String,
    (wrong_key, tick_secs, any_connected): (bool, u64, bool),
    reach: Option<&cordelia_node::device_entries::Reach>,
) {
    let another = paced_with_another(any_connected, reach, &relay);
    if let Some(reach) = reach {
        reach.dial_ends(&reach_id(&relay), false);
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
            tried_relay(relay),
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
            tried_relay(relay),
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
            moved,
            moved_away,
            (false, tick_secs, any_connected),
            reach,
        );
    }
    (answers, refused)
}

/// A dial at `addr` failed with `error`: each configured relay at that
/// address, among `relays` as their names resolve now, and each that the
/// dial was begun for ([`Dialling`]), wherever its name resolves now.
fn dial_errored(
    tries: &mut std::collections::HashMap<TriedRelay, RelayTry>,
    dialling: &mut Dialling,
    relays: &[cordelia_network::bootstrap::RelayAddr],
    (addr, error): (std::net::SocketAddr, String),
    (tick_secs, any_connected): (u64, bool),
    reach: Option<&cordelia_node::device_entries::Reach>,
) {
    let mut failed: Vec<TriedRelay> = relays
        .iter()
        .filter(|relay| relay.addr == addr)
        .map(tried_relay)
        .collect();
    for begun in dialling.remove(&addr).unwrap_or_default() {
        if !failed.contains(&begun) {
            failed.push(begun);
        }
    }
    for tried in failed {
        dial_failed(
            tries,
            tried,
            error.clone(),
            (false, tick_secs, any_connected),
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
/// - Its dial policy (§8.2.2): a personal node with trusted peers dials
///   only those (a swarm node), any other personal node only relays, and
///   a relay or a bootnode any peer.
/// - **A personal node keeps its relays** (decision 2026-10-17 §2):
///   every relay it is set up with is one the person chose, and churn
///   closes none of them. A relay and a bootnode churn as before.
fn governor_for(
    role: &str,
    gov_config: &cordelia_core::config::GovernorConfig,
    trusted_peer_ids: &[NodeId],
) -> cordelia_network::governor::Governor {
    use cordelia_network::governor::{DialPolicy, Governor, GovernorTargets, GovernorTimeouts};
    let personal = role == "personal";
    let dial_policy = if personal && !trusted_peer_ids.is_empty() {
        DialPolicy::TrustedOnly(trusted_peer_ids.to_vec())
    } else if personal {
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

/// Dial a configured relay (decision 2026-10-22 (memory), rule 12): one
/// configured by key with the transport settings between relays listed by
/// key, one configured by address alone with every peer's.
async fn dial_relay(
    ctx: &cordelia_network::connection::ConnectContext,
    relay: &cordelia_network::bootstrap::RelayAddr,
) -> Result<
    cordelia_network::connection::ConnectOutcome,
    cordelia_network::connection::ConnectionError,
> {
    if relay.key.is_some() {
        cordelia_network::connection::outbound_connect_to_listed(ctx, relay.addr).await
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
            let link = peer.and_then(|peer| {
                let conn = conn_mgr.get_connection(&peer)?.clone();
                Some(Link::new(relay.host.clone(), peer, conn))
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
/// other relay. Only while the device wakes does one pass ask every
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
            }
        })
        .collect()
}

/// Publish where each relay that the node is set up with stands
/// ([`relay_snapshots`]).
fn publish_relays(
    state: &cordelia_api::state::AppState,
    set_up: &[cordelia_network::bootstrap::Relay],
    resolved: &[cordelia_network::bootstrap::RelayAddr],
    tries: &std::collections::HashMap<TriedRelay, RelayTry>,
    conn_mgr: &cordelia_network::connection::ConnectionManager,
) {
    let (_, one) = one_relay_each_now(set_up, resolved, conn_mgr);
    let list = relay_snapshots(set_up, resolved, tries, &one, &|relay| {
        relay_connected(conn_mgr, relay)
    });
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
/// limit by address counts the peer under it, for both kinds of channel,
/// whatever address the connection has moved to since: one that was read
/// at each stream would hand a peer that moves a new address's allowance.
#[allow(clippy::too_many_arguments)]
pub async fn handle_peer_streams(
    conn: quinn::Connection,
    peer_id: NodeId,
    made_from: std::net::IpAddr,
    state: web::Data<cordelia_api::state::AppState>,
    shared_peers: std::sync::Arc<std::sync::RwLock<Vec<cordelia_network::messages::PeerAddress>>>,
    node_role: String,
    repush_tx: tokio::sync::mpsc::UnboundedSender<(cordelia_network::messages::Item, NodeId)>,
    delivery_tx: tokio::sync::mpsc::UnboundedSender<(NodeId, u64)>,
    peer_rates: std::sync::Arc<std::sync::Mutex<Rates>>,
    peer_states: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<NodeId, u8>>>,
    peer_relays: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<NodeId>>>,
    gov_tx: tokio::sync::mpsc::UnboundedSender<GovEvent>,
    swarm_members: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<NodeId>>>,
    seen_table: std::sync::Arc<std::sync::RwLock<cordelia_network::seen_table::SeenTable>>,
    relay_entries: Option<std::sync::Arc<crate::relay_entries::RelayEntries>>,
    large_permits: std::sync::Arc<LargePermits>,
    listed_settings: bool,
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
        // bootnode answers only peer-sharing (small), and the one case it
        // leaves is a relay listed by key pushing the older kind over a
        // small message to a bootnode, which does not happen between
        // R1's nodes.
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

        // Protocol gating by peer state (§5.4.2, §7.2)
        // Relays accept data protocols from Warm+ peers (public infrastructure).
        // Personal nodes require Hot for data protocols (private, serve chosen peers only).
        // PSK-Exchange remains Hot-only for all roles (security boundary).
        let peer_state = peer_states
            .read()
            .ok()
            .and_then(|s| s.get(&peer_id).copied())
            .unwrap_or(1); // default Warm if not yet synced
        let is_hot = peer_state == 2;
        let is_warm_or_hot = peer_state >= 1;

        let data_allowed = match protocol {
            cordelia_network::messages::Protocol::ItemPush
            | cordelia_network::messages::Protocol::ItemSync
            | cordelia_network::messages::Protocol::ChannelAnnounce => {
                if node_role == "relay" {
                    is_warm_or_hot
                } else {
                    is_hot
                }
            }
            _ => true, // non-data protocols handled elsewhere
        };

        match protocol {
            // A personal node carries no channel of the older kind. What
            // a peer asks it of that kind it answers with nothing, as a
            // device that holds no such channel would (decision
            // 2026-10-04 §10.1): a relay asks each of its devices which
            // channels it holds, and one that is answered asks again at
            // its usual pace, where one that is refused takes that for a
            // failure and asks again within the minute.
            cordelia_network::messages::Protocol::ItemSync if !carries_older_kind(&node_role) => {
                answer_sync_with_nothing(&mut send, &mut recv, &peer_id).await;
                continue;
            }
            // It takes no push of that kind, and hears no announcement of
            // one. Each is refused at once, so that the peer does not
            // wait for an answer that is not coming.
            cordelia_network::messages::Protocol::ItemPush
            | cordelia_network::messages::Protocol::ChannelAnnounce
                if !carries_older_kind(&node_role) =>
            {
                tracing::debug!(peer = %peer_id, protocol = proto_name, "refused: a personal node carries no channel of the older kind");
                refuse_stream(&mut send, &mut recv);
                continue;
            }
            cordelia_network::messages::Protocol::ItemPush
            | cordelia_network::messages::Protocol::ItemSync
            | cordelia_network::messages::Protocol::ChannelAnnounce
                if !data_allowed =>
            {
                tracing::debug!(peer = %peer_id, protocol = proto_name, state = peer_state, "rejected: data protocol below required state");
                continue;
            }
            cordelia_network::messages::Protocol::ItemPush => {
                let over = handle_inbound_push(
                    &mut send,
                    &mut recv,
                    &peer_id,
                    &state,
                    &node_role,
                    &repush_tx,
                    &delivery_tx,
                    &seen_table,
                    &peer_rates,
                    !unlimited,
                    address,
                    Some(&large_permits),
                    listed_by_key,
                )
                .await;
                if over.is_some_and(|over| over.cut_off) && !own_relay {
                    cut_off(&conn, &peer_id, address, &gov_tx);
                    break;
                }
            }
            cordelia_network::messages::Protocol::ItemSync => {
                let is_swarm_peer = swarm_members
                    .read()
                    .ok()
                    .map(|m| m.contains(&peer_id))
                    .unwrap_or(false);
                let is_relay_peer = peer_relays
                    .read()
                    .ok()
                    .map(|relays| relays.contains(&peer_id))
                    .unwrap_or(false);
                handle_inbound_sync(
                    &mut send,
                    &mut recv,
                    &peer_id,
                    &state,
                    is_relay_peer,
                    is_swarm_peer,
                    Some(&large_permits),
                    address,
                    listed_by_key,
                )
                .await;
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
            cordelia_network::messages::Protocol::ChannelAnnounce => {
                handle_inbound_channel_announce(&mut recv, &peer_id, &gov_tx).await;
            }
            // The streams of entries of channels from their secrets
            // (decision 2026-10-04 §2.4), which a relay serves. A node of
            // any other role holds nothing to serve them with, and they
            // fall through to what it does with a stream it does not
            // serve. A relay serves them to the peers it serves the older
            // kind to: those that are warm or hot.
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
                    listed_settings,
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

/// What reading the one push on a stream of Item-Push gives.
enum PushRead<'p> {
    /// The push, with the large permit held for a frame longer than a
    /// small message (rule 2). The permit is held until the answer is
    /// written.
    Payload(
        cordelia_network::messages::PushPayload,
        Option<LargePermit<'p>>,
    ),
    /// The frame was over the push allowance: the breach, with which the
    /// caller refuses the stream (ERR_RATE_LIMIT).
    Over(OverLimit),
    /// A frame longer than a small message, for which no permit came in
    /// time (rule 2): the caller refuses it with ERR_LARGE_MESSAGE_LATER.
    LargeLater,
    /// The stream ended, or a frame that is no push and no breach.
    Ended,
}

/// Read the one push on a stream of Item-Push. A frame longer than a small
/// message is read only under a large permit (decision 2026-10-22
/// (memory), rule 2), unless the peer is a relay listed by key (rule 7). A
/// frame that is no push, bytes that are no message of the stream or a
/// message that is not a push, is not answered, and its bytes count
/// against what the peer may push, as an entry of that size would, where
/// the peer is `limited`: the node read them, and a megabyte read for
/// nothing is still a megabyte.
async fn read_push<'p, R>(
    recv: &mut R,
    peer_id: &NodeId,
    peer_rates: &std::sync::Mutex<Rates>,
    limited: bool,
    address: std::net::IpAddr,
    permits: Option<&'p LargePermits>,
    listed: bool,
) -> PushRead<'p>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let (frame, permit) = match read_under_permit(recv, permits, address, listed).await {
        Framed::Frame(frame, permit) => (frame, permit),
        Framed::LargeLater => return PushRead::LargeLater,
        Framed::Ended => {
            tracing::debug!(peer = %peer_id, "failed to read push frame");
            return PushRead::Ended;
        }
    };
    match cordelia_network::codec::decode_message(
        cordelia_network::messages::Protocol::ItemPush,
        &frame,
    ) {
        Ok(cordelia_network::messages::WireMessage::PushPayload(payload)) => {
            PushRead::Payload(payload, permit)
        }
        read => {
            tracing::debug!(peer = %peer_id, bytes = frame.len(), is_message = read.is_ok(), "a frame on a push stream that is no push");
            let bytes = cordelia_core::protocol::entry_cost(frame.len());
            let over = limited
                .then(|| {
                    peer_rates
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .pushed(peer_id, address, bytes)
                        .err()
                })
                .flatten();
            match over {
                Some(over) => PushRead::Over(over),
                None => PushRead::Ended,
            }
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "forwarding state moves into a struct when slot/rev and tombstones change this handler"
)]
async fn handle_inbound_push(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    peer_id: &NodeId,
    state: &web::Data<cordelia_api::state::AppState>,
    node_role: &str,
    repush_tx: &tokio::sync::mpsc::UnboundedSender<(cordelia_network::messages::Item, NodeId)>,
    delivery_tx: &tokio::sync::mpsc::UnboundedSender<(NodeId, u64)>,
    seen_table: &std::sync::Arc<std::sync::RwLock<cordelia_network::seen_table::SeenTable>>,
    peer_rates: &std::sync::Arc<std::sync::Mutex<Rates>>,
    limited: bool,
    address: std::net::IpAddr,
    permits: Option<&LargePermits>,
    listed: bool,
) -> Option<OverLimit> {
    // The permit, where this is a frame longer than a small message from a
    // peer that is not a listed relay (rule 2), is held through the ack's
    // write below and let go when this handler returns.
    let (payload, _permit) =
        match read_push(recv, peer_id, peer_rates, limited, address, permits, listed).await {
            PushRead::Payload(payload, permit) => (payload, permit),
            PushRead::Over(over) => {
                refuse_stream(send, recv);
                return Some(over);
            }
            PushRead::LargeLater => {
                refuse_large_later(send, recv);
                return None;
            }
            PushRead::Ended => return None,
        };

    // What this push carries counts against the connection's allowance
    // and its address's: each entry as its ciphertext and what an entry
    // takes beyond it, so that small entries cost what they take. Over
    // either, the push is refused whole: no answer, so a sender on any
    // version keeps what it sent and offers it again.
    let bytes: u64 = payload
        .items
        .iter()
        .map(|item| cordelia_core::protocol::entry_cost(item.encrypted_blob.len()))
        .sum();
    let over = limited
        .then(|| {
            peer_rates
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pushed(peer_id, address, bytes)
                .err()
        })
        .flatten();
    if let Some(over) = over {
        tracing::warn!(peer = %peer_id, bytes, cut_off = over.cut_off, "push over the byte allowance; refused");
        refuse_stream(send, recv);
        return Some(over);
    }

    // Checked before the database is held (see `check_item`).
    let checked: Vec<Result<Checked, &'static str>> =
        payload.items.iter().map(check_item).collect();

    // Track which items are newly stored (for selective re-push)
    let mut newly_stored: Vec<cordelia_network::messages::Item> = Vec::new();
    let mut refused: Vec<cordelia_network::messages::Refusal> = Vec::new();
    let (stored, dedup, rejected) = {
        let db = match state.db.lock() {
            Ok(db) => db,
            Err(_) => return None,
        };
        let own = state.identity.public_key();
        // A relay has only so much room (see `RelayRoom`). What a relay it
        // lists sends it is not counted against an address.
        let max_bytes = peer_rates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .relay_max_bytes;
        let mut room = RelayRoom::new(max_bytes, Some(&**peer_rates), limited.then_some(address));
        let mut stored = 0u32;
        let mut dedup = 0u32;
        let mut rejected = 0u32;
        // One transaction for the push: one write to disk however many
        // entries it carries. Stored one by one, a push of small entries
        // held the database for seconds, and every other peer waited.
        let batch = match db.unchecked_transaction() {
            Ok(batch) => batch,
            Err(e) => {
                tracing::warn!(peer = %peer_id, error = %e, "could not begin storing a push");
                return None;
            }
        };
        for (item, checked) in payload.items.iter().zip(checked) {
            let room = (node_role == "relay").then_some(&mut room);
            let outcome = checked
                .and_then(|checked| store_checked(&db, item, &checked, node_role, &own, room));
            match outcome {
                Ok(true) => {
                    stored += 1;
                    newly_stored.push(item.clone());
                }
                Ok(false) => dedup += 1,
                Err(why) => {
                    rejected += 1;
                    refused.push(cordelia_network::messages::Refusal {
                        item_id: item.item_id.clone(),
                        why: why.into(),
                    });
                }
            }
        }
        // Nothing is answered for a push that could not be stored: the
        // sender keeps what it sent, and offers it again.
        if let Err(e) = batch.commit() {
            tracing::warn!(peer = %peer_id, error = %e, "could not store a push");
            return None;
        }
        // What the relay dropped to make room is listed again from the
        // start, from every peer.
        if !room.dropped.is_empty()
            && let Ok(mut relist) = state.relist.lock()
        {
            relist.extend(room.dropped.drain(..));
        }
        (stored, dedup, rejected)
    };

    tracing::debug!(peer = %peer_id, stored, dedup, items = payload.items.len(), "processed inbound push");

    if stored > 0 {
        let _ = delivery_tx.send((peer_id.clone(), stored as u64));
    }

    // Epidemic relay forwarding (§7.2):
    // - ALL newly stored items queued for forwarding regardless of sender role
    // - Sender recorded in seen table so they're excluded from forward targets
    // - Seen table prevents forwarding loops across multi-hop paths
    if node_role == "relay" && !newly_stored.is_empty() {
        if let Ok(mut st) = seen_table.write() {
            for item in &newly_stored {
                let hash: [u8; 32] = item.content_hash.as_slice().try_into().unwrap_or([0u8; 32]);
                st.record_sender(&hash, peer_id);
            }
        }
        for item in &newly_stored {
            let _ = repush_tx.send((item.clone(), peer_id.clone()));
        }
        tracing::debug!(peer = %peer_id, queued = newly_stored.len(), "relay repush queued (epidemic)");
    }

    let ack =
        cordelia_network::messages::WireMessage::PushAck(cordelia_network::messages::PushAck {
            stored,
            dedup_dropped: dedup,
            policy_rejected: 0,
            verification_failed: rejected,
            refused,
        });
    // The answer is encoded, and the message dropped, before the write
    // (decision 2026-10-22 (memory), rule 4): a peer that grants no credit
    // can make the write wait up to STREAM_TIMEOUT, and through it the
    // node holds the encoding alone, not the answer (which lists what was
    // refused).
    let written = cordelia_network::codec::encode_message(&ack);
    drop(ack);
    if let Ok(written) = written {
        let _ = cordelia_network::codec::write_raw_frame(send, &written).await;
    }
    None
}

/// The items a relay passes on to one peer, as pushes of at most
/// MAX_PUSHED_ITEMS each, in their order: a push of more is refused where
/// it is read (parameter-rationale.md §1).
fn in_pushes(
    items: Vec<cordelia_network::messages::Item>,
) -> Vec<Vec<cordelia_network::messages::Item>> {
    let mut items = items.into_iter().peekable();
    let mut pushes = Vec::new();
    while items.peek().is_some() {
        pushes.push(
            items
                .by_ref()
                .take(cordelia_core::protocol::MAX_PUSHED_ITEMS)
                .collect(),
        );
    }
    pushes
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
        // waits, as `test_a_fetch_request_is_not_held_while_the_node_waits`
        // has for the sync of a node that carries the older kind.
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
    tracing::debug!(peer = %peer_id, "answered a sync of the older kind with nothing: a personal node carries no channel of that kind");
    send.finish_up();
}

#[expect(
    clippy::too_many_arguments,
    reason = "the permit, the address and whether the peer is listed join an already wide handler"
)]
async fn handle_inbound_sync<W, R>(
    send: &mut W,
    recv: &mut R,
    peer_id: &NodeId,
    state: &web::Data<cordelia_api::state::AppState>,
    is_relay_peer: bool,
    is_swarm_peer: bool,
    permits: Option<&LargePermits>,
    address: std::net::IpAddr,
    listed: bool,
) where
    W: tokio::io::AsyncWrite
        + Unpin
        + cordelia_network::codec::GiveUp
        + crate::relay_entries::Refuse,
    R: tokio::io::AsyncRead + Unpin + crate::relay_entries::Refuse,
{
    // Each request on the stream in turn (§4.5): the channel list, a
    // channel's headers, and a fetch of a channel's items. A frame longer
    // than a small message is read only under a large permit (decision
    // 2026-10-22 (memory), rule 2), which is held through the write of its
    // answer and let go before the next frame is read: one for the stream
    // at a time. A fetch answer over a small page is loaded and written
    // only under one too (rule 3). A listed relay's frames are read, and
    // its answers written, at once (rule 7). Every
    // answer is encoded and the message dropped before it is written (rule
    // 4), so a peer that grants no credit cannot make the node hold the
    // answer (a page of headers, or a fetch of up to a message of items)
    // through the write.
    let mut channels_served: u32 = 0;
    // The channel of the last SyncRequest that was served: a FetchRequest
    // is for it, and is honoured only right after it, as it was when each
    // fetch was read in the branch of its own.
    let mut fetch_channel: Option<String> = None;
    let mut first = true;
    loop {
        let (msg, mut permit) = match read_under_permit(recv, permits, address, listed).await {
            Framed::Frame(bytes, permit) => {
                match cordelia_network::codec::decode_message(
                    cordelia_network::messages::Protocol::ItemSync,
                    &bytes,
                ) {
                    Ok(msg) => (msg, permit),
                    Err(e) => {
                        tracing::debug!(peer = %peer_id, error = %e, "a frame on a sync stream that is no message");
                        break;
                    }
                }
            }
            Framed::LargeLater => {
                tracing::debug!(peer = %peer_id, "a sync frame over a small message, and no permit for now; refused");
                refuse_large_later(send, recv);
                break;
            }
            Framed::Ended => break,
        };
        match msg {
            // Phase 0 (§4.5): which channels the node holds, told only to
            // its own relays or swarm; anyone else gets an empty list. Only
            // as the first frame, as it was read only before the loop.
            cordelia_network::messages::WireMessage::SyncChannelListRequest(_) if first => {
                let channel_ids = if !(is_relay_peer || is_swarm_peer) {
                    Vec::new()
                } else {
                    let db = match state.db.lock() {
                        Ok(db) => db,
                        Err(_) => break,
                    };
                    channels_it_lists(&db, is_swarm_peer)
                };
                tracing::debug!(peer = %peer_id, channels = channel_ids.len(), "served channel list request");
                let resp = cordelia_network::messages::WireMessage::SyncChannelListResponse(
                    cordelia_network::messages::SyncChannelListResponse { channel_ids },
                );
                write_sync_answer(send, resp).await;
            }
            cordelia_network::messages::WireMessage::SyncRequest(current_req) => {
                fetch_channel = None;
                // Don't serve local-scope channel items to non-swarm peers
                // (§8.2.2), nor to any peer the items of a channel whose ID
                // may not be told to one: the answer is that it holds
                // nothing.
                let answers = {
                    let db = match state.db.lock() {
                        Ok(db) => db,
                        Err(_) => break,
                    };
                    answers_for(&db, &current_req.channel_id, is_swarm_peer)
                };
                if !answers {
                    tracing::debug!(peer = %peer_id, channel = %current_req.channel_id, "rejecting sync for a channel that is not served to this peer");
                    let resp = cordelia_network::messages::WireMessage::SyncResponse(
                        cordelia_network::messages::SyncResponse {
                            items: vec![],
                            has_more: false,
                            last_seq: None,
                        },
                    );
                    write_sync_answer(send, resp).await;
                    channels_served += 1;
                } else {
                    let (headers, has_more, last_seq) = {
                        let db = match state.db.lock() {
                            Ok(db) => db,
                            Err(_) => break,
                        };
                        let items = match current_req.after_seq {
                            Some(after) => cordelia_storage::items::query_sync_after(
                                &db,
                                &current_req.channel_id,
                                i64::try_from(after).unwrap_or(i64::MAX),
                                current_req.limit,
                            ),
                            None => cordelia_storage::items::query_sync(
                                &db,
                                &current_req.channel_id,
                                current_req.since.as_deref(),
                                current_req.limit,
                            ),
                        }
                        .unwrap_or_default();
                        let has_more = items.len() as u32 >= current_req.limit;
                        // Arrival paging: tell the peer where this page
                        // ended. With no items, echo its cursor so it keeps
                        // its place.
                        let last_seq = current_req.after_seq.map(|after| {
                            items.last().map(|i| i.seq.max(0) as u64).unwrap_or(after)
                        });
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
                                slot: si.slot.clone(),
                                rev: si.rev,
                            })
                            .collect();
                        (headers, has_more, last_seq)
                    };
                    let resp = cordelia_network::messages::WireMessage::SyncResponse(
                        cordelia_network::messages::SyncResponse {
                            items: headers,
                            has_more,
                            last_seq,
                        },
                    );
                    write_sync_answer(send, resp).await;
                    channels_served += 1;
                    tracing::debug!(peer = %peer_id, channel = %current_req.channel_id, "served sync request");
                    // A fetch may follow, for this channel.
                    fetch_channel = Some(current_req.channel_id);
                }
            }
            cordelia_network::messages::WireMessage::FetchRequest(mut freq) => {
                // A fetch is honoured only right after the channel it is
                // for was served.
                let Some(channel) = fetch_channel.take() else {
                    break;
                };
                freq.item_ids
                    .truncate(cordelia_core::protocol::MAX_BATCH_SIZE);
                // An answer is one message. If these items do not fit in
                // one, end the stream now: the peer learns at once, and
                // asks for fewer. (Reading them all first, only to find
                // that they cannot be sent, cost a megabyte a request.)
                let bytes = {
                    let db = match state.db.lock() {
                        Ok(db) => db,
                        Err(_) => break,
                    };
                    cordelia_storage::items::total_cost_by_ids(&db, &channel, &freq.item_ids)
                        .unwrap_or(0)
                };
                let room = u64::from(cordelia_core::protocol::MAX_MESSAGE_BYTES);
                if bytes > room {
                    tracing::debug!(peer = %peer_id, channel = %channel, asked = freq.item_ids.len(), bytes, "fetch does not fit in one message; ending the stream");
                    break;
                }
                // An answer over a small page, to a peer that is not a
                // relay listed by key, is loaded and written only under a
                // large permit (decision 2026-10-22 (memory), rules 2 and
                // 3), taken before the items are loaded: one for the
                // stream at a time, so the frame's own is used where the
                // stream holds one already. Where none comes within
                // STREAM_TIMEOUT, the stream is refused with
                // ERR_LARGE_MESSAGE_LATER, and no breach is counted.
                let small = bytes <= cordelia_core::protocol::SMALL_PAGE_BYTES as u64;
                if !small
                    && !listed
                    && permit.is_none()
                    && let Some(permits) = permits
                {
                    match permits.take(address).await {
                        Some(taken) => permit = Some(taken),
                        None => {
                            tracing::debug!(peer = %peer_id, channel = %channel, bytes, "a fetch answer over a small page, and no permit for now; refused");
                            refuse_large_later(send, recv);
                            break;
                        }
                    }
                }
                let fetch_items = {
                    let db = match state.db.lock() {
                        Ok(db) => db,
                        Err(_) => break,
                    };
                    cordelia_storage::items::get_items_by_ids(&db, &channel, &freq.item_ids)
                        .unwrap_or_default()
                        .into_iter()
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
                            slot: si.slot,
                            rev: si.rev,
                        })
                        .collect::<Vec<_>>()
                };
                let fetched = freq.item_ids.len();
                drop(freq);
                let fresp = cordelia_network::messages::WireMessage::FetchResponse(
                    cordelia_network::messages::FetchResponse { items: fetch_items },
                );
                write_sync_answer(send, fresp).await;
                tracing::debug!(peer = %peer_id, fetched, "served fetch request");
            }
            _ => break,
        }
        first = false;
        // The permit for this frame is let go before the next is read: one
        // for the stream at a time (rule 2).
        drop(permit);
    }
    tracing::debug!(peer = %peer_id, channels_served, "inbound sync stream complete");
}

/// Write one answer of the older kind's sync stream, encoded and the
/// message dropped before the write (decision 2026-10-22 (memory), rule
/// 4): through the write, which a peer that grants no credit can make wait
/// up to STREAM_TIMEOUT, the node holds the encoding alone, not the answer.
async fn write_sync_answer<W>(send: &mut W, answer: cordelia_network::messages::WireMessage)
where
    W: tokio::io::AsyncWrite + Unpin + cordelia_network::codec::GiveUp,
{
    let written = cordelia_network::codec::encode_message(&answer);
    drop(answer);
    if let Ok(written) = written {
        let _ = cordelia_network::codec::write_raw_frame(send, &written).await;
    }
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

/// Text that a peer chose, as it is safe to put in a warning: its first 64
/// characters, with control characters, the marks that change the
/// direction of text, and what cannot be seen and is no part of ordinary
/// writing, shown as escapes. A peer chooses what the text holds
/// and how long it is.
fn as_a_peer_sent_it(text: &str) -> String {
    const MOST: usize = 64;
    let start: String = text.chars().take(MOST).collect();
    crate::history_cmd::printable(&start)
}

/// Handle inbound ChannelAnnounce (0x04) stream.
/// Reads frames until EOF/error, dispatches ChannelJoined/ChannelLeft to governor.
///
/// A channel's ID is logged for debugging only. What a node logs as a
/// matter of course is how many channels a peer announced, not which.
async fn handle_inbound_channel_announce<R>(
    recv: &mut R,
    peer_id: &NodeId,
    gov_tx: &tokio::sync::mpsc::UnboundedSender<GovEvent>,
) where
    R: tokio::io::AsyncRead + Unpin,
{
    let (mut announced, mut withdrawn) = (0u64, 0u64);
    loop {
        // A channel announcement carries a descriptor of short fields, so
        // no honest frame is over a small message (rule 2): a longer one
        // is refused at its length.
        let msg = match cordelia_network::codec::read_small_frame(
            recv,
            cordelia_network::messages::Protocol::ChannelAnnounce,
        )
        .await
        {
            Ok(m) => m,
            Err(_) => break, // EOF or error -- stream done
        };
        match msg {
            cordelia_network::messages::WireMessage::ChannelJoined(joined) => {
                if let Err(e) =
                    cordelia_network::channel_announce::validate_descriptor(&joined.descriptor)
                {
                    // Both are what the peer sent, or hold it.
                    tracing::warn!(
                        peer = %peer_id,
                        channel = %as_a_peer_sent_it(&joined.channel_id),
                        error = %as_a_peer_sent_it(&e.to_string()),
                        "channel-announce: invalid descriptor"
                    );
                    continue;
                }
                tracing::debug!(
                    peer = %peer_id,
                    channel = %joined.channel_id,
                    "peer announced channel"
                );
                announced += 1;
                let _ = gov_tx.send(GovEvent::ChannelAnnounced(
                    peer_id.clone(),
                    joined.channel_id,
                ));
            }
            cordelia_network::messages::WireMessage::ChannelLeft(left) => {
                tracing::debug!(
                    peer = %peer_id,
                    channel = %left.channel_id,
                    "peer withdrew channel"
                );
                withdrawn += 1;
                let _ = gov_tx.send(GovEvent::ChannelWithdrawn(peer_id.clone(), left.channel_id));
            }
            _ => {
                tracing::debug!(peer = %peer_id, "channel-announce: unexpected message type");
                break;
            }
        }
    }
    if announced + withdrawn > 0 {
        tracing::info!(peer = %peer_id, announced, withdrawn, "peer announced channels");
    }
}

/// Send ChannelJoined announcements for all our subscribed channels.
/// Opens a 0x04 stream and sends one ChannelJoined per channel.
async fn send_channel_announcements(
    conn: &quinn::Connection,
    state: &web::Data<cordelia_api::state::AppState>,
) -> Result<(), String> {
    let channels = {
        let db = state.db.lock().map_err(|e| format!("db lock: {e}"))?;
        // Only network-scope channels (§8.2.2: local channels never leave
        // PAN), and only those whose IDs may be told to a peer.
        channels_to_announce(&db, &state.identity.public_key())
    };
    if channels.is_empty() {
        return Ok(());
    }

    let (mut send, _recv) = open_bi(conn).await?;

    // The protocol byte for ChannelAnnounce (0x04), through the codec, so
    // that it has the codec's timeout as every write does.
    cordelia_network::codec::write_protocol_byte(
        &mut send,
        cordelia_network::messages::Protocol::ChannelAnnounce,
    )
    .await
    .map_err(|e| format!("write protocol byte: {e}"))?;

    for channel_id in &channels {
        // The ID and nothing else: a relay is not told a channel's name.
        let descriptor =
            cordelia_network::channel_announce::announcement(&state.identity, channel_id);
        if let Err(e) = cordelia_network::channel_announce::send_channel_joined(
            &mut send,
            channel_id,
            &descriptor,
        )
        .await
        {
            tracing::debug!(channel = %channel_id, error = %e, "channel announce send failed");
            break;
        }
    }

    let _ = send.finish();
    tracing::debug!(channels = channels.len(), "sent channel announcements");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let mut governor = governor_for(role, &config, &[]);
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

    /// A frame on a push stream that is no push counts against what the
    /// peer may push, by its bytes, where the peer is limited: frames of
    /// bytes that are no message, and a message that is not a push. Over
    /// the allowance, the breach is returned. A push is read as it was.
    #[tokio::test]
    async fn test_a_frame_that_is_no_push_counts_against_the_push_allowance() {
        use cordelia_core::protocol::{PUSH_BYTES_PER_PEER_PER_MINUTE, entry_cost};
        use cordelia_network::codec::encode_message;
        use cordelia_network::messages::{PushAck, PushPayload, WireMessage};

        // A frame of `payload`, as it travels.
        fn framed(payload: &[u8]) -> Vec<u8> {
            [&(payload.len() as u32).to_be_bytes()[..], payload].concat()
        }
        // What `read_push` makes of `bytes` from a peer that is `limited`,
        // with no large-permit budget (the bytes here are read whatever
        // their size, as a listed relay's would be).
        async fn read(
            rates: &std::sync::Mutex<Rates>,
            limited: bool,
            bytes: Vec<u8>,
        ) -> PushRead<'static> {
            let peer = NodeId([9; 32]);
            let address: std::net::IpAddr = "203.0.113.9".parse().unwrap();
            let mut cursor = std::io::Cursor::new(bytes);
            read_push(&mut cursor, &peer, rates, limited, address, None, false).await
        }

        // Frames of 900,000 bytes that are no message: two are within the
        // allowance, and the third is over it.
        let garbage = framed(&vec![0x5a; 900_000]);
        assert!(2 * entry_cost(900_000) <= PUSH_BYTES_PER_PEER_PER_MINUTE);
        assert!(3 * entry_cost(900_000) > PUSH_BYTES_PER_PEER_PER_MINUTE);
        let rates = std::sync::Mutex::new(Rates::default());
        for _ in 0..2 {
            assert!(matches!(
                read(&rates, true, garbage.clone()).await,
                PushRead::Ended
            ));
        }
        assert!(matches!(
            read(&rates, true, garbage.clone()).await,
            PushRead::Over(_)
        ));

        // A message of the stream that is not a push counts the same.
        let ack = framed(&encode_message(&WireMessage::PushAck(PushAck::default())).unwrap());
        let rates = std::sync::Mutex::new(Rates::default());
        let mut over = None;
        for tries in 1..=2_100 {
            if let PushRead::Over(breach) = read(&rates, true, ack.clone()).await {
                over = Some((tries, breach));
                break;
            }
        }
        let (tries, _) = over.expect("answers sent as pushes were never over");
        assert_eq!(
            tries as u64,
            PUSH_BYTES_PER_PEER_PER_MINUTE / entry_cost(ack.len() - 4) + 1
        );

        // A peer that is not limited is not counted.
        let rates = std::sync::Mutex::new(Rates::default());
        for _ in 0..4 {
            assert!(matches!(
                read(&rates, false, garbage.clone()).await,
                PushRead::Ended
            ));
        }

        // A push is read as it was, and counts nothing here.
        let push = framed(
            &encode_message(&WireMessage::PushPayload(PushPayload { items: Vec::new() })).unwrap(),
        );
        let rates = std::sync::Mutex::new(Rates::default());
        for _ in 0..2 {
            assert!(!matches!(
                read(&rates, true, garbage.clone()).await,
                PushRead::Payload(..)
            ));
        }
        assert!(matches!(
            read(&rates, true, push).await,
            PushRead::Payload(..)
        ));
    }

    /// A relay passes items on to a peer in pushes of at most
    /// MAX_PUSHED_ITEMS, every item once and in its order: a push of more
    /// would be refused where it is read.
    #[test]
    fn test_a_relay_passes_items_on_in_pushes_of_at_most_the_bound() {
        use cordelia_core::protocol::MAX_PUSHED_ITEMS;
        let item = |n: usize| cordelia_network::messages::Item {
            item_id: format!("ci_{n}"),
            channel_id: "grp_x".into(),
            item_type: "memory".into(),
            encrypted_blob: Vec::new(),
            content_hash: vec![0; 32],
            content_length: 0,
            author_id: vec![0; 32],
            signature: vec![0; 64],
            key_version: 1,
            published_at: "2026-10-22T10:00:00Z".into(),
            is_tombstone: false,
            parent_id: None,
            slot: None,
            rev: None,
        };
        for (count, sizes) in [
            (0, vec![]),
            (1, vec![1]),
            (MAX_PUSHED_ITEMS, vec![MAX_PUSHED_ITEMS]),
            (MAX_PUSHED_ITEMS + 1, vec![MAX_PUSHED_ITEMS, 1]),
            (
                2 * MAX_PUSHED_ITEMS + 7,
                vec![MAX_PUSHED_ITEMS, MAX_PUSHED_ITEMS, 7],
            ),
        ] {
            let pushes = in_pushes((0..count).map(item).collect());
            assert_eq!(
                pushes.iter().map(Vec::len).collect::<Vec<_>>(),
                sizes,
                "{count}"
            );
            let ids: Vec<String> = pushes.into_iter().flatten().map(|i| i.item_id).collect();
            assert_eq!(
                ids,
                (0..count).map(|n| format!("ci_{n}")).collect::<Vec<_>>()
            );
        }
    }

    /// What this thread holds (`crate::counting`).
    use crate::counting;

    /// A node's state over a database in memory, with no network.
    fn a_state() -> web::Data<cordelia_api::state::AppState> {
        web::Data::new(cordelia_api::state::AppState {
            db: std::sync::Mutex::new(cordelia_storage::db::open_in_memory().unwrap()),
            identity: cordelia_crypto::identity::NodeIdentity::generate().unwrap(),
            bearer_token: "t".into(),
            home_dir: std::env::temp_dir().join("cordelia-p2p-test-no-such-directory"),
            started_at: std::time::Instant::now(),
            sync_errors: Default::default(),
            peers_hot: Default::default(),
            peers_warm: Default::default(),
            push_tx: None,
            announce_tx: None,
            peers: Default::default(),
            relays: Default::default(),
            outbox_refused: Default::default(),
            relist: Default::default(),
            sync_control: Default::default(),
            own_channels: Default::default(),
            held: Default::default(),
            history: Default::default(),
        })
    }

    /// A request for items that a peer sent on a sync of the older kind is
    /// answered and dropped before the node writes the answer: while it
    /// waits for the peer's next request, up to STREAM_TIMEOUT, it holds
    /// nothing of the request. One of a hundred IDs of some 9 KB each is
    /// near a megabyte.
    #[tokio::test]
    async fn test_a_fetch_request_is_not_held_while_the_node_waits() {
        use cordelia_network::codec::{encode_message, read_raw_frame, write_raw_frame};
        use cordelia_network::messages::{FetchRequest, SyncRequest, WireMessage};

        let state = a_state();
        let peer = NodeId([7; 32]);
        // A pipe each way, small, so that what a pipe keeps for itself is
        // small.
        let (mut node_w, mut client_r) = tokio::io::duplex(8 * 1024);
        let (mut client_w, mut node_r) = tokio::io::duplex(8 * 1024);
        // Each request, encoded before anything is counted.
        let sync = encode_message(&WireMessage::SyncRequest(SyncRequest {
            channel_id: "grp_00000000-0000-4000-8000-000000000000".into(),
            since: None,
            limit: 100,
            after_seq: None,
        }))
        .unwrap();
        let small = encode_message(&WireMessage::FetchRequest(FetchRequest {
            item_ids: vec!["ci_a".into()],
        }))
        .unwrap();
        let large = encode_message(&WireMessage::FetchRequest(FetchRequest {
            item_ids: vec!["x".repeat(9_000); 100],
        }))
        .unwrap();
        assert!(large.len() > 900_000, "{}", large.len());

        // No large-permit budget here: this test is of what the node
        // holds across a wait, not of the permits. The large fetch is read
        // as a listed relay's would be.
        let address: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let node = handle_inbound_sync(
            &mut node_w,
            &mut node_r,
            &peer,
            &state,
            true,
            false,
            None,
            address,
            false,
        );
        tokio::pin!(node);
        let client = async {
            // A channel and a small fetch first: whatever the node keeps
            // from then on, such as its prepared statements, is in the
            // count it is measured from.
            write_raw_frame(&mut client_w, &sync).await.unwrap();
            let _ = read_raw_frame(&mut client_r).await.unwrap();
            write_raw_frame(&mut client_w, &small).await.unwrap();
            let _ = read_raw_frame(&mut client_r).await.unwrap();
            let before = counting::live();
            // The next channel, and a fetch near a megabyte. Once its
            // answer is read, the node waits for the next request.
            write_raw_frame(&mut client_w, &sync).await.unwrap();
            let _ = read_raw_frame(&mut client_r).await.unwrap();
            write_raw_frame(&mut client_w, &large).await.unwrap();
            let _ = read_raw_frame(&mut client_r).await.unwrap();
            counting::live() - before
        };
        // Both on this thread, polled in turn: the node is waiting on its
        // read when the client measures.
        let held = tokio::select! {
            _ = &mut node => panic!("the node ended the stream"),
            held = client => held,
        };
        println!("held while the node waits: {held} bytes");
        assert!(
            held < 64 * 1024,
            "the node holds {held} bytes more while it waits for the next request"
        );
    }

    /// What a relay holds while it fetches the entries of a page from a
    /// peer that is not hot is what it took out of the page, and not the
    /// page: while the peer keeps it waiting for the entries, up to
    /// STREAM_TIMEOUT_SECS on the length and as long again on the rest, it
    /// holds at most the IDs to fetch, MAX_FETCH_ITEMS of at most
    /// MAX_ITEM_ID_LEN bytes each (8,800 bytes), and 4 KiB for what else a
    /// pass keeps. A page of a hundred headers at their bounds holds some
    /// 76 KB once read; before the bounds of a header's fields, a page of
    /// about a megabyte held 1.7 MB.
    #[tokio::test]
    async fn test_a_page_is_not_held_while_its_entries_are_fetched() {
        use cordelia_core::protocol::{
            DEFAULT_SYNC_LIMIT, MAX_FETCH_ITEMS, MAX_ITEM_ID_LEN, MAX_ITEM_TYPE_LEN,
            MAX_TIMESTAMP_LEN,
        };
        use cordelia_network::codec::{encode_message, read_raw_frame, write_raw_frame};
        use cordelia_network::messages::{
            FetchResponse, ItemHeader, SyncChannelListResponse, SyncResponse, WireMessage,
        };
        use tokio::io::AsyncReadExt;

        const HOLDS_MOST: isize = (MAX_FETCH_ITEMS
            * (std::mem::size_of::<String>() + MAX_ITEM_ID_LEN)
            + 4 * 1024) as isize;

        let channels = [
            "grp_00000000-0000-4000-8000-00000000000a",
            "grp_00000000-0000-4000-8000-00000000000b",
        ];
        // A page of a channel: the most headers, each at its bounds, and
        // each of an entry the relay does not hold.
        let page_of = |channel: &str, n: u8| {
            let headers = (0..DEFAULT_SYNC_LIMIT)
                .map(|i| ItemHeader {
                    item_id: format!("{n}{i:0>63}"),
                    channel_id: channel.to_string(),
                    item_type: "t".repeat(MAX_ITEM_TYPE_LEN),
                    content_hash: vec![0xa1; 32],
                    author_id: vec![0xa2; 32],
                    signature: vec![0xa3; 64],
                    key_version: 1,
                    published_at: "p".repeat(MAX_TIMESTAMP_LEN),
                    is_tombstone: false,
                    parent_id: Some("q".repeat(MAX_ITEM_ID_LEN)),
                    slot: Some(vec![0xa4; 32]),
                    rev: Some(1),
                })
                .collect();
            encode_message(&WireMessage::SyncResponse(SyncResponse {
                items: headers,
                has_more: true,
                last_seq: Some(100),
            }))
            .unwrap()
        };
        // Each answer, encoded before anything is counted.
        let listed = encode_message(&WireMessage::SyncChannelListResponse(
            SyncChannelListResponse {
                channel_ids: channels.iter().map(|c| c.to_string()).collect(),
            },
        ))
        .unwrap();
        let pages: Vec<(String, Vec<u8>)> = channels
            .iter()
            .enumerate()
            .map(|(n, c)| (c.to_string(), page_of(c, n as u8)))
            .collect();
        let nothing =
            encode_message(&WireMessage::FetchResponse(FetchResponse { items: vec![] })).unwrap();

        let (repush_tx, _repush_rx) = tokio::sync::mpsc::unbounded_channel();
        let from = FetchFrom {
            target: NodeId([9; 32]),
            state: a_state(),
            role: "relay".into(),
            channels: Vec::new(),
            ask_what_it_holds: true,
            limited: true,
            address: std::net::IpAddr::from([192, 0, 2, 9]),
            rates: std::sync::Arc::new(std::sync::Mutex::new(Rates::new(u64::MAX))),
            kept: Default::default(),
            repush_tx,
            seen_table: Default::default(),
            permits: None,
            listed_by_key: false,
        };
        // A pipe each way, small, so that what a pipe keeps for itself is
        // small.
        let (mut node_w, mut peer_r) = tokio::io::duplex(8 * 1024);
        let (mut peer_w, mut node_r) = tokio::io::duplex(8 * 1024);
        let node = fetch_on(&mut node_w, &mut node_r, from);
        tokio::pin!(node);
        let peer = async {
            // The channels it holds, asked for on a stream of item sync.
            assert_eq!(peer_r.read_u8().await.unwrap(), 0x05);
            let _ = read_raw_frame(&mut peer_r).await.unwrap();
            write_raw_frame(&mut peer_w, &listed).await.unwrap();
            // The relay asks for a page of each, in an order of its own.
            // The first, and its fetch, answered with nothing: whatever the
            // relay keeps from then on is in the count it is measured from.
            let page_for = |asked: &[u8]| {
                pages
                    .iter()
                    .find(|(channel, _)| {
                        asked
                            .windows(channel.len())
                            .any(|w| w == channel.as_bytes())
                    })
                    .map(|(_, page)| page.clone())
                    .unwrap()
            };
            let asked = read_raw_frame(&mut peer_r).await.unwrap();
            write_raw_frame(&mut peer_w, &page_for(&asked))
                .await
                .unwrap();
            let _ = read_raw_frame(&mut peer_r).await.unwrap();
            write_raw_frame(&mut peer_w, &nothing).await.unwrap();
            // The second: its page, and then the relay's fetch of its
            // entries, which is not answered.
            let asked = read_raw_frame(&mut peer_r).await.unwrap();
            let page = page_for(&asked);
            let before = counting::live();
            write_raw_frame(&mut peer_w, &page).await.unwrap();
            let fetch = read_raw_frame(&mut peer_r).await.unwrap();
            let held = counting::live() - before - fetch.capacity() as isize;
            (held, fetch.len())
        };
        // Both on this thread, polled in turn: the relay is waiting for the
        // entries when the peer measures.
        let (held, fetch) = tokio::select! {
            ended = &mut node => panic!("the fetch ended: {ended:?}"),
            measured = peer => measured,
        };
        println!("held while the relay waits for the entries: {held} bytes (a fetch of {fetch})");
        assert!(fetch > 6_000, "the fetch asked for too few: {fetch} bytes");
        assert!(
            held <= HOLDS_MOST,
            "the relay holds {held} bytes more while it waits for the entries"
        );
    }

    /// A relay's fetch from a peer lets each channel's ID go once it has
    /// gone through the channel, and does not hold every ID the peer
    /// listed to the end of the pass, through every wait on the peer. A
    /// peer lists 200 channels of the longest ID, MAX_CHANNEL_ID_LEN bytes,
    /// and answers each with an empty page: by the last, the relay holds
    /// at least 199 IDs' bytes less than at the first, less 4 KiB for what
    /// else a pass keeps.
    #[tokio::test]
    async fn test_each_channel_is_let_go_once_it_has_been_gone_through() {
        use cordelia_core::protocol::MAX_CHANNEL_ID_LEN;
        use cordelia_network::codec::{encode_message, read_raw_frame, write_raw_frame};
        use cordelia_network::messages::{SyncChannelListResponse, SyncResponse, WireMessage};
        use tokio::io::AsyncReadExt;

        const CHANNELS: usize = 200;
        let ids: Vec<String> = (0..CHANNELS)
            .map(|n| format!("grp_{n:0>width$}", width = MAX_CHANNEL_ID_LEN - 4))
            .collect();
        assert!(ids.iter().all(|id| id.len() == MAX_CHANNEL_ID_LEN));
        let listed = encode_message(&WireMessage::SyncChannelListResponse(
            SyncChannelListResponse {
                channel_ids: ids.clone(),
            },
        ))
        .unwrap();
        let empty = encode_message(&WireMessage::SyncResponse(SyncResponse {
            items: vec![],
            has_more: false,
            last_seq: Some(0),
        }))
        .unwrap();

        let (repush_tx, _repush_rx) = tokio::sync::mpsc::unbounded_channel();
        let from = FetchFrom {
            target: NodeId([9; 32]),
            state: a_state(),
            role: "relay".into(),
            channels: Vec::new(),
            ask_what_it_holds: true,
            limited: true,
            address: std::net::IpAddr::from([192, 0, 2, 9]),
            rates: std::sync::Arc::new(std::sync::Mutex::new(Rates::new(u64::MAX))),
            kept: Default::default(),
            repush_tx,
            seen_table: Default::default(),
            permits: None,
            listed_by_key: false,
        };
        let (mut node_w, mut peer_r) = tokio::io::duplex(8 * 1024);
        let (mut peer_w, mut node_r) = tokio::io::duplex(8 * 1024);
        let node = fetch_on(&mut node_w, &mut node_r, from);
        tokio::pin!(node);
        let peer = async {
            assert_eq!(peer_r.read_u8().await.unwrap(), 0x05);
            let _ = read_raw_frame(&mut peer_r).await.unwrap();
            write_raw_frame(&mut peer_w, &listed).await.unwrap();
            // The relay waits for the first page, and then for each.
            let _ = read_raw_frame(&mut peer_r).await.unwrap();
            let first = counting::live();
            write_raw_frame(&mut peer_w, &empty).await.unwrap();
            for _ in 1..CHANNELS - 1 {
                let _ = read_raw_frame(&mut peer_r).await.unwrap();
                write_raw_frame(&mut peer_w, &empty).await.unwrap();
            }
            // The last channel asked for: the relay waits for its page.
            let _ = read_raw_frame(&mut peer_r).await.unwrap();
            counting::live() - first
        };
        let held = tokio::select! {
            ended = &mut node => panic!("the fetch ended: {ended:?}"),
            held = peer => held,
        };
        let let_go = ((CHANNELS - 1) * MAX_CHANNEL_ID_LEN) as isize;
        println!("held at the last channel over the first: {held} bytes");
        assert!(
            held <= -let_go + 4 * 1024,
            "the relay holds {held} bytes more at the last channel than at the first"
        );
    }

    // ── The relay's own fetch (decision 2026-10-22 (memory), rule 6) ──

    /// A relay's fetch from a peer at 192.0.2.9, which it asks which
    /// channels it holds.
    fn a_relays_fetch(
        permits: &std::sync::Arc<LargePermits>,
        limited: bool,
        listed_by_key: bool,
    ) -> FetchFrom {
        let (repush_tx, _repush_rx) = tokio::sync::mpsc::unbounded_channel();
        FetchFrom {
            target: NodeId([9; 32]),
            state: a_state(),
            role: "relay".into(),
            channels: Vec::new(),
            ask_what_it_holds: true,
            limited,
            address: std::net::IpAddr::from([192, 0, 2, 9]),
            rates: std::sync::Arc::new(std::sync::Mutex::new(Rates::new(u64::MAX))),
            kept: Default::default(),
            repush_tx,
            seen_table: Default::default(),
            permits: Some(permits.clone()),
            listed_by_key,
        }
    }

    /// Every large permit, each held from a /24 of its own, none the
    /// fetched peer's.
    fn every_permit_held(permits: &LargePermits) -> Vec<LargePermit<'_>> {
        (0..cordelia_core::protocol::LARGE_MESSAGES_AT_ONCE)
            .map(|n| {
                futures_lite_block(permits.take(std::net::IpAddr::from([10, n as u8, 0, 1])))
                    .expect("a permit free")
            })
            .collect()
    }

    /// What a peer saw of a relay's fetch from it.
    struct Asked {
        /// How the fetch ended.
        fetched: Fetched,
        /// How long it took, on the test's clock.
        took: std::time::Duration,
        /// The channels it asked a page of, in order.
        pages: Vec<String>,
        /// How many IDs each of its fetches asked for, in order.
        fetches: Vec<usize>,
    }

    /// 100 headers of small entries of `channel`, each of an entry the
    /// relay does not hold.
    fn small_headers(channel: &str) -> Vec<cordelia_network::messages::ItemHeader> {
        (0..100)
            .map(|i| cordelia_network::messages::ItemHeader {
                item_id: format!("ci_{i:0>60}"),
                channel_id: channel.to_string(),
                item_type: "memory".into(),
                content_hash: vec![0xa1; 32],
                author_id: vec![0xa2; 32],
                signature: vec![0xa3; 64],
                key_version: 1,
                published_at: "2026-10-22T00:00:00Z".into(),
                is_tombstone: false,
                parent_id: None,
                slot: None,
                rev: None,
            })
            .collect()
    }

    /// `encoded`, a message (a map of its name and its fields), with one
    /// field more that no reader reads, so that it is `to` bytes long and
    /// still decodes as the message it was.
    fn padded(mut encoded: Vec<u8>, to: usize) -> Vec<u8> {
        // A map of fewer than 23 pairs says how many in its first byte.
        assert!((0xa1..0xb7).contains(&encoded[0]));
        encoded[0] += 1;
        encoded.push(0x67);
        encoded.extend(b"padding");
        let room = to - encoded.len() - 5;
        encoded.push(0x5a);
        encoded.extend((room as u32).to_be_bytes());
        encoded.extend(std::iter::repeat_n(0x70, room));
        assert_eq!(encoded.len(), to);
        encoded
    }

    /// Run `from` against a peer that answers it: with `listed` for the
    /// channel list, a page of 100 small headers for the first channel
    /// asked about and an empty page for every other, and an empty answer
    /// to each fetch. Each answer is within a small message, but for a list
    /// that is not; with `pad`, each page and each fetch's answer is padded
    /// to that many bytes.
    async fn a_peer_answers(from: FetchFrom, listed: &[String], pad: Option<usize>) -> Asked {
        use cordelia_network::codec::{encode_message, read_frame, write_raw_frame};
        use cordelia_network::messages::{
            FetchResponse, Protocol, SyncChannelListResponse, SyncResponse, WireMessage,
        };
        use tokio::io::AsyncReadExt;

        let (mut node_w, mut peer_r) = tokio::io::duplex(8 * 1024);
        let (mut peer_w, mut node_r) = tokio::io::duplex(8 * 1024);
        let start = tokio::time::Instant::now();
        let node = fetch_on(&mut node_w, &mut node_r, from);
        tokio::pin!(node);
        let pages = std::cell::RefCell::new(Vec::<String>::new());
        let fetches = std::cell::RefCell::new(Vec::<usize>::new());
        let peer = async {
            assert_eq!(peer_r.read_u8().await.unwrap(), 0x05);
            loop {
                let answer = match read_frame(&mut peer_r, Protocol::ItemSync).await {
                    Ok(WireMessage::SyncChannelListRequest(_)) => {
                        WireMessage::SyncChannelListResponse(SyncChannelListResponse {
                            channel_ids: listed.to_vec(),
                        })
                    }
                    Ok(WireMessage::SyncRequest(asked)) => {
                        let first = pages.borrow().is_empty();
                        pages.borrow_mut().push(asked.channel_id.clone());
                        let items = if first {
                            small_headers(&asked.channel_id)
                        } else {
                            Vec::new()
                        };
                        WireMessage::SyncResponse(SyncResponse {
                            items,
                            has_more: false,
                            last_seq: Some(100),
                        })
                    }
                    Ok(WireMessage::FetchRequest(asked)) => {
                        fetches.borrow_mut().push(asked.item_ids.len());
                        WireMessage::FetchResponse(FetchResponse { items: vec![] })
                    }
                    other => panic!("the relay asked what a fetch does not: {other:?}"),
                };
                let padding =
                    pad.filter(|_| !matches!(answer, WireMessage::SyncChannelListResponse(_)));
                let mut answer = encode_message(&answer).unwrap();
                if let Some(to) = padding {
                    answer = padded(answer, to);
                }
                write_raw_frame(&mut peer_w, &answer).await.unwrap();
            }
        };
        let fetched = tokio::select! {
            ended = &mut node => ended.0,
            () = peer => unreachable!("the peer answers until the fetch ends"),
        };
        Asked {
            fetched,
            took: start.elapsed(),
            pages: pages.into_inner(),
            fetches: fetches.into_inner(),
        }
    }

    /// An answer within a small message is read at once, with every large
    /// permit held (decision 2026-10-22 (memory), rule 6): the fetch reads
    /// its answers by their length, and a list, a page of 100 headers and
    /// a fetch's answer each fit a small message.
    #[tokio::test(start_paused = true)]
    async fn a_fetch_reads_an_answer_within_a_small_message_with_every_permit_held() {
        let permits = std::sync::Arc::new(LargePermits::new(
            cordelia_core::protocol::LARGE_MESSAGES_AT_ONCE,
        ));
        let _held = every_permit_held(&permits);
        let channel = "grp_00000000-0000-4000-8000-00000000000a".to_string();
        let asked = a_peer_answers(a_relays_fetch(&permits, true, false), &[channel], None).await;
        assert_eq!(
            asked.fetched,
            Fetched::All,
            "the fetch did not read its answers"
        );
        assert!(
            asked.took < cordelia_network::codec::STREAM_TIMEOUT,
            "the fetch waited {:?} for answers within a small message",
            asked.took
        );
    }

    /// The fetch asks as it did before rule 6: up to 100 headers a page,
    /// and the entries of a page in one fetch, not one entry a request
    /// (decision 2026-10-22 (memory), rule 6). A header carries no size, so
    /// a request cannot be fitted to the sizes of what it asks; read by its
    /// length, a fetch of small entries stays one small message.
    #[tokio::test(start_paused = true)]
    async fn a_page_of_100_headers_is_fetched_in_one_request() {
        let permits = std::sync::Arc::new(LargePermits::new(
            cordelia_core::protocol::LARGE_MESSAGES_AT_ONCE,
        ));
        let channel = "grp_00000000-0000-4000-8000-00000000000a".to_string();
        let asked = a_peer_answers(a_relays_fetch(&permits, true, false), &[channel], None).await;
        assert_eq!(asked.fetched, Fetched::All);
        assert_eq!(
            asked.fetches,
            vec![100],
            "a page of 100 headers was not fetched in one request of 100"
        );
    }

    /// Where a stand-in peer sends an answer longer than a small message.
    #[derive(Clone, Copy, PartialEq)]
    enum LongAt {
        /// The channel list.
        List,
        /// The first page.
        Page,
        /// The answer to the first page's fetch.
        Fetch,
    }

    /// What a relay's fetch did when a peer that is not a relay listed by
    /// key sent a frame of a small message and one byte `at` one of its
    /// answers, with every large permit held.
    struct NoPermit {
        fetched: Fetched,
        took: std::time::Duration,
        /// What the relay's thread held more while the peer had sent the
        /// length and as much of the rest as its pipe takes.
        held: isize,
        /// The code each end of the relay's stream was refused with.
        send_refused: Option<u64>,
        recv_refused: Option<u64>,
    }

    async fn a_long_answer_with_every_permit_held(at: LongAt) -> NoPermit {
        use cordelia_core::protocol::SMALL_MESSAGE_BYTES;
        use cordelia_network::codec::{encode_message, read_raw_frame, write_raw_frame};
        use cordelia_network::messages::{SyncChannelListResponse, SyncResponse, WireMessage};
        use tokio::io::AsyncReadExt;

        let permits = std::sync::Arc::new(LargePermits::new(
            cordelia_core::protocol::LARGE_MESSAGES_AT_ONCE,
        ));
        let _held = every_permit_held(&permits);
        let channel = "grp_00000000-0000-4000-8000-00000000000a";
        // Each answer made before anything is counted: the list and the
        // page small, and the long frame of a small message and one byte.
        let list = encode_message(&WireMessage::SyncChannelListResponse(
            SyncChannelListResponse {
                channel_ids: vec![channel.to_string()],
            },
        ))
        .unwrap();
        let page = encode_message(&WireMessage::SyncResponse(SyncResponse {
            items: small_headers(channel),
            has_more: false,
            last_seq: Some(100),
        }))
        .unwrap();
        let long = vec![0x5a; SMALL_MESSAGE_BYTES as usize + 1];

        let (node_w, mut peer_r) = tokio::io::duplex(8 * 1024);
        let (mut peer_w, node_r) = tokio::io::duplex(8 * 1024);
        let (mut node_w, mut node_r) = (Refusable::new(node_w), Refusable::new(node_r));
        let start = tokio::time::Instant::now();
        let node = fetch_on(
            &mut node_w,
            &mut node_r,
            a_relays_fetch(&permits, true, false),
        );
        let peer = async {
            assert_eq!(peer_r.read_u8().await.unwrap(), 0x05);
            // The list asked for.
            let _ = read_raw_frame(&mut peer_r).await.unwrap();
            if at != LongAt::List {
                write_raw_frame(&mut peer_w, &list).await.unwrap();
                // The page asked for.
                let _ = read_raw_frame(&mut peer_r).await.unwrap();
                if at != LongAt::Page {
                    write_raw_frame(&mut peer_w, &page).await.unwrap();
                    // The fetch of its entries.
                    let _ = read_raw_frame(&mut peer_r).await.unwrap();
                }
            }
            let before = counting::live();
            // The length, and as much of the rest as the pipe takes: the
            // relay has read the length and is waiting for a permit.
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                write_raw_frame(&mut peer_w, &long),
            )
            .await;
            counting::live() - before
        };
        // Both on this thread, polled in turn.
        let ((fetched, _), held) = tokio::join!(node, peer);
        NoPermit {
            fetched,
            took: start.elapsed(),
            held,
            send_refused: node_w.refused,
            recv_refused: node_r.refused,
        }
    }

    /// An answer longer than a small message, from a peer that is not a
    /// relay listed by key, waits unread for a large permit (decision
    /// 2026-10-22 (memory), rules 2 and 6): with every permit held, the
    /// fetch reads its length and nothing of its body, so nothing of the
    /// frame's size is allocated while it waits. After STREAM_TIMEOUT the
    /// stream is refused with ERR_LARGE_MESSAGE_LATER at both ends, as rule
    /// 2 refuses a request, and the fetch fails: the peer is asked again as
    /// after any failed fetch, a rate window later.
    fn fails_without_a_permit(what: &str, ended: NoPermit) {
        use cordelia_core::protocol::{ERR_LARGE_MESSAGE_LATER, RATE_WINDOW_SECS};
        use cordelia_network::codec::STREAM_TIMEOUT;
        let NoPermit {
            fetched,
            took,
            held,
            send_refused,
            recv_refused,
        } = ended;
        println!("held while the relay waits for a permit for {what}: {held} bytes");
        assert!(
            held < 32 * 1024,
            "the relay holds {held} bytes of {what} it has no permit for"
        );
        assert_eq!(
            fetched,
            Fetched::Failed,
            "a fetch with no permit for {what} did not fail"
        );
        assert!(
            took >= STREAM_TIMEOUT,
            "the fetch gave up after {took:?}, before STREAM_TIMEOUT"
        );
        let later = Some(u64::from(ERR_LARGE_MESSAGE_LATER));
        assert_eq!(
            (send_refused, recv_refused),
            (later, later),
            "the stream was not refused with ERR_LARGE_MESSAGE_LATER for {what}"
        );
        let now = std::time::Instant::now();
        assert_eq!(
            next_ask(fetched, std::time::Duration::from_secs(600), now),
            Some(now + std::time::Duration::from_secs(RATE_WINDOW_SECS)),
            "the peer is not asked again as after a failed fetch"
        );
    }

    /// A channel list longer than a small message, with no permit for it
    /// (see [`fails_without_a_permit`]).
    #[tokio::test(start_paused = true)]
    async fn a_long_answer_waits_unread_for_a_permit_and_the_fetch_fails_without_one() {
        let ended = a_long_answer_with_every_permit_held(LongAt::List).await;
        fails_without_a_permit("a channel list", ended);
    }

    /// A page longer than a small message, with no permit for it (see
    /// [`fails_without_a_permit`]).
    #[tokio::test(start_paused = true)]
    async fn a_long_page_waits_unread_for_a_permit_and_the_fetch_fails_without_one() {
        let ended = a_long_answer_with_every_permit_held(LongAt::Page).await;
        fails_without_a_permit("a page", ended);
    }

    /// The answer to a fetch longer than a small message, with no permit
    /// for it (see [`fails_without_a_permit`]).
    #[tokio::test(start_paused = true)]
    async fn a_long_fetch_answer_waits_unread_for_a_permit_and_the_fetch_fails_without_one() {
        let ended = a_long_answer_with_every_permit_held(LongAt::Fetch).await;
        fails_without_a_permit("a fetch's answer", ended);
    }

    /// A page's permit is let go before its entries are fetched (decision
    /// 2026-10-22 (memory), rule 6: one for the stream at a time). From a
    /// relay configured by address alone, which is not `limited` and is
    /// not listed by key, a page of 100 real headers and the answer to its
    /// fetch are each longer than a small message, and each takes the
    /// permit of the peer's /24: had the page's been held through the
    /// fetch, the answer would wait on it and the fetch would fail.
    #[tokio::test(start_paused = true)]
    async fn a_pages_permit_is_let_go_before_its_entries_are_fetched() {
        use cordelia_core::protocol::{LARGE_MESSAGES_AT_ONCE, SMALL_MESSAGE_BYTES};
        let permits = std::sync::Arc::new(LargePermits::new(LARGE_MESSAGES_AT_ONCE));
        let channel = "grp_00000000-0000-4000-8000-00000000000a".to_string();
        let long = SMALL_MESSAGE_BYTES as usize + 1024;
        let asked = a_peer_answers(
            a_relays_fetch(&permits, false, false),
            &[channel],
            Some(long),
        )
        .await;
        assert_eq!(
            asked.fetched,
            Fetched::All,
            "a long fetch answer after a long page did not get the /24's permit"
        );
        assert!(
            asked.took < cordelia_network::codec::STREAM_TIMEOUT,
            "the fetch waited {:?}",
            asked.took
        );
        assert_eq!(
            asked.fetches,
            vec![100],
            "the page's entries were not fetched"
        );
    }

    /// The channel IDs a peer lists, each of the longest length: 1,600 of
    /// them, which with their lengths are longer than a small message.
    fn a_long_list() -> Vec<String> {
        use cordelia_core::protocol::{MAX_CHANNEL_ID_LEN, SMALL_MESSAGE_BYTES};
        use cordelia_network::messages::{SyncChannelListResponse, WireMessage};
        let ids: Vec<String> = (0..1600)
            .map(|n| format!("grp_{n:0>width$}", width = MAX_CHANNEL_ID_LEN - 4))
            .collect();
        let encoded = cordelia_network::codec::encode_message(
            &WireMessage::SyncChannelListResponse(SyncChannelListResponse {
                channel_ids: ids.clone(),
            }),
        )
        .unwrap();
        assert!(encoded.len() > SMALL_MESSAGE_BYTES as usize);
        ids
    }

    /// An honest peer lists every channel it holds, which can be longer
    /// than a small message (decision 2026-10-22 (memory), rule 6): with a
    /// permit free, the list is read under it, MAX_CHANNELS_ASKED_OF_A_PEER
    /// of its IDs are kept and asked about, each once, and the permit is
    /// given back. Which of them are kept is a set's order, so a peer
    /// listing more is asked about a different part of them each time
    /// (`channels_to_ask`): the record's "its first are kept" is any of the
    /// list's first MAX_LISTED_CHANNEL_IDS, which bound it where it is read.
    #[tokio::test(start_paused = true)]
    async fn a_long_channel_list_is_read_under_a_permit_and_the_channels_asked_of_a_peer_are_kept_a_different_part_each_time()
     {
        use cordelia_core::protocol::{LARGE_MESSAGES_AT_ONCE, MAX_CHANNELS_ASKED_OF_A_PEER};
        let permits = std::sync::Arc::new(LargePermits::new(LARGE_MESSAGES_AT_ONCE));
        let listed = a_long_list();
        let asked = a_peer_answers(a_relays_fetch(&permits, true, false), &listed, None).await;
        let again = a_peer_answers(a_relays_fetch(&permits, true, false), &listed, None).await;
        let kept = |asked: &Asked| {
            asked
                .pages
                .iter()
                .cloned()
                .collect::<std::collections::HashSet<_>>()
        };
        assert_ne!(
            kept(&asked),
            kept(&again),
            "the same channels were kept of a long list twice"
        );
        assert_eq!(asked.fetched, Fetched::All, "the long list was not read");
        let distinct: std::collections::HashSet<&String> = asked.pages.iter().collect();
        assert_eq!(
            asked.pages.len(),
            MAX_CHANNELS_ASKED_OF_A_PEER,
            "the relay asked about {} of the {} channels listed",
            asked.pages.len(),
            listed.len()
        );
        assert_eq!(distinct.len(), asked.pages.len(), "a channel asked twice");
        assert!(asked.pages.iter().all(|asked| listed.contains(asked)));
        // Every permit is free again: the list's was let go.
        let all: Vec<_> = (0..LARGE_MESSAGES_AT_ONCE)
            .map(|n| std::net::IpAddr::from([10, n as u8, 0, 1]))
            .collect();
        for address in all {
            assert!(
                permits.take(address).await.is_some(),
                "the list's permit was not given back"
            );
        }
    }

    /// A relay listed by key is outside rule 6 (rule 7): its list longer
    /// than a small message is read at once with every permit held, and
    /// every channel in it is asked about.
    #[tokio::test(start_paused = true)]
    async fn a_relay_listed_by_key_has_its_long_list_read_with_every_permit_held() {
        let permits = std::sync::Arc::new(LargePermits::new(
            cordelia_core::protocol::LARGE_MESSAGES_AT_ONCE,
        ));
        let _held = every_permit_held(&permits);
        let listed = a_long_list();
        let asked = a_peer_answers(a_relays_fetch(&permits, false, true), &listed, None).await;
        assert_eq!(
            asked.fetched,
            Fetched::All,
            "a listed relay's long list waited for a permit"
        );
        assert!(asked.took < cordelia_network::codec::STREAM_TIMEOUT);
        assert_eq!(asked.pages.len(), listed.len());
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
        let rates = std::sync::Arc::new(std::sync::Mutex::new(Rates::default()));

        let np = permits.clone();
        let nr = rates.clone();
        let node = tokio::spawn(async move {
            let mut node_r = node_r;
            // An unlisted peer (listed = false), with the budget full.
            matches!(
                read_push(
                    &mut node_r,
                    &NodeId([9; 32]),
                    &nr,
                    true,
                    "198.51.100.1".parse().unwrap(),
                    Some(&np),
                    false,
                )
                .await,
                PushRead::Ended | PushRead::Over(_)
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
        assert!(read_body, "the frame was read, but not as a push");
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
        let rates = std::sync::Arc::new(std::sync::Mutex::new(Rates::default()));
        let np = permits.clone();
        let nr = rates.clone();
        let node = tokio::spawn(async move {
            let mut node_r = node_r;
            // Listed by key (rule 7): read at once.
            read_push(
                &mut node_r,
                &NodeId([9; 32]),
                &nr,
                true,
                "198.51.100.1".parse().unwrap(),
                Some(&np),
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

    /// A frame longer than a small message, for which no permit comes
    /// within STREAM_TIMEOUT, is refused with ERR_LARGE_MESSAGE_LATER and
    /// counts no breach (decision 2026-10-22 (memory), rule 2): the node
    /// stops its receive side with 0x05, which the peer sees, and the
    /// peer's push allowance is untouched. (This waits out the stream
    /// timeout, about ten seconds.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_large_frame_with_no_permit_is_refused_later_and_counts_no_breach() {
        use cordelia_network::codec::{write_protocol_byte, write_raw_frame};
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
                let (repush_tx, _r) = tokio::sync::mpsc::unbounded_channel();
                let (delivery_tx, _d) = tokio::sync::mpsc::unbounded_channel();
                let seen_table = std::sync::Arc::new(std::sync::RwLock::new(
                    cordelia_network::seen_table::SeenTable::default(),
                ));
                let over = handle_inbound_push(
                    &mut send,
                    &mut recv,
                    &peer,
                    &state,
                    "relay",
                    &repush_tx,
                    &delivery_tx,
                    &seen_table,
                    &rates,
                    true,
                    address,
                    Some(&permits),
                    false,
                )
                .await;
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
        write_protocol_byte(&mut csend, Protocol::ItemPush)
            .await
            .unwrap();
        // A frame of a megabyte: longer than a small message, and than the
        // stream's window, so the write waits while the node reads none of
        // the body, as a device of the version before waits in its write,
        // until the node stops the receive side. The send is left open
        // (not finished), so the stop is seen on it.
        let _ = write_raw_frame(&mut csend, &vec![0x5a; 1_000_000]).await;

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
        match csend.stopped().await {
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
        let (over, _conn) = serving.await.unwrap();
        assert!(over.is_none(), "a refused large frame counted a breach");
        assert!(
            !rates.lock().unwrap().is_counting(&peer),
            "a refused large frame was counted against the peer's push allowance"
        );
    }

    /// An answer of the older kind's sync stream is encoded and the
    /// message dropped before the write (decision 2026-10-22 (memory),
    /// rule 4): while the write waits for a peer that grants no credit, the
    /// node holds the encoding alone, not the answer as a message beside
    /// it. The node holds a megabyte of items; a fetch of them is answered
    /// while the peer does not read.
    #[tokio::test]
    async fn an_older_kind_sync_answer_is_not_held_through_its_write() {
        use crate::counting;
        use cordelia_network::codec::{read_frame, write_raw_frame};
        use cordelia_network::messages::{FetchRequest, Protocol, SyncRequest, WireMessage};

        let state = a_state();
        let channel = "grp_00000000-0000-4000-8000-00000000000f";
        let ids: Vec<String> = (0..14u8).map(|n| format!("ci_{n:0>60}")).collect();
        {
            let db = state.db.lock().unwrap();
            cordelia_storage::channels::ensure_group(&db, channel, None, "realtime", &[1u8; 32])
                .unwrap();
            for (n, id) in ids.iter().enumerate() {
                let blob = vec![n as u8; 60_000];
                let hash = {
                    let mut h = vec![0xa1u8; 32];
                    h[0] = n as u8;
                    h
                };
                let item = cordelia_storage::items::NewItem::plain(
                    id,
                    channel,
                    &[1u8; 32],
                    "memory",
                    "2026-10-22T00:00:00Z",
                    1,
                    &hash,
                    &[0xa3u8; 64],
                    &blob,
                );
                assert!(cordelia_storage::items::insert_item(&db, &item).unwrap());
            }
        }

        // A pipe wide enough for the small headers, too small for the
        // megabyte of items: the fetch answer's write blocks.
        let (mut client_w, mut node_r) = tokio::io::duplex(64 * 1024);
        let (mut node_w, mut client_r) = tokio::io::duplex(64 * 1024);
        let address: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let peer = NodeId([7; 32]);
        let node = handle_inbound_sync(
            &mut node_w,
            &mut node_r,
            &peer,
            &state,
            true,
            false,
            None,
            address,
            false,
        );
        tokio::pin!(node);

        let client = async {
            let sync =
                cordelia_network::codec::encode_message(&WireMessage::SyncRequest(SyncRequest {
                    channel_id: channel.into(),
                    since: None,
                    limit: 100,
                    after_seq: None,
                }))
                .unwrap();
            let fetch =
                cordelia_network::codec::encode_message(&WireMessage::FetchRequest(FetchRequest {
                    item_ids: ids.clone(),
                }))
                .unwrap();
            // The channel's headers first: read, so what the node keeps
            // from then on is in the count it is measured from.
            write_raw_frame(&mut client_w, &sync).await.unwrap();
            let _ = read_frame(&mut client_r, Protocol::ItemSync).await.unwrap();
            let before = counting::live();
            // The fetch of a megabyte of items. The node builds the answer
            // and begins to write it; the peer does not read, so the write
            // waits.
            write_raw_frame(&mut client_w, &fetch).await.unwrap();
            for _ in 0..50 {
                tokio::task::yield_now().await;
            }
            counting::live() - before
        };

        let held = tokio::select! {
            _ = &mut node => panic!("the node ended the stream"),
            held = client => held,
        };
        println!("held while the fetch answer is written: {held} bytes");
        // The encoded answer is about 840 KB. Holding the answer as a
        // message beside its encoding would be about twice that.
        assert!(
            held < 1_300_000,
            "the node holds {held} bytes: the answer is held as a message through its write"
        );
        assert!(
            held > 600_000,
            "the answer of a megabyte was not built: {held} bytes"
        );
    }

    /// A channel of the older kind of `count` items of `size` bytes each,
    /// in `state`: its ID and the items' IDs.
    fn an_older_kind_channel(
        state: &web::Data<cordelia_api::state::AppState>,
        count: u8,
        size: usize,
    ) -> (String, Vec<String>) {
        let channel = "grp_00000000-0000-4000-8000-0000000000aa".to_string();
        let ids: Vec<String> = (0..count).map(|n| format!("ci_{n:0>60}")).collect();
        let db = state.db.lock().unwrap();
        cordelia_storage::channels::ensure_group(&db, &channel, None, "realtime", &[1u8; 32])
            .unwrap();
        for (n, id) in ids.iter().enumerate() {
            let mut hash = vec![0xa1u8; 32];
            hash[0] = n as u8;
            let blob = vec![n as u8; size];
            let item = cordelia_storage::items::NewItem::plain(
                id,
                &channel,
                &[1u8; 32],
                "memory",
                "2026-10-22T00:00:00Z",
                1,
                &hash,
                &[0xa3u8; 64],
                &blob,
            );
            assert!(cordelia_storage::items::insert_item(&db, &item).unwrap());
        }
        (channel, ids)
    }

    /// One end of a pipe in memory that keeps the code it was refused
    /// with, where a stream of QUIC would be stopped or reset with it.
    struct Refusable {
        pipe: tokio::io::DuplexStream,
        refused: Option<u64>,
    }

    impl Refusable {
        fn new(pipe: tokio::io::DuplexStream) -> Self {
            Self {
                pipe,
                refused: None,
            }
        }
    }

    impl tokio::io::AsyncRead for Refusable {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.pipe).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for Refusable {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.pipe).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.pipe).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.pipe).poll_shutdown(cx)
        }
    }

    impl cordelia_network::codec::GiveUp for Refusable {}

    impl crate::relay_entries::Refuse for Refusable {
        fn refuse(&mut self, code: quinn::VarInt) {
            self.refused = Some(code.into_inner());
        }
    }

    /// The older kind's fetch answer over SMALL_PAGE_BYTES is loaded and
    /// written to a peer that is not a relay listed by key only under a
    /// large permit (decision 2026-10-22 (memory), rules 2 and 3).
    ///
    /// - With every permit held, a fetch of two items, within a small
    ///   page, is answered at once.
    /// - A fetch of fourteen is not answered while the permits are held,
    ///   and the items are not loaded meanwhile: what the node's thread
    ///   holds grows by far less than the answer's 840 KB. It is answered
    ///   once a permit is let go.
    /// - A relay listed by key is answered at once whatever the size (rule
    ///   7).
    /// - A fetch whose own frame is over a small message, read under the
    ///   one permit there is, is answered under that permit with no wait:
    ///   one permit a stream (rule 2).
    /// - Where no permit comes within STREAM_TIMEOUT, the stream is
    ///   stopped and reset with ERR_LARGE_MESSAGE_LATER, unanswered.
    #[tokio::test(start_paused = true)]
    async fn an_older_kind_fetch_answer_over_a_small_page_waits_for_a_large_permit() {
        use cordelia_core::protocol::{ERR_LARGE_MESSAGE_LATER, SMALL_MESSAGE_BYTES};
        use cordelia_network::codec::{STREAM_TIMEOUT, read_frame, write_raw_frame};
        use cordelia_network::messages::{FetchRequest, Protocol, SyncRequest, WireMessage};

        let state = a_state();
        let (channel, ids) = an_older_kind_channel(&state, 14, 60_000);
        let peer = NodeId([7; 32]);
        let address: std::net::IpAddr = "198.51.100.7".parse().unwrap();
        let sync =
            cordelia_network::codec::encode_message(&WireMessage::SyncRequest(SyncRequest {
                channel_id: channel.clone(),
                since: None,
                limit: 100,
                after_seq: None,
            }))
            .unwrap();
        let fetch = |ids: &[String]| {
            cordelia_network::codec::encode_message(&WireMessage::FetchRequest(FetchRequest {
                item_ids: ids.to_vec(),
            }))
            .unwrap()
        };
        // The answer to a fetch, where one comes within `wait`.
        async fn fetched(
            from: &mut tokio::io::DuplexStream,
            wait: std::time::Duration,
        ) -> Option<usize> {
            match tokio::time::timeout(wait, read_frame(from, Protocol::ItemSync)).await {
                Ok(Ok(WireMessage::FetchResponse(answer))) => Some(answer.items.len()),
                Ok(other) => panic!("not a fetch answer: {other:?}"),
                Err(_) => None,
            }
        }
        let two_seconds = std::time::Duration::from_secs(2);

        for listed in [false, true] {
            let permits = LargePermits::new(1);
            let held = permits.take("203.0.113.1".parse().unwrap()).await;
            assert!(held.is_some(), "the one permit");
            let (client_w, node_r) = tokio::io::duplex(64 * 1024);
            let (node_w, mut client_r) = tokio::io::duplex(2 * 1024 * 1024);
            let (mut node_w, mut node_r) = (Refusable::new(node_w), Refusable::new(node_r));
            let node = handle_inbound_sync(
                &mut node_w,
                &mut node_r,
                &peer,
                &state,
                true,
                false,
                Some(&permits),
                address,
                listed,
            );
            let client = async {
                // The client's half is its own: dropped at its end, which
                // ends the node's stream.
                let mut client_w = client_w;
                let mut held = held;
                // Two items: within a small page, answered with the
                // permits held.
                write_raw_frame(&mut client_w, &sync).await.unwrap();
                let _ = read_frame(&mut client_r, Protocol::ItemSync).await.unwrap();
                write_raw_frame(&mut client_w, &fetch(&ids[..2]))
                    .await
                    .unwrap();
                assert_eq!(fetched(&mut client_r, two_seconds).await, Some(2));
                // Fourteen: over a small page. Not answered while the
                // permits are held, unless the peer is a listed relay.
                write_raw_frame(&mut client_w, &sync).await.unwrap();
                let _ = read_frame(&mut client_r, Protocol::ItemSync).await.unwrap();
                // The node and this client run on this one thread, which
                // the counting allocator counts: what it comes to hold
                // while the permit is awaited is the request, not the
                // items.
                let before = crate::counting::live();
                write_raw_frame(&mut client_w, &fetch(&ids)).await.unwrap();
                let at_once = fetched(&mut client_r, two_seconds).await;
                if listed {
                    assert_eq!(at_once, Some(14), "a listed relay waited for a permit");
                    return;
                }
                assert_eq!(
                    at_once, None,
                    "a fetch over a small page was answered with no permit"
                );
                let waiting = crate::counting::live() - before;
                assert!(
                    waiting < 64 * 1024,
                    "the items were loaded before a permit came: {waiting} bytes held"
                );
                held.take();
                assert_eq!(fetched(&mut client_r, two_seconds).await, Some(14));
                drop(held);
            };
            let ((), ()) = tokio::join!(
                async {
                    node.await;
                },
                client
            );
            assert_eq!((node_w.refused, node_r.refused), (None, None));
        }

        // A fetch whose own frame is over a small message, with a budget of
        // one permit: the frame is read under it, and the answer, over a
        // small page, is written under the same permit at once. (Asked for
        // a second, the stream would wait for its own subnet's.)
        let mut asked = ids.clone();
        asked.extend((0..86).map(|n| format!("absent_{n:0>1992}")));
        let large = fetch(&asked);
        assert!(
            large.len() > SMALL_MESSAGE_BYTES as usize,
            "{}",
            large.len()
        );
        let permits = LargePermits::new(1);
        let (mut client_w, node_r) = tokio::io::duplex(64 * 1024);
        let (node_w, mut client_r) = tokio::io::duplex(2 * 1024 * 1024);
        let (mut node_w, mut node_r) = (Refusable::new(node_w), Refusable::new(node_r));
        let node = handle_inbound_sync(
            &mut node_w,
            &mut node_r,
            &peer,
            &state,
            true,
            false,
            Some(&permits),
            address,
            false,
        );
        let client = async {
            write_raw_frame(&mut client_w, &sync).await.unwrap();
            let _ = read_frame(&mut client_r, Protocol::ItemSync).await.unwrap();
            write_raw_frame(&mut client_w, &large).await.unwrap();
            let answered = fetched(&mut client_r, two_seconds).await;
            assert_eq!(
                answered,
                Some(14),
                "the answer waited for a second permit beside the frame's"
            );
            drop(client_w);
        };
        let ((), ()) = tokio::join!(
            async {
                node.await;
            },
            client
        );
        assert_eq!((node_w.refused, node_r.refused), (None, None));

        // No permit within STREAM_TIMEOUT: the stream is stopped and reset
        // with ERR_LARGE_MESSAGE_LATER, and ends unanswered.
        let permits = LargePermits::new(1);
        let _held = permits.take("203.0.113.1".parse().unwrap()).await;
        let (mut client_w, node_r) = tokio::io::duplex(64 * 1024);
        let (node_w, mut client_r) = tokio::io::duplex(2 * 1024 * 1024);
        let (mut node_w, mut node_r) = (Refusable::new(node_w), Refusable::new(node_r));
        write_raw_frame(&mut client_w, &sync).await.unwrap();
        write_raw_frame(&mut client_w, &fetch(&ids)).await.unwrap();
        let node = handle_inbound_sync(
            &mut node_w,
            &mut node_r,
            &peer,
            &state,
            true,
            false,
            Some(&permits),
            address,
            false,
        );
        tokio::time::timeout(STREAM_TIMEOUT + two_seconds, node)
            .await
            .expect("the stream was not given up when no permit came");
        let later = Some(u64::from(ERR_LARGE_MESSAGE_LATER));
        assert_eq!(
            (node_w.refused, node_r.refused),
            (later, later),
            "the stream was not refused with ERR_LARGE_MESSAGE_LATER"
        );
        let _ = read_frame(&mut client_r, Protocol::ItemSync).await.unwrap();
        assert_eq!(fetched(&mut client_r, two_seconds).await, None);
    }

    /// Which inbound handler to run over a pair of pipes.
    enum Handler {
        PeerShare,
        ChannelAnnounce,
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
                Handler::ChannelAnnounce => {
                    let (gov_tx, _rx) = tokio::sync::mpsc::unbounded_channel();
                    handle_inbound_channel_announce(&mut node_r, &peer, &gov_tx).await;
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

    /// The peer-share, channel-announce and older-kind-sync handlers read a
    /// frame only within a small message (decision 2026-10-22 (memory),
    /// rule 2): no honest message of any version on these streams is
    /// larger, so a longer frame is refused at its length and its body is
    /// not read.
    #[tokio::test]
    async fn the_small_streams_do_not_read_a_frame_over_a_small_message() {
        assert!(
            !handler_drains_a_large_frame(Handler::PeerShare).await,
            "peer-share read a frame over a small message"
        );
        assert!(
            !handler_drains_a_large_frame(Handler::ChannelAnnounce).await,
            "channel-announce read a frame over a small message"
        );
        assert!(
            !handler_drains_a_large_frame(Handler::SyncNothing).await,
            "the older kind's answer-nothing read a frame over a small message"
        );
    }

    /// Whether a relay reads and answers a large push (longer than a small
    /// message) from a client, run through the live inbound loop
    /// (`handle_peer_streams`). `proto` is the stream: `ItemPush` (0x01) of
    /// the older kind, or `EntryPush` (0x13) of the streams of entries,
    /// whose permits the loop hands to `serve` in the `Serving` it builds.
    /// The client is listed by key iff `listed`, and is in `peer_relays` (a
    /// relay configured by address alone) iff `addressed`; the large-permit
    /// budget is `budget`. A permit is read and answered within two seconds,
    /// or it is not.
    async fn large_push_answered(
        proto: cordelia_network::messages::Protocol,
        listed: bool,
        addressed: bool,
        budget: usize,
    ) -> bool {
        use cordelia_network::bootstrap::RelayAddr;
        use cordelia_network::messages::{EntryPush, Item, Protocol, PushPayload, WireMessage};
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
        let (repush_tx, _r) = tokio::sync::mpsc::unbounded_channel();
        let (delivery_tx, _d) = tokio::sync::mpsc::unbounded_channel();
        let (gov_tx, _g) = tokio::sync::mpsc::unbounded_channel();
        let shared_peers = Arc::new(RwLock::new(Vec::new()));
        let swarm = Arc::new(RwLock::new(HashSet::new()));
        let seen = Arc::new(RwLock::new(
            cordelia_network::seen_table::SeenTable::default(),
        ));
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
            repush_tx,
            delivery_tx,
            peer_rates,
            peer_states,
            peer_relays,
            gov_tx,
            swarm,
            seen,
            relay_entries,
            permits,
            listed,
        ));

        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        codec::write_protocol_byte(&mut send, proto).await.unwrap();
        // A push longer than a small message, in the shape the stream
        // carries: a payload of one big item for the older kind, a push of
        // one big entry for the streams of entries. Each is a valid message,
        // so a relay that reads it answers (a push ack, or the per-entry
        // word), and a relay that does not read it does not.
        let frame = match proto {
            Protocol::EntryPush => {
                let push = WireMessage::EntryPush(EntryPush {
                    entries: vec![serde_bytes::ByteBuf::from(vec![0u8; 200_000])],
                });
                codec::encode_message(&push).unwrap()
            }
            _ => {
                let item = Item {
                    item_id: "ci_big".into(),
                    channel_id: "grp_x".into(),
                    item_type: "memory".into(),
                    encrypted_blob: vec![0u8; 200_000],
                    content_hash: vec![0u8; 32],
                    content_length: 200_000,
                    author_id: vec![0u8; 32],
                    signature: vec![0u8; 64],
                    key_version: 1,
                    published_at: "2026-10-22T00:00:00Z".into(),
                    is_tombstone: false,
                    parent_id: None,
                    slot: None,
                    rev: None,
                };
                let push = WireMessage::PushPayload(PushPayload { items: vec![item] });
                codec::encode_message(&push).unwrap()
            }
        };
        assert!(
            frame.len() > cordelia_core::protocol::SMALL_MESSAGE_BYTES as usize,
            "the push was meant to be over a small message"
        );
        let _ = codec::write_raw_frame(&mut send, &frame).await;
        // An answer within two seconds means it was read.
        let answered = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            codec::read_frame(&mut recv, proto),
        )
        .await
        .is_ok_and(|r| r.is_ok());
        loop_task.abort();
        answered
    }

    /// The live inbound loop reads a large frame only under the permits,
    /// and exempts a relay listed by key alone, not one configured by
    /// address (decision 2026-10-22 (memory), rules 2 and 7). With no
    /// permit free, a listed relay's large push is read, an unlisted
    /// peer's and a relay-by-address's are not; with a permit free, an
    /// unlisted peer's is read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_inbound_loop_takes_permits_and_exempts_only_listed_relays() {
        use cordelia_network::messages::Protocol::ItemPush;
        // A relay listed by key: read though no permit is free (rule 7).
        assert!(
            large_push_answered(ItemPush, true, false, 0).await,
            "a listed relay's large push was not read"
        );
        // A peer that is not listed: not read with no permit (rule 2).
        assert!(
            !large_push_answered(ItemPush, false, false, 0).await,
            "an unlisted peer's large push was read with no permit"
        );
        // A relay configured by address alone is unlisted for F: it waits.
        assert!(
            !large_push_answered(ItemPush, false, true, 0).await,
            "a relay configured by address alone was exempted"
        );
        // With a permit free, an unlisted peer's push is read.
        assert!(
            large_push_answered(ItemPush, false, false, 1).await,
            "an unlisted peer's large push was not read when a permit was free"
        );
    }

    /// The live inbound loop hands the permits to the streams of entries
    /// too (decision 2026-10-22 (memory), rules 2 and 7; the high finding).
    /// On a 0x13 EntryPush stream the loop builds a `Serving` with the
    /// permits, so a frame longer than a small message from an unlisted
    /// peer is read only under a permit, and a relay listed by key is read
    /// at once. This catches `permits: None` in that `Serving`, which the
    /// older-kind loop test above cannot see.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_inbound_loop_takes_permits_on_the_streams_of_entries() {
        use cordelia_network::messages::Protocol::EntryPush;
        // A relay listed by key: read though no permit is free (rule 7).
        assert!(
            large_push_answered(EntryPush, true, false, 0).await,
            "a listed relay's large entry push was not read"
        );
        // An unlisted peer: not read with no permit (rule 2).
        assert!(
            !large_push_answered(EntryPush, false, false, 0).await,
            "an unlisted peer's large entry push was read with no permit"
        );
        // With a permit free, an unlisted peer's entry push is read.
        assert!(
            large_push_answered(EntryPush, false, false, 1).await,
            "an unlisted peer's large entry push was not read when a permit was free"
        );
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
    /// held, the client sends a push longer than a small message, the
    /// permit is let go well within the stream timeout, and the push is
    /// answered rather than refused with ERR_LARGE_MESSAGE_LATER.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_large_frame_is_read_once_a_permit_frees_over_quic() {
        use cordelia_network::codec::{read_frame, write_protocol_byte, write_raw_frame};
        use cordelia_network::messages::{Item, Protocol, PushPayload, WireMessage};
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
                let (repush_tx, _r) = tokio::sync::mpsc::unbounded_channel();
                let (delivery_tx, _d) = tokio::sync::mpsc::unbounded_channel();
                let seen_table = std::sync::Arc::new(std::sync::RwLock::new(
                    cordelia_network::seen_table::SeenTable::default(),
                ));
                handle_inbound_push(
                    &mut send,
                    &mut recv,
                    &peer,
                    &state,
                    "relay",
                    &repush_tx,
                    &delivery_tx,
                    &seen_table,
                    &rates,
                    true,
                    address,
                    Some(&permits),
                    false,
                )
                .await;
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
        write_protocol_byte(&mut csend, Protocol::ItemPush)
            .await
            .unwrap();
        // A valid push longer than a small message.
        let item = Item {
            item_id: "ci_frees".into(),
            channel_id: "grp_x".into(),
            item_type: "memory".into(),
            encrypted_blob: vec![0u8; 200_000],
            content_hash: vec![0u8; 32],
            content_length: 200_000,
            author_id: vec![0u8; 32],
            signature: vec![0u8; 64],
            key_version: 1,
            published_at: "2026-10-22T00:00:00Z".into(),
            is_tombstone: false,
            parent_id: None,
            slot: None,
            rev: None,
        };
        let push = WireMessage::PushPayload(PushPayload { items: vec![item] });
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
            read_frame(&mut crecv, Protocol::ItemPush),
        )
        .await;
        assert!(
            answered.is_ok_and(|r| r.is_ok()),
            "the large frame was not answered once a permit freed"
        );
        let _ = writing.await;
        let _ = serving.await;
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

    /// A personal node carries no channel of the older kind (decision
    /// 2026-10-04 §10): it pushes none, fetches none, announces none and
    /// takes none. A node of any other role carries both kinds.
    #[test]
    fn only_a_personal_node_carries_no_channel_of_the_older_kind() {
        assert!(!carries_older_kind("personal"));
        for role in ["relay", "bootnode", "keeper"] {
            assert!(carries_older_kind(role), "{role}");
        }
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
                    relay.clone(),
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
            lacks.clone(),
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
                    &now_listed,
                    (b.addr, "timed out".into()),
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
        let accepted = accepted.await.unwrap();
        (
            conn_mgr,
            relay.public_key(),
            relay_addr,
            (relay_mgr, accepted),
        )
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

    fn ids(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    fn refusal(id: &str) -> cordelia_network::messages::Refusal {
        cordelia_network::messages::Refusal {
            item_id: id.into(),
            why: cordelia_network::messages::REFUSED_STORAGE.into(),
        }
    }

    /// T16. An item counts as delivered only if the relay stored it or
    /// already held it. An item the relay refused stays in the outbox.
    #[test]
    fn a_relays_refusal_is_not_delivery() {
        use cordelia_network::messages::PushAck;
        let sent = ids(&["a", "b", "c"]);

        // Everything stored or already held: everything delivered.
        let ack = PushAck {
            stored: 2,
            dedup_dropped: 1,
            ..Default::default()
        };
        assert_eq!(
            outbox_outcome(&sent, &ack),
            Pushed::Answered {
                delivered: sent.clone(),
                refused: vec![]
            }
        );

        // One refused: the other two are delivered, and it is not.
        let ack = PushAck {
            stored: 2,
            verification_failed: 1,
            refused: vec![refusal("b")],
            ..Default::default()
        };
        assert_eq!(
            outbox_outcome(&sent, &ack),
            Pushed::Answered {
                delivered: ids(&["a", "c"]),
                refused: vec![refusal("b")]
            }
        );

        // A relay from before the list existed says how many it refused,
        // not which: nothing is taken as delivered.
        let ack = PushAck {
            stored: 2,
            verification_failed: 1,
            ..Default::default()
        };
        assert_eq!(outbox_outcome(&sent, &ack), Pushed::Unknown);
    }

    /// An answer that does not add up is not trusted for any item.
    #[test]
    fn an_answer_that_does_not_add_up_delivers_nothing() {
        use cordelia_network::messages::PushAck;
        let sent = ids(&["a", "b", "c"]);
        let unknown = |ack: PushAck| assert_eq!(outbox_outcome(&sent, &ack), Pushed::Unknown);

        // Not every item answered for.
        unknown(PushAck {
            stored: 1,
            ..Default::default()
        });
        // More refused than listed, by listing one twice.
        unknown(PushAck {
            stored: 1,
            verification_failed: 2,
            refused: vec![refusal("b"), refusal("b")],
            ..Default::default()
        });
        // An item that was not in the push.
        unknown(PushAck {
            stored: 2,
            verification_failed: 1,
            refused: vec![refusal("z")],
            ..Default::default()
        });
        // Numbers chosen to overflow.
        unknown(PushAck {
            stored: u32::MAX,
            dedup_dropped: u32::MAX,
            policy_rejected: u32::MAX,
            verification_failed: 6,
            ..Default::default()
        });
    }

    const A_CHANNEL: &str = "grp_550e8400-e29b-41d4-a716-446655440000";

    /// An item of `blob`, signed by `id`, as it arrives from another node.
    fn arriving(
        id: &cordelia_crypto::identity::NodeIdentity,
        blob: Vec<u8>,
    ) -> cordelia_network::messages::Item {
        arriving_in(id, A_CHANNEL, blob)
    }

    fn arriving_in(
        id: &cordelia_crypto::identity::NodeIdentity,
        channel: &str,
        blob: Vec<u8>,
    ) -> cordelia_network::messages::Item {
        let hash = cordelia_crypto::sha256(&blob);
        let item_id = cordelia_storage::items::generate_item_id();
        let published_at = "2026-10-02T00:00:00Z";
        let cbor = cordelia_crypto::signing::build_item_metadata_envelope(
            &id.public_key(),
            channel,
            &hash,
            false,
            &item_id,
            1,
            published_at,
        )
        .unwrap();
        cordelia_network::messages::Item {
            item_id,
            channel_id: channel.into(),
            item_type: "memory".into(),
            content_length: blob.len() as u32,
            encrypted_blob: blob,
            content_hash: hash.to_vec(),
            author_id: id.public_key().to_vec(),
            signature: id.sign(&cbor).to_vec(),
            key_version: 1,
            published_at: published_at.into(),
            is_tombstone: false,
            parent_id: None,
            slot: None,
            rev: None,
        }
    }

    /// T3. A node refuses an entry over the size limit, whoever sends it:
    /// a relay that is pushed one, and a device whose relay hands it one.
    #[test]
    fn an_entry_over_the_size_limit_is_refused_by_whoever_is_sent_it() {
        use cordelia_core::protocol::MAX_ITEM_BYTES;
        use cordelia_network::messages::REFUSED_TOO_LARGE;
        let db = cordelia_storage::db::open_in_memory().unwrap();
        let id = cordelia_crypto::identity::NodeIdentity::generate().unwrap();

        let over = arriving(&id, vec![7; MAX_ITEM_BYTES + 1]);
        for role in ["relay", "personal"] {
            assert_eq!(
                store_item(&db, &over, role, &[0x0E; 32]),
                Err(REFUSED_TOO_LARGE),
                "{role}"
            );
        }
        let largest = arriving(&id, vec![7; MAX_ITEM_BYTES]);
        assert_eq!(store_item(&db, &largest, "relay", &[0x0E; 32]), Ok(true));
    }

    /// An entry signed as it should be, with these values in the fields its
    /// signature covers.
    fn signed(
        id: &cordelia_crypto::identity::NodeIdentity,
        channel: &str,
        item_id: &str,
        published_at: &str,
    ) -> cordelia_network::messages::Item {
        let blob = vec![7u8; 16];
        let hash = cordelia_crypto::sha256(&blob);
        let cbor = cordelia_crypto::signing::build_item_metadata_envelope(
            &id.public_key(),
            channel,
            &hash,
            false,
            item_id,
            1,
            published_at,
        )
        .unwrap();
        cordelia_network::messages::Item {
            item_id: item_id.into(),
            channel_id: channel.into(),
            item_type: "memory".into(),
            content_length: blob.len() as u32,
            encrypted_blob: blob,
            content_hash: hash.to_vec(),
            author_id: id.public_key().to_vec(),
            signature: id.sign(&cbor).to_vec(),
            key_version: 1,
            published_at: published_at.into(),
            is_tombstone: false,
            parent_id: None,
            slot: None,
            rev: None,
        }
    }

    /// T3. One size for every entry means every field of it. An entry whose
    /// ID, channel, type, time or parent is over the size it must fit in is
    /// refused by whoever is sent it, however small its content and though
    /// it is signed as it should be. Otherwise a megabyte could travel as
    /// an entry's type.
    #[test]
    fn an_entry_with_a_field_over_its_size_is_refused_by_whoever_is_sent_it() {
        use cordelia_core::protocol::{
            MAX_CHANNEL_ID_LEN, MAX_ITEM_ID_LEN, MAX_ITEM_TYPE_LEN, MAX_TIMESTAMP_LEN,
        };
        use cordelia_network::messages::{Item, REFUSED_TOO_LARGE};
        const TIME: &str = "2026-10-02T00:00:00Z";
        let db = cordelia_storage::db::open_in_memory().unwrap();
        let id = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
        let long = |len: usize| "x".repeat(len);

        let over = [
            (
                "id",
                signed(&id, A_CHANNEL, &long(MAX_ITEM_ID_LEN + 1), TIME),
            ),
            (
                "channel",
                signed(&id, &long(MAX_CHANNEL_ID_LEN + 1), "ci_channel", TIME),
            ),
            (
                "time",
                signed(&id, A_CHANNEL, "ci_time", &long(MAX_TIMESTAMP_LEN + 1)),
            ),
            (
                "type",
                Item {
                    item_type: long(MAX_ITEM_TYPE_LEN + 1),
                    ..signed(&id, A_CHANNEL, "ci_type", TIME)
                },
            ),
            (
                "parent",
                Item {
                    parent_id: Some(long(MAX_ITEM_ID_LEN + 1)),
                    ..signed(&id, A_CHANNEL, "ci_parent", TIME)
                },
            ),
        ];
        for (field, item) in &over {
            for role in ["relay", "personal"] {
                assert_eq!(
                    store_item(&db, item, role, &[0x0E; 32]),
                    Err(REFUSED_TOO_LARGE),
                    "{field}, {role}"
                );
            }
        }

        // An entry with each field at its largest is taken.
        let largest = Item {
            item_type: long(MAX_ITEM_TYPE_LEN),
            parent_id: Some(long(MAX_ITEM_ID_LEN)),
            ..signed(
                &id,
                &long(MAX_CHANNEL_ID_LEN),
                &long(MAX_ITEM_ID_LEN),
                &long(MAX_TIMESTAMP_LEN),
            )
        };
        assert_eq!(store_item(&db, &largest, "relay", &[0x0E; 32]), Ok(true));
    }

    /// T2. A device stores only what belongs in its own channels: an entry
    /// that a member of one of them wrote, and what is sent to its own
    /// inbox. A relay stores all of it.
    #[test]
    fn a_device_stores_only_what_members_of_its_channels_wrote() {
        use cordelia_crypto::identity::NodeIdentity;
        use cordelia_network::messages::REFUSED_NOT_MEMBER;
        use cordelia_storage::{channels, naming};
        const NOT_MINE: &str = "grp_660e8400-e29b-41d4-a716-446655440000";

        let (me, friend, stranger) = (
            NodeIdentity::generate().unwrap(),
            NodeIdentity::generate().unwrap(),
            NodeIdentity::generate().unwrap(),
        );
        let own = me.public_key();
        let device = cordelia_storage::db::open_in_memory().unwrap();
        // A channel this device and a friend are in; one it is not in; its
        // own inbox; and the friend's inbox, which it writes to.
        channels::ensure_group(&device, A_CHANNEL, None, "realtime", &own).unwrap();
        channels::add_member(&device, A_CHANNEL, &own, "owner").unwrap();
        channels::add_member(&device, A_CHANNEL, &friend.public_key(), "owner").unwrap();
        channels::ensure_group(&device, NOT_MINE, None, "realtime", &friend.public_key()).unwrap();
        channels::add_member(&device, NOT_MINE, &friend.public_key(), "owner").unwrap();
        let my_inbox = naming::inbox_channel_id(&own);
        let their_inbox = naming::inbox_channel_id(&friend.public_key());
        channels::ensure_inbox(&device, &my_inbox, &own, true).unwrap();
        channels::ensure_inbox(&device, &their_inbox, &friend.public_key(), false).unwrap();

        let cases = [
            (&friend, A_CHANNEL, Ok(true)),
            (&stranger, A_CHANNEL, Err(REFUSED_NOT_MEMBER)),
            (&friend, NOT_MINE, Err(REFUSED_NOT_MEMBER)),
            (&stranger, my_inbox.as_str(), Ok(true)),
            (&stranger, their_inbox.as_str(), Err(REFUSED_NOT_MEMBER)),
        ];
        let relay = cordelia_storage::db::open_in_memory().unwrap();
        for (n, (author, channel, expected)) in cases.into_iter().enumerate() {
            let item = arriving_in(author, channel, vec![n as u8; 40]);
            assert_eq!(
                store_item(&device, &item, "personal", &own),
                expected,
                "case {n}: {channel}"
            );
            assert_eq!(
                store_item(&relay, &item, "relay", &own),
                Ok(true),
                "case {n}"
            );
        }

        // A member that is removed is no longer one whose entries are stored.
        channels::remove_member(&device, A_CHANNEL, &friend.public_key()).unwrap();
        let later = arriving_in(&friend, A_CHANNEL, vec![9; 40]);
        assert_eq!(
            store_item(&device, &later, "personal", &own),
            Err(REFUSED_NOT_MEMBER)
        );
    }

    /// A relay's database, how much it holds when empty, and a way to
    /// store one entry of `bytes` in `channel` with the room it is given.
    fn relay_store(
        db: &rusqlite::Connection,
        room: &mut RelayRoom,
        channel: &str,
        bytes: usize,
    ) -> Result<bool, &'static str> {
        thread_local! {
            static AUTHOR: cordelia_crypto::identity::NodeIdentity =
                cordelia_crypto::identity::NodeIdentity::generate().unwrap();
        }
        // Distinct content each time, so nothing is taken for a duplicate.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut blob = vec![7u8; bytes];
        blob[..8].copy_from_slice(&n.to_be_bytes());
        let item = AUTHOR.with(|author| arriving_in(author, channel, blob));
        store_checked(
            db,
            &item,
            &check_item(&item)?,
            "relay",
            &[0u8; 32],
            Some(room),
        )
    }

    fn channel(n: usize) -> String {
        format!("grp_550e8400-e29b-41d4-a716-{n:012}")
    }

    /// Store at a relay an entry under a name: `name` at revision `rev`, of
    /// `bytes` bytes, by one author. A later revision replaces an earlier.
    fn relay_store_named(
        db: &rusqlite::Connection,
        room: &mut RelayRoom,
        channel: &str,
        name: [u8; 32],
        rev: u64,
        bytes: usize,
    ) -> Result<bool, &'static str> {
        thread_local! {
            static AUTHOR: cordelia_crypto::identity::NodeIdentity =
                cordelia_crypto::identity::NodeIdentity::generate().unwrap();
        }
        AUTHOR.with(|author| relay_store_named_by(db, room, author, channel, name, rev, bytes))
    }

    /// The same, by `author`: another device of the same person writes a
    /// name under its own key.
    fn relay_store_named_by(
        db: &rusqlite::Connection,
        room: &mut RelayRoom,
        author: &cordelia_crypto::identity::NodeIdentity,
        channel: &str,
        name: [u8; 32],
        rev: u64,
        bytes: usize,
    ) -> Result<bool, &'static str> {
        let mut blob = vec![9u8; bytes];
        blob[..8].copy_from_slice(&rev.to_be_bytes());
        blob[8..16].copy_from_slice(&name[..8]);
        let hash = cordelia_crypto::sha256(&blob);
        let item_id = cordelia_storage::items::generate_item_id();
        let published_at = "2026-10-02T00:00:00Z";
        let item = {
            let cbor = cordelia_crypto::signing::ItemMetadata {
                author_id: &author.public_key(),
                channel_id: channel,
                content_hash: &hash,
                is_tombstone: false,
                item_id: &item_id,
                key_version: 1,
                published_at,
                slot: Some(&name),
                rev: Some(rev),
            }
            .encode()
            .unwrap();
            cordelia_network::messages::Item {
                item_id: item_id.clone(),
                channel_id: channel.into(),
                item_type: "memory".into(),
                content_length: blob.len() as u32,
                encrypted_blob: blob.clone(),
                content_hash: hash.to_vec(),
                author_id: author.public_key().to_vec(),
                signature: author.sign(&cbor).to_vec(),
                key_version: 1,
                published_at: published_at.into(),
                is_tombstone: false,
                parent_id: None,
                slot: Some(name.to_vec()),
                rev: Some(rev),
            }
        };
        store_checked(
            db,
            &item,
            &check_item(&item)?,
            "relay",
            &[0u8; 32],
            Some(room),
        )
    }

    fn holds(db: &rusqlite::Connection, channel: &str) -> u64 {
        cordelia_storage::items::channel_bytes(db, channel).unwrap()
    }

    /// T3. A relay has a storage cap. At the cap it takes no channel it
    /// does not hold. A write to a channel it holds is taken, and room is
    /// made by dropping the channel it came to hold most recently: what
    /// was there first is never pushed out by what came later.
    #[test]
    fn a_full_relay_keeps_what_it_held_first() {
        use cordelia_network::messages::REFUSED_FULL;
        const ENTRY: usize = 60_000;
        let db = cordelia_storage::db::open_in_memory().unwrap();
        let empty = cordelia_storage::items::stored_cost(&db).unwrap();
        let mut room = RelayRoom::new(empty + 400_000, None, None);

        // The first channel, then newer ones, one entry each, until the
        // relay will take no more.
        let first = channel(0);
        assert_eq!(relay_store(&db, &mut room, &first, ENTRY), Ok(true));
        let mut newer = Vec::new();
        loop {
            let next = channel(newer.len() + 1);
            match relay_store(&db, &mut room, &next, ENTRY) {
                Ok(true) => newer.push(next),
                Err(REFUSED_FULL) => break,
                other => panic!("unexpected: {other:?}"),
            }
            assert!(newer.len() < 50, "the relay is never full");
        }
        assert!(newer.len() >= 3, "{}", newer.len());
        let used = cordelia_storage::items::stored_cost(&db).unwrap();
        assert!(used <= room.max_bytes, "{used} > {}", room.max_bytes);
        // The channel that was refused, or was the newest when the cap was
        // passed, is not held; all the others are.
        let refused = channel(newer.len() + 1);
        assert_eq!(holds(&db, &refused), 0);

        // The first channel grows. Each write is taken, and the newest
        // channels go, newest first; the first channel is never touched.
        let mut dropped = 0;
        for write in 1..=4 {
            assert_eq!(
                relay_store(&db, &mut room, &first, ENTRY),
                Ok(true),
                "write {write}"
            );
            assert_eq!(holds(&db, &first), (ENTRY * (write + 1)) as u64);
            let used = cordelia_storage::items::stored_cost(&db).unwrap();
            assert!(used <= room.max_bytes, "{used} > {}", room.max_bytes);
            // Whatever was dropped is a suffix of the newer channels.
            let held: Vec<bool> = newer.iter().map(|c| holds(&db, c) > 0).collect();
            let kept = held.iter().take_while(|h| **h).count();
            assert!(
                held[kept..].iter().all(|h| !h),
                "not newest first: {held:?}"
            );
            dropped = newer.len() - kept;
        }
        assert!(dropped >= 3, "nothing made room: {dropped}");
    }

    /// T3. One channel may hold only so much at a relay, and one address
    /// may make a relay hold only so many new channels in an hour.
    #[test]
    fn a_relay_limits_one_channel_and_new_channels_from_one_address() {
        use cordelia_core::protocol::NEW_CHANNELS_PER_ADDRESS_PER_HOUR;
        use cordelia_network::messages::REFUSED_FULL;
        let db = cordelia_storage::db::open_in_memory().unwrap();

        // One channel: two entries fit in its share, a third does not.
        let mut room = RelayRoom::new(u64::MAX, None, None);
        room.max_channel_bytes = 150_000;
        let full = channel(100);
        assert_eq!(relay_store(&db, &mut room, &full, 60_000), Ok(true));
        assert_eq!(relay_store(&db, &mut room, &full, 60_000), Ok(true));
        assert_eq!(
            relay_store(&db, &mut room, &full, 60_000),
            Err(REFUSED_FULL)
        );
        assert_eq!(holds(&db, &full), 120_000);
        // A smaller one still fits, and another channel is unaffected.
        assert_eq!(relay_store(&db, &mut room, &full, 20_000), Ok(true));
        assert_eq!(relay_store(&db, &mut room, &channel(101), 60_000), Ok(true));

        // New channels from one address.
        let rates = std::sync::Mutex::new(Rates::default());
        let address: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        let mut room = RelayRoom::new(u64::MAX, Some(&rates), Some(address));
        for n in 0..NEW_CHANNELS_PER_ADDRESS_PER_HOUR {
            assert_eq!(
                relay_store(&db, &mut room, &channel(200 + n), 100),
                Ok(true),
                "{n}"
            );
        }
        assert_eq!(
            relay_store(&db, &mut room, &channel(300), 100),
            Err(REFUSED_FULL)
        );
        // A channel it already made the relay hold is still written to.
        assert_eq!(relay_store(&db, &mut room, &channel(200), 100), Ok(true));
        // Another address, and a relay this one lists, are not affected.
        let elsewhere: std::net::IpAddr = "192.0.2.8".parse().unwrap();
        let mut room = RelayRoom::new(u64::MAX, Some(&rates), Some(elsewhere));
        assert_eq!(relay_store(&db, &mut room, &channel(301), 100), Ok(true));
        let mut room = RelayRoom::new(u64::MAX, None, None);
        assert_eq!(relay_store(&db, &mut room, &channel(302), 100), Ok(true));
    }

    /// T3. What one channel may hold at a relay counts each entry as its
    /// ciphertext and what an entry takes beyond it. Entries of eight bytes
    /// cannot be stored in a channel without end.
    #[test]
    fn small_entries_count_for_what_they_take_in_a_channel() {
        use cordelia_core::protocol::entry_cost;
        use cordelia_network::messages::REFUSED_FULL;
        const SMALL: usize = 8;
        let db = cordelia_storage::db::open_in_memory().unwrap();
        let mut room = RelayRoom::new(u64::MAX, None, None);
        // Room for a hundred of them, and half of one more.
        room.max_channel_bytes = 100 * entry_cost(SMALL) + entry_cost(SMALL) / 2;
        let small = channel(400);
        for n in 0..100 {
            assert_eq!(relay_store(&db, &mut room, &small, SMALL), Ok(true), "{n}");
        }
        assert_eq!(
            relay_store(&db, &mut room, &small, SMALL),
            Err(REFUSED_FULL)
        );
        // The next push finds the same: what the channel holds is counted
        // the same way when it is read back.
        let mut next = RelayRoom::new(u64::MAX, None, None);
        next.max_channel_bytes = room.max_channel_bytes;
        assert_eq!(
            relay_store(&db, &mut next, &small, SMALL),
            Err(REFUSED_FULL)
        );
        assert_eq!(holds(&db, &small), 100 * SMALL as u64);
    }

    /// T3. A write that does not make a channel hold more is always taken.
    /// So in a channel that is over its share, because it was written
    /// before each entry counted for what it takes, a device can still
    /// edit and delete what it wrote there, and the channel can shrink.
    /// Without this every write to it would be refused for good.
    ///
    /// It is the device that wrote an entry that can change it there. What
    /// another device writes under the same name is an entry of its own,
    /// and makes the channel hold more.
    #[test]
    fn in_a_channel_over_its_share_a_device_can_still_change_what_it_wrote() {
        use cordelia_core::protocol::entry_cost;
        use cordelia_network::messages::REFUSED_FULL;
        const ENTRY: usize = 10_000;
        let db = cordelia_storage::db::open_in_memory().unwrap();
        let over = channel(800);
        let name = |n: u8| [n; 32];

        // Three entries under names, taken when there was room for them.
        let mut room = RelayRoom::new(u64::MAX, None, None);
        for n in 0..3 {
            assert_eq!(
                relay_store_named(&db, &mut room, &over, name(n), 1, ENTRY),
                Ok(true),
                "{n}"
            );
        }

        // Now a channel may hold only one such entry: this one holds three.
        let mut room = RelayRoom::new(u64::MAX, None, None);
        room.max_channel_bytes = entry_cost(ENTRY);
        // Another name is refused, and so is an edit larger than what it
        // replaces.
        assert_eq!(
            relay_store_named(&db, &mut room, &over, name(9), 1, 100),
            Err(REFUSED_FULL)
        );
        assert_eq!(
            relay_store_named(&db, &mut room, &over, name(0), 2, ENTRY + 1),
            Err(REFUSED_FULL)
        );
        // An edit of the same size is taken, and a smaller one.
        assert_eq!(
            relay_store_named(&db, &mut room, &over, name(0), 2, ENTRY),
            Ok(true)
        );
        assert_eq!(
            relay_store_named(&db, &mut room, &over, name(1), 2, 100),
            Ok(true)
        );
        // It has shrunk by that much, and is still over: still no new name.
        assert_eq!(holds(&db, &over), (2 * ENTRY + 100) as u64);
        assert_eq!(
            relay_store_named(&db, &mut room, &over, name(9), 1, 100),
            Err(REFUSED_FULL)
        );
        // Nor an edit by another device, however small: under its key the
        // name is a new entry.
        let another = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
        assert_eq!(
            relay_store_named_by(&db, &mut room, &another, &over, name(2), 2, 100),
            Err(REFUSED_FULL)
        );
        assert_eq!(holds(&db, &over), (2 * ENTRY + 100) as u64);
    }

    /// T3. Only what is stored counts for what a channel holds. A revision
    /// older than the one held is taken, since it would not make the
    /// channel hold more, and is then not stored. If it were counted as if
    /// it had replaced the larger one, each copy of it in a push would make
    /// the channel look emptier, and new entries would be taken into room
    /// the channel does not have.
    #[test]
    fn a_revision_that_is_not_stored_makes_no_room_in_a_channel() {
        use cordelia_core::protocol::entry_cost;
        use cordelia_network::messages::REFUSED_FULL;
        const ENTRY: usize = 10_000;
        const SMALL: usize = 100;
        let db = cordelia_storage::db::open_in_memory().unwrap();
        let full = channel(801);
        let name = |n: u8| [n; 32];

        // One entry under a name, at its second revision, in a channel
        // with room for it and not for one more, however small.
        let mut room = RelayRoom::new(u64::MAX, None, None);
        room.max_channel_bytes = entry_cost(ENTRY) + entry_cost(SMALL) - 1;
        assert_eq!(
            relay_store_named(&db, &mut room, &full, name(0), 2, ENTRY),
            Ok(true)
        );
        assert_eq!(
            relay_store_named(&db, &mut room, &full, name(9), 1, SMALL),
            Err(REFUSED_FULL)
        );

        // Copies of its first revision, small ones: taken, and not stored.
        for copy in 0..3 {
            assert_eq!(
                relay_store_named(&db, &mut room, &full, name(0), 1, SMALL),
                Ok(false),
                "{copy}"
            );
        }
        // There is still no room for another name: in this push,
        assert_eq!(
            relay_store_named(&db, &mut room, &full, name(9), 1, SMALL),
            Err(REFUSED_FULL)
        );
        // and in the next.
        let mut next = RelayRoom::new(u64::MAX, None, None);
        next.max_channel_bytes = room.max_channel_bytes;
        assert_eq!(
            relay_store_named(&db, &mut next, &full, name(9), 1, SMALL),
            Err(REFUSED_FULL)
        );
        assert_eq!(holds(&db, &full), ENTRY as u64);
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

    /// A relay asks every peer connected to it which channels it holds, not
    /// only its hot peers: a peer that has just connected at once, and then
    /// when the fetch from it says. Two relays that list each other are
    /// each other's hot peer, so this is how a relay comes to ask its
    /// devices.
    #[test]
    fn a_relay_asks_the_peers_that_are_not_hot_when_they_connect_and_again_later() {
        use std::time::{Duration, Instant};
        let peer = |n: u8| NodeId([n; 32]);
        let (relay, a, b) = (peer(1), peer(2), peer(3));
        let every = Duration::from_secs(600);
        let window = Duration::from_secs(cordelia_core::protocol::RATE_WINDOW_SECS);
        let start = Instant::now();
        let connected = vec![relay.clone(), a.clone(), b.clone()];
        let hot = vec![relay.clone()];
        let mut ask_next = std::collections::HashMap::new();

        // Both devices at the first cycle; the hot peer is fetched from
        // every cycle and is not among them.
        assert_eq!(
            peers_to_ask(&connected, &hot, &mut ask_next, start),
            vec![a.clone(), b.clone()]
        );

        // The fetch from A got all of it: A is asked again after the wait.
        // B's allowance ran out: B is asked when it has room again.
        ask_next.insert(a.clone(), next_ask(Fetched::All, every, start).unwrap());
        ask_next.insert(
            b.clone(),
            next_ask(Fetched::AllowanceUsed, every, start).unwrap(),
        );
        assert!(
            peers_to_ask(
                &connected,
                &hot,
                &mut ask_next,
                start + Duration::from_secs(10)
            )
            .is_empty()
        );
        assert_eq!(
            peers_to_ask(&connected, &hot, &mut ask_next, start + window),
            vec![b.clone()]
        );
        ask_next.insert(
            b.clone(),
            next_ask(Fetched::All, every, start + window).unwrap(),
        );
        assert!(
            peers_to_ask(
                &connected,
                &hot,
                &mut ask_next,
                start + every - Duration::from_secs(1)
            )
            .is_empty()
        );
        assert_eq!(
            peers_to_ask(&connected, &hot, &mut ask_next, start + every),
            vec![a.clone()]
        );

        // More to fetch now is the next cycle; no proper answer waits a
        // window, as a used allowance does.
        assert_eq!(next_ask(Fetched::More, every, start), None);
        assert_eq!(
            next_ask(Fetched::Failed, every, start),
            Some(start + window)
        );
        assert_eq!(next_ask(Fetched::All, every, start), Some(start + every));

        // A peer that has gone is forgotten, and asked as soon as it is back.
        let later = start + every + window;
        ask_next.insert(b.clone(), later + every);
        assert!(peers_to_ask(std::slice::from_ref(&relay), &hot, &mut ask_next, later).is_empty());
        assert_eq!(
            peers_to_ask(&connected, &hot, &mut ask_next, later),
            vec![a.clone(), b.clone()]
        );

        // A relay whose hot peer is a device asks its other devices too.
        let mut ask_next = std::collections::HashMap::new();
        assert_eq!(
            peers_to_ask(
                &[a.clone(), b.clone()],
                std::slice::from_ref(&a),
                &mut ask_next,
                start
            ),
            vec![b]
        );
    }

    /// T3. What a peer lists is the peer's to write, so a relay bounds it:
    /// only IDs that could be a channel's, each once, and so many of them.
    /// A peer cannot have a relay ask about, and keep a place in, any
    /// number of channels with names of any length.
    #[test]
    fn what_a_peer_lists_is_bounded_before_a_relay_asks_about_it() {
        use cordelia_core::protocol::{MAX_CHANNEL_ID_LEN, MAX_CHANNELS_ASKED_OF_A_PEER};
        let good = |n: usize| channel(n);

        // An ID that is too long, one with a space, one that is not text a
        // channel's ID could be, and an empty one are dropped; one listed
        // twice is asked about once.
        let listed = vec![
            good(1),
            "x".repeat(MAX_CHANNEL_ID_LEN + 1),
            "grp_with a space".to_string(),
            "grp_\u{7}bell".to_string(),
            String::new(),
            good(1),
            "x".repeat(MAX_CHANNEL_ID_LEN),
        ];
        let mut asked = channels_to_ask(Vec::new(), listed, usize::MAX);
        asked.sort();
        let mut expected = vec![good(1), "x".repeat(MAX_CHANNEL_ID_LEN)];
        expected.sort();
        assert_eq!(asked, expected);

        // However many a peer lists, only so many are asked about.
        let many: Vec<String> = (0..5 * MAX_CHANNELS_ASKED_OF_A_PEER).map(good).collect();
        let asked = channels_to_ask(Vec::new(), many.clone(), MAX_CHANNELS_ASKED_OF_A_PEER);
        assert_eq!(asked.len(), MAX_CHANNELS_ASKED_OF_A_PEER);
        assert!(asked.iter().all(|id| many.contains(id)));

        // This node's own channels are asked about whatever the peer lists.
        let asked = channels_to_ask(vec![good(9_999_999)], many, 0);
        assert_eq!(asked, vec![good(9_999_999)]);
    }

    /// A node's database with a channel of each kind, the node the owner
    /// of each and one item in each: its inbox, a group, a local channel,
    /// and a swarm channel, made as a version up to 0.2.0-alpha.7 made one
    /// for itself each time it started. Returns their IDs in that order.
    fn a_node_that_holds_a_swarm_channel(
        own: &cordelia_crypto::identity::NodeIdentity,
    ) -> (rusqlite::Connection, [String; 4]) {
        use cordelia_storage::{channels, naming};
        let db = cordelia_storage::db::open_in_memory().unwrap();
        let pk = own.public_key();

        let inbox = naming::inbox_channel_id(&pk);
        channels::ensure_inbox(&db, &inbox, &pk, true).unwrap();
        channels::ensure_group(&db, A_CHANNEL, None, "realtime", &pk).unwrap();
        channels::add_member(&db, A_CHANNEL, &pk, "owner").unwrap();
        let local = "cordelia:local:550e8400".to_string();
        channels::create_local(&db, &local, &pk, None).unwrap();
        let swarm = naming::swarm_channel_id("lead_a1b2");
        db.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, scope, creator_id, created_at, updated_at)
             VALUES (?1, 'named', 'realtime', 'invite_only', 'network', ?2, '2026-10-02', '2026-10-02')",
            rusqlite::params![swarm, pk.as_slice()],
        )
        .unwrap();
        channels::add_member(&db, &swarm, &pk, "owner").unwrap();

        let ids = [inbox, A_CHANNEL.to_string(), local, swarm];
        for (n, channel) in ids.iter().enumerate() {
            let item = arriving_in(own, channel, vec![n as u8; 40]);
            assert_eq!(
                store_item(&db, &item, "personal", &pk),
                Ok(true),
                "{channel}"
            );
        }
        (db, ids)
    }

    fn sorted(mut ids: Vec<String>) -> Vec<String> {
        ids.sort();
        ids
    }

    /// A channel ID that holds a name is never told to a peer. A node that
    /// holds a swarm channel announces its other network-scope channels,
    /// and not that one.
    #[test]
    fn a_node_announces_no_channel_whose_id_holds_a_name() {
        use cordelia_storage::{channels, naming};
        let own = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
        let (db, [inbox, group, _local, swarm]) = a_node_that_holds_a_swarm_channel(&own);
        // It is one of the node's network-scope channels, like the others.
        assert!(
            channels::list_network_channels(&db, &own.public_key())
                .unwrap()
                .iter()
                .any(|c| c.channel_id == swarm)
        );

        let announced = channels_to_announce(&db, &own.public_key());
        assert_eq!(sorted(announced.clone()), sorted(vec![inbox, group]));
        // So no announcement the node builds names it.
        for channel_id in &announced {
            let d = cordelia_network::channel_announce::announcement(&own, channel_id);
            assert!(naming::may_be_told_to_a_peer(&d.channel_id), "{channel_id}");
        }
    }

    /// When one of its own relays asks a node which channels it holds, the
    /// node lists those whose IDs may be told to a peer. A swarm channel
    /// it holds is not among them, whoever asks.
    #[test]
    fn a_node_lists_no_channel_whose_id_holds_a_name() {
        let own = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
        let (db, [inbox, group, local, swarm]) = a_node_that_holds_a_swarm_channel(&own);
        // It holds items for it, as for the others.
        assert!(
            cordelia_storage::channels::list_stored_channel_ids(&db)
                .unwrap()
                .contains(&swarm)
        );

        assert_eq!(
            sorted(channels_it_lists(&db, false)),
            sorted(vec![inbox.clone(), group.clone()])
        );
        // A swarm peer is told of local channels too, and still not of it.
        assert_eq!(
            sorted(channels_it_lists(&db, true)),
            sorted(vec![inbox, group, local])
        );
    }

    /// To fetch a channel from a peer is to ask for it by its ID. A node
    /// that holds a swarm channel fetches its other channels, the inbox
    /// first, and does not ask for that one: neither a device, which
    /// fetches the channels it is a member of, nor a relay, which fetches
    /// those it holds items for.
    #[test]
    fn a_node_fetches_no_channel_whose_id_holds_a_name() {
        let own = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
        let (db, [inbox, group, local, swarm]) = a_node_that_holds_a_swarm_channel(&own);
        let pk = own.public_key();
        assert!(
            cordelia_storage::channels::is_member(&db, &swarm, &pk).unwrap(),
            "the node is a member of it, as of the others"
        );

        for role in ["personal", "relay"] {
            let fetched = channels_to_fetch(&db, role, &pk);
            assert_eq!(fetched[0], inbox, "{role}: the inbox comes first");
            assert_eq!(
                sorted(fetched),
                sorted(vec![inbox.clone(), group.clone(), local.clone()]),
                "{role}"
            );
        }
    }

    /// A relay asks a peer about the channels the peer lists. One whose ID
    /// may not be told to a peer is not asked about, though the peer
    /// listed it: asking sends the ID.
    #[test]
    fn a_relay_asks_about_no_channel_whose_id_holds_a_name() {
        let swarm = cordelia_storage::naming::swarm_channel_id("lead_a1b2");
        let asked = channels_to_ask(Vec::new(), vec![channel(1), swarm, channel(2)], usize::MAX);
        assert_eq!(sorted(asked), vec![channel(1), channel(2)]);
    }

    /// A node asked for the items of a channel answers that it holds none
    /// if the channel's ID may not be told to a peer: each item it would
    /// list carries the ID. It answers for its other channels as before,
    /// and for a local channel to a swarm peer only.
    #[test]
    fn a_node_answers_no_peer_for_a_channel_whose_id_holds_a_name() {
        let own = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
        let (db, [inbox, group, local, swarm]) = a_node_that_holds_a_swarm_channel(&own);

        for to_a_swarm_peer in [false, true] {
            assert!(!answers_for(&db, &swarm, to_a_swarm_peer));
            assert!(answers_for(&db, &inbox, to_a_swarm_peer));
            assert!(answers_for(&db, &group, to_a_swarm_peer));
            // A channel it does not hold: the answer is an empty page.
            assert!(answers_for(&db, &channel(7), to_a_swarm_peer));
        }
        assert!(!answers_for(&db, &local, false));
        assert!(answers_for(&db, &local, true));
    }

    /// A relay passes on to the relays it lists what it is sent, but not
    /// an item of a channel whose ID may not be told to a peer: an item
    /// carries its channel's ID.
    #[test]
    fn a_relay_passes_on_no_item_of_a_channel_whose_id_holds_a_name() {
        let own = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
        let (db, [inbox, group, local, swarm]) = a_node_that_holds_a_swarm_channel(&own);

        assert!(!passed_on(Some(&db), &swarm));
        assert!(passed_on(Some(&db), &inbox));
        assert!(passed_on(Some(&db), &group));
        assert!(!passed_on(Some(&db), &local), "local scope, as before");
        // Whether or not the database can be asked for the channel's scope.
        assert!(!passed_on(None, &swarm));
        assert!(passed_on(None, &group));
    }

    /// A relay stores nothing of a channel whose ID may not be told to a
    /// peer: it would hold, under an ID that holds a name, what it never
    /// lists, serves or passes on. An item of such a channel is refused as
    /// one that is not valid, and nothing is made for its channel. A
    /// device, which stores only what belongs in the channels it holds, is
    /// as it was.
    #[test]
    fn a_relay_stores_no_item_of_a_channel_whose_id_holds_a_name() {
        use cordelia_network::messages::REFUSED_INVALID;
        use cordelia_storage::channels;
        let relay = cordelia_storage::db::open_in_memory().unwrap();
        let author = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
        let swarm = cordelia_storage::naming::swarm_channel_id("lead_a1b2");

        let item = arriving_in(&author, &swarm, vec![7; 40]);
        assert_eq!(
            store_item(&relay, &item, "relay", &[0x0E; 32]),
            Err(REFUSED_INVALID)
        );
        assert!(!channels::exists(&relay, &swarm).unwrap());
        assert_eq!(
            channels::list_stored_channel_ids(&relay).unwrap(),
            Vec::<String>::new()
        );

        // An item of another channel, by the same author, is stored.
        let other = arriving_in(&author, A_CHANNEL, vec![8; 40]);
        assert_eq!(store_item(&relay, &other, "relay", &[0x0E; 32]), Ok(true));

        // A device that holds such a channel stores what arrives in it,
        // as it stores what arrives in any channel of that kind.
        let (device, [_, _, _, held]) = a_node_that_holds_a_swarm_channel(&author);
        let more = arriving_in(&author, &held, vec![9; 40]);
        assert_eq!(
            store_item(&device, &more, "personal", &author.public_key()),
            Ok(true)
        );
    }

    /// Text that a peer chose goes into a warning as its first 64
    /// characters, with whatever could act on a terminal or pass for
    /// another line shown as escapes. A peer chooses what an announcement
    /// names and how long the name is, and the error for an announcement
    /// that is not valid holds that name too.
    #[test]
    fn what_a_peer_sent_goes_into_a_warning_short_and_escaped() {
        assert_eq!(as_a_peer_sent_it("grp_550e8400"), "grp_550e8400");
        assert_eq!(as_a_peer_sent_it(&"x".repeat(100_000)), "x".repeat(64));
        // Characters are counted, not bytes.
        assert_eq!(
            as_a_peer_sent_it(&"\u{e9}".repeat(100)),
            "\u{e9}".repeat(64)
        );

        let hostile = "grp_\u{1b}[2J\n2026-10-05 INFO a line of its own\u{202e}";
        let shown = as_a_peer_sent_it(hostile);
        assert!(!shown.chars().any(char::is_control), "{shown:?}");
        assert!(shown.starts_with("grp_\\u{1b}[2J\\n2026"), "{shown:?}");
        assert!(shown.ends_with("\\u{202e}"), "{shown:?}");

        let error = cordelia_network::channel_announce::ChannelAnnounceError::InvalidSignature(
            format!("{}\n", "x".repeat(100_000)),
        );
        let shown = as_a_peer_sent_it(&error.to_string());
        assert_eq!(shown.chars().count(), 64);
        assert!(shown.starts_with("invalid descriptor signature"), "{shown}");
    }

    /// T3. What a relay keeps for a peer it fetches from is bounded for
    /// each peer, and forgotten when the peer goes. A peer cannot list new
    /// names in every pass, or connect under key after key, and leave a
    /// relay keeping something for each.
    #[test]
    fn what_is_kept_for_a_peer_is_bounded_and_forgotten_when_it_goes() {
        let peer = |n: u8| NodeId([n; 32]);
        let at = |after: u64| Place {
            after,
            step: 0,
            done: false,
        };
        // Keep a place as a fetch does: with the mark taken when it began.
        let keep = |kept: &mut Kept, p: u8, c: usize, after: u64| {
            let (_, mark) = kept.get(&peer(p), &channel(c));
            kept.keep(&peer(p), &channel(c), at(after), 4, mark)
        };
        let place = |kept: &Kept, p: u8, c: usize| kept.get(&peer(p), &channel(c)).0;
        let mut kept = Kept::default();

        // So many channels for one peer, and no more. One that is kept
        // already can still be moved.
        for c in 0..4 {
            assert!(keep(&mut kept, 1, c, 7));
        }
        assert!(keep(&mut kept, 1, 0, 8));
        assert_eq!(kept.kept_for(&peer(1)), 4);
        // One more takes the place of the one kept longest ago (none is
        // caught up here), and is kept.
        assert!(keep(&mut kept, 1, 4, 7));
        assert_eq!(kept.kept_for(&peer(1)), 4);
        assert_eq!(place(&kept, 1, 1), Place::default(), "kept longest ago");
        assert_eq!(place(&kept, 1, 0), at(8));
        assert_eq!(place(&kept, 1, 4), at(7));
        // The start is not kept: it is what a channel with nothing kept
        // has. So nothing is kept for a name under which nothing is listed.
        assert!(keep(&mut kept, 2, 9, 0));
        assert_eq!(kept.kept_for(&peer(2)), 0);
        // Another peer has its own.
        assert!(keep(&mut kept, 2, 4, 9));
        assert!(keep(&mut kept, 3, 0, 9));
        // The size of page asked for is kept with the place.
        let (_, mark) = kept.get(&peer(3), &channel(0));
        let smaller = Place {
            after: 9,
            step: 2,
            done: false,
        };
        assert!(kept.keep(&peer(3), &channel(0), smaller, 4, mark));
        assert_eq!(place(&kept, 3, 0), smaller);

        // A channel that is to be listed again is forgotten for every
        // peer, and a fetch that was under way does not put its place back.
        let (_, under_way) = kept.get(&peer(1), &channel(2));
        kept.forget_channels(&[channel(0)]);
        assert_eq!(place(&kept, 1, 0), Place::default());
        assert_eq!(place(&kept, 3, 0), Place::default());
        assert_eq!(place(&kept, 1, 2), at(7));
        assert!(!kept.keep(&peer(1), &channel(0), at(50), 4, under_way));
        assert!(!kept.keep(&peer(1), &channel(2), at(50), 4, under_way));
        assert_eq!(place(&kept, 1, 0), Place::default());
        assert_eq!(place(&kept, 1, 2), at(7));

        // A peer that connects again starts from nothing, and a fetch that
        // was under way from it does not put its place back: the peer may
        // have a new store, where the same place is somewhere else.
        let (_, under_way) = kept.get(&peer(1), &channel(2));
        let (_, of_another) = kept.get(&peer(2), &channel(4));
        kept.forget_peer(&peer(1));
        assert_eq!(kept.kept_for(&peer(1)), 0);
        assert!(!kept.keep(&peer(1), &channel(2), at(50), 4, under_way));
        assert_eq!(kept.kept_for(&peer(1)), 0);
        // Nor after it has connected once more.
        let (_, since) = kept.get(&peer(1), &channel(2));
        kept.forget_peer(&peer(1));
        assert!(!kept.keep(&peer(1), &channel(2), at(50), 4, since));
        // One peer's connecting again costs no other peer's fetch its
        // place.
        assert!(kept.keep(&peer(2), &channel(4), at(10), 4, of_another));
        assert_eq!(place(&kept, 2, 4), at(10));

        // Peers that are no longer connected are forgotten, and a fetch
        // under way from one of them keeps nothing.
        assert!(keep(&mut kept, 1, 1, 7));
        let (_, under_way) = kept.get(&peer(1), &channel(1));
        kept.forget_gone(&[peer(2)]);
        assert_eq!(kept.kept_for(&peer(1)), 0);
        assert_eq!(kept.kept_for(&peer(3)), 0);
        assert_eq!(place(&kept, 2, 4), at(10));
        assert!(!kept.keep(&peer(1), &channel(1), at(9), 4, under_way));
        assert_eq!(kept.total(), 1);
    }

    /// T3. When a peer has as many places kept as it may, a caught-up
    /// channel's place makes room before one that is still being fetched,
    /// whatever was kept longest ago. So a long channel keeps its place
    /// from one pass to the next, though the peer lists more channels than
    /// a relay keeps places for.
    #[test]
    fn a_channel_still_being_fetched_keeps_its_place_before_caught_up_ones() {
        let peer = NodeId([1; 32]);
        let mut kept = Kept::default();
        let keep = |kept: &mut Kept, c: usize, after: u64, done: bool| {
            let (_, mark) = kept.get(&peer, &channel(c));
            let place = Place {
                after,
                step: 0,
                done,
            };
            kept.keep(&peer, &channel(c), place, 3, mark)
        };
        let after = |kept: &Kept, c: usize| kept.get(&peer, &channel(c)).0.after;

        // A long channel still being fetched, kept first; then two that
        // are caught up.
        assert!(keep(&mut kept, 0, 1000, false));
        assert!(keep(&mut kept, 1, 5, true));
        assert!(keep(&mut kept, 2, 5, true));
        // One more: the caught-up one kept longest ago makes room.
        assert!(keep(&mut kept, 3, 5, true));
        assert_eq!(after(&kept, 0), 1000, "the long channel kept its place");
        assert_eq!(after(&kept, 1), 0);
        // When every place is still being fetched, the one kept longest ago
        // makes room.
        assert!(keep(&mut kept, 2, 7, false));
        assert!(keep(&mut kept, 3, 7, false));
        assert!(keep(&mut kept, 4, 7, false));
        assert_eq!(after(&kept, 0), 0);
        assert_eq!(kept.kept_for(&peer), 3);
    }

    /// T3. A fetch under way goes on from its own place when another
    /// channel's place is forgotten, and starts its channel again when that
    /// channel's place is forgotten or the peer connects again. Before, any
    /// channel's being listed again stopped every fetch under way from
    /// keeping its place for the rest of its channel.
    #[test]
    fn a_fetch_starts_its_channel_again_only_when_that_channel_is_forgotten() {
        let peer = NodeId([1; 32]);
        let at = |after: u64| Place {
            after,
            step: 0,
            done: false,
        };
        let mut kept = Kept::default();

        // A fetch keeps its place in channel 0, page by page, and brings
        // itself up to date before each.
        let catch_up = |kept: &Kept, here: Place, mark: Mark| {
            let (mut here, mut mark) = (here, mark);
            kept.catch_up(&peer, &channel(0), &mut here, &mut mark);
            (here, mark)
        };
        let (_, mark) = kept.get(&peer, &channel(0));
        assert!(kept.keep(&peer, &channel(0), at(100), 1024, mark));
        // Nothing forgotten: it goes on.
        assert_eq!(catch_up(&kept, at(100), mark), (at(100), mark));
        // Another channel is to be listed again: it goes on from its own
        // place, with a mark it can keep its next place with.
        kept.forget_channels(&[channel(1)]);
        let (place, fresh) = catch_up(&kept, at(100), mark);
        assert_eq!(place.after, 100);
        assert!(kept.keep(&peer, &channel(0), at(200), 1024, fresh));
        // Its own channel is to be listed again: it starts from the start.
        kept.forget_channels(&[channel(0)]);
        let (place, fresh) = catch_up(&kept, at(200), fresh);
        assert_eq!(place, Place::default());
        // So does it when the peer connects again.
        assert!(kept.keep(&peer, &channel(0), at(50), 1024, fresh));
        kept.forget_peer(&peer);
        let (place, _) = catch_up(&kept, at(50), fresh);
        assert_eq!(place, Place::default());
        // A place it could not keep, because something was forgotten while
        // its page was on its way: it goes back to the place that was kept,
        // and lists that page again.
        let (_, mark) = kept.get(&peer, &channel(0));
        assert!(kept.keep(&peer, &channel(0), at(10), 1024, mark));
        kept.forget_channels(&[channel(1)]);
        assert!(!kept.keep(&peer, &channel(0), at(20), 1024, mark));
        let (place, _) = catch_up(&kept, at(20), mark);
        assert_eq!(place.after, 10);
    }

    /// T3. Against its address, what a relay fetches from one connection
    /// counts for no more than a connection may be fetched from in a
    /// minute, whatever its answers hold. An answer can hold more than was
    /// asked for. If all of it counted against the address, a few
    /// connections could use up what every device at their address may be
    /// fetched from.
    #[test]
    fn a_connection_cannot_use_up_what_its_address_may_be_fetched_from() {
        use cordelia_core::protocol::{MAX_CONNECTIONS_PER_IP, PUSH_BYTES_PER_PEER_PER_MINUTE};
        let peer = |n: u8| NodeId([n; 32]);
        let address: std::net::IpAddr = "192.0.2.9".parse().unwrap();
        let mut rates = Rates::default();

        // All but one of an address's connections answer with four times
        // what a connection may be fetched from. Each has used its own
        // allowance.
        let others = MAX_CONNECTIONS_PER_IP as u8 - 1;
        for n in 1..=others {
            rates.fetched(&peer(n), address, 4 * PUSH_BYTES_PER_PEER_PER_MINUTE);
            assert_eq!(rates.fetch_room(&peer(n), address), 0, "{n}");
        }
        // The last still has all a connection may be fetched from.
        assert_eq!(
            rates.fetch_room(&peer(others + 1), address),
            PUSH_BYTES_PER_PEER_PER_MINUTE
        );
        // And what the others send after that counts for nothing more
        // against the address.
        for n in 1..=others {
            rates.fetched(&peer(n), address, 4 * PUSH_BYTES_PER_PEER_PER_MINUTE);
        }
        assert_eq!(
            rates.fetch_room(&peer(others + 1), address),
            PUSH_BYTES_PER_PEER_PER_MINUTE
        );
    }

    /// One fetch at a time from each peer: a peer that answers slowly does
    /// not have fetches pile up behind it.
    #[test]
    fn one_fetch_at_a_time_runs_from_each_peer() {
        let peer = |n: u8| NodeId([n; 32]);
        let fetching = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
        let first = Fetching::begin(&fetching, &peer(1)).expect("the first begins");
        assert!(Fetching::begin(&fetching, &peer(1)).is_none());
        // Another peer is not held up, and its fetch ends here.
        assert!(Fetching::begin(&fetching, &peer(2)).is_some());
        assert!(Fetching::begin(&fetching, &peer(2)).is_some());
        drop(first);
        assert!(Fetching::begin(&fetching, &peer(1)).is_some());
    }

    /// T3. What a relay fetches from a peer is bounded as what the peer may
    /// push is: so many bytes a minute for the connection, and five times
    /// that for its address. It is counted apart from what the peer pushes,
    /// so a relay that asks a device for its channels never makes the
    /// device's own pushes a breach.
    #[test]
    fn what_a_relay_fetches_from_a_peer_is_bounded_as_what_the_peer_may_push_is() {
        use cordelia_core::protocol::{MAX_CONNECTIONS_PER_IP, PUSH_BYTES_PER_PEER_PER_MINUTE};
        let address: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        let peer = |n: u8| NodeId([n; 32]);
        let mut rates = Rates::default();

        assert_eq!(
            rates.fetch_room(&peer(1), address),
            PUSH_BYTES_PER_PEER_PER_MINUTE
        );
        rates.fetched(&peer(1), address, PUSH_BYTES_PER_PEER_PER_MINUTE - 1000);
        assert_eq!(rates.fetch_room(&peer(1), address), 1000);
        rates.fetched(&peer(1), address, 1000);
        assert_eq!(rates.fetch_room(&peer(1), address), 0);

        // Other connections from the address have room of their own, until
        // the address has had its share.
        for n in 2..=MAX_CONNECTIONS_PER_IP as u8 {
            assert_eq!(
                rates.fetch_room(&peer(n), address),
                PUSH_BYTES_PER_PEER_PER_MINUTE,
                "{n}"
            );
            rates.fetched(&peer(n), address, PUSH_BYTES_PER_PEER_PER_MINUTE);
        }
        assert_eq!(rates.fetch_room(&peer(100), address), 0);

        // What the relay fetched is not held against what the peer pushes.
        assert_eq!(
            rates.pushed(&peer(1), address, PUSH_BYTES_PER_PEER_PER_MINUTE),
            Ok(())
        );

        // The address's allowance outlasts its connections, as for pushes:
        // closing them all does not give it more to be fetched. (An address
        // from which only fetching was counted, and connections that had
        // been fetched from nowhere else, to be sure of that.)
        let fetched_from: std::net::IpAddr = "192.0.2.9".parse().unwrap();
        for n in 1..=MAX_CONNECTIONS_PER_IP as u8 {
            rates.fetched(&peer(100 + n), fetched_from, PUSH_BYTES_PER_PEER_PER_MINUTE);
        }
        rates.prune(&[], &[]);
        assert_eq!(rates.fetch_room(&peer(200), fetched_from), 0);
    }

    /// What a peer is handed of channels from their secrets counts against
    /// the bytes that may be fetched in a minute: the one allowance that
    /// what a relay fetches from the peer counts against, for the
    /// connection and for its address. A page that either has no room for
    /// is not handed, and nothing is counted for it: no breach either,
    /// however often it is asked for. A page leaves room in both for the
    /// answer to a show, and only that answer uses it (decision
    /// 2026-10-04 §16). The entry that answers a show is always counted,
    /// and takes the allowance over. What a peer pushes is counted apart.
    #[test]
    fn what_a_peer_is_handed_counts_with_what_a_relay_fetches_from_it() {
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

        // Handed, and fetched, and handed: one count.
        assert!(rates.handed(&peer(1), address, MINUTE / 2));
        assert_eq!(rates.fetch_room(&peer(1), address), MINUTE / 2);
        assert_eq!(rates.pull_room(&peer(1), address), MINUTE / 2 - SHOW);
        rates.fetched(&peer(1), address, MINUTE / 4);
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

    /// The older kind's room is counted by its own items, and by nothing
    /// else that the database holds (decision 2026-10-04 §2.5, §16). A
    /// relay that holds a megabyte of entries of channels from their
    /// secrets beside them does, at its cap for the older kind, exactly
    /// what a relay that holds none does: it takes the same channels,
    /// refuses the same one, and drops the same ones to make room. And
    /// what it drops is never of the other kind.
    #[test]
    fn the_older_kinds_room_is_counted_by_its_own_items_whatever_else_the_relay_holds() {
        use cordelia_core::protocol::entry_cost;
        use cordelia_network::messages::REFUSED_FULL;
        use cordelia_storage::relay;
        const ENTRY: usize = 60_000;
        const CAP: u64 = 400_000;

        // What a relay does at its cap for the older kind: what each
        // write came to, and the channels it holds after it.
        fn at_its_cap(db: &rusqlite::Connection) -> Vec<String> {
            let mut room = RelayRoom::new(CAP, None, None);
            let mut done = Vec::new();
            let channels = |from: usize| -> Vec<String> { (from..from + 9).map(channel).collect() };
            let mut note = |what: String, db: &rusqlite::Connection| {
                let held: Vec<usize> = (900..909).filter(|n| holds(db, &channel(*n)) > 0).collect();
                let used = cordelia_storage::items::stored_cost(db).unwrap();
                done.push(format!("{what}: holds {held:?}, {used} in use"));
            };
            // Nine channels, one entry each, the oldest first.
            for id in channels(900) {
                let stored = relay_store(db, &mut room, &id, ENTRY);
                note(format!("{stored:?}"), db);
            }
            // The oldest grows, four times.
            for _ in 0..4 {
                let stored = relay_store(db, &mut room, &channel(900), ENTRY);
                note(format!("{stored:?}"), db);
            }
            // Whether it would take a channel that it does not hold.
            let asked = room.takes_new_channel(db, &channel(950));
            note(format!("{asked:?}"), db);
            done
        }

        let alone = cordelia_storage::db::open_in_memory().unwrap();
        let beside = cordelia_storage::db::open_in_memory().unwrap();
        // The other relay holds sixteen entries of the largest size, of
        // channels from their secrets: more than a megabyte, where its
        // cap for the older kind is 400,000 bytes.
        let author = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
        let mut of_entries = relay::Room::new(u64::MAX);
        for n in 0..16u8 {
            let inside = cordelia_crypto::entry::Inside {
                name: "n".into(),
                value: cordelia_crypto::entry::Value::Text(
                    "x".repeat(cordelia_core::protocol::MAX_ENTRY_NAME_AND_VALUE_BYTES - 1),
                ),
                chain: Some(Vec::new()),
            };
            let entry = cordelia_crypto::entry::Entry::seal(&[n; 32], &author, 1, &inside)
                .unwrap()
                .check()
                .unwrap();
            let asker = relay::Asker::Address("192.0.2.7".parse().unwrap());
            assert_eq!(
                relay::take(&beside, &mut of_entries, &entry, &asker, 1_800_000_000).unwrap(),
                relay::Taken::Stored
            );
        }
        let entries_held = relay::used_bytes(&beside).unwrap();
        assert_eq!(entries_held, 16 * entry_cost(65_536));
        assert!(entries_held > 2 * CAP);
        // None of it counts for the older kind: both relays hold nothing
        // of that.
        assert_eq!(cordelia_storage::items::stored_cost(&beside).unwrap(), 0);

        let did = at_its_cap(&alone);
        assert_eq!(at_its_cap(&beside), did);

        // And what it did is what a relay does at its cap: six channels
        // fit, the seventh takes it over and is itself the newest, so it
        // goes and the write is refused. Then the relay is still under
        // its cap, so the eighth and the ninth are tried the same way.
        let one = entry_cost(ENTRY);
        assert_eq!(6 * one, 366_144);
        let full = format!("Err({REFUSED_FULL:?})");
        for (write, held) in (0..6).map(|n| (n, (900..=900 + n).collect::<Vec<usize>>())) {
            assert_eq!(
                did[write],
                format!(
                    "Ok(true): holds {held:?}, {} in use",
                    (write as u64 + 1) * one
                )
            );
        }
        let six: Vec<usize> = (900..906).collect();
        for refused in &did[6..9] {
            assert_eq!(*refused, format!("{full}: holds {six:?}, 366144 in use"));
        }
        // The oldest grows: each write is taken, and the newest channel
        // goes for it. The oldest is never touched.
        for (write, newest) in [(9, 904), (10, 903), (11, 902), (12, 901)] {
            let held: Vec<usize> = (900..=newest).collect();
            assert_eq!(
                did[write],
                format!("Ok(true): holds {held:?}, 366144 in use")
            );
        }
        // Under its cap, it would take a channel it does not hold.
        assert_eq!(did[13], "Ok(()): holds [900, 901], 366144 in use");
        assert_eq!(did.len(), 14);
        assert_eq!(holds(&alone, &channel(900)), 5 * ENTRY as u64);

        // Making room for the older kind took nothing of the other kind:
        // every entry is still there.
        assert_eq!(relay::used_bytes(&beside).unwrap(), entries_held);
        // At the older kind's cap to the byte, no new channel is taken,
        // whatever the other kind holds.
        let used = cordelia_storage::items::stored_cost(&beside).unwrap();
        let full_room = RelayRoom::new(used, None, None);
        assert_eq!(
            full_room.takes_new_channel(&beside, &channel(950)),
            Err(REFUSED_FULL)
        );
        let a_byte_more = RelayRoom::new(used + 1, None, None);
        assert_eq!(
            a_byte_more.takes_new_channel(&beside, &channel(950)),
            Ok(())
        );
    }

    /// A relay can say whether it would take a channel it does not hold
    /// without counting it, so that it does not fetch what it would then
    /// refuse: not at its cap, and not from an address that has had its
    /// share of new channels.
    #[test]
    fn a_relay_says_whether_it_has_room_for_a_channel_without_counting_it() {
        use cordelia_core::protocol::NEW_CHANNELS_PER_ADDRESS_PER_HOUR;
        use cordelia_network::messages::REFUSED_FULL;
        let db = cordelia_storage::db::open_in_memory().unwrap();
        let rates = std::sync::Mutex::new(Rates::default());
        let address: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        let mut room = RelayRoom::new(u64::MAX, Some(&rates), Some(address));

        // Asking uses none of the address's allowance.
        for n in 0..10 * NEW_CHANNELS_PER_ADDRESS_PER_HOUR {
            assert_eq!(
                room.takes_new_channel(&db, &channel(500 + n)),
                Ok(()),
                "{n}"
            );
        }
        for n in 0..NEW_CHANNELS_PER_ADDRESS_PER_HOUR {
            assert_eq!(
                relay_store(&db, &mut room, &channel(500 + n), 100),
                Ok(true),
                "{n}"
            );
        }
        // The address has had its share.
        assert_eq!(
            room.takes_new_channel(&db, &channel(600)),
            Err(REFUSED_FULL)
        );
        // A relay this one lists is not limited by it.
        let listed = RelayRoom::new(u64::MAX, Some(&rates), None);
        assert_eq!(listed.takes_new_channel(&db, &channel(600)), Ok(()));
        // At the cap, nobody's new channel is taken.
        let used = cordelia_storage::items::stored_cost(&db).unwrap();
        let full = RelayRoom::new(used, Some(&rates), None);
        assert_eq!(
            full.takes_new_channel(&db, &channel(600)),
            Err(REFUSED_FULL)
        );
    }

    /// A channel that a relay dropped to make room is noted, so that it is
    /// listed again from the start, and it is not taken again until a wait
    /// has passed. Without the wait, a relay at its cap would fetch the
    /// channel from a peer, drop it, and fetch it again, without end.
    #[test]
    fn a_channel_a_relay_dropped_is_left_for_a_while_before_it_is_taken_again() {
        use cordelia_network::messages::REFUSED_FULL;
        const ENTRY: usize = 60_000;
        let db = cordelia_storage::db::open_in_memory().unwrap();
        let empty = cordelia_storage::items::stored_cost(&db).unwrap();
        let rates = std::sync::Mutex::new(Rates::default());
        let mut room = RelayRoom::new(empty + 400_000, Some(&rates), None);

        // An older channel and a newer one; the older one grows until the
        // newer one is dropped.
        let (older, newer) = (channel(700), channel(701));
        assert_eq!(relay_store(&db, &mut room, &older, ENTRY), Ok(true));
        assert_eq!(relay_store(&db, &mut room, &newer, ENTRY), Ok(true));
        assert!(room.dropped.is_empty());
        for write in 0..10 {
            assert_eq!(
                relay_store(&db, &mut room, &older, ENTRY),
                Ok(true),
                "{write}"
            );
            if !room.dropped.is_empty() {
                break;
            }
        }
        assert_eq!(room.dropped, vec![newer.clone()]);
        assert_eq!(holds(&db, &newer), 0);

        // It is not taken again yet, even by a relay with room for it.
        let mut roomy = RelayRoom::new(u64::MAX, Some(&rates), None);
        assert_eq!(roomy.takes_new_channel(&db, &newer), Err(REFUSED_FULL));
        assert_eq!(
            relay_store(&db, &mut roomy, &newer, ENTRY),
            Err(REFUSED_FULL)
        );
        // Another channel is.
        assert_eq!(relay_store(&db, &mut roomy, &channel(702), ENTRY), Ok(true));

        // Once the wait has passed, it is.
        let mut rates = Rates::default().ask_again(std::time::Duration::ZERO);
        rates.dropped(&newer);
        assert!(!rates.dropped_lately(&newer));
        let mut rates = Rates::default();
        rates.dropped(&newer);
        assert!(rates.dropped_lately(&newer));
        assert!(!rates.dropped_lately(&older));

        // A channel that is dropped again each time it is taken does not
        // fit: the wait doubles each time, up to 32 times the first.
        let first = std::time::Duration::from_secs(cordelia_core::protocol::RELAY_ASK_AGAIN_SECS);
        assert_eq!(rates.dropped_wait(1), first);
        assert_eq!(rates.dropped_wait(2), 2 * first);
        assert_eq!(rates.dropped_wait(3), 4 * first);
        assert_eq!(rates.dropped_wait(6), 32 * first);
        assert_eq!(rates.dropped_wait(60), 32 * first);
        rates.dropped(&newer);
        rates.dropped(&newer);
        assert_eq!(rates.dropped.get(&newer).map(|(_, times)| *times), Some(3));
    }

    /// A device paces what it pushes to a relay: full batches while there is
    /// room in the minute, then smaller ones, then nothing until there is
    /// room for an entry of the largest size again.
    #[test]
    fn a_device_paces_what_it_pushes_to_a_relay() {
        use cordelia_core::protocol::{
            MAX_ITEM_BYTES, OUTBOX_BATCH_MAX_BYTES, OUTBOX_BYTES_PER_MINUTE,
            PUSH_BYTES_PER_PEER_PER_MINUTE, entry_cost,
        };
        let mut sent = cordelia_network::rate_limit::ByteCounter::new(
            std::time::Duration::from_secs(60),
            OUTBOX_BYTES_PER_MINUTE,
        );
        let mut total = 0u64;
        let mut pushes = 0;
        while let Some(room) = outbox_room(&mut sent) {
            assert!(room <= OUTBOX_BATCH_MAX_BYTES);
            assert!(sent.check_and_record(room as u64));
            total += room as u64;
            pushes += 1;
            assert!(pushes < 100, "never stops");
        }
        // It stops under what a relay allows a connection in a minute, with
        // less room left than one entry of the largest size costs.
        assert!(total <= OUTBOX_BYTES_PER_MINUTE);
        assert!(total < PUSH_BYTES_PER_PEER_PER_MINUTE);
        assert!(OUTBOX_BYTES_PER_MINUTE - total < entry_cost(MAX_ITEM_BYTES));

        // With room for an entry of the largest size, less one byte, it
        // sends nothing: what an entry takes beyond its ciphertext counts.
        let mut sent = cordelia_network::rate_limit::ByteCounter::new(
            std::time::Duration::from_secs(60),
            OUTBOX_BYTES_PER_MINUTE,
        );
        assert!(sent.check_and_record(OUTBOX_BYTES_PER_MINUTE - entry_cost(MAX_ITEM_BYTES) + 1));
        assert_eq!(outbox_room(&mut sent), None);
    }

    /// T3. A connection has an allowance, and so does its address: the
    /// connections from one address share five times what one may send. A
    /// peer that reconnects, or comes back under another key, does not
    /// start again from nothing. Going over three times cuts a peer off.
    #[test]
    fn limits_are_counted_for_a_connection_and_for_its_address() {
        use cordelia_core::protocol::{
            BAN_THRESHOLD, MAX_CONNECTIONS_PER_IP, PUSH_BYTES_PER_PEER_PER_MINUTE,
            WRITES_PER_PEER_PER_MINUTE,
        };
        use cordelia_network::messages::Protocol;
        let address: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        let mut rates = Rates::default();
        let peer = |n: u8| NodeId([n; 32]);

        // One connection: its own allowance, then refusals, then cut off.
        for _ in 0..WRITES_PER_PEER_PER_MINUTE {
            assert_eq!(rates.request(&peer(1), address, Protocol::ItemPush), Ok(()));
        }
        for breach in 1..=BAN_THRESHOLD {
            let over = rates
                .request(&peer(1), address, Protocol::ItemPush)
                .unwrap_err();
            assert_eq!(over.cut_off, breach == BAN_THRESHOLD, "breach {breach}");
        }

        // The same address under new keys: each has its own allowance, until
        // the address's share is used up.
        let mut allowed = u64::from(WRITES_PER_PEER_PER_MINUTE);
        let mut key = 2u8;
        'address: loop {
            for _ in 0..WRITES_PER_PEER_PER_MINUTE {
                if rates
                    .request(&peer(key), address, Protocol::ItemPush)
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
            u64::from(WRITES_PER_PEER_PER_MINUTE) * MAX_CONNECTIONS_PER_IP as u64
        );
        // Another address is not affected.
        let elsewhere: std::net::IpAddr = "192.0.2.8".parse().unwrap();
        assert_eq!(
            rates.request(&peer(9), elsewhere, Protocol::ItemPush),
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

    /// A refused item is offered again at a slowing pace, up to ten
    /// minutes apart.
    #[test]
    fn a_refused_item_is_offered_again_at_a_slowing_pace() {
        use cordelia_core::protocol::OUTBOX_REFUSED_RETRY_MAX_SECS;
        let secs = |refusals| refused_wait(refusals).as_secs();
        assert_eq!(secs(1), 4);
        assert_eq!(secs(2), 8);
        assert_eq!(secs(3), 16);
        assert_eq!(secs(9), OUTBOX_REFUSED_RETRY_MAX_SECS);
        assert_eq!(secs(u32::MAX), OUTBOX_REFUSED_RETRY_MAX_SECS);
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

    /// Decision 2026-10-22 (memory), rule 9. A failed repush of 100 items
    /// to a peer is tried again at most PUSH_RETRY_STREAMS_AT_ONCE streams
    /// at once, and every item is tried at least once and at most
    /// PUSH_RETRY_MAX times: an item held back for a later round has spent
    /// none of its tries. The peer fails every push, after holding its
    /// stream a moment.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_failed_repush_is_tried_again_a_few_streams_at_a_time() {
        use cordelia_core::protocol::PUSH_RETRY_STREAMS_AT_ONCE;
        use cordelia_network::codec;
        use cordelia_network::messages::{Protocol, WireMessage};
        use cordelia_network::transport;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let id = |seed: u8| cordelia_crypto::identity::NodeIdentity::from_seed([seed; 32]).unwrap();
        let (node_key, peer_key) = (id(8), id(9));
        let peer_end =
            transport::create_endpoint(&peer_key, "127.0.0.1:0".parse().unwrap()).unwrap();
        let peer_addr = peer_end.local_addr().unwrap();
        let node_end =
            transport::create_client_endpoint(&node_key, "127.0.0.1".parse().unwrap()).unwrap();

        // The peer: each push it is sent counts its stream as open while it
        // holds it, notes the item, and fails it with a reset.
        let open = std::sync::Arc::new(AtomicUsize::new(0));
        let most = std::sync::Arc::new(AtomicUsize::new(0));
        let tried = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
            String,
            usize,
        >::new()));
        let peer = {
            let (open, most, tried) = (open.clone(), most.clone(), tried.clone());
            tokio::spawn(async move {
                let conn = peer_end.accept().await.unwrap().await.unwrap();
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let (open, most, tried) = (open.clone(), most.clone(), tried.clone());
                    tokio::spawn(async move {
                        let now = open.fetch_add(1, Ordering::SeqCst) + 1;
                        most.fetch_max(now, Ordering::SeqCst);
                        let _ = codec::read_protocol_byte(&mut recv).await;
                        if let Ok(WireMessage::PushPayload(push)) =
                            codec::read_frame(&mut recv, Protocol::ItemPush).await
                        {
                            let mut tried = tried.lock().unwrap();
                            for item in push.items {
                                *tried.entry(item.item_id).or_default() += 1;
                            }
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        open.fetch_sub(1, Ordering::SeqCst);
                        let _ = send.reset(0u32.into());
                        let _ = recv.stop(0u32.into());
                    });
                }
            })
        };
        let conn = node_end
            .connect(peer_addr, "cordelia")
            .unwrap()
            .await
            .unwrap();
        let to = NodeId(peer_key.public_key());

        // A repush of 100 items failed: each is reported for a retry.
        let mut retries = PushRetries::new();
        let failed = retries.failed();
        for n in 0..100 {
            let item = cordelia_network::messages::Item {
                item_id: format!("ci_{n}"),
                channel_id: "grp_retries".into(),
                item_type: "note".into(),
                encrypted_blob: vec![n as u8; 64],
                content_hash: vec![0; 32],
                content_length: 64,
                author_id: vec![0; 32],
                signature: vec![0; 64],
                key_version: 1,
                published_at: "2026-10-22T00:00:00Z".into(),
                is_tombstone: false,
                parent_id: None,
                slot: None,
                rev: None,
            };
            failed
                .send(RetryEntry {
                    item,
                    peer_id: to.clone(),
                    channel_id: "grp_retries".into(),
                    exclude_peer: None,
                    attempt: 0,
                    retry_at: tokio::time::Instant::now(),
                })
                .unwrap();
        }

        // Rounds in quick succession, each with every backoff passed,
        // until nothing waits and nothing runs.
        let began = std::time::Instant::now();
        loop {
            let later = tokio::time::Instant::now() + std::time::Duration::from_secs(3600);
            retries.round(later, &|_| true, &|_| Some(conn.clone()));
            if retries.is_idle() {
                break;
            }
            assert!(
                began.elapsed() < std::time::Duration::from_secs(60),
                "the retries did not end"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let most = most.load(Ordering::SeqCst);
        assert!(
            most <= PUSH_RETRY_STREAMS_AT_ONCE,
            "{most} retries ran to the peer at once"
        );
        let tried = tried.lock().unwrap().clone();
        for n in 0..100 {
            let times = tried.get(&format!("ci_{n}")).copied().unwrap_or(0);
            assert!(
                (1..=PUSH_RETRY_MAX as usize).contains(&times),
                "item {n} was tried {times} times"
            );
        }
        peer.abort();
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
        let dialled = dial_relay(&node_ctx, &configured).await.unwrap();
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
    }

    /// What a relay's own fetch from a relay configured by address alone,
    /// of the version before, and that relay's large pushes on the same
    /// connection come to (decision 2026-10-22 (memory), rules 2, 6 and 8):
    /// how the fetch ended and how long it took, and how many of the
    /// pushes were answered, with the time of the last.
    struct Contended {
        fetched: Fetched,
        fetch_took: std::time::Duration,
        pushes_answered: usize,
        pushes_took: std::time::Duration,
    }

    /// A relay fetches from a peer it is connected to, which answers the
    /// fetch of a page's entries with `fetched_bytes` of items, while the
    /// peer pushes `pushes` frames of `push_bytes` each, each on a stream of
    /// its own, all begun as the fetch's answer is written. The relay
    /// dialled the peer where `node_dials`, and the peer dialled it
    /// otherwise: the end that dials holds one of its streams for the
    /// handshake for as long as the connection lasts, so a peer that was
    /// dialled may open one stream more.
    async fn a_fetch_beside_large_pushes(
        pushes: usize,
        push_bytes: usize,
        fetched_bytes: usize,
        node_dials: bool,
    ) -> Contended {
        use cordelia_network::codec::{self, encode_message, write_raw_frame};
        use cordelia_network::messages::{
            FetchResponse, Item, ItemHeader, Protocol, PushPayload, SyncChannelListResponse,
            SyncResponse, WireMessage,
        };
        use cordelia_network::{connection, transport};
        use std::collections::{HashMap, HashSet};
        use std::sync::{Arc, RwLock};

        let id = |seed: u8| {
            Arc::new(cordelia_crypto::identity::NodeIdentity::from_seed([seed; 32]).unwrap())
        };
        let (node, peer) = (id(41), id(42));
        let here: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
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
        let peer_key = NodeId(peer.public_key());
        // A relay configured by address alone: in peer_relays, listed by
        // no key.
        let relay_entries = Some(Arc::new(crate::relay_entries::RelayEntries::new(
            u64::MAX,
            Arc::new(RwLock::new(Vec::new())),
            std::time::Duration::from_secs(600),
        )));
        let peer_relays = Arc::new(RwLock::new(HashSet::from([peer_key.clone()])));
        let peer_states = Arc::new(RwLock::new(HashMap::from([(peer_key.clone(), 2u8)])));
        let permits = Arc::new(LargePermits::new(
            cordelia_core::protocol::LARGE_MESSAGES_AT_ONCE,
        ));
        let state = a_state();
        let (repush_tx, _r) = tokio::sync::mpsc::unbounded_channel();
        let (delivery_tx, _d) = tokio::sync::mpsc::unbounded_channel();
        let (gov_tx, _g) = tokio::sync::mpsc::unbounded_channel();
        let peer_rates = Arc::new(std::sync::Mutex::new(Rates::new(u64::MAX)));

        let peer_end = transport::create_endpoint(&peer, here).unwrap();
        let peer_addr = peer_end.local_addr().unwrap();
        let peer_mgr = connection::ConnectionManager::new(
            peer.clone(),
            peer_end,
            vec![],
            vec!["relay".into()],
            peer_addr.port(),
        );
        let (node_conn, at_peer) = if node_dials {
            let (peer_accepts, as_peer) = (peer_mgr.endpoint(), peer_mgr.connect_context());
            let at_peer = tokio::spawn(async move {
                let incoming = peer_accepts.accept().await.unwrap();
                connection::inbound_accept(&as_peer, incoming)
                    .await
                    .unwrap()
                    .conn
            });
            let dialled = connection::outbound_connect(&as_node, peer_addr)
                .await
                .unwrap()
                .conn;
            drop(accepts);
            (dialled, at_peer.await.unwrap())
        } else {
            let node_conn = tokio::spawn(async move {
                let incoming = accepts.accept().await.unwrap();
                connection::inbound_accept(&as_node, incoming)
                    .await
                    .unwrap()
                    .conn
            });
            let dialled = connection::outbound_connect(&peer_mgr.connect_context(), node_addr)
                .await
                .unwrap()
                .conn;
            (node_conn.await.unwrap(), dialled)
        };

        let loop_task = tokio::spawn(handle_peer_streams(
            node_conn.clone(),
            peer_key.clone(),
            "127.0.0.1".parse().unwrap(),
            state.clone(),
            Arc::new(RwLock::new(Vec::new())),
            "relay".into(),
            repush_tx.clone(),
            delivery_tx,
            peer_rates.clone(),
            peer_states,
            peer_relays,
            gov_tx,
            Arc::new(RwLock::new(HashSet::new())),
            Arc::new(RwLock::new(
                cordelia_network::seen_table::SeenTable::default(),
            )),
            relay_entries,
            permits.clone(),
            false,
        ));

        let item = |n: usize, bytes: usize| Item {
            item_id: format!("ci_{n:0>26}"),
            channel_id: "grp_00000000-0000-4000-8000-00000000000c".into(),
            item_type: "memory".into(),
            encrypted_blob: vec![n as u8; bytes],
            content_hash: vec![0u8; 32],
            content_length: bytes as u32,
            author_id: vec![0u8; 32],
            signature: vec![0u8; 64],
            key_version: 1,
            published_at: "2026-10-22T00:00:00Z".into(),
            is_tombstone: false,
            parent_id: None,
            slot: None,
            rev: None,
        };
        let began = tokio::time::Instant::now();
        let answered = Arc::new(std::sync::Mutex::new(Vec::<std::time::Duration>::new()));

        // The peer: it answers the relay's fetch, and when the fetch asks
        // for a page's entries it begins its pushes, then writes the
        // answer.
        let serving = {
            let (at_peer, answered) = (at_peer.clone(), answered.clone());
            tokio::spawn(async move {
                let (mut send, mut recv) = at_peer.accept_bi().await.unwrap();
                let _ = codec::read_protocol_byte(&mut recv).await;
                let channel = "grp_00000000-0000-4000-8000-00000000000c".to_string();
                let mut first = true;
                loop {
                    let answer = match codec::read_frame(&mut recv, Protocol::ItemSync).await {
                        Ok(WireMessage::SyncChannelListRequest(_)) => {
                            WireMessage::SyncChannelListResponse(SyncChannelListResponse {
                                channel_ids: vec![channel.clone()],
                            })
                        }
                        Ok(WireMessage::SyncRequest(_)) => {
                            let items = if first {
                                first = false;
                                (0..4)
                                    .map(|n| ItemHeader {
                                        item_id: format!("ci_{n:0>26}"),
                                        channel_id: channel.clone(),
                                        item_type: "memory".into(),
                                        content_hash: vec![0u8; 32],
                                        author_id: vec![0u8; 32],
                                        signature: vec![0u8; 64],
                                        key_version: 1,
                                        published_at: "2026-10-22T00:00:00Z".into(),
                                        is_tombstone: false,
                                        parent_id: None,
                                        slot: None,
                                        rev: None,
                                    })
                                    .collect()
                            } else {
                                Vec::new()
                            };
                            WireMessage::SyncResponse(SyncResponse {
                                items,
                                has_more: false,
                                last_seq: Some(4),
                            })
                        }
                        Ok(WireMessage::FetchRequest(_)) => {
                            for n in 0..pushes {
                                let (at_peer, answered) = (at_peer.clone(), answered.clone());
                                tokio::spawn(async move {
                                    let (mut send, mut recv) = at_peer.open_bi().await.unwrap();
                                    let push = WireMessage::PushPayload(PushPayload {
                                        items: vec![item(1000 + n, push_bytes)],
                                    });
                                    let mut stream = tokio::io::join(&mut recv, &mut send);
                                    let sent =
                                        codec::send_request(&mut stream, Protocol::ItemPush, &push)
                                            .await;
                                    if sent.is_ok() {
                                        answered.lock().unwrap().push(began.elapsed());
                                    }
                                });
                            }
                            WireMessage::FetchResponse(FetchResponse {
                                items: (0..4).map(|n| item(n, fetched_bytes / 4)).collect(),
                            })
                        }
                        _ => break,
                    };
                    if write_raw_frame(&mut send, &encode_message(&answer).unwrap())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            })
        };

        let from = FetchFrom {
            target: peer_key,
            state,
            role: "relay".into(),
            channels: Vec::new(),
            ask_what_it_holds: true,
            limited: false,
            address: "127.0.0.1".parse().unwrap(),
            rates: peer_rates,
            kept: Default::default(),
            repush_tx,
            seen_table: Default::default(),
            permits: Some(permits),
            listed_by_key: false,
        };
        let (fetched, _) = fetch_from(node_conn, from).await;
        let fetch_took = began.elapsed();
        // The pushes have until a stream timeout and a half after the fetch.
        let until = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        while answered.lock().unwrap().len() < pushes && tokio::time::Instant::now() < until {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let answered = answered.lock().unwrap().clone();
        loop_task.abort();
        serving.abort();
        // Close both ends, so that nothing of this run (a push still
        // waiting in its write) is left beside the next.
        at_peer.close(0u32.into(), b"done");
        node_mgr.endpoint().close(0u32.into(), b"done");
        peer_mgr.endpoint().close(0u32.into(), b"done");
        node_mgr.endpoint().wait_idle().await;
        peer_mgr.endpoint().wait_idle().await;
        Contended {
            fetched,
            fetch_took,
            pushes_answered: answered.len(),
            pushes_took: answered.iter().max().copied().unwrap_or_default(),
        }
    }

    /// Decision 2026-10-22 (memory), rule 8. A relay's own fetch from a
    /// relay configured by address alone, and that relay's large pushes on
    /// the same connection, all end: the fetch within two seconds and every
    /// push answered. The relay reads the streams the peer opens one at a
    /// time; at a stream window of a small message, two pushes queued
    /// behind the one being read held the whole connection's window, and
    /// the push being read, the fetch and the other pushes waited out
    /// STREAM_TIMEOUT. With every stream the peer may open within seven
    /// eighths of the connection's window, the streams queued cannot hold
    /// all of it, and the fetch, on a stream the relay opened, has an
    /// eighth to read back, which is when quinn announces more. Both ways
    /// round: the relay dialled by the peer, and the relay dialling it,
    /// where the peer may open all 8 of its streams.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_fetch_and_large_pushes_on_one_connection_do_not_wait_on_each_other() {
        for (pushes, push_bytes, fetched_bytes) in [
            (3, 300_000, 400_000),
            (5, 300_000, 100_000),
            (3, 900_000, 100_000),
            (7, 140_000, 100_000),
            (8, 300_000, 400_000),
            (8, 900_000, 900_000),
        ] {
            for node_dials in [false, true] {
                let ended =
                    a_fetch_beside_large_pushes(pushes, push_bytes, fetched_bytes, node_dials)
                        .await;
                assert!(
                    ended.fetched == Fetched::All
                        && ended.fetch_took < std::time::Duration::from_secs(2)
                        && ended.pushes_answered == pushes,
                    "{pushes} pushes of {push_bytes} bytes beside a fetch of {fetched_bytes}, the relay dialling: {node_dials}: \
                 the fetch ended {:?} after {:?}, and {} pushes were answered, the last after {:?}",
                    ended.fetched,
                    ended.fetch_took,
                    ended.pushes_answered,
                    ended.pushes_took
                );
            }
        }
    }
}
