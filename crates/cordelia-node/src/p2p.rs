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
    /// no room for it, nothing is counted, and the caller hands nothing.
    /// That is no breach (§16): the relay sized the page, and the asker
    /// cannot know its room. Nothing is kept of a request that hands
    /// nothing.
    pub fn handed(&mut self, peer: &NodeId, address: std::net::IpAddr, bytes: u64) -> bool {
        if bytes == 0 {
            return true;
        }
        let mut limiters = self.both(peer, address);
        if limiters
            .iter_mut()
            .any(|limiter| limiter.fetch_bytes.room() < bytes)
        {
            return false;
        }
        for limiter in &mut limiters {
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
fn channels_to_ask(own: Vec<String>, listed: Vec<String>, most: usize) -> Vec<String> {
    let mut channels: std::collections::HashSet<String> = own.into_iter().collect();
    let listed: std::collections::HashSet<String> = listed
        .into_iter()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= cordelia_core::protocol::MAX_CHANNEL_ID_LEN
                && id.bytes().all(|b| b.is_ascii_graphic())
        })
        .collect();
    channels.extend(listed.into_iter().take(most));
    channels.into_iter().collect()
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

/// What a fetch from one peer needs.
struct FetchFrom {
    conn: quinn::Connection,
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
}

/// Fetch from one peer what this node lacks: one stream, every channel in
/// turn (§4.5). Returns how it ended, and how many items were stored.
///
/// Each channel is paged by the peer's arrival sequence from this node's
/// place in it (§4.4a), at most `PAGES` pages a pass. The place moves when
/// a page has been gone through, whether or not what it listed could be
/// stored. A page that could not be fetched, or stored as a whole, is asked
/// for again.
async fn fetch_from(from: FetchFrom) -> (Fetched, u64) {
    use cordelia_core::protocol::{MAX_ITEM_BYTES, SYNC_PAGE_STEPS, entry_cost};
    use cordelia_network::item_sync;
    const PAGES: usize = 10;

    let FetchFrom {
        conn,
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
    } = from;
    let is_relay_node = role == "relay";
    let lock_rates = || rates.lock().unwrap_or_else(|e| e.into_inner());
    let lock_kept = || kept.lock().unwrap_or_else(|e| e.into_inner());

    let (mut send, mut recv) = match open_bi(&conn).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(peer = %target, error = %e, "sync open_bi failed");
            return (Fetched::Failed, 0);
        }
    };
    if let Err(e) = cordelia_network::codec::write_protocol_byte(
        &mut send,
        cordelia_network::messages::Protocol::ItemSync,
    )
    .await
    {
        tracing::debug!(peer = %target, error = %e, "sync protocol byte failed");
        return (Fetched::Failed, 0);
    }

    // Phase 0 (§4.5): a relay asks the peer which channels it holds.
    let channels = if ask_what_it_holds {
        let listed = match item_sync::send_channel_list_request(&mut send, &mut recv).await {
            Ok(resp) => resp.channel_ids,
            Err(e) => {
                tracing::debug!(peer = %target, error = %e, "phase0 channel list request failed");
                if limited {
                    return (Fetched::Failed, 0);
                }
                Vec::new()
            }
        };
        let most = if limited {
            cordelia_core::protocol::MAX_CHANNELS_ASKED_OF_A_PEER
        } else {
            usize::MAX
        };
        channels_to_ask(channels, listed, most)
    } else {
        channels
    };
    if channels.is_empty() {
        let _ = send.finish();
        return (Fetched::All, 0);
    }
    tracing::debug!(peer = %target, channels = channels.len(), "pull-sync starting");

    let max_bytes = lock_rates().relay_max_bytes;
    let mut fetched = Fetched::All;
    let mut total_stored: u64 = 0;
    // How many channels of this peer a place, and a page size, is kept
    // for. A relay it lists holds as many channels as this node does.
    let most = if limited {
        cordelia_core::protocol::MAX_CHANNELS_ASKED_OF_A_PEER
    } else {
        usize::MAX
    };
    'channels: for ch_id in &channels {
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
            let resp = match item_sync::send_sync_page(&mut send, &mut recv, ch_id, after, limit)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(peer = %target, channel = %ch_id, error = %e, "sync request failed");
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

            // The page is not passed if the relay had no room for the
            // channel: it is asked for again.
            let mut not_taken = false;
            if !resp.items.is_empty() {
                let known = {
                    let Ok(db) = state.db.lock() else {
                        fetched = Fetched::Failed;
                        break 'channels;
                    };
                    let offered: Vec<String> =
                        resp.items.iter().map(|h| h.item_id.clone()).collect();
                    cordelia_storage::items::known_items(&db, &offered).unwrap_or_default()
                };
                let mut fetch_ids = item_sync::compute_fetch_list(&resp.items, &known);
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
                if !fetch_ids.is_empty() {
                    if let Err(e) = item_sync::send_fetch_request(&mut send, &fetch_ids).await {
                        tracing::debug!(peer = %target, error = %e, "fetch request failed");
                        fetched = Fetched::Failed;
                        break 'channels; // Stream corrupted
                    }
                    let mut items = match item_sync::read_fetch_response(&mut recv).await {
                        Ok(items) => items,
                        Err(e) => {
                            // The page's entries could not be fetched in
                            // one message: ask for fewer next time.
                            tracing::debug!(peer = %target, channel = %ch_id, asked = fetch_ids.len(), error = %e, "fetch response failed; asking for fewer next time");
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
                        items.retain(|i| {
                            i.channel_id == *ch_id && wanted.remove(i.item_id.as_str())
                        });
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
                        tracing::info!(channel = %ch_id, fetched = fetch_ids.len(), stored = stored_count, "pull-sync page complete");
                        total_stored += stored_count as u64;
                    }
                }
            }

            if not_taken {
                continue 'channels;
            }
            // A peer without arrival paging answers once, the old way.
            let Some(last_seq) = resp.last_seq else {
                caught_up = true;
                break;
            };
            // The page is passed, whether or not what it listed could be
            // stored, so that what follows is reached; what this node will
            // not store it does not ask for again in this part of the list.
            // A page with nothing in it moves no place, so a name that lists
            // nothing has nothing kept for it.
            let after = if resp.items.is_empty() {
                after
            } else {
                last_seq
            };
            // A page with nothing in it is the end, whatever it says.
            let end = !resp.has_more || resp.items.is_empty();
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
    // FIN: signal end of batch to server
    let _ = send.finish();
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
    if peer_is_hot
        && node_role != "relay"
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
        tokio::spawn(async move {
            handle_peer_streams(
                conn, peer_id, made_from, db_state, peers_ref, role, rtx, dtx, rates, states,
                relays, gtx, sm, st, entries,
            )
            .await;
        });
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
    relay_addrs: RelayAddrs,
    trusted_peer_ids: Vec<NodeId>,
    max_storage_bytes: u64,
    relay_ask_again: std::time::Duration,
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

    // Governor -- with dial policy based on trusted_peers config (§8.2.2)
    let gov_targets = cordelia_network::governor::GovernorTargets::from_config(&gov_config);
    let gov_timeouts = cordelia_network::governor::GovernorTimeouts::from_config(&gov_config);
    let dial_policy = if !trusted_peer_ids.is_empty() && node_role == "personal" {
        // Swarm node: only dial trusted peers (lead node)
        cordelia_network::governor::DialPolicy::TrustedOnly(trusted_peer_ids.clone())
    } else if node_role == "personal" {
        cordelia_network::governor::DialPolicy::RelaysOnly
    } else {
        cordelia_network::governor::DialPolicy::All
    };
    let mut governor =
        cordelia_network::governor::Governor::with_dial_policy(gov_targets, vec![], dial_policy)
            .with_timeouts(gov_timeouts);

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
            std::sync::Arc::new(crate::relay_entries::RelayEntries::new(
                max_storage_bytes,
                relay_addrs.clone(),
                relay_ask_again,
            ))
        });
    // The cap is read here, when the node starts, and at no other time:
    // a relay whose cap came down drops its newest channels now.
    if let Some(entries) = &relay_entries {
        entries.make_room(&state.db);
    }
    // A device's side of its relays, for the channels of its own
    // (decision 2026-10-04 §4.6): the show, the leave it gives, and the
    // passes that prove, pull and push. Only a personal node has one, and
    // it does nothing on a device that follows no phrase.
    let device_entries = (node_role == "personal").then(|| {
        cordelia_node::device_entries::DeviceEntries::new(
            state.clone().into_inner(),
            cordelia_node::device_entries::Clock::system(),
        )
    });

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
    let (retry_fail_tx, mut retry_fail_rx) = tokio::sync::mpsc::unbounded_channel::<RetryEntry>();
    let mut retry_queue: Vec<RetryEntry> = Vec::new();
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
    let mut relay_tries: std::collections::HashMap<String, RelayTry> =
        std::collections::HashMap::new();

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
                        tokio::spawn(async move {
                            let accepted = cordelia_network::connection::inbound_accept(&ctx, incoming).await;
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
                            // A configured relay must answer with its key.
                            let dialled = relay_addrs
                                .read()
                                .ok()
                                .and_then(|relays| relays.iter().find(|r| r.addr == addr).cloned());
                            if let Some(relay) = dialled {
                                let any_connected = any_relay_connected(&relay_addrs, &conn_mgr);
                                let tried = relay_tries.entry(relay.host.clone()).or_default();
                                match relay.key {
                                    Some(key) if key != outcome.node_id.0 => {
                                        tracing::warn!(
                                            relay = %relay.host,
                                            answered = %outcome.node_id,
                                            "another key answered at a relay's address; refusing it"
                                        );
                                        outcome.conn.close(0u32.into(), b"not the relay");
                                        tried.failed(
                                            "another key answered at this address".into(),
                                            true,
                                            p2p_gov_tick_secs,
                                            any_connected,
                                        );
                                        continue;
                                    }
                                    // Keep the count of failures until the
                                    // connection has lasted (see the relay
                                    // tick), so a relay that accepts and
                                    // drops at once is not redialled every
                                    // second.
                                    _ => tried.connected_at = Some(std::time::Instant::now()),
                                }
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
                                    &relay_addrs, &relay_entries,
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
                            .ok()
                            .and_then(|relays| relays.iter().find(|r| r.addr == addr).cloned());
                        if let Some(relay) = dialled {
                            let any_connected = any_relay_connected(&relay_addrs, &conn_mgr);
                            relay_tries.entry(relay.host).or_default().failed(
                                error,
                                false,
                                p2p_gov_tick_secs,
                                any_connected,
                            );
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
                let any_connected = relays.iter().any(|r| relay_connected(&conn_mgr, r));
                for relay in &relays {
                    if relay_connected(&conn_mgr, relay) {
                        // Forget earlier failures once the connection has lasted.
                        if relay_tries
                            .get(&relay.host)
                            .is_some_and(|t| t.connected_at.is_none_or(|at| at.elapsed() >= settled))
                        {
                            relay_tries.remove(&relay.host);
                        }
                        continue;
                    }
                    if in_flight.contains(&relay.addr) || in_flight.len() >= MAX_IN_FLIGHT {
                        continue;
                    }
                    let tried = relay_tries.entry(relay.host.clone()).or_default();
                    if let Some(at) = tried.connected_at.take()
                        && at.elapsed() < settled
                    {
                        // It connected and was gone again at once: a failure
                        // like any other, so the pace keeps slowing.
                        tried.failed(
                            "the relay closed the connection at once".into(),
                            false,
                            p2p_gov_tick_secs,
                            any_connected,
                        );
                    }
                    if tried.next_try.is_some_and(|at| now < at) {
                        continue;
                    }
                    tried.last_tried = Some(now);
                    in_flight.insert(relay.addr);
                    let ctx = connect_ctx.clone();
                    let tx = connect_tx.clone();
                    let addr = relay.addr;
                    tracing::debug!(relay = %relay.host, %addr, "dialling relay");
                    tokio::spawn(async move {
                        match cordelia_network::connection::outbound_connect(&ctx, addr).await {
                            Ok(outcome) => { let _ = tx.send(Ok(outcome)); }
                            Err(e) => { let _ = tx.send(Err((addr, e.to_string()))); }
                        }
                    });
                }
                publish_relays(&state, &relays, &relay_tries, &conn_mgr);
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
            Some(_) = push_rx.recv() => {
                while push_rx.try_recv().is_ok() {}
                if last_outbox_flush.elapsed() >= outbox_interval_dur {
                    last_outbox_flush = std::time::Instant::now();
                    flush_outbox(&state, &governor, &conn_mgr, &outbox_in_flight, &mut outbox_rotation, &outbox_refusals);
                }
            }

            _ = outbox_interval.tick() => {
                if node_role == "personal" && last_outbox_flush.elapsed() >= outbox_interval_dur {
                    last_outbox_flush = std::time::Instant::now();
                    flush_outbox(&state, &governor, &conn_mgr, &outbox_in_flight, &mut outbox_rotation, &outbox_refusals);
                }
                // What waits in a channel of the device's own is sent on
                // the same timer, through the leave that a show gives.
                device_pass(&device_entries, &relay_addrs, &conn_mgr, cordelia_node::device_entries::Pass::Send);
            }

            // Something was written in a channel of the device's own: it
            // is sent without waiting for the timer, through that leave.
            _ = state.own_channels.wait_written(), if device_entries.is_some() => {
                device_pass(&device_entries, &relay_addrs, &conn_mgr, cordelia_node::device_entries::Pass::Send);
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

            // ── Keyed tombstone GC (§4.4) ─────────────────────────────
            _ = gc_interval.tick() => {
                let gc_state = state.clone();
                // Only a personal node holds its channels' member lists.
                // Any other node sweeps a key only when every author has
                // deleted it.
                let members_known = node_role == "personal";
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

                // Filter out local-scope items (§8.2.2: never leave the PAN)
                {
                    let db = state.db.lock();
                    if let Ok(db) = db {
                        pending.retain(|_, (item, _)| {
                            !cordelia_storage::channels::is_local_scope(&db, &item.channel_id).unwrap_or(false)
                        });
                    }
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
                while announce_rx.try_recv().is_ok() {}
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

                // A device's own channels, at each relay it is set up
                // with: it shows its change entry, and then proves, pulls
                // and pushes where the answer gives it leave.
                device_pass(&device_entries, &relay_addrs, &conn_mgr, cordelia_node::device_entries::Pass::Whole);

                // Apply channel states that arrived in our inbox since the last
                // cycle (decision 2026-09-30 §4.1). Off the select loop: it does
                // crypto and SQLite work under the db lock.
                if node_role == "personal" {
                    let inbox_state = state.clone();
                    tokio::task::spawn_blocking(move || {
                        if let Err(e) = cordelia_api::membership::process_inbox(&inbox_state) {
                            tracing::warn!(error = %e, "inbox processing failed");
                        }
                        // Add this person's other devices to projects they have
                        // found locally (decision 2026-09-30 §4.5).
                        if let Err(e) = cordelia_api::membership::process_join_requests(&inbox_state) {
                            tracing::warn!(error = %e, "join request processing failed");
                        }
                        // Offer again the channel states that a member has
                        // not confirmed (decision 2026-09-30 §4.1).
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |d| d.as_secs() as i64);
                        if let Err(e) = cordelia_api::membership::offer_again(&inbox_state, now) {
                            tracing::warn!(error = %e, "offering channel states again failed");
                        }
                    });
                }
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
                // The inbox first. A device that removes another publishes
                // again what that device last wrote, and then sends the
                // removal. Fetching the removal before the channels means
                // that whenever it is seen, those entries are fetched in the
                // same pass, before it is applied.
                let mut local_channels = local_channels;
                local_channels.sort_by_key(|id| {
                    cordelia_storage::naming::ChannelType::from_id(id)
                        != cordelia_storage::naming::ChannelType::Inbox
                });

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
                        conn: conn.clone(),
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
                    };
                    let gtx = gov_tx.clone();
                    let ask_next = ask_next.clone();
                    tokio::spawn(async move {
                        let _fetch = fetch;
                        let target = from.target.clone();
                        let (fetched, stored) = fetch_from(from).await;
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
pub async fn keep_relays_resolved(
    relays: Vec<cordelia_network::bootstrap::Relay>,
    addrs: RelayAddrs,
) {
    use cordelia_core::protocol::{BOOTNODE_RESOLVE_INTERVAL_SECS, BOOTNODE_RESOLVE_RETRY_SECS};
    loop {
        let resolved = cordelia_network::bootstrap::resolve_relays(&relays).await;
        let have_any = if resolved.is_empty() {
            addrs.read().map(|a| !a.is_empty()).unwrap_or(false)
        } else {
            if let Ok(mut current) = addrs.write()
                && *current != resolved
            {
                let list: Vec<String> = resolved
                    .iter()
                    .map(|r| format!("{}={}", r.host, r.addr))
                    .collect();
                tracing::info!(addrs = ?list, "relay addresses updated");
                *current = resolved;
            }
            true
        };
        let wait = if have_any {
            BOOTNODE_RESOLVE_INTERVAL_SECS
        } else {
            BOOTNODE_RESOLVE_RETRY_SECS
        };
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
    }
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
/// it was dialled at.
fn relays_with_links(
    relay_addrs: &RelayAddrs,
    conn_mgr: &cordelia_network::connection::ConnectionManager,
) -> Vec<cordelia_node::device_entries::Relay> {
    use cordelia_node::device_entries::{Link, Relay};
    let Ok(relays) = relay_addrs.read() else {
        return Vec::new();
    };
    relays
        .iter()
        .map(|relay| {
            let peer = match relay.key {
                Some(key) => Some(NodeId(key)),
                None => conn_mgr.connected_peers().into_iter().find(|peer| {
                    conn_mgr
                        .get_connection(peer)
                        .is_some_and(|conn| conn.remote_address() == relay.addr)
                }),
            };
            let link = peer.and_then(|peer| {
                let conn = conn_mgr.get_connection(&peer)?.clone();
                Some(Link::new(relay.host.clone(), peer, conn))
            });
            Relay {
                name: relay.host.clone(),
                link,
            }
        })
        .collect()
}

/// Start a pass of a device's side of its relays, where this node has
/// one: off the select loop, since it waits on the relays. A pass that
/// finds another running does nothing.
fn device_pass(
    device: &Option<std::sync::Arc<cordelia_node::device_entries::DeviceEntries>>,
    relay_addrs: &RelayAddrs,
    conn_mgr: &cordelia_network::connection::ConnectionManager,
    kind: cordelia_node::device_entries::Pass,
) {
    let Some(device) = device.clone() else {
        return;
    };
    let relays = relays_with_links(relay_addrs, conn_mgr);
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
    relay_addrs: &RelayAddrs,
    conn_mgr: &cordelia_network::connection::ConnectionManager,
) -> bool {
    relay_addrs
        .read()
        .map(|relays| relays.iter().any(|r| relay_connected(conn_mgr, r)))
        .unwrap_or(false)
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

/// Publish where each configured relay stands, for `cordelia peers` and
/// `cordelia status`.
fn publish_relays(
    state: &cordelia_api::state::AppState,
    relays: &[cordelia_network::bootstrap::RelayAddr],
    tries: &std::collections::HashMap<String, RelayTry>,
    conn_mgr: &cordelia_network::connection::ConnectionManager,
) {
    let list: Vec<cordelia_api::state::RelaySnapshot> = relays
        .iter()
        .map(|relay| {
            let tried = tries.get(&relay.host);
            let connected = relay_connected(conn_mgr, relay);
            let failing = tried.filter(|t| t.failures > 0 && !connected);
            let state = if connected {
                "connected"
            } else {
                match failing {
                    Some(t) if t.wrong_key => "wrong key",
                    Some(_) => "unreachable",
                    None => "connecting",
                }
            };
            cordelia_api::state::RelaySnapshot {
                host: relay.host.clone(),
                key: relay
                    .key
                    .and_then(|k| cordelia_crypto::bech32::encode_public_key(&k).ok()),
                state: state.into(),
                unreachable_secs: failing.and_then(|t| t.since).map(|t| t.elapsed().as_secs()),
                last_tried_secs: tried
                    .filter(|_| !connected)
                    .and_then(|t| t.last_tried)
                    .map(|t| t.elapsed().as_secs()),
                error: failing.and_then(|t| t.error.clone()),
            }
        })
        .collect();
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
                )
                .await;
            }
            cordelia_network::messages::Protocol::PeerSharing => {
                // Allowed on Warm + Hot (§2.1)
                handle_inbound_peer_share(&mut send, &mut recv, &peer_id, &shared_peers).await;
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
                    conn: &conn,
                    peer: &peer_id,
                    address,
                    db: &state.db,
                    rates: &peer_rates,
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
) -> Option<OverLimit> {
    let msg = match cordelia_network::codec::read_frame(recv).await {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(peer = %peer_id, error = %e, "failed to read push frame");
            return None;
        }
    };

    let payload = match msg {
        cordelia_network::messages::WireMessage::PushPayload(p) => p,
        _ => return None,
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
    let _ = cordelia_network::codec::write_frame(send, &ack).await;
    None
}

async fn handle_inbound_sync(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    peer_id: &NodeId,
    state: &web::Data<cordelia_api::state::AppState>,
    is_relay_peer: bool,
    is_swarm_peer: bool,
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
    let mut current_req = match msg {
        cordelia_network::messages::WireMessage::SyncChannelListRequest(_) => {
            // Which channels a node holds is told only to its own relays.
            // Anyone else gets an empty list.
            let channel_ids = if !(is_relay_peer || is_swarm_peer) {
                Vec::new()
            } else {
                let db = match state.db.lock() {
                    Ok(db) => db,
                    Err(_) => return,
                };
                let mut ids =
                    cordelia_storage::channels::list_stored_channel_ids(&db).unwrap_or_default();
                // Hide local-scope channels from non-swarm peers (§8.2.2)
                if !is_swarm_peer {
                    ids.retain(|ch_id| {
                        !cordelia_storage::channels::is_local_scope(&db, ch_id).unwrap_or(false)
                    });
                }
                ids
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

    // Batched sync loop (§4.5): serve multiple channels on one stream.
    // After each SyncResponse + optional FetchResponse, read the next frame.
    // SyncRequest -> continue loop. EOF/error -> break. Backward compatible:
    // old clients close after one channel, server reads EOF, loop breaks.
    let mut channels_served: u32 = 0;
    loop {
        // Scope check: don't serve local-scope channel items to non-swarm peers (§8.2.2)
        if !is_swarm_peer {
            let is_local = {
                let db = match state.db.lock() {
                    Ok(db) => db,
                    Err(_) => break,
                };
                cordelia_storage::channels::is_local_scope(&db, &current_req.channel_id)
                    .unwrap_or(false)
            };
            if is_local {
                tracing::debug!(peer = %peer_id, channel = %current_req.channel_id, "rejecting sync for local-scope channel from non-swarm peer");
                let resp = cordelia_network::messages::WireMessage::SyncResponse(
                    cordelia_network::messages::SyncResponse {
                        items: vec![],
                        has_more: false,
                        last_seq: None,
                    },
                );
                let _ = cordelia_network::codec::write_frame(send, &resp).await;
                // Don't abort stream -- read next frame to continue batch
                match cordelia_network::codec::read_frame(recv).await {
                    Ok(cordelia_network::messages::WireMessage::SyncRequest(r)) => {
                        current_req = r;
                        channels_served += 1;
                        continue;
                    }
                    _ => break,
                }
            }
        }

        // Build sync response headers
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
            // Arrival paging: tell the peer where this page ended. With no
            // items, echo its cursor so it keeps its place.
            let last_seq = current_req
                .after_seq
                .map(|after| items.last().map(|i| i.seq.max(0) as u64).unwrap_or(after));
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
        let _ = cordelia_network::codec::write_frame(send, &resp).await;
        channels_served += 1;
        tracing::debug!(peer = %peer_id, channel = %current_req.channel_id, "served sync request");

        // Read next frame: FetchRequest (for this channel), SyncRequest (next channel), or EOF
        match cordelia_network::codec::read_frame(recv).await {
            Ok(cordelia_network::messages::WireMessage::FetchRequest(mut freq)) => {
                freq.item_ids
                    .truncate(cordelia_core::protocol::MAX_BATCH_SIZE);
                let fetch_items = {
                    let db = match state.db.lock() {
                        Ok(db) => db,
                        Err(_) => break,
                    };
                    // An answer is one message. If these items do not fit in
                    // one, end the stream now: the peer learns at once, and
                    // asks for fewer. (Reading them all first, only to find
                    // that they cannot be sent, cost a megabyte a request.)
                    let bytes = cordelia_storage::items::total_cost_by_ids(
                        &db,
                        &current_req.channel_id,
                        &freq.item_ids,
                    )
                    .unwrap_or(0);
                    let room = u64::from(cordelia_core::protocol::MAX_MESSAGE_BYTES);
                    if bytes > room {
                        tracing::debug!(peer = %peer_id, channel = %current_req.channel_id, asked = freq.item_ids.len(), bytes, "fetch does not fit in one message; ending the stream");
                        break;
                    }
                    cordelia_storage::items::get_items_by_ids(
                        &db,
                        &current_req.channel_id,
                        &freq.item_ids,
                    )
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
                let fresp = cordelia_network::messages::WireMessage::FetchResponse(
                    cordelia_network::messages::FetchResponse { items: fetch_items },
                );
                let _ = cordelia_network::codec::write_frame(send, &fresp).await;
                tracing::debug!(peer = %peer_id, fetched = freq.item_ids.len(), "served fetch request");

                // After fetch, read next frame for potential next channel
                match cordelia_network::codec::read_frame(recv).await {
                    Ok(cordelia_network::messages::WireMessage::SyncRequest(r)) => {
                        current_req = r;
                        continue;
                    }
                    _ => break, // EOF or unexpected -> done
                }
            }
            Ok(cordelia_network::messages::WireMessage::SyncRequest(r)) => {
                // No fetch for previous channel, move to next
                current_req = r;
                continue;
            }
            _ => break, // EOF or unexpected -> done
        }
    }
    tracing::debug!(peer = %peer_id, channels_served, "inbound sync stream complete");
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
                let _ = gov_tx.send(GovEvent::ChannelWithdrawn(peer_id.clone(), left.channel_id));
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
        let db = state.db.lock().map_err(|e| format!("db lock: {e}"))?;
        let pk = state.identity.public_key();
        // Only announce network-scope channels (§8.2.2: local channels never leave PAN)
        cordelia_storage::channels::list_network_channels(&db, &pk).unwrap_or_default()
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
        // The ID and nothing else: a relay is not told a channel's name.
        let descriptor =
            cordelia_network::channel_announce::announcement(&state.identity, &ch.channel_id);
        if let Err(e) = cordelia_network::channel_announce::send_channel_joined(
            &mut send,
            &ch.channel_id,
            &descriptor,
        )
        .await
        {
            tracing::debug!(channel = %ch.channel_id, error = %e, "channel announce send failed");
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
    /// however often it is asked for. The entry that answers a show is
    /// always counted, and takes the allowance over. What a peer pushes is
    /// counted apart.
    #[test]
    fn what_a_peer_is_handed_counts_with_what_a_relay_fetches_from_it() {
        use cordelia_core::protocol::{
            BAN_THRESHOLD, MAX_CONNECTIONS_PER_IP, PUSH_BYTES_PER_PEER_PER_MINUTE,
        };
        const MINUTE: u64 = PUSH_BYTES_PER_PEER_PER_MINUTE;
        let address: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        let peer = |n: u8| NodeId([n; 32]);
        let mut rates = Rates::default();

        // Handed, and fetched, and handed: one count.
        assert!(rates.handed(&peer(1), address, MINUTE / 2));
        assert_eq!(rates.fetch_room(&peer(1), address), MINUTE / 2);
        rates.fetched(&peer(1), address, MINUTE / 4);
        assert_eq!(rates.fetch_room(&peer(1), address), MINUTE / 4);
        // A byte more than there is room for: it is not handed, and
        // nothing is counted for it.
        assert!(!rates.handed(&peer(1), address, MINUTE / 4 + 1));
        assert_eq!(rates.fetch_room(&peer(1), address), MINUTE / 4);
        // What fits to the byte is handed.
        assert!(rates.handed(&peer(1), address, MINUTE / 4));
        assert_eq!(rates.fetch_room(&peer(1), address), 0);
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
        assert!(rates.handed(&peer(1), address, MINUTE - 1000));
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

        // The address: its connections are handed, between them, what
        // five may be. A sixth key at it has a connection's allowance of
        // its own, and is handed nothing.
        let home: std::net::IpAddr = "192.0.2.8".parse().unwrap();
        for n in 10..10 + MAX_CONNECTIONS_PER_IP as u8 {
            assert!(rates.handed(&peer(n), home, MINUTE), "{n}");
        }
        assert!(!rates.handed(&peer(20), home, 1));
        // And a relay fetches nothing more from that address either.
        assert_eq!(rates.fetch_room(&peer(21), home), 0);

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
}
