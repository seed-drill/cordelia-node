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
#[derive(Default)]
pub struct Rates {
    by_peer: std::collections::HashMap<NodeId, cordelia_network::rate_limit::PeerRateLimiter>,
    by_address:
        std::collections::HashMap<std::net::IpAddr, cordelia_network::rate_limit::PeerRateLimiter>,
    /// When each address made a relay hold a channel it did not hold
    /// before, within the last hour.
    new_channels:
        std::collections::HashMap<std::net::IpAddr, std::collections::VecDeque<std::time::Instant>>,
    /// The most a relay's database may hold (its operator's setting).
    relay_max_bytes: u64,
}

/// A request that is over a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverLimit {
    /// This is one breach too many: the peer is to be cut off.
    pub cut_off: bool,
}

impl Rates {
    /// For a node whose database, if it is a relay, may hold `relay_max_bytes`.
    pub fn new(relay_max_bytes: u64) -> Self {
        Self {
            relay_max_bytes,
            ..Self::default()
        }
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
        let mut limiters = self.both(peer, address);
        if limiters
            .iter_mut()
            .any(|limiter| limiter.write_bytes.room() < bytes)
        {
            return Err(Self::over(limiters));
        }
        for limiter in &mut limiters {
            limiter.write_bytes.check_and_record(bytes);
        }
        Ok(())
    }

    /// Count a channel that `address` is making a relay hold for the first
    /// time. False, counting nothing, if the address has had its share for
    /// the hour (NEW_CHANNELS_PER_ADDRESS_PER_HOUR). A channel costs
    /// nothing to make, so without this one address could make a relay
    /// hold any number of them.
    pub fn new_channel(&mut self, address: std::net::IpAddr) -> bool {
        let hour = std::time::Duration::from_secs(3600);
        let made = self.new_channels.entry(address).or_default();
        while made.front().is_some_and(|at| at.elapsed() >= hour) {
            made.pop_front();
        }
        if made.len() >= cordelia_core::protocol::NEW_CHANNELS_PER_ADDRESS_PER_HOUR {
            return false;
        }
        made.push_back(std::time::Instant::now());
        true
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
    let mut room = RelayRoom::new(u64::MAX, None);
    let room = (node_role == "relay").then_some(&mut room);
    store_checked(db, item, &check_item(item)?, node_role, own, room)
}

/// What a relay needs to decide whether it has room for an item (decision
/// 2026-09-30 §4.6). A relay is a cache with a cap:
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
/// A relay fetches again from its devices what it dropped, once it has
/// room: each device answers its relay with the channels it holds. It
/// asks a device again when that device next connects, and not before
/// (#92).
pub struct RelayRoom<'a> {
    /// The most the relay's database may hold, in bytes.
    pub max_bytes: u64,
    /// The most one channel may hold, in bytes of entries.
    pub max_channel_bytes: u64,
    /// The address the item came from, with the counts of new channels for
    /// each address. `None` when it came from a relay this one lists,
    /// which is not limited.
    pub source: Option<(std::net::IpAddr, &'a std::sync::Mutex<Rates>)>,
    /// What each channel holds, for the channels met while handling one
    /// batch, so that it is added up once a batch and not once an item.
    pub channel_bytes: std::collections::HashMap<String, u64>,
}

impl<'a> RelayRoom<'a> {
    pub fn new(
        max_bytes: u64,
        source: Option<(std::net::IpAddr, &'a std::sync::Mutex<Rates>)>,
    ) -> Self {
        Self {
            max_bytes,
            max_channel_bytes: cordelia_core::protocol::MAX_CHANNEL_BYTES_AT_RELAY,
            source,
            channel_bytes: std::collections::HashMap::new(),
        }
    }

    /// Whether the relay takes this item, as far as room goes. Makes the
    /// channel's row if it is a channel the relay will now hold.
    fn admit(
        &mut self,
        db: &rusqlite::Connection,
        item: &cordelia_network::messages::Item,
        checked: &Checked,
    ) -> Result<(), &'static str> {
        use cordelia_network::messages::{REFUSED_FULL, REFUSED_STORAGE};
        use cordelia_storage::{channels, items};
        // What the entry takes, not only its ciphertext: or a channel of
        // small entries could hold any number of them.
        let bytes = cordelia_core::protocol::entry_cost(item.encrypted_blob.len());

        if !channels::exists(db, &item.channel_id).map_err(|_| REFUSED_STORAGE)? {
            // A channel the relay does not hold: only if there is room,
            // and the address has not made it hold too many lately.
            let used = cordelia_storage::db::used_bytes(db).map_err(|_| REFUSED_STORAGE)?;
            if used >= self.max_bytes {
                tracing::debug!(channel = %item.channel_id, used, "at the storage cap; not taking a channel this relay does not hold");
                return Err(REFUSED_FULL);
            }
            if let Some((address, rates)) = &self.source
                && !rates
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .new_channel(*address)
            {
                tracing::debug!(channel = %item.channel_id, %address, "this address has made the relay hold enough new channels for now");
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
            None => items::channel_cost(db, &item.channel_id).map_err(|_| REFUSED_STORAGE)?,
        };
        let replaced = match &checked.slot {
            Some(slot) => {
                items::author_slot_cost(db, &item.channel_id, slot, &checked.author).unwrap_or(0)
            }
            None => 0,
        };
        let after = held.saturating_sub(replaced) + bytes;
        if after > self.max_channel_bytes {
            tracing::debug!(channel = %item.channel_id, held, "this channel holds as much as one channel may");
            return Err(REFUSED_FULL);
        }
        self.channel_bytes.insert(item.channel_id.clone(), after);
        Ok(())
    }

    /// After a write to `written`: if the relay is over its cap, drop the
    /// channels it came to hold most recently until it is not. Returns
    /// false if `written` was itself among them: it was the newest, so the
    /// write did not stay.
    fn make_room(&mut self, db: &rusqlite::Connection, written: &str) -> bool {
        use cordelia_storage::channels;
        let mut kept = true;
        while cordelia_storage::db::used_bytes(db).is_ok_and(|used| used > self.max_bytes) {
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
            kept &= newest != written;
        }
        kept
    }
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

    if let Some(room) = room.as_deref_mut() {
        room.admit(db, item, checked)?;
    }

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
            if inserted
                && let Some(room) = room
                && !room.make_room(db, &item.channel_id)
            {
                return Err(cordelia_network::messages::REFUSED_FULL);
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
        tokio::spawn(async move {
            handle_peer_streams(
                conn, peer_id, db_state, peers_ref, role, rtx, dtx, rates, states, relays, gtx, sm,
                st,
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
    let peer_rates: std::sync::Arc<std::sync::Mutex<Rates>> =
        std::sync::Arc::new(std::sync::Mutex::new(Rates::new(max_storage_bytes)));
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

    // Pull-sync cursors (§4.4a): per (peer, channel), the peer's arrival
    // sequence of the last item we have processed. In memory, and for one
    // connection: after a restart, or when a peer connects again, each
    // channel is re-listed once, and only unknown items fetched.
    let sync_cursors: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<(NodeId, String), u64>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    // How many entries to ask for in one page, per (peer, channel): an index
    // into SYNC_PAGE_STEPS. It moves down when a fetch fails (the page's
    // entries did not fit in one message) and goes back once the channel
    // is caught up with that peer.
    let sync_page_steps: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<(NodeId, String), usize>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

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
            &swarm_members,
            &seen_table,
            &relay_addrs,
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
                            let ip = outcome.conn.remote_address().ip();
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
                                if let Ok(mut cursors) = sync_cursors.lock() {
                                    cursors.retain(|(peer, _), _| peer != &node_id);
                                }
                                post_connect(
                                    &node_id, &conn_mgr, &mut governor, &shared_peers,
                                    &state, &node_role, &repush_tx, &delivery_tx, &peer_rates, &peer_states,
                                    &peer_relays, &gov_tx, &swarm_members, &seen_table,
                                    &relay_addrs,
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
                if !changed.is_empty()
                    && let Ok(mut cursors) = sync_cursors.lock()
                {
                    cursors.retain(|(_, channel), _| !changed.contains(channel));
                }
                let peers = conn_mgr.connected_peers();
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
                sync_cycles_completed += 1;
                tracing::info!(hot_peers = hot.len(), total_peers = peers.len(), local_channels = local_channels.len(), cycle = sync_cycles_completed, "pull-sync cycle");
                for target in &hot {
                    if let Some(conn) = conn_mgr.get_connection(target) {
                    let conn = conn.clone();
                    let sync_state = state.clone();
                    let sync_local = local_channels.clone();
                    let target = target.clone();
                    let gtx = gov_tx.clone();
                    let role = node_role.clone();
                    let do_phase0 = is_relay;
                    let is_relay_node = is_relay;
                    let rtx = repush_tx.clone();
                    let seen_ref = seen_table.clone();
                    let cursors = sync_cursors.clone();
                    let page_steps = sync_page_steps.clone();
                    let room_rates = peer_rates.clone();
                    // What a relay this node lists hands over is not counted
                    // against an address.
                    let from_listed_relay = governor
                        .peer_info(&target)
                        .is_some_and(|peer| peer.is_relay);
                    let source_address = conn.remote_address().ip();
                    tokio::spawn(async move {
                        // Batched sync (§4.5): one stream per peer, all channels.
                        // Open one (send, recv) pair, write protocol byte once.
                        let (mut send, mut recv) = match open_bi(&conn).await {
                            Ok(s) => s,
                            Err(e) => { tracing::debug!(peer = %target, error = %e, "sync open_bi failed"); return; }
                        };
                        if let Err(e) = cordelia_network::codec::write_protocol_byte(&mut send, cordelia_network::messages::Protocol::ItemSync).await {
                            tracing::debug!(peer = %target, error = %e, "sync protocol byte failed");
                            return;
                        }

                        // Phase 0: relay channel discovery (§4.5)
                        // Ask peer "what channels do you have?", merge with local.
                        let sync_channels = if do_phase0 {
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

                        // Loop channels on one stream. Each channel is paged by the
                        // peer's arrival sequence from our cursor (§4.4a), at most
                        // SYNC_PAGES_PER_CYCLE pages per cycle; the cursor moves only
                        // after a page is fully processed, so a failure retries it.
                        const SYNC_PAGES_PER_CYCLE: usize = 10;
                        let mut total_stored: u64 = 0;
                        'channels: for ch_id in &sync_channels {
                            let cursor_key = (target.clone(), ch_id.clone());
                            for _page in 0..SYNC_PAGES_PER_CYCLE {
                                let after = cursors.lock().ok().and_then(|c| c.get(&cursor_key).copied()).unwrap_or(0);
                                let steps = cordelia_core::protocol::SYNC_PAGE_STEPS;
                                let step = page_steps.lock().ok().and_then(|p| p.get(&cursor_key).copied()).unwrap_or(0).min(steps.len() - 1);
                                // The page's entries could not be fetched in one
                                // message: ask for fewer next time.
                                let fewer_next_time = || {
                                    if let Ok(mut p) = page_steps.lock() {
                                        p.insert(cursor_key.clone(), (step + 1).min(steps.len() - 1));
                                    }
                                };
                                let resp = match cordelia_network::item_sync::send_sync_page(&mut send, &mut recv, ch_id, after, steps[step]).await {
                                    Ok(r) => r,
                                    Err(e) => { tracing::debug!(peer = %target, channel = %ch_id, error = %e, "sync request failed"); break 'channels; }
                                };

                                if !resp.items.is_empty() {
                                    let known = {
                                        let db = match sync_state.db.lock() {
                                            Ok(db) => db,
                                            Err(_) => break 'channels,
                                        };
                                        let offered: Vec<String> = resp.items.iter().map(|h| h.item_id.clone()).collect();
                                        cordelia_storage::items::known_items(&db, &offered).unwrap_or_default()
                                    };
                                    let mut fetch_ids = cordelia_network::item_sync::compute_fetch_list(&resp.items, &known);
                                    // A device can tell from an entry's header
                                    // whether it will store it, and does not
                                    // fetch the rest of one it will not.
                                    if role == "personal" {
                                        let own = sync_state.identity.public_key();
                                        if let Ok(db) = sync_state.db.lock() {
                                            fetch_ids.retain(|id| {
                                                resp.items.iter().find(|h| &h.item_id == id).is_some_and(|h| {
                                                    <[u8; 32]>::try_from(h.author_id.as_slice()).is_ok_and(|author| {
                                                        wanted_by_a_device(&db, &h.channel_id, &author, &own)
                                                    })
                                                })
                                            });
                                        }
                                    }
                                    if !fetch_ids.is_empty() {
                                        if let Err(e) = cordelia_network::item_sync::send_fetch_request(&mut send, &fetch_ids).await {
                                            tracing::debug!(peer = %target, error = %e, "fetch request failed");
                                            break 'channels; // Stream corrupted
                                        }
                                        let items = match cordelia_network::item_sync::read_fetch_response(&mut recv).await {
                                            Ok(items) => items,
                                            Err(e) => {
                                                tracing::debug!(peer = %target, channel = %ch_id, asked = fetch_ids.len(), error = %e, "fetch response failed; asking for fewer next time");
                                                fewer_next_time();
                                                break 'channels;
                                            }
                                        };

                                        let mut stored_count = 0u32;
                                        let mut newly_stored_items: Vec<cordelia_network::messages::Item> = Vec::new();
                                        // Checked before the database is held.
                                        let checked: Vec<Result<Checked, &'static str>> = items.iter().map(check_item).collect();
                                        {
                                            let db = match sync_state.db.lock() {
                                                Ok(db) => db,
                                                Err(_) => break 'channels,
                                            };
                                            let own = sync_state.identity.public_key();
                                            let max_bytes = room_rates.lock().unwrap_or_else(|e| e.into_inner()).relay_max_bytes;
                                            let mut room = RelayRoom::new(
                                                max_bytes,
                                                (!from_listed_relay).then_some((source_address, &*room_rates)),
                                            );
                                            // One transaction for the page,
                                            // as for a push.
                                            let Ok(batch) = db.unchecked_transaction() else { break 'channels };
                                            for (item, checked) in items.iter().zip(checked) {
                                                let room = is_relay_node.then_some(&mut room);
                                                let outcome = checked.and_then(|checked| store_checked(&db, item, &checked, &role, &own, room));
                                                if let Ok(true) = outcome {
                                                    stored_count += 1;
                                                    if is_relay_node {
                                                        newly_stored_items.push(item.clone());
                                                    }
                                                }
                                            }
                                            // A page that could not be stored
                                            // is not passed: it is asked for
                                            // again.
                                            if let Err(e) = batch.commit() {
                                                tracing::warn!(peer = %target, error = %e, "could not store a fetched page");
                                                break 'channels;
                                            }
                                        }
                                        // Epidemic forwarding: relay queues sync-discovered items
                                        // for repush, recording sync source in seen table.
                                        if is_relay_node && !newly_stored_items.is_empty() {
                                            if let Ok(mut st) = seen_ref.write() {
                                                for item in &newly_stored_items {
                                                    let hash: [u8; 32] = item.content_hash.as_slice().try_into().unwrap_or([0u8; 32]);
                                                    st.record_sender(&hash, &target);
                                                }
                                            }
                                            for item in newly_stored_items {
                                                let _ = rtx.send((item, target.clone()));
                                            }
                                        }
                                        if stored_count > 0 {
                                            tracing::info!(channel = %ch_id, fetched = fetch_ids.len(), stored = stored_count, "pull-sync page complete");
                                            total_stored += stored_count as u64;
                                        }
                                    }
                                }

                                // A peer without arrival paging answers once, the old way.
                                let Some(last_seq) = resp.last_seq else { break };
                                if let Ok(mut c) = cursors.lock() {
                                    c.insert(cursor_key.clone(), last_seq);
                                }
                                if !resp.has_more {
                                    // Caught up here: back to full pages.
                                    if let Ok(mut p) = page_steps.lock() {
                                        p.remove(&cursor_key);
                                    }
                                    break;
                                }
                            }
                        }
                        // FIN: signal end of batch to server
                        let _ = send.finish();
                        // One GovEvent per peer (not per channel)
                        if total_stored > 0 {
                            let _ = gtx.send(GovEvent::ItemsDelivered(target.clone(), total_stored));
                        }
                    });
                    }
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
#[allow(clippy::too_many_arguments)]
pub async fn handle_peer_streams(
    conn: quinn::Connection,
    peer_id: NodeId,
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

        // Rate limits (§9.2): this connection's allowance, and its
        // address's. A request over either is refused at once, so the peer
        // does not wait for an answer that is not coming. A peer that keeps
        // going over is cut off, and its address refused for a time.
        //
        // A relay this node was configured with is never cut off. Between
        // two relays that list each other there is no limit at all: they
        // are one operator's, and each passes on everything its devices
        // send. A device still counts what its relay asks of it.
        let address = conn.remote_address().ip();
        let own_relay = peer_relays
            .read()
            .ok()
            .is_some_and(|relays| relays.contains(&peer_id));
        let unlimited = own_relay && node_role == "relay";
        let over = if unlimited {
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
        let mut room = RelayRoom::new(max_bytes, limited.then_some((address, &**peer_rates)));
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
        let empty = cordelia_storage::db::used_bytes(&db).unwrap();
        let mut room = RelayRoom::new(empty + 400_000, None);

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
        let used = cordelia_storage::db::used_bytes(&db).unwrap();
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
            let used = cordelia_storage::db::used_bytes(&db).unwrap();
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
        let mut room = RelayRoom::new(u64::MAX, None);
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
        let mut room = RelayRoom::new(u64::MAX, Some((address, &rates)));
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
        let mut room = RelayRoom::new(u64::MAX, Some((elsewhere, &rates)));
        assert_eq!(relay_store(&db, &mut room, &channel(301), 100), Ok(true));
        let mut room = RelayRoom::new(u64::MAX, None);
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
        let mut room = RelayRoom::new(u64::MAX, None);
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
        let mut next = RelayRoom::new(u64::MAX, None);
        next.max_channel_bytes = room.max_channel_bytes;
        assert_eq!(
            relay_store(&db, &mut next, &small, SMALL),
            Err(REFUSED_FULL)
        );
        assert_eq!(holds(&db, &small), 100 * SMALL as u64);
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
