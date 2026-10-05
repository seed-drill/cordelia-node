//! A relay's side of the entries of channels from their secrets, on real
//! connections (decision 2026-10-04 §2.4, §2.5, §4.6).
//!
//! What a relay does with an entry is in `cordelia_storage::relay`: plain
//! functions over a database. This is who asks them, and when: the streams
//! that a peer opens, the relays that the operator lists together, and the
//! limits that every peer is held to.
//!
//! **Only a relay has any of it.** [`RelayEntries`] is made for a node
//! whose role is "relay" and for no other. A personal node answers none of
//! these streams, as it answers none that it does not serve (§4.6): a
//! relay's rules count and drop what a store holds as the relay's own, and
//! a device's store is its own.
//!
//! ## The four streams, one request on each
//!
//! - **Show** (§2.4 item 5). The entry is read from its bytes and both its
//!   signatures are checked before the store is looked at (§16). The
//!   answer is the store's: it holds that entry; it took it; or it holds
//!   another from that author in that slot, and here it is. The
//!   connection remembers, for each author's slot, the last entry that it
//!   showed whole there whose signatures held, up to a bound and for as
//!   long as it lasts. It may then show that same entry in short: by its
//!   channel, slot, author, revision and ID. A short show of anything else
//!   is answered "show it whole" from what the connection remembers,
//!   before the store is looked at and with no lock on the database
//!   taken. One of the entry remembered is answered from the store: held,
//!   "show it whole", or the revision and ID of another. The answer to a
//!   short show never carries an entry.
//! - **Prove** (§2.4 items 3 and 4). The proof is checked against the
//!   value that this connection's TLS session exports, and against the
//!   node key of the peer as its certificate says it: nothing that says
//!   who proves is taken from the message. The connection remembers each
//!   channel for which a proof held, up to a bound, for as long as it
//!   lasts, and forgets them when it closes.
//! - **Pull** (§2.4 item 3). A page of a channel, only where the channel
//!   was proved on this connection. Without that the answer is the one
//!   for a channel that the relay does not hold.
//! - **Push** (§2.4 items 1 and 2). Each entry is checked and taken by the
//!   store's rule, and each is answered for.
//!
//! ## Who asks
//!
//! A peer is its address, for the room's allowance of new channels, or it
//! is a relay that the operator lists. **A listed relay is one whose key
//! the operator configured**, and the key is the one in the peer's
//! certificate. A relay that is configured by address alone is not one
//! here: whoever came from that address would be handed every channel.
//!
//! ## The limits
//!
//! The limits by address are the ones that the older kind of channel has,
//! with the same numbers, and the two kinds are counted together
//! ([`Rates`]):
//!
//! - what a peer pushes and shows, against the bytes it may push in a
//!   minute;
//! - what it is handed, in a page or in the answer to an entry shown,
//!   against the bytes that may be fetched in a minute;
//! - each for the connection and for its address, and a peer that pushes
//!   or shows over its allowance is refused that request, and cut off
//!   after as many breaches as cut a peer off today, with its address
//!   refused for a time;
//! - a pull that would hand more than the asker may be handed for now is
//!   refused, and is no breach: the relay sized the page, and the asker
//!   cannot know its room. The entry that answers a show is always
//!   handed, and counted, though it take the asker over by that one
//!   entry: a device that is over its bytes must still hear of a removal
//!   (§16).
//!
//! Every entry counts as its content and what an entry takes beyond it.
//! Bytes that are no entry's count for all of them, and for no less than
//! an entry. The short form of a show counts as bytes that are no entry's.
//! A relay that the operator lists is not limited.
//!
//! ## Relays that work together
//!
//! On a stream of their own, which is refused for any peer that is not a
//! listed relay (§2.4 items 4 and 6):
//!
//! - a relay tells which channels it holds, each with the mark of its
//!   holding, since when it has held it, when it was last used, and its
//!   last place;
//! - a relay hands a page of a channel without the proof;
//! - a relay passes on an entry that it took, with those two times.
//!
//! A relay asks each listed relay what it holds, keeps the earlier "held
//! since" and the later "last used" for the channels it holds itself, and
//! pulls what it lacks ([`RelayEntries::pull_from`]). An entry that it
//! takes, from anyone, is passed on to the listed relays that are
//! connected, but for the one it came from ([`RelayEntries::pass_on`]).
//! Nothing is tried again: what did not arrive is pulled.
//!
//! A pass reads only so many pages of a relay's list, and the next goes
//! on from where it stopped: a list that never ends does not keep a
//! relay asking, and what is remembered of a list is a page of it at a
//! time. A channel whose page cannot be taken is left for the next pass,
//! and the channels after it are pulled all the same.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cordelia_core::NodeId;
use cordelia_core::protocol::{
    ENTRY_OVERHEAD_BYTES, ENTRY_PAGE_MAX_BYTES, ENTRY_PAGE_MAX_ENTRIES, ENTRY_WIRE_OVERHEAD_BYTES,
    MAX_CHANNELS_PROVED_ON_A_CONNECTION, MAX_ITEM_BYTES, MAX_SLOTS_SHOWN_ON_A_CONNECTION,
    MIN_ENTRY_CONTENT_BYTES, RELAY_CHANNEL_PAGES_PER_PASS, RELAY_CHANNELS_PAGE_MAX,
    RELAY_ENTRY_PULL_PAGES, SESSION_VALUE_BYTES, entry_cost,
};
use cordelia_crypto::entry::CheckedEntry;
use cordelia_crypto::proof;
use cordelia_network::codec;
use cordelia_network::messages::{
    ChannelProve, ChannelProved, EntryPull, EntryPulled, EntryPush, EntryPushed, EntryShow,
    EntryShowShort, EntryShown, Protocol, PushAnswer, RelayChannel, RelayChannelsAsk,
    RelayChannelsHeld, RelayEntry, RelayPull, RelayPush, ShowAnswer, WireMessage,
};
use cordelia_network::transport;
use cordelia_storage::relay::{self, Asker, Mark, Refused, Room, Shown, Taken};
use rusqlite::Connection;

use crate::p2p::{OverLimit, Rates, RelayAddrs};

/// The most a page can be counted at: every byte a page may take as it
/// travels, and what each of the most entries it may hold takes beyond
/// its content.
const FULL_PAGE_COST: u64 =
    ENTRY_PAGE_MAX_BYTES as u64 + ENTRY_PAGE_MAX_ENTRIES as u64 * ENTRY_OVERHEAD_BYTES as u64;

// Checked at compile time. A whole page is handed only while the allowance
// has room for the most it can be counted at, so that must be within what
// a connection may be handed in a minute, or none ever would be.
const _: () = assert!(FULL_PAGE_COST <= cordelia_core::protocol::PUSH_BYTES_PER_PEER_PER_MINUTE);

/// Lock a mutex, also one whose holder panicked: what it guards is counts
/// and places, which are whole after any one step.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// This relay's time, in seconds, in UTC.
fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// What bytes that a peer sends as an entry count at, against what it may
/// push: an entry's content and what an entry takes beyond it
/// ([`entry_cost`]). Bytes that are no entry's count for every one of
/// them, and for no less than the smallest thing an entry is counted at.
fn counted(bytes: &[u8]) -> u64 {
    entry_cost(bytes.len().saturating_sub(ENTRY_WIRE_OVERHEAD_BYTES))
}

/// How many entries a page may hold for a peer whose allowance has `room`
/// bytes left, where it asked for `asked`.
///
/// - Room for the most a page can be counted at: as many as it asked for.
/// - Less: as many as would fit if each were of the largest size, since
///   an entry's size is not known until it is read.
/// - Not room for one of the largest: one. It is handed if it fits, and
///   the pull is refused if it does not.
fn page_limit(asked: u32, room: u64) -> u32 {
    if room >= FULL_PAGE_COST {
        return asked;
    }
    let fit = (room / entry_cost(MAX_ITEM_BYTES)).max(1);
    asked.min(u32::try_from(fit).unwrap_or(u32::MAX))
}

/// What a relay remembers of one connection: the channels whose keys were
/// proved on it (decision 2026-10-04 §2.4 item 3).
///
/// It lives as long as the connection's stream handler does, and is gone
/// with it: a proof is for the one TLS session it was made over. Only a
/// proof that held is remembered, whether or not the relay held the
/// channel then, so that a channel which arrives later is handed with no
/// proof more.
///
/// At most MAX_CHANNELS_PROVED_ON_A_CONNECTION channels are remembered.
/// Whoever holds a secret can prove its channel, held or not, and a secret
/// costs nothing to make.
#[derive(Debug, Default)]
pub struct Proved {
    channels: HashSet<[u8; 32]>,
}

impl Proved {
    /// Whether `channel` was proved on this connection.
    pub fn holds(&self, channel: &[u8; 32]) -> bool {
        self.channels.contains(channel)
    }

    /// Whether a proof for `channel` is looked at: it is remembered
    /// already, or there is room to remember one channel more.
    fn has_room_for(&self, channel: &[u8; 32]) -> bool {
        self.holds(channel) || self.channels.len() < MAX_CHANNELS_PROVED_ON_A_CONNECTION
    }

    /// A proof for `channel` held.
    fn remember(&mut self, channel: [u8; 32]) {
        self.channels.insert(channel);
    }

    /// How many channels are remembered.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.channels.len()
    }
}

/// What a relay remembers of one connection besides: for each author's
/// slot in a channel, the last entry that the connection showed whole
/// there whose two signatures held, by its revision and its ID, whatever
/// the relay answered (decision 2026-10-04 §2.4 item 5).
///
/// The connection may show that same entry in short, and is answered from
/// the store. A short show of anything else, a slot that is not remembered
/// included, is answered "show it whole" from here alone: so the short
/// form tells nothing, and hands nothing, to anyone who has not shown that
/// very entry whole.
///
/// It lives and goes as [`Proved`] does. At most
/// MAX_SLOTS_SHOWN_ON_A_CONNECTION slots are remembered: one more is not,
/// and is shown whole each time. None is put out for it.
#[derive(Debug, Default)]
pub struct ShownWhole {
    slots: Vec<ShownSlot>,
}

/// An author's slot in a channel, and the entry that a connection last
/// showed whole there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShownSlot {
    /// The slot: its channel, its slot and its author.
    place: [[u8; 32]; 3],
    /// The entry's revision.
    rev: u64,
    /// The entry's ID.
    id: [u8; 32],
}

impl ShownWhole {
    /// Whether `show` is of the very entry that the connection last
    /// showed whole in that author's slot.
    pub fn is_of(&self, show: &EntryShowShort) -> bool {
        self.slots.contains(&ShownSlot {
            place: [show.channel, show.slot, show.author],
            rev: show.rev,
            id: show.id,
        })
    }

    /// The connection showed `entry` whole, and both its signatures held.
    fn remember(&mut self, entry: &CheckedEntry) {
        let shown = ShownSlot {
            place: [entry.channel, entry.slot, entry.author],
            rev: entry.rev,
            id: entry.id(),
        };
        if let Some(kept) = self.slots.iter_mut().find(|kept| kept.place == shown.place) {
            *kept = shown;
        } else if self.slots.len() < MAX_SLOTS_SHOWN_ON_A_CONNECTION {
            self.slots.push(shown);
        }
    }

    /// How many slots are remembered.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.slots.len()
    }
}

/// Who opened a stream: the peer, as its connection says it.
pub struct Who<'a> {
    /// The peer's node key.
    pub peer: &'a NodeId,
    /// The address its connection comes from.
    pub address: IpAddr,
    /// Whether it is a relay that the operator lists by key.
    pub listed: bool,
}

impl Who<'_> {
    /// Who asks the store: a listed relay, or the peer's address.
    fn asker(&self) -> Asker {
        if self.listed {
            Asker::ListedRelay {
                held_since: None,
                used_at: None,
            }
        } else {
            Asker::Address(self.address)
        }
    }
}

/// What a connection is for a proof: the value that its TLS session
/// exports, and the node key of the peer at its other end.
pub struct Session {
    /// What both ends export from this connection's TLS session.
    pub value: [u8; SESSION_VALUE_BYTES],
    /// The node key in the certificate that the peer presented.
    pub prover: [u8; 32],
}

impl Session {
    /// Of `conn`. `None` where the session gives no value, or the peer no
    /// key: no proof holds on such a connection.
    fn of(conn: &quinn::Connection) -> Option<Self> {
        Some(Self {
            value: transport::session_value(conn).ok()?,
            prover: transport::peer_key(conn).ok()?,
        })
    }
}

/// What becomes of a request.
#[derive(Debug)]
pub enum Answer {
    /// It is answered with this.
    Message(Box<WireMessage>),
    /// It is over a limit: the stream is refused, and nothing is said.
    Over(OverLimit),
    /// It asks for more than the asker may be handed for now: the stream
    /// is refused, nothing is said, and nothing is counted. It is no
    /// breach.
    NotNow,
    /// It could not be served: nothing is said.
    Nothing,
    /// It is no request for the stream it came on: one of another
    /// stream's, or one on the stream between relays from a peer that the
    /// operator does not list. Nothing is said, and the bytes of its
    /// frame count as pushed.
    Stray,
}

impl Answer {
    /// It is answered with `message`.
    fn of(message: WireMessage) -> Self {
        Self::Message(Box::new(message))
    }
}

/// An entry that this relay took, to be passed on.
struct TakenEntry {
    /// The entry, as its bytes on the wire.
    bytes: Vec<u8>,
    /// Its channel.
    channel: [u8; 32],
    /// The relay it came from, where it came from one: it is not passed
    /// back there.
    from: Option<NodeId>,
}

/// A relay's place in a channel that a relay it works with holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Place {
    /// The mark of the holding there that the place is in.
    mark: Mark,
    /// The place of the last entry that was pulled.
    after: u64,
    /// Not pulled before this: the channel found no room here.
    not_before: Option<Instant>,
}

/// What a relay keeps for the relays it pulls from: its place in each
/// channel that each of them holds. In memory: after a restart every
/// channel is pulled from the start, and what is held already is not
/// stored again.
#[derive(Default)]
struct Places {
    by_peer: HashMap<NodeId, HashMap<[u8; 32], Place>>,
}

impl Places {
    fn get(&self, peer: &NodeId, channel: &[u8; 32]) -> Option<Place> {
        self.by_peer.get(peer)?.get(channel).copied()
    }

    fn keep(&mut self, peer: &NodeId, channel: [u8; 32], place: Place) {
        self.by_peer
            .entry(peer.clone())
            .or_default()
            .insert(channel, place);
    }

    /// Forget the places in `channels`, at every relay: this relay dropped
    /// them, and pulls each from the start if it takes it again.
    fn forget_channels(&mut self, channels: &[[u8; 32]]) {
        for kept in self.by_peer.values_mut() {
            kept.retain(|channel, _| !channels.contains(channel));
        }
    }

    /// Keep for `peer`, of the places in channels whose IDs are after
    /// `from` and up to `to`, only those in channels that it told of: a
    /// page of its list tells every channel it holds between those two,
    /// and what it holds no more has no place.
    fn keep_only(
        &mut self,
        peer: &NodeId,
        (from, to): (&[u8; 32], &[u8; 32]),
        told: &HashSet<[u8; 32]>,
    ) {
        if let Some(kept) = self.by_peer.get_mut(peer) {
            kept.retain(|channel, _| channel <= from || channel > to || told.contains(channel));
        }
    }

    #[cfg(test)]
    fn total(&self) -> usize {
        self.by_peer.values().map(HashMap::len).sum()
    }
}

/// How a page that was pulled from a listed relay ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pulled {
    /// It was taken, and there is more: go on from this mark and place.
    More(Mark, u64),
    /// It was taken, and the channel is caught up there.
    CaughtUp,
    /// An entry found no room here. The page is not passed, and the
    /// channel is left for a while.
    NoRoom,
    /// What came back was not a page of the channel asked for. Nothing of
    /// it was taken.
    NotThePage,
    /// The page could not be stored. Nothing of it was taken.
    NotStored,
}

/// A pull that is running from one relay. While it lives, no other is
/// started from that relay.
struct Pulling<'a> {
    relays: &'a Mutex<HashSet<NodeId>>,
    relay: NodeId,
}

impl<'a> Pulling<'a> {
    /// `None` where a pull from `relay` is already running.
    fn begin(relays: &'a Mutex<HashSet<NodeId>>, relay: &NodeId) -> Option<Self> {
        lock(relays).insert(relay.clone()).then(|| Self {
            relays,
            relay: relay.clone(),
        })
    }
}

impl Drop for Pulling<'_> {
    fn drop(&mut self) {
        lock(self.relays).remove(&self.relay);
    }
}

/// What a relay holds, across its connections, for the entries of channels
/// from their secrets (see the module's documentation).
pub struct RelayEntries {
    /// Its room for this kind of channel: a cap of its own, of the size of
    /// the older kind's, and what each address made it take lately
    /// (decision 2026-10-04 §2.5). For the one version that carries both
    /// kinds a relay can hold twice its cap.
    room: Mutex<Room>,
    /// The relays that the operator configured.
    relays: RelayAddrs,
    /// The entries it took, waiting to be passed on to the listed relays.
    taken: Mutex<Vec<TakenEntry>>,
    /// Its places in the channels of the relays it pulls from.
    places: Mutex<Places>,
    /// The relays a pull is running from.
    pulling: Mutex<HashSet<NodeId>>,
    /// Where the last pass stopped in the list of each relay that tells
    /// of more channels than one pass reads: the next goes on after that
    /// ID. A relay whose list was read to its end has none.
    stopped_at: Mutex<HashMap<NodeId, [u8; 32]>>,
    /// How long a channel that found no room here is left before it is
    /// pulled again from a listed relay.
    ask_again: Duration,
}

impl RelayEntries {
    /// For a relay that may hold `max_bytes` of this kind of channel, and
    /// works with `relays`.
    pub fn new(max_bytes: u64, relays: RelayAddrs, ask_again: Duration) -> Self {
        Self {
            room: Mutex::new(Room::new(max_bytes)),
            relays,
            taken: Mutex::default(),
            places: Mutex::default(),
            pulling: Mutex::default(),
            stopped_at: Mutex::default(),
            ask_again,
        }
    }

    /// The keys of the relays that the operator lists: each configured
    /// relay that has one.
    pub fn listed(&self) -> Vec<NodeId> {
        let Ok(relays) = self.relays.read() else {
            return Vec::new();
        };
        let mut listed: Vec<NodeId> = relays
            .iter()
            .filter_map(|relay| relay.key.map(NodeId))
            .collect();
        listed.sort_by_key(|relay| relay.0);
        listed.dedup();
        listed
    }

    /// Whether `peer` is a relay that the operator lists (decision
    /// 2026-10-04 §2.4 item 6): its key is the configured key of a relay.
    /// The caller has the peer's key from its certificate.
    ///
    /// A relay that is configured with no key is not listed, whatever
    /// address a peer comes from and whatever it says of itself.
    pub fn lists(&self, peer: &NodeId) -> bool {
        self.relays
            .read()
            .is_ok_and(|relays| relays.iter().any(|relay| relay.key == Some(peer.0)))
    }

    // ── What is done when the relay starts, and each hour ──────────────

    /// Drop what the relay holds beyond its cap, the newest first: for a
    /// relay whose cap came down (decision 2026-10-04 §2.5). The cap is
    /// read when the node starts and at no other time, so this is run
    /// then. No write takes a relay past its cap.
    pub fn make_room(&self, db: &Mutex<Connection>) {
        let Ok(db) = db.lock() else { return };
        let max_bytes = lock(&self.room).max_bytes;
        match relay::make_room(&db, max_bytes) {
            Ok(dropped) => self.dropped(&dropped, "to be within the cap"),
            Err(e) => tracing::warn!(error = %e, "could not make room for entries"),
        }
    }

    /// Drop each channel that nobody has used for 90 days (decision
    /// 2026-10-04 §2.5), and forget each address that has made the relay
    /// take no channel within the hour.
    pub fn sweep(&self, db: &Mutex<Connection>) {
        self.sweep_at(db, unix_now());
    }

    /// [`Self::sweep`], at `now`, this relay's time in seconds.
    fn sweep_at(&self, db: &Mutex<Connection>, now: i64) {
        lock(&self.room).forget_old(now);
        let Ok(db) = db.lock() else { return };
        match relay::sweep_unused(&db, now) {
            Ok(dropped) => self.dropped(&dropped, "unused"),
            Err(e) => tracing::warn!(error = %e, "could not sweep the channels nobody uses"),
        }
    }

    /// The relay dropped `channels`. Its places in them, at the relays it
    /// pulls from, mean nothing for a channel that it takes again: they
    /// are forgotten, and such a channel is pulled from the start.
    fn dropped(&self, channels: &[[u8; 32]], why: &str) {
        if channels.is_empty() {
            return;
        }
        lock(&self.places).forget_channels(channels);
        tracing::info!(
            channels = channels.len(),
            why,
            "dropped channels of entries"
        );
    }

    // ── The four streams ───────────────────────────────────────────────

    /// Answer one request that `who` made on a stream of `protocol`, at
    /// `now`, this relay's time in seconds. `session` is what a proof on
    /// this connection is checked against, `proved` what the connection
    /// has proved so far, and `whole` what it has shown whole.
    ///
    /// A stream carries its own kind of request and no other. The stream
    /// between relays that work together is answered for a relay that the
    /// operator lists, and for no other peer.
    #[expect(
        clippy::too_many_arguments,
        reason = "what a request is answered from: the stream, the peer, its connection, and what the node holds"
    )]
    fn answer(
        &self,
        protocol: Protocol,
        request: &WireMessage,
        who: &Who,
        session: Option<&Session>,
        proved: &mut Proved,
        whole: &mut ShownWhole,
        db: &Mutex<Connection>,
        rates: &Mutex<Rates>,
        now: i64,
    ) -> Answer {
        match (protocol, request) {
            (Protocol::EntryShow, WireMessage::EntryShow(show)) => {
                self.shown(db, rates, who, whole, show, now)
            }
            (Protocol::EntryShow, WireMessage::EntryShowShort(show)) => {
                self.shown_short(db, rates, who, whole, show, now)
            }
            (Protocol::ChannelProve, WireMessage::ChannelProve(prove)) => {
                self.proving(db, session, proved, prove, now)
            }
            (Protocol::EntryPull, WireMessage::EntryPull(pull)) => {
                self.pulling(db, rates, who, proved, pull)
            }
            (Protocol::EntryPush, WireMessage::EntryPush(push)) => {
                self.pushing(db, rates, who, push, now)
            }
            (Protocol::RelayEntries, request) if who.listed => {
                self.asked_by_a_relay(db, who.peer, request, now)
            }
            _ => Answer::Stray,
        }
    }

    /// Answer an entry that is shown (decision 2026-10-04 §2.4 item 5).
    /// Where both its signatures hold, the connection is remembered to
    /// have shown it whole in its slot, whatever the store then answers:
    /// `whole` is what the connection has shown so.
    fn shown(
        &self,
        db: &Mutex<Connection>,
        rates: &Mutex<Rates>,
        who: &Who,
        whole: &mut ShownWhole,
        show: &EntryShow,
        now: i64,
    ) -> Answer {
        // What is shown may be taken, so it counts as what is pushed
        // does. Over either allowance, it is not looked at.
        if !who.listed
            && let Err(over) = lock(rates).pushed(who.peer, who.address, counted(&show.entry))
        {
            return Answer::Over(over);
        }
        // Read strictly, and both signatures, before the store is looked
        // at (§16).
        let entry = match relay::check(&show.entry) {
            Ok(entry) => entry,
            Err(why) => {
                return Answer::of(WireMessage::EntryShown(EntryShown {
                    answer: ShowAnswer::Refused((&why).into()),
                }));
            }
        };
        // Its signatures held: from now on the connection may show this
        // entry in short, and no other of its slot.
        whole.remember(&entry);
        let found = {
            let Ok(db) = db.lock() else {
                return Answer::Nothing;
            };
            let found = {
                let mut room = lock(&self.room);
                relay::show(&db, &mut room, &entry, &who.asker(), now)
            };
            let found = match found {
                Ok(found) => found,
                Err(e) => {
                    tracing::warn!(peer = %who.peer, error = %e, "could not answer an entry shown");
                    return Answer::Nothing;
                }
            };
            // The entry that goes back counts against the asker's limits
            // as anything fetched does. It goes back all the same where
            // it takes the asker over: this is how a change reaches a
            // device.
            if !who.listed
                && let Shown::Another { cost, .. } = &found
            {
                lock(rates).answered(who.peer, who.address, *cost);
            }
            found
        };
        if found == Shown::Taken {
            self.took(std::iter::once(&entry), who.listed.then_some(who.peer));
        }
        Answer::of(WireMessage::EntryShown(EntryShown {
            answer: (&found).into(),
        }))
    }

    /// Answer an entry that is shown in short (decision 2026-10-04 §2.4
    /// item 5): by its channel, slot, author, revision and ID. `whole` is
    /// what this connection has shown whole.
    ///
    /// **The connection's memory is asked before the store.** A short show
    /// of anything but the entry that the connection last showed whole in
    /// that slot is answered "show it whole" from the memory alone: the
    /// store is not looked at and the database is not locked, so the
    /// answer says nothing of what the relay holds, takes no longer where
    /// something is held, and waits for no writer.
    ///
    /// Where it is of that entry, the store answers: held, "show it
    /// whole", or the revision and ID of another. No entry goes back, so
    /// nothing counts as fetched.
    fn shown_short(
        &self,
        db: &Mutex<Connection>,
        rates: &Mutex<Rates>,
        who: &Who,
        whole: &ShownWhole,
        show: &EntryShowShort,
        now: i64,
    ) -> Answer {
        // It counts as bytes that are no entry's do: for no less than the
        // smallest thing an entry is counted at. Over either allowance, it
        // is not looked at.
        if !who.listed
            && let Err(over) = lock(rates).pushed(who.peer, who.address, counted(&[]))
        {
            return Answer::Over(over);
        }
        if !whole.is_of(show) {
            return Answer::of(WireMessage::EntryShown(EntryShown {
                answer: ShowAnswer::Whole,
            }));
        }
        let found = {
            let Ok(db) = db.lock() else {
                return Answer::Nothing;
            };
            relay::show_short(
                &db,
                &show.channel,
                &show.slot,
                &show.author,
                show.rev,
                &show.id,
                now,
            )
        };
        match found {
            Ok(found) => Answer::of(WireMessage::EntryShown(EntryShown {
                answer: (&found).into(),
            })),
            Err(e) => {
                tracing::warn!(peer = %who.peer, error = %e, "could not answer an entry shown in short");
                Answer::Nothing
            }
        }
    }

    /// Answer a proof that the peer holds a channel's key (decision
    /// 2026-10-04 §2.4 items 3 and 4), and remember the channel with the
    /// connection where the proof holds.
    ///
    /// `session` is this connection's: the value its TLS session exports,
    /// and the peer's key from its certificate. Without one no proof
    /// holds.
    fn proving(
        &self,
        db: &Mutex<Connection>,
        session: Option<&Session>,
        proved: &mut Proved,
        prove: &ChannelProve,
        now: i64,
    ) -> Answer {
        let no = Answer::of(WireMessage::ChannelProved(ChannelProved { proved: false }));
        let Some(session) = session else {
            return no;
        };
        // A connection that has proved as many channels as one may is
        // answered as for a proof that fails, and the proof is not looked
        // at: nothing more is remembered for it.
        if !proved.has_room_for(&prove.channel) {
            return no;
        }
        // The signature, before the channel is looked up and before the
        // database is held.
        if !proof::check(
            &prove.channel,
            &session.value,
            &session.prover,
            &prove.proof,
        ) {
            return no;
        }
        let found = {
            let Ok(db) = db.lock() else {
                return Answer::Nothing;
            };
            relay::prove(
                &db,
                &prove.channel,
                &session.value,
                &session.prover,
                &prove.proof,
                now,
            )
        };
        let found = match found {
            Ok(found) => found,
            Err(e) => {
                tracing::warn!(error = %e, "could not answer a proof");
                return Answer::Nothing;
            }
        };
        if found.holds() {
            proved.remember(prove.channel);
        }
        Answer::of(WireMessage::ChannelProved((&found).into()))
    }

    /// Answer a request for a page of a channel (decision 2026-10-04 §2.4
    /// item 3): only where the channel was proved on this connection.
    ///
    /// The connection's memory is asked before the store (§16). A channel
    /// that was not proved on it is answered as one that is not held, with
    /// the place and the mark that were asked with, and the database is
    /// not waited for: whoever asks without a proof costs the relay no
    /// look at what it holds.
    fn pulling(
        &self,
        db: &Mutex<Connection>,
        rates: &Mutex<Rates>,
        who: &Who,
        proved: &Proved,
        pull: &EntryPull,
    ) -> Answer {
        let proved = proved.holds(&pull.channel);
        if !proved {
            return Answer::of(WireMessage::EntryPulled(EntryPulled {
                entries: Vec::new(),
                next: pull.after,
                mark: pull.mark,
            }));
        }
        let Ok(db) = db.lock() else {
            return Answer::Nothing;
        };
        // What the peer's allowance has room for, where it is handed
        // anything: a relay the operator lists is not limited, and a
        // channel that was not proved is not handed.
        let room = (proved && !who.listed).then(|| lock(rates).fetch_room(who.peer, who.address));
        let limit = room.map_or(pull.limit, |room| page_limit(pull.limit, room));
        let page = match relay::pull(&db, &pull.channel, proved, &pull.mark, pull.after, limit) {
            Ok(page) => page,
            Err(e) => {
                tracing::warn!(peer = %who.peer, error = %e, "could not read a page of entries");
                return Answer::Nothing;
            }
        };
        // What is handed counts against the asker's limits. A page is
        // sized to the room there is, so this is over only where not even
        // the first entry fits: then nothing is handed, and nothing is
        // counted. The asker could not know: it is no breach.
        if room.is_some() && !lock(rates).handed(who.peer, who.address, page.cost) {
            return Answer::NotNow;
        }
        Answer::of(WireMessage::EntryPulled((&page).into()))
    }

    /// Take the entries that a peer pushes (decision 2026-10-04 §2.4
    /// items 1 and 2), and answer for each.
    fn pushing(
        &self,
        db: &Mutex<Connection>,
        rates: &Mutex<Rates>,
        who: &Who,
        push: &EntryPush,
        now: i64,
    ) -> Answer {
        // A push of nothing is answered with nothing, and nothing is
        // kept of it.
        if push.entries.is_empty() {
            return Answer::of(WireMessage::EntryPushed(EntryPushed {
                answers: Vec::new(),
            }));
        }
        // What the push carries counts against the connection's allowance
        // and its address's. Over either, it is refused whole.
        let bytes: u64 = push.entries.iter().map(|entry| counted(entry)).sum();
        if !who.listed
            && let Err(over) = lock(rates).may_push(who.peer, who.address, bytes)
        {
            return Answer::Over(over);
        }
        // Checked before the database is held.
        let checked: Vec<Result<CheckedEntry, Refused>> = push
            .entries
            .iter()
            .map(|entry| relay::check(entry))
            .collect();
        let asker = who.asker();
        let from = who.listed.then_some(who.peer);
        match self.take_all(db, checked.iter().map(|entry| (entry, &asker)), from, now) {
            Some(taken) => {
                // Counted once what was pushed is written, and for every
                // entry of it, whatever became of each. A push that the
                // relay could not write is undone, and is not held
                // against whoever sent it.
                if !who.listed {
                    lock(rates).count_pushed(who.peer, who.address, bytes);
                }
                Answer::of(WireMessage::EntryPushed(EntryPushed {
                    answers: taken.iter().map(PushAnswer::from).collect(),
                }))
            }
            None => Answer::Nothing,
        }
    }

    /// Take each entry by the store's rule, as one write, and say what
    /// became of each. What was stored is kept to be passed on. `None`
    /// where the store could not be written: then nothing was taken, and
    /// no address is counted for a channel that the write would have made
    /// the relay take.
    fn take_all<'a>(
        &self,
        db: &Mutex<Connection>,
        entries: impl Iterator<Item = (&'a Result<CheckedEntry, Refused>, &'a Asker)>,
        from: Option<&NodeId>,
        now: i64,
    ) -> Option<Vec<Taken>> {
        let (all, stored) = {
            let db = db.lock().ok()?;
            let mut room = lock(&self.room);
            let written = Self::written_as_one(&db, &mut room, entries, now);
            // An address is counted for the channels it made the relay
            // take once they are written for good, and for none where
            // the write was undone.
            match written {
                Some(_) => room.written(),
                None => room.undone(),
            }
            written?
        };
        self.took(stored.into_iter(), from);
        Some(all)
    }

    /// [`Self::take_all`], in the one transaction: what became of each
    /// entry, and the entries that were stored. `None` where any of it
    /// could not be written: the transaction is then undone as it is
    /// dropped.
    fn written_as_one<'a>(
        db: &Connection,
        room: &mut Room,
        entries: impl Iterator<Item = (&'a Result<CheckedEntry, Refused>, &'a Asker)>,
        now: i64,
    ) -> Option<(Vec<Taken>, Vec<&'a CheckedEntry>)> {
        let mut all = Vec::new();
        let mut stored = Vec::new();
        // One transaction for all of them: one write to disk however
        // many entries there are.
        let batch = db
            .unchecked_transaction()
            .map_err(|e| tracing::warn!(error = %e, "could not begin storing entries"))
            .ok()?;
        for (entry, asker) in entries {
            let taken = match entry {
                Ok(entry) => relay::take(db, room, entry, asker, now)
                    .map_err(|e| tracing::warn!(error = %e, "could not take an entry"))
                    .ok()?,
                Err(why) => Taken::Refused(why.clone()),
            };
            if let (Taken::Stored, Ok(entry)) = (&taken, entry) {
                stored.push(entry);
            }
            all.push(taken);
        }
        batch
            .commit()
            .map_err(|e| tracing::warn!(error = %e, "could not store entries"))
            .ok()?;
        Some((all, stored))
    }

    /// The relay took these entries, from `from` where that is a relay it
    /// works with: they wait to be passed on to the others. Where the
    /// operator lists no relay, nothing waits.
    fn took<'a>(&self, entries: impl Iterator<Item = &'a CheckedEntry>, from: Option<&NodeId>) {
        if self.listed().is_empty() {
            return;
        }
        lock(&self.taken).extend(entries.map(|entry| TakenEntry {
            bytes: entry.to_wire(),
            channel: entry.channel,
            from: from.cloned(),
        }));
    }

    // ── Between relays that work together ──────────────────────────────

    /// Answer a relay that the operator lists (decision 2026-10-04 §2.4
    /// item 6). The caller has made sure that `from` is one.
    fn asked_by_a_relay(
        &self,
        db: &Mutex<Connection>,
        from: &NodeId,
        request: &WireMessage,
        now: i64,
    ) -> Answer {
        match request {
            WireMessage::RelayChannelsAsk(RelayChannelsAsk { after, limit }) => {
                let Ok(db) = db.lock() else {
                    return Answer::Nothing;
                };
                match relay::held_channels(&db, after, *limit) {
                    Ok(held) => Answer::of(WireMessage::RelayChannelsHeld(RelayChannelsHeld {
                        channels: held.iter().map(RelayChannel::from).collect(),
                    })),
                    Err(e) => {
                        tracing::warn!(error = %e, "could not list the channels of entries");
                        Answer::Nothing
                    }
                }
            }
            // Without the proof: the page is the one for a channel that
            // was proved.
            WireMessage::RelayPull(pull) => {
                let Ok(db) = db.lock() else {
                    return Answer::Nothing;
                };
                match relay::pull(&db, &pull.channel, true, &pull.mark, pull.after, pull.limit) {
                    Ok(page) => Answer::of(WireMessage::EntryPulled((&page).into())),
                    Err(e) => {
                        tracing::warn!(error = %e, "could not read a page of entries");
                        Answer::Nothing
                    }
                }
            }
            WireMessage::RelayPush(push) => {
                let passed: Vec<(Result<CheckedEntry, Refused>, Asker)> = push
                    .entries
                    .iter()
                    .map(|passed| {
                        let asker = Asker::ListedRelay {
                            held_since: Some(passed.held_since),
                            used_at: Some(passed.used_at),
                        };
                        (relay::check(&passed.entry), asker)
                    })
                    .collect();
                let entries = passed.iter().map(|(entry, asker)| (entry, asker));
                match self.take_all(db, entries, Some(from), now) {
                    Some(taken) => Answer::of(WireMessage::EntryPushed(EntryPushed {
                        answers: taken.iter().map(PushAnswer::from).collect(),
                    })),
                    None => Answer::Nothing,
                }
            }
            _ => Answer::Stray,
        }
    }

    /// What this relay asks `relay` for of a channel that it tells of:
    /// the mark and the place to pull from, or `None` where this relay
    /// lacks nothing of it, or would not take it now.
    ///
    /// What `relay` says of the channel's two times is kept first, where
    /// this relay holds the channel: the earlier "held since", and the
    /// later "last used".
    fn wants(
        &self,
        db: &Mutex<Connection>,
        relay: &NodeId,
        told: &RelayChannel,
        now: i64,
    ) -> Option<(Mark, u64)> {
        let db = db.lock().ok()?;
        let held = relay::held_channel(&db, &told.channel).ok()?;
        if let Some(held) = held {
            // Written only where there is something to keep: a relay is
            // told of every channel in every pass.
            if told.held_since > 0 && told.held_since < held.held_since {
                let _ = relay::listed_relay_says(&db, &told.channel, told.held_since);
            }
            if told.used_at > held.used_at {
                let _ = relay::listed_relay_used(&db, &told.channel, told.used_at, now);
            }
        }
        let kept = lock(&self.places).get(relay, &told.channel);
        let in_this_holding = kept.filter(|kept| kept.mark == told.mark);
        // Pulled to the end of what is there: nothing is lacked.
        if in_this_holding.is_some_and(|kept| kept.after >= told.places) {
            return None;
        }
        // It found no room here a short while ago.
        if kept.is_some_and(|kept| kept.not_before.is_some_and(|at| Instant::now() < at)) {
            return None;
        }
        if held.is_none() {
            // A channel that nobody has used for 90 days, by what is told
            // of it, would be dropped here at the next sweep.
            if told.used_at > 0 && relay::unused(told.used_at, now) {
                return None;
            }
            // And one that the relay has no room for the smallest entry
            // of is not asked for: every entry of it would be refused.
            let used = relay::used_bytes(&db).ok()?;
            let smallest = entry_cost(MIN_ENTRY_CONTENT_BYTES);
            if used.saturating_add(smallest) > lock(&self.room).max_bytes {
                return None;
            }
        }
        Some(in_this_holding.map_or((told.mark, 0), |kept| (kept.mark, kept.after)))
    }

    /// Take a page that `relay` handed of the channel it told of as
    /// `told`, which was asked for from `asked`, and keep the place.
    /// Returns how it ended, and how many of its entries were stored.
    fn pulled(
        &self,
        db: &Mutex<Connection>,
        relay: &NodeId,
        told: &RelayChannel,
        asked: (Mark, u64),
        page: &EntryPulled,
        now: i64,
    ) -> (Pulled, usize) {
        // Each entry is checked as anything a relay is sent is, and is of
        // the channel that was asked for: otherwise this is not the page,
        // and nothing of it is taken.
        let checked: Vec<Result<CheckedEntry, Refused>> = page
            .entries
            .iter()
            .map(|entry| relay::check(entry))
            .collect();
        if checked.iter().any(|entry| {
            !entry
                .as_ref()
                .is_ok_and(|entry| entry.channel == told.channel)
        }) {
            return (Pulled::NotThePage, 0);
        }
        // Each is taken with what the relay says of the channel's two
        // times.
        let asker = Asker::ListedRelay {
            held_since: Some(told.held_since),
            used_at: Some(told.used_at),
        };
        let Some(taken) = self.take_all(
            db,
            checked.iter().map(|entry| (entry, &asker)),
            Some(relay),
            now,
        ) else {
            return (Pulled::NotStored, 0);
        };
        let stored = taken
            .iter()
            .filter(|taken| **taken == Taken::Stored)
            .count();
        // An entry that found no room: the page is not passed, so that it
        // is asked for again, and not before a while has gone by.
        if taken.iter().any(|taken| matches!(taken, Taken::Refused(_))) {
            let after = if page.mark == asked.0 { asked.1 } else { 0 };
            lock(&self.places).keep(
                relay,
                told.channel,
                Place {
                    mark: page.mark,
                    after,
                    not_before: Some(Instant::now() + self.ask_again),
                },
            );
            return (Pulled::NoRoom, stored);
        }
        // The place is kept: in the holding that the page says. (A page
        // that says the mark of no holding is of no holding, and no place
        // is kept for it. Nor is one kept for a page with nothing in it
        // where none was kept: a relay that tells of channels and hands
        // nothing of them has this relay remember nothing.)
        let kept_before = lock(&self.places).get(relay, &told.channel).is_some();
        if page.mark != relay::NO_MARK && (kept_before || !page.entries.is_empty()) {
            lock(&self.places).keep(
                relay,
                told.channel,
                Place {
                    mark: page.mark,
                    after: page.next,
                    not_before: None,
                },
            );
        }
        // The end: a page with nothing in it; one that does not move on
        // within the holding it was asked in; and one that reaches the
        // last place the relay told of in that holding.
        let moved = page.mark != asked.0 || page.next > asked.1;
        let reached = page.mark == told.mark && page.next >= told.places;
        if page.entries.is_empty() || !moved || reached {
            (Pulled::CaughtUp, stored)
        } else {
            (Pulled::More(page.mark, page.next), stored)
        }
    }

    /// The entries that wait to be passed on, as the messages for each of
    /// `relays`: every entry but those that came from that relay, each
    /// with the two times of its channel as this relay holds it, a page's
    /// worth to a message. Nothing waits afterwards.
    fn to_pass_on(
        &self,
        db: &Mutex<Connection>,
        relays: &[NodeId],
    ) -> Vec<(NodeId, Vec<RelayPush>)> {
        let taken = std::mem::take(&mut *lock(&self.taken));
        if taken.is_empty() || relays.is_empty() {
            return Vec::new();
        }
        // The two times of each channel. An entry of a channel that was
        // dropped since is passed on to nobody.
        let times: HashMap<[u8; 32], (i64, i64)> = {
            let Ok(db) = db.lock() else {
                return Vec::new();
            };
            let channels: HashSet<[u8; 32]> = taken.iter().map(|taken| taken.channel).collect();
            channels
                .into_iter()
                .filter_map(|channel| {
                    let held = relay::held_channel(&db, &channel).ok()??;
                    Some((channel, (held.held_since, held.used_at)))
                })
                .collect()
        };
        relays
            .iter()
            .filter_map(|relay| {
                let mut messages: Vec<RelayPush> = Vec::new();
                let mut bytes = 0;
                for entry in taken
                    .iter()
                    .filter(|taken| taken.from.as_ref() != Some(relay))
                {
                    let Some((held_since, used_at)) = times.get(&entry.channel) else {
                        continue;
                    };
                    let full = messages.last().is_none_or(|message| {
                        message.entries.len() >= ENTRY_PAGE_MAX_ENTRIES as usize
                            || bytes + entry.bytes.len() > ENTRY_PAGE_MAX_BYTES
                    });
                    if full {
                        messages.push(RelayPush {
                            entries: Vec::new(),
                        });
                        bytes = 0;
                    }
                    bytes += entry.bytes.len();
                    if let Some(message) = messages.last_mut() {
                        message.entries.push(RelayEntry {
                            entry: entry.bytes.clone(),
                            held_since: *held_since,
                            used_at: *used_at,
                        });
                    }
                }
                (!messages.is_empty()).then(|| (relay.clone(), messages))
            })
            .collect()
    }
}

/// A relay that the operator lists, as this relay asks it: one request on
/// a stream between relays that work together, and its answer.
pub trait Asked {
    fn ask(
        &self,
        request: WireMessage,
    ) -> impl std::future::Future<Output = Result<WireMessage, String>> + Send;
}

impl Asked for quinn::Connection {
    async fn ask(&self, request: WireMessage) -> Result<WireMessage, String> {
        ask(self, Protocol::RelayEntries, &request).await
    }
}

/// Ask `conn` one thing on a stream of `protocol`, and read its answer.
async fn ask(
    conn: &quinn::Connection,
    protocol: Protocol,
    request: &WireMessage,
) -> Result<WireMessage, String> {
    let (mut send, mut recv) =
        match tokio::time::timeout(codec::STREAM_TIMEOUT, conn.open_bi()).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(format!("open_bi failed: {e}")),
            Err(_) => return Err("open_bi timed out".into()),
        };
    let mut stream = tokio::io::join(&mut recv, &mut send);
    let answer = codec::send_request(&mut stream, protocol, request)
        .await
        .map_err(|e| e.to_string());
    let _ = send.finish();
    answer
}

/// What a stream is served with: the connection it is on, and what the
/// node holds.
pub struct Serving<'a> {
    pub conn: &'a quinn::Connection,
    pub peer: &'a NodeId,
    pub address: IpAddr,
    pub db: &'a Mutex<Connection>,
    pub rates: &'a Mutex<Rates>,
}

impl RelayEntries {
    /// Serve one stream of `protocol`: one of the four streams of
    /// entries, or the one between relays that work together. `proved` is
    /// what this connection has proved, and `whole` what it has shown
    /// whole.
    ///
    /// Returns the breach where the request was over a limit: the stream
    /// was refused, and the caller cuts the peer off where it says so.
    pub async fn serve(
        &self,
        protocol: Protocol,
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
        serving: &Serving<'_>,
        proved: &mut Proved,
        whole: &mut ShownWhole,
    ) -> Option<OverLimit> {
        let who = Who {
            peer: serving.peer,
            address: serving.address,
            // By the key in the peer's certificate: the connection is
            // known by that key.
            listed: self.lists(serving.peer),
        };
        // The frame as its bytes: what is no request is counted by them.
        let frame = match codec::read_raw_frame(recv).await {
            Ok(frame) => frame,
            Err(e) => {
                tracing::debug!(peer = %who.peer, error = %e, "failed to read a request for entries");
                return None;
            }
        };
        let request = match codec::decode_message(&frame) {
            Ok(request) => request,
            Err(e) => {
                tracing::debug!(peer = %who.peer, error = %e, "a frame on a stream of entries that is no message");
                return Self::no_request(send, recv, &who, serving.rates, &frame);
            }
        };
        // What a proof is checked against is this connection's own: the
        // value of its TLS session, and the key in the peer's certificate.
        let session = (protocol == Protocol::ChannelProve)
            .then(|| Session::of(serving.conn))
            .flatten();
        let answer = self.answer(
            protocol,
            &request,
            &who,
            session.as_ref(),
            proved,
            whole,
            serving.db,
            serving.rates,
            unix_now(),
        );
        match answer {
            Answer::Message(answer) => {
                let _ = codec::write_frame(send, &answer).await;
                None
            }
            Answer::Over(over) => {
                tracing::warn!(peer = %who.peer, ?protocol, cut_off = over.cut_off, "a request for entries over the byte allowance; refused");
                let code = quinn::VarInt::from_u32(cordelia_core::protocol::ERR_RATE_LIMIT);
                let _ = send.reset(code);
                let _ = recv.stop(code);
                Some(over)
            }
            Answer::NotNow => {
                tracing::debug!(peer = %who.peer, ?protocol, "a pull for more than the peer may be handed for now; refused, and no breach");
                let code = quinn::VarInt::from_u32(cordelia_core::protocol::ERR_RATE_LIMIT);
                let _ = send.reset(code);
                let _ = recv.stop(code);
                None
            }
            Answer::Nothing => None,
            Answer::Stray => {
                tracing::debug!(peer = %who.peer, ?protocol, "a request that is not for this stream");
                Self::no_request(send, recv, &who, serving.rates, &frame)
            }
        }
    }

    /// A frame that was read and is no request for its stream: bytes that
    /// decode as no message, a request of another stream, or one on the
    /// stream between relays from a peer that is not listed. Nothing is
    /// answered. Its bytes count as pushed, and where they are over what
    /// the peer may push the stream is refused: returns the breach.
    fn no_request(
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
        who: &Who,
        rates: &Mutex<Rates>,
        frame: &[u8],
    ) -> Option<OverLimit> {
        let over = Self::counted_as_pushed(rates, who, frame)?;
        let code = quinn::VarInt::from_u32(cordelia_core::protocol::ERR_RATE_LIMIT);
        let _ = send.reset(code);
        let _ = recv.stop(code);
        Some(over)
    }

    /// Count the bytes of a frame that is no request for its stream
    /// against what `who` may push (decision 2026-10-04 §16): the relay
    /// read them, and a megabyte that is read for nothing is still a
    /// megabyte. They count as bytes that are no entry's do. Returns the
    /// breach where they are over either allowance. A relay that the
    /// operator lists is not limited.
    fn counted_as_pushed(rates: &Mutex<Rates>, who: &Who, frame: &[u8]) -> Option<OverLimit> {
        if who.listed {
            return None;
        }
        lock(rates)
            .pushed(who.peer, who.address, counted(frame))
            .err()
    }

    /// Pass the entries that wait on to `relays`, the listed relays that
    /// are connected, each on its connection. What a relay does not take
    /// is not tried again: it pulls what it lacks.
    pub fn pass_on(&self, db: &Mutex<Connection>, relays: Vec<(NodeId, quinn::Connection)>) {
        let keys: Vec<NodeId> = relays.iter().map(|(relay, _)| relay.clone()).collect();
        for (relay, messages) in self.to_pass_on(db, &keys) {
            let Some((_, conn)) = relays.iter().find(|(key, _)| *key == relay) else {
                continue;
            };
            let conn = conn.clone();
            tokio::spawn(async move {
                for message in messages {
                    let entries = message.entries.len();
                    match ask(
                        &conn,
                        Protocol::RelayEntries,
                        &WireMessage::RelayPush(message),
                    )
                    .await
                    {
                        Ok(WireMessage::EntryPushed(pushed)) => {
                            let stored = pushed
                                .answers
                                .iter()
                                .filter(|answer| **answer == PushAnswer::Stored)
                                .count();
                            tracing::debug!(peer = %relay, entries, stored, "passed entries on");
                        }
                        Ok(_) => {
                            tracing::debug!(peer = %relay, entries, "passing entries on was not answered as it should be");
                            break;
                        }
                        Err(e) => {
                            tracing::debug!(peer = %relay, entries, error = %e, "passing entries on failed");
                            break;
                        }
                    }
                }
            });
        }
    }

    /// Ask `relay`, a listed relay that is reached by `link`, which
    /// channels it holds, and pull what this relay lacks of them. One pull
    /// at a time runs from each relay.
    ///
    /// A pass reads at most RELAY_CHANNEL_PAGES_PER_PASS pages of the
    /// relay's list. Where the list is longer, the next pass goes on after
    /// the last ID that this one read, and starts again from the first
    /// once the end is reached. Of the list itself, one page is held at a
    /// time.
    ///
    /// A channel whose page was not the one asked for, could not be
    /// stored, or was not answered, is left where it was, and the pass
    /// goes on with the next channel: one channel does not keep those
    /// after it waiting.
    pub async fn pull_from(&self, link: &impl Asked, relay: NodeId, db: &Mutex<Connection>) {
        let Some(_pulling) = Pulling::begin(&self.pulling, &relay) else {
            return;
        };
        let mut after = lock(&self.stopped_at)
            .get(&relay)
            .copied()
            .unwrap_or([0u8; 32]);
        let mut stored = 0usize;
        // Where the next pass goes on: `None` from the start.
        let mut goes_on = Some(after);
        for _ in 0..RELAY_CHANNEL_PAGES_PER_PASS {
            let asked = WireMessage::RelayChannelsAsk(RelayChannelsAsk {
                after,
                limit: RELAY_CHANNELS_PAGE_MAX,
            });
            let channels = match link.ask(asked).await {
                Ok(WireMessage::RelayChannelsHeld(held)) => held.channels,
                Ok(_) => break,
                Err(e) => {
                    tracing::debug!(peer = %relay, error = %e, "asking a relay what it holds failed");
                    break;
                }
            };
            // In the order of their IDs, each after the last: or this is
            // not the list that was asked for, and nothing of it is used.
            let in_order = channels.iter().try_fold(after, |last, told| {
                (told.channel > last).then_some(told.channel)
            });
            if in_order.is_none() || channels.len() > RELAY_CHANNELS_PAGE_MAX as usize {
                tracing::debug!(peer = %relay, "a list of channels that was not the one asked for");
                goes_on = None;
                break;
            }
            let from = after;
            for told in &channels {
                after = told.channel;
                match self.pull_channel(link, &relay, db, told).await {
                    Ok(taken) => stored += taken,
                    // It is left as it was, and asked for in a later
                    // pass. The next channel is pulled all the same.
                    Err(e) => {
                        tracing::debug!(peer = %relay, error = %e, "pulling a channel from a relay failed; going on with the next");
                    }
                }
            }
            // The page told of every channel that the relay holds between
            // the ID that was asked after and its last one, or to the end
            // of the list where it was not full: a place kept in any other
            // channel between them is a place in one it holds no more.
            let last = channels.len() < RELAY_CHANNELS_PAGE_MAX as usize;
            let to = if last { [0xff; 32] } else { after };
            let told: HashSet<[u8; 32]> = channels.iter().map(|told| told.channel).collect();
            lock(&self.places).keep_only(&relay, (&from, &to), &told);
            goes_on = (!last).then_some(after);
            if last {
                break;
            }
        }
        match goes_on {
            Some(after) if after != [0u8; 32] => {
                lock(&self.stopped_at).insert(relay.clone(), after)
            }
            _ => lock(&self.stopped_at).remove(&relay),
        };
        if stored > 0 {
            tracing::info!(peer = %relay, entries = stored, "pulled entries from a relay");
        }
    }

    /// Pull what this relay lacks of one channel that `relay` told of, at
    /// most RELAY_ENTRY_PULL_PAGES pages of it in a pass. Returns how many
    /// entries were stored.
    async fn pull_channel(
        &self,
        link: &impl Asked,
        relay: &NodeId,
        db: &Mutex<Connection>,
        told: &RelayChannel,
    ) -> Result<usize, String> {
        let Some((mut mark, mut after)) = self.wants(db, relay, told, unix_now()) else {
            return Ok(0);
        };
        let mut stored = 0;
        for _ in 0..RELAY_ENTRY_PULL_PAGES {
            let asked = WireMessage::RelayPull(RelayPull {
                channel: told.channel,
                mark,
                after,
                limit: ENTRY_PAGE_MAX_ENTRIES,
            });
            let WireMessage::EntryPulled(page) = link.ask(asked).await? else {
                return Err("a request for a page was not answered with one".into());
            };
            let (ended, entries) = self.pulled(db, relay, told, (mark, after), &page, unix_now());
            stored += entries;
            match ended {
                Pulled::More(next_mark, next) => (mark, after) = (next_mark, next),
                Pulled::CaughtUp | Pulled::NoRoom => break,
                Pulled::NotThePage => {
                    return Err("a page that was not the one asked for".into());
                }
                Pulled::NotStored => return Err("a page could not be stored".into()),
            }
        }
        Ok(stored)
    }
}

/// The listed relays that are connected, with the connection of each.
pub fn listed_and_connected(
    entries: &RelayEntries,
    conn_mgr: &cordelia_network::connection::ConnectionManager,
) -> Vec<(NodeId, quinn::Connection)> {
    entries
        .listed()
        .into_iter()
        .filter_map(|relay| {
            let conn = conn_mgr.get_connection(&relay)?.clone();
            Some((relay, conn))
        })
        .collect()
}

/// Run `entries.pull_from` for each of `relays`, each in a task of its own.
pub fn pull_from_each(
    entries: &Arc<RelayEntries>,
    state: &actix_web::web::Data<cordelia_api::state::AppState>,
    relays: Vec<(NodeId, quinn::Connection)>,
) {
    for (relay, conn) in relays {
        let (entries, state) = (entries.clone(), state.clone());
        tokio::spawn(async move {
            entries.pull_from(&conn, relay, &state.db).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordelia_core::protocol::{
        BAN_THRESHOLD, MAX_CONNECTIONS_PER_IP, MAX_ENTRY_NAME_AND_VALUE_BYTES,
        NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR, PUSH_BYTES_PER_PEER_PER_MINUTE,
    };
    use cordelia_crypto::derive;
    use cordelia_crypto::entry::{Entry, Inside, Value};
    use cordelia_crypto::identity::NodeIdentity;
    use cordelia_network::bootstrap::RelayAddr;
    use cordelia_network::messages::EntryRefused;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 24 * 60 * 60;
    const HOUR: i64 = 60 * 60;
    /// What an entry with a small text is counted at: 256 bytes of content
    /// and what an entry takes beyond it.
    const SMALL: u64 = 256 + 1024;
    /// What an entry of the largest size is counted at.
    const LARGEST: u64 = 65_536 + 1024;
    const MINUTE: u64 = PUSH_BYTES_PER_PEER_PER_MINUTE;

    /// The secret of the channel numbered `c`.
    fn secret(c: u16) -> [u8; 32] {
        let mut secret = [0x77; 32];
        secret[..2].copy_from_slice(&c.to_be_bytes());
        secret
    }

    /// The ID of the channel numbered `c`.
    fn channel(c: u16) -> [u8; 32] {
        derive::channel_id(&secret(c)).unwrap()
    }

    fn device(d: u8) -> NodeIdentity {
        NodeIdentity::from_seed([d; 32]).unwrap()
    }

    /// An entry of channel `c` that device `d` made of `said` under `name`
    /// at `rev`, checked.
    fn made(c: u16, d: u8, rev: u64, name: &str, said: &str) -> CheckedEntry {
        let inside = Inside {
            name: name.to_string(),
            value: Value::Text(said.to_string()),
            chain: Some(Vec::new()),
        };
        Entry::seal(&secret(c), &device(d), rev, &inside)
            .unwrap()
            .check()
            .unwrap()
    }

    /// An entry of channel `c` with a small text, that device `d` made
    /// under `notes.md` at `rev`.
    fn small(c: u16, d: u8, rev: u64) -> CheckedEntry {
        let entry = made(c, d, rev, "notes.md", "a small text");
        assert_eq!(entry_cost(entry.content.len()), SMALL);
        entry
    }

    /// An entry of channel `c` of the largest size, that device `d` made.
    fn largest(c: u16, d: u8) -> CheckedEntry {
        let text = "x".repeat(MAX_ENTRY_NAME_AND_VALUE_BYTES - 1);
        let entry = made(c, d, 5, "n", &text);
        assert_eq!(entry_cost(entry.content.len()), LARGEST);
        entry
    }

    /// The node key of the peer numbered `n`: none of them is a device
    /// that makes entries here.
    fn peer(n: u8) -> NodeId {
        let mut seed = [0xee; 32];
        seed[0] = n;
        NodeId(NodeIdentity::from_seed(seed).unwrap().public_key())
    }

    /// The address numbered `n`, of those kept for examples.
    fn address(n: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, n])
    }

    /// A relay, its database, and what its peers have sent lately.
    struct Relay {
        entries: RelayEntries,
        db: Mutex<Connection>,
        rates: Mutex<Rates>,
    }

    /// A relay that may hold `max_bytes`, whose operator lists the peers
    /// numbered `listed` by key, and one relay more by its address alone:
    /// the one at address 200.
    fn relay_of(max_bytes: u64, listed: &[u8]) -> Relay {
        let mut relays: Vec<RelayAddr> = listed
            .iter()
            .map(|n| RelayAddr {
                host: format!("relay{n}.example:9474"),
                addr: std::net::SocketAddr::new(address(*n), 9474),
                key: Some(peer(*n).0),
            })
            .collect();
        relays.push(RelayAddr {
            host: "keyless.example:9474".into(),
            addr: std::net::SocketAddr::new(address(200), 9474),
            key: None,
        });
        Relay {
            entries: RelayEntries::new(
                max_bytes,
                Arc::new(std::sync::RwLock::new(relays)),
                Duration::from_secs(600),
            ),
            db: Mutex::new(cordelia_storage::db::open_in_memory().unwrap()),
            rates: Mutex::new(Rates::default()),
        }
    }

    /// A relay with room for everything, that lists nobody by key.
    fn relay() -> Relay {
        relay_of(u64::MAX, &[])
    }

    impl Relay {
        /// The peer numbered `n`, at the address numbered `n`.
        fn who<'a>(&self, peer: &'a NodeId, n: u8) -> Who<'a> {
            Who {
                peer,
                address: address(n),
                listed: self.entries.lists(peer),
            }
        }

        /// The answer to `request`, made by the peer numbered `n` on a
        /// stream of `protocol`, on a connection that has proved `proved`
        /// and whose session is `session`, and that has shown nothing
        /// whole.
        fn answer(
            &self,
            n: u8,
            protocol: Protocol,
            request: WireMessage,
            session: Option<&Session>,
            proved: &mut Proved,
        ) -> Answer {
            let peer = peer(n);
            self.entries.answer(
                protocol,
                &request,
                &self.who(&peer, n),
                session,
                proved,
                &mut ShownWhole::default(),
                &self.db,
                &self.rates,
                NOW,
            )
        }

        /// The answer to a show that the peer numbered `n` makes on a
        /// connection that has shown `whole` so far: of the entry whole,
        /// or in short.
        fn show_on(&self, n: u8, whole: &mut ShownWhole, request: WireMessage) -> ShowAnswer {
            let peer = peer(n);
            shown(self.entries.answer(
                Protocol::EntryShow,
                &request,
                &self.who(&peer, n),
                None,
                &mut Proved::default(),
                whole,
                &self.db,
                &self.rates,
                NOW,
            ))
        }

        /// The peer numbered `n` shows `entry`.
        fn show(&self, n: u8, entry: Vec<u8>) -> Answer {
            self.answer(
                n,
                Protocol::EntryShow,
                WireMessage::EntryShow(EntryShow { entry }),
                None,
                &mut Proved::default(),
            )
        }

        /// The peer numbered `n` pushes `entries`.
        fn push(&self, n: u8, entries: Vec<Vec<u8>>) -> Answer {
            self.answer(
                n,
                Protocol::EntryPush,
                WireMessage::EntryPush(EntryPush {
                    entries: entries.into_iter().map(Into::into).collect(),
                }),
                None,
                &mut Proved::default(),
            )
        }

        /// The peer numbered `n` asks for a page of channel `c`, on a
        /// connection that has proved `proved`.
        fn pull(&self, n: u8, c: u16, proved: &Proved, mark: Mark, after: u64) -> Answer {
            let peer = peer(n);
            self.entries.pulling(
                &self.db,
                &self.rates,
                &self.who(&peer, n),
                proved,
                &EntryPull {
                    channel: channel(c),
                    mark,
                    after,
                    limit: 100,
                },
            )
        }

        /// The channel numbered `c` as the relay holds it.
        fn held(&self, c: u16) -> Option<relay::HeldChannel> {
            relay::held_channel(&lock(&self.db), &channel(c)).unwrap()
        }

        /// What the relay holds of this kind, as entries are counted.
        fn used(&self) -> u64 {
            relay::used_bytes(&lock(&self.db)).unwrap()
        }

        /// Store `entry` as a relay that the operator lists passes it on:
        /// no limit is asked about.
        fn hold(&self, entry: &CheckedEntry, at: i64) {
            let asker = Asker::ListedRelay {
                held_since: None,
                used_at: None,
            };
            let mut room = lock(&self.entries.room);
            assert_eq!(
                relay::take(&lock(&self.db), &mut room, entry, &asker, at).unwrap(),
                Taken::Stored
            );
        }

        fn push_room(&self, n: u8) -> u64 {
            lock(&self.rates).push_room(&peer(n), address(n))
        }

        fn fetch_room(&self, n: u8) -> u64 {
            lock(&self.rates).fetch_room(&peer(n), address(n))
        }
    }

    /// A connection that has proved the channels numbered `channels`.
    fn having_proved(channels: &[u16]) -> Proved {
        let mut proved = Proved::default();
        for c in channels {
            proved.remember(channel(*c));
        }
        proved
    }

    fn said(answer: Answer) -> WireMessage {
        match answer {
            Answer::Message(message) => *message,
            other => panic!("not answered: {other:?}"),
        }
    }

    fn shown(answer: Answer) -> ShowAnswer {
        match said(answer) {
            WireMessage::EntryShown(shown) => shown.answer,
            other => panic!("not an answer to a show: {other:?}"),
        }
    }

    fn pushed(answer: Answer) -> Vec<PushAnswer> {
        match said(answer) {
            WireMessage::EntryPushed(pushed) => pushed.answers,
            other => panic!("not an answer to a push: {other:?}"),
        }
    }

    fn page(answer: Answer) -> EntryPulled {
        match said(answer) {
            WireMessage::EntryPulled(page) => page,
            other => panic!("not a page: {other:?}"),
        }
    }

    fn proved_said(answer: Answer) -> bool {
        match said(answer) {
            WireMessage::ChannelProved(proved) => proved.proved,
            other => panic!("not an answer to a proof: {other:?}"),
        }
    }

    /// A pull that asked for more than the peer may be handed for now:
    /// refused, with nothing said, and no breach.
    fn not_now(answer: Answer) {
        assert!(matches!(answer, Answer::NotNow), "not refused for now");
    }

    /// How many breaches are counted for the peer numbered `n`, and for
    /// the address numbered `n`.
    fn breaches(at: &Relay, n: u8) -> (u32, u32) {
        let rates = lock(&at.rates);
        let of = |limiter: Option<&cordelia_network::rate_limit::PeerRateLimiter>| {
            limiter.map_or(0, |limiter| limiter.breach_count)
        };
        (
            of(rates.breaches_of_peer(&peer(n))),
            of(rates.breaches_of_address(address(n))),
        )
    }

    /// The breach, where a request was over a limit.
    fn over(answer: Answer) -> OverLimit {
        match answer {
            Answer::Over(over) => over,
            other => panic!("not over a limit: {other:?}"),
        }
    }

    // ── What is counted ──────────────────────────────────────────────

    /// What a peer sends as an entry counts as its content and what an
    /// entry takes beyond it. Bytes that are no entry's count for every
    /// one of them, and for no less than an entry does.
    #[test]
    fn what_is_sent_as_an_entry_counts_as_an_entry_or_as_every_byte_of_it() {
        let entry = small(1, 1, 5);
        assert_eq!(counted(&entry.to_wire()), SMALL);
        assert_eq!(counted(&entry.to_wire()), entry_cost(entry.content.len()));
        assert_eq!(counted(&largest(1, 1).to_wire()), LARGEST);
        // No entry's: nothing, a few bytes, an entry's worth, a megabyte.
        assert_eq!(counted(&[]), 1024);
        assert_eq!(counted(&[1, 2, 3]), 1024);
        assert_eq!(counted(&[0; 237]), 1024);
        assert_eq!(counted(&[0; 238]), 1025);
        assert_eq!(counted(&vec![0; 1_000_000]), 1_000_000 - 237 + 1024);
    }

    /// A page is as long as was asked for while the allowance has room
    /// for the most a page can be counted at; then as long as would fit
    /// if every entry were of the largest size; and never shorter than
    /// one entry, which is handed only if it fits.
    #[test]
    fn a_page_is_sized_to_the_room_the_allowance_has() {
        assert_eq!(FULL_PAGE_COST, 917_504 + 100 * 1024);
        assert_eq!(page_limit(100, MINUTE), 100);
        assert_eq!(page_limit(100, FULL_PAGE_COST), 100);
        assert_eq!(page_limit(7, FULL_PAGE_COST), 7);
        // A byte short of a whole page: 15 of the largest fit in it.
        assert_eq!(page_limit(100, FULL_PAGE_COST - 1), 15);
        assert_eq!(page_limit(7, FULL_PAGE_COST - 1), 7);
        assert_eq!(page_limit(100, 5 * LARGEST), 5);
        assert_eq!(page_limit(100, 5 * LARGEST - 1), 4);
        assert_eq!(page_limit(100, LARGEST), 1);
        // Not room for one of the largest: one is read all the same.
        assert_eq!(page_limit(100, LARGEST - 1), 1);
        assert_eq!(page_limit(100, 0), 1);
        // Nothing is asked for: nothing.
        assert_eq!(page_limit(0, MINUTE), 0);
        assert_eq!(page_limit(0, 0), 0);
    }

    // ── Show ─────────────────────────────────────────────────────────

    /// An entry that is shown is answered from the store: taken, held, or
    /// another that the relay holds from that author in that slot. Both
    /// signatures are checked first, and what does not pass is refused
    /// and changes nothing.
    #[test]
    fn an_entry_shown_is_checked_and_then_answered_from_the_store() {
        let at = relay();
        let first = small(1, 1, 5);
        assert_eq!(shown(at.show(1, first.to_wire())), ShowAnswer::Taken);
        assert_eq!(shown(at.show(1, first.to_wire())), ShowAnswer::Held);
        // Another peer is told the same.
        assert_eq!(shown(at.show(2, first.to_wire())), ShowAnswer::Held);
        // An earlier one, and another at that revision: here is the one
        // the relay holds, as its bytes.
        let another = made(1, 1, 5, "notes.md", "another text");
        for earlier in [small(1, 1, 4), another] {
            assert_eq!(
                shown(at.show(2, earlier.to_wire())),
                ShowAnswer::Another(first.to_wire())
            );
        }
        // A later one is taken in its place.
        let later = small(1, 1, 6);
        assert_eq!(shown(at.show(2, later.to_wire())), ShowAnswer::Taken);
        assert_eq!(
            shown(at.show(1, first.to_wire())),
            ShowAnswer::Another(later.to_wire())
        );

        // An entry that its channel's key did not sign, one that was
        // changed after it was signed, and bytes that are no entry's: each
        // is refused as not signed, and the store is as it was.
        let holds = at.held(1).unwrap();
        let mut by_a_stranger = small(1, 1, 9).into_entry();
        by_a_stranger.channel_signature = device(9).sign(b"anything");
        let mut changed = small(1, 1, 9).into_entry();
        changed.rev = 10;
        let mut of_another = small(2, 1, 9).into_entry();
        of_another.channel = channel(1);
        for bytes in [
            by_a_stranger.to_wire(),
            changed.to_wire(),
            of_another.to_wire(),
            vec![1, 2, 3],
            Vec::new(),
        ] {
            assert_eq!(
                shown(at.show(1, bytes)),
                ShowAnswer::Refused(EntryRefused::NotSigned)
            );
        }
        assert_eq!(at.held(1), Some(holds));
        assert_eq!(at.held(2), None);
        assert_eq!(at.used(), SMALL);

        // A stream carries its own kind of request: an entry shown on the
        // stream of another is not answered, and not looked at.
        for protocol in [
            Protocol::EntryPush,
            Protocol::EntryPull,
            Protocol::ChannelProve,
            Protocol::RelayEntries,
            Protocol::ItemPush,
        ] {
            let answer = at.answer(
                1,
                protocol,
                WireMessage::EntryShow(EntryShow {
                    entry: small(3, 1, 5).to_wire(),
                }),
                None,
                &mut Proved::default(),
            );
            assert!(matches!(answer, Answer::Stray), "{protocol:?}");
        }
        assert_eq!(at.held(3), None);
    }

    /// What a peer shows counts as what it pushes does, and the entry it
    /// is answered with counts as anything fetched does: each against the
    /// allowance that the older kind of channel counts against.
    #[test]
    fn an_entry_shown_counts_as_pushed_and_what_goes_back_as_fetched() {
        let at = relay();
        assert_eq!((at.push_room(1), at.fetch_room(1)), (MINUTE, MINUTE));
        let first = small(1, 1, 5);
        // Taken, and held: each show counts for the entry that was sent.
        assert_eq!(shown(at.show(1, first.to_wire())), ShowAnswer::Taken);
        assert_eq!(at.push_room(1), MINUTE - SMALL);
        assert_eq!(shown(at.show(1, first.to_wire())), ShowAnswer::Held);
        assert_eq!(at.push_room(1), MINUTE - 2 * SMALL);
        // Nothing went back yet.
        assert_eq!(at.fetch_room(1), MINUTE);
        // Bytes that are no entry's count for what was sent.
        shown(at.show(1, vec![0; 5000]));
        assert_eq!(at.push_room(1), MINUTE - 2 * SMALL - (5000 - 237 + 1024));

        // The entry that goes back counts as fetched: a larger one than
        // the one that was shown.
        let larger = made(1, 1, 6, "notes.md", &"x".repeat(3000));
        assert_eq!(entry_cost(larger.content.len()), 4096 + 1024);
        at.hold(&larger, NOW);
        assert_eq!(
            shown(at.show(2, first.to_wire())),
            ShowAnswer::Another(larger.to_wire())
        );
        assert_eq!(at.push_room(2), MINUTE - SMALL);
        assert_eq!(at.fetch_room(2), MINUTE - (4096 + 1024));

        // With the older kind, one allowance. A peer from which the relay
        // has fetched all but a little of what it may in a minute is
        // handed the entry all the same: the answer to a show is always
        // handed. It is counted, and takes the peer over by that entry.
        lock(&at.rates).fetched(&peer(3), address(3), MINUTE - 5000);
        assert_eq!(at.fetch_room(3), 5000);
        assert_eq!(
            shown(at.show(3, first.to_wire())),
            ShowAnswer::Another(larger.to_wire())
        );
        assert_eq!(at.fetch_room(3), 0);
        assert_eq!(lock(&at.rates).fetched_of_peer(&peer(3)), MINUTE + 120);
        // And again, with no room at all: handed, and counted.
        assert_eq!(
            shown(at.show(3, first.to_wire())),
            ShowAnswer::Another(larger.to_wire())
        );
        assert_eq!(
            lock(&at.rates).fetched_of_peer(&peer(3)),
            MINUTE + 120 + 5120
        );
        // It is no breach.
        assert_eq!(breaches(&at, 3), (0, 0));
        // What it showed was counted as pushed, each time.
        assert_eq!(at.push_room(3), MINUTE - 2 * SMALL);
        // With room for it to the byte, it is handed, and none is left.
        lock(&at.rates).fetched(&peer(4), address(4), MINUTE - 5120);
        assert_eq!(
            shown(at.show(4, first.to_wire())),
            ShowAnswer::Another(larger.to_wire())
        );
        assert_eq!(at.fetch_room(4), 0);

        // A peer that has pushed all but a little of what it may, in
        // items of the older kind, shows an entry: it is not looked at.
        lock(&at.rates)
            .pushed(&peer(5), address(5), MINUTE - 1000)
            .unwrap();
        let unseen = small(7, 1, 5);
        assert!(!over(at.show(5, unseen.to_wire())).cut_off);
        assert_eq!(at.held(7), None, "an entry over the allowance was taken");
        assert_eq!(at.push_room(5), 1000);
        // As many breaches as cut a peer off: the last says so.
        assert_eq!(BAN_THRESHOLD, 3);
        assert!(!over(at.show(5, unseen.to_wire())).cut_off);
        assert!(over(at.show(5, unseen.to_wire())).cut_off);
    }

    /// `entry` as it is shown whole.
    fn whole_of(entry: &CheckedEntry) -> WireMessage {
        WireMessage::EntryShow(EntryShow {
            entry: entry.to_wire(),
        })
    }

    /// `entry` as it is shown in short: by its channel, slot, author,
    /// revision and ID.
    fn short_of(entry: &CheckedEntry) -> WireMessage {
        WireMessage::EntryShowShort(EntryShowShort {
            channel: entry.channel,
            author: entry.author,
            slot: entry.slot,
            rev: entry.rev,
            id: entry.id(),
        })
    }

    /// A short show is only ever of the entry that this connection last
    /// showed whole in that slot. Of that entry, the relay looks, and
    /// answers held, "show it whole", or the revision and ID of another.
    /// Of anything else it answers "show it whole", whatever it holds: an
    /// entry that it holds and the connection never showed, another
    /// revision in a slot the connection did show, another entry at that
    /// revision, the same entry on another connection.
    #[test]
    fn a_short_show_is_only_ever_of_the_entry_last_shown_whole_on_the_connection() {
        let at = relay();
        let first = small(1, 1, 5);
        at.hold(&first, NOW);
        let earlier = small(1, 1, 4);
        let later = small(1, 1, 6);
        let at_that_revision = made(1, 1, 5, "notes.md", "another text");

        // A connection that has shown nothing whole: a short show of the
        // very entry that the relay holds is told to show it whole, and so
        // is one of anything else. Nothing is learnt from either.
        let mut whole = ShownWhole::default();
        for entry in [&first, &earlier, &later, &at_that_revision] {
            assert_eq!(
                at.show_on(1, &mut whole, short_of(entry)),
                ShowAnswer::Whole
            );
        }
        assert_eq!(whole.len(), 0);

        // It shows the entry whole, and then the short show of that entry
        // is answered from the store: held.
        assert_eq!(
            at.show_on(1, &mut whole, whole_of(&first)),
            ShowAnswer::Held
        );
        assert_eq!(whole.len(), 1);
        assert_eq!(
            at.show_on(1, &mut whole, short_of(&first)),
            ShowAnswer::Held
        );
        // Anything else in that slot is still to be shown whole, though
        // the relay holds an entry at that revision or a later one: the
        // connection has not shown it.
        for entry in [&earlier, &later, &at_that_revision] {
            assert_eq!(
                at.show_on(1, &mut whole, short_of(entry)),
                ShowAnswer::Whole
            );
        }
        // So is the same entry by another revision or another ID.
        for (rev, id) in [(4, first.id()), (6, first.id()), (5, [7; 32])] {
            let other = WireMessage::EntryShowShort(EntryShowShort {
                channel: first.channel,
                author: first.author,
                slot: first.slot,
                rev,
                id,
            });
            assert_eq!(at.show_on(1, &mut whole, other), ShowAnswer::Whole);
        }
        // And the same entry on a connection that has not shown it.
        assert_eq!(
            at.show_on(1, &mut ShownWhole::default(), short_of(&first)),
            ShowAnswer::Whole
        );

        // The relay comes to hold a later one. The short show of the
        // entry remembered is answered with word of it: its revision and
        // its ID, and no more. The connection shows its own whole, and is
        // answered with the entry.
        at.hold(&later, NOW);
        let word = ShowAnswer::Other {
            rev: 6,
            id: later.id(),
        };
        assert_eq!(at.show_on(1, &mut whole, short_of(&first)), word);
        assert_eq!(
            at.show_on(1, &mut whole, whole_of(&first)),
            ShowAnswer::Another(later.to_wire())
        );
        // What it was answered with is not what it showed: the entry
        // remembered is still its own, and a short show of the later one
        // is to be shown whole.
        assert_eq!(at.show_on(1, &mut whole, short_of(&first)), word);
        assert_eq!(
            at.show_on(1, &mut whole, short_of(&later)),
            ShowAnswer::Whole
        );
        // It shows the later one whole: that is the one remembered now,
        // and the first is not.
        assert_eq!(
            at.show_on(1, &mut whole, whole_of(&later)),
            ShowAnswer::Held
        );
        assert_eq!(
            at.show_on(1, &mut whole, short_of(&later)),
            ShowAnswer::Held
        );
        assert_eq!(
            at.show_on(1, &mut whole, short_of(&first)),
            ShowAnswer::Whole
        );
        assert_eq!(whole.len(), 1);
    }

    /// What is remembered is the last entry shown whole whose signatures
    /// held, whatever the relay answered: one that it took, one that it
    /// answered with another, and one that found no room. An entry whose
    /// signatures do not hold is not remembered.
    #[test]
    fn what_was_shown_whole_is_remembered_whatever_was_answered() {
        // Taken: remembered, and held.
        let at = relay();
        let mut whole = ShownWhole::default();
        let first = small(1, 1, 5);
        assert_eq!(
            at.show_on(1, &mut whole, whole_of(&first)),
            ShowAnswer::Taken
        );
        assert_eq!(
            at.show_on(1, &mut whole, short_of(&first)),
            ShowAnswer::Held
        );

        // Answered with another: remembered, and the short show is told
        // which other.
        let mut behind = ShownWhole::default();
        let earlier = small(1, 1, 4);
        assert_eq!(
            at.show_on(2, &mut behind, whole_of(&earlier)),
            ShowAnswer::Another(first.to_wire())
        );
        assert_eq!(
            at.show_on(2, &mut behind, short_of(&earlier)),
            ShowAnswer::Other {
                rev: 5,
                id: first.id(),
            }
        );

        // No room for it: remembered, and the short show is answered from
        // the store, which holds none and says to show it whole.
        let full = relay_of(SMALL, &[]);
        let mut refused = ShownWhole::default();
        full.hold(&small(2, 1, 1), NOW);
        assert_eq!(
            full.show_on(1, &mut refused, whole_of(&first)),
            ShowAnswer::Refused(EntryRefused::NoRoom)
        );
        assert_eq!(refused.len(), 1);
        assert!(refused.is_of(&EntryShowShort {
            channel: first.channel,
            author: first.author,
            slot: first.slot,
            rev: 5,
            id: first.id(),
        }));
        assert_eq!(
            full.show_on(1, &mut refused, short_of(&first)),
            ShowAnswer::Whole
        );

        // Signatures that do not hold: not remembered.
        let mut unsigned = ShownWhole::default();
        let mut by_a_stranger = small(3, 1, 9).into_entry();
        by_a_stranger.channel_signature = device(9).sign(b"anything");
        assert_eq!(
            at.show_on(
                3,
                &mut unsigned,
                WireMessage::EntryShow(EntryShow {
                    entry: by_a_stranger.to_wire(),
                })
            ),
            ShowAnswer::Refused(EntryRefused::NotSigned)
        );
        assert_eq!(unsigned.len(), 0);
    }

    /// A short show of anything but the entry remembered is answered from
    /// the connection's memory, before the store is looked at and with no
    /// lock on the database taken: the answer comes while the database is
    /// held by another. One of the entry remembered waits for the store.
    #[test]
    fn a_short_show_of_anything_else_does_not_wait_for_the_store() {
        use std::sync::mpsc;
        let at = relay();
        let first = small(1, 1, 5);
        at.hold(&first, NOW);
        let shown_whole = {
            let mut whole = ShownWhole::default();
            assert_eq!(
                at.show_on(1, &mut whole, whole_of(&first)),
                ShowAnswer::Held
            );
            whole
        };

        // What a short show of `entry` is answered within two seconds, on
        // a connection that has shown `whole`, while this thread holds
        // the database.
        let while_held = |whole: &ShownWhole, entry: &CheckedEntry| {
            let WireMessage::EntryShowShort(show) = short_of(entry) else {
                unreachable!()
            };
            let held = lock(&at.db);
            std::thread::scope(|scope| {
                let (said, heard) = mpsc::channel();
                let (at, show) = (&at, &show);
                scope.spawn(move || {
                    let peer = peer(1);
                    let answer = at.entries.shown_short(
                        &at.db,
                        &at.rates,
                        &at.who(&peer, 1),
                        whole,
                        show,
                        NOW,
                    );
                    let _ = said.send(shown(answer));
                });
                let answered = heard.recv_timeout(Duration::from_secs(2));
                drop(held);
                answered.ok()
            })
        };
        let nothing = ShownWhole::default();
        assert_eq!(while_held(&nothing, &first), Some(ShowAnswer::Whole));
        assert_eq!(
            while_held(&nothing, &small(9, 1, 5)),
            Some(ShowAnswer::Whole)
        );
        for other in [small(1, 1, 4), small(1, 1, 6), small(1, 2, 5)] {
            assert_eq!(while_held(&shown_whole, &other), Some(ShowAnswer::Whole));
        }
        // The control: the entry remembered is looked up in the store.
        assert_eq!(while_held(&shown_whole, &first), None);
        let mut whole = shown_whole;
        assert_eq!(
            at.show_on(1, &mut whole, short_of(&first)),
            ShowAnswer::Held
        );
    }

    /// A connection is remembered for eight slots and no more: a ninth is
    /// not remembered, and is shown whole each time. Showing another
    /// entry in a slot that is remembered takes no slot more.
    #[test]
    fn what_a_connection_showed_whole_is_remembered_for_eight_slots() {
        assert_eq!(MAX_SLOTS_SHOWN_ON_A_CONNECTION, 8);
        let at = relay();
        let mut whole = ShownWhole::default();
        let entries: Vec<CheckedEntry> = (1..=9).map(|d| small(1, d, 5)).collect();
        for entry in &entries {
            assert_eq!(
                at.show_on(1, &mut whole, whole_of(entry)),
                ShowAnswer::Taken
            );
        }
        assert_eq!(whole.len(), 8);
        for entry in &entries[..8] {
            assert_eq!(at.show_on(1, &mut whole, short_of(entry)), ShowAnswer::Held);
        }
        // The ninth, though the relay holds it and it was shown whole.
        assert_eq!(
            at.show_on(1, &mut whole, short_of(&entries[8])),
            ShowAnswer::Whole
        );
        assert_eq!(
            at.show_on(1, &mut whole, whole_of(&entries[8])),
            ShowAnswer::Held
        );
        assert_eq!(
            at.show_on(1, &mut whole, short_of(&entries[8])),
            ShowAnswer::Whole
        );
        assert_eq!(whole.len(), 8);
        // A later entry in the first slot: the slot is remembered already.
        let later = small(1, 1, 6);
        assert_eq!(
            at.show_on(1, &mut whole, whole_of(&later)),
            ShowAnswer::Taken
        );
        assert_eq!(whole.len(), 8);
        assert_eq!(
            at.show_on(1, &mut whole, short_of(&later)),
            ShowAnswer::Held
        );
        // A slot is an author's, in a channel: that author under another
        // name, and that slot in another channel, are others.
        let mut one = ShownWhole::default();
        one.remember(&entries[0]);
        for elsewhere in [
            made(1, 1, 5, "other.md", "a small text"),
            small(2, 1, 5),
            small(1, 2, 5),
        ] {
            let WireMessage::EntryShowShort(show) = short_of(&elsewhere) else {
                unreachable!()
            };
            assert!(!one.is_of(&show));
        }
    }

    /// A short show counts as bytes that are no entry's, against what the
    /// peer may push: whatever it is answered. Nothing goes back that
    /// counts as fetched. Over the allowance it is not looked at.
    #[test]
    fn a_short_show_counts_as_pushed_and_nothing_goes_back() {
        let at = relay();
        let first = small(1, 1, 5);
        let later = small(1, 1, 6);
        at.hold(&first, NOW);
        let mut whole = ShownWhole::default();
        // Told to show it whole: counted.
        assert_eq!(
            at.show_on(1, &mut whole, short_of(&first)),
            ShowAnswer::Whole
        );
        assert_eq!(at.push_room(1), MINUTE - 1024);
        assert_eq!(
            at.show_on(1, &mut whole, whole_of(&first)),
            ShowAnswer::Held
        );
        assert_eq!(at.push_room(1), MINUTE - 1024 - SMALL);
        // Held: counted.
        assert_eq!(
            at.show_on(1, &mut whole, short_of(&first)),
            ShowAnswer::Held
        );
        assert_eq!(at.push_room(1), MINUTE - 2 * 1024 - SMALL);
        // Word of another: counted as pushed, and nothing as fetched.
        at.hold(&later, NOW);
        assert!(matches!(
            at.show_on(1, &mut whole, short_of(&first)),
            ShowAnswer::Other { .. }
        ));
        assert_eq!(at.push_room(1), MINUTE - 3 * 1024 - SMALL);
        assert_eq!(at.fetch_room(1), MINUTE);

        // A peer with less left than a short show counts at: it is not
        // looked at, and is a breach.
        lock(&at.rates)
            .pushed(&peer(5), address(5), MINUTE - 1000)
            .unwrap();
        let peer5 = peer(5);
        let mut whole = ShownWhole::default();
        whole.remember(&later);
        let WireMessage::EntryShowShort(show) = short_of(&later) else {
            unreachable!()
        };
        let answer =
            at.entries
                .shown_short(&at.db, &at.rates, &at.who(&peer5, 5), &whole, &show, NOW);
        assert!(!over(answer).cut_off);
        assert_eq!(at.push_room(5), 1000);
        assert_eq!(breaches(&at, 5), (1, 1));
    }

    // ── Prove ────────────────────────────────────────────────────────

    /// A proof holds where the channel's key signed this connection's
    /// value and the key of the peer at its other end. One made up, one
    /// made over another connection's value, one that another peer made,
    /// and one that this end made, do not. Each no is the same answer.
    #[test]
    fn a_proof_holds_only_over_this_connections_value_and_for_the_peer_that_sends_it() {
        let at = relay();
        at.hold(&small(1, 1, 5), NOW - 2 * HOUR);
        // The connection: the value its session exports, and the peer's
        // key as its certificate says it.
        let session = Session {
            value: [0x51; 32],
            prover: peer(1).0,
        };
        let relays_key = device(250).public_key();
        let mut proved = Proved::default();
        let prove = |c: u16, proof: [u8; 64], session: Option<&Session>, proved: &mut Proved| {
            proved_said(at.answer(
                1,
                Protocol::ChannelProve,
                WireMessage::ChannelProve(ChannelProve {
                    channel: channel(c),
                    proof,
                }),
                session,
                proved,
            ))
        };

        // Each proof that is not this peer's, on this connection, for
        // this channel: no.
        let elsewhere = proof::make(&secret(1), &[0x52; 32], &session.prover).unwrap();
        let by_another = proof::make(&secret(1), &session.value, &peer(2).0).unwrap();
        let by_this_end = proof::make(&secret(1), &session.value, &relays_key).unwrap();
        let of_another = proof::make(&secret(2), &session.value, &session.prover).unwrap();
        for not_its_own in [
            [7u8; 64],
            [0; 64],
            elsewhere,
            by_another,
            by_this_end,
            of_another,
        ] {
            assert!(!prove(1, not_its_own, Some(&session), &mut proved));
        }
        // None of it was use of the channel, and nothing is remembered of
        // a proof that failed.
        assert_eq!(at.held(1).unwrap().used_at, NOW - 2 * HOUR);
        assert_eq!(proved.len(), 0);
        assert!(!proved.holds(&channel(1)));

        // The proof: yes, and the channel was used.
        let good = proof::make(&secret(1), &session.value, &session.prover).unwrap();
        assert!(prove(1, good, Some(&session), &mut proved));
        assert_eq!(at.held(1).unwrap().used_at, NOW);
        // The same proof on a connection with another value, or from
        // another peer, is none: the connection is what it is checked
        // against, and nothing in the message says who proves.
        let another_connection = Session {
            value: [0x52; 32],
            prover: session.prover,
        };
        let another_peer = Session {
            value: session.value,
            prover: peer(2).0,
        };
        let mut elsewhere_proved = Proved::default();
        assert!(!prove(
            1,
            good,
            Some(&another_connection),
            &mut elsewhere_proved
        ));
        assert!(!prove(1, good, Some(&another_peer), &mut elsewhere_proved));
        // And on a connection that gives no value, no proof holds.
        assert!(!prove(1, good, None, &mut elsewhere_proved));
        assert_eq!(elsewhere_proved.len(), 0);

        // A channel that the relay does not hold, proved as it should
        // be: the same no as for a proof that fails.
        let not_held = proof::make(&secret(3), &session.value, &session.prover).unwrap();
        assert!(!prove(3, not_held, Some(&session), &mut proved));
        assert_eq!(at.held(3), None);

        // What the connection remembers: each channel for which a proof
        // held, also the one that is not held, and no other.
        assert!(proved.holds(&channel(1)));
        assert!(proved.holds(&channel(3)));
        assert!(!proved.holds(&channel(2)));
        assert_eq!(proved.len(), 2);

        // The signature is looked at before the database is held: with a
        // database that cannot be had, a proof that fails is still
        // answered, and one that holds cannot be.
        let lost = relay();
        let _ = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _held = lost.db.lock().unwrap();
                    panic!("the database is lost while it is held");
                })
                .join()
        });
        assert!(lost.db.lock().is_err(), "the database can still be had");
        let mut at_the_lost = Proved::default();
        let mut prove_there = |proof: [u8; 64]| {
            lost.answer(
                1,
                Protocol::ChannelProve,
                WireMessage::ChannelProve(ChannelProve {
                    channel: channel(1),
                    proof,
                }),
                Some(&session),
                &mut at_the_lost,
            )
        };
        for fails in [[7u8; 64], elsewhere, by_another, by_this_end] {
            assert!(!proved_said(prove_there(fails)));
        }
        assert!(matches!(prove_there(good), Answer::Nothing));
        assert_eq!(at_the_lost.len(), 0);

        // A proof on the stream of another kind of request is not looked
        // at.
        let mut none = Proved::default();
        let answer = at.answer(
            1,
            Protocol::EntryPull,
            WireMessage::ChannelProve(ChannelProve {
                channel: channel(1),
                proof: good,
            }),
            Some(&session),
            &mut none,
        );
        assert!(matches!(answer, Answer::Stray));
        assert_eq!(none.len(), 0);
    }

    /// A connection is remembered to have proved only so many channels.
    /// A proof for one more is answered as one that fails, and is not
    /// looked at. A channel that is remembered can still be proved again.
    #[test]
    fn a_connection_is_remembered_to_have_proved_only_so_many_channels() {
        assert_eq!(MAX_CHANNELS_PROVED_ON_A_CONNECTION, 1024);
        let at = relay();
        at.hold(&small(7, 1, 5), NOW - 2 * HOUR);
        at.hold(&small(2000, 1, 5), NOW - 2 * HOUR);
        let session = Session {
            value: [0x51; 32],
            prover: peer(1).0,
        };
        let prove = |c: u16, proved: &mut Proved| {
            let proof = proof::make(&secret(c), &session.value, &session.prover).unwrap();
            proved_said(at.answer(
                1,
                Protocol::ChannelProve,
                WireMessage::ChannelProve(ChannelProve {
                    channel: channel(c),
                    proof,
                }),
                Some(&session),
                proved,
            ))
        };
        // A connection that has proved one channel the relay holds, one
        // it does not, and as many more as one connection may in all.
        let mut proved = Proved::default();
        assert!(prove(7, &mut proved));
        assert!(!prove(8, &mut proved));
        assert_eq!(proved.len(), 2);
        for n in 0..1021u32 {
            let mut made_up = [0x33; 32];
            made_up[..4].copy_from_slice(&n.to_be_bytes());
            assert!(proved.has_room_for(&made_up));
            proved.remember(made_up);
        }
        assert_eq!(proved.len(), 1023);
        // The last that it may: a proof that holds is remembered.
        assert!(!prove(9, &mut proved));
        assert_eq!(proved.len(), 1024);
        assert!(proved.holds(&channel(9)));

        // One more, which the relay holds, with a proof that holds: no.
        // Nothing is remembered for it, and it was no use of the channel.
        assert!(!prove(2000, &mut proved));
        assert_eq!(at.held(2000).unwrap().used_at, NOW - 2 * HOUR);
        assert!(!proved.holds(&channel(2000)));
        // Nor any after it.
        assert!(!prove(2001, &mut proved));
        assert_eq!(proved.len(), 1024);
        // One of those that are remembered is proved again: yes, and it
        // is use of the channel.
        lock(&at.db)
            .execute("UPDATE relay_channels SET used_at = ?1", [NOW - 2 * HOUR])
            .unwrap();
        assert!(prove(7, &mut proved));
        assert_eq!(at.held(7).unwrap().used_at, NOW);
        assert_eq!(proved.len(), 1024);

        // Another connection has a memory of its own.
        let mut another = Proved::default();
        assert!(prove(2000, &mut another));
        assert_eq!(another.len(), 1);
    }

    // ── Pull ─────────────────────────────────────────────────────────

    /// A channel is handed only to a connection that has proved its key.
    /// Without that the answer is the one for a channel that the relay
    /// does not hold, byte for byte, and counts for nothing.
    #[test]
    fn a_channel_is_handed_only_to_a_connection_that_proved_it() {
        let at = relay();
        let entries = [small(1, 1, 5), small(1, 2, 5), small(1, 3, 5)];
        for entry in &entries {
            at.hold(entry, NOW);
        }
        let mark = at.held(1).unwrap().mark;
        let bytes = |page: &EntryPulled| {
            codec::encode_message(&WireMessage::EntryPulled(page.clone())).unwrap()
        };

        // Not proved on this connection: nothing, whatever mark and place
        // are asked with. A channel that is not held is answered so,
        // proved or not.
        let nothing = Proved::default();
        for (asked_mark, after) in [(relay::NO_MARK, 0), (mark, 0), (mark, 2), ([9; 8], 7)] {
            let unproved = page(at.pull(1, 1, &nothing, asked_mark, after));
            assert_eq!(
                unproved,
                EntryPulled {
                    entries: Vec::new(),
                    next: after,
                    mark: asked_mark,
                }
            );
            for proved in [&nothing, &having_proved(&[2])] {
                let not_held = page(at.pull(1, 2, proved, asked_mark, after));
                assert_eq!(bytes(&not_held), bytes(&unproved));
            }
        }
        assert_eq!(at.fetch_room(1), MINUTE, "nothing was handed");

        // Proved on this connection: the page, and the mark of the
        // holding. It counts against what the peer may be handed.
        let proved = having_proved(&[1]);
        let handed = page(at.pull(1, 1, &proved, relay::NO_MARK, 0));
        let wire: Vec<Vec<u8>> = handed.entries.iter().map(|entry| entry.to_vec()).collect();
        let stored: Vec<Vec<u8>> = entries.iter().map(|entry| entry.to_wire()).collect();
        assert_eq!(wire, stored);
        assert_eq!((handed.next, handed.mark), (3, mark));
        assert_eq!(at.fetch_room(1), MINUTE - 3 * SMALL);
        // From its place, with the mark it was told: what came after.
        let rest = page(at.pull(1, 1, &proved, mark, 2));
        assert_eq!((rest.entries.len(), rest.next), (1, 3));
        // With a mark that is not this holding's, from the start.
        let again = page(at.pull(1, 1, &proved, [9; 8], 3));
        assert_eq!((again.entries.len(), again.next, again.mark), (3, 3, mark));

        // A proof of another channel is no proof of this one, and what
        // one connection proved is nothing to another.
        let other = having_proved(&[2]);
        assert!(page(at.pull(1, 1, &other, mark, 0)).entries.is_empty());
        assert!(page(at.pull(2, 1, &nothing, mark, 0)).entries.is_empty());
    }

    /// A pull of a channel that was not proved on the connection is
    /// answered from the connection's memory, and the store is not asked:
    /// the answer comes while the database is held by another. It is the
    /// answer for a channel that is not held, to the byte. A pull of a
    /// channel that was proved waits for the store.
    #[test]
    fn a_pull_of_a_channel_that_was_not_proved_does_not_wait_for_the_store() {
        use std::sync::mpsc;
        let at = relay();
        at.hold(&small(1, 1, 5), NOW);
        let mark = at.held(1).unwrap().mark;

        // The page that a pull with `proved` is handed within two seconds
        // while this thread holds the database, where one is.
        let while_held = |proved: &Proved, mark: Mark, after: u64| {
            let held = lock(&at.db);
            std::thread::scope(|scope| {
                let (said, heard) = mpsc::channel();
                let at = &at;
                scope.spawn(move || {
                    let _ = said.send(page(at.pull(1, 1, proved, mark, after)));
                });
                let answered = heard.recv_timeout(Duration::from_secs(2));
                drop(held);
                answered.ok()
            })
        };
        let nothing_proved = Proved::default();
        for (asked_mark, after) in [(relay::NO_MARK, 0), (mark, 0), (mark, 1), ([9; 8], 7)] {
            assert_eq!(
                while_held(&nothing_proved, asked_mark, after),
                Some(EntryPulled {
                    entries: Vec::new(),
                    next: after,
                    mark: asked_mark,
                })
            );
        }
        // Another channel proved is no proof of this one.
        assert!(while_held(&having_proved(&[2]), mark, 0).is_some());
        // The control: the channel was proved, and the store is asked.
        assert_eq!(while_held(&having_proved(&[1]), mark, 0), None);
        let handed = page(at.pull(1, 1, &having_proved(&[1]), mark, 0));
        assert_eq!((handed.entries.len(), handed.next), (1, 1));

        // And the answer is the one that the store gives for a channel
        // that is not held, or was not proved.
        let stores = relay::pull(&lock(&at.db), &channel(1), false, &[9; 8], 7, 100).unwrap();
        assert_eq!(
            page(at.pull(1, 1, &nothing_proved, [9; 8], 7)),
            EntryPulled::from(&stores)
        );
    }

    /// What a peer is handed in a minute is bounded, as what a relay may
    /// fetch from it is. A page is sized to the room there is, an entry
    /// that fits is still handed, and a pull whose first entry does not
    /// fit is refused, and is no breach.
    #[test]
    fn a_peer_is_handed_only_what_may_be_fetched_in_a_minute() {
        let at = relay();
        // Forty entries of the largest size, and a channel of small ones.
        for d in 1..=40 {
            at.hold(&largest(1, d), NOW);
        }
        for d in 1..=3 {
            at.hold(&small(2, d, 5), NOW);
        }
        let proved = having_proved(&[1, 2]);
        let mut mark = relay::NO_MARK;
        let mut after = 0;
        let mut handed = Vec::new();
        // Whole pages while there is room for the most a page can be
        // counted at: 13 of the largest are what one message holds.
        // Then as many as fit.
        for _ in 0..3 {
            let page = page(at.pull(1, 1, &proved, mark, after));
            handed.push(page.entries.len());
            (mark, after) = (page.mark, page.next);
        }
        assert_eq!(handed, [13, 13, 5]);
        assert_eq!(at.fetch_room(1), MINUTE - 31 * LARGEST);
        assert!(at.fetch_room(1) < LARGEST);

        // The next entry of the largest size does not fit: the pull is
        // refused, and nothing is counted for it. It is no breach: the
        // relay sized the page, and the asker cannot know its room.
        not_now(at.pull(1, 1, &proved, mark, after));
        assert_eq!(at.fetch_room(1), MINUTE - 31 * LARGEST);
        assert_eq!(breaches(&at, 1), (0, 0));
        // A page with nothing in it is still answered: the end of the
        // channel, and a channel that is not held.
        let end = page(at.pull(1, 1, &proved, mark, 40));
        assert_eq!((end.entries.len(), end.next), (0, 40));
        assert!(page(at.pull(1, 9, &proved, mark, 0)).entries.is_empty());
        // And an entry that fits is still handed, one at a time.
        let one = page(at.pull(1, 2, &proved, relay::NO_MARK, 0));
        assert_eq!((one.entries.len(), one.next), (1, 1));
        assert_eq!(at.fetch_room(1), MINUTE - 31 * LARGEST - SMALL);

        // Asked for many more times than cut a peer off, it is refused
        // each time, and never a breach.
        for _ in 0..3 * BAN_THRESHOLD {
            not_now(at.pull(1, 1, &proved, mark, after));
        }
        assert_eq!(breaches(&at, 1), (0, 0));
        assert_eq!(at.fetch_room(1), MINUTE - 31 * LARGEST - SMALL);

        // Another connection, at another address, has an allowance of its
        // own.
        assert_eq!(page(at.pull(2, 1, &proved, mark, after)).entries.len(), 9);
    }

    /// The bytes that may be fetched in a minute are one allowance for
    /// both kinds of channel, for a connection and for its address: what
    /// a relay fetched from a peer of the older kind leaves less to hand
    /// it of this kind, and an address that has been handed its share is
    /// handed no more under another key.
    #[test]
    fn what_is_handed_is_counted_with_the_older_kind_and_for_the_address() {
        let at = relay();
        for d in 1..=3 {
            at.hold(&small(1, d, 5), NOW);
        }
        at.hold(&largest(2, 1), NOW);
        let proved = having_proved(&[1, 2]);

        // The relay has fetched from this peer, of the older kind, all
        // but 2000 bytes of what may be fetched in a minute.
        lock(&at.rates).fetched(&peer(1), address(1), MINUTE - 2000);
        // One small entry fits, and is handed. The next does not.
        let one = page(at.pull(1, 1, &proved, relay::NO_MARK, 0));
        assert_eq!(one.entries.len(), 1);
        assert_eq!(at.fetch_room(1), 2000 - SMALL);
        not_now(at.pull(1, 1, &proved, one.mark, one.next));
        // And what was handed counts where the older kind looks: it is
        // one count.
        assert_eq!(
            lock(&at.rates).fetch_room(&peer(1), address(1)),
            2000 - SMALL
        );

        // An address: its connections are handed, between them, five
        // times what one may be. Five peers at one address are each
        // handed all that a connection may be.
        let home = address(50);
        let at_home = |n: u8| Who {
            peer: Box::leak(Box::new(peer(n))),
            address: home,
            listed: false,
        };
        assert_eq!(MAX_CONNECTIONS_PER_IP, 5);
        for n in 10..15 {
            assert!(lock(&at.rates).handed(&peer(n), home, MINUTE));
        }
        // A sixth key at that address has a connection's allowance of its
        // own, and the address has none left: nothing is handed.
        let pull = |who: &Who, c: u16| {
            at.entries.pulling(
                &at.db,
                &at.rates,
                who,
                &proved,
                &EntryPull {
                    channel: channel(c),
                    mark: relay::NO_MARK,
                    after: 0,
                    limit: 100,
                },
            )
        };
        not_now(pull(&at_home(16), 1));
        not_now(pull(&at_home(16), 2));
        // However often, and under whatever key: refused, and no breach
        // of the address.
        for n in 17..17 + 2 * BAN_THRESHOLD as u8 {
            not_now(pull(&at_home(n), 1));
        }
        assert_eq!(
            lock(&at.rates)
                .breaches_of_address(home)
                .map(|limiter| limiter.breach_count),
            Some(0)
        );
        // Another address is handed the same channel.
        assert_eq!(
            page(at.pull(3, 1, &proved, relay::NO_MARK, 0))
                .entries
                .len(),
            3
        );
    }

    // ── Push ─────────────────────────────────────────────────────────

    /// Each entry that is pushed is checked and taken by the store's
    /// rule, and each is answered for, in the order they were sent.
    #[test]
    fn each_entry_pushed_is_checked_taken_and_answered_for() {
        let at = relay();
        let held = small(1, 1, 5);
        assert_eq!(
            pushed(at.push(1, vec![held.to_wire()])),
            [PushAnswer::Stored]
        );

        let mut unsigned = small(1, 3, 5).into_entry();
        unsigned.channel_signature = [0; 64];
        let answers = pushed(at.push(
            1,
            vec![
                small(1, 2, 5).to_wire(),
                held.to_wire(),
                small(1, 1, 4).to_wire(),
                unsigned.to_wire(),
                vec![9; 300],
                small(2, 1, 5).to_wire(),
                small(1, 1, 6).to_wire(),
            ],
        ));
        assert_eq!(
            answers,
            [
                PushAnswer::Stored,
                PushAnswer::Held,
                PushAnswer::Older,
                PushAnswer::Refused(EntryRefused::NotSigned),
                PushAnswer::Refused(EntryRefused::NotSigned),
                PushAnswer::Stored,
                PushAnswer::Stored,
            ]
        );
        // What was stored is held: two authors in the first channel, and
        // a second channel.
        assert_eq!(at.held(1).unwrap().bytes, 2 * SMALL);
        assert_eq!(at.held(2).unwrap().bytes, SMALL);
        assert_eq!(at.used(), 3 * SMALL);

        // A push of nothing is answered with nothing, and nothing is kept
        // of it: not a count for a peer that has sent nothing else.
        assert_eq!(pushed(at.push(1, Vec::new())), []);
        assert_eq!(pushed(at.push(77, Vec::new())), []);
        assert!(!lock(&at.rates).is_counting(&peer(77)));
        assert!(lock(&at.rates).is_counting(&peer(1)));
        // Entries on the stream of another kind of request are not taken.
        let answer = at.answer(
            1,
            Protocol::EntryShow,
            WireMessage::EntryPush(EntryPush {
                entries: vec![small(3, 1, 5).to_wire().into()],
            }),
            None,
            &mut Proved::default(),
        );
        assert!(matches!(answer, Answer::Stray));
        assert_eq!(at.held(3), None);
    }

    /// A frame that is no request for its stream counts as pushed, for
    /// every byte of it and for no less than an entry: the relay read it.
    /// Over what its sender may push, it is a breach, as a push is. A
    /// relay that the operator lists is not limited.
    #[test]
    fn a_frame_that_is_no_request_counts_as_pushed() {
        let at = relay_of(u64::MAX, &[9]);
        let sent_by = |n: u8, frame: &[u8]| {
            let peer = peer(n);
            RelayEntries::counted_as_pushed(&at.rates, &at.who(&peer, n), frame)
        };
        // A few bytes count for what the smallest entry does.
        assert_eq!(sent_by(1, &[1, 2, 3]), None);
        assert_eq!(at.push_room(1), MINUTE - 1024);
        assert_eq!(sent_by(1, &[]), None);
        assert_eq!(at.push_room(1), MINUTE - 2 * 1024);
        // A megabyte counts for a megabyte.
        let megabyte = vec![0x5a; 1_000_000];
        assert_eq!(sent_by(1, &megabyte), None);
        assert_eq!(
            at.push_room(1),
            MINUTE - 2 * 1024 - (1_000_000 - 237 + 1024)
        );
        // Another does not fit what is left of the minute: nothing is
        // counted for it, and it is a breach. The third cuts off.
        assert_eq!(sent_by(1, &megabyte), None);
        let room = at.push_room(1);
        assert!(room < 1_000_000);
        assert_eq!(sent_by(1, &megabyte), Some(OverLimit { cut_off: false }));
        assert_eq!(at.push_room(1), room);
        // It is one allowance with what is pushed as entries: two of the
        // largest do not fit it either, and that is the second breach.
        assert!(room < 2 * LARGEST);
        assert!(!over(at.push(1, vec![largest(1, 1).to_wire(); 2])).cut_off);
        assert_eq!(sent_by(1, &megabyte), Some(OverLimit { cut_off: true }));

        // A relay that the operator lists is not counted.
        assert!(at.entries.lists(&peer(9)));
        for _ in 0..5 {
            assert_eq!(sent_by(9, &megabyte), None);
        }
        assert_eq!(at.push_room(9), MINUTE);

        // What is one: a request of another stream, on each of the four,
        // and what is asked on the stream between relays by a peer that
        // is not listed. Each is a stray one, and is not answered.
        let stray = |n: u8, protocol: Protocol, request: WireMessage| {
            let answer = at.answer(n, protocol, request, None, &mut Proved::default());
            matches!(answer, Answer::Stray)
        };
        let pull = WireMessage::EntryPull(EntryPull {
            channel: channel(1),
            mark: relay::NO_MARK,
            after: 0,
            limit: 100,
        });
        for protocol in [
            Protocol::EntryShow,
            Protocol::ChannelProve,
            Protocol::EntryPush,
            Protocol::RelayEntries,
        ] {
            assert!(stray(2, protocol, pull.clone()), "{protocol:?}");
        }
        for request in requests_of_a_relay() {
            assert!(stray(2, Protocol::RelayEntries, request.clone()));
            // From the listed relay it is a request, and is answered.
            assert!(!stray(9, Protocol::RelayEntries, request));
        }
        // A message that is no request at all, on any of them.
        let an_answer = WireMessage::ChannelProved(ChannelProved { proved: true });
        for protocol in [Protocol::EntryShow, Protocol::RelayEntries] {
            assert!(stray(2, protocol, an_answer.clone()));
            assert!(stray(9, protocol, an_answer.clone()));
        }
        // The control: a request on its own stream is none.
        assert!(!stray(2, Protocol::EntryPull, pull));
    }

    /// A push that the relay cannot write is undone, and is counted for
    /// nothing: not against the bytes that its sender may push, and not
    /// against the channels that its address may make the relay take. A
    /// push that is written is counted for both.
    #[test]
    fn a_push_that_cannot_be_written_is_counted_for_nothing() {
        let at = relay();
        // The store refuses every entry of the channel numbered 300.
        lock(&at.db)
            .execute_batch(&format!(
                "CREATE TRIGGER refuses BEFORE INSERT ON entries
                 WHEN NEW.channel_id = X'{}'
                 BEGIN SELECT RAISE(ABORT, 'refused'); END;",
                hex::encode(channel(300))
            ))
            .unwrap();
        // A push of two entries, each in a channel that the relay does
        // not hold. The first is taken, the second cannot be written: the
        // push is not answered, and nothing of it is held.
        let cannot = vec![small(299, 1, 5).to_wire(), small(300, 1, 5).to_wire()];
        for _ in 0..3 {
            assert!(matches!(at.push(1, cannot.clone()), Answer::Nothing));
        }
        assert_eq!(at.held(299), None);
        assert_eq!(at.used(), 0);
        // Its bytes were not counted against what the peer may push.
        assert_eq!(at.push_room(1), MINUTE);
        // Nor was its address counted for the channel that was taken and
        // undone: it may still make the relay take all of its share.
        assert_eq!(NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR, 256);
        for from in [0u16, 100, 200] {
            let to = (from + 100).min(256);
            let answers =
                pushed(at.push(1, (from..to).map(|c| small(c, 1, 5).to_wire()).collect()));
            assert!(
                answers.iter().all(|answer| *answer == PushAnswer::Stored),
                "{from}: {answers:?}"
            );
        }
        // Those were written, and are counted: the bytes, and the share.
        assert_eq!(at.push_room(1), MINUTE - 256 * SMALL);
        assert_eq!(
            pushed(at.push(1, vec![small(299, 1, 5).to_wire()])),
            [PushAnswer::Refused(EntryRefused::OverLimit)]
        );
        // A push that is refused for a limit is written all the same, as
        // a push of nothing new: its bytes count.
        assert_eq!(at.push_room(1), MINUTE - 257 * SMALL);
    }

    /// What a peer pushes counts against the bytes it may push in a
    /// minute, with the older kind of channel: one allowance for both. A
    /// push that is over it is refused whole, stores nothing, and is a
    /// breach.
    #[test]
    fn what_is_pushed_is_counted_with_the_older_kind_against_one_allowance() {
        let at = relay();
        // Each entry counts as its content and what an entry takes beyond
        // it, and bytes that are no entry's count for all of them.
        let push = vec![
            small(1, 1, 5).to_wire(),
            small(1, 2, 5).to_wire(),
            vec![9; 5000],
        ];
        pushed(at.push(1, push));
        assert_eq!(at.push_room(1), MINUTE - 2 * SMALL - (5000 - 237 + 1024));
        // A push of nothing counts for nothing.
        let before = at.push_room(1);
        pushed(at.push(1, Vec::new()));
        assert_eq!(at.push_room(1), before);

        // A peer that has pushed, in items of the older kind, all but
        // 2000 bytes of what it may: two small entries are over it. The
        // push is refused whole, and nothing of it is stored.
        lock(&at.rates)
            .pushed(&peer(2), address(2), MINUTE - 2000)
            .unwrap();
        let two = vec![small(5, 1, 5).to_wire(), small(6, 1, 5).to_wire()];
        assert!(!over(at.push(2, two.clone())).cut_off);
        assert_eq!((at.held(5), at.held(6)), (None, None));
        assert_eq!(at.push_room(2), 2000, "a refused push was counted");
        // One fits in what is left, and is stored.
        assert_eq!(pushed(at.push(2, two[..1].to_vec())), [PushAnswer::Stored]);
        assert_eq!(at.push_room(2), 2000 - SMALL);
        // And what it pushed of this kind counts where the older kind
        // looks.
        assert!(
            lock(&at.rates)
                .pushed(&peer(2), address(2), 2000 - SMALL + 1)
                .is_err()
        );
        // That was the second breach. The third cuts the peer off.
        assert!(over(at.push(2, two)).cut_off);
    }

    // ── Who asks ─────────────────────────────────────────────────────

    /// A peer is its address, for the allowance of new channels: the
    /// 257th that one address makes the relay take in an hour is refused.
    /// A relay that the operator lists by key is not counted. A relay
    /// that is configured by address alone is not listed, wherever a peer
    /// comes from.
    #[test]
    fn a_peer_is_its_address_or_a_relay_that_the_operator_lists_by_key() {
        let at = relay_of(u64::MAX, &[9]);
        assert_eq!(at.entries.listed(), [peer(9)]);
        assert!(at.entries.lists(&peer(9)));
        assert!(!at.entries.lists(&peer(1)));
        // A peer that comes from the address of the relay configured with
        // no key is not a listed relay, nor one from a listed relay's
        // address under another key.
        let keyless = peer(200);
        assert!(!at.who(&keyless, 200).listed);
        let another_key = peer(10);
        assert!(!at.who(&another_key, 9).listed);
        assert_eq!(at.who(&another_key, 9).asker(), Asker::Address(address(9)));
        assert_eq!(
            at.who(&peer(9), 9).asker(),
            Asker::ListedRelay {
                held_since: None,
                used_at: None
            }
        );

        // One address makes the relay take as many new channels as it
        // may in an hour: every push is within the bytes it may push.
        assert_eq!(NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR, 256);
        let first = |c: u16| small(c, 1, 5).to_wire();
        for from in [0u16, 100, 200] {
            let to = (from + 100).min(256);
            let answers = pushed(at.push(1, (from..to).map(first).collect()));
            assert!(answers.iter().all(|a| *a == PushAnswer::Stored), "{from}");
        }
        // The 257th, pushed and shown: over the limit, and not held.
        assert_eq!(
            pushed(at.push(1, vec![first(256)])),
            [PushAnswer::Refused(EntryRefused::OverLimit)]
        );
        assert_eq!(
            shown(at.show(1, first(256))),
            ShowAnswer::Refused(EntryRefused::OverLimit)
        );
        assert_eq!(at.held(256), None);
        // Under another key at that address it is the same address.
        let other_key = peer(2);
        let from_there = Who {
            peer: &other_key,
            address: address(1),
            listed: false,
        };
        let push = EntryPush {
            entries: vec![first(256).into()],
        };
        let answer = at
            .entries
            .pushing(&at.db, &at.rates, &from_there, &push, NOW);
        assert_eq!(
            pushed(answer),
            [PushAnswer::Refused(EntryRefused::OverLimit)]
        );
        // An entry in a channel that is held is no new channel.
        assert_eq!(
            pushed(at.push(1, vec![small(7, 2, 5).to_wire()])),
            [PushAnswer::Stored]
        );
        // Another address has an allowance of its own.
        assert_eq!(pushed(at.push(3, vec![first(256)])), [PushAnswer::Stored]);

        // A listed relay is not counted by address, and not limited. It
        // makes the relay take new channels from the address that has
        // had its share, and pushes more bytes than a connection may in
        // a minute.
        let listed = peer(9);
        let room_before = (at.push_room(1), at.fetch_room(1));
        let from_that_address = Who {
            peer: &listed,
            address: address(1),
            listed: at.entries.lists(&listed),
        };
        let push = |entries: Vec<Vec<u8>>| {
            let push = EntryPush {
                entries: entries.into_iter().map(Into::into).collect(),
            };
            pushed(
                at.entries
                    .pushing(&at.db, &at.rates, &from_that_address, &push, NOW),
            )
        };
        assert_eq!(
            push(vec![first(1000), first(1001)]),
            [PushAnswer::Stored, PushAnswer::Stored]
        );
        let large: Vec<Vec<u8>> = (1..=13).map(|d| largest(3000, d).to_wire()).collect();
        for _ in 0..3 {
            assert_eq!(push(large.clone()).len(), 13);
        }
        assert_eq!(
            lock(&at.rates).push_room(&listed, address(1)),
            MINUTE,
            "a listed relay was counted"
        );
        assert_eq!(
            (at.push_room(1), at.fetch_room(1)),
            room_before,
            "a listed relay was counted against the address"
        );
        assert_eq!(at.held(3000).unwrap().bytes, 13 * LARGEST);
        // The address is where it was: another new channel from it is
        // still refused.
        assert_eq!(
            pushed(at.push(1, vec![first(257)])),
            [PushAnswer::Refused(EntryRefused::OverLimit)]
        );
    }

    // ── Relays that work together ────────────────────────────────────

    /// The stream between relays is answered for a relay that the
    /// operator lists by key, and for no other peer: which channels a
    /// relay holds is told to nobody else, and nobody else is handed a
    /// channel without the proof or has its word for a time kept.
    #[test]
    fn the_stream_between_relays_is_for_a_listed_relay_and_no_other() {
        let at = relay_of(u64::MAX, &[9]);
        at.hold(&small(1, 1, 5), NOW - 100);
        at.hold(&small(1, 2, 5), NOW - 100);
        at.hold(&small(2, 1, 5), NOW - 50);
        let mark = at.held(1).unwrap().mark;
        let requests = || {
            vec![
                WireMessage::RelayChannelsAsk(RelayChannelsAsk {
                    after: [0; 32],
                    limit: 1000,
                }),
                WireMessage::RelayPull(RelayPull {
                    channel: channel(1),
                    mark: relay::NO_MARK,
                    after: 0,
                    limit: 100,
                }),
                WireMessage::RelayPush(RelayPush {
                    entries: vec![RelayEntry {
                        entry: small(3, 1, 5).to_wire(),
                        held_since: NOW - 9000,
                        used_at: NOW - 10,
                    }],
                }),
            ]
        };
        let ask = |n: u8, request: WireMessage| {
            at.answer(
                n,
                Protocol::RelayEntries,
                request,
                None,
                &mut Proved::default(),
            )
        };

        // A peer that is not listed, one that has proved the channel on
        // its connection, and one from the address of a relay that is
        // configured with no key: nothing is said, and nothing changes.
        let before = (at.held(1), at.held(2), at.held(3));
        for n in [1, 200] {
            for request in requests() {
                assert!(matches!(ask(n, request), Answer::Stray), "{n}");
            }
        }
        for request in requests() {
            let answer = at.answer(
                1,
                Protocol::RelayEntries,
                request,
                None,
                &mut having_proved(&[1, 2, 3]),
            );
            assert!(matches!(answer, Answer::Stray));
        }
        assert_eq!((at.held(1), at.held(2), at.held(3)), before);

        // The listed relay is told which channels are held, each as it is
        // held.
        let mut requests = requests().into_iter();
        let WireMessage::RelayChannelsHeld(told) = said(ask(9, requests.next().unwrap())) else {
            panic!("not an answer about channels");
        };
        let held: Vec<RelayChannel> = relay::held_channels(&lock(&at.db), &[0; 32], 1000)
            .unwrap()
            .iter()
            .map(RelayChannel::from)
            .collect();
        assert_eq!(told.channels, held);
        assert_eq!(told.channels.len(), 2);
        let first = told
            .channels
            .iter()
            .find(|told| told.channel == channel(1))
            .unwrap();
        assert_eq!(
            (first.mark, first.held_since, first.used_at, first.places),
            (mark, NOW - 100, NOW - 100, 2)
        );
        // It is handed a channel with no proof.
        let handed = page(ask(9, requests.next().unwrap()));
        assert_eq!(
            (handed.entries.len(), handed.next, handed.mark),
            (2, 2, mark)
        );
        // And what it passes on is taken, with its word for the two
        // times of the channel.
        assert_eq!(
            pushed(ask(9, requests.next().unwrap())),
            [PushAnswer::Stored]
        );
        let passed_on = at.held(3).unwrap();
        assert_eq!(
            (passed_on.held_since, passed_on.used_at),
            (NOW - 9000, NOW - 10)
        );
        // None of it counted against what a peer may push or be handed.
        assert_eq!((at.push_room(9), at.fetch_room(9)), (MINUTE, MINUTE));

        // The requests of the four streams are not answered on this one,
        // nor these on the four.
        let stray = WireMessage::EntryPull(EntryPull {
            channel: channel(1),
            mark,
            after: 0,
            limit: 100,
        });
        assert!(matches!(ask(9, stray), Answer::Stray));
        for protocol in [
            Protocol::EntryShow,
            Protocol::ChannelProve,
            Protocol::EntryPull,
            Protocol::EntryPush,
        ] {
            for request in self::requests_of_a_relay() {
                let answer = at.answer(9, protocol, request, None, &mut Proved::default());
                assert!(matches!(answer, Answer::Stray), "{protocol:?}");
            }
        }
    }

    /// One of each request that a relay makes of a relay it works with.
    fn requests_of_a_relay() -> Vec<WireMessage> {
        vec![
            WireMessage::RelayChannelsAsk(RelayChannelsAsk {
                after: [0; 32],
                limit: 1000,
            }),
            WireMessage::RelayPull(RelayPull {
                channel: channel(1),
                mark: relay::NO_MARK,
                after: 0,
                limit: 100,
            }),
            WireMessage::RelayPush(RelayPush {
                entries: Vec::new(),
            }),
        ]
    }

    /// The messages that wait for the relay numbered `n`, as the entries
    /// in them: each as its bytes, with the two times it is passed on
    /// with.
    fn waiting_for(passed: &[(NodeId, Vec<RelayPush>)], n: u8) -> Vec<Vec<RelayEntry>> {
        passed
            .iter()
            .filter(|(relay, _)| *relay == peer(n))
            .flat_map(|(_, messages)| messages.iter().map(|message| message.entries.clone()))
            .collect()
    }

    /// An entry that a relay takes, from anyone, waits to be passed on to
    /// the relays it works with that are connected, with the two times
    /// of its channel: to each but the one it came from, and once.
    #[test]
    fn an_entry_that_is_taken_is_passed_on_to_the_listed_relays_but_not_back() {
        let at = relay_of(u64::MAX, &[8, 9]);
        let both = [peer(8), peer(9)];
        let passed = |entry: &CheckedEntry, held_since: i64, used_at: i64| RelayEntry {
            entry: entry.to_wire(),
            held_since,
            used_at,
        };
        assert!(at.entries.to_pass_on(&at.db, &both).is_empty());

        // From a device: pushed, and shown. To both relays.
        let (one, two) = (small(1, 1, 5), small(2, 1, 5));
        pushed(at.push(1, vec![one.to_wire()]));
        assert_eq!(shown(at.show(1, two.to_wire())), ShowAnswer::Taken);
        // What is not stored does not wait: one that is held already,
        // an older one, and one that is refused.
        pushed(at.push(1, vec![one.to_wire(), small(1, 1, 4).to_wire(), vec![1]]));
        assert_eq!(shown(at.show(1, two.to_wire())), ShowAnswer::Held);
        let waiting = at.entries.to_pass_on(&at.db, &both);
        for n in [8, 9] {
            assert_eq!(
                waiting_for(&waiting, n),
                [vec![passed(&one, NOW, NOW), passed(&two, NOW, NOW)]],
                "{n}"
            );
        }
        // Once: nothing waits afterwards.
        assert!(at.entries.to_pass_on(&at.db, &both).is_empty());

        // From a relay it works with, with that relay's word for the two
        // times: to the other, with the times as this relay holds them
        // now, and not back to the one it came from.
        let three = small(3, 1, 5);
        let from_a_relay = WireMessage::RelayPush(RelayPush {
            entries: vec![passed(&three, NOW - 9000, NOW - 10)],
        });
        let answer = at.answer(
            8,
            Protocol::RelayEntries,
            from_a_relay,
            None,
            &mut Proved::default(),
        );
        assert_eq!(pushed(answer), [PushAnswer::Stored]);
        // And one that the same relay pushes on the stream of entries.
        let four = small(4, 1, 5);
        pushed(at.push(8, vec![four.to_wire()]));
        let waiting = at.entries.to_pass_on(&at.db, &both);
        assert!(waiting_for(&waiting, 8).is_empty());
        assert_eq!(
            waiting_for(&waiting, 9),
            [vec![
                passed(&three, NOW - 9000, NOW - 10),
                passed(&four, NOW, NOW)
            ]]
        );

        // Only to the relays that are connected. What waited while none
        // was is not kept: it is pulled.
        pushed(at.push(1, vec![small(5, 1, 5).to_wire()]));
        let waiting = at.entries.to_pass_on(&at.db, &both[1..]);
        assert!(waiting_for(&waiting, 8).is_empty());
        assert_eq!(waiting_for(&waiting, 9).len(), 1);
        pushed(at.push(1, vec![small(6, 1, 5).to_wire()]));
        assert!(at.entries.to_pass_on(&at.db, &[]).is_empty());
        assert!(at.entries.to_pass_on(&at.db, &both).is_empty());

        // An entry of a channel that was dropped since is passed on to
        // nobody.
        pushed(at.push(1, vec![small(7, 1, 5).to_wire()]));
        relay::make_room(&lock(&at.db), 0).unwrap();
        assert!(at.entries.to_pass_on(&at.db, &both).is_empty());

        // A page's worth to a message: 150 small entries are two, and 20
        // of the largest are two, 13 and 7.
        for from in [0u8, 100] {
            let entries = (from..(from + 100).min(150))
                .map(|d| made(10, d, 5, "notes.md", "a small text").to_wire())
                .collect();
            pushed(at.push(8, entries));
        }
        let waiting = at.entries.to_pass_on(&at.db, &both);
        let sizes: Vec<usize> = waiting_for(&waiting, 9).iter().map(Vec::len).collect();
        assert_eq!(sizes, [100, 50]);
        pushed(at.push(8, (1..=13).map(|d| largest(11, d).to_wire()).collect()));
        pushed(at.push(8, (14..=20).map(|d| largest(11, d).to_wire()).collect()));
        let waiting = at.entries.to_pass_on(&at.db, &both);
        let sizes: Vec<usize> = waiting_for(&waiting, 9).iter().map(Vec::len).collect();
        assert_eq!(sizes, [13, 7]);
        for message in &waiting[0].1 {
            let bytes: usize = message.entries.iter().map(|e| e.entry.len()).sum();
            assert!(bytes <= ENTRY_PAGE_MAX_BYTES);
            let travels = codec::encode_message(&WireMessage::RelayPush(message.clone()));
            assert!(travels.unwrap().len() <= codec::MAX_MESSAGE_BYTES as usize);
        }

        // A relay whose operator lists no relay by key keeps nothing to
        // pass on.
        let alone = relay();
        pushed(alone.push(1, vec![one.to_wire()]));
        assert!(lock(&alone.entries.taken).is_empty());
    }

    /// A relay that is asked by this relay, in this process: each request
    /// is answered as `relay` answers a listed relay, at [`NOW`], and kept
    /// for the test to look at. `spoil` changes an answer on its way.
    struct Link<'a> {
        relay: &'a Relay,
        asked: Mutex<Vec<WireMessage>>,
        spoil: Option<fn(WireMessage) -> WireMessage>,
        /// The requests that are not answered at all, as where the relay
        /// is too slow: asking fails.
        unanswered: Option<fn(&WireMessage) -> bool>,
    }

    impl<'a> Link<'a> {
        fn to(relay: &'a Relay) -> Self {
            Self {
                relay,
                asked: Mutex::default(),
                spoil: None,
                unanswered: None,
            }
        }

        /// The pages that were asked for since the last time this was
        /// asked: the channel, the mark and the place of each.
        fn pulls(&self) -> Vec<([u8; 32], Mark, u64)> {
            std::mem::take(&mut *lock(&self.asked))
                .into_iter()
                .filter_map(|request| match request {
                    WireMessage::RelayPull(pull) => Some((pull.channel, pull.mark, pull.after)),
                    _ => None,
                })
                .collect()
        }
    }

    impl Asked for Link<'_> {
        async fn ask(&self, request: WireMessage) -> Result<WireMessage, String> {
            lock(&self.asked).push(request.clone());
            if self
                .unanswered
                .is_some_and(|unanswered| unanswered(&request))
            {
                return Err("timed out".into());
            }
            // The asker is the one relay that `relay` lists: number 9.
            let answer = self.relay.answer(
                9,
                Protocol::RelayEntries,
                request,
                None,
                &mut Proved::default(),
            );
            match answer {
                Answer::Message(answer) => {
                    Ok(self.spoil.map_or(*answer.clone(), |spoil| spoil(*answer)))
                }
                _ => Err("not answered".into()),
            }
        }
    }

    /// This relay's time, as the functions that are given none read it.
    fn now() -> i64 {
        unix_now()
    }

    /// A relay asks a relay it works with what it holds, and pulls what
    /// it lacks: every entry, with since when the channel is held there
    /// and when it was last used. Then it asks for nothing until there
    /// is more, and then from its place.
    #[tokio::test]
    async fn a_relay_pulls_what_it_lacks_from_a_relay_it_works_with() {
        // The other relay lists this one (number 9), and this one lists
        // the other (number 8).
        let other = relay_of(u64::MAX, &[9]);
        let this = relay_of(u64::MAX, &[8]);
        let then = now() - 10 * HOUR;
        for c in 1..=5 {
            other.hold(&small(c, 1, 5), then + i64::from(c));
            other.hold(&small(c, 2, 5), then + i64::from(c));
        }
        // One of them was used since: its key was proved there.
        let session = [0x51; 32];
        let proof = proof::make(&secret(3), &session, &peer(1).0).unwrap();
        relay::prove(
            &lock(&other.db),
            &channel(3),
            &session,
            &peer(1).0,
            &proof,
            then + 2 * HOUR,
        )
        .unwrap();

        let link = Link::to(&other);
        this.entries.pull_from(&link, peer(8), &this.db).await;
        // Every channel is held here as it is there: what it holds, since
        // when, and when it was last used. Each has a mark of this
        // relay's own.
        for c in 1..=5 {
            let (here, there) = (this.held(c).unwrap(), other.held(c).unwrap());
            assert_eq!(
                (here.bytes, here.held_since, here.used_at),
                (there.bytes, there.held_since, there.used_at),
                "{c}"
            );
            assert_eq!(here.held_since, then + i64::from(c));
            assert_ne!(here.mark, there.mark);
        }
        assert_eq!(this.held(3).unwrap().used_at, then + 2 * HOUR);
        assert_eq!(this.used(), 10 * SMALL);
        // Each was asked for once, from the start, with the mark that was
        // told.
        let mut pulls = link.pulls();
        pulls.sort();
        let mut all: Vec<([u8; 32], Mark, u64)> = (1..=5)
            .map(|c| (channel(c), other.held(c).unwrap().mark, 0))
            .collect();
        all.sort();
        assert_eq!(pulls, all);
        assert_eq!(lock(&this.entries.places).total(), 5);

        // Asked again, with nothing new there: the relay is told what is
        // held, and asks for no page.
        this.entries.pull_from(&link, peer(8), &this.db).await;
        assert!(link.pulls().is_empty());

        // An entry more there, and a newer revision of one: the channel
        // is asked for from this relay's place in it, and no other is.
        other.hold(&small(2, 3, 5), now());
        other.hold(&small(2, 1, 6), now());
        this.entries.pull_from(&link, peer(8), &this.db).await;
        assert_eq!(link.pulls(), [(channel(2), other.held(2).unwrap().mark, 2)]);
        assert_eq!(this.held(2).unwrap().bytes, 3 * SMALL);
        let here =
            relay::pull(&lock(&this.db), &channel(2), true, &relay::NO_MARK, 0, 100).unwrap();
        let mut revs: Vec<u64> = here.entries.iter().map(|entry| entry.rev).collect();
        revs.sort();
        assert_eq!(revs, [5, 5, 6]);

        // What it pulled waits to be passed on to the relays it works
        // with, and not back to the one it came from.
        let waiting = this.entries.to_pass_on(&this.db, &[peer(8)]);
        assert!(waiting.is_empty());

        // The other relay drops a channel and takes it again, with one
        // entry of the two: another holding, under another mark. It is
        // asked for from the start, and what is held already stays.
        let dropped = other.held(4).unwrap().mark;
        lock(&other.db)
            .execute(
                "DELETE FROM relay_channels WHERE channel_id = ?1",
                [channel(4).as_slice()],
            )
            .unwrap();
        lock(&other.db)
            .execute(
                "DELETE FROM entries WHERE channel_id = ?1",
                [channel(4).as_slice()],
            )
            .unwrap();
        other.hold(&small(4, 7, 5), now());
        let again = other.held(4).unwrap().mark;
        assert_ne!(again, dropped);
        this.entries.pull_from(&link, peer(8), &this.db).await;
        assert_eq!(link.pulls(), [(channel(4), again, 0)]);
        assert_eq!(this.held(4).unwrap().bytes, 3 * SMALL);

        // A channel that the other relay holds no more has no place kept
        // here. What this relay holds of it stays.
        lock(&other.db)
            .execute(
                "DELETE FROM relay_channels WHERE channel_id = ?1",
                [channel(5).as_slice()],
            )
            .unwrap();
        this.entries.pull_from(&link, peer(8), &this.db).await;
        assert!(link.pulls().is_empty());
        assert_eq!(lock(&this.entries.places).total(), 4);
        assert_eq!(this.held(5).unwrap().bytes, 2 * SMALL);
    }

    /// What a relay it works with says of a channel's two times is kept
    /// for a channel that this relay holds: the earlier "held since", and
    /// the later "last used". And a channel that is told of as unused for
    /// 90 days is not taken: it would be dropped at the next sweep.
    #[tokio::test]
    async fn what_a_listed_relay_tells_of_a_channel_is_kept_and_an_unused_one_is_not_taken() {
        let other = relay_of(u64::MAX, &[9]);
        let this = relay_of(u64::MAX, &[8]);
        let now = now();
        // Both hold the first channel, whole. There it is held from
        // earlier, and was used later.
        other.hold(&small(1, 1, 5), now - 9 * HOUR);
        this.hold(&small(1, 1, 5), now - 5 * HOUR);
        lock(&other.db)
            .execute(
                "UPDATE relay_channels SET used_at = ?1 WHERE channel_id = ?2",
                rusqlite::params![now - 3 * HOUR, channel(1).as_slice()],
            )
            .unwrap();
        // The second is held here from earlier, and was used here later:
        // nothing that is told changes it.
        other.hold(&small(2, 1, 5), now - 300);
        this.hold(&small(2, 1, 5), now - 7000);
        lock(&this.db)
            .execute(
                "UPDATE relay_channels SET used_at = ?1 WHERE channel_id = ?2",
                rusqlite::params![now - 30, channel(2).as_slice()],
            )
            .unwrap();
        // The third is only there, and nobody has used it for 90 days,
        // to the second. The fourth, for a second less.
        for (c, used) in [(3, now - 90 * DAY), (4, now - 90 * DAY + 60)] {
            other.hold(&small(c, 1, 5), now - 200 * DAY);
            lock(&other.db)
                .execute(
                    "UPDATE relay_channels SET used_at = ?1 WHERE channel_id = ?2",
                    rusqlite::params![used, channel(c).as_slice()],
                )
                .unwrap();
        }

        let link = Link::to(&other);
        this.entries.pull_from(&link, peer(8), &this.db).await;
        let first = this.held(1).unwrap();
        assert_eq!(
            (first.held_since, first.used_at),
            (now - 9 * HOUR, now - 3 * HOUR)
        );
        let second = this.held(2).unwrap();
        assert_eq!((second.held_since, second.used_at), (now - 7000, now - 30));
        // The unused one was not asked for, and is not held. The other
        // is, with the two times that were told.
        assert_eq!(this.held(3), None);
        let fourth = this.held(4).unwrap();
        assert_eq!(
            (fourth.held_since, fourth.used_at),
            (now - 200 * DAY, now - 90 * DAY + 60)
        );
        let asked: Vec<[u8; 32]> = link.pulls().into_iter().map(|pull| pull.0).collect();
        assert!(asked.contains(&channel(4)));
        assert!(!asked.contains(&channel(3)));

        // Later the other relay holds the first channel from an earlier
        // time still, by the word of a relay that it works with, and sees
        // it used: its key is proved there. This relay has pulled the
        // channel to its end and asks for no page of it. It is told the
        // two times with the channel, and keeps them.
        lock(&other.db)
            .execute(
                "UPDATE relay_channels SET held_since = ?1, used_at = ?2 WHERE channel_id = ?3",
                rusqlite::params![now - 20 * HOUR, now - 5, channel(1).as_slice()],
            )
            .unwrap();
        this.entries.pull_from(&link, peer(8), &this.db).await;
        assert!(link.pulls().is_empty());
        let first = this.held(1).unwrap();
        assert_eq!(
            (first.held_since, first.used_at),
            (now - 20 * HOUR, now - 5)
        );
        // What is told of a later "held since", and of an earlier "last
        // used", changes nothing.
        let second = this.held(2).unwrap();
        assert_eq!((second.held_since, second.used_at), (now - 7000, now - 30));

        // A minute on, this relay's sweep drops the fourth as unused, and
        // forgets its place in it. It is not asked for again: it is
        // unused there too, by what is told.
        this.entries.sweep_at(&this.db, now + 120);
        assert_eq!(this.held(4), None);
        assert!(
            lock(&this.entries.places)
                .get(&peer(8), &channel(4))
                .is_none()
        );
        assert!(
            this.entries
                .wants(&this.db, &peer(8), &told_of(&other, 4), now + 120)
                .is_none()
        );
        // Used there again, it is asked for from the start.
        let mut told = told_of(&other, 4);
        told.used_at = now + 100;
        assert_eq!(
            this.entries.wants(&this.db, &peer(8), &told, now + 120),
            Some((told.mark, 0))
        );
    }

    /// The channel numbered `c` as `relay` tells a relay it works with of
    /// it.
    fn told_of(relay: &Relay, c: u16) -> RelayChannel {
        relay::held_channels(&lock(&relay.db), &[0; 32], 1000)
            .unwrap()
            .iter()
            .map(RelayChannel::from)
            .find(|told| told.channel == channel(c))
            .unwrap()
    }

    /// A relay with no room does not ask for a channel that it does not
    /// hold. One with room for a part of a channel takes what fits, does
    /// not pass the page, and leaves the channel for a while before it
    /// asks again.
    #[tokio::test]
    async fn a_relay_with_no_room_asks_for_no_new_channel_and_leaves_a_page_that_did_not_fit() {
        let other = relay_of(u64::MAX, &[9]);
        for c in 1..=3 {
            other.hold(&small(c, 1, 5), NOW);
            other.hold(&small(c, 2, 5), NOW);
        }
        let link = Link::to(&other);
        let in_order = {
            let mut ids: Vec<(usize, [u8; 32])> = (1..=3).map(|c| (c, channel(c as u16))).collect();
            ids.sort_by_key(|(_, id)| *id);
            ids.into_iter().map(|(c, _)| c as u16).collect::<Vec<u16>>()
        };

        // Room for three entries: the first channel that is told of, and
        // half of the second.
        let mut this = relay_of(3 * SMALL, &[8]);
        this.entries.pull_from(&link, peer(8), &this.db).await;
        assert_eq!(this.held(in_order[0]).unwrap().bytes, 2 * SMALL);
        assert_eq!(this.held(in_order[1]).unwrap().bytes, SMALL);
        assert_eq!(this.held(in_order[2]), None);
        assert_eq!(this.used(), 3 * SMALL);
        // The third was not asked for: there was no room for the
        // smallest entry of it.
        let asked: Vec<[u8; 32]> = link.pulls().into_iter().map(|pull| pull.0).collect();
        assert_eq!(asked, [channel(in_order[0]), channel(in_order[1])]);

        // Asked again at once: the page that did not fit is not asked for
        // yet, and nothing else is.
        this.entries.pull_from(&link, peer(8), &this.db).await;
        assert!(link.pulls().is_empty());
        let place = lock(&this.entries.places)
            .get(&peer(8), &channel(in_order[1]))
            .unwrap();
        assert_eq!(place.after, 0, "a page that did not fit was passed");
        assert!(place.not_before.is_some());

        // With no wait, it is asked for again each time, from the place
        // before the page.
        this.entries.ask_again = Duration::ZERO;
        lock(&this.entries.places).forget_channels(&[channel(in_order[1])]);
        for _ in 0..2 {
            this.entries.pull_from(&link, peer(8), &this.db).await;
            let pulls = link.pulls();
            assert_eq!(pulls.len(), 1);
            assert_eq!((pulls[0].0, pulls[0].2), (channel(in_order[1]), 0));
        }
        // Nothing was dropped to make room, and nothing more is held.
        assert_eq!(this.used(), 3 * SMALL);

        // With room, the rest arrives.
        lock(&this.entries.room).max_bytes = u64::MAX;
        this.entries.pull_from(&link, peer(8), &this.db).await;
        assert_eq!(this.used(), 6 * SMALL);
    }

    /// A long channel is pulled so many pages in a pass, and gone on with
    /// in the next from the place that was reached.
    #[tokio::test]
    async fn a_long_channel_is_pulled_in_passes_of_so_many_pages() {
        let other = relay_of(u64::MAX, &[9]);
        let this = relay_of(u64::MAX, &[8]);
        assert_eq!(RELAY_ENTRY_PULL_PAGES, 10);
        // 140 entries of the largest size: 13 fit a page, so they are ten
        // pages and ten entries more.
        for d in 1..=140 {
            other.hold(&largest(1, d), NOW);
        }
        let link = Link::to(&other);
        this.entries.pull_from(&link, peer(8), &this.db).await;
        let places: Vec<u64> = link.pulls().iter().map(|pull| pull.2).collect();
        assert_eq!(places, (0..10).map(|page| page * 13).collect::<Vec<u64>>());
        assert_eq!(this.held(1).unwrap().bytes, 130 * LARGEST);

        // The next pass goes on from the 130th, to the end.
        this.entries.pull_from(&link, peer(8), &this.db).await;
        let places: Vec<u64> = link.pulls().iter().map(|pull| pull.2).collect();
        assert_eq!(places, [130]);
        assert_eq!(this.held(1).unwrap().bytes, 140 * LARGEST);
        this.entries.pull_from(&link, peer(8), &this.db).await;
        assert!(link.pulls().is_empty());
    }

    /// What a relay is handed is checked as anything it is sent is: a
    /// page that holds an entry of another channel, or one that is not
    /// signed, is not the page that was asked for, and nothing of it is
    /// taken. Nor is a list of channels that is not in the order of
    /// their IDs gone on with.
    #[tokio::test]
    async fn a_page_that_is_not_the_one_asked_for_is_not_taken() {
        let other = relay_of(u64::MAX, &[9]);
        other.hold(&small(1, 1, 5), NOW);
        other.hold(&small(2, 1, 5), NOW);

        // A page with an entry of another channel in it.
        fn with_another(answer: WireMessage) -> WireMessage {
            match answer {
                WireMessage::EntryPulled(mut page) => {
                    page.entries.push(small(77, 1, 5).to_wire().into());
                    WireMessage::EntryPulled(page)
                }
                other => other,
            }
        }
        // A page with an entry that was changed after it was signed.
        fn changed(answer: WireMessage) -> WireMessage {
            match answer {
                WireMessage::EntryPulled(mut page) => {
                    for entry in &mut page.entries {
                        let last = entry.len() - 1;
                        entry[last] ^= 1;
                    }
                    WireMessage::EntryPulled(page)
                }
                other => other,
            }
        }
        // A list with its channels the other way round.
        fn turned(answer: WireMessage) -> WireMessage {
            match answer {
                WireMessage::RelayChannelsHeld(mut held) => {
                    held.channels.reverse();
                    WireMessage::RelayChannelsHeld(held)
                }
                other => other,
            }
        }
        // Not a page at all.
        fn something_else(answer: WireMessage) -> WireMessage {
            match answer {
                WireMessage::EntryPulled(_) => WireMessage::EntryPushed(EntryPushed {
                    answers: Vec::new(),
                }),
                other => other,
            }
        }
        for (spoil, asked_for) in [
            (with_another as fn(WireMessage) -> WireMessage, 2),
            (changed, 2),
            (something_else, 2),
            // A list that is not in the order of its IDs is not the list
            // that was asked for: no channel of it is asked for at all.
            (turned, 0),
        ] {
            let this = relay_of(u64::MAX, &[8]);
            let link = Link {
                spoil: Some(spoil),
                ..Link::to(&other)
            };
            this.entries.pull_from(&link, peer(8), &this.db).await;
            assert_eq!(this.used(), 0);
            assert_eq!(this.held(77), None);
            // Each channel's page was asked for once, and none taken: a
            // page that is not taken does not end the pass.
            assert_eq!(link.pulls().len(), asked_for);
            // And no place was kept for a page that was not taken.
            assert_eq!(lock(&this.entries.places).total(), 0);
        }

        // A page that says a place no further on than the one it was
        // asked after: its entries are taken, and the channel is not
        // asked for again in this pass.
        fn stuck(answer: WireMessage) -> WireMessage {
            match answer {
                WireMessage::EntryPulled(mut page) => {
                    page.next = 0;
                    WireMessage::EntryPulled(page)
                }
                other => other,
            }
        }
        let this = relay_of(u64::MAX, &[8]);
        let link = Link {
            spoil: Some(stuck),
            ..Link::to(&other)
        };
        this.entries.pull_from(&link, peer(8), &this.db).await;
        assert_eq!(this.used(), 2 * SMALL);
        assert_eq!(
            link.pulls().len(),
            2,
            "a page that does not move on was asked for again"
        );

        // The control: with nothing spoiled, both channels arrive.
        let this = relay_of(u64::MAX, &[8]);
        this.entries
            .pull_from(&Link::to(&other), peer(8), &this.db)
            .await;
        assert_eq!(this.used(), 2 * SMALL);
    }

    /// A channel whose page is not the one asked for, cannot be stored,
    /// or is not answered, is left as it was, and the pass goes on with
    /// the next channel: the channels after it arrive all the same. It is
    /// asked for again in the next pass, from where it was.
    #[tokio::test]
    async fn a_channel_that_cannot_be_pulled_does_not_keep_the_others_waiting() {
        let other = relay_of(u64::MAX, &[9]);
        for c in 1..=5 {
            other.hold(&small(c, 1, 5), NOW);
        }
        // The channels in the order of their IDs, which is the order they
        // are told and pulled in. The one that fails is the second.
        let mut by_id: Vec<u16> = (1..=5).collect();
        by_id.sort_by_key(|c| channel(*c));
        assert_eq!(
            by_id[1], FAILS,
            "the channel that fails is the second by its ID"
        );
        const FAILS: u16 = 2;
        let arrived =
            |this: &Relay| -> Vec<u16> { (1..=5).filter(|c| this.held(*c).is_some()).collect() };
        let but_the_one: Vec<u16> = (1..=5).filter(|c| *c != FAILS).collect();

        // Its page holds an entry of another channel: not the page.
        fn not_the_page(answer: WireMessage) -> WireMessage {
            match answer {
                WireMessage::EntryPulled(mut page)
                    if page
                        .entries
                        .first()
                        .is_some_and(|entry| entry.starts_with(&channel(FAILS))) =>
                {
                    page.entries.push(small(77, 1, 5).to_wire().into());
                    WireMessage::EntryPulled(page)
                }
                other => other,
            }
        }
        // Its page is not answered.
        fn unanswered(request: &WireMessage) -> bool {
            matches!(request, WireMessage::RelayPull(pull) if pull.channel == channel(FAILS))
        }
        for link in [
            Link {
                spoil: Some(not_the_page),
                ..Link::to(&other)
            },
            Link {
                unanswered: Some(unanswered),
                ..Link::to(&other)
            },
        ] {
            let this = relay_of(u64::MAX, &[8]);
            this.entries.pull_from(&link, peer(8), &this.db).await;
            assert_eq!(arrived(&this), but_the_one);
            assert_eq!(link.pulls().len(), 5, "each channel was asked for once");
            assert_eq!(lock(&this.entries.places).total(), 4);
            // The next pass asks for that one alone, from the start, and
            // it arrives where the relay answers as it should.
            let whole = Link::to(&other);
            this.entries.pull_from(&whole, peer(8), &this.db).await;
            let mark = other.held(FAILS).unwrap().mark;
            assert_eq!(whole.pulls(), [(channel(FAILS), mark, 0)]);
            assert_eq!(arrived(&this), [1, 2, 3, 4, 5]);
        }

        // A page that cannot be stored: the store refuses it. The others
        // are stored, each in a write of its own.
        let this = relay_of(u64::MAX, &[8]);
        lock(&this.db)
            .execute_batch(&format!(
                "CREATE TRIGGER refuses BEFORE INSERT ON entries
                 WHEN NEW.channel_id = X'{}'
                 BEGIN SELECT RAISE(ABORT, 'refused'); END;",
                hex::encode(channel(FAILS))
            ))
            .unwrap();
        let link = Link::to(&other);
        this.entries.pull_from(&link, peer(8), &this.db).await;
        assert_eq!(arrived(&this), but_the_one);
        assert_eq!(link.pulls().len(), 5);
        lock(&this.db)
            .execute_batch("DROP TRIGGER refuses")
            .unwrap();
        this.entries.pull_from(&link, peer(8), &this.db).await;
        assert_eq!(arrived(&this), [1, 2, 3, 4, 5]);
    }

    /// A relay's list of channels that never ends is read for so many
    /// pages in a pass, and no more. The next pass goes on from where
    /// that one stopped, and what is remembered of the list is where it
    /// stopped: no place is kept for a channel of which nothing was
    /// handed. A list that is longer than one pass reads is read to its
    /// end over several, and then from the start again.
    #[tokio::test]
    async fn a_list_of_channels_that_never_ends_is_read_so_many_pages_at_a_time() {
        /// A relay that tells of a thousand channels more whenever it is
        /// asked, up to `ends_after` pages, and hands nothing of any.
        struct Endless {
            asked: Mutex<Vec<[u8; 32]>>,
            /// How many pages of its list it has told, and how many pages
            /// of channels it was asked for.
            pages: Mutex<usize>,
            pulls: Mutex<usize>,
            ends_after: Option<usize>,
        }
        /// The ID numbered `n`, in the order of the IDs.
        fn id(n: u64) -> [u8; 32] {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&n.to_be_bytes());
            id[31] = 1;
            id
        }
        impl Asked for Endless {
            async fn ask(&self, request: WireMessage) -> Result<WireMessage, String> {
                match request {
                    WireMessage::RelayChannelsAsk(ask) => {
                        lock(&self.asked).push(ask.after);
                        let pages = {
                            let mut pages = lock(&self.pages);
                            *pages += 1;
                            *pages
                        };
                        let from = u64::from_be_bytes(ask.after[..8].try_into().unwrap());
                        let last = self.ends_after.is_some_and(|ends| pages % ends == 0);
                        let told = if last { 10 } else { 1000 };
                        let now = now();
                        Ok(WireMessage::RelayChannelsHeld(RelayChannelsHeld {
                            channels: (1..=told)
                                .map(|n| RelayChannel {
                                    channel: id(from + n),
                                    mark: [7; 8],
                                    held_since: now,
                                    used_at: now,
                                    places: 1,
                                })
                                .collect(),
                        }))
                    }
                    WireMessage::RelayPull(pull) => {
                        *lock(&self.pulls) += 1;
                        Ok(WireMessage::EntryPulled(EntryPulled {
                            entries: Vec::new(),
                            next: 0,
                            mark: pull.mark,
                        }))
                    }
                    _ => Err("not answered".into()),
                }
            }
        }
        assert_eq!(RELAY_CHANNEL_PAGES_PER_PASS, 10);
        assert_eq!(RELAY_CHANNELS_PAGE_MAX, 1000);

        let this = relay_of(u64::MAX, &[8]);
        let endless = Endless {
            asked: Mutex::default(),
            pages: Mutex::default(),
            pulls: Mutex::default(),
            ends_after: None,
        };
        this.entries.pull_from(&endless, peer(8), &this.db).await;
        // Ten pages, each after the last ID of the one before.
        let asked = std::mem::take(&mut *lock(&endless.asked));
        assert_eq!(asked.len(), 10);
        assert_eq!(asked[0], [0u8; 32]);
        for (n, after) in asked.iter().enumerate().skip(1) {
            assert_eq!(*after, id(1000 * n as u64), "page {n}");
        }
        assert_eq!(*lock(&endless.pulls), 10_000);
        // Nothing was handed, and nothing is remembered but where the
        // pass stopped.
        assert_eq!(this.used(), 0);
        assert_eq!(lock(&this.entries.places).total(), 0);
        assert_eq!(
            lock(&this.entries.stopped_at).get(&peer(8)),
            Some(&id(10_000))
        );
        // The next pass goes on from there, for ten pages more.
        this.entries.pull_from(&endless, peer(8), &this.db).await;
        let asked = std::mem::take(&mut *lock(&endless.asked));
        assert_eq!(asked.len(), 10);
        assert_eq!(asked[0], id(10_000));
        assert_eq!(asked[9], id(19_000));
        assert_eq!(lock(&this.entries.stopped_at).len(), 1);

        // A list of 25 pages: read to its end in three passes, and the
        // fourth starts from the first channel again.
        let this = relay_of(u64::MAX, &[8]);
        let long = Endless {
            asked: Mutex::default(),
            pages: Mutex::default(),
            pulls: Mutex::default(),
            ends_after: Some(25),
        };
        let mut pages = Vec::new();
        for _ in 0..3 {
            this.entries.pull_from(&long, peer(8), &this.db).await;
            pages.push(std::mem::take(&mut *lock(&long.asked)).len());
        }
        assert_eq!(pages, [10, 10, 5]);
        assert!(lock(&this.entries.stopped_at).is_empty());
        this.entries.pull_from(&long, peer(8), &this.db).await;
        assert_eq!(lock(&long.asked)[0], [0u8; 32]);
    }

    /// One pull at a time runs from each relay.
    #[test]
    fn one_pull_at_a_time_runs_from_each_relay() {
        let relays = Mutex::new(HashSet::new());
        let first = Pulling::begin(&relays, &peer(8)).expect("the first begins");
        assert!(Pulling::begin(&relays, &peer(8)).is_none());
        // Another relay is not held up, and its pull ends here.
        assert!(Pulling::begin(&relays, &peer(9)).is_some());
        assert!(Pulling::begin(&relays, &peer(9)).is_some());
        drop(first);
        assert!(Pulling::begin(&relays, &peer(8)).is_some());
    }

    // ── Its room, when it starts and each hour ───────────────────────

    /// A relay whose cap came down drops its newest channels when it
    /// starts, until it is within the cap. Each hour it drops what nobody
    /// has used for 90 days. Its places in what it dropped are forgotten,
    /// so that a channel it takes again is pulled from the start.
    #[test]
    fn a_relay_makes_room_when_it_starts_and_sweeps_what_nobody_uses() {
        let at = relay_of(2 * SMALL, &[8]);
        // It holds three channels: more than its cap, since its cap came
        // down. It has a place in each, at a relay it works with.
        lock(&at.entries.room).max_bytes = u64::MAX;
        for (c, taken) in [(1, NOW - 300), (2, NOW - 200), (3, NOW - 100)] {
            at.hold(&small(c, 1, 5), taken);
            lock(&at.entries.places).keep(
                &peer(8),
                channel(c),
                Place {
                    mark: [7; 8],
                    after: 1,
                    not_before: None,
                },
            );
        }
        lock(&at.entries.room).max_bytes = 2 * SMALL;

        // When it starts: the newest goes, and the place in it.
        at.entries.make_room(&at.db);
        assert_eq!(at.used(), 2 * SMALL);
        assert_eq!(at.held(3), None);
        assert!(at.held(1).is_some() && at.held(2).is_some());
        assert!(
            lock(&at.entries.places)
                .get(&peer(8), &channel(3))
                .is_none()
        );
        assert_eq!(lock(&at.entries.places).total(), 2);
        // Within its cap, nothing more goes.
        at.entries.make_room(&at.db);
        assert_eq!(at.used(), 2 * SMALL);

        // The sweep: a second short of 90 days after the first was last
        // used, nothing goes. At 90 days it does, and its place.
        at.entries.sweep_at(&at.db, NOW - 300 + 90 * DAY - 1);
        assert_eq!(at.used(), 2 * SMALL);
        at.entries.sweep_at(&at.db, NOW - 300 + 90 * DAY);
        assert_eq!(at.held(1), None);
        assert!(at.held(2).is_some());
        assert_eq!(lock(&at.entries.places).total(), 1);
        assert!(
            lock(&at.entries.places)
                .get(&peer(8), &channel(2))
                .is_some()
        );
    }

    /// The room for this kind of channel is its own: what the relay holds
    /// of the older kind is not counted against it, and is never dropped
    /// to make room in it.
    #[test]
    fn the_room_for_entries_is_its_own_and_takes_none_of_the_older_kinds() {
        let at = relay_of(2 * SMALL, &[]);
        // The older kind: a channel with far more than this kind's cap.
        {
            let db = lock(&at.db);
            db.execute(
                "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id,
                                       created_at, updated_at)
                 VALUES ('old_a', 'named', 'realtime', 'open', X'00', '2026-01-01', '2026-01-01')",
                [],
            )
            .unwrap();
            let blob = vec![0x5a; 60_000];
            let item = cordelia_storage::items::NewItem::plain(
                "ci_old",
                "old_a",
                &[1; 32],
                "memory",
                "2026-01-01T00:00:00Z",
                1,
                &[2; 32],
                &[3; 64],
                &blob,
            );
            assert!(cordelia_storage::items::insert_item(&db, &item).unwrap());
        }
        let older = || cordelia_storage::items::stored_cost(&lock(&at.db)).unwrap();
        assert_eq!(older(), 60_000 + 1024);

        // This kind is taken up to its own cap, and no further.
        assert_eq!(
            pushed(at.push(
                1,
                vec![
                    small(1, 1, 5).to_wire(),
                    small(2, 1, 5).to_wire(),
                    small(3, 1, 5).to_wire()
                ]
            )),
            [
                PushAnswer::Stored,
                PushAnswer::Stored,
                PushAnswer::Refused(EntryRefused::NoRoom)
            ]
        );
        assert_eq!(at.used(), 2 * SMALL);
        // And what the relay holds of this kind is no part of what the
        // older kind's cap is set against.
        assert_eq!(older(), 60_000 + 1024);
        // Making room, and sweeping, take nothing of the older kind.
        lock(&at.entries.room).max_bytes = SMALL;
        at.entries.make_room(&at.db);
        at.entries.sweep_at(&at.db, NOW + 365 * DAY);
        assert_eq!(at.used(), 0);
        assert_eq!(older(), 60_000 + 1024);
    }
}
