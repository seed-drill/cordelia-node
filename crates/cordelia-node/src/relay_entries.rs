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
//!   connection remembers, for each author's slot, each entry that it
//!   showed whole there whose signatures held, and each it was handed
//!   whole there, up to bounds and for as long as it lasts. It may then
//!   show any of those in short: by its channel, slot, author, revision
//!   and ID. A short show of anything else is answered "show it whole"
//!   from what the connection remembers, before the store is looked at
//!   and with no lock on the database taken. One of an entry remembered is
//!   answered from the store: held, "show it whole", or the revision and
//!   ID of another. The answer to a short show never carries an entry.
//!   **Every head before "held"** (decision 2026-10-24 (removal), rule
//!   16): where the relay keeps more than one entry of that author in that
//!   slot, it takes the entry shown first, and then hands each the
//!   connection does not remember, one in each answer, the lowest number
//!   first, before it says that it holds the entry, took it, or refused
//!   it. Only a whole hand is remembered: to a short show it says the
//!   revision and ID, and the whole show that follows is handed the entry.
//! - **Prove** (§2.4 items 3 and 4). The proof is checked against the
//!   value that this connection's TLS session exports, and against the
//!   node key of the peer as its certificate says it: nothing that says
//!   who proves is taken from the message. The connection remembers each
//!   channel for which a proof held, up to a bound, for as long as it
//!   lasts, and forgets them when it closes.
//! - **Pull** (§2.4 item 3). A page of a channel, only where the channel
//!   was proved on this connection. Without that nothing is said of the
//!   channel: no entries, and the place and the mark that were asked
//!   with. A channel that was proved and is not held is answered as no
//!   holding, by the mark of none: whoever holds its key then knows that
//!   nothing it sent is there. A page for a peer that is not a relay
//!   listed by key holds at most SMALL_PAGE_BYTES of entries, and at least
//!   one, so that it fits a small message; it says there is more as a
//!   full page does (decision 2026-10-22 (memory), rule 3). A listed relay
//!   is given full pages.
//! - **Push** (§2.4 items 1 and 2). Each entry is checked and taken by the
//!   store's rule, and each is answered for.
//!
//! ## When a channel was used
//!
//! A proof that holds for a channel the relay holds, and an entry shown,
//! whole or in short, that the relay holds, are use of the channel
//! (decision 2026-10-04 §2.5). None of them writes: each is answered by
//! reading, and the use is kept in memory ([`Uses`]), with the database's
//! lock held, so that a sweep that holds it sees every use before it. The
//! uses are written in one transaction once a minute
//! (RELAY_USES_WRITE_INTERVAL_SECS), at the hourly sweep, before it reads
//! them, and at a clean stop ([`RelayEntries::write_uses`]), by the rule
//! of §16: a time more than an hour later than the one kept, never an
//! earlier one (issue #214). The same is done with when a listed relay
//! says a channel was last used.
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
//!   cannot know its room. Where the asker has no room at all, that is
//!   decided before the store is read.
//! - the entry that answers a show is handed while the asker is not yet
//!   over its bytes, and counted, so it can take the asker over by that
//!   one entry and no more: a device that is near its bytes must still
//!   hear of a removal. After that a show that would be answered with an
//!   entry is refused as "not now", with no breach, until the minute
//!   frees (§16). The answers that carry no entry are always given.
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
//! Nothing is tried again: what did not arrive is pulled. **But a head**
//! (decision 2026-10-24 (removal), rule 17): an entry with a lineage that
//! the relay keeps, beside another or alone, is offered at each offer to
//! each relay it works with that has not answered for it, connected or not
//! when the relay took it, for as long as the relay keeps it.
//!
//! A pass reads only so many pages of a relay's list, and the next goes
//! on from where it stopped: a list that never ends does not keep a
//! relay asking, and what is remembered of a list is a page of it at a
//! time. A channel whose page cannot be taken is left for the next pass,
//! and the channels after it are pulled all the same.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cordelia_core::NodeId;
use cordelia_core::load::{Answered, Kind, Refusal, Stream, StreamCounts};
use cordelia_core::lock::{LockWhole, Nested, TimedGuard, TimedLock, take_as, taking};
use cordelia_core::protocol::{
    ENTRY_OVERHEAD_BYTES, ENTRY_PAGE_MAX_BYTES, ENTRY_PAGE_MAX_ENTRIES, ENTRY_WIRE_OVERHEAD_BYTES,
    FRAME_LENGTH_BYTES, LINEAGE_HASH_BYTES, MAX_CHANGE_HEADS, MAX_CHANNELS_PROVED_ON_A_CONNECTION,
    MAX_ITEM_BYTES, MAX_SLOTS_SHOWN_ON_A_CONNECTION, MIN_ENTRY_CONTENT_BYTES,
    RELAY_CHANNEL_PAGES_PER_PASS, RELAY_CHANNELS_PAGE_MAX, RELAY_CHECKPOINT_LOG_PAGES,
    RELAY_ENTRY_PULL_PAGES, SESSION_VALUE_BYTES, SMALL_PAGE_BYTES, SMALL_WINDOWS_PULL_ENTRIES,
    entry_cost,
};
use cordelia_crypto::change_entry::{self, Lineage};
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_network::codec;
use cordelia_network::messages::{
    ChannelProve, ChannelProved, EntryPull, EntryPulled, EntryPush, EntryPushed, EntryRefused,
    EntryShow, EntryShowShort, EntryShown, Protocol, PushAnswer, RelayChannel, RelayChannelsAsk,
    RelayChannelsHeld, RelayEntry, RelayPull, RelayPush, ShowAnswer, WireMessage,
};
use cordelia_network::transport;
use cordelia_storage::relay::{self, Asker, Mark, Proof, Refused, Room, Shown, Taken, Uses};
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
fn lock<L: LockWhole + ?Sized>(mutex: &L) -> L::Guard<'_> {
    mutex.lock_whole()
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
    /// already, or there is room to remember one channel more, of the
    /// `most` that a relay remembers for a connection.
    fn has_room_for(&self, channel: &[u8; 32], most: usize) -> bool {
        self.holds(channel) || self.channels.len() < most
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

/// The entries a connection is remembered to have shown whole or been
/// handed whole in one slot: the heads a relay keeps there, and the
/// change a device follows with the heads it sets aside, which are as
/// many (decision 2026-10-24 (removal), rule 16). Fewer, and a device
/// that shows entries the relay does not keep would put out a head it was
/// handed, and be handed it again at each show.
const ENTRIES_SHOWN_IN_A_SLOT: usize = 2 * MAX_CHANGE_HEADS;

/// What a relay remembers of one connection besides: for each author's
/// slot in a channel, each entry that the connection showed whole there
/// whose two signatures held, and each that the relay handed it whole
/// there, by its revision and its ID, whatever the relay answered (decision
/// 2026-10-04 §2.4 item 5; decision 2026-10-24 (removal), rule 16).
///
/// The connection may show any of those in short, and is answered from
/// the store. A short show of anything else, a slot that is not remembered
/// included, is answered "show it whole" from here alone: so the short
/// form tells nothing, and hands nothing, to anyone who has not shown or
/// been handed that very entry whole. And the relay hands the connection no
/// entry that it remembers here: each head is handed whole once on a
/// connection.
///
/// It lives and goes as [`Proved`] does. At most
/// MAX_SLOTS_SHOWN_ON_A_CONNECTION slots are remembered: one more is not,
/// and is shown whole each time, and handed the same lowest head at each
/// show. None is put out for it. That costs only the connection that shows
/// them: a device chooses what it shows on its own connection, and shows
/// its person's channel, one slot. In a slot, at most
/// [`ENTRIES_SHOWN_IN_A_SLOT`]: one more puts out the one remembered
/// longest.
///
/// **An entry handed is remembered only once its answer is written
/// whole** (the review of the whole build, its H2): one whose answer could
/// not be written, or was dropped, is handed again at the next show on the
/// connection. Remembered before, a lost answer would have the relay say
/// "held" to the change followed with a removal never handed, and the
/// device would have leave without it.
#[derive(Debug, Default)]
pub struct ShownWhole {
    slots: Vec<ShownSlot>,
    /// The entry handed whole in the answer being made, by its slot, its
    /// revision and its ID: remembered once that answer is written.
    handing: Option<Handing>,
}

/// An entry handed whole in an answer: its slot (its channel, its slot and
/// its author), its revision and its ID.
type Handing = ([[u8; 32]; 3], (u64, [u8; 32]));

/// An author's slot in a channel, and the entries that a connection showed
/// whole there or was handed whole there.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ShownSlot {
    /// The slot: its channel, its slot and its author.
    place: [[u8; 32]; 3],
    /// Each entry, by its revision and its ID, the one remembered longest
    /// first.
    entries: Vec<(u64, [u8; 32])>,
}

impl ShownWhole {
    /// Whether `show` is of an entry that the connection showed whole in
    /// that author's slot, or was handed whole there.
    pub fn is_of(&self, show: &EntryShowShort) -> bool {
        self.slots.iter().any(|kept| {
            kept.place == [show.channel, show.slot, show.author]
                && kept.entries.contains(&(show.rev, show.id))
        })
    }

    /// The IDs of the entries that the connection showed whole, or was
    /// handed whole, in the author's slot that `place` names.
    fn known(&self, place: [[u8; 32]; 3]) -> Vec<[u8; 32]> {
        self.slots
            .iter()
            .find(|kept| kept.place == place)
            .map(|kept| kept.entries.iter().map(|(_, id)| *id).collect())
            .unwrap_or_default()
    }

    /// The connection showed `entry` whole, and both its signatures held.
    fn remember(&mut self, entry: &CheckedEntry) {
        self.remember_at(
            [entry.channel, entry.slot, entry.author],
            (entry.rev, entry.id()),
        );
    }

    /// The answer being made hands `entry` whole: it is remembered once
    /// that answer is written whole ([`Self::written`]).
    fn handing(&mut self, entry: &CheckedEntry) {
        self.handing = Some((
            [entry.channel, entry.slot, entry.author],
            (entry.rev, entry.id()),
        ));
    }

    /// What the answer just made hands, taken out: nothing is remembered
    /// of it unless it is given back to [`Self::written`].
    fn take_handing(&mut self) -> Option<Handing> {
        self.handing.take()
    }

    /// The answer that handed `handed` was written whole: the entry is
    /// remembered as handed on the connection.
    fn written(&mut self, handed: Option<Handing>) {
        if let Some((place, shown)) = handed {
            self.remember_at(place, shown);
        }
    }

    /// The connection showed the entry `shown` whole in the slot `place`,
    /// or was handed it whole there.
    fn remember_at(&mut self, place: [[u8; 32]; 3], shown: (u64, [u8; 32])) {
        if let Some(kept) = self.slots.iter_mut().find(|kept| kept.place == place) {
            if !kept.entries.contains(&shown) {
                if kept.entries.len() >= ENTRIES_SHOWN_IN_A_SLOT {
                    kept.entries.remove(0);
                }
                kept.entries.push(shown);
            }
        } else if self.slots.len() < MAX_SLOTS_SHOWN_ON_A_CONNECTION {
            self.slots.push(ShownSlot {
                place,
                entries: vec![shown],
            });
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

    /// What became of the request, as it is counted (decision 2026-10-22
    /// §1.2).
    fn counted(&self) -> Answered {
        match self {
            Answer::Message(_) => Answered::Answered,
            Answer::Over(_) => Answered::RefusedForRate,
            Answer::NotNow => Answered::NotNow,
            Answer::Nothing => Answered::NotServed,
            Answer::Stray => Answered::Stray,
        }
    }
}

/// The entries refused in an answer, for room or for the allowance of new
/// channels (decision 2026-10-22 §1.2): an entry shown, or each entry
/// pushed or passed on. One refused as not signed is neither.
fn refusals(answer: &WireMessage) -> Vec<Refusal> {
    let refused: Vec<EntryRefused> = match answer {
        WireMessage::EntryShown(EntryShown {
            answer: ShowAnswer::Refused(why),
        }) => vec![*why],
        WireMessage::EntryPushed(pushed) => pushed
            .answers
            .iter()
            .filter_map(|answer| match answer {
                PushAnswer::Refused(why) => Some(*why),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    refused
        .into_iter()
        .filter_map(|why| match why {
            EntryRefused::NoRoom => Some(Refusal::Room),
            EntryRefused::OverLimit => Some(Refusal::NewChannels),
            EntryRefused::NotSigned => None,
        })
        .collect()
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

/// A head that this relay keeps, waiting to be offered to the relays it
/// works with until each has answered for it (decision 2026-10-24
/// (removal), rule 17). Not the entry: its place and ID, by which it is
/// read from the store at each offer, so that what waits is small, and a
/// head that the relay no longer keeps is offered to nobody.
struct WaitingHead {
    /// Its channel, its slot and its author.
    place: [[u8; 32]; 3],
    /// Its ID.
    id: [u8; 32],
    /// Its revision: of more heads of one place than a relay keeps, the
    /// lowest go first.
    rev: u64,
    /// The first bytes of its statement's hash, by which a head that
    /// replaces it is known.
    statement: [u8; LINEAGE_HASH_BYTES],
    /// The relays it waits for: each that this relay works with, but the
    /// one it came from, that has not answered for it.
    to: HashSet<NodeId>,
}

/// A head by its place (its channel, its slot and its author) and its ID.
type HeadAt = ([[u8; 32]; 3], [u8; 32]);

/// Each channel's two times as this relay holds it: since when it has held
/// it, and when it was last used.
type ChannelTimes = HashMap<[u8; 32], (i64, i64)>;

/// The heads that wait to be offered, and the relays an offer of them is
/// on its way to (decision 2026-10-24 (removal), rule 17).
#[derive(Default)]
struct WaitingHeads {
    heads: Vec<WaitingHead>,
    /// The relays an offer is on its way to: none more is made to them
    /// until it ends.
    offered: HashSet<NodeId>,
}

impl WaitingHeads {
    /// The relay took `entry`, whose lineage is `lineage`, as a head: it
    /// waits for each of `to`. A head waiting at its place that it was made
    /// after is kept no more, and waits no more. Of one place, at most
    /// MAX_CHANGE_HEADS wait, the highest numbers first, as a relay keeps.
    fn took(&mut self, entry: &CheckedEntry, lineage: &Lineage, to: HashSet<NodeId>) {
        let place = [entry.channel, entry.slot, entry.author];
        let id = entry.id();
        self.heads
            .retain(|head| head.place != place || !lineage.chain.contains(&head.statement));
        if let Some(head) = self.heads.iter_mut().find(|head| head.id == id) {
            head.to.extend(to);
            return;
        }
        self.heads.push(WaitingHead {
            place,
            id,
            rev: entry.rev,
            statement: lineage.statement,
            to,
        });
        let mut of_place: Vec<(u64, [u8; 32])> = self
            .heads
            .iter()
            .filter(|head| head.place == place)
            .map(|head| (head.rev, head.id))
            .collect();
        if of_place.len() > MAX_CHANGE_HEADS {
            of_place.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            let out: Vec<[u8; 32]> = of_place[MAX_CHANGE_HEADS..]
                .iter()
                .map(|(_, id)| *id)
                .collect();
            self.heads.retain(|head| !out.contains(&head.id));
        }
    }

    /// The heads to offer `relay` now: each that waits for it, where no
    /// offer is on its way to it.
    fn to_offer(&self, relay: &NodeId) -> Vec<HeadAt> {
        if self.offered.contains(relay) {
            return Vec::new();
        }
        self.heads
            .iter()
            .filter(|head| head.to.contains(relay))
            .map(|head| (head.place, head.id))
            .collect()
    }

    /// `relay` answered for the heads named `ids`: they wait for it no
    /// more, and a head that waits for nobody goes.
    fn answered(&mut self, relay: &NodeId, ids: &[[u8; 32]]) {
        for head in self.heads.iter_mut().filter(|head| ids.contains(&head.id)) {
            head.to.remove(relay);
        }
        self.heads.retain(|head| !head.to.is_empty());
    }

    /// The heads named `ids` are kept here no more: they wait for nobody.
    fn gone(&mut self, ids: &[[u8; 32]]) {
        self.heads.retain(|head| !ids.contains(&head.id));
    }

    /// The offer on its way to `relay` ended, answered or not: what it
    /// was not answered for is offered again at the next offer.
    fn ended(&mut self, relay: &NodeId) {
        self.offered.remove(relay);
    }
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
    /// The heads it keeps, offered at each offer to each listed relay
    /// until that relay has answered for them (decision 2026-10-24
    /// (removal), rule 17). Shared with the offers on their way.
    heads: Arc<Mutex<WaitingHeads>>,
    /// Its places in the channels of the relays it pulls from.
    places: Mutex<Places>,
    /// The relays a pull is running from.
    pulling: Mutex<HashSet<NodeId>>,
    /// Where the last pass stopped in the list of each relay that tells
    /// of more channels than one pass reads: the next goes on after that
    /// ID. A relay whose list was read to its end has none.
    stopped_at: Mutex<HashMap<NodeId, [u8; 32]>>,
    /// When the channels it holds were used, as it saw them, until they
    /// are written: once a minute, at the hourly sweep, and at a clean
    /// stop. Taken with the database's lock held.
    uses: Mutex<Uses>,
    /// How long a channel that found no room here is left before it is
    /// pulled again from a listed relay.
    ask_again: Duration,
    /// The most channels whose proofs it remembers for one connection.
    most_proved: usize,
    /// What it is asked on the streams, by stream kind, and what became of
    /// each request: counted, and read by nothing it does (decision
    /// 2026-10-22 §1.2, §7.3).
    counts: Arc<StreamCounts>,
    /// Whether a checkpoint of the store is running (issue #224): a tick
    /// that finds one running does nothing, so that ticks do not queue on
    /// the lock behind a long hold.
    checkpointing: AtomicBool,
}

/// What a tick of a relay's checkpoint did (issue #224).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checkpointed {
    /// Another was still running: this one took no lock.
    Running,
    /// The relay had written fewer than RELAY_CHECKPOINT_LOG_PAGES to its
    /// log since its last whole checkpoint: nothing was written back.
    Short,
    /// The log was written back whole; the next commit starts it again.
    Whole,
    /// A reader in another process holds a part of the log (or the
    /// checkpoint failed): the rest was written back, and the next tick
    /// tries again.
    Part,
}

/// While a checkpoint runs: its relay's flag set, cleared when dropped.
struct Running<'a>(&'a AtomicBool);

impl<'a> Running<'a> {
    fn start(flag: &'a AtomicBool) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self(flag))
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Whether a node of `role` holds the entries of channels from their
/// secrets as a relay (decision 2026-10-04 §2.4): it then keeps a
/// [`RelayEntries`], and its store has SQLite's automatic checkpoint off,
/// for the relay checkpoints it on its timer (issue #224). One test for
/// both, so that no node has the one without the other.
pub fn kept_by(role: &str) -> bool {
    role == "relay"
}

impl RelayEntries {
    /// For a relay that may hold `max_bytes` of this kind of channel, and
    /// works with `relays`.
    pub fn new(max_bytes: u64, relays: RelayAddrs, ask_again: Duration) -> Self {
        Self {
            room: Mutex::new(Room::new(max_bytes)),
            relays,
            taken: Mutex::default(),
            heads: Arc::default(),
            places: Mutex::default(),
            pulling: Mutex::default(),
            stopped_at: Mutex::default(),
            uses: Mutex::default(),
            ask_again,
            most_proved: MAX_CHANNELS_PROVED_ON_A_CONNECTION,
            counts: Arc::default(),
            checkpointing: AtomicBool::new(false),
        }
    }

    /// The same relay, counting what it is asked in `counts`: the node's
    /// counters (decision 2026-10-22 §7.3).
    pub fn counting(mut self, counts: Arc<StreamCounts>) -> Self {
        self.counts = counts;
        self
    }

    /// The same relay, remembering the proofs of `most` channels for one
    /// connection, where that is fewer than a relay does.
    pub fn remembering_at_most(mut self, most: usize) -> Self {
        self.most_proved = most.min(MAX_CHANNELS_PROVED_ON_A_CONNECTION);
        self
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
    pub fn make_room(&self, db: &TimedLock<Connection>) {
        let _sweep = taking(Kind::Sweep);
        let Ok(db) = db.lock() else { return };
        let max_bytes = db.nested(Nested::Room, &self.room).max_bytes;
        match relay::make_room(&db, max_bytes) {
            Ok(dropped) => self.dropped(&dropped, "to be within the cap"),
            Err(e) => tracing::warn!(error = %e, "could not make room for entries"),
        }
    }

    /// Drop each channel that nobody has used for 90 days (decision
    /// 2026-10-04 §2.5), and forget each address that has made the relay
    /// take no channel within the hour.
    pub fn sweep(&self, db: &TimedLock<Connection>) {
        self.sweep_at(db, unix_now());
    }

    /// [`Self::sweep`], at `now`, this relay's time in seconds. The uses
    /// that the relay kept are written first, in the same hold of the
    /// lock: the sweep reads every use there was before it.
    fn sweep_at(&self, db: &TimedLock<Connection>, now: i64) {
        let _sweep = taking(Kind::Sweep);
        lock(&self.room).forget_old(now);
        let Ok(db) = db.lock() else { return };
        // A use that could not be written is in memory alone: a sweep now
        // could drop a channel in use. It waits for the next hour.
        if !self.uses_written(&db) {
            return;
        }
        match relay::sweep_unused(&db, now) {
            Ok(dropped) => self.dropped(&dropped, "unused"),
            Err(e) => tracing::warn!(error = %e, "could not sweep the channels nobody uses"),
        }
    }

    /// Write the uses of channels that the relay kept, in one transaction
    /// (issue #214): once a minute, RELAY_USES_WRITE_INTERVAL_SECS, and at
    /// a clean stop. The hourly sweep writes them as well, before it reads
    /// them.
    ///
    /// A relay that stops uncleanly loses the uses of one interval at
    /// most. That is harmless: a channel that is in use is proved again on
    /// its devices' next passes, and one that is not was last used at most
    /// an hour and a minute after the time kept (the step and the
    /// interval), which brings its drop at most that much nearer at the
    /// end of 90 days.
    pub fn write_uses(&self, db: &TimedLock<Connection>) {
        let _sweep = taking(Kind::Sweep);
        let Ok(db) = db.lock() else { return };
        self.uses_written(&db);
    }

    /// A tick of the store's checkpoint, every
    /// RELAY_CHECKPOINT_INTERVAL_SECS from when the relay starts, in a take
    /// of the lock of its own, of kind Checkpoint (issue #224). Where the
    /// relay has written RELAY_CHECKPOINT_LOG_PAGES to its log since its
    /// last whole checkpoint, the log is written back; otherwise the tick
    /// lets go at once. A relay's connection has SQLite's automatic
    /// checkpoint off, so that no push or show pays for one, and this
    /// keeps SQLite's threshold, so that a push pays for no more syncs than
    /// it did. The checkpoint is passive: where a reader in another process
    /// holds a part of the log, the rest is written back at once, and the
    /// next tick writes back what is left. A tick that finds another still
    /// running does nothing.
    pub fn checkpoint(&self, db: &TimedLock<Connection>) -> Checkpointed {
        self.checkpoint_over(db, RELAY_CHECKPOINT_LOG_PAGES)
    }

    /// [`Self::checkpoint`], once `pages` have been written to the log.
    fn checkpoint_over(&self, db: &TimedLock<Connection>, pages: u64) -> Checkpointed {
        let Some(_running) = Running::start(&self.checkpointing) else {
            return Checkpointed::Running;
        };
        let _checkpoint = taking(Kind::Checkpoint);
        let Ok(db) = db.lock() else {
            return Checkpointed::Part;
        };
        match cordelia_storage::db::log_pages_written(&db, false) {
            Ok(written) if written < pages => return Checkpointed::Short,
            Ok(_) => {}
            // Not known: the log is written back, as where it is long.
            Err(e) => tracing::warn!(error = %e, "could not read the pages written to the log"),
        }
        if Self::checkpointed_with(&db, cordelia_storage::db::checkpoint_passive) {
            Checkpointed::Whole
        } else {
            Checkpointed::Part
        }
    }

    /// At a clean stop, once no stream asks: the log is written back whole
    /// and its file truncated, waiting for a reader up to the connection's
    /// busy timeout, as kind Checkpoint (issue #224). It waits for a tick
    /// that is running, on the lock.
    pub fn checkpoint_at_stop(&self, db: &TimedLock<Connection>) -> bool {
        let _checkpoint = taking(Kind::Checkpoint);
        let Ok(db) = db.lock() else { return false };
        Self::checkpointed_with(&db, cordelia_storage::db::checkpoint_truncating)
    }

    /// Whether `checkpoint` wrote the log back whole; where it did, the
    /// count of the pages written to it starts again.
    fn checkpointed_with(
        db: &Connection,
        checkpoint: fn(&Connection) -> Result<bool, cordelia_storage::StorageError>,
    ) -> bool {
        match checkpoint(db) {
            Ok(true) => {
                if let Err(e) = cordelia_storage::db::log_pages_written(db, true) {
                    tracing::warn!(error = %e, "could not clear the pages written to the log");
                }
                true
            }
            Ok(false) => {
                tracing::debug!("a reader holds a part of the log: the next checkpoint writes it");
                false
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not checkpoint the store's log");
                false
            }
        }
    }

    /// [`Self::write_uses`], with the database's lock held: whether every
    /// use kept was written. What could not be written is kept, for the
    /// next time.
    fn uses_written(&self, db: &TimedGuard<'_, Connection>) -> bool {
        let mut uses = db.nested(Nested::Uses, &self.uses);
        let kept = uses.len();
        match relay::write_uses(db, &mut uses) {
            Ok(written) => {
                if kept > 0 {
                    tracing::debug!(kept, written, "wrote when channels of entries were used");
                }
                true
            }
            Err(e) => {
                tracing::warn!(error = %e, kept, "could not write when channels were used");
                false
            }
        }
    }

    /// The relay saw `channel` used at `at` (decision 2026-10-04 §2.5): it
    /// is kept, with the database's lock held, until it is written.
    fn used(&self, db: &TimedGuard<'_, Connection>, channel: &[u8; 32], at: i64) {
        db.nested(Nested::Uses, &self.uses).used(channel, at);
    }

    /// Drop each slot in which every entry is a delete that the relay has
    /// held for 90 days (decision 2026-10-04 §2.3, §7.3): the channel's
    /// count of its room follows, and a channel of which nothing is left
    /// is held no more.
    pub fn sweep_deletes(&self, db: &TimedLock<Connection>) {
        self.sweep_deletes_at(db, unix_now());
    }

    /// [`Self::sweep_deletes`], at `now`, this relay's time in seconds.
    fn sweep_deletes_at(&self, db: &TimedLock<Connection>, now: i64) {
        let _sweep = taking(Kind::Sweep);
        let Ok(db) = db.lock() else { return };
        match relay::sweep_deletes(&db, now) {
            Ok(swept) => {
                if swept.entries > 0 {
                    tracing::info!(
                        entries = swept.entries,
                        "swept the deletes that this relay has held for 90 days"
                    );
                }
                self.dropped(&swept.channels, "nothing left once its old deletes went");
            }
            Err(e) => tracing::warn!(error = %e, "could not sweep old deletes"),
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
        db: &TimedLock<Connection>,
        rates: &Mutex<Rates>,
        now: i64,
    ) -> Answer {
        // Each take of the lock in it is of the request's kind (decision
        // 2026-10-22 §1.1, rule 4).
        let _kind = taking(
            protocol
                .counted_as(Some(request))
                .map_or(Kind::Other, Stream::kind),
        );
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
                self.asked_by_a_relay(db, who, request, now)
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
        db: &TimedLock<Connection>,
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
        // entry in short, and is handed nothing it knows of its slot.
        whole.remember(&entry);
        let known = whole.known([entry.channel, entry.slot, entry.author]);
        let showing = {
            let Ok(db) = db.lock() else {
                return Answer::Nothing;
            };
            let showing = {
                let mut room = db.nested(Nested::Room, &self.room);
                relay::show_handing(&db, &mut room, &entry, &who.asker(), now, &known)
            };
            let showing = match showing {
                Ok(showing) => showing,
                Err(e) => {
                    tracing::warn!(peer = %who.peer, error = %e, "could not answer an entry shown");
                    return Answer::Nothing;
                }
            };
            let found = &showing.answer;
            // An entry held, and not taken now: use of its channel, kept
            // and not written.
            if showing.holds && !showing.stored {
                self.used(&db, &entry.channel, now);
            }
            // The entry that goes back counts against the asker's limits
            // as anything fetched does. It goes back while neither
            // allowance is over already, also where it takes the asker
            // over: this is how a change reaches a device. An asker that
            // is over is told "not now", and that is no breach: whoever
            // shows an earlier entry again and again is handed one entry
            // beyond its bytes for the minute, and no more.
            let mut not_now = false;
            if !who.listed
                && let Shown::Another { cost, .. } = &found
            {
                let mut rates = db.nested(Nested::Rates, rates);
                if rates.fetch_room(who.peer, who.address) == 0 {
                    not_now = true;
                } else {
                    rates.answered(who.peer, who.address, *cost);
                }
            }
            (showing, not_now)
        };
        let (showing, not_now) = showing;
        // What was stored is passed on, whatever the answer hands, and
        // also where the asker is told "not now": it is stored all the
        // same, and a later show of it is answered "held", which passes
        // nothing on (decision 2026-10-24 (removal), rule 17).
        if showing.stored {
            self.took(std::iter::once(&entry), who.listed.then_some(who.peer));
        }
        if not_now {
            return Answer::NotNow;
        }
        // An entry handed whole is not handed again on this connection
        // (decision 2026-10-24 (removal), rule 16), once the answer that
        // hands it is written whole ([`ShownWhole::written`]).
        if let Shown::Another { entry, .. } = &showing.answer {
            whole.handing(entry);
        }
        Answer::of(WireMessage::EntryShown(EntryShown {
            answer: (&showing.answer).into(),
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
        db: &TimedLock<Connection>,
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
        let place = [show.channel, show.slot, show.author];
        let known = whole.known(place);
        let found = {
            let Ok(db) = db.lock() else {
                return Answer::Nothing;
            };
            let found = relay::show_short_handing(
                &db,
                (&show.channel, &show.slot, &show.author),
                show.rev,
                &show.id,
                &known,
            );
            // An entry held: use of its channel, kept and not written.
            if matches!(found, Ok((_, true))) {
                self.used(&db, &show.channel, now);
            }
            found
        };
        match found {
            Ok((found, _)) => Answer::of(WireMessage::EntryShown(EntryShown {
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
        db: &TimedLock<Connection>,
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
        if !proved.has_room_for(&prove.channel, self.most_proved) {
            return no;
        }
        // The signature, before the channel is looked up and before the
        // database is held, and only here: what the store is given is a
        // proof that was checked, and it does not check it again.
        let Some(checked) = relay::check_proof(
            &prove.channel,
            &session.value,
            &session.prover,
            &prove.proof,
        ) else {
            return no;
        };
        // A read: the use of a channel held is kept, and not written.
        let found = {
            let Ok(db) = db.lock() else {
                return Answer::Nothing;
            };
            let found = relay::prove(&db, &checked);
            if matches!(found, Ok(Proof::Holds { channel_held: true })) {
                self.used(&db, checked.channel(), now);
            }
            found
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
    ///
    /// **A refusal for the asker's bytes is decided first.** Where its
    /// allowance has not room for the smallest thing an entry is counted
    /// at, nothing could be handed: the pull is refused before the
    /// database is waited for, and the store is not read.
    ///
    /// **A page leaves room for the answer to a show** (§16): it is sized
    /// to what the key's allowance and the address's have room for beside
    /// one entry of the largest size, and is refused where it would use
    /// that room. So a device that pulls all it may in a minute, or
    /// shares its address with one that does, is still handed the entry
    /// that tells it of a removal.
    fn pulling(
        &self,
        db: &TimedLock<Connection>,
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
        // What the peer's allowance has room for, where it is handed
        // anything, beside the room that is left for the answer to a
        // show: a relay the operator lists is not limited, and a channel
        // that was not proved is not handed.
        let room = (proved && !who.listed).then(|| lock(rates).pull_room(who.peer, who.address));
        // With no room for even the smallest entry, the answer is known
        // before the store is asked.
        if room.is_some_and(|room| room < entry_cost(MIN_ENTRY_CONTENT_BYTES)) {
            return Answer::NotNow;
        }
        let Ok(db) = db.lock() else {
            return Answer::Nothing;
        };
        let limit = room.map_or(pull.limit, |room| page_limit(pull.limit, room));
        // A page for a peer that is not a relay listed by key is a small
        // one (decision 2026-10-22 (memory), rule 3): it holds at most
        // SMALL_PAGE_BYTES of entries, so that it fits a small message, and
        // says there is more as a full page does. A listed relay is given
        // full pages (rule 7); where its own end of the connection does not
        // carry the listed settings, it asks for fewer (rule 12).
        let most_bytes = match who.listed {
            true => ENTRY_PAGE_MAX_BYTES,
            false => SMALL_PAGE_BYTES,
        };
        let page = relay::pull(
            &db,
            &pull.channel,
            proved,
            &pull.mark,
            pull.after,
            limit,
            most_bytes,
        );
        let page = match page {
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
        if room.is_some()
            && !db
                .nested(Nested::Rates, rates)
                .handed(who.peer, who.address, page.cost)
        {
            return Answer::NotNow;
        }
        Answer::of(WireMessage::EntryPulled((&page).into()))
    }

    /// Take the entries that a peer pushes (decision 2026-10-04 §2.4
    /// items 1 and 2), and answer for each.
    fn pushing(
        &self,
        db: &TimedLock<Connection>,
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
        db: &TimedLock<Connection>,
        entries: impl Iterator<Item = (&'a Result<CheckedEntry, Refused>, &'a Asker)>,
        from: Option<&NodeId>,
        now: i64,
    ) -> Option<Vec<Taken>> {
        let (all, stored) = {
            let db = db.lock().ok()?;
            let mut room = db.nested(Nested::Room, &self.room);
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
    ///
    /// **A head waits until it is taken** (decision 2026-10-24 (removal),
    /// rule 17). An entry with a lineage, which the relay keeps as a head,
    /// beside another or alone, is offered at each offer to each relay it
    /// works with, but the one it came from, until that relay has answered
    /// for it: connected or not when this relay took it. Any other entry is
    /// passed on once, to the relays connected then, as before: what did
    /// not arrive is pulled.
    fn took<'a>(&self, entries: impl Iterator<Item = &'a CheckedEntry>, from: Option<&NodeId>) {
        let listed = self.listed();
        if listed.is_empty() {
            return;
        }
        let to: HashSet<NodeId> = listed
            .into_iter()
            .filter(|relay| Some(relay) != from)
            .collect();
        for entry in entries {
            match change_entry::lineage(&entry.content).ok().flatten() {
                Some(lineage) => lock(&*self.heads).took(entry, &lineage, to.clone()),
                None => lock(&self.taken).push(TakenEntry {
                    bytes: entry.to_wire(),
                    channel: entry.channel,
                    from: from.cloned(),
                }),
            }
        }
    }

    // ── Between relays that work together ──────────────────────────────

    /// Answer a relay that the operator lists (decision 2026-10-04 §2.4
    /// item 6). The caller has made sure that `from` is one.
    fn asked_by_a_relay(
        &self,
        db: &TimedLock<Connection>,
        who: &Who,
        request: &WireMessage,
        now: i64,
    ) -> Answer {
        let from = who.peer;
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
            // was proved, and a full one, as for any listed relay
            // (decision 2026-10-22 (memory), rule 7). The asker bounds it
            // by its limit where its own end does not carry the listed
            // settings (rule 12): the windows a page crosses are the
            // asker's, and this end cannot see them.
            WireMessage::RelayPull(pull) => {
                let Ok(db) = db.lock() else {
                    return Answer::Nothing;
                };
                let page = relay::pull(
                    &db,
                    &pull.channel,
                    true,
                    &pull.mark,
                    pull.after,
                    pull.limit,
                    ENTRY_PAGE_MAX_BYTES,
                );
                match page {
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
        db: &TimedLock<Connection>,
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
            // When it was last used is kept with this relay's own uses,
            // and written with them: never later than this relay's clock.
            if told.used_at > held.used_at {
                self.used(&db, &told.channel, told.used_at.min(now));
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
            if used.saturating_add(smallest) > db.nested(Nested::Room, &self.room).max_bytes {
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
        db: &TimedLock<Connection>,
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
    /// with the two times of its channel as this relay holds it, a small
    /// page's worth to a message. Nothing waits afterwards of what was
    /// passed on once.
    ///
    /// **And each head that waits for a relay of them** (decision
    /// 2026-10-24 (removal), rule 17), read from the store: a head the
    /// relay no longer keeps waits no more, and is offered to nobody. A
    /// relay that heads are offered to is offered none more until that
    /// offer ends ([`Self::heads_answered`], [`Self::offer_ended`]): what
    /// it did not answer for is offered again at the next offer.
    ///
    /// A small page, not a full one (decision 2026-10-22 (memory), rule
    /// 12): a push crosses the other relay's receive windows, which this
    /// end cannot see. A listed relay whose connection came from another
    /// address than the one it is configured at has every peer's windows
    /// at its end, at which a message of 896 KiB fails the stream timeout
    /// past a round trip of about 0.33 s.
    fn to_pass_on(
        &self,
        db: &TimedLock<Connection>,
        relays: &[NodeId],
    ) -> Vec<(NodeId, Vec<RelayPush>)> {
        let taken = std::mem::take(&mut *lock(&self.taken));
        let offers: Vec<(NodeId, Vec<HeadAt>)> = {
            let heads = lock(&*self.heads);
            relays
                .iter()
                .map(|relay| (relay.clone(), heads.to_offer(relay)))
                .filter(|(_, heads)| !heads.is_empty())
                .collect()
        };
        if (taken.is_empty() && offers.is_empty()) || relays.is_empty() {
            return Vec::new();
        }
        // Each head that is offered, as it is kept: at most a page of them
        // to each relay at an offer (ENTRY_PAGE_MAX_BYTES), the ones that
        // waited longest first, read MAX_CHANGE_HEADS at a time with the
        // lock taken for each (the review of the whole build, its M1).
        // What is not offered now waits for the next offer, in its place.
        // So an offer holds no more than a page for each relay, however
        // many heads wait, and no read of them holds the lock for long.
        let mut kept: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        let mut gone: Vec<[u8; 32]> = Vec::new();
        let mut paged: Vec<(NodeId, Vec<HeadAt>)> = Vec::new();
        for (relay, heads) in offers {
            let mut page: Vec<HeadAt> = Vec::new();
            let mut bytes = 0usize;
            let mut full = false;
            for batch in heads.chunks(MAX_CHANGE_HEADS) {
                {
                    let Ok(db) = db.lock() else {
                        return Vec::new();
                    };
                    for (place, id) in batch {
                        if kept.contains_key(id) || gone.contains(id) {
                            continue;
                        }
                        match relay::kept_entry(&db, (&place[0], &place[1], &place[2]), id) {
                            Ok(Some(entry)) => {
                                kept.insert(*id, entry.to_wire());
                            }
                            Ok(None) => gone.push(*id),
                            Err(e) => {
                                tracing::debug!(error = %e, "could not read a head to offer");
                            }
                        }
                    }
                }
                for head in batch {
                    let Some(entry) = kept.get(&head.1) else {
                        continue;
                    };
                    if !page.is_empty() && bytes + entry.len() > ENTRY_PAGE_MAX_BYTES {
                        full = true;
                        break;
                    }
                    bytes += entry.len();
                    page.push(*head);
                }
                if full {
                    break;
                }
            }
            if !page.is_empty() {
                paged.push((relay, page));
            }
        }
        lock(&*self.heads).gone(&gone);
        // A head read and not offered to any relay now is not held.
        kept.retain(|id, _| {
            paged
                .iter()
                .any(|(_, page)| page.iter().any(|head| head.1 == *id))
        });
        let offers = paged;
        // The two times of each channel. An entry of a channel that was
        // dropped since is passed on to nobody.
        let times: ChannelTimes = {
            let Ok(db) = db.lock() else {
                return Vec::new();
            };
            let channels: HashSet<[u8; 32]> = taken
                .iter()
                .map(|taken| taken.channel)
                .chain(
                    offers
                        .iter()
                        .flat_map(|(_, heads)| heads.iter().map(|(place, _)| place[0])),
                )
                .collect();
            channels
                .into_iter()
                .filter_map(|channel| {
                    let held = relay::held_channel(&db, &channel).ok()??;
                    Some((channel, (held.held_since, held.used_at)))
                })
                .collect()
        };
        let passed: Vec<(NodeId, Vec<RelayPush>)> = relays
            .iter()
            .filter_map(|relay| {
                let heads = offers
                    .iter()
                    .find(|(to, _)| to == relay)
                    .map(|(_, heads)| heads.as_slice())
                    .unwrap_or_default();
                let entries = taken
                    .iter()
                    .filter(|taken| taken.from.as_ref() != Some(relay))
                    .map(|taken| (&taken.bytes, taken.channel))
                    .chain(
                        heads
                            .iter()
                            .filter_map(|(place, id)| kept.get(id).map(|bytes| (bytes, place[0]))),
                    );
                let mut messages: Vec<RelayPush> = Vec::new();
                let mut bytes = 0;
                for (entry, channel) in entries {
                    let Some((held_since, used_at)) = times.get(&channel) else {
                        continue;
                    };
                    let full = messages.last().is_none_or(|message| {
                        message.entries.len() >= ENTRY_PAGE_MAX_ENTRIES as usize
                            || bytes + entry.len() > SMALL_PAGE_BYTES
                    });
                    if full {
                        messages.push(RelayPush {
                            entries: Vec::new(),
                        });
                        bytes = 0;
                    }
                    bytes += entry.len();
                    if let Some(message) = messages.last_mut() {
                        message.entries.push(RelayEntry {
                            entry: entry.clone(),
                            held_since: *held_since,
                            used_at: *used_at,
                        });
                    }
                }
                (!messages.is_empty()).then(|| (relay.clone(), messages))
            })
            .collect();
        // An offer of heads is on its way to each relay that has one.
        let mut heads = lock(&*self.heads);
        for (relay, _) in offers {
            if passed.iter().any(|(to, _)| *to == relay) {
                heads.offered.insert(relay);
            }
        }
        passed
    }

    /// `relay` answered for each entry of `message`, which was passed on
    /// to it: a head among them waits for it no more (decision 2026-10-24
    /// (removal), rule 17).
    fn heads_answered(heads: &Mutex<WaitingHeads>, relay: &NodeId, message: &RelayPush) {
        let ids: Vec<[u8; 32]> = message
            .entries
            .iter()
            .filter_map(|passed| Entry::from_wire(&passed.entry).ok())
            .map(|entry| entry.id())
            .collect();
        lock(heads).answered(relay, &ids);
    }

    /// The offer on its way to `relay` ended: what it did not answer for
    /// is offered again at the next offer.
    fn offer_ended(heads: &Mutex<WaitingHeads>, relay: &NodeId) {
        lock(heads).ended(relay);
    }
}

/// A relay that the operator lists, as this relay asks it: one request on
/// a stream between relays that work together, and its answer.
pub trait Asked {
    fn ask(
        &self,
        request: WireMessage,
    ) -> impl std::future::Future<Output = Result<WireMessage, String>> + Send;

    /// Whether this end of the connection has every peer's windows: it
    /// does not carry the listed settings (decision 2026-10-22 (memory),
    /// rule 12), as where the listed relay dialled from another address
    /// than the one configured. Then a full page would cross this end's
    /// windows a stream window at a time, and is not asked for.
    fn small_windows(&self) -> bool;
}

/// A listed relay's connection, as this relay asks it, and whether this
/// end of it has every peer's windows.
pub struct RelayLink {
    pub conn: quinn::Connection,
    pub small_windows: bool,
}

impl Asked for RelayLink {
    async fn ask(&self, request: WireMessage) -> Result<WireMessage, String> {
        ask(&self.conn, Protocol::RelayEntries, &request).await
    }

    fn small_windows(&self) -> bool {
        self.small_windows
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
    /// The connection, whose session a proof is checked against. None in
    /// a test over streams in memory: no proof holds there.
    pub conn: Option<&'a quinn::Connection>,
    pub peer: &'a NodeId,
    pub address: IpAddr,
    pub db: &'a TimedLock<Connection>,
    pub rates: &'a Mutex<Rates>,
    /// The large permits, under which a frame longer than a small message
    /// from a peer that is not a listed relay is read (decision
    /// 2026-10-22 (memory), rule 2). `None` in a test that does not
    /// exercise them.
    pub permits: Option<&'a crate::p2p::LargePermits>,
}

/// An end of a stream that can be refused with a code: a QUIC stream's is
/// reset or stopped. A stream in memory, as the tests use, has nothing to
/// refuse.
pub trait Refuse {
    fn refuse(&mut self, code: quinn::VarInt);
}

impl Refuse for quinn::SendStream {
    fn refuse(&mut self, code: quinn::VarInt) {
        let _ = self.reset(code);
    }
}

impl Refuse for quinn::RecvStream {
    fn refuse(&mut self, code: quinn::VarInt) {
        let _ = self.stop(code);
    }
}

#[cfg(test)]
impl Refuse for tokio::io::DuplexStream {
    fn refuse(&mut self, _code: quinn::VarInt) {}
}

impl RelayEntries {
    /// Serve one stream of `protocol`: one of the four streams of
    /// entries, or the one between relays that work together. `proved` is
    /// what this connection has proved, and `whole` what it has shown
    /// whole.
    ///
    /// Returns the breach where the request was over a limit: the stream
    /// was refused, and the caller cuts the peer off where it says so.
    ///
    /// Through the write of its answer, which a peer that does not read
    /// can make wait up to STREAM_TIMEOUT_SECS, it holds the answer as it
    /// is written and nothing else: the frame of the request, the request
    /// and the answer as a message are dropped before it
    /// (parameter-rationale.md §1).
    pub async fn serve<W, R>(
        &self,
        protocol: Protocol,
        send: &mut W,
        recv: &mut R,
        serving: &Serving<'_>,
        proved: &mut Proved,
        whole: &mut ShownWhole,
    ) -> Option<OverLimit>
    where
        W: tokio::io::AsyncWrite + Unpin + codec::GiveUp + Refuse,
        R: tokio::io::AsyncRead + Unpin + Refuse,
    {
        let who = Who {
            peer: serving.peer,
            address: serving.address,
            // By the key in the peer's certificate: the connection is
            // known by that key.
            listed: self.lists(serving.peer),
        };
        // The frame as its bytes: what is no request is counted by them. A
        // frame longer than a small message from a peer that is not a
        // listed relay is read only under a large permit (decision
        // 2026-10-22 (memory), rule 2); the permit is held through the
        // write of the answer and let go when the stream is done. A listed
        // relay's frame is read at once (rule 7).
        let (frame, _permit) = match crate::p2p::read_under_permit(
            recv,
            serving.permits,
            who.address,
            who.listed,
        )
        .await
        {
            crate::p2p::Framed::Frame(frame, permit) => (frame, permit),
            crate::p2p::Framed::LargeLater => {
                tracing::debug!(peer = %who.peer, ?protocol, "a request for entries over a small message, and no permit for now; refused");
                // Counted as a request of its stream's first kind, of
                // which its length alone was read, refused to be sent
                // again later (decision 2026-10-22 §1.2).
                let stream = protocol.counted_as(None);
                self.count_read(stream, FRAME_LENGTH_BYTES);
                self.count_answered(stream, Answered::LargeLater);
                crate::p2p::refuse_large_later(send, recv);
                return None;
            }
            crate::p2p::Framed::Ended => {
                tracing::debug!(peer = %who.peer, "failed to read a request for entries");
                return None;
            }
        };
        let request = match codec::decode_message(protocol, &frame) {
            Ok(request) => request,
            Err(e) => {
                tracing::debug!(peer = %who.peer, error = %e, "a frame on a stream of entries that is no message");
                // Counted as a request of its stream's first kind.
                let stream = protocol.counted_as(None);
                self.count_read(stream, FRAME_LENGTH_BYTES + frame.len());
                self.count_answered(stream, Answered::Stray);
                return Self::no_request(send, recv, &who, serving.rates, &frame);
            }
        };
        // Counted as it is read, by its kind, with the bytes of its frame
        // and its length (decision 2026-10-22 §1.2): before its answer is
        // made, which may wait for the lock.
        let stream = protocol.counted_as(Some(&request));
        self.count_read(stream, FRAME_LENGTH_BYTES + frame.len());
        // What a proof is checked against is this connection's own: the
        // value of its TLS session, and the key in the peer's certificate.
        let session = (protocol == Protocol::ChannelProve)
            .then(|| serving.conn.and_then(Session::of))
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
        // What the answer hands is remembered only once it is written
        // whole: an answer not made, or not written, hands nothing.
        let handed = whole.take_handing();
        // The answer is made, and needs nothing more of the request, which
        // is large where its answer is small (a push of a page of
        // entries), nor of its frame, which a pull may pad to a message
        // with fields that are not read.
        drop(request);
        // What became of it, where it is not answered; an answer is
        // counted once it is written.
        if !matches!(answer, Answer::Message(_)) {
            self.count_answered(stream, answer.counted());
        }
        let answer = match answer {
            Answer::Message(answer) => answer,
            Answer::Over(over) => {
                tracing::warn!(peer = %who.peer, ?protocol, cut_off = over.cut_off, "a request for entries over the byte allowance; refused");
                let code = quinn::VarInt::from_u32(cordelia_core::protocol::ERR_RATE_LIMIT);
                send.refuse(code);
                recv.refuse(code);
                return Some(over);
            }
            Answer::NotNow => {
                tracing::debug!(peer = %who.peer, ?protocol, "a pull for more than the peer may be handed for now; refused, and no breach");
                let code = quinn::VarInt::from_u32(cordelia_core::protocol::ERR_RATE_LIMIT);
                send.refuse(code);
                recv.refuse(code);
                return None;
            }
            Answer::Nothing => return None,
            Answer::Stray => {
                tracing::debug!(peer = %who.peer, ?protocol, "a request that is not for this stream");
                return Self::no_request(send, recv, &who, serving.rates, &frame);
            }
        };
        drop(frame);
        if let Some(stream) = stream {
            for why in refusals(&answer) {
                self.counts.refused(stream, why);
            }
        }
        // The answer is encoded, and the message dropped, before the write:
        // what is held through it is the answer as it is written.
        let written = codec::encode_message(&answer);
        drop(answer);
        // Answered once its answer is written, with the bytes of its frame;
        // one whose answer could not be written was not served: nothing
        // was said (decision 2026-10-22 §1.2).
        let wrote = match written {
            Ok(written) => codec::write_raw_frame(send, &written)
                .await
                .is_ok()
                .then_some(written.len()),
            Err(_) => None,
        };
        if wrote.is_some() {
            whole.written(handed);
        }
        match (wrote, stream) {
            (Some(bytes), Some(stream)) => {
                self.counts.wrote(stream, FRAME_LENGTH_BYTES + bytes);
                self.counts.answered(stream, Answered::Answered);
            }
            (None, stream) => self.count_answered(stream, Answered::NotServed),
            (Some(_), None) => {}
        }
        None
    }

    /// A request of `stream` was read, in `bytes` with its frame's length
    /// (decision 2026-10-22 §1.2). Nothing is counted of a stream that is
    /// not one of entries.
    fn count_read(&self, stream: Option<Stream>, bytes: usize) {
        if let Some(stream) = stream {
            self.counts.read(stream, bytes);
        }
    }

    /// What became of a request of `stream` (decision 2026-10-22 §1.2).
    fn count_answered(&self, stream: Option<Stream>, answered: Answered) {
        if let Some(stream) = stream {
            self.counts.answered(stream, answered);
        }
    }

    /// A frame that was read and is no request for its stream: bytes that
    /// decode as no message, a request of another stream, or one on the
    /// stream between relays from a peer that is not listed. Nothing is
    /// answered. Its bytes count as pushed, and where they are over what
    /// the peer may push the stream is refused: returns the breach.
    fn no_request(
        send: &mut impl Refuse,
        recv: &mut impl Refuse,
        who: &Who,
        rates: &Mutex<Rates>,
        frame: &[u8],
    ) -> Option<OverLimit> {
        let over = Self::counted_as_pushed(rates, who, frame)?;
        let code = quinn::VarInt::from_u32(cordelia_core::protocol::ERR_RATE_LIMIT);
        send.refuse(code);
        recv.refuse(code);
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
    /// is not tried again, but for a head: it pulls what it lacks. A head
    /// is offered again at the next offer until the relay has answered for
    /// it (decision 2026-10-24 (removal), rule 17).
    pub fn pass_on(&self, db: &TimedLock<Connection>, relays: Vec<(NodeId, quinn::Connection)>) {
        let _relays = taking(Kind::Relays);
        let keys: Vec<NodeId> = relays.iter().map(|(relay, _)| relay.clone()).collect();
        for (relay, messages) in self.to_pass_on(db, &keys) {
            let Some((_, conn)) = relays.iter().find(|(key, _)| *key == relay) else {
                Self::offer_ended(&self.heads, &relay);
                continue;
            };
            let conn = conn.clone();
            let heads = self.heads.clone();
            tokio::spawn(async move {
                for message in messages {
                    let entries = message.entries.len();
                    let answered = ask(
                        &conn,
                        Protocol::RelayEntries,
                        &WireMessage::RelayPush(message.clone()),
                    )
                    .await;
                    match answered {
                        Ok(WireMessage::EntryPushed(pushed)) if pushed.answers.len() == entries => {
                            Self::heads_answered(&heads, &relay, &message);
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
                Self::offer_ended(&heads, &relay);
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
    pub async fn pull_from(&self, link: &impl Asked, relay: NodeId, db: &TimedLock<Connection>) {
        // Each take of the lock in it is of the stream between relays
        // (decision 2026-10-22 §1.1, rule 4).
        take_as(Kind::Relays, self.pulling_from(link, relay, db)).await
    }

    /// [`Self::pull_from`], whose takes of the lock are said as its own.
    async fn pulling_from(&self, link: &impl Asked, relay: NodeId, db: &TimedLock<Connection>) {
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
        db: &TimedLock<Connection>,
        told: &RelayChannel,
    ) -> Result<usize, String> {
        let Some((mut mark, mut after)) = self.wants(db, relay, told, unix_now()) else {
            return Ok(0);
        };
        let mut stored = 0;
        // A receive window bounds what the other end may send, so it is
        // this end's windows that a page crosses (decision 2026-10-22
        // (memory), rule 12). Where they are every peer's, the page asked
        // for is a small page at worst, whatever its entries' sizes: the
        // relay that serves it cannot see this end's windows.
        let limit = if link.small_windows() {
            SMALL_WINDOWS_PULL_ENTRIES
        } else {
            ENTRY_PAGE_MAX_ENTRIES
        };
        for _ in 0..RELAY_ENTRY_PULL_PAGES {
            let asked = WireMessage::RelayPull(RelayPull {
                channel: told.channel,
                mark,
                after,
                limit,
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

/// The listed relays that are connected, each with its connection as this
/// relay asks it: whether this end of it carries the listed settings
/// (decision 2026-10-22 (memory), rule 12) decides the pages it asks for.
pub fn listed_links(
    entries: &RelayEntries,
    conn_mgr: &cordelia_network::connection::ConnectionManager,
) -> Vec<(NodeId, RelayLink)> {
    listed_and_connected(entries, conn_mgr)
        .into_iter()
        .map(|(relay, conn)| {
            let small_windows = !conn_mgr.carries_listed_settings(&relay);
            (
                relay,
                RelayLink {
                    conn,
                    small_windows,
                },
            )
        })
        .collect()
}

/// Run `entries.pull_from` for each of `relays`, each in a task of its own.
pub fn pull_from_each(
    entries: &Arc<RelayEntries>,
    state: &actix_web::web::Data<cordelia_api::state::AppState>,
    relays: Vec<(NodeId, RelayLink)>,
) {
    for (relay, link) in relays {
        let (entries, state) = (entries.clone(), state.clone());
        tokio::spawn(async move {
            entries.pull_from(&link, relay, &state.db).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordelia_core::protocol::{
        BAN_THRESHOLD, MAX_CONNECTIONS_PER_IP, MAX_ENTRY_NAME_AND_VALUE_BYTES,
        NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR, PUSH_BYTES_PER_PEER_PER_MINUTE,
        SMALL_MESSAGE_BYTES,
    };
    use cordelia_crypto::derive;
    use cordelia_crypto::entry::{Entry, Inside, Value};
    use cordelia_crypto::identity::NodeIdentity;
    use cordelia_crypto::proof;
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
        db: TimedLock<Connection>,
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
            db: TimedLock::new(cordelia_storage::db::open_in_memory().unwrap()),
            rates: Mutex::new(Rates::default()),
        }
    }

    /// A relay with room for everything, that lists nobody by key.
    fn relay() -> Relay {
        relay_of(u64::MAX, &[])
    }

    /// Whether `serve` read the body of a frame longer than a small
    /// message, sent by the peer numbered `n` on an EntryPush (0x13)
    /// stream, with a large-permit budget of `budget`. The pipe is too
    /// small to hold the whole frame, so the peer's write finishes only
    /// if the relay drains the body; a relay that parks for a permit it
    /// cannot get leaves the write blocked.
    async fn serve_reads_a_large_frame(n: u8, budget: usize) -> bool {
        let relay = relay_of(u64::MAX, &[2]);
        let permits = crate::p2p::LargePermits::new(budget);
        let peer = peer(n);
        let serving = Serving {
            conn: None,
            peer: &peer,
            address: address(n),
            db: &relay.db,
            rates: &relay.rates,
            permits: Some(&permits),
        };
        let mut proved = Proved::default();
        let mut whole = ShownWhole::default();
        let (mut relay_w, mut _peer_r) = tokio::io::duplex(64 * 1024);
        let (mut peer_w, mut relay_r) = tokio::io::duplex(64 * 1024);
        let serve = relay.entries.serve(
            Protocol::EntryPush,
            &mut relay_w,
            &mut relay_r,
            &serving,
            &mut proved,
            &mut whole,
        );
        tokio::pin!(serve);
        // A frame of a megabyte: longer than a small message.
        let frame = vec![0x5au8; 1_000_000];
        let write = codec::write_raw_frame(&mut peer_w, &frame);
        tokio::pin!(write);
        tokio::select! {
            biased;
            _ = &mut serve => true,
            r = &mut write => r.is_ok(),
            _ = tokio::time::sleep(Duration::from_millis(300)) => false,
        }
    }

    /// Rule 2 holds on the streams of entries, which carry the pushes it
    /// is mainly for (decision 2026-10-22 (memory), rule 2; the record's
    /// test 2 over a 0x13 stream): a frame longer than a small message
    /// from an unlisted peer is read only under a permit, a listed relay's
    /// is read at once (rule 7).
    #[tokio::test]
    async fn a_large_frame_on_an_entry_stream_is_read_only_under_a_permit() {
        // An unlisted peer, no permit free: its large frame is not read.
        assert!(
            !serve_reads_a_large_frame(1, 0).await,
            "an unlisted peer's large frame was read on a 0x13 stream with no permit"
        );
        // A relay listed by key is exempt, so its large frame is read at
        // once though no permit is free (rule 7).
        assert!(
            serve_reads_a_large_frame(2, 0).await,
            "a listed relay's large frame was not read on a 0x13 stream"
        );
        // An unlisted peer with a permit free: read.
        assert!(
            serve_reads_a_large_frame(1, 1).await,
            "an unlisted peer's large frame was not read when a permit was free"
        );
    }

    /// Whether the one permit is free while a stream is held in the write
    /// of its answer, having read its large frame under that permit. It
    /// should not be: the permit is held from the read until the answer is
    /// written (decision 2026-10-22 (memory), rule 2). `true` only if the
    /// stream let its permit go too early.
    async fn the_permit_is_free_while_a_stream_writes_its_answer() -> bool {
        let relay = relay_of(u64::MAX, &[]);
        let permits = crate::p2p::LargePermits::new(1);
        let peer1 = peer(1);
        let serving = Serving {
            conn: None,
            peer: &peer1,
            address: address(1),
            db: &relay.db,
            rates: &relay.rates,
            permits: Some(&permits),
        };
        // The answer goes into a one-byte pipe the peer never reads, so the
        // write blocks and the stream stays in it, holding its permit.
        let (mut relay_w, _peer_r) = tokio::io::duplex(1);
        let (mut peer_w, mut relay_r) = tokio::io::duplex(64 * 1024);
        let mut proved = Proved::default();
        let mut whole = ShownWhole::default();
        // A show of a large (garbage) entry: longer than a small message,
        // and answered (with a refusal) whatever the entry, so the relay
        // reaches the answer's write and is held in it.
        let frame = codec::encode_message(&WireMessage::EntryShow(EntryShow {
            entry: vec![0u8; 200_000],
        }))
        .unwrap();
        let serve = relay.entries.serve(
            Protocol::EntryShow,
            &mut relay_w,
            &mut relay_r,
            &serving,
            &mut proved,
            &mut whole,
        );
        tokio::pin!(serve);
        let write = codec::write_raw_frame(&mut peer_w, &frame);
        tokio::pin!(write);
        // Drive the serve and the peer's write until the serve is parked in
        // its answer's write (it never finishes, since the peer never
        // reads the one-byte pipe).
        tokio::select! {
            biased;
            _ = &mut serve => panic!("the serve finished; it was meant to block in its write"),
            _ = async { (&mut write).await.ok(); std::future::pending::<()>().await } => {}
            _ = tokio::time::sleep(Duration::from_millis(300)) => {}
        }
        // Now try to take the one permit from another subnet: it is free
        // only if the stream let its permit go before its write.
        let got = tokio::time::timeout(
            Duration::from_millis(100),
            permits.take("10.0.0.1".parse().unwrap()),
        )
        .await;
        matches!(got, Ok(Some(_)))
    }

    /// A stream holds its permit from the read of its large frame until the
    /// answer is written (decision 2026-10-22 (memory), rule 2): while a
    /// stream is held in its answer's write, the one permit is not free.
    #[tokio::test]
    async fn a_stream_holds_its_permit_through_the_write() {
        assert!(
            !the_permit_is_free_while_a_stream_writes_its_answer().await,
            "the permit was free while a stream was held in its answer's write"
        );
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
            let answer = self.show_unwritten(n, whole, request);
            // The answer is written whole: what it hands is remembered.
            let handed = whole.take_handing();
            whole.written(handed);
            answer
        }

        /// As [`Self::show_on`], where the answer is made and never
        /// written: what it hands is not remembered as handed.
        fn show_unwritten(
            &self,
            n: u8,
            whole: &mut ShownWhole,
            request: WireMessage,
        ) -> ShowAnswer {
            let peer = peer(n);
            let answer = shown(self.entries.answer(
                Protocol::EntryShow,
                &request,
                &self.who(&peer, n),
                None,
                &mut Proved::default(),
                whole,
                &self.db,
                &self.rates,
                NOW,
            ));
            answer
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

        /// The use of the channel numbered `c` that the relay keeps, not
        /// yet written.
        fn kept(&self, c: u16) -> Option<i64> {
            lock(&self.entries.uses).of(&channel(c))
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
        // handed the entry all the same, while it is not over yet. It is
        // counted, and takes the peer over by that entry.
        lock(&at.rates).fetched(&peer(3), address(3), MINUTE - 5000);
        assert_eq!(at.fetch_room(3), 5000);
        assert_eq!(
            shown(at.show(3, first.to_wire())),
            ShowAnswer::Another(larger.to_wire())
        );
        assert_eq!(at.fetch_room(3), 0);
        assert_eq!(lock(&at.rates).fetched_of_peer(&peer(3)), MINUTE + 120);
        // And again, now that it is over: "not now", and nothing more is
        // counted as fetched, however often it shows.
        for _ in 0..3 * BAN_THRESHOLD {
            not_now(at.show(3, first.to_wire()));
        }
        assert_eq!(lock(&at.rates).fetched_of_peer(&peer(3)), MINUTE + 120);
        // It is no breach.
        assert_eq!(breaches(&at, 3), (0, 0));
        // What it showed was counted as pushed, each time.
        assert_eq!(
            at.push_room(3),
            MINUTE - (1 + 3 * BAN_THRESHOLD as u64) * SMALL
        );
        // The answers that carry no entry are given all the same: the
        // entry that the relay holds, shown by a peer that is over, is
        // held, and one that it lacks is taken.
        assert_eq!(shown(at.show(3, larger.to_wire())), ShowAnswer::Held);
        let lacked = small(8, 1, 5);
        assert_eq!(shown(at.show(3, lacked.to_wire())), ShowAnswer::Taken);
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

    /// A short show is only ever of an entry that this connection showed
    /// whole in that slot, or was handed whole there (decision 2026-10-24
    /// (removal), rule 16). Of such an entry, the relay looks, and answers
    /// held, "show it whole", or the revision and ID of another. Of
    /// anything else it answers "show it whole", whatever it holds: an
    /// entry that it holds and the connection never showed, another
    /// revision in a slot the connection did show, another entry at that
    /// revision, the same entry on another connection.
    #[test]
    fn a_short_show_is_only_ever_of_an_entry_shown_or_handed_whole_on_the_connection() {
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
        // What it was handed whole is remembered beside its own (rule 16):
        // the short show of its own is told of the later one still, and a
        // short show of the later one is answered from the store.
        assert_eq!(at.show_on(1, &mut whole, short_of(&first)), word);
        assert_eq!(
            at.show_on(1, &mut whole, short_of(&later)),
            ShowAnswer::Held
        );
        assert_eq!(
            at.show_on(1, &mut whole, whole_of(&later)),
            ShowAnswer::Held
        );
        assert_eq!(whole.len(), 1, "one slot, with the two entries in it");
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

    // ── When a channel was used ──────────────────────────────────────

    /// The rows the relay's database has changed since it was opened.
    fn changes(at: &Relay) -> i64 {
        lock(&at.db)
            .query_row("SELECT total_changes()", [], |row| row.get(0))
            .unwrap()
    }

    /// A proof, a show of an entry held, whole and in short, and a pull
    /// write nothing with the lock held (issue #214), where the time kept
    /// is two hours old and each would have been written: the database's
    /// count of changes is as it was. The use of the channel is kept in
    /// memory, at the time of the request. What is no use (a proof that
    /// fails, an earlier entry shown, a pull) keeps nothing.
    #[test]
    fn a_proof_a_show_and_a_pull_write_nothing_and_keep_the_use() {
        let at = relay();
        let held_entry = small(1, 1, 5);
        at.hold(&held_entry, NOW - 2 * HOUR);
        at.hold(&small(2, 1, 5), NOW - 2 * HOUR);
        let session = Session {
            value: [0x51; 32],
            prover: peer(1).0,
        };
        let before = changes(&at);
        let prove = |c: u16, proof: [u8; 64], proved: &mut Proved| {
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

        // What is no use: a proof that fails, an earlier entry of channel
        // 2 shown, and a pull of it.
        let mut proved = Proved::default();
        assert!(!prove(2, [7; 64], &mut proved));
        assert!(matches!(
            at.show(1, small(2, 1, 4).to_wire()),
            Answer::Message(..)
        ));
        let none = Proved::default();
        page(at.pull(1, 2, &none, relay::NO_MARK, 0));
        assert_eq!(at.kept(2), None);

        // A proof that holds.
        let good = proof::make(&secret(1), &session.value, &session.prover).unwrap();
        assert!(prove(1, good, &mut proved));
        assert_eq!(changes(&at), before, "a proof wrote");
        assert_eq!(at.kept(1), Some(NOW));
        *lock(&at.entries.uses) = Uses::default();
        // An entry held, shown whole, and then in short.
        let mut whole = ShownWhole::default();
        let show = WireMessage::EntryShow(EntryShow {
            entry: held_entry.to_wire(),
        });
        assert_eq!(at.show_on(1, &mut whole, show), ShowAnswer::Held);
        assert_eq!(changes(&at), before, "a show wrote");
        assert_eq!(at.kept(1), Some(NOW));
        *lock(&at.entries.uses) = Uses::default();
        assert_eq!(
            at.show_on(1, &mut whole, short_of(&held_entry)),
            ShowAnswer::Held
        );
        assert_eq!(changes(&at), before, "a short show wrote");
        assert_eq!(at.kept(1), Some(NOW));
        // A pull of the channel proved.
        assert_eq!(
            page(at.pull(1, 1, &proved, relay::NO_MARK, 0))
                .entries
                .len(),
            1
        );
        assert_eq!(changes(&at), before, "a pull wrote");
        assert_eq!(at.held(1).unwrap().used_at, NOW - 2 * HOUR);

        // The control: the uses kept are written, as one.
        at.entries.write_uses(&at.db);
        assert_eq!(at.held(1).unwrap().used_at, NOW);
        assert_eq!(at.held(2).unwrap().used_at, NOW - 2 * HOUR);
        assert_eq!(changes(&at), before + 1);
    }

    /// The uses that a relay keeps are written at its hourly sweep, before
    /// the sweep reads them, and at a clean stop ([`RelayEntries::write_uses`]),
    /// by the rule of decision 2026-10-04 §16: a time is written only where
    /// it is more than an hour later than the time kept, and an earlier one
    /// never. From made-up times.
    #[test]
    fn the_uses_kept_are_written_at_the_sweep_and_at_a_stop_more_than_an_hour_later_only() {
        let at = relay();
        let t = NOW;
        for c in 1..=3 {
            at.hold(&small(c, 1, 5), t);
        }
        let session = Session {
            value: [0x51; 32],
            prover: peer(1).0,
        };
        // Channel `c` proved at `when`, by the stream.
        let prove_at = |c: u16, when: i64| {
            let proof = proof::make(&secret(c), &session.value, &session.prover).unwrap();
            let answer = at.entries.proving(
                &at.db,
                Some(&session),
                &mut Proved::default(),
                &ChannelProve {
                    channel: channel(c),
                    proof,
                },
                when,
            );
            assert!(proved_said(answer));
        };
        let used_at = |c: u16| at.held(c).unwrap().used_at;

        // Channel 1 past the hour, channel 2 within it, and channel 1
        // again earlier: the latest is kept, and nothing is written.
        prove_at(1, t + HOUR + 1);
        prove_at(2, t + 600);
        prove_at(1, t + 60);
        assert_eq!(
            (at.kept(1), at.kept(2)),
            (Some(t + HOUR + 1), Some(t + 600))
        );
        assert_eq!((used_at(1), used_at(2)), (t, t));

        // The sweep writes them: channel 1, more than an hour later, and
        // not channel 2. Nothing is kept after.
        at.entries.sweep_at(&at.db, t + 2 * HOUR);
        assert_eq!((used_at(1), used_at(2)), (t + HOUR + 1, t));
        assert_eq!((at.kept(1), at.kept(2)), (None, None));

        // A clock that was set back: an earlier time is never written.
        for earlier in [t + HOUR, t, 1] {
            prove_at(1, earlier);
            at.entries.write_uses(&at.db);
            assert_eq!(used_at(1), t + HOUR + 1, "{earlier}");
        }
        // An hour later to the second is not more than an hour later;
        // a second past it is.
        prove_at(1, t + 2 * HOUR + 1);
        at.entries.write_uses(&at.db);
        assert_eq!(used_at(1), t + HOUR + 1);
        prove_at(1, t + 2 * HOUR + 2);
        at.entries.write_uses(&at.db);
        assert_eq!(used_at(1), t + 2 * HOUR + 2);

        // The sweep reads every use there was before it: channel 3 is
        // proved ten seconds before its 90 days are up, and the sweep at
        // 90 days keeps it. Channel 2, used last at `t`, goes.
        prove_at(3, t + 90 * DAY - 10);
        assert_eq!(used_at(3), t);
        at.entries.sweep_at(&at.db, t + 90 * DAY);
        assert_eq!(at.held(2), None);
        assert_eq!(used_at(3), t + 90 * DAY - 10);
        assert_eq!(used_at(1), t + 2 * HOUR + 2);
    }

    /// A sweep whose uses could not be written drops nothing (the review
    /// of #217): a use in memory alone may be of a channel in use. Channel
    /// 1 is proved ten seconds before its 90 days are up, the database
    /// refuses the uses' write at the sweep, and the channel stays; once writes are
    /// taken again, the next sweep writes the use first.
    #[test]
    fn a_sweep_whose_uses_could_not_be_written_drops_nothing() {
        let at = relay();
        let t = NOW;
        at.hold(&small(1, 1, 5), t);
        let session = Session {
            value: [0x52; 32],
            prover: peer(1).0,
        };
        let proof = proof::make(&secret(1), &session.value, &session.prover).unwrap();
        let answer = at.entries.proving(
            &at.db,
            Some(&session),
            &mut Proved::default(),
            &ChannelProve {
                channel: channel(1),
                proof,
            },
            t + 90 * DAY - 10,
        );
        assert!(proved_said(answer));
        // The uses' write (an update) is refused; the sweep's (a delete)
        // is not.
        let updates_refused = |on: bool| {
            let db = at.db.lock().unwrap();
            let sql = match on {
                true => {
                    "CREATE TEMP TRIGGER no_update BEFORE UPDATE ON relay_channels \
                         BEGIN SELECT RAISE(ABORT, 'refused'); END"
                }
                false => "DROP TRIGGER no_update",
            };
            db.execute_batch(sql).unwrap();
        };
        updates_refused(true);
        at.entries.sweep_at(&at.db, t + 90 * DAY);
        updates_refused(false);
        assert!(at.held(1).is_some(), "a channel in use was dropped");
        assert_eq!(at.kept(1), Some(t + 90 * DAY - 10));
        at.entries.sweep_at(&at.db, t + 90 * DAY + HOUR);
        assert_eq!(at.held(1).unwrap().used_at, t + 90 * DAY - 10);
    }

    /// The lock's hold for a proof, from the node's counters (issue #214):
    /// many proofs on one relay with a database on disk, each of a channel
    /// whose time kept is two hours old, as after churn or a restart.
    /// Printed, not asserted: run with `--ignored --nocapture`.
    #[test]
    #[ignore = "a measurement, not a check"]
    fn bench_the_locks_hold_for_many_proofs() {
        const N: u16 = 2000;
        let dir = tempfile::tempdir().unwrap();
        let mut at = relay();
        at.db = TimedLock::new(cordelia_storage::db::open(&dir.path().join("relay.db")).unwrap());
        for c in 1..=N {
            at.hold(&small(c, 1, 5), NOW - 2 * HOUR);
        }
        let session = Session {
            value: [0x51; 32],
            prover: peer(1).0,
        };
        let proofs: Vec<[u8; 64]> = (1..=N)
            .map(|c| proof::make(&secret(c), &session.value, &session.prover).unwrap())
            .collect();
        let read = |what: &str| {
            let hold = at.db.times().hold(Kind::Proof);
            // The upper bound of the bucket that holds the quantile.
            let upper = |q: f64| {
                let target = (q * hold.count as f64).ceil() as u64;
                let mut seen = 0;
                for (i, n) in hold.buckets.iter().enumerate() {
                    seen += n;
                    if seen >= target {
                        return 1u64 << i;
                    }
                }
                u64::MAX
            };
            println!(
                "{what}: {} holds, mean {:.1} us, p50 <= {} us, p99 <= {} us, max {} us, over 5/50/100/250 ms {:?}",
                hold.count,
                hold.sum_nanos as f64 / hold.count.max(1) as f64 / 1000.0,
                upper(0.50),
                upper(0.99),
                hold.max_micros,
                hold.over,
            );
        };
        let round = || {
            let started = Instant::now();
            for (i, proof) in proofs.iter().enumerate() {
                // A connection remembers so many proofs: one for each.
                let mut proved = Proved::default();
                let c = i as u16 + 1;
                assert!(proved_said(at.answer(
                    1,
                    Protocol::ChannelProve,
                    WireMessage::ChannelProve(ChannelProve {
                        channel: channel(c),
                        proof: *proof,
                    }),
                    Some(&session),
                    &mut proved,
                )));
            }
            started.elapsed()
        };
        let took = round();
        read(&format!(
            "first round, every time kept 2 h old ({took:?} in all)"
        ));
        let sweep = Instant::now();
        at.entries.write_uses(&at.db);
        let sweep_hold = at.db.times().hold(Kind::Sweep);
        println!(
            "the {N} uses written in one transaction: hold {} us ({:?} in all)",
            sweep_hold.max_micros,
            sweep.elapsed()
        );
        let took = round();
        read(&format!(
            "both rounds, the second with every time kept new ({took:?} in all)"
        ));
    }

    // ── The checkpoint (issue #224) ──────────────────────────────────

    /// A relay with room for everything, whose store is a file in `dir`,
    /// opened as a relay's node opens it: with SQLite's automatic
    /// checkpoint off where `off`.
    fn relay_on_disk(dir: &std::path::Path, off: bool) -> (Relay, std::path::PathBuf) {
        let path = dir.join("relay.db");
        let conn = cordelia_storage::db::open(&path).unwrap();
        if off {
            cordelia_storage::db::automatic_checkpoint_off(&conn).unwrap();
        }
        let mut at = relay();
        at.db = TimedLock::new(conn);
        (at, path)
    }

    /// The bytes of the store's write-ahead log.
    fn wal_bytes(path: &std::path::Path) -> u64 {
        std::fs::metadata(path.with_extension("db-wal")).map_or(0, |file| file.len())
    }

    /// The kinds of take of the lock that held it at least once.
    fn kinds_held(db: &TimedLock<Connection>) -> Vec<Kind> {
        Kind::ALL
            .into_iter()
            .filter(|kind| db.times().hold(*kind).count > 0)
            .collect()
    }

    /// The peer numbered `n` pushes one entry of its own channel, `n`,
    /// in slot `slot`, at `rev`: stored.
    fn pushes_one(at: &Relay, n: u8, slot: u64, rev: u64) {
        let entry = made(n.into(), n, rev, &format!("note-{slot}.md"), "a small text");
        assert_eq!(
            pushed(at.push(n, vec![entry.to_wire()])),
            [PushAnswer::Stored]
        );
    }

    /// No push checkpoints the log (issue #224): on a relay's store, a
    /// thousand pushes from ten devices grow its log past twice the 1,000
    /// pages at which SQLite's automatic checkpoint would have run inside
    /// one of them, and it never shrinks; every take of the lock is of a
    /// push.
    #[test]
    fn a_push_never_runs_a_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let (at, path) = relay_on_disk(dir.path(), true);
        let page: u64 = Connection::open(&path)
            .unwrap()
            .pragma_query_value(None, "page_size", |row| row.get(0))
            .unwrap();
        let mut log = wal_bytes(&path);
        for i in 0..100u64 {
            for n in 1..=10u8 {
                pushes_one(&at, n, i, 5 + i);
                let now = wal_bytes(&path);
                assert!(now >= log, "a push shrank the log: {log} to {now}");
                log = now;
            }
        }
        assert!(log / page > 2_000, "the log is {} pages", log / page);
        assert_eq!(kinds_held(&at.db), [Kind::Push]);
    }

    /// The pages the relay has written to its log since its last whole
    /// checkpoint.
    fn log_written(at: &Relay) -> u64 {
        cordelia_storage::db::log_pages_written(&lock_db(&at.db), false).unwrap()
    }

    fn lock_db(db: &TimedLock<Connection>) -> TimedGuard<'_, Connection> {
        db.lock().unwrap()
    }

    /// The relay's checkpoint takes the lock as a checkpoint, and as no
    /// other kind (issue #224). A tick lets go while the relay has written
    /// fewer than RELAY_CHECKPOINT_LOG_PAGES to its log, and the log grows;
    /// the first tick once it has written them writes the log back whole,
    /// and the next pushes start the log again over its file, which does
    /// not grow. The checkpoint at a stop truncates it.
    #[test]
    fn the_checkpoint_takes_the_lock_as_a_checkpoint_and_starts_the_log_again() {
        let dir = tempfile::tempdir().unwrap();
        let (at, path) = relay_on_disk(dir.path(), true);
        let mut rev = 5;
        while log_written(&at) < RELAY_CHECKPOINT_LOG_PAGES {
            assert!(rev < 500, "the log stays at {} pages", log_written(&at));
            assert_eq!(at.entries.checkpoint(&at.db), Checkpointed::Short);
            for n in 1..=10u8 {
                pushes_one(&at, n, rev, rev);
            }
            rev += 1;
        }
        assert_eq!(at.db.times().hold(Kind::Checkpoint).count, rev - 5);
        let grown = wal_bytes(&path);
        assert_eq!(at.entries.checkpoint(&at.db), Checkpointed::Whole);
        assert_eq!(log_written(&at), 0);
        assert_eq!(at.entries.checkpoint(&at.db), Checkpointed::Short);
        for n in 1..=10u8 {
            pushes_one(&at, n, rev, rev);
        }
        assert_eq!(wal_bytes(&path), grown, "the log starts again in place");
        assert!(log_written(&at) > 0);
        assert_eq!(
            kinds_held(&at.db),
            [Kind::Push, Kind::Checkpoint, Kind::Other]
        );
        assert!(at.entries.checkpoint_at_stop(&at.db));
        assert_eq!(wal_bytes(&path), 0);
        assert_eq!(log_written(&at), 0);
        // What was pushed is held after it.
        assert!(at.held(10).is_some());
    }

    /// At the scale test's rates a relay sees a write every few seconds,
    /// and so a tick after each push (issue #224, the review's sequence: a
    /// push, then a tick, hundreds of times). A tick checkpoints only once
    /// the relay has written RELAY_CHECKPOINT_LOG_PAGES to its log since
    /// the last, as SQLite's automatic checkpoint did inside a commit; a
    /// checkpoint at each tick would cost each push the checkpoint's two
    /// syncs, and the next push one more to start the log again.
    #[test]
    fn a_tick_after_each_push_checkpoints_only_once_the_log_holds_its_pages() {
        let dir = tempfile::tempdir().unwrap();
        let (at, _path) = relay_on_disk(dir.path(), true);
        let (mut whole, pushes) = (0, 600u64);
        for i in 0..pushes {
            pushes_one(&at, 1 + (i % 10) as u8, i, 5 + i);
            let written = log_written(&at);
            let tick = at.entries.checkpoint(&at.db);
            assert_eq!(
                tick == Checkpointed::Whole,
                written >= RELAY_CHECKPOINT_LOG_PAGES,
                "push {i}: {written} pages written, {tick:?}"
            );
            assert!(matches!(tick, Checkpointed::Whole | Checkpointed::Short));
            whole += u64::from(tick == Checkpointed::Whole);
        }
        // A push writes a few pages: one checkpoint for each hundred pushes
        // or more, never one for each.
        assert!((1..=pushes / 100).contains(&whole), "{whole} checkpoints");
    }

    /// While something holds the lock for long, the ticks that come do not
    /// queue behind it (issue #224): one tick waits for the lock, and each
    /// other finds it running and answers at once, taking no lock. Once the
    /// lock is let go, the waiting tick runs.
    #[test]
    fn ticks_do_not_queue_on_the_lock_behind_a_long_hold() {
        let dir = tempfile::tempdir().unwrap();
        let (at, _path) = relay_on_disk(dir.path(), true);
        pushes_one(&at, 1, 1, 5);
        let at = &at;
        let held = lock_db(&at.db);
        std::thread::scope(|s| {
            let waiting = s.spawn(|| at.entries.checkpoint_over(&at.db, 0));
            // Until it has started, or a second.
            let started = Instant::now();
            while !at.entries.checkpointing.load(Ordering::Acquire)
                && started.elapsed() < Duration::from_secs(1)
            {
                std::thread::yield_now();
            }
            // A slow start is said as one, not taken for a tick that queued;
            // the lock is let go first, or the waiting tick would never end.
            if !at.entries.checkpointing.load(Ordering::Acquire) {
                drop(held);
                panic!("the waiting tick did not start within a second");
            }
            // The other ticks from a thread of their own, so that a tick
            // that queued on the lock fails the test rather than hang it.
            let (said, answers) = std::sync::mpsc::channel();
            s.spawn(move || {
                for _ in 0..5 {
                    said.send(at.entries.checkpoint(&at.db)).unwrap();
                }
            });
            let mut ticks = Vec::new();
            for _ in 0..5 {
                match answers.recv_timeout(Duration::from_millis(500)) {
                    Ok(tick) => ticks.push(tick),
                    Err(_) => break,
                }
            }
            drop(held);
            assert_eq!(
                ticks,
                [Checkpointed::Running; 5],
                "a tick queued on the lock"
            );
            assert_eq!(waiting.join().unwrap(), Checkpointed::Whole);
        });
        assert_eq!(at.db.times().wait(Kind::Checkpoint).count, 1);
        assert_eq!(at.entries.checkpoint(&at.db), Checkpointed::Short);
    }

    /// A checkpoint that a reader in another process holds back answers at
    /// once, and the next, once the reader is gone, writes the log back
    /// whole (issue #224). The count of pages written starts again only
    /// then.
    #[test]
    fn a_checkpoint_that_a_reader_holds_back_is_made_again_at_the_next() {
        let dir = tempfile::tempdir().unwrap();
        let (at, path) = relay_on_disk(dir.path(), true);
        pushes_one(&at, 1, 1, 5);
        let reader = Connection::open(&path).unwrap();
        reader.execute_batch("BEGIN").unwrap();
        let _: i64 = reader
            .query_row("SELECT count(*) FROM node_meta", [], |row| row.get(0))
            .unwrap();
        pushes_one(&at, 2, 1, 5);
        let written = log_written(&at);
        let started = Instant::now();
        assert_eq!(at.entries.checkpoint_over(&at.db, 0), Checkpointed::Part);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(log_written(&at), written);
        reader.execute_batch("COMMIT").unwrap();
        drop(reader);
        assert_eq!(at.entries.checkpoint_over(&at.db, 0), Checkpointed::Whole);
        assert_eq!(log_written(&at), 0);
    }

    /// A push's hold of the lock, and a checkpoint's, from the node's own
    /// counters, on a relay whose store is a file on disk, in three ways:
    /// `on`, SQLite's automatic checkpoint, as before issue #224; `every`,
    /// that off and a checkpoint at each tick whatever was written; `pages`,
    /// that off and a checkpoint at the first tick once
    /// RELAY_CHECKPOINT_LOG_PAGES have been written, as the relay does.
    /// `CORDELIA_BENCH_ONLY` names one of them (all three otherwise).
    ///
    /// `CORDELIA_BENCH_RATE=fast` (the default): many devices push from
    /// four threads as fast as they can, about a thousand pushes a second,
    /// and a thread ticks every `CORDELIA_BENCH_CHECKPOINT_MS`
    /// (RELAY_CHECKPOINT_INTERVAL_SECS otherwise); `CORDELIA_BENCH_DEVICES`
    /// and `CORDELIA_BENCH_ROUNDS` say how many devices push, and how many
    /// entries each (100 and 200). `CORDELIA_BENCH_RATE=stage`: the scale
    /// test's rates, a push every few seconds, with
    /// `CORDELIA_BENCH_TICKS_PER_PUSH` ticks after each push (3: a push
    /// every three seconds, stage 190's 21 writes a minute; 5 for stage
    /// 100's 11; 1 for stage 500's 55), `CORDELIA_BENCH_PUSHES` of them
    /// (2,000), one after another; the time between is not slept, since
    /// SQLite sees only the order of the commits and the ticks.
    ///
    /// `CORDELIA_BENCH_DIR` names where the store goes (a temporary
    /// directory otherwise), and `CORDELIA_BENCH_LOG_KEPT_BYTES` the bytes
    /// of the log's file kept where the automatic checkpoint is off
    /// (RELAY_LOG_KEPT_BYTES otherwise; -1 for no limit). Printed, not
    /// asserted: run with `--ignored --nocapture`. A disk whose sync is
    /// slow is had by running the test binary under `strace -f
    /// --seccomp-bpf -o FILE -e trace=fsync,fdatasync -e
    /// inject=fsync,fdatasync:delay_exit=10000`, which makes each sync take
    /// 10 ms more, and whose FILE has a line for each sync: run one way at
    /// a time to count the syncs for each push.
    #[test]
    #[ignore = "a measurement, not a check"]
    fn bench_a_pushs_hold_with_and_without_the_automatic_checkpoint() {
        use cordelia_core::protocol::RELAY_CHECKPOINT_INTERVAL_SECS;
        use std::sync::atomic::AtomicU64;
        let number = |name: &str, or: i64| -> i64 {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(or)
        };
        let stage = std::env::var("CORDELIA_BENCH_RATE").is_ok_and(|rate| rate == "stage");
        let only = std::env::var("CORDELIA_BENCH_ONLY").ok();
        let devices = number("CORDELIA_BENCH_DEVICES", 100).clamp(1, 199) as u8;
        let rounds = number("CORDELIA_BENCH_ROUNDS", 200) as u64;
        let ticks_per_push = number("CORDELIA_BENCH_TICKS_PER_PUSH", 3) as u64;
        let stage_pushes = number("CORDELIA_BENCH_PUSHES", 2_000) as u64;
        let kept = number(
            "CORDELIA_BENCH_LOG_KEPT_BYTES",
            cordelia_core::protocol::RELAY_LOG_KEPT_BYTES,
        );
        let base = std::env::var("CORDELIA_BENCH_DIR").ok();
        let every_ms = number(
            "CORDELIA_BENCH_CHECKPOINT_MS",
            RELAY_CHECKPOINT_INTERVAL_SECS as i64 * 1000,
        ) as u64;
        let upper = |hold: &cordelia_core::load::HistogramRead, q: f64| -> u64 {
            let target = (q * hold.count as f64).ceil() as u64;
            let mut seen = 0;
            for (i, n) in hold.buckets.iter().enumerate() {
                seen += n;
                if seen >= target {
                    return 1u64 << i;
                }
            }
            u64::MAX
        };
        // Each way: its name, whether the automatic checkpoint is off, and
        // the pages written at which a tick checkpoints.
        let ways = [
            ("on", false, 0),
            ("every", true, 0),
            ("pages", true, RELAY_CHECKPOINT_LOG_PAGES),
        ];
        for (name, off, pages) in ways {
            if only.as_deref().is_some_and(|only| only != name) {
                continue;
            }
            let dir = match &base {
                Some(base) => tempfile::tempdir_in(base).unwrap(),
                None => tempfile::tempdir().unwrap(),
            };
            let (at, path) = relay_on_disk(dir.path(), off);
            if off {
                lock_db(&at.db)
                    .pragma_update(None, "journal_size_limit", kept)
                    .unwrap();
            }
            // The counts start after the store is opened.
            let at = Relay {
                db: TimedLock::new(at.db.into_inner().unwrap()),
                ..at
            };
            // Each push's own time, around the call, for exact quantiles
            // beside the counters' buckets.
            let took = Mutex::new(Vec::new());
            let most_log = AtomicU64::new(0);
            let whole = AtomicU64::new(0);
            let tick = || {
                most_log.fetch_max(wal_bytes(&path), std::sync::atomic::Ordering::Relaxed);
                if at.entries.checkpoint_over(&at.db, pages) == Checkpointed::Whole {
                    whole.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            };
            let started = Instant::now();
            if stage {
                for i in 0..stage_pushes {
                    let one = Instant::now();
                    pushes_one(&at, 1 + (i % 10) as u8, i % 8, 5 + i);
                    lock(&took).push(one.elapsed());
                    if off {
                        (0..ticks_per_push).for_each(|_| tick());
                    }
                }
            } else {
                let done = std::sync::atomic::AtomicBool::new(false);
                std::thread::scope(|s| {
                    if off {
                        s.spawn(|| {
                            let every = Duration::from_millis(every_ms);
                            let mut next = Instant::now();
                            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                                if Instant::now() >= next {
                                    tick();
                                    next += every;
                                }
                                std::thread::sleep(Duration::from_millis(5));
                            }
                        });
                    }
                    let pushers: Vec<_> = (0..4u8)
                        .map(|t| {
                            let (at, took) = (&at, &took);
                            s.spawn(move || {
                                for i in 0..rounds {
                                    for n in (1..=devices).filter(|n| n % 4 == t) {
                                        let one = Instant::now();
                                        pushes_one(at, n, i % 8, 5 + i);
                                        lock(took).push(one.elapsed());
                                    }
                                }
                            })
                        })
                        .collect();
                    for pusher in pushers {
                        pusher.join().unwrap();
                    }
                    done.store(true, std::sync::atomic::Ordering::Relaxed);
                });
            }
            most_log.fetch_max(wal_bytes(&path), std::sync::atomic::Ordering::Relaxed);
            let elapsed = started.elapsed();
            let mut took = took.into_inner().unwrap();
            took.sort();
            let at_q =
                |q: f64| took[((q * took.len() as f64).ceil() as usize).clamp(1, took.len()) - 1];
            let times = at.db.times();
            let (push, checkpoint) = (times.hold(Kind::Push), times.hold(Kind::Checkpoint));
            println!(
                "{name} ({}): {} pushes in {elapsed:?}, {} whole checkpoints, the log's file at most {} KiB; the lock held {:.1} ms for pushes and {:.1} ms for checkpoints, {:.3} ms a push in all",
                if stage {
                    format!("stage rate, {ticks_per_push} ticks a push")
                } else {
                    format!("fast, a tick every {every_ms} ms")
                },
                took.len(),
                whole.into_inner(),
                most_log.into_inner() / 1024,
                push.sum_nanos as f64 / 1e6,
                checkpoint.sum_nanos as f64 / 1e6,
                (push.sum_nanos + checkpoint.sum_nanos) as f64 / 1e6 / took.len() as f64,
            );
            for kind in [Kind::Push, Kind::Checkpoint] {
                let hold = times.hold(kind);
                let wait = times.wait(kind);
                println!(
                    "  {}: {} holds, mean {:.0} us, p50 <= {} us, p99 <= {} us, max {} us, over 5/50/100/250 ms {:?}; wait p99 <= {} us, max {} us",
                    kind.name(),
                    hold.count,
                    hold.sum_nanos as f64 / hold.count.max(1) as f64 / 1000.0,
                    upper(&hold, 0.50),
                    upper(&hold, 0.99),
                    hold.max_micros,
                    hold.over,
                    upper(&wait, 0.99),
                    wait.max_micros,
                );
                // The holds over 8 ms, by bucket: up to 16, 32, 64 and
                // 128 ms, and over.
                println!(
                    "    holds over 8 ms, in buckets to 16/32/64/128 ms and over: {:?}",
                    [
                        hold.buckets[14],
                        hold.buckets[15],
                        hold.buckets[16],
                        hold.buckets[17],
                        hold.buckets[18..].iter().sum::<u64>(),
                    ]
                );
            }
            println!(
                "  a push's call, timed around it: p50 {:?}, p99 {:?}, p99.9 {:?}, max {:?}",
                at_q(0.50),
                at_q(0.99),
                at_q(0.999),
                took[took.len() - 1]
            );
        }
    }

    /// A listed relay whose clock runs ahead says a channel was used later
    /// than this relay's time: the use is kept at this relay's time, and
    /// written so (decision 2026-10-04 §2.4 item 6).
    #[test]
    fn a_listed_relays_word_of_use_is_kept_no_later_than_this_relays_clock() {
        let at = relay_of(u64::MAX, &[8]);
        at.hold(&small(1, 1, 5), NOW - 2 * HOUR);
        let held = at.held(1).unwrap();
        let told = RelayChannel {
            channel: channel(1),
            mark: held.mark,
            held_since: held.held_since,
            used_at: NOW + 10 * DAY,
            places: 1,
        };
        at.entries.wants(&at.db, &peer(8), &told, NOW);
        assert_eq!(at.kept(1), Some(NOW));
        at.entries.write_uses(&at.db);
        assert_eq!(at.held(1).unwrap().used_at, NOW);
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
        assert_eq!(at.kept(1), None);
        assert_eq!(proved.len(), 0);
        assert!(!proved.holds(&channel(1)));

        // The proof: yes, and the channel was used. The use is kept, and
        // written with the others: the proof wrote nothing.
        let good = proof::make(&secret(1), &session.value, &session.prover).unwrap();
        assert!(prove(1, good, Some(&session), &mut proved));
        assert_eq!(at.held(1).unwrap().used_at, NOW - 2 * HOUR);
        assert_eq!(at.kept(1), Some(NOW));
        at.entries.write_uses(&at.db);
        assert_eq!(at.held(1).unwrap().used_at, NOW);
        assert_eq!(at.kept(1), None);
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
            assert!(proved.has_room_for(&made_up, MAX_CHANNELS_PROVED_ON_A_CONNECTION));
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
        assert_eq!(at.kept(2000), None);
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
        assert_eq!(at.kept(7), Some(NOW));
        at.entries.write_uses(&at.db);
        assert_eq!(at.held(7).unwrap().used_at, NOW);
        assert_eq!(proved.len(), 1024);

        // Another connection has a memory of its own.
        let mut another = Proved::default();
        assert!(prove(2000, &mut another));
        assert_eq!(another.len(), 1);
    }

    /// A relay that is set up to remember the proofs of fewer channels
    /// for one connection than a relay does, as a test has one do, looks
    /// at none beyond those: and never at more than the protocol's own
    /// bound, whatever it is set up with.
    #[test]
    fn a_relay_remembers_for_a_connection_as_many_proofs_as_it_is_set_up_to() {
        let at = Relay {
            entries: relay().entries.remembering_at_most(2),
            ..relay()
        };
        for c in [7, 8, 9] {
            at.hold(&small(c, 1, 5), NOW - 2 * HOUR);
        }
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
        let mut proved = Proved::default();
        assert!(prove(7, &mut proved));
        assert!(prove(8, &mut proved));
        // The third is not looked at, though the relay holds its channel
        // and the proof holds. One that is remembered is proved again.
        assert!(!prove(9, &mut proved));
        assert_eq!(proved.len(), 2);
        assert!(prove(7, &mut proved));

        let more = relay().entries.remembering_at_most(usize::MAX);
        assert_eq!(more.most_proved, MAX_CHANNELS_PROVED_ON_A_CONNECTION);
        assert_eq!(relay().entries.most_proved, 1024);
    }

    // ── Pull ─────────────────────────────────────────────────────────

    /// A channel is handed only to a connection that has proved its key.
    /// Without that the answer is the one for a channel that the relay
    /// does not hold and that was not proved either, byte for byte, and
    /// counts for nothing. A connection that proved a channel which is
    /// not held is told so: by the mark of no holding, and the start.
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
        // are asked with. A channel that is not held, and was not proved,
        // is answered so too.
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
            let not_held = page(at.pull(1, 2, &nothing, asked_mark, after));
            assert_eq!(bytes(&not_held), bytes(&unproved));
            // Proved, and not held: no holding. Whoever holds the key and
            // keeps a place then knows that nothing it sent is there.
            let proved_not_held = page(at.pull(1, 2, &having_proved(&[2]), asked_mark, after));
            assert_eq!(
                proved_not_held,
                EntryPulled {
                    entries: Vec::new(),
                    next: 0,
                    mark: relay::NO_MARK,
                }
            );
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

    /// A page for a peer that is not a relay listed by key is a small one
    /// (decision 2026-10-22 (memory), rule 3). Of a channel that holds 13
    /// entries of the largest size, each page to a device holds at most
    /// SMALL_PAGE_BYTES of entries, and at least one; its place is that of
    /// its last entry, so the next starts at the one it left out; and its
    /// answer fits a small message. Read on page after page, the channel
    /// is handed whole, in order, with nothing passed over. A relay
    /// configured by its address alone is no relay listed by key, and is
    /// given small pages too.
    #[test]
    fn a_page_for_an_unlisted_peer_holds_at_most_a_small_page_and_says_there_is_more() {
        let at = relay_of(u64::MAX, &[8]);
        let held: Vec<CheckedEntry> = (1..=13).map(|d| largest(1, d)).collect();
        for entry in &held {
            at.hold(entry, NOW);
        }
        let mark = at.held(1).unwrap().mark;
        let proved = having_proved(&[1]);
        // A device, and the relay at address 200, configured by address
        // alone.
        for n in [1, 200] {
            let (mut after, mut read) = (0, Vec::new());
            loop {
                let answer = said(at.pull(n, 1, &proved, mark, after));
                let wire = codec::encode_message(&answer).unwrap();
                let WireMessage::EntryPulled(page) = answer else {
                    panic!("not a page");
                };
                if page.entries.is_empty() {
                    break;
                }
                let bytes: usize = page.entries.iter().map(|entry| entry.len()).sum();
                assert!(bytes <= SMALL_PAGE_BYTES, "a page of {bytes} bytes to {n}");
                assert!(wire.len() <= SMALL_MESSAGE_BYTES as usize, "{}", wire.len());
                // One entry of the largest size, and not two.
                assert_eq!(page.entries.len(), 1);
                // It says there is more: its place is its last entry's.
                assert_eq!(page.next, after + 1);
                read.extend(page.entries.iter().map(|entry| entry.to_vec()));
                after = page.next;
            }
            let stored: Vec<Vec<u8>> = held.iter().map(|entry| entry.to_wire()).collect();
            assert_eq!(read, stored, "the channel was not handed whole to {n}");
        }
    }

    /// A relay listed by key keeps full pages (decision 2026-10-22
    /// (memory), rules 3 and 7): of a channel of 13 entries of the largest
    /// size, a pull on the stream of entries and a pull between relays
    /// each hand all 13 in one page, up to ENTRY_PAGE_MAX_BYTES, and not a
    /// small page.
    #[test]
    fn a_page_for_a_relay_listed_by_key_is_not_cut_to_a_small_page() {
        let at = relay_of(u64::MAX, &[8]);
        for d in 1..=13 {
            at.hold(&largest(1, d), NOW);
        }
        let mark = at.held(1).unwrap().mark;
        let pulled = page(at.pull(8, 1, &having_proved(&[1]), mark, 0));
        let between = page(at.answer(
            8,
            Protocol::RelayEntries,
            WireMessage::RelayPull(RelayPull {
                channel: channel(1),
                mark,
                after: 0,
                limit: 100,
            }),
            None,
            &mut Proved::default(),
        ));
        for page in [pulled, between] {
            let bytes: usize = page.entries.iter().map(|entry| entry.len()).sum();
            assert_eq!(page.entries.len(), 13, "a listed relay's page was cut");
            assert!(bytes > SMALL_PAGE_BYTES && bytes <= ENTRY_PAGE_MAX_BYTES);
            assert_eq!(page.next, 13);
        }
    }

    /// A relay asks a relay it lists by key for pages whose worst case is a
    /// small page where its own end of their connection has every peer's
    /// windows, and for full pages where it carries the listed settings
    /// (decision 2026-10-22 (memory), rule 12). A receive window bounds
    /// what the other end may send, so it is the asker's windows that a
    /// page crosses, and only the asker can see them; the relay that
    /// serves a listed relay gives it what it asks for, up to a full page.
    ///
    /// The check's NAT case: relay B dials relay A by key from an address
    /// that A has not configured, so A's end has every peer's windows and
    /// B's the listed ones. Each holds a channel of 13 entries of the
    /// largest size. A pulls from B one entry a page, ten in a pass; B
    /// pulls from A the whole channel in one full page.
    #[tokio::test]
    async fn a_relay_on_every_peers_windows_asks_a_listed_relay_for_small_pages() {
        let pages_asked = |link: &Link| -> Vec<u32> {
            lock(&link.asked)
                .iter()
                .filter_map(|request| match request {
                    WireMessage::RelayPull(pull) => Some(pull.limit),
                    _ => None,
                })
                .collect()
        };
        // Each serves the other as a relay it lists (number 9), and each
        // pulls from the other as number 8.
        let (a, b) = (relay_of(u64::MAX, &[8, 9]), relay_of(u64::MAX, &[8, 9]));
        for d in 1..=13 {
            a.hold(&largest(1, d), NOW);
            b.hold(&largest(2, d), NOW);
        }

        // A pulls from B: A's end has every peer's windows.
        let from_b = Link {
            small_windows: true,
            ..Link::to(&b)
        };
        a.entries.pull_from(&from_b, peer(8), &a.db).await;
        let asked = pages_asked(&from_b);
        assert_eq!(
            asked,
            vec![SMALL_WINDOWS_PULL_ENTRIES; RELAY_ENTRY_PULL_PAGES],
            "a relay on every peer's windows asked for pages larger than a small page"
        );
        assert_eq!(
            a.held(2).unwrap().bytes,
            RELAY_ENTRY_PULL_PAGES as u64 * LARGEST,
            "a pass of pages of one entry did not store one entry a page"
        );
        // The next pass goes on, and the channel is had whole.
        a.entries.pull_from(&from_b, peer(8), &a.db).await;
        assert_eq!(a.held(2).unwrap().bytes, 13 * LARGEST);

        // B pulls from A: B's end carries the listed settings, and A, which
        // cannot see B's windows, hands the full page it is asked for: the
        // channel whole, in one page.
        let from_a = Link::to(&a);
        b.entries.pull_from(&from_a, peer(8), &b.db).await;
        // Of each channel A holds (channel 2 too, which A had of B), a
        // full page.
        let asked = pages_asked(&from_a);
        assert!(
            !asked.is_empty() && asked.iter().all(|limit| *limit == ENTRY_PAGE_MAX_ENTRIES),
            "a relay that carries the listed settings did not ask for full pages: {asked:?}"
        );
        let of_one = from_a
            .pulls()
            .iter()
            .filter(|(c, ..)| *c == channel(1))
            .count();
        assert_eq!(of_one, 1, "the channel was not had in one full page");
        assert_eq!(
            b.held(1).unwrap().bytes,
            13 * LARGEST,
            "a listed relay was not handed the full page it asked for"
        );
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
        let stores = relay::pull(
            &lock(&at.db),
            &channel(1),
            false,
            &[9; 8],
            7,
            100,
            ENTRY_PAGE_MAX_BYTES,
        )
        .unwrap();
        assert_eq!(
            page(at.pull(1, 1, &nothing_proved, [9; 8], 7)),
            EntryPulled::from(&stores)
        );
    }

    /// A stranger with one large entry at a relay, who shows a small
    /// earlier one again and again, is handed the large one while it is
    /// not over its bytes for the minute, once more as it goes over, and
    /// then no more: about what a connection may be handed in a minute,
    /// and not as much as it cares to ask for. A relay that the operator
    /// lists is not limited.
    #[test]
    fn the_answer_to_a_show_is_handed_only_while_the_asker_is_not_over_its_bytes() {
        let at = relay_of(u64::MAX, &[9]);
        let big = largest(1, 1);
        at.hold(&big, NOW);
        let earlier = made(1, 1, 4, "n", "a small earlier one");
        // It is handed the large one until it is refused.
        let mut handed = 0u64;
        loop {
            match at.show(1, earlier.to_wire()) {
                Answer::Message(answer) => {
                    assert!(matches!(
                        *answer,
                        WireMessage::EntryShown(EntryShown {
                            answer: ShowAnswer::Another(_)
                        })
                    ));
                    handed += 1;
                    assert!(handed <= 100, "it is handed without bound");
                }
                Answer::NotNow => break,
                other => panic!("{other:?}"),
            }
        }
        // As many as fit in the minute's bytes, and the one that took it
        // over.
        assert_eq!(handed, MINUTE / LARGEST + 1);
        assert_eq!(lock(&at.rates).fetched_of_peer(&peer(1)), handed * LARGEST);
        // From then on it is refused, and nothing more is counted as
        // fetched. It is no breach.
        for _ in 0..3 * BAN_THRESHOLD {
            not_now(at.show(1, earlier.to_wire()));
        }
        assert_eq!(lock(&at.rates).fetched_of_peer(&peer(1)), handed * LARGEST);
        assert_eq!(breaches(&at, 1), (0, 0));
        // A relay that the operator lists is handed it however often.
        for _ in 0..2 * handed {
            assert_eq!(
                shown(at.show(9, earlier.to_wire())),
                ShowAnswer::Another(big.to_wire())
            );
        }
    }

    /// A pull that is refused for the asker's bytes is refused before the
    /// store is read: with no room for the smallest entry it does not
    /// wait for the database. With room for one, the store is asked.
    #[test]
    fn a_pull_that_is_refused_for_the_askers_bytes_does_not_wait_for_the_store() {
        use std::sync::mpsc;
        let at = relay();
        at.hold(&small(1, 1, 5), NOW);
        let proved = having_proved(&[1]);
        // Whether the pull is refused within two seconds while this
        // thread holds the database: `None` where it waited.
        let while_held = |n: u8| {
            let held = lock(&at.db);
            std::thread::scope(|scope| {
                let (said, heard) = mpsc::channel();
                let (at, proved) = (&at, &proved);
                scope.spawn(move || {
                    let refused =
                        matches!(at.pull(n, 1, proved, relay::NO_MARK, 0), Answer::NotNow);
                    let _ = said.send(refused);
                });
                let answered = heard.recv_timeout(Duration::from_secs(2));
                drop(held);
                answered.ok()
            })
        };
        // No room at all; room for the answer to a show and nothing
        // beside it; and room, beside that, for less than the smallest
        // entry.
        lock(&at.rates).fetched(&peer(1), address(1), MINUTE);
        assert_eq!(at.fetch_room(1), 0);
        assert_eq!(while_held(1), Some(true));
        lock(&at.rates).fetched(&peer(5), address(5), MINUTE - LARGEST);
        assert_eq!(at.fetch_room(5), LARGEST);
        assert_eq!(while_held(5), Some(true));
        lock(&at.rates).fetched(&peer(2), address(2), MINUTE - LARGEST - (SMALL - 1));
        assert_eq!(while_held(2), Some(true));
        assert_eq!(breaches(&at, 1), (0, 0));
        // Room for the smallest beside it: the store is asked, and the
        // entry handed.
        for n in [3, 4] {
            lock(&at.rates).fetched(&peer(n), address(n), MINUTE - LARGEST - SMALL);
        }
        assert_eq!(while_held(3), None);
        let handed = page(at.pull(4, 1, &proved, relay::NO_MARK, 0));
        assert_eq!(handed.entries.len(), 1);
        // A relay that the operator lists is not limited, and is not
        // refused.
        let listed = relay_of(u64::MAX, &[9]);
        listed.hold(&small(1, 1, 5), NOW);
        lock(&listed.rates).fetched(&peer(9), address(9), MINUTE);
        assert_eq!(
            page(listed.pull(9, 1, &proved, relay::NO_MARK, 0))
                .entries
                .len(),
            1
        );
    }

    /// What a peer is handed in a minute is bounded, as what a relay may
    /// fetch from it is. A page is sized to the room there is beside the
    /// room for the answer to a show, an entry that fits is still handed,
    /// and a pull whose first entry does not fit is refused, and is no
    /// breach.
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
        // A page for a device is a small one, which holds one of the
        // largest (decision 2026-10-22 (memory), rule 3). Pages are handed
        // until what is left of the minute, beside the room that is left
        // for the answer to a show (one entry of the largest size), holds
        // no other.
        for _ in 0..30 {
            let page = page(at.pull(1, 1, &proved, mark, after));
            handed.push(page.entries.len());
            (mark, after) = (page.mark, page.next);
        }
        assert_eq!(handed, [1; 30]);
        assert_eq!(at.fetch_room(1), MINUTE - 30 * LARGEST);
        assert!(at.fetch_room(1) >= LARGEST);
        assert!(at.fetch_room(1) < 2 * LARGEST);

        // The next entry of the largest size does not fit beside that
        // room: the pull is refused, and nothing is counted for it. It is
        // no breach: the relay sized the page, and the asker cannot know
        // its room.
        not_now(at.pull(1, 1, &proved, mark, after));
        assert_eq!(at.fetch_room(1), MINUTE - 30 * LARGEST);
        assert_eq!(breaches(&at, 1), (0, 0));
        // A page with nothing in it is still answered: the end of the
        // channel, and a channel that is not held.
        let end = page(at.pull(1, 1, &proved, mark, 40));
        assert_eq!((end.entries.len(), end.next), (0, 40));
        assert!(page(at.pull(1, 9, &proved, mark, 0)).entries.is_empty());
        // And an entry that fits is still handed, one at a time.
        let one = page(at.pull(1, 2, &proved, relay::NO_MARK, 0));
        assert_eq!((one.entries.len(), one.next), (1, 1));
        assert_eq!(at.fetch_room(1), MINUTE - 30 * LARGEST - SMALL);

        // Asked for many more times than cut a peer off, it is refused
        // each time, and never a breach.
        for _ in 0..3 * BAN_THRESHOLD {
            not_now(at.pull(1, 1, &proved, mark, after));
        }
        assert_eq!(breaches(&at, 1), (0, 0));
        assert_eq!(at.fetch_room(1), MINUTE - 30 * LARGEST - SMALL);

        // Another connection, at another address, has an allowance of its
        // own.
        assert_eq!(page(at.pull(2, 1, &proved, mark, after)).entries.len(), 1);
    }

    /// A pull leaves room for the answer to a show (decision 2026-10-04
    /// §16). A key that has pulled all it may in the minute is still
    /// handed the entry when it shows an earlier one, though that entry
    /// is of the largest size. And where the keys at one address have
    /// between them pulled all that the address may be handed in pages,
    /// another key there is refused a page, and is still handed the
    /// entry: a device that pulls at its full rate, or shares its address
    /// with those that do, is still told of a removal.
    #[test]
    fn a_key_that_has_pulled_all_it_may_is_still_handed_the_answer_to_a_show() {
        let at = relay();
        for d in 1..=40 {
            at.hold(&largest(1, d), NOW);
        }
        // What the relay holds where a device will show an earlier entry.
        let later = largest(2, 1);
        at.hold(&later, NOW);
        let earlier = made(2, 1, 4, "n", "a small earlier one");
        let proved = having_proved(&[1]);

        // It pulls until it is refused.
        let (mut mark, mut after, mut pages) = (relay::NO_MARK, 0, 0);
        loop {
            match at.pull(1, 1, &proved, mark, after) {
                Answer::NotNow => break,
                answer => {
                    let page = page(answer);
                    assert!(!page.entries.is_empty());
                    (mark, after, pages) = (page.mark, page.next, pages + 1);
                    assert!(pages <= 40, "it is handed without bound");
                }
            }
        }
        let left = at.fetch_room(1);
        assert!((LARGEST..2 * LARGEST).contains(&left), "{left}");
        assert!(lock(&at.rates).pull_room(&peer(1), address(1)) < LARGEST);
        // It shows an earlier entry, and is handed the one that the relay
        // holds: the room was left for this.
        assert_eq!(
            shown(at.show(1, earlier.to_wire())),
            ShowAnswer::Another(later.to_wire())
        );
        assert_eq!(at.fetch_room(1), left - LARGEST);
        not_now(at.pull(1, 1, &proved, mark, after));
        assert_eq!(breaches(&at, 1), (0, 0));

        // An address. Five keys at it are each handed all that a key may
        // be in pages, and a sixth what is left to pages there.
        let home = address(50);
        let at_home = |n: u8| Who {
            peer: Box::leak(Box::new(peer(n))),
            address: home,
            listed: false,
        };
        assert_eq!(MAX_CONNECTIONS_PER_IP, 5);
        for n in 10..15 {
            assert!(lock(&at.rates).handed(&peer(n), home, MINUTE - LARGEST));
        }
        assert!(lock(&at.rates).handed(&peer(15), home, 4 * LARGEST));
        // A seventh key there is refused a page of a channel it proved.
        let seventh = at_home(16);
        let pull = EntryPull {
            channel: channel(1),
            mark: relay::NO_MARK,
            after: 0,
            limit: 100,
        };
        not_now(
            at.entries
                .pulling(&at.db, &at.rates, &seventh, &proved, &pull),
        );
        // It shows an earlier entry, and is handed the one that is held.
        let show = |who: &Who| {
            at.entries.answer(
                Protocol::EntryShow,
                &WireMessage::EntryShow(EntryShow {
                    entry: earlier.to_wire(),
                }),
                who,
                None,
                &mut Proved::default(),
                &mut ShownWhole::default(),
                &at.db,
                &at.rates,
                NOW,
            )
        };
        assert_eq!(shown(show(&seventh)), ShowAnswer::Another(later.to_wire()));
        // That was the address's room for one answer. Whoever shows from
        // that address after it is told "not now", for the minute: that
        // room can be used up from the address itself (§2.5).
        assert!(matches!(show(&at_home(17)), Answer::NotNow));
        assert_eq!(
            lock(&at.rates)
                .breaches_of_address(home)
                .map(|limiter| limiter.breach_count),
            Some(0)
        );
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
        // but 2000 bytes of what may be handed in pages in a minute:
        // what may be fetched, less the room for the answer to a show.
        lock(&at.rates).fetched(&peer(1), address(1), MINUTE - LARGEST - 2000);
        // One small entry fits, and is handed. The next does not.
        let one = page(at.pull(1, 1, &proved, relay::NO_MARK, 0));
        assert_eq!(one.entries.len(), 1);
        assert_eq!(at.fetch_room(1), LARGEST + 2000 - SMALL);
        not_now(at.pull(1, 1, &proved, one.mark, one.next));
        // And what was handed counts where the older kind looks: it is
        // one count.
        assert_eq!(
            lock(&at.rates).fetch_room(&peer(1), address(1)),
            LARGEST + 2000 - SMALL
        );

        // An address: its connections are handed in pages, between them,
        // five times what one may be, less the room for one answer to a
        // show. Five peers at one address are each handed all that a
        // connection may be in pages, and a sixth what the address has
        // left for them.
        let home = address(50);
        let at_home = |n: u8| Who {
            peer: Box::leak(Box::new(peer(n))),
            address: home,
            listed: false,
        };
        assert_eq!(MAX_CONNECTIONS_PER_IP, 5);
        for n in 10..15 {
            assert!(lock(&at.rates).handed(&peer(n), home, MINUTE - LARGEST));
        }
        assert!(lock(&at.rates).handed(&peer(15), home, 4 * LARGEST));
        // Another key at that address has a connection's allowance of its
        // own, and the address has none left for a page: nothing is
        // handed.
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

        // A small page's worth to a message: 150 small entries are two,
        // and 20 of the largest are twenty, one each.
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
        assert_eq!(
            sizes, [1; 20],
            "entries of the largest size were passed on more than a small page to a message"
        );
        for message in &waiting[0].1 {
            let bytes: usize = message.entries.iter().map(|e| e.entry.len()).sum();
            assert!(bytes <= SMALL_PAGE_BYTES);
            let travels = codec::encode_message(&WireMessage::RelayPush(message.clone()));
            assert!(travels.unwrap().len() <= SMALL_MESSAGE_BYTES as usize);
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
        /// Whether this end of the connection has every peer's windows.
        small_windows: bool,
    }

    impl<'a> Link<'a> {
        fn to(relay: &'a Relay) -> Self {
            Self {
                relay,
                asked: Mutex::default(),
                spoil: None,
                unanswered: None,
                small_windows: false,
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

        fn small_windows(&self) -> bool {
            self.small_windows
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
        let checked = relay::check_proof(&channel(3), &session, &peer(1).0, &proof).unwrap();
        {
            let db = other.db.lock().unwrap();
            assert!(relay::prove(&db, &checked).unwrap().answer());
            other.entries.used(&db, &channel(3), then + 2 * HOUR);
        }
        other.entries.write_uses(&other.db);

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
        let here = relay::pull(
            &lock(&this.db),
            &channel(2),
            true,
            &relay::NO_MARK,
            0,
            100,
            ENTRY_PAGE_MAX_BYTES,
        )
        .unwrap();
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

    /// A relay that pulls from a relay it works with is handed what
    /// that relay stores after a sweep took the entry it had stored last
    /// of a channel (decision 2026-10-04 §2.4 items 3 and 6): the place
    /// of the swept entry is not given again there, so the place that
    /// this relay keeps is below the next entry's, and it asks for it.
    #[tokio::test]
    async fn a_relay_pulls_what_is_stored_after_a_sweep_took_the_last_place() {
        let other = relay_of(u64::MAX, &[9]);
        let this = relay_of(u64::MAX, &[8]);
        let then = now() - HOUR;
        let delete = Inside {
            name: "gone.md".to_string(),
            value: Value::Delete,
            chain: Some(Vec::new()),
        };
        let gone = Entry::seal(&secret(1), &device(1), 7, &delete).unwrap();
        other.hold(&small(1, 1, 5), then);
        other.hold(&gone.check().unwrap(), then);

        let link = Link::to(&other);
        this.entries.pull_from(&link, peer(8), &this.db).await;
        let mark = other.held(1).unwrap().mark;
        assert_eq!(link.pulls(), [(channel(1), mark, 0)]);
        assert_eq!(
            lock(&this.entries.places)
                .get(&peer(8), &channel(1))
                .map(|kept| kept.after),
            Some(2)
        );

        // The delete goes there at its 90 days, and an entry is stored
        // after it. The holding is the one it was.
        other.entries.sweep_deletes_at(&other.db, then + 90 * DAY);
        assert_eq!(other.held(1).unwrap().bytes, SMALL);
        let new = made(1, 2, 1, "new.md", "written after the sweep");
        other.hold(&new, now());
        assert_eq!(other.held(1).unwrap().mark, mark);

        // This relay asks from the place it kept, and is handed the new
        // entry.
        this.entries.pull_from(&link, peer(8), &this.db).await;
        assert_eq!(link.pulls(), [(channel(1), mark, 2)]);
        let here = relay::pull(
            &lock(&this.db),
            &channel(1),
            true,
            &relay::NO_MARK,
            0,
            100,
            ENTRY_PAGE_MAX_BYTES,
        )
        .unwrap();
        assert!(here.entries.iter().any(|entry| entry.id() == new.id()));
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
        // When it was last used is kept with this relay's uses, and
        // written with them.
        assert_eq!(this.held(1).unwrap().used_at, now - 3 * HOUR);
        assert_eq!(this.kept(1), Some(now - 5));
        this.entries.write_uses(&this.db);
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

            fn small_windows(&self) -> bool {
                false
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

    /// Each hour a relay drops the deletes that it has held for 90 days
    /// (decision 2026-10-04 §2.3, §7.3): what it holds of the channel is
    /// counted less by what went, and a channel of which nothing is left
    /// is held no more, with the relay's place in it at a relay it works
    /// with. A text is never swept.
    #[test]
    fn a_relay_sweeps_the_deletes_it_has_held_for_90_days_and_its_room_follows() {
        let at = relay_of(u64::MAX, &[8]);
        let delete = |c: u16, name: &str| {
            let inside = Inside {
                name: name.to_string(),
                value: Value::Delete,
                chain: Some(Vec::new()),
            };
            Entry::seal(&secret(c), &device(1), 7, &inside)
                .unwrap()
                .check()
                .unwrap()
        };
        // Channel 1: a text, and a delete. Channel 2: a delete alone.
        let (gone, alone) = (delete(1, "gone.md"), delete(2, "hand-over"));
        at.hold(&small(1, 1, 5), NOW);
        at.hold(&gone, NOW);
        at.hold(&alone, NOW);
        for c in [1, 2] {
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
        let cost = |entry: &CheckedEntry| entry_cost(entry.content.len());
        assert_eq!(at.used(), SMALL + cost(&gone) + cost(&alone));

        // A second short of 90 days nothing goes.
        at.entries.sweep_deletes_at(&at.db, NOW + 90 * DAY - 1);
        assert_eq!(at.used(), SMALL + cost(&gone) + cost(&alone));
        // At 90 days both deletes go. The first channel is counted at its
        // text alone. The second is held no more, and the place in it is
        // forgotten: taken again, it is pulled from the start.
        at.entries.sweep_deletes_at(&at.db, NOW + 90 * DAY);
        assert_eq!(at.used(), SMALL);
        assert_eq!(at.held(1).unwrap().bytes, SMALL);
        assert_eq!(at.held(2), None);
        let places = lock(&at.entries.places);
        assert_eq!(places.total(), 1);
        assert!(places.get(&peer(8), &channel(1)).is_some());
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

    /// What `relay` holds through the write of its answer to `request`,
    /// made on a stream of `protocol` on a connection that has proved
    /// `proved`: its bytes over
    /// what it held before the request was sent, and the length of the
    /// answer. The answer is not read past its length, so the relay is in
    /// its write when this is measured, as it is for a peer that does not
    /// read, up to STREAM_TIMEOUT_SECS.
    async fn held_through_the_write(
        relay: &Relay,
        protocol: Protocol,
        proved: &mut Proved,
        request: &[u8],
    ) -> (isize, usize) {
        use cordelia_network::codec::write_raw_frame;
        use tokio::io::AsyncReadExt;

        let peer = peer(1);
        let serving = Serving {
            conn: None,
            peer: &peer,
            address: address(1),
            db: &relay.db,
            rates: &relay.rates,
            permits: None,
        };
        let mut whole = ShownWhole::default();
        // Small pipes, so that what a pipe keeps for itself is small: the
        // answer's waits after its first byte.
        let (mut relay_w, mut peer_r) = tokio::io::duplex(1);
        let (mut peer_w, mut relay_r) = tokio::io::duplex(1024);
        let serve = relay.entries.serve(
            protocol,
            &mut relay_w,
            &mut relay_r,
            &serving,
            proved,
            &mut whole,
        );
        tokio::pin!(serve);
        let asker = async {
            let before = crate::counting::live();
            write_raw_frame(&mut peer_w, request).await.unwrap();
            let length = peer_r.read_u32().await.unwrap() as usize;
            (crate::counting::live() - before, length)
        };
        // Both on this thread, polled in turn.
        tokio::select! {
            biased;
            measured = asker => measured,
            served = &mut serve => panic!("the answer was written whole: {served:?}"),
        }
    }

    /// Through the write of its answer, a relay holds the answer as it is
    /// written and nothing else: not the request's frame, which a pull may
    /// pad to a message with fields that are not read, nor the request (a
    /// push of a page of entries), nor the answer as a message (a page). At most the answer's bytes, in the
    /// room they were written into, which grows by doubling, and 4 KiB.
    /// Each request is made twice, and measured the second time, so that
    /// what the relay keeps from the first on (its statements, the
    /// asker's allowance) is not counted.
    #[tokio::test]
    async fn a_request_is_not_held_while_its_answer_is_written() {
        use cordelia_core::protocol::MAX_MESSAGE_BYTES;
        use cordelia_network::codec::encode_message;
        const SLACK: isize = 4 * 1024;

        let pull_of = |c: u16| {
            encode_message(&WireMessage::EntryPull(EntryPull {
                channel: channel(c),
                mark: [0; 8],
                after: 0,
                limit: 100,
            }))
            .unwrap()
        };
        // A pull padded to a message with a field that is not read: of a
        // channel that was not proved, so its answer is small.
        let padded = {
            let mut pull = pull_of(2);
            // A map of the name and the four fields, and one field more.
            assert_eq!(pull[0], 0xa5);
            pull[0] = 0xa6;
            pull.extend([0x67]);
            pull.extend(b"padding");
            let room = MAX_MESSAGE_BYTES as usize - pull.len() - 5;
            pull.push(0x5a);
            pull.extend((room as u32).to_be_bytes());
            pull.extend(std::iter::repeat_n(0x70, room));
            pull
        };
        assert_eq!(padded.len(), MAX_MESSAGE_BYTES as usize);
        assert!(matches!(
            cordelia_network::codec::decode_message(Protocol::EntryPull, &padded),
            Ok(WireMessage::EntryPull(_))
        ));
        // A pull of a channel that was proved, whose answer is a page of
        // twelve entries of the largest size: asked by a relay listed by
        // key, which is given full pages (decision 2026-10-22 (memory),
        // rule 7). Anyone else is given a small one.
        let full = pull_of(1);
        // A push of twelve entries of the largest size, whose answer says
        // one word of each.
        let push = encode_message(&WireMessage::EntryPush(EntryPush {
            entries: (1..=12).map(|d| largest(3, d).to_wire().into()).collect(),
        }))
        .unwrap();
        assert!(push.len() > 700_000, "{}", push.len());

        for (what, protocol, request, proved, large) in [
            (
                "a pull padded to a message",
                Protocol::EntryPull,
                &padded,
                &[][..],
                false,
            ),
            (
                "a push of a page",
                Protocol::EntryPush,
                &push,
                &[][..],
                false,
            ),
            (
                "a pull answered with a page",
                Protocol::EntryPull,
                &full,
                &[1][..],
                true,
            ),
        ] {
            // The asker of the full page is listed by key.
            let relay = match large {
                true => relay_of(u64::MAX, &[1]),
                false => relay(),
            };
            for d in 1..=12 {
                relay.hold(&largest(1, d), NOW);
            }
            let mut proved = having_proved(proved);
            let _ = held_through_the_write(&relay, protocol, &mut proved, request).await;
            let (held, answer) =
                held_through_the_write(&relay, protocol, &mut proved, request).await;
            println!(
                "{what}, {} bytes: {held} bytes held through the write of an answer of {answer}",
                request.len()
            );
            assert!(
                held <= 2 * answer as isize + SLACK,
                "{what}: {held} bytes held through the write of an answer of {answer}"
            );
            assert_eq!(answer > 700_000, large, "{what}: an answer of {answer}");
        }
    }
    // ── The counters (decision 2026-10-22 §1.2, §7.3) ─────────────────

    /// What `at` counts of its streams, by the route's text: each line
    /// of the requests, the answers, the entries refused and the bytes.
    fn counts_of(at: &Relay) -> std::collections::BTreeMap<String, u64> {
        let load = cordelia_core::load::Load {
            streams: at.entries.counts.clone(),
            ..Default::default()
        };
        cordelia_core::load::render(&load, &cordelia_core::lock::LockTimes::default(), 0.0)
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| line.rsplit_once(' '))
            .filter(|(name, _)| {
                ["requests", "answers", "entries_refused", "stream_bytes"]
                    .iter()
                    .any(|of| name.starts_with(&format!("cordelia_{of}")))
            })
            .map(|(name, value)| (name.to_string(), value.parse().unwrap()))
            .collect()
    }

    /// The lines that moved from `before` to `after`, with how far.
    fn moved(
        before: &std::collections::BTreeMap<String, u64>,
        after: &std::collections::BTreeMap<String, u64>,
    ) -> Vec<(String, u64)> {
        after
            .iter()
            .filter(|(name, n)| before[*name] != **n)
            .map(|(name, n)| (name.clone(), n - before[name]))
            .collect()
    }

    /// Serve one stream of `protocol` for the peer numbered `n`, on a
    /// connection that has proved `proved`, with `frame` as its request.
    /// Returns the bytes written back.
    async fn served(
        at: &Relay,
        n: u8,
        protocol: Protocol,
        proved: &mut Proved,
        frame: &[u8],
    ) -> Vec<u8> {
        let peer = peer(n);
        let serving = Serving {
            conn: None,
            peer: &peer,
            address: address(n),
            db: &at.db,
            rates: &at.rates,
            permits: None,
        };
        let (mut relay_w, mut peer_r) = tokio::io::duplex(1 << 21);
        let (mut peer_w, mut relay_r) = tokio::io::duplex(1 << 21);
        codec::write_raw_frame(&mut peer_w, frame).await.unwrap();
        drop(peer_w);
        let mut whole = ShownWhole::default();
        let _ = at
            .entries
            .serve(
                protocol,
                &mut relay_w,
                &mut relay_r,
                &serving,
                proved,
                &mut whole,
            )
            .await;
        drop(relay_w);
        let mut back = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut peer_r, &mut back)
            .await
            .unwrap();
        back
    }

    /// The lines of a request of `kind` read, with `bytes` in, and what
    /// became of it.
    fn read_as(kind: &str, bytes: usize, answer: &str) -> Vec<(String, u64)> {
        vec![
            (
                format!("cordelia_answers_total{{kind=\"{kind}\",answer=\"{answer}\"}}"),
                1,
            ),
            (format!("cordelia_requests_total{{kind=\"{kind}\"}}"), 1),
            (
                format!("cordelia_stream_bytes_total{{kind=\"{kind}\",direction=\"in\"}}"),
                4 + bytes as u64,
            ),
        ]
    }

    /// With the bytes of the answer written, `back`.
    fn and_written(mut lines: Vec<(String, u64)>, kind: &str, back: &[u8]) -> Vec<(String, u64)> {
        lines.push((
            format!("cordelia_stream_bytes_total{{kind=\"{kind}\",direction=\"out\"}}"),
            back.len() as u64,
        ));
        lines.sort();
        lines
    }

    /// Each request a relay serves is counted as it is read, by its kind
    /// and with the bytes of its frame; what became of it is counted; and
    /// the bytes of its answer as it is written (decision 2026-10-22
    /// §1.2). Each moves for its own request, and nothing else moves: a
    /// short show and a pull answered; a frame on the stream of shows that
    /// is no message, counted as a whole show and stray; the stream
    /// between relays from a peer it does not list, stray; a push whose
    /// entry found no room, answered with the refusal counted; a push
    /// over the peer's bytes, refused for rate; and a pull for more than
    /// the peer may be handed for now, not now.
    #[tokio::test]
    async fn each_request_served_is_counted_by_its_kind_with_its_bytes_and_what_became_of_it() {
        let at = relay_of(SMALL - 1, &[]);
        let frame = |message: &WireMessage| codec::encode_message(message).unwrap();
        let entry = small(1, 1, 1);

        let short = frame(&short_of(&entry));
        let before = counts_of(&at);
        let back = served(&at, 1, Protocol::EntryShow, &mut Proved::default(), &short).await;
        assert!(!back.is_empty());
        let want = and_written(
            read_as("show_short", short.len(), "answered"),
            "show_short",
            &back,
        );
        assert_eq!(moved(&before, &counts_of(&at)), want);

        let pull = frame(&WireMessage::EntryPull(EntryPull {
            channel: channel(1),
            mark: relay::NO_MARK,
            after: 0,
            limit: 100,
        }));
        let before = counts_of(&at);
        let back = served(&at, 1, Protocol::EntryPull, &mut Proved::default(), &pull).await;
        let want = and_written(read_as("pull", pull.len(), "answered"), "pull", &back);
        assert_eq!(moved(&before, &counts_of(&at)), want);

        let nothing = vec![0xffu8; 40];
        let before = counts_of(&at);
        let back = served(
            &at,
            1,
            Protocol::EntryShow,
            &mut Proved::default(),
            &nothing,
        )
        .await;
        assert!(back.is_empty());
        assert_eq!(
            moved(&before, &counts_of(&at)),
            read_as("show_whole", 40, "stray")
        );

        let ask = frame(&WireMessage::RelayChannelsAsk(RelayChannelsAsk {
            after: [0; 32],
            limit: 10,
        }));
        let before = counts_of(&at);
        let back = served(&at, 1, Protocol::RelayEntries, &mut Proved::default(), &ask).await;
        assert!(back.is_empty());
        assert_eq!(
            moved(&before, &counts_of(&at)),
            read_as("relays", ask.len(), "stray")
        );

        let push = frame(&WireMessage::EntryPush(EntryPush {
            entries: vec![entry.to_wire().into()],
        }));
        let before = counts_of(&at);
        let back = served(&at, 2, Protocol::EntryPush, &mut Proved::default(), &push).await;
        let mut want = read_as("push", push.len(), "answered");
        want.push((
            "cordelia_entries_refused_total{kind=\"push\",answer=\"refused_for_room\"}".into(),
            1,
        ));
        assert_eq!(
            moved(&before, &counts_of(&at)),
            and_written(want, "push", &back)
        );

        lock(&at.rates).count_pushed(&peer(3), address(3), MINUTE);
        let before = counts_of(&at);
        let back = served(&at, 3, Protocol::EntryPush, &mut Proved::default(), &push).await;
        assert!(back.is_empty());
        assert_eq!(
            moved(&before, &counts_of(&at)),
            read_as("push", push.len(), "refused_for_rate")
        );

        lock(&at.rates).fetched(&peer(4), address(4), MINUTE);
        let before = counts_of(&at);
        let back = served(&at, 4, Protocol::EntryPull, &mut having_proved(&[1]), &pull).await;
        assert!(back.is_empty());
        assert_eq!(
            moved(&before, &counts_of(&at)),
            read_as("pull", pull.len(), "not_now")
        );
    }

    /// A pull of channel 1, from its start, as its frame.
    fn pull_frame() -> Vec<u8> {
        codec::encode_message(&WireMessage::EntryPull(EntryPull {
            channel: channel(1),
            mark: relay::NO_MARK,
            after: 0,
            limit: 100,
        }))
        .unwrap()
    }

    /// A request is counted as it is read, with its bytes, before its
    /// answer is made; what became of it, once it is (decision 2026-10-22
    /// §1.2). While the lock is held, a pull waits for it: it is counted
    /// read, and not yet answered; once the lock is let go, it is
    /// answered.
    #[test]
    fn a_request_is_counted_as_it_is_read_before_its_answer_is_made() {
        let at = relay();
        let pull = pull_frame();
        let read = "cordelia_requests_total{kind=\"pull\"}";
        let answered = "cordelia_answers_total{kind=\"pull\",answer=\"answered\"}";
        let before = counts_of(&at);
        let held = at.db.lock().unwrap();
        let back = std::thread::scope(|scope| {
            let serving = scope.spawn(|| {
                let mut proved = having_proved(&[1]);
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(served(&at, 1, Protocol::EntryPull, &mut proved, &pull))
            });
            let waited = Instant::now();
            while counts_of(&at)[read] == before[read] {
                assert!(
                    waited.elapsed() < Duration::from_secs(10),
                    "a request waiting for the lock was not counted as read"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(counts_of(&at)[answered], before[answered]);
            drop(held);
            serving.join().unwrap()
        });
        assert!(!back.is_empty());
        let want = and_written(read_as("pull", pull.len(), "answered"), "pull", &back);
        assert_eq!(moved(&before, &counts_of(&at)), want);
    }

    /// An answer that could not be written is no answer: its request is
    /// counted as read and as not served, and no byte as written (decision
    /// 2026-10-22 §1.2). The peer's end is gone before the relay writes.
    #[tokio::test]
    async fn a_request_whose_answer_could_not_be_written_is_not_served() {
        let at = relay();
        let pull = pull_frame();
        let peer = peer(1);
        let serving = Serving {
            conn: None,
            peer: &peer,
            address: address(1),
            db: &at.db,
            rates: &at.rates,
            permits: None,
        };
        let (mut relay_w, peer_r) = tokio::io::duplex(1 << 21);
        drop(peer_r);
        let (mut peer_w, mut relay_r) = tokio::io::duplex(1 << 21);
        codec::write_raw_frame(&mut peer_w, &pull).await.unwrap();
        drop(peer_w);
        let before = counts_of(&at);
        let mut proved = having_proved(&[1]);
        let mut whole = ShownWhole::default();
        let over = at
            .entries
            .serve(
                Protocol::EntryPull,
                &mut relay_w,
                &mut relay_r,
                &serving,
                &mut proved,
                &mut whole,
            )
            .await;
        assert!(over.is_none());
        assert_eq!(
            moved(&before, &counts_of(&at)),
            read_as("pull", pull.len(), "not_served")
        );
    }

    /// A request whose frame is longer than a small message, from a peer
    /// that is not a listed relay, for which no large permit came within
    /// STREAM_TIMEOUT_SECS, is counted: a request of its stream, of the
    /// bytes of its length, which alone were read, refused to be sent
    /// again later, and no breach (decision 2026-10-22 §1.2).
    #[tokio::test(start_paused = true)]
    async fn a_request_refused_at_its_length_for_want_of_a_permit_is_counted() {
        let at = relay();
        let permits = crate::p2p::LargePermits::new(0);
        let peer = peer(1);
        let serving = Serving {
            conn: None,
            peer: &peer,
            address: address(1),
            db: &at.db,
            rates: &at.rates,
            permits: Some(&permits),
        };
        let (mut relay_w, _peer_r) = tokio::io::duplex(1 << 16);
        let (mut peer_w, mut relay_r) = tokio::io::duplex(1 << 16);
        let length = (cordelia_core::protocol::SMALL_MESSAGE_BYTES + 1).to_be_bytes();
        tokio::io::AsyncWriteExt::write_all(&mut peer_w, &length)
            .await
            .unwrap();
        let before = counts_of(&at);
        let mut whole = ShownWhole::default();
        let over = at
            .entries
            .serve(
                Protocol::EntryPush,
                &mut relay_w,
                &mut relay_r,
                &serving,
                &mut Proved::default(),
                &mut whole,
            )
            .await;
        assert!(over.is_none(), "no breach");
        assert_eq!(
            moved(&before, &counts_of(&at)),
            read_as("push", 0, "large_later")
        );
        drop(peer_w);
    }

    /// The entries refused in an answer are counted for room and for the
    /// allowance of new channels; one refused as not signed is neither,
    /// and an answer that refuses nothing counts none (decision
    /// 2026-10-22 §1.2).
    #[test]
    fn the_entries_refused_for_room_and_for_new_channels_are_told_from_an_answer() {
        let pushed = |answers: Vec<PushAnswer>| WireMessage::EntryPushed(EntryPushed { answers });
        assert_eq!(
            refusals(&pushed(vec![
                PushAnswer::Stored,
                PushAnswer::Refused(EntryRefused::NoRoom),
                PushAnswer::Refused(EntryRefused::NotSigned),
                PushAnswer::Refused(EntryRefused::OverLimit),
                PushAnswer::Refused(EntryRefused::NoRoom),
            ])),
            [Refusal::Room, Refusal::NewChannels, Refusal::Room]
        );
        let shown = |answer| WireMessage::EntryShown(EntryShown { answer });
        assert_eq!(
            refusals(&shown(ShowAnswer::Refused(EntryRefused::OverLimit))),
            [Refusal::NewChannels]
        );
        assert_eq!(refusals(&shown(ShowAnswer::Taken)), []);
        assert_eq!(refusals(&pushed(vec![PushAnswer::Held])), []);
    }

    /// The kinds whose takes of the lock moved, and how many each.
    fn takes(at: &Relay) -> Vec<(Kind, u64)> {
        Kind::ALL
            .into_iter()
            .map(|kind| (kind, at.db.times().hold(kind).count))
            .filter(|(_, count)| *count > 0)
            .collect()
    }

    /// Each take of the lock in a request is of the request's kind, its
    /// wait and its hold, and of no other (decision 2026-10-22 §1.1, rule
    /// 4): a whole show, a short show of the entry shown whole, a pull of
    /// a proved channel and a push; the stream between relays; and a
    /// sweep of what nobody uses and of old deletes, and the room made at
    /// a start within a cap that came down.
    #[test]
    fn each_take_of_the_lock_in_a_request_is_of_its_kind() {
        let at = relay_of(u64::MAX, &[9]);
        let entry = small(1, 1, 1);
        let mut whole = ShownWhole::default();
        at.show_on(1, &mut whole, whole_of(&entry));
        assert_eq!(takes(&at), [(Kind::ShowWhole, 1)]);
        at.show_on(1, &mut whole, short_of(&entry));
        assert_eq!(takes(&at), [(Kind::ShowWhole, 1), (Kind::ShowShort, 1)]);
        let pull = WireMessage::EntryPull(EntryPull {
            channel: channel(1),
            mark: relay::NO_MARK,
            after: 0,
            limit: 100,
        });
        page(at.answer(1, Protocol::EntryPull, pull, None, &mut having_proved(&[1])));
        pushed(at.push(2, vec![small(2, 2, 1).to_wire()]));
        let ask = WireMessage::RelayChannelsAsk(RelayChannelsAsk {
            after: [0; 32],
            limit: 10,
        });
        said(at.answer(9, Protocol::RelayEntries, ask, None, &mut Proved::default()));
        at.entries.sweep_at(&at.db, NOW);
        at.entries.sweep_deletes_at(&at.db, NOW);
        at.entries.make_room(&at.db);
        assert_eq!(
            takes(&at),
            [
                (Kind::ShowWhole, 1),
                (Kind::ShowShort, 1),
                (Kind::Pull, 1),
                (Kind::Push, 1),
                (Kind::Relays, 1),
                (Kind::Sweep, 3),
            ]
        );
        for kind in Kind::ALL {
            assert_eq!(
                at.db.times().wait(kind).count,
                at.db.times().hold(kind).count,
                "{kind:?}"
            );
        }
    }

    /// A relay's own pull from a relay it lists takes the lock as the
    /// stream between relays, and as nothing else (decision 2026-10-22
    /// §1.1, rule 4).
    #[tokio::test]
    async fn a_relays_pull_from_a_listed_relay_takes_the_lock_as_the_stream_between_relays() {
        let other = relay_of(u64::MAX, &[9]);
        let this = relay_of(u64::MAX, &[8]);
        other.hold(&small(1, 1, 5), now());
        this.entries
            .pull_from(&Link::to(&other), peer(8), &this.db)
            .await;
        let taken = takes(&this);
        assert_eq!(taken.len(), 1, "{taken:?}");
        assert_eq!(taken[0].0, Kind::Relays);
        assert!(this.held(1).is_some(), "the pull took what it lacked");
    }

    /// The waits for the rates and for the room, each taken while the
    /// lock is held, are timed apart as the one each is (decision
    /// 2026-10-22 §1.1, rule 4): a push takes the room under the lock and
    /// not the rates; a pull of a proved channel by a peer that is not
    /// listed takes the rates under it to count what it is handed, and
    /// not the room; a whole show that is taken takes the room.
    #[test]
    fn a_wait_for_the_rates_or_the_room_under_the_lock_is_timed_apart() {
        let at = relay();
        let nested = |at: &Relay| {
            let times = at.db.times();
            (
                times.nested(Nested::Rates).count,
                times.nested(Nested::Room).count,
            )
        };
        pushed(at.push(1, vec![small(1, 1, 1).to_wire()]));
        assert_eq!(nested(&at), (0, 1));
        page(at.pull(2, 1, &having_proved(&[1]), relay::NO_MARK, 0));
        assert_eq!(nested(&at), (1, 1));
        assert_eq!(
            shown(at.show(3, small(2, 3, 1).to_wire())),
            ShowAnswer::Taken
        );
        assert_eq!(nested(&at), (1, 2));
    }

    // ── Every head (decision 2026-10-24 (removal), rules 16 and 17) ──

    /// A change entry of channel `c` by device `d`, numbered `rev`, whose
    /// statement is named `name` and whose chain is the statements named
    /// `chain`: what a relay reads of it is its lineage alone.
    fn change(c: u16, d: u8, rev: u64, name: u8, chain: &[u8]) -> CheckedEntry {
        use cordelia_core::protocol::{
            CHANGE_ENTRY_BYTES, LABEL_ENTRY_AUTHOR, LABEL_ENTRY_CHANNEL,
        };
        let lineage = Lineage {
            made_at: NOW as u64,
            statement: [name; 8],
            chain: chain.iter().map(|link| [*link; 8]).collect(),
        };
        let tail = lineage.to_bytes().unwrap();
        let mut content = vec![0u8; CHANGE_ENTRY_BYTES - tail.len()];
        content.extend(tail);
        let key = derive::signing_key(&secret(c)).unwrap();
        let mut entry = Entry {
            channel: channel(c),
            slot: [0x33; 32],
            author: device(d).public_key(),
            rev,
            delete: false,
            content,
            author_signature: [0; 64],
            channel_signature: [0; 64],
        };
        let form = entry.signed_bytes();
        entry.author_signature = device(d).sign(&[LABEL_ENTRY_AUTHOR, form.as_slice()].concat());
        entry.channel_signature = key.sign(&[LABEL_ENTRY_CHANNEL, form.as_slice()].concat());
        entry.check().unwrap()
    }

    /// The laptop's change 3 and the desktop's, each made after change 2
    /// and apart from each other (the record's section 0).
    fn made_apart(c: u16) -> (CheckedEntry, CheckedEntry) {
        (
            change(c, 1, 3, 0x13, &[0x01, 0x02]),
            change(c, 1, 3, 0x23, &[0x01, 0x02]),
        )
    }

    /// The ID of the entry a show was answered with whole.
    fn handed_whole(answer: &ShowAnswer) -> Option<[u8; 32]> {
        match answer {
            ShowAnswer::Another(bytes) => Some(Entry::from_wire(bytes).unwrap().id()),
            _ => None,
        }
    }

    /// Rule 16 on a connection: the relay hands each head whole once on
    /// it, and remembers it as handed, so that it may be shown in short; a
    /// short show answered `Other` hands nothing, and the whole show that
    /// follows is handed the head; "held" comes only after. Another
    /// connection is handed each again.
    #[test]
    fn a_connection_is_handed_each_head_whole_once_before_it_is_told_held() {
        let at = relay();
        let (laptop, desktop) = made_apart(1);
        let short = |entry: &CheckedEntry| short_of(entry);

        // The tablet's connection: it showed the laptop's change whole when
        // the relay kept that alone.
        let mut tablet = ShownWhole::default();
        assert_eq!(
            at.show_on(1, &mut tablet, whole_of(&laptop)),
            ShowAnswer::Taken
        );
        assert_eq!(at.show_on(1, &mut tablet, short(&laptop)), ShowAnswer::Held);
        // The desktop's change comes, from another, which is handed the
        // laptop's before the relay says it took it.
        let mut desktops = ShownWhole::default();
        let answer = at.show_on(2, &mut desktops, whole_of(&desktop));
        assert_eq!(handed_whole(&answer), Some(laptop.id()));
        assert_eq!(
            at.show_on(2, &mut desktops, whole_of(&desktop)),
            ShowAnswer::Held
        );
        // Told of it in short, again and again: that hands nothing.
        for _ in 0..3 {
            assert_eq!(
                at.show_on(1, &mut tablet, short(&laptop)),
                ShowAnswer::Other {
                    rev: 3,
                    id: desktop.id()
                }
            );
        }
        // The whole show after it is handed it whole, and then the relay
        // says that it holds the entry shown.
        let answer = at.show_on(1, &mut tablet, whole_of(&laptop));
        assert_eq!(handed_whole(&answer), Some(desktop.id()));
        assert_eq!(at.show_on(1, &mut tablet, short(&laptop)), ShowAnswer::Held);
        assert_eq!(
            at.show_on(1, &mut tablet, whole_of(&laptop)),
            ShowAnswer::Held
        );
        // What it was handed whole it may show in short.
        assert_eq!(
            at.show_on(1, &mut tablet, short(&desktop)),
            ShowAnswer::Held
        );

        // A new connection is handed it again, whole once.
        let mut again = ShownWhole::default();
        assert_eq!(at.show_on(1, &mut again, short(&laptop)), ShowAnswer::Whole);
        let answer = at.show_on(1, &mut again, whole_of(&laptop));
        assert_eq!(handed_whole(&answer), Some(desktop.id()));
        assert_eq!(
            at.show_on(1, &mut again, whole_of(&laptop)),
            ShowAnswer::Held
        );
    }

    /// A head is remembered as handed only once the answer that hands it
    /// is written whole (the review of the whole build, its H2). A show
    /// whose answer cannot be written, the device gone or its stream reset,
    /// is handed the head again at the next show on the same connection,
    /// and the relay says "held" only after that: so a lost answer gives
    /// the device no leave without the removal.
    #[tokio::test]
    async fn a_head_whose_answer_was_not_written_is_handed_again() {
        let at = relay();
        let (laptop, desktop) = made_apart(1);
        // The relay keeps the laptop's change, and then the desktop's
        // beside it; the second connection was handed the laptop's.
        let mut first = ShownWhole::default();
        assert_eq!(
            at.show_on(1, &mut first, whole_of(&laptop)),
            ShowAnswer::Taken
        );
        let mut second = ShownWhole::default();
        let answer = at.show_on(2, &mut second, whole_of(&desktop));
        assert_eq!(handed_whole(&answer), Some(laptop.id()));

        // A third connection shows the desktop's change, as a device that
        // follows it does, on a stream whose answer cannot be written: the
        // device has gone from it.
        let peer3 = peer(3);
        let serving = Serving {
            conn: None,
            peer: &peer3,
            address: address(3),
            db: &at.db,
            rates: &at.rates,
            permits: None,
        };
        let mut proved = Proved::default();
        let mut third = ShownWhole::default();
        let (mut relay_w, peer_r) = tokio::io::duplex(1 << 20);
        drop(peer_r);
        let (mut peer_w, mut relay_r) = tokio::io::duplex(1 << 20);
        let frame = codec::encode_message(&whole_of(&desktop)).unwrap();
        codec::write_raw_frame(&mut peer_w, &frame).await.unwrap();
        at.entries
            .serve(
                Protocol::EntryShow,
                &mut relay_w,
                &mut relay_r,
                &serving,
                &mut proved,
                &mut third,
            )
            .await;
        // The next show on the same connection is handed the laptop's
        // change, whose first answer was lost, and only then told "held".
        let answer = at.show_on(3, &mut third, whole_of(&desktop));
        assert_eq!(
            handed_whole(&answer),
            Some(laptop.id()),
            "a head whose answer was never written counted as handed: {answer:?}"
        );
        assert_eq!(
            at.show_on(3, &mut third, whole_of(&desktop)),
            ShowAnswer::Held
        );

        // An answer made and dropped before its write hands nothing either.
        let mut fourth = ShownWhole::default();
        let answer = at.show_unwritten(4, &mut fourth, whole_of(&desktop));
        assert_eq!(handed_whole(&answer), Some(laptop.id()));
        let _ = fourth.take_handing();
        let answer = at.show_on(4, &mut fourth, whole_of(&desktop));
        assert_eq!(handed_whole(&answer), Some(laptop.id()));
    }

    /// Rule 17: a head that a relay keeps, beside another or alone, is
    /// offered to each relay it works with, but the one it came from, at
    /// each offer until that relay has answered for it: one connected then
    /// or not, and one whose offer was not answered. A head that the relay
    /// keeps no more waits no more. An entry that is no head is passed on
    /// once, as before.
    #[test]
    fn a_head_is_offered_again_until_each_relay_it_works_with_has_answered_for_it() {
        let at = relay_of(u64::MAX, &[8, 9]);
        let (laptop, desktop) = made_apart(1);
        let heads_in = |passed: &[(NodeId, Vec<RelayPush>)], n: u8| -> Vec<[u8; 32]> {
            let mut ids: Vec<[u8; 32]> = waiting_for(passed, n)
                .iter()
                .flatten()
                .map(|passed| Entry::from_wire(&passed.entry).unwrap().id())
                .collect();
            ids.sort();
            ids
        };
        let mut both = vec![laptop.id(), desktop.id()];
        both.sort();
        pushed(at.push(1, vec![laptop.to_wire()]));
        // The desktop's change from relay 8: not offered back to it.
        let from_8 = WireMessage::RelayPush(RelayPush {
            entries: vec![RelayEntry {
                entry: desktop.to_wire(),
                held_since: NOW,
                used_at: NOW,
            }],
        });
        let answer = at.answer(
            8,
            Protocol::RelayEntries,
            from_8,
            None,
            &mut Proved::default(),
        );
        assert_eq!(pushed(answer), [PushAnswer::Stored]);
        let text = small(2, 1, 5);
        pushed(at.push(1, vec![text.to_wire()]));

        // Relay 9 alone is connected: offered both heads and the text.
        let first = at.entries.to_pass_on(&at.db, &[peer(9)]);
        assert_eq!(heads_in(&first, 9).len(), 3);
        // While that offer is on its way, nothing more is offered to it.
        assert!(at.entries.to_pass_on(&at.db, &[peer(9)]).is_empty());
        // The offer ends unanswered: both heads are offered again, and the
        // text is not.
        RelayEntries::offer_ended(&at.entries.heads, &peer(9));
        let again = at.entries.to_pass_on(&at.db, &[peer(9)]);
        assert_eq!(heads_in(&again, 9), both);
        // Answered: offered to it no more.
        for message in &again[0].1 {
            RelayEntries::heads_answered(&at.entries.heads, &peer(9), message);
        }
        RelayEntries::offer_ended(&at.entries.heads, &peer(9));
        assert!(at.entries.to_pass_on(&at.db, &[peer(9)]).is_empty());

        // Relay 8, not connected when the relay took them, is offered the
        // laptop's change when it is: not the desktop's, which came from
        // it.
        let to_8 = at.entries.to_pass_on(&at.db, &[peer(8), peer(9)]);
        assert_eq!(heads_in(&to_8, 8), [laptop.id()]);
        assert!(heads_in(&to_8, 9).is_empty());
        RelayEntries::offer_ended(&at.entries.heads, &peer(8));

        // A settlement replaces both: they wait no more, and it does.
        let settles = change(1, 1, 4, 0x04, &[0x01, 0x02, 0x13, 0x23]);
        pushed(at.push(1, vec![settles.to_wire()]));
        let after = at.entries.to_pass_on(&at.db, &[peer(8), peer(9)]);
        assert_eq!(heads_in(&after, 8), [settles.id()]);
        assert_eq!(heads_in(&after, 9), [settles.id()]);
        RelayEntries::offer_ended(&at.entries.heads, &peer(8));
        RelayEntries::offer_ended(&at.entries.heads, &peer(9));

        // A head of a channel the relay dropped waits no more.
        relay::make_room(&lock(&at.db), 0).unwrap();
        assert!(
            at.entries
                .to_pass_on(&at.db, &[peer(8), peer(9)])
                .is_empty()
        );
        assert!(lock(&*at.entries.heads).heads.is_empty());
    }

    /// An offer of heads holds at most a page for each relay (the review
    /// of the whole build, its M1): of 40 heads that wait, each a change
    /// entry of 32 KB, an offer carries no more than ENTRY_PAGE_MAX_BYTES
    /// of them, those that waited longest first, and the rest are offered
    /// at the offers after, in order, until each is answered.
    ///
    /// Taken out: the page (all 40 go in one offer: the first fails).
    #[test]
    fn an_offer_of_heads_holds_at_most_a_page_for_each_relay() {
        let at = relay_of(u64::MAX, &[9]);
        let heads: Vec<CheckedEntry> = (0..40u16)
            .map(|n| change(100 + n, 1, 3, 0x13, &[0x01, 0x02]))
            .collect();
        for head in &heads {
            assert_eq!(
                pushed(at.push(1, vec![head.to_wire()])),
                [PushAnswer::Stored]
            );
        }
        let mut offered: Vec<[u8; 32]> = Vec::new();
        for _ in 0..heads.len() {
            let passed = at.entries.to_pass_on(&at.db, &[peer(9)]);
            if passed.is_empty() {
                break;
            }
            let messages = waiting_for(&passed, 9);
            let bytes: usize = messages
                .iter()
                .flatten()
                .map(|passed| passed.entry.len())
                .sum();
            assert!(
                bytes <= ENTRY_PAGE_MAX_BYTES,
                "an offer of {bytes} bytes of heads to one relay"
            );
            for message in &passed[0].1 {
                offered.extend(
                    message
                        .entries
                        .iter()
                        .map(|passed| Entry::from_wire(&passed.entry).unwrap().id()),
                );
                RelayEntries::heads_answered(&at.entries.heads, &peer(9), message);
            }
            RelayEntries::offer_ended(&at.entries.heads, &peer(9));
        }
        let ids: Vec<[u8; 32]> = heads.iter().map(|head| head.id()).collect();
        assert_eq!(
            offered, ids,
            "every head is offered once, in the order it waited"
        );
    }

    /// Rule 17, where the asker is over its allowance (the review of slice
    /// 6, its medium): the relay keeps the laptop's change 3, and a device
    /// whose address has been handed all it may be in the minute shows the
    /// desktop's removal. The removal is stored, and the device is told
    /// "not now", since the answer would hand it the laptop's change. The
    /// removal waits for the relay it works with all the same: a later show
    /// of it is answered "held", which passes nothing on.
    #[test]
    fn a_head_stored_by_a_show_answered_not_now_waits_to_be_offered() {
        let at = relay_of(u64::MAX, &[9]);
        let (laptop, desktop) = made_apart(1);
        pushed(at.push(1, vec![laptop.to_wire()]));
        let first = at.entries.to_pass_on(&at.db, &[peer(9)]);
        for message in &first[0].1 {
            RelayEntries::heads_answered(&at.entries.heads, &peer(9), message);
        }
        RelayEntries::offer_ended(&at.entries.heads, &peer(9));
        assert!(at.entries.to_pass_on(&at.db, &[peer(9)]).is_empty());

        // The device's address has been handed all it may be.
        lock(&at.rates).fetched(&peer(2), address(2), MINUTE);
        assert_eq!(at.fetch_room(2), 0);
        assert!(matches!(at.show(2, desktop.to_wire()), Answer::NotNow));
        // It was stored, and waits for relay 9.
        let offered: Vec<[u8; 32]> = waiting_for(&at.entries.to_pass_on(&at.db, &[peer(9)]), 9)
            .iter()
            .flatten()
            .map(|passed| Entry::from_wire(&passed.entry).unwrap().id())
            .collect();
        assert_eq!(offered, [desktop.id()]);
    }

    /// Rule 16 where the relay keeps eight heads (the review of slice 6,
    /// its second low): a device shows an entry that the relay does not
    /// keep, below all eight and made apart from them. It is handed each
    /// head once, and then, at every show, the first of them again: no
    /// head is put out of what the connection remembers, so none is handed
    /// anew. And a device that shows its eight, none of them kept, is
    /// handed the relay's eight once each.
    #[test]
    fn a_connection_that_shows_entries_not_kept_is_handed_each_head_once() {
        let at = relay();
        let heads: Vec<CheckedEntry> = (0..MAX_CHANGE_HEADS as u8)
            .map(|n| change(1, 1, 3 + u64::from(n), 0x30 + n, &[0x01, 0x02]))
            .collect();
        for head in &heads {
            pushed(at.push(1, vec![head.to_wire()]));
        }
        let mut order: Vec<[u8; 32]> = heads.iter().map(|head| head.id()).collect();
        let shown = change(1, 1, 2, 0x99, &[0x01]);
        let mut whole = ShownWhole::default();
        let handed: Vec<Option<[u8; 32]>> = (0..2 * MAX_CHANGE_HEADS)
            .map(|_| handed_whole(&at.show_on(2, &mut whole, whole_of(&shown))))
            .collect();
        let mut expected: Vec<Option<[u8; 32]>> = order.iter().copied().map(Some).collect();
        expected.extend(std::iter::repeat_n(Some(order[0]), MAX_CHANGE_HEADS));
        assert_eq!(handed, expected);

        // A device's own eight, the change it follows and seven set aside.
        let own: Vec<CheckedEntry> = (0..MAX_CHANGE_HEADS as u8)
            .map(|n| change(1, 1, 2, 0x90 + n, &[0x01]))
            .collect();
        let mut whole = ShownWhole::default();
        let mut handed = Vec::new();
        for _ in 0..2 {
            for entry in &own {
                if let Some(id) = handed_whole(&at.show_on(3, &mut whole, whole_of(entry))) {
                    if !handed.contains(&id) {
                        handed.push(id);
                    } else {
                        assert_eq!(id, order[0], "only the first is handed again");
                    }
                }
            }
        }
        handed.sort();
        order.sort();
        assert_eq!(handed, order);
    }
}
