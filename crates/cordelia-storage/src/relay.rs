//! What a relay does with the entries of channels from their secrets
//! (decision 2026-10-04 §2.4, §2.5).
//!
//! These are plain functions over a database connection. The clock is a
//! parameter, and so is whoever asks. Nothing here opens a stream or reads
//! one, and nothing here touches `items` or the channels of the older
//! kind: the two kinds are counted apart, each against a cap of its own,
//! and neither is refused or dropped to make room for the other (§2.5).
//!
//! ## Whose database
//!
//! **These rules are for a database that no device writes.** A relay
//! counts every entry of a channel in `entries` as its own to hold, and
//! drops them all with the channel. A device's own code writes the same
//! table, for the channels of its person, and what it holds there is not
//! a relay's to count or to drop.
//!
//! So each function here that writes or drops ([`take`], [`show`],
//! [`show_short`], [`make_room`], [`sweep_unused`], [`listed_relay_says`],
//! [`listed_relay_used`]) refuses, with
//! [`RelayError::DeviceFollowsAPhrase`], a database in which a device
//! follows a phrase ([`crate::person::person`]), and changes nothing in
//! it.
//!
//! ## What a relay takes
//!
//! Only an entry that passed the check ([`check`], which reads it from its
//! bytes, strictly, and looks at both signatures), and by the store's rule:
//! the newest revision for each author in each slot ([`take`], §2.4 items
//! 1 and 2). It needs no list of members and no state of the channel.
//!
//! ## Its room
//!
//! Room is counted by what entries are counted at
//! ([`cordelia_core::protocol::entry_cost`]), and never by the database's
//! pages, so an entry that replaces one of its size changes nothing (§16).
//!
//! - One channel may hold only so much ([`Room::max_channel_bytes`]).
//! - A write that would take the relay past its cap ([`Room::max_bytes`])
//!   is refused before anything is stored: the first entry of a channel
//!   that it does not hold, and an entry that makes a channel it holds
//!   hold more. So at its cap a relay takes no new channel, and no write
//!   makes it drop anything that it holds.
//! - A newer revision of an entry it holds, that is no larger, is never
//!   refused for room.
//! - A relay that holds more than its cap drops the channels it has held
//!   for the shortest time, until it is under ([`make_room`]). That is for
//!   a relay whose cap came down, and for its operator: whoever runs the
//!   relay calls it.
//! - One address may make it take only so many new channels in an hour:
//!   it is counted for each channel that the relay takes from it, and for
//!   none that was refused. A relay that the operator lists is not
//!   counted.
//!
//! ## How long it has held a channel
//!
//! A time for each channel, set when the relay first takes it. Where a
//! relay that the operator lists says it has held the channel since an
//! earlier time, the earlier of the two is kept, also for a channel
//! already held (§2.4 item 6). Nobody else can say so. A channel that was
//! dropped has no time: taken again, it is new from then.
//!
//! ## What it answers
//!
//! - **Shown an entry** ([`show`], §2.4 item 5): that it holds that very
//!   entry; that it held none from that author in that slot, or an earlier
//!   one, and took this one; or the other entry it holds from that author
//!   in that slot, at that revision or a later one.
//! - **Shown an entry in short** ([`show_short`], §2.4 item 5): its
//!   channel, its slot, its author, its revision and its ID, and nothing
//!   else of it. The relay holds that entry; or it holds none, or an
//!   earlier one, and the entry is to be shown whole; or it holds another
//!   at that revision or a later one, and says that one's revision and ID
//!   and no more. The answer never carries an entry. Who may show in short
//!   is the caller's to say: a connection that last showed that very entry
//!   whole in that slot.
//! - **A proof** ([`prove`], §2.4 items 3 and 4): yes or no. The signature
//!   is checked before the channel is looked up, and a proof that fails
//!   and a channel that is not held are answered alike. The caller is
//!   given the two apart, and may remember a proof that held.
//! - **A pull** ([`pull`]): a page of a channel's entries, only where the
//!   caller says the channel was proved on this connection. Without that
//!   it is answered as for a channel that is not held.
//!
//! ## One holding of a channel
//!
//! A place in a channel is a count of what the relay stored in it. A relay
//! that drops a channel and takes it again counts from 1 again, so a place
//! means something only within one holding. Each holding has a mark of
//! its own ([`Mark`]): 8 random bytes, made when the relay takes a channel
//! that it does not hold. Whoever asks for a page says the mark it holds
//! with its place, and is given the relay's. Where the two differ, the
//! place is from another holding, and the channel is handed from the
//! start.
//!
//! ## What nobody uses
//!
//! A time for each channel of when its key was last proved, or an entry of
//! it last shown that the relay holds. [`sweep_unused`] drops each channel
//! that was last used 90 days ago or longer (§2.5).
//!
//! The time is written at most once an hour for a channel, and never an
//! earlier time than the one kept (§16): a use is written down only where
//! it is more than an hour later than what is kept. A device proves and
//! shows on every pass, and each would otherwise be a write for whoever
//! asks. Whether to write is decided by reading: an answer that writes
//! nothing takes the database for reading alone. The same holds for the
//! time that a relay the operator lists says.
//!
//! ## Relays that work together
//!
//! Relays that their operator lists together pass entries between them
//! without the proof (§2.4 item 6). A relay that has a channel only from
//! another sees no proof of it and no entry of it shown, so each tells the
//! other two times with what it passes on: since when it has held the
//! channel, and when the channel was last used. The earlier of two "held
//! since" is kept ([`listed_relay_says`]), and the later of two "last
//! used" ([`listed_relay_used`]), never later than this relay's own clock.
//! A channel that is new here from such a relay was last used when that
//! relay says: taking it from a relay is no use of it. Which channels a
//! relay holds is told to a listed relay ([`held_channels`]), and to
//! nobody else: who is one, is the caller's to say.

use std::collections::HashMap;
use std::net::IpAddr;

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;
use cordelia_core::protocol::{
    CHANNEL_MARK_BYTES, ENTRY_CHANNEL_UNUSED_DAYS, ENTRY_CHANNEL_USED_STEP_SECS,
    ENTRY_PAGE_MAX_BYTES, ENTRY_PAGE_MAX_ENTRIES, ENTRY_WIRE_OVERHEAD_BYTES,
    MAX_ENTRY_CHANNEL_BYTES_AT_RELAY, NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR,
    RELAY_CHANNELS_PAGE_MAX, SESSION_VALUE_BYTES, entry_cost,
};
use cordelia_crypto::entry::{CheckedEntry, Entry, EntryError};
use cordelia_crypto::proof;
use cordelia_crypto::wire::WireError;

use crate::entries::{self, Outcome};

/// The hour that an address's allowance of new channels is counted over,
/// in seconds.
const HOUR_SECS: i64 = 60 * 60;

/// How long a channel that nobody uses is kept, in seconds.
const UNUSED_SECS: i64 = ENTRY_CHANNEL_UNUSED_DAYS as i64 * 24 * 60 * 60;

/// How much later than the time kept a use must be to be written, in
/// seconds.
const USED_STEP_SECS: i64 = ENTRY_CHANNEL_USED_STEP_SECS as i64;

/// How many entries a page is read from the store at a time.
const PAGE_READ: usize = 16;

/// The mark of one holding of a channel (see the module's documentation).
pub type Mark = [u8; CHANNEL_MARK_BYTES];

/// The mark of no holding: what an asker sends that has no place in a
/// channel yet. No holding has it.
pub const NO_MARK: Mark = [0; CHANNEL_MARK_BYTES];

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

/// Why a function here that writes or drops did nothing.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// A device follows a phrase in this database: it is a device's, and
    /// what it holds is not a relay's to count or to drop.
    #[error("a device follows a phrase in this database: a relay's rules are not for it")]
    DeviceFollowsAPhrase,

    /// The database could not be read or written, and nothing was changed.
    #[error(transparent)]
    Storage(#[from] CordeliaError),
}

/// Refuse a database in which a device follows a phrase (see the module's
/// documentation).
fn no_device_writes(conn: &Connection) -> Result<(), RelayError> {
    if crate::person::person(conn)?.is_some() {
        return Err(RelayError::DeviceFollowsAPhrase);
    }
    Ok(())
}

/// A relay's room for channels from their secrets (decision 2026-10-04
/// §2.5): its two caps, and what each address has made it take lately.
#[derive(Debug)]
pub struct Room {
    /// The most the relay holds of channels from their secrets, in bytes
    /// as entries are counted. It is this kind's own cap: what the relay
    /// holds of the older kind is not counted against it.
    pub max_bytes: u64,
    /// The most one channel may hold, in bytes as entries are counted.
    pub max_channel_bytes: u64,
    /// When each address made the relay take a channel it did not hold,
    /// within the last hour.
    new_channels: HashMap<IpAddr, Vec<i64>>,
    /// The channels that addresses made the relay take in a write that is
    /// not written for good yet. They are part of the address's share
    /// while the write is under way, stay counted once it is written
    /// ([`Room::written`]), and are taken back where it is undone
    /// ([`Room::undone`]).
    not_yet: Vec<(IpAddr, i64)>,
}

impl Room {
    /// For a relay that may hold `max_bytes` of channels from their
    /// secrets.
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            max_channel_bytes: MAX_ENTRY_CHANNEL_BYTES_AT_RELAY,
            new_channels: HashMap::new(),
            not_yet: Vec::new(),
        }
    }

    /// Whether `address` may make the relay take a channel it does not
    /// hold: no, where it has had its share for the hour that ends at
    /// `now` (NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR). Counts nothing.
    pub fn may_add_channel(&mut self, address: IpAddr, now: i64) -> bool {
        let Some(made) = self.new_channels.get_mut(&address) else {
            return true;
        };
        made.retain(|at| now - at < HOUR_SECS);
        made.len() < NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR
    }

    /// Count a channel that `address` made the relay take at `now`, in a
    /// write that is under way: it is part of the address's share from
    /// now, and is taken back where the write is undone.
    fn added_channel(&mut self, address: IpAddr, now: i64) {
        self.new_channels.entry(address).or_default().push(now);
        self.not_yet.push((address, now));
    }

    /// What was taken is written for good: each address stays counted for
    /// the channels it made the relay take in it.
    ///
    /// [`take`] and [`show`] call this themselves where the write is
    /// their own. Whoever takes several entries in one transaction of its
    /// own calls it once that is committed, and [`Room::undone`] where it
    /// is not: an address is not counted for a channel that the relay did
    /// not come to hold (decision 2026-10-04 §2.5).
    pub fn written(&mut self) {
        self.not_yet.clear();
    }

    /// What was taken was undone: no address is counted for it.
    pub fn undone(&mut self) {
        self.taken_back(0);
    }

    /// The channels that were counted in a write under way, after the
    /// first `kept` of them, are counted no more.
    fn taken_back(&mut self, kept: usize) {
        for (address, at) in self.not_yet.split_off(kept.min(self.not_yet.len())) {
            let Some(made) = self.new_channels.get_mut(&address) else {
                continue;
            };
            if let Some(counted) = made.iter().rposition(|made_at| *made_at == at) {
                made.remove(counted);
            }
            if made.is_empty() {
                self.new_channels.remove(&address);
            }
        }
    }

    /// One write ended: `own` says whether it was a write of its own, or
    /// part of a transaction of the caller's, `before` how many channels
    /// were under way when it began, and `done` whether it was done.
    fn ended(&mut self, own: bool, before: usize, done: bool) {
        if !done {
            self.taken_back(before);
        } else if own {
            self.written();
        }
    }

    /// Forget each address that has made the relay take no channel within
    /// the hour that ends at `now`.
    pub fn forget_old(&mut self, now: i64) {
        self.new_channels.retain(|_, made| {
            made.retain(|at| now - at < HOUR_SECS);
            !made.is_empty()
        });
    }
}

/// Who asks a relay to take an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asker {
    /// A connection from this address. A channel that it makes the relay
    /// take counts against the address's allowance for the hour. What is
    /// one address is the caller's to say.
    Address(IpAddr),
    /// A relay that the operator lists (decision 2026-10-04 §2.4 item 6).
    /// It is not counted by address, and it alone may say since when it
    /// has held the entry's channel, and when that channel was last used,
    /// each in seconds.
    ListedRelay {
        held_since: Option<i64>,
        used_at: Option<i64>,
    },
}

/// Why a relay did not take an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The bytes are not an entry's.
    NotAnEntry(WireError),
    /// It is not signed as it must be: a signature does not hold, or a
    /// key is one that anyone can sign for.
    NotSigned(EntryError),
    /// With the entry the relay would hold more than its cap: the first
    /// entry of a channel that it does not hold, or one that makes a
    /// channel it holds hold more. Nothing was stored.
    NoRoom,
    /// The entry's channel holds as much as one channel may.
    ChannelFull,
    /// The asker's address has made the relay take as many new channels
    /// as one address may in an hour.
    OverAllowance,
}

/// What became of an entry that a relay was asked to take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Taken {
    /// It was stored: the relay held none from its author in its slot, or
    /// a lower revision, which it replaces.
    Stored,
    /// The relay holds that very entry. It was not stored again.
    AlreadyHeld,
    /// The relay holds another entry from that author in that slot at
    /// that revision: one that the author signed apart from this one.
    /// This one was not stored, and the relay does not hold it.
    HeldAnother,
    /// The relay holds one at a higher revision from that author in that
    /// slot. It was not stored.
    OlderThanHeld,
    /// It was refused, and is not held.
    Refused(Refused),
}

/// What a relay answers to an entry it is shown (decision 2026-10-04 §2.4
/// item 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    /// The relay holds that very entry.
    Held,
    /// The relay held none from that author in that slot, or an earlier
    /// one, and took this one.
    Taken,
    /// The relay holds another entry from that author in that slot, at
    /// that revision or a later one: here it is.
    Another {
        entry: Box<CheckedEntry>,
        /// What the entry is counted at. It is handed to the asker as
        /// anything fetched is, and counts against the asker's limits.
        cost: u64,
    },
    /// The relay would have taken it, and did not.
    Refused(Refused),
}

/// What a relay answers to an entry that it is shown in short (decision
/// 2026-10-04 §2.4 item 5): by its channel, its slot, its author, its
/// revision and its ID. The answer never carries an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShownShort {
    /// The relay holds that very entry.
    Held,
    /// The relay holds none from that author in that slot, or an earlier
    /// one. It would take the entry, and cannot from its short form: the
    /// entry is to be shown whole.
    Whole,
    /// The relay holds another entry from that author in that slot, at
    /// that revision or a later one: that one's revision and ID, and no
    /// more.
    Other { rev: u64, id: [u8; 32] },
}

/// One page of a channel's entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// The entries, in the order this relay stored them, as they are
    /// stored: whoever receives them checks them.
    pub entries: Vec<Entry>,
    /// The place the next page starts after, in the channel's own order:
    /// the place of the last entry here, or the place that was asked
    /// after where there is none.
    pub next: u64,
    /// What the entries are counted at together. It counts against the
    /// asker's limits.
    pub cost: u64,
    /// The mark of the holding that `next` is a place in: the relay's,
    /// where it holds the channel and hands it. The one that was asked
    /// with, where the channel was not proved. And the mark of no holding
    /// where it was proved and is not held.
    pub mark: Mark,
}

/// What a relay found of a proof that a connection holds a channel's key
/// ([`prove`]): whether the proof holds, and whether the relay holds the
/// channel, as two things.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    /// The proof does not hold. The channel was not looked up.
    Fails,
    /// The proof holds: the other end of the connection holds the
    /// channel's key.
    Holds {
        /// Whether the relay holds the channel now.
        channel_held: bool,
    },
}

impl Proof {
    /// Whether the proof holds: what the caller may remember with the
    /// connection, whether or not the channel is held.
    pub fn holds(self) -> bool {
        matches!(self, Self::Holds { .. })
    }

    /// What the other end is told: yes only where the proof holds and the
    /// relay holds the channel. A no says neither which of the two it
    /// was.
    pub fn answer(self) -> bool {
        self == Self::Holds { channel_held: true }
    }
}

/// A channel that a relay holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldChannel {
    /// Since when the relay has held it, in seconds: when it first took
    /// it, or the earlier time that a relay the operator lists said.
    pub held_since: i64,
    /// When its key was last proved, or an entry of it last shown that
    /// the relay holds, in seconds: here, or at a relay the operator
    /// lists, by its word.
    pub used_at: i64,
    /// What it holds, in bytes as entries are counted.
    pub bytes: u64,
    /// The mark of this holding of it.
    pub mark: Mark,
}

/// A channel as a relay tells a relay it works with that it holds it
/// ([`held_channels`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToldChannel {
    /// The channel's ID.
    pub channel: [u8; 32],
    /// The channel as the relay holds it.
    pub held: HeldChannel,
    /// The place of the entry that the relay stored last in this holding
    /// of the channel: whoever has pulled as far as this lacks nothing of
    /// it.
    pub places: u64,
}

// ── What a relay takes ───────────────────────────────────────────────

/// Read an entry from its bytes on the wire, and check it: the door that
/// everything a relay is sent comes through. It touches no database.
///
/// Refused: bytes that are not an entry's, read strictly; and an entry
/// that is not signed as it must be. Only what passes is a
/// [`CheckedEntry`], and the functions here that store take nothing else.
pub fn check(bytes: &[u8]) -> Result<CheckedEntry, Refused> {
    Entry::from_wire(bytes)
        .map_err(Refused::NotAnEntry)?
        .check()
        .map_err(Refused::NotSigned)
}

/// Take an entry: store it by the store's rule, if the relay has room for
/// it (decision 2026-10-04 §2.4 items 1 and 2, §2.5). `now` is the relay's
/// time, in seconds.
///
/// An entry that the store's rule does not take is answered by that rule
/// ([`Taken::AlreadyHeld`], [`Taken::OlderThanHeld`]), whatever room there
/// is. The entry is stored and the relay's counts are changed as one: all
/// of it happens, or none.
///
/// Refused, with nothing changed, on a database in which a device follows
/// a phrase.
///
/// An address is counted for a channel that it made the relay take only
/// where the write is written for good. Where the write is part of a
/// transaction of the caller's, the caller says what became of that
/// ([`Room::written`], [`Room::undone`]).
pub fn take(
    conn: &Connection,
    room: &mut Room,
    entry: &CheckedEntry,
    asker: &Asker,
    now: i64,
) -> Result<Taken, RelayError> {
    let (own, before) = (conn.is_autocommit(), room.not_yet.len());
    let done = taken_as_one(conn, room, entry, asker, now);
    room.ended(own, before, done.is_ok());
    done
}

/// [`take`], as one write: all of it happens, or none.
fn taken_as_one(
    conn: &Connection,
    room: &mut Room,
    entry: &CheckedEntry,
    asker: &Asker,
    now: i64,
) -> Result<Taken, RelayError> {
    in_one(conn, || {
        no_device_writes(conn)?;
        said_by(conn, asker, &entry.channel, now)?;
        Ok(taken(conn, room, entry, asker, now)?)
    })
}

/// [`take`], inside what the caller began.
fn taken(
    conn: &Connection,
    room: &mut Room,
    entry: &CheckedEntry,
    asker: &Asker,
    now: i64,
) -> Result<Taken, CordeliaError> {
    // What the entry would replace, as it is counted. An entry at the
    // revision of the one held from its author in its slot, or below it,
    // replaces nothing: the store says which it is, and no room is asked
    // about.
    let replaced = match entries::author_cost(conn, &entry.channel, &entry.slot, &entry.author)? {
        Some((rev, _)) if rev >= entry.rev => {
            return match entries::store(conn, entry, now)? {
                // Held at that revision: that very entry, or another
                // that its author signed at it. The two are told apart
                // by what an entry is named by.
                Outcome::AlreadyHeld => {
                    let held =
                        entries::author_entry(conn, &entry.channel, &entry.slot, &entry.author)?;
                    match held.is_some_and(|held| held.entry.id() == entry.id()) {
                        true => Ok(Taken::AlreadyHeld),
                        false => Ok(Taken::HeldAnother),
                    }
                }
                Outcome::OlderThanHeld => Ok(Taken::OlderThanHeld),
                Outcome::Stored => Err(CordeliaError::Storage(
                    "an entry no newer than the one held was stored".into(),
                )),
            };
        }
        Some((_, replaced)) => replaced,
        None => 0,
    };

    // What the channel would hold with this entry, less what it replaces,
    // and how much more that is than it holds. A write that makes it hold
    // no more is always taken: a newer revision, of an entry the relay
    // holds, that is no larger.
    let held = held_channel(conn, &entry.channel)?;
    let holds = held.map_or(0, |held| held.bytes);
    let after = holds.saturating_sub(replaced) + entry_cost(entry.content.len());
    let more = after.saturating_sub(holds);

    // A write that would take the relay past its cap is refused here,
    // before anything is stored: no entry, no row, and nothing counted
    // against the address. The first entry of a channel it does not hold
    // is all of it more.
    if more > 0 && used_bytes(conn)?.saturating_add(more) > room.max_bytes {
        return Ok(Taken::Refused(Refused::NoRoom));
    }
    // A channel the relay does not hold: only if the address has not made
    // it take too many lately.
    if held.is_none()
        && let Asker::Address(address) = asker
        && !room.may_add_channel(*address, now)
    {
        return Ok(Taken::Refused(Refused::OverAllowance));
    }
    if more > 0 && after > room.max_channel_bytes {
        return Ok(Taken::Refused(Refused::ChannelFull));
    }

    if entries::store(conn, entry, now)? != Outcome::Stored {
        return Err(CordeliaError::Storage(
            "an entry newer than the one held was not stored".into(),
        ));
    }
    match held {
        Some(_) => {
            conn.execute(
                "UPDATE relay_channels SET bytes = ?2 WHERE channel_id = ?1",
                params![entry.channel.as_slice(), to_sql(after)],
            )
            .map_err(storage)?;
        }
        None => {
            // The relay holds the channel from now, or from the earlier
            // time that a relay the operator lists says.
            let since = match asker {
                Asker::ListedRelay {
                    held_since: Some(said),
                    ..
                } if *said > 0 => now.min(*said),
                _ => now,
            };
            // It is used now. From a relay the operator lists that says
            // when it was last used, it was last used then: that relay
            // passing it on is no use of it.
            let used = match asker {
                Asker::ListedRelay {
                    used_at: Some(last),
                    ..
                } if *last > 0 => now.min(*last),
                _ => now,
            };
            let bytes = entries::channel_cost(conn, &entry.channel)?;
            // This holding's own mark: another than any it had before.
            let mark = new_mark()?;
            conn.execute(
                "INSERT INTO relay_channels (channel_id, mark, held_since, used_at, bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    entry.channel.as_slice(),
                    mark.as_slice(),
                    since,
                    used,
                    to_sql(bytes)
                ],
            )
            .map_err(storage)?;
            // The address is counted for a channel that the relay took,
            // and that stays: nothing drops it for room.
            if let Asker::Address(address) = asker {
                room.added_channel(*address, now);
            }
        }
    }
    Ok(Taken::Stored)
}

// ── Its room ─────────────────────────────────────────────────────────

/// What the relay holds of channels from their secrets, in bytes as
/// entries are counted: what its cap is set against.
pub fn used_bytes(conn: &Connection) -> Result<u64, CordeliaError> {
    conn.query_row(
        "SELECT COALESCE(SUM(bytes), 0) FROM relay_channels",
        [],
        |row| row.get::<_, i64>(0),
    )
    .map(|bytes| bytes.max(0) as u64)
    .map_err(storage)
}

/// While the relay holds more than `max_bytes`, drop the channel it has
/// held for the shortest time: of two held since one time, the one it
/// took later. Returns the channels dropped, in the order they went.
///
/// So what was there first is never pushed out by what came later
/// (decision 2026-10-04 §2.5).
///
/// No write makes a relay hold more than its cap, so this is for a relay
/// whose cap came down, and for its operator. Whoever runs the relay
/// calls it with the relay's cap: nothing here calls it for a write.
///
/// Refused, with nothing dropped, on a database in which a device follows
/// a phrase.
pub fn make_room(conn: &Connection, max_bytes: u64) -> Result<Vec<[u8; 32]>, RelayError> {
    in_one(conn, || {
        no_device_writes(conn)?;
        Ok(dropped_for_room(conn, max_bytes)?)
    })
}

/// [`make_room`], inside what the caller began.
fn dropped_for_room(conn: &Connection, max_bytes: u64) -> Result<Vec<[u8; 32]>, CordeliaError> {
    let mut dropped = Vec::new();
    while used_bytes(conn)? > max_bytes {
        let newest: Option<[u8; 32]> = conn
            .query_row(
                "SELECT channel_id FROM relay_channels
                 ORDER BY held_since DESC, rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        let Some(newest) = newest else {
            break;
        };
        let entries = drop_channel(conn, &newest)?;
        tracing::warn!(
            channel = %hex::encode(&newest[..4]),
            entries,
            "over the cap: dropped the channel this relay has held for the shortest time"
        );
        dropped.push(newest);
    }
    Ok(dropped)
}

/// Drop a channel: its entries, and its row. Returns how many entries
/// went.
fn drop_channel(conn: &Connection, channel: &[u8; 32]) -> Result<usize, CordeliaError> {
    let entries = entries::remove_channel(conn, channel)?;
    conn.execute(
        "DELETE FROM relay_channels WHERE channel_id = ?1",
        params![channel.as_slice()],
    )
    .map_err(storage)?;
    Ok(entries)
}

/// A mark for a holding that begins: 8 random bytes, never all zeros,
/// which is the mark of no holding.
fn new_mark() -> Result<Mark, CordeliaError> {
    loop {
        let random = cordelia_crypto::generate_psk()
            .map_err(|e| CordeliaError::Storage(format!("no mark could be made: {e}")))?;
        let mut mark = NO_MARK;
        mark.copy_from_slice(&random[..CHANNEL_MARK_BYTES]);
        if mark != NO_MARK {
            return Ok(mark);
        }
    }
}

// ── How long it has held a channel ───────────────────────────────────

/// The channel as the relay holds it, or `None` where it does not.
pub fn held_channel(
    conn: &Connection,
    channel: &[u8; 32],
) -> Result<Option<HeldChannel>, CordeliaError> {
    conn.query_row(
        "SELECT held_since, used_at, bytes, mark FROM relay_channels WHERE channel_id = ?1",
        params![channel.as_slice()],
        held_channel_from_row,
    )
    .optional()
    .map_err(storage)
}

/// Map a row of `held_since, used_at, bytes, mark` to a [`HeldChannel`].
fn held_channel_from_row(row: &rusqlite::Row) -> rusqlite::Result<HeldChannel> {
    Ok(HeldChannel {
        held_since: row.get(0)?,
        used_at: row.get(1)?,
        bytes: row.get::<_, i64>(2)?.max(0) as u64,
        mark: row.get(3)?,
    })
}

/// The channels that the relay holds, in the order of their IDs, after
/// the ID `after` (all zeros is before the first), and at most `limit` of
/// them, never more than RELAY_CHANNELS_PAGE_MAX: one page of what a
/// relay tells a relay it works with (decision 2026-10-04 §2.4 item 6).
///
/// A relay tells nobody else which channels it holds (§2.4 item 4). The
/// caller says who the operator lists: this is called for no other.
pub fn held_channels(
    conn: &Connection,
    after: &[u8; 32],
    limit: u32,
) -> Result<Vec<ToldChannel>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT held_since, used_at, bytes, mark, channel_id,
                    (SELECT COALESCE(MAX(channel_place), 0) FROM entries
                     WHERE entries.channel_id = relay_channels.channel_id)
             FROM relay_channels WHERE channel_id > ?1
             ORDER BY channel_id LIMIT ?2",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map(
            params![after.as_slice(), limit.min(RELAY_CHANNELS_PAGE_MAX)],
            |row| {
                Ok(ToldChannel {
                    held: held_channel_from_row(row)?,
                    channel: row.get(4)?,
                    places: row.get::<_, i64>(5)?.max(0) as u64,
                })
            },
        )
        .map_err(storage)?;
    rows.collect::<Result<_, _>>().map_err(storage)
}

/// A relay that the operator lists says it has held `channel` since
/// `held_since`, in seconds (decision 2026-10-04 §2.4 item 6). Where this
/// relay holds the channel, and since a later time, the earlier is kept.
/// Returns whether it was.
///
/// The caller says who the operator lists: this is called for no other.
/// Nothing is kept for a channel that this relay does not hold, and a
/// time that is not after 0 is no time.
///
/// Refused, with nothing changed, on a database in which a device follows
/// a phrase.
pub fn listed_relay_says(
    conn: &Connection,
    channel: &[u8; 32],
    held_since: i64,
) -> Result<bool, RelayError> {
    in_one_reading(conn, || {
        no_device_writes(conn)?;
        Ok(kept_the_earlier(conn, channel, held_since)?)
    })
}

/// [`listed_relay_says`], inside what the caller began. What is kept is
/// read first: where the time said is no earlier, nothing is written.
fn kept_the_earlier(
    conn: &Connection,
    channel: &[u8; 32],
    held_since: i64,
) -> Result<bool, CordeliaError> {
    if held_since <= 0 {
        return Ok(false);
    }
    // Read first: where nothing is to be kept, nothing is written.
    let later = held_channel(conn, channel)?.is_some_and(|held| held.held_since > held_since);
    if !later {
        return Ok(false);
    }
    conn.execute(
        "UPDATE relay_channels SET held_since = ?2 WHERE channel_id = ?1 AND held_since > ?2",
        params![channel.as_slice(), held_since],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

/// A relay that the operator lists says that `channel` was last used at
/// `used_at`, in seconds: its key proved there, or an entry of it shown
/// that that relay holds (decision 2026-10-04 §2.4 item 6). Where this
/// relay holds the channel, and saw it used last at an earlier time, the
/// later is kept. Returns whether it was. `now` is this relay's time.
///
/// So a channel that this relay has only from another, and of which it
/// sees no proof and no entry shown, is not dropped as unused while it is
/// in use there.
///
/// No time later than `now` is kept: a relay whose clock runs ahead does
/// not keep a channel here beyond 90 days after this relay heard of its
/// use. The caller says who the operator lists: this is called for no
/// other. Nothing is kept for a channel that this relay does not hold,
/// and a time that is not after 0 is no time.
///
/// The time is kept only where it is more than an hour later than the one
/// this relay has (ENTRY_CHANNEL_USED_STEP_SECS): a relay is told of every
/// channel in every pass, and what it is told is no reason to write each
/// time. Where nothing is kept, the database is read and not written.
///
/// Refused, with nothing changed, on a database in which a device follows
/// a phrase.
pub fn listed_relay_used(
    conn: &Connection,
    channel: &[u8; 32],
    used_at: i64,
    now: i64,
) -> Result<bool, RelayError> {
    in_one_reading(conn, || {
        no_device_writes(conn)?;
        Ok(kept_the_later(conn, channel, used_at, now)?)
    })
}

/// [`listed_relay_used`], inside what the caller began. A time that is
/// not after 0 is never the later of two: a channel is held from a time
/// after 0, and was last used no earlier.
fn kept_the_later(
    conn: &Connection,
    channel: &[u8; 32],
    used_at: i64,
    now: i64,
) -> Result<bool, CordeliaError> {
    Ok(used_then(conn, channel, used_at.min(now))? == Some(true))
}

/// What the asker says of how long it has held `channel`, and of when it
/// was last used, kept where it may say so.
fn said_by(
    conn: &Connection,
    asker: &Asker,
    channel: &[u8; 32],
    now: i64,
) -> Result<(), CordeliaError> {
    if let Asker::ListedRelay {
        held_since,
        used_at,
    } = asker
    {
        if let Some(said) = held_since {
            kept_the_earlier(conn, channel, *said)?;
        }
        if let Some(last) = used_at {
            kept_the_later(conn, channel, *last, now)?;
        }
    }
    Ok(())
}

// ── What it answers ──────────────────────────────────────────────────

/// Answer an entry that the relay is shown (decision 2026-10-04 §2.4 item
/// 5), from the store. `entry` has passed the check: both signatures were
/// looked at before anything here is (§16).
///
/// What comes back with [`Shown::Another`] counts against the asker's
/// limits as anything fetched does: its cost is given with it.
///
/// Refused, with nothing changed, on a database in which a device follows
/// a phrase.
///
/// **An entry that the relay does not take is answered by reading.** A
/// device shows its entry on every pass, and nearly every time the relay
/// holds it. Whether the relay would take the entry is read first, and
/// decides how the database is taken: for writing where it would, and
/// otherwise for reading alone, with nothing written but when the channel
/// was last used, at most once an hour (§16).
pub fn show(
    conn: &Connection,
    room: &mut Room,
    entry: &CheckedEntry,
    asker: &Asker,
    now: i64,
) -> Result<Shown, RelayError> {
    no_device_writes(conn)?;
    let to_write = would_take(conn, entry)?;
    let (own, before) = (conn.is_autocommit(), room.not_yet.len());
    let done = in_one_begun(conn, to_write, || {
        no_device_writes(conn)?;
        Ok(shown(conn, room, entry, asker, now)?)
    });
    room.ended(own, before, done.is_ok());
    done
}

/// Whether the relay would take `entry` where it is shown: it holds none
/// from that author in that slot, or an earlier one.
fn would_take(conn: &Connection, entry: &CheckedEntry) -> Result<bool, CordeliaError> {
    let held = entries::author_cost(conn, &entry.channel, &entry.slot, &entry.author)?;
    Ok(held.is_none_or(|(rev, _)| rev < entry.rev))
}

/// [`show`], inside what the caller began.
fn shown(
    conn: &Connection,
    room: &mut Room,
    entry: &CheckedEntry,
    asker: &Asker,
    now: i64,
) -> Result<Shown, CordeliaError> {
    said_by(conn, asker, &entry.channel, now)?;
    match entries::author_entry(conn, &entry.channel, &entry.slot, &entry.author)? {
        Some(held) if held.entry.rev >= entry.rev => {
            if held.entry.id() == entry.id() {
                used(conn, &entry.channel, now)?;
                return Ok(Shown::Held);
            }
            let cost = entry_cost(held.entry.content.len());
            let other = held.entry.check().map_err(|e| {
                CordeliaError::Storage(format!("a stored entry does not pass the check: {e}"))
            })?;
            Ok(Shown::Another {
                entry: Box::new(other),
                cost,
            })
        }
        _ => match taken(conn, room, entry, asker, now)? {
            Taken::Stored => {
                used(conn, &entry.channel, now)?;
                Ok(Shown::Taken)
            }
            Taken::Refused(why) => Ok(Shown::Refused(why)),
            Taken::AlreadyHeld | Taken::HeldAnother | Taken::OlderThanHeld => Err(
                CordeliaError::Storage("an entry newer than the one held was not stored".into()),
            ),
        },
    }
}

/// Answer an entry that the relay is shown in short (decision 2026-10-04
/// §2.4 item 5): the entry of `author` in `slot` of `channel`, at `rev`,
/// whose ID is `id` ([`Entry::id`]). `now` is the relay's time, in
/// seconds.
///
/// The relay holds that very entry, which is use of the channel as with
/// the whole one. Or it holds none from that author in that slot, or an
/// earlier one: there is nothing here for it to take, and the entry is to
/// be shown whole. Or it holds another, at that revision or a later one,
/// and says that one's revision and ID, and no more: whoever is told of
/// one that it does not keep shows its own whole, and is answered with the
/// entry then.
///
/// **Whoever calls this says who may ask.** A short form is looked up only
/// for a connection that last showed that very entry whole in that slot,
/// with both signatures: anyone else could ask what a relay holds from an
/// ID alone. For any other the caller answers [`ShownShort::Whole`] from
/// what it remembers of the connection, and does not call this at all.
///
/// It is answered by reading: nothing is written but when the channel was
/// last used, at most once an hour (§16).
///
/// Refused, with nothing changed, on a database in which a device follows
/// a phrase.
pub fn show_short(
    conn: &Connection,
    channel: &[u8; 32],
    slot: &[u8; 32],
    author: &[u8; 32],
    rev: u64,
    id: &[u8; 32],
    now: i64,
) -> Result<ShownShort, RelayError> {
    in_one_reading(conn, || {
        no_device_writes(conn)?;
        Ok(shown_short(conn, (channel, slot, author), rev, id, now)?)
    })
}

/// [`show_short`], inside what the caller began. `place` is the channel,
/// the slot and the author.
fn shown_short(
    conn: &Connection,
    place: (&[u8; 32], &[u8; 32], &[u8; 32]),
    rev: u64,
    id: &[u8; 32],
    now: i64,
) -> Result<ShownShort, CordeliaError> {
    let (channel, slot, author) = place;
    match entries::author_entry(conn, channel, slot, author)? {
        Some(held) if held.entry.rev >= rev => {
            let held_id = held.entry.id();
            if held_id == *id {
                used(conn, channel, now)?;
                return Ok(ShownShort::Held);
            }
            Ok(ShownShort::Other {
                rev: held.entry.rev,
                id: held_id,
            })
        }
        _ => Ok(ShownShort::Whole),
    }
}

/// Check the proof that the other end of the connection whose TLS session
/// exports `session` sent, that it holds the key of `channel` (decision
/// 2026-10-04 §2.4 items 3 and 4). `prover` is the node key of the peer at
/// the other end, as the connection says it: a proof says which end made
/// it, and one that this end made is no proof when the other end sends it
/// back. `now` is the relay's time, in seconds.
///
/// The signature is checked first, and the channel is looked up only
/// where it holds. The caller is given the two apart ([`Proof`]): whether
/// the proof holds, and, where it does, whether the relay holds the
/// channel. A proof that holds for a channel the relay holds is use of
/// the channel.
///
/// **What the other end is told** is one thing, [`Proof::answer`]: yes
/// only where the proof holds and the channel is held. A proof that fails
/// and a channel that is not held are answered alike, so that nobody
/// without a channel's key learns whether the relay holds it.
///
/// **What the caller may remember** is that the proof held
/// ([`Proof::holds`]), for this channel, with this connection and for as
/// long as it lasts, whether or not the relay holds the channel now. A
/// channel that arrives later is then handed to the connection with no
/// proof more: the caller says so where the channel is asked for
/// ([`pull`]). It remembers nothing of a proof that failed, and nothing
/// beyond the connection: a proof is for the one session it was made
/// over. Whoever holds a secret can prove its channel, held or not, and
/// secrets cost nothing to make, so the caller bounds how many channels
/// it remembers for one connection.
pub fn prove(
    conn: &Connection,
    channel: &[u8; 32],
    session: &[u8; SESSION_VALUE_BYTES],
    prover: &[u8; 32],
    proof: &[u8; 64],
    now: i64,
) -> Result<Proof, CordeliaError> {
    if !proof::check(channel, session, prover, proof) {
        return Ok(Proof::Fails);
    }
    let channel_held = used(conn, channel, now)?;
    Ok(Proof::Holds { channel_held })
}

/// One page of the entries of `channel` that this relay stored after the
/// place `after`, at most `limit` of them (decision 2026-10-04 §2.4 item
/// 3).
///
/// A place is the channel's own: a count of the entries that the relay
/// stored in this channel, from 1. It says nothing of what the relay
/// stored in any other channel, so the places that a holder of one
/// channel's key is given do not tell it how much the relay stored for
/// anyone else in between.
///
/// **A place is within one holding of the channel.** A channel that was
/// dropped and is taken again counts from the start, under another mark.
/// `mark` is the mark that the asker holds with its place: [`NO_MARK`]
/// where it has none. The page says the relay's. Where the two differ,
/// `after` is a place in another holding, or in none, and means nothing
/// here: the channel is handed from the start. (Without the mark, whoever
/// kept a place from an earlier holding would be handed nothing until the
/// new count passed it.)
///
/// `proved` is whether the channel's key was proved on the connection
/// that asks: a proof that held there ([`Proof::holds`]), also one from
/// before the relay held the channel. Where it was not, nothing is said
/// of the channel: no entries, and the place and the mark that were asked
/// with. The store is not looked at.
///
/// **A channel that was proved and is not held is answered as no
/// holding:** no entries, [`NO_MARK`], and the start. Whoever holds the
/// channel's key and keeps a place in it then knows that the relay holds
/// nothing of it now, and so nothing of what it was sent: the relay
/// dropped the channel since. (A pull tells this only to a connection
/// that proved the key. A proof is answered yes only for a channel that
/// is held, so the same connection could have asked that.)
///
/// A page holds at most ENTRY_PAGE_MAX_ENTRIES entries, and at most
/// ENTRY_PAGE_MAX_BYTES of them as they travel, so that it fits one
/// message. It always holds the first entry there is, whatever its size.
pub fn pull(
    conn: &Connection,
    channel: &[u8; 32],
    proved: bool,
    mark: &Mark,
    after: u64,
    limit: u32,
) -> Result<Page, CordeliaError> {
    let mut page = Page {
        entries: Vec::new(),
        next: after,
        cost: 0,
        mark: *mark,
    };
    if !proved {
        return Ok(page);
    }
    // A channel that is not held has no holding to have a place in: the
    // asker is told so, by the mark of no holding.
    let Some(holding) = held_channel(conn, channel)? else {
        page.mark = NO_MARK;
        page.next = 0;
        return Ok(page);
    };
    // A place from another holding is no place in this one.
    let after = if holding.mark == *mark { after } else { 0 };
    page.mark = holding.mark;
    page.next = after;
    let most = limit.min(ENTRY_PAGE_MAX_ENTRIES) as usize;
    let mut place = i64::try_from(after).unwrap_or(i64::MAX);
    let mut bytes = 0;
    while page.entries.len() < most {
        let ask = (most - page.entries.len()).min(PAGE_READ);
        let read = entries::channel_entries_after_place(conn, channel, place, ask as u32)?;
        let last = read.len() < ask;
        for held in read {
            let travels = ENTRY_WIRE_OVERHEAD_BYTES + held.entry.content.len();
            if !page.entries.is_empty() && bytes + travels > ENTRY_PAGE_MAX_BYTES {
                return Ok(page);
            }
            bytes += travels;
            place = held.channel_place;
            page.next = held.channel_place.max(0) as u64;
            page.cost += entry_cost(held.entry.content.len());
            page.entries.push(held.entry);
        }
        if last {
            break;
        }
    }
    Ok(page)
}

// ── What nobody uses ─────────────────────────────────────────────────

/// The channel was used at `now`: its key was proved, or an entry of it
/// was shown that the relay holds. Returns whether the relay holds it.
fn used(conn: &Connection, channel: &[u8; 32], now: i64) -> Result<bool, CordeliaError> {
    Ok(used_then(conn, channel, now)?.is_some())
}

/// The channel was used at `at`, here or at a relay that the operator
/// lists. `None` where the relay does not hold it, and otherwise whether
/// the time was written down.
///
/// It is written only where it is more than an hour later than the time
/// kept (decision 2026-10-04 §16), and so never an earlier time than that
/// one. The time kept is read first, and decides: where nothing is
/// written, no statement that writes is run, so the database is not taken
/// for writing.
fn used_then(
    conn: &Connection,
    channel: &[u8; 32],
    at: i64,
) -> Result<Option<bool>, CordeliaError> {
    let Some(held) = held_channel(conn, channel)? else {
        return Ok(None);
    };
    if at.saturating_sub(held.used_at) <= USED_STEP_SECS {
        return Ok(Some(false));
    }
    write_used(conn, channel, at).map(Some)
}

/// Write down that `channel` was last used at `at`, where that is later
/// than the time kept: the write itself never puts down an earlier time,
/// whoever calls it and whatever was read before. Returns whether it was
/// written.
fn write_used(conn: &Connection, channel: &[u8; 32], at: i64) -> Result<bool, CordeliaError> {
    conn.execute(
        "UPDATE relay_channels SET used_at = ?2 WHERE channel_id = ?1 AND used_at < ?2",
        params![channel.as_slice(), at],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

/// Drop each channel that nobody has used for 90 days (decision
/// 2026-10-04 §2.5): whose key no connection has proved, and of which
/// nobody has shown an entry that the relay holds, since 90 days before
/// `now`, the relay's time in seconds. Returns the channels dropped.
///
/// Refused, with nothing dropped, on a database in which a device follows
/// a phrase.
pub fn sweep_unused(conn: &Connection, now: i64) -> Result<Vec<[u8; 32]>, RelayError> {
    in_one(conn, || {
        no_device_writes(conn)?;
        Ok(swept(conn, now)?)
    })
}

/// Whether a channel that was last used at `used_at` is one that nobody
/// uses at `now`, both in seconds: the rule of [`sweep_unused`], for a
/// relay that is told when a channel was last used and does not hold it.
/// It takes no such channel from a relay it works with: it would drop it
/// at its next sweep.
pub fn unused(used_at: i64, now: i64) -> bool {
    used_at.saturating_add(UNUSED_SECS) <= now
}

/// [`sweep_unused`], inside what the caller began.
fn swept(conn: &Connection, now: i64) -> Result<Vec<[u8; 32]>, CordeliaError> {
    let unused: Vec<[u8; 32]> = {
        let mut stmt = conn
            .prepare(
                "SELECT channel_id FROM relay_channels WHERE used_at + ?1 <= ?2
                 ORDER BY used_at, rowid",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map(params![UNUSED_SECS, now], |row| row.get(0))
            .map_err(storage)?;
        rows.collect::<Result<_, _>>().map_err(storage)?
    };
    for channel in &unused {
        drop_channel(conn, channel)?;
    }
    Ok(unused)
}

// ── As one ───────────────────────────────────────────────────────────

/// A count of bytes as the database holds it.
fn to_sql(bytes: u64) -> i64 {
    i64::try_from(bytes).unwrap_or(i64::MAX)
}

/// Run `work` as one: everything it writes is written, or nothing is.
///
/// It is a transaction of its own, which takes the database for writing
/// before it reads, so that what it reads is what it writes over. Inside a
/// transaction of the caller's it is a savepoint, and is whole with that
/// one. Where the work fails, or unwinds, what it wrote is undone.
fn in_one<T>(
    conn: &Connection,
    work: impl FnOnce() -> Result<T, RelayError>,
) -> Result<T, RelayError> {
    in_one_begun(conn, true, work)
}

/// [`in_one`], for work that mostly writes nothing: the database is taken
/// for reading, and for writing only where the work comes to write
/// (decision 2026-10-04 §16). So an answer that is read from what the
/// relay holds waits for no writer, and makes none wait.
///
/// What the work reads is still what it writes over: where another
/// writer came between, its write is refused, and nothing is changed.
fn in_one_reading<T>(
    conn: &Connection,
    work: impl FnOnce() -> Result<T, RelayError>,
) -> Result<T, RelayError> {
    in_one_begun(conn, false, work)
}

/// Run `work` as one: in a transaction of its own, which takes the
/// database for writing at once where `to_write` says so and otherwise
/// when the work first writes, or in a savepoint inside a transaction of
/// the caller's.
fn in_one_begun<T>(
    conn: &Connection,
    to_write: bool,
    work: impl FnOnce() -> Result<T, RelayError>,
) -> Result<T, RelayError> {
    let storage = |e: rusqlite::Error| RelayError::Storage(storage(e));
    let (begin, commit, undo) = if conn.is_autocommit() && to_write {
        ("BEGIN IMMEDIATE", "COMMIT", "ROLLBACK")
    } else if conn.is_autocommit() {
        ("BEGIN", "COMMIT", "ROLLBACK")
    } else {
        (
            "SAVEPOINT relay",
            "RELEASE relay",
            "ROLLBACK TO relay; RELEASE relay",
        )
    };
    conn.execute_batch(begin).map_err(storage)?;
    let mut begun = Begun {
        conn,
        undo,
        ended: false,
    };
    match work() {
        Ok(done) => {
            // Where the commit fails, what was begun is undone as it is
            // dropped.
            conn.execute_batch(commit).map_err(storage)?;
            begun.ended = true;
            Ok(done)
        }
        Err(e) => {
            begun.ended = true;
            conn.execute_batch(undo).map_err(storage)?;
            Err(e)
        }
    }
}

/// What [`in_one`] began on a connection. Dropped before it was ended, it
/// is undone: so it is where the work unwinds.
struct Begun<'a> {
    conn: &'a Connection,
    /// What undoes it.
    undo: &'static str,
    /// Whether it was committed, or undone already.
    ended: bool,
}

impl Drop for Begun<'_> {
    fn drop(&mut self) {
        if !self.ended {
            // Nothing can be done where this fails: the connection is the
            // caller's, and says so at its next use.
            let _ = self.conn.execute_batch(self.undo);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{channels, db, items};
    use cordelia_core::protocol::{
        LABEL_ENTRY_AUTHOR, LABEL_ENTRY_CHANNEL, MAX_ENTRY_NAME_AND_VALUE_BYTES,
        MAX_ENTRY_WIRE_BYTES, MAX_ITEM_BYTES,
    };
    use cordelia_crypto::derive;
    use cordelia_crypto::entry::{Inside, Value};
    use cordelia_crypto::identity::NodeIdentity;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 24 * 60 * 60;
    const HOUR: i64 = 60 * 60;
    /// What an entry with a small text is counted at: 256 bytes of content
    /// and what an entry takes beyond it.
    const SMALL: u64 = 256 + 1024;
    const SESSION: [u8; 32] = [0x51; 32];

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

    /// The node key of the peer at the other end of the connection whose
    /// session exports [`SESSION`].
    fn peer() -> [u8; 32] {
        device(7).public_key()
    }

    /// A connection from the address numbered `n`, of those kept for
    /// examples.
    fn from(n: u8) -> Asker {
        Asker::Address(IpAddr::from([192, 0, 2, n]))
    }

    /// A relay that the operator lists, which says nothing of how long it
    /// has held a channel.
    const LISTED: Asker = Asker::ListedRelay {
        held_since: None,
        used_at: None,
    };

    /// A relay that the operator lists, which says it has held the channel
    /// since `since`.
    fn listed_since(since: i64) -> Asker {
        Asker::ListedRelay {
            held_since: Some(since),
            used_at: None,
        }
    }

    /// A relay that the operator lists, which says it has held the channel
    /// since `since`, and that it was last used at `used`.
    fn listed(since: i64, used: i64) -> Asker {
        Asker::ListedRelay {
            held_since: Some(since),
            used_at: Some(used),
        }
    }

    /// The mark of the relay's holding of channel `c`, or the mark of no
    /// holding where it holds none.
    fn mark_of(conn: &Connection, c: u16) -> Mark {
        held_channel(conn, &channel(c))
            .unwrap()
            .map_or(NO_MARK, |held| held.mark)
    }

    /// A page of channel `c`, for an asker whose place is in the holding
    /// that the relay has of it now.
    fn paged(conn: &Connection, c: u16, proved: bool, after: u64, limit: u32) -> Page {
        pull(conn, &channel(c), proved, &mark_of(conn, c), after, limit).unwrap()
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

    /// `entry` shown in short: its channel, its slot, its author, its
    /// revision and its ID.
    fn short(conn: &Connection, entry: &CheckedEntry, now: i64) -> Result<ShownShort, RelayError> {
        show_short(
            conn,
            &entry.channel,
            &entry.slot,
            &entry.author,
            entry.rev,
            &entry.id(),
            now,
        )
    }

    /// A relay with room for everything.
    fn relay() -> (Connection, Room) {
        (db::open_in_memory().unwrap(), Room::new(u64::MAX))
    }

    /// A relay that may hold `max_bytes`.
    fn relay_of(max_bytes: u64) -> (Connection, Room) {
        (db::open_in_memory().unwrap(), Room::new(max_bytes))
    }

    /// The entries the relay holds of channel `c`, by name, in the order
    /// it stored them.
    fn ids(conn: &Connection, c: u16) -> Vec<[u8; 32]> {
        entries::channel_entries_after(conn, &channel(c), 0, 1000)
            .unwrap()
            .iter()
            .map(|held| held.entry.id())
            .collect()
    }

    /// The channels the relay holds, of those numbered up to 300.
    fn held(conn: &Connection) -> Vec<u16> {
        (0..300)
            .filter(|c| held_channel(conn, &channel(*c)).unwrap().is_some())
            .collect()
    }

    fn since(conn: &Connection, c: u16) -> Option<i64> {
        held_channel(conn, &channel(c))
            .unwrap()
            .map(|held| held.held_since)
    }

    fn used_at(conn: &Connection, c: u16) -> Option<i64> {
        held_channel(conn, &channel(c))
            .unwrap()
            .map(|held| held.used_at)
    }

    /// The relay's counts are what its entries are counted at: each
    /// channel's bytes are its entries' cost, the relay's are the sum, and
    /// it holds a channel exactly where it holds an entry of it. Returns
    /// what the relay holds.
    fn counted(conn: &Connection) -> u64 {
        let rows: Vec<([u8; 32], i64)> = conn
            .prepare("SELECT channel_id, bytes FROM relay_channels")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let mut sum = 0;
        for (channel, bytes) in &rows {
            let cost = entries::channel_cost(conn, channel).unwrap();
            assert_eq!(*bytes as u64, cost);
            assert!(cost > 0, "a channel is held with no entry");
            sum += cost;
        }
        assert_eq!(used_bytes(conn).unwrap(), sum);
        let with_entries: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT channel_id) FROM entries",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(with_entries as usize, rows.len());
        sum
    }

    /// The entry with these clear fields, signed by `author` under the
    /// author's label, and by `by_channel` under the channel's where one
    /// is given.
    fn signed_by(
        channel: [u8; 32],
        slot: [u8; 32],
        author: &NodeIdentity,
        by_channel: Option<&NodeIdentity>,
        rev: u64,
    ) -> Entry {
        let mut entry = Entry {
            channel,
            slot,
            author: author.public_key(),
            rev,
            delete: false,
            content: vec![0x5a; 256],
            author_signature: [0; 64],
            channel_signature: [0; 64],
        };
        let form = entry.signed_bytes();
        entry.author_signature = author.sign(&[LABEL_ENTRY_AUTHOR, form.as_slice()].concat());
        if let Some(key) = by_channel {
            entry.channel_signature = key.sign(&[LABEL_ENTRY_CHANNEL, form.as_slice()].concat());
        }
        entry
    }

    // ── What a relay takes ───────────────────────────────────────────

    #[test]
    fn test_a_relay_takes_a_checked_entry_and_holds_its_channel_from_then() {
        let (conn, mut room) = relay();
        assert_eq!(held_channel(&conn, &channel(1)).unwrap(), None);
        assert_eq!(used_bytes(&conn).unwrap(), 0);

        let first = small(1, 1, 5);
        // It comes through the door as bytes, and is taken as checked.
        let checked = check(&first.to_wire()).unwrap();
        assert_eq!(checked, first);
        assert_eq!(
            take(&conn, &mut room, &checked, &from(1), NOW).unwrap(),
            Taken::Stored
        );
        let mark = mark_of(&conn, 1);
        assert_ne!(mark, NO_MARK, "a holding has a mark of its own");
        assert_eq!(
            held_channel(&conn, &channel(1)).unwrap(),
            Some(HeldChannel {
                held_since: NOW,
                used_at: NOW,
                bytes: SMALL,
                mark,
            })
        );
        assert_eq!(ids(&conn, 1), [first.id()]);

        // Another author in that slot, and that author in another slot:
        // each is its author's own there, whatever its revision.
        let by_another = small(1, 2, 3);
        let elsewhere = made(1, 1, 2, "other.md", "another name");
        for entry in [&by_another, &elsewhere] {
            assert_eq!(
                take(&conn, &mut room, entry, &from(1), NOW + 60).unwrap(),
                Taken::Stored
            );
        }
        assert_eq!(ids(&conn, 1), [first.id(), by_another.id(), elsewhere.id()]);
        // The channel is held from when it was first taken, and it is
        // the one holding still: its mark is as it was.
        assert_eq!(
            held_channel(&conn, &channel(1)).unwrap(),
            Some(HeldChannel {
                held_since: NOW,
                used_at: NOW,
                bytes: 3 * SMALL,
                mark,
            })
        );

        // A newer revision replaces its author's alone.
        let newer = small(1, 1, 6);
        assert_eq!(
            take(&conn, &mut room, &newer, &from(2), NOW + 120).unwrap(),
            Taken::Stored
        );
        assert_eq!(ids(&conn, 1), [by_another.id(), elsewhere.id(), newer.id()]);
        assert_eq!(counted(&conn), 3 * SMALL);

        // It needs no list of members and no state of the channel: the
        // tables of the older kind hold nothing of it.
        for table in ["channels", "channel_members", "items"] {
            let rows: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "{table}");
        }
    }

    /// An entry at the revision of one held from its author in its slot,
    /// and a lower one, are not stored, and are answered by the store's
    /// rule whatever room there is. "Held" is said only of the very entry
    /// that is held: another that its author signed at that revision is
    /// said to be that.
    #[test]
    fn test_an_entry_at_the_revision_of_one_held_or_below_it_is_not_stored() {
        let (conn, mut room) = relay();
        let first = small(1, 1, 5);
        take(&conn, &mut room, &first, &from(1), NOW).unwrap();
        let before = held_channel(&conn, &channel(1)).unwrap();

        // The very entry, another that its author signed at that
        // revision, and one of another size at it.
        let another = made(1, 1, 5, "notes.md", "another text");
        let larger = made(1, 1, 5, "notes.md", &"x".repeat(3000));
        assert_ne!(another.id(), first.id());
        assert_eq!(
            take(&conn, &mut room, &first, &from(1), NOW + 60).unwrap(),
            Taken::AlreadyHeld
        );
        for entry in [&another, &larger] {
            assert_eq!(
                take(&conn, &mut room, entry, &from(1), NOW + 60).unwrap(),
                Taken::HeldAnother
            );
        }
        // A lower one, by one revision and by many.
        for rev in [4, 1] {
            assert_eq!(
                take(&conn, &mut room, &small(1, 1, rev), &from(1), NOW + 60).unwrap(),
                Taken::OlderThanHeld
            );
        }
        assert_eq!(ids(&conn, 1), [first.id()]);
        assert_eq!(held_channel(&conn, &channel(1)).unwrap(), before);

        // With no room at all, they are answered the same: nothing of
        // them would be stored, so no room is asked about.
        room.max_bytes = 0;
        room.max_channel_bytes = 0;
        assert_eq!(
            take(&conn, &mut room, &another, &from(1), NOW + 60).unwrap(),
            Taken::HeldAnother
        );
        assert_eq!(
            take(&conn, &mut room, &first, &from(1), NOW + 60).unwrap(),
            Taken::AlreadyHeld
        );
        assert_eq!(
            take(&conn, &mut room, &small(1, 1, 4), &from(1), NOW + 60).unwrap(),
            Taken::OlderThanHeld
        );
        assert_eq!(ids(&conn, 1), [first.id()]);
        assert_eq!(counted(&conn), SMALL);
    }

    /// An entry with either signature missing or wrong does not come
    /// through the door, and neither do bytes that are no entry's. What
    /// stores takes only what came through it.
    #[test]
    fn test_an_entry_with_either_signature_missing_or_wrong_is_refused() {
        let good = small(1, 1, 5).into_entry();
        assert_eq!(*check(&good.to_wire()).unwrap(), good);

        // Missing: nothing where a signature is.
        let mut entry = good.clone();
        entry.author_signature = [0; 64];
        assert_eq!(
            check(&entry.to_wire()),
            Err(Refused::NotSigned(EntryError::AuthorSignature))
        );
        let mut entry = good.clone();
        entry.channel_signature = [0; 64];
        assert_eq!(
            check(&entry.to_wire()),
            Err(Refused::NotSigned(EntryError::ChannelSignature))
        );

        // Wrong by one bit.
        let mut entry = good.clone();
        entry.author_signature[7] ^= 1;
        assert_eq!(
            check(&entry.to_wire()),
            Err(Refused::NotSigned(EntryError::AuthorSignature))
        );
        let mut entry = good.clone();
        entry.channel_signature[7] ^= 1;
        assert_eq!(
            check(&entry.to_wire()),
            Err(Refused::NotSigned(EntryError::ChannelSignature))
        );

        // Each in the other's place, and a field changed after signing.
        let mut entry = good.clone();
        std::mem::swap(&mut entry.author_signature, &mut entry.channel_signature);
        assert!(matches!(
            check(&entry.to_wire()),
            Err(Refused::NotSigned(_))
        ));
        let mut entry = good.clone();
        entry.rev = 6;
        assert_eq!(
            check(&entry.to_wire()),
            Err(Refused::NotSigned(EntryError::AuthorSignature))
        );

        // Bytes that are no entry's: cut short, and with one byte more.
        let bytes = good.to_wire();
        assert!(matches!(
            check(&bytes[..bytes.len() - 1]),
            Err(Refused::NotAnEntry(WireError::Length { .. }))
        ));
        assert!(matches!(
            check(&[bytes.as_slice(), &[0]].concat()),
            Err(Refused::NotAnEntry(WireError::Length { .. }))
        ));
        assert_eq!(check(&[]), Err(Refused::NotAnEntry(WireError::TooShort)));
    }

    /// A stranger knows a channel's ID, and holds no key of it. It pushes
    /// an entry: nothing is stored. It asks for the channel: it is
    /// answered as for a channel that is not held. It shows an entry that
    /// it made up: refused, since its signatures do not hold.
    #[test]
    fn test_a_stranger_with_a_channels_id_and_no_key_gets_nothing() {
        let (conn, mut room) = relay();
        let held_entry = small(1, 1, 5);
        take(&conn, &mut room, &held_entry, &from(1), NOW).unwrap();
        let before = (ids(&conn, 1), held_channel(&conn, &channel(1)).unwrap());

        let stranger = device(9);
        let strangers_channel = derive::signing_key(&secret(99)).unwrap();
        // What it can make: an entry that names the channel, in a slot it
        // has seen, signed as its author by its own key. The channel's
        // signature it cannot make: it leaves it out, or signs with its
        // own key, or with the key of a channel of its own.
        let made_up = [None, Some(&stranger), Some(&strangers_channel)]
            .map(|by| signed_by(channel(1), held_entry.slot, &stranger, by, 9));
        for entry in &made_up {
            // The control: its author's signature holds.
            assert!(cordelia_crypto::identity::verify_signature(
                &stranger.public_key(),
                &[LABEL_ENTRY_AUTHOR, entry.signed_bytes().as_slice()].concat(),
                &entry.author_signature
            ));
            // Pushed or shown, it comes through the one door, and is
            // refused there: there is nothing to store, and nothing to
            // answer with.
            assert_eq!(
                check(&entry.to_wire()),
                Err(Refused::NotSigned(EntryError::ChannelSignature))
            );
        }
        // Nor does it pass as the entry of the author whose entry is held.
        let mut as_another = held_entry.clone().into_entry();
        as_another.rev = 9;
        assert_eq!(
            check(&as_another.to_wire()),
            Err(Refused::NotSigned(EntryError::AuthorSignature))
        );
        assert_eq!(
            (ids(&conn, 1), held_channel(&conn, &channel(1)).unwrap()),
            before
        );

        // It asks for the channel. It cannot prove the key: with its own
        // key, with a channel of its own, and with no proof at all, the
        // answer is the answer for a channel that the relay does not hold.
        assert_eq!(held_channel(&conn, &channel(2)).unwrap(), None);
        let not_held = prove(
            &conn,
            &channel(2),
            &SESSION,
            &peer(),
            &proof::make(&secret(2), &SESSION, &peer()).unwrap(),
            NOW,
        )
        .unwrap()
        .answer();
        assert!(!not_held);
        // The stranger is the peer on its connection, and says so in what
        // it signs.
        let itself = stranger.public_key();
        let mut what_it_signs = cordelia_core::protocol::LABEL_CHANNEL_PROOF.to_vec();
        what_it_signs.extend_from_slice(&SESSION);
        what_it_signs.extend_from_slice(&itself);
        what_it_signs.extend_from_slice(&channel(1));
        for forged in [
            stranger.sign(&what_it_signs),
            strangers_channel.sign(&what_it_signs),
            proof::make(&secret(99), &SESSION, &itself).unwrap(),
            [0; 64],
        ] {
            assert_eq!(
                prove(&conn, &channel(1), &SESSION, &itself, &forged, NOW + 60)
                    .unwrap()
                    .answer(),
                not_held
            );
        }
        // It has come by a proof of the channel: one that a node which
        // holds the key made on another connection, and one that the node
        // at this end of its own connection made and sent to it. It sends
        // each as its own: neither says that it made it.
        for seen in [
            proof::make(&secret(1), &[0x52; 32], &peer()).unwrap(),
            proof::make(&secret(1), &SESSION, &peer()).unwrap(),
        ] {
            assert_eq!(
                prove(&conn, &channel(1), &SESSION, &itself, &seen, NOW + 60)
                    .unwrap()
                    .answer(),
                not_held
            );
        }
        // And asked for without a proof, the channel it holds is handed as
        // the one it does not hold is, from any place.
        for after in [0, 1, 7] {
            // Whatever mark it asks with: none, one it made up, and the
            // mark of the relay's holding, which it has no way to know.
            for mark in [NO_MARK, [0x4d; 8], mark_of(&conn, 1)] {
                let unproved = pull(&conn, &channel(1), false, &mark, after, 100).unwrap();
                assert_eq!(
                    unproved,
                    Page {
                        entries: Vec::new(),
                        next: after,
                        cost: 0,
                        mark,
                    }
                );
                assert_eq!(
                    unproved,
                    pull(&conn, &channel(2), false, &mark, after, 100).unwrap()
                );
                // Only a connection that proved a channel is told that it
                // is not held: by the mark of no holding, and the start.
                assert_eq!(
                    pull(&conn, &channel(2), true, &mark, after, 100).unwrap(),
                    Page {
                        entries: Vec::new(),
                        next: 0,
                        cost: 0,
                        mark: NO_MARK,
                    }
                );
            }
        }
        // Nothing of all that counted as use of the channel.
        assert_eq!(used_at(&conn, 1), Some(NOW));
        // The control: whoever holds the key is handed it.
        let proved = proof::make(&secret(1), &SESSION, &peer()).unwrap();
        assert!(
            prove(&conn, &channel(1), &SESSION, &peer(), &proved, NOW + 60)
                .unwrap()
                .answer()
        );
        assert_eq!(
            paged(&conn, 1, true, 0, 100).entries,
            [held_entry.into_entry()]
        );
    }

    /// Taking is whole: the entry is stored and the relay's counts are
    /// changed, or neither.
    #[test]
    fn test_an_entry_is_stored_and_counted_as_one_or_not_at_all() {
        let (conn, mut room) = relay();
        // Inside a transaction of the caller's, it is whole with that one.
        conn.execute_batch("BEGIN").unwrap();
        assert_eq!(
            take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).unwrap(),
            Taken::Stored
        );
        assert_eq!(counted(&conn), SMALL);
        conn.execute_batch("ROLLBACK").unwrap();
        assert_eq!(counted(&conn), 0);
        assert!(ids(&conn, 1).is_empty());
        assert!(conn.is_autocommit());

        // Where the channel's row cannot be written, the entry that was
        // stored for it is not kept.
        conn.execute_batch(
            "CREATE TRIGGER no_row BEFORE INSERT ON relay_channels
             BEGIN SELECT RAISE(ABORT, 'no row is written'); END;",
        )
        .unwrap();
        assert!(take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).is_err());
        assert!(ids(&conn, 1).is_empty());
        assert!(conn.is_autocommit(), "no transaction is left open");
        assert!(show(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).is_err());
        assert!(ids(&conn, 1).is_empty());
        assert!(conn.is_autocommit());
        // Inside a transaction of the caller's, the same: what was stored
        // for it is undone, and the caller's transaction goes on.
        conn.execute_batch("BEGIN").unwrap();
        assert!(take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).is_err());
        assert!(ids(&conn, 1).is_empty());
        assert!(!conn.is_autocommit(), "the caller's transaction is open");
        conn.execute_batch("COMMIT").unwrap();
        assert!(ids(&conn, 1).is_empty());

        conn.execute_batch("DROP TRIGGER no_row").unwrap();
        assert_eq!(
            take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).unwrap(),
            Taken::Stored
        );
        assert_eq!(counted(&conn), SMALL);
    }

    /// A relay's rules are for a database that no device writes. On one
    /// in which a device follows a phrase, taking and showing refuse and
    /// store nothing, and nothing is dropped to make room or as unused.
    #[test]
    fn test_a_database_in_which_a_device_follows_a_phrase_is_refused() {
        use crate::person::{Following, Person, State, put_person};

        let (conn, mut room) = relay();
        // What a relay took here before, and what a device's own code
        // wrote in the same table.
        take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).unwrap();
        take(&conn, &mut room, &small(2, 1, 5), &from(1), NOW + 10).unwrap();
        entries::store(&conn, &small(3, 1, 5), NOW + 20).unwrap();
        // A device follows a phrase in this database.
        let follows = Person {
            state: State::Applied,
            following: Following {
                phrase_key: [1; 32],
                statement_key: [2; 32],
                phrase_channel: [3; 32],
            },
            statement: vec![4, 5, 6],
        };
        put_person(&conn, &follows).unwrap();

        let all = |conn: &Connection| {
            let rows: Vec<([u8; 32], i64, i64, i64)> = conn
                .prepare(
                    "SELECT channel_id, held_since, used_at, bytes FROM relay_channels
                     ORDER BY rowid",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            (ids(conn, 1), ids(conn, 2), ids(conn, 3), ids(conn, 4), rows)
        };
        let before = all(&conn);
        assert_eq!((before.0.len(), before.1.len(), before.2.len()), (1, 1, 1));
        assert_eq!(before.4.len(), 2);
        let refused = |done: Result<(), RelayError>| {
            assert!(
                matches!(done, Err(RelayError::DeviceFollowsAPhrase)),
                "{done:?}"
            );
        };

        // Taking, and showing: a new channel, a newer revision in a
        // channel held, an entry already held, and one in the channel
        // that the device wrote. Each is refused, and nothing is stored.
        for entry in [
            small(4, 1, 5),
            small(1, 1, 6),
            small(1, 1, 5),
            small(3, 1, 6),
        ] {
            for asker in [
                from(1),
                LISTED,
                listed_since(NOW - DAY),
                listed(NOW - DAY, NOW + 30),
            ] {
                refused(take(&conn, &mut room, &entry, &asker, NOW + 60).map(|_| ()));
                refused(show(&conn, &mut room, &entry, &asker, NOW + 60).map(|_| ()));
            }
            // Shown in short, it is refused as well: where it is held,
            // that would be use of its channel.
            refused(short(&conn, &entry, NOW + 60).map(|_| ()));
        }
        assert_eq!(all(&conn), before);
        // Nor is an address counted for what was refused.
        assert_eq!(room.new_channels[&IpAddr::from([192, 0, 2, 1])].len(), 2);

        // Making room with no room at all, and sweeping long after
        // anything was used: nothing is dropped.
        refused(make_room(&conn, 0).map(|_| ()));
        refused(sweep_unused(&conn, NOW + 365 * DAY).map(|_| ()));
        // Nor is what a listed relay says kept: since when it has held a
        // channel, and when the channel was last used.
        refused(listed_relay_says(&conn, &channel(1), NOW - DAY).map(|_| ()));
        refused(listed_relay_used(&conn, &channel(1), NOW + 30, NOW + 60).map(|_| ()));
        assert_eq!(all(&conn), before);
        assert!(conn.is_autocommit(), "no transaction is left open");

        // The control: with no device following a phrase there, each does
        // what it does.
        conn.execute("DELETE FROM person", []).unwrap();
        assert!(listed_relay_says(&conn, &channel(1), NOW - DAY).unwrap());
        assert!(listed_relay_used(&conn, &channel(2), NOW + 2 * HOUR, NOW + 3 * HOUR).unwrap());
        assert_eq!(
            take(&conn, &mut room, &small(4, 1, 5), &from(1), NOW + 60).unwrap(),
            Taken::Stored
        );
        assert_eq!(
            show(&conn, &mut room, &small(1, 1, 6), &from(1), NOW + 60).unwrap(),
            Shown::Taken
        );
        assert_eq!(
            sweep_unused(&conn, NOW + 365 * DAY).unwrap(),
            [channel(1), channel(4), channel(2)]
        );
        assert!(make_room(&conn, 0).unwrap().is_empty());
    }

    // ── Its room ─────────────────────────────────────────────────────

    /// Room is counted by what entries are counted at: an entry that
    /// replaces one of its size changes nothing, a larger one takes the
    /// difference, and a smaller one gives it back.
    #[test]
    fn test_what_a_relay_holds_is_counted_as_its_entries_are() {
        let (conn, mut room) = relay();
        let mut now = NOW;
        let mut taken = |entry: CheckedEntry| {
            now += 1;
            assert_eq!(
                take(&conn, &mut room, &entry, &from(1), now).unwrap(),
                Taken::Stored
            );
            counted(&conn)
        };
        assert_eq!(taken(small(1, 1, 5)), SMALL);
        assert_eq!(taken(small(1, 2, 5)), 2 * SMALL);
        assert_eq!(taken(small(2, 1, 5)), 3 * SMALL);
        // One of the same size in the place of another.
        assert_eq!(taken(small(1, 1, 6)), 3 * SMALL);
        // A larger one: 4096 bytes of content where 256 were.
        let larger = made(1, 1, 7, "notes.md", &"x".repeat(3000));
        assert_eq!(larger.content.len(), 4096);
        assert_eq!(taken(larger), 3 * SMALL + 3840);
        assert_eq!(
            held_channel(&conn, &channel(1)).unwrap().unwrap().bytes,
            2 * SMALL + 3840
        );
        assert_eq!(
            held_channel(&conn, &channel(2)).unwrap().unwrap().bytes,
            SMALL
        );
        // A smaller one gives the difference back.
        assert_eq!(taken(small(1, 1, 8)), 3 * SMALL);
        // The largest an entry may be.
        let largest = made(
            3,
            1,
            1,
            "n",
            &"x".repeat(MAX_ENTRY_NAME_AND_VALUE_BYTES - 1),
        );
        assert_eq!(largest.content.len(), MAX_ITEM_BYTES);
        assert_eq!(taken(largest), 3 * SMALL + 65_536 + 1024);
    }

    /// One channel may hold only so much. A channel at that takes no
    /// entry that makes it hold more, and still takes a newer revision
    /// that is no larger.
    #[test]
    fn test_a_channel_holds_only_so_much_and_still_takes_what_is_no_larger() {
        let (conn, mut room) = relay();
        assert_eq!(room.max_channel_bytes, 16 * 1024 * 1024);
        room.max_channel_bytes = 3 * SMALL;
        for d in 1..=3 {
            assert_eq!(
                take(&conn, &mut room, &small(1, d, 5), &from(1), NOW).unwrap(),
                Taken::Stored
            );
        }
        let full = ids(&conn, 1);

        // Another author's entry, another name's, and a larger revision
        // of one it holds: each would make it hold more.
        let larger = made(1, 1, 6, "notes.md", &"x".repeat(300));
        assert_eq!(larger.content.len(), 512);
        for entry in [
            small(1, 4, 5),
            made(1, 1, 5, "other.md", "another name"),
            larger,
        ] {
            assert_eq!(
                take(&conn, &mut room, &entry, &from(1), NOW + 60).unwrap(),
                Taken::Refused(Refused::ChannelFull)
            );
            assert_eq!(ids(&conn, 1), full);
        }
        // Shown, it is refused the same.
        assert_eq!(
            show(&conn, &mut room, &small(1, 4, 5), &from(1), NOW + 60).unwrap(),
            Shown::Refused(Refused::ChannelFull)
        );

        // A newer revision of the same size is taken.
        let newer = small(1, 1, 6);
        assert_eq!(
            take(&conn, &mut room, &newer, &from(1), NOW + 60).unwrap(),
            Taken::Stored
        );
        assert_eq!(counted(&conn), 3 * SMALL);
        // Another channel has its own share.
        assert_eq!(
            take(&conn, &mut room, &small(2, 4, 5), &from(1), NOW + 60).unwrap(),
            Taken::Stored
        );

        // A channel that holds more than its share, since its share came
        // down: a newer revision that is no larger is still taken, so
        // what is there can be edited, and the channel can shrink.
        room.max_channel_bytes = SMALL;
        assert_eq!(
            take(&conn, &mut room, &small(1, 2, 6), &from(1), NOW + 120).unwrap(),
            Taken::Stored
        );
        assert_eq!(
            take(&conn, &mut room, &small(1, 4, 5), &from(1), NOW + 120).unwrap(),
            Taken::Refused(Refused::ChannelFull)
        );
        assert_eq!(counted(&conn), 4 * SMALL);
        // The first entry of a channel is within any share that holds an
        // entry, and over one that holds none.
        room.max_channel_bytes = SMALL - 1;
        assert_eq!(
            take(&conn, &mut room, &small(3, 1, 5), &from(1), NOW + 120).unwrap(),
            Taken::Refused(Refused::ChannelFull)
        );
        assert_eq!(held(&conn), [1, 2]);
    }

    /// At its cap a relay takes no channel that it does not hold. A newer
    /// revision of an entry it holds, that is no larger, is never refused
    /// for room: so a change entry replaces the one before it at a relay
    /// that is full.
    #[test]
    fn test_a_relay_at_its_cap_takes_a_newer_revision_of_an_entry_it_holds_and_no_new_channel() {
        let (conn, mut room) = relay_of(2 * SMALL);
        let first = small(1, 1, 5);
        take(&conn, &mut room, &first, &from(1), NOW).unwrap();
        // Under its cap, by one entry: a new channel is taken.
        assert_eq!(
            take(&conn, &mut room, &small(2, 1, 5), &from(1), NOW + 10).unwrap(),
            Taken::Stored
        );
        assert_eq!(counted(&conn), room.max_bytes);

        // At its cap: a new channel is refused, pushed or shown, from an
        // address and from a relay that the operator lists.
        for asker in [from(1), LISTED, listed_since(NOW - DAY)] {
            assert_eq!(
                take(&conn, &mut room, &small(3, 1, 5), &asker, NOW + 20).unwrap(),
                Taken::Refused(Refused::NoRoom)
            );
            assert_eq!(
                show(&conn, &mut room, &small(3, 1, 5), &asker, NOW + 20).unwrap(),
                Shown::Refused(Refused::NoRoom)
            );
        }
        assert_eq!(held(&conn), [1, 2]);

        // A newer revision of an entry it holds, of the same size: taken,
        // in the older channel and in the newer, and nothing is dropped.
        for (c, rev) in [(1, 6), (2, 6)] {
            assert_eq!(
                take(&conn, &mut room, &small(c, 1, rev), &from(1), NOW + 30).unwrap(),
                Taken::Stored
            );
        }
        // Shown, it is taken the same.
        let newer = small(2, 1, 7);
        assert_eq!(
            show(&conn, &mut room, &newer, &from(1), NOW + 40).unwrap(),
            Shown::Taken
        );
        assert_eq!(ids(&conn, 2), [newer.id()]);
        assert_eq!(held(&conn), [1, 2]);
        assert_eq!(counted(&conn), room.max_bytes);

        // Also where the relay is over its cap, since its cap came down:
        // a write that makes it hold no more drops nothing, and stays.
        room.max_bytes = SMALL;
        assert_eq!(
            take(&conn, &mut room, &small(2, 1, 8), &from(1), NOW + 50).unwrap(),
            Taken::Stored
        );
        assert_eq!(held(&conn), [1, 2]);
        assert_eq!(counted(&conn), 2 * SMALL);
    }

    /// One byte under its cap a relay has no room for the first entry of
    /// a channel it does not hold. It is refused before anything is
    /// stored: no entry, no row, and nothing counted against the address.
    /// So refusals for room do not use up an address's allowance.
    #[test]
    fn test_a_byte_under_its_cap_a_new_channels_first_entry_is_refused_and_nothing_is_stored() {
        let address = IpAddr::from([192, 0, 2, 2]);
        let (conn, mut room) = relay_of(SMALL + 1);
        assert_eq!(
            take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).unwrap(),
            Taken::Stored
        );
        assert_eq!(counted(&conn) + 1, room.max_bytes);
        // What the store has written, in all: one entry, at one place.
        let written = |conn: &Connection| -> (i64, i64, i64) {
            conn.query_row(
                "SELECT (SELECT COUNT(*) FROM entries),
                        (SELECT value FROM counters WHERE name = 'entry_seq'),
                        (SELECT COUNT(*) FROM relay_channels)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap()
        };
        assert_eq!(written(&conn), (1, 1, 1));

        // The first entry of a channel it does not hold, pushed and
        // shown, from an address and from a relay that the operator
        // lists: with it the relay would pass its cap, by all but a byte
        // of the entry.
        for asker in [from(2), LISTED, listed_since(NOW - DAY)] {
            assert_eq!(
                take(&conn, &mut room, &small(2, 1, 5), &asker, NOW + 10).unwrap(),
                Taken::Refused(Refused::NoRoom)
            );
            assert_eq!(
                show(&conn, &mut room, &small(2, 1, 5), &asker, NOW + 10).unwrap(),
                Shown::Refused(Refused::NoRoom)
            );
        }
        // Nothing was stored for it, also not for a moment: the store has
        // given out no place. No row was made, and nothing was dropped.
        assert_eq!(written(&conn), (1, 1, 1));
        assert_eq!(held(&conn), [1]);
        assert_eq!(counted(&conn), SMALL);
        // And the address was not counted.
        assert!(!room.new_channels.contains_key(&address));

        // 256 such refusals, each of another channel, do not use up the
        // address's allowance.
        let firsts: Vec<CheckedEntry> = (2..258).map(|c| small(c, 1, 5)).collect();
        assert_eq!(firsts.len(), NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR);
        for entry in &firsts {
            assert_eq!(
                take(&conn, &mut room, entry, &from(2), NOW + 20).unwrap(),
                Taken::Refused(Refused::NoRoom)
            );
        }
        assert_eq!(written(&conn), (1, 1, 1));
        assert!(!room.new_channels.contains_key(&address));
        assert!(room.may_add_channel(address, NOW + 20));

        // With room, in that same hour, the address makes the relay take
        // every one of them: it has all of its allowance. The one after
        // is over it.
        room.max_bytes = u64::MAX;
        for entry in &firsts {
            assert_eq!(
                take(&conn, &mut room, entry, &from(2), NOW + 30).unwrap(),
                Taken::Stored
            );
        }
        assert_eq!(room.new_channels[&address].len(), 256);
        assert_eq!(
            take(&conn, &mut room, &small(258, 1, 5), &from(2), NOW + 30).unwrap(),
            Taken::Refused(Refused::OverAllowance)
        );

        // To the byte: with room for the entry and no more, it is taken.
        let (conn, mut room) = relay_of(2 * SMALL);
        take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).unwrap();
        assert_eq!(
            take(&conn, &mut room, &small(2, 1, 5), &from(2), NOW).unwrap(),
            Taken::Stored
        );
        assert_eq!(counted(&conn), room.max_bytes);
    }

    /// A write that would make the relay's newest channel hold more, past
    /// the relay's cap, is refused, and the channel keeps what it held:
    /// its hundred entries are still there.
    #[test]
    fn test_a_growing_write_to_the_newest_channel_is_refused_and_what_it_held_stays() {
        let (conn, mut room) = relay();
        take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).unwrap();
        // The newest channel: a hundred entries, of a hundred authors.
        for d in 1..=100 {
            take(&conn, &mut room, &small(2, d, 5), &from(1), NOW + 10).unwrap();
        }
        let before = (ids(&conn, 1), ids(&conn, 2));
        assert_eq!(before.1.len(), 100);
        let row = held_channel(&conn, &channel(2)).unwrap();
        // The relay is at its cap.
        room.max_bytes = counted(&conn);
        assert_eq!(room.max_bytes, 101 * SMALL);

        // One entry more in the newest channel, and a larger revision of
        // one that it holds there: pushed and shown, each is refused.
        let larger = made(2, 1, 6, "notes.md", &"x".repeat(300));
        assert_eq!(larger.content.len(), 512);
        for entry in [small(2, 101, 5), larger] {
            assert_eq!(
                take(&conn, &mut room, &entry, &from(1), NOW + 20).unwrap(),
                Taken::Refused(Refused::NoRoom)
            );
            assert_eq!(
                show(&conn, &mut room, &entry, &from(1), NOW + 20).unwrap(),
                Shown::Refused(Refused::NoRoom)
            );
        }
        // Its hundred entries are still there, and its row is as it was.
        assert_eq!((ids(&conn, 1), ids(&conn, 2)), before);
        assert_eq!(held_channel(&conn, &channel(2)).unwrap(), row);
        assert_eq!(held(&conn), [1, 2]);
        assert_eq!(counted(&conn), 101 * SMALL);

        // An older channel that would hold more is refused the same: no
        // write makes a relay drop what it holds, the newest channel no
        // more than any other.
        assert_eq!(
            take(&conn, &mut room, &small(1, 2, 5), &from(1), NOW + 30).unwrap(),
            Taken::Refused(Refused::NoRoom)
        );
        assert_eq!((ids(&conn, 1), ids(&conn, 2)), before);
        assert_eq!(held(&conn), [1, 2]);

        // What makes neither hold more is taken, in each.
        for c in [1, 2] {
            assert_eq!(
                take(&conn, &mut room, &small(c, 1, 6), &from(1), NOW + 40).unwrap(),
                Taken::Stored
            );
        }
        assert_eq!(ids(&conn, 2).len(), 100);
        assert_eq!(counted(&conn), 101 * SMALL);

        // To the byte: one byte short of room for an entry more, it is
        // refused, and with room for it and no more, it is taken.
        room.max_bytes = 102 * SMALL - 1;
        assert_eq!(
            take(&conn, &mut room, &small(2, 101, 5), &from(1), NOW + 50).unwrap(),
            Taken::Refused(Refused::NoRoom)
        );
        room.max_bytes = 102 * SMALL;
        assert_eq!(
            take(&conn, &mut room, &small(2, 101, 5), &from(1), NOW + 50).unwrap(),
            Taken::Stored
        );
        assert_eq!(ids(&conn, 2).len(), 101);
        assert_eq!(counted(&conn), room.max_bytes);
    }

    /// A relay that holds more than its cap, since its cap came down,
    /// drops the channels it has held for the shortest time when room is
    /// made. What was there first is never pushed out by what came later.
    /// No write makes it drop anything.
    #[test]
    fn test_a_relay_over_its_cap_drops_the_newest_channel() {
        let (conn, mut room) = relay_of(3 * SMALL);
        for (c, at) in [(1, NOW), (2, NOW + 10), (3, NOW + 20)] {
            assert_eq!(
                take(&conn, &mut room, &small(c, 1, 5), &from(1), at).unwrap(),
                Taken::Stored
            );
        }
        assert_eq!(counted(&conn), room.max_bytes);

        // Its cap comes down, to what two of the three take. It holds
        // more than its cap now.
        room.max_bytes = 2 * SMALL;
        // No write brings it under: what would make it hold more is
        // refused, in the oldest channel and in the newest, and what
        // makes it hold no more is taken. All three channels stay.
        for c in [1, 3] {
            assert_eq!(
                take(&conn, &mut room, &small(c, 2, 5), &from(1), NOW + 30).unwrap(),
                Taken::Refused(Refused::NoRoom)
            );
            assert_eq!(
                take(&conn, &mut room, &small(c, 1, 6), &from(1), NOW + 30).unwrap(),
                Taken::Stored
            );
        }
        assert_eq!(held(&conn), [1, 2, 3]);
        assert_eq!(counted(&conn), 3 * SMALL);

        // Room is made, with the relay's cap: the newest channel goes,
        // with its entries, and the two that were there before it stay.
        assert_eq!(make_room(&conn, room.max_bytes).unwrap(), [channel(3)]);
        assert_eq!(held(&conn), [1, 2]);
        assert!(ids(&conn, 3).is_empty());
        assert_eq!((ids(&conn, 1).len(), ids(&conn, 2).len()), (1, 1));
        assert_eq!(counted(&conn), 2 * SMALL);
        // It is under its cap: made again, nothing more goes.
        assert!(make_room(&conn, room.max_bytes).unwrap().is_empty());

        // Enough is dropped to be under: as many of the newest as it
        // takes, and no more.
        room.max_bytes = 5 * SMALL;
        for (c, at) in [(5, NOW + 70), (6, NOW + 80), (7, NOW + 90)] {
            take(&conn, &mut room, &small(c, 1, 5), &from(1), at).unwrap();
        }
        assert_eq!(held(&conn), [1, 2, 5, 6, 7]);
        room.max_bytes = 3 * SMALL + 1;
        assert_eq!(
            make_room(&conn, room.max_bytes).unwrap(),
            [channel(7), channel(6)]
        );
        assert_eq!(held(&conn), [1, 2, 5]);
        assert_eq!(counted(&conn), 3 * SMALL);
    }

    /// Making room, by itself: the newest first, and of two channels held
    /// since one time, the one that was taken later.
    #[test]
    fn test_making_room_drops_the_newest_first_and_stops_when_under() {
        let (conn, mut room) = relay();
        // Four channels, the middle two taken in one second.
        for (c, at) in [(1, NOW), (2, NOW + 10), (3, NOW + 10), (4, NOW + 20)] {
            take(&conn, &mut room, &small(c, 1, 5), &from(1), at).unwrap();
        }
        // Under, and at: nothing goes.
        assert!(make_room(&conn, 5 * SMALL).unwrap().is_empty());
        assert!(make_room(&conn, 4 * SMALL).unwrap().is_empty());
        assert_eq!(held(&conn), [1, 2, 3, 4]);

        // Over by one byte: one channel goes, the newest.
        assert_eq!(make_room(&conn, 4 * SMALL - 1).unwrap(), [channel(4)]);
        // Of the two held since one time, the one taken later.
        assert_eq!(make_room(&conn, 2 * SMALL).unwrap(), [channel(3)]);
        assert_eq!(held(&conn), [1, 2]);
        assert_eq!(counted(&conn), 2 * SMALL);
        // No room at all: everything goes, the newest first.
        assert_eq!(make_room(&conn, 0).unwrap(), [channel(2), channel(1)]);
        assert_eq!(counted(&conn), 0);
        assert!(make_room(&conn, 0).unwrap().is_empty());
    }

    /// A channel that a relay the operator lists has held longer is held
    /// from that time here, and is not the newest: making room drops what
    /// this relay took before it, and not it.
    #[test]
    fn test_a_channel_that_a_listed_relay_has_held_longer_is_not_the_newest() {
        let (conn, mut room) = relay_of(3 * SMALL);
        take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).unwrap();
        take(&conn, &mut room, &small(2, 1, 5), &from(1), NOW + 10).unwrap();
        // Taken last, from a relay that has held it for a year.
        assert_eq!(
            take(
                &conn,
                &mut room,
                &small(3, 1, 5),
                &listed_since(NOW - 365 * DAY),
                NOW + 20
            )
            .unwrap(),
            Taken::Stored
        );
        assert_eq!(since(&conn, 3), Some(NOW - 365 * DAY));
        // It was used when it was taken here, whatever the other relay
        // says of how long it has held it: it is not swept as unused for
        // the year that this relay did not hold it.
        assert_eq!(used_at(&conn, 3), Some(NOW + 20));
        assert!(sweep_unused(&conn, NOW + 30).unwrap().is_empty());
        assert_eq!(counted(&conn), room.max_bytes);

        // The relay's cap comes down by one channel's worth, and room is
        // made: the channel that goes is the second, though the third
        // was taken after it.
        assert_eq!(make_room(&conn, 2 * SMALL).unwrap(), [channel(2)]);
        assert_eq!(held(&conn), [1, 3]);
        // And then the first, which this relay has held longest itself:
        // the one that the listed relay has held longer is what stays.
        assert_eq!(make_room(&conn, SMALL).unwrap(), [channel(1)]);
        assert_eq!(held(&conn), [3]);

        // The control: taken the same way with nothing said, the third is
        // the newest, and is the one that goes.
        let (conn, mut room) = relay_of(3 * SMALL);
        take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).unwrap();
        take(&conn, &mut room, &small(2, 1, 5), &from(1), NOW + 10).unwrap();
        take(&conn, &mut room, &small(3, 1, 5), &LISTED, NOW + 20).unwrap();
        assert_eq!(make_room(&conn, 2 * SMALL).unwrap(), [channel(3)]);
        assert_eq!(held(&conn), [1, 2]);
    }

    /// An address is counted for a channel that it made the relay take
    /// only where the write is written for good. Inside a transaction of
    /// the caller's the channels taken so far are part of the address's
    /// share while the write is under way, stay counted where the caller
    /// says that it is written, and are taken back where it is undone. A
    /// write of its own that fails counts nothing either.
    #[test]
    fn test_an_address_is_counted_for_a_new_channel_only_once_it_is_written() {
        let (conn, mut room) = relay();
        let address = IpAddr::from([192, 0, 2, 1]);
        let made = |room: &Room| room.new_channels.get(&address).map_or(0, Vec::len);

        // A write of several entries, in a transaction of the caller's:
        // nothing is counted yet, and the share is used all the same.
        conn.execute_batch("BEGIN").unwrap();
        for c in 0..256 {
            assert_eq!(
                take(&conn, &mut room, &small(c, 1, 5), &from(1), NOW).unwrap(),
                Taken::Stored
            );
        }
        assert_eq!((made(&room), room.not_yet.len()), (256, 256));
        assert!(!room.may_add_channel(address, NOW));
        assert_eq!(
            take(&conn, &mut room, &small(256, 1, 5), &from(1), NOW).unwrap(),
            Taken::Refused(Refused::OverAllowance)
        );
        assert_eq!(
            show(&conn, &mut room, &small(257, 1, 5), &from(1), NOW).unwrap(),
            Shown::Refused(Refused::OverAllowance)
        );
        // It is undone: the relay holds none of them, and the address is
        // counted for none.
        conn.execute_batch("ROLLBACK").unwrap();
        room.undone();
        assert_eq!(held(&conn), [0u16; 0]);
        assert_eq!((made(&room), room.not_yet.len()), (0, 0));
        assert!(room.may_add_channel(address, NOW));

        // The same again, written: counted from then.
        conn.execute_batch("BEGIN").unwrap();
        for c in 0..3 {
            take(&conn, &mut room, &small(c, 1, 5), &from(1), NOW).unwrap();
        }
        assert_eq!(
            show(&conn, &mut room, &small(3, 1, 5), &from(1), NOW).unwrap(),
            Shown::Taken
        );
        assert_eq!((made(&room), room.not_yet.len()), (4, 4));
        conn.execute_batch("COMMIT").unwrap();
        room.written();
        assert_eq!((made(&room), room.not_yet.len()), (4, 0));

        // A write of its own is counted as it is written.
        take(&conn, &mut room, &small(4, 1, 5), &from(1), NOW).unwrap();
        show(&conn, &mut room, &small(5, 1, 5), &from(1), NOW).unwrap();
        assert_eq!((made(&room), room.not_yet.len()), (6, 0));

        // One that fails counts nothing: the store refuses the entry.
        conn.execute_batch(
            "CREATE TRIGGER refuses BEFORE INSERT ON relay_channels
             BEGIN SELECT RAISE(ABORT, 'refused'); END;",
        )
        .unwrap();
        assert!(take(&conn, &mut room, &small(6, 1, 5), &from(1), NOW).is_err());
        assert!(show(&conn, &mut room, &small(7, 1, 5), &from(1), NOW).is_err());
        assert_eq!((made(&room), room.not_yet.len()), (6, 0));
        // Inside a transaction of the caller's, one that fails takes back
        // what it added, and leaves what the others before it added.
        conn.execute_batch("DROP TRIGGER refuses; BEGIN").unwrap();
        take(&conn, &mut room, &small(8, 1, 5), &from(1), NOW).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER refuses BEFORE INSERT ON relay_channels
             BEGIN SELECT RAISE(ABORT, 'refused'); END;",
        )
        .unwrap();
        assert!(take(&conn, &mut room, &small(9, 1, 5), &from(1), NOW).is_err());
        assert_eq!((made(&room), room.not_yet.len()), (7, 1));
        conn.execute_batch("COMMIT").unwrap();
        room.written();
        assert_eq!(made(&room), 7);
        assert_eq!(held(&conn), [0, 1, 2, 3, 4, 5, 8]);

        // A write that counted a channel and then failed, where it could
        // not be written for good: the channel is counted no more,
        // whether the write was its own or part of the caller's. What
        // the writes before it counted stays.
        room.added_channel(address, NOW + 5);
        assert_eq!((made(&room), room.not_yet.len()), (8, 1));
        room.ended(true, 0, false);
        assert_eq!((made(&room), room.not_yet.len()), (7, 0));
        room.added_channel(address, NOW + 6);
        room.added_channel(address, NOW + 7);
        room.ended(false, 1, false);
        assert_eq!((made(&room), room.not_yet.len()), (8, 1));
        assert_eq!(room.new_channels[&address].last(), Some(&(NOW + 6)));
        // Done, in a write of the caller's: counted, and still under way.
        room.added_channel(address, NOW + 8);
        room.ended(false, 1, true);
        assert_eq!((made(&room), room.not_yet.len()), (9, 2));
        // Done, in a write of its own: written.
        room.ended(true, 2, true);
        assert_eq!((made(&room), room.not_yet.len()), (9, 0));
    }

    /// The 257th channel that one address makes a relay take in an hour
    /// is refused. What is already held is not counted, nor is another
    /// address, nor a relay that the operator lists.
    #[test]
    fn test_the_257th_new_channel_of_an_address_in_an_hour_is_refused() {
        let (conn, mut room) = relay();
        assert_eq!(NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR, 256);
        // The first at the start of the hour, and the rest a minute in.
        for c in 0..256 {
            let at = if c == 0 { NOW } else { NOW + 60 };
            assert_eq!(
                take(&conn, &mut room, &small(c, 1, 5), &from(1), at).unwrap(),
                Taken::Stored,
                "{c}"
            );
        }
        // The 257th, pushed and shown.
        assert_eq!(
            take(&conn, &mut room, &small(256, 1, 5), &from(1), NOW + 120).unwrap(),
            Taken::Refused(Refused::OverAllowance)
        );
        assert_eq!(
            show(&conn, &mut room, &small(256, 1, 5), &from(1), NOW + 120).unwrap(),
            Shown::Refused(Refused::OverAllowance)
        );
        assert_eq!(held_channel(&conn, &channel(256)).unwrap(), None);
        assert!(!room.may_add_channel(IpAddr::from([192, 0, 2, 1]), NOW + 120));

        // An entry in a channel that the relay holds is no new channel:
        // another author's, and a newer revision.
        assert_eq!(
            take(&conn, &mut room, &small(7, 2, 5), &from(1), NOW + 120).unwrap(),
            Taken::Stored
        );
        assert_eq!(
            take(&conn, &mut room, &small(7, 1, 6), &from(1), NOW + 120).unwrap(),
            Taken::Stored
        );
        // Another address has an allowance of its own, and a relay that
        // the operator lists is not counted.
        assert_eq!(
            take(&conn, &mut room, &small(256, 1, 5), &from(2), NOW + 120).unwrap(),
            Taken::Stored
        );
        assert_eq!(
            take(&conn, &mut room, &small(257, 1, 5), &LISTED, NOW + 120).unwrap(),
            Taken::Stored
        );
        // And still refused: what was refused, and what others added, did
        // not count for it or against it.
        assert_eq!(
            take(&conn, &mut room, &small(258, 1, 5), &from(1), NOW + 3599).unwrap(),
            Taken::Refused(Refused::OverAllowance)
        );

        // An hour after the first, there is room for one: the first is
        // out of the hour, and the rest are not.
        assert_eq!(
            take(&conn, &mut room, &small(258, 1, 5), &from(1), NOW + 3600).unwrap(),
            Taken::Stored
        );
        assert_eq!(
            take(&conn, &mut room, &small(259, 1, 5), &from(1), NOW + 3600).unwrap(),
            Taken::Refused(Refused::OverAllowance)
        );
        // An hour after the rest, the address has all but one again.
        assert!(room.may_add_channel(IpAddr::from([192, 0, 2, 1]), NOW + 3660));
        assert_eq!(
            room.new_channels[&IpAddr::from([192, 0, 2, 1])],
            [NOW + 3600]
        );
    }

    /// What an address is counted for is the channels it made the relay
    /// take: not what was refused, and not what was already held. An
    /// address that has added nothing within the hour is forgotten.
    #[test]
    fn test_an_address_is_counted_for_each_channel_it_made_the_relay_take() {
        let (conn, mut room) = relay_of(2 * SMALL);
        let address = |n: u8| IpAddr::from([192, 0, 2, n]);
        let v6 = IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
        let made_by = |room: &Room, of: IpAddr| room.new_channels.get(&of).map_or(0, Vec::len);

        take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).unwrap();
        take(&conn, &mut room, &small(1, 2, 5), &from(1), NOW).unwrap();
        take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).unwrap();
        assert_eq!(made_by(&room, address(1)), 1);
        // A new channel that was refused for room counts for nothing.
        assert_eq!(
            take(&conn, &mut room, &small(2, 1, 5), &from(2), NOW).unwrap(),
            Taken::Refused(Refused::NoRoom)
        );
        assert_eq!(made_by(&room, address(2)), 0);
        // Nor does what a relay that the operator lists passes on.
        room.max_bytes = u64::MAX;
        take(&conn, &mut room, &small(2, 1, 5), &LISTED, NOW).unwrap();
        assert_eq!(room.new_channels.len(), 1);
        // An address of the other kind is an address.
        take(
            &conn,
            &mut room,
            &small(3, 1, 5),
            &Asker::Address(v6),
            NOW + 1800,
        )
        .unwrap();
        assert_eq!(made_by(&room, v6), 1);

        // Forgotten once nothing of theirs is within the hour.
        room.forget_old(NOW + 3599);
        assert_eq!(room.new_channels.len(), 2);
        room.forget_old(NOW + 3600);
        assert_eq!(room.new_channels.len(), 1);
        assert_eq!(made_by(&room, v6), 1);
        room.forget_old(NOW + 1800 + 3600);
        assert!(room.new_channels.is_empty());
    }

    // ── How long it has held a channel ───────────────────────────────

    /// A channel is held from when the relay first took it. Where a relay
    /// that the operator lists says it has held it since an earlier time,
    /// the earlier of the two is kept, also for a channel already held.
    #[test]
    fn test_a_channel_is_held_from_the_earlier_of_when_it_was_taken_and_what_a_listed_relay_says() {
        let (conn, mut room) = relay();
        take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).unwrap();
        assert_eq!(since(&conn, 1), Some(NOW));
        // Later entries, from an address and from a listed relay that
        // says nothing, leave the time as it is.
        take(&conn, &mut room, &small(1, 2, 5), &from(1), NOW + 500).unwrap();
        take(&conn, &mut room, &small(1, 3, 5), &LISTED, NOW + 600).unwrap();
        assert_eq!(since(&conn, 1), Some(NOW));

        // A listed relay says an earlier time, with an entry that is
        // stored: the earlier is kept.
        let said = listed_since(NOW - 100);
        let passed_on = small(1, 4, 5);
        take(&conn, &mut room, &passed_on, &said, NOW + 700).unwrap();
        assert_eq!(since(&conn, 1), Some(NOW - 100));
        // With an entry that is already held, and with one shown.
        assert_eq!(
            take(
                &conn,
                &mut room,
                &passed_on,
                &listed_since(NOW - 200),
                NOW + 700
            )
            .unwrap(),
            Taken::AlreadyHeld
        );
        assert_eq!(since(&conn, 1), Some(NOW - 200));
        assert!(matches!(
            show(
                &conn,
                &mut room,
                &small(1, 4, 4),
                &listed_since(NOW - 300),
                NOW + 700
            )
            .unwrap(),
            Shown::Another { .. }
        ));
        assert_eq!(since(&conn, 1), Some(NOW - 300));
        // And with no entry at all.
        assert!(listed_relay_says(&conn, &channel(1), NOW - 400).unwrap());
        assert_eq!(since(&conn, 1), Some(NOW - 400));

        // A later time than the one kept is not kept, nor the same one.
        for later in [NOW - 399, NOW, NOW + 10_000, NOW - 400] {
            assert!(!listed_relay_says(&conn, &channel(1), later).unwrap());
            take(
                &conn,
                &mut room,
                &small(1, 4, 5),
                &listed_since(later),
                NOW + 800,
            )
            .unwrap();
            assert_eq!(since(&conn, 1), Some(NOW - 400));
        }
        // A time that is not after 0 is no time.
        for none in [0, -1, i64::MIN] {
            assert!(!listed_relay_says(&conn, &channel(1), none).unwrap());
            take(
                &conn,
                &mut room,
                &small(1, 4, 5),
                &listed_since(none),
                NOW + 800,
            )
            .unwrap();
            assert_eq!(since(&conn, 1), Some(NOW - 400));
        }

        // A channel that is new here, from a listed relay: the time it
        // says, where that is earlier than now, and now otherwise.
        take(
            &conn,
            &mut room,
            &small(2, 1, 5),
            &listed_since(NOW - 5000),
            NOW + 900,
        )
        .unwrap();
        take(
            &conn,
            &mut room,
            &small(3, 1, 5),
            &listed_since(NOW + 5000),
            NOW + 900,
        )
        .unwrap();
        take(
            &conn,
            &mut room,
            &small(4, 1, 5),
            &listed_since(0),
            NOW + 900,
        )
        .unwrap();
        take(
            &conn,
            &mut room,
            &small(5, 1, 5),
            &listed_since(-7),
            NOW + 900,
        )
        .unwrap();
        assert_eq!(since(&conn, 2), Some(NOW - 5000));
        for c in [3, 4, 5] {
            assert_eq!(since(&conn, c), Some(NOW + 900), "{c}");
        }
        // Nothing is kept for a channel that the relay does not hold.
        assert!(!listed_relay_says(&conn, &channel(6), NOW - 5000).unwrap());
        assert_eq!(held_channel(&conn, &channel(6)).unwrap(), None);
        take(&conn, &mut room, &small(6, 1, 5), &from(1), NOW + 900).unwrap();
        assert_eq!(since(&conn, 6), Some(NOW + 900));
        // None of it is use of a channel, or changes what one holds.
        assert_eq!(used_at(&conn, 1), Some(NOW));
        assert_eq!(counted(&conn), 9 * SMALL);
    }

    /// A channel that was dropped has no time. Taken again, it is held
    /// from then: it is new, counts against the address's allowance
    /// again, and is the first to go.
    #[test]
    fn test_a_channel_that_was_dropped_and_is_taken_again_is_new() {
        let (conn, mut room) = relay_of(2 * SMALL);
        take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).unwrap();
        take(&conn, &mut room, &small(2, 1, 5), &from(1), NOW + 10).unwrap();
        let first_holding = (mark_of(&conn, 1), mark_of(&conn, 2));
        // The older of the two is held from far back, by a listed relay's
        // word, and was used a moment ago.
        assert!(listed_relay_says(&conn, &channel(1), NOW - 365 * DAY).unwrap());
        // A third, newer still, and room is made by hand: the two newest
        // go, and the one held longest stays.
        room.max_bytes = 3 * SMALL;
        take(&conn, &mut room, &small(3, 1, 5), &from(1), NOW + 20).unwrap();
        assert_eq!(make_room(&conn, SMALL).unwrap(), [channel(3), channel(2)]);
        assert_eq!(held(&conn), [1]);
        // Then that one too.
        assert_eq!(make_room(&conn, 0).unwrap(), [channel(1)]);
        assert_eq!(held_channel(&conn, &channel(1)).unwrap(), None);
        assert!(ids(&conn, 1).is_empty());

        // Taken again, each is held from then: the year is gone with the
        // row, and the very entry it held is stored as a first one.
        take(&conn, &mut room, &small(2, 1, 5), &from(1), NOW + 500).unwrap();
        assert_eq!(
            take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW + 600).unwrap(),
            Taken::Stored
        );
        assert_eq!(
            held_channel(&conn, &channel(1)).unwrap(),
            Some(HeldChannel {
                held_since: NOW + 600,
                used_at: NOW + 600,
                bytes: SMALL,
                mark: mark_of(&conn, 1),
            })
        );
        assert_eq!(since(&conn, 2), Some(NOW + 500));
        // Each is another holding, under another mark than the one that
        // was dropped.
        assert_ne!(mark_of(&conn, 1), first_holding.0);
        assert_ne!(mark_of(&conn, 2), first_holding.1);
        assert_ne!(mark_of(&conn, 1), NO_MARK);
        // It counted against the address again: five channels in all.
        assert_eq!(room.new_channels[&IpAddr::from([192, 0, 2, 1])].len(), 5);
        // And it is the newest now, where it was the oldest: it goes
        // first.
        assert_eq!(make_room(&conn, SMALL).unwrap(), [channel(1)]);
        assert_eq!(held(&conn), [2]);

        // So is one that went because nobody used it.
        assert_eq!(
            sweep_unused(&conn, NOW + 500 + 90 * DAY).unwrap(),
            [channel(2)]
        );
        take(&conn, &mut room, &small(2, 1, 5), &from(1), NOW + 91 * DAY).unwrap();
        assert_eq!(since(&conn, 2), Some(NOW + 91 * DAY));
    }

    /// When a channel was last used is written at most once an hour, and
    /// never an earlier time than the one kept: a proof that holds, an
    /// entry shown that the relay holds, and one shown that it takes, each
    /// within the hour of the time kept, leave that time as it is. One
    /// second past the hour, the time is written.
    #[test]
    fn test_when_a_channel_was_used_is_written_at_most_once_an_hour_and_never_earlier() {
        assert_eq!(USED_STEP_SECS, 3600);
        let (conn, mut room) = relay();
        let held_entry = small(1, 1, 5);
        take(&conn, &mut room, &held_entry, &from(1), NOW).unwrap();
        let proof = proof::make(&secret(1), &SESSION, &peer()).unwrap();
        let proved = |at: i64| {
            let found = prove(&conn, &channel(1), &SESSION, &peer(), &proof, at).unwrap();
            assert_eq!(found, Proof::Holds { channel_held: true });
        };
        let shown_held = |at: i64| {
            let mut room = Room::new(u64::MAX);
            assert_eq!(
                show(&conn, &mut room, &held_entry, &from(1), at).unwrap(),
                Shown::Held
            );
        };

        // Within the hour, to the second: nothing is written.
        for at in [NOW, NOW + 1, NOW + 600, NOW + HOUR - 1, NOW + HOUR] {
            proved(at);
            shown_held(at);
            assert_eq!(used_at(&conn, 1), Some(NOW), "{}", at - NOW);
        }
        // A second past it: a proof is written down.
        proved(NOW + HOUR + 1);
        assert_eq!(used_at(&conn, 1), Some(NOW + HOUR + 1));
        // And then the next hour runs from there, for a show as well.
        shown_held(NOW + 2 * HOUR);
        shown_held(NOW + 2 * HOUR + 1);
        assert_eq!(used_at(&conn, 1), Some(NOW + HOUR + 1));
        shown_held(NOW + 2 * HOUR + 2);
        assert_eq!(used_at(&conn, 1), Some(NOW + 2 * HOUR + 2));

        // An earlier time is never written: a clock that was set back,
        // by a minute and by a year.
        let kept = NOW + 2 * HOUR + 2;
        for at in [kept - 60, kept - 365 * DAY, 1, 0] {
            proved(at);
            shown_held(at);
            assert_eq!(used_at(&conn, 1), Some(kept), "{at}");
        }

        // An entry that is shown and taken, in a channel that the relay
        // holds: within the hour it is taken, and no time is written.
        let later = small(1, 1, 6);
        assert_eq!(
            show(&conn, &mut room, &later, &from(1), kept + 60).unwrap(),
            Shown::Taken
        );
        assert_eq!(ids(&conn, 1), [later.id()]);
        assert_eq!(used_at(&conn, 1), Some(kept));
        // Past the hour, it is.
        let latest = small(1, 1, 7);
        assert_eq!(
            show(&conn, &mut room, &latest, &from(1), kept + HOUR + 1).unwrap(),
            Shown::Taken
        );
        assert_eq!(used_at(&conn, 1), Some(kept + HOUR + 1));
        // Since when the channel is held is as it was all along.
        assert_eq!(since(&conn, 1), Some(NOW));
    }

    /// Where the time a channel was used is not written, nothing is: an
    /// entry shown that the relay holds, another that it holds, a proof,
    /// and what a listed relay says of when the channel was used, are each
    /// answered while another connection holds the database for writing.
    /// Only what has something to write waits for it.
    #[test]
    fn test_an_answer_that_writes_nothing_does_not_take_the_database_for_writing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        let conn = db::open(&path).unwrap();
        conn.busy_timeout(std::time::Duration::ZERO).unwrap();
        let mut room = Room::new(u64::MAX);
        let held_entry = small(1, 1, 5);
        take(&conn, &mut room, &held_entry, &from(1), NOW).unwrap();
        let proof = proof::make(&secret(1), &SESSION, &peer()).unwrap();

        // Another connection takes the database for writing, and keeps it.
        let other = Connection::open(&path).unwrap();
        other.execute_batch("BEGIN IMMEDIATE").unwrap();

        // Within the hour of the time kept: each is answered, by reading.
        let at = NOW + 600;
        assert_eq!(
            show(&conn, &mut room, &held_entry, &from(2), at).unwrap(),
            Shown::Held
        );
        assert!(matches!(
            show(&conn, &mut room, &small(1, 1, 4), &from(2), at).unwrap(),
            Shown::Another { .. }
        ));
        assert_eq!(
            prove(&conn, &channel(1), &SESSION, &peer(), &proof, at).unwrap(),
            Proof::Holds { channel_held: true }
        );
        assert!(!listed_relay_used(&conn, &channel(1), at, at).unwrap());
        // And so is an earlier "held since" that is no earlier, and what
        // a listed relay shows with both of its times.
        assert!(!listed_relay_says(&conn, &channel(1), NOW + 5).unwrap());
        assert_eq!(
            show(&conn, &mut room, &held_entry, &listed(NOW + 5, at), at).unwrap(),
            Shown::Held
        );

        // The control: what has something to write cannot, while the
        // other connection holds the database. An entry that the relay
        // would take, and a use that is past the hour.
        assert!(show(&conn, &mut room, &small(1, 1, 6), &from(2), at).is_err());
        let past = NOW + HOUR + 1;
        assert!(show(&conn, &mut room, &held_entry, &from(2), past).is_err());
        assert!(prove(&conn, &channel(1), &SESSION, &peer(), &proof, past).is_err());
        assert!(listed_relay_used(&conn, &channel(1), past, past).is_err());
        assert!(listed_relay_says(&conn, &channel(1), NOW - DAY).is_err());

        // Once the other lets go, each is done.
        other.execute_batch("ROLLBACK").unwrap();
        assert_eq!(
            show(&conn, &mut room, &held_entry, &from(2), past).unwrap(),
            Shown::Held
        );
        assert_eq!(used_at(&conn, 1), Some(past));
        assert!(listed_relay_says(&conn, &channel(1), NOW - DAY).unwrap());
    }

    // ── Relays that work together ────────────────────────────────────

    /// A channel was last used at the later of two times: when this relay
    /// saw its key proved or an entry of it shown, and when a relay that
    /// the operator lists says it was. No time later than this relay's
    /// own clock is kept, and none that is not more than an hour later
    /// than the one kept.
    #[test]
    fn test_a_channel_was_last_used_at_the_later_of_here_and_what_a_listed_relay_says() {
        let (conn, mut room) = relay();
        take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).unwrap();
        assert_eq!(used_at(&conn, 1), Some(NOW));
        let clock = NOW + 3 * HOUR;

        // A listed relay says a later time, with no entry at all: kept.
        assert!(listed_relay_used(&conn, &channel(1), NOW + 2 * HOUR, clock).unwrap());
        assert_eq!(used_at(&conn, 1), Some(NOW + 2 * HOUR));
        // An earlier time, and the same one, are not kept.
        for earlier in [NOW + 2 * HOUR - 1, NOW, NOW - 365 * DAY, NOW + 2 * HOUR] {
            assert!(!listed_relay_used(&conn, &channel(1), earlier, clock).unwrap());
            assert_eq!(used_at(&conn, 1), Some(NOW + 2 * HOUR));
        }
        // The write itself puts down no earlier time, and not the same
        // one: whatever was read before it.
        for earlier in [NOW + 2 * HOUR - 1, NOW, 1, NOW + 2 * HOUR] {
            assert!(!write_used(&conn, &channel(1), earlier).unwrap());
            assert_eq!(used_at(&conn, 1), Some(NOW + 2 * HOUR));
        }
        // Nor is a later one that is within the hour of the one kept, to
        // the second. One second more, and it is.
        for within in [NOW + 2 * HOUR + 1, NOW + 3 * HOUR - 1, NOW + 3 * HOUR] {
            assert!(!listed_relay_used(&conn, &channel(1), within, NOW + DAY).unwrap());
            assert_eq!(used_at(&conn, 1), Some(NOW + 2 * HOUR));
        }
        assert!(listed_relay_used(&conn, &channel(1), NOW + 3 * HOUR + 1, NOW + DAY).unwrap());
        assert_eq!(used_at(&conn, 1), Some(NOW + 3 * HOUR + 1));
        // A time that is not after 0 is no time.
        for none in [0, -1, i64::MIN] {
            assert!(!listed_relay_used(&conn, &channel(1), none, clock).unwrap());
            assert_eq!(used_at(&conn, 1), Some(NOW + 3 * HOUR + 1));
        }
        // A time later than this relay's clock is kept as this relay's
        // time, and no later: also the latest there is.
        assert!(listed_relay_used(&conn, &channel(1), NOW + 100 * HOUR, NOW + 5 * HOUR).unwrap());
        assert_eq!(used_at(&conn, 1), Some(NOW + 5 * HOUR));
        assert!(!listed_relay_used(&conn, &channel(1), i64::MAX, NOW + 5 * HOUR).unwrap());
        assert!(listed_relay_used(&conn, &channel(1), i64::MAX, NOW + 7 * HOUR).unwrap());
        assert_eq!(used_at(&conn, 1), Some(NOW + 7 * HOUR));

        // With an entry that it passes on: one that is stored, one that
        // is already held, and one shown.
        let clock = NOW + 50 * HOUR;
        let passed_on = small(1, 2, 5);
        take(
            &conn,
            &mut room,
            &passed_on,
            &listed(NOW, NOW + 9 * HOUR),
            clock,
        )
        .unwrap();
        assert_eq!(used_at(&conn, 1), Some(NOW + 9 * HOUR));
        assert_eq!(
            take(
                &conn,
                &mut room,
                &passed_on,
                &listed(NOW, NOW + 11 * HOUR),
                clock
            )
            .unwrap(),
            Taken::AlreadyHeld
        );
        assert_eq!(used_at(&conn, 1), Some(NOW + 11 * HOUR));
        assert!(matches!(
            show(
                &conn,
                &mut room,
                &small(1, 2, 4),
                &listed(NOW, NOW + 13 * HOUR),
                clock
            )
            .unwrap(),
            Shown::Another { .. }
        ));
        assert_eq!(used_at(&conn, 1), Some(NOW + 13 * HOUR));
        // An earlier time with an entry, one within the hour, and none
        // said, change nothing.
        for asker in [
            listed(NOW, NOW + 10),
            listed(NOW, NOW + 14 * HOUR),
            listed(NOW, 0),
            listed_since(NOW),
        ] {
            take(&conn, &mut room, &small(1, 2, 5), &asker, clock).unwrap();
            assert_eq!(used_at(&conn, 1), Some(NOW + 13 * HOUR));
        }
        // An address says nothing of it: a push is no use of a channel.
        take(&conn, &mut room, &small(1, 3, 5), &from(1), NOW + 60 * HOUR).unwrap();
        assert_eq!(used_at(&conn, 1), Some(NOW + 13 * HOUR));
        // None of it changed since when the channel is held, its mark, or
        // what it holds.
        assert_eq!(since(&conn, 1), Some(NOW));
        assert_eq!(counted(&conn), 3 * SMALL);

        // Nothing is kept for a channel that the relay does not hold.
        assert!(!listed_relay_used(&conn, &channel(6), NOW + 100, NOW + 500).unwrap());
        assert_eq!(held_channel(&conn, &channel(6)).unwrap(), None);
    }

    /// A channel that is new here, from a relay that the operator lists:
    /// it was last used when that relay says it was. That relay passing
    /// it on is no use of it, or a channel that nobody uses would live on
    /// for as long as relays passed it between them.
    #[test]
    fn test_a_channel_from_a_listed_relay_was_last_used_when_that_relay_says() {
        let (conn, mut room) = relay();
        // Held there for a year, and last used ten days ago.
        let said = listed(NOW - 365 * DAY, NOW - 10 * DAY);
        assert_eq!(
            take(&conn, &mut room, &small(1, 1, 5), &said, NOW).unwrap(),
            Taken::Stored
        );
        assert_eq!(since(&conn, 1), Some(NOW - 365 * DAY));
        assert_eq!(used_at(&conn, 1), Some(NOW - 10 * DAY));
        // A time later than this relay's clock is this relay's time.
        take(
            &conn,
            &mut room,
            &small(2, 1, 5),
            &listed(NOW - DAY, NOW + 9000),
            NOW,
        )
        .unwrap();
        assert_eq!(used_at(&conn, 2), Some(NOW));
        // With no time said, or one that is not after 0, it is used now.
        take(
            &conn,
            &mut room,
            &small(3, 1, 5),
            &listed(NOW - DAY, 0),
            NOW,
        )
        .unwrap();
        take(
            &conn,
            &mut room,
            &small(4, 1, 5),
            &listed_since(NOW - DAY),
            NOW,
        )
        .unwrap();
        take(
            &conn,
            &mut room,
            &small(5, 1, 5),
            &listed(NOW - DAY, -5),
            NOW,
        )
        .unwrap();
        for c in [3, 4, 5] {
            assert_eq!(used_at(&conn, c), Some(NOW), "{c}");
        }
        // From an address it is used now, as it always was.
        take(&conn, &mut room, &small(6, 1, 5), &from(1), NOW).unwrap();
        assert_eq!(used_at(&conn, 6), Some(NOW));

        // The first goes 90 days after it was last used there, which is
        // 80 days from now: not 90 days after this relay took it.
        assert!(sweep_unused(&conn, NOW + 80 * DAY - 1).unwrap().is_empty());
        assert_eq!(sweep_unused(&conn, NOW + 80 * DAY).unwrap(), [channel(1)]);
        assert_eq!(held(&conn), [2, 3, 4, 5, 6]);
    }

    /// A channel that a relay has only from a relay it works with: it
    /// sees no proof of it and no entry of it shown. It is not dropped as
    /// unused while it is in use at the other relay, which says so.
    #[test]
    fn test_a_channel_in_use_at_a_listed_relay_is_not_swept_here() {
        let (conn, mut room) = relay();
        let said = listed(NOW, NOW);
        take(&conn, &mut room, &small(1, 1, 5), &said, NOW).unwrap();
        take(&conn, &mut room, &small(2, 1, 5), &said, NOW).unwrap();
        // The first is proved at the other relay 89 days on, and that
        // relay tells this one. The second is used nowhere.
        let later = NOW + 89 * DAY;
        assert!(listed_relay_used(&conn, &channel(1), later, later + 60).unwrap());

        // At 90 days the second goes, and the first stays.
        assert_eq!(sweep_unused(&conn, NOW + 90 * DAY).unwrap(), [channel(2)]);
        assert_eq!(held(&conn), [1]);
        // The first goes 90 days after it was last used there.
        assert!(
            sweep_unused(&conn, later + 90 * DAY - 1)
                .unwrap()
                .is_empty()
        );
        assert_eq!(sweep_unused(&conn, later + 90 * DAY).unwrap(), [channel(1)]);
    }

    /// The rule of the sweep, as a relay asks it of a channel that it is
    /// told of and does not hold: unused is 90 days to the second, as the
    /// sweep has it.
    #[test]
    fn test_a_channel_that_is_told_of_is_unused_by_the_rule_of_the_sweep() {
        assert!(!unused(NOW, NOW));
        assert!(!unused(NOW, NOW + 90 * DAY - 1));
        assert!(unused(NOW, NOW + 90 * DAY));
        assert!(unused(NOW, NOW + 365 * DAY));
        // A time ahead of the clock is not unused, and the latest time
        // there is does not wrap round to the earliest.
        assert!(!unused(NOW + DAY, NOW));
        assert!(!unused(i64::MAX, NOW));

        // The sweep drops a channel exactly where the rule says so.
        let (conn, mut room) = relay();
        take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).unwrap();
        for at in [NOW, NOW + 90 * DAY - 1] {
            assert!(!unused(used_at(&conn, 1).unwrap(), at));
            assert!(sweep_unused(&conn, at).unwrap().is_empty());
        }
        assert!(unused(used_at(&conn, 1).unwrap(), NOW + 90 * DAY));
        assert_eq!(sweep_unused(&conn, NOW + 90 * DAY).unwrap(), [channel(1)]);
    }

    /// What a relay tells a relay it works with: each channel it holds,
    /// in the order of their IDs and in pages, with its mark, since when
    /// it is held, when it was last used, and the place of the entry
    /// stored last in it.
    #[test]
    fn test_a_relay_tells_which_channels_it_holds_in_pages_by_their_ids() {
        let (conn, mut room) = relay();
        const START: [u8; 32] = [0; 32];
        assert!(held_channels(&conn, &START, 100).unwrap().is_empty());

        // Seven channels, taken in an order that is not that of their
        // IDs, each at its own time.
        for (n, c) in [5u16, 2, 7, 1, 6, 3, 4].into_iter().enumerate() {
            take(&conn, &mut room, &small(c, 1, 5), &from(1), NOW + n as i64).unwrap();
        }
        // One of them holds three entries, of which one replaced another:
        // four places were given out in it. One was used later, and one
        // is held from an earlier time by a listed relay's word.
        take(&conn, &mut room, &small(2, 2, 5), &from(1), NOW + 50).unwrap();
        take(&conn, &mut room, &small(2, 3, 5), &from(1), NOW + 50).unwrap();
        take(&conn, &mut room, &small(2, 2, 6), &from(1), NOW + 50).unwrap();
        let proved = proof::make(&secret(7), &SESSION, &peer()).unwrap();
        prove(&conn, &channel(7), &SESSION, &peer(), &proved, NOW + DAY).unwrap();
        listed_relay_says(&conn, &channel(6), NOW - DAY).unwrap();
        // What the relay holds of the older kind is no part of it.
        conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id,
                                   created_at, updated_at)
             VALUES ('old_a', 'named', 'realtime', 'open', X'00', '2026-01-01', '2026-01-01')",
            [],
        )
        .unwrap();

        let all = held_channels(&conn, &START, 100).unwrap();
        assert_eq!(all.len(), 7);
        // In the order of their IDs, each once: which is not the order in
        // which the relay took them.
        let mut sorted: Vec<[u8; 32]> = (1..=7).map(channel).collect();
        sorted.sort();
        let told: Vec<[u8; 32]> = all.iter().map(|told| told.channel).collect();
        assert_eq!(told, sorted);
        assert_ne!(sorted, [5u16, 2, 7, 1, 6, 3, 4].map(channel));
        // Each as the relay holds it.
        for told in &all {
            assert_eq!(
                Some(told.held),
                held_channel(&conn, &told.channel).unwrap(),
                "{told:?}"
            );
            assert_ne!(told.held.mark, NO_MARK);
        }
        let of = |c: u16| *all.iter().find(|told| told.channel == channel(c)).unwrap();
        assert_eq!((of(2).places, of(2).held.bytes), (4, 3 * SMALL));
        assert_eq!((of(1).places, of(1).held.bytes), (1, SMALL));
        assert_eq!(of(7).held.used_at, NOW + DAY);
        assert_eq!(of(6).held.held_since, NOW - DAY);
        // The places are what a puller is handed as its place: whoever
        // has pulled a channel to the end holds that place.
        for c in 1..=7 {
            assert_eq!(paged(&conn, c, true, 0, 100).next, of(c).places, "{c}");
        }

        // In pages: each goes on after the last ID of the one before, and
        // together they are the whole list, with nothing twice.
        for limit in [1, 2, 3, 6, 7, 8] {
            let mut after = START;
            let mut paged = Vec::new();
            // At most a page for each channel, and one that is empty.
            for _ in 0..=all.len() {
                let page = held_channels(&conn, &after, limit).unwrap();
                assert!(page.len() <= limit as usize);
                let Some(last) = page.last() else { break };
                after = last.channel;
                paged.extend(page);
            }
            assert_eq!(paged, all, "{limit}");
        }
        assert!(held_channels(&conn, &START, 0).unwrap().is_empty());
        assert!(
            held_channels(&conn, &sorted[6], 100).unwrap().is_empty(),
            "nothing is after the last"
        );
        assert_eq!(held_channels(&conn, &[0xff; 32], 100).unwrap(), []);

        // A channel that is dropped is told no more.
        assert_eq!(make_room(&conn, 6 * SMALL).unwrap().len(), 3);
        let left: Vec<[u8; 32]> = held_channels(&conn, &START, 100)
            .unwrap()
            .iter()
            .map(|told| told.channel)
            .collect();
        assert_eq!(left.len(), 4);
        assert!(
            left.iter()
                .all(|c| held_channel(&conn, c).unwrap().is_some())
        );
    }

    /// One answer tells of no more channels than a page of them holds,
    /// however many are asked for.
    #[test]
    fn test_one_answer_tells_of_at_most_a_pages_worth_of_channels() {
        let (conn, _room) = relay();
        // Rows as the relay keeps them, without their entries: this is
        // about how many are told.
        let most = RELAY_CHANNELS_PAGE_MAX as usize;
        for n in 0..most + 5 {
            let mut id = [0x11u8; 32];
            id[..4].copy_from_slice(&(n as u32 + 1).to_be_bytes());
            conn.execute(
                "INSERT INTO relay_channels (channel_id, mark, held_since, used_at, bytes)
                 VALUES (?1, X'0102030405060708', ?2, ?2, 1280)",
                params![id.as_slice(), NOW],
            )
            .unwrap();
        }
        for limit in [
            RELAY_CHANNELS_PAGE_MAX,
            RELAY_CHANNELS_PAGE_MAX + 1,
            u32::MAX,
        ] {
            let page = held_channels(&conn, &[0; 32], limit).unwrap();
            assert_eq!(page.len(), most, "{limit}");
        }
        let page = held_channels(&conn, &[0; 32], u32::MAX).unwrap();
        let rest = held_channels(&conn, &page[most - 1].channel, u32::MAX).unwrap();
        assert_eq!(rest.len(), 5);
        // No entry is stored in them: no place was given out.
        assert!(page.iter().all(|told| told.places == 0));
    }

    // ── What it answers ──────────────────────────────────────────────

    /// Shown the entry it holds, an earlier one, another at that
    /// revision, and a later one: the three answers, from the store.
    #[test]
    fn test_shown_an_entry_a_relay_answers_with_what_it_holds() {
        let (conn, mut room) = relay();
        let held_entry = small(1, 1, 5);
        // It holds none from that author in that slot: it takes this one.
        assert_eq!(
            show(&conn, &mut room, &held_entry, &from(1), NOW).unwrap(),
            Shown::Taken
        );
        assert_eq!(ids(&conn, 1), [held_entry.id()]);
        assert_eq!(since(&conn, 1), Some(NOW));

        // The same entry: it holds that very one.
        assert_eq!(
            show(&conn, &mut room, &held_entry, &from(2), NOW + 60).unwrap(),
            Shown::Held
        );
        // An earlier one: here is the one it holds.
        let another = Shown::Another {
            entry: Box::new(held_entry.clone()),
            cost: SMALL,
        };
        for rev in [4, 1] {
            assert_eq!(
                show(&conn, &mut room, &small(1, 1, rev), &from(2), NOW + 60).unwrap(),
                another
            );
        }
        // Another at that revision: here is the one it holds.
        let at_that_revision = made(1, 1, 5, "notes.md", "another text");
        assert_ne!(at_that_revision.id(), held_entry.id());
        assert_eq!(
            show(&conn, &mut room, &at_that_revision, &from(2), NOW + 60).unwrap(),
            another
        );
        // Nothing of those was stored.
        assert_eq!(ids(&conn, 1), [held_entry.id()]);

        // A later one: it held an earlier one, and takes this one.
        let later = made(1, 1, 6, "notes.md", &"x".repeat(3000));
        assert_eq!(
            show(&conn, &mut room, &later, &from(2), NOW + 120).unwrap(),
            Shown::Taken
        );
        assert_eq!(ids(&conn, 1), [later.id()]);
        // And then the first is the earlier one, and is answered with the
        // later, at what that one is counted at.
        assert_eq!(
            show(&conn, &mut room, &held_entry, &from(1), NOW + 180).unwrap(),
            Shown::Another {
                entry: Box::new(later.clone()),
                cost: 4096 + 1024,
            }
        );
        assert_eq!(
            show(&conn, &mut room, &later, &from(1), NOW + 180).unwrap(),
            Shown::Held
        );

        // The answer is about that author in that slot: another author's
        // entry there, and that author's elsewhere, are each taken.
        assert_eq!(
            show(&conn, &mut room, &small(1, 2, 1), &from(1), NOW + 180).unwrap(),
            Shown::Taken
        );
        assert_eq!(
            show(
                &conn,
                &mut room,
                &made(1, 1, 1, "other.md", "another name"),
                &from(1),
                NOW + 180
            )
            .unwrap(),
            Shown::Taken
        );
        assert_eq!(counted(&conn), 4096 + 1024 + 2 * SMALL);
    }

    /// Shown an entry in short, a relay answers one of three things. It
    /// holds that entry. It holds none, or an earlier one: the entry is to
    /// be shown whole, and nothing is taken from a short form. Or it holds
    /// another at that revision or a later one: it says that one's
    /// revision and ID, and no more.
    #[test]
    fn test_shown_an_entry_in_short_a_relay_says_held_whole_or_which_other() {
        let (conn, mut room) = relay();
        let held_entry = small(1, 1, 5);
        // It holds nothing there: whole.
        assert_eq!(short(&conn, &held_entry, NOW).unwrap(), ShownShort::Whole);
        assert_eq!(held(&conn), [0u16; 0]);
        take(&conn, &mut room, &held_entry, &from(1), NOW).unwrap();

        // The same entry: it holds that very one.
        assert_eq!(
            short(&conn, &held_entry, NOW + 60).unwrap(),
            ShownShort::Held
        );
        // An earlier one, and another at that revision: the revision and
        // the ID of the one it holds.
        let other = ShownShort::Other {
            rev: 5,
            id: held_entry.id(),
        };
        let at_that_revision = made(1, 1, 5, "notes.md", "another text");
        assert_ne!(at_that_revision.id(), held_entry.id());
        for shown in [small(1, 1, 4), small(1, 1, 1), at_that_revision] {
            assert_eq!(short(&conn, &shown, NOW + 60).unwrap(), other);
            // The whole entry is answered with that one.
            assert_eq!(
                show(&conn, &mut room, &shown, &from(2), NOW + 60).unwrap(),
                Shown::Another {
                    entry: Box::new(held_entry.clone()),
                    cost: SMALL,
                }
            );
        }
        // A later one: the relay holds an earlier one, and would take
        // this. It cannot from its short form: whole. Nothing is stored.
        let later = made(1, 1, 6, "notes.md", &"x".repeat(3000));
        assert_eq!(short(&conn, &later, NOW + 120).unwrap(), ShownShort::Whole);
        assert_eq!(ids(&conn, 1), [held_entry.id()]);
        // Whole, it is taken: and then its short form is held, and the
        // first is answered with word of it.
        assert_eq!(
            show(&conn, &mut room, &later, &from(2), NOW + 120).unwrap(),
            Shown::Taken
        );
        assert_eq!(short(&conn, &later, NOW + 180).unwrap(), ShownShort::Held);
        assert_eq!(
            short(&conn, &held_entry, NOW + 180).unwrap(),
            ShownShort::Other {
                rev: 6,
                id: later.id(),
            }
        );

        // The answer is about that author in that slot, in that channel:
        // another author's there, that author's under another name, and
        // that slot in another channel, each hold nothing.
        let elsewhere = made(1, 1, 6, "other.md", "another name");
        for shown in [small(1, 2, 6), elsewhere, small(2, 1, 6)] {
            assert_eq!(short(&conn, &shown, NOW + 180).unwrap(), ShownShort::Whole);
        }
        assert_eq!(held(&conn), [1]);
        assert_eq!(ids(&conn, 1), [later.id()]);
    }

    /// A short form that the relay answers with "holds that entry" is use
    /// of the channel, as the whole one is. One that it answers with word
    /// of another, or with a call for the whole one, is not.
    #[test]
    fn test_an_entry_shown_in_short_that_is_held_is_use_of_its_channel() {
        let (conn, mut room) = relay();
        let held_entry = small(1, 1, 5);
        take(&conn, &mut room, &held_entry, &from(1), NOW).unwrap();
        assert_eq!(used_at(&conn, 1), Some(NOW));

        // Another, and whole: the channel was last used when it was.
        assert!(matches!(
            short(&conn, &small(1, 1, 4), NOW + DAY).unwrap(),
            ShownShort::Other { .. }
        ));
        assert_eq!(
            short(&conn, &small(1, 1, 6), NOW + DAY).unwrap(),
            ShownShort::Whole
        );
        assert_eq!(used_at(&conn, 1), Some(NOW));
        // Held: it is used now.
        assert_eq!(
            short(&conn, &held_entry, NOW + 2 * DAY).unwrap(),
            ShownShort::Held
        );
        assert_eq!(used_at(&conn, 1), Some(NOW + 2 * DAY));
        // So a channel of which an entry is shown in short is not swept.
        assert_eq!(
            short(&conn, &held_entry, NOW + 100 * DAY).unwrap(),
            ShownShort::Held
        );
        assert!(sweep_unused(&conn, NOW + 150 * DAY).unwrap().is_empty());
        assert_eq!(sweep_unused(&conn, NOW + 190 * DAY).unwrap(), [channel(1)]);
    }

    /// A short form is answered by reading: while another connection
    /// holds the database for writing, each of its three answers is
    /// given. Only a use that is past the hour has something to write.
    #[test]
    fn test_an_entry_shown_in_short_is_answered_by_reading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        let conn = db::open(&path).unwrap();
        conn.busy_timeout(std::time::Duration::ZERO).unwrap();
        let mut room = Room::new(u64::MAX);
        let held_entry = small(1, 1, 5);
        take(&conn, &mut room, &held_entry, &from(1), NOW).unwrap();

        let other = Connection::open(&path).unwrap();
        other.execute_batch("BEGIN IMMEDIATE").unwrap();
        let at = NOW + 600;
        assert_eq!(short(&conn, &held_entry, at).unwrap(), ShownShort::Held);
        assert!(matches!(
            short(&conn, &small(1, 1, 4), at).unwrap(),
            ShownShort::Other { .. }
        ));
        assert_eq!(
            short(&conn, &small(1, 1, 6), at).unwrap(),
            ShownShort::Whole
        );
        // The control: a use that is past the hour is written, and cannot
        // be while the other holds the database.
        let past = NOW + HOUR + 1;
        assert!(short(&conn, &held_entry, past).is_err());
        other.execute_batch("ROLLBACK").unwrap();
        assert_eq!(short(&conn, &held_entry, past).unwrap(), ShownShort::Held);
        assert_eq!(used_at(&conn, 1), Some(past));
    }

    /// An entry that is shown and not held is taken as any entry is:
    /// only where there is room.
    #[test]
    fn test_an_entry_that_is_shown_is_taken_only_where_there_is_room() {
        let (conn, mut room) = relay_of(SMALL);
        let first = small(1, 1, 5);
        assert_eq!(
            show(&conn, &mut room, &first, &from(1), NOW).unwrap(),
            Shown::Taken
        );
        // At its cap: no new channel.
        assert_eq!(
            show(&conn, &mut room, &small(2, 1, 5), &from(1), NOW).unwrap(),
            Shown::Refused(Refused::NoRoom)
        );
        assert_eq!(held(&conn), [1]);
        // What it holds is still answered: held, and another.
        assert_eq!(
            show(&conn, &mut room, &first, &from(1), NOW).unwrap(),
            Shown::Held
        );
        assert!(matches!(
            show(&conn, &mut room, &small(1, 1, 4), &from(1), NOW).unwrap(),
            Shown::Another { .. }
        ));
        // A later one that is no larger is taken. One that is larger
        // would take the relay past its cap: it is refused, and the one
        // that is held stays.
        let later = small(1, 1, 6);
        assert_eq!(
            show(&conn, &mut room, &later, &from(1), NOW).unwrap(),
            Shown::Taken
        );
        let larger = made(1, 1, 7, "notes.md", &"x".repeat(300));
        assert_eq!(
            show(&conn, &mut room, &larger, &from(1), NOW).unwrap(),
            Shown::Refused(Refused::NoRoom)
        );
        assert_eq!(held(&conn), [1]);
        assert_eq!(ids(&conn, 1), [later.id()]);
        assert_eq!(counted(&conn), SMALL);
    }

    /// A stored entry that was changed where it lay is not handed out as
    /// an answer: what comes back is signed like any entry.
    #[test]
    fn test_what_is_answered_with_is_checked_as_it_is_read() {
        let (conn, mut room) = relay();
        take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).unwrap();
        conn.execute("UPDATE entries SET rev = 9", []).unwrap();
        assert!(show(&conn, &mut room, &small(1, 1, 6), &from(1), NOW).is_err());
    }

    /// A proof for another channel, and one made over another session's
    /// value, are refused. The signature is checked before the channel is
    /// looked up, and a proof that fails is answered as a channel that is
    /// not held is.
    #[test]
    fn test_a_proof_is_checked_before_the_channel_is_looked_up_and_no_is_one_answer() {
        let (conn, mut room) = relay();
        take(&conn, &mut room, &small(1, 1, 5), &from(1), NOW).unwrap();
        take(&conn, &mut room, &small(2, 1, 5), &from(1), NOW).unwrap();
        let other_session = [0x52; 32];
        let good = proof::make(&secret(1), &SESSION, &peer()).unwrap();

        // The channel's key, on this connection, for a channel it holds.
        assert!(
            prove(&conn, &channel(1), &SESSION, &peer(), &good, NOW + 2 * HOUR)
                .unwrap()
                .answer()
        );

        // A proof for another channel: the holder of channel 2 proves
        // that one, and shows the proof for channel 1.
        let for_another = proof::make(&secret(2), &SESSION, &peer()).unwrap();
        assert!(
            prove(
                &conn,
                &channel(2),
                &SESSION,
                &peer(),
                &for_another,
                NOW + 2 * HOUR
            )
            .unwrap()
            .answer()
        );
        assert!(
            !prove(
                &conn,
                &channel(1),
                &SESSION,
                &peer(),
                &for_another,
                NOW + 4 * HOUR
            )
            .unwrap()
            .answer()
        );
        // And the proof of channel 1 is none for channel 2.
        assert!(
            !prove(&conn, &channel(2), &SESSION, &peer(), &good, NOW + 4 * HOUR)
                .unwrap()
                .answer()
        );

        // A proof made over another session's value: replayed here from
        // another connection, and from here on another.
        let elsewhere = proof::make(&secret(1), &other_session, &peer()).unwrap();
        assert!(
            !prove(
                &conn,
                &channel(1),
                &SESSION,
                &peer(),
                &elsewhere,
                NOW + 4 * HOUR
            )
            .unwrap()
            .answer()
        );
        assert!(
            !prove(
                &conn,
                &channel(1),
                &other_session,
                &peer(),
                &good,
                NOW + 4 * HOUR
            )
            .unwrap()
            .answer()
        );

        // A proof says which end made it. One that this end made, over
        // the value that both ends export, is none when the other end
        // sends it back; and one that the peer made is none from another.
        let this_end = device(3).public_key();
        let sent_by_this_end = proof::make(&secret(1), &SESSION, &this_end).unwrap();
        assert!(proof::check(
            &channel(1),
            &SESSION,
            &this_end,
            &sent_by_this_end
        ));
        assert!(
            !prove(
                &conn,
                &channel(1),
                &SESSION,
                &peer(),
                &sent_by_this_end,
                NOW + 4 * HOUR
            )
            .unwrap()
            .answer()
        );
        let another = device(9).public_key();
        assert!(
            !prove(
                &conn,
                &channel(1),
                &SESSION,
                &another,
                &good,
                NOW + 4 * HOUR
            )
            .unwrap()
            .answer()
        );

        // What the caller is given is two things: whether the proof
        // holds, and whether the channel is held. What the other end is
        // told is one: yes only where both are so.
        let found = |c: u16, proof: &[u8; 64]| {
            prove(&conn, &channel(c), &SESSION, &peer(), proof, NOW + 2 * HOUR).unwrap()
        };
        assert_eq!(found(1, &good), Proof::Holds { channel_held: true });
        assert_eq!(found(1, &for_another), Proof::Fails);
        assert_eq!(found(1, &sent_by_this_end), Proof::Fails);
        assert_eq!(found(1, &[0; 64]), Proof::Fails);
        let for_none = proof::make(&secret(3), &SESSION, &peer()).unwrap();
        assert_eq!(
            found(3, &for_none),
            Proof::Holds {
                channel_held: false
            }
        );
        for (proof, holds, told) in [
            (Proof::Holds { channel_held: true }, true, true),
            (
                Proof::Holds {
                    channel_held: false,
                },
                true,
                false,
            ),
            (Proof::Fails, false, false),
        ] {
            assert_eq!((proof.holds(), proof.answer()), (holds, told), "{proof:?}");
        }

        // A channel that the relay does not hold, proved as it should be:
        // the same no.
        let not_held = proof::make(&secret(3), &SESSION, &peer()).unwrap();
        assert!(proof::check(&channel(3), &SESSION, &peer(), &not_held));
        assert!(
            !prove(
                &conn,
                &channel(3),
                &SESSION,
                &peer(),
                &not_held,
                NOW + 4 * HOUR
            )
            .unwrap()
            .answer()
        );
        // And nothing is kept of having been asked.
        assert_eq!(held_channel(&conn, &channel(3)).unwrap(), None);

        // Only a proof that holds is use of a channel.
        assert_eq!(used_at(&conn, 1), Some(NOW + 2 * HOUR));
        assert_eq!(used_at(&conn, 2), Some(NOW + 2 * HOUR));

        // The channel is looked up only after the signature holds: with
        // nothing to look channels up in, a proof that fails is still
        // answered, and one that holds is not.
        conn.execute_batch("DROP TABLE relay_channels").unwrap();
        assert!(
            !prove(&conn, &channel(1), &SESSION, &peer(), &for_another, NOW)
                .unwrap()
                .answer()
        );
        assert!(
            !prove(&conn, &channel(1), &SESSION, &peer(), &[0; 64], NOW)
                .unwrap()
                .answer()
        );
        assert!(prove(&conn, &channel(1), &SESSION, &peer(), &good, NOW).is_err());
    }

    /// A proof that held is the caller's to remember, with the connection,
    /// also for a channel that the relay does not hold: when the channel
    /// arrives a minute later, the connection is handed it with no proof
    /// more. A proof that failed is nothing to remember.
    #[test]
    fn test_a_proof_that_held_is_remembered_for_a_channel_that_arrives_later() {
        let (conn, mut room) = relay();
        let nothing = Page {
            entries: Vec::new(),
            next: 0,
            cost: 0,
            mark: NO_MARK,
        };
        let proof = proof::make(&secret(3), &SESSION, &peer()).unwrap();

        // The relay does not hold the channel. The proof holds all the
        // same, and the caller is given that. The other end is told no.
        let found = prove(&conn, &channel(3), &SESSION, &peer(), &proof, NOW).unwrap();
        assert_eq!(
            found,
            Proof::Holds {
                channel_held: false
            }
        );
        assert!(found.holds());
        assert!(!found.answer());
        // Nothing is kept in the store of having been asked.
        assert_eq!(held_channel(&conn, &channel(3)).unwrap(), None);
        assert_eq!(counted(&conn), 0);

        // The caller remembers that the proof held. Asked for now, the
        // channel is handed as one that is not held.
        let proved = found.holds();
        assert_eq!(paged(&conn, 3, proved, 0, 100), nothing);

        // A minute later the channel arrives, from elsewhere.
        let entry = small(3, 1, 5);
        take(&conn, &mut room, &entry, &from(2), NOW + 60).unwrap();
        // The connection is handed it, on what it proved a minute ago: it
        // asks with the mark of no holding, as it did before, and is told
        // the mark of the holding there is now.
        assert_eq!(
            pull(&conn, &channel(3), proved, &NO_MARK, 0, 100).unwrap(),
            Page {
                entries: vec![(*entry).clone()],
                next: 1,
                cost: SMALL,
                mark: mark_of(&conn, 3),
            }
        );
        // The proof was no use of a channel that was not held: the
        // channel was used when it was taken.
        assert_eq!(used_at(&conn, 3), Some(NOW + 60));

        // A proof that fails is nothing to remember, also where the
        // channel is held: this one was made over another session's
        // value. A connection that has only that is handed nothing.
        let fails = prove(
            &conn,
            &channel(3),
            &[0x52; 32],
            &peer(),
            &proof,
            NOW + 2 * HOUR,
        )
        .unwrap();
        assert_eq!(fails, Proof::Fails);
        assert!(!fails.holds() && !fails.answer());
        assert_eq!(
            pull(&conn, &channel(3), fails.holds(), &NO_MARK, 0, 100).unwrap(),
            nothing
        );
        assert_eq!(used_at(&conn, 3), Some(NOW + 60));

        // Proved again now that it is held: yes, to the caller and to the
        // other end, and the channel was used.
        let again = prove(
            &conn,
            &channel(3),
            &SESSION,
            &peer(),
            &proof,
            NOW + 3 * HOUR,
        )
        .unwrap();
        assert_eq!(again, Proof::Holds { channel_held: true });
        assert!(again.holds() && again.answer());
        assert_eq!(used_at(&conn, 3), Some(NOW + 3 * HOUR));
    }

    /// A channel is handed in pages, in the order the relay stored its
    /// entries, only where the caller says its key was proved on this
    /// connection.
    #[test]
    fn test_a_channel_is_handed_in_pages_only_where_it_was_proved() {
        let (conn, mut room) = relay();
        let entries: Vec<CheckedEntry> = (1..=5u8)
            .map(|d| made(1, d, 5, &format!("{d}.md"), "a small text"))
            .collect();
        for entry in &entries {
            take(&conn, &mut room, entry, &from(1), NOW).unwrap();
        }
        // Another channel's entries are in no page of this one.
        take(&conn, &mut room, &small(2, 1, 5), &from(1), NOW).unwrap();

        let page = |after: u64, limit: u32| paged(&conn, 1, true, after, limit);
        let of = |n: std::ops::RangeInclusive<usize>| -> Vec<Entry> {
            n.map(|n| (*entries[n - 1]).clone()).collect()
        };
        let mark = mark_of(&conn, 1);
        assert_eq!(
            page(0, 2),
            Page {
                entries: of(1..=2),
                next: 2,
                cost: 2 * SMALL,
                mark,
            }
        );
        assert_eq!(
            page(2, 2),
            Page {
                entries: of(3..=4),
                next: 4,
                cost: 2 * SMALL,
                mark,
            }
        );
        assert_eq!(
            page(4, 2),
            Page {
                entries: of(5..=5),
                next: 5,
                cost: SMALL,
                mark,
            }
        );
        // After the last there is nothing, and the place stays.
        let nothing = |after: u64| Page {
            entries: Vec::new(),
            next: after,
            cost: 0,
            mark,
        };
        assert_eq!(page(5, 2), nothing(5));
        assert_eq!(page(0, 0), nothing(0));
        assert_eq!(page(u64::MAX, 100), nothing(u64::MAX));
        assert_eq!(page(0, 100).entries, of(1..=5));

        // What is handed is what was stored, and passes the check.
        for (handed, entry) in page(0, 100).entries.into_iter().zip(&entries) {
            assert_eq!(&check(&handed.to_wire()).unwrap(), entry);
        }

        // Not proved on this connection: nothing, from any place, though
        // the relay holds it, and the place and the mark that were asked
        // with. So is a channel that is not held, to a connection that
        // has not proved it. To one that has, a channel that is not held
        // is no holding: the mark of none, and the start.
        for after in [0, 2, 5] {
            assert_eq!(paged(&conn, 1, false, after, 100), nothing(after));
            assert_eq!(
                pull(&conn, &channel(3), false, &mark, after, 100).unwrap(),
                nothing(after)
            );
            assert_eq!(
                pull(&conn, &channel(3), true, &mark, after, 100).unwrap(),
                Page {
                    entries: Vec::new(),
                    next: 0,
                    cost: 0,
                    mark: NO_MARK,
                }
            );
        }

        // A newer revision has a later place: a connection that has paged
        // past the one it replaces is handed it next. The place is the
        // sixth of this channel's own, though the relay has stored an
        // entry of another channel since the fifth.
        let newer = made(1, 2, 6, "2.md", "a newer text");
        take(&conn, &mut room, &newer, &from(1), NOW).unwrap();
        assert_eq!(
            page(5, 100),
            Page {
                entries: vec![(*newer).clone()],
                next: 6,
                cost: SMALL,
                mark,
            }
        );
    }

    /// The places that a holder of one channel's key is given are that
    /// channel's own count. They are the same whatever the relay stored
    /// for anyone else in between, so they tell it nothing of that.
    #[test]
    fn test_a_pages_places_are_the_channels_own_and_say_nothing_of_other_channels() {
        // Two relays take the same entries of one channel, in one order.
        // The first stores nothing else. The second stores entries of
        // other channels before them, between them and after them.
        let (quiet, mut quiet_room) = relay();
        let (busy, mut busy_room) = relay();
        let own: Vec<CheckedEntry> = (1..=4u8)
            .map(|d| made(1, d, 5, &format!("{d}.md"), "a small text"))
            .collect();
        let mut others = (2..).map(|c| small(c, 1, 5));
        let mut elsewhere = |room: &mut Room, how_many: usize| {
            for entry in others.by_ref().take(how_many) {
                take(&busy, room, &entry, &from(2), NOW).unwrap();
            }
        };
        elsewhere(&mut busy_room, 3);
        for (n, entry) in own.iter().enumerate() {
            take(&quiet, &mut quiet_room, entry, &from(1), NOW).unwrap();
            take(&busy, &mut busy_room, entry, &from(1), NOW).unwrap();
            elsewhere(&mut busy_room, 5 * (n + 1));
        }
        // And a newer revision of the second, at both.
        let newer = made(1, 2, 6, "2.md", "a newer text");
        take(&quiet, &mut quiet_room, &newer, &from(1), NOW).unwrap();
        elsewhere(&mut busy_room, 7);
        take(&busy, &mut busy_room, &newer, &from(1), NOW).unwrap();
        // The busy relay has stored 65 entries, and the quiet one 5.
        let stored = |conn: &Connection| -> i64 {
            conn.query_row(
                "SELECT value FROM counters WHERE name = 'entry_seq'",
                [],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert_eq!((stored(&quiet), stored(&busy)), (5, 65));

        // Paged in every step, the holder of the channel's key is handed
        // the same entries at the same places by both.
        for limit in [1, 2, 3, 100] {
            let mut after = 0;
            let mut places = Vec::new();
            loop {
                let page = paged(&quiet, 1, true, after, limit);
                let at_the_other = paged(&busy, 1, true, after, limit);
                assert_eq!(
                    (&page.entries, page.next, page.cost),
                    (&at_the_other.entries, at_the_other.next, at_the_other.cost)
                );
                if page.entries.is_empty() {
                    break;
                }
                places.push(page.next);
                after = page.next;
            }
            // The places are the channel's count: one to five, the second
            // gone where its newer revision took the fifth.
            let last: Vec<u64> = match limit {
                1 => vec![1, 3, 4, 5],
                2 => vec![3, 5],
                3 => vec![4, 5],
                _ => vec![5],
            };
            assert_eq!(places, last, "{limit}");
        }

        // A channel that was dropped and is taken again counts from the
        // start, in another holding.
        let before = mark_of(&quiet, 1);
        assert_eq!(make_room(&quiet, 0).unwrap(), [channel(1)]);
        take(&quiet, &mut quiet_room, &own[0], &from(1), NOW).unwrap();
        assert_eq!(paged(&quiet, 1, true, 0, 100).next, 1);
        assert_ne!(mark_of(&quiet, 1), before);
    }

    /// A place is within one holding of a channel. A relay drops a channel
    /// and takes it again: whoever kept a place from the earlier holding
    /// asks with that holding's mark, and is handed the channel from the
    /// start, with the mark of the holding there is now. (Asked by the
    /// place alone, it would be handed nothing until the new count had
    /// passed the old place.)
    #[test]
    fn test_a_place_kept_from_an_earlier_holding_is_handed_the_channel_from_the_start() {
        let (conn, mut room) = relay();
        let entries: Vec<CheckedEntry> = (1..=5u8)
            .map(|d| made(1, d, 5, &format!("{d}.md"), "a small text"))
            .collect();
        for entry in &entries {
            take(&conn, &mut room, entry, &from(1), NOW).unwrap();
        }
        // A holder of the key pulls all of it, and keeps its place: the
        // fifth, in the holding marked so.
        let first = mark_of(&conn, 1);
        let all = pull(&conn, &channel(1), true, &NO_MARK, 0, 100).unwrap();
        assert_eq!((all.entries.len(), all.next, all.mark), (5, 5, first));
        // With that mark and that place there is nothing more, and the
        // place and the mark stay.
        let nothing_more = pull(&conn, &channel(1), true, &first, 5, 100).unwrap();
        assert_eq!(
            nothing_more,
            Page {
                entries: Vec::new(),
                next: 5,
                cost: 0,
                mark: first,
            }
        );

        // The relay drops the channel, and takes it again: two entries,
        // counted from 1, in another holding.
        assert_eq!(make_room(&conn, 0).unwrap(), [channel(1)]);
        for entry in &entries[..2] {
            take(&conn, &mut room, entry, &from(2), NOW + 60).unwrap();
        }
        let second = mark_of(&conn, 1);
        assert_ne!(second, first);
        assert_ne!(second, NO_MARK);

        // The holder asks from its place in the earlier holding. It is
        // handed the channel from the start, and told the new mark.
        let again = pull(&conn, &channel(1), true, &first, 5, 100).unwrap();
        assert_eq!(
            again,
            Page {
                entries: vec![(*entries[0]).clone(), (*entries[1]).clone()],
                next: 2,
                cost: 2 * SMALL,
                mark: second,
            }
        );
        // From a place that the new count has not reached, and from one
        // that it has passed: the same, since neither is a place here.
        for after in [1, 2, 3, 5, 100, u64::MAX] {
            let page = pull(&conn, &channel(1), true, &first, after, 100).unwrap();
            assert_eq!(page, again, "{after}");
        }
        // So is it for an asker with no mark, whatever place it says, and
        // for one with a mark that is no holding's.
        for mark in [NO_MARK, [0x4d; 8]] {
            for after in [0, 1, 2, 7] {
                let page = pull(&conn, &channel(1), true, &mark, after, 100).unwrap();
                assert_eq!(page, again, "{mark:?} {after}");
            }
        }
        // And where no entry is asked for, the place that is said is the
        // start of this holding, not the place in the other.
        let none = pull(&conn, &channel(1), true, &first, 5, 0).unwrap();
        assert_eq!((none.entries.len(), none.next, none.mark), (0, 0, second));
        // In pages, the first of them from the start whatever was asked.
        let one = pull(&conn, &channel(1), true, &first, 5, 1).unwrap();
        assert_eq!((one.entries.len(), one.next, one.mark), (1, 1, second));
        // With the mark it was told, the holder goes on from its place in
        // this holding.
        let rest = pull(&conn, &channel(1), true, &one.mark, one.next, 100).unwrap();
        assert_eq!(
            rest,
            Page {
                entries: vec![(*entries[1]).clone()],
                next: 2,
                cost: SMALL,
                mark: second,
            }
        );
        let caught_up = pull(&conn, &channel(1), true, &second, 2, 100).unwrap();
        assert_eq!(
            (caught_up.entries.len(), caught_up.next, caught_up.mark),
            (0, 2, second)
        );
        // A place beyond the count, in this holding, is that place still:
        // nothing is handed, and nothing is said of the start.
        let beyond = pull(&conn, &channel(1), true, &second, 9, 100).unwrap();
        assert_eq!((beyond.entries.len(), beyond.next), (0, 9));

        // A holding keeps its mark for as long as it lasts: through an
        // entry more, a newer revision, a proof, and an entry shown.
        take(&conn, &mut room, &entries[2], &from(2), NOW + 120).unwrap();
        take(&conn, &mut room, &small(1, 9, 6), &from(2), NOW + 120).unwrap();
        let proved = proof::make(&secret(1), &SESSION, &peer()).unwrap();
        prove(&conn, &channel(1), &SESSION, &peer(), &proved, NOW + 180).unwrap();
        show(&conn, &mut room, &entries[0], &from(2), NOW + 240).unwrap();
        listed_relay_says(&conn, &channel(1), NOW - DAY).unwrap();
        listed_relay_used(&conn, &channel(1), NOW + 300, NOW + 300).unwrap();
        assert_eq!(mark_of(&conn, 1), second);

        // Dropped because nobody used it, and taken again: a third
        // holding, under a third mark.
        assert_eq!(sweep_unused(&conn, NOW + 365 * DAY).unwrap(), [channel(1)]);
        assert_eq!(mark_of(&conn, 1), NO_MARK);
        take(&conn, &mut room, &entries[4], &from(2), NOW + 366 * DAY).unwrap();
        let third = mark_of(&conn, 1);
        assert!(third != first && third != second && third != NO_MARK);
        let from_the_start = pull(&conn, &channel(1), true, &second, 4, 100).unwrap();
        assert_eq!(
            (
                from_the_start.entries,
                from_the_start.next,
                from_the_start.mark
            ),
            (vec![(*entries[4]).clone()], 1, third)
        );

        // While the relay does not hold the channel there is no holding
        // to have a place in. A connection that proved the channel is
        // told so, by the mark of no holding and the start: it knows
        // then that nothing it sent is there. One that did not prove it
        // keeps the place and the mark it asked with, as for any channel.
        assert_eq!(make_room(&conn, 0).unwrap(), [channel(1)]);
        for c in [1, 7] {
            assert_eq!(
                pull(&conn, &channel(c), true, &third, 4, 100).unwrap(),
                Page {
                    entries: Vec::new(),
                    next: 0,
                    cost: 0,
                    mark: NO_MARK,
                },
                "{c}"
            );
            assert_eq!(
                pull(&conn, &channel(c), false, &third, 4, 100).unwrap(),
                Page {
                    entries: Vec::new(),
                    next: 4,
                    cost: 0,
                    mark: third,
                },
                "{c}"
            );
        }
        // And a mark is a holding's own: two channels taken in one moment
        // have two.
        take(&conn, &mut room, &small(2, 1, 5), &from(2), NOW).unwrap();
        take(&conn, &mut room, &small(3, 1, 5), &from(2), NOW).unwrap();
        assert_ne!(mark_of(&conn, 2), mark_of(&conn, 3));
    }

    /// A page holds at most 100 entries, and at most what one message
    /// has room for: 13 of the largest. It always holds one.
    #[test]
    fn test_a_page_is_within_what_one_message_holds() {
        let (conn, mut room) = relay();
        // 103 small entries: a page is 100 of them, however many are
        // asked for.
        for d in 1..=103u8 {
            let entry = made(1, d, 5, "notes.md", "a small text");
            take(&conn, &mut room, &entry, &from(1), NOW).unwrap();
        }
        for limit in [100, 101, 1000, u32::MAX] {
            let page = paged(&conn, 1, true, 0, limit);
            assert_eq!(page.entries.len(), 100, "{limit}");
            assert_eq!((page.next, page.cost), (100, 100 * SMALL));
        }
        let rest = paged(&conn, 1, true, 100, 1000);
        assert_eq!((rest.entries.len(), rest.next), (3, 103));
        // Fewer where fewer are asked for, across the steps in which a
        // page is read.
        for limit in [1, 15, 16, 17, 33, 99] {
            let page = paged(&conn, 1, true, 0, limit);
            assert_eq!(page.entries.len(), limit as usize);
            assert_eq!(page.next, u64::from(limit));
        }

        // Entries of the largest size: 13 are within what a page may
        // take, and 14 are not.
        assert_eq!(ENTRY_PAGE_MAX_BYTES / MAX_ENTRY_WIRE_BYTES, 13);
        let longest = "x".repeat(MAX_ENTRY_NAME_AND_VALUE_BYTES - 1);
        for d in 1..=30u8 {
            let entry = made(2, d, 5, "n", &longest);
            assert_eq!(entry.to_wire().len(), MAX_ENTRY_WIRE_BYTES);
            take(&conn, &mut room, &entry, &from(1), NOW).unwrap();
        }
        let travels =
            |page: &Page| -> usize { page.entries.iter().map(|entry| entry.to_wire().len()).sum() };
        let first = paged(&conn, 2, true, 0, 100);
        assert_eq!(first.entries.len(), 13);
        assert!(travels(&first) <= ENTRY_PAGE_MAX_BYTES);
        assert_eq!(first.cost, 13 * entry_cost(MAX_ITEM_BYTES));
        // The next page starts after the last entry handed, and nothing
        // is passed over between pages.
        let second = paged(&conn, 2, true, first.next, 100);
        assert_eq!(second.entries.len(), 13);
        assert_eq!(second.entries[0].author, device(14).public_key());
        let third = paged(&conn, 2, true, second.next, 100);
        assert_eq!(third.entries.len(), 4);
        assert_eq!(third.entries[3].author, device(30).public_key());

        // Small entries and then large ones: the page ends before the
        // large entry that would take it over, and is never empty.
        for d in 1..=3u8 {
            take(&conn, &mut room, &small(3, d, 5), &from(1), NOW).unwrap();
        }
        for d in 4..=20u8 {
            take(
                &conn,
                &mut room,
                &made(3, d, 5, "n", &longest),
                &from(1),
                NOW,
            )
            .unwrap();
        }
        let mixed = paged(&conn, 3, true, 0, 100);
        assert_eq!(mixed.entries.len(), 3 + 13);
        assert!(travels(&mixed) <= ENTRY_PAGE_MAX_BYTES);
        assert!(travels(&mixed) + MAX_ENTRY_WIRE_BYTES > ENTRY_PAGE_MAX_BYTES);
        let one = paged(&conn, 3, true, mixed.next, 1);
        assert_eq!(one.entries.len(), 1);
        assert_eq!(one.entries[0].author, device(17).public_key());
    }

    // ── What nobody uses ─────────────────────────────────────────────

    /// A channel that nobody has used for 90 days goes: one whose key no
    /// connection has proved, and of which nobody has shown an entry that
    /// the relay holds. One whose entry was shown yesterday does not.
    #[test]
    fn test_a_channel_unused_for_90_days_goes_and_one_shown_yesterday_does_not() {
        let (conn, mut room) = relay();
        let entries: Vec<CheckedEntry> = (1..=6).map(|c| small(c, 1, 5)).collect();
        for entry in &entries {
            take(&conn, &mut room, entry, &from(1), NOW).unwrap();
        }
        let yesterday = NOW + 89 * DAY;
        // The second: its entry is shown, and the relay holds it.
        assert_eq!(
            show(&conn, &mut room, &entries[1], &from(1), yesterday).unwrap(),
            Shown::Held
        );
        // The third: its key is proved.
        let proved = proof::make(&secret(3), &SESSION, &peer()).unwrap();
        assert!(
            prove(&conn, &channel(3), &SESSION, &peer(), &proved, yesterday)
                .unwrap()
                .answer()
        );
        // The fourth: an entry is shown that the relay did not hold, and
        // took. It holds it now.
        assert_eq!(
            show(&conn, &mut room, &small(4, 1, 6), &from(1), yesterday).unwrap(),
            Shown::Taken
        );
        // The fifth: an earlier entry is shown, which the relay does not
        // hold, and a proof is tried that fails. Neither is use.
        assert!(matches!(
            show(&conn, &mut room, &small(5, 1, 4), &from(1), yesterday).unwrap(),
            Shown::Another { .. }
        ));
        assert!(
            !prove(&conn, &channel(5), &SESSION, &peer(), &proved, yesterday)
                .unwrap()
                .answer()
        );
        // The sixth: an entry is pushed, and stored. Whoever holds an
        // entry can push it: it proves no key, and is no use either.
        assert_eq!(
            take(&conn, &mut room, &small(6, 1, 6), &from(1), yesterday).unwrap(),
            Taken::Stored
        );
        // And it is handed in pages: that is no use, the proof was.
        paged(&conn, 6, true, 0, 100);
        for (c, at) in [
            (1, NOW),
            (2, yesterday),
            (3, yesterday),
            (4, yesterday),
            (5, NOW),
            (6, NOW),
        ] {
            assert_eq!(used_at(&conn, c), Some(at), "{c}");
        }

        // One second short of 90 days: nothing goes.
        assert!(sweep_unused(&conn, NOW + 90 * DAY - 1).unwrap().is_empty());
        assert_eq!(held(&conn), [1, 2, 3, 4, 5, 6]);
        // At 90 days: the three that nobody used go, with their entries.
        assert_eq!(
            sweep_unused(&conn, NOW + 90 * DAY).unwrap(),
            [channel(1), channel(5), channel(6)]
        );
        assert_eq!(held(&conn), [2, 3, 4]);
        for c in [1, 5, 6] {
            assert!(ids(&conn, c).is_empty(), "{c}");
        }
        assert_eq!(counted(&conn), 3 * SMALL);
        // Swept again, nothing more goes.
        assert!(sweep_unused(&conn, NOW + 90 * DAY).unwrap().is_empty());

        // The rest go 90 days after they were last used, and not before.
        assert!(
            sweep_unused(&conn, yesterday + 90 * DAY - 1)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            sweep_unused(&conn, yesterday + 90 * DAY).unwrap(),
            [channel(2), channel(3), channel(4)]
        );
        assert_eq!(counted(&conn), 0);
    }

    // ── The two kinds ────────────────────────────────────────────────

    /// The channels of the older kind and those from their secrets are
    /// counted apart in the store. What this kind counts against its cap,
    /// and what it drops to make room or as unused, is never of the older
    /// kind. And what the older kind's functions count, list and drop is
    /// never of this kind.
    #[test]
    fn test_the_older_kinds_room_and_this_kinds_do_not_touch_each_other() {
        let (conn, mut room) = relay_of(2 * SMALL);
        // What the relay holds of the older kind: two channels, far more
        // than this kind's cap.
        let key = device(1).public_key();
        let blob = vec![0x5a; 8192];
        for (n, channel_id) in ["old_a", "old_b"].into_iter().enumerate() {
            conn.execute(
                "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id,
                                       created_at, updated_at)
                 VALUES (?1, 'named', 'realtime', 'open', X'00', ?2, ?2)",
                params![channel_id, format!("2026-01-0{}", n + 1)],
            )
            .unwrap();
            for i in 0..4u8 {
                let id = format!("ci_{channel_id}_{i}");
                let hash = [i + 16 * n as u8; 32];
                let item = items::NewItem::plain(
                    &id,
                    channel_id,
                    &key,
                    "memory",
                    "2026-01-01T00:00:00Z",
                    1,
                    &hash,
                    &[0x02; 64],
                    &blob,
                );
                assert!(items::insert_item(&conn, &item).unwrap());
            }
        }
        let older = |conn: &Connection| {
            let rows: i64 = conn
                .query_row("SELECT COUNT(*) FROM items", [], |row| row.get(0))
                .unwrap();
            (
                rows,
                items::channel_cost(conn, "old_a").unwrap(),
                items::channel_cost(conn, "old_b").unwrap(),
                channels::newest_stored(conn).unwrap(),
                channels::list_stored_channel_ids(conn).unwrap().len(),
            )
        };
        let before = older(&conn);
        assert_eq!(before.0, 8);
        assert_eq!(before.1, 4 * (8192 + 1024));
        assert_eq!(before.3.as_deref(), Some("old_b"));
        assert!(before.1 + before.2 > room.max_bytes);

        // None of it is counted against this kind's cap: the relay takes
        // new channels up to it.
        assert_eq!(used_bytes(&conn).unwrap(), 0);
        for c in [1, 2] {
            assert_eq!(
                take(&conn, &mut room, &small(c, 1, 5), &from(1), NOW).unwrap(),
                Taken::Stored
            );
        }
        assert_eq!(counted(&conn), 2 * SMALL);
        // At this kind's cap, a new channel of this kind is refused, and
        // nothing of the older kind went to make room for it.
        assert_eq!(
            take(&conn, &mut room, &small(3, 1, 5), &from(1), NOW).unwrap(),
            Taken::Refused(Refused::NoRoom)
        );
        assert_eq!(older(&conn), before);

        // Over this kind's cap, since its cap came down, what is dropped
        // to make room is of this kind, down to nothing: the older kind's
        // channels are never among them.
        assert_eq!(make_room(&conn, SMALL).unwrap(), [channel(2)]);
        assert_eq!(held(&conn), [1]);
        assert_eq!(make_room(&conn, 0).unwrap(), [channel(1)]);
        assert!(make_room(&conn, 0).unwrap().is_empty());
        assert_eq!(older(&conn), before);
        // Nor does what nobody uses of this kind take any of the older.
        take(&conn, &mut room, &small(2, 1, 5), &from(1), NOW + 20).unwrap();
        assert_eq!(sweep_unused(&conn, NOW + 365 * DAY).unwrap(), [channel(2)]);
        assert_eq!(older(&conn), before);

        // The other way round: what the older kind counts and drops is
        // never of this kind.
        room.max_bytes = u64::MAX;
        for c in [4, 5] {
            take(&conn, &mut room, &small(c, 1, 5), &from(1), NOW + 30).unwrap();
        }
        // Its newest channel, and the channels it lists, are its own.
        assert_eq!(older(&conn), before);
        // It drops its newest, and then its other one: this kind's
        // channels and entries are as they were.
        assert_eq!(channels::drop_stored(&conn, "old_b").unwrap(), 4);
        assert_eq!(
            channels::newest_stored(&conn).unwrap().as_deref(),
            Some("old_a")
        );
        assert_eq!(channels::drop_stored(&conn, "old_a").unwrap(), 4);
        assert_eq!(channels::newest_stored(&conn).unwrap(), None);
        assert_eq!(held(&conn), [4, 5]);
        assert_eq!(counted(&conn), 2 * SMALL);
        assert_eq!(ids(&conn, 4).len(), 1);
    }
}
