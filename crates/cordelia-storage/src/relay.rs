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
//! [`make_room`], [`sweep_unused`], [`listed_relay_says`]) refuses, with
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
//! - **A proof** ([`prove`], §2.4 items 3 and 4): yes or no. The signature
//!   is checked before the channel is looked up, and a proof that fails
//!   and a channel that is not held are answered alike.
//! - **A pull** ([`pull`]): a page of a channel's entries, only where the
//!   caller says the channel was proved on this connection. Without that
//!   it is answered as for a channel that is not held.
//!
//! ## What nobody uses
//!
//! A time for each channel of when its key was last proved, or an entry of
//! it last shown that the relay holds. [`sweep_unused`] drops each channel
//! that was last used 90 days ago or longer (§2.5).

use std::collections::HashMap;
use std::net::IpAddr;

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;
use cordelia_core::protocol::{
    ENTRY_CHANNEL_UNUSED_DAYS, ENTRY_PAGE_MAX_BYTES, ENTRY_PAGE_MAX_ENTRIES,
    ENTRY_WIRE_OVERHEAD_BYTES, MAX_ENTRY_CHANNEL_BYTES_AT_RELAY,
    NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR, SESSION_VALUE_BYTES, entry_cost,
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

/// How many entries a page is read from the store at a time.
const PAGE_READ: usize = 16;

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
}

impl Room {
    /// For a relay that may hold `max_bytes` of channels from their
    /// secrets.
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            max_channel_bytes: MAX_ENTRY_CHANNEL_BYTES_AT_RELAY,
            new_channels: HashMap::new(),
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

    /// Count a channel that `address` made the relay take at `now`.
    fn added_channel(&mut self, address: IpAddr, now: i64) {
        self.new_channels.entry(address).or_default().push(now);
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
    /// has held the entry's channel, in seconds.
    ListedRelay { held_since: Option<i64> },
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
    /// The relay holds one at that revision from that author in that
    /// slot. It was not stored.
    AlreadyHeld,
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

/// One page of a channel's entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// The entries, in the order this relay stored them, as they are
    /// stored: whoever receives them checks them.
    pub entries: Vec<Entry>,
    /// The place the next page starts after: the place of the last entry
    /// here, or the place that was asked after where there is none.
    pub next: u64,
    /// What the entries are counted at together. It counts against the
    /// asker's limits.
    pub cost: u64,
}

/// A channel that a relay holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldChannel {
    /// Since when the relay has held it, in seconds: when it first took
    /// it, or the earlier time that a relay the operator lists said.
    pub held_since: i64,
    /// When its key was last proved, or an entry of it last shown that
    /// the relay holds, in seconds.
    pub used_at: i64,
    /// What it holds, in bytes as entries are counted.
    pub bytes: u64,
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
pub fn take(
    conn: &Connection,
    room: &mut Room,
    entry: &CheckedEntry,
    asker: &Asker,
    now: i64,
) -> Result<Taken, RelayError> {
    in_one(conn, || {
        no_device_writes(conn)?;
        said_by(conn, asker, &entry.channel)?;
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
                Outcome::AlreadyHeld => Ok(Taken::AlreadyHeld),
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
            // time that a relay the operator lists says. It is used now.
            let since = match asker {
                Asker::ListedRelay {
                    held_since: Some(said),
                } if *said > 0 => now.min(*said),
                _ => now,
            };
            let bytes = entries::channel_cost(conn, &entry.channel)?;
            conn.execute(
                "INSERT INTO relay_channels (channel_id, held_since, used_at, bytes)
                 VALUES (?1, ?2, ?3, ?4)",
                params![entry.channel.as_slice(), since, now, to_sql(bytes)],
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

// ── How long it has held a channel ───────────────────────────────────

/// The channel as the relay holds it, or `None` where it does not.
pub fn held_channel(
    conn: &Connection,
    channel: &[u8; 32],
) -> Result<Option<HeldChannel>, CordeliaError> {
    conn.query_row(
        "SELECT held_since, used_at, bytes FROM relay_channels WHERE channel_id = ?1",
        params![channel.as_slice()],
        |row| {
            Ok(HeldChannel {
                held_since: row.get(0)?,
                used_at: row.get(1)?,
                bytes: row.get::<_, i64>(2)?.max(0) as u64,
            })
        },
    )
    .optional()
    .map_err(storage)
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
    in_one(conn, || {
        no_device_writes(conn)?;
        Ok(kept_the_earlier(conn, channel, held_since)?)
    })
}

/// [`listed_relay_says`], inside what the caller began.
fn kept_the_earlier(
    conn: &Connection,
    channel: &[u8; 32],
    held_since: i64,
) -> Result<bool, CordeliaError> {
    if held_since <= 0 {
        return Ok(false);
    }
    conn.execute(
        "UPDATE relay_channels SET held_since = ?2 WHERE channel_id = ?1 AND held_since > ?2",
        params![channel.as_slice(), held_since],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

/// What the asker says of how long it has held `channel`, kept where it
/// may say so.
fn said_by(conn: &Connection, asker: &Asker, channel: &[u8; 32]) -> Result<(), CordeliaError> {
    if let Asker::ListedRelay {
        held_since: Some(said),
    } = asker
    {
        kept_the_earlier(conn, channel, *said)?;
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
pub fn show(
    conn: &Connection,
    room: &mut Room,
    entry: &CheckedEntry,
    asker: &Asker,
    now: i64,
) -> Result<Shown, RelayError> {
    in_one(conn, || {
        no_device_writes(conn)?;
        Ok(shown(conn, room, entry, asker, now)?)
    })
}

/// [`show`], inside what the caller began.
fn shown(
    conn: &Connection,
    room: &mut Room,
    entry: &CheckedEntry,
    asker: &Asker,
    now: i64,
) -> Result<Shown, CordeliaError> {
    said_by(conn, asker, &entry.channel)?;
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
            Taken::AlreadyHeld | Taken::OlderThanHeld => Err(CordeliaError::Storage(
                "an entry newer than the one held was not stored".into(),
            )),
        },
    }
}

/// Whether the other end of the connection whose TLS session exports
/// `session` has proved, with `proof`, that it holds the key of a channel
/// this relay holds (decision 2026-10-04 §2.4 items 3 and 4). `prover` is
/// the node key of the peer at the other end, as the connection says it:
/// a proof says which end made it, and one that this end made is no proof
/// when the other end sends it back. `now` is the relay's time, in
/// seconds.
///
/// The signature is checked first, and the channel is looked up only
/// where it holds. No, for a proof that fails; and no, for a channel that
/// the relay does not hold: the two are answered alike, so that nobody
/// without a channel's key learns whether the relay holds it.
///
/// A yes is for this connection alone: the caller keeps it with the
/// connection, and says so where it asks for the channel ([`pull`]).
pub fn prove(
    conn: &Connection,
    channel: &[u8; 32],
    session: &[u8; SESSION_VALUE_BYTES],
    prover: &[u8; 32],
    proof: &[u8; 64],
    now: i64,
) -> Result<bool, CordeliaError> {
    if !proof::check(channel, session, prover, proof) {
        return Ok(false);
    }
    used(conn, channel, now)
}

/// One page of the entries of `channel` that this relay stored after the
/// place `after`, at most `limit` of them (decision 2026-10-04 §2.4 item
/// 3).
///
/// `proved` is whether the channel's key was proved on the connection
/// that asks ([`prove`]). Where it was not, the answer is the one for a
/// channel that is not held: no entries, and the place that was asked
/// after. The store is not looked at.
///
/// A page holds at most ENTRY_PAGE_MAX_ENTRIES entries, and at most
/// ENTRY_PAGE_MAX_BYTES of them as they travel, so that it fits one
/// message. It always holds the first entry there is, whatever its size.
pub fn pull(
    conn: &Connection,
    channel: &[u8; 32],
    proved: bool,
    after: u64,
    limit: u32,
) -> Result<Page, CordeliaError> {
    let mut page = Page {
        entries: Vec::new(),
        next: after,
        cost: 0,
    };
    if !proved {
        return Ok(page);
    }
    let most = limit.min(ENTRY_PAGE_MAX_ENTRIES) as usize;
    let mut place = i64::try_from(after).unwrap_or(i64::MAX);
    let mut bytes = 0;
    while page.entries.len() < most {
        let ask = (most - page.entries.len()).min(PAGE_READ);
        let read = entries::channel_entries_after(conn, channel, place, ask as u32)?;
        let last = read.len() < ask;
        for held in read {
            let travels = ENTRY_WIRE_OVERHEAD_BYTES + held.entry.content.len();
            if !page.entries.is_empty() && bytes + travels > ENTRY_PAGE_MAX_BYTES {
                return Ok(page);
            }
            bytes += travels;
            place = held.seq;
            page.next = held.seq.max(0) as u64;
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
    conn.execute(
        "UPDATE relay_channels SET used_at = ?2 WHERE channel_id = ?1",
        params![channel.as_slice(), now],
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
    let storage = |e: rusqlite::Error| RelayError::Storage(storage(e));
    let (begin, commit, undo) = if conn.is_autocommit() {
        ("BEGIN IMMEDIATE", "COMMIT", "ROLLBACK")
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
    const LISTED: Asker = Asker::ListedRelay { held_since: None };

    /// A relay that the operator lists, which says it has held the channel
    /// since `since`.
    fn listed_since(since: i64) -> Asker {
        Asker::ListedRelay {
            held_since: Some(since),
        }
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
        assert_eq!(
            held_channel(&conn, &channel(1)).unwrap(),
            Some(HeldChannel {
                held_since: NOW,
                used_at: NOW,
                bytes: SMALL,
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
        // The channel is held from when it was first taken.
        assert_eq!(
            held_channel(&conn, &channel(1)).unwrap(),
            Some(HeldChannel {
                held_since: NOW,
                used_at: NOW,
                bytes: 3 * SMALL,
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
    /// rule whatever room there is.
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
        for entry in [&first, &another, &larger] {
            assert_eq!(
                take(&conn, &mut room, entry, &from(1), NOW + 60).unwrap(),
                Taken::AlreadyHeld
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
        .unwrap();
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
                prove(&conn, &channel(1), &SESSION, &itself, &forged, NOW + 60).unwrap(),
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
                prove(&conn, &channel(1), &SESSION, &itself, &seen, NOW + 60).unwrap(),
                not_held
            );
        }
        // And asked for without a proof, the channel it holds is handed as
        // the one it does not hold is, from any place.
        for after in [0, 1, 7] {
            let unproved = pull(&conn, &channel(1), false, after, 100).unwrap();
            assert_eq!(
                unproved,
                Page {
                    entries: Vec::new(),
                    next: after,
                    cost: 0,
                }
            );
            assert_eq!(
                unproved,
                pull(&conn, &channel(2), false, after, 100).unwrap()
            );
            assert_eq!(
                unproved,
                pull(&conn, &channel(2), true, after, 100).unwrap()
            );
        }
        // Nothing of all that counted as use of the channel.
        assert_eq!(used_at(&conn, 1), Some(NOW));
        // The control: whoever holds the key is handed it.
        let proved = proof::make(&secret(1), &SESSION, &peer()).unwrap();
        assert!(prove(&conn, &channel(1), &SESSION, &peer(), &proved, NOW + 60).unwrap());
        assert_eq!(
            pull(&conn, &channel(1), true, 0, 100).unwrap().entries,
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
            for asker in [from(1), LISTED, listed_since(NOW - DAY)] {
                refused(take(&conn, &mut room, &entry, &asker, NOW + 60).map(|_| ()));
                refused(show(&conn, &mut room, &entry, &asker, NOW + 60).map(|_| ()));
            }
        }
        assert_eq!(all(&conn), before);
        // Nor is an address counted for what was refused.
        assert_eq!(room.new_channels[&IpAddr::from([192, 0, 2, 1])].len(), 2);

        // Making room with no room at all, and sweeping long after
        // anything was used: nothing is dropped.
        refused(make_room(&conn, 0).map(|_| ()));
        refused(sweep_unused(&conn, NOW + 365 * DAY).map(|_| ()));
        // Nor is what a listed relay says kept.
        refused(listed_relay_says(&conn, &channel(1), NOW - DAY).map(|_| ()));
        assert_eq!(all(&conn), before);
        assert!(conn.is_autocommit(), "no transaction is left open");

        // The control: with no device following a phrase there, each does
        // what it does.
        conn.execute("DELETE FROM person", []).unwrap();
        assert!(listed_relay_says(&conn, &channel(1), NOW - DAY).unwrap());
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
            [channel(2), channel(1), channel(4)]
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
        take(&conn, &mut room, &small(1, 4, 5), &said, NOW + 700).unwrap();
        assert_eq!(since(&conn, 1), Some(NOW - 100));
        // With an entry that is already held, and with one shown.
        assert_eq!(
            take(
                &conn,
                &mut room,
                &small(1, 4, 5),
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
            })
        );
        assert_eq!(since(&conn, 2), Some(NOW + 500));
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
        assert!(prove(&conn, &channel(1), &SESSION, &peer(), &good, NOW + 60).unwrap());

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
                NOW + 60
            )
            .unwrap()
        );
        assert!(
            !prove(
                &conn,
                &channel(1),
                &SESSION,
                &peer(),
                &for_another,
                NOW + 120
            )
            .unwrap()
        );
        // And the proof of channel 1 is none for channel 2.
        assert!(!prove(&conn, &channel(2), &SESSION, &peer(), &good, NOW + 120).unwrap());

        // A proof made over another session's value: replayed here from
        // another connection, and from here on another.
        let elsewhere = proof::make(&secret(1), &other_session, &peer()).unwrap();
        assert!(!prove(&conn, &channel(1), &SESSION, &peer(), &elsewhere, NOW + 120).unwrap());
        assert!(
            !prove(
                &conn,
                &channel(1),
                &other_session,
                &peer(),
                &good,
                NOW + 120
            )
            .unwrap()
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
                NOW + 120
            )
            .unwrap()
        );
        let another = device(9).public_key();
        assert!(!prove(&conn, &channel(1), &SESSION, &another, &good, NOW + 120).unwrap());

        // A channel that the relay does not hold, proved as it should be:
        // the same no.
        let not_held = proof::make(&secret(3), &SESSION, &peer()).unwrap();
        assert!(proof::check(&channel(3), &SESSION, &peer(), &not_held));
        assert!(!prove(&conn, &channel(3), &SESSION, &peer(), &not_held, NOW + 120).unwrap());
        // And nothing is kept of having been asked.
        assert_eq!(held_channel(&conn, &channel(3)).unwrap(), None);

        // Only a proof that holds is use of a channel.
        assert_eq!(used_at(&conn, 1), Some(NOW + 60));
        assert_eq!(used_at(&conn, 2), Some(NOW + 60));

        // The channel is looked up only after the signature holds: with
        // nothing to look channels up in, a proof that fails is still
        // answered, and one that holds is not.
        conn.execute_batch("DROP TABLE relay_channels").unwrap();
        assert!(!prove(&conn, &channel(1), &SESSION, &peer(), &for_another, NOW).unwrap());
        assert!(!prove(&conn, &channel(1), &SESSION, &peer(), &[0; 64], NOW).unwrap());
        assert!(prove(&conn, &channel(1), &SESSION, &peer(), &good, NOW).is_err());
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

        let page = |after: u64, limit: u32| pull(&conn, &channel(1), true, after, limit).unwrap();
        let of = |n: std::ops::RangeInclusive<usize>| -> Vec<Entry> {
            n.map(|n| (*entries[n - 1]).clone()).collect()
        };
        assert_eq!(
            page(0, 2),
            Page {
                entries: of(1..=2),
                next: 2,
                cost: 2 * SMALL,
            }
        );
        assert_eq!(
            page(2, 2),
            Page {
                entries: of(3..=4),
                next: 4,
                cost: 2 * SMALL,
            }
        );
        assert_eq!(
            page(4, 2),
            Page {
                entries: of(5..=5),
                next: 5,
                cost: SMALL,
            }
        );
        // After the last there is nothing, and the place stays.
        let nothing = |after: u64| Page {
            entries: Vec::new(),
            next: after,
            cost: 0,
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
        // the relay holds it. That is the answer for a channel that is
        // not held.
        for after in [0, 2, 5] {
            assert_eq!(
                pull(&conn, &channel(1), false, after, 100).unwrap(),
                nothing(after)
            );
            assert_eq!(
                pull(&conn, &channel(3), true, after, 100).unwrap(),
                nothing(after)
            );
        }

        // A newer revision has a later place: a connection that has paged
        // past the one it replaces is handed it next.
        let newer = made(1, 2, 6, "2.md", "a newer text");
        take(&conn, &mut room, &newer, &from(1), NOW).unwrap();
        assert_eq!(
            page(5, 100),
            Page {
                entries: vec![(*newer).clone()],
                next: 7,
                cost: SMALL,
            }
        );
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
            let page = pull(&conn, &channel(1), true, 0, limit).unwrap();
            assert_eq!(page.entries.len(), 100, "{limit}");
            assert_eq!((page.next, page.cost), (100, 100 * SMALL));
        }
        let rest = pull(&conn, &channel(1), true, 100, 1000).unwrap();
        assert_eq!((rest.entries.len(), rest.next), (3, 103));
        // Fewer where fewer are asked for, across the steps in which a
        // page is read.
        for limit in [1, 15, 16, 17, 33, 99] {
            let page = pull(&conn, &channel(1), true, 0, limit).unwrap();
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
        let first = pull(&conn, &channel(2), true, 0, 100).unwrap();
        assert_eq!(first.entries.len(), 13);
        assert!(travels(&first) <= ENTRY_PAGE_MAX_BYTES);
        assert_eq!(first.cost, 13 * entry_cost(MAX_ITEM_BYTES));
        // The next page starts after the last entry handed, and nothing
        // is passed over between pages.
        let second = pull(&conn, &channel(2), true, first.next, 100).unwrap();
        assert_eq!(second.entries.len(), 13);
        assert_eq!(second.entries[0].author, device(14).public_key());
        let third = pull(&conn, &channel(2), true, second.next, 100).unwrap();
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
        let mixed = pull(&conn, &channel(3), true, 0, 100).unwrap();
        assert_eq!(mixed.entries.len(), 3 + 13);
        assert!(travels(&mixed) <= ENTRY_PAGE_MAX_BYTES);
        assert!(travels(&mixed) + MAX_ENTRY_WIRE_BYTES > ENTRY_PAGE_MAX_BYTES);
        let one = pull(&conn, &channel(3), true, mixed.next, 1).unwrap();
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
        assert!(prove(&conn, &channel(3), &SESSION, &peer(), &proved, yesterday).unwrap());
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
        assert!(!prove(&conn, &channel(5), &SESSION, &peer(), &proved, yesterday).unwrap());
        // The sixth: an entry is pushed, and stored. Whoever holds an
        // entry can push it: it proves no key, and is no use either.
        assert_eq!(
            take(&conn, &mut room, &small(6, 1, 6), &from(1), yesterday).unwrap(),
            Taken::Stored
        );
        // And it is handed in pages: that is no use, the proof was.
        pull(&conn, &channel(6), true, 0, 100).unwrap();
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
