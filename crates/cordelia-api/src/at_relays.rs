//! What a device does at a relay it is set up with, for the channels of
//! its own (decision 2026-10-04 §4.6, §7.3): which entry it shows, what it
//! does with the entry it is answered with, which channels it proves and
//! pulls, what it takes of a page, what it sends, and what it does with
//! each answer.
//!
//! Plain functions over the node's database and the device's own key, as
//! the rest of what a device does under a channel from its secret is.
//! Nothing here opens a stream, and nothing here knows a connection: the
//! node asks these when it has leave to use one, and tells them what came
//! back. A relay is its node key.
//!
//! ## The show (§4.6)
//!
//! [`to_show`] is the change entry that a device shows a relay: the
//! latest it keeps, which in a fork is the one it had applied. [`answered`]
//! takes the entry that a relay answers with, which goes through the one
//! door ([`crate::take::take`]) and no other, and only where it is an
//! entry of the slot that was shown.
//!
//! ## The channels (§2.5)
//!
//! [`channels`] is what a pass goes through, for a device that has applied
//! a statement and has not stopped: the pair channels in which it has
//! something of its own to send, the personal channel, and the channel of
//! each name it holds. [`listed`] is the channels of the names that the
//! personal channel lists and that the device does not hold: it proves
//! those once a day, so that a name whose only device is gone is not
//! dropped while any device of the person's is on.
//!
//! ## Pulling (§16)
//!
//! [`take_page`] takes a page that a relay handed, in one transaction:
//! each entry through the one door, and then the place, with the mark of
//! the relay's holding. Where an entry makes a key count, or lets one add,
//! every place is forgotten instead, at every relay: every channel is read
//! again from the start, since what that key signed was refused when it
//! arrived, and was not kept.
//!
//! ## Sending (§7.3)
//!
//! What a device holds of a channel is sent to each relay in the order in
//! which its own store took it, and how far it has got is kept for each
//! relay ([`to_send`], [`sent`]). So what one relay handed it reaches a
//! relay that is not listed with that one. What it took from a relay is
//! not sent back there, where nothing else was waiting.
//!
//! What a device carried into the channel of a name when it applied a
//! statement is sent by a rule of its own ([`Which::Carried`]): after the
//! channel was fetched from the relay, and not where the device holds, in
//! that slot, another key's entry of that version, or one at a higher
//! revision. After the fetch that is what the relay's copy has, or was
//! sent just before. Two devices that carried one version would otherwise
//! each leave a copy of it at every relay.
//!
//! In a pair channel a device sends only what it wrote itself: a
//! hand-over, and the delete that it writes over one that has gone
//! ([`crate::adding::write_over_dropped`]). The hand-over goes to every
//! relay, and that a relay was sent it is kept from before it is sent,
//! whatever comes back. The delete goes only to a relay that was sent
//! something of that channel: any other has nothing to write over.

use rusqlite::Connection;

use cordelia_core::protocol::{ENTRY_WIRE_OVERHEAD_BYTES, PERSONAL_NAME_PREFIX};
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::proof;
use cordelia_crypto::version;
use cordelia_storage::at_relays::{self as kept_rows};
use cordelia_storage::entries;
use cordelia_storage::person::{self as held_rows, Kept, State};
use cordelia_storage::relay::{Mark, NO_MARK};

use crate::person::{PersonError, Shown, in_one, kept_entry, latest_entry};
use crate::publish::Standing;
use crate::take::{Taken, take};

// ── Where a device stands ────────────────────────────────────────────

/// Where a device stands in its own channels, as its database says it
/// now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stands {
    /// It follows no phrase: it has no channel of its own, and nothing to
    /// show (decision 2026-10-04 §5.2).
    NoPhrase,
    /// It follows a phrase, and has stopped or is in a fork: it neither
    /// sends in its own channels nor takes from them (§4.3, §4.5).
    Stopped(State),
    /// It has applied a statement, and is a device under it.
    Applied,
}

/// Where this device stands. It is read from the one row, and nothing is
/// checked: whoever goes on to read a channel checks what it reads.
pub fn stands(conn: &Connection) -> Result<Stands, PersonError> {
    Ok(match held_rows::person(conn)? {
        None => Stands::NoPhrase,
        Some(person) if person.state == State::Applied => Stands::Applied,
        Some(person) => Stands::Stopped(person.state),
    })
}

// ── The show ─────────────────────────────────────────────────────────

/// The change entry that a device shows a relay, and what it keeps
/// besides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shows {
    /// The latest change entry the device keeps: the one it shows. In a
    /// fork that is the one it had applied (decision 2026-10-04 §4.5).
    pub entry: CheckedEntry,
    /// What the entry made apart from it is named by, where the device is
    /// in a fork and keeps one. A relay that says it holds that one is
    /// asked no more for it.
    pub apart: Option<[u8; 32]>,
}

/// What this device shows a relay. `None` where it follows no phrase: it
/// has nothing to show.
pub fn to_show(conn: &Connection) -> Result<Option<Shows>, PersonError> {
    if held_rows::person(conn)?.is_none() {
        return Ok(None);
    }
    Ok(Some(Shows {
        entry: latest_entry(conn)?,
        apart: kept_entry(conn, Kept::Apart)?.map(|apart| apart.id()),
    }))
}

/// What the latest change entry that this device keeps is named by: what
/// a leave to use a connection was given for. `None` where the device
/// follows no phrase. The entry is not checked: only its name is asked.
pub fn kept_id(conn: &Connection) -> Result<Option<[u8; 32]>, PersonError> {
    Ok(held_rows::change_entry(conn, Kept::Latest)?.map(|entry| entry.id()))
}

/// What became of the entry that a relay answered a show with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answered {
    /// It was shown to the device, which did what a change entry has it
    /// do: applied it, stopped, kept it apart, or nothing.
    Shown(Shown),
    /// It is no entry of the slot that was shown: another channel's,
    /// another author's or another slot's. A relay answers a show only
    /// with an entry by the author of the one it was shown, in its slot.
    /// Nothing was done with it.
    NotOfTheSlot,
    /// It is of the slot that was shown, and the one door did not take it
    /// as a change entry. Nothing was done with it.
    NotTaken,
}

/// Take the entry that a relay answered a show of `shown` with. `answer`
/// has passed the check that needs no key.
///
/// It goes through the one door ([`take`]), and is trusted no further
/// than that door and the judging of its statement trust it (decision
/// 2026-10-04 §4.6). An error is this device's, and not the entry's: its
/// database could not be read or written, nothing was changed, and the
/// device has been answered with a change that it has not applied.
pub fn answered(
    conn: &Connection,
    identity: &NodeIdentity,
    shown: &CheckedEntry,
    answer: &CheckedEntry,
    now: i64,
) -> Result<Answered, PersonError> {
    let of_the_slot = answer.channel == shown.channel
        && answer.author == shown.author
        && answer.slot == shown.slot;
    if !of_the_slot {
        return Ok(Answered::NotOfTheSlot);
    }
    Ok(match take(conn, identity, answer, now)? {
        Taken::Shown(shown) => Answered::Shown(shown),
        Taken::Own { .. } | Taken::Refused(_) => Answered::NotTaken,
    })
}

// ── The channels ─────────────────────────────────────────────────────

/// Which of a device's channels one is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// A pair channel, in which this device wrote a hand-over: it sends
    /// there what it wrote, and reads nothing.
    Pair,
    /// The personal channel of the generation it has applied.
    Personal,
    /// The channel of this name, in the generation it has applied.
    Name(String),
}

/// A channel of a device's own, as a pass goes through it.
#[derive(Clone, PartialEq, Eq)]
pub struct Own {
    pub kind: Kind,
    /// The channel's ID.
    pub id: [u8; 32],
    /// The channel's secret, where the device proves and reads the
    /// channel: `None` for a pair channel.
    secret: Option<[u8; 32]>,
}

impl std::fmt::Debug for Own {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The secret is not printed.
        f.debug_struct("Own")
            .field("kind", &self.kind)
            .field("id", &hex::encode(&self.id[..4]))
            .finish_non_exhaustive()
    }
}

impl Own {
    /// The proof that the end of a connection whose node key is `prover`
    /// holds this channel's key, over the value `session` that both ends
    /// export from the connection's TLS session (decision 2026-10-04 §2.4
    /// item 3). `None` for a channel that the device does not prove.
    pub fn proof(&self, session: &[u8; 32], prover: &[u8; 32]) -> Option<[u8; 64]> {
        proof::make(self.secret.as_ref()?, session, prover).ok()
    }

    /// Whether the device pulls the channel from a relay: every channel
    /// but a pair channel, which it only writes.
    pub fn is_pulled(&self) -> bool {
        self.secret.is_some()
    }
}

/// The channels that a pass goes through, in its order: the pair channels
/// in which this device has something of its own, since a hand-over goes
/// ahead of everything (decision 2026-10-04 §6); the personal channel; and
/// the channel of each name it holds, in order of name.
///
/// None for a device that follows no phrase, has stopped, or is in a
/// fork: it neither sends in a channel of its own nor takes from one.
pub fn channels(conn: &Connection, identity: &NodeIdentity) -> Result<Vec<Own>, PersonError> {
    if stands(conn)? != Stands::Applied {
        return Ok(Vec::new());
    }
    let standing = Standing::to_write(conn)?;
    let personal = derive::personal_secret(&standing.secret)?;
    let mut own = vec![Own {
        kind: Kind::Personal,
        id: derive::channel_id(&personal)?,
        secret: Some(personal),
    }];
    for name in held_rows::names(conn)? {
        let secret = standing.name_secret(conn, &name.name)?;
        own.push(Own {
            kind: Kind::Name(name.name),
            id: name.channel,
            secret: Some(secret),
        });
    }
    // Whatever else this device wrote in is a pair channel: its store
    // holds nothing of its own but in its own channels, and where it
    // handed a device what it needs.
    let mut pairs: Vec<Own> = kept_rows::channels_written_by(conn, &identity.public_key())?
        .into_iter()
        .filter(|id| !own.iter().any(|channel| channel.id == *id))
        .map(|id| Own {
            kind: Kind::Pair,
            id,
            secret: None,
        })
        .collect();
    pairs.append(&mut own);
    Ok(pairs)
}

/// The channels of the names that the personal channel lists and that
/// this device does not hold, at most `most` of them, in order of name
/// (decision 2026-10-04 §2.5): a device proves those too, once a day.
///
/// A name is listed where a key that counts has an entry of its own under
/// the name's place in the personal channel
/// (PERSONAL_NAME_PREFIX and the name) that is no delete. A name that is
/// not in its one spelling is no name, and is passed over.
pub fn listed(conn: &Connection, most: usize) -> Result<Vec<Own>, PersonError> {
    if stands(conn)? != Stands::Applied {
        return Ok(Vec::new());
    }
    let standing = Standing::to_write(conn)?;
    let personal = derive::personal_secret(&standing.secret)?;
    let channel = derive::channel_id(&personal)?;
    let held: Vec<String> = held_rows::names(conn)?
        .into_iter()
        .map(|name| name.name)
        .collect();
    let mut names: Vec<String> = Vec::new();
    for slot in entries::channel_slots(conn, &channel)? {
        for entry in entries::slot_entries(conn, &channel, &slot)? {
            if entry.delete || !standing.counting.counts(&entry.author) {
                continue;
            }
            let Ok(inside) = entry.open(&personal) else {
                continue;
            };
            let Some(name) = inside.name.strip_prefix(PERSONAL_NAME_PREFIX) else {
                continue;
            };
            if !held.iter().any(|held| held == name) && !names.iter().any(|seen| seen == name) {
                names.push(name.to_string());
            }
        }
    }
    names.sort();
    let mut listed = Vec::new();
    for name in names {
        if listed.len() >= most {
            break;
        }
        // Another spelling would be another channel: it is refused where
        // the secret is derived, and the name is passed over.
        let Ok(secret) = derive::own_secret(&standing.secret, &name) else {
            continue;
        };
        listed.push(Own {
            kind: Kind::Name(name),
            id: derive::channel_id(&secret)?,
            secret: Some(secret),
        });
    }
    Ok(listed)
}

// ── Pulling ──────────────────────────────────────────────────────────

/// The mark and the place that a device asks `relay` for a page of
/// `channel` with: the ones it keeps, and the mark of no holding, from the
/// start, where it keeps none.
pub fn place(
    conn: &Connection,
    relay: &[u8; 32],
    channel: &[u8; 32],
) -> Result<(Mark, u64), PersonError> {
    Ok(kept_rows::kept(conn, relay, channel)?
        .place
        .unwrap_or((NO_MARK, 0)))
}

/// A page that a relay handed of a channel.
#[derive(Debug, Clone, Copy)]
pub struct Page<'a> {
    /// The relay's node key.
    pub relay: &'a [u8; 32],
    /// The channel that was asked for.
    pub channel: &'a Own,
    /// The entries, each checked as whatever a device is sent is checked.
    pub entries: &'a [CheckedEntry],
    /// The mark of the holding that `next` is a place in, as the relay
    /// says it.
    pub mark: Mark,
    /// The place to ask after next.
    pub next: u64,
}

/// What became of a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageTaken {
    /// Each entry went through the one door, and this became of each.
    Taken {
        each: Vec<Taken>,
        /// A key came to count by one of them, or came to may add: every
        /// place was forgotten, at every relay, and every channel is read
        /// again from the start.
        read_again: bool,
    },
    /// The page holds an entry of another channel than the one asked for:
    /// it is not the page. Nothing of it was taken, and the place is as
    /// it was.
    NotThePage,
}

/// Take a page that a relay handed (see the module's documentation). One
/// transaction: every entry is taken and the place moves, or nothing
/// does. So the place moves only past what the one door has dealt with.
///
/// - A page under another mark than the one kept is of another holding:
///   the relay dropped the channel and took it again. It holds nothing of
///   what it was sent before, so nothing is kept of that either, and the
///   device sends it the channel again.
/// - A page with nothing in it under the mark of no holding, against a
///   place that the device keeps, says that the relay holds the channel
///   no more: it is as [`not_held_at`]. (A relay says so only to a
///   connection that proved the channel. A pull that was not proved is
///   answered with the mark that was asked with.)
/// - An entry of this device's own that it carried is not sent to this
///   relay where the relay hands another key's entry of that version, or
///   one at a higher revision: that is decided where the carried entries
///   are sent ([`to_send`]), from what the store holds once the channel
///   was fetched.
/// - What the page brought is not sent back to the relay it came from,
///   where nothing else was waiting to be sent there.
pub fn take_page(
    conn: &Connection,
    identity: &NodeIdentity,
    page: &Page,
    now: i64,
) -> Result<PageTaken, PersonError> {
    let channel = &page.channel.id;
    if page.entries.iter().any(|entry| entry.channel != *channel) {
        return Ok(PageTaken::NotThePage);
    }
    in_one(conn, || {
        let kept = kept_rows::kept(conn, page.relay, channel)?;
        let another_holding =
            page.mark != NO_MARK && kept.place.is_some_and(|(mark, _)| mark != page.mark);
        // A relay answers a pull of a channel that was proved and that
        // it does not hold with the mark of no holding. Against a place
        // that the device keeps there, the relay dropped the channel
        // since.
        let no_holding = page.mark == NO_MARK && page.entries.is_empty() && kept.place.is_some();
        if another_holding || no_holding {
            kept_rows::start_again(conn, page.relay, channel)?;
        }
        let kept = kept_rows::kept(conn, page.relay, channel)?;
        // Whether anything waits to be sent to this relay, before the
        // page: where nothing does, nothing does after it.
        let waiting = kept_rows::last_taken(conn, channel)? > sent_from(conn, page.channel, &kept)?;

        let mut each = Vec::with_capacity(page.entries.len());
        let mut read_again = false;
        for entry in page.entries {
            let taken = take(conn, identity, entry, now)?;
            if let Taken::Own {
                came_to_count,
                came_to_add,
                ..
            } = &taken
            {
                read_again |= *came_to_count > 0 || *came_to_add > 0;
            }
            each.push(taken);
        }

        if page.mark != NO_MARK {
            kept_rows::keep_place(conn, page.relay, channel, &page.mark, page.next)?;
        }
        if read_again {
            kept_rows::forget_places(conn)?;
        }
        if !waiting {
            let last = kept_rows::last_taken(conn, channel)?;
            kept_rows::sent(conn, page.relay, channel, last)?;
        }
        Ok(PageTaken::Taken { each, read_again })
    })
}

/// `relay` answered a proof of `channel` with no: it does not hold the
/// channel. Nothing is kept of what it was sent, nor a place in it:
/// everything the device holds of the channel is sent there again.
pub fn not_held_at(
    conn: &Connection,
    relay: &[u8; 32],
    channel: &[u8; 32],
) -> Result<(), PersonError> {
    kept_rows::start_again(conn, relay, channel)?;
    Ok(())
}

/// Every channel of this device's own is read again from the start, at
/// every relay (decision 2026-10-04 §16): what whoever takes a record of
/// an addition owes, where a key came to count by it. The next pass of the
/// node does the reading.
pub fn read_again(conn: &Connection) -> Result<(), PersonError> {
    kept_rows::forget_places(conn)?;
    Ok(())
}

// ── Sending ──────────────────────────────────────────────────────────

/// Which part of what a device holds of a channel is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    /// What the device wrote or took since it last applied a statement:
    /// sent whenever there is leave to send.
    Since,
    /// What the device carried into the channel of a name when it applied
    /// a statement (decision 2026-10-04 §7.3): sent only once the channel
    /// was fetched from the relay in this pass, and what came since was
    /// sent.
    Carried,
}

/// One thing in a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    /// The entry at this place in the store's order is not sent to this
    /// relay.
    Passed(i64),
    /// The entry at this place is sent.
    Sent(i64),
}

/// What a device sends a relay of one channel in one push: the entries,
/// and how far in the store's order they reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    which: Which,
    /// Each entry that the store holds of the channel from where the last
    /// batch ended, in the store's order: sent, or passed over.
    items: Vec<Item>,
    /// The entries that are sent, in that order, as they are stored.
    pub entries: Vec<Entry>,
}

impl Batch {
    /// Whether there is nothing to send and nothing to pass over.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// How much one push may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Most {
    /// The most entries.
    pub entries: usize,
    /// The most bytes, as the entries travel. One entry is always sent,
    /// whatever its size.
    pub bytes: usize,
}

/// What a relay answered for one entry that it was pushed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pushed {
    /// It stored the entry, or holds it, or holds a later one from that
    /// author in that slot: it is not sent again.
    Holds,
    /// It refused the entry as not signed as it must be: it is not sent
    /// again.
    DoesNotCheck,
    /// It had no room for the entry: it is kept, and sent again later.
    NoRoom,
    /// The device's address is over its allowance of new channels there:
    /// the entry is kept, and sent again later.
    OverAllowance,
}

/// What became of a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Sent {
    /// How many entries the relay holds now, or held.
    pub held: usize,
    /// How many it refused as not signed as they must be.
    pub do_not_check: usize,
    /// The refusal that stopped the batch, where one did: for room, or
    /// for the allowance. That entry, and every one after it, is sent
    /// again.
    pub refused: Option<Pushed>,
}

/// Where what is sent of `channel` to a relay begins, of what came since
/// the device last applied a statement: after what was sent, and in the
/// channel of a name after what was carried, which has a turn of its own.
fn sent_from(
    conn: &Connection,
    channel: &Own,
    kept: &kept_rows::KeptThere,
) -> Result<i64, PersonError> {
    Ok(match channel.kind {
        Kind::Name(_) => kept.sent_to.max(kept_rows::carried_up_to(conn)?),
        Kind::Pair | Kind::Personal => kept.sent_to,
    })
}

/// How many entries of a channel are read from the store at a time.
const READ: u32 = 64;

/// The next batch that `relay` is sent of `channel`: what the store holds
/// of it from where the last batch ended, in the store's order, as much
/// as one push may hold (see the module's documentation). [`sent`] is
/// told what the relay answered.
///
/// Nothing is written but this: that the relay is about to be sent
/// something of a pair channel, which is kept whatever comes back. A
/// hand-over that reached a relay whose answer was lost is still written
/// over there.
pub fn to_send(
    conn: &Connection,
    identity: &NodeIdentity,
    relay: &[u8; 32],
    channel: &Own,
    which: Which,
    most: Most,
) -> Result<Batch, PersonError> {
    let batch = batch_of(conn, identity, relay, channel, which, most)?;
    if channel.kind == Kind::Pair && !batch.entries.is_empty() {
        kept_rows::sending(conn, relay, &channel.id)?;
    }
    Ok(batch)
}

/// [`to_send`], with nothing written.
fn batch_of(
    conn: &Connection,
    identity: &NodeIdentity,
    relay: &[u8; 32],
    channel: &Own,
    which: Which,
    most: Most,
) -> Result<Batch, PersonError> {
    let own = identity.public_key();
    let kept = kept_rows::kept(conn, relay, &channel.id)?;
    // Whether the relay was sent anything of a pair channel.
    let sent_the_pair =
        channel.kind == Kind::Pair && kept_rows::keeps_any(conn, relay, &channel.id)?;
    let carried_up_to = kept_rows::carried_up_to(conn)?;
    let (mut after, up_to) = match (which, &channel.kind) {
        (Which::Since, _) => (sent_from(conn, channel, &kept)?, i64::MAX),
        (Which::Carried, Kind::Name(_)) => (kept.carried_to, carried_up_to),
        // Only the channel of a name has what was carried sent apart.
        (Which::Carried, _) => (0, 0),
    };
    let mut batch = Batch {
        which,
        items: Vec::new(),
        entries: Vec::new(),
    };
    let mut bytes = 0;
    loop {
        let read = entries::channel_entries_after(conn, &channel.id, after, READ)?;
        let last = read.len() < READ as usize;
        for held in read {
            if held.seq > up_to {
                return Ok(batch);
            }
            after = held.seq;
            // A delete in a pair channel is for a relay that was sent
            // what it is written over. Any other is not sent it, and
            // nothing is kept of that: it is asked again each time.
            if channel.kind == Kind::Pair && held.entry.delete && !sent_the_pair {
                continue;
            }
            let passed = match (&channel.kind, which) {
                // Only what the device wrote itself.
                (Kind::Pair, _) => held.entry.author != own,
                (Kind::Name(_), Which::Carried) => {
                    held.entry.author != own || held_back(conn, channel, &held.entry, &own)?
                }
                _ => false,
            };
            if passed {
                batch.items.push(Item::Passed(held.seq));
                continue;
            }
            let travels = ENTRY_WIRE_OVERHEAD_BYTES + held.entry.content.len();
            let full = batch.entries.len() >= most.entries
                || (!batch.entries.is_empty() && bytes + travels > most.bytes);
            if full {
                return Ok(batch);
            }
            bytes += travels;
            batch.items.push(Item::Sent(held.seq));
            batch.entries.push(held.entry);
        }
        if last {
            return Ok(batch);
        }
    }
}

/// Whether an entry that this device carried into the channel of a name
/// is held back from a relay (decision 2026-10-04 §7.3): the device
/// holds, in that slot, another key's entry of that version, or an entry
/// at a higher revision. Once the channel was fetched from the relay, and
/// what came since was sent there, that is what the relay's copy has.
fn held_back(
    conn: &Connection,
    channel: &Own,
    carried: &Entry,
    own: &[u8; 32],
) -> Result<bool, PersonError> {
    let Some(secret) = &channel.secret else {
        return Ok(false);
    };
    let standing = Standing::of(conn)?;
    let held = entries::slot_entries(conn, &channel.id, &carried.slot)?;
    let slot = version::current(&held, secret, standing.number(), |key| {
        standing.counting.counts(key)
    })?;
    // An entry at a higher revision, whatever it holds: of a key that
    // counts, in a band that the statement has.
    if slot.highest.is_some_and(|highest| highest > carried.rev) {
        return Ok(true);
    }
    // That version, in another key's entry.
    let id = carried.id();
    Ok(slot.current.is_some_and(|current| {
        current.rev == carried.rev
            && current.entries.iter().any(|one| one.id == id)
            && current.entries.iter().any(|one| one.author != *own)
    }))
}

/// A relay answered a batch: `answers` says what it answered for each
/// entry that was sent, in their order. How far the relay was sent the
/// channel moves on past each entry that it holds now or will not take,
/// and past what was passed over, up to the first that it refused for
/// room or for the allowance: that one, and what follows it, is sent
/// again.
///
/// An answer that does not say one thing for each entry says nothing of
/// any: nothing moves, and all of it is sent again.
pub fn sent(
    conn: &Connection,
    relay: &[u8; 32],
    channel: &Own,
    batch: &Batch,
    answers: &[Pushed],
) -> Result<Sent, PersonError> {
    let mut done = Sent::default();
    if answers.len() != batch.entries.len() {
        return Ok(done);
    }
    let mut answers = answers.iter();
    let mut up_to = None;
    for item in &batch.items {
        match item {
            Item::Passed(seq) => up_to = Some(*seq),
            Item::Sent(seq) => match answers.next() {
                Some(Pushed::Holds) => {
                    done.held += 1;
                    up_to = Some(*seq);
                }
                Some(Pushed::DoesNotCheck) => {
                    done.do_not_check += 1;
                    up_to = Some(*seq);
                }
                Some(refused @ (Pushed::NoRoom | Pushed::OverAllowance)) => {
                    done.refused = Some(*refused);
                    break;
                }
                None => break,
            },
        }
    }
    if let Some(up_to) = up_to {
        match batch.which {
            Which::Since => kept_rows::sent(conn, relay, &channel.id, up_to)?,
            Which::Carried => kept_rows::carried(conn, relay, &channel.id, up_to)?,
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use cordelia_core::protocol::HAND_OVER_NAME;
    use cordelia_crypto::addition::Addition;
    use cordelia_crypto::entry::Value;
    use cordelia_storage::entries::Outcome;

    use crate::adding::{Accepted, drop_old_hand_overs, write_over_dropped};
    use crate::person::{AdditionSeen, NotCounted, added_name};
    use crate::several::{Machine, Several, entry_by, identity_of, listed_as, signed_in, text};
    use crate::take::{NotTaken, Record};

    const RELAY: [u8; 32] = [0xa1; 32];
    const OTHER_RELAY: [u8; 32] = [0xa2; 32];
    const MARK: Mark = [0x4d, 1, 2, 3, 4, 5, 6, 7];
    const OTHER_MARK: Mark = [0x4e, 1, 2, 3, 4, 5, 6, 7];

    /// As much as one push may hold, and more than any test sends.
    const MOST: Most = Most {
        entries: 100,
        bytes: 1_000_000,
    };

    /// An ordinary entry that the store took.
    const STORED: Taken = Taken::Own {
        stored: Outcome::Stored,
        record: None,
        came_to_count: 0,
        came_to_add: 0,
    };

    /// An entry that the store held already, and that says no more.
    const HELD: Taken = Taken::Own {
        stored: Outcome::AlreadyHeld,
        record: None,
        came_to_count: 0,
        came_to_add: 0,
    };

    /// The channel of that kind among those that a pass on `on` goes
    /// through.
    fn channel_of(on: &Machine, kind: Kind) -> Own {
        channels(&on.conn, &on.identity)
            .unwrap()
            .into_iter()
            .find(|own| own.kind == kind)
            .unwrap_or_else(|| panic!("the device has no such channel: {kind:?}"))
    }

    fn notes_of(on: &Machine) -> Own {
        channel_of(on, Kind::Name("notes".into()))
    }

    fn ids(entries: &[Entry]) -> Vec<[u8; 32]> {
        entries.iter().map(Entry::id).collect()
    }

    fn ids_of(entries: &[CheckedEntry]) -> Vec<[u8; 32]> {
        entries.iter().map(|entry| entry.id()).collect()
    }

    /// What `on` sends `relay` next of `channel`.
    fn sends(on: &Machine, relay: &[u8; 32], channel: &Own, which: Which) -> Batch {
        to_send(&on.conn, &on.identity, relay, channel, which, MOST).unwrap()
    }

    /// `on` sends `relay` everything that waits of `channel`, and the
    /// relay takes each entry. Returns what it was sent.
    fn sends_all(on: &Machine, relay: &[u8; 32], channel: &Own, which: Which) -> Vec<[u8; 32]> {
        let mut all = Vec::new();
        loop {
            let batch = sends(on, relay, channel, which);
            if batch.is_empty() {
                return all;
            }
            all.extend(ids(&batch.entries));
            let answers = vec![Pushed::Holds; batch.entries.len()];
            sent(&on.conn, relay, channel, &batch, &answers).unwrap();
        }
    }

    /// A relay's holding of one channel, as a device is handed it: in
    /// pages of two.
    struct Holding {
        mark: Mark,
        entries: Vec<CheckedEntry>,
    }

    impl Holding {
        fn of(entries: &[CheckedEntry]) -> Self {
            Self {
                mark: MARK,
                entries: entries.to_vec(),
            }
        }

        /// The page after `after` in the holding marked `mark`: from the
        /// start where that is another holding than this one.
        fn page(&self, mark: Mark, after: u64) -> (Vec<CheckedEntry>, u64) {
            let after = if mark == self.mark { after as usize } else { 0 };
            let after = after.min(self.entries.len());
            let to = (after + 2).min(self.entries.len());
            (self.entries[after..to].to_vec(), to as u64)
        }
    }

    /// What became of the entries that were not held already.
    fn new_to_it(taken: &[Taken]) -> Vec<Taken> {
        taken.iter().filter(|one| **one != HELD).cloned().collect()
    }

    /// `on` reads `channel` at `relay`, from the place it keeps there to
    /// the end of what the relay holds. Returns what became of each
    /// entry, and whether a page said that everything is to be read
    /// again: where one did, the channel is read from the start in this
    /// same reading, since its place was forgotten with the others.
    fn reads(
        on: &Machine,
        relay: &[u8; 32],
        channel: &Own,
        holding: &Holding,
        now: i64,
    ) -> (Vec<Taken>, bool) {
        let (mut all, mut again) = (Vec::new(), false);
        loop {
            let (mark, after) = place(&on.conn, relay, &channel.id).unwrap();
            let (entries, next) = holding.page(mark, after);
            if entries.is_empty() {
                return (all, again);
            }
            let page = Page {
                relay,
                channel,
                entries: &entries,
                mark: holding.mark,
                next,
            };
            match take_page(&on.conn, &on.identity, &page, now).unwrap() {
                PageTaken::Taken { each, read_again } => {
                    all.extend(each);
                    again |= read_again;
                }
                PageTaken::NotThePage => panic!("not the page"),
            }
        }
    }

    /// The entry in which device `adder` adds device `new`, in the
    /// personal channel of `on`, under the statement it has applied.
    fn adds(on: &Machine, adder: u16, new: u16) -> CheckedEntry {
        let by = identity_of(adder);
        let statement = on.held().statement.statement;
        let record = Addition::under(&statement, listed_as(new), by.public_key(), 1)
            .unwrap()
            .sign(&by)
            .unwrap();
        let name = added_name(&record.addition.device.key).unwrap();
        let value = Value::Other(record.to_bytes().unwrap());
        entry_by(&by, &on.personal(), 1, &name, value, &[])
    }

    // ── Where a device stands, and what it shows ─────────────────────

    /// A device shows the latest change entry it keeps. One that follows
    /// no phrase has nothing to show, and no channel. In a fork it shows
    /// the entry it had applied, and says which other it keeps. A device
    /// that has stopped has no channel that a pass goes through.
    #[test]
    fn test_a_device_shows_the_latest_entry_it_keeps_and_in_a_fork_the_one_it_had_applied() {
        let s = Several::new(1);
        let on = &s[0];
        assert_eq!(stands(&on.conn).unwrap(), Stands::NoPhrase);
        assert_eq!(to_show(&on.conn).unwrap(), None);
        assert_eq!(kept_id(&on.conn).unwrap(), None);
        assert!(channels(&on.conn, &on.identity).unwrap().is_empty());
        assert!(listed(&on.conn, 1024).unwrap().is_empty());

        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        let first = s[0].latest();
        assert_eq!(stands(&s[0].conn).unwrap(), Stands::Applied);
        assert_eq!(
            to_show(&s[0].conn).unwrap(),
            Some(Shows {
                entry: first.clone(),
                apart: None,
            })
        );
        assert_eq!(kept_id(&s[0].conn).unwrap(), Some(first.id()));
        // Its pair channels with the two devices it added, the personal
        // channel, and the name.
        assert_eq!(channels(&s[0].conn, &s[0].identity).unwrap().len(), 4);

        // A change is made on it: the entry it keeps is another.
        let by_0 = s.change(0, &[0, 1, 2], &[]);
        assert_eq!(kept_id(&s[0].conn).unwrap(), Some(by_0.id()));
        assert_ne!(by_0.id(), first.id());
        // One made apart, on device 1, is what a relay answers with.
        let by_1 = s.change(1, &[0, 1, 2], &[]);
        let on = &s[0];
        assert_eq!(
            answered(&on.conn, &on.identity, &by_0, &by_1, s.now).unwrap(),
            Answered::Shown(Shown::Fork)
        );
        assert_eq!(stands(&on.conn).unwrap(), Stands::Stopped(State::Fork));
        // It shows the one it had applied, and keeps the other.
        assert_eq!(
            to_show(&on.conn).unwrap(),
            Some(Shows {
                entry: by_0.clone(),
                apart: Some(by_1.id()),
            })
        );
        assert_eq!(kept_id(&on.conn).unwrap(), Some(by_0.id()));
        // It has no channel that a pass goes through, and proves none.
        assert!(channels(&on.conn, &on.identity).unwrap().is_empty());
        assert!(listed(&on.conn, 1024).unwrap().is_empty());

        // A device that a change removes: it is answered with the change,
        // stops, and shows the entry that says so.
        let mut s = Several::of_one_person(3);
        let before = s[2].latest();
        let removal = s.change(0, &[0, 1], &[2]);
        let on = &s[2];
        assert_eq!(
            answered(&on.conn, &on.identity, &before, &removal, s.now).unwrap(),
            Answered::Shown(Shown::Removed)
        );
        assert_eq!(stands(&on.conn).unwrap(), Stands::Stopped(State::Removed));
        assert_eq!(kept_id(&on.conn).unwrap(), Some(removal.id()));
        assert!(channels(&on.conn, &on.identity).unwrap().is_empty());
    }

    /// What a relay answers a show with goes through the one door, and
    /// only where it is an entry of the slot that was shown: by that
    /// author, in that slot of that channel. Anything else is not looked
    /// at, and changes nothing.
    #[test]
    fn test_the_answer_to_a_show_is_taken_only_where_it_is_of_the_slot_shown() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        let file = s.write(0, "notes", "a.md", "a text");
        let shown = s[1].latest();
        let change = s.change(0, &[0, 1], &[]);
        let on = &s[1];
        let before = on.everything();
        let answer =
            |entry: &CheckedEntry| answered(&on.conn, &on.identity, &shown, entry, s.now).unwrap();

        // An entry of another channel: one of the device's own.
        assert_eq!(answer(&file), Answered::NotOfTheSlot);
        // An entry of the phrase's channel in that slot, that another key
        // than the phrase's signed: another author.
        let channel = s.phrase.channel_secret().unwrap();
        let by_another = signed_in(
            &channel,
            &identity_of(9),
            change.slot,
            change.rev,
            change.content.clone(),
        );
        assert_eq!(answer(&by_another), Answered::NotOfTheSlot);
        // The phrase's own entry in another slot of its channel.
        let phrase_key = s.phrase.signing_key().unwrap();
        let elsewhere = signed_in(
            &channel,
            &phrase_key,
            [7; 32],
            change.rev,
            change.content.clone(),
        );
        assert_eq!(answer(&elsewhere), Answered::NotOfTheSlot);
        // And the phrase's own entry, in that slot, of another channel.
        let of_another = signed_in(
            &[9; 32],
            &phrase_key,
            change.slot,
            change.rev,
            change.content.clone(),
        );
        assert_eq!(answer(&of_another), Answered::NotOfTheSlot);
        assert_eq!(on.everything(), before);

        // The entry that it shows: it keeps it.
        assert_eq!(answer(&shown), Answered::Shown(Shown::Held));
        // The later change: it is applied, in that step.
        assert!(matches!(
            answer(&change),
            Answered::Shown(Shown::Applied(_))
        ));
        assert_eq!(kept_id(&on.conn).unwrap(), Some(change.id()));
        // And the one it showed before is behind it now.
        assert_eq!(answer(&shown), Answered::Shown(Shown::Behind));
    }

    // ── The channels ─────────────────────────────────────────────────

    /// A pass goes through the pair channels in which the device has
    /// something of its own, then the personal channel, then the channel
    /// of each name it holds, in order of name. It proves and pulls each
    /// but a pair channel, which it only writes.
    #[test]
    fn test_a_pass_goes_through_the_pair_channels_the_personal_channel_and_each_name() {
        let mut s = Several::new(2);
        s.make_phrase(0);
        s.hold(&[0], "notes");
        s.hold(&[0], "a team");
        let on = &s[0];
        let own = channels(&on.conn, &on.identity).unwrap();
        let kinds: Vec<Kind> = own.iter().map(|own| own.kind.clone()).collect();
        assert_eq!(
            kinds,
            [
                Kind::Personal,
                Kind::Name("a team".into()),
                Kind::Name("notes".into())
            ]
        );
        assert_eq!(own[0].id, derive::channel_id(&on.personal()).unwrap());
        assert_eq!(own[1].id, derive::channel_id(&on.own("a team")).unwrap());
        assert_eq!(own[2].id, derive::channel_id(&on.own("notes")).unwrap());

        // Each is proved with its own key, over the session's value and
        // the prover's key.
        let (session, prover) = ([0x51; 32], on.key());
        for channel in &own {
            assert!(channel.is_pulled());
            let made = channel.proof(&session, &prover).unwrap();
            assert!(proof::check(&channel.id, &session, &prover, &made));
            assert!(!proof::check(&own[0].id, &session, &prover, &made) || channel.id == own[0].id);
            assert!(!proof::check(&channel.id, &[0x52; 32], &prover, &made));
        }

        // It adds a device: the pair channel goes ahead of the others.
        let handed = s.hand(0, 1).hand_over;
        let on = &s[0];
        let own = channels(&on.conn, &on.identity).unwrap();
        assert_eq!(own.len(), 4);
        assert_eq!(
            (own[0].kind.clone(), own[0].id),
            (Kind::Pair, handed.channel)
        );
        assert_eq!(own[1].kind, Kind::Personal);
        // A pair channel is written, and is neither proved nor pulled.
        assert!(!own[0].is_pulled());
        assert_eq!(own[0].proof(&session, &prover), None);
        // Nothing of a secret is printed.
        let printed = format!("{own:?}");
        assert!(!printed.contains(&hex::encode(on.personal())));
        assert!(!printed.contains(&hex::encode(on.own("notes"))));
    }

    /// A device proves, once a day, the channel of every name that its
    /// personal channel lists and that it does not hold: a name is listed
    /// where a key that counts has an entry of its own there, under the
    /// name's place, that is no delete. At most as many as it is asked
    /// for, in order of name.
    #[test]
    fn test_the_names_that_the_personal_channel_lists_and_the_device_does_not_hold() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0], "notes");
        let now = s.tick();
        let on = &s[0];
        let personal = on.personal();
        assert!(listed(&on.conn, 1024).unwrap().is_empty());
        let says = |by: &NodeIdentity, rev: u64, name: &str, value: Value| {
            let entry = entry_by(by, &personal, rev, name, value, &[]);
            take(&on.conn, &on.identity, &entry, now).unwrap()
        };
        let other = &s[1].identity;
        // Device 1 lists three names, one of which this device holds, and
        // this device lists one that it does not hold itself.
        for name in ["name/work", "name/notes", "name/a team"] {
            assert_eq!(says(other, 1, name, text("")), STORED);
        }
        assert_eq!(says(&on.identity, 1, "name/music", text("")), STORED);
        // A name that both list is listed once.
        assert_eq!(says(&on.identity, 1, "name/work", text("")), STORED);
        // What is no word that a name is synced: another place, a delete,
        // a name in another spelling, and the word of a key that does not
        // count.
        assert_eq!(says(other, 1, "names/films", text("")), STORED);
        assert_eq!(says(other, 1, "name/gone", Value::Delete), STORED);
        assert_eq!(says(other, 1, "name/Films ", text("")), STORED);
        assert_eq!(
            says(&identity_of(9), 1, "name/strangers", text("")),
            Taken::Refused(NotTaken::SignerDoesNotCount)
        );
        // And the word of a key that does not count, where the store
        // holds it all the same: it lists nothing.
        let unlisted = entry_by(
            &identity_of(9),
            &personal,
            1,
            "name/unlisted",
            text(""),
            &[],
        );
        entries::store(&on.conn, &unlisted, now).unwrap();

        let names = |most: usize| -> Vec<Kind> {
            listed(&on.conn, most)
                .unwrap()
                .into_iter()
                .map(|own| own.kind)
                .collect()
        };
        let name = |name: &str| Kind::Name(name.into());
        assert_eq!(names(1024), [name("a team"), name("music"), name("work")]);
        assert_eq!(names(2), [name("a team"), name("music")]);
        assert!(names(0).is_empty());
        // Each is the name's channel in the generation applied, and is
        // proved with its key.
        let all = listed(&on.conn, 1024).unwrap();
        assert_eq!(all[2].id, derive::channel_id(&on.own("work")).unwrap());
        let made = all[2].proof(&[0x51; 32], &on.key()).unwrap();
        assert!(proof::check(&all[2].id, &[0x51; 32], &on.key(), &made));
        // A name that it comes to hold is one that a pass goes through,
        // and is listed here no more.
        hold_name_on(on, "work", now);
        assert_eq!(names(1024), [name("a team"), name("music")]);
        // A delete over the word takes the name from the list.
        assert_eq!(says(other, 2, "name/a team", Value::Delete), STORED);
        assert_eq!(names(1024), [name("music")]);
    }

    fn hold_name_on(on: &Machine, name: &str, now: i64) {
        crate::person::hold_name(&on.conn, name, now).unwrap();
    }

    // ── Pulling ──────────────────────────────────────────────────────

    /// A device keeps its place in a relay's holding of a channel with
    /// the mark of that holding, and the next pull goes on from it. The
    /// place moves with the page, in the transaction that takes its
    /// entries. A page under another mark is of another holding: the
    /// relay dropped the channel and took it again, so the channel is
    /// read from the start, and everything is sent there again.
    #[test]
    fn test_a_pull_goes_on_from_the_place_kept_and_from_the_start_under_another_mark() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        let written: Vec<CheckedEntry> = ["a.md", "b.md", "c.md", "d.md", "e.md"]
            .iter()
            .map(|file| s.write(0, "notes", file, "a text"))
            .collect();
        let now = s.tick();
        let notes = notes_of(&s[1]);
        fn take_one(
            on: &Machine,
            channel: &Own,
            relay: &[u8; 32],
            entries: &[CheckedEntry],
            (mark, next): (Mark, u64),
        ) -> PageTaken {
            let page = Page {
                relay,
                channel,
                entries,
                mark,
                next,
            };
            take_page(&on.conn, &on.identity, &page, 1_800_001_000).unwrap()
        }
        let stored = |n: usize| PageTaken::Taken {
            each: vec![STORED; n],
            read_again: false,
        };
        let on = &s[1];
        let kept = |relay: &[u8; 32], channel: &Own| place(&on.conn, relay, &channel.id).unwrap();

        // It has no place: it asks from the start, with no mark.
        assert_eq!(kept(&RELAY, &notes), (NO_MARK, 0));
        assert_eq!(
            take_one(on, &notes, &RELAY, &written[..2], (MARK, 2)),
            stored(2)
        );
        assert_eq!(kept(&RELAY, &notes), (MARK, 2));
        // The place is for that relay and that channel.
        assert_eq!(kept(&OTHER_RELAY, &notes), (NO_MARK, 0));
        let personal = channel_of(on, Kind::Personal);
        assert_eq!(kept(&RELAY, &personal), (NO_MARK, 0));
        // The next page goes on from there.
        assert_eq!(
            take_one(on, &notes, &RELAY, &written[2..4], (MARK, 4)),
            stored(2)
        );
        assert_eq!(kept(&RELAY, &notes), (MARK, 4));
        // A page with nothing in it, at the end: the place stays. That
        // is also the answer to a pull that was not proved.
        assert_eq!(take_one(on, &notes, &RELAY, &[], (MARK, 4)), stored(0));
        assert_eq!(kept(&RELAY, &notes), (MARK, 4));
        // The mark of no holding, to a device that keeps no place there:
        // nothing is kept of it, and what the device sent that relay
        // stays as sent. (It is also what a pull that was not proved is
        // answered, where it was asked with no mark.)
        assert_eq!(sends_all(on, &OTHER_RELAY, &notes, Which::Since).len(), 4);
        assert_eq!(
            take_one(on, &notes, &OTHER_RELAY, &[], (NO_MARK, 0)),
            stored(0)
        );
        assert_eq!(kept(&OTHER_RELAY, &notes), (NO_MARK, 0));
        assert!(sends(on, &OTHER_RELAY, &notes, Which::Since).is_empty());

        // What it then writes itself is sent there, and held. What the
        // relay handed it is not sent back.
        let mine = s.write(1, "notes", "mine.md", "by device 1");
        assert!(mine.rev > 0 && now > 0);
        let on = &s[1];
        let kept = |relay: &[u8; 32], channel: &Own| place(&on.conn, relay, &channel.id).unwrap();
        assert_eq!(sends_all(on, &RELAY, &notes, Which::Since), [mine.id()]);
        assert!(sends(on, &RELAY, &notes, Which::Since).is_empty());

        // A page under another mark: the relay dropped the channel, and
        // holds it anew. The place is in the new holding, and nothing is
        // kept of what the relay was sent: it is all sent again.
        assert_eq!(
            take_one(on, &notes, &RELAY, &written[4..], (OTHER_MARK, 1)),
            stored(1)
        );
        assert_eq!(kept(&RELAY, &notes), (OTHER_MARK, 1));
        let again = sends(on, &RELAY, &notes, Which::Since);
        assert_eq!(again.entries.len(), 6);
        assert!(ids(&again.entries).contains(&mine.id()));

        // A page that holds an entry of another channel is not the page:
        // nothing of it is taken, and the place is as it was.
        let before = on.everything();
        let stray = s[0].stored_in(&s[0].personal());
        let mixed = [written[0].clone(), stray[0].clone()];
        assert_eq!(
            take_one(on, &notes, &RELAY, &mixed, (MARK, 9)),
            PageTaken::NotThePage
        );
        assert_eq!(on.everything(), before);

        // A proof that the relay answers with no: it does not hold the
        // channel. Nothing is kept of it there.
        not_held_at(&on.conn, &RELAY, &notes.id).unwrap();
        assert_eq!(kept(&RELAY, &notes), (NO_MARK, 0));
        assert_eq!(sends(on, &RELAY, &notes, Which::Since).entries.len(), 6);
    }

    /// A relay that answers a pull with the mark of no holding, and
    /// nothing, holds the channel no more. Against a place that the
    /// device keeps there, nothing it sent is there: the place is
    /// forgotten, and everything it holds of the channel is sent again.
    /// At another relay nothing changes.
    #[test]
    fn test_a_page_of_no_holding_against_a_place_kept_has_everything_sent_again() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        let written = [
            s.write(0, "notes", "a.md", "a text"),
            s.write(0, "notes", "b.md", "a text"),
        ];
        let now = s.tick();
        let notes = notes_of(&s[1]);
        fn page(
            on: &Machine,
            notes: &Own,
            relay: &[u8; 32],
            entries: &[CheckedEntry],
            (mark, next): (Mark, u64),
        ) -> PageTaken {
            let page = Page {
                relay,
                channel: notes,
                entries,
                mark,
                next,
            };
            take_page(&on.conn, &on.identity, &page, 1_800_001_000).unwrap()
        }
        // Both relays handed it the two entries, and were then sent what
        // it wrote itself.
        for relay in [&RELAY, &OTHER_RELAY] {
            page(&s[1], &notes, relay, &written, (MARK, 2));
        }
        let mine = s.write(1, "notes", "mine.md", "by device 1");
        assert!(now > 0);
        let on = &s[1];
        let page = |relay: &[u8; 32], entries: &[CheckedEntry], mark: Mark, next: u64| {
            page(on, &notes, relay, entries, (mark, next))
        };
        for relay in [&RELAY, &OTHER_RELAY] {
            // (What the first relay handed it goes to the second too.)
            let sent = sends_all(on, relay, &notes, Which::Since);
            assert_eq!(sent.last(), Some(&mine.id()));
            assert!(sends(on, relay, &notes, Which::Since).is_empty());
            assert_eq!(place(&on.conn, relay, &notes.id).unwrap(), (MARK, 2));
        }

        // One of them says that it holds nothing of the channel now.
        let taken = page(&RELAY, &[], NO_MARK, 0);
        assert_eq!(
            taken,
            PageTaken::Taken {
                each: Vec::new(),
                read_again: false
            }
        );
        assert_eq!(place(&on.conn, &RELAY, &notes.id).unwrap(), (NO_MARK, 0));
        let again: BTreeSet<[u8; 32]> = sends_all(on, &RELAY, &notes, Which::Since)
            .into_iter()
            .collect();
        let all: BTreeSet<[u8; 32]> = [written[0].id(), written[1].id(), mine.id()]
            .into_iter()
            .collect();
        assert_eq!(again, all);
        // The other relay still holds what it held.
        assert_eq!(place(&on.conn, &OTHER_RELAY, &notes.id).unwrap(), (MARK, 2));
        assert!(sends(on, &OTHER_RELAY, &notes, Which::Since).is_empty());
        // Said again, with no place kept: nothing more happens.
        page(&RELAY, &[], NO_MARK, 0);
        assert!(sends(on, &RELAY, &notes, Which::Since).is_empty());
    }

    /// The place moves only past what the one door has dealt with: a page
    /// whose taking fails moves nothing, and none of its entries is kept.
    #[test]
    fn test_a_page_is_taken_whole_with_its_place_or_not_at_all() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        let written = [
            s.write(0, "notes", "a.md", "a text"),
            s.write(0, "notes", "b.md", "a text"),
        ];
        let now = s.tick();
        let on = &s[1];
        let notes = notes_of(on);
        let page = Page {
            relay: &RELAY,
            channel: &notes,
            entries: &written,
            mark: MARK,
            next: 2,
        };
        // The store cannot keep a place: the table is gone, and the page
        // fails before any of it is taken.
        on.conn
            .execute_batch("ALTER TABLE at_relays RENAME TO elsewhere")
            .unwrap();
        assert!(take_page(&on.conn, &on.identity, &page, now).is_err());
        on.conn
            .execute_batch("ALTER TABLE elsewhere RENAME TO at_relays")
            .unwrap();
        assert!(on.stored_in(&on.own("notes")).is_empty());
        assert_eq!(place(&on.conn, &RELAY, &notes.id).unwrap(), (NO_MARK, 0));
        // The store can read what it keeps of the relay, and cannot write
        // the place: the page fails after its entries went through the
        // one door, and none of them is kept.
        on.conn
            .execute_batch(
                "CREATE TRIGGER no_place BEFORE INSERT ON at_relays
                 BEGIN SELECT RAISE(ABORT, 'no place is written'); END",
            )
            .unwrap();
        assert!(take_page(&on.conn, &on.identity, &page, now).is_err());
        on.conn.execute_batch("DROP TRIGGER no_place").unwrap();
        assert!(on.stored_in(&on.own("notes")).is_empty());
        assert_eq!(place(&on.conn, &RELAY, &notes.id).unwrap(), (NO_MARK, 0));
        // The control.
        assert!(take_page(&on.conn, &on.identity, &page, now).is_ok());
        assert_eq!(on.stored_in(&on.own("notes")).len(), 2);
        assert_eq!(place(&on.conn, &RELAY, &notes.id).unwrap(), (MARK, 2));
    }

    /// Where an entry of a page makes a key count, every place is
    /// forgotten, at every relay and in every channel: what that key
    /// signed was refused when it arrived, and is read again. So a device
    /// that is handed a new device's entries before the record of its
    /// addition ends with the same as one that is handed the record
    /// first.
    #[test]
    fn test_a_record_that_arrives_after_what_its_device_wrote_has_everything_read_again() {
        // Device 0 made the phrase and added devices 1 and 2. It adds
        // device 3, which holds the name and writes two files.
        let mut s = Several::new(4);
        s.make_phrase(0);
        for new in [1, 2] {
            assert!(matches!(s.add(0, new), Accepted::Joined(_)));
        }
        s.meet(&[0, 1, 2]);
        s.hold(&[0, 1, 2], "notes");
        let earlier = s.write(0, "notes", "earlier.md", "by device 0");
        assert!(matches!(s.add(0, 3), Accepted::Joined(_)));
        s.hold(&[3], "notes");
        let by_3 = [
            s.write(3, "notes", "a.md", "by device 3"),
            s.write(3, "notes", "b.md", "by device 3 too"),
        ];
        let now = s.tick();
        // What a relay holds of the two channels: everything that devices
        // 0 and 3 hold of them.
        let mut personal: Vec<CheckedEntry> = s[0].stored_in(&s[0].personal());
        personal.extend(s[3].stored_in(&s[3].personal()));
        let personal = Holding::of(&personal);
        let notes = Holding::of(&[earlier.clone(), by_3[0].clone(), by_3[1].clone()]);
        const REFUSED: Taken = Taken::Refused(NotTaken::SignerDoesNotCount);

        // Device 1 reads the name first: what device 3 wrote is refused,
        // and its place is past it.
        let on = &s[1];
        let (of_notes, of_personal) = (notes_of(on), channel_of(on, Kind::Personal));
        let (taken, again) = reads(on, &RELAY, &of_notes, &notes, now);
        assert_eq!((taken, again), (vec![STORED, REFUSED, REFUSED], false));
        assert_eq!(place(&on.conn, &RELAY, &of_notes.id).unwrap(), (MARK, 3));
        // And at another relay, which holds the same.
        reads(on, &OTHER_RELAY, &of_notes, &notes, now);
        assert_eq!(
            place(&on.conn, &OTHER_RELAY, &of_notes.id).unwrap(),
            (MARK, 3)
        );
        assert!(!on.counts(&s.key(3)));

        // Then the personal channel, with the record: a key came to
        // count, and every place is forgotten, at both relays.
        let (taken, again) = reads(on, &RELAY, &of_personal, &personal, now);
        assert!(again);
        let counted = taken
            .iter()
            .filter(|one| {
                matches!(
                    one,
                    Taken::Own {
                        came_to_count: 1,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(counted, 1);
        assert!(on.counts(&s.key(3)));
        for relay in [RELAY, OTHER_RELAY] {
            assert_eq!(place(&on.conn, &relay, &of_notes.id).unwrap(), (NO_MARK, 0));
        }
        // The page that said so was read to its end all the same, and the
        // channel it is of is read again from the start with the others:
        // nothing stops at an entry that is held already.
        let (taken, again) = reads(on, &RELAY, &of_notes, &notes, now);
        assert_eq!((taken, again), (vec![HELD, STORED, STORED], false));

        // Device 2 reads the personal channel first, and nothing twice.
        let on = &s[2];
        let (of_notes, of_personal) = (notes_of(on), channel_of(on, Kind::Personal));
        reads(on, &RELAY, &of_personal, &personal, now);
        let (taken, _) = reads(on, &RELAY, &of_notes, &notes, now);
        assert_eq!(taken, [STORED, STORED, STORED]);

        // The two hold the same of the name, and of the personal channel
        // what the relay holds and what each wrote itself.
        let held = |n: usize, secret: &[u8; 32]| -> BTreeSet<[u8; 32]> {
            ids_of(&s[n].stored_in(secret)).into_iter().collect()
        };
        assert_eq!(held(1, &s[1].own("notes")), held(2, &s[2].own("notes")));
        assert_eq!(held(1, &s[1].own("notes")).len(), 3);
        let from_relay: BTreeSet<[u8; 32]> = ids_of(&personal.entries).into_iter().collect();
        for n in [1, 2] {
            assert!(held(n, &s[n].personal()).is_superset(&from_relay), "{n}");
        }
    }

    /// The same where a key comes to may add: a record that it signed
    /// before was not counted, and what the key it adds wrote was
    /// refused. A record by which a key comes to may add, and by which no
    /// key comes to count, has everything read again too.
    #[test]
    fn test_a_key_that_comes_to_may_add_has_everything_read_again() {
        // The statement lists device 0, which added device 1.
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        let now = s.tick();
        let (personal, notes) = (s[1].personal(), s[1].own("notes"));
        // Device 1 adds device 8, which counts and may not add. Device 8
        // adds device 9, which writes a file. And device 0 adds device 8
        // too: it may add from then on.
        let by_1 = adds(&s[1], 1, 8);
        let by_8 = adds(&s[1], 8, 9);
        let lets_8_add = adds(&s[1], 0, 8);
        let by_9 = entry_by(&identity_of(9), &notes, 1, "a.md", text("by device 9"), &[]);
        let of_notes = Holding::of(std::slice::from_ref(&by_9));
        const REFUSED: Taken = Taken::Refused(NotTaken::SignerDoesNotCount);
        let record = |seen: AdditionSeen, came_to_count: usize, came_to_add: usize| Taken::Own {
            stored: Outcome::Stored,
            record: Some(Record::Seen(seen)),
            came_to_count,
            came_to_add,
        };
        let may_not = AdditionSeen::NotCounted(NotCounted::MayNotAdd);
        let already = AdditionSeen::NotCounted(NotCounted::CountsAlready);

        // Device 1 is handed them in the order in which each fails: the
        // file, the record that device 8 signed, and last the one that
        // lets device 8 add.
        let on = &s[1];
        let (own_notes, own_personal) = (notes_of(on), channel_of(on, Kind::Personal));
        assert_eq!(
            reads(on, &RELAY, &own_notes, &of_notes, now),
            (vec![REFUSED], false)
        );
        let first = Holding::of(&[by_1.clone(), by_8.clone()]);
        let (taken, again) = reads(on, &RELAY, &own_personal, &first, now);
        assert_eq!(
            new_to_it(&taken),
            [record(AdditionSeen::Counted, 1, 0), record(may_not, 0, 0)]
        );
        assert!(again, "device 8 came to count");
        // The name is read again, and the file is refused still.
        assert_eq!(
            reads(on, &RELAY, &own_notes, &of_notes, now),
            (vec![REFUSED], false)
        );
        assert_eq!(place(&on.conn, &RELAY, &own_notes.id).unwrap(), (MARK, 1));
        // The record that lets device 8 add: the record that it signed
        // comes to count with it, and everything is read again.
        let whole = Holding::of(&[by_1.clone(), by_8.clone(), lets_8_add.clone()]);
        let (taken, again) = reads(on, &RELAY, &own_personal, &whole, now);
        assert_eq!(new_to_it(&taken), [record(already, 1, 1)]);
        assert!(again);
        assert_eq!(
            place(&on.conn, &RELAY, &own_notes.id).unwrap(),
            (NO_MARK, 0)
        );
        assert_eq!(
            reads(on, &RELAY, &own_notes, &of_notes, now),
            (vec![STORED], false)
        );

        // Device 2 is handed the records in the order that fails nowhere.
        let on = &s[2];
        let (own_notes, own_personal) = (notes_of(on), channel_of(on, Kind::Personal));
        let in_order = Holding::of(&[by_1.clone(), lets_8_add.clone()]);
        let (taken, again) = reads(on, &RELAY, &own_personal, &in_order, now);
        // The second lets a key add, and no key comes to count by it:
        // that alone says that everything is read again.
        assert_eq!(
            new_to_it(&taken),
            [record(AdditionSeen::Counted, 1, 0), record(already, 0, 1)]
        );
        assert!(again);
        // Said by itself, in a page of its own: every place is forgotten.
        let on_0 = &s[0];
        let (notes_0, personal_0) = (notes_of(on_0), channel_of(on_0, Kind::Personal));
        reads(on_0, &RELAY, &notes_0, &of_notes, now);
        reads(
            on_0,
            &RELAY,
            &personal_0,
            &Holding::of(std::slice::from_ref(&by_1)),
            now,
        );
        reads(on_0, &RELAY, &notes_0, &of_notes, now);
        assert_eq!(place(&on_0.conn, &RELAY, &notes_0.id).unwrap(), (MARK, 1));
        let alone = Page {
            relay: &OTHER_RELAY,
            channel: &personal_0,
            entries: std::slice::from_ref(&lets_8_add),
            mark: MARK,
            next: 1,
        };
        assert_eq!(
            take_page(&on_0.conn, &on_0.identity, &alone, now).unwrap(),
            PageTaken::Taken {
                each: vec![record(already, 0, 1)],
                read_again: true,
            }
        );
        assert_eq!(
            place(&on_0.conn, &RELAY, &notes_0.id).unwrap(),
            (NO_MARK, 0)
        );
        assert_eq!(
            place(&on_0.conn, &OTHER_RELAY, &personal_0.id).unwrap(),
            (NO_MARK, 0)
        );

        // Device 2 goes on: the record that device 8 signed counts as it
        // arrives, and the file is taken the first time.
        let rest = Holding::of(&[by_1, lets_8_add, by_8]);
        let (taken, _) = reads(on, &RELAY, &own_personal, &rest, now);
        assert!(taken.contains(&record(AdditionSeen::Counted, 1, 0)));
        assert_eq!(
            reads(on, &RELAY, &own_notes, &of_notes, now),
            (vec![STORED], false)
        );
        // The two hold the same.
        for secret in [&personal, &notes] {
            let held = |n: usize| -> BTreeSet<[u8; 32]> {
                ids_of(&s[n].stored_in(secret))
                    .into_iter()
                    .filter(|id| {
                        // What each wrote itself in the personal channel,
                        // and gave no relay here, is its own.
                        [
                            &by_9,
                            &whole.entries[0],
                            &whole.entries[1],
                            &whole.entries[2],
                        ]
                        .iter()
                        .any(|entry| entry.id() == *id)
                    })
                    .collect()
            };
            assert_eq!(held(1), held(2));
            assert!(!held(1).is_empty());
        }
        assert!(s[1].counts(&identity_of(9).public_key()));
        assert!(s[2].counts(&identity_of(9).public_key()));
    }

    // ── Sending ──────────────────────────────────────────────────────

    /// What a device holds of a channel is sent to a relay in the order
    /// in which its store took it, as much as one push may hold, and how
    /// far it has got is kept for each relay. An entry that the relay
    /// holds, or refuses as not signed as it must be, is not sent again.
    /// One that it refuses for room, or for the allowance, is kept, with
    /// everything after it, and sent again.
    #[test]
    fn test_what_a_relay_has_not_been_sent_is_sent_and_each_answer_is_acted_on() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        let written: Vec<CheckedEntry> = ["a.md", "b.md", "c.md", "d.md"]
            .iter()
            .map(|file| s.write(0, "notes", file, "a text"))
            .collect();
        let on = &s[0];
        let notes = notes_of(on);
        let send = |relay: &[u8; 32], most: Most| {
            to_send(&on.conn, &on.identity, relay, &notes, Which::Since, most).unwrap()
        };
        let answered = |relay: &[u8; 32], batch: &Batch, answers: &[Pushed]| {
            sent(&on.conn, relay, &notes, batch, answers).unwrap()
        };

        // All four, in the order in which they were written.
        let batch = send(&RELAY, MOST);
        assert_eq!(ids(&batch.entries), ids_of(&written));
        // Asking writes nothing: asked again, it is the same.
        assert_eq!(send(&RELAY, MOST), batch);
        // As many as one push may hold, by their number and by their
        // bytes as they travel. The first is sent whatever its size.
        let few = Most { entries: 3, ..MOST };
        assert_eq!(ids(&send(&RELAY, few).entries), ids_of(&written[..3]));
        let travels = |entry: &CheckedEntry| ENTRY_WIRE_OVERHEAD_BYTES + entry.content.len();
        let two = travels(&written[0]) + travels(&written[1]);
        for (bytes, fit) in [(1, 1), (two - 1, 1), (two, 2), (two + 1, 2)] {
            let most = Most {
                entries: 100,
                bytes,
            };
            assert_eq!(send(&RELAY, most).entries.len(), fit, "{bytes} bytes");
        }

        // The relay stores the first, refuses the second as not signed as
        // it must be, and has no room for the third: the first two are
        // not sent again, and the third and what follows it are.
        let done = answered(
            &RELAY,
            &batch,
            &[
                Pushed::Holds,
                Pushed::DoesNotCheck,
                Pushed::NoRoom,
                Pushed::Holds,
            ],
        );
        assert_eq!(
            done,
            Sent {
                held: 1,
                do_not_check: 1,
                refused: Some(Pushed::NoRoom),
            }
        );
        let again = send(&RELAY, MOST);
        assert_eq!(ids(&again.entries), ids_of(&written[2..]));
        // An answer that does not say one thing for each entry says
        // nothing of any: nothing moves.
        for answers in [&[][..], &[Pushed::Holds][..], &[Pushed::Holds; 3][..]] {
            assert_eq!(answered(&RELAY, &again, answers), Sent::default());
            assert_eq!(send(&RELAY, MOST), again);
        }
        // Over the allowance, at the first: nothing moves either.
        let done = answered(&RELAY, &again, &[Pushed::OverAllowance, Pushed::Holds]);
        assert_eq!(
            done,
            Sent {
                held: 0,
                do_not_check: 0,
                refused: Some(Pushed::OverAllowance),
            }
        );
        assert_eq!(send(&RELAY, MOST), again);
        // Both held: there is nothing more for that relay.
        assert_eq!(answered(&RELAY, &again, &[Pushed::Holds; 2]).held, 2);
        assert!(send(&RELAY, MOST).is_empty());
        // An answer for a batch that was answered before moves nothing
        // back.
        answered(&RELAY, &batch, &[Pushed::Holds; 4]);
        assert!(send(&RELAY, MOST).is_empty());

        // What one relay was sent is not what another was: the other is
        // sent all of it.
        assert_eq!(ids(&send(&OTHER_RELAY, MOST).entries), ids_of(&written));
        // And what is written next is sent to both.
        let next = s.write(0, "notes", "e.md", "a text");
        let on = &s[0];
        assert_eq!(sends_all(on, &RELAY, &notes, Which::Since), [next.id()]);
        assert_eq!(sends_all(on, &OTHER_RELAY, &notes, Which::Since).len(), 5);
    }

    /// What a relay handed a device is sent to another relay, which is
    /// how an entry reaches a relay that is not listed with the first.
    /// It is not sent back to the relay it came from, where nothing else
    /// was waiting there.
    #[test]
    fn test_what_one_relay_handed_is_sent_to_another_and_not_back() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        let from_0 = [
            s.write(0, "notes", "a.md", "a text"),
            s.write(0, "notes", "b.md", "a text"),
        ];
        let now = s.tick();
        let on = &s[1];
        let notes = notes_of(on);
        let holding = Holding::of(&from_0);
        assert_eq!(reads(on, &RELAY, &notes, &holding, now).0, [STORED, STORED]);
        // Not back where it came from.
        assert!(sends(on, &RELAY, &notes, Which::Since).is_empty());
        // To the other relay: both.
        assert_eq!(
            sends_all(on, &OTHER_RELAY, &notes, Which::Since),
            ids_of(&from_0)
        );
        assert!(sends(on, &OTHER_RELAY, &notes, Which::Since).is_empty());

        // Where something was waiting to be sent to the relay when the
        // page came, the page is sent back with it: the relay answers
        // that it holds it.
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        let from_0 = [s.write(0, "notes", "a.md", "a text")];
        let mine = s.write(1, "notes", "mine.md", "by device 1");
        let now = s.tick();
        let on = &s[1];
        let notes = notes_of(on);
        reads(on, &RELAY, &notes, &Holding::of(&from_0), now);
        assert_eq!(
            sends_all(on, &RELAY, &notes, Which::Since),
            [mine.id(), from_0[0].id()]
        );
    }

    /// What a device carried into the channel of a name when it applied a
    /// statement is sent apart from what came since, and not where the
    /// device holds, in that slot, another key's entry of that version or
    /// an entry at a higher revision. In the personal channel a device's
    /// own word is sent with everything else.
    #[test]
    fn test_what_was_carried_is_held_back_where_the_relay_has_that_version_or_a_later_one() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        for file in ["a.md", "b.md", "c.md"] {
            s.write(0, "notes", file, &format!("what {file} holds"));
        }
        s.meet(&[0, 1]);
        // Device 0 has a word of its own in the personal channel.
        let word = entry_by(
            &s[0].identity,
            &s[0].personal(),
            1,
            "name/notes",
            text(""),
            &[],
        );
        assert_eq!(
            take(&s[0].conn, &s[0].identity, &word, s.now).unwrap(),
            STORED
        );
        // A change, made on device 0: it carries what it holds.
        let change = s.change(0, &[0, 1], &[]);
        let now = s.tick();
        let on = &s[0];
        let notes = notes_of(on);
        let carried = on.stored_in(&on.own("notes"));
        assert_eq!(carried.len(), 3);
        assert!(carried.iter().all(|entry| entry.author == on.key()));

        // What it carried is not what came since: in the name's channel
        // nothing did.
        assert!(sends(on, &RELAY, &notes, Which::Since).is_empty());
        // In the personal channel the word that it carried, and its word
        // that it applied, are sent with everything, and nothing there
        // is sent apart.
        let personal = channel_of(on, Kind::Personal);
        assert_eq!(on.stored_in(&on.personal()).len(), 2);
        assert_eq!(sends(on, &RELAY, &personal, Which::Since).entries.len(), 2);
        assert!(sends(on, &RELAY, &personal, Which::Carried).is_empty());
        // The relay holds nothing of the name: all three are sent.
        let all = sends(on, &RELAY, &notes, Which::Carried);
        assert_eq!(ids(&all.entries), ids_of(&carried));
        // The relay has no room for the second: the first is not sent
        // again, and the second and third are.
        let done = sent(
            &on.conn,
            &RELAY,
            &notes,
            &all,
            &[Pushed::Holds, Pushed::NoRoom, Pushed::Holds],
        );
        assert_eq!(done.unwrap().refused, Some(Pushed::NoRoom));
        let rest = sends(on, &RELAY, &notes, Which::Carried);
        assert_eq!(ids(&rest.entries), ids_of(&carried[1..]));

        // Device 1 applies the change, and carries the same versions.
        // The relay holds its entry of b.md, and device 0 fetches it.
        let other = &s[1];
        assert!(matches!(
            answered(&other.conn, &other.identity, &other.latest(), &change, now).unwrap(),
            Answered::Shown(Shown::Applied(_))
        ));
        let by_1 = other.stored_in(&other.own("notes"));
        assert_eq!(by_1.len(), 3);
        let same = |file: usize| {
            by_1.iter()
                .find(|entry| entry.slot == carried[file].slot)
                .unwrap()
                .clone()
        };
        // And an entry of device 1's at a higher revision than what was
        // carried of c.md.
        let later = entry_by(
            &other.identity,
            &on.own("notes"),
            carried[2].rev + 1,
            "c.md",
            text("a later text"),
            &[],
        );
        let fetched = Holding::of(&[same(1), later.clone()]);
        assert_eq!(reads(on, &RELAY, &notes, &fetched, now).0, [STORED, STORED]);
        // Neither is sent there now: the relay's copy has that version of
        // b.md, and a later entry in the slot of c.md. That the relay had
        // no room for one of them is dropped with it.
        let held_back = sends(on, &RELAY, &notes, Which::Carried);
        assert!(held_back.entries.is_empty());
        assert!(!held_back.is_empty());
        sent(&on.conn, &RELAY, &notes, &held_back, &[]).unwrap();
        assert!(sends(on, &RELAY, &notes, Which::Carried).is_empty());

        // At another relay nothing was fetched yet, and what came from
        // the first is sent there as what came since. What was carried is
        // held back there by the same rule: of a.md alone it is sent.
        assert_eq!(
            sends_all(on, &OTHER_RELAY, &notes, Which::Since),
            [same(1).id(), later.id()]
        );
        assert_eq!(
            sends_all(on, &OTHER_RELAY, &notes, Which::Carried),
            [carried[0].id()]
        );

        // What it writes from now on is not what it carried.
        let since = s.write(0, "notes", "d.md", "written since");
        let on = &s[0];
        assert_eq!(
            sends_all(on, &RELAY, &notes_of(on), Which::Since),
            [since.id()]
        );
        assert!(sends(on, &RELAY, &notes_of(on), Which::Carried).is_empty());
    }

    /// In a pair channel a device sends what it wrote itself. The
    /// hand-over goes to every relay, and that a relay was sent it is
    /// kept from before it is sent. The delete that is written over a
    /// hand-over which has gone goes only to a relay that was sent
    /// something of the channel.
    #[test]
    fn test_a_hand_over_goes_to_every_relay_and_its_delete_only_where_it_went() {
        let mut s = Several::new(2);
        s.make_phrase(0);
        let handed = s.hand(0, 1).hand_over;
        let made = s.now;
        let on = &s[0];
        let pair = channel_of(on, Kind::Pair);
        assert_eq!(pair.id, handed.channel);

        // It is sent to the first relay, whose answer is lost: that the
        // relay was sent it is kept all the same.
        let batch = sends(on, &RELAY, &pair, Which::Since);
        assert_eq!(ids(&batch.entries), [handed.id()]);
        assert!(kept_rows::keeps_any(&on.conn, &RELAY, &pair.id).unwrap());
        assert!(!kept_rows::keeps_any(&on.conn, &OTHER_RELAY, &pair.id).unwrap());
        // It is sent again, and the relay holds it.
        assert_eq!(sends_all(on, &RELAY, &pair, Which::Since), [handed.id()]);
        // Nothing of a pair channel is sent apart.
        assert!(sends(on, &RELAY, &pair, Which::Carried).is_empty());

        // Two hours on, the hand-over goes from the store, and a delete
        // is written over it, one revision above.
        let later = made + 2 * 60 * 60;
        assert_eq!(drop_old_hand_overs(&on.conn, later).unwrap(), 1);
        assert_eq!(
            write_over_dropped(&on.conn, &on.identity, later).unwrap(),
            1
        );
        let pair_secret = derive::pair_secret(&on.identity, &s.key(1)).unwrap();
        let over = on.stored_in(&pair_secret);
        assert_eq!(over.len(), 1);
        assert_eq!((over[0].rev, over[0].delete), (handed.rev + 1, true));
        let inside = over[0].open(&pair_secret).unwrap();
        assert_eq!(
            (inside.name.as_str(), inside.value),
            (HAND_OVER_NAME, Value::Delete)
        );

        // The delete goes to the relay that was sent the hand-over.
        let pair = channel_of(on, Kind::Pair);
        assert_eq!(sends_all(on, &RELAY, &pair, Which::Since), [over[0].id()]);
        // The other relay was sent nothing of the channel: it is not
        // sent the delete, and nothing is kept of that.
        assert!(sends(on, &OTHER_RELAY, &pair, Which::Since).is_empty());
        assert!(!kept_rows::keeps_any(&on.conn, &OTHER_RELAY, &pair.id).unwrap());
    }
}
