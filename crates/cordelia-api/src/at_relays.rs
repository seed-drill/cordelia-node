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
//! something of its own to send, the personal channel, the channel of
//! each name it holds, and last, where sync is on, the messages channel
//! (decision 2026-10-09 §2.1). [`listed`] is the channels of the names
//! that the personal channel lists and that the device does not hold: it
//! proves those once a day, so that a name whose only device is gone is
//! not dropped while any device of the person's is on.
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
//! An entry that a relay has no room for does not hold up what follows
//! it (§16): a delete, or a replacement that is no larger, makes room.
//! How far the relay was sent the channel goes on past it, and the entry
//! is kept apart, to be sent again after a wait: behind whatever is new,
//! so that what makes room reaches the relay first. Nothing that a relay
//! answered that it holds is sent it twice.
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
use cordelia_core::revision::next_under;
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Entry, Inside, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::proof;
use cordelia_crypto::slots::slot_id;
use cordelia_crypto::version;
use cordelia_storage::at_relays::{self as kept_rows};
use cordelia_storage::entries;
use cordelia_storage::meta;
use cordelia_storage::person::{self as held_rows, Kept, State};
use cordelia_storage::relay::{Mark, NO_MARK};

use crate::person::{
    PersonError, Shown, applied_name, applied_word, in_one, kept_entry, latest_entry,
};
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

/// Do `work` on what came from outside, and say with what it came to
/// whether the device applied a statement by it or its state changed
/// (decision 2026-10-04 §4.2): where it stands, or the change entry that
/// it keeps as the latest, is another after the work than before it. A
/// device that applies a statement keeps that statement's entry, and one
/// that stops, or comes to be in a fork, stands elsewhere.
///
/// Where either cannot be read, it is taken to have changed: whoever
/// asks then counts a change that may be none, and misses none.
pub fn telling_a_change<T>(conn: &Connection, work: impl FnOnce(&Connection) -> T) -> (T, bool) {
    let stood = |conn: &Connection| Some((stands(conn).ok()?, kept_id(conn).ok()?));
    let before = stood(conn);
    let done = work(conn);
    let after = stood(conn);
    (done, before.is_none() || before != after)
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
    /// The messages channel of the generation it has applied (decision
    /// 2026-10-09 §2.1): a channel of its own in every rule of decision
    /// 2026-10-04, last in a pass, and in none where sync is off.
    Messages,
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
/// ahead of everything (decision 2026-10-04 §6); the personal channel; the
/// channel of each name it holds, in order of name; and the messages
/// channel.
///
/// **The messages channel is last** (decision 2026-10-09 §2.1, C14): a
/// device that is added pulls its memory before its messages, and a relay
/// short of room drops messages before every name it held when the
/// generation began. **It is in the list only where sync is on** (C12):
/// where the node's settings hold no Claude Code directory, nothing of it
/// is proved, pulled or pushed.
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
    let messages = derive::messages_secret(&standing.secret)?;
    let messages = Own {
        kind: Kind::Messages,
        id: derive::channel_id(&messages)?,
        secret: Some(messages),
    };
    // Whatever else this device wrote in is a pair channel: its store
    // holds nothing of its own but in its own channels, and where it
    // handed a device what it needs. The messages channel is never one,
    // with sync off as with it on.
    let mut pairs: Vec<Own> = kept_rows::channels_written_by(conn, &identity.public_key())?
        .into_iter()
        .filter(|id| *id != messages.id && !own.iter().any(|channel| channel.id == *id))
        .map(|id| Own {
            kind: Kind::Pair,
            id,
            secret: None,
        })
        .collect();
    if meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_some() {
        own.push(messages);
    }
    pairs.append(&mut own);
    Ok(pairs)
}

/// The ID of the messages channel of the generation that this device
/// stands applied under, whether or not sync is on (decision 2026-10-09
/// §2.1): it is not read through the door for a carry. None for a device
/// that does not stand applied.
pub fn messages_channel(conn: &Connection) -> Result<Option<[u8; 32]>, PersonError> {
    if stands(conn)? != Stands::Applied {
        return Ok(None);
    }
    let standing = Standing::to_write(conn)?;
    let messages = derive::messages_secret(&standing.secret)?;
    Ok(Some(derive::channel_id(&messages)?))
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

// ── What is kept for nothing ─────────────────────────────────────────

/// What [`forget_what_is_done`] forgot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Forgotten {
    /// How many relays the device is no longer set up with.
    pub relays: usize,
    /// How many pair channels whose delete went everywhere.
    pub pairs: usize,
}

/// Forget what the device keeps of its relays and has no more use for,
/// since nothing else does (decision 2026-10-04 §6, §16):
///
/// - Everything kept of a relay that the device is no longer set up
///   with. `set_up` is the node keys of the relays it is set up with,
///   where every one of them is known: a relay's key is known while it
///   is connected. With `None` nothing is forgotten of any relay.
/// - Everything kept of a pair channel of which the store holds only
///   this device's delete, once every relay that was sent anything of
///   the channel was sent the delete. The delete itself stays in the
///   store: a hand-over made later for that key goes above it.
///
/// It is one transaction.
pub fn forget_what_is_done(
    conn: &Connection,
    identity: &NodeIdentity,
    set_up: Option<&[[u8; 32]]>,
) -> Result<Forgotten, PersonError> {
    in_one(conn, || {
        let mut forgotten = Forgotten::default();
        if let Some(set_up) = set_up {
            forgotten.relays = kept_rows::forget_relays_but(conn, set_up)?;
        }
        for channel in channels(conn, identity)? {
            if channel.kind != Kind::Pair || !kept_rows::keeps_any_anywhere(conn, &channel.id)? {
                continue;
            }
            // Of a pair channel a device's store holds what the device
            // wrote there, and nothing else.
            let held = entries::channel_entries_after(conn, &channel.id, 0, 2)?;
            let [only] = held.as_slice() else {
                continue;
            };
            if only.entry.delete && kept_rows::sent_everywhere(conn, &channel.id, only.seq)? {
                kept_rows::forget_channel(conn, &channel.id)?;
                forgotten.pairs += 1;
            }
        }
        Ok(forgotten)
    })
}

// ── What was carried, and whether it was sent ────────────────────────

/// Whether something that this device carried when it applied its
/// statement still waits to be sent to the relay whose node key is
/// `relay` (decision 2026-10-04 §7.3, §8): its own words in the personal
/// channel, and in the channel of each name it holds what it carried
/// there, which has a turn of its own.
pub fn carried_waits_at(
    conn: &Connection,
    identity: &NodeIdentity,
    relay: &[u8; 32],
) -> Result<bool, PersonError> {
    let carried_up_to = kept_rows::carried_up_to(conn)?;
    for channel in channels(conn, identity)? {
        let kept = kept_rows::kept(conn, relay, &channel.id)?;
        let from = match channel.kind {
            Kind::Personal => kept.sent_to,
            Kind::Name(_) => kept.carried_to,
            // Nothing is carried into the messages channel (decision
            // 2026-10-09 §9.1).
            Kind::Pair | Kind::Messages => continue,
        };
        let next = entries::channel_entries_after(conn, &channel.id, from, 1)?;
        if next.first().is_some_and(|held| held.seq <= carried_up_to) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// This device writes that it has sent what it carried, once it has
/// (decision 2026-10-04 §8): its word that it has applied the statement,
/// in the personal channel, then says so beside the statement's number
/// ([`crate::person::applied_word`]). Returns whether the word was
/// written: it waits in the store, and is sent as anything is.
///
/// `relays` are the relays that the device is set up with, every one, by
/// their node keys. It has sent what it carried where nothing of that
/// waits at any of them ([`carried_waits_at`]). With no relay nothing is
/// sent, and nothing is said. Nor is anything said twice, or by a device
/// that has stopped.
///
/// **A machine that recovered says nothing until its look has ended**
/// (§9): what it carries, it carries by that look. Where the look was
/// interrupted it never says so under that statement, and the recovery
/// that follows says that this one was cut short.
pub fn say_sent(
    conn: &Connection,
    identity: &NodeIdentity,
    relays: &[[u8; 32]],
    now: i64,
) -> Result<bool, PersonError> {
    in_one(conn, || {
        if relays.is_empty() || stands(conn)? != Stands::Applied {
            return Ok(false);
        }
        // A machine that recovered has not carried what it takes until
        // its look has ended (§9): it says nothing before that.
        if meta::get(conn, meta::PERSON_LOOK_PENDING)?.is_some() {
            return Ok(false);
        }
        let standing = Standing::to_write(conn)?;
        let own = identity.public_key();
        let personal = derive::personal_secret(&standing.secret)?;
        let channel = derive::channel_id(&personal)?;
        let name = applied_name(&own)?;
        let slot = slot_id(&derive::slot_key(&personal)?, &name);
        // Its own word there, as it stands: the statement's number alone.
        let Some(held) = entries::author_entry(conn, &channel, &slot, &own)? else {
            return Ok(false);
        };
        let before = held.entry.rev;
        let said = held.entry.check()?.open(&personal)?.value;
        let number = standing.number();
        if said != Value::Text(applied_word(number, false)) {
            return Ok(false);
        }
        for relay in relays {
            if carried_waits_at(conn, identity, relay)? {
                return Ok(false);
            }
        }
        let rev = next_under(Some(before), number).ok_or_else(|| {
            PersonError::Held(
                "this device's own word in that slot is at the last revision under the statement"
                    .into(),
            )
        })?;
        let inside = Inside {
            name,
            value: Value::Text(applied_word(number, true)),
            chain: Some(Vec::new()),
        };
        let entry = Entry::seal(&personal, identity, rev, &inside)?.check()?;
        entries::store(conn, &entry, now)?;
        Ok(true)
    })
}

// ── Sending ──────────────────────────────────────────────────────────

/// Which part of what a device holds of a channel is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// The entry at this place, which the relay had no room for before,
    /// is sent again.
    Again(i64),
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
    /// Whether entries that the relay had no room for wait to be sent it
    /// again and are not in this batch.
    pub waits: bool,
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
    /// It stored the entry, or holds it: it is not sent again.
    Holds,
    /// It holds a later one from that author in that slot: the entry is
    /// not sent again. In the messages channel it was not taken there,
    /// and a message waits for the pull that hands back the later one
    /// (decision 2026-10-09 §2.3, F6).
    HoldsLater,
    /// It holds another entry from that author in that slot at that
    /// revision, and not this one: the author signed two at one
    /// revision. This one is not sent again: no relay takes it over the
    /// other. The author's next entry in the slot goes above both.
    HoldsAnother,
    /// It refused the entry as not signed as it must be: it is not sent
    /// again.
    DoesNotCheck,
    /// It had no room for the entry: it is kept, and sent again later.
    /// What follows it is still offered.
    NoRoom,
    /// The device's address is over its allowance of new channels there:
    /// the entry is kept, and sent again later.
    OverAllowance,
}

/// What became of a batch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Sent {
    /// How many entries the relay holds now, or held.
    pub held: usize,
    /// How many it holds in another form: another entry from that author
    /// in that slot at that revision. They are sent no more.
    pub another: usize,
    /// The place, in the store's own order, of each entry that it holds
    /// in another form: for as long as the store holds an entry at that
    /// place, the file's next edit has not gone above both (§16).
    pub another_at: Vec<i64>,
    /// How many it refused as not signed as they must be.
    pub do_not_check: usize,
    /// How many it had no room for, and are kept to be sent again after
    /// a wait. What followed each was still offered.
    pub no_room: usize,
    /// The refusal that stopped the batch, where one did: for the
    /// allowance, or for room where the batch is of what was carried.
    /// That entry, and every one after it, is sent again from there.
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
        Kind::Pair | Kind::Personal | Kind::Messages => kept.sent_to,
    })
}

/// How many entries of a channel are read from the store at a time.
const READ: u32 = 64;

/// The next batch that `relay` is sent of `channel`: what the store holds
/// of it from where the last batch ended, in the store's order, as much
/// as one push may hold (see the module's documentation). [`sent`] is
/// told what the relay answered.
///
/// `again` says that what the relay had no room for is offered it again
/// (decision 2026-10-04 §16): the wait since it refused has gone by. It
/// goes behind what is new, where the batch has room left. Without it
/// only what is new is offered, and [`Batch::waits`] says that something
/// waits.
///
/// Nothing is written. Whoever goes on to send the batch says so once
/// the stream for it is opened ([`opened_for`]).
pub fn to_send(
    conn: &Connection,
    identity: &NodeIdentity,
    relay: &[u8; 32],
    channel: &Own,
    which: Which,
    most: Most,
    again: bool,
) -> Result<Batch, PersonError> {
    let mut batch = Batch {
        which,
        items: Vec::new(),
        entries: Vec::new(),
        waits: false,
    };
    let mut bytes = 0;
    batch_of(conn, identity, relay, channel, most, &mut batch, &mut bytes)?;
    // Only what came since has its refusals kept apart: a batch of what
    // was carried stops at one ([`sent`]).
    if which != Which::Since {
        return Ok(batch);
    }
    let refused = kept_rows::waiting_refused(conn, relay, &channel.id)?;
    let mut offered = 0;
    if again {
        for seq in &refused {
            let held = entries::channel_entries_after(conn, &channel.id, seq - 1, 1)?;
            let Some(held) = held.into_iter().find(|held| held.seq == *seq) else {
                continue;
            };
            let travels = ENTRY_WIRE_OVERHEAD_BYTES + held.entry.content.len();
            if !fits(&batch, bytes, travels, most) {
                break;
            }
            bytes += travels;
            batch.items.push(Item::Again(held.seq));
            batch.entries.push(held.entry);
            offered += 1;
        }
    }
    batch.waits = offered < refused.len();
    Ok(batch)
}

/// Whether one entry more, of `travels` bytes as it travels, goes into
/// `batch`, which holds `bytes`: by the number of its entries and by
/// their bytes. The first is sent whatever its size.
fn fits(batch: &Batch, bytes: usize, travels: usize, most: Most) -> bool {
    batch.entries.len() < most.entries
        && (batch.entries.is_empty() || bytes + travels <= most.bytes)
}

/// A stream is about to be opened to send `relay` the batch `batch` of
/// `channel`: there is leave to send it, and it goes out now.
///
/// What is written is this: that the relay is sent something of a pair
/// channel, which is kept whatever comes back. A hand-over that reached a
/// relay whose answer was lost is still written over there. It is kept
/// only for a push that was opened: a relay that was never sent a
/// hand-over is never sent the delete over it, as a channel of its own.
pub fn opened_for(
    conn: &Connection,
    relay: &[u8; 32],
    channel: &Own,
    batch: &Batch,
) -> Result<(), PersonError> {
    if channel.kind == Kind::Pair && !batch.entries.is_empty() {
        kept_rows::sending(conn, relay, &channel.id)?;
    }
    Ok(())
}

/// [`to_send`], of what the store holds from where the last batch ended:
/// it goes into `batch`, whose bytes as they travel are counted in
/// `bytes`.
fn batch_of(
    conn: &Connection,
    identity: &NodeIdentity,
    relay: &[u8; 32],
    channel: &Own,
    most: Most,
    batch: &mut Batch,
    bytes: &mut usize,
) -> Result<(), PersonError> {
    let which = batch.which;
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
    loop {
        let read = entries::channel_entries_after(conn, &channel.id, after, READ)?;
        let last = read.len() < READ as usize;
        for held in read {
            if held.seq > up_to {
                return Ok(());
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
            if !fits(batch, *bytes, travels, most) {
                return Ok(());
            }
            *bytes += travels;
            batch.items.push(Item::Sent(held.seq));
            batch.entries.push(held.entry);
        }
        if last {
            return Ok(());
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

/// Nothing of `batch` was sent to the relay: every entry in it was passed
/// over. That is kept, so that the next batch goes on after them, only
/// where the device still keeps the change entry named `under`, which is
/// the one the batch was read under (decision 2026-10-04 §16). Where it
/// keeps another, it applied a change since: the channel is one that the
/// device has left, and nothing is written of it. Returns whether it was
/// kept.
///
/// What a relay answered is taken through the one way in, which asks the
/// same before it takes anything. This write is made with nothing asked
/// of the relay, so it asks for itself.
pub fn passed_over(
    conn: &Connection,
    relay: &[u8; 32],
    channel: &Own,
    batch: &Batch,
    under: &[u8; 32],
) -> Result<bool, PersonError> {
    in_one(conn, || {
        if kept_id(conn)? != Some(*under) {
            return Ok(false);
        }
        sent(conn, relay, channel, batch, &[])?;
        Ok(true)
    })
}

/// A relay answered a batch: `answers` says what it answered for each
/// entry that was sent, in their order. How far the relay was sent the
/// channel moves on past each entry that it holds now or will not take,
/// and past what was passed over.
///
/// It moves on past an entry that the relay had no room for as well
/// (decision 2026-10-04 §16): that entry is kept apart, to be sent again
/// after a wait, and what follows it is still offered. An entry that was
/// sent again, and that the relay holds now or will not take, waits no
/// more.
///
/// Two refusals stop a batch where they are, and that entry and what
/// follows it are sent again from there. Over the allowance, the relay
/// will not begin the channel: nothing that follows makes room for it.
/// And for room, where the batch is of what was carried: what makes
/// room is something new, which is sent before it at every pass.
///
/// **So too for room, where the entry is one that the device carried
/// into the personal channel** (decision 2026-10-04 §7.3, §8): its own
/// words there, which are sent with what came since. How far a relay
/// was sent that channel is what says whether the words that were
/// carried have been sent ([`carried_waits_at`]). Moved on past a word
/// that waits, it would have the device say that it has sent what it
/// carried ([`say_sent`]) while that word waits.
///
/// An answer that does not say one thing for each entry says nothing of
/// any: nothing moves, and all of it is sent again. All of it is written
/// as one.
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
    in_one(conn, || {
        // In the personal channel, what the device carried is sent with
        // what came since: up to here in the store's order.
        let carried_words_to = match (batch.which, &channel.kind) {
            (Which::Since, Kind::Personal) => kept_rows::carried_up_to(conn)?,
            _ => 0,
        };
        let mut answers = answers.iter();
        let mut up_to = None;
        for item in &batch.items {
            let (seq, again) = match item {
                Item::Passed(seq) => {
                    up_to = Some(*seq);
                    continue;
                }
                Item::Sent(seq) => (*seq, false),
                Item::Again(seq) => (*seq, true),
            };
            match answers.next() {
                Some(Pushed::Holds | Pushed::HoldsLater) => done.held += 1,
                Some(Pushed::HoldsAnother) => {
                    done.another += 1;
                    done.another_at.push(seq);
                }
                Some(Pushed::DoesNotCheck) => done.do_not_check += 1,
                Some(Pushed::NoRoom) if batch.which == Which::Since && seq > carried_words_to => {
                    done.no_room += 1;
                    kept_rows::refused(conn, relay, &channel.id, seq)?;
                    if !again {
                        up_to = Some(seq);
                    }
                    continue;
                }
                Some(refused @ (Pushed::NoRoom | Pushed::OverAllowance)) => {
                    done.refused = Some(*refused);
                    break;
                }
                None => break,
            }
            // The relay holds it now, or will not take it.
            match again {
                true => {
                    kept_rows::not_refused(conn, relay, &channel.id, seq)?;
                }
                false => up_to = Some(seq),
            }
        }
        if let Some(up_to) = up_to {
            match batch.which {
                Which::Since => kept_rows::sent(conn, relay, &channel.id, up_to)?,
                Which::Carried => kept_rows::carried(conn, relay, &channel.id, up_to)?,
            }
        }
        Ok(done)
    })
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
    use crate::publish::{PlannedAgainst, Published, Write, publish};
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

    /// What `on` sends `relay` next of `channel`, what the relay had no
    /// room for among it.
    fn sends(on: &Machine, relay: &[u8; 32], channel: &Own, which: Which) -> Batch {
        to_send(&on.conn, &on.identity, relay, channel, which, MOST, true).unwrap()
    }

    /// Device `n` deletes `file` in `name`, over what it reads there.
    fn deleted(s: &mut Several, n: usize, name: &str, file: &str) -> CheckedEntry {
        let now = s.tick();
        let on = &s[n];
        let write = Write {
            name,
            file,
            value: Value::Delete,
            planned: PlannedAgainst::what_is_in(&on.slot(name, file)),
            merge: None,
        };
        match publish(&on.conn, &on.identity, &write, now).unwrap() {
            Published::Made(entry) => *entry,
            other => panic!("{other:?}"),
        }
    }

    /// What `on` sends `relay` next of `channel` while what the relay
    /// had no room for waits.
    fn sends_new(on: &Machine, relay: &[u8; 32], channel: &Own) -> Batch {
        to_send(
            &on.conn,
            &on.identity,
            relay,
            channel,
            Which::Since,
            MOST,
            false,
        )
        .unwrap()
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

    /// The messages channel is the last channel of a pass, after every
    /// name, and after a pair channel too (decision 2026-10-09 §2.1, C14).
    /// It is in the list only where sync is on (C12). It is proved with
    /// its own key and pulled, as the personal channel is.
    #[test]
    fn test_the_messages_channel_is_last_in_the_pass() {
        let mut s = Several::new(2);
        s.make_phrase(0);
        s.hold(&[0], "notes");
        s.hold(&[0], "a team");
        let names = [
            Kind::Personal,
            Kind::Name("a team".into()),
            Kind::Name("notes".into()),
        ];
        // Sync is off: there is no messages channel.
        assert_eq!(kinds_of(&s[0]), names);

        meta::set(&s[0].conn, meta::SYNC_CLAUDE_DIR, "/home/sam/.claude").unwrap();
        let mut with = names.to_vec();
        with.push(Kind::Messages);
        assert_eq!(kinds_of(&s[0]), with);
        let on = &s[0];
        let own = channels(&on.conn, &on.identity).unwrap();
        let messages = derive::messages_secret(&on.secret()).unwrap();
        assert_eq!(own[3].id, derive::channel_id(&messages).unwrap());
        assert!(own[3].is_pulled());
        let (session, prover) = ([0x51; 32], on.key());
        let made = own[3].proof(&session, &prover).unwrap();
        assert!(proof::check(&own[3].id, &session, &prover, &made));
        // Neither the personal channel's nor a name's.
        assert!(own[..3].iter().all(|channel| channel.id != own[3].id));

        // A name held later, and a pair channel: it is still last.
        s.hold(&[0], "z");
        s.hand(0, 1);
        let kinds = kinds_of(&s[0]);
        assert_eq!(kinds.first(), Some(&Kind::Pair));
        assert_eq!(
            kinds[kinds.len() - 2..],
            [Kind::Name("z".into()), Kind::Messages]
        );

        // Sync off again: it is gone from the pass, and an entry of the
        // device's own in it does not make it a pair channel.
        let on = &s[0];
        let name = cordelia_crypto::message::message_name(&on.key(), 1).unwrap();
        let value = Value::Other(cordelia_crypto::message::clearing_value());
        let entry = entry_by(&on.identity, &messages, 2, &name, value, &[]);
        entries::store(&on.conn, &entry, s.now).unwrap();
        assert_eq!(kinds_of(&s[0]).last(), Some(&Kind::Messages));
        meta::remove(&s[0].conn, meta::SYNC_CLAUDE_DIR).unwrap();
        let own = channels(&s[0].conn, &s[0].identity).unwrap();
        assert!(own.iter().all(|channel| channel.id != entry.channel));
        assert_eq!(own.len(), 5);
    }

    /// The kinds of the channels that a pass on `on` goes through, in
    /// their order.
    fn kinds_of(on: &Machine) -> Vec<Kind> {
        let own = channels(&on.conn, &on.identity).unwrap();
        own.iter().map(|own| own.kind.clone()).collect()
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
    /// One that it refuses for the allowance is kept, with everything
    /// after it, and sent again.
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
            to_send(
                &on.conn,
                &on.identity,
                relay,
                &notes,
                Which::Since,
                most,
                true,
            )
            .unwrap()
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
        // it must be, and is over its allowance at the third: the first
        // two are not sent again, and the third and what follows it are,
        // whatever it said of what follows.
        let done = answered(
            &RELAY,
            &batch,
            &[
                Pushed::Holds,
                Pushed::DoesNotCheck,
                Pushed::OverAllowance,
                Pushed::Holds,
            ],
        );
        assert_eq!(
            done,
            Sent {
                held: 1,
                another: 0,
                another_at: Vec::new(),
                do_not_check: 1,
                no_room: 0,
                refused: Some(Pushed::OverAllowance),
            }
        );
        let again = send(&RELAY, MOST);
        assert_eq!(ids(&again.entries), ids_of(&written[2..]));
        assert!(
            !again.waits,
            "nothing is kept apart of a batch that stopped"
        );
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
                another: 0,
                another_at: Vec::new(),
                do_not_check: 0,
                no_room: 0,
                refused: Some(Pushed::OverAllowance),
            }
        );
        assert_eq!(send(&RELAY, MOST), again);
        // Both held, one as a later one is: there is nothing more for that
        // relay.
        let done = answered(&RELAY, &again, &[Pushed::Holds, Pushed::HoldsLater]);
        assert_eq!(done.held, 2);
        assert!(send(&RELAY, MOST).is_empty());
        // An answer for a batch that was answered before moves nothing
        // back.
        answered(&RELAY, &batch, &[Pushed::Holds; 4]);
        assert!(send(&RELAY, MOST).is_empty());

        // What one relay was sent is not what another was: the other is
        // sent all of it. It says of the last that it holds another
        // entry from this device at that revision, and not this one: that
        // one is counted as that, and is sent there no more.
        let all = send(&OTHER_RELAY, MOST);
        assert_eq!(ids(&all.entries), ids_of(&written));
        let done = answered(
            &OTHER_RELAY,
            &all,
            &[
                Pushed::Holds,
                Pushed::Holds,
                Pushed::Holds,
                Pushed::HoldsAnother,
            ],
        );
        // With its place in the store's order: the store holds it there
        // until the file's next edit takes its place (§16).
        let last = entries::channel_entries_after(&s[0].conn, &notes.id, 0, 100).unwrap();
        let place_of_the_last = last.last().unwrap().seq;
        assert_eq!(
            done,
            Sent {
                held: 3,
                another: 1,
                another_at: vec![place_of_the_last],
                do_not_check: 0,
                no_room: 0,
                refused: None,
            }
        );
        assert!(entries::holds_at(&s[0].conn, &notes.id, place_of_the_last).unwrap());
        assert!(send(&OTHER_RELAY, MOST).is_empty());
        // And what is written next is sent to both.
        let next = s.write(0, "notes", "e.md", "a text");
        let on = &s[0];
        assert_eq!(sends_all(on, &RELAY, &notes, Which::Since), [next.id()]);
        assert_eq!(
            sends_all(on, &OTHER_RELAY, &notes, Which::Since),
            [next.id()]
        );
    }

    /// An entry that a relay has no room for does not hold up what
    /// follows it (decision 2026-10-04 §16): how far the relay was sent
    /// the channel goes on past it, and it is kept apart. While it
    /// waits, only what is new is offered. Once the wait has gone by it
    /// is offered again, behind what is new, and what the relay holds
    /// then waits no more. Nothing that the relay answered that it holds
    /// is sent twice.
    #[test]
    fn test_what_a_relay_had_no_room_for_waits_apart_and_what_follows_is_still_offered() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        let written: Vec<CheckedEntry> = ["a.md", "b.md", "c.md", "d.md"]
            .iter()
            .map(|file| s.write(0, "notes", file, "a text"))
            .collect();
        let answered = |s: &Several, relay: &[u8; 32], batch: &Batch, answers: &[Pushed]| {
            sent(&s[0].conn, relay, &notes_of(&s[0]), batch, answers).unwrap()
        };
        let notes = notes_of(&s[0]);
        let waiting = |s: &Several, relay: &[u8; 32]| {
            kept_rows::waiting_refused(&s[0].conn, relay, &notes.id)
                .unwrap()
                .len()
        };

        // The relay has no room for the second and the third, and holds
        // the first and the fourth: each answer is acted on, and the
        // fourth was offered although the two before it found no room.
        let batch = sends(&s[0], &RELAY, &notes, Which::Since);
        assert_eq!(ids(&batch.entries), ids_of(&written));
        let done = answered(
            &s,
            &RELAY,
            &batch,
            &[Pushed::Holds, Pushed::NoRoom, Pushed::NoRoom, Pushed::Holds],
        );
        assert_eq!(
            done,
            Sent {
                held: 2,
                another: 0,
                another_at: Vec::new(),
                do_not_check: 0,
                no_room: 2,
                refused: None,
            }
        );
        assert_eq!(waiting(&s, &RELAY), 2);
        // While the two wait, nothing is offered: nothing is new. The
        // batch says that something waits.
        let new = sends_new(&s[0], &RELAY, &notes);
        assert!(new.is_empty());
        assert!(new.waits);
        // And another relay is sent all four: what waits, waits at the
        // one relay.
        assert_eq!(waiting(&s, &OTHER_RELAY), 0);
        let other = sends_new(&s[0], &OTHER_RELAY, &notes);
        assert_eq!(ids(&other.entries), ids_of(&written));
        assert!(!other.waits);

        // What follows is still offered while they wait: a delete of the
        // first, which makes room. Only it is sent, and the first and
        // the fourth, which the relay holds, are not sent again.
        let delete = deleted(&mut s, 0, "notes", "a.md");
        let new = sends_new(&s[0], &RELAY, &notes);
        assert_eq!(ids(&new.entries), [delete.id()]);
        assert!(new.waits);
        assert_eq!(answered(&s, &RELAY, &new, &[Pushed::Holds]).held, 1);
        assert_eq!(waiting(&s, &RELAY), 2);

        // The wait has gone by: the two are offered again, behind what
        // is new, so that what makes room reaches the relay first.
        let next = s.write(0, "notes", "e.md", "a text");
        let again = sends(&s[0], &RELAY, &notes, Which::Since);
        assert_eq!(
            ids(&again.entries),
            [next.id(), written[1].id(), written[2].id()]
        );
        assert!(!again.waits);
        // Asking writes nothing.
        assert_eq!(sends(&s[0], &RELAY, &notes, Which::Since), again);
        // An answer that does not say one thing for each says nothing of
        // any: nothing moves, and nothing waits the less.
        assert_eq!(
            answered(&s, &RELAY, &again, &[Pushed::Holds; 2]),
            Sent::default()
        );
        assert_eq!(sends(&s[0], &RELAY, &notes, Which::Since), again);
        // The relay holds the new one and the first of the two now, and
        // still has no room for the second: that one goes on waiting,
        // and the others are sent no more.
        let done = answered(
            &s,
            &RELAY,
            &again,
            &[Pushed::Holds, Pushed::Holds, Pushed::NoRoom],
        );
        assert_eq!((done.held, done.no_room, done.refused), (2, 1, None));
        assert_eq!(waiting(&s, &RELAY), 1);
        let again = sends(&s[0], &RELAY, &notes, Which::Since);
        assert_eq!(ids(&again.entries), [written[2].id()]);
        assert!(sends_new(&s[0], &RELAY, &notes).is_empty());
        // As many as one push may hold: where what is new fills it, what
        // waits is not in it, and the batch says so.
        let last = s.write(0, "notes", "f.md", "a text");
        let one = Most { entries: 1, ..MOST };
        let full = to_send(
            &s[0].conn,
            &s[0].identity,
            &RELAY,
            &notes,
            Which::Since,
            one,
            true,
        )
        .unwrap();
        assert_eq!(ids(&full.entries), [last.id()]);
        assert!(full.waits);
        assert_eq!(answered(&s, &RELAY, &full, &[Pushed::Holds]).held, 1);

        // An entry that waits and is written again waits no more: the
        // new revision is new, and is sent as anything new is, once.
        let rewritten = s.write(0, "notes", "c.md", "another text");
        assert_eq!(waiting(&s, &RELAY), 0);
        let again = sends(&s[0], &RELAY, &notes, Which::Since);
        assert_eq!(ids(&again.entries), [rewritten.id()]);
        assert!(!again.waits);
        // The relay will not take it, as not signed as it must be, when
        // it is sent again after it found no room: it waits no more.
        assert_eq!(answered(&s, &RELAY, &again, &[Pushed::NoRoom]).no_room, 1);
        let again = sends(&s[0], &RELAY, &notes, Which::Since);
        assert_eq!(ids(&again.entries), [rewritten.id()]);
        let done = answered(&s, &RELAY, &again, &[Pushed::DoesNotCheck]);
        assert_eq!((done.do_not_check, done.no_room), (1, 0));
        assert_eq!(waiting(&s, &RELAY), 0);
        assert!(sends(&s[0], &RELAY, &notes, Which::Since).is_empty());

        // Over its allowance for one that waited: the batch stops there,
        // and it goes on waiting.
        let more = s.write(0, "notes", "g.md", "a text");
        let batch = sends(&s[0], &RELAY, &notes, Which::Since);
        assert_eq!(answered(&s, &RELAY, &batch, &[Pushed::NoRoom]).no_room, 1);
        let again = sends(&s[0], &RELAY, &notes, Which::Since);
        assert_eq!(ids(&again.entries), [more.id()]);
        let done = answered(&s, &RELAY, &again, &[Pushed::OverAllowance]);
        assert_eq!(done.refused, Some(Pushed::OverAllowance));
        assert_eq!(waiting(&s, &RELAY), 1);
        // A relay that holds the channel anew is sent all of it from the
        // start, once: what waited is among it, and waits apart no more.
        kept_rows::start_again(&s[0].conn, &RELAY, &notes.id).unwrap();
        let all = sends(&s[0], &RELAY, &notes, Which::Since);
        let mut unique = ids(&all.entries);
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), all.entries.len());
        assert!(ids(&all.entries).contains(&more.id()));
        assert!(!all.waits);
    }

    /// What was carried is sent in its order, and a refusal for room
    /// stops a batch of it where it is (decision 2026-10-04 §7.3, §16):
    /// nothing of it is kept apart, and that entry and what follows it
    /// are sent again from there. What makes room is something new,
    /// which is sent before what was carried at every pass.
    #[test]
    fn test_a_refusal_for_room_stops_a_batch_of_what_was_carried() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        s.write(0, "notes", "a.md", "a text");
        s.write(0, "notes", "b.md", "a text");
        s.write(0, "notes", "c.md", "a text");
        s.meet(&[0, 1]);
        s.change(0, &[0, 1], &[]);
        let on = &s[0];
        let notes = notes_of(on);
        let carried = sends(on, &RELAY, &notes, Which::Carried);
        assert_eq!(carried.entries.len(), 3);
        let done = sent(
            &on.conn,
            &RELAY,
            &notes,
            &carried,
            &[Pushed::Holds, Pushed::NoRoom, Pushed::Holds],
        )
        .unwrap();
        assert_eq!(
            done,
            Sent {
                held: 1,
                another: 0,
                another_at: Vec::new(),
                do_not_check: 0,
                no_room: 0,
                refused: Some(Pushed::NoRoom),
            }
        );
        assert!(
            kept_rows::waiting_refused(&on.conn, &RELAY, &notes.id)
                .unwrap()
                .is_empty()
        );
        let again = sends(on, &RELAY, &notes, Which::Carried);
        assert_eq!(ids(&again.entries), ids(&carried.entries[1..]));
        assert!(!again.waits);
    }

    /// A word that the device carried into the personal channel, and that
    /// a relay has no room for, stops the batch where it is (decision
    /// 2026-10-04 §7.3, §8): how far the relay was sent the channel does
    /// not move past it, nothing is kept apart, and the word and what
    /// follows it are sent again from there. So the device does not say
    /// that it has sent what it carried while a word that it carried
    /// waits. What it wrote there since the change is kept apart as in
    /// any channel, and what follows that is still offered.
    #[test]
    fn test_a_carried_word_that_a_relay_has_no_room_for_is_not_passed() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        let now = s.tick();
        crate::names::say(&s[0].conn, &s[0].identity, "notes", now).unwrap();
        s.write(0, "notes", "a.md", "a text");
        s.meet(&[0, 1]);
        s.change(0, &[0, 1], &[]);
        // What it carried into the name's channel has been sent.
        let notes = notes_of(&s[0]);
        let far = i64::MAX / 2;
        kept_rows::sent(&s[0].conn, &RELAY, &notes.id, far).unwrap();
        kept_rows::carried(&s[0].conn, &RELAY, &notes.id, far).unwrap();

        // In the new personal channel: its word that it syncs the name,
        // which it carried, and then its word that it has applied the
        // statement, which it wrote once it had carried.
        let personal = channel_of(&s[0], Kind::Personal);
        let both = sends(&s[0], &RELAY, &personal, Which::Since);
        assert_eq!(both.entries.len(), 2, "{both:?}");
        let waiting = |s: &Several| {
            kept_rows::waiting_refused(&s[0].conn, &RELAY, &personal.id)
                .unwrap()
                .len()
        };
        let waits = |s: &Several| carried_waits_at(&s[0].conn, &s[0].identity, &RELAY).unwrap();
        let says = |s: &mut Several| {
            let now = s.tick();
            say_sent(&s[0].conn, &s[0].identity, &[RELAY], now).unwrap()
        };
        let answered = |s: &Several, batch: &Batch, answers: &[Pushed]| {
            sent(&s[0].conn, &RELAY, &personal, batch, answers).unwrap()
        };
        let done = answered(&s, &both, &[Pushed::NoRoom, Pushed::Holds]);
        assert_eq!(
            done,
            Sent {
                refused: Some(Pushed::NoRoom),
                ..Sent::default()
            }
        );
        assert_eq!(waiting(&s), 0);
        assert!(waits(&s));
        assert!(!says(&mut s));
        // The word is sent again from where it is, with what follows it.
        let again = sends(&s[0], &RELAY, &personal, Which::Since);
        assert_eq!(ids(&again.entries), ids(&both.entries));
        // The relay holds it now, and has no room for the other, which
        // came since the device carried: that one is kept apart, as in
        // any channel, and passed. Nothing that was carried waits.
        let done = answered(&s, &again, &[Pushed::Holds, Pushed::NoRoom]);
        assert_eq!((done.held, done.no_room, done.refused), (1, 1, None));
        assert_eq!(waiting(&s), 1);
        assert!(sends_new(&s[0], &RELAY, &personal).is_empty());
        assert!(!waits(&s));
        assert!(says(&mut s));
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
        // That they were passed over is kept only under the change entry
        // that the batch was read under (decision 2026-10-04 §16). Under
        // another, the device has applied a change since: nothing is
        // written, and the batch is as it was.
        let kept_before = kept_rows::kept(&on.conn, &RELAY, &notes.id).unwrap();
        let under_another = [9u8; 32];
        assert!(!passed_over(&on.conn, &RELAY, &notes, &held_back, &under_another).unwrap());
        assert_eq!(
            kept_rows::kept(&on.conn, &RELAY, &notes.id).unwrap(),
            kept_before
        );
        assert_eq!(sends(on, &RELAY, &notes, Which::Carried), held_back);
        let under = kept_id(&on.conn).unwrap().unwrap();
        assert_eq!(under, on.latest().id());
        assert!(passed_over(&on.conn, &RELAY, &notes, &held_back, &under).unwrap());
        assert_ne!(
            kept_rows::kept(&on.conn, &RELAY, &notes.id).unwrap(),
            kept_before
        );
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
    /// kept from when the push is opened, whatever comes back, and not
    /// before: a push that found no leave was not sent. The delete that
    /// is written over a hand-over which has gone goes only to a relay
    /// that was sent something of the channel.
    #[test]
    fn test_a_hand_over_goes_to_every_relay_and_its_delete_only_where_it_went() {
        let mut s = Several::new(2);
        s.make_phrase(0);
        let handed = s.hand(0, 1).hand_over;
        let made = s.now;
        let on = &s[0];
        let pair = channel_of(on, Kind::Pair);
        assert_eq!(pair.id, handed.channel);

        // What is to be sent is read, for each relay. Nothing is kept of
        // that: there may be no leave to send it.
        let batch = sends(on, &RELAY, &pair, Which::Since);
        assert_eq!(ids(&batch.entries), [handed.id()]);
        let not_sent = sends(on, &OTHER_RELAY, &pair, Which::Since);
        assert_eq!(ids(&not_sent.entries), [handed.id()]);
        for relay in [&RELAY, &OTHER_RELAY] {
            assert!(!kept_rows::keeps_any(&on.conn, relay, &pair.id).unwrap());
        }
        // The push to the first relay is opened, and its answer is lost:
        // that the relay was sent it is kept all the same. The push to
        // the other was never opened.
        opened_for(&on.conn, &RELAY, &pair, &batch).unwrap();
        assert!(kept_rows::keeps_any(&on.conn, &RELAY, &pair.id).unwrap());
        assert!(!kept_rows::keeps_any(&on.conn, &OTHER_RELAY, &pair.id).unwrap());
        // A push of nothing, and one of a channel of the device's own,
        // keep nothing.
        let personal = channel_of(on, Kind::Personal);
        let own = sends(on, &OTHER_RELAY, &personal, Which::Since);
        assert!(!own.entries.is_empty());
        opened_for(&on.conn, &OTHER_RELAY, &personal, &own).unwrap();
        assert!(!kept_rows::keeps_any(&on.conn, &OTHER_RELAY, &personal.id).unwrap());
        let nothing = sends(on, &OTHER_RELAY, &pair, Which::Carried);
        opened_for(&on.conn, &OTHER_RELAY, &pair, &nothing).unwrap();
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
        // The other relay was sent nothing of the channel, though what
        // would have gone to it was read: it is not sent the delete, and
        // nothing is kept of that.
        assert!(sends(on, &OTHER_RELAY, &pair, Which::Since).is_empty());
        assert!(!kept_rows::keeps_any(&on.conn, &OTHER_RELAY, &pair.id).unwrap());
    }

    /// What is kept of a pair channel at the relays is forgotten once
    /// the delete over its hand-over went to every relay that was sent
    /// anything of it, and not before. The delete stays in the store,
    /// and goes to no relay after that. What is kept of a relay that the
    /// device is no longer set up with is forgotten where every relay it
    /// is set up with is known, and holds up nothing.
    #[test]
    fn test_what_is_kept_of_a_pair_channel_is_forgotten_once_its_delete_went_everywhere() {
        const THIRD_RELAY: [u8; 32] = [0xa3; 32];
        let mut s = Several::new(2);
        s.make_phrase(0);
        let handed = s.hand(0, 1).hand_over;
        let made = s.now;
        let on = &s[0];
        let pair = channel_of(on, Kind::Pair);
        let forget = |set_up: Option<&[[u8; 32]]>| {
            forget_what_is_done(&on.conn, &on.identity, set_up).unwrap()
        };
        let none = Forgotten::default();
        // The hand-over goes to two relays, which hold it. While the
        // store holds the hand-over, nothing is forgotten, though each
        // relay was sent everything of the channel.
        for relay in [&RELAY, &OTHER_RELAY] {
            let batch = sends(on, relay, &pair, Which::Since);
            opened_for(&on.conn, relay, &pair, &batch).unwrap();
            assert_eq!(sends_all(on, relay, &pair, Which::Since), [handed.id()]);
        }
        assert_eq!(forget(None), none);
        assert_eq!(forget(Some(&[RELAY, OTHER_RELAY])), none);
        assert!(kept_rows::keeps_any(&on.conn, &RELAY, &pair.id).unwrap());
        // A push to a third is opened, and never answered.
        let batch = sends(on, &THIRD_RELAY, &pair, Which::Since);
        opened_for(&on.conn, &THIRD_RELAY, &pair, &batch).unwrap();
        let later = made + 2 * 60 * 60;
        drop_old_hand_overs(&on.conn, later).unwrap();
        // Nor while it holds nothing of the channel: the delete is not
        // written yet.
        assert_eq!(forget(None), none);
        assert_eq!(
            write_over_dropped(&on.conn, &on.identity, later).unwrap(),
            1
        );
        let over = on.stored_in(&derive::pair_secret(&on.identity, &s.key(1)).unwrap());
        assert!(over[0].delete);
        // Nor while the delete waits for any relay that was sent
        // anything: for all three, then for two, then for the one whose
        // answer to the hand-over was lost.
        assert_eq!(forget(None), none);
        assert_eq!(sends_all(on, &RELAY, &pair, Which::Since), [over[0].id()]);
        assert_eq!(forget(None), none);
        assert_eq!(
            sends_all(on, &OTHER_RELAY, &pair, Which::Since),
            [over[0].id()]
        );
        assert_eq!(forget(None), none);
        assert_eq!(forget(Some(&[RELAY, OTHER_RELAY, THIRD_RELAY])), none);
        assert!(kept_rows::keeps_any(&on.conn, &RELAY, &pair.id).unwrap());
        // The personal channel is kept for the third relay too.
        let personal = channel_of(on, Kind::Personal);
        sends_all(on, &THIRD_RELAY, &personal, Which::Since);
        sends_all(on, &RELAY, &personal, Which::Since);

        // The device is set up with the third relay no longer: what was
        // kept of it goes, for every channel, and the delete has then
        // gone everywhere it was to go. What is kept of the pair channel
        // goes with it, at once.
        assert_eq!(
            forget(Some(&[RELAY, OTHER_RELAY])),
            Forgotten {
                relays: 1,
                pairs: 1
            }
        );
        for relay in [&RELAY, &OTHER_RELAY, &THIRD_RELAY] {
            assert!(!kept_rows::keeps_any(&on.conn, relay, &pair.id).unwrap());
        }
        assert!(!kept_rows::keeps_any(&on.conn, &THIRD_RELAY, &personal.id).unwrap());
        assert!(kept_rows::keeps_any(&on.conn, &RELAY, &personal.id).unwrap());
        assert_eq!(forget(Some(&[RELAY, OTHER_RELAY])), none);
        // The delete stays in the store, is written no second time, and
        // goes to no relay: nothing is kept of the channel again.
        assert_eq!(
            on.stored_in(&derive::pair_secret(&on.identity, &s.key(1)).unwrap()),
            over
        );
        assert_eq!(
            write_over_dropped(&on.conn, &on.identity, later + 1).unwrap(),
            0
        );
        for relay in [&RELAY, &OTHER_RELAY, &THIRD_RELAY] {
            assert!(sends(on, relay, &pair, Which::Since).is_empty());
            assert!(!kept_rows::keeps_any(&on.conn, relay, &pair.id).unwrap());
        }
        // A channel of the device's own is never forgotten so: what the
        // relays were sent of the personal channel is kept.
        assert!(sends(on, &RELAY, &personal, Which::Since).is_empty());
        // Nor is the channel of a name of which the store holds one
        // entry, a delete of this device's, that went everywhere.
        s.hold(&[0], "notes");
        s.write(0, "notes", "a.md", "a text");
        let delete = deleted(&mut s, 0, "notes", "a.md");
        let on = &s[0];
        let notes = notes_of(on);
        assert_eq!(
            on.stored_in(&on.own("notes")),
            std::slice::from_ref(&delete)
        );
        for relay in [&RELAY, &OTHER_RELAY] {
            assert_eq!(sends_all(on, relay, &notes, Which::Since), [delete.id()]);
        }
        let forgotten = forget_what_is_done(&on.conn, &on.identity, Some(&[RELAY, OTHER_RELAY]));
        assert_eq!(forgotten.unwrap(), Forgotten::default());
        assert!(kept_rows::keeps_any(&on.conn, &RELAY, &notes.id).unwrap());
        assert!(sends(on, &RELAY, &notes, Which::Since).is_empty());
    }
}
