//! Recovery (decision 2026-10-04 §9): a person who has no device left
//! that they trust types their recovery phrase on a new machine.
//!
//! The command that is typed the phrase does the part that needs it, in
//! its own process, and the node does the rest. Nothing here reads a
//! phrase.
//!
//! ## What the command reads, in its own process
//!
//! The phrase proves the key of the phrase's own channel, which no
//! device can. The command has the node pull that channel at every relay
//! (the node is handed proofs, and no secret), and reads each change
//! entry that came back with the phrase.
//!
//! - [`found`] takes **the change entry with the highest number,** of
//!   those whose signatures hold and whose secret opens to its
//!   statement's commitment. **Any other that is not on that one's chain
//!   is a fork,** whatever its number: the command shows both lists, and
//!   the statement it makes settles them.
//! - [`read_generation`] reads the personal channel of the generation
//!   that is recovered from, as a device that had applied its statement
//!   reads it. **Every device of the statement is shown, always, and
//!   first;** after them the keys added since that count, each under the
//!   device that added it; and after those the records that do not count,
//!   **up to 256 rows in all**, each with how much its key signed there.
//!   One key has one row. No device can push a device of the statement
//!   out of the rows by what it signs. **It counts the keys that a
//!   record of an addition was read for and that have no row at all:** a
//!   reader keeps 256 records that do not count, and where more were
//!   written, one that was read is not among them. **And it says of each
//!   row whether a record that was read for its key is not among those
//!   kept:** the row is then by another record, and may say less of the
//!   key than was written. It also reads the names that those devices
//!   list, and whether the device it recovers from had written that it
//!   sent what it carried.
//! - A person says one of three things of each row that counts
//!   ([`Answer`]). **A record that does not count is shown as that and is
//!   not asked about:** it is no device, nothing is taken from it, and it
//!   is not made a removed key. **One that fails only for the bound of 64
//!   counted devices is asked about all the same** ([`asked_for_room`]),
//!   where a key that added it may add (a device of the statement, or a
//!   key that counts and that such a device added) and is not in someone
//!   else's hands, by what was said of it and of the device that added
//!   it: filling the 64 alone pushes no device out of what is asked.
//!   Nothing is taken from it either way; said to be gone, its key is
//!   removed. [`takes`] is then the keys that the look takes from: a key
//!   that counts, and that the person still has or that is lost or
//!   broken. **Nothing is taken from a device that may
//!   be in someone else's hands, nor from a key that it added, nor from a
//!   key that such a key added.** [`room`] says, before anything is
//!   asked, whether the answers could all be kept: a statement has room
//!   for 256 removed keys.
//! - [`names_in_order`] is the names that are carried, **at most 1,024,**
//!   in the order that §9 gives: those of the generation recovered from
//!   that a device the person still has lists, then those that a device
//!   which is lost or broken lists, then those of the generations before
//!   ([`names_before`]), the newest first.
//!
//! ## What the node does
//!
//! [`make`] is handed the change entry that the command made, the
//! phrase's statement key, the secrets of the generations before (which
//! the machine keeps, as a device keeps a secret it left: §3, §9), and a
//! word that the phrase signed for the look ([`crate::carry::Allows::Look`]).
//! It applies the statement, lists the names in its new personal channel,
//! and wakes the node: **the change entry is shown to every relay at
//! once, before anything is carried,** and the names go straight after
//! it.
//!
//! **The look is then made once** ([`the_look`]): each name's channel is
//! read at every relay, in the generation recovered from and in those
//! before it, and what the keys of the word signed there is brought in
//! through the one function that judges a version for a carry
//! ([`crate::carry::bring`]). A look that is interrupted is not taken up
//! again by itself. What it found is kept in memory for the command to
//! read ([`progress`]): which relays and names it could not read, and,
//! for each removed key, how much that key signed there that the new
//! channels lack.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use cordelia_core::protocol::{
    CARRY_READ_MAX_SECS, MAX_STATEMENT_REMOVED, PERSONAL_NAME_PREFIX, RECOVERY_MAX_DEVICES_SHOWN,
    RECOVERY_MAX_NAMES,
};
use cordelia_core::revision::band;
use cordelia_crypto::addition::SignedAddition;
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Entry, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::statement::{SignedStatement, Statement};
use cordelia_storage::acts;
use cordelia_storage::at_relays as kept_rows;
use cordelia_storage::meta;
use cordelia_storage::person::{self as held_rows, Following, Kept, Person, State};

use crate::carry::{self, Allows, Rule, Tally, Word};
use crate::carrying;
use crate::commands;
use crate::error::ApiError;
use crate::names;
use crate::person::{self, NotCounted, PersonError, in_one};
use crate::state::{AppState, AtRelays};
use crate::take::{self, Record, Taken};

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn db(state: &AppState) -> std::sync::MutexGuard<'_, rusqlite::Connection> {
    state.db.lock().unwrap_or_else(|e| e.into_inner())
}

// ── What the command reads, in its own process ───────────────────────

/// A change entry that a relay handed of the phrase's channel, as the
/// command read it with the phrase: its signatures hold, and its secret
/// opens to its statement's commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub entry: CheckedEntry,
    pub statement: SignedStatement,
}

/// What a recovery found in the phrase's channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The change entry with the highest number.
    pub from: Candidate,
    /// Each other that is not on that one's chain, the highest number
    /// first: with any of these, the changes were made apart.
    pub apart: Vec<Candidate>,
}

impl Found {
    /// The change that was made apart from [`Self::from`] and that a
    /// recovery settles with it, where there is one: the first of those
    /// that are apart. With how many of the others are **on the chain of
    /// neither of the two** (decision 2026-10-04 §9, step 2): one that
    /// is on the second's chain is behind that one, and is nothing, as
    /// one on the first's chain is. Those on neither's chain are not
    /// settled by the recovery.
    pub fn second(&self) -> Option<(&Candidate, usize)> {
        let (second, others) = self.apart.split_first()?;
        let behind = |other: &&Candidate| {
            let link = other.statement.statement.link();
            link.is_ok_and(|link| second.statement.statement.has_on_chain(&link))
        };
        let on_neither = others.len() - others.iter().filter(behind).count();
        Some((second, on_neither))
    }
}

/// Of the change entries that the relays handed, the one to recover from
/// (decision 2026-10-04 §9, step 2): the one with the highest number.
/// **Any other that is not on that one's chain is a fork, whatever its
/// number:** two relays can hold two. One that is on its chain is behind
/// it, and is nothing.
///
/// Of two at one number, the one whose statement has the greater hash is
/// first: every machine that is handed the two says the same. `None`
/// where none was handed.
pub fn found(mut candidates: Vec<Candidate>) -> Option<Found> {
    let rank = |candidate: &Candidate| {
        let statement = &candidate.statement.statement;
        (
            statement.number,
            statement.link().map(|link| link.hash).ok(),
        )
    };
    candidates.sort_by_key(|candidate| std::cmp::Reverse(rank(candidate)));
    candidates.dedup_by(|a, b| rank(a) == rank(b));
    let mut all = candidates.into_iter();
    let from = all.next()?;
    let apart = all
        .filter(|other| {
            let link = other.statement.statement.link();
            !link.is_ok_and(|link| from.statement.statement.has_on_chain(&link))
        })
        .collect();
    Some(Found { from, apart })
}

/// One of the three things that a person says of a device at a recovery
/// (decision 2026-10-04 §9, step 3), or that nothing was asked of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Nothing was asked: the row is a record that does not count. It is
    /// no device: nothing is taken from it, its key is not removed, and
    /// it is not one that the person still has.
    NotAsked,
    /// The person still has it: it is in no list, and is added again by
    /// hand.
    Have,
    /// It is lost or broken: its key is removed, and what it wrote is
    /// taken.
    Lost,
    /// It may be in someone else's hands: its key is removed, and nothing
    /// that it wrote is taken.
    OtherHands,
}

/// A device that a recovery shows, of the generation it recovers from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub key: [u8; 32],
    /// The label of the statement, or the one its adder gave it.
    pub label: String,
    /// The key that added it since the statement, and when its record
    /// says so: `None` for a device of the statement.
    pub added_by: Option<([u8; 32], u64)>,
    /// Whether it counts under the statement: a device of the statement,
    /// or a key that a record which counts adds.
    pub counts: bool,
    /// How many entries it signed in the personal channel, as the relays
    /// handed it.
    pub signed: usize,
    /// The keys that signed a record of it which fails for one thing
    /// only, that 64 devices counted already (decision 2026-10-04 §9,
    /// step 3): each with when its record says so, in order of key. Each
    /// of them may add: it is a device of the statement, or a key that
    /// counts and that such a device added. None for a row that counts,
    /// and none for a record that does not count for another reason.
    /// Such a key is asked about all the same, where one of these is not
    /// in someone else's hands ([`asked_for_room`]).
    pub no_room: Vec<([u8; 32], u64)>,
    /// Whether a record of an addition that was read for this key, under
    /// some adder, is not among the records that the reader kept
    /// (decision 2026-10-04 §9, step 3): a reader keeps 256 records that
    /// do not count, the oldest it saw going first. The row is then by
    /// another record of the key, and may say less of it than was
    /// written: the record that went may be the one that fails only for
    /// the bound of 64, under an adder that may add, by which the key
    /// would have been asked about. Never so for a key that the statement
    /// removes: it stays removed whatever a record says of it.
    pub record_let_go: bool,
}

/// What a recovery reads of the generation that it recovers from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Generation {
    /// Every device of the statement, in its order; then the keys added
    /// since that count, under the device that added each, and under
    /// each of those the keys that it added; then the records that do
    /// not count, those that fail only for the bound of 64 counted
    /// devices first. One row for a key, and no more than 256 in all.
    pub rows: Vec<Row>,
    /// The rows that could not be shown beyond those: the look takes
    /// nothing from them, and the new machine keeps their keys as left
    /// out.
    pub not_shown: Vec<Row>,
    /// How many keys a record of an addition was read for that have no
    /// row at all, shown or not (decision 2026-10-04 §9, step 3). A
    /// reader keeps 256 records that do not count, the oldest it saw
    /// going first: where more were written, one that was read is not
    /// among those it kept. A device that was added since the change,
    /// and that the bound of 64 kept out, may be among them. Nothing is
    /// asked of such a key, nothing is taken from it, and the reader
    /// does not hold it: the command says how many there are. Keys are
    /// counted, and not records, and no key in either list of the
    /// statement is among them.
    pub no_row: usize,
    /// Each name that the personal channel lists, with the keys that
    /// count and list it. A name that only keys list which do not count
    /// is here too, with no key: nothing is taken for it, and it is
    /// named among the names that are left.
    pub names: Vec<(String, Vec<[u8; 32]>)>,
    /// The one device of the statement, where the statement lists one
    /// alone and was made after another, and that device's word that it
    /// had sent what it carried is not among what was handed: a
    /// recovery, or a change, that was made on it was cut short, unless
    /// the word is in what was not read, or no relay holds the channel.
    /// (Whoever had the channel read knows how it was read at each
    /// relay, and says which it is.)
    pub cut_short: Option<[u8; 32]>,
}

/// How often the entries of a personal channel are given again, at most,
/// so that what a key signed before its record was read is taken: a
/// chain of additions is two long.
const GIVEN_AGAIN: usize = 4;

/// Read the personal channel of the generation that is recovered from
/// (decision 2026-10-04 §9, step 3), in the command's own process.
/// `from` is the change entry that was found, `statement_key` the
/// phrase's statement key, `secret` the person secret of that generation
/// (which the phrase opened), and `handed` what the relays handed of its
/// personal channel.
///
/// **It is read as a device that had applied that statement reads it,**
/// with the same functions, over a database of its own in memory: an
/// entry is taken only where its signer counts, a record of an addition
/// counts by the one rule for that, and a name is listed by a key that
/// counts. The entries are given in an order that no device chooses by
/// when it signs: by the place of their signer in the statement, and
/// then by key.
pub fn read_generation(
    from: &Candidate,
    statement_key: &[u8; 32],
    secret: &[u8; 32],
    handed: &[CheckedEntry],
    now: i64,
) -> Result<Generation, PersonError> {
    let statement = &from.statement.statement;
    if !statement.commits_to(secret) {
        return Err(PersonError::SecretNotCommitted);
    }
    let conn = cordelia_storage::db::open_in_memory()
        .map_err(|e| PersonError::Held(format!("a database in memory: {e}")))?;
    held_rows::put_person(
        &conn,
        &Person {
            state: State::Applied,
            following: Following {
                phrase_key: from.entry.author,
                statement_key: *statement_key,
                phrase_channel: from.entry.channel,
            },
            statement: from.statement.to_bytes()?,
        },
    )?;
    held_rows::apply_secret(&conn, statement.number, secret, now)?;
    held_rows::keep_change_entry(&conn, Kept::Latest, &from.entry)?;
    // Whoever reads is in no list: it only reads.
    let reader = NodeIdentity::generate()?;

    let personal = Zeroizing::new(derive::personal_secret(secret)?);
    let channel = derive::channel_id(&personal)?;
    let place = |key: &[u8; 32]| {
        let listed = statement.devices.iter().position(|one| one.key == *key);
        listed.unwrap_or(usize::MAX)
    };
    let mut of_it: Vec<&CheckedEntry> = Vec::new();
    for entry in handed.iter().filter(|entry| entry.channel == channel) {
        if !of_it.iter().any(|held| held.id() == entry.id()) {
            of_it.push(entry);
        }
    }
    // The records of additions that were read: of each entry that the
    // one door took as such a record, at any giving, the key that it
    // adds and the key that signed it. Its signer counted, and the
    // record is its signer's own word, verifies, and is made under this
    // statement.
    let mut read_for: BTreeSet<([u8; 32], [u8; 32])> = BTreeSet::new();
    of_it.sort_by_key(|entry| (place(&entry.author), entry.author, entry.slot, entry.rev));
    for _ in 0..GIVEN_AGAIN {
        let mut again = false;
        for entry in &of_it {
            if let Taken::Own {
                record,
                came_to_count,
                came_to_add,
                ..
            } = take::take(&conn, &reader, entry, now)?
            {
                again |= came_to_count + came_to_add > 0;
                if let Some(Record::Seen(_)) = record {
                    read_for.extend(added_by(entry, &personal));
                }
            }
        }
        if !again {
            break;
        }
    }

    let counting = person::who_counts(&conn)?;
    let mut signed: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    for entry in &of_it {
        *signed.entry(entry.author).or_default() += 1;
    }
    let kept = held_rows::additions(&conn)?;
    // The keys one of whose records was read, under some adder, and is
    // not among the records kept: the reader let go of it. A key that
    // the statement removes stays removed whatever a record says of it,
    // and is not among them.
    let is_kept = |key: &[u8; 32], adder: &[u8; 32]| {
        let records = kept.iter();
        records
            .filter(|record| record.key == *key)
            .any(|record| record.adder == *adder)
    };
    let let_go: BTreeSet<[u8; 32]> = read_for
        .iter()
        .filter(|(key, adder)| !is_kept(key, adder) && !statement.removes(key))
        .map(|(key, _)| *key)
        .collect();
    // The records that fail only for the bound of 64 counted devices:
    // for each key, the keys that signed one, each with when its record
    // says so. (A key that counts has none: its other records fail
    // because it counts already.)
    let mut no_room: BTreeMap<[u8; 32], Vec<([u8; 32], u64)>> = BTreeMap::new();
    // One key has one row. A key counts by one record: that one is shown
    // for it. Where none counts, one that fails only for the bound is
    // shown before another, and of those the one whose adder has the
    // lowest key.
    let mut records: Vec<(Row, [u8; 32])> = Vec::new();
    for record in &kept {
        let read = SignedAddition::from_bytes(&record.record)?.addition;
        // The one rule says that a record fails for the bound only
        // where nothing else keeps it out ([`Counting::why_not`]): its
        // key is not removed and does not count, and **its adder may
        // add,** being a device of the statement, or a key that counts
        // and that such a device added. Whoever the adder is, of those.
        let only_for_room = !record.counted
            && counting.why_not(&record.key, &record.adder) == Some(NotCounted::NoRoom);
        if only_for_room {
            let by = no_room.entry(record.key).or_default();
            by.push((record.adder, read.at));
        }
        let row = Row {
            key: record.key,
            label: read.device.label,
            added_by: Some((record.adder, read.at)),
            counts: record.counted && counting.counts(&record.key),
            signed: signed.get(&record.key).copied().unwrap_or(0),
            no_room: Vec::new(),
            record_let_go: let_go.contains(&record.key),
        };
        records.push((row, record.adder));
    }
    let for_room = |key: &[u8; 32], adder: &[u8; 32]| {
        let by = no_room.get(key);
        by.is_some_and(|by| by.iter().any(|(signed, _)| signed == adder))
    };
    records.sort_by_key(|(row, adder)| {
        let for_room = for_room(&row.key, adder);
        (row.key, !row.counts, !for_room, *adder)
    });
    records.dedup_by(|a, b| a.0.key == b.0.key);
    records.retain(|(row, _)| !statement.lists(&row.key));
    for (row, _) in &mut records {
        if let Some(mut by) = no_room.remove(&row.key) {
            by.sort_unstable();
            by.dedup_by_key(|(adder, _)| *adder);
            row.no_room = by;
        }
    }
    let (mut counted, not_counted): (Vec<_>, Vec<_>) =
        records.into_iter().partition(|(row, _)| row.counts);

    // Every device of the statement, always, and first: there are at
    // most 64, and no device can push another out of the rows by what it
    // signs (§9, step 3).
    let mut rows: Vec<Row> = Vec::new();
    for device in &statement.devices {
        rows.push(Row {
            key: device.key,
            label: device.label.clone(),
            added_by: None,
            counts: counting.counts(&device.key),
            signed: signed.get(&device.key).copied().unwrap_or(0),
            no_room: Vec::new(),
            record_let_go: let_go.contains(&device.key),
        });
    }
    // Then the keys added since that count, each under the device that
    // added it, and under each of those the keys that it added.
    let under = |adder: &[u8; 32], records: &mut Vec<(Row, [u8; 32])>| -> Vec<Row> {
        let (added, rest): (Vec<_>, Vec<_>) = std::mem::take(records)
            .into_iter()
            .partition(|(_, by)| by == adder);
        *records = rest;
        added.into_iter().map(|(row, _)| row).collect()
    };
    for device in &statement.devices {
        for added in under(&device.key, &mut counted) {
            let key = added.key;
            rows.push(added);
            rows.extend(under(&key, &mut counted));
        }
    }
    rows.extend(counted.into_iter().map(|(row, _)| row));
    // And then the records that do not count, in order of key: those
    // that fail only for the bound of 64 counted devices first, since
    // each of them may be asked about.
    let (only_for_room, others): (Vec<_>, Vec<_>) = not_counted
        .into_iter()
        .partition(|(row, _)| !row.no_room.is_empty());
    rows.extend(only_for_room.into_iter().map(|(row, _)| row));
    rows.extend(others.into_iter().map(|(row, _)| row));
    let not_shown = rows.split_off(RECOVERY_MAX_DEVICES_SHOWN.min(rows.len()));
    // The keys that a record was read for and that have no row, shown
    // or not: the reader kept 256 records that do not count, and let go
    // of the oldest beyond that. A key that the statement removes stays
    // removed whatever a record says of it, and is not counted. (A
    // device of the statement always has a row.)
    let has_a_row = |key: &[u8; 32]| rows.iter().chain(&not_shown).any(|row| row.key == *key);
    let read_keys: BTreeSet<[u8; 32]> = read_for.iter().map(|(key, _)| *key).collect();
    let no_row = read_keys
        .iter()
        .filter(|key| !has_a_row(key) && !statement.removes(key))
        .count();

    let mut names: Vec<(String, Vec<[u8; 32]>)> = names::listed(&conn)?
        .into_iter()
        .map(|listed| (listed.name, listed.by))
        .collect();
    // A name that only keys list which do not count (§9): their words
    // are in what the relays handed, and in no store, since nothing that
    // such a key signed is taken. It is read from there, as the names of
    // a generation before are, and listed by no key: the look leaves it,
    // and the person is told that it did.
    let of_no_count = |key: &[u8; 32]| !counting.counts(key);
    for name in names_before(handed, secret, statement.number, of_no_count)? {
        if !names.iter().any(|(listed, _)| *listed == name) {
            names.push((name, Vec::new()));
        }
    }

    // Whether the one device of a statement that was made after another
    // wrote that it had sent what it carried (§8).
    let mut cut_short = None;
    if statement.devices.len() == 1 && statement.number > 1 {
        let seen = crate::look::look(&conn, &reader, &AtRelays::default(), now)?;
        let said_sent = seen
            .devices
            .first()
            .is_some_and(|device| device.applied == Some(statement.number) && device.sent);
        if !said_sent {
            cut_short = Some(statement.devices[0].key);
        }
    }
    Ok(Generation {
        rows,
        not_shown,
        no_row,
        names,
        cut_short,
    })
}

/// The key that `entry` holds a record of an addition for, and the key
/// that signed that record (decision 2026-10-04 §6), where it is an
/// entry of the personal channel whose secret is `personal`. `None`
/// where it holds none. It checks nothing: it is asked of an entry that
/// the one door took as a record.
fn added_by(entry: &CheckedEntry, personal: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
    let inside = entry.open(personal).ok()?;
    let Value::Other(bytes) = &inside.value else {
        return None;
    };
    let added = SignedAddition::from_bytes(bytes).ok()?.addition;
    Some((added.device.key, added.adder))
}

/// Whether nothing is taken from the device of the row at `at` because
/// of whose hands it may be in (decision 2026-10-04 §9, step 3): a
/// person said so of it, or of the device that added it, or of the
/// device that added that one.
pub fn in_other_hands(rows: &[Row], answers: &[Answer], at: usize) -> bool {
    let said_of = |key: &[u8; 32]| {
        let place = rows.iter().position(|row| row.key == *key)?;
        Some((answers.get(place).copied()?, rows[place].added_by))
    };
    let mut key = rows[at].key;
    // A chain of additions is two long: the device, its adder, and the
    // adder of that.
    for _ in 0..3 {
        match said_of(&key) {
            Some((Answer::OtherHands, _)) => return true,
            Some((_, Some((adder, _)))) => key = adder,
            _ => return false,
        }
    }
    false
}

/// The keys that the look of a recovery takes from (decision 2026-10-04
/// §9, steps 3 and 5): each device that was shown, that counts under the
/// statement recovered from, and of which the person said that they
/// still have it or that it is lost or broken. **Nothing is taken from a
/// device that may be in someone else's hands, nor from a key that it
/// added, nor from a key that such a key added** ([`in_other_hands`]). A
/// row that has no answer is not taken from, and nor is a record that
/// does not count, whatever is said of it.
pub fn takes(rows: &[Row], answers: &[Answer]) -> Vec<[u8; 32]> {
    rows.iter()
        .enumerate()
        .filter(|(at, row)| {
            let said = matches!(answers.get(*at), Some(Answer::Have | Answer::Lost));
            row.counts && said && !in_other_hands(rows, answers, *at)
        })
        .map(|(_, row)| row.key)
        .collect()
}

/// The key for whose record the row at `at` is asked about though it
/// does not count (decision 2026-10-04 §9, step 3), with when that
/// record says it was added: the row's key fails only for the bound of
/// 64 counted devices ([`Row::no_room`]), and this key signed a record of
/// it, **was said to be one that the person still has, or that is lost
/// or broken, and is not in someone else's hands** ([`in_other_hands`]
/// of its own row: by what was said of it, of the device that added it,
/// and of the device that added that one). The first such, in order of
/// key.
///
/// `answers` are those given so far. A key that signed such a record may
/// add, so it counts: its row comes before every row that does not
/// count, and it was asked about, with the device that added it, before
/// this row is reached.
///
/// `None` for a row that counts, which is asked about as that; for a
/// record that does not count for another reason; and where each key
/// that signed such a record may be in someone else's hands, or has no
/// answer: what such a key added is not asked about, and nothing is
/// taken from it.
///
/// **So filling the 64 alone pushes no device out of what is asked.**
/// A device that is listed can sign additions until 64 count, and a
/// device that another added since then finds no room. It is asked about
/// all the same. Nothing is taken from it by the look, whatever is said:
/// said to be gone, its key is removed ([`gone`]), and what it wrote
/// comes in by the command that names a removed key, with the phrase.
///
/// **The two bounds of 256 can be reached by what one device signs:** a
/// reader keeps 256 records that do not count, and 256 rows are shown.
/// What they leave out is counted and said: the rows beyond those shown
/// ([`Generation::not_shown`]), and the keys whose record was read and
/// that have no row at all ([`Generation::no_row`]).
pub fn asked_for_room(rows: &[Row], answers: &[Answer], at: usize) -> Option<([u8; 32], u64)> {
    let row = rows.get(at).filter(|row| !row.counts)?;
    let not_in_other_hands = |(adder, _): &&([u8; 32], u64)| {
        let Some(place) = rows.iter().position(|row| row.key == *adder) else {
            return false;
        };
        let said = matches!(answers.get(place), Some(Answer::Have | Answer::Lost));
        said && !in_other_hands(rows, answers, place)
    };
    row.no_room.iter().find(not_in_other_hands).copied()
}

/// The keys that the statement of a recovery removes (decision
/// 2026-10-04 §9, step 4): each device of which the person said that it
/// is gone, lost or broken or in someone else's hands. A device that
/// they still have is in neither list. **A record that does not count is
/// not made a removed key,** whatever is said of it: it is no device, a
/// device that counts can sign hundreds, and each removal is one of the
/// 256 that a phrase has. **One that was asked about for the bound of 64
/// alone is** ([`asked_for_room`]): it is then a removed key, and what
/// it wrote can be brought in by the command that names one.
pub fn gone(rows: &[Row], answers: &[Answer]) -> Vec<[u8; 32]> {
    rows.iter()
        .zip(answers)
        .enumerate()
        .filter(|(at, (row, answer))| {
            let asked = row.counts || asked_for_room(rows, answers, *at).is_some();
            asked && matches!(answer, Answer::Lost | Answer::OtherHands)
        })
        .map(|(_, (row, _))| row.key)
        .collect()
}

/// Whether the answers of a recovery could all be kept (decision
/// 2026-10-04 §9, step 3): a statement has room for 256 removed keys, and
/// it lists every key removed so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Room {
    /// How many keys are removed already: by the statement recovered
    /// from, and by one made apart from it, which the recovery settles.
    pub removed: usize,
    /// How many rows are asked about, at most: each device that counts,
    /// but the machine itself, and each key that fails only for the
    /// bound of 64 counted devices. (Whether one of those is asked about
    /// turns on what is said of the device that added it, which is not
    /// known before the first question.)
    pub asked: usize,
    /// How many of those can be said to be gone, at most.
    pub can_go: usize,
}

impl Room {
    /// Whether every row that is asked about could be said to be gone.
    pub fn for_every_answer(&self) -> bool {
        self.asked <= self.can_go
    }
}

/// What room the statement of a recovery has for the keys that the
/// person may say are gone ([`Room`]), worked out before anything is
/// asked. `from` is the statement recovered from, `apart` one that was
/// made apart from it, `rows` the rows that are shown, and `own` the key
/// of the machine that recovers.
pub fn room(from: &Statement, apart: Option<&Statement>, rows: &[Row], own: &[u8; 32]) -> Room {
    let mut removed: BTreeSet<[u8; 32]> = from.removed.iter().copied().collect();
    removed.extend(apart.iter().flat_map(|apart| apart.removed.iter().copied()));
    let asked = rows
        .iter()
        .filter(|row| row.counts || !row.no_room.is_empty())
        .filter(|row| row.key != *own && !removed.contains(&row.key))
        .count();
    Room {
        removed: removed.len(),
        asked,
        can_go: MAX_STATEMENT_REMOVED.saturating_sub(removed.len()),
    }
}

/// The names that a recovery carries, and those it leaves.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Names {
    /// The names that are carried, in their order: no more than the
    /// bound.
    pub carried: Vec<String>,
    /// The names that are left because the bound was reached.
    pub over_the_bound: Vec<String>,
    /// The names of the generation recovered from that only a device
    /// lists from which nothing is taken: one that may be in someone
    /// else's hands, and a key that does not count.
    pub only_other_hands: Vec<String>,
}

/// The names that a recovery carries, in their order, and no more than
/// `max` (decision 2026-10-04 §9, "It listed the names"): the names of
/// the generation recovered from that a device the person still has
/// lists; then those that a device which is lost or broken lists; then
/// the names of the generations before, the newest first, as `before`
/// gives them. Each name once, at its first place.
///
/// **A name that only a device lists from which nothing is taken is not
/// carried,** and is named apart. The names beyond the bound are named
/// too.
pub fn names_in_order(
    generation: &Generation,
    answers: &[Answer],
    before: &[Vec<String>],
    max: usize,
) -> Names {
    let taken = takes(&generation.rows, answers);
    let said = |key: &[u8; 32]| {
        let place = generation.rows.iter().position(|row| row.key == *key)?;
        taken.contains(key).then(|| answers[place])
    };
    let listed_by = |answer: Answer| {
        let names = generation.names.iter();
        names
            .filter(move |(_, by)| by.iter().any(|key| said(key) == Some(answer)))
            .map(|(name, _)| name.clone())
    };
    let mut ordered: Vec<String> = Vec::new();
    let in_turn = listed_by(Answer::Have)
        .chain(listed_by(Answer::Lost))
        .chain(before.iter().flatten().cloned());
    for name in in_turn {
        if !ordered.contains(&name) {
            ordered.push(name);
        }
    }
    let only_other_hands = generation
        .names
        .iter()
        .filter(|(name, _)| !ordered.contains(name))
        .map(|(name, _)| name.clone())
        .collect();
    let over_the_bound = ordered.split_off(max.min(ordered.len()));
    Names {
        carried: ordered,
        over_the_bound,
        only_other_hands,
    }
}

/// The names that the personal channel of a generation before lists
/// (decision 2026-10-04 §9, step 5): a recovery reads the names there,
/// and only the names. `handed` is what the relays handed of that
/// channel, `secret` the generation's person secret and `number` its
/// statement's number. `of` says whose words are read: a recovery holds
/// no statement for such a generation, and anyone who ever held its
/// secret can write there.
///
/// A word is an entry under a name's place that is no delete, read from
/// its own signer: the one at the highest revision that the relays
/// handed of that signer in that slot, and no entry in a band above the
/// generation's. What it lists is read as a name only where it is one.
pub fn names_before(
    handed: &[CheckedEntry],
    secret: &[u8; 32],
    number: u64,
    of: impl Fn(&[u8; 32]) -> bool,
) -> Result<Vec<String>, PersonError> {
    let personal = Zeroizing::new(derive::personal_secret(secret)?);
    let channel = derive::channel_id(&personal)?;
    let mut last: BTreeMap<([u8; 32], [u8; 32]), &CheckedEntry> = BTreeMap::new();
    for entry in handed {
        let read = entry.channel == channel && of(&entry.author) && band(entry.rev) <= number;
        if !read {
            continue;
        }
        let held = last.entry((entry.slot, entry.author)).or_insert(entry);
        if entry.rev > held.rev {
            *held = entry;
        }
    }
    let mut listed: BTreeSet<String> = BTreeSet::new();
    for entry in last.values().filter(|entry| !entry.delete) {
        let Ok(inside) = entry.open(&personal) else {
            continue;
        };
        if let Some(name) = inside.name.strip_prefix(PERSONAL_NAME_PREFIX)
            && names::is_a_name(name)
        {
            listed.insert(name.to_string());
        }
    }
    Ok(listed.into_iter().collect())
}

// ── What the node does ───────────────────────────────────────────────

/// `POST /api/v1/recover/look`: what `cordelia recover` asks before
/// anything else: this device's key, whether it follows a phrase (a
/// recovery is refused where it does), and each relay that it is set up
/// with, with the value of the session of its connection, over which the
/// command makes its proofs. A relay with no session is not reached.
pub async fn look(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse, ApiError> {
    commands::asked(&req, &state)?;
    let sessions = carrying::sessions(&state).await;
    let follows = held_rows::person(&db(&state))?.is_some();
    let this_device = cordelia_crypto::bech32::encode_public_key(&state.identity.public_key())
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(HttpResponse::Ok().json(json!({
        "this_device": this_device,
        "follows_a_phrase": follows,
        "sessions": carrying::sessions_say(&sessions),
    })))
}

#[derive(Deserialize)]
pub struct LeftSecret {
    /// The number of the generation's statement.
    pub number: u64,
    /// Its person secret, in hex.
    pub secret: String,
}

#[derive(Deserialize)]
pub struct KeyLabel {
    /// The key, in hex.
    pub key: String,
    /// The label that the person was shown it by.
    #[serde(default)]
    pub label: String,
}

#[derive(Deserialize)]
pub struct MakeRequest {
    /// The change entry of the recovery's statement, which the command
    /// made: hex of its bytes.
    pub entry: String,
    /// The phrase's statement key, in hex.
    pub statement_key: String,
    /// The secrets of the generation recovered from, and of those before
    /// it that its change entry gave the phrase: what the machine keeps
    /// as a device keeps a secret it left (decision 2026-10-04 §3, §9).
    pub left: Vec<LeftSecret>,
    /// The keys that the statement newly removes, each with the label
    /// that the person was shown it by.
    #[serde(default)]
    pub gone: Vec<KeyLabel>,
    /// The devices that the person still has, which are in neither list:
    /// each is shown as that until it is added again (§8).
    #[serde(default)]
    pub still_have: Vec<KeyLabel>,
    /// The keys of the rows that the command could not show, each with
    /// the label of its record: nothing was asked of them, and each is
    /// kept as left out, so that `cordelia devices` shows it with its
    /// key (§9, step 3).
    #[serde(default)]
    pub not_shown: Vec<KeyLabel>,
    /// The word that the phrase gave for the look ([`Allows::Look`]),
    /// under this very change entry.
    pub word: Word,
}

/// What a recovery is to look at, as its word allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToLook {
    pub names: Vec<String>,
    pub takes: Vec<[u8; 32]>,
}

/// What `word` allows a recovery to look at, where the phrase whose
/// change entry is `entry` gave it for this device, under that entry,
/// within its time: refused otherwise, and where it names more names
/// than a recovery carries, what is no name, or what is no key.
fn to_look(state: &AppState, entry: &CheckedEntry, word: &Word) -> Result<ToLook, PersonError> {
    let own = state.identity.public_key();
    if !word.holds(&entry.author, &own, &entry.id(), now()) {
        return Err(PersonError::NoWord);
    }
    let Some(Allows::Look { names, takes }) = Allows::of(word) else {
        return Err(PersonError::NoWord);
    };
    let not = |why: &str| PersonError::NotCarried(format!("the word for the look: {why}"));
    if names.len() > RECOVERY_MAX_NAMES {
        return Err(not("it names more names than a recovery carries"));
    }
    if !names.iter().all(|name| names::is_a_name(name)) {
        return Err(not("it names what is no name"));
    }
    let takes: Option<Vec<[u8; 32]>> = takes.iter().map(|key| carry::key_named(key)).collect();
    Ok(ToLook {
        names,
        takes: takes.ok_or_else(|| not("it names what is no key"))?,
    })
}

/// What the person was shown, or could not be shown, of the keys of the
/// generation recovered from, as the command hands it to the node: each
/// key with its label.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Shown {
    /// The keys that the statement newly removes.
    pub gone: Vec<([u8; 32], String)>,
    /// The devices that the person still has, which are in neither list.
    pub still_have: Vec<([u8; 32], String)>,
    /// The keys of the rows that could not be shown.
    pub not_shown: Vec<([u8; 32], String)>,
}

/// The node's half of a recovery (decision 2026-10-04 §9, step 4, and
/// the first part of step 5), in one transaction: the statement is
/// applied on this machine ([`person::follow_recovered`]), which keeps
/// the secrets of the generations before; what the person was shown of
/// each key is kept, so that `cordelia devices` shows the removed keys
/// by their labels, and each device that they still have as not in the
/// last change; **the key of each row that could not be shown is kept as
/// left out too, and as one that was not shown,** so that `cordelia
/// devices` shows it with its key; and **the names are listed in the new
/// personal channel** ([`names::hold_for_a_carry`]), so that a recovery
/// which follows this one finds them, whether or not this machine ever
/// maps a folder.
///
/// **A folder's first cycle in a name of the look waits for the look**
/// (§7.3): this machine may map folders already, and what a folder
/// publishes is to be written over what the look carried, not beside it.
/// A file published first, at the first revision, would tie with the
/// version of before at that revision, which no command could then
/// bring. Each name's channel is held back from here on ([`held_back`]),
/// under the hold of the database's lock that the statement was applied
/// under: no cycle runs between the two.
///
/// Refused, with nothing changed: whatever [`person::follow_recovered`]
/// refuses, and a word for the look that does not hold ([`to_look`]).
pub fn follow(
    state: &AppState,
    entry: &CheckedEntry,
    statement_key: &[u8; 32],
    left: &[(u64, [u8; 32])],
    shown: &Shown,
    word: &Word,
) -> Result<(u64, ToLook), PersonError> {
    let to_look = to_look(state, entry, word)?;
    let at = now();
    let identity = &state.identity;
    let number = state.as_a_change(|conn| {
        let applied = in_one(conn, || {
            let applied = person::follow_recovered(conn, identity, entry, statement_key, left, at)?;
            // The word for the look is taken once (§16), as one with
            // the statement that it was given under.
            carry::take_once(conn, word, at)?;
            // Whatever key was typed at `cordelia accept` before was
            // typed by a device that followed no phrase: none of them is
            // spent under this one (§16).
            acts::forget_every_typed_key(conn)?;
            let held = person::held(conn)?.ok_or(PersonError::FollowsNoPhrase)?;
            let listed = &held.statement.statement;
            crate::look::note_removed_labels(conn, listed, &shown.gone)?;
            let in_no_list = |key: &[u8; 32]| !listed.lists(key) && !listed.removes(key);
            for (key, label) in shown.still_have.iter().filter(|(key, _)| in_no_list(key)) {
                acts::note_left_out(conn, key, label, applied.number, at)?;
            }
            // What could not be shown is in no list either, and the
            // person was asked nothing of it: it is kept as left out,
            // and as that.
            let mut not_shown: Vec<[u8; 32]> = Vec::new();
            for (key, label) in shown.not_shown.iter().filter(|(key, _)| in_no_list(key)) {
                acts::note_left_out(conn, key, label, applied.number, at)?;
                not_shown.push(*key);
            }
            crate::look::note_not_shown(conn, &not_shown)?;
            // The folders that this machine maps, and then the names of
            // the look, each held and listed.
            names::hold_mapped(conn, identity, at)?;
            for name in &to_look.names {
                names::hold_for_a_carry(conn, identity, name, at)?;
            }
            // What this machine carries, it carries by the look: until
            // that has ended it does not write that it has sent what it
            // carried (§8).
            meta::set(conn, meta::PERSON_LOOK_PENDING, "1")?;
            Ok(applied.number)
        });
        if applied.is_ok() {
            held_back(state, &channels_of(conn, &to_look.names));
        }
        applied
    })?;
    Ok((number, to_look))
}

/// The channel of each of `names` that this device holds, in their order:
/// `None` for one that it does not hold.
fn channels_of(conn: &rusqlite::Connection, names: &[String]) -> Vec<Option<[u8; 32]>> {
    let of = |name: &String| held_rows::channel_of_name(conn, name).ok().flatten();
    names.iter().map(of).collect()
}

/// A folder's first cycle in each of `channels` waits from now on
/// ([`crate::state::OwnChannels::carrying`], decision 2026-10-04 §7.3):
/// the look of a recovery has still to read the name. The wait lasts
/// until the look says that it has read the name, and for no longer than
/// a carry may take: so the look says it again for the names it has not
/// read yet, each time it begins one.
fn held_back(state: &AppState, channels: &[Option<[u8; 32]>]) {
    let now = Instant::now();
    for channel in channels.iter().flatten() {
        state.own_channels.carrying(channel, now);
    }
}

/// `POST /api/v1/recover/make`: the node's half of `cordelia recover`
/// ([`follow`]). The node is then woken: **it shows the change entry to
/// every relay at once, before anything is carried,** and sends the
/// names straight after it. The look is begun, and goes on after this
/// has answered ([`the_look`]): the command reads how far it is
/// ([`progress`]).
pub async fn make(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<MakeRequest>,
) -> Result<HttpResponse, ApiError> {
    commands::asked(&req, &state)?;
    let bad = |what: &str| ApiError::BadRequest(format!("{what} is not 32 bytes in hex"));
    let entry = hex::decode(&body.entry)
        .ok()
        .and_then(|bytes| Entry::from_wire(&bytes).ok()?.check().ok())
        .ok_or_else(|| ApiError::BadRequest("entry is no entry".into()))?;
    let statement_key =
        carry::key_named(&body.statement_key).ok_or_else(|| bad("statement_key"))?;
    let mut left: Vec<(u64, [u8; 32])> = Vec::new();
    for secret in &body.left {
        let bytes = carry::key_named(&secret.secret).ok_or_else(|| bad("a secret"))?;
        left.push((secret.number, bytes));
    }
    let labelled = |keys: &[KeyLabel]| -> Result<Vec<([u8; 32], String)>, ApiError> {
        keys.iter()
            .map(|one| {
                let key = carry::key_named(&one.key).ok_or_else(|| bad("a key"))?;
                Ok((key, one.label.clone()))
            })
            .collect()
    };
    let shown = Shown {
        gone: labelled(&body.gone)?,
        still_have: labelled(&body.still_have)?,
        not_shown: labelled(&body.not_shown)?,
    };
    let made = follow(&state, &entry, &statement_key, &left, &shown, &body.word);
    // What was handed of the secrets is overwritten here: the store
    // holds them now, or nothing was made.
    for (_, secret) in &mut left {
        zeroize::Zeroize::zeroize(secret);
    }
    let (number, to_look) = made.map_err(commands::refused)?;
    // One line in the log, of numbers alone: no key, and no name.
    tracing::info!(
        "a recovery was made on this machine: change {number}, {} to look through",
        names_counted(to_look.names.len())
    );
    state.own_channels.set_look(json!({
        "change": number,
        "finished": false,
        "names": to_look.names.len(),
        "read": 0,
    }));
    state.own_channels.written();
    state.own_channels.ask_whole();
    state.sync_control.ask_cycle();
    let node = state.clone();
    actix_web::rt::spawn(async move {
        the_look(&node, number, &to_look).await;
    });
    Ok(HttpResponse::Ok().json(json!({ "change": number })))
}

/// How many names, in words: `1 name`, `3 names`.
fn names_counted(names: usize) -> String {
    match names {
        1 => "1 name".to_string(),
        names => format!("{names} names"),
    }
}

/// What the node's log says when the look of a recovery has ended
/// (decision 2026-10-04 §9, step 5): the change, how many names it looked
/// through, how many versions it carried and in how many names, how many
/// reads did not reach their end, and how many names failed. Numbers
/// alone: no key, and no name of a file or of a folder.
fn look_ended_says(number: u64, found: &serde_json::Value) -> String {
    let count = |field: &str| found[field].as_u64().unwrap_or(0);
    let listed = |field: &str| found[field].as_array().map_or(0, Vec::len);
    if found["new_not_read"] == true {
        return format!(
            "the look of the recovery (change {number}) has ended: the new channels could not \
             be read whole, and nothing was taken"
        );
    }
    format!(
        "the look of the recovery (change {number}) has ended: {} looked through, {} carried \
         in {}, {} not to their end, {} failed",
        names_counted(count("names") as usize),
        match count("carried") {
            1 => "1 version".to_string(),
            carried => format!("{carried} versions"),
        },
        names_counted(count("carried_names") as usize),
        match listed("not_read") {
            1 => "1 read".to_string(),
            reads => format!("{reads} reads"),
        },
        names_counted(listed("failed")),
    )
}

/// `POST /api/v1/recover/progress`: how far the look of a recovery is,
/// and what it found once it has ended ([`the_look`]). `null` where this
/// node has made no look since it started: one that was interrupted is
/// not taken up again by itself.
pub async fn progress(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    commands::asked(&req, &state)?;
    Ok(HttpResponse::Ok().json(json!({ "look": state.own_channels.look() })))
}

/// The look of a recovery (decision 2026-10-04 §9, step 5), made once.
///
/// **The change entry goes first:** the node is asked for a whole pass,
/// which shows the entry to every relay before anything else is done
/// there, and the look waits for it.
///
/// Then, for each name of `to_look`, in its order: the name's channel is
/// read at every relay, in the generation recovered from and in each
/// generation before it whose secret the machine was handed, and what the
/// keys of `to_look` signed there goes to the one function that judges a
/// version for a carry ([`carry::bring`]): it comes in as this machine's
/// own entry, at its revision, with a first link for the key that signed
/// it, where the new channel holds neither that version nor an entry at
/// a higher revision. **From any other key it takes nothing.**
///
/// **Where the new channels could not be fetched whole in that pass,
/// nothing is taken** ([`carrying::fetched_whole`], §7.3): which of their
/// slots hold nothing is not known. The look says so, reads nothing, and
/// is not noted as ended: the machine never writes, under this
/// statement, that it has sent what it carried.
///
/// What it found is kept for the command, and given back: how many
/// versions were carried; which relays and which names it could not read
/// to their end; and, for each removed key, how many versions that key
/// signed in what was read that the new channels lack, with the names
/// they are in.
///
/// **When it has ended, what the store has taken is what this machine
/// carried:** it is sent as what a device carries is sent, and only then
/// may the machine come to write that it has sent what it carried
/// ([`crate::at_relays::say_sent`]).
///
/// **A folder's first cycle in a name waits until the look has read that
/// name** ([`held_back`]): each name that is still to be read is held
/// back afresh when the look begins a name, and let go once it is read.
/// Where the look takes nothing, every name is let go at once.
pub async fn the_look(state: &AppState, number: u64, to_look: &ToLook) -> serde_json::Value {
    let channels = channels_of(&db(state), &to_look.names);
    let first = Instant::now() + Duration::from_secs(CARRY_READ_MAX_SECS);
    if !carrying::fetched_whole(state, first).await {
        for channel in channels.iter().flatten() {
            state.own_channels.carried(channel);
        }
        let found = json!({
            "change": number,
            "finished": true,
            "new_not_read": true,
            "names": to_look.names.len(),
            "read": 0,
            "carried": 0,
            "carried_names": 0,
        });
        tracing::info!("{}", look_ended_says(number, &found));
        state.own_channels.set_look(found.clone());
        return found;
    }

    let (left, removed) = {
        let conn = db(state);
        let left = carrying::left_secrets(&conn).unwrap_or_default();
        let removed = person::held(&conn)
            .ok()
            .flatten()
            .map(|held| held.statement.statement.removed)
            .unwrap_or_default();
        (left, removed)
    };
    let mut tally = Tally::default();
    let mut carried_names = 0usize;
    let mut not_read: Vec<serde_json::Value> = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    // For each removed key: how many versions the new channels lack, and
    // in which names.
    let mut lacking: BTreeMap<[u8; 32], (usize, Vec<String>)> = BTreeMap::new();
    for (done, name) in to_look.names.iter().enumerate() {
        // This name, and each after it, is still to be read.
        held_back(state, &channels[done..]);
        let until = Instant::now() + Duration::from_secs(CARRY_READ_MAX_SECS);
        let read = match carrying::read_generations(state, name, &left, until).await {
            Ok(read) => read,
            Err(e) => {
                failed.push(format!("{name}: {e}"));
                continue;
            }
        };
        for generation in &read {
            for relay in &generation.said {
                let how = relay["read"].as_str().unwrap_or_default();
                if !matches!(how, "whole" | "not held") {
                    not_read.push(json!({
                        "name": name,
                        "change": generation.number,
                        "relay": relay["relay"],
                        "read": how,
                    }));
                }
            }
            if generation.said.is_empty() {
                not_read.push(json!({
                    "name": name, "change": generation.number, "relay": null,
                    "read": "no relay was reached",
                }));
            }
        }
        let before = tally.carried;
        let brought = (|| -> Result<(), PersonError> {
            let conn = db(state);
            for generation in &read {
                let was = carry::read(
                    &generation.entries,
                    &generation.secret,
                    generation.number,
                    |key| to_look.takes.contains(key),
                )?;
                for version in &was.versions {
                    let brought =
                        carry::bring(&conn, &state.identity, name, version, Rule::Counts, now())?;
                    tally.count(&format!("{name}: {}", version.name), brought);
                }
            }
            // What each removed key signed there that the new channel
            // lacks, once what is taken has come in.
            let mut signers: BTreeSet<[u8; 32]> = BTreeSet::new();
            for generation in &read {
                signers.extend(generation.entries.iter().map(|entry| entry.author));
            }
            for key in removed.iter().filter(|key| signers.contains(*key)) {
                let mut lacks = 0;
                for version in carrying::newest_of(&read, &[*key])? {
                    let would =
                        carry::would_bring(&conn, &state.identity, name, &version, Rule::Above)?;
                    lacks += usize::from(would == carry::Brought::Carried);
                }
                if lacks > 0 {
                    let of = lacking.entry(*key).or_default();
                    of.0 += lacks;
                    of.1.push(name.clone());
                }
            }
            Ok(())
        })();
        if let Err(e) = brought {
            failed.push(format!("{name}: {e}"));
        }
        if tally.carried > before {
            carried_names += 1;
            state.own_channels.written();
        }
        if let Some(channel) = &channels[done] {
            state.own_channels.carried(channel);
        }
        state.own_channels.set_look(json!({
            "change": number,
            "finished": false,
            "names": to_look.names.len(),
            "read": done + 1,
        }));
    }
    let labels = crate::look::removed_labels(&db(state)).unwrap_or_default();
    let label_of = |key: &[u8; 32]| -> String {
        let label = labels.iter().find(|(known, _)| known == key);
        label.map(|(_, label)| label.clone()).unwrap_or_default()
    };
    // Every removed key that this machine knows of, with its label:
    // whether a key's six words name it, and no other, is said of each
    // key that the new channels lack something of (§7.3).
    let all: Vec<carry::Removed> = removed
        .iter()
        .map(|key| carry::Removed {
            key: *key,
            label: label_of(key),
        })
        .collect();
    let lacking: Vec<serde_json::Value> = lacking
        .into_iter()
        .map(|(key, (versions, names))| {
            json!({
                "key": hex::encode(key),
                "label": label_of(&key),
                "by_words": carry::words_tell(&key, &all),
                "versions": versions,
                "names": names,
            })
        })
        .collect();
    let found = json!({
        "change": number,
        "finished": true,
        "names": to_look.names.len(),
        "read": to_look.names.len(),
        "carried": tally.carried,
        "carried_names": carried_names,
        "held": tally.held,
        "higher": tally.higher,
        "ties": tally.ties,
        "not_read": not_read,
        "failed": failed,
        "lacking": lacking,
    });
    // The look has ended: what the store has taken up to here is what
    // this machine carried, and it may now come to say that it has sent
    // it (§7.3, §8).
    {
        let conn = db(state);
        let ended = in_one(&conn, || {
            kept_rows::carried_to_here(&conn)?;
            meta::remove(&conn, meta::PERSON_LOOK_PENDING)?;
            Ok(())
        });
        if let Err(e) = ended {
            tracing::warn!("the look of a recovery could not be noted as ended: {e}");
        }
    }
    tracing::info!("{}", look_ended_says(number, &found));
    state.own_channels.set_look(found.clone());
    state.own_channels.written();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    use cordelia_crypto::addition::Addition;
    use cordelia_crypto::phrase::Phrase;
    use cordelia_crypto::statement::Device;

    use crate::change::{make_change, prepare_recovery, read_with};
    use crate::person::{added_name, applied_name, applied_word};
    use crate::several::{Machine, Node, OTHER_WORDS, Several, WORDS, entry_by, identity_of, text};

    const LAB: &str = "lab";

    fn phrase() -> Phrase {
        Phrase::parse(WORDS).unwrap()
    }

    /// A change entry as a recovery reads it with the phrase.
    fn candidate(entry: &CheckedEntry) -> Candidate {
        let (statement, _) = read_with(&phrase(), entry).unwrap();
        Candidate {
            entry: entry.clone(),
            statement,
        }
    }

    /// Device `n` holds `name`, and says that it syncs it.
    fn syncs(s: &mut Several, n: usize, name: &str) {
        s.hold(&[n], name);
        let now = s.tick();
        names::say(&s[n].conn, &s[n].identity, name, now).unwrap();
    }

    /// What the devices numbered so hold between them of the channel
    /// whose secret is `channel`: what a relay that each had sent
    /// everything holds.
    fn sent_by(s: &Several, who: &[usize], channel: &[u8; 32]) -> Vec<CheckedEntry> {
        let mut all: Vec<CheckedEntry> = Vec::new();
        for n in who {
            for entry in s[*n].stored_in(channel) {
                if !all.iter().any(|held| held.id() == entry.id()) {
                    all.push(entry);
                }
            }
        }
        all
    }

    /// Add to `handed` an entry that device 1 signed in the channel of a
    /// name, which is no entry of the personal channel.
    fn syncs_file(s: &Several, handed: &mut Vec<CheckedEntry>) {
        let lab = s[1].own(LAB);
        handed.push(entry_by(
            &s[1].identity,
            &lab,
            1,
            "notes.md",
            text("a file"),
            &[],
        ));
    }

    /// The change entry with the highest number is the one that a
    /// recovery is made from (decision 2026-10-04 §9, step 2). One that
    /// is on its chain is behind it, and is nothing; one that two relays
    /// handed is read once. **Any other that is not on its chain is a
    /// fork, whatever its number.** Of two at one number the same one is
    /// first, in whichever order they were handed.
    #[test]
    fn test_a_recovery_is_made_from_the_highest_change_and_what_is_off_its_chain_is_a_fork() {
        let mut s = Several::of_one_person(2);
        let first = s[0].latest();
        let second = s.change(0, &[0, 1], &[]);
        // A change made apart from the third: it is made after the
        // second, and never applied.
        let other = make_change(
            &s.phrase,
            &s[0].held().statement,
            &s[0].latest(),
            &s.key(0),
            s.listed(&[0, 1]),
            &[],
        )
        .unwrap();
        let third = s.change(0, &[0, 1], &[]);
        let fourth = s.change(0, &[0, 1], &[]);
        let of = |entries: &[&CheckedEntry]| -> Option<Found> {
            found(entries.iter().map(|entry| candidate(entry)).collect())
        };

        let one_chain = of(&[&first, &fourth, &second, &fourth, &third]).unwrap();
        assert_eq!(one_chain.from.entry.id(), fourth.id());
        assert_eq!(one_chain.from.statement.statement.number, 4);
        assert!(one_chain.apart.is_empty());

        // The other was made at number 3, and the fourth is higher: it
        // is not on the fourth's chain, and is a fork all the same.
        let forked = of(&[&other, &second, &fourth]).unwrap();
        assert_eq!(forked.from.entry.id(), fourth.id());
        let apart: Vec<[u8; 32]> = forked.apart.iter().map(|c| c.entry.id()).collect();
        assert_eq!(apart, [other.id()]);

        // Two at one number: a fork, and the same one first either way.
        let (a, b) = (
            of(&[&third, &other]).unwrap(),
            of(&[&other, &third]).unwrap(),
        );
        assert_eq!(a, b);
        assert_eq!(a.apart.len(), 1);
        assert_ne!(a.from.entry.id(), a.apart[0].entry.id());

        assert_eq!(of(&[&first]).unwrap().from.entry.id(), first.id());
        assert_eq!(of(&[]), None);

        // **What is on neither's chain is counted against both.** A
        // change is made after the other, at number 4, as the fourth is:
        // whichever of the two is first, the other is the second, and
        // the change that it was made after is behind it, on its chain,
        // and is nothing. A change made apart from the second, which is
        // on the chain of neither, is counted.
        assert_eq!(one_chain.second(), None);
        let (second_of, none) = forked.second().unwrap();
        assert_eq!((second_of.entry.id(), none), (other.id(), 0));
        let made_after = |entry: &CheckedEntry| {
            let after = candidate(entry).statement;
            make_change(&s.phrase, &after, entry, &s.key(0), s.listed(&[0, 1]), &[]).unwrap()
        };
        let after_other = made_after(&other);
        let apart_from_second = made_after(&first);
        // Each of the two at number 4 has a change behind it that is off
        // the other's chain: the third is behind the fourth, and the
        // other behind the one made after it. Which of the two is first
        // goes by the hash of its statement, and a change is made with a
        // new secret: it is the one in one run and the other in the
        // next. Both of those behind are handed, so that whichever is
        // the second, the one behind it is among those apart from the
        // first, and is counted as nothing.
        let both = of(&[&fourth, &after_other, &other, &third]).unwrap();
        let (second_of, on_neither) = both.second().unwrap();
        let two = [both.from.entry.id(), second_of.entry.id()];
        assert!(two.contains(&fourth.id()) && two.contains(&after_other.id()));
        let behind_the_second = match second_of.entry.id() == fourth.id() {
            true => third.id(),
            false => other.id(),
        };
        let apart: Vec<[u8; 32]> = both.apart.iter().map(|c| c.entry.id()).collect();
        assert_eq!(apart, [second_of.entry.id(), behind_the_second]);
        assert_eq!(on_neither, 0);
        let all = [&fourth, &after_other, &other, &third, &apart_from_second];
        let three = of(&all).unwrap();
        assert_eq!(three.apart.len(), 3);
        assert_eq!(three.second().unwrap().1, 1);
    }

    /// **A name that only a key lists which does not count is named
    /// among the names that the look leaves** (decision 2026-10-04 §9).
    /// Such a key's word is in what the relays hand, and nothing that it
    /// signed is taken: the name is read all the same, listed by no key,
    /// not carried, and said. A name that a device which counts lists
    /// too is listed once, by that device.
    #[test]
    fn test_a_name_that_only_a_key_which_does_not_count_lists_is_named_as_left() {
        let gone = two_gone();
        let from = candidate(&gone.s[0].latest());
        let (_, for_phrase) = read_with(&phrase(), &from.entry).unwrap();
        let statement_key = *phrase().statement_key().unwrap();
        let personal = derive::personal_secret(&for_phrase.secret).unwrap();
        // A key that holds the generation's secret, and is no device of
        // the statement nor added by one, says that it syncs a name of
        // its own, and one that the devices list.
        let stranger = identity_of(77);
        let says = |name: &str| {
            let word = names::word_name(name);
            entry_by(&stranger, &personal, 1, &word, text("it syncs this"), &[])
        };
        let handed = &gone.at_the_relay[1].1;
        let mut with_theirs = handed.clone();
        with_theirs.extend([says("theirs"), says(LAB)]);
        let reads = |handed: &[CheckedEntry]| {
            read_generation(&from, &statement_key, &for_phrase.secret, handed, now()).unwrap()
        };

        let before = reads(handed);
        assert!(before.names.iter().all(|(_, by)| !by.is_empty()));
        let read = reads(&with_theirs);
        // The stranger's own name, listed by no key, after those that
        // devices list; and the other name once, by its devices.
        let mut expected = before.names.clone();
        expected.push(("theirs".to_string(), Vec::new()));
        assert_eq!(read.names, expected);
        assert_eq!(read.rows, before.rows);

        let answers = [Answer::Lost, Answer::Lost];
        let names = names_in_order(&read, &answers, &[], RECOVERY_MAX_NAMES);
        assert_eq!(names.carried, ["desk", LAB]);
        assert_eq!(names.only_other_hands, ["theirs"]);
        assert!(names.over_the_bound.is_empty());
    }

    /// Six devices: 0, 1 and 2 are the statement's; device 1 added 3,
    /// which added 4; device 2 added 5. Each lists names. Returns the
    /// fixture and what a relay holds of the personal channel.
    fn six_devices() -> (Several, Vec<CheckedEntry>) {
        let mut s = Several::new(6);
        s.make_phrase(0);
        s.add(0, 1);
        s.add(0, 2);
        s.meet(&[0, 1, 2]);
        s.change(0, &[0, 1, 2], &[]);
        s.pass(0, 1);
        s.pass(0, 2);
        s.add(1, 3);
        s.meet(&[0, 1, 2, 3]);
        s.add(3, 4);
        s.add(2, 5);
        s.meet(&[0, 1, 2, 3, 4, 5]);
        for (n, names) in [
            (0, &["lab"][..]),
            (1, &["lab", "desk"][..]),
            (3, &["tablet"][..]),
            (4, &["deep"][..]),
            (5, &["phone"][..]),
        ] {
            for name in names {
                syncs(&mut s, n, name);
            }
        }
        let personal = s[0].personal();
        let handed = sent_by(&s, &[0, 1, 2, 3, 4, 5], &personal);
        (s, handed)
    }

    /// A recovery shows every device of the generation it recovers from
    /// (decision 2026-10-04 §9, step 3): the statement's devices first,
    /// in its order; then the keys added since, each under the device
    /// that added it, and under each of those the keys that it added,
    /// each with who added it and how much it signed in the personal
    /// channel; and the names that they list. It is read as a device that
    /// had applied the statement reads it. One key has one row: a key
    /// with a record that counts and one that does not is shown once, as
    /// counting.
    #[test]
    fn test_a_recovery_shows_each_device_under_the_one_that_added_it() {
        let (s, handed) = six_devices();
        let from = candidate(&s[0].latest());
        let statement_key = *phrase().statement_key().unwrap();
        let secret = s[0].secret();
        let read = read_generation(&from, &statement_key, &secret, &handed, s.now).unwrap();
        let shown: Vec<([u8; 32], Option<[u8; 32]>, bool)> = read
            .rows
            .iter()
            .map(|row| (row.key, row.added_by.map(|(adder, _)| adder), row.counts))
            .collect();
        let k = |n: usize| s.key(n);
        assert_eq!(
            shown,
            [
                (k(0), None, true),
                (k(1), None, true),
                (k(2), None, true),
                (k(3), Some(k(1)), true),
                (k(4), Some(k(3)), true),
                (k(5), Some(k(2)), true),
            ]
        );
        assert!(read.not_shown.is_empty());
        let labels: Vec<&str> = read.rows.iter().map(|row| row.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "device 0", "device 1", "device 2", "device 3", "device 4", "device 5"
            ]
        );
        // Each signed something there: its word that it applied the
        // statement, its records, its names.
        assert!(
            read.rows.iter().all(|row| row.signed > 0),
            "{:?}",
            read.rows
        );
        let signed_by_one = handed.iter().filter(|entry| entry.author == k(1)).count();
        assert_eq!(read.rows[1].signed, signed_by_one);
        assert_eq!(
            read.names,
            [
                ("deep".to_string(), vec![k(4)]),
                ("desk".to_string(), vec![k(1)]),
                ("lab".to_string(), {
                    let mut by = vec![k(0), k(1)];
                    by.sort();
                    by
                }),
                ("phone".to_string(), vec![k(5)]),
                ("tablet".to_string(), vec![k(3)]),
            ]
        );
        // Three devices: no one device whose carry could be cut short.
        assert_eq!(read.cut_short, None);
        // In whichever order the relays handed the entries.
        let mut turned = handed.clone();
        turned.reverse();
        let again = read_generation(&from, &statement_key, &secret, &turned, s.now).unwrap();
        assert_eq!(again, read);
        // What the relays handed of another channel is not read with it.
        let mut with_another = handed.clone();
        syncs_file(&s, &mut with_another);
        let same = read_generation(&from, &statement_key, &secret, &with_another, s.now).unwrap();
        assert_eq!(same, read);
        // A secret that the statement does not commit to reads nothing.
        let refused = read_generation(&from, &statement_key, &[9; 32], &handed, s.now);
        assert!(matches!(refused, Err(PersonError::SecretNotCommitted)));
        // What the relays handed of another channel is not read.
        let none = read_generation(&from, &statement_key, &secret, &[], s.now).unwrap();
        assert_eq!(none.rows.len(), 3);
        assert!(none.names.is_empty());

        // One key has one row. Device 0 signs a record for device 3 too:
        // it is read first, and device 3 counts by it. The record that
        // device 1 signed for that key does not count then, and is no
        // second row.
        let statement = &from.statement.statement;
        let again = Addition::under(statement, s[3].listed(), k(0), 1_800_000_000)
            .unwrap()
            .sign(&s[0].identity)
            .unwrap();
        let mut twice = handed.clone();
        twice.push(entry_by(
            &s[0].identity,
            &s[0].personal(),
            (2u64 << cordelia_core::protocol::REV_COUNT_BITS) + 1,
            &added_name(&k(3)).unwrap(),
            Value::Other(again.to_bytes().unwrap()),
            &[],
        ));
        let read = read_generation(&from, &statement_key, &secret, &twice, s.now).unwrap();
        let shown: Vec<([u8; 32], Option<[u8; 32]>, bool)> = read
            .rows
            .iter()
            .map(|row| (row.key, row.added_by.map(|(adder, _)| adder), row.counts))
            .collect();
        assert_eq!(
            shown,
            [
                (k(0), None, true),
                (k(1), None, true),
                (k(2), None, true),
                (k(3), Some(k(0)), true),
                (k(4), Some(k(3)), true),
                (k(5), Some(k(2)), true),
            ]
        );
    }

    /// What the look takes from whom (decision 2026-10-04 §9, step 3):
    /// from each device that the person still has, or that is lost or
    /// broken. From a device that may be in someone else's hands it
    /// takes nothing, nor from a key that it added, nor from a key that
    /// such a key added. Every device that is gone is removed, whichever
    /// way; one that the person still has is in neither list.
    #[test]
    fn test_the_look_takes_nothing_from_other_hands_nor_from_what_they_added() {
        use Answer::{Have, Lost, NotAsked, OtherHands};
        let (s, handed) = six_devices();
        let from = candidate(&s[0].latest());
        let statement_key = *phrase().statement_key().unwrap();
        let read = read_generation(&from, &statement_key, &s[0].secret(), &handed, s.now).unwrap();
        // The rows are devices 0 to 5, in that order: 1 added 3, which
        // added 4, and 2 added 5.
        let rows = &read.rows;
        let k = |n: usize| s.key(n);
        let taken = |answers: &[Answer]| takes(rows, answers);

        assert_eq!(
            taken(&[Lost, Lost, Lost, Lost, Lost, Lost]),
            [k(0), k(1), k(2), k(3), k(4), k(5)]
        );
        assert_eq!(
            taken(&[Have, Have, Lost, Lost, Have, Have]),
            [k(0), k(1), k(2), k(3), k(4), k(5)]
        );
        // Device 1 may be in someone else's hands: nothing from it, from
        // device 3, which it added, or from device 4, which 3 added.
        let ones = [Lost, OtherHands, Lost, Lost, Have, Lost];
        assert_eq!(taken(&ones), [k(0), k(2), k(5)]);
        for (at, so) in [false, true, false, true, true, false].iter().enumerate() {
            assert_eq!(in_other_hands(rows, &ones, at), *so, "{at}");
        }
        // Device 3: nothing from it, or from device 4.
        assert_eq!(
            taken(&[Lost, Lost, Lost, OtherHands, Lost, Lost]),
            [k(0), k(1), k(2), k(5)]
        );
        // Device 4, which added nobody: nothing from it alone.
        assert_eq!(
            taken(&[Lost, Lost, Lost, Lost, OtherHands, Lost]),
            [k(0), k(1), k(2), k(3), k(5)]
        );
        // A row that was not answered is not taken from, and nor is one
        // of which nothing was asked.
        assert_eq!(taken(&[Lost, Lost]), [k(0), k(1)]);
        assert_eq!(
            taken(&[Lost, Lost, NotAsked, Lost, Lost, NotAsked]),
            [k(0), k(1), k(3), k(4)]
        );
        // A key that does not count is not taken from, whatever is said.
        let mut not_counted = rows.clone();
        not_counted[5].counts = false;
        assert_eq!(
            takes(&not_counted, &[Lost, Lost, Lost, Lost, Lost, Have]),
            [k(0), k(1), k(2), k(3), k(4)]
        );

        // What is gone is removed, whichever way it went.
        assert_eq!(
            gone(rows, &[Have, OtherHands, Lost, Lost, Have, Have]),
            [k(1), k(2), k(3)]
        );
        assert!(gone(rows, &[Have, Have, Have, Have, Have, Have]).is_empty());
        // A record that does not count is not made a removed key,
        // whatever is said of it: and nothing is said of one.
        for of_the_last in [Lost, OtherHands, NotAsked] {
            assert_eq!(
                gone(&not_counted, &[Lost, Lost, Lost, Lost, Lost, of_the_last]),
                [k(0), k(1), k(2), k(3), k(4)]
            );
        }
        assert_eq!(
            gone(rows, &[Lost, NotAsked, Lost, NotAsked, Have, Lost]),
            [k(0), k(2), k(5)]
        );
    }

    /// The names that a recovery carries, in their order, and no more
    /// than the bound (decision 2026-10-04 §9): those of the generation
    /// recovered from that a device the person still has lists; then
    /// those that a device which is lost or broken lists; then those of
    /// the generations before, the newest first. A name that only a
    /// device lists from which nothing is taken is left, and named; so
    /// are the names beyond the bound.
    #[test]
    fn test_a_recovery_carries_at_most_so_many_names_in_their_order() {
        use Answer::{Have, Lost, OtherHands};
        let (s, handed) = six_devices();
        let from = candidate(&s[0].latest());
        let statement_key = *phrase().statement_key().unwrap();
        let read = read_generation(&from, &statement_key, &s[0].secret(), &handed, s.now).unwrap();
        // The rows are devices 0 to 5, in that order: device 0 lists lab;
        // 1 lists lab and desk; 3 lists tablet; 4 lists deep; 5 lists
        // phone.
        let answers = [Lost, Have, Have, Lost, OtherHands, Lost];
        let before = vec![
            vec!["older".to_string(), "lab".to_string()],
            vec!["oldest".to_string(), "older".to_string()],
        ];
        let all = names_in_order(&read, &answers, &before, RECOVERY_MAX_NAMES);
        assert_eq!(
            all.carried,
            ["desk", "lab", "phone", "tablet", "older", "oldest"]
        );
        assert_eq!(all.only_other_hands, ["deep"]);
        assert!(all.over_the_bound.is_empty());
        // The bound: what is beyond it is left, from the end.
        let four = names_in_order(&read, &answers, &before, 4);
        assert_eq!(four.carried, ["desk", "lab", "phone", "tablet"]);
        assert_eq!(four.over_the_bound, ["older", "oldest"]);
        let none = names_in_order(&read, &answers, &before, 0);
        assert!(none.carried.is_empty());
        assert_eq!(none.over_the_bound.len(), 6);
        // With device 1 in someone else's hands, what only it and the
        // devices under it list is left: desk, tablet and deep. The name
        // that device 0 lists too is carried.
        let ones = [Lost, OtherHands, Lost, Lost, Lost, Lost];
        let left = names_in_order(&read, &ones, &[], RECOVERY_MAX_NAMES);
        assert_eq!(left.carried, ["lab", "phone"]);
        assert_eq!(left.only_other_hands, ["deep", "desk", "tablet"]);

        // The bound itself, with more names than it: 1,024 are carried.
        let many: Vec<String> = (0..RECOVERY_MAX_NAMES + 10)
            .map(|n| format!("name-{n:05}"))
            .collect();
        let most = names_in_order(&read, &answers, &[many], RECOVERY_MAX_NAMES);
        assert_eq!(most.carried.len(), RECOVERY_MAX_NAMES);
        assert_eq!(most.over_the_bound.len(), 14);
        assert_eq!(most.carried[..4], ["desk", "lab", "phone", "tablet"]);
    }

    /// The names of a generation before are read from its personal
    /// channel, and only the names (decision 2026-10-04 §9, step 5): a
    /// word under a name's place that is no delete, read from its own
    /// signer at the highest revision that was handed, by a key of which
    /// the caller says so, and in no band above the generation's.
    #[test]
    fn test_the_names_of_a_generation_before_are_read_from_the_keys_that_are_said() {
        let mut s = Several::of_one_person(3);
        for (n, name) in [(0, "lab"), (1, "desk"), (2, "phone"), (1, "gone")] {
            syncs(&mut s, n, name);
        }
        let (secret, personal) = (s[0].secret(), s[0].personal());
        let mut handed = sent_by(&s, &[0, 1, 2], &personal);
        // Device 1 stopped syncing a name: a relay holds its word, and
        // another the delete over it.
        let now = s.tick();
        names::unsay(&s[1].conn, &s[1].identity, "gone", now).unwrap();
        handed.extend(s[1].stored_in(&personal));
        let (k0, k1) = (s.key(0), s.key(1));
        let of = |handed: &[CheckedEntry], of: &dyn Fn(&[u8; 32]) -> bool| {
            names_before(handed, &secret, 1, of).unwrap()
        };
        assert_eq!(of(&handed, &|_| true), ["desk", "lab", "phone"]);
        assert_eq!(
            of(&handed, &|key| *key == k0 || *key == k1),
            ["desk", "lab"]
        );
        assert!(of(&handed, &|_| false).is_empty());
        // A word in a band above the generation's is none, and nor is
        // what is no name, or an entry of another channel.
        let above = (2u64 << cordelia_core::protocol::REV_COUNT_BITS) + 1;
        for (rev, name) in [
            (above, "name/above"),
            (5, "name/Not A Name"),
            (5, "other/x"),
        ] {
            handed.push(entry_by(
                &s[0].identity,
                &personal,
                rev,
                name,
                text(""),
                &[],
            ));
        }
        let elsewhere = s[0].own(LAB);
        handed.push(entry_by(
            &s[0].identity,
            &elsewhere,
            5,
            "name/elsewhere",
            text(""),
            &[],
        ));
        assert_eq!(of(&handed, &|_| true), ["desk", "lab", "phone"]);
        // Under the generation after, the word in its band is read.
        let later = names_before(&handed, &secret, 2, |_| true).unwrap();
        assert_eq!(later, ["above", "desk", "lab", "phone"]);
    }

    /// Every record under the statement is shown, up to 256 (decision
    /// 2026-10-04 §9, step 3). Beyond that the command says how many it
    /// could not show, and the look takes nothing from those. Of the
    /// keys that are shown, the look takes only from those that count,
    /// and only those are made removed keys.
    #[test]
    fn test_a_recovery_shows_at_most_so_many_devices_and_takes_nothing_from_the_rest() {
        let mut s = Several::new(1);
        s.make_phrase(0);
        let statement = s[0].held().statement.statement;
        let personal = s[0].personal();
        let mut handed = s[0].stored_in(&personal);
        // Device 0 signs 330 records: more than count, and more than
        // are kept as not counted.
        for n in 0..330u16 {
            let key = identity_of(1_000 + n).public_key();
            let device = Device::new(key, &format!("added {n}")).unwrap();
            let record = Addition::under(&statement, device, s.key(0), 1_800_000_000)
                .unwrap()
                .sign(&s[0].identity)
                .unwrap();
            handed.push(entry_by(
                &s[0].identity,
                &personal,
                (1u64 << cordelia_core::protocol::REV_COUNT_BITS) + 1,
                &added_name(&key).unwrap(),
                Value::Other(record.to_bytes().unwrap()),
                &[],
            ));
        }
        let from = candidate(&s[0].latest());
        let statement_key = *phrase().statement_key().unwrap();
        let read = read_generation(&from, &statement_key, &s[0].secret(), &handed, s.now).unwrap();
        assert_eq!(read.rows.len(), RECOVERY_MAX_DEVICES_SHOWN);
        // 256 rows, and no more: the number itself is what is promised.
        assert_eq!(read.rows.len(), 256);
        let counted = cordelia_core::protocol::MAX_COUNTED_DEVICES;
        let kept = cordelia_core::protocol::MAX_NOT_COUNTED_RECORDS;
        assert_eq!(
            read.not_shown.len(),
            counted + kept - RECOVERY_MAX_DEVICES_SHOWN
        );
        assert!(read.not_shown.iter().all(|row| !row.counts));
        // The statement's device first, then the keys it added: those
        // that count ahead of those that do not.
        assert_eq!(read.rows[0].key, s.key(0));
        let counts: Vec<bool> = read.rows.iter().map(|row| row.counts).collect();
        assert!(counts[..counted].iter().all(|counts| *counts));
        assert!(counts[counted..].iter().all(|counts| !*counts));
        // The look takes from those that count, and from no other.
        let answers = vec![Answer::Lost; read.rows.len()];
        assert_eq!(takes(&read.rows, &answers).len(), counted);
        // Each record that does not count fails only for the bound of 64,
        // and the device of the statement signed it. Where that device
        // may be in someone else's hands, none of them is asked about,
        // and none is made a removed key, whatever is said of it.
        assert!(
            read.rows[counted..]
                .iter()
                .all(|row| { row.no_room.len() == 1 && row.no_room[0].0 == s.key(0) })
        );
        let mut hands = answers.clone();
        hands[0] = Answer::OtherHands;
        assert_eq!(gone(&read.rows, &hands).len(), counted);
        // Where it is lost or broken, each that is shown is asked about,
        // and is removed as it is answered.
        assert_eq!(gone(&read.rows, &answers).len(), read.rows.len());
        let mut still = vec![Answer::Have; read.rows.len()];
        still[0] = Answer::Lost;
        assert_eq!(gone(&read.rows, &still), [s.key(0)]);
    }

    /// What a relay holds once two devices of one person have sent it
    /// everything, of two names and the personal channel; with the
    /// fixture, and the keys of the two devices.
    struct TwoGone {
        s: Several,
        /// The secrets of the channels, and what the relay holds of
        /// each.
        at_the_relay: Vec<([u8; 32], Vec<CheckedEntry>)>,
    }

    /// Device 0 and device 1 are the devices of change 2. Both sync
    /// `lab`: device 0 wrote `a.md` and device 1 wrote `b.md`. Device 1
    /// alone syncs `desk`, with `d.md`. Before that change, under the
    /// first, device 0 wrote `old.md` in `lab`, which no device carried:
    /// the relay holds it in the generation before.
    fn two_gone() -> TwoGone {
        let mut s = Several::of_one_person(2);
        s.hold(&[0], LAB);
        let first_lab = s[0].own(LAB);
        let old = entry_by(
            &s[0].identity,
            &first_lab,
            1,
            "old.md",
            text("from before"),
            &[],
        );
        let mut at_the_relay = vec![(first_lab, vec![old])];
        s.change(0, &[0, 1], &[]);
        s.pass(0, 1);
        syncs(&mut s, 0, LAB);
        syncs(&mut s, 1, LAB);
        syncs(&mut s, 1, "desk");
        s.write(0, LAB, "a.md", "of device 0");
        s.write(1, LAB, "b.md", "of device 1");
        s.write(1, "desk", "d.md", "on the desk");
        for secret in [s[0].personal(), s[0].own(LAB), s[1].own("desk")] {
            at_the_relay.push((secret, sent_by(&s, &[0, 1], &secret)));
        }
        TwoGone { s, at_the_relay }
    }

    /// What the command does with the phrase, for a test: the statement
    /// of a recovery from `from` on the machine of `node`, with the rows
    /// answered so, and the word for the look.
    struct Made {
        entry: CheckedEntry,
        statement_key: [u8; 32],
        left: Vec<(u64, [u8; 32])>,
        shown: Shown,
        word: Word,
        names: Names,
        cut_short: Option<[u8; 32]>,
    }

    fn makes(node: &Node, from: &Candidate, handed: &[CheckedEntry], answers: &[Answer]) -> Made {
        makes_as(node, from, handed, |_, at| answers[at])
    }

    /// As [`makes`], with each row answered as `answer` says of it and of
    /// its place: but a record that does not count, of which the command
    /// asks nothing, unless it is asked about for the bound of 64 alone
    /// ([`asked_for_room`]).
    fn makes_as(
        node: &Node,
        from: &Candidate,
        handed: &[CheckedEntry],
        answer: impl Fn(&Row, usize) -> Answer,
    ) -> Made {
        let phrase = phrase();
        let own = node.state.identity.public_key();
        let (_, for_phrase) = read_with(&phrase, &from.entry).unwrap();
        let statement_key = *phrase.statement_key().unwrap();
        let read =
            read_generation(from, &statement_key, &for_phrase.secret, handed, now()).unwrap();
        let mut answers: Vec<Answer> = Vec::new();
        for (at, row) in read.rows.iter().enumerate() {
            let asked = row.counts || asked_for_room(&read.rows, &answers, at).is_some();
            answers.push(match asked {
                true => answer(row, at),
                false => Answer::NotAsked,
            });
        }
        let answers = &answers[..];
        let names = names_in_order(&read, answers, &[], RECOVERY_MAX_NAMES);
        let removed = gone(&read.rows, answers);
        let maker = Device::new(own, "new machine").unwrap();
        let entry = prepare_recovery(&from.statement, None, maker, &removed)
            .unwrap()
            .sign(&phrase, &from.entry, None)
            .unwrap();
        let allows = Allows::Look {
            names: names.carried.clone(),
            takes: takes(&read.rows, answers).iter().map(hex::encode).collect(),
        };
        let word = Word::give(&phrase, &own, &entry.id(), allows.says().unwrap(), now()).unwrap();
        let mut left = vec![(from.statement.statement.number, for_phrase.secret)];
        left.extend(for_phrase.earlier.iter().map(|e| (e.number, e.secret)));
        let labelled = |said_so: fn(&Answer) -> bool| -> Vec<([u8; 32], String)> {
            let rows = read.rows.iter().zip(answers);
            rows.filter(|(_, said)| said_so(said))
                .map(|(row, _)| (row.key, row.label.clone()))
                .collect()
        };
        let not_shown = read.not_shown.iter();
        Made {
            entry,
            statement_key,
            left,
            shown: Shown {
                gone: labelled(|said| matches!(said, Answer::Lost | Answer::OtherHands)),
                still_have: labelled(|said| *said == Answer::Have),
                not_shown: not_shown.map(|row| (row.key, row.label.clone())).collect(),
            },
            word,
            names,
            cut_short: read.cut_short,
        }
    }

    fn follows(node: &Node, made: &Made) -> Result<(u64, ToLook), PersonError> {
        follow(
            &node.state,
            &made.entry,
            &made.statement_key,
            &made.left,
            &made.shown,
            &made.word,
        )
    }

    /// The node of a new machine, whose relay holds what `gone` says.
    fn new_machine(n: u16, gone: &TwoGone) -> Node {
        let node = Node::of(Machine::new(n));
        for (secret, entries) in &gone.at_the_relay {
            node.relay_holds(secret, entries);
        }
        node
    }

    /// A recovery, on the node (decision 2026-10-04 §9, steps 4 and 5).
    /// The statement is applied on a machine that followed no phrase,
    /// which keeps the secrets of the generations before as secrets it
    /// left, and lists the names in its new personal channel. The look
    /// then takes, from the generation recovered from and from those
    /// before it, what the keys of the phrase's word signed, and nothing
    /// that another key signed: of a device that may be in someone
    /// else's hands it says how much the new channels lack. That comes
    /// in afterwards by the command that names its key, with the phrase.
    #[actix_web::test]
    async fn test_a_recovery_takes_what_the_answered_keys_signed_and_nothing_of_other_hands() {
        let gone = two_gone();
        let s = &gone.s;
        let (k0, k1) = (s.key(0), s.key(1));
        let from = candidate(&s[0].latest());
        let personal = &gone.at_the_relay[1].1;
        let node = new_machine(9, &gone);
        let own = node.state.identity.public_key();
        // Device 0 is lost; device 1 may be in someone else's hands.
        let made = makes(&node, &from, personal, &[Answer::Lost, Answer::OtherHands]);
        assert_eq!(made.names.carried, [LAB]);
        assert_eq!(made.names.only_other_hands, ["desk"]);
        assert_eq!(made.cut_short, None);

        // A word that does not hold: nothing is made.
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let says = made.word.what.clone();
        let no_words = [
            Word::give(&other, &own, &made.entry.id(), says.clone(), now()).unwrap(),
            Word::give(&phrase(), &own, &[9; 32], says.clone(), now()).unwrap(),
            Word::give(&phrase(), &k0, &made.entry.id(), says.clone(), now()).unwrap(),
            Word::give(&phrase(), &own, &made.entry.id(), says.clone(), now() - 601).unwrap(),
            Word::give(
                &phrase(),
                &own,
                &made.entry.id(),
                Allows::Handed {
                    name: LAB.into(),
                    run: hex::encode(k0),
                }
                .says()
                .unwrap(),
                now(),
            )
            .unwrap(),
        ];
        for word in no_words {
            let refused = follows(
                &node,
                &Made {
                    word,
                    ..clone(&made)
                },
            );
            assert!(matches!(refused, Err(PersonError::NoWord)), "{refused:?}");
        }
        // A word that names what is no name, or no key.
        for allows in [
            Allows::Look {
                names: vec!["Not A Name".into()],
                takes: vec![],
            },
            Allows::Look {
                names: vec![],
                takes: vec!["zz".into()],
            },
        ] {
            let says = allows.says().unwrap();
            let word = Word::give(&phrase(), &own, &made.entry.id(), says, now()).unwrap();
            let refused = follows(
                &node,
                &Made {
                    word,
                    ..clone(&made)
                },
            );
            assert!(
                matches!(refused, Err(PersonError::NotCarried(_))),
                "{refused:?}"
            );
        }
        // More secrets than an entry gives, and one of a later change.
        let too_many = Made {
            left: vec![(1, [7; 32]); 10],
            ..clone(&made)
        };
        assert!(matches!(
            follows(&node, &too_many),
            Err(PersonError::NotARecovery)
        ));
        let later = Made {
            left: vec![(3, [7; 32])],
            ..clone(&made)
        };
        assert!(matches!(
            follows(&node, &later),
            Err(PersonError::NotARecovery)
        ));
        assert!(person::held(&db(&node.state)).unwrap().is_none());
        assert_eq!(node.stored(), 0);

        // The recovery: change 3, with this machine alone, and both
        // devices removed.
        let (number, to_look) = follows(&node, &made).unwrap();
        assert_eq!(number, 3);
        assert_eq!(to_look.names, [LAB]);
        assert_eq!(to_look.takes, [k0]);
        {
            let conn = db(&node.state);
            let held = person::held(&conn).unwrap().unwrap();
            let statement = &held.statement.statement;
            assert_eq!(statement.devices.len(), 1);
            assert_eq!(statement.devices[0].key, own);
            assert!(statement.removes(&k0) && statement.removes(&k1));
            // It keeps the secrets of the generations before, as left.
            let left: Vec<(u64, [u8; 32])> = carrying::left_secrets(&conn)
                .unwrap()
                .into_iter()
                .map(|(number, secret)| (number, *secret))
                .collect();
            assert_eq!(left, made.left);
            assert_eq!(left.len(), 2);
            // The name is held and listed, with no folder mapped to it.
            assert!(held_rows::channel_of_name(&conn, LAB).unwrap().is_some());
            assert!(
                names::said_here(&conn, &node.state.identity)
                    .unwrap()
                    .contains(LAB)
            );
            assert!(names::carried(&conn).unwrap().contains(LAB));
            assert!(held_rows::channel_of_name(&conn, "desk").unwrap().is_none());
            // What the person was shown each removed key by is kept.
            let labels = crate::look::removed_labels(&conn).unwrap();
            assert!(labels.contains(&(k0, "device 0".to_string())), "{labels:?}");
            assert!(labels.contains(&(k1, "device 1".to_string())));
        }
        // It is made once: a machine that follows a phrase is refused.
        assert!(matches!(
            follows(&node, &made),
            Err(PersonError::FollowsAPhrase)
        ));
        // And the word for the look is taken with it: a word is taken
        // once (§16).
        assert!(carry::is_taken(&db(&node.state), &made.word, now()).unwrap());

        // Until the look has ended, the machine does not write that it
        // has sent what it carried, though nothing waits at its relay:
        // what it carries, it carries by the look.
        let relay = [7u8; 32];
        let sent_everything = |node: &Node| {
            let conn = db(&node.state);
            let far = i64::MAX / 2;
            for channel in crate::at_relays::channels(&conn, &node.state.identity).unwrap() {
                kept_rows::sent(&conn, &relay, &channel.id, far).unwrap();
                kept_rows::carried(&conn, &relay, &channel.id, far).unwrap();
            }
        };
        let says_sent = |node: &Node| {
            let conn = db(&node.state);
            crate::at_relays::say_sent(&conn, &node.state.identity, &[relay], now()).unwrap()
        };
        sent_everything(&node);
        assert!(
            meta::get(&db(&node.state), meta::PERSON_LOOK_PENDING)
                .unwrap()
                .is_some()
        );
        assert!(!says_sent(&node));

        // The look. The change entry goes first: the node is asked for
        // a whole pass, which shows it to every relay, and nothing is
        // read at a relay before that pass has been made.
        node.asked.lock().unwrap().clear();
        node.did.lock().unwrap().clear();
        let found = the_look(&node.state, number, &to_look).await;
        assert_eq!(*node.did.lock().unwrap(), ["pass", "read", "read"]);
        assert_eq!(found["finished"], true, "{found}");
        assert_eq!((&found["names"], &found["read"]), (&json!(1), &json!(1)));
        // What device 0 signed, in the generation recovered from and in
        // the one before: two versions.
        assert_eq!(found["carried"], 2, "{found}");
        assert_eq!(node.text(LAB, "a.md").as_deref(), Some("of device 0"));
        assert_eq!(node.text(LAB, "old.md").as_deref(), Some("from before"));
        // Nothing of the device that may be in someone else's hands.
        assert_eq!(node.text(LAB, "b.md"), None);
        assert_eq!(
            found["lacking"],
            json!([{
                "key": hex::encode(k1), "label": "device 1", "by_words": true, "versions": 1,
                "names": [LAB],
            }])
        );
        assert_eq!(found["not_read"], json!([]));
        assert_eq!(node.state.own_channels.look(), Some(found.clone()));
        // It read the name in each generation that it was handed the
        // secret of, with the node's own proof, and nothing else.
        let asked = node.asked.lock().unwrap().clone();
        assert_eq!(asked.len(), 2, "{asked:?}");
        assert!(asked.iter().all(|(_, by_secret)| *by_secret));
        // Each is this machine's own entry, with a first link for the
        // key that signed it.
        let slot = crate::publish::read(&db(&node.state), LAB, "a.md")
            .unwrap()
            .slot;
        let current = slot.current.unwrap();
        assert_eq!(current.entries[0].author, own);
        let chain = current.entries[0].chain.clone().unwrap();
        assert_eq!(
            chain[0],
            cordelia_crypto::entry::Link::of(&text("of device 0"), k0)
        );

        // The look has ended: what it brought in is what this machine
        // carried, and waits to be sent as that. Once it is sent, the
        // machine writes that it has sent what it carried.
        assert_eq!(
            meta::get(&db(&node.state), meta::PERSON_LOOK_PENDING).unwrap(),
            None
        );
        {
            let conn = db(&node.state);
            let other_relay = [8u8; 32];
            let waits =
                crate::at_relays::carried_waits_at(&conn, &node.state.identity, &other_relay);
            assert!(waits.unwrap());
            let lab = held_rows::channel_of_name(&conn, LAB).unwrap().unwrap();
            let last = cordelia_storage::entries::channel_entries_after(&conn, &lab, 0, 100)
                .unwrap()
                .iter()
                .map(|held| held.seq)
                .max()
                .unwrap();
            assert!(kept_rows::carried_up_to(&conn).unwrap() >= last);
        }
        assert!(says_sent(&node));

        // What the other device wrote comes in by the command that names
        // its key, with the phrase: by the label it was shown by.
        let said = carrying::look_from(&node.state, LAB, &["device 1".to_string()])
            .await
            .unwrap();
        assert_eq!(said["empty"], 1, "{said}");
        let word = node.word(
            &phrase(),
            &Allows::From {
                name: LAB.into(),
                keys: vec![hex::encode(k1)],
                above: vec![],
            },
        );
        let done = carrying::take_from(&node.state, &word).await.unwrap();
        assert_eq!(done["carried"], 1, "{done}");
        assert_eq!(node.text(LAB, "b.md").as_deref(), Some("of device 1"));
    }

    /// **No device can push another out of a recovery by what it signs**
    /// (decision 2026-10-04 §9, step 3). A statement lists two devices,
    /// and the first signs 300 records of additions: 62 count, and the
    /// rest do not. The other device is shown all the same, straight
    /// after the first: it is asked about, and what it wrote comes back.
    ///
    /// A record that does not count is shown as that and is asked
    /// nothing: nothing is taken from its key, and its key is not made a
    /// removed key. The rows beyond 256 are kept as left out on the new
    /// machine, each with its key.
    #[actix_web::test]
    async fn test_a_device_that_signs_hundreds_of_records_pushes_no_device_out_of_a_recovery() {
        let gone = two_gone();
        let s = &gone.s;
        let (k0, k1) = (s.key(0), s.key(1));
        let from = candidate(&s[0].latest());
        let statement = from.statement.statement.clone();
        assert_eq!(statement.devices[0].key, k0);
        // What the relay holds of the personal channel, and 300 records
        // that device 0 signed since.
        let mut personal = gone.at_the_relay[1].1.clone();
        let added: Vec<[u8; 32]> = (0..300u16)
            .map(|n| identity_of(1_000 + n).public_key())
            .collect();
        for (n, key) in added.iter().enumerate() {
            let device = Device::new(*key, &format!("added {n}")).unwrap();
            let record = Addition::under(&statement, device, k0, 1_800_000_000)
                .unwrap()
                .sign(&s[0].identity)
                .unwrap();
            personal.push(entry_by(
                &s[0].identity,
                &s[0].personal(),
                (2u64 << cordelia_core::protocol::REV_COUNT_BITS) + 1,
                &added_name(key).unwrap(),
                Value::Other(record.to_bytes().unwrap()),
                &[],
            ));
        }
        let statement_key = *phrase().statement_key().unwrap();
        let read =
            read_generation(&from, &statement_key, &s[0].secret(), &personal, s.now).unwrap();
        // Both devices of the statement, first: and then the records.
        assert_eq!((read.rows[0].key, read.rows[1].key), (k0, k1));
        assert!(read.rows[1].counts && read.rows[1].added_by.is_none());
        assert_eq!(read.rows.len(), RECOVERY_MAX_DEVICES_SHOWN);
        let counted = cordelia_core::protocol::MAX_COUNTED_DEVICES;
        assert!(read.rows[..counted].iter().all(|row| row.counts));
        assert!(read.rows[counted..].iter().all(|row| !row.counts));
        assert_eq!(read.not_shown.len(), 2 + 300 - RECOVERY_MAX_DEVICES_SHOWN);
        // One row for a key, shown or not.
        let mut keys: Vec<[u8; 32]> = read.rows.iter().map(|row| row.key).collect();
        keys.extend(read.not_shown.iter().map(|row| row.key));
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), 302);

        // Device 0 may be in someone else's hands, and so may each key
        // that it added and that counts. Device 1 is lost.
        let node = new_machine(9, &gone);
        let made = makes_as(&node, &from, &personal, |row, _| match row.key == k1 {
            true => Answer::Lost,
            false => Answer::OtherHands,
        });
        assert_eq!(made.shown.gone.len(), counted);
        assert!(made.shown.still_have.is_empty());
        assert_eq!(made.shown.not_shown.len(), 46);
        let (number, to_look) = follows(&node, &made).unwrap();
        assert_eq!(to_look.takes, [k1]);
        {
            let conn = db(&node.state);
            let held = person::held(&conn).unwrap().unwrap();
            let listed = &held.statement.statement;
            // The devices that count are removed, and no other key.
            assert_eq!(listed.removed.len(), counted);
            assert!(listed.removes(&k0) && listed.removes(&k1));
            let not_counted: Vec<&Row> = read.rows[counted..].iter().collect();
            assert_eq!(not_counted.len(), RECOVERY_MAX_DEVICES_SHOWN - counted);
            for row in not_counted.iter().copied().chain(&read.not_shown) {
                assert!(!listed.removes(&row.key) && !listed.lists(&row.key));
            }
            // What could not be shown is kept as left out, each with its
            // key: and nothing else is.
            let mut not_shown: Vec<[u8; 32]> = read.not_shown.iter().map(|row| row.key).collect();
            not_shown.sort_unstable();
            let mut noted = crate::look::not_shown(&conn).unwrap();
            noted.sort_unstable();
            assert_eq!(noted, not_shown);
            let left_out: Vec<[u8; 32]> = acts::left_out(&conn)
                .unwrap()
                .iter()
                .map(|kept| kept.key)
                .collect();
            assert_eq!(left_out, not_shown);
            let seen = crate::look::look(&conn, &node.state.identity, &AtRelays::default(), now())
                .unwrap();
            assert_eq!(seen.left_out.len(), not_shown.len());
            let written = |key: &[u8; 32]| cordelia_crypto::bech32::encode_public_key(key).unwrap();
            let keys: Vec<String> = seen
                .left_out
                .iter()
                .map(|kept| kept.key.clone().unwrap())
                .collect();
            assert_eq!(keys, not_shown.iter().map(written).collect::<Vec<_>>());
            let notice = &seen.notices[0];
            assert_eq!(notice.kind, "left_out");
            assert!(
                notice.says.contains("the recovery could not show it")
                    && notice.says.contains(&written(&not_shown[0])),
                "{}",
                notice.says
            );
        }

        // What the other device wrote comes back: its file in each name.
        let found = the_look(&node.state, number, &to_look).await;
        assert_eq!(found["carried"], 2, "{found}");
        assert_eq!(node.text(LAB, "b.md").as_deref(), Some("of device 1"));
        assert_eq!(node.text("desk", "d.md").as_deref(), Some("on the desk"));
        assert_eq!(node.text(LAB, "a.md"), None);
    }

    /// **No device pushes another out of a recovery by filling the 64**
    /// (decision 2026-10-04 §9, step 3). A statement lists device 0 and
    /// device 1. Device 1 added a phone since, which wrote a file.
    /// Device 0 signed 62 additions, which are read first and count: the
    /// phone's record then fails for the bound of 64, and for nothing
    /// else.
    ///
    /// The phone is shown with the device that added it, and is asked
    /// about where that device was not said to be in someone else's
    /// hands. The room for removed keys counts it. The look takes
    /// nothing from it. Said to be lost, its key is removed, and what it
    /// wrote comes in by the command that names its key, with the
    /// phrase.
    ///
    /// A key that counts and that a device of the statement added may add
    /// too. Two of the 62 signed records: one for the phone, and one for a
    /// key of nobody's. Each fails for the bound alone, as the record of
    /// device 1 does, and each is asked about under its adder only where
    /// that adder, and device 0, which added it, are not in someone
    /// else's hands.
    #[actix_web::test]
    async fn test_a_device_added_since_is_asked_about_where_only_the_bound_of_64_kept_it_out() {
        use Answer::{Have, Lost, OtherHands};
        const AT: u64 = 1_800_000_000;
        let mut gone_two = two_gone();
        let s = &gone_two.s;
        let (k0, k1) = (s.key(0), s.key(1));
        let from = candidate(&s[0].latest());
        let statement = from.statement.statement.clone();
        let listed: Vec<[u8; 32]> = statement.devices.iter().map(|one| one.key).collect();
        assert_eq!(listed, [k0, k1]);
        let phone = identity_of(500);
        let phone_key = phone.public_key();
        let band = 2u64 << cordelia_core::protocol::REV_COUNT_BITS;
        let record_by = |adder: &NodeIdentity, key: [u8; 32], label: &str| {
            let device = Device::new(key, label).unwrap();
            let record = Addition::under(&statement, device, adder.public_key(), AT)
                .unwrap()
                .sign(adder)
                .unwrap();
            entry_by(
                adder,
                &s[0].personal(),
                band + 1,
                &added_name(&key).unwrap(),
                Value::Other(record.to_bytes().unwrap()),
                &[],
            )
        };
        let mut personal = gone_two.at_the_relay[1].1.clone();
        personal.push(record_by(&s[1].identity, phone_key, "phone"));
        for n in 0..62u16 {
            let key = identity_of(1_000 + n).public_key();
            personal.push(record_by(&s[0].identity, key, &format!("added {n}")));
        }
        // Device 1 signed a record for one of the 62 too: that key
        // counts already, by the record of device 0.
        let counted_twice = identity_of(1_000).public_key();
        personal.push(record_by(&s[1].identity, counted_twice, "added 0, again"));
        // And two of the 62, which device 0 added, signed records: one
        // for the phone, and one for a key of nobody's. Neither is a
        // device of the statement, and each may add.
        let nobody = identity_of(600).public_key();
        let (k1001, k1002) = (
            identity_of(1_001).public_key(),
            identity_of(1_002).public_key(),
        );
        personal.push(record_by(&identity_of(1_001), phone_key, "their phone"));
        personal.push(record_by(&identity_of(1_002), nobody, "nobody"));
        // What the phone wrote in `lab`, as the relay holds it.
        let lab = s[0].own(LAB);
        let of_the_phone = entry_by(&phone, &lab, band + 1, "p.md", text("of the phone"), &[]);
        assert_eq!(gone_two.at_the_relay[2].0, lab);
        gone_two.at_the_relay[2].1.push(of_the_phone);

        let statement_key = *phrase().statement_key().unwrap();
        let read =
            read_generation(&from, &statement_key, &s[0].secret(), &personal, s.now).unwrap();
        // The two devices, the 62 that count, and then the phone and
        // the key of nobody's, in order of key: each with the keys that
        // added it, and that only the bound kept it out. One row for a
        // key: of the phone's two records, the one whose adder has the
        // lower key is shown.
        let counted = cordelia_core::protocol::MAX_COUNTED_DEVICES;
        assert_eq!(counted, 64);
        assert_eq!(read.rows.len(), counted + 2);
        assert_eq!((read.rows[0].key, read.rows[1].key), (k0, k1));
        let all_count = |rows: &[Row]| rows.iter().all(|row| row.counts && row.no_room.is_empty());
        assert!(all_count(&read.rows[..counted]));
        let place = |key: [u8; 32]| read.rows.iter().position(|row| row.key == key).unwrap();
        let (phone_at, nobody_at) = (place(phone_key), place(nobody));
        let mut after_those_that_count = [phone_at, nobody_at];
        after_those_that_count.sort_unstable();
        assert_eq!(after_those_that_count, [counted, counted + 1]);
        assert_eq!(phone_at < nobody_at, phone_key < nobody);
        let of_the_phone = &read.rows[phone_at];
        let (shown_by, phone_label) = match k1 < k1001 {
            true => (k1, "phone"),
            false => (k1001, "their phone"),
        };
        assert_eq!(of_the_phone.label, phone_label);
        assert!(!of_the_phone.counts);
        assert_eq!(of_the_phone.added_by, Some((shown_by, AT)));
        let mut by = vec![(k1, AT), (k1001, AT)];
        by.sort_unstable();
        assert_eq!(of_the_phone.no_room, by);
        // The record that one of the 62 signed for a key of nobody's
        // fails for the bound alone too: its adder may add.
        let other = &read.rows[nobody_at];
        assert_eq!((other.key, other.counts), (nobody, false));
        assert_eq!(other.no_room, [(k1002, AT)]);
        // The room for removed keys is worked out with both, before
        // anything is asked.
        assert_eq!(
            room(&statement, None, &read.rows, &[9; 32]).asked,
            counted + 2
        );

        // What is said of the two devices, and of the 62: each of those
        // was added by device 0.
        let said = |of_0: Answer, of_1: Answer| -> Vec<Answer> {
            let mut answers = vec![of_0, of_1];
            answers.extend(vec![OtherHands; counted - 2]);
            answers
        };
        // The phone is asked about where device 1 was not said to be in
        // someone else's hands, whatever was said of device 0: the other
        // key that added it, one of the 62, may be in someone else's
        // hands here.
        for of_0 in [Have, Lost, OtherHands] {
            for (of_1, asked) in [(Have, true), (Lost, true), (OtherHands, false)] {
                let so_far = said(of_0, of_1);
                let under = asked_for_room(&read.rows, &so_far, phone_at);
                assert_eq!(under, asked.then_some((k1, AT)), "{of_0:?} {of_1:?}");
                // Nothing is asked of what such a key added.
                assert_eq!(asked_for_room(&read.rows, &so_far, nobody_at), None);
            }
        }
        // Where device 1 may be in someone else's hands, the phone is
        // asked about for the record of the other key that added it:
        // where that key, and device 0, which added it, are not.
        let with_the_62 = |of_0: Answer, of_1: Answer, of_the_62: Answer| -> Vec<Answer> {
            let mut answers = vec![of_0, of_1];
            answers.extend(vec![of_the_62; counted - 2]);
            answers
        };
        for (of_0, of_the_62, asked) in [
            (Lost, Lost, true),
            (Have, Have, true),
            (Lost, OtherHands, false),
            (OtherHands, Lost, false),
            (OtherHands, Have, false),
        ] {
            let so_far = with_the_62(of_0, OtherHands, of_the_62);
            let (of_the_phone, of_nobody) = (
                asked_for_room(&read.rows, &so_far, phone_at),
                asked_for_room(&read.rows, &so_far, nobody_at),
            );
            let why = format!("{of_0:?} {of_the_62:?}");
            assert_eq!(of_the_phone, asked.then_some((k1001, AT)), "{why}");
            assert_eq!(of_nobody, asked.then_some((k1002, AT)), "{why}");
        }
        // Not before its adder was asked about. A row that counts is
        // asked about as that.
        assert_eq!(asked_for_room(&read.rows, &[], phone_at), None);
        assert_eq!(asked_for_room(&read.rows, &[OtherHands], phone_at), None);
        assert_eq!(asked_for_room(&read.rows, &said(Lost, Lost), 1), None);
        let all_lost = vec![Lost; counted + 2];
        assert_eq!(
            asked_for_room(&read.rows, &all_lost, nobody_at),
            Some((k1002, AT))
        );
        assert_eq!(asked_for_room(&read.rows, &all_lost, counted + 2), None);
        assert!(gone(&read.rows, &all_lost).contains(&nobody));
        assert_eq!(gone(&read.rows, &all_lost).len(), counted + 2);

        // As answered: gone removes it, and the look takes nothing from
        // it, whatever is said.
        let with = |of_1: Answer, of_the_phone: Answer| -> Vec<Answer> {
            let mut answers = said(OtherHands, of_1);
            answers.extend([Have, Have]);
            answers[phone_at] = of_the_phone;
            answers
        };
        assert!(gone(&read.rows, &with(Lost, Lost)).contains(&phone_key));
        assert!(gone(&read.rows, &with(Lost, OtherHands)).contains(&phone_key));
        assert!(!gone(&read.rows, &with(Lost, Have)).contains(&phone_key));
        // What a device in someone else's hands added is not asked
        // about: whatever is said of it, it is not removed.
        assert!(!gone(&read.rows, &with(OtherHands, Lost)).contains(&phone_key));
        for of_the_phone in [Have, Lost, OtherHands] {
            assert_eq!(takes(&read.rows, &with(Lost, of_the_phone)), [k1]);
        }

        // The recovery: device 0 may be in someone else's hands, with
        // what it added; device 1 is lost, and so is the phone.
        let node = new_machine(9, &gone_two);
        let made = makes_as(&node, &from, &personal, |row, _| {
            match row.key == k1 || row.key == phone_key || row.key == nobody {
                true => Lost,
                false => OtherHands,
            }
        });
        assert_eq!(made.shown.gone.len(), counted + 1);
        assert!(
            made.shown
                .gone
                .contains(&(phone_key, phone_label.to_string()))
        );
        assert!(made.shown.still_have.is_empty());
        let (number, to_look) = follows(&node, &made).unwrap();
        assert_eq!(to_look.takes, [k1]);
        {
            let conn = db(&node.state);
            let held = person::held(&conn).unwrap().unwrap();
            assert!(held.statement.statement.removes(&phone_key));
            // The key of nobody's was not asked about: the key that
            // added it may be in someone else's hands.
            assert!(!held.statement.statement.removes(&nobody));
        }
        // The look takes what device 1 wrote, and nothing of the phone:
        // it says how much the phone signed that the new channels lack.
        let found = the_look(&node.state, number, &to_look).await;
        assert_eq!(found["carried"], 2, "{found}");
        assert_eq!(node.text(LAB, "b.md").as_deref(), Some("of device 1"));
        assert_eq!(node.text(LAB, "p.md"), None);
        let lacking = found["lacking"].as_array().unwrap();
        let of_the_phone = lacking
            .iter()
            .find(|lacks| lacks["key"] == hex::encode(phone_key));
        let of_the_phone = of_the_phone.unwrap_or_else(|| panic!("{found}"));
        assert_eq!(
            (&of_the_phone["label"], &of_the_phone["versions"]),
            (&json!(phone_label), &json!(1))
        );
        assert_eq!(of_the_phone["names"], json!([LAB]));

        // Its key is a removed key: what it wrote comes in by the
        // command that names it, with the phrase.
        let said = carrying::look_from(&node.state, LAB, &[phone_label.to_string()])
            .await
            .unwrap();
        assert_eq!(said["empty"], 1, "{said}");
        let word = node.word(
            &phrase(),
            &Allows::From {
                name: LAB.into(),
                keys: vec![hex::encode(phone_key)],
                above: vec![],
            },
        );
        let done = carrying::take_from(&node.state, &word).await.unwrap();
        assert_eq!(done["carried"], 1, "{done}");
        assert_eq!(node.text(LAB, "p.md").as_deref(), Some("of the phone"));
    }

    /// **A device added since, kept out by the 64, is asked about where
    /// its adder may add** (decision 2026-10-04 §9, step 3): also where
    /// that adder is no device of the statement, but a key that counts
    /// and that a device of the statement added. A chain is two long.
    ///
    /// A statement lists device 0 and device 1. Device 0 added 61 keys
    /// since, a desktop among them, and all of them count. The desktop
    /// added two: the first that is read counts, as the 64th, and the
    /// other, a tablet, finds no room. The one that counts added a third
    /// key: it may not add, and that record fails for that.
    ///
    /// The tablet is asked about under the desktop, where the desktop
    /// was said to be one that the person still has, or that is lost or
    /// broken, and neither it nor device 0, which added it, may be in
    /// someone else's hands. In each case the look takes nothing from
    /// the tablet, and it is a removed key only where it was asked about
    /// and said to be gone. A name that only the tablet listed is not
    /// carried, and is named among the names that are left.
    #[test]
    fn test_a_device_kept_out_by_the_64_is_asked_about_where_its_adder_may_add() {
        use Answer::{Have, Lost, NotAsked, OtherHands};
        const AT: u64 = 1_800_000_000;
        let gone_two = two_gone();
        let s = &gone_two.s;
        let (k0, k1) = (s.key(0), s.key(1));
        let from = candidate(&s[0].latest());
        let statement = from.statement.statement.clone();
        let listed: Vec<[u8; 32]> = statement.devices.iter().map(|one| one.key).collect();
        assert_eq!(listed, [k0, k1]);
        let band = 2u64 << cordelia_core::protocol::REV_COUNT_BITS;
        let personal_secret = s[0].personal();
        let record_by = |adder: &NodeIdentity, key: [u8; 32], label: &str| {
            let device = Device::new(key, label).unwrap();
            let record = Addition::under(&statement, device, adder.public_key(), AT)
                .unwrap()
                .sign(adder)
                .unwrap();
            entry_by(
                adder,
                &personal_secret,
                band + 1,
                &added_name(&key).unwrap(),
                Value::Other(record.to_bytes().unwrap()),
                &[],
            )
        };
        let desktop = identity_of(700);
        let kx = desktop.public_key();
        let (one, other) = (identity_of(701), identity_of(702));
        let third = identity_of(703).public_key();
        let base = {
            let mut personal = gone_two.at_the_relay[1].1.clone();
            for n in 0..60u16 {
                let key = identity_of(1_000 + n).public_key();
                personal.push(record_by(&s[0].identity, key, &format!("added {n}")));
            }
            personal.push(record_by(&s[0].identity, kx, "desktop"));
            personal.push(record_by(&desktop, one.public_key(), "one"));
            personal.push(record_by(&desktop, other.public_key(), "another"));
            personal
        };
        let statement_key = *phrase().statement_key().unwrap();
        let reads = |handed: &[CheckedEntry]| {
            read_generation(&from, &statement_key, &s[0].secret(), handed, s.now).unwrap()
        };
        // Of the two that the desktop added, the first that is read
        // counts, and the other is the tablet.
        let first = reads(&base);
        let counts = |key: [u8; 32]| first.rows.iter().any(|row| row.key == key && row.counts);
        let (counted_one, tablet) = match counts(one.public_key()) {
            true => (&one, &other),
            false => (&other, &one),
        };
        let (ky, kt) = (counted_one.public_key(), tablet.public_key());
        assert!(counts(ky) && !counts(kt));
        // The one that counts adds a third key, and the tablet says that
        // it syncs a name of its own.
        let mut personal = base.clone();
        personal.push(record_by(counted_one, third, "third"));
        // It signs a record for the tablet too. It may not add, so that
        // record fails for that, and not for the bound: the tablet's row
        // is by the record that fails only for the bound, which the
        // desktop signed, whichever of the two keys is the lower.
        personal.push(record_by(counted_one, kt, "the tablet, by another"));
        let word = names::word_name("theirs");
        let personal_channel = derive::personal_secret(&s[0].secret()).unwrap();
        personal.push(entry_by(
            tablet,
            &personal_channel,
            band + 1,
            &word,
            text("it syncs this"),
            &[],
        ));
        let read = reads(&personal);

        // Both devices, the 62 that count, the tablet, and the third.
        let counted = cordelia_core::protocol::MAX_COUNTED_DEVICES;
        assert_eq!(read.rows.len(), counted + 2);
        assert!(read.rows[..counted].iter().all(|row| row.counts));
        let place = |key: [u8; 32]| read.rows.iter().position(|row| row.key == key).unwrap();
        let (x_at, t_at, third_at) = (place(kx), place(kt), place(third));
        // The desktop is a row that counts, under device 0, and so comes
        // before every row that does not count: it is asked about before
        // the tablet is reached.
        assert_eq!(read.rows[x_at].added_by, Some((k0, AT)));
        assert!(x_at < counted && place(ky) == x_at + 1);
        assert_eq!((t_at, third_at), (counted, counted + 1));
        let of_the_tablet = &read.rows[t_at];
        assert!(!of_the_tablet.counts);
        assert_eq!(of_the_tablet.added_by, Some((kx, AT)));
        assert_ne!(of_the_tablet.label, "the tablet, by another");
        assert_eq!(of_the_tablet.no_room, [(kx, AT)]);
        // The third: its adder counts, and was added by a device added
        // since, so it may not add. The record fails for that, and not
        // for the bound: nothing is asked of it, whatever was said.
        let of_the_third = &read.rows[third_at];
        assert_eq!(of_the_third.added_by, Some((ky, AT)));
        assert!(!of_the_third.counts && of_the_third.no_room.is_empty());
        assert_eq!(
            room(&statement, None, &read.rows, &[9; 32]).asked,
            counted + 1
        );

        // What was said of device 0, of the desktop, and then of the
        // tablet: every other row is lost.
        let said = |of_0: Answer, of_x: Answer, of_t: Option<Answer>| -> Vec<Answer> {
            let mut answers = vec![Lost; counted];
            (answers[0], answers[x_at]) = (of_0, of_x);
            answers.extend(of_t);
            answers
        };
        let asked =
            |of_0: Answer, of_x: Answer| asked_for_room(&read.rows, &said(of_0, of_x, None), t_at);
        // Asked about: the desktop may add, and neither it nor the
        // device that added it may be in someone else's hands.
        for (of_0, of_x) in [(Lost, Lost), (Have, Lost), (Lost, Have), (Have, Have)] {
            assert_eq!(asked(of_0, of_x), Some((kx, AT)), "{of_0:?} {of_x:?}");
        }
        // Its adder may be in someone else's hands: not asked.
        for of_0 in [Have, Lost, OtherHands] {
            assert_eq!(asked(of_0, OtherHands), None, "{of_0:?}");
        }
        // The device that added its adder may be: not asked.
        for of_x in [Have, Lost] {
            assert_eq!(asked(OtherHands, of_x), None, "{of_x:?}");
        }
        // Nor before its adder was asked about.
        assert_eq!(asked_for_room(&read.rows, &[Lost, Lost], t_at), None);
        // The third is asked about in none of them.
        let all_lost = vec![Lost; counted + 2];
        assert_eq!(asked_for_room(&read.rows, &all_lost, third_at), None);
        assert!(!gone(&read.rows, &all_lost).contains(&third));

        // In each of the three, the look takes nothing from the tablet,
        // whatever is said of it: and it is a removed key only where it
        // was asked about and said to be gone.
        for (of_0, of_x, is_asked) in [
            (Lost, Lost, true),
            (Lost, OtherHands, false),
            (OtherHands, Lost, false),
        ] {
            for of_t in [Have, Lost, OtherHands, NotAsked] {
                let answers = said(of_0, of_x, Some(of_t));
                let why = format!("{of_0:?} {of_x:?} {of_t:?}");
                assert!(!takes(&read.rows, &answers).contains(&kt), "{why}");
                let goes = is_asked && matches!(of_t, Lost | OtherHands);
                assert_eq!(gone(&read.rows, &answers).contains(&kt), goes, "{why}");
            }
        }

        // A name that only the tablet listed: its word is not taken,
        // since its key does not count. The recovery does not carry the
        // name, and names it among those it left: where the tablet was
        // asked about and said to be lost, and where it was not asked.
        assert!(read.names.contains(&("theirs".to_string(), Vec::new())));
        assert!(!first.names.iter().any(|(name, _)| name == "theirs"));
        for (of_x, of_t) in [(Lost, Lost), (Lost, Have), (OtherHands, NotAsked)] {
            let mut answers = said(Lost, of_x, Some(of_t));
            answers.push(NotAsked);
            let names = names_in_order(&read, &answers, &[], RECOVERY_MAX_NAMES);
            assert!(!names.carried.contains(&"theirs".to_string()), "{names:?}");
            assert_eq!(names.only_other_hands, ["theirs"], "{of_x:?} {of_t:?}");
            assert!(names.over_the_bound.is_empty());
        }
    }

    /// **A recovery counts the keys that a record of an addition was read
    /// for and that have no row at all** (decision 2026-10-04 §9, step
    /// 3). A reader keeps 256 records that do not count, the oldest it
    /// saw going first: where more were written, a record that was read
    /// is not among those it kept, and its key has no row, shown or not.
    ///
    /// A statement lists device 0 and device 1, and removes device 2.
    /// Device 0 signed 62 additions, which are read first and count, and
    /// a record for device 1. Device 1 added a phone since, which only
    /// the bound of 64 keeps out, and signed a record for the key that
    /// the statement removes. One of the 62 then signed records for keys
    /// of nobody's: each fails for the bound alone, and is read after
    /// those three.
    ///
    /// With no more records that do not count than a reader keeps, each
    /// key has a row and the count is 0. With more, the oldest are let
    /// go, the phone's among them: the count says how many keys have no
    /// row, and neither a device of the statement nor a key that it
    /// removes is counted.
    #[test]
    fn test_a_recovery_counts_the_keys_whose_record_was_read_and_that_have_no_row() {
        const AT: u64 = 1_800_000_000;
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1], &[2]);
        let (k0, k1, removed) = (s.key(0), s.key(1), s.key(2));
        let from = candidate(&s[0].latest());
        let statement = from.statement.statement.clone();
        assert!(statement.lists(&k0) && statement.lists(&k1) && statement.removes(&removed));
        let band = statement.number << cordelia_core::protocol::REV_COUNT_BITS;
        let personal = s[0].personal();
        let record_by = |adder: &NodeIdentity, key: [u8; 32], label: &str| {
            let device = Device::new(key, label).unwrap();
            let record = Addition::under(&statement, device, adder.public_key(), AT)
                .unwrap()
                .sign(adder)
                .unwrap();
            entry_by(
                adder,
                &personal,
                band + 1,
                &added_name(&key).unwrap(),
                Value::Other(record.to_bytes().unwrap()),
                &[],
            )
        };
        let phone = identity_of(500).public_key();
        let not_read = identity_of(600).public_key();
        let (counted, kept) = (
            cordelia_core::protocol::MAX_COUNTED_DEVICES,
            cordelia_core::protocol::MAX_NOT_COUNTED_RECORDS,
        );
        assert_eq!((counted, kept, RECOVERY_MAX_DEVICES_SHOWN), (64, 256, 256));
        let base = {
            let mut handed = s[0].stored_in(&personal);
            for n in 0..62u16 {
                let key = identity_of(1_000 + n).public_key();
                handed.push(record_by(&s[0].identity, key, &format!("added {n}")));
            }
            handed.push(record_by(&s[0].identity, k1, "device 1, again"));
            handed.push(record_by(&s[1].identity, phone, "phone"));
            handed.push(record_by(&s[1].identity, removed, "removed"));
            // An entry of device 1's that holds a record which device 0
            // signed, for a key of nobody's: it is not its signer's own
            // word, and is taken as no record. Its key has no row, and
            // is not counted: no record was read for it.
            let device = Device::new(not_read, "not read").unwrap();
            let record = Addition::under(&statement, device, k0, AT)
                .unwrap()
                .sign(&s[0].identity)
                .unwrap();
            handed.push(entry_by(
                &s[1].identity,
                &personal,
                band + 1,
                &added_name(&not_read).unwrap(),
                Value::Other(record.to_bytes().unwrap()),
                &[],
            ));
            handed
        };
        // One of the 62 signs `more` records, for keys of nobody's.
        let nobodys = |n: usize| identity_of(2_000 + n as u16).public_key();
        let statement_key = *phrase().statement_key().unwrap();
        let reads = |more: usize| {
            let mut handed = base.clone();
            for n in 0..more {
                handed.push(record_by(&identity_of(1_000), nobodys(n), "nobody's"));
            }
            read_generation(&from, &statement_key, &s[0].secret(), &handed, s.now).unwrap()
        };
        let has_a_row = |read: &Generation, key: [u8; 32]| {
            let rows = read.rows.iter().chain(&read.not_shown);
            rows.filter(|row| row.key == key).count() == 1
        };
        // How many of the keys that a record was handed for have no row,
        // and are in neither list of the statement: counted here from
        // the keys themselves.
        let with_no_row = |read: &Generation, more: usize| {
            let mut keys: Vec<[u8; 32]> = (0..62u16)
                .map(|n| identity_of(1_000 + n).public_key())
                .collect();
            keys.extend([k1, phone, removed]);
            keys.extend((0..more).map(nobodys));
            let in_no_list = |key: &&[u8; 32]| !statement.lists(key) && !statement.removes(key);
            let listed = keys.iter().filter(in_no_list);
            listed.filter(|key| !has_a_row(read, **key)).count()
        };

        // Three records that do not count, and 253 more: as many as a
        // reader keeps. Each key has a row, and the count is 0. The
        // phone is one that only the bound of 64 kept out, under the
        // device that added it.
        let within = reads(kept - 3);
        assert_eq!(within.no_row, 0);
        assert_eq!(with_no_row(&within, kept - 3), 0);
        assert!(has_a_row(&within, phone) && has_a_row(&within, removed));
        assert!(!has_a_row(&within, not_read));
        // (The record for device 1 is one of those kept, and is no row
        // of its own: device 1 has its row as a device of the statement.)
        assert_eq!(within.rows.len(), RECOVERY_MAX_DEVICES_SHOWN);
        assert_eq!(within.not_shown.len(), counted - 1);
        assert!(within.rows[..counted].iter().all(|row| row.counts));
        let of_the_phone = &within.rows[counted..];
        let of_the_phone = of_the_phone.iter().find(|row| row.key == phone).unwrap();
        assert_eq!(of_the_phone.no_room, [(k1, AT)]);
        // With no record but those of the 62, and with none at all.
        let few = read_generation(&from, &statement_key, &s[0].secret(), &base, s.now).unwrap();
        assert_eq!((few.no_row, few.rows.len()), (0, counted + 2));
        let none = read_generation(&from, &statement_key, &s[0].secret(), &[], s.now).unwrap();
        assert_eq!((none.no_row, none.rows.len()), (0, 2));

        // Three more than a reader keeps: the three oldest are let go.
        // The record for device 1, which has its row as a device of the
        // statement; the record for the key that the statement removes,
        // which is not counted; and the phone's. The count is 1, and
        // the phone's is the one key with no row: it is not among the
        // rows that are shown, nor among those that are not.
        let over = reads(kept);
        assert_eq!(over.no_row, 1);
        assert_eq!(with_no_row(&over, kept), 1);
        assert!(!has_a_row(&over, phone) && !has_a_row(&over, removed));
        assert!(has_a_row(&over, k1));
        assert!((0..kept).all(|n| has_a_row(&over, nobodys(n))));
        assert_eq!(over.rows.len(), RECOVERY_MAX_DEVICES_SHOWN);
        assert_eq!(over.not_shown.len(), counted);
        // Nothing is asked of a key with no row, and nothing is taken
        // from it or removed: only the rows are answered.
        let all_lost = vec![Answer::Lost; over.rows.len()];
        assert!(!gone(&over.rows, &all_lost).contains(&phone));
        assert!(!takes(&over.rows, &all_lost).contains(&phone));

        // One more: a key of nobody's has no row either, and the count
        // is 2.
        let further = reads(kept + 1);
        assert_eq!(further.no_row, 2);
        assert_eq!(with_no_row(&further, kept + 1), 2);
        assert!(!has_a_row(&further, phone));
    }

    /// **A recovery says of each row whether a record that was read for
    /// its key is not among the records kept** (decision 2026-10-04 §9,
    /// step 3). A reader keeps 256 records that do not count, the oldest
    /// it saw going first: where the record by which a key would be
    /// asked about is the one that went, and another record of the key
    /// is kept, the key has a row, by that other record, and the count
    /// of keys with no row does not tell of it.
    ///
    /// A statement lists device 0 and device 1, and removes device 2.
    /// Device 0 added 61 keys, which count. The first of them, in order
    /// of key, added a key that counts as the 64th, and may not add; and
    /// it signed a record for the key that the statement removes. The
    /// second, which may add, signed a record for a tablet: it fails only
    /// for the bound of 64. The key that may not add signed a record for
    /// the tablet too, one for a watch, and one for the removed key: each
    /// fails for another reason than the bound. Others of the 61 signed
    /// records for keys that count already. The entries are read in the
    /// order of their signers, so the record for the removed key is the
    /// first that does not count to be read, and the tablet's, under the
    /// key that may add, the second.
    ///
    /// With as many records that do not count as a reader keeps, the
    /// tablet's row is by the record that fails only for the bound, and
    /// no row is flagged. With two more, both of those go. The tablet's
    /// row is by the other record, has nothing that fails only for the
    /// bound, and is flagged. The watch's row, none of whose records
    /// went, is not; nor is the row of the key that the statement
    /// removes, which stays removed whatever a record says. Every key
    /// has a row, and the count of keys with none is 0.
    #[test]
    fn test_a_row_says_that_a_record_read_for_its_key_was_not_kept() {
        const AT: u64 = 1_800_000_000;
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1], &[2]);
        let (k0, k1, removed) = (s.key(0), s.key(1), s.key(2));
        let from = candidate(&s[0].latest());
        let statement = from.statement.statement.clone();
        assert!(statement.lists(&k0) && statement.lists(&k1) && statement.removes(&removed));
        let band = statement.number << cordelia_core::protocol::REV_COUNT_BITS;
        let personal = s[0].personal();
        let record_by = |adder: &NodeIdentity, key: [u8; 32], label: &str| {
            let device = Device::new(key, label).unwrap();
            let record = Addition::under(&statement, device, adder.public_key(), AT)
                .unwrap()
                .sign(adder)
                .unwrap();
            entry_by(
                adder,
                &personal,
                band + 1,
                &added_name(&key).unwrap(),
                Value::Other(record.to_bytes().unwrap()),
                &[],
            )
        };
        // The 61 that device 0 added, in order of key: the entries of a
        // key that the statement does not list are read in that order.
        let mut added: Vec<NodeIdentity> = (0..61u16).map(|n| identity_of(1_000 + n)).collect();
        added.sort_by_key(NodeIdentity::public_key);
        let (first, second) = (&added[0], &added[1]);
        // The key that the first of them adds: it counts as the 64th,
        // and may not add. Its entries are read after the second's.
        let may_not_add = (2_000..2_100u16)
            .map(identity_of)
            .find(|one| one.public_key() > second.public_key())
            .unwrap();
        let (tablet, watch) = (identity_of(500).public_key(), identity_of(501).public_key());
        let counted = cordelia_core::protocol::MAX_COUNTED_DEVICES;
        let kept = cordelia_core::protocol::MAX_NOT_COUNTED_RECORDS;
        let base = {
            let mut handed = s[0].stored_in(&personal);
            for one in &added {
                handed.push(record_by(&s[0].identity, one.public_key(), "added"));
            }
            handed.push(record_by(first, may_not_add.public_key(), "the 64th"));
            handed.push(record_by(first, removed, "removed"));
            handed.push(record_by(second, tablet, "tablet"));
            handed.push(record_by(&may_not_add, tablet, "the tablet, by another"));
            handed.push(record_by(&may_not_add, watch, "watch"));
            handed.push(record_by(&may_not_add, removed, "removed, by another"));
            handed
        };
        // Records for keys that count already, signed by the others of
        // the 61: each is kept as not counted, and is no row of its own.
        let mut counting: Vec<[u8; 32]> = added.iter().map(NodeIdentity::public_key).collect();
        counting.extend([k0, k1, may_not_add.public_key()]);
        let fillers: Vec<CheckedEntry> = added[2..]
            .iter()
            .flat_map(|signer| {
                let others = counting.iter().filter(|key| **key != signer.public_key());
                others.map(|key| record_by(signer, *key, "counts already"))
            })
            .take(kept)
            .collect();
        assert_eq!(fillers.len(), kept);
        let statement_key = *phrase().statement_key().unwrap();
        let reads = |more: usize| {
            let mut handed = base.clone();
            handed.extend(fillers[..more].iter().cloned());
            read_generation(&from, &statement_key, &s[0].secret(), &handed, s.now).unwrap()
        };
        let row_of = |read: &Generation, key: [u8; 32]| -> Row {
            let of_it = read.rows.iter().find(|row| row.key == key);
            of_it.cloned().unwrap()
        };
        let flagged = |read: &Generation| -> Vec<[u8; 32]> {
            let rows = read.rows.iter().chain(&read.not_shown);
            rows.filter(|row| row.record_let_go)
                .map(|row| row.key)
                .collect()
        };

        // Five records that do not count, and 251 more: as many as a
        // reader keeps. The tablet's row is by the record that fails only
        // for the bound, under the key that may add.
        let within = reads(kept - 5);
        assert_eq!(within.rows.len(), counted + 3);
        assert!(within.rows[..counted].iter().all(|row| row.counts));
        let of_the_tablet = row_of(&within, tablet);
        assert_eq!(of_the_tablet.added_by, Some((second.public_key(), AT)));
        assert_eq!(of_the_tablet.no_room, [(second.public_key(), AT)]);
        assert!(!of_the_tablet.counts && !of_the_tablet.record_let_go);
        assert!(flagged(&within).is_empty());
        assert_eq!(within.no_row, 0);

        // One more: the oldest that does not count is let go, which is
        // the first record for the key that the statement removes. That
        // key stays removed whatever a record says of it: its row, by
        // its other record, is not flagged.
        let one_over = reads(kept - 4);
        let of_the_removed = row_of(&one_over, removed);
        assert_eq!(
            of_the_removed.added_by,
            Some((may_not_add.public_key(), AT))
        );
        assert!(!of_the_removed.counts && !of_the_removed.record_let_go);
        assert_eq!(row_of(&one_over, tablet), of_the_tablet);
        assert!(flagged(&one_over).is_empty());

        // And one more: the tablet's record under the key that may add
        // is let go too. The tablet has a row all the same, by the record
        // of the key that may not add: it fails for that, and nothing of
        // it fails only for the bound.
        let over = reads(kept - 3);
        assert_eq!(over.rows.len(), counted + 3);
        let of_the_tablet = row_of(&over, tablet);
        assert_eq!(of_the_tablet.added_by, Some((may_not_add.public_key(), AT)));
        assert_eq!(of_the_tablet.label, "the tablet, by another");
        assert!(!of_the_tablet.counts && of_the_tablet.no_room.is_empty());
        assert!(of_the_tablet.record_let_go);
        assert_eq!(flagged(&over), [tablet]);
        // The watch's row is as it was: none of its records went.
        let of_the_watch = row_of(&over, watch);
        assert_eq!(of_the_watch, row_of(&within, watch));
        assert!(!of_the_watch.counts && !of_the_watch.record_let_go);
        assert!(of_the_watch.no_room.is_empty());
        // Every key has a row: the count of keys with none does not
        // tell of the tablet.
        assert_eq!(over.no_row, 0);
        // Nothing else has changed for it: it is not asked about, and
        // whatever is said of it, nothing is taken from it and its key
        // is not removed.
        let at = over.rows.iter().position(|row| row.key == tablet).unwrap();
        let all_lost = vec![Answer::Lost; over.rows.len()];
        assert_eq!(asked_for_room(&over.rows, &all_lost, at), None);
        assert!(!gone(&over.rows, &all_lost).contains(&tablet));
        assert!(!takes(&over.rows, &all_lost).contains(&tablet));
    }

    /// Whether the answers of a recovery could all be kept is worked out
    /// before anything is asked (decision 2026-10-04 §9, step 3): a
    /// statement has room for 256 removed keys, and lists every key
    /// removed so far, also those of a statement made apart. A record
    /// that does not count is not asked about, and nor is the machine
    /// itself, or a key that is removed already.
    #[test]
    fn test_whether_every_answer_could_be_kept_is_known_before_anything_is_asked() {
        let (s, handed) = six_devices();
        let from = candidate(&s[0].latest());
        let statement_key = *phrase().statement_key().unwrap();
        let read = read_generation(&from, &statement_key, &s[0].secret(), &handed, s.now).unwrap();
        let mut statement = from.statement.statement.clone();
        let own = [9u8; 32];
        let all = room(&statement, None, &read.rows, &own);
        assert_eq!(
            all,
            Room {
                removed: 0,
                asked: 6,
                can_go: MAX_STATEMENT_REMOVED
            }
        );
        assert!(all.for_every_answer());
        // The machine itself is not asked about, and nor is a record
        // that does not count.
        assert_eq!(room(&statement, None, &read.rows, &s.key(0)).asked, 5);
        let mut rows = read.rows.clone();
        rows[5].counts = false;
        assert_eq!(room(&statement, None, &rows, &own).asked, 5);

        // 251 keys are removed already: five of the six can go.
        statement.removed = (0..251u16)
            .map(|n| identity_of(2_000 + n).public_key())
            .collect();
        let tight = room(&statement, None, &read.rows, &own);
        assert_eq!((tight.removed, tight.asked, tight.can_go), (251, 6, 5));
        assert!(!tight.for_every_answer());
        statement.removed.pop();
        assert!(room(&statement, None, &read.rows, &own).for_every_answer());
        // A statement made apart removed two keys more, one of them a
        // key that the other removed too: each is counted once. One is a
        // device that is shown here: it is removed whatever is said.
        let mut apart = from.statement.statement.clone();
        apart.removed = vec![statement.removed[0], [7; 32], s.key(5)];
        let both = room(&statement, Some(&apart), &read.rows, &own);
        assert_eq!((both.removed, both.asked, both.can_go), (252, 5, 4));
        assert!(!both.for_every_answer());
    }

    fn clone(made: &Made) -> Made {
        Made {
            entry: made.entry.clone(),
            statement_key: made.statement_key,
            left: made.left.clone(),
            shown: made.shown.clone(),
            word: made.word.clone(),
            names: made.names.clone(),
            cut_short: made.cut_short,
        }
    }

    /// A device that the person still has is in neither list of the
    /// recovery's statement (decision 2026-10-04 §9, steps 3 and 6): the
    /// look takes what it wrote, and the new machine shows it as not in
    /// the last change, by its label, until it is added again.
    #[actix_web::test]
    async fn test_a_device_that_the_person_still_has_is_in_no_list_and_is_shown_as_that() {
        let gone = two_gone();
        let s = &gone.s;
        let (k0, k1) = (s.key(0), s.key(1));
        let from = candidate(&s[0].latest());
        let node = new_machine(9, &gone);
        let made = makes(
            &node,
            &from,
            &gone.at_the_relay[1].1,
            &[Answer::Lost, Answer::Have],
        );
        assert_eq!(made.names.carried, ["desk", LAB]);
        let (number, to_look) = follows(&node, &made).unwrap();
        assert_eq!(to_look.takes, [k0, k1]);
        {
            let conn = db(&node.state);
            let statement = person::held(&conn).unwrap().unwrap().statement.statement;
            assert!(statement.removes(&k0));
            assert!(!statement.removes(&k1) && !statement.lists(&k1));
            let seen = crate::look::look(&conn, &node.state.identity, &AtRelays::default(), now())
                .unwrap();
            let left_out: Vec<&str> = seen.left_out.iter().map(|k| k.label.as_str()).collect();
            assert_eq!(left_out, ["device 1"]);
            // It was shown, and the person said that they still have it:
            // its key is the one that it prints, and is not said here.
            assert_eq!(seen.left_out[0].key, None);
            let notice = seen.notices.iter().find(|notice| notice.kind == "left_out");
            let says = &notice.unwrap().says;
            assert!(
                says.ends_with("is not in the last change: add it again, or it was meant to go"),
                "{says}"
            );
            assert_eq!(seen.removed.len(), 1);
            assert_eq!(seen.removed[0].label, "device 0");
        }
        let found = the_look(&node.state, number, &to_look).await;
        // Both names, from both devices: a.md, b.md and old.md in the
        // one, and d.md in the other.
        assert_eq!(found["carried"], 4, "{found}");
        assert_eq!(found["carried_names"], 2);
        assert_eq!(found["lacking"], json!([]));
        assert_eq!(node.text(LAB, "b.md").as_deref(), Some("of device 1"));
        assert_eq!(node.text("desk", "d.md").as_deref(), Some("on the desk"));
    }

    /// A recovery that is cut short, and the one after it (decision
    /// 2026-10-04 §9). The first machine carried what the two devices
    /// had written and sent only a part of it before it was lost. The
    /// next recovery starts from the first machine's statement, under
    /// which it alone counts: it brings back what that machine had sent,
    /// by the names that it listed, and says that the earlier recovery
    /// was cut short. What the two devices wrote in the files that it
    /// had not sent is still at the relay, in the generation before, and
    /// comes in by the command that names both keys in one run, with the
    /// phrase.
    #[actix_web::test]
    async fn test_a_recovery_cut_short_is_recovered_from_and_the_rest_comes_by_both_keys() {
        let gone = two_gone();
        let s = &gone.s;
        let (k0, k1) = (s.key(0), s.key(1));
        let from = candidate(&s[0].latest());
        let first = new_machine(9, &gone);
        let first_key = first.state.identity.public_key();
        let made = makes(
            &first,
            &from,
            &gone.at_the_relay[1].1,
            &[Answer::Lost, Answer::Lost],
        );
        let (number, to_look) = follows(&first, &made).unwrap();
        let found = the_look(&first.state, number, &to_look).await;
        assert_eq!(found["carried"], 4, "{found}");

        // What the first machine had sent when it was lost: its change
        // entry, its personal channel, and of what it carried only a.md.
        let (personal, lab) = {
            let conn = db(&first.state);
            let held = person::held(&conn).unwrap().unwrap();
            let secret = person::applied_secret(&conn, &held.statement.statement).unwrap();
            (
                derive::personal_secret(&secret).unwrap(),
                derive::own_secret(&secret, LAB).unwrap(),
            )
        };
        let stored_in = |secret: &[u8; 32]| -> Vec<CheckedEntry> {
            let id = derive::channel_id(secret).unwrap();
            cordelia_storage::entries::channel_entries_after(&db(&first.state), &id, 0, 10_000)
                .unwrap()
                .into_iter()
                .map(|held| held.entry.check().unwrap())
                .collect()
        };
        let sent_of_lab: Vec<CheckedEntry> = stored_in(&lab)
            .into_iter()
            .filter(|entry| entry.open(&lab).is_ok_and(|inside| inside.name == "a.md"))
            .collect();
        assert_eq!(sent_of_lab.len(), 1);
        let firsts_entry = person::latest_entry(&db(&first.state)).unwrap();

        // The second machine: the relay holds what it held, and what the
        // first machine had sent.
        let second = new_machine(10, &gone);
        second.relay_holds(&personal, &stored_in(&personal));
        second.relay_holds(&lab, &sent_of_lab);
        let from = candidate(&firsts_entry);
        assert_eq!(from.statement.statement.number, 3);
        let made = makes(&second, &from, &stored_in(&personal), &[Answer::Lost]);
        // It starts from the first machine's statement, under which that
        // machine alone counts, and which never wrote that it had sent
        // what it carried.
        assert_eq!(made.cut_short, Some(first_key));
        assert_eq!(made.names.carried, ["desk", LAB]);
        assert_eq!(made.left.len(), 3);
        let (number, to_look) = follows(&second, &made).unwrap();
        assert_eq!(number, 4);
        assert_eq!(to_look.takes, [first_key]);
        let found = the_look(&second.state, number, &to_look).await;
        // What the first machine had sent comes back: one file.
        assert_eq!(found["carried"], 1, "{found}");
        assert_eq!(second.text(LAB, "a.md").as_deref(), Some("of device 0"));
        assert_eq!(second.text(LAB, "b.md"), None);
        assert_eq!(second.text("desk", "d.md"), None);
        // And it says, for each removed key, how much the new channels
        // lack of what that key signed in what was read.
        let lacking = found["lacking"].as_array().unwrap();
        let lacks = |key: &[u8; 32]| -> (u64, Vec<String>) {
            let of = lacking
                .iter()
                .find(|of| of["key"] == hex::encode(key))
                .unwrap();
            let names = of["names"].as_array().unwrap();
            (
                of["versions"].as_u64().unwrap(),
                names
                    .iter()
                    .map(|n| n.as_str().unwrap().to_string())
                    .collect(),
            )
        };
        assert_eq!(lacking.len(), 2, "{found}");
        assert_eq!(lacks(&k0), (1, vec![LAB.to_string()]));
        assert_eq!(lacks(&k1), (2, vec!["desk".to_string(), LAB.to_string()]));

        // Both gone devices are named in one run, each by the first six
        // words of its key's fingerprint: the second machine never knew
        // either by a label.
        let named = [carry::naming_words(&k0), carry::naming_words(&k1)];
        let said = carrying::look_from(&second.state, LAB, &named)
            .await
            .unwrap();
        assert_eq!(said["empty"], 2, "{said}");
        assert_eq!(said["above"], json!([]));
        let by_label = carrying::look_from(&second.state, LAB, &["device 0".to_string()]).await;
        assert!(matches!(by_label, Err(PersonError::NotCarried(_))));
        let word = second.word(
            &phrase(),
            &Allows::From {
                name: LAB.into(),
                keys: vec![hex::encode(k0), hex::encode(k1)],
                above: vec![],
            },
        );
        let done = carrying::take_from(&second.state, &word).await.unwrap();
        assert_eq!(done["carried"], 2, "{done}");
        assert_eq!(second.text(LAB, "b.md").as_deref(), Some("of device 1"));
        assert_eq!(second.text(LAB, "old.md").as_deref(), Some("from before"));
        // A third recovery would bring back what the first machine had
        // sent in the same way: its key is a removed key here too.
        let firsts = carrying::look_from(&second.state, LAB, &[carry::naming_words(&first_key)])
            .await
            .unwrap();
        assert_eq!(firsts["keys"][0]["key"], hex::encode(first_key));
    }

    /// The look says which names it could not read to their end, and
    /// where (decision 2026-10-04 §9, step 5): a relay that handed a
    /// channel in part, by its name and the generation; and a name for
    /// which no relay was reached. What was handed is carried all the
    /// same.
    #[actix_web::test]
    async fn test_the_look_says_which_names_it_could_not_read_to_their_end() {
        let gone = two_gone();
        let from = candidate(&gone.s[0].latest());
        let node = new_machine(9, &gone);
        let answers = [Answer::Lost, Answer::Lost];
        let made = makes(&node, &from, &gone.at_the_relay[1].1, &answers);
        let (number, to_look) = follows(&node, &made).unwrap();
        node.in_part
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let found = the_look(&node.state, number, &to_look).await;
        assert_eq!(found["carried"], 4, "{found}");
        // The relay holds `desk` in the generation recovered from, and
        // `lab` in that one and in the one before.
        let not_read = |name: &str, change: u64| json!({ "name": name, "change": change, "relay": "relay", "read": "part" });
        assert_eq!(
            found["not_read"],
            json!([not_read("desk", 2), not_read(LAB, 2), not_read(LAB, 1)])
        );

        // A machine with no network reaches no relay.
        let mut alone = crate::several::state_of(Machine::new(10));
        alone.push_tx = None;
        let alone = Node {
            state: std::sync::Arc::new(alone),
            relay: Default::default(),
            asked: Default::default(),
            did: Default::default(),
            in_part: Default::default(),
            short_passes: Default::default(),
            not_connected: Default::default(),
            no_room: Default::default(),
            remade: Default::default(),
            remake_takes: Default::default(),
            held_back_at_reads: Default::default(),
        };
        let made = makes(&alone, &from, &gone.at_the_relay[1].1, &answers);
        let (number, to_look) = follows(&alone, &made).unwrap();
        let found = the_look(&alone.state, number, &to_look).await;
        assert_eq!(found["carried"], 0);
        let missed = found["not_read"].as_array().unwrap();
        assert_eq!(missed.len(), 4, "{found}");
        assert!(
            missed
                .iter()
                .all(|one| one["read"] == "no relay was reached")
        );
    }

    /// **A folder's first cycle in a name of the look waits until the
    /// look has read that name** (decision 2026-10-04 §7.3, §9): a machine
    /// that recovers may map folders already, and what a folder publishes
    /// is to be written over what the look carried. The wait begins when
    /// the statement is applied, for each name of the look and for no
    /// other. While the look reads a name, that name and each one after
    /// it are held back afresh, so that a look which takes long holds
    /// them for as long; a name that was read is let go. And where the
    /// look takes nothing, every name is let go at once.
    #[actix_web::test]
    async fn test_a_folders_first_cycle_waits_until_the_look_has_read_its_name() {
        use cordelia_core::protocol::CARRY_FIRST_MAX_SECS;
        let gone = two_gone();
        let from = candidate(&gone.s[0].latest());
        let answers = [Answer::Lost, Answer::Lost];
        // Whether a folder with no record in the channel would have its
        // first cycle there now: the relay has handed the channel.
        let cycles = |node: &Node, channel: &[u8; 32]| {
            let now = Instant::now();
            node.state.own_channels.fetched_from(channel, "relay", now);
            node.state.own_channels.first_fetch_done(channel, now)
        };
        let channel = |node: &Node, name: &str| {
            held_rows::channel_of_name(&db(&node.state), name)
                .unwrap()
                .unwrap()
        };

        let node = new_machine(9, &gone);
        node.state.own_channels.set_up_with(1);
        let made = makes(&node, &from, &gone.at_the_relay[1].1, &answers);
        let (number, to_look) = follows(&node, &made).unwrap();
        assert_eq!(to_look.names, ["desk", LAB]);
        let (desk, lab) = (channel(&node, "desk"), channel(&node, LAB));
        // From the moment the statement is applied, neither name's
        // folder has its first cycle. A name that is not of the look
        // does not wait.
        assert!(!cycles(&node, &desk) && !cycles(&node, &lab));
        let other = person::hold_name(&db(&node.state), "other", now()).unwrap();
        assert!(cycles(&node, &other));
        // The wait lasts as long as a carry may take, from when it was
        // last said: a second on, what was said when the statement was
        // applied would end a second sooner than what the look says.
        let nearly = Duration::from_secs(CARRY_FIRST_MAX_SECS - 1);
        let held_back = |node: &Node, at: Instant| node.state.own_channels.carried_into(at);
        assert_eq!(
            held_back(&node, Instant::now() + nearly),
            BTreeSet::from([desk, lab])
        );
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(held_back(&node, Instant::now() + nearly).is_empty());

        let found = the_look(&node.state, number, &to_look).await;
        assert_eq!(found["carried"], 4, "{found}");
        // The look read `desk` in two generations, and then `lab` in
        // two. While it read `desk`, both names were held back afresh;
        // while it read `lab`, that name alone: `desk` was let go.
        let at_reads = node.held_back_at_reads.lock().unwrap().clone();
        let both = BTreeSet::from([desk, lab]);
        let last = BTreeSet::from([lab]);
        assert_eq!(at_reads, [both.clone(), both, last.clone(), last]);
        // Once the look has ended, each folder has its first cycle.
        assert!(cycles(&node, &desk) && cycles(&node, &lab));
        assert!(held_back(&node, Instant::now()).is_empty());

        // Where the look takes nothing, every name is let go at once.
        let node = new_machine(10, &gone);
        node.state.own_channels.set_up_with(1);
        let made = makes(&node, &from, &gone.at_the_relay[1].1, &answers);
        let (number, to_look) = follows(&node, &made).unwrap();
        let (desk, lab) = (channel(&node, "desk"), channel(&node, LAB));
        assert!(!cycles(&node, &desk) && !cycles(&node, &lab));
        node.not_connected
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let found = the_look(&node.state, number, &to_look).await;
        assert_eq!(found["new_not_read"], true, "{found}");
        assert!(cycles(&node, &desk) && cycles(&node, &lab));

        // A recovery that is refused holds nothing back: here on a
        // machine that follows the phrase already, and holds the names.
        assert!(follows(&node, &made).is_err());
        assert!(held_back(&node, Instant::now()).is_empty());
    }

    /// Where the new channels could not be fetched whole before the look
    /// (decision 2026-10-04 §7.3, §9), the look takes nothing: it reads
    /// nothing of what was left, says that the new channels could not be
    /// read, and is not noted as ended, so that the machine never writes,
    /// under this statement, that it has sent what it carried.
    #[actix_web::test]
    async fn test_the_look_takes_nothing_where_the_new_channels_could_not_be_fetched() {
        let gone = two_gone();
        let from = candidate(&gone.s[0].latest());
        let node = new_machine(9, &gone);
        let answers = [Answer::Lost, Answer::Lost];
        let made = makes(&node, &from, &gone.at_the_relay[1].1, &answers);
        let (number, to_look) = follows(&node, &made).unwrap();
        let before = node.stored();
        node.not_connected
            .store(true, std::sync::atomic::Ordering::SeqCst);
        node.asked.lock().unwrap().clear();
        let found = the_look(&node.state, number, &to_look).await;
        assert_eq!(found["new_not_read"], true, "{found}");
        assert_eq!(
            (&found["finished"], &found["carried"]),
            (&json!(true), &json!(0))
        );
        assert_eq!(node.state.own_channels.look(), Some(found.clone()));
        assert!(node.asked.lock().unwrap().is_empty());
        assert_eq!(node.stored(), before);
        assert_eq!(node.text(LAB, "a.md"), None);
        // The look is not noted as ended.
        let conn = db(&node.state);
        assert!(
            meta::get(&conn, meta::PERSON_LOOK_PENDING)
                .unwrap()
                .is_some()
        );
    }

    /// **A statement made on a remaining device while a recovery is made
    /// from the statement before it** (decision 2026-10-04 §4.5, §9). The
    /// person still has device 0, and recovers on a new machine all the
    /// same, from the change that the relays hold. Before the recovery's
    /// statement is made, device 0 makes a statement of its own: the two
    /// have one number, and neither is on the other's chain.
    ///
    /// **Whichever of the two is answered with the other's is in a
    /// fork,** and keeps both entries. **The settlement, made with the
    /// phrase on either of them, ends it:** that device applies it, and
    /// so does the other when it is shown it. The key that both removed
    /// stays removed.
    #[actix_web::test]
    async fn test_a_statement_made_while_a_recovery_is_made_is_a_fork_and_is_settled() {
        use crate::change::make_settlement;
        use crate::person::{Applied, Shown as Answered, shown};
        for settled_on_the_new_machine in [true, false] {
            let gone = two_gone();
            let from = candidate(&gone.s[0].latest());
            let node = new_machine(9, &gone);
            let new = &node.state;
            // The recovery is prepared from change 2: device 0 is one
            // that the person still has, and device 1 is lost.
            let answers = [Answer::Have, Answer::Lost];
            let made = makes(&node, &from, &gone.at_the_relay[1].1, &answers);
            // Meanwhile device 0, which remains, makes a statement: it
            // removes device 1 itself.
            let mut s = gone.s;
            let theirs = s.change(0, &[0], &[1]);
            // The recovery is made, from the statement before that one.
            let (number, _) = follows(&node, &made).unwrap();
            assert_eq!((number, s[0].number()), (3, 3));
            assert_ne!(made.entry.id(), theirs.id());

            // The new machine is answered with device 0's, and device 0
            // with the new machine's: each is in a fork, and keeps both.
            let at = s.tick();
            let answered = shown(&db(new), &new.identity, &theirs, at).unwrap();
            assert_eq!(answered, Answered::Fork);
            let on = &s[0];
            let answered = shown(&on.conn, &on.identity, &made.entry, at).unwrap();
            assert_eq!(answered, Answered::Fork);
            let stands = || person::held(&db(new)).unwrap().unwrap();
            let kept = |which: Kept| {
                let entry = held_rows::change_entry(&db(new), which).unwrap();
                entry.map(|entry| entry.check().unwrap())
            };
            assert_eq!((stands().state, on.state()), (State::Fork, State::Fork));
            assert_eq!(
                (
                    kept(Kept::Latest).unwrap().id(),
                    kept(Kept::Apart).unwrap().id()
                ),
                (made.entry.id(), theirs.id())
            );
            assert_eq!(
                (on.latest().id(), on.apart().unwrap().id()),
                (theirs.id(), made.entry.id())
            );

            // The settlement, with the phrase, on the one or on the
            // other: both devices stay.
            let own = new.identity.public_key();
            let stay = vec![on.listed(), Device::new(own, "new machine").unwrap()];
            let settlement = match settled_on_the_new_machine {
                true => make_settlement(
                    &phrase(),
                    &stands().statement,
                    &kept(Kept::Latest).unwrap(),
                    &kept(Kept::Apart).unwrap(),
                    &own,
                    stay,
                    &[],
                ),
                false => make_settlement(
                    &phrase(),
                    &on.held().statement,
                    &on.latest(),
                    &on.apart().unwrap(),
                    &on.key(),
                    stay,
                    &[],
                ),
            }
            .unwrap();
            assert_eq!(settlement.rev, 4);
            let applied = |answered: Answered| {
                assert!(
                    matches!(
                        answered,
                        Answered::Applied(Applied {
                            number: 4,
                            left: Some(3),
                            ..
                        })
                    ),
                    "{answered:?}"
                );
            };
            let at = s.tick();
            let on = &s[0];
            applied(shown(&db(new), &new.identity, &settlement, at).unwrap());
            applied(shown(&on.conn, &on.identity, &settlement, at).unwrap());
            // Neither is in a fork, each keeps the settlement alone, and
            // the key that both had removed is removed still.
            assert_eq!(
                (stands().state, on.state()),
                (State::Applied, State::Applied)
            );
            assert_eq!((kept(Kept::Apart), on.apart()), (None, None));
            assert_eq!(kept(Kept::Latest).unwrap().id(), settlement.id());
            assert_eq!(on.latest().id(), settlement.id());
            let listed = stands().statement.statement;
            assert!(listed.removes(&s.key(1)));
            assert!(listed.lists(&s.key(0)) && listed.lists(&own));
        }
    }

    /// A recovery whose look was interrupted was cut short (decision
    /// 2026-10-04 §8, §9): the machine never writes, under that
    /// statement, that it has sent what it carried, however much it has
    /// sent. Under a later statement it carries what it holds as any
    /// device does, and says so as any device does.
    #[actix_web::test]
    async fn test_a_machine_whose_look_was_interrupted_never_says_that_it_sent() {
        let gone = two_gone();
        let from = candidate(&gone.s[0].latest());
        let node = new_machine(9, &gone);
        let made = makes(
            &node,
            &from,
            &gone.at_the_relay[1].1,
            &[Answer::Lost, Answer::Lost],
        );
        follows(&node, &made).unwrap();
        // No look is made: the node was stopped. Everything that the
        // machine holds is sent to its relay.
        let relay = [7u8; 32];
        let conn = db(&node.state);
        let identity = &node.state.identity;
        let sent_everything = || {
            let far = i64::MAX / 2;
            for channel in crate::at_relays::channels(&conn, identity).unwrap() {
                kept_rows::sent(&conn, &relay, &channel.id, far).unwrap();
                kept_rows::carried(&conn, &relay, &channel.id, far).unwrap();
            }
        };
        sent_everything();
        assert!(!crate::at_relays::say_sent(&conn, identity, &[relay], now()).unwrap());
        assert!(
            meta::get(&conn, meta::PERSON_LOOK_PENDING)
                .unwrap()
                .is_some()
        );

        // A later change, made on this machine.
        let held = person::held(&conn).unwrap().unwrap();
        let entry = make_change(
            &phrase(),
            &held.statement,
            &person::latest_entry(&conn).unwrap(),
            &identity.public_key(),
            held.statement.statement.devices.clone(),
            &[],
        )
        .unwrap();
        let shown = person::shown(&conn, identity, &entry, now()).unwrap();
        assert!(matches!(shown, person::Shown::Applied(_)), "{shown:?}");
        assert_eq!(meta::get(&conn, meta::PERSON_LOOK_PENDING).unwrap(), None);
        sent_everything();
        assert!(crate::at_relays::say_sent(&conn, identity, &[relay], now()).unwrap());
    }

    /// A machine that was recovered from, and that had written that it
    /// sent what it carried, was not cut short (decision 2026-10-04 §8,
    /// §9).
    #[test]
    fn test_a_machine_that_wrote_that_it_sent_what_it_carried_was_not_cut_short() {
        let mut s = Several::of_one_person(2);
        s.change(0, &[0], &[1]);
        let from = candidate(&s[0].latest());
        let statement_key = *phrase().statement_key().unwrap();
        let personal = s[0].personal();
        let mut handed = s[0].stored_in(&personal);
        let read = read_generation(&from, &statement_key, &s[0].secret(), &handed, s.now).unwrap();
        assert_eq!(read.cut_short, Some(s.key(0)));
        // Its word that it has sent what it carried under that change.
        handed.push(entry_by(
            &s[0].identity,
            &personal,
            (2u64 << cordelia_core::protocol::REV_COUNT_BITS) + 2,
            &applied_name(&s.key(0)).unwrap(),
            text(&applied_word(2, true)),
            &[],
        ));
        let read = read_generation(&from, &statement_key, &s[0].secret(), &handed, s.now).unwrap();
        assert_eq!(read.cut_short, None);
        // A first statement was made after no other: nothing was carried.
        let mut alone = Several::new(1);
        alone.make_phrase(0);
        let from = candidate(&alone[0].latest());
        let handed = alone[0].stored_in(&alone[0].personal());
        let read = read_generation(
            &from,
            &statement_key,
            &alone[0].secret(),
            &handed,
            alone.now,
        )
        .unwrap();
        assert_eq!(read.cut_short, None);
    }
}
