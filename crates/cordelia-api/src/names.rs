//! The names a device syncs, as the personal channel says them (decision
//! 2026-10-04 §2.2, §7.1, §7.3, §16).
//!
//! A mapped folder syncs a name, and the name's channel comes from the
//! person secret: a device holds the name ([`crate::person::hold_name`])
//! for as long as a folder of its own is mapped to it. Beside that, each
//! device says in the personal channel which names it syncs:
//!
//! - **A device's word that it syncs a name** is its own entry under
//!   `name/` and the name, that is no delete. It writes the word when it
//!   comes to sync the name ([`say`]), and writes a delete over it when it
//!   stops: when the name is unmapped, and when sync is turned off
//!   ([`unsay`]). Only a device's own entry under a name is its word,
//!   whatever another key wrote there and at whatever revision.
//! - **The names that the personal channel lists** ([`listed`]) are those
//!   that a key which counts has such a word for. A device proves the
//!   channel of each, whether or not it syncs the name itself, and a
//!   command that removes a device shows the names that only that device
//!   lists.
//! - **A word is read as a name only where it is one that this version
//!   would itself map, in its one spelling** ([`is_a_name`], decision
//!   2026-10-04 §16). What a device wrote under `name/` is whatever it
//!   chose to write, and a status and the prompt of a removal show names:
//!   a word that is no name is counted ([`not_names`]), and never shown.
//! - **When a device applies a statement** it carries its own words with
//!   the rest of what it wrote in the personal channel
//!   ([`crate::person`]): the list of names in a new personal channel is
//!   what the devices under the statement say they sync. What the old
//!   personal channel listed is noted then ([`note_listed_before`]), so
//!   that a device can show the names that no device lists yet in the new
//!   generation ([`not_listed_yet`]).
//!
//! - **A name that a device holds by a carry, with no folder mapped to
//!   it,** is listed all the same ([`hold_for_a_carry`], decision
//!   2026-10-04 §7.3, §9): a person asked for the name by a command, or
//!   recovered it, and the device holds its channel and sends it,
//!   whether or not sync is on here. Its word is taken back by nothing
//!   but the device's stopping the name.
//!
//! Plain functions over the node's database and the device's own key.
//! Nothing here sends anything: what is written waits in the store, and
//! the node sends it.

use std::collections::BTreeSet;

use rusqlite::Connection;

use cordelia_core::protocol::{LEFT_SECRET_KEPT_DAYS, PERSONAL_NAME_PREFIX};
use cordelia_core::revision::next_under;
use cordelia_crypto::bech32::encode_channel_id;
use cordelia_crypto::derive;
use cordelia_crypto::entry::{Entry, Inside, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::slots::slot_id;
use cordelia_storage::at_relays as kept_rows;
use cordelia_storage::entries;
use cordelia_storage::meta;
use cordelia_storage::person::{self as held_rows, State};
use cordelia_storage::sync_state;

use crate::person::{Counting, PersonError, hold_name, in_one};
use crate::publish::Standing;

/// Whether `name` is a name as this version would itself map one: of the
/// characters that a name may have, no longer than a name may be, and in
/// its one spelling (decision 2026-10-04 §16). A word of the personal
/// channel is read as a name only where it is. So what another device
/// wrote there is never shown where it holds a control character, an
/// escape sequence or a new line, is longer than a name, or is spelled
/// another way.
pub fn is_a_name(name: &str) -> bool {
    crate::sync::valid_sync_name(name) && cordelia_core::sync_name::tidy(name) == name
}

/// The name, in the personal channel, of a device's word that it syncs
/// `name`: `name/` and the name.
pub fn word_name(name: &str) -> String {
    format!("{PERSONAL_NAME_PREFIX}{name}")
}

/// What this device's own entry under the word of `name` holds, in the
/// personal channel whose secret is `personal`: `None` where it has none
/// there, or one that does not open.
fn own_word(
    conn: &Connection,
    identity: &NodeIdentity,
    personal: &[u8; 32],
    name: &str,
) -> Result<Option<(u64, Value)>, PersonError> {
    let channel = derive::channel_id(personal)?;
    let slot = slot_id(&derive::slot_key(personal)?, &word_name(name));
    let Some(held) = entries::author_entry(conn, &channel, &slot, &identity.public_key())? else {
        return Ok(None);
    };
    let rev = held.entry.rev;
    let opened = held
        .entry
        .check()
        .ok()
        .and_then(|entry| entry.open(personal).ok());
    Ok(Some((
        rev,
        opened.map_or(Value::Delete, |inside| inside.value),
    )))
}

/// Write this device's own entry under the word of `name`, one revision
/// above the one it wrote there before: a text where it syncs the name,
/// and a delete where it has stopped.
fn write_word(
    conn: &Connection,
    identity: &NodeIdentity,
    standing: &Standing,
    name: &str,
    syncs: bool,
    now: i64,
) -> Result<(), PersonError> {
    let personal = derive::personal_secret(&standing.secret)?;
    let before = own_word(conn, identity, &personal, name)?.map(|(rev, _)| rev);
    let rev = next_under(before, standing.number()).ok_or_else(|| {
        PersonError::Held(
            "this device's own word in that slot is at the last revision under the statement"
                .into(),
        )
    })?;
    let value = match syncs {
        true => Value::Text(String::new()),
        false => Value::Delete,
    };
    let inside = Inside {
        name: word_name(name),
        value,
        chain: Some(Vec::new()),
    };
    let entry = Entry::seal(&personal, identity, rev, &inside)?.check()?;
    entries::store(conn, &entry, now)?;
    Ok(())
}

/// This device says that it syncs `name`: its own entry under the name's
/// word in the personal channel of the generation it has applied. Returns
/// whether a word was written: where its word there is a text already,
/// nothing is.
///
/// The name is in its one spelling, and another is refused: a word lists
/// only a name that has a channel. A device that follows no phrase, or
/// has stopped, says nothing.
pub fn say(
    conn: &Connection,
    identity: &NodeIdentity,
    name: &str,
    now: i64,
) -> Result<bool, PersonError> {
    in_one(conn, || {
        let standing = Standing::to_write(conn)?;
        derive::own_secret(&standing.secret, name)?;
        let personal = derive::personal_secret(&standing.secret)?;
        if let Some((_, Value::Text(_))) = own_word(conn, identity, &personal, name)? {
            return Ok(false);
        }
        write_word(conn, identity, &standing, name, true, now)?;
        Ok(true)
    })
}

/// This device says no longer that it syncs `name`: a delete over its own
/// word, where it has one that is no delete. Returns whether one was
/// written. A device that follows no phrase, or has stopped, writes
/// nothing: it publishes nothing in its own channels.
pub fn unsay(
    conn: &Connection,
    identity: &NodeIdentity,
    name: &str,
    now: i64,
) -> Result<bool, PersonError> {
    in_one(conn, || {
        let Ok(standing) = Standing::to_write(conn) else {
            return Ok(false);
        };
        let personal = derive::personal_secret(&standing.secret)?;
        match own_word(conn, identity, &personal, name)? {
            Some((_, Value::Text(_) | Value::Other(_))) => {
                write_word(conn, identity, &standing, name, false, now)?;
                Ok(true)
            }
            Some((_, Value::Delete)) | None => Ok(false),
        }
    })
}

/// Whether an entry at the revision `rev` is read under the statement
/// numbered `number` (decision 2026-10-04 §2.3): one in a band above the
/// statement's counts for nothing, whoever signed it. It is the one rule
/// for every word of the personal channel that is read as a name: those
/// of the generation applied ([`words`]), and those that are noted when a
/// generation is left ([`note_listed_before`]).
fn in_a_band_of(rev: u64, number: u64) -> bool {
    cordelia_core::revision::band(rev) <= number
}

/// The words of the personal channel that list something, as this
/// device's store holds it.
struct Words {
    /// Each word that lists a name ([`is_a_name`]): the name, and the key
    /// whose word it is, in order.
    names: Vec<(String, [u8; 32])>,
    /// The key of each word that is under `name/` and lists no name, once
    /// for each such word, in order of key.
    not_names: Vec<[u8; 32]>,
}

/// Each word of the personal channel that lists something, as this
/// device's store holds it. A word is an entry under `name/` that is no
/// delete, read from its own signer and no other. `of` says whose words
/// are read. An entry in a band above the statement's is no word
/// ([`in_a_band_of`]).
///
/// What comes after `name/` is read as a name only where it is one
/// ([`is_a_name`]): a word that is not is counted for its key, and what
/// it holds goes no further.
fn words(
    conn: &Connection,
    standing: &Standing,
    of: impl Fn(&[u8; 32]) -> bool,
) -> Result<Words, PersonError> {
    let personal = derive::personal_secret(&standing.secret)?;
    let channel = derive::channel_id(&personal)?;
    let (mut names, mut not_names) = (Vec::new(), Vec::new());
    for slot in entries::channel_slots(conn, &channel)? {
        for entry in entries::slot_entries(conn, &channel, &slot)? {
            let read = of(&entry.author) && in_a_band_of(entry.rev, standing.number());
            if entry.delete || !read {
                continue;
            }
            let Ok(inside) = entry.open(&personal) else {
                continue;
            };
            match inside.name.strip_prefix(PERSONAL_NAME_PREFIX) {
                Some(name) if is_a_name(name) => names.push((name.to_string(), entry.author)),
                Some(_) => not_names.push(entry.author),
                None => {}
            }
        }
    }
    names.sort();
    names.dedup();
    not_names.sort();
    Ok(Words { names, not_names })
}

/// The names that this device says it syncs: those its own word lists.
/// None on a device that follows no phrase.
pub fn said_here(
    conn: &Connection,
    identity: &NodeIdentity,
) -> Result<BTreeSet<String>, PersonError> {
    let Ok(standing) = Standing::of(conn) else {
        return Ok(BTreeSet::new());
    };
    let own = identity.public_key();
    let said = words(conn, &standing, |key| *key == own)?.names;
    Ok(said.into_iter().map(|(name, _)| name).collect())
}

/// A name that the personal channel lists, with each key that lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub name: String,
    /// The keys that count and whose word lists the name, in order.
    pub by: Vec<[u8; 32]>,
}

/// The names that the personal channel of the generation applied lists,
/// as this device's store holds it, in order of name: each name that a
/// key which counts has a word for, with every such key. None on a device
/// that follows no phrase.
pub fn listed(conn: &Connection) -> Result<Vec<Listed>, PersonError> {
    let Ok(standing) = Standing::of(conn) else {
        return Ok(Vec::new());
    };
    let said = words(conn, &standing, |key| standing.counting.counts(key))?.names;
    let mut listed: Vec<Listed> = Vec::new();
    for (name, key) in said {
        match listed.last_mut() {
            Some(last) if last.name == name => last.by.push(key),
            _ => listed.push(Listed {
                name,
                by: vec![key],
            }),
        }
    }
    Ok(listed)
}

/// The words of the personal channel of the generation applied that are
/// under `name/` and list no name ([`is_a_name`]), of keys that count:
/// each such key, in order, with how many of its words they are. None on
/// a device that follows no phrase.
///
/// They are counted so that a person can be told that there are some, and
/// of which device: what they hold is never shown.
pub fn not_names(conn: &Connection) -> Result<Vec<([u8; 32], usize)>, PersonError> {
    let Ok(standing) = Standing::of(conn) else {
        return Ok(Vec::new());
    };
    let said = words(conn, &standing, |key| standing.counting.counts(key))?.not_names;
    let mut by_key: Vec<([u8; 32], usize)> = Vec::new();
    for key in said {
        match by_key.last_mut() {
            Some((last, words)) if *last == key => *words += 1,
            _ => by_key.push((key, 1)),
        }
    }
    Ok(by_key)
}

/// How many names that were noted as listed in a generation this device
/// left are no names ([`is_a_name`]): an earlier build noted whatever a
/// word held. They are counted, and never shown.
pub fn not_names_before(conn: &Connection) -> Result<usize, PersonError> {
    let noted = held_rows::names_before(conn)?;
    let not_names: BTreeSet<&str> = noted
        .iter()
        .map(|before| before.name.as_str())
        .filter(|name| !is_a_name(name))
        .collect();
    Ok(not_names.len())
}

/// The names that this device's own folders are mapped to: each mapping's
/// name, in the order they were declared.
fn mapped(conn: &Connection) -> Result<Vec<String>, PersonError> {
    Ok(crate::sync::mappings(conn)
        .map_err(|e| PersonError::Held(format!("the mappings: {e}")))?
        .into_iter()
        .map(|mapping| mapping.name)
        .collect())
}

/// Whether sync is on here.
fn sync_is_on(conn: &Connection) -> Result<bool, PersonError> {
    Ok(meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_some())
}

/// This device comes to sync `name`: it holds the name, so that its
/// channel is fetched, and says so in the personal channel. Returns the
/// ID of the name's channel. On a device that follows no phrase, or has
/// stopped, it is refused: such a device publishes nothing.
pub fn sync_name(
    conn: &Connection,
    identity: &NodeIdentity,
    name: &str,
    now: i64,
) -> Result<[u8; 32], PersonError> {
    in_one(conn, || {
        let channel = hold_name(conn, name, now)?;
        say(conn, identity, name, now)?;
        Ok(channel)
    })
}

/// Hold a name for each folder that this device maps, and say of each
/// that it syncs it where sync is on (decision 2026-10-04 §5.2, §6): what
/// a device does when it comes to follow a phrase, by making it or by
/// accepting a device that follows it, and when sync is turned on. A name
/// that is no name in its one spelling is passed over: it has no channel.
/// Returns how many names it holds for its folders.
///
/// On a device that follows no phrase, or has stopped, nothing is done.
pub fn hold_mapped(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
) -> Result<usize, PersonError> {
    in_one(conn, || {
        if Standing::to_write(conn).is_err() {
            return Ok(0);
        }
        let says = sync_is_on(conn)?;
        let mut held = 0;
        for name in mapped(conn)? {
            match hold_name(conn, &name, now) {
                Ok(_) => {}
                Err(PersonError::Derive(_)) => continue,
                Err(e) => return Err(e),
            }
            if says {
                say(conn, identity, &name, now)?;
            }
            held += 1;
        }
        Ok(held)
    })
}

/// Whether a folder of this device's is mapped to `name` (decision
/// 2026-10-04 §7.3): only there is a text that a carried version replaces
/// kept beside its file.
pub fn has_folder(conn: &Connection, name: &str) -> Result<bool, PersonError> {
    Ok(mapped(conn)?.iter().any(|mapped| mapped == name))
}

/// Sync was turned off here: this device says of no name that it syncs
/// it. Returns how many words were written over. The names stay held:
/// their folders are still mapped.
///
/// **A name that the device holds by a carry keeps its word**
/// ([`hold_for_a_carry`]): no folder of this device's syncs it, with
/// sync on or off, and the device goes on holding its channel and
/// sending it all the same.
pub fn unsay_all(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
) -> Result<usize, PersonError> {
    in_one(conn, || {
        let kept = carried(conn)?;
        let mut written = 0;
        for name in said_here(conn, identity)? {
            if kept.contains(&name) {
                continue;
            }
            written += usize::from(unsay(conn, identity, &name, now)?);
        }
        Ok(written)
    })
}

/// The names that this device holds by a carry that a person asked for,
/// or by a recovery, with no folder of its own mapped to them (decision
/// 2026-10-04 §7.3, §9).
pub fn carried(conn: &Connection) -> Result<BTreeSet<String>, PersonError> {
    Ok(meta::get(conn, meta::PERSON_NAMES_CARRIED)?
        .and_then(|kept| serde_json::from_str(&kept).ok())
        .unwrap_or_default())
}

/// Keep `names` as the names that this device holds by a carry.
fn keep_carried(conn: &Connection, names: &BTreeSet<String>) -> Result<(), PersonError> {
    if names.is_empty() {
        meta::remove(conn, meta::PERSON_NAMES_CARRIED)?;
        return Ok(());
    }
    let kept = serde_json::to_string(names)
        .map_err(|e| PersonError::Held(format!("the names held by a carry: {e}")))?;
    meta::set(conn, meta::PERSON_NAMES_CARRIED, &kept)?;
    Ok(())
}

/// This device comes to hold `name` for a carry that a person asked for
/// (decision 2026-10-04 §7.3, §9): it holds the name, so that its channel
/// is fetched and what is carried into it is sent, and it lists the name
/// in the personal channel, so that every device of the person's, and a
/// recovery that follows, finds the name in the generation applied.
/// Returns the ID of the name's channel.
///
/// Where no folder of this device's is mapped to the name, that it holds
/// the name by a carry is kept ([`carried`]): its word then stands with
/// sync on or off, and a cycle that finds no folder for it does not stop
/// it. A name that a folder is mapped to is held for the folder, and
/// nothing more is kept of it.
///
/// Refused on a device that follows no phrase, or has stopped, and for a
/// name that is none in its one spelling.
pub fn hold_for_a_carry(
    conn: &Connection,
    identity: &NodeIdentity,
    name: &str,
    now: i64,
) -> Result<[u8; 32], PersonError> {
    in_one(conn, || {
        let channel = hold_name(conn, name, now)?;
        say(conn, identity, name, now)?;
        if !mapped(conn)?.iter().any(|mapped| mapped == name) {
            let mut kept = carried(conn)?;
            if kept.insert(name.to_string()) {
                keep_carried(conn, &kept)?;
            }
        }
        Ok(channel)
    })
}

/// How many versions this device holds of `name` that wait to be sent:
/// those in the name's channel that it has sent to no relay
/// ([`kept_rows::sent_to_no_relay`]). Were it to hold the name no more
/// ([`stop`]), they would go with what its store holds of the channel,
/// and be nowhere in the generation applied (decision 2026-10-04 §7.3).
///
/// None on a device that follows no phrase, or has stopped: it sends
/// nothing in a channel of its own, so nothing waits there to be sent.
pub fn waits_to_be_sent(conn: &Connection, name: &str) -> Result<usize, PersonError> {
    if crate::at_relays::stands(conn)? != crate::at_relays::Stands::Applied {
        return Ok(0);
    }
    let Some(channel) = held_rows::channel_of_name(conn, name)? else {
        return Ok(0);
    };
    Ok(kept_rows::sent_to_no_relay(conn, &channel)?)
}

/// This device syncs `name` no longer, and no folder of its own is mapped
/// to it: it says so, where it had said that it syncs it, and holds the
/// name no more. What its store holds of the name's channel goes, with
/// what it kept of each relay for it, and with what every folder had
/// agreed in that channel and its records of index lines there: all of
/// it in one transaction. Returns the ID of the channel that it held for
/// the name, where it held one: whoever calls this keeps nothing more of
/// that channel either.
///
/// So a folder that comes to sync the name again, in the same generation
/// or a later one, has no record in the channel: it waits for the channel
/// to be fetched, and meets it as on any first sync (decision 2026-10-04
/// §6). A record that outlived the channel's entries would say that a
/// file was agreed which the folder has lost since, and a delete would be
/// published for it.
///
/// **The files under it whose record could not be carried are noted no
/// longer** ([`crate::look::forget_not_carried_of`]): the name syncs here
/// no more, on purpose, and they have no channel to meet.
///
/// **A name that this device stops is noted no longer as listed before**
/// ([`note_listed_before`]): it was mapped here in the generation
/// applied, and a person has it synced here no more. Otherwise it would
/// be shown for 90 days as a name that no device lists yet
/// ([`not_listed_yet`]), on the device that stopped it on purpose.
pub fn stop(
    conn: &Connection,
    identity: &NodeIdentity,
    name: &str,
    now: i64,
) -> Result<Option<[u8; 32]>, PersonError> {
    in_one(conn, || {
        unsay(conn, identity, name, now)?;
        held_rows::forget_name_before(conn, name)?;
        // A file under it whose record could not be carried has no
        // channel to meet here now: it is noted no longer.
        crate::look::forget_not_carried_of(conn, name)?;
        // Nor is the name held by a carry any longer.
        let mut kept = carried(conn)?;
        if kept.remove(name) {
            keep_carried(conn, &kept)?;
        }
        let Some(channel) = held_rows::channel_of_name(conn, name)? else {
            return Ok(None);
        };
        entries::remove_channel(conn, &channel)?;
        kept_rows::forget_channel(conn, &channel)?;
        sync_state::forget_channel(conn, &encode_channel_id(&channel)?)?;
        held_rows::drop_name(conn, name)?;
        Ok(Some(channel))
    })
}

/// Whether the key `key` has said, in the personal channel whose secret is
/// `personal`, whether it syncs `name`, as this device's store holds it:
/// an entry of its own under the name's word, in a band of the statement
/// numbered `number`, that passes the check. A text says that it syncs
/// the name there, and a delete that it syncs it no longer.
fn has_said(
    conn: &Connection,
    personal: &[u8; 32],
    number: u64,
    name: &str,
    key: &[u8; 32],
) -> Result<bool, PersonError> {
    let channel = derive::channel_id(personal)?;
    let slot = slot_id(&derive::slot_key(personal)?, &word_name(name));
    let Some(held) = entries::author_entry(conn, &channel, &slot, key)? else {
        return Ok(false);
    };
    Ok(in_a_band_of(held.entry.rev, number) && held.entry.check().is_ok())
}

/// Note what the personal channel of the generation that this device is
/// leaving lists, as its store holds it at `now`: each name, with each
/// key that counts under the statement it leaves and whose word lists the
/// name. It is called in the transaction that applies a statement, before
/// what the store holds of that generation is dropped (decision
/// 2026-10-04 §7.3).
///
/// **A note of an earlier generation goes first where the key that had
/// listed the name has said, in the generation that is left, whether it
/// syncs the name** ([`has_said`]): a word that lists it is noted again
/// here, as of now, and a delete says that the device syncs it no longer,
/// on purpose. So a name that a device has unmapped is not shown again,
/// at the next statement, as one that no device lists yet.
///
/// `secret` is the person secret of the generation that is left, and
/// `counting` who counted under its statement.
pub(crate) fn note_listed_before(
    conn: &Connection,
    secret: &[u8; 32],
    number: u64,
    counting: &Counting,
    now: i64,
) -> Result<(), PersonError> {
    let personal = derive::personal_secret(secret)?;
    let channel = derive::channel_id(&personal)?;
    for before in held_rows::names_before(conn)? {
        let said = counting.counts(&before.key)
            && has_said(conn, &personal, number, &before.name, &before.key)?;
        if said {
            held_rows::forget_name_said_by(conn, &before.name, &before.key)?;
        }
    }
    for slot in entries::channel_slots(conn, &channel)? {
        for entry in entries::slot_entries(conn, &channel, &slot)? {
            // An entry in a band above the statement's counts for
            // nothing, and its word is not read.
            let counts = counting.counts(&entry.author) && in_a_band_of(entry.rev, number);
            if entry.delete || !counts {
                continue;
            }
            let Ok(inside) = entry.open(&personal) else {
                continue;
            };
            // Only a name is noted: what a word holds that is no name is
            // not kept.
            match inside.name.strip_prefix(PERSONAL_NAME_PREFIX) {
                Some(name) if is_a_name(name) => {
                    held_rows::note_name_before(conn, name, &entry.author, now)?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// A name that was listed in a generation this device left, and that no
/// device lists yet in the one it has applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotListedYet {
    pub name: String,
    /// The keys that had listed it and that count now.
    pub by: Vec<[u8; 32]>,
    /// The keys that had listed it and that count no longer.
    pub by_gone: Vec<[u8; 32]>,
    /// Until when it can still be brought in, in seconds: 90 days after
    /// the device left the generation that listed it, when the secret of
    /// that generation is forgotten.
    pub until: i64,
}

/// The names that a device had listed in the personal channel of a
/// generation this device left, as it held that channel, and that no
/// device lists in the personal channel of the generation it has applied
/// (decision 2026-10-04 §7.3, §8), in order of name. A name that only
/// keys which count no longer had listed has none in [`NotListedYet::by`]:
/// it is shown apart, as that.
///
/// **A key's note of a name is passed over where that key has said, in
/// the generation applied, that it syncs the name no longer** (decision
/// 2026-10-04 §10.1): the device that listed the name has unmapped it, or
/// turned sync off, on purpose, and every device that reads its word
/// shows the name no more for it. The note itself goes when the
/// generation is left ([`note_listed_before`]).
pub fn not_listed_yet(conn: &Connection) -> Result<Vec<NotListedYet>, PersonError> {
    let Ok(standing) = Standing::of(conn) else {
        return Ok(Vec::new());
    };
    let now_listed: BTreeSet<String> = listed(conn)?.into_iter().map(|one| one.name).collect();
    let kept_for = i64::from(LEFT_SECRET_KEPT_DAYS) * 24 * 60 * 60;
    let personal = derive::personal_secret(&standing.secret)?;
    let mut not_yet: Vec<NotListedYet> = Vec::new();
    for before in held_rows::names_before(conn)? {
        // What was noted and is no name is counted apart, and not shown
        // ([`not_names_before`]).
        if now_listed.contains(&before.name) || !is_a_name(&before.name) {
            continue;
        }
        let counts = standing.counting.counts(&before.key);
        let said_since = counts
            && has_said(
                conn,
                &personal,
                standing.number(),
                &before.name,
                &before.key,
            )?;
        if said_since {
            continue;
        }
        if not_yet.last().is_none_or(|last| last.name != before.name) {
            not_yet.push(NotListedYet {
                name: before.name.clone(),
                by: Vec::new(),
                by_gone: Vec::new(),
                until: before.left_at.saturating_add(kept_for),
            });
        }
        let Some(of) = not_yet.last_mut() else {
            continue;
        };
        of.until = of.until.max(before.left_at.saturating_add(kept_for));
        match counts {
            true => of.by.push(before.key),
            false => of.by_gone.push(before.key),
        }
    }
    Ok(not_yet)
}

/// Whether this device has applied a statement and has not stopped: it
/// may hold a name, and say that it syncs one.
pub fn may_say(conn: &Connection) -> Result<bool, PersonError> {
    Ok(held_rows::person(conn)?.is_some_and(|person| person.state == State::Applied))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::several::{Machine, Several, entry_by};
    use crate::take::{NotTaken, Taken, take};

    /// The names this device lists, each with the numbers of the devices
    /// of `s` that list it.
    fn listed_on(s: &Several, n: usize) -> Vec<(String, Vec<usize>)> {
        listed(&s[n].conn)
            .unwrap()
            .into_iter()
            .map(|one| {
                let by = one
                    .by
                    .iter()
                    .map(|key| (0..s.machines.len()).find(|m| s.key(*m) == *key).unwrap())
                    .collect();
                (one.name, by)
            })
            .collect()
    }

    /// What this device's own entry under the word of `name` holds.
    fn word(on: &Machine, name: &str) -> Option<(u64, Value)> {
        own_word(&on.conn, &on.identity, &on.personal(), name).unwrap()
    }

    fn maps(on: &Machine, names: &[&str], sync_on: bool) {
        let mappings: Vec<serde_json::Value> = names
            .iter()
            .enumerate()
            .map(|(n, name)| serde_json::json!({ "folder": format!("/home/sam/f{n}"), "name": name }))
            .collect();
        let json = serde_json::to_string(&mappings).unwrap();
        meta::set(&on.conn, meta::SYNC_CLAUDE_MAPPINGS, &json).unwrap();
        match sync_on {
            true => meta::set(&on.conn, meta::SYNC_CLAUDE_DIR, "/home/sam/.claude").unwrap(),
            false => meta::remove(&on.conn, meta::SYNC_CLAUDE_DIR).unwrap(),
        }
    }

    /// A device's word that it syncs a name is its own entry under
    /// `name/` and the name, in the personal channel: a text when it
    /// comes to sync the name, and a delete over it when it stops
    /// (decision 2026-10-04 §2.2, §16). Each is written once, one
    /// revision above the last, and the names that the channel lists are
    /// those that a key which counts has such a word for.
    #[test]
    fn test_a_device_says_that_it_syncs_a_name_and_then_no_longer() {
        let mut s = Several::of_one_person(2);
        let now = s.tick();
        assert_eq!(word_name("lab"), "name/lab");
        assert!(listed_on(&s, 0).is_empty());

        assert!(say(&s[0].conn, &s[0].identity, "lab", now).unwrap());
        let (first, said) = word(&s[0], "lab").unwrap();
        assert!(matches!(said, Value::Text(_)));
        // Said already: nothing is written.
        assert!(!say(&s[0].conn, &s[0].identity, "lab", now).unwrap());
        assert_eq!(word(&s[0], "lab").unwrap().0, first);
        assert_eq!(listed_on(&s, 0), [("lab".to_string(), vec![0])]);
        assert_eq!(
            said_here(&s[0].conn, &s[0].identity).unwrap(),
            BTreeSet::from(["lab".to_string()])
        );

        // The other device is given the word, and lists the name as one
        // that device 0 syncs. It says nothing of it itself.
        s.pass(0, 1);
        assert_eq!(listed_on(&s, 1), [("lab".to_string(), vec![0])]);
        assert!(said_here(&s[1].conn, &s[1].identity).unwrap().is_empty());
        // It says so too, and of another name: each name with every key
        // that lists it, in order of name.
        let now = s.tick();
        assert!(say(&s[1].conn, &s[1].identity, "lab", now).unwrap());
        assert!(say(&s[1].conn, &s[1].identity, "another", now).unwrap());
        s.pass(1, 0);
        let both: Vec<(String, Vec<usize>)> = listed_on(&s, 0);
        let mut of_lab = both[1].1.clone();
        of_lab.sort();
        assert_eq!(both[0], ("another".to_string(), vec![1]));
        assert_eq!((both[1].0.as_str(), of_lab), ("lab", vec![0, 1]));

        // It stops: a delete, one revision above its word, and once.
        let now = s.tick();
        assert!(unsay(&s[0].conn, &s[0].identity, "lab", now).unwrap());
        assert_eq!(word(&s[0], "lab"), Some((first + 1, Value::Delete)));
        assert!(!unsay(&s[0].conn, &s[0].identity, "lab", now).unwrap());
        assert!(!unsay(&s[0].conn, &s[0].identity, "never-said", now).unwrap());
        assert_eq!(
            listed_on(&s, 0),
            [
                ("another".to_string(), vec![1]),
                ("lab".to_string(), vec![1])
            ]
        );
        // And says it again: a text, above the delete.
        assert!(say(&s[0].conn, &s[0].identity, "lab", now).unwrap());
        assert_eq!(word(&s[0], "lab").unwrap().0, first + 2);

        // A name that is not in its one spelling has no channel, and is
        // not said.
        assert!(matches!(
            say(&s[0].conn, &s[0].identity, "Lab.git", now),
            Err(PersonError::Derive(_))
        ));
    }

    /// Only a device's own entry under a name is its word, whatever
    /// another key wrote there and at whatever revision; and a word of a
    /// key that does not count lists nothing.
    #[test]
    fn test_a_word_is_its_own_signers_and_only_of_a_key_that_counts() {
        let mut s = Several::of_one_person(2);
        let now = s.tick();
        say(&s[0].conn, &s[0].identity, "lab", now).unwrap();
        // Device 1 writes a delete under the word of device 0's name, at
        // a revision far above it: device 0's word stands.
        let personal = s[0].personal();
        let over = entry_by(
            &s[1].identity,
            &personal,
            500,
            "name/lab",
            Value::Delete,
            &[],
        );
        take(&s[0].conn, &s[0].identity, &over, now).unwrap();
        assert_eq!(listed_on(&s, 0), [("lab".to_string(), vec![0])]);
        assert!(matches!(word(&s[0], "lab"), Some((_, Value::Text(_)))));

        // A key that does not count says that it syncs a name: the entry
        // is not taken, and were it in the store it would list nothing.
        let stranger = Machine::new(9);
        let word = entry_by(
            &stranger.identity,
            &personal,
            1,
            "name/theirs",
            Value::Text(String::new()),
            &[],
        );
        assert_eq!(
            take(&s[0].conn, &s[0].identity, &word, now).unwrap(),
            Taken::Refused(NotTaken::SignerDoesNotCount)
        );
        entries::store(&s[0].conn, &word, now).unwrap();
        assert_eq!(listed_on(&s, 0), [("lab".to_string(), vec![0])]);
    }

    /// A word in a band above the statement's counts for nothing
    /// (decision 2026-10-04 §2.3), by the one rule for every word that
    /// is read as a name: it lists no name in the generation applied,
    /// for its own device or for any other, is counted as no word that
    /// is no name, and is not noted as listed before when the generation
    /// is left. A word in the statement's own band, and one in a band
    /// below it, are read.
    #[test]
    fn test_a_word_in_a_band_above_the_statements_is_read_nowhere() {
        use cordelia_core::protocol::REV_COUNT_BITS;
        let mut s = Several::of_one_person(2);
        // A second statement, so that there is a band below the applied
        // one's as well as one above it.
        s.change(0, &[0, 1], &[]);
        let change = s[0].latest();
        let now = s.tick();
        take(&s[1].conn, &s[1].identity, &change, now).unwrap();
        assert_eq!((s[0].number(), s[1].number()), (2, 2));
        let personal = s[0].personal();
        let word = |by: usize, band: u64, name: &str| {
            entry_by(
                &s[by].identity,
                &personal,
                (band << REV_COUNT_BITS) + 1,
                &word_name(name),
                Value::Text(String::new()),
                &[],
            )
        };
        // As a store would hold them had it taken them: the door for an
        // entry from outside takes none in a band above.
        for entry in [
            word(1, 1, "below"),
            word(1, 2, "in-its-band"),
            word(1, 3, "above"),
            word(0, 3, "its-own-above"),
            word(1, 3, "Above And No Name"),
        ] {
            entries::store(&s[0].conn, &entry, now).unwrap();
        }
        assert_eq!(
            listed_on(&s, 0),
            [
                ("below".to_string(), vec![1]),
                ("in-its-band".to_string(), vec![1])
            ]
        );
        assert!(said_here(&s[0].conn, &s[0].identity).unwrap().is_empty());
        assert!(not_names(&s[0].conn).unwrap().is_empty());

        // The generation is left: what was listed is noted by the same
        // rule.
        s.change(0, &[0, 1], &[]);
        let noted: Vec<String> = held_rows::names_before(&s[0].conn)
            .unwrap()
            .into_iter()
            .map(|before| before.name)
            .collect();
        assert_eq!(noted, ["below", "in-its-band"]);
    }

    /// A device that follows no phrase has no secret: it holds no name,
    /// says nothing and lists nothing (decision 2026-10-04 §5.2). Nor
    /// does one that has stopped write a word.
    #[test]
    fn test_a_device_that_follows_no_phrase_or_has_stopped_says_nothing() {
        let alone = Machine::new(7);
        let now = crate::several::START;
        maps(&alone, &["lab"], true);
        assert!(matches!(
            say(&alone.conn, &alone.identity, "lab", now),
            Err(PersonError::FollowsNoPhrase)
        ));
        assert!(matches!(
            sync_name(&alone.conn, &alone.identity, "lab", now),
            Err(PersonError::FollowsNoPhrase)
        ));
        assert!(!unsay(&alone.conn, &alone.identity, "lab", now).unwrap());
        assert_eq!(hold_mapped(&alone.conn, &alone.identity, now).unwrap(), 0);
        assert_eq!(unsay_all(&alone.conn, &alone.identity, now).unwrap(), 0);
        assert!(listed(&alone.conn).unwrap().is_empty());
        assert!(said_here(&alone.conn, &alone.identity).unwrap().is_empty());
        assert!(not_listed_yet(&alone.conn).unwrap().is_empty());
        assert!(!may_say(&alone.conn).unwrap());
        assert!(held_rows::names(&alone.conn).unwrap().is_empty());

        // A device that was removed, and has been shown so, has stopped.
        let mut s = Several::of_one_person(2);
        let now = s.tick();
        maps(&s[1], &["lab"], true);
        assert_eq!(hold_mapped(&s[1].conn, &s[1].identity, now).unwrap(), 1);
        assert!(may_say(&s[1].conn).unwrap());
        let change = s.change(0, &[0], &[1]);
        let now = s.tick();
        take(&s[1].conn, &s[1].identity, &change, now).unwrap();
        assert_eq!(s[1].state(), State::Removed);
        assert!(!may_say(&s[1].conn).unwrap());
        let stored = s[1].stored().len();
        assert!(matches!(
            say(&s[1].conn, &s[1].identity, "other", now),
            Err(PersonError::Stopped(State::Removed))
        ));
        assert!(!unsay(&s[1].conn, &s[1].identity, "lab", now).unwrap());
        assert_eq!(hold_mapped(&s[1].conn, &s[1].identity, now).unwrap(), 0);
        assert_eq!(s[1].stored().len(), stored);
    }

    /// A device that comes to follow a phrase, or turns sync on, holds a
    /// name for each folder it maps, and with sync on says of each that
    /// it syncs it (decision 2026-10-04 §5.2, §6). A mapping whose name is
    /// not in its one spelling has no channel, and is passed over.
    #[test]
    fn test_a_name_is_held_for_each_mapped_folder_and_said_with_sync_on() {
        let mut s = Several::of_one_person(1);
        let now = s.tick();
        let held = |s: &Several| -> Vec<String> {
            let names = held_rows::names(&s[0].conn).unwrap();
            names.into_iter().map(|name| name.name).collect()
        };

        // With sync off: held, and nothing said.
        maps(&s[0], &["lab", "github.com/sam/notes.git", "~"], false);
        assert_eq!(hold_mapped(&s[0].conn, &s[0].identity, now).unwrap(), 2);
        assert_eq!(held(&s), ["lab", "~"]);
        assert!(said_here(&s[0].conn, &s[0].identity).unwrap().is_empty());

        // With sync on: said too. Done again, nothing more is written.
        maps(&s[0], &["lab", "github.com/sam/notes.git", "~"], true);
        assert_eq!(hold_mapped(&s[0].conn, &s[0].identity, now).unwrap(), 2);
        let said = said_here(&s[0].conn, &s[0].identity).unwrap();
        assert_eq!(said, BTreeSet::from(["lab".to_string(), "~".to_string()]));
        let stored = s[0].stored().len();
        assert_eq!(hold_mapped(&s[0].conn, &s[0].identity, now).unwrap(), 2);
        assert_eq!(s[0].stored().len(), stored);

        // Sync is turned off: every word is taken back, once, and the
        // names stay held: their folders are still mapped.
        assert_eq!(unsay_all(&s[0].conn, &s[0].identity, now).unwrap(), 2);
        assert!(said_here(&s[0].conn, &s[0].identity).unwrap().is_empty());
        assert_eq!(unsay_all(&s[0].conn, &s[0].identity, now).unwrap(), 0);
        assert_eq!(held(&s), ["lab", "~"]);
    }

    /// A name that is unmapped is synced no longer: the device takes its
    /// word back and holds the name no more. What its store held of the
    /// name's channel goes, with what it kept of each relay for it, and
    /// with what every folder had agreed there and its records of index
    /// lines.
    #[test]
    fn test_a_name_that_is_stopped_is_said_no_longer_and_held_no_more() {
        let mut s = Several::of_one_person(1);
        s.hold(&[0], "lab");
        s.hold(&[0], "stays");
        let now = s.tick();
        say(&s[0].conn, &s[0].identity, "lab", now).unwrap();
        s.write(0, "lab", "notes.md", "one");
        s.write(0, "stays", "notes.md", "one");
        let lab = held_rows::channel_of_name(&s[0].conn, "lab")
            .unwrap()
            .unwrap();
        let relay = [8u8; 32];
        kept_rows::sending(&s[0].conn, &relay, &lab).unwrap();
        assert!(kept_rows::keeps_any_anywhere(&s[0].conn, &lab).unwrap());
        // What two folders agreed in the name's channel, and a record of
        // an index line there; and what a folder agreed in the other
        // name's channel.
        let written = |on: &Machine, name: &str| {
            let channel = held_rows::channel_of_name(&on.conn, name).unwrap().unwrap();
            encode_channel_id(&channel).unwrap()
        };
        let (in_lab, in_stays) = (written(&s[0], "lab"), written(&s[0], "stays"));
        let agreed = sync_state::Agreed {
            hash: Some([7; 32]),
            rev: 1,
            signer: None,
            chain: None,
        };
        for (folder, channel) in [("/m", &in_lab), ("/n", &in_lab), ("/m", &in_stays)] {
            sync_state::save(&s[0].conn, folder, channel, "notes.md", &agreed).unwrap();
        }
        cordelia_storage::index_lines::line_removed(
            &s[0].conn, "/m", &in_lab, "notes.md", "- a line", now,
        )
        .unwrap();
        let lines_in = |on: &Machine, channel: &str| -> i64 {
            on.conn
                .query_row(
                    "SELECT COUNT(*) FROM index_lines WHERE channel_id = ?1",
                    [channel],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert_eq!(lines_in(&s[0], &in_lab), 1);
        // What the store holds of the name's channel, by the channel's ID.
        let stored_of_lab = |on: &Machine| {
            entries::channel_entries_after(&on.conn, &lab, 0, 100_000)
                .unwrap()
                .len()
        };
        assert_eq!(stored_of_lab(&s[0]), 1);

        let stopped = stop(&s[0].conn, &s[0].identity, "lab", now).unwrap();
        assert_eq!(stopped, Some(lab));
        assert!(matches!(word(&s[0], "lab"), Some((_, Value::Delete))));
        assert_eq!(held_rows::channel_of_name(&s[0].conn, "lab").unwrap(), None);
        assert_eq!(stored_of_lab(&s[0]), 0);
        assert!(!kept_rows::keeps_any_anywhere(&s[0].conn, &lab).unwrap());
        // No folder has a record in the channel that went, nor a record
        // of an index line there: held again, the name's channel is met
        // as on any first sync.
        for folder in ["/m", "/n"] {
            assert!(!sync_state::any(&s[0].conn, folder, &in_lab).unwrap());
        }
        assert_eq!(lines_in(&s[0], &in_lab), 0);
        // The other name is as it was, and what a folder agreed there.
        assert!(sync_state::any(&s[0].conn, "/m", &in_stays).unwrap());
        assert_eq!(s[0].text("stays", "notes.md").as_deref(), Some("one"));
        // Stopped already: there is no channel to say.
        assert_eq!(stop(&s[0].conn, &s[0].identity, "lab", now).unwrap(), None);
    }

    /// A word is read as a name only where it is one that this version
    /// would itself map, in its one spelling (decision 2026-10-04 §16).
    /// What a device wrote under `name/` that is none is counted for that
    /// device, and is in no list of names: not in what the personal
    /// channel lists, and not in what is noted of a generation that is
    /// left.
    #[test]
    fn test_a_word_that_is_no_name_is_counted_and_is_in_no_list_of_names() {
        use crate::several::{words_that_are_no_names, writes_words_that_are_no_names};
        for name in ["lab", "~", "github.com/sam/lab", "notes_2026", "a"] {
            assert!(is_a_name(name), "{name}");
        }
        for no_name in words_that_are_no_names() {
            assert!(!is_a_name(&no_name), "{no_name:?}");
        }
        for no_name in [
            "", "Lab", "lab.git", "lab/", " lab", "-lab", "a b", "a\tb", "\u{7}",
        ] {
            assert!(!is_a_name(no_name), "{no_name:?}");
        }
        let longest = "x".repeat(200);
        assert!(is_a_name(&longest) && !is_a_name(&format!("{longest}x")));

        let mut s = Several::of_one_person(2);
        let now = s.tick();
        for (n, name) in [(0, "team"), (1, "lab")] {
            s.hold(&[n], name);
            say(&s[n].conn, &s[n].identity, name, now).unwrap();
        }
        let no_names = writes_words_that_are_no_names(&mut s, 1, 0);
        assert_eq!(no_names, 6);
        // On the device that was given them: the names, and no other.
        assert_eq!(
            listed_on(&s, 0),
            [("lab".to_string(), vec![1]), ("team".to_string(), vec![0])]
        );
        assert_eq!(not_names(&s[0].conn).unwrap(), [(s.key(1), no_names)]);
        // The device that wrote them does not say that it syncs them.
        let said: Vec<String> = said_here(&s[1].conn, &s[1].identity)
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(said, ["lab"]);
        // A device that follows no phrase counts none.
        assert!(not_names(&Machine::new(7).conn).unwrap().is_empty());

        // Device 1 is removed. What the personal channel listed is noted:
        // the two names, and nothing of what was no name.
        s.change(0, &[0], &[1]);
        let noted: Vec<String> = held_rows::names_before(&s[0].conn)
            .unwrap()
            .into_iter()
            .map(|before| before.name)
            .collect();
        assert_eq!(noted, ["lab", "team"]);
        assert!(not_names(&s[0].conn).unwrap().is_empty());
        assert_eq!(not_names_before(&s[0].conn).unwrap(), 0);
        // What an earlier build noted is not read as a name either: it is
        // counted, once for each thing it noted.
        for no_name in &words_that_are_no_names()[..2] {
            for by in [s.key(0), s.key(1)] {
                held_rows::note_name_before(&s[0].conn, no_name, &by, s.now).unwrap();
            }
        }
        let not_yet: Vec<String> = not_listed_yet(&s[0].conn)
            .unwrap()
            .into_iter()
            .map(|name| name.name)
            .collect();
        assert_eq!(not_yet, ["lab"]);
        assert_eq!(not_names_before(&s[0].conn).unwrap(), 2);
    }

    /// The list of names in a new personal channel is what the devices
    /// under the statement say they sync (decision 2026-10-04 §7.3): a
    /// device carries its own words when it applies a statement. What the
    /// personal channel that is left listed is noted then, so that a name
    /// which no device lists yet in the new generation is shown, with the
    /// keys that had listed it; a name that only a key which no longer
    /// counts had listed is shown apart, as that. A name is shown no more
    /// once a device lists it.
    #[test]
    fn test_the_names_listed_before_a_statement_are_shown_until_a_device_lists_them() {
        let mut s = Several::of_one_person(3);
        let now = s.tick();
        for (n, name) in [(0, "lab"), (1, "team"), (2, "lab"), (2, "only-the-tablets")] {
            s.hold(&[n], name);
            say(&s[n].conn, &s[n].identity, name, now).unwrap();
        }
        s.meet(&[0, 1, 2]);
        assert!(not_listed_yet(&s[0].conn).unwrap().is_empty());
        // A word that was taken back lists nothing, and nor does the word
        // of a key that does not count, were one in the store: neither is
        // noted as a name that was listed.
        let now = s.tick();
        s.hold(&[1], "taken-back");
        say(&s[1].conn, &s[1].identity, "taken-back", now).unwrap();
        unsay(&s[1].conn, &s[1].identity, "taken-back", now).unwrap();
        s.pass(1, 0);
        let stranger = Machine::new(9);
        let personal = s[0].personal();
        let said = Value::Text(String::new());
        let word = entry_by(
            &stranger.identity,
            &personal,
            1,
            "name/strangers",
            said,
            &[],
        );
        entries::store(&s[0].conn, &word, now).unwrap();

        // Device 2 is removed, on device 0, which carries its own word.
        let change = s.change(0, &[0, 1], &[2]);
        let applied_at = s.now;
        assert_eq!(listed_on(&s, 0), [("lab".to_string(), vec![0])]);
        let not_yet = not_listed_yet(&s[0].conn).unwrap();
        let ninety_days = 90 * 24 * 60 * 60;
        assert_eq!(
            not_yet,
            [
                NotListedYet {
                    name: "only-the-tablets".into(),
                    by: vec![],
                    by_gone: vec![s.key(2)],
                    until: applied_at + ninety_days,
                },
                NotListedYet {
                    name: "team".into(),
                    by: vec![s.key(1)],
                    by_gone: vec![],
                    until: applied_at + ninety_days,
                },
            ]
        );

        let noted: Vec<String> = held_rows::names_before(&s[0].conn)
            .unwrap()
            .into_iter()
            .map(|before| before.name)
            .collect();
        assert_eq!(noted, ["lab", "lab", "only-the-tablets", "team"]);

        // Device 1 applies the statement, carries its word, and device 0
        // is given it: the name is listed, and shown no more.
        let now = s.tick();
        take(&s[1].conn, &s[1].identity, &change, now).unwrap();
        assert_eq!(s[1].number(), 2);
        assert_eq!(listed_on(&s, 1), [("team".to_string(), vec![1])]);
        s.pass(1, 0);
        let not_yet = not_listed_yet(&s[0].conn).unwrap();
        let names: Vec<&str> = not_yet.iter().map(|name| name.name.as_str()).collect();
        assert_eq!(names, ["only-the-tablets"]);

        // A device that leaves its phrase keeps no note of them.
        let now = s.tick();
        crate::leaving::forget(&s[0].conn, &s[0].identity, false, now).unwrap();
        assert!(held_rows::names_before(&s[0].conn).unwrap().is_empty());
    }

    /// A name that this device stops syncing is noted no longer as one
    /// that was listed before the last change: it is not shown, on the
    /// device that stopped it on purpose, as a name that no device lists
    /// yet (decision 2026-10-04 §7.3, §8). A name that the device only
    /// says no longer that it syncs, with sync turned off, is still
    /// mapped here, and is shown.
    #[test]
    fn test_a_name_that_this_device_stops_is_not_shown_as_listed_by_no_device() {
        let mut s = Several::of_one_person(2);
        let now = s.tick();
        for name in ["lab", "team"] {
            s.hold(&[0], name);
            say(&s[0].conn, &s[0].identity, name, now).unwrap();
        }
        s.meet(&[0, 1]);
        // A change is made on device 0, which carries its own words: it
        // lists both names in the new generation.
        s.change(0, &[0, 1], &[]);
        let noted = |s: &Several| -> Vec<String> {
            let before = held_rows::names_before(&s[0].conn).unwrap();
            before.into_iter().map(|before| before.name).collect()
        };
        let not_yet = |s: &Several| -> Vec<String> {
            let not_yet = not_listed_yet(&s[0].conn).unwrap();
            not_yet.into_iter().map(|name| name.name).collect()
        };
        assert_eq!(noted(&s), ["lab", "team"]);
        assert!(not_yet(&s).is_empty());

        // It stops one of them: that name is noted no longer, and shown
        // by nothing.
        let now = s.tick();
        assert!(
            stop(&s[0].conn, &s[0].identity, "lab", now)
                .unwrap()
                .is_some()
        );
        assert_eq!(noted(&s), ["team"]);
        assert!(not_yet(&s).is_empty());
        // The other it says no longer, and holds still: no device lists
        // it now, and the one that had listed it has said so on purpose.
        // It is shown no more, and stays noted until the generation is
        // left.
        assert!(unsay(&s[0].conn, &s[0].identity, "team", now).unwrap());
        assert!(not_yet(&s).is_empty());
        assert_eq!(noted(&s), ["team"]);
        // Stopped on a device that holds it no more: the note goes all
        // the same.
        assert!(held_rows::drop_name(&s[0].conn, "team").unwrap());
        assert_eq!(stop(&s[0].conn, &s[0].identity, "team", now).unwrap(), None);
        assert!(noted(&s).is_empty());
    }

    /// Where the device that had listed a name says, in the new
    /// generation, that it syncs it no longer, the note of it goes on
    /// every device that reads that (decision 2026-10-04 §10.1): the name
    /// is not shown as one that no device lists yet, for 90 days, on
    /// devices where nobody can do anything about it. The note of another
    /// key that had listed the name stays, and a word in a band above the
    /// statement's, or of a key that counts no longer, takes no note
    /// away. When the generation is left the note is gone for good.
    #[test]
    fn test_a_note_goes_where_the_device_that_listed_the_name_says_it_syncs_it_no_longer() {
        let mut s = Several::of_one_person(3);
        let now = s.tick();
        for (n, name) in [(1, "team"), (1, "lab"), (2, "lab"), (2, "tablets")] {
            s.hold(&[n], name);
            say(&s[n].conn, &s[n].identity, name, now).unwrap();
        }
        s.meet(&[0, 1, 2]);
        let change = s.change(0, &[0, 1, 2], &[]);
        let not_yet = |s: &Several, n: usize| -> Vec<(String, usize)> {
            let not_yet = not_listed_yet(&s[n].conn).unwrap();
            not_yet
                .into_iter()
                .map(|name| (name.name, name.by.len()))
                .collect()
        };
        let all = [("lab".into(), 2), ("tablets".into(), 1), ("team".into(), 1)];
        assert_eq!(not_yet(&s, 0), all);

        // Device 1 applies the change and carries its words. It then
        // unmaps one name: a delete over its word, in the new generation.
        let now = s.tick();
        take(&s[1].conn, &s[1].identity, &change, now).unwrap();
        assert!(
            stop(&s[1].conn, &s[1].identity, "team", now)
                .unwrap()
                .is_some()
        );
        // Until device 0 reads that, it shows the name.
        assert_eq!(not_yet(&s, 0), all);
        s.pass(1, 0);
        // Device 1 lists `lab` there, so that name is listed; and it has
        // said that it syncs `team` no longer, so that note is passed
        // over. What device 2 had listed is still not listed by it.
        assert_eq!(not_yet(&s, 0), [("tablets".into(), 1)]);
        assert_eq!(listed_on(&s, 0), [("lab".to_string(), vec![1])]);
        // It unmaps the other too: the name is listed by no device, and
        // is shown for device 2, which had listed it and has not said.
        let now = s.tick();
        stop(&s[1].conn, &s[1].identity, "lab", now).unwrap();
        s.pass(1, 0);
        assert_eq!(not_yet(&s, 0), [("lab".into(), 1), ("tablets".into(), 1)]);

        // A word in a band above the statement's says nothing: the note
        // stays. So does it for the word of a key that does not count.
        let above = entry_by(
            &s[2].identity,
            &s[0].personal(),
            (3 << cordelia_core::protocol::REV_COUNT_BITS) + 1,
            "name/tablets",
            Value::Delete,
            &[],
        );
        entries::store(&s[0].conn, &above, now).unwrap();
        assert_eq!(not_yet(&s, 0), [("lab".into(), 1), ("tablets".into(), 1)]);
        let stranger = Machine::new(9);
        held_rows::note_name_before(&s[0].conn, "theirs", &stranger.identity.public_key(), now)
            .unwrap();
        let theirs = entry_by(
            &stranger.identity,
            &s[0].personal(),
            (2 << cordelia_core::protocol::REV_COUNT_BITS) + 1,
            "name/theirs",
            Value::Delete,
            &[],
        );
        entries::store(&s[0].conn, &theirs, now).unwrap();
        let shown = not_listed_yet(&s[0].conn).unwrap();
        assert_eq!(shown.len(), 3);
        assert_eq!(shown[2].name, "theirs");
        assert_eq!(shown[2].by_gone.len(), 1);
        held_rows::forget_name_before(&s[0].conn, "theirs").unwrap();

        // The next statement: the notes that a device has answered since
        // go for good, before the store drops the generation, and what it
        // had listed and still lists is noted as of now.
        let noted = |s: &Several| -> Vec<(String, usize)> {
            let before = held_rows::names_before(&s[0].conn).unwrap();
            let key_of = |key: &[u8; 32]| (0..3).find(|n| s.key(*n) == *key).unwrap();
            before
                .into_iter()
                .map(|before| (before.name, key_of(&before.key)))
                .collect()
        };
        let both = |a: usize, b: usize| (a.min(b), a.max(b));
        let mut before = noted(&s);
        before.sort_by_key(|(name, key)| (name.clone(), *key));
        let lab = both(1, 2);
        assert_eq!(
            before,
            [
                ("lab".into(), lab.0),
                ("lab".into(), lab.1),
                ("tablets".into(), 2),
                ("team".into(), 1)
            ]
        );
        s.change(0, &[0, 1, 2], &[]);
        let mut after = noted(&s);
        after.sort_by_key(|(name, key)| (name.clone(), *key));
        assert_eq!(after, [("lab".into(), 2), ("tablets".into(), 2)]);
    }

    /// A name that a device holds for a carry that a person asked for is
    /// held and listed with no folder mapped to it (decision 2026-10-04
    /// §7.3, §9): its word stands with sync off, and is taken back only
    /// where the device stops the name. A name that a folder is mapped
    /// to is held for the folder, and its word goes with sync.
    #[test]
    fn test_a_name_held_for_a_carry_is_listed_with_no_folder_and_with_sync_off() {
        let mut s = Several::of_one_person(1);
        let now = s.tick();
        let (conn, identity) = (&s[0].conn, &s[0].identity);
        maps(&s[0], &["mapped"], true);
        hold_mapped(conn, identity, now).unwrap();
        assert!(carried(conn).unwrap().is_empty());

        let channel = hold_for_a_carry(conn, identity, "brought", now).unwrap();
        assert_eq!(channel, derive::channel_id(&s[0].own("brought")).unwrap());
        assert_eq!(
            held_rows::channel_of_name(conn, "brought").unwrap(),
            Some(channel)
        );
        let kept =
            |conn: &Connection| -> Vec<String> { carried(conn).unwrap().into_iter().collect() };
        assert_eq!(kept(conn), ["brought"]);
        let said = |conn: &Connection| -> Vec<String> {
            said_here(conn, identity).unwrap().into_iter().collect()
        };
        assert_eq!(said(conn), ["brought", "mapped"]);
        // Held again, nothing more is kept; and a name that a folder is
        // mapped to is held for the folder.
        hold_for_a_carry(conn, identity, "brought", now).unwrap();
        hold_for_a_carry(conn, identity, "mapped", now).unwrap();
        assert_eq!(kept(conn), ["brought"]);

        // Sync is turned off: the word of the name that a folder syncs
        // is taken back, and the other stands.
        assert_eq!(unsay_all(conn, identity, now).unwrap(), 1);
        assert_eq!(said(conn), ["brought"]);
        // The device stops the name: it is held and listed no more.
        assert!(stop(conn, identity, "brought", now).unwrap().is_some());
        assert!(kept(conn).is_empty());
        assert!(said(conn).is_empty());
        assert_eq!(meta::get(conn, meta::PERSON_NAMES_CARRIED).unwrap(), None);
        // Refused on a device that follows no phrase, and for what is no
        // name in its one spelling.
        let alone = Machine::new(9);
        assert!(hold_for_a_carry(&alone.conn, &alone.identity, "brought", now).is_err());
        assert!(hold_for_a_carry(conn, identity, "Not-A-Name", now).is_err());
        assert!(kept(conn).is_empty());
        // And a device that leaves its phrase keeps none.
        hold_for_a_carry(conn, identity, "brought", now).unwrap();
        crate::leaving::forget(conn, identity, false, now).unwrap();
        assert!(kept(conn).is_empty());
    }

    /// Where a device comes to sync a name it holds it, so that its
    /// channel is fetched, and says so, in one step. The channel is the
    /// name's, from the person's secret.
    #[test]
    fn test_a_device_that_comes_to_sync_a_name_holds_it_and_says_so() {
        let mut s = Several::of_one_person(1);
        let now = s.tick();
        let channel = sync_name(&s[0].conn, &s[0].identity, "lab", now).unwrap();
        assert_eq!(channel, derive::channel_id(&s[0].own("lab")).unwrap());
        assert_eq!(
            held_rows::channel_of_name(&s[0].conn, "lab").unwrap(),
            Some(channel)
        );
        assert_eq!(listed_on(&s, 0), [("lab".to_string(), vec![0])]);
        // What a folder agreed there is kept by the channel as written.
        let written = encode_channel_id(&channel).unwrap();
        assert!(!sync_state::any(&s[0].conn, "/home/sam/memory", &written).unwrap());
    }
}
