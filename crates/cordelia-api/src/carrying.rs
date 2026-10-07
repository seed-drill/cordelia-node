//! The node's half of a carry that a person asks for (decision 2026-10-04
//! §7.3, §7.5): `cordelia sync carry`, with and without the recovery
//! phrase, and what `cordelia sync map` carries for a name that the
//! device comes to sync.
//!
//! A carry by command reads the name's channel in each generation that
//! the device left and still holds the secret of, the newest first, at
//! each relay it reaches ([`read_at_relays`], through the node's one door
//! for that), and takes from each what keys that count signed there. Each
//! version goes to the one function that judges it
//! ([`crate::carry::bring`]): it comes in as this device's own entry, at
//! its revision, where the new channel holds neither that version nor an
//! entry at a higher revision.
//!
//! **What a key that does not count signed is not read by that at all.**
//! It comes in only by the command that names the key and asks for the
//! phrase (`--from`, [`from_look`] and [`from_take`]): the node says what
//! it found, takes nothing, and then takes only what a word that the
//! phrase signed allows ([`crate::carry::Word`]), into slots where the new
//! channel holds nothing, and above a version that it holds only for the
//! files that a second yes named.
//!
//! **A generation whose secret this device never held** is read by the
//! command that was typed the phrase, in its own process (`--phrase`):
//! the node is handed no secret. It proves the channel's key with proofs
//! that the command made ([`read_proved`]), hands back what the relays
//! handed, as it came, and is then handed the versions in the clear
//! ([`handed_take`]), again under a word that the phrase signed.
//!
//! The device's own store is brought up to what the relays hold of the
//! new channel first (a whole pass), so that what is judged against is
//! what the new channel holds now. What is carried waits in the store and
//! is sent like anything the device writes.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use cordelia_core::protocol::{CARRY_PART_MAX_BYTES, CARRY_READ_MAX_SECS};
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_crypto::fingerprint;
use cordelia_crypto::version::Version;
use cordelia_storage::entries;
use cordelia_storage::person::{self as held_rows, State};

use crate::carry::{self, Allows, Handed, Removed, Rule, Tally, WasRead, Word};
use crate::commands;
use crate::error::ApiError;
use crate::names;
use crate::person::{self, Held, PersonError};
use crate::state::{AppState, DoorAsk, LeftAt, LeftRead, ProvedBy};

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn db(state: &AppState) -> std::sync::MutexGuard<'_, rusqlite::Connection> {
    state.db.lock().unwrap_or_else(|e| e.into_inner())
}

/// Read the channel whose ID is `channel` at each relay that the device
/// is set up with, until `until`, through the node's one door for a carry
/// (decision 2026-10-04 §7.3, §9). It is of a generation that the device
/// has left, or never followed, and `by` says how its key is proved.
///
/// A node with no network has nobody to ask: nothing is read, of no
/// relay. Where the node does not take the asking up in time, nothing is
/// read either.
pub async fn read_at_relays(
    state: &AppState,
    channel: [u8; 32],
    by: ProvedBy,
    until: Instant,
) -> Vec<LeftAt> {
    if state.push_tx.is_none() {
        return Vec::new();
    }
    let (answer, answered) = tokio::sync::oneshot::channel();
    state.own_channels.ask_door(DoorAsk::Read {
        channel,
        by,
        until,
        answer,
    });
    // A little longer than the reading itself may take: the last page
    // that was asked for before `until` is still waited for.
    let wait = until.saturating_duration_since(Instant::now()) + Duration::from_secs(30);
    match tokio::time::timeout(wait, answered).await {
        Ok(Ok(read)) => read,
        _ => Vec::new(),
    }
}

/// Each relay that the device is set up with, by its name, with the value
/// of the session of its connection, where it has one: what a proof for
/// that connection is made over.
pub async fn sessions(state: &AppState) -> Vec<(String, Option<[u8; 32]>)> {
    if state.push_tx.is_none() {
        return Vec::new();
    }
    let (answer, answered) = tokio::sync::oneshot::channel();
    state.own_channels.ask_door(DoorAsk::Sessions { answer });
    match tokio::time::timeout(Duration::from_secs(30), answered).await {
        Ok(Ok(sessions)) => sessions,
        _ => Vec::new(),
    }
}

/// What the relays handed of one channel, as entries that pass the check,
/// and what is said of each relay: `whole` where it handed the channel to
/// its end, `part` where it did not, `not held`, `not reached`, or why
/// nothing was read there.
pub fn handed(read: &[LeftAt]) -> (Vec<CheckedEntry>, Vec<serde_json::Value>) {
    let mut entries = Vec::new();
    let mut said = Vec::new();
    for at in read {
        let how = match &at.read {
            LeftRead::NotReached => "not reached".to_string(),
            LeftRead::NotHeld => "not held".to_string(),
            LeftRead::NotRead(why) => format!("not read: {why}"),
            LeftRead::Read {
                entries: wire,
                whole,
            } => {
                let checked = wire
                    .iter()
                    .filter_map(|bytes| Entry::from_wire(bytes).ok()?.check().ok());
                entries.extend(checked);
                match whole {
                    true => "whole".to_string(),
                    false => "part".to_string(),
                }
            }
        };
        said.push(json!({ "relay": at.relay, "read": how }));
    }
    (entries, said)
}

/// Whether what a relay said of a read is that nothing more could be
/// had there: it handed the channel whole, or holds none of it.
fn read_to_its_end(said: &serde_json::Value) -> bool {
    matches!(said["read"].as_str(), Some("whole" | "not held"))
}

/// This device's key, as a key is written.
fn this_device(state: &AppState) -> Result<String, PersonError> {
    cordelia_crypto::bech32::encode_public_key(&state.identity.public_key())
        .map_err(|e| PersonError::Held(format!("this device's key: {e}")))
}

/// What this device holds of its person, where it may carry: it follows a
/// phrase, and has not stopped.
fn applied(conn: &rusqlite::Connection) -> Result<Held, PersonError> {
    let held = person::held(conn)?.ok_or(PersonError::FollowsNoPhrase)?;
    if held.state != State::Applied {
        return Err(PersonError::Stopped(held.state));
    }
    Ok(held)
}

/// Generations, each by its statement's number, with its secret.
pub(crate) type Secrets = Vec<(u64, Zeroizing<[u8; 32]>)>;

/// The generations that this device left and still holds the secret of,
/// the newest first: each by its statement's number, with its secret.
pub(crate) fn left_secrets(conn: &rusqlite::Connection) -> Result<Secrets, PersonError> {
    Ok(held_rows::secrets(conn)?
        .into_iter()
        .filter(|secret| secret.left_at.is_some())
        .map(|secret| (secret.number, Zeroizing::new(secret.secret)))
        .collect())
}

/// What is said where a device holds the secret of no generation that it
/// left.
const HOLDS_NO_LEFT_SECRET: &str = "this device holds the secret of no generation that it left: \
                                    there is nothing that it can read";

/// What the relays handed of a name's channel in one generation that the
/// device left.
pub(crate) struct Generation {
    /// The number of the generation's statement.
    pub(crate) number: u64,
    /// The secret of the name's channel in it.
    pub(crate) secret: Zeroizing<[u8; 32]>,
    pub(crate) entries: Vec<CheckedEntry>,
    /// What is said of each relay.
    pub(crate) said: Vec<serde_json::Value>,
}

impl Generation {
    /// Whether it was read to its end at every relay.
    pub(crate) fn read_all(&self) -> bool {
        !self.said.is_empty() && self.said.iter().all(read_to_its_end)
    }

    /// What a command is told of it, with how many of its entries keys
    /// signed that are not read by a carry of the keys that count.
    fn says(&self, by_other_keys: usize) -> serde_json::Value {
        json!({
            "number": self.number,
            "relays": self.said,
            "by_other_keys": by_other_keys,
        })
    }
}

/// Read the channel of `name` in each generation of `left`, at each
/// relay, until `until`: the node holds each secret, and proves each
/// channel's key itself.
pub(crate) async fn read_generations(
    state: &AppState,
    name: &str,
    left: &[(u64, Zeroizing<[u8; 32]>)],
    until: Instant,
) -> Result<Vec<Generation>, PersonError> {
    let mut read = Vec::new();
    for (number, secret) in left {
        let of_the_name = Zeroizing::new(derive::own_secret(secret, name)?);
        let channel = derive::channel_id(&of_the_name)?;
        let by = ProvedBy::Secret(of_the_name.clone());
        let at = read_at_relays(state, channel, by, until).await;
        let (entries, said) = handed(&at);
        read.push(Generation {
            number: *number,
            secret: of_the_name,
            entries,
            said,
        });
    }
    Ok(read)
}

/// The device holds `name`, so that its new channel is fetched and what
/// is carried into it is sent. Says whether it came to hold it now.
fn holds(state: &AppState, name: &str) -> Result<bool, PersonError> {
    let anew = {
        let conn = db(state);
        match held_rows::channel_of_name(&conn, name)? {
            Some(_) => false,
            None => {
                names::hold_for_a_carry(&conn, &state.identity, name, now())?;
                true
            }
        }
    };
    if anew {
        state.own_channels.written();
    }
    Ok(anew)
}

#[derive(Deserialize)]
pub struct CarryRequest {
    /// The name to carry.
    pub name: String,
}

/// What a carry of one name did (decision 2026-10-04 §7.3).
#[derive(Debug, Default)]
pub struct Carried {
    /// Whether the device came to hold the name for this carry.
    pub held_anew: bool,
    /// What was read: for each generation, its statement's number, what
    /// each relay handed, and how many entries keys that do not count
    /// signed there.
    pub generations: Vec<serde_json::Value>,
    pub tally: Tally,
    /// How many entries were left behind that other keys signed.
    pub by_other_keys: usize,
    /// Whether every channel was read to its end at every relay.
    pub read_all: bool,
    /// Why nothing was carried, where nothing was tried.
    pub nothing: Option<String>,
}

impl Carried {
    /// What a command is told of it.
    pub(crate) fn says(&self, name: &str) -> serde_json::Value {
        json!({
            "name": name,
            "held_anew": self.held_anew,
            "generations": self.generations,
            "carried": self.tally.carried,
            "held": self.tally.held,
            "higher": self.tally.higher,
            "ties": self.tally.ties,
            "above": self.tally.above,
            "deletes": self.tally.deletes,
            "by_other_keys": self.by_other_keys,
            "read_all": self.read_all,
            "nothing": self.nothing,
        })
    }
}

/// Carry the name `name` by command (see the module's documentation).
/// With `only_where_empty`, nothing is carried where the new channel
/// holds anything for the name: that is the carry of a device that comes
/// to sync a name (§7.3).
///
/// Refused on a device that follows no phrase or has stopped, and for a
/// name that is none in its one spelling.
pub async fn carry_name(
    state: &AppState,
    name: &str,
    only_where_empty: bool,
) -> Result<Carried, PersonError> {
    let mut done = Carried {
        read_all: true,
        ..Default::default()
    };
    // The generations it left and still holds the secret of, the newest
    // first; and the name is held, so that its new channel is fetched.
    let (left, counting) = {
        let conn = db(state);
        applied(&conn)?;
        if !names::is_a_name(name) {
            return Err(PersonError::NameNotHeld(name.to_string()));
        }
        (left_secrets(&conn)?, person::who_counts(&conn)?)
    };
    if left.is_empty() {
        done.nothing = Some(HOLDS_NO_LEFT_SECRET.into());
        return Ok(done);
    }
    done.held_anew = holds(state, name)?;

    // What the relays hold of the new channel is fetched first: what a
    // version is judged against is what the new channel holds now.
    let deadline = Instant::now() + Duration::from_secs(CARRY_READ_MAX_SECS);
    commands::fetch(state, true, deadline).await;

    let counts = |key: &[u8; 32]| counting.counts(key);
    let mut read: Vec<WasRead> = Vec::new();
    for generation in read_generations(state, name, &left, deadline).await? {
        done.read_all &= generation.read_all();
        let was = carry::read(
            &generation.entries,
            &generation.secret,
            generation.number,
            counts,
        )?;
        let other_keys = was.signed_by(|key| !counts(key));
        done.by_other_keys += other_keys;
        done.generations.push(generation.says(other_keys));
        read.push(was);
    }

    // Each version to the one function that judges it, the newest
    // generation first.
    {
        let conn = db(state);
        let channel = held_rows::channel_of_name(&conn, name)?
            .ok_or_else(|| PersonError::NameNotHeld(name.to_string()))?;
        if only_where_empty && !entries::channel_slots(&conn, &channel)?.is_empty() {
            done.nothing = Some(
                "the new channel holds something for this name already: nothing was carried \
                 for the mapping"
                    .into(),
            );
            return Ok(done);
        }
        for was in &read {
            for version in &was.versions {
                let brought =
                    carry::bring(&conn, &state.identity, name, version, Rule::Counts, now())?;
                done.tally.count(&version.name, brought);
            }
        }
    }
    if done.tally.carried > 0 {
        state.own_channels.written();
    }
    Ok(done)
}

/// `POST /api/v1/carry`: carry one name by command, with no phrase
/// (decision 2026-10-04 §7.3). Answers with what was read at which relay
/// in which generation, how many versions were brought in, and how many
/// were left and why.
pub async fn carry(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<CarryRequest>,
) -> Result<HttpResponse, ApiError> {
    commands::asked(&req, &state)?;
    let done = carry_name(&state, &body.name, false)
        .await
        .map_err(commands::refused)?;
    Ok(HttpResponse::Ok().json(done.says(&body.name)))
}

// ── What a removed key signed: `--from` ──────────────────────────────

/// The keys that the statement applied lists as removed, each with the
/// label that this device knew it by, where it knew it by one.
fn removed_keys(conn: &rusqlite::Connection, held: &Held) -> Result<Vec<Removed>, PersonError> {
    let labels = crate::look::removed_labels(conn)?;
    let label_of = |key: &[u8; 32]| {
        let known = labels.iter().find(|(known, _)| known == key);
        known.map(|(_, label)| label.clone()).unwrap_or_default()
    };
    let removed = &held.statement.statement.removed;
    Ok(removed
        .iter()
        .map(|key| Removed {
            key: *key,
            label: label_of(key),
        })
        .collect())
}

/// A removed key, as a command is told of one: its key in hex, the first
/// six words of its fingerprint, which name it, and its label.
fn removed_says(removed: &Removed) -> serde_json::Value {
    json!({
        "key": hex::encode(removed.key),
        "words": carry::naming_words(&removed.key),
        "shown": fingerprint::shown(&removed.key),
        "label": removed.label,
    })
}

/// Of what was read in the generations, the newest version of each file
/// among what the keys in `keys` signed (decision 2026-10-04 §7.3): with
/// several keys named, a carry judges once, and takes for each slot the
/// newest version among them.
pub(crate) fn newest_of(
    read: &[Generation],
    keys: &[[u8; 32]],
) -> Result<Vec<Version>, PersonError> {
    let mut all = Vec::new();
    for generation in read {
        let was = carry::read(
            &generation.entries,
            &generation.secret,
            generation.number,
            |key| keys.contains(key),
        )?;
        all.extend(was.versions);
    }
    Ok(carry::newest(all))
}

#[derive(Deserialize)]
pub struct FromLookRequest {
    /// The name.
    pub name: String,
    /// The removed keys that a person named, each by a label or by the
    /// first six words of its key's fingerprint. With none, the removed
    /// keys that signed there are listed, and nothing more is looked at.
    #[serde(default)]
    pub from: Vec<String>,
}

/// What `cordelia sync carry <name> --from` says before it asks for the
/// phrase (decision 2026-10-04 §7.3). **It takes nothing.**
///
/// It reads the name's channel in each generation that the device left
/// and still holds the secret of, and answers with:
///
/// - each removed key that signed there, with how many entries;
/// - where keys were named: those keys; how many of their versions would
///   go into slots where the new channel holds nothing; the files of
///   which a version of theirs stands above a version that the new
///   channel holds; and whether a folder of this device's is mapped to
///   the name, without which none of those comes in.
///
/// A key is named by the label that this device knew it by, or by the
/// first six words of its key's fingerprint: refused where either
/// matches two removed keys, or none ([`carry::named_key`]). With keys
/// named, the device comes to hold the name, so that what is judged
/// against is what the relays hold of its new channel.
pub async fn look_from(
    state: &AppState,
    name: &str,
    from: &[String],
) -> Result<serde_json::Value, PersonError> {
    let (left, removed, under) = {
        let conn = db(state);
        let held = applied(&conn)?;
        if !names::is_a_name(name) {
            return Err(PersonError::NameNotHeld(name.to_string()));
        }
        let removed = removed_keys(&conn, &held)?;
        let under = person::latest_entry(&conn)?.id();
        (left_secrets(&conn)?, removed, under)
    };
    let mut keys: Vec<[u8; 32]> = Vec::new();
    for named in from {
        let key = carry::named_key(named, &removed).map_err(PersonError::NotCarried)?;
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    let this_device = this_device(state)?;
    if left.is_empty() {
        return Ok(json!({
            "name": name,
            "this_device": this_device,
            "nothing": HOLDS_NO_LEFT_SECRET,
        }));
    }
    let deadline = Instant::now() + Duration::from_secs(CARRY_READ_MAX_SECS);
    let mut held_anew = false;
    if !keys.is_empty() {
        held_anew = holds(state, name)?;
        commands::fetch(state, true, deadline).await;
    }
    let read = read_generations(state, name, &left, deadline).await?;

    // Each removed key that signed there, with how much.
    let mut signed: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    for generation in &read {
        let was = carry::read(
            &generation.entries,
            &generation.secret,
            generation.number,
            |_| false,
        )?;
        for (key, entries) in was.signed {
            *signed.entry(key).or_default() += entries;
        }
    }
    let signed_there: Vec<serde_json::Value> = removed
        .iter()
        .filter_map(|one| {
            let entries = *signed.get(&one.key)?;
            let mut says = removed_says(one);
            says["entries"] = entries.into();
            Some(says)
        })
        .collect();

    // What the named keys signed, judged against the new channel, with
    // nothing written.
    let mut tally = Tally::default();
    let has_folder = {
        let conn = db(state);
        for version in newest_of(&read, &keys)? {
            let would =
                carry::would_bring(&conn, &state.identity, name, &version, Rule::EmptySlots)?;
            tally.count(&version.name, would);
        }
        names::has_folder(&conn, name)?
    };
    let named: Vec<serde_json::Value> = removed
        .iter()
        .filter(|one| keys.contains(&one.key))
        .map(removed_says)
        .collect();
    Ok(json!({
        "name": name,
        "this_device": this_device,
        // What the word is given under: the change entry that the device
        // keeps now.
        "under": hex::encode(under),
        "held_anew": held_anew,
        "signed": signed_there,
        "keys": named,
        // Would go into slots where the new channel holds nothing.
        "empty": tally.carried,
        // Stand above a version that the new channel holds, by file.
        "above": tally.above,
        "held": tally.held,
        "higher": tally.higher,
        "ties": tally.ties,
        "deletes": tally.deletes,
        "has_folder": has_folder,
        "generations": read.iter().map(|g| g.says(0)).collect::<Vec<_>>(),
        "read_all": read.iter().all(Generation::read_all),
        "nothing": null,
    }))
}

/// `POST /api/v1/carry/from/look` ([`look_from`]).
pub async fn from_look(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<FromLookRequest>,
) -> Result<HttpResponse, ApiError> {
    commands::asked(&req, &state)?;
    let found = look_from(&state, &body.name, &body.from).await;
    Ok(HttpResponse::Ok().json(found.map_err(commands::refused)?))
}

#[derive(Deserialize)]
pub struct WordRequest {
    /// The word that the phrase gave: what it allows is read from it.
    pub word: Word,
}

/// What `word` allows, where it holds: the phrase that this device
/// follows signed it, for this device, under the change entry that the
/// device keeps now, within its ten minutes ([`Word::holds`]).
fn allowed(state: &AppState, word: &Word) -> Result<Allows, PersonError> {
    let conn = db(state);
    allowed_still(&conn, state, word)?;
    Allows::of(word).ok_or(PersonError::NoWord)
}

/// Whether `word` holds, asked under the lock in which what it allows is
/// done: a change that reached the device since it was given ends it.
fn allowed_still(
    conn: &rusqlite::Connection,
    state: &AppState,
    word: &Word,
) -> Result<(), PersonError> {
    let held = applied(conn)?;
    let under = person::latest_entry(conn)?.id();
    let own = state.identity.public_key();
    match word.holds(&held.following.phrase_key, &own, &under, now()) {
        true => Ok(()),
        false => Err(PersonError::NoWord),
    }
}

/// What is said where a version was named to come in above one that the
/// new channel holds, for a name with no folder on this device.
pub const NO_FOLDER_FOR_ABOVE: &str = "no folder of this device's is mapped to that name: a \
    version that stands above one that the new channel holds is not brought in there, since \
    nothing would be kept of the text that it replaces";

/// Take what the named removed keys signed (decision 2026-10-04 §7.3),
/// as the word that the phrase gave allows ([`Allows::From`]), and
/// nothing beyond it.
///
/// The name's channel is read again in each generation that the device
/// left, and for each file the newest version among the named keys is
/// judged once ([`carry::bring`]): it comes in where the new channel
/// holds nothing in that slot; and above a version that it holds only
/// for a file that the word names, which a second yes named. A delete of
/// theirs is never taken.
///
/// Refused, with nothing taken: a word that does not hold; a key that
/// the statement applied does not list as removed; and a file named to
/// come in above a version, for a name that no folder of this device's
/// is mapped to: nothing would be kept of the text that it replaces.
pub async fn take_from(state: &AppState, word: &Word) -> Result<serde_json::Value, PersonError> {
    let not = |why: &str| PersonError::NotCarried(why.to_string());
    let Allows::From { name, keys, above } = allowed(state, word)? else {
        return Err(PersonError::NoWord);
    };
    let name = name.as_str();
    let (left, keys) = {
        let conn = db(state);
        let held = applied(&conn)?;
        if !names::is_a_name(name) {
            return Err(PersonError::NameNotHeld(name.to_string()));
        }
        let mut named: Vec<[u8; 32]> = Vec::new();
        for key in &keys {
            let key = carry::key_named(key).ok_or_else(|| not("a key that was named is none"))?;
            if !held.statement.statement.removes(&key) {
                return Err(not(
                    "a key that was named is not a removed key: only what a removed key signed \
                     is taken by this",
                ));
            }
            named.push(key);
        }
        if !above.is_empty() && !names::has_folder(&conn, name)? {
            return Err(not(NO_FOLDER_FOR_ABOVE));
        }
        (left_secrets(&conn)?, named)
    };
    let mut done = Carried {
        read_all: true,
        ..Default::default()
    };
    if left.is_empty() || keys.is_empty() {
        done.nothing = Some(match keys.is_empty() {
            true => "no key was named".into(),
            false => HOLDS_NO_LEFT_SECRET.into(),
        });
        return Ok(done.says(name));
    }
    done.held_anew = holds(state, name)?;
    let deadline = Instant::now() + Duration::from_secs(CARRY_READ_MAX_SECS);
    commands::fetch(state, true, deadline).await;
    let read = read_generations(state, name, &left, deadline).await?;
    for generation in &read {
        done.read_all &= generation.read_all();
        done.generations.push(generation.says(0));
    }
    {
        let conn = db(state);
        // The word was given under the change entry that the device kept
        // then: where it keeps another by now, nothing is taken.
        allowed_still(&conn, state, word)?;
        for version in newest_of(&read, &keys)? {
            let rule = match above.contains(&version.name) {
                true => Rule::Above,
                false => Rule::EmptySlots,
            };
            let brought = carry::bring(&conn, &state.identity, name, &version, rule, now())?;
            done.tally.count(&version.name, brought);
        }
    }
    if done.tally.carried > 0 {
        state.own_channels.written();
    }
    Ok(done.says(name))
}

/// `POST /api/v1/carry/from` ([`take_from`]).
pub async fn from_take(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<WordRequest>,
) -> Result<HttpResponse, ApiError> {
    commands::asked(&req, &state)?;
    let done = take_from(&state, &body.word).await;
    Ok(HttpResponse::Ok().json(done.map_err(commands::refused)?))
}

// ── A generation that this device never held: `--phrase` ─────────────

/// What `cordelia sync carry <name> --phrase` is handed before it asks
/// for the phrase (decision 2026-10-04 §7.3): the change entry that the
/// device keeps, whose part for the phrase the command opens in its own
/// process; the ID of the name's channel in each generation whose secret
/// this device holds, which the plain command reads; the keys that
/// count; and each relay with the value of its connection's session,
/// over which the command makes its proofs.
///
/// The device comes to hold the name, and fetches its new channel, so
/// that what is handed to it afterwards is judged against what the
/// relays hold now.
pub async fn look_for_phrase(
    state: &AppState,
    name: &str,
) -> Result<serde_json::Value, PersonError> {
    {
        let conn = db(state);
        applied(&conn)?;
        if !names::is_a_name(name) {
            return Err(PersonError::NameNotHeld(name.to_string()));
        }
    }
    let held_anew = holds(state, name)?;
    let deadline = Instant::now() + Duration::from_secs(CARRY_READ_MAX_SECS);
    commands::fetch(state, true, deadline).await;
    let sessions = sessions(state).await;
    let conn = db(state);
    let entry = person::latest_entry(&conn)?;
    let mut held_channels: Vec<String> = Vec::new();
    for secret in held_rows::secrets(&conn)? {
        let of_the_name = Zeroizing::new(derive::own_secret(&secret.secret, name)?);
        held_channels.push(hex::encode(derive::channel_id(&of_the_name)?));
    }
    let counting = person::who_counts(&conn)?;
    Ok(json!({
        "name": name,
        "this_device": this_device(state)?,
        "held_anew": held_anew,
        "entry": hex::encode(entry.to_wire()),
        "under": hex::encode(entry.id()),
        "held": held_channels,
        "counts": counting.keys().iter().map(hex::encode).collect::<Vec<_>>(),
        "sessions": sessions_say(&sessions),
    }))
}

/// `POST /api/v1/carry/phrase/look` ([`look_for_phrase`]).
pub async fn phrase_look(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<CarryRequest>,
) -> Result<HttpResponse, ApiError> {
    commands::asked(&req, &state)?;
    let handed = look_for_phrase(&state, &body.name).await;
    Ok(HttpResponse::Ok().json(handed.map_err(commands::refused)?))
}

/// The sessions, as a command is told them: each relay by its name, with
/// the value of its connection's session in hex, where it has one.
pub(crate) fn sessions_say(sessions: &[(String, Option<[u8; 32]>)]) -> Vec<serde_json::Value> {
    sessions
        .iter()
        .map(|(relay, session)| json!({ "relay": relay, "session": session.map(hex::encode) }))
        .collect()
}

#[derive(Deserialize)]
pub struct ProofFor {
    /// The relay, by its name.
    pub relay: String,
    /// The proof for the connection to it, in hex.
    pub proof: String,
}

#[derive(Deserialize)]
pub struct ReadRequest {
    /// The ID of the channel, in hex.
    pub channel: String,
    /// The proof of its key for each relay's connection: made by whoever
    /// holds the channel's secret, which the node does not.
    pub proofs: Vec<ProofFor>,
}

/// Read, at each relay, a channel whose secret the node does not hold,
/// with proofs that the command made in its own process (decision
/// 2026-10-04 §7.3, §9). It is how the command that was typed the phrase
/// reads the phrase's own channel, and a channel of a generation that
/// this device never held: **the node is handed no secret, and learns
/// none.** It proves and pulls, through the one door for a carry, and
/// hands back what each relay handed, as it came.
///
/// Answers with what is said of each relay, how many entries were
/// handed, and what the reading is named by: the entries themselves are
/// handed a part at a time ([`read_part`]). A channel of this device's
/// own is not read this way.
pub async fn read_with_proofs(
    state: &AppState,
    channel: [u8; 32],
    proofs: Vec<(String, [u8; 64])>,
) -> serde_json::Value {
    let until = Instant::now() + Duration::from_secs(CARRY_READ_MAX_SECS);
    let at = read_at_relays(state, channel, ProvedBy::Proofs(proofs), until).await;
    let (_, said) = handed(&at);
    // Each entry once, as it came: the command checks each itself.
    let mut entries: Vec<Vec<u8>> = Vec::new();
    for relay in at {
        if let LeftRead::Read { entries: wire, .. } = relay.read {
            for bytes in wire {
                if !entries.contains(&bytes) {
                    entries.push(bytes);
                }
            }
        }
    }
    let count = entries.len();
    let id = state.own_channels.shelve(entries);
    json!({ "relays": said, "read": id, "entries": count })
}

/// `POST /api/v1/carry/read` ([`read_with_proofs`]).
pub async fn read_proved(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ReadRequest>,
) -> Result<HttpResponse, ApiError> {
    commands::asked(&req, &state)?;
    let bad = |what: &str| ApiError::BadRequest(format!("{what} is not as many bytes in hex"));
    let channel: [u8; 32] = carry::key_named(&body.channel).ok_or_else(|| bad("channel"))?;
    let mut proofs: Vec<(String, [u8; 64])> = Vec::new();
    for proof in &body.proofs {
        let bytes: [u8; 64] = hex::decode(&proof.proof)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| bad("a proof"))?;
        proofs.push((proof.relay.clone(), bytes));
    }
    Ok(HttpResponse::Ok().json(read_with_proofs(&state, channel, proofs).await))
}

#[derive(Deserialize)]
pub struct PartRequest {
    /// What the reading is named by.
    pub read: u64,
    /// The first entry to hand, counted from none.
    pub from: usize,
}

/// `POST /api/v1/carry/read/part`: a part of what [`read_with_proofs`]
/// read, from the entry numbered `from` on: as many entries as fit a
/// part, each as the hex of its bytes, and where the next part begins,
/// where there is one. Only the last reading is kept: an older one is
/// answered as gone.
pub async fn read_part(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<PartRequest>,
) -> Result<HttpResponse, ApiError> {
    commands::asked(&req, &state)?;
    let part = state
        .own_channels
        .shelved(body.read, body.from, CARRY_PART_MAX_BYTES);
    let Some((entries, next)) = part else {
        return Err(ApiError::BadRequest(
            "that reading is kept no longer: another was made since".into(),
        ));
    };
    let entries: Vec<String> = entries.iter().map(hex::encode).collect();
    Ok(HttpResponse::Ok().json(json!({ "entries": entries, "next": next })))
}

#[derive(Deserialize)]
pub struct HandedRequest {
    /// The word that the phrase gave ([`Allows::Handed`]).
    pub word: Word,
    /// The versions that the command read, each in the clear.
    pub versions: Vec<Handed>,
}

/// Take the versions that the command read in generations whose secret
/// this device never held (decision 2026-10-04 §7.3), under the word
/// that the phrase gave for the name.
///
/// Each is judged as a carry by command judges a version that it read
/// itself ([`carry::bring`]): it comes in as this device's own entry, at
/// its revision, where the new channel holds neither that version nor an
/// entry at a higher revision. **One whose signer does not count is not
/// taken:** it is counted, and that is all.
pub fn take_handed(
    state: &AppState,
    word: &Word,
    versions: &[Handed],
) -> Result<serde_json::Value, PersonError> {
    let Allows::Handed { name } = allowed(state, word)? else {
        return Err(PersonError::NoWord);
    };
    let mut done = Carried {
        read_all: true,
        ..Default::default()
    };
    {
        let conn = db(state);
        allowed_still(&conn, state, word)?;
        let counting = person::who_counts(&conn)?;
        for handed in versions {
            let version = handed.version()?;
            let counts = version.entries.iter().all(|e| counting.counts(&e.author));
            if !counts {
                done.by_other_keys += 1;
                continue;
            }
            let brought =
                carry::bring(&conn, &state.identity, &name, &version, Rule::Counts, now())?;
            done.tally.count(&version.name, brought);
        }
    }
    if done.tally.carried > 0 {
        state.own_channels.written();
    }
    Ok(done.says(&name))
}

/// `POST /api/v1/carry/handed` ([`take_handed`]).
pub async fn handed_take(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<HandedRequest>,
) -> Result<HttpResponse, ApiError> {
    commands::asked(&req, &state)?;
    let done = take_handed(&state, &body.word, &body.versions);
    Ok(HttpResponse::Ok().json(done.map_err(commands::refused)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    use cordelia_crypto::entry::Value;
    use cordelia_crypto::phrase::Phrase;

    use crate::several::{Machine, Node, OTHER_WORDS, SESSION, Several, entry_by};

    const LAB: &str = "lab";

    /// Devices 0 and 2 sync a name, and device 2 writes there what only
    /// the relay is sent: over a file that device 0 holds, a file of its
    /// own, and a delete. It is then removed, on device 0. Returns the
    /// node of device 0, the phrase, and the key of the removed device.
    fn after_a_removal() -> (Node, Phrase, [u8; 32], [u8; 32]) {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 2], LAB);
        s.write(0, LAB, "kept.md", "of device 0");
        s.meet(&[0, 2]);
        let old = s[2].own(LAB);
        s.write(2, LAB, "kept.md", "over it");
        s.write(2, LAB, "only.md", "of device 2");
        let now = s.tick();
        let deleted = entry_by(&s[2].identity, &old, 1, "deleted.md", Value::Delete, &[]);
        cordelia_storage::entries::store(&s[2].conn, &deleted, now).unwrap();
        let at_the_relay = s[2].stored_in(&old);
        s.change(0, &[0, 1], &[2]);
        let (removed, counts) = (s.key(2), s.key(1));
        let phrase = Phrase::parse(crate::several::WORDS).unwrap();
        let node = Node::of(s.machines.remove(0));
        node.relay_holds(&old, &at_the_relay);
        (node, phrase, removed, counts)
    }

    fn from(keys: &[[u8; 32]], above: &[&str]) -> Allows {
        Allows::From {
            name: LAB.into(),
            keys: keys.iter().map(hex::encode).collect(),
            above: above.iter().map(|file| file.to_string()).collect(),
        }
    }

    /// `--from` with no key lists each removed key that signed in the
    /// generations that the device can read, with how much, and takes
    /// nothing (decision 2026-10-04 §7.3). With a key named, by its
    /// label or by the first six words of its fingerprint, it says what
    /// it found, and still takes nothing: how many versions would go
    /// into slots where the new channel holds none, which stand above a
    /// version that it holds, and how many are deletes.
    #[actix_web::test]
    async fn test_what_a_removed_key_signed_is_said_before_anything_is_taken() {
        let (node, _, removed, _) = after_a_removal();
        let before = node.stored();
        let listed = look_from(&node.state, LAB, &[]).await.unwrap();
        assert_eq!(listed["signed"].as_array().unwrap().len(), 1, "{listed}");
        let signed = &listed["signed"][0];
        assert_eq!(signed["key"], hex::encode(removed));
        assert_eq!(signed["words"], carry::naming_words(&removed));
        assert_eq!(signed["label"], "device 2");
        assert_eq!(signed["entries"], 3);
        assert_eq!(listed["keys"], json!([]));
        assert_eq!(listed["empty"], 0);
        // Nothing was written, and the name is not held anew for it.
        assert_eq!(listed["held_anew"], false);
        assert_eq!(node.stored(), before);
        // It was read through the door, with the secret that the node
        // holds of the generation it left.
        assert_eq!(node.asked.lock().unwrap().len(), 1);
        assert!(node.asked.lock().unwrap()[0].1);

        // Named by its label, and by its six words.
        for named in ["device 2".to_string(), carry::naming_words(&removed)] {
            let found = look_from(&node.state, LAB, &[named]).await.unwrap();
            assert_eq!(found["keys"][0]["key"], hex::encode(removed), "{found}");
            assert_eq!(found["empty"], 1, "{found}");
            assert_eq!(found["above"], json!(["kept.md"]));
            assert_eq!(found["deletes"], 1);
            assert_eq!(found["has_folder"], false);
            assert_eq!(found["read_all"], true);
            let under = person::latest_entry(&db(&node.state)).unwrap().id();
            assert_eq!(found["under"], hex::encode(under));
        }
        assert_eq!(node.stored(), before);
        assert_eq!(node.text(LAB, "only.md"), None);
        assert_eq!(node.text(LAB, "kept.md").as_deref(), Some("of device 0"));

        // What names no removed key is refused: a label that none goes
        // by, and a key that counts.
        for none in ["nobody", "device 1"] {
            let refused = look_from(&node.state, LAB, &[none.to_string()]).await;
            assert!(
                matches!(&refused, Err(PersonError::NotCarried(why)) if why.contains("names no removed key")),
                "{refused:?}"
            );
        }
        // What is no name, and a device that follows no phrase.
        let no_name = look_from(&node.state, "Not A Name", &[]).await;
        assert!(matches!(no_name, Err(PersonError::NameNotHeld(_))));
        let alone = Node::of(Machine::new(9));
        let none = look_from(&alone.state, LAB, &[]).await;
        assert!(matches!(none, Err(PersonError::FollowsNoPhrase)));
    }

    /// What a removed key signed comes in only under a word that the
    /// phrase gave (decision 2026-10-04 §7.3): into slots where the new
    /// channel holds nothing, and never its delete. Above a version that
    /// the new channel holds, only for the files that the word names,
    /// and only for a name that has a folder on this device.
    #[actix_web::test]
    async fn test_what_a_removed_key_signed_comes_in_only_as_the_phrases_word_allows() {
        let (node, phrase, removed, counts) = after_a_removal();
        let before = node.stored();
        let own = node.state.identity.public_key();
        let under = person::latest_entry(&db(&node.state)).unwrap().id();
        let says = from(&[removed], &[]).says().unwrap();

        // No word that holds: nothing is read at a relay, and nothing is
        // taken.
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let no_words = [
            // Another phrase gave it.
            node.word(&other, &from(&[removed], &[])),
            // It was given for another device, and under another entry.
            Word::give(&phrase, &counts, &under, says.clone(), now()).unwrap(),
            Word::give(&phrase, &own, &[9; 32], says.clone(), now()).unwrap(),
            // Its ten minutes have gone by.
            Word::give(&phrase, &own, &under, says.clone(), now() - 601).unwrap(),
            // It allows another thing.
            node.word(&phrase, &Allows::Handed { name: LAB.into() }),
            // Its text was changed after it was signed.
            Word {
                what: from(&[removed], &["kept.md"]).says().unwrap(),
                ..node.word(&phrase, &from(&[removed], &[]))
            },
        ];
        for word in &no_words {
            let refused = take_from(&node.state, word).await;
            assert!(matches!(refused, Err(PersonError::NoWord)), "{refused:?}");
        }
        // A word that holds, for a key that is not removed; and one that
        // names a file to come in above, for a name with no folder.
        let not_removed = take_from(&node.state, &node.word(&phrase, &from(&[counts], &[]))).await;
        assert!(
            matches!(&not_removed, Err(PersonError::NotCarried(why)) if why.contains("not a removed key")),
            "{not_removed:?}"
        );
        let no_folder = node.word(&phrase, &from(&[removed], &["kept.md"]));
        let refused = take_from(&node.state, &no_folder).await;
        assert!(
            matches!(&refused, Err(PersonError::NotCarried(why)) if why == NO_FOLDER_FOR_ABOVE),
            "{refused:?}"
        );
        assert_eq!(node.stored(), before);
        assert!(node.asked.lock().unwrap().is_empty());

        // The word: one version into the empty slot. The version that
        // stands above one that the new channel holds is left, and the
        // delete is never taken.
        let word = node.word(&phrase, &from(&[removed], &[]));
        let done = take_from(&node.state, &word).await.unwrap();
        assert_eq!(done["carried"], 1, "{done}");
        assert_eq!(done["above"], json!(["kept.md"]));
        assert_eq!(done["deletes"], 1);
        assert_eq!(node.text(LAB, "only.md").as_deref(), Some("of device 2"));
        assert_eq!(node.text(LAB, "kept.md").as_deref(), Some("of device 0"));
        assert_eq!(node.text(LAB, "deleted.md"), None);
        assert_eq!(node.stored(), before + 1);
        // Run again, it takes what the new channel still lacks: nothing.
        let again = take_from(&node.state, &word).await.unwrap();
        assert_eq!((&again["carried"], &again["held"]), (&json!(0), &json!(1)));

        // With a folder mapped, the second yes named the file: it comes
        // in above the version that the new channel holds.
        node.maps_a_folder(LAB);
        let word = node.word(&phrase, &from(&[removed], &["kept.md"]));
        let done = take_from(&node.state, &word).await.unwrap();
        assert_eq!(done["carried"], 1, "{done}");
        assert_eq!(done["above"], json!([]));
        assert_eq!(node.text(LAB, "kept.md").as_deref(), Some("over it"));
        // A file that the word does not name stays where it is.
        assert_eq!(node.text(LAB, "deleted.md"), None);
    }

    /// A generation whose secret this device never held is read by the
    /// command, and the node is handed no secret (decision 2026-10-04
    /// §7.3): it says which channels it can read itself, and each relay's
    /// session; it reads a channel with proofs that were made for it,
    /// and hands back what the relay handed, a part at a time; and it
    /// takes the versions that it is handed only under the phrase's
    /// word, and only where a key that counts signed them.
    #[actix_web::test]
    async fn test_a_generation_never_held_is_read_by_the_command_and_handed_in_the_clear() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 2], LAB);
        s.write(0, LAB, "kept.md", "of device 0");
        s.meet(&[0, 2]);
        let old = s[2].own(LAB);
        s.write(2, LAB, "kept.md", "edited on device 2");
        s.write(2, LAB, "late.md", "sent before the change");
        let at_the_relay = s[2].stored_in(&old);
        // Device 2 still counts; device 1 is removed.
        s.change(0, &[0, 2], &[1]);
        let (two, one) = (s.key(2), s.key(1));
        let phrase = Phrase::parse(crate::several::WORDS).unwrap();
        let entry = s[0].latest();
        let node = Node::of(s.machines.remove(0));
        node.relay_holds(&old, &at_the_relay);
        let own = node.state.identity.public_key();

        // What the command is handed before it asks for the phrase.
        let handed = look_for_phrase(&node.state, LAB).await.unwrap();
        assert_eq!(handed["entry"], hex::encode(entry.to_wire()));
        assert_eq!(handed["under"], hex::encode(entry.id()));
        let old_channel = hex::encode(derive::channel_id(&old).unwrap());
        // It holds the secret of the generation it left, and of the one
        // applied: it says each of the name's channels that it can read.
        let held: Vec<&str> = handed["held"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|channel| channel.as_str())
            .collect();
        assert_eq!(held.len(), 2);
        assert!(held.contains(&old_channel.as_str()));
        let counts: Vec<String> = vec![hex::encode(own), hex::encode(two)];
        assert_eq!(handed["counts"], json!(counts));
        assert_eq!(
            handed["sessions"],
            json!([{ "relay": "relay", "session": hex::encode(SESSION) }])
        );

        // The command reads a channel with proofs of its own making: the
        // node is handed the proofs, and no secret.
        let (statement, for_phrase) = crate::change::read_with(&phrase, &entry).unwrap();
        assert_eq!(statement.statement.number, 2);
        assert_eq!(for_phrase.earlier.len(), 1);
        let first = derive::own_secret(&for_phrase.earlier[0].secret, LAB).unwrap();
        assert_eq!(first, old);
        let proof = cordelia_crypto::proof::make(&first, &SESSION, &own).unwrap();
        let channel = derive::channel_id(&first).unwrap();
        node.asked.lock().unwrap().clear();
        let read = read_with_proofs(&node.state, channel, vec![("relay".into(), proof)]).await;
        assert_eq!(read["entries"], 3, "{read}");
        assert_eq!(
            read["relays"],
            json!([{ "relay": "relay", "read": "whole" }])
        );
        assert_eq!(*node.asked.lock().unwrap(), [(channel, false)]);
        // A part at a time, and nothing is kept of it after the last.
        let id = read["read"].as_u64().unwrap();
        let (part, next) = node.state.own_channels.shelved(id, 0, 1).unwrap();
        assert_eq!((part.len(), next), (1, Some(1)));
        let (rest, next) = node.state.own_channels.shelved(id, 1, usize::MAX).unwrap();
        assert_eq!((rest.len(), next), (2, None));
        assert_eq!(node.state.own_channels.shelved(id, 0, usize::MAX), None);

        // The command reads what was handed, and hands the node the
        // versions in the clear.
        let entries: Vec<CheckedEntry> = part
            .iter()
            .chain(&rest)
            .map(|bytes| Entry::from_wire(bytes).unwrap().check().unwrap())
            .collect();
        let was = carry::read(&entries, &first, 1, |key| *key == own || *key == two).unwrap();
        let versions: Vec<Handed> = carry::newest(was.versions)
            .iter()
            .filter_map(|version| Handed::of(version, &own))
            .collect();
        assert_eq!(versions.len(), 2);
        let before = node.stored();
        // With no word that holds, nothing is taken.
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        for word in [
            node.word(&other, &Allows::Handed { name: LAB.into() }),
            node.word(&phrase, &from(&[one], &[])),
        ] {
            let refused = take_handed(&node.state, &word, &versions);
            assert!(matches!(refused, Err(PersonError::NoWord)), "{refused:?}");
        }
        assert_eq!(node.stored(), before);
        // With the phrase's word, each comes in as a carry by command
        // brings one in.
        let word = node.word(&phrase, &Allows::Handed { name: LAB.into() });
        let done = take_handed(&node.state, &word, &versions).unwrap();
        assert_eq!(done["carried"], 2, "{done}");
        assert_eq!(
            node.text(LAB, "kept.md").as_deref(),
            Some("edited on device 2")
        );
        assert_eq!(
            node.text(LAB, "late.md").as_deref(),
            Some("sent before the change")
        );
        // A version that says a key signed it which does not count is
        // not taken: it is counted, and that is all.
        let theirs = Handed {
            name: "theirs.md".into(),
            signer: hex::encode(one),
            ..versions[0].clone()
        };
        let done = take_handed(&node.state, &word, &[theirs]).unwrap();
        assert_eq!(
            (&done["carried"], &done["by_other_keys"]),
            (&json!(0), &json!(1))
        );
        assert_eq!(node.text(LAB, "theirs.md"), None);
    }
}
