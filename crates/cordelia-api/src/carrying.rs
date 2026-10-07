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
//! ([`handed_take`]), again under a word that the phrase signed: a batch
//! at a time, each signed by the key that the word names for its run.
//!
//! **A word is taken once** ([`carry::take_once`]), and under the word of
//! `--phrase` each batch is ([`carry::take_batch_once`]): in the
//! transaction that brings in what the word allows.
//!
//! The device's own store is brought up to what the relays hold of the
//! new channel first (a whole pass), so that what is judged against is
//! what the new channel holds now. **Where that could not be done, nothing
//! is taken** ([`fetched_whole`]): no relay answered, or the pass did not
//! end with every channel read to its end, so which slots of the new
//! channel hold nothing is not known. The command says that the new
//! channel could not be read. What is carried waits in the store and is
//! sent like anything the device writes.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use cordelia_core::protocol::{
    CARRY_PART_MAX_BYTES, CARRY_READ_MAX_SECS, OUTBOX_FLUSH_INTERVAL_SECS,
};
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_crypto::fingerprint;
use cordelia_crypto::version::Version;
use cordelia_storage::entries;
use cordelia_storage::person::{self as held_rows, State};

use crate::carry::{self, Allows, Handed, Removed, Rule, Tally, WasRead, Word};
use crate::commands::{self, Waited};
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
///
/// **Where a connection has no room left for the channel's proof, it is
/// made again, and the read goes on there** (decision 2026-10-04 §16): a
/// relay remembers the proofs of so many channels for one connection,
/// and a new connection starts with none remembered. The node holding
/// the channel's secret proves it anew on the new connection. Proofs
/// that a command made were made for the connection that is gone: the
/// relay is then answered for as one whose connection changed, and the
/// command makes them again.
pub async fn read_at_relays(
    state: &AppState,
    channel: [u8; 32],
    by: ProvedBy,
    until: Instant,
) -> Vec<LeftAt> {
    if state.push_tx.is_none() {
        return Vec::new();
    }
    let mut read = asks_to_read(state, channel, by.clone(), None, until).await;
    loop {
        let no_room = |at: &&LeftAt| at.read == LeftRead::NoRoom;
        let full: Vec<String> = read
            .iter()
            .filter(no_room)
            .map(|at| at.relay.clone())
            .collect();
        if full.is_empty() || Instant::now() >= until {
            return read;
        }
        let remade = made_again(state, &full, until).await;
        let again = match &by {
            ProvedBy::Secret(_) if remade.is_empty() => return read,
            ProvedBy::Secret(_) => {
                asks_to_read(state, channel, by.clone(), Some(remade), until).await
            }
            ProvedBy::Proofs(_) => full
                .iter()
                .map(|relay| LeftAt {
                    relay: relay.clone(),
                    read: LeftRead::Changed,
                })
                .collect(),
        };
        for at in again {
            if let Some(of_it) = read.iter_mut().find(|of_it| of_it.relay == at.relay) {
                *of_it = at;
            }
        }
    }
}

/// One asking of the door to read `channel`: at every relay, or at those
/// named in `only`.
async fn asks_to_read(
    state: &AppState,
    channel: [u8; 32],
    by: ProvedBy,
    only: Option<Vec<String>>,
    until: Instant,
) -> Vec<LeftAt> {
    let (answer, answered) = tokio::sync::oneshot::channel();
    state.own_channels.ask_door(DoorAsk::Read {
        channel,
        by,
        only,
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

/// How often the node is asked whether a connection that is being made
/// again is there.
const REMADE_ASKED_EVERY: Duration = Duration::from_millis(200);

/// Have the connection to each relay named in `relays` made again
/// (decision 2026-10-04 §16), and wait, until `until` at most, for each
/// to have a connection that is another than the one it had: one with
/// another session. Returns the relays that have one.
async fn made_again(state: &AppState, relays: &[String], until: Instant) -> Vec<String> {
    let session_of = |all: &[(String, Option<[u8; 32]>)], relay: &String| {
        let of_it = all.iter().find(|(name, _)| name == relay);
        of_it.and_then(|(_, session)| *session)
    };
    let before = sessions(state).await;
    for relay in relays {
        let (answer, answered) = tokio::sync::oneshot::channel();
        state.own_channels.ask_door(DoorAsk::Remake {
            relay: relay.clone(),
            answer,
        });
        let _ = tokio::time::timeout(Duration::from_secs(30), answered).await;
    }
    loop {
        tokio::time::sleep(REMADE_ASKED_EVERY).await;
        let now = sessions(state).await;
        let another = |relay: &&String| {
            let is = session_of(&now, relay);
            is.is_some() && is != session_of(&before, relay)
        };
        let remade: Vec<String> = relays.iter().filter(another).cloned().collect();
        if remade.len() == relays.len() || Instant::now() >= until {
            return remade;
        }
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

/// What is said where the new channel could not be fetched whole before
/// a carry ([`fetched_whole`]).
pub const NEW_CHANNEL_NOT_READ: &str = "the new channel could not be read at a relay (no relay \
    answered, or the read did not end), so which of its slots hold nothing is not known: nothing \
    was taken. Run this again once a relay can be read";

/// Bring the device's store up to what the relays hold of its channels,
/// the new channel of a name that it has just come to hold among them,
/// and say whether that was done by `deadline` (decision 2026-10-04
/// §7.3): a whole pass that began after this was asked read every channel
/// to its end at every relay it reached ([`commands::fetch`]). **Which
/// slots of a new channel hold nothing is judged only where this says
/// yes.**
///
/// - Where no relay is connected, no relay answers: nothing is waited
///   for.
/// - A pass that ends early is asked for again, after the time between
///   two sends, for as long as `deadline` allows: a turn that it found
///   running at a relay has ended by then, and a device that has just
///   woken has heard from each relay or waited its time.
/// - A node with no network has no relay to read, and nothing to wait
///   for: what it holds is all there is.
pub(crate) async fn fetched_whole(state: &AppState, deadline: Instant) -> bool {
    if state.push_tx.is_none() {
        return true;
    }
    let connected = sessions(state).await;
    if !connected.iter().any(|(_, session)| session.is_some()) {
        return false;
    }
    loop {
        match commands::fetch(state, true, deadline).await {
            Waited::Done => return true,
            Waited::NotEnded => return false,
            Waited::EndedEarly => {}
        }
        let again = Instant::now() + Duration::from_secs(OUTBOX_FLUSH_INTERVAL_SECS);
        if again >= deadline {
            return false;
        }
        tokio::time::sleep_until(again.into()).await;
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
            LeftRead::Changed => "not read: the connection changed".to_string(),
            LeftRead::NoRoom => "not read: the connection has no room left for a proof".to_string(),
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
    // version is judged against is what the new channel holds now. Where
    // it could not be fetched whole, nothing is taken.
    let deadline = Instant::now() + Duration::from_secs(CARRY_READ_MAX_SECS);
    if !fetched_whole(state, deadline).await {
        done.read_all = false;
        done.nothing = Some(NEW_CHANNEL_NOT_READ.into());
        return Ok(done);
    }

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
    // Whether the new channel was fetched whole just before: only then
    // is it judged which of its slots hold nothing (§7.3).
    let mut new_read = true;
    if !keys.is_empty() {
        held_anew = holds(state, name)?;
        new_read = fetched_whole(state, deadline).await;
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
    // nothing written: and not judged at all where the new channel could
    // not be read.
    let mut tally = Tally::default();
    let has_folder = {
        let conn = db(state);
        for version in newest_of(&read, &keys)?.iter().filter(|_| new_read) {
            let would =
                carry::would_bring(&conn, &state.identity, name, version, Rule::EmptySlots)?;
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
        // Whether the new channel was fetched whole: where it was not,
        // nothing above was judged, and nothing is taken.
        "new_read": new_read,
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
/// **The word is taken once** (decision 2026-10-04 §16), in the
/// transaction that brings the versions in: posted again, it is refused,
/// and nothing is read for it.
///
/// Refused, with nothing taken: a word that does not hold, or that was
/// taken before; a key that the statement applied does not list as
/// removed; and a file named to come in above a version, for a name that
/// no folder of this device's is mapped to: nothing would be kept of the
/// text that it replaces.
pub async fn take_from(state: &AppState, word: &Word) -> Result<serde_json::Value, PersonError> {
    let not = |why: &str| PersonError::NotCarried(why.to_string());
    let Allows::From { name, keys, above } = allowed(state, word)? else {
        return Err(PersonError::NoWord);
    };
    let name = name.as_str();
    let (left, keys) = {
        let conn = db(state);
        if carry::is_taken(&conn, word, now())? {
            return Err(not(&format!("{}.", carry::WORD_TAKEN)));
        }
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
    // Which slots are empty is judged only where the new channel was
    // fetched whole just before (§7.3): where it could not be, nothing
    // is taken.
    let deadline = Instant::now() + Duration::from_secs(CARRY_READ_MAX_SECS);
    if !fetched_whole(state, deadline).await {
        done.read_all = false;
        done.nothing = Some(NEW_CHANNEL_NOT_READ.into());
        return Ok(done.says(name));
    }
    let read = read_generations(state, name, &left, deadline).await?;
    for generation in &read {
        done.read_all &= generation.read_all();
        done.generations.push(generation.says(0));
    }
    {
        let conn = db(state);
        // The word was given under the change entry that the device kept
        // then: where it keeps another by now, nothing is taken. And it
        // is taken once, as one with what it brings in.
        allowed_still(&conn, state, word)?;
        let versions = newest_of(&read, &keys)?;
        done.tally = person::in_one(&conn, || {
            carry::take_once(&conn, word, now())?;
            let mut tally = Tally::default();
            for version in &versions {
                let rule = match above.contains(&version.name) {
                    true => Rule::Above,
                    false => Rule::EmptySlots,
                };
                let brought = carry::bring(&conn, &state.identity, name, version, rule, now())?;
                tally.count(&version.name, brought);
            }
            Ok(tally)
        })?;
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
/// relays hold now. Refused where the new channel could not be fetched
/// whole ([`fetched_whole`]): the command is handed nothing, and gives
/// no word.
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
    // What the command hands back is judged against the new channel:
    // where that could not be fetched whole, nothing is handed out, and
    // so nothing is taken.
    let deadline = Instant::now() + Duration::from_secs(CARRY_READ_MAX_SECS);
    if !fetched_whole(state, deadline).await {
        return Err(PersonError::NotCarried(format!("{NEW_CHANNEL_NOT_READ}.")));
    }
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
    /// The number of this batch under the word: each is taken once.
    pub number: u64,
    /// The signature of the key that the word names for its run, over
    /// the batch's number and the hash of its versions, in hex
    /// ([`carry::batch_signed`]).
    pub signature: String,
    /// The versions that the command read, each in the clear.
    pub versions: Vec<Handed>,
}

/// One batch of versions that a command hands the node under its word:
/// its number, the signature of the key of the run over it, in hex, and
/// the versions.
#[derive(Debug, Clone, Copy)]
pub struct Batch<'a> {
    pub number: u64,
    pub signature: &'a str,
    pub versions: &'a [Handed],
}

/// Take the versions that the command read in generations whose secret
/// this device never held (decision 2026-10-04 §7.3), under the word
/// that the phrase gave for the name.
///
/// **What is handed is bound to the word** (decision 2026-10-04 §16):
/// the word names a key that the command made for that one run, the
/// batch is signed by that key over its number and its hash, and each
/// number is taken once under the word. So whoever sees the word cross
/// to the node can hand in no version of their own, and nothing twice.
///
/// Each version is judged as a carry by command judges a version that it
/// read itself ([`carry::bring`]): it comes in as this device's own
/// entry, at its revision, where the new channel holds neither that
/// version nor an entry at a higher revision. **One whose signer does not
/// count is not taken:** it is counted, and that is all.
///
/// Refused, with nothing taken: a word that does not hold; a batch that
/// the key of the run did not sign; a batch whose number was taken
/// before; and a batch that holds a version at a revision which no entry
/// may have under the statement applied ([`Handed::may_be_under`]).
pub fn take_handed(
    state: &AppState,
    word: &Word,
    batch: Batch,
) -> Result<serde_json::Value, PersonError> {
    let not = |why: &str| PersonError::NotCarried(format!("{why}."));
    let Allows::Handed { name, run } = allowed(state, word)? else {
        return Err(PersonError::NoWord);
    };
    let run = carry::key_named(&run).ok_or(PersonError::NoWord)?;
    if !carry::batch_holds(&run, batch.number, batch.versions, batch.signature) {
        return Err(not(carry::BATCH_NOT_SIGNED));
    }
    let mut done = Carried {
        read_all: true,
        ..Default::default()
    };
    {
        let conn = db(state);
        allowed_still(&conn, state, word)?;
        let number = applied(&conn)?.statement.statement.number;
        if !batch.versions.iter().all(|one| one.may_be_under(number)) {
            return Err(not(carry::REVISION_MAY_NOT_BE));
        }
        let counting = person::who_counts(&conn)?;
        (done.tally, done.by_other_keys) = person::in_one(&conn, || {
            carry::take_batch_once(&conn, word, batch.number, now())?;
            let (mut tally, mut by_other_keys) = (Tally::default(), 0);
            for handed in batch.versions {
                let version = handed.version()?;
                let counts = version.entries.iter().all(|e| counting.counts(&e.author));
                if !counts {
                    by_other_keys += 1;
                    continue;
                }
                let brought =
                    carry::bring(&conn, &state.identity, &name, &version, Rule::Counts, now())?;
                tally.count(&version.name, brought);
            }
            Ok((tally, by_other_keys))
        })?;
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
    let batch = Batch {
        number: body.number,
        signature: &body.signature,
        versions: &body.versions,
    };
    let done = take_handed(&state, &body.word, batch);
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

    /// A carry by command, on the node (decision 2026-10-04 §7.3): the
    /// name is held, its new channel is fetched, and its channel in each
    /// generation that the device left is read at the relay, with the
    /// node's own proof. What keys that count signed there comes in, each
    /// version as this device's own entry. What another key signed is
    /// counted, and not taken. Run again, it takes what the new channel
    /// still lacks: nothing.
    #[actix_web::test]
    async fn test_a_carry_by_command_takes_what_keys_that_count_signed_and_counts_the_rest() {
        let mut s = Several::of_one_person(3);
        s.hold(&[1, 2], LAB);
        let old = s[1].own(LAB);
        // Device 1, which stays, and device 2, which is removed, each
        // write a file that only the relay is sent.
        s.write(1, LAB, "stays.md", "of device 1");
        s.write(2, LAB, "gone.md", "of device 2");
        let mut at_the_relay = s[1].stored_in(&old);
        at_the_relay.extend(s[2].stored_in(&old));
        s.change(0, &[0, 1], &[2]);
        let node = Node::of(s.machines.remove(0));
        node.relay_holds(&old, &at_the_relay);
        let before = node.stored();

        let done = carry_name(&node.state, LAB, false).await.unwrap();
        assert!(done.held_anew);
        assert!(done.read_all);
        assert_eq!(done.tally.carried, 1);
        assert_eq!(done.by_other_keys, 1);
        assert_eq!(done.nothing, None);
        assert_eq!(node.text(LAB, "stays.md").as_deref(), Some("of device 1"));
        assert_eq!(node.text(LAB, "gone.md"), None);
        // The name's word, and the version.
        assert_eq!(node.stored(), before + 2);
        // The new channel was fetched before anything was read, and the
        // one generation that was left was read with the node's proof.
        assert_eq!(*node.did.lock().unwrap(), ["pass", "read"]);
        let channel = derive::channel_id(&old).unwrap();
        assert_eq!(*node.asked.lock().unwrap(), [(channel, true)]);
        let said = done.says(LAB);
        assert_eq!(
            said["generations"],
            json!([{
                "number": 1,
                "relays": [{ "relay": "relay", "read": "whole" }],
                "by_other_keys": 1,
            }])
        );

        // Again: the new channel holds it.
        let again = carry_name(&node.state, LAB, false).await.unwrap();
        assert!(!again.held_anew);
        assert_eq!((again.tally.carried, again.tally.held), (0, 1));
        assert_eq!(node.stored(), before + 2);

        // A relay that hands the channel in part: the carry says that it
        // did not read to the end, and where.
        node.in_part
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let part = carry_name(&node.state, LAB, false).await.unwrap();
        assert!(!part.read_all);
        assert_eq!(
            part.says(LAB)["generations"][0]["relays"],
            json!([{ "relay": "relay", "read": "part" }])
        );
    }

    /// A device that comes to sync a name carries it first, where the
    /// new channel holds nothing for it (decision 2026-10-04 §7.3). Where
    /// the new channel holds anything for the name, the mapping carries
    /// nothing, and says so: the command that is asked for by name does.
    #[actix_web::test]
    async fn test_a_mapping_carries_only_where_the_new_channel_holds_nothing() {
        let fixture = |holds_something: bool| {
            let mut s = Several::of_one_person(2);
            s.hold(&[1], LAB);
            let old = s[1].own(LAB);
            s.write(1, LAB, "theirs.md", "of device 1");
            let at_the_relay = s[1].stored_in(&old);
            s.change(0, &[0, 1], &[]);
            if holds_something {
                s.hold(&[0], LAB);
                s.write(0, LAB, "mine.md", "of device 0");
            }
            let node = Node::of(s.machines.remove(0));
            node.relay_holds(&old, &at_the_relay);
            node
        };
        // Nothing there: what the other device had sent is carried.
        let empty = fixture(false);
        let done = carry_name(&empty.state, LAB, true).await.unwrap();
        assert_eq!((done.tally.carried, &done.nothing), (1, &None));
        assert_eq!(empty.text(LAB, "theirs.md").as_deref(), Some("of device 1"));

        // Something there: nothing is carried for the mapping.
        let held = fixture(true);
        let before = held.stored();
        let done = carry_name(&held.state, LAB, true).await.unwrap();
        assert_eq!(done.tally.carried, 0);
        let nothing = done.nothing.unwrap();
        assert!(
            nothing.contains("holds something for this name already"),
            "{nothing}"
        );
        assert_eq!(held.stored(), before);
        assert_eq!(held.text(LAB, "theirs.md"), None);
        // Asked for by name, it is carried.
        let done = carry_name(&held.state, LAB, false).await.unwrap();
        assert_eq!(done.tally.carried, 1);
        assert_eq!(held.text(LAB, "theirs.md").as_deref(), Some("of device 1"));
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
        // With no key, a name that the device does not hold is not held
        // for the look.
        let other = look_from(&node.state, "another", &[]).await.unwrap();
        assert_eq!(other["signed"], json!([]));
        let held = held_rows::channel_of_name(&db(&node.state), "another");
        assert_eq!(held.unwrap(), None);

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
            node.word(
                &phrase,
                &Allows::Handed {
                    name: LAB.into(),
                    run: hex::encode(counts),
                },
            ),
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
        // **A word is taken once:** posted again, it is refused, whatever
        // case its signature is written in, and nothing is read for it.
        node.asked.lock().unwrap().clear();
        let in_capitals = Word {
            signature: word.signature.to_uppercase(),
            ..word.clone()
        };
        for posted_again in [&word, &in_capitals] {
            let refused = take_from(&node.state, posted_again).await;
            assert!(
                matches!(&refused, Err(PersonError::NotCarried(why)) if why.contains(carry::WORD_TAKEN)),
                "{refused:?}"
            );
        }
        assert!(node.asked.lock().unwrap().is_empty());
        assert_eq!(node.stored(), before + 1);
        // Run again, with a word given anew, it takes what the new
        // channel still lacks: nothing. (Another word than the first:
        // one that stands until another second.)
        let given = word.until - cordelia_core::protocol::CARRY_WORD_SECS - 2;
        let anew = Word::give(&phrase, &own, &under, says.clone(), given).unwrap();
        assert_ne!(anew.signature, word.signature);
        let again = take_from(&node.state, &anew).await.unwrap();
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

    /// **Which slots of the new channel hold nothing is judged only
    /// where the new channel was fetched whole just before** (decision
    /// 2026-10-04 §7.3). Where no relay answers, a plain carry, a
    /// mapping's carry, `--from` and `--phrase` take nothing, and each
    /// says that the new channel could not be read: nothing is read of
    /// what was left, and nothing is written. Once the relay answers,
    /// each does what it does.
    #[actix_web::test]
    async fn test_nothing_is_taken_where_the_new_channel_could_not_be_fetched_whole() {
        use std::sync::atomic::Ordering::SeqCst;
        let (node, phrase, removed, _) = after_a_removal();
        let before = node.stored();
        node.not_connected.store(true, SeqCst);

        for only_where_empty in [false, true] {
            let done = carry_name(&node.state, LAB, only_where_empty)
                .await
                .unwrap();
            assert_eq!(done.nothing.as_deref(), Some(NEW_CHANNEL_NOT_READ));
            assert!(!done.read_all);
            assert_eq!(done.tally, Tally::default());
        }
        // `--from`: nothing is judged before the phrase, and nothing is
        // taken with its word.
        let found = look_from(&node.state, LAB, &["device 2".to_string()])
            .await
            .unwrap();
        assert_eq!(found["new_read"], false, "{found}");
        assert_eq!((&found["empty"], &found["above"]), (&json!(0), &json!([])));
        assert_eq!(found["deletes"], 0);
        let word = node.word(&phrase, &from(&[removed], &[]));
        let taken = take_from(&node.state, &word).await.unwrap();
        assert_eq!(taken["nothing"], NEW_CHANNEL_NOT_READ, "{taken}");
        assert_eq!(taken["carried"], 0);
        // `--phrase`: the command is handed nothing.
        let refused = look_for_phrase(&node.state, LAB).await;
        assert!(
            matches!(&refused, Err(PersonError::NotCarried(why)) if why.starts_with(NEW_CHANNEL_NOT_READ)),
            "{refused:?}"
        );
        assert_eq!(node.stored(), before);
        assert_eq!(node.text(LAB, "only.md"), None);
        // No pass was waited for, and nothing that was left was taken:
        // only the look before the phrase read it, to list who signed.
        assert_eq!(*node.did.lock().unwrap(), ["read"]);

        // The relay answers: the same word takes what it allows.
        node.not_connected.store(false, SeqCst);
        let found = look_from(&node.state, LAB, &["device 2".to_string()])
            .await
            .unwrap();
        assert_eq!(found["new_read"], true);
        assert_eq!(found["empty"], 1, "{found}");
        let taken = take_from(&node.state, &word).await.unwrap();
        assert_eq!(
            (&taken["carried"], &taken["nothing"]),
            (&json!(1), &json!(null))
        );
        assert_eq!(node.text(LAB, "only.md").as_deref(), Some("of device 2"));
        assert!(look_for_phrase(&node.state, LAB).await.is_ok());
    }

    /// Where a connection has no room left for the proof of a channel
    /// that was left, it is made again, and the read goes on there
    /// (decision 2026-10-04 §16): a relay remembers the proofs of so many
    /// channels for one connection, and a new connection starts with
    /// none. The node proves the channel anew where it holds its secret.
    /// Proofs that a command made were made for the connection that is
    /// gone: the relay is answered for as one whose connection changed,
    /// and never as one that holds none.
    #[actix_web::test]
    async fn test_a_read_goes_on_at_a_connection_that_was_made_again() {
        use std::sync::atomic::Ordering::SeqCst;
        let mut s = Several::of_one_person(3);
        s.hold(&[1], LAB);
        let old = s[1].own(LAB);
        s.write(1, LAB, "stays.md", "of device 1");
        let at_the_relay = s[1].stored_in(&old);
        s.change(0, &[0, 1], &[2]);
        let node = Node::of(s.machines.remove(0));
        node.relay_holds(&old, &at_the_relay);
        let own = node.state.identity.public_key();

        // The connection has no room, twice: it is made again each time,
        // and the channel is then read to its end.
        node.no_room.store(2, SeqCst);
        let done = carry_name(&node.state, LAB, false).await.unwrap();
        assert_eq!(
            *node.did.lock().unwrap(),
            ["pass", "no room", "remake", "no room", "remake", "read"]
        );
        assert_eq!(node.remade.load(SeqCst), 2);
        assert!(done.read_all);
        assert_eq!(done.tally.carried, 1);
        assert_eq!(node.text(LAB, "stays.md").as_deref(), Some("of device 1"));
        let said = done.says(LAB);
        assert_eq!(
            said["generations"][0]["relays"],
            json!([{ "relay": "relay", "read": "whole" }])
        );

        // With proofs that a command made: the connection is made again,
        // and the command is told that it changed.
        node.did.lock().unwrap().clear();
        node.no_room.store(1, SeqCst);
        let channel = derive::channel_id(&old).unwrap();
        let session = crate::several::session_after(2);
        let proof = cordelia_crypto::proof::make(&old, &session, &own).unwrap();
        let read = read_with_proofs(&node.state, channel, vec![("relay".into(), proof)]).await;
        assert_eq!(*node.did.lock().unwrap(), ["no room", "remake"]);
        assert_eq!(read["entries"], 0, "{read}");
        assert_eq!(
            read["relays"],
            json!([{ "relay": "relay", "read": "not read: the connection changed" }])
        );
        assert_eq!(
            sessions(&node.state).await,
            [("relay".to_string(), Some(crate::several::session_after(3)))]
        );

        // The read goes on only once the connection is another: while
        // the node still says the session of the one that is being made
        // again, it waits, and asks nothing of the relay.
        node.did.lock().unwrap().clear();
        node.no_room.store(1, SeqCst);
        node.remake_takes.store(3, SeqCst);
        let by = ProvedBy::Secret(Zeroizing::new(old));
        let within = Instant::now() + Duration::from_secs(30);
        let at = read_at_relays(&node.state, channel, by, within).await;
        assert_eq!(*node.did.lock().unwrap(), ["no room", "remake", "read"]);
        assert!(matches!(at[0].read, LeftRead::Read { whole: true, .. }));
        node.remake_takes.store(0, SeqCst);

        // Where the time has gone by, the connection is not made again,
        // and the relay is said to be one that was not read: for want of
        // room, and not as one that holds none.
        node.did.lock().unwrap().clear();
        node.no_room.store(1, SeqCst);
        let by = ProvedBy::Secret(Zeroizing::new(old));
        let at = read_at_relays(&node.state, channel, by, Instant::now()).await;
        assert_eq!(*node.did.lock().unwrap(), ["no room"]);
        assert_eq!(
            handed(&at).1,
            [json!({
                "relay": "relay",
                "read": "not read: the connection has no room left for a proof",
            })]
        );
    }

    /// The new channel was fetched whole where a whole pass that began
    /// after the asking read every channel to its end (decision
    /// 2026-10-04 §7.3). A pass that ends early is asked for again: three
    /// at once, and then again after the time between two sends, for as
    /// long as the time allows. Where none goes to its end in that time,
    /// or no relay is connected, it was not.
    #[actix_web::test]
    async fn test_the_new_channel_is_fetched_whole_by_a_pass_that_read_everything() {
        use std::sync::atomic::Ordering::SeqCst;
        let (node, _, _, _) = after_a_removal();
        let within = |secs: u64| Instant::now() + Duration::from_secs(secs);
        let passes = |node: &Node| node.did.lock().unwrap().len();

        assert!(fetched_whole(&node.state, within(30)).await);
        assert_eq!(passes(&node), 1);
        // Three passes end early, and the next goes to its end: it is
        // asked for after a wait.
        node.short_passes.store(3, SeqCst);
        let began = Instant::now();
        assert!(fetched_whole(&node.state, within(30)).await);
        assert_eq!(passes(&node), 5);
        assert!(began.elapsed() >= Duration::from_secs(OUTBOX_FLUSH_INTERVAL_SECS));
        // Every pass ends early: not fetched, once the time has gone by.
        node.short_passes.store(usize::MAX, SeqCst);
        let began = Instant::now();
        assert!(!fetched_whole(&node.state, within(1)).await);
        assert!(began.elapsed() < Duration::from_secs(5));
        // No relay is connected: no pass is waited for.
        node.short_passes.store(0, SeqCst);
        node.not_connected.store(true, SeqCst);
        let asked = passes(&node);
        assert!(!fetched_whole(&node.state, within(30)).await);
        assert_eq!(passes(&node), asked);
        // A node with no network has nothing to fetch.
        let alone = crate::several::state_of(Machine::new(9));
        assert!(fetched_whole(&alone, within(30)).await);
    }

    /// A generation whose secret this device never held is read by the
    /// command, and the node is handed no secret (decision 2026-10-04
    /// §7.3): it says which channels it can read itself, and each relay's
    /// session; it reads a channel with proofs that were made for it,
    /// and hands back what the relay handed, a part at a time; and it
    /// takes the versions that it is handed only under the phrase's
    /// word, and only where a key that counts signed them.
    ///
    /// **What is handed is bound to the word** (§16): a batch that the
    /// key of the run did not sign is refused, and so is a batch that is
    /// posted twice, and one that holds a version at a revision which no
    /// entry may have under the statement applied.
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
        // The key of this run, which the word names: it signs each
        // batch over its number and its hash.
        let run = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
        let handed = Allows::Handed {
            name: LAB.into(),
            run: hex::encode(run.public_key()),
        };
        let signed_by =
            |key: &cordelia_crypto::identity::NodeIdentity, number: u64, versions: &[Handed]| {
                hex::encode(key.sign(&carry::batch_signed(number, versions).unwrap()))
            };
        let takes = |word: &Word, number: u64, signature: &str, versions: &[Handed]| {
            let batch = Batch {
                number,
                signature,
                versions,
            };
            take_handed(&node.state, word, batch)
        };
        let first_batch = signed_by(&run, 0, &versions);
        // With no word that holds, nothing is taken.
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        for word in [
            node.word(&other, &handed),
            node.word(&phrase, &from(&[one], &[])),
        ] {
            let refused = takes(&word, 0, &first_batch, &versions);
            assert!(matches!(refused, Err(PersonError::NoWord)), "{refused:?}");
        }
        let word = node.word(&phrase, &handed);
        let not_signed = |refused: Result<serde_json::Value, PersonError>| {
            assert!(
                matches!(&refused, Err(PersonError::NotCarried(why)) if why.contains(carry::BATCH_NOT_SIGNED)),
                "{refused:?}"
            );
        };
        // A batch that the key of the run did not sign: another key
        // signed it; the run's key signed another number, or other
        // versions; or it is signed by nothing.
        let another = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
        not_signed(takes(
            &word,
            0,
            &signed_by(&another, 0, &versions),
            &versions,
        ));
        not_signed(takes(&word, 1, &first_batch, &versions));
        let mut changed = versions.clone();
        changed[0].text = Some("a text of somebody's own".into());
        not_signed(takes(&word, 0, &first_batch, &changed));
        not_signed(takes(&word, 0, &first_batch, &versions[..1]));
        not_signed(takes(&word, 0, "zz", &versions));
        // A version at a revision that no entry may have under the
        // statement applied, which is the second: one in a band above
        // it, and revision 0. The key of the run signed each batch.
        let above = (3u64 << cordelia_core::protocol::REV_COUNT_BITS) + 1;
        for rev in [above, 0] {
            let mut at_no_revision = versions.clone();
            at_no_revision[1].rev = rev;
            let refused = takes(
                &word,
                0,
                &signed_by(&run, 0, &at_no_revision),
                &at_no_revision,
            );
            assert!(
                matches!(&refused, Err(PersonError::NotCarried(why)) if why.contains(carry::REVISION_MAY_NOT_BE)),
                "{rev}: {refused:?}"
            );
        }
        assert_eq!(node.stored(), before);
        // With the phrase's word, and signed by the key of its run, each
        // comes in as a carry by command brings one in.
        let done = takes(&word, 0, &first_batch, &versions).unwrap();
        assert_eq!(done["carried"], 2, "{done}");
        // **A batch is taken once:** posted again under its word, it is
        // refused, and nothing is judged again.
        let again = takes(&word, 0, &first_batch, &versions);
        assert!(
            matches!(&again, Err(PersonError::NotCarried(why)) if why.contains(carry::BATCH_TAKEN)),
            "{again:?}"
        );
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
        let theirs = [theirs];
        let done = takes(&word, 1, &signed_by(&run, 1, &theirs), &theirs).unwrap();
        assert_eq!(
            (&done["carried"], &done["by_other_keys"]),
            (&json!(0), &json!(1))
        );
        assert_eq!(node.text(LAB, "theirs.md"), None);
    }
}
