//! The local API behind the commands a person types (decision 2026-10-04
//! §5 to §8): `cordelia phrase`, `add-device`, `accept`, `devices`,
//! `remove-device`, `renew`, `settle` and `init --new-key`.
//!
//! What each does is in the modules these handlers call: the look
//! ([`crate::look`]), adding ([`crate::adding`]), leaving
//! ([`crate::leaving`]), and applying what a command made
//! ([`crate::person`]). The handlers translate between JSON and those,
//! wake the node where something was written in a channel of the device's
//! own, and say a refusal in words that tell a person the way on.
//!
//! **No route here takes a recovery phrase, and none is given one** (§5).
//! A command that needs the phrase reads it at its own terminal, signs
//! and seals in its own process, and hands the node what it made: a
//! change entry, which any device of the person's is shown, and for a new
//! phrase the statement key, which every device that follows the phrase
//! is given. An entry and a statement travel as hex of their bytes.
//!
//! **No route here asks a yes** (§5): every yes is asked by the command,
//! at a terminal. A program that holds the node's token can make these
//! calls itself. What it cannot do is have a phrase sign what a person
//! was not shown.
//!
//! **Every route here is refused once the device was given a new key**
//! (`cordelia init --new-key`) and the node has not been started again:
//! the node still runs under the key it started with, and what it wrote
//! down under that key would be another device's.

use std::time::{Duration, Instant};

use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;
use serde_json::json;

use cordelia_core::protocol::{CHANGE_FETCH_MAX_SECS, PAIR_KEY_TYPED_SECS};
use cordelia_crypto::bech32::{decode_public_key, encode_public_key};
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_crypto::fingerprint;
use cordelia_storage::acts;
use cordelia_storage::meta;
use cordelia_storage::person::{self as held_rows, Kept, KeptAddition, State};

use crate::adding::{self, WouldAdd};
use crate::at_relays;
use crate::auth;
use crate::error::ApiError;
use crate::leaving::{self, Among};
use crate::look;
use crate::person::{self, PersonError};
use crate::state::AppState;

/// This node's clock, in seconds.
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn db(state: &AppState) -> std::sync::MutexGuard<'_, rusqlite::Connection> {
    state.db.lock().unwrap_or_else(|e| e.into_inner())
}

/// The file that holds a device's key, in the node's data directory.
pub const KEY_FILE: &str = "identity.key";

/// A request of a command, from whoever holds the node's token, to a
/// node that still runs under the device's key.
///
/// The key that the node started with is the one it signs with, and the
/// one its connections are made under. Where the file holds another, the
/// device was given a new key since (`cordelia init --new-key`), and the
/// node is to be started again: until then it makes nothing for a
/// command, under a key that is the device's no longer. A node whose
/// directory holds no key file has the key it was given, and is asked.
fn asked(req: &HttpRequest, state: &AppState) -> Result<(), ApiError> {
    auth::check_bearer(req, state)?;
    let on_disk = std::fs::read(state.home_dir.join(KEY_FILE))
        .ok()
        .and_then(|seed| <[u8; 32]>::try_from(seed).ok());
    match on_disk {
        Some(seed) if seed != *state.identity.seed() => Err(ApiError::Conflict(
            "this device was given a new key, and the node still runs under the old one: stop \
             the node and start it again (`cordelia start`)."
                .into(),
        )),
        _ => Ok(()),
    }
}

/// A refusal, as the API answers it: what a person did that is refused is
/// a bad request, what changed under a prompt is a conflict, and what the
/// device could not read or write is the node's own failure.
fn refused(e: PersonError) -> ApiError {
    match &e {
        PersonError::ChangedSincePrompt => ApiError::Conflict(says(&e)),
        PersonError::Storage(_) | PersonError::Held(_) | PersonError::Crypto(_) => {
            ApiError::Internal(e.to_string())
        }
        _ => ApiError::BadRequest(says(&e)),
    }
}

/// A refusal in words that say the way on.
fn says(e: &PersonError) -> String {
    match e {
        PersonError::FollowsNoPhrase => "this device follows no recovery phrase yet. Make one \
                                         here (`cordelia phrase`), or add this device from one \
                                         that has one."
            .into(),
        PersonError::Stopped(State::Fork) => "two changes were made apart, and this device has \
                                              seen both: settle it with the phrase first \
                                              (`cordelia settle`)."
            .into(),
        PersonError::Stopped(State::Removed) => "this device was removed. `cordelia init \
                                                 --new-key` gives it a new key; it is then \
                                                 added as a new device."
            .into(),
        PersonError::Stopped(State::NotListed) => "this device is not in the last change: add \
                                                   it again from a device that is."
            .into(),
        PersonError::Stopped(State::NotOpened) => "a change could not be opened on this \
                                                   device: add it again from a device that has \
                                                   the change."
            .into(),
        PersonError::KeyRemoved => "that key was removed, and a removed key is not added again. \
                                    `cordelia init --new-key` on that device gives it a new \
                                    one."
            .into(),
        PersonError::MayNotAdd => "this device may not add another yet: it was itself added, \
                                   since the last change, by a device added since. Add from \
                                   another device, or make a change first (`cordelia renew`)."
            .into(),
        PersonError::NoRoom => {
            "64 devices count already: a change makes room (`cordelia renew`).".into()
        }
        PersonError::Derive(_) => "that is this device's own key, or no device's key.".into(),
        PersonError::ChangedSincePrompt => "what this device holds changed while you were \
                                            answering: nothing was made."
            .into(),
        other => other.to_string(),
    }
}

fn key_of(field: &str, value: &str) -> Result<[u8; 32], ApiError> {
    decode_public_key(value).map_err(|e| ApiError::BadRequest(format!("invalid {field}: {e}")))
}

fn written(key: &[u8; 32]) -> Result<String, ApiError> {
    encode_public_key(key).map_err(|e| ApiError::Internal(e.to_string()))
}

/// An entry that a command made, read from the hex of its bytes and
/// checked as whatever a device is given is checked.
fn entry_of(field: &str, hex_bytes: &str) -> Result<CheckedEntry, ApiError> {
    let not = |why: String| ApiError::BadRequest(format!("{field} is no entry: {why}"));
    let bytes = hex::decode(hex_bytes).map_err(|e| not(e.to_string()))?;
    Entry::from_wire(&bytes)
        .map_err(|e| not(e.to_string()))?
        .check()
        .map_err(|e| not(e.to_string()))
}

/// What an entry is named by, read from hex.
fn id_of(field: &str, hex_bytes: &str) -> Result<[u8; 32], ApiError> {
    hex::decode(hex_bytes)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ApiError::BadRequest(format!("{field} is not 32 bytes in hex")))
}

/// Whether sync is on here: what `cordelia sync off` turns off.
pub fn sync_is_on(conn: &rusqlite::Connection) -> Result<bool, ApiError> {
    Ok(meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_some())
}

/// How many folders this device maps.
fn folders_mapped(conn: &rusqlite::Connection) -> Result<usize, ApiError> {
    Ok(meta::get(conn, meta::SYNC_CLAUDE_MAPPINGS)?
        .and_then(|list| serde_json::from_str::<Vec<serde_json::Value>>(&list).ok())
        .map_or(0, |list| list.len()))
}

/// The relays that this node is connected to now, each by the address it
/// is reached at and its node key.
fn relays_reached(state: &AppState) -> Vec<(String, [u8; 32])> {
    let peers = state.peers.read().unwrap_or_else(|e| e.into_inner());
    peers
        .iter()
        .filter(|peer| peer.role == "relay")
        .filter_map(|peer| Some((peer.address.clone(), decode_public_key(&peer.key).ok()?)))
        .collect()
}

/// For each relay that the node is connected to, how many of this
/// device's channels have something that waits to be sent there.
fn waiting(state: &AppState) -> Result<Vec<serde_json::Value>, ApiError> {
    let relays = relays_reached(state);
    let conn = db(state);
    relays
        .iter()
        .map(|(address, key)| {
            let waits = leaving::waits_at(&conn, &state.identity, key).map_err(refused)?;
            Ok(json!({ "relay": address, "waits": waits }))
        })
        .collect()
}

// ── POST /api/v1/devices/list ───────────────────────────────────────

/// Everything `cordelia devices` and `cordelia status` say of this device
/// and its person ([`look::Look`]), with whether sync is on, how many
/// folders the device maps, and what waits to be sent to each relay.
pub async fn list(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    let at = state.own_channels.read();
    let (seen, sync_on, folders) = {
        let conn = db(&state);
        let seen = look::look(&conn, &state.identity, &at, now()).map_err(refused)?;
        (seen, sync_is_on(&conn)?, folders_mapped(&conn)?)
    };
    let mut answer = serde_json::to_value(&seen).map_err(|e| ApiError::Internal(e.to_string()))?;
    answer["sync_on"] = sync_on.into();
    answer["folders"] = folders.into();
    answer["waiting"] = waiting(&state)?.into();
    Ok(HttpResponse::Ok().json(answer))
}

// ── POST /api/v1/devices/clear ──────────────────────────────────────

#[derive(Deserialize)]
pub struct ClearRequest {
    /// What the notice is named by, as a look gives it.
    pub notice: String,
}

/// A person clears a notice on this device ([`look::clear`]).
pub async fn clear(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ClearRequest>,
) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    let id = id_of("notice", &body.notice)?;
    let cleared = look::clear(&db(&state), &state.identity, &id, now()).map_err(refused)?;
    match cleared {
        Some(notice) => Ok(HttpResponse::Ok().json(json!({ "cleared": notice }))),
        None => Err(ApiError::NotFound(
            "this device shows no such notice".into(),
        )),
    }
}

// ── POST /api/v1/devices/add/look and /add ──────────────────────────

#[derive(Deserialize)]
pub struct AddRequest {
    /// The key of the device to add, as `cordelia id` prints it there.
    pub device: String,
    /// What the person calls it. A key that the statement already lists
    /// keeps the statement's label.
    #[serde(default)]
    pub label: Option<String>,
}

/// The label a device is added under where a person gave none.
const NO_LABEL: &str = "device";

/// What adding the key would do, with nothing written
/// ([`adding::would_add`]): for the command to show before its yes.
pub async fn add_look(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<AddRequest>,
) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    let device = key_of("device", &body.device)?;
    let label = body.label.as_deref().unwrap_or(NO_LABEL);
    let would = adding::would_add(&db(&state), &state.identity, &device, label).map_err(refused)?;
    let words = fingerprint::shown(&device);
    Ok(HttpResponse::Ok().json(match would {
        WouldAdd::HandsAgain { label } => json!({
            "would": "hand_again", "label": label, "words": words,
        }),
        WouldAdd::Adds {
            counts_already,
            left_out_as,
        } => json!({
            "would": "add", "label": label, "words": words,
            "counts_already": counts_already, "left_out_as": left_out_as,
        }),
    }))
}

/// Add the device ([`adding::add_device`]). Where a record was made,
/// every channel of the device's own is read again from the start
/// ([`at_relays::read_again`]): what the new device wrote was refused
/// where it arrived before the record. And the node is woken, to send the
/// hand-over and the record.
pub async fn add(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<AddRequest>,
) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    let device = key_of("device", &body.device)?;
    let label = body.label.as_deref().unwrap_or(NO_LABEL);
    let record = {
        let conn = db(&state);
        let added =
            adding::add_device(&conn, &state.identity, &device, label, now()).map_err(refused)?;
        if added.record.is_some() {
            at_relays::read_again(&conn).map_err(refused)?;
        }
        added.record.is_some()
    };
    state.own_channels.written();
    Ok(HttpResponse::Ok().json(json!({
        "device": body.device,
        "this_device": written(&state.identity.public_key())?,
        "record": record,
    })))
}

// ── POST /api/v1/devices/accept ─────────────────────────────────────

#[derive(Deserialize)]
pub struct AcceptRequest {
    /// The key of the device that adds this one, as a person typed it.
    pub key: String,
}

/// A person typed a key at `cordelia accept`: it is kept with its time,
/// and the node asks its relays for what that device hands over until it
/// is taken or the hour is gone (decision 2026-10-04 §5.1, §6). What
/// became of it is in the look.
///
/// Refused, with nothing kept, where no hand-over could be taken as the
/// device stands: it was removed, it is in a fork, or it is alone under a
/// phrase with sync on.
pub async fn accept(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<AcceptRequest>,
) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    let key = key_of("key", &body.key)?;
    let typed_at = now();
    {
        let conn = db(&state);
        derive::pair_secret(&state.identity, &key).map_err(|e| refused(e.into()))?;
        match leaving::among(&conn, &state.identity).map_err(refused)? {
            Among::Stopped(state @ (State::Removed | State::Fork)) => {
                return Err(refused(PersonError::Stopped(state)));
            }
            Among::Alone if sync_is_on(&conn)? => {
                return Err(ApiError::BadRequest(
                    "sync is on here, and this device is alone under a recovery phrase: \
                     `cordelia sync off` first, so that sending its folders to another set of \
                     devices takes two acts."
                        .into(),
                ));
            }
            _ => {}
        }
        acts::type_key(&conn, &key, typed_at)?;
        // What became of a key typed long ago is kept no longer.
        acts::forget_typed_keys(&conn, typed_at - 24 * PAIR_KEY_TYPED_SECS)?;
    }
    // The node asks its relays for the hand-over in its whole pass: now,
    // and then at each one until it is taken or the hour is gone.
    state.own_channels.ask_whole();
    Ok(HttpResponse::Ok().json(json!({
        "key": body.key,
        "words": fingerprint::shown(&key),
        "typed_at": typed_at,
        "until": typed_at + PAIR_KEY_TYPED_SECS,
    })))
}

// ── POST /api/v1/phrase/make ────────────────────────────────────────

#[derive(Deserialize)]
pub struct PhraseRequest {
    /// The change entry of the new phrase's first statement, which the
    /// command made: hex of its bytes.
    pub entry: String,
    /// The new phrase's statement key, in hex.
    pub statement_key: String,
    /// Where the device stood when the command asked its yes:
    /// `no_phrase`, `alone` or `several`.
    pub from: String,
}

/// The device starts again alone under a new phrase
/// ([`leaving::start_again`]): it is handed the first statement's change
/// entry and the statement key, and never the words.
pub async fn phrase_make(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<PhraseRequest>,
) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    let entry = entry_of("entry", &body.entry)?;
    let statement_key = id_of("statement_key", &body.statement_key)?;
    let shown = match body.from.as_str() {
        "no_phrase" => Among::NoPhrase,
        "alone" => Among::Alone,
        "several" => Among::Several(0),
        other => {
            return Err(ApiError::BadRequest(format!(
                "from is '{other}', and is one of no_phrase, alone and several"
            )));
        }
    };
    let applied = leaving::start_again(
        &db(&state),
        &state.identity,
        shown,
        &entry,
        &statement_key,
        now(),
    )
    .map_err(refused)?;
    state.own_channels.written();
    state.own_channels.ask_whole();
    Ok(HttpResponse::Ok().json(json!({ "change": applied.number })))
}

// ── POST /api/v1/devices/leave, /leave/sent and /forget ─────────────

/// What a device owes the devices it leaves, before it is given a new
/// key ([`leaving::begin`]): its word that it has left, and a delete over
/// each hand-over that a relay was sent. They wait in its store, and the
/// node is woken to send them.
pub async fn leave(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    let (stands, begun) = {
        let conn = db(&state);
        let stands = leaving::among(&conn, &state.identity).map_err(refused)?;
        let begun = leaving::begin(&conn, &state.identity, now()).map_err(refused)?;
        (stands, begun)
    };
    state.own_channels.written();
    let (among, others) = match stands {
        Among::NoPhrase => ("no_phrase", 0),
        Among::Alone => ("alone", 0),
        Among::Several(others) => ("several", others),
        Among::Stopped(_) => ("stopped", 0),
    };
    Ok(HttpResponse::Ok().json(json!({
        "among": among,
        "others": others,
        "said": begun.word.is_some(),
        "written_over": begun.written_over,
        "relays": relays_reached(&state).len(),
    })))
}

/// For each relay the node is connected to, how many of the device's
/// channels still have something that waits to be sent there.
pub async fn leave_sent(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    Ok(HttpResponse::Ok().json(json!({ "waiting": waiting(&state)? })))
}

/// The device forgets what it holds of its person, and keeps no word of
/// its own to send ([`leaving::forget`]): for a device that is given a new
/// key. It then follows no phrase.
pub async fn forget(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    let forgot = leaving::forget(&db(&state), &state.identity, false, now()).map_err(refused)?;
    Ok(HttpResponse::Ok().json(json!({ "forgot": forgot })))
}

// ── POST /api/v1/change/prepare and /make ───────────────────────────

#[derive(Deserialize)]
pub struct PrepareRequest {
    /// Whether the change settles two that were made apart.
    #[serde(default)]
    pub settle: bool,
}

/// Have the device show its change entry to each relay and fetch its
/// channels, in a whole pass that began after this was asked: two
/// minutes at most (decision 2026-10-04 §7.1, step 1). Says whether a
/// pass ended in that time.
///
/// It is asked for once: the node keeps one asking until it takes it up,
/// and a pass that began after the asking has a number above the count
/// at that moment. A node with no network has nobody to ask, and nothing
/// is waited for.
async fn fetch(state: &AppState) -> bool {
    if state.push_tx.is_none() {
        return true;
    }
    let (begun, _) = state.own_channels.whole_passes();
    let deadline = Instant::now() + Duration::from_secs(CHANGE_FETCH_MAX_SECS);
    state.own_channels.ask_whole();
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if state.own_channels.whole_passes().1 > begun {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
    }
}

/// What a command that makes a statement is handed before it asks
/// anything (decision 2026-10-04 §5, §7.1): the statement that the device
/// has applied, as its signed bytes; the change entry it keeps; the
/// record of each device added since that counts, as its signed bytes
/// ([`asked_about`]); and, in a fork, the statement made apart and its
/// entry. The command reads what it shows from those bytes.
///
/// Before that the device shows its change entry to each relay and
/// fetches, for two minutes at most, and what it could not fetch is said
/// ([`fetch`]).
///
/// Refused on a device that makes no statement (§4.3): one that follows
/// no phrase, was removed, is in no list or could not open a change. A
/// device in a fork is handed this only to settle, and a device that is
/// in none has nothing to settle.
pub async fn change_prepare(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<PrepareRequest>,
) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    let stands = |conn: &rusqlite::Connection| -> Result<State, ApiError> {
        let held = person::held(conn)
            .map_err(refused)?
            .ok_or_else(|| refused(PersonError::FollowsNoPhrase))?;
        match (held.state, body.settle) {
            (State::Applied, false) | (State::Fork, true) => Ok(held.state),
            (State::Applied, true) => Err(ApiError::BadRequest(
                "this device has seen no two changes made apart: there is nothing to settle."
                    .into(),
            )),
            (state, _) => Err(refused(PersonError::Stopped(state))),
        }
    };
    stands(&db(&state))?;

    // A device in a fork has no leave anywhere: it goes on showing each
    // relay the entry it had applied, and fetches nothing.
    let fetched = fetch(&state).await;
    let at = state.own_channels.read();
    let mut could_not_fetch: Vec<String> = Vec::new();
    if !fetched {
        could_not_fetch.push(format!(
            "the fetch did not end within {CHANGE_FETCH_MAX_SECS} seconds"
        ));
    }
    for relay in &at.relays {
        if !relay.heard_since_woke {
            could_not_fetch.push(format!("{} did not answer", relay.relay));
        }
    }
    if at.relays.is_empty() && state.push_tx.is_some() {
        could_not_fetch.push("no relay was reached".into());
    }

    let conn = db(&state);
    stands(&conn)?;
    let hex_of = |entry: CheckedEntry| hex::encode(entry.to_wire());
    let held = person::held(&conn)
        .map_err(refused)?
        .ok_or_else(|| refused(PersonError::FollowsNoPhrase))?;
    let statement = held.statement.to_bytes().map_err(|e| refused(e.into()))?;
    let latest = person_entry(&conn, Kept::Latest)?
        .ok_or_else(|| ApiError::Internal("no change entry is kept".into()))?;
    let apart = person_entry(&conn, Kept::Apart)?;
    let apart_statement = match &apart {
        None => None,
        Some(entry) => {
            let following = &held.following;
            let read = cordelia_crypto::change_entry::open_statement(
                entry,
                &following.phrase_key,
                &following.phrase_channel,
                &following.statement_key,
            )
            .map_err(|e| refused(e.into()))?;
            Some(hex::encode(read.to_bytes().map_err(|e| refused(e.into()))?))
        }
    };
    let additions: Vec<String> = asked_about(&held_rows::additions(&conn)?)
        .into_iter()
        .map(|kept| hex::encode(&kept.record))
        .collect();
    let seen = look::look(&conn, &state.identity, &at, now()).map_err(refused)?;
    Ok(HttpResponse::Ok().json(json!({
        "this_device": written(&state.identity.public_key())?,
        "statement": hex::encode(statement),
        "over": hex::encode(latest.id()),
        "entry": hex_of(latest),
        "apart": apart.as_ref().map(|entry| hex::encode(entry.id())),
        "apart_entry": apart.map(hex_of),
        "apart_statement": apart_statement,
        "additions": additions,
        "could_not_fetch": could_not_fetch,
        "look": seen,
    })))
}

/// The records of additions that a command asks a person about at a
/// change (decision 2026-10-04 §6): for each device added since the
/// statement that counts, the record it counts by, in the order the
/// device saw them. A key counts by one record. A record that does not
/// count adds no device: its key is in no list, and nothing is asked of
/// it.
fn asked_about(kept: &[KeptAddition]) -> Vec<&KeptAddition> {
    kept.iter().filter(|record| record.counted).collect()
}

/// A change entry that the device keeps, checked as it is read.
fn person_entry(
    conn: &rusqlite::Connection,
    which: Kept,
) -> Result<Option<CheckedEntry>, ApiError> {
    held_rows::change_entry(conn, which)?
        .map(|entry| {
            entry
                .check()
                .map_err(|e| ApiError::Internal(format!("a change entry that is kept: {e}")))
        })
        .transpose()
}

#[derive(Deserialize)]
pub struct MakeRequest {
    /// The change entry that the command signed and sealed: hex of its
    /// bytes.
    pub entry: String,
    /// What the change entry was named by that the device kept as the
    /// latest when the command was handed what it showed.
    pub over: String,
    /// What the entry of the statement made apart was named by, where
    /// the change settles two.
    #[serde(default)]
    pub apart: Option<String>,
}

/// The node's half of a change that a command made with the phrase
/// ([`person::apply_made`]): one transaction, in which what the prompt
/// showed is checked again. A statement that arrived meanwhile is
/// answered with a conflict: nothing was made, and the command asks
/// again. The node is then woken, to show the change to every relay at
/// once and to send what it carried.
pub async fn change_make(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<MakeRequest>,
) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    let entry = entry_of("entry", &body.entry)?;
    let over = id_of("over", &body.over)?;
    let apart = body
        .apart
        .as_deref()
        .map(|apart| id_of("apart", apart))
        .transpose()?;
    let applied = person::apply_made(
        &db(&state),
        &state.identity,
        &entry,
        &over,
        apart.as_ref(),
        now(),
    )
    .map_err(refused)?;
    state.own_channels.written();
    state.own_channels.ask_whole();
    Ok(HttpResponse::Ok().json(json!({
        "change": applied.number,
        "carried": applied.carried,
        "no_version": applied.no_version,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    use cordelia_crypto::addition::Addition;
    use cordelia_crypto::statement::Device;

    use crate::adding::add_device;
    use crate::several::{Machine, Several};
    use crate::take::take;

    /// A command asks about each device added since the statement that
    /// counts, once, and about no key whose record does not count: that
    /// key is in no list of the change, whatever a person would say.
    #[test]
    fn test_a_change_asks_about_each_device_added_since_that_counts_and_no_other() {
        let mut s = Several::of_one_person(3);
        // Device 1 was added by device 0, which made the phrase, and adds
        // device 9: device 9 counts, and may add nothing. It writes a
        // record all the same, of device 10, which does not count.
        let now = s.tick();
        let nine = Machine::new(9);
        let by_one = add_device(&s[1].conn, &s[1].identity, &nine.key(), "device 9", now).unwrap();
        let record = by_one.record.clone().unwrap();
        take(&s[0].conn, &s[0].identity, &record, now).unwrap();
        let ten = Machine::new(10);
        let statement = s[0].held().statement.statement;
        let record = Addition::under(
            &statement,
            Device::new(ten.key(), "device 10").unwrap(),
            nine.key(),
            now as u64,
        )
        .unwrap()
        .sign(&nine.identity)
        .unwrap();
        crate::person::see_addition(&s[0].conn, &record, now).unwrap();
        let kept = held_rows::additions(&s[0].conn).unwrap();
        let not_counted: Vec<[u8; 32]> = kept
            .iter()
            .filter(|record| !record.counted)
            .map(|record| record.key)
            .collect();
        assert_eq!(not_counted, [ten.key()]);

        let asked: Vec<[u8; 32]> = asked_about(&kept).iter().map(|record| record.key).collect();
        assert_eq!(asked.len(), kept.len() - 1);
        for counts in [s.key(1), s.key(2), nine.key()] {
            assert!(asked.contains(&counts));
        }
        assert!(!asked.contains(&ten.key()));
        // Each key once: a key counts by one record.
        let mut once = asked.clone();
        once.sort();
        once.dedup();
        assert_eq!(once.len(), asked.len());
        assert!(asked_about(&[]).is_empty());
    }
}
