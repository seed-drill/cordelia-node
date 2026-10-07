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

use cordelia_core::protocol::{
    CHANGE_FETCH_MAX_SECS, CHANGE_FETCH_PASSES, PAIR_KEY_TYPED_SECS, RECEIVED_LAST_DAY_SECS,
    RECEIVED_LAST_WEEK_SECS,
};
use cordelia_crypto::bech32::{decode_public_key, encode_public_key};
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_crypto::fingerprint;
use cordelia_crypto::statement::Statement;
use cordelia_storage::meta;
use cordelia_storage::person::{self as held_rows, Kept, KeptAddition, State};

use crate::adding::{self, Row, WouldAdd};
use crate::at_relays;
use crate::auth;
use crate::error::ApiError;
use crate::leaving::{self, Among};
use crate::look;
use crate::names;
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

/// The relays that the device is set up with, by the names of its
/// configuration, to which the node is not connected now. What waits to
/// be sent to one of them is in no row of [`waiting`]: a command that
/// waits until everything is sent counts each as missing (decision
/// 2026-10-04 §7.1, step 4).
///
/// `at` is where the device stands at its relays, which names every
/// relay it is set up with. A relay is connected where the node's list
/// of its relays says so, by that name.
fn not_reached(state: &AppState, at: &crate::state::AtRelays) -> Vec<String> {
    let known = state.relays.read().unwrap_or_else(|e| e.into_inner());
    let connected = |name: &str| {
        known
            .iter()
            .any(|relay| relay.host == name && relay.state == "connected")
    };
    at.relays
        .iter()
        .map(|relay| relay.relay.clone())
        .filter(|name| !connected(name))
        .collect()
}

/// How many of this device's own channels have something that waits to
/// be sent to a relay the node is connected to: the most that wait at
/// any one of them. None on a node that follows no phrase, and none
/// where no relay is connected: what waits then is not known by relay.
pub fn channels_waiting(state: &AppState) -> u64 {
    let relays = relays_reached(state);
    let conn = db(state);
    relays
        .iter()
        .filter_map(|(_, key)| leaving::waits_at(&conn, &state.identity, key).ok())
        .max()
        .unwrap_or(0) as u64
}

/// What this device has still to send, by name (decision 2026-10-04
/// §7.1, §8): the names it holds whose channel has nothing waiting at any
/// relay the node is connected to, and those of which something waits at
/// one of them. A relay that is not connected is not asked here: whether
/// it holds the change is said of it apart.
fn names_sent(state: &AppState) -> Result<serde_json::Value, ApiError> {
    let relays: Vec<[u8; 32]> = relays_reached(state)
        .into_iter()
        .map(|(_, key)| key)
        .collect();
    let conn = db(state);
    let names = leaving::names_to_go(&conn, &state.identity, &relays).map_err(refused)?;
    // Since when the first of what is still to go has waited.
    let since = leaving::names_waiting_since(&conn, &state.identity, &relays).map_err(refused)?;
    let (to_go, sent): (Vec<_>, Vec<_>) = names.into_iter().partition(|(_, to_go)| *to_go);
    let named = |names: Vec<(String, bool)>| -> Vec<String> {
        names.into_iter().map(|(name, _)| name).collect()
    };
    Ok(json!({ "sent": named(sent), "to_go": named(to_go), "to_go_since": since }))
}

/// The files whose record a change could not carry, as an answer lists
/// them: each as the name it syncs under and the file.
fn not_carried(applied: &person::Applied) -> Vec<serde_json::Value> {
    applied
        .not_carried
        .iter()
        .map(|(name, file)| json!({ "name": name, "file": file }))
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
    // For how long each relay has been connected, by the node's own
    // clock: a status counts a relay that does not hold the latest
    // change only once it has been connected for some minutes (decision
    // 2026-10-04 §10.1).
    let at_now = std::time::Instant::now();
    for relay in answer["relays"].as_array_mut().into_iter().flatten() {
        let connected = relay["relay"]
            .as_str()
            .and_then(|name| state.own_channels.connected_for(name, at_now));
        relay["connected_secs"] = connected.map(|connected| connected.as_secs()).into();
    }
    answer["sync_on"] = sync_on.into();
    answer["folders"] = folders.into();
    answer["waiting"] = waiting(&state)?.into();
    answer["not_reached"] = not_reached(&state, &at).into();
    // What it has still to send, by name: a status says it in a line.
    let names = names_sent(&state)?;
    let to_go: Vec<&str> = names["to_go"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|name| name.as_str())
        .collect();
    if !to_go.is_empty() {
        let says = format!(
            "this device has still to send {} name{}: {}",
            to_go.len(),
            if to_go.len() == 1 { "" } else { "s" },
            to_go.join(", ")
        );
        if let Some(lines) = answer["says"].as_array_mut() {
            lines.push(says.into());
        }
    }
    answer["names"] = names;
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
    /// What the yes was for, where the device is to be added: `add`, or
    /// `hand_again` for a key that the statement lists already, which is
    /// handed the last change again with no record. It is what the look
    /// said adding would do, when the command asked its yes (§16).
    #[serde(default)]
    pub would: Option<String>,
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
    // The key that the node runs under: the command refuses where it is
    // another than the one in the device's key file (§16).
    let this_device = written(&state.identity.public_key())?;
    Ok(HttpResponse::Ok().json(match would {
        WouldAdd::HandsAgain { label } => json!({
            "would": "hand_again", "label": label, "words": words,
            "this_device": this_device,
        }),
        WouldAdd::Adds {
            counts_already,
            left_out_as,
        } => json!({
            "would": "add", "label": label, "words": words,
            "counts_already": counts_already, "left_out_as": left_out_as,
            "this_device": this_device,
        }),
    }))
}

/// Add the device ([`adding::add_device`]). Where a record was made,
/// every channel of the device's own is read again from the start
/// ([`at_relays::read_again`]): what the new device wrote was refused
/// where it arrived before the record. And the node is woken, to send the
/// hand-over and the record.
///
/// **The request says what the yes was for** (§16): to add the device,
/// or to hand a device that is listed already the last change again.
/// Where adding the key would now do the other, nothing is done, and the
/// answer is a conflict: the command asks again.
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
        // What adding would do now, against what the yes was for.
        let would = adding::would_add(&conn, &state.identity, &device, label).map_err(refused)?;
        let would = match would {
            WouldAdd::HandsAgain { .. } => "hand_again",
            WouldAdd::Adds { .. } => "add",
        };
        match body.would.as_deref() {
            Some(yes_was_for) if yes_was_for == would => {}
            Some("add" | "hand_again") => {
                return Err(ApiError::Conflict(
                    "what adding that key would do changed while you were answering: nothing \
                     was done."
                        .into(),
                ));
            }
            _ => {
                return Err(ApiError::BadRequest(
                    "would says what the yes was for, and is one of add and hand_again".into(),
                ));
            }
        }
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
    /// The row of §5.1 that the yes named: `no_phrase`, `alone`,
    /// `several` or `not_listed`.
    #[serde(default)]
    pub row: Option<String>,
}

/// A person typed a key at `cordelia accept`: it is kept with its time
/// and the row that its yes named, and the node asks its relays for what
/// that device hands over until it is taken or the hour is gone (decision
/// 2026-10-04 §5.1, §6, §16). What became of it is in the look.
///
/// Refused, with nothing kept, where no hand-over could be taken as the
/// device stands: it was removed, it is in a fork, or it is alone under a
/// phrase with sync on. Refused too where the device stands in another
/// row than the yes named, as a conflict; and a ninth key
/// ([`adding::type_key`]).
pub async fn accept(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<AcceptRequest>,
) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    let key = key_of("key", &body.key)?;
    let row = body.row.as_deref().and_then(Row::named).ok_or_else(|| {
        ApiError::BadRequest(
            "row says what the yes was for, and is one of no_phrase, alone, several and \
             not_listed"
                .into(),
        )
    })?;
    let typed_at = now();
    {
        let conn = db(&state);
        let sync_on = sync_is_on(&conn)?;
        adding::type_key(&conn, &state.identity, &key, row, sync_on, typed_at).map_err(refused)?;
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
    // It counts as a change of settings, and waits for a sync cycle that
    // is running to stop: the device's folders forget what they had
    // agreed where a phrase is replaced, and nothing of a cycle that
    // began before is published or recorded after (§4.2, §5.2). Where a
    // phrase was replaced the device has left one: the node keeps no
    // note of which relays had handed its channels.
    let applied = state
        .as_a_leaving(
            |conn| {
                leaving::start_again(conn, &state.identity, shown, &entry, &statement_key, now())
            },
            |applied| applied.is_ok(),
        )
        .map_err(refused)?;
    state.own_channels.written();
    state.own_channels.ask_whole();
    // The device's folders are published by the next cycle: now.
    state.sync_control.ask_cycle();
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

/// The device takes back its word that it has left
/// ([`leaving::take_back`]): for `cordelia init --new-key` that a person
/// stops at its second yes, on a device that then keeps its key and
/// leaves nobody (decision 2026-10-04 §16). The node is woken, to send
/// the delete wherever the word went.
pub async fn leave_back(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    let back = leaving::take_back(&db(&state), &state.identity, now()).map_err(refused)?;
    state.own_channels.written();
    Ok(HttpResponse::Ok().json(json!({ "taken_back": back.is_some() })))
}

/// The device forgets what it holds of its person, and keeps no word of
/// its own to send ([`leaving::forget`]): for a device that is given a new
/// key. It then follows no phrase.
pub async fn forget(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    // As a change of settings: its folders forget what they had agreed,
    // and no cycle that began before records anything after. The node
    // keeps no note of which relays had handed the channels it held.
    let forgot = state
        .as_a_leaving(
            |conn| leaving::forget(conn, &state.identity, false, now()),
            |forgot| matches!(forgot, Ok(true)),
        )
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(json!({ "forgot": forgot })))
}

// ── POST /api/v1/change/prepare and /make ───────────────────────────

#[derive(Deserialize)]
pub struct PrepareRequest {
    /// Whether the change settles two that were made apart.
    #[serde(default)]
    pub settle: bool,
}

/// What became of something that a command had the node do, and waited
/// for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Waited {
    /// One that began after the asking ended, and went to its end.
    Done,
    /// One that began after the asking ended early: it did not do all
    /// that it is asked for.
    EndedEarly,
    /// None ended in the time.
    NotEnded,
}

/// Have the device show its change entry to each relay and fetch its
/// channels, in a whole pass that began after this was asked: two
/// minutes at most (decision 2026-10-04 §7.1, step 1). Says whether a
/// pass ended in that time, and whether it had read every channel to its
/// end at every relay it reached: a pass that a relay gave no leave for,
/// or that left a channel longer than one pass takes part read, has not
/// fetched what the relays hold.
///
/// The node keeps one asking until it takes it up, and a pass that began
/// after the asking has a number above the count at that moment. **A
/// pass that ended early is asked for again,** up to
/// CHANGE_FETCH_PASSES passes in all, where `again` says so: the next
/// reads on. (A device in a fork has no leave anywhere, and is not asked
/// again.) A node with no network has nobody to ask, and nothing is
/// waited for.
async fn fetch(state: &AppState, again: bool, deadline: Instant) -> Waited {
    if state.push_tx.is_none() {
        return Waited::Done;
    }
    let (mut begun, _) = state.own_channels.whole_passes();
    let mut ended_early = 0;
    state.own_channels.ask_whole();
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if state.own_channels.whole_passes().1 > begun {
            if state.own_channels.last_short_pass() <= begun {
                return Waited::Done;
            }
            ended_early += 1;
            if !again || ended_early >= CHANGE_FETCH_PASSES {
                return Waited::EndedEarly;
            }
            begun = state.own_channels.whole_passes().0;
            state.own_channels.ask_whole();
        }
        if Instant::now() >= deadline {
            return match ended_early {
                0 => Waited::NotEnded,
                _ => Waited::EndedEarly,
            };
        }
    }
}

/// Have the node run a sync cycle that began after this was asked, and
/// wait for it until `deadline`: the folders here are then as current as
/// they can be made (decision 2026-10-04 §7.1, step 1). Says whether one
/// ended in that time, and whether it went to its end: a cycle that
/// stopped part-way has not brought the folders up to what was fetched.
///
/// A node with no network runs no cycle of its own, and nothing is
/// waited for; nor where sync is off, since no folder syncs.
async fn cycle(state: &AppState, deadline: Instant) -> Waited {
    let off = !sync_is_on(&db(state)).unwrap_or(false);
    if state.push_tx.is_none() || off {
        return Waited::Done;
    }
    let (begun, _) = state.sync_control.cycles();
    state.sync_control.ask_cycle();
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if state.sync_control.cycles().1 > begun {
            return match state.sync_control.last_cycle_cut_short() > begun {
                true => Waited::EndedEarly,
                false => Waited::Done,
            };
        }
        if Instant::now() >= deadline {
            return Waited::NotEnded;
        }
    }
}

/// What a command is told of a fetch, and of the cycle after it, that
/// did not do all that was asked (decision 2026-10-04 §7.1, step 1): one
/// line for each, or none where both went to their end. `fork` is
/// whether the device is in a fork: it then has no leave anywhere, and
/// fetches nothing, which is no failure of the fetch.
fn not_fetched(fetched: Waited, cycled: Waited, fork: bool) -> Vec<String> {
    let mut lines = Vec::new();
    match fetched {
        Waited::Done => {}
        Waited::EndedEarly if fork => {}
        Waited::EndedEarly => lines.push(
            "the fetch ended before every channel was read to its end at every relay: a relay \
             gave no leave or stopped answering, or holds more of a channel than one pass takes"
                .to_string(),
        ),
        Waited::NotEnded => lines.push(format!(
            "the fetch did not end within {CHANGE_FETCH_MAX_SECS} seconds"
        )),
    }
    match cycled {
        Waited::Done => {}
        Waited::EndedEarly => lines.push(
            "the sync cycle stopped before its end: the folders here may not hold what was \
             fetched"
                .to_string(),
        ),
        Waited::NotEnded => lines.push(format!(
            "no sync cycle ended within {CHANGE_FETCH_MAX_SECS} seconds: the folders here may \
             not hold what was fetched"
        )),
    }
    lines
}

/// How much each device has written that this device received in the
/// last day and in the last week (decision 2026-10-04 §7.1, step 2), from
/// local history: for each device's key, as a key is written, how many
/// versions of a file arrived here that it had signed. `None` with
/// history off: nothing was kept to count.
///
/// A version that a device carried is counted for the key that signed
/// the entry it was carried from: that is the key a record names.
fn received(state: &AppState, now: i64) -> Option<serde_json::Value> {
    use cordelia_storage::history::{Change, Replacement};
    let store = state.history.store()?;
    let listing = store.list().ok()?;
    let mut by_device: std::collections::BTreeMap<String, (u64, u64)> = Default::default();
    for record in listing.records {
        let arrived = matches!(
            record.about.change,
            Change::Pulled | Change::Removed | Change::Arrived
        );
        let Replacement::Entry(entry) = record.about.replaced_by else {
            continue;
        };
        let Ok(at) = chrono::DateTime::parse_from_rfc3339(&record.about.at) else {
            continue;
        };
        let ago = now.saturating_sub(at.timestamp());
        if !arrived || ago >= RECEIVED_LAST_WEEK_SECS {
            continue;
        }
        let of = by_device.entry(entry.device).or_default();
        of.1 += 1;
        if ago < RECEIVED_LAST_DAY_SECS {
            of.0 += 1;
        }
    }
    Some(
        by_device
            .into_iter()
            .map(|(device, (day, week))| (device, json!({ "day": day, "week": week })))
            .collect::<serde_json::Map<_, _>>()
            .into(),
    )
}

/// What a command that makes a statement is handed before it asks
/// anything (decision 2026-10-04 §5, §7.1): the statement that the device
/// has applied, as its signed bytes; the change entry it keeps; the
/// record of each device added since that counts, as its signed bytes
/// ([`asked_about`]); and, in a fork, the statement made apart and its
/// entry. The command reads what it shows from those bytes.
///
/// Before that the device shows its change entry to each relay and
/// fetches, for two minutes at most, and then runs a sync cycle, within
/// the same two minutes: what it could not fetch is said ([`fetch`],
/// [`cycle`]).
///
/// It is handed the key of each device that has said that it left, of
/// which a person is asked whether it stays ([`look::Look::said_left`]).
///
/// With those it is handed what the command shows of names: each name
/// that the personal channel lists, with the keys that list it, so that
/// the names which only a device being removed syncs can be shown; and
/// how much each device wrote that this one received in the last day and
/// the last week ([`received`]).
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
    let fork = stands(&db(&state))? == State::Fork;

    // A device in a fork has no leave anywhere: it goes on showing each
    // relay the entry it had applied, and fetches nothing.
    let deadline = Instant::now() + Duration::from_secs(CHANGE_FETCH_MAX_SECS);
    let fetched = fetch(&state, !fork, deadline).await;
    // Then a sync cycle, so that what was fetched is in the folders.
    let cycled = cycle(&state, deadline).await;
    let at = state.own_channels.read();
    let mut could_not_fetch: Vec<String> = not_fetched(fetched, cycled, fork);
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
    let kept = held_rows::additions(&conn)?;
    let additions: Vec<String> = asked_about(&kept)
        .into_iter()
        .map(|kept| hex::encode(&kept.record))
        .collect();
    let standing: Vec<String> = standing(&held.statement.statement, &kept)
        .into_iter()
        .map(|kept| hex::encode(&kept.record))
        .collect();
    let seen = look::look(&conn, &state.identity, &at, now()).map_err(refused)?;
    let (names, names_not_shown) = names_handed(&conn)?;
    Ok(HttpResponse::Ok().json(json!({
        "this_device": written(&state.identity.public_key())?,
        "statement": hex::encode(statement),
        "over": hex::encode(latest.id()),
        "entry": hex_of(latest),
        "apart": apart.as_ref().map(|entry| hex::encode(entry.id())),
        "apart_entry": apart.map(hex_of),
        "apart_statement": apart_statement,
        "additions": additions,
        "standing": standing,
        // Each device that has said that it left: a person is asked
        // about each (§7.1).
        "left": seen.said_left(),
        "could_not_fetch": could_not_fetch,
        "names": names,
        "names_not_shown": names_not_shown,
        "received": received(&state, now()),
        "look": seen,
    })))
}

/// What a command that makes a change is handed of the names that the
/// personal channel lists, as this device holds that channel now: each
/// name with the keys that list it; and, of what a device lists there
/// that is no name as this version would map one, for each such device
/// how many, and nothing of what they hold (decision 2026-10-04 §16).
fn names_handed(
    conn: &rusqlite::Connection,
) -> Result<(Vec<serde_json::Value>, Vec<serde_json::Value>), ApiError> {
    let mut names: Vec<serde_json::Value> = Vec::new();
    for listed in names::listed(conn).map_err(refused)? {
        let by: Vec<String> = listed.by.iter().map(written).collect::<Result<_, _>>()?;
        names.push(json!({ "name": listed.name, "by": by }));
    }
    let mut not_shown: Vec<serde_json::Value> = Vec::new();
    for (key, words) in names::not_names(conn).map_err(refused)? {
        not_shown.push(json!({ "by": written(&key)?, "words": words }));
    }
    Ok((names, not_shown))
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

/// The records that give a device added since its standing to add, where
/// the record it counts by does not (decision 2026-10-04 §6, §16): a key
/// that counts may add where any record kept for it was signed by a
/// device of the statement. The command checks, of each record it asks
/// about, that its adder is a device of the statement or was added by
/// one, and reads that from these and from the records it asks about. It
/// asks about none of these: each is of a key that counts by another
/// record.
fn standing<'a>(statement: &Statement, kept: &'a [KeptAddition]) -> Vec<&'a KeptAddition> {
    let adds = |key: &[u8; 32]| asked_about(kept).iter().any(|record| record.adder == *key);
    kept.iter()
        .filter(|record| !record.counted && statement.lists(&record.adder) && adds(&record.key))
        .collect()
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
    // The node stops its sync cycle, and makes the change in one
    // transaction (§7.2): it counts as a change of settings, and waits
    // for a cycle that is running to stop.
    let applied = state
        .as_a_change(|conn| {
            person::apply_made(conn, &state.identity, &entry, &over, apart.as_ref(), now())
        })
        .map_err(refused)?;
    for (name, file) in &applied.not_carried {
        tracing::warn!(
            name,
            file,
            "what this device held of a file could not be read, and was not carried: it meets its channel as a new file does"
        );
    }
    state.own_channels.written();
    state.own_channels.ask_whole();
    Ok(HttpResponse::Ok().json(json!({
        "change": applied.number,
        "carried": applied.carried,
        "no_version": applied.no_version,
        "not_carried": not_carried(&applied),
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

    /// A command is handed, beside the records it asks about, each record
    /// that gives the adder of one of them its standing to add where the
    /// record that adder counts by does not (decision 2026-10-04 §6, §16):
    /// a key that counts may add where any record kept for it was signed
    /// by a device of the statement.
    #[test]
    fn test_a_change_hands_the_record_that_gives_an_adder_its_standing() {
        let mut s = Several::of_one_person(3);
        let statement = s[0].held().statement.statement;
        // With every device added by the one that the statement lists,
        // every adder has its standing by the record it counts by.
        let kept = held_rows::additions(&s[0].conn).unwrap();
        assert_eq!(asked_about(&kept).len(), 2);
        assert!(standing(&statement, &kept).is_empty());

        // Device 1, which device 0 added, adds device 9: it counts, and
        // may not add. Then device 0 adds it too: it counts already, by
        // the first record, and by this one it may add. It adds device 10.
        let now = s.tick();
        let (nine, ten) = (Machine::new(9), Machine::new(10));
        let by_one = add_device(&s[1].conn, &s[1].identity, &nine.key(), "device 9", now).unwrap();
        take(&s[0].conn, &s[0].identity, &by_one.record.unwrap(), now).unwrap();
        add_device(&s[0].conn, &s[0].identity, &nine.key(), "device 9", now).unwrap();
        // Device 2, which the statement does not list, adds it as well:
        // that record gives nobody a standing.
        let by_two = add_device(&s[2].conn, &s[2].identity, &nine.key(), "device 9", now).unwrap();
        take(&s[0].conn, &s[0].identity, &by_two.record.unwrap(), now).unwrap();
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
        let asked: Vec<([u8; 32], [u8; 32])> = asked_about(&kept)
            .iter()
            .map(|record| (record.key, record.adder))
            .collect();
        assert!(asked.contains(&(nine.key(), s.key(1))), "{asked:?}");
        assert!(asked.contains(&(ten.key(), nine.key())), "{asked:?}");
        let gives: Vec<([u8; 32], [u8; 32])> = standing(&statement, &kept)
            .iter()
            .map(|record| (record.key, record.adder))
            .collect();
        assert_eq!(gives, [(nine.key(), s.key(0))]);
        let kept_of_nine = kept.iter().filter(|record| record.key == nine.key());
        assert_eq!(kept_of_nine.count(), 3);
    }

    use cordelia_storage::at_relays as kept_rows;
    use cordelia_storage::history::{About, Change, Entry as Named, Replacement, Store};

    use crate::several::state_of;
    use crate::state::PeerSnapshot;

    /// A relay that the node is connected to, as the node says it.
    fn connected(state: &AppState, relay: &[u8; 32], address: &str) {
        let mut peers = state.peers.write().unwrap();
        peers.push(PeerSnapshot {
            key: encode_public_key(relay).unwrap(),
            role: "relay".into(),
            state: "hot".into(),
            address: address.into(),
            connected_secs: 1,
            idle_secs: 0,
        });
    }

    /// What a device has still to send is said by name, of the relays it
    /// is connected to (decision 2026-10-04 §7.1, §8); and a status counts
    /// how many of its own channels wait at one of them.
    #[test]
    fn test_what_a_device_has_still_to_send_is_said_by_name_of_the_relays_it_reaches() {
        let mut s = Several::of_one_person(1);
        s.hold(&[0], "lab");
        s.hold(&[0], "team");
        s.write(0, "lab", "notes.md", "one");
        s.write(0, "team", "notes.md", "one");
        let state = state_of(s.machines.remove(0));
        // The names, and since when the first of what is still to go has
        // waited: a time where something waits, and none where nothing
        // does.
        let names_sent = |state: &AppState| -> Result<serde_json::Value, ApiError> {
            let mut names = super::names_sent(state)?;
            let since = names
                .as_object_mut()
                .unwrap()
                .remove("to_go_since")
                .unwrap();
            let waits = !names["to_go"].as_array().unwrap().is_empty();
            assert_eq!(since.as_i64().is_some(), waits, "{names}: {since}");
            Ok(names)
        };
        // No relay is connected: nothing is known to wait anywhere.
        assert_eq!(channels_waiting(&state), 0);
        assert_eq!(
            names_sent(&state).unwrap(),
            json!({ "sent": ["lab", "team"], "to_go": [] })
        );

        let relay = [7u8; 32];
        connected(&state, &relay, "relay.example:9474");
        // The personal channel and both names wait there.
        assert_eq!(channels_waiting(&state), 3);
        assert_eq!(
            names_sent(&state).unwrap(),
            json!({ "sent": [], "to_go": ["lab", "team"] })
        );
        {
            let conn = db(&state);
            let lab = held_rows::channel_of_name(&conn, "lab").unwrap().unwrap();
            kept_rows::sent(&conn, &relay, &lab, i64::MAX / 2).unwrap();
        }
        assert_eq!(channels_waiting(&state), 2);
        assert_eq!(
            names_sent(&state).unwrap(),
            json!({ "sent": ["lab"], "to_go": ["team"] })
        );
        // With a second relay, at which more waits: what is counted is
        // the most that wait at any one of them.
        connected(&state, &[8u8; 32], "other.example:9474");
        assert_eq!(channels_waiting(&state), 3);
        assert_eq!(
            names_sent(&state).unwrap(),
            json!({ "sent": [], "to_go": ["lab", "team"] })
        );
        // A peer that is no relay is not asked about.
        let mut peers = state.peers.write().unwrap();
        peers[0].role = "node".into();
        peers[1].role = "node".into();
        drop(peers);
        assert_eq!(channels_waiting(&state), 0);
    }

    /// A command that makes a change is handed the names that the
    /// personal channel lists, and, of what a device lists there that is
    /// no name, only how many and by which device (decision 2026-10-04
    /// §16): nothing of what it holds reaches the prompt of a removal.
    #[test]
    fn test_a_change_is_handed_no_word_that_is_no_name() {
        use crate::several::writes_words_that_are_no_names;
        let mut s = Several::of_one_person(2);
        let now = s.tick();
        s.hold(&[1], "lab");
        names::say(&s[1].conn, &s[1].identity, "lab", now).unwrap();
        let no_names = writes_words_that_are_no_names(&mut s, 1, 0);

        let (names, not_shown) = names_handed(&s[0].conn).unwrap();
        let listing = encode_public_key(&s.key(1)).unwrap();
        assert_eq!(names, [json!({ "name": "lab", "by": [listing] })]);
        assert_eq!(not_shown, [json!({ "by": listing, "words": no_names })]);
        let handed = json!([names, not_shown]).to_string();
        assert!(!handed.to_uppercase().contains("NOT-A-NAME"), "{handed}");
    }

    /// A relay that the device is set up with and that the node is not
    /// connected to is named as not reached (decision 2026-10-04 §7.1,
    /// step 4): no row says what waits to be sent there. It is known by
    /// the name of the configuration, in the node's list of its relays.
    #[test]
    fn test_a_relay_that_is_set_up_and_not_connected_is_named_as_not_reached() {
        use crate::state::{AtRelay, AtRelays, RelaySnapshot};
        let s = Several::of_one_person(1);
        let state = state_of(s.machines.into_iter().next().unwrap());
        let at = |name: &str| AtRelay {
            relay: name.into(),
            holds_latest: Some(true),
            heard_since_woke: true,
            no_room: None,
            another_form: 0,
            refuses: None,
        };
        let set_up = AtRelays {
            relays: vec![at("one.example:9474"), at("two.example:9474")],
            cannot_go_on: None,
        };
        let known = |name: &str, stands: &str| RelaySnapshot {
            host: name.into(),
            key: None,
            state: stands.into(),
            unreachable_secs: None,
            last_tried_secs: None,
            error: None,
        };
        // Before the node has listed its relays, none is known to be
        // connected.
        assert_eq!(
            not_reached(&state, &set_up),
            ["one.example:9474", "two.example:9474"]
        );
        *state.relays.write().unwrap() = vec![
            known("one.example:9474", "connected"),
            known("two.example:9474", "unreachable"),
        ];
        assert_eq!(not_reached(&state, &set_up), ["two.example:9474"]);
        state.relays.write().unwrap()[1].state = "connecting".into();
        assert_eq!(not_reached(&state, &set_up), ["two.example:9474"]);
        state.relays.write().unwrap()[1].state = "connected".into();
        assert!(not_reached(&state, &set_up).is_empty());
        // A device that is set up with no relay has none to reach.
        assert!(not_reached(&state, &AtRelays::default()).is_empty());
    }

    /// How much each device wrote that this device received in the last
    /// day and in the last week is counted from local history (decision
    /// 2026-10-04 §7.1, step 2): each version that arrived here, a text
    /// or a delete, by the key that its record names. With history off
    /// nothing was kept to count.
    #[test]
    fn test_what_a_device_wrote_that_arrived_here_is_counted_for_a_day_and_a_week() {
        let s = Several::of_one_person(1);
        let state = state_of(s.machines.into_iter().next().unwrap());
        let at = chrono::DateTime::parse_from_rfc3339("2026-10-05T12:00:00Z").unwrap();
        let now = at.with_timezone(&chrono::Utc);
        assert_eq!(received(&state, now.timestamp()), None);

        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path(), 30, 1 << 20).unwrap();
        store.prepare().unwrap();
        let keep = |change: Change, by: Option<&str>, ago: chrono::Duration| {
            let about = About {
                at: String::new(),
                agent: "lab".into(),
                folder: "/home/sam/memory".into(),
                file: "notes.md".into(),
                change,
                kept: None,
                replaced_by: match by {
                    Some(device) => Replacement::Entry(Named {
                        device: device.into(),
                        rev: 2,
                    }),
                    None => Replacement::Nothing,
                },
                behind: false,
            };
            let pending = store.keep(about, None, now - ago).unwrap();
            store.settle(pending).unwrap();
        };
        let (hours, days) = (chrono::Duration::hours, chrono::Duration::days);
        keep(Change::Pulled, Some("laptop"), hours(1));
        keep(Change::Removed, Some("laptop"), hours(23));
        keep(Change::Arrived, Some("laptop"), days(2));
        keep(Change::Pulled, Some("tablet"), days(6));
        // Out of the week.
        keep(Change::Pulled, Some("laptop"), days(8));
        // No arrival: this device's own edit, and its own merge.
        keep(Change::EditedHere, Some("laptop"), hours(1));
        keep(Change::Merged, Some("laptop"), hours(1));
        // An arrival that names no entry.
        keep(Change::Pulled, None, hours(1));
        state.history.open(Some(store));

        assert_eq!(
            received(&state, now.timestamp()),
            Some(json!({
                "laptop": { "day": 2, "week": 3 },
                "tablet": { "day": 0, "week": 1 },
            }))
        );
    }

    /// A command that prepares a change has the node run a sync cycle
    /// that began after it asked, and waits for it only so long (decision
    /// 2026-10-04 §7.1, step 1). A node with no network runs none, and
    /// with sync off no folder syncs: nothing is waited for.
    #[actix_web::test]
    async fn test_a_command_waits_for_a_cycle_that_began_after_it_asked() {
        let soon = || Instant::now() + Duration::from_millis(400);
        let with_network = |sync_on: bool| {
            let mut state = state_of(Machine::new(1));
            let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
            state.push_tx = Some(tx);
            if sync_on {
                meta::set(&db(&state), meta::SYNC_CLAUDE_DIR, "/home/sam/.claude").unwrap();
            }
            std::sync::Arc::new(state)
        };
        // No network, and sync off: nothing is waited for.
        let mut no_network = state_of(Machine::new(1));
        meta::set(&db(&no_network), meta::SYNC_CLAUDE_DIR, "/home/sam/.claude").unwrap();
        no_network.push_tx = None;
        assert_eq!(cycle(&no_network, soon()).await, Waited::Done);
        assert_eq!(cycle(&with_network(false), soon()).await, Waited::Done);

        // Sync on, and no cycle runs: it waits until the time is up.
        let state = with_network(true);
        let began = Instant::now();
        assert_eq!(cycle(&state, soon()).await, Waited::NotEnded);
        assert!(began.elapsed() >= Duration::from_millis(400));
        assert!(
            began.elapsed() < Duration::from_secs(2),
            "it waited past its time"
        );

        // A cycle that was running when it asked does not count: one
        // that began after does.
        let state = with_network(true);
        let running = state.sync_control.cycle_begins();
        let node = std::sync::Arc::clone(&state);
        let ran = tokio::spawn(async move {
            node.sync_control.woken().await;
            node.sync_control.cycle_ended(running);
            tokio::time::sleep(Duration::from_millis(150)).await;
            let next = node.sync_control.cycle_begins();
            node.sync_control.cycle_ended(next);
        });
        let began = Instant::now();
        let waited = cycle(&state, Instant::now() + Duration::from_secs(20)).await;
        assert_eq!(waited, Waited::Done);
        assert!(began.elapsed() >= Duration::from_millis(150));
        ran.await.unwrap();

        // A cycle that stopped before its end has ended, and early.
        let state = with_network(true);
        let node = std::sync::Arc::clone(&state);
        let ran = tokio::spawn(async move {
            node.sync_control.woken().await;
            let stopped = node.sync_control.cycle_begins();
            node.sync_control.cycle_was_cut_short(stopped);
            node.sync_control.cycle_ended(stopped);
        });
        let waited = cycle(&state, Instant::now() + Duration::from_secs(20)).await;
        assert_eq!(waited, Waited::EndedEarly);
        ran.await.unwrap();
    }

    /// A command that prepares a change has the device make a whole pass
    /// that began after it asked (decision 2026-10-04 §7.1, step 1). A
    /// pass that ended before it had read every channel to its end has
    /// not fetched what the relays hold: it is asked for again, so many
    /// times, and then the command is told so. A device in a fork is not
    /// asked again.
    #[actix_web::test]
    async fn test_a_pass_that_ended_early_is_asked_for_again_and_then_said() {
        let with_network = || {
            let mut state = state_of(Machine::new(1));
            let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
            state.push_tx = Some(tx);
            std::sync::Arc::new(state)
        };
        // The node, as its loop does it: at each asking it makes a whole
        // pass, of which the first `short` end early.
        let node_makes = |state: &std::sync::Arc<AppState>, short: usize| {
            let node = std::sync::Arc::clone(state);
            tokio::spawn(async move {
                let mut made = 0;
                loop {
                    node.own_channels.wait_asked().await;
                    let pass = node.own_channels.whole_pass_begins();
                    if made < short {
                        node.own_channels.whole_pass_was_short(pass);
                    }
                    node.own_channels.whole_pass_ended(pass);
                    made += 1;
                }
            })
        };
        let soon = || Instant::now() + Duration::from_secs(20);

        // A node with no network has nobody to ask.
        let mut no_network = state_of(Machine::new(1));
        no_network.push_tx = None;
        assert_eq!(fetch(&no_network, true, soon()).await, Waited::Done);
        // No pass ends: the time is up.
        let state = with_network();
        let briefly = Instant::now() + Duration::from_millis(300);
        assert_eq!(fetch(&state, true, briefly).await, Waited::NotEnded);

        // A pass that read everything is asked for once.
        let state = with_network();
        let node = node_makes(&state, 0);
        assert_eq!(fetch(&state, true, soon()).await, Waited::Done);
        assert_eq!(state.own_channels.whole_passes(), (1, 1));
        node.abort();
        // One that ended early is asked for again, and the next read on.
        let state = with_network();
        let node = node_makes(&state, CHANGE_FETCH_PASSES - 1);
        assert_eq!(fetch(&state, true, soon()).await, Waited::Done);
        assert_eq!(
            state.own_channels.whole_passes().1,
            CHANGE_FETCH_PASSES as u64
        );
        node.abort();
        // So many times, and no more.
        let state = with_network();
        let node = node_makes(&state, usize::MAX);
        assert_eq!(fetch(&state, true, soon()).await, Waited::EndedEarly);
        assert_eq!(
            state.own_channels.whole_passes().1,
            CHANGE_FETCH_PASSES as u64
        );
        node.abort();
        // A device in a fork is asked once.
        let state = with_network();
        let node = node_makes(&state, usize::MAX);
        assert_eq!(fetch(&state, false, soon()).await, Waited::EndedEarly);
        assert_eq!(state.own_channels.whole_passes().1, 1);
        node.abort();

        // What the command is told: a line for each that did not do all
        // that was asked.
        assert!(not_fetched(Waited::Done, Waited::Done, false).is_empty());
        let early = not_fetched(Waited::EndedEarly, Waited::EndedEarly, false);
        assert_eq!(early.len(), 2, "{early:?}");
        assert!(
            early[0].starts_with(
                "the fetch ended before every channel was read to its end at every relay"
            ),
            "{early:?}"
        );
        assert!(
            early[1].starts_with("the sync cycle stopped before its end"),
            "{early:?}"
        );
        let not_ended = not_fetched(Waited::NotEnded, Waited::NotEnded, false);
        assert!(not_ended[0].starts_with("the fetch did not end within 120 seconds"));
        assert!(not_ended[1].starts_with("no sync cycle ended within 120 seconds"));
        // A device in a fork fetches nothing, and that is no failure of
        // the fetch.
        assert!(not_fetched(Waited::EndedEarly, Waited::Done, true).is_empty());
        assert_eq!(not_fetched(Waited::NotEnded, Waited::Done, true).len(), 1);
    }
}
