//! The node's half of a carry that a person asks for (decision 2026-10-04
//! §7.3, §7.5): `cordelia sync carry`, and what `cordelia sync map`
//! carries for a name that the device comes to sync.
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
//! **What a key that does not count signed is not read here at all.** It
//! comes in only by the command that names the key and asks for the
//! phrase.
//!
//! The device's own store is brought up to what the relays hold of the
//! new channel first (a whole pass), so that what is judged against is
//! what the new channel holds now. What is carried waits in the store and
//! is sent like anything the device writes.

use std::time::{Duration, Instant};

use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use cordelia_core::protocol::CARRY_READ_MAX_SECS;
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_storage::entries;
use cordelia_storage::person::{self as held_rows, State};

use crate::carry::{self, Rule, Tally, WasRead};
use crate::commands;
use crate::error::ApiError;
use crate::names;
use crate::person::{self, PersonError};
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
        let held = person::held(&conn)?.ok_or(PersonError::FollowsNoPhrase)?;
        if held.state != State::Applied {
            return Err(PersonError::Stopped(held.state));
        }
        if !names::is_a_name(name) {
            return Err(PersonError::NameNotHeld(name.to_string()));
        }
        let left: Vec<(u64, Zeroizing<[u8; 32]>)> = held_rows::secrets(&conn)?
            .into_iter()
            .filter(|secret| secret.left_at.is_some())
            .map(|secret| (secret.number, Zeroizing::new(secret.secret)))
            .collect();
        if left.is_empty() {
            done.nothing = Some(
                "this device holds the secret of no generation that it left: there is nothing \
                 that it can read"
                    .into(),
            );
            return Ok(done);
        }
        if held_rows::channel_of_name(&conn, name)?.is_none() {
            names::hold_for_a_carry(&conn, &state.identity, name, now())?;
            done.held_anew = true;
        }
        (left, person::who_counts(&conn)?)
    };
    if done.held_anew {
        state.own_channels.written();
    }

    // What the relays hold of the new channel is fetched first: what a
    // version is judged against is what the new channel holds now.
    let deadline = Instant::now() + Duration::from_secs(CARRY_READ_MAX_SECS);
    commands::fetch(state, true, deadline).await;

    let counts = |key: &[u8; 32]| counting.counts(key);
    let mut read: Vec<(u64, WasRead)> = Vec::new();
    for (number, secret) in &left {
        let of_the_name = Zeroizing::new(derive::own_secret(secret, name)?);
        let channel = derive::channel_id(&of_the_name)?;
        let by = ProvedBy::Secret(of_the_name.clone());
        let at = read_at_relays(state, channel, by, deadline).await;
        let (entries, said) = handed(&at);
        done.read_all &= !said.is_empty() && said.iter().all(read_to_its_end);
        let was = carry::read(&entries, &of_the_name, *number, counts)?;
        let other_keys = was.signed_by(|key| !counts(key));
        done.by_other_keys += other_keys;
        done.generations.push(json!({
            "number": number,
            "relays": said,
            "by_other_keys": other_keys,
        }));
        read.push((*number, was));
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
        for (_, was) in &read {
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
