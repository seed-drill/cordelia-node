//! The status's `shared` object (decision 2026-10-10 §9): what a personal
//! node that stands applied says of its shared channels, beside the
//! `messages` object of the messages record and apart from it.
//!
//! - **Nothing here sets a level.** The level is worked out in the command
//!   (`cordelia-node/src/indicator.rs`), which reads of this object two
//!   facts alone: `removed_device_holds`, each removed device that still
//!   holds a shared channel the person has not made anew (property 16);
//!   and each line of `repositories` that is amber, the joining record's
//!   ambers, by the person's ruling of 6 November (decision 2026-11-06
//!   (joining), rule 6; [`crate::repository_status`]). Everything else is
//!   for a person and a panel to read.
//! - **Nothing in it is another person's text:** a relay is given by the
//!   configuration's address for it and its key's words (§8.1), a key by
//!   its whole key and its words, and a name is the person's own.
//! - **Absent** on a node that does not stand applied, and on a relay or a
//!   bootnode ([`status_of`] answers `None`).

use std::collections::{BTreeMap, HashSet};

use rusqlite::Connection;
use serde_json::{Value, json};

use cordelia_crypto::acts::Filing;
use cordelia_crypto::bech32::encode_public_key;
use cordelia_crypto::fingerprint;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_storage::shared::{self as kept, State};
use cordelia_storage::shared_anew as anew_rows;
use cordelia_storage::shared_messages as message_rows;
use cordelia_storage::shared_sharing as sharing_rows;

use crate::at_relays::{Stands, stands};
use crate::lists::AnyAct;
use crate::person::{PersonError, in_one};
use crate::shared_anew::{self, Fault, OfferIs};
use crate::sharing::{self, OwnRelay, channel_words, sender_form, six_words};
use crate::state::SharedSaid;

fn st<T>(answer: Result<T, cordelia_core::CordeliaError>) -> Result<T, PersonError> {
    answer.map_err(PersonError::Storage)
}

/// A moment by the node's clock in RFC 3339.
fn rfc3339(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// What the status is given beside the database: the relays the device
/// knows by their keys, the keys of those connected now, what the shared
/// pass said since the node started, and when the node's timer next reads
/// the lists of the repositories it follows, where one does.
pub struct Beside<'a> {
    pub own_relays: &'a [OwnRelay],
    pub connected: &'a [[u8; 32]],
    pub said: &'a SharedSaid,
    pub next_read: Option<i64>,
}

/// The `shared` object at `now` (§9), or `None` where the device does not
/// stand applied: it is then absent from the status.
pub fn status_of(
    conn: &Connection,
    identity: &NodeIdentity,
    beside: &Beside,
    now: i64,
) -> Result<Option<Value>, PersonError> {
    in_one(conn, || {
        if stands(conn)? != Stands::Applied {
            return Ok(None);
        }
        let Some(held) = crate::person::held(conn)? else {
            return Ok(None);
        };
        let own = identity.public_key();
        let names: Vec<String> = crate::names::listed(conn)?
            .into_iter()
            .map(|listed| listed.name)
            .collect();
        let worked_out = crate::lists::holds_worked_out(conn, &own, now)?;
        let labels: Vec<[u8; 32]> = worked_out
            .labels
            .iter()
            .filter(|(act, _)| act.item.label.is_some())
            .map(|(act, _)| act.item.key)
            .collect();
        let subscriptions = crate::shared_messages::in_force(conn)?;
        let filings = sharing::filed(conn)?;
        let mut channels = Vec::new();
        for filing in &filings {
            channels.push(channel_of(
                conn,
                identity,
                &held,
                beside,
                filing,
                &names,
                &labels,
                &subscriptions,
                now,
            )?);
        }

        let mut typed = Vec::new();
        for row in st(sharing_rows::typed_keys(conn))? {
            typed.push(json!({
                "key": encode_public_key(&row.key)?,
                "words": six_words(&row.key),
                "channel": row.name,
                "until": rfc3339(row.typed_at + cordelia_core::protocol::PAIR_KEY_TYPED_SECS),
                "became": row.became,
            }));
        }

        // Each removed device that still holds a shared channel the person
        // has not made anew and moved from, or dropped (§3.5, §9; decision
        // 2026-10-24, rule 25): a channel not yet clean, by when this device
        // applied the removal. The one fact the level reads.
        let removed_labels = crate::look::removed_labels(conn)?;
        let named = |key: &[u8; 32]| match removed_labels.iter().find(|(of, _)| of == key) {
            Some((_, label)) if !label.is_empty() => format!(
                "\"{}\" ({})",
                crate::messages::cleaned(label),
                fingerprint::shown(key)
            ),
            _ => format!("({})", fingerprint::shown(key)),
        };
        let mut by_since: BTreeMap<i64, Vec<String>> = BTreeMap::new();
        for mark in st(anew_rows::not_clean_all(conn))? {
            if !shared_anew::is_not_clean(conn, &mark.channel)? {
                continue;
            }
            if let Some(row) = st(kept::channel(conn, &mark.channel))? {
                by_since.entry(mark.since).or_default().push(row.name);
            }
        }
        // Each group names the keys that the removal of its time removed,
        // and the statement before it did not. A group of channels first
        // held after a removal, marked at no removal's time, has no
        // `device`: none of them was held by a removed device (issue #279).
        // One first held in the same second as the removal names the
        // removal's keys: the mark keeps no more than its time.
        let mut removed_device_holds: Vec<Value> = Vec::new();
        for (since, channels) in by_since {
            let removed = shared_anew::removed_at(conn, since)?.unwrap_or_default();
            let mut group = json!({
                "channels": channels,
                "since": rfc3339(since),
            });
            if !removed.is_empty() {
                let device: Vec<String> = removed.iter().map(named).collect();
                group["device"] = json!(device.join(", "));
            }
            removed_device_holds.push(group);
        }

        let mut acts_of_removed_devices = Vec::new();
        for act in shared_anew::acts_of_removed(conn)? {
            acts_of_removed_devices.push(json!({
                "device": named(&act.maker),
                "act": act.act,
                "item": act.item,
                "undo": act.undo,
            }));
        }

        let mut passed_over = Vec::new();
        for (key, acts) in &worked_out.passed_over_acts {
            passed_over.push(json!({
                "key": encode_public_key(key)?,
                "words": six_words(key),
                "acts": acts,
            }));
        }

        let in_force: Vec<Filing> = worked_out
            .filings
            .iter()
            .map(|(act, _)| act.item.clone())
            .collect();
        let mut past_a_bound = Vec::new();
        for (act, _) in &worked_out.left_out {
            let (kind, item, _) = shared_anew::described(act, &in_force)?;
            let channel = match act {
                AnyAct::Filing(filing) => Some(channel_words(&filing.item.channel)),
                AnyAct::Drop(drop) => Some(channel_words(&drop.item.channel)),
                _ => None,
            };
            past_a_bound.push(json!({ "act": kind, "item": item, "channel": channel }));
        }

        // Each channel past a bound that a removal here made anew in the
        // last seven days (§3.5): the person's devices hold neither it nor
        // the new one. It sets no level.
        let shown_since =
            now - cordelia_core::protocol::REMOVAL_NOT_APPLIED_SHOWN_DAYS as i64 * 86_400;
        let mut made_anew_past_a_bound = Vec::new();
        for (name, made, line) in shared_anew::made_anew_past_a_bound(conn, shown_since)? {
            made_anew_past_a_bound.push(json!({
                "name": name,
                "words": channel_words(&made.new_channel),
                "made": rfc3339(made.made_at),
                "said": line,
            }));
        }

        // Each repository this device follows (decision 2026-11-06
        // (joining), rule 7).
        // The unread messages of each channel, as worked out above.
        let unread: Vec<([u8; 32], (usize, usize))> = channels
            .iter()
            .filter_map(|channel| {
                let id: [u8; 32] = hex::decode(channel["id"].as_str()?).ok()?.try_into().ok()?;
                let count = |field: &str| channel[field].as_u64().unwrap_or(0) as usize;
                Some((
                    id,
                    (count("unread_by_an_agent"), count("unread_by_a_person")),
                ))
            })
            .collect();
        let repositories = crate::repository_status::views(
            conn,
            identity,
            beside.own_relays,
            Some(&unread),
            beside.next_read,
            now,
        );

        Ok(Some(json!({
            "channels": channels,
            "typed": typed,
            "removed_device_holds": removed_device_holds,
            "acts_of_removed_devices": acts_of_removed_devices,
            "passed_over": passed_over,
            "past_a_bound": past_a_bound,
            "made_anew_past_a_bound": made_anew_past_a_bound,
            "repositories": repositories,
        })))
    })
}

/// One channel of the object (§9).
#[allow(clippy::too_many_arguments)]
fn channel_of(
    conn: &Connection,
    identity: &NodeIdentity,
    held: &crate::person::Held,
    beside: &Beside,
    filing: &Filing,
    names: &[String],
    labels: &[[u8; 32]],
    subscriptions: &[([u8; 32], String)],
    now: i64,
) -> Result<Value, PersonError> {
    let own = identity.public_key();
    let row = st(kept::channel(conn, &filing.channel))?;
    let keys = match &row {
        Some(row) => st(kept::keys(conn, row.id))?,
        None => Vec::new(),
    };
    let wrote: Vec<&kept::Key> = keys
        .iter()
        .filter(|key| key.first_held.is_some() && key.key != own)
        .collect();
    // Since this device last wrote there (§5.4): its latest entry the
    // store holds, or, where it holds none, when it first held the
    // channel. The lines of §5.4 say nothing then; this count still does.
    let last_written = cordelia_storage::entries::author_entries(conn, &filing.channel, &own)
        .map_err(PersonError::Storage)?
        .iter()
        .map(|stored| stored.stored_at)
        .max();
    let since = last_written.or(row.as_ref().map(|row| row.first_held));
    let new_since_written = wrote
        .iter()
        .filter(|key| since.is_some_and(|since| key.first_held.is_some_and(|at| at > since)))
        .count();
    let refused: Vec<&kept::Key> = keys
        .iter()
        .filter(|key| key.key != own && key.first_refused.is_some() && key.bytes_refused > 0)
        .collect();
    let mut refused_keys = Vec::new();
    for key in &refused {
        refused_keys.push(json!({
            "key": encode_public_key(&key.key)?,
            "words": six_words(&key.key),
            "first_refused": key.first_refused.map(rfc3339),
            "bytes": key.bytes_refused,
        }));
    }
    let subscribed: Vec<&str> = subscriptions
        .iter()
        .filter(|(channel, _)| *channel == filing.channel)
        .map(|(_, agent)| agent.as_str())
        .collect();

    let (mut unread_by_an_agent, mut unread_by_a_person, mut held_back) = (0, 0, 0);
    let (mut beyond_shown, mut waiting) = (0, 0);
    let mut offers = Vec::new();
    let mut not_moved_yet = 0;
    if let Some(row) = row.as_ref().filter(|row| row.state == State::Held) {
        (unread_by_an_agent, unread_by_a_person) =
            unread_in(conn, identity, row, &subscribed, now)?;
        for key in &keys {
            held_back += st(kept::held_back(conn, row.id, &key.key, now))?;
        }
        let shown: HashSet<[u8; 32]> = crate::shared::shown_keys(conn, &filing.channel)?
            .into_iter()
            .collect();
        beyond_shown = st(kept::waiting_to_open(conn, row.id))?
            .iter()
            .filter(|(key, _)| !shown.contains(key))
            .map(|(_, count)| *count)
            .sum::<u64>();
        waiting = st(message_rows::kept(conn))?
            .iter()
            .filter(|kept| kept.channel == row.id)
            .count();
        for judged in shared_anew::judged(conn, identity, row, Some(now))? {
            let (is, fault) = match &judged.is {
                OfferIs::Fault(fault) => ("fault", Some(Fault::word(*fault))),
                OfferIs::WithoutYou => ("without_you", None),
                OfferIs::SealedElsewhere(_) => ("sealed_elsewhere", None),
                OfferIs::ForThisDevice(_) => ("move", None),
            };
            offers.push(json!({
                "by": sender_form(conn, held, &own, &judged.offer.maker)?,
                "made": rfc3339(i64::try_from(judged.offer.made).unwrap_or(i64::MAX)),
                "left_out": judged.left_out.len(),
                "words": channel_words(&judged.offer.new_channel),
                "is": is,
                "fault": fault,
            }));
        }
        not_moved_yet = shared_anew::not_moved_yet(conn, &own, &filing.channel)?.len();
    }

    let relays: Vec<Value> = filing
        .card
        .relays()
        .keys()
        .iter()
        .map(|key| {
            let named = beside.own_relays.iter().find(|relay| relay.key == *key);
            let not_reached = match named {
                None => Some("not_own"),
                Some(_) if beside.said.no_proof_room.contains(&(filing.channel, *key)) => {
                    Some("no_proof_room")
                }
                Some(_) => None,
            };
            json!({
                "relay": named.map(|relay| relay.name.clone()),
                "words": fingerprint::shown(key),
                "connected": named.is_some() && beside.connected.contains(key),
                "not_reached": not_reached,
            })
        })
        .collect();
    let refused_at_a_relay: u64 = beside
        .said
        .refused_at
        .iter()
        .filter(|((channel, _), _)| *channel == filing.channel)
        .map(|(_, refused)| *refused)
        .sum();

    Ok(json!({
        "id": hex::encode(filing.channel),
        "name": filing.name,
        "words": channel_words(&filing.channel),
        "keys": wrote.len(),
        "labelled": wrote.iter().filter(|key| labels.contains(&key.key)).count(),
        "new_since_written": new_since_written,
        "not_moved_yet": not_moved_yet,
        "unread_by_an_agent": unread_by_an_agent,
        "unread_by_a_person": unread_by_a_person,
        "held_back": held_back,
        "beyond_shown": beyond_shown,
        "subscribed": subscribed,
        "waiting": waiting,
        "not_stored": beside.said.not_stored.get(&filing.channel).copied().unwrap_or(0),
        "refused_for_room": refused.len(),
        "refused_keys": refused_keys,
        "rows_let_go": row.as_ref().map_or(0, |row| row.let_go),
        "refused_at_a_relay": refused_at_a_relay,
        "reached": sharing::any_own(beside.own_relays, &filing.card),
        "relays": relays,
        "offers": offers,
        "also_a_name": names.contains(&filing.name),
    }))
}

/// The messages of the channel of `row`, which the person holds, that wait
/// unread at `now`: by an agent, for each folder of `subscribed` that
/// subscribes to it, a message unread by two counting twice, as the
/// `messages` object counts a message to every name once for each folder;
/// and by the person, on this device.
pub(crate) fn unread_in(
    conn: &Connection,
    identity: &NodeIdentity,
    row: &kept::Channel,
    subscribed: &[&str],
    now: i64,
) -> Result<(usize, usize), PersonError> {
    let own = identity.public_key();
    let mut by_an_agent = 0;
    for agent in subscribed {
        by_an_agent += crate::shared_messages::unread(conn, identity, agent, now)?
            .iter()
            .filter(|seen| seen.row.channel == row.channel)
            .count();
    }
    let read_here = st(message_rows::read_by_a_person(conn, row.id))?;
    let mut by_a_person = 0;
    for message in crate::shared::shown(conn, identity, &row.channel, now)? {
        let id = crate::shared_messages::id_of(&message.id)?;
        if message.signer != own && !read_here.contains(&id) {
            by_a_person += 1;
        }
    }
    Ok((by_an_agent, by_a_person))
}

#[cfg(test)]
mod tests;
