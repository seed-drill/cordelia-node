//! The routes of subscribing and of messages in a shared channel (decision
//! 2026-10-10 §4, §5.1 to §5.6, §6): `/api/v1/shared/subscribe`,
//! `unsubscribe`, `read`, `send`, `summary` and `log`.
//!
//! - **Each is a POST with a JSON body that refuses a field it does not
//!   know** (`deny_unknown_fields`), behind the node's token, refused while
//!   the node is held up; `summary` aside, which answers nothing then.
//! - **The send route builds only an address of a shared channel**
//!   (`Address::Shared`): its body names a channel and no agent of the
//!   person's own, and a body that says `to` is refused here. The routes of
//!   the messages record build only the other kind, and are unchanged.
//! - **`read`, `send`, `summary` and `log`** answer a refusal as the
//!   messages record's routes do: a conflict whose code is the word, with
//!   its line as the message and what the command needs beside it.

use std::time::{Duration, Instant};

use actix_web::{HttpRequest, HttpResponse, web};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{Value, json};

use cordelia_core::protocol::{
    AGENT_MESSAGE_BODY_MAX_BYTES, AGENT_MESSAGE_ID_BYTES, AGENT_MESSAGE_SUMMARY_WAIT_MS,
};
use cordelia_crypto::acts::Subscription;
use cordelia_crypto::bech32::encode_public_key;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::message::{is_a_link, shared_read_mark};
use cordelia_crypto::share::Card;
use cordelia_storage::shared::{self as kept, Channel, Shown, State};
use cordelia_storage::shared_messages as rows;

use crate::at_relays::{Stands, stands};
use crate::error::ApiError;
use crate::lists::Do;
use crate::messages::{agent_of, cleaned, is_an_id};
use crate::person::{PersonError, in_one, who_counts};
use crate::sender::{self, Address, At, NotSent, Refused, Reply, Request};
use crate::shared_messages::{self as seen, Seen, id_of, thread_of};
use crate::sharing::{self, Failed, OwnRelay, Plan, Refusal};
use crate::sharing_routes::{answer_of, asked_then, db};
use crate::state::AppState;

// ── Lines ────────────────────────────────────────────────────────────

/// A word as a shell argument: as it is where that is safe, quoted
/// otherwise, as the commands quote a name they print.
pub fn shell_word(word: &str) -> String {
    let plain = !word.is_empty()
        && !word.starts_with('-')
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-+@~".contains(&b));
    match plain {
        true => word.to_string(),
        false => format!("'{}'", word.replace('\'', "'\\''")),
    }
}

/// The line of a folder that is not mapped (the messages record's §4.3).
fn not_mapped_line(folder: &str) -> String {
    format!(
        "This folder is not mapped, so no agent of yours runs here, and nothing was done. Map it \
         with: cordelia sync map {} <name>",
        shell_word(folder)
    )
}

/// A refusal of a command of this record with its word and line.
fn refusal<T>(word: &'static str, line: String) -> Result<T, Failed> {
    Err(Failed::Refused(Refusal { word, line }))
}

/// A refusal as the messages record's routes answer one: its word, its
/// line, and what is beside it.
fn refused_with(word: &str, line: &str, details: Value) -> HttpResponse {
    HttpResponse::Conflict().json(json!({
        "error": { "code": word, "message": line },
        "refused": details,
    }))
}

/// [`refused_with`] of a refusal of this record's lookups.
fn failed(failed: Failed) -> Result<HttpResponse, ApiError> {
    match failed {
        Failed::Refused(refusal) => Ok(refused_with(
            if refusal.word.is_empty() {
                "refused"
            } else {
                refusal.word
            },
            &refusal.line,
            json!({}),
        )),
        Failed::Error(e) => Err(crate::commands::refused(e)),
    }
}

/// The relays of `card` that are, by key, the device's own: how many.
fn reached(own: &[OwnRelay], card: &Card) -> usize {
    card.relays()
        .keys()
        .iter()
        .filter(|key| own.iter().any(|relay| relay.key == **key))
        .count()
}

fn card_of(row: &Channel) -> Result<Card, PersonError> {
    Card::from_bytes(&row.card)
        .map_err(|e| PersonError::Held(format!("the card of a shared channel: {e}")))
}

/// The folder's agent, or the refusal of a folder that is not mapped.
fn agent_here(conn: &Connection, folder: &str) -> Result<String, Failed> {
    match agent_of(conn, folder).map_err(|e| Failed::Error(PersonError::Held(e.to_string())))? {
        Some(agent) => Ok(agent),
        None => refusal("not_mapped", not_mapped_line(folder)),
    }
}

// ── POST /api/v1/shared/subscribe ────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscribeRequest {
    pub folder: String,
    pub name: String,
    #[serde(default)]
    pub words: Option<String>,
    #[serde(default)]
    pub look: bool,
    #[serde(default)]
    pub said_yes_to: Option<String>,
}

/// What `subscribe` would do: the subscription, and its yes; or, where
/// the agent subscribes already, the line said with nothing done.
pub fn subscribe_plan(
    conn: &Connection,
    identity: &NodeIdentity,
    folder: &str,
    name: &str,
    words: Option<&str>,
) -> Result<Result<Plan<Subscription>, String>, Failed> {
    let held = sharing::standing(conn)?;
    let agent = agent_here(conn, folder)?;
    let filing = sharing::find(conn, name, words, None)?;
    let shown = cleaned(&filing.name);
    let shown_agent = cleaned(&agent);
    if seen::in_force(conn)?
        .iter()
        .any(|(channel, of)| *channel == filing.channel && *of == agent)
    {
        return Ok(Err(format!(
            "{shown_agent} subscribes to \"{shown}\" already."
        )));
    }
    let own = identity.public_key();
    let (keys, labelled) = keys_that_wrote(conn, &held, &own, &filing.channel)?;
    let asks = format!(
        "The agent of this folder, {shown_agent}, will be shown a count of the messages in the \
         shared channel \"{shown}\", on every device of yours where {shown_agent} is mapped. It \
         can read them, and write there with --channel {}.\nThey come from other people's \
         agents: {keys} keys wrote there, {labelled} of them labelled by you. Anyone a member \
         handed the channel to reads it too, unseen.",
        shell_word(&filing.name)
    );
    Ok(Ok(Plan {
        asks,
        what: Subscription {
            channel: filing.channel,
            agent,
            subscribed: true,
        },
    }))
}

/// How many keys wrote in `channel` as this device holds it, this device
/// not among them, and how many of them the person labelled, as `shared
/// list` counts them.
fn keys_that_wrote(
    conn: &Connection,
    _held: &crate::person::Held,
    own: &[u8; 32],
    channel: &[u8; 32],
) -> Result<(usize, usize), PersonError> {
    let Some(row) = kept::channel(conn, channel)? else {
        return Ok((0, 0));
    };
    let labels: Vec<[u8; 32]> = crate::lists::holds(conn)?
        .labels
        .iter()
        .filter(|(act, _)| act.item.label.is_some())
        .map(|(act, _)| act.item.key)
        .collect();
    let wrote: Vec<[u8; 32]> = kept::keys(conn, row.id)?
        .into_iter()
        .filter(|key| key.first_held.is_some() && key.key != *own)
        .map(|key| key.key)
        .collect();
    let labelled = wrote.iter().filter(|key| labels.contains(key)).count();
    Ok((wrote.len(), labelled))
}

/// `cordelia subscribe <name>` (§4.1, §5.2): of the folder's agent, at a
/// terminal, with a yes. No other command subscribes.
pub async fn subscribe(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SubscribeRequest>,
) -> Result<HttpResponse, ApiError> {
    crate::commands::asked(&req, &state)?;
    let identity = &state.identity;
    let plan = |conn: &Connection| {
        subscribe_plan(
            conn,
            identity,
            &body.folder,
            &body.name,
            body.words.as_deref(),
        )
    };
    {
        let conn = db(&state);
        match plan(&conn) {
            Ok(Err(line)) => return Ok(HttpResponse::Ok().json(json!({ "said": [line] }))),
            Ok(Ok(_)) => {}
            Err(failed) => return answer_of(failed),
        }
    }
    asked_then(
        &state,
        body.look,
        body.said_yes_to.as_deref(),
        |conn, _, _| match plan(conn) {
            Ok(Ok(plan)) => Ok(plan),
            Ok(Err(line)) => Err(Failed::Refused(Refusal { word: "", line })),
            Err(failed) => Err(failed),
        },
        |conn, _, subscription, now| {
            let held = sharing::standing(conn)?;
            let name = cleaned(&channel_name(conn, &subscription.channel)?);
            sharing::act(
                conn,
                identity,
                &held,
                Do::Subscribe(subscription.clone()),
                now,
            )?;
            Ok(json!({ "said": [format!(
                "Subscribed: {} to \"{name}\", from now on. What was written there before now is \
                 in cordelia msg log only.",
                cleaned(&subscription.agent)
            )] }))
        },
    )
}

/// The name the person files the shared channel `channel` under.
fn channel_name(conn: &Connection, channel: &[u8; 32]) -> Result<String, PersonError> {
    Ok(sharing::filed(conn)?
        .into_iter()
        .find(|filing| filing.channel == *channel)
        .map(|filing| filing.name)
        .unwrap_or_default())
}

// ── POST /api/v1/shared/unsubscribe ──────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsubscribeRequest {
    /// The folder the command was run in, where no agent is given.
    #[serde(default)]
    pub folder: Option<String>,
    /// The agent, from anywhere.
    #[serde(default)]
    pub agent: Option<String>,
    pub name: String,
    #[serde(default)]
    pub words: Option<String>,
}

/// `cordelia unsubscribe <name> [--agent <agent>]` (§4.1, §5.2): no yes.
/// Returns the line said.
pub fn unsubscribe_of(
    conn: &Connection,
    identity: &NodeIdentity,
    asked: &UnsubscribeRequest,
    now: i64,
) -> Result<String, Failed> {
    let held = sharing::standing(conn)?;
    let agent = match (&asked.agent, &asked.folder) {
        (Some(agent), _) => agent.clone(),
        (None, Some(folder)) => agent_here(conn, folder)?,
        (None, None) => return refusal("not_mapped", not_mapped_line("")),
    };
    let filing = sharing::find(conn, &asked.name, asked.words.as_deref(), None)?;
    let shown = cleaned(&filing.name);
    let subscribed = seen::in_force(conn)?
        .iter()
        .any(|(channel, of)| *channel == filing.channel && *of == agent);
    if !subscribed {
        return Ok(format!(
            "{} does not subscribe to \"{shown}\".",
            cleaned(&agent)
        ));
    }
    let ended = Subscription {
        channel: filing.channel,
        agent: agent.clone(),
        subscribed: false,
    };
    sharing::act(conn, identity, &held, Do::Subscribe(ended), now)?;
    Ok(format!(
        "Unsubscribed: {} from \"{shown}\". This agent is shown nothing from it from now on, on \
         every device of yours.",
        cleaned(&agent)
    ))
}

pub async fn unsubscribe(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<UnsubscribeRequest>,
) -> Result<HttpResponse, ApiError> {
    crate::commands::asked(&req, &state)?;
    let now = state.sync_control.now();
    let done = unsubscribe_of(&db(&state), &state.identity, &body, now);
    match done {
        Ok(said) => {
            state.own_channels.written();
            Ok(HttpResponse::Ok().json(json!({ "said": [said] })))
        }
        Err(failed) => answer_of(failed),
    }
}

// ── read ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRequest {
    pub folder: String,
    /// 8 to 32 hex characters of the message's ID, or none with `next`.
    #[serde(default)]
    pub id: Option<String>,
    /// The oldest unread message of a channel this folder subscribes to.
    #[serde(default)]
    pub next: bool,
}

/// Why `read` shows nothing.
#[derive(Debug)]
pub enum NotShown {
    Refused(Refused),
    Failed(Failed),
}

impl From<PersonError> for NotShown {
    fn from(e: PersonError) -> Self {
        Self::Failed(Failed::Error(e))
    }
}

/// `read` of a shared message by the agent of `folder` at `now` (§4.2,
/// §5.3, §6.1), in one write: by `id`, among the messages of the channels
/// it subscribes to (refused with `more_than_one` where the ID begins two,
/// in two channels or one of them a message of the person's own), or the
/// oldest unread with `next` (`Ok(None)` where none is). It is marked read
/// by that agent here, unless an agent of its name sent it, and the list of
/// shared marks is written where it may be (`fetched`). It works with sync
/// off.
pub fn read_of(
    conn: &Connection,
    identity: &NodeIdentity,
    asked: &ReadRequest,
    now: i64,
    fetched: bool,
) -> Result<Option<Value>, NotShown> {
    in_one(conn, || {
        Ok(match read_in(conn, identity, asked, now, fetched) {
            Err(NotShown::Failed(Failed::Error(e))) => return Err(e),
            done => done,
        })
    })?
}

fn read_in(
    conn: &Connection,
    identity: &NodeIdentity,
    asked: &ReadRequest,
    now: i64,
    fetched: bool,
) -> Result<Option<Value>, NotShown> {
    if stands(conn)? != Stands::Applied {
        return Err(NotShown::Refused(Refused::NotApplied));
    }
    let Some(agent) =
        agent_of(conn, &asked.folder).map_err(|e| PersonError::Held(e.to_string()))?
    else {
        return Err(NotShown::Refused(Refused::NotMapped));
    };
    let found = match (&asked.id, asked.next) {
        (Some(given), false) => {
            let prefix = given.to_ascii_lowercase();
            let mut of_it: Vec<Seen> = seen::shown_to(conn, identity, &agent, now)?
                .into_iter()
                .filter(|seen| hex::encode(seen.id).starts_with(&prefix))
                .collect();
            let own = match crate::messages::named(conn, identity, &agent, given, now, true)? {
                Ok(message) => Some(hex::encode(&message.id)),
                Err(Refused::MoreThanOne { ids, .. }) => ids.into_iter().next(),
                Err(_) => None,
            };
            if of_it.is_empty() {
                return Err(NotShown::Refused(Refused::NoSuchMessage(given.clone())));
            }
            if of_it.len() > 1 || own.is_some() {
                let mut ids: Vec<String> = of_it.iter().map(|seen| hex::encode(seen.id)).collect();
                ids.extend(own);
                return Err(NotShown::Refused(Refused::MoreThanOne {
                    id: given.clone(),
                    ids,
                }));
            }
            of_it.remove(0)
        }
        (None, true) => match seen::unread(conn, identity, &agent, now)?
            .into_iter()
            .next()
        {
            Some(seen) => seen,
            None => return Ok(None),
        },
        _ => {
            return Err(NotShown::Failed(Failed::Refused(Refusal {
                word: "",
                line: "Give a message's ID or --next-shared.".into(),
            })));
        }
    };
    let counting = who_counts(conn)?;
    let marks = seen::marks_now(conn, &counting)?;
    let its_own = marks.sent_by(&found.row.channel, &found.id, &agent);
    let mut list = None;
    if !its_own {
        seen::mark(
            conn,
            &shared_read_mark(&found.row.channel, &found.id, &agent),
            now,
        )?;
        list = seen::list_written(conn, identity, now, fetched, None)?;
    }
    let held = crate::person::held(conn)?.ok_or(PersonError::FollowsNoPhrase)?;
    let mut read_on = Vec::new();
    for key in marks.read_on(&found.row.channel, &found.id, &agent) {
        read_on.push(crate::reader::label_of(
            conn,
            &held.statement.statement,
            &key,
        )?);
    }
    let thread = thread_of(&found.message)?;
    let read_here = rows::read_by_a_person(conn, found.row.id).map_err(PersonError::Storage)?;
    let in_thread: Vec<Shown> = crate::shared::shown(conn, identity, &found.row.channel, now)?
        .into_iter()
        .filter(|message| thread_of(message).is_ok_and(|of| of == thread))
        .collect();
    let unread_by_a_person = in_thread
        .iter()
        .filter(|message| id_of(&message.id).is_ok_and(|id| !read_here.contains(&id)))
        .count();
    let mut answer = said_of(conn, identity, &held, &found.row, &found.message, now)?;
    answer["thread"] = hex::encode(thread).into();
    answer["thread_count"] = in_thread.len().into();
    answer["thread_unread_by_a_person"] = unread_by_a_person.into();
    answer["read_on"] = json!(read_on);
    answer["its_own"] = its_own.into();
    answer["listed"] = list.is_some().into();
    Ok(Some(answer))
}

/// What is said of a shown message of the channel of `row`: the channel's
/// name and words, the message's ID, its sender in the one fixed form, of
/// which kind, how long ago, and every field of it.
fn said_of(
    conn: &Connection,
    identity: &NodeIdentity,
    held: &crate::person::Held,
    row: &Channel,
    message: &Shown,
    now: i64,
) -> Result<Value, PersonError> {
    let own = identity.public_key();
    let counting = crate::person::Counting::of(
        &held.statement.statement,
        &cordelia_storage::person::additions(conn)?,
    );
    let kind = match message.signer {
        signer if signer == own => "this",
        signer if counting.counts(&signer) => "own",
        _ => "other",
    };
    let answers = (message.answers.iter().any(|b| *b != 0)).then(|| hex::encode(&message.answers));
    Ok(json!({
        "channel": row.name,
        "words": sharing::channel_words(&row.channel),
        "id": hex::encode(&message.id),
        "sender": sharing::sender_form(conn, held, &own, &message.signer)?,
        "kind": kind,
        "sent": message.sent,
        "ago_secs": now.saturating_sub(message.shown_at).max(0),
        "shown_at": message.shown_at,
        "answers": answers,
        "asks": message.asks,
        "link": message.link,
        "body": message.body,
        "reply_with": shell_word(&row.name),
    }))
}

/// A refusal of the sender's or of a lookup, as the route answers it:
/// what each line names is beside its word, the channel's name among it.
fn refusal_of(conn: &Connection, why: &Refused, name: &str) -> Result<HttpResponse, ApiError> {
    let shown = cleaned(name);
    let line = |line: String| Ok(refused_with(why.word(), &line, json!({ "channel": name })));
    match why {
        Refused::NotApplied => {
            let why_not = match stands(conn).map_err(crate::commands::refused)? {
                Stands::NoPhrase => "this device follows no recovery phrase yet",
                Stands::Stopped(state) => crate::look::short_why(state),
                Stands::Applied => crate::look::short_why(cordelia_storage::person::State::Applied),
            };
            Ok(refused_with(why.word(), "", json!({ "why": why_not })))
        }
        Refused::NoSuchChannel => line(format!("No shared channel of yours is named \"{shown}\".")),
        Refused::NotSubscribed => line(format!(
            "This agent does not subscribe to \"{shown}\", so it does not write there. A person \
             subscribes it with: cordelia subscribe {}",
            shell_word(name)
        )),
        Refused::NotReached => line(format!(
            "\"{shown}\" is held on this device but not reached from it: write there from a device \
             of yours that reaches its relays."
        )),
        Refused::ReplyElsewhere { id, channel: None } => line(format!(
            "Message {} came from your own agents: a reply goes to them with --to or --all, never \
             to a shared channel, so nothing was sent.",
            cleaned(id)
        )),
        Refused::ReplyElsewhere {
            id,
            channel: Some(channel),
        } => {
            let other = channel_name(conn, channel).map_err(crate::commands::refused)?;
            line(format!(
                "Message {} came from the shared channel \"{}\": a reply goes there only with \
                 --channel {}, so nothing was sent.",
                cleaned(id),
                cleaned(&other),
                shell_word(&other)
            ))
        }
        Refused::ChannelRate {
            sends,
            again,
            next_at,
        } => line(format!(
            "This device has written {sends} messages, and {again} again after a relay's answer, \
             in \"{shown}\" in the last hour: 60 in all, which is the most for one channel, so \
             nothing was sent. The next can go at {}.",
            time_of(*next_at)
        )),
        Refused::SharedHeld { .. } => line(format!(
            "Ten messages of this agent's in \"{shown}\", or answering it there, wait to be read \
             by a person on this device, so this agent writes no more there until a person reads \
             them with: cordelia msg log (at a terminal)"
        )),
        Refused::NotClean => line(crate::shared_anew::not_clean_line(name)),
        Refused::Paused {
            maker,
            made,
            left_out,
        } => {
            let form = match crate::person::held(conn).map_err(crate::commands::refused)? {
                Some(held) => sharing::sender_form(conn, &held, &[0; 32], maker)
                    .map_err(crate::commands::refused)?,
                None => format!("({})", sharing::six_words(maker)),
            };
            line(format!(
                "\"{shown}\" was made anew by {form} on {} without {left_out} keys, so your devices \
                 send nothing more there: move with cordelia shared move {word}, or go on there, \
                 where those keys read, with cordelia shared stay {word} (at a terminal).",
                sharing::date_of(i64::try_from(*made).unwrap_or(i64::MAX)),
                word = shell_word(name)
            ))
        }
        Refused::Moved { id, .. } => line(format!(
            "Message {} is from \"{shown}\" before it was made anew, and your devices moved: \
             answer in the new channel without --reply.",
            cleaned(id)
        )),
        Refused::FolderRate { limit, next_at } => Ok(refused_with(
            why.word(),
            "",
            json!({ "limit": limit, "next_at": next_at }),
        )),
        Refused::DeviceRate {
            sends,
            again,
            next_at,
        } => Ok(refused_with(
            why.word(),
            "",
            json!({ "sends": sends, "again": again, "next_at": next_at }),
        )),
        Refused::NoSuchMessage(id) | Refused::AsksNothing(id) | Refused::SignerRemoved(id) => {
            Ok(refused_with(why.word(), "", json!({ "id": id })))
        }
        Refused::MoreThanOne { id, ids } => Ok(refused_with(
            why.word(),
            "",
            json!({ "id": id, "ids": ids }),
        )),
        // The messages record's own lines, which the command words.
        _ => Ok(refused_with(why.word(), "", json!({}))),
    }
}

/// A time as a refusal says when the next can go.
fn time_of(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|at| at.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| unix.to_string())
}

// ── POST /api/v1/shared/read ─────────────────────────────────────────

/// `cordelia msg read <id>` of a shared message, and `msg read
/// --next-shared` (§5.1, §5.3). The command asks it first: where it answers
/// `no_such_message`, it asks the messages record's route.
pub async fn read(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ReadRequest>,
) -> Result<HttpResponse, ApiError> {
    crate::commands::asked(&req, &state)?;
    if let Some(id) = &body.id
        && !is_an_id(id)
    {
        return Err(ApiError::BadRequest(format!(
            "{id} is not a message's ID: give 8 to 32 of its hex characters"
        )));
    }
    let now = state.sync_control.now();
    let db = db(&state);
    crate::messages::lists_read(&db, &state);
    let fetched = sender::fetched(&db, &state.own_channels, Instant::now())
        .map_err(crate::commands::refused)?;
    match read_of(&db, &state.identity, &body, now, fetched) {
        Ok(Some(answer)) => {
            if answer["listed"] == true {
                state.own_channels.written();
            }
            Ok(HttpResponse::Ok().json(answer))
        }
        Ok(None) => Ok(HttpResponse::Ok().json(json!({ "nothing": true }))),
        Err(NotShown::Refused(why)) => refusal_of(&db, &why, ""),
        Err(NotShown::Failed(f)) => failed(f),
    }
}

// ── send ─────────────────────────────────────────────────────────────

/// What `send --channel` asks. It names a shared channel, and no agent of
/// the person's own: a field it does not know, `to` among them, is refused.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    pub folder: String,
    /// The name the person files the channel under.
    pub channel: String,
    #[serde(default)]
    pub words: Option<String>,
    /// 8 to 32 hex characters of the ID of the message it answers.
    #[serde(default)]
    pub reply: Option<String>,
    #[serde(default)]
    pub asks: bool,
    #[serde(default)]
    pub link: Option<String>,
    pub body: String,
}

/// What the node knows, besides its store, when it sends.
#[derive(Debug, Clone)]
pub struct SendAt {
    pub now: i64,
    pub no_place: bool,
    pub per_folder_per_hour: usize,
    pub own_relays: Vec<OwnRelay>,
}

/// Why a send was not made.
#[derive(Debug)]
pub enum NotSentHere {
    Refused(Refused, String),
    Failed(Failed),
    Asked(String),
}

impl From<Failed> for NotSentHere {
    fn from(f: Failed) -> Self {
        Self::Failed(f)
    }
}

impl From<PersonError> for NotSentHere {
    fn from(e: PersonError) -> Self {
        Self::Failed(Failed::Error(e))
    }
}

/// `send --channel`: the agent of `folder` sends into the shared channel
/// the person files as `channel`, at `at` (§4.2, §5.2, §5.4), through the
/// one function that sends with `Address::Shared`. `fetched` says whether
/// a channel was fetched since the node started at `reached` of its relays.
/// Returns the message's ID, the channel's name, and the lines of §5.4.
pub fn send_of(
    conn: &Connection,
    identity: &NodeIdentity,
    asked: &SendRequest,
    at: &SendAt,
    fetched: impl Fn(&[u8; 32], usize) -> bool,
) -> Result<(String, String, Vec<String>), NotSentHere> {
    if let Some(reply) = &asked.reply
        && !is_an_id(reply)
    {
        return Err(NotSentHere::Asked(format!(
            "{reply} is not a message's ID: give 8 to 32 of its hex characters"
        )));
    }
    if let Some(link) = &asked.link
        && !is_a_link(link)
    {
        return Err(NotSentHere::Asked(format!(
            "{link} is not a link of the form owner/repo#number"
        )));
    }
    if asked.body.len() > AGENT_MESSAGE_BODY_MAX_BYTES || asked.body.is_empty() {
        return Err(NotSentHere::Asked(
            "the message is empty or too large".into(),
        ));
    }
    let held = sharing::standing(conn)?;
    let agent = agent_of(conn, &asked.folder).map_err(|e| PersonError::Held(e.to_string()))?;
    let Some(agent) = agent else {
        return Err(NotSentHere::Refused(
            Refused::NotMapped,
            asked.channel.clone(),
        ));
    };
    let filing = sharing::find(conn, &asked.channel, asked.words.as_deref(), None)?;
    let channel = filing.channel;
    let reached_count = kept::channel(conn, &channel)
        .map_err(PersonError::Storage)?
        .filter(|row| row.state == State::Held)
        .map(|row| card_of(&row).map(|card| reached(&at.own_relays, &card)))
        .transpose()?
        .unwrap_or(0);
    // What this device saw of who wrote there, since this folder last
    // wrote there.
    let wrote = sharing::who_wrote(
        conn,
        &held,
        &identity.public_key(),
        &channel,
        &filing.name,
        Some(&agent),
    )?;
    let sends_at = At {
        now: at.now,
        fetched: true,
        no_place: at.no_place,
        mapped: true,
        per_folder_per_hour: at.per_folder_per_hour,
        shared_fetched: fetched(&channel, reached_count),
        shared_reached: reached_count > 0,
    };
    let request = Request {
        from: agent.clone(),
        address: Address::Shared(channel),
        asks: asked.asks,
        link: asked.link.clone(),
        body: asked.body.clone(),
        thread: [0; AGENT_MESSAGE_ID_BYTES],
        answers: [0; AGENT_MESSAGE_ID_BYTES],
    };
    // A reply is looked up in this channel alone.
    let reply = |conn: &Connection| match &asked.reply {
        Some(given) => answering(conn, identity, &agent, &channel, given, at.now),
        None => Ok(None),
    };
    match sender::send(conn, identity, &sends_at, &request, reply) {
        Ok(sent) => Ok((hex::encode(sent.id), filing.name, wrote)),
        Err(NotSent::Refused(why)) => Err(NotSentHere::Refused(why, filing.name)),
        Err(NotSent::NotAMessage(why)) => Err(NotSentHere::Asked(why.to_string())),
        Err(NotSent::Failed(e)) => Err(e.into()),
    }
}

/// The lookup of the message a reply answers, in the shared channel
/// `channel` alone (§4.2): among the messages there that the agent of
/// `agent` may be shown, the one `given` begins; refused where it begins
/// none (the sender then says where it is), more than one, or one that
/// asks for nothing.
fn answering(
    conn: &Connection,
    identity: &NodeIdentity,
    agent: &str,
    channel: &[u8; 32],
    given: &str,
    now: i64,
) -> Result<Option<Reply>, Refused> {
    let prefix = given.to_ascii_lowercase();
    let mut found: Vec<Seen> = match seen::shown_to(conn, identity, agent, now) {
        Ok(found) => found,
        Err(_) => return Err(Refused::NoSuchMessage(given.into())),
    };
    found.retain(|seen| seen.row.channel == *channel && hex::encode(seen.id).starts_with(&prefix));
    let message = match found.len() {
        0 => return Err(Refused::NoSuchMessage(given.into())),
        1 => found.remove(0),
        _ => {
            return Err(Refused::MoreThanOne {
                id: given.into(),
                ids: found.iter().map(|seen| hex::encode(seen.id)).collect(),
            });
        }
    };
    if !message.message.asks {
        return Err(Refused::AsksNothing(given.into()));
    }
    let thread = thread_of(&message.message).map_err(|_| Refused::NoSuchMessage(given.into()))?;
    Ok(Some(Reply {
        to: Address::Shared(*channel),
        thread,
        answers: message.id,
    }))
}

// ── POST /api/v1/shared/send ─────────────────────────────────────────

/// `cordelia msg send --channel <name>` (§4.2, §5.2, §5.4).
pub async fn send(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SendRequest>,
) -> Result<HttpResponse, ApiError> {
    crate::commands::asked(&req, &state)?;
    let at = SendAt {
        now: state.sync_control.now(),
        no_place: state.own_channels.no_place(),
        per_folder_per_hour: state.own_channels.per_folder_per_hour(),
        own_relays: sharing::own_relays(&state),
    };
    let fetched = |channel: &[u8; 32], reached: usize| {
        state
            .own_channels
            .shared_fetch_done(channel, reached, Instant::now())
    };
    let db = db(&state);
    crate::messages::lists_read(&db, &state);
    match send_of(&db, &state.identity, &body, &at, fetched) {
        Ok((id, name, wrote)) => {
            state.own_channels.written();
            Ok(HttpResponse::Ok().json(json!({ "id": id, "channel": name, "wrote": wrote })))
        }
        Err(NotSentHere::Refused(why, name)) => refusal_of(&db, &why, &name),
        Err(NotSentHere::Failed(f)) => failed(f),
        Err(NotSentHere::Asked(says)) => Err(ApiError::BadRequest(says)),
    }
}

// ── POST /api/v1/shared/summary ──────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryRequest {
    pub folder: String,
    pub within_ms: u64,
    pub version: String,
}

/// The count of §5.3: the messages unread by the agent of `folder` in the
/// shared channels it subscribes to, with a place. `None` where it prints
/// nothing: the folder is not mapped, sync is off, the device does not
/// stand applied, or nothing is unread.
pub fn summary_of(
    conn: &Connection,
    identity: &NodeIdentity,
    folder: &str,
    now: i64,
) -> Result<Option<usize>, PersonError> {
    in_one(conn, || {
        let Some(agent) = agent_of(conn, folder).map_err(|e| PersonError::Held(e.to_string()))?
        else {
            return Ok(None);
        };
        if crate::shared_pass::may_open(conn)?.is_err() {
            return Ok(None);
        }
        let count = seen::unread(conn, identity, &agent, now)?.len();
        Ok((count > 0).then_some(count))
    })
}

/// `cordelia msg summary`'s count of shared channels (§5.3): asked after
/// the messages record's route, within what is left of the 100 ms. It
/// answers nothing, never a refusal, wherever the command prints nothing.
pub async fn summary(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SummaryRequest>,
) -> Result<HttpResponse, ApiError> {
    let deadline =
        Instant::now() + Duration::from_millis(body.within_ms.min(AGENT_MESSAGE_SUMMARY_WAIT_MS));
    match crate::commands::asked(&req, &state) {
        Ok(()) => {}
        Err(ApiError::Unauthorized) => return Err(ApiError::Unauthorized),
        Err(_) => return Ok(HttpResponse::NoContent().finish()),
    }
    if body.version != env!("CARGO_PKG_VERSION") {
        return Ok(HttpResponse::NoContent().finish());
    }
    let pause = || actix_web::rt::time::sleep(Duration::from_millis(1));
    let Some(db) = state.db.try_lock_until(deadline, pause).await else {
        return Ok(HttpResponse::NoContent().finish());
    };
    let now = state.sync_control.now();
    match summary_of(&db, &state.identity, &body.folder, now) {
        Ok(Some(count)) => Ok(HttpResponse::Ok().json(json!({ "count": count }))),
        _ => Ok(HttpResponse::NoContent().finish()),
    }
}

// ── log ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogRequest {
    /// The folder the command was run in, where it is not at a terminal.
    #[serde(default)]
    pub folder: Option<String>,
    /// Whether its input and its output are both terminals: only then are
    /// bodies answered.
    #[serde(default)]
    pub terminal: bool,
    /// The shared messages to mark read by a person here: those the
    /// command printed, each as the channel's ID and the message's ID, in
    /// hex.
    #[serde(default)]
    pub mark: Vec<(String, String)>,
}

/// `log`'s shared channels at `now` (§5.1, §6.3, §6.4), in one write. At a
/// terminal (`terminal`, no folder), every shared channel held, each with
/// its name, words and relays, its keys, those refused for room, what is
/// held back and counted, the hold of each agent that subscribes, and each
/// message that no person here has read, with what it says. Anywhere else,
/// of the channels the folder's agent subscribes to, each message's ID,
/// sender form and shown time, and nothing more. The messages of `mark`
/// that it lists are marked read by a person here, on this device alone:
/// a shared message's ID never goes into the `person/` list (§6.1).
pub fn log_of(
    conn: &Connection,
    identity: &NodeIdentity,
    asked: &LogRequest,
    own_relays: &[OwnRelay],
    now: i64,
) -> Result<Value, NotShown> {
    in_one(conn, || {
        Ok(match log_in(conn, identity, asked, own_relays, now) {
            Err(NotShown::Failed(Failed::Error(e))) => return Err(e),
            done => done,
        })
    })?
}

fn log_in(
    conn: &Connection,
    identity: &NodeIdentity,
    asked: &LogRequest,
    own_relays: &[OwnRelay],
    now: i64,
) -> Result<Value, NotShown> {
    if stands(conn)? != Stands::Applied {
        return Err(NotShown::Refused(Refused::NotApplied));
    }
    let agent = match &asked.folder {
        Some(folder) => {
            match agent_of(conn, folder).map_err(|e| PersonError::Held(e.to_string()))? {
                Some(agent) => Some(agent),
                None => return Err(NotShown::Refused(Refused::NotMapped)),
            }
        }
        None => None,
    };
    let held = crate::person::held(conn)?.ok_or(PersonError::FollowsNoPhrase)?;
    let own = identity.public_key();
    let rows_held: Vec<(Channel, Option<i64>)> = match &agent {
        Some(agent) => seen::subscribed_by(conn, agent)?
            .into_iter()
            .map(|(row, start)| (row, Some(start)))
            .collect(),
        None => kept::channels(conn)
            .map_err(PersonError::Storage)?
            .into_iter()
            .filter(|row| row.state == State::Held)
            .map(|row| (row, None))
            .collect(),
    };
    let at_a_terminal = asked.terminal && agent.is_none();
    let mut marked = 0;
    let mut channels = Vec::new();
    for (row, start) in rows_held {
        let shown = crate::shared::shown(conn, identity, &row.channel, now)?;
        for (channel, id) in &asked.mark {
            if *channel != hex::encode(row.channel) {
                continue;
            }
            let Some(id) = hex::decode(id).ok().and_then(|id| id_of(&id).ok()) else {
                continue;
            };
            if shown.iter().any(|message| message.id[..] == id[..])
                && rows::mark_read_by_a_person(conn, row.id, &id).map_err(PersonError::Storage)?
            {
                marked += 1;
            }
        }
        let read_here = rows::read_by_a_person(conn, row.id).map_err(PersonError::Storage)?;
        let mut messages = Vec::new();
        for message in &shown {
            if start.is_some_and(|start| message.shown_at < start || message.first_held < start) {
                continue;
            }
            let id = id_of(&message.id)?;
            if at_a_terminal && read_here.contains(&id) {
                continue;
            }
            let mut said = json!({
                "id": hex::encode(id),
                "sender": sharing::sender_form(conn, &held, &own, &message.signer)?,
                "ago_secs": now.saturating_sub(message.shown_at).max(0),
                "shown_at": message.shown_at,
            });
            if at_a_terminal {
                let full = said_of(conn, identity, &held, &row, message, now)?;
                for field in ["kind", "asks", "link", "body", "answers"] {
                    said[field] = full[field].clone();
                }
                said["thread"] = hex::encode(thread_of(message)?).into();
            }
            messages.push(said);
        }
        let mut entry = json!({
            "id": hex::encode(row.channel),
            "name": row.name,
            "words": sharing::channel_words(&row.channel),
            "messages": messages,
        });
        if at_a_terminal {
            let card = card_of(&row)?;
            let relays: Vec<String> = card
                .relays()
                .keys()
                .iter()
                .map(|key| sharing::relay_shown(own_relays, key))
                .collect();
            entry["relays"] = json!(relays);
            let labels: Vec<[u8; 32]> = crate::lists::holds(conn)?
                .labels
                .iter()
                .filter(|(act, _)| act.item.label.is_some())
                .map(|(act, _)| act.item.key)
                .collect();
            let mut keys = Vec::new();
            let mut refused = Vec::new();
            let mut held_back = Vec::new();
            let mut not_messages = Vec::new();
            for key in kept::keys(conn, row.id).map_err(PersonError::Storage)? {
                if key.key == own {
                    continue;
                }
                let form = sharing::sender_form(conn, &held, &own, &key.key)?;
                if let Some(first) = key.first_held {
                    keys.push(json!({
                        "form": form,
                        "labelled": labels.contains(&key.key),
                        "first_held": sharing::date_of(first),
                    }));
                }
                if let Some(first) = key.first_refused {
                    refused.push(json!({
                        "form": form,
                        "key": encode_public_key(&key.key).map_err(PersonError::from)?,
                        "first_refused": sharing::date_of(first),
                        "bytes": key.bytes_refused,
                    }));
                }
                let back =
                    kept::held_back(conn, row.id, &key.key, now).map_err(PersonError::Storage)?;
                if back > 0 {
                    held_back.push(json!({ "form": form, "count": back }));
                }
                if let Some(signer) =
                    kept::signer(conn, row.id, &key.key).map_err(PersonError::Storage)?
                    && signer.not_messages > 0
                {
                    not_messages.push(json!({ "form": form, "count": signer.not_messages }));
                }
            }
            entry["keys"] = json!(keys);
            entry["refused"] = json!(refused);
            entry["held_back"] = json!(held_back);
            entry["not_messages"] = json!(not_messages);
            let mut holds = Vec::new();
            for (channel, agent) in seen::in_force(conn)? {
                if channel == row.channel
                    && seen::held(conn, identity, &row, &agent, now)?
                        >= cordelia_core::protocol::AGENT_MESSAGE_PAIR_UNREAD_MAX as u64
                {
                    holds.push(agent);
                }
            }
            entry["held"] = json!(holds);
            entry["anew"] = json!(crate::shared_anew::log_lines(conn, identity, &row, now)?);
        }
        channels.push(entry);
    }
    Ok(json!({ "channels": channels, "marked": marked }))
}

/// `cordelia msg log`'s shared channels (§5.1): asked after the messages
/// record's route.
pub async fn log(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<LogRequest>,
) -> Result<HttpResponse, ApiError> {
    crate::commands::asked(&req, &state)?;
    let own_relays = sharing::own_relays(&state);
    let now = state.sync_control.now();
    let db = db(&state);
    crate::messages::lists_read(&db, &state);
    match log_of(&db, &state.identity, &body, &own_relays, now) {
        Ok(answer) => Ok(HttpResponse::Ok().json(answer)),
        Err(NotShown::Refused(why)) => refusal_of(&db, &why, ""),
        Err(NotShown::Failed(f)) => failed(f),
    }
}

#[cfg(test)]
mod tests;
