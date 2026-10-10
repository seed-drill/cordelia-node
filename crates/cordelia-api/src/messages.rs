//! The local API of messages between the person's own agents (decision
//! 2026-10-09 §4.2): the routes behind `cordelia msg summary`, `msg read`
//! and `msg send`, each a POST with a JSON body, each behind the node's
//! token.
//!
//! The node does every check of §4.3 that is not the command's alone, in
//! the record's order, and answers a refusal by its word; the command
//! prints the line. The frame, the escapes, the cutting of names and the
//! quoting are the command's (`cordelia-node/src/msg_cmd.rs`), from what
//! the node answers. The subject is cut here too, so that `summary`
//! answers small.
//!
//! - **The agent of a folder** ([`agent_of`], §3.1): the command works out
//!   the directory and sends it as `folder`; the node takes it through the
//!   same tidying that a mapping was stored through, and compares it, byte
//!   for byte, with each mapping's folder.
//! - **`summary`** ([`summary_of`], §4.1, C5, C20) reads only the index and
//!   the marks: it opens no entry. It answers nothing where anything is
//!   not as it should be, and nothing where it cannot have the store
//!   within the time the command gives it.
//! - **`read`** ([`read_of`]) gives places, finds the one message an ID
//!   names ([`named`]), and marks it read by the folder's agent.
//! - **`send`** ([`send_of`]) gives [`sender::send`] what it needs, and the
//!   lookup of the message a reply answers ([`answering`]), which it calls
//!   at step 9.
//!
//! **Text that another device chose** is cleaned by one function
//! ([`cleaned`]): the set of §4.1, seven Unicode general categories and
//! the characters that render as nothing, is taken out of a name, a label, a subject and a link, and a body's are shown
//! as escapes by the command ([`taken_out`]).

use std::cell::RefCell;
use std::time::{Duration, Instant};

use actix_web::{HttpRequest, HttpResponse, web};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{Value, json};

use cordelia_core::protocol::{
    AGENT_MESSAGE_BODY_MAX_BYTES, AGENT_MESSAGE_ID_BYTES, AGENT_MESSAGE_ID_SHOWN_CHARS,
    AGENT_MESSAGE_SUBJECT_CHARS, AGENT_MESSAGE_SUMMARY_LINES, AGENT_MESSAGE_SUMMARY_WAIT_MS,
};
use cordelia_crypto::fingerprint;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::message::{To, is_a_link};
use cordelia_storage::StorageError;
use cordelia_storage::messages::{self as held, Id, Shown};
use cordelia_storage::meta;

use crate::at_relays::{Stands, messages_channel, stands};
use crate::commands::{asked, refused};
use crate::error::ApiError;
use crate::marks;
use crate::person::{PersonError, in_one, who_counts};
use crate::publish::Standing;
use crate::sender::{self, At, NotSent, Refused, Reply, Request};
use crate::state::{AppState, OwnChannels};

// ── Text that another device chose ───────────────────────────────────

/// The code points of the Unicode property Default_Ignorable_Code_Point,
/// first and last of each range, from `DerivedCoreProperties.txt` of
/// Unicode 16.0, the version of the crate `unicode-general-category`
/// (decision 2026-10-09 §4.1). Each renders as nothing.
const DEFAULT_IGNORABLE: [(char, char); 17] = [
    ('\u{00ad}', '\u{00ad}'),
    ('\u{034f}', '\u{034f}'),
    ('\u{061c}', '\u{061c}'),
    ('\u{115f}', '\u{1160}'),
    ('\u{17b4}', '\u{17b5}'),
    ('\u{180b}', '\u{180f}'),
    ('\u{200b}', '\u{200f}'),
    ('\u{202a}', '\u{202e}'),
    ('\u{2060}', '\u{206f}'),
    ('\u{3164}', '\u{3164}'),
    ('\u{fe00}', '\u{fe0f}'),
    ('\u{feff}', '\u{feff}'),
    ('\u{ffa0}', '\u{ffa0}'),
    ('\u{fff0}', '\u{fff8}'),
    ('\u{1bca0}', '\u{1bca3}'),
    ('\u{1d173}', '\u{1d17a}'),
    ('\u{e0000}', '\u{e0fff}'),
];

/// The braille pattern blank (So), which shows as a space and is none.
const BRAILLE_BLANK: char = '\u{2800}';

/// Whether `c` is of the set that a command takes out of text another
/// device chose, and shows as an escape in a body (decision 2026-10-09
/// §4.1, C4): the seven Unicode general categories Cc, Cf, Co, Cn, Cs, Zl
/// and Zp; and every code point that renders as nothing
/// ([`DEFAULT_IGNORABLE`]), and U+2800. The categories are those of the
/// table the build uses: a character that a later version of Unicode
/// assigns is unassigned here, and taken out.
pub fn taken_out(c: char) -> bool {
    use unicode_general_category::{GeneralCategory as Category, get_general_category};
    matches!(
        get_general_category(c),
        Category::Control
            | Category::Format
            | Category::PrivateUse
            | Category::Unassigned
            | Category::Surrogate
            | Category::LineSeparator
            | Category::ParagraphSeparator
    ) || DEFAULT_IGNORABLE
        .iter()
        .any(|(first, last)| (*first..=*last).contains(&c))
        || c == BRAILLE_BLANK
}

/// `text` with every character of the set taken out
/// ([`taken_out`]): a name, a label, a subject or a link, wherever a
/// command prints one.
pub fn cleaned(text: &str) -> String {
    text.chars().filter(|c| !taken_out(*c)).collect()
}

/// The first `most` Unicode scalar values of `text`, and whether there
/// were more.
pub fn cut(text: &str, most: usize) -> (String, bool) {
    match text.char_indices().nth(most) {
        Some((at, _)) => (text[..at].to_string(), true),
        None => (text.to_string(), false),
    }
}

/// A message's subject as `summary` answers it: the body's first line,
/// cleaned, and cut to 80 Unicode scalar values, with whether it was cut
/// (decision 2026-10-09 §2.2, §4.1).
pub fn subject_of(body: &str) -> (String, bool) {
    let first = body.split('\n').next().unwrap_or_default();
    cut(&cleaned(first), AGENT_MESSAGE_SUBJECT_CHARS)
}

// ── The agent of a folder ────────────────────────────────────────────

/// The agent of `folder`, the directory a command worked out (decision
/// 2026-10-09 §3.1, C19): the name of the mapping whose folder is the
/// same, byte for byte, once `folder` is tidied as a mapping was when it
/// was stored. `None` where the folder is not mapped.
pub fn agent_of(conn: &Connection, folder: &str) -> Result<Option<String>, ApiError> {
    let Some(folder) = crate::sync::clean_path(folder) else {
        return Ok(None);
    };
    Ok(crate::sync::mappings(conn)?
        .into_iter()
        .find(|mapping| mapping.folder == folder)
        .map(|mapping| mapping.name))
}

// ── The message an ID names ──────────────────────────────────────────

/// Whether `given` has the form of a message's ID as a command takes it:
/// 8 to 32 hex characters (decision 2026-10-09 §4.1).
pub fn is_an_id(given: &str) -> bool {
    (AGENT_MESSAGE_ID_SHOWN_CHARS..=2 * AGENT_MESSAGE_ID_BYTES).contains(&given.len())
        && given.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether `message` is one that the agent of `name` on the device whose
/// key is `own` may be shown (decision 2026-10-09 §3, §4.1): addressed to
/// its name or to every name and not one it sent here, or, where
/// `sent_too`, one it sent here.
fn may_read(message: &Shown, own: &[u8; 32], name: &str, sent_too: bool) -> bool {
    let its_own = message.signer[..] == own[..] && message.from == name;
    let to_it = message.to.as_deref().is_none_or(|to| to == name);
    (to_it && !its_own) || (sent_too && its_own)
}

/// The one message shown at `now` whose ID begins with `given` among those
/// the agent of `name` may read (decision 2026-10-09 §4.1, §4.3 step 9):
/// for `read` those it sent here too (`sent_too`), and for a reply those
/// addressed to it alone. Refused, in this order: no such message; more
/// than one; its signer no longer counts.
pub fn named(
    conn: &Connection,
    identity: &NodeIdentity,
    name: &str,
    given: &str,
    now: i64,
    sent_too: bool,
) -> Result<Result<Shown, Refused>, PersonError> {
    let own = identity.public_key();
    let prefix = given.to_ascii_lowercase();
    let mut found: Vec<Shown> = kept(held::shown(conn, now))?
        .into_iter()
        .filter(|message| may_read(message, &own, name, sent_too))
        .filter(|message| hex::encode(&message.id).starts_with(&prefix))
        .collect();
    let message = match found.len() {
        0 => return Ok(Err(Refused::NoSuchMessage(given.to_string()))),
        1 => found.remove(0),
        _ => {
            return Ok(Err(Refused::MoreThanOne {
                id: given.to_string(),
                ids: found
                    .iter()
                    .map(|message| hex::encode(&message.id))
                    .collect(),
            }));
        }
    };
    let signer = key_of(&message.signer)?;
    if !who_counts(conn)?.counts(&signer) {
        return Ok(Err(Refused::SignerRemoved(given.to_string())));
    }
    Ok(Ok(message))
}

/// The lookup of the message a reply answers, at step 9 of §4.3 (decision
/// 2026-10-09 §3, C7): among the messages addressed to the agent of
/// `name`, the one `given` names ([`named`]); refused where it asks for
/// nothing. The reply goes to that message's `from`, in its thread, or in
/// the thread that message begins, and answers it: the node sets those,
/// whatever the request said.
pub fn answering(
    conn: &Connection,
    identity: &NodeIdentity,
    name: &str,
    given: &str,
    now: i64,
) -> Result<Option<Reply>, Refused> {
    let message = match named(conn, identity, name, given, now, false) {
        Ok(Ok(message)) => message,
        Ok(Err(why)) => return Err(why),
        // What the store could not read names no message.
        Err(_) => return Err(Refused::NoSuchMessage(given.to_string())),
    };
    if !message.asks {
        return Err(Refused::AsksNothing(given.to_string()));
    }
    let id = id_of(&message.id).map_err(|_| Refused::NoSuchMessage(given.to_string()))?;
    let thread = match id_of(&message.thread) {
        Ok(thread) if thread != [0; AGENT_MESSAGE_ID_BYTES] => thread,
        _ => id,
    };
    Ok(Some(Reply {
        to: To::Name(message.from),
        thread,
        answers: id,
    }))
}

// ── summary ──────────────────────────────────────────────────────────

/// One line of a summary (decision 2026-10-09 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub id: Id,
    pub from: String,
    /// The label the device knows the signer by, or `None` where it is
    /// this device.
    pub label: Option<String>,
    /// How long before the node's clock its shown time was, in seconds.
    pub ago_secs: i64,
    /// The body's first line, cleaned and cut ([`subject_of`]).
    pub subject: String,
    pub subject_cut: bool,
}

/// What `summary` answers (decision 2026-10-09 §4.1, §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// The folder's agent.
    pub name: String,
    /// At most five messages, the oldest first, each announced once.
    pub lines: Vec<Line>,
    /// Every other message that waits for the agent, the oldest first.
    pub waiting: Vec<Id>,
}

/// The summary of the agent of `folder` at `now` by the node's clock
/// (decision 2026-10-09 §4.1, C5, C6), in one write: places are given,
/// and each message whose line it answers is marked announced to that
/// agent on this device. **It opens no entry:** it reads the index and
/// the marks. `None` where it prints nothing: the folder is not mapped,
/// sync is off, the device does not stand applied or has no place for
/// messages, or nothing is unread.
///
/// The lines are of messages to the agent's name, unread by an agent of
/// that name (§7.2), not yet announced to it here, from a signer that
/// counts: at most five, the oldest first. The rest waits in the count:
/// those announced before, every message to every name, whose subject
/// `summary` never prints, and what is beyond the five.
pub fn summary_of(
    conn: &Connection,
    identity: &NodeIdentity,
    own_channels: &OwnChannels,
    folder: &str,
    now: i64,
) -> Result<Option<Summary>, PersonError> {
    in_one(conn, || {
        let Some(name) = agent_of(conn, folder).map_err(said)? else {
            return Ok(None);
        };
        if meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_none()
            || stands(conn)? != Stands::Applied
            || own_channels.no_place()
        {
            return Ok(None);
        }
        let own = identity.public_key();
        kept(held::give_places(conn, &own, now))?;
        let counting = who_counts(conn)?;
        let mut lines = Vec::new();
        let mut waiting = Vec::new();
        for message in marks::unread(conn, identity, &name, now)? {
            let id = id_of(&message.id)?;
            if !counting.counts(&key_of(&message.signer)?) {
                continue;
            }
            let new = message.to.is_some()
                && lines.len() < AGENT_MESSAGE_SUMMARY_LINES
                && !kept(held::is_announced(conn, &id, &name))?;
            if !new {
                waiting.push(id);
                continue;
            }
            kept(held::announce(conn, &id, &name))?;
            let (subject, subject_cut) = subject_of(&message.body);
            lines.push(Line {
                id,
                from: message.from,
                label: (message.signer[..] != own[..]).then_some(message.label),
                ago_secs: now.saturating_sub(message.shown_at).max(0),
                subject,
                subject_cut,
            });
        }
        if lines.is_empty() && waiting.is_empty() {
            return Ok(None);
        }
        Ok(Some(Summary {
            name,
            lines,
            waiting,
        }))
    })
}

impl Summary {
    /// As the route answers it: each ID whole, and the oldest five of
    /// those that wait, with how many wait.
    pub fn answered(&self) -> Value {
        let lines: Vec<Value> = self
            .lines
            .iter()
            .map(|line| {
                let device = match &line.label {
                    Some(label) => json!({ "label": label }),
                    None => json!("this"),
                };
                json!({
                    "id": hex::encode(line.id),
                    "from": line.from,
                    "device": device,
                    "ago_secs": line.ago_secs,
                    "subject": line.subject,
                    "subject_cut": line.subject_cut,
                })
            })
            .collect();
        let oldest: Vec<String> = self
            .waiting
            .iter()
            .take(AGENT_MESSAGE_SUMMARY_LINES)
            .map(hex::encode)
            .collect();
        json!({
            "name": self.name,
            "lines": lines,
            "waiting": { "count": self.waiting.len(), "ids": oldest },
        })
    }
}

#[derive(Deserialize)]
pub struct SummaryRequest {
    /// The directory the command worked out (§3.1).
    pub folder: String,
    /// How long the command waits for the answer, from when it sent it.
    pub within_ms: u64,
    /// The command's version: a node of another answers nothing.
    pub version: String,
}

/// What the store's lock is tried for, at most: the command's time left,
/// within the summary's own (decision 2026-10-09 §4.1, C20).
fn summary_wait(within_ms: u64) -> Duration {
    Duration::from_millis(within_ms.min(AGENT_MESSAGE_SUMMARY_WAIT_MS))
}

/// The store, where its lock is had before `deadline`: tried until then,
/// and `None` where it was not. Time spent waiting counts as no answer.
/// It waits without holding the worker, which serves other requests
/// meanwhile.
async fn db_by(
    state: &AppState,
    deadline: Instant,
) -> Option<std::sync::MutexGuard<'_, Connection>> {
    loop {
        match state.db.try_lock() {
            Ok(db) => return Some(db),
            Err(std::sync::TryLockError::Poisoned(e)) => return Some(e.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) if Instant::now() < deadline => {
                actix_web::rt::time::sleep(Duration::from_millis(1)).await;
            }
            Err(std::sync::TryLockError::WouldBlock) => return None,
        }
    }
}

/// Nothing: what `summary` answers wherever it prints nothing.
fn nothing() -> HttpResponse {
    HttpResponse::NoContent().finish()
}

// ── POST /api/v1/messages/summary ────────────────────────────────────

/// `cordelia msg summary` (decision 2026-10-09 §4.1, §4.2). It answers
/// nothing, not a refusal, wherever the command would print nothing: the
/// node is held up, the request is of another version, the store's lock
/// is not had within `within_ms`, or [`summary_of`] has nothing.
pub async fn summary(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SummaryRequest>,
) -> Result<HttpResponse, ApiError> {
    let deadline = Instant::now() + summary_wait(body.within_ms);
    match asked(&req, &state) {
        Ok(()) => {}
        Err(ApiError::Unauthorized) => return Err(ApiError::Unauthorized),
        Err(_) => return Ok(nothing()),
    }
    if body.version != env!("CARGO_PKG_VERSION") {
        return Ok(nothing());
    }
    let Some(db) = db_by(&state, deadline).await else {
        return Ok(nothing());
    };
    let now = state.sync_control.now();
    match summary_of(&db, &state.identity, &state.own_channels, &body.folder, now) {
        Ok(Some(summary)) => Ok(HttpResponse::Ok().json(summary.answered())),
        _ => Ok(nothing()),
    }
}

// ── read ─────────────────────────────────────────────────────────────

/// What `read` shows of a message (decision 2026-10-09 §4.1, §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readout {
    /// The folder's agent.
    pub name: String,
    pub message: Shown,
    /// The fingerprint's words of the signer, as a device is shown.
    pub fingerprint: String,
    /// The signer is this device.
    pub this_device: bool,
    /// The agent is reading what it sent here: neither line on answering
    /// is printed.
    pub its_own: bool,
    /// The messages between the two sides of its pair that are shown
    /// here, and how many of them no person has read here.
    pub pair_count: usize,
    pub pair_unread_by_a_person: usize,
    /// The labels of the devices whose lists say that an agent of this
    /// name read it.
    pub read_on: Vec<String>,
    /// It is of a generation before the one the device stands under.
    pub before_the_last_change: bool,
    /// How long before the node's clock its shown time was, in seconds.
    pub ago_secs: i64,
}

/// Why `read` shows nothing.
#[derive(Debug)]
pub enum NotRead {
    Refused(Refused),
    Failed(PersonError),
}

impl From<PersonError> for NotRead {
    fn from(e: PersonError) -> Self {
        Self::Failed(e)
    }
}

/// The two sides of the pair a message is of (decision 2026-10-09 §6): its
/// sender's name and its recipient's, in order, or its sender's and all.
fn pair_of(message: &Shown) -> (String, Option<String>) {
    match &message.to {
        None => (message.from.clone(), None),
        Some(to) if *to < message.from => (to.clone(), Some(message.from.clone())),
        Some(to) => (message.from.clone(), Some(to.clone())),
    }
}

/// `read`: the agent of `folder` reads the message that `given` names, at
/// `now` by the node's clock (decision 2026-10-09 §4.1, §4.3, §7.2), in
/// one write. The checks are made in the record's order: the device (step
/// 4), the folder (step 7), the message (step 9). Places are given first,
/// as at every show. Where the message is addressed to the agent, and is
/// not its own, it is marked read by that agent here, and the device's
/// list is written again where it may be (`fetched`). It works with sync
/// off.
pub fn read_of(
    conn: &Connection,
    identity: &NodeIdentity,
    folder: &str,
    given: &str,
    now: i64,
    fetched: bool,
) -> Result<(Readout, Option<u64>), NotRead> {
    in_one(conn, || {
        Ok(match read_in(conn, identity, folder, given, now, fetched) {
            Err(NotRead::Failed(e)) => return Err(e),
            done => done,
        })
    })?
}

fn read_in(
    conn: &Connection,
    identity: &NodeIdentity,
    folder: &str,
    given: &str,
    now: i64,
    fetched: bool,
) -> Result<(Readout, Option<u64>), NotRead> {
    if stands(conn)? != Stands::Applied {
        return Err(NotRead::Refused(Refused::NotApplied));
    }
    let Some(name) = agent_of(conn, folder).map_err(said)? else {
        return Err(NotRead::Refused(Refused::NotMapped));
    };
    let own = identity.public_key();
    kept(held::give_places(conn, &own, now))?;
    let message = named(conn, identity, &name, given, now, true)?.map_err(NotRead::Refused)?;
    let id = id_of(&message.id)?;
    let signer = key_of(&message.signer)?;
    let marked = marks::read_here(conn, identity, &name, &id, now, fetched)?;

    let pair = pair_of(&message);
    let shown = kept(held::shown(conn, now))?;
    let mut pair_count = 0;
    let mut pair_unread_by_a_person = 0;
    for other in shown.iter().filter(|other| pair_of(other) == pair) {
        pair_count += 1;
        if !kept(held::is_read_by_a_person(conn, &id_of(&other.id)?))? {
            pair_unread_by_a_person += 1;
        }
    }
    let standing = Standing::of(conn)?;
    let statement = &standing.held.statement.statement;
    let mut read_on = Vec::new();
    // A device keeps no list of its own beside its table: every key here
    // is another device's.
    for key in marks::read_on(conn, &id, &name)?.devices {
        read_on.push(crate::reader::label_of(conn, statement, &key)?);
    }
    let current = match messages_channel(conn)? {
        Some(channel) => kept(held::generation_of(conn, &channel))?,
        None => None,
    };
    Ok((
        Readout {
            name: name.clone(),
            fingerprint: fingerprint::shown(&signer),
            this_device: signer == own,
            its_own: signer == own && message.from == name,
            pair_count,
            pair_unread_by_a_person,
            read_on,
            before_the_last_change: current != Some(message.generation),
            ago_secs: now.saturating_sub(message.shown_at).max(0),
            message,
        },
        marked.list,
    ))
}

impl Readout {
    /// As the route answers it: every field of the message, and what is
    /// said of it here.
    pub fn answered(&self) -> Value {
        let message = &self.message;
        let device = match self.this_device {
            true => json!("this"),
            false => json!({ "label": message.label, "fingerprint": self.fingerprint }),
        };
        let answers =
            (message.answers.iter().any(|b| *b != 0)).then(|| hex::encode(&message.answers));
        let thread = match message.thread.iter().any(|b| *b != 0) {
            true => hex::encode(&message.thread),
            false => hex::encode(&message.id),
        };
        json!({
            "name": self.name,
            "id": hex::encode(&message.id),
            "from": message.from,
            "to": message.to,
            "sent": message.sent,
            "ago_secs": self.ago_secs,
            "thread": thread,
            "answers": answers,
            "asks": message.asks,
            "link": message.link,
            "body": message.body,
            "device": device,
            "its_own": self.its_own,
            "pair_count": self.pair_count,
            "pair_unread_by_a_person": self.pair_unread_by_a_person,
            "read_on": self.read_on,
            "before_the_last_change": self.before_the_last_change,
        })
    }
}

#[derive(Deserialize)]
pub struct ReadRequest {
    pub folder: String,
    /// 8 to 32 hex characters of the message's ID.
    pub id: String,
}

// ── POST /api/v1/messages/read ───────────────────────────────────────

/// `cordelia msg read <id>` (decision 2026-10-09 §4.1, §4.2).
pub async fn read(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ReadRequest>,
) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    if !is_an_id(&body.id) {
        return Err(ApiError::BadRequest(format!(
            "{} is not a message's ID: give 8 to 32 of its hex characters",
            body.id
        )));
    }
    let now = state.sync_control.now();
    let done = {
        let db = db_of(&state);
        let fetched = sender::fetched(&db, &state.own_channels, Instant::now()).map_err(refused)?;
        read_of(&db, &state.identity, &body.folder, &body.id, now, fetched)
            .map(|(readout, list)| (readout, list, ()))
            .map_err(|not| match not {
                NotRead::Refused(why) => refusal(&db, &why),
                NotRead::Failed(e) => Err(refused(e)),
            })
    };
    match done {
        Ok((readout, list, ())) => {
            // A list written waits to be sent.
            if list.is_some() {
                state.own_channels.written();
            }
            Ok(HttpResponse::Ok().json(readout.answered()))
        }
        Err(answer) => answer,
    }
}

// ── send ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SendRequest {
    pub folder: String,
    /// A name, or null.
    pub to: Option<String>,
    #[serde(default)]
    pub all: bool,
    /// 8 to 32 hex characters of the ID of the message it answers, or
    /// null.
    pub reply: Option<String>,
    #[serde(default)]
    pub asks: bool,
    pub link: Option<String>,
    pub body: String,
}

/// What a send did: its ID, the name it was sent as and to (`None` for
/// every name), and the signer whose entries fill the messages channel
/// where a relay refused it for room since the node started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    pub id: Id,
    pub from: String,
    pub to: Option<String>,
    pub filled_by: Option<(String, u64)>,
}

/// Why a send was not made at the node.
#[derive(Debug)]
pub enum NotSentHere {
    /// A refusal of §4.3 with a word, for the command to print.
    Refused(Refused),
    /// What the command checks alone, checked again: a refusal with a
    /// word and its sentence.
    Said(&'static str, String),
    /// What the command line could not have given: no word.
    Asked(String),
    Failed(PersonError),
}

/// What the node checks again of step 2 of §4.3 that the command checked
/// alone, in the same order: the flags, the reply's ID, the link, and the
/// body.
fn step_2(request: &SendRequest) -> Result<(), NotSentHere> {
    let addressed = usize::from(request.to.is_some())
        + usize::from(request.all)
        + usize::from(request.reply.is_some());
    if request.reply.is_some() && addressed > 1 {
        return Err(NotSentHere::Asked(
            "--reply sends to the agent that sent the message it answers: give no --to or \
             --all with it"
                .into(),
        ));
    }
    if addressed != 1 {
        return Err(NotSentHere::Asked(
            "give one of --to <name>, --all and --reply <id>".into(),
        ));
    }
    if let Some(reply) = &request.reply
        && !is_an_id(reply)
    {
        return Err(NotSentHere::Asked(format!(
            "{reply} is not a message's ID: give 8 to 32 of its hex characters"
        )));
    }
    if let Some(link) = &request.link
        && !is_a_link(link)
    {
        return Err(NotSentHere::Said(
            "bad_link",
            format!("{link} is not a link of the form owner/repo#number"),
        ));
    }
    if request.body.len() > AGENT_MESSAGE_BODY_MAX_BYTES {
        return Err(NotSentHere::Said(
            "too_large",
            format!("the message is over {AGENT_MESSAGE_BODY_MAX_BYTES} bytes"),
        ));
    }
    if request.body.is_empty() {
        return Err(NotSentHere::Said("empty", "the message is empty".into()));
    }
    Ok(())
}

/// What the node knows, besides its store, when it sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendAt {
    pub now: i64,
    pub fetched: bool,
    pub no_place: bool,
    pub per_folder_per_hour: usize,
}

/// `send`: the agent of `folder` sends what `request` asks, at `at`
/// (decision 2026-10-09 §3, §4.1, §4.3). What the command checked alone is
/// checked again ([`step_2`]); then [`sender::send`] makes the checks from
/// step 4 in their order, given whether the folder is mapped and, at step
/// 9, the lookup of the message a reply answers ([`answering`]).
pub fn send_of(
    conn: &Connection,
    identity: &NodeIdentity,
    request: &SendRequest,
    at: &SendAt,
    no_room: impl FnOnce(&[u8; 32]) -> bool,
) -> Result<Sent, NotSentHere> {
    step_2(request)?;
    let name = agent_of(conn, &request.folder)
        .map_err(|e| NotSentHere::Failed(PersonError::Held(e.to_string())))?;
    let sends_at = At {
        now: at.now,
        fetched: at.fetched,
        no_place: at.no_place,
        mapped: name.is_some(),
        per_folder_per_hour: at.per_folder_per_hour,
    };
    let from = name.unwrap_or_default();
    let to = match &request.to {
        Some(name) => To::Name(name.clone()),
        None => To::All,
    };
    let asked = Request {
        from: from.clone(),
        to: to.clone(),
        asks: request.asks,
        link: request.link.clone(),
        body: request.body.clone(),
        thread: [0; AGENT_MESSAGE_ID_BYTES],
        answers: [0; AGENT_MESSAGE_ID_BYTES],
    };
    // The recipient of a reply is the node's, from what it answers.
    let replied_to: RefCell<Option<To>> = RefCell::new(None);
    let reply = |conn: &Connection| match &request.reply {
        Some(given) => {
            let reply = answering(conn, identity, &from, given, at.now)?;
            *replied_to.borrow_mut() = reply.as_ref().map(|reply| reply.to.clone());
            Ok(reply)
        }
        None => sender::no_reply(conn),
    };
    let done = match sender::send(conn, identity, &sends_at, &asked, reply) {
        Ok(done) => done,
        Err(NotSent::Refused(why)) => return Err(NotSentHere::Refused(why)),
        Err(NotSent::NotAMessage(why)) => return Err(NotSentHere::Asked(why.to_string())),
        Err(NotSent::Failed(e)) => return Err(NotSentHere::Failed(e)),
    };
    let to = replied_to.into_inner().unwrap_or(to);
    let filled_by = filled_by(conn, no_room).map_err(NotSentHere::Failed)?;
    Ok(Sent {
        id: done.id,
        from,
        to: match to {
            To::Name(name) => Some(name),
            To::All => None,
        },
        filled_by,
    })
}

/// Where a relay refused the messages channel for room since the node
/// started (`no_room`, of the channel's ID), the signer whose entries fill
/// it, by the count of entries of each author that the device holds of
/// the channel, with that count (decision 2026-10-09 §10, C15).
fn filled_by(
    conn: &Connection,
    no_room: impl FnOnce(&[u8; 32]) -> bool,
) -> Result<Option<(String, u64)>, PersonError> {
    let Some(channel) = messages_channel(conn)? else {
        return Ok(None);
    };
    if !no_room(&channel) {
        return Ok(None);
    }
    let Some((author, entries)) = kept(held::entries_by_author(conn, &channel))?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    let standing = Standing::of(conn)?;
    let label = crate::reader::label_of(conn, &standing.held.statement.statement, &author)?;
    Ok(Some((label, entries)))
}

// ── POST /api/v1/messages/send ───────────────────────────────────────

/// `cordelia msg send` (decision 2026-10-09 §4.1, §4.2). What it sent
/// waits to be sent as anything a device writes does.
pub async fn send(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SendRequest>,
) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    let done = {
        let db = db_of(&state);
        let at = SendAt {
            now: state.sync_control.now(),
            fetched: sender::fetched(&db, &state.own_channels, Instant::now()).map_err(refused)?,
            no_place: state.own_channels.no_place(),
            per_folder_per_hour: state.own_channels.per_folder_per_hour(),
        };
        let no_room = |channel: &[u8; 32]| state.own_channels.no_room_for_messages(channel);
        send_of(&db, &state.identity, &body, &at, no_room).map_err(|not| match not {
            NotSentHere::Refused(why) => refusal(&db, &why),
            NotSentHere::Said(word, says) => Ok(refused_with(word, &says, json!({}))),
            NotSentHere::Asked(says) => Err(ApiError::BadRequest(says)),
            NotSentHere::Failed(e) => Err(refused(e)),
        })
    };
    match done {
        Ok(sent) => {
            state.own_channels.written();
            let filled_by = sent
                .filled_by
                .map(|(label, entries)| json!({ "label": label, "entries": entries }));
            Ok(HttpResponse::Ok().json(json!({
                "id": hex::encode(sent.id),
                "as": sent.from,
                "to": sent.to,
                "refused_for_room": filled_by.is_some(),
                "filled_by": filled_by,
            })))
        }
        Err(answer) => answer,
    }
}

// ── Refusals ─────────────────────────────────────────────────────────

/// A refusal by its word (decision 2026-10-09 §4.3): a conflict, whose
/// error's code is the word, with what the command needs to print its
/// line beside it.
fn refused_with(word: &str, says: &str, details: Value) -> HttpResponse {
    HttpResponse::Conflict().json(json!({
        "error": { "code": word, "message": says },
        "refused": details,
    }))
}

/// [`refused_with`] for a refusal of the sender's, or of the lookup of an
/// ID: what each line names is beside its word.
fn refusal(conn: &Connection, why: &Refused) -> Result<HttpResponse, ApiError> {
    let details = match why {
        Refused::NotApplied => json!({ "why": why_not_applied(conn).map_err(refused)? }),
        Refused::NoSuchName(name) => json!({ "name": name }),
        Refused::FolderRate { limit, next_at } => json!({ "limit": limit, "next_at": next_at }),
        Refused::DeviceRate {
            sends,
            again,
            next_at,
        } => json!({ "sends": sends, "again": again, "next_at": next_at }),
        Refused::PairHeld { from, other, every } => {
            json!({ "from": from, "other": other, "every": every })
        }
        Refused::NoSuchMessage(id) | Refused::SignerRemoved(id) | Refused::AsksNothing(id) => {
            json!({ "id": id })
        }
        Refused::MoreThanOne { id, ids } => json!({ "id": id, "ids": ids }),
        _ => json!({}),
    };
    Ok(refused_with(why.word(), &why.to_string(), details))
}

/// Why the device does not stand applied, as `cordelia devices` says it
/// first.
fn why_not_applied(conn: &Connection) -> Result<&'static str, PersonError> {
    Ok(match stands(conn)? {
        Stands::NoPhrase => "this device follows no recovery phrase yet",
        Stands::Stopped(state) => crate::look::short_why(state),
        Stands::Applied => crate::look::short_why(cordelia_storage::person::State::Applied),
    })
}

// ── Plumbing ─────────────────────────────────────────────────────────

fn db_of(state: &AppState) -> std::sync::MutexGuard<'_, Connection> {
    state.db.lock().unwrap_or_else(|e| e.into_inner())
}

/// A message's ID from its bytes in the index.
fn id_of(bytes: &[u8]) -> Result<Id, PersonError> {
    bytes
        .try_into()
        .map_err(|_| PersonError::Held("a message's ID is not of its length".into()))
}

/// A signer's key from its bytes in the index.
fn key_of(bytes: &[u8]) -> Result<[u8; 32], PersonError> {
    bytes
        .try_into()
        .map_err(|_| PersonError::Held("a signer's key is not of its length".into()))
}

/// An error of the API as the device's.
fn said(e: ApiError) -> PersonError {
    PersonError::Held(e.to_string())
}

/// What the store answered, with its error as the device's.
fn kept<T>(answer: Result<T, StorageError>) -> Result<T, PersonError> {
    answer.map_err(|e| PersonError::Storage(cordelia_core::CordeliaError::Storage(e.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::to_bytes;
    use actix_web::test::TestRequest;
    use cordelia_crypto::message::Message;
    use cordelia_storage::messages::Opened;
    use cordelia_storage::person::{self as held_rows, State};

    use crate::several::{Several, identity_of, state_of};
    use crate::state::Held;

    const MINUTE: i64 = 60;

    /// The names each device of a test syncs, each mapped from a folder of
    /// its own.
    const NAMES: [&str; 3] = ["notes", "work", "plans"];

    fn folder(name: &str) -> String {
        format!("/home/sam/{name}")
    }

    /// `count` devices of one person, each with sync on, saying that it
    /// syncs every one of [`NAMES`] and mapping a folder to each, each
    /// having been given what every other holds.
    fn devices(count: u16) -> Several {
        let mut s = Several::of_one_person(count);
        for n in 0..usize::from(count) {
            let conn = &s[n].conn;
            meta::set(conn, meta::SYNC_CLAUDE_DIR, "/home/sam/.claude").unwrap();
            for name in NAMES {
                crate::names::say(conn, &s[n].identity, name, s.now).unwrap();
            }
            let mapped: Vec<Value> = NAMES
                .iter()
                .map(|name| json!({ "folder": folder(name), "name": name }))
                .collect();
            meta::set(
                conn,
                meta::SYNC_CLAUDE_MAPPINGS,
                &Value::from(mapped).to_string(),
            )
            .unwrap();
        }
        let all: Vec<usize> = (0..usize::from(count)).collect();
        s.meet(&all);
        s
    }

    /// The node at `now`, which has fetched the messages channel.
    fn at(now: i64) -> SendAt {
        SendAt {
            now,
            fetched: true,
            no_place: false,
            per_folder_per_hour: 20,
        }
    }

    fn asking(from: &str, to: Option<&str>, body: &str) -> SendRequest {
        SendRequest {
            folder: folder(from),
            to: to.map(String::from),
            all: to.is_none(),
            reply: None,
            asks: true,
            link: None,
            body: body.into(),
        }
    }

    fn replying(from: &str, to: &Id) -> SendRequest {
        SendRequest {
            folder: folder(from),
            to: None,
            all: false,
            reply: Some(hex::encode(&to[..4])),
            asks: true,
            link: None,
            body: "an answer".into(),
        }
    }

    /// Device `n` sends what `request` asks at `now`.
    fn sends(s: &Several, n: usize, request: &SendRequest, now: i64) -> Result<Sent, NotSentHere> {
        send_of(&s[n].conn, &s[n].identity, request, &at(now), |_| false)
    }

    fn sent(s: &Several, n: usize, request: &SendRequest, now: i64) -> Id {
        sends(s, n, request, now).unwrap().id
    }

    fn refused_send(s: &Several, n: usize, request: &SendRequest, now: i64) -> &'static str {
        match sends(s, n, request, now) {
            Err(NotSentHere::Refused(why)) => why.word(),
            Err(NotSentHere::Said(word, _)) => word,
            Err(NotSentHere::Asked(_)) => "asked",
            other => panic!("{other:?}"),
        }
    }

    fn summary_on(s: &Several, n: usize, name: &str, now: i64) -> Option<Summary> {
        summary_of(
            &s[n].conn,
            &s[n].identity,
            &OwnChannels::default(),
            &folder(name),
            now,
        )
        .unwrap()
    }

    fn reads(s: &Several, n: usize, name: &str, id: &str, now: i64) -> Result<Readout, Refused> {
        match read_of(&s[n].conn, &s[n].identity, &folder(name), id, now, true) {
            Ok((readout, _)) => Ok(readout),
            Err(NotRead::Refused(why)) => Err(why),
            Err(NotRead::Failed(e)) => panic!("{e}"),
        }
    }

    /// A message held by device `n` as a reader holds one, with the ID
    /// `id`, signed by `signer`, written into its index at `number` with
    /// a place: the path a reader takes, without an entry.
    #[allow(clippy::too_many_arguments)]
    fn held_as(
        s: &Several,
        n: usize,
        id: Id,
        signer: [u8; 32],
        from: &str,
        to: Option<&str>,
        asks: bool,
        times: (i64, i64),
        number: u64,
    ) {
        let conn = &s[n].conn;
        let channel = messages_channel(conn).unwrap().unwrap();
        let generation = held::generation(conn, &channel, s[n].number(), times.1).unwrap();
        held::hold_number(conn, &signer, generation, number, false, times.1).unwrap();
        let message = Message {
            asks,
            sent: times.0 as u64,
            nonce: [0; 16],
            thread: [0; 16],
            answers: [0; 16],
            from: from.into(),
            to: match to {
                Some(to) => To::Name(to.into()),
                None => To::All,
            },
            link: None,
            body: format!("the body of {}", hex::encode(id)),
        };
        let opened = Opened {
            id: &id,
            signer: &signer,
            label: "elsewhere",
            generation,
            number,
            message: &message,
            first_held: times.1,
            placed_at: Some(times.1),
        };
        held::index(conn, &opened).unwrap();
    }

    fn row(conn: &Connection, id: &Id) -> (Option<String>, Vec<u8>, Vec<u8>) {
        conn.query_row(
            "SELECT to_name, thread, answers FROM message_index WHERE id = ?1",
            [&id[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
    }

    // ── Text ─────────────────────────────────────────────────────────

    /// The first and the last code point of each range of the Unicode
    /// property Default_Ignorable_Code_Point, as `DerivedCoreProperties.
    /// txt` of Unicode 16.0 lists them, and U+2800.
    const FIRST_AND_LAST_THAT_RENDER_AS_NOTHING: [char; 31] = [
        '\u{00ad}',
        '\u{034f}',
        '\u{061c}',
        '\u{115f}',
        '\u{1160}',
        '\u{17b4}',
        '\u{17b5}',
        '\u{180b}',
        '\u{180f}',
        '\u{200b}',
        '\u{200f}',
        '\u{202a}',
        '\u{202e}',
        '\u{2060}',
        '\u{206f}',
        '\u{3164}',
        '\u{fe00}',
        '\u{fe0f}',
        '\u{feff}',
        '\u{ffa0}',
        '\u{fff0}',
        '\u{fff8}',
        '\u{1bca0}',
        '\u{1bca3}',
        '\u{1d173}',
        '\u{1d17a}',
        '\u{e0000}',
        '\u{e0fff}',
        '\u{e0100}',
        '\u{e01ef}',
        '\u{2800}',
    ];

    /// The seven categories and the characters that render as nothing,
    /// and no other (decision 2026-10-09 §4.1, C4): a letter, a digit, a
    /// space, punctuation, a mark and an emoji's symbol are kept, and so
    /// is nothing of the set.
    #[test]
    fn the_seven_categories_and_what_renders_as_nothing_are_taken_out_and_no_other() {
        for c in [
            '\u{0}',
            '\u{1b}',
            '\r',
            '\n',
            '\t',
            '\u{7f}',
            '\u{85}', // Cc
            '\u{ad}',
            '\u{200b}',
            '\u{200d}',
            '\u{2060}',
            '\u{feff}',
            '\u{061c}',
            '\u{200e}',
            '\u{200f}',
            '\u{202a}',
            '\u{202e}',
            '\u{2066}',
            '\u{2069}',
            '\u{e0001}',
            '\u{e0041}',
            // Cf, and of no range that renders as nothing.
            '\u{0600}',
            '\u{fff9}',
            '\u{110bd}', // Cf
            '\u{e000}',
            '\u{f8ff}',
            '\u{f0000}', // Co
            '\u{378}',
            '\u{e0080}',
            '\u{10ffff}', // Cn
            '\u{2028}',   // Zl
            '\u{2029}',   // Zp
        ] {
            assert!(taken_out(c), "{:?}", c);
        }
        // The first and the last of each range of Default_Ignorable_Code_
        // Point, as Unicode 16.0 lists them, and the braille blank: those
        // of Mn, Lo and So are of none of the seven categories.
        for c in FIRST_AND_LAST_THAT_RENDER_AS_NOTHING {
            assert!(taken_out(c), "{:?}", c);
        }
        // A character beside each range that is of none is kept.
        for c in [
            '\u{034e}', '\u{0350}', '\u{115e}', '\u{1161}', '\u{17b3}', '\u{17b6}', '\u{3163}',
            '\u{3165}', '\u{fdff}', '\u{fe10}', '\u{ff9f}', '\u{ffa1}', '\u{27ff}', '\u{2801}',
        ] {
            assert!(!taken_out(c), "{:?}", c);
        }
        for c in [
            'a',
            'Z',
            '7',
            ' ',
            '~',
            '/',
            '#',
            '"',
            '\\',
            'é',
            '日',
            '\u{301}',
            '\u{1f600}',
        ] {
            assert!(!taken_out(c), "{:?}", c);
        }
        assert_eq!(cleaned("a\u{202e}b\u{e0041}c\u{2028}d\re"), "abcde");
    }

    /// The subject is the body's first line, cleaned, and cut to 80
    /// Unicode scalar values, with whether it was cut (decision 2026-10-09
    /// §2.2, §4.1).
    #[test]
    fn a_subject_is_the_first_line_cleaned_and_cut_at_80() {
        assert_eq!(subject_of("first\nsecond"), ("first".into(), false));
        assert_eq!(subject_of("only"), ("only".into(), false));
        assert_eq!(subject_of("\u{202e}\n"), (String::new(), false));
        let long = "日".repeat(81);
        assert_eq!(subject_of(&long), ("日".repeat(80), true));
        assert_eq!(subject_of(&"日".repeat(80)), ("日".repeat(80), false));
        // Cleaned first: what is taken out is not counted.
        let marked = format!("{}{}", "\u{200b}".repeat(10), "a".repeat(80));
        assert_eq!(subject_of(&marked), ("a".repeat(80), false));
    }

    // ── The folder ───────────────────────────────────────────────────

    /// The agent of a folder is the name of the mapping whose folder is
    /// the same, byte for byte, once the path is tidied as a mapping's was
    /// (decision 2026-10-09 §3.1).
    #[test]
    fn the_agent_of_a_folder_is_the_mapping_whose_folder_is_the_same_byte_for_byte() {
        let s = devices(1);
        let of = |folder: &str| agent_of(&s[0].conn, folder).unwrap();
        assert_eq!(of("/home/sam/notes").as_deref(), Some("notes"));
        assert_eq!(of("/home/sam/notes/").as_deref(), Some("notes"));
        assert_eq!(of("/home/sam//notes").as_deref(), Some("notes"));
        assert_eq!(of("/home/sam/work").as_deref(), Some("work"));
        for unmapped in [
            "/home/sam/notes/sub",
            "/home/sam/Notes",
            "/home/sam/notes ",
            "/home/sam",
            "/home/sam/notes/../notes",
            "home/sam/notes",
            "",
        ] {
            assert_eq!(of(unmapped), None, "{unmapped}");
        }
    }

    // ── summary ──────────────────────────────────────────────────────

    /// A summary's lines are of messages to the agent's name, at most five,
    /// the oldest first, each announced once; the count is of every other
    /// that waits: those announced before, every message to every name,
    /// and what is beyond the five (decision 2026-10-09 §4.1, C5, C6).
    #[test]
    fn a_summary_announces_at_most_five_and_counts_the_rest() {
        let mut s = devices(2);
        // Sent before they are held, so each is shown from its `sent`.
        let t = s.now - 10 * MINUTE;
        let mut to_work = Vec::new();
        for k in 0..7 {
            to_work.push(sent(
                &s,
                0,
                &asking("notes", Some("work"), &format!("{k}")),
                t + k,
            ));
        }
        let to_all = sent(&s, 0, &asking("notes", None, "to every name"), t + 7);
        let to_plans = sent(&s, 0, &asking("notes", Some("plans"), "to plans"), t + 8);
        s.pass(0, 1);
        let now = s.now + MINUTE;

        let first = summary_on(&s, 1, "work", now).unwrap();
        assert_eq!(first.name, "work");
        let lines: Vec<Id> = first.lines.iter().map(|line| line.id).collect();
        assert_eq!(lines, to_work[..5]);
        assert_eq!(first.waiting, [to_work[5], to_work[6], to_all]);
        assert!(!first.waiting.contains(&to_plans));
        assert_eq!(first.lines[0].from, "notes");
        assert_eq!(first.lines[0].subject, "0");
        assert_eq!(first.lines[0].label.as_deref(), Some("device 0"));

        // Announced, each is counted after.
        let second = summary_on(&s, 1, "work", now).unwrap();
        assert_eq!(
            second.lines.iter().map(|line| line.id).collect::<Vec<_>>(),
            to_work[5..]
        );
        let third = summary_on(&s, 1, "work", now).unwrap();
        assert!(third.lines.is_empty());
        assert_eq!(third.waiting.len(), 8);
        // Announced to one agent is not announced to another.
        let plans = summary_on(&s, 1, "plans", now).unwrap();
        assert_eq!(plans.lines.len(), 1);
        assert_eq!(plans.lines[0].id, to_plans);
        // The agent that sent them is shown nothing of its own here; the
        // agent they are to there is, from this device.
        assert_eq!(summary_on(&s, 0, "notes", now), None);
        let here = summary_on(&s, 0, "work", now).unwrap();
        assert_eq!(here.lines[0].label, None);
        assert_eq!(here.lines[0].id, to_work[0]);
        // A message to every name is never a line.
        let answered = third.answered();
        assert_eq!(answered["waiting"]["count"], 8);
        assert_eq!(answered["waiting"]["ids"].as_array().unwrap().len(), 5);
    }

    /// Two messages of one shown time stand by their IDs, and a message
    /// whose `sent` is earlier but whose first holding is later stands by
    /// its shown time, the earlier of the two (decision 2026-10-09 §4.1,
    /// F9).
    #[test]
    fn oldest_first_is_by_shown_time_then_by_id() {
        let s = devices(2);
        let t = s.now + MINUTE;
        let to_work = |id: u8, times: (i64, i64), number: u64| {
            let signer = s.key(0);
            held_as(
                &s,
                1,
                [id; 16],
                signer,
                "notes",
                Some("work"),
                false,
                times,
                number,
            );
        };
        to_work(0xb0, (t, t), 1);
        to_work(0xa0, (t, t), 2);
        // Sent before both, held after both: it stands at its `sent`.
        to_work(0xc0, (t - 10, t + 10), 3);
        // Sent after both, and so shown at its `sent`.
        to_work(0x10, (t + 5, t + 20), 4);
        // Said to be sent after it was held: shown from its first holding.
        to_work(0x05, (t + 50, t + 1), 5);
        let now = t + MINUTE;
        let summarised = summary_on(&s, 1, "work", now).unwrap();
        let ids: Vec<Id> = summarised.lines.iter().map(|line| line.id).collect();
        assert_eq!(
            ids,
            [[0xc0; 16], [0xa0; 16], [0xb0; 16], [0x05; 16], [0x10; 16]]
        );
        let agos: Vec<i64> = summarised.lines.iter().map(|line| line.ago_secs).collect();
        assert_eq!(
            agos,
            [
                now - (t - 10),
                now - t,
                now - t,
                now - (t + 1),
                now - (t + 5)
            ]
        );
    }

    /// Everything `summary` answers is in the index and the marks: with
    /// every entry of the messages channel gone from the store, it answers
    /// the same (decision 2026-10-09 §4.1, C20).
    #[test]
    fn the_summary_opens_no_entry() {
        let mut s = devices(2);
        let t = s.now + MINUTE;
        let id = sent(
            &s,
            0,
            &asking("notes", Some("work"), "a subject\nand more"),
            t,
        );
        s.pass(0, 1);
        let conn = &s[1].conn;
        let channel = messages_channel(conn).unwrap().unwrap();
        let gone = conn
            .execute("DELETE FROM entries WHERE channel_id = ?1", [&channel[..]])
            .unwrap();
        assert!(gone > 0);
        let summarised = summary_on(&s, 1, "work", s.now + MINUTE).unwrap();
        assert_eq!(summarised.lines.len(), 1);
        assert_eq!(summarised.lines[0].id, id);
        assert_eq!(summarised.lines[0].subject, "a subject");
    }

    /// A device that does not stand applied, in a fork, in no list, whose
    /// change did not open or that was removed, shows nothing: `summary`
    /// answers nothing, and `read` and `send` are refused with
    /// `not_applied` (decision 2026-10-09 §1, property 1).
    #[test]
    fn a_device_in_a_fork_or_in_no_list_shows_nothing() {
        for state in [
            State::Fork,
            State::NotListed,
            State::NotOpened,
            State::Removed,
        ] {
            let mut s = devices(2);
            let t = s.now + MINUTE;
            let id = sent(&s, 0, &asking("notes", Some("work"), "hello"), t);
            s.pass(0, 1);
            let now = s.now + MINUTE;
            let given = hex::encode(&id[..4]);
            let other = sent(&s, 0, &asking("notes", Some("work"), "again"), t + 1);
            s.pass(0, 1);
            assert!(summary_on(&s, 1, "work", now).is_some());
            assert!(reads(&s, 1, "work", &given, now).is_ok());
            held_rows::set_state(&s[1].conn, state).unwrap();
            assert_eq!(summary_on(&s, 1, "work", now), None, "{state:?}");
            assert_eq!(
                reads(&s, 1, "work", &given, now).unwrap_err(),
                Refused::NotApplied,
                "{state:?}"
            );
            assert_eq!(
                refused_send(&s, 1, &asking("work", Some("notes"), "x"), now),
                "not_applied"
            );
            held_rows::set_state(&s[1].conn, State::Applied).unwrap();
            assert!(reads(&s, 1, "work", &given, now).is_ok());
            // The other waits still, and is counted once it stands again.
            let counted = summary_on(&s, 1, "work", now).unwrap();
            assert_eq!(counted.waiting, [other]);
        }
    }

    // ── read ─────────────────────────────────────────────────────────

    /// `read` shows a message to the agent's name, to every name, or one it
    /// sent here, and marks it read by that agent where it is addressed to
    /// it: `summary` then counts it no more (decision 2026-10-09 §4.1,
    /// §7.2).
    #[test]
    fn read_shows_what_the_agent_may_read_and_marks_what_is_for_it() {
        let mut s = devices(2);
        let t = s.now + MINUTE;
        let to_work = sent(&s, 0, &asking("notes", Some("work"), "to work"), t);
        let to_plans = sent(&s, 0, &asking("notes", Some("plans"), "to plans"), t + 1);
        s.pass(0, 1);
        let now = s.now + MINUTE;
        let shown = reads(&s, 1, "work", &hex::encode(to_work), now).unwrap();
        assert_eq!(shown.message.body, "to work");
        assert_eq!(shown.name, "work");
        assert!(!shown.this_device && !shown.its_own);
        assert_eq!(shown.message.label, "device 0");
        assert_eq!(shown.fingerprint, fingerprint::shown(&s.key(0)));
        assert_eq!((shown.pair_count, shown.pair_unread_by_a_person), (1, 1));
        // Once a person has read it here, it is read by a person.
        s[1].conn
            .execute(
                "INSERT INTO message_read_by_a_person (id) VALUES (?1)",
                [&to_work[..]],
            )
            .unwrap();
        let again = reads(&s, 1, "work", &hex::encode(to_work), now).unwrap();
        assert_eq!((again.pair_count, again.pair_unread_by_a_person), (1, 0));
        assert!(!shown.before_the_last_change);
        assert!(shown.read_on.is_empty());
        // Read, it waits no more.
        assert_eq!(summary_on(&s, 1, "work", now), None);
        // Another agent cannot read it.
        assert_eq!(
            reads(&s, 1, "plans", &hex::encode(to_work), now).unwrap_err(),
            Refused::NoSuchMessage(hex::encode(to_work))
        );
        assert!(reads(&s, 1, "plans", &hex::encode(to_plans), now).is_ok());
        // The sender reads what it sent, which is its own; the agent it is
        // to on the same device reads it as from this device.
        let own = reads(&s, 0, "notes", &hex::encode(to_work), now).unwrap();
        assert!(own.this_device && own.its_own);
        let here = reads(&s, 0, "work", &hex::encode(to_work), now).unwrap();
        assert!(here.this_device && !here.its_own);
        // A message that begins its thread is in the thread of its ID.
        assert_eq!(shown.answered()["thread"], hex::encode(to_work));
        assert_eq!(shown.answered()["answers"], Value::Null);
        assert_eq!(shown.answered()["device"]["label"], "device 0");
        assert_eq!(here.answered()["device"], "this");
        // And it is no other agent's on the sending device.
        assert!(reads(&s, 0, "plans", &hex::encode(to_work), now).is_err());
        // Read with sync off: it shows what is held.
        meta::remove(&s[1].conn, meta::SYNC_CLAUDE_DIR).unwrap();
        assert!(reads(&s, 1, "work", &hex::encode(to_work), now).is_ok());
    }

    // ── send ─────────────────────────────────────────────────────────

    /// A reply's recipient, thread and `answers` are the node's, from the
    /// message it answers: the request names none of them (decision
    /// 2026-10-09 §3, C7).
    #[test]
    fn the_thread_is_set_by_the_node_and_not_the_sender() {
        let mut s = devices(2);
        let t = s.now + MINUTE;
        let first = sent(&s, 0, &asking("notes", Some("work"), "a question"), t);
        s.pass(0, 1);
        // Only what has a place is answered: it was shown.
        assert!(matches!(
            sends(&s, 1, &replying("work", &first), s.now + MINUTE),
            Err(NotSentHere::Refused(Refused::NoSuchMessage(_)))
        ));
        reads(&s, 1, "work", &hex::encode(first), s.now + MINUTE).unwrap();
        let reply = sends(&s, 1, &replying("work", &first), s.now + MINUTE).unwrap();
        assert_eq!(reply.to.as_deref(), Some("notes"));
        assert_eq!(reply.from, "work");
        assert_eq!(
            row(&s[1].conn, &reply.id),
            (Some("notes".into()), first.to_vec(), first.to_vec())
        );
        // An answer to the answer stays in the thread the first began.
        s.pass(1, 0);
        reads(&s, 0, "notes", &hex::encode(reply.id), s.now + MINUTE).unwrap();
        let again = sends(&s, 0, &replying("notes", &reply.id), s.now + MINUTE).unwrap();
        assert_eq!(
            row(&s[0].conn, &again.id),
            (Some("work".into()), first.to_vec(), reply.id.to_vec())
        );
        // The answer and its question are of one pair, either way round.
        let pair = reads(&s, 0, "notes", &hex::encode(reply.id), s.now + MINUTE).unwrap();
        assert_eq!((pair.pair_count, pair.pair_unread_by_a_person), (3, 3));
        // An agent answers no message of its own, to a name or to every
        // name.
        assert!(matches!(
            sends(&s, 0, &replying("notes", &first), s.now + MINUTE),
            Err(NotSentHere::Refused(Refused::NoSuchMessage(_)))
        ));
        let own_to_all = sent(&s, 0, &asking("notes", None, "to all"), s.now + MINUTE);
        reads(&s, 0, "notes", &hex::encode(own_to_all), s.now + MINUTE).unwrap();
        assert!(matches!(
            sends(&s, 0, &replying("notes", &own_to_all), s.now + MINUTE),
            Err(NotSentHere::Refused(Refused::NoSuchMessage(_)))
        ));
        // A request that names a recipient beside a reply is refused.
        let mut both = replying("notes", &reply.id);
        both.to = Some("plans".into());
        assert_eq!(refused_send(&s, 0, &both, s.now + MINUTE), "asked");
    }

    /// The node checks again what the command checked alone, and makes its
    /// own checks in the record's order, the first that applies refusing
    /// (decision 2026-10-09 §4.3, D5): here, those of the route and of
    /// step 9, each beside a later one that applies at once.
    #[test]
    fn the_checks_are_made_in_one_order() {
        let mut s = devices(2);
        let t = s.now + MINUTE;
        let (laptop, removed) = (s.key(0), identity_of(9).public_key());
        // Two messages from a key that no longer counts that begin alike,
        // one alone, and one from it that asks nothing; one from laptop
        // that asks nothing, and one that asks from a name nobody lists.
        let twin = |last: u8| {
            let mut id = [0xab; 16];
            id[15] = last;
            id
        };
        held_as(
            &s,
            1,
            twin(1),
            removed,
            "notes",
            Some("work"),
            true,
            (t, t),
            1,
        );
        held_as(
            &s,
            1,
            twin(2),
            removed,
            "notes",
            Some("work"),
            true,
            (t, t),
            2,
        );
        held_as(
            &s,
            1,
            [0xcd; 16],
            removed,
            "notes",
            Some("work"),
            false,
            (t, t),
            3,
        );
        held_as(
            &s,
            1,
            [0xef; 16],
            laptop,
            "notes",
            Some("work"),
            false,
            (t, t),
            70,
        );
        held_as(
            &s,
            1,
            [0x12; 16],
            laptop,
            "nobody",
            Some("work"),
            true,
            (t, t),
            71,
        );
        s.tick();
        let now = s.now + MINUTE;

        // The route's own, of step 2: --reply with --to, then not one of
        // three, then the link, then the body.
        let mut all_wrong = replying("work", &[0xef; 16]);
        all_wrong.to = Some("notes".into());
        all_wrong.link = Some("not a link".into());
        all_wrong.body = "x".repeat(AGENT_MESSAGE_BODY_MAX_BYTES + 1);
        assert!(matches!(
            sends(&s, 1, &all_wrong, now),
            Err(NotSentHere::Asked(says)) if says.starts_with("--reply sends")
        ));
        all_wrong.reply = None;
        all_wrong.all = true;
        assert!(matches!(
            sends(&s, 1, &all_wrong, now),
            Err(NotSentHere::Asked(says)) if says.starts_with("give one of")
        ));
        all_wrong.all = false;
        assert_eq!(refused_send(&s, 1, &all_wrong, now), "bad_link");
        all_wrong.link = None;
        assert_eq!(refused_send(&s, 1, &all_wrong, now), "too_large");
        all_wrong.body = String::new();
        assert_eq!(refused_send(&s, 1, &all_wrong, now), "empty");

        // Step 9: more than one before a signer that no longer counts.
        let both = hex::encode(&twin(1)[..8]);
        let more = Refused::MoreThanOne {
            id: both.clone(),
            ids: vec![hex::encode(twin(1)), hex::encode(twin(2))],
        };
        assert_eq!(reads(&s, 1, "work", &both, now).unwrap_err(), more);
        let mut reply = replying("work", &twin(1));
        reply.reply = Some(both);
        assert_eq!(refused_send(&s, 1, &reply, now), "more_than_one");
        // A signer that no longer counts before a message that asks
        // nothing.
        reply.reply = Some(hex::encode([0xcd; 16]));
        assert_eq!(refused_send(&s, 1, &reply, now), "signer_removed");
        assert_eq!(
            reads(&s, 1, "work", &hex::encode([0xcd; 16]), now).unwrap_err(),
            Refused::SignerRemoved(hex::encode([0xcd; 16]))
        );
        // A message that asks nothing, before its sender not being a
        // name: step 9 before step 10.
        reply.reply = Some(hex::encode(&[0xef; 16][..4]));
        assert_eq!(refused_send(&s, 1, &reply, now), "asks_nothing");
        reply.reply = Some(hex::encode([0x12; 16]));
        assert_eq!(refused_send(&s, 1, &reply, now), "no_such_name");
        // A reply's ID of another form.
        let mut odd = replying("work", &[0x12; 16]);
        odd.reply = Some("xyz".into());
        assert!(matches!(
            sends(&s, 1, &odd, now),
            Err(NotSentHere::Asked(says)) if says.starts_with("xyz is not a message's ID")
        ));
        odd.reply = Some("ghijklmn".into());
        assert!(matches!(
            sends(&s, 1, &odd, now),
            Err(NotSentHere::Asked(says)) if says.starts_with("ghijklmn is not a message's ID")
        ));
        // A signer that no longer counts is in no summary.
        let summarised = summary_on(&s, 1, "work", now).unwrap();
        let removed_ids = [twin(1), twin(2), [0xcd; 16]];
        assert!(
            summarised
                .lines
                .iter()
                .all(|line| !removed_ids.contains(&line.id))
        );
        assert!(
            summarised
                .waiting
                .iter()
                .all(|id| !removed_ids.contains(id))
        );
        assert!(summarised.lines.iter().any(|line| line.id == [0xef; 16]));
        // Unmapped before the message; not applied before both.
        let unmapped = SendRequest {
            folder: "/home/sam/unmapped".into(),
            ..replying("work", &[0x77; 16])
        };
        assert_eq!(refused_send(&s, 1, &unmapped, now), "not_mapped");
        let read_unmapped = read_of(
            &s[1].conn,
            &s[1].identity,
            "/nowhere",
            "77777777",
            now,
            true,
        );
        assert!(matches!(
            read_unmapped,
            Err(NotRead::Refused(Refused::NotMapped))
        ));
        assert_eq!(
            reads(&s, 1, "work", "77777777", now).unwrap_err(),
            Refused::NoSuchMessage("77777777".into())
        );
        held_rows::set_state(&s[1].conn, State::Fork).unwrap();
        assert_eq!(refused_send(&s, 1, &unmapped, now), "not_applied");
        let read_fork = read_of(
            &s[1].conn,
            &s[1].identity,
            "/nowhere",
            "77777777",
            now,
            true,
        );
        assert!(matches!(
            read_fork,
            Err(NotRead::Refused(Refused::NotApplied))
        ));
    }

    /// A device whose messages channel has no place among the proofs of a
    /// connection has no messages: its summary is nothing (decision
    /// 2026-10-09 §2.1).
    #[test]
    fn a_device_with_no_place_for_messages_shows_no_summary() {
        let mut s = devices(2);
        sent(
            &s,
            0,
            &asking("notes", Some("work"), "hello"),
            s.now + MINUTE,
        );
        s.pass(0, 1);
        let now = s.now + MINUTE;
        let of = |own_channels: &OwnChannels| {
            summary_of(
                &s[1].conn,
                &s[1].identity,
                own_channels,
                &folder("work"),
                now,
            )
            .unwrap()
        };
        let no_place = OwnChannels::default();
        no_place.say_no_place(true);
        assert_eq!(of(&no_place), None);
        assert!(of(&OwnChannels::default()).is_some());
    }

    /// The body of a refusal, as the route answers it.
    fn refusal_said(conn: &Connection, why: &Refused) -> Value {
        let response = refusal(conn, why).unwrap();
        assert_eq!(response.status().as_u16(), 409);
        let body = actix_web::rt::System::new()
            .block_on(to_bytes(response.into_body()))
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    /// Each refusal is answered by its word, beside what its line names
    /// (decision 2026-10-09 §4.3).
    #[test]
    fn the_details_of_each_refusal_are_beside_its_word() {
        let s = devices(1);
        let conn = &s[0].conn;
        let said = |why: Refused| {
            let body = refusal_said(conn, &why);
            assert_eq!(body["error"]["code"], why.word());
            body["refused"].clone()
        };
        assert_eq!(
            said(Refused::NoSuchName("x".into())),
            json!({ "name": "x" })
        );
        let rate = Refused::FolderRate {
            limit: 7,
            next_at: 9,
        };
        assert_eq!(said(rate), json!({ "limit": 7, "next_at": 9 }));
        let rate = Refused::DeviceRate {
            sends: 55,
            again: 5,
            next_at: 9,
        };
        assert_eq!(said(rate), json!({ "sends": 55, "again": 5, "next_at": 9 }));
        let held = Refused::PairHeld {
            from: "a".into(),
            other: Some("b".into()),
            every: true,
        };
        assert_eq!(
            said(held),
            json!({ "from": "a", "other": "b", "every": true })
        );
        let held = Refused::PairHeld {
            from: "a".into(),
            other: None,
            every: false,
        };
        assert_eq!(
            said(held),
            json!({ "from": "a", "other": null, "every": false })
        );
        for (why, word) in [
            (Refused::NoSuchMessage("0123abcd".into()), "no_such_message"),
            (Refused::SignerRemoved("0123abcd".into()), "signer_removed"),
            (Refused::AsksNothing("0123abcd".into()), "asks_nothing"),
        ] {
            assert_eq!(why.word(), word);
            assert_eq!(said(why), json!({ "id": "0123abcd" }));
        }
        let more = Refused::MoreThanOne {
            id: "0123abcd".into(),
            ids: vec!["a".into(), "b".into()],
        };
        assert_eq!(more.word(), "more_than_one");
        assert_eq!(said(more), json!({ "id": "0123abcd", "ids": ["a", "b"] }));
        held_rows::set_state(conn, State::Fork).unwrap();
        assert_eq!(
            said(Refused::NotApplied),
            json!({ "why": "two changes were made apart" })
        );
        assert_eq!(said(Refused::SyncOff), json!({}));
        let none = Several::new(1);
        let body = refusal_said(&none[0].conn, &Refused::NotApplied);
        assert_eq!(
            body["refused"]["why"],
            "this device follows no recovery phrase yet"
        );
    }

    // ── The routes ───────────────────────────────────────────────────

    const TOKEN: &str = "t";

    fn asked() -> HttpRequest {
        TestRequest::post()
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .to_http_request()
    }

    fn not_asked() -> HttpRequest {
        TestRequest::post().to_http_request()
    }

    async fn answer(answered: Result<HttpResponse, ApiError>) -> (u16, Value) {
        let response = match answered {
            Ok(response) => response,
            Err(e) => actix_web::ResponseError::error_response(&e),
        };
        let status = response.status().as_u16();
        let body = to_bytes(response.into_body()).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap_or_default())
    }

    fn summary_asked(name: &str, within_ms: u64) -> web::Json<SummaryRequest> {
        web::Json(SummaryRequest {
            folder: folder(name),
            within_ms,
            version: env!("CARGO_PKG_VERSION").into(),
        })
    }

    /// A node over device 1 of two, given a message from device 0 to
    /// `work`, whose ID is returned.
    fn a_node_with_a_message() -> (web::Data<AppState>, Id) {
        let mut s = devices(2);
        let t = s.now + MINUTE;
        let id = sent(&s, 0, &asking("notes", Some("work"), "hello"), t);
        s.pass(0, 1);
        let machine = s.machines.remove(1);
        let state = web::Data::new(state_of(machine));
        state.sync_control.set_now(Some(t + MINUTE));
        (state, id)
    }

    /// With the store's lock held by another, `summary` answers nothing
    /// once `within_ms` is spent, and does not wait for the lock past it
    /// (decision 2026-10-09 §4.1, C20).
    #[actix_web::test]
    async fn a_node_that_cannot_have_its_lock_in_time_answers_nothing() {
        let (state, _) = a_node_with_a_message();
        {
            // Another holds the store's lock until it is told to let go.
            let (holding, held) = std::sync::mpsc::channel();
            let (let_go, told) = std::sync::mpsc::channel::<()>();
            let other = state.clone();
            let holder = std::thread::spawn(move || {
                let _held = other.db.lock().unwrap();
                holding.send(()).unwrap();
                let _ = told.recv();
            });
            held.recv().unwrap();
            let began = Instant::now();
            let (status, _) =
                answer(summary(asked(), state.clone(), summary_asked("work", 50)).await).await;
            let waited = began.elapsed();
            assert_eq!(status, 204);
            assert!(waited >= Duration::from_millis(50), "{waited:?}");
            assert!(waited < Duration::from_millis(1_000), "{waited:?}");
            // Its time is never more than the summary's own.
            let began = Instant::now();
            let (status, _) =
                answer(summary(asked(), state.clone(), summary_asked("work", 60_000)).await).await;
            assert_eq!(status, 204);
            assert!(began.elapsed() < Duration::from_millis(1_000));
            let_go.send(()).unwrap();
            holder.join().unwrap();
        }
        let (status, said) =
            answer(summary(asked(), state.clone(), summary_asked("work", 50)).await).await;
        assert_eq!(status, 200, "{said}");
        assert_eq!(said["lines"].as_array().unwrap().len(), 1);
    }

    /// While a summary waits for the store's lock, the worker it runs on
    /// serves another request: the wait holds no thread (decision
    /// 2026-10-09 §4.1, C20).
    #[actix_web::test]
    async fn another_request_is_served_while_a_summary_waits_for_the_store() {
        let (state, _) = a_node_with_a_message();
        let (holding, held) = std::sync::mpsc::channel();
        let (let_go, told) = std::sync::mpsc::channel::<()>();
        let other = state.clone();
        let holder = std::thread::spawn(move || {
            let _held = other.db.lock().unwrap();
            holding.send(()).unwrap();
            let _ = told.recv();
        });
        held.recv().unwrap();
        let began = Instant::now();
        let waits = async {
            let answered = summary(asked(), state.clone(), summary_asked("work", 100)).await;
            (answer(answered).await.0, Instant::now())
        };
        // Another request, sent once the summary is waiting: of another
        // version, which is answered without the store.
        let another = async {
            actix_web::rt::time::sleep(Duration::from_millis(10)).await;
            let mut other = summary_asked("work", 100);
            other.version = "0.0.0".into();
            let answered = summary(asked(), state.clone(), other).await;
            (answer(answered).await.0, Instant::now())
        };
        let ((waited, waited_until), (served, served_at)) = tokio::join!(waits, another);
        let_go.send(()).unwrap();
        holder.join().unwrap();
        assert_eq!((waited, served), (204, 204));
        assert!(
            served_at < waited_until,
            "the other request waited for the summary"
        );
        assert!(waited_until.duration_since(began) >= Duration::from_millis(100));
    }

    /// `summary` answers nothing to a request of another version, and
    /// nothing while the node is held up; `read` and `send` are refused
    /// then with `held_up` (decision 2026-10-09 §4.2, §4.3).
    #[actix_web::test]
    async fn a_summary_of_another_version_or_while_held_up_is_nothing() {
        let (state, id) = a_node_with_a_message();
        let mut other = summary_asked("work", 100);
        other.version = "0.0.0".into();
        let (status, _) = answer(summary(asked(), state.clone(), other).await).await;
        assert_eq!(status, 204);
        state.held.hold(Held::FirstStart("a copy failed".into()));
        let (status, _) =
            answer(summary(asked(), state.clone(), summary_asked("work", 100)).await).await;
        assert_eq!(status, 204);
        let read_asked = web::Json(ReadRequest {
            folder: folder("work"),
            id: hex::encode(id),
        });
        let (status, said) = answer(read(asked(), state.clone(), read_asked).await).await;
        assert_eq!((status, &said["error"]["code"]), (503, &json!("held_up")));
        let send_asked = web::Json(asking("work", Some("notes"), "x"));
        let (status, said) = answer(send(asked(), state.clone(), send_asked).await).await;
        assert_eq!((status, &said["error"]["code"]), (503, &json!("held_up")));
        state.held.release();
        let (status, _) =
            answer(summary(asked(), state.clone(), summary_asked("work", 100)).await).await;
        assert_eq!(status, 200);
    }

    /// Each route of messages needs the node's token, and is served by a
    /// personal node and by no other (decision 2026-10-09 §4.2).
    #[actix_web::test]
    async fn the_routes_of_messages_are_a_personal_nodes_and_each_needs_the_token() {
        use actix_web::{App, test};
        let (state, id) = a_node_with_a_message();
        let bodies = [
            (
                "/api/v1/messages/summary",
                json!({ "folder": folder("work"), "within_ms": 100,
                "version": env!("CARGO_PKG_VERSION") }),
            ),
            (
                "/api/v1/messages/read",
                json!({ "folder": folder("work"), "id": hex::encode(id) }),
            ),
            (
                "/api/v1/messages/send",
                json!({ "folder": folder("work"), "to": "notes",
                "all": false, "reply": null, "asks": false, "link": null, "body": "x" }),
            ),
        ];
        let personal = test::init_service(
            App::new()
                .app_data(state.clone())
                .configure(crate::configure_device_routes),
        )
        .await;
        for (path, body) in &bodies {
            let without = test::TestRequest::post()
                .uri(path)
                .set_json(body)
                .to_request();
            let status = test::call_service(&personal, without).await.status();
            assert_eq!(status.as_u16(), 401, "{path}");
            let with = test::TestRequest::post()
                .uri(path)
                .insert_header(("Authorization", format!("Bearer {TOKEN}")))
                .set_json(body)
                .to_request();
            let status = test::call_service(&personal, with).await.status();
            assert!(
                status.as_u16() == 200 || status.as_u16() == 409,
                "{path}: {status}"
            );
        }
        let relay = test::init_service(
            App::new()
                .app_data(state.clone())
                .configure(crate::configure_routes),
        )
        .await;
        for (path, body) in &bodies {
            let with = test::TestRequest::post()
                .uri(path)
                .insert_header(("Authorization", format!("Bearer {TOKEN}")))
                .set_json(body)
                .to_request();
            let status = test::call_service(&relay, with).await.status();
            assert_eq!(status.as_u16(), 404, "{path}");
        }
        // And without the token the handlers refuse before anything.
        let (status, _) =
            answer(summary(not_asked(), state.clone(), summary_asked("work", 100)).await).await;
        assert_eq!(status, 401);
    }

    /// The first send after a start waits until the messages channel was
    /// fetched, as `OwnChannels::first_fetch_done` answers it; a device set
    /// up with no relay is never refused for it (decision 2026-10-09 §2.3).
    #[actix_web::test]
    async fn the_first_send_after_a_start_waits_for_the_ring_to_be_fetched() {
        let (state, _) = a_node_with_a_message();
        state.own_channels.set_up_with(1);
        let asked_to = || web::Json(asking("work", Some("notes"), "x"));
        let (status, said) = answer(send(asked(), state.clone(), asked_to()).await).await;
        assert_eq!(
            (status, &said["error"]["code"]),
            (409, &json!("not_fetched"))
        );
        let channel = messages_channel(&state.db.lock().unwrap())
            .unwrap()
            .unwrap();
        state
            .own_channels
            .fetched_from(&channel, "relay", Instant::now());
        let (status, said) = answer(send(asked(), state.clone(), asked_to()).await).await;
        assert_eq!(status, 200, "{said}");
        assert_eq!(
            (&said["as"], &said["to"]),
            (&json!("work"), &json!("notes"))
        );

        let (none, _) = a_node_with_a_message();
        none.own_channels.set_up_with(0);
        let (status, said) = answer(send(asked(), none.clone(), asked_to()).await).await;
        assert_eq!(status, 200, "{said}");
    }

    /// A refusal is answered by its word, with what its line names beside
    /// it; the folder's rate comes from what the node was told of the
    /// configuration (decision 2026-10-09 §4.3, §6).
    #[actix_web::test]
    async fn a_refusal_is_answered_by_its_word_and_what_its_line_names() {
        let (state, _) = a_node_with_a_message();
        state.own_channels.set_up_with(0);
        state.own_channels.set_per_folder_per_hour(0);
        let asked_to = |to: &str| web::Json(asking("work", Some(to), "x"));
        let (status, said) = answer(send(asked(), state.clone(), asked_to("notes")).await).await;
        assert_eq!(
            (status, &said["error"]["code"]),
            (409, &json!("sending_off"))
        );
        state.own_channels.set_per_folder_per_hour(1);
        let (status, said) = answer(send(asked(), state.clone(), asked_to("nobody")).await).await;
        assert_eq!(said["error"]["code"], "no_such_name", "{status}");
        assert_eq!(said["refused"]["name"], "nobody");
        let (status, _) = answer(send(asked(), state.clone(), asked_to("notes")).await).await;
        assert_eq!(status, 200);
        let (_, said) = answer(send(asked(), state.clone(), asked_to("notes")).await).await;
        assert_eq!(said["error"]["code"], "folder_rate");
        assert_eq!(said["refused"]["limit"], 1);
        assert!(said["refused"]["next_at"].as_i64().unwrap() > 0);
        let read_asked = web::Json(ReadRequest {
            folder: folder("work"),
            id: "xyz".into(),
        });
        let (status, _) = answer(read(asked(), state.clone(), read_asked).await).await;
        assert_eq!(status, 400);
        let read_asked = web::Json(ReadRequest {
            folder: folder("work"),
            id: "ghijklmn".into(),
        });
        let (status, _) = answer(read(asked(), state.clone(), read_asked).await).await;
        assert_eq!(status, 400);
        let read_asked = web::Json(ReadRequest {
            folder: "/nowhere".into(),
            id: "0123456789".into(),
        });
        let (_, said) = answer(read(asked(), state.clone(), read_asked).await).await;
        assert_eq!(said["error"]["code"], "not_mapped");
        held_rows::set_state(&state.db.lock().unwrap(), State::Removed).unwrap();
        let read_asked = web::Json(ReadRequest {
            folder: folder("work"),
            id: "0123456789".into(),
        });
        let (_, said) = answer(read(asked(), state.clone(), read_asked).await).await;
        assert_eq!(said["error"]["code"], "not_applied");
        assert_eq!(said["refused"]["why"], "this device was removed");
    }

    /// Where a relay refused the messages channel for room since the node
    /// started, `send` names the signer whose entries fill it, by the count
    /// of each author's entries the device holds (decision 2026-10-09
    /// §4.1, §10, C15).
    #[test]
    fn a_send_after_a_refusal_for_room_names_who_fills_the_channel() {
        let mut s = devices(2);
        let t = s.now + MINUTE;
        for k in 0..3 {
            sent(
                &s,
                0,
                &asking("notes", Some("work"), &format!("{k}")),
                t + k,
            );
        }
        s.pass(0, 1);
        let request = asking("work", Some("notes"), "x");
        let quiet = sends(&s, 1, &request, s.now + MINUTE).unwrap();
        assert_eq!(quiet.filled_by, None);
        let channel = messages_channel(&s[1].conn).unwrap().unwrap();
        let full = send_of(
            &s[1].conn,
            &s[1].identity,
            &request,
            &at(s.now + 2 * MINUTE),
            |refused| *refused == channel,
        )
        .unwrap();
        assert_eq!(full.filled_by, Some(("device 0".into(), 3)));
    }
}
