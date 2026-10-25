//! The local API of messages between the person's own agents (decision
//! 2026-10-09 §4.2): the routes behind `cordelia msg summary`, `msg read`,
//! `msg send` and `msg log`, each a POST with a JSON body, each behind the
//! node's token.
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
//!   within the time the command gives it. It marks nothing announced:
//!   the command says which lines it printed ([`announced_of`]).
//! - **`read`** ([`read_of`]) gives places, finds the one message an ID
//!   names ([`named`]), and marks it read by the folder's agent.
//! - **`send`** ([`send_of`]) gives [`sender::send`] what it needs, and the
//!   lookup of the message a reply answers ([`answering`]), which it calls
//!   at step 9.
//! - **`log`** ([`log_of`]) gives places, lists the messages of the
//!   folder's agent, or of every name, that no person has read on any
//!   device that counts (decision 2026-10-25, rule 1), and counts those a
//!   person has, by where they were read, with what is counted of each
//!   signer and of the device's own messages, and marks read by a person
//!   what the command printed, after a yes, writing the device's list of a
//!   person's reads in the same write: the act that ends a hold, on every
//!   device (§6, §7.2).
//! - **`allow`** ([`allow_of`], decision 2026-10-25, rule 2) answers the
//!   look of a pair, and sets a bound for it after a yes: the other act of
//!   a person at a terminal.
//!
//! **Text that another device chose** is cleaned by one function
//! ([`cleaned`]): the set of §4.1, seven Unicode general categories and
//! the characters that render as nothing, is taken out of a name, a label, a subject and a link, and a body's are shown
//! as escapes by the command ([`taken_out`]).

use std::cell::RefCell;
use std::collections::HashSet;
use std::time::{Duration, Instant};

use actix_web::{HttpRequest, HttpResponse, web};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{Value, json};

use cordelia_core::protocol::{
    AGENT_MESSAGE_BODY_MAX_BYTES, AGENT_MESSAGE_ID_BYTES, AGENT_MESSAGE_ID_SHOWN_CHARS,
    AGENT_MESSAGE_SUBJECT_CHARS, AGENT_MESSAGE_SUMMARY_LINES, AGENT_MESSAGE_SUMMARY_WAIT_MS,
};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::message::{To, is_a_link};
use cordelia_crypto::{derive, fingerprint};
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
/// (decision 2026-10-09 §4.1, C5, C6), in one write: places are given.
/// **It marks nothing announced:** the command prints only an answer that
/// came within its time, so it is the command that says which lines it
/// printed ([`announced_of`]). **It opens no entry:** it reads the index
/// and the marks. `None` where it prints nothing: the folder is not
/// mapped, sync is off, the device does not stand applied or has no place
/// for messages, or nothing is unread.
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
        for message in marks::unread(conn, identity, &name, now, &counting)? {
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

/// Marks announced to the agent of `folder` on this device each of `ids`
/// that is a message `summary` could answer a line of: one to that agent's
/// name, unread by it, from a signer that counts (decision 2026-10-09
/// §4.1, §7.2, rule 14). The command says which lines it printed, after it
/// printed them. Nothing where the folder is not mapped, sync is off, or
/// the device does not stand applied or has no place for messages. How
/// many it marked.
pub fn announced_of(
    conn: &Connection,
    identity: &NodeIdentity,
    own_channels: &OwnChannels,
    folder: &str,
    ids: &[Id],
    now: i64,
) -> Result<usize, PersonError> {
    in_one(conn, || {
        let Some(name) = agent_of(conn, folder).map_err(said)? else {
            return Ok(0);
        };
        if meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_none()
            || stands(conn)? != Stands::Applied
            || own_channels.no_place()
        {
            return Ok(0);
        }
        let counting = who_counts(conn)?;
        let mut marked = 0;
        for message in marks::unread(conn, identity, &name, now, &counting)? {
            let id = id_of(&message.id)?;
            if message.to.is_none()
                || !ids.contains(&id)
                || !counting.counts(&key_of(&message.signer)?)
            {
                continue;
            }
            kept(held::announce(conn, &id, &name))?;
            marked += 1;
        }
        Ok(marked)
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
/// every millisecond, and `None` where it was not. Time spent waiting
/// counts as no answer. It waits without holding the worker, which serves
/// other requests meanwhile. Its wait is recorded from its first try, and
/// a give-up is counted, for the scale test's bar 5 (decision 2026-10-22
/// §1.2).
async fn db_by(
    state: &AppState,
    deadline: Instant,
) -> Option<cordelia_core::lock::TimedGuard<'_, Connection>> {
    let pause = || actix_web::rt::time::sleep(Duration::from_millis(1));
    state.db.try_lock_until(deadline, pause).await
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
    lists_read(&db, &state);
    let now = state.sync_control.now();
    match summary_of(&db, &state.identity, &state.own_channels, &body.folder, now) {
        Ok(Some(summary)) => Ok(HttpResponse::Ok().json(summary.answered())),
        _ => Ok(nothing()),
    }
}

#[derive(Deserialize)]
pub struct AnnouncedRequest {
    /// The directory the command worked out (§3.1).
    pub folder: String,
    /// The IDs of the lines the command printed, each whole.
    pub ids: Vec<String>,
    /// The command's version: a node of another marks nothing.
    pub version: String,
}

// ── POST /api/v1/messages/announced ──────────────────────────────────

/// Whether `id` is a message's ID whole, as the command sends it: 32
/// lower-case hex characters.
fn is_whole(id: &str) -> bool {
    id.len() == 2 * AGENT_MESSAGE_ID_BYTES
        && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// What `cordelia msg summary` printed (decision 2026-10-09 §4.1, §7.2):
/// the command says it after it printed the lines of an answer that came
/// within its time, and the node marks them announced ([`announced_of`]).
/// It answers nothing, whatever it marked: the command does not wait on
/// it past its 100 ms, and prints nothing more. More IDs than a summary
/// has lines, or one that is not an ID whole in lower-case hex, mark
/// nothing. It tries the
/// store's lock as `summary` does, without holding the worker, for at
/// most the summary's 100 ms, and marks nothing where it did not have it
/// (C20).
pub async fn announced(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<AnnouncedRequest>,
) -> Result<HttpResponse, ApiError> {
    let deadline = Instant::now() + summary_wait(AGENT_MESSAGE_SUMMARY_WAIT_MS);
    match asked(&req, &state) {
        Ok(()) => {}
        Err(ApiError::Unauthorized) => return Err(ApiError::Unauthorized),
        Err(_) => return Ok(nothing()),
    }
    if body.version != env!("CARGO_PKG_VERSION") || body.ids.len() > AGENT_MESSAGE_SUMMARY_LINES {
        return Ok(nothing());
    }
    let Some(ids) = body
        .ids
        .iter()
        .map(|id| match is_whole(id) {
            true => hex::decode(id).ok()?.try_into().ok(),
            false => None,
        })
        .collect::<Option<Vec<Id>>>()
    else {
        return Ok(nothing());
    };
    let Some(db) = db_by(&state, deadline).await else {
        return Ok(nothing());
    };
    let now = state.sync_control.now();
    let _ = announced_of(
        &db,
        &state.identity,
        &state.own_channels,
        &body.folder,
        &ids,
        now,
    );
    Ok(nothing())
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
    /// here, and how many of them no person has read on any device that
    /// counts.
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
    let standing = Standing::of(conn)?;
    // Read by a person on any device that counts (decision 2026-10-25,
    // rule 1.3).
    let person = marks::person_read_now(conn, &standing.counting)?;
    let mut pair_count = 0;
    let mut pair_unread_by_a_person = 0;
    for other in shown.iter().filter(|other| pair_of(other) == pair) {
        pair_count += 1;
        if !person.is_read(&id_of(&other.id)?) {
            pair_unread_by_a_person += 1;
        }
    }
    let statement = &standing.held.statement.statement;
    let mut read_on = Vec::new();
    // A device keeps no list of its own beside its table: every key here
    // is another device's.
    for key in marks::read_on(conn, &id, &name, &standing.counting)?.devices {
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
        lists_read(&db, &state);
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
/// where a relay refused it for room ([`room_of`]).
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
    // The message is sent: what is not known of the room is no refusal.
    let filled_by = match room_of(conn, &identity.public_key(), at.now, no_room) {
        Ok(room) => room.filled_by,
        Err(e) => {
            tracing::warn!("messages: a message was sent, and its room is not known: {e}");
            None
        }
    };
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

/// What a relay refused of the messages channel for room, as `send`,
/// `log` and the status say it ([`room_of`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Room {
    /// The device's own messages whose entry a relay had no room for, and
    /// that wait to be sent there again, in order of ID.
    pub refused: Vec<Id>,
    /// The signer whose entries fill the channel, with how many of them
    /// the device holds: where a relay refused the channel for room.
    pub filled_by: Option<(String, u64)>,
}

/// What a relay refused of the messages channel of the generation applied
/// for room (decision 2026-10-09 §4.1, §10, C15): the messages of this
/// device's own, signed by `own`, that wait refused at a relay at `now`;
/// and, where a relay refused the channel for room since the node started
/// (`no_room`, of the channel's ID) or such a message waits, the signer
/// whose entries fill the channel, by the count of entries of each author
/// that the device holds of it, with that count.
pub fn room_of(
    conn: &Connection,
    own: &[u8; 32],
    now: i64,
    no_room: impl FnOnce(&[u8; 32]) -> bool,
) -> Result<Room, PersonError> {
    let Some(channel) = messages_channel(conn)? else {
        return Ok(Room::default());
    };
    // A list's revision says nothing of a number: its slot is passed over.
    let secret = derive::messages_secret(&Standing::to_write(conn)?.secret)?;
    let list_slot = cordelia_crypto::slots::slot_id(
        &derive::slot_key(&secret)?,
        &cordelia_crypto::message::read_name(own)?,
    );
    let refused = kept(held::refused_for_room(conn, &channel, &list_slot, now))?;
    if !no_room(&channel) && refused.is_empty() {
        return Ok(Room::default());
    }
    let Some((author, entries)) = kept(held::entries_by_author(conn, &channel))?
        .into_iter()
        .next()
    else {
        return Ok(Room {
            refused,
            filled_by: None,
        });
    };
    let standing = Standing::of(conn)?;
    let label = crate::reader::label_of(conn, &standing.held.statement.statement, &author)?;
    Ok(Room {
        refused,
        filled_by: Some((label, entries)),
    })
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
        lists_read(&db, &state);
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

// ── The status ───────────────────────────────────────────────────────

/// What the status says of messages (decision 2026-10-09 §8, C13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counts {
    /// For each mapped folder, the messages unread by its agent (§7.2): a
    /// message to every name once for each folder.
    pub unread_by_an_agent: u64,
    /// The messages to a name mapped here or to every name, not sent
    /// here, that no person has read on any device that counts (decision
    /// 2026-10-25, rule 1).
    pub unread_by_a_person: u64,
    /// Each bound in force that is not the usual hold (decision
    /// 2026-10-25, rule 4).
    pub bounds: Vec<BoundSaid>,
    /// This device's messages that wait to be sent.
    pub waiting: u64,
    /// Of those, the ones a relay refused for room.
    pub refused_for_room: u64,
    /// The signer whose entries fill the channel where a relay refused it
    /// for room, by its label, with the count of its entries (§10).
    pub filled_by: Option<(String, u64)>,
    /// Held back by the reader's hour (§6).
    pub held_back: u64,
    /// Overwritten before they were shown (§2.5).
    pub overwritten: u64,
    /// The device has no place for messages (§2.1).
    pub no_place: bool,
}

/// The `messages` object of the status at `now` by the node's clock
/// (decision 2026-10-09 §8, C13), in one write: working it out gives
/// places, as a show does (§6). `None` where the device does not stand
/// applied: the object is absent then.
///
/// **It is said nowhere but here.** Nothing of it feeds the level, the
/// holds or the line, which a command works out from facts that pass
/// over the messages channel.
///
/// What is shown is what a show would show: a message from a signer that
/// no longer counts is shown by `log` alone (§9.1), and is not counted as
/// unread by an agent, whose summary never shows it.
pub fn status_of(
    conn: &Connection,
    identity: &NodeIdentity,
    own_channels: &OwnChannels,
    now: i64,
) -> Result<Option<Counts>, PersonError> {
    in_one(conn, || {
        let Some(channel) = messages_channel(conn)? else {
            return Ok(None);
        };
        let own = identity.public_key();
        kept(held::give_places(conn, &own, now))?;
        let counting = who_counts(conn)?;
        let names: Vec<String> = crate::sync::mappings(conn)
            .map_err(said)?
            .into_iter()
            .map(|mapping| mapping.name)
            .collect();
        // What is shown is read once, who counts worked out once, and the
        // marks read once, for the whole object: its cost grows with the
        // messages and with the names, and not with the two multiplied by
        // a read of the store.
        let read = marks::read_now(conn, &counting)?;
        let person = marks::person_read_now(conn, &counting)?;
        let mut unread_by_an_agent = 0;
        let mut unread_by_a_person = 0;
        for message in kept(held::shown(conn, now))? {
            let id = id_of(&message.id)?;
            if counting.counts(&key_of(&message.signer)?) {
                for name in &names {
                    if marks::is_for(&message, &own, name) && !read.is_read(&id, name) {
                        unread_by_an_agent += 1;
                    }
                }
            }
            let to_here = message
                .to
                .as_ref()
                .is_none_or(|to| names.iter().any(|name| name == to));
            if to_here && message.signer[..] != own[..] && !person.is_read(&id) {
                unread_by_a_person += 1;
            }
        }
        let room = room_of(conn, &own, now, |channel| {
            own_channels.no_room_for_messages(channel)
        })?;
        let bounds = bounds_said(conn, &own, &counting, now)?;
        Ok(Some(Counts {
            unread_by_an_agent,
            unread_by_a_person,
            bounds,
            waiting: match kept(held::generation_of(conn, &channel))? {
                Some(generation) => kept(held::kept_count(conn, generation, now))?,
                None => 0,
            },
            refused_for_room: room.refused.len() as u64,
            filled_by: room.filled_by,
            held_back: kept(held::held_back_in_all(conn, now))?,
            overwritten: kept(held::overwritten_in_all(conn))?,
            no_place: own_channels.no_place(),
        }))
    })
}

impl Counts {
    /// As the status answers it.
    pub fn answered(&self) -> Value {
        let filled_by = self
            .filled_by
            .as_ref()
            .map(|(label, entries)| json!({ "label": label, "entries": entries }));
        let bounds: Vec<Value> = self.bounds.iter().map(BoundSaid::answered).collect();
        json!({
            "unread_by_an_agent": self.unread_by_an_agent,
            "unread_by_a_person": self.unread_by_a_person,
            "bounds": bounds,
            "waiting": self.waiting,
            "refused_for_room": self.refused_for_room,
            "filled_by": filled_by,
            "held_back": self.held_back,
            "overwritten": self.overwritten,
            "no_place": self.no_place,
        })
    }
}

/// A bound in force that is not the usual hold, as the status says it
/// (decision 2026-10-25, rule 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundSaid {
    pub pair: crate::bounds::Pair,
    /// 1 to 64, or `None` for any.
    pub bound: Option<u8>,
    /// When it ends, by the node's clock.
    pub until: i64,
    /// The label and the fingerprint's words of the device it was set on,
    /// or `None` where it is this device.
    pub set_on: Option<(String, String)>,
}

impl BoundSaid {
    /// As the status answers it: `a`, `b` (null for every agent), `bound`
    /// (null for any), `until` in RFC 3339, and `set_on`.
    pub fn answered(&self) -> Value {
        json!({
            "a": self.pair.a,
            "b": self.pair.b,
            "bound": self.bound,
            "until": rfc3339(self.until),
            "set_on": set_on(&self.set_on),
        })
    }
}

/// A moment by the node's clock in RFC 3339.
fn rfc3339(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// The device a bound was set on, as a route says it: `"this"`, or its
/// label and fingerprint.
fn set_on(on: &Option<(String, String)>) -> Value {
    match on {
        None => json!("this"),
        Some((label, fingerprint)) => json!({ "label": label, "fingerprint": fingerprint }),
    }
}

/// The device whose key is `key`, as [`BoundSaid::set_on`] holds it.
fn device_of(
    conn: &Connection,
    own: &[u8; 32],
    key: &[u8; 32],
) -> Result<Option<(String, String)>, PersonError> {
    if key == own {
        return Ok(None);
    }
    let standing = Standing::of(conn)?;
    let label = signer_label(conn, &standing.held.statement.statement, key)?;
    Ok(Some((label, fingerprint::shown(key))))
}

/// Each bound in force at `now` that is not the usual hold, with the
/// device it was set on (decision 2026-10-25, rule 4).
fn bounds_said(
    conn: &Connection,
    own: &[u8; 32],
    counting: &crate::person::Counting,
    now: i64,
) -> Result<Vec<BoundSaid>, PersonError> {
    let mut said = Vec::new();
    for (pair, in_force) in crate::bounds::set_now(conn, own, counting, now)? {
        if let crate::bounds::InForce::Set { bound, until, on } = in_force {
            said.push(BoundSaid {
                pair,
                bound,
                until,
                set_on: device_of(conn, own, &on)?,
            });
        }
    }
    Ok(said)
}

// ── log ──────────────────────────────────────────────────────────────

/// One message as `log` lists it (decision 2026-10-09 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logged {
    pub id: Id,
    /// The thread it is in: its `thread`, or its own ID where that is
    /// zeros.
    pub thread: Id,
    /// The whole name of the agent it is from, and of the one it is to
    /// (`None` for every name).
    pub from: String,
    pub to: Option<String>,
    /// The label the device knows the signer by, or `None` where it is
    /// this device.
    pub label: Option<String>,
    /// The fingerprint's words of the signer.
    pub fingerprint: String,
    /// Its shown time, and how long before the node's clock that was.
    pub shown_at: i64,
    pub ago_secs: i64,
    /// It is of a generation before the one the device stands under.
    pub before_the_last_change: bool,
    /// Its signer no longer counts: `log` alone lists it.
    pub signer_removed: bool,
    /// What it says, and what is said of it here; `None` where it has no
    /// place yet, held back by the reader's hour, and, where a folder is
    /// given, where its signer no longer counts.
    pub said: Option<Said>,
}

/// What `log` shows of a message that has a place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Said {
    pub asks: bool,
    pub link: Option<String>,
    pub body: String,
    /// The labels of the devices that count whose latest list says that an
    /// agent read it, worked out now (§7.2), in order of key.
    pub read_on: Vec<String>,
    /// This device's own table says that an agent here read it.
    pub read_here: bool,
}

/// What `log` counts of one signer, across the generations the device
/// holds (decision 2026-10-09 §2.2, §2.5, §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counted {
    /// The label the device knows it by, or `None` where it is this
    /// device; and its fingerprint's words.
    pub label: Option<String>,
    pub fingerprint: String,
    pub overwritten: u64,
    pub not_messages: u64,
    pub held_back: u64,
}

/// What `log` answers (decision 2026-10-09 §4.1, §4.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Log {
    /// The folder's agent, or `None` where every name is listed.
    pub name: Option<String>,
    /// Each thread, newest first by the shown time of its newest message,
    /// with its messages oldest first: only the messages that no person
    /// has read on any device that counts.
    pub threads: Vec<(Id, Vec<Logged>)>,
    /// How many messages it would list but that a person has read: they
    /// are not listed (decision 2026-10-09 §4.1).
    pub already_read: usize,
    /// Where a person read them (decision 2026-10-25, rule 1): this device
    /// first, as `None`, and then each device by its label and its
    /// fingerprint's words, in order of label, each with its count. A
    /// message read here and elsewhere counts as here; one read on two
    /// other devices counts under the first label, in order of label.
    pub already_read_on: Vec<(Option<(String, String)>, usize)>,
    /// What is counted of each signer that has anything counted, in order
    /// of key.
    pub signers: Vec<Counted>,
    /// The device's own messages that wait to be sent, that a relay had no
    /// room for, and the signer that fills the channel (§10).
    pub waiting: Vec<Id>,
    pub room: Room,
    /// The device's own messages whose kept value was dropped before every
    /// relay took it (§2.3).
    pub not_every_relay: Vec<Id>,
    /// The device's own messages of a generation before the one it stands
    /// under: they may not have reached every device (§9.1).
    pub not_every_device: Vec<Id>,
    /// How many were marked read by a person.
    pub marked: usize,
    /// The revision of the list of a person's reads written after them,
    /// where one was.
    pub list: Option<u64>,
    /// Whether sync is on: where it is off, the other devices hear of what
    /// was marked once it is on.
    pub sync_on: bool,
}

/// What a request asks of `log`.
#[derive(Debug, Clone, Copy)]
pub struct LogAsked<'a> {
    /// The folder the command was run in, or `None` for every name: only
    /// where its input and its output are both terminals.
    pub folder: Option<&'a str>,
    /// Only messages shown at this time or after, in seconds.
    pub since: Option<i64>,
    /// The messages to mark read by a person: those the command printed.
    pub mark: &'a [Id],
    /// Whether the messages channel was fetched since the node started:
    /// the list of a person's reads is written only after (decision
    /// 2026-10-25, rule 1).
    pub fetched: bool,
}

/// The names whose agents may have read a message to every name: each
/// that the personal channel lists, and each mapped here.
fn every_name(conn: &Connection) -> Result<Vec<String>, PersonError> {
    let mut names: Vec<String> = crate::names::listed(conn)?
        .into_iter()
        .map(|listed| listed.name)
        .collect();
    names.extend(
        crate::sync::mappings(conn)
            .map_err(said)?
            .into_iter()
            .map(|mapping| mapping.name),
    );
    names.sort();
    names.dedup();
    Ok(names)
}

/// `log` at `now` by the node's clock (decision 2026-10-09 §4.1, §4.2,
/// §7.2), in one write. The checks are made in the record's order: the
/// device (step 4), then, where a folder is given, the folder (step 7).
/// Places are given first, as at every show.
///
/// It lists every message of the folder's agent, or of every name where
/// none is given, that no person has read here: those addressed to its
/// name or to every name, and those it sent here, as `read` reaches them;
/// a message whose signer no longer counts among them, which `log` alone
/// lists. One that a person here has read is not listed, and is counted
/// in `already_read`. A message held back by the reader's hour is listed
/// without what it says, and so, where a folder is given, is one whose
/// signer no longer counts. Whether an agent read a message is worked out
/// now, from the device's own table and the latest list of each device
/// that counts, so a device that lies in its list hides nothing from
/// `log`.
///
/// **Where `mark` is not empty,** each message whose ID is in it and that
/// it lists with a place is marked read by a person here, and no other:
/// a message that arrived after the command printed, or that it printed
/// as held back, is not in it.
pub fn log_of(
    conn: &Connection,
    identity: &NodeIdentity,
    asked: &LogAsked,
    now: i64,
    no_room: impl FnOnce(&[u8; 32]) -> bool,
) -> Result<Log, NotRead> {
    // A set, made before the write: each ID shown is looked up in it once.
    let mark: HashSet<Id> = asked.mark.iter().copied().collect();
    in_one(conn, || {
        Ok(match log_in(conn, identity, asked, &mark, now, no_room) {
            Err(NotRead::Failed(e)) => return Err(e),
            done => done,
        })
    })?
}

fn log_in(
    conn: &Connection,
    identity: &NodeIdentity,
    asked: &LogAsked,
    mark: &HashSet<Id>,
    now: i64,
    no_room: impl FnOnce(&[u8; 32]) -> bool,
) -> Result<Log, NotRead> {
    if stands(conn)? != Stands::Applied {
        return Err(NotRead::Refused(Refused::NotApplied));
    }
    let name = match asked.folder {
        Some(folder) => match agent_of(conn, folder).map_err(said)? {
            Some(name) => Some(name),
            None => return Err(NotRead::Refused(Refused::NotMapped)),
        },
        None => None,
    };
    let own = identity.public_key();
    kept(held::give_places(conn, &own, now))?;
    let counting = who_counts(conn)?;
    let standing = Standing::of(conn)?;
    let statement = &standing.held.statement.statement;
    // Read by a person on any device that counts (decision 2026-10-25,
    // rule 1.3), worked out once, after what is marked here.
    let mut person: Option<marks::PersonRead> = None;
    let current = match messages_channel(conn)? {
        Some(channel) => kept(held::generation_of(conn, &channel))?,
        None => None,
    };
    let of_the_agent = |signer: &[u8], from: &str, to: Option<&str>| match &name {
        None => true,
        Some(name) => {
            let its_own = signer == own && from == name;
            its_own || to.is_none_or(|to| to == name)
        }
    };
    let names = every_name(conn)?;

    let mut listed = Vec::new();
    let shown = kept(held::shown(conn, now))?;
    let mut marked = 0;
    for message in &shown {
        if !of_the_agent(&message.signer, &message.from, message.to.as_deref()) {
            continue;
        }
        let id = id_of(&message.id)?;
        if mark.contains(&id) {
            kept(held::mark_read_by_a_person(conn, &id))?;
            marked += 1;
        }
    }
    // What was marked is said to the other devices in the same write,
    // where it may be (decision 2026-10-25, rule 1).
    let list = match marked {
        0 => None,
        _ => marks::person_list_written(conn, identity, now, asked.fetched, None)?,
    };
    let person = person.insert(marks::person_read_now(conn, &counting)?);
    let mut already_read = 0;
    let mut read_where: Vec<(Option<String>, Option<[u8; 32]>)> = Vec::new();
    for message in &shown {
        if !of_the_agent(&message.signer, &message.from, message.to.as_deref()) {
            continue;
        }
        let id = id_of(&message.id)?;
        if asked.since.is_some_and(|since| message.shown_at < since) {
            continue;
        }
        // What a person has read, here or on a device that counts, is
        // counted by where, and not listed again.
        let on = person.on(&id);
        if on.is_read() {
            already_read += 1;
            match on.here {
                true => read_where.push((None, None)),
                false => {
                    let mut labels = Vec::new();
                    for key in &on.devices {
                        labels.push((signer_label(conn, statement, key)?, *key));
                    }
                    labels.sort();
                    let (label, key) = labels.swap_remove(0);
                    read_where.push((Some(label), Some(key)));
                }
            }
            continue;
        }
        // Away from a terminal, nothing that such a signer wrote.
        if name.is_some() && !counting.counts(&key_of(&message.signer)?) {
            listed.push(logged_of(
                message.id.as_slice(),
                message.signer.as_slice(),
                &message.label,
                &message.thread,
                (&message.from, message.to.as_deref()),
                message.shown_at,
                now,
                current != Some(message.generation),
                None,
                &own,
                &counting,
            )?);
            continue;
        }
        let mut read_on: Vec<[u8; 32]> = Vec::new();
        let mut read_here = false;
        let read_by: Vec<&str> = match &message.to {
            Some(to) => vec![to.as_str()],
            None => names.iter().map(String::as_str).collect(),
        };
        for name in read_by {
            let on = marks::read_on(conn, &id, name, &counting)?;
            read_here |= on.here;
            for key in on.devices {
                if !read_on.contains(&key) {
                    read_on.push(key);
                }
            }
        }
        read_on.sort();
        let mut labels = Vec::new();
        for key in &read_on {
            labels.push(crate::reader::label_of(conn, statement, key)?);
        }
        listed.push(logged_of(
            message.id.as_slice(),
            message.signer.as_slice(),
            &message.label,
            &message.thread,
            (&message.from, message.to.as_deref()),
            message.shown_at,
            now,
            current != Some(message.generation),
            Some(Said {
                asks: message.asks,
                link: message.link.clone(),
                body: message.body.clone(),
                read_on: labels,
                read_here,
            }),
            &own,
            &counting,
        )?);
    }
    for message in kept(held::waiting_for_places(conn, now))? {
        if !of_the_agent(&message.signer, &message.from, message.to.as_deref())
            || asked.since.is_some_and(|since| message.shown_at < since)
        {
            continue;
        }
        listed.push(logged_of(
            &message.id,
            &message.signer,
            &message.label,
            &message.thread,
            (&message.from, message.to.as_deref()),
            message.shown_at,
            now,
            current != Some(message.generation),
            None,
            &own,
            &counting,
        )?);
    }

    // Threads newest first by the shown time of their newest message, and
    // in each the messages oldest first, by shown time and then by ID.
    listed.sort_by_key(|message| (message.shown_at, message.id));
    let mut threads: Vec<(Id, Vec<Logged>)> = Vec::new();
    for message in listed {
        match threads
            .iter_mut()
            .find(|(thread, _)| *thread == message.thread)
        {
            Some((_, messages)) => messages.push(message),
            None => threads.push((message.thread, vec![message])),
        }
    }
    let newest = |messages: &[Logged]| messages.iter().map(|m| (m.shown_at, m.id)).max();
    threads.sort_by(|(a, of_a), (b, of_b)| (newest(of_b), b).cmp(&(newest(of_a), a)));

    // What is counted of each signer, across the generations held.
    let mut signers: Vec<([u8; 32], Counted)> = Vec::new();
    for (key, generation, signer) in kept(held::signers(conn))? {
        let held_back = kept(held::held_back(conn, &key, generation, now))?;
        let counted = match signers.iter_mut().find(|(of, _)| *of == key) {
            Some((_, counted)) => counted,
            None => {
                let label = match key == own {
                    true => None,
                    false => Some(signer_label(conn, statement, &key)?),
                };
                signers.push((
                    key,
                    Counted {
                        label,
                        fingerprint: fingerprint::shown(&key),
                        overwritten: 0,
                        not_messages: 0,
                        held_back: 0,
                    },
                ));
                &mut signers.last_mut().expect("just pushed").1
            }
        };
        counted.overwritten += signer.overwritten;
        counted.not_messages += signer.not_messages;
        counted.held_back += held_back;
    }
    let signers = signers
        .into_iter()
        .map(|(_, counted)| counted)
        .filter(|c| c.overwritten + c.not_messages + c.held_back > 0)
        .collect();

    // The device's own, of the folder's agent where one is given.
    let own_of_the_agent = |id: &Id| match &name {
        None => true,
        Some(name) => shown
            .iter()
            .any(|m| m.id[..] == id[..] && m.signer[..] == own[..] && m.from == *name),
    };
    let room = room_of(conn, &own, now, no_room)?;
    let waiting = kept(held::kept(conn))?
        .into_iter()
        .filter(|kept| Some(kept.generation) == current && !room.refused.contains(&kept.id))
        .map(|kept| kept.id)
        .filter(own_of_the_agent)
        .collect();
    let room = Room {
        refused: room.refused.into_iter().filter(own_of_the_agent).collect(),
        filled_by: room.filled_by,
    };
    let not_every_relay = kept(held::not_every_relay(conn, &own))?
        .into_iter()
        .filter(own_of_the_agent)
        .collect();
    let mut not_every_device = Vec::new();
    for message in &shown {
        if message.signer[..] == own[..] && current != Some(message.generation) {
            let id = id_of(&message.id)?;
            if own_of_the_agent(&id) {
                not_every_device.push(id);
            }
        }
    }
    // This device first, then each label in its order, each once.
    read_where.sort();
    let mut already_read_on: Vec<(Option<(String, String)>, usize)> = Vec::new();
    for (label, key) in read_where {
        let device = label.zip(key.map(|key| fingerprint::shown(&key)));
        match already_read_on.last_mut() {
            Some((last, count))
                if last.as_ref().map(|(label, _)| label)
                    == device.as_ref().map(|(label, _)| label) =>
            {
                *count += 1
            }
            _ => already_read_on.push((device, 1)),
        }
    }
    Ok(Log {
        name,
        threads,
        already_read,
        already_read_on,
        signers,
        waiting,
        room,
        not_every_relay,
        not_every_device,
        marked,
        list,
        sync_on: meta::get(conn, meta::SYNC_CLAUDE_DIR)
            .map_err(PersonError::from)?
            .is_some(),
    })
}

/// The label that this device knows `key` by, or, where it knows none
/// (a device removed since), the one an index row of it was written with.
fn signer_label(
    conn: &Connection,
    statement: &cordelia_crypto::statement::Statement,
    key: &[u8; 32],
) -> Result<String, PersonError> {
    let label = crate::reader::label_of(conn, statement, key)?;
    if !label.is_empty() {
        return Ok(label);
    }
    Ok(kept(held::label_held(conn, key))?.unwrap_or_default())
}

/// One message as `log` lists it, from what the index holds of it.
#[allow(clippy::too_many_arguments)]
fn logged_of(
    id: &[u8],
    signer: &[u8],
    label: &str,
    thread: &[u8],
    (from, to): (&str, Option<&str>),
    shown_at: i64,
    now: i64,
    before_the_last_change: bool,
    said: Option<Said>,
    own: &[u8; 32],
    counting: &crate::person::Counting,
) -> Result<Logged, PersonError> {
    let id = id_of(id)?;
    let signer = key_of(signer)?;
    let thread = match id_of(thread) {
        Ok(thread) if thread != [0; AGENT_MESSAGE_ID_BYTES] => thread,
        _ => id,
    };
    Ok(Logged {
        id,
        thread,
        from: from.to_string(),
        to: to.map(String::from),
        label: (signer != *own).then(|| label.to_string()),
        fingerprint: fingerprint::shown(&signer),
        shown_at,
        ago_secs: now.saturating_sub(shown_at).max(0),
        before_the_last_change,
        signer_removed: !counting.counts(&signer),
        said,
    })
}

impl Log {
    /// The IDs of the messages it lists with what they say: those that
    /// the command prints with their bodies, and marks after a yes.
    pub fn printed(&self) -> Vec<Id> {
        self.threads
            .iter()
            .flat_map(|(_, messages)| messages)
            .filter(|message| message.said.is_some())
            .map(|message| message.id)
            .collect()
    }

    /// As the route answers it: each name whole, each ID whole.
    pub fn answered(&self) -> Value {
        let device = |label: &Option<String>, fingerprint: &str| match label {
            Some(label) => json!({ "label": label, "fingerprint": fingerprint }),
            None => json!("this"),
        };
        let ids = |ids: &[Id]| -> Vec<String> { ids.iter().map(hex::encode).collect() };
        let threads: Vec<Value> = self
            .threads
            .iter()
            .map(|(thread, messages)| {
                let messages: Vec<Value> = messages
                    .iter()
                    .map(|m| {
                        let mut said = json!({
                            "id": hex::encode(m.id),
                            "thread": hex::encode(m.thread),
                            "from": m.from,
                            "to": m.to,
                            "device": device(&m.label, &m.fingerprint),
                            "ago_secs": m.ago_secs,
                            "before_the_last_change": m.before_the_last_change,
                            "signer_removed": m.signer_removed,
                            "held_back": m.said.is_none()
                                && !(self.name.is_some() && m.signer_removed),
                        });
                        if let Some(shown) = &m.said {
                            said["asks"] = json!(shown.asks);
                            said["link"] = json!(shown.link);
                            said["body"] = json!(shown.body);
                            said["read_on"] = json!(shown.read_on);
                            said["read_here"] = json!(shown.read_here);
                        }
                        said
                    })
                    .collect();
                json!({ "thread": hex::encode(thread), "messages": messages })
            })
            .collect();
        let signers: Vec<Value> = self
            .signers
            .iter()
            .map(|c| {
                json!({
                    "device": device(&c.label, &c.fingerprint),
                    "overwritten": c.overwritten,
                    "not_messages": c.not_messages,
                    "held_back": c.held_back,
                })
            })
            .collect();
        let filled_by = self
            .room
            .filled_by
            .as_ref()
            .map(|(label, entries)| json!({ "label": label, "entries": entries }));
        let already_read_on: Vec<Value> = self
            .already_read_on
            .iter()
            .map(|(device, count)| json!({ "device": set_on(device), "count": count }))
            .collect();
        json!({
            "name": self.name,
            "threads": threads,
            "already_read": self.already_read,
            "already_read_on": already_read_on,
            "sync_on": self.sync_on,
            "signers": signers,
            "waiting": ids(&self.waiting),
            "refused_for_room": ids(&self.room.refused),
            "filled_by": filled_by,
            "not_every_relay": ids(&self.not_every_relay),
            "not_every_device": ids(&self.not_every_device),
            "marked": self.marked,
        })
    }
}

#[derive(Deserialize)]
pub struct LogRequest {
    /// The directory the command worked out (§3.1), or null for every
    /// name.
    pub folder: Option<String>,
    /// A time in RFC 3339, or null.
    pub since: Option<String>,
    /// The whole IDs of the messages to mark read by a person, in hex.
    #[serde(default)]
    pub mark: Vec<String>,
}

/// A whole message's ID from its 32 hex characters.
fn whole_id(given: &str) -> Option<Id> {
    let bytes = hex::decode(given).ok()?;
    bytes.try_into().ok()
}

// ── POST /api/v1/messages/log ────────────────────────────────────────

/// `cordelia msg log` (decision 2026-10-09 §4.1, §4.2). What the command
/// checks alone is checked again: a `since` that is no time, and an ID to
/// mark that is not whole, are refused before anything.
pub async fn log(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<LogRequest>,
) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    let since = match &body.since {
        Some(since) => match chrono::DateTime::parse_from_rfc3339(since) {
            Ok(at) => Some(at.timestamp()),
            Err(_) => {
                return Err(ApiError::BadRequest(format!("{since} is not a time")));
            }
        },
        None => None,
    };
    let mut mark = Vec::new();
    for given in &body.mark {
        match whole_id(given) {
            Some(id) => mark.push(id),
            None => {
                return Err(ApiError::BadRequest(format!(
                    "{given} is not a message's whole ID"
                )));
            }
        }
    }
    let now = state.sync_control.now();
    let db = db_of(&state);
    lists_read(&db, &state);
    let asked_of = LogAsked {
        folder: body.folder.as_deref(),
        since,
        mark: &mark,
        fetched: sender::fetched(&db, &state.own_channels, Instant::now()).map_err(refused)?,
    };
    let no_room = |channel: &[u8; 32]| state.own_channels.no_room_for_messages(channel);
    match log_of(&db, &state.identity, &asked_of, now, no_room) {
        Ok(log) => {
            // A list written waits to be sent.
            if log.list.is_some() {
                state.own_channels.written();
            }
            Ok(HttpResponse::Ok().json(log.answered()))
        }
        Err(NotRead::Refused(why)) => refusal(&db, &why),
        Err(NotRead::Failed(e)) => Err(refused(e)),
    }
}

// ── allow ────────────────────────────────────────────────────────────

/// What a request asks of `allow` (decision 2026-10-25, rule 2).
#[derive(Debug, Deserialize)]
pub struct AllowRequest {
    pub a: String,
    /// The other name, or null for every agent.
    pub b: Option<String>,
    /// 1 to 64, or null for any.
    pub bound: Option<u8>,
    /// How long it holds: 60 to 604,800 seconds.
    pub for_secs: u32,
    /// False for the look; true sets it.
    #[serde(default)]
    pub yes: bool,
}

/// What `allow` answers ([`allow_of`]): the pair as it is spelt, the
/// look, and whether it was set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowSaid {
    pub pair: crate::bounds::Pair,
    pub bound: Option<u8>,
    pub allowed: crate::bounds::Allowed,
    /// The device the bound in force before was set on, where one was.
    pub was_on: Option<Option<(String, String)>>,
}

impl AllowSaid {
    /// As the route answers it: `a`, `b`, `bound`, `waiting`, `until` (by
    /// the node's clock, in seconds), `in_force` (null for the usual hold,
    /// or its `bound`, `until` and `set_on`), and `set`.
    pub fn answered(&self) -> Value {
        let in_force = match (&self.allowed.was, &self.was_on) {
            (crate::bounds::InForce::Set { bound, until, .. }, Some(on)) => {
                json!({ "bound": bound, "until": until, "set_on": set_on(on) })
            }
            _ => Value::Null,
        };
        json!({
            "a": self.pair.a,
            "b": self.pair.b,
            "bound": self.bound,
            "waiting": self.allowed.waiting,
            "until": self.allowed.until,
            "in_force": in_force,
            "set": self.allowed.set,
        })
    }
}

/// `allow` at `now` by the node's clock (decision 2026-10-25, rule 2): what
/// the command checks alone is checked again, before anything (a bound of
/// 1 to 64 or any, and a `for_secs` of 60 to 604,800); then
/// [`crate::bounds::allow`] makes the node's checks in their order, and
/// answers the look, or sets the bound after a yes. Nothing tells a person
/// from a program here: whoever holds the token is answered (rule 5).
pub fn allow_of(
    conn: &Connection,
    identity: &NodeIdentity,
    asked: &AllowRequest,
    now: i64,
    fetched: bool,
) -> Result<AllowSaid, NotSentHere> {
    use cordelia_core::protocol::{
        AGENT_MESSAGE_PAIR_BOUND_MAX_SECS, AGENT_MESSAGE_PAIR_BOUND_MIN_SECS, AGENT_MESSAGE_RING,
    };
    if asked
        .bound
        .is_some_and(|bound| bound == 0 || usize::from(bound) > AGENT_MESSAGE_RING)
    {
        return Err(NotSentHere::Asked(format!(
            "{} is not a number you can allow: give 1 to 64, or any",
            asked.bound.unwrap_or(0)
        )));
    }
    if !(AGENT_MESSAGE_PAIR_BOUND_MIN_SECS..=AGENT_MESSAGE_PAIR_BOUND_MAX_SECS)
        .contains(&asked.for_secs)
    {
        return Err(NotSentHere::Asked(format!(
            "{} seconds is not a time you can allow it for: give 60 to 604800",
            asked.for_secs
        )));
    }
    let pair = crate::bounds::Pair::of(&asked.a, asked.b.as_deref());
    let allow = crate::bounds::Allow {
        pair: pair.clone(),
        bound: asked.bound,
        for_secs: asked.for_secs,
    };
    let allowed = match crate::bounds::allow(conn, identity, &allow, now, fetched, asked.yes) {
        Ok(allowed) => allowed,
        Err(crate::bounds::AllowNot::Refused(why)) => return Err(NotSentHere::Refused(why)),
        Err(crate::bounds::AllowNot::Failed(e)) => return Err(NotSentHere::Failed(e)),
    };
    let was_on = match &allowed.was {
        crate::bounds::InForce::Set { on, .. } => {
            Some(device_of(conn, &identity.public_key(), on).map_err(NotSentHere::Failed)?)
        }
        crate::bounds::InForce::Usual => None,
    };
    Ok(AllowSaid {
        pair,
        bound: asked.bound,
        allowed,
        was_on,
    })
}

// ── POST /api/v1/messages/allow ──────────────────────────────────────

/// `cordelia msg allow` (decision 2026-10-25, rule 2): the look with `yes`
/// false, and the bound set with it true. A list of bounds written waits
/// to be sent as anything a device writes does.
pub async fn allow(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<AllowRequest>,
) -> Result<HttpResponse, ApiError> {
    asked(&req, &state)?;
    let now = state.sync_control.now();
    let db = db_of(&state);
    lists_read(&db, &state);
    let fetched = sender::fetched(&db, &state.own_channels, Instant::now()).map_err(refused)?;
    match allow_of(&db, &state.identity, &body, now, fetched) {
        Ok(said) => {
            if said.allowed.list.is_some() {
                state.own_channels.written();
            }
            Ok(HttpResponse::Ok().json(said.answered()))
        }
        Err(NotSentHere::Refused(why)) => refusal(&db, &why),
        Err(NotSentHere::Said(word, says)) => Ok(refused_with(word, &says, json!({}))),
        Err(NotSentHere::Asked(says)) => Err(ApiError::BadRequest(says)),
        Err(NotSentHere::Failed(e)) => Err(refused(e)),
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
        Refused::PairHeld {
            from,
            other,
            every,
            waiting,
            bound,
        } => {
            json!({ "from": from, "other": other, "every": every, "waiting": waiting,
                    "bound": bound })
        }
        Refused::BoundsFull(pairs) => {
            let pairs: Vec<Value> = pairs
                .iter()
                .map(|(pair, until)| json!({ "a": pair.a, "b": pair.b, "until": until }))
                .collect();
            json!({ "pairs": pairs })
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

/// The lists of a person's reads and of bounds that the store held from
/// before step 20 are read before any route of messages answers, where
/// they were not yet (decision 2026-10-25, rule 1). An error is logged:
/// the next asks again.
fn lists_read(db: &Connection, state: &AppState) {
    if let Err(e) = crate::reader::read_held_lists(db, &state.identity, state.sync_control.now()) {
        tracing::warn!(error = %e, "messages: could not read the lists held");
    }
}

fn db_of(state: &AppState) -> cordelia_core::lock::TimedGuard<'_, Connection> {
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

    /// Mark announced on device `n`, as the command does once it printed
    /// them, `ids` for the agent of the folder `name`: how many were.
    fn told_on(s: &Several, n: usize, name: &str, ids: &[Id], now: i64) -> usize {
        told_with(s, n, name, ids, now, &OwnChannels::default())
    }

    /// [`told_on`], with the device's own channels as `own_channels`.
    fn told_with(
        s: &Several,
        n: usize,
        name: &str,
        ids: &[Id],
        now: i64,
        own_channels: &OwnChannels,
    ) -> usize {
        announced_of(
            &s[n].conn,
            &s[n].identity,
            own_channels,
            &folder(name),
            ids,
            now,
        )
        .unwrap()
    }

    /// [`summary_on`], whose lines are then printed: the node is told them,
    /// as the command tells it.
    fn summary_told(s: &Several, n: usize, name: &str, now: i64) -> Option<Summary> {
        let summary = summary_on(s, n, name, now)?;
        let lines: Vec<Id> = summary.lines.iter().map(|line| line.id).collect();
        assert_eq!(told_on(s, n, name, &lines, now), lines.len());
        Some(summary)
    }

    fn reads(s: &Several, n: usize, name: &str, id: &str, now: i64) -> Result<Readout, Refused> {
        match read_of(&s[n].conn, &s[n].identity, &folder(name), id, now, true) {
            Ok((readout, _)) => Ok(readout),
            Err(NotRead::Refused(why)) => Err(why),
            Err(NotRead::Failed(e)) => panic!("{e}"),
        }
    }

    /// `log` on device `n` at `now`: of the agent of the folder `name`, or
    /// of every name where it is `None`, marking `mark`.
    fn log_on(
        s: &Several,
        n: usize,
        name: Option<&str>,
        mark: &[Id],
        now: i64,
    ) -> Result<Log, Refused> {
        let of = name.map(folder);
        let asked = LogAsked {
            folder: of.as_deref(),
            since: None,
            mark,
            fetched: true,
        };
        match log_of(&s[n].conn, &s[n].identity, &asked, now, |_| false) {
            Ok(log) => Ok(log),
            Err(NotRead::Refused(why)) => Err(why),
            Err(NotRead::Failed(e)) => panic!("{e}"),
        }
    }

    /// The IDs of the messages `log` lists, in the order it lists them.
    fn logged_ids(log: &Log) -> Vec<Id> {
        log.threads
            .iter()
            .flat_map(|(_, messages)| messages.iter().map(|message| message.id))
            .collect()
    }

    /// What `log` lists of message `id`.
    fn logged<'a>(log: &'a Log, id: &Id) -> &'a Logged {
        log.threads
            .iter()
            .flat_map(|(_, messages)| messages)
            .find(|message| message.id == *id)
            .unwrap_or_else(|| panic!("{} is not listed", hex::encode(id)))
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
        held_in(s, n, id, signer, (from, to), asks, times, number, [0; 16]);
    }

    /// [`held_as`], in the thread `thread`.
    #[allow(clippy::too_many_arguments)]
    fn held_in(
        s: &Several,
        n: usize,
        id: Id,
        signer: [u8; 32],
        (from, to): (&str, Option<&str>),
        asks: bool,
        times: (i64, i64),
        number: u64,
        thread: Id,
    ) {
        let conn = &s[n].conn;
        let channel = messages_channel(conn).unwrap().unwrap();
        let generation = held::generation(conn, &channel, s[n].number(), times.1).unwrap();
        held::hold_number(conn, &signer, generation, number, false, times.1).unwrap();
        let message = Message {
            asks,
            sent: times.0 as u64,
            nonce: [0; 16],
            thread,
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

        let first = summary_told(&s, 1, "work", now).unwrap();
        assert_eq!(first.name, "work");
        let lines: Vec<Id> = first.lines.iter().map(|line| line.id).collect();
        assert_eq!(lines, to_work[..5]);
        assert_eq!(first.waiting, [to_work[5], to_work[6], to_all]);
        assert!(!first.waiting.contains(&to_plans));
        assert_eq!(first.lines[0].from, "notes");
        assert_eq!(first.lines[0].subject, "0");
        assert_eq!(first.lines[0].label.as_deref(), Some("device 0"));

        // Announced, each is counted after.
        let second = summary_told(&s, 1, "work", now).unwrap();
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

    /// A summary answered marks nothing announced: its lines are answered
    /// again until the node is told that they were printed, and then are
    /// counted (decision 2026-10-09 §4.1, rule 14).
    #[test]
    fn a_summary_marks_nothing_until_it_is_told_what_was_printed() {
        let mut s = devices(2);
        // Sent before they are held, so each is shown from its `sent`.
        let t = s.now - 10 * MINUTE;
        let one = sent(&s, 0, &asking("notes", Some("work"), "one"), t);
        let two = sent(&s, 0, &asking("notes", Some("work"), "two"), t + 1);
        s.pass(0, 1);
        let now = s.now + MINUTE;
        let lines_of =
            |summary: Summary| -> Vec<Id> { summary.lines.iter().map(|line| line.id).collect() };
        // Answered, and not printed: answered again, line for line.
        for _ in 0..2 {
            let answered = summary_on(&s, 1, "work", now).unwrap();
            assert!(answered.waiting.is_empty());
            assert_eq!(lines_of(answered), [one, two]);
            assert!(!held::is_announced(&s[1].conn, &one, "work").unwrap());
        }
        // Told that one was printed: that one only is counted after.
        assert_eq!(told_on(&s, 1, "work", &[one], now), 1);
        assert!(held::is_announced(&s[1].conn, &one, "work").unwrap());
        let after = summary_on(&s, 1, "work", now).unwrap();
        assert_eq!(after.waiting, [one]);
        assert_eq!(lines_of(after), [two]);
    }

    /// The node marks announced only what a summary of that folder could
    /// have printed as a line: a message to that agent's name, unread by
    /// it. Not one to every name, to another name, read already, or none
    /// it holds; and nothing for a folder that is not mapped (decision
    /// 2026-10-09 §4.1, C5, C6).
    #[test]
    fn only_a_line_of_the_folders_agent_is_marked_announced() {
        let mut s = devices(2);
        let t = s.now + MINUTE;
        let to_work = sent(&s, 0, &asking("notes", Some("work"), "w"), t);
        let to_all = sent(&s, 0, &asking("notes", None, "all"), t + 1);
        let to_plans = sent(&s, 0, &asking("notes", Some("plans"), "p"), t + 2);
        let was_read = sent(&s, 0, &asking("notes", Some("work"), "r"), t + 3);
        s.pass(0, 1);
        let now = s.now + MINUTE;
        reads(&s, 1, "work", &hex::encode(was_read), now).unwrap();
        let not_held = [0x5a; 16];
        let given = [to_all, to_plans, was_read, not_held];
        assert_eq!(told_on(&s, 1, "work", &given, now), 0);
        assert_eq!(told_on(&s, 1, "unmapped", &[to_work], now), 0);
        for id in [to_work, to_all, to_plans, was_read] {
            assert!(!held::is_announced(&s[1].conn, &id, "work").unwrap());
        }
        // The plans line stays a line for plans.
        let plans = summary_on(&s, 1, "plans", now).unwrap();
        assert_eq!(plans.lines[0].id, to_plans);

        // A message from a signer that does not count is no line, and is
        // not marked.
        let not_counted = [0x99; 16];
        held_as(
            &s,
            1,
            not_counted,
            [9; 32],
            "notes",
            Some("work"),
            false,
            (now, now),
            1,
        );
        assert_eq!(told_on(&s, 1, "work", &[not_counted], now), 0);
        assert!(!held::is_announced(&s[1].conn, &not_counted, "work").unwrap());

        // Where `summary` would answer nothing, nothing is marked: sync
        // off, the device not standing applied, no place for messages.
        let sync_dir = meta::get(&s[1].conn, meta::SYNC_CLAUDE_DIR)
            .unwrap()
            .unwrap();
        meta::remove(&s[1].conn, meta::SYNC_CLAUDE_DIR).unwrap();
        assert_eq!(told_on(&s, 1, "work", &[to_work], now), 0);
        meta::set(&s[1].conn, meta::SYNC_CLAUDE_DIR, &sync_dir).unwrap();
        held_rows::set_state(&s[1].conn, State::Fork).unwrap();
        assert_eq!(told_on(&s, 1, "work", &[to_work], now), 0);
        held_rows::set_state(&s[1].conn, State::Applied).unwrap();
        let no_place = OwnChannels::default();
        no_place.say_no_place(true);
        assert_eq!(told_with(&s, 1, "work", &[to_work], now, &no_place), 0);
        assert!(!held::is_announced(&s[1].conn, &to_work, "work").unwrap());

        assert_eq!(told_on(&s, 1, "work", &[to_work], now), 1);
        assert!(held::is_announced(&s[1].conn, &to_work, "work").unwrap());
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

        // `log`: three of one thread, to plans, two of one shown time.
        let thread = [0x77; 16];
        let to_plans = |id: u8, times: (i64, i64), number: u64| {
            let signer = s.key(0);
            let to = ("notes", Some("plans"));
            held_in(&s, 1, [id; 16], signer, to, false, times, number, thread);
        };
        to_plans(0xe2, (t, t), 6);
        to_plans(0xe1, (t, t), 7);
        to_plans(0xe3, (t - 20, t + 30), 8);
        let log = log_on(&s, 1, None, &[], now).unwrap();
        // Threads newest first, by the shown time of their newest message;
        // in each, the messages oldest first, by shown time and then by ID.
        let threads: Vec<Id> = log.threads.iter().map(|(thread, _)| *thread).collect();
        assert_eq!(
            threads,
            [
                [0x10; 16], [0x05; 16], thread, [0xb0; 16], [0xa0; 16], [0xc0; 16]
            ]
        );
        let in_thread: Vec<Id> = log.threads[2].1.iter().map(|m| m.id).collect();
        assert_eq!(in_thread, [[0xe3; 16], [0xe1; 16], [0xe2; 16]]);
        // Each says how long ago from its shown time.
        assert_eq!(log.threads[2].1[0].ago_secs, now - (t - 20));
        assert_eq!(log.threads[1].1[0].ago_secs, now - (t + 1));
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
            assert!(summary_told(&s, 1, "work", now).is_some());
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
        let log_unmapped = LogAsked {
            folder: Some("/nowhere"),
            since: None,
            mark: &[],
            fetched: true,
        };
        assert!(matches!(
            log_of(&s[1].conn, &s[1].identity, &log_unmapped, now, |_| false),
            Err(NotRead::Refused(Refused::NotMapped))
        ));
        held_rows::set_state(&s[1].conn, State::Fork).unwrap();
        assert!(matches!(
            log_of(&s[1].conn, &s[1].identity, &log_unmapped, now, |_| false),
            Err(NotRead::Refused(Refused::NotApplied))
        ));
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

    // ── log ──────────────────────────────────────────────────────────

    /// With no folder `log` lists every message the device shows, of every
    /// name; given a folder, only those of its agent: addressed to its name
    /// or to every name, and those it sent on this device, as `read`
    /// reaches them (decision 2026-10-09 §3.1, §4.1, F3). Each is listed
    /// from the device that signed it, with whether it asks, and its body
    /// and link.
    #[test]
    fn log_lists_every_name_without_a_folder_and_the_folders_agent_with_one() {
        let mut s = devices(2);
        // Sent before they are held, so each is shown from its `sent`.
        let t = s.now - 10 * MINUTE;
        let to_work = sent(&s, 0, &asking("notes", Some("work"), "to work"), t);
        let to_plans = sent(&s, 0, &asking("notes", Some("plans"), "to plans"), t + 1);
        let to_all = sent(&s, 0, &asking("notes", None, "to all"), t + 2);
        let mut linked = asking("work", Some("notes"), "from work there");
        linked.link = Some("owner/repo#7".into());
        linked.asks = false;
        let from_work = sent(&s, 0, &linked, t + 3);
        s.pass(0, 1);
        let reply = sent(
            &s,
            1,
            &asking("work", Some("notes"), "from work here"),
            t + 4,
        );
        let now = s.now + MINUTE;

        let every = log_on(&s, 1, None, &[], now).unwrap();
        assert_eq!(every.name, None);
        let mut all = logged_ids(&every);
        all.sort();
        let mut expected = vec![to_work, to_plans, to_all, from_work, reply];
        expected.sort();
        assert_eq!(all, expected);
        // Each thread its own: it begins one.
        assert_eq!(every.threads.len(), 5);
        // Newest first.
        assert_eq!(every.threads[0].0, reply);
        let there = logged(&every, &from_work);
        assert_eq!(there.label.as_deref(), Some("device 0"));
        assert_eq!(there.fingerprint, fingerprint::shown(&s.key(0)));
        assert_eq!(
            (there.from.as_str(), there.to.as_deref()),
            ("work", Some("notes"))
        );
        let said = there.said.as_ref().unwrap();
        assert_eq!(said.body, "from work there");
        assert_eq!(said.link.as_deref(), Some("owner/repo#7"));
        assert!(!said.asks);
        assert!(logged(&every, &to_work).said.as_ref().unwrap().asks);
        assert_eq!(logged(&every, &reply).label, None);
        assert_eq!(logged(&every, &to_all).to, None);

        let work = log_on(&s, 1, Some("work"), &[], now).unwrap();
        assert_eq!(work.name.as_deref(), Some("work"));
        let mut of_work = logged_ids(&work);
        of_work.sort();
        let mut expected = vec![to_work, to_all, reply];
        expected.sort();
        assert_eq!(of_work, expected);
        // Unmapped, a folder is refused.
        let asked = LogAsked {
            folder: Some("/home/sam/unmapped"),
            since: None,
            mark: &[],
            fetched: true,
        };
        assert!(matches!(
            log_of(&s[1].conn, &s[1].identity, &asked, now, |_| false),
            Err(NotRead::Refused(Refused::NotMapped))
        ));
        // Only what was shown since a time.
        let asked = LogAsked {
            folder: None,
            since: Some(t + 3),
            mark: &[],
            fetched: true,
        };
        let since = log_of(&s[1].conn, &s[1].identity, &asked, now, |_| false).unwrap();
        let mut late = logged_ids(&since);
        late.sort();
        let mut expected = vec![from_work, reply];
        expected.sort();
        assert_eq!(late, expected);
        // Whether an agent read one to every name is of each name: here,
        // where plans read it.
        let said = |log: &Log, id: &Id| logged(log, id).said.clone().unwrap();
        assert!(!said(&every, &to_all).read_here);
        reads(&s, 1, "plans", &hex::encode(to_all), now).unwrap();
        let after = log_on(&s, 1, None, &[], now).unwrap();
        assert!(said(&after, &to_all).read_here);
        assert!(said(&after, &to_all).read_on.is_empty());
        assert!(!said(&after, &to_work).read_here);
        // It works with sync off, and shows what is held.
        meta::remove(&s[1].conn, meta::SYNC_CLAUDE_DIR).unwrap();
        assert_eq!(logged_ids(&log_on(&s, 1, None, &[], now).unwrap()).len(), 5);
        // As the route answers it, every name whole.
        let answered = every.answered();
        assert_eq!(answered["threads"][0]["thread"], hex::encode(reply));
        let first = &answered["threads"][0]["messages"][0];
        assert_eq!(first["device"], "this");
        assert_eq!(first["held_back"], false);
        assert_eq!(first["body"], "from work here");
    }

    /// `log` marks as read by a person each message whose ID it is given
    /// and that it lists with a place, and no other: one of another
    /// folder's agent, one it does not hold, and one it was not given stay
    /// unread by a person; the pair's count starts again (decision
    /// 2026-10-09 §4.1, §6, §7.2, property 14).
    #[test]
    fn log_marks_as_read_by_a_person_only_what_it_was_given() {
        let mut s = devices(2);
        let t = s.now + MINUTE;
        let ids: Vec<Id> = (0..3)
            .map(|k| {
                sent(
                    &s,
                    0,
                    &asking("notes", Some("work"), &format!("{k}")),
                    t + k,
                )
            })
            .collect();
        let to_plans = sent(&s, 0, &asking("notes", Some("plans"), "plans"), t + 3);
        s.pass(0, 1);
        let now = s.now + MINUTE;
        // What a person has not read here is listed, and nothing else.
        let unread = |log: &Log, id: &Id| logged_ids(log).contains(id);
        let first = log_on(&s, 1, None, &[], now).unwrap();
        assert_eq!(first.marked, 0);
        assert!(ids.iter().all(|id| unread(&first, id)));
        assert_eq!(first.printed().len(), 4);

        let not_held = [0x99; 16];
        let marked = log_on(
            &s,
            1,
            Some("work"),
            &[ids[0], ids[1], to_plans, not_held],
            now,
        );
        assert_eq!(marked.unwrap().marked, 2);
        let after = log_on(&s, 1, None, &[], now).unwrap();
        assert!(!unread(&after, &ids[0]) && !unread(&after, &ids[1]));
        assert!(unread(&after, &ids[2]) && unread(&after, &to_plans));
        assert_eq!(after.already_read, 2);
        assert!(held::is_read_by_a_person(&s[1].conn, &ids[0]).unwrap());
        assert!(!held::is_read_by_a_person(&s[1].conn, &not_held).unwrap());
        // Only a person's mark: no agent read them.
        assert_eq!(summary_on(&s, 1, "work", now).unwrap().lines.len(), 3);
        // The pair counts what is left.
        let pairs = held::pairs_with(&s[1].conn, "work", now, &s.keys_counting(1)).unwrap();
        assert_eq!(pairs, [(Some("notes".to_string()), 1)]);
        // Marked again, it is counted, and is one mark.
        let again = log_on(&s, 1, None, &[ids[0], to_plans], now).unwrap();
        assert_eq!(again.marked, 2);
        assert_eq!(
            held::pairs_with(&s[1].conn, "plans", now, &s.keys_counting(1)).unwrap(),
            Vec::<(held::Other, u64)>::new()
        );
    }

    /// `log` lists only the messages that no person has read here, and
    /// counts the others, of every name, of a folder's agent and since a
    /// time; where a person has read them all it lists none (decision
    /// 2026-10-09 §4.1).
    #[test]
    fn log_lists_only_what_no_person_has_read_here_and_counts_the_rest() {
        let mut s = devices(2);
        // Sent before they are held, so each is shown from its `sent`.
        let t = s.now - 10 * MINUTE;
        let old = sent(&s, 0, &asking("notes", Some("work"), "old"), t);
        let old_to_plans = sent(
            &s,
            0,
            &asking("notes", Some("plans"), "old to plans"),
            t + 1,
        );
        let new = sent(&s, 0, &asking("notes", Some("work"), "new"), t + 2);
        s.pass(0, 1);
        let now = s.now + MINUTE;
        let first = log_on(&s, 1, None, &[], now).unwrap();
        assert_eq!((logged_ids(&first).len(), first.already_read), (3, 0));

        // A person here reads the two older ones.
        assert_eq!(
            log_on(&s, 1, None, &[old, old_to_plans], now)
                .unwrap()
                .marked,
            2
        );
        let every = log_on(&s, 1, None, &[], now).unwrap();
        assert_eq!((logged_ids(&every), every.already_read), (vec![new], 2));
        assert_eq!(every.printed(), [new]);
        let answered = every.answered();
        assert_eq!(answered["already_read"], 2);
        assert_eq!(answered["threads"].as_array().unwrap().len(), 1);
        assert!(!answered.to_string().contains("old to plans"));
        // Of a folder's agent, only what is its own is counted.
        let work = log_on(&s, 1, Some("work"), &[], now).unwrap();
        assert_eq!((logged_ids(&work), work.already_read), (vec![new], 1));
        let plans = log_on(&s, 1, Some("plans"), &[], now).unwrap();
        assert_eq!((logged_ids(&plans), plans.already_read), (vec![], 1));
        // Since a time, only what was shown since it.
        let asked = LogAsked {
            folder: None,
            since: Some(t + 1),
            mark: &[],
            fetched: true,
        };
        let since = log_of(&s[1].conn, &s[1].identity, &asked, now, |_| false).unwrap();
        assert_eq!((logged_ids(&since), since.already_read), (vec![new], 1));

        // A person here has read them all: none is listed.
        log_on(&s, 1, None, &[new], now).unwrap();
        let none = log_on(&s, 1, None, &[], now).unwrap();
        assert!(none.threads.is_empty() && none.printed().is_empty());
        assert_eq!(none.already_read, 3);
        assert_eq!(none.answered()["threads"], json!([]));
    }

    /// After the threads `log` says, of the device's own messages, which
    /// wait to be sent, which a relay had no room for and which signer
    /// fills the channel, which may not have reached every relay, and
    /// which are from before the last change of the person's devices; of
    /// a folder's agent, only its own (decision 2026-10-09 §2.3, §4.1,
    /// §9.1, §10).
    #[test]
    fn log_says_what_waits_what_was_refused_for_room_and_what_may_not_have_reached_everyone() {
        let mut s = devices(2);
        let t = s.now + MINUTE;
        let waits = sent(&s, 0, &asking("notes", Some("work"), "waits"), t);
        let dropped = sent(&s, 0, &asking("notes", Some("work"), "dropped"), t + 1);
        let refused_one = sent(&s, 0, &asking("plans", Some("work"), "refused"), t + 2);
        let now = t + MINUTE;
        let first = log_on(&s, 0, None, &[], now).unwrap();
        assert_eq!(first.waiting, [waits, dropped, refused_one]);
        // Its own numbers are held, and nothing of them is counted.
        assert!(first.signers.is_empty());
        assert_eq!(first.room, Room::default());
        assert!(first.not_every_relay.is_empty() && first.not_every_device.is_empty());

        // A kept value dropped before every relay took it.
        held::drop_kept(&s[0].conn, &dropped, false).unwrap();
        // A relay with no room for the entry of the third.
        let conn = &s[0].conn;
        let secret = cordelia_crypto::derive::messages_secret(&s[0].secret()).unwrap();
        let channel = cordelia_crypto::derive::channel_id(&secret).unwrap();
        let slot = cordelia_crypto::slots::slot_id(
            &cordelia_crypto::derive::slot_key(&secret).unwrap(),
            &cordelia_crypto::message::message_name(&s.key(0), 3).unwrap(),
        );
        let entry = cordelia_storage::entries::author_entry(conn, &channel, &slot, &s.key(0))
            .unwrap()
            .unwrap();
        cordelia_storage::at_relays::refused(conn, &[0xa1; 32], &channel, entry.seq).unwrap();
        let second = log_on(&s, 0, None, &[], now).unwrap();
        assert_eq!(second.waiting, [waits]);
        assert_eq!(second.room.refused, [refused_one]);
        assert_eq!(second.room.filled_by, Some(("device 0".into(), 3)));
        assert_eq!(second.not_every_relay, [dropped]);
        // Of a folder's agent, only its own.
        let notes = log_on(&s, 0, Some("notes"), &[], now).unwrap();
        assert_eq!(notes.waiting, [waits]);
        assert!(notes.room.refused.is_empty());
        assert_eq!(notes.not_every_relay, [dropped]);
        let plans = log_on(&s, 0, Some("plans"), &[], now).unwrap();
        assert!(plans.waiting.is_empty() && plans.not_every_relay.is_empty());
        assert_eq!(plans.room.refused, [refused_one]);
        let answered = second.answered();
        assert_eq!(answered["refused_for_room"][0], hex::encode(refused_one));
        assert_eq!(answered["filled_by"]["label"], "device 0");
        assert_eq!(answered["filled_by"]["entries"], 3);
        assert_eq!(answered["not_every_relay"][0], hex::encode(dropped));
        assert_eq!(answered["waiting"][0], hex::encode(waits));

        // An entry of its own key that is no message is counted, for this
        // device.
        let junk = crate::several::entry_by(
            &s[0].identity,
            &secret,
            1,
            "junk",
            cordelia_crypto::entry::Value::Other(vec![0; 16]),
            &[],
        );
        crate::take::take(&s[0].conn, &s[0].identity, &junk, now).unwrap();
        let counted = log_on(&s, 0, None, &[], now).unwrap().signers;
        assert_eq!(counted.len(), 1);
        assert_eq!(counted[0].label, None);
        assert_eq!(counted[0].not_messages, 1);

        // After a renewal, its own from before may not have reached every
        // device, and each is from before the last change.
        s.change(0, &[0, 1], &[]);
        let later = s.now + MINUTE;
        let renewed = log_on(&s, 0, None, &[], later).unwrap();
        let mut before = renewed.not_every_device.clone();
        before.sort();
        let mut expected = vec![waits, dropped, refused_one];
        expected.sort();
        assert_eq!(before, expected);
        assert!(logged(&renewed, &waits).before_the_last_change);
        assert!(!logged(&first, &waits).before_the_last_change);
        assert_eq!(
            log_on(&s, 0, Some("plans"), &[], later)
                .unwrap()
                .not_every_device,
            [refused_one]
        );
        // What waited was of the generation left: it waits no more.
        assert!(renewed.waiting.is_empty());
        assert_eq!(
            renewed.answered()["not_every_device"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }

    /// A message that has no place yet is listed by its ID and its sender,
    /// as held back, with nothing of what it says, and counted as held back
    /// for its signer (decision 2026-10-09 §4.1, §6).
    #[test]
    fn log_lists_a_message_held_back_by_its_id_and_its_sender_alone() {
        let s = devices(2);
        let t = s.now + MINUTE;
        let channel = messages_channel(&s[1].conn).unwrap().unwrap();
        let generation = held::generation(&s[1].conn, &channel, s[1].number(), t).unwrap();
        // 64 places of the signer in the hour already.
        for _ in 0..64 {
            s[1].conn
                .execute(
                    "INSERT INTO message_places (signer, generation, placed_at) VALUES (?1, ?2, ?3)",
                    rusqlite::params![&s.key(0)[..], generation, t],
                )
                .unwrap();
        }
        held::hold_number(&s[1].conn, &s.key(0), generation, 1, false, t).unwrap();
        let message = Message {
            asks: true,
            sent: t as u64,
            nonce: [0; 16],
            thread: [0; 16],
            answers: [0; 16],
            from: "notes".into(),
            to: To::Name("work".into()),
            link: Some("owner/repo#1".into()),
            body: "nothing of this is shown".into(),
        };
        let id = [0x42; 16];
        let opened = Opened {
            id: &id,
            signer: &s.key(0),
            label: "device 0",
            generation,
            number: 1,
            message: &message,
            first_held: t,
            placed_at: None,
        };
        held::index(&s[1].conn, &opened).unwrap();
        let log = log_on(&s, 1, None, &[id], t + 1).unwrap();
        let listed = logged(&log, &id);
        assert_eq!(listed.said, None);
        assert_eq!(listed.label.as_deref(), Some("device 0"));
        assert_eq!(listed.from, "notes");
        assert!(log.printed().is_empty());
        // Given to mark, it is not marked.
        assert_eq!(log.marked, 0);
        assert!(!held::is_read_by_a_person(&s[1].conn, &id).unwrap());
        assert_eq!(log.signers.len(), 1);
        assert_eq!(log.signers[0].held_back, 1);
        assert_eq!(log.signers[0].label.as_deref(), Some("device 0"));
        // A message of a key that no longer counts is listed as such, and
        // its signer is counted under the label it was held with.
        let removed = identity_of(9).public_key();
        held_as(
            &s,
            1,
            [0x43; 16],
            removed,
            "notes",
            Some("work"),
            false,
            (t, t),
            1,
        );
        held::not_a_message(&s[1].conn, &removed, generation).unwrap();
        let again = log_on(&s, 1, None, &[], t + 1).unwrap();
        assert!(logged(&again, &[0x43; 16]).signer_removed);
        assert!(!logged(&again, &id).signer_removed);
        let counted = again
            .signers
            .iter()
            .find(|c| c.fingerprint == fingerprint::shown(&removed))
            .unwrap();
        assert_eq!(counted.label.as_deref(), Some("elsewhere"));
        assert_eq!(counted.not_messages, 1);
        // With no folder, at a terminal, what it says is answered; given a
        // folder, it is listed by its ID and its sender alone, and is not
        // said to be held back.
        let gone = [0x43; 16];
        let body = format!("the body of {}", hex::encode(gone));
        assert_eq!(logged(&again, &gone).said.as_ref().unwrap().body, body);
        let of = |log: &Log| -> Value {
            log.answered()["threads"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|thread| thread["messages"].as_array().unwrap().clone())
                .find(|m| m["id"] == hex::encode(gone))
                .unwrap()
        };
        assert_eq!(of(&again)["body"], json!(body));
        let away = log_on(&s, 1, Some("work"), &[], t + 1).unwrap();
        let listed = logged(&away, &gone);
        assert!(listed.signer_removed);
        assert_eq!(listed.said, None);
        assert_eq!(
            (listed.from.as_str(), listed.label.as_deref()),
            ("notes", Some("elsewhere"))
        );
        assert!(away.printed().is_empty());
        let answered = of(&away);
        assert_eq!(
            (&answered["signer_removed"], &answered["held_back"]),
            (&json!(true), &json!(false))
        );
        for field in ["body", "link", "subject", "asks", "read_on"] {
            assert!(answered.get(field).is_none(), "{field}: {answered}");
        }
        assert!(!away.answered().to_string().contains(&body));
        // Once a person here has read it, it is listed there no more, and
        // is counted.
        assert_eq!(log_on(&s, 1, None, &[gone], t + 1).unwrap().marked, 1);
        let read = log_on(&s, 1, Some("work"), &[], t + 1).unwrap();
        assert!(!logged_ids(&read).contains(&gone));
        assert_eq!(read.already_read, 1);
        let answered = log.answered();
        let first = &answered["threads"][0]["messages"][0];
        assert_eq!(first["held_back"], true);
        assert!(first.get("body").is_none() && first.get("link").is_none());
        assert_eq!(answered["signers"][0]["held_back"], 1);
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
            waiting: 12,
            bound: 5,
        };
        assert_eq!(
            said(held),
            json!({ "from": "a", "other": "b", "every": true, "waiting": 12, "bound": 5 })
        );
        let held = Refused::PairHeld {
            from: "a".into(),
            other: None,
            every: false,
            waiting: 10,
            bound: 10,
        };
        assert_eq!(
            said(held),
            json!({ "from": "a", "other": null, "every": false, "waiting": 10, "bound": 10 })
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

    fn log_asked(name: Option<&str>, mark: &[Id]) -> web::Json<LogRequest> {
        web::Json(LogRequest {
            folder: name.map(folder),
            since: None,
            mark: mark.iter().map(hex::encode).collect(),
        })
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

    fn told_asked(name: &str, ids: &[String]) -> web::Json<AnnouncedRequest> {
        web::Json(AnnouncedRequest {
            folder: folder(name),
            ids: ids.to_vec(),
            version: env!("CARGO_PKG_VERSION").into(),
        })
    }

    /// The route the command tells what it printed: a summary answered
    /// over the route marks nothing; told the line's ID whole, the node
    /// marks it announced and answers nothing; told by a command of
    /// another version, or more IDs than a summary has lines, or an ID
    /// not whole, it marks nothing (decision 2026-10-09 §4.1, §4.2).
    #[actix_web::test]
    async fn the_node_marks_announced_what_the_command_says_it_printed() {
        let (state, id) = a_node_with_a_message();
        let lines = |said: &Value| said["lines"].as_array().unwrap().len();
        for _ in 0..2 {
            let (status, said) =
                answer(summary(asked(), state.clone(), summary_asked("work", 100)).await).await;
            assert_eq!((status, lines(&said)), (200, 1), "{said}");
        }
        let whole = hex::encode(id);
        let mut other = told_asked("work", std::slice::from_ref(&whole));
        other.version = "0.0.0".into();
        let too_many = vec![whole.clone(); AGENT_MESSAGE_SUMMARY_LINES + 1];
        // Upper case is another form of the same ID.
        assert_ne!(whole.to_ascii_uppercase(), whole);
        for wrong in [
            other,
            told_asked("work", &too_many),
            told_asked("work", &[whole[..8].to_string()]),
            told_asked("work", &[whole.to_ascii_uppercase()]),
        ] {
            let (status, _) = answer(announced(asked(), state.clone(), wrong).await).await;
            assert_eq!(status, 204);
            assert!(!held::is_announced(&db_of(&state), &id, "work").unwrap());
        }
        let (status, _) = answer(
            announced(
                asked(),
                state.clone(),
                told_asked("work", std::slice::from_ref(&whole)),
            )
            .await,
        )
        .await;
        assert_eq!(status, 204);
        assert!(held::is_announced(&db_of(&state), &id, "work").unwrap());
        let (status, said) =
            answer(summary(asked(), state.clone(), summary_asked("work", 100)).await).await;
        assert_eq!((status, lines(&said)), (200, 0), "{said}");
        assert_eq!(said["waiting"]["ids"], json!([whole]));
        let (status, _) =
            answer(announced(not_asked(), state.clone(), told_asked("work", &[])).await).await;
        assert_eq!(status, 401);
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

    /// A wait for the store's lock that tries, as a summary does, is
    /// recorded from its first try to the take, as a wait of its kind; and
    /// a summary that does not have the lock within its 100 ms is counted
    /// as given up, and records no wait (decision 2026-10-22 §1.2, bar 5).
    /// Another holds the lock for 150 ms while a try of up to a second
    /// waits for it, and for 400 ms while a summary does.
    #[actix_web::test]
    async fn a_wait_that_tries_for_the_store_is_recorded_and_a_summary_that_gives_up_is_counted() {
        use cordelia_core::load::Kind;
        use cordelia_core::lock::take_as;
        let (state, _) = a_node_with_a_message();
        let held_for = |ms: u64| {
            let (holding, held) = std::sync::mpsc::channel();
            let other = state.clone();
            let holder = std::thread::spawn(move || {
                let _held = other.db.lock().unwrap();
                holding.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(ms));
            });
            held.recv().unwrap();
            holder
        };
        let holder = held_for(150);
        let deadline = Instant::now() + Duration::from_secs(1);
        let taken = take_as(Kind::Api, async { db_by(&state, deadline).await.is_some() }).await;
        holder.join().unwrap();
        assert!(taken, "the lock was let go within the deadline");
        let wait = state.db.times().wait(Kind::Api);
        assert_eq!(wait.count, 1);
        assert!(wait.max_micros >= 100_000, "{wait:?}");
        assert_eq!(wait.over[2], 1, "a wait over 100 ms, as bar 5 counts");
        assert_eq!(state.db.times().given_up(Kind::Api), 0);

        let holder = held_for(400);
        let summarised = summary(asked(), state.clone(), summary_asked("work", 100));
        let answered = take_as(Kind::Api, summarised).await;
        holder.join().unwrap();
        assert_eq!(answer(answered).await.0, 204);
        assert_eq!(state.db.times().given_up(Kind::Api), 1);
        let wait = state.db.times().wait(Kind::Api);
        assert_eq!(wait.count, 1, "a give-up is no wait");
    }

    /// While `announced` waits for the store's lock, the worker it runs on
    /// serves another request; it waits at most the summary's 100 ms, and
    /// then marks nothing (decision 2026-10-09 §4.1, C20).
    #[actix_web::test]
    async fn another_request_is_served_while_announced_waits_for_the_store() {
        let (state, id) = a_node_with_a_message();
        let (holding, held) = std::sync::mpsc::channel();
        let other = state.clone();
        // Another holds the store's lock for 400 ms, longer than the wait.
        let holder = std::thread::spawn(move || {
            let _held = other.db.lock().unwrap();
            holding.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(400));
        });
        held.recv().unwrap();
        let began = Instant::now();
        let waits = async {
            let told = told_asked("work", &[hex::encode(id)]);
            let answered = announced(asked(), state.clone(), told).await;
            (answer(answered).await.0, Instant::now())
        };
        // Another request, sent once `announced` is waiting: of another
        // version, which is answered without the store.
        let another = async {
            actix_web::rt::time::sleep(Duration::from_millis(10)).await;
            let mut other = summary_asked("work", 100);
            other.version = "0.0.0".into();
            let answered = summary(asked(), state.clone(), other).await;
            (answer(answered).await.0, Instant::now())
        };
        let ((waited, waited_until), (served, served_at)) = tokio::join!(waits, another);
        holder.join().unwrap();
        assert_eq!((waited, served), (204, 204));
        assert!(
            served_at < waited_until,
            "the other request waited for announced"
        );
        let waited = waited_until.duration_since(began);
        assert!(waited >= Duration::from_millis(100), "{waited:?}");
        assert!(waited < Duration::from_millis(400), "{waited:?}");
        // It gave up the lock it did not have, and marked nothing.
        assert!(!held::is_announced(&db_of(&state), &id, "work").unwrap());
    }

    /// The node's status answers the `messages` object on a personal node
    /// that stands applied, and none on a relay's, and none while the node
    /// is held up, which reads nothing of its database (decision 2026-10-09
    /// §8; decision 2026-10-04 §10.1).
    #[actix_web::test]
    async fn the_status_of_a_relay_or_of_a_node_held_up_says_nothing_of_messages() {
        let (state, _) = a_node_with_a_message();
        let status_of = |older_kind: bool| {
            let state = state.clone();
            async move {
                let get = TestRequest::get()
                    .insert_header(("Authorization", format!("Bearer {TOKEN}")))
                    .to_http_request();
                answer(crate::handlers::status_with(state, get, older_kind).await).await
            }
        };
        let (code, said) = status_of(false).await;
        assert_eq!(code, 200);
        assert_eq!(said["messages"]["unread_by_an_agent"], 1, "{said}");
        let (_, said) = status_of(true).await;
        assert_eq!(said.get("messages"), None, "{said}");
        state.held.hold(Held::FirstStart("a copy failed".into()));
        let (code, said) = status_of(false).await;
        assert_eq!(code, 200);
        assert_eq!(said.get("messages"), None, "{said}");
    }

    /// `summary` answers nothing to a request of another version, and
    /// nothing while the node is held up; `read` and `send` are refused
    /// then with `held_up` (decision 2026-10-09 §4.2, §4.3).
    #[actix_web::test]
    async fn a_summary_of_another_version_or_while_held_up_is_nothing() {
        let (state, id) = a_node_with_a_message();
        // A summary of this version gives the message its place, so that
        // it is a line `announced` could mark, as it is in use.
        let (status, said) =
            answer(summary(asked(), state.clone(), summary_asked("work", 100)).await).await;
        assert_eq!(
            (status, said["lines"][0]["id"].clone()),
            (200, json!(hex::encode(id)))
        );
        let mut other = summary_asked("work", 100);
        other.version = "0.0.0".into();
        let (status, _) = answer(summary(asked(), state.clone(), other).await).await;
        assert_eq!(status, 204);
        // Nor is anything marked by `announced` of another version, or
        // while the node is held up.
        let whole = hex::encode(id);
        let mut other = told_asked("work", std::slice::from_ref(&whole));
        other.version = "0.0.0".into();
        let (status, _) = answer(announced(asked(), state.clone(), other).await).await;
        assert_eq!(status, 204);
        assert!(!held::is_announced(&db_of(&state), &id, "work").unwrap());
        state.held.hold(Held::FirstStart("a copy failed".into()));
        let (status, _) =
            answer(summary(asked(), state.clone(), summary_asked("work", 100)).await).await;
        assert_eq!(status, 204);
        let told = told_asked("work", std::slice::from_ref(&whole));
        let (status, _) = answer(announced(asked(), state.clone(), told).await).await;
        assert_eq!(status, 204);
        assert!(!held::is_announced(&db_of(&state), &id, "work").unwrap());
        let read_asked = web::Json(ReadRequest {
            folder: folder("work"),
            id: hex::encode(id),
        });
        let (status, said) = answer(read(asked(), state.clone(), read_asked).await).await;
        assert_eq!((status, &said["error"]["code"]), (503, &json!("held_up")));
        let send_asked = web::Json(asking("work", Some("notes"), "x"));
        let (status, said) = answer(send(asked(), state.clone(), send_asked).await).await;
        assert_eq!((status, &said["error"]["code"]), (503, &json!("held_up")));
        // `log` too, before the device is asked whether it stands.
        held_rows::set_state(&state.db.lock().unwrap(), State::Removed).unwrap();
        let (status, said) = answer(log(asked(), state.clone(), log_asked(None, &[])).await).await;
        assert_eq!((status, &said["error"]["code"]), (503, &json!("held_up")));
        state.held.release();
        let (status, said) = answer(log(asked(), state.clone(), log_asked(None, &[])).await).await;
        assert_eq!(
            (status, &said["error"]["code"]),
            (409, &json!("not_applied"))
        );
        assert_eq!(said["refused"]["why"], "this device was removed");
        held_rows::set_state(&state.db.lock().unwrap(), State::Applied).unwrap();
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
                "/api/v1/messages/announced",
                json!({ "folder": folder("work"), "ids": [],
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
            (
                "/api/v1/messages/log",
                json!({ "folder": null, "since": null, "mark": [] }),
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
                [200, 204, 409].contains(&status.as_u16()),
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

    /// The log route answers every thread as `log` prints it, marks what it
    /// is given, and refuses, before anything, a `since` that is no time
    /// and an ID to mark that is not whole; in a folder that is not mapped
    /// it is refused with `not_mapped` (decision 2026-10-09 §4.2, §4.3).
    /// What it marked it lists no more, and counts.
    #[actix_web::test]
    async fn the_log_route_lists_marks_and_refuses_what_is_not_asked_rightly() {
        let (state, id) = a_node_with_a_message();
        let (status, said) =
            answer(log(asked(), state.clone(), log_asked(Some("work"), &[])).await).await;
        assert_eq!(status, 200, "{said}");
        assert_eq!(said["name"], "work");
        assert_eq!(said["threads"][0]["messages"][0]["id"], hex::encode(id));
        assert_eq!(
            (&said["marked"], &said["already_read"]),
            (&json!(0), &json!(0))
        );
        let since = web::Json(LogRequest {
            folder: None,
            since: Some("2999-01-01T00:00:00Z".into()),
            mark: vec![],
        });
        let (status, said) = answer(log(asked(), state.clone(), since).await).await;
        assert_eq!(status, 200);
        assert_eq!(said["threads"], json!([]));
        assert_eq!(said["already_read"], 0);
        let (status, said) =
            answer(log(asked(), state.clone(), log_asked(None, &[id])).await).await;
        assert_eq!((status, &said["marked"]), (200, &json!(1)));
        assert_eq!(said["threads"], json!([]));
        assert_eq!(said["already_read"], 1);
        for (since, mark) in [
            (Some("yesterday".to_string()), vec![]),
            (None, vec!["0123456789abcdef".to_string()]),
            (None, vec!["zz".repeat(16)]),
        ] {
            let asked_badly = web::Json(LogRequest {
                folder: None,
                since,
                mark,
            });
            let (status, _) = answer(log(asked(), state.clone(), asked_badly).await).await;
            assert_eq!(status, 400);
        }
        let unmapped = web::Json(LogRequest {
            folder: Some("/nowhere".into()),
            since: None,
            mark: vec![],
        });
        let (status, said) = answer(log(asked(), state.clone(), unmapped).await).await;
        assert_eq!(
            (status, &said["error"]["code"]),
            (409, &json!("not_mapped"))
        );
        let (status, _) = answer(log(not_asked(), state.clone(), log_asked(None, &[])).await).await;
        assert_eq!(status, 401);
    }

    /// A `mark` of as many IDs as a body of 2 MiB holds, each whole and
    /// none held here, is answered, and marks nothing (decision 2026-10-09
    /// §4.2): each ID shown is looked up in a set of them.
    #[actix_web::test]
    async fn a_mark_of_many_thousands_of_ids_held_nowhere_is_answered_and_marks_nothing() {
        let (state, id) = a_node_with_a_message();
        let many: Vec<Id> = (0..58_000u32)
            .map(|k| {
                let mut other = [0xee; 16];
                other[..4].copy_from_slice(&k.to_be_bytes());
                other
            })
            .collect();
        let (status, said) =
            answer(log(asked(), state.clone(), log_asked(None, &many)).await).await;
        assert_eq!((status, &said["marked"]), (200, &json!(0)), "{said}");
        assert_eq!(said["threads"][0]["messages"][0]["id"], hex::encode(id));
        assert_eq!(said["already_read"], 0);
        assert!(!held::is_read_by_a_person(&state.db.lock().unwrap(), &id).unwrap());
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

    /// A message is written before its room is looked at: where that
    /// cannot be read, the send is still answered as sent, with no signer
    /// named, and the message is held (decision 2026-10-09 §4.1).
    #[test]
    fn a_send_whose_room_cannot_be_read_is_answered_as_sent() {
        let s = devices(1);
        let conn = &s[0].conn;
        let request = asking("work", Some("notes"), "sent all the same");
        // The store breaks once the message is written, before its room
        // is read.
        let breaks = |_: &[u8; 32]| {
            conn.execute_batch("ALTER TABLE entries RENAME TO entries_gone")
                .unwrap();
            true
        };
        let sent = send_of(conn, &s[0].identity, &request, &at(s.now + MINUTE), breaks)
            .unwrap_or_else(|not| panic!("{not:?}"));
        assert_eq!(sent.filled_by, None);
        conn.execute_batch("ALTER TABLE entries_gone RENAME TO entries")
            .unwrap();
        assert_eq!(row(conn, &sent.id).0.as_deref(), Some("notes"));
    }

    // ── The status ───────────────────────────────────────────────────

    /// The `messages` object of the status counts each of its fields by
    /// its rule (decision 2026-10-09 §8, C13): unread by an agent, for each
    /// mapped folder, a message to every name once for each, and none of
    /// a signer that no longer counts; unread by a person, of what was not
    /// sent here; what waits, and what a relay refused for room, each
    /// message once and no list; the signer that fills the channel; what is
    /// held back and overwritten; and whether there is no place. It is
    /// absent on a device that does not stand applied.
    #[test]
    fn the_status_counts_messages_each_by_its_rule() {
        let mut s = devices(2);
        let t = s.now + MINUTE;
        let a1 = sent(&s, 0, &asking("notes", Some("work"), "first"), t);
        let a2 = sent(&s, 0, &asking("notes", Some("work"), "second"), t + 1);
        let b = sent(&s, 0, &asking("notes", None, "to every name"), t + 2);
        s.pass(0, 1);
        sent(&s, 1, &asking("work", Some("notes"), "from here"), t + 3);
        let now = s.now + MINUTE;
        let channels = OwnChannels::default();
        let counts = |n: usize, channels: &OwnChannels| {
            status_of(&s[n].conn, &s[n].identity, channels, now)
                .unwrap()
                .unwrap()
        };

        // On the device they were sent to: `notes` is shown the message to
        // every name and this device's own from `work`; `work` the two to
        // it and the one to every name; `plans` the one to every name. A
        // person here is shown the three that were not sent here.
        let on_1 = counts(1, &channels);
        assert_eq!((on_1.unread_by_an_agent, on_1.unread_by_a_person), (6, 3));
        assert_eq!((on_1.waiting, on_1.refused_for_room), (1, 0));
        assert_eq!(on_1.filled_by, None);
        assert_eq!(
            (on_1.held_back, on_1.overwritten, on_1.no_place),
            (0, 0, false)
        );

        // A person read one: an agent has not.
        s[1].conn
            .execute(
                "INSERT INTO message_read_by_a_person (id) VALUES (?1)",
                [&a1[..]],
            )
            .unwrap();
        let on_1 = counts(1, &channels);
        assert_eq!((on_1.unread_by_an_agent, on_1.unread_by_a_person), (6, 2));
        // An agent read two: a person has not.
        reads(&s, 1, "work", &hex::encode(a2), now).unwrap();
        reads(&s, 1, "work", &hex::encode(b), now).unwrap();
        let on_1 = counts(1, &channels);
        assert_eq!((on_1.unread_by_an_agent, on_1.unread_by_a_person), (4, 2));

        // A signer that does not count: a person is shown it by `log`, and
        // no agent by its summary.
        held_as(
            &s,
            1,
            [0x99; 16],
            [9; 32],
            "notes",
            Some("work"),
            false,
            (now, now),
            1,
        );
        let on_1 = counts(1, &channels);
        assert_eq!((on_1.unread_by_an_agent, on_1.unread_by_a_person), (4, 3));
        // A message to a name that no folder here maps: shown to nobody here.
        held_as(
            &s,
            1,
            [0x66; 16],
            [6; 32],
            "notes",
            Some("elsewhere"),
            false,
            (now, now),
            1,
        );
        let on_1 = counts(1, &channels);
        assert_eq!((on_1.unread_by_an_agent, on_1.unread_by_a_person), (4, 3));

        // A signer that had its hour of places: its next waits, held back.
        let conn = &s[1].conn;
        let channel = messages_channel(conn).unwrap().unwrap();
        let generation = held::generation(conn, &channel, s[1].number(), now).unwrap();
        for _ in 0..64 {
            conn.execute(
                "INSERT INTO message_places (signer, generation, placed_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![&[8u8; 32][..], generation, now - 1],
            )
            .unwrap();
        }
        held::hold_number(conn, &[8; 32], generation, 1, false, now).unwrap();
        let message = Message {
            asks: false,
            sent: now as u64,
            nonce: [0; 16],
            thread: [0; 16],
            answers: [0; 16],
            from: "notes".into(),
            to: To::Name("work".into()),
            link: None,
            body: "held back".into(),
        };
        held::index(
            conn,
            &Opened {
                id: &[0x88; 16],
                signer: &[8; 32],
                label: "elsewhere",
                generation,
                number: 1,
                message: &message,
                first_held: now,
                placed_at: None,
            },
        )
        .unwrap();
        // A signer of which a lap and more was never held: overwritten.
        held::hold_number(conn, &[7; 32], generation, 1, false, now).unwrap();
        held::hold_number(conn, &[7; 32], generation, 200, false, now).unwrap();
        // Rows that wait for a place too, and are counted nowhere: one past
        // its 30 days, and one at a number that is not live.
        for (signer, sent) in [([5u8; 32], now - 31 * 24 * 60 * MINUTE), ([4u8; 32], now)] {
            for _ in 0..64 {
                conn.execute(
                    "INSERT INTO message_places (signer, generation, placed_at)
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![&signer[..], generation, now - 1],
                )
                .unwrap();
            }
            held::hold_number(conn, &signer, generation, 1, false, sent).unwrap();
            let message = Message {
                sent: sent as u64,
                ..message.clone()
            };
            held::index(
                conn,
                &Opened {
                    id: &[signer[0]; 16],
                    signer: &signer,
                    label: "elsewhere",
                    generation,
                    number: 1,
                    message: &message,
                    first_held: sent,
                    placed_at: None,
                },
            )
            .unwrap();
        }
        conn.execute(
            "UPDATE message_signers SET highest = 200 WHERE signer = ?1",
            [&[4u8; 32][..]],
        )
        .unwrap();
        let on_1 = counts(1, &channels);
        assert_eq!((on_1.held_back, on_1.overwritten), (1, 136));
        assert_eq!(on_1.unread_by_a_person, 3);

        // What a relay refused of this device's own: its message, once for
        // two relays, and not its list, which stands at an even revision,
        // nor another device's entries that it holds, said refused too.
        let own = s.key(1);
        let refused: Vec<(i64, u64, Vec<u8>)> = conn
            .prepare("SELECT seq, rev, author FROM entries WHERE channel_id = ?1")
            .unwrap()
            .query_map([&channel[..]], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let of_its_own: Vec<_> = refused
            .iter()
            .filter(|(_, _, author)| author[..] == own[..])
            .collect();
        assert_eq!((refused.len(), of_its_own.len()), (5, 2));
        assert!(
            of_its_own.iter().all(|(_, rev, _)| rev % 2 == 0),
            "{refused:?}"
        );
        // Its list, written after its message, alone: at revision 2 it
        // stands at the number of its message, and is no message.
        let list_seq = of_its_own.iter().map(|(seq, _, _)| *seq).max().unwrap();
        cordelia_storage::at_relays::refused(conn, &[0x71; 32], &channel, list_seq).unwrap();
        assert_eq!(counts(1, &channels).refused_for_room, 0);
        for relay in [[0x71; 32], [0x72; 32]] {
            for (seq, _, _) in &refused {
                cordelia_storage::at_relays::refused(conn, &relay, &channel, *seq).unwrap();
            }
        }
        let on_1 = counts(1, &channels);
        assert_eq!((on_1.waiting, on_1.refused_for_room), (1, 1));
        // A message of its own waits refused: who fills the channel is
        // named, as `log` names it.
        assert_eq!(on_1.filled_by, Some(("device 0".into(), 3)));

        // The sender keeps what it sent until every relay takes it; where
        // a relay refused the channel for room, the signer that fills it
        // is named, by its entries.
        assert_eq!(counts(0, &channels).waiting, 3);
        // A relay refused the three, and the first is cleared since: the
        // clearing, refused in its turn, is no message.
        let conn = &s[0].conn;
        let channel = messages_channel(conn).unwrap().unwrap();
        let secret = cordelia_crypto::derive::messages_secret(&s[0].secret()).unwrap();
        let name = cordelia_crypto::message::message_name(&s.key(0), 1).unwrap();
        let inside =
            cordelia_crypto::message::inside(name, cordelia_crypto::message::clearing_value());
        let rev = cordelia_crypto::message::clearing_rev(1).unwrap();
        let seqs = |conn: &Connection| -> Vec<i64> {
            conn.prepare("SELECT seq FROM entries WHERE channel_id = ?1")
                .unwrap()
                .query_map([&channel[..]], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        for seq in seqs(conn) {
            cordelia_storage::at_relays::refused(conn, &[0x71; 32], &channel, seq).unwrap();
        }
        assert_eq!(counts(0, &channels).refused_for_room, 3);
        // The second, sent again under number 4 and refused there too, is
        // one message refused.
        let second = held::kept(conn).unwrap().remove(1);
        let generation = held::generation_of(conn, &channel).unwrap().unwrap();
        let again = cordelia_crypto::message::inside(
            cordelia_crypto::message::message_name(&s.key(0), 4).unwrap(),
            second.value.clone(),
        );
        let rev_4 = cordelia_crypto::message::message_rev(4).unwrap();
        let again = cordelia_crypto::entry::Entry::seal(&secret, &s[0].identity, rev_4, &again);
        cordelia_storage::entries::store(conn, &again.unwrap().check().unwrap(), now).unwrap();
        held::hold_number(conn, &s.key(0), generation, 4, false, now).unwrap();
        let value = cordelia_crypto::entry::Value::Other(second.value.clone());
        let message = Message::from_value(&value, |_| true).unwrap();
        let opened = Opened {
            id: &second.id,
            signer: &s.key(0),
            label: "",
            generation,
            number: 4,
            message: &message,
            first_held: now,
            placed_at: Some(now),
        };
        assert_eq!(
            held::index(conn, &opened).unwrap(),
            held::Indexed::AnotherNumber
        );
        for seq in seqs(conn) {
            cordelia_storage::at_relays::refused(conn, &[0x71; 32], &channel, seq).unwrap();
        }
        assert_eq!(counts(0, &channels).refused_for_room, 3);
        let clearing = cordelia_crypto::entry::Entry::seal(&secret, &s[0].identity, rev, &inside);
        let clearing = clearing.unwrap().check().unwrap();
        cordelia_storage::entries::store(conn, &clearing, now).unwrap();
        for seq in seqs(conn) {
            cordelia_storage::at_relays::refused(conn, &[0x71; 32], &channel, seq).unwrap();
        }
        assert_eq!(counts(0, &channels).refused_for_room, 2);
        // A kept value of a generation the device has left, and one past
        // its 30 days, wait for nothing: they go at the next send or the
        // hourly task.
        let left = held::generation(conn, &[0xee; 32], 1, now).unwrap();
        for (id, generation, sent) in [
            ([0xe1; 16], left, now),
            ([0xe2; 16], generation, now - 30 * 24 * 60 * MINUTE),
        ] {
            let kept = held::Kept {
                id,
                generation,
                value: vec![0; cordelia_core::protocol::AGENT_MESSAGE_VALUE_BYTES],
                sent,
                numbers: Vec::new(),
                again: false,
            };
            held::keep(conn, &kept, now).unwrap();
        }
        assert_eq!(held::kept(conn).unwrap().len(), 5);
        assert_eq!(counts(0, &channels).waiting, 3);
        let full = OwnChannels::default();
        full.say_no_room_for_messages(&messages_channel(&s[0].conn).unwrap().unwrap());
        full.say_no_place(true);
        let on_0 = counts(0, &full);
        assert_eq!(on_0.filled_by, Some(("device 0".into(), 4)));
        assert!(on_0.no_place);
        let answered = on_0.answered();
        assert_eq!(
            answered["filled_by"],
            json!({ "label": "device 0", "entries": 4 })
        );
        assert_eq!(answered["no_place"], true);
        assert_eq!(answered["waiting"], 3);
        for key in [
            "unread_by_an_agent",
            "unread_by_a_person",
            "bounds",
            "waiting",
            "refused_for_room",
            "filled_by",
            "held_back",
            "overwritten",
            "no_place",
        ] {
            assert!(answered.get(key).is_some(), "{key}");
        }
        assert_eq!(answered.as_object().unwrap().len(), 9);
        // A message refused whose 30 days are up waits no more, and is
        // refused of those that wait no more, until the hourly task.
        conn.execute(
            "UPDATE message_kept SET sent = ?2 WHERE id = ?1",
            rusqlite::params![&second.id[..], now - 30 * 24 * 60 * MINUTE],
        )
        .unwrap();
        let on_0 = counts(0, &channels);
        assert_eq!((on_0.waiting, on_0.refused_for_room), (2, 1));

        // A device that does not stand applied says nothing of messages.
        held_rows::set_state(&s[1].conn, State::Removed).unwrap();
        let removed = status_of(&s[1].conn, &s[1].identity, &channels, now).unwrap();
        assert_eq!(removed, None);
    }

    thread_local! {
        /// The statements a connection ran, as its trace gave them.
        static RAN: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    fn traced(sql: &str) {
        RAN.with(|ran| ran.borrow_mut().push(sql.to_string()));
    }

    /// The status of device 0, with `names` folders mapped and `messages`
    /// messages to every name from each of three other devices, all shown:
    /// how many times it read who counts (the statement of the additions
    /// that `who_counts` and every `Standing` read), what is shown (the
    /// statement of `held::shown`), the device's own marks and the lists
    /// kept, and its count of what is unread by an agent.
    fn work_of_a_status(names: usize, messages: u64) -> ([usize; 4], u64) {
        let mut s = devices(4);
        let now = s.now + MINUTE;
        let mapped: Vec<Value> = (0..names)
            .map(|k| json!({ "folder": folder(&format!("name{k}")), "name": format!("name{k}") }))
            .collect();
        meta::set(
            &s[0].conn,
            meta::SYNC_CLAUDE_MAPPINGS,
            &Value::from(mapped).to_string(),
        )
        .unwrap();
        for signer in 1..4usize {
            for number in 1..=messages {
                let mut id = [0u8; 16];
                id[0] = signer as u8;
                id[1] = number as u8;
                let key = s.key(signer);
                held_as(&s, 0, id, key, "notes", None, false, (now, now), number);
            }
        }
        RAN.with(|ran| ran.borrow_mut().clear());
        s.machines[0].conn.trace(Some(traced));
        let counts = status_of(&s[0].conn, &s[0].identity, &OwnChannels::default(), now)
            .unwrap()
            .unwrap();
        s.machines[0].conn.trace(None);
        let ran = RAN.with(|ran| ran.borrow().clone());
        let of = |what: &str| ran.iter().filter(|sql| sql.contains(what)).count();
        (
            [
                of("FROM person_additions"),
                of("MIN(i.sent, i.first_held) AS shown_at, i.subject"),
                of("FROM message_read_here"),
                of("FROM message_lists"),
            ],
            counts.unread_by_an_agent,
        )
    }

    /// The work of a status does not grow with the names mapped times the
    /// messages shown (decision 2026-10-09 §8, property 15): who counts,
    /// the device's own marks and the lists kept are read as often, and
    /// what is shown read once, whether 3 or 30 names are mapped and
    /// whether 2 or 20 messages of each signer are shown. A
    /// status is asked for every few seconds, inside the store's write, and
    /// one that took longer than a command waits would say that the node
    /// had stopped.
    #[test]
    fn a_status_reads_who_counts_and_what_is_shown_as_often_whatever_is_mapped() {
        let (work, unread) = work_of_a_status(3, 2);
        assert_eq!(unread, 3 * 3 * 2);
        let [counted, shown, here, lists] = work;
        assert_eq!(shown, 1);
        assert!(counted >= 1, "{counted}");
        assert!(here >= 1 && lists >= 1, "{work:?}");
        for (names, messages) in [(30, 2), (3, 20), (30, 20)] {
            let (more, unread) = work_of_a_status(names, messages);
            assert_eq!(unread, names as u64 * 3 * messages, "{names} {messages}");
            assert_eq!(more, work, "{names} names, {messages} messages");
        }
    }

    // ── A person's read on every device (decision 2026-10-25, rule 1) ──

    /// The status's counts of device `n` at `now`.
    fn counts_on(s: &Several, n: usize, now: i64) -> Counts {
        status_of(&s[n].conn, &s[n].identity, &OwnChannels::default(), now)
            .unwrap()
            .unwrap()
    }

    /// The entry of device `n`'s own list of a person's reads that its
    /// store holds, in the generation it stands applied under.
    fn person_list_of(s: &Several, n: usize) -> Option<cordelia_crypto::entry::CheckedEntry> {
        let secret = derive::messages_secret(&s[n].secret()).unwrap();
        let slot = cordelia_crypto::slots::slot_id(
            &derive::slot_key(&secret).unwrap(),
            &cordelia_crypto::message::person_name(&s.key(n)).unwrap(),
        );
        let channel = derive::channel_id(&secret).unwrap();
        cordelia_storage::entries::author_entry(&s[n].conn, &channel, &slot, &s.key(n))
            .unwrap()
            .map(|stored| stored.entry.check().unwrap())
    }

    /// Device `to` takes `entry` through the door at `now`.
    fn takes(s: &Several, to: usize, entry: &cordelia_crypto::entry::CheckedEntry, now: i64) {
        let taken = crate::take::take(&s[to].conn, &s[to].identity, entry, now).unwrap();
        assert!(matches!(taken, crate::take::Taken::Own { .. }), "{taken:?}");
    }

    /// Where `log` on device `n` says a person read what it does not show.
    fn read_where(s: &Several, n: usize, now: i64) -> Vec<(Option<String>, usize)> {
        log_on(s, n, None, &[], now)
            .unwrap()
            .already_read_on
            .into_iter()
            .map(|(device, count)| (device.map(|(label, _)| label), count))
            .collect()
    }

    /// The laptop's `log` marks three messages read by a person; the
    /// desktop takes its list, and its pair count, its status's
    /// `unread_by_a_person` and its `log`'s `already_read` count all three
    /// as read by a person (decision 2026-10-25, rule 1).
    #[test]
    fn a_persons_read_on_one_device_counts_on_another() {
        let mut s = devices(2);
        let t = s.now + MINUTE;
        let ids: Vec<Id> = (0..3)
            .map(|k| {
                sent(
                    &s,
                    0,
                    &asking("notes", Some("work"), &format!("{k}")),
                    t + k,
                )
            })
            .collect();
        s.pass(0, 1);
        let now = t + MINUTE;
        assert_eq!(counts_on(&s, 1, now).unread_by_a_person, 3);
        let pairs = |s: &Several| held::pairs_with(&s[1].conn, "work", now, &s.keys_counting(1));
        assert_eq!(pairs(&s).unwrap(), [(Some("notes".to_string()), 3)]);

        let marked = log_on(&s, 0, None, &ids, now).unwrap();
        assert_eq!(marked.marked, 3);
        assert_eq!(marked.list, Some(1));
        s.pass(0, 1);
        assert_eq!(counts_on(&s, 1, now).unread_by_a_person, 0);
        assert!(pairs(&s).unwrap().is_empty());
        let log = log_on(&s, 1, None, &[], now).unwrap();
        assert!(logged_ids(&log).is_empty());
        assert_eq!(log.already_read, 3);
        assert_eq!(read_where(&s, 1, now), [(Some("device 0".to_string()), 3)]);
        // Nothing of it was marked here.
        for id in &ids {
            assert!(!held::is_read_by_a_person(&s[1].conn, id).unwrap());
        }
        // `read`'s header counts the same.
        let id = hex::encode(ids[0]);
        let readout = reads(&s, 1, "work", &id, now).unwrap();
        assert_eq!(
            (readout.pair_count, readout.pair_unread_by_a_person),
            (3, 0)
        );
    }

    /// `log` says where a person read what it does not show (decision
    /// 2026-10-25, rule 1): 3 read here and 7 by the laptop's list, one of
    /// them read both here and there, which counts as here; with a third
    /// device, one read on two other devices counts under the first label,
    /// in order of label, and this device is first.
    #[test]
    fn log_says_where_you_read_what_it_does_not_show() {
        let mut s = devices(3);
        let t = s.now + MINUTE;
        // Two pairs, so that no pair holds on the sender.
        let ids: Vec<Id> = (0..11)
            .map(|k| {
                let to = if k % 2 == 0 { "work" } else { "plans" };
                sent(&s, 0, &asking("notes", Some(to), &format!("{k}")), t + k)
            })
            .collect();
        s.pass(0, 1);
        s.pass(0, 2);
        let now = t + MINUTE;
        log_on(&s, 1, None, &ids[..3], now).unwrap();
        log_on(&s, 0, None, &ids[2..10], now).unwrap();
        s.pass(0, 1);
        assert_eq!(
            read_where(&s, 1, now),
            [(None, 3), (Some("device 0".to_string()), 7)]
        );
        log_on(&s, 2, None, &ids[9..11], now).unwrap();
        s.pass(2, 1);
        assert_eq!(
            read_where(&s, 1, now),
            [
                (None, 3),
                (Some("device 0".to_string()), 7),
                (Some("device 2".to_string()), 1)
            ]
        );
        let log = log_on(&s, 1, None, &[], now).unwrap();
        assert_eq!(log.already_read, 11);
        assert_eq!(
            log.answered()["already_read_on"][1]["device"]["fingerprint"],
            fingerprint::shown(&s.key(0))
        );
        assert_eq!(log.answered()["already_read_on"][0]["device"], "this");
    }

    /// A person's read that arrives before its message loses nothing
    /// (decision 2026-10-25, rule 1, hard case 5): the desktop takes the
    /// laptop's list, then the message, which is read by a person at once
    /// and is never in a pair's count.
    #[test]
    fn a_persons_read_that_arrives_before_its_message_loses_nothing() {
        let mut s = devices(3);
        let t = s.now + MINUTE;
        let id = sent(&s, 0, &asking("notes", Some("work"), "early"), t);
        s.pass(0, 2);
        let now = t + MINUTE;
        log_on(&s, 2, None, &[id], now).unwrap();
        let list = person_list_of(&s, 2).unwrap();
        takes(&s, 1, &list, now);
        let counting = who_counts(&s[1].conn).unwrap();
        assert!(!held::holds_message(&s[1].conn, &id).unwrap());
        assert!(
            marks::person_read_now(&s[1].conn, &counting)
                .unwrap()
                .is_read(&id)
        );
        s.pass(0, 1);
        assert!(held::holds_message(&s[1].conn, &id).unwrap());
        assert!(
            held::pairs_with(&s[1].conn, "work", now, &s.keys_counting(1))
                .unwrap()
                .is_empty()
        );
        let log = log_on(&s, 1, None, &[], now).unwrap();
        assert!(logged_ids(&log).is_empty());
        assert_eq!(log.already_read, 1);
        assert_eq!(counts_on(&s, 1, now).unread_by_a_person, 0);
    }

    /// Device `n` holds `count` messages to `work` from `notes`, as a
    /// reader holds them, from three signers that write nothing else: the
    /// same IDs on each device asked.
    fn held_many(s: &Several, on: &[usize], count: usize, now: i64) -> Vec<Id> {
        let ids: Vec<Id> = (0..count)
            .map(|k| {
                let mut id = [0xe0; 16];
                id[..8].copy_from_slice(&(k as u64).to_be_bytes());
                id
            })
            .collect();
        for n in on {
            for (k, id) in ids.iter().enumerate() {
                let signer = [0xa1 + (k % 3) as u8; 32];
                let number = (k / 3 + 1) as u64;
                held_as(
                    s,
                    *n,
                    *id,
                    signer,
                    "notes",
                    Some("work"),
                    false,
                    (now, now),
                    number,
                );
            }
        }
        ids
    }

    /// A person's read that falls out of the newest list stays read
    /// (decision 2026-10-25, rule 1.2): the laptop marks 130; the desktop
    /// takes its list at 60 and at 130, which holds the newest 120; all 130
    /// stay read there, and the pair counts none.
    #[test]
    fn a_persons_read_that_falls_out_of_the_newest_list_stays_read() {
        let s = devices(2);
        let now = s.now + MINUTE;
        let ids = held_many(&s, &[0, 1], 130, now);
        log_on(&s, 0, None, &ids[..60], now).unwrap();
        let first = person_list_of(&s, 0).unwrap();
        takes(&s, 1, &first, now);
        log_on(&s, 0, None, &ids[60..], now).unwrap();
        let second = person_list_of(&s, 0).unwrap();
        assert_eq!(second.rev, 2);
        let listed = cordelia_crypto::message::PersonReads::from_value(
            &second
                .open(&derive::messages_secret(&s[0].secret()).unwrap())
                .unwrap()
                .value,
        )
        .unwrap();
        assert_eq!(listed.ids.len(), 120);
        assert!(!listed.ids.contains(&ids[0]));
        takes(&s, 1, &second, now + 1);
        let counting = who_counts(&s[1].conn).unwrap();
        let read = marks::person_read_now(&s[1].conn, &counting).unwrap();
        for id in &ids {
            assert!(read.is_read(id), "{}", hex::encode(id));
        }
        assert!(
            held::pairs_with(&s[1].conn, "work", now, &s.keys_counting(1))
                .unwrap()
                .is_empty()
        );
    }

    /// Device `n`'s list of a person's reads at `rev`, holding `ids`.
    fn person_list(
        s: &Several,
        n: usize,
        rev: u64,
        ids: &[Id],
    ) -> cordelia_crypto::entry::CheckedEntry {
        let value = cordelia_crypto::message::PersonReads { ids: ids.to_vec() }
            .to_value()
            .unwrap();
        cordelia_crypto::entry::Entry::seal(
            &derive::messages_secret(&s[n].secret()).unwrap(),
            &s[n].identity,
            rev,
            &cordelia_crypto::message::inside(
                cordelia_crypto::message::person_name(&s.key(n)).unwrap(),
                value,
            ),
        )
        .unwrap()
        .check()
        .unwrap()
    }

    /// The IDs device `n` keeps of `key`'s lists of a person's reads.
    fn kept_of(s: &Several, n: usize, key: &[u8; 32]) -> Vec<Id> {
        let mut ids: Vec<Id> = held::person_reads(&s[n].conn)
            .unwrap()
            .lists
            .into_iter()
            .filter(|(of, _)| of == key)
            .map(|(_, id)| id)
            .collect();
        ids.sort();
        ids
    }

    /// What is kept of messages not held is bounded (decision 2026-10-25,
    /// rule 1.2): a key lists 240 IDs of messages the desktop does not
    /// hold, in two lists; 120 are kept, the latest taken; a third list's
    /// one more keeps it and the newest 119; and each goes 30 days after
    /// it was taken.
    #[test]
    fn what_is_kept_of_messages_not_held_is_bounded() {
        let s = devices(2);
        let t = s.now + MINUTE;
        let id = |k: usize| -> Id {
            let mut id = [0xd0; 16];
            id[..8].copy_from_slice(&(k as u64).to_be_bytes());
            id
        };
        let first: Vec<Id> = (0..120).map(id).collect();
        let second: Vec<Id> = (120..240).map(id).collect();
        takes(&s, 1, &person_list(&s, 0, 1, &first), t);
        takes(&s, 1, &person_list(&s, 0, 2, &second), t + 1);
        let mut newest = second.clone();
        newest.sort();
        assert_eq!(kept_of(&s, 1, &s.key(0)), newest);
        // One more, taken later: it and the newest 119 of the second, the
        // first of that list being its newest.
        let one = id(240);
        let mut third = vec![one];
        third.extend(&second[..119]);
        takes(&s, 1, &person_list(&s, 0, 3, &third), t + 2);
        let kept = kept_of(&s, 1, &s.key(0));
        assert_eq!(kept.len(), 120);
        assert!(kept.contains(&one) && !kept.contains(&second[119]));
        // Each goes 30 days after it was taken.
        let month = i64::from(cordelia_core::protocol::AGENT_MESSAGE_KEPT_DAYS) * 24 * 60 * 60;
        let hourly = |now: i64| {
            crate::reader::hourly(&s[1].conn, &s[1].identity, now, true).unwrap();
        };
        hourly(t + 1 + month - 1);
        assert_eq!(kept_of(&s, 1, &s.key(0)).len(), 120);
        hourly(t + 1 + month);
        assert_eq!(kept_of(&s, 1, &s.key(0)), [one]);
        hourly(t + 2 + month);
        assert!(kept_of(&s, 1, &s.key(0)).is_empty());
    }

    /// A person's read from a key that no longer counts says nothing
    /// (decision 2026-10-25, rule 1): what is kept of it is not read by a
    /// person, and counts towards the pair.
    #[test]
    fn a_persons_read_from_a_key_that_no_longer_counts_says_nothing() {
        let mut s = devices(2);
        let t = s.now + MINUTE;
        let id = sent(&s, 0, &asking("notes", Some("work"), "once"), t);
        s.pass(0, 1);
        let now = t + MINUTE;
        held::keep_person_list(&s[1].conn, &[0x99; 32], &[id], now).unwrap();
        // The status gives places, as a show does.
        assert_eq!(counts_on(&s, 1, now).unread_by_a_person, 1);
        let counting = who_counts(&s[1].conn).unwrap();
        assert!(
            !marks::person_read_now(&s[1].conn, &counting)
                .unwrap()
                .is_read(&id)
        );
        assert_eq!(
            held::pairs_with(&s[1].conn, "work", now, &s.keys_counting(1)).unwrap(),
            [(Some("notes".to_string()), 1)]
        );
        assert_eq!(counts_on(&s, 1, now).unread_by_a_person, 1);
        let log = log_on(&s, 1, None, &[], now).unwrap();
        assert_eq!(logged_ids(&log), [id]);
        // The control: under a key that counts, it is read.
        held::keep_person_list(&s[1].conn, &s.key(0), &[id], now).unwrap();
        assert_eq!(counts_on(&s, 1, now).unread_by_a_person, 0);
    }

    /// A statement drops the rows of a key it does not count (decision
    /// 2026-10-25, rule 1.2, hard case 3): in the transaction that applies
    /// it, so the message only the removed device's person read is unread
    /// by a person again, and holds again; the rows of a key it counts
    /// stay.
    #[test]
    fn a_statement_drops_the_rows_of_a_key_it_does_not_count() {
        let mut s = devices(3);
        let t = s.now + MINUTE;
        let ids: Vec<Id> = (0..2)
            .map(|k| {
                sent(
                    &s,
                    0,
                    &asking("notes", Some("work"), &format!("{k}")),
                    t + k,
                )
            })
            .collect();
        s.pass(0, 1);
        s.pass(0, 2);
        let now = t + MINUTE;
        log_on(&s, 2, None, &ids[..1], now).unwrap();
        log_on(&s, 0, None, &ids[1..], now).unwrap();
        s.pass(2, 1);
        s.pass(0, 1);
        assert_eq!(counts_on(&s, 1, now).unread_by_a_person, 0);
        s.change(0, &[0, 1], &[2]);
        s.meet(&[0, 1]);
        assert_eq!(s[1].number(), 2);
        assert!(kept_of(&s, 1, &s.key(2)).is_empty());
        assert_eq!(kept_of(&s, 1, &s.key(0)), [ids[1]]);
        assert_eq!(counts_on(&s, 1, now).unread_by_a_person, 1);
        let log = log_on(&s, 1, None, &[], now).unwrap();
        assert_eq!(logged_ids(&log), [ids[0]]);
    }

    /// A store restored from a backup takes its own later list of a
    /// person's reads (decision 2026-10-25, rule 1): each ID whose message
    /// it holds goes to its own table, and the rest are kept under its own
    /// key, so each is read by a person; its next list goes above it.
    #[test]
    fn a_persons_list_handed_back_is_merged() {
        let mut s = devices(2);
        let t = s.now + MINUTE;
        let ids: Vec<Id> = (0..2)
            .map(|k| {
                sent(
                    &s,
                    0,
                    &asking("notes", Some("work"), &format!("{k}")),
                    t + k,
                )
            })
            .collect();
        s.pass(0, 1);
        let now = t + MINUTE;
        let not_held = [0xcc; 16];
        let later = person_list(&s, 1, 4, &[ids[1], not_held, ids[0]]);
        takes(&s, 1, &later, now);
        for id in &ids {
            assert!(held::is_read_by_a_person(&s[1].conn, id).unwrap());
        }
        assert_eq!(kept_of(&s, 1, &s.key(1)), [not_held]);
        let counting = who_counts(&s[1].conn).unwrap();
        assert!(
            marks::person_read_now(&s[1].conn, &counting)
                .unwrap()
                .is_read(&not_held)
        );
        // Its next list goes above it, and holds the two it holds.
        let third = sent(&s, 0, &asking("notes", Some("work"), "third"), now);
        s.pass(0, 1);
        let marked = log_on(&s, 1, None, &[third], now + 1).unwrap();
        assert_eq!(marked.list, Some(5));
    }

    /// The lists of a person's reads and of bounds that a store held from
    /// before step 20 are read once after it (decision 2026-10-25, rule
    /// 1): the version before stored them unread and counted each as no
    /// message; the first read takes both, sets the count to 0, and marks
    /// itself done; a device that does not stand applied does nothing and
    /// marks nothing.
    #[test]
    fn lists_held_before_the_upgrade_are_read_after_it() {
        let mut s = devices(3);
        let t = s.now + MINUTE;
        let id = sent(&s, 0, &asking("notes", Some("work"), "read on laptop"), t);
        s.pass(0, 1);
        let now = t + MINUTE;
        log_on(&s, 0, None, &[id], now).unwrap();
        let allow = crate::bounds::Allow {
            pair: crate::bounds::Pair::of("notes", Some("work")),
            bound: Some(20),
            for_secs: 3600,
        };
        crate::bounds::allow(&s[0].conn, &s[0].identity, &allow, now, true, true).unwrap();
        // The version before stored both as a relay does, and counted each
        // as an entry in a slot it did not know.
        let secret = derive::messages_secret(&s[0].secret()).unwrap();
        let channel = derive::channel_id(&secret).unwrap();
        let generation = held::generation_of(&s[1].conn, &channel).unwrap().unwrap();
        let lists: Vec<_> = s[0]
            .stored_in(&secret)
            .into_iter()
            .filter(|entry| entry.author == s.key(0) && entry.rev == 1)
            .collect();
        assert_eq!(lists.len(), 2, "the list of a person's reads and of bounds");
        for entry in &lists {
            cordelia_storage::entries::store(&s[1].conn, entry, now).unwrap();
            held::not_a_message(&s[1].conn, &s.key(0), generation).unwrap();
        }
        assert_eq!(counts_on(&s, 1, now).unread_by_a_person, 1);
        let not_messages = |s: &Several| {
            held::signer(&s[1].conn, &s.key(0), generation)
                .unwrap()
                .unwrap()
                .not_messages
        };
        assert_eq!(not_messages(&s), 2);
        assert!(crate::reader::read_held_lists(&s[1].conn, &s[1].identity, now).unwrap());
        assert_eq!(not_messages(&s), 0);
        assert_eq!(counts_on(&s, 1, now).unread_by_a_person, 0);
        assert_eq!(counts_on(&s, 1, now).bounds.len(), 1);
        assert!(
            meta::get(&s[1].conn, meta::MESSAGES_LISTS_READ)
                .unwrap()
                .is_some()
        );
        // Once only.
        assert!(!crate::reader::read_held_lists(&s[1].conn, &s[1].identity, now).unwrap());

        // A device that does not stand applied does nothing, and marks
        // nothing done.
        s.change(0, &[0, 1], &[2]);
        s.pass(0, 2);
        assert!(!matches!(
            crate::at_relays::stands(&s[2].conn).unwrap(),
            Stands::Applied
        ));
        assert!(!crate::reader::read_held_lists(&s[2].conn, &s[2].identity, now).unwrap());
        assert!(
            meta::get(&s[2].conn, meta::MESSAGES_LISTS_READ)
                .unwrap()
                .is_none()
        );
    }

    /// The known limit (decision 2026-10-25, rule 5, T22): the route of
    /// `log` marks what it is given read by a person for whoever holds the
    /// token, with no terminal at all, and so ends a hold and hides those
    /// messages from `log`. This test fails where that is no longer so, so
    /// that the record is changed with the code.
    #[actix_web::test]
    async fn the_route_marks_with_no_terminal() {
        let (state, id) = a_node_with_a_message();
        let (status, said) =
            answer(log(asked(), state.clone(), log_asked(None, &[id])).await).await;
        assert_eq!(status, 200, "{said}");
        assert_eq!(said["marked"], 1);
        let (_, said) = answer(log(asked(), state.clone(), log_asked(None, &[])).await).await;
        assert_eq!(said["threads"], json!([]));
        assert_eq!(said["already_read"], 1);
    }

    // ── A bound for each pair, set only by a person (decision 2026-10-25,
    // rules 2 and 4) ──────────────────────────────────────────────────

    fn allow_asked(
        a: &str,
        b: Option<&str>,
        bound: Option<u8>,
        for_secs: u32,
        yes: bool,
    ) -> AllowRequest {
        AllowRequest {
            a: a.into(),
            b: b.map(String::from),
            bound,
            for_secs,
            yes,
        }
    }

    /// `allow` on device `n` at `now`, the channel fetched: what it said,
    /// or the word of its refusal.
    fn allows_on(
        s: &Several,
        n: usize,
        asked: &AllowRequest,
        now: i64,
    ) -> Result<AllowSaid, &'static str> {
        allowed_on(s, n, asked, now, true)
    }

    fn allowed_on(
        s: &Several,
        n: usize,
        asked: &AllowRequest,
        now: i64,
        fetched: bool,
    ) -> Result<AllowSaid, &'static str> {
        match allow_of(&s[n].conn, &s[n].identity, asked, now, fetched) {
            Ok(said) => Ok(said),
            Err(NotSentHere::Refused(why)) => Err(why.word()),
            Err(NotSentHere::Asked(_)) => Err("asked"),
            Err(NotSentHere::Said(word, _)) => Err(word),
            Err(NotSentHere::Failed(e)) => panic!("{e}"),
        }
    }

    /// Device `n`'s own list of bounds that its store holds.
    fn bounds_list_of(s: &Several, n: usize) -> Option<cordelia_crypto::entry::CheckedEntry> {
        let secret = derive::messages_secret(&s[n].secret()).unwrap();
        let slot = cordelia_crypto::slots::slot_id(
            &derive::slot_key(&secret).unwrap(),
            &cordelia_crypto::message::hold_name(&s.key(n)).unwrap(),
        );
        let channel = derive::channel_id(&secret).unwrap();
        cordelia_storage::entries::author_entry(&s[n].conn, &channel, &slot, &s.key(n))
            .unwrap()
            .map(|stored| stored.entry.check().unwrap())
    }

    /// Device `n`'s list of bounds at `rev`, holding the bytes `value`.
    fn bounds_entry(
        s: &Several,
        n: usize,
        rev: u64,
        value: Vec<u8>,
    ) -> cordelia_crypto::entry::CheckedEntry {
        cordelia_crypto::entry::Entry::seal(
            &derive::messages_secret(&s[n].secret()).unwrap(),
            &s[n].identity,
            rev,
            &cordelia_crypto::message::inside(
                cordelia_crypto::message::hold_name(&s.key(n)).unwrap(),
                value,
            ),
        )
        .unwrap()
        .check()
        .unwrap()
    }

    /// The bound in force for `pair` on device `n` at `now`.
    fn in_force_on(
        s: &Several,
        n: usize,
        pair: &crate::bounds::Pair,
        now: i64,
    ) -> crate::bounds::InForce {
        let counting = who_counts(&s[n].conn).unwrap();
        crate::bounds::in_force(&s[n].conn, &s.key(n), &counting, pair, now).unwrap()
    }

    /// The look says how many messages of the pair wait, and the bound in
    /// force with when it ends and the device it was set on, or null for
    /// the usual hold (decision 2026-10-25, rule 2): of two names, and of
    /// a name and every agent.
    #[test]
    fn the_look_says_the_count_and_the_bound_in_force() {
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
        sent(&s, 0, &asking("notes", None, "to all"), t + 3);
        s.pass(0, 1);
        let now = t + MINUTE;
        // The status gives places, as a show does.
        counts_on(&s, 1, now);
        let look = allows_on(
            &s,
            1,
            &allow_asked("work", Some("notes"), Some(20), 3600, false),
            now,
        )
        .unwrap();
        assert_eq!(look.pair, crate::bounds::Pair::of("notes", Some("work")));
        assert_eq!(look.allowed.waiting, 3);
        assert!(!look.allowed.set);
        let said = look.answered();
        assert_eq!(said["a"], "notes");
        assert_eq!(said["b"], "work");
        assert_eq!(said["waiting"], 3);
        assert_eq!(said["until"], now + 3600);
        assert_eq!(said["in_force"], Value::Null);
        assert_eq!(said["set"], false);
        let all = allows_on(&s, 1, &allow_asked("notes", None, None, 3600, false), now).unwrap();
        assert_eq!(all.allowed.waiting, 1);
        assert_eq!(all.answered()["b"], Value::Null);
        // Nothing was set by a look.
        assert!(bounds_list_of(&s, 1).is_none());

        // The laptop sets 20; the desktop holds it, and says so.
        allows_on(
            &s,
            0,
            &allow_asked("notes", Some("work"), Some(20), 3600, true),
            now,
        )
        .unwrap();
        takes(&s, 1, &bounds_list_of(&s, 0).unwrap(), now + 1);
        let look = allows_on(
            &s,
            1,
            &allow_asked("notes", Some("work"), None, 3600, false),
            now + 1,
        )
        .unwrap();
        let in_force = &look.answered()["in_force"];
        assert_eq!(in_force["bound"], 20);
        assert_eq!(in_force["until"], now + 3600);
        assert_eq!(in_force["set_on"]["label"], "device 0");
        assert_eq!(
            in_force["set_on"]["fingerprint"],
            fingerprint::shown(&s.key(0))
        );
        let mine = allows_on(
            &s,
            0,
            &allow_asked("notes", Some("work"), None, 3600, false),
            now + 1,
        )
        .unwrap();
        assert_eq!(mine.answered()["in_force"]["set_on"], "this");
        // An any in force is a null bound.
        allows_on(
            &s,
            0,
            &allow_asked("notes", Some("work"), None, 3600, true),
            now + 2,
        )
        .unwrap();
        let any = allows_on(
            &s,
            0,
            &allow_asked("notes", Some("work"), Some(5), 3600, false),
            now + 3,
        )
        .unwrap();
        assert_eq!(any.answered()["in_force"]["bound"], Value::Null);
        assert_eq!(any.answered()["in_force"]["until"], now + 2 + 3600);
    }

    /// The route checks again what the command checks (decision
    /// 2026-10-25, rule 2): a bound of 0 or 65, a `for_secs` of 59 or
    /// 604,801, and a name no device syncs, each before anything is set;
    /// the bounds and the times at their edges are taken.
    #[test]
    fn the_allow_route_refuses_what_the_command_refuses() {
        let s = devices(2);
        let now = s.now + MINUTE;
        for (bound, for_secs) in [
            (Some(0), 3600),
            (Some(65), 3600),
            (Some(5), 59),
            (None, 604_801),
        ] {
            assert_eq!(
                allows_on(
                    &s,
                    0,
                    &allow_asked("notes", Some("work"), bound, for_secs, true),
                    now
                )
                .err(),
                Some("asked"),
                "{bound:?} {for_secs}"
            );
        }
        assert_eq!(
            allows_on(
                &s,
                0,
                &allow_asked("notes", Some("nowhere"), Some(5), 3600, true),
                now
            )
            .err(),
            Some("no_such_name")
        );
        assert_eq!(
            allows_on(
                &s,
                0,
                &allow_asked("nowhere", None, Some(5), 3600, true),
                now
            )
            .err(),
            Some("no_such_name")
        );
        assert!(bounds_list_of(&s, 0).is_none());
        assert!(held::bounds(&s[0].conn).unwrap().is_empty());
        for (bound, for_secs) in [(Some(1), 60), (Some(64), 604_800), (None, 3600)] {
            let said = allows_on(
                &s,
                0,
                &allow_asked("notes", Some("work"), bound, for_secs, true),
                now,
            )
            .unwrap();
            assert!(said.allowed.set);
        }
    }

    /// `allow` is refused where the device does not stand applied, with
    /// sync off, and before its first fetch since the node started, in
    /// that order (decision 2026-10-25, rule 2, refusals 4 and 5): a bound
    /// is set only after the device has read what the relays hold.
    #[test]
    fn allow_is_refused_before_the_first_fetch_and_with_sync_off() {
        let s = devices(2);
        let now = s.now + MINUTE;
        let asked = allow_asked("notes", Some("work"), Some(20), 3600, true);
        assert_eq!(
            allowed_on(&s, 0, &asked, now, false).err(),
            Some("not_fetched")
        );
        meta::remove(&s[0].conn, meta::SYNC_CLAUDE_DIR).unwrap();
        assert_eq!(
            allowed_on(&s, 0, &asked, now, false).err(),
            Some("sync_off")
        );
        assert_eq!(allowed_on(&s, 0, &asked, now, true).err(), Some("sync_off"));
        held_rows::set_state(&s[0].conn, State::Fork).unwrap();
        assert_eq!(
            allowed_on(&s, 0, &asked, now, true).err(),
            Some("not_applied")
        );
        held_rows::set_state(&s[0].conn, State::Applied).unwrap();
        meta::set(&s[0].conn, meta::SYNC_CLAUDE_DIR, "/home/sam/.claude").unwrap();
        assert!(held::bounds(&s[0].conn).unwrap().is_empty());
        assert!(allowed_on(&s, 0, &asked, now, true).unwrap().allowed.set);
    }

    /// A full list of bounds refuses a new pair and takes one it holds
    /// (decision 2026-10-25, rules 2 and 3.6): at the longest names four
    /// bounds fit; a fifth pair is refused with each pair the list holds
    /// and when it leaves the list; each of the four can be set again, in
    /// its place.
    #[test]
    fn a_full_list_of_bounds_refuses_a_new_pair_and_takes_one_it_holds() {
        let s = devices(1);
        let now = s.now + MINUTE;
        let long = |c: char| format!("{c}{}", "x".repeat(199));
        let names: Vec<String> = "abcdez".chars().map(long).collect();
        for name in &names {
            crate::names::say(&s[0].conn, &s[0].identity, name, now).unwrap();
        }
        let z = names[5].as_str();
        for (k, name) in names[..4].iter().enumerate() {
            let said = allows_on(
                &s,
                0,
                &allow_asked(name, Some(z), Some(5), 3600, true),
                now + k as i64,
            )
            .unwrap();
            assert!(said.allowed.set);
        }
        let full = allow_of(
            &s[0].conn,
            &s[0].identity,
            &allow_asked(&names[4], Some(z), Some(5), 3600, true),
            now + 10,
            true,
        );
        let Err(NotSentHere::Refused(Refused::BoundsFull(pairs))) = full else {
            panic!("{full:?}");
        };
        let listed_secs = cordelia_core::protocol::AGENT_MESSAGE_PAIR_BOUND_LISTED_SECS as i64;
        let mut expected: Vec<(crate::bounds::Pair, i64)> = names[..4]
            .iter()
            .enumerate()
            .map(|(k, name)| {
                (
                    crate::bounds::Pair::of(name, Some(z)),
                    now + k as i64 + listed_secs,
                )
            })
            .collect();
        expected.reverse();
        assert_eq!(pairs, expected);
        let said = refusal_said(&s[0].conn, &Refused::BoundsFull(pairs));
        assert_eq!(said["error"]["code"], "bounds_full");
        assert_eq!(said["refused"]["pairs"][0]["until"], now + 3 + listed_secs);
        // A look is refused alike, before the question.
        assert_eq!(
            allows_on(
                &s,
                0,
                &allow_asked(&names[4], Some(z), Some(5), 3600, false),
                now + 10
            )
            .err(),
            Some("bounds_full")
        );
        // Each held can be set again, in its place.
        let again = allows_on(
            &s,
            0,
            &allow_asked(&names[1], Some(z), None, 3600, true),
            now + 11,
        )
        .unwrap();
        assert!(again.allowed.set);
        assert_eq!(held::bounds(&s[0].conn).unwrap().len(), 4);
    }

    /// A bound is listed and taken by another device (decision 2026-10-25,
    /// rule 2): the yes writes the list in the same write; the desktop
    /// takes it, holds by it, and its status says it.
    #[test]
    fn a_bound_is_listed_and_taken_by_another_device() {
        let s = devices(2);
        let now = s.now + MINUTE;
        let said = allows_on(
            &s,
            0,
            &allow_asked("work", Some("notes"), Some(20), 3600, true),
            now,
        )
        .unwrap();
        assert_eq!(said.allowed.list, Some(1));
        let pair = crate::bounds::Pair::of("notes", Some("work"));
        assert_eq!(in_force_on(&s, 1, &pair, now + 1).stops_at(), Some(10));
        takes(&s, 1, &bounds_list_of(&s, 0).unwrap(), now + 1);
        assert_eq!(in_force_on(&s, 1, &pair, now + 1).stops_at(), Some(20));
        let bounds = counts_on(&s, 1, now + 1).bounds;
        assert_eq!(bounds.len(), 1);
        assert_eq!(bounds[0].bound, Some(20));
        assert_eq!(bounds[0].set_on.as_ref().unwrap().0, "device 0");
    }

    /// A list of bounds that is not one is no list (decision 2026-10-25,
    /// rule 2): one case for each check, each counted as no message, and
    /// each drops that key's bounds where it is of form 4; a form this
    /// version does not know keeps them.
    #[test]
    fn a_list_of_bounds_that_is_not_one_is_no_list() {
        use cordelia_core::protocol::AGENT_MESSAGE_VALUE_BYTES;
        let good_bound = |a: &str, b: Option<&str>| cordelia_crypto::message::PairBound {
            a: a.into(),
            b: b.map(String::from),
            bound: Some(20),
            set: 1_900_000_000,
            at: 1_800_000_000,
            for_secs: 3600,
        };
        let good = cordelia_crypto::message::PairBounds {
            bounds: vec![good_bound("notes", Some("work"))],
        }
        .to_value(crate::names::is_a_name)
        .unwrap();
        let written = |bytes: &[u8]| {
            let mut value = bytes.to_vec();
            value.resize(AGENT_MESSAGE_VALUE_BYTES, 0);
            value
        };
        // One bound, by hand: a, kind, b, bound, set, at, for.
        let by_hand = |a: &[u8], kind: u8, b: &[u8], bound: u8, for_secs: u32| {
            let mut out = vec![4, 1, 0, a.len() as u8];
            out.extend_from_slice(a);
            out.push(kind);
            if kind == 1 {
                out.extend_from_slice(&[0, b.len() as u8]);
                out.extend_from_slice(b);
            }
            out.push(bound);
            out.extend_from_slice(&1_900_000_000u64.to_be_bytes());
            out.extend_from_slice(&1_800_000_000u64.to_be_bytes());
            out.extend_from_slice(&for_secs.to_be_bytes());
            written(&out)
        };
        let mut twice = cordelia_crypto::message::PairBounds {
            bounds: vec![good_bound("notes", Some("work")), good_bound("notes", None)],
        }
        .to_value(crate::names::is_a_name)
        .unwrap();
        // The second bound made the first's pair.
        let at = twice.iter().rposition(|b| *b == 2).unwrap();
        let mut second_as_first = twice[..at].to_vec();
        second_as_first.extend_from_slice(&[1, 0, 4]);
        second_as_first.extend_from_slice(b"work");
        second_as_first.extend_from_slice(&twice[at + 1..]);
        second_as_first.truncate(AGENT_MESSAGE_VALUE_BYTES);
        twice = second_as_first;
        let mut past = good.clone();
        past[1] = 2;
        let mut fill = good.clone();
        fill[AGENT_MESSAGE_VALUE_BYTES - 1] = 7;
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "a name that is not a name",
                by_hand(b"NOTES", 1, b"work", 20, 3600),
            ),
            (
                "a kind other than 1 or 2",
                by_hand(b"notes", 3, b"work", 20, 3600),
            ),
            ("a above b", by_hand(b"work", 1, b"notes", 20, 3600)),
            ("a bound over 64", by_hand(b"notes", 1, b"work", 65, 3600)),
            ("a for below 60", by_hand(b"notes", 1, b"work", 20, 59)),
            (
                "a for over 604,800",
                by_hand(b"notes", 1, b"work", 20, 604_801),
            ),
            ("two bounds of one pair", twice),
            ("bytes that run past the value", past),
            ("a fill that is not zeros", fill),
        ];
        let pair = crate::bounds::Pair::of("notes", Some("work"));
        for (case, bad) in cases {
            let s = devices(2);
            let now = s.now + MINUTE;
            takes(&s, 1, &bounds_entry(&s, 0, 1, good.clone()), now);
            assert_eq!(
                in_force_on(&s, 1, &pair, now).stops_at(),
                Some(20),
                "{case}"
            );
            let generation = held::generation_of(
                &s[1].conn,
                &derive::channel_id(&derive::messages_secret(&s[1].secret()).unwrap()).unwrap(),
            )
            .unwrap()
            .unwrap();
            let before = held::signer(&s[1].conn, &s.key(0), generation)
                .unwrap()
                .unwrap_or_default()
                .not_messages;
            takes(&s, 1, &bounds_entry(&s, 0, 2, bad), now);
            assert_eq!(
                in_force_on(&s, 1, &pair, now).stops_at(),
                Some(10),
                "{case}"
            );
            assert!(held::bounds(&s[1].conn).unwrap().is_empty(), "{case}");
            let after = held::signer(&s[1].conn, &s.key(0), generation)
                .unwrap()
                .unwrap()
                .not_messages;
            assert_eq!(after, before + 1, "{case}");
        }
        // A form this version does not know leaves that key's bounds as
        // they were.
        let s = devices(2);
        let now = s.now + MINUTE;
        takes(&s, 1, &bounds_entry(&s, 0, 1, good.clone()), now);
        takes(&s, 1, &bounds_entry(&s, 0, 2, written(&[9, 1, 2, 3])), now);
        assert_eq!(in_force_on(&s, 1, &pair, now).stops_at(), Some(20));
    }

    /// A store restored from a backup takes its own later list of bounds
    /// (decision 2026-10-25, rule 2): merged into its own bounds by pair,
    /// the later `set` kept; its next list goes above it.
    #[test]
    fn a_restored_store_takes_its_own_later_bounds() {
        let s = devices(2);
        let now = s.now + MINUTE;
        allows_on(
            &s,
            0,
            &allow_asked("notes", Some("work"), Some(20), 3600, true),
            now,
        )
        .unwrap();
        let held_set = held::bounds(&s[0].conn).unwrap()[0].set;
        let later = cordelia_crypto::message::PairBounds {
            bounds: vec![
                cordelia_crypto::message::PairBound {
                    a: "notes".into(),
                    b: Some("work".into()),
                    bound: None,
                    set: held_set + 5,
                    at: (now + 5) as u64,
                    for_secs: 3600,
                },
                cordelia_crypto::message::PairBound {
                    a: "plans".into(),
                    b: None,
                    bound: Some(3),
                    set: (now + 4) as u64,
                    at: (now + 4) as u64,
                    for_secs: 3600,
                },
            ],
        }
        .to_value(crate::names::is_a_name)
        .unwrap();
        takes(&s, 0, &bounds_entry(&s, 0, 6, later), now + 10);
        let pair = crate::bounds::Pair::of("notes", Some("work"));
        assert_eq!(in_force_on(&s, 0, &pair, now + 10).stops_at(), None);
        assert_eq!(
            in_force_on(&s, 0, &crate::bounds::Pair::of("plans", None), now + 10).stops_at(),
            Some(3)
        );
        let set = allows_on(
            &s,
            0,
            &allow_asked("notes", Some("work"), Some(30), 3600, true),
            now + 11,
        )
        .unwrap();
        assert_eq!(set.allowed.list, Some(7));
        assert_eq!(in_force_on(&s, 0, &pair, now + 12).stops_at(), Some(30));
    }

    /// A restored store that reaches its later list late keeps both lives'
    /// last acts (decision 2026-10-25, rule 2, the review's two cases):
    /// its first life set any, its later life ended it with a 10, and the
    /// store went back to the any. After the restart a person sets a pair
    /// of its own. Where a relay answers another to its list, it drops its
    /// own bounds set before this start, the any among them, and keeps
    /// what was set since; where a relay answers that it holds a later
    /// list, nothing changes until the next pull hands that back, which is
    /// merged: the 10 decides, and what was set since stays.
    #[test]
    fn a_restored_store_that_reaches_its_later_list_late_keeps_both_lives_last_acts() {
        use crate::at_relays::{Kind, Pushed};
        let pair = crate::bounds::Pair::of("notes", Some("work"));
        let since = crate::bounds::Pair::of("plans", Some("work"));
        for answered_another in [true, false] {
            let s = devices(2);
            let now = s.now + MINUTE;
            crate::bounds::started(&s[0].conn).unwrap();
            allows_on(
                &s,
                0,
                &allow_asked("notes", Some("work"), None, 3600, true),
                now,
            )
            .unwrap();
            let backup_set = held::bounds(&s[0].conn).unwrap()[0].set;
            // The later life's list, which the relays hold: the 10.
            let later = cordelia_crypto::message::PairBounds {
                bounds: vec![cordelia_crypto::message::PairBound {
                    a: "notes".into(),
                    b: Some("work".into()),
                    bound: Some(10),
                    set: backup_set + 1,
                    at: (now + 60) as u64,
                    for_secs: 604_800,
                }],
            }
            .to_value(crate::names::is_a_name)
            .unwrap();
            // At the revision the restored store next writes, where a relay
            // answers another; above it, where it answers that it holds a
            // later one.
            let later = bounds_entry(&s, 0, if answered_another { 2 } else { 5 }, later);
            // The restored store starts again, and a person sets a pair.
            crate::bounds::started(&s[0].conn).unwrap();
            allows_on(
                &s,
                0,
                &allow_asked("plans", Some("work"), Some(4), 3600, true),
                now + 120,
            )
            .unwrap();
            assert_eq!(in_force_on(&s, 0, &pair, now + 121).stops_at(), None);
            let pushed = bounds_list_of(&s, 0).unwrap().into_entry();
            let channels = crate::at_relays::channels(&s[0].conn, &s[0].identity).unwrap();
            let channel = channels
                .iter()
                .find(|own| own.kind == Kind::Messages)
                .unwrap();
            let answer = match answered_another {
                true => Pushed::HoldsAnother,
                false => Pushed::HoldsLater,
            };
            crate::marks::answered(
                &s[0].conn,
                &s[0].identity,
                channel,
                std::slice::from_ref(&pushed),
                &[answer],
                now + 122,
                true,
            )
            .unwrap();
            match answered_another {
                true => {
                    assert_eq!(in_force_on(&s, 0, &pair, now + 123).stops_at(), Some(10));
                    assert_eq!(bounds_list_of(&s, 0).unwrap().rev, pushed.rev + 1);
                }
                false => {
                    assert_eq!(in_force_on(&s, 0, &pair, now + 123).stops_at(), None);
                    takes(&s, 0, &later, now + 124);
                    assert_eq!(in_force_on(&s, 0, &pair, now + 125).stops_at(), Some(10));
                }
            }
            assert_eq!(in_force_on(&s, 0, &since, now + 125).stops_at(), Some(4));
        }
    }

    /// The known limit (decision 2026-10-25, rule 5, T22): the route of
    /// `allow` sets any bound for whoever holds the token, with no terminal
    /// at all. This test fails where that is no longer so, so that the
    /// record is changed with the code.
    #[actix_web::test]
    async fn the_route_sets_a_bound_with_no_terminal() {
        let (state, _) = a_node_with_a_message();
        // A node set up with no relay has fetched what there is to fetch.
        state.own_channels.set_up_with(0);
        let body = web::Json(allow_asked("notes", Some("work"), None, 604_800, true));
        let (status, said) = answer(allow(asked(), state.clone(), body).await).await;
        assert_eq!(status, 200, "{said}");
        assert_eq!(said["set"], true);
        let rows = held::bounds(&state.db.lock().unwrap()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].bound, None);
        // Without the token, nothing.
        let body = web::Json(allow_asked("notes", Some("work"), Some(3), 3600, true));
        let (status, _) = answer(allow(not_asked(), state.clone(), body).await).await;
        assert_eq!(status, 401);
    }

    /// The status object carries each bound in force that is not the usual
    /// hold (decision 2026-10-25, rule 4): `a`, `b` (null for every agent),
    /// `bound` (null for any), `until` in RFC 3339 and `set_on`; nothing
    /// for a listed 10, or for one that has ended.
    #[test]
    fn the_status_object_carries_the_bounds() {
        let s = devices(2);
        let now = s.now + MINUTE;
        allows_on(
            &s,
            0,
            &allow_asked("notes", Some("work"), Some(20), 3600, true),
            now,
        )
        .unwrap();
        allows_on(&s, 0, &allow_asked("plans", None, None, 7200, true), now).unwrap();
        allows_on(
            &s,
            1,
            &allow_asked("notes", Some("plans"), Some(10), 3600, true),
            now,
        )
        .unwrap();
        takes(&s, 1, &bounds_list_of(&s, 0).unwrap(), now + 1);
        let said = counts_on(&s, 1, now + 1).answered();
        let bounds = said["bounds"].as_array().unwrap();
        assert_eq!(bounds.len(), 2, "{said}");
        assert_eq!(
            bounds[0],
            json!({ "a": "notes", "b": "work", "bound": 20,
                    "until": rfc3339(now + 3600),
                    "set_on": { "label": "device 0", "fingerprint": fingerprint::shown(&s.key(0)) } })
        );
        assert_eq!(bounds[1]["a"], "plans");
        assert_eq!(bounds[1]["b"], Value::Null);
        assert_eq!(bounds[1]["bound"], Value::Null);
        let mine = counts_on(&s, 0, now + 1).answered();
        assert_eq!(mine["bounds"][0]["set_on"], "this");
        assert!(rfc3339(now).ends_with('Z'));
        // Ended: nothing.
        let later = counts_on(&s, 1, now + 7200).answered();
        assert_eq!(later["bounds"], json!([]));
    }
}
