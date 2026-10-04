//! Local history over the API: what `cordelia history`, `history show`,
//! `restore` and `history drop` do (decision 2026-09-30 §4.5b).
//!
//! Listing and showing only read. A restore and a drop change the store or
//! a memory folder, so each takes the turn that a sync cycle takes
//! ([`crate::state::History`]), and gives up with "busy" if a cycle holds
//! it for too long: nothing is queued, so nothing is carried out after the
//! node has answered. (A command that is interrupted before the node
//! answers is not taken back: what it asked for may still be done.)

use std::path::Path;
use std::time::Duration;

use actix_web::{HttpRequest, HttpResponse, web};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use cordelia_core::claude_code::is_safe_file_name;
use cordelia_core::protocol::HISTORY_TURN_WAIT_SECS;
use cordelia_storage::atomic::write_atomic;
use cordelia_storage::history::{About, Change, Id, Record, Replacement, Store, Whose, kept};
use cordelia_storage::meta;

use crate::auth;
use crate::error::ApiError;
use crate::state::AppState;

/// The index file: restoring it says which lines go.
const INDEX_FILE: &str = "MEMORY.md";

// ── What is asked and answered ─────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
pub struct ListRequest {
    /// An agent's name, or the folder it works in. Without it, only the
    /// summary is returned.
    #[serde(default)]
    pub of: Option<String>,
    /// What was typed, as a full path, where a directory of that name is
    /// there: records of `of` taken as a name, and of this folder, are
    /// both listed. A name that a directory happens to have is still a
    /// name.
    #[serde(default)]
    pub folder: Option<String>,
    /// Only files that were removed and are still absent, each with the
    /// record to restore it from.
    #[serde(default)]
    pub removed: bool,
    /// Only records written at or after this time (RFC 3339).
    #[serde(default)]
    pub since: Option<String>,
}

/// One record, as it is listed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Line {
    pub id: String,
    pub at: String,
    pub agent: String,
    pub folder: String,
    pub file: String,
    pub change: Change,
    /// Whose text is kept, or `None` where none is.
    pub text_of: Option<Whose>,
    pub replaced_by: Replacement,
    pub behind: bool,
    pub interrupted: bool,
}

impl Line {
    fn of(record: &Record) -> Self {
        let about = &record.about;
        Self {
            id: record.id.to_string(),
            at: about.at.clone(),
            agent: about.agent.clone(),
            folder: about.folder.clone(),
            file: about.file.clone(),
            change: about.change,
            text_of: about.kept.as_ref().map(|k| k.whose.clone()),
            replaced_by: about.replaced_by.clone(),
            behind: about.behind,
            interrupted: record.interrupted,
        }
    }
}

/// What is kept for one agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Agent {
    pub agent: String,
    pub folder: String,
    pub records: usize,
    pub oldest: String,
    pub newest: String,
}

#[derive(Debug, Default, Serialize)]
pub struct ListResponse {
    /// Whether history is kept on this device at all.
    pub on: bool,
    pub days: u32,
    pub max_bytes: u64,
    /// How much is kept, and from when.
    pub bytes: u64,
    pub oldest: Option<String>,
    pub agents: Vec<Agent>,
    /// Newest first. Empty unless an agent was asked for.
    pub records: Vec<Line>,
    /// Records that cannot be read. They count towards the size and go
    /// when they are old.
    pub unreadable: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ShowRequest {
    pub id: String,
}

#[derive(Debug, Serialize)]
pub struct ShowResponse {
    pub record: Line,
    /// The text as it was, or `None` where the record keeps none.
    pub text: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RestoreRequest {
    pub ids: Vec<String>,
}

/// What became of one id given to `restore`.
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct Restored {
    pub id: String,
    pub done: bool,
    /// What was done, or why nothing was.
    pub message: String,
    /// The file that was written.
    pub file: Option<String>,
    /// The record that keeps what the restore replaced: restoring that
    /// one undoes it. `None` where the file was absent, when undoing is
    /// deleting it; and where the record could not be made final, when it
    /// is listed, as interrupted, after the next sweep of history (within
    /// an hour that the machine is awake, and when the node starts).
    pub undo: Option<String>,
    /// There was no file: the restore brought it back.
    pub was_absent: bool,
    /// Whether the folder syncs now, so that the restored text goes to the
    /// other devices at the next cycle.
    pub syncs: Syncs,
    /// The kept text was behind what replaced it: another device may hold
    /// a newer copy.
    pub behind: bool,
    /// For the index: the lines of the index as it was that are not in the
    /// restored one.
    pub lines_gone: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RestoreResponse {
    pub results: Vec<Restored>,
}

/// Whether a restored text will sync, as far as the node can tell from
/// the report its last whole cycle left.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Syncs {
    /// Its folder synced in that cycle, with nothing to report.
    Yes,
    /// Sync is off, or that cycle did not have the folder.
    No,
    /// The folder is to sync, and waits to join its channel.
    Waits,
    /// The text does not fit in an entry, so it stays on this device
    /// whatever its folder does.
    TooLarge,
    /// It cannot be told: there is no report since a setting last
    /// changed, the cycle ended before it reached its folders, or the
    /// report has something to say of this one (it failed, or ended part
    /// of the way through, or Claude Code keeps its memory elsewhere).
    /// (A report is not removed when the node starts: for the seconds
    /// until the first cycle ends, the answer is the last run's.)
    #[default]
    Unknown,
}

#[derive(Debug, Default, Deserialize)]
pub struct DropRequest {
    /// An agent's name, or the folder it works in.
    #[serde(default)]
    pub of: Option<String>,
    /// As in [`ListRequest`].
    #[serde(default)]
    pub folder: Option<String>,
    /// One file of it.
    #[serde(default)]
    pub file: Option<String>,
    /// Everything kept on this device.
    #[serde(default)]
    pub all: bool,
}

#[derive(Debug, Serialize)]
pub struct DropResponse {
    /// The records removed: those asked for, and every other record on
    /// this device that held the same text as one of them.
    pub dropped: Vec<Line>,
    /// How many records were removed (with `all`, readable or not).
    pub removed: usize,
    /// How many were to go and could not be removed: they are still on
    /// this device.
    pub left: usize,
    /// How many records are left pending that could be neither marked nor
    /// read. Nothing shows whose they are, so a drop that names records
    /// leaves them, and says that they are there: one may hold the text.
    pub unreadable: usize,
}

// ── Reading ────────────────────────────────────────────────────────

fn io(what: &str) -> impl Fn(std::io::Error) -> ApiError + '_ {
    move |e| ApiError::Internal(format!("history: {what}: {e}"))
}

/// Whether a record is of `of`: the agent's name, its memory folder, or
/// the folder the agent works in (under the Claude Code directory in use).
fn is_of(about: &About, of: &str, claude_dir: Option<&str>) -> bool {
    about.agent == of
        || about.folder == of
        || claude_dir.is_some_and(|dir| about.folder == crate::sync::memory_folder(dir, of))
}

/// Whether a record is of what was asked for: as it was typed, or as the
/// directory of that name.
fn asked_for(about: &About, of: &str, folder: Option<&str>, claude_dir: Option<&str>) -> bool {
    is_of(about, of, claude_dir) || folder.is_some_and(|path| is_of(about, path, claude_dir))
}

fn claude_dir(state: &AppState) -> Result<Option<String>, ApiError> {
    let db = state
        .db
        .lock()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(meta::get(&db, meta::SYNC_CLAUDE_DIR)?)
}

/// What `POST /api/v1/history/list` answers.
pub fn list(state: &AppState, request: &ListRequest) -> Result<ListResponse, ApiError> {
    let Some(store) = state.history.store() else {
        return Ok(ListResponse::default());
    };
    let since = match &request.since {
        Some(text) => Some(
            DateTime::parse_from_rfc3339(text)
                .map_err(|_| ApiError::BadRequest(format!("{text} is not a time")))?
                .with_timezone(&Utc),
        ),
        None => None,
    };
    let listing = store.list().map_err(io("cannot be read"))?;
    let mut response = ListResponse {
        on: true,
        days: store.days(),
        max_bytes: store.max_bytes(),
        bytes: listing.bytes,
        oldest: listing.records.last().map(|r| r.about.at.clone()),
        unreadable: listing.unreadable.iter().map(Id::to_string).collect(),
        ..Default::default()
    };
    // Newest first, so the first record seen of an agent is its newest.
    for record in &listing.records {
        let about = &record.about;
        let seen = response
            .agents
            .iter_mut()
            .find(|a| a.agent == about.agent && a.folder == about.folder);
        match seen {
            Some(agent) => {
                agent.records += 1;
                agent.oldest = about.at.clone();
            }
            None => response.agents.push(Agent {
                agent: about.agent.clone(),
                folder: about.folder.clone(),
                records: 1,
                oldest: about.at.clone(),
                newest: about.at.clone(),
            }),
        }
    }
    response
        .agents
        .sort_by(|a, b| (&a.agent, &a.folder).cmp(&(&b.agent, &b.folder)));

    let Some(of) = &request.of else {
        return Ok(response);
    };
    let dir = claude_dir(state)?;
    let written_since = |about: &About| match since {
        Some(since) => DateTime::parse_from_rfc3339(&about.at).is_ok_and(|at| at >= since),
        None => true,
    };
    let mut records: Vec<&Record> = listing
        .records
        .iter()
        .filter(|r| asked_for(&r.about, of, request.folder.as_deref(), dir.as_deref()))
        .collect();
    if request.removed {
        // For each file, its newest record. It is listed if that record
        // is of a removal, it keeps the text, and the file is still
        // absent: restoring it brings the file back as it was.
        let mut newest: Vec<&Record> = Vec::new();
        for record in records {
            let same = |r: &&Record| {
                r.about.folder == record.about.folder && r.about.file == record.about.file
            };
            if !newest.iter().any(same) {
                newest.push(record);
            }
        }
        records = newest
            .into_iter()
            .filter(|r| matches!(r.about.change, Change::Removed | Change::DeletedHere))
            .filter(|r| r.about.kept.is_some())
            .filter(|r| !Path::new(&r.about.folder).join(&r.about.file).exists())
            .collect();
    }
    response.records = records
        .into_iter()
        .filter(|r| written_since(&r.about))
        .map(Line::of)
        .collect();
    Ok(response)
}

/// The store, or the refusal for a command that needs one.
fn store_of(state: &AppState) -> Result<Store, ApiError> {
    state.history.store().ok_or_else(|| {
        ApiError::BadRequest("history is turned off on this device (history.days is 0)".into())
    })
}

/// An id as it was given, if it has the shape of one. Checked before any
/// path is made from it.
fn id_of(text: &str) -> Result<Id, String> {
    Id::parse(text).ok_or_else(|| format!("{text:?} is not a record's id (14 hex digits)"))
}

/// What `POST /api/v1/history/show` answers.
pub fn show(state: &AppState, request: &ShowRequest) -> Result<ShowResponse, ApiError> {
    let store = store_of(state)?;
    let id = id_of(&request.id).map_err(ApiError::BadRequest)?;
    let (record, text) = store
        .read(&id)
        .map_err(|e| match e.kind() {
            // The record is there, and is not the text that was kept.
            std::io::ErrorKind::InvalidData => ApiError::Conflict(e.to_string()),
            _ => io("cannot be read")(e),
        })?
        .ok_or_else(|| ApiError::NotFound(format!("no record {id} in history")))?;
    Ok(ShowResponse {
        record: Line::of(&record),
        text,
    })
}

// ── Restoring ──────────────────────────────────────────────────────

/// How long a restore or a drop waits for its turn.
const TURN_WAIT: Duration = Duration::from_secs(HISTORY_TURN_WAIT_SECS);

/// The turn, or the answer that the node is busy.
fn turn(state: &AppState, wait: Duration) -> Result<std::sync::MutexGuard<'_, ()>, ApiError> {
    state.history.turn_within(wait).ok_or_else(|| {
        ApiError::Conflict(
            "the node is busy syncing and did not come free. Nothing was done; try again".into(),
        )
    })
}

/// Whether `folder` (a memory folder) syncs now.
///
/// It is read from the report the node's last whole cycle left, which is
/// removed whenever a setting changes. A folder that the cycle gave a
/// channel, with nothing to say of it, synced. (A file that failed is
/// reported by itself, and its folder synced.) One that the report says
/// anything of may or may not sync in the next cycle: it failed before
/// it began, or part of the way through, or Claude Code has moved its
/// memory. A cycle that ended before it reached its folders says nothing
/// of any of them.
fn syncs(state: &AppState, folder: &str) -> Syncs {
    let Ok(db) = state.db.lock() else {
        return Syncs::Unknown;
    };
    match meta::get(&db, meta::SYNC_CLAUDE_DIR) {
        Ok(Some(_)) => {}
        // Sync is off.
        Ok(None) => return Syncs::No,
        Err(_) => return Syncs::Unknown,
    }
    let report = meta::get(&db, meta::SYNC_CLAUDE_REPORT).ok().flatten();
    let Some(report) =
        report.and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
    else {
        return Syncs::Unknown;
    };
    // A report from before the settings last changed is not of what syncs
    // now.
    if report["generation"].as_u64() != Some(state.sync_control.generation_under(&db)) {
        return Syncs::Unknown;
    }
    let Some(folders) = report["folders"].as_array() else {
        return Syncs::Unknown;
    };
    let listed = folders.iter().find(|f| {
        f["folder"]
            .as_str()
            .is_some_and(|dir| Path::new(dir).join("memory") == Path::new(folder))
    });
    let reached_none = folders.is_empty()
        && report["errors"]
            .as_array()
            .is_some_and(|errors| !errors.is_empty());
    match listed {
        None if reached_none => Syncs::Unknown,
        None => Syncs::No,
        Some(f) if f["waiting"] == true => Syncs::Waits,
        Some(f) if f["channel_id"].is_string() && f["error"].is_null() => Syncs::Yes,
        Some(_) => Syncs::Unknown,
    }
}

/// The file as it is now: its text, or `None` if it is absent. A link, a
/// directory, or a file that is not text is an error: what the restore
/// would replace could not be kept.
fn text_now(path: &Path) -> Result<Option<String>, String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot be read ({e})")),
        Ok(meta) if !meta.file_type().is_file() => {
            Err("is a link or a directory, not a file".to_string())
        }
        Ok(_) => match std::fs::read(path).map(String::from_utf8) {
            Ok(Ok(text)) => Ok(Some(text)),
            Ok(Err(_)) => Err("is not text, so what is there now could not be kept".to_string()),
            Err(e) => Err(format!("cannot be read ({e})")),
        },
    }
}

/// Put one kept text back. `Err` is the reason nothing was done.
/// `flushed` is run once the text is flushed and before the last look at
/// the file: nothing, except in a test.
fn restore_one(
    state: &AppState,
    store: &Store,
    given: &str,
    now: DateTime<Utc>,
    flushed: &dyn Fn(),
) -> Result<Restored, String> {
    let id = id_of(given)?;
    let (record, text) = store
        .read(&id)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::InvalidData => e.to_string(),
            _ => format!("history cannot be read ({e})"),
        })?
        .ok_or_else(|| "no such record in history".to_string())?;
    let about = &record.about;
    let text = text.ok_or_else(|| {
        format!(
            "this record keeps no text: {} was not here before the change",
            about.file
        )
    })?;
    if !is_safe_file_name(&about.file) {
        return Err("the record names a file that is not a plain file name".to_string());
    }
    // One file written into a folder that has gone would make the folder
    // look emptied, and the rest would sync as deletes.
    let folder = Path::new(&about.folder);
    if !folder.is_dir() {
        return Err(format!(
            "its memory folder is not there ({}). Bring the folder back first",
            about.folder
        ));
    }
    let target = folder.join(&about.file);
    let display = target.display().to_string();
    let before = text_now(&target).map_err(|why| format!("{display} {why}"))?;
    // A text that fits in no entry stays on this device, whether or not
    // its folder syncs: a record keeps a text of any size (what a restore
    // replaced, say), and a restore puts back whatever it kept.
    let syncs = match crate::entries::fits(&about.file, &serde_json::json!(text)) {
        true => syncs(state, &about.folder),
        false => Syncs::TooLarge,
    };
    let mut restored = Restored {
        id: id.to_string(),
        done: true,
        file: Some(display.clone()),
        was_absent: before.is_none(),
        syncs,
        behind: about.behind,
        ..Default::default()
    };
    if before.as_deref() == Some(text.as_str()) {
        restored.message = format!("{display} already holds that text. Nothing changed");
        return Ok(restored);
    }

    // No kept copy, no replacement: what is there now goes into history
    // first, and the restore can then be undone by that record's id.
    let kept_now = About {
        at: String::new(),
        agent: about.agent.clone(),
        folder: about.folder.clone(),
        file: about.file.clone(),
        change: Change::Restored,
        kept: before
            .as_deref()
            .map(|t| kept(Whose::Here { agreed: None }, t)),
        replaced_by: Replacement::Record(id.to_string()),
        behind: false,
    };
    let pending = store
        .keep(kept_now, before.as_deref(), now)
        .map_err(|e| format!("what {display} holds now could not be kept ({e})"))?;
    // Written as the adapter writes a file: flushed, never through a link
    // left under its temporary name, and only if the file is still what
    // was kept, looked at as the last thing before it is replaced. An
    // agent may have written it since it was read.
    let unchanged = || text_now(&target).ok().as_ref() == Some(&before);
    let written = write_atomic(folder, &about.file, &text, flushed, &unchanged);
    if !written.map_err(|e| format!("{display}: {e}"))? {
        return Err(format!("{display} changed while it was being restored"));
    }
    // Left pending where it cannot be made final: the text is kept either
    // way, and is listed, as interrupted, after the next sweep.
    let undo = store.settle(pending).ok();

    if about.file == INDEX_FILE {
        let kept_lines: Vec<&str> = text.lines().collect();
        restored.lines_gone = before
            .as_deref()
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty() && !kept_lines.contains(line))
            .map(String::from)
            .collect();
    }
    restored.undo = before
        .is_some()
        .then_some(undo)
        .flatten()
        .map(|id| id.to_string());
    restored.message = format!("{display} restored");
    Ok(restored)
}

/// What `POST /api/v1/history/restore` does: each id by itself, in the
/// order given. One that fails does not stop the rest. It waits up to
/// `wait` for its turn, and does nothing if that does not come.
pub fn restore(
    state: &AppState,
    request: &RestoreRequest,
    wait: Duration,
) -> Result<RestoreResponse, ApiError> {
    restore_with(state, request, &Utc::now, wait, &|| {})
}

/// [`restore`], with the clock, and with what a test does while a restored
/// text is flushed. The clock is read once the turn has come, for each id:
/// a record of what a restore replaced is as old as the restore, not as
/// the request, which may have waited while a cycle kept texts of its own.
fn restore_with(
    state: &AppState,
    request: &RestoreRequest,
    clock: &dyn Fn() -> DateTime<Utc>,
    wait: Duration,
    flushed: &dyn Fn(),
) -> Result<RestoreResponse, ApiError> {
    let store = store_of(state)?;
    let _turn = turn(state, wait)?;
    let results = request
        .ids
        .iter()
        .map(|given| {
            restore_one(state, &store, given, clock(), flushed).unwrap_or_else(|why| Restored {
                id: given.clone(),
                message: why,
                ..Default::default()
            })
        })
        .collect();
    Ok(RestoreResponse { results })
}

// ── Dropping ───────────────────────────────────────────────────────

/// What `POST /api/v1/history/drop` does: remove the records asked for,
/// and every other record on this device that holds the same text as one
/// of them. A conflict file holds a copy of the text it was made from, so
/// a text dropped under one name alone would stay under the other.
pub fn drop_records(
    state: &AppState,
    request: &DropRequest,
    wait: Duration,
) -> Result<DropResponse, ApiError> {
    drop_with(state, request, wait, &|| {})
}

/// [`drop_records`], with what a test does once the drop has found what
/// is to go, and before it removes anything.
fn drop_with(
    state: &AppState,
    request: &DropRequest,
    wait: Duration,
    removing: &dyn Fn(),
) -> Result<DropResponse, ApiError> {
    let store = store_of(state)?;
    if request.all == request.of.is_some() {
        return Err(ApiError::BadRequest(
            "say whose records to drop, or all of them".into(),
        ));
    }
    let _turn = turn(state, wait)?;
    if request.all {
        removing();
        let (removed, left) = store.clear().map_err(io("could not be cleared"))?;
        return Ok(DropResponse {
            dropped: Vec::new(),
            removed,
            left,
            unreadable: 0,
        });
    }
    // A record left pending holds a text too: its change could not be
    // finished, or it could not be made final. Whoever holds the turn has
    // no change in hand, so each is marked first, and is then listed with
    // the rest. One that cannot be marked is in no listing: it is still
    // looked at, by what it says of itself, and goes as it is if it was
    // to go. (One that says nothing that can be read is no more this
    // drop's than a record that cannot be read: only `--all` takes those.)
    let stuck = store.recover().map_err(io("cannot be read"))?.left;
    let unreadable = stuck.iter().filter(|s| s.about.is_none()).count();
    let stuck: Vec<(&Id, &About)> = stuck
        .iter()
        .filter_map(|s| s.about.as_ref().map(|about| (&s.id, about)))
        .collect();
    let of = request.of.as_deref().unwrap_or_default();
    let dir = claude_dir(state)?;
    let listing = store.list().map_err(io("cannot be read"))?;
    let asked = |about: &About| {
        asked_for(about, of, request.folder.as_deref(), dir.as_deref())
            && request.file.as_ref().is_none_or(|f| *f == about.file)
    };
    let texts: Vec<&str> = listing
        .records
        .iter()
        .map(|r| &r.about)
        .chain(stuck.iter().map(|(_, about)| *about))
        .filter(|about| asked(about))
        .filter_map(|about| about.kept.as_ref().map(|k| k.sha256.as_str()))
        .collect();
    let same_text = |about: &About| {
        about
            .kept
            .as_ref()
            .is_some_and(|k| texts.contains(&k.sha256.as_str()))
    };
    let to_go = |about: &About| asked(about) || same_text(about);
    let gone: Vec<&Record> = listing.records.iter().filter(|r| to_go(&r.about)).collect();
    let ids: Vec<Id> = gone.iter().map(|r| r.id.clone()).collect();
    removing();
    // Listed as dropped: what this drop removed. A record that had gone by
    // then (something else removed it) is neither dropped nor left.
    let (went, left) = store.remove(&ids);
    let mut removed = went.len();
    let mut dropped: Vec<Line> = gone
        .into_iter()
        .filter(|r| went.contains(&r.id))
        .map(Line::of)
        .collect();
    let mut left = left.len();
    // What was to go and is still pending goes too, as it is. One that
    // cannot be removed either is still on this device, and is counted: a
    // drop that passed it over would say that nothing was left. (One that
    // is no longer there is neither.)
    for (id, about) in stuck.into_iter().filter(|(_, about)| to_go(about)) {
        match store.remove_pending(id) {
            Ok(false) => {}
            Ok(true) => {
                removed += 1;
                dropped.push(Line::of(&Record {
                    id: id.clone(),
                    about: about.clone(),
                    interrupted: true,
                    bytes: 0,
                }));
            }
            Err(_) => left += 1,
        }
    }
    Ok(DropResponse {
        dropped,
        removed,
        left,
        unreadable,
    })
}

// ── Handlers ───────────────────────────────────────────────────────

/// Run `work` off the async runtime: it reads files, and a restore or a
/// drop may wait for its turn.
async fn blocking<T: Serialize + Send + 'static>(
    state: web::Data<AppState>,
    work: impl FnOnce(&AppState) -> Result<T, ApiError> + Send + 'static,
) -> Result<HttpResponse, ApiError> {
    let answer = web::block(move || work(&state))
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))??;
    Ok(HttpResponse::Ok().json(answer))
}

pub async fn list_handler(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ListRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    blocking(state, move |state| list(state, &body)).await
}

pub async fn show_handler(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ShowRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    blocking(state, move |state| show(state, &body)).await
}

pub async fn restore_handler(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<RestoreRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    blocking(state, move |state| restore(state, &body, TURN_WAIT)).await
}

pub async fn drop_handler(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<DropRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    blocking(state, move |state| drop_records(state, &body, TURN_WAIT)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordelia_storage::history::Entry;

    const NO_WAIT: Duration = Duration::from_millis(60);

    /// A node with history on, and an agent's memory folder.
    struct Node {
        state: AppState,
        memory: std::path::PathBuf,
        /// How many times the clock has been read: each reading is a
        /// second on from the last.
        read: std::cell::Cell<i64>,
        _dir: tempfile::TempDir,
    }

    fn node() -> Node {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("node");
        let state = AppState {
            db: std::sync::Mutex::new(cordelia_storage::db::open_in_memory().unwrap()),
            identity: cordelia_crypto::identity::NodeIdentity::generate().unwrap(),
            bearer_token: "t".into(),
            home_dir: home.clone(),
            started_at: std::time::Instant::now(),
            sync_errors: Default::default(),
            peers_hot: Default::default(),
            peers_warm: Default::default(),
            push_tx: None,
            announce_tx: None,
            peers: Default::default(),
            relays: Default::default(),
            outbox_refused: Default::default(),
            relist: Default::default(),
            sync_control: Default::default(),
            usable_keys: Default::default(),
            history: Default::default(),
        };
        state.history.open(Store::new(&home, 30, 1 << 20));
        let memory = dir.path().join("claude/projects/-home-sam-notes/memory");
        std::fs::create_dir_all(&memory).unwrap();
        Node {
            state,
            memory,
            read: Default::default(),
            _dir: dir,
        }
    }

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + seconds, 0).unwrap()
    }

    impl Node {
        fn store(&self) -> Store {
            self.state.history.store().unwrap()
        }

        fn about(&self, file: &str, change: Change, text: Option<&str>) -> About {
            About {
                at: String::new(),
                agent: "lab".into(),
                folder: self.memory.display().to_string(),
                file: file.into(),
                change,
                kept: text.map(|t| kept(Whose::Here { agreed: Some(3) }, t)),
                replaced_by: Replacement::Entry(Entry {
                    device: "cordelia_pk1other".into(),
                    rev: 4,
                }),
                behind: false,
            }
        }

        /// Keep `text` as what `file` held before `change`, as the adapter
        /// does. Returns the record's id.
        fn kept(&self, file: &str, change: Change, text: Option<&str>, when: i64) -> String {
            let store = self.store();
            let about = self.about(file, change, text);
            let pending = store.keep(about, text, at(when)).unwrap();
            store.settle(pending).unwrap().to_string()
        }

        /// The same, for a change that was never finished: the record is
        /// left pending, as when the node stops between the two.
        fn left_pending(&self, file: &str, text: &str, when: i64) -> String {
            let about = self.about(file, Change::Pulled, Some(text));
            let pending = self.store().keep(about, Some(text), at(when)).unwrap();
            let id = pending.id().to_string();
            std::mem::forget(pending);
            id
        }

        fn write(&self, file: &str, text: &str) {
            std::fs::write(self.memory.join(file), text).unwrap();
        }

        fn read(&self, file: &str) -> Option<String> {
            std::fs::read_to_string(self.memory.join(file)).ok()
        }

        /// A clock that is a second on each time it is read, from a time
        /// after every record a test keeps by hand.
        fn clock(&self) -> DateTime<Utc> {
            self.read.set(self.read.get() + 1);
            at(1000 + self.read.get())
        }

        fn restore(&self, ids: &[&str]) -> Vec<Restored> {
            let request = RestoreRequest {
                ids: ids.iter().map(|id| id.to_string()).collect(),
            };
            restore_with(&self.state, &request, &|| self.clock(), NO_WAIT, &|| {})
                .unwrap()
                .results
        }

        /// The ids of every record, newest first.
        fn ids(&self) -> Vec<String> {
            let listing = self.store().list().unwrap();
            listing.records.iter().map(|r| r.id.to_string()).collect()
        }

        fn files(&self) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(&self.memory)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }
    }

    /// A restore writes as the adapter writes. A file that an agent writes
    /// to while the restored text is being flushed is not replaced, and
    /// nothing is recorded as replaced. A link left under the temporary
    /// name is not written through.
    #[test]
    fn test_a_restore_looks_again_before_it_replaces_a_file() {
        let n = node();
        n.write("notes.md", "now\n");
        let before = n.kept("notes.md", Change::Pulled, Some("before\n"), 0);
        let request = RestoreRequest {
            ids: vec![before.clone()],
        };
        let agent_writes = || n.write("notes.md", "written meanwhile\n");
        let done = restore_with(&n.state, &request, &|| at(1000), NO_WAIT, &agent_writes)
            .unwrap()
            .results;
        assert!(!done[0].done, "{done:?}");
        assert!(done[0].message.contains("changed while"), "{done:?}");
        assert_eq!(n.read("notes.md").as_deref(), Some("written meanwhile\n"));
        // Nothing is kept for a change that was not made, and no temporary
        // file is left.
        assert_eq!(n.ids(), std::slice::from_ref(&before));
        assert_eq!(n.files(), ["notes.md"]);

        // A link under the temporary name leads elsewhere.
        let elsewhere = n.memory.with_file_name("elsewhere.md");
        std::fs::write(&elsewhere, "not to be touched\n").unwrap();
        let temporary = cordelia_storage::atomic::temporary_name("notes.md");
        std::os::unix::fs::symlink(&elsewhere, n.memory.join(temporary)).unwrap();
        let done = n.restore(&[&before]);
        assert!(done[0].done, "{done:?}");
        assert_eq!(n.read("notes.md").as_deref(), Some("before\n"));
        let untouched = std::fs::read_to_string(&elsewhere).unwrap();
        assert_eq!(untouched, "not to be touched\n");
        assert_eq!(n.files(), ["notes.md"]);
    }

    /// A restore puts the kept text back in the folder it was kept from,
    /// and keeps what it replaces, so it can be undone by that record's
    /// id. Where the file was absent, undoing it is deleting the file.
    #[test]
    fn test_a_restore_puts_the_text_back_and_can_be_undone() {
        let n = node();
        n.write("notes.md", "now\n");
        let before = n.kept("notes.md", Change::Pulled, Some("before\n"), 0);

        let done = n.restore(&[&before]);
        assert!(done[0].done, "{done:?}");
        assert_eq!(n.read("notes.md").as_deref(), Some("before\n"));
        let undo = done[0].undo.clone().expect("what it replaced is kept");
        let (record, text) = n.store().read(&Id::parse(&undo).unwrap()).unwrap().unwrap();
        assert_eq!(text.as_deref(), Some("now\n"));
        assert_eq!(record.about.change, Change::Restored);
        assert_eq!(
            record.about.replaced_by,
            Replacement::Record(before.clone())
        );
        assert_eq!(record.about.agent, "lab");

        // Undone by that id.
        let undone = n.restore(&[&undo]);
        assert!(undone[0].done);
        assert_eq!(n.read("notes.md").as_deref(), Some("now\n"));
        assert_eq!(n.ids().len(), 3);

        // The text it already holds: nothing to do, and nothing kept.
        let again = n.restore(&[&undo]);
        assert!(again[0].done && again[0].undo.is_none(), "{again:?}");
        assert_eq!(n.ids().len(), 3);

        // A file that is absent comes back, and there is nothing to undo
        // to: the record of it keeps no text, and the answer says that
        // there was no file.
        assert!(!done[0].was_absent && !undone[0].was_absent);
        std::fs::remove_file(n.memory.join("notes.md")).unwrap();
        let back = n.restore(&[&before]);
        assert!(back[0].done && back[0].undo.is_none(), "{back:?}");
        assert!(back[0].was_absent);
        assert_eq!(n.read("notes.md").as_deref(), Some("before\n"));
        // The record it made is the newest: each is as old as its restore.
        let newest = Id::parse(&n.ids()[0]).unwrap();
        let (record, text) = n.store().read(&newest).unwrap().unwrap();
        assert_eq!((record.about.change, text), (Change::Restored, None));
        assert_eq!(n.files(), ["notes.md"], "no temporary file is left");
    }

    /// The record of what a restore replaced is as old as the restore: the
    /// clock is read once the turn has come, and again for each id. A
    /// request can wait for a cycle, which keeps texts of its own; read
    /// when the request was made, the clock would put the restore's
    /// records before those.
    #[test]
    fn test_what_a_restore_keeps_is_as_old_as_the_restore() {
        let n = node();
        n.write("a.md", "a now\n");
        n.write("b.md", "b now\n");
        let a = n.kept("a.md", Change::Pulled, Some("a before\n"), 0);
        let b = n.kept("b.md", Change::Pulled, Some("b before\n"), 1);
        let request = RestoreRequest { ids: vec![a, b] };
        let clock = || {
            // The restore holds the turn by now: nobody else can take it.
            let free = n.state.history.turn_within(Duration::ZERO).is_some();
            assert!(!free, "the clock was read before the turn came");
            n.clock()
        };
        let done = restore_with(&n.state, &request, &clock, NO_WAIT, &|| {}).unwrap();
        let written: Vec<String> = done
            .results
            .iter()
            .map(|r| Id::parse(r.undo.as_deref().expect("what it replaced is kept")).unwrap())
            .map(|id| n.store().read(&id).unwrap().unwrap().0.about.at)
            .collect();
        // One reading for each id, a second apart by this clock.
        let rfc = |when: DateTime<Utc>| when.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        assert_eq!(written, [rfc(at(1001)), rfc(at(1002))]);
    }

    /// A record that no longer holds the text that was kept is not put
    /// back, or shown, as that text.
    #[test]
    fn test_a_damaged_record_is_not_restored_or_shown() {
        let n = node();
        n.write("notes.md", "now\n");
        let before = n.kept("notes.md", Change::Pulled, Some("before, in full\n"), 0);
        let path = n.state.home_dir.join("history").join(&before);
        let whole = std::fs::read(&path).unwrap();
        std::fs::write(&path, &whole[..whole.len() - 6]).unwrap();

        let done = n.restore(&[&before]);
        assert!(!done[0].done, "{done:?}");
        assert!(
            done[0].message.contains("no longer holds the text"),
            "{done:?}"
        );
        assert_eq!(n.read("notes.md").as_deref(), Some("now\n"));
        assert_eq!(n.ids().len(), 1);
        let shown = show(&n.state, &ShowRequest { id: before.clone() });
        assert!(matches!(shown, Err(ApiError::Conflict(_))), "{shown:?}");

        std::fs::write(&path, &whole).unwrap();
        assert!(n.restore(&[&before])[0].done);
    }

    /// A file of any size is kept before it is replaced: one too large to
    /// sync is still text.
    #[test]
    fn test_a_restore_keeps_a_file_too_large_to_sync() {
        let n = node();
        let large = "x".repeat(200_000);
        n.write("notes.md", &large);
        let before = n.kept("notes.md", Change::Pulled, Some("small\n"), 0);
        let done = n.restore(&[&before]);
        let undo = Id::parse(done[0].undo.as_deref().unwrap()).unwrap();
        assert_eq!(n.store().read(&undo).unwrap().unwrap().1, Some(large));
        assert_eq!(n.read("notes.md").as_deref(), Some("small\n"));
    }

    /// What a restore refuses, each leaving everything as it was: an id
    /// that is not one, a record that is not there, a record with no
    /// text, a folder that has gone, a link, and a file that is not text.
    /// Several ids are taken each by itself, in the order given.
    #[test]
    fn test_a_restore_refuses_what_it_cannot_do_safely() {
        let n = node();
        n.write("notes.md", "now\n");
        let good = n.kept("notes.md", Change::Pulled, Some("before\n"), 0);
        let arrived = n.kept("new.md", Change::Arrived, None, 1);
        let linked = n.kept("link.md", Change::Pulled, Some("for the link\n"), 2);
        let binary = n.kept("data.md", Change::Pulled, Some("for the data\n"), 3);
        // A record whose folder has gone.
        let gone = {
            let elsewhere = n.memory.parent().unwrap().join("gone/memory");
            let about = About {
                at: String::new(),
                agent: "old".into(),
                folder: elsewhere.display().to_string(),
                file: "notes.md".into(),
                change: Change::Removed,
                kept: Some(kept(Whose::Here { agreed: None }, "x")),
                replaced_by: Replacement::Nothing,
                behind: false,
            };
            let store = n.store();
            let pending = store.keep(about, Some("x"), at(4)).unwrap();
            store.settle(pending).unwrap().to_string()
        };
        // A record that names a path, where a file's name should be.
        let escaping = {
            let about = About {
                at: String::new(),
                agent: "lab".into(),
                folder: n.memory.display().to_string(),
                file: "../escaped.md".into(),
                change: Change::Removed,
                kept: Some(kept(Whose::Here { agreed: None }, "x")),
                replaced_by: Replacement::Nothing,
                behind: false,
            };
            let store = n.store();
            let pending = store.keep(about, Some("x"), at(5)).unwrap();
            store.settle(pending).unwrap().to_string()
        };
        let target = n.memory.parent().unwrap().join("outside.md");
        std::fs::write(&target, "outside the folder\n").unwrap();
        std::os::unix::fs::symlink(&target, n.memory.join("link.md")).unwrap();
        std::fs::write(n.memory.join("data.md"), [0xff, 0xfe, 0x00]).unwrap();
        let kept_before = n.ids().len();

        let ids = [
            "../../etc/passwd",
            "0000000000000a",
            &arrived,
            &gone,
            &linked,
            &binary,
            &escaping,
            &good,
        ];
        let results = n.restore(&ids);
        let said: Vec<(bool, &str)> = results
            .iter()
            .map(|r| (r.done, r.message.as_str()))
            .collect();
        for ((done, message), expected) in said[..7].iter().zip([
            "is not a record's id",
            "no such record",
            "keeps no text",
            "memory folder is not there",
            "is a link",
            "is not text",
            "not a plain file name",
        ]) {
            assert!(!done && message.contains(expected), "{message}");
        }
        assert!(!n.memory.parent().unwrap().join("escaped.md").exists());
        // The last one was still carried out.
        assert!(results[7].done, "{:?}", results[7]);
        assert_eq!(n.read("notes.md").as_deref(), Some("before\n"));

        // And nothing else changed: no folder made, the link and what it
        // points at untouched, the data file as it was, one record more.
        assert!(!n.memory.parent().unwrap().join("gone").exists());
        assert!(
            std::fs::symlink_metadata(n.memory.join("link.md"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "outside the folder\n"
        );
        assert_eq!(
            std::fs::read(n.memory.join("data.md")).unwrap(),
            [0xff, 0xfe, 0x00]
        );
        assert_eq!(n.ids().len(), kept_before + 1);
    }

    /// No kept copy, no replacement: where what a file holds now cannot be
    /// kept, the restore does not replace it.
    #[test]
    fn test_a_restore_that_cannot_keep_what_it_replaces_does_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let n = node();
        n.write("notes.md", "now\n");
        let before = n.kept("notes.md", Change::Pulled, Some("before\n"), 0);
        let history = n.state.home_dir.join("history");
        let closed = std::fs::Permissions::from_mode(0o500);
        std::fs::set_permissions(&history, closed).unwrap();
        // As root nothing is closed, and there is nothing to show.
        if std::fs::write(history.join("probe"), "").is_ok() {
            return;
        }

        let done = n.restore(&[&before]);
        assert!(!done[0].done, "{done:?}");
        assert!(done[0].message.contains("could not be kept"), "{done:?}");
        assert_eq!(n.read("notes.md").as_deref(), Some("now\n"));

        std::fs::set_permissions(&history, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(n.restore(&[&before])[0].done);
    }

    /// A restore takes its turn with a sync cycle. While a cycle holds
    /// the turn it waits, for a bounded time, then says the node is busy
    /// and does nothing. Nothing is queued. Reading is not held up.
    #[test]
    fn test_a_restore_waits_its_turn_and_then_gives_up() {
        let n = node();
        n.write("notes.md", "now\n");
        let before = n.kept("notes.md", Change::Pulled, Some("before\n"), 0);
        let request = RestoreRequest {
            ids: vec![before.clone()],
        };
        let dropping = DropRequest {
            all: true,
            ..Default::default()
        };

        let cycle = n.state.history.turn();
        let started = std::time::Instant::now();
        let busy = restore(&n.state, &request, NO_WAIT);
        assert!(matches!(busy, Err(ApiError::Conflict(_))), "{busy:?}");
        assert!(matches!(
            drop_records(&n.state, &dropping, NO_WAIT),
            Err(ApiError::Conflict(_))
        ));
        assert!(started.elapsed() >= NO_WAIT);
        assert!(started.elapsed() < Duration::from_secs(5));
        // Listing and showing do not wait.
        assert_eq!(
            list(&n.state, &ListRequest::default())
                .unwrap()
                .agents
                .len(),
            1
        );
        let shown = ShowRequest { id: before.clone() };
        assert!(show(&n.state, &shown).unwrap().text.is_some());
        drop(cycle);

        // Nothing was carried out after it gave up.
        assert_eq!(n.read("notes.md").as_deref(), Some("now\n"));
        assert_eq!(n.ids(), std::slice::from_ref(&before));
        // With the turn free, it goes ahead.
        assert!(restore(&n.state, &request, NO_WAIT).unwrap().results[0].done);
    }

    /// A restore says whether the folder syncs now, from the report of
    /// the node's last whole cycle: it does, it does not, it waits to join
    /// its channel, or it cannot be told. The command tells the person
    /// what will happen to the text in each case.
    #[test]
    fn test_a_restore_says_whether_the_folder_syncs() {
        use serde_json::{Value, json};
        let n = node();
        n.write("notes.md", "now\n");
        let before = n.kept("notes.md", Change::Pulled, Some("before\n"), 0);
        let behind = {
            let mut about = n
                .store()
                .read(&Id::parse(&before).unwrap())
                .unwrap()
                .unwrap()
                .0
                .about;
            about.behind = true;
            about.kept = Some(kept(Whose::Here { agreed: Some(3) }, "older\n"));
            let store = n.store();
            let pending = store.keep(about, Some("older\n"), at(1)).unwrap();
            store.settle(pending).unwrap().to_string()
        };
        // The two texts in turn, so that each restore changes the file.
        let turn = std::cell::Cell::new(false);
        let syncs = || {
            turn.set(!turn.get());
            let id = if turn.get() { &before } else { &behind };
            let done = n.restore(&[id]);
            assert!(done[0].done, "{done:?}");
            done[0].syncs
        };
        let set = |key: &str, value: Option<String>| {
            let db = n.state.db.lock().unwrap();
            match value {
                Some(value) => meta::set(&db, key, &value).unwrap(),
                None => meta::remove(&db, key).unwrap(),
            }
        };
        let project = n.memory.parent().unwrap().display().to_string();
        let generation = n.state.sync_control.generation();
        let report = |generation: u64, folder: Value| {
            let report = json!({ "generation": generation, "folders": [
                { "folder": "/somewhere/else", "channel_id": "grp_other", "error": null },
                folder,
            ]});
            set(meta::SYNC_CLAUDE_REPORT, Some(report.to_string()));
        };
        let listed = |with: Value| {
            let mut folder = json!({ "folder": project, "waiting": false,
                "channel_id": null, "error": null });
            for (key, value) in with.as_object().unwrap() {
                folder[key] = value.clone();
            }
            folder
        };
        let synced = listed(json!({ "channel_id": "grp_this" }));

        // Sync is off: nothing syncs, whatever an old report says.
        report(generation, synced.clone());
        assert_eq!(syncs(), Syncs::No);
        // On, and no cycle has finished since: it cannot be told.
        set(meta::SYNC_CLAUDE_DIR, Some("/home/sam/.claude".into()));
        set(meta::SYNC_CLAUDE_REPORT, None);
        assert_eq!(syncs(), Syncs::Unknown);
        // The last cycle synced it.
        report(generation, synced.clone());
        assert_eq!(syncs(), Syncs::Yes);
        // So it did where a file of it failed: that is reported by itself.
        let a_file = json!({ "channel_id": "grp_this",
            "failed": [{ "name": "other.md", "error": "is not text" }] });
        report(generation, listed(a_file));
        assert_eq!(syncs(), Syncs::Yes);
        // Where the report has something to say of the folder, it may sync
        // in the next cycle or not: it ended part of the way through, or
        // Claude Code keeps its memory elsewhere now.
        let part_way = json!({ "channel_id": "grp_this", "error": "the database is locked" });
        report(generation, listed(part_way));
        assert_eq!(syncs(), Syncs::Unknown);
        // The same where it failed before it began.
        report(
            generation,
            listed(json!({ "error": "the database is locked" })),
        );
        assert_eq!(syncs(), Syncs::Unknown);
        // It waits to join its channel.
        report(generation, listed(json!({ "waiting": true })));
        assert_eq!(syncs(), Syncs::Waits);
        // The cycle did not have it: it is not mapped.
        report(
            generation,
            json!({ "folder": "/another", "channel_id": "grp_this" }),
        );
        assert_eq!(syncs(), Syncs::No);
        // The cycle ended before it reached any folder: it says nothing of
        // this one. (One that reached none and had no failure had none.)
        let reached = |errors: Value| {
            let report = json!({ "generation": generation, "folders": [], "errors": errors });
            set(meta::SYNC_CLAUDE_REPORT, Some(report.to_string()));
        };
        reached(json!(["personal channel: the database is locked"]));
        assert_eq!(syncs(), Syncs::Unknown);
        reached(json!([]));
        assert_eq!(syncs(), Syncs::No);
        // A report from before the settings last changed says nothing of
        // what syncs now.
        report(generation + 1, synced.clone());
        assert_eq!(syncs(), Syncs::Unknown);
        set(meta::SYNC_CLAUDE_REPORT, Some("not a report".into()));
        assert_eq!(syncs(), Syncs::Unknown);

        // Whether the kept text was behind is passed on beside it.
        report(generation, synced);
        let done = n.restore(&[&before, &behind]);
        assert_eq!((done[0].syncs, done[0].behind), (Syncs::Yes, false));
        assert_eq!((done[1].syncs, done[1].behind), (Syncs::Yes, true));

        // A text that fits in no entry stays on this device, though its
        // folder syncs: the largest that fits goes, and one byte more
        // does not. (An entry holds the file's name and the text.)
        let envelope = json!({ "key": "notes.md", "content": "", "metadata": null });
        let room = cordelia_core::protocol::MAX_ITEM_BYTES
            - cordelia_core::protocol::ITEM_SEAL_OVERHEAD_BYTES
            - serde_json::to_vec(&envelope).unwrap().len();
        let fits = n.kept("notes.md", Change::Restored, Some(&"x".repeat(room)), 2);
        let too_large = n.kept("notes.md", Change::Restored, Some(&"x".repeat(room + 1)), 3);
        assert_eq!(n.restore(&[&fits])[0].syncs, Syncs::Yes);
        let done = n.restore(&[&too_large]);
        assert!(done[0].done, "{done:?}");
        assert_eq!(done[0].syncs, Syncs::TooLarge);
    }

    /// Restoring the index replaces it, and says which lines of the index
    /// as it was are not in the restored one.
    #[test]
    fn test_restoring_the_index_says_which_lines_go() {
        let n = node();
        n.write(
            "MEMORY.md",
            "- [Kept](kept.md) in both\n\n- [New](new.md) added since\n",
        );
        let before = n.kept(
            "MEMORY.md",
            Change::Merged,
            Some("- [Kept](kept.md) in both\n- [Old](old.md) only before\n"),
            0,
        );
        let done = n.restore(&[&before]);
        assert_eq!(done[0].lines_gone, ["- [New](new.md) added since"]);
        // Another file's restore lists none.
        n.write("notes.md", "one\ntwo\n");
        let notes = n.kept("notes.md", Change::Pulled, Some("one\n"), 1);
        assert!(n.restore(&[&notes])[0].lines_gone.is_empty());
    }

    /// `drop` removes the records it names and every other record on this
    /// device that holds the same text: a conflict file holds a copy of
    /// the text it was made from.
    #[test]
    fn test_dropping_a_text_drops_it_under_every_name() {
        let n = node();
        let token = n.kept("notes.md", Change::Pulled, Some("a token\n"), 0);
        let older = n.kept("notes.md", Change::Pulled, Some("an older text\n"), 1);
        let copy = n.kept(
            "notes.conflict-0a1b2c3d.md",
            Change::Removed,
            Some("a token\n"),
            2,
        );
        let other = n.kept("other.md", Change::Pulled, Some("something else\n"), 3);
        let nearly = n.kept("other.md", Change::Pulled, Some("a token"), 4);
        let arrived = n.kept("notes.md", Change::Arrived, None, 5);
        // A record of the file whose change was never finished holds a
        // text too. It is not listed until it is marked.
        let unfinished = n.left_pending("notes.md", "a text left pending\n", 6);
        assert!(!n.ids().contains(&unfinished));
        let drop_of = |of: Option<&str>, file: Option<&str>, all: bool| {
            let request = DropRequest {
                of: of.map(String::from),
                file: file.map(String::from),
                all,
                ..Default::default()
            };
            drop_records(&n.state, &request, NO_WAIT)
        };

        // Neither, or both, is refused.
        assert!(matches!(
            drop_of(None, None, false),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(
            drop_of(Some("lab"), None, true),
            Err(ApiError::BadRequest(_))
        ));
        assert_eq!(
            drop_of(Some("someone-else"), None, false).unwrap().removed,
            0
        );

        // One file: its records, and the copy of its text under the other
        // name. A text that differs by a character is another text.
        let dropped = drop_of(Some("lab"), Some("notes.md"), false).unwrap();
        let mut ids: Vec<String> = dropped.dropped.iter().map(|l| l.id.clone()).collect();
        ids.sort();
        let mut expected = vec![token, older, copy, arrived, unfinished];
        expected.sort();
        assert_eq!(ids, expected);
        assert_eq!((dropped.removed, dropped.left), (5, 0));
        assert_eq!(n.ids(), [nearly.clone(), other.clone()]);
        let on_disk = std::fs::read_dir(n.state.home_dir.join("history")).unwrap();
        assert_eq!(on_disk.count(), 2);

        // By the memory folder as well as by name; then everything.
        let folder = n.memory.display().to_string();
        assert_eq!(
            drop_of(Some(&folder), Some("nothing.md"), false)
                .unwrap()
                .removed,
            0
        );
        n.kept("notes.md", Change::Pulled, Some("again\n"), 7);
        // Everything: what cannot be removed is passed over and counted,
        // and the rest goes. (A directory under a record's name, older
        // than every record, cannot be removed as a file.)
        let stuck = n.state.home_dir.join("history").join("00000000000abc");
        std::fs::create_dir(&stuck).unwrap();
        let all = drop_of(None, None, true).unwrap();
        assert_eq!((all.removed, all.left), (3, 1));
        assert!(n.ids().is_empty());
        assert!(stuck.is_dir());
    }

    /// A record left pending that cannot be marked is in no listing. One
    /// that was to go, for what was asked or for the text it holds, goes
    /// all the same, as it is: a drop that passed it over would say that
    /// there were no such records, with the text still on the disk.
    #[test]
    fn test_a_drop_removes_a_pending_record_that_cannot_be_marked() {
        let n = node();
        let asked = n.left_pending("notes.md", "a token\n", 0);
        let copy = n.left_pending("notes.conflict-0a1b2c3d.md", "a token\n", 1);
        let other = n.left_pending("other.md", "something else\n", 2);
        // Something that is not a file has the name each would be marked
        // under, so none can be.
        let history = n.state.home_dir.join("history");
        for id in [&asked, &copy, &other] {
            std::fs::create_dir(history.join(format!("{id}.interrupted"))).unwrap();
        }
        let request = DropRequest {
            of: Some("lab".into()),
            file: Some("notes.md".into()),
            ..Default::default()
        };
        let dropped = drop_records(&n.state, &request, NO_WAIT).unwrap();
        assert_eq!((dropped.removed, dropped.left), (2, 0));
        let mut ids: Vec<String> = dropped.dropped.iter().map(|l| l.id.clone()).collect();
        ids.sort();
        let mut expected = vec![asked.clone(), copy.clone()];
        expected.sort();
        assert_eq!(ids, expected);
        assert!(dropped.dropped.iter().all(|l| l.interrupted));
        for id in [&asked, &copy] {
            assert!(!history.join(format!("{id}.pending")).exists());
        }
        // Another file's, with another text, is not this drop's.
        assert!(history.join(format!("{other}.pending")).is_file());
    }

    /// A record left pending that cannot be marked, and says nothing of
    /// itself that can be read, is not a named drop's: nothing shows whose
    /// it is. It is not counted, and it stays. `--all` takes it.
    #[test]
    fn test_a_pending_record_that_cannot_be_read_goes_only_with_all() {
        let n = node();
        let unread = n.left_pending("notes.md", "a token\n", 0);
        let history = n.state.home_dir.join("history");
        let pending = history.join(format!("{unread}.pending"));
        std::fs::write(&pending, "not a line of JSON\na token\n").unwrap();
        let held = history.join(format!("{unread}.interrupted"));
        std::fs::create_dir(&held).unwrap();
        let request = DropRequest {
            of: Some("lab".into()),
            file: Some("notes.md".into()),
            ..Default::default()
        };
        let dropped = drop_records(&n.state, &request, NO_WAIT).unwrap();
        assert_eq!((dropped.removed, dropped.left), (0, 0));
        assert!(dropped.dropped.is_empty());
        assert!(pending.is_file());
        // The answer says that it is there: it may hold the text.
        assert_eq!(dropped.unreadable, 1);
        // Everything: the record goes. (What holds the name it would be
        // marked under is no file, and is counted as still there.)
        let request = DropRequest {
            all: true,
            ..Default::default()
        };
        let all = drop_records(&n.state, &request, NO_WAIT).unwrap();
        assert_eq!((all.removed, all.left), (1, 1));
        assert_eq!(all.unreadable, 0);
        assert!(!pending.exists());
    }

    /// A record left pending that cannot be marked, and has gone by the
    /// time the drop would remove it, is neither dropped nor still there:
    /// nothing of it is left on this device.
    #[test]
    fn test_a_pending_record_that_has_gone_is_not_counted() {
        let n = node();
        let kept = n.kept("notes.md", Change::Pulled, Some("one\n"), 0);
        let stuck = n.left_pending("notes.md", "two\n", 1);
        let history = n.state.home_dir.join("history");
        std::fs::create_dir(history.join(format!("{stuck}.interrupted"))).unwrap();
        let pending = history.join(format!("{stuck}.pending"));
        let request = DropRequest {
            of: Some("lab".into()),
            ..Default::default()
        };
        // Something else removes it once the drop has found it.
        let removing = || std::fs::remove_file(&pending).unwrap();
        let dropped = drop_with(&n.state, &request, NO_WAIT, &removing).unwrap();
        assert_eq!((dropped.removed, dropped.left), (1, 0));
        let ids: Vec<&str> = dropped.dropped.iter().map(|l| l.id.as_str()).collect();
        assert_eq!(ids, [kept.as_str()]);
    }

    /// The same for a record that stands: one that has gone by the time
    /// the drop would remove it is not listed as dropped, and is not
    /// counted either way.
    #[test]
    fn test_a_record_that_has_gone_is_not_listed_as_dropped() {
        let n = node();
        let first = n.kept("notes.md", Change::Pulled, Some("one\n"), 0);
        let second = n.kept("notes.md", Change::Pulled, Some("two\n"), 1);
        let history = n.state.home_dir.join("history");
        let request = DropRequest {
            of: Some("lab".into()),
            ..Default::default()
        };
        let removing = || std::fs::remove_file(history.join(&first)).unwrap();
        let dropped = drop_with(&n.state, &request, NO_WAIT, &removing).unwrap();
        assert_eq!((dropped.removed, dropped.left), (1, 0));
        let ids: Vec<&str> = dropped.dropped.iter().map(|l| l.id.as_str()).collect();
        assert_eq!(ids, [second.as_str()]);
    }

    /// A pending record that can be neither marked nor removed is counted
    /// as still on this device, for any user: here something that is not
    /// a file has taken its place by the time the drop would remove it.
    #[test]
    fn test_a_pending_record_that_cannot_be_removed_is_counted() {
        let n = node();
        let stuck = n.left_pending("notes.md", "two\n", 1);
        let history = n.state.home_dir.join("history");
        std::fs::create_dir(history.join(format!("{stuck}.interrupted"))).unwrap();
        let pending = history.join(format!("{stuck}.pending"));
        let request = DropRequest {
            of: Some("lab".into()),
            ..Default::default()
        };
        let removing = || {
            std::fs::remove_file(&pending).unwrap();
            std::fs::create_dir(&pending).unwrap();
        };
        let dropped = drop_with(&n.state, &request, NO_WAIT, &removing).unwrap();
        assert_eq!((dropped.removed, dropped.left), (0, 1));
        assert!(dropped.dropped.is_empty());
    }

    /// A drop holds the turn at the moment it comes to remove, whichever
    /// it was asked for, and has let go of it when it returns: no cycle
    /// keeps a text, and no restore and no other drop is at work, then.
    /// (It takes the turn before its look at what is there and holds it
    /// to its end, as a guard that lives as long as the function: a test
    /// of one moment shows that moment.)
    #[test]
    fn test_a_drop_holds_the_turn_while_it_removes() {
        let n = node();
        n.kept("notes.md", Change::Pulled, Some("one\n"), 0);
        n.left_pending("notes.md", "two\n", 1);
        let asked = std::cell::Cell::new(0);
        let removing = || {
            let free = n.state.history.turn_within(Duration::ZERO).is_some();
            assert!(!free, "the drop let go of the turn before it removed");
            asked.set(asked.get() + 1);
        };
        let named = DropRequest {
            of: Some("lab".into()),
            ..Default::default()
        };
        let dropped = drop_with(&n.state, &named, NO_WAIT, &removing).unwrap();
        assert_eq!((dropped.removed, dropped.left), (2, 0));
        n.kept("notes.md", Change::Pulled, Some("three\n"), 2);
        let all = DropRequest {
            all: true,
            ..Default::default()
        };
        let dropped = drop_with(&n.state, &all, NO_WAIT, &removing).unwrap();
        assert_eq!((dropped.removed, dropped.left), (1, 0));
        assert_eq!(asked.get(), 2);
        // And lets go of it when it is done.
        assert!(n.state.history.turn_within(Duration::ZERO).is_some());
    }

    /// A record that cannot be removed is passed over, and the rest that
    /// were asked for go: the answer says how many are still there, and
    /// lists as dropped only those that went.
    #[test]
    fn test_a_drop_goes_on_past_a_record_it_cannot_remove() {
        use std::os::unix::fs::PermissionsExt;
        let n = node();
        let first = n.kept("notes.md", Change::Pulled, Some("one\n"), 0);
        let second = n.kept("notes.md", Change::Pulled, Some("two\n"), 1);
        // And one left pending, which in a directory that is closed can
        // be neither marked nor removed.
        let pending = n.left_pending("notes.md", "three\n", 2);
        let history = n.state.home_dir.join("history");
        let request = DropRequest {
            of: Some("lab".into()),
            ..Default::default()
        };
        std::fs::set_permissions(&history, std::fs::Permissions::from_mode(0o500)).unwrap();
        // As root nothing is closed, and there is nothing to show.
        if std::fs::write(history.join("probe"), "").is_ok() {
            return;
        }
        let dropped = drop_records(&n.state, &request, NO_WAIT).unwrap();
        // None could go, and each was tried.
        assert_eq!((dropped.removed, dropped.left), (0, 3));
        assert!(dropped.dropped.is_empty());
        std::fs::set_permissions(&history, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(n.ids(), [second, first]);
        let dropped = drop_records(&n.state, &request, NO_WAIT).unwrap();
        assert_eq!((dropped.removed, dropped.left), (3, 0));
        assert_eq!(dropped.dropped.len(), 3);
        assert!(dropped.dropped.iter().any(|l| l.id == pending));
    }

    /// What a listing shows: how much is kept and from when, the agents
    /// with records, and one agent's records, newest first, by its name
    /// or by the folder it works in.
    #[test]
    fn test_listing_what_is_kept() {
        let n = node();
        assert!(
            list(&n.state, &ListRequest::default())
                .unwrap()
                .agents
                .is_empty()
        );
        let first = n.kept("notes.md", Change::Pulled, Some("one\n"), 0);
        let second = n.kept("other.md", Change::Removed, Some("two\n"), 60);
        let third = n.kept("notes.md", Change::EditedHere, Some("three\n"), 120);

        let summary = list(&n.state, &ListRequest::default()).unwrap();
        assert!(summary.on);
        assert_eq!((summary.days, summary.max_bytes), (30, 1 << 20));
        assert_eq!(summary.oldest.as_deref(), Some("2027-01-15T08:00:00Z"));
        assert!(summary.bytes > 0 && summary.records.is_empty());
        let agent = &summary.agents[0];
        assert_eq!((agent.agent.as_str(), agent.records), ("lab", 3));
        assert_eq!(agent.oldest, "2027-01-15T08:00:00Z");
        assert_eq!(agent.newest, "2027-01-15T08:02:00Z");

        let asked = |of: &str, folder: Option<&str>, since: Option<&str>| -> Vec<String> {
            let request = ListRequest {
                of: Some(of.into()),
                folder: folder.map(String::from),
                removed: false,
                since: since.map(String::from),
            };
            let listed = list(&n.state, &request).unwrap().records;
            listed.into_iter().map(|l| l.id).collect()
        };
        let of = |of: &str, since: Option<&str>| asked(of, None, since);
        let all = [third.clone(), second.clone(), first.clone()];
        assert_eq!(of("lab", None), all);
        assert!(of("someone-else", None).is_empty());
        // By the folder the agent works in, under the directory in use.
        {
            let db = n.state.db.lock().unwrap();
            let dir = n.memory.ancestors().nth(3).unwrap().display().to_string();
            meta::set(&db, meta::SYNC_CLAUDE_DIR, &dir).unwrap();
        }
        assert_eq!(of("/home/sam/notes", None), all);
        assert!(of("/home/sam/other", None).is_empty());
        // What was typed may be a name and a directory at once. A name
        // stays a name where a directory happens to be called that; and a
        // directory typed in another form is found by its full path.
        assert_eq!(asked("lab", Some("/home/sam/work/lab"), None), all);
        assert_eq!(asked("notes", Some("/home/sam/notes"), None), all);
        assert!(asked("notes", Some("/home/sam/other"), None).is_empty());
        let drop_as = |of: &str, folder: &str| DropRequest {
            of: Some(of.into()),
            folder: Some(folder.into()),
            file: Some("no-such-file.md".into()),
            all: false,
        };
        let dropped = drop_records(&n.state, &drop_as("lab", "/home/sam/work/lab"), NO_WAIT);
        assert_eq!(dropped.unwrap().removed, 0);
        // Since a time.
        assert_eq!(of("lab", Some("2027-01-15T08:01:00Z")), all[..2]);
        assert_eq!(of("lab", Some("2027-01-15T09:01:00+01:00")), all[..2]);
        let not_a_time = ListRequest {
            of: Some("lab".into()),
            since: Some("yesterday".into()),
            ..Default::default()
        };
        assert!(matches!(
            list(&n.state, &not_a_time),
            Err(ApiError::BadRequest(_))
        ));

        // A drop takes the directory as a listing does: the records of the
        // agent that works there go, and no others.
        let other_md = |of: &str, folder: &str| DropRequest {
            file: Some("other.md".into()),
            ..drop_as(of, folder)
        };
        let dropped = drop_records(&n.state, &other_md("notes", "/home/sam/other"), NO_WAIT);
        assert_eq!(dropped.unwrap().removed, 0);
        let dropped = drop_records(&n.state, &other_md("notes", "/home/sam/notes"), NO_WAIT);
        assert_eq!(dropped.unwrap().removed, 1);
        assert_eq!(of("lab", None), [third.clone(), first.clone()]);

        // With history off there is nothing, and it says so.
        n.state.history.open(None);
        assert!(!list(&n.state, &ListRequest::default()).unwrap().on);
        let shown = ShowRequest { id: first };
        assert!(matches!(
            show(&n.state, &shown),
            Err(ApiError::BadRequest(_))
        ));
    }

    /// `--removed` lists the files that were removed and are still absent,
    /// each with the record that brings it back as it was.
    #[test]
    fn test_listing_what_was_removed_and_is_still_absent() {
        let n = node();
        // Removed, and absent: listed, by its newest record.
        n.kept("gone.md", Change::Pulled, Some("an earlier text\n"), 0);
        let gone = n.kept("gone.md", Change::Removed, Some("as it was\n"), 1);
        // Deleted here: listed too.
        let deleted = n.kept("deleted.md", Change::DeletedHere, Some("deleted here\n"), 2);
        // Removed, and there again: not listed.
        n.kept("back.md", Change::Removed, Some("came back\n"), 3);
        n.write("back.md", "came back\n");
        // Absent, but its newest record is not of a removal: not listed.
        n.kept("moved.md", Change::Removed, Some("x\n"), 4);
        n.kept("moved.md", Change::Pulled, Some("y\n"), 5);
        // Present, and only ever replaced: not listed.
        n.write("notes.md", "now\n");
        n.kept("notes.md", Change::Pulled, Some("before\n"), 6);

        let removed = |since: Option<&str>| -> Vec<String> {
            let request = ListRequest {
                of: Some("lab".into()),
                removed: true,
                since: since.map(String::from),
                ..Default::default()
            };
            let listed = list(&n.state, &request).unwrap().records;
            listed.into_iter().map(|l| l.id).collect()
        };
        assert_eq!(removed(None), [deleted.clone(), gone.clone()]);
        assert_eq!(
            removed(Some("2027-01-15T08:00:02Z")),
            std::slice::from_ref(&deleted)
        );

        // Restoring those ids brings the files back, and they are then no
        // longer listed.
        let results = n.restore(&[&deleted, &gone]);
        assert!(results.iter().all(|r| r.done), "{results:?}");
        assert_eq!(n.read("gone.md").as_deref(), Some("as it was\n"));
        assert!(removed(None).is_empty());
    }

    #[test]
    fn test_showing_one_record() {
        let n = node();
        let id = n.kept("notes.md", Change::Pulled, Some("as it was\n"), 0);
        let shown = show(&n.state, &ShowRequest { id: id.clone() }).unwrap();
        assert_eq!(shown.text.as_deref(), Some("as it was\n"));
        assert_eq!(
            (shown.record.id, shown.record.file.as_str()),
            (id, "notes.md")
        );
        assert_eq!(shown.record.text_of, Some(Whose::Here { agreed: Some(3) }));

        let absent = ShowRequest {
            id: "0000000000000a".into(),
        };
        assert!(matches!(
            show(&n.state, &absent),
            Err(ApiError::NotFound(_))
        ));
        let not_an_id = ShowRequest {
            id: "../history/x".into(),
        };
        assert!(matches!(
            show(&n.state, &not_an_id),
            Err(ApiError::BadRequest(_))
        ));
    }
}
