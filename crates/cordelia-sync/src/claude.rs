//! The Claude Code adapter: keeps each Claude Code memory folder in step
//! with a Cordelia channel (decision 2026-09-30-agent-memory-sync §4.5).
//!
//! - The home folder's memory syncs with the personal channel, under keys
//!   `home/<file>`.
//! - A project folder syncs with the project's own channel, found by its
//!   git remote in the personal channel's map (`project/<remote>` ->
//!   channel ID), and created, shared with all of this person's devices,
//!   the first time any device sees the project.
//! - Other folders (no repository, or no portable remote) do not sync and
//!   are reported as such.
//!
//! Each cycle plans every file with [`crate::plan`] and applies the actions.
//! Files are written atomically (temporary file, then rename), never
//! through a symlink, and only under names [`crate::names`] accepts.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;

use cordelia_api::entries::{self, Write};
use cordelia_api::membership;
use cordelia_api::state::AppState;
use cordelia_core::CordeliaError;
use cordelia_storage::{channels, sync_state};

use crate::discover::{self, Project};
use crate::names;
use crate::plan::{self, Action, Agreed, Content, Remote};

/// Seconds between sync cycles.
pub const CYCLE_SECS: u64 = 5;

/// Largest memory file synced. Leaves room under the item size limit for
/// JSON escaping and the envelope; larger files are reported, not synced.
pub const MAX_FILE_BYTES: usize = 128 * 1024;

/// How long a folder's project lookup (transcripts + git) is cached.
const PROJECT_CACHE: Duration = Duration::from_secs(300);

/// A device that joined its personal channel less recently than this does
/// not create project channels yet: the map entries other devices already
/// made may still be arriving, and creating its own would only compete.
const NEW_DEVICE_GRACE: Duration = Duration::from_secs(60);

/// Keys in the personal channel.
const HOME_PREFIX: &str = "home/";
const PROJECT_PREFIX: &str = "project/";

/// Item type of synced memory files.
const ITEM_TYPE: &str = "memory";

/// What one cycle did for one folder.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FolderReport {
    pub folder: String,
    pub project: String,
    pub channel_id: Option<String>,
    /// Waiting to join the project's channel (its invite is in transit).
    pub waiting: bool,
    pub published: usize,
    pub pulled: usize,
    pub conflicts: usize,
    /// Files present but not synced (unsafe name, not text, too large).
    pub skipped: Vec<String>,
}

/// What one cycle did.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CycleReport {
    pub folders: Vec<FolderReport>,
    /// Folders that do not sync: not the home folder, and no git remote.
    pub unsynced: Vec<String>,
    pub errors: Vec<String>,
}

/// The adapter for one Claude Code directory (`~/.claude`).
pub struct ClaudeAdapter {
    claude_dir: PathBuf,
    home: PathBuf,
    /// Tag in conflict file names: the first 8 hex digits of this device's key.
    device_tag: String,
    projects: HashMap<PathBuf, (Instant, Option<Project>)>,
}

impl ClaudeAdapter {
    pub fn new(claude_dir: PathBuf, home: PathBuf, device_key: &[u8; 32]) -> Self {
        Self {
            claude_dir,
            home,
            device_tag: hex::encode(&device_key[..4]),
            projects: HashMap::new(),
        }
    }

    fn project_of(&mut self, folder: &Path) -> Option<Project> {
        if let Some((at, project)) = self.projects.get(folder)
            && at.elapsed() < PROJECT_CACHE
        {
            return project.clone();
        }
        let project =
            discover::recorded_cwd(folder).and_then(|cwd| discover::project_for(&cwd, &self.home));
        self.projects
            .insert(folder.to_path_buf(), (Instant::now(), project.clone()));
        project
    }

    /// Run one sync cycle over every folder.
    pub fn run_cycle(&mut self, state: &AppState) -> CycleReport {
        let mut report = CycleReport::default();
        let personal = match membership::personal_channel_id(state) {
            Ok(id) => id,
            Err(e) => {
                report.errors.push(format!("personal channel: {e}"));
                return report;
            }
        };

        for folder in discover::folders(&self.claude_dir) {
            let label = folder.dir.display().to_string();
            let Some(project) = self.project_of(&folder.dir) else {
                report.unsynced.push(label);
                continue;
            };
            let result = match &project {
                Project::Home => sync_folder(
                    state,
                    &folder.memory_dir,
                    &personal,
                    HOME_PREFIX,
                    &self.device_tag,
                )
                .map(|mut r| {
                    r.channel_id = Some(personal.clone());
                    r
                }),
                Project::Repo(remote) => match project_channel(state, &personal, remote) {
                    Ok(Some(channel)) => {
                        sync_folder(state, &folder.memory_dir, &channel, "", &self.device_tag).map(
                            |mut r| {
                                r.channel_id = Some(channel);
                                r
                            },
                        )
                    }
                    Ok(None) => Ok(FolderReport {
                        waiting: true,
                        ..Default::default()
                    }),
                    Err(e) => Err(e),
                },
            };
            match result {
                Ok(mut r) => {
                    r.folder = label;
                    r.project = match &project {
                        Project::Home => "~".into(),
                        Project::Repo(remote) => remote.clone(),
                    };
                    report.folders.push(r);
                }
                Err(e) => report.errors.push(format!("{label}: {e}")),
            }
        }
        report
    }
}

/// The channel for a project, from the personal channel's map; created and
/// shared with this person's devices if no device has mapped it yet.
/// `None` while this node has not yet joined the mapped channel.
fn project_channel(
    state: &AppState,
    personal: &str,
    remote: &str,
) -> Result<Option<String>, CordeliaError> {
    let key = format!("{PROJECT_PREFIX}{remote}");
    let mapped = {
        let db = lock(state)?;
        entries::current(state, &db, personal)?
            .into_iter()
            .find(|e| e.key == key && !e.current.deleted)
            .and_then(|e| {
                e.current
                    .content
                    .get("channel_id")
                    .and_then(Value::as_str)
                    .map(String::from)
            })
    };

    if let Some(channel) = mapped {
        let pk = state.identity.public_key();
        let db = lock(state)?;
        return Ok(channels::is_member(&db, &channel, &pk)?.then_some(channel));
    }

    if recently_joined(state, personal)? {
        return Ok(None);
    }
    let channel = membership::create_device_group(state, &format!("project:{remote}"))?;
    let db = lock(state)?;
    entries::publish(
        state,
        &db,
        personal,
        &Write {
            key: &key,
            content: &serde_json::json!({ "channel_id": channel }),
            metadata: None,
            item_type: ITEM_TYPE,
            deleted: false,
        },
    )?;
    tracing::info!(%remote, %channel, "mapped project to a new channel");
    Ok(Some(channel))
}

/// Whether this device joined another device's personal channel within
/// [`NEW_DEVICE_GRACE`]. The device that created the channel never waits,
/// and neither does a device alone in its personal channel: in both cases
/// no earlier map can be on its way.
fn recently_joined(state: &AppState, personal: &str) -> Result<bool, CordeliaError> {
    let pk = state.identity.public_key();
    let db = lock(state)?;
    if channels::member_count(&db, personal)? <= 1
        || channels::get_by_id(&db, personal)?.creator_id == pk
    {
        return Ok(false);
    }
    let Some(joined) = channels::member_joined_at(&db, personal, &pk)? else {
        return Ok(true);
    };
    let joined = chrono::DateTime::parse_from_rfc3339(&joined)
        .map_err(|e| CordeliaError::Internal(format!("joined_at: {e}")))?;
    let age = chrono::Utc::now().signed_duration_since(joined);
    Ok(age.to_std().unwrap_or_default() < NEW_DEVICE_GRACE)
}

fn lock(
    state: &AppState,
) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, CordeliaError> {
    state
        .db
        .lock()
        .map_err(|e| CordeliaError::Internal(format!("db lock: {e}")))
}

/// Read the syncable files of a memory folder. Symlinks, hidden files,
/// unsafe names, non-UTF-8, and oversized files are skipped and listed.
fn read_local(dir: &Path) -> (HashMap<String, Content>, Vec<String>) {
    let mut files = HashMap::new();
    let mut skipped = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (files, skipped);
    };
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue; // our temporary files, editor swap files, etc.
        }
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !meta.file_type().is_file() {
            if meta.file_type().is_symlink() {
                skipped.push(name);
            }
            continue;
        }
        if !names::is_safe_file_name(&name) || meta.len() as usize > MAX_FILE_BYTES {
            skipped.push(name);
            continue;
        }
        match std::fs::read(entry.path()).map(String::from_utf8) {
            Ok(Ok(text)) => {
                files.insert(name, Content::new(text));
            }
            _ => skipped.push(name),
        }
    }
    (files, skipped)
}

/// Write `text` to `dir/name` atomically: temporary file, then rename. The
/// rename replaces a symlink at `name` rather than writing through it.
fn write_atomic(dir: &Path, name: &str, text: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".{name}.cordelia-tmp"));
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, dir.join(name))
}

/// A free conflict-file name for `key`, or `None` if a conflict file with
/// exactly this content already exists.
fn conflict_target(dir: &Path, key: &str, tag: &str, text: &str) -> Option<String> {
    let base = names::conflict_name(key, tag);
    for n in 1.. {
        let candidate = if n == 1 {
            base.clone()
        } else {
            names::conflict_name(key, &format!("{tag}-{n}"))
        };
        match std::fs::read_to_string(dir.join(&candidate)) {
            Ok(existing) if existing == text => return None,
            Ok(_) => continue,
            Err(_) => return Some(candidate),
        }
    }
    unreachable!()
}

/// Sync one memory folder with one channel (keys under `prefix`).
fn sync_folder(
    state: &AppState,
    dir: &Path,
    channel: &str,
    prefix: &str,
    tag: &str,
) -> Result<FolderReport, CordeliaError> {
    let folder = dir.display().to_string();
    let mut report = FolderReport::default();
    let (local, skipped) = read_local(dir);
    report.skipped = skipped;

    let (remote, deleted, agreed) = {
        let db = lock(state)?;
        let mut remote: HashMap<String, Remote> = HashMap::new();
        let mut deleted: HashSet<String> = HashSet::new();
        for e in entries::current(state, &db, channel)? {
            let Some(name) = e.key.strip_prefix(prefix) else {
                continue;
            };
            if !names::is_safe_file_name(name) {
                tracing::warn!(key = %e.key, "ignoring entry whose key is not a safe file name");
                continue;
            }
            let content = if e.current.deleted {
                deleted.insert(name.to_string());
                None
            } else {
                match e.current.content.as_str() {
                    Some(text) => Some(Content::new(text)),
                    None => continue, // not a memory file (e.g. a map entry)
                }
            };
            remote.insert(
                name.to_string(),
                Remote {
                    rev: e.current.rev,
                    content,
                },
            );
        }
        let agreed: HashMap<String, Agreed> = sync_state::load(&db, &folder, channel)?
            .into_iter()
            .map(|(k, (hash, rev))| (k, Agreed { hash, rev }))
            .collect();
        (remote, deleted, agreed)
    };

    let mut keys: Vec<&String> = local
        .keys()
        .chain(remote.keys())
        .chain(agreed.keys())
        .collect();
    keys.sort();
    keys.dedup();

    for key in keys {
        let actions = plan::plan(
            key,
            local.get(key),
            remote.get(key),
            agreed.get(key),
            &deleted,
        );
        for action in actions {
            apply(
                state,
                dir,
                channel,
                prefix,
                tag,
                &folder,
                key,
                action,
                &mut report,
            )?;
        }
    }
    Ok(report)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the folder/channel context is passed through unchanged from sync_folder"
)]
fn apply(
    state: &AppState,
    dir: &Path,
    channel: &str,
    prefix: &str,
    tag: &str,
    folder: &str,
    key: &str,
    action: Action,
    report: &mut FolderReport,
) -> Result<(), CordeliaError> {
    let io =
        |e: std::io::Error| CordeliaError::Internal(format!("{}: {e}", dir.join(key).display()));
    let full_key = format!("{prefix}{key}");
    let publish = |text: Option<&str>| -> Result<u64, CordeliaError> {
        let db = lock(state)?;
        let content = text.map_or(Value::Null, |t| Value::String(t.to_string()));
        Ok(entries::publish(
            state,
            &db,
            channel,
            &Write {
                key: &full_key,
                content: &content,
                metadata: None,
                item_type: ITEM_TYPE,
                deleted: text.is_none(),
            },
        )?
        .rev)
    };
    let record = |hash: Option<[u8; 32]>, rev: u64| -> Result<(), CordeliaError> {
        let db = lock(state)?;
        sync_state::save(&db, folder, channel, key, (hash, rev))
    };

    match action {
        Action::Publish(text) => {
            let rev = publish(Some(&text))?;
            record(Some(Content::new(text).hash), rev)?;
            report.published += 1;
        }
        Action::PublishDelete => {
            let rev = publish(None)?;
            record(None, rev)?;
            report.published += 1;
        }
        Action::Pull { text, rev } => {
            write_atomic(dir, key, &text).map_err(io)?;
            record(Some(Content::new(text).hash), rev)?;
            report.pulled += 1;
        }
        Action::RemoveFile { rev } => {
            match std::fs::remove_file(dir.join(key)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(io(e)),
            }
            record(None, rev)?;
            report.pulled += 1;
        }
        Action::SaveConflict(text) => {
            if let Some(name) = conflict_target(dir, key, tag, &text) {
                write_atomic(dir, &name, &text).map_err(io)?;
                tracing::info!(file = %dir.join(&name).display(), "kept this device's version of a conflicting edit");
            }
            report.conflicts += 1;
        }
        Action::Merge(text) => {
            write_atomic(dir, key, &text).map_err(io)?;
            let rev = publish(Some(&text))?;
            record(Some(Content::new(text).hash), rev)?;
            report.published += 1;
        }
        Action::Record(a) => record(a.hash, a.rev)?,
    }
    Ok(())
}
