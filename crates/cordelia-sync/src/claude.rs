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
    /// Conflict files in the folder now, full paths: each holds a version of
    /// a memory that lost to a concurrent edit, until someone merges it
    /// and deletes the file.
    pub conflict_files: Vec<String>,
    /// Files present but not synced (unsafe name, not text, too large).
    pub skipped: Vec<String>,
}

/// What one cycle did.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CycleReport {
    pub folders: Vec<FolderReport>,
    /// Folders that do not sync: not the home folder, and no git remote.
    pub unsynced: Vec<String>,
    /// Folders not synced because this device excludes them (the project's
    /// remote, or "~" for home memory).
    pub excluded: Vec<String>,
    pub errors: Vec<String>,
}

/// Per-device sync settings, kept in node metadata.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    /// Project remotes this device never syncs. A trailing `*` matches a
    /// prefix (`github.com/client-co/*`).
    pub exclude: Vec<String>,
    /// Whether home-folder memory syncs on this device.
    pub home: bool,
}

impl Settings {
    /// Read from node metadata: `sync.claude.exclude` (JSON array) and
    /// `sync.claude.home` (`"off"` disables home memory).
    pub fn load(state: &AppState) -> Result<Self, CordeliaError> {
        let db = lock(state)?;
        let exclude =
            cordelia_storage::meta::get(&db, cordelia_storage::meta::SYNC_CLAUDE_EXCLUDE)?
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();
        let home = cordelia_storage::meta::get(&db, cordelia_storage::meta::SYNC_CLAUDE_HOME)?
            .is_none_or(|v| v != "off");
        Ok(Self { exclude, home })
    }

    /// Whether this device excludes `project`.
    pub fn excludes(&self, project: &Project) -> bool {
        match project {
            Project::Home => !self.home,
            Project::Repo(remote) => self.exclude.iter().any(|pattern| {
                let pattern = pattern.to_lowercase();
                match pattern.strip_suffix('*') {
                    Some(prefix) => remote.starts_with(prefix),
                    None => *remote == pattern,
                }
            }),
        }
    }
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
        let settings = match Settings::load(state) {
            Ok(s) => s,
            Err(e) => {
                report.errors.push(format!("settings: {e}"));
                return report;
            }
        };
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
            if settings.excludes(&project) {
                report.excluded.push(match &project {
                    Project::Home => "~".into(),
                    Project::Repo(remote) => remote.clone(),
                });
                continue;
            }
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

/// The channel for a project, from the personal channel's map, or created
/// (owned by this device alone) if no device has mapped it yet. `None`
/// while this device is not yet a member of the mapped channel: it asks the
/// person's other devices to add it, and waits.
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
        let member = {
            let db = lock(state)?;
            channels::is_member(&db, &channel, &pk)?
        };
        if member {
            return Ok(Some(channel));
        }
        membership::request_join(state, &channel)?;
        return Ok(None);
    }

    if recently_joined(state, personal)? {
        return Ok(None);
    }
    let channel = membership::create_project_group(state, &format!("project:{remote}"))?;
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
        let seen = local.get(key).map(|c| c.hash);
        let actions = plan::plan(
            key,
            local.get(key),
            remote.get(key),
            agreed.get(key),
            &deleted,
        );
        let ctx = Ctx {
            state,
            dir,
            channel,
            prefix,
            tag,
            folder: &folder,
        };
        for action in actions {
            if !apply(&ctx, key, seen, action, &mut report)? {
                break; // the file changed under us; re-plan it next cycle
            }
        }
    }
    report.conflict_files = conflict_files(dir);
    Ok(report)
}

/// The conflict files in `dir` now, sorted, as full paths.
fn conflict_files(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|e| names::is_conflict_name(&e.file_name().to_string_lossy()))
        .map(|e| e.path().display().to_string())
        .collect();
    files.sort();
    files
}

/// The folder and channel an action applies to.
struct Ctx<'a> {
    state: &'a AppState,
    dir: &'a Path,
    channel: &'a str,
    prefix: &'a str,
    tag: &'a str,
    folder: &'a str,
}

/// Hash of the file as it is on disk right now (`None` if absent).
fn current_hash(dir: &Path, key: &str) -> Option<[u8; 32]> {
    std::fs::read(dir.join(key))
        .ok()
        .map(|bytes| cordelia_crypto::sha256(&bytes))
}

/// Apply one action. Returns `false`, doing nothing, if the action would
/// replace or remove the file but the file changed since it was scanned:
/// an agent wrote to it mid-cycle. The next cycle plans with that write, so
/// it is published or kept as a conflict, never overwritten.
fn apply(
    ctx: &Ctx,
    key: &str,
    seen: Option<[u8; 32]>,
    action: Action,
    report: &mut FolderReport,
) -> Result<bool, CordeliaError> {
    let Ctx {
        state,
        dir,
        channel,
        prefix,
        tag,
        folder,
    } = *ctx;
    let replaces_file = matches!(
        action,
        Action::Pull { .. } | Action::RemoveFile { .. } | Action::Merge(_)
    );
    if replaces_file && current_hash(dir, key) != seen {
        tracing::debug!(file = %dir.join(key).display(), "changed during the cycle; deferring");
        return Ok(false);
    }
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
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(dir: &Path) -> AppState {
        AppState {
            db: std::sync::Mutex::new(cordelia_storage::db::open_in_memory().unwrap()),
            identity: cordelia_crypto::identity::NodeIdentity::generate().unwrap(),
            bearer_token: "t".into(),
            home_dir: dir.join("node"),
            started_at: std::time::Instant::now(),
            sync_errors: std::sync::atomic::AtomicU64::new(0),
            peers_hot: std::sync::atomic::AtomicU64::new(0),
            peers_warm: std::sync::atomic::AtomicU64::new(0),
            push_tx: None,
            announce_tx: None,
        }
    }

    /// An agent writing a file after the scan must not be overwritten by an
    /// incoming version planned from the older scan.
    #[test]
    fn a_file_written_mid_cycle_is_never_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let st = state(tmp.path());
        let mem = tmp.path().join("memory");
        std::fs::create_dir_all(&mem).unwrap();
        std::fs::write(mem.join("notes.md"), "scanned\n").unwrap();
        let seen = Some(Content::new("scanned\n").hash);

        // The agent writes after the scan...
        std::fs::write(mem.join("notes.md"), "written mid-cycle\n").unwrap();

        let ctx = Ctx {
            state: &st,
            dir: &mem,
            channel: "grp_x",
            prefix: "",
            tag: "abcd",
            folder: "f",
        };
        let mut report = FolderReport::default();
        for action in [
            Action::Pull {
                text: "incoming\n".into(),
                rev: 2,
            },
            Action::RemoveFile { rev: 2 },
            Action::Merge("merged\n".into()),
        ] {
            assert!(!apply(&ctx, "notes.md", seen, action, &mut report).unwrap());
        }
        // ...and it survives every replacing action.
        assert_eq!(
            std::fs::read_to_string(mem.join("notes.md")).unwrap(),
            "written mid-cycle\n"
        );

        // With an unchanged file, the pull goes ahead.
        let now = Some(Content::new("written mid-cycle\n").hash);
        assert!(
            apply(
                &ctx,
                "notes.md",
                now,
                Action::Pull {
                    text: "incoming\n".into(),
                    rev: 2
                },
                &mut report
            )
            .unwrap()
        );
        assert_eq!(
            std::fs::read_to_string(mem.join("notes.md")).unwrap(),
            "incoming\n"
        );
    }
}
