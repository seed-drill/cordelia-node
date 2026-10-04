//! The Claude Code adapter: keeps Claude Code memory folders in step with
//! Cordelia channels (decision 2026-09-30-agent-memory-sync §4.5).
//!
//! What syncs is declared, not assumed. A *mapping* says that Claude's
//! memory for a folder syncs under a name. The name is shared by all of a
//! person's devices: the personal channel maps it to a channel
//! (`project/<name>` -> channel ID), created by the first device to sync
//! it and joined by each device that maps the same name. Home memory is
//! the mapping of the home directory: under the name `~` unless it is
//! given another, and `~` names nothing else.
//!
//! - With declared mappings only (the default), nothing else syncs. Other
//!   memory found on the machine is reported, with the name each would
//!   get, so it can be mapped.
//! - With `all` on, everything found syncs as well: home, and each git
//!   project under its normalised remote, minus the excluded ones.
//!
//! A mapped folder syncs exactly the Claude Code folder named after it
//! ([`discover::claude_folder`]), never one chosen by reading transcripts:
//! a mapping cannot come to sync a different folder than the one declared.
//! Claude Code keeps one memory per git repository, so the folder to map
//! is the repository's main working tree ([`discover::memory_root`]).
//!
//! Each cycle plans every file with [`crate::plan`] and applies the actions.
//! Files are written atomically (temporary file, then rename), never
//! through a symlink, and only under names [`crate::names`] accepts.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;

use cordelia_api::entries::{self, Write};
use cordelia_api::membership;
use cordelia_api::state::{AppState, Kept};
use cordelia_core::CordeliaError;
use cordelia_storage::{channels, meta, sync_state};

use crate::discover::{self, Project};
use crate::names;
use crate::plan::{self, Action, Agreed, Content, Remote};

/// Seconds between sync cycles.
pub const CYCLE_SECS: u64 = 5;

/// A memory file larger than this cannot fit in an entry, whatever is in
/// it, and is not read: it is reported as too large. A file under it may
/// still not fit, since an entry also holds the file's name and its text
/// is escaped; that is found when it is published, and reported the same
/// way. Either way the file is left alone and nothing is deleted anywhere.
pub const MAX_FILE_BYTES: usize = cordelia_core::protocol::MAX_ITEM_BYTES;

/// How long a folder's project lookup (transcripts + git) is cached.
const PROJECT_CACHE: Duration = Duration::from_secs(300);

/// A device that joined its personal channel less recently than this does
/// not create project channels yet: the map entries other devices already
/// made may still be arriving, and creating its own would only compete.
const NEW_DEVICE_GRACE: Duration = Duration::from_secs(60);

/// The name home memory syncs under unless it is given another.
pub const HOME_NAME: &str = "~";

/// Keys in the personal channel that map a name to its channel.
const PROJECT_PREFIX: &str = "project/";

/// Keys in the personal channel under which each device lists the names it
/// syncs (`syncing/<device key>`), so the others can say what there is to
/// map.
const SYNCING_PREFIX: &str = "syncing/";

/// Item type of synced memory files.
const ITEM_TYPE: &str = "memory";

/// What one cycle did for one folder.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FolderReport {
    /// Claude Code's folder for it (`~/.claude/projects/<slug>`).
    pub folder: String,
    /// The working directory it belongs to, when known.
    pub cwd: Option<String>,
    /// The name it syncs under.
    pub project: String,
    /// Declared with `cordelia sync map`, as opposed to found by `all`.
    pub mapped: bool,
    pub channel_id: Option<String>,
    /// Waiting to join the name's channel (its invite is in transit).
    pub waiting: bool,
    pub published: usize,
    pub pulled: usize,
    pub conflicts: usize,
    /// Conflict files in the folder now, full paths: each holds a version of
    /// a memory that lost to a concurrent edit, until someone merges it
    /// and deletes the file.
    pub conflict_files: Vec<String>,
    /// Files present but not synced: an unsafe name, not text, or a link.
    /// And names that something other than a file has here (a folder),
    /// where the channel has a file of that name.
    pub skipped: Vec<String>,
    /// Files present but not synced because they do not fit in an entry
    /// (64 KB as it travels). They are left as they are on this device, and
    /// the other devices keep the last version that did fit.
    #[serde(default)]
    pub too_large: Vec<String>,
    /// When this device last received a memory under this name, and last
    /// sent one (RFC 3339).
    pub last_pulled_at: Option<String>,
    pub last_published_at: Option<String>,
    /// Why this folder did not sync this cycle, or stopped part-way (the
    /// counts say what it had done by then); or what a person should know
    /// of a folder that did sync (Claude Code keeps its memory elsewhere).
    pub error: Option<String>,
    /// Files that could not be synced this cycle, each with why: the first
    /// [`FAILED_FILES_KEPT`] of them. The other files of the folder were
    /// synced, and these are tried again in the next cycle.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<FailedFile>,
    /// How many more files failed than `failed` lists.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub failed_more: usize,
    /// The settings changed while this folder was being synced, and the
    /// cycle stopped there.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stopped: bool,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// A file that could not be synced in a cycle.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FailedFile {
    /// The file's name in its folder.
    pub name: String,
    pub error: String,
}

/// The most files that failed in one folder that a cycle's errors name one
/// by one. The rest are counted.
const FAILED_FILES_NAMED: usize = 5;

/// The most files that failed that a folder's report lists. The rest are
/// counted: the report is stored after every cycle, and a folder that
/// cannot be written fails for every file there is to write.
const FAILED_FILES_KEPT: usize = 100;

impl FolderReport {
    /// Note that the file `name` could not be synced, and why.
    fn fail(&mut self, name: &str, error: String) {
        if self.failed.len() < FAILED_FILES_KEPT {
            self.failed.push(FailedFile {
                name: name.to_string(),
                error,
            });
        } else {
            self.failed_more += 1;
        }
    }
}

/// The errors a cycle reports for the files of one folder that failed: one
/// for each, with its path, up to [`FAILED_FILES_NAMED`], and one more that
/// counts the rest, those in `failed` and `more` besides.
fn failed_as_errors(memory: &Path, failed: &[FailedFile], more: usize) -> Vec<String> {
    let mut errors: Vec<String> = failed
        .iter()
        .take(FAILED_FILES_NAMED)
        .map(|f| format!("{}: {}", memory.join(&f.name).display(), f.error))
        .collect();
    let more = failed.len().saturating_sub(FAILED_FILES_NAMED) + more;
    if more > 0 {
        errors.push(format!(
            "{}: {more} more {} could not be synced",
            memory.display(),
            if more == 1 { "file" } else { "files" }
        ));
    }
    errors
}

/// When a device last received and last sent a memory under one name.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Activity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pulled: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    published: Option<String>,
}

/// Memory found on this machine that does not sync.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Found {
    /// Claude Code's folder for it.
    pub folder: String,
    /// The directory to map to sync it, when its transcripts say: the
    /// directory it belongs to, or the repository that directory is in.
    pub cwd: Option<String>,
    /// The name it would sync under: `~` for home, the normalised remote
    /// for a git project, nothing for any other folder (it needs a name).
    pub name: Option<String>,
}

/// What one cycle did.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CycleReport {
    pub folders: Vec<FolderReport>,
    /// Folders found on this machine that do not sync: not mapped, or,
    /// with `all` on, neither home nor a git project.
    pub unmapped: Vec<Found>,
    /// The folders in `unmapped` that have no name to sync under (neither
    /// home nor a git project).
    pub unsynced: Vec<String>,
    /// With `all` on: names found but excluded on this device.
    pub excluded: Vec<String>,
    /// Names this person's other devices sync that this device does not,
    /// sorted.
    pub available: Vec<String>,
    pub errors: Vec<String>,
    /// How many times the settings had changed when this cycle read them
    /// (see `SyncControl`). A reader can tell a report made before a
    /// change from one made after it.
    pub generation: u64,
    /// The settings changed during the cycle, and it stopped there: a
    /// command that stops a folder syncing has stopped it when it answers.
    /// The next cycle starts from the new settings.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stopped: bool,
}

/// A declared mapping: Claude's memory for sessions started in `folder`
/// syncs under `name`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Mapping {
    pub folder: String,
    pub name: String,
}

/// Per-device sync settings, kept in node metadata.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    /// Sync every folder found as well as the declared mappings.
    pub all: bool,
    /// With `all`: what this device never syncs. A name, where a trailing
    /// `*` matches a prefix (`github.com/client-co/*`); or a folder (an
    /// absolute path), which is how an unmapped folder stays unsynced.
    pub exclude: Vec<String>,
    /// With `all`: whether home memory syncs on this device.
    pub home: bool,
    pub mappings: Vec<Mapping>,
    /// The Claude Code directory sync is on for; `None` when sync is off.
    pub dir: Option<String>,
    /// How many times the settings had changed when these were read. Both
    /// are read under one hold of the database lock, and a handler counts
    /// its change under that lock, so these are the settings of exactly
    /// this count.
    pub generation: u64,
}

impl Settings {
    /// Read from node metadata: `sync.claude.all`, `.mappings`, `.exclude`,
    /// `.home` and `.dir`, with the count of changes to them.
    pub fn load(state: &AppState) -> Result<Self, CordeliaError> {
        let db = lock(state)?;
        let json = |key: &str| -> Result<Option<String>, CordeliaError> { meta::get(&db, key) };
        Ok(Self {
            all: json(meta::SYNC_CLAUDE_ALL)?.is_some_and(|v| v == "on"),
            exclude: json(meta::SYNC_CLAUDE_EXCLUDE)?
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default(),
            home: json(meta::SYNC_CLAUDE_HOME)?.is_none_or(|v| v != "off"),
            mappings: json(meta::SYNC_CLAUDE_MAPPINGS)?
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default(),
            dir: json(meta::SYNC_CLAUDE_DIR)?,
            generation: state.sync_control.generation_under(&db),
        })
    }

    /// With `all` on: whether this device leaves `project` out by name.
    pub fn excludes(&self, project: &Project) -> bool {
        match project {
            Project::Home => !self.home,
            Project::Repo(remote) => self
                .exclude
                .iter()
                .filter(|entry| !entry.starts_with('/'))
                .any(|pattern| {
                    // In the spelling a project is found under. The node
                    // stores it so; an earlier version could store one
                    // that ended in `.git`.
                    let pattern = cordelia_core::sync_name::tidy(pattern);
                    match pattern.strip_suffix('*') {
                        Some(prefix) => remote.starts_with(prefix),
                        None => *remote == pattern,
                    }
                }),
        }
    }

    /// With `all` on: whether the folder `dir` was taken out of the sync on
    /// this device (it was unmapped), whatever name it would sync under.
    pub fn declines(&self, dir: &Path) -> bool {
        self.exclude
            .iter()
            .any(|entry| entry.starts_with('/') && Path::new(entry) == dir)
    }
}

/// The name a found project would sync under.
fn name_of(project: &Project) -> String {
    match project {
        Project::Home => HOME_NAME.to_string(),
        Project::Repo(remote) => remote.clone(),
    }
}

/// One folder to sync this cycle.
struct Target {
    /// Claude Code's folder.
    dir: PathBuf,
    cwd: Option<String>,
    name: String,
    mapped: bool,
}

/// What a Claude Code folder's transcripts say about it.
#[derive(Clone)]
enum Seen {
    /// Claude Code's own folder, named after the directory its sessions
    /// started in. Their memory is kept in `dir`, the folder of `root`:
    /// this folder, or the folder of the repository the directory is in.
    Own {
        dir: PathBuf,
        root: PathBuf,
        project: Option<Project>,
    },
    /// Claude Code's own folder, for a directory in a repository whose
    /// folder name cannot be predicted: nothing to sync from here.
    OwnElsewhere,
    /// Not named after the directory its transcripts record: someone laid
    /// it out by hand, and it is its own memory folder.
    ByHand {
        cwd: PathBuf,
        project: Option<Project>,
    },
}

/// Memory found on disk that no mapping claims.
struct Candidate {
    /// Claude Code's folder holding the memory, or due to.
    dir: PathBuf,
    /// The directory to map to sync it.
    cwd: Option<PathBuf>,
    project: Option<Project>,
}

/// The adapter for one Claude Code directory (`~/.claude`).
pub struct ClaudeAdapter {
    claude_dir: PathBuf,
    home: PathBuf,
    /// Tag in conflict file names: the first 8 hex digits of this device's key.
    device_tag: String,
    /// Per Claude folder: when its transcripts were read, and what they say.
    seen: HashMap<PathBuf, (Instant, Option<Seen>)>,
    /// Per mapped directory: when it was checked, and where Claude Code
    /// keeps its memory now if that is no longer the directory itself.
    moved: HashMap<String, (Instant, Option<PathBuf>)>,
}

impl ClaudeAdapter {
    pub fn new(claude_dir: PathBuf, home: PathBuf, device_key: &[u8; 32]) -> Self {
        Self {
            claude_dir,
            // Claude Code names folders after real paths, so compare with one.
            home: home.canonicalize().unwrap_or(home),
            device_tag: hex::encode(&device_key[..4]),
            seen: HashMap::new(),
            moved: HashMap::new(),
        }
    }

    /// Whether this adapter is for the Claude Code directory `dir`, which
    /// is the text that is stored as the setting, not the path it spells.
    /// What a folder agrees is recorded under that text, and the handlers
    /// forget by it. So an adapter made for another spelling of the same
    /// path is not for it: the node's loop makes a new one, and a cycle
    /// of the old one does nothing.
    pub fn is_for(&self, dir: &str) -> bool {
        self.claude_dir.as_os_str() == std::ffi::OsStr::new(dir)
    }

    /// The project a directory belongs to, if it has a name to sync under.
    /// A remote that does not make a usable name is left for the person to
    /// name.
    fn project(&self, dir: &Path) -> Option<Project> {
        discover::project_for(dir, &self.home).filter(|project| match project {
            Project::Home => true,
            Project::Repo(remote) => cordelia_api::sync::valid_sync_name(remote),
        })
    }

    /// Where Claude Code keeps the memory of a mapped directory now, if
    /// that is no longer the directory itself: a git repository has
    /// appeared above it since it was mapped. Cached like `seen`.
    fn moved_to(&mut self, mapped: &str) -> Option<PathBuf> {
        if let Some((at, moved)) = self.moved.get(mapped)
            && at.elapsed() < PROJECT_CACHE
        {
            return moved.clone();
        }
        let root = discover::memory_root(Path::new(mapped));
        let moved = (root != Path::new(mapped)).then_some(root);
        self.moved
            .insert(mapped.to_string(), (Instant::now(), moved.clone()));
        moved
    }

    /// What a Claude folder's transcripts say about it, cached: reading
    /// them and asking git is too slow to repeat every cycle.
    fn seen(&mut self, folder: &Path) -> Option<Seen> {
        if let Some((at, seen)) = self.seen.get(folder)
            && at.elapsed() < PROJECT_CACHE
        {
            return seen.clone();
        }
        // Claude Code names its folders after an absolute path, so they
        // start with a dash. Such a folder is believed only about the
        // directory it is named after: a session can move elsewhere, and a
        // transcript that starts in another directory must not turn this
        // folder into that directory's memory.
        let cwds = discover::recorded_cwds(folder);
        let named_by_claude = folder
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with('-'));
        let own = cwds
            .iter()
            .find(|cwd| discover::is_claude_folder_for(folder, cwd));
        let seen = match own {
            Some(cwd) => {
                let root = discover::memory_root(cwd);
                let dir = if root == *cwd {
                    Some(folder.to_path_buf())
                } else {
                    discover::claude_folder(&self.claude_dir, &root)
                };
                Some(match dir {
                    Some(dir) => Seen::Own {
                        project: self.project(&root),
                        dir,
                        root,
                    },
                    None => Seen::OwnElsewhere,
                })
            }
            None if named_by_claude => None,
            None => cwds.into_iter().next().map(|cwd| Seen::ByHand {
                project: self.project(&cwd),
                cwd,
            }),
        };
        self.seen
            .insert(folder.to_path_buf(), (Instant::now(), seen.clone()));
        seen
    }

    /// Memory on disk that no mapping claims: each Claude folder that holds
    /// memory, or belongs to a project and so may be sent some.
    fn candidates(&mut self, claimed: &HashSet<PathBuf>) -> Vec<Candidate> {
        let mut found: Vec<Candidate> = Vec::new();
        for folder in discover::folders(&self.claude_dir) {
            let holds_memory = folder.memory_dir.is_dir();
            let candidate = match self.seen(&folder.dir) {
                Some(Seen::Own { dir, root, project }) => Candidate {
                    dir,
                    cwd: Some(root),
                    project,
                },
                Some(Seen::ByHand { cwd, project }) if holds_memory => Candidate {
                    dir: folder.dir,
                    cwd: Some(cwd),
                    project,
                },
                // No transcripts: all that is known is that it holds memory.
                None if holds_memory => Candidate {
                    dir: folder.dir,
                    cwd: None,
                    project: None,
                },
                _ => continue,
            };
            // Nothing to send and no project to receive from: not worth a line.
            if candidate.project.is_none() && !candidate.dir.join("memory").is_dir() {
                continue;
            }
            if claimed.contains(&candidate.dir) {
                continue;
            }
            match found.iter_mut().find(|c| c.dir == candidate.dir) {
                // Several folders of one repository: one memory, listed once.
                Some(existing) if existing.cwd.is_none() => *existing = candidate,
                Some(_) => {}
                None => found.push(candidate),
            }
        }
        found.sort_by(|a, b| a.dir.cmp(&b.dir));
        found
    }

    /// Run one sync cycle: the declared mappings, and with `all` on,
    /// everything else found.
    pub fn run_cycle(&mut self, state: &AppState) -> CycleReport {
        match Settings::load(state) {
            Ok(settings) => self.run_cycle_under(state, settings),
            Err(e) => CycleReport {
                generation: state.sync_control.generation(),
                errors: vec![format!("settings: {e}")],
                ..Default::default()
            },
        }
    }

    /// Run one sync cycle under `settings`, as they were read. If they have
    /// been changed since, by the time the cycle gets to a folder or to an
    /// entry, it stops there (see [`CycleReport::stopped`]).
    pub fn run_cycle_under(&mut self, state: &AppState, settings: Settings) -> CycleReport {
        let generation = settings.generation;
        let mut report = CycleReport {
            generation,
            ..Default::default()
        };
        // Whether sync is on, and for which directory, is a setting like
        // the others. It was looked at before these were read, and may
        // have been turned off or changed since: then there is nothing to
        // do.
        if !settings.dir.as_deref().is_some_and(|dir| self.is_for(dir)) {
            report.stopped = true;
            return report;
        }
        let personal = match membership::personal_channel_id(state) {
            Ok(id) => id,
            Err(e) => {
                report.errors.push(format!("personal channel: {e}"));
                return report;
            }
        };

        // What to sync: declared mappings first.
        let mut targets: Vec<Target> = Vec::new();
        let mut claimed: HashSet<PathBuf> = HashSet::new();
        for mapping in &settings.mappings {
            let Some(dir) = discover::claude_folder(&self.claude_dir, Path::new(&mapping.folder))
            else {
                let error = "the path is too long to tell which folder Claude Code uses for it";
                report.errors.push(format!("{}: {error}", mapping.folder));
                report.folders.push(FolderReport {
                    cwd: Some(mapping.folder.clone()),
                    project: mapping.name.clone(),
                    mapped: true,
                    error: Some(error.to_string()),
                    ..Default::default()
                });
                continue;
            };
            claimed.insert(dir.clone());
            targets.push(Target {
                dir,
                cwd: Some(mapping.folder.clone()),
                name: mapping.name.clone(),
                mapped: true,
            });
        }

        // Then everything else on disk: synced with `all`, reported without.
        // A folder that was unmapped stays out either way, under any name.
        for candidate in self.candidates(&claimed) {
            let label = candidate.dir.display().to_string();
            let declined = candidate
                .cwd
                .as_deref()
                .is_some_and(|dir| settings.declines(dir));
            let cwd = candidate.cwd.map(|c| c.display().to_string());
            match candidate.project {
                Some(project) if settings.all && !declined && settings.excludes(&project) => {
                    report.excluded.push(name_of(&project));
                }
                Some(project) if settings.all && !declined => targets.push(Target {
                    dir: candidate.dir,
                    cwd,
                    name: name_of(&project),
                    mapped: false,
                }),
                project => {
                    if project.is_none() {
                        report.unsynced.push(label.clone());
                    }
                    report.unmapped.push(Found {
                        folder: label,
                        cwd,
                        name: project.as_ref().map(name_of),
                    });
                }
            }
        }

        // The names this device means to sync, and those it has a channel
        // for: only the second kind is something to tell other devices.
        let mut wanted: BTreeSet<String> = BTreeSet::new();
        let mut joined: BTreeSet<String> = BTreeSet::new();
        // The (memory folder, channel) pairs that sync now. What any other
        // pair agreed is forgotten below, unless a channel could not be
        // looked up this cycle.
        let mut syncing: Vec<(String, String)> = Vec::new();
        let mut looked_up_all = true;
        let stored = load_activity(state);
        let mut activity: HashMap<String, Activity> = HashMap::new();
        for target in targets {
            // A setting changed: this folder may be one it stopped.
            if state.sync_control.generation() != generation {
                report.stopped = true;
                break;
            }
            let label = target.dir.display().to_string();
            let memory = target.dir.join("memory");
            wanted.insert(target.name.clone());
            let result = match project_channel(state, &personal, &target.name) {
                Ok(Some(channel)) => {
                    joined.insert(target.name.clone());
                    syncing.push((memory.display().to_string(), channel.clone()));
                    sync_folder(state, &memory, &channel, "", &self.device_tag, generation).map(
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
                Err(e) => {
                    looked_up_all = false;
                    Err(e)
                }
            };
            // A folder that failed is still listed, with why.
            let mut r = result.unwrap_or_else(|e| FolderReport {
                error: Some(e.to_string()),
                ..Default::default()
            });
            // So is one that failed part of the way through its files,
            // with what it had done by then. Either is an error of the
            // cycle.
            if let Some(e) = &r.error {
                report.errors.push(format!("{label}: {e}"));
            }
            // A file that failed is an error of the cycle, by name.
            report
                .errors
                .extend(failed_as_errors(&memory, &r.failed, r.failed_more));
            // A repository created above a mapped folder moves its memory.
            if target.mapped
                && r.error.is_none()
                && let Some(mapped) = target.cwd.as_deref()
                && let Some(root) = self.moved_to(mapped)
            {
                let moved = format!(
                    "Claude Code now keeps this folder's memory with {}, a git repository \
                     that contains it: unmap it, and map that instead",
                    root.display()
                );
                report.errors.push(format!("{mapped}: {moved}"));
                r.error = Some(moved);
            }
            let seen = activity
                .entry(target.name.clone())
                .or_insert_with(|| stored.get(&target.name).cloned().unwrap_or_default());
            let now = chrono::Utc::now().to_rfc3339();
            if r.pulled > 0 {
                seen.pulled = Some(now.clone());
            }
            if r.published > 0 {
                seen.published = Some(now);
            }
            r.last_pulled_at = seen.pulled.clone();
            r.last_published_at = seen.published.clone();
            r.folder = label;
            r.cwd = target.cwd;
            r.project = target.name;
            r.mapped = target.mapped;
            let stopped = r.stopped;
            report.folders.push(r);
            if stopped {
                report.stopped = true;
                break;
            }
        }
        // A cycle that stopped did not reach every folder, and one whose
        // settings changed as it finished worked from settings that no
        // longer stand. Either way what it has is not what syncs now, so
        // nothing is concluded from it. A folder that a command stopped
        // has already forgotten what it had agreed: the handler that
        // stopped it saw to that.
        if state.sync_control.generation() != generation {
            report.stopped = true;
        }
        if report.stopped {
            return report;
        }
        // Kept for the names that sync now; written only when it changes.
        if activity != stored
            && let Err(e) = store_activity(state, &activity)
        {
            report.errors.push(format!("activity: {e}"));
        }
        // A folder that no longer syncs starts afresh if it syncs again:
        // what it lost in between is not taken for deletes.
        if looked_up_all && let Err(e) = forget_other_folders(state, &syncing, generation) {
            report.errors.push(format!("agreements: {e}"));
        }

        match exchange_names(state, &personal, &joined, &wanted, generation) {
            Ok(available) => report.available = available,
            Err(e) => report.errors.push(format!("names: {e}")),
        }
        report
    }
}

/// Forget what every folder agreed with its channel, except those in
/// `syncing` (memory folder, channel), which is what syncs under the
/// settings of `generation`. Nothing is forgotten if the settings have
/// changed since: a folder they now sync may not be in `syncing`.
fn forget_other_folders(
    state: &AppState,
    syncing: &[(String, String)],
    generation: u64,
) -> Result<(), CordeliaError> {
    let db = lock(state)?;
    if state.sync_control.generation_under(&db) != generation {
        return Ok(());
    }
    let forgotten = sync_state::forget_except(&db, syncing)?;
    state.sync_control.forget_kept_except(syncing);
    if forgotten > 0 {
        tracing::info!(
            files = forgotten,
            "sync: forgot what folders that no longer sync had agreed"
        );
    }
    Ok(())
}

/// When this device last received and sent a memory under each name.
fn load_activity(state: &AppState) -> HashMap<String, Activity> {
    lock(state)
        .ok()
        .and_then(|db| meta::get(&db, meta::SYNC_CLAUDE_ACTIVITY).ok().flatten())
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

fn store_activity(
    state: &AppState,
    activity: &HashMap<String, Activity>,
) -> Result<(), CordeliaError> {
    let json =
        serde_json::to_string(activity).map_err(|e| CordeliaError::Internal(e.to_string()))?;
    meta::set(&*lock(state)?, meta::SYNC_CLAUDE_ACTIVITY, &json)
}

/// Sync was turned off: tell this person's other devices that this one
/// no longer syncs anything. (What its folders had agreed was forgotten by
/// the handler that turned sync off.)
///
/// `generation` is the settings count read with the setting that says sync
/// is off. Returns `false` if the settings have changed since: sync may be
/// on again, the list may not have been published, and whoever asked
/// looks again. Looking again when it had been published does no harm.
pub fn withdraw(state: &AppState, generation: u64) -> Result<bool, CordeliaError> {
    let personal = membership::personal_channel_id(state)?;
    let none = BTreeSet::new();
    exchange_names(state, &personal, &none, &none, generation)?;
    Ok(state.sync_control.generation() == generation)
}

/// Publish the names this device syncs (`mine`), if they changed, and
/// return the names this person's other devices sync that this one neither
/// syncs nor is waiting to (`wanted`). Each device speaks only for itself:
/// a list is read only from the device its key names, and only the names
/// in it that could be mapped. (Another member writing a later revision
/// under a device's key can therefore hide that device's list until it
/// next publishes, but cannot add to it.) Nothing is published if the
/// settings are no longer those of `generation`: the names were worked out
/// from settings that have since been replaced.
fn exchange_names(
    state: &AppState,
    personal: &str,
    mine: &BTreeSet<String>,
    wanted: &BTreeSet<String>,
    generation: u64,
) -> Result<Vec<String>, CordeliaError> {
    let crypto = |e: cordelia_crypto::CryptoError| CordeliaError::Crypto(e.to_string());
    let me = state.identity.public_key();
    let my_key = format!(
        "{SYNCING_PREFIX}{}",
        cordelia_crypto::bech32::encode_public_key(&me).map_err(crypto)?
    );

    let db = lock(state)?;
    let mut published: BTreeSet<String> = BTreeSet::new();
    let mut others: BTreeSet<String> = BTreeSet::new();
    for entry in entries::current(state, &db, personal)? {
        let Some(device) = entry.key.strip_prefix(SYNCING_PREFIX) else {
            continue;
        };
        let author = cordelia_crypto::bech32::encode_public_key(&entry.current.author);
        if entry.current.deleted || author.ok().as_deref() != Some(device) {
            continue;
        }
        let names = entry.current.content["names"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|n| n.as_str().map(String::from));
        if entry.current.author == me {
            published.extend(names);
        } else {
            // Shown to the person, and inside a command to copy.
            others.extend(names.filter(|n| cordelia_api::sync::valid_sync_name(n)));
        }
    }
    if published != *mine && state.sync_control.generation_under(&db) == generation {
        entries::publish(
            state,
            &db,
            personal,
            &Write {
                key: &my_key,
                content: &serde_json::json!({ "names": mine }),
                metadata: None,
                item_type: ITEM_TYPE,
                deleted: false,
            },
        )?;
    }
    Ok(others.difference(wanted).cloned().collect())
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

/// The files of a memory folder: those that can sync, and those that are
/// there but cannot.
#[derive(Default)]
struct Local {
    files: HashMap<String, Content>,
    /// An unsafe name, not UTF-8 text, or a link.
    skipped: Vec<String>,
    /// Too large to fit in an entry.
    too_large: Vec<String>,
    /// Neither a file nor a link (a folder, say). Something is there, so
    /// the name is not synced and is not taken for deleted. It is listed
    /// only where the channel has a file of that name.
    not_files: Vec<String>,
    /// The folder was not there when it was listed.
    missing: bool,
}

/// Read the syncable files of a memory folder. Symlinks, unsafe names,
/// non-UTF-8 and oversized files are left out and listed; hidden files are
/// ignored; what is neither a file nor a link is left out and remembered.
/// A folder that does not exist has no files; one that cannot be read is
/// an error, never an empty folder. Nor is a name whose kind cannot be
/// told (the folder can be listed and not looked into) a file that has
/// gone: that is an error too, or every file in it would be taken for
/// deleted.
fn read_local(dir: &Path) -> std::io::Result<Local> {
    let mut local = Local::default();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            local.missing = true;
            return Ok(local);
        }
        Err(e) => return Err(e),
    };
    let Local {
        files,
        skipped,
        too_large,
        not_files,
        missing: _,
    } = &mut local;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue; // our temporary files, editor swap files, etc.
        }
        let meta = match std::fs::symlink_metadata(entry.path()) {
            Ok(meta) => meta,
            // Gone since the folder was listed. (It may be the folder
            // that has gone, and everything in it with it: the cycle
            // looks at the folder again once it is listed, and lists it
            // again before it publishes a delete.)
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(std::io::Error::new(e.kind(), format!("{name}: {e}"))),
        };
        if !meta.file_type().is_file() {
            if meta.file_type().is_symlink() {
                skipped.push(name);
            } else {
                not_files.push(name);
            }
            continue;
        }
        // A file whose name is not text cannot be an entry's, and could
        // not be found again under the text made of it.
        if entry.file_name().to_str().is_none() {
            skipped.push(name);
            continue;
        }
        if !names::is_safe_file_name(&name) {
            skipped.push(name);
            continue;
        }
        if meta.len() as usize > MAX_FILE_BYTES {
            too_large.push(name);
            continue;
        }
        match std::fs::read(entry.path()).map(String::from_utf8) {
            Ok(Ok(text)) => {
                files.insert(name, Content::new(text));
            }
            _ => skipped.push(name),
        }
    }
    Ok(local)
}

/// Write `text` to `dir/name` atomically: temporary file, then rename. The
/// rename replaces a symlink at `name` rather than writing through it.
/// Returns `false`, with nothing written under `name`, if `unchanged` says
/// that what is there is no longer what the cycle saw.
///
/// The text is flushed to the disk before the file gets its name. A copy
/// of this device's version is written just before the file is replaced:
/// if the power went between the two, the copy must not be the one that
/// is empty. A flush takes long enough for an agent to write to the file
/// meanwhile, so `unchanged` is asked after it, as the last thing before
/// the rename. The name is flushed after the rename, as far as the volume
/// can: the record of a write is on the disk as soon as it is made, and a
/// name that was not would leave the old text under a record of the new.
///
/// `flushed` is run between the flush and that last look. A cycle does
/// nothing there. A test does what an agent may do while a text is
/// flushed.
///
/// The folder is never made here. A cycle makes it once, before any file,
/// where it was not there when it was listed and a file is to arrive
/// ([`sync_folder_with`]). A folder that is not there for a write has
/// gone since: made again by the write, it would hold only what is written
/// from then on, and the next cycle would read that as every other file
/// deleted.
fn write_atomic(
    dir: &Path,
    name: &str,
    text: &str,
    flushed: &dyn Fn(),
    unchanged: &dyn Fn() -> bool,
) -> std::io::Result<bool> {
    let tmp = dir.join(temporary_name(name));
    // Made anew each time, so that it is never written through a link
    // that something has left under its name.
    let _ = std::fs::remove_file(&tmp);
    let mut made = std::fs::OpenOptions::new();
    made.write(true).create_new(true);
    let written = made
        .open(&tmp)
        .and_then(|mut file| {
            std::io::Write::write_all(&mut file, text.as_bytes())?;
            flush(&file)
        })
        .and_then(|()| {
            flushed();
            match unchanged() {
                true => std::fs::rename(&tmp, dir.join(name)).map(|()| true),
                false => Ok(false),
            }
        });
    match written {
        Ok(true) => flush_names(dir),
        // Not left behind where it could not be written whole, or did not
        // take the file's place.
        _ => {
            let _ = std::fs::remove_file(&tmp);
        }
    }
    written
}

/// Flush the names in a folder to the disk. The file is already in place,
/// so where this cannot be done there is nothing more to do.
fn flush_names(dir: &Path) {
    if let Err(error) = std::fs::File::open(dir).and_then(|dir| dir.sync_all()) {
        tracing::debug!(folder = %dir.display(), %error, "could not flush a folder's names");
    }
}

/// Flush a file's contents to the disk. A volume that has no flush (some
/// network volumes and some removable ones) is written as it was before a
/// flush was asked for.
fn flush(file: &std::fs::File) -> std::io::Result<()> {
    match file.sync_all() {
        Err(e) if has_no_flush(&e) => Ok(()),
        done => done,
    }
}

/// Whether a flush failed because the volume has none, as against a flush
/// that was tried and failed (a full disk, a fault of the disk).
fn has_no_flush(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{InvalidInput, Unsupported};
    // On a Mac a flush is a request of its own, which a volume without it
    // answers with one of two codes that have no kind of their own there:
    // ENOTSUP (45) and ENOTTY (25).
    let on_a_mac = cfg!(target_vendor = "apple") && matches!(e.raw_os_error(), Some(45 | 25));
    on_a_mac || matches!(e.kind(), InvalidInput | Unsupported)
}

/// The name of the temporary file that `name` is written through: hidden,
/// so that it is never read as a memory file, and short whatever the
/// length of `name`. A name may be as long as a file name can be, and a
/// temporary name made by adding to it would then be too long to create.
fn temporary_name(name: &str) -> String {
    let hash = cordelia_crypto::sha256(name.as_bytes());
    format!(".cordelia-tmp-{}", hex::encode(&hash[..8]))
}

/// Where the text of a file in conflict is kept: see [`conflict_file`].
#[derive(Debug, PartialEq, Eq)]
enum ConflictFile {
    /// It is kept already: this conflict file holds exactly the text, and
    /// is the copy made for this conflict.
    Kept(String),
    /// It is to be written under this name, which is free and has been
    /// taken for it.
    ToWrite(String),
    /// The settings have changed: nothing is to be written.
    Stopped,
}

/// What became of a conflict-file name that was asked for: see [`claim`].
#[derive(Debug, PartialEq, Eq)]
enum Claim {
    /// It is taken for this text, and written down.
    Taken,
    /// It is in use otherwise: the next name is tried.
    InUse,
    /// The settings have changed.
    Stopped,
}

/// The conflict file for the text of `key`: one that holds exactly this
/// text and that `the_copy` says is the copy made for this conflict (see
/// [`is_the_copy`]), or else the first name that is free and that `claim`
/// takes (see [`claim`]). A conflict file with this text that is from
/// before this conflict is not taken for the copy, and the text is kept
/// again.
///
/// The names after the first free one are not looked at. So where an
/// earlier copy has been deleted and the copy of this conflict has a later
/// name, the text is kept once more, under the name that came free.
///
/// A file that cannot be read as text, a folder or a link under a name is
/// not ours to replace: the next name is tried. A name that cannot be
/// looked at is this file's failure: nothing says that the name is free,
/// and the reason may be the name's own (too long for the volume).
fn conflict_file(
    dir: &Path,
    key: &str,
    tag: &str,
    text: &str,
    the_copy: &dyn Fn(&str) -> Result<bool, CordeliaError>,
    claim: &dyn Fn(&str) -> Result<Claim, CordeliaError>,
) -> Result<ConflictFile, Failure> {
    let base = names::conflict_name(key, tag);
    for n in 1.. {
        let candidate = if n == 1 {
            base.clone()
        } else {
            names::conflict_name(key, &format!("{tag}-{n}"))
        };
        let path = dir.join(&candidate);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_file() => match std::fs::read(&path) {
                Ok(existing) if existing == text.as_bytes() && the_copy(&candidate)? => {
                    return Ok(ConflictFile::Kept(candidate));
                }
                _ => continue,
            },
            Ok(_) => continue,
            // Nothing there: free, unless it is in use otherwise. (Where
            // the folder has gone, the write that follows fails and says
            // so.)
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match claim(&candidate)? {
                Claim::Taken => return Ok(ConflictFile::ToWrite(candidate)),
                Claim::InUse => continue,
                Claim::Stopped => return Ok(ConflictFile::Stopped),
            },
            Err(e) => {
                return Err(Failure::File(format!(
                    "the version here could not be kept beside it: {candidate} cannot be \
                     looked at ({e}), so the file is left as it is"
                )));
            }
        }
    }
    unreachable!()
}

/// Sync one memory folder with one channel (keys under `prefix`), under
/// the settings of `generation`. It stops, and says so in its report, as
/// soon as it finds that the settings have changed: the change may be the
/// one that stops this folder syncing.
fn sync_folder(
    state: &AppState,
    dir: &Path,
    channel: &str,
    prefix: &str,
    tag: &str,
    generation: u64,
) -> Result<FolderReport, CordeliaError> {
    sync_folder_with(state, dir, channel, prefix, tag, generation, &Hooks::NONE)
}

/// The places where a test puts something of its own into a cycle. A
/// cycle does nothing at any of them.
struct Hooks<'a> {
    /// Run once the folder has been listed, and before the cycle looks at
    /// whether it is still there. A test does what can happen to a folder
    /// while it is being listed.
    listed: &'a dyn Fn(),
    /// Run once the folder and the channel have been read and before
    /// anything is done about them. A test does what another device may
    /// do in that gap.
    between: &'a dyn Fn(),
    /// Run each time a file's new text has been flushed, with the file's
    /// name, before the last look at what is there ([`write_atomic`]). A
    /// test does what an agent may do while a text is flushed.
    flushed: &'a dyn Fn(&str),
}

impl Hooks<'_> {
    /// What a cycle does: nothing at any of them.
    const NONE: Hooks<'static> = Hooks {
        listed: &|| {},
        between: &|| {},
        flushed: &|_| {},
    };
}

/// [`sync_folder`], with `hooks` for a test.
fn sync_folder_with(
    state: &AppState,
    dir: &Path,
    channel: &str,
    prefix: &str,
    tag: &str,
    generation: u64,
    hooks: &Hooks,
) -> Result<FolderReport, CordeliaError> {
    let folder = dir.display().to_string();
    let mut report = FolderReport::default();
    let Local {
        files: local,
        skipped,
        too_large,
        not_files,
        missing,
    } = read_local(dir).map_err(|e| CordeliaError::Internal(format!("{}: {e}", dir.display())))?;
    (hooks.listed)();
    // A file that is there but cannot sync takes no part, in either
    // direction. It is not gone, so it must not be planned as deleted,
    // which would delete it on every other device; and nothing from the
    // channel is written over it. The same for a name that something
    // other than a file has (a folder): a file cannot be written there.
    let apart: HashSet<String> = skipped
        .iter()
        .chain(too_large.iter())
        .chain(not_files.iter())
        .cloned()
        .collect();
    report.skipped = skipped;
    report.too_large = too_large;

    let (remote, deleted, taken, agreed) = {
        let db = lock(state)?;
        let mut remote: HashMap<String, Remote> = HashMap::new();
        let mut deleted: HashSet<String> = HashSet::new();
        // The entry each file was planned against: see `Ctx::planned`.
        let mut taken: HashMap<String, String> = HashMap::new();
        for e in entries::current(state, &db, channel)? {
            let Some(name) = e.key.strip_prefix(prefix) else {
                continue;
            };
            if !names::is_safe_file_name(name) {
                tracing::warn!(key = %e.key, "ignoring entry whose key is not a safe file name");
                continue;
            }
            // Not a memory file (something that is not a text, written
            // through the API under a file's name): no version of one.
            let Some(item_id) = taken_as_a_version(&e) else {
                continue;
            };
            let content = if e.current.deleted {
                deleted.insert(name.to_string());
                None
            } else {
                e.current.content.as_str().map(Content::new)
            };
            taken.insert(name.to_string(), item_id.to_string());
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
        (remote, deleted, taken, agreed)
    };

    // What is not a file is listed only where the channel has a memory
    // file of that name, which cannot be written here: a folder beside
    // the memory files is nobody's business, and neither is one under a
    // name that is deleted in the channel.
    for name in not_files {
        if remote.get(&name).is_some_and(|r| r.content.is_some()) {
            report.skipped.push(name);
        }
    }

    // A memory folder that has gone is not a folder emptied by hand: its
    // disk may not be attached, or it was moved or restored. Taking that
    // for deletes would remove the memory from every other device. It is
    // gone if it was not there when it was listed, whatever is there now,
    // or is not there now that it has been listed (it went meanwhile, and
    // the names in it were passed over as they went), and the folder has a
    // file agreed: with none agreed there is nothing to take for deleted,
    // and the folder may never have been made. (A folder that goes later
    // still is caught where a delete would be published: see `apply`.)
    if (missing || !dir.is_dir()) && agreed.values().any(|a| a.hash.is_some()) {
        return Err(gone(dir));
    }
    // A folder that was not there is made here, once, where a file is to
    // arrive: a device that maps a name has no memory folder for it until
    // then. It is never made by a write (see `write_atomic`), and not once
    // the settings have changed: the change may be the one that stops this
    // folder syncing. The count is read and the folder made under the
    // database lock, which a handler holds while it counts a change: so
    // the folder is made before such a command answers, or not at all.
    if missing && remote.values().any(|r| r.content.is_some()) {
        let db = lock(state)?;
        if state.sync_control.generation_under(&db) != generation {
            report.stopped = true;
            return Ok(report);
        }
        std::fs::create_dir_all(dir)
            .map_err(|e| CordeliaError::Internal(format!("{}: {e}", dir.display())))?;
    }

    (hooks.between)();

    let mut keys: Vec<&String> = local
        .keys()
        .chain(remote.keys())
        .chain(agreed.keys())
        .collect();
    keys.sort();
    keys.dedup();

    'files: for key in keys {
        if apart.contains(key) {
            // It takes no part, so nothing is kept beside it from one
            // cycle to the next either.
            state.sync_control.unkeep(&folder, channel, key);
            continue;
        }
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
            generation,
            planned: taken.get(key).map(String::as_str),
            agreed: &agreed,
            flushed: hooks.flushed,
            relied: RefCell::new(None),
        };
        // What was kept beside this file lasts from one cycle to the next
        // only while the file is still planned with a text to keep. Any
        // other plan means that the conflict it was kept for is over,
        // however that came about (see `is_the_copy`).
        if !actions.iter().any(|a| matches!(a, Action::SaveConflict(_))) {
            state.sync_control.unkeep(&folder, channel, key);
        }
        for action in actions {
            match apply(&ctx, key, seen, action, &mut report) {
                Ok(true) => {}
                // Left as it is; planned again next cycle.
                Ok(false) => break,
                // One file that fails does not stop the files after it.
                // Nothing more is done for this file (a version that was
                // to be kept first and could not be is not written over),
                // and the next cycle plans it again.
                Err(Failure::File(error)) => {
                    tracing::debug!(file = %dir.join(key).display(), %error, "could not sync a file; going on with the rest of the folder");
                    report.fail(key, error);
                    break;
                }
                // Not this file's failure: the next file would meet it too,
                // and a file written with no record of it made would be
                // taken for a change the next time. The folder's cycle
                // ends here, and its report says why, with what it had
                // done by then.
                Err(Failure::Folder(e)) => {
                    report.error = Some(e.to_string());
                    break 'files;
                }
            }
        }
        if state.sync_control.generation() != generation {
            report.stopped = true;
            break;
        }
    }
    report.conflict_files = conflict_files(dir);
    Ok(report)
}

/// The conflict files in `dir` now, sorted, as full paths. Hidden files
/// are none of them, as they are no memory files: a temporary file left
/// by a write that was cut short has a hidden name.
fn conflict_files(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let is_conflict = |name: &str| !name.starts_with('.') && names::is_conflict_name(name);
    let mut files: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|e| is_conflict(&e.file_name().to_string_lossy()))
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
    /// The settings count this cycle runs under.
    generation: u64,
    /// The entry the plan for this file took as the channel's version of
    /// it (its item ID), or `None` if it took there to be none. An edit, a
    /// delete or a merge is published only over this: see `publish_over`.
    planned: Option<&'a str>,
    /// What the folder had agreed, for each file, when the cycle began.
    agreed: &'a HashMap<String, Agreed>,
    /// See [`Hooks::flushed`]: nothing, except in a test.
    flushed: &'a dyn Fn(&str),
    /// The conflict file that this file's text is kept in, and the hash
    /// of that text, once a step of the file's plan has kept the text or
    /// found it kept. The file is replaced only while that copy still
    /// holds the text (see `apply`).
    relied: RefCell<Option<(String, [u8; 32])>>,
}

/// Why an action could not be done.
#[derive(Debug)]
enum Failure {
    /// This file could not be written, removed or published, or its text
    /// could not be kept beside it, for a reason of its own. The cycle
    /// goes on with the other files of the folder.
    File(String),
    /// A failure that is not this file's: the database, the channel's
    /// key, this device's place in the channel, a folder that has gone.
    /// The folder's cycle ends.
    Folder(CordeliaError),
}

impl From<CordeliaError> for Failure {
    fn from(e: CordeliaError) -> Self {
        Failure::Folder(e)
    }
}

/// What a cycle says of a memory folder that has gone.
fn gone(dir: &Path) -> CordeliaError {
    CordeliaError::Internal(format!(
        "{} is gone (moved, removed, or its disk is not attached). Its files were not \
         deleted on your other devices. Bring it back; or unmap it, and map it again to \
         fetch the memory here",
        dir.display()
    ))
}

/// Whether the folder lists `name`, spelled exactly so. Looking at the
/// path would not say: on a file system that folds case, another spelling
/// of the name answers for it.
fn lists(dir: &Path, name: &str) -> std::io::Result<bool> {
    for entry in std::fs::read_dir(dir)? {
        if entry?.file_name().to_str() == Some(name) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether the conflict file `name`, which holds `text`, is the copy that
/// this folder made of the text of `key` for the conflict that `key` is in
/// now. If it is, the text is not kept again.
///
/// The folder writes down each copy it is about to make ([`claim`]): for
/// which file, against which version of the channel's, and the entry the
/// channel has under the copy's name at that moment, which is never a
/// text. Where the folder then publishes the copy, it writes down the
/// entry it published it as ([`note_published`]). A copy is relied on only
/// where
///
/// - what is written down is this copy, this text and this version; and
/// - the entry that counts under the copy's name is the one written down
///   (or there is still none).
///
/// What is written down is kept in the node's memory and nowhere else
/// (`SyncControl`). It goes:
///
/// - when the file is replaced or removed, and when an agreement for the
///   file is recorded;
/// - when a cycle plans the file with no text to keep, whatever it plans
///   in its place, or passes the file over as one that takes no part;
/// - when the copy cannot be written, and when a name is taken for the
///   file's text: the record made for that name replaces this one (there
///   is one record for a file);
/// - each time the node takes a settings command, which is any
///   `cordelia sync` command but `status`. The node takes a command when
///   what the command asks passes the node's checks, whether or not the
///   command then changes anything. A command that the node refuses is
///   not taken, and nor is one that the command line answers by itself,
///   as the command line answers a `map` of a mapping that is already
///   declared;
/// - when the folder stops syncing, and when the node stops.
///
/// So a copy is relied on from one cycle to the next only while the file
/// has still to take the version the copy was made against, and only
/// until the node takes a settings command or stops. In every other case
/// a conflict file that holds the text is not relied on, and the text is
/// kept again under the first name that is free. That is one copy more
/// than was needed where the conflict file was this conflict's own:
/// after each restart, after each settings command that the node takes,
/// and each time the folder stops syncing and syncs again, for a file
/// that still cannot take the channel's version. It is what keeps the
/// text where the conflict file is from an earlier conflict: that file
/// has been with the other devices, and a delete or an edit of it may be
/// on its way back from one that did not know the text would be relied
/// on again. The text would then be in no file.
fn is_the_copy(ctx: &Ctx, key: &str, name: &str, text: &str) -> Result<bool, CordeliaError> {
    let control = &ctx.state.sync_control;
    let Some(kept) = control.kept_beside(ctx.folder, ctx.channel, key) else {
        return Ok(false);
    };
    let version = kept.version.as_deref();
    if kept.copy != name || version != ctx.planned || kept.hash != Content::new(text).hash {
        return Ok(false);
    }
    let db = lock(ctx.state)?;
    let full_name = format!("{}{name}", ctx.prefix);
    let now = entries::current_of(ctx.state, &db, ctx.channel, &full_name)?;
    Ok(now.map(|entry| entry.current.item_id) == kept.under)
}

/// Take the conflict-file name `name`, which nothing has in the folder,
/// for a copy of `text`, the text of `key`, and write that down
/// ([`is_the_copy`]). It is written down before the copy is: a copy that
/// was made and could not be written down would be made again in every
/// cycle.
///
/// The name is in use all the same, and is not taken, in two cases:
///
/// - The channel has a text under it. A copy written there would be taken
///   for that entry, and would go when that entry goes.
/// - The folder had this text agreed under it when the cycle began. The
///   file was there and is not now: it was removed or moved here, or the
///   cycle has just removed it for a delete. A copy written there with
///   the same text could be taken for the agreed file again, unchanged,
///   and a delete of it that another device has made would then remove
///   it. (Where the channel has nothing under the name and the folder's
///   record of it stays, the name stays in use for that text.)
///
/// The look at the channel, the look at the settings and the record are
/// made under one hold of the database lock. So nothing arrives under the
/// name between the look and the record, and nothing is written down once
/// the settings have changed: the text is then not kept in this cycle,
/// and the file is not replaced in it either.
fn claim(ctx: &Ctx, key: &str, name: &str, text: &str) -> Result<Claim, CordeliaError> {
    let hash = Content::new(text).hash;
    if ctx.agreed.get(name).is_some_and(|a| a.hash == Some(hash)) {
        return Ok(Claim::InUse);
    }
    let db = lock(ctx.state)?;
    if ctx.state.sync_control.generation_under(&db) != ctx.generation {
        return Ok(Claim::Stopped);
    }
    let full_name = format!("{}{name}", ctx.prefix);
    let under = entries::current_of(ctx.state, &db, ctx.channel, &full_name)?;
    if under
        .as_ref()
        .is_some_and(|entry| is_a_text(&entry.current))
    {
        return Ok(Claim::InUse);
    }
    let kept = Kept {
        version: ctx.planned.map(str::to_string),
        copy: name.to_string(),
        hash,
        under: under.map(|entry| entry.current.item_id),
    };
    ctx.state
        .sync_control
        .keep(&db, ctx.folder, ctx.channel, key, kept);
    Ok(Claim::Taken)
}

/// Write down that this folder has published `text` under `key` as the
/// entry `entry`. Where `key` is a copy that the folder wrote down, with
/// this text, the copy is under that entry now ([`is_the_copy`]): a copy
/// that its own folder publishes is still the copy.
fn note_published(ctx: &Ctx, key: &str, text: &str, entry: &str) {
    let hash = Content::new(text).hash;
    let control = &ctx.state.sync_control;
    control.kept_published(ctx.folder, ctx.channel, key, &hash, entry);
}

/// Forget what this folder has written down as kept beside `key`. Where
/// the file has been replaced or removed, it no longer holds the text
/// that was kept, and a copy of that text is the copy of a conflict that
/// is over. What was written down is forgotten whatever the settings are
/// now, and before an agreement is recorded. Where the copy could not be
/// written, nothing was kept.
fn forget_kept(ctx: &Ctx, key: &str) {
    let control = &ctx.state.sync_control;
    control.unkeep(ctx.folder, ctx.channel, key);
}

/// Whether `version` is a text. A delete is not, whatever it carries.
fn is_a_text(version: &entries::Version) -> bool {
    !version.deleted && version.content.is_string()
}

/// The item that the adapter takes as the channel's version of a memory
/// file, given the channel's current entry under the file's name: a text,
/// or a delete. An entry that holds anything else (something that is not
/// a text, written through the API under a file's name) is no version of
/// a memory file, for the plan and for the check before a publish alike.
fn taken_as_a_version(entry: &entries::Entry) -> Option<&str> {
    let version = &entry.current;
    (version.deleted || version.content.is_string()).then_some(version.item_id.as_str())
}

/// Hash of the file as it is on disk right now (`None` if absent).
fn current_hash(dir: &Path, key: &str) -> Option<[u8; 32]> {
    std::fs::read(dir.join(key))
        .ok()
        .map(|bytes| cordelia_crypto::sha256(&bytes))
}

/// Record what `folder` and `channel` now agree on for `key`, under the
/// settings of `generation`, and forget what was kept beside the file
/// ([`is_the_copy`]): a file can come to agree with the channel without
/// being replaced. Nothing is recorded once the settings have
/// changed: the folder may have been stopped, and what it had agreed
/// forgotten, since the change this would record. If it still syncs, the
/// next cycle finds both sides the same and records it then.
fn record_agreed(
    state: &AppState,
    generation: u64,
    folder: &str,
    channel: &str,
    key: &str,
    agreed: sync_state::Agreed,
) -> Result<(), CordeliaError> {
    let db = lock(state)?;
    if state.sync_control.generation_under(&db) != generation {
        return Ok(());
    }
    sync_state::save(&db, folder, channel, key, agreed)?;
    // The file and the channel agree, so the conflict that a text was
    // kept for is over: a copy made for it is relied on no longer.
    state.sync_control.unkeep(folder, channel, key);
    Ok(())
}

/// Publish `text` under `full_key`, or a delete if there is none, and
/// return the entry. `None`, with nothing published, if the settings
/// have changed since the cycle read them, or the channel's version of the
/// file is not the entry the plan took it to be (`Ctx::planned`).
///
/// Both are looked at on `db`, and the entry is published on it: the caller
/// holds the database lock for the whole of this, so neither can change
/// between the look and the publish.
fn publish_over(
    ctx: &Ctx,
    db: &rusqlite::Connection,
    full_key: &str,
    text: Option<&str>,
) -> Result<Option<entries::Published>, CordeliaError> {
    let Ctx {
        state,
        channel,
        folder,
        generation,
        planned,
        ..
    } = *ctx;
    // Called with the lock held, and `db` is the connection behind it.
    // In a debug build this catches a caller that took no lock at all. It
    // cannot tell who holds the lock, or that `db` is that connection.
    debug_assert!(state.db.try_lock().is_err());
    if state.sync_control.generation_under(db) != generation {
        tracing::debug!(
            folder,
            channel,
            key = full_key,
            "the settings changed since the cycle read them; not published"
        );
        return Ok(None);
    }
    let now = entries::current_of(state, db, channel, full_key)?;
    if now.as_ref().and_then(taken_as_a_version) != planned {
        tracing::debug!(
            folder,
            channel,
            key = full_key,
            "the channel's version changed since the plan; left for the next cycle"
        );
        return Ok(None);
    }
    let content = text.map_or(Value::Null, |t| Value::String(t.to_string()));
    let write = Write {
        key: full_key,
        content: &content,
        metadata: None,
        item_type: ITEM_TYPE,
        deleted: text.is_none(),
    };
    Ok(Some(entries::publish(state, db, channel, &write)?))
}

/// Apply one action. An error says whether it is this file's or the
/// folder's ([`Failure`]). Returns `false` in seven cases, and in all but
/// the last it has made no change:
///
/// - The action would replace or remove the file, but the file changed
///   since it was scanned: an agent wrote to it mid-cycle. The next cycle
///   plans with that write, so it is published or kept as a conflict,
///   never overwritten. A file that is to be written is looked at for
///   this as the last thing before it is replaced ([`write_atomic`]).
/// - The action would replace or remove the file, and the conflict file
///   in which an earlier step of the plan kept the file's text, or found
///   it kept, no longer holds that text: someone removed or changed the
///   copy meanwhile. The text would be in no file. The next cycle keeps
///   it again.
/// - The settings have changed since the cycle read them. A command that
///   stops this folder syncing may have answered, and nothing more of the
///   folder is to be published or written after that. An entry is
///   published only after the count is read under the database lock, which
///   is the lock a handler holds while it changes a setting and counts it.
/// - The action would publish, and the channel's version of the file is
///   no longer the one it was planned against. Something has changed which
///   entry counts since the plan was made: another device's entry arrived,
///   most often, or a device was removed, or a key arrived that makes an
///   entry readable. Publishing would put this device's text over an entry
///   the plan never read, with no conflict file. The next cycle plans
///   against what is there now. It is the entry that is compared, not its
///   revision: two devices can publish the same revision, and which of
///   them counts can change while the number does not.
/// - The action would publish, and the file does not fit in an entry. It
///   is named in the report and left as it is.
/// - The action would publish a delete, and the folder now lists the
///   file's name: the file is back, or something else has its name. The
///   next cycle plans with what is there.
/// - A merged index was published, and the file was written to while the
///   merged text was being flushed. The file is left as it is, nothing is
///   recorded, and the next cycle merges what is there.
fn apply(
    ctx: &Ctx,
    key: &str,
    seen: Option<[u8; 32]>,
    action: Action,
    report: &mut FolderReport,
) -> Result<bool, Failure> {
    let Ctx {
        state,
        dir,
        channel,
        prefix,
        tag,
        folder,
        generation,
        planned: _,
        agreed: _,
        flushed: _,
        relied: _,
    } = *ctx;
    let writes_file = matches!(
        action,
        Action::Pull { .. } | Action::RemoveFile { .. } | Action::SaveConflict(_)
    );
    if writes_file && state.sync_control.generation() != generation {
        return Ok(false);
    }
    // Whether the file is still as the cycle saw it, and the copy that
    // its text is kept in, if a step of the plan kept the text or found
    // it kept, still holds that text: a copy that someone removes while
    // the file's new text is flushed would leave the text in no file.
    // This is asked of a file that is removed, or merged, before anything
    // is done. Of a file that is written (by `Pull`, or as the file of a
    // `Merge`) `write_atomic` asks it, as the last thing before the file
    // is replaced.
    let unchanged = || {
        let kept = ctx.relied.borrow();
        current_hash(dir, key) == seen
            && kept
                .as_ref()
                .is_none_or(|(copy, hash)| current_hash(dir, copy) == Some(*hash))
    };
    let flushed = || (ctx.flushed)(key);
    let deferred = || {
        tracing::debug!(file = %dir.join(key).display(), "the file, or the copy of its text, changed during the cycle; deferring");
    };
    let replaces_file = matches!(action, Action::RemoveFile { .. } | Action::Merge(_));
    if replaces_file && !unchanged() {
        deferred();
        return Ok(false);
    }
    // A delete is published only for a name that the folder, listed again
    // now, does not have. It is asked of the listing, not of the path: on
    // a file system that folds case, a file renamed to another spelling of
    // its name would answer for the name it had, and its delete would
    // never be published.
    // - The name is there: the file is back, or something else has its
    //   name. Nothing is published.
    // - The folder is not there, or cannot be listed: that the name is
    //   not there shows nothing then. (Where a folder goes while it is
    //   being listed, every name in it is passed over as it goes.) No
    //   delete is published, and the folder's cycle ends, as it does for
    //   a folder that was gone from the start.
    if matches!(action, Action::PublishDelete) {
        match lists(dir, key) {
            Ok(false) => {}
            Ok(true) => {
                tracing::debug!(file = %dir.join(key).display(), "back during the cycle; deferring its delete");
                return Ok(false);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Failure::Folder(gone(dir)));
            }
            Err(e) => {
                let why = format!("{}: {e}", dir.display());
                return Err(Failure::Folder(CordeliaError::Internal(why)));
            }
        }
    }
    // The reason alone: the file is named by whoever reports it.
    let io = |e: std::io::Error| Failure::File(e.to_string());
    let full_key = format!("{prefix}{key}");
    // A publish that is refused for what the entry is (its name's
    // revisions are used up, say) is this file's failure. Any other is
    // the folder's.
    let publish = |text: Option<&str>| -> Result<Option<entries::Published>, Failure> {
        let db = lock(state)?;
        publish_over(ctx, &db, &full_key, text).map_err(|e| match e {
            CordeliaError::Validation(why) => Failure::File(why),
            e => Failure::Folder(e),
        })
    };
    let record = |hash: Option<[u8; 32]>, rev: u64| -> Result<(), CordeliaError> {
        record_agreed(state, generation, folder, channel, key, (hash, rev))
    };

    // An entry holds the file's name beside its text, and the text is
    // escaped, so a file under MAX_FILE_BYTES can still be too large. It is
    // then left as it is, like one that was never read.
    let too_large = |report: &mut FolderReport| {
        if !report.too_large.iter().any(|name| name == key) {
            report.too_large.push(key.to_string());
        }
    };

    match action {
        Action::Publish(text) => match publish(Some(&text)) {
            Ok(Some(entry)) => {
                report.published += 1;
                note_published(ctx, key, &text, &entry.item_id);
                record(Some(Content::new(text).hash), entry.rev)?;
            }
            Ok(None) => return Ok(false),
            Err(Failure::Folder(CordeliaError::TooLarge { .. })) => {
                too_large(report);
                return Ok(false);
            }
            Err(e) => return Err(e),
        },
        Action::PublishDelete => {
            let Some(entry) = publish(None)? else {
                return Ok(false);
            };
            report.published += 1;
            record(None, entry.rev)?;
        }
        Action::Pull { text, rev } => {
            if !write_atomic(dir, key, &text, &flushed, &unchanged).map_err(io)? {
                deferred();
                return Ok(false);
            }
            report.pulled += 1;
            forget_kept(ctx, key);
            record(Some(Content::new(text).hash), rev)?;
        }
        Action::RemoveFile { rev } => {
            match std::fs::remove_file(dir.join(key)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(io(e)),
            }
            report.pulled += 1;
            forget_kept(ctx, key);
            record(None, rev)?;
        }
        Action::SaveConflict(text) => {
            // Not kept twice: a conflict file that holds this text and is
            // the copy made for this conflict is relied on.
            let the_copy = |name: &str| is_the_copy(ctx, key, name, &text);
            let claim = |name: &str| claim(ctx, key, name, &text);
            let name = match conflict_file(dir, key, tag, &text, &the_copy, &claim)? {
                ConflictFile::Stopped => return Ok(false),
                ConflictFile::Kept(name) => name,
                ConflictFile::ToWrite(name) => {
                    // Said in full: the file named in the report is there
                    // and can be read, and it is the copy beside it that
                    // failed. Nothing was kept, so nothing stays written
                    // down.
                    let not_kept = |why: String| {
                        forget_kept(ctx, key);
                        Failure::File(format!(
                            "the version here could not be kept beside it as {name} ({why}), \
                             so the file is left as it is"
                        ))
                    };
                    // The name was free. If something has it by the time
                    // the text is flushed, or it can no longer be looked
                    // at, that is not written over.
                    let free = || {
                        let there = std::fs::symlink_metadata(dir.join(&name));
                        matches!(there, Err(e) if e.kind() == std::io::ErrorKind::NotFound)
                    };
                    let flushed = || (ctx.flushed)(&name);
                    match write_atomic(dir, &name, &text, &flushed, &free) {
                        Ok(true) => {}
                        Ok(false) => return Err(not_kept("the name is no longer free".into())),
                        Err(e) => return Err(not_kept(e.to_string())),
                    }
                    tracing::info!(file = %dir.join(&name).display(), "kept this device's version of a conflicting edit");
                    name
                }
            };
            *ctx.relied.borrow_mut() = Some((name, Content::new(text).hash));
            report.conflicts += 1;
        }
        Action::Merge(text) => {
            // Published before the file is written: if the merged text does
            // not fit, the file stays as it was.
            match publish(Some(&text)) {
                Ok(Some(entry)) => {
                    report.published += 1;
                    if !write_atomic(dir, key, &text, &flushed, &unchanged).map_err(io)? {
                        // Published, and the file was written to meanwhile:
                        // the next cycle merges what is there now.
                        deferred();
                        return Ok(false);
                    }
                    forget_kept(ctx, key);
                    record(Some(Content::new(text).hash), entry.rev)?;
                }
                Ok(None) => return Ok(false),
                Err(Failure::Folder(CordeliaError::TooLarge { .. })) => {
                    too_large(report);
                    return Ok(false);
                }
                Err(e) => return Err(e),
            }
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
            peers: Default::default(),
            relays: Default::default(),
            outbox_refused: Default::default(),
            relist: Default::default(),
            sync_control: Default::default(),
            usable_keys: Default::default(),
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
            generation: 0,
            planned: None,
            agreed: &HashMap::new(),
            flushed: &|_| {},
            relied: RefCell::new(None),
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
    /// A command that stops a folder syncing has stopped it when it
    /// answers. Its handler counts the change while it holds the database
    /// lock. A cycle that started before reads the count under that lock
    /// before each entry it publishes, and reads it before each file it
    /// writes; once it differs, the cycle does nothing more.
    #[test]
    fn a_cycle_stops_when_the_settings_change() {
        let tmp = tempfile::tempdir().unwrap();
        let st = state(tmp.path());
        membership::ensure_own_inbox(&st).unwrap();
        let channel = membership::create_project_group(&st, "project:x").unwrap();
        let mem = tmp.path().join("memory");
        std::fs::create_dir_all(&mem).unwrap();
        // The files the channel holds, and whether each is live.
        let held = |st: &AppState| -> Vec<(String, bool)> {
            entries::current(st, &st.db.lock().unwrap(), &channel)
                .unwrap()
                .into_iter()
                .map(|e| (e.key, !e.current.deleted))
                .collect()
        };
        let cycle =
            |generation: u64| sync_folder(&st, &mem, &channel, "", "abcd", generation).unwrap();

        // Under the settings it started from, a cycle publishes.
        std::fs::write(mem.join("a.md"), "one\n").unwrap();
        let started = st.sync_control.generation();
        let report = cycle(started);
        assert_eq!((report.published, report.stopped), (1, false));
        assert_eq!(held(&st), [("a.md".to_string(), true)]);

        // A setting changes. A cycle still running under the old settings
        // publishes no edit and no delete...
        st.sync_control.changed(&st.db.lock().unwrap());
        std::fs::write(mem.join("b.md"), "two\n").unwrap();
        let report = cycle(started);
        assert_eq!((report.published, report.stopped), (0, true));
        std::fs::remove_file(mem.join("a.md")).unwrap();
        std::fs::remove_file(mem.join("b.md")).unwrap();
        let report = cycle(started);
        assert_eq!((report.published, report.stopped), (0, true));
        assert_eq!(held(&st), [("a.md".to_string(), true)]);

        // ...and writes, replaces and removes no file.
        std::fs::write(mem.join("kept.md"), "here\n").unwrap();
        let folder = mem.display().to_string();
        let ctx = Ctx {
            state: &st,
            dir: &mem,
            channel: &channel,
            prefix: "",
            tag: "abcd",
            folder: &folder,
            generation: started,
            planned: None,
            agreed: &HashMap::new(),
            flushed: &|_| {},
            relied: RefCell::new(None),
        };
        let seen = Some(Content::new("here\n").hash);
        let mut report = FolderReport::default();
        let pull = || Action::Pull {
            text: "from another device\n".into(),
            rev: 2,
        };
        assert!(!apply(&ctx, "new.md", None, pull(), &mut report).unwrap());
        assert!(!apply(&ctx, "kept.md", seen, pull(), &mut report).unwrap());
        let gone = Action::RemoveFile { rev: 2 };
        assert!(!apply(&ctx, "kept.md", seen, gone, &mut report).unwrap());
        let beside = Action::SaveConflict("this device's\n".into());
        assert!(!apply(&ctx, "kept.md", seen, beside, &mut report).unwrap());
        let mut names: Vec<String> = std::fs::read_dir(&mem)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["kept.md"]);
        assert_eq!(
            std::fs::read_to_string(mem.join("kept.md")).unwrap(),
            "here\n"
        );
        assert_eq!((report.pulled, report.conflicts), (0, 0));

        // ...and records nothing: the handler that changed the setting may
        // have forgotten what a folder agreed, and a record made after it
        // would bring a part of that back.
        let elsewhere = "/another/memory";
        let agreed = |st: &AppState| {
            let db = st.db.lock().unwrap();
            let all = sync_state::load(&db, elsewhere, &channel).unwrap();
            all.contains_key("late.md")
        };
        record_agreed(&st, started, elsewhere, &channel, "late.md", (None, 9)).unwrap();
        assert!(!agreed(&st));
        let now = st.sync_control.generation();
        record_agreed(&st, now, elsewhere, &channel, "late.md", (None, 9)).unwrap();
        assert!(agreed(&st));

        // The next cycle, under the settings as they are now, carries on.
        let report = cycle(st.sync_control.generation());
        assert!(!report.stopped);
        assert_eq!(report.published, 2, "the delete of a.md, and kept.md");
    }
    /// A second device of the same person in `channel`: a member there as
    /// `st` holds it, with the channel's keys, as pairing and joining
    /// leave it. Entries pass between devices by `deliver`.
    fn another_device(st: &AppState, dir: &Path, channel: &str) -> AppState {
        use cordelia_storage::psk;
        let other = state(dir);
        let (mine, theirs) = (st.identity.public_key(), other.identity.public_key());
        let key = psk::read_psk(&st.home_dir, channel).unwrap();
        let slot_key = psk::read_slot_key(&st.home_dir, channel).unwrap();
        psk::write_psk(&other.home_dir, channel, &key).unwrap();
        psk::write_slot_key(&other.home_dir, channel, &slot_key).unwrap();
        {
            let db = other.db.lock().unwrap();
            channels::ensure_group(&db, channel, None, "realtime", &mine).unwrap();
            let hash = cordelia_crypto::sha256(&key);
            channels::set_state(&db, channel, 1, &mine, 1, &hash).unwrap();
            for member in [&mine, &theirs] {
                channels::add_member(&db, channel, member, "owner").unwrap();
            }
        }
        channels::add_member(&st.db.lock().unwrap(), channel, &theirs, "owner").unwrap();
        other
    }

    /// The entries `st` holds in `channel`, as they are stored.
    fn held(st: &AppState, channel: &str) -> Vec<cordelia_storage::items::StoredItem> {
        cordelia_storage::items::query_sync(&st.db.lock().unwrap(), channel, None, 1000).unwrap()
    }

    /// Copy the entries `from` holds in `channel` to `to`, as a relay does.
    fn deliver(from: &AppState, to: &AppState, channel: &str) {
        use cordelia_storage::items;
        let db = to.db.lock().unwrap();
        for it in held(from, channel) {
            let slot: Option<[u8; 32]> = it.slot.as_deref().map(|s| s.try_into().unwrap());
            items::insert_item(
                &db,
                &items::NewItem {
                    item_id: &it.item_id,
                    channel_id: &it.channel_id,
                    author_id: it.author_id.as_slice().try_into().unwrap(),
                    item_type: &it.item_type,
                    published_at: &it.published_at,
                    parent_id: it.parent_id.as_deref(),
                    key_version: it.key_version,
                    content_hash: &it.content_hash,
                    signature: &it.signature,
                    encrypted_blob: &it.encrypted_blob,
                    is_tombstone: it.is_tombstone,
                    slot: slot.as_ref(),
                    rev: it.rev,
                },
            )
            .unwrap();
        }
    }

    /// Publish `content` under `key` as `st`, as its adapter would a text.
    /// Returns the entry's ID.
    fn write(st: &AppState, channel: &str, key: &str, content: Value) -> String {
        let write = Write {
            key,
            content: &content,
            metadata: None,
            item_type: ITEM_TYPE,
            deleted: false,
        };
        entries::publish(st, &st.db.lock().unwrap(), channel, &write)
            .unwrap()
            .item_id
    }

    /// Put in `st`'s store an entry for `key` by `st` at the revision
    /// `rev`, with `text`: what a device that has written the file that
    /// many times holds. (A publish takes the next revision, whatever it
    /// is.)
    fn write_at(st: &AppState, channel: &str, key: &str, text: &str, rev: u64) {
        entry_at(st, channel, key, text, rev, false);
    }

    /// The same, as a delete if `deleted`: one that carries `text`, which
    /// no device that follows the code writes. Returns the entry's ID.
    fn entry_at(
        st: &AppState,
        channel: &str,
        key: &str,
        text: &str,
        rev: u64,
        deleted: bool,
    ) -> String {
        use cordelia_crypto::signing::ItemMetadata;
        use cordelia_crypto::slots::{item_aad, slot_id};
        use cordelia_storage::{items, psk};
        let author = st.identity.public_key();
        let slot = slot_id(&psk::read_slot_key(&st.home_dir, channel).unwrap(), key);
        let plaintext = serde_json::json!({ "key": key, "content": text, "metadata": null });
        let blob = cordelia_crypto::item_encrypt(
            &psk::read_psk(&st.home_dir, channel).unwrap(),
            &serde_json::to_vec(&plaintext).unwrap(),
            &item_aad(channel, Some(&slot), Some(rev)),
        )
        .unwrap();
        let content_hash = cordelia_crypto::sha256(&blob);
        let db = st.db.lock().unwrap();
        let key_version = channels::get_by_id(&db, channel).unwrap().key_version;
        let item_id = items::generate_item_id();
        let published_at = chrono::Utc::now().to_rfc3339();
        let signed = ItemMetadata {
            author_id: &author,
            channel_id: channel,
            content_hash: &content_hash,
            is_tombstone: deleted,
            item_id: &item_id,
            key_version,
            published_at: &published_at,
            slot: Some(&slot),
            rev: Some(rev),
        }
        .encode()
        .unwrap();
        let stored = items::insert_item(
            &db,
            &items::NewItem {
                item_id: &item_id,
                channel_id: channel,
                author_id: &author,
                item_type: ITEM_TYPE,
                published_at: &published_at,
                parent_id: None,
                key_version,
                content_hash: &content_hash,
                signature: &st.identity.sign(&signed),
                encrypted_blob: &blob,
                is_tombstone: deleted,
                slot: Some(&slot),
                rev: Some(rev),
            },
        )
        .unwrap();
        assert!(stored);
        item_id
    }

    /// What `st` takes as the channel's version of `key`: the entry's ID,
    /// its revision and its text.
    fn version(st: &AppState, channel: &str, key: &str) -> Option<(String, u64, String)> {
        let db = st.db.lock().unwrap();
        let entry = entries::current_of(st, &db, channel, key).unwrap()?;
        let text = entry.current.content.as_str().unwrap_or_default();
        Some((entry.current.item_id, entry.current.rev, text.to_string()))
    }

    /// An edit, a delete or a merged index is published only over the
    /// entry it was planned against. An entry from another device that
    /// arrives between the plan and the publish is one this device never
    /// read: published over, its text would be replaced with no conflict
    /// file anywhere. It is the entry that is compared, not its revision.
    #[test]
    fn an_edit_is_published_only_over_the_entry_it_was_planned_against() {
        let tmp = tempfile::tempdir().unwrap();
        let st = state(tmp.path());
        membership::ensure_own_inbox(&st).unwrap();
        let channel = membership::create_project_group(&st, "project:x").unwrap();
        let other = another_device(&st, &tmp.path().join("other"), &channel);
        let mem = tmp.path().join("memory");
        std::fs::create_dir_all(&mem).unwrap();
        let folder = mem.display().to_string();
        let text = |t: &str| Value::String(t.into());
        // Apply `action` to `key`, under `prefix` in the channel, as
        // planned against the entry `planned`.
        let apply_under =
            |prefix: &str, key: &str, planned: Option<&str>, action: Action| -> bool {
                let ctx = Ctx {
                    state: &st,
                    dir: &mem,
                    channel: &channel,
                    prefix,
                    tag: "abcd",
                    folder: &folder,
                    generation: st.sync_control.generation(),
                    planned,
                    agreed: &HashMap::new(),
                    flushed: &|_| {},
                    relied: RefCell::new(None),
                };
                let seen = current_hash(&mem, key);
                apply(&ctx, key, seen, action, &mut FolderReport::default()).unwrap()
            };
        let apply_over = |key: &str, planned: Option<&str>, action: Action| -> bool {
            apply_under("", key, planned, action)
        };
        // Each action that publishes. None of them may go over an entry
        // that was not planned against. A refusal leaves everything as it
        // was: nothing is counted or recorded, and a merge writes no file.
        let refused = |key: &str, planned: Option<&str>| {
            for action in [
                Action::Publish("mine\n".into()),
                Action::PublishDelete,
                Action::Merge("merged\n".into()),
            ] {
                let ctx = Ctx {
                    state: &st,
                    dir: &mem,
                    channel: &channel,
                    prefix: "",
                    tag: "abcd",
                    folder: &folder,
                    generation: st.sync_control.generation(),
                    planned,
                    agreed: &HashMap::new(),
                    flushed: &|_| {},
                    relied: RefCell::new(None),
                };
                let mut report = FolderReport::default();
                let done = apply(&ctx, key, None, action.clone(), &mut report).unwrap();
                assert!(!done, "{action:?}");
                assert_eq!(report.published, 0, "{action:?}");
            }
            assert!(!mem.join(key).exists());
            let db = st.db.lock().unwrap();
            let agreed = sync_state::load(&db, &folder, &channel).unwrap();
            assert!(!agreed.contains_key(key), "{key}");
        };

        // A higher revision has arrived.
        let planned = write(&st, &channel, "notes.md", text("one\n"));
        deliver(&st, &other, &channel);
        let theirs = write(&other, &channel, "notes.md", text("theirs\n"));
        deliver(&other, &st, &channel);
        refused("notes.md", Some(&planned));
        let there = Some((theirs.clone(), 2, "theirs\n".to_string()));
        assert_eq!(version(&st, &channel, "notes.md"), there);
        // Planned against what is there now, it goes ahead.
        assert!(apply_over(
            "notes.md",
            Some(&theirs),
            Action::Publish("mine\n".into())
        ));
        let (_, rev, now) = version(&st, &channel, "notes.md").unwrap();
        assert_eq!((rev, now.as_str()), (3, "mine\n"));

        // Another device's entry at the same revision has taken its place.
        // The number has not changed, so a check of the number would pass.
        let planned = write(&st, &channel, "tied.md", text("mine\n"));
        let hash = |st: &AppState, id: &str| -> Vec<u8> {
            let it = held(st, &channel).into_iter().find(|it| it.item_id == id);
            it.unwrap().content_hash
        };
        // A tie goes to the higher hash, and a hash is over a random nonce:
        // devices write until one writes the entry that wins.
        let theirs = (0..)
            .find_map(|n| {
                let third = another_device(&st, &tmp.path().join(format!("tie{n}")), &channel);
                let id = write(&third, &channel, "tied.md", text("theirs\n"));
                (hash(&third, &id) > hash(&st, &planned)).then(|| {
                    deliver(&third, &st, &channel);
                    id
                })
            })
            .unwrap();
        let there = Some((theirs, 1, "theirs\n".to_string()));
        assert_eq!(version(&st, &channel, "tied.md"), there);
        refused("tied.md", Some(&planned));
        assert_eq!(version(&st, &channel, "tied.md"), there);

        // An entry has appeared where the plan read none.
        let theirs = write(&other, &channel, "new.md", text("theirs\n"));
        deliver(&other, &st, &channel);
        refused("new.md", None);
        let there = Some((theirs.clone(), 1, "theirs\n".to_string()));
        assert_eq!(version(&st, &channel, "new.md"), there);

        // The entry the plan read has gone: the device that wrote it was
        // removed, and what it wrote counts for nothing. (This is a device
        // that hears of the removal before the entry the remover publishes
        // again for it has arrived.)
        let removed = other.identity.public_key();
        channels::remove_member(&st.db.lock().unwrap(), &channel, &removed).unwrap();
        assert_eq!(version(&st, &channel, "new.md"), None);
        refused("new.md", Some(&theirs));
        assert_eq!(version(&st, &channel, "new.md"), None);
        assert!(apply_over("new.md", None, Action::Publish("mine\n".into())));

        // A file's entry is looked at under the name it is published
        // under, prefix and all: not under the file's bare name, where
        // there is nothing.
        let held_as = write(&st, &channel, "p/pre.md", text("one\n"));
        let edit = || Action::Publish("two\n".into());
        assert!(!apply_under("p/", "pre.md", None, edit()));
        assert!(apply_under("p/", "pre.md", Some(&held_as), edit()));
        let (_, rev, now) = version(&st, &channel, "p/pre.md").unwrap();
        assert_eq!((rev, now.as_str()), (2, "two\n"));
        assert_eq!(version(&st, &channel, "pre.md"), None);
    }

    /// The check reads what the plan reads. An entry under a file's name
    /// that is not a text or a delete (something written through the API),
    /// and an entry this device cannot read, are no version of the file to
    /// either: the plan finds none, and the file is published over them as
    /// it was before there was a check. What this pins is that the two
    /// agree: a plan that counted such an entry where the check did not, or
    /// the other way round, would leave the file unpublished for good.
    #[test]
    fn what_is_no_version_of_a_memory_file_holds_nothing_back() {
        let tmp = tempfile::tempdir().unwrap();
        let st = state(tmp.path());
        membership::ensure_own_inbox(&st).unwrap();
        let channel = membership::create_project_group(&st, "project:x").unwrap();
        let mem = tmp.path().join("memory");
        std::fs::create_dir_all(&mem).unwrap();

        // Not a text.
        write(&st, &channel, "api.md", serde_json::json!({ "a": 1 }));
        // Sealed by another member under a key this device does not hold.
        let other = another_device(&st, &tmp.path().join("other"), &channel);
        let key = [7u8; 32];
        cordelia_storage::psk::write_psk(&other.home_dir, &channel, &key).unwrap();
        channels::set_state(
            &other.db.lock().unwrap(),
            &channel,
            2,
            &other.identity.public_key(),
            2,
            &cordelia_crypto::sha256(&key),
        )
        .unwrap();
        write(
            &other,
            &channel,
            "sealed.md",
            Value::String("theirs\n".into()),
        );
        deliver(&other, &st, &channel);
        assert_eq!(held(&st, &channel).len(), 2);
        assert_eq!(version(&st, &channel, "sealed.md"), None);

        for name in ["api.md", "sealed.md"] {
            std::fs::write(mem.join(name), "mine\n").unwrap();
        }
        let generation = st.sync_control.generation();
        let report = sync_folder(&st, &mem, &channel, "", "abcd", generation).unwrap();
        assert_eq!(report.published, 2);
        for name in ["api.md", "sealed.md"] {
            let (_, rev, text) = version(&st, &channel, name).unwrap();
            assert_eq!((rev, text.as_str()), (2, "mine\n"), "{name}");
        }

        // An entry of that kind over a file that is agreed and unchanged,
        // at a higher revision than the one agreed: it is no delete and no
        // text to take, so the file is left as it is and nothing is
        // published.
        write(&st, &channel, "api.md", serde_json::json!({ "a": 2 }));
        let report = sync_folder(&st, &mem, &channel, "", "abcd", generation).unwrap();
        assert_eq!((report.published, report.pulled), (0, 0), "{report:?}");
        let kept = std::fs::read_to_string(mem.join("api.md")).unwrap();
        assert_eq!(kept, "mine\n");
    }

    /// A folder in a channel that two devices hold, as a cycle on the first
    /// sees it: `st` with its memory folder, and `other` to write to the
    /// channel as another device would.
    struct Pair {
        st: AppState,
        other: AppState,
        channel: String,
        mem: PathBuf,
        _tmp: tempfile::TempDir,
    }

    impl Pair {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let st = state(tmp.path());
            membership::ensure_own_inbox(&st).unwrap();
            let channel = membership::create_project_group(&st, "project:x").unwrap();
            let other = another_device(&st, &tmp.path().join("other"), &channel);
            let mem = tmp.path().join("memory");
            std::fs::create_dir_all(&mem).unwrap();
            Self {
                st,
                other,
                channel,
                mem,
                _tmp: tmp,
            }
        }

        fn file(&self, name: &str, text: &str) {
            std::fs::write(self.mem.join(name), text).unwrap();
        }

        fn read(&self, name: &str) -> Option<String> {
            std::fs::read_to_string(self.mem.join(name)).ok()
        }

        /// One cycle of the folder on `st`, with `between` done once it
        /// has read the folder and the channel.
        fn cycle_with(&self, between: &dyn Fn()) -> FolderReport {
            self.try_cycle_with(between).unwrap()
        }

        /// The same, for a cycle that may fail for the whole folder.
        fn try_cycle_with(&self, between: &dyn Fn()) -> Result<FolderReport, CordeliaError> {
            self.cycle_hooked(&Hooks {
                between,
                ..Hooks::NONE
            })
        }

        /// One cycle with `hooks`.
        fn cycle_hooked(&self, hooks: &Hooks) -> Result<FolderReport, CordeliaError> {
            let generation = self.st.sync_control.generation();
            sync_folder_with(
                &self.st,
                &self.mem,
                &self.channel,
                "",
                "abcd",
                generation,
                hooks,
            )
        }

        fn cycle(&self) -> FolderReport {
            self.cycle_with(&|| {})
        }

        /// One cycle, with `listed` done once it has listed the folder
        /// and before it looks at whether the folder is still there.
        fn cycle_when_listed(&self, listed: &dyn Fn()) -> Result<FolderReport, CordeliaError> {
            self.cycle_hooked(&Hooks {
                listed,
                ..Hooks::NONE
            })
        }

        /// One cycle, with `flushed` done each time a file's new text has
        /// been flushed and before the last look at what is there. It is
        /// given the name of the file that is being written.
        fn cycle_when_flushed(&self, flushed: &dyn Fn(&str)) -> FolderReport {
            self.cycle_hooked(&Hooks {
                flushed,
                ..Hooks::NONE
            })
            .unwrap()
        }

        /// The folder forgets what it had agreed, as it does when it stops
        /// syncing: a handler counts the change and forgets, under one
        /// hold of the lock.
        fn forgets(&self) {
            let db = self.st.db.lock().unwrap();
            self.st.sync_control.changed(&db);
            let folder = self.mem.display().to_string();
            sync_state::forget_folder(&db, &folder).unwrap();
        }

        /// The conflict file that the folder has written down as holding
        /// the text of `file`, if any.
        fn written_down(&self, file: &str) -> Option<String> {
            let folder = self.mem.display().to_string();
            let kept = self
                .st
                .sync_control
                .kept_beside(&folder, &self.channel, file);
            kept.map(|kept| kept.copy)
        }

        /// The other device writes `text` under `name` (or deletes it),
        /// having received what `st` holds, and `st` receives it.
        fn other_writes(&self, name: &str, text: Option<&str>) {
            deliver(&self.st, &self.other, &self.channel);
            let content = text.map_or(Value::Null, |t| Value::String(t.into()));
            let write = Write {
                key: name,
                content: &content,
                metadata: None,
                item_type: ITEM_TYPE,
                deleted: text.is_none(),
            };
            let db = self.other.db.lock().unwrap();
            entries::publish(&self.other, &db, &self.channel, &write).unwrap();
            drop(db);
            deliver(&self.other, &self.st, &self.channel);
        }

        /// The text of the channel's version of `name`, as `st` holds it.
        fn held(&self, name: &str) -> Option<String> {
            version(&self.st, &self.channel, name).map(|(_, _, text)| text)
        }
    }

    /// An entry from another device that arrives while a cycle runs, after
    /// the cycle has read the channel, and becomes the channel's version
    /// of the file, is not published over. The file waits, and the next
    /// cycle finds both changed: this device's text is kept as a conflict
    /// file and the channel's is taken. Before the check, the cycle
    /// published over the entry and the other device's text was in no
    /// file anywhere.
    #[test]
    fn an_entry_that_arrives_while_a_cycle_runs_is_not_published_over() {
        let p = Pair::new();
        p.file("notes.md", "one\n");
        assert_eq!(p.cycle().published, 1);

        p.file("notes.md", "mine\n");
        let report = p.cycle_with(&|| p.other_writes("notes.md", Some("theirs\n")));
        assert_eq!((report.published, report.conflicts), (0, 0));
        assert_eq!(p.held("notes.md").as_deref(), Some("theirs\n"));
        assert_eq!(p.read("notes.md").as_deref(), Some("mine\n"));

        let report = p.cycle();
        assert_eq!(
            (report.published, report.pulled, report.conflicts),
            (0, 1, 1)
        );
        assert_eq!(p.read("notes.md").as_deref(), Some("theirs\n"));
        assert_eq!(p.read("notes.conflict-abcd.md").as_deref(), Some("mine\n"));

        // The conflict file is a file like any other, and goes next.
        assert_eq!(p.cycle().published, 1);

        // The same for a delete made here, and nothing is deleted.
        std::fs::remove_file(p.mem.join("notes.md")).unwrap();
        let report = p.cycle_with(&|| p.other_writes("notes.md", Some("theirs again\n")));
        assert_eq!(report.published, 0);
        assert_eq!(p.held("notes.md").as_deref(), Some("theirs again\n"));
        p.cycle();
        assert_eq!(p.read("notes.md").as_deref(), Some("theirs again\n"));

        // With another device's entry beside the one that counts (it lost
        // a tie), an edit goes over the one that counts.
        p.file("tied.md", "mine\n");
        p.cycle();
        let mine = version(&p.st, &p.channel, "tied.md").unwrap().0;
        let hash = |st: &AppState, id: &str| -> Vec<u8> {
            let it = held(st, &p.channel).into_iter().find(|it| it.item_id == id);
            it.unwrap().content_hash
        };
        (0..)
            .find_map(|n| {
                let dir = p.mem.parent().unwrap().join(format!("tie{n}"));
                let third = another_device(&p.st, &dir, &p.channel);
                let id = write(
                    &third,
                    &p.channel,
                    "tied.md",
                    Value::String("theirs\n".into()),
                );
                (hash(&third, &id) < hash(&p.st, &mine)).then(|| deliver(&third, &p.st, &p.channel))
            })
            .unwrap();
        assert_eq!(version(&p.st, &p.channel, "tied.md").unwrap().0, mine);
        p.file("tied.md", "mine, edited\n");
        assert_eq!(p.cycle().published, 1);
        assert_eq!(p.held("tied.md").as_deref(), Some("mine, edited\n"));
    }

    /// A delete is a version of a file like any other. An edit made here
    /// is planned against it and published over it, since an edit beats a
    /// delete. The plan and the check have to agree that it is the entry
    /// planned against: if only one of them took a delete for "no entry",
    /// the edit would be held back for ever.
    #[test]
    fn an_edit_is_published_over_a_delete_it_was_planned_against() {
        let p = Pair::new();
        p.file("kept.md", "first\n");
        assert_eq!(p.cycle().published, 1);

        // The other device deletes the file. Here it is edited.
        p.other_writes("kept.md", None);
        p.file("kept.md", "edited here\n");
        let report = p.cycle();
        assert_eq!(report.published, 1, "{report:?}");
        assert_eq!(p.held("kept.md").as_deref(), Some("edited here\n"));
        assert_eq!(p.read("kept.md").as_deref(), Some("edited here\n"));
    }

    /// What section 9 of the decision record says of a device that waits
    /// for a key. After a removal the device that removes writes under the
    /// new key at once, so another device can hold an entry it cannot read
    /// yet. It passes that entry over. Where its writer had an earlier
    /// entry for the file, the unread one has taken its place, so what is
    /// read instead is the newest entry by any other writer.
    ///
    /// Five files, for five of the things it then does. An unchanged file
    /// for which an earlier text is read is taken back to that text, and
    /// what it held is kept beside it. The other four are published above
    /// the unread entry (a merged index, a file over a delete, an edit, a
    /// delete), and when the key arrives the entry does not count on this
    /// device. Its author would take what was published, by revision: that
    /// side is not run here, and the new key is put in place by hand, not
    /// by a removal. This is behaviour the released version has; the test
    /// states it, so that it changes on purpose.
    #[test]
    fn a_device_that_waits_for_a_key_plans_from_what_it_can_read() {
        use cordelia_storage::psk;
        let p = Pair::new();
        let index = crate::memory_md::INDEX_FILE;
        let (a_line, b_line, c_line, x_line) = (
            "- [A](a.md) — a\n",
            "- [B](b.md) — b\n",
            "- [C](c.md) — c\n",
            "- [X](x.md) — x\n",
        );

        // Five files that both devices agree on.
        // - `note.md` and the index: written here, then edited there. The
        //   index loses a line there and gains one.
        p.file("note.md", "one\n");
        p.file(index, &format!("{a_line}{x_line}"));
        // - `mine.md` and `gone.md`: written here, and not touched there.
        p.file("mine.md", "one\n");
        p.file("gone.md", "one\n");
        assert_eq!(p.cycle().published, 4);
        p.other_writes("note.md", Some("two\n"));
        p.other_writes(index, Some(&format!("{a_line}{b_line}")));
        // - `back.md`: written there, deleted here, written there again.
        p.other_writes("back.md", Some("one\n"));
        assert_eq!(p.cycle().pulled, 3);
        std::fs::remove_file(p.mem.join("back.md")).unwrap();
        assert_eq!(p.cycle().published, 1);
        p.other_writes("back.md", Some("two\n"));
        assert_eq!(p.cycle().pulled, 1);
        assert_eq!(p.read("back.md").as_deref(), Some("two\n"));

        // The other device moves to a new key, which this one has not got
        // yet, and edits each file under it.
        let was = psk::read_psk(&p.other.home_dir, &p.channel).unwrap();
        let key = [7u8; 32];
        let other_pk = p.other.identity.public_key();
        let now_at = |st: &AppState| {
            psk::rotate_psk(&st.home_dir, &p.channel, &key, "2026-10-03T00:00:00Z").unwrap();
            let db = st.db.lock().unwrap();
            channels::set_state(
                &db,
                &p.channel,
                2,
                &other_pk,
                2,
                &cordelia_crypto::sha256(&key),
            )
            .unwrap();
        };
        now_at(&p.other);
        p.other_writes("note.md", Some("three\n"));
        p.other_writes(index, Some(&format!("{a_line}{b_line}{c_line}")));
        p.other_writes("back.md", Some("three\n"));
        p.other_writes("mine.md", Some("two\n"));
        p.other_writes("gone.md", Some("two\n"));
        // This device holds each, and reads what is under it.
        assert_eq!(p.held("note.md").as_deref(), Some("one\n"));
        assert_eq!(
            p.held(index).as_deref(),
            Some(format!("{a_line}{x_line}").as_str())
        );
        assert_eq!(
            p.held("back.md").as_deref(),
            Some(""),
            "this device's delete"
        );
        assert_eq!(p.held("mine.md").as_deref(), Some("one\n"));
        assert_eq!(psk::read_psk(&p.st.home_dir, &p.channel).unwrap(), was);

        // It edits one of the two files whose entries here are still the
        // ones that were agreed, and deletes the other. A cycle runs.
        p.file("mine.md", "edited here\n");
        std::fs::remove_file(p.mem.join("gone.md")).unwrap();
        let report = p.cycle();
        assert_eq!(
            (report.published, report.pulled, report.conflicts),
            (4, 1, 1),
            "{report:?}"
        );
        // A file for which an earlier text is read goes back to that
        // text, and what the file held is kept beside it.
        assert_eq!(p.read("note.md").as_deref(), Some("one\n"));
        assert_eq!(p.read("note.conflict-abcd.md").as_deref(), Some("two\n"));
        // The other four are published, above the entry that could not be
        // read: the index, merged with the earlier text (which is neither
        // text: the line that was taken out there comes back); the file
        // for which a delete is read; the file that was edited here, for
        // which what was agreed is read; and a delete for the file that
        // was deleted here.
        let above = |name: &str, rev: u64, text: &str| {
            let (_, at, now) = version(&p.st, &p.channel, name).unwrap();
            assert_eq!((at, now.as_str()), (rev, text), "{name}");
        };
        let merged = format!("{a_line}{x_line}{b_line}");
        above(index, 4, &merged);
        above("back.md", 5, "two\n");
        above("mine.md", 3, "edited here\n");
        // A delete has no text.
        above("gone.md", 3, "");
        let files = |p: &Pair| -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(&p.mem)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        };
        let there = [
            index,
            "back.md",
            "mine.md",
            "note.conflict-abcd.md",
            "note.md",
        ];
        assert_eq!(files(&p), there);

        // The key arrives. The first file takes the newest entry, and the
        // conflict file stays (it is published as a file of its own).
        now_at(&p.st);
        let report = p.cycle();
        assert_eq!((report.published, report.pulled), (1, 1), "{report:?}");
        assert_eq!(p.read("note.md").as_deref(), Some("three\n"));
        assert_eq!(p.read("note.conflict-abcd.md").as_deref(), Some("two\n"));
        // For the other four, what this device published is the
        // channel's version, and what the other device wrote under the new
        // key does not count here.
        above(index, 4, &merged);
        above("back.md", 5, "two\n");
        above("mine.md", 3, "edited here\n");
        above("gone.md", 3, "");
        assert_eq!(p.read(index), Some(merged));
        // No file comes back and no second conflict file is made.
        assert_eq!(files(&p), there);
    }

    /// One file that fails does not stop the files after it. It is named
    /// in the folder's report with why, nothing more is done for it in
    /// that cycle, and the next cycle plans it again.
    #[test]
    fn a_file_that_fails_is_passed_over_and_the_rest_sync() {
        let p = Pair::new();
        for (name, text) in [("a.md", "a\n"), ("b.md", "b\n"), ("c.md", "c\n")] {
            p.other_writes(name, Some(text));
        }
        // A folder takes the second file's name once the cycle has read
        // what is there, so the file cannot be written.
        let in_the_way = p.mem.join("b.md");
        let report = p.cycle_with(&|| std::fs::create_dir(&in_the_way).unwrap());
        assert_eq!(p.read("a.md").as_deref(), Some("a\n"));
        assert_eq!(p.read("c.md").as_deref(), Some("c\n"), "the file after it");
        assert_eq!(report.pulled, 2, "{report:?}");
        let failed: Vec<&str> = report.failed.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(failed, ["b.md"], "{report:?}");
        assert!(!report.failed[0].error.is_empty(), "{report:?}");
        assert!(report.error.is_none(), "{report:?}");
        // No temporary file is left where the file could not go.
        let left: Vec<String> = std::fs::read_dir(&p.mem)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with('.'))
            .collect();
        assert!(left.is_empty(), "{left:?}");

        // While the folder is there the name takes no part: it is listed
        // as something that cannot sync, and is no failure.
        let report = p.cycle();
        assert_eq!((report.pulled, report.failed.len()), (0, 0), "{report:?}");
        assert_eq!(report.skipped, ["b.md"], "{report:?}");

        // With the folder gone, the next cycle writes the file.
        std::fs::remove_dir(&in_the_way).unwrap();
        let report = p.cycle();
        assert_eq!((report.pulled, report.failed.len()), (1, 0), "{report:?}");
        assert_eq!(p.read("b.md").as_deref(), Some("b\n"));
    }

    /// Where a file's first action fails, its others are not done. Here
    /// this device's text was to be kept beside the file before the
    /// channel's version was written over it. It could not be kept
    /// (something is in the way of the temporary file the copy is written
    /// through), so the file is left as it is, and the report says that it
    /// is the copy that failed.
    #[test]
    fn a_file_whose_text_cannot_be_kept_is_not_written_over() {
        let p = Pair::new();
        p.file("notes.md", "agreed\n");
        p.file("z.md", "z\n");
        assert_eq!(p.cycle().published, 2);
        p.other_writes("notes.md", Some("theirs\n"));
        p.other_writes("z.md", Some("theirs too\n"));
        p.file("notes.md", "mine\n");
        let copy = names::conflict_name("notes.md", "abcd");
        let in_the_way = p.mem.join(temporary_name(&copy));
        std::fs::create_dir(&in_the_way).unwrap();

        let report = p.cycle();
        assert_eq!(report.failed.len(), 1, "{report:?}");
        assert_eq!(report.failed[0].name, "notes.md");
        let why = &report.failed[0].error;
        let start = format!("the version here could not be kept beside it as {copy} (");
        assert!(why.starts_with(&start), "{why}");
        assert!(why.ends_with("), so the file is left as it is"), "{why}");
        assert_eq!(p.read("notes.md").as_deref(), Some("mine\n"));
        assert!(!p.mem.join(&copy).exists());
        // The file after it is synced all the same.
        assert_eq!(p.read("z.md").as_deref(), Some("theirs too\n"));
        assert_eq!((report.pulled, report.conflicts), (1, 0), "{report:?}");

        // With nothing in the way, the next cycle keeps the text and
        // takes the channel's.
        std::fs::remove_dir(&in_the_way).unwrap();
        let report = p.cycle();
        assert_eq!(
            (report.pulled, report.conflicts, report.failed.len()),
            (1, 1, 0),
            "{report:?}"
        );
        assert_eq!(p.read(&copy).as_deref(), Some("mine\n"));
        assert_eq!(p.read("notes.md").as_deref(), Some("theirs\n"));
    }

    /// A conflict file takes a name only if nothing is there. What is
    /// there and is not a text file that can be read (a file that is not
    /// text, a folder, a link) is not replaced: the next name is taken.
    #[test]
    fn a_conflict_file_replaces_nothing_that_is_there() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let at = |n: usize| match n {
            1 => "notes.conflict-abcd.md".to_string(),
            n => format!("notes.conflict-abcd-{n}.md"),
        };
        let the_copy = |_: &str| Ok(true);
        let free = |_: &str| Ok(Claim::Taken);
        let target =
            |text: &str| conflict_file(dir, "notes.md", "abcd", text, &the_copy, &free).unwrap();
        let write = |n: usize| ConflictFile::ToWrite(at(n));
        // Nothing there: the first name.
        assert_eq!(target("mine\n"), write(1));
        // A file that is not text has that name: it is left, and the next
        // name is taken.
        std::fs::write(dir.join(at(1)), [0xff, 0xfe, 0x00, 0x80]).unwrap();
        assert_eq!(target("mine\n"), write(2));
        // A folder has the next: the one after.
        std::fs::create_dir(dir.join(at(2))).unwrap();
        assert_eq!(target("mine\n"), write(3));
        // A link has that one, to a file with this very text. A link is
        // no copy: it is never synced, and what it points at may be
        // anywhere.
        std::fs::write(dir.join("elsewhere"), "mine\n").unwrap();
        std::os::unix::fs::symlink(dir.join("elsewhere"), dir.join(at(3))).unwrap();
        assert_eq!(target("mine\n"), write(4));
        // A link to nothing has the next.
        std::os::unix::fs::symlink(dir.join("nowhere"), dir.join(at(4))).unwrap();
        assert_eq!(target("mine\n"), write(5));
        // A file with the same text: it is the copy, and there is nothing
        // to write. Another text takes the name after it.
        std::fs::write(dir.join(at(5)), "mine\n").unwrap();
        assert_eq!(target("mine\n"), ConflictFile::Kept(at(5)));
        assert_eq!(target("other\n"), write(6));

        // But not if that file is from before this conflict: then the
        // text is kept again, under the next name.
        let fifth = at(5);
        let from_before = |name: &str| Ok(name != fifth);
        let again = conflict_file(dir, "notes.md", "abcd", "mine\n", &from_before, &free);
        assert_eq!(again.unwrap(), write(6));

        // A name that is in use otherwise is not free, though nothing is
        // there: the next is taken.
        let sixth = at(6);
        let in_use = |name: &str| {
            Ok(match name == sixth {
                true => Claim::InUse,
                false => Claim::Taken,
            })
        };
        let other = conflict_file(dir, "notes.md", "abcd", "other\n", &the_copy, &in_use);
        assert_eq!(other.unwrap(), write(7));

        // Once the settings have changed there is nothing to write.
        let stopped = |_: &str| Ok(Claim::Stopped);
        let none = conflict_file(dir, "notes.md", "abcd", "other\n", &the_copy, &stopped);
        assert_eq!(none.unwrap(), ConflictFile::Stopped);
    }

    /// The two names a file's text is kept under, first and second, with
    /// the tag these tests use.
    fn copies_of(file: &str) -> (String, String) {
        (
            names::conflict_name(file, "abcd"),
            names::conflict_name(file, "abcd-2"),
        )
    }

    /// A file with an extension like `.md` comes after its conflict files
    /// in a cycle, and one with none comes before them. Either way round a
    /// copy can be relied on first and removed afterwards, so the tests of
    /// the copy run both.
    const EITHER_ORDER: [&str; 2] = ["notes", "notes.md"];

    /// A text is kept in a conflict file that this folder has made and not
    /// yet agreed with the channel, or in a new one. A conflict file that
    /// has been agreed has been to the other devices, and a delete of it
    /// can be on its way back from one that did not know it would be
    /// relied on again. Taken for the copy, the text would be in no file.
    ///
    /// Where the file is handled before its conflict file, the conflict
    /// file would be relied on first and removed afterwards. Where it is
    /// handled after, the old copy has gone by then, and its name is not
    /// free: the folder had this text agreed under it when the cycle
    /// began.
    #[test]
    fn a_conflict_file_that_was_agreed_is_not_taken_for_the_copy() {
        for file in EITHER_ORDER {
            let p = Pair::new();
            let (first, second) = copies_of(file);
            p.file(file, "base\n");
            assert_eq!(p.cycle().published, 1);
            // Both devices edit. This device's text is kept beside the
            // file, and the copy is published: every device has it.
            p.file(file, "mine\n");
            p.other_writes(file, Some("theirs\n"));
            let report = p.cycle();
            assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
            assert_eq!(p.read(&first).as_deref(), Some("mine\n"));
            assert_eq!(p.cycle().published, 1);

            // On the other device the file is edited again and the copy
            // is deleted, as a conflict that is done with. Here,
            // meanwhile, the person has put the copy's text back in the
            // file.
            p.other_writes(file, Some("theirs again\n"));
            p.other_writes(&first, None);
            p.file(file, "mine\n");
            let report = p.cycle();
            assert_eq!((report.pulled, report.conflicts), (2, 1), "{report:?}");
            assert_eq!(p.read(file).as_deref(), Some("theirs again\n"));
            // The copy that had been agreed goes, as the other device
            // asked, and the text is in a copy made now, under the second
            // name.
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{file}");
            assert_eq!(p.read(&first), None, "{file}");
            // It is published as this device's.
            assert_eq!(p.cycle().published, 1, "{file}");
            assert_eq!(p.held(&second).as_deref(), Some("mine\n"), "{file}");
        }
    }

    /// The same while the other device's delete of the copy is still on
    /// its way. The copy is there, with the text, and the folder has
    /// agreed it: but it was written down for the conflict before, which
    /// ended when the file took that version, so it is not the copy of
    /// this one. When the delete arrives the old copy goes, and the text
    /// is still in a file.
    #[test]
    fn a_copy_from_before_is_not_the_copy_though_it_is_still_there() {
        for file in EITHER_ORDER {
            let p = Pair::new();
            let (first, second) = copies_of(file);
            p.file(file, "base\n");
            assert_eq!(p.cycle().published, 1);
            p.file(file, "mine\n");
            p.other_writes(file, Some("theirs\n"));
            p.cycle();
            assert_eq!(p.cycle().published, 1);

            // The other device writes the file again, and that arrives.
            // It deletes the copy, and that has not arrived yet.
            p.other_writes(file, Some("theirs again\n"));
            let delete = Write {
                key: &first,
                content: &Value::Null,
                metadata: None,
                item_type: ITEM_TYPE,
                deleted: true,
            };
            deliver(&p.st, &p.other, &p.channel);
            entries::publish(&p.other, &p.other.db.lock().unwrap(), &p.channel, &delete).unwrap();
            // Here, meanwhile, the copy's text is put back in the file.
            p.file(file, "mine\n");
            let report = p.cycle();
            assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
            assert_eq!(p.read(&first).as_deref(), Some("mine\n"), "{file}");
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{file}");

            // The delete arrives.
            deliver(&p.other, &p.st, &p.channel);
            p.cycle();
            assert_eq!(p.read(&first), None, "{file}");
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{file}");
            assert_eq!(p.read(file).as_deref(), Some("theirs again\n"));
        }
    }

    /// The same for a folder that has forgotten what it agreed (sync was
    /// turned off and on, say). The copy is there with the text, and no
    /// record says that the folder ever agreed it. What the folder wrote
    /// down of the copy is forgotten with the rest, and a copy that is
    /// not written down is not relied on.
    #[test]
    fn a_copy_from_before_is_not_the_copy_after_the_folder_forgets() {
        for file in EITHER_ORDER {
            let p = Pair::new();
            let (first, second) = copies_of(file);
            p.file(file, "base\n");
            assert_eq!(p.cycle().published, 1);
            p.file(file, "mine\n");
            p.other_writes(file, Some("theirs\n"));
            p.cycle();
            assert_eq!(p.cycle().published, 1);

            // The other device writes the file again and deletes the
            // copy: the delete has not arrived.
            p.other_writes(file, Some("theirs again\n"));
            let delete = Write {
                key: &first,
                content: &Value::Null,
                metadata: None,
                item_type: ITEM_TYPE,
                deleted: true,
            };
            deliver(&p.st, &p.other, &p.channel);
            entries::publish(&p.other, &p.other.db.lock().unwrap(), &p.channel, &delete).unwrap();
            // Here the folder forgets, and the copy's text is put back in
            // the file.
            p.forgets();
            p.file(file, "mine\n");
            p.cycle();
            assert_eq!(p.read(&first).as_deref(), Some("mine\n"), "{file}");
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{file}");

            // The delete arrives.
            deliver(&p.other, &p.st, &p.channel);
            p.cycle();
            assert_eq!(p.read(&first), None, "{file}");
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{file}");
            assert_eq!(p.read(file).as_deref(), Some("theirs again\n"));
        }
    }

    /// The same with no newer version of the file. The folder forgets, and
    /// the text is put back in a file that then differs from the version
    /// the channel has had all along. (With its records the folder would
    /// publish the text as an edit: there is a conflict only because it
    /// has forgotten.) The copy is this device's own, and it was published
    /// after that version arrived. It is still the copy of a conflict that
    /// is over, and it is not relied on.
    #[test]
    fn a_copy_of_a_conflict_that_is_over_is_not_the_copy() {
        for file in EITHER_ORDER {
            let p = Pair::new();
            let (first, second) = copies_of(file);
            p.file(file, "base\n");
            assert_eq!(p.cycle().published, 1);
            p.file(file, "mine\n");
            p.other_writes(file, Some("theirs\n"));
            p.cycle();
            assert_eq!(p.cycle().published, 1);

            // The other device deletes the copy: the delete has not
            // arrived.
            let delete = Write {
                key: &first,
                content: &Value::Null,
                metadata: None,
                item_type: ITEM_TYPE,
                deleted: true,
            };
            deliver(&p.st, &p.other, &p.channel);
            entries::publish(&p.other, &p.other.db.lock().unwrap(), &p.channel, &delete).unwrap();
            p.forgets();
            p.file(file, "mine\n");
            p.cycle();
            assert_eq!(p.read(file).as_deref(), Some("theirs\n"), "{file}");
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{file}");

            // The delete arrives.
            deliver(&p.other, &p.st, &p.channel);
            p.cycle();
            assert_eq!(p.read(&first), None, "{file}");
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{file}");
        }
    }

    /// A copy that the channel sends again is not the copy either. The
    /// folder had agreed a delete of its copy, and another device then
    /// published the copy again with the same text (a folder that has
    /// forgotten what it agreed publishes what it still has). That entry
    /// is from before this conflict, and a delete of it can be on its
    /// way: the text is kept under a name of its own.
    ///
    /// Where the file is handled after its conflict file, the copy has
    /// been written from the channel by then, and it is not the copy
    /// because the folder did not write it down for this conflict. Where
    /// it is handled before, nothing is under the name yet, and the name
    /// is not free because the channel has a text under it.
    #[test]
    fn a_copy_that_the_channel_sent_again_is_not_the_copy() {
        for (file, copy_first) in EITHER_ORDER
            .into_iter()
            .flat_map(|f| [(f, true), (f, false)])
        {
            let p = Pair::new();
            let (first, second) = copies_of(file);
            p.file(file, "base\n");
            assert_eq!(p.cycle().published, 1);
            p.file(file, "mine\n");
            p.other_writes(file, Some("theirs\n"));
            p.cycle();
            assert_eq!(p.cycle().published, 1);
            // The copy is deleted on the other device, and that is agreed
            // here. Then the other device has the copy again, with the
            // same text, and writes the file: in either order. Neither
            // makes it this device's copy, or one written down here.
            p.other_writes(&first, None);
            assert_eq!(p.cycle().pulled, 1);
            assert_eq!(p.read(&first), None);
            if copy_first {
                p.other_writes(&first, Some("mine\n"));
                p.other_writes(file, Some("theirs again\n"));
            } else {
                p.other_writes(file, Some("theirs again\n"));
                p.other_writes(&first, Some("mine\n"));
            }
            // Here, meanwhile, the text has been put back in the file.
            p.file(file, "mine\n");
            p.cycle();
            p.cycle();
            let at = format!("{file}, the copy sent first: {copy_first}");
            assert_eq!(p.read(file).as_deref(), Some("theirs again\n"), "{at}");
            assert_eq!(p.read(&first).as_deref(), Some("mine\n"), "{at}");
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{at}");

            // The other device deletes the copy it sent. The text is
            // still in a file.
            p.other_writes(&first, None);
            p.cycle();
            assert_eq!(p.read(&first), None, "{at}");
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{at}");
        }
    }

    /// A delete of the copy that arrives while the cycle runs, once the
    /// cycle has read the channel. What the cycle does with the copy
    /// itself was planned without the delete, and the copy is not relied
    /// on whenever the delete arrives: it was written down for the
    /// conflict before, and that ended when the file took the version.
    /// With the folder's records and without them (a folder that has
    /// forgotten has nothing written down either).
    #[test]
    fn a_copy_whose_delete_arrives_while_the_cycle_runs_is_not_the_copy() {
        for (file, forgets) in EITHER_ORDER
            .into_iter()
            .flat_map(|f| [(f, false), (f, true)])
        {
            let p = Pair::new();
            let (first, second) = copies_of(file);
            p.file(file, "base\n");
            assert_eq!(p.cycle().published, 1);
            p.file(file, "mine\n");
            p.other_writes(file, Some("theirs\n"));
            p.cycle();
            assert_eq!(p.cycle().published, 1);

            p.other_writes(file, Some("theirs again\n"));
            let delete = Write {
                key: &first,
                content: &Value::Null,
                metadata: None,
                item_type: ITEM_TYPE,
                deleted: true,
            };
            deliver(&p.st, &p.other, &p.channel);
            entries::publish(&p.other, &p.other.db.lock().unwrap(), &p.channel, &delete).unwrap();
            if forgets {
                p.forgets();
            }
            p.file(file, "mine\n");
            p.cycle_with(&|| deliver(&p.other, &p.st, &p.channel));
            p.cycle();
            let at = format!("{file}, forgotten: {forgets}");
            assert_eq!(p.read(&first), None, "{at}");
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{at}");
            assert_eq!(p.read(file).as_deref(), Some("theirs again\n"), "{at}");
        }
    }

    /// A copy is not written under a name that the folder has this very
    /// text agreed for. Here the copy was agreed, and the person has moved
    /// it over the file: the file holds the text, and nothing has the
    /// copy's name. The other device has written the file again and
    /// deleted the copy, and the delete arrives while the cycle runs. A
    /// copy written under the old name would be the agreed file again,
    /// unchanged, and the delete would remove it.
    #[test]
    fn a_copy_is_not_written_under_a_name_agreed_with_its_text() {
        for file in EITHER_ORDER {
            let p = Pair::new();
            let (first, second) = copies_of(file);
            p.file(file, "base\n");
            assert_eq!(p.cycle().published, 1);
            p.file(file, "mine\n");
            p.other_writes(file, Some("theirs\n"));
            p.cycle();
            assert_eq!(p.cycle().published, 1);

            p.other_writes(file, Some("theirs again\n"));
            let delete = Write {
                key: &first,
                content: &Value::Null,
                metadata: None,
                item_type: ITEM_TYPE,
                deleted: true,
            };
            deliver(&p.st, &p.other, &p.channel);
            entries::publish(&p.other, &p.other.db.lock().unwrap(), &p.channel, &delete).unwrap();
            std::fs::rename(p.mem.join(&first), p.mem.join(file)).unwrap();
            p.cycle_with(&|| deliver(&p.other, &p.st, &p.channel));
            p.cycle();
            p.cycle();
            assert_eq!(p.read(&first), None, "{file}");
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{file}");
            assert_eq!(p.read(file).as_deref(), Some("theirs again\n"), "{file}");
        }
    }

    /// A conflict name under which the channel has something that is no
    /// text (written through the API) is free, as it is for the plan: the
    /// copy is written there, and published over it.
    #[test]
    fn a_copy_takes_a_name_that_the_channel_has_no_text_under() {
        let p = Pair::new();
        let (first, _) = copies_of("notes.md");
        p.file("notes.md", "base\n");
        assert_eq!(p.cycle().published, 1);
        deliver(&p.st, &p.other, &p.channel);
        write(
            &p.other,
            &p.channel,
            &first,
            serde_json::json!({ "no": "text" }),
        );
        deliver(&p.other, &p.st, &p.channel);
        p.file("notes.md", "mine\n");
        p.other_writes("notes.md", Some("theirs\n"));
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
        assert_eq!(p.read(&first).as_deref(), Some("mine\n"));
        assert_eq!(p.cycle().published, 1);
        assert_eq!(p.held(&first).as_deref(), Some("mine\n"));
    }

    /// Where the channel cannot be read for the copy's entry, the folder's
    /// cycle ends, as for any failure that is not one file's. The copy is
    /// neither relied on nor made again, and the file is left as it is.
    #[test]
    fn the_cycle_ends_where_the_channel_cannot_be_read_for_the_copy() {
        let p = Pair::new();
        let (first, second) = copies_of("notes.md");
        p.file("notes.md", "base\n");
        assert_eq!(p.cycle().published, 1);
        p.file("notes.md", "mine\n");
        p.other_writes("notes.md", Some("theirs\n"));
        let in_the_way = p.mem.join(temporary_name("notes.md"));
        std::fs::create_dir(&in_the_way).unwrap();
        p.cycle();
        assert_eq!(p.cycle().published, 1);
        assert_eq!(p.read(&first).as_deref(), Some("mine\n"));
        std::fs::remove_dir(&in_the_way).unwrap();

        let rename = |from: &str, to: &str| {
            let db = p.st.db.lock().unwrap();
            db.execute_batch(&format!("ALTER TABLE {from} RENAME TO {to}"))
                .unwrap();
        };
        let report = p.try_cycle_with(&|| rename("items", "items_away")).unwrap();
        rename("items_away", "items");
        assert!(report.error.is_some(), "{report:?}");
        assert_eq!(report.pulled, 0, "{report:?}");
        assert_eq!(p.read("notes.md").as_deref(), Some("mine\n"));
        assert!(!p.mem.join(&second).exists());
        // With the channel readable again, the copy is the copy and the
        // file takes the channel's version.
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
        assert_eq!(p.read("notes.md").as_deref(), Some("theirs\n"));
        assert!(!p.mem.join(&second).exists());
    }

    /// A file that cannot take the channel's version has its text kept
    /// once, however many cycles pass: the copy that an earlier cycle made
    /// for this conflict is the copy, before it is published and after.
    /// When another version arrives, the text is kept once more: the copy
    /// from before could have been let go of on another device since.
    ///
    /// Something is in the way of the temporary file that the channel's
    /// version is written through, so the file can be read and not
    /// replaced, while its copy can be written.
    #[test]
    fn a_file_that_cannot_take_the_channels_version_is_kept_once() {
        for file in EITHER_ORDER {
            let p = Pair::new();
            let (first, second) = copies_of(file);
            let copies = |p: &Pair| -> Vec<String> {
                let mut names: Vec<String> = std::fs::read_dir(&p.mem)
                    .unwrap()
                    .map(|e| e.unwrap().file_name().into_string().unwrap())
                    .filter(|name| name.starts_with("notes.conflict-"))
                    .collect();
                names.sort();
                names
            };
            p.file(file, "base\n");
            assert_eq!(p.cycle().published, 1);
            p.file(file, "mine\n");
            p.other_writes(file, Some("theirs\n"));
            let in_the_way = p.mem.join(temporary_name(file));
            std::fs::create_dir(&in_the_way).unwrap();
            // The copy is made, then published, and then it has been
            // agreed: it is the copy all along.
            for cycle in 0..6 {
                let report = p.cycle();
                assert_eq!(report.failed.len(), 1, "cycle {cycle}: {report:?}");
                assert_eq!(report.pulled, 0, "cycle {cycle}: {report:?}");
                assert_eq!(copies(&p), std::slice::from_ref(&first), "{file}, {cycle}");
                assert_eq!(p.read(file).as_deref(), Some("mine\n"));
            }
            // The folder has written the copy down, for this file.
            let written_down = || p.written_down(file);
            assert_eq!(written_down().as_ref(), Some(&first), "{file}");
            // Another version arrives. The first copy is from before it,
            // so the text is kept again, once.
            p.other_writes(file, Some("theirs again\n"));
            let mut two = vec![first.clone(), second.clone()];
            two.sort();
            for cycle in 0..6 {
                p.cycle();
                assert_eq!(copies(&p), two, "{file}, cycle {cycle}");
            }
            assert_eq!(written_down().as_ref(), Some(&second), "{file}");
            // With nothing in the way the file takes the channel's
            // version, and nothing more is kept.
            std::fs::remove_dir(&in_the_way).unwrap();
            let report = p.cycle();
            assert_eq!((report.pulled, report.failed.len()), (1, 0), "{report:?}");
            assert_eq!(p.read(file).as_deref(), Some("theirs again\n"));
            assert_eq!(copies(&p), two, "{file}");
            for copy in copies(&p) {
                assert_eq!(p.read(&copy).as_deref(), Some("mine\n"));
            }
            // And the conflict is over: nothing is written down any more.
            assert_eq!(written_down(), None, "{file}");
        }
    }

    /// The copy of this conflict is taken for the copy only while it holds
    /// the text. Here the other device edits the copy, and that edit is
    /// held when the file comes to take the channel's version: the text
    /// is kept again, and the copy takes the other device's edit.
    #[test]
    fn a_copy_that_was_edited_elsewhere_is_not_the_copy() {
        for file in EITHER_ORDER {
            let p = Pair::new();
            let (first, second) = copies_of(file);
            p.file(file, "base\n");
            assert_eq!(p.cycle().published, 1);
            p.file(file, "mine\n");
            p.other_writes(file, Some("theirs\n"));
            let in_the_way = p.mem.join(temporary_name(file));
            std::fs::create_dir(&in_the_way).unwrap();
            p.cycle();
            assert_eq!(p.cycle().published, 1);
            assert_eq!(p.held(&first).as_deref(), Some("mine\n"));

            p.other_writes(&first, Some("edited there\n"));
            std::fs::remove_dir(&in_the_way).unwrap();
            let report = p.cycle();
            assert_eq!((report.pulled, report.conflicts), (2, 1), "{report:?}");
            assert_eq!(p.read(file).as_deref(), Some("theirs\n"));
            assert_eq!(p.read(&first).as_deref(), Some("edited there\n"), "{file}");
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{file}");
        }
    }

    /// A copy that an earlier cycle made for this conflict is the copy:
    /// the same text is not kept twice. Here the cycle that made it could
    /// not go on to take the channel's version, because the file was
    /// being written to. The next cycle finds the same text against the
    /// same version, and relies on the copy that is written down.
    #[test]
    fn a_conflict_file_not_yet_agreed_is_the_copy() {
        for file in EITHER_ORDER {
            let p = Pair::new();
            let (first, second) = copies_of(file);
            p.file(file, "base\n");
            assert_eq!(p.cycle().published, 1);
            p.file(file, "mine\n");
            p.other_writes(file, Some("theirs\n"));
            let report = p.cycle_with(&|| p.file(file, "being written\n"));
            assert_eq!((report.pulled, report.conflicts), (0, 1), "{report:?}");
            assert_eq!(p.read(&first).as_deref(), Some("mine\n"));

            p.file(file, "mine\n");
            let report = p.cycle();
            assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
            assert_eq!(p.read(file).as_deref(), Some("theirs\n"));
            assert_eq!(p.read(&first).as_deref(), Some("mine\n"), "{file}");
            assert!(!p.mem.join(&second).exists(), "{file}");
        }
    }

    /// Something that is not a file (a folder), under a name a memory file
    /// has, takes no part: nothing is written there, and the name is not
    /// taken for deleted, which would delete the file on every other
    /// device. It is listed where the channel has a file of that name,
    /// and nowhere else.
    #[test]
    fn a_name_that_a_folder_has_takes_no_part() {
        let p = Pair::new();
        p.file("mine.md", "mine\n");
        assert_eq!(p.cycle().published, 1);
        p.other_writes("theirs.md", Some("theirs\n"));
        p.other_writes("gone.md", Some("for a while\n"));
        p.other_writes("gone.md", None);
        // The file that was agreed is replaced by a folder; another folder
        // has the name of the entry that has just arrived; a third has a
        // name that is deleted in the channel, where no file could be
        // written anyway; a fourth has a name nothing else has.
        std::fs::remove_file(p.mem.join("mine.md")).unwrap();
        for name in ["mine.md", "theirs.md", "gone.md", "attic"] {
            std::fs::create_dir(p.mem.join(name)).unwrap();
        }
        let report = p.cycle();
        assert_eq!(
            (report.published, report.pulled, report.failed.len()),
            (0, 0, 0),
            "{report:?}"
        );
        let mut skipped = report.skipped.clone();
        skipped.sort();
        assert_eq!(skipped, ["mine.md", "theirs.md"], "{report:?}");
        // Not deleted in the channel.
        assert_eq!(p.held("mine.md").as_deref(), Some("mine\n"));
    }

    /// Whether a file name can be as long here as a file name usually can
    /// (255 bytes). A test that needs such names says so and passes where
    /// it cannot.
    fn long_names_fit(dir: &Path) -> bool {
        let probe = dir.join("p".repeat(255));
        let fits = std::fs::write(&probe, "").is_ok();
        let _ = std::fs::remove_file(&probe);
        if !fits {
            eprintln!("not run: this file system does not take a file name of 255 bytes");
        }
        fits
    }

    /// A file name may be as long as a file name can be. It is written
    /// through a temporary file whose name does not grow with it, and a
    /// version of it is kept under a conflict name that is cut to fit.
    #[test]
    fn a_file_with_the_longest_name_is_written_and_its_conflict_kept() {
        let long = format!("{}.md", "n".repeat(252));
        assert_eq!(long.len(), 255);
        assert!(names::is_safe_file_name(&long));
        let temporary = temporary_name(&long);
        assert!(
            temporary.starts_with('.') && temporary.len() < 40,
            "{temporary}"
        );
        assert_ne!(temporary, temporary_name("other.md"));

        let p = Pair::new();
        if !long_names_fit(&p.mem) {
            return;
        }
        p.other_writes(&long, Some("text\n"));
        let report = p.cycle();
        assert_eq!((report.pulled, report.failed.len()), (1, 0), "{report:?}");
        assert_eq!(p.read(&long).as_deref(), Some("text\n"));
        assert!(!p.mem.join(&temporary).exists());

        // Both edit it: this device's text is kept, and the file takes
        // the channel's.
        p.file(&long, "mine\n");
        p.other_writes(&long, Some("theirs\n"));
        let report = p.cycle();
        assert_eq!(
            (report.pulled, report.conflicts, report.failed.len()),
            (1, 1, 0),
            "{report:?}"
        );
        assert_eq!(p.read(&long).as_deref(), Some("theirs\n"));
        let copy = names::conflict_name(&long, "abcd");
        assert_eq!(p.read(&copy).as_deref(), Some("mine\n"));
    }

    /// A cycle's errors name the files of a folder that failed, each with
    /// its path and why, up to five, and count the rest. The folder's
    /// report lists the first hundred, and counts those after.
    #[test]
    fn test_files_that_failed_are_named_in_the_cycles_errors() {
        let memory = Path::new("/home/sam/.claude/projects/-home-sam/memory");
        let failed = |n: usize| -> Vec<FailedFile> {
            (0..n)
                .map(|i| FailedFile {
                    name: format!("f{i}.md"),
                    error: format!("why {i}"),
                })
                .collect()
        };
        assert!(failed_as_errors(memory, &[], 0).is_empty());
        assert_eq!(
            failed_as_errors(memory, &failed(1), 0),
            ["/home/sam/.claude/projects/-home-sam/memory/f0.md: why 0"]
        );
        assert_eq!(failed_as_errors(memory, &failed(5), 0).len(), 5);
        let six = failed_as_errors(memory, &failed(6), 0);
        assert_eq!(six.len(), 6);
        assert_eq!(
            six[5],
            "/home/sam/.claude/projects/-home-sam/memory: 1 more file could not be synced"
        );
        let eight = failed_as_errors(memory, &failed(8), 0);
        assert!(
            eight[5].ends_with("3 more files could not be synced"),
            "{eight:?}"
        );
        assert!(eight[4].ends_with("f4.md: why 4"), "{eight:?}");
        // Those the report only counted are counted here too.
        let counted = failed_as_errors(memory, &failed(8), 4);
        assert!(
            counted[5].ends_with("7 more files could not be synced"),
            "{counted:?}"
        );
        let few = failed_as_errors(memory, &failed(2), 1);
        assert_eq!(few.len(), 3, "{few:?}");
        assert!(few[2].ends_with("1 more file could not be synced"));

        let mut report = FolderReport::default();
        for i in 0..FAILED_FILES_KEPT + 3 {
            report.fail(&format!("f{i}.md"), "why".into());
        }
        assert_eq!(
            (report.failed.len(), report.failed_more),
            (FAILED_FILES_KEPT, 3)
        );
        assert_eq!(report.failed[FAILED_FILES_KEPT - 1].name, "f99.md");
    }

    /// A failure that is not one file's ends the folder's cycle, as any
    /// failure did before files were passed over. The file after it would
    /// meet it too: written with no record made of it, it would be taken
    /// for a change of this device's the next time. Here the folder's
    /// records cannot be written. The folder's report says why, with what
    /// the cycle had done by then.
    #[test]
    fn a_failure_that_is_not_a_files_ends_the_folders_cycle() {
        let p = Pair::new();
        p.other_writes("a.md", Some("a\n"));
        p.other_writes("b.md", Some("b\n"));
        let broken = p.try_cycle_with(&|| {
            let db = p.st.db.lock().unwrap();
            db.execute_batch("ALTER TABLE sync_files RENAME TO sync_files_away")
                .unwrap();
        });
        let report = broken.unwrap();
        let why = report.error.as_deref().unwrap_or_default();
        assert!(why.contains("sync_files"), "{report:?}");
        // The first file was written before its record failed, and is
        // counted. The second was not come to.
        assert_eq!((report.pulled, report.failed.len()), (1, 0), "{report:?}");
        assert_eq!(p.read("a.md").as_deref(), Some("a\n"));
        assert_eq!(p.read("b.md"), None);

        // With the records back, the next cycle finishes: the first file
        // is as the channel has it, and only needs recording.
        let db = p.st.db.lock().unwrap();
        db.execute_batch("ALTER TABLE sync_files_away RENAME TO sync_files")
            .unwrap();
        drop(db);
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (1, 0), "{report:?}");
        assert_eq!(p.read("b.md").as_deref(), Some("b\n"));
    }

    /// A publish that is refused for what the entry is fails for that file
    /// alone. Here a name's revisions are used up: a device holds an entry
    /// for it at the highest revision there is, so nothing can be written
    /// after it. The file is reported, and the file after it is published.
    #[test]
    fn a_name_whose_revisions_are_used_up_fails_alone() {
        let p = Pair::new();
        p.file("a.md", "one\n");
        p.file("b.md", "one\n");
        assert_eq!(p.cycle().published, 2);
        let limit = cordelia_core::protocol::MAX_REV;
        write_at(&p.other, &p.channel, "a.md", "at the limit\n", limit);
        deliver(&p.other, &p.st, &p.channel);
        assert_eq!(p.cycle().pulled, 1);

        p.file("a.md", "two\n");
        p.file("b.md", "two\n");
        let report = p.cycle();
        assert_eq!(report.published, 1, "{report:?}");
        assert_eq!(report.failed.len(), 1, "{report:?}");
        assert_eq!(report.failed[0].name, "a.md");
        assert!(
            report.failed[0].error.contains("revision limit"),
            "{report:?}"
        );
        assert_eq!(p.held("b.md").as_deref(), Some("two\n"));
        assert_eq!(p.held("a.md").as_deref(), Some("at the limit\n"));
    }

    /// A folder that can be listed and not looked into (its names can be
    /// read, and nothing about them) is an error, like a folder that
    /// cannot be read at all. Its files are not taken for deleted, which
    /// would delete them on every other device.
    #[test]
    fn a_folder_that_cannot_be_looked_into_deletes_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let p = Pair::new();
        p.file("a.md", "a\n");
        p.file("b.md", "b\n");
        assert_eq!(p.cycle().published, 2);

        let mode = |mode: u32| {
            std::fs::set_permissions(&p.mem, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        mode(0o444);
        if std::fs::symlink_metadata(p.mem.join("a.md")).is_ok() {
            // Nothing is closed to this user (root): there is no such
            // folder to test with.
            mode(0o755);
            eprintln!("not run: this user can look into any folder");
            return;
        }
        let closed = p.try_cycle_with(&|| {});
        mode(0o755);
        // The error names the entry that could not be looked at.
        let why = closed.unwrap_err().to_string();
        assert!(why.contains("a.md: ") || why.contains("b.md: "), "{why}");
        assert_eq!(p.held("a.md").as_deref(), Some("a\n"));
        assert_eq!(p.held("b.md").as_deref(), Some("b\n"));
        // Open again, there is nothing to do.
        let report = p.cycle();
        assert_eq!((report.published, report.pulled), (0, 0), "{report:?}");
    }

    /// A folder that has agreed files and goes while a cycle runs is not
    /// made again by a file that the cycle writes. Made again, it would
    /// hold that one file, and the next cycle would take every other file
    /// for deleted and delete them on every other device.
    #[test]
    fn a_folder_that_goes_during_a_cycle_is_not_made_again() {
        let p = Pair::new();
        p.file("a.md", "a\n");
        p.file("b.md", "b\n");
        assert_eq!(p.cycle().published, 2);
        p.other_writes("new.md", Some("new\n"));
        let away = p.mem.with_file_name("memory-away");
        let report = p.cycle_with(&|| std::fs::rename(&p.mem, &away).unwrap());
        assert_eq!((report.pulled, report.published), (0, 0), "{report:?}");
        let failed: Vec<&str> = report.failed.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(failed, ["new.md"], "{report:?}");
        assert!(!p.mem.exists(), "the folder is not made again");

        // The next cycle finds it gone, and says so. Nothing is deleted.
        let gone = p.try_cycle_with(&|| {}).unwrap_err().to_string();
        assert!(gone.contains("is gone"), "{gone}");
        assert_eq!(p.held("a.md").as_deref(), Some("a\n"));
        assert_eq!(p.held("b.md").as_deref(), Some("b\n"));

        // Back where it was, it syncs.
        std::fs::rename(&away, &p.mem).unwrap();
        let report = p.cycle();
        assert_eq!((report.pulled, report.published), (1, 0), "{report:?}");
        assert_eq!(p.read("new.md").as_deref(), Some("new\n"));
    }

    /// The same in a folder's first cycle, when it has agreed nothing yet:
    /// it was there when the cycle listed it, so a file the cycle writes
    /// does not make it again.
    #[test]
    fn a_folder_that_goes_during_its_first_cycle_is_not_made_again() {
        let p = Pair::new();
        p.file("a.md", "a\n");
        p.file("b.md", "b\n");
        p.other_writes("new.md", Some("new\n"));
        let away = p.mem.with_file_name("memory-away");
        let report = p.cycle_with(&|| std::fs::rename(&p.mem, &away).unwrap());
        // What it had read is published. What was to arrive is not
        // written, and the folder is not made.
        assert_eq!((report.published, report.pulled), (2, 0), "{report:?}");
        let failed: Vec<&str> = report.failed.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(failed, ["new.md"], "{report:?}");
        assert!(!p.mem.exists(), "the folder is not made again");
        // The next cycle finds it gone, and deletes nothing.
        let gone = p.try_cycle_with(&|| {}).unwrap_err().to_string();
        assert!(gone.contains("is gone"), "{gone}");
        assert_eq!(p.held("a.md").as_deref(), Some("a\n"));
    }

    /// A folder that was never there and has only ever agreed deletes is
    /// not a folder that has gone: nothing was in it. It is made when a
    /// file is to arrive. (A device that maps a name whose files had all
    /// been deleted has no memory folder for it.)
    #[test]
    fn a_folder_that_only_ever_agreed_deletes_is_not_gone() {
        let p = Pair::new();
        std::fs::remove_dir(&p.mem).unwrap();
        p.other_writes("was.md", Some("for a while\n"));
        p.other_writes("was.md", None);
        let report = p.cycle();
        assert_eq!((report.pulled, report.failed.len()), (0, 0), "{report:?}");
        assert!(!p.mem.exists());
        // The delete is recorded, and the next cycles are no error.
        p.cycle();
        p.other_writes("first.md", Some("first\n"));
        let report = p.cycle();
        assert_eq!((report.pulled, report.failed.len()), (1, 0), "{report:?}");
        assert_eq!(p.read("first.md").as_deref(), Some("first\n"));
    }

    /// A delete is not published for a file that is there again by the
    /// time the cycle comes to it.
    #[test]
    fn a_delete_is_not_published_for_a_file_that_is_back() {
        let p = Pair::new();
        p.file("a.md", "a\n");
        assert_eq!(p.cycle().published, 1);
        std::fs::remove_file(p.mem.join("a.md")).unwrap();
        let report = p.cycle_with(&|| p.file("a.md", "a\n"));
        assert_eq!(report.published, 0, "{report:?}");
        assert_eq!(p.held("a.md").as_deref(), Some("a\n"));
        // Gone for good, it is deleted.
        std::fs::remove_file(p.mem.join("a.md")).unwrap();
        assert_eq!(p.cycle().published, 1);
        assert_eq!(p.held("a.md").as_deref(), Some(""));
    }

    /// Nor is a delete published while anything has the file's name. It
    /// is asked of the folder's listing, so a folder there counts as much
    /// as a file. (Asked of the path, a folder would not: it cannot be
    /// read as a file.)
    #[test]
    fn a_delete_is_not_published_while_something_has_the_name() {
        let p = Pair::new();
        p.file("a.md", "a\n");
        assert_eq!(p.cycle().published, 1);
        std::fs::remove_file(p.mem.join("a.md")).unwrap();
        let report = p.cycle_with(&|| std::fs::create_dir(p.mem.join("a.md")).unwrap());
        assert_eq!(report.published, 0, "{report:?}");
        assert_eq!(p.held("a.md").as_deref(), Some("a\n"));
        // And the name takes no part while the folder is there.
        let report = p.cycle();
        assert_eq!(report.published, 0, "{report:?}");
        assert_eq!(report.skipped, ["a.md"], "{report:?}");
    }

    /// On a file system that folds case, a file renamed to another
    /// spelling of its name still answers for the name it had. The name
    /// it had is not in the folder's listing, so its delete is published,
    /// and the other devices do not keep a file that is no longer here.
    /// (Not run where the file system tells the two names apart: there
    /// the rename is a delete and a new file like any other.)
    #[test]
    fn a_file_renamed_to_another_spelling_has_its_old_name_deleted() {
        let p = Pair::new();
        p.file("Notes.md", "notes\n");
        if !p.mem.join("notes.md").exists() {
            eprintln!("not run: this file system tells Notes.md from notes.md");
            return;
        }
        assert!(lists(&p.mem, "Notes.md").unwrap());
        assert!(!lists(&p.mem, "notes.md").unwrap());
        assert_eq!(p.cycle().published, 1);
        std::fs::rename(p.mem.join("Notes.md"), p.mem.join("notes.md")).unwrap();
        let report = p.cycle();
        assert_eq!(report.published, 2, "{report:?}");
        assert_eq!(p.held("Notes.md").as_deref(), Some(""));
        assert_eq!(p.held("notes.md").as_deref(), Some("notes\n"));
    }

    /// A delete is published only from a folder that is there. One that
    /// goes while a cycle runs took its files with it, and that is no
    /// delete of any of them: the cycle ends, and says that the folder is
    /// gone. (A folder that goes while it is being listed has its names
    /// passed over as they go, and for a delete the same look catches it.
    /// Here it goes once it has been listed, with a file that was deleted
    /// before.)
    #[test]
    fn a_delete_is_not_published_from_a_folder_that_has_gone() {
        let p = Pair::new();
        p.file("a.md", "a\n");
        p.file("b.md", "b\n");
        assert_eq!(p.cycle().published, 2);
        std::fs::remove_file(p.mem.join("a.md")).unwrap();
        let away = p.mem.with_file_name("memory-away");
        let report = p.cycle_with(&|| std::fs::rename(&p.mem, &away).unwrap());
        assert_eq!(report.published, 0, "{report:?}");
        let why = report.error.as_deref().unwrap_or_default();
        assert!(why.contains("is gone"), "{report:?}");
        assert_eq!(p.held("a.md").as_deref(), Some("a\n"));
        // Back where it was, the file's delete is published.
        std::fs::rename(&away, &p.mem).unwrap();
        assert_eq!(p.cycle().published, 1);
        assert_eq!(p.held("a.md").as_deref(), Some(""));
        assert_eq!(p.held("b.md").as_deref(), Some("b\n"));
    }

    /// Nor from a folder that cannot be listed when the cycle comes to
    /// the delete: whether the file is back cannot be told.
    #[test]
    fn a_delete_is_not_published_from_a_folder_that_cannot_be_listed() {
        use std::os::unix::fs::PermissionsExt;
        let p = Pair::new();
        p.file("a.md", "a\n");
        assert_eq!(p.cycle().published, 1);
        std::fs::remove_file(p.mem.join("a.md")).unwrap();
        let mode = |mode: u32| {
            std::fs::set_permissions(&p.mem, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        mode(0o000);
        let open_to_all = std::fs::read_dir(&p.mem).is_ok();
        mode(0o755);
        if open_to_all {
            eprintln!("not run: this user can list any folder");
            return;
        }
        let report = p.cycle_with(&|| mode(0o000));
        mode(0o755);
        assert_eq!(report.published, 0, "{report:?}");
        assert!(report.error.is_some(), "{report:?}");
        assert_eq!(p.held("a.md").as_deref(), Some("a\n"));
        // Open again, the delete is published.
        assert_eq!(p.cycle().published, 1);
    }

    /// The folder is made by the cycle, once, before any file, and never
    /// by a write. One that the cycle made and that then goes is not made
    /// again by a file that arrives: it would hold only the files written
    /// from then on, and the next cycle would take the others for deleted.
    #[test]
    fn a_folder_that_the_cycle_made_and_that_goes_is_not_made_again() {
        let p = Pair::new();
        std::fs::remove_dir(&p.mem).unwrap();
        p.other_writes("a.md", Some("a\n"));
        p.other_writes("b.md", Some("b\n"));
        let report = p.cycle_with(&|| {
            // The cycle has made it by now, for the files that are to
            // arrive.
            assert!(p.mem.is_dir());
            std::fs::remove_dir(&p.mem).unwrap();
        });
        assert_eq!((report.pulled, report.failed.len()), (0, 2), "{report:?}");
        assert!(!p.mem.exists(), "the folder is not made again");
        // The next cycle makes it, and the files arrive.
        let report = p.cycle();
        assert_eq!((report.pulled, report.failed.len()), (2, 0), "{report:?}");
    }

    /// What a cycle did is counted before the record of it is written. A
    /// record that fails ends the folder's cycle, and the report then
    /// says what was done by then: an entry published, a file removed.
    /// (For a file that is written, see
    /// `a_failure_that_is_not_a_files_ends_the_folders_cycle`.)
    #[test]
    fn what_was_done_is_counted_though_its_record_fails() {
        // A cycle on a folder whose records cannot be written once it has
        // read them.
        let broken = |p: &Pair| -> FolderReport {
            let report = p
                .try_cycle_with(&|| {
                    let db = p.st.db.lock().unwrap();
                    db.execute_batch("ALTER TABLE sync_files RENAME TO sync_files_away")
                        .unwrap();
                })
                .unwrap();
            assert!(report.error.is_some(), "{report:?}");
            report
        };
        // An edit is published.
        let p = Pair::new();
        p.file("a.md", "a\n");
        let report = broken(&p);
        assert_eq!((report.published, report.pulled), (1, 0), "{report:?}");
        // A delete is published.
        let p = Pair::new();
        p.file("a.md", "a\n");
        assert_eq!(p.cycle().published, 1);
        std::fs::remove_file(p.mem.join("a.md")).unwrap();
        let report = broken(&p);
        assert_eq!((report.published, report.pulled), (1, 0), "{report:?}");
        // A file is removed.
        let p = Pair::new();
        p.file("a.md", "a\n");
        assert_eq!(p.cycle().published, 1);
        p.other_writes("a.md", None);
        let report = broken(&p);
        assert_eq!((report.published, report.pulled), (0, 1), "{report:?}");
        assert_eq!(p.read("a.md"), None);
        // A merged index is published.
        let p = Pair::new();
        let index = crate::memory_md::INDEX_FILE;
        p.file(index, "- [A](a.md) a\n");
        assert_eq!(p.cycle().published, 1);
        p.file(index, "- [A](a.md) a\n- [B](b.md) b\n");
        p.other_writes(index, Some("- [A](a.md) a\n- [C](c.md) c\n"));
        let report = broken(&p);
        assert_eq!((report.published, report.pulled), (1, 0), "{report:?}");
    }

    /// The rule for the copy, asked directly. A conflict file with the text
    /// is the copy only where the folder wrote it down for this file, this
    /// text and this version, and the channel's entry under its name is
    /// the one written down: the one that was there when the name was
    /// taken, or the one the folder published the copy as. An agreement
    /// for the file ends it, and so does a change of settings. A name is
    /// not taken while the channel has a text under it, or once the
    /// settings have changed.
    #[test]
    fn the_copy_is_the_one_the_folder_wrote_down() {
        let p = Pair::new();
        let copy = "notes.conflict-abcd.md";
        let text = |t: &str| Value::String(t.into());
        let version = write(&p.st, &p.channel, "notes.md", text("theirs\n"));
        let version = Some(version.as_str());
        let folder = p.mem.display().to_string();
        let none = HashMap::new();
        let with = |planned| Ctx {
            state: &p.st,
            dir: &p.mem,
            channel: &p.channel,
            prefix: "",
            tag: "abcd",
            folder: &folder,
            generation: p.st.sync_control.generation(),
            planned,
            agreed: &none,
            flushed: &|_| {},
            relied: RefCell::new(None),
        };
        let is = |planned, name: &str, text: &str| {
            is_the_copy(&with(planned), "notes.md", name, text).unwrap()
        };
        let take = || claim(&with(version), "notes.md", copy, "mine\n").unwrap();
        let under = || {
            let db = p.st.db.lock().unwrap();
            entries::current_of(&p.st, &db, &p.channel, copy)
                .unwrap()
                .map(|entry| entry.current.item_id)
        };

        // Nothing written down: no copy.
        assert!(!is(version, copy, "mine\n"));
        // Taken and written down, with nothing under its name then or now.
        assert_eq!(take(), Claim::Taken);
        assert!(is(version, copy, "mine\n"));
        // For this copy, this text, this version and this file, and no
        // other.
        assert!(!is(version, "notes.conflict-abcd-2.md", "mine\n"));
        assert!(!is(version, copy, "another\n"));
        assert!(!is(Some("ci_another"), copy, "mine\n"));
        assert!(!is(None, copy, "mine\n"));
        assert!(!is_the_copy(&with(version), "other.md", copy, "mine\n").unwrap());

        // Published by the folder, it is still the copy: the folder writes
        // down the entry it published it as.
        let mut report = FolderReport::default();
        let publish = Action::Publish("mine\n".into());
        let over = under();
        let done = apply(&with(over.as_deref()), copy, None, publish, &mut report);
        assert!(matches!(done, Ok(true)), "{done:?}");
        assert!(is(version, copy, "mine\n"));
        // An entry with another text that the folder publishes there is
        // not the copy's.
        let publish = Action::Publish("edited here\n".into());
        let over = under();
        let done = apply(&with(over.as_deref()), copy, None, publish, &mut report);
        assert!(matches!(done, Ok(true)), "{done:?}");
        assert!(!is(version, copy, "mine\n"));
        // Nor is this device's own entry with the text, where the folder
        // did not publish it for the copy.
        write(&p.st, &p.channel, copy, text("mine\n"));
        assert!(!is(version, copy, "mine\n"));
        // And the name is not taken while the channel has a text under
        // it, this device's own or not: nothing is written down.
        assert_eq!(take(), Claim::InUse);
        assert!(!is(version, copy, "mine\n"));

        // What the channel has under the name when it is taken is no
        // arrival: taken over a delete, it is the copy until something
        // else counts there, whatever that is.
        p.other_writes(copy, None);
        assert!(!is(version, copy, "mine\n"));
        assert_eq!(take(), Claim::Taken);
        assert!(is(version, copy, "mine\n"));
        entry_at(&p.st, &p.channel, copy, "mine\n", 9, true);
        assert!(!is(version, copy, "mine\n"));
        assert_eq!(take(), Claim::Taken);
        assert!(is(version, copy, "mine\n"));
        p.other_writes(copy, Some("mine\n"));
        assert!(!is(version, copy, "mine\n"));
        assert_eq!(take(), Claim::InUse);

        // A name that the folder had this very text agreed under is not
        // taken either.
        p.other_writes(copy, None);
        let had: HashMap<String, Agreed> = [(
            copy.to_string(),
            Agreed {
                hash: Some(Content::new("mine\n").hash),
                rev: 1,
            },
        )]
        .into();
        let agreed = Ctx {
            agreed: &had,
            ..with(version)
        };
        assert_eq!(
            claim(&agreed, "notes.md", copy, "mine\n").unwrap(),
            Claim::InUse
        );
        assert_eq!(
            claim(&agreed, "notes.md", copy, "other\n").unwrap(),
            Claim::Taken
        );

        // An agreement for the file ends it.
        assert_eq!(take(), Claim::Taken);
        assert!(is(version, copy, "mine\n"));
        let generation = p.st.sync_control.generation();
        record_agreed(
            &p.st,
            generation,
            &folder,
            &p.channel,
            "notes.md",
            (None, 1),
        )
        .unwrap();
        assert!(!is(version, copy, "mine\n"));

        // A name taken where the plan read no version of the file is the
        // copy for a plan that read none, and for no other.
        let read_none = claim(&with(None), "notes.md", copy, "mine\n");
        assert_eq!(read_none.unwrap(), Claim::Taken);
        assert!(is(None, copy, "mine\n"));
        assert!(!is(version, copy, "mine\n"));

        // A change of settings ends it, and the name is not taken by a
        // cycle that began before the change.
        assert_eq!(take(), Claim::Taken);
        let before = with(version);
        assert!(is_the_copy(&before, "notes.md", copy, "mine\n").unwrap());
        p.st.sync_control.changed(&p.st.db.lock().unwrap());
        assert!(!is_the_copy(&before, "notes.md", copy, "mine\n").unwrap());
        assert_eq!(
            claim(&before, "notes.md", copy, "mine\n").unwrap(),
            Claim::Stopped
        );
        assert_eq!(p.written_down("notes.md"), None);
    }

    /// What was kept beside a file is forgotten as soon as the file is
    /// replaced or removed, whether or not anything is then recorded: the
    /// file no longer holds the text, and a copy of it is the copy of a
    /// conflict that is over. Here the folder's records cannot be written
    /// (in a cycle, the settings can change between the write and the
    /// record, and then nothing is recorded either).
    #[test]
    fn what_was_kept_is_forgotten_once_the_file_is_replaced() {
        let index = crate::memory_md::INDEX_FILE;
        let replaced = [
            (
                "notes.md",
                Action::Pull {
                    text: "theirs\n".into(),
                    rev: 1,
                },
            ),
            ("notes.md", Action::RemoveFile { rev: 1 }),
            (index, Action::Merge("- [A](a.md) a\n".into())),
        ];
        for (file, action) in replaced {
            let p = Pair::new();
            p.file(file, "mine\n");
            let seen = Some(Content::new("mine\n").hash);
            let version = write(&p.st, &p.channel, file, Value::String("theirs\n".into()));
            let folder = p.mem.display().to_string();
            let none = HashMap::new();
            let ctx = Ctx {
                state: &p.st,
                dir: &p.mem,
                channel: &p.channel,
                prefix: "",
                tag: "abcd",
                folder: &folder,
                generation: p.st.sync_control.generation(),
                planned: Some(version.as_str()),
                agreed: &none,
                flushed: &|_| {},
                relied: RefCell::new(None),
            };
            let copy = names::conflict_name(file, "abcd");
            assert_eq!(claim(&ctx, file, &copy, "mine\n").unwrap(), Claim::Taken);
            assert!(is_the_copy(&ctx, file, &copy, "mine\n").unwrap(), "{file}");
            p.st.db
                .lock()
                .unwrap()
                .execute_batch("ALTER TABLE sync_files RENAME TO sync_files_away")
                .unwrap();
            let mut report = FolderReport::default();
            let done = apply(&ctx, file, seen, action, &mut report);
            assert!(matches!(done, Err(Failure::Folder(_))), "{file}: {done:?}");
            assert_ne!(p.read(file).as_deref(), Some("mine\n"), "{file}");
            assert_eq!(p.written_down(file), None, "{file}: {report:?}");
        }
    }

    /// What was kept beside a file lasts from one cycle to the next only
    /// while the file is still planned with a text to keep. Here the file
    /// cannot be replaced, so its text stays written down. Then the edit
    /// is undone by hand, so that the plan is to take the channel's
    /// version with nothing to keep; or a folder takes the file's name, so
    /// that it takes no part at all. And then the same text is put back.
    /// The copy is of a conflict that was over in between, and the text
    /// is kept again.
    #[test]
    fn what_was_kept_is_forgotten_once_there_is_nothing_to_keep() {
        for (file, undone) in EITHER_ORDER
            .into_iter()
            .flat_map(|f| [(f, true), (f, false)])
        {
            let p = Pair::new();
            let (first, second) = copies_of(file);
            let at = format!("{file}, undone: {undone}");
            p.file(file, "base\n");
            assert_eq!(p.cycle().published, 1);
            p.file(file, "mine\n");
            p.other_writes(file, Some("theirs\n"));
            let in_the_way = p.mem.join(temporary_name(file));
            std::fs::create_dir(&in_the_way).unwrap();
            assert_eq!(p.cycle().failed.len(), 1);
            assert_eq!(p.written_down(file).as_ref(), Some(&first), "{at}");

            if undone {
                p.file(file, "base\n");
                let report = p.cycle();
                assert_eq!(
                    (report.conflicts, report.failed.len()),
                    (0, 1),
                    "{report:?}"
                );
            } else {
                std::fs::remove_file(p.mem.join(file)).unwrap();
                std::fs::create_dir(p.mem.join(file)).unwrap();
                let report = p.cycle();
                assert_eq!(
                    (report.conflicts, report.failed.len()),
                    (0, 0),
                    "{report:?}"
                );
                std::fs::remove_dir(p.mem.join(file)).unwrap();
            }
            assert_eq!(p.written_down(file), None, "{at}");

            p.file(file, "mine\n");
            std::fs::remove_dir(&in_the_way).unwrap();
            p.cycle();
            p.cycle();
            assert_eq!(p.read(&first).as_deref(), Some("mine\n"), "{at}");
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{at}");
            assert_eq!(p.read(file).as_deref(), Some("theirs\n"), "{at}");
        }
    }

    /// What was kept beside a file is forgotten when a setting changes,
    /// and when a cycle forgets what a folder that no longer syncs had
    /// agreed: either may be the end of the conflict it was kept for.
    #[test]
    fn what_was_kept_is_forgotten_with_what_was_agreed() {
        for file in EITHER_ORDER {
            let p = Pair::new();
            let (first, second) = copies_of(file);
            p.file(file, "base\n");
            assert_eq!(p.cycle().published, 1);
            p.file(file, "mine\n");
            p.other_writes(file, Some("theirs\n"));
            let in_the_way = p.mem.join(temporary_name(file));
            std::fs::create_dir(&in_the_way).unwrap();
            assert_eq!(p.cycle().failed.len(), 1);
            assert_eq!(p.written_down(file).as_ref(), Some(&first), "{file}");

            // A setting changes, whichever it is. The text is kept again.
            p.st.sync_control.changed(&p.st.db.lock().unwrap());
            assert_eq!(p.written_down(file), None, "{file}");
            assert_eq!(p.cycle().failed.len(), 1);
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{file}");
            assert_eq!(p.written_down(file).as_ref(), Some(&second), "{file}");

            // A cycle forgets what folders that no longer sync had agreed.
            let generation = p.st.sync_control.generation();
            let folder = p.mem.display().to_string();
            let this = [(folder, p.channel.clone())];
            forget_other_folders(&p.st, &this, generation).unwrap();
            assert_eq!(p.written_down(file).as_ref(), Some(&second), "{file}");
            forget_other_folders(&p.st, &[], generation).unwrap();
            assert_eq!(p.written_down(file), None, "{file}");
        }
    }

    /// A text is kept once though the folder's records cannot be written.
    /// What is kept is written down before the copy is made, and not in
    /// the database: a copy that was made and could not be written down
    /// would be made again in every cycle.
    #[test]
    fn a_text_is_kept_once_though_no_record_can_be_written() {
        for file in EITHER_ORDER {
            let p = Pair::new();
            let (first, _) = copies_of(file);
            p.file(file, "base\n");
            assert_eq!(p.cycle().published, 1);
            p.file(file, "mine\n");
            p.other_writes(file, Some("theirs\n"));
            let db = |sql: &str| p.st.db.lock().unwrap().execute_batch(sql).unwrap();
            db("PRAGMA query_only = ON");
            for cycle in 0..4 {
                let report = p.cycle();
                assert!(report.error.is_some(), "{file}, cycle {cycle}: {report:?}");
                let copies = report_copies(&p);
                assert_eq!(
                    copies,
                    std::slice::from_ref(&first),
                    "{file}, {cycle}: {report:?}"
                );
            }
            assert_eq!(p.read(&first).as_deref(), Some("mine\n"), "{file}");
            assert_eq!(p.read(file).as_deref(), Some("theirs\n"), "{file}");
            // With the records back, the folder settles with that one copy.
            db("PRAGMA query_only = OFF");
            p.cycle();
            let report = p.cycle();
            assert_eq!(report.error, None, "{report:?}");
            assert_eq!(report_copies(&p), std::slice::from_ref(&first), "{file}");
        }
    }

    /// A copy is not written where its name cannot be looked at: nothing
    /// then says that the name is free. It is the file's own failure (the
    /// reason may be the name's own), and the file is left as it is.
    #[test]
    fn a_copy_is_not_written_where_its_name_cannot_be_looked_at() {
        use std::os::unix::fs::PermissionsExt;
        let p = Pair::new();
        p.file("notes.md", "base\n");
        assert_eq!(p.cycle().published, 1);
        p.file("notes.md", "mine\n");
        p.other_writes("notes.md", Some("theirs\n"));
        let mode = |mode: u32| {
            std::fs::set_permissions(&p.mem, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        mode(0o444);
        let open_to_all = std::fs::symlink_metadata(p.mem.join("notes.md")).is_ok();
        mode(0o755);
        if open_to_all {
            eprintln!("not run: this user can look into any folder");
            return;
        }
        let report = p.cycle_with(&|| mode(0o444));
        mode(0o755);
        assert_eq!((report.pulled, report.failed.len()), (0, 1), "{report:?}");
        let why = &report.failed[0].error;
        assert!(why.contains("cannot be looked at"), "{why}");
        assert_eq!(p.read("notes.md").as_deref(), Some("mine\n"));
        assert_eq!(p.written_down("notes.md"), None);
        // Open again, the text is kept and the version taken.
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
        assert_eq!(p.read("notes.conflict-abcd.md").as_deref(), Some("mine\n"));
    }

    /// A file is looked at again once its new text has been flushed, and
    /// is not replaced if it is no longer what the cycle saw: a flush
    /// takes long enough for an agent to write to the file meanwhile.
    #[test]
    fn a_file_is_not_replaced_if_it_changed_while_its_text_was_flushed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let nothing = || {};
        std::fs::write(dir.join("a.md"), "written meanwhile\n").unwrap();
        assert!(!write_atomic(dir, "a.md", "from the channel\n", &nothing, &|| false).unwrap());
        let there = std::fs::read_to_string(dir.join("a.md")).unwrap();
        assert_eq!(there, "written meanwhile\n");
        assert!(!dir.join(temporary_name("a.md")).exists());

        assert!(write_atomic(dir, "a.md", "from the channel\n", &nothing, &|| true).unwrap());
        let there = std::fs::read_to_string(dir.join("a.md")).unwrap();
        assert_eq!(there, "from the channel\n");
        // The look comes last: after the text is written whole, and after
        // whatever is done while it is flushed.
        let steps = RefCell::new(Vec::new());
        let whole = || std::fs::read_to_string(dir.join(temporary_name("b.md"))).unwrap();
        let flushed = || steps.borrow_mut().push(("flushed", whole()));
        let look = || {
            steps.borrow_mut().push(("look", whole()));
            true
        };
        assert!(write_atomic(dir, "b.md", "whole\n", &flushed, &look).unwrap());
        let whole = "whole\n".to_string();
        assert_eq!(
            *steps.borrow(),
            [("flushed", whole.clone()), ("look", whole)]
        );
    }

    /// The same in a cycle, for each thing a cycle writes: a file that
    /// arrives, a merged index, and a copy. Each is written to by an
    /// agent while its new text is flushed, and none is written over.
    #[test]
    fn nothing_written_while_a_text_is_flushed_is_written_over() {
        let agent_writes = |p: &Pair, file: &'static str, text: &'static str| {
            let path = p.mem.join(file);
            move |name: &str| {
                if name == file {
                    std::fs::write(&path, text).unwrap();
                }
            }
        };

        // A file that arrives.
        let p = Pair::new();
        p.file("notes.md", "base\n");
        assert_eq!(p.cycle().published, 1);
        p.other_writes("notes.md", Some("theirs\n"));
        let report = p.cycle_when_flushed(&agent_writes(&p, "notes.md", "written meanwhile\n"));
        assert_eq!((report.pulled, report.failed.len()), (0, 0), "{report:?}");
        assert_eq!(p.read("notes.md").as_deref(), Some("written meanwhile\n"));
        assert!(!p.mem.join(temporary_name("notes.md")).exists());
        // The next cycle plans with that write: it is kept, and the
        // channel's version taken.
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
        let copy = p.read("notes.conflict-abcd.md");
        assert_eq!(copy.as_deref(), Some("written meanwhile\n"));

        // A merged index.
        let p = Pair::new();
        let index = crate::memory_md::INDEX_FILE;
        p.file(index, "- [A](a.md) a\n");
        assert_eq!(p.cycle().published, 1);
        p.file(index, "- [A](a.md) a\n- [B](b.md) b\n");
        p.other_writes(index, Some("- [A](a.md) a\n- [C](c.md) c\n"));
        let meanwhile = "- [A](a.md) a\n- [B](b.md) b\n- [D](d.md) d\n";
        let report = p.cycle_when_flushed(&agent_writes(&p, index, meanwhile));
        assert_eq!((report.published, report.pulled), (1, 0), "{report:?}");
        assert_eq!(p.read(index).as_deref(), Some(meanwhile));
        // The next cycle merges what is there now.
        p.cycle();
        let merged = p.read(index).unwrap();
        for line in ["(a.md)", "(b.md)", "(c.md)", "(d.md)"] {
            assert!(merged.contains(line), "{line}: {merged}");
        }

        // A copy: something takes its name while its text is flushed.
        let p = Pair::new();
        p.file("notes.md", "base\n");
        assert_eq!(p.cycle().published, 1);
        p.file("notes.md", "mine\n");
        p.other_writes("notes.md", Some("theirs\n"));
        let copy = "notes.conflict-abcd.md";
        let report = p.cycle_when_flushed(&agent_writes(&p, copy, "someone else's\n"));
        assert_eq!((report.pulled, report.failed.len()), (0, 1), "{report:?}");
        let why = &report.failed[0].error;
        assert!(why.contains("no longer free"), "{why}");
        assert_eq!(p.read(copy).as_deref(), Some("someone else's\n"));
        assert_eq!(p.read("notes.md").as_deref(), Some("mine\n"));
        assert_eq!(p.written_down("notes.md"), None);
        // The next cycle keeps the text under the next name.
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
        let second = p.read("notes.conflict-abcd-2.md");
        assert_eq!(second.as_deref(), Some("mine\n"));
    }

    /// A file is not replaced if the copy that its text is kept in has
    /// gone by the time the file's new text is flushed: the text would
    /// then be in no file. Here the copy is one that an earlier cycle
    /// made, and one that this cycle has just made.
    #[test]
    fn a_file_is_not_replaced_once_the_copy_of_its_text_has_gone() {
        for (file, made_earlier) in EITHER_ORDER
            .into_iter()
            .flat_map(|f| [(f, false), (f, true)])
        {
            let p = Pair::new();
            let (first, _) = copies_of(file);
            let at = format!("{file}, made earlier: {made_earlier}");
            p.file(file, "base\n");
            assert_eq!(p.cycle().published, 1);
            p.file(file, "mine\n");
            p.other_writes(file, Some("theirs\n"));
            if made_earlier {
                let in_the_way = p.mem.join(temporary_name(file));
                std::fs::create_dir(&in_the_way).unwrap();
                assert_eq!(p.cycle().failed.len(), 1, "{at}");
                std::fs::remove_dir(&in_the_way).unwrap();
                assert_eq!(p.read(&first).as_deref(), Some("mine\n"), "{at}");
            }
            // Someone removes the copy while the file's new text is
            // flushed.
            let copy = p.mem.join(&first);
            let report = p.cycle_when_flushed(&|name| {
                if name == file {
                    std::fs::remove_file(&copy).unwrap();
                }
            });
            assert_eq!(report.pulled, 0, "{at}: {report:?}");
            assert_eq!(p.read(file).as_deref(), Some("mine\n"), "{at}");
            assert_eq!(p.read(&first), None, "{at}");
            // The next cycles keep the text again and take the version.
            p.cycle();
            p.cycle();
            assert_eq!(p.read(file).as_deref(), Some("theirs\n"), "{at}");
            let kept = report_copies(&p);
            assert!(!kept.is_empty(), "{at}");
            for copy in kept {
                assert_eq!(p.read(&copy).as_deref(), Some("mine\n"), "{at}");
            }
        }
    }

    /// The conflict files in the folder of `p`, by name. (The tag these
    /// tests use is shorter than a device's, so the adapter's own listing
    /// of conflict files does not show them.)
    fn report_copies(p: &Pair) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&p.mem)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.contains(".conflict-"))
            .collect();
        names.sort();
        names
    }

    /// A flush that fails because the volume has none is no failure, and
    /// one that was tried and failed is.
    #[test]
    fn test_a_volume_with_no_flush_is_told_from_a_flush_that_failed() {
        let failed = std::io::Error::from_raw_os_error;
        // EINVAL, and whatever the system calls unsupported: no flush
        // here.
        assert!(has_no_flush(&failed(22)));
        assert!(has_no_flush(&std::io::Error::from(
            std::io::ErrorKind::Unsupported
        )));
        if cfg!(target_os = "linux") {
            // ENOSYS and EOPNOTSUPP.
            assert!(has_no_flush(&failed(38)));
            assert!(has_no_flush(&failed(95)));
        }
        // EIO, ENOSPC and EACCES: a flush that failed.
        assert!(!has_no_flush(&failed(5)));
        assert!(!has_no_flush(&failed(28)));
        assert!(!has_no_flush(&failed(13)));
        // ENOTSUP and ENOTTY as a Mac numbers them.
        if cfg!(target_vendor = "apple") {
            assert!(has_no_flush(&failed(45)));
            assert!(has_no_flush(&failed(25)));
        }
    }

    /// A folder that goes once it has been listed is gone, and the cycle
    /// says so before it does anything. (While it is being listed, each
    /// name in it is passed over as it goes; here every file had been
    /// read.) Its files are not deleted on the other devices.
    #[test]
    fn a_folder_that_goes_once_it_is_listed_is_gone() {
        let p = Pair::new();
        p.file("a.md", "a\n");
        p.file("b.md", "b\n");
        assert_eq!(p.cycle().published, 2);
        p.other_writes("b.md", None);
        let away = p.mem.with_file_name("memory-away");
        let went = p.cycle_when_listed(&|| std::fs::rename(&p.mem, &away).unwrap());
        let why = went.unwrap_err().to_string();
        assert!(why.contains("is gone"), "{why}");
        // Nothing was recorded of the file whose delete had arrived, so
        // back where it was the folder takes the delete as any other.
        std::fs::rename(&away, &p.mem).unwrap();
        let report = p.cycle();
        assert_eq!((report.pulled, report.published), (1, 0), "{report:?}");
        assert_eq!(p.read("b.md"), None);
        assert_eq!(p.held("a.md").as_deref(), Some("a\n"));
    }

    /// A folder that has agreed nothing, was there when it was listed and
    /// has gone since, is not made: only one that was not there is. Made,
    /// it would be empty, and the files it was listed with would be
    /// published now and read as deleted in the next cycle.
    #[test]
    fn a_folder_that_was_listed_and_has_gone_is_not_made() {
        let p = Pair::new();
        p.file("a.md", "a\n");
        p.other_writes("new.md", Some("new\n"));
        let away = p.mem.with_file_name("memory-away");
        let report = p
            .cycle_when_listed(&|| std::fs::rename(&p.mem, &away).unwrap())
            .unwrap();
        assert_eq!((report.published, report.pulled), (1, 0), "{report:?}");
        assert!(!p.mem.exists(), "the folder is not made");
        // The next cycle finds it gone, and deletes nothing.
        let gone = p.try_cycle_with(&|| {}).unwrap_err().to_string();
        assert!(gone.contains("is gone"), "{gone}");
        assert_eq!(p.held("a.md").as_deref(), Some("a\n"));
    }

    /// A folder is not made once the settings have changed: the change
    /// may be the one that stops this folder syncing, and it would leave
    /// an empty folder behind.
    #[test]
    fn a_folder_is_not_made_once_the_settings_have_changed() {
        let p = Pair::new();
        std::fs::remove_dir(&p.mem).unwrap();
        p.other_writes("first.md", Some("first\n"));
        let report = p
            .cycle_when_listed(&|| p.st.sync_control.changed(&p.st.db.lock().unwrap()))
            .unwrap();
        assert!(report.stopped, "{report:?}");
        assert!(!p.mem.exists());
        // Under the settings as they are now, it is made.
        assert_eq!(p.cycle().pulled, 1);
    }

    /// A folder that cannot be made ends the folder's cycle with why.
    #[test]
    fn a_folder_that_cannot_be_made_ends_the_cycle() {
        use std::os::unix::fs::PermissionsExt;
        let p = Pair::new();
        std::fs::remove_dir(&p.mem).unwrap();
        p.other_writes("first.md", Some("first\n"));
        let above = p.mem.parent().unwrap().to_path_buf();
        let mode = |mode: u32| {
            std::fs::set_permissions(&above, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        mode(0o555);
        let failed = p.try_cycle_with(&|| {});
        let made = p.mem.exists();
        mode(0o755);
        if made {
            eprintln!("not run: this user can write in any folder");
            return;
        }
        assert!(failed.is_err(), "{failed:?}");
        assert_eq!(p.cycle().pulled, 1);
    }

    /// A file whose name is not text is not synced: no entry could have
    /// its name, and under the text made of it the file could not be
    /// found again. It is listed, and left alone. A folder with such a
    /// name is no file, and is not listed.
    #[test]
    fn a_file_whose_name_is_not_text_is_left_alone() {
        use std::os::unix::ffi::OsStrExt;
        let p = Pair::new();
        let name = std::ffi::OsStr::from_bytes(b"bad-\xff.md");
        if std::fs::write(p.mem.join(name), "x\n").is_err() {
            eprintln!("not run: this file system takes no such name");
            return;
        }
        std::fs::create_dir(p.mem.join(std::ffi::OsStr::from_bytes(b"dir-\xff"))).unwrap();
        p.file("good.md", "good\n");
        let report = p.cycle();
        assert_eq!(report.published, 1, "{report:?}");
        assert_eq!(report.skipped.len(), 1, "{report:?}");
        assert!(report.skipped[0].starts_with("bad-"), "{report:?}");
        assert_eq!(held(&p.st, &p.channel).len(), 1);
    }

    /// A file is written through a temporary file that is made anew, and
    /// never through a link that something has left under that name.
    #[test]
    fn a_file_is_not_written_through_a_link_at_its_temporary_name() {
        let p = Pair::new();
        let elsewhere = p.mem.with_file_name("elsewhere.md");
        std::fs::write(&elsewhere, "not to be touched\n").unwrap();
        std::os::unix::fs::symlink(&elsewhere, p.mem.join(temporary_name("a.md"))).unwrap();
        p.other_writes("a.md", Some("a\n"));
        let report = p.cycle();
        assert_eq!((report.pulled, report.failed.len()), (1, 0), "{report:?}");
        assert_eq!(p.read("a.md").as_deref(), Some("a\n"));
        let untouched = std::fs::read_to_string(&elsewhere).unwrap();
        assert_eq!(untouched, "not to be touched\n");
        assert!(
            std::fs::symlink_metadata(p.mem.join("a.md"))
                .unwrap()
                .is_file()
        );
    }

    /// A conflict name that was used before, for a copy that was deleted
    /// since, is free again, and the copy made under it is the copy of
    /// this conflict like any other that is not yet published: the folder
    /// has a record for the name, and it is of the delete, not of this
    /// text.
    #[test]
    fn a_copy_under_a_name_used_before_is_the_copy() {
        for file in EITHER_ORDER {
            let p = Pair::new();
            let (copy, second) = copies_of(file);
            p.file(file, "base\n");
            assert_eq!(p.cycle().published, 1);
            // A first conflict, resolved: the copy is published, then
            // deleted.
            p.file(file, "mine\n");
            p.other_writes(file, Some("theirs\n"));
            p.cycle();
            assert_eq!(p.cycle().published, 1);
            std::fs::remove_file(p.mem.join(&copy)).unwrap();
            assert_eq!(p.cycle().published, 1);
            // A second, and the cycle that keeps the text cannot go on.
            p.file(file, "mine again\n");
            p.other_writes(file, Some("theirs again\n"));
            let report = p.cycle_with(&|| p.file(file, "being written\n"));
            assert_eq!((report.pulled, report.conflicts), (0, 1), "{report:?}");
            assert_eq!(p.read(&copy).as_deref(), Some("mine again\n"));
            // The next cycle does not keep the same text under a second
            // name.
            p.file(file, "mine again\n");
            let report = p.cycle();
            assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
            assert!(!p.mem.join(&second).exists(), "{file}");
            assert_eq!(p.read(&copy).as_deref(), Some("mine again\n"), "{file}");
        }
    }

    /// A folder that has agreed nothing is made when its first file is to
    /// arrive: a device that maps a name has no memory folder for it until
    /// then.
    #[test]
    fn a_folder_that_has_agreed_nothing_is_made_by_its_first_file() {
        let p = Pair::new();
        std::fs::remove_dir(&p.mem).unwrap();
        p.other_writes("first.md", Some("first\n"));
        let report = p.cycle();
        assert_eq!((report.pulled, report.failed.len()), (1, 0), "{report:?}");
        assert_eq!(p.read("first.md").as_deref(), Some("first\n"));
    }

    /// Where the channel's index already has every line this device has,
    /// the merge is the channel's version, and the file takes it: nothing
    /// is published. (Published all the same, an index that could not be
    /// written to the file would be published again in every cycle.)
    #[test]
    fn an_index_the_channel_already_has_whole_is_taken_and_not_published() {
        let p = Pair::new();
        let index = crate::memory_md::INDEX_FILE;
        p.file(index, "- [A](a.md) a\n");
        assert_eq!(p.cycle().published, 1);
        // Both change it; the other device's has this device's new line
        // and one more.
        p.file(index, "- [A](a.md) a\n- [B](b.md) b\n");
        let theirs = "- [A](a.md) a\n- [B](b.md) b\n- [C](c.md) c\n";
        p.other_writes(index, Some(theirs));
        let (_, rev, _) = version(&p.st, &p.channel, index).unwrap();
        let report = p.cycle();
        assert_eq!((report.published, report.pulled), (0, 1), "{report:?}");
        assert_eq!(p.read(index).as_deref(), Some(theirs));
        let (_, now, text) = version(&p.st, &p.channel, index).unwrap();
        assert_eq!((now, text.as_str()), (rev, theirs));
        // And it is agreed: the next cycle has nothing to do.
        let report = p.cycle();
        assert_eq!((report.published, report.pulled), (0, 0), "{report:?}");

        // A line of this device's that the channel's lacks is merged in
        // and published, as before.
        p.file(index, &format!("{theirs}- [D](d.md) d\n"));
        p.other_writes(index, Some(&format!("{theirs}- [E](e.md) e\n")));
        let report = p.cycle();
        assert_eq!((report.published, report.pulled), (1, 0), "{report:?}");
        let merged = format!("{theirs}- [E](e.md) e\n- [D](d.md) d\n");
        assert_eq!(p.read(index), Some(merged));
    }

    /// A hidden file is no conflict file, as it is no memory file. The
    /// temporary file that 0.2.0-alpha.5 and earlier wrote a conflict file
    /// through is hidden, and its name reads as a conflict file's: one
    /// that such a version left behind is not listed as a conflict.
    #[test]
    fn test_a_hidden_file_is_no_conflict_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let left_behind = ".notes.conflict-0a1b2c3d.md.cordelia-tmp";
        assert!(names::is_conflict_name(left_behind));
        for name in ["notes.conflict-0a1b2c3d.md", left_behind, "notes.md"] {
            std::fs::write(dir.join(name), "x\n").unwrap();
        }
        let listed = conflict_files(dir);
        let only = dir.join("notes.conflict-0a1b2c3d.md").display().to_string();
        assert_eq!(listed, [only]);
    }

    /// The bookkeeping at the end of a cycle is done under the settings
    /// the cycle read, or not at all. A list of names worked out from
    /// settings that have since changed is not published, and nothing is
    /// forgotten on their say: a folder the new settings sync would not be
    /// among those the old ones kept.
    #[test]
    fn nothing_is_concluded_from_settings_that_have_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let st = state(tmp.path());
        membership::ensure_own_inbox(&st).unwrap();
        let personal = membership::personal_channel_id(&st).unwrap();
        let listed = |st: &AppState| -> usize {
            entries::current(st, &st.db.lock().unwrap(), &personal)
                .unwrap()
                .iter()
                .filter(|e| e.key.starts_with(SYNCING_PREFIX))
                .count()
        };
        let agreed = |st: &AppState| -> usize {
            let db = st.db.lock().unwrap();
            sync_state::load(&db, "/a/memory", "grp_x").unwrap().len()
        };
        sync_state::save(
            &st.db.lock().unwrap(),
            "/a/memory",
            "grp_x",
            "notes.md",
            (None, 1),
        )
        .unwrap();
        let mine: BTreeSet<String> = ["one".to_string()].into();

        let started = st.sync_control.generation();
        st.sync_control.changed(&st.db.lock().unwrap());
        exchange_names(&st, &personal, &mine, &mine, started).unwrap();
        forget_other_folders(&st, &[], started).unwrap();
        assert_eq!((listed(&st), agreed(&st)), (0, 1));

        let now = st.sync_control.generation();
        exchange_names(&st, &personal, &mine, &mine, now).unwrap();
        forget_other_folders(&st, &[], now).unwrap();
        assert_eq!((listed(&st), agreed(&st)), (1, 0));

        // Withdrawing, once sync is off, is the same: it is done under the
        // count read with that setting, or not at all, and says which.
        // Sync may be on again.
        let names = |st: &AppState| -> usize {
            let db = st.db.lock().unwrap();
            let all = entries::current(st, &db, &personal).unwrap();
            let list = all.iter().find(|e| e.key.starts_with(SYNCING_PREFIX));
            list.unwrap().current.content["names"]
                .as_array()
                .unwrap()
                .len()
        };
        st.sync_control.changed(&st.db.lock().unwrap());
        assert!(!withdraw(&st, now).unwrap());
        assert_eq!(names(&st), 1);
        assert!(withdraw(&st, st.sync_control.generation()).unwrap());
        assert_eq!(names(&st), 0);
    }
}
