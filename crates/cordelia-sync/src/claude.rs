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

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;

use cordelia_api::entries::{self, Write};
use cordelia_api::membership;
use cordelia_api::state::AppState;
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
    /// Why this folder did not sync this cycle.
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
            let mut r = result.unwrap_or_else(|e| {
                report.errors.push(format!("{label}: {e}"));
                FolderReport {
                    error: Some(e.to_string()),
                    ..Default::default()
                }
            });
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
    /// Neither a file nor a link (a folder, say), under a name a memory
    /// file could have. Something is there, so the name is not synced and
    /// is not taken for deleted. It is listed only where the channel has a
    /// file of that name.
    not_files: Vec<String>,
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(local),
        Err(e) => return Err(e),
    };
    let Local {
        files,
        skipped,
        too_large,
        not_files,
    } = &mut local;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue; // our temporary files, editor swap files, etc.
        }
        let meta = match std::fs::symlink_metadata(entry.path()) {
            Ok(meta) => meta,
            // Gone since the folder was listed.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if !meta.file_type().is_file() {
            if meta.file_type().is_symlink() {
                skipped.push(name);
            } else {
                not_files.push(name);
            }
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
///
/// The folder is made only where `create` says it may be: where it has
/// agreed nothing yet, so that a first file can arrive. A folder that has
/// agreed files was there when the cycle began. If it is not there now it
/// has gone since, and making it again would leave a folder with one file
/// in it, which the next cycle would read as every other file deleted.
fn write_atomic(dir: &Path, name: &str, text: &str, create: bool) -> std::io::Result<()> {
    if create {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = dir.join(temporary_name(name));
    std::fs::write(&tmp, text)
        .and_then(|()| std::fs::rename(&tmp, dir.join(name)))
        .inspect_err(|_| {
            // Not left behind where it could not be written whole, or the
            // file could not take its place.
            let _ = std::fs::remove_file(&tmp);
        })
}

/// The name of the temporary file that `name` is written through: hidden,
/// so that it is never read as a memory file, and short whatever the
/// length of `name`. A name may be as long as a file name can be, and a
/// temporary name made by adding to it would then be too long to create.
fn temporary_name(name: &str) -> String {
    let hash = cordelia_crypto::sha256(name.as_bytes());
    format!(".cordelia-tmp-{}", hex::encode(&hash[..8]))
}

/// A free conflict-file name for `key`, or `None` if this text is already
/// kept: a conflict file holds exactly it, and is one this folder made and
/// has not yet agreed with the channel (`agreed` says which names the
/// folder had agreed when the cycle began).
///
/// A conflict file that the folder has agreed is not taken for the copy,
/// whatever it holds. It has been to the other devices, and a delete or an
/// edit of it may be on its way back from one that did not know it would
/// be relied on again: the text would then be in no file. So the text is
/// kept again, under the next name.
///
/// A name is free only if nothing is there. A file that cannot be read as
/// text, a folder or a link under the name is not ours to replace: the
/// next name is tried.
fn conflict_target(
    dir: &Path,
    key: &str,
    tag: &str,
    text: &str,
    agreed: &dyn Fn(&str) -> bool,
) -> Option<String> {
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
                Ok(existing) if existing == text.as_bytes() && !agreed(&candidate) => {
                    return None;
                }
                _ => continue,
            },
            Ok(_) => continue,
            // Nothing there. (Where the folder cannot be looked into at
            // all, or has gone, the write that follows fails and says so.)
            Err(_) => return Some(candidate),
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
    sync_folder_between(state, dir, channel, prefix, tag, generation, &|| {})
}

/// [`sync_folder`], with `between` run once the folder and the channel
/// have been read and before anything is done about them. A cycle does
/// nothing there. A test does what another device may do in that gap.
fn sync_folder_between(
    state: &AppState,
    dir: &Path,
    channel: &str,
    prefix: &str,
    tag: &str,
    generation: u64,
    between: &dyn Fn(),
) -> Result<FolderReport, CordeliaError> {
    let folder = dir.display().to_string();
    let mut report = FolderReport::default();
    let Local {
        files: local,
        skipped,
        too_large,
        not_files,
    } = read_local(dir).map_err(|e| CordeliaError::Internal(format!("{}: {e}", dir.display())))?;
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
    // for deletes would remove the memory from every other device.
    if !agreed.is_empty() && !dir.is_dir() {
        return Err(CordeliaError::Internal(format!(
            "{} is gone (moved, removed, or its disk is not attached). Nothing was deleted \
             on your other devices. Bring it back; or unmap it, and map it again to fetch \
             the memory here",
            dir.display()
        )));
    }

    between();

    let mut keys: Vec<&String> = local
        .keys()
        .chain(remote.keys())
        .chain(agreed.keys())
        .collect();
    keys.sort();
    keys.dedup();

    for key in keys {
        if apart.contains(key) {
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
        };
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
                // ends here.
                Err(Failure::Folder(e)) => return Err(e),
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
    /// Where that is nothing at all, a write may make the folder
    /// ([`write_atomic`]); and a conflict file that is among them is not
    /// taken for a copy made now ([`conflict_target`]).
    agreed: &'a HashMap<String, Agreed>,
}

/// Why an action could not be done.
#[derive(Debug)]
enum Failure {
    /// This file could not be written, removed or published, for a reason
    /// of its own. The cycle goes on with the other files of the folder.
    File(String),
    /// A failure that is not this file's: the database, the channel's
    /// keys, this device's place in the channel. The folder's cycle ends.
    Folder(CordeliaError),
}

impl From<CordeliaError> for Failure {
    fn from(e: CordeliaError) -> Self {
        Failure::Folder(e)
    }
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
/// settings of `generation`. Nothing is recorded once the settings have
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
    sync_state::save(&db, folder, channel, key, agreed)
}

/// Publish `text` under `full_key`, or a delete if there is none, and
/// return its revision. `None`, with nothing published, if the settings
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
) -> Result<Option<u64>, CordeliaError> {
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
    Ok(Some(entries::publish(state, db, channel, &write)?.rev))
}

/// Apply one action. An error says whether it is this file's or the
/// folder's ([`Failure`]). Returns `false`, having made no change, in four
/// cases:
///
/// - The action would replace or remove the file, but the file changed
///   since it was scanned: an agent wrote to it mid-cycle. The next cycle
///   plans with that write, so it is published or kept as a conflict,
///   never overwritten.
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
        agreed,
    } = *ctx;
    let create = agreed.is_empty();
    let writes_file = matches!(
        action,
        Action::Pull { .. } | Action::RemoveFile { .. } | Action::SaveConflict(_)
    );
    if writes_file && state.sync_control.generation() != generation {
        return Ok(false);
    }
    let replaces_file = matches!(
        action,
        Action::Pull { .. } | Action::RemoveFile { .. } | Action::Merge(_)
    );
    if replaces_file && current_hash(dir, key) != seen {
        tracing::debug!(file = %dir.join(key).display(), "changed during the cycle; deferring");
        return Ok(false);
    }
    // The reason alone: the file is named by whoever reports it.
    let io = |e: std::io::Error| Failure::File(e.to_string());
    let full_key = format!("{prefix}{key}");
    // A publish that is refused for what the entry is (its name's
    // revisions are used up, say) is this file's failure. Any other is
    // the folder's.
    let publish = |text: Option<&str>| -> Result<Option<u64>, Failure> {
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
            Ok(Some(rev)) => {
                record(Some(Content::new(text).hash), rev)?;
                report.published += 1;
            }
            Ok(None) => return Ok(false),
            Err(Failure::Folder(CordeliaError::TooLarge { .. })) => {
                too_large(report);
                return Ok(false);
            }
            Err(e) => return Err(e),
        },
        Action::PublishDelete => {
            let Some(rev) = publish(None)? else {
                return Ok(false);
            };
            record(None, rev)?;
            report.published += 1;
        }
        Action::Pull { text, rev } => {
            write_atomic(dir, key, &text, create).map_err(io)?;
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
            let had_agreed = |name: &str| agreed.contains_key(name);
            if let Some(name) = conflict_target(dir, key, tag, &text, &had_agreed) {
                // Said in full: the file named in the report is there and
                // can be read, and it is the copy beside it that failed.
                write_atomic(dir, &name, &text, create).map_err(|e| {
                    Failure::File(format!(
                        "the version here could not be kept beside it as {name} ({e}), \
                         so the file is left as it is"
                    ))
                })?;
                tracing::info!(file = %dir.join(&name).display(), "kept this device's version of a conflicting edit");
            }
            report.conflicts += 1;
        }
        Action::Merge(text) => {
            // Published before the file is written: if the merged text does
            // not fit, the file stays as it was.
            match publish(Some(&text)) {
                Ok(Some(rev)) => {
                    write_atomic(dir, key, &text, create).map_err(io)?;
                    record(Some(Content::new(text).hash), rev)?;
                    report.published += 1;
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
            is_tombstone: false,
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
                is_tombstone: false,
                slot: Some(&slot),
                rev: Some(rev),
            },
        )
        .unwrap();
        assert!(stored);
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
            let generation = self.st.sync_control.generation();
            sync_folder_between(
                &self.st,
                &self.mem,
                &self.channel,
                "",
                "abcd",
                generation,
                between,
            )
        }

        fn cycle(&self) -> FolderReport {
            self.cycle_with(&|| {})
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
        let none_agreed = |_: &str| false;
        let target = |text: &str| conflict_target(dir, "notes.md", "abcd", text, &none_agreed);
        let at = |n: usize| match n {
            1 => "notes.conflict-abcd.md".to_string(),
            n => format!("notes.conflict-abcd-{n}.md"),
        };
        // Nothing there: the first name.
        assert_eq!(target("mine\n"), Some(at(1)));
        // A file that is not text has that name: it is left, and the next
        // name is taken.
        std::fs::write(dir.join(at(1)), [0xff, 0xfe, 0x00, 0x80]).unwrap();
        assert_eq!(target("mine\n"), Some(at(2)));
        // A folder has the next: the one after.
        std::fs::create_dir(dir.join(at(2))).unwrap();
        assert_eq!(target("mine\n"), Some(at(3)));
        // A link has that one, to a file with this very text. A link is
        // no copy: it is never synced, and what it points at may be
        // anywhere.
        std::fs::write(dir.join("elsewhere"), "mine\n").unwrap();
        std::os::unix::fs::symlink(dir.join("elsewhere"), dir.join(at(3))).unwrap();
        assert_eq!(target("mine\n"), Some(at(4)));
        // A link to nothing has the next.
        std::os::unix::fs::symlink(dir.join("nowhere"), dir.join(at(4))).unwrap();
        assert_eq!(target("mine\n"), Some(at(5)));
        // A file with the same text: it is the copy, and there is nothing
        // to write. Another text takes the name after it.
        std::fs::write(dir.join(at(5)), "mine\n").unwrap();
        assert_eq!(target("mine\n"), None);
        assert_eq!(target("other\n"), Some(at(6)));

        // But not if that file is one the folder has agreed with the
        // channel: then the text is kept again, under the next name.
        let fifth = at(5);
        let agreed = |name: &str| name == fifth;
        let again = conflict_target(dir, "notes.md", "abcd", "mine\n", &agreed);
        assert_eq!(again, Some(at(6)));
    }

    /// A text is kept in a conflict file that this folder has made and not
    /// yet agreed with the channel, or in a new one. A conflict file that
    /// has been agreed has been to the other devices, and a delete of it
    /// can be on its way back from one that did not know it would be
    /// relied on again. Taken for the copy, the text would be in no file.
    ///
    /// The file here has no extension, so it is handled before its
    /// conflict file in a cycle: the order in which the conflict file
    /// would be relied on first and removed afterwards.
    #[test]
    fn a_conflict_file_that_was_agreed_is_not_taken_for_the_copy() {
        let p = Pair::new();
        let (first, second) = ("notes.conflict-abcd", "notes.conflict-abcd-2");
        p.file("notes", "base\n");
        assert_eq!(p.cycle().published, 1);
        // Both devices edit. This device's text is kept beside the file,
        // and the copy is published: every device has it.
        p.file("notes", "mine\n");
        p.other_writes("notes", Some("theirs\n"));
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
        assert_eq!(p.read(first).as_deref(), Some("mine\n"));
        assert_eq!(p.cycle().published, 1);

        // On the other device the file is edited again and the copy is
        // deleted, as a conflict that is done with. Here, meanwhile, the
        // person has put the copy's text back in the file.
        p.other_writes("notes", Some("theirs again\n"));
        p.other_writes(first, None);
        p.file("notes", "mine\n");
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (2, 1), "{report:?}");
        assert_eq!(p.read("notes").as_deref(), Some("theirs again\n"));
        // The copy that had been agreed goes, as the other device asked.
        // The text is in a copy of its own, made now.
        assert_eq!(p.read(first), None);
        assert_eq!(p.read(second).as_deref(), Some("mine\n"));
    }

    /// A conflict file that this folder made and has not yet agreed is the
    /// copy: the same text is not kept twice. Here the cycle that made it
    /// could not go on to take the channel's version, because the file was
    /// being written to; the next cycle keeps the same text again.
    #[test]
    fn a_conflict_file_not_yet_agreed_is_the_copy() {
        let p = Pair::new();
        p.file("notes", "base\n");
        assert_eq!(p.cycle().published, 1);
        p.file("notes", "mine\n");
        p.other_writes("notes", Some("theirs\n"));
        let report = p.cycle_with(&|| p.file("notes", "being written\n"));
        assert_eq!((report.pulled, report.conflicts), (0, 1), "{report:?}");
        assert_eq!(p.read("notes.conflict-abcd").as_deref(), Some("mine\n"));

        p.file("notes", "mine\n");
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
        assert_eq!(p.read("notes").as_deref(), Some("theirs\n"));
        assert_eq!(p.read("notes.conflict-abcd").as_deref(), Some("mine\n"));
        assert!(!p.mem.join("notes.conflict-abcd-2").exists());
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
    /// records cannot be written.
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
        assert!(
            matches!(broken, Err(CordeliaError::Storage(_))),
            "{broken:?}"
        );
        // The first file was written before its record failed. The second
        // was not come to.
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
        assert!(closed.is_err(), "{closed:?}");
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

    /// A folder that has agreed nothing is made by the first file that
    /// arrives for it: a device that maps a name has no memory folder for
    /// it until then.
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

    /// A hidden file is no conflict file, as it is no memory file: a
    /// temporary file left by a write that was cut short has a hidden
    /// name, and for a conflict file it ends as a conflict file's does.
    #[test]
    fn test_a_hidden_file_is_no_conflict_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        for name in [
            "notes.conflict-0a1b2c3d.md",
            ".notes.conflict-0a1b2c3d.md",
            "notes.md",
        ] {
            std::fs::write(dir.join(name), "x\n").unwrap();
        }
        let listed = conflict_files(dir);
        assert_eq!(
            listed,
            [dir.join("notes.conflict-0a1b2c3d.md").display().to_string()]
        );
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
