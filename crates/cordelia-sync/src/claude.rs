//! The Claude Code adapter: keeps Claude Code memory folders in step with
//! Cordelia channels (decision 2026-09-30-agent-memory-sync §4.5).
//!
//! What syncs is declared, not assumed. A *mapping* says that Claude's
//! memory for a folder syncs under a name. The name is shared by all of a
//! person's devices: its channel comes from the person's secret and the
//! name (decision 2026-10-04 §2.2), so every device that maps the name
//! has the same channel for it, and none is made or joined. Home memory
//! is the mapping of the home directory: under the name `~` unless it is
//! given another, and `~` names nothing else.
//!
//! A device that follows no recovery phrase has no secret, and publishes
//! nothing: what is in its folders stays on the machine, and the cycle's
//! report says so (decision 2026-10-04 §5.2).
//!
//! **Only what is mapped syncs** (decision 2026-10-04 §10.1): a cycle's
//! targets are the mappings and nothing else. Other memory found on the
//! machine is listed in the cycle's report, with the name each would get,
//! so that a person can map it. What is found is never synced: no name is
//! held for it, and it is named to no other device. The adapter reads no
//! stored scope, no list of exclusions and no switch for home memory:
//! none of them says what syncs.
//!
//! A mapped folder syncs exactly the Claude Code folder named after it
//! ([`discover::claude_folder`]), never one chosen by reading transcripts:
//! a mapping cannot come to sync a different folder than the one declared.
//! Claude Code keeps one memory per git repository, so the folder to map
//! is the repository's main working tree ([`discover::memory_root`]).
//!
//! Each cycle reads a name's channel ([`publish::read_name`]: the slots
//! and who counts, of one moment), plans every file with [`crate::plan`]
//! and applies the actions. What it publishes goes through
//! [`publish::publish`], planned against the version it read: an edit is
//! written over that version, a merged index is merged with it, and a new
//! file has an empty chain (decision 2026-10-04 §7.3).
//! Files are written atomically (temporary file, then rename), never
//! through a symlink, and only under names [`crate::names`] accepts.
//!
//! A folder that has no record in its channel yet has its first cycle
//! there only once the channel was fetched from a relay (decision
//! 2026-10-04 §6): what another device has already sent then meets the
//! folder's files as on any first sync, and is not published a second
//! time as this device's own.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cordelia_api::at_relays::{self, Stands};
use cordelia_api::names as said_names;
use cordelia_api::person::{self, PersonError};
use cordelia_api::publish::{self, OtherSource, PlannedAgainst, Published, Write};
use cordelia_api::state::{AppState, Kept};
use cordelia_core::CordeliaError;
use cordelia_core::protocol::MAX_ENTRY_NAME_AND_VALUE_BYTES;
use cordelia_crypto::bech32::encode_channel_id;
use cordelia_crypto::entry::{Link, Value};
use cordelia_storage::atomic::write_atomic;
use cordelia_storage::person::State;
use cordelia_storage::{history, meta, sync_state};

use crate::discover::{self, Project};
use crate::memory_md;
use crate::names;
use crate::plan::{self, Action, Agreed, Content, Counting, Remote};
use cordelia_api::found;
use cordelia_api::types::SyncMapping;

/// Seconds between sync cycles.
pub const CYCLE_SECS: u64 = 5;

/// A memory file larger than this cannot fit in an entry, whatever is in
/// it, and is not read: it is reported as too large. It is the bound on a
/// text and its name together (decision 2026-10-04 §2.3). A file under it
/// may still not fit, since an entry also holds the file's name; that is
/// found before it is published ([`publish::fits`]), and reported the
/// same way. Either way the file is left alone and nothing is deleted
/// anywhere.
pub const MAX_FILE_BYTES: usize = MAX_ENTRY_NAME_AND_VALUE_BYTES;

/// How long a folder's project lookup (transcripts + git) is cached.
const PROJECT_CACHE: Duration = Duration::from_secs(300);

/// The name home memory syncs under unless it is given another.
pub const HOME_NAME: &str = "~";

/// What one cycle did for one folder.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FolderReport {
    /// Claude Code's folder for it (`~/.claude/projects/<slug>`).
    pub folder: String,
    /// The working directory it belongs to, when known.
    pub cwd: Option<String>,
    /// The name it syncs under.
    pub project: String,
    /// Always true: only a folder that is mapped syncs (decision
    /// 2026-10-04 §10.1). It is kept for whoever reads a report as an
    /// earlier version wrote it.
    pub mapped: bool,
    pub channel_id: Option<String>,
    /// Waiting for the name's channel to be fetched from a relay: the
    /// folder has no record there yet, and has its first cycle only once
    /// the channel was fetched (decision 2026-10-04 §6). It waits for a
    /// relay, and never for a device.
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
    /// (a text and its name may together be 60 KB). They are left as they
    /// are on this device, and the other devices keep the last version
    /// that did fit.
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

/// What one cycle did.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CycleReport {
    pub folders: Vec<FolderReport>,
    /// Folders found on this machine that hold memory, or may be sent
    /// some, and are not mapped: none of them syncs. Each says whether
    /// `cordelia sync map` would sync that folder, and why not where it
    /// would not; its directory is under `cwd` only where it would
    /// (decision 2026-10-04 §10.1).
    pub unmapped: Vec<found::Entry>,
    /// The folders in `unmapped` that have no name to sync under (neither
    /// home nor a git project).
    pub unsynced: Vec<String>,
    /// Always empty: nothing that is found syncs, so nothing is kept out
    /// of it. It is kept for whoever reads a report as an earlier version
    /// wrote it.
    pub excluded: Vec<String>,
    /// Names this person's other devices sync that this device does not,
    /// sorted.
    pub available: Vec<String>,
    pub errors: Vec<String>,
    /// Why nothing is published from this device, and nothing taken into
    /// its folders, where that is so (decision 2026-10-04 §5.2): it
    /// follows no recovery phrase yet, or it has stopped. Its folders are
    /// listed, and what is in them stays on the machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publishes_nothing: Option<String>,
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

/// Per-device sync settings, kept in node metadata: what a cycle reads.
/// The mappings say what syncs, and nothing else does (decision
/// 2026-10-04 §10.1): the stored scope, the list of exclusions and the
/// switch for home memory are not read.
#[derive(Debug, Clone, Default)]
pub struct Settings {
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
    /// Read from node metadata: `sync.claude.mappings` and `.dir`, with
    /// the count of changes to them.
    pub fn load(state: &AppState) -> Result<Self, CordeliaError> {
        let db = lock(state)?;
        let json = |key: &str| -> Result<Option<String>, CordeliaError> { meta::get(&db, key) };
        Ok(Self {
            mappings: json(meta::SYNC_CLAUDE_MAPPINGS)?
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default(),
            dir: json(meta::SYNC_CLAUDE_DIR)?,
            generation: state.sync_control.generation_under(&db),
        })
    }
}

/// The name a found project would sync under.
fn name_of(project: &Project) -> String {
    match project {
        Project::Home => HOME_NAME.to_string(),
        Project::Repo(remote) => remote.clone(),
    }
}

/// One folder to sync this cycle: a mapped one.
struct Target {
    /// Claude Code's folder.
    dir: PathBuf,
    /// The directory that is mapped.
    cwd: String,
    name: String,
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
        /// Whether git could be run to say which repository the
        /// directory is in. Where it could not, `root` is the directory
        /// itself, and a repository above it is not known of.
        git: bool,
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
    /// The directory it belongs to: the one its sessions started in, or
    /// the repository that directory is in.
    cwd: Option<PathBuf>,
    project: Option<Project>,
    /// Whether git could be run when the folder's transcripts were read.
    git: bool,
}

/// What the adapter read of a found folder's directory when it last
/// looked at the folder's transcripts ([`ClaudeAdapter::seen`]): it
/// answers [`found::would_map`] from that, so that a cycle asks git no
/// more often than it did. The directory it is asked about is the one the
/// lookup gave as holding the memory, so where git ran it is its own
/// root.
struct Looked {
    git: bool,
}

impl found::Machine for Looked {
    fn is_dir(&self, dir: &Path) -> bool {
        dir.is_dir()
    }

    fn memory_root(&self, dir: &Path) -> Option<PathBuf> {
        self.git.then(|| dir.to_path_buf())
    }
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
                let known = discover::memory_root_known(cwd);
                let git = known.is_some();
                let root = known.unwrap_or_else(|| cwd.clone());
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
                        git,
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
                Some(Seen::Own {
                    dir,
                    root,
                    project,
                    git,
                }) => Candidate {
                    dir,
                    cwd: Some(root),
                    project,
                    git,
                },
                Some(Seen::ByHand { cwd, project }) if holds_memory => Candidate {
                    dir: folder.dir,
                    cwd: Some(cwd),
                    project,
                    git: true,
                },
                // No transcripts: all that is known is that it holds memory.
                None if holds_memory => Candidate {
                    dir: folder.dir,
                    cwd: None,
                    project: None,
                    git: true,
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

    /// Run one sync cycle: the declared mappings, and nothing else.
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
        // A cycle takes its turn with a restore, a drop and the sweep of
        // local history, and holds it to the end. The database lock is
        // taken only inside it.
        let _turn = state.history.turn();
        let report = self.cycle_in_turn(state, settings);
        // What the cycle kept may have taken local history over its size.
        state.history.sweep_if_grown(chrono::Utc::now());
        report
    }

    /// The cycle itself, for the caller that holds the turn.
    fn cycle_in_turn(&mut self, state: &AppState, settings: Settings) -> CycleReport {
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
        // A device that follows no phrase has no secret, and one that has
        // stopped writes nothing: neither publishes, and its folders stay
        // as they are. They are listed all the same, and the report says
        // why nothing syncs.
        let stands = match lock(state).and_then(|db| at_relays::stands(&db).map_err(of_person)) {
            Ok(stands) => stands,
            Err(e) => {
                report.errors.push(format!("recovery phrase: {e}"));
                return report;
            }
        };
        // A device that took this version with what an earlier one held
        // is not added yet, and says so (decision 2026-10-04 §10.1).
        let moved_on = lock(state)
            .and_then(|db| cordelia_api::look::moved_on(&db))
            .unwrap_or(false);
        report.publishes_nothing = publishes_nothing(stands, moved_on);

        // What to sync: the declared mappings, and nothing else (decision
        // 2026-10-04 §10.1).
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
                cwd: mapping.folder.clone(),
                name: mapping.name.clone(),
            });
        }

        // Everything else on disk is listed, and never synced: it is no
        // target, no name is held for it, and nothing says of it to the
        // person's other devices that this one syncs it. Each is listed
        // with whether `cordelia sync map` would sync that folder, as the
        // one function says it ([`found::would_map`]).
        let declared: Vec<SyncMapping> = settings
            .mappings
            .iter()
            .map(|mapping| SyncMapping {
                folder: mapping.folder.clone(),
                name: mapping.name.clone(),
            })
            .collect();
        let candidates = self.candidates(&claimed);
        let against = found::Against {
            claude_dir: &self.claude_dir,
            // A node whose `HOME` is not set is given an empty path.
            home: (!self.home.as_os_str().is_empty()).then_some(self.home.as_path()),
            mappings: &declared,
        };
        for candidate in candidates {
            if candidate.project.is_none() {
                report.unsynced.push(candidate.dir.display().to_string());
            }
            let name = candidate.project.as_ref().map(name_of);
            let asked = found::Asked {
                folder: &candidate.dir,
                directory: candidate.cwd.as_deref(),
                name: name.as_deref(),
            };
            let looked = Looked { git: candidate.git };
            report
                .unmapped
                .push(found::Entry::of(&asked, &against, &looked));
        }

        // The names this device syncs are those its folders are mapped
        // to: each is held, and said in the personal channel, where its
        // folder is reached below. A name that is mapped stays one of
        // them whatever became of its folder.
        let wanted: BTreeSet<String> = settings
            .mappings
            .iter()
            .map(|mapping| mapping.name.clone())
            .collect();
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
            let folder = memory.display().to_string();
            let result = match stands {
                // Nothing syncs: the folder is listed, and left as it is.
                Stands::NoPhrase | Stands::Stopped(_) => Ok(FolderReport::default()),
                Stands::Applied => match name_channel(state, &folder, &target.name, generation) {
                    Ok(Channel::Ready(channel)) => {
                        syncing.push((folder, channel.clone()));
                        sync_folder(
                            state,
                            &memory,
                            &channel,
                            &target.name,
                            &self.device_tag,
                            generation,
                        )
                        .map(|mut r| {
                            r.channel_id = Some(channel);
                            r
                        })
                    }
                    Ok(Channel::Waits(channel)) => {
                        syncing.push((folder, channel.clone()));
                        Ok(FolderReport {
                            waiting: true,
                            channel_id: Some(channel),
                            ..Default::default()
                        })
                    }
                    Ok(Channel::Stopped) => Ok(FolderReport {
                        stopped: true,
                        ..Default::default()
                    }),
                    Err(e) => {
                        looked_up_all = false;
                        Err(e)
                    }
                },
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
            if r.error.is_none()
                && let Some(root) = self.moved_to(&target.cwd)
            {
                let moved = format!(
                    "Claude Code now keeps this folder's memory with {}, a git repository \
                     that contains it: unmap it, and map that instead",
                    root.display()
                );
                report.errors.push(format!("{}: {moved}", target.cwd));
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
            r.cwd = Some(target.cwd);
            r.project = target.name;
            r.mapped = true;
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
        // A device that publishes nothing has nothing more to conclude:
        // what its folders had agreed, and what it says of names, stand
        // as they are until it follows a phrase.
        if stands != Stands::Applied {
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
        // A file whose record a change could not carry is said until it
        // has met its channel (decision 2026-10-04 §4.2): once a folder
        // has a record of it there, it is said no more.
        let met = lock(state)
            .and_then(|db| cordelia_api::look::clear_not_carried_that_met(&db).map_err(of_person));
        if let Err(e) = met {
            report.errors.push(format!("files not carried: {e}"));
        }

        match exchange_names(state, &wanted, generation) {
            Ok(available) => report.available = available,
            Err(e) => report.errors.push(format!("names: {e}")),
        }
        report
    }
}

/// Why a device that stands so publishes nothing and takes nothing into
/// its folders (decision 2026-10-04 §4.3, §4.5, §5.2), or `None` for one
/// that has applied a statement and syncs. `moved_on` is whether the
/// device took this version with what an earlier one held: with no
/// phrase it is then not added yet (§10.1).
fn publishes_nothing(stands: Stands, moved_on: bool) -> Option<String> {
    let why = match stands {
        Stands::Applied => return None,
        Stands::NoPhrase => cordelia_api::look::no_phrase_says(moved_on).1,
        Stands::Stopped(State::Fork) => {
            "two changes were made apart: memory stays on this machine until it is settled \
             with the phrase (`cordelia settle`)."
        }
        Stands::Stopped(State::Removed) => {
            "this device was removed: memory stays on this machine. `cordelia init --new-key` \
             gives it a new key; it is then added as a new device."
        }
        Stands::Stopped(State::NotListed) => {
            "this device is not in the last change: memory stays on this machine until it is \
             added again from a device that is."
        }
        Stands::Stopped(_) => {
            "a change could not be opened on this device: memory stays on this machine until \
             it is added again from a device that has the change."
        }
    };
    Some(why.to_string())
}

/// A [`PersonError`] as the adapter reports it.
fn of_person(e: PersonError) -> CordeliaError {
    match e {
        PersonError::Storage(e) => e,
        other => CordeliaError::Internal(other.to_string()),
    }
}

/// What became of asking for the channel of a name that a folder syncs.
enum Channel {
    /// The channel's ID, as it is written: the folder syncs with it now.
    Ready(String),
    /// The folder has no record in this channel yet, and the channel has
    /// not been fetched from a relay: its first cycle there waits
    /// (decision 2026-10-04 §6).
    Waits(String),
    /// The settings have changed: nothing was held or said.
    Stopped,
}

/// The channel that the memory folder `folder` syncs the name `name`
/// with, under the settings of `generation`: the device holds the name,
/// so that its channel is fetched, and says in the personal channel that
/// it syncs it (decision 2026-10-04 §2.2, §16).
///
/// **A folder with no record in the channel yet waits** until the channel
/// was fetched from at least one relay, and from each other relay the
/// device is set up with that answers in time
/// ([`cordelia_api::state::OwnChannels::first_fetch_done`]). So a file
/// that another device has already sent meets the folder's as on any
/// first sync, and is not published a second time as this device's own.
///
/// The hold, the word and the look at the settings are made under one
/// hold of the database lock: nothing is held or said once a command has
/// changed what this device syncs.
fn name_channel(
    state: &AppState,
    folder: &str,
    name: &str,
    generation: u64,
) -> Result<Channel, CordeliaError> {
    let now = state.sync_control.now();
    let db = lock(state)?;
    if state.sync_control.generation_under(&db) != generation {
        return Ok(Channel::Stopped);
    }
    let id = match person::hold_name(&db, name, now) {
        Ok(id) => id,
        Err(PersonError::Derive(_)) => {
            return Err(CordeliaError::Validation(format!(
                "{name:?} is not a name in its one spelling ({:?}): unmap the folder, and map \
                 it under that",
                cordelia_core::sync_name::tidy(name)
            )));
        }
        Err(e) => return Err(of_person(e)),
    };
    if said_names::say(&db, &state.identity, name, now).map_err(of_person)? {
        state.own_channels.written();
    }
    let channel = encode_channel_id(&id).map_err(|e| CordeliaError::Crypto(e.to_string()))?;
    let met = sync_state::any(&db, folder, &channel)?;
    if !met && !state.own_channels.first_fetch_done(&id, Instant::now()) {
        return Ok(Channel::Waits(channel));
    }
    Ok(Channel::Ready(channel))
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

/// Sync was turned off: this device says of no name that it syncs it
/// (decision 2026-10-04 §16). (What its folders had agreed was forgotten
/// by the handler that turned sync off, which also took the words back:
/// this is for a word that could not be written then.)
///
/// `generation` is the settings count read with the setting that says sync
/// is off. Returns `false` if the settings have changed since: sync may be
/// on again, nothing was taken back, and whoever asked looks again.
/// Looking again when it had been taken back does no harm.
pub fn withdraw(state: &AppState, generation: u64) -> Result<bool, CordeliaError> {
    let db = lock(state)?;
    if state.sync_control.generation_under(&db) != generation {
        return Ok(false);
    }
    let now = state.sync_control.now();
    if said_names::unsay_all(&db, &state.identity, now).map_err(of_person)? > 0 {
        state.own_channels.written();
    }
    Ok(true)
}

/// Take back what this device says of each name that it syncs no longer,
/// and return the names this person's other devices sync that this one
/// does not (`wanted` is what it syncs, or is mapped to). Each device
/// speaks only for itself: a word is read only from the key that signed
/// it, of keys that count, and only where its name could be mapped.
///
/// A name that this device said it syncs and that is not in `wanted` is
/// mapped no longer, and the command that unmapped it could not write so:
/// the device says so no longer, and holds the name no more
/// ([`said_names::stop`]). Nothing is written if the settings are no
/// longer those of `generation`: the names were worked out from settings
/// that have since been replaced.
fn exchange_names(
    state: &AppState,
    wanted: &BTreeSet<String>,
    generation: u64,
) -> Result<Vec<String>, CordeliaError> {
    let me = state.identity.public_key();
    let now = state.sync_control.now();
    let db = lock(state)?;
    if state.sync_control.generation_under(&db) == generation {
        let said = said_names::said_here(&db, &state.identity).map_err(of_person)?;
        let mut written = false;
        for name in said.difference(wanted) {
            let stopped = said_names::stop(&db, &state.identity, name, now).map_err(of_person)?;
            if let Some(channel) = stopped {
                state.own_channels.forget_fetched(&channel);
            }
            written = true;
        }
        if written {
            state.own_channels.written();
        }
    }
    let mut others: BTreeSet<String> = BTreeSet::new();
    for listed in said_names::listed(&db).map_err(of_person)? {
        // Shown to the person, and inside a command to copy.
        let by_another = listed.by.iter().any(|key| *key != me);
        if by_another && cordelia_api::sync::valid_sync_name(&listed.name) {
            others.insert(listed.name);
        }
    }
    Ok(others.difference(wanted).cloned().collect())
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

/// Sync one memory folder with the channel of the name it syncs, under
/// the settings of `generation`. It stops, and says so in its report, as
/// soon as it finds that the settings have changed: the change may be the
/// one that stops this folder syncing. `agent` is the name the folder syncs
/// under, which the device holds: its channel is read and published in by
/// that name, and local history files its records by it. `channel` is
/// that channel's ID as it is written, which is what the folder's records
/// are kept by.
fn sync_folder(
    state: &AppState,
    dir: &Path,
    channel: &str,
    agent: &str,
    tag: &str,
    generation: u64,
) -> Result<FolderReport, CordeliaError> {
    let hooks = &Hooks::NONE;
    sync_folder_with(state, dir, channel, agent, tag, generation, hooks)
}

/// How one file is planned: [`plan::plan`].
type Planner = fn(
    &str,
    Option<&Content>,
    Option<&Remote>,
    Option<&Agreed>,
    &HashSet<String>,
    &Counting,
) -> Vec<Action>;

/// The places where a test puts something of its own into a cycle.
struct Hooks<'a> {
    /// How each file is planned. A test can plan as an earlier version
    /// did, to compare what the two come to.
    plan: Planner,
    /// Run once the folder has been listed, and before the cycle looks at
    /// whether it is still there. A cycle does nothing there. A test does
    /// what can happen to a folder while it is being listed.
    listed: &'a dyn Fn(),
    /// Run once the folder and the channel have been read and before
    /// anything is done about them. A cycle does nothing there either. A
    /// test does what another device may do in that gap.
    between: &'a dyn Fn(),
    /// Run each time a file's new text has been flushed, with the file's
    /// name, before the last look at what is there ([`write_atomic`]). A
    /// cycle does nothing there. A test does what an agent may do while
    /// a text is flushed.
    flushed: &'a dyn Fn(&str),
    /// Write down the lines and the memories this device deletes, and put
    /// a line back when its memory comes back ([`lines`]). Without it a
    /// test has a device of the version before that.
    lines: bool,
    /// Run just before the hold under which lines are put back. A cycle
    /// does nothing there. A test does what can arrive in that gap.
    before_hold: &'a dyn Fn(),
}

impl Hooks<'_> {
    /// What a cycle does: the plan, nothing at any of the four places,
    /// and the index line of a memory that comes back.
    const NONE: Hooks<'static> = Hooks {
        plan: plan::plan,
        listed: &|| {},
        between: &|| {},
        flushed: &|_| {},
        lines: true,
        before_hold: &|| {},
    };
}

/// [`sync_folder`], with `hooks` for a test.
fn sync_folder_with(
    state: &AppState,
    dir: &Path,
    channel: &str,
    agent: &str,
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

    // The channel, as one read gives it: each slot that holds a version,
    // and who counts, of one moment (decision 2026-10-04 §2.3). What the
    // plan asks of a version it asks of this read, and what is published
    // is published over the version that was read or not at all.
    let (remote, deleted, taken, agreed, index_read, counting) = {
        let db = lock(state)?;
        let read = publish::read_name(&db, agent).map_err(of_person)?;
        let own = state.identity.public_key();
        let mut remote: HashMap<String, Remote> = HashMap::new();
        let mut deleted: HashSet<String> = HashSet::new();
        // What each file was planned against: see `Ctx::planned`.
        let mut taken: HashMap<String, PlannedAgainst> = HashMap::new();
        // What stands beside the index's version: see `lines`.
        let mut beside = Vec::new();
        for slot in &read.slots {
            let Some(version) = &slot.current else {
                continue;
            };
            let name = version.name.as_str();
            if !names::is_safe_file_name(name) {
                tracing::warn!(key = %name, "ignoring entry whose name is not a safe file name");
                continue;
            }
            // Whatever is published under the name is published over
            // what the slot holds, a version of a memory file or not.
            taken.insert(name.to_string(), PlannedAgainst::what_is_in(slot));
            let content = match &version.value {
                Value::Text(text) => Some(Content::new(text.clone())),
                Value::Delete => {
                    deleted.insert(name.to_string());
                    None
                }
                // Not a memory file (bytes that are not a text, written
                // through the API under a file's name): no version of
                // one.
                Value::Other(_) => continue,
            };
            if name == memory_md::INDEX_FILE {
                beside = lines::beside(slot);
            }
            // The one entry of the version that a record is of.
            let one = publish::the_one_entry(version, &own).map_err(of_person)?;
            remote.insert(
                name.to_string(),
                Remote {
                    rev: version.rev,
                    content,
                    signer: one.author,
                    chain: one.chain.clone(),
                    version: version.clone(),
                },
            );
        }
        let agreed: HashMap<String, Agreed> = sync_state::load(&db, &folder, channel)?;
        let index_read = match hooks.lines {
            true => lines::read_index(&db, agent, beside)?,
            false => lines::IndexRead::default(),
        };
        (remote, deleted, taken, agreed, index_read, read.counting)
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

    // The files for which nothing is planned: see `lines`.
    let mut quiet: HashSet<String> = HashSet::new();
    let no_version = PlannedAgainst::NoVersion;
    let ctx_of = |key: &str| Ctx {
        state,
        dir,
        channel,
        tag,
        folder: &folder,
        agent,
        generation,
        planned: taken.get(key).unwrap_or(&no_version),
        over: remote.get(key),
        agreed: &agreed,
        flushed: hooks.flushed,
        relied: RefCell::new(None),
        lines: hooks.lines,
    };
    'files: for key in keys {
        if apart.contains(key) {
            // It takes no part, so nothing is kept beside it from one
            // cycle to the next either.
            state.sync_control.unkeep(&folder, channel, key);
            continue;
        }
        let seen = local.get(key).map(|c| c.hash);
        let actions = (hooks.plan)(
            key,
            local.get(key),
            remote.get(key),
            agreed.get(key),
            &deleted,
            &counting,
        );
        let ctx = ctx_of(key);
        // A minute of looking at a file's line starts again when a cycle
        // applies any action to the file, or to the index, at that moment
        // and whether or not the cycle reaches its end.
        if actions.is_empty() {
            quiet.insert(key.clone());
        } else if hooks.lines {
            let of_this = (key != memory_md::INDEX_FILE).then_some(key.as_str());
            state.sync_control.look_again(&folder, channel, of_this);
        }
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
    // Only a cycle that dealt with every file of the folder looks at its
    // lines: one ended by a failure that is not a file's asks nothing. (A
    // file that failed was dealt with. And a cycle that a change of
    // settings stopped makes no look: `look` asks that itself, under the
    // lock.) A failure here is the index's, reported as any file's is:
    // the folder's other files are done by then.
    if hooks.lines && report.error.is_none() {
        let cycle = lines::Cycle {
            local: &local,
            remote: &remote,
            agreed: &agreed,
            taken: &taken,
            quiet: &quiet,
            index: &index_read,
            before_hold: hooks.before_hold,
        };
        match lines::look(&ctx_of(memory_md::INDEX_FILE), &cycle, &mut report) {
            Ok(()) => {}
            Err(Failure::File(error)) => report.fail(memory_md::INDEX_FILE, error),
            Err(Failure::Folder(e)) => report.error = Some(e.to_string()),
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
    /// The channel's ID, as it is written: what the folder's records, and
    /// what the node keeps in memory of the folder, are kept by.
    channel: &'a str,
    tag: &'a str,
    folder: &'a str,
    /// The name the folder syncs under, which the device holds: its
    /// channel is read and published in by it, and a history record is
    /// filed by it.
    agent: &'a str,
    /// The settings count this cycle runs under.
    generation: u64,
    /// What the cycle read in this file's slot: the current version, with
    /// every entry held of it, or no version. An edit, a delete or a
    /// merge is published only over this: see `publish_over`.
    planned: &'a PlannedAgainst,
    /// That version as the plan read it, where it is a text or a delete:
    /// its revision, its text, and the signer and chain of its one entry.
    /// It is what a publish replaces, if the publish is made at all, and
    /// what a pull brings.
    over: Option<&'a Remote>,
    /// What the folder had agreed, for each file, when the cycle began.
    agreed: &'a HashMap<String, Agreed>,
    /// See [`Hooks::flushed`]: nothing, except in a test.
    flushed: &'a dyn Fn(&str),
    /// The conflict file that this file's text is kept in, and the hash
    /// of that text, once a step of the file's plan has kept the text or
    /// found it kept. The file is replaced only while that copy still
    /// holds the text (see `apply`).
    relied: RefCell<Option<(String, [u8; 32])>>,
    /// See [`Hooks::lines`]: `true` except in a test.
    lines: bool,
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
/// which file, against which version of the channel's, and what the
/// channel holds under the copy's name at that moment, which is never a
/// text. Where the folder then publishes the copy, it writes down what
/// the channel holds under the name once it has ([`note_published`]). A
/// copy is relied on only where
///
/// - what is written down is this copy, this text and this version, with
///   every entry held of it; and
/// - what the channel holds under the copy's name is what was written
///   down (or there is still no version).
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
///   `cordelia sync` command but `status` (what the node counts is the
///   request such a command sends, whoever sends it). The node takes a
///   command when what the command asks passes the node's checks, whether
///   or not the command then changes anything. A command that the node
///   refuses is not taken, and nor is one that the command line answers
///   without sending it, as the command line answers a `map` of a mapping
///   that is already declared;
/// - when the folder stops syncing, and when the node stops.
///
/// So a copy is relied on from one cycle to the next only while the file
/// has still to take the version the copy was made against, and only
/// until the node takes a settings command or stops. In every other case
/// a conflict file that holds the text is not relied on, and the text is
/// kept again under the first name that is free and can be taken. That
/// is one copy more than was needed where the conflict file was this
/// conflict's own. It is made once, in the first cycle that reaches the
/// file after the record has gone in one of the ways above, where the
/// file still cannot take the channel's version: after a restart, say,
/// or after a settings command that the node took. It is what keeps the
/// text where the conflict file is from an earlier conflict: that file
/// has been with the other devices, and a delete or an edit of it may be
/// on its way back from one that did not know the text would be relied
/// on again. The text would then be in no file.
fn is_the_copy(ctx: &Ctx, key: &str, name: &str, text: &str) -> Result<bool, CordeliaError> {
    let control = &ctx.state.sync_control;
    let Some(kept) = control.kept_beside(ctx.folder, ctx.channel, key) else {
        return Ok(false);
    };
    if kept.copy != name || kept.version != *ctx.planned || kept.hash != Content::new(text).hash {
        return Ok(false);
    }
    let db = lock(ctx.state)?;
    let now = publish::read(&db, ctx.agent, name).map_err(of_person)?;
    Ok(PlannedAgainst::what_is_in(&now.slot) == kept.under)
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
    let under = publish::read(&db, ctx.agent, name).map_err(of_person)?.slot;
    let is_a_text =
        |version: &cordelia_crypto::version::Version| matches!(version.value, Value::Text(_));
    if under.current.as_ref().is_some_and(is_a_text) {
        return Ok(Claim::InUse);
    }
    let kept = Kept {
        version: ctx.planned.clone(),
        copy: name.to_string(),
        hash,
        under: PlannedAgainst::what_is_in(&under),
    };
    ctx.state
        .sync_control
        .keep(&db, ctx.folder, ctx.channel, key, kept);
    Ok(Claim::Taken)
}

/// Write down that this folder has published `text` under `key`, and
/// that the channel holds `now` under that name since. Where `key` is a
/// copy that the folder wrote down, with this text, the copy is under
/// that now ([`is_the_copy`]): a copy that its own folder publishes is
/// still the copy.
fn note_published(ctx: &Ctx, key: &str, text: &str, now: &PlannedAgainst) {
    let hash = Content::new(text).hash;
    let control = &ctx.state.sync_control;
    control.kept_published(ctx.folder, ctx.channel, key, &hash, now);
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

/// Hash of the file as it is on disk right now (`None` if absent).
fn current_hash(dir: &Path, key: &str) -> Option<[u8; 32]> {
    std::fs::read(dir.join(key))
        .ok()
        .map(|bytes| cordelia_crypto::sha256(&bytes))
}

/// Whether the file is as the cycle saw it: the same bytes, or still not
/// there. A name that has come to hold something that cannot be read (a
/// directory, a link to nowhere) is not absent: what it holds could not
/// be kept, so it is not replaced. Nor is a name that cannot be looked
/// at: nothing says that it is free ([`cannot_be_looked_at`]).
fn as_seen(dir: &Path, key: &str, seen: Option<[u8; 32]>) -> bool {
    match seen {
        Some(hash) => current_hash(dir, key) == Some(hash),
        None => {
            let there = std::fs::symlink_metadata(dir.join(key));
            matches!(there, Err(e) if e.kind() == std::io::ErrorKind::NotFound)
        }
    }
}

/// Why a name that had no file when the cycle listed the folder cannot be
/// looked at now, if it cannot: the name is too long for the volume, say,
/// or the volume does not answer. Such a name is not taken for free, and
/// what arrives for it is not written: a file made under it since would be
/// replaced unseen. It is the file's failure, said in each cycle, where a
/// name that was only passed over would be passed over in silence.
fn cannot_be_looked_at(dir: &Path, key: &str) -> Option<String> {
    match std::fs::symlink_metadata(dir.join(key)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Some(format!(
            "its name cannot be looked at ({e}), so what arrived for it was not written"
        )),
        _ => None,
    }
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
    agreed: &Agreed,
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

/// What this device published under a file's name: what a record of it
/// keeps, and what the slot holds since.
struct Made {
    /// The entry's revision.
    rev: u64,
    /// The entry's chain: what it says it was written after.
    chain: Option<Vec<Link>>,
    /// What the slot holds now: the version just published, as this
    /// device's own entry.
    now: PlannedAgainst,
}

impl Made {
    /// What the folder records where its file holds the text of `hash`
    /// (`None` for no file) and the channel this entry, which `me` signed.
    fn agreed(self, hash: Option<[u8; 32]>, me: [u8; 32]) -> Agreed {
        Agreed {
            hash,
            rev: self.rev,
            signer: Some(me),
            chain: self.chain,
        }
    }
}

/// Publish `text` under the file's name `key`, or a delete if there is
/// none, through the one path for every entry that a node writes in a
/// name ([`publish::publish`]), and return what was made. `None`, with
/// nothing published, if the settings have changed since the cycle read
/// them, or what the slot holds is not what the plan read there
/// (`Ctx::planned`): another version, or the same one with another entry
/// held of it.
///
/// The entry says what it was written after (decision 2026-10-04 §7.3):
/// its chain is that of an entry written over the version the plan read,
/// with `merge` woven in where it is a merged index, and is empty over no
/// version. Room for it is kept in every entry, so nothing is ever left
/// out of it, and a text that fits is published whole or not at all.
///
/// Both looks are made on `db`, and the entry is published on it: the
/// caller holds the database lock for the whole of this, so neither can
/// change between the look and the publish. The pass that sends is woken
/// once the entry is in the store.
///
/// What the entry replaces went into local history before the lock was
/// taken ([`keep_channel`], [`keep_here`]), in a record that names the
/// revision the entry was then to have: `at`. Nothing is published where
/// the entry would now have another, so a record never names a revision
/// that its text was not replaced at.
fn publish_over(
    ctx: &Ctx,
    db: &rusqlite::Connection,
    key: &str,
    text: Option<&str>,
    at: Option<u64>,
    merge: Option<&OtherSource>,
) -> Result<Option<Made>, Failure> {
    let Ctx {
        state,
        channel,
        folder,
        agent,
        generation,
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
            key,
            "the settings changed since the cycle read them; not published"
        );
        return Ok(None);
    }
    if let Some(at) = at
        && publish::read(db, agent, key)
            .map_err(of_a_publish)?
            .slot
            .next
            != Some(at)
    {
        tracing::debug!(
            folder,
            channel,
            key,
            "an entry arrived under the file's name since its text was kept; left for the next cycle"
        );
        return Ok(None);
    }
    let write = Write {
        name: agent,
        file: key,
        value: text.map_or(Value::Delete, |text| Value::Text(text.to_string())),
        planned: ctx.planned.clone(),
        merge,
    };
    let now = state.sync_control.now();
    match publish::publish(db, &state.identity, &write, now).map_err(of_a_publish)? {
        Published::Made(_) => {}
        Published::Changed => {
            tracing::debug!(
                folder,
                channel,
                key,
                "the channel's version changed since the plan; left for the next cycle"
            );
            return Ok(None);
        }
        Published::OutOfReach => return Err(Failure::File(out_of_reach())),
    }
    // Something was written in a channel of the device's own: the pass
    // that sends is woken.
    state.own_channels.written();
    // The entry as the store holds it now: this device's own, and the
    // slot's current version, since it is one above everything there.
    let read = publish::read(db, agent, key).map_err(of_a_publish)?;
    let me = state.identity.public_key();
    let made = read.slot.current.as_ref().and_then(|version| {
        let own = version.entries.iter().find(|entry| entry.author == me)?;
        Some(Made {
            rev: version.rev,
            chain: own.chain.clone(),
            now: PlannedAgainst::what_is_in(&read.slot),
        })
    });
    made.map(Some).ok_or_else(|| {
        Failure::Folder(CordeliaError::Internal(format!(
            "the entry just published under {key} is not what its slot holds"
        )))
    })
}

/// What is said of a file whose name has no revision left under the
/// statement that the device has applied (decision 2026-10-04 §2.3).
fn out_of_reach() -> String {
    "no revision is left for this file until the next change of devices (`cordelia renew` makes \
     one), so it was not published"
        .to_string()
}

/// A text kept in local history ahead of the change that replaces it
/// (decision 2026-09-30 §4.5b), as a pending record. `None` with history
/// off, and where there was no text to keep. Dropped, it takes its record
/// with it: a record stays only if its change was made ([`settle`]).
type Ahead = Option<history::Pending>;

/// A failure of the publish itself, or of what is asked of the channel
/// ahead of it, as this file's or the folder's: one that is refused for
/// what the entry is (its name and its text are over their bound, say)
/// is this file's. Any other is the folder's: the device follows no
/// phrase any more, it has stopped, or it holds the name no longer.
fn of_a_publish(e: PersonError) -> Failure {
    match e {
        PersonError::Entry(why) => Failure::File(why.to_string()),
        e => Failure::Folder(of_person(e)),
    }
}

/// The revision the entry that this device is about to publish for `key`
/// will have, with history on; `None` with history off, where nothing
/// names it. A record of what the entry replaces names it, and the
/// publish is then made at this revision or not at all
/// ([`publish_over`]). A name with no revision left is this file's
/// failure, said before anything is kept for it.
fn revision_ahead(ctx: &Ctx, key: &str) -> Result<Option<u64>, Failure> {
    if ctx.state.history.store().is_none() {
        return Ok(None);
    }
    let db = lock(ctx.state)?;
    let read = publish::read(&db, ctx.agent, key).map_err(of_a_publish)?;
    match read.slot.next {
        Some(rev) => Ok(Some(rev)),
        None => Err(Failure::File(out_of_reach())),
    }
}

/// Why a change is not made where the text it would replace could not be
/// kept. The file is named by whoever reports it.
fn not_kept(why: impl std::fmt::Display) -> String {
    format!(
        "the text this would replace could not be kept in history ({why}), so nothing was changed"
    )
}

/// A device's entry, as a history record names it.
fn entry_of(device: &[u8; 32], rev: u64) -> history::Entry {
    let device =
        cordelia_crypto::bech32::encode_public_key(device).unwrap_or_else(|_| hex::encode(device));
    history::Entry { device, rev }
}

/// The channel's version `version`, as a history record names it: the
/// key that signed it, and its revision.
///
/// **A version that a device carried is named by the key in its first
/// link, and not by the carrier** (decision 2026-10-04 §16): a device
/// that applies a statement writes each version it holds again as its own
/// entry, and its chain then begins with the version's own hash and the
/// key that signed the entry it was carried from (§7.3). A chain names a
/// key by its first 16 bytes: the whole key is the one that the device
/// knows of with those ([`person::key_signed_as`]), and where it knows of
/// none, or of two, the record says the bytes it has.
fn written_by(ctx: &Ctx, version: &Remote) -> history::Entry {
    let carried_from = version.chain.as_deref().and_then(|chain| {
        let first = chain.first()?;
        let value = match &version.content {
            Some(content) => content.hash,
            None => [0u8; 32],
        };
        let of_itself = first.hash[..] == value[..first.hash.len()];
        (of_itself && first.signer != Link::signer_of(&version.signer)).then_some(first.signer)
    });
    let Some(signer) = carried_from else {
        return entry_of(&version.signer, version.rev);
    };
    let known = lock(ctx.state)
        .ok()
        .and_then(|db| person::key_signed_as(&db, &signer).ok().flatten());
    match known {
        Some(key) => entry_of(&key, version.rev),
        None => history::Entry {
            device: format!("a key that begins {}", hex::encode(signer)),
            rev: version.rev,
        },
    }
}

/// The change that a text was kept for has been made: its record stands.
/// One that cannot be made final is left pending, and is marked at the
/// next sweep, drop or start: the text is kept either way.
fn settle(ctx: &Ctx, ahead: Ahead) {
    if let (Some(pending), Some(store)) = (ahead, ctx.state.history.store())
        && let Err(error) = store.settle(pending)
    {
        tracing::warn!(%error, "a history record could not be made final");
    }
}

/// What [`keep_here`] found.
enum KeptHere {
    /// What was kept, if anything was to be.
    Ahead(Ahead),
    /// The file is no longer as the cycle saw it. Nothing was kept, and
    /// the change is left for the next cycle.
    Changed,
}

/// Keep the file as it is here, ahead of a change that replaces or removes
/// it: no kept copy, no replacement. The file is read again for it, and is
/// kept only if it is still what the cycle saw (`seen`).
///
/// Where no file is here, an arrival is noted, with no text, and for any
/// other change nothing: there is nothing to keep. A note that cannot be
/// written holds nothing up, since no text is lost without it.
fn keep_here(
    ctx: &Ctx,
    key: &str,
    seen: Option<[u8; 32]>,
    change: history::Change,
    replaced_by: history::Replacement,
) -> Result<KeptHere, Failure> {
    let Some(store) = ctx.state.history.store() else {
        return Ok(KeptHere::Ahead(None));
    };
    let text = match seen {
        None => None,
        Some(hash) => {
            let bytes = match std::fs::read(ctx.dir.join(key)) {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(KeptHere::Changed);
                }
                Err(e) => return Err(Failure::File(not_kept(e))),
            };
            if cordelia_crypto::sha256(&bytes) != hash {
                return Ok(KeptHere::Changed);
            }
            // The cycle read these bytes as text.
            Some(String::from_utf8(bytes).map_err(|e| Failure::File(not_kept(e)))?)
        }
    };
    let arrives = matches!(change, history::Change::Pulled) && text.is_none();
    if text.is_none() && !arrives {
        return Ok(KeptHere::Ahead(None));
    }
    let agreed = ctx.agreed.get(key).filter(|a| a.hash.is_some());
    let whose = history::Whose::Here {
        agreed: agreed.map(|a| a.rev),
    };
    let about = history::About {
        at: String::new(),
        agent: ctx.agent.to_string(),
        folder: ctx.folder.to_string(),
        file: key.to_string(),
        change: if arrives {
            history::Change::Arrived
        } else {
            change
        },
        kept: text.as_deref().map(|t| history::kept(whose, t)),
        replaced_by,
        // The file here was the version this device had agreed, and what
        // takes its place was written after it.
        behind: matches!(change, history::Change::Pulled)
            && seen.is_some()
            && agreed.is_some_and(|a| a.hash == seen),
    };
    match store.keep(about, text.as_deref(), chrono::Utc::now()) {
        Ok(pending) => Ok(KeptHere::Ahead(Some(pending))),
        Err(error) if arrives => {
            tracing::warn!(%error, "an arrival could not be noted in history");
            Ok(KeptHere::Ahead(None))
        }
        Err(e) => Err(Failure::File(not_kept(e))),
    }
}

/// Keep the channel's version of a file, as the plan read it, ahead of
/// this device's edit or delete that replaces it; and say the revision
/// the edit or delete is then to be published at. Nothing is kept where
/// the plan read no text there: a first publish, and a publish over a
/// delete, replace no text.
///
/// It is kept before the database lock is taken for the publish. The
/// publish is made only over the very entry the plan read, so the text
/// kept here is the text replaced; if it is not made, the record goes.
fn keep_channel(
    ctx: &Ctx,
    key: &str,
    change: history::Change,
) -> Result<(Ahead, Option<u64>), Failure> {
    let Some(store) = ctx.state.history.store() else {
        return Ok((None, None));
    };
    let Some((over, text)) = ctx
        .over
        .and_then(|version| Some((version, version.content.as_ref()?)))
    else {
        return Ok((None, None));
    };
    let Some(rev) = revision_ahead(ctx, key)? else {
        return Ok((None, None));
    };
    let about = history::About {
        at: String::new(),
        agent: ctx.agent.to_string(),
        folder: ctx.folder.to_string(),
        file: key.to_string(),
        change,
        kept: Some(history::kept(
            history::Whose::Channel(written_by(ctx, over)),
            &text.text,
        )),
        replaced_by: history::Replacement::Entry(entry_of(&ctx.state.identity.public_key(), rev)),
        behind: false,
    };
    match store.keep(about, Some(&text.text), chrono::Utc::now()) {
        Ok(pending) => Ok((Some(pending), Some(rev))),
        Err(e) => Err(Failure::File(not_kept(e))),
    }
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
///   no longer the one it was planned against. Something has changed what
///   the slot holds since the plan was made: another device's entry
///   arrived, most often, or a statement was applied. Publishing would
///   put this device's text over a version the plan never read, with no
///   conflict file. The next cycle plans against what is there now. It is
///   the version that is compared (its text or delete, and its revision),
///   with every entry held of it: two devices can publish the same
///   revision, and an entry of the version that arrives later may say
///   less of what it was written after.
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
        tag,
        folder,
        generation,
        ..
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
        as_seen(dir, key, seen)
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
    let me = state.identity.public_key();
    // A merged index is published over the channel's version, with the
    // version that the folder's own file held as its other source: what
    // the folder's record keeps of it (decision 2026-10-04 §7.3). A
    // merge at a folder's first sync has one source.
    let other_source = ctx.agreed.get(key).and_then(|agreed| {
        Some(OtherSource {
            hash: agreed.hash.unwrap_or([0u8; 32]),
            signer: agreed.signer?,
            chain: agreed.chain.clone(),
        })
    });
    // A publish that is refused for what the entry is (its name has no
    // revision left, say) is this file's failure. Any other is the
    // folder's. `at` is the revision that a history record of what the
    // entry replaces was kept for, if one was.
    let publish_merged = |text: &str, at: Option<u64>| -> Result<Option<Made>, Failure> {
        let db = lock(state)?;
        publish_over(ctx, &db, key, Some(text), at, other_source.as_ref())
    };
    // The same, for an edit or a delete that this device makes of its own
    // (not a merge): what it published is written down for the file's
    // index line ([`lines::published`]), under the hold of the lock that
    // the publish was made under. An entry that is published, and of
    // which nothing could be written down, is published all the same.
    let publish_own = |text: Option<&str>, at: Option<u64>| -> Result<Option<Made>, Failure> {
        let db = lock(state)?;
        let published = publish_over(ctx, &db, key, text, at, None)?;
        if ctx.lines
            && published.is_some()
            && let Err(error) = lines::published(ctx, &db, key, text)
        {
            tracing::warn!(file = %dir.join(key).display(), %error, "published, and what it means for the file's index line could not be written down");
        }
        Ok(published)
    };
    // What is agreed is one entry of one version: the text, the
    // revision, and the signer and the chain of that entry (decision
    // 2026-10-04 §2.3).
    let record = |agreed: Agreed| -> Result<(), CordeliaError> {
        record_agreed(state, generation, folder, channel, key, &agreed)
    };

    // An entry holds the file's name beside its text, so a file under
    // MAX_FILE_BYTES can still be too large. It is then left as it is,
    // like one that was never read.
    let too_large = |report: &mut FolderReport| {
        if !report.too_large.iter().any(|name| name == key) {
            report.too_large.push(key.to_string());
        }
    };

    // Whether a text can be published under this name at all: the name
    // and the text are within their bound together (decision 2026-10-04
    // §2.3). It is asked before anything is kept for the publish: a text
    // that fits in no entry is not published in any cycle while the file
    // stays as it is, and what it would replace would otherwise be
    // written to history, and removed again, in each.
    let fits = |text: &str| publish::fits(key, &Value::Text(text.to_string()));

    match action {
        Action::Publish(text) => {
            if !fits(&text) {
                too_large(report);
                return Ok(false);
            }
            // The channel's version is kept in history first. A publish
            // that is not made takes the record with it.
            let (ahead, at) = keep_channel(ctx, key, history::Change::EditedHere)?;
            let Some(made) = publish_own(Some(&text), at)? else {
                return Ok(false);
            };
            settle(ctx, ahead);
            report.published += 1;
            note_published(ctx, key, &text, &made.now);
            record(made.agreed(Some(Content::new(text).hash), me))?;
        }
        Action::PublishDelete => {
            let (ahead, at) = keep_channel(ctx, key, history::Change::DeletedHere)?;
            let Some(made) = publish_own(None, at)? else {
                return Ok(false);
            };
            settle(ctx, ahead);
            report.published += 1;
            record(made.agreed(None, me))?;
        }
        Action::Pull { text, agreed } => {
            // Asked before anything is kept, or noted, for the write.
            if seen.is_none()
                && let Some(why) = cannot_be_looked_at(dir, key)
            {
                return Err(Failure::File(why));
            }
            // The file as it is here is kept first, or its arrival noted.
            // The last look at the file comes after: `write_atomic` makes
            // it. A write that is not made takes the record with it. What
            // replaces the file is the channel's version, as the plan
            // read it: the record names the key that signed it, and for
            // a version that was carried the key it was carried from.
            let replaced_by = match ctx.over {
                Some(version) => history::Replacement::Entry(written_by(ctx, version)),
                None => history::Replacement::Nothing,
            };
            let ahead = match keep_here(ctx, key, seen, history::Change::Pulled, replaced_by)? {
                KeptHere::Ahead(ahead) => ahead,
                KeptHere::Changed => {
                    deferred();
                    return Ok(false);
                }
            };
            if !write_atomic(dir, key, &text, &flushed, &unchanged).map_err(io)? {
                deferred();
                return Ok(false);
            }
            settle(ctx, ahead);
            report.pulled += 1;
            forget_kept(ctx, key);
            record(agreed)?;
        }
        Action::RemoveFile { agreed } => {
            // The file is kept first, and looked at once more now that it
            // is: an agent may have written to it meanwhile. What takes
            // its place is the channel's delete, as the plan read it: the
            // record names the key that signed it, as for a text that
            // arrives, so that what a device wrote and this one received
            // can be counted whether it was a text or a delete.
            let delete = match ctx.over {
                Some(version) => history::Replacement::Entry(written_by(ctx, version)),
                None => history::Replacement::Nothing,
            };
            let ahead = match keep_here(ctx, key, seen, history::Change::Removed, delete)? {
                KeptHere::Ahead(ahead) if unchanged() => ahead,
                _ => {
                    deferred();
                    return Ok(false);
                }
            };
            match std::fs::remove_file(dir.join(key)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(io(e)),
            }
            settle(ctx, ahead);
            report.pulled += 1;
            forget_kept(ctx, key);
            record(agreed)?;
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
            if !fits(&text) {
                too_large(report);
                return Ok(false);
            }
            // The file as it is here is kept in history first, in a record
            // that names the revision the merged entry is to have.
            let at = revision_ahead(ctx, key)?;
            let ahead = match at {
                Some(rev) => {
                    let replaced_by = history::Replacement::Entry(entry_of(&me, rev));
                    match keep_here(ctx, key, seen, history::Change::Merged, replaced_by)? {
                        KeptHere::Ahead(ahead) => ahead,
                        KeptHere::Changed => {
                            deferred();
                            return Ok(false);
                        }
                    }
                }
                None => None,
            };
            // Published before the file is written: if the merged text does
            // not fit, the file stays as it was.
            let Some(made) = publish_merged(&text, at)? else {
                return Ok(false);
            };
            report.published += 1;
            if !write_atomic(dir, key, &text, &flushed, &unchanged).map_err(io)? {
                // Published, and the file was written to meanwhile: the
                // next cycle merges what is there now. The file was not
                // replaced, so its record goes.
                deferred();
                return Ok(false);
            }
            settle(ctx, ahead);
            forget_kept(ctx, key);
            record(made.agreed(Some(Content::new(text).hash), me))?;
        }
        Action::Record(agreed) => record(agreed)?,
    }
    Ok(true)
}

mod lines;
#[cfg(test)]
mod sequences;

#[cfg(test)]
mod tests {
    use super::*;
    use cordelia_api::{adding, change, take};
    use cordelia_crypto::derive;
    use cordelia_crypto::entry::{CheckedEntry, Entry, Inside};
    use cordelia_crypto::phrase::Phrase;
    use cordelia_crypto::statement::Device;
    use cordelia_storage::atomic::temporary_name;
    use cordelia_storage::entries as stored;
    use cordelia_storage::person as held_rows;

    mod index_lines;

    /// The name that a test's folder syncs.
    const NAME: &str = "x";

    /// The device that signed a version of the channel's, where a test
    /// makes an action by hand and does not look at whose it is.
    const OTHER: [u8; 32] = [7; 32];

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    /// A node that follows no phrase yet, and is set up with no relay: a
    /// folder's first cycle waits for none.
    fn state(dir: &Path) -> AppState {
        let state = AppState {
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
            own_channels: Default::default(),
            held: Default::default(),
            history: Default::default(),
        };
        state.own_channels.set_up_with(0);
        state
    }

    /// `st` makes a recovery phrase, which it then follows alone, and
    /// holds `name`. Returns the ID of the name's channel, as it is
    /// written: what the folder's records are kept by.
    fn with_phrase(st: &AppState, name: &str) -> String {
        person_of(st, name).0
    }

    /// The same, with the phrase: for a test that makes a change.
    fn person_of(st: &AppState, name: &str) -> (String, Phrase) {
        let db = st.db.lock().unwrap();
        let phrase = Phrase::generate().unwrap();
        person::first_statement(&db, &st.identity, &phrase, "desktop", now()).unwrap();
        let id = person::hold_name(&db, name, now()).unwrap();
        (encode_channel_id(&id).unwrap(), phrase)
    }

    /// A second device of the same person, which holds `name` too: `st`
    /// adds it, and it accepts what `st` hands over. Entries pass between
    /// devices by `deliver`.
    fn another_device(st: &AppState, dir: &Path, name: &str) -> AppState {
        let other = state(dir);
        let at = now();
        let added = {
            let db = st.db.lock().unwrap();
            adding::add_device(
                &db,
                &st.identity,
                &other.identity.public_key(),
                "laptop",
                at,
            )
            .unwrap()
        };
        {
            let db = other.db.lock().unwrap();
            let typed = st.identity.public_key();
            let accepted = adding::accept(
                &db,
                &other.identity,
                &typed,
                at,
                false,
                &added.hand_over,
                at,
            )
            .unwrap();
            assert!(
                matches!(accepted, adding::Accepted::Joined(_)),
                "{accepted:?}"
            );
            person::hold_name(&db, name, at).unwrap();
        }
        other
    }

    /// The secret of the channel of `name`, in the generation that `st`
    /// has applied.
    fn name_secret(st: &AppState, name: &str) -> [u8; 32] {
        let db = st.db.lock().unwrap();
        let person = held_rows::applied_secret(&db).unwrap().unwrap();
        derive::own_secret(&person.secret, name).unwrap()
    }

    /// The entries `st` holds in the channel whose secret is `secret`, as
    /// they are stored, in the order it stored them.
    fn held_under(st: &AppState, secret: &[u8; 32]) -> Vec<CheckedEntry> {
        let channel = derive::channel_id(secret).unwrap();
        let db = st.db.lock().unwrap();
        stored::channel_entries_after(&db, &channel, 0, 10_000)
            .unwrap()
            .into_iter()
            .map(|held| held.entry.check().unwrap())
            .collect()
    }

    /// The entries `st` holds in the channel of `name`.
    fn held(st: &AppState, name: &str) -> Vec<CheckedEntry> {
        held_under(st, &name_secret(st, name))
    }

    /// Give `to` every entry that `from` holds in the personal channel
    /// and in the channel of `name`, through the one door for an entry
    /// from outside, as a relay's pages do. Twice over: an entry that a
    /// key signed before a record made that key count is given again.
    fn deliver(from: &AppState, to: &AppState, name: &str) {
        let personal = {
            let db = from.db.lock().unwrap();
            let person = held_rows::applied_secret(&db).unwrap().unwrap();
            derive::personal_secret(&person.secret).unwrap()
        };
        let mut all = held_under(from, &personal);
        all.extend(held(from, name));
        let db = to.db.lock().unwrap();
        for _ in 0..2 {
            for entry in &all {
                take::take(&db, &to.identity, entry, now()).unwrap();
            }
        }
    }

    /// Publish `value` under `key` as `st`, over whatever its slot holds,
    /// as its adapter would a text. Returns what the slot holds then: what
    /// a plan that reads it now is planned against.
    fn write(st: &AppState, name: &str, key: &str, value: Value) -> PlannedAgainst {
        let db = st.db.lock().unwrap();
        let read = publish::read(&db, name, key).unwrap();
        let write = Write {
            name,
            file: key,
            value,
            planned: PlannedAgainst::what_is_in(&read.slot),
            merge: None,
        };
        let published = publish::publish(&db, &st.identity, &write, now()).unwrap();
        assert!(matches!(published, Published::Made(_)), "{published:?}");
        PlannedAgainst::what_is_in(&publish::read(&db, name, key).unwrap().slot)
    }

    /// A text, as an entry holds one.
    fn text(t: &str) -> Value {
        Value::Text(t.into())
    }

    /// Put in `st`'s store an entry for `key` by `st` at the revision
    /// `rev`, with `text` and the chain of a new file's entry: what a
    /// device that has written the file that many times holds. (A publish
    /// takes the next revision, whatever it is.)
    fn write_at(st: &AppState, name: &str, key: &str, text: &str, rev: u64) {
        entry_at(
            st,
            name,
            key,
            Value::Text(text.into()),
            rev,
            Some(Vec::new()),
        );
    }

    /// The same, for any value and with any chain: `None` for an entry
    /// that lacks what it should say. Returns what the entry is named by.
    fn entry_at(
        st: &AppState,
        name: &str,
        key: &str,
        value: Value,
        rev: u64,
        chain: Option<Vec<Link>>,
    ) -> [u8; 32] {
        let secret = name_secret(st, name);
        let entry = match chain {
            // No entry is made that lacks its chain: it is put together.
            None => lacking_its_chain(&secret, &st.identity, key, value, rev),
            chain => {
                let inside = Inside {
                    name: key.to_string(),
                    value,
                    chain,
                };
                Entry::seal(&secret, &st.identity, rev, &inside)
                    .unwrap()
                    .check()
                    .unwrap()
            }
        };
        let db = st.db.lock().unwrap();
        let outcome = stored::store(&db, &entry, now()).unwrap();
        assert_eq!(outcome, stored::Outcome::Stored);
        entry.id()
    }

    /// An entry by `author`, of the channel whose secret is `secret`, that
    /// holds `value` under `key` at `rev` and lacks what it should say:
    /// what follows its value in its content is not a chain and the fill.
    /// No device makes one, so it is made here from a whole entry: after
    /// the count of its links, which is none, a byte is put that is no
    /// fill.
    fn lacking_its_chain(
        secret: &[u8; 32],
        author: &cordelia_crypto::identity::NodeIdentity,
        key: &str,
        value: Value,
        rev: u64,
    ) -> CheckedEntry {
        use cordelia_core::protocol::{
            LABEL_ENTRY_AUTHOR, LABEL_ENTRY_CHANNEL, LABEL_ENTRY_CONTENT,
        };
        // What the form takes: the name behind its length, the kind of
        // the value, the value behind its length (a delete has none), and
        // the count of links.
        let value_takes = match value.is_delete() {
            true => 0,
            false => 2 + value.bytes().len(),
        };
        let said = 2 + key.len() + 1 + value_takes + 2;
        let inside = Inside {
            name: key.to_string(),
            value,
            chain: Some(Vec::new()),
        };
        let mut entry = Entry::seal(secret, author, rev, &inside).unwrap();
        let entry_key = derive::entry_key(secret).unwrap();
        let bound = [
            LABEL_ENTRY_CONTENT,
            &entry.channel[..],
            &entry.slot[..],
            &rev.to_be_bytes()[..],
        ]
        .concat();
        let mut filled = cordelia_crypto::item_decrypt(&entry_key, &entry.content, &bound).unwrap();
        assert!(filled[said..].iter().all(|byte| *byte == 0));
        filled[said] = 7;
        entry.content = cordelia_crypto::item_encrypt(&entry_key, &filled, &bound).unwrap();
        // The signatures are over the content's hash: both are made again.
        let channel_key = derive::signing_key(secret).unwrap();
        let form = entry.signed_bytes();
        entry.author_signature = author.sign(&[LABEL_ENTRY_AUTHOR, &form[..]].concat());
        entry.channel_signature = channel_key.sign(&[LABEL_ENTRY_CHANNEL, &form[..]].concat());
        let entry = entry.check().unwrap();
        assert_eq!(entry.open(secret).unwrap().chain, None);
        entry
    }

    /// What `st` takes as the channel's version of `key`: what its slot
    /// holds, as a plan is planned against it, with the version's revision
    /// and its text (none for a delete, or for what is no text).
    fn version(st: &AppState, name: &str, key: &str) -> Option<(PlannedAgainst, u64, String)> {
        let db = st.db.lock().unwrap();
        let slot = publish::read(&db, name, key).unwrap().slot;
        let current = slot.current.as_ref()?;
        let text = match &current.value {
            Value::Text(text) => text.clone(),
            _ => String::new(),
        };
        Some((PlannedAgainst::what_is_in(&slot), current.rev, text))
    }

    /// The chain of the entry that `st` itself holds of the channel's
    /// version of `key`: what that entry says it was written after.
    fn said(st: &AppState, name: &str, key: &str) -> Option<Vec<Link>> {
        let db = st.db.lock().unwrap();
        let slot = publish::read(&db, name, key).unwrap().slot;
        let own = st.identity.public_key();
        let current = slot.current?;
        let entry = current.entries.iter().find(|entry| entry.author == own)?;
        entry.chain.clone()
    }

    /// What a chain names `text` by (a delete for `None`) as signed by
    /// the device `by`.
    fn link(text: Option<&str>, by: &AppState) -> Link {
        link_of(text, &by.identity.public_key())
    }

    fn link_of(text: Option<&str>, signer: &[u8; 32]) -> Link {
        let whole = text.map_or([0u8; 32], |t| Content::new(t).hash);
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&whole[..16]);
        Link {
            hash,
            signer: Link::signer_of(signer),
        }
    }

    /// An entry of the channel whose secret is `secret`, in `slot` at
    /// `rev`, that `author` and the channel signed, and whose content is
    /// `content` whatever that opens as: for an entry that is no version.
    fn signed_in(
        secret: &[u8; 32],
        author: &cordelia_crypto::identity::NodeIdentity,
        slot: [u8; 32],
        rev: u64,
        content: Vec<u8>,
    ) -> CheckedEntry {
        use cordelia_core::protocol::{LABEL_ENTRY_AUTHOR, LABEL_ENTRY_CHANNEL};
        let channel_key = derive::signing_key(secret).unwrap();
        let mut entry = Entry {
            channel: channel_key.public_key(),
            slot,
            author: author.public_key(),
            rev,
            delete: false,
            content,
            author_signature: [0u8; 64],
            channel_signature: [0u8; 64],
        };
        let form = entry.signed_bytes();
        entry.author_signature = author.sign(&[LABEL_ENTRY_AUTHOR, &form[..]].concat());
        entry.channel_signature = channel_key.sign(&[LABEL_ENTRY_CHANNEL, &form[..]].concat());
        entry.check().unwrap()
    }

    /// `st` makes a change that removes the key `gone`, with `phrase`, and
    /// applies it: every other key that counts for it stays. Returns the
    /// change entry, which another device is shown through `take`.
    fn removes(st: &AppState, phrase: &Phrase, gone: &[u8; 32]) -> CheckedEntry {
        let db = st.db.lock().unwrap();
        let held = person::held(&db).unwrap().unwrap();
        let latest = held_rows::change_entry(&db, held_rows::Kept::Latest)
            .unwrap()
            .unwrap()
            .check()
            .unwrap();
        let stay: Vec<Device> = person::who_counts(&db)
            .unwrap()
            .keys()
            .into_iter()
            .filter(|key| key != gone)
            .map(|key| Device::new(key, "device").unwrap())
            .collect();
        let own = st.identity.public_key();
        let entry =
            change::make_change(phrase, &held.statement, &latest, &own, stay, &[*gone]).unwrap();
        person::apply_made(&db, &st.identity, &entry, &latest.id(), None, now()).unwrap();
        entry
    }

    /// The folder and channel that an action is applied to by hand, as
    /// planned against `planned`.
    fn ctx_of<'a>(
        st: &'a AppState,
        mem: &'a Path,
        channel: &'a str,
        folder: &'a str,
        planned: &'a PlannedAgainst,
        agreed: &'a HashMap<String, Agreed>,
    ) -> Ctx<'a> {
        Ctx {
            state: st,
            dir: mem,
            channel,
            tag: "abcd",
            folder,
            agent: NAME,
            generation: st.sync_control.generation(),
            planned,
            over: None,
            agreed,
            flushed: &|_| {},
            relied: RefCell::new(None),
            lines: true,
        }
    }

    /// What a folder records of a version that `OTHER` signed at `rev`,
    /// with the text of `hash` in its file.
    fn agreed_at(hash: Option<[u8; 32]>, rev: u64) -> Agreed {
        Agreed {
            hash,
            rev,
            signer: Some(OTHER),
            chain: Some(Vec::new()),
        }
    }

    /// An agent writing a file after the scan must not be overwritten by an
    /// incoming version planned from the older scan.
    #[test]
    fn a_file_written_mid_cycle_is_never_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let st = state(tmp.path());
        let channel = with_phrase(&st, NAME);
        let mem = tmp.path().join("memory");
        std::fs::create_dir_all(&mem).unwrap();
        std::fs::write(mem.join("notes.md"), "scanned\n").unwrap();
        let seen = Some(Content::new("scanned\n").hash);

        // The agent writes after the scan...
        std::fs::write(mem.join("notes.md"), "written mid-cycle\n").unwrap();

        let (none, agreed) = (PlannedAgainst::NoVersion, HashMap::new());
        let ctx = ctx_of(&st, &mem, &channel, "f", &none, &agreed);
        let mut report = FolderReport::default();
        let incoming = || Action::Pull {
            text: "incoming\n".into(),
            agreed: agreed_at(Some(Content::new("incoming\n").hash), 2),
        };
        for action in [
            incoming(),
            Action::RemoveFile {
                agreed: agreed_at(None, 2),
            },
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
        assert!(apply(&ctx, "notes.md", now, incoming(), &mut report).unwrap());
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
        let channel = with_phrase(&st, NAME);
        let mem = tmp.path().join("memory");
        std::fs::create_dir_all(&mem).unwrap();
        // The files the channel holds, and whether each is live.
        let held = |st: &AppState| -> Vec<(String, bool)> {
            let db = st.db.lock().unwrap();
            let read = publish::read_name(&db, NAME).unwrap();
            let mut files: Vec<(String, bool)> = read
                .slots
                .iter()
                .filter_map(|slot| slot.current.as_ref())
                .map(|version| (version.name.clone(), version.value != Value::Delete))
                .collect();
            files.sort();
            files
        };
        let cycle =
            |generation: u64| sync_folder(&st, &mem, &channel, NAME, "abcd", generation).unwrap();

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
        let (none, agreed) = (PlannedAgainst::NoVersion, HashMap::new());
        let ctx = Ctx {
            generation: started,
            ..ctx_of(&st, &mem, &channel, &folder, &none, &agreed)
        };
        let seen = Some(Content::new("here\n").hash);
        let mut report = FolderReport::default();
        let pull = || Action::Pull {
            text: "from another device\n".into(),
            agreed: agreed_at(Some(Content::new("from another device\n").hash), 2),
        };
        assert!(!apply(&ctx, "new.md", None, pull(), &mut report).unwrap());
        assert!(!apply(&ctx, "kept.md", seen, pull(), &mut report).unwrap());
        let gone = Action::RemoveFile {
            agreed: agreed_at(None, 2),
        };
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
        let late = agreed_at(None, 9);
        record_agreed(&st, started, elsewhere, &channel, "late.md", &late).unwrap();
        assert!(!agreed(&st));
        let now = st.sync_control.generation();
        record_agreed(&st, now, elsewhere, &channel, "late.md", &late).unwrap();
        assert!(agreed(&st));

        // The next cycle, under the settings as they are now, carries on.
        let report = cycle(st.sync_control.generation());
        assert!(!report.stopped);
        assert_eq!(report.published, 2, "the delete of a.md, and kept.md");
    }

    /// An edit, a delete or a merged index is published only over the
    /// version it was planned against. An entry from another device that
    /// arrives between the plan and the publish is one this device never
    /// read: published over, its text would be replaced with no conflict
    /// file anywhere. It is the version that is compared, with every
    /// entry held of it, and not its revision alone.
    #[test]
    fn an_edit_is_published_only_over_the_entry_it_was_planned_against() {
        let tmp = tempfile::tempdir().unwrap();
        let st = state(tmp.path());
        let (channel, phrase) = person_of(&st, NAME);
        let other = another_device(&st, &tmp.path().join("other"), NAME);
        let mem = tmp.path().join("memory");
        std::fs::create_dir_all(&mem).unwrap();
        let folder = mem.display().to_string();
        let agreed = HashMap::new();
        // Apply `action` to `key`, as planned against `planned`.
        let apply_over = |key: &str, planned: &PlannedAgainst, action: Action| -> bool {
            let ctx = ctx_of(&st, &mem, &channel, &folder, planned, &agreed);
            let seen = current_hash(&mem, key);
            apply(&ctx, key, seen, action, &mut FolderReport::default()).unwrap()
        };
        // Each action that publishes. None of them may go over a version
        // that was not planned against. A refusal leaves everything as it
        // was: nothing is counted or recorded, and a merge writes no file.
        let refused = |key: &str, planned: &PlannedAgainst| {
            for action in [
                Action::Publish("mine\n".into()),
                Action::PublishDelete,
                Action::Merge("merged\n".into()),
            ] {
                let ctx = ctx_of(&st, &mem, &channel, &folder, planned, &agreed);
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
        let planned = write(&st, NAME, "notes.md", text("one\n"));
        deliver(&st, &other, NAME);
        let theirs = write(&other, NAME, "notes.md", text("theirs\n"));
        deliver(&other, &st, NAME);
        refused("notes.md", &planned);
        let there = Some((theirs.clone(), 2, "theirs\n".to_string()));
        assert_eq!(version(&st, NAME, "notes.md"), there);
        // Planned against what is there now, it goes ahead.
        assert!(apply_over(
            "notes.md",
            &theirs,
            Action::Publish("mine\n".into())
        ));
        let (_, rev, now) = version(&st, NAME, "notes.md").unwrap();
        assert_eq!((rev, now.as_str()), (3, "mine\n"));

        // Another device's version at the same revision has taken its
        // place. The number has not changed, so a check of the number
        // would pass. A tie goes to the higher hash of the text.
        let planned = write(&st, NAME, "tied.md", text("mine\n"));
        let wins = (0..)
            .map(|n| format!("theirs {n}\n"))
            .find(|t| Content::new(t.as_str()).hash > Content::new("mine\n").hash)
            .unwrap();
        let theirs = write(&other, NAME, "tied.md", text(&wins));
        deliver(&other, &st, NAME);
        let there = Some((theirs, 1, wins.clone()));
        assert_eq!(version(&st, NAME, "tied.md"), there);
        refused("tied.md", &planned);
        assert_eq!(version(&st, NAME, "tied.md"), there);

        // The same version, with another entry held of it: another device
        // made the same edit apart, and its entry may say less of what it
        // was written after. What was planned against is that version
        // without it.
        let planned = write(&st, NAME, "same.md", text("same\n"));
        let both = write(&other, NAME, "same.md", text("same\n"));
        deliver(&other, &st, NAME);
        let (now, rev, _) = version(&st, NAME, "same.md").unwrap();
        assert_eq!(rev, 1);
        assert_ne!(now, planned);
        assert_ne!(
            now, both,
            "it holds two entries of the version, the other device one"
        );
        refused("same.md", &planned);
        assert!(apply_over(
            "same.md",
            &now,
            Action::Publish("mine\n".into())
        ));

        // A version has appeared where the plan read none.
        let theirs = write(&other, NAME, "new.md", text("theirs\n"));
        deliver(&other, &st, NAME);
        refused("new.md", &PlannedAgainst::NoVersion);
        let there = Some((theirs.clone(), 1, "theirs\n".to_string()));
        assert_eq!(version(&st, NAME, "new.md"), there);

        // A statement was applied since the plan: the device that wrote
        // the version was removed, and this device has carried what it
        // held. The version is the same text at the same revision, and is
        // this device's own entry now, in another channel: it is not what
        // was planned against.
        removes(&st, &phrase, &other.identity.public_key());
        let (carried, rev, now) = version(&st, NAME, "new.md").unwrap();
        assert_eq!((rev, now.as_str()), (1, "theirs\n"));
        assert_ne!(carried, theirs);
        refused("new.md", &theirs);
        assert_eq!(version(&st, NAME, "new.md").unwrap().0, carried);
        let channel = {
            let db = st.db.lock().unwrap();
            let id = held_rows::channel_of_name(&db, NAME).unwrap().unwrap();
            encode_channel_id(&id).unwrap()
        };
        let ctx = ctx_of(&st, &mem, &channel, &folder, &carried, &agreed);
        let edit = Action::Publish("mine\n".into());
        assert!(apply(&ctx, "new.md", None, edit, &mut FolderReport::default()).unwrap());
    }

    /// The check reads what the plan reads. A version under a file's name
    /// that is not a text or a delete (bytes written through the API), and
    /// an entry this device cannot read, are no version of the file to the
    /// plan: it finds none, and the file is published over them. What
    /// this pins is that the plan and the publish agree: a plan that took
    /// such an entry for a version where the publish did not, or the
    /// other way round, would leave the file unpublished for good.
    #[test]
    fn what_is_no_version_of_a_memory_file_holds_nothing_back() {
        let tmp = tempfile::tempdir().unwrap();
        let st = state(tmp.path());
        let channel = with_phrase(&st, NAME);
        let mem = tmp.path().join("memory");
        std::fs::create_dir_all(&mem).unwrap();

        // Not a text.
        write(&st, NAME, "api.md", Value::Other(b"{\"a\":1}".to_vec()));
        // An entry that does not open: sealed under another secret, by
        // another device, in this channel's slot.
        let other = another_device(&st, &tmp.path().join("other"), NAME);
        deliver(&st, &other, NAME);
        let secret = name_secret(&st, NAME);
        let wrong = [7u8; 32];
        let inside = Inside {
            name: "sealed.md".into(),
            value: text("theirs\n"),
            chain: Some(Vec::new()),
        };
        let elsewhere = Entry::seal(&wrong, &other.identity, 1, &inside).unwrap();
        // The entry is of this channel and this slot, and signed for it:
        // only its content is another channel's.
        let of_this = Entry::seal(&secret, &other.identity, 1, &inside).unwrap();
        let sealed = signed_in(&secret, &other.identity, of_this.slot, 1, elsewhere.content);
        assert!(sealed.open(&secret).is_err());
        take::take(&st.db.lock().unwrap(), &st.identity, &sealed, now()).unwrap();
        assert_eq!(held(&st, NAME).len(), 2);
        assert_eq!(version(&st, NAME, "sealed.md"), None);

        for name in ["api.md", "sealed.md"] {
            std::fs::write(mem.join(name), "mine\n").unwrap();
        }
        let generation = st.sync_control.generation();
        let report = sync_folder(&st, &mem, &channel, NAME, "abcd", generation).unwrap();
        assert_eq!(report.published, 2);
        for name in ["api.md", "sealed.md"] {
            let (_, rev, text) = version(&st, NAME, name).unwrap();
            assert_eq!((rev, text.as_str()), (2, "mine\n"), "{name}");
        }

        // A version of that kind over a file that is agreed and unchanged,
        // at a higher revision than the one agreed: it is no delete and no
        // text to take, so the file is left as it is and nothing is
        // published.
        write(&st, NAME, "api.md", Value::Other(b"{\"a\":2}".to_vec()));
        let report = sync_folder(&st, &mem, &channel, NAME, "abcd", generation).unwrap();
        assert_eq!((report.published, report.pulled), (0, 0), "{report:?}");
        let kept = std::fs::read_to_string(mem.join("api.md")).unwrap();
        assert_eq!(kept, "mine\n");
    }

    /// After every publish the pass that sends is woken (decision
    /// 2026-10-04 §16): what a cycle wrote in a channel of the device's
    /// own goes out without waiting for the timer. A cycle that publishes
    /// nothing wakes nothing.
    #[test]
    fn a_publish_wakes_the_pass_that_sends() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        let tmp = tempfile::tempdir().unwrap();
        let st = state(tmp.path());
        let channel = with_phrase(&st, NAME);
        let mem = tmp.path().join("memory");
        std::fs::create_dir_all(&mem).unwrap();
        // Whether the pass was woken since this was last asked: the word
        // is kept until it is waited for, and no more than one is kept.
        let woken = || {
            let mut word = std::pin::pin!(st.own_channels.wait_written());
            let mut context = Context::from_waker(Waker::noop());
            matches!(word.as_mut().poll(&mut context), Poll::Ready(()))
        };
        let cycle = || {
            let generation = st.sync_control.generation();
            sync_folder(&st, &mem, &channel, NAME, "abcd", generation).unwrap()
        };
        assert!(!woken());
        // Nothing to publish: nothing is woken.
        assert_eq!(cycle().published, 0);
        assert!(!woken());
        // A new file, an edit, and a delete: each wakes it.
        std::fs::write(mem.join("notes.md"), "one\n").unwrap();
        assert_eq!(cycle().published, 1);
        assert!(woken());
        assert!(!woken());
        std::fs::write(mem.join("notes.md"), "two\n").unwrap();
        assert_eq!(cycle().published, 1);
        assert!(woken());
        std::fs::remove_file(mem.join("notes.md")).unwrap();
        assert_eq!(cycle().published, 1);
        assert!(woken());
        // A cycle with nothing to do wakes nothing.
        assert_eq!(cycle().published, 0);
        assert!(!woken());
    }

    /// A folder in a channel that two devices hold, as a cycle on the first
    /// sees it: `st` with its memory folder, and `other` to write to the
    /// channel as another device would.
    struct Pair {
        st: AppState,
        other: AppState,
        /// The channel's ID as it is written: what the folder's records
        /// are kept by.
        channel: String,
        /// The phrase that the two devices follow.
        phrase: Phrase,
        mem: PathBuf,
        _tmp: tempfile::TempDir,
    }

    impl Pair {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let st = state(tmp.path());
            let (channel, phrase) = person_of(&st, NAME);
            let other = another_device(&st, &tmp.path().join("other"), NAME);
            let mem = tmp.path().join("memory");
            std::fs::create_dir_all(&mem).unwrap();
            Self {
                st,
                other,
                channel,
                phrase,
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
                NAME,
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
        /// having received what `st` holds, and `st` receives it. It is
        /// written over the version that the other device then holds, as
        /// its adapter would write it: its chain says so.
        fn other_writes(&self, name: &str, text: Option<&str>) {
            deliver(&self.st, &self.other, NAME);
            let value = text.map_or(Value::Delete, |t| Value::Text(t.into()));
            write(&self.other, NAME, name, value);
            deliver(&self.other, &self.st, NAME);
        }

        /// The other device writes `text` under `name` at the slot's next
        /// revision, in an entry whose chain is `chain` whatever the slot
        /// holds (`None` for an entry that lacks its chain), having
        /// received what `st` holds; and `st` receives it.
        fn other_says(&self, name: &str, text: &str, chain: Option<Vec<Link>>) {
            deliver(&self.st, &self.other, NAME);
            let next = {
                let db = self.other.db.lock().unwrap();
                publish::read(&db, NAME, name).unwrap().slot.next.unwrap()
            };
            entry_at(
                &self.other,
                NAME,
                name,
                Value::Text(text.into()),
                next,
                chain,
            );
            deliver(&self.other, &self.st, NAME);
        }

        /// The text of the channel's version of `name`, as `st` holds it.
        fn held(&self, name: &str) -> Option<String> {
            let (_, _, text) = version(&self.st, NAME, name)?;
            let db = self.st.db.lock().unwrap();
            let slot = publish::read(&db, NAME, name).unwrap().slot;
            matches!(slot.current?.value, Value::Text(_)).then_some(text)
        }
    }

    impl Pair {
        /// Whether the channel's version of `name` is a delete, as `st`
        /// holds it.
        fn deleted(&self, name: &str) -> bool {
            let db = self.st.db.lock().unwrap();
            let slot = publish::read(&db, NAME, name).unwrap().slot;
            slot.current
                .is_some_and(|version| version.value == Value::Delete)
        }

        /// The other device writes `text` under `name`, or a delete, at
        /// the slot's next revision, in an entry whose chain is `chain`
        /// whatever the slot holds, having received what `st` holds; and
        /// `st` receives it.
        fn other_puts(&self, name: &str, text: Option<&str>, chain: Option<Vec<Link>>) {
            deliver(&self.st, &self.other, NAME);
            let next = {
                let db = self.other.db.lock().unwrap();
                publish::read(&db, NAME, name).unwrap().slot.next.unwrap()
            };
            let value = text.map_or(Value::Delete, |t| Value::Text(t.into()));
            entry_at(&self.other, NAME, name, value, next, chain);
            deliver(&self.other, &self.st, NAME);
        }

        /// The other device deletes `name`, having received what `st`
        /// holds, and `st` does not receive the delete: it is on its way.
        fn other_deletes_unsent(&self, name: &str) {
            deliver(&self.st, &self.other, NAME);
            write(&self.other, NAME, name, Value::Delete);
        }

        /// An entry of the other device's arrives under `name`, at the
        /// slot's next revision, that does not open with the channel's
        /// secret: it is no version. Whatever the other device had in the
        /// slot before, this entry has its place in the store of `st`.
        fn other_sends_what_does_not_open(&self, name: &str) {
            let secret = name_secret(&self.st, NAME);
            let rev = {
                let db = self.st.db.lock().unwrap();
                publish::read(&db, NAME, name).unwrap().slot.next.unwrap()
            };
            let inside = Inside {
                name: name.into(),
                value: text("sealed\n"),
                chain: Some(Vec::new()),
            };
            // The entry is of this channel and this slot, and signed for
            // it: only its content is another channel's.
            let by = &self.other.identity;
            let of_this = Entry::seal(&secret, by, rev, &inside).unwrap();
            let elsewhere = Entry::seal(&[7u8; 32], by, rev, &inside).unwrap();
            let sealed = signed_in(&secret, by, of_this.slot, rev, elsewhere.content);
            assert!(sealed.open(&secret).is_err());
            let db = self.st.db.lock().unwrap();
            let taken = take::take(&db, &self.st.identity, &sealed, now()).unwrap();
            let stored = stored::Outcome::Stored;
            assert!(
                matches!(taken, take::Taken::Own { stored: s, .. } if s == stored),
                "{taken:?}"
            );
        }

        /// What the folder has recorded of `name` in the channel that
        /// `st` holds for the name now.
        fn record(&self, name: &str) -> Option<Agreed> {
            record_of(&self.st, &self.mem, name)
        }
    }

    /// The ID, as it is written, of the channel that `st` holds for the
    /// name now: after a statement it is another than before.
    fn channel_now(st: &AppState) -> String {
        let db = st.db.lock().unwrap();
        let id = held_rows::channel_of_name(&db, NAME).unwrap().unwrap();
        encode_channel_id(&id).unwrap()
    }

    /// The last revision that an entry may have under the first statement
    /// of a phrase, which is the one these tests' devices have applied:
    /// the top of that statement's band. Nothing can be written above it
    /// until the next statement.
    const LAST_REV: u64 = 2 * cordelia_core::protocol::REV_BAND_SIZE - 1;

    /// A text that loses a tie at one revision to `text`: its hash is the
    /// lower of the two.
    fn a_text_below(text: &str) -> String {
        let hash = Content::new(text).hash;
        (0..)
            .map(|n| format!("another text {n}\n"))
            .find(|t| Content::new(t.as_str()).hash < hash)
            .unwrap()
    }

    /// A text that wins a tie at one revision over `text`: its hash is the
    /// higher of the two.
    fn a_text_above(text: &str) -> String {
        let hash = Content::new(text).hash;
        (0..)
            .map(|n| format!("another text {n}\n"))
            .find(|t| Content::new(t.as_str()).hash > hash)
            .unwrap()
    }

    /// An entry from another device that arrives while a cycle runs, after
    /// the cycle has read the channel, and becomes the channel's version
    /// of the file, is not published over. The file waits, and the next
    /// cycle finds both changed: this device's text is kept as a conflict
    /// file and the channel's is taken. Published over, the other
    /// device's text would be in no file anywhere.
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

        // With another device's version beside the one that counts (it
        // lost a tie: its text has the lower hash), an edit goes over the
        // one that counts.
        p.file("tied.md", "mine\n");
        p.cycle();
        let mine = version(&p.st, NAME, "tied.md").unwrap().0;
        let third = another_device(&p.st, &p.mem.with_file_name("third"), NAME);
        write(&third, NAME, "tied.md", text(&a_text_below("mine\n")));
        deliver(&third, &p.st, NAME);
        let lost = {
            let db = p.st.db.lock().unwrap();
            publish::read(&db, NAME, "tied.md").unwrap().slot.lost.len()
        };
        assert_eq!(lost, 1, "the version that lost the tie is held beside it");
        assert_eq!(version(&p.st, NAME, "tied.md").unwrap().0, mine);
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

    /// An entry that does not open with the channel's secret is no version
    /// (decision 2026-10-04 §2.3): a device passes it over, and plans from
    /// what it can read. A slot holds one entry for each author, so where
    /// the entry's author had an earlier entry for the file, the one that
    /// does not open has taken its place: what is read instead is the
    /// newest version by any other author.
    ///
    /// Five files, for five of the things the device then does. An
    /// unchanged file for which an earlier text is read is taken back to
    /// that text, and what it held is kept beside it. The other four are
    /// published above the entry that is not read (a merged index, a file
    /// over a delete, an edit, a delete): the next revision is above every
    /// entry of a key that counts, a version or not. Nothing more comes of
    /// such an entry: no key arrives that would open it.
    #[test]
    fn a_device_plans_from_what_it_can_read_where_an_entry_does_not_open() {
        let p = Pair::new();
        let index = crate::memory_md::INDEX_FILE;
        let (a_line, b_line, x_line) = (
            "- [A](a.md) — a\n",
            "- [B](b.md) — b\n",
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

        // The other device's next entry for each file does not open here.
        for name in ["note.md", index, "back.md", "mine.md", "gone.md"] {
            p.other_sends_what_does_not_open(name);
        }
        // This device holds each, and reads what is under it.
        assert_eq!(p.held("note.md").as_deref(), Some("one\n"));
        assert_eq!(
            p.held(index).as_deref(),
            Some(format!("{a_line}{x_line}").as_str())
        );
        assert!(p.deleted("back.md"), "this device's delete");
        assert_eq!(p.held("mine.md").as_deref(), Some("one\n"));

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
            let (_, at, now) = version(&p.st, NAME, name).unwrap();
            assert_eq!((at, now.as_str()), (rev, text), "{name}");
        };
        let merged = format!("{a_line}{x_line}{b_line}");
        above(index, 4, &merged);
        above("back.md", 5, "two\n");
        above("mine.md", 3, "edited here\n");
        // A delete has no text.
        above("gone.md", 3, "");
        assert!(p.deleted("gone.md"));
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

        // Nothing more comes of the entries that do not open. The next
        // cycle publishes the conflict file, as a file of its own, and
        // that is all: what this device published is still the channel's
        // version of each of the four.
        let report = p.cycle();
        assert_eq!(
            (report.published, report.pulled, report.conflicts),
            (1, 0, 0),
            "{report:?}"
        );
        assert_eq!(p.read("note.md").as_deref(), Some("one\n"));
        assert_eq!(p.read("note.conflict-abcd.md").as_deref(), Some("two\n"));
        above(index, 4, &merged);
        above("back.md", 5, "two\n");
        above("mine.md", 3, "edited here\n");
        above("gone.md", 3, "");
        assert_eq!(p.read(index), Some(merged));
        // No file comes back and no second conflict file is made.
        assert_eq!(files(&p), there);
    }

    /// What each entry the adapter publishes says it was written after
    /// (decision 2026-10-04 §7.3): its chain is that of an entry written
    /// over the version the plan read. That version comes first, named by
    /// its text and by the key that signed it, and then what that
    /// version's entry says.
    #[test]
    fn an_entry_says_what_it_was_written_over() {
        let p = Pair::new();
        let (me, them) = (&p.st, &p.other);
        let said = |name: &str| said(&p.st, NAME, name);

        // A new file: over nothing. Its chain is empty, which is not the
        // same as an entry that lacks its chain.
        p.file("mine.md", "one\n");
        p.cycle();
        assert_eq!(said("mine.md"), Some(Vec::new()));
        // An edit of it, over this device's own entry.
        p.file("mine.md", "two\n");
        p.cycle();
        let one = link(Some("one\n"), me);
        assert_eq!(said("mine.md"), Some(vec![one]));
        // And again: the version it was written over comes first.
        p.file("mine.md", "three\n");
        p.cycle();
        let two = link(Some("two\n"), me);
        assert_eq!(said("mine.md"), Some(vec![two, one]));
        // A delete says the same things an edit does.
        std::fs::remove_file(p.mem.join("mine.md")).unwrap();
        p.cycle();
        let three = link(Some("three\n"), me);
        assert_eq!(said("mine.md"), Some(vec![three, two, one]));
        // The file written again, over the delete: a delete has no text,
        // and is named as a delete is.
        p.file("mine.md", "back\n");
        p.cycle();
        let over_the_delete = vec![link(None, me), three, two, one];
        assert_eq!(said("mine.md"), Some(over_the_delete));

        // Over another device's entry: the link names that device.
        p.other_writes("theirs.md", Some("one\n"));
        p.cycle();
        p.file("theirs.md", "two\n");
        p.cycle();
        let theirs = link(Some("one\n"), them);
        assert_eq!(said("theirs.md"), Some(vec![theirs]));
        // Over that one, both are named.
        p.file("theirs.md", "three\n");
        p.cycle();
        assert_eq!(said("theirs.md"), Some(vec![two, theirs]));

        // Over an entry that lacks its chain: the entry is named, and
        // nothing is copied, since it says nothing that could be.
        p.other_says("bare.md", "one\n", None);
        p.cycle();
        p.file("bare.md", "two\n");
        p.cycle();
        assert_eq!(said("bare.md"), Some(vec![theirs]));

        // Over something that is no version of a memory file (bytes that
        // are not a text, written through the API under the file's name).
        // The plan read no version of the file there, and the file is
        // published over what the slot holds all the same: the entry
        // names those bytes.
        deliver(&p.st, &p.other, NAME);
        let bytes = Value::Other(b"{\"not\":\"a text\"}".to_vec());
        write(&p.other, NAME, "api.md", bytes.clone());
        deliver(&p.other, &p.st, NAME);
        p.file("api.md", "a text\n");
        assert_eq!(p.cycle().published, 1);
        let of_the_bytes = Link::of(&bytes, them.identity.public_key());
        assert_eq!(said("api.md"), Some(vec![of_the_bytes]));

        // A conflict file is a new file: over nothing. And an index merged
        // with the channel's is over the channel's. The version that this
        // device's own file held is in that version's chain already, and
        // nothing is added for it.
        let index = crate::memory_md::INDEX_FILE;
        p.file(index, "- a\n");
        p.file("both.md", "base\n");
        assert_eq!(p.cycle().published, 2);
        p.file("both.md", "mine\n");
        p.file(index, "- a\n- mine\n");
        p.other_writes("both.md", Some("theirs\n"));
        p.other_writes(index, Some("- a\n- theirs\n"));
        let report = p.cycle();
        assert_eq!((report.conflicts, report.published), (1, 1), "{report:?}");
        assert_eq!(p.cycle().published, 1);
        assert_eq!(said("both.conflict-abcd.md"), Some(Vec::new()));
        let first = link(Some("- a\n"), me);
        let second = link(Some("- a\n- theirs\n"), them);
        assert_eq!(said(index), Some(vec![second, first]));

        // An index merged with a version that was written apart from this
        // device's own (the two tie at one revision, and the other's text
        // wins): it is over the channel's, the version that this device's
        // file held comes second, and what the two descend from follows
        // once.
        let mine = p.read(index).unwrap();
        let wins = a_text_above(&mine);
        write(&p.other, NAME, index, text(&wins));
        deliver(&p.other, &p.st, NAME);
        let (_, rev, counts) = version(&p.st, NAME, index).unwrap();
        assert_eq!((rev, counts.as_str()), (3, wins.as_str()));
        let report = p.cycle();
        assert_eq!((report.published, report.conflicts), (1, 0), "{report:?}");
        let apart = vec![
            link(Some(&wins), them),
            link(Some(&mine), me),
            second,
            first,
        ];
        assert_eq!(said(index), Some(apart));
    }

    /// What an entry says comes from the one entry of the version that the
    /// plan read, and from nothing else this device holds. Here a third
    /// device's entry for the file is held beside the channel's version,
    /// at a lower revision: it was never the version this device took,
    /// and it is not named.
    #[test]
    fn an_entry_names_only_what_it_was_written_over() {
        let p = Pair::new();
        let third = another_device(&p.st, &p.mem.with_file_name("third"), NAME);
        let (me, them) = (&p.st, &p.other);
        // The third device writes the file having seen nothing, and so
        // does the other; then the other writes it again.
        write(&third, NAME, "z.md", text("third\n"));
        p.other_writes("z.md", Some("one\n"));
        p.other_writes("z.md", Some("two\n"));
        deliver(&third, &p.st, NAME);
        // This device takes the other's second, and edits it.
        assert_eq!(p.cycle().pulled, 1);
        assert_eq!(p.read("z.md").as_deref(), Some("two\n"));
        p.file("z.md", "mine\n");
        assert_eq!(p.cycle().published, 1);
        let mut chain = vec![link(Some("two\n"), them), link(Some("one\n"), them)];
        assert_eq!(said(&p.st, NAME, "z.md"), Some(chain.clone()));

        // The same where the version held beside the channel's is at its
        // own revision. The other device and the third each write the
        // file over this device's version, neither with the other's, and
        // this device takes the one that counts: the one whose text has
        // the higher hash. The one that lost the tie is not named: this
        // device's entry was not written over it. Once with each of the
        // two as the one that counts.
        let mut mine = "mine\n".to_string();
        for (round, the_others_counts) in [true, false].into_iter().enumerate() {
            let between = format!("round {round}\n");
            let (higher, lower) = (a_text_above(&between), a_text_below(&between));
            let (others, thirds) = match the_others_counts {
                true => (higher.clone(), lower),
                false => (lower, higher.clone()),
            };
            deliver(&p.st, &third, NAME);
            write(&third, NAME, "z.md", text(&thirds));
            p.other_writes("z.md", Some(&others));
            deliver(&third, &p.st, NAME);
            let (_, rev, counts) = version(&p.st, NAME, "z.md").unwrap();
            assert_eq!((rev, &counts), (4 + 2 * round as u64, &higher));
            let report = p.cycle();
            assert_eq!((report.pulled, report.conflicts), (1, 0), "{report:?}");

            // Each of the two was written over this device's version, and
            // what this device writes now is written over the one that
            // counts.
            chain.insert(0, link(Some(&mine), me));
            let winner = if the_others_counts { them } else { &third };
            chain.insert(0, link(Some(&counts), winner));
            mine = format!("mine again, {round}\n");
            p.file("z.md", &mine);
            assert_eq!(p.cycle().published, 1);
            assert_eq!(said(&p.st, NAME, "z.md"), Some(chain.clone()), "{round}");
        }
    }

    /// An entry cannot have been written after a version at its own
    /// revision or a higher one, whatever its chain says: a chain is read
    /// only of a version at a higher revision than the one agreed. Here
    /// another device's entry lists this device's text in its chain. At a
    /// higher revision that is believed, and nothing is kept. At the
    /// revision this device wrote, and below the one its folder records,
    /// it is not, and this device's text is kept.
    #[test]
    fn what_a_chain_says_is_not_read_at_the_revision_agreed_or_below() {
        let p = Pair::new();
        let (me, them) = (&p.st, &p.other);
        let lists_mine = || Some(vec![link(Some("mine\n"), me)]);
        // At a higher revision: known to follow, and nothing is kept.
        p.file("y.md", "mine\n");
        assert_eq!(p.cycle().published, 1);
        p.other_says("y.md", "theirs\n", lists_mine());
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (1, 0), "{report:?}");

        // At the revision this device wrote, 1, with a text that wins the
        // tie: this device's text is kept.
        p.file("z.md", "mine\n");
        assert_eq!(p.cycle().published, 1);
        let wins = a_text_above("mine\n");
        entry_at(&p.other, NAME, "z.md", text(&wins), 1, lists_mine());
        deliver(&p.other, &p.st, NAME);
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
        assert_eq!(p.read("z.md").as_deref(), Some(wins.as_str()));
        assert_eq!(p.read("z.conflict-abcd.md").as_deref(), Some("mine\n"));
        assert_eq!(p.cycle().published, 1);

        // What this device then writes over that entry says what the
        // entry says: a chain is copied as it stands, and what it says
        // decided nothing where the revision did not follow.
        p.file("z.md", "mine again\n");
        assert_eq!(p.cycle().published, 1);
        let over_it = vec![link(Some(&wins), them), link(Some("mine\n"), me)];
        assert_eq!(said(&p.st, NAME, "z.md"), Some(over_it));

        // Below the revision that the folder records (the channel is at
        // a lower revision than the record, as for a folder whose records
        // are newer than the channel it meets): the same.
        p.file("w.md", "mine\n");
        let ahead = Agreed {
            hash: Some(Content::new("mine\n").hash),
            rev: 5,
            signer: Some(me.identity.public_key()),
            chain: Some(Vec::new()),
        };
        let folder = p.mem.display().to_string();
        sync_state::save(
            &p.st.db.lock().unwrap(),
            &folder,
            &p.channel,
            "w.md",
            &ahead,
        )
        .unwrap();
        p.other_says("w.md", "theirs\n", lists_mine());
        assert_eq!(version(&p.st, NAME, "w.md").unwrap().1, 1);
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
        assert_eq!(p.read("w.md").as_deref(), Some("theirs\n"));
        assert_eq!(p.read("w.conflict-abcd.md").as_deref(), Some("mine\n"));
    }

    /// What a folder records of a file is one entry of the channel's
    /// version (decision 2026-10-04 §2.3): its text, its revision, the key
    /// that signed the entry, and the entry's chain. A row that says
    /// nothing of the entry (one from before that was kept) makes nothing
    /// known, and a cycle that finds it in step with the channel gives it
    /// what the channel's version says.
    #[test]
    fn a_record_keeps_the_signer_and_the_chain_of_the_entry_it_agrees_with() {
        let p = Pair::new();
        let me = p.st.identity.public_key();
        let them = p.other.identity.public_key();
        let hash = |text: &str| Some(Content::new(text).hash);
        let record = |name: &str| p.record(name).unwrap();
        // The rows say nothing of the entries any more.
        let rows_say_nothing = || {
            let db = p.st.db.lock().unwrap();
            db.execute("UPDATE sync_files SET author = NULL, chain = NULL", [])
                .unwrap();
        };
        // What an entry written over this device's first entry of a file
        // says.
        let over_one = || Some(vec![link(Some("one\n"), &p.st)]);

        // Published here: this device's entry.
        for name in ["a.md", "b.md", "c.md", "d.md"] {
            p.file(name, "one\n");
        }
        p.cycle();
        let first = Agreed {
            hash: hash("one\n"),
            rev: 1,
            signer: Some(me),
            chain: Some(Vec::new()),
        };
        assert_eq!(
            (record("a.md"), record("b.md")),
            (first.clone(), first.clone())
        );
        // Pulled, or removed for a delete: the entry of the channel's
        // version, as the device that signed it wrote it.
        p.other_says("a.md", "two\n", over_one());
        p.other_puts("b.md", None, over_one());
        p.other_writes("c.md", Some("two\n"));
        p.other_writes("d.md", None);
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (4, 0), "{report:?}");
        let taken = Agreed {
            hash: hash("two\n"),
            rev: 2,
            signer: Some(them),
            chain: over_one(),
        };
        let removed = Agreed {
            hash: None,
            ..taken.clone()
        };
        assert_eq!(
            (record("a.md"), record("b.md")),
            (taken.clone(), removed.clone())
        );
        assert_eq!((record("c.md"), record("d.md")), (taken.clone(), removed));
        // Deleted here: this device's entry, written over the other's.
        std::fs::remove_file(p.mem.join("a.md")).unwrap();
        p.cycle();
        let deleted = Agreed {
            hash: None,
            rev: 3,
            signer: Some(me),
            chain: Some(vec![
                link(Some("two\n"), &p.other),
                link(Some("one\n"), &p.st),
            ]),
        };
        assert_eq!(record("a.md"), deleted);
        // A merged index is an entry that this device writes: this device.
        p.file("MEMORY.md", "- mine\n");
        p.cycle();
        p.other_writes("MEMORY.md", Some("- theirs\n"));
        p.file("MEMORY.md", "- mine\n- more\n");
        let report = p.cycle();
        assert_eq!((report.published, report.conflicts), (1, 0), "{report:?}");
        let merged = record("MEMORY.md");
        assert_eq!((merged.rev, merged.signer), (3, Some(me)));
        assert_eq!(merged.hash, hash(&p.read("MEMORY.md").unwrap()));
        let over_theirs = vec![
            link(Some("- theirs\n"), &p.other),
            link(Some("- mine\n"), &p.st),
        ];
        assert_eq!(merged.chain, Some(over_theirs));
        assert_eq!(merged.chain, said(&p.st, NAME, "MEMORY.md"));

        // A row that says nothing of the entry, and a version of the
        // channel's whose chain shows nothing: it is not known to follow,
        // as with any row, and what the file held is kept. (Nothing is
        // taken by its revision alone.)
        p.file("old.md", "one\n");
        p.file("new.md", "one\n");
        p.file("known.md", "one\n");
        p.cycle();
        rows_say_nothing();
        let unsaid = Agreed {
            signer: None,
            chain: None,
            ..first.clone()
        };
        assert_eq!(record("old.md"), unsaid);
        p.other_says("old.md", "two\n", Some(Vec::new()));
        // With such a row the chain still decides, as with any: a version
        // whose chain holds the agreed text is taken, and nothing is kept.
        p.other_writes("known.md", Some("two\n"));
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (2, 1), "{report:?}");
        assert_eq!(p.read("old.conflict-abcd.md").as_deref(), Some("one\n"));
        assert_eq!(p.read("known.conflict-abcd.md"), None);
        let shows_nothing = Agreed {
            chain: Some(Vec::new()),
            ..taken.clone()
        };
        assert_eq!(
            (record("old.md"), record("known.md")),
            (shows_nothing, taken)
        );

        // A cycle that has nothing to do for a file gives its row the
        // entry of the channel's version.
        rows_say_nothing();
        assert_eq!(record("new.md"), unsaid);
        assert_eq!(p.cycle().pulled, 0);
        assert_eq!(record("new.md"), first);
        // And a version that is not known to follow it has what the file
        // held kept first.
        p.other_says("new.md", "two\n", Some(Vec::new()));
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
        assert_eq!(p.read("new.conflict-abcd.md").as_deref(), Some("one\n"));
        assert_eq!(p.read("new.md").as_deref(), Some("two\n"));
    }

    /// That a version was signed by the key that signed the entry a
    /// folder records shows nothing: a device's later version need not
    /// descend from its earlier one. Here another device publishes this
    /// device's text again, a revision on, and the folder's record is
    /// then of that device's entry. What that device writes later, over
    /// another text (from a folder that held something else), is not
    /// known to follow: the text is kept.
    ///
    /// The entries here are made by hand, to show the rule alone: no two
    /// devices come to them by syncing.
    #[test]
    fn a_text_is_kept_from_what_the_publisher_of_its_entry_writes_later() {
        let p = Pair::new();
        let them = p.other.identity.public_key();
        p.file("notes.md", "mine\n");
        assert_eq!(p.cycle().published, 1);
        // The other device publishes the same text again, a revision on.
        p.other_writes("notes.md", Some("mine\n"));
        let report = p.cycle();
        assert_eq!((report.pulled, report.published), (0, 0), "{report:?}");
        let record = p.record("notes.md").unwrap();
        assert_eq!((record.rev, record.signer), (2, Some(them)));
        // Its next entry is written over another text: from a folder that
        // held something else.
        let later = Some(vec![link(Some("something else\n"), &p.other)]);
        p.other_says("notes.md", "theirs\n", later);
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
        assert_eq!(p.read("notes.md").as_deref(), Some("theirs\n"));
        let kept = p.read("notes.conflict-abcd.md");
        assert_eq!(kept.as_deref(), Some("mine\n"));
    }

    /// Where what a file holds was to be kept before a version at a higher
    /// revision is taken, and cannot be kept, the file is left as it is:
    /// not written over, and not removed. The text is kept first, and only
    /// then is the version taken.
    #[test]
    fn a_file_that_is_overtaken_is_left_where_its_text_cannot_be_kept() {
        let p = Pair::new();
        // The chain of a new file's entry: it shows nothing.
        let unseen = || Some(Vec::new());
        p.file("text.md", "mine\n");
        p.file("gone.md", "mine too\n");
        assert_eq!(p.cycle().published, 2);
        // The other device writes one and deletes the other, and neither
        // entry shows that this device's text was in front of it.
        p.other_says("text.md", "theirs\n", unseen());
        p.other_puts("gone.md", None, unseen());
        // Something is in the way of each copy.
        let in_the_way: Vec<PathBuf> = ["text.md", "gone.md"]
            .iter()
            .map(|name| temporary_name(&names::conflict_name(name, "abcd")))
            .map(|temporary| p.mem.join(temporary))
            .collect();
        for path in &in_the_way {
            std::fs::create_dir(path).unwrap();
        }
        let report = p.cycle();
        assert_eq!(
            (report.pulled, report.conflicts, report.failed.len()),
            (0, 0, 2),
            "{report:?}"
        );
        assert_eq!(p.read("text.md").as_deref(), Some("mine\n"));
        assert_eq!(p.read("gone.md").as_deref(), Some("mine too\n"));

        // With nothing in the way each text is kept. One file takes the
        // channel's version, and the other goes.
        for path in &in_the_way {
            std::fs::remove_dir(path).unwrap();
        }
        let report = p.cycle();
        assert_eq!(
            (report.pulled, report.conflicts, report.failed.len()),
            (2, 2, 0),
            "{report:?}"
        );
        assert_eq!(p.read("text.md").as_deref(), Some("theirs\n"));
        assert_eq!(p.read("gone.md"), None);
        assert_eq!(p.read("text.conflict-abcd.md").as_deref(), Some("mine\n"));
        let kept = p.read("gone.conflict-abcd.md");
        assert_eq!(kept.as_deref(), Some("mine too\n"));
    }

    /// A text that is overtaken twice is kept twice. The first copy has
    /// been to the other device, which deleted it as a conflict that was
    /// done with, not knowing that the text was back in the file here and
    /// about to be overtaken again.
    #[test]
    fn a_text_overtaken_twice_is_kept_twice() {
        let p = Pair::new();
        let (first, second) = ("notes.conflict-abcd", "notes.conflict-abcd-2");
        // The chain of a new file's entry: it shows nothing.
        let unseen = || Some(Vec::new());
        p.file("notes", "mine\n");
        assert_eq!(p.cycle().published, 1);
        // The other device writes the file without having had this
        // device's text in front of it. The text here is kept, and the
        // copy is published.
        p.other_says("notes", "theirs\n", unseen());
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
        assert_eq!(p.read(first).as_deref(), Some("mine\n"));
        assert_eq!(p.cycle().published, 1);

        // The person puts the text back in the file here. On the other
        // device, meanwhile, the copy is deleted and the file is written
        // again, without sight of that.
        p.file("notes", "mine\n");
        assert_eq!(p.cycle().published, 1);
        p.other_says("notes", "theirs again\n", unseen());
        p.other_writes(first, None);
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (2, 1), "{report:?}");
        assert_eq!(p.read("notes").as_deref(), Some("theirs again\n"));
        assert_eq!(p.read(first), None);
        assert_eq!(p.read(second).as_deref(), Some("mine\n"));
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
        // Something is in the way of the temporary file that the second
        // file is written through, so the file cannot be written.
        let in_the_way = p.mem.join(temporary_name("b.md"));
        std::fs::create_dir(&in_the_way).unwrap();
        let hidden = || -> Vec<String> {
            std::fs::read_dir(&p.mem)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .filter(|name| name.starts_with('.'))
                .collect()
        };
        // It fails in each cycle, and each says so.
        for pulled in [2, 0] {
            let report = p.cycle();
            assert_eq!(p.read("a.md").as_deref(), Some("a\n"));
            assert_eq!(p.read("c.md").as_deref(), Some("c\n"), "the file after it");
            assert_eq!(report.pulled, pulled, "{report:?}");
            let failed: Vec<&str> = report.failed.iter().map(|f| f.name.as_str()).collect();
            assert_eq!(failed, ["b.md"], "{report:?}");
            assert!(!report.failed[0].error.is_empty(), "{report:?}");
            assert!(report.error.is_none(), "{report:?}");
            assert_eq!(p.read("b.md"), None);
        }
        // With nothing in the way, the next cycle writes the file.
        std::fs::remove_dir(&in_the_way).unwrap();
        let report = p.cycle();
        assert_eq!((report.pulled, report.failed.len()), (1, 0), "{report:?}");
        assert_eq!(p.read("b.md").as_deref(), Some("b\n"));
        assert!(hidden().is_empty(), "{:?}", hidden());

        // A folder that takes a file's name once the cycle has read what
        // is there: the name is no longer as the cycle saw it, so nothing
        // is written there, no temporary file is left, and it is no
        // failure. The next cycle plans with what is there.
        p.other_writes("d.md", Some("d\n"));
        let in_the_way = p.mem.join("d.md");
        let report = p.cycle_with(&|| std::fs::create_dir(&in_the_way).unwrap());
        assert_eq!((report.pulled, report.failed.len()), (0, 0), "{report:?}");
        assert!(in_the_way.is_dir());
        assert!(hidden().is_empty(), "{:?}", hidden());
        // While the folder is there the name takes no part: it is listed
        // as something that cannot sync, and is no failure.
        let report = p.cycle();
        assert_eq!((report.pulled, report.failed.len()), (0, 0), "{report:?}");
        assert_eq!(report.skipped, ["d.md"], "{report:?}");

        // With the folder gone, the next cycle writes the file.
        std::fs::remove_dir(&in_the_way).unwrap();
        let report = p.cycle();
        assert_eq!((report.pulled, report.failed.len()), (1, 0), "{report:?}");
        assert_eq!(p.read("d.md").as_deref(), Some("d\n"));
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
            p.other_deletes_unsent(&first);
            // Here, meanwhile, the copy's text is put back in the file.
            p.file(file, "mine\n");
            let report = p.cycle();
            assert_eq!((report.pulled, report.conflicts), (1, 1), "{report:?}");
            assert_eq!(p.read(&first).as_deref(), Some("mine\n"), "{file}");
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{file}");

            // The delete arrives.
            deliver(&p.other, &p.st, NAME);
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
            p.other_deletes_unsent(&first);
            // Here the folder forgets, and the copy's text is put back in
            // the file.
            p.forgets();
            p.file(file, "mine\n");
            p.cycle();
            assert_eq!(p.read(&first).as_deref(), Some("mine\n"), "{file}");
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{file}");

            // The delete arrives.
            deliver(&p.other, &p.st, NAME);
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
            p.other_deletes_unsent(&first);
            p.forgets();
            p.file(file, "mine\n");
            p.cycle();
            assert_eq!(p.read(file).as_deref(), Some("theirs\n"), "{file}");
            assert_eq!(p.read(&second).as_deref(), Some("mine\n"), "{file}");

            // The delete arrives.
            deliver(&p.other, &p.st, NAME);
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
            p.other_deletes_unsent(&first);
            if forgets {
                p.forgets();
            }
            p.file(file, "mine\n");
            p.cycle_with(&|| deliver(&p.other, &p.st, NAME));
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
            p.other_deletes_unsent(&first);
            std::fs::rename(p.mem.join(&first), p.mem.join(file)).unwrap();
            p.cycle_with(&|| deliver(&p.other, &p.st, NAME));
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
        deliver(&p.st, &p.other, NAME);
        let no_text = Value::Other(b"{\"no\":\"text\"}".to_vec());
        write(&p.other, NAME, &first, no_text);
        deliver(&p.other, &p.st, NAME);
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
        let report = p
            .try_cycle_with(&|| rename("entries", "entries_away"))
            .unwrap();
        rename("entries_away", "entries");
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

    /// Where the node cannot run git, no found entry carries its
    /// directory under `cwd` (decision 2026-10-04 §10.1): the repository
    /// that the directory may be in is not known, and whoever has git
    /// would map the repository above it. The adapter answers the one
    /// function from what it read when it looked at the folder.
    #[test]
    fn test_a_folder_found_where_git_cannot_be_run_has_no_cwd() {
        use found::Machine;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().canonicalize().unwrap();
        let notes = home.join("notes");
        std::fs::create_dir_all(&notes).unwrap();
        let claude = home.join(".claude");
        let folder = found::claude_folder(&claude, &notes).unwrap();
        let entry = |git: bool| {
            let asked = found::Asked {
                folder: &folder,
                directory: Some(&notes),
                name: Some("lab"),
            };
            let against = found::Against {
                claude_dir: &claude,
                home: Some(&home),
                mappings: &[],
            };
            found::Entry::of(&asked, &against, &Looked { git })
        };
        let with_git = entry(true);
        assert!(with_git.mappable, "{with_git:?}");
        assert_eq!(with_git.cwd, Some(notes.display().to_string()));
        let without = entry(false);
        assert!(!without.mappable, "{without:?}");
        assert_eq!(without.cwd, None);
        assert_eq!(without.directory, Some(notes.display().to_string()));
        assert_eq!(without.why_not, Some("git_not_run"));
        // The directory is asked of the disk each time.
        assert!(Looked { git: true }.is_dir(&notes));
        assert!(!Looked { git: true }.is_dir(&home.join("gone")));
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
    /// for it at the highest revision there is under the statement, so
    /// nothing can be written after it until the next statement (decision
    /// 2026-10-04 §2.3). The file is reported, and the file after it is
    /// published.
    #[test]
    fn a_name_whose_revisions_are_used_up_fails_alone() {
        let p = Pair::new();
        p.file("a.md", "one\n");
        p.file("b.md", "one\n");
        assert_eq!(p.cycle().published, 2);
        let over_one = Some(vec![link(Some("one\n"), &p.st)]);
        let at_the_limit = text("at the limit\n");
        entry_at(&p.other, NAME, "a.md", at_the_limit, LAST_REV, over_one);
        deliver(&p.other, &p.st, NAME);
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (1, 0), "{report:?}");

        p.file("a.md", "two\n");
        p.file("b.md", "two\n");
        let report = p.cycle();
        assert_eq!(report.published, 1, "{report:?}");
        assert_eq!(report.failed.len(), 1, "{report:?}");
        assert_eq!(report.failed[0].name, "a.md");
        assert!(
            report.failed[0].error.contains("no revision is left"),
            "{report:?}"
        );
        assert_eq!(p.held("b.md").as_deref(), Some("two\n"));
        assert_eq!(p.held("a.md").as_deref(), Some("at the limit\n"));

        // The same for a file that arrived at that revision as a new
        // file: an edit of it has no revision to be published at.
        write_at(&p.other, NAME, "c.md", "at the limit\n", LAST_REV);
        deliver(&p.other, &p.st, NAME);
        assert_eq!(p.cycle().pulled, 1);
        p.file("c.md", "two\n");
        let report = p.cycle();
        let failed: Vec<&str> = report.failed.iter().map(|f| f.name.as_str()).collect();
        assert_eq!((report.published, failed), (0, vec!["a.md", "c.md"]));
        assert_eq!(p.held("c.md").as_deref(), Some("at the limit\n"));
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
        assert!(p.deleted("a.md"));
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
        assert!(p.deleted("Notes.md"));
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
        assert!(p.deleted("a.md"));
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
    /// text and this version, and what the channel holds under its name is
    /// what was written down: what was there when the name was taken, or
    /// the entry the folder published the copy as. An agreement for the
    /// file ends it, and so does a change of settings. A name is not taken
    /// while the channel has a text under it, or once the settings have
    /// changed.
    #[test]
    fn the_copy_is_the_one_the_folder_wrote_down() {
        let p = Pair::new();
        let copy = "notes.conflict-abcd.md";
        let version = write(&p.st, NAME, "notes.md", text("theirs\n"));
        let folder = p.mem.display().to_string();
        let none = HashMap::new();
        let is = |planned: &PlannedAgainst, name: &str, text: &str| {
            let ctx = ctx_of(&p.st, &p.mem, &p.channel, &folder, planned, &none);
            is_the_copy(&ctx, "notes.md", name, text).unwrap()
        };
        let take = || {
            let ctx = ctx_of(&p.st, &p.mem, &p.channel, &folder, &version, &none);
            claim(&ctx, "notes.md", copy, "mine\n").unwrap()
        };
        // What the channel holds under the copy's name now.
        let under = || {
            let db = p.st.db.lock().unwrap();
            PlannedAgainst::what_is_in(&publish::read(&db, NAME, copy).unwrap().slot)
        };
        // The folder publishes `text` under the copy's name, over what
        // the channel holds there.
        let publishes = |text: &str| {
            let over = under();
            let ctx = ctx_of(&p.st, &p.mem, &p.channel, &folder, &over, &none);
            let publish = Action::Publish(text.into());
            let done = apply(&ctx, copy, None, publish, &mut FolderReport::default());
            assert!(matches!(done, Ok(true)), "{done:?}");
        };

        // Nothing written down: no copy.
        assert!(!is(&version, copy, "mine\n"));
        // Taken and written down, with nothing under its name then or now.
        assert_eq!(take(), Claim::Taken);
        assert!(is(&version, copy, "mine\n"));
        // For this copy, this text, this version and this file, and no
        // other.
        assert!(!is(&version, "notes.conflict-abcd-2.md", "mine\n"));
        assert!(!is(&version, copy, "another\n"));
        let another = write(&p.st, NAME, "another.md", text("theirs\n"));
        assert!(!is(&another, copy, "mine\n"));
        // Nor for that version with another entry held of it.
        let PlannedAgainst::Version {
            rev,
            kind,
            hash,
            entries,
        } = version.clone()
        else {
            panic!("{version:?}");
        };
        let with_another_entry = PlannedAgainst::Version {
            rev,
            kind,
            hash,
            entries: [entries, vec![[9; 32]]].concat(),
        };
        assert!(!is(&with_another_entry, copy, "mine\n"));
        assert!(!is(&PlannedAgainst::NoVersion, copy, "mine\n"));
        let ctx = ctx_of(&p.st, &p.mem, &p.channel, &folder, &version, &none);
        assert!(!is_the_copy(&ctx, "other.md", copy, "mine\n").unwrap());

        // Published by the folder, it is still the copy: the folder writes
        // down the entry it published it as.
        publishes("mine\n");
        assert!(is(&version, copy, "mine\n"));
        // An entry with another text that the folder publishes there is
        // not the copy's.
        publishes("edited here\n");
        assert!(!is(&version, copy, "mine\n"));
        // Nor is this device's own entry with the text, where the folder
        // did not publish it for the copy.
        write(&p.st, NAME, copy, text("mine\n"));
        assert!(!is(&version, copy, "mine\n"));
        // And the name is not taken while the channel has a text under
        // it, this device's own or not: nothing is written down.
        assert_eq!(take(), Claim::InUse);
        assert!(!is(&version, copy, "mine\n"));

        // What the channel has under the name when it is taken is no
        // arrival: taken over a delete, it is the copy until something
        // else counts there, whatever that is.
        p.other_writes(copy, None);
        assert!(!is(&version, copy, "mine\n"));
        assert_eq!(take(), Claim::Taken);
        assert!(is(&version, copy, "mine\n"));
        entry_at(&p.st, NAME, copy, Value::Delete, 9, Some(Vec::new()));
        assert!(!is(&version, copy, "mine\n"));
        assert_eq!(take(), Claim::Taken);
        assert!(is(&version, copy, "mine\n"));
        p.other_writes(copy, Some("mine\n"));
        assert!(!is(&version, copy, "mine\n"));
        assert_eq!(take(), Claim::InUse);

        // A name that the folder had this very text agreed under is not
        // taken either.
        p.other_writes(copy, None);
        let mine = Some(Content::new("mine\n").hash);
        let had: HashMap<String, Agreed> = [(copy.to_string(), agreed_at(mine, 1))].into();
        let agreed = ctx_of(&p.st, &p.mem, &p.channel, &folder, &version, &had);
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
        assert!(is(&version, copy, "mine\n"));
        let generation = p.st.sync_control.generation();
        let agreement = agreed_at(None, 1);
        record_agreed(
            &p.st, generation, &folder, &p.channel, "notes.md", &agreement,
        )
        .unwrap();
        assert!(!is(&version, copy, "mine\n"));

        // A name taken where the plan read no version of the file is the
        // copy for a plan that read none, and for no other.
        let read_none = PlannedAgainst::NoVersion;
        let ctx = ctx_of(&p.st, &p.mem, &p.channel, &folder, &read_none, &none);
        assert_eq!(
            claim(&ctx, "notes.md", copy, "mine\n").unwrap(),
            Claim::Taken
        );
        assert!(is(&read_none, copy, "mine\n"));
        assert!(!is(&version, copy, "mine\n"));

        // A change of settings ends it, and the name is not taken by a
        // cycle that began before the change.
        assert_eq!(take(), Claim::Taken);
        let before = ctx_of(&p.st, &p.mem, &p.channel, &folder, &version, &none);
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
        let theirs = Some(Content::new("theirs\n").hash);
        let replaced = [
            (
                "notes.md",
                Action::Pull {
                    text: "theirs\n".into(),
                    agreed: agreed_at(theirs, 1),
                },
            ),
            (
                "notes.md",
                Action::RemoveFile {
                    agreed: agreed_at(None, 1),
                },
            ),
            (index, Action::Merge("- [A](a.md) a\n".into())),
        ];
        for (file, action) in replaced {
            let p = Pair::new();
            p.file(file, "mine\n");
            let seen = Some(Content::new("mine\n").hash);
            let version = write(&p.st, NAME, file, text("theirs\n"));
            let folder = p.mem.display().to_string();
            let none = HashMap::new();
            let ctx = ctx_of(&p.st, &p.mem, &p.channel, &folder, &version, &none);
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
    ///
    /// The records are read, and a write of one is refused. (A database
    /// that takes no write at all cannot be read either: a channel is read
    /// in a transaction that takes the database for writing, and the
    /// folder's cycle then ends before it does anything.)
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
            db("CREATE TEMP TRIGGER no_record BEFORE INSERT ON sync_files
                BEGIN SELECT RAISE(ABORT, 'no record can be written'); END");
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
            db("DROP TRIGGER no_record");
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
        assert_eq!(held(&p.st, NAME).len(), 1);
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
        let (_, rev, _) = version(&p.st, NAME, index).unwrap();
        let report = p.cycle();
        assert_eq!((report.published, report.pulled), (0, 1), "{report:?}");
        assert_eq!(p.read(index).as_deref(), Some(theirs));
        let (_, now, text) = version(&p.st, NAME, index).unwrap();
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

    /// The bookkeeping of a cycle is done under the settings the cycle
    /// read, or not at all. A name worked out from settings that have
    /// since changed is not held or said, a word is not taken back on
    /// their say, and nothing is forgotten on it: a folder the new
    /// settings sync would not be among those the old ones kept.
    #[test]
    fn nothing_is_concluded_from_settings_that_have_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let st = state(tmp.path());
        let channel = with_phrase(&st, NAME);
        // The names this device says that it syncs, in the personal
        // channel.
        let said = |st: &AppState| -> Vec<String> {
            let db = st.db.lock().unwrap();
            let said = said_names::said_here(&db, &st.identity).unwrap();
            said.into_iter().collect()
        };
        let agreed = |st: &AppState| -> usize {
            let db = st.db.lock().unwrap();
            sync_state::load(&db, "/a/memory", &channel).unwrap().len()
        };
        let agreement = agreed_at(None, 1);
        sync_state::save(
            &st.db.lock().unwrap(),
            "/a/memory",
            &channel,
            "notes.md",
            &agreement,
        )
        .unwrap();

        // A cycle that began before a change of settings comes to a folder
        // that syncs a name: the name is not held, and nothing is said.
        let started = st.sync_control.generation();
        st.sync_control.changed(&st.db.lock().unwrap());
        let late = name_channel(&st, "/a/memory", "one", started).unwrap();
        assert!(matches!(late, Channel::Stopped));
        assert!(said(&st).is_empty());
        let held = |st: &AppState, name: &str| {
            let db = st.db.lock().unwrap();
            held_rows::channel_of_name(&db, name).unwrap().is_some()
        };
        assert!(!held(&st, "one"));
        // Under the settings as they are, it is held and said.
        let now = st.sync_control.generation();
        let ready = name_channel(&st, "/a/memory", "one", now).unwrap();
        assert!(matches!(ready, Channel::Ready(_)));
        assert_eq!(said(&st), ["one"]);
        assert!(held(&st, "one"));

        // The settings change again, and no folder syncs the name any
        // more. A cycle that began before takes no word back, and forgets
        // nothing.
        let nothing: BTreeSet<String> = BTreeSet::new();
        let started = now;
        st.sync_control.changed(&st.db.lock().unwrap());
        // Nor is the device offered the name, which only it lists: what
        // is offered is what another device syncs.
        let offered = exchange_names(&st, &nothing, started).unwrap();
        assert!(offered.is_empty(), "{offered:?}");
        forget_other_folders(&st, &[], started).unwrap();
        assert_eq!((said(&st).len(), agreed(&st)), (1, 1));
        assert!(held(&st, "one"));

        let now = st.sync_control.generation();
        exchange_names(&st, &nothing, now).unwrap();
        forget_other_folders(&st, &[], now).unwrap();
        assert_eq!((said(&st).len(), agreed(&st)), (0, 0));
        assert!(!held(&st, "one"));

        // Withdrawing, once sync is off, is the same: it is done under the
        // count read with that setting, or not at all, and says which.
        // Sync may be on again.
        let ready = name_channel(&st, "/a/memory", "one", now).unwrap();
        assert!(matches!(ready, Channel::Ready(_)));
        assert_eq!(said(&st), ["one"]);
        st.sync_control.changed(&st.db.lock().unwrap());
        assert!(!withdraw(&st, now).unwrap());
        assert_eq!(said(&st), ["one"]);
        assert!(withdraw(&st, st.sync_control.generation()).unwrap());
        assert!(said(&st).is_empty());
    }

    /// What `st` has kept in history, in no order: for each record its
    /// file, its change, the text it keeps, and all it says.
    type Kept4 = (String, history::Change, Option<String>, history::About);

    impl Pair {
        /// Turn local history on for `st`.
        fn with_history(self) -> (Self, history::Store) {
            let store = history::Store::new(&self.st.home_dir, 30, 1 << 24).unwrap();
            self.st.history.open(Some(store.clone()));
            (self, store)
        }

        /// A key as a history record shows it.
        fn shown(key: &[u8; 32]) -> String {
            cordelia_crypto::bech32::encode_public_key(key).unwrap()
        }
    }

    /// The records in `store`, sorted by file and then by the text kept.
    /// Nothing may be left pending.
    fn kept_in(store: &history::Store) -> Vec<Kept4> {
        let listing = store.list().unwrap();
        assert!(listing.unreadable.is_empty());
        let mut records: Vec<Kept4> = listing
            .records
            .iter()
            .map(|record| {
                let (read, text) = store.read(&record.id).unwrap().unwrap();
                assert!(!read.interrupted);
                let about = record.about.clone();
                (about.file.clone(), about.change, text, about)
            })
            .collect();
        let held: u64 = listing.records.iter().map(|record| record.bytes).sum();
        assert_eq!(held, listing.bytes, "a record was left pending");
        records.sort_by(|a, b| (&a.0, &a.2).cmp(&(&b.0, &b.2)));
        records
    }

    /// The file, the change and the text of each record.
    fn briefly(records: &[Kept4]) -> Vec<(&str, history::Change, Option<&str>)> {
        records
            .iter()
            .map(|(file, change, text, _)| (file.as_str(), *change, text.as_deref()))
            .collect()
    }

    /// Each change that replaces or removes a file's text here keeps the
    /// file as it was, and says what replaced it. A file that arrives is
    /// noted with no text. A first publish replaces nothing and keeps
    /// nothing (decision 2026-09-30 §4.5b).
    #[test]
    fn what_another_devices_change_replaces_here_is_kept_in_history() {
        use history::{Change, Replacement, Whose};
        let (p, store) = Pair::new().with_history();
        let them = Pair::shown(&p.other.identity.public_key());
        let folder = p.mem.display().to_string();

        // A first publish: nothing is replaced.
        p.file("notes.md", "one\n");
        assert_eq!(p.cycle().published, 1);
        assert_eq!(kept_in(&store), []);

        // Another device's version replaces the file here.
        p.other_writes("notes.md", Some("two\n"));
        assert_eq!(p.cycle().pulled, 1);
        let records = kept_in(&store);
        assert_eq!(
            briefly(&records),
            [("notes.md", Change::Pulled, Some("one\n"))]
        );
        let about = &records[0].3;
        assert_eq!((about.agent.as_str(), &about.folder), (NAME, &folder));
        let kept = about.kept.as_ref().unwrap();
        assert_eq!(kept.whose, Whose::Here { agreed: Some(1) });
        assert_eq!(kept.sha256, hex::encode(Content::new("one\n").hash));
        let theirs = history::Entry {
            device: them.clone(),
            rev: 2,
        };
        assert_eq!(about.replaced_by, Replacement::Entry(theirs));
        // The file here was the version agreed, and what replaced it was
        // written after it.
        assert!(about.behind);

        // A file arrives that was not here: noted, with no text.
        p.other_writes("new.md", Some("theirs\n"));
        assert_eq!(p.cycle().pulled, 1);
        let records = kept_in(&store);
        assert_eq!(
            briefly(&records),
            [
                ("new.md", Change::Arrived, None),
                ("notes.md", Change::Pulled, Some("one\n"))
            ]
        );
        let about = &records[0].3;
        assert_eq!(about.kept, None);
        let arrived = history::Entry {
            device: them.clone(),
            rev: 1,
        };
        assert_eq!(about.replaced_by, Replacement::Entry(arrived));
        assert!(!about.behind);

        // Another device's delete removes the file here.
        p.other_writes("notes.md", None);
        assert_eq!(p.cycle().pulled, 1);
        assert_eq!(p.read("notes.md"), None);
        let records = kept_in(&store);
        assert_eq!(
            briefly(&records),
            [
                ("new.md", Change::Arrived, None),
                ("notes.md", Change::Pulled, Some("one\n")),
                ("notes.md", Change::Removed, Some("two\n"))
            ]
        );
        // What took its place is the delete, and the record names the
        // key that signed it.
        let about = &records[2].3;
        let delete = history::Entry {
            device: them,
            rev: 3,
        };
        assert_eq!(about.replaced_by, Replacement::Entry(delete));
        assert_eq!(
            about.kept.as_ref().unwrap().whose,
            Whose::Here { agreed: Some(2) }
        );
        assert!(!about.behind);
    }

    /// An edit of this device's that another device overtook is kept
    /// beside the file, and the text that the channel's version then
    /// replaces is kept in history too. It was not behind: it is this
    /// device's own.
    #[test]
    fn an_edit_that_was_overtaken_is_kept_in_history_as_well() {
        use history::Change;
        let (p, store) = Pair::new().with_history();
        p.file("notes.md", "one\n");
        assert_eq!(p.cycle().published, 1);
        p.file("notes.md", "mine\n");
        p.other_writes("notes.md", Some("theirs\n"));
        let report = p.cycle();
        assert_eq!((report.conflicts, report.pulled), (1, 1), "{report:?}");
        let records = kept_in(&store);
        assert_eq!(
            briefly(&records),
            [("notes.md", Change::Pulled, Some("mine\n"))]
        );
        assert!(!records[0].3.behind);
        // The copy is a new file: its publish replaces nothing.
        assert_eq!(p.cycle().published, 1);
        assert_eq!(kept_in(&store).len(), 1);
    }

    /// An edit or a delete made here replaces the channel's version: that
    /// version is kept, whoever wrote it. A publish over a delete replaces
    /// no text and keeps nothing.
    #[test]
    fn what_this_devices_change_replaces_in_the_channel_is_kept_in_history() {
        use history::{Change, Replacement, Whose};
        let (p, store) = Pair::new().with_history();
        let me = Pair::shown(&p.st.identity.public_key());
        let them = Pair::shown(&p.other.identity.public_key());
        let entry = |device: &str, rev: u64| history::Entry {
            device: device.to_string(),
            rev,
        };

        // An edit over this device's own version.
        p.file("notes.md", "one\n");
        assert_eq!(p.cycle().published, 1);
        p.file("notes.md", "two\n");
        assert_eq!(p.cycle().published, 1);
        let records = kept_in(&store);
        assert_eq!(
            briefly(&records),
            [("notes.md", Change::EditedHere, Some("one\n"))]
        );
        let about = &records[0].3;
        assert_eq!(about.agent, NAME);
        assert_eq!(
            about.kept.as_ref().unwrap().whose,
            Whose::Channel(entry(&me, 1))
        );
        assert_eq!(about.replaced_by, Replacement::Entry(entry(&me, 2)));
        assert!(!about.behind);

        // An edit over another device's version.
        p.other_writes("notes.md", Some("theirs\n"));
        assert_eq!(p.cycle().pulled, 1);
        p.file("notes.md", "four\n");
        assert_eq!(p.cycle().published, 1);
        let records = kept_in(&store);
        assert_eq!(
            briefly(&records),
            [
                ("notes.md", Change::EditedHere, Some("one\n")),
                ("notes.md", Change::EditedHere, Some("theirs\n")),
                ("notes.md", Change::Pulled, Some("two\n"))
            ]
        );
        let about = &records[1].3;
        assert_eq!(
            about.kept.as_ref().unwrap().whose,
            Whose::Channel(entry(&them, 3))
        );
        assert_eq!(about.replaced_by, Replacement::Entry(entry(&me, 4)));

        // A delete made here.
        std::fs::remove_file(p.mem.join("notes.md")).unwrap();
        assert_eq!(p.cycle().published, 1);
        let records = kept_in(&store);
        assert_eq!(records.len(), 4);
        let (file, change, text, about) = &records[0];
        assert_eq!(
            (file.as_str(), *change, text.as_deref()),
            ("notes.md", Change::DeletedHere, Some("four\n"))
        );
        assert_eq!(
            about.kept.as_ref().unwrap().whose,
            Whose::Channel(entry(&me, 4))
        );
        assert_eq!(about.replaced_by, Replacement::Entry(entry(&me, 5)));

        // A publish over a delete: no text is replaced.
        p.file("notes.md", "back\n");
        assert_eq!(p.cycle().published, 1);
        assert_eq!(kept_in(&store).len(), 4);
    }

    /// A merged index replaces the file here: the file as it was is kept,
    /// and the record names the merged entry.
    #[test]
    fn an_index_as_it_was_before_a_merge_is_kept_in_history() {
        use history::{Change, Replacement, Whose};
        let (p, store) = Pair::new().with_history();
        let me = Pair::shown(&p.st.identity.public_key());
        let index = crate::memory_md::INDEX_FILE;
        p.file(index, "- a\n");
        assert_eq!(p.cycle().published, 1);
        p.file(index, "- a\n- mine\n");
        p.other_writes(index, Some("- a\n- theirs\n"));
        let report = p.cycle();
        assert_eq!((report.published, report.conflicts), (1, 0), "{report:?}");
        let records = kept_in(&store);
        assert_eq!(
            briefly(&records),
            [(index, Change::Merged, Some("- a\n- mine\n"))]
        );
        let about = &records[0].3;
        assert_eq!(
            about.kept.as_ref().unwrap().whose,
            Whose::Here { agreed: Some(1) }
        );
        let merged = history::Entry { device: me, rev: 3 };
        assert_eq!(about.replaced_by, Replacement::Entry(merged));
        assert!(!about.behind);
    }

    /// No kept copy, no replacement. Where the text cannot be kept, that
    /// one change is not made: the file and the channel stay as they were,
    /// the file is reported as failed, and the cycle goes on with the files
    /// that need nothing kept. A file that arrives needs nothing kept.
    #[test]
    fn a_text_that_cannot_be_kept_is_not_replaced() {
        let index = crate::memory_md::INDEX_FILE;
        // Each case: what is agreed first, the change on each side, and
        // what the file and the channel hold once the keep has failed.
        type Case = (
            &'static str,
            &'static str,
            Option<&'static str>,
            Option<Option<&'static str>>,
        );
        let cases: [Case; 5] = [
            // A version from another device.
            ("notes.md", "one\n", Some("one\n"), Some(Some("theirs\n"))),
            // A delete from another device.
            ("notes.md", "one\n", Some("one\n"), Some(None)),
            // An edit made here.
            ("notes.md", "one\n", Some("mine\n"), None),
            // A delete made here.
            ("notes.md", "one\n", None, None),
            // A merged index.
            (
                index,
                "- a\n",
                Some("- a\n- mine\n"),
                Some(Some("- a\n- theirs\n")),
            ),
        ];
        for (file, agreed, here, there) in cases {
            let (p, store) = Pair::new().with_history();
            p.file(file, agreed);
            assert_eq!(p.cycle().published, 1);
            // Something other than a directory where history is kept.
            let dir = p.st.home_dir.join("history");
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&p.st.home_dir).unwrap();
            std::fs::write(&dir, "in the way").unwrap();

            match here {
                Some(text) => p.file(file, text),
                None => std::fs::remove_file(p.mem.join(file)).unwrap(),
            }
            if let Some(theirs) = there {
                p.other_writes(file, theirs);
            }
            let held = version(&p.st, NAME, file);
            // Two files that need nothing kept: one to publish, one that
            // arrives.
            p.file("zz-new.md", "new here\n");
            p.other_writes("zz-arrives.md", Some("new there\n"));

            let report = p.cycle();
            let case = format!("{file} {here:?} {there:?}: {report:?}");
            assert_eq!(report.failed.len(), 1, "{case}");
            assert_eq!(report.failed[0].name, file, "{case}");
            assert!(report.failed[0].error.contains("kept in history"), "{case}");
            assert_eq!(p.read(file).as_deref(), here, "{case}");
            assert_eq!(version(&p.st, NAME, file), held, "{case}");
            assert_eq!((report.published, report.pulled), (1, 1), "{case}");
            assert_eq!(p.read("zz-arrives.md").as_deref(), Some("new there\n"));
            assert_eq!(p.held("zz-new.md").as_deref(), Some("new here\n"));
            assert!(dir.is_file(), "{case}");
            drop(store);

            // It is tried again, and fails again, every cycle: nothing is
            // changed until the text can be kept.
            let report = p.cycle();
            assert_eq!(report.failed.len(), 1, "{case}");
            assert_eq!(p.read(file).as_deref(), here, "{case}");
            assert_eq!(version(&p.st, NAME, file), held, "{case}");
        }
    }

    /// Nothing is kept for an entry that cannot be published: a text that
    /// fits in no entry, a merged index that does not, a name whose
    /// revisions are used up. Each is found out before the text it would
    /// replace goes into history, and would otherwise be written there,
    /// and removed again, in every cycle. Here nothing can be kept at all,
    /// so anything that asked for a record would fail for that: each is
    /// reported for what it is.
    #[test]
    fn nothing_is_kept_for_an_entry_that_cannot_be_published() {
        let index = crate::memory_md::INDEX_FILE;
        // As large as a file that is read may be: with any name, it is
        // over the bound on a name and a text together.
        let large = "x".repeat(MAX_FILE_BYTES);
        let (p, store) = Pair::new().with_history();
        p.file("notes.md", "one\n");
        p.file("a.md", "one\n");
        p.file(index, "- [Notes](notes.md) one\n");
        assert_eq!(p.cycle().published, 3);
        // A name at the last revision there is under the statement.
        let over_one = Some(vec![link(Some("one\n"), &p.st)]);
        let at_the_limit = text("at the limit\n");
        entry_at(&p.other, NAME, "a.md", at_the_limit, LAST_REV, over_one);
        deliver(&p.other, &p.st, NAME);
        let report = p.cycle();
        assert_eq!((report.pulled, report.conflicts), (1, 0), "{report:?}");
        // Something other than a directory where history is kept.
        drop(store);
        let dir = p.st.home_dir.join("history");
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::write(&dir, "in the way").unwrap();

        p.file("notes.md", &large);
        p.file("a.md", "two\n");
        p.file(index, &large);
        p.other_writes(index, Some("- [Other](other.md) there\n"));
        for _ in 0..2 {
            let report = p.cycle();
            let mut too_large = report.too_large.clone();
            too_large.sort();
            assert_eq!(too_large, [index, "notes.md"], "{report:?}");
            assert_eq!(report.failed.len(), 1, "{report:?}");
            assert_eq!(report.failed[0].name, "a.md");
            assert!(
                report.failed[0].error.contains("no revision is left"),
                "{report:?}"
            );
            assert_eq!(report.published, 0, "{report:?}");
        }
        assert!(dir.is_file());
        assert_eq!(p.read("notes.md").as_deref(), Some(large.as_str()));
        assert_eq!(p.held("notes.md").as_deref(), Some("one\n"));
    }

    /// A record stays only if its change was made. A publish that is
    /// refused, and a file that is written to while its new text is
    /// flushed, each take their record with them, cycle after cycle. For
    /// an entry that does not fit, none is made.
    #[test]
    fn a_change_that_is_not_made_leaves_no_record() {
        use history::Change;
        let index = crate::memory_md::INDEX_FILE;

        // A publish that is refused: the channel's version moved after
        // the plan was made.
        let (p, store) = Pair::new().with_history();
        p.file("notes.md", "one\n");
        assert_eq!(p.cycle().published, 1);
        p.file("notes.md", "mine\n");
        let report = p.cycle_with(&|| p.other_writes("notes.md", Some("theirs\n")));
        assert_eq!(report.published, 0);
        assert_eq!(kept_in(&store), []);

        // An entry that does not fit: the file is as large as one that is
        // read may be, and with its name it is over the bound.
        let (p, store) = Pair::new().with_history();
        p.file("notes.md", "one\n");
        assert_eq!(p.cycle().published, 1);
        p.file("notes.md", &"x".repeat(MAX_FILE_BYTES));
        for _ in 0..2 {
            let report = p.cycle();
            assert_eq!(report.published, 0, "{report:?}");
            assert_eq!(report.too_large, ["notes.md"]);
            assert_eq!(kept_in(&store), []);
        }
        assert_eq!(p.held("notes.md").as_deref(), Some("one\n"));

        // A file that is written to while the channel's version is being
        // flushed is not replaced.
        let agent_writes = |p: &Pair, file: &'static str, text: &'static str| {
            let path = p.mem.join(file);
            move |name: &str| {
                if name == file {
                    std::fs::write(&path, text).unwrap();
                }
            }
        };
        let (p, store) = Pair::new().with_history();
        p.file("notes.md", "one\n");
        assert_eq!(p.cycle().published, 1);
        p.other_writes("notes.md", Some("theirs\n"));
        let report = p.cycle_when_flushed(&agent_writes(&p, "notes.md", "written meanwhile\n"));
        assert_eq!(report.pulled, 0, "{report:?}");
        assert_eq!(kept_in(&store), []);
        // The next cycle keeps that write beside the file, and what it
        // then replaces goes into history.
        let report = p.cycle();
        assert_eq!((report.conflicts, report.pulled), (1, 1), "{report:?}");
        assert_eq!(
            briefly(&kept_in(&store)),
            [("notes.md", Change::Pulled, Some("written meanwhile\n"))]
        );

        // The same for a merged index: it is published, the file is not
        // replaced, and nothing is recorded as replaced.
        let (p, store) = Pair::new().with_history();
        p.file(index, "- a\n");
        assert_eq!(p.cycle().published, 1);
        p.file(index, "- a\n- mine\n");
        p.other_writes(index, Some("- a\n- theirs\n"));
        let report = p.cycle_when_flushed(&agent_writes(&p, index, "- a\n- mine\n- more\n"));
        assert_eq!((report.published, report.pulled), (1, 0), "{report:?}");
        assert_eq!(p.read(index).as_deref(), Some("- a\n- mine\n- more\n"));
        assert_eq!(kept_in(&store), []);

        // A write that fails: something is in the way of the temporary
        // file. And a removal that fails: the folder cannot be changed.
        let (p, store) = Pair::new().with_history();
        p.file("notes.md", "one\n");
        p.file("gone.md", "one\n");
        assert_eq!(p.cycle().published, 2);
        p.other_writes("notes.md", Some("theirs\n"));
        let in_the_way = p.mem.join(temporary_name("notes.md"));
        std::fs::create_dir(&in_the_way).unwrap();
        for _ in 0..2 {
            let report = p.cycle();
            assert_eq!((report.pulled, report.failed.len()), (0, 1), "{report:?}");
            assert_eq!(p.read("notes.md").as_deref(), Some("one\n"));
            assert_eq!(kept_in(&store), []);
        }
        std::fs::remove_dir(&in_the_way).unwrap();
        assert_eq!(p.cycle().pulled, 1);
        assert_eq!(
            briefly(&kept_in(&store)),
            [("notes.md", Change::Pulled, Some("one\n"))]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            p.other_writes("gone.md", None);
            let mode = |mode: u32| {
                std::fs::set_permissions(&p.mem, std::fs::Permissions::from_mode(mode)).unwrap()
            };
            mode(0o500);
            // As root the folder is not closed, and there is nothing to
            // show.
            let closed = std::fs::write(p.mem.join("probe.md"), "").is_err();
            if closed {
                for _ in 0..2 {
                    let report = p.cycle();
                    assert_eq!((report.pulled, report.failed.len()), (0, 1), "{report:?}");
                    assert_eq!(p.read("gone.md").as_deref(), Some("one\n"));
                    assert_eq!(kept_in(&store).len(), 1);
                }
            }
            mode(0o700);
            let _ = std::fs::remove_file(p.mem.join("probe.md"));
            assert_eq!(p.cycle().pulled, 1);
            assert_eq!(p.read("gone.md"), None);
            assert_eq!(
                briefly(&kept_in(&store)),
                [
                    ("gone.md", Change::Removed, Some("one\n")),
                    ("notes.md", Change::Pulled, Some("one\n")),
                ]
            );
        }
    }

    /// The text that a publish replaces is kept before the database lock
    /// is taken, in a record that names the revision the new entry is to
    /// have. The publish is then made at that revision or not at all: an
    /// entry that arrived under the file's name meanwhile, and is no
    /// version of the file, would give the new entry another.
    #[test]
    fn an_entry_is_published_at_the_revision_its_record_names_or_not_at_all() {
        let (p, store) = Pair::new().with_history();
        p.file("notes.md", "one\n");
        assert_eq!(p.cycle().published, 1);
        let folder = p.mem.display().to_string();
        let (planned, rev, _) = version(&p.st, NAME, "notes.md").unwrap();
        assert_eq!(rev, 1);
        let agreed = HashMap::new();
        let ctx = ctx_of(&p.st, &p.mem, &p.channel, &folder, &planned, &agreed);
        let publish = |at: Option<u64>| {
            let db = p.st.db.lock().unwrap();
            publish_over(&ctx, &db, "notes.md", Some("two\n"), at, None).unwrap()
        };
        // The next revision is 2. Kept for any other, nothing is published.
        assert_eq!(revision_ahead(&ctx, "notes.md").unwrap(), Some(2));
        for at in [1, 3] {
            assert!(publish(Some(at)).is_none(), "{at}");
            assert_eq!(p.held("notes.md").as_deref(), Some("one\n"));
        }
        let made = publish(Some(2)).expect("published at the revision named");
        assert_eq!(made.rev, 2);
        assert_eq!(p.held("notes.md").as_deref(), Some("two\n"));
        assert_eq!(kept_in(&store), []);

        // With history off no record names a revision, none is asked for,
        // and the publish is made at whatever revision is next.
        p.st.history.open(None);
        assert_eq!(revision_ahead(&ctx, "notes.md").unwrap(), None);
        let (planned, ..) = version(&p.st, NAME, "notes.md").unwrap();
        let ctx = Ctx {
            planned: &planned,
            ..ctx
        };
        let db = p.st.db.lock().unwrap();
        let made = publish_over(&ctx, &db, "notes.md", Some("three\n"), None, None).unwrap();
        assert_eq!(made.map(|made| made.rev), Some(3));
    }

    /// A name that cannot be looked at is not taken for free, and is not
    /// passed over either: it has a reason, which the cycle reports as the
    /// file's failure. (Here a name longer than any volume takes.) A name
    /// with nothing under it, and one that holds something, have none:
    /// the first is written, and the second is left for the next cycle.
    #[test]
    fn a_name_that_cannot_be_looked_at_is_not_taken_for_free() {
        let dir = tempfile::tempdir().unwrap();
        let long = "n".repeat(4096);
        let looked = std::fs::symlink_metadata(dir.path().join(&long));
        assert!(looked.is_err_and(|e| e.kind() != std::io::ErrorKind::NotFound));
        assert!(!as_seen(dir.path(), &long, None));
        let why = cannot_be_looked_at(dir.path(), &long).unwrap();
        assert!(why.contains("cannot be looked at"), "{why}");

        assert!(as_seen(dir.path(), "absent.md", None));
        assert_eq!(cannot_be_looked_at(dir.path(), "absent.md"), None);
        std::fs::create_dir(dir.path().join("taken.md")).unwrap();
        assert!(!as_seen(dir.path(), "taken.md", None));
        assert_eq!(cannot_be_looked_at(dir.path(), "taken.md"), None);
    }

    /// What arrives for a name that cannot be looked at is not written, and
    /// nothing is noted for it: a file made under the name since the folder
    /// was listed would be replaced unseen. The cycle says so, as the
    /// file's failure, each time, and the version is taken once the name
    /// can be looked at.
    #[test]
    fn nothing_is_written_under_a_name_that_cannot_be_looked_at() {
        use std::os::unix::fs::PermissionsExt;
        let (p, store) = Pair::new().with_history();
        p.other_writes("notes.md", Some("theirs\n"));
        let mode = |mode: u32| {
            std::fs::set_permissions(&p.mem, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        mode(0o444);
        let open_to_all = std::fs::symlink_metadata(p.mem.join("notes.md"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound);
        mode(0o755);
        if open_to_all {
            eprintln!("not run: this user can look into any folder");
            return;
        }
        for _ in 0..2 {
            let report = p.cycle_with(&|| mode(0o444));
            mode(0o755);
            assert_eq!((report.pulled, report.failed.len()), (0, 1), "{report:?}");
            assert_eq!(report.failed[0].name, "notes.md");
            let why = &report.failed[0].error;
            assert!(why.contains("cannot be looked at"), "{why}");
            assert_eq!(p.read("notes.md"), None);
            assert_eq!(kept_in(&store), []);
            // Nothing was noted and then taken back either: the first
            // record that is made makes the directory, and it is not there.
            assert!(!p.st.home_dir.join("history").exists());
            assert_eq!(std::fs::read_dir(&p.mem).unwrap().count(), 0);
        }
        let report = p.cycle();
        assert_eq!((report.pulled, report.failed.len()), (1, 0), "{report:?}");
        assert_eq!(p.read("notes.md").as_deref(), Some("theirs\n"));
    }

    /// A name that had no file when the cycle listed the folder, and has
    /// come to hold something that cannot be read, is not written over:
    /// what it holds could not be kept. What cannot be read does not pass
    /// for absent.
    #[cfg(unix)]
    #[test]
    fn a_name_that_has_come_to_hold_what_cannot_be_read_is_not_written_over() {
        use std::os::unix::fs::PermissionsExt;
        let (p, store) = Pair::new().with_history();
        p.other_writes("closed.md", Some("theirs\n"));
        p.other_writes("link.md", Some("theirs\n"));
        let elsewhere = p.mem.with_file_name("elsewhere.md");
        let report = p.cycle_with(&|| {
            // A file that nobody may read, and a link to nothing.
            p.file("closed.md", "an agent's, written meanwhile\n");
            let closed = std::fs::Permissions::from_mode(0o000);
            std::fs::set_permissions(p.mem.join("closed.md"), closed).unwrap();
            std::os::unix::fs::symlink(&elsewhere, p.mem.join("link.md")).unwrap();
        });
        assert_eq!(report.pulled, 0, "{report:?}");
        assert_eq!(kept_in(&store), []);
        let open = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(p.mem.join("closed.md"), open).unwrap();
        assert_eq!(
            p.read("closed.md").as_deref(),
            Some("an agent's, written meanwhile\n")
        );
        let link = std::fs::symlink_metadata(p.mem.join("link.md")).unwrap();
        assert!(link.file_type().is_symlink());
        assert!(!elsewhere.exists());
    }

    /// A file that changed between the cycle's read of it and the keep is
    /// neither kept nor replaced: what would be kept is no longer what the
    /// cycle planned with. That holds though the file is as the cycle saw
    /// it again by the last look before it is replaced.
    #[test]
    fn a_file_that_changed_since_it_was_read_is_not_kept_as_it_was() {
        let (p, store) = Pair::new().with_history();
        p.file("notes.md", "one\n");
        p.file("gone.md", "one\n");
        assert_eq!(p.cycle().published, 2);
        p.other_writes("notes.md", Some("theirs\n"));
        p.other_writes("gone.md", None);
        // An agent writes to both once the cycle has read the folder.
        let report = p.cycle_with(&|| {
            p.file("notes.md", "written meanwhile\n");
            p.file("gone.md", "written meanwhile\n");
        });
        assert_eq!(report.pulled, 0, "{report:?}");
        assert_eq!(kept_in(&store), []);
        assert_eq!(p.read("notes.md").as_deref(), Some("written meanwhile\n"));
        assert_eq!(p.read("gone.md").as_deref(), Some("written meanwhile\n"));

        // The same, where the agent puts back what the file held while the
        // channel's version is being flushed. The last look finds the file
        // as the cycle saw it, and the text kept would be another.
        let (p, store) = Pair::new().with_history();
        p.file("notes.md", "one\n");
        assert_eq!(p.cycle().published, 1);
        p.other_writes("notes.md", Some("theirs\n"));
        let hooks = Hooks {
            between: &|| p.file("notes.md", "written meanwhile\n"),
            flushed: &|name| {
                if name == "notes.md" {
                    p.file("notes.md", "one\n");
                }
            },
            ..Hooks::NONE
        };
        let report = p.cycle_hooked(&hooks).unwrap();
        assert_eq!(report.pulled, 0, "{report:?}");
        assert_eq!(kept_in(&store), []);
        assert_eq!(p.read("notes.md").as_deref(), Some("written meanwhile\n"));
    }

    /// With history off nothing is kept, and nothing waits for it.
    #[test]
    fn with_history_off_nothing_is_kept() {
        let p = Pair::new();
        p.file("notes.md", "one\n");
        assert_eq!(p.cycle().published, 1);
        p.other_writes("notes.md", Some("two\n"));
        assert_eq!(p.cycle().pulled, 1);
        p.file("notes.md", "three\n");
        assert_eq!(p.cycle().published, 1);
        p.other_writes("notes.md", None);
        assert_eq!(p.cycle().pulled, 1);
        assert!(!p.st.home_dir.join("history").exists());
    }
    // ── What the plan does once a statement is applied, and the bounds ──
    //
    // The tests from here on are of a change of devices and of the
    // chain's rule, on real stores (decision 2026-10-04 §6, §7.3).

    /// The tag in the names of the conflict files of the other device's
    /// folder: the folder of `st` has `abcd`.
    const OTHER_TAG: &str = "ef01";

    /// One cycle of the folder `mem` on `st`, in the channel that `st`
    /// holds for the name now.
    fn cycle_of(st: &AppState, mem: &Path, tag: &str) -> FolderReport {
        let channel = channel_now(st);
        let generation = st.sync_control.generation();
        sync_folder(st, mem, &channel, NAME, tag, generation).unwrap()
    }

    /// What the folder `mem` on `st` has recorded of `name`, in the
    /// channel that `st` holds for the name now.
    fn record_of(st: &AppState, mem: &Path, name: &str) -> Option<Agreed> {
        let folder = mem.display().to_string();
        let channel = channel_now(st);
        let db = st.db.lock().unwrap();
        let mut rows = sync_state::load(&db, &folder, &channel).unwrap();
        rows.remove(name)
    }

    /// Every file in `mem` with its text, in order of name: the memory
    /// files and whatever is kept beside them.
    fn files_in(mem: &Path) -> Vec<(String, String)> {
        let mut files: Vec<(String, String)> = std::fs::read_dir(mem)
            .unwrap()
            .map(|e| e.unwrap())
            .map(|e| {
                let name = e.file_name().into_string().unwrap();
                (name, std::fs::read_to_string(e.path()).unwrap())
            })
            .collect();
        files.sort();
        files
    }

    /// `files`, as [`files_in`] gives them.
    fn these(files: &[(&str, &str)]) -> Vec<(String, String)> {
        let owned = |(name, text): &(&str, &str)| (name.to_string(), text.to_string());
        files.iter().map(owned).collect()
    }

    /// What `st` holds in the slot of `key`: the revision and the value
    /// of its current version, who signed each entry held of it, and how
    /// many versions lost a tie to it.
    fn slot_of(st: &AppState, key: &str) -> (u64, Value, Vec<[u8; 32]>, usize) {
        let db = st.db.lock().unwrap();
        let slot = publish::read(&db, NAME, key).unwrap().slot;
        let current = slot.current.expect("a version");
        let signers = current.entries.iter().map(|entry| entry.author).collect();
        (current.rev, current.value, signers, slot.lost.len())
    }

    /// What a cycle did, in short: how many entries it published, how
    /// many files it took, and how many texts it kept beside a file. It
    /// failed for no file.
    fn did(report: &FolderReport) -> (usize, usize, usize) {
        assert!(report.failed.is_empty(), "{report:?}");
        assert!(report.error.is_none(), "{report:?}");
        (report.published, report.pulled, report.conflicts)
    }

    impl Pair {
        /// One cycle of the folder on `st`, in the channel that it holds
        /// for the name now: after a statement, another than `channel`.
        fn cycle_now(&self) -> FolderReport {
            cycle_of(&self.st, &self.mem, "abcd")
        }

        /// The memory folder of the other device, made if it is not
        /// there. (The folder of `st` is `mem`.)
        fn other_mem(&self) -> PathBuf {
            let mem = self.mem.with_file_name("memory-of-the-other");
            std::fs::create_dir_all(&mem).unwrap();
            mem
        }

        /// One cycle of the other device's folder.
        fn other_cycle(&self) -> FolderReport {
            cycle_of(&self.other, &self.other_mem(), OTHER_TAG)
        }

        /// A third device of the person, which holds the name too, and
        /// has received what `st` holds.
        fn third(&self) -> AppState {
            let third = another_device(&self.st, &self.mem.with_file_name("third"), NAME);
            deliver(&self.st, &third, NAME);
            third
        }

        /// `st` makes a change that removes the device `gone`, and
        /// applies it: it carries what it holds. Returns the change entry.
        fn st_removes(&self, gone: &AppState) -> CheckedEntry {
            removes(&self.st, &self.phrase, &gone.identity.public_key())
        }

        /// The other device is shown `change`, as a relay shows it, and
        /// applies it: it carries what it holds.
        fn other_is_shown(&self, change: &CheckedEntry) {
            let db = self.other.db.lock().unwrap();
            let shown = take::take(&db, &self.other.identity, change, now()).unwrap();
            let applied = matches!(shown, take::Taken::Shown(person::Shown::Applied(_)));
            assert!(applied, "{shown:?}");
        }

        /// `gone` is removed by a change made on `st`, and both devices
        /// apply it, each carrying what it holds. Neither has received
        /// what the other carried.
        fn both_apply_a_removal_of(&self, gone: &AppState) {
            let change = self.st_removes(gone);
            self.other_is_shown(&change);
        }
    }

    /// What the plan does once a device has applied a statement and
    /// carried what it holds (decision 2026-10-04 §7.3): a file that is as
    /// its record, where the name's new channel has that version, is left
    /// alone. Nothing is published, nothing is taken, and nothing is kept
    /// beside it: for a text that this device wrote, for one that another
    /// device wrote, and for a delete.
    #[test]
    fn a_file_as_its_record_is_left_alone_once_its_version_is_carried() {
        let p = Pair::new();
        let gone = p.third();
        let me = p.st.identity.public_key();
        p.file("mine.md", "mine\n");
        assert_eq!(p.cycle().published, 1);
        p.other_writes("theirs.md", Some("theirs\n"));
        p.other_writes("was.md", Some("for a while\n"));
        assert_eq!(p.cycle().pulled, 2);
        p.other_writes("was.md", None);
        assert_eq!(p.cycle().pulled, 1);
        let files = these(&[("mine.md", "mine\n"), ("theirs.md", "theirs\n")]);
        assert_eq!(files_in(&p.mem), files);
        let names = ["mine.md", "theirs.md", "was.md"];
        let records = || names.map(|name| p.record(name).expect("a record"));
        let versions =
            || names.map(|name| version(&p.st, NAME, name).map(|(_, rev, text)| (rev, text)));
        let (recorded, held_before) = (records(), versions());

        // The statement: this device makes it, applies it, and carries.
        p.st_removes(&gone);
        assert_ne!(channel_now(&p.st), p.channel);
        // The folder's records went with the name to its new channel, as
        // they were. And that channel holds each version, at its
        // revision, as this device's own entry.
        assert_eq!(records(), recorded);
        assert_eq!(versions(), held_before);
        for name in names {
            assert_eq!(slot_of(&p.st, name).2, [me], "{name}");
        }
        let entries = || -> Vec<[u8; 32]> { held(&p.st, NAME).iter().map(|e| e.id()).collect() };
        let carried = entries();
        assert_eq!(carried.len(), 3);

        // The cycle does nothing to any file, publishes nothing, and
        // keeps nothing beside a file.
        assert_eq!(did(&p.cycle_now()), (0, 0, 0));
        assert_eq!(files_in(&p.mem), files);
        assert_eq!(entries(), carried);
        // Only the records follow. Each is of this device's own entry
        // now, which says who signed the entry it was carried from.
        let [mine, theirs, was] = records();
        assert_eq!(mine, recorded[0]);
        let by_me = |hash: Option<[u8; 32]>, rev: u64, chain: Vec<Link>| Agreed {
            hash,
            rev,
            signer: Some(me),
            chain: Some(chain),
        };
        let their_text = link(Some("theirs\n"), &p.other);
        assert_eq!(theirs, by_me(recorded[1].hash, 1, vec![their_text]));
        let their_delete = vec![link(None, &p.other), link(Some("for a while\n"), &p.other)];
        assert_eq!(was, by_me(None, 2, their_delete));

        // And the cycle after it has nothing to do at all.
        let recorded = records();
        assert_eq!(did(&p.cycle_now()), (0, 0, 0));
        assert_eq!(files_in(&p.mem), files);
        assert_eq!((entries(), records()), (carried, recorded));
    }

    /// The new channel comes to be ahead: another device, which has
    /// applied the statement too, publishes a higher revision over the
    /// version it carried. The file takes it, as it would have in the
    /// channel that was left, and nothing is kept beside it. With a cycle
    /// between the carry and the arrival, and with none.
    #[test]
    fn a_higher_revision_over_a_carried_version_is_taken_and_nothing_is_kept() {
        for cycles_between in [true, false] {
            let p = Pair::new();
            let gone = p.third();
            // A version that the other device wrote over this device's.
            p.file("notes.md", "one\n");
            assert_eq!(p.cycle().published, 1);
            p.other_writes("notes.md", Some("two\n"));
            assert_eq!(p.cycle().pulled, 1);

            // Both apply the statement, and each carries that version.
            p.both_apply_a_removal_of(&gone);
            if cycles_between {
                assert_eq!(did(&p.cycle_now()), (0, 0, 0));
            }
            // The other device edits the file, over the version it
            // carried, and this device receives the edit.
            write(&p.other, NAME, "notes.md", text("three\n"));
            deliver(&p.other, &p.st, NAME);
            let (rev, value, signers, _) = slot_of(&p.st, "notes.md");
            let them = p.other.identity.public_key();
            assert_eq!((rev, value, signers), (3, text("three\n"), vec![them]));

            let at = format!("a cycle between: {cycles_between}");
            assert_eq!(did(&p.cycle_now()), (0, 1, 0), "{at}");
            assert_eq!(files_in(&p.mem), these(&[("notes.md", "three\n")]), "{at}");
            let taken = Agreed {
                hash: Some(Content::new("three\n").hash),
                rev: 3,
                signer: Some(them),
                chain: Some(vec![
                    link(Some("two\n"), &p.other),
                    link(Some("one\n"), &p.st),
                ]),
            };
            assert_eq!(p.record("notes.md"), Some(taken), "{at}");
        }
    }

    /// The file was edited here and not yet published when the statement
    /// was applied: the edit is published over the version it was made
    /// on, which this device has carried, and says so. Its chain begins
    /// with that version's text and the key that signed the carried
    /// entry, which is this device's own, and goes on as the carried
    /// entry's does. The other device, which carried the version too,
    /// takes the edit with nothing kept beside its file.
    #[test]
    fn an_edit_made_before_a_statement_is_published_over_the_version_carried() {
        let p = Pair::new();
        let gone = p.third();
        let theirs = p.other_mem();
        // Both folders agree a version that the other device wrote over
        // one of this device's.
        p.file("notes.md", "one\n");
        assert_eq!(p.cycle().published, 1);
        deliver(&p.st, &p.other, NAME);
        assert_eq!(p.other_cycle().pulled, 1);
        std::fs::write(theirs.join("notes.md"), "two\n").unwrap();
        assert_eq!(p.other_cycle().published, 1);
        deliver(&p.other, &p.st, NAME);
        assert_eq!(p.cycle().pulled, 1);

        // It is edited here, and no cycle runs before the statement is
        // applied.
        p.file("notes.md", "edited here\n");
        p.both_apply_a_removal_of(&gone);
        assert_eq!(did(&p.cycle_now()), (1, 0, 0));
        let (rev, value, signers, _) = slot_of(&p.st, "notes.md");
        let me = p.st.identity.public_key();
        assert_eq!((rev, value, signers), (3, text("edited here\n"), vec![me]));
        let over_the_carried = vec![
            link(Some("two\n"), &p.st),
            link(Some("two\n"), &p.other),
            link(Some("one\n"), &p.st),
        ];
        assert_eq!(said(&p.st, NAME, "notes.md"), Some(over_the_carried));
        assert_eq!(files_in(&p.mem), these(&[("notes.md", "edited here\n")]));

        // The other device has nothing to do for what it carried, and
        // takes the edit when it arrives, keeping nothing.
        assert_eq!(did(&p.other_cycle()), (0, 0, 0));
        deliver(&p.st, &p.other, NAME);
        assert_eq!(did(&p.other_cycle()), (0, 1, 0));
        assert_eq!(files_in(&theirs), these(&[("notes.md", "edited here\n")]));
    }

    /// Two devices carry one version: the two entries are one version
    /// (decision 2026-10-04 §2.3), and nothing follows on either. No
    /// entry is published, no file is taken, and nothing is kept beside a
    /// file. The slot holds one version, in two entries.
    #[test]
    fn two_devices_that_carry_one_version_hold_one_version_and_nothing_follows() {
        let p = Pair::new();
        let gone = p.third();
        let theirs = p.other_mem();
        let (me, them) = (p.st.identity.public_key(), p.other.identity.public_key());
        p.file("notes.md", "one\n");
        assert_eq!(p.cycle().published, 1);
        deliver(&p.st, &p.other, NAME);
        assert_eq!(p.other_cycle().pulled, 1);

        // Each applies the statement and carries, apart. Then each
        // receives what the other carried.
        p.both_apply_a_removal_of(&gone);
        deliver(&p.st, &p.other, NAME);
        deliver(&p.other, &p.st, NAME);
        let mut both = vec![me, them];
        both.sort();
        for st in [&p.st, &p.other] {
            assert_eq!(slot_of(st, "notes.md"), (1, text("one\n"), both.clone(), 0));
            assert_eq!(held(st, NAME).len(), 2);
        }
        // This device signed the version, and its entry says what it
        // said. The other's says who signed the entry it carried.
        assert_eq!(said(&p.st, NAME, "notes.md"), Some(Vec::new()));
        let carried = vec![link(Some("one\n"), &p.st)];
        assert_eq!(said(&p.other, NAME, "notes.md"), Some(carried.clone()));

        // Nothing follows on either, in this cycle or the next.
        let file = these(&[("notes.md", "one\n")]);
        for _ in 0..2 {
            assert_eq!(did(&p.cycle_now()), (0, 0, 0));
            assert_eq!(did(&p.other_cycle()), (0, 0, 0));
            assert_eq!(
                (files_in(&p.mem), files_in(&theirs)),
                (file.clone(), file.clone())
            );
        }
        for st in [&p.st, &p.other] {
            assert_eq!(slot_of(st, "notes.md"), (1, text("one\n"), both.clone(), 0));
            assert_eq!(held(st, NAME).len(), 2, "nothing was published");
        }
        // Each folder's record is of its own device's entry of the
        // version.
        let record = |signer: [u8; 32], chain: Vec<Link>| Agreed {
            hash: Some(Content::new("one\n").hash),
            rev: 1,
            signer: Some(signer),
            chain: Some(chain),
        };
        assert_eq!(p.record("notes.md"), Some(record(me, Vec::new())));
        let of_the_other = record_of(&p.other, &theirs, "notes.md");
        assert_eq!(of_the_other, Some(record(them, carried)));
    }

    /// Two devices carry two versions at one revision: each had edited
    /// the file, and published, before it heard of the statement. It is a
    /// tie, as it would have been in the channel that was left, decided
    /// by the text: the text with the higher hash is the file on both,
    /// and the text that loses is kept beside the file on the device that
    /// held it. Once with each device as the one whose text wins.
    #[test]
    fn two_versions_carried_at_one_revision_tie_and_the_text_that_loses_is_kept() {
        for this_device_wins in [true, false] {
            let p = Pair::new();
            let gone = p.third();
            let theirs = p.other_mem();
            p.file("notes.md", "one\n");
            assert_eq!(p.cycle().published, 1);
            deliver(&p.st, &p.other, NAME);
            assert_eq!(p.other_cycle().pulled, 1);

            // Each edits the file and publishes its edit, and neither
            // receives the other's.
            let (wins, loses) = (a_text_above("between\n"), a_text_below("between\n"));
            let (here, there) = match this_device_wins {
                true => (&wins, &loses),
                false => (&loses, &wins),
            };
            p.file("notes.md", here);
            assert_eq!(p.cycle().published, 1);
            std::fs::write(theirs.join("notes.md"), there).unwrap();
            assert_eq!(p.other_cycle().published, 1);

            // Each applies the statement, and carries its own version.
            // Then they meet in the name's new channel.
            p.both_apply_a_removal_of(&gone);
            deliver(&p.st, &p.other, NAME);
            deliver(&p.other, &p.st, NAME);
            let winner = match this_device_wins {
                true => p.st.identity.public_key(),
                false => p.other.identity.public_key(),
            };
            for st in [&p.st, &p.other] {
                assert_eq!(slot_of(st, "notes.md"), (2, text(&wins), vec![winner], 1));
            }

            let at = format!("this device wins: {this_device_wins}");
            let (of_this, of_the_other) = (did(&p.cycle_now()), did(&p.other_cycle()));
            let (won, lost) = match this_device_wins {
                true => (of_this, of_the_other),
                false => (of_the_other, of_this),
            };
            assert_eq!((won, lost), ((0, 0, 0), (0, 1, 1)), "{at}");
            let (winners, losers, tag) = match this_device_wins {
                true => (&p.mem, &theirs, OTHER_TAG),
                false => (&theirs, &p.mem, "abcd"),
            };
            assert_eq!(files_in(winners), these(&[("notes.md", &wins)]), "{at}");
            let copy = names::conflict_name("notes.md", tag);
            let kept = these(&[(&copy, &loses), ("notes.md", &wins)]);
            assert_eq!(files_in(losers), kept, "{at}");
        }
    }

    /// A version by a key that no longer counts stands between the
    /// folder's text and the version that arrives: the text is kept
    /// beside the file (decision 2026-10-04 §7.3). In the same sequence
    /// with that key still counting, nothing is kept.
    #[test]
    fn a_text_is_kept_where_a_key_that_counts_no_longer_signed_a_version_between() {
        for removed in [true, false] {
            let p = Pair::new();
            let third = p.third();
            p.file("notes.md", "one\n");
            assert_eq!(p.cycle().published, 1);
            // The third device writes the file over this device's
            // version, and only the other device receives that. The other
            // device writes over the third's.
            deliver(&p.st, &third, NAME);
            write(&third, NAME, "notes.md", text("two\n"));
            deliver(&p.st, &p.other, NAME);
            deliver(&third, &p.other, NAME);
            write(&p.other, NAME, "notes.md", text("three\n"));
            let chain = vec![link(Some("two\n"), &third), link(Some("one\n"), &p.st)];
            assert_eq!(said(&p.other, NAME, "notes.md"), Some(chain.clone()));

            if removed {
                // The third device is removed. Each of the two applies
                // the change and carries what it holds: this device its
                // own version, and the other the one it wrote, with the
                // chain that it had.
                p.both_apply_a_removal_of(&third);
                assert_eq!(said(&p.other, NAME, "notes.md"), Some(chain));
            }
            deliver(&p.other, &p.st, NAME);
            let (rev, value, ..) = slot_of(&p.st, "notes.md");
            assert_eq!((rev, value), (3, text("three\n")));

            let at = format!("removed: {removed}");
            let report = p.cycle_now();
            assert_eq!(did(&report), (0, 1, usize::from(removed)), "{at}");
            let files = match removed {
                true => these(&[("notes.conflict-abcd.md", "one\n"), ("notes.md", "three\n")]),
                false => these(&[("notes.md", "three\n")]),
            };
            assert_eq!(files_in(&p.mem), files, "{at}");
        }
    }

    /// A version at a higher revision whose entry lacks its chain shows
    /// nothing, and is known to follow nothing: it is taken, as it would
    /// be anyway, and what the file held is kept beside it. The same for
    /// a delete: the file goes, and its text is kept.
    #[test]
    fn a_higher_revision_whose_entry_lacks_its_chain_is_taken_and_the_text_kept() {
        let p = Pair::new();
        let them = p.other.identity.public_key();
        p.file("notes.md", "mine\n");
        p.file("gone.md", "mine too\n");
        assert_eq!(p.cycle().published, 2);
        p.other_says("notes.md", "theirs\n", None);
        p.other_puts("gone.md", None, None);
        // Each is the channel's version, in one entry, which says no
        // chain.
        assert_eq!(
            slot_of(&p.st, "notes.md"),
            (2, text("theirs\n"), vec![them], 0)
        );
        assert_eq!(slot_of(&p.st, "gone.md"), (2, Value::Delete, vec![them], 0));
        for name in ["notes.md", "gone.md"] {
            let db = p.st.db.lock().unwrap();
            let slot = publish::read(&db, NAME, name).unwrap().slot;
            assert_eq!(slot.current.unwrap().entries[0].chain, None, "{name}");
        }

        assert_eq!(did(&p.cycle()), (0, 2, 2));
        let files = these(&[
            ("gone.conflict-abcd.md", "mine too\n"),
            ("notes.conflict-abcd.md", "mine\n"),
            ("notes.md", "theirs\n"),
        ]);
        assert_eq!(files_in(&p.mem), files);
        // The folder's record is of that entry: its signer, and no chain.
        let taken = Agreed {
            hash: Some(Content::new("theirs\n").hash),
            rev: 2,
            signer: Some(them),
            chain: None,
        };
        assert_eq!(p.record("notes.md"), Some(taken));
    }

    /// A chain holds a hundred links, and the oldest fall off it. A
    /// folder whose text is the hundredth version back is still at the
    /// chain's end: the version is taken, and nothing is kept. One version
    /// more, and the text has fallen off: the version is taken, and the
    /// text is kept beside the file, with no change of devices at all.
    #[test]
    fn a_text_at_the_end_of_the_chain_is_known_and_one_that_fell_off_it_is_kept() {
        use cordelia_core::protocol::MAX_ENTRY_LINKS;
        let p = Pair::new();
        p.file("at.md", "mine\n");
        p.file("past.md", "mine\n");
        assert_eq!(p.cycle().published, 2);
        // The other device has edited each file many times since. Its
        // entry says ninety-nine links, each for an edit of its own, and
        // the oldest of them is this device's text.
        let mine = link(Some("mine\n"), &p.st);
        let mut many: Vec<Link> = (2..MAX_ENTRY_LINKS)
            .map(|n| link(Some(&format!("an edit, {n} back\n")), &p.other))
            .collect();
        many.push(mine);
        assert_eq!(many.len(), MAX_ENTRY_LINKS - 1);
        for name in ["at.md", "past.md"] {
            p.other_says(name, "the last but one\n", Some(many.clone()));
        }
        // It edits each once more, and one of them once more again: each
        // edit is published over the one before.
        let edited = |name: &str, texts: &[&str]| {
            for edit in texts {
                write(&p.other, NAME, name, text(edit));
            }
            said(&p.other, NAME, name).unwrap()
        };
        let at = edited("at.md", &["the last\n"]);
        let past = edited("past.md", &["the last\n", "one more\n"]);
        assert_eq!((at.len(), past.len()), (MAX_ENTRY_LINKS, MAX_ENTRY_LINKS));
        assert_eq!(at.last(), Some(&mine), "the hundredth link");
        assert!(!past.contains(&mine), "it has fallen off");

        deliver(&p.other, &p.st, NAME);
        assert_eq!(did(&p.cycle()), (0, 2, 1));
        let files = these(&[
            ("at.md", "the last\n"),
            ("past.conflict-abcd.md", "mine\n"),
            ("past.md", "one more\n"),
        ]);
        assert_eq!(files_in(&p.mem), files);
    }

    /// Two devices each publish a file of one name, with two texts, into
    /// a channel that is still empty: neither had received what the other
    /// holds. They meet as a tie (decision 2026-10-04 §6). One text is
    /// the file on both devices, by the tie's rule, and the other is kept
    /// beside it on the device that wrote it. Nothing is lost: the copy
    /// is a file like any other, and reaches the other device.
    #[test]
    fn two_files_published_apart_into_an_empty_channel_meet_as_a_tie() {
        for this_device_wins in [true, false] {
            let p = Pair::new();
            let theirs = p.other_mem();
            let (wins, loses) = (a_text_above("between\n"), a_text_below("between\n"));
            let (here, there) = match this_device_wins {
                true => (&wins, &loses),
                false => (&loses, &wins),
            };
            p.file("notes.md", here);
            std::fs::write(theirs.join("notes.md"), there).unwrap();
            // Each has its first cycle with the channel empty, and
            // publishes its file as a new one.
            assert_eq!(did(&p.cycle()), (1, 0, 0));
            assert_eq!(did(&p.other_cycle()), (1, 0, 0));
            for st in [&p.st, &p.other] {
                assert_eq!(said(st, NAME, "notes.md"), Some(Vec::new()));
            }

            // They meet.
            deliver(&p.st, &p.other, NAME);
            deliver(&p.other, &p.st, NAME);
            let winner = match this_device_wins {
                true => p.st.identity.public_key(),
                false => p.other.identity.public_key(),
            };
            for st in [&p.st, &p.other] {
                assert_eq!(slot_of(st, "notes.md"), (1, text(&wins), vec![winner], 1));
            }
            let at = format!("this device wins: {this_device_wins}");
            let (of_this, of_the_other) = (did(&p.cycle()), did(&p.other_cycle()));
            let (won, lost) = match this_device_wins {
                true => (of_this, of_the_other),
                false => (of_the_other, of_this),
            };
            assert_eq!((won, lost), ((0, 0, 0), (0, 1, 1)), "{at}");
            let (winners, losers, tag) = match this_device_wins {
                true => (&p.mem, &theirs, OTHER_TAG),
                false => (&theirs, &p.mem, "abcd"),
            };
            assert_eq!(files_in(winners), these(&[("notes.md", &wins)]), "{at}");
            let copy = names::conflict_name("notes.md", tag);
            let both = these(&[(&copy, &loses), ("notes.md", &wins)]);
            assert_eq!(files_in(losers), both, "{at}");

            // The copy is published, and the device whose text won takes
            // it: both texts are on both devices.
            let (of_this, of_the_other) = (did(&p.cycle()), did(&p.other_cycle()));
            let published = if this_device_wins {
                of_the_other
            } else {
                of_this
            };
            assert_eq!(published, (1, 0, 0), "{at}");
            deliver(&p.st, &p.other, NAME);
            deliver(&p.other, &p.st, NAME);
            let (of_this, of_the_other) = (did(&p.cycle()), did(&p.other_cycle()));
            let taken = if this_device_wins {
                of_this
            } else {
                of_the_other
            };
            assert_eq!(taken, (0, 1, 0), "{at}");
            assert_eq!(
                (files_in(&p.mem), files_in(&theirs)),
                (both.clone(), both),
                "{at}"
            );
        }
    }

    /// A folder that has no record in its channel yet has its first cycle
    /// there only once the channel was fetched (decision 2026-10-04 §6):
    /// from one relay, and from each other relay that the device is set
    /// up with or until the wait for those has gone by. It waits for a
    /// relay, and never for a device. A folder that has a record does not
    /// wait, and neither does a node that is set up with no relay.
    #[test]
    fn a_folders_first_cycle_in_a_channel_waits_until_the_channel_was_fetched() {
        use cordelia_core::protocol::FIRST_FETCH_WAIT_SECS;
        let tmp = tempfile::tempdir().unwrap();
        let st = state(tmp.path());
        let channel = with_phrase(&st, NAME);
        let id = {
            let db = st.db.lock().unwrap();
            held_rows::channel_of_name(&db, NAME).unwrap().unwrap()
        };
        let asked = |folder: &str| {
            let generation = st.sync_control.generation();
            name_channel(&st, folder, NAME, generation).unwrap()
        };
        let waits = |folder: &str| matches!(asked(folder), Channel::Waits(c) if c == channel);
        let is_ready = |folder: &str| matches!(asked(folder), Channel::Ready(c) if c == channel);
        let folder = "/a/memory";

        // A node that is set up with no relay has none to wait for.
        assert!(is_ready(folder));
        // Set up with two, a folder with no record in the channel waits.
        st.own_channels.set_up_with(2);
        assert!(waits(folder));
        // It waits though the device holds the name and says that it
        // syncs it: that is what has the channel fetched.
        {
            let db = st.db.lock().unwrap();
            let said = said_names::said_here(&db, &st.identity).unwrap();
            assert!(said.contains(NAME));
        }
        // One relay has handed the channel: it waits for the other.
        let now = Instant::now();
        st.own_channels.fetched_from(&id, "relay one", now);
        assert!(waits(folder));
        // Both have.
        st.own_channels.fetched_from(&id, "relay two", now);
        assert!(is_ready(folder));
        // One has, and the wait for the other has gone by.
        let ago = |secs: u64| {
            let wait = Duration::from_secs(secs);
            Instant::now().checked_sub(wait).unwrap()
        };
        st.own_channels.forget_fetched(&id);
        assert!(waits(folder));
        let waited = ago(FIRST_FETCH_WAIT_SECS);
        st.own_channels.fetched_from(&id, "relay one", waited);
        assert!(is_ready(folder));
        // One has, and the wait has not gone by yet.
        st.own_channels.forget_fetched(&id);
        let half_way = ago(FIRST_FETCH_WAIT_SECS / 2);
        st.own_channels.fetched_from(&id, "relay one", half_way);
        assert!(waits(folder));

        // A folder that has a record in the channel does not wait,
        // whatever was fetched. Another folder of the same name, with no
        // record, still does.
        st.own_channels.forget_fetched(&id);
        let agreement = agreed_at(None, 1);
        sync_state::save(
            &st.db.lock().unwrap(),
            folder,
            &channel,
            "notes.md",
            &agreement,
        )
        .unwrap();
        assert!(is_ready(folder));
        assert!(waits("/another/memory"));
    }

    /// The same through a cycle of the adapter: a folder that waits is
    /// listed as waiting, with its channel. Nothing of it is published,
    /// and its files are left as they are, until the channel was fetched.
    #[test]
    fn a_folder_that_waits_for_its_channel_is_listed_and_publishes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        // Real paths, as Claude Code records them.
        let home = tmp.path().canonicalize().unwrap().join("home");
        let (claude, work) = (home.join(".claude"), home.join("work"));
        std::fs::create_dir_all(&work).unwrap();
        let memory = discover::claude_folder(&claude, &work)
            .unwrap()
            .join("memory");
        std::fs::create_dir_all(&memory).unwrap();
        std::fs::write(memory.join("notes.md"), "mine\n").unwrap();

        let st = state(tmp.path());
        let channel = with_phrase(&st, NAME);
        st.own_channels.set_up_with(2);
        let id = {
            let db = st.db.lock().unwrap();
            // Sync is on for this directory, and the folder is mapped.
            let mapped = vec![Mapping {
                folder: work.display().to_string(),
                name: NAME.to_string(),
            }];
            let mappings = serde_json::to_string(&mapped).unwrap();
            meta::set(&db, meta::SYNC_CLAUDE_MAPPINGS, &mappings).unwrap();
            meta::set(&db, meta::SYNC_CLAUDE_DIR, &claude.display().to_string()).unwrap();
            held_rows::channel_of_name(&db, NAME).unwrap().unwrap()
        };
        let mut adapter = ClaudeAdapter::new(claude, home, &st.identity.public_key());

        for fetched_from in [0, 1] {
            if fetched_from == 1 {
                st.own_channels
                    .fetched_from(&id, "relay one", Instant::now());
            }
            let report = adapter.run_cycle(&st);
            assert!(report.errors.is_empty(), "{report:?}");
            assert_eq!(report.publishes_nothing, None);
            let [folder] = report.folders.as_slice() else {
                panic!("{report:?}");
            };
            assert!(folder.waiting, "{fetched_from}: {folder:?}");
            assert_eq!(folder.channel_id.as_deref(), Some(channel.as_str()));
            assert_eq!((folder.published, folder.pulled), (0, 0), "{folder:?}");
            assert!(held(&st, NAME).is_empty(), "{fetched_from}");
            assert_eq!(files_in(&memory), these(&[("notes.md", "mine\n")]));
        }

        // The second relay has handed the channel too: the folder has
        // its first cycle, and its file is published.
        st.own_channels
            .fetched_from(&id, "relay two", Instant::now());
        let report = adapter.run_cycle(&st);
        assert!(report.errors.is_empty(), "{report:?}");
        let [folder] = report.folders.as_slice() else {
            panic!("{report:?}");
        };
        assert!(!folder.waiting, "{folder:?}");
        assert_eq!(folder.published, 1, "{folder:?}");
        assert_eq!(
            version(&st, NAME, "notes.md").map(|(_, rev, text)| (rev, text)),
            Some((1, "mine\n".to_string()))
        );
        // It has a record now, and waits no more, whatever is fetched.
        st.own_channels.forget_fetched(&id);
        let report = adapter.run_cycle(&st);
        assert!(!report.folders[0].waiting, "{report:?}");
    }

    /// The bound, at every bound together (decision 2026-10-04 §2.3). A
    /// file whose name and text are together exactly as large as an
    /// entry's may be is published, over a version whose chain is at its
    /// longest: room for a chain is kept in every entry. One byte more,
    /// and the file is reported as too large, in each cycle: it is left as
    /// it is, the channel keeps the version that fitted, and nothing is
    /// written to history for it.
    #[test]
    fn a_file_is_published_at_every_bound_together_and_not_one_byte_over() {
        use cordelia_core::protocol::MAX_ENTRY_LINKS;
        let (p, store) = Pair::new().with_history();
        let name = "notes.md";
        // The channel's version says a chain at its longest.
        let longest: Vec<Link> = (0..MAX_ENTRY_LINKS)
            .map(|n| link(Some(&format!("text {n}\n")), &p.other))
            .collect();
        p.other_says(name, "before\n", Some(longest.clone()));
        assert_eq!(did(&p.cycle()), (0, 1, 0));

        // A text that is, with the file's name, exactly at the bound.
        let at_the_bound = "x".repeat(MAX_ENTRY_NAME_AND_VALUE_BYTES - name.len());
        p.file(name, &at_the_bound);
        let report = p.cycle();
        assert_eq!(did(&report), (1, 0, 0));
        assert!(report.too_large.is_empty(), "{report:?}");
        assert_eq!(p.held(name).as_deref(), Some(at_the_bound.as_str()));
        // Its chain is at its longest too: the version it was written
        // over comes first, and the oldest link has fallen off.
        let chain = said(&p.st, NAME, name).unwrap();
        assert_eq!(chain.len(), MAX_ENTRY_LINKS);
        assert_eq!(chain[0], link(Some("before\n"), &p.other));
        assert_eq!(chain[1..], longest[..MAX_ENTRY_LINKS - 1]);
        // Another device takes the entry as a version: it opens, whole.
        deliver(&p.st, &p.other, NAME);
        let taken = version(&p.other, NAME, name).map(|(_, rev, text)| (rev, text));
        assert_eq!(taken, Some((2, at_the_bound.clone())));
        // History has the file's arrival, and what the edit replaced.
        let kept = kept_in(&store);
        let (arrived, edited) = (history::Change::Arrived, history::Change::EditedHere);
        assert_eq!(
            briefly(&kept),
            [(name, arrived, None), (name, edited, Some("before\n"))]
        );

        // One byte more.
        let over = format!("{at_the_bound}x");
        p.file(name, &over);
        for _ in 0..2 {
            let report = p.cycle();
            assert_eq!(report.too_large, [name], "{report:?}");
            assert_eq!(did(&report), (0, 0, 0));
            assert_eq!(files_in(&p.mem), these(&[(name, &over)]));
            assert_eq!(p.held(name).as_deref(), Some(at_the_bound.as_str()));
            assert_eq!(kept_in(&store), kept);
        }
    }

    /// Local history names the device that wrote a version, and not the
    /// device that carried it (decision 2026-10-04 §16): for a version
    /// that this device took after another device had carried it, the
    /// record names the key in the carried entry's first link. And the
    /// record of a file that was removed names the key that signed the
    /// delete: the carried delete's first link, or the delete's own
    /// signer where it was not carried.
    #[test]
    fn history_names_who_wrote_a_carried_version_and_who_signed_a_delete() {
        use history::{Change, Replacement, Whose};
        let (p, store) = Pair::new().with_history();
        let third = p.third();
        let entry = |device: &AppState, rev: u64| history::Entry {
            device: Pair::shown(&device.identity.public_key()),
            rev,
        };
        for name in ["notes.md", "gone.md", "plain.md"] {
            p.file(name, "one\n");
        }
        assert_eq!(p.cycle().published, 3);
        p.other_writes("theirs.md", Some("theirs\n"));
        assert_eq!(p.cycle().pulled, 1);

        // The third device edits one file and deletes another, and only
        // the other device receives that.
        deliver(&p.st, &third, NAME);
        write(&third, NAME, "notes.md", text("two\n"));
        write(&third, NAME, "gone.md", Value::Delete);
        deliver(&p.st, &p.other, NAME);
        deliver(&third, &p.other, NAME);
        // The third device is removed, and both devices apply the change:
        // the other carries the third's two versions, as its own entries.
        // Then it deletes a file itself.
        p.both_apply_a_removal_of(&third);
        write(&p.other, NAME, "plain.md", Value::Delete);
        deliver(&p.other, &p.st, NAME);
        let them = p.other.identity.public_key();
        assert_eq!(
            slot_of(&p.st, "notes.md"),
            (2, text("two\n"), vec![them], 0)
        );
        for name in ["gone.md", "plain.md"] {
            assert_eq!(slot_of(&p.st, name), (2, Value::Delete, vec![them], 0));
        }

        // This device takes all three. What the third device signed is
        // not known to follow this device's texts, which are kept beside.
        let before = kept_in(&store).len();
        assert_eq!(did(&p.cycle_now()), (0, 3, 2));
        let records = kept_in(&store);
        assert_eq!(records.len(), before + 3);
        let of = |file: &str, change: Change| -> history::About {
            let found = records.iter().find(|(f, c, ..)| f == file && *c == change);
            found
                .unwrap_or_else(|| panic!("{file} {change:?}"))
                .3
                .clone()
        };
        // The version that the other device carried: the third wrote it.
        let pulled = of("notes.md", Change::Pulled);
        assert_eq!(pulled.replaced_by, Replacement::Entry(entry(&third, 2)));
        // The delete that the other device carried: the third signed it.
        let removed = of("gone.md", Change::Removed);
        assert_eq!(removed.replaced_by, Replacement::Entry(entry(&third, 2)));
        // The delete that the other device made: it signed it.
        let removed = of("plain.md", Change::Removed);
        assert_eq!(removed.replaced_by, Replacement::Entry(entry(&p.other, 2)));

        // The same where a version of the channel's is kept: an edit here
        // replaces the version that the other device carried, and the one
        // that this device carried itself. Each record names who wrote
        // the version, and that this device's entry replaced it.
        p.file("notes.md", "three\n");
        p.file("theirs.md", "mine now\n");
        p.cycle_now();
        let records = kept_in(&store);
        let of = |file: &str| -> history::About {
            let edited = Change::EditedHere;
            let found = records.iter().find(|(f, c, ..)| f == file && *c == edited);
            found.unwrap_or_else(|| panic!("{file}")).3.clone()
        };
        let edited = of("notes.md");
        assert_eq!(edited.kept.unwrap().whose, Whose::Channel(entry(&third, 2)));
        assert_eq!(edited.replaced_by, Replacement::Entry(entry(&p.st, 3)));
        let edited = of("theirs.md");
        assert_eq!(
            edited.kept.unwrap().whose,
            Whose::Channel(entry(&p.other, 1))
        );
        assert_eq!(edited.replaced_by, Replacement::Entry(entry(&p.st, 2)));
    }
}
