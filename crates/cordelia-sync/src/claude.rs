//! The Claude Code adapter: keeps Claude Code memory folders in step with
//! Cordelia channels (decision 2026-09-30-agent-memory-sync §4.5).
//!
//! What syncs is declared, not assumed. A *mapping* says that Claude's
//! memory for a folder syncs under a name. The name is shared by all of a
//! person's devices: the personal channel maps it to a channel
//! (`project/<name>` -> channel ID), created by the first device to sync
//! it and joined by each device that maps the same name. Home memory is
//! the mapping of the home directory, under the name `~`.
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

/// The name home memory syncs under.
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
}

impl Settings {
    /// Read from node metadata: `sync.claude.all`, `.mappings`, `.exclude`
    /// and `.home`.
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
                    let pattern = pattern.to_lowercase();
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
            let label = target.dir.display().to_string();
            let memory = target.dir.join("memory");
            wanted.insert(target.name.clone());
            let result = match project_channel(state, &personal, &target.name) {
                Ok(Some(channel)) => {
                    joined.insert(target.name.clone());
                    syncing.push((memory.display().to_string(), channel.clone()));
                    sync_folder(state, &memory, &channel, "", &self.device_tag).map(|mut r| {
                        r.channel_id = Some(channel);
                        r
                    })
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
            report.folders.push(r);
        }
        // Kept for the names that sync now; written only when it changes.
        if activity != stored
            && let Err(e) = store_activity(state, &activity)
        {
            report.errors.push(format!("activity: {e}"));
        }
        // A folder that no longer syncs starts afresh if it syncs again:
        // what it lost in between is not taken for deletes.
        if looked_up_all && let Err(e) = forget_other_folders(state, &syncing) {
            report.errors.push(format!("agreements: {e}"));
        }

        match exchange_names(state, &personal, &joined, &wanted) {
            Ok(available) => report.available = available,
            Err(e) => report.errors.push(format!("names: {e}")),
        }
        report
    }
}

/// Forget what every folder agreed with its channel, except those in
/// `syncing` (memory folder, channel).
fn forget_other_folders(
    state: &AppState,
    syncing: &[(String, String)],
) -> Result<(), CordeliaError> {
    let forgotten = sync_state::forget_except(&*lock(state)?, syncing)?;
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
/// no longer syncs anything, and forget what its folders had agreed, so
/// that turning sync on again merges rather than replays what changed in
/// between.
pub fn withdraw(state: &AppState) -> Result<(), CordeliaError> {
    forget_other_folders(state, &[])?;
    let personal = membership::personal_channel_id(state)?;
    let none = BTreeSet::new();
    exchange_names(state, &personal, &none, &none).map(|_| ())
}

/// Publish the names this device syncs (`mine`), if they changed, and
/// return the names this person's other devices sync that this one neither
/// syncs nor is waiting to (`wanted`). Each device speaks only for itself:
/// a list is read only from the device its key names, and only the names
/// in it that could be mapped. (Another member writing a later revision
/// under a device's key can therefore hide that device's list until it
/// next publishes, but cannot add to it.)
fn exchange_names(
    state: &AppState,
    personal: &str,
    mine: &BTreeSet<String>,
    wanted: &BTreeSet<String>,
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
    if published != *mine {
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
}

/// Read the syncable files of a memory folder. Symlinks, unsafe names,
/// non-UTF-8 and oversized files are left out and listed; hidden files are
/// ignored. A folder that does not exist has no files; one that cannot be
/// read is an error, never an empty folder.
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
    } = &mut local;
    for entry in entries {
        let entry = entry?;
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
    let Local {
        files: local,
        skipped,
        too_large,
    } = read_local(dir).map_err(|e| CordeliaError::Internal(format!("{}: {e}", dir.display())))?;
    // A file that is there but cannot sync takes no part, in either
    // direction. It is not gone, so it must not be planned as deleted,
    // which would delete it on every other device; and nothing from the
    // channel is written over it.
    let apart: HashSet<String> = skipped.iter().chain(too_large.iter()).cloned().collect();
    report.skipped = skipped;
    report.too_large = too_large;

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
            Ok(rev) => {
                record(Some(Content::new(text).hash), rev)?;
                report.published += 1;
            }
            Err(CordeliaError::TooLarge { .. }) => {
                too_large(report);
                return Ok(false);
            }
            Err(e) => return Err(e),
        },
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
            // Published before the file is written: if the merged text does
            // not fit, the file stays as it was.
            match publish(Some(&text)) {
                Ok(rev) => {
                    write_atomic(dir, key, &text).map_err(io)?;
                    record(Some(Content::new(text).hash), rev)?;
                    report.published += 1;
                }
                Err(CordeliaError::TooLarge { .. }) => {
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
