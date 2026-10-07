//! Memory that is found on a machine and is not mapped: whether `cordelia
//! sync map` would sync it (decision 2026-10-04 §10.1).
//!
//! Only what is mapped syncs. A folder that holds memory and is not
//! mapped is listed, so that a person can map it: by the sync adapter,
//! for what it finds on disk, and by the node's status, for each folder
//! that a notice of what stopped names. Beside each is the command that
//! maps it, **and that command must map that folder and no other.**
//!
//! `cordelia sync map <directory>` syncs one folder: the one that Claude
//! Code names after the directory, or after the repository the directory
//! is in, under the Claude Code directory that is set. For a memory tree
//! that someone laid out by hand, and for a directory that a git
//! repository has appeared above since it was found, that is another
//! folder than the one that was found. A command printed beside such an
//! entry would map a folder that nobody meant.
//!
//! So one function says, of a folder that was found, whether `map` would
//! sync it, and why not where it would not ([`would_map`]). It is asked
//! for a found entry and for an entry of the notice alike, and its tests
//! are made in one order: the folder first, then the directory, then the
//! name.
//!
//! An entry that `map` would not sync is carried without its directory
//! under `cwd` ([`Entry`]): a panel that is not yet brought up to date
//! gives a switch to every found entry that has a `cwd`, and that switch
//! would map another folder.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use cordelia_core::claude_code::{FOLDER_NAME_MAX, folder_name};
use cordelia_storage::first_start::Notice;

use crate::types::SyncMapping;

// ── Where Claude Code keeps the memory of a directory ────────────────

/// What git says of a directory.
enum Layout {
    /// Git cannot be run: which repository the directory is in is not
    /// known.
    GitNotRun,
    /// The directory is in no repository.
    NoRepository,
    /// The work tree it is in, and the repository's common directory
    /// (which linked worktrees share), as real paths.
    Repository { top: PathBuf, common: PathBuf },
}

/// Ask git for the work tree `cwd` is in and the repository's common
/// directory.
fn git_layout(cwd: &Path) -> Layout {
    let asked = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--show-toplevel", "--git-common-dir"])
        .output();
    let Ok(output) = asked else {
        return Layout::GitNotRun;
    };
    if !output.status.success() {
        return Layout::NoRepository;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = text.lines();
    let (Some(top), Some(common)) = (lines.next(), lines.next()) else {
        return Layout::NoRepository;
    };
    // The common directory may be given relative to `cwd`.
    match cwd.join(common).canonicalize() {
        Ok(common) => Layout::Repository {
            top: PathBuf::from(top),
            common,
        },
        Err(_) => Layout::NoRepository,
    }
}

/// The directory whose folder holds the memory for sessions started in
/// `cwd`, where git can be run. Claude Code keeps one memory per git
/// repository, shared by its subdirectories and worktrees, in the folder
/// of the repository's main working tree. Outside a repository it is
/// `cwd` itself. `None` where git cannot be run: the repository that
/// `cwd` may be in is then not known.
pub fn memory_root_known(cwd: &Path) -> Option<PathBuf> {
    Some(match git_layout(cwd) {
        Layout::GitNotRun => return None,
        // A linked worktree's common directory is the main working tree's
        // `.git`.
        Layout::Repository { common, .. } if common.file_name().is_some_and(|n| n == ".git") => {
            common
                .parent()
                .map_or_else(|| cwd.to_path_buf(), Path::to_path_buf)
        }
        // Anything else is taken to be its own root: see
        // [`memory_root_is_assumed`].
        Layout::Repository { top, .. } => top,
        Layout::NoRepository => cwd.to_path_buf(),
    })
}

/// [`memory_root_known`], or `cwd` itself where git cannot be run.
pub fn memory_root(cwd: &Path) -> PathBuf {
    memory_root_known(cwd).unwrap_or_else(|| cwd.to_path_buf())
}

/// Whether [`memory_root`] is a guess for `cwd`: it is in a repository
/// whose common directory is not a plain `.git`, which is a submodule or a
/// worktree of a bare repository. Where Claude Code keeps memory for those
/// has not been confirmed.
pub fn memory_root_is_assumed(cwd: &Path) -> bool {
    match git_layout(cwd) {
        Layout::Repository { common, .. } => common.file_name().is_none_or(|n| n != ".git"),
        Layout::GitNotRun | Layout::NoRepository => false,
    }
}

/// The name Claude Code gives the folder for a directory
/// (`/home/sam/Work` -> `-home-sam-Work`).
pub fn claude_folder_name(dir: &Path) -> String {
    folder_name(&dir.to_string_lossy())
}

/// Claude Code's folder for a directory, under `claude_dir/projects`; it
/// may not exist yet. `None` when the path is too long for its folder name
/// to be predicted.
pub fn claude_folder(claude_dir: &Path, dir: &Path) -> Option<PathBuf> {
    let name = claude_folder_name(dir);
    (name.len() <= FOLDER_NAME_MAX).then(|| claude_dir.join("projects").join(name))
}

/// Whether `folder` is the one Claude Code names after `dir`, as opposed to
/// a folder someone laid out by hand.
pub fn is_claude_folder_for(folder: &Path, dir: &Path) -> bool {
    let Some(have) = folder.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let want = claude_folder_name(dir);
    if want.len() <= FOLDER_NAME_MAX {
        return have == want;
    }
    have.strip_prefix(&want[..FOLDER_NAME_MAX])
        .is_some_and(|hash| hash.starts_with('-'))
}

// ── Whether `map` would sync a folder ────────────────────────────────

/// A folder that was found: what the one function is asked about.
#[derive(Debug, Clone, Copy)]
pub struct Asked<'a> {
    /// Claude Code's folder for it, by its whole path.
    pub folder: &'a Path,
    /// The directory it belongs to, where one is known: what its
    /// transcripts record, or what a notice kept of it.
    pub directory: Option<&'a Path>,
    /// The name it would sync under, or did.
    pub name: Option<&'a str>,
}

/// What a folder is asked against.
#[derive(Debug, Clone, Copy)]
pub struct Against<'a> {
    /// The Claude Code directory that is set, as it is stored; or, with
    /// sync off, the one that turning sync on would use.
    pub claude_dir: &'a Path,
    /// The home directory as the node has it, a real path. `None` where
    /// `HOME` is not set in the node's environment: nothing can be mapped
    /// then.
    pub home: Option<&'a Path>,
    /// The mappings that are declared.
    pub mappings: &'a [SyncMapping],
}

/// What a machine says of a directory. The node asks the disk and git
/// ([`ThisMachine`]); the sync adapter answers from what it read when it
/// last looked at a folder's transcripts, so that a cycle asks git no
/// more often than it did.
pub trait Machine {
    /// Whether `dir` is there, and a directory.
    fn is_dir(&self, dir: &Path) -> bool;
    /// The directory whose folder holds the memory of sessions started
    /// in `dir` ([`memory_root_known`]). `None` where git cannot be run.
    fn memory_root(&self, dir: &Path) -> Option<PathBuf>;
}

/// The machine the node runs on, asked each time.
pub struct ThisMachine;

impl Machine for ThisMachine {
    fn is_dir(&self, dir: &Path) -> bool {
        dir.is_dir()
    }

    fn memory_root(&self, dir: &Path) -> Option<PathBuf> {
        memory_root_known(dir)
    }
}

/// How long what git said of a directory is kept by [`Remembered`]. A
/// status is asked every few seconds by a status line, and asks about
/// each folder that a notice names.
const ROOT_KEPT: std::time::Duration = std::time::Duration::from_secs(30);

/// The machine the node runs on, asked of git no more often than every
/// [`ROOT_KEPT`] for one directory: what a status asks, while a notice is
/// stored. Whether a directory is there is asked of the disk each time.
/// (`cordelia sync map` does not ask through this: it asks git when it
/// is run.)
pub struct Remembered;

/// What git last said of each directory, and when.
type Roots = std::collections::HashMap<PathBuf, (std::time::Instant, Option<PathBuf>)>;

static ROOTS: std::sync::LazyLock<std::sync::Mutex<Roots>> =
    std::sync::LazyLock::new(Default::default);

impl Machine for Remembered {
    fn is_dir(&self, dir: &Path) -> bool {
        dir.is_dir()
    }

    fn memory_root(&self, dir: &Path) -> Option<PathBuf> {
        let kept = |roots: &Roots| {
            let fresh = roots.get(dir).filter(|(at, _)| at.elapsed() < ROOT_KEPT);
            fresh.map(|(_, root)| root.clone())
        };
        if let Some(root) = kept(&ROOTS.lock().unwrap_or_else(|e| e.into_inner())) {
            return root;
        }
        // Asked with the lock let go: git may take its time.
        let root = memory_root_known(dir);
        let mut roots = ROOTS.lock().unwrap_or_else(|e| e.into_inner());
        roots.retain(|_, (at, _)| at.elapsed() < ROOT_KEPT);
        roots.insert(dir.to_path_buf(), (std::time::Instant::now(), root.clone()));
        root
    }
}

/// What `cordelia sync map` would do with a folder that was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Maps {
    /// A mapping's Claude Code folder is this folder: it syncs now.
    Mapped,
    /// `map`, given the folder's directory, would sync this folder.
    Yes(How),
    /// It would not, and why.
    No(WhyNot),
}

/// How a folder is mapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum How {
    /// By its directory, under the name it has.
    UnderItsName,
    /// It is the home directory: `cordelia sync home on`, or `cordelia
    /// sync map ~ <name> --home`.
    Home,
    /// By its directory and a name that a person gives it.
    UnderAName(WhyAName),
}

/// Why a folder can be mapped only under a name that a person gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhyAName {
    /// It has none: it is not a git project with a remote.
    HasNone,
    /// The name it has is not one that a folder can be mapped under.
    NotUsable,
    /// Another folder is mapped under the name it has: that folder.
    Taken(String),
}

/// Why `cordelia sync map` would not sync a folder that was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhyNot {
    /// It is not under the Claude Code directory that is set: a notice
    /// names it, and was made under another directory.
    UnderAnotherDirectory,
    /// Claude Code did not name the folder after its directory: it is of
    /// a memory tree that someone laid out by hand.
    LaidOutByHand,
    /// No directory is known for it.
    NoDirectory,
    /// `HOME` is not set in the node's environment.
    HomeNotSet,
    /// Its directory is outside the home directory.
    OutsideHome,
    /// Its directory's path is too long for Claude Code's folder name to
    /// be told from it.
    PathTooLong,
    /// Its directory is gone.
    DirectoryGone,
    /// Git cannot be run, so the repository that its directory may be in
    /// is not known.
    GitNotRun,
    /// Claude Code keeps the memory of its directory with this one: a
    /// git repository that contains it.
    MemoryElsewhere(PathBuf),
}

impl WhyNot {
    /// The reason in a word, for whoever reads a status by a program.
    pub fn code(&self) -> &'static str {
        match self {
            WhyNot::UnderAnotherDirectory => "another_claude_dir",
            WhyNot::LaidOutByHand => "laid_out_by_hand",
            WhyNot::NoDirectory => "no_directory",
            WhyNot::HomeNotSet => "home_not_set",
            WhyNot::OutsideHome => "outside_home",
            WhyNot::PathTooLong => "path_too_long",
            WhyNot::DirectoryGone => "directory_gone",
            WhyNot::GitNotRun => "git_not_run",
            WhyNot::MemoryElsewhere(_) => "memory_elsewhere",
        }
    }

    /// The reason in words, for a person: what stands in the place of a
    /// command that would map the folder.
    pub fn says(&self) -> String {
        match self {
            WhyNot::UnderAnotherDirectory => {
                "it is not under the Claude Code directory that sync is set to".into()
            }
            WhyNot::LaidOutByHand => "this layout cannot be mapped: Claude Code did not name \
                                      the folder after its directory"
                .into(),
            WhyNot::NoDirectory => "its directory is not known".into(),
            WhyNot::HomeNotSet => {
                "HOME is not set for the node: nothing can be mapped until it is".into()
            }
            WhyNot::OutsideHome => "outside your home directory: it cannot be mapped".into(),
            WhyNot::PathTooLong => format!(
                "its path is longer than {FOLDER_NAME_MAX} characters: it cannot be mapped yet"
            ),
            WhyNot::DirectoryGone => "its directory is gone".into(),
            WhyNot::GitNotRun => "the node cannot run git, and cannot tell which repository \
                                  its directory is in"
                .into(),
            WhyNot::MemoryElsewhere(root) => format!(
                "Claude Code now keeps its memory with {}, a git repository that contains it",
                root.display()
            ),
        }
    }
}

impl WhyAName {
    /// Why a name is needed, in words.
    pub fn says(&self) -> String {
        match self {
            WhyAName::HasNone => "needs a name (not a git project)".into(),
            WhyAName::NotUsable => "needs a name (the one it has cannot be mapped)".into(),
            WhyAName::Taken(folder) => {
                format!("needs another name (its own is mapped from {folder})")
            }
        }
    }
}

/// Whether `cordelia sync map` would sync the folder `asked`, and why not
/// where it would not (see the module's documentation).
///
/// **Its tests are made in this order,** and the first that holds is the
/// answer:
///
/// 1. **The folder,** on its whole path under the Claude Code directory
///    that is set. A folder that is not directly under that directory's
///    `projects` is of another directory. A folder that a mapping's
///    directory names is mapped now: by its Claude Code folder, and not by
///    its directory or its name. A folder that Claude Code did not name
///    after its directory is a tree laid out by hand, whatever its
///    transcripts record as its directory, the home directory included.
/// 2. **The directory:** none is known; `HOME` is not set; it is outside
///    the home directory; its path is too long; it is gone; git cannot be
///    run; or Claude Code keeps its memory with a repository that
///    contains it. The home directory itself is mapped by its own command.
/// 3. **The name:** it has none, or one that cannot be mapped, or one
///    that another folder is mapped under. It can then be mapped under a
///    name that a person gives it.
pub fn would_map(asked: &Asked, against: &Against, machine: &dyn Machine) -> Maps {
    // 1. The folder.
    let folder = asked.folder;
    let projects = against.claude_dir.join("projects");
    if folder.parent() != Some(projects.as_path()) {
        return Maps::No(WhyNot::UnderAnotherDirectory);
    }
    let synced_by = |mapping: &SyncMapping| {
        claude_folder(against.claude_dir, Path::new(&mapping.folder)).as_deref() == Some(folder)
    };
    if against.mappings.iter().any(synced_by) {
        return Maps::Mapped;
    }
    // Claude Code names its folders after an absolute path, so each
    // starts with a dash.
    let named_as_one_of_its_own = folder
        .file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with('-'));
    let named_after_it = match asked.directory {
        Some(directory) => is_claude_folder_for(folder, directory),
        None => named_as_one_of_its_own,
    };
    if !named_after_it {
        return Maps::No(WhyNot::LaidOutByHand);
    }

    // 2. The directory.
    let Some(directory) = asked.directory else {
        return Maps::No(WhyNot::NoDirectory);
    };
    let Some(home) = against.home else {
        return Maps::No(WhyNot::HomeNotSet);
    };
    if !directory.starts_with(home) {
        return Maps::No(WhyNot::OutsideHome);
    }
    if claude_folder_name(directory).len() > FOLDER_NAME_MAX {
        return Maps::No(WhyNot::PathTooLong);
    }
    if !machine.is_dir(directory) {
        return Maps::No(WhyNot::DirectoryGone);
    }
    match machine.memory_root(directory) {
        None => return Maps::No(WhyNot::GitNotRun),
        Some(root) if root != directory => return Maps::No(WhyNot::MemoryElsewhere(root)),
        Some(_) => {}
    }
    if directory == home {
        return Maps::Yes(How::Home);
    }

    // 3. The name.
    let Some(name) = asked.name else {
        return Maps::Yes(How::UnderAName(WhyAName::HasNone));
    };
    // In its one spelling, as `map` sends a name that is typed.
    let name = cordelia_core::sync_name::tidy(name);
    if !crate::names::is_a_name(&name) || name == HOME_NAME {
        return Maps::Yes(How::UnderAName(WhyAName::NotUsable));
    }
    if let Some(mapped) = against.mappings.iter().find(|mapping| mapping.name == name) {
        return Maps::Yes(How::UnderAName(WhyAName::Taken(mapped.folder.clone())));
    }
    Maps::Yes(How::UnderItsName)
}

/// The name of home memory: only the home directory is mapped under it.
const HOME_NAME: &str = "~";

// ── An entry, as a status carries it ─────────────────────────────────

/// A folder that was found and is not mapped, as a status carries it:
/// the adapter's report lists one for each folder it found, and the
/// node's status one for each folder that a notice names.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Entry {
    /// Claude Code's folder for it.
    pub folder: String,
    /// The directory to map to sync it. **It is carried only where
    /// `cordelia sync map`, given this directory, would sync this
    /// folder:** whoever offers a switch or a command for each entry
    /// that has one maps this folder and no other.
    pub cwd: Option<String>,
    /// The directory it belongs to, where one is known and `map` would
    /// not sync this folder: to show, and never to map.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
    /// The name it would sync under, or did: `~` for home, the
    /// normalised remote for a git project, nothing for any other folder.
    pub name: Option<String>,
    /// Whether `cordelia sync map`, given the directory under `cwd`,
    /// would sync this folder.
    pub mappable: bool,
    /// Whether it can be mapped only under a name that a person gives
    /// it: it has none, or the one it has cannot be used.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub needs_name: bool,
    /// Whether it is the home directory's own folder, which has its own
    /// command: `cordelia sync home on`, or `cordelia sync map ~ <name>
    /// --home`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub home: bool,
    /// Whether a mapping syncs this folder now. An entry of a notice can
    /// be; what the adapter lists as found never is.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub mapped: bool,
    /// Why `map` would not sync it, in a word ([`WhyNot::code`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why_not: Option<&'static str>,
    /// Why not, or why a name is needed, in words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub says: Option<String>,
}

impl Entry {
    /// The entry for the folder `asked`, with what [`would_map`] says of
    /// it.
    pub fn of(asked: &Asked, against: &Against, machine: &dyn Machine) -> Self {
        let shown = |path: &Path| path.display().to_string();
        let directory = asked.directory.map(shown);
        let mut entry = Self {
            folder: shown(asked.folder),
            name: asked.name.map(str::to_string),
            ..Default::default()
        };
        match would_map(asked, against, machine) {
            Maps::Mapped => {
                entry.mapped = true;
                entry.directory = directory;
            }
            Maps::Yes(how) => {
                entry.mappable = true;
                entry.cwd = directory;
                match how {
                    How::UnderItsName => {}
                    How::Home => entry.home = true,
                    How::UnderAName(why) => {
                        entry.needs_name = true;
                        entry.says = Some(why.says());
                    }
                }
            }
            Maps::No(why) => {
                entry.directory = directory;
                entry.why_not = Some(why.code());
                entry.says = Some(why.says());
            }
        }
        entry
    }
}

// ── The folders that a notice names ──────────────────────────────────

/// A folder that a notice names, with the record that names it last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Named {
    /// Claude Code's folder for it.
    pub folder: String,
    /// The directory it belongs to, where the notice has one.
    pub cwd: Option<String>,
    /// The name it synced under, where the notice has one.
    pub name: Option<String>,
    /// The Claude Code directory that it synced under.
    pub synced_under: Option<String>,
    /// When the notice was stored.
    pub at: String,
}

/// Each folder that the stored notices name, once, in the order in which
/// each was first named (decision 2026-10-04 §10.1). A folder is told by
/// Claude Code's folder for it. Where it is named again, the later
/// directory and name stand, with the later record's date and Claude Code
/// directory.
pub fn named_in(notices: &[Notice]) -> Vec<Named> {
    let mut out: Vec<Named> = Vec::new();
    for notice in notices {
        for stopped in notice.folders.iter().flatten() {
            let named = Named {
                folder: stopped.folder.clone(),
                cwd: stopped.cwd.clone(),
                name: stopped.name.clone(),
                synced_under: notice.dir.clone(),
                at: notice.at.clone(),
            };
            match out
                .iter_mut()
                .find(|earlier| earlier.folder == named.folder)
            {
                Some(earlier) => *earlier = named,
                None => out.push(named),
            }
        }
    }
    out
}

/// One record of the notice, as a status carries it: one for each time a
/// notice was stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NoticeRecord {
    /// When it was stored (RFC 3339).
    pub at: String,
    /// The Claude Code directory that sync was on for then, or last was.
    pub dir: Option<String>,
    /// How many folders it names. `None` where what stopped is not
    /// known: the record has the date alone.
    pub folders: Option<usize>,
}

/// A folder that the notice names, as a status carries it: what the one
/// function says of it now ([`Entry`]), with the Claude Code directory
/// that it synced under and the date of the record that names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NoticeFolder {
    #[serde(flatten)]
    pub entry: Entry,
    /// The Claude Code directory that it synced under.
    pub synced_under: Option<String>,
    /// When the record that names it was stored.
    pub at: String,
}

/// What a device whose stored scope was on is told, and told what
/// stopped (decision 2026-10-04 §10.1): the notice, as a status carries
/// it while one is stored.
///
/// It is what was syncing in the last whole cycle before only mapped
/// folders synced: a folder that had synced earlier, and not in that
/// cycle, is not in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NoticeShown {
    /// One for each time a notice was stored, the oldest first.
    pub records: Vec<NoticeRecord>,
    /// Whether some record names no folder: what stopped then is not
    /// known.
    pub not_known: bool,
    /// The Claude Code directory that its folders are asked against: the
    /// one that is set, or, with sync off, the one that turning sync on
    /// would use.
    pub dir: String,
    /// Each folder that the records name, once, with whether `cordelia
    /// sync map` would sync it now.
    pub folders: Vec<NoticeFolder>,
    /// How many of them no mapping syncs now.
    pub stopped: usize,
}

/// The notice as a status carries it, where one is stored: for each
/// folder that it names, what the one function says now ([`would_map`]),
/// asked against `against`.
pub fn notice_shown(
    notices: &[Notice],
    against: &Against,
    machine: &dyn Machine,
) -> Option<NoticeShown> {
    if notices.is_empty() {
        return None;
    }
    let records = notices
        .iter()
        .map(|notice| NoticeRecord {
            at: notice.at.clone(),
            dir: notice.dir.clone(),
            folders: notice.folders.as_ref().map(Vec::len),
        })
        .collect();
    let names_none = |notice: &Notice| {
        notice
            .folders
            .as_ref()
            .is_none_or(|folders| folders.is_empty())
    };
    let folders: Vec<NoticeFolder> = named_in(notices)
        .into_iter()
        .map(|named| {
            let asked = Asked {
                folder: Path::new(&named.folder),
                directory: named.cwd.as_deref().map(Path::new),
                name: named.name.as_deref(),
            };
            NoticeFolder {
                entry: Entry::of(&asked, against, machine),
                synced_under: named.synced_under,
                at: named.at,
            }
        })
        .collect();
    Some(NoticeShown {
        records,
        not_known: notices.iter().any(names_none),
        dir: against.claude_dir.display().to_string(),
        stopped: folders.iter().filter(|folder| !folder.entry.mapped).count(),
        folders,
    })
}

// ── `map` checks when it is run ──────────────────────────────────────

/// What `cordelia sync map` is about to do: what its check is asked of.
#[derive(Debug, Clone, Copy)]
pub struct ToMap<'a> {
    /// The directory that was given.
    pub given: &'a Path,
    /// The folder that `map` would sync: Claude Code's own folder for
    /// the directory, or for the repository the directory is in.
    pub would_sync: &'a Path,
    /// The Claude Code directory that is set.
    pub claude_dir: &'a Path,
}

impl ToMap<'_> {
    /// Whether the folder at `folder` is a tree laid out by hand for the
    /// directory that was given: Claude Code did not name it after that
    /// directory.
    pub fn is_by_hand(&self, folder: &str) -> bool {
        !is_claude_folder_for(Path::new(folder), self.given)
    }
}

/// The folder that stands in the way of `cordelia sync map`, where one
/// does (decision 2026-10-04 §10.1). `entries` are the folders that were
/// found, and those that a notice names, each as its folder and its
/// directory. One of them stands in the way where all of this holds:
///
/// - it has the directory that was given, and is another folder than the
///   one that `map` would sync;
/// - it is directly under the `projects` of the Claude Code directory
///   that is set: **a folder that a notice names under another Claude
///   Code directory stands in nobody's way,** for nothing under this
///   directory was listed for it;
/// - it holds memory now: where its memory was moved away, nothing sits
///   there that the mapping would leave behind;
/// - and, **where it is a tree laid out by hand, Claude Code's own folder
///   for the directory is not there.** Where that folder is there, `map`
///   syncs it, which is what was asked: the tree records the directory,
///   and is not its memory. Where it is not there, `map` would sync an
///   empty folder while the memory sits in the tree.
///
/// `map` asks this whenever it is run, however the command was come by:
/// copied from earlier output, sent by a panel whose status is seconds
/// old, or typed from memory. Without it, `map` would sync another folder
/// than the one that was listed.
pub fn in_the_way<'a>(
    to_map: &ToMap,
    entries: impl IntoIterator<Item = (&'a str, &'a str)>,
    machine: &dyn Machine,
) -> Option<&'a str> {
    let projects = to_map.claude_dir.join("projects");
    let own_is_there = machine.is_dir(to_map.would_sync);
    entries
        .into_iter()
        .find(|(folder, directory)| {
            let another =
                Path::new(directory) == to_map.given && Path::new(folder) != to_map.would_sync;
            let under_this = Path::new(folder).parent() == Some(projects.as_path());
            if !another || !under_this || !machine.is_dir(&Path::new(folder).join("memory")) {
                return false;
            }
            !(to_map.is_by_hand(folder) && own_is_there)
        })
        .map(|(folder, _)| folder)
}

/// What `cordelia sync map` is refused with, for the folder that stands
/// in its way ([`in_the_way`]). **Every refusal says which folder is in
/// the way, why, and what clears it** (decision 2026-10-04 §10.1).
///
/// `reason` is what stands in the place of a command for that folder,
/// where there is one. What always clears it is to move the folder's
/// memory to where `map` syncs it. `or_else` is another way out, where
/// there is one: for a tree laid out by hand, a session of Claude Code in
/// the directory makes its own folder, which `map` then syncs.
pub fn map_refused(
    to_map: &ToMap,
    folder: &str,
    reason: Option<&str>,
    machine: &dyn Machine,
) -> String {
    let (given, would_sync) = (to_map.given.display(), to_map.would_sync.display());
    let reason = reason.map(|why| format!(" ({why})")).unwrap_or_default();
    let there = match machine.is_dir(to_map.would_sync) {
        true => "",
        false => ", which is not there",
    };
    let mut says = format!(
        "{given} was found as the directory of the memory in {folder}{reason}, and `cordelia \
         sync map` would sync another folder for it ({would_sync}{there}): nothing was mapped. \
         To sync the memory in {folder}, move it into {would_sync}/memory, where Claude Code \
         keeps the memory of {given}, and map again."
    );
    if to_map.is_by_hand(folder) {
        says.push_str(&format!(
            " To map {given} and leave that memory where it is, start a Claude Code session in \
             {given} first: it makes the folder that `cordelia sync map` then syncs."
        ));
    }
    says
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A machine as a test says it is: the directories that are there,
    /// the repository that each directory is in, and whether git runs.
    #[derive(Default)]
    struct Said {
        gone: Vec<&'static str>,
        inside: Vec<(&'static str, &'static str)>,
        no_git: bool,
    }

    impl Machine for Said {
        fn is_dir(&self, dir: &Path) -> bool {
            !self.gone.iter().any(|gone| Path::new(gone) == dir)
        }

        fn memory_root(&self, dir: &Path) -> Option<PathBuf> {
            if self.no_git {
                return None;
            }
            let root = self
                .inside
                .iter()
                .find(|(inside, _)| Path::new(inside) == dir);
            Some(root.map_or_else(|| dir.to_path_buf(), |(_, root)| PathBuf::from(root)))
        }
    }

    const HOME: &str = "/home/sam";
    const CLAUDE: &str = "/home/sam/.claude";

    fn mapping(folder: &str, name: &str) -> SyncMapping {
        SyncMapping {
            folder: folder.into(),
            name: name.into(),
        }
    }

    /// Claude Code's own folder for `dir`, under the directory that is
    /// set.
    fn folder_of(dir: &str) -> String {
        let folder = claude_folder(Path::new(CLAUDE), Path::new(dir));
        folder.unwrap().display().to_string()
    }

    fn asks(
        folder: &str,
        directory: Option<&str>,
        name: Option<&str>,
        mappings: &[SyncMapping],
        machine: &Said,
        home: Option<&str>,
    ) -> Maps {
        let asked = Asked {
            folder: Path::new(folder),
            directory: directory.map(Path::new),
            name,
        };
        let against = Against {
            claude_dir: Path::new(CLAUDE),
            home: home.map(Path::new),
            mappings,
        };
        would_map(&asked, &against, machine)
    }

    /// The one function, for a folder that Claude Code named after its
    /// directory, on a machine where nothing is in the way.
    fn asks_of(directory: &str, name: Option<&str>, mappings: &[SyncMapping]) -> Maps {
        let folder = folder_of(directory);
        let machine = Said::default();
        asks(
            &folder,
            Some(directory),
            name,
            mappings,
            &machine,
            Some(HOME),
        )
    }

    /// For each kind of folder that is found: whether `cordelia sync map`
    /// would sync it, and why not (decision 2026-10-04 §10.1).
    #[test]
    fn test_each_kind_of_found_folder_is_mapped_or_says_why_not() {
        let none: [SyncMapping; 0] = [];
        // A git project, under its remote's name.
        assert_eq!(
            asks_of("/home/sam/Work/cn", Some("github.com/o/cn"), &none),
            Maps::Yes(How::UnderItsName)
        );
        // A folder that is no git project: under a name that is given.
        assert_eq!(
            asks_of("/home/sam/notes", None, &none),
            Maps::Yes(How::UnderAName(WhyAName::HasNone))
        );
        // The home directory itself, by its own command, whatever is
        // mapped under `~`'s name elsewhere.
        assert_eq!(asks_of(HOME, Some("~"), &none), Maps::Yes(How::Home));
        // Outside the home directory.
        assert_eq!(
            asks_of("/srv/code/app", Some("github.com/o/app"), &none),
            Maps::No(WhyNot::OutsideHome)
        );
        assert_eq!(
            asks_of("/home/samantha/notes", None, &none),
            Maps::No(WhyNot::OutsideHome)
        );
        // A path too long for its folder's name to be told from it:
        // Claude Code's own folder for it is known by its start.
        let long = format!("/home/sam/{}", "a".repeat(200));
        let its_folder = format!(
            "{CLAUDE}/projects/{}-1a2b3c",
            &claude_folder_name(Path::new(&long))[..FOLDER_NAME_MAX]
        );
        let machine = Said::default();
        assert_eq!(
            asks(&its_folder, Some(&long), None, &none, &machine, Some(HOME)),
            Maps::No(WhyNot::PathTooLong)
        );
        // No directory known, for a folder that Claude Code named.
        let unknown = folder_of("/home/sam/unknown");
        assert_eq!(
            asks(&unknown, None, None, &none, &machine, Some(HOME)),
            Maps::No(WhyNot::NoDirectory)
        );
        // The directory gone.
        let gone = Said {
            gone: vec!["/home/sam/was-here"],
            ..Default::default()
        };
        let folder = folder_of("/home/sam/was-here");
        assert_eq!(
            asks(
                &folder,
                Some("/home/sam/was-here"),
                Some("was"),
                &none,
                &gone,
                Some(HOME)
            ),
            Maps::No(WhyNot::DirectoryGone)
        );
        // `HOME` not set in the node's environment: nothing is mapped.
        let folder = folder_of("/home/sam/notes");
        assert_eq!(
            asks(
                &folder,
                Some("/home/sam/notes"),
                Some("lab"),
                &none,
                &machine,
                None
            ),
            Maps::No(WhyNot::HomeNotSet)
        );
        // Git cannot be run: the repository above is not known.
        let no_git = Said {
            no_git: true,
            ..Default::default()
        };
        assert_eq!(
            asks(
                &folder,
                Some("/home/sam/notes"),
                Some("lab"),
                &none,
                &no_git,
                Some(HOME)
            ),
            Maps::No(WhyNot::GitNotRun)
        );
        // A repository has appeared above the directory since it was
        // found: `map` would sync the repository's folder.
        let above = Said {
            inside: vec![("/home/sam/notes", "/home/sam")],
            ..Default::default()
        };
        assert_eq!(
            asks(
                &folder,
                Some("/home/sam/notes"),
                Some("lab"),
                &none,
                &above,
                Some(HOME)
            ),
            Maps::No(WhyNot::MemoryElsewhere(PathBuf::from("/home/sam")))
        );
    }

    /// A tree laid out by hand is that, whatever its transcripts record
    /// as its directory: a git project, the home directory, a directory
    /// outside it, or none. So is a folder that Claude Code names for
    /// another directory than the one recorded.
    #[test]
    fn test_a_tree_laid_out_by_hand_is_that_whatever_directory_it_records() {
        let none: [SyncMapping; 0] = [];
        let machine = Said::default();
        let in_a_tree = format!("{CLAUDE}/projects/workspace");
        for directory in [
            Some("/home/sam/Work/cn"),
            Some(HOME),
            Some("/srv/code/app"),
            None,
        ] {
            assert_eq!(
                asks(
                    &in_a_tree,
                    directory,
                    Some("github.com/o/cn"),
                    &none,
                    &machine,
                    Some(HOME)
                ),
                Maps::No(WhyNot::LaidOutByHand),
                "{directory:?}"
            );
        }
        // With `HOME` not set, and with the directory gone: still that.
        let gone = Said {
            gone: vec!["/home/sam/Work/cn"],
            ..Default::default()
        };
        assert_eq!(
            asks(
                &in_a_tree,
                Some("/home/sam/Work/cn"),
                None,
                &none,
                &gone,
                None
            ),
            Maps::No(WhyNot::LaidOutByHand)
        );
        // Claude Code's folder for one directory, with a transcript that
        // records another: not that directory's folder.
        let of_another = folder_of("/home/sam/other");
        assert_eq!(
            asks(
                &of_another,
                Some("/home/sam/notes"),
                None,
                &none,
                &machine,
                Some(HOME)
            ),
            Maps::No(WhyNot::LaidOutByHand)
        );
    }

    /// The order of the tests: the folder first, then the directory, then
    /// the name. Each folder here fails two of them, and is said to fail
    /// the one that comes first.
    #[test]
    fn test_the_folder_is_judged_first_then_the_directory_then_the_name() {
        let machine = Said::default();
        let mapped = [mapping("/home/sam/notes", "lab")];
        // Under another Claude Code directory, and mapped by its
        // directory there: of another directory.
        let elsewhere = "/home/sam/.claude-other/projects/-home-sam-notes";
        assert_eq!(
            asks(
                elsewhere,
                Some("/home/sam/notes"),
                Some("lab"),
                &mapped,
                &machine,
                Some(HOME)
            ),
            Maps::No(WhyNot::UnderAnotherDirectory)
        );
        // Deeper than the directory's `projects`: not under it either.
        let deeper = format!("{CLAUDE}/projects/x/-home-sam-notes");
        assert_eq!(
            asks(
                &deeper,
                Some("/home/sam/notes"),
                None,
                &[],
                &machine,
                Some(HOME)
            ),
            Maps::No(WhyNot::UnderAnotherDirectory)
        );
        // Mapped now, though its directory is gone and `HOME` is not set.
        let gone = Said {
            gone: vec!["/home/sam/notes"],
            ..Default::default()
        };
        let folder = folder_of("/home/sam/notes");
        assert_eq!(
            asks(
                &folder,
                Some("/home/sam/notes"),
                Some("lab"),
                &mapped,
                &gone,
                None
            ),
            Maps::Mapped
        );
        // Laid out by hand, and outside the home directory: laid out by
        // hand.
        let by_hand = format!("{CLAUDE}/projects/workspace");
        assert_eq!(
            asks(&by_hand, Some("/srv/app"), None, &[], &machine, Some(HOME)),
            Maps::No(WhyNot::LaidOutByHand)
        );
        // Outside the home directory, and with a name that is taken: the
        // directory is judged before the name.
        let outside = folder_of("/srv/notes");
        assert_eq!(
            asks(
                &outside,
                Some("/srv/notes"),
                Some("lab"),
                &mapped,
                &machine,
                Some(HOME)
            ),
            Maps::No(WhyNot::OutsideHome)
        );
        // Among the directory's own: `HOME` not set before anything that
        // needs it; outside home before the length of its path; its path
        // before whether it is there; whether it is there before git.
        let long_outside = format!("/srv/{}", "a".repeat(200));
        let its_folder = format!(
            "{CLAUDE}/projects/{}-0f",
            &claude_folder_name(Path::new(&long_outside))[..FOLDER_NAME_MAX]
        );
        assert_eq!(
            asks(&its_folder, Some(&long_outside), None, &[], &machine, None),
            Maps::No(WhyNot::HomeNotSet)
        );
        assert_eq!(
            asks(
                &its_folder,
                Some(&long_outside),
                None,
                &[],
                &machine,
                Some(HOME)
            ),
            Maps::No(WhyNot::OutsideHome)
        );
        let gone_and_no_git = Said {
            gone: vec!["/home/sam/was-here"],
            no_git: true,
            ..Default::default()
        };
        let was_here = folder_of("/home/sam/was-here");
        assert_eq!(
            asks(
                &was_here,
                Some("/home/sam/was-here"),
                None,
                &[],
                &gone_and_no_git,
                Some(HOME)
            ),
            Maps::No(WhyNot::DirectoryGone)
        );
        // The home directory with a repository above it is not the home
        // directory's own folder.
        let above_home = Said {
            inside: vec![(HOME, "/home")],
            ..Default::default()
        };
        assert_eq!(
            asks(
                &folder_of(HOME),
                Some(HOME),
                Some("~"),
                &[],
                &above_home,
                Some(HOME)
            ),
            Maps::No(WhyNot::MemoryElsewhere(PathBuf::from("/home")))
        );
    }

    /// An entry is mapped now when a mapping's Claude Code folder is its
    /// folder: not when its directory or its name is mapped. So a tree
    /// laid out by hand whose directory is mapped is still listed, and so
    /// is the second of two clones of one repository: under a name of
    /// its own.
    #[test]
    fn test_an_entry_is_mapped_by_its_folder_and_not_by_its_directory_or_name() {
        let machine = Said::default();
        let mapped = [mapping("/home/sam/Work/cn", "github.com/o/cn")];
        // The folder that the mapping syncs.
        assert_eq!(
            asks_of("/home/sam/Work/cn", Some("github.com/o/cn"), &mapped),
            Maps::Mapped
        );
        // Two paths that Claude Code keeps in one folder: the same folder.
        assert_eq!(
            asks_of("/home/sam/Work.cn", Some("another"), &mapped),
            Maps::Mapped
        );
        // A tree laid out by hand that records the mapped directory.
        let by_hand = format!("{CLAUDE}/projects/workspace");
        assert_eq!(
            asks(
                &by_hand,
                Some("/home/sam/Work/cn"),
                Some("github.com/o/cn"),
                &mapped,
                &machine,
                Some(HOME)
            ),
            Maps::No(WhyNot::LaidOutByHand)
        );
        // A second clone, found under the name that the first is mapped
        // under: it needs a name of its own.
        assert_eq!(
            asks_of("/home/sam/src/cn", Some("github.com/o/cn"), &mapped),
            Maps::Yes(How::UnderAName(WhyAName::Taken("/home/sam/Work/cn".into())))
        );
    }

    /// The name: one that is not usable needs another, one in another
    /// spelling is taken in its one spelling, as `map` sends it, and `~`
    /// names nothing but the home directory.
    #[test]
    fn test_a_folder_whose_name_cannot_be_used_is_mapped_under_another() {
        let none: [SyncMapping; 0] = [];
        for (name, how) in [
            ("lab", How::UnderItsName),
            ("github.com/o/cn", How::UnderItsName),
            // As an earlier version found a remote: tidied, it is a name.
            ("github.com/o/cn.git", How::UnderItsName),
            ("Has Space", How::UnderAName(WhyAName::NotUsable)),
            ("-x", How::UnderAName(WhyAName::NotUsable)),
            ("~", How::UnderAName(WhyAName::NotUsable)),
            ("", How::UnderAName(WhyAName::NotUsable)),
        ] {
            assert_eq!(
                asks_of("/home/sam/notes", Some(name), &none),
                Maps::Yes(how),
                "{name:?}"
            );
        }
        // Taken in its one spelling.
        let mapped = [mapping("/home/sam/Work/cn", "github.com/o/cn")];
        assert_eq!(
            asks_of("/home/sam/src/cn", Some("github.com/o/cn.git"), &mapped),
            Maps::Yes(How::UnderAName(WhyAName::Taken("/home/sam/Work/cn".into())))
        );
    }

    /// An entry carries its directory under `cwd` only where `map` would
    /// sync its folder, and under another key where it would not: with
    /// why, in a word and in words. One that needs a name says so.
    #[test]
    fn test_an_entry_carries_its_directory_only_where_map_would_sync_it() {
        let machine = Said::default();
        let mapped = [mapping("/home/sam/Work/cn", "github.com/o/cn")];
        let entry = |folder: &str, directory: Option<&str>, name: Option<&str>| {
            let asked = Asked {
                folder: Path::new(folder),
                directory: directory.map(Path::new),
                name,
            };
            let against = Against {
                claude_dir: Path::new(CLAUDE),
                home: Some(Path::new(HOME)),
                mappings: &mapped,
            };
            Entry::of(&asked, &against, &machine)
        };

        let maps = entry(
            &folder_of("/home/sam/notes"),
            Some("/home/sam/notes"),
            Some("lab"),
        );
        assert_eq!(
            maps,
            Entry {
                folder: folder_of("/home/sam/notes"),
                cwd: Some("/home/sam/notes".into()),
                name: Some("lab".into()),
                mappable: true,
                ..Default::default()
            }
        );
        let as_json = serde_json::to_value(&maps).unwrap();
        assert_eq!(
            as_json,
            serde_json::json!({
                "folder": folder_of("/home/sam/notes"),
                "cwd": "/home/sam/notes",
                "name": "lab",
                "mappable": true,
            })
        );

        let home = entry(&folder_of(HOME), Some(HOME), Some("~"));
        assert!(home.mappable && home.home && !home.needs_name);
        assert_eq!(home.cwd.as_deref(), Some(HOME));
        assert_eq!(serde_json::to_value(&home).unwrap()["home"], true);

        let needs = entry(&folder_of("/home/sam/ideas"), Some("/home/sam/ideas"), None);
        assert_eq!(needs.cwd.as_deref(), Some("/home/sam/ideas"));
        assert!(needs.mappable && needs.needs_name);
        assert_eq!(
            needs.says.as_deref(),
            Some("needs a name (not a git project)")
        );

        let by_hand = format!("{CLAUDE}/projects/workspace");
        let cannot = entry(&by_hand, Some("/home/sam/Work/cn"), Some("github.com/o/cn"));
        assert_eq!(
            serde_json::to_value(&cannot).unwrap(),
            serde_json::json!({
                "folder": by_hand,
                "cwd": null,
                "directory": "/home/sam/Work/cn",
                "name": "github.com/o/cn",
                "mappable": false,
                "why_not": "laid_out_by_hand",
                "says": "this layout cannot be mapped: Claude Code did not name the folder \
                         after its directory",
            })
        );

        let synced = entry(
            &folder_of("/home/sam/Work/cn"),
            Some("/home/sam/Work/cn"),
            Some("github.com/o/cn"),
        );
        assert!(synced.mapped && !synced.mappable);
        assert_eq!((synced.cwd.as_deref(), synced.why_not), (None, None));
        assert_eq!(synced.directory.as_deref(), Some("/home/sam/Work/cn"));

        // Each reason has a word of its own, and words.
        let reasons = [
            WhyNot::UnderAnotherDirectory,
            WhyNot::LaidOutByHand,
            WhyNot::NoDirectory,
            WhyNot::HomeNotSet,
            WhyNot::OutsideHome,
            WhyNot::PathTooLong,
            WhyNot::DirectoryGone,
            WhyNot::GitNotRun,
            WhyNot::MemoryElsewhere(PathBuf::from("/home/sam")),
        ];
        let mut codes: Vec<&str> = reasons.iter().map(WhyNot::code).collect();
        codes.sort();
        codes.dedup();
        assert_eq!(codes.len(), reasons.len());
        assert!(reasons.iter().all(|why| !why.says().is_empty()));
    }

    /// What a status asks of git, it asks once for a directory while the
    /// answer is kept: a status is asked every few seconds. Whether the
    /// directory is there is asked each time. `map` asks git when it is
    /// run.
    #[test]
    fn test_what_git_said_of_a_directory_is_kept_for_a_status() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let notes = base.join("above/notes");
        std::fs::create_dir_all(&notes).unwrap();
        assert_eq!(Remembered.memory_root(&notes), Some(notes.clone()));
        assert_eq!(ThisMachine.memory_root(&notes), Some(notes.clone()));
        // A repository appears above it.
        let made = Command::new("git")
            .arg("-C")
            .arg(base.join("above"))
            .args(["init", "-q"])
            .output()
            .unwrap();
        assert!(made.status.success());
        assert_eq!(ThisMachine.memory_root(&notes), Some(base.join("above")));
        assert_eq!(Remembered.memory_root(&notes), Some(notes.clone()));
        // The disk is asked each time.
        assert!(Remembered.is_dir(&notes));
        std::fs::remove_dir_all(&notes).unwrap();
        assert!(!Remembered.is_dir(&notes));
        assert!(!ThisMachine.is_dir(&notes));
    }

    /// The notice as a status carries it: one record for each time it
    /// was stored, each folder once, and for each what the one function
    /// says now. A folder that is named again has its later directory and
    /// name. A record with the date alone says that what stopped is not
    /// known. What is mapped since is counted as stopped no longer.
    #[test]
    fn test_the_notice_names_each_folder_once_with_what_map_would_do_now() {
        use cordelia_storage::first_start::StoppedFolder;
        let machine = Said::default();
        let stopped = |directory: &str, name: Option<&str>| StoppedFolder {
            folder: folder_of(directory),
            cwd: Some(directory.into()),
            name: name.map(str::to_string),
        };
        let notice = |at: &str, dir: &str, folders: Option<Vec<StoppedFolder>>| Notice {
            at: at.into(),
            dir: Some(dir.into()),
            folders,
        };
        let against = |mappings: &'static [SyncMapping]| Against {
            claude_dir: Path::new(CLAUDE),
            home: Some(Path::new(HOME)),
            mappings,
        };
        assert_eq!(notice_shown(&[], &against(&[]), &machine), None);

        // The form of a report from before mappings: no directory.
        let from_before = StoppedFolder {
            folder: folder_of("/home/sam/old"),
            cwd: None,
            name: Some("github.com/o/old".into()),
        };
        // A tree laid out by hand, and a folder under another directory.
        let by_hand = StoppedFolder {
            folder: format!("{CLAUDE}/projects/workspace"),
            cwd: Some("/home/sam/Work/cn".into()),
            name: Some("github.com/o/cn".into()),
        };
        let elsewhere = StoppedFolder {
            folder: "/home/sam/.other/projects/-home-sam-x".into(),
            cwd: Some("/home/sam/x".into()),
            name: None,
        };
        let first = notice(
            "2026-10-05T10:00:00Z",
            CLAUDE,
            Some(vec![
                stopped("/home/sam/Work/cn", Some("github.com/o/cn")),
                stopped("/home/sam/notes", None),
                from_before.clone(),
                by_hand.clone(),
            ]),
        );
        // Later: one of them again, with another directory's name, and
        // one more; and a record with the date alone.
        let again = StoppedFolder {
            name: Some("github.com/o/renamed".into()),
            ..stopped("/home/sam/Work/cn", None)
        };
        let second = notice(
            "2026-10-06T10:00:00Z",
            "/home/sam/.other",
            Some(vec![again, elsewhere.clone()]),
        );
        let third = Notice {
            at: "2026-10-07T10:00:00Z".into(),
            dir: None,
            folders: None,
        };
        let all = [first, second, third];
        let shown = notice_shown(&all, &against(&[]), &machine).unwrap();
        assert_eq!(
            shown.records,
            [
                NoticeRecord {
                    at: "2026-10-05T10:00:00Z".into(),
                    dir: Some(CLAUDE.into()),
                    folders: Some(4)
                },
                NoticeRecord {
                    at: "2026-10-06T10:00:00Z".into(),
                    dir: Some("/home/sam/.other".into()),
                    folders: Some(2)
                },
                NoticeRecord {
                    at: "2026-10-07T10:00:00Z".into(),
                    dir: None,
                    folders: None
                },
            ]
        );
        assert!(shown.not_known);
        assert_eq!(shown.dir, CLAUDE);
        assert_eq!(shown.stopped, 5);
        let named: Vec<&str> = shown
            .folders
            .iter()
            .map(|folder| folder.entry.folder.as_str())
            .collect();
        assert_eq!(
            named,
            [
                folder_of("/home/sam/Work/cn").as_str(),
                folder_of("/home/sam/notes").as_str(),
                folder_of("/home/sam/old").as_str(),
                by_hand.folder.as_str(),
                elsewhere.folder.as_str(),
            ]
        );
        // Named twice: the later name, date and directory stand, and its
        // command would carry that name.
        let cn = &shown.folders[0];
        assert_eq!(cn.entry.name.as_deref(), Some("github.com/o/renamed"));
        assert_eq!(cn.entry.cwd.as_deref(), Some("/home/sam/Work/cn"));
        assert!(cn.entry.mappable && !cn.entry.needs_name);
        assert_eq!(cn.at, "2026-10-06T10:00:00Z");
        assert_eq!(cn.synced_under.as_deref(), Some("/home/sam/.other"));
        // The others, each as the one function says.
        let why: Vec<Option<&str>> = shown.folders.iter().map(|f| f.entry.why_not).collect();
        assert_eq!(
            why,
            [
                None,
                None,
                Some("no_directory"),
                Some("laid_out_by_hand"),
                Some("another_claude_dir")
            ]
        );
        assert!(shown.folders[1].entry.needs_name);
        for cannot in &shown.folders[2..] {
            assert_eq!(cannot.entry.cwd, None, "{cannot:?}");
            assert!(!cannot.entry.mappable);
        }
        // As JSON: an entry's fields beside the two of the notice.
        let as_json = serde_json::to_value(&shown).unwrap();
        assert_eq!(as_json["folders"][3]["why_not"], "laid_out_by_hand");
        assert_eq!(as_json["folders"][3]["synced_under"], CLAUDE);
        assert_eq!(as_json["folders"][3]["cwd"], serde_json::Value::Null);
        assert_eq!(as_json["folders"][3]["directory"], "/home/sam/Work/cn");
        assert_eq!(as_json["records"][2]["folders"], serde_json::Value::Null);

        // Mapped since: by its folder, and it is stopped no longer.
        let mapped: &'static [SyncMapping] = Box::leak(Box::new([
            mapping("/home/sam/Work/cn", "github.com/o/renamed"),
            mapping("/home/sam/notes", "lab"),
        ]));
        let shown = notice_shown(&all, &against(mapped), &machine).unwrap();
        assert!(shown.folders[0].entry.mapped && shown.folders[1].entry.mapped);
        assert_eq!(shown.stopped, 3);

        // A notice whose records all name folders says nothing is
        // unknown, and one that names none says that it is.
        let known = notice_shown(&all[..2], &against(&[]), &machine).unwrap();
        assert!(!known.not_known);
        let empty = notice("2026-10-07T10:00:00Z", CLAUDE, Some(Vec::new()));
        let unknown = notice_shown(&[empty], &against(&[]), &machine).unwrap();
        assert!(unknown.not_known && unknown.folders.is_empty());
        assert_eq!(unknown.stopped, 0);
    }

    /// `map` is refused for a directory that an entry has with another
    /// folder than the one `map` would sync, and for no other: not for an
    /// entry of another directory, and not where the folder that was
    /// found is the one that would be synced.
    ///
    /// A tree laid out by hand that records the directory stands in the
    /// way only where Claude Code's own folder for the directory is not
    /// there (decision 2026-10-04 §10.1): where it is, `map` syncs it,
    /// which is what was asked. An entry whose folder is under another
    /// Claude Code directory stands in nobody's way, and nor does a
    /// folder that holds no memory now.
    #[test]
    fn test_map_is_refused_for_a_directory_whose_found_folder_is_another() {
        let would_sync = PathBuf::from(folder_of("/home/sam/Work/cn"));
        let by_hand = format!("{CLAUDE}/projects/workspace");
        let given = Path::new("/home/sam/Work/cn");
        let to_map = ToMap {
            given,
            would_sync: &would_sync,
            claude_dir: Path::new(CLAUDE),
        };
        let own: &'static str = folder_of("/home/sam/Work/cn").leak();
        let by_hand: &'static str = by_hand.leak();
        // Claude Code's own folder for the directory is not there.
        let own_gone = Said {
            gone: vec![own],
            ..Default::default()
        };
        let stands = |entries: &[(&'static str, &'static str)], machine: &Said| {
            in_the_way(&to_map, entries.iter().copied(), machine)
        };
        assert_eq!(stands(&[], &own_gone), None);
        assert_eq!(stands(&[(own, "/home/sam/Work/cn")], &own_gone), None);
        assert_eq!(stands(&[(by_hand, "/home/sam/other")], &own_gone), None);
        let both = [(own, "/home/sam/Work/cn"), (by_hand, "/home/sam/Work/cn")];
        assert_eq!(stands(&both, &own_gone), Some(by_hand));

        // The own folder is there: the tree stands in nobody's way, with
        // the own folder listed or not.
        let there = Said::default();
        assert_eq!(stands(&both, &there), None);
        assert_eq!(stands(&both[1..], &there), None);

        // A folder under another Claude Code directory: in nobody's way,
        // though it is another folder for the directory, laid out by
        // hand or named by Claude Code.
        let elsewhere: &'static str = "/home/sam/.claude-before/projects/workspace";
        let named_elsewhere: &'static str = "/home/sam/.claude-before/projects/-home-sam-Work-cn";
        let deeper: &'static str = "/home/sam/.claude/projects/a/workspace";
        for folder in [elsewhere, named_elsewhere, deeper] {
            assert_eq!(stands(&[(folder, "/home/sam/Work/cn")], &own_gone), None);
        }
        // A tree whose memory was moved away holds none: it is in
        // nobody's way.
        let moved: &'static str = format!("{by_hand}/memory").leak();
        let emptied = Said {
            gone: vec![own, moved],
            ..Default::default()
        };
        assert_eq!(stands(&both, &emptied), None);

        // A folder that Claude Code named after the directory, and that
        // is another than the one `map` would sync (the directory's
        // memory is now a repository's): in the way, with the folder
        // that would be synced there or not.
        let of_the_repository = PathBuf::from(folder_of("/home/sam/Work"));
        let above = ToMap {
            given,
            would_sync: &of_the_repository,
            claude_dir: Path::new(CLAUDE),
        };
        let found = [(own, "/home/sam/Work/cn")];
        assert_eq!(in_the_way(&above, found.iter().copied(), &there), Some(own));
        assert!(!above.is_by_hand(own));
        assert!(to_map.is_by_hand(by_hand));

        // A folder that Claude Code named after another directory, and
        // that records this one, is laid out by hand for this one.
        let after_another: &'static str = folder_of("/home/sam/Work/old").leak();
        assert!(to_map.is_by_hand(after_another));
        let recorded = [(after_another, "/home/sam/Work/cn")];
        assert_eq!(stands(&recorded, &there), None);
        assert_eq!(stands(&recorded, &own_gone), Some(after_another));

        // Every refusal says which folder is in the way, why, and what
        // clears it.
        let why = map_refused(
            &to_map,
            by_hand,
            Some(&WhyNot::LaidOutByHand.says()),
            &own_gone,
        );
        assert!(why.contains(by_hand), "{why}");
        assert!(why.contains("this layout cannot be mapped"), "{why}");
        assert!(why.contains("would sync another folder"), "{why}");
        assert!(
            why.contains(&format!("({own}, which is not there)")),
            "{why}"
        );
        assert!(why.contains("nothing was mapped"), "{why}");
        assert!(
            why.contains(&format!(
                "To sync the memory in {by_hand}, move it into {own}/memory"
            )),
            "{why}"
        );
        assert!(
            why.contains("start a Claude Code session in /home/sam/Work/cn first"),
            "{why}"
        );
        // A folder that Claude Code named: the one way out.
        let bare = map_refused(&above, own, None, &there);
        assert!(
            bare.contains(&format!("{own}, and `cordelia sync map`")),
            "{bare}"
        );
        let repository = of_the_repository.display();
        assert!(bare.contains(&format!("({repository})")), "{bare}");
        assert!(
            bare.contains(&format!("move it into {repository}/memory")),
            "{bare}"
        );
        assert!(!bare.contains("start a Claude Code session"), "{bare}");
    }
}
