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

// ── `map` checks when it is run ──────────────────────────────────────

/// The folder that stands in the way of `cordelia sync map` for the
/// directory `given`, where one does (decision 2026-10-04 §10.1): an
/// entry that was found, or that a notice names, has that directory, and
/// a Claude Code folder other than `would_sync`, which is the folder that
/// `map` would sync. `entries` are those entries, each as its folder and
/// its directory.
///
/// `map` asks this whenever it is run, however the command was come by:
/// copied from earlier output, sent by a panel whose status is seconds
/// old, or typed from memory. Without it, `map` would sync another folder
/// than the one that was listed: for a tree laid out by hand, Claude
/// Code's own folder for the directory, which may hold memory that the
/// tree had kept out.
pub fn in_the_way<'a>(
    given: &Path,
    would_sync: &Path,
    entries: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Option<&'a str> {
    entries
        .into_iter()
        .find(|(folder, directory)| {
            Path::new(directory) == given && Path::new(folder) != would_sync
        })
        .map(|(folder, _)| folder)
}

/// What `cordelia sync map` is refused with, for the directory `given`
/// and the folder that stands in its way ([`in_the_way`]): with the
/// reason that stands in the place of a command for that folder, where
/// there is one.
pub fn map_refused(given: &Path, would_sync: &Path, folder: &str, reason: Option<&str>) -> String {
    let reason = reason.map(|why| format!(" ({why})")).unwrap_or_default();
    format!(
        "{} was found as the directory of the memory in {folder}{reason}, and `cordelia sync \
         map` would sync another folder for it ({}): nothing was mapped. No command maps the \
         memory in {folder} as it stands: it has to be where Claude Code keeps the memory of a \
         folder that can be mapped.",
        given.display(),
        would_sync.display(),
    )
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

    /// `map` is refused for a directory that an entry has with another
    /// folder than the one `map` would sync, and for no other: not for an
    /// entry of another directory, and not where the folder that was
    /// found is the one that would be synced.
    #[test]
    fn test_map_is_refused_for_a_directory_whose_found_folder_is_another() {
        let would_sync = PathBuf::from(folder_of("/home/sam/Work/cn"));
        let by_hand = format!("{CLAUDE}/projects/workspace");
        let given = Path::new("/home/sam/Work/cn");
        let stands = |entries: &[(&'static str, &'static str)]| {
            in_the_way(given, &would_sync, entries.iter().copied())
        };
        let own: &'static str = folder_of("/home/sam/Work/cn").leak();
        let by_hand: &'static str = by_hand.leak();
        assert_eq!(stands(&[]), None);
        assert_eq!(stands(&[(own, "/home/sam/Work/cn")]), None);
        assert_eq!(stands(&[(by_hand, "/home/sam/other")]), None);
        let folder = stands(&[(own, "/home/sam/Work/cn"), (by_hand, "/home/sam/Work/cn")]);
        assert_eq!(folder, Some(by_hand));

        let why = map_refused(
            given,
            &would_sync,
            by_hand,
            Some(&WhyNot::LaidOutByHand.says()),
        );
        assert!(why.contains(by_hand), "{why}");
        assert!(why.contains("this layout cannot be mapped"), "{why}");
        assert!(why.contains("would sync another folder"), "{why}");
        assert!(why.contains("nothing was mapped"), "{why}");
        let bare = map_refused(given, &would_sync, by_hand, None);
        assert!(
            bare.contains(&format!("{by_hand}, and `cordelia sync map`")),
            "{bare}"
        );
    }
}
