//! Memory that is found on a machine and is not mapped: whether `cordelia
//! sync map` would sync it (decision 2026-10-04 §10.1).
//!
//! Only what is mapped syncs. A folder that holds memory and is not
//! mapped is listed by the sync adapter, for what it finds on disk, so
//! that a person can map it. Beside each is the command that maps it,
//! **and that command must map that folder and no other.**
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
//! sync it, and why not where it would not ([`would_map`]). Its tests
//! are made in one order: the folder first, then the directory, then the
//! name.
//!
//! An entry that `map` would not sync is carried without its directory
//! under `cwd` ([`Entry`]): a panel that is not yet brought up to date
//! gives a switch to every found entry that has a `cwd`, and that switch
//! would map another folder.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use cordelia_core::claude_code::{FOLDER_NAME_MAX, folder_name};
use cordelia_core::protocol::STREAM_TIMEOUT_SECS;

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

/// The deadline that git is given where its caller has no bound of its
/// own: [`STREAM_TIMEOUT_SECS`] from now.
pub fn git_deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(STREAM_TIMEOUT_SECS)
}

/// The command that asks git where `cwd` is.
fn git_rev_parse(cwd: &Path) -> Command {
    let mut git = Command::new("git");
    git.arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--show-toplevel", "--git-common-dir"]);
    git
}

/// What git's answer says of `cwd`.
fn layout_of(cwd: &Path, output: &std::process::Output) -> Layout {
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

/// Ask git for the work tree `cwd` is in and the repository's common
/// directory, with git given until `deadline`: `None` where it has not
/// answered by then, and is killed.
fn git_layout_by(cwd: &Path, deadline: std::time::Instant) -> Option<Layout> {
    Some(match git_output_by(&mut git_rev_parse(cwd), deadline)? {
        Ok(output) => layout_of(cwd, &output),
        Err(_) => Layout::GitNotRun,
    })
}

/// Run `git`, given until `deadline`: `None` where it has not answered by
/// then, and is killed, with what it started; an error where it cannot be
/// run. What it writes must be a few short lines, which the pipe holds
/// whole.
pub fn git_output_by(
    git: &mut Command,
    deadline: std::time::Instant,
) -> Option<std::io::Result<std::process::Output>> {
    use std::process::Stdio;
    // A process group of its own: a `git` that is a wrapper (a version
    // manager's shim) may run git, or anything, without `exec`.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(git, 0);
    let mut child = match git
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => return Some(Err(e)),
    };
    loop {
        // The time is taken before git is looked at: an answer seen after
        // the deadline is not taken, however soon after it git ended.
        let in_time = std::time::Instant::now() < deadline;
        match child.try_wait() {
            Ok(Some(_)) if in_time => break,
            Ok(None) if in_time => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            _ => {
                // Its group, while git is not yet waited for and the
                // group's ID cannot be another's.
                #[cfg(unix)]
                if let Ok(group) = libc::pid_t::try_from(child.id()) {
                    // SAFETY: kill(2) is given no pointer.
                    unsafe { libc::kill(-group, libc::SIGKILL) };
                }
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    child.wait_with_output().ok().map(Ok)
}

/// What [`git_run_by`] keeps of what git writes, and how it stops git.
#[derive(Debug, Clone, Copy)]
pub struct GitBounds {
    /// The most bytes of git's output that are kept. Git that writes more
    /// is stopped, and gives [`GitRan::TooMuch`].
    pub stdout_max: usize,
    /// The most bytes of what git says on stderr that are kept: the last
    /// ones, where it says more, as an error is said last.
    pub stderr_max: usize,
    /// How long git is given to end after TERM, once it is to be stopped,
    /// before its group is killed.
    pub term_grace: std::time::Duration,
}

/// What came of git, run by [`git_run_by`].
#[derive(Debug)]
pub enum GitRan {
    /// It ended by its deadline: how, what it wrote, and the last of what
    /// it said on stderr.
    Ended {
        status: std::process::ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    /// It wrote more than [`GitBounds::stdout_max`], and was stopped.
    TooMuch,
    /// It had not ended by its deadline, and was stopped.
    Late,
    /// It could not be run.
    NotRun(std::io::Error),
}

/// Run `git` as [`git_output_by`] does, in a process group of its own and
/// given until `deadline`, with what `bounds` say: its output read as it
/// comes and kept up to a bound, the last of its stderr kept, and git
/// stopped by TERM first and KILL after (decision 2026-11-06 (joining),
/// rule 3). TERM lets git remove the locks it holds. Whatever its group
/// started is killed with it.
///
/// Its group is signalled only while git is not yet reaped, so that the
/// group's ID cannot be another's: whether git has ended is asked without
/// reaping it.
pub fn git_run_by(git: &mut Command, deadline: std::time::Instant, bounds: GitBounds) -> GitRan {
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(git, 0);
    let mut child = match git
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => return GitRan::NotRun(e),
    };
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        stop(&mut child, bounds.term_grace);
        return GitRan::NotRun(std::io::Error::other("git's output was not given"));
    };
    let stdout_max = bounds.stdout_max;
    let mut stdout = Some(std::thread::spawn(move || read_at_most(out, stdout_max)));
    let stderr_max = bounds.stderr_max;
    let mut stderr = Some(std::thread::spawn(move || read_the_last(err, stderr_max)));
    let mut output = None;
    let mut nap = Duration::from_millis(1);
    loop {
        // As in `git_output_by`: an answer seen after the deadline is not
        // taken, however soon after it git ended.
        if Instant::now() >= deadline {
            stop(&mut child, bounds.term_grace);
            return GitRan::Late;
        }
        if let Some(reading) = stdout.take_if(|reading| reading.is_finished()) {
            match reading.join() {
                Ok((kept, false)) => output = Some(kept),
                _ => {
                    stop(&mut child, bounds.term_grace);
                    return GitRan::TooMuch;
                }
            }
        }
        // Git has ended, and both of its pipes are closed: what holds them
        // open past git's end is of its group, and is stopped with it at
        // the deadline.
        let said = stderr.as_ref().is_some_and(|reading| reading.is_finished());
        if output.is_some() && said && has_ended(&mut child) {
            let said = stderr.take().and_then(|reading| reading.join().ok());
            return match child.wait() {
                Ok(status) => GitRan::Ended {
                    status,
                    stdout: output.unwrap_or_default(),
                    stderr: said.unwrap_or_default(),
                },
                Err(e) => GitRan::NotRun(e),
            };
        }
        std::thread::sleep(nap);
        nap = (nap * 2).min(Duration::from_millis(10));
    }
}

/// Stop git: TERM to its group, up to `grace` for git to end, then KILL
/// to its group and to git, and git reaped. A reader of its output that
/// something outside its group still holds open is left to end by itself.
fn stop(child: &mut std::process::Child, grace: std::time::Duration) {
    #[cfg(unix)]
    {
        use std::time::{Duration, Instant};
        signal_group(child, libc::SIGTERM);
        let until = Instant::now() + grace;
        while !has_ended(child) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
        signal_group(child, libc::SIGKILL);
    }
    #[cfg(not(unix))]
    let _ = grace;
    let _ = child.kill();
    let _ = child.wait();
}

/// Send `signal` to the process group that git leads. Only while git is
/// not yet reaped: its group's ID is then its own.
#[cfg(unix)]
fn signal_group(child: &std::process::Child, signal: libc::c_int) {
    if let Ok(group) = libc::pid_t::try_from(child.id()) {
        // SAFETY: kill(2) is given no pointer.
        unsafe { libc::kill(-group, signal) };
    }
}

/// Whether git has ended, asked without reaping it, so that its process
/// group's ID stays its own until [`stop`] or the caller reaps it.
#[cfg(unix)]
fn has_ended(child: &mut std::process::Child) -> bool {
    // `id_t` is a `u32` where the node runs, and may be narrower elsewhere.
    #[allow(irrefutable_let_patterns)]
    let Ok(pid) = libc::id_t::try_from(child.id()) else {
        return true;
    };
    // SAFETY: an all-zero siginfo_t is a valid value of it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: waitid(2) writes only to `info`, which outlives the call.
    let asked = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if asked != 0 {
        // Interrupted: asked again on the next look. Any other error says
        // that there is no such child left to wait for.
        return std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted;
    }
    // SAFETY: waitid filled `info`; with WNOHANG, its pid is 0 where git
    // has not ended.
    unsafe { info.si_pid() != 0 }
}

/// Whether git has ended. Elsewhere than on Unix, it is reaped as it is
/// asked, and no group is signalled.
#[cfg(not(unix))]
fn has_ended(child: &mut std::process::Child) -> bool {
    !matches!(child.try_wait(), Ok(None))
}

/// Read `from` to its end, keeping at most `max` bytes: true beside them
/// where more came, and nothing more is read.
fn read_at_most(mut from: impl std::io::Read, max: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf) {
            Ok(0) => return (kept, false),
            Ok(n) if kept.len() + n > max => return (kept, true),
            Ok(n) => kept.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return (kept, false),
        }
    }
}

/// Read `from` to its end, keeping its last `max` bytes.
fn read_the_last(mut from: impl std::io::Read, max: usize) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                kept.extend_from_slice(&buf[..n]);
                if kept.len() > 2 * max.max(1) {
                    kept.drain(..kept.len() - max);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    if kept.len() > max {
        kept.drain(..kept.len() - max);
    }
    kept
}

/// The directory whose folder holds the memory for sessions started in
/// `cwd`, where git can be run. Claude Code keeps one memory per git
/// repository, shared by its subdirectories and worktrees, in the folder
/// of the repository's main working tree. Outside a repository it is
/// `cwd` itself. `None` where git cannot be run, or has not answered by
/// [`git_deadline`]: the repository that `cwd` may be in is then not
/// known.
pub fn memory_root_known(cwd: &Path) -> Option<PathBuf> {
    root_of(cwd, git_layout_by(cwd, git_deadline())?)
}

/// [`memory_root_known`] of `cwd`, given what git says of it.
fn root_of(cwd: &Path, layout: Layout) -> Option<PathBuf> {
    Some(match layout {
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

/// [`memory_root_known`], or `cwd` itself where git cannot be run, with
/// git given until `deadline` (decision 2026-10-09 §4.1, C20): `None`
/// where git has not answered by then. Git is killed, and nothing falls
/// back to `cwd` itself, which may be another agent's folder than the
/// repository's.
pub fn memory_root_by(cwd: &Path, deadline: std::time::Instant) -> Option<PathBuf> {
    let layout = git_layout_by(cwd, deadline)?;
    Some(root_of(cwd, layout).unwrap_or_else(|| cwd.to_path_buf()))
}

/// Whether [`memory_root_known`] is a guess for `cwd`: it is in a repository
/// whose common directory is not a plain `.git`, which is a submodule or a
/// worktree of a bare repository. Where Claude Code keeps memory for those
/// has not been confirmed. Not where git has not answered by
/// [`git_deadline`]: nothing is known of the directory then.
pub fn memory_root_is_assumed(cwd: &Path) -> bool {
    match git_layout_by(cwd, git_deadline()) {
        Some(Layout::Repository { common, .. }) => common.file_name().is_none_or(|n| n != ".git"),
        Some(Layout::GitNotRun | Layout::NoRepository) | None => false,
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

// ── The directory that a folder's transcripts record ─────────────────

/// Lines read from each transcript while looking for the working directory.
const TRANSCRIPT_SCAN_LINES: usize = 200;

/// Transcripts read per folder while looking for its working directory.
const TRANSCRIPTS_SCANNED: usize = 20;

/// The working directories recorded in the folder's transcripts, without
/// repeats: the newest transcript's first. A session can move to another
/// directory, so a folder's transcripts may name more than one.
pub fn recorded_cwds(folder: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut transcripts: Vec<(std::time::SystemTime, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "jsonl"))
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    transcripts.sort_by_key(|t| std::cmp::Reverse(t.0));

    let mut found: Vec<PathBuf> = Vec::new();
    for (_, path) in transcripts.into_iter().take(TRANSCRIPTS_SCANNED) {
        let Ok(file) = std::fs::File::open(&path) else {
            continue;
        };
        for line in std::io::BufReader::new(file)
            .lines()
            .take(TRANSCRIPT_SCAN_LINES)
            .map_while(Result::ok)
        {
            if !line.contains("\"cwd\"") {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line)
                && let Some(cwd) = value.get("cwd").and_then(|c| c.as_str())
                && !found.iter().any(|f| f == Path::new(cwd))
            {
                found.push(PathBuf::from(cwd));
            }
        }
    }
    found
}

/// The directory that the folder `folder` under `projects` belongs to,
/// as its transcripts record it, told as the sync adapter tells it:
///
/// - the directory that Claude Code named the folder after, where a
///   transcript of it records that directory: a session can move
///   elsewhere, and a folder is believed only about the directory it is
///   named after;
/// - for a folder that Claude Code did not name (its names start with a
///   dash), which is a tree laid out by hand, the directory that its
///   newest transcript records first;
/// - none for a folder that Claude Code named and whose transcripts
///   record another directory, or none.
pub fn recorded_directory(folder: &Path) -> Option<PathBuf> {
    let cwds = recorded_cwds(folder);
    if let Some(own) = cwds.iter().find(|cwd| is_claude_folder_for(folder, cwd)) {
        return Some(own.clone());
    }
    let named_by_claude = folder
        .file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with('-'));
    match named_by_claude {
        true => None,
        false => cwds.into_iter().next(),
    }
}

/// Whether the memory folder `memory` holds a file that a cycle would
/// look at: a plain file whose name does not start with a dot (#207). One
/// that cannot be read is taken to hold one, so that it is listed; one
/// that is not there, or is no folder, holds none.
pub fn holds_a_file(memory: &Path) -> bool {
    let entries = match std::fs::read_dir(memory) {
        Ok(entries) => entries,
        Err(e) => {
            use std::io::ErrorKind::{NotADirectory, NotFound};
            return !matches!(e.kind(), NotFound | NotADirectory);
        }
    };
    entries.filter_map(Result::ok).any(|entry| {
        !entry.file_name().to_string_lossy().starts_with('.')
            && entry.file_type().is_ok_and(|kind| kind.is_file())
    })
}

/// What is found on disk for the directory `given`, under the Claude Code
/// directory `claude_dir`, as the node looks itself (decision 2026-10-04
/// §10.1): each folder directly under `projects` whose memory holds a
/// file ([`holds_a_file`]) and that belongs to that directory
/// ([`recorded_directory`]), as its folder and
/// its directory as recorded, in order of folder. Directories are
/// compared by their real paths.
///
/// `map` checks against what the last cycle's report lists as found, and
/// every request that changes a setting removes that report. Until the
/// next cycle stores one, the node looks here, at the one directory that
/// is being mapped: a mapping that comes just after another is checked
/// as any is. It reads the transcripts of each folder that holds memory,
/// which is what a cycle does, and is called with the database's lock
/// let go.
pub fn found_for(claude_dir: &Path, given: &Path, machine: &dyn Machine) -> Vec<(String, String)> {
    let Ok(listed) = std::fs::read_dir(claude_dir.join("projects")) else {
        return Vec::new();
    };
    let real = |dir: &Path| machine.real_path(dir).unwrap_or_else(|| dir.to_path_buf());
    let given = real(given);
    let shown = |path: &Path| path.display().to_string();
    let mut found: Vec<(String, String)> = listed
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|folder| holds_a_file(&folder.join("memory")))
        .filter_map(|folder| Some((shown(&folder), recorded_directory(&folder)?)))
        .filter(|(_, directory)| real(directory) == given)
        .map(|(folder, directory)| (folder, shown(&directory)))
        .collect();
    found.sort();
    found
}

// ── Whether `map` would sync a folder ────────────────────────────────

/// A folder that was found: what the one function is asked about.
#[derive(Debug, Clone, Copy)]
pub struct Asked<'a> {
    /// Claude Code's folder for it, by its whole path.
    pub folder: &'a Path,
    /// The directory it belongs to, where one is known: what its
    /// transcripts record.
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
    /// The real path of `dir`, with every link on the way followed.
    /// `None` where it cannot be told: the directory is gone.
    fn real_path(&self, dir: &Path) -> Option<PathBuf>;
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

    fn real_path(&self, dir: &Path) -> Option<PathBuf> {
        dir.canonicalize().ok()
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
    /// Another folder is mapped under the name it has.
    Taken {
        /// The name, as `map` would send it.
        name: String,
        /// The folder that is mapped under it.
        folder: String,
        /// Whether that folder is there: one that is gone may be this
        /// one, moved.
        there: bool,
    },
}

/// Why `cordelia sync map` would not sync a folder that was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhyNot {
    /// It is not under the Claude Code directory that is set.
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
    /// Its directory is reached through a link, and this is its real
    /// path: `map` syncs the folder that Claude Code names after the real
    /// path, which is another folder.
    ThroughALink(PathBuf),
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
            WhyNot::ThroughALink(_) => "through_a_link",
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
            WhyNot::ThroughALink(real) => format!(
                "its directory is reached through a link: `cordelia sync map` syncs the folder \
                 of {}, which is another",
                real.display()
            ),
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
    /// Why a name is needed, in words, with a folder under `home` shown
    /// from `~`.
    pub fn says(&self, home: Option<&Path>) -> String {
        match self {
            WhyAName::HasNone => "needs a name (not a git project)".into(),
            WhyAName::NotUsable => "needs a name (the one it has cannot be mapped)".into(),
            WhyAName::Taken {
                name,
                folder,
                there,
            } => {
                let folder = from_home(Path::new(folder), home);
                match there {
                    true => format!(
                        "{name} already syncs from {folder}: give this one its own name, or \
                         unmap {folder} first"
                    ),
                    false => format!(
                        "{name} is mapped from {folder}, which is gone: unmap it first, or give \
                         this one its own name"
                    ),
                }
            }
        }
    }
}

/// `path` as a person reads it: from `~` where it is under `home`.
fn from_home(path: &Path, home: Option<&Path>) -> String {
    match home.and_then(|home| path.strip_prefix(home).ok()) {
        Some(rest) if rest.as_os_str().is_empty() => "~".into(),
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
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
///    the home directory; its path is too long; it is gone; it is not its
///    own real path; git cannot be run; or Claude Code keeps its memory
///    with a repository that contains it. The home directory itself is
///    mapped by its own command.
///
///    `cordelia sync map` takes a directory by its real path, and syncs
///    the folder that Claude Code names after that. So a directory that
///    was recorded through a link is asked by its real path here too: a
///    command printed for it would map the folder of the real path, which
///    is another folder than the one that was found.
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
    match machine.real_path(directory) {
        Some(real) if real != directory => return Maps::No(WhyNot::ThroughALink(real)),
        Some(_) => {}
        None => return Maps::No(WhyNot::DirectoryGone),
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
        return Maps::Yes(How::UnderAName(WhyAName::Taken {
            name,
            folder: mapped.folder.clone(),
            there: machine.is_dir(Path::new(&mapped.folder)),
        }));
    }
    Maps::Yes(How::UnderItsName)
}

/// The name of home memory: only the home directory is mapped under it.
const HOME_NAME: &str = "~";

// ── An entry, as a status carries it ─────────────────────────────────

/// A folder that was found and is not mapped, as a status carries it:
/// the adapter's report lists one for each folder it found that it lists
/// (one whose memory holds no file is listed only where mapping it would
/// bring memory in).
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
    /// Whether a mapping syncs this folder now: what the adapter lists as
    /// found never is.
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
                        entry.says = Some(why.says(against.home));
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
/// found, each as its folder and its directory. One of them stands in the
/// way where all of this holds:
///
/// - it has the directory that was given, and is another folder than the
///   one that `map` would sync. **Directories are compared by their real
///   paths,** as `map` takes the one it is given: a folder whose directory
///   was recorded through a link has the directory that the link leads
///   to;
/// - it is directly under the `projects` of the Claude Code directory
///   that is set;
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
/// than the one that was listed. Returns the entry that stands in the
/// way: its folder, and its directory as it was recorded.
pub fn in_the_way<'a>(
    to_map: &ToMap,
    entries: impl IntoIterator<Item = (&'a str, &'a str)>,
    machine: &dyn Machine,
) -> Option<(&'a str, &'a str)> {
    let projects = to_map.claude_dir.join("projects");
    let own_is_there = machine.is_dir(to_map.would_sync);
    // A directory that is gone has no real path: it is compared as it is
    // written.
    let real = |dir: &Path| machine.real_path(dir).unwrap_or_else(|| dir.to_path_buf());
    let given = real(to_map.given);
    entries.into_iter().find(|(folder, directory)| {
        let another = real(Path::new(directory)) == given && Path::new(folder) != to_map.would_sync;
        let under_this = Path::new(folder).parent() == Some(projects.as_path());
        if !another || !under_this || !machine.is_dir(&Path::new(folder).join("memory")) {
            return false;
        }
        !(to_map.is_by_hand(folder) && own_is_there)
    })
}

/// What `cordelia sync map` is refused with, for the folder that stands
/// in its way ([`in_the_way`]). **Every refusal says which folder is in
/// the way, why, and what clears it** (decision 2026-10-04 §10.1).
///
/// `reason` is what stands in the place of a command for that folder,
/// where there is one. What always clears it is to move the folder's
/// memory to where `map` syncs it. For a tree laid out by hand there is
/// another way: a session of Claude Code in the directory makes its own
/// folder, which `map` then syncs.
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
        /// Each path that is there and is no directory: a file.
        files: Vec<&'static str>,
        inside: Vec<(&'static str, &'static str)>,
        no_git: bool,
        /// Each directory that is a link, with where it leads.
        links: Vec<(&'static str, &'static str)>,
    }

    impl Machine for Said {
        fn is_dir(&self, dir: &Path) -> bool {
            let is = |paths: &[&str]| paths.iter().any(|path| Path::new(path) == dir);
            !is(&self.gone) && !is(&self.files)
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

        fn real_path(&self, dir: &Path) -> Option<PathBuf> {
            // What is gone has no real path. A file has one.
            if self.gone.iter().any(|gone| Path::new(gone) == dir) {
                return None;
            }
            let link = self.links.iter().find(|(link, _)| Path::new(link) == dir);
            Some(link.map_or_else(|| dir.to_path_buf(), |(_, real)| PathBuf::from(real)))
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
        // A file where the directory was: the path is there, it has a
        // real path, and git says that it is in no repository. It is no
        // directory, and `map` takes none but a directory: gone.
        let a_file = Said {
            files: vec!["/home/sam/was-here"],
            ..Default::default()
        };
        assert_eq!(
            asks(
                &folder,
                Some("/home/sam/was-here"),
                Some("was"),
                &none,
                &a_file,
                Some(HOME)
            ),
            Maps::No(WhyNot::DirectoryGone)
        );
        // A directory that was recorded through a link: `map` takes a
        // directory by its real path, and would sync the folder of that,
        // which is another. It is said before git is asked, and after a
        // directory that is gone.
        let linked = Said {
            links: vec![("/home/sam/link", "/home/sam/Work/real")],
            no_git: true,
            ..Default::default()
        };
        let folder = folder_of("/home/sam/link");
        let through = WhyNot::ThroughALink(PathBuf::from("/home/sam/Work/real"));
        assert_eq!(
            asks(
                &folder,
                Some("/home/sam/link"),
                Some("lab"),
                &none,
                &linked,
                Some(HOME)
            ),
            Maps::No(through.clone())
        );
        assert_eq!(through.code(), "through_a_link");
        assert!(
            through
                .says()
                .contains("syncs the folder of /home/sam/Work/real, which is another"),
            "{}",
            through.says()
        );
        // The real directory itself is mapped as any other.
        let real_folder = folder_of("/home/sam/Work/real");
        let with_git = Said {
            links: vec![("/home/sam/link", "/home/sam/Work/real")],
            ..Default::default()
        };
        assert_eq!(
            asks(
                &real_folder,
                Some("/home/sam/Work/real"),
                Some("lab"),
                &none,
                &with_git,
                Some(HOME)
            ),
            Maps::Yes(How::UnderItsName)
        );
        let link_gone = Said {
            links: vec![("/home/sam/link", "/home/sam/Work/real")],
            gone: vec!["/home/sam/link"],
            ..Default::default()
        };
        assert_eq!(
            asks(
                &folder,
                Some("/home/sam/link"),
                Some("lab"),
                &none,
                &link_gone,
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
            Maps::Yes(How::UnderAName(WhyAName::Taken {
                name: "github.com/o/cn".into(),
                folder: "/home/sam/Work/cn".into(),
                there: true,
            }))
        );
    }

    /// What a memory folder holds, as the found list counts it (#207): a
    /// plain file whose name does not start with a dot. One that is not
    /// there, or is no folder, holds none; one that cannot be read is
    /// taken to hold one, so that it is listed.
    #[test]
    fn test_a_memory_folder_holds_a_file_only_where_a_cycle_would_look_at_one() {
        let tmp = tempfile::tempdir().unwrap();
        let memory = tmp.path().join("memory");
        assert!(!holds_a_file(&memory), "not there");
        std::fs::write(tmp.path().join("a-file"), "x").unwrap();
        assert!(!holds_a_file(&tmp.path().join("a-file")), "no folder");
        std::fs::create_dir(&memory).unwrap();
        assert!(!holds_a_file(&memory), "empty");
        std::fs::write(memory.join(".DS_Store"), "x").unwrap();
        std::fs::create_dir(memory.join("kept")).unwrap();
        assert!(!holds_a_file(&memory), "a dotfile and a folder");
        std::fs::write(memory.join("a.md"), "x").unwrap();
        assert!(holds_a_file(&memory));

        use std::os::unix::fs::PermissionsExt;
        let locked = tmp.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        // One who may read anything (root) reads it, and it is empty.
        if std::fs::read_dir(&locked).is_err() {
            assert!(holds_a_file(&locked), "cannot be read");
        }
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A name that another folder is mapped under: whether that folder is
    /// there, and the words for each, with a folder under the home
    /// directory shown from `~`.
    #[test]
    fn test_a_name_mapped_from_another_folder_says_whether_that_folder_is_there() {
        let mapped = [mapping("/home/sam/Work/cn", "github.com/o/cn")];
        let Maps::Yes(How::UnderAName(there)) =
            asks_of("/home/sam/src/cn", Some("github.com/o/cn"), &mapped)
        else {
            panic!("not a name taken");
        };
        assert_eq!(
            there.says(Some(Path::new(HOME))),
            "github.com/o/cn already syncs from ~/Work/cn: give this one its own name, or unmap \
             ~/Work/cn first"
        );
        let gone = Said {
            gone: vec!["/home/sam/Work/cn"],
            ..Default::default()
        };
        let folder = folder_of("/home/sam/src/cn");
        let asked = asks(
            &folder,
            Some("/home/sam/src/cn"),
            Some("github.com/o/cn"),
            &mapped,
            &gone,
            Some(HOME),
        );
        let Maps::Yes(How::UnderAName(why)) = asked else {
            panic!("{asked:?}");
        };
        assert_eq!(
            why,
            WhyAName::Taken {
                name: "github.com/o/cn".into(),
                folder: "/home/sam/Work/cn".into(),
                there: false,
            }
        );
        assert_eq!(
            why.says(Some(Path::new(HOME))),
            "github.com/o/cn is mapped from ~/Work/cn, which is gone: unmap it first, or give \
             this one its own name"
        );
        // Outside the home directory, or with none known, as it is.
        assert!(why.says(None).contains("mapped from /home/sam/Work/cn,"));
        assert_eq!(from_home(Path::new(HOME), Some(Path::new(HOME))), "~");
        assert_eq!(
            from_home(Path::new("/home/samantha"), Some(Path::new(HOME))),
            "/home/samantha"
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
            Maps::Yes(How::UnderAName(WhyAName::Taken {
                name: "github.com/o/cn".into(),
                folder: "/home/sam/Work/cn".into(),
                there: true,
            }))
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

    /// Git given until a deadline answers as git with none, and where the
    /// deadline is past it is killed, and no directory is answered: not
    /// the subdirectory itself, which is not the repository's root
    /// (decision 2026-10-09 §4.1, C20).
    #[test]
    fn test_git_given_until_a_deadline_answers_in_time_or_not_at_all() {
        use std::time::{Duration, Instant};
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let notes = base.join("repo/notes");
        std::fs::create_dir_all(&notes).unwrap();
        let in_time = || Instant::now() + Duration::from_secs(30);
        assert_eq!(memory_root_by(&notes, in_time()), Some(notes.clone()));
        let made = Command::new("git")
            .arg("-C")
            .arg(base.join("repo"))
            .args(["init", "-q"])
            .output()
            .unwrap();
        assert!(made.status.success());
        assert_eq!(memory_root_by(&notes, in_time()), Some(base.join("repo")));
        assert_eq!(memory_root_by(&notes, in_time()), memory_root_known(&notes));
        // A deadline past before git is looked at gives no answer, though
        // git ended before that look, as it may on a loaded machine: asked
        // often, so that one such end is likely among them.
        for _ in 0..500 {
            assert_eq!(memory_root_by(&notes, Instant::now()), None);
        }
    }

    /// A `git` that is a wrapper, and runs a child without `exec`, as some
    /// version managers' shims do: at the deadline, nothing it started is
    /// left running.
    #[cfg(unix)]
    #[test]
    fn test_a_git_that_is_a_wrapper_leaves_nothing_running() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};
        let tmp = tempfile::tempdir().unwrap();
        let git = tmp.path().join("git");
        let pid_file = tmp.path().join("child.pid");
        std::fs::write(
            &git,
            "#!/bin/sh\nsh -c 'echo $$ > \"$PID_FILE\"; exec sleep 30'\necho done\n",
        )
        .unwrap();
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut wrapper = Command::new(&git);
        wrapper.env("PID_FILE", &pid_file);
        assert!(git_output_by(&mut wrapper, deadline).is_none());
        let pid: libc::pid_t = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // Running: listed, and not a zombie that no one has reaped yet.
        let running = || {
            let ps = Command::new("ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .unwrap();
            let stat = String::from_utf8_lossy(&ps.stdout).trim().to_string();
            !stat.is_empty() && !stat.starts_with('Z')
        };
        let gone_by = Instant::now() + Duration::from_secs(5);
        while running() && Instant::now() < gone_by {
            std::thread::sleep(Duration::from_millis(50));
        }
        let left = running();
        if left {
            // SAFETY: kill(2) is given no pointer.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        assert!(!left, "the wrapper's child {pid} is still running");
    }

    /// A script that stands in for git, run by `git_run_by` through
    /// `sh`: a file that is written and then run as a program may be held
    /// open for writing by a fork in another of the tests' threads, which
    /// fails its run.
    #[cfg(unix)]
    fn script(dir: &Path, body: &str) -> Command {
        let path = dir.join("git.sh");
        std::fs::write(&path, format!("{body}\n")).unwrap();
        let mut sh = Command::new("/bin/sh");
        sh.arg(path);
        sh
    }

    /// Whether the process `pid` is running: listed, and not a zombie.
    #[cfg(unix)]
    fn is_running(pid: &str) -> bool {
        let ps = Command::new("ps")
            .args(["-o", "stat=", "-p", pid])
            .output()
            .unwrap();
        let stat = String::from_utf8_lossy(&ps.stdout).trim().to_string();
        !stat.is_empty() && !stat.starts_with('Z')
    }

    fn bounds(stdout_max: usize, stderr_max: usize, term_grace_ms: u64) -> GitBounds {
        GitBounds {
            stdout_max,
            stderr_max,
            term_grace: std::time::Duration::from_millis(term_grace_ms),
        }
    }

    /// Git that ends in time gives its status, its output whole, and the
    /// last of what it said on stderr, where an error is said
    /// (decision 2026-11-06 (joining), rule 3).
    #[cfg(unix)]
    #[test]
    fn test_git_run_by_keeps_the_output_and_the_last_of_stderr() {
        use std::time::{Duration, Instant};
        let tmp = tempfile::tempdir().unwrap();
        let mut git = script(
            tmp.path(),
            "head -c 20000 /dev/zero | tr '\\0' x >&2\necho 'fatal: the last' >&2\n\
             printf 'one\\ntwo\\n'\nexit 3",
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        let GitRan::Ended {
            status,
            stdout,
            stderr,
        } = git_run_by(&mut git, deadline, bounds(100, 64, 100))
        else {
            panic!("git ended in time");
        };
        assert_eq!(status.code(), Some(3));
        assert_eq!(stdout, b"one\ntwo\n");
        assert_eq!(stderr.len(), 64);
        assert!(stderr.ends_with(b"fatal: the last\n"));
        // Output of just its bound is whole; a byte more is too much.
        let mut git = script(tmp.path(), "printf 12345");
        let ran = git_run_by(&mut git, deadline, bounds(5, 64, 100));
        assert!(matches!(ran, GitRan::Ended { ref stdout, .. } if stdout == b"12345"));
        let mut git = script(tmp.path(), "printf 123456");
        assert!(matches!(
            git_run_by(&mut git, deadline, bounds(5, 64, 100)),
            GitRan::TooMuch
        ));
        let mut missing = Command::new(tmp.path().join("no-such-git"));
        assert!(matches!(
            git_run_by(&mut missing, deadline, bounds(5, 64, 100)),
            GitRan::NotRun(_)
        ));
    }

    /// Git that writes more than its bound is stopped at once, not at its
    /// deadline, and nothing of it is left running.
    #[cfg(unix)]
    #[test]
    fn test_git_run_by_stops_git_that_writes_too_much() {
        use std::time::{Duration, Instant};
        let tmp = tempfile::tempdir().unwrap();
        let pid_file = tmp.path().join("pid");
        let mut git = script(tmp.path(), "echo $$ > \"$PID_FILE\"\nexec yes");
        git.env("PID_FILE", &pid_file);
        let began = Instant::now();
        let ran = git_run_by(
            &mut git,
            began + Duration::from_secs(30),
            bounds(4096, 64, 100),
        );
        assert!(matches!(ran, GitRan::TooMuch));
        assert!(began.elapsed() < Duration::from_secs(10));
        let pid = std::fs::read_to_string(&pid_file).unwrap();
        assert!(!is_running(pid.trim()));
    }

    /// At its deadline, git is sent TERM first, and given its grace to
    /// end: a git that removes its locks on TERM has done so.
    #[cfg(unix)]
    #[test]
    fn test_git_run_by_sends_term_before_kill() {
        use std::time::{Duration, Instant};
        let tmp = tempfile::tempdir().unwrap();
        let mark = tmp.path().join("termed");
        let mut git = script(
            tmp.path(),
            "trap 'echo term > \"$MARK\"; exit 0' TERM\nwhile :; do sleep 0.05; done",
        );
        git.env("MARK", &mark);
        let ran = git_run_by(
            &mut git,
            Instant::now() + Duration::from_millis(500),
            bounds(64, 64, 5000),
        );
        assert!(matches!(ran, GitRan::Late));
        assert_eq!(std::fs::read_to_string(&mark).unwrap(), "term\n");
    }

    /// Git that does not end on TERM is killed once its grace is over,
    /// with what it started, and none of it is left running; an answer
    /// seen after the deadline is not taken.
    #[cfg(unix)]
    #[test]
    fn test_git_run_by_kills_git_that_ignores_term() {
        use std::time::{Duration, Instant};
        let tmp = tempfile::tempdir().unwrap();
        let pid_file = tmp.path().join("pid");
        // TERM ignored, and a child that holds git's output open after git
        // itself has ended.
        let mut git = script(
            tmp.path(),
            "trap '' TERM\nsh -c 'trap \"\" TERM; echo $$ > \"$PID_FILE\"; exec sleep 30' &\n\
             echo started",
        );
        git.env("PID_FILE", &pid_file);
        let began = Instant::now();
        let ran = git_run_by(
            &mut git,
            began + Duration::from_secs(1),
            bounds(64, 64, 300),
        );
        assert!(matches!(ran, GitRan::Late));
        assert!(began.elapsed() < Duration::from_secs(10));
        let pid = std::fs::read_to_string(&pid_file).unwrap();
        let gone_by = Instant::now() + Duration::from_secs(5);
        while is_running(pid.trim()) && Instant::now() < gone_by {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(!is_running(pid.trim()), "{pid} is still running");
        for _ in 0..200 {
            let mut quick = Command::new("/bin/sh");
            quick.args(["-c", "echo quick"]);
            assert!(matches!(
                git_run_by(&mut quick, Instant::now(), bounds(64, 64, 100)),
                GitRan::Late
            ));
        }
    }

    /// The node looks at what is found for a directory itself (decision
    /// 2026-10-04 §10.1): each folder under `projects` that holds memory
    /// and belongs to the directory, as the sync adapter tells which
    /// directory a folder belongs to. A tree laid out by hand belongs to
    /// the directory that its newest transcript records first; a folder
    /// that Claude Code named, to the directory it is named after, where
    /// a transcript records that, and to none otherwise. Directories are
    /// compared by their real paths.
    #[test]
    fn test_the_node_looks_at_what_is_found_for_a_directory_itself() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let claude = root.join(".claude");
        let shown = |path: &Path| path.display().to_string();
        let work = root.join("work/app");
        let other = root.join("work/other");
        for made in [&work, &other] {
            std::fs::create_dir_all(made).unwrap();
        }
        // A folder under `projects`, with a transcript for each
        // directory it records, and with memory or without.
        let folder = |name: &str, records: &[&Path], memory: bool| {
            let folder = claude.join("projects").join(name);
            std::fs::create_dir_all(&folder).unwrap();
            if memory {
                std::fs::create_dir_all(folder.join("memory")).unwrap();
                std::fs::write(folder.join("memory/a.md"), "a\n").unwrap();
            }
            let lines: Vec<String> = records
                .iter()
                .map(|cwd| format!("{{\"type\":\"user\",\"cwd\":{:?}}}\n", shown(cwd)))
                .collect();
            if !lines.is_empty() {
                std::fs::write(folder.join("session.jsonl"), lines.concat()).unwrap();
            }
            folder
        };
        let own_name = claude_folder_name(&work);
        let own = folder(&own_name, &[&other, &work], true);
        let tree = folder("workspace", &[&work, &other], true);
        // In no list: a tree that records another directory first, one
        // that holds no memory, one whose memory folder is empty, one with
        // no transcript, and a folder that Claude Code named after another
        // directory.
        folder("second", &[&other, &work], true);
        folder("emptied", &[&work], false);
        let empty = folder("empty", &[&work], false);
        std::fs::create_dir(empty.join("memory")).unwrap();
        folder("bare", &[], true);
        folder(&claude_folder_name(&root.join("gone")), &[&work], true);

        assert_eq!(recorded_directory(&own), Some(work.clone()));
        assert_eq!(recorded_directory(&tree), Some(work.clone()));
        assert_eq!(
            recorded_directory(&claude.join("projects/second")),
            Some(other.clone())
        );
        assert_eq!(recorded_directory(&claude.join("projects/bare")), None);
        let named_after_another = claude
            .join("projects")
            .join(claude_folder_name(&root.join("gone")));
        assert_eq!(recorded_directory(&named_after_another), None);

        let found = found_for(&claude, &work, &ThisMachine);
        let mut want = vec![(shown(&own), shown(&work)), (shown(&tree), shown(&work))];
        want.sort();
        assert_eq!(found, want);
        // For the other directory: the tree that records it first.
        assert_eq!(
            found_for(&claude, &other, &ThisMachine),
            [(shown(&claude.join("projects/second")), shown(&other))]
        );
        // By real path: a link to the directory is the directory.
        let link = root.join("link");
        std::os::unix::fs::symlink(&work, &link).unwrap();
        assert_eq!(found_for(&claude, &link, &ThisMachine), want);
        // Nothing where there is no such directory of projects.
        assert!(found_for(&root.join("nowhere"), &work, &ThisMachine).is_empty());

        // And the check finds the tree in the way with it, while Claude
        // Code's own folder for the directory is not there.
        std::fs::remove_dir_all(&own).unwrap();
        let would_sync = claude_folder(&claude, &work).unwrap();
        let to_map = ToMap {
            given: &work,
            would_sync: &would_sync,
            claude_dir: &claude,
        };
        let found = found_for(&claude, &work, &ThisMachine);
        let pairs = found
            .iter()
            .map(|(folder, directory)| (folder.as_str(), directory.as_str()));
        let in_the_way = in_the_way(&to_map, pairs, &ThisMachine);
        assert_eq!(
            in_the_way.map(|(folder, _)| folder.to_string()),
            Some(shown(&tree))
        );
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
            in_the_way(&to_map, entries.iter().copied(), machine).map(|(folder, _)| folder)
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
        assert_eq!(
            in_the_way(&above, found.iter().copied(), &there),
            Some((own, "/home/sam/Work/cn"))
        );
        assert!(!above.is_by_hand(own));
        assert!(to_map.is_by_hand(by_hand));

        // A folder that Claude Code named after another directory, and
        // that records this one, is laid out by hand for this one.
        let after_another: &'static str = folder_of("/home/sam/Work/old").leak();
        assert!(to_map.is_by_hand(after_another));
        let recorded = [(after_another, "/home/sam/Work/cn")];
        assert_eq!(stands(&recorded, &there), None);
        assert_eq!(stands(&recorded, &own_gone), Some(after_another));

        // Directories are compared by their real paths, as `map` takes
        // the one it is given. A folder that was found for a link to the
        // directory has the directory: it is in the way while the folder
        // that `map` would sync is not there, and is told by its
        // directory as it was recorded.
        let of_the_link: &'static str = folder_of("/home/sam/link").leak();
        let through = [(of_the_link, "/home/sam/link")];
        let link = |gone: Vec<&'static str>| Said {
            links: vec![("/home/sam/link", "/home/sam/Work/cn")],
            gone,
            ..Default::default()
        };
        assert_eq!(
            in_the_way(&to_map, through.iter().copied(), &link(vec![own])),
            Some((of_the_link, "/home/sam/link"))
        );
        assert_eq!(
            in_the_way(&to_map, through.iter().copied(), &link(vec![])),
            None
        );
        // With no link between them they are two directories.
        assert_eq!(stands(&through, &own_gone), None);
        // And a mapping that is given through the link is checked
        // against what was found for the real directory.
        let given_link = ToMap {
            given: Path::new("/home/sam/link"),
            would_sync: Path::new(of_the_link),
            claude_dir: Path::new(CLAUDE),
        };
        let found_real = [(own, "/home/sam/Work/cn")];
        assert_eq!(
            in_the_way(
                &given_link,
                found_real.iter().copied(),
                &link(vec![of_the_link])
            ),
            Some((own, "/home/sam/Work/cn"))
        );

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
