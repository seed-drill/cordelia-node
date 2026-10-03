//! Finding Claude Code's memory folders and the project each belongs to
//! (decision 2026-09-30-agent-memory-sync §4.5).
//!
//! Claude Code keeps one folder per working directory under
//! `~/.claude/projects/`, named after the path (`-home-sam-Work`,
//! `-Users-...`), so the same project has different folder names on
//! different machines. Session transcripts go in the folder of the
//! directory the session started in. Memory goes in one folder per git
//! repository, shared by its subdirectories and worktrees: the folder of
//! the repository's main working tree ([`memory_root`]). Outside a
//! repository the two are the same folder.
//!
//! A folder found on disk is matched to its project by the working
//! directory recorded in its transcripts, and that directory's git remote.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Lines read from each transcript while looking for the working directory.
const TRANSCRIPT_SCAN_LINES: usize = 200;

/// A Claude Code project folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    /// `~/.claude/projects/<slug>`
    pub dir: PathBuf,
    /// `<dir>/memory`, which may not exist yet.
    pub memory_dir: PathBuf,
}

/// What a folder's memory syncs with.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Project {
    /// The home directory: syncs with the person's personal channel.
    Home,
    /// A git repository, by normalised remote (`github.com/owner/repo`).
    Repo(String),
}

/// Every project folder under `claude_dir/projects`, sorted by path.
pub fn folders(claude_dir: &Path) -> Vec<Folder> {
    let Ok(entries) = std::fs::read_dir(claude_dir.join("projects")) else {
        return Vec::new();
    };
    let mut out: Vec<Folder> = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| Folder {
            memory_dir: e.path().join("memory"),
            dir: e.path(),
        })
        .collect();
    out.sort_by(|a, b| a.dir.cmp(&b.dir));
    out
}

use cordelia_core::claude_code::FOLDER_NAME_MAX as CLAUDE_NAME_MAX;

/// The name Claude Code gives the folder for a directory
/// (`/home/sam/Work` -> `-home-sam-Work`).
pub fn claude_folder_name(dir: &Path) -> String {
    cordelia_core::claude_code::folder_name(&dir.to_string_lossy())
}

/// Claude Code's folder for a directory, under `claude_dir/projects`; it
/// may not exist yet. `None` when the path is too long for its folder name
/// to be predicted.
pub fn claude_folder(claude_dir: &Path, dir: &Path) -> Option<PathBuf> {
    let name = claude_folder_name(dir);
    (name.len() <= CLAUDE_NAME_MAX).then(|| claude_dir.join("projects").join(name))
}

/// Whether `folder` is the one Claude Code names after `dir`, as opposed to
/// a folder someone laid out by hand.
pub fn is_claude_folder_for(folder: &Path, dir: &Path) -> bool {
    let Some(have) = folder.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let want = claude_folder_name(dir);
    if want.len() <= CLAUDE_NAME_MAX {
        return have == want;
    }
    have.strip_prefix(&want[..CLAUDE_NAME_MAX])
        .is_some_and(|hash| hash.starts_with('-'))
}

/// The work tree `cwd` is in and the repository's common directory (which
/// linked worktrees share), as real paths. `None` outside a repository, or
/// without git.
fn git_layout(cwd: &Path) -> Option<(PathBuf, PathBuf)> {
    let output = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--show-toplevel", "--git-common-dir"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = text.lines();
    let (top, common) = (lines.next()?, lines.next()?);
    // The common directory may be given relative to `cwd`.
    Some((PathBuf::from(top), cwd.join(common).canonicalize().ok()?))
}

/// The directory whose folder holds the memory for sessions started in
/// `cwd`. Claude Code keeps one memory per git repository, shared by its
/// subdirectories and worktrees, in the folder of the repository's main
/// working tree. Outside a repository (or without git) it is `cwd` itself.
pub fn memory_root(cwd: &Path) -> PathBuf {
    match git_layout(cwd) {
        // A linked worktree's common directory is the main working tree's
        // `.git`.
        Some((_, common)) if common.file_name().is_some_and(|n| n == ".git") => common
            .parent()
            .map_or_else(|| cwd.to_path_buf(), Path::to_path_buf),
        // Anything else is taken to be its own root: see
        // [`memory_root_is_assumed`].
        Some((top, _)) => top,
        None => cwd.to_path_buf(),
    }
}

/// Whether [`memory_root`] is a guess for `cwd`: it is in a repository
/// whose common directory is not a plain `.git`, which is a submodule or a
/// worktree of a bare repository. Where Claude Code keeps memory for those
/// has not been confirmed.
pub fn memory_root_is_assumed(cwd: &Path) -> bool {
    git_layout(cwd).is_some_and(|(_, common)| common.file_name().is_none_or(|n| n != ".git"))
}

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

/// The working directory recorded first in the folder's newest transcript.
pub fn recorded_cwd(folder: &Path) -> Option<PathBuf> {
    recorded_cwds(folder).into_iter().next()
}

/// The project a working directory belongs to: the home directory itself,
/// or a git repository with a portable remote. `None` for anything else
/// (not a repository, no `origin`, or an origin that is a local path).
pub fn project_for(cwd: &Path, home: &Path) -> Option<Project> {
    if cwd == home {
        return Some(Project::Home);
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    normalize_remote(String::from_utf8_lossy(&output.stdout).trim()).map(Project::Repo)
}

/// Normalise a git remote URL to `host/path`, so every clone of the same
/// repository agrees whatever the transport: lowercased, no scheme, user,
/// credentials, port, trailing `.git` or `/`. Local paths are not portable
/// across machines and give `None`.
///
/// What it gives is a name in its one spelling
/// (`cordelia_core::sync_name::tidy`), so a project's name typed as an
/// exclusion is the name the project is found under.
pub fn normalize_remote(url: &str) -> Option<String> {
    let url = url.trim();
    let (host, path) = if let Some(rest) = url.split_once("://").map(|(_, r)| r) {
        // scheme://[user[:pass]@]host[:port]/path
        let (authority, path) = rest.split_once('/')?;
        let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let host = host.split_once(':').map_or(host, |(h, _)| h);
        (host, path)
    } else if let Some((user_host, path)) = url.split_once(':') {
        // scp-like: [user@]host:path (a Windows drive letter is not a host)
        if user_host.contains('/') || user_host.len() == 1 {
            return None;
        }
        let host = user_host.rsplit_once('@').map_or(user_host, |(_, h)| h);
        (host, path)
    } else {
        return None;
    };

    if url.starts_with("file://") {
        return None;
    }
    let name = cordelia_core::sync_name::tidy(&format!("{host}/{}", path.trim_matches('/')));
    // A name is a host and a path. Tidied, it does not end in `/`, so
    // where there is a `/` there is a path after it.
    match name.split_once('/') {
        Some((host, _)) if !host.is_empty() => Some(name),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_remote() {
        let cases = [
            (
                "https://github.com/seed-drill/cordelia-node.git",
                "github.com/seed-drill/cordelia-node",
            ),
            (
                "https://github.com/Seed-Drill/Cordelia-Node",
                "github.com/seed-drill/cordelia-node",
            ),
            (
                "git@github.com:seed-drill/cordelia-node.git",
                "github.com/seed-drill/cordelia-node",
            ),
            (
                "ssh://git@github.com/seed-drill/cordelia-node.git",
                "github.com/seed-drill/cordelia-node",
            ),
            (
                "ssh://git@git.example.com:2222/team/repo.git/",
                "git.example.com/team/repo",
            ),
            (
                "https://user:secret-token@gitlab.com/group/sub/repo.git",
                "gitlab.com/group/sub/repo",
            ),
            // The ending however it is spelled, and however often.
            (
                "https://github.com/Seed-Drill/Cordelia-Node.GIT",
                "github.com/seed-drill/cordelia-node",
            ),
            (
                "git@github.com:seed-drill/cordelia-node.Git",
                "github.com/seed-drill/cordelia-node",
            ),
            (
                "https://git.example.com/team/repo.git.git",
                "git.example.com/team/repo",
            ),
            (
                "https://git.example.com/team/repo.git/.git/",
                "git.example.com/team/repo",
            ),
            // Not an ending.
            (
                "https://git.example.com/team/repo.github",
                "git.example.com/team/repo.github",
            ),
        ];
        for (url, want) in cases {
            let found = normalize_remote(url);
            assert_eq!(found.as_deref(), Some(want), "{url}");
            // What is found is a name in its one spelling: an exclusion
            // typed for it, which is tidied, is that name.
            assert_eq!(cordelia_core::sync_name::tidy(want), want, "{url}");
        }
        // Nothing is left of the path.
        for no_path in [
            "https://git.example.com/.git",
            "https://git.example.com/.GIT/",
            "git@git.example.com:.git",
            "https://host.git/",
        ] {
            assert_eq!(normalize_remote(no_path), None, "{no_path}");
        }
        for local in [
            "/srv/git/repo.git",
            "../repo",
            "file:///srv/git/repo.git",
            // A `file` URL that names a host is still a path on a machine.
            "file://host/srv/git/repo.git",
            // No host.
            "https:///team/repo.git",
            "C:\\repos\\x",
            "",
        ] {
            assert_eq!(normalize_remote(local), None, "{local}");
        }
    }

    #[test]
    fn test_credentials_never_survive_normalisation() {
        let id = normalize_remote("https://russ:ghp_abc123@github.com/o/r.git").unwrap();
        assert!(!id.contains("ghp_") && !id.contains("russ"), "{id}");
    }

    #[test]
    fn test_recorded_cwd_from_newest_transcript() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("old.jsonl"),
            "{\"type\":\"mode\"}\n{\"cwd\":\"/home/old\",\"type\":\"user\"}\n",
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(
            dir.path().join("new.jsonl"),
            "{\"type\":\"mode\"}\nnot json\n{\"cwd\":\"/home/sam/Work\",\"type\":\"user\"}\n",
        )
        .unwrap();
        assert_eq!(
            recorded_cwd(dir.path()),
            Some(PathBuf::from("/home/sam/Work"))
        );

        let empty = tempfile::tempdir().unwrap();
        assert_eq!(recorded_cwd(empty.path()), None);
    }

    #[test]
    fn test_recorded_cwds_lists_every_directory_once() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("old.jsonl"),
            "{\"cwd\":\"/home/sam\"}\n{\"cwd\":\"/home/sam/Work\"}\n",
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(
            dir.path().join("new.jsonl"),
            "{\"cwd\":\"/home/sam/Work\"}\n{\"cwd\":\"/home/sam/Work\"}\n{\"cwd\":\"/srv/x\"}\n",
        )
        .unwrap();
        assert_eq!(
            recorded_cwds(dir.path()),
            ["/home/sam/Work", "/srv/x", "/home/sam"].map(PathBuf::from)
        );
        assert!(recorded_cwds(&dir.path().join("missing")).is_empty());
    }

    #[test]
    fn test_project_for_home_repo_and_neither() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(project_for(home.path(), home.path()), Some(Project::Home));

        let repo = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            assert!(
                Command::new("git")
                    .arg("-C")
                    .arg(repo.path())
                    .args(args)
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        };
        git(&["init", "-q"]);
        assert_eq!(project_for(repo.path(), home.path()), None, "no origin yet");
        git(&[
            "remote",
            "add",
            "origin",
            "git@github.com:seed-drill/cordelia-node.git",
        ]);
        assert_eq!(
            project_for(repo.path(), home.path()),
            Some(Project::Repo("github.com/seed-drill/cordelia-node".into()))
        );

        let plain = tempfile::tempdir().unwrap();
        assert_eq!(project_for(plain.path(), home.path()), None);
    }

    #[test]
    fn test_claude_folder_for_a_path_too_long_to_predict() {
        let claude = Path::new("/home/x/.claude");
        assert_eq!(
            claude_folder(claude, Path::new("/home/x/Work")),
            Some(PathBuf::from("/home/x/.claude/projects/-home-x-Work"))
        );
        let long = PathBuf::from(format!("/home/x/{}", "a".repeat(200)));
        assert_eq!(claude_folder(claude, &long), None);

        // A long path's folder is recognised by its first 200 characters.
        let cut = &claude_folder_name(&long)[..200];
        let hashed = claude.join("projects").join(format!("{cut}-1x2y3z"));
        assert!(is_claude_folder_for(&hashed, &long));
        assert!(!is_claude_folder_for(
            &claude.join("projects").join(cut),
            &long
        ));
        assert!(is_claude_folder_for(
            Path::new("/home/x/.claude/projects/-home-x-Work"),
            Path::new("/home/x/Work")
        ));
        assert!(!is_claude_folder_for(
            Path::new("/home/x/scope/workspace"),
            Path::new("/home/x/Work")
        ));
    }

    #[test]
    fn test_memory_root_is_the_main_working_tree() {
        let tmp = tempfile::tempdir().unwrap();
        // Compare real paths: the temporary directory may sit behind a link.
        let base = tmp.path().canonicalize().unwrap();
        let git = |dir: &Path, args: &[&str]| {
            let out = Command::new("git")
                .arg("-C")
                .arg(dir)
                .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?}: {out:?}");
        };

        // Not a repository: the directory itself, even if it does not exist.
        let plain = base.join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        assert_eq!(memory_root(&plain), plain);
        assert_eq!(memory_root(&base.join("gone")), base.join("gone"));

        // A repository: its root, from the root and from a subdirectory.
        let repo = base.join("repo");
        std::fs::create_dir_all(repo.join("src/deep")).unwrap();
        git(&repo, &["init", "-q"]);
        assert_eq!(memory_root(&repo), repo);
        assert_eq!(memory_root(&repo.join("src/deep")), repo);

        // A linked worktree shares the main working tree's memory.
        git(&repo, &["commit", "-q", "--allow-empty", "-m", "first"]);
        let worktree = base.join("elsewhere/wt");
        git(
            &repo,
            &["worktree", "add", "-q", &worktree.display().to_string()],
        );
        assert_eq!(memory_root(&worktree), repo);
        for sure in [&plain, &repo, &repo.join("src/deep"), &worktree] {
            assert!(!memory_root_is_assumed(sure), "{}", sure.display());
        }

        // A repository inside the home directory's own repository is its
        // own root; a plain folder there belongs to the home repository.
        let home = base.join("home");
        std::fs::create_dir_all(home.join("notes")).unwrap();
        std::fs::create_dir_all(home.join("code/app")).unwrap();
        git(&home, &["init", "-q"]);
        git(&home.join("code/app"), &["init", "-q"]);
        assert_eq!(memory_root(&home.join("notes")), home);
        assert_eq!(memory_root(&home.join("code/app")), home.join("code/app"));

        // A worktree of a bare repository: taken to be its own root, and
        // flagged, because where Claude Code keeps its memory is not
        // confirmed.
        let bare = base.join("proj.git");
        git(
            &base,
            &[
                "clone",
                "-q",
                "--bare",
                &repo.display().to_string(),
                "proj.git",
            ],
        );
        let bare_wt = base.join("wt-main");
        git(
            &bare,
            &["worktree", "add", "-q", &bare_wt.display().to_string()],
        );
        assert_eq!(memory_root(&bare_wt), bare_wt);
        assert!(memory_root_is_assumed(&bare_wt));
    }

    #[test]
    fn test_folders_lists_project_dirs() {
        let claude = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(claude.path().join("projects/-home-sam/memory")).unwrap();
        std::fs::create_dir_all(claude.path().join("projects/-home-sam-Work")).unwrap();
        std::fs::write(claude.path().join("projects/stray.txt"), "x").unwrap();
        let found = folders(claude.path());
        assert_eq!(found.len(), 2);
        assert!(found[0].memory_dir.ends_with("-home-sam/memory"));
    }
}
