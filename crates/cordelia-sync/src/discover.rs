//! Finding Claude Code's memory folders and the project each belongs to
//! (decision 2026-09-30-agent-memory-sync §4.5).
//!
//! Claude Code keeps one folder per working directory under
//! `~/.claude/projects/`, named after the path (`-home-rezi-Work`,
//! `-Users-...`), so the same project has different folder names on
//! different machines. A folder is matched to its project instead by the
//! working directory recorded in its session transcripts, and that
//! directory's git remote.

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

/// The working directory recorded in the folder's most recent transcript.
pub fn recorded_cwd(folder: &Path) -> Option<PathBuf> {
    let mut transcripts: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(folder)
        .ok()?
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "jsonl"))
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    transcripts.sort_by_key(|t| std::cmp::Reverse(t.0));

    for (_, path) in transcripts {
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
            {
                return Some(PathBuf::from(cwd));
            }
        }
    }
    None
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

    let path = path.trim_matches('/');
    let path = path
        .strip_suffix(".git")
        .unwrap_or(path)
        .trim_end_matches('/');
    if host.is_empty() || path.is_empty() || url.starts_with("file://") {
        return None;
    }
    Some(format!("{host}/{path}").to_lowercase())
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
        ];
        for (url, want) in cases {
            assert_eq!(normalize_remote(url).as_deref(), Some(want), "{url}");
        }
        for local in [
            "/srv/git/repo.git",
            "../repo",
            "file:///srv/git/repo.git",
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
            "{\"type\":\"mode\"}\nnot json\n{\"cwd\":\"/home/rezi/Work\",\"type\":\"user\"}\n",
        )
        .unwrap();
        assert_eq!(
            recorded_cwd(dir.path()),
            Some(PathBuf::from("/home/rezi/Work"))
        );

        let empty = tempfile::tempdir().unwrap();
        assert_eq!(recorded_cwd(empty.path()), None);
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
    fn test_folders_lists_project_dirs() {
        let claude = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(claude.path().join("projects/-home-rezi/memory")).unwrap();
        std::fs::create_dir_all(claude.path().join("projects/-home-rezi-Work")).unwrap();
        std::fs::write(claude.path().join("projects/stray.txt"), "x").unwrap();
        let found = folders(claude.path());
        assert_eq!(found.len(), 2);
        assert!(found[0].memory_dir.ends_with("-home-rezi/memory"));
    }
}
