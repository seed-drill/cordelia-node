//! A repository's list, read with git (decision 2026-11-06 (joining),
//! rules 2 and 3), against a server of git over HTTPS on loopback
//! (`common`): the node's own fetch of a public repository's list; a read
//! of a clone, at its remote's default branch and nothing else; never
//! back; a partial clone; and nothing of the person's that reaches git,
//! so that nothing asks, at a terminal too.

#![cfg(unix)]

mod common;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::{
    Answers, GitServer, commit_list, commit_work, git, marker, marks_in, snapshot, test_git,
};
use cordelia_api::git_list::{
    ClonedList, Git, GitVersion, Identity, ListAt, ListFailed, NotAnIdentity, RemoteRefused,
};
use cordelia_core::protocol::{
    MEMBERS_FETCH_MAX_SECS, MEMBERS_FILE_MAX_BYTES, MEMBERS_GIT_TERM_SECS, MEMBERS_REPO_MAX_BYTES,
};

const LIST: &[u8] = b"# the list\ncordelia_pk1example alice-laptop\n";

fn identity() -> Identity {
    Identity::from_address("https://example.org/example/project").unwrap()
}

/// A server, the repository it serves, a work tree that pushes to it, and
/// a folder for the node and for clones.
struct Bench {
    tmp: tempfile::TempDir,
    server: GitServer,
    bare: PathBuf,
}

impl Bench {
    fn new(answers: Answers) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("home")).unwrap();
        let server = GitServer::start(answers);
        let bare = server.bare("example", "project");
        Self { tmp, server, bare }
    }

    /// The test's own git's HOME.
    fn home(&self) -> PathBuf {
        self.tmp.path().join("home")
    }

    /// Commit the list (or none) and push it to the served repository.
    fn commit(&self, list: Option<&[u8]>) -> String {
        commit_list(
            &self.home(),
            &self.tmp.path().join("work"),
            &self.bare,
            list,
        )
    }

    /// The environment the node inherits: git on its `PATH`, and the
    /// server's certificate authority.
    fn inherited(&self) -> Vec<(OsString, OsString)> {
        vec![
            ("PATH".into(), std::env::var_os("PATH").unwrap_or_default()),
            ("GIT_SSL_CAINFO".into(), self.server.ca_file().into()),
        ]
    }

    /// The node's git, under a data directory of its own.
    fn node(&self, name: &str) -> Git {
        Git::given(&self.tmp.path().join(name), "git", self.inherited()).unwrap()
    }

    fn url(&self) -> String {
        self.server.url("example", "project")
    }

    /// A clone of the served repository, whose `origin` names it at its
    /// public address, as a person's clone does.
    fn clone_of(&self, name: &str) -> PathBuf {
        let clone = self.tmp.path().join(name);
        git(
            &self.home(),
            self.tmp.path(),
            &["clone", "--quiet", self.bare.to_str().unwrap(), name],
        );
        git(
            &self.home(),
            &clone,
            &[
                "remote",
                "set-url",
                "origin",
                "https://example.org/example/project.git",
            ],
        );
        clone
    }

    /// The person's own `git fetch origin` into a clone.
    fn fetch_into(&self, clone: &Path) {
        self.fetch_into_with(clone, false);
    }

    /// The person's own `git fetch origin` into a clone, with `--prune`
    /// where `prune`: from the served repository on the disk in place of
    /// the public address, which `FETCH_HEAD` then names, as a fetch from
    /// it would.
    fn fetch_into_with(&self, clone: &Path, prune: bool) {
        let home = self.home();
        let public = git(&home, clone, &["config", "remote.origin.url"]);
        let instead = format!("url.{}.insteadOf={public}", self.bare.display());
        let mut args = vec!["-c", &instead, "fetch", "--quiet"];
        if prune {
            args.push("--prune");
        }
        args.push("origin");
        git(&home, clone, &args);
        // Git writes the address it fetched from without `.git`.
        let on_disk = self.bare.to_str().unwrap().strip_suffix(".git").unwrap();
        let fetch_head = clone.join(".git/FETCH_HEAD");
        let said = std::fs::read_to_string(&fetch_head).unwrap();
        let said = said.replace(
            &format!(" of {on_disk}\n"),
            " of https://example.org/example/project\n",
        );
        std::fs::write(&fetch_head, said).unwrap();
    }
}

// ── The fetch ────────────────────────────────────────────────────────

/// The node fetches `HEAD` at a depth of one, with no tags, into
/// `refs/cordelia/list` of a bare repository of its own that names its
/// remote, and reads the one file there; a new commit brings the new
/// list, and a commit with no list gives none (rule 3).
#[test]
fn a_fetch_reads_the_list_into_the_nodes_own_repository() {
    let bench = Bench::new(Answers::Git);
    // A file elsewhere in the repository, larger than the list may be.
    let work = bench.tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("big.bin"), vec![b'x'; 100_000]).unwrap();
    let first = bench.commit(Some(LIST));
    git(&bench.home(), &bench.bare, &["tag", "v1", "main"]);
    let node = bench.node("node");
    assert!(
        node.version()
            .is_some_and(|v| v >= GitVersion { major: 2, minor: 0 })
    );
    let read = node.fetch_list(&identity(), &bench.url()).unwrap();
    assert_eq!(
        read,
        ListAt {
            commit: first.clone(),
            file: Some(LIST.to_vec()),
        }
    );
    let repo = node.repo_of(&identity());
    assert!(repo.ends_with("repos/example.org/example/project.git"));
    let ask = |args: &[&str]| git(&bench.home(), &repo, args);
    assert_eq!(ask(&["rev-parse", "--is-bare-repository"]), "true");
    assert_eq!(ask(&["rev-parse", "--is-shallow-repository"]), "true");
    assert_eq!(ask(&["rev-parse", "refs/cordelia/list"]), first);
    assert_eq!(ask(&["config", "remote.origin.url"]), bench.url());
    assert_eq!(ask(&["for-each-ref", "refs/tags"]), "");
    // A partial clone of its own, whose fetch leaves out every file larger
    // than the list may be: the large file is not there, and the list is.
    assert_eq!(ask(&["config", "remote.origin.promisor"]), "true");
    assert_eq!(ask(&["config", "extensions.partialClone"]), "origin");
    let big = git(&bench.home(), &bench.bare, &["rev-parse", "main:big.bin"]);
    let list = git(
        &bench.home(),
        &bench.bare,
        &["rev-parse", "main:.cordelia/members"],
    );
    assert!(
        !holds(&bench.home(), &repo, &big),
        "the large file was fetched"
    );
    assert!(holds(&bench.home(), &repo, &list));
    // The node asked in git's protocol 2, which the server was given.
    assert!(
        bench
            .server
            .seen()
            .iter()
            .any(|seen| seen.header("git-protocol") == Some("version=2"))
    );
    // A new commit.
    let second = bench.commit(Some(b"# the list, changed\n"));
    let read = node.fetch_list(&identity(), &bench.url()).unwrap();
    assert_eq!(read.commit, second);
    assert_eq!(read.file.as_deref(), Some(&b"# the list, changed\n"[..]));
    assert_eq!(ask(&["rev-list", "--count", "refs/cordelia/list"]), "1");
    // A commit with no list.
    let third = bench.commit(None);
    assert_eq!(
        node.fetch_list(&identity(), &bench.url()).unwrap(),
        ListAt {
            commit: third,
            file: None,
        }
    );
    // A host that has no such repository, and one with no commit.
    let missing = bench.server.url("example", "missing");
    assert_eq!(
        node.fetch_list(&identity(), &missing),
        Err(ListFailed::NotFound)
    );
    bench.server.bare("example", "empty");
    let empty = Identity::from_address("https://example.org/example/empty").unwrap();
    assert_eq!(
        node.fetch_list(&empty, &bench.server.url("example", "empty")),
        Err(ListFailed::NoCommits)
    );
}

/// The list must be a plain file of at most 16 KiB (rule 1): of that
/// size it is read, a byte more is too large, and a folder or a link in
/// its place is not a list.
#[test]
fn the_list_is_a_plain_file_of_at_most_16_kib() {
    let bench = Bench::new(Answers::Git);
    let node = bench.node("node");
    let fetched = || node.fetch_list(&identity(), &bench.url());
    let largest = vec![b'#'; MEMBERS_FILE_MAX_BYTES];
    bench.commit(Some(&largest));
    assert_eq!(fetched().unwrap().file, Some(largest.clone()));
    let mut larger = largest;
    larger.push(b'\n');
    bench.commit(Some(&larger));
    assert_eq!(fetched(), Err(ListFailed::TooLarge));
    // The fetch left it out.
    let blob = git(
        &bench.home(),
        &bench.bare,
        &["rev-parse", "main:.cordelia/members"],
    );
    assert!(!holds(&bench.home(), &node.repo_of(&identity()), &blob));
    // A folder in its place.
    let work = bench.tmp.path().join("work");
    std::fs::remove_file(work.join(".cordelia/members")).unwrap();
    std::fs::create_dir_all(work.join(".cordelia/members")).unwrap();
    std::fs::write(work.join(".cordelia/members/list"), LIST).unwrap();
    commit_work(&bench.home(), &work, &bench.bare);
    assert_eq!(fetched(), Err(ListFailed::NotAFile));
    // A link in its place.
    std::fs::remove_dir_all(work.join(".cordelia/members")).unwrap();
    std::os::unix::fs::symlink("../README", work.join(".cordelia/members")).unwrap();
    commit_work(&bench.home(), &work, &bench.bare);
    assert_eq!(fetched(), Err(ListFailed::NotAFile));
}

/// Whether the repository `repo` holds the object `object`, asked so that
/// nothing is fetched for the asking.
fn holds(home: &Path, repo: &Path, object: &str) -> bool {
    test_git(home, repo, &["cat-file", "-e", object])
        .env("GIT_NO_LAZY_FETCH", "1")
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
        .success()
}

/// The node's own repository is made afresh before a fetch where it holds
/// more than its bound, `MEMBERS_REPO_MAX_BYTES`, and the list is fetched
/// again; within its bound it is kept (rule 3).
#[test]
fn the_nodes_repository_is_made_afresh_past_its_bound() {
    assert_eq!(MEMBERS_REPO_MAX_BYTES, 64 * 1024 * 1024);
    let bench = Bench::new(Answers::Git);
    bench.commit(Some(LIST));
    let node = bench.node("node");
    node.fetch_list(&identity(), &bench.url()).unwrap();
    let repo = node.repo_of(&identity());
    std::fs::write(repo.join("planted"), "a file of the node's repository").unwrap();
    let second = bench.commit(Some(b"# the list, changed\n"));
    assert_eq!(
        node.fetch_list(&identity(), &bench.url()).unwrap().commit,
        second
    );
    assert!(
        repo.join("planted").exists(),
        "made afresh within its bound"
    );
    // A bound it is past.
    let small = Git::given(&bench.tmp.path().join("node"), "git", bench.inherited())
        .unwrap()
        .with_repo_max_bytes(1);
    let third = bench.commit(Some(LIST));
    assert_eq!(
        small.fetch_list(&identity(), &bench.url()).unwrap(),
        ListAt {
            commit: third.clone(),
            file: Some(LIST.to_vec()),
        }
    );
    assert!(!repo.join("planted").exists(), "not made afresh");
    assert_eq!(
        git(&bench.home(), &repo, &["rev-parse", "refs/cordelia/list"]),
        third
    );
}

/// A redirect, as for a repository renamed or moved, is not followed:
/// the host is asked once, and the fetch says that the repository has
/// moved (rule 3).
#[test]
fn a_redirect_is_not_followed_and_says_the_repository_moved() {
    let bench = Bench::new(Answers::Redirect);
    let node = bench.node("node");
    let failed = node.fetch_list(&identity(), &bench.url()).unwrap_err();
    assert_eq!(failed, ListFailed::Moved);
    assert!(failed.says().contains("has moved"), "{}", failed.says());
    let seen = bench.server.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(
        seen[0].target.starts_with("/example/project.git/info/refs"),
        "{seen:?}"
    );
}

/// A fetch from a host that never answers is stopped at its deadline, by
/// TERM and then KILL, and the node's own repository's locks are cleared;
/// while it runs, a second fetch of the repository waits for the next
/// read; and a lock that a stopped fetch left does not hold up the next
/// (rule 3).
#[test]
fn a_fetch_that_does_not_end_is_stopped_and_its_locks_cleared() {
    assert_eq!(MEMBERS_FETCH_MAX_SECS, 60);
    let bench = Bench::new(Answers::Never);
    let node = bench.node("node");
    let repo = node.repo_of(&identity());
    let began = Instant::now();
    let (fetched, second) = std::thread::scope(|scope| {
        let fetching = scope.spawn(|| {
            node.fetch_list_by(&identity(), &bench.url(), began + Duration::from_secs(3))
        });
        // While git waits on the host, it holds locks of the node's
        // repository, as a fetch that has begun to write does.
        while bench.server.seen().is_empty() && began.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !bench.server.seen().is_empty() && !fetching.is_finished(),
            "git did not reach the host before its deadline"
        );
        std::fs::create_dir_all(repo.join("refs/cordelia")).unwrap();
        std::fs::write(repo.join("shallow.lock"), "").unwrap();
        std::fs::write(repo.join("refs/cordelia/list.lock"), "").unwrap();
        let second = node.fetch_list(&identity(), &bench.url());
        (fetching.join().unwrap(), second)
    });
    let took = began.elapsed();
    assert_eq!(second, Err(ListFailed::Busy));
    assert_eq!(fetched, Err(ListFailed::Late { secs: 3 }));
    assert!(took >= Duration::from_secs(3), "{took:?}");
    assert!(
        took < Duration::from_secs(3 + MEMBERS_GIT_TERM_SECS + 10),
        "{took:?}"
    );
    assert!(!repo.join("shallow.lock").exists());
    assert!(!repo.join("refs/cordelia/list.lock").exists());
    assert!(repo.join("HEAD").exists());

    // A stopped fetch's locks, left by a node that was stopped too, do not
    // hold up a fetch that the host answers.
    let bench = Bench::new(Answers::Git);
    let first = bench.commit(Some(LIST));
    let node = bench.node("node");
    node.fetch_list(&identity(), &bench.url()).unwrap();
    let repo = node.repo_of(&identity());
    for lock in ["shallow.lock", "config.lock", "refs/cordelia/list.lock"] {
        std::fs::write(repo.join(lock), "").unwrap();
    }
    let second = bench.commit(Some(LIST));
    assert_ne!(first, second);
    assert_eq!(
        node.fetch_list(&identity(), &bench.url()).unwrap().commit,
        second
    );
}

// ── A clone ──────────────────────────────────────────────────────────

/// A clone is read at `refs/remotes/<remote>/<branch>`, the branch that
/// `refs/remotes/<remote>/HEAD` names: never the working tree, a local
/// branch or `HEAD`; and nothing of the clone changes (rule 3).
#[test]
fn a_clone_is_read_at_its_remotes_default_branch_and_left_as_it_was() {
    let bench = Bench::new(Answers::Git);
    let first = bench.commit(Some(LIST));
    let clone = bench.clone_of("clone");
    let home = bench.home();
    // A list on a local branch, checked out, and another in the working
    // tree, not committed.
    std::fs::write(clone.join(".cordelia/members"), b"# on a local branch\n").unwrap();
    git(&home, &clone, &["commit", "--quiet", "-am", "local"]);
    std::fs::write(clone.join(".cordelia/members"), b"# in the working tree\n").unwrap();
    let node = bench.node("node");
    assert_eq!(
        node.identity_of_clone(&clone, None),
        Ok(("origin".to_string(), identity()))
    );
    let before = snapshot(&clone);
    let read = node.read_clone(&clone, "origin", &identity()).unwrap();
    assert_eq!(
        read,
        ClonedList {
            at: ListAt {
                commit: first.clone(),
                file: Some(LIST.to_vec()),
            },
            branch: "main".to_string(),
            fetched: None,
        }
    );
    assert_eq!(snapshot(&clone), before, "a read changed the clone");
    // The person fetches: the new list, and when it was fetched.
    let second = bench.commit(Some(b"# the list, changed\n"));
    bench.fetch_into(&clone);
    let read = node.read_clone(&clone, "origin", &identity()).unwrap();
    assert_eq!(read.at.commit, second);
    assert_eq!(read.at.file.as_deref(), Some(&b"# the list, changed\n"[..]));
    let fetched = read.fetched.expect("FETCH_HEAD says when");
    assert!(fetched.elapsed().unwrap_or_default() < Duration::from_secs(600));
    assert_eq!(node.comes_after(&clone, &first, &second), Ok(true));
    // A default branch renamed at the host: the clone no longer says
    // which branch is the default.
    git(&home, &clone, &["remote", "set-head", "origin", "--delete"]);
    let failed = node.read_clone(&clone, "origin", &identity()).unwrap_err();
    assert_eq!(
        failed,
        ListFailed::NoRemoteHead {
            remote: "origin".to_string()
        }
    );
    assert!(failed.says().contains("git remote set-head origin --auto"));
    git(
        &home,
        &clone,
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/trunk",
        ],
    );
    assert_eq!(
        node.read_clone(&clone, "origin", &identity()),
        Err(ListFailed::NoBranch {
            remote: "origin".to_string(),
            branch: "trunk".to_string()
        })
    );
    // A folder that is not in a repository.
    let elsewhere = bench.tmp.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    assert_eq!(
        node.read_clone(&elsewhere, "origin", &identity()),
        Err(ListFailed::NotARepository)
    );
}

/// A clone whose remote now names another repository, as a fork, is not
/// read; several remotes that name different repositories need one
/// chosen; and an SSH alias is refused with why (rule 2.1).
#[test]
fn a_clone_whose_remote_names_another_repository_is_not_read() {
    let bench = Bench::new(Answers::Git);
    bench.commit(Some(LIST));
    let clone = bench.clone_of("clone");
    let home = bench.home();
    let node = bench.node("node");
    let set_url = |remote: &str, url: &str| git(&home, &clone, &["remote", "set-url", remote, url]);
    set_url("origin", "git@example.org:alice/project.git");
    assert_eq!(
        node.read_clone(&clone, "origin", &identity()),
        Err(ListFailed::RemoteMoved {
            remote: "origin".to_string()
        })
    );
    let fork = Identity::from_address("https://example.org/alice/project").unwrap();
    assert_eq!(
        node.identity_of_clone(&clone, None),
        Ok(("origin".to_string(), fork.clone()))
    );
    // A fork's origin and the repository's upstream.
    git(
        &home,
        &clone,
        &[
            "remote",
            "add",
            "upstream",
            "https://example.org/example/project",
        ],
    );
    assert_eq!(
        node.identity_of_clone(&clone, None),
        Err(RemoteRefused::Several(vec![
            ("origin".to_string(), fork),
            ("upstream".to_string(), identity())
        ]))
    );
    assert_eq!(
        node.identity_of_clone(&clone, Some("upstream")),
        Ok(("upstream".to_string(), identity()))
    );
    // Upstream has never been fetched: no default branch is known of it.
    assert_eq!(
        node.read_clone(&clone, "upstream", &identity()),
        Err(ListFailed::NoRemoteHead {
            remote: "upstream".to_string()
        })
    );
    // An alias that only SSH's settings know.
    set_url("origin", "git@github.com-work:example/project.git");
    assert_eq!(
        node.identity_of_clone(&clone, Some("origin")),
        Err(RemoteRefused::NotARepository(
            "origin".to_string(),
            NotAnIdentity::Alias("github.com-work".to_string())
        ))
    );
    assert_eq!(
        node.read_clone(&clone, "origin", &identity()),
        Err(ListFailed::RemoteMoved {
            remote: "origin".to_string()
        })
    );
    assert_eq!(
        node.read_clone(&clone, "nowhere", &identity()),
        Err(ListFailed::NoSuchRemote("nowhere".to_string()))
    );
    // Its origin set back: read.
    set_url("origin", "ssh://git@example.org/example/project");
    assert!(node.read_clone(&clone, "origin", &identity()).is_ok());
}

/// A read of a clone never goes back (rule 3): a commit counts only where
/// it is the last commit read or comes after it, and a clone that is
/// behind, or whose history was written again, gives no new list.
#[test]
fn a_read_of_a_clone_never_goes_back() {
    let bench = Bench::new(Answers::Git);
    let first = bench.commit(Some(LIST));
    let second = bench.commit(Some(LIST));
    let third = bench.commit(Some(LIST));
    let clone = bench.clone_of("clone");
    let node = bench.node("node");
    let after = |last: &str, commit: &str| node.comes_after(&clone, last, commit);
    assert_eq!(after(&third, &third), Ok(true));
    assert_eq!(after(&first, &third), Ok(true));
    assert_eq!(after(&second, &third), Ok(true));
    assert_eq!(after(&third, &first), Ok(false));
    assert_eq!(after(&third, &second), Ok(false));
    // History written again: the new tip does not come after the last
    // commit read.
    let work = bench.tmp.path().join("work");
    git(
        &bench.home(),
        &work,
        &["reset", "--quiet", "--hard", &first],
    );
    let rewritten = bench.commit(Some(LIST));
    bench.fetch_into(&clone);
    assert_eq!(
        node.read_clone(&clone, "origin", &identity())
            .unwrap()
            .at
            .commit,
        rewritten
    );
    assert_eq!(after(&third, &rewritten), Ok(false));
    assert_eq!(after(&first, &rewritten), Ok(true));
    // A last commit that the clone does not hold: it is behind.
    let other = Bench::new(Answers::Git);
    let elsewhere = other.commit(Some(LIST));
    assert_eq!(after(&elsewhere, &third), Ok(false));
    assert!(after("main", &third).is_err());
    assert!(after(&third, "--all").is_err());
}

/// A replace ref or a graft in a clone is not heeded (rule 3): a replace
/// ref that makes the remote branch's commit read as a local commit with
/// another list leaves the list read the remote's; and a graft, in
/// `info/grafts` or made with `git replace --graft`, that makes a commit of
/// a history written again seem to come after the last commit read does
/// not make it count.
#[test]
fn a_replace_ref_or_a_graft_in_the_clone_is_not_heeded() {
    let bench = Bench::new(Answers::Git);
    let first = bench.commit(Some(LIST));
    let clone = bench.clone_of("clone");
    let home = bench.home();
    let node = bench.node("node");
    // A local commit with another list, put in place of the remote's.
    std::fs::write(clone.join(".cordelia/members"), b"# replaced\n").unwrap();
    git(&home, &clone, &["commit", "--quiet", "-am", "local"]);
    let local = git(&home, &clone, &["rev-parse", "HEAD"]);
    git(&home, &clone, &["replace", &first, &local]);
    let shown = format!("{first}:.cordelia/members");
    assert_eq!(git(&home, &clone, &["show", &shown]), "# replaced");
    let read = node.read_clone(&clone, "origin", &identity()).unwrap();
    assert_eq!(
        read.at,
        ListAt {
            commit: first.clone(),
            file: Some(LIST.to_vec()),
        }
    );
    // History written again at the host: a commit with no parent.
    let work = bench.tmp.path().join("work");
    git(&home, &work, &["checkout", "--quiet", "--orphan", "again"]);
    std::fs::write(work.join("README"), "written again\n").unwrap();
    git(&home, &work, &["add", "-A"]);
    git(&home, &work, &["commit", "--quiet", "-m", "again"]);
    let bare = bench.bare.to_str().unwrap();
    git(
        &home,
        &work,
        &["push", "--quiet", "--force", bare, "again:main"],
    );
    let rewritten = git(&home, &work, &["rev-parse", "HEAD"]);
    bench.fetch_into(&clone);
    let read = node.read_clone(&clone, "origin", &identity()).unwrap();
    assert_eq!(read.at.commit, rewritten);
    assert_eq!(node.comes_after(&clone, &first, &rewritten), Ok(false));
    // The person's git sees each graft; the node's does not.
    let ancestor = || {
        test_git(
            &home,
            &clone,
            &["merge-base", "--is-ancestor", &first, &rewritten],
        )
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
        .success()
    };
    std::fs::create_dir_all(clone.join(".git/info")).unwrap();
    std::fs::write(
        clone.join(".git/info/grafts"),
        format!("{rewritten} {first}\n"),
    )
    .unwrap();
    assert!(ancestor(), "the graft file is not heeded by this git");
    assert_eq!(node.comes_after(&clone, &first, &rewritten), Ok(false));
    std::fs::remove_file(clone.join(".git/info/grafts")).unwrap();
    git(&home, &clone, &["replace", "--graft", &rewritten, &first]);
    assert!(ancestor());
    assert_eq!(node.comes_after(&clone, &first, &rewritten), Ok(false));
}

/// A host that renames its default branch (rule 3): after the person's
/// plain `git fetch`, `refs/remotes/origin/HEAD` still names the old
/// branch at its old commit, and `FETCH_HEAD` is new, but names only the
/// new branch: the list is read at the old commit, and not known to be
/// fresh. After `git fetch --prune` the old branch is gone, and the person
/// is told what to run.
#[test]
fn a_default_branch_renamed_at_the_host_is_not_known_to_be_fresh() {
    let bench = Bench::new(Answers::Git);
    let first = bench.commit(Some(LIST));
    let home = bench.home();
    let at_host = |args: &[&str]| git(&home, &bench.bare, args);
    at_host(&["branch", "-m", "main", "master"]);
    at_host(&["symbolic-ref", "HEAD", "refs/heads/master"]);
    let clone = bench.clone_of("clone");
    let node = bench.node("node");
    bench.fetch_into(&clone);
    let read = node.read_clone(&clone, "origin", &identity()).unwrap();
    assert_eq!(read.at.commit, first);
    assert_eq!(read.branch, "master");
    assert!(read.fetched.is_some());
    // A FETCH_HEAD of another repository says nothing of this one.
    let fetch_head = clone.join(".git/FETCH_HEAD");
    let said = std::fs::read_to_string(&fetch_head).unwrap();
    std::fs::write(
        &fetch_head,
        said.replace("/example/project", "/alice/project"),
    )
    .unwrap();
    let read = node.read_clone(&clone, "origin", &identity()).unwrap();
    assert_eq!(read.fetched, None);
    // The host renames master to main, and a commit follows.
    at_host(&["branch", "-m", "master", "main"]);
    at_host(&["symbolic-ref", "HEAD", "refs/heads/main"]);
    let second = bench.commit(Some(b"# the list, changed\n"));
    bench.fetch_into(&clone);
    let read = node.read_clone(&clone, "origin", &identity()).unwrap();
    assert_eq!(read.at.commit, first);
    assert_eq!(read.branch, "master");
    assert_eq!(read.fetched, None);
    // With --prune, the old branch goes.
    bench.fetch_into_with(&clone, true);
    let failed = node.read_clone(&clone, "origin", &identity()).unwrap_err();
    assert_eq!(
        failed,
        ListFailed::NoBranch {
            remote: "origin".to_string(),
            branch: "master".to_string()
        }
    );
    assert_eq!(
        failed.says(),
        "your clone has no copy of origin/master: run git fetch origin, \
         then git remote set-head origin --auto"
    );
    // What set-head writes, as the host answers it: read, and fresh.
    git(
        &home,
        &clone,
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/main",
        ],
    );
    let read = node.read_clone(&clone, "origin", &identity()).unwrap();
    assert_eq!(read.at.commit, second);
    assert_eq!(read.branch, "main");
    assert!(read.fetched.is_some());
}

/// A clone's remote branch is looked up by its whole name, and nothing
/// else that git could take the name for (rule 3): a tag or a local branch
/// of the same name, or a symbolic ref in its place, is not read.
#[test]
fn a_clones_remote_branch_is_looked_up_by_its_whole_name() {
    let bench = Bench::new(Answers::Git);
    let first = bench.commit(Some(LIST));
    let clone = bench.clone_of("clone");
    let home = bench.home();
    let node = bench.node("node");
    std::fs::write(clone.join(".cordelia/members"), b"# a local branch\n").unwrap();
    git(&home, &clone, &["commit", "--quiet", "-am", "local"]);
    // The default branch named as a branch that the clone has no copy of,
    // where a local branch of that name is there, and a tag whose name is
    // the remote branch's whole name, which `rev-parse` would take for it.
    git(&home, &clone, &["branch", "trunk"]);
    git(&home, &clone, &["tag", "refs/remotes/origin/trunk"]);
    git(
        &home,
        &clone,
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/trunk",
        ],
    );
    assert_eq!(
        node.read_clone(&clone, "origin", &identity()),
        Err(ListFailed::NoBranch {
            remote: "origin".to_string(),
            branch: "trunk".to_string()
        })
    );
    // A symbolic ref in the branch's place, to the local branch: git
    // follows it from `refs/remotes/origin/HEAD`, out of the remote's refs,
    // so no default branch of the remote is known.
    git(
        &home,
        &clone,
        &[
            "symbolic-ref",
            "refs/remotes/origin/trunk",
            "refs/heads/trunk",
        ],
    );
    assert_eq!(
        node.read_clone(&clone, "origin", &identity()),
        Err(ListFailed::NoRemoteHead {
            remote: "origin".to_string()
        })
    );
    git(
        &home,
        &clone,
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/main",
        ],
    );
    assert_eq!(
        node.read_clone(&clone, "origin", &identity())
            .unwrap()
            .at
            .commit,
        first
    );
}

/// A partial clone is read without a fetch, by a git that heeds
/// `GIT_NO_LAZY_FETCH`: where it lacks the list, it says so, and nothing
/// is fetched; once it holds it, it is read. A git older than 2.44 does
/// not heed it, and is refused a partial clone, and not a whole one
/// (rule 3).
#[test]
fn a_partial_clone_is_read_without_a_fetch_and_refused_to_an_older_git() {
    let bench = Bench::new(Answers::Git);
    let first = bench.commit(Some(LIST));
    let home = bench.home();
    let partial = bench.tmp.path().join("partial");
    let from = format!("file://{}", bench.bare.display());
    git(
        &home,
        bench.tmp.path(),
        &[
            "clone",
            "--quiet",
            "--filter=blob:none",
            "--no-checkout",
            &from,
            "partial",
        ],
    );
    // Its origin is the repository's public address, and its promisor is
    // the test's server: a lazy fetch would be seen there.
    let config = |args: &[&str]| git(&home, &partial, args);
    config(&[
        "remote",
        "set-url",
        "origin",
        "https://example.org/example/project.git",
    ]);
    config(&["config", "remote.origin.promisor", "false"]);
    config(&["remote", "add", "lazy", &bench.url()]);
    config(&["config", "remote.lazy.promisor", "true"]);
    config(&["config", "remote.lazy.partialclonefilter", "blob:none"]);
    let node = bench.node("node");
    let new_enough = node.version().is_some_and(|v| {
        v >= GitVersion {
            major: 2,
            minor: 44,
        }
    });
    if new_enough {
        let before = snapshot(&partial);
        assert_eq!(
            node.read_clone(&partial, "origin", &identity()),
            Err(ListFailed::NotInClone {
                remote: "origin".to_string(),
                branch: "main".to_string()
            })
        );
        assert_eq!(snapshot(&partial), before, "a read fetched into the clone");
        assert!(bench.server.seen().is_empty(), "{:?}", bench.server.seen());
        // The person's git brings the file: it is read.
        let blob = git(&home, &bench.bare, &["rev-parse", "main:.cordelia/members"]);
        let mut write = test_git(&home, &partial, &["hash-object", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(&mut write.stdin.take().unwrap(), LIST).unwrap();
        let written = write.wait_with_output().unwrap();
        assert_eq!(String::from_utf8_lossy(&written.stdout).trim(), blob);
        let read = node.read_clone(&partial, "origin", &identity()).unwrap();
        assert_eq!(read.at.commit, first);
        assert_eq!(read.at.file.as_deref(), Some(LIST));
    } else {
        eprintln!("this git is older than 2.44: only the refusal is tested");
    }
    // A git that says it is 2.43, and is this one otherwise.
    let real = which_git();
    let older = marker(
        &bench.tmp.path().join("older"),
        "git",
        &bench.tmp.path().join("older-marks"),
        &format!(
            "for a; do last=$a; done\n\
             if [ \"$last\" = version ]; then echo 'git version 2.43.0'; exit 0; fi\n\
             exec '{}' \"$@\"",
            real.display()
        ),
    );
    let old = Git::given(
        &bench.tmp.path().join("old-node"),
        &older,
        bench.inherited(),
    )
    .unwrap();
    assert_eq!(
        old.version(),
        Some(GitVersion {
            major: 2,
            minor: 43
        })
    );
    let refused = old.read_clone(&partial, "origin", &identity()).unwrap_err();
    assert_eq!(
        refused,
        ListFailed::PartialOnOldGit {
            version: Some(GitVersion {
                major: 2,
                minor: 43
            })
        }
    );
    assert!(refused.says().contains("older than 2.44"));
    // Never back reads the clone's objects too, and is refused alike.
    assert_eq!(
        old.comes_after(&partial, &first, &"0".repeat(40)),
        Err(refused.clone())
    );
    let whole = bench.clone_of("whole");
    assert_eq!(
        old.read_clone(&whole, "origin", &identity())
            .unwrap()
            .at
            .commit,
        first
    );
    assert!(bench.server.seen().is_empty(), "{:?}", bench.server.seen());
}

/// The real git on the `PATH`.
fn which_git() -> PathBuf {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|dir| dir.join("git"))
        .find(|git| git.is_file())
        .expect("git on the PATH")
}

// ── Nothing asks ─────────────────────────────────────────────────────

/// A person whose git settings and environment would each ask, or hand
/// over something of theirs: each a program that writes a mark.
struct Person {
    root: PathBuf,
    env: Vec<(OsString, OsString)>,
}

impl Person {
    fn of(bench: &Bench) -> Self {
        let root = bench.tmp.path().join("person");
        let (bin, marks) = (root.join("bin"), root.join("marks"));
        std::fs::create_dir_all(&marks).unwrap();
        let mark = |name: &str, then: &str| marker(&bin, name, &marks, then).display().to_string();
        let home = root.join("home");
        let xdg = root.join("xdg");
        std::fs::create_dir_all(xdg.join("git")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join(".gitconfig"),
            format!(
                "[credential]\n\thelper = {}\n[core]\n\taskPass = {}\n\tsshCommand = {}\n\
                 [http]\n\textraHeader = X-Person: home\n\tfollowRedirects = true\n\
                 \temptyAuth = true\n",
                mark("helper-home", "exit 0"),
                mark("askpass-core", "echo secret"),
                mark("ssh-core", "exit 255"),
            ),
        )
        .unwrap();
        std::fs::write(
            home.join(".netrc"),
            "machine 127.0.0.1 login alice password secret\n",
        )
        .unwrap();
        std::fs::write(
            xdg.join("git/config"),
            format!(
                "[credential]\n\thelper = {}\n[http]\n\textraHeader = X-Person: xdg\n",
                mark("helper-xdg", "exit 0")
            ),
        )
        .unwrap();
        let global = root.join("global-config");
        std::fs::write(
            &global,
            format!(
                "[credential]\n\thelper = {}\n[http]\n\textraHeader = X-Person: global\n",
                mark("helper-global", "exit 0")
            ),
        )
        .unwrap();
        // An `ssh` first on the PATH: run, it is seen.
        mark("ssh", "exit 255");
        let path = std::env::join_paths(std::iter::once(bin.clone()).chain(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        )))
        .unwrap();
        let env: Vec<(OsString, OsString)> = [
            ("PATH", path),
            ("HOME", home.into()),
            ("XDG_CONFIG_HOME", xdg.into()),
            ("GIT_SSL_CAINFO", bench.server.ca_file().into()),
            ("GIT_ASKPASS", mark("askpass-git", "echo secret").into()),
            ("SSH_ASKPASS", mark("askpass-ssh", "echo secret").into()),
            ("SSH_ASKPASS_REQUIRE", "force".into()),
            ("DISPLAY", ":0".into()),
            ("GIT_TERMINAL_PROMPT", "1".into()),
            ("GIT_SSH_COMMAND", mark("ssh-env", "exit 255").into()),
            ("GIT_SSH", mark("ssh-git", "exit 255").into()),
            ("GIT_CONFIG_GLOBAL", global.into()),
            ("GIT_CONFIG_COUNT", "2".into()),
            ("GIT_CONFIG_KEY_0", "credential.helper".into()),
            ("GIT_CONFIG_VALUE_0", mark("helper-count", "exit 0").into()),
            ("GIT_CONFIG_KEY_1", "http.extraHeader".into()),
            ("GIT_CONFIG_VALUE_1", "X-Person: count".into()),
            (
                "GIT_CONFIG_PARAMETERS",
                format!(
                    "'credential.helper'='{}'",
                    mark("helper-parameters", "exit 0")
                )
                .into(),
            ),
        ]
        .into_iter()
        .map(|(name, value)| (OsString::from(name), value))
        .collect();
        Self { root, env }
    }

    fn marks(&self) -> Vec<String> {
        marks_in(&self.root.join("marks"))
    }

    /// A clone whose remote is SSH, with settings of its own that would
    /// ask.
    fn clone_of(&self, bench: &Bench) -> PathBuf {
        let clone = bench.clone_of("ssh-clone");
        let (bin, marks) = (self.root.join("bin"), self.root.join("marks"));
        let mark = |name: &str, then: &str| marker(&bin, name, &marks, then).display().to_string();
        let home = bench.home();
        let set = |key: &str, value: &str| git(&home, &clone, &["config", key, value]);
        set(
            "remote.origin.url",
            "ssh://git@example.org/example/project.git",
        );
        set("credential.helper", &mark("helper-clone", "exit 0"));
        set("core.askPass", &mark("askpass-clone", "echo secret"));
        set("core.sshCommand", &mark("ssh-clone", "exit 255"));
        set(
            &format!("url.{}.insteadOf", bench.server.url("example", "x")),
            "ssh://git@example.org/",
        );
        clone
    }
}

/// What the node does that could ask, and what it must give: a fetch from
/// a host that asks for a password, a fetch over SSH and one from a file,
/// and the reads of a clone whose remote is SSH.
fn the_node_reads(
    node: &Git,
    bench_url: &str,
    ssh_url: &str,
    file_url: &str,
    clone: &Path,
) -> Vec<String> {
    let deadline = || Instant::now() + Duration::from_secs(20);
    let mut said = Vec::new();
    let failed = |read: Result<ListAt, ListFailed>| match read {
        Ok(_) => "read".to_string(),
        Err(failed) => failed.code().to_string(),
    };
    said.push(format!(
        "password: {}",
        failed(node.fetch_list_by(&identity(), bench_url, deadline()))
    ));
    said.push(format!(
        "ssh: {}",
        failed(node.fetch_list_by(&identity(), ssh_url, deadline()))
    ));
    said.push(format!(
        "file: {}",
        failed(node.fetch_list_by(&identity(), file_url, deadline()))
    ));
    let chosen = node.identity_of_clone(clone, None);
    said.push(format!("remote: {:?}", chosen.map(|(remote, _)| remote)));
    let read = node.read_clone(clone, "origin", &identity());
    said.push(format!(
        "clone: {}",
        failed(read.clone().map(|read| read.at))
    ));
    if let Ok(read) = read {
        said.push(format!(
            "after: {:?}",
            node.comes_after(clone, &read.at.commit, &read.at.commit)
        ));
    }
    said
}

/// What the node must have said, in [`the_node_reads`].
const EXPECTED: [&str; 6] = [
    "password: asks_for_password",
    "ssh: not_https",
    "file: not_https",
    "remote: Ok(\"origin\")",
    "clone: read",
    "after: Ok(true)",
];

/// Nothing of the person's reaches git, so nothing asks (rule 3): a
/// credential helper, `GIT_ASKPASS`, `SSH_ASKPASS` and `core.sshCommand`,
/// each set in the person's HOME, in the clone's own configuration and in
/// the environment the node inherits, is a program that writes a mark,
/// and none is written; the host is sent no password and nothing of the
/// person's settings; nothing goes over SSH or from a file; and the clone
/// is left as it was. Here the environment is handed to `Git::given`:
/// that a node takes only what it should of the environment its own
/// process inherits is shown by `nothing_asks_at_a_terminal` alone.
#[test]
fn nothing_of_the_persons_reaches_git_and_nothing_asks() {
    let bench = Bench::new(Answers::Password);
    bench.commit(Some(LIST));
    let person = Person::of(&bench);
    let clone = person.clone_of(&bench);
    let node = Git::given(&bench.tmp.path().join("node"), "git", person.env.clone()).unwrap();
    let before = snapshot(&clone);
    let ssh_url = format!(
        "ssh://git@127.0.0.1:{}/example/project.git",
        bench.server.port
    );
    let file_url = format!("file://{}", bench.bare.display());
    let said = the_node_reads(&node, &bench.url(), &ssh_url, &file_url, &clone);
    assert_eq!(said, EXPECTED);
    assert_eq!(person.marks(), Vec::<String>::new());
    assert_eq!(snapshot(&clone), before, "a read changed the clone");
    nothing_of_the_persons_reached(&bench.server);
}

/// The host was asked, and sent no password and no header that the
/// person's settings add.
fn nothing_of_the_persons_reached(server: &GitServer) {
    let seen = server.seen();
    assert!(!seen.is_empty());
    for seen in &seen {
        assert_eq!(seen.header("authorization"), None, "{seen:?}");
        assert_eq!(seen.header("x-person"), None, "{seen:?}");
    }
}

/// [`nothing_of_the_persons_reaches_git_and_nothing_asks`], run by a
/// process of its own whose controlling terminal is the test's: git would
/// ask there, if anything let it. Nothing is written at the terminal.
#[test]
fn nothing_asks_at_a_terminal() {
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use std::os::unix::process::CommandExt;
    let bench = Bench::new(Answers::Password);
    bench.commit(Some(LIST));
    let person = Person::of(&bench);
    let clone = person.clone_of(&bench);
    let ours = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("a terminal");
    grantpt(&ours).unwrap();
    unlockpt(&ours).unwrap();
    let theirs = PathBuf::from(ptsname(&ours, Vec::new()).unwrap().to_str().unwrap());
    let terminal = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&theirs)
        .unwrap();
    let said_to = bench.tmp.path().join("child-said");
    let log = std::fs::File::create(bench.tmp.path().join("child-log")).unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "the_child_at_a_terminal",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env_clear()
        .envs(person.env.iter().map(|(n, v)| (n, v)))
        .env("RUST_BACKTRACE", "0")
        .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|file| ("LLVM_PROFILE_FILE", file)))
        .env("CORDELIA_GIT_LIST_CHILD", &said_to)
        .env("CHILD_DATA", bench.tmp.path().join("node"))
        .env("CHILD_URL", bench.url())
        .env(
            "CHILD_SSH_URL",
            format!(
                "ssh://git@127.0.0.1:{}/example/project.git",
                bench.server.port
            ),
        )
        .env("CHILD_FILE_URL", format!("file://{}", bench.bare.display()))
        .env("CHILD_CLONE", &clone)
        .stdin(terminal)
        .stdout(log.try_clone().unwrap())
        .stderr(log);
    // SAFETY: setsid(2) and ioctl(2) are async-signal-safe, and are given
    // no pointer.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    // The child holds its end of the terminal, and the test none of it.
    drop(command);
    let ours = std::fs::File::from(ours);
    let (tx, heard) = std::sync::mpsc::channel();
    let mut reads = ours.try_clone().unwrap();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = [0u8; 4096];
        while let Ok(n) = reads.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let until = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > until {
            let _ = child.kill();
            panic!("the child did not end");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    std::thread::sleep(Duration::from_millis(200));
    let at_the_terminal: Vec<u8> = heard.try_iter().flatten().collect();
    let log = std::fs::read_to_string(bench.tmp.path().join("child-log")).unwrap_or_default();
    assert!(status.success(), "the child failed: {log}");
    let said = std::fs::read_to_string(&said_to).unwrap_or_else(|_| panic!("{log}"));
    assert_eq!(
        String::from_utf8_lossy(&at_the_terminal),
        "",
        "git wrote at the terminal"
    );
    let mut said = said.lines();
    // The child's terminal is the test's: git could ask there.
    assert_eq!(said.next(), Some("terminal: true"), "{log}");
    assert_eq!(said.collect::<Vec<_>>(), EXPECTED, "{log}");
    assert_eq!(person.marks(), Vec::<String>::new());
    nothing_of_the_persons_reached(&bench.server);
}

/// The child of [`nothing_asks_at_a_terminal`]: the node's git made from
/// the environment it inherited, as a node makes it. Run by itself, it
/// does nothing.
#[test]
fn the_child_at_a_terminal() {
    let Some(said_to) = std::env::var_os("CORDELIA_GIT_LIST_CHILD") else {
        return;
    };
    let var = |name: &str| std::env::var(name).unwrap();
    let node = Git::under(Path::new(&var("CHILD_DATA"))).unwrap();
    // Opened, and nothing written at it.
    let terminal = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_ok();
    let mut said = vec![format!("terminal: {terminal}")];
    said.extend(the_node_reads(
        &node,
        &var("CHILD_URL"),
        &var("CHILD_SSH_URL"),
        &var("CHILD_FILE_URL"),
        Path::new(&var("CHILD_CLONE")),
    ));
    std::fs::write(said_to, said.join("\n") + "\n").unwrap();
}
