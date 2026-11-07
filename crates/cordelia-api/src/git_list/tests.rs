//! The identity of a repository, the choice of a remote, and what git's
//! words say (decision 2026-11-06 (joining), rules 2.1 and 3). Git itself
//! is run in `tests/git_list.rs`.

use super::*;

use std::ffi::OsString;

fn identity(address: &str) -> Result<String, NotAnIdentity> {
    Identity::from_address(address).map(|identity| identity.to_string())
}

fn remote(name: &str, addresses: &[&str]) -> Remote {
    Remote {
        name: name.to_string(),
        addresses: addresses.iter().map(|a| a.to_string()).collect(),
    }
}

/// Each of the four forms, with and without `.git`, names the same
/// repository, in lower case (rule 2.1).
#[test]
fn test_each_of_the_four_forms_names_the_repository_in_lower_case() {
    for address in [
        "https://example.org/example/project",
        "https://example.org/example/project.git",
        "ssh://git@example.org/example/project",
        "ssh://git@example.org/example/project.git",
        "ssh://example.org/example/project",
        "ssh://example.org/example/project.git",
        "git@example.org:example/project",
        "git@example.org:example/project.git",
        "https://Example.ORG/Example/Project.GIT",
        "git@EXAMPLE.org:EXAMPLE/project",
    ] {
        assert_eq!(
            identity(address).as_deref(),
            Ok("example.org/example/project"),
            "{address}"
        );
    }
    let named = Identity::from_address("git@code.example.org:team-1/a.b_c-d").unwrap();
    assert_eq!(named.host(), "code.example.org");
    assert_eq!(named.owner(), "team-1");
    assert_eq!(named.name(), "a.b_c-d");
    // A repository's name may begin with a dot, as `.github` does.
    assert_eq!(
        identity("https://example.org/example/.github").as_deref(),
        Ok("example.org/example/.github")
    );
    // An international top-level name.
    assert_eq!(
        identity("https://example.xn--p1ai/example/project").as_deref(),
        Ok("example.xn--p1ai/example/project")
    );
}

/// An address names a port, or a user other than `git`, or is in no
/// other form: it names nothing (rule 2.1: "nothing else, and no port").
#[test]
fn test_a_port_another_user_or_another_form_names_nothing() {
    use NotAnIdentity::*;
    for (address, why) in [
        ("https://example.org:443/example/project", Port),
        ("https://example.org:8443/example/project.git", Port),
        ("ssh://git@example.org:22/example/project", Port),
        ("ssh://example.org:2222/example/project", Port),
        ("ssh://bob@example.org/example/project", User),
        ("https://bob@example.org/example/project", User),
        ("https://bob:secret@example.org/example/project", User),
        ("bob@example.org:example/project", User),
        ("http://example.org/example/project", Form),
        ("git://example.org/example/project", Form),
        ("file:///srv/example/project", Form),
        ("/srv/example/project", Form),
        ("../project", Form),
        ("example.org:example/project", Form),
        ("https://example.org/example", Form),
        ("https://example.org/example/project/", Form),
        ("https://example.org/group/sub/project", Form),
        ("https://example.org//project", Form),
        ("https://example.org/example/", Form),
        ("https://example.org", Form),
        ("git@example.org:/example/project", Form),
        ("git@example.org:example/project/more", Form),
        ("git@example.org/example/project", Form),
        ("HTTPS://example.org/example/project", Form),
        ("https://example.org/exa mple/project", Part),
        ("https://example.org/example/pro%20ject", Part),
        ("https://example.org/example/project?x=1", Part),
        ("https://example.org/example/project#main", Part),
        ("https://example.org/~bob/project", Part),
        ("https://example.org/example/..", Part),
        ("https://example.org/../project", Part),
        ("https://example.org/example/.", Part),
        ("https://example.org/-example/project", Part),
        ("https://example.org/example/-project", Part),
        ("https://example.org/example/.git", Form),
        ("", Form),
    ] {
        assert_eq!(identity(address), Err(why), "{address}");
    }
    let long = "a".repeat(AGENT_MESSAGE_LINK_REPO_MAX_BYTES + 1);
    assert_eq!(
        identity(&format!("https://example.org/{long}/project")),
        Err(Part)
    );
    let longest = "a".repeat(AGENT_MESSAGE_LINK_REPO_MAX_BYTES);
    assert!(identity(&format!("https://example.org/{longest}/{longest}")).is_ok());
}

/// A host that HTTPS cannot reach, as an SSH alias that only
/// `~/.ssh/config` knows, is refused with a reason that names it (rule
/// 2.1).
#[test]
fn test_an_ssh_alias_is_refused_with_a_reason_that_names_it() {
    for (address, host) in [
        ("git@github.com-work:example/project", "github.com-work"),
        ("git@work:example/project", "work"),
        ("ssh://git@gitserver/example/project", "gitserver"),
        ("https://localhost/example/project", "localhost"),
        ("git@192.168.1.10:example/project", "192.168.1.10"),
        ("https://example.org./example/project", "example.org."),
        ("https://-example.org/example/project", "-example.org"),
        ("https://example-.org/example/project", "example-.org"),
        ("https://exa_mple.org/example/project", "exa_mple.org"),
        ("https://example.o/example/project", "example.o"),
        ("https://[::1]/example/project", "[::1]"),
        ("https://example.xn--/example/project", "example.xn--"),
    ] {
        let why = Identity::from_address(address).unwrap_err();
        assert_eq!(why, NotAnIdentity::Alias(host.to_string()), "{address}");
        assert!(why.says().contains(host), "{}", why.says());
        assert!(why.says().contains("HTTPS cannot reach"), "{}", why.says());
    }
}

/// An identity is kept as `host/owner/name`, and read back only as that.
#[test]
fn test_an_identity_reads_back_from_its_text_alone() {
    let named = Identity::from_address("git@example.org:example/project.git").unwrap();
    assert_eq!(Identity::from_text(&named.to_string()), Some(named.clone()));
    assert_eq!(named.https_url(), "https://example.org/example/project.git");
    for text in [
        "example.org/example",
        "example.org/example/project/more",
        "Example.org/example/project",
        "work/example/project",
        "example.org/../project",
        "",
    ] {
        assert_eq!(Identity::from_text(text), None, "{text}");
    }
}

/// The node's own repository for an identity is one folder under its
/// repositories: `<host>/<owner>/<name>.git`.
#[test]
fn test_the_nodes_own_repository_is_under_its_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let git = Git::given(tmp.path(), "git", std::env::vars_os()).unwrap();
    let named = Identity::from_address("https://example.org/example/.github").unwrap();
    assert_eq!(
        git.repo_of(&named),
        tmp.path().join("repos/example.org/example/.github.git")
    );
    assert!(tmp.path().join("git-home").is_dir());
    assert_eq!(
        std::fs::read_dir(tmp.path().join("git-home"))
            .unwrap()
            .count(),
        0
    );
}

/// One remote that names a repository is the one; several that name one
/// repository read through `origin`; several that name different ones
/// need `--remote`, and the choice is named (rule 2.1).
#[test]
fn test_one_remote_is_the_one_and_several_that_differ_need_a_choice() {
    let project = Identity::from_address("https://example.org/example/project").unwrap();
    let fork = Identity::from_address("https://example.org/alice/project").unwrap();
    // One remote.
    let remotes = [remote("upstream", &["git@example.org:example/project.git"])];
    assert_eq!(
        choose_remote(&remotes, None),
        Ok(("upstream".to_string(), project.clone()))
    );
    // Two that name one repository: through origin.
    let remotes = [
        remote("mirror", &["https://example.org/example/project"]),
        remote("origin", &["ssh://git@example.org/example/project.git"]),
    ];
    assert_eq!(
        choose_remote(&remotes, None),
        Ok(("origin".to_string(), project.clone()))
    );
    // A fork's origin and the repository's upstream.
    let remotes = [
        remote("origin", &["git@example.org:alice/project.git"]),
        remote("upstream", &["https://example.org/example/project.git"]),
    ];
    let Err(RemoteRefused::Several(each)) = choose_remote(&remotes, None) else {
        panic!("two repositories need a choice");
    };
    assert_eq!(
        each,
        vec![
            ("origin".to_string(), fork.clone()),
            ("upstream".to_string(), project.clone())
        ]
    );
    let says = RemoteRefused::Several(each).says();
    assert!(says.contains("--remote"), "{says}");
    assert!(
        says.contains("origin is example.org/alice/project"),
        "{says}"
    );
    assert_eq!(
        choose_remote(&remotes, Some("upstream")),
        Ok(("upstream".to_string(), project.clone()))
    );
    assert_eq!(
        choose_remote(&remotes, Some("origin")),
        Ok(("origin".to_string(), fork))
    );
    assert_eq!(
        choose_remote(&remotes, Some("other")),
        Err(RemoteRefused::NoSuchRemote("other".to_string()))
    );
    // An alias beside a remote that names a repository is passed over.
    let remotes = [
        remote("origin", &["git@github.com-work:alice/project.git"]),
        remote("upstream", &["https://example.org/example/project"]),
    ];
    assert_eq!(
        choose_remote(&remotes, None),
        Ok(("upstream".to_string(), project.clone()))
    );
    // Chosen, it is refused with why.
    let refused = choose_remote(&remotes, Some("origin")).unwrap_err();
    assert_eq!(
        refused,
        RemoteRefused::NotARepository(
            "origin".to_string(),
            NotAnIdentity::Alias("github.com-work".to_string())
        )
    );
    assert!(refused.says().contains("github.com-work"));
}

/// A clone with no remote, or none that names a repository, is refused
/// with each remote and why; a remote whose addresses differ names none.
#[test]
fn test_no_remote_that_names_a_repository_is_refused_with_why() {
    assert_eq!(choose_remote(&[], None), Err(RemoteRefused::NoRemote));
    let remotes = [
        remote("origin", &["git@work:example/project"]),
        remote("local", &["/srv/git/project"]),
    ];
    let refused = choose_remote(&remotes, None).unwrap_err();
    assert_eq!(
        refused,
        RemoteRefused::NoneNamesARepository(vec![
            (
                "origin".to_string(),
                NotAnIdentity::Alias("work".to_string())
            ),
            ("local".to_string(), NotAnIdentity::Form),
        ])
    );
    let says = refused.says();
    assert!(says.contains("origin has the host work"), "{says}");
    assert!(says.contains("local is not https://"), "{says}");
    let two = [remote(
        "origin",
        &[
            "https://example.org/example/project",
            "https://example.org/alice/project",
        ],
    )];
    assert_eq!(
        choose_remote(&two, Some("origin")),
        Err(RemoteRefused::TwoRepositories("origin".to_string()))
    );
    let refused = choose_remote(&two, None).unwrap_err();
    assert_eq!(refused, RemoteRefused::NoneNamesARepository(Vec::new()));
    assert_eq!(
        refused.says(),
        "No remote of this clone names one repository that can be read."
    );
    // Two addresses of the one repository name it.
    let same = [remote(
        "origin",
        &[
            "https://example.org/example/project",
            "git@example.org:example/project.git",
        ],
    )];
    assert!(choose_remote(&same, None).is_ok());
}

/// A clone's remotes, and whether it is partial, from what `git config
/// --null --list` gives.
#[test]
fn test_a_clones_remotes_and_whether_it_is_partial_are_read_from_its_config() {
    let list = b"core.bare\nfalse\0remote.origin.url\nhttps://example.org/example/project\0\
remote.origin.fetch\n+refs/heads/*:refs/remotes/origin/*\0remote.Up.Stream.url\ngit@example.org:a/b\0\
remote.origin.url\ngit@example.org:example/project\0remote.-bad.url\nhttps://example.org/x/y\0\
remote.novalue.url\0";
    let config = CloneConfig::from_list(list);
    assert_eq!(
        config.remotes,
        vec![
            remote(
                "origin",
                &[
                    "https://example.org/example/project",
                    "git@example.org:example/project"
                ]
            ),
            remote("Up.Stream", &["git@example.org:a/b"]),
        ]
    );
    assert!(!config.partial);
    for (list, partial) in [
        (&b"remote.origin.promisor\ntrue\0"[..], true),
        (b"remote.origin.promisor\0", true),
        (b"remote.origin.promisor\nyes\0", true),
        (b"remote.origin.promisor\nfalse\0", false),
        (b"remote.origin.promisor\nOff\0", false),
        (b"extensions.partialclone\norigin\0", true),
        (b"extensions.worktreeconfig\ntrue\0", false),
    ] {
        assert_eq!(
            CloneConfig::from_list(list).partial,
            partial,
            "{}",
            String::from_utf8_lossy(list)
        );
    }
}

/// Git's version, from what `git version` prints on each kind of system;
/// and the first that heeds `GIT_NO_LAZY_FETCH`.
#[test]
fn test_gits_version_is_read_from_what_it_prints() {
    for (printed, version) in [
        ("git version 2.55.0\n", Some((2, 55))),
        ("git version 2.43.0\n", Some((2, 43))),
        ("git version 2.39.3 (Apple Git-146)\n", Some((2, 39))),
        ("git version 2.45.1.windows.1\n", Some((2, 45))),
        ("git version 3.0\n", Some((3, 0))),
        ("git version\n", None),
        ("version 2.44.0\n", None),
        ("", None),
    ] {
        assert_eq!(
            GitVersion::from_output(printed.as_bytes()),
            version.map(|(major, minor)| GitVersion { major, minor }),
            "{printed}"
        );
    }
    let v = |major, minor| GitVersion { major, minor };
    assert!(v(2, 43) < NO_LAZY_FETCH_SINCE);
    assert!(v(1, 99) < NO_LAZY_FETCH_SINCE);
    assert!(v(2, 44) >= NO_LAZY_FETCH_SINCE);
    assert!(v(3, 0) >= NO_LAZY_FETCH_SINCE);
}

/// Why a fetch failed, from git's words in the C locale.
#[test]
fn test_why_a_fetch_failed_is_read_from_gits_words() {
    let at = "fatal: unable to access 'https://example.org/example/project.git/': ";
    for (said, failed) in [
        (
            format!("{at}The requested URL returned error: 301\n"),
            ListFailed::Moved,
        ),
        (
            format!("{at}The requested URL returned error: 308\n"),
            ListFailed::Moved,
        ),
        (
            "fatal: could not read Username for 'https://example.org': terminal prompts disabled\n"
                .to_string(),
            ListFailed::AsksForPassword,
        ),
        (
            format!("{at}The requested URL returned error: 403\n"),
            ListFailed::AsksForPassword,
        ),
        (
            "fatal: repository 'https://example.org/example/project.git/' not found\n".to_string(),
            ListFailed::NotFound,
        ),
        (
            "fatal: couldn't find remote ref HEAD\n".to_string(),
            ListFailed::NoCommits,
        ),
        (
            "fatal: transport 'ssh' not allowed\n".to_string(),
            ListFailed::NotHttps,
        ),
        (
            format!("{at}SSL certificate problem: unable to get local issuer certificate\n"),
            ListFailed::Certificate(
                "SSL certificate problem: unable to get local issuer certificate".to_string(),
            ),
        ),
        (
            format!("{at}Could not resolve host: example.org\n"),
            ListFailed::NotReached("Could not resolve host: example.org".to_string()),
        ),
        (
            format!("{at}Failed to connect to example.org port 443 after 0 ms\n"),
            ListFailed::NotReached(
                "Failed to connect to example.org port 443 after 0 ms".to_string(),
            ),
        ),
        (
            "remote: something\nfatal: the remote end hung up unexpectedly\n".to_string(),
            ListFailed::Git("the remote end hung up unexpectedly".to_string()),
        ),
        // What the host says, on the lines git begins with `remote:`, is
        // not read as git's own words.
        (
            "remote: fatal: The requested URL returned error: 301\n\
             remote: fatal: could not read Username\n\
             fatal: the remote end hung up unexpectedly\n"
                .to_string(),
            ListFailed::Git("the remote end hung up unexpectedly".to_string()),
        ),
        (
            "remote: fatal: transport 'x' not allowed\n".to_string(),
            ListFailed::Git("nothing".to_string()),
        ),
        // What a host says is shown only as printable ASCII, and short.
        (
            format!("fatal: \x1b[31m{}\n", "x".repeat(300)),
            ListFailed::Git(format!("[31m{}", "x".repeat(116))),
        ),
    ] {
        assert_eq!(fetch_failed(&said), failed, "{said}");
    }
}

/// Every failure says why in words of its own, and has a word of its own.
#[test]
fn test_every_failure_says_why_and_has_a_word_of_its_own() {
    let remote = || "origin".to_string();
    let failures = [
        ListFailed::GitNotRun("No such file or directory".to_string()),
        ListFailed::Late { secs: 60 },
        ListFailed::Busy,
        ListFailed::OldGitNoFetch {
            version: Some(GitVersion {
                major: 2,
                minor: 39,
            }),
        },
        ListFailed::Moved,
        ListFailed::AsksForPassword,
        ListFailed::NotFound,
        ListFailed::NoCommits,
        ListFailed::NotReached("Could not resolve host".to_string()),
        ListFailed::Certificate("unable to get local issuer certificate".to_string()),
        ListFailed::NotHttps,
        ListFailed::NotARepository,
        ListFailed::NoSuchRemote(remote()),
        ListFailed::RemoteMoved { remote: remote() },
        ListFailed::NoRemoteHead { remote: remote() },
        ListFailed::NoBranch {
            remote: remote(),
            branch: "main".to_string(),
        },
        ListFailed::PartialOnOldGit {
            version: Some(GitVersion {
                major: 2,
                minor: 43,
            }),
        },
        ListFailed::NotInClone {
            remote: remote(),
            branch: "main".to_string(),
        },
        ListFailed::NotAFile,
        ListFailed::TooLarge,
        ListFailed::Git("bad object".to_string()),
    ];
    let mut codes: Vec<_> = failures.iter().map(ListFailed::code).collect();
    codes.sort();
    codes.dedup();
    assert_eq!(codes.len(), failures.len());
    let says: BTreeSet<String> = failures.iter().map(ListFailed::says).collect();
    assert_eq!(says.len(), failures.len());
    assert!(says.iter().all(|line| line.len() < 160 && !line.is_empty()));
    assert!(
        ListFailed::NoRemoteHead { remote: remote() }
            .says()
            .contains("git remote set-head origin --auto")
    );
    assert!(ListFailed::Moved.says().contains("has moved"));
    assert!(
        ListFailed::PartialOnOldGit {
            version: Some(GitVersion {
                major: 2,
                minor: 43
            })
        }
        .says()
        .contains("git 2.43 is older than 2.44")
    );
    assert!(ListFailed::TooLarge.says().contains("16 KiB"));
    assert_eq!(
        ListFailed::OldGitNoFetch { version: None }.says(),
        "the version of git is not known, so the node does not fetch the list itself: \
         it is read from your clone; upgrade git for the node to fetch it"
    );
}

/// A branch, a remote's name and a commit, as the node puts them in a
/// command.
#[test]
fn test_what_the_node_puts_in_a_command_is_checked_first() {
    for good in ["main", "release/1.0", "feat/a_b-c"] {
        assert!(is_a_branch(good), "{good}");
    }
    for bad in [
        "", "-x", "a/-x", "a b", "a..b", "..", "a//b", "a~1", "a^", "a:b", "a\x1bb",
    ] {
        assert!(!is_a_branch(bad), "{bad}");
    }
    assert!(is_a_remote_name("origin"));
    assert!(is_a_remote_name("Up.Stream_2-x"));
    for bad in ["", "-c", ".x", "a/b", "a b", "a:b"] {
        assert!(!is_a_remote_name(bad), "{bad}");
    }
    assert!(is_a_commit(&"a".repeat(40)));
    assert!(is_a_commit(&"0".repeat(64)));
    for bad in [
        "a".repeat(39),
        "g".repeat(40),
        "--all".to_string(),
        String::new(),
    ] {
        assert!(!is_a_commit(&bad), "{bad}");
    }
}

/// The node's folder for git's HOME is kept empty: what is put in it is
/// taken out before git runs.
#[test]
fn test_gits_home_is_kept_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let git = Git::given(tmp.path(), "git", std::env::vars_os()).unwrap();
    std::fs::write(
        git.home().join(".gitconfig"),
        "[credential]\n\thelper = x\n",
    )
    .unwrap();
    std::fs::create_dir_all(git.home().join("git")).unwrap();
    std::fs::write(git.home().join("git/config"), "").unwrap();
    std::fs::write(git.home().join(".netrc"), "machine example.org\n").unwrap();
    keep_empty(git.home()).unwrap();
    assert_eq!(std::fs::read_dir(git.home()).unwrap().count(), 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(git.home()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        // A link in its place is refused, and what it leads to is left.
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join(".gitconfig"), "").unwrap();
        std::fs::remove_dir_all(git.home()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, git.home()).unwrap();
        assert!(keep_empty(git.home()).is_err());
        assert!(elsewhere.join(".gitconfig").exists());
        assert!(Git::given(tmp.path(), "git", std::env::vars_os()).is_err());
    }
}

/// What a repository of the node's own holds on the disk, links not
/// followed.
#[test]
fn test_what_a_repository_holds_is_measured() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("r.git");
    std::fs::create_dir_all(repo.join("objects/pack")).unwrap();
    std::fs::write(repo.join("HEAD"), [0u8; 10]).unwrap();
    std::fs::write(repo.join("objects/pack/pack-1.pack"), [0u8; 1000]).unwrap();
    #[cfg(unix)]
    {
        let big = tmp.path().join("big");
        std::fs::write(&big, vec![0u8; 100_000]).unwrap();
        std::os::unix::fs::symlink(&big, repo.join("objects/linked")).unwrap();
        std::os::unix::fs::symlink(tmp.path(), repo.join("objects/up")).unwrap();
    }
    assert_eq!(bytes_under(&repo), 1010);
    assert_eq!(bytes_under(&tmp.path().join("none")), 0);
}

/// A `FETCH_HEAD` says the list is fresh only where it has a line for the
/// branch read, of the repository followed: git writes the address with
/// its user taken out, and without `.git`.
#[test]
fn test_fetch_head_says_fresh_only_for_the_branch_of_the_repository() {
    let project = Identity::from_address("https://example.org/example/project").unwrap();
    let commit = "a".repeat(40);
    let line = |flag: &str, note: &str| format!("{commit}\t{flag}\t{note}\n");
    for (text, fresh) in [
        (
            line("", "branch 'main' of https://example.org/example/project"),
            true,
        ),
        (
            line(
                "not-for-merge",
                "branch 'main' of https://example.org/example/project",
            ),
            true,
        ),
        (
            line("", "branch 'main' of ssh://example.org/example/project"),
            true,
        ),
        (
            line("", "branch 'main' of example.org:example/project"),
            true,
        ),
        (
            line(
                "not-for-merge",
                "branch 'dev' of https://example.org/example/project",
            ) + &line("", "branch 'main' of https://Example.org/Example/Project"),
            true,
        ),
        // Another branch: the one the clone reads was not fetched.
        (
            line("", "branch 'master' of https://example.org/example/project"),
            false,
        ),
        (
            line("", "branch 'main/x' of https://example.org/example/project"),
            false,
        ),
        (
            line("", "tag 'main' of https://example.org/example/project"),
            false,
        ),
        // Another repository, or one the node does not read.
        (
            line("", "branch 'main' of https://example.org/alice/project"),
            false,
        ),
        (line("", "branch 'main' of /srv/git/project"), false),
        (line("", "branch 'main' of work:example/project"), false),
        (
            line("", "branch 'main' of bob@example.org:example/project"),
            false,
        ),
        // Not a line of git's.
        (
            format!("{commit} branch 'main' of https://example.org/example/project\n"),
            false,
        ),
        (
            "x\t\tbranch 'main' of https://example.org/example/project\n".to_string(),
            false,
        ),
        (String::new(), false),
    ] {
        assert_eq!(fetch_head_names(&text, "main", &project), fresh, "{text}");
    }
}

/// What a git that was stopped leaves in the node's own repository is
/// taken out, and nothing else.
#[test]
fn test_a_stopped_gits_locks_are_cleared() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("r.git");
    for dir in [
        "refs/cordelia",
        "refs/heads",
        "objects/info",
        "objects/pack",
    ] {
        std::fs::create_dir_all(repo.join(dir)).unwrap();
    }
    let stale = [
        "shallow.lock",
        "config.lock",
        "packed-refs.lock",
        "HEAD.lock",
        "refs/cordelia/list.lock",
        "objects/info/commit-graph.lock",
        "objects/pack/tmp_pack_x1",
        "objects/pack/tmp_idx_x1",
        "objects/pack/multi-pack-index.lock",
    ];
    let kept = [
        "shallow",
        "config",
        "HEAD",
        "refs/cordelia/list",
        "objects/pack/pack-1.pack",
        "objects/pack/pack-1.idx",
    ];
    for file in stale.iter().chain(kept.iter()) {
        std::fs::write(repo.join(file), "").unwrap();
    }
    clear_locks(&repo);
    for file in stale {
        assert!(!repo.join(file).exists(), "{file}");
    }
    for file in kept {
        assert!(repo.join(file).exists(), "{file}");
    }
}

/// Every git command runs in the cleared environment of rule 3, with the
/// settings that stand over a clone's own, whatever the node inherited:
/// only the kept variables come through.
#[test]
fn test_every_git_command_runs_in_the_cleared_environment() {
    let tmp = tempfile::tempdir().unwrap();
    let inherited = [
        ("PATH", "/usr/bin:/bin"),
        ("HTTPS_PROXY", "http://proxy.example.org:3128"),
        ("NO_PROXY", "example.org"),
        ("SSL_CERT_FILE", "/etc/ssl/a.pem"),
        ("GIT_SSL_CAINFO", "/etc/ssl/b.pem"),
        ("HOME", "/home/person"),
        ("XDG_CONFIG_HOME", "/home/person/.config"),
        ("GIT_ASKPASS", "/usr/bin/ask"),
        ("SSH_ASKPASS", "/usr/bin/ask"),
        ("GIT_CONFIG_GLOBAL", "/home/person/.gitconfig"),
        ("GIT_CONFIG_COUNT", "1"),
        ("GIT_SSH_COMMAND", "ssh -i key"),
        ("GIT_DIR", "/elsewhere"),
        ("SSH_AUTH_SOCK", "/tmp/agent"),
        ("KRB5CCNAME", "/tmp/krb5cc"),
    ]
    .map(|(name, value)| (OsString::from(name), OsString::from(value)));
    let git = Git::given(tmp.path(), "git", inherited).unwrap();
    let home = git.home().as_os_str().to_owned();
    let clone = tmp.path().join("clone");
    for at in [At::Nowhere, At::Own(&clone), At::Clone(&clone)] {
        let command = git.command(at);
        let envs: Vec<(String, Option<String>)> = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        let mut envs: std::collections::BTreeMap<String, Option<String>> =
            envs.into_iter().collect();
        let set = |value: &str| Some(value.to_string());
        let home = home.to_string_lossy().into_owned();
        let mut expected = std::collections::BTreeMap::new();
        for (name, value) in [
            ("PATH", "/usr/bin:/bin"),
            ("HTTPS_PROXY", "http://proxy.example.org:3128"),
            ("NO_PROXY", "example.org"),
            ("SSL_CERT_FILE", "/etc/ssl/a.pem"),
            ("GIT_SSL_CAINFO", "/etc/ssl/b.pem"),
            ("HOME", home.as_str()),
            ("XDG_CONFIG_HOME", home.as_str()),
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_ASKPASS", ""),
            ("GIT_ALLOW_PROTOCOL", "https"),
            ("GIT_NO_LAZY_FETCH", "1"),
            ("GIT_NO_REPLACE_OBJECTS", "1"),
            ("GIT_GRAFT_FILE", "/dev/null"),
            ("LC_ALL", "C"),
        ] {
            expected.insert(name.to_string(), set(value));
        }
        // Nothing else: the environment is cleared first.
        envs.retain(|_, value| value.is_some());
        assert_eq!(envs, expected);
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let mut settings = Vec::new();
        let mut args_left = args.iter();
        while let Some(arg) = args_left.next() {
            if arg == "-c" {
                settings.push(args_left.next().unwrap().clone());
            }
        }
        for setting in [
            "credential.helper=",
            "http.followRedirects=false",
            "http.emptyAuth=false",
            "core.hooksPath=/dev/null",
            "core.fsmonitor=false",
            "gc.auto=0",
            "maintenance.auto=false",
            "advice.graftFileDeprecated=false",
        ] {
            assert!(
                settings.iter().any(|s| s == setting),
                "{setting} in {args:?}"
            );
        }
        let safe = format!("safe.directory={}", clone.display());
        assert_eq!(
            settings.contains(&safe),
            matches!(at, At::Clone(_)),
            "{args:?}"
        );
    }
}
