//! Joining a repository's shared channel by pull request (decision
//! 2026-11-06 (joining), section 12), run as people run it, at a terminal,
//! against devices that are real processes and a relay of the test's own
//! on this machine.
//!
//! - **The host** is a bare repository on this machine's disk ([`Host`]). A
//!   merged pull request is a commit pushed there, and a person's `git
//!   fetch` brings it into their clone. Each clone's `origin` names the
//!   repository by its public address, as a person's clone does: the
//!   person's own git reaches the bare repository through a setting given
//!   on its command line alone, which the node never sees. The node reads
//!   the list from the clone, and fetches nothing.
//! - **The node's git** is a script that writes down each command it is
//!   given, then runs git, so a test can say what the node asked of git.
//! - **Each device reads its lists every few seconds** (`[members]
//!   read_interval_secs`, which only a test sets), so that no test waits
//!   ten minutes for a read. A member's device reads every
//!   [`MEMBER_READS`] seconds, so that its share waits two of those for a
//!   take; a device that waits to take reads every [`JOINER_READS`].

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::*;
use cordelia_crypto::bech32::{decode_public_key, encode_public_key};
use cordelia_crypto::identity::NodeIdentity;
use serde_json::{Value, json};

/// The repository of these tests, as each clone's `origin` names it.
const REPOSITORY: &str = "github.com/example/project";

/// Its public address, which each clone's `origin` has.
const PUBLIC: &str = "https://github.com/example/project";

/// The name its channel is filed under: its `owner/name`.
const NAME: &str = "example/project";

/// The agent of each person's clone of it.
const AGENT: &str = "project";

/// How often a member's device reads the list, in seconds: its share to a
/// key lives for two reads.
const MEMBER_READS: u64 = 20;

/// How often a device that waits to take the channel reads the list, in
/// seconds: each read asks the relays for a share once.
const JOINER_READS: u64 = 5;

/// What every making anew says before its new channel line (decision
/// 2026-11-06 (joining), rule 5).
const PUT_THE_LINE: &str = "If this channel follows a repository's list, put this line in place \
                            of its channel line, in a pull request:";

fn path(p: &Path) -> String {
    p.to_str().unwrap().to_string()
}

// ── The host and the clones ──────────────────────────────────────────

/// git, run in `dir` with `home` as its home and nothing else of whoever
/// runs the tests: no setting of theirs, and no variable but `PATH`.
fn git_in(home: &Path, dir: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(["-c", "user.name=Test", "-c", "user.email=test@example.org"])
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// git, run in `dir` as `n`'s person runs it.
fn git(n: &Node, dir: &Path, args: &[&str]) -> String {
    git_in(&n.home(), dir, args)
}

/// The repository's host: a bare repository, whose default branch is
/// `main`, and a work tree where its pull requests are merged, each a
/// commit pushed to it.
struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    /// A repository with one commit, which has no list.
    fn new() -> Self {
        let host = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        let top = host.dir.path();
        std::fs::create_dir_all(host.work().join(".cordelia")).unwrap();
        git_in(top, top, &["init", "--quiet", "--bare", "project.git"]);
        git_in(
            top,
            &host.bare(),
            &["symbolic-ref", "HEAD", "refs/heads/main"],
        );
        let work = host.work();
        git_in(top, &work, &["init", "--quiet"]);
        git_in(top, &work, &["symbolic-ref", "HEAD", "refs/heads/main"]);
        std::fs::write(work.join("README"), "A project.\n").unwrap();
        git_in(top, &work, &["add", "README"]);
        git_in(top, &work, &["commit", "--quiet", "-m", "first"]);
        git_in(
            top,
            &work,
            &["remote", "add", "origin", &path(&host.bare())],
        );
        git_in(top, &work, &["push", "--quiet", "origin", "main"]);
        host
    }

    fn bare(&self) -> PathBuf {
        self.dir.path().join("project.git")
    }

    fn work(&self) -> PathBuf {
        self.dir.path().join("work")
    }

    /// The commit the default branch is at.
    fn at(&self) -> String {
        git_in(self.dir.path(), &self.bare(), &["rev-parse", "main"])
    }

    /// A pull request that makes the list `list` is merged: a commit after
    /// the last one merged here, pushed to the default branch. Its commit.
    fn merges(&self, list: &str) -> String {
        let (top, work) = (self.dir.path(), self.work());
        std::fs::write(work.join(".cordelia/members"), list).unwrap();
        git_in(top, &work, &["add", "-A"]);
        git_in(
            top,
            &work,
            &["commit", "--quiet", "--allow-empty", "-m", "list"],
        );
        git_in(top, &work, &["push", "--quiet", "origin", "main"]);
        self.at()
    }

    /// The host's history is written again: its default branch goes back
    /// to `commit`, as a force push leaves it.
    fn goes_back_to(&self, commit: &str) {
        let refspec = format!("{commit}:main");
        git_in(
            self.dir.path(),
            &self.work(),
            &["push", "--quiet", "--force", "origin", &refspec],
        );
    }

    /// What the person's own git is given so that the public address
    /// reaches the bare repository on this disk: on its command line, and
    /// nowhere the node could read it.
    fn instead_of(&self) -> String {
        format!("url.{}.insteadOf={PUBLIC}", path(&self.bare()))
    }

    /// `n`'s person clones the repository from its public address into a
    /// folder of their home, and maps that folder to [`AGENT`]. The top of
    /// the clone.
    fn clone_for(&self, n: &Node) -> PathBuf {
        let home = n.home();
        std::fs::create_dir_all(&home).unwrap();
        let instead = self.instead_of();
        git(
            n,
            &home,
            &["-c", &instead, "clone", "--quiet", PUBLIC, "project"],
        );
        let top = home.join("project").canonicalize().unwrap();
        assert_eq!(git(n, &top, &["config", "remote.origin.url"]), PUBLIC);
        n.cli(&["sync", "map", &path(&top), AGENT]);
        top
    }

    /// `n`'s person runs `git fetch` in their clone at `top`, as `git
    /// pull` does first. Its `FETCH_HEAD` names the public address, as a
    /// fetch from the host writes it. The commit the clone's copy of the
    /// default branch is then at.
    fn fetches(&self, n: &Node, top: &Path) -> String {
        let instead = self.instead_of();
        git(n, top, &["-c", &instead, "fetch", "--quiet", "origin"]);
        // Git writes the address it fetched from without `.git`.
        let on_disk = path(&self.bare());
        let on_disk = on_disk.strip_suffix(".git").unwrap();
        let fetch_head = top.join(".git/FETCH_HEAD");
        let said = std::fs::read_to_string(&fetch_head).unwrap();
        let said = said.replace(&format!(" of {on_disk}\n"), &format!(" of {PUBLIC}\n"));
        std::fs::write(&fetch_head, said).unwrap();
        git(n, top, &["rev-parse", "refs/remotes/origin/main"])
    }
}

/// A key of a device that is never on: on a list, and nothing more.
fn key_off(seed: u8) -> String {
    let identity = NodeIdentity::from_seed([seed; 32]).unwrap();
    encode_public_key(&identity.public_key()).unwrap()
}

/// A list's line for the key `key`, labelled `label`.
fn line_for(key: &str, label: &str) -> String {
    format!("{key}   {label}\n")
}

/// The channel a list's `channel` line names.
fn channel_of_line(line: &str) -> [u8; 32] {
    let id = line.split(' ').nth(1).unwrap();
    hex::decode(id).unwrap().try_into().unwrap()
}

/// The commit `commit` as a status shows it.
fn short(commit: &str) -> &str {
    &commit[..12]
}

// ── The devices ──────────────────────────────────────────────────────

/// The real git on the `PATH`.
fn real_git() -> PathBuf {
    let paths = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&paths)
        .map(|dir| dir.join("git"))
        .find(|git| git.is_file())
        .expect("git is on the PATH")
}

/// The file in which `n`'s git writes down each command it is given.
fn git_commands(n: &Node) -> PathBuf {
    n.dir.path().join("git-commands")
}

/// The `PATH` that `n`'s node is started with: first a folder whose `git`
/// writes down each command it is given, one to a line, and then runs the
/// real git.
fn path_for(n: &Node) -> String {
    use std::os::unix::fs::PermissionsExt;
    let bin = n.dir.path().join("bin");
    let git = bin.join("git");
    if !git.exists() {
        std::fs::create_dir_all(&bin).unwrap();
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexec '{}' \"$@\"\n",
            path(&git_commands(n)),
            path(&real_git())
        );
        std::fs::write(&git, script).unwrap();
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let rest = std::env::var("PATH").unwrap_or_default();
    format!("{}:{rest}", path(&bin))
}

/// `n`'s node, started with its git of [`path_for`], and connected to
/// `relay`.
fn starts(n: &mut Node, relay: &Node) {
    let given = path_for(n);
    n.start_given(&[("PATH", given.as_str())]);
    wait_for("device healthy", &[n], 30, || healthy(n));
    wait_for("device reaches its relay", &[n, relay], 60, || {
        has_hot_peer(n)
    });
}

/// A device, `name`, which knows `relay` by its key, and reads the lists
/// it follows every `reads` seconds, or every ten minutes where none is
/// given: then it reads one only when a person follows it. Started.
fn device(name: &'static str, relay: &Node, reads: Option<u64>) -> Node {
    let mut device = node(name, "personal", Some(relay.p2p));
    device.add_relay(&format!("127.0.0.1:{}", relay.p2p), Some(&key_of(relay)));
    if let Some(secs) = reads {
        device.reads_lists_every_secs(secs);
    }
    starts(&mut device, relay);
    device
}

/// Sync on for `n`, with nothing mapped.
fn sync_on(n: &Node) {
    let out = n.cli(&["sync", "claude", "--dir", &path(&n.home().join(".claude"))]);
    assert!(out.starts_with("Sync turned on.\n"), "{out}");
}

/// A person's one device, as [`device`] makes it, which follows a phrase of
/// its own labelled `label` and has sync on.
fn person(name: &'static str, label: &str, relay: &Node, reads: Option<u64>) -> Node {
    let device = device(name, relay, reads);
    makes_a_phrase(&device, label);
    sync_on(&device);
    device
}

/// Every command `n`'s node gave git reads this machine alone: none
/// fetches, or asks a remote anything. Some read a clone's list.
fn asked_git_nothing_of_the_network(n: &Node) {
    let said = std::fs::read_to_string(git_commands(n)).unwrap_or_default();
    let mut read_a_list = false;
    for command in said.lines() {
        let mut words = command.split(' ');
        // Each `-c` and `-C` has its value after it.
        let what = loop {
            match words.next() {
                Some("-c" | "-C") => {
                    words.next();
                }
                Some(word) if word.starts_with('-') => {}
                Some(word) => break word,
                None => break "",
            }
        };
        let local = [
            "version",
            "for-each-ref",
            "ls-tree",
            "cat-file",
            "merge-base",
            "rev-parse",
            "config",
            "symbolic-ref",
        ];
        let get_url = what == "remote" && words.next() == Some("get-url");
        assert!(
            local.contains(&what) || get_url,
            "{}: its node gave git `{command}`",
            n.name
        );
        read_a_list |= what == "cat-file";
    }
    assert!(read_a_list, "{}: its node read no list:\n{said}", n.name);
}

// ── What the commands say ────────────────────────────────────────────

/// `cordelia subscribe` with no name on `n`, in the clone at `top`, with
/// `extra` arguments, at a terminal: its yes, once it has said `asks`.
/// What it said.
fn subscribes_in(n: &Node, top: &Path, extra: &[&str], asks: &str) -> String {
    let args = [&["subscribe"], extra].concat();
    let mut at = n.at_terminal_given(&[("CLAUDE_PROJECT_DIR", &path(top))], &args);
    at.says(asks).says("Type yes to go on").types("yes");
    at.done()
}

/// `cordelia subscribe --new` on `n`, in its clone at `top`: the channel
/// line it prints, and the lines of the person's own devices, each ending
/// in a line feed.
fn makes_the_channel(n: &Node, top: &Path) -> (String, String) {
    let said = subscribes_in(n, top, &["--new"], "This makes the shared channel");
    assert!(
        said.contains("Add these lines to .cordelia/members in a pull request:"),
        "{said}"
    );
    let line = said
        .lines()
        .find(|line| line.starts_with("channel "))
        .unwrap_or_else(|| panic!("no channel line:\n{said}"))
        .trim_end()
        .to_string();
    assert!(line.ends_with(" without 0"), "{line}");
    let own: String = said
        .lines()
        .filter(|line| line.starts_with("cordelia_pk1"))
        .map(|line| format!("{}\n", line.trim_end()))
        .collect();
    (line, own)
}

/// What `n` says of its shared channels (`POST /api/v1/shared/list`).
fn listed(n: &Node) -> Value {
    n.post("/api/v1/shared/list", json!({}))
}

/// The channel `name` as `n` lists it, where it does.
fn channel_of(n: &Node, name: &str) -> Option<Value> {
    listed(n)["channels"]
        .as_array()?
        .iter()
        .find(|channel| channel["name"] == name)
        .cloned()
}

/// The ID of the channel `n` files as `name`, where it does.
fn id_filed(n: &Node, name: &str) -> Option<[u8; 32]> {
    let channel = channel_of(n, name)?;
    hex::decode(channel["id"].as_str()?).ok()?.try_into().ok()
}

/// What `n` says of the one repository it follows (rule 7).
fn view_of(n: &Node) -> Value {
    listed(n)["repositories"][0].clone()
}

/// The lines of `n`'s view: each its word, what it says, and whether it
/// is amber.
fn lines_of(n: &Node) -> Vec<(String, String, bool)> {
    view_of(n)["lines"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|line| {
            (
                line["word"].as_str().unwrap_or_default().to_string(),
                line["says"].as_str().unwrap_or_default().to_string(),
                line["amber"] == true,
            )
        })
        .collect()
}

/// Wait until `n`'s view has a line with the word `word` that says
/// `says`, amber where `amber`. The view then.
fn shows(all: &[&Node], n: &Node, word: &str, says: &str, amber: bool) -> Value {
    let what = format!("{}: {word}: {says}", n.name);
    wait_for(&what, all, 300, || {
        let view = view_of(n);
        let shown = lines_of(n)
            .iter()
            .any(|line| line.0 == word && line.1 == says && line.2 == amber);
        shown.then_some(view)
    })
}

/// Wait until `n` has read the list at `commit`: its view.
fn has_read(all: &[&Node], n: &Node, commit: &str) -> Value {
    let what = format!("{} reads the list at {}", n.name, short(commit));
    wait_for(&what, all, 300, || {
        let view = view_of(n);
        (view["read"]["commit"] == commit).then_some(view)
    })
}

/// The labels of the members a view shows, in the list's order.
fn members_of(view: &Value) -> Vec<String> {
    view["members"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|member| member["label"].as_str().unwrap().to_string())
        .collect()
}

/// `cordelia status --json` on `n`.
fn status_json(n: &Node) -> Value {
    serde_json::from_str(&n.cli(&["status", "--json"])).unwrap()
}

/// What holds in a status, each by its word.
fn holds_of(status: &Value) -> Vec<String> {
    status["holds"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|holds| holds["what"].as_str().map(String::from))
        .collect()
}

// ── What a device keeps ──────────────────────────────────────────────

/// `n`'s database, read only.
fn store_of(n: &Node) -> rusqlite::Connection {
    let db = rusqlite::Connection::open_with_flags(
        n.data_dir().join("cordelia.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.busy_timeout(Duration::from_secs(10)).unwrap();
    db
}

/// A share `n` wrote: to which key, of which channel, when, whether a
/// delete was written over it since, and whether the node made it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ShareMade {
    key: String,
    channel: [u8; 32],
    made: i64,
    gone: bool,
    by_node: bool,
}

/// Every share `n` keeps, waiting or gone. A share written over is kept
/// for a day, so a test sees each share made while it runs.
fn shares_of(n: &Node) -> Vec<ShareMade> {
    let db = store_of(n);
    let mut rows = db
        .prepare("SELECT key, channel, made, gone, by_node FROM shared_shares ORDER BY made")
        .unwrap();
    rows.query_map([], |row| {
        let key: [u8; 32] = row.get(0)?;
        Ok(ShareMade {
            key: encode_public_key(&key).unwrap(),
            channel: row.get(1)?,
            made: row.get(2)?,
            gone: row.get(3)?,
            by_node: row.get(4)?,
        })
    })
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

/// Whether `n` ever handed the channel `channel` to `key`.
fn handed(n: &Node, key: &str, channel: &[u8; 32]) -> bool {
    shares_of(n)
        .iter()
        .any(|share| share.key == key && share.channel == *channel)
}

/// What became of the key `key` that `n`'s node typed for the repository,
/// where it typed it.
fn became_of_typed(n: &Node, key: &str) -> Option<Option<String>> {
    let key = decode_public_key(key).unwrap();
    let db = store_of(n);
    db.query_row(
        "SELECT became FROM shared_follow_typed WHERE identity = ?1 AND key = ?2",
        rusqlite::params![REPOSITORY, &key[..]],
        |row| row.get::<_, Option<String>>(0),
    )
    .ok()
}

/// The entries `relay` holds of `channel` by the author `key`.
fn at_the_relay_by(relay: &Node, channel: &[u8; 32], key: &str) -> usize {
    let key = decode_public_key(key).unwrap();
    let db = store_of(relay);
    db.query_row(
        "SELECT COUNT(*) FROM entries WHERE channel_id = ?1 AND author = ?2",
        rusqlite::params![&channel[..], &key[..]],
        |row| row.get::<_, i64>(0),
    )
    .unwrap() as usize
}

/// Wait until `relay` holds a share that `from` wrote for `to`'s key.
fn share_at_the_relay(all: &[&Node], relay: &Node, from: &Node, to: &str) {
    let identity = NodeIdentity::from_file(&from.data_dir().join("identity.key")).unwrap();
    let to_key = decode_public_key(to).unwrap();
    let (pair, _) = cordelia_api::shared_pass::share_pair(&identity, &to_key).unwrap();
    let what = format!("{}'s share for {to} is at the relay", from.name);
    wait_for(&what, all, 300, || {
        (at_the_relay_by(relay, &pair, &key_of(from)) > 0).then_some(())
    });
}

// ── Messages ─────────────────────────────────────────────────────────

/// A command of messages on `n`, run in `dir`, its input a pipe that
/// gives `input` and ends.
fn msg_in(n: &Node, dir: &Path, args: &[&str], input: &[u8]) -> std::process::Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut command = n.command_for(&[], &[&["msg"], args].concat());
    command
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(input);
    drop(stdin);
    child.wait_with_output().unwrap()
}

/// `msg send --channel <name>` on `n` in `dir`, saying `body`: tried again
/// while the device has not read the channel since it started.
fn sends_into(all: &[&Node], n: &Node, dir: &Path, name: &str, body: &str) {
    wait_for("the shared message is sent", all, 180, || {
        let said = msg_in(n, dir, &["send", "--channel", name], body.as_bytes());
        let err = String::from_utf8_lossy(&said.stderr).into_owned();
        match said.status.success() {
            true => Some(()),
            false if err.contains("has not yet read its own messages back") => None,
            false => panic!("{}: send --channel was refused: {err}", n.name),
        }
    });
}

/// `msg read --next-shared` on `n` in `dir`, until it reads a message:
/// what it printed.
fn reads_next(all: &[&Node], n: &Node, dir: &Path) -> String {
    wait_for("a shared message waits", all, 180, || {
        let said = msg_in(n, dir, &["read", "--next-shared"], b"");
        assert!(
            said.status.success(),
            "{}",
            String::from_utf8_lossy(&said.stderr)
        );
        let said = String::from_utf8_lossy(&said.stdout).into_owned();
        (!said.starts_with("Nothing waits")).then_some(said)
    })
}

// ── Making anew, moving and a removal ────────────────────────────────

/// The six words of the fingerprint of the key `key`.
fn six_words_of(key: &str) -> String {
    cordelia_crypto::fingerprint::words(&decode_public_key(key).unwrap(), 6)
}

/// `cordelia shared reset <name>` on `n`, at a terminal: each key it asks
/// about is answered as `answers` says of the key the question names;
/// then its yes. The new channel line it prints.
fn makes_anew(n: &Node, name: &str, answers: &[(&str, &str)]) -> String {
    let mut at = n.at_terminal(&["shared", "reset", name]);
    let questions: Vec<String> = answers
        .iter()
        .map(|(key, _)| format!("Does ({}) ", six_words_of(key)))
        .collect();
    let questions: Vec<&str> = questions.iter().map(String::as_str).collect();
    for _ in answers {
        let which = at.says_one_of(&questions);
        at.says("out for the rest: ").types(answers[which].1);
    }
    at.says("Type yes to go on").types("yes");
    at.says(&format!("Made \"{name}\" anew: it is channel "))
        .says(PUT_THE_LINE);
    let said = at.done();
    new_line_in(&said)
}

/// The new channel line that a making anew printed, after
/// [`PUT_THE_LINE`].
fn new_line_in(said: &str) -> String {
    let after = said.split(PUT_THE_LINE).nth(1).unwrap_or_default();
    after
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("channel "))
        .unwrap_or_else(|| panic!("no new channel line:\n{said}"))
        .to_string()
}

/// `cordelia shared move <name>` on `n`, at a terminal, with its yes,
/// once it has read the offer.
fn moves(all: &[&Node], n: &Node, name: &str) {
    wait_for("an offer to move to is read", all, 300, || {
        let (status, _) = n.post_told(
            "/api/v1/shared/move",
            &json!({ "name": name, "to": null, "look": true }),
        );
        (status == 200).then_some(())
    });
    let mut at = n.at_terminal(&["shared", "move", name]);
    at.says("These stay, each if its seal opens for it")
        .says("Type yes to go on")
        .types("yes");
    let said = at.done();
    assert!(
        said.contains(&format!("Moved \"{name}\" to channel ")),
        "{said}"
    );
}

/// `cordelia remove-device <key>` on `device`, a device that the change
/// before does not list, at a terminal: it lists this machine, asks
/// nothing else, and is given its yes and the phrase `words`. The
/// command, still running.
fn removes_from_an_added(device: &Node, key: &str, words: &str) -> AtTerminal {
    let mut at = device.at_terminal(&["remove-device", key]);
    at.says("Type `list` to list this machine").types("list");
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says(ASKS_THE_PHRASE).types(words);
    at
}

// ── The join itself ──────────────────────────────────────────────────

/// Two people, the whole join (rules 2 to 4, section 12): Bob runs
/// `subscribe --new` in his clone, and its lines are merged; then Alice's
/// line is merged, and Bob pulls. Bob's node hands the channel to Alice's
/// key at its read. Alice follows the repository from her clone: her
/// device reads the list only then, and at that one read takes the
/// channel, filed under the repository's `owner/name` as taken from Bob's
/// key, with the agent of her clone subscribed. Her agent sends a message
/// there, and Bob's agent reads it. Nobody runs `share` or `accept`: every
/// share is the node's, and no key was typed by hand. Bob's status shows
/// Alice's device new on the list, amber, by its label and the commit,
/// until he runs `cordelia shared seen` at a terminal (rules 4.5 and 7, as
/// the person ruled on 10 November). The list
/// came from each clone, and the status says how old the clone's copy is:
/// no command either node gave git reached the network. Last, `cordelia
/// unsubscribe` in Alice's clone stops her device following the
/// repository, and its channel and its agent's subscription stay; `cordelia
/// subscribe` there follows it again (rule 2.5), a new follow, which names
/// Bob's device, already on the list.
#[test]
fn two_people_join_by_a_merged_pull_request_alone() {
    let relay = relay_started();
    let host = Host::new();
    let bob = person("desktop", "bob-desktop", &relay, Some(MEMBER_READS));
    let alice = person("laptop", "alice-laptop", &relay, None);
    let all = [&relay, &alice, &bob];
    let alice_key = key_of(&alice);

    let bob_clone = host.clone_for(&bob);
    let (line, bobs) = makes_the_channel(&bob, &bob_clone);
    assert_eq!(bobs, line_for(&key_of(&bob), "bob-desktop"));
    host.merges(&format!("{line}\n{bobs}"));
    let merged = host.merges(&format!(
        "{line}\n{bobs}{}",
        line_for(&alice_key, "alice-laptop")
    ));
    assert_eq!(host.fetches(&bob, &bob_clone), merged);

    // Bob's node reads the merged list and hands the channel to Alice's
    // key: its share is at the relay. It lives for two of his reads, and
    // Alice follows the repository at once.
    let alice_clone = host.clone_for(&alice);
    share_at_the_relay(&all, &relay, &bob, &alice_key);
    assert!(channel_of(&alice, NAME).is_none());
    let made = channel_of(&bob, NAME).unwrap();
    let said = subscribes_in(&alice, &alice_clone, &[], "which you do not hold");
    assert!(
        said.contains(&format!(
            "Following {REPOSITORY}, from its list at commit {}",
            short(&merged)
        )),
        "{said}"
    );
    let taken = wait_for("Alice's node takes the channel", &all, 120, || {
        channel_of(&alice, NAME)
    });
    assert_eq!(taken["words"], made["words"]);
    let from = taken["came"]["taken_from"].as_str().unwrap();
    assert!(from.contains(&six_words_of(&key_of(&bob))), "{taken}");
    let said = listed(&alice);
    assert_eq!(
        said["subscriptions"],
        json!([{ "agent": AGENT, "channel": NAME }]),
        "{said}"
    );
    // Nobody typed a key or shared the channel by hand.
    for n in [&alice, &bob] {
        assert_eq!(listed(n)["typed"], json!([]), "{}", n.name);
        let shares = shares_of(n);
        assert!(shares.iter().all(|share| share.by_node), "{shares:?}");
    }

    // Alice's agent sends a message in the channel, and Bob's agent reads
    // it.
    sends_into(&all, &alice, &alice_clone, NAME, "The build is green.");
    let read = reads_next(&all, &bob, &bob_clone);
    assert!(read.contains("The build is green."), "{read}");

    // Bob's read of the merged list, his first with a channel line, named
    // Alice's device new on it, until he clears it at a terminal.
    let joined = format!(
        "New on the list of {NAME} at {}: alice-laptop",
        short(&merged)
    );
    shows(&all, &bob, "joined", &joined, true);
    let status = status_json(&bob);
    assert_eq!(status["level"], "amber", "{status}");
    assert!(
        holds_of(&status).contains(&"shared_repository".to_string()),
        "{status}"
    );
    let plain = bob.cli(&["status"]);
    assert!(
        plain.contains(&format!("  Following: {REPOSITORY}, for {NAME}")),
        "{plain}"
    );
    assert!(plain.contains(&format!("    ◆ {joined}")), "{plain}");
    assert!(
        plain.contains("Members: bob-desktop (in), alice-laptop (in)."),
        "{plain}"
    );
    // Something waits on the list, so its read says when the next read is
    // (#323 item 1).
    assert!(plain.contains(". Next read in "), "{plain}");
    let refused = bob.refused(&["shared", "seen", NAME]);
    assert!(
        refused.contains("Run cordelia shared seen in a terminal"),
        "{refused}"
    );
    assert!(holds_of(&status_json(&bob)).contains(&"shared_repository".to_string()));
    let said = bob.at_terminal(&["shared", "seen", NAME]).done();
    assert!(said.contains(&format!("Cleared: {joined}")), "{said}");
    let status = status_json(&bob);
    assert!(
        !holds_of(&status)
            .iter()
            .any(|what| what.starts_with("shared")),
        "{status}"
    );

    // From the clone only: the status says how old the clone's copy is,
    // from the person's last fetch, or that it is not known, as of a clone
    // that was never fetched since it was made. No git of either node
    // reached the network.
    let view = view_of(&bob);
    assert_eq!(view["read"]["from"], "clone", "{view}");
    // Nothing waits now: the plain status says the repository in one line
    // (issue #338), and the node's timer says when it reads the list next.
    assert_eq!(view["in_step"], true, "{view}");
    assert!(view["next_read"].is_string(), "{view}");
    let plain = bob.cli(&["status"]);
    assert!(
        plain.contains(&format!(
            "  Following: {REPOSITORY}, for {NAME}: 2 members, all in"
        )),
        "{plain}"
    );
    let says = view["read"]["says"].as_str().unwrap();
    assert!(
        says.starts_with(&format!(
            "List of {REPOSITORY} read from your clone, fetched "
        )),
        "{says}"
    );
    assert!(
        says.ends_with(&format!("at commit {}.", short(&merged))),
        "{says}"
    );
    let says = &view_of(&alice)["read"]["says"];
    assert!(
        says.as_str().unwrap().starts_with(&format!(
            "List of {REPOSITORY} read from your clone; your clone's last fetch is not known."
        )),
        "{says}"
    );
    for n in [&alice, &bob] {
        asked_git_nothing_of_the_network(n);
    }

    // `cordelia unsubscribe` with no name, in Alice's clone.
    let out = alice.command_in(&alice_clone, &["unsubscribe"]);
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{said}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(said, format!("This device follows {REPOSITORY} no more.\n"));
    assert_eq!(listed(&alice)["repositories"], json!([]));
    assert_eq!(id_filed(&alice, NAME), id_filed(&bob, NAME));
    assert_eq!(
        listed(&alice)["subscriptions"],
        json!([{ "agent": AGENT, "channel": NAME }])
    );
    // `subscribe` there follows it again: a new follow, whose list names
    // Bob's device new to it, and not hers.
    subscribes_in(&alice, &alice_clone, &[], "which you hold");
    assert_eq!(view_of(&alice)["identity"], REPOSITORY);
    let bobs = format!(
        "New on the list of {NAME} at {}: bob-desktop",
        short(&merged)
    );
    shows(&all, &alice, "joined", &bobs, true);
}

/// Order does not matter (section 12): Alice's line is merged before
/// anyone has made the channel, and she follows the repository, waiting,
/// and her status says that the list names no channel yet. Then Bob makes
/// the channel in his clone, and a pull request adds his lines. Alice's
/// clone has the merge before any member's: she waits for a member's
/// device, and says so (rule 6). Bob pulls, and she holds the channel. Her
/// first list with a channel line named Bob's device new on it, amber, and
/// not hers (rule 4.5, as the person ruled on 10 November).
#[test]
fn a_device_that_follows_before_the_channel_is_named_waits_and_says_why() {
    let relay = relay_started();
    let host = Host::new();
    let bob = person("desktop", "bob-desktop", &relay, Some(MEMBER_READS));
    let alice = person("laptop", "alice-laptop", &relay, Some(JOINER_READS));
    let all = [&relay, &alice, &bob];
    let alices = line_for(&key_of(&alice), "alice-laptop");

    host.merges(&alices);
    let alice_clone = host.clone_for(&alice);
    subscribes_in(&alice, &alice_clone, &[], "once the list names one");
    let no_channel = format!("The list of {REPOSITORY} names no channel yet.");
    shows(&all, &alice, "no_channel", &no_channel, false);

    let bob_clone = host.clone_for(&bob);
    let (line, bobs) = makes_the_channel(&bob, &bob_clone);
    let merged = host.merges(&format!("{line}\n{alices}{bobs}"));
    host.fetches(&alice, &alice_clone);
    let view = has_read(&all, &alice, &merged);
    let waiting = lines_of(&alice)
        .into_iter()
        .find(|line| line.0 == "waiting")
        .unwrap_or_else(|| panic!("{view}"));
    assert!(
        waiting.1.starts_with(&format!(
            "Waiting for a member's device to hand you {NAME}. Your list was read "
        )),
        "{waiting:?}"
    );
    assert!(
        waiting.1.ends_with(
            "A member's device hands it over once a member's clone has the merged list: a \
             member runs git pull there."
        ),
        "{waiting:?}"
    );
    assert!(channel_of(&alice, NAME).is_none());

    host.fetches(&bob, &bob_clone);
    let taken = wait_for("Alice's node takes the channel", &all, 300, || {
        channel_of(&alice, NAME)
    });
    assert_eq!(taken["words"], channel_of(&bob, NAME).unwrap()["words"]);
    let bobs = format!(
        "New on the list of {NAME} at {}: bob-desktop",
        short(&merged)
    );
    shows(&all, &alice, "joined", &bobs, true);
    let status = status_json(&alice);
    assert_eq!(status["level"], "amber", "{status}");
    assert!(
        holds_of(&status).contains(&"shared_repository".to_string()),
        "{status}"
    );
}

// ── Never back ───────────────────────────────────────────────────────

/// A read of the clone never goes back, across a restart too (rule 3):
/// once Bob's device has read the list at a commit, a clone whose copy of
/// the default branch is behind it, as after the host's history is written
/// again, gives no new list. The status says so, and the last list read
/// stands. The last commit read is kept: after a restart, a clone further
/// back still gives none. A merge after the last commit read is read.
#[test]
fn a_clone_behind_the_last_commit_read_gives_no_new_list_across_a_restart() {
    let relay = relay_started();
    let host = Host::new();
    let mut bob = person("desktop", "bob-desktop", &relay, Some(JOINER_READS));
    let all = [&relay, &bob];
    let before_any_list = host.at();
    let bob_clone = host.clone_for(&bob);
    let (line, bobs) = makes_the_channel(&bob, &bob_clone);
    let first = host.merges(&format!("{line}\n{bobs}"));
    let carols = line_for(&key_off(0xC0), "carol-laptop");
    let second = host.merges(&format!("{line}\n{bobs}{carols}"));
    host.fetches(&bob, &bob_clone);
    let view = has_read(&all, &bob, &second);
    assert_eq!(members_of(&view), ["bob-desktop", "carol-laptop"]);

    // The host's history goes back to the first commit, and Bob fetches.
    host.goes_back_to(&first);
    assert_eq!(host.fetches(&bob, &bob_clone), first);
    let behind = |at: &str| {
        format!(
            "Your clone of {REPOSITORY} is behind: your clone is at commit {}, which does not \
             come after commit {}, the last one read. The last list read stands. Run git pull \
             there; if its history was rewritten, run cordelia subscribe there again.",
            short(at),
            short(&second)
        )
    };
    let view = shows(&all, &bob, "behind", &behind(&first), false);
    assert_eq!(view["read"]["commit"], second.as_str());
    assert_eq!(members_of(&view), ["bob-desktop", "carol-laptop"]);

    // Bob's device is off while his clone goes further back; at its start
    // it reads the clone, and the last commit read is still the one it
    // goes by.
    bob.stop();
    host.goes_back_to(&before_any_list);
    assert_eq!(host.fetches(&bob, &bob_clone), before_any_list);
    starts(&mut bob, &relay);
    let all = [&relay, &bob];
    let view = shows(&all, &bob, "behind", &behind(&before_any_list), false);
    assert_eq!(view["read"]["commit"], second.as_str());
    assert_eq!(members_of(&view), ["bob-desktop", "carol-laptop"]);

    // A merge after the last commit read: the host's own branch goes on
    // from it.
    let daves = line_for(&key_off(0xD0), "dave-laptop");
    let third = host.merges(&format!("{line}\n{bobs}{carols}{daves}"));
    assert_eq!(host.fetches(&bob, &bob_clone), third);
    let view = has_read(&all, &bob, &third);
    assert_eq!(
        members_of(&view),
        ["bob-desktop", "carol-laptop", "dave-laptop"]
    );
    assert!(
        !lines_of(&bob).iter().any(|line| line.0 == "behind"),
        "{view}"
    );
}

// ── Who gets the channel ─────────────────────────────────────────────

/// Only the named channel, and only to keys on the list (rules 4.2 and
/// 4.4): Bob holds the repository's channel and another, `design`, which
/// he shares by hand to Alice's key. The list names Bob's and Alice's
/// devices and Dave's, which is off. Carol's and Erin's keys are on no
/// list the host holds: Carol's on a commit of Bob's own branch, which he
/// has not pushed, and both in his working tree. Bob's node hands the
/// channel the list names to Dave's key at its read, and passes over
/// Alice's while his own share of `design` waits for her. It hands Carol
/// and Erin nothing. Alice follows the repository: her node asks the
/// relay for a share from Bob's key, finds the one of `design`, and takes
/// nothing.
#[test]
fn only_the_named_channel_is_taken_and_only_keys_on_the_list_are_handed_it() {
    let relay = relay_started();
    let host = Host::new();
    let bob = person("desktop", "bob-desktop", &relay, Some(MEMBER_READS));
    let alice = person("laptop", "alice-laptop", &relay, Some(JOINER_READS));
    let all = [&relay, &alice, &bob];
    let (alice_key, bob_key) = (key_of(&alice), key_of(&bob));
    let (carol, dave, erin) = (key_off(0xC0), key_off(0xD0), key_off(0xE0));

    let bob_clone = host.clone_for(&bob);
    let (line, bobs) = makes_the_channel(&bob, &bob_clone);
    let channel = channel_of_line(&line);
    let mut at = bob.at_terminal(&["shared", "new", "design"]);
    at.says("Type yes to go on").types("yes");
    at.done();
    let design = id_filed(&bob, "design").unwrap();
    let mut at = bob.at_terminal(&["share", "design", &alice_key]);
    at.says("Type yes to go on").types("yes");
    at.done();
    share_at_the_relay(&all, &relay, &bob, &alice_key);

    let list = format!(
        "{line}\n{bobs}{}{}",
        line_for(&alice_key, "alice-laptop"),
        line_for(&dave, "dave-laptop")
    );
    let merged = host.merges(&list);
    host.fetches(&bob, &bob_clone);
    git(
        &bob,
        &bob_clone,
        &["checkout", "--quiet", "-B", "main", "origin/main"],
    );
    let members = bob_clone.join(".cordelia/members");
    std::fs::write(
        &members,
        format!("{list}{}", line_for(&carol, "carol-laptop")),
    )
    .unwrap();
    git(&bob, &bob_clone, &["commit", "--quiet", "-am", "carol"]);
    std::fs::write(
        &members,
        format!(
            "{list}{}{}",
            line_for(&carol, "carol-laptop"),
            line_for(&erin, "erin-laptop")
        ),
    )
    .unwrap();

    let shares = wait_for(
        "Bob's node hands the channel to Dave's key",
        &all,
        300,
        || {
            let shares = shares_of(&bob);
            handed(&bob, &dave, &channel).then_some(shares)
        },
    );
    assert_eq!(view_of(&bob)["read"]["commit"], merged.as_str());
    let to = |key: &str| -> Vec<(bool, bool)> {
        shares
            .iter()
            .filter(|share| share.key == key)
            .map(|share| (share.channel == channel, share.by_node))
            .collect()
    };
    assert_eq!(to(&dave), [(true, true)]);
    assert_eq!(
        to(&alice_key),
        [(false, false)],
        "the share of design alone"
    );
    assert!(shares.iter().any(|share| share.channel == design));
    assert!(to(&carol).is_empty() && to(&erin).is_empty(), "{shares:?}");

    let alice_clone = host.clone_for(&alice);
    subscribes_in(&alice, &alice_clone, &[], "which you do not hold");
    wait_for(
        "Alice's node asks for a share from Bob's key",
        &all,
        300,
        || (became_of_typed(&alice, &bob_key)? == Some("asked".into())).then_some(()),
    );
    let said = listed(&alice);
    assert_eq!(said["channels"], json!([]), "{said}");
    assert_eq!(said["typed"], json!([]), "{said}");
    assert!(
        lines_of(&alice).iter().any(|line| line.0 == "waiting"),
        "{said}"
    );
}

/// Turns (rule 4.2): nine new keys, with eight of them off. Bob's node
/// hands the channel to four at each read, in the list's order; each share
/// lives for two reads, and a key whose share goes waits out that read. So
/// the ninth, Alice's laptop, is handed it at the third read, as the shares
/// of the first four go, and takes it.
#[test]
fn nine_new_keys_with_eight_off_the_ninth_is_handed_the_channel_at_the_third_read() {
    let relay = relay_started();
    let host = Host::new();
    let bob = person("desktop", "bob-desktop", &relay, Some(MEMBER_READS));
    let alice = person("laptop", "alice-laptop", &relay, Some(JOINER_READS));
    let all = [&relay, &alice, &bob];
    let alice_key = key_of(&alice);
    let off: Vec<String> = (1..=8).map(key_off).collect();

    let bob_clone = host.clone_for(&bob);
    let (line, bobs) = makes_the_channel(&bob, &bob_clone);
    let channel = channel_of_line(&line);
    let mut list = format!("{line}\n{bobs}");
    for (n, key) in off.iter().enumerate() {
        list.push_str(&line_for(key, &format!("off-{}", n + 1)));
    }
    list.push_str(&line_for(&alice_key, "alice-laptop"));
    host.merges(&list);
    host.fetches(&bob, &bob_clone);
    let alice_clone = host.clone_for(&alice);
    subscribes_in(&alice, &alice_clone, &[], "which you do not hold");

    // What Bob's node keeps of its shares as it hands Alice's key the
    // channel: that read writes it all at once.
    let shares = wait_for(
        "Bob's node hands Alice's key the channel",
        &all,
        300,
        || {
            let shares = shares_of(&bob);
            shares
                .iter()
                .any(|share| share.key == alice_key)
                .then_some(shares)
        },
    );
    let of = |key: &str| {
        shares
            .iter()
            .find(|share| share.key == key && share.channel == channel)
            .unwrap_or_else(|| panic!("no share to {key}: {shares:?}"))
            .clone()
    };
    let (first, second, third) = (of(&off[0]).made, of(&off[4]).made, of(&alice_key).made);
    for key in &off[0..4] {
        let share = of(key);
        assert_eq!(share.made, first, "{shares:?}");
        assert!(share.gone, "the first four's shares went: {shares:?}");
    }
    for key in &off[4..8] {
        let share = of(key);
        assert_eq!(share.made, second, "{shares:?}");
        assert!(!share.gone, "{shares:?}");
    }
    assert!(shares.iter().all(|share| share.by_node), "{shares:?}");
    // Three reads of Bob's, one after another: the third is a whole read
    // after the first, at least.
    assert!(first < second && second < third, "{first} {second} {third}");
    assert!(third - first >= MEMBER_READS as i64, "{first} {third}");
    wait_for("Alice's node takes the channel", &all, 300, || {
        channel_of(&alice, NAME)
    });
}

// ── Leaving ──────────────────────────────────────────────────────────

/// Leaving, by hand (rules 1, 4.6, 4.7 and 5): Alice and Carol join Bob's
/// channel by the list. Bob makes it anew and leaves Carol out: it prints
/// the new channel line, Carol's key after `without`.
///
/// - **Before that line is merged, nobody hands anything over:** Alice's
///   device and Carol's have read Bob's offer, which leaves Carol out, and
///   Bob's has moved from the channel the list names, so Dave's key, merged
///   meanwhile, is handed nothing, by Carol's device either.
/// - **A key dropped by a merge shows amber** on each follower.
/// - **Once the new line is merged,** Alice moves, Bob's device hands the
///   new channel to Dave's key, and never to Carol's.
/// - **A list that names Carol both as a member and after `without` names
///   no channel** for Bob's and Alice's devices, which say so, amber, and
///   Carol's device takes nothing, and says why.
/// - **A pull request that adds Carol's line and takes her off `without`
///   lets her back in:** Bob's device shows amber that the line does not
///   say she was left out, and hands her the channel. Her device files the
///   channel she was left out of under the repository's name, and says so:
///   she renames it, and takes the new one. `shared seen` with her label
///   clears Bob's amber, and without it says how.
#[test]
fn leaving_by_hand_and_coming_back_by_a_pull_request() {
    let relay = relay_started();
    let host = Host::new();
    let bob = person("desktop", "bob-desktop", &relay, Some(MEMBER_READS));
    let alice = person("laptop", "alice-laptop", &relay, Some(JOINER_READS));
    let carol = person("tablet", "carol-tablet", &relay, Some(JOINER_READS));
    let all = [&relay, &alice, &bob, &carol];
    let (alice_key, carol_key) = (key_of(&alice), key_of(&carol));
    let dave = key_off(0xD0);
    let (alices, carols, daves) = (
        line_for(&alice_key, "alice-laptop"),
        line_for(&carol_key, "carol-tablet"),
        line_for(&dave, "dave-laptop"),
    );

    let bob_clone = host.clone_for(&bob);
    let (old_line, bobs) = makes_the_channel(&bob, &bob_clone);
    let old = channel_of_line(&old_line);
    host.merges(&format!("{old_line}\n{bobs}{alices}{carols}"));
    host.fetches(&bob, &bob_clone);
    let alice_clone = host.clone_for(&alice);
    let carol_clone = host.clone_for(&carol);
    for (n, clone) in [(&alice, &alice_clone), (&carol, &carol_clone)] {
        subscribes_in(n, clone, &[], "which you do not hold");
    }
    // Each device holds the other two's keys: each wrote in the channel as
    // it took it.
    wait_for("each holds the others' keys", &all, 300, || {
        let each = [&bob, &alice, &carol]
            .iter()
            .all(|n| channel_of(n, NAME).is_some_and(|channel| channel["keys"] == 2));
        each.then_some(())
    });

    // Bob makes the channel anew, leaving Carol out.
    let new_line = makes_anew(&bob, NAME, &[(&alice_key, "keep"), (&carol_key, "out")]);
    assert!(
        new_line.ends_with(&format!(" without 1 {carol_key}")),
        "{new_line}"
    );
    let new = channel_of_line(&new_line);
    assert_ne!(new, old);
    assert_eq!(id_filed(&bob, NAME), Some(new));
    let put = format!(
        "{NAME} was made anew here: put its new channel line in .cordelia/members, in a pull \
         request"
    );
    let view = shows(&all, &bob, "put_the_line", &put, true);
    let shown: Vec<&Value> = view["lines"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|line| line["word"] == "put_the_line")
        .collect();
    assert_eq!(shown[0]["line"], new_line.as_str());

    // Before the new line is merged: once Alice's device has read Bob's
    // offer, and Carol's has read it "without you", a merge adds Dave's
    // line, and nobody hands Dave anything, or anyone the new channel.
    let offer_read = format!(
        "{NAME} was made anew by bob-desktop: nothing is handed over until the list names the \
         new channel."
    );
    for n in [&alice, &carol] {
        shows(&all, n, "offer_read", &offer_read, false);
    }
    let with_dave = host.merges(&format!("{old_line}\n{bobs}{alices}{carols}{daves}"));
    for (n, clone) in [
        (&bob, &bob_clone),
        (&alice, &alice_clone),
        (&carol, &carol_clone),
    ] {
        host.fetches(n, clone);
        has_read(&all, n, &with_dave);
    }
    for n in [&bob, &alice, &carol] {
        let shares = shares_of(n);
        assert!(
            !shares
                .iter()
                .any(|share| share.key == dave || share.channel == new),
            "{}: {shares:?}",
            n.name
        );
    }

    // A merge drops Carol's line: each follower shows it, amber.
    host.merges(&format!("{old_line}\n{bobs}{alices}{daves}"));
    host.fetches(&bob, &bob_clone);
    host.fetches(&alice, &alice_clone);
    let no_longer = format!(
        "carol-tablet is no longer on the list of {NAME}: make it anew with cordelia shared \
         reset {NAME}"
    );
    for n in [&bob, &alice] {
        shows(&all, n, "no_longer_listed", &no_longer, true);
    }

    // The new channel line is merged. Alice moves to it, and Bob's device
    // hands it to Dave's key.
    let merged_new = host.merges(&format!("{new_line}\n{bobs}{alices}{daves}"));
    host.fetches(&bob, &bob_clone);
    host.fetches(&alice, &alice_clone);
    let move_to =
        format!("Run cordelia shared move {NAME}: the list names the channel it was made anew as.");
    shows(&all, &alice, "made_anew", &move_to, false);
    moves(&all, &alice, NAME);
    assert_eq!(id_filed(&alice, NAME), Some(new));
    wait_for(
        "Bob's node hands the new channel to Dave",
        &all,
        300,
        || handed(&bob, &dave, &new).then_some(()),
    );
    // Carol is no longer shown once the list names the channel made anew
    // without her; the changed line is, until it is seen.
    let changed = format!(
        "The list of {REPOSITORY} names a new channel for {NAME} at {}.",
        short(&merged_new)
    );
    shows(&all, &bob, "line_changed", &changed, true);
    let words: Vec<String> = lines_of(&bob).into_iter().map(|line| line.0).collect();
    assert!(
        !words.contains(&"no_longer_listed".to_string()) && !words.contains(&"put_the_line".into()),
        "{words:?}"
    );

    // A merge adds Carol's line back, while the channel line still names
    // her after `without`: the list names no channel.
    let gated = host.merges(&format!("{new_line}\n{bobs}{alices}{daves}{carols}"));
    for (n, clone) in [
        (&bob, &bob_clone),
        (&alice, &alice_clone),
        (&carol, &carol_clone),
    ] {
        host.fetches(n, clone);
    }
    let gate = format!(
        "carol-tablet is on the list of {NAME} but was left out of it: delete its line in a pull \
         request, or wait for that device to write in the channel"
    );
    for n in [&bob, &alice] {
        shows(&all, n, "left_out", &gate, true);
    }
    let left_out = format!(
        "The list of {REPOSITORY} at {} names channel {}, which no device of yours holds or can \
         move to.",
        short(&gated),
        view_of(&bob)["words"].as_str().unwrap()
    );
    shows(&all, &carol, "left_out_of_it", &left_out, true);
    for n in [&bob, &alice] {
        assert!(!handed(n, &carol_key, &new), "{}", n.name);
    }
    assert_ne!(id_filed(&carol, NAME), Some(new));

    // A pull request takes Carol off `without`, with her line in the list:
    // Bob's device says the line does not say she was left out, and hands
    // her the new channel.
    let without_none = new_line.replace(&format!(" without 1 {carol_key}"), " without 0");
    host.merges(&format!("{without_none}\n{bobs}{alices}{daves}{carols}"));
    for (n, clone) in [
        (&bob, &bob_clone),
        (&alice, &alice_clone),
        (&carol, &carol_clone),
    ] {
        host.fetches(n, clone);
    }
    let not_said = format!(
        "carol-tablet was left out of {NAME}, and its channel line does not say so: add it after \
         without, or delete its line"
    );
    shows(&all, &bob, "not_said", &not_said, true);
    let taken =
        format!("You file another channel as {NAME}: rename it with cordelia shared rename.");
    shows(&all, &carol, "name_taken", &taken, false);
    carol.cli(&["shared", "rename", NAME, "project-before"]);
    wait_for("Carol's node takes the new channel", &all, 300, || {
        (id_filed(&carol, NAME)? == new).then_some(())
    });
    assert!(handed(&bob, &carol_key, &new) || handed(&alice, &carol_key, &new));

    // `shared seen` alone leaves that amber, and says how to clear it.
    let said = bob.at_terminal(&["shared", "seen", NAME]).done();
    assert!(
        said.contains(&format!(
            "Still shown: {not_said}. If you brought it back on purpose, run cordelia shared \
             seen {NAME} carol-tablet."
        )),
        "{said}"
    );
    let said = bob
        .at_terminal(&["shared", "seen", NAME, "carol-tablet"])
        .done();
    assert!(said.contains(&format!("Cleared: {not_said}")), "{said}");
    assert!(
        !lines_of(&bob).iter().any(|line| line.0 == "not_said"),
        "{}",
        view_of(&bob)
    );
}

/// After a removal (rules 1 and 5, section 12): Alice's laptop, desktop
/// and tablet and Bob's desktop are on the list, and each follower holds
/// the channel. Bob's device and Alice's laptop are off when her desktop
/// removes the tablet: the removal makes the channel anew without it, and
/// prints the new channel line, the tablet after `without`. A pull request
/// puts that line in the list and leaves the tablet's line: the list names
/// no channel, and the desktop, the laptop once it is back on, and Bob's
/// device once he is back on and moves, each say so. Then a pull request
/// deletes the tablet's line and adds Dave's: the desktop and Bob's device
/// hand the new channel to Dave's key. No follower ever hands it to the
/// tablet, and the tablet holds no seed of it.
#[test]
fn a_removed_device_still_listed_is_never_handed_the_new_channel() {
    let relay = relay_started();
    let host = Host::new();
    let mut laptop = device("laptop", &relay, Some(MEMBER_READS));
    let words = makes_a_phrase(&laptop, "alice-laptop");
    sync_on(&laptop);
    let desktop = device("desktop", &relay, Some(MEMBER_READS));
    let tablet = device("tablet", &relay, None);
    let mut bob = person("bob", "bob-desktop", &relay, Some(JOINER_READS));
    let tablet_key = key_of(&tablet);
    {
        let all = [&relay, &laptop, &desktop, &tablet, &bob];
        for (device, label) in [(&desktop, "alice-desktop"), (&tablet, "alice-tablet")] {
            adds(&laptop, device, label);
            has_applied(device, 1, &all);
            sync_on(device);
        }
    }
    let bobs = line_for(&key_of(&bob), "bob-desktop");

    let laptop_clone = host.clone_for(&laptop);
    let (line, alices) = makes_the_channel(&laptop, &laptop_clone);
    assert_eq!(alices.lines().count(), 3, "{alices}");
    assert!(
        alices.contains(&line_for(&tablet_key, "alice-tablet")),
        "{alices}"
    );
    host.merges(&format!("{line}\n{alices}{bobs}"));
    host.fetches(&laptop, &laptop_clone);
    let bob_clone = host.clone_for(&bob);
    let desktop_clone = host.clone_for(&desktop);
    {
        let all = [&relay, &laptop, &desktop, &tablet, &bob];
        subscribes_in(&bob, &bob_clone, &[], "which you do not hold");
        wait_for("Bob's node takes the channel", &all, 300, || {
            channel_of(&bob, NAME)
        });
        wait_for("the desktop holds the channel", &all, 300, || {
            channel_of(&desktop, NAME)
        });
        subscribes_in(&desktop, &desktop_clone, &[], "which you hold");
        wait_for("the desktop holds every key", &all, 300, || {
            (channel_of(&desktop, NAME)?["keys"] == 3).then_some(())
        });
    }

    // Bob's device and Alice's laptop are off; her desktop removes the
    // tablet.
    bob.stop();
    laptop.stop();
    let on = [&relay, &desktop, &tablet];
    let mut at = removes_from_an_added(&desktop, &tablet_key, &words);
    at.says("The change is made (change 2)")
        .says("The wait has ended.")
        .says(&format!(
            "\"{NAME}\" is made anew without the device removed: it is channel "
        ))
        .says(PUT_THE_LINE)
        .says(&format!(" without 1 {tablet_key}"));
    let new_line = new_line_in(&at.said.clone());
    drop(at);
    let new = channel_of_line(&new_line);
    wait_for("the desktop holds the new channel", &on, 300, || {
        (id_filed(&desktop, NAME)? == new).then_some(())
    });

    // The new channel line is merged, and the tablet's line is not deleted.
    let gated = host.merges(&format!("{new_line}\n{alices}{bobs}"));
    let gate = format!(
        "alice-tablet is on the list of {NAME} but was left out of it: delete its line in a pull \
         request, or wait for that device to write in the channel"
    );
    host.fetches(&desktop, &desktop_clone);
    shows(&on, &desktop, "left_out", &gate, true);

    // The laptop comes back on, and reads the merged list.
    starts(&mut laptop, &relay);
    host.fetches(&laptop, &laptop_clone);
    let back = [&relay, &laptop, &desktop, &tablet];
    has_applied(&laptop, 2, &back);
    has_read(&back, &laptop, &gated);

    // Bob comes back on, and moves to the new channel.
    starts(&mut bob, &relay);
    let all = [&relay, &laptop, &desktop, &tablet, &bob];
    host.fetches(&bob, &bob_clone);
    let move_to =
        format!("Run cordelia shared move {NAME}: the list names the channel it was made anew as.");
    shows(&all, &bob, "made_anew", &move_to, false);
    moves(&all, &bob, NAME);
    shows(&all, &bob, "left_out", &gate, true);
    for n in [&laptop, &desktop, &bob] {
        let shares = shares_of(n);
        assert!(
            !shares.iter().any(|share| share.channel == new),
            "{}: {shares:?}",
            n.name
        );
    }

    // A pull request deletes the tablet's line and adds Dave's.
    let dave = key_off(0xD0);
    let without_tablet: String = alices
        .lines()
        .filter(|line| !line.starts_with(&tablet_key))
        .map(|line| format!("{line}\n"))
        .collect();
    let dropped = host.merges(&format!(
        "{new_line}\n{without_tablet}{bobs}{}",
        line_for(&dave, "dave-laptop")
    ));
    for (n, clone) in [
        (&laptop, &laptop_clone),
        (&desktop, &desktop_clone),
        (&bob, &bob_clone),
    ] {
        host.fetches(n, clone);
    }
    for n in [&desktop, &bob] {
        let what = format!("{} hands the new channel to Dave", n.name);
        wait_for(&what, &all, 300, || handed(n, &dave, &new).then_some(()));
    }
    has_read(&all, &laptop, &dropped);
    for n in [&laptop, &desktop, &bob] {
        assert!(!handed(n, &tablet_key, &new), "{}", n.name);
    }
    // The tablet holds no seed of the new channel.
    let held: i64 = store_of(&tablet)
        .query_row(
            "SELECT COUNT(*) FROM shared_channels WHERE channel = ?1",
            [&new[..]],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(held, 0);
}
