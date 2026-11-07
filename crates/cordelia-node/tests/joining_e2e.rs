//! Joining a repository's shared channel by pull request (decision
//! 2026-11-06 (joining)), run as a person runs it, at a terminal, against
//! devices that are real processes and a relay of the test's own on this
//! machine. Each device reads the list from a clone of the repository on
//! its disk, as the person's own git last fetched it: nothing is fetched
//! over a network.

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::*;
use cordelia_crypto::bech32::decode_public_key;
use cordelia_crypto::identity::NodeIdentity;

/// The repository of these tests, as each clone's `origin` names it.
const REPOSITORY: &str = "example.org/team/project";

/// The name its channel is filed under: its `owner/name`.
const NAME: &str = "team/project";

/// The agent of each person's clone of it.
const AGENT: &str = "project";

fn path(p: &Path) -> String {
    p.to_str().unwrap().to_string()
}

/// A person's one device, `name`, which knows `relay` by its key, follows
/// a phrase of its own and has sync on.
fn person(name: &'static str, relay: &Node) -> Node {
    let device = device_started_with_its_relays_key(name, relay);
    makes_a_phrase(&device, name);
    let out = device.cli(&[
        "sync",
        "claude",
        "--dir",
        &path(&device.home().join(".claude")),
    ]);
    assert!(out.starts_with("Sync turned on.\n"), "{out}");
    device
}

/// git, run in `dir` for `n`'s person with none of their settings, as
/// their own git would leave the clone.
fn git(n: &Node, dir: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", n.home())
        .env("XDG_CONFIG_HOME", n.home())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(["-c", "user.name=Test", "-c", "user.email=test@example.org"])
        .args(["-c", "commit.gpgsign=false"])
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

/// A clone of the repository under `n`'s home, with `list` as its list,
/// its folder mapped to [`AGENT`]. Its `origin` names the repository, and
/// its copy of the remote's default branch is the list's commit.
fn clone_of(n: &Node, list: &str) -> PathBuf {
    let top = n.home().join("project");
    std::fs::create_dir_all(top.join(".cordelia")).unwrap();
    let top = top.canonicalize().unwrap();
    git(n, &top, &["init", "--quiet"]);
    git(n, &top, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    let origin = format!("https://{REPOSITORY}");
    git(n, &top, &["remote", "add", "origin", &origin]);
    fetched(n, &top, list);
    n.cli(&["sync", "map", &path(&top), AGENT]);
    top
}

/// Commit `list` in the clone at `top`, and make it the remote's default
/// branch, as a pull of the merge leaves it.
fn fetched(n: &Node, top: &Path, list: &str) {
    std::fs::write(top.join(".cordelia/members"), list).unwrap();
    git(n, top, &["add", "-A"]);
    git(
        n,
        top,
        &["commit", "--quiet", "--allow-empty", "-m", "list"],
    );
    let commit = git(n, top, &["rev-parse", "HEAD"]);
    git(n, top, &["update-ref", "refs/remotes/origin/main", &commit]);
    let head = [
        "symbolic-ref",
        "refs/remotes/origin/HEAD",
        "refs/remotes/origin/main",
    ];
    git(n, top, &head);
}

/// `cordelia subscribe` with no name on `n`, in the clone at `top`, with
/// `extra` arguments, at a terminal: its yes, once it has said `asks`.
/// What it said.
fn subscribes_in(n: &Node, top: &Path, extra: &[&str], asks: &str) -> String {
    let args = [&["subscribe"], extra].concat();
    let mut at = n.at_terminal_given(&[("CLAUDE_PROJECT_DIR", &path(top))], &args);
    at.says(asks).says("Type yes to go on").types("yes");
    at.done()
}

/// The channel `name` as `n` lists it, where it does.
fn channel_of(n: &Node, name: &str) -> Option<serde_json::Value> {
    let listed = n.post("/api/v1/shared/list", serde_json::json!({}));
    listed["channels"]
        .as_array()?
        .iter()
        .find(|channel| channel["name"] == name)
        .cloned()
}

/// The entries `relay` holds of `channel` by the author `key`.
fn at_the_relay_by(relay: &Node, channel: &[u8; 32], key: &[u8; 32]) -> usize {
    let db = rusqlite::Connection::open_with_flags(
        relay.data_dir().join("cordelia.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.busy_timeout(Duration::from_secs(10)).unwrap();
    db.query_row(
        "SELECT COUNT(*) FROM entries WHERE channel_id = ?1 AND author = ?2",
        rusqlite::params![&channel[..], &key[..]],
        |row| row.get::<_, i64>(0),
    )
    .unwrap() as usize
}

/// A device on the list takes the channel with no one asked (rule 4.4).
/// Alice's laptop makes the repository's channel with `subscribe --new`,
/// and a merge puts its line, her laptop's and Bob's desktop's in the
/// list. Alice's node reads it and hands the channel to Bob's key. Bob
/// follows the repository from a clone of his own: at that one read, his
/// node types Alice's key, asks the relay for it, and takes the channel,
/// filed under the repository's `owner/name` as taken from Alice's key,
/// with the agent of his clone subscribed. Nobody runs `share` or
/// `accept`. Then Alice's status shows Bob's device joined, amber, by the
/// list's label and the commit, until she runs `cordelia shared seen` at
/// a terminal (rules 4.5 and 7); anywhere else it is refused.
#[test]
fn a_device_on_the_list_takes_the_channel_with_no_one_asked() {
    let relay = relay_started();
    let alice = person("laptop", &relay);
    let bob = person("desktop", &relay);
    let all = [&relay, &alice, &bob];
    let (alice_key, bob_key) = (key_of(&alice), key_of(&bob));

    let alice_clone = clone_of(&alice, "");
    let said = subscribes_in(&alice, &alice_clone, &["--new"], "to the new channel");
    let line = said
        .lines()
        .find(|line| line.starts_with("channel "))
        .unwrap_or_else(|| panic!("no channel line:\n{said}"));
    let list = format!("{line}\n{alice_key}   alice-laptop\n{bob_key}   bob-desktop\n");
    fetched(&alice, &alice_clone, &list);
    // Following again reads the merged list now, not in ten minutes.
    subscribes_in(&alice, &alice_clone, &[], "which you hold");
    let made = channel_of(&alice, NAME).unwrap();

    // Alice's node hands the channel to Bob's key: its share is at the
    // relay.
    let alice_id = NodeIdentity::from_file(&alice.data_dir().join("identity.key")).unwrap();
    let bob_pk = decode_public_key(&bob_key).unwrap();
    let alice_pk = decode_public_key(&alice_key).unwrap();
    let (pair, _) = cordelia_api::shared_pass::share_pair(&alice_id, &bob_pk).unwrap();
    wait_for("the share to Bob's key is at the relay", &all, 120, || {
        (at_the_relay_by(&relay, &pair, &alice_pk) > 0).then_some(())
    });
    assert!(channel_of(&bob, NAME).is_none());

    let bob_clone = clone_of(&bob, &list);
    let said = subscribes_in(&bob, &bob_clone, &[], "once this device takes it");
    assert!(
        said.contains(&format!("Following {REPOSITORY}, from its list at commit")),
        "{said}"
    );
    let taken = wait_for("Bob's node takes the channel", &all, 120, || {
        channel_of(&bob, NAME)
    });
    assert_eq!(taken["words"], made["words"]);
    let from = taken["came"]["taken_from"].as_str().unwrap();
    let words = cordelia_crypto::fingerprint::words(&alice_pk, 6);
    assert!(from.contains(&words), "{taken}");
    let listed = bob.post("/api/v1/shared/list", serde_json::json!({}));
    assert_eq!(
        listed["subscriptions"],
        serde_json::json!([{ "agent": AGENT, "channel": NAME }]),
        "{listed}"
    );
    assert_eq!(
        listed["typed"],
        serde_json::json!([]),
        "nothing was typed by hand"
    );

    // Bob's device writes in the channel as it takes it. Once Alice's
    // device holds what it wrote, her next read says it joined.
    wait_for("Alice's device holds Bob's entry", &all, 120, || {
        (channel_of(&alice, NAME)?["keys"] == 1).then_some(())
    });
    subscribes_in(&alice, &alice_clone, &[], "which you hold");
    let commit = git(&alice, &alice_clone, &["rev-parse", "HEAD"]);
    let joined = format!("bob-desktop joined {NAME} from the list at {commit}");
    let status = wait_for("Alice's status says Bob joined", &all, 120, || {
        let status = status_json(&alice);
        let says = status["shared"]["repositories"][0]["lines"]
            .as_array()?
            .iter()
            .any(|line| line["says"] == joined.as_str() && line["amber"] == true);
        says.then_some(status)
    });
    assert_eq!(status["level"], "amber", "{status}");
    assert!(
        holds_of(&status).contains(&"shared_repository".to_string()),
        "{status}"
    );
    let plain = alice.cli(&["status"]);
    assert!(
        plain.contains(&format!("  Following: {REPOSITORY}, for {NAME}")),
        "{plain}"
    );
    assert!(plain.contains(&format!("    To know: {joined}")), "{plain}");
    assert!(
        plain.contains("Members: alice-laptop (in), bob-desktop (in)."),
        "{plain}"
    );

    // Not at a terminal, nothing is cleared.
    let refused = alice.refused(&["shared", "seen", NAME]);
    assert!(
        refused.contains("Run cordelia shared seen in a terminal"),
        "{refused}"
    );
    assert!(
        status_json(&alice)["holds"]
            .to_string()
            .contains("shared_repository")
    );
    let said = alice.at_terminal(&["shared", "seen", NAME]).done();
    assert!(
        said.contains(&format!("Cleared 1 notice for {NAME} on this device.")),
        "{said}"
    );
    let status = status_json(&alice);
    assert!(
        !holds_of(&status)
            .iter()
            .any(|what| what.starts_with("shared")),
        "{status}"
    );
}

/// `cordelia status --json` on `n`.
fn status_json(n: &Node) -> serde_json::Value {
    serde_json::from_str(&n.cli(&["status", "--json"])).unwrap()
}

/// What holds in a status, each by its word.
fn holds_of(status: &serde_json::Value) -> Vec<String> {
    status["holds"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|holds| holds["what"].as_str().map(String::from))
        .collect()
}
