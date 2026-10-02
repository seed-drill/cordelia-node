//! The threat model, as tests.
//!
//! `docs/security/threat-model.md` lists what Cordelia defends against and
//! names the tests that prove each claim. The first test here keeps that
//! file and the tests in step: a claim marked as tested must name tests
//! that exist and run. The others are the claims that need real processes.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cordelia_network::messages::{ChannelDescriptor, Protocol, WireMessage};

use common::*;

// ── The table and the tests agree ────────────────────────────────────

const THREAT_MODEL: &str = "docs/security/threat-model.md";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

#[derive(Debug, PartialEq)]
enum State {
    /// Every part of the claim has a test.
    Tested,
    /// Some of it is tested; the issue builds the rest.
    PartlyTested(u32),
    /// Not built yet; the issue builds it.
    Planned(u32),
    /// We do not defend against this, and say so.
    NotDefended,
}

fn parse_state(cell: &str) -> Option<State> {
    let issue = |rest: &str| -> Option<u32> {
        rest.trim()
            .strip_prefix("(#")?
            .strip_suffix(')')?
            .parse()
            .ok()
    };
    match cell.trim() {
        "tested" => Some(State::Tested),
        "not defended" => Some(State::NotDefended),
        other => {
            if let Some(rest) = other.strip_prefix("partly tested") {
                issue(rest).map(State::PartlyTested)
            } else if let Some(rest) = other.strip_prefix("planned") {
                issue(rest).map(State::Planned)
            } else {
                None
            }
        }
    }
}

/// The rows of the table (`| T3 | ... | state |`) and the tests listed for
/// each threat (`### T3`, then `` - `path`: `test_name` `` lines).
type Rows = BTreeMap<String, State>;
type Tests = BTreeMap<String, Vec<(String, String)>>;

fn parse(text: &str) -> Result<(Rows, Tests), String> {
    let mut rows = Rows::new();
    let mut tests = Tests::new();
    let mut section: Option<String> = None;
    for (n, line) in text.lines().enumerate() {
        let n = n + 1;
        if let Some(rest) = line.strip_prefix("| T") {
            let cells: Vec<&str> = rest.trim_end_matches('|').split('|').collect();
            let id = format!("T{}", cells[0].trim());
            if !id[1..].chars().all(|c| c.is_ascii_digit()) || id.len() < 2 {
                return Err(format!("line {n}: {id:?} is not a threat number"));
            }
            let state = parse_state(cells[cells.len() - 1]).ok_or_else(|| {
                format!(
                    "line {n}: {id} has no state. Use `tested`, `partly tested (#issue)`, \
                     `planned (#issue)` or `not defended`"
                )
            })?;
            if rows.insert(id.clone(), state).is_some() {
                return Err(format!("line {n}: {id} appears twice"));
            }
        } else if let Some(rest) = line.strip_prefix("### ") {
            let id = rest.trim().to_string();
            section = id.starts_with('T').then_some(id);
        } else if line.starts_with("## ") {
            section = None;
        } else if let (Some(id), Some(rest)) = (&section, line.strip_prefix("- `")) {
            let (path, rest) = rest
                .split_once("`: `")
                .ok_or_else(|| format!("line {n}: expected - `path`: `test_name`"))?;
            let name = rest
                .strip_suffix('`')
                .ok_or_else(|| format!("line {n}: expected - `path`: `test_name`"))?;
            tests
                .entry(id.clone())
                .or_default()
                .push((path.to_string(), name.to_string()));
        }
    }
    Ok((rows, tests))
}

/// Whether `source` has a test function `name` that runs: declared with a
/// test attribute and not ignored.
fn runs_as_a_test(source: &str, name: &str) -> Result<(), String> {
    let lines: Vec<&str> = source.lines().collect();
    let decl = lines
        .iter()
        .position(|l| {
            let l = l.trim_start();
            ["fn ", "async fn ", "pub fn ", "pub async fn "]
                .iter()
                .any(|p| {
                    l.strip_prefix(p)
                        .is_some_and(|r| r.strip_prefix(name).is_some_and(|r| r.starts_with('(')))
                })
        })
        .ok_or("no such function")?;
    // The attributes directly above the declaration.
    let attrs: Vec<&str> = lines[..decl]
        .iter()
        .rev()
        .map(|l| l.trim())
        .take_while(|l| l.starts_with("#[") || l.starts_with("///") || l.starts_with("//"))
        .collect();
    if !attrs
        .iter()
        .any(|a| a.starts_with("#[test]") || a.contains("::test]") || a.contains("::test("))
    {
        return Err("it is not a test".into());
    }
    if attrs.iter().any(|a| a.starts_with("#[ignore")) {
        return Err("it is ignored, so CI does not run it".into());
    }
    Ok(())
}

/// Everything wrong with the threat model as written, given a way to read
/// a source file. Empty when the table and the tests agree.
fn problems(text: &str, read: impl Fn(&str) -> Option<String>) -> Vec<String> {
    let (rows, tests) = match parse(text) {
        Ok(parsed) => parsed,
        Err(e) => return vec![e],
    };
    let mut out = Vec::new();
    if rows.is_empty() {
        out.push("the table has no rows".into());
    }
    for (id, state) in &rows {
        let listed = tests.get(id).map_or(0, Vec::len);
        match state {
            State::Tested | State::PartlyTested(_) if listed == 0 => {
                out.push(format!("{id} is marked as tested and lists no test"))
            }
            State::NotDefended if listed > 0 => out.push(format!(
                "{id} is marked as not defended and lists tests; say what they prove in a row of its own"
            )),
            _ => {}
        }
    }
    for (id, listed) in &tests {
        if !rows.contains_key(id) {
            out.push(format!(
                "tests are listed for {id}, which is not in the table"
            ));
        }
        let mut seen = BTreeSet::new();
        for (path, name) in listed {
            if !seen.insert((path, name)) {
                out.push(format!("{id}: `{name}` is listed twice"));
            }
            match read(path) {
                None => out.push(format!("{id}: {path} does not exist")),
                Some(source) => {
                    if let Err(why) = runs_as_a_test(&source, name) {
                        out.push(format!("{id}: `{name}` in {path}: {why}"));
                    }
                }
            }
        }
    }
    out
}

/// The threat model names, for every claim it marks as tested, tests that
/// exist and that CI runs. A defence cannot lose its test unnoticed, and a
/// threat cannot be added without a decision about it.
#[test]
fn the_threat_model_names_tests_that_exist() {
    let root = workspace_root();
    let text = std::fs::read_to_string(root.join(THREAT_MODEL))
        .unwrap_or_else(|e| panic!("{THREAT_MODEL}: {e}"));
    let found = problems(&text, |path| std::fs::read_to_string(root.join(path)).ok());
    assert!(
        found.is_empty(),
        "{THREAT_MODEL} and the tests disagree:\n  {}",
        found.join("\n  ")
    );
}

/// The check itself catches what it is there to catch.
#[test]
fn the_check_catches_a_missing_ignored_or_unlisted_test() {
    let source = "\
#[test]
fn it_holds() {}

#[test]
#[ignore = \"slow\"]
fn it_is_skipped() {}

fn a_helper() {}

#[tokio::test]
async fn it_holds_async() {}
";
    let read = |path: &str| (path == "tests/x.rs").then(|| source.to_string());
    let check = |doc: &str| problems(doc, read);
    let doc = |state: &str, tests: &str| {
        format!("| # | Who | State |\n|---|---|---|\n| T1 | someone | {state} |\n\n### T1\n{tests}")
    };

    assert!(check(&doc("tested", "- `tests/x.rs`: `it_holds`\n")).is_empty());
    assert!(check(&doc("tested", "- `tests/x.rs`: `it_holds_async`\n")).is_empty());
    assert!(check(&doc("planned (#12)", "")).is_empty());
    assert!(check(&doc("partly tested (#12)", "- `tests/x.rs`: `it_holds`\n")).is_empty());
    assert!(check(&doc("not defended", "")).is_empty());

    let one = |doc: String, expected: &str| {
        let found = check(&doc);
        assert!(
            found.len() == 1 && found[0].contains(expected),
            "expected one problem containing {expected:?}, got {found:?}"
        );
    };
    one(doc("tested", ""), "lists no test");
    one(doc("partly tested (#12)", ""), "lists no test");
    one(
        doc("tested", "- `tests/x.rs`: `it_is_gone`\n"),
        "no such function",
    );
    one(
        doc("tested", "- `tests/x.rs`: `it_is_skipped`\n"),
        "ignored",
    );
    one(doc("tested", "- `tests/x.rs`: `a_helper`\n"), "not a test");
    one(
        doc("tested", "- `tests/y.rs`: `it_holds`\n"),
        "does not exist",
    );
    one(doc("done", "- `tests/x.rs`: `it_holds`\n"), "has no state");
    one(doc("planned", ""), "has no state");
    one(
        doc("not defended", "- `tests/x.rs`: `it_holds`\n"),
        "not defended and lists tests",
    );
    one(
        doc(
            "tested",
            "- `tests/x.rs`: `it_holds`\n- `tests/x.rs`: `it_holds`\n",
        ),
        "listed twice",
    );
    one(
        format!(
            "{}\n### T9\n- `tests/x.rs`: `it_holds`\n",
            doc("tested", "- `tests/x.rs`: `it_holds`\n")
        ),
        "T9, which is not in the table",
    );
    one(
        "| T1 | a | tested |\n| T1 | b | tested |\n".to_string(),
        "appears twice",
    );
}

// ── Claims that need real processes ──────────────────────────────────

/// Every file under `dir` that contains `needle`, as raw bytes: SQLite
/// keeps text as it was written, so this finds it in a database, in the
/// write-ahead log beside it, and in a log file alike.
fn files_containing(dir: &Path, needle: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path)
                && bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
            {
                found.push(path);
            }
        }
    }
    found
}

/// T1. A relay holds nothing it can read. Two devices pair through a relay
/// and exchange a named entry. Afterwards nothing the relay wrote to disk
/// (its database, the write-ahead log beside it, its own log) contains the
/// entry's name, its content, or the label one device gave the other. The
/// relay did carry the entry: the channel's ID is there.
#[test]
fn t01_a_relay_holds_nothing_it_can_read() {
    const NAME: &str = "t01-canary-name.md";
    const CONTENT: &str = "t01 canary content: prefers short answers";
    const LABEL: &str = "t01-canary-label";

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let mut a = node("a", "personal", Some(relay.p2p));
    let mut b = node("b", "personal", Some(relay.p2p));
    a.start();
    b.start();
    let all = [&relay, &a, &b];
    for n in [&a, &b] {
        wait_for("node healthy", &all, 30, || healthy(n));
        wait_for("connected to the relay", &all, 60, || has_hot_peer(n));
    }
    let personal = pair(&a, &b, LABEL, &all);

    a.post(
        "/api/v1/channels/publish",
        serde_json::json!({ "channel": personal, "key": NAME, "content": { "text": CONTENT } }),
    );
    // B reads it, so it went through the relay: the two devices have no
    // other path to each other.
    wait_for("b reads a's entry", &all, 90, || {
        let resp = b.post(
            "/api/v1/channels/entries",
            serde_json::json!({ "channel": personal }),
        );
        resp["entries"]
            .as_array()?
            .iter()
            .any(|e| e["key"] == NAME && e["content"]["text"] == CONTENT)
            .then_some(())
    });

    // Stop the relay as a service manager would, so everything it holds
    // is on disk.
    relay.stop();
    let dir = relay.dir.path();
    assert!(
        !files_containing(dir, &personal).is_empty(),
        "the relay carried the channel, so its ID should be on its disk"
    );
    for (what, needle) in [("name", NAME), ("content", CONTENT), ("label", LABEL)] {
        let found = files_containing(dir, needle);
        assert!(
            found.is_empty(),
            "the relay's disk holds an entry's {what} in {found:?}"
        );
    }
    // The same search does find them where they are allowed to be: on the
    // device that wrote them. So an empty result above means something.
    a.stop();
    assert!(
        !files_containing(a.dir.path(), LABEL).is_empty(),
        "the label should be on the device that gave it"
    );
}

/// A stand-in for a relay. It completes the handshake as a relay does, and
/// records what each node that connects does: the protocol of every stream
/// it opens, and what it says when announcing channels.
struct StandIn {
    port: u16,
    /// The stand-in's own key, as a device would be configured with it.
    key: String,
    told: Arc<Mutex<Vec<ChannelDescriptor>>>,
    streams: Arc<Mutex<Vec<Protocol>>>,
}

fn stand_in_relay() -> StandIn {
    use cordelia_network::{codec, connection, transport};

    let identity = Arc::new(cordelia_crypto::identity::NodeIdentity::generate().unwrap());
    let key = cordelia_crypto::bech32::encode_public_key(&identity.public_key()).unwrap();
    let endpoint = transport::create_endpoint(&identity, "127.0.0.1:0".parse().unwrap()).unwrap();
    let port = endpoint.local_addr().unwrap().port();
    let manager = connection::ConnectionManager::new(
        identity,
        endpoint.clone(),
        vec![],
        vec!["relay".into()],
        port,
    );
    let ctx = manager.connect_context();
    let told = Arc::new(Mutex::new(Vec::new()));
    let streams = Arc::new(Mutex::new(Vec::new()));

    let (record, opened) = (told.clone(), streams.clone());
    tokio::spawn(async move {
        let _manager = manager; // keeps the endpoint's context alive
        while let Some(incoming) = endpoint.accept().await {
            let (ctx, record, opened) = (ctx.clone(), record.clone(), opened.clone());
            tokio::spawn(async move {
                let Ok(outcome) = connection::inbound_accept(&ctx, incoming).await else {
                    return;
                };
                while let Ok((_send, mut recv)) = outcome.conn.accept_bi().await {
                    let (record, opened) = (record.clone(), opened.clone());
                    tokio::spawn(async move {
                        let Ok(protocol) = codec::read_protocol_byte(&mut recv).await else {
                            return;
                        };
                        opened.lock().unwrap().push(protocol);
                        if protocol != Protocol::ChannelAnnounce {
                            return;
                        }
                        while let Ok(WireMessage::ChannelJoined(joined)) =
                            codec::read_frame(&mut recv).await
                        {
                            record.lock().unwrap().push(joined.descriptor);
                        }
                    });
                }
            });
        }
    });
    StandIn {
        port,
        key,
        told,
        streams,
    }
}

/// T1. A device tells a relay a channel's ID and nothing else about it. A
/// real node, with its personal channel and a project mapped under a name,
/// connects to a stand-in relay that records every announcement. None
/// carries a name, a date, a key version or anything derived from a key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t01_a_device_tells_a_relay_only_a_channels_id() {
    const PROJECT: &str = "t01-canary-project-name";

    let relay = stand_in_relay();
    let told = relay.told.clone();
    let mut a = node("a", "personal", Some(relay.port));
    a.start();
    wait_for("node healthy", &[&a], 30, || healthy(&a));
    wait_for("connected to the relay", &[&a], 60, || has_hot_peer(&a));

    // Sync on, and one folder mapped under a name: the node now has its
    // personal channel and a channel for the project.
    let folder = a.home().join("notes");
    std::fs::create_dir_all(&folder).unwrap();
    let memory = claude_folder(&a.home(), &folder);
    std::fs::write(memory.join("idea.md"), "A thought.\n").unwrap();
    let claude_dir = a.home().join(".claude");
    a.cli(&["sync", "claude", "--dir", claude_dir.to_str().unwrap()]);
    a.cli(&["sync", "map", folder.to_str().unwrap(), PROJECT]);
    let channels = wait_for("the node has both channels", &[&a], 60, || {
        let ids = groups(&a);
        (ids.len() >= 2).then_some(ids)
    });

    // The relay hears of each of them.
    let heard = wait_for("the relay is told of both channels", &[&a], 60, || {
        let told = told.lock().unwrap().clone();
        channels
            .iter()
            .all(|id| told.iter().any(|d| &d.channel_id == id))
            .then_some(told)
    });

    for d in &heard {
        let what = format!("the announcement of {}", d.channel_id);
        assert_eq!(d.channel_name, None, "{what} carries a name");
        assert_eq!(d.created_at, "", "{what} says when the channel was made");
        assert_eq!(d.key_version, 0, "{what} carries a key version");
        assert!(
            d.psk_hash.iter().all(|b| *b == 0),
            "{what} carries something derived from the channel's key"
        );
        assert_eq!((d.access.as_str(), d.mode.as_str()), ("", ""), "{what}");
        // Whatever the fields are called, the name is nowhere in it.
        let bytes = serde_json::to_vec(d).unwrap();
        for needle in [PROJECT, "personal", "project:"] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "{what} contains {needle:?}"
            );
        }
        // It is still an announcement a relay accepts.
        cordelia_network::channel_announce::validate_descriptor(d).unwrap();
    }
}

/// T19. A device knows its relays by key. When another key answers at a
/// relay's address, the device refuses it, stays without that relay, and
/// says why. With the right key configured the same relay is accepted.
#[test]
fn t19_a_device_refuses_another_key_at_its_relays_address() {
    let mut real = node("real", "relay", None);
    let mut other = node("other", "relay", None);
    real.start();
    other.start();
    wait_for("relays healthy", &[&real, &other], 30, || {
        healthy(&real).and(healthy(&other))
    });
    let key_of = |n: &Node| n.cli(&["id"]).trim().to_string();
    let at_other = format!("127.0.0.1:{}", other.p2p);

    // This device was told that the relay at `other`'s address has `real`'s
    // key: what it would see if someone else answered for its relay's name.
    let mut fooled = node_with_relays(
        "fooled",
        "personal",
        &[(at_other.clone(), Some(key_of(&real)))],
    );
    fooled.start();
    let all = [&real, &other, &fooled];
    wait_for("node healthy", &all, 30, || healthy(&fooled));
    let relay = wait_for("the device refuses the key that answered", &all, 60, || {
        relays_of(&fooled)
            .into_iter()
            .find(|r| r["state"] == "wrong key")
    });
    assert_eq!(relay["host"], at_other.as_str(), "{relay}");
    assert!(
        relay["error"]
            .as_str()
            .unwrap()
            .contains("another key answered"),
        "{relay}"
    );
    assert!(
        has_hot_peer(&fooled).is_none(),
        "it must not use that relay"
    );
    let said = fooled.cli(&["peers"]);
    assert!(said.contains("No peers connected."), "{said}");
    assert!(said.contains("wrong key"), "{said}");

    // With the key that really is at that address, the relay is accepted.
    let mut told_right = node_with_relays("right", "personal", &[(at_other, Some(key_of(&other)))]);
    told_right.start();
    let all = [&real, &other, &told_right];
    wait_for("node healthy", &all, 30, || healthy(&told_right));
    wait_for("the device connects to its relay", &all, 60, || {
        has_hot_peer(&told_right)
    });
    wait_for("it reports the relay connected", &all, 30, || {
        (relays_of(&told_right)[0]["state"] == "connected").then_some(())
    });
}

/// T19. A device's network is the relays it was configured with. It does
/// not ask a relay for the addresses of other peers, so a relay cannot send
/// it anywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t19_a_device_asks_no_peer_for_addresses_to_dial() {
    let relay = stand_in_relay();
    let mut a = node_with_relays(
        "a",
        "personal",
        &[(format!("127.0.0.1:{}", relay.port), Some(relay.key.clone()))],
    );
    a.start();
    wait_for("node healthy", &[&a], 30, || healthy(&a));
    wait_for("connected to the relay", &[&a], 60, || has_hot_peer(&a));
    // The device is at work with this relay: it opens streams to it.
    wait_for("the device talks to the relay", &[&a], 60, || {
        (!relay.streams.lock().unwrap().is_empty()).then_some(())
    });

    // Long enough for several of the rounds in which it used to ask.
    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
    let opened = relay.streams.lock().unwrap().clone();
    assert!(
        !opened.contains(&Protocol::PeerSharing),
        "the device asked its relay for other peers' addresses: {opened:?}"
    );
}
