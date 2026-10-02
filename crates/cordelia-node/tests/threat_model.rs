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
/// it opens, what it says when announcing channels, and the items of each
/// push.
struct StandIn {
    port: u16,
    /// The stand-in's own key, as a device would be configured with it.
    key: String,
    told: Arc<Mutex<Vec<ChannelDescriptor>>>,
    streams: Arc<Mutex<Vec<Protocol>>>,
    /// The item IDs of each push, in the order the pushes arrived.
    pushes: Arc<Mutex<Vec<Vec<String>>>>,
}

/// How a stand-in answers its `n`th push (from 1), given the items in it.
type PushAnswer =
    Arc<dyn Fn(usize, &[String]) -> cordelia_network::messages::PushAck + Send + Sync>;

/// A stand-in relay that answers no push.
fn stand_in_relay() -> StandIn {
    stand_in(None)
}

fn stand_in(answer: Option<PushAnswer>) -> StandIn {
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
    let pushes = Arc::new(Mutex::new(Vec::new()));

    let (record, opened, pushed) = (told.clone(), streams.clone(), pushes.clone());
    tokio::spawn(async move {
        let _manager = manager; // keeps the endpoint's context alive
        while let Some(incoming) = endpoint.accept().await {
            let (ctx, record, opened) = (ctx.clone(), record.clone(), opened.clone());
            let (pushed, answer) = (pushed.clone(), answer.clone());
            tokio::spawn(async move {
                let Ok(outcome) = connection::inbound_accept(&ctx, incoming).await else {
                    return;
                };
                while let Ok((mut send, mut recv)) = outcome.conn.accept_bi().await {
                    let (record, opened) = (record.clone(), opened.clone());
                    let (pushed, answer) = (pushed.clone(), answer.clone());
                    tokio::spawn(async move {
                        let Ok(protocol) = codec::read_protocol_byte(&mut recv).await else {
                            return;
                        };
                        opened.lock().unwrap().push(protocol);
                        if protocol == Protocol::ItemPush {
                            let Some(answer) = answer else { return };
                            let Ok(WireMessage::PushPayload(payload)) =
                                codec::read_frame(&mut recv).await
                            else {
                                return;
                            };
                            let ids: Vec<String> =
                                payload.items.iter().map(|i| i.item_id.clone()).collect();
                            let n = {
                                let mut pushed = pushed.lock().unwrap();
                                pushed.push(ids.clone());
                                pushed.len()
                            };
                            let ack = WireMessage::PushAck(answer(n, &ids));
                            let _ = codec::write_frame(&mut send, &ack).await;
                            let _ = send.finish();
                            return;
                        }
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
        pushes,
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

/// T19. Being a relay is a property of configuration. A stranger that
/// connects to a relay and says it is a relay is treated as an ordinary
/// peer: the relay does not tell it which channels it holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t19_a_stranger_that_says_it_is_a_relay_is_not_treated_as_one() {
    use cordelia_network::{codec, connection, item_sync, transport};

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let relay_key = relay.cli(&["id"]).trim().to_string();
    let relay_addr = format!("127.0.0.1:{}", relay.p2p);

    // A device gives the relay something to hold.
    let mut a = node_with_relays("a", "personal", &[(relay_addr.clone(), Some(relay_key))]);
    a.start();
    let all = [&relay, &a];
    wait_for("node healthy", &all, 30, || healthy(&a));
    wait_for("connected to the relay", &all, 60, || has_hot_peer(&a));
    let folder = a.home().join("notes");
    std::fs::create_dir_all(&folder).unwrap();
    let memory = claude_folder(&a.home(), &folder);
    std::fs::write(memory.join("idea.md"), "A thought.\n").unwrap();
    a.cli(&[
        "sync",
        "claude",
        "--dir",
        a.home().join(".claude").to_str().unwrap(),
    ]);
    a.cli(&["sync", "map", folder.to_str().unwrap(), "t19-notes"]);
    wait_for("the relay holds the device's entries", &all, 90, || {
        let stats: serde_json::Value =
            serde_json::from_str(&relay.cli(&["stats", "--json"])).ok()?;
        (stats["items_stored"].as_u64()? > 0).then_some(())
    });

    // The stranger: its own key, and "relay" in its handshake.
    let identity = Arc::new(cordelia_crypto::identity::NodeIdentity::generate().unwrap());
    let stranger_key = cordelia_crypto::bech32::encode_public_key(&identity.public_key()).unwrap();
    let endpoint = transport::create_endpoint(&identity, "127.0.0.1:0".parse().unwrap()).unwrap();
    let port = endpoint.local_addr().unwrap().port();
    let mut manager =
        connection::ConnectionManager::new(identity, endpoint, vec![], vec!["relay".into()], port);
    let relay_id = manager
        .connect_to(relay_addr.parse().unwrap())
        .await
        .expect("the stranger connects, as any node may");
    let conn = manager.get_connection(&relay_id).unwrap().clone();

    // It asks which channels the relay holds, as one relay asks another.
    let listed = wait_for("the relay answers the stranger", &all, 30, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let (mut send, mut recv) = conn.open_bi().await.ok()?;
                codec::write_protocol_byte(&mut send, Protocol::ItemSync)
                    .await
                    .ok()?;
                item_sync::send_channel_list_request(&mut send, &mut recv)
                    .await
                    .ok()
            })
        })
    });
    assert!(
        listed.channel_ids.is_empty(),
        "the relay told a stranger which channels it holds: {:?}",
        listed.channel_ids
    );

    // And the relay does not count it as a relay.
    let seen = wait_for("the relay lists the stranger", &all, 30, || {
        let peers: serde_json::Value =
            serde_json::from_str(&relay.cli(&["peers", "--json"])).ok()?;
        peers["peers"]
            .as_array()?
            .iter()
            .find(|p| p["key"] == stranger_key.as_str())
            .cloned()
    });
    assert_eq!(seen["role"], "node", "{seen}");
}

/// The newest entry a stopped node holds in `channel`, as it would travel:
/// what anyone carrying it sees.
fn newest_entry_on_disk(n: &Node, channel: &str) -> cordelia_network::messages::Item {
    let db = rusqlite::Connection::open_with_flags(
        n.data_dir().join("cordelia.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.query_row(
        "SELECT item_id, item_type, encrypted_blob, content_hash, author_id, signature,
                key_version, published_at, slot, rev
         FROM items WHERE channel_id = ?1 AND slot IS NOT NULL ORDER BY seq DESC LIMIT 1",
        [channel],
        |row| {
            let blob: Vec<u8> = row.get(2)?;
            Ok(cordelia_network::messages::Item {
                item_id: row.get(0)?,
                channel_id: channel.to_string(),
                item_type: row.get(1)?,
                content_length: blob.len() as u32,
                encrypted_blob: blob,
                content_hash: row.get(3)?,
                author_id: row.get(4)?,
                signature: row.get(5)?,
                key_version: row.get(6)?,
                published_at: row.get(7)?,
                is_tombstone: false,
                parent_id: None,
                slot: row.get(8)?,
                rev: row.get::<_, Option<i64>>(9)?.map(|r| r as u64),
            })
        },
    )
    .unwrap()
}

/// T2. A stranger who knows a channel's ID and has seen one of its entries
/// in transit stores a copy of it at the relay before the entry itself
/// arrives: the same ciphertext, in the same slot, under the stranger's own
/// key and with the highest revision there is. The relay still stores the
/// entry, the channel's other device still reads it, and both devices go on
/// writing that name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t02_a_strangers_copy_at_a_relay_changes_nothing_for_a_channels_devices() {
    use cordelia_network::{connection, item_sync, transport};
    const NAME: &str = "t02-notes.md";

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let mut a = node("a", "personal", Some(relay.p2p));
    let mut b = node("b", "personal", Some(relay.p2p));
    a.start();
    b.start();
    for n in [&a, &b] {
        wait_for("node healthy", &[&relay, &a, &b], 30, || healthy(n));
        wait_for("connected to the relay", &[&relay, &a, &b], 60, || {
            has_hot_peer(n)
        });
    }
    let personal = pair(&a, &b, "b", &[&relay, &a, &b]);
    let entries_of = |n: &Node| {
        n.post(
            "/api/v1/channels/entries",
            serde_json::json!({ "channel": personal }),
        )["entries"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    };
    let reads = |n: &Node, text: &str| {
        entries_of(n)
            .iter()
            .any(|e| e["key"] == NAME && e["content"]["text"] == text)
            .then_some(())
    };

    // A writes an entry while the relay is away, so the entry waits on A.
    // A then stops, so that the stranger's copy gets to the relay first.
    relay.stop();
    a.post(
        "/api/v1/channels/publish",
        serde_json::json!({ "channel": personal, "key": NAME, "content": { "text": "one" } }),
    );
    a.stop();
    let entry = newest_entry_on_disk(&a, &personal);
    assert_eq!(entry.rev, Some(1));

    // The copy: the stranger's key and signature on the same ciphertext.
    let stranger = Arc::new(cordelia_crypto::identity::NodeIdentity::generate().unwrap());
    let slot: [u8; 32] = entry.slot.clone().unwrap().try_into().unwrap();
    let hash: [u8; 32] = entry.content_hash.clone().try_into().unwrap();
    let rev = cordelia_core::protocol::MAX_REV;
    let item_id = cordelia_storage::items::generate_item_id();
    let cbor = cordelia_crypto::signing::ItemMetadata {
        author_id: &stranger.public_key(),
        channel_id: &personal,
        content_hash: &hash,
        is_tombstone: false,
        item_id: &item_id,
        key_version: entry.key_version as i64,
        published_at: &entry.published_at,
        slot: Some(&slot),
        rev: Some(rev),
    }
    .encode()
    .unwrap();
    let copy_author = stranger.public_key();
    let copy = cordelia_network::messages::Item {
        item_id,
        author_id: stranger.public_key().to_vec(),
        signature: stranger.sign(&cbor).to_vec(),
        rev: Some(rev),
        ..entry.clone()
    };

    relay.start();
    wait_for("relay healthy again", &[&relay, &b], 30, || healthy(&relay));
    let endpoint = transport::create_endpoint(&stranger, "127.0.0.1:0".parse().unwrap()).unwrap();
    let port = endpoint.local_addr().unwrap().port();
    let mut manager = connection::ConnectionManager::new(
        stranger,
        endpoint,
        vec![],
        vec!["personal".into()],
        port,
    );
    let relay_id = manager
        .connect_to(format!("127.0.0.1:{}", relay.p2p).parse().unwrap())
        .await
        .expect("the stranger connects, as any node may");
    let conn = manager.get_connection(&relay_id).unwrap().clone();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let mut stream = tokio::io::join(&mut recv, &mut send);
    let ack = item_sync::send_push(&mut stream, &[copy]).await.unwrap();
    assert_eq!(
        ack.stored, 1,
        "the copy has to be at the relay first, or this proves nothing: {ack:?}"
    );

    // A comes back and sends the entry itself. B reads it, so the relay
    // stored it beside the copy and passed it on.
    a.start();
    let all = [&relay, &a, &b];
    wait_for("a healthy again", &all, 30, || healthy(&a));
    wait_for("b reads a's entry", &all, 120, || reads(&b, "one"));

    // The name is not out of reach: B writes it again as the next revision,
    // and A reads that.
    let published = b.post(
        "/api/v1/channels/publish",
        serde_json::json!({ "channel": personal, "key": NAME, "content": { "text": "two" } }),
    );
    assert_eq!(published["rev"], 2, "{published}");
    wait_for("a reads b's edit", &all, 120, || reads(&a, "two"));

    // The relay holds the stranger's copy: it cannot tell a channel's
    // members from anyone else. The devices do not: a device stores only
    // what members of its channels wrote.
    let stranger_key = copy_author;
    let held_by = |n: &mut Node| -> i64 {
        n.stop();
        let db = rusqlite::Connection::open_with_flags(
            n.data_dir().join("cordelia.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        db.query_row(
            "SELECT COUNT(*) FROM items WHERE author_id = ?1",
            [stranger_key.as_slice()],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert_eq!(held_by(&mut relay), 1, "the copy never reached the relay");
    assert_eq!(held_by(&mut a), 0, "a stored what a stranger wrote");
    assert_eq!(held_by(&mut b), 0, "b stored what a stranger wrote");
}

/// T16. A device is removed. What it last wrote is still in the channel
/// for the device that removed it and for one added afterwards: a file it
/// edited keeps its edit, a file it created is there, and a file it deleted
/// stays deleted. What it writes after its removal reaches nobody, and the
/// names it wrote stay writable.
#[test]
fn t16_a_removed_devices_last_entries_are_kept_and_its_later_ones_are_not() {
    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let mut a = node("a", "personal", Some(relay.p2p));
    let mut r = node("r", "personal", Some(relay.p2p));
    let mut d = node("d", "personal", Some(relay.p2p));
    for n in [&mut a, &mut r, &mut d] {
        n.start();
    }
    let all = [&relay, &a, &r, &d];
    for n in [&a, &r, &d] {
        wait_for("node healthy", &all, 30, || healthy(n));
        wait_for("connected to the relay", &all, 60, || has_hot_peer(n));
    }
    let personal = pair(&a, &r, "r", &all);

    let publish = |n: &Node, key: &str, text: &str| {
        n.post(
            "/api/v1/channels/publish",
            serde_json::json!({ "channel": personal, "key": key, "content": { "text": text } }),
        )
    };
    // What a node reads for each name: its text, or `None` once deleted.
    let reads = |n: &Node| -> BTreeMap<String, Option<String>> {
        n.post(
            "/api/v1/channels/entries",
            serde_json::json!({ "channel": personal }),
        )["entries"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| {
                let text = e["content"]["text"].as_str().map(String::from);
                Some((e["key"].as_str()?.to_string(), text))
            })
            .collect()
    };
    let text = |s: &str| Some(s.to_string());
    let held: BTreeMap<String, Option<String>> = [
        ("created.md".to_string(), text("by r")),
        ("deleted.md".to_string(), None),
        ("edited.md".to_string(), text("by r")),
    ]
    .into();

    // A writes two files. R edits one, deletes the other and creates a third.
    publish(&a, "edited.md", "by a");
    publish(&a, "deleted.md", "by a");
    wait_for("r reads a's files", &all, 90, || {
        (reads(&r).len() == 2).then_some(())
    });
    publish(&r, "edited.md", "by r");
    r.post(
        "/api/v1/channels/delete-key",
        serde_json::json!({ "channel": personal, "key": "deleted.md" }),
    );
    publish(&r, "created.md", "by r");
    wait_for("a reads what r wrote", &all, 90, || {
        (reads(&a) == held).then_some(())
    });

    // A removes R. R is not told, and writes on.
    let r_key = r.cli(&["id"]).trim().to_string();
    a.cli(&["remove-device", &r_key]);
    assert_eq!(reads(&a), held, "removing r changed what the channel holds");
    publish(&r, "edited.md", "after removal");
    publish(&r, "created.md", "after removal");

    // A device added afterwards gets what the channel held.
    pair(&a, &d, "d", &all);
    wait_for(
        "the new device reads what the channel held",
        &all,
        120,
        || (reads(&d) == held).then_some(()),
    );
    // Long enough for what R wrote afterwards to have reached both: it is
    // at the relay, and they fetch from it every ten seconds.
    std::thread::sleep(std::time::Duration::from_secs(25));
    assert_eq!(reads(&a), held, "a shows what r wrote after its removal");
    assert_eq!(reads(&d), held, "d shows what r wrote after its removal");

    // The names stay writable, at the next revision: what R stored after
    // its removal does not count on the device that knew it either.
    let published = publish(&a, "edited.md", "by a again");
    assert_eq!(published["rev"], 3, "{published}");
    wait_for("d reads a's edit", &all, 90, || {
        (reads(&d).get("edited.md") == Some(&text("by a again"))).then_some(())
    });
}

/// T16. A relay's refusal is not delivery. A device's relay refuses an item:
/// first as a relay from before 0.2.0-alpha.4 does, with a count and no
/// list; then with the list. Each time the item stays in the device's
/// outbox and is offered again. Only when the relay stores it does the
/// outbox empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t16_a_relays_refusal_is_not_taken_for_delivery() {
    use cordelia_network::messages::{PushAck, REFUSED_STORAGE, Refusal};

    let relay = stand_in(Some(Arc::new(|n, ids: &[String]| match n {
        1 => PushAck {
            verification_failed: ids.len() as u32,
            ..Default::default()
        },
        2 => PushAck {
            verification_failed: ids.len() as u32,
            refused: ids
                .iter()
                .map(|id| Refusal {
                    item_id: id.clone(),
                    why: REFUSED_STORAGE.into(),
                })
                .collect(),
            ..Default::default()
        },
        _ => PushAck {
            stored: ids.len() as u32,
            ..Default::default()
        },
    })));
    let pushes = relay.pushes.clone();
    let mut a = node_with_relays(
        "a",
        "personal",
        &[(format!("127.0.0.1:{}", relay.port), Some(relay.key.clone()))],
    );
    a.start();
    wait_for("node healthy", &[&a], 30, || healthy(&a));
    wait_for("connected to the relay", &[&a], 60, || has_hot_peer(&a));
    let status = |n: &Node| n.get("/api/v1/status").unwrap_or_default();

    // Adding a device writes one item for the relay: the offer to it.
    let other = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
    let other = cordelia_crypto::bech32::encode_public_key(&other.public_key()).unwrap();
    a.cli(&["add-device", &other]);

    // Refused twice: the item is still waiting, and status says a relay
    // refused it and why.
    let refused = wait_for("status shows the refusal", &[&a], 60, || {
        let s = status(&a);
        let refused = s["outbox_refused"].as_array()?.first()?.clone();
        (s["outbox_waiting"].as_u64()? >= 1).then_some(refused)
    });
    assert_eq!(refused["why"], REFUSED_STORAGE, "{refused}");
    let item = refused["item_id"].as_str().unwrap().to_string();
    {
        let pushes = pushes.lock().unwrap();
        assert!(pushes.len() >= 2, "{pushes:?}");
        assert!(
            pushes[0].contains(&item) && pushes[1].contains(&item),
            "{pushes:?}"
        );
    }

    // Offered a third time and stored: nothing waits any more.
    wait_for(
        "the outbox empties once the relay stores it",
        &[&a],
        60,
        || {
            let s = status(&a);
            (s["outbox_waiting"] == 0 && s["outbox_refused"].as_array()?.is_empty()).then_some(())
        },
    );
    let pushes = pushes.lock().unwrap();
    assert!(
        pushes.iter().filter(|ids| ids.contains(&item)).count() >= 3,
        "{pushes:?}"
    );
}

/// T16. A removal reaches the devices that remain even when the relay loses
/// it. One device is away while another removes a third, and the relay then
/// loses everything it held. The device that removed goes on offering the
/// change, the one that was away applies it when it is back, and answers;
/// until then `cordelia devices` on the remover shows it as not confirmed.
#[test]
fn t16_a_removal_is_offered_again_when_the_relay_loses_it() {
    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let mut a = node("a", "personal", Some(relay.p2p));
    let mut b = node("b", "personal", Some(relay.p2p));
    let mut r = node("r", "personal", Some(relay.p2p));
    for n in [&mut a, &mut b, &mut r] {
        n.start();
    }
    for n in [&a, &b, &r] {
        wait_for("node healthy", &[&relay, &a, &b, &r], 30, || healthy(n));
        wait_for("connected to the relay", &[&relay, &a, &b, &r], 60, || {
            has_hot_peer(n)
        });
    }
    let key_of = |n: &Node| n.cli(&["id"]).trim().to_string();
    let (b_key, r_key) = (key_of(&b), key_of(&r));
    // The devices a node lists, by key.
    let devices = |n: &Node| -> BTreeMap<String, serde_json::Value> {
        n.post("/api/v1/devices/list", serde_json::json!({}))["devices"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| Some((d["key"].as_str()?.to_string(), d.clone())))
            .collect()
    };
    let status = |n: &Node| n.get("/api/v1/status").unwrap_or_default();

    pair(&a, &b, "b", &[&relay, &a, &b, &r]);
    pair(&a, &r, "r", &[&relay, &a, &b, &r]);
    wait_for("b knows r as a device", &[&relay, &a, &b, &r], 90, || {
        devices(&b).get(&r_key)?["in_personal_channel"]
            .as_bool()?
            .then_some(())
    });
    wait_for(
        "b and r have confirmed to a",
        &[&relay, &a, &b, &r],
        90,
        || {
            let listed = devices(&a);
            [&b_key, &r_key]
                .iter()
                .all(|key| listed[*key]["unconfirmed_since"].is_null())
                .then_some(())
        },
    );

    // B goes away. A removes R, and the relay has it.
    b.stop();
    a.cli(&["remove-device", &r_key]);
    wait_for("the removal reached the relay", &[&relay, &a], 60, || {
        (status(&a)["outbox_waiting"] == 0).then_some(())
    });
    // The relay loses everything it held.
    relay.stop();
    for file in ["cordelia.db", "cordelia.db-wal", "cordelia.db-shm"] {
        let _ = std::fs::remove_file(relay.data_dir().join(file));
    }
    relay.start();
    wait_for("relay healthy again", &[&relay, &a], 30, || healthy(&relay));

    // B is back, and has not heard: it still counts R as a device. A shows
    // that B has not confirmed.
    b.start();
    let all = [&relay, &a, &b, &r];
    wait_for("b healthy again", &all, 30, || healthy(&b));
    assert!(devices(&b).contains_key(&r_key), "b heard of the removal");
    assert!(
        devices(&a)[&b_key]["unconfirmed_since"].is_string(),
        "a does not show b as waiting: {:?}",
        devices(&a)
    );

    // A offers the removal again. B applies it and answers.
    wait_for("b drops r", &all, 240, || {
        (!devices(&b).contains_key(&r_key)).then_some(())
    });
    wait_for("a hears that b holds it", &all, 120, || {
        devices(&a)[&b_key]["unconfirmed_since"]
            .is_null()
            .then_some(())
    });
}

/// T3. A relay refuses an entry over the size limit. A client pushes two
/// entries, one of the largest size there is and one a byte larger. The
/// relay stores the first, refuses the second, and says which and why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_a_relay_refuses_an_entry_over_the_size_limit() {
    use cordelia_core::protocol::MAX_ITEM_BYTES;
    use cordelia_network::messages::{Item, REFUSED_TOO_LARGE};
    use cordelia_network::{connection, item_sync, transport};

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));

    let client = Arc::new(cordelia_crypto::identity::NodeIdentity::generate().unwrap());
    let channel = "grp_550e8400-e29b-41d4-a716-446655440000";
    let entry = |bytes: usize| -> Item {
        let blob = vec![7u8; bytes];
        let hash = cordelia_crypto::sha256(&blob);
        let item_id = cordelia_storage::items::generate_item_id();
        let published_at = "2026-10-02T00:00:00Z";
        let cbor = cordelia_crypto::signing::build_item_metadata_envelope(
            &client.public_key(),
            channel,
            &hash,
            false,
            &item_id,
            1,
            published_at,
        )
        .unwrap();
        Item {
            item_id,
            channel_id: channel.into(),
            item_type: "memory".into(),
            content_length: blob.len() as u32,
            encrypted_blob: blob,
            content_hash: hash.to_vec(),
            author_id: client.public_key().to_vec(),
            signature: client.sign(&cbor).to_vec(),
            key_version: 1,
            published_at: published_at.into(),
            is_tombstone: false,
            parent_id: None,
            slot: None,
            rev: None,
        }
    };
    let (largest, over) = (entry(MAX_ITEM_BYTES), entry(MAX_ITEM_BYTES + 1));

    let endpoint = transport::create_endpoint(&client, "127.0.0.1:0".parse().unwrap()).unwrap();
    let port = endpoint.local_addr().unwrap().port();
    let mut manager = connection::ConnectionManager::new(
        client.clone(),
        endpoint,
        vec![],
        vec!["personal".into()],
        port,
    );
    let relay_id = manager
        .connect_to(format!("127.0.0.1:{}", relay.p2p).parse().unwrap())
        .await
        .expect("the client connects");
    let conn = manager.get_connection(&relay_id).unwrap().clone();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let mut stream = tokio::io::join(&mut recv, &mut send);
    let ack = item_sync::send_push(&mut stream, &[largest.clone(), over.clone()])
        .await
        .unwrap();

    assert_eq!(ack.stored, 1, "{ack:?}");
    assert_eq!(ack.refused.len(), 1, "{ack:?}");
    assert_eq!(ack.refused[0].item_id, over.item_id, "{ack:?}");
    assert_eq!(ack.refused[0].why, REFUSED_TOO_LARGE, "{ack:?}");
    let stats: serde_json::Value = serde_json::from_str(&relay.cli(&["stats", "--json"])).unwrap();
    assert_eq!(stats["items_stored"], 1, "{stats}");
}

/// A client of a relay that is not a node: it connects as any node may, and
/// pushes whatever the test gives it.
struct Client {
    identity: Arc<cordelia_crypto::identity::NodeIdentity>,
    conn: quinn::Connection,
    _manager: cordelia_network::connection::ConnectionManager,
}

/// Connect a new client, with a key of its own, to `relay`.
async fn client_of(relay: &Node) -> Result<Client, String> {
    use cordelia_network::{connection, transport};
    let identity = Arc::new(cordelia_crypto::identity::NodeIdentity::generate().unwrap());
    let endpoint = transport::create_endpoint(&identity, "127.0.0.1:0".parse().unwrap()).unwrap();
    let port = endpoint.local_addr().unwrap().port();
    let mut manager = connection::ConnectionManager::new(
        identity.clone(),
        endpoint,
        vec![],
        vec!["personal".into()],
        port,
    );
    let relay_id = manager
        .connect_to(format!("127.0.0.1:{}", relay.p2p).parse().unwrap())
        .await
        .map_err(|e| e.to_string())?;
    let conn = manager.get_connection(&relay_id).unwrap().clone();
    Ok(Client {
        identity,
        conn,
        _manager: manager,
    })
}

impl Client {
    /// An entry of `bytes` bytes, signed by this client, as it travels.
    fn entry(&self, bytes: usize) -> cordelia_network::messages::Item {
        let channel = "grp_550e8400-e29b-41d4-a716-446655440000";
        let item_id = cordelia_storage::items::generate_item_id();
        // Distinct content for each entry.
        let mut blob = vec![7u8; bytes];
        let tag = item_id.as_bytes();
        blob[..tag.len().min(bytes)].copy_from_slice(&tag[..tag.len().min(bytes)]);
        let hash = cordelia_crypto::sha256(&blob);
        let published_at = "2026-10-02T00:00:00Z";
        let cbor = cordelia_crypto::signing::build_item_metadata_envelope(
            &self.identity.public_key(),
            channel,
            &hash,
            false,
            &item_id,
            1,
            published_at,
        )
        .unwrap();
        cordelia_network::messages::Item {
            item_id,
            channel_id: channel.into(),
            item_type: "memory".into(),
            content_length: blob.len() as u32,
            encrypted_blob: blob,
            content_hash: hash.to_vec(),
            author_id: self.identity.public_key().to_vec(),
            signature: self.identity.sign(&cbor).to_vec(),
            key_version: 1,
            published_at: published_at.into(),
            is_tombstone: false,
            parent_id: None,
            slot: None,
            rev: None,
        }
    }

    /// Push `items` in one push. `Err` if the relay did not answer it.
    async fn push(
        &self,
        items: &[cordelia_network::messages::Item],
    ) -> Result<cordelia_network::messages::PushAck, String> {
        let (mut send, mut recv) = self.conn.open_bi().await.map_err(|e| e.to_string())?;
        let mut stream = tokio::io::join(&mut recv, &mut send);
        cordelia_network::item_sync::send_push(&mut stream, items)
            .await
            .map_err(|e| e.to_string())
    }
}

/// T3. A peer that keeps going over its rate is cut off, and its address is
/// refused for a time. A client pushes as fast as it can: what is within
/// the rate is stored, the next pushes are refused at once, and at the
/// third the relay closes the connection. The client cannot come back,
/// under the same key or a new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_a_peer_over_its_rate_is_cut_off_and_refused_for_a_time() {
    use cordelia_core::protocol::{BAN_THRESHOLD, ERR_RATE_LIMIT, WRITES_PER_PEER_PER_MINUTE};

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let client = client_of(&relay).await.expect("the client connects");

    let mut stored = 0;
    let mut refused = 0;
    for _ in 0..WRITES_PER_PEER_PER_MINUTE + BAN_THRESHOLD {
        match client.push(&[client.entry(64)]).await {
            Ok(ack) => stored += ack.stored,
            Err(_) => refused += 1,
        }
    }
    assert_eq!(
        stored, WRITES_PER_PEER_PER_MINUTE,
        "what is within the rate is stored"
    );
    assert_eq!(refused, BAN_THRESHOLD, "the rest is refused");

    // The relay closed the connection, and says why.
    let closed = tokio::time::timeout(std::time::Duration::from_secs(10), client.conn.closed())
        .await
        .expect("the relay did not close the connection");
    match closed {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(
                close.error_code,
                quinn::VarInt::from_u32(ERR_RATE_LIMIT),
                "{close:?}"
            );
        }
        other => panic!("closed for another reason: {other:?}"),
    }
    // It is not let back in: not under a new key either, since it is the
    // address that is refused.
    assert!(
        client_of(&relay).await.is_err(),
        "the address was let back in"
    );
    let stats: serde_json::Value = serde_json::from_str(&relay.cli(&["stats", "--json"])).unwrap();
    assert_eq!(stats["items_stored"], WRITES_PER_PEER_PER_MINUTE, "{stats}");
}

/// T3. A connection may push two megabytes of entries a minute. A third
/// megabyte is refused, and nothing of it is stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_a_connection_may_push_two_megabytes_a_minute() {
    use cordelia_core::protocol::MAX_ITEM_BYTES;

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let client = client_of(&relay).await.expect("the client connects");

    // Fifteen entries of the largest size: 960 KB a push.
    let megabyte = || -> Vec<_> { (0..15).map(|_| client.entry(MAX_ITEM_BYTES)).collect() };
    assert_eq!(client.push(&megabyte()).await.unwrap().stored, 15);
    assert_eq!(client.push(&megabyte()).await.unwrap().stored, 15);
    assert!(
        client.push(&megabyte()).await.is_err(),
        "a third megabyte was taken"
    );
    // A small push still fits in what is left of the allowance.
    assert_eq!(client.push(&[client.entry(64)]).await.unwrap().stored, 1);
    let stats: serde_json::Value = serde_json::from_str(&relay.cli(&["stats", "--json"])).unwrap();
    assert_eq!(stats["items_stored"], 31, "{stats}");
}

/// T3. An address has its share of connections, and the next one is turned
/// away as it arrives, before the cost of a handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_an_address_is_turned_away_once_it_has_its_share_of_connections() {
    use cordelia_core::protocol::MAX_CONNECTIONS_PER_IP;

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));

    let mut clients = Vec::new();
    for n in 0..MAX_CONNECTIONS_PER_IP {
        clients.push(
            client_of(&relay)
                .await
                .unwrap_or_else(|e| panic!("connection {n} was refused: {e}")),
        );
    }
    assert!(
        client_of(&relay).await.is_err(),
        "one more connection than an address's share was accepted"
    );
    // It was turned away as it arrived: the relay did no handshake with it.
    let log = std::fs::read_to_string(relay.log()).unwrap_or_default();
    assert!(
        log.contains("turning an inbound connection away before the handshake"),
        "the relay did not turn it away on arrival"
    );
    assert!(
        !log.contains("rejecting: connection limit exceeded"),
        "the relay shook hands with it first"
    );
    // When one goes, there is room again.
    let gone = clients.pop().unwrap();
    gone.conn.close(0u32.into(), b"done");
    drop(gone);
    let again = wait_for("room for another connection", &[&relay], 30, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(client_of(&relay))
                .ok()
        })
    });
    drop(again);
}

impl Client {
    /// An entry of `bytes` bytes in `channel`, signed by this client.
    fn entry_in(&self, channel: &str, bytes: usize) -> cordelia_network::messages::Item {
        let mut item = self.entry(bytes);
        let hash: [u8; 32] = item.content_hash.clone().try_into().unwrap();
        let cbor = cordelia_crypto::signing::build_item_metadata_envelope(
            &self.identity.public_key(),
            channel,
            &hash,
            false,
            &item.item_id,
            1,
            &item.published_at,
        )
        .unwrap();
        item.channel_id = channel.into();
        item.signature = self.identity.sign(&cbor).to_vec();
        item
    }

    /// How many entries of `channel` the relay lists.
    async fn listed(&self, channel: &str) -> usize {
        let (mut send, mut recv) = self.conn.open_bi().await.unwrap();
        cordelia_network::codec::write_protocol_byte(&mut send, Protocol::ItemSync)
            .await
            .unwrap();
        cordelia_network::item_sync::send_sync_page(&mut send, &mut recv, channel, 0, 100)
            .await
            .map(|page| page.items.len())
            .unwrap_or(0)
    }
}

/// T3. A relay has a storage cap, and keeps what it held first. A client
/// fills a relay with channels. Once it is full, a new channel is refused.
/// The first channel can still be written to, and room is made for it by
/// dropping the newest: everything the first channel held is still there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_a_full_relay_keeps_what_it_held_first() {
    use cordelia_core::protocol::MAX_ITEM_BYTES;
    use cordelia_network::messages::REFUSED_FULL;
    let channel = |n: usize| format!("grp_550e8400-e29b-41d4-a716-{n:012}");
    let stats = |relay: &Node| -> serde_json::Value {
        serde_json::from_str(&relay.cli(&["stats", "--json"])).unwrap()
    };

    let relay = node("relay", "relay", None);
    let cap = 1_000_000;
    relay.max_storage_bytes(cap);
    let mut relay = relay;
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    assert_eq!(stats(&relay)["storage_max_bytes"], cap);
    let client = client_of(&relay).await.expect("the client connects");

    // The first channel, then newer ones, two entries each, until the
    // relay refuses one for lack of room.
    let two = |ch: &str| {
        vec![
            client.entry_in(ch, MAX_ITEM_BYTES),
            client.entry_in(ch, MAX_ITEM_BYTES),
        ]
    };
    assert_eq!(client.push(&two(&channel(0))).await.unwrap().stored, 2);
    let mut newer = Vec::new();
    loop {
        let next = channel(newer.len() + 1);
        let ack = client.push(&two(&next)).await.unwrap();
        if ack.stored == 2 {
            newer.push(next);
            assert!(newer.len() < 12, "the relay is never full");
            continue;
        }
        assert!(!ack.refused.is_empty(), "{ack:?}");
        assert!(ack.refused.iter().all(|r| r.why == REFUSED_FULL), "{ack:?}");
        break;
    }
    assert!(newer.len() >= 2, "{}", newer.len());
    assert!(stats(&relay)["storage_used_bytes"].as_u64().unwrap() <= cap);
    assert_eq!(client.listed(&channel(newer.len() + 1)).await, 0);

    // The first channel is written to again. The relay takes it, stays
    // within its cap, and has dropped the newest channel to do so; the
    // first channel holds everything it was sent.
    let ack = client.push(&two(&channel(0))).await.unwrap();
    assert_eq!(ack.stored, 2, "{ack:?}");
    assert!(stats(&relay)["storage_used_bytes"].as_u64().unwrap() <= cap);
    assert_eq!(client.listed(&channel(0)).await, 4);
    assert_eq!(
        client.listed(newer.last().unwrap()).await,
        0,
        "the newest was kept"
    );
    assert_eq!(
        client.listed(&newer[0]).await,
        2,
        "an older channel was dropped"
    );
}
