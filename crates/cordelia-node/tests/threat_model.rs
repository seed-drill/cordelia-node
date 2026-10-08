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

use cordelia_crypto::entry::Entry;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_network::messages::{Protocol, WireMessage};

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
/// keeps text and bytes as they were written, so this finds it in a
/// database, in the write-ahead log beside it, and in a log file alike.
fn files_containing(dir: &Path, needle: impl AsRef<[u8]>) -> Vec<PathBuf> {
    let needle = needle.as_ref();
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path)
                && bytes.windows(needle.len()).any(|w| w == needle)
            {
                found.push(path);
            }
        }
    }
    found
}

/// A node's database, opened for reading: while the node runs, or once
/// it has stopped.
fn store_of(n: &Node) -> rusqlite::Connection {
    let db = rusqlite::Connection::open_with_flags(
        n.data_dir().join("cordelia.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.busy_timeout(std::time::Duration::from_secs(10)).unwrap();
    db
}

/// The person secret of the statement that the device `n` has applied,
/// read from its database: every channel of its own comes from it
/// (decision 2026-10-04 §2.2).
fn person_secret_of(n: &Node) -> [u8; 32] {
    cordelia_storage::person::applied_secret(&store_of(n))
        .unwrap()
        .unwrap_or_else(|| panic!("{} has applied no statement", n.name))
        .secret
}

/// The secret of the channel in which the device `n` syncs the name
/// `name`, under the statement it has applied.
fn name_secret_of(n: &Node, name: &str) -> [u8; 32] {
    cordelia_crypto::derive::own_secret(&person_secret_of(n), name).unwrap()
}

/// The ID of the channel whose secret is `secret`.
fn channel_of(secret: &[u8; 32]) -> [u8; 32] {
    cordelia_crypto::derive::channel_id(secret).unwrap()
}

/// The ID of the personal channel of the device `n`, under the statement
/// it has applied.
fn personal_channel_of(n: &Node) -> [u8; 32] {
    channel_of(&cordelia_crypto::derive::personal_secret(&person_secret_of(n)).unwrap())
}

/// Turn sync on for `n`, with a folder `notes` of its own mapped to the
/// name `name`: the device holds the name once it follows a recovery
/// phrase. Returns the memory folder that Claude Code keeps for the
/// folder.
fn syncs_notes_as(n: &Node, name: &str) -> PathBuf {
    let notes = n.home().join("notes");
    std::fs::create_dir_all(&notes).unwrap();
    let memory = claude_folder(&n.home(), &notes);
    let claude_dir = n.home().join(".claude");
    n.cli(&["sync", "claude", "--dir", claude_dir.to_str().unwrap()]);
    n.cli(&["sync", "map", notes.to_str().unwrap(), name]);
    memory
}

/// Ask a node's local API for something that it may refuse: the status
/// of its answer, and what it says.
fn asks(n: &Node, path: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .proxy(None)
        .http_status_as_error(false)
        .build()
        .into();
    let mut answer = agent
        .post(format!("http://127.0.0.1:{}{path}", n.http))
        .header("Authorization", &format!("Bearer {}", n.token()))
        .send_json(&body)
        .unwrap_or_else(|e| panic!("{}: POST {path} failed: {e}", n.name));
    let status = answer.status().as_u16();
    let said = answer.body_mut().read_json();
    (status, said.unwrap_or(serde_json::Value::Null))
}

/// Publish the text `text` under `key` in the name `name`, through the
/// local API of the device `n`. What it answers: the revision, what the
/// entry is named by, and what it was published over.
fn publishes(n: &Node, name: &str, key: &str, text: &str) -> serde_json::Value {
    n.post(
        "/api/v1/channels/publish",
        serde_json::json!({ "channel": name, "key": key, "content": text }),
    )
}

/// What the device `n` reads under each key of the name `name`: its
/// text, or `None` once it is deleted. Nothing where the device does not
/// hold the name.
fn reads(n: &Node, name: &str) -> BTreeMap<String, Option<String>> {
    let (status, answer) = asks(
        n,
        "/api/v1/channels/entries",
        serde_json::json!({ "channel": name }),
    );
    if status != 200 {
        return BTreeMap::new();
    }
    answer["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| {
            let text = e["content"].as_str().map(String::from);
            Some((e["key"].as_str()?.to_string(), text))
        })
        .collect()
}

/// Whether the device `n` holds the name `name`: its local API lists
/// what the name holds.
fn holds_name(n: &Node, name: &str) -> Option<()> {
    let body = serde_json::json!({ "channel": name });
    (asks(n, "/api/v1/channels/entries", body).0 == 200).then_some(())
}

/// How many entries the node `n` holds that the key `author` signed, in
/// channels from their secrets.
fn entries_by(n: &Node, author: &[u8; 32]) -> i64 {
    store_of(n)
        .query_row(
            "SELECT COUNT(*) FROM entries WHERE author = ?1",
            [author.as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}

/// T1. A relay holds nothing it can read. Two devices of one person sync
/// a folder under a name through a relay, and exchange a named entry.
/// Afterwards nothing the relay wrote to disk (its database, the
/// write-ahead log beside it, its own log) contains the entry's name, its
/// content, the name the folder syncs under, or the label one device gave
/// the other. The relay did carry the entry: the channel's ID is there.
#[test]
fn t01_a_relay_holds_nothing_it_can_read() {
    const PROJECT: &str = "t01-canary-project";
    const NAME: &str = "t01-canary-name.md";
    const CONTENT: &str = "t01 canary content: prefers short answers";
    const LABEL: &str = "t01-canary-label";

    let mut relay = relay_started();
    let mut a = device_started("a", &relay);
    let b = device_started("b", &relay);
    let all = [&relay, &a, &b];
    let memory = syncs_notes_as(&a, PROJECT);
    syncs_notes_as(&b, PROJECT);
    pair(&a, &b, LABEL, &all);
    for n in [&a, &b] {
        wait_for("the device holds the name", &all, 60, || {
            holds_name(n, PROJECT)
        });
    }

    publishes(&a, PROJECT, NAME, CONTENT);
    // B reads it, so it went through the relay: the two devices have no
    // other path to each other.
    wait_for("b reads a's entry", &all, 90, || {
        (reads(&b, PROJECT).get(NAME)? == &Some(CONTENT.to_string())).then_some(())
    });
    // And A's own folder takes it, as a memory file.
    wait_for("a's folder takes the entry", &all, 90, || {
        (std::fs::read_to_string(memory.join(NAME)).ok()? == CONTENT).then_some(())
    });
    let channel = channel_of(&name_secret_of(&a, PROJECT));

    // Stop the relay as a service manager would, so everything it holds
    // is on disk.
    relay.stop();
    let dir = relay.dir.path();
    assert!(
        !files_containing(dir, channel).is_empty(),
        "the relay carried the channel, so its ID should be on its disk"
    );
    for (what, needle) in [
        ("name", NAME),
        ("content", CONTENT),
        ("label", LABEL),
        ("folder's name", PROJECT),
    ] {
        let found = files_containing(dir, needle);
        assert!(
            found.is_empty(),
            "the relay's disk holds an entry's {what} in {found:?}"
        );
    }
    // The same search does find them where they are allowed to be: on the
    // device that wrote them. So an empty result above means something.
    a.stop();
    for (what, needle) in [
        ("name", NAME),
        ("content", CONTENT),
        ("label", LABEL),
        ("folder's name", PROJECT),
    ] {
        assert!(
            !files_containing(a.dir.path(), needle).is_empty(),
            "the {what} should be on the device that gave it"
        );
    }
}

/// What a stand-in for a relay was sent on a stream of entries: the
/// stream it came on, its bytes as they travelled, and the request that
/// they are, where they are one.
#[derive(Clone)]
struct Heard {
    protocol: Protocol,
    bytes: Vec<u8>,
    request: Option<WireMessage>,
}

/// What a stand-in for a relay holds, and how it answers.
struct Script {
    /// Whether it has room. Without room it takes no entry: one that is
    /// shown or pushed is refused for room, as a relay that is full
    /// refuses it.
    has_room: bool,
    /// How many pushes it still answers with an answer that says nothing
    /// of any entry: fewer things than the push held entries.
    says_nothing_of: usize,
    /// The entries it took, each by what it is named by.
    holds: BTreeSet<[u8; 32]>,
}

/// A stand-in for a relay. It completes the handshake as a relay does,
/// and records what each node that connects does: the protocol of every
/// stream it opens, and every request it makes on a stream of entries
/// (decision 2026-10-04 §2.4).
///
/// It answers those requests as a relay with room does, until a test
/// says otherwise: an entry that is shown, it takes; a proof it answers
/// with no, as a relay that holds nothing of the channel yet; a pull,
/// with a page of nothing; and a push, with "stored" for each entry.
struct StandIn {
    port: u16,
    /// The stand-in's own key, as a device would be configured with it.
    key: String,
    streams: Arc<Mutex<Vec<Protocol>>>,
    heard: Arc<Mutex<Vec<Heard>>>,
    script: Arc<Mutex<Script>>,
}

/// A stand-in relay that has room.
fn stand_in_relay() -> StandIn {
    use cordelia_network::{connection, transport};

    let identity = Arc::new(NodeIdentity::generate().unwrap());
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
    let relay = StandIn {
        port,
        key,
        streams: Arc::default(),
        heard: Arc::default(),
        script: Arc::new(Mutex::new(Script {
            has_room: true,
            says_nothing_of: 0,
            holds: BTreeSet::new(),
        })),
    };

    let (streams, heard, script) = (
        relay.streams.clone(),
        relay.heard.clone(),
        relay.script.clone(),
    );
    tokio::spawn(async move {
        let _manager = manager; // keeps the endpoint's context alive
        while let Some(incoming) = endpoint.accept().await {
            let ctx = ctx.clone();
            let (streams, heard, script) = (streams.clone(), heard.clone(), script.clone());
            tokio::spawn(async move {
                let Ok(outcome) = connection::inbound_accept(&ctx, incoming).await else {
                    return;
                };
                while let Ok((send, recv)) = outcome.conn.accept_bi().await {
                    let (streams, heard, script) = (streams.clone(), heard.clone(), script.clone());
                    tokio::spawn(StandIn::answers(streams, heard, script, send, recv));
                }
            });
        }
    });
    relay
}

impl StandIn {
    /// Answer one stream.
    async fn answers(
        streams: Arc<Mutex<Vec<Protocol>>>,
        heard: Arc<Mutex<Vec<Heard>>>,
        script: Arc<Mutex<Script>>,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) {
        use cordelia_network::codec;
        use cordelia_network::messages::{
            ChannelProved, EntryPulled, EntryPushed, EntryRefused, EntryShown, PushAnswer,
            ShowAnswer,
        };

        let Ok(protocol) = codec::read_protocol_byte(&mut recv).await else {
            return;
        };
        streams.lock().unwrap().push(protocol);
        let of_entries = [
            Protocol::EntryShow,
            Protocol::ChannelProve,
            Protocol::EntryPull,
            Protocol::EntryPush,
        ];
        if !of_entries.contains(&protocol) {
            return;
        }
        let Ok(bytes) = codec::read_raw_frame(&mut recv).await else {
            return;
        };
        let request = codec::decode_message(&bytes).ok();
        // What an entry that is shown or pushed is answered with, where
        // its bytes are an entry's: it is held, or taken, or refused for
        // room.
        let taken = |script: &mut Script, bytes: &[u8]| -> Option<PushAnswer> {
            let id = Entry::from_wire(bytes).ok()?.id();
            Some(if script.holds.contains(&id) {
                PushAnswer::Held
            } else if script.has_room {
                script.holds.insert(id);
                PushAnswer::Stored
            } else {
                PushAnswer::Refused(EntryRefused::NoRoom)
            })
        };
        let answer = {
            let mut script = script.lock().unwrap();
            match &request {
                Some(WireMessage::EntryShow(show)) => {
                    taken(&mut script, &show.entry).map(|became| {
                        let answer = match became {
                            PushAnswer::Stored => ShowAnswer::Taken,
                            PushAnswer::Refused(why) => ShowAnswer::Refused(why),
                            _ => ShowAnswer::Held,
                        };
                        WireMessage::EntryShown(EntryShown { answer })
                    })
                }
                // It holds the entry, or holds none: "show it whole".
                Some(WireMessage::EntryShowShort(short)) => {
                    let answer = match script.holds.contains(&short.id) {
                        true => ShowAnswer::Held,
                        false => ShowAnswer::Whole,
                    };
                    Some(WireMessage::EntryShown(EntryShown { answer }))
                }
                Some(WireMessage::ChannelProve(_)) => {
                    Some(WireMessage::ChannelProved(ChannelProved { proved: false }))
                }
                Some(WireMessage::EntryPull(pull)) => Some(WireMessage::EntryPulled(EntryPulled {
                    entries: Vec::new(),
                    next: pull.after,
                    mark: pull.mark,
                })),
                Some(WireMessage::EntryPush(push)) if script.says_nothing_of > 0 => {
                    script.says_nothing_of -= 1;
                    let answers = vec![PushAnswer::Stored; push.entries.len().saturating_sub(1)];
                    Some(WireMessage::EntryPushed(EntryPushed { answers }))
                }
                Some(WireMessage::EntryPush(push)) => {
                    let answers: Option<Vec<PushAnswer>> = push
                        .entries
                        .iter()
                        .map(|bytes| taken(&mut script, bytes))
                        .collect();
                    answers.map(|answers| WireMessage::EntryPushed(EntryPushed { answers }))
                }
                _ => None,
            }
        };
        heard.lock().unwrap().push(Heard {
            protocol,
            bytes,
            request,
        });
        // What is no request for a stream of entries is answered nothing.
        if let Some(answer) = answer {
            let _ = codec::write_frame(&mut send, &answer).await;
            let _ = send.finish();
        }
    }

    /// From now on it has room, or has none, as `has_room` says.
    fn has_room(&self, has_room: bool) {
        self.script.lock().unwrap().has_room = has_room;
    }

    /// Every request it was sent on a stream of entries, in the order
    /// they arrived.
    fn heard(&self) -> Vec<Heard> {
        self.heard.lock().unwrap().clone()
    }

    /// The entries that it was shown whole, in the order they were
    /// shown, each by what it is named by.
    fn shown_whole(&self) -> Vec<[u8; 32]> {
        self.heard()
            .iter()
            .filter_map(|heard| match &heard.request {
                Some(WireMessage::EntryShow(show)) => {
                    Some(Entry::from_wire(&show.entry).ok()?.id())
                }
                _ => None,
            })
            .collect()
    }

    /// The entries of each push, in the order the pushes arrived.
    fn pushes(&self) -> Vec<Vec<Entry>> {
        self.heard()
            .iter()
            .filter_map(|heard| match &heard.request {
                Some(WireMessage::EntryPush(push)) => Some(
                    push.entries
                        .iter()
                        .filter_map(|bytes| Entry::from_wire(bytes).ok())
                        .collect(),
                ),
                _ => None,
            })
            .collect()
    }

    /// How many pushes held the entry that is named by `id`, in hex.
    fn pushes_of(&self, id: &str) -> usize {
        let holds = |push: &Vec<Entry>| push.iter().any(|entry| hex::encode(entry.id()) == id);
        self.pushes().iter().filter(|push| holds(push)).count()
    }
}

/// Whether the device `n` has nothing left to send to the relays it
/// reaches: of no channel of its own, and of no name.
fn has_sent_everything(n: &Node) -> Option<()> {
    let seen = person_of(n);
    let waiting = seen["waiting"].as_array()?;
    let sent = seen["names"]["to_go"].as_array()?.is_empty()
        && waiting.iter().all(|relay| relay["waits"] == 0);
    (!waiting.is_empty() && sent).then_some(())
}

/// T1. A device tells a relay a channel's ID and nothing else about it. A
/// real node that follows a recovery phrase, with its personal channel
/// and a folder mapped under a name, connects to a stand-in relay that
/// records every request. Each names a channel by its ID alone, and each
/// entry in one is an entry that a relay accepts: none carries the name,
/// a file's name or text, or a label, and none carries anything beyond
/// what its form has. The device announces no channel at all: it opens no
/// stream of the older kind (decision 2026-10-04 §2.3, §2.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t01_a_device_tells_a_relay_only_a_channels_id() {
    const PROJECT: &str = "t01-canary-project-name";
    const FILE: &str = "t01-canary-file.md";
    const TEXT: &str = "t01 canary text: a thought.\n";
    const LABEL: &str = "t01-canary-label";

    let relay = stand_in_relay();
    let mut a = node("a", "personal", Some(relay.port));
    a.start();
    wait_for("node healthy", &[&a], 30, || healthy(&a));
    wait_for("connected to the relay", &[&a], 60, || has_hot_peer(&a));

    // Sync on, one folder mapped under a name, and a recovery phrase: the
    // node now has its personal channel and a channel for the name.
    let memory = syncs_notes_as(&a, PROJECT);
    std::fs::write(memory.join(FILE), TEXT).unwrap();
    makes_a_phrase(&a, LABEL);
    wait_for("the node publishes its folder", &[&a], 90, || {
        (reads(&a, PROJECT).get(FILE)? == &Some(TEXT.to_string())).then_some(())
    });
    let (personal, named) = (
        personal_channel_of(&a),
        channel_of(&name_secret_of(&a, PROJECT)),
    );
    let change = cordelia_api::at_relays::to_show(&store_of(&a))
        .unwrap()
        .expect("the node keeps a change entry")
        .entry
        .channel;
    let own = [change, personal, named];

    // The relay hears of each of them: it is sent what the node holds of
    // each.
    fn entry_of(bytes: &[u8]) -> cordelia_crypto::entry::CheckedEntry {
        Entry::from_wire(bytes)
            .expect("what the node sent as an entry is one")
            .check()
            .expect("a relay accepts the entry")
    }
    let channels_of = |heard: &Heard| -> Vec<[u8; 32]> {
        match &heard.request {
            Some(WireMessage::EntryShow(show)) => vec![entry_of(&show.entry).channel],
            Some(WireMessage::EntryShowShort(short)) => vec![short.channel],
            Some(WireMessage::ChannelProve(prove)) => vec![prove.channel],
            Some(WireMessage::EntryPull(pull)) => vec![pull.channel],
            Some(WireMessage::EntryPush(push)) => push
                .entries
                .iter()
                .map(|bytes| entry_of(bytes).channel)
                .collect(),
            other => panic!("the node told its relay something else: {other:?}"),
        }
    };
    let heard = wait_for("the relay is told of both channels", &[&a], 90, || {
        has_sent_everything(&a)?;
        let heard = relay.heard();
        let pushed: BTreeSet<[u8; 32]> = heard
            .iter()
            .filter(|heard| heard.protocol == Protocol::EntryPush)
            .flat_map(&channels_of)
            .collect();
        (pushed.contains(&personal) && pushed.contains(&named)).then_some(heard)
    });
    assert!(
        heard.iter().any(|heard| channels_of(heard) == [change]),
        "the relay was not shown the change entry"
    );

    for one in &heard {
        let what = format!("a request on a stream of {:?}", one.protocol);
        // It speaks of the node's own channels, each by its ID.
        for channel in channels_of(one) {
            assert!(own.contains(&channel), "{what} names another channel");
        }
        // It carries what its form has, and nothing else.
        let request = one.request.as_ref().expect("it is a request");
        assert_eq!(
            cordelia_network::codec::encode_message(request).unwrap(),
            one.bytes,
            "{what} carries more than its form has"
        );
        // Whatever the fields are called, no name is anywhere in it.
        for needle in [PROJECT, FILE, TEXT, LABEL, "personal", "notes"] {
            assert!(
                !one.bytes
                    .windows(needle.len())
                    .any(|w| w == needle.as_bytes()),
                "{what} contains {needle:?}"
            );
        }
    }
    // And it announced no channel, under any name: a personal node opens
    // no stream of the older kind.
    let opened = relay.streams.lock().unwrap().clone();
    for older in [
        Protocol::ChannelAnnounce,
        Protocol::ItemPush,
        Protocol::ItemSync,
    ] {
        assert!(
            !opened.contains(&older),
            "the node opened a stream of {older:?} to its relay"
        );
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
    // The device is at work with this relay: it follows a recovery
    // phrase, and opens streams to it.
    makes_a_phrase(&a, "laptop");
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
/// peer: the relay does not tell it which channels it holds, of either
/// kind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t19_a_stranger_that_says_it_is_a_relay_is_not_treated_as_one() {
    use cordelia_crypto::entry::{Inside, Value};
    use cordelia_network::messages::{EntryPush, PushAnswer, RelayChannelsAsk};
    use cordelia_network::{codec, connection, item_sync, transport};

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let relay_addr = format!("127.0.0.1:{}", relay.p2p);
    let all = [&relay];

    // A client gives the relay something to hold, of each kind of
    // channel: an item of the older kind, and an entry of a channel from
    // its secret.
    let holder = client_of(&relay).await.expect("the holder connects");
    let ack = holder.push(&[holder.entry(64)]).await.unwrap();
    assert_eq!(ack.stored, 1, "{ack:?}");
    let inside = Inside {
        name: "idea.md".into(),
        value: Value::Text("A thought.\n".into()),
        chain: Some(Vec::new()),
    };
    let entry = Entry::seal(&[0x19; 32], &holder.identity, 1, &inside).unwrap();
    let push = WireMessage::EntryPush(EntryPush {
        entries: vec![entry.to_wire().into()],
    });
    match holder.ask(Protocol::EntryPush, push).await.unwrap() {
        WireMessage::EntryPushed(pushed) => assert_eq!(pushed.answers, [PushAnswer::Stored]),
        other => panic!("not an answer to a push: {other:?}"),
    }
    let stats: serde_json::Value = serde_json::from_str(&relay.cli(&["stats", "--json"])).unwrap();
    assert_eq!(stats["items_stored"], 1, "{stats}");
    assert_eq!(entries_by(&relay, &holder.identity.public_key()), 1);

    // The stranger: its own key, and "relay" in its handshake.
    let identity = Arc::new(NodeIdentity::generate().unwrap());
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
    // And as a relay asks one that it works with, for the channels from
    // their secrets: that is answered to nobody but a relay that the
    // operator lists by key.
    let ask = WireMessage::RelayChannelsAsk(RelayChannelsAsk {
        after: [0; 32],
        limit: 100,
    });
    let answered = ask_on(&conn, Protocol::RelayEntries, ask).await;
    assert!(
        answered.is_err(),
        "the relay answered a stranger that asked as a relay it works with: {answered:?}"
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

/// The newest entry that the key `author` signed in `channel`, as the
/// node `n` holds it: as it travels, and as anyone who carries it sees
/// it.
fn newest_entry_by(n: &Node, channel: &[u8; 32], author: &[u8; 32]) -> Entry {
    cordelia_storage::entries::channel_entries_after(&store_of(n), channel, 0, 10_000)
        .unwrap()
        .into_iter()
        .rev()
        .find(|held| held.entry.author == *author)
        .unwrap_or_else(|| panic!("{} holds no entry by that key in the channel", n.name))
        .entry
}

/// The node key of `n`, as its bytes.
fn key_bytes_of(n: &Node) -> [u8; 32] {
    cordelia_crypto::bech32::decode_public_key(&key_of(n)).expect("a node prints its key")
}

/// A device says nothing to its relay of a channel of the older kind,
/// though its database holds one (decision 2026-10-04 §10): a personal
/// node carries no channel of that kind. Its store is given a group
/// channel that it is a member of, with an item of its own that no relay
/// has taken, as a build from before the first start on this version
/// left them: on a device that follows a phrase, in a database with no
/// mark, whose start writes the mark and steps nothing (§10.1). So the
/// rows are there while the node runs. It follows a phrase, so it does
/// talk to its relay: of its own channels, on the streams of entries. It
/// announces no channel, asks for none, and pushes no item, however long
/// the relay listens.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_says_nothing_to_its_relay_of_a_channel_of_the_older_kind() {
    use cordelia_storage::{channels, first_start, items, meta};
    let relay = stand_in_relay();
    let mut a = node("a", "personal", Some(relay.port));
    let own = key_bytes_of(&a);
    let group = "grp_550e8400-e29b-41d4-a716-446655440000";
    a.start();
    wait_for("node healthy", &[&a], 30, || healthy(&a));
    wait_for("connected to the relay", &[&a], 60, || has_hot_peer(&a));
    makes_a_phrase(&a, "desktop");
    wait_for("the device talks to its relay", &[&a], 60, || {
        (!relay.heard().is_empty()).then_some(())
    });
    a.stop();
    {
        let db = cordelia_storage::db::open(&a.data_dir().join("cordelia.db")).unwrap();
        // No mark, and no guard, as such a build left the database.
        assert!(first_start::remove_guard(&db).unwrap());
        meta::remove(&db, meta::FIRST_START).unwrap();
        channels::ensure_group(&db, group, None, "realtime", &own).unwrap();
        channels::add_member(&db, group, &own, "owner").unwrap();
        let blob = b"what an earlier version sealed".to_vec();
        let item = items::NewItem {
            item_id: "ci_01JARV8XMHW8G9QZP0000000AA",
            channel_id: group,
            author_id: &own,
            item_type: "memory",
            published_at: "2026-10-01T00:00:00Z",
            parent_id: None,
            key_version: 1,
            content_hash: &cordelia_crypto::sha256(&blob),
            signature: &[7u8; 64],
            encrypted_blob: &blob,
            is_tombstone: false,
            slot: None,
            rev: None,
        };
        assert!(items::insert_item(&db, &item).unwrap());
    }
    // What the older outbox, fetch and announcement would each have gone
    // by: it is there while the node runs.
    let held = |a: &Node| {
        let db = rusqlite::Connection::open_with_flags(
            a.data_dir().join("cordelia.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        db.busy_timeout(std::time::Duration::from_secs(10)).unwrap();
        (
            items::outbox_len(&db, &own).unwrap(),
            channels::list_for_entity(&db, &own).unwrap().len(),
            first_start::mark(&db).unwrap().map(|mark| mark.stepped),
        )
    };
    assert_eq!(held(&a), (1, 1, None));
    let before = relay.streams.lock().unwrap().len();
    a.start();
    wait_for("node healthy again", &[&a], 30, || healthy(&a));
    wait_for("connected to the relay again", &[&a], 60, || {
        has_hot_peer(&a)
    });
    wait_for("the device talks to its relay again", &[&a], 60, || {
        (relay.streams.lock().unwrap().len() > before).then_some(())
    });
    // The start wrote the mark, and stepped nothing: the rows are there.
    assert_eq!(held(&a), (1, 1, Some(false)));

    // Long enough for each of the three: an announcement goes when a
    // peer is promoted and when a node connects, a fetch is made every
    // ten seconds, and the outbox was flushed every two.
    tokio::time::sleep(std::time::Duration::from_secs(25)).await;
    let opened = relay.streams.lock().unwrap()[before..].to_vec();
    assert!(!opened.is_empty());
    for older in [
        Protocol::ChannelAnnounce,
        Protocol::ItemSync,
        Protocol::ItemPush,
    ] {
        assert!(
            !opened.contains(&older),
            "the device opened a stream of {older:?} to its relay"
        );
    }
    // And it does not count the item as waiting to be sent: what waits
    // is of its own channels alone.
    wait_for("nothing waits to be sent", &[&a], 60, || {
        let status = a.get("/api/v1/status")?;
        (status["outbox_waiting"] == 0).then_some(())
    });
    assert_eq!(held(&a), (1, 1, Some(false)));
}

/// T2. A stranger who knows a channel's ID and has seen one of its entries
/// in transit makes a copy of it: the same ciphertext, in the same slot,
/// under the stranger's own key and with the highest revision there is.
/// The channel's own signature the stranger cannot make, so the relay
/// stores no copy, whichever signature the copy carries in its place
/// (decision 2026-10-04 §2.4, item 1). The relay stores the entry itself
/// when it arrives, the channel's other device reads it, and both devices
/// go on writing that name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t02_a_strangers_copy_at_a_relay_changes_nothing_for_a_channels_devices() {
    use cordelia_core::protocol::{LABEL_ENTRY_AUTHOR, LABEL_ENTRY_CHANNEL};
    use cordelia_network::messages::{EntryPush, EntryRefused, EntryShow, PushAnswer, ShowAnswer};
    const PROJECT: &str = "t02";
    const NAME: &str = "t02-notes.md";

    let mut relay = relay_started();
    let mut a = device_started("a", &relay);
    let mut b = device_started("b", &relay);
    for n in [&a, &b] {
        syncs_notes_as(n, PROJECT);
    }
    pair(&a, &b, "b", &[&relay, &a, &b]);
    for n in [&a, &b] {
        wait_for("the device holds the name", &[&relay, &a, &b], 60, || {
            holds_name(n, PROJECT)
        });
    }
    let reads_text = |n: &Node, text: &str| {
        (reads(n, PROJECT).get(NAME)? == &Some(text.to_string())).then_some(())
    };
    let a_key = key_bytes_of(&a);

    // A writes an entry while the relay is away, so the entry waits on A.
    // A then stops, so that the stranger gets to the relay first.
    relay.stop();
    let published = publishes(&a, PROJECT, NAME, "one");
    assert_eq!(published["rev"], 1, "{published}");
    a.stop();
    let channel = channel_of(&name_secret_of(&a, PROJECT));
    let entry = newest_entry_by(&a, &channel, &a_key);
    assert_eq!(entry.rev, 1);
    assert_eq!(published["entry"], hex::encode(entry.id()), "{published}");

    // The copy: the stranger's key and signature on the same ciphertext.
    // In the place of the channel's signature it has the one it saw, or
    // one that it makes with its own key.
    let stranger = Arc::new(NodeIdentity::generate().unwrap());
    let copy = |by_channel: Option<&NodeIdentity>| -> Vec<u8> {
        let mut copy = Entry {
            author: stranger.public_key(),
            rev: cordelia_core::protocol::MAX_REV,
            ..entry.clone()
        };
        let form = copy.signed_bytes();
        let under = |label: &[u8]| [label, form.as_slice()].concat();
        copy.author_signature = stranger.sign(&under(LABEL_ENTRY_AUTHOR));
        if let Some(key) = by_channel {
            copy.channel_signature = key.sign(&under(LABEL_ENTRY_CHANNEL));
        }
        copy.to_wire()
    };
    let copies = [copy(None), copy(Some(&stranger))];

    relay.start();
    wait_for("relay healthy again", &[&relay, &b], 30, || healthy(&relay));
    let client = client_as(stranger.clone(), &relay)
        .await
        .expect("the stranger connects, as any node may");
    let push = WireMessage::EntryPush(EntryPush {
        entries: copies.iter().map(|copy| copy.clone().into()).collect(),
    });
    let refused = EntryRefused::NotSigned;
    match client.ask(Protocol::EntryPush, push).await.unwrap() {
        WireMessage::EntryPushed(pushed) => assert_eq!(
            pushed.answers,
            [PushAnswer::Refused(refused), PushAnswer::Refused(refused)],
            "the relay took a stranger's copy"
        ),
        other => panic!("not an answer to a push: {other:?}"),
    }
    for copy in &copies {
        let show = WireMessage::EntryShow(EntryShow {
            entry: copy.clone(),
        });
        match client.ask(Protocol::EntryShow, show).await.unwrap() {
            WireMessage::EntryShown(shown) => {
                assert_eq!(shown.answer, ShowAnswer::Refused(refused))
            }
            other => panic!("not an answer to a show: {other:?}"),
        }
    }

    // A comes back and sends the entry itself. B reads it, so the relay
    // stored it and passed it on.
    a.start();
    let all = [&relay, &a, &b];
    wait_for("a healthy again", &all, 30, || healthy(&a));
    wait_for("b reads a's entry", &all, 120, || reads_text(&b, "one"));

    // The name is not out of reach: B writes it again as the next revision,
    // and A reads that.
    let published = publishes(&b, PROJECT, NAME, "two");
    assert_eq!(published["rev"], 2, "{published}");
    wait_for("a reads b's edit", &all, 120, || reads_text(&a, "two"));

    // Nobody holds anything that the stranger signed: not the relay, which
    // holds the channel's entries without its secret, and not a device.
    let stranger_key = stranger.public_key();
    let held_by = |n: &mut Node, author: &[u8; 32]| -> i64 {
        n.stop();
        entries_by(n, author)
    };
    assert_eq!(
        held_by(&mut relay, &stranger_key),
        0,
        "the relay stored what a stranger wrote"
    );
    assert_eq!(
        held_by(&mut a, &stranger_key),
        0,
        "a stored what a stranger wrote"
    );
    assert_eq!(
        held_by(&mut b, &stranger_key),
        0,
        "b stored what a stranger wrote"
    );
    // The same count does find what a device of the channel signed, at
    // each of the three.
    for n in [&mut relay, &mut a, &mut b] {
        assert!(
            held_by(n, &a_key) > 0,
            "{} holds nothing that a signed",
            n.name
        );
    }
}

/// Every list in which a node shows a key of its person's: the devices of
/// the change it has applied, those added since, the keys removed and
/// left out, the keys typed at `cordelia accept`, and its notices; with
/// where the device stands.
fn keys_shown_by(n: &Node) -> serde_json::Value {
    let seen = person_of(n);
    let devices: Vec<&serde_json::Value> = seen["devices"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|device| &device["key"])
        .collect();
    serde_json::json!({
        "state": seen["state"],
        "change": seen["change"],
        "devices": devices,
        "added": seen["added"],
        "removed": seen["removed"],
        "left_out": seen["left_out"],
        "accepting": seen["accepting"],
        "notices": seen["notices"],
    })
}

/// T20. A key that is no device's key (a point of small order, under
/// which anyone can sign and the secret is one anyone can work out) is
/// never one of this person's devices. `add-device` refuses it, `accept`
/// refuses it on a device that follows no phrase, and `remove-device`
/// refuses it. Nothing is kept of it, and no command shows anything
/// about it afterwards. A real device is added as it always is (decision
/// 2026-10-04 §2.2, §6).
#[test]
fn t20_a_key_that_is_no_devices_is_not_added_accepted_or_removed() {
    let relay = relay_started();
    let a = device_started("a", &relay);
    let b = device_started("b", &relay);
    let all = [&relay, &a, &b];
    makes_a_phrase(&a, "desktop");

    // The identity of the curve: a point of small order.
    let mut nobody = [0u8; 32];
    nobody[0] = 1;
    let listed_as = cordelia_crypto::bech32::encode_public_key(&nobody).unwrap();
    let (a_before, b_before) = (keys_shown_by(&a), keys_shown_by(&b));

    // It is not added: the device that is in refuses it before it asks
    // its yes, and writes nothing.
    let no_devices_key = "that is this device's own key, or no device's key";
    let said = a
        .at_terminal(&["add-device", &listed_as, "--name", "laptop"])
        .refused();
    assert!(said.contains(no_devices_key), "{said}");
    // It is not accepted: after its yes, a device that follows no phrase
    // keeps no such key to ask its relays with.
    let mut at = b.at_terminal(&["accept", &listed_as]);
    at.says("Type yes to go on").types("yes");
    let said = at.refused();
    assert!(said.contains(no_devices_key), "{said}");
    // And it is not removed: it is no device of this person's.
    let said = a.at_terminal(&["remove-device", &listed_as]).refused();
    assert!(said.contains("no device of yours"), "{said}");

    // Nothing is kept of it, and nothing is said of it: not where the
    // person looks at their devices, and not in the status that panels
    // read.
    assert_eq!(keys_shown_by(&a), a_before);
    assert_eq!(keys_shown_by(&b), b_before);
    let commands: [&[&str]; 3] = [&["devices"], &["status"], &["status", "--json"]];
    for n in [&a, &b] {
        for command in commands {
            let said = n.cli(command);
            assert!(!said.contains(&listed_as), "{said}");
        }
    }

    // A real device is added as it always is.
    pair(&a, &b, "laptop", &all);
    let seen = person_of(&a);
    let added: Vec<&str> = seen["added"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|device| device["key"].as_str())
        .collect();
    assert_eq!(added, [key_of(&b).as_str()], "{seen}");
}

/// The keys that the device `n` counts as its person's devices: those of
/// the change it has applied, and those added since that count.
fn devices_of(n: &Node) -> BTreeSet<String> {
    let seen = person_of(n);
    ["devices", "added"]
        .iter()
        .flat_map(|list| seen[*list].as_array().cloned().unwrap_or_default())
        .filter(|device| device["counted"] != false)
        .filter_map(|device| device["key"].as_str().map(String::from))
        .collect()
}

/// The number of the change that the device `n` has heard the device
/// whose key is `key` say it has applied.
fn applied_as_heard_by(n: &Node, key: &str) -> Option<u64> {
    let seen = person_of(n);
    ["devices", "added"]
        .iter()
        .flat_map(|list| seen[*list].as_array().cloned().unwrap_or_default())
        .find(|device| device["key"] == key)?["applied"]
        .as_u64()
}

/// T16. A device is removed. What it last wrote is still in the name's
/// channel for the device that removed it and for one added afterwards: a
/// file it edited keeps its edit, a file it created is there, and a file
/// it deleted stays deleted. What it writes after its removal reaches
/// nobody, and the names it wrote stay writable.
///
/// The removed device stops once it hears, and its own node then
/// publishes nothing. A removed device that does not stop still holds its
/// key and the secret of the channel that the others have left: what it
/// writes there, a relay stores, and nobody reads. In the channel that
/// the others moved to it can sign nothing (decision 2026-10-04 §7.3,
/// §7.5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t16_a_removed_devices_last_entries_are_kept_and_its_later_ones_are_not() {
    use cordelia_core::protocol::{LABEL_ENTRY_AUTHOR, LABEL_ENTRY_CHANNEL, MAX_REV};
    use cordelia_crypto::entry::{Inside, Value};
    use cordelia_network::messages::{EntryPush, EntryRefused, PushAnswer};
    const PROJECT: &str = "t16";

    let relay = relay_started();
    let a = device_started("a", &relay);
    let mut r = device_started("r", &relay);
    let d = device_started("d", &relay);
    for n in [&a, &r, &d] {
        syncs_notes_as(n, PROJECT);
    }
    let words = pair(&a, &r, "r", &[&relay, &a, &r, &d]).expect("a makes the phrase");
    for n in [&a, &r] {
        wait_for("the device holds the name", &[&relay, &a, &r], 60, || {
            holds_name(n, PROJECT)
        });
    }

    let text = |s: &str| Some(s.to_string());
    let held: BTreeMap<String, Option<String>> = [
        ("created.md".to_string(), text("by r")),
        ("deleted.md".to_string(), None),
        ("edited.md".to_string(), text("by r")),
    ]
    .into();

    // A writes two files. R edits one, deletes the other and creates a third.
    publishes(&a, PROJECT, "edited.md", "by a");
    publishes(&a, PROJECT, "deleted.md", "by a");
    wait_for("r reads a's files", &[&relay, &a, &r], 90, || {
        (reads(&r, PROJECT).len() == 2).then_some(())
    });
    publishes(&r, PROJECT, "edited.md", "by r");
    r.post(
        "/api/v1/channels/delete-key",
        serde_json::json!({ "channel": PROJECT, "key": "deleted.md" }),
    );
    publishes(&r, PROJECT, "created.md", "by r");
    wait_for("a reads what r wrote", &[&relay, &a, &r], 90, || {
        (reads(&a, PROJECT) == held).then_some(())
    });
    let left = name_secret_of(&a, PROJECT);

    // A removes R, with the phrase. What the name holds is as it was: A
    // carried it into the channel that the name moved to.
    let r_key = key_of(&r);
    let mut at = removes(&a, &r_key, &[], &words);
    at.says("The change is made (change 2)");
    assert_eq!(
        reads(&a, PROJECT),
        held,
        "removing r changed what the channel holds"
    );
    let moved_to = name_secret_of(&a, PROJECT);
    assert_ne!(channel_of(&left), channel_of(&moved_to));
    let said = at.done();
    assert!(said.contains("this machine may be closed"), "{said}");

    // R hears that it was removed, and stops: what it writes now, its own
    // node refuses, and writes nowhere.
    wait_for("r hears that it was removed", &[&relay, &a, &r], 90, || {
        (person_of(&r)["state"] == "removed").then_some(())
    });
    for key in ["edited.md", "created.md"] {
        let (status, said) = asks(
            &r,
            "/api/v1/channels/publish",
            serde_json::json!({ "channel": PROJECT, "key": key, "content": "after removal" }),
        );
        assert_eq!(status, 400, "{said}");
        let why = said["error"]["message"].as_str().unwrap_or_default();
        assert!(why.contains("has stopped, and publishes nothing"), "{said}");
    }

    // A removed device that does not stop writes on with its key, in the
    // channel that the others have left: above everything there, and as
    // high as a revision goes. That is at the relay.
    r.stop();
    let rogue = Arc::new(NodeIdentity::from_file(&r.data_dir().join("identity.key")).unwrap());
    assert_eq!(rogue.public_key(), key_bytes_of(&r));
    let later = |key: &str, rev: u64| -> Entry {
        let inside = Inside {
            name: key.to_string(),
            value: Value::Text("after removal".into()),
            chain: Some(Vec::new()),
        };
        Entry::seal(&left, &rogue, rev, &inside).unwrap()
    };
    // In the channel that the others moved to it can make no entry: it
    // signs as the author, and for the channel with the key of the one
    // it still holds.
    let mut in_the_new = Entry {
        channel: channel_of(&moved_to),
        ..later("edited.md", 3)
    };
    let form = in_the_new.signed_bytes();
    let under = |label: &[u8]| [label, form.as_slice()].concat();
    in_the_new.author_signature = rogue.sign(&under(LABEL_ENTRY_AUTHOR));
    in_the_new.channel_signature = cordelia_crypto::derive::signing_key(&left)
        .unwrap()
        .sign(&under(LABEL_ENTRY_CHANNEL));
    let client = client_as(rogue.clone(), &relay)
        .await
        .expect("the removed device's key still connects");
    let push = WireMessage::EntryPush(EntryPush {
        entries: vec![
            later("edited.md", MAX_REV).to_wire().into(),
            later("created.md", 2).to_wire().into(),
            in_the_new.to_wire().into(),
        ],
    });
    match client.ask(Protocol::EntryPush, push).await.unwrap() {
        WireMessage::EntryPushed(pushed) => assert_eq!(
            pushed.answers,
            [
                PushAnswer::Stored,
                PushAnswer::Stored,
                PushAnswer::Refused(EntryRefused::NotSigned)
            ]
        ),
        other => panic!("not an answer to a push: {other:?}"),
    }

    // A device added afterwards gets what the channel held.
    let all = [&relay, &a, &d];
    pair(&a, &d, "d", &all);
    wait_for(
        "the new device reads what the channel held",
        &all,
        120,
        || (reads(&d, PROJECT) == held).then_some(()),
    );
    // Long enough for what R wrote afterwards to have reached both, were
    // it to: it is at the relay, and they fetch from it every ten seconds.
    tokio::time::sleep(std::time::Duration::from_secs(25)).await;
    assert_eq!(
        reads(&a, PROJECT),
        held,
        "a shows what r wrote after its removal"
    );
    assert_eq!(
        reads(&d, PROJECT),
        held,
        "d shows what r wrote after its removal"
    );

    // The names stay writable, at the next revision: what R wrote after
    // its removal counts for nothing, on the device that knew it either.
    let published = publishes(&a, PROJECT, "edited.md", "by a again");
    assert_eq!(published["rev"], 3, "{published}");
    wait_for("d reads a's edit", &all, 90, || {
        (reads(&d, PROJECT).get("edited.md") == Some(&text("by a again"))).then_some(())
    });
}

/// T16. A relay's refusal is not delivery. A device's relay has no room:
/// it refuses the device's change entry, and each entry that the device
/// sends it; and its first answer to a push says nothing of any entry.
/// Each time, what was refused is kept and offered again, and the device
/// says that its relay does not hold the change and that something waits
/// there. Only when the relay stores it does nothing wait (decision
/// 2026-10-04 §4.6, §16).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t16_a_relays_refusal_is_not_taken_for_delivery() {
    const PROJECT: &str = "t16-refused";

    let relay = stand_in_relay();
    relay.has_room(false);
    relay.script.lock().unwrap().says_nothing_of = 1;
    let mut a = node_with_relays(
        "a",
        "personal",
        &[(format!("127.0.0.1:{}", relay.port), Some(relay.key.clone()))],
    );
    a.start();
    wait_for("node healthy", &[&a], 30, || healthy(&a));
    wait_for("connected to the relay", &[&a], 60, || has_hot_peer(&a));
    let status = |n: &Node| n.get("/api/v1/status").unwrap_or_default();
    let at_its_relay = |n: &Node| person_of(n)["relays"][0].clone();

    // A phrase, and an entry under a name: the device has its change
    // entry to show its relay, and entries of its own channels to send.
    syncs_notes_as(&a, PROJECT);
    makes_a_phrase(&a, "desktop");
    wait_for("the device holds the name", &[&a], 60, || {
        holds_name(&a, PROJECT)
    });
    let published = publishes(&a, PROJECT, "note.md", "a note");
    let item = published["entry"].as_str().unwrap().to_string();
    let change = cordelia_api::at_relays::to_show(&store_of(&a))
        .unwrap()
        .expect("the device keeps a change entry")
        .entry
        .id();

    // Refused, and refused again: the entry is still waiting, and the
    // device says that its relay refused for room and does not hold the
    // change.
    let refused = wait_for("the device says what its relay refused", &[&a], 90, || {
        let shown = relay.shown_whole();
        let shown = shown.iter().filter(|id| **id == change).count();
        (relay.pushes_of(&item) >= 3 && shown >= 2).then(|| at_its_relay(&a))
    });
    assert_eq!(refused["holds_latest"], false, "{refused}");
    let why = refused["no_room"].as_str().unwrap_or_default();
    assert!(
        why.contains("had no room for") && why.contains("it is full"),
        "{refused}"
    );
    assert!(status(&a)["outbox_waiting"].as_u64().unwrap() >= 1);
    let waiting = person_of(&a)["waiting"][0]["waits"].as_u64();
    assert!(waiting.unwrap() >= 1, "{}", person_of(&a));
    let said = a.cli(&["devices"]);
    assert!(
        said.contains("does not hold the latest change yet"),
        "{said}"
    );
    let offered_while_refused = relay.pushes_of(&item);

    // The relay has room: what was refused is offered once more, and
    // stored. Nothing waits any more, and the relay holds the change.
    relay.has_room(true);
    wait_for(
        "nothing waits once the relay stores what it refused",
        &[&a],
        120,
        || {
            let s = status(&a);
            let held = at_its_relay(&a)["holds_latest"] == true;
            has_sent_everything(&a)?;
            (held && s["outbox_waiting"] == 0 && s["outbox_refused"].as_array()?.is_empty())
                .then_some(())
        },
    );
    assert!(relay.pushes_of(&item) > offered_while_refused);
    // The first push of all was answered with an answer that said nothing
    // of any entry: each entry of it was offered again, or a later one
    // that the device wrote in its place.
    let pushes = relay.pushes();
    for first in &pushes[0] {
        let again = |later: &Entry| {
            (later.channel, later.slot, later.author) == (first.channel, first.slot, first.author)
                && later.rev >= first.rev
        };
        assert!(
            pushes[1..].iter().flatten().any(again),
            "an entry that the relay said nothing of was not offered again"
        );
    }
    assert!(relay.script.lock().unwrap().holds.contains(&change));
    let shown = relay.shown_whole();
    assert!(
        shown.iter().filter(|id| **id == change).count() >= 3,
        "the change was not shown again"
    );
}

/// T16. A removal reaches the devices that remain even when the relay loses
/// it. One device is away while another removes a third, and the relay then
/// loses everything it held. The device that removed goes on showing the
/// change, the one that was away applies it when it is back, and says so;
/// until then `cordelia devices` on the remover shows it as not having
/// applied the change (decision 2026-10-04 §4.6, §8).
#[test]
fn t16_a_removal_is_offered_again_when_the_relay_loses_it() {
    let mut relay = relay_started();
    let a = device_started("a", &relay);
    let mut b = device_started("b", &relay);
    let r = device_started("r", &relay);
    let (b_key, r_key) = (key_of(&b), key_of(&r));

    let words = pair(&a, &b, "b", &[&relay, &a, &b, &r]).expect("a makes the phrase");
    pair(&a, &r, "r", &[&relay, &a, &b, &r]);
    wait_for("b knows r as a device", &[&relay, &a, &b, &r], 90, || {
        devices_of(&b).contains(&r_key).then_some(())
    });
    wait_for(
        "b and r have said to a that they applied",
        &[&relay, &a, &b, &r],
        90,
        || {
            [&b_key, &r_key]
                .iter()
                .all(|key| applied_as_heard_by(&a, key) == Some(1))
                .then_some(())
        },
    );

    // B goes away. A removes R, and the relay has it: the command stays
    // until it does, and says of B that it has not applied the change.
    b.stop();
    let mut at = removes(&a, &r_key, &["stays"], &words);
    at.says("The change is made (change 2)");
    let said = at.done();
    assert!(said.contains("holds the change"), "{said}");
    assert!(said.contains("has not applied the change yet"), "{said}");
    // The relay loses everything it held.
    relay.stop();
    for file in ["cordelia.db", "cordelia.db-wal", "cordelia.db-shm"] {
        let _ = std::fs::remove_file(relay.data_dir().join(file));
    }

    // B is back, and has not heard: it still counts R as a device. A shows
    // that B has not applied the change.
    b.start();
    wait_for("b healthy again", &[&a, &b, &r], 30, || healthy(&b));
    assert_eq!(person_of(&b)["change"], 1, "b heard of the removal");
    assert!(devices_of(&b).contains(&r_key), "b heard of the removal");
    assert_ne!(
        applied_as_heard_by(&a, &b_key),
        Some(2),
        "a does not show b as waiting: {}",
        person_of(&a)
    );
    let said = a.cli(&["devices"]);
    assert!(said.contains("has not applied change 2 yet"), "{said}");

    // The relay is back, with nothing. A shows it the removal again. B
    // applies it and says so.
    relay.start();
    let all = [&relay, &a, &b, &r];
    wait_for("relay healthy again", &all, 30, || healthy(&relay));
    wait_for("b drops r", &all, 240, || {
        (person_of(&b)["change"] == 2 && !devices_of(&b).contains(&r_key)).then_some(())
    });
    wait_for("a hears that b holds it", &all, 120, || {
        (applied_as_heard_by(&a, &b_key) == Some(2)).then_some(())
    });
    let said = a.cli(&["devices"]);
    assert!(said.contains("has applied change 2"), "{said}");
    assert!(!said.contains("has not applied change 2 yet"), "{said}");
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

/// What a client holds as a device holds its channels, how its answers may
/// depart from an honest device's, and what the relay has asked it.
#[derive(Clone, Default)]
struct Held {
    /// The entries held. A test may add to them while the relay is
    /// connected.
    items: Arc<Mutex<Vec<cordelia_network::messages::Item>>>,
    /// What it answers when asked which channels it holds, if not the
    /// channels of the entries held.
    lists: Option<Vec<String>>,
    /// Entries nobody asked for, added to each answer to a fetch.
    unasked: Vec<cordelia_network::messages::Item>,
    /// Answer a request for a page with every entry of the channel,
    /// whatever size of page was asked for.
    ignores_page_size: bool,
    /// Each time it is asked which channels it holds, answer with this
    /// many names made up for the occasion, never the same twice. And
    /// answer each request for a page of one with an empty page that says
    /// there is more.
    makes_up_names: usize,
    /// What the relay asked, one for each time it asked what is held.
    passes: Arc<Mutex<Vec<Pass>>>,
}

/// What a relay asked in one pass over what a client holds.
#[derive(Clone, Default)]
struct Pass {
    /// The channel of each request for a list of entries.
    listed: Vec<String>,
    /// The size of page asked for, with each request for a list.
    limits: Vec<u32>,
    /// How many requests for entries.
    fetches: usize,
    /// The entries asked for, by ID, in the order asked.
    asked: Vec<String>,
}

impl Held {
    fn of(items: Vec<cordelia_network::messages::Item>) -> Self {
        Self {
            items: Arc::new(Mutex::new(items)),
            ..Self::default()
        }
    }

    fn passes(&self) -> Vec<Pass> {
        self.passes.lock().unwrap().clone()
    }
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
    client_as(Arc::new(NodeIdentity::generate().unwrap()), relay).await
}

/// Connect a client with the key `identity` to `relay`.
async fn client_as(identity: Arc<NodeIdentity>, relay: &Node) -> Result<Client, String> {
    use cordelia_network::{connection, transport};
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

/// Ask one thing on a new stream of `protocol` on `conn`, and read the
/// answer. `Err` where the stream was refused, or nothing was answered.
async fn ask_on(
    conn: &quinn::Connection,
    protocol: Protocol,
    request: WireMessage,
) -> Result<WireMessage, String> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    let mut stream = tokio::io::join(&mut recv, &mut send);
    let answer = cordelia_network::codec::send_request(&mut stream, protocol, &request)
        .await
        .map_err(|e| e.to_string());
    let _ = send.finish();
    answer
}

impl Client {
    /// Ask one thing on a new stream of `protocol`, and read the answer.
    async fn ask(&self, protocol: Protocol, request: WireMessage) -> Result<WireMessage, String> {
        ask_on(&self.conn, protocol, request).await
    }

    /// An entry of `bytes` bytes, signed by this client, as it travels.
    fn entry(&self, bytes: usize) -> cordelia_network::messages::Item {
        // Distinct content for each entry.
        let mut blob = vec![7u8; bytes];
        let tag = cordelia_storage::items::generate_item_id();
        let tag = tag.as_bytes();
        blob[..tag.len().min(bytes)].copy_from_slice(&tag[..tag.len().min(bytes)]);
        self.entry_of(blob)
    }

    /// Close the connection, as a device that goes away does.
    async fn close(self) {
        self.conn.close(0u32.into(), b"done");
        // Long enough for the relay to be told.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    /// An entry with this ciphertext, signed by this client.
    fn entry_of(&self, blob: Vec<u8>) -> cordelia_network::messages::Item {
        let channel = "grp_550e8400-e29b-41d4-a716-446655440000";
        let item_id = cordelia_storage::items::generate_item_id();
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

/// T3. Small entries count for what they take. A connection's allowance
/// counts each entry as its ciphertext and what an entry takes beyond it, a
/// kilobyte. So fifteen kilobytes of ciphertext, in entries of eight bytes,
/// use most of two megabytes, and the next push is refused.
///
/// The entries go in two pushes, so that a slow machine has time to check
/// each one's signatures before the push times out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_small_entries_count_for_what_they_take() {
    use cordelia_core::protocol::{PUSH_BYTES_PER_PEER_PER_MINUTE, entry_cost};
    const SMALL: usize = 8;
    const HALF: u64 = 950;
    const FIRST: u64 = 2 * HALF;

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let client = client_of(&relay).await.expect("the client connects");
    let stored = || -> u64 {
        serde_json::from_str::<serde_json::Value>(&relay.cli(&["stats", "--json"])).unwrap()
            ["items_stored"]
            .as_u64()
            .unwrap()
    };
    let small = |from: u64, count: u64| -> Vec<_> {
        (from..from + count)
            .map(|n| client.entry_of(n.to_be_bytes().to_vec()))
            .collect()
    };

    // What the first push costs is within the allowance; with the second
    // it would be over.
    assert!(FIRST * entry_cost(SMALL) <= PUSH_BYTES_PER_PEER_PER_MINUTE);
    assert!((FIRST + 200) * entry_cost(SMALL) > PUSH_BYTES_PER_PEER_PER_MINUTE);

    for half in 0..2 {
        let ack = client.push(&small(half * HALF, HALF)).await.unwrap();
        assert_eq!(u64::from(ack.stored), HALF, "{ack:?}");
    }
    assert!(
        client.push(&small(FIRST, 200)).await.is_err(),
        "small entries were taken past the allowance"
    );
    assert_eq!(stored(), FIRST);
    // What is left of the allowance still takes a push that fits in it.
    let ack = client.push(&small(FIRST, 100)).await.unwrap();
    assert_eq!(ack.stored, 100, "{ack:?}");
}

/// T3. An address's allowance lasts as long as what was counted against it,
/// whether or not its connections do. Five connections from one address
/// push what the address may in a minute, and close. A new connection from
/// that address, under a new key, is refused another megabyte.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_an_addresss_allowance_outlasts_its_connections() {
    use cordelia_core::protocol::{MAX_CONNECTIONS_PER_IP, MAX_ITEM_BYTES};

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let connected = || -> usize {
        relay
            .get("/api/v1/peers")
            .and_then(|v| v["peers"].as_array().map(Vec::len))
            .unwrap_or(usize::MAX)
    };

    // Fifteen entries of the largest size are just under a megabyte, and
    // two such pushes are what one connection may send in a minute.
    let megabyte =
        |client: &Client| -> Vec<_> { (0..15).map(|_| client.entry(MAX_ITEM_BYTES)).collect() };
    let mut clients = Vec::new();
    for n in 0..MAX_CONNECTIONS_PER_IP {
        let client = client_of(&relay)
            .await
            .unwrap_or_else(|e| panic!("connection {n} was refused: {e}"));
        for push in 0..2 {
            let ack = client.push(&megabyte(&client)).await.unwrap();
            assert_eq!(ack.stored, 15, "connection {n}, push {push}: {ack:?}");
        }
        clients.push(client);
    }

    // They all close, and the relay tidies its counts.
    for client in clients {
        client.close().await;
    }
    wait_for("the relay sees them gone", &[&relay], 30, || {
        (connected() == 0).then_some(())
    });
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;

    // The address comes back under a new key. Its allowance for the minute
    // is still used.
    let again = client_of(&relay).await.expect("the address connects again");
    assert!(
        again.push(&megabyte(&again)).await.is_err(),
        "the address had a fresh allowance after connecting again"
    );
    let stats: serde_json::Value = serde_json::from_str(&relay.cli(&["stats", "--json"])).unwrap();
    assert_eq!(
        stats["items_stored"],
        30 * MAX_CONNECTIONS_PER_IP,
        "{stats}"
    );
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
        self.resigned_in(self.entry(bytes), channel)
    }

    /// `item` moved to `channel` and signed again by this client.
    fn resigned_in(
        &self,
        mut item: cordelia_network::messages::Item,
        channel: &str,
    ) -> cordelia_network::messages::Item {
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

    /// An entry under a name: `slot` at revision `rev`, of `bytes` bytes,
    /// in `channel`, signed by this client. A later revision replaces an
    /// earlier one of the same slot.
    fn keyed_in(
        &self,
        channel: &str,
        slot: [u8; 32],
        rev: u64,
        bytes: usize,
    ) -> cordelia_network::messages::Item {
        let mut item = self.entry(bytes);
        let hash: [u8; 32] = item.content_hash.clone().try_into().unwrap();
        let cbor = cordelia_crypto::signing::ItemMetadata {
            author_id: &self.identity.public_key(),
            channel_id: channel,
            content_hash: &hash,
            is_tombstone: false,
            item_id: &item.item_id,
            key_version: 1,
            published_at: &item.published_at,
            slot: Some(&slot),
            rev: Some(rev),
        }
        .encode()
        .unwrap();
        item.channel_id = channel.into();
        item.slot = Some(slot.to_vec());
        item.rev = Some(rev);
        item.signature = self.identity.sign(&cbor).to_vec();
        item
    }

    /// Hold entries as a device holds its channels, and answer the relay
    /// when it asks: which channels, what each lists, and the entries.
    /// `held` says what is held and how the answers may depart from what an
    /// honest device gives, and records what the relay asked.
    fn serve(&self, held: Held) {
        use cordelia_network::codec;
        use cordelia_network::messages::{
            FetchResponse, ItemHeader, SyncChannelListResponse, SyncResponse,
        };
        let conn = self.conn.clone();
        tokio::spawn(async move {
            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                if !matches!(
                    codec::read_protocol_byte(&mut recv).await,
                    Ok(Protocol::ItemSync)
                ) {
                    continue;
                }
                let mut pass = Pass::default();
                while let Ok(msg) = codec::read_frame(&mut recv).await {
                    let items = held.items.lock().unwrap().clone();
                    let answer = match msg {
                        WireMessage::SyncChannelListRequest(_) if held.makes_up_names > 0 => {
                            let passes = held.passes.lock().unwrap().len();
                            WireMessage::SyncChannelListResponse(SyncChannelListResponse {
                                channel_ids: (0..held.makes_up_names)
                                    .map(|n| format!("grp_made-up-{passes:06}-{n:06}"))
                                    .collect(),
                            })
                        }
                        WireMessage::SyncRequest(req) if held.makes_up_names > 0 => {
                            pass.listed.push(req.channel_id.clone());
                            pass.limits.push(req.limit);
                            WireMessage::SyncResponse(SyncResponse {
                                items: Vec::new(),
                                has_more: true,
                                last_seq: Some(req.after_seq.unwrap_or(0) + 1),
                            })
                        }
                        WireMessage::SyncChannelListRequest(_) => {
                            let channel_ids = held.lists.clone().unwrap_or_else(|| {
                                let ids: BTreeSet<String> =
                                    items.iter().map(|i| i.channel_id.clone()).collect();
                                ids.into_iter().collect()
                            });
                            WireMessage::SyncChannelListResponse(SyncChannelListResponse {
                                channel_ids,
                            })
                        }
                        // An entry's place in its channel's list is its
                        // place among the entries held, from 1.
                        WireMessage::SyncRequest(req) => {
                            pass.listed.push(req.channel_id.clone());
                            pass.limits.push(req.limit);
                            let after = req.after_seq.unwrap_or(0);
                            let of: Vec<(u64, &cordelia_network::messages::Item)> = items
                                .iter()
                                .filter(|i| i.channel_id == req.channel_id)
                                .zip(1u64..)
                                .map(|(i, seq)| (seq, i))
                                .collect();
                            let most = if held.ignores_page_size {
                                usize::MAX
                            } else {
                                req.limit as usize
                            };
                            let page: Vec<&(u64, &cordelia_network::messages::Item)> = of
                                .iter()
                                .filter(|(seq, _)| *seq > after)
                                .take(most)
                                .collect();
                            let last = page.last().map_or(after, |(seq, _)| *seq);
                            WireMessage::SyncResponse(SyncResponse {
                                items: page
                                    .iter()
                                    .map(|(_, i)| ItemHeader {
                                        item_id: i.item_id.clone(),
                                        channel_id: i.channel_id.clone(),
                                        item_type: i.item_type.clone(),
                                        content_hash: i.content_hash.clone(),
                                        author_id: i.author_id.clone(),
                                        signature: i.signature.clone(),
                                        key_version: i.key_version,
                                        published_at: i.published_at.clone(),
                                        is_tombstone: i.is_tombstone,
                                        parent_id: i.parent_id.clone(),
                                        slot: i.slot.clone(),
                                        rev: i.rev,
                                    })
                                    .collect(),
                                has_more: of.last().is_some_and(|(seq, _)| *seq > last),
                                last_seq: Some(last),
                            })
                        }
                        WireMessage::FetchRequest(req) => {
                            pass.fetches += 1;
                            pass.asked.extend(req.item_ids.iter().cloned());
                            let mut answer: Vec<_> = items
                                .iter()
                                .filter(|i| req.item_ids.contains(&i.item_id))
                                .cloned()
                                .collect();
                            answer.extend(held.unasked.iter().cloned());
                            WireMessage::FetchResponse(FetchResponse { items: answer })
                        }
                        _ => break,
                    };
                    if codec::write_frame(&mut send, &answer).await.is_err() {
                        break;
                    }
                }
                held.passes.lock().unwrap().push(pass);
            }
        });
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

/// What a relay's database holds, from `cordelia stats`: how many entries,
/// and their bytes.
fn relay_holds(relay: &Node) -> (u64, u64) {
    let stats: serde_json::Value = serde_json::from_str(&relay.cli(&["stats", "--json"])).unwrap();
    (
        stats["items_stored"].as_u64().unwrap(),
        stats["content_bytes_stored"].as_u64().unwrap(),
    )
}

/// T3. What a relay fetches from a peer is bounded as what the peer may
/// push is, and a fetch stores only what was asked for. A device holds
/// three megabytes of entries that its relay lacks. The relay has another
/// peer as its hot peer, as two relays that list each other have, so the
/// device is not one of its hot peers.
///
/// The relay asks the device all the same when the device connects, takes
/// no more than a connection may push in a minute, and takes the rest once
/// the minute has passed. The device adds entries that were not asked for
/// to every answer; the relay stores none of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_a_relay_fetches_from_a_peer_no_faster_than_the_peer_may_push() {
    use cordelia_core::protocol::PUSH_BYTES_PER_PEER_PER_MINUTE;
    const ENTRY: usize = 30_000;
    const ENTRIES: usize = 100;
    let total = (ENTRY * ENTRIES) as u64;

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    // The relay's one hot place goes to the first peer that connects.
    let mut first = node("first", "personal", Some(relay.p2p));
    first.start();
    wait_for("first healthy", &[&relay, &first], 30, || healthy(&first));
    wait_for("first connected", &[&relay, &first], 60, || {
        has_hot_peer(&first)
    });
    assert_eq!(relay_holds(&relay), (0, 0));

    let device = client_of(&relay).await.expect("the device connects");
    let channel = "grp_550e8400-e29b-41d4-a716-446655440077";
    let held = Held {
        // Five entries of another size that are never listed.
        unasked: (0..5).map(|_| device.entry_in(channel, 2_000)).collect(),
        ..Held::of(
            (0..ENTRIES)
                .map(|_| device.entry_in(channel, ENTRY))
                .collect(),
        )
    };
    device.serve(held);

    // The relay asks the device, and takes what a connection may push in a
    // minute, and no more for now.
    wait_for("the relay fetches from the device", &[&relay], 40, || {
        (relay_holds(&relay).1 > 0).then_some(())
    });
    let mut most = 0;
    for _ in 0..20 {
        let (entries, bytes) = relay_holds(&relay);
        // Only what was asked for is stored: every entry is one of those
        // the device listed.
        assert_eq!(bytes, entries * ENTRY as u64, "an entry nobody asked for");
        most = most.max(bytes);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    assert!(
        most <= PUSH_BYTES_PER_PEER_PER_MINUTE,
        "the relay fetched {most} bytes within the minute"
    );
    assert!(most < total, "{most}");

    // Once the minute has passed it takes the rest.
    wait_for("the relay fetches the rest", &[&relay], 150, || {
        (relay_holds(&relay) == (ENTRIES as u64, total)).then_some(())
    });
}

/// T3. Nothing is lost when a relay drops a channel to make room. A relay
/// holds an older channel and a newer one, which it fetched from a device.
/// The older one grows, and the relay drops the newer one. While there is
/// no room, the relay tries the newer channel again and drops it again.
/// Then the older one shrinks. The relay asks the device again, lists the
/// newer channel from the start, and holds all of it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_a_channel_a_relay_dropped_comes_back_when_there_is_room() {
    const LARGE: usize = 60_000;
    let channel = |n: usize| format!("grp_550e8400-e29b-41d4-a716-{n:012}");
    let (older, newer) = (channel(0), channel(1));
    let name = |n: u8| [n; 32];

    let relay = node("relay", "relay", None);
    relay.max_storage_bytes(1_000_000);
    relay.relay_ask_again_secs(3);
    let mut relay = relay;
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let client = client_of(&relay).await.expect("the client connects");

    // The older channel, written under names so that it can shrink later.
    let ack = client
        .push(&[client.keyed_in(&older, name(0), 1, LARGE)])
        .await
        .unwrap();
    assert_eq!(ack.stored, 1, "{ack:?}");

    // The newer channel is held by the client as a device holds one: more
    // small entries than one page lists, then a few large ones. So it
    // takes the relay two pages to list it, and the large ones come in the
    // second. The relay asks, and fetches it.
    const SMALL: u64 = 120;
    const HELD: u64 = SMALL + 8;
    client.serve(Held::of(
        (0..HELD)
            .map(|n| client.entry_in(&newer, if n < SMALL { 100 } else { 11_000 }))
            .collect(),
    ));
    wait_for("the relay fetches the newer channel", &[&relay], 40, || {
        (relay_holds(&relay).0 == 1 + HELD).then_some(())
    });

    // The older channel grows until the relay has dropped the newer one.
    let mut names = 1u8;
    loop {
        let ack = client
            .push(&[client.keyed_in(&older, name(names), 1, LARGE)])
            .await
            .unwrap();
        assert_eq!(ack.stored, 1, "{ack:?}");
        names += 1;
        if relay_holds(&relay).0 == u64::from(names) {
            break;
        }
        assert!(names < 20, "the relay never dropped the newer channel");
    }
    assert_eq!(client.listed(&newer).await, 0);

    // There is room for the newer channel's first page and not for all
    // of it. The relay tries it again, and drops it again when the large
    // entries of the second page do not fit: by then its place had moved
    // past the first page.
    tokio::time::sleep(std::time::Duration::from_secs(15)).await;

    // The older channel shrinks: each name gets a small entry in place of
    // its large one.
    for n in 0..names {
        let ack = client
            .push(&[client.keyed_in(&older, name(n), 2, 1_000)])
            .await
            .unwrap();
        assert_eq!(ack.stored, 1, "{ack:?}");
    }

    // The relay asks the device again, and the newer channel is back, whole.
    wait_for("the newer channel is back", &[&relay], 90, || {
        (relay_holds(&relay).0 == u64::from(names) + HELD).then_some(())
    });
    assert_eq!(client.listed(&older).await, usize::from(names));
}

/// T3. What a peer lists is the peer's to write, so a relay bounds it. One
/// peer says it holds three thousand channels: the relay asks about so many
/// and no more in one pass. Another lists a few channels and one with an ID
/// far longer than a channel's can be: the relay asks about the few, and
/// never about the long one. (Among three thousand the long one would be
/// asked about only by chance.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_a_relay_asks_a_peer_about_only_so_many_channels() {
    use cordelia_core::protocol::{MAX_CHANNEL_ID_LEN, MAX_CHANNELS_ASKED_OF_A_PEER};
    const FEW: usize = 10;
    let channel = |n: usize| format!("grp_550e8400-e29b-41d4-a716-{n:012}");

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));

    let many = client_of(&relay).await.expect("the first peer connects");
    let held_many = Held {
        lists: Some((0..3000).map(channel).collect()),
        ..Held::default()
    };
    many.serve(held_many.clone());
    let pass = wait_for("the relay asks the first peer", &[&relay], 60, || {
        held_many.passes().into_iter().next()
    });
    assert_eq!(pass.listed.len(), MAX_CHANNELS_ASKED_OF_A_PEER);

    let few = client_of(&relay).await.expect("the second peer connects");
    let mut lists: Vec<String> = (0..FEW).map(channel).collect();
    lists.push("x".repeat(50_000));
    let held_few = Held {
        lists: Some(lists),
        ..Held::default()
    };
    few.serve(held_few.clone());
    let pass = wait_for("the relay asks the second peer", &[&relay], 60, || {
        held_few.passes().into_iter().next()
    });
    assert!(
        pass.listed.iter().all(|id| id.len() <= MAX_CHANNEL_ID_LEN),
        "the relay asked about a channel with an ID no channel has"
    );
    assert_eq!(pass.listed.len(), FEW);
}

/// What a relay's log says it keeps for its peers (places in their lists,
/// and page sizes), at each cycle.
fn places_kept(relay: &Node) -> Vec<u64> {
    let log = std::fs::read_to_string(relay.log()).unwrap_or_default();
    // The log has colour codes around each field's name.
    let mut plain = String::with_capacity(log.len());
    let mut chars = log.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            plain.push(c);
        }
    }
    plain
        .lines()
        .filter(|line| line.contains("pull-sync cycle"))
        .filter_map(|line| {
            line.split_whitespace()
                .find_map(|field| field.strip_prefix("places="))
                .and_then(|n| n.parse().ok())
        })
        .collect()
}

/// T3. A relay keeps nothing for names a peer makes up. A peer says it
/// holds a thousand channels, different ones each time it is asked, and
/// answers each request with an empty page that says there is more. The
/// relay asks about each name once, and keeps a place in none of them:
/// nothing is kept where a peer lists nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_a_relay_keeps_nothing_for_names_a_peer_makes_up() {
    use cordelia_core::protocol::MAX_CHANNELS_ASKED_OF_A_PEER;

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let peer = client_of(&relay).await.expect("the peer connects");
    let held = Held {
        makes_up_names: MAX_CHANNELS_ASKED_OF_A_PEER,
        ..Held::default()
    };
    peer.serve(held.clone());

    wait_for("the relay asks the peer three times", &[&relay], 90, || {
        (held.passes().len() >= 3).then_some(())
    });
    for (n, pass) in held.passes().iter().enumerate() {
        // Once about each name: an empty page is the end, whatever it says.
        assert_eq!(pass.listed.len(), MAX_CHANNELS_ASKED_OF_A_PEER, "pass {n}");
        assert_eq!(pass.fetches, 0, "pass {n}");
    }
    let kept = places_kept(&relay);
    assert!(kept.len() >= 3, "{kept:?}");
    assert!(
        kept.iter().all(|places| *places == 0),
        "the relay kept places for names a peer made up: {kept:?}"
    );
    assert_eq!(relay_holds(&relay), (0, 0));
}

/// T3. A relay gets past what it will not store. A device holds a channel
/// that begins with more than a page of entries the relay refuses (their
/// signatures are not good), then one whose header shows a field over its
/// size, then entries that are as they should be. It holds a second channel
/// with nothing in it that the relay takes.
///
/// The relay ends up with every entry that is as it should be. It asks for
/// each of the others once, not once a page or once a pass, and never for
/// the one whose header shows it will be refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_a_relay_gets_past_what_it_will_not_store() {
    use cordelia_core::protocol::MAX_ITEM_TYPE_LEN;
    const REFUSED: usize = 120;
    const GOOD: usize = 30;
    let mixed = "grp_550e8400-e29b-41d4-a716-000000000001";
    let refused_only = "grp_550e8400-e29b-41d4-a716-000000000002";

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let device = client_of(&relay).await.expect("the device connects");

    let not_good = |channel: &str| {
        let mut item = device.entry_in(channel, 100);
        item.signature[0] ^= 1;
        item
    };
    let mut long_type = device.entry_in(mixed, 100);
    long_type.item_type = "x".repeat(MAX_ITEM_TYPE_LEN + 1);
    let mut items: Vec<_> = (0..REFUSED).map(|_| not_good(mixed)).collect();
    items.push(long_type.clone());
    items.extend((0..GOOD).map(|_| device.entry_in(mixed, 100)));
    items.extend((0..REFUSED + GOOD).map(|_| not_good(refused_only)));
    let held = Held::of(items);
    device.serve(held.clone());

    wait_for("the relay asks the device twice", &[&relay], 90, || {
        (held.passes().len() >= 2).then_some(())
    });
    let passes = held.passes();
    assert_eq!(
        relay_holds(&relay).0,
        GOOD as u64,
        "the relay did not get past what it will not store"
    );
    let asked: Vec<&String> = passes.iter().flat_map(|pass| &pass.asked).collect();
    assert!(
        !asked.contains(&&long_type.item_id),
        "asked for an entry whose header shows it will be refused"
    );
    let distinct: BTreeSet<&String> = asked.iter().copied().collect();
    assert_eq!(
        (asked.len(), distinct.len()),
        (2 * (REFUSED + GOOD), 2 * (REFUSED + GOOD)),
        "each entry is asked for once"
    );
    assert!(
        passes[1].asked.is_empty(),
        "asked again for {} entries it had been through",
        passes[1].asked.len()
    );
}

/// T3. A relay keeps only so many places for one peer. A peer lists more
/// channels than a relay asks about in one pass, each with an entry the
/// relay fetches and refuses, so that there is a place to keep in each.
/// Over three passes the relay asks about more channels than it may keep
/// places for, and keeps no more than it may.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_a_relay_keeps_only_so_many_places_for_a_peer() {
    use cordelia_core::protocol::MAX_CHANNELS_ASKED_OF_A_PEER;
    const CHANNELS: usize = MAX_CHANNELS_ASKED_OF_A_PEER + 200;

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let peer = client_of(&relay).await.expect("the peer connects");
    let held = Held::of(
        (0..CHANNELS)
            .map(|n| {
                let mut item = peer.entry_in(&format!("grp_550e8400-e29b-41d4-a716-{n:012}"), 8);
                item.signature[0] ^= 1;
                item
            })
            .collect(),
    );
    peer.serve(held.clone());

    wait_for(
        "the relay asks the peer three times",
        &[&relay],
        180,
        || (held.passes().len() >= 3).then_some(()),
    );
    let passes = held.passes();
    let asked_about: BTreeSet<&String> = passes.iter().flat_map(|pass| &pass.listed).collect();
    assert!(
        asked_about.len() > MAX_CHANNELS_ASKED_OF_A_PEER,
        "asked about {} channels",
        asked_about.len()
    );
    let kept = places_kept(&relay);
    assert_eq!(
        kept.iter().max(),
        Some(&(MAX_CHANNELS_ASKED_OF_A_PEER as u64)),
        "{kept:?}"
    );
    assert_eq!(relay_holds(&relay), (0, 0));

    // Once the peer has gone, what was kept for it is forgotten. (Another
    // peer stays, so that the relay goes on saying what it keeps.)
    let stays = client_of(&relay).await.expect("another peer connects");
    stays.serve(Held::default());
    peer.close().await;
    wait_for(
        "the relay forgets the places it kept",
        &[&relay],
        90,
        || (places_kept(&relay).last() == Some(&0)).then_some(()),
    );
}

/// A relay that asked a device for fewer entries at a time, because a page
/// of them did not fit in one message, asks for whole pages again once it
/// has caught up with that channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_asks_for_whole_pages_again_once_caught_up() {
    use cordelia_core::protocol::SYNC_PAGE_STEPS;
    let large = "grp_550e8400-e29b-41d4-a716-000000000001";

    let mut relay = node("relay", "relay", None);
    relay.relay_ask_again_secs(2);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let device = client_of(&relay).await.expect("the device connects");
    // Thirty entries that are more than a megabyte together: the first
    // request for them cannot be answered, and the relay asks for fewer.
    let held = Held::of((0..30).map(|_| device.entry_in(large, 40_000)).collect());
    device.serve(held.clone());
    wait_for("the relay holds the channel", &[&relay], 120, || {
        (relay_holds(&relay).0 == 30).then_some(())
    });
    let asked_fewer = held
        .passes()
        .iter()
        .flat_map(|pass| pass.limits.clone())
        .any(|limit| limit < SYNC_PAGE_STEPS[0]);
    assert!(asked_fewer, "the relay never asked for fewer");

    // The device comes to hold a few more, small ones, once what the relay
    // fetched has left the minute it counts against the device: until then
    // the relay asks for fewer for that reason. It asks for them a whole
    // page at a time.
    tokio::time::sleep(std::time::Duration::from_secs(
        cordelia_core::protocol::RATE_WINDOW_SECS + 1,
    ))
    .await;
    let before = held.passes().len();
    held.items
        .lock()
        .unwrap()
        .extend((0..5).map(|_| device.entry_in(large, 100)));
    wait_for("the relay holds the new entries", &[&relay], 60, || {
        (relay_holds(&relay).0 == 35).then_some(())
    });
    let later: Vec<u32> = held.passes()[before..]
        .iter()
        .flat_map(|pass| pass.limits.clone())
        .collect();
    assert!(!later.is_empty());
    assert!(
        later.iter().all(|limit| *limit == SYNC_PAGE_STEPS[0]),
        "asked for {later:?} after it had caught up"
    );
}

/// T3. A relay does not fetch what it has no room for. A device holds
/// twenty channels, and one address may make a relay hold sixteen new
/// channels in an hour. The relay fetches sixteen. For the other four it
/// asks for nothing, in that pass or the next.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_a_relay_does_not_fetch_what_it_has_no_room_for() {
    use cordelia_core::protocol::NEW_CHANNELS_PER_ADDRESS_PER_HOUR;
    const CHANNELS: usize = 20;

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let device = client_of(&relay).await.expect("the device connects");
    let held = Held::of(
        (0..CHANNELS)
            .map(|n| device.entry_in(&format!("grp_550e8400-e29b-41d4-a716-{n:012}"), 100))
            .collect(),
    );
    device.serve(held.clone());

    wait_for("the relay asks the device twice", &[&relay], 60, || {
        (held.passes().len() >= 2).then_some(())
    });
    let passes = held.passes();
    assert_eq!(
        relay_holds(&relay).0,
        NEW_CHANNELS_PER_ADDRESS_PER_HOUR as u64
    );
    // One request for entries for each channel it took, and none since.
    assert_eq!(passes[0].fetches, NEW_CHANNELS_PER_ADDRESS_PER_HOUR);
    assert_eq!(passes[0].listed.len(), NEW_CHANNELS_PER_ADDRESS_PER_HOUR);
    assert_eq!(passes[1].fetches, 0);
    assert_eq!(passes[1].listed.len(), NEW_CHANNELS_PER_ADDRESS_PER_HOUR);
}

/// A relay that asks a device for what it lacks gets all of it without
/// long waits, though it asks a device again only every ten minutes. Two
/// devices, neither one of the relay's hot peers:
///
/// - one holds a channel whose entries do not fit in one message at the
///   size of page the relay first asks for;
/// - one holds a channel with more entries than one pass takes.
///
/// Each time, the relay comes back at the next cycle for the rest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_fetches_all_a_device_holds_without_long_waits() {
    const LARGE: usize = 30;
    const SMALL: usize = 1100;
    let large = "grp_550e8400-e29b-41d4-a716-000000000001";
    let long = "grp_550e8400-e29b-41d4-a716-000000000002";

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    // The relay's one hot place goes to the first peer that connects.
    let mut first = node("first", "personal", Some(relay.p2p));
    first.start();
    wait_for("first healthy", &[&relay, &first], 30, || healthy(&first));
    wait_for("first connected", &[&relay, &first], 60, || {
        has_hot_peer(&first)
    });

    // Thirty entries that are more than a megabyte together: the first
    // request for them cannot be answered, and the relay asks for fewer.
    let device = client_of(&relay).await.expect("the device connects");
    device.serve(Held::of(
        (0..LARGE).map(|_| device.entry_in(large, 40_000)).collect(),
    ));
    wait_for("the relay holds the large entries", &[&relay], 45, || {
        (relay_holds(&relay).0 == LARGE as u64).then_some(())
    });

    // Eleven hundred small entries: more than the ten pages one pass takes.
    let other = client_of(&relay).await.expect("the other device connects");
    other.serve(Held::of(
        (0..SMALL as u64)
            .map(|n| other.resigned_in(other.entry_of(n.to_be_bytes().to_vec()), long))
            .collect(),
    ));
    wait_for(
        "the relay holds the long channel too",
        &[&relay],
        50,
        || (relay_holds(&relay).0 == (LARGE + SMALL) as u64).then_some(()),
    );
}

/// A relay asks a device again every so often, without the device
/// connecting again: an entry the device comes to hold later is fetched.
/// The device is not one of the relay's hot peers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_asks_a_device_again_every_so_often() {
    let channel = "grp_550e8400-e29b-41d4-a716-000000000003";
    let relay = node("relay", "relay", None);
    relay.relay_ask_again_secs(5);
    let mut relay = relay;
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let mut first = node("first", "personal", Some(relay.p2p));
    first.start();
    wait_for("first healthy", &[&relay, &first], 30, || healthy(&first));
    wait_for("first connected", &[&relay, &first], 60, || {
        has_hot_peer(&first)
    });

    let device = client_of(&relay).await.expect("the device connects");
    let held = Held::of(vec![device.entry_in(channel, 1_000)]);
    device.serve(held.clone());
    wait_for(
        "the relay fetches what the device holds",
        &[&relay],
        40,
        || (relay_holds(&relay).0 == 1).then_some(()),
    );

    // The device comes to hold one more. The relay asks again, and has it.
    held.items
        .lock()
        .unwrap()
        .push(device.entry_in(channel, 1_000));
    wait_for(
        "the relay asks again and fetches the new entry",
        &[&relay],
        40,
        || (relay_holds(&relay).0 == 2).then_some(()),
    );
}

/// T3. A peer that answers a request for a page with more than the page
/// asked for is not fetched from: the size of a page is how a relay keeps
/// what it takes within the peer's allowance.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_a_page_longer_than_the_one_asked_for_is_not_taken() {
    let channel = "grp_550e8400-e29b-41d4-a716-000000000004";
    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let peer = client_of(&relay).await.expect("the peer connects");

    // More entries than the largest page a relay asks for.
    let entries = 3 * cordelia_core::protocol::DEFAULT_SYNC_LIMIT / 2;
    let held = Held {
        ignores_page_size: true,
        ..Held::of((0..entries).map(|_| peer.entry_in(channel, 100)).collect())
    };
    peer.serve(held.clone());
    wait_for("the relay asks the peer", &[&relay], 60, || {
        (!held.passes().is_empty()).then_some(())
    });
    let pass = &held.passes()[0];
    assert_eq!(pass.listed, vec![channel.to_string()]);
    assert_eq!(
        pass.fetches, 0,
        "the relay fetched from a page it did not ask for"
    );
    assert_eq!(relay_holds(&relay), (0, 0));
}

/// A device answers its relay's request of the older kind with nothing,
/// as a device that holds no channel of that kind would (decision
/// 2026-10-04 §10.1). A relay asks each of its devices which channels it
/// holds: answered, it asks again at its usual pace, which this relay is
/// set up to make short. A device that refused the request would be asked
/// again only a minute later, as a peer that failed to answer is.
#[test]
fn a_device_answers_its_relays_request_of_the_older_kind_with_nothing() {
    let mut relay = node("relay", "relay", None);
    relay.relay_ask_again_secs(1);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let a = device_started("a", &relay);

    let answered = || {
        let log = std::fs::read_to_string(a.log()).unwrap_or_default();
        log.matches("answered a sync of the older kind with nothing")
            .count()
    };
    // Asked, answered, and asked again within the relay's own pace: three
    // times in well under the minute that a failure would cost.
    let began = std::time::Instant::now();
    wait_for(
        "the relay asks its device again and again",
        &[&relay, &a],
        50,
        || (answered() >= 3).then_some(()),
    );
    assert!(
        began.elapsed() < std::time::Duration::from_secs(55),
        "{:?}",
        began.elapsed()
    );
}
