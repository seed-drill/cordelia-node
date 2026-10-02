//! The threat model, as tests.
//!
//! `docs/security/threat-model.md` lists what Cordelia defends against and
//! names the tests that prove each claim. The first test here keeps that
//! file and the tests in step: a claim marked as tested must name tests
//! that exist and run. The others are the claims that need real processes.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

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
