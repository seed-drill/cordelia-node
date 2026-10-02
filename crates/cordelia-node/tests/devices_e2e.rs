//! End to end, with real processes: a relay and two personal nodes on
//! localhost, talking QUIC. Device A runs `add-device B`, B runs
//! `accept A`, B joins A's personal channel through the relay, and an item
//! A then publishes in that channel reaches B, decrypted with the key B
//! received (decision 2026-09-30-agent-memory-sync §3, §4.1).
//!
//! Uses only the CLI and the local HTTP API, as a person would.

mod common;

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use common::*;

#[test]
fn add_device_accept_and_sync_through_a_relay() {
    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));

    let mut a = node("a", "personal", Some(relay.p2p));
    let mut b = node("b", "personal", Some(relay.p2p));
    a.start();
    b.start();
    let all = [&relay, &a, &b];
    wait_for("a healthy", &all, 30, || healthy(&a));
    wait_for("b healthy", &all, 30, || healthy(&b));
    wait_for("a connected to the relay", &all, 60, || has_hot_peer(&a));
    wait_for("b connected to the relay", &all, 60, || has_hot_peer(&b));

    // `cordelia status` reports the running node's connections.
    let status = a.cli(&["status"]);
    assert!(status.contains("Running:   yes"), "{status}");
    let hot: u64 = status
        .lines()
        .find_map(|l| l.trim().strip_prefix("Peers:"))
        .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
        .unwrap_or_else(|| panic!("status lacks a Peers line:\n{status}"));
    assert!(hot >= 1, "{status}");

    // `cordelia peers` lists who each node is connected to: the devices
    // see the relay, and the relay sees both devices, by key.
    let peers_of = |n: &Node| -> Vec<serde_json::Value> {
        let v: serde_json::Value = serde_json::from_str(&n.cli(&["peers", "--json"])).unwrap();
        v["peers"].as_array().cloned().unwrap_or_default()
    };
    let relay_key = relay.cli(&["id"]).trim().to_string();
    let a_peers = wait_for("a lists the relay", &all, 30, || {
        let p = peers_of(&a);
        (!p.is_empty()).then_some(p)
    });
    assert_eq!(a_peers[0]["key"], relay_key.as_str(), "{a_peers:?}");
    assert_eq!(a_peers[0]["role"], "relay");
    assert!(a.cli(&["peers"]).contains(&relay_key));
    let device_keys = [
        a.cli(&["id"]).trim().to_string(),
        b.cli(&["id"]).trim().to_string(),
    ];
    wait_for("the relay lists both devices", &all, 30, || {
        let p = peers_of(&relay);
        device_keys
            .iter()
            .all(|k| {
                p.iter()
                    .any(|x| x["key"] == k.as_str() && x["role"] == "node")
            })
            .then_some(())
    });

    // The relay's usage counts: two devices seen, as counts only.
    wait_for("the relay counts two peers", &all, 30, || {
        let v: serde_json::Value = serde_json::from_str(&relay.cli(&["stats", "--json"])).ok()?;
        (v["peers_seen"]["1d"]["node"] == 2 && v["peers_seen"]["7d"]["relay"] == 0).then_some(())
    });
    let metrics = relay.get_text("/api/v1/metrics");
    assert!(
        metrics.contains("cordelia_peers_seen{window=\"1d\",role=\"node\"} 2"),
        "{metrics}"
    );
    assert!(
        !metrics.contains(&device_keys[0]),
        "metrics carry counts, not keys"
    );

    // The documented flow: one key copied in each direction.
    let b_key = b.cli(&["id"]).trim().to_string();
    let added = a.cli(&["add-device", &b_key, "--name", "b"]);
    let a_key = added
        .lines()
        .find_map(|l| l.trim().strip_prefix("cordelia accept "))
        .unwrap_or_else(|| panic!("add-device output lacks the accept line:\n{added}"))
        .to_string();
    assert_eq!(a_key, a.cli(&["id"]).trim());
    b.cli(&["accept", &a_key, "--name", "a"]);

    let personal = groups(&a)
        .into_iter()
        .next()
        .expect("a has a personal channel");
    wait_for("b joins a's personal channel", &all, 90, || {
        groups(&b).contains(&personal).then_some(())
    });

    let devices = b.post("/api/v1/devices/list", serde_json::json!({}));
    assert!(
        devices["devices"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["key"] == a_key.as_str() && d["in_personal_channel"] == true),
        "b lists a as a device: {devices}"
    );

    // Data now flows with the shared key: A publishes, B reads it.
    a.post(
        "/api/v1/channels/publish",
        serde_json::json!({ "channel": personal, "content": { "text": "hello from a" } }),
    );
    wait_for("b receives a's item", &all, 90, || {
        let listened = b.post(
            "/api/v1/channels/listen",
            serde_json::json!({ "channel": personal, "limit": 10 }),
        );
        listened["items"]
            .as_array()?
            .iter()
            .any(|i| i["content"]["text"] == "hello from a" && i["signature_valid"] == true)
            .then_some(())
    });

    // Nothing is waiting: every invite was applied.
    let invites = b.cli(&["invites"]);
    assert!(invites.contains("No invites waiting"), "{invites}");

    // Keyed items (§4.3): A writes a key, B reads it; B edits, A sees it.
    let entry = |n: &Node, key: &str| -> Option<(String, u64)> {
        let resp = n.post(
            "/api/v1/channels/entries",
            serde_json::json!({ "channel": personal }),
        );
        resp["entries"]
            .as_array()?
            .iter()
            .find(|e| e["key"] == key)
            .map(|e| {
                (
                    e["content"]["text"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    e["rev"].as_u64().unwrap_or(0),
                )
            })
    };
    let written = a.post(
        "/api/v1/channels/publish",
        serde_json::json!({ "channel": personal, "key": "notes.md", "content": { "text": "v1" } }),
    );
    assert_eq!(written["rev"], 1, "{written}");
    wait_for("b reads a's key", &all, 90, || {
        (entry(&b, "notes.md")? == ("v1".to_string(), 1)).then_some(())
    });
    b.post(
        "/api/v1/channels/publish",
        serde_json::json!({ "channel": personal, "key": "notes.md", "content": { "text": "v2 from b" } }),
    );
    wait_for("a reads b's edit", &all, 90, || {
        (entry(&a, "notes.md")? == ("v2 from b".to_string(), 2)).then_some(())
    });

    // Deleting a key replicates as a tombstone revision (§4.4).
    let deleted = a.post(
        "/api/v1/channels/delete-key",
        serde_json::json!({ "channel": personal, "key": "notes.md" }),
    );
    assert_eq!(deleted["rev"], 3, "{deleted}");
    wait_for("b sees the key deleted", &all, 90, || {
        let resp = b.post(
            "/api/v1/channels/entries",
            serde_json::json!({ "channel": personal }),
        );
        resp["entries"]
            .as_array()?
            .iter()
            .any(|e| e["key"] == "notes.md" && e["deleted"] == true && e["rev"] == 3)
            .then_some(())
    });

    // Paging (§4.4a): more items than one sync page, all arrive.
    const BULK: usize = 150;
    for i in 0..BULK {
        a.post(
            "/api/v1/channels/publish",
            serde_json::json!({ "channel": personal, "content": { "text": format!("bulk {i}") } }),
        );
    }
    wait_for("b receives every bulk item", &all, 120, || {
        let listened = b.post(
            "/api/v1/channels/listen",
            serde_json::json!({ "channel": personal, "limit": 500 }),
        );
        let got = listened["items"]
            .as_array()?
            .iter()
            .filter(|i| {
                i["content"]["text"]
                    .as_str()
                    .is_some_and(|t| t.starts_with("bulk "))
            })
            .count();
        (got == BULK).then_some(())
    });
}

#[test]
fn a_node_started_before_its_relay_reaches_it_by_name_once_it_is_up() {
    // The relay is given by name, as the default relays are, and does not
    // exist yet when the node starts: its first dial fails, and it must
    // keep resolving and retrying the name rather than give up.
    let mut relay = node("relay", "relay", None);
    let mut a = node_with_bootnode(
        "early",
        "personal",
        Some(format!("localhost:{}", relay.p2p)),
    );
    a.start();
    wait_for("a healthy", &[&a], 30, || healthy(&a));
    wait_for("a's first dial to fail", &[&a], 60, || {
        let relays = relays_of(&a);
        (relays.len() == 1 && relays[0]["state"] == "unreachable").then_some(())
    });
    assert!(has_hot_peer(&a).is_none(), "no relay yet, so no peer");

    relay.start();
    wait_for("relay healthy", &[&relay, &a], 30, || healthy(&relay));
    wait_for("a reaches the relay by name", &[&relay, &a], 60, || {
        has_hot_peer(&a)
    });
}

/// The peers `n` is connected to, by key.
fn peer_keys(n: &Node) -> Vec<String> {
    let Some(v) = n.get("/api/v1/peers") else {
        return Vec::new();
    };
    v["peers"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|p| p["key"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn two_relays_and_two_devices_keep_delivering_through_restarts() {
    // The topology we run: two relays that list each other, a device that
    // reaches both, and a device that reaches only one. Everything is
    // judged by items arriving, not by what the nodes say about themselves.
    let mut r1 = node("relay1", "relay", None);
    let mut r2 = node_with_bootnodes("relay2", "relay", &[format!("localhost:{}", r1.p2p)]);
    r1.start();
    wait_for("relay1 healthy", &[&r1], 30, || healthy(&r1));
    r2.start();
    wait_for("relay2 healthy", &[&r1, &r2], 30, || healthy(&r2));
    let (r1_key, r2_key) = (
        r1.cli(&["id"]).trim().to_string(),
        r2.cli(&["id"]).trim().to_string(),
    );
    wait_for("the relays mesh", &[&r1, &r2], 60, || {
        (peer_keys(&r1).contains(&r2_key) && peer_keys(&r2).contains(&r1_key)).then_some(())
    });

    let both = [
        format!("localhost:{}", r1.p2p),
        format!("localhost:{}", r2.p2p),
    ];
    let mut a = node_with_bootnodes("a", "personal", &both);
    let mut b = node_with_bootnodes("b", "personal", &both[1..]);
    a.start();
    b.start();
    {
        let all = [&r1, &r2, &a, &b];
        wait_for("a healthy", &all, 30, || healthy(&a));
        wait_for("b healthy", &all, 30, || healthy(&b));
        wait_for("a reaches both relays", &all, 60, || {
            (peer_keys(&a).len() == 2).then_some(())
        });
        wait_for("b reaches relay2", &all, 60, || {
            peer_keys(&b).contains(&r2_key).then_some(())
        });
    }

    let b_key = b.cli(&["id"]).trim().to_string();
    let a_key = a.cli(&["id"]).trim().to_string();
    a.cli(&["add-device", &b_key, "--name", "b"]);
    b.cli(&["accept", &a_key, "--name", "a"]);
    let personal = groups(&a)
        .into_iter()
        .next()
        .expect("a has a personal channel");
    wait_for(
        "b joins a's personal channel",
        &[&r1, &r2, &a, &b],
        90,
        || groups(&b).contains(&personal).then_some(()),
    );

    // `from` publishes `text`; it must arrive at `to`.
    let deliver = |from: &Node, to: &Node, text: &str, all: &[&Node]| {
        from.post(
            "/api/v1/channels/publish",
            serde_json::json!({ "channel": personal, "content": { "text": text } }),
        );
        wait_for(
            &format!("{} receives {text:?} from {}", to.name, from.name),
            all,
            150,
            || {
                let listened = to.post(
                    "/api/v1/channels/listen",
                    serde_json::json!({ "channel": personal, "limit": 100 }),
                );
                listened["items"]
                    .as_array()?
                    .iter()
                    .any(|i| i["content"]["text"] == text)
                    .then_some(())
            },
        );
    };
    deliver(&a, &b, "first", &[&r1, &r2, &a, &b]);
    deliver(&b, &a, "second", &[&r1, &r2, &a, &b]);

    // A relay is upgraded: stopped cleanly and started again.
    r2.stop();
    r2.start();
    wait_for("relay2 healthy again", &[&r1, &r2], 30, || healthy(&r2));
    deliver(&a, &b, "after relay2 restarts", &[&r1, &r2, &a, &b]);
    deliver(&b, &a, "and back", &[&r1, &r2, &a, &b]);
    wait_for("the relays mesh again", &[&r1, &r2], 120, || {
        (peer_keys(&r1).contains(&r2_key) && peer_keys(&r2).contains(&r1_key)).then_some(())
    });

    // The other relay crashes: nobody is told.
    r1.crash();
    r1.start();
    wait_for("relay1 healthy again", &[&r1, &r2], 30, || healthy(&r1));
    deliver(&a, &b, "after relay1 crashes", &[&r1, &r2, &a, &b]);
    wait_for("a is back on both relays", &[&r1, &r2, &a, &b], 180, || {
        let keys = peer_keys(&a);
        (keys.contains(&r1_key) && keys.contains(&r2_key)).then_some(())
    });

    // A laptop sleeps and wakes more often than the per-address connection
    // limit: every reconnect must still be accepted, and still deliver.
    for round in 0..7 {
        if round % 2 == 0 {
            b.stop();
        } else {
            b.crash();
        }
        b.start();
        wait_for("b healthy again", &[&r1, &r2, &a, &b], 30, || healthy(&b));
        deliver(
            &b,
            &a,
            &format!("b after restart {round}"),
            &[&r1, &r2, &a, &b],
        );
    }
    deliver(&a, &b, "last", &[&r1, &r2, &a, &b]);
}

/// A personal node only dials out. It starts and reaches its relay while
/// something else holds its configured P2P port, so it cannot be listening
/// there; told to listen, the same node needs the port and cannot start.
/// A device with two relays, one of them down. It says so, with the reason,
/// and goes on trying at a slowing pace; when the relay comes up it is
/// connected again without a restart.
#[test]
fn a_relay_that_is_down_is_shown_and_found_when_it_comes_up() {
    let mut up = node("up", "relay", None);
    let mut down = node("down", "relay", None);
    up.start();
    wait_for("the first relay healthy", &[&up], 30, || healthy(&up));
    let key_of = |n: &Node| n.cli(&["id"]).trim().to_string();
    let relays = [
        (format!("127.0.0.1:{}", up.p2p), Some(key_of(&up))),
        (format!("127.0.0.1:{}", down.p2p), Some(key_of(&down))),
    ];
    let mut a = node_with_relays("a", "personal", &relays);
    a.start();
    let all = [&up, &a];
    wait_for("a healthy", &all, 30, || healthy(&a));
    wait_for("a connected to the relay that is up", &all, 60, || {
        has_hot_peer(&a)
    });

    let state_of = |host: &str| -> Option<serde_json::Value> {
        relays_of(&a).into_iter().find(|r| r["host"] == host)
    };
    let missing = wait_for("a reports the other relay unreachable", &all, 60, || {
        state_of(&relays[1].0).filter(|r| r["state"] == "unreachable")
    });
    assert_eq!(
        missing["key"],
        relays[1].1.clone().unwrap().as_str(),
        "{missing}"
    );
    assert!(missing["error"].is_string(), "{missing}");
    assert!(missing["unreachable_secs"].is_u64(), "{missing}");
    assert_eq!(state_of(&relays[0].0).unwrap()["state"], "connected");

    // The same, as a person reads it.
    let said = a.cli(&["peers"]);
    assert!(
        said.contains("Configured relays that are not connected:"),
        "{said}"
    );
    assert!(
        said.lines()
            .any(|l| l.contains(&relays[1].0) && l.contains("unreachable")),
        "{said}"
    );
    let status: serde_json::Value = serde_json::from_str(&a.cli(&["status", "--json"])).unwrap();
    assert_eq!(
        status["peers"]["relays"].as_array().unwrap().len(),
        2,
        "{status}"
    );

    // The relay comes up, and is found without a restart.
    down.start();
    let all = [&up, &down, &a];
    wait_for("the second relay healthy", &all, 30, || healthy(&down));
    wait_for("a reaches the relay that was down", &all, 120, || {
        state_of(&relays[1].0)
            .filter(|r| r["state"] == "connected")
            .map(|_| ())
    });
    let said = a.cli(&["peers"]);
    assert!(!said.contains("not connected"), "{said}");
}

#[test]
fn a_personal_node_listens_on_nothing() {
    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));

    let mut a = node("a", "personal", Some(relay.p2p));
    let _held = std::net::UdpSocket::bind(("0.0.0.0", a.p2p)).expect("the port is free");
    a.start();
    wait_for("node healthy", &[&relay, &a], 30, || healthy(&a));
    wait_for("connected to the relay", &[&relay, &a], 60, || {
        has_hot_peer(&a)
    });
    let status = a.cli(&["status"]);
    assert!(status.contains("outbound only"), "{status}");
    assert!(
        std::fs::read_to_string(a.log())
            .unwrap()
            .contains("dials out only"),
        "{}",
        a.log_tail()
    );

    a.stop();
    let config = std::fs::read_to_string(a.config()).unwrap();
    assert!(config.contains("role = \"personal\"\n"));
    std::fs::write(
        a.config(),
        config.replace(
            "role = \"personal\"\n",
            "role = \"personal\"\nlisten = true\n",
        ),
    )
    .unwrap();
    a.start();
    let deadline = Instant::now() + Duration::from_secs(30);
    let exit = loop {
        if let Some(status) = a.child.as_mut().unwrap().try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the node kept running:\n{}",
            a.log_tail()
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    assert!(!exit.success());
    assert!(a.log_tail().contains("P2P transport"), "{}", a.log_tail());
}

#[test]
fn cli_reports_when_the_node_is_not_running() {
    let n = node("idle", "personal", None);
    let out = Command::new(BIN)
        .arg("--config")
        .arg(n.config())
        .args(["devices"])
        .env("CORDELIA_DATA_DIR", n.data_dir())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cordelia start"), "{stderr}");

    // `status` still works, and says the node is not running.
    let status = n.cli(&["status"]);
    assert!(status.contains("Running:   no"), "{status}");
    let line = n.cli(&["status", "--line"]);
    assert!(line.contains("memory: node stopped"), "{line}");
    let json: serde_json::Value = serde_json::from_str(&n.cli(&["status", "--json"])).unwrap();
    assert_eq!(json["state"], "stopped", "{json}");

    // On a machine without Cordelia (an empty home directory), the status
    // line prints nothing.
    let empty_home = tempfile::tempdir().unwrap();
    let none = Command::new(BIN)
        .args(["status", "--line"])
        .env("HOME", empty_home.path())
        .env_remove("CORDELIA_CONFIG")
        .env_remove("CORDELIA_DATA_DIR")
        .output()
        .unwrap();
    assert!(none.status.success());
    assert!(
        none.stdout.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&none.stdout)
    );
}

/// Claude Code's folder under `home` for `dir`, named as Claude Code names
/// it: every character that is not a letter or a digit becomes `-`.
fn clone_at(home: &std::path::Path, rel: &str) -> PathBuf {
    let repo = home.join(rel);
    std::fs::create_dir_all(&repo).unwrap();
    for args in [
        vec!["init", "-q"],
        vec![
            "remote",
            "add",
            "origin",
            "https://github.com/seed-drill/cordelia-node.git",
        ],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(&args)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    repo
}

/// The names a device has mapped, from its status snapshot.
fn mapped_names(snapshot: &serde_json::Value) -> Vec<String> {
    let mut names: Vec<String> = snapshot["sync"]["mappings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| m["name"].as_str().map(String::from))
        .collect();
    names.sort();
    names
}

/// The product, end to end: two machines, each with its own home, Claude
/// Code folder, and clone of the same repository at a different path.
/// After pairing, `cordelia sync claude` and mapping the same names on
/// both, memory Claude writes on one machine appears on the other. Until a
/// folder is mapped, nothing of it leaves the machine.
#[test]
fn claude_memory_syncs_between_two_machines() {
    const PROJECT: &str = "github.com/seed-drill/cordelia-node";

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
    let path = |p: &std::path::Path| p.to_str().unwrap().to_string();
    let read = |p: &std::path::Path| std::fs::read_to_string(p).ok();
    let state = |n: &Node| -> serde_json::Value {
        serde_json::from_str(&n.cli(&["status", "--json"])).unwrap()
    };

    // Each machine: home memory and a clone at a different path. A also has
    // a folder that is not a repository.
    let a_home_mem = claude_folder(&a.home(), &a.home());
    let b_home_mem = claude_folder(&b.home(), &b.home());
    let a_repo = clone_at(&a.home(), "Work/cordelia-node");
    let b_repo = clone_at(&b.home(), "code/cn");
    let a_proj_mem = claude_folder(&a.home(), &a_repo);
    let b_proj_mem = claude_folder(&b.home(), &b_repo);
    let a_notes = a.home().join("notes");
    std::fs::create_dir_all(&a_notes).unwrap();
    let a_notes_mem = claude_folder(&a.home(), &a_notes);

    // Pair, then switch sync on.
    let b_key = b.cli(&["id"]).trim().to_string();
    let added = a.cli(&["add-device", &b_key]);
    let a_key = added
        .lines()
        .find_map(|l| l.trim().strip_prefix("cordelia accept "))
        .unwrap()
        .to_string();
    b.cli(&["accept", &a_key]);
    for n in [&a, &b] {
        let out = n.cli(&["sync", "claude", "--dir", &path(&n.home().join(".claude"))]);
        assert!(out.starts_with("Sync turned on.\n"), "{out}");
    }

    // Claude writes memories on A.
    std::fs::write(a_home_mem.join("user_role.md"), "Prefers short answers.\n").unwrap();
    std::fs::write(
        a_proj_mem.join("decision.md"),
        "Invite-only channels only.\n",
    )
    .unwrap();
    std::fs::write(a_notes_mem.join("idea.md"), "A thought.\n").unwrap();

    // Nothing syncs until a folder is mapped. What was found is listed
    // with the command that maps it.
    let found = wait_for("a lists what it found", &all, 60, || {
        let out = a.cli(&["sync", "status"]);
        out.contains("Found on this machine").then_some(out)
    });
    for expected in [
        "Nothing syncs yet.",
        "cordelia sync map ~ --home",
        "cordelia sync map ~/Work/cordelia-node",
        "cordelia sync map ~/notes <name>",
        "Scope: mapped folders only.",
    ] {
        assert!(
            found.contains(expected),
            "missing {expected:?} in:\n{found}"
        );
    }
    let s = state(&a);
    assert_eq!(s["state"], "off", "{s}");
    assert_eq!(s["summary"], "memory: nothing mapped", "{s}");
    assert_eq!(s["sync"]["all"], false, "{s}");
    assert_eq!(s["sync"]["unmapped"].as_array().unwrap().len(), 3, "{s}");

    // What cannot be mapped by accident, or by a slip.
    let said = a.refused(&["sync", "map", &path(&a.home())]);
    assert!(said.contains("cordelia sync map ~ --home"), "{said}");
    let said = a.refused(&["sync", "map", &path(&a_repo), "--home"]);
    assert!(said.contains("--home maps the home directory"), "{said}");
    let said = a.refused(&["sync", "map", &path(&a_notes)]);
    assert!(said.contains("needs a name"), "{said}");
    let said = a.refused(&["sync", "map", &path(&a_notes), "Lab Notes"]);
    assert!(said.contains("not a usable name"), "{said}");
    let said = a.refused(&["sync", "map", &path(&a.home().join("missing"))]);
    assert!(said.contains("No such file"), "{said}");
    let outside = a.home().parent().unwrap().to_path_buf();
    let said = a.refused(&["sync", "map", &path(&outside), "outside"]);
    assert!(said.contains("outside the home directory"), "{said}");

    // A maps the project (from one of its subdirectories: the repository is
    // what gets mapped, under its remote), the folder under a name, and home.
    let sub = a_repo.join("crates/x");
    std::fs::create_dir_all(&sub).unwrap();
    let out = a.cli(&["sync", "map", &path(&sub)]);
    assert!(
        out.contains(&format!("Mapped ~/Work/cordelia-node to {PROJECT}.")),
        "{out}"
    );
    a.cli(&["sync", "map", &path(&a_notes), "lab-notes"]);
    let out = a.cli(&["sync", "map", &path(&a.home()), "--home"]);
    assert!(out.contains("home memory"), "{out}");
    let said = a.refused(&["sync", "map", &path(&a_notes), "other"]);
    assert!(said.contains("already mapped"), "{said}");
    assert_eq!(mapped_names(&state(&a)), [PROJECT, "lab-notes", "~"]);

    // B is offered all three and has none of them: what it found itself is
    // marked, and the name it has no folder for is listed on its own.
    let offered = wait_for("b sees what a syncs", &all, 120, || {
        let out = b.cli(&["sync", "status"]);
        (out.matches("(your other devices sync it)").count() == 2 && out.contains("lab-notes"))
            .then_some(out)
    });
    assert!(
        offered.contains("cordelia sync map <folder> lab-notes"),
        "{offered}"
    );
    let s = state(&b);
    assert_eq!(
        s["sync"]["available"],
        serde_json::json!([PROJECT, "lab-notes", "~"]),
        "{s}"
    );
    assert_eq!(s["sync"]["folders"], 0, "{s}");
    assert_eq!(read(&b_proj_mem.join("decision.md")), None);
    assert_eq!(read(&b_home_mem.join("user_role.md")), None);

    // B maps the same names: its clone (named by its remote), a folder
    // Claude Code has never run in, and home.
    b.cli(&["sync", "map", &path(&b_repo)]);
    let b_notes = b.home().join("Documents/lab");
    std::fs::create_dir_all(&b_notes).unwrap();
    let b_notes_mem = claude_project(&b.home(), &b_notes).join("memory");
    b.cli(&["sync", "map", &path(&b_notes), "lab-notes"]);
    b.cli(&["sync", "home", "on"]);
    assert_eq!(mapped_names(&state(&b)), [PROJECT, "lab-notes", "~"]);

    wait_for("b gets a's home memory", &all, 120, || {
        (read(&b_home_mem.join("user_role.md"))?.as_str() == "Prefers short answers.\n")
            .then_some(())
    });
    wait_for(
        "b gets a's project memory, at a different path",
        &all,
        120,
        || {
            (read(&b_proj_mem.join("decision.md"))?.as_str() == "Invite-only channels only.\n")
                .then_some(())
        },
    );
    wait_for(
        "b gets the named folder's memory, where Claude Code will look",
        &all,
        120,
        || (read(&b_notes_mem.join("idea.md"))?.as_str() == "A thought.\n").then_some(()),
    );

    // And back: B edits, A sees it.
    std::fs::write(
        b_proj_mem.join("decision.md"),
        "Invite-only channels only. No keepers.\n",
    )
    .unwrap();
    wait_for("a gets b's edit", &all, 120, || {
        (read(&a_proj_mem.join("decision.md"))?.as_str()
            == "Invite-only channels only. No keepers.\n")
            .then_some(())
    });

    // Status says, for each folder, when it last received and sent.
    let status = b.cli(&["sync", "status"]);
    let line = status
        .lines()
        .find(|l| l.contains(PROJECT))
        .unwrap_or_else(|| panic!("{status}"));
    assert!(
        line.contains("syncing") && line.contains("received ") && line.contains("sent "),
        "{status}"
    );
    assert!(!status.contains("Found on this machine"), "{status}");

    // The status indicator: once everything has reached the relay, both
    // devices say so.
    for n in [&a, &b] {
        let s = wait_for("the device reports synced", &all, 60, || {
            let s = state(n);
            (s["state"] == "synced").then_some(s)
        });
        assert_eq!(s["sync"]["enabled"], true, "{s}");
        assert!(s["sync"]["last_change_at"].is_string(), "{s}");
        assert_eq!(s["outbox_waiting"], 0, "{s}");
    }
    let line = a.cli(&["status", "--line"]);
    assert!(line.contains("memory synced"), "{line}");
    let bar: serde_json::Value = serde_json::from_str(&a.cli(&["status", "--waybar"])).unwrap();
    assert_eq!(bar["class"], "synced", "{bar}");
    assert!(
        bar["tooltip"]
            .as_str()
            .unwrap()
            .contains("Relays: 1 connected"),
        "{bar}"
    );

    // The full snapshot a panel reads: relays, this person's devices, and
    // each synced folder with its name and where it is.
    let snapshot = state(&a);
    assert_eq!(snapshot["peers"]["list"][0]["role"], "relay", "{snapshot}");
    assert_eq!(
        snapshot["devices"].as_array().unwrap().len(),
        2,
        "{snapshot}"
    );
    let project = snapshot["sync"]["projects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["project"] == PROJECT)
        .unwrap_or_else(|| panic!("{snapshot}"));
    assert_eq!(project["mapped"], true, "{snapshot}");
    assert_eq!(project["cwd"], path(&a_repo), "{snapshot}");
    assert!(
        project["channel"].as_str().unwrap().starts_with("grp_"),
        "{snapshot}"
    );
    assert!(project["last_published_at"].is_string(), "{snapshot}");
    assert!(project["last_pulled_at"].is_string(), "{snapshot}");
    assert!(project["error"].is_null(), "{snapshot}");

    // One setting changes at a time; the others stay as they were. Turning
    // home memory off unmaps it; a mapped folder is unmapped, not excluded.
    a.cli(&["sync", "home", "off"]);
    a.cli(&["sync", "exclude", "github.com/Client-Co/App.git"]);
    let s = state(&a);
    assert_eq!(s["sync"]["home"], false, "{s}");
    assert_eq!(mapped_names(&s), [PROJECT, "lab-notes"], "{s}");
    assert_eq!(
        s["sync"]["exclude"],
        serde_json::json!(["github.com/client-co/app"])
    );
    assert_eq!(s["sync"]["enabled"], true);
    let said = a.refused(&["sync", "exclude", "lab-notes"]);
    assert!(said.contains("cordelia sync unmap lab-notes"), "{said}");
    a.cli(&["sync", "include", "github.com/client-co/app"]);
    a.cli(&["sync", "home", "on"]);
    let s = state(&a);
    assert_eq!(s["sync"]["home"], true, "{s}");
    assert_eq!(s["sync"]["exclude"], serde_json::json!([]));
    assert_eq!(mapped_names(&s), [PROJECT, "lab-notes", "~"], "{s}");

    // Turning sync on again changes nothing: not the directory (which is
    // not the default here), not the scope, not the mappings.
    let out = a.cli(&["sync", "claude"]);
    assert!(out.starts_with("No settings changed.\n"), "{out}");
    let s = state(&a);
    assert_eq!(s["sync"]["dir"], path(&a.home().join(".claude")), "{s}");
    assert_eq!(s["sync"]["all"], false, "{s}");
    assert_eq!(mapped_names(&s), [PROJECT, "lab-notes", "~"], "{s}");

    // Nor does turning it off and on again.
    a.cli(&["sync", "off"]);
    assert_eq!(state(&a)["state"], "off");
    let out = a.cli(&["sync", "claude"]);
    assert!(out.starts_with("Sync turned on.\n"), "{out}");
    let s = state(&a);
    assert_eq!(s["sync"]["dir"], path(&a.home().join(".claude")), "{s}");
    assert_eq!(mapped_names(&s), [PROJECT, "lab-notes", "~"], "{s}");

    // Unmapping, by name or by folder, stops the sync from this device and
    // leaves the files. The folder is back among those found.
    let out = a.cli(&["sync", "unmap", "lab-notes"]);
    assert!(out.contains("Its files stay where they are."), "{out}");
    assert!(out.contains("cordelia sync map ~/notes <name>"), "{out}");
    assert!(
        out.contains("cordelia sync map <folder> lab-notes"),
        "B still syncs it:\n{out}"
    );
    assert_eq!(
        read(&a_notes_mem.join("idea.md")).as_deref(),
        Some("A thought.\n")
    );
    let said = a.refused(&["sync", "unmap", "lab-notes"]);
    assert!(said.contains("not mapped on this device"), "{said}");
    assert_eq!(
        state(&a)["sync"]["exclude"],
        serde_json::json!([path(&a_notes)]),
        "an unmapped folder stays out until it is mapped again"
    );
    a.cli(&["sync", "unmap", &path(&sub)]);
    assert_eq!(mapped_names(&state(&a)), ["~"]);
    a.cli(&["sync", "map", &path(&a_repo)]);
    wait_for("a settles after the settings changes", &all, 60, || {
        (state(&a)["state"] == "synced").then_some(())
    });

    // A conflict file shows until someone merges it and deletes it.
    let conflict = a_proj_mem.join("decision.conflict-0123abcd.md");
    std::fs::write(&conflict, "the other version\n").unwrap();
    wait_for("a reports the conflict", &all, 60, || {
        let s = state(&a);
        (s["summary"] == "memory: 1 conflict" && s["state"] == "attention").then_some(())
    });
    std::fs::remove_file(&conflict).unwrap();
    wait_for("a is synced again", &all, 60, || {
        (state(&a)["state"] == "synced").then_some(())
    });
}
