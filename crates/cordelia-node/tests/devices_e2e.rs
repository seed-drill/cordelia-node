//! End to end, with real processes: relays and personal nodes on
//! localhost, talking QUIC. One device makes a recovery phrase and runs
//! `add-device` for another, which runs `accept`: the two are then one
//! person's devices, and what one publishes under a name that both hold
//! reaches the other through the relay, in the name's channel, which comes
//! from the person's secret (decision 2026-10-04 §2.2, §5.2, §6, and
//! decision 2026-09-30-agent-memory-sync §4.3 to §4.6).
//!
//! A device is driven only through the CLI and the local HTTP API, as a
//! person would drive it. A relay carries the older kind of channel as it
//! did, and no device holds one (decision 2026-10-04 §10): what a relay
//! does for that kind is shown with a stand-in that speaks its streams.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;

/// What a node writes to its log on the way to running: its banner, its
/// endpoint, and the relays it worked out. The test of a node that stops
/// before all that looks for none of them, and a test of a node that
/// starts looks for each: a line that is reworded is then missed there,
/// where it shows, and not only here, where it would pass.
const A_STARTED_NODE_LOGS: [&str; 3] = ["Cordelia v", "P2P endpoint", "relays configured"];

fn path(p: &Path) -> String {
    p.to_str().unwrap().to_string()
}

fn read(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

/// What `cordelia status --json` says of a node.
fn state(n: &Node) -> serde_json::Value {
    serde_json::from_str(&n.cli(&["status", "--json"])).unwrap()
}

/// Turn memory sync on for `n`, for the Claude Code directory in its home.
/// Returns what the command said.
fn sync_on(n: &Node) -> String {
    n.cli(&["sync", "claude", "--dir", &path(&n.home().join(".claude"))])
}

/// The name that the tests of what a device holds and sends publish
/// under.
const NAME: &str = "lab";

/// `n` comes to hold the name [`NAME`]: its folder `notes` is mapped to
/// the name, with sync on, as a mapping is made. A device holds a name for
/// as long as a folder of its own is mapped to it, and its local API then
/// publishes and lists under that name (decision 2026-10-04 §2.2, §16).
/// Nothing is made or joined: the name's channel is from the person's
/// secret.
///
/// Sync is then turned off again. The folder stays mapped and the name
/// held, and the device goes on sending and fetching the name's channel.
/// What is turned off is the adapter, which takes no part in what these
/// tests show: they publish through the local API, and what they publish
/// there is no memory file.
fn holds_the_name(n: &Node) {
    let notes = n.home().join("notes");
    std::fs::create_dir_all(&notes).unwrap();
    let out = sync_on(n);
    assert!(out.starts_with("Sync turned on.\n"), "{out}");
    let out = n.cli(&["sync", "map", &path(&notes), NAME]);
    assert!(out.contains(&format!("Mapped ~/notes to {NAME}.")), "{out}");
    n.cli(&["sync", "off"]);
}

/// Publish `content` under `key` in the name [`NAME`], through the local
/// API of `n`. Returns the answer.
fn publishes(n: &Node, key: &str, content: serde_json::Value) -> serde_json::Value {
    n.post(
        "/api/v1/channels/publish",
        serde_json::json!({ "channel": NAME, "key": key, "content": content }),
    )
}

/// What `n` holds under the name [`NAME`]: the current version under each
/// key, as its local API lists them.
fn held(n: &Node) -> Vec<serde_json::Value> {
    let answer = n.post(
        "/api/v1/channels/entries",
        serde_json::json!({ "channel": NAME }),
    );
    answer["entries"].as_array().cloned().unwrap_or_default()
}

/// Whether `n` holds `text` under `key` in the name [`NAME`].
fn reads(n: &Node, key: &str, text: &str) -> Option<()> {
    held(n)
        .iter()
        .any(|e| e["key"] == key && e["content"]["text"] == text)
        .then_some(())
}

/// A node's database, opened for reading while the node runs.
fn store_of(node: &Node) -> rusqlite::Connection {
    let db = rusqlite::Connection::open_with_flags(
        node.data_dir().join("cordelia.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.busy_timeout(Duration::from_secs(10)).unwrap();
    db
}

/// How many entries of channels from their secrets a relay holds, read
/// from its database.
fn entries_at(relay: &Node) -> u64 {
    let held: i64 = store_of(relay)
        .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
        .unwrap();
    held as u64
}

/// The ID of the channel that `n` holds the name [`NAME`] with, read from
/// its database.
fn channel_of_the_name(n: &Node) -> [u8; 32] {
    cordelia_storage::person::channel_of_name(&store_of(n), NAME)
        .unwrap()
        .expect("the device holds the name")
}

/// Whether a relay holds the channel whose ID is `channel`, read from its
/// database.
fn holds_the_channel(relay: &Node, channel: &[u8; 32]) -> bool {
    let held: i64 = store_of(relay)
        .query_row(
            "SELECT COUNT(*) FROM relay_channels WHERE channel_id = ?1",
            [channel.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    held > 0
}

/// What a device tells its relay of: `n` makes a recovery phrase, comes to
/// hold the name [`NAME`] and publishes an entry under it, and this comes
/// back once `relay` holds the name's channel and the device has nothing
/// left to send. Returns the channel's ID, which the relay was told.
fn tells_its_relay_of_its_name(n: &Node, relay: &Node) -> [u8; 32] {
    let all = [relay, n];
    makes_a_phrase(n, "desktop");
    holds_the_name(n);
    publishes(n, "notes.md", serde_json::json!({ "text": "an entry" }));
    let channel = channel_of_the_name(n);
    wait_for("the relay holds the name's channel", &all, 90, || {
        holds_the_channel(relay, &channel).then_some(())
    });
    wait_for("the device has sent what it holds", &all, 90, || {
        (n.get("/api/v1/status")?["outbox_waiting"] == 0).then_some(())
    });
    channel
}

/// Two of a person's devices and the relay between them, end to end
/// (decision 2026-10-04 §5.2, §6, §16): what a running node says of its
/// connections; the relay's counts of who it has seen; the documented
/// flow that makes the second device one of the person's; and then what
/// one device publishes under a name that both hold reaches the other,
/// with an edit back, a delete, and more entries than one page of a
/// channel's list holds.
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

    // The documented flow: a recovery phrase is made on the first device,
    // and then one key is copied in each direction, `add-device` on the
    // device that is in and `accept` on the new one, each at a terminal
    // with its yes.
    let [a_key, b_key] = &device_keys;
    makes_a_phrase(&a, "desktop");
    let (added, _) = adds(&a, &b, "laptop");
    let accept = format!("cordelia accept {a_key}");
    assert!(
        added.lines().any(|line| line.trim() == accept),
        "add-device output lacks the accept line:\n{added}"
    );
    has_applied(&b, 1, &all);

    // The new device lists the first as a device of the change, and
    // itself as added since, by the first.
    let seen = person_of(&b);
    assert_eq!(seen["among"], "several", "{seen}");
    assert!(
        seen["devices"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["key"] == a_key.as_str() && d["maker"] == true),
        "b lists a as a device: {seen}"
    );
    assert!(
        seen["added"].as_array().unwrap().iter().any(|d| {
            d["key"] == b_key.as_str()
                && d["this_device"] == true
                && d["counted"] == true
                && d["by"]["key"] == a_key.as_str()
        }),
        "b lists itself as added by a: {seen}"
    );
    // Nothing is waiting: what the key typed at `accept` was to bring was
    // taken, and the node asks for it no more.
    let typed = seen["accepting"].as_array().unwrap();
    assert_eq!(typed.len(), 1, "{seen}");
    assert_eq!(
        (&typed[0]["key"], &typed[0]["taken"], &typed[0]["asking"]),
        (
            &serde_json::json!(a_key),
            &serde_json::json!(true),
            &serde_json::json!(false)
        ),
        "{seen}"
    );

    // Both hold a name: its channel is from the secret that the second
    // device was handed. Data now flows: A publishes, B reads it, as an
    // entry that A signed.
    holds_the_name(&a);
    holds_the_name(&b);
    publishes(&a, "hello", serde_json::json!({ "text": "hello from a" }));
    wait_for("b receives a's entry", &all, 90, || {
        held(&b)
            .iter()
            .any(|e| {
                e["content"]["text"] == "hello from a" && e["authors"] == serde_json::json!([a_key])
            })
            .then_some(())
    });

    // Keyed entries (§4.3): A writes a key, B reads it; B edits, A sees it.
    let entry = |n: &Node, key: &str| -> Option<(String, u64)> {
        held(n).iter().find(|e| e["key"] == key).map(|e| {
            (
                e["content"]["text"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                e["rev"].as_u64().unwrap_or(0),
            )
        })
    };
    let written = publishes(&a, "notes.md", serde_json::json!({ "text": "v1" }));
    assert_eq!(written["rev"], 1, "{written}");
    // It was published over no version.
    assert!(written["over"].is_null(), "{written}");
    wait_for("b reads a's key", &all, 90, || {
        (entry(&b, "notes.md")? == ("v1".to_string(), 1)).then_some(())
    });
    let edited = publishes(&b, "notes.md", serde_json::json!({ "text": "v2 from b" }));
    // And the edit over the version that B had read: A's entry.
    assert_eq!(edited["over"]["rev"], 1, "{edited}");
    assert_eq!(
        edited["over"]["entries"],
        serde_json::json!([written["entry"]]),
        "{edited}"
    );
    wait_for("a reads b's edit", &all, 90, || {
        (entry(&a, "notes.md")? == ("v2 from b".to_string(), 2)).then_some(())
    });

    // Deleting a key replicates as a delete at the next revision (§4.4).
    let deleted = a.post(
        "/api/v1/channels/delete-key",
        serde_json::json!({ "channel": NAME, "key": "notes.md" }),
    );
    assert_eq!(deleted["rev"], 3, "{deleted}");
    wait_for("b sees the key deleted", &all, 90, || {
        held(&b)
            .iter()
            .any(|e| e["key"] == "notes.md" && e["deleted"] == true && e["rev"] == 3)
            .then_some(())
    });

    // Paging (§4.4a): more entries than one page of a channel's list, all
    // arrive.
    const BULK: usize = 150;
    for i in 0..BULK {
        publishes(
            &a,
            &format!("bulk-{i:03}"),
            serde_json::json!({ "text": format!("bulk {i}") }),
        );
    }
    wait_for("b receives every bulk entry", &all, 120, || {
        let got = held(&b)
            .iter()
            .filter(|e| {
                e["content"]["text"]
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
    // The node says for how long no relay has been connected, by its
    // own clock (decision 2026-10-04 §10.1): the status line goes by it.
    let no_relay_secs = |n: &Node| n.get("/api/v1/status").unwrap()["no_relay_secs"].clone();
    let first = wait_for("a says since when it has no relay", &[&a], 30, || {
        no_relay_secs(&a).as_u64()
    });
    std::thread::sleep(Duration::from_secs(2));
    let later = no_relay_secs(&a).as_u64().unwrap();
    assert!(later > first && later < 120, "{first} then {later}");
    // `cordelia status --json` carries it as the node says it.
    assert!(state(&a)["no_relay_secs"].as_u64() >= Some(later));

    relay.start();
    wait_for("relay healthy", &[&relay, &a], 30, || healthy(&relay));
    wait_for("a reaches the relay by name", &[&relay, &a], 60, || {
        has_hot_peer(&a)
    });
    // With a relay connected, it says none.
    wait_for(
        "a says that a relay is connected",
        &[&relay, &a],
        30,
        || no_relay_secs(&a).is_null().then_some(()),
    );
    let said = state(&a);
    assert!(said["no_relay_secs"].is_null(), "{said}");
    assert!(said.as_object().unwrap().contains_key("no_relay_secs"));
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
    // judged by entries arriving, not by what the nodes say about themselves.
    let mut r1 = node("relay1", "relay", None);
    let mut r2 = node_with_relays(
        "relay2",
        "relay",
        &[(format!("localhost:{}", r1.p2p), Some(key_of(&r1)))],
    );
    r1.add_relay(&format!("localhost:{}", r2.p2p), Some(&key_of(&r2)));
    r1.start();
    wait_for("relay1 healthy", &[&r1], 30, || healthy(&r1));
    r2.start();
    wait_for("relay2 healthy", &[&r1, &r2], 30, || healthy(&r2));
    let (r1_key, r2_key) = (key_of(&r1), key_of(&r2));
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

    // The two are one person's devices, and both hold a name.
    pair(&a, &b, "b", &[&r1, &r2, &a, &b]);
    holds_the_name(&a);
    holds_the_name(&b);

    // `from` publishes `text`, under a key of its own; it must arrive at
    // `to`.
    let sent = std::cell::Cell::new(0);
    let deliver = |from: &Node, to: &Node, text: &str, all: &[&Node]| {
        let key = format!("sent-{:02}", sent.replace(sent.get() + 1));
        publishes(from, &key, serde_json::json!({ "text": text }));
        wait_for(
            &format!("{} receives {text:?} from {}", to.name, from.name),
            all,
            150,
            || reads(to, &key, text),
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

/// A node stops on each signal that tells it to: SIGINT, as at a terminal,
/// and SIGQUIT, which would otherwise end it with a core holding its keys.
/// (SIGTERM is how every other test stops a node.) Each time it exits with
/// success, in time, and with every part of it stopped.
#[test]
fn a_node_stops_on_each_signal_that_tells_it_to() {
    for signal in ["INT", "QUIT"] {
        let mut n = node("relay", "relay", None);
        n.start();
        wait_for("node healthy", &[&n], 30, || healthy(&n));
        n.stop_with(signal);
    }
}

/// A node that is told to stop gives a request it is answering one stream
/// timeout to finish, and no more, whichever signal tells it. A client has
/// sent a request's head and not all its body, to a route that reads the
/// body, so the server waits for the rest for as long as the client keeps
/// the connection open. The node waits for it (it does not end in the
/// middle of a request) and then closes it, where actix's own default would
/// wait half a minute. (Left to handle SIGINT itself, actix would not wait
/// at all.)
#[test]
fn a_node_told_to_stop_gives_an_open_request_one_stream_timeout() {
    use cordelia_core::protocol::STREAM_TIMEOUT_SECS;
    use std::io::Write;

    for signal in ["TERM", "INT"] {
        let mut n = node("relay", "relay", None);
        n.start();
        wait_for("node healthy", &[&n], 30, || healthy(&n));

        let mut held = std::net::TcpStream::connect(("127.0.0.1", n.http)).unwrap();
        let head = format!(
            "POST /api/v1/channels/publish HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: 64\r\n\r\n{{\"channel\":",
            n.token()
        );
        held.write_all(head.as_bytes()).unwrap();
        held.flush().unwrap();
        std::thread::sleep(Duration::from_millis(500));

        let told = Instant::now();
        n.stop_with(signal);
        let took = told.elapsed();
        assert!(
            took >= Duration::from_secs(STREAM_TIMEOUT_SECS - 1),
            "SIG{signal}: the node did not wait for the request it was answering: it exited after {took:?}"
        );
        assert!(
            took < Duration::from_secs(STREAM_TIMEOUT_SECS + 5),
            "SIG{signal}: the node took {took:?} to exit"
        );
        drop(held);
    }
}

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

/// A relay loses its database (it was rebuilt) while two devices stay up.
///
/// - What a device writes afterwards still reaches the other one through
///   that relay. A device keeps its place in each channel's list at a
///   relay; the rebuilt relay starts its list again, so a place kept from
///   before would skip everything it stores from then on. The place is
///   kept with the mark that the relay gives its holding of the channel,
///   and a new holding is read from the start.
/// - What was written before is put back. A relay is a cache, and its
///   devices are where the entries are: a device that proves a channel of
///   its own to a relay which holds nothing of it sends that relay what it
///   holds (decision 2026-10-04 §2.4, §4.6). So a device added afterwards,
///   which has only the relay to fetch from, gets all of it.
/// - The same holds of the older kind of channel, which a relay carries as
///   it did (decision 2026-10-04 §10) and which no device of this version
///   holds: there it is the relay that asks whoever connects which
///   channels it holds, and fetches what it lacks. A stand-in for a device
///   of that kind shows it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_that_lost_its_database_carries_on_and_is_filled_again() {
    const OLDER: &str = "grp_550e8400-e29b-41d4-a716-446655440000";
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
    pair(&a, &b, "b", &[&relay, &a, &b]);
    holds_the_name(&a);
    holds_the_name(&b);
    let publish =
        |n: &Node, key: &str, text: &str| publishes(n, key, serde_json::json!({ "text": text }));

    // Enough goes through the relay for B's place in the channel's list to
    // be well past where the rebuilt relay will start again.
    for n in 0..5 {
        publish(&a, &format!("before-{n}.md"), "before");
    }
    wait_for("b reads what a wrote", &[&relay, &a, &b], 90, || {
        reads(&b, "before-4.md", "before")
    });
    // And an entry of the older kind, from what stands in for a device
    // that holds one.
    let older = Arc::new(cordelia_crypto::identity::NodeIdentity::generate().unwrap());
    let before = entry_in(&older, OLDER, vec![7; 40]);
    let ack = push_to(&relay, older.clone(), std::slice::from_ref(&before)).await;
    assert_eq!(ack.stored, 1, "{ack:?}");

    // The relay comes back with nothing. Both devices find it again.
    relay.stop();
    for file in ["cordelia.db", "cordelia.db-wal", "cordelia.db-shm"] {
        let _ = std::fs::remove_file(relay.data_dir().join(file));
    }
    relay.start();
    let all = [&relay, &a, &b];
    wait_for("relay healthy again", &all, 30, || healthy(&relay));
    for n in [&a, &b] {
        wait_for("connected to the relay again", &all, 90, || has_hot_peer(n));
    }

    publish(&a, "after.md", "after");
    wait_for(
        "b reads what a wrote after the relay lost its database",
        &all,
        90,
        || reads(&b, "after.md", "after"),
    );

    // A relay is a cache. Its devices send it again what it lost: a
    // device added now, which has only the relay to fetch from, gets all
    // of it.
    let mut d = node("d", "personal", Some(relay.p2p));
    d.start();
    let all = [&relay, &a, &b, &d];
    wait_for("d healthy", &all, 30, || healthy(&d));
    wait_for("d connected to the relay", &all, 60, || has_hot_peer(&d));
    pair(&a, &d, "d", &all);
    holds_the_name(&d);
    wait_for(
        "the new device reads what was written before the relay lost its database",
        &all,
        120,
        || {
            (0..5)
                .all(|n| reads(&d, &format!("before-{n}.md"), "before").is_some())
                .then_some(())
        },
    );

    // Of the older kind the relay fetches again what it lost, from what
    // stands in for a device that holds it: it asks whoever connects
    // which channels it holds.
    let stored = |relay: &Node| -> u64 {
        serde_json::from_str::<serde_json::Value>(&relay.cli(&["stats", "--json"])).unwrap()
            ["items_stored"]
            .as_u64()
            .unwrap()
    };
    assert_eq!(stored(&relay), 0);
    let (_manager, conn) = client_of(&relay, older).await;
    serves_the_older_kind(&conn, vec![before]);
    wait_for(
        "the relay fetches the entry of the older kind again",
        &[&relay],
        90,
        || (stored(&relay) == 1).then_some(()),
    );
    // The relay says that it fetched, and says from which channel only for
    // debugging.
    let log = std::fs::read_to_string(relay.log()).unwrap();
    assert!(log.contains("pull-sync page complete"), "{log}");
    assert_names_channels_only_for_debugging(&relay, &[OLDER]);
}

/// A device with a great many small entries to send is never the one its
/// relay refuses. A relay counts each entry as its content and what an
/// entry takes beyond it, and a device paces itself by the same count: if
/// it counted content alone, it would send several times what the relay
/// allows a connection, and be refused and then cut off.
#[test]
fn a_device_with_many_small_entries_is_never_refused_by_its_relay() {
    const ENTRIES: u64 = 1100;
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
    pair(&a, &b, "b", &[&relay, &a, &b]);
    holds_the_name(&a);
    wait_for("a has sent what it holds so far", &[&relay, &a], 90, || {
        (a.get("/api/v1/status")?["outbox_waiting"] == 0).then_some(())
    });
    let before = entries_at(&relay);

    // About a kilobyte each as an entry holds it: a megabyte of content,
    // which costs two.
    let text = "x".repeat(900);
    for n in 0..ENTRIES {
        publishes(
            &a,
            &format!("small-{n:04}"),
            serde_json::json!({ "n": n, "text": text }),
        );
    }
    wait_for("the relay holds every entry", &[&relay, &a], 240, || {
        (entries_at(&relay) >= before + ENTRIES).then_some(())
    });
    // Each is held as what was meant: a kilobyte of content.
    let of_a_kilobyte: i64 = store_of(&relay)
        .query_row(
            "SELECT COUNT(*) FROM entries WHERE length(content) = 1024",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(of_a_kilobyte as u64, ENTRIES);
    let log = std::fs::read_to_string(relay.log()).unwrap_or_default();
    for refusal in [
        "over the byte allowance",
        "rate limit exceeded",
        "over its rate limits",
    ] {
        assert!(
            !log.contains(refusal),
            "the relay refused its device: {refusal}"
        );
    }
}

/// The topology we run: two relays that list each other. Each keeps the
/// other as its hot peer, so the devices are warm at both. Both relays lose
/// their databases while the devices are away.
///
/// A relay is a cache, and its devices are where the entries are: each
/// device that connects sends a relay which holds nothing of a channel of
/// its own what it holds, whether or not the relay counts that device
/// among its hot peers. A device added afterwards, which has only the
/// relays to fetch from, gets what was written before.
///
/// Of the older kind of channel, which a relay carries as it did (decision
/// 2026-10-04 §10), it is the relay that asks each peer that connects
/// which channels it holds, and fetches what it lacks, whether or not it
/// counts that peer among its hot ones: a stand-in for a device of that
/// kind shows it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_that_list_each_other_are_filled_again_by_their_devices() {
    const OLDER: &str = "grp_550e8400-e29b-41d4-a716-446655440000";
    let mut r1 = node("relay1", "relay", None);
    let mut r2 = node_with_relays(
        "relay2",
        "relay",
        &[(format!("localhost:{}", r1.p2p), Some(key_of(&r1)))],
    );
    r1.add_relay(&format!("localhost:{}", r2.p2p), Some(&key_of(&r2)));
    let (r1_key, r2_key) = (key_of(&r1), key_of(&r2));
    let meshed = |r1: &Node, r2: &Node| {
        (peer_keys(r1).contains(&r2_key) && peer_keys(r2).contains(&r1_key)).then_some(())
    };
    r1.start();
    wait_for("relay1 healthy", &[&r1], 30, || healthy(&r1));
    r2.start();
    wait_for("relay2 healthy", &[&r1, &r2], 30, || healthy(&r2));
    wait_for("the relays mesh", &[&r1, &r2], 60, || meshed(&r1, &r2));

    let both = [
        format!("localhost:{}", r1.p2p),
        format!("localhost:{}", r2.p2p),
    ];
    let mut a = node_with_bootnodes("a", "personal", &both);
    let mut b = node_with_bootnodes("b", "personal", &both);
    a.start();
    b.start();
    for n in [&a, &b] {
        let all = [&r1, &r2, &a, &b];
        wait_for("device healthy", &all, 30, || healthy(n));
        wait_for("device reaches both relays", &all, 60, || {
            (peer_keys(n).len() == 2).then_some(())
        });
    }
    pair(&a, &b, "b", &[&r1, &r2, &a, &b]);
    holds_the_name(&a);
    holds_the_name(&b);
    for n in 0..5 {
        publishes(
            &a,
            &format!("before-{n}.md"),
            serde_json::json!({ "text": "before" }),
        );
    }
    wait_for("b reads what a wrote", &[&r1, &r2, &a, &b], 90, || {
        reads(&b, "before-4.md", "before")
    });
    // And an entry of the older kind, from what stands in for a device
    // that holds one.
    let older = Arc::new(cordelia_crypto::identity::NodeIdentity::generate().unwrap());
    let before = entry_in(&older, OLDER, vec![7; 40]);
    let ack = push_to(&r1, older.clone(), std::slice::from_ref(&before)).await;
    assert_eq!(ack.stored, 1, "{ack:?}");

    // The devices are away, and both relays come back with nothing. They
    // find each other first, so each has its hot peer before a device
    // connects.
    a.stop();
    b.stop();
    r1.stop();
    r2.stop();
    for relay in [&r1, &r2] {
        for file in ["cordelia.db", "cordelia.db-wal", "cordelia.db-shm"] {
            let _ = std::fs::remove_file(relay.data_dir().join(file));
        }
    }
    r1.start();
    wait_for("relay1 healthy again", &[&r1], 30, || healthy(&r1));
    r2.start();
    wait_for("relay2 healthy again", &[&r1, &r2], 30, || healthy(&r2));
    wait_for("the relays mesh again", &[&r1, &r2], 120, || {
        meshed(&r1, &r2)
    });

    // Of the older kind, a relay asks whoever connects, hot or not: what
    // stands in for a device connects to the first relay, is no hot peer
    // of it, and is asked for what the relay lacks.
    let stored = |relay: &Node| -> u64 {
        serde_json::from_str::<serde_json::Value>(&relay.cli(&["stats", "--json"])).unwrap()
            ["items_stored"]
            .as_u64()
            .unwrap()
    };
    assert_eq!(stored(&r1), 0);
    {
        let older_key = cordelia_crypto::bech32::encode_public_key(&older.public_key()).unwrap();
        let (_manager, conn) = client_of(&r1, older).await;
        serves_the_older_kind(&conn, vec![before]);
        wait_for(
            "the relay fetches the entry of the older kind again",
            &[&r1, &r2],
            90,
            || (stored(&r1) == 1).then_some(()),
        );
        let listed = r1.get("/api/v1/peers").unwrap();
        let as_a_peer = listed["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|peer| peer["key"] == older_key.as_str())
            .unwrap_or_else(|| panic!("the relay does not list what stands in: {listed}"));
        assert_ne!(as_a_peer["state"], "hot", "{listed}");
        conn.close(0u32.into(), b"done");
    }

    a.start();
    b.start();
    for n in [&a, &b] {
        let all = [&r1, &r2, &a, &b];
        wait_for("device healthy again", &all, 30, || healthy(n));
        wait_for("device reaches both relays again", &all, 120, || {
            (peer_keys(n).len() == 2).then_some(())
        });
    }
    // What this test is about: each relay's hot peer is the other relay,
    // and no device is a hot peer of either.
    for relay in [&r1, &r2] {
        // A relay's own list is a moment behind its devices'.
        let peers = wait_for(
            "the relay lists both devices",
            &[&r1, &r2, &a, &b],
            30,
            || {
                let listed = relay.get("/api/v1/peers")?;
                let peers = listed["peers"].as_array()?.clone();
                (peers.len() == 3).then_some(peers)
            },
        );
        for peer in &peers {
            assert_eq!(peer["state"] == "hot", peer["role"] == "relay", "{peer}");
        }
    }

    // A device added now has only the relays to fetch from.
    let mut d = node_with_bootnodes("d", "personal", &both);
    d.start();
    let all = [&r1, &r2, &a, &b, &d];
    wait_for("d healthy", &all, 30, || healthy(&d));
    wait_for("d reaches both relays", &all, 60, || {
        (peer_keys(&d).len() == 2).then_some(())
    });
    pair(&a, &d, "d", &all);
    holds_the_name(&d);
    wait_for(
        "the new device reads what was written before the relays lost their databases",
        &all,
        120,
        || {
            (0..5)
                .all(|n| reads(&d, &format!("before-{n}.md"), "before").is_some())
                .then_some(())
        },
    );
}

/// A channel holds more than fits in one message. A device that fetches it
/// still gets all of it: a relay answers a request for a page of entries
/// with as many as one message holds, and the device asks on from there.
#[test]
fn a_channel_larger_than_one_message_still_syncs() {
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
    pair(&a, &b, "b", &[&relay, &a, &b]);
    holds_the_name(&a);
    holds_the_name(&b);

    // B is away while A writes twenty entries of 60 KB: 1.2 MB, more than
    // one message holds, and all within one page of the channel's list.
    b.stop();
    let text = "x".repeat(60_000);
    for n in 0..20 {
        publishes(
            &a,
            &format!("big-{n:02}.md"),
            serde_json::json!({ "text": text }),
        );
    }
    wait_for("a's entries reached the relay", &[&relay, &a], 120, || {
        (a.get("/api/v1/status")?["outbox_waiting"] == 0).then_some(())
    });

    b.start();
    let all = [&relay, &a, &b];
    wait_for("b healthy again", &all, 30, || healthy(&b));
    wait_for("b holds all twenty entries", &all, 180, || {
        let held = held(&b)
            .iter()
            .filter(|e| e["key"].as_str().is_some_and(|k| k.starts_with("big-")))
            .count();
        (held == 20).then_some(())
    });
}

/// A personal node only dials out. It starts and reaches its relay while
/// something else holds its configured P2P port, so it cannot be listening
/// there; told to listen, the same node needs the port and cannot start.
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
    let log = std::fs::read_to_string(a.log()).unwrap();
    assert!(log.contains("dials out only"), "{}", a.log_tail());
    // And what a node with no identity is checked not to have reached.
    for line in A_STARTED_NODE_LOGS {
        assert!(log.contains(line), "{line}: {}", a.log_tail());
    }

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

/// No test node dials the default relays, which are real and public: a
/// node that reached them from a test would be counted there as
/// somebody's device, and would leave its channels behind. A personal node
/// that is configured with no relay does dial them, so the harness never
/// leaves one with none: a test that gives a node no relay gets a node
/// whose one relay is an address on this machine where nothing listens.
#[test]
fn a_test_node_that_is_given_no_relay_dials_none_of_the_public_ones() {
    let mut n = node("alone", "personal", None);
    // Looked at before the node is started: one that did have the default
    // relays is not to be run to show it.
    let config = std::fs::read_to_string(n.config()).unwrap();
    let dialled = format!("[[network.bootnodes]]\naddr = \"{NOWHERE}\"");
    assert_eq!(
        config.matches("[[network.bootnodes]]").count(),
        1,
        "{config}"
    );
    assert!(config.contains(&dialled), "{config}");
    for public in cordelia_core::protocol::FALLBACK_PEERS {
        let host = public.rsplit_once(':').unwrap().0;
        assert!(!config.contains(host), "{config}");
    }

    // And the node says the same of itself: its one relay is that address.
    n.start();
    wait_for("node healthy", &[&n], 30, || healthy(&n));
    // (It lists its relays once its network loop has begun.)
    let hosts = wait_for("the node lists its relays", &[&n], 30, || {
        let hosts: Vec<String> = relays_of(&n)
            .iter()
            .filter_map(|relay| relay["host"].as_str().map(String::from))
            .collect();
        (!hosts.is_empty()).then_some(hosts)
    });
    assert_eq!(hosts, [NOWHERE]);
    // Which is what the harness read from its configuration before it
    // started the node.
    assert_eq!(hosts, n.will_dial());
    n.stop();

    // A relay that is given none dials nothing, and is left with none.
    let relay = node("relay", "relay", None);
    let config = std::fs::read_to_string(relay.config()).unwrap();
    assert!(!config.contains("[[network.bootnodes]]"), "{config}");
    assert!(relay.will_dial().is_empty());

    // And of a relay that is given one, the harness reads what the relay
    // then says of itself.
    let mut second = node_with_bootnode("second", "relay", Some(NOWHERE.into()));
    assert_eq!(second.will_dial(), [NOWHERE]);
    second.start();
    wait_for("relay healthy", &[&second], 30, || healthy(&second));
    let hosts = wait_for("the relay lists its relays", &[&second], 30, || {
        let hosts: Vec<String> = relays_of(&second)
            .iter()
            .filter_map(|relay| relay["host"].as_str().map(String::from))
            .collect();
        (!hosts.is_empty()).then_some(hosts)
    });
    assert_eq!(hosts, second.will_dial());
}

/// A loopback address passes in each form the node reads as one, and so
/// does `localhost`.
#[test]
fn the_harness_takes_an_address_of_this_machine() {
    for addr in ["127.0.0.1:9", "127.0.0.2:9474", "[::1]:9474", "localhost:9"] {
        assert_on_this_machine("here", addr);
    }
}

/// One name passes that is no address of this machine: the one under
/// which nothing can be looked up, since it has no port. The same name
/// with a port could be looked up, and does not pass.
#[test]
fn the_harness_takes_the_name_under_which_nothing_is_looked_up() {
    use std::net::ToSocketAddrs;
    assert!(!NO_SUCH_NAME.contains(':'));
    let read = NO_SUCH_NAME.to_socket_addrs().map(|_| ());
    assert_eq!(
        read.map_err(|e| e.kind()),
        Err(std::io::ErrorKind::InvalidInput)
    );
    assert_on_this_machine("here", NO_SUCH_NAME);
    let with_a_port = format!("{NO_SUCH_NAME}:9474");
    let refused = std::panic::catch_unwind(|| assert_on_this_machine("odd", &with_a_port));
    assert!(refused.is_err(), "{with_a_port} passed");
}

/// What the node would not read as an address it takes for a name, and
/// looks up: such a form does not pass, though the address inside it is
/// this machine's.
#[test]
#[should_panic(expected = "not on this machine")]
fn the_harness_refuses_what_the_node_would_take_for_a_name() {
    assert_on_this_machine("odd", "[127.0.0.1]:9");
}

/// A node, and each command that the harness runs, is run without three
/// things of the caller's: any `CORDELIA_` variable, `RUST_LOG` and any
/// proxy; none of git's own variables, which would point the `git` that
/// a node runs, and the one a test runs, at the caller's repository; and
/// not `STY`, which would tell a command that it runs inside GNU
/// `screen` because the tests do. It is given its own data directory and
/// home, and the rest is left.
///
/// This is a test of the function that removes them, given the names: no
/// node is spawned here with such a variable set, and that the harness
/// gives the function the real environment's names is not under test.
#[test]
fn a_node_is_given_none_of_the_callers_settings() {
    let n = node("alone", "personal", None);
    let inherited = [
        "CORDELIA_BOOTNODES",
        "CORDELIA_DATA_DIR",
        "HTTP_PROXY",
        "all_proxy",
        "no_proxy",
        "PATH",
        "RUST_LOG",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GITHUB_SHA",
        "STY",
        "STYLE",
    ];
    let command = n.binary_given(inherited.iter().map(std::ffi::OsString::from));
    let set = |name: &str| -> Option<Option<PathBuf>> {
        let found = command.get_envs().find(|(key, _)| *key == name)?;
        Some(found.1.map(PathBuf::from))
    };
    // Removed.
    for name in [
        "CORDELIA_BOOTNODES",
        "HTTP_PROXY",
        "all_proxy",
        "no_proxy",
        "RUST_LOG",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "STY",
    ] {
        assert_eq!(set(name), Some(None), "{name}");
    }
    // Its own.
    assert_eq!(set("CORDELIA_DATA_DIR"), Some(Some(n.data_dir())));
    assert_eq!(set("HOME"), Some(Some(n.home())));
    // Left as it is: what is not git's own is not taken for it, nor what
    // only begins as the variable of `screen` does.
    assert_eq!(set("PATH"), None);
    assert_eq!(set("GITHUB_SHA"), None);
    assert_eq!(set("STYLE"), None);
}

/// A node with no identity does not start: it stops before it opens a
/// socket or looks a name up. Four of the tests below rest on that. Each
/// of them starts a node that the harness should have refused, with its
/// identity taken away, so that even with the refusal gone nothing
/// reaches a relay.
#[test]
fn a_node_with_no_identity_stops_before_it_dials() {
    let mut n = node("bare", "personal", None);
    std::fs::remove_file(n.data_dir().join("identity.key")).unwrap();
    n.start();
    let mut child = n.child.take().unwrap();
    let told = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if told.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            panic!(
                "a node with no identity is still running:\n{}",
                n.log_tail()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(!status.success());
    let log = std::fs::read_to_string(n.log()).unwrap();
    assert!(log.contains("Node not initialised"), "{log}");
    // It got no further: not to the banner it prints once it has its
    // identity, not to its endpoint, and not to the relays it would then
    // have worked out. (The harness's configuration logs at debug, and
    // the node is given no `RUST_LOG` to say otherwise.)
    for later in A_STARTED_NODE_LOGS {
        assert!(!log.contains(later), "{later}: {log}");
    }
}

/// The harness refuses to give a node a relay that is not on this machine,
/// when the node is made. Nothing is started, and nothing is asked of the
/// network to find out. (The address is one kept for documentation, which
/// no machine has.)
#[test]
#[should_panic(expected = "not on this machine")]
fn the_harness_refuses_a_relay_that_is_not_on_this_machine() {
    node_with_bootnode("far", "personal", Some("192.0.2.1:9474".into()));
}

/// And when a relay is added to a node that is already made, and when it
/// is given by a name other than `localhost`.
#[test]
#[should_panic(expected = "not on this machine")]
fn the_harness_refuses_to_add_a_relay_that_is_not_on_this_machine() {
    let relay = node("relay", "relay", None);
    relay.add_relay("relay.example:9474", None);
}

/// A node is not started if a relay it would dial is not on this machine,
/// whatever wrote its configuration. Here a test has taken the stand-in
/// relay out of a personal node's configuration, so that the node would
/// dial the default relays: the harness reads the configuration as the
/// node will, and stops before the node is started.
///
/// (In each of these tests the node's identity is taken away first. A
/// node that finds none stops before it opens a socket, so that even with
/// the check gone, and the node started, nothing would reach a relay.)
#[test]
#[should_panic(expected = "not on this machine")]
fn a_node_that_would_dial_a_public_relay_is_not_started() {
    let mut n = node("bare", "personal", None);
    let config = std::fs::read_to_string(n.config()).unwrap();
    let stand_in = format!("[[network.bootnodes]]\naddr = \"{NOWHERE}\"\n");
    assert!(config.contains(&stand_in), "{config}");
    std::fs::write(n.config(), config.replace(&stand_in, "")).unwrap();
    assert_eq!(
        n.will_dial(),
        cordelia_core::protocol::FALLBACK_PEERS.to_vec(),
        "a personal node that names no relay dials the default ones"
    );
    std::fs::remove_file(n.data_dir().join("identity.key")).unwrap();
    n.start();
}

/// The same for a node whose configuration is not there at all: the node
/// would run on its defaults, which name the public relays.
#[test]
#[should_panic(expected = "not on this machine")]
fn a_node_with_no_configuration_is_not_started() {
    let mut n = node("unconfigured", "personal", None);
    std::fs::remove_file(n.config()).unwrap();
    std::fs::remove_file(n.data_dir().join("identity.key")).unwrap();
    n.start();
}

/// And for a relay whose configuration has come to name a relay on
/// another machine. (The address is one kept for documentation.)
#[test]
#[should_panic(expected = "not on this machine")]
fn a_relay_that_would_dial_another_machine_is_not_started() {
    let mut relay = node("relay", "relay", None);
    let mut config = std::fs::read_to_string(relay.config()).unwrap();
    config.push_str("\n[[network.bootnodes]]\naddr = \"192.0.2.1:9474\"\n");
    std::fs::write(relay.config(), config).unwrap();
    assert_eq!(relay.will_dial(), ["192.0.2.1:9474"]);
    std::fs::remove_file(relay.data_dir().join("identity.key")).unwrap();
    relay.start();
}

/// The harness starts a node with no variable but one it knows not to
/// change where the node dials: its look at that is at the file, and a
/// variable could stand in place of what the file says.
#[test]
#[should_panic(expected = "may not be started with")]
fn the_harness_starts_a_node_with_no_variable_it_does_not_know() {
    let mut n = node("alone", "personal", None);
    n.start_given(&[("CORDELIA_BOOTNODES", "relay.example:9474")]);
}

/// The harness reads what a command left at its terminal: what was typed
/// there and not read, which whoever reads the terminal next is handed,
/// as a shell is once a command has ended. Here a command asks one yes.
/// Two lines are typed at once: the first answers it, and the second is
/// left. So a test that finds nothing left has looked where something
/// would be. And keys that are sent at once are sent with no moment
/// before them.
#[test]
fn the_harness_reads_what_a_command_left_typed_at_its_terminal() {
    let mut n = node("alone", "personal", None);
    n.start();
    wait_for("the node is up", &[&n], 30, || healthy(&n));
    let other = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
    let other = cordelia_crypto::bech32::encode_public_key(&other.public_key()).unwrap();

    let mut at = n.at_terminal(&["accept", &other]);
    at.says("Type yes to go on");
    let asked = std::time::Instant::now();
    let sent = at.sends(b"no\nleft behind\n");
    assert!(sent >= asked && sent.elapsed() < std::time::Duration::from_secs(1));
    let (success, said, left) = at.ends_and_leaves();
    assert!(success, "{said}");
    assert!(
        said.contains("That was not a yes. Nothing was done."),
        "{said}"
    );
    assert_eq!(left, "left behind\n");

    // With one line typed, nothing is left.
    let mut at = n.at_terminal(&["accept", &other]);
    at.says("Type yes to go on").types("no");
    let (_, said, left) = at.ends_and_leaves();
    assert!(
        said.contains("That was not a yes. Nothing was done."),
        "{said}"
    );
    assert_eq!(left, "");
}

/// What a command says at its terminal arrives in pieces, and a piece can
/// end in the middle of a character of several bytes, as a mark is. The
/// harness keeps the bytes that begin one until the rest has come: they
/// are never read as two characters that are none.
#[test]
fn the_harness_keeps_a_character_that_arrived_in_part_for_its_rest() {
    let tick = "\u{2713}".as_bytes();
    assert_eq!(tick.len(), 3);
    let said = [b"   1. ", tick, b"\r\n"].concat();
    // Whole: nothing is kept back, after plain text or after a mark.
    for whole in [&b""[..], &said[..6], &said[..9], &said[..]] {
        assert_eq!(begun_at_the_end(whole), 0, "{whole:?}");
    }
    // Cut in the mark: its one byte, or its two, wait for the rest.
    assert_eq!(begun_at_the_end(&said[..7]), 1);
    assert_eq!(begun_at_the_end(&said[..8]), 2);
    // A character of two bytes, and one of four.
    let (two, four) = ("\u{e9}".as_bytes(), "\u{1f511}".as_bytes());
    assert_eq!((two.len(), four.len()), (2, 4));
    assert_eq!(begun_at_the_end(&two[..1]), 1);
    assert_eq!(begun_at_the_end(two), 0);
    for cut in 1..4 {
        assert_eq!(begun_at_the_end(&four[..cut]), cut);
    }
    assert_eq!(begun_at_the_end(four), 0);
    // Bytes that are the middle of nothing are kept back by nothing.
    assert_eq!(begun_at_the_end(&[b'a', 0x80, 0x80]), 0);
    assert_eq!(begun_at_the_end(&[0x80, 0x80, 0x80, 0x80]), 0);
}

/// The harness makes personal nodes and relays: what those will dial can
/// be known before they are started. A node of another role dials the
/// addresses its peers hand it, which nothing read beforehand can show,
/// so the harness makes none.
#[test]
#[should_panic(expected = "does not run one")]
fn the_harness_makes_no_node_whose_dialling_it_cannot_check() {
    node("boot", "bootnode", None);
}

/// And it starts none, where a configuration has come to name such a
/// role.
#[test]
#[should_panic(expected = "does not run one")]
fn a_node_whose_dialling_cannot_be_checked_is_not_started() {
    let mut n = node("turned", "relay", None);
    let config = std::fs::read_to_string(n.config()).unwrap();
    assert!(config.contains("role = \"relay\""), "{config}");
    let turned = config.replace("role = \"relay\"", "role = \"bootnode\"");
    std::fs::write(n.config(), turned).unwrap();
    std::fs::remove_file(n.data_dir().join("identity.key")).unwrap();
    n.start();
}

/// A command asks its own node directly, whatever proxy the environment
/// names: a proxy is for the network, and a request to this machine
/// carries the node's token. Here every proxy variable names something
/// on this machine that counts who calls it and answers with a refusal.
/// A client that takes the proxy is counted and refused; each command
/// works, and none of them calls it.
#[test]
fn a_command_asks_its_own_node_and_no_proxy() {
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut n = node("alone", "personal", None);
    n.start();
    wait_for("node healthy", &[&n], 30, || healthy(&n));

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            counted.fetch_add(1, Ordering::SeqCst);
            let mut stream = stream;
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n");
        }
    });
    // What stands in for a proxy does count a caller, and does refuse
    // one: a client told to use it, asking the node what a command asks,
    // is counted, and gets nothing.
    let through: ureq::Agent = ureq::Agent::config_builder()
        .proxy(Some(ureq::Proxy::new(&proxy).unwrap()))
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();
    let asked = through
        .get(&format!("http://127.0.0.1:{}/api/v1/status", n.http))
        .header("Authorization", &format!("Bearer {}", n.token()))
        .call();
    assert!(asked.is_err(), "the stand-in passed a request on");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // The harness passes a command no proxy of the caller's, and nothing
    // of theirs that excepts this machine from one. Here it is given
    // every name the client reads a proxy from, and an empty list of
    // exceptions.
    let named = [
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
    ];
    let mut given = named.map(|name| (name, proxy.as_str())).to_vec();
    given.extend([("NO_PROXY", ""), ("no_proxy", "")]);
    let run = |args: &[&str]| {
        let mut command = n.command_for(&given, args);
        // The command has them: the test is not passing for want of them.
        for (name, value) in &given {
            let set = command
                .get_envs()
                .find(|(key, _)| *key == std::ffi::OsStr::new(name))
                .and_then(|(_, value)| value);
            assert_eq!(set, Some(std::ffi::OsStr::new(value)), "{name}");
        }
        command.output().unwrap()
    };
    // One that reads, one that posts, and the one that does both.
    for args in [&["peers", "--json"][..], &["devices"], &["status"]] {
        let out = run(args);
        assert!(
            out.status.success(),
            "cordelia {args:?}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "cordelia {args:?}");
    }
    // The answers came from the node: its own key is in what it lists,
    // and `status`, which succeeds whether or not it reached a node, says
    // that it did.
    let listed = String::from_utf8_lossy(&run(&["devices"]).stdout).into_owned();
    let own = format!("This device: {}", key_of(&n));
    assert!(listed.contains(&own), "{listed}");
    let status = String::from_utf8_lossy(&run(&["status"]).stdout).into_owned();
    assert!(status.contains("Running:   yes"), "{status}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// A command asks the node at one of the two addresses that the node's
/// API may have, and at no other: its request carries the node's token.
/// With the API's address set to another (an address, or a name), a
/// command that reads and one that posts each say why they do not ask,
/// every form of `status` says that the node was not asked (not that it
/// is stopped), and the node itself does not start, and says the same.
///
/// (Neither value leaves this machine, so nothing does with a refusal
/// taken out either: `127.0.0.2` is another address of the machine on
/// Linux, and elsewhere traffic to it stays on the machine; and
/// `localhost` is looked up first, as the harness looks up a relay's
/// name, and the test goes no further where it is not this machine.)
#[test]
fn a_command_asks_no_address_but_the_nodes_own() {
    assert_on_this_machine("idle", "localhost:9");
    let mut n = node("idle", "personal", None);
    for other in ["127.0.0.2", "localhost"] {
        let given = [("CORDELIA_BIND_ADDRESS", other)];
        let named = format!("'{other}'");
        for args in [&["peers", "--json"][..], &["devices"]] {
            let out = n.command_given(&given, args);
            let said = String::from_utf8_lossy(&out.stderr);
            assert!(!out.status.success(), "cordelia {args:?}");
            assert!(
                said.contains(&named) && said.contains("nowhere else"),
                "cordelia {args:?}: {said}"
            );
        }
        let out = n.command_given(&given, &["status"]);
        let said = String::from_utf8_lossy(&out.stdout);
        assert!(
            said.contains("Running:   not asked") && said.contains(&named),
            "{said}"
        );
        assert!(!said.contains("cordelia start"), "{said}");
        // The forms that a bar and a panel read say it too.
        let out = n.command_given(&given, &["status", "--line"]);
        let said = String::from_utf8_lossy(&out.stdout);
        assert!(
            said.contains("not asked") && !said.contains("stopped"),
            "{said}"
        );
        let out = n.command_given(&given, &["status", "--json"]);
        let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(said["state"], "attention", "{said}");
        let summary = said["summary"].as_str().unwrap();
        assert!(summary.contains("not asked"), "{said}");
        // It is not said to be stopped, or running, and the reason is there.
        assert!(said["running"].is_null(), "{said}");
        assert!(
            said["not_asked"].as_str().unwrap().contains(&named),
            "{said}"
        );
        // A node that was not asked has a state of its own, and no
        // level: the bar is drawn as it was before there was a level,
        // `active` with `attention`, and the line in red.
        assert!(said["level"].is_null(), "{said}");
        let out = n.command_given(&given, &["status", "--waybar"]);
        let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            said["class"],
            serde_json::json!(["attention", "active"]),
            "{said}"
        );
        let out = n.command_given(&given, &["status", "--line"]);
        let line = String::from_utf8_lossy(&out.stdout);
        assert!(line.contains("▲ memory: node not asked"), "{line}");
        let tooltip = said["tooltip"].as_str().unwrap();
        assert!(
            tooltip.contains("not asked") && tooltip.contains(&named),
            "{said}"
        );

        // The node holds itself to the same: it does not start there, and
        // says which address, and where it is set.
        n.start_given(&given);
        let mut child = n.child.take().unwrap();
        let told = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if told.elapsed() > Duration::from_secs(30) {
                let _ = child.kill();
                panic!("a node started at {other}:\n{}", n.log_tail());
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(!status.success());
        let log = std::fs::read_to_string(n.log()).unwrap();
        assert!(
            log.contains(&named) && log.contains("CORDELIA_BIND_ADDRESS"),
            "{log}"
        );
        // A person who upgrades with the name in their configuration is
        // told what to write.
        assert_eq!(log.contains("write `127.0.0.1`"), other == "localhost");
    }
}

/// A node whose API address is `::1` listens there and not at
/// `127.0.0.1`, and a command reaches it there: the address is written in
/// brackets before a port, by the node and by a command alike. (On a
/// machine with no `::1` to listen on the test says so and shows nothing:
/// what it says is seen only where the run prints what a passing test
/// printed.)
#[test]
fn a_node_at_the_ipv6_address_is_reached_there() {
    if let Err(e) = std::net::TcpListener::bind("[::1]:0") {
        eprintln!("not run: this machine has no [::1] to listen on ({e})");
        return;
    }
    let mut n = node("six", "personal", None);
    // The other address at the node's port is held here for as long as
    // the test runs: a node that listened there too could not start, and
    // nothing else can come to answer there.
    let _held = std::net::TcpListener::bind(("127.0.0.1", n.http)).unwrap();
    let given = [("CORDELIA_BIND_ADDRESS", "::1")];
    n.start_given(&given);
    let running = || {
        let out = n.command_given(&given, &["status"]);
        let said = String::from_utf8_lossy(&out.stdout);
        said.contains("Running:   yes").then_some(())
    };
    wait_for("the node to answer at ::1", &[&n], 30, running);
    let out = n.command_given(&given, &["devices"]);
    let listed = String::from_utf8_lossy(&out.stdout);
    let own = format!("This device: {}", key_of(&n));
    assert!(out.status.success() && listed.contains(&own), "{listed}");

    // There, as the node says when it starts.
    let log = std::fs::read_to_string(n.log()).unwrap();
    assert!(log.contains(&format!("http://[::1]:{}/", n.http)), "{log}");
    n.stop();
}

/// Read a request's head from `stream` and answer it with `head` (a
/// status line and any header lines) and `body`, as JSON.
fn answer(stream: &mut std::net::TcpStream, head: &str, body: &str) {
    use std::io::{Read, Write};
    let mut seen = Vec::new();
    let mut byte = [0u8; 1];
    while !seen.ends_with(b"\r\n\r\n") && stream.read(&mut byte).is_ok_and(|n| n == 1) {
        seen.push(byte[0]);
    }
    let _ = stream.write_all(
        format!(
            "{head}content-type: application/json\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
}

/// A command follows no redirect, and reads none as the node's answer:
/// the node's API sends none, and a request carries the node's token.
/// Here what listens at the node's port answers every request with a
/// redirect to another listener, which counts who calls it, and with what
/// a node's status would be. A client that follows redirects is counted
/// there. A command is not, and does not take the answer for the node's.
#[test]
fn a_command_follows_no_redirect() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let n = node("idle", "personal", None);
    let status =
        r#"{"version":"0.0.0","uptime_secs":1,"error":{"message":"said by what answered"}}"#;

    let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let there = target.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    std::thread::spawn(move || {
        for mut stream in target.incoming().flatten() {
            counted.fetch_add(1, Ordering::SeqCst);
            answer(&mut stream, "HTTP/1.1 200 OK\r\n", status);
        }
    });
    let stand_in = std::net::TcpListener::bind(("127.0.0.1", n.http)).unwrap();
    let redirect = format!("HTTP/1.1 302 Found\r\nlocation: http://{there}/api/v1/status\r\n");
    std::thread::spawn(move || {
        for mut stream in stand_in.incoming().flatten() {
            answer(&mut stream, &redirect, status);
        }
    });
    // What stands in for the node does send a client on, and what it
    // sends it to does count it: a client that follows redirects, asking
    // what a command asks, gets its answer there.
    let follows: ureq::Agent = ureq::Agent::config_builder()
        .proxy(None)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();
    let asked = follows
        .get(&format!("http://127.0.0.1:{}/api/v1/status", n.http))
        .call();
    assert!(asked.is_ok_and(|answer| answer.status() == 200));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // `status` succeeds whether or not it reached a node, and does not
    // say that it reached one.
    let out = n.command(&["status"]);
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{said}");
    assert!(said.contains("Running:   no (start it"), "{said}");
    // One that reads, and one that posts: each fails, says that what
    // answered is not the node, and repeats nothing of what it said.
    for args in [&["peers", "--json"][..], &["devices"]] {
        let out = n.command(args);
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "cordelia {args:?}: {said}");
        assert!(
            said.contains("is not the node") && !said.contains("said by what answered"),
            "cordelia {args:?}: {said}"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn cli_reports_when_the_node_is_not_running() {
    let n = node("idle", "personal", None);
    let stderr = n.refused(&["devices"]);
    assert!(stderr.contains("cordelia start"), "{stderr}");

    // `status` still works, and says the node is not running.
    let status = n.cli(&["status"]);
    assert!(status.contains("Running:   no"), "{status}");
    let line = n.cli(&["status", "--line"]);
    assert!(line.contains("memory: node stopped"), "{line}");
    let json: serde_json::Value = serde_json::from_str(&n.cli(&["status", "--json"])).unwrap();
    assert_eq!(json["state"], "stopped", "{json}");

    // On a machine without Cordelia (an empty home directory), the status
    // line prints nothing. (Built by hand: the harness would give it this
    // node's configuration and home. It finds no identity, so it asks
    // nothing of any node, whatever else the caller's environment says.)
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

/// `cordelia init` ends by saying how the node is started, where a
/// person runs it. Run by a script (`--non-interactive`), as the install
/// script runs it, it says nothing of `cordelia start`: the script names
/// the command that starts the node as the service.
#[test]
fn init_run_by_a_script_does_not_say_how_to_start_the_node() {
    let n = node("fresh", "personal", None);
    let by_a_person = n.cli(&["init"]);
    assert!(
        by_a_person.ends_with("\nNode is ready. Run `cordelia start` to begin.\n"),
        "{by_a_person}"
    );
    let by_a_script = n.cli(&["init", "--non-interactive"]);
    assert!(by_a_script.ends_with("\nNode is ready.\n"), "{by_a_script}");
    assert!(!by_a_script.contains("cordelia start"), "{by_a_script}");
}

/// A clone of this repository at `rel` under `home`: a git repository
/// whose remote is this project's. Returns where it is.
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
        // Without git's own variables: `GIT_DIR`, where the caller has
        // it set, would make these act on the caller's repository.
        let mut git = Command::new("git");
        for (name, _) in std::env::vars_os() {
            if name.to_str().is_some_and(|name| name.starts_with("GIT_")) {
                git.env_remove(&name);
            }
        }
        assert!(
            git.arg("-C")
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
/// Once the two are one person's devices, with `cordelia sync claude` and
/// the same names mapped on both, memory Claude writes on one machine
/// appears on the other. Until a folder is mapped, nothing of it leaves
/// the machine.
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

    // The two become one person's devices, and then sync is switched on.
    pair(&a, &b, "b", &all);
    for n in [&a, &b] {
        let out = sync_on(n);
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
        "Only mapped folders sync.",
    ] {
        assert!(
            found.contains(expected),
            "missing {expected:?} in:\n{found}"
        );
    }
    // Nothing is mapped: the state is off. What is about a person's
    // devices holds all the same (decision 2026-10-04 §10.1): the device
    // that was added, and that nobody has cleared, is amber on each of
    // the two, and the line says it.
    for n in [&a, &b] {
        let s = state(n);
        assert_eq!(s["state"], "off", "{s}");
        assert_eq!(s["level"], "amber", "{s}");
        assert_eq!(
            s["summary"], "memory: 1 device added, not yet cleared",
            "{s}"
        );
        assert_eq!(s["holds"].as_array().unwrap().len(), 1, "{s}");
    }
    let s = state(&a);
    assert_eq!(s["sync"]["all"], false, "{s}");
    // Each is carried with whether `cordelia sync map` would sync it:
    // all three would, and so each has its directory under `cwd`.
    let unmapped = s["sync"]["unmapped"].as_array().unwrap();
    assert_eq!(unmapped.len(), 3, "{s}");
    for found in unmapped {
        assert_eq!(found["mappable"], true, "{found}");
        assert!(found["cwd"].is_string(), "{found}");
    }

    // What cannot be mapped by accident, or by a slip.
    let said = a.refused(&["sync", "map", &path(&a.home())]);
    assert!(said.contains("cordelia sync home on"), "{said}");
    let said = a.refused(&["sync", "map", &path(&a.home()), "team"]);
    assert!(said.contains("cordelia sync map ~ team --home"), "{said}");
    // The name `~` is offered as the command that maps home as `~`, and a
    // name that cannot be used is said to be one, with nothing offered
    // that would map home under another.
    let said = a.refused(&["sync", "map", &path(&a.home()), "~"]);
    assert!(said.contains("cordelia sync map ~ --home"), "{said}");
    let said = a.refused(&["sync", "map", &path(&a.home()), "not a name"]);
    assert!(said.contains("is not a name it can sync under"), "{said}");
    assert!(!said.contains("home on"), "{said}");
    let said = a.refused(&["sync", "map", &path(&a_repo), "--home"]);
    assert!(said.contains("--home is for the home directory"), "{said}");
    let said = a.refused(&["sync", "map", &path(&a_notes), "~"]);
    assert!(said.contains("the name of home memory"), "{said}");
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
    assert!(out.contains("Mapped ~ to home memory."), "{out}");
    // Mapping what is mapped, with no name, changes nothing and says the
    // name it has: for home without the flag, and for a folder whose name
    // is not the one it would get by default.
    let out = a.cli(&["sync", "map", &path(&a.home())]);
    assert!(
        out.contains("~ is already mapped to home memory. Nothing changed."),
        "{out}"
    );
    let out = a.cli(&["sync", "map", &path(&a_notes)]);
    assert!(
        out.contains("~/notes is already mapped to lab-notes. Nothing changed."),
        "{out}"
    );
    // A shell hands an unquoted `~` over as the home directory's path:
    // as a name, that is `~`, the name home has here.
    let out = a.cli(&["sync", "map", &path(&a.home()), &path(&a.home()), "--home"]);
    assert!(
        out.contains("~ is already mapped to home memory. Nothing changed."),
        "{out}"
    );
    let said = a.refused(&["sync", "map", &path(&a_notes), "other"]);
    assert!(
        said.contains(
            "~/notes is already mapped to lab-notes. To sync it under another name, unmap \
             it first: cordelia sync unmap ~/notes"
        ),
        "{said}"
    );
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
    // The level (decision 2026-10-04 §10.1). A device was added since
    // the last change, and nobody has cleared it: that is amber on each
    // device, with a mark of its own in the line and a class of its own
    // in the bar, and the state is as it was.
    for n in [&a, &b] {
        let s = state(n);
        assert_eq!(
            (&s["state"], &s["level"]),
            (&serde_json::json!("synced"), &serde_json::json!("amber"))
        );
        assert_eq!(s["summary"], "memory: 1 device added, not yet cleared");
        assert_eq!(s["holds"][0]["what"], "added", "{s}");
        assert_eq!(s["holds"].as_array().unwrap().len(), 1, "{s}");
    }
    let line = a.cli(&["status", "--line"]);
    assert!(line.contains("◆ memory: 1 device added"), "{line}");
    let bar: serde_json::Value = serde_json::from_str(&a.cli(&["status", "--waybar"])).unwrap();
    assert_eq!(
        bar["class"],
        serde_json::json!(["synced", "amber"]),
        "{bar}"
    );
    // Cleared on a device, nothing holds there: no level.
    for n in [&a, &b] {
        clears_what_it_tells(n);
        let s = state(n);
        assert!(s["level"].is_null(), "{s}");
        assert_eq!(s["holds"], serde_json::json!([]), "{s}");
        assert_eq!(s["summary"], "memory synced", "{s}");
    }
    let line = a.cli(&["status", "--line"]);
    assert!(line.contains("● memory synced"), "{line}");
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
    let person = &snapshot["person"];
    let listed = |which: &str| person[which].as_array().map_or(0, Vec::len);
    assert_eq!(listed("devices") + listed("added"), 2, "{snapshot}");
    let project = snapshot["sync"]["projects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["project"] == PROJECT)
        .unwrap_or_else(|| panic!("{snapshot}"));
    assert_eq!(project["mapped"], true, "{snapshot}");
    assert_eq!(project["cwd"], path(&a_repo), "{snapshot}");
    assert!(
        project["channel"]
            .as_str()
            .unwrap()
            .starts_with("cordelia_ch1"),
        "{snapshot}"
    );
    assert!(project["last_published_at"].is_string(), "{snapshot}");
    assert!(project["last_pulled_at"].is_string(), "{snapshot}");
    assert!(project["error"].is_null(), "{snapshot}");
    // Always there, for a panel to read: no file failed, and none more.
    assert_eq!(project["failed"], serde_json::json!([]), "{snapshot}");
    assert_eq!(project["failed_more"], 0, "{snapshot}");

    // One setting changes at a time; the others stay as they were. Turning
    // home memory off unmaps it.
    a.cli(&["sync", "home", "off"]);
    let s = state(&a);
    assert_eq!(s["sync"]["home"], false, "{s}");
    assert_eq!(mapped_names(&s), [PROJECT, "lab-notes"], "{s}");
    assert_eq!(s["sync"]["enabled"], true);

    // What is no more is refused, with what to do instead, and changes
    // nothing: everything found does not sync, and there is nothing left
    // to exclude (decision 2026-10-04 §10.1).
    let generation = a.post("/api/v1/sync/status", serde_json::json!({}))["generation"].clone();
    let dir = path(&a.home().join(".claude"));
    for everything in [
        &["sync", "claude", "--all"][..],
        &["sync", "claude", "--all", "--dir", &dir],
        &["sync", "claude", "--all", "--reset"],
        &["sync", "claude", "--all", "--no-home"],
    ] {
        let said = a.refused(everything);
        assert!(said.contains("only mapped folders sync"), "{said}");
        assert!(said.contains("cordelia sync map <folder>"), "{said}");
    }
    for exclusion in [
        &["sync", "exclude", "github.com/Client-Co/App.git"][..],
        &["sync", "exclude", "lab-notes"],
        &["sync", "include", "github.com/client-co/app"],
        &["sync", "claude", "--exclude", "Client-Co/App.GIT"],
    ] {
        let said = a.refused(exclusion);
        assert!(said.contains("nothing left to exclude"), "{said}");
        assert!(said.contains("cordelia sync unmap <folder>"), "{said}");
    }
    let s = state(&a);
    assert_eq!(s["sync"]["all"], false, "{s}");
    assert_eq!(s["sync"]["exclude"], serde_json::json!([]), "{s}");
    assert_eq!(s["sync"]["home"], false, "{s}");
    assert_eq!(mapped_names(&s), [PROJECT, "lab-notes"], "{s}");
    let after = a.post("/api/v1/sync/status", serde_json::json!({}));
    assert_eq!(after["generation"], generation, "nothing was sent: {after}");
    // The node refuses the same, from whoever asks it: a panel that is
    // not yet brought up to date. Nothing is changed, and no change is
    // counted.
    let asks: ureq::Agent = ureq::Agent::config_builder()
        .proxy(None)
        .http_status_as_error(false)
        .build()
        .into();
    let mut answer = asks
        .post(&format!("http://127.0.0.1:{}/api/v1/sync/claude", a.http))
        .header("Authorization", &format!("Bearer {}", a.token()))
        .send_json(serde_json::json!({ "enabled": true, "all": true, "home": true }))
        .unwrap();
    assert_eq!(answer.status().as_u16(), 400);
    let asked: serde_json::Value = answer.body_mut().read_json().unwrap();
    let refused = asked["error"]["message"].as_str().unwrap_or_default();
    assert!(refused.contains("only mapped folders sync"), "{asked}");
    let after = a.post("/api/v1/sync/status", serde_json::json!({}));
    assert_eq!(after["generation"], generation, "{after}");
    assert_eq!(after["home"], false, "{after}");
    // `--mapped-only` is taken, and says that it is the only scope.
    let out = a.cli(&["sync", "claude", "--mapped-only"]);
    assert!(out.starts_with("No settings changed.\n"), "{out}");
    assert!(
        out.contains("Only mapped folders sync: that is the only scope there is."),
        "{out}"
    );
    a.cli(&["sync", "home", "on"]);
    let s = state(&a);
    assert_eq!(s["sync"]["home"], true, "{s}");
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
    // An unmapped folder does not sync, and needs no exclusion to stay
    // out: nothing is written of it.
    assert_eq!(state(&a)["sync"]["exclude"], serde_json::json!([]));
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

/// The home directory maps under any name. So one machine's home memory and
/// another machine's folder can be one agent's memory: the agent starts in
/// `~` on one and in a project folder on the other. "Stop syncing home
/// memory" stops it whatever it is called, and turning it on again puts it
/// back under the name it had.
#[test]
fn home_memory_syncs_under_any_name() {
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

    // A's agent starts in its home directory, B's in a folder. Beside
    // them, a second folder on each, which syncs throughout: without it,
    // "nothing arrived" would also be true of a sync that had stopped.
    // (Made before sync is on: a cycle that saw a folder before its
    // transcript was written would not look at it again for minutes.)
    let a_mem = claude_folder(&a.home(), &a.home());
    let b_dir = b.home().join("seeddrill");
    std::fs::create_dir_all(&b_dir).unwrap();
    let b_mem = claude_folder(&b.home(), &b_dir);
    let a_other = a.home().join("notes");
    let b_other = b.home().join("notes");
    std::fs::create_dir_all(&a_other).unwrap();
    std::fs::create_dir_all(&b_other).unwrap();
    let a_other_mem = claude_folder(&a.home(), &a_other);
    let b_other_mem = claude_folder(&b.home(), &b_other);

    pair(&a, &b, "b", &all);
    for n in [&a, &b] {
        sync_on(n);
    }
    // The node says what version it is, beside the command's own.
    let s = state(&a);
    assert_eq!(s["node_version"], s["version"], "{s}");

    let out = a.cli(&["sync", "map", &path(&a.home()), "team", "--home"]);
    assert!(out.contains("Mapped ~ to team."), "{out}");
    // Declared again under the name it has, with or without the flag:
    // nothing to change, and nothing refused.
    let home_path = path(&a.home());
    for again in [&["team", "--home"][..], &["team"], &["Team"], &[]] {
        let args = [&["sync", "map", home_path.as_str()], again].concat();
        let out = a.cli(&args);
        assert!(
            out.contains("is already mapped to team. Nothing changed."),
            "{again:?}: {out}"
        );
    }
    // Under another name, with the flag, it is told to unmap first, and
    // nothing is offered that the node would refuse.
    let said = a.refused(&["sync", "map", home_path.as_str(), "other", "--home"]);
    assert!(
        said.contains(
            "~ is already mapped to team. To sync it under another name, unmap it \
             first: cordelia sync unmap ~"
        ),
        "{said}"
    );
    assert!(!said.contains("other --home"), "{said}");
    // Without the flag the command as typed would be refused again once
    // home was unmapped. So it is told that this is the home directory,
    // and both steps, in order.
    let said = a.refused(&["sync", "map", home_path.as_str(), "other"]);
    assert!(
        said.contains("that is your home directory, and it is already mapped to team."),
        "{said}"
    );
    let (unmap, map) = (
        said.find("cordelia sync unmap ~\n").expect(&said),
        said.find("cordelia sync map ~ other --home").expect(&said),
    );
    assert!(unmap < map, "{said}");
    b.cli(&["sync", "map", &path(&b_dir), "team"]);
    a.cli(&["sync", "map", &path(&a_other), "lab"]);
    b.cli(&["sync", "map", &path(&b_other), "lab"]);
    // Unmapping is advised only when it would help. A request that would
    // be refused once the folder was unmapped is refused for its own
    // reason, and no unmap is offered: for home, and for a folder.
    let notes = path(&a_other);
    let refusals: [(&[&str], &str); 9] = [
        // The home directory's path as a name is `~`, for any folder.
        (&[&notes, &home_path], "is the name of home memory"),
        (&[&home_path, "my team", "--home"], "is not a usable name"),
        (&[&home_path, "my team"], "is not a name it can sync under"),
        (&[&home_path, "lab", "--home"], "is already mapped from"),
        (&[&home_path, "lab"], "it cannot sync under that name"),
        (&[&notes, "Lab Notes"], "is not a usable name"),
        (&[&notes, "~"], "is the name of home memory"),
        (
            &[&notes, "other", "--home"],
            "--home is for the home directory itself",
        ),
        (&[&notes, "team"], "is already mapped from"),
    ];
    for (asked, why) in refusals {
        let args = [&["sync", "map"], asked].concat();
        let said = a.refused(&args);
        assert!(said.contains(why), "{asked:?}: {said}");
        assert!(!said.contains("unmap"), "{asked:?}: {said}");
    }
    // The flag given for another folder: what is said about home memory
    // is said in full.
    let said = a.refused(&["sync", "map", &notes, "other", "--home"]);
    assert!(
        said.contains(
            "--home is for the home directory itself. To sync home memory: \
             cordelia sync home on"
        ),
        "{said}"
    );
    let s = state(&a);
    assert_eq!(mapped_names(&s), ["lab", "team"], "{s}");
    assert_eq!(s["sync"]["home"], true, "{s}");
    assert_eq!(s["sync"]["home_name"], "team", "{s}");

    // Memory written on each arrives on the other.
    std::fs::write(a_mem.join("from_a.md"), "Written in A's home.\n").unwrap();
    wait_for("b's folder gets a's home memory", &all, 120, || {
        (read(&b_mem.join("from_a.md"))?.as_str() == "Written in A's home.\n").then_some(())
    });
    std::fs::write(b_mem.join("from_b.md"), "Written in B's folder.\n").unwrap();
    wait_for("a's home gets b's folder's memory", &all, 120, || {
        (read(&a_mem.join("from_b.md"))?.as_str() == "Written in B's folder.\n").then_some(())
    });

    // Home has one name on a device. Mapping it again with no name changes
    // nothing; another name is refused.
    let out = a.cli(&["sync", "map", &path(&a.home())]);
    assert!(
        out.contains("~ is already mapped to team. Nothing changed."),
        "{out}"
    );
    let said = a.refused(&["sync", "map", &path(&a.home()), "other", "--home"]);
    assert!(said.contains("~ is already mapped to team."), "{said}");
    assert_eq!(mapped_names(&state(&a)), ["lab", "team"]);

    // One word that is a name and also a folder is not unmapped: `lab` is
    // what `~/notes` syncs under, and in the home directory it is also a
    // folder, mapped as something else.
    let a_lab = a.home().join("lab");
    std::fs::create_dir_all(&a_lab).unwrap();
    a.cli(&["sync", "map", &path(&a_lab), "elsewhere"]);
    let out = a.command_in(&a.home(), &["sync", "unmap", "lab"]);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{said}");
    assert!(
        said.contains("cordelia sync unmap ~/lab") && said.contains("cordelia sync unmap ~/notes"),
        "{said}"
    );
    assert_eq!(mapped_names(&state(&a)), ["elsewhere", "lab", "team"]);
    // With a `/` at its end, as a shell completes it, the word is the
    // folder and not the name: the folder is unmapped, and what syncs as
    // `lab` is left alone.
    let out = a.command_in(&a.home(), &["sync", "unmap", "lab/"]);
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{said}");
    assert!(
        said.contains("No longer synced from this device: ~/lab (elsewhere)."),
        "{said}"
    );
    assert_eq!(mapped_names(&state(&a)), ["lab", "team"]);
    // And where the folder is not a mapped one, the word names nothing:
    // it says so, with the command for the name.
    let out = a.command_in(&a.home(), &["sync", "unmap", "lab/"]);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{said}");
    assert!(
        said.contains("is taken for a folder") && said.contains("cordelia sync unmap lab"),
        "{said}"
    );
    assert_eq!(mapped_names(&state(&a)), ["lab", "team"]);

    // B syncs its own home as `~`. A is not offered it: its home has a
    // name already, and mapping it as `~` would take it out of `team`.
    b.cli(&["sync", "map", &path(&b.home()), "--home"]);
    let offered = wait_for("a sees that b syncs home memory", &all, 120, || {
        let out = a.cli(&["sync", "status"]);
        out.contains("home memory on this device syncs as team")
            .then_some(out)
    });
    assert!(!offered.contains("cordelia sync map ~ --home"), "{offered}");

    // Turning home memory off stops it, under whatever name it synced, and
    // leaves the other folder syncing.
    let out = a.cli(&["sync", "home", "off"]);
    assert!(out.contains("is not synced on this device"), "{out}");
    let s = state(&a);
    assert_eq!(mapped_names(&s), ["lab"], "{s}");
    assert_eq!(s["sync"]["home"], false, "{s}");
    assert_eq!(s["sync"]["home_name"], "team", "{s}");
    std::fs::write(
        a_mem.join("later.md"),
        "Written after home was turned off.\n",
    )
    .unwrap();
    std::fs::write(
        a_other_mem.join("control.md"),
        "Written at the same time.\n",
    )
    .unwrap();
    wait_for("the other folder still syncs", &all, 120, || {
        read(&b_other_mem.join("control.md")).map(|_| ())
    });
    std::thread::sleep(Duration::from_secs(2 * cordelia_sync::claude::CYCLE_SECS));
    assert_eq!(read(&b_mem.join("later.md")), None);
    // What was found is offered under the name it had, not as `~`, and
    // B's `~` is still not offered.
    let status = a.cli(&["sync", "status"]);
    assert!(
        status
            .lines()
            .any(|l| l.contains("last synced as team") && l.contains("cordelia sync home on")),
        "{status}"
    );
    assert!(!status.contains("cordelia sync map ~ --home"), "{status}");
    assert!(!status.contains("(your other devices sync it)"), "{status}");

    // The name home memory last had can be another folder's by now. A
    // refusal of `map` then does not offer `home on`, which the node
    // would refuse: it says why, and how to map home under a name.
    a.cli(&["sync", "map", &path(&a_lab), "team"]);
    let said = a.refused(&["sync", "map", &path(&a.home())]);
    assert!(
        said.contains("Home memory cannot be put back as team")
            && said.contains("cordelia sync map ~ <name> --home"),
        "{said}"
    );
    assert!(!said.contains("home on"), "{said}");
    a.cli(&["sync", "unmap", &path(&a_lab)]);
    let said = a.refused(&["sync", "map", &path(&a.home())]);
    assert!(said.contains("cordelia sync home on"), "{said}");

    // On again: under the name it had, so into the channel it was in.
    let out = a.cli(&["sync", "home", "on"]);
    assert!(
        out.contains("Home-folder memory syncs on this device, as team."),
        "{out}"
    );
    let s = state(&a);
    assert_eq!(mapped_names(&s), ["lab", "team"], "{s}");
    assert_eq!(s["sync"]["home"], true, "{s}");
    wait_for("b gets what a wrote while home was off", &all, 120, || {
        read(&b_mem.join("later.md")).map(|_| ())
    });

    // `unmap` remembers the name as `home off` does: mapped under another
    // name and unmapped, home comes back under that one. Turning on what
    // is on changes nothing.
    a.cli(&["sync", "unmap", "team"]);
    a.cli(&["sync", "map", &path(&a.home()), "crew", "--home"]);
    a.cli(&["sync", "unmap", "crew"]);
    assert_eq!(state(&a)["sync"]["home_name"], "crew");
    a.cli(&["sync", "home", "on"]);
    let out = a.cli(&["sync", "home", "on"]);
    assert!(out.contains("as crew."), "{out}");
    assert_eq!(mapped_names(&state(&a)), ["crew", "lab"]);

    // Home is unmapped by its folder, as the two steps that `map` gives
    // for a home mapped under another name spell it, and mapped again
    // under the name it had before.
    let out = a.cli(&["sync", "unmap", "~"]);
    assert!(
        out.contains("No longer synced from this device: ~ (crew)."),
        "{out}"
    );
    a.cli(&["sync", "map", &path(&a.home()), "team", "--home"]);

    // A home directory that is itself a git repository: Claude Code keeps
    // the memory of every folder in it with home's. Naming one of those
    // folders must not sync home memory; naming home does.
    a.cli(&["sync", "unmap", "team"]);
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(a.home())
            .args(["init", "-q"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let inside = a.home().join("scratch");
    std::fs::create_dir_all(&inside).unwrap();
    let inside = path(&inside);
    let said = a.refused(&["sync", "map", &inside, "scratch"]);
    assert!(
        said.contains("your home directory is a git repository")
            && said.contains("cordelia sync home on"),
        "{said}"
    );
    let said = a.refused(&["sync", "map", &inside, "scratch", "--home"]);
    assert!(said.contains("--home is for the home directory"), "{said}");
    assert_eq!(mapped_names(&state(&a)), ["lab"]);
    let out = a.cli(&["sync", "map", &path(&a.home()), "team", "--home"]);
    assert!(out.contains("Mapped ~ to team."), "{out}");

    // The home directory is now the repository that `~/notes` is in, and
    // both are mapped. Unmapping the folder, by a path that is not the
    // one stored, unmaps the folder and not the repository above it.
    let out = a.command_in(&a.home(), &["sync", "unmap", "notes"]);
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{said}");
    assert!(
        said.contains("No longer synced from this device: ~/notes (lab)."),
        "{said}"
    );
    assert_eq!(mapped_names(&state(&a)), ["team"]);
}

/// One edit on one machine against two on the other, made while the two
/// cannot reach each other. The second of the two is at a higher revision
/// than the one, and its chain does not hold the one: it descends from
/// the first of the two, and from the text that both machines had
/// (decision 2026-10-04 §7.3). Both machines end with the later text in
/// the file, and with the one edit in a conflict file beside it.
#[test]
fn an_edit_overtaken_while_apart_is_kept_on_both_machines() {
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
    let a_mem = claude_folder(&a.home(), &a.home());
    let b_mem = claude_folder(&b.home(), &b.home());

    pair(&a, &b, "b", &[&relay, &a, &b]);
    for n in [&a, &b] {
        sync_on(n);
        n.cli(&["sync", "map", &path(&n.home()), "--home"]);
    }
    std::fs::write(a_mem.join("notes.md"), "base\n").unwrap();
    wait_for("b has the file", &[&relay, &a, &b], 120, || {
        (read(&b_mem.join("notes.md")).as_deref() == Some("base\n")).then_some(())
    });

    // The machines are apart: the relay, which is how they meet, is down.
    relay.stop();
    // When home memory was last published from a machine: `Some(None)` if
    // it never was, and `None` if this reading says nothing (a status
    // that could not ask the node has no folders in it). Each edit is
    // waited for, so that two edits are two revisions; and a reading that
    // says nothing is not taken for a change, or the wait would end before
    // the edit was published and two edits could be one revision.
    let published = |n: &Node| -> Option<Option<String>> {
        let state: serde_json::Value = serde_json::from_str(&n.cli(&["status", "--json"])).ok()?;
        let projects = state["sync"]["projects"].as_array()?.clone();
        let home = projects.into_iter().find(|p| p["project"] == "~")?;
        Some(home["last_published_at"].as_str().map(String::from))
    };
    let edit = |n: &Node, mem: &std::path::Path, text: &str| {
        let before = wait_for("when it last published", &[&a, &b], 60, || published(n));
        std::fs::write(mem.join("notes.md"), text).unwrap();
        wait_for("the edit is published", &[&a, &b], 60, || {
            published(n)
                .filter(|now| now.is_some() && *now != before)
                .map(|_| ())
        });
    };
    edit(&b, &b_mem, "from b\n");
    edit(&a, &a_mem, "from a, one\n");
    edit(&a, &a_mem, "from a, two\n");

    // They meet again.
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let copies = |mem: &std::path::Path| -> Vec<String> {
        let mut texts: Vec<String> = std::fs::read_dir(mem)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("notes.conflict-"))
            .filter_map(|name| read(&mem.join(name)))
            .collect();
        texts.sort();
        texts
    };
    wait_for(
        "both have the later text, and the edit it overtook beside it",
        &[&relay, &a, &b],
        180,
        || {
            [&a_mem, &b_mem]
                .iter()
                .all(|mem| {
                    read(&mem.join("notes.md")).as_deref() == Some("from a, two\n")
                        && copies(mem) == ["from b\n"]
                })
                .then_some(())
        },
    );
}

/// What sync replaces or removes on a machine can be put back from that
/// machine (decision 2026-09-30 §4.5b). One machine edits a memory and then
/// deletes it. Each keeps the text that each change replaced there. A
/// restore of the text the edit replaced goes to the other machine as an
/// ordinary edit, and so does its undo; a restore on the machine that did
/// not make the delete brings the memory back on both. Then one machine
/// empties the folder: the other lists what was removed, and restoring
/// those brings every file back on both, with the index that points at
/// them. Records dropped on one machine are gone from it and from no other.
#[test]
fn what_sync_replaced_or_removed_is_put_back_from_either_machine() {
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
    let a_mem = claude_folder(&a.home(), &a.home());
    let b_mem = claude_folder(&b.home(), &b.home());

    pair(&a, &b, "b", &[&relay, &a, &b]);
    for n in [&a, &b] {
        sync_on(n);
        n.cli(&["sync", "map", &path(&n.home()), "--home"]);
    }
    // Both machines hold `name` with `text`, or neither holds it.
    let both = |what: &str, name: &str, text: Option<&str>| {
        wait_for(what, &[&relay, &a, &b], 180, || {
            [&a_mem, &b_mem]
                .iter()
                .all(|mem| read(&mem.join(name)).as_deref() == text)
                .then_some(())
        });
    };
    // What a machine has kept for home memory: the file, the change and the
    // text of each record, sorted.
    let kept = |n: &Node| -> Vec<(String, String, Option<String>)> {
        let listed = n.post("/api/v1/history/list", serde_json::json!({ "of": "~" }));
        let mut records: Vec<(String, String, Option<String>)> = listed["records"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|record| {
                let shown = n.post(
                    "/api/v1/history/show",
                    serde_json::json!({ "id": record["id"] }),
                );
                (
                    record["file"].as_str().unwrap().to_string(),
                    record["change"].as_str().unwrap().to_string(),
                    shown["text"].as_str().map(String::from),
                )
            })
            .collect();
        records.sort();
        records
    };
    let record = |file: &str, change: &str, text: Option<&str>| {
        (file.to_string(), change.to_string(), text.map(String::from))
    };
    // The id of the record a machine has of `change`, keeping `text`.
    let id_of = |n: &Node, change: &str, text: &str| -> Option<String> {
        let listed = n.post("/api/v1/history/list", serde_json::json!({ "of": "~" }));
        listed["records"].as_array()?.iter().find_map(|record| {
            let id = record["id"].as_str()?;
            let shown = n.post("/api/v1/history/show", serde_json::json!({ "id": id }));
            (record["change"] == change && shown["text"] == text).then(|| id.to_string())
        })
    };
    // The ids that `--removed` offers to put back, as a person would copy
    // them from its last line.
    let removed = |n: &Node| -> Vec<String> {
        let listed = n.cli(&["history", "~", "--removed"]);
        listed
            .lines()
            .find_map(|line| line.strip_prefix("To put them all back: cordelia restore "))
            .map(|ids| ids.split_whitespace().map(String::from).collect())
            .unwrap_or_default()
    };

    // One machine writes a memory and then edits it.
    std::fs::write(a_mem.join("notes.md"), "one\n").unwrap();
    both("both have the memory", "notes.md", Some("one\n"));
    std::fs::write(a_mem.join("notes.md"), "two\n").unwrap();
    both("both have the edit", "notes.md", Some("two\n"));
    // Each has the text that the edit replaced: where it was made, as the
    // channel's version, and on the other, as the file it replaced there.
    // (A record is made final a moment after the file is replaced.)
    wait_for(
        "each has kept what the edit replaced",
        &[&relay, &a, &b],
        60,
        || {
            let on_a = [record("notes.md", "edited_here", Some("one\n"))];
            let on_b = [
                record("notes.md", "arrived", None),
                record("notes.md", "pulled", Some("one\n")),
            ];
            (kept(&a) == on_a && kept(&b) == on_b).then_some(())
        },
    );

    // The other machine puts back the text that the edit replaced there.
    // Its folder syncs, and the command says so: the restored file goes to
    // the first machine as an ordinary edit.
    let before = id_of(&b, "pulled", "one\n").expect("the record of what was pulled over");
    let said = b.cli(&["restore", &before]);
    assert!(said.contains("It goes to your other devices"), "{said}");
    both("the restored text is on both", "notes.md", Some("one\n"));
    // And undoes it, by the id the restore gave: the record of what the
    // restore replaced.
    let undo = said
        .lines()
        .find_map(|line| line.trim().strip_prefix("To undo: cordelia restore "))
        .expect("the restore says how to undo it")
        .to_string();
    assert_eq!(id_of(&b, "restored", "two\n"), Some(undo.clone()));
    b.cli(&["restore", &undo]);
    both("the edit is back on both", "notes.md", Some("two\n"));

    // It deletes the memory, and the other machine's file goes.
    std::fs::remove_file(a_mem.join("notes.md")).unwrap();
    both("the memory is gone from both", "notes.md", None);
    wait_for(
        "each has kept what the delete removed",
        &[&relay, &a, &b],
        60,
        || {
            (kept(&a).contains(&record("notes.md", "deleted_here", Some("two\n")))
                && kept(&b).contains(&record("notes.md", "removed", Some("two\n"))))
            .then_some(())
        },
    );
    // A restore on the machine that did not make the delete brings it back
    // on both.
    let ids = removed(&b);
    assert_eq!(ids.len(), 1, "{ids:?}");
    b.cli(&["restore", &ids[0]]);
    both("the memory is back on both", "notes.md", Some("two\n"));

    // An index that points at the memory, and then the folder is emptied
    // on one machine.
    let index = "- [Notes](notes.md) what was noted\n";
    std::fs::write(a_mem.join("MEMORY.md"), index).unwrap();
    both("both have the index", "MEMORY.md", Some(index));
    for name in ["notes.md", "MEMORY.md"] {
        std::fs::remove_file(a_mem.join(name)).unwrap();
    }
    both("the memory is gone from both", "notes.md", None);
    both("the index is gone from both", "MEMORY.md", None);
    // The other machine lists what was removed, and puts it all back.
    let ids = wait_for("both removals are listed", &[&relay, &a, &b], 60, || {
        Some(removed(&b)).filter(|ids| ids.len() == 2)
    });
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    b.cli(&[&["restore"], ids.as_slice()].concat());
    both("the memory is back on both", "notes.md", Some("two\n"));
    both("the index is back on both", "MEMORY.md", Some(index));

    // Records dropped on one machine are gone from it, and stay on the
    // other. Those of another file stay too.
    let of = |n: &Node, file: &str| kept(n).iter().filter(|r| r.0 == file).count();
    // (A record is made final a moment after its file is written, so a
    // machine may come to list one more than it did: none fewer.)
    let (notes_on_a, index_on_b) = (of(&a, "notes.md"), of(&b, "MEMORY.md"));
    assert!(of(&b, "notes.md") > 0 && notes_on_a > 0 && index_on_b > 0);
    let said = b.cli(&["history", "drop", "~", "notes.md"]);
    assert!(said.contains("records from this device"), "{said}");
    assert_eq!(of(&b, "notes.md"), 0);
    assert!(of(&b, "MEMORY.md") >= index_on_b);
    assert!(of(&a, "notes.md") >= notes_on_a);
    assert_eq!(read(&b_mem.join("notes.md")).as_deref(), Some("two\n"));
}

/// Local history is set up as the configuration says: how long a record
/// is kept, how much is kept, and whether anything is. A node told to
/// keep nothing removes what it had kept.
#[test]
fn local_history_is_kept_as_the_configuration_says() {
    let mut n = node("alone", "personal", None);
    let path = n.config();
    let config = std::fs::read_to_string(&path).unwrap();
    let with = |history: &str| std::fs::write(&path, format!("{config}\n{history}")).unwrap();
    with("[history]\ndays = 7\nmax_bytes = 123456\n");
    n.start();
    wait_for("node healthy", &[&n], 30, || healthy(&n));
    let listed = n.post("/api/v1/history/list", serde_json::json!({}));
    assert_eq!(listed["on"], true, "{listed}");
    assert_eq!(
        (&listed["days"], &listed["max_bytes"]),
        (&serde_json::json!(7), &serde_json::json!(123456))
    );
    let kept = n.data_dir().join("history");
    assert!(kept.is_dir());
    // A drop that leaves something behind says so, and fails. (A
    // directory under a record's name cannot be removed as a file.)
    let stuck = kept.join("00000000000abc");
    std::fs::create_dir(&stuck).unwrap();
    let said = n.refused(&["history", "drop", "--all"]);
    assert!(said.contains("1 records could not be removed"), "{said}");
    assert!(stuck.is_dir());
    std::fs::remove_dir(&stuck).unwrap();
    assert!(
        n.cli(&["history", "drop", "--all"])
            .contains("Dropped all history")
    );
    n.stop();

    with("[history]\ndays = 0\n");
    n.start();
    wait_for("node healthy", &[&n], 30, || healthy(&n));
    let listed = n.post("/api/v1/history/list", serde_json::json!({}));
    assert_eq!(listed["on"], false, "{listed}");
    assert!(!kept.exists());
    assert!(n.cli(&["history"]).contains("turned off"));
}

/// One machine deletes a memory and its line in the index while the other,
/// apart, edits the memory. An edit beats a delete, so the file comes back
/// on both. A minute of looks later the machine that deleted it puts its
/// line back, and both end with the file and its line (decision 2026-09-30
/// §4.5). With `restart`, the node that deleted is stopped and started
/// between the delete and the reunion: what it wrote down is in its
/// database, and the minute starts when it is up.
///
/// It waits the real minute: nothing sets a node's clock from outside.
fn a_memory_deleted_with_its_line_comes_back_listed(restart: bool) {
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
    let a_mem = claude_folder(&a.home(), &a.home());
    let b_mem = claude_folder(&b.home(), &b.home());

    pair(&a, &b, "b", &[&relay, &a, &b]);
    for n in [&a, &b] {
        sync_on(n);
        n.cli(&["sync", "map", &path(&n.home()), "--home"]);
    }
    let line = "- [Notes](notes.md) what was noted\n";
    let other = "- [Other](other.md) the other one\n";
    std::fs::write(a_mem.join("notes.md"), "base\n").unwrap();
    std::fs::write(a_mem.join("other.md"), "x\n").unwrap();
    std::fs::write(a_mem.join("MEMORY.md"), format!("{line}{other}")).unwrap();
    wait_for(
        "b has the memory and the index",
        &[&relay, &a, &b],
        120,
        || {
            let index = read(&b_mem.join("MEMORY.md"));
            let listed = index.is_some_and(|index| index.contains(line.trim_end()));
            (listed && read(&b_mem.join("notes.md")).is_some()).then_some(())
        },
    );

    // The machines are apart: the relay, which is how they meet, is down.
    relay.stop();
    let published = |n: &Node| -> Option<Option<String>> {
        let state: serde_json::Value = serde_json::from_str(&n.cli(&["status", "--json"])).ok()?;
        let projects = state["sync"]["projects"].as_array()?.clone();
        let home = projects.into_iter().find(|p| p["project"] == "~")?;
        Some(home["last_published_at"].as_str().map(String::from))
    };
    let publishes = |n: &Node, change: &dyn Fn()| {
        let before = wait_for("when it last published", &[&a, &b], 60, || published(n));
        change();
        wait_for("the change is published", &[&a, &b], 60, || {
            published(n)
                .filter(|now| now.is_some() && *now != before)
                .map(|_| ())
        });
    };
    // One machine deletes the memory, and then its line: two publishes,
    // well inside the hour.
    publishes(&a, &|| {
        std::fs::remove_file(a_mem.join("notes.md")).unwrap()
    });
    publishes(&a, &|| {
        std::fs::write(a_mem.join("MEMORY.md"), other).unwrap()
    });
    // The other, which has heard of neither, edits the memory.
    publishes(&b, &|| {
        std::fs::write(b_mem.join("notes.md"), "from b\n").unwrap()
    });

    if restart {
        a.stop();
        a.start();
        wait_for("a is up again", &[&a], 30, || healthy(&a));
    }

    // They meet again.
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let listed_once = |mem: &std::path::Path| {
        let index = read(&mem.join("MEMORY.md")).unwrap_or_default();
        index.lines().filter(|l| *l == line.trim_end()).count() == 1
            && index.contains(other.trim_end())
    };
    wait_for(
        "both have the memory, and its line once",
        &[&relay, &a, &b],
        300,
        || {
            [&a_mem, &b_mem]
                .iter()
                .all(|mem| {
                    read(&mem.join("notes.md")).as_deref() == Some("from b\n") && listed_once(mem)
                })
                .then_some(())
        },
    );
    // The line went back at the end of the index, on the machine that
    // had removed it.
    assert_eq!(
        read(&a_mem.join("MEMORY.md")).as_deref(),
        Some(format!("{other}{line}").as_str())
    );
}

#[test]
fn the_line_of_a_memory_that_comes_back_is_put_back_on_both_machines() {
    a_memory_deleted_with_its_line_comes_back_listed(false);
}

#[test]
fn the_line_of_a_memory_that_comes_back_is_put_back_after_a_restart() {
    a_memory_deleted_with_its_line_comes_back_listed(true);
}

/// The files under a node's directory that contain `needle`, as raw
/// bytes: its database and the write-ahead log beside it, where SQLite
/// keeps text and bytes as they were written, and its log.
fn files_holding(n: &Node, needle: impl AsRef<[u8]>) -> Vec<PathBuf> {
    let needle = needle.as_ref();
    let mut found = Vec::new();
    let mut dirs = vec![n.dir.path().to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
            } else if let Ok(bytes) = std::fs::read(&path)
                && bytes.windows(needle.len()).any(|w| w == needle)
            {
                found.push(path);
            }
        }
    }
    found
}

/// A log without the colour codes a terminal would take.
fn without_colour(log: &str) -> String {
    let mut plain = String::with_capacity(log.len());
    let mut chars = log.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            plain.push(c);
        }
    }
    plain
}

/// A node's entity ID, from its configuration.
fn entity_id(n: &Node) -> String {
    cordelia_core::config::Config::load(&n.config())
        .unwrap()
        .identity
        .entity_id
}

/// How many swarm channels a node's database holds: a look at the
/// database itself. (`cordelia channels` says nothing of them on a
/// personal node, where it lists the names that the device holds.)
fn swarm_channels_held(n: &Node) -> i64 {
    let prefix = cordelia_storage::naming::SWARM_CHANNEL_PREFIX;
    let db = rusqlite::Connection::open(n.data_dir().join("cordelia.db")).unwrap();
    db.busy_timeout(Duration::from_secs(10)).unwrap();
    db.query_row(
        "SELECT COUNT(*) FROM channels WHERE substr(channel_id, 1, ?1) = ?2",
        rusqlite::params![prefix.len() as i64, prefix],
        |row| row.get(0),
    )
    .unwrap()
}

/// The key files a node keeps for swarm channels.
fn swarm_key_files(n: &Node) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(n.data_dir().join("channel-keys")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with(cordelia_storage::naming::SWARM_CHANNEL_PREFIX))
        .collect()
}

/// Put in a node's database the swarm channel that a personal node made
/// for itself each time it started, up to 0.2.0-alpha.7, as that version
/// made it: its row, the node as its owner, and its key file. Its ID
/// holds the node's entity ID. Returns the ID.
///
/// A database of this version refuses a new row of the older kind, from
/// its first start on (decision 2026-10-04 §10.1). Where the node has
/// started, the test takes that guard away first: it puts the row where
/// nothing of this version would.
fn swarm_channel_as_an_earlier_version_made_it(n: &Node) -> String {
    let id = cordelia_storage::naming::swarm_channel_id(&entity_id(n));
    let pk = cordelia_crypto::bech32::decode_public_key(&key_of(n)).unwrap();
    let psk = cordelia_crypto::generate_psk().unwrap();
    let now = "2026-10-01T00:00:00+00:00";
    let db = rusqlite::Connection::open(n.data_dir().join("cordelia.db")).unwrap();
    db.busy_timeout(Duration::from_secs(10)).unwrap();
    cordelia_storage::first_start::remove_guard(&db).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO channels (channel_id, channel_type, mode, access, scope, creator_id, psk_hash, created_at, updated_at)
         VALUES (?1, 'named', 'realtime', 'invite_only', 'network', ?2, ?3, ?4, ?5)",
        rusqlite::params![id, pk.as_slice(), cordelia_crypto::sha256(&psk).as_slice(), now, now],
    )
    .unwrap();
    db.execute(
        "INSERT OR IGNORE INTO channel_members (channel_id, entity_key, role, joined_at)
         VALUES (?1, ?2, 'owner', ?3)",
        rusqlite::params![id, pk.as_slice(), now],
    )
    .unwrap();
    cordelia_storage::psk::write_psk(&n.data_dir(), &id, &psk).unwrap();
    id
}

/// Put in a node's database an entry of the channel `channel` of the
/// older kind, as the node of an earlier version wrote one there: signed
/// with the node's own key, and sent to no relay yet. Returns its ID.
fn entry_as_an_earlier_version_wrote_it(n: &Node, channel: &str) -> String {
    let own =
        cordelia_crypto::identity::NodeIdentity::from_file(&n.data_dir().join("identity.key"))
            .unwrap();
    let entry = entry_in(&own, channel, vec![9; 40]);
    let db = rusqlite::Connection::open(n.data_dir().join("cordelia.db")).unwrap();
    db.busy_timeout(Duration::from_secs(10)).unwrap();
    let stored = cordelia_storage::items::insert_item(
        &db,
        &cordelia_storage::items::NewItem {
            item_id: &entry.item_id,
            channel_id: channel,
            author_id: &own.public_key(),
            item_type: &entry.item_type,
            published_at: &entry.published_at,
            parent_id: None,
            key_version: 1,
            content_hash: &entry.content_hash,
            signature: &entry.signature,
            encrypted_blob: &entry.encrypted_blob,
            is_tombstone: false,
            slot: None,
            rev: None,
        },
    )
    .unwrap();
    assert!(stored, "the entry was not stored");
    entry.item_id
}

/// A relay names a channel in its log only for debugging. Its log does
/// hold each of `channels`, which it was told of, and no line that holds
/// one is of a level above debug: what a relay logs as a matter of course
/// says how many channels, and not which.
fn assert_names_channels_only_for_debugging(relay: &Node, channels: &[&str]) {
    let log = without_colour(&std::fs::read_to_string(relay.log()).unwrap());
    for channel in channels {
        let naming: Vec<&str> = log.lines().filter(|l| l.contains(channel)).collect();
        assert!(!naming.is_empty(), "the relay's log should hold {channel}");
        for line in naming {
            let level = line.split_whitespace().nth(1);
            assert!(
                matches!(level, Some("DEBUG" | "TRACE")),
                "the relay's log names a channel above debug: {line}"
            );
        }
    }
}

/// What a relay must never be told: a swarm channel's ID, which holds an
/// entity ID, and the entity ID of the node it serves. Nothing the relay
/// has written to disk holds either: not its log, and not its database,
/// where it keeps what it is sent. What it was told is there: `told`, the
/// ID of a channel of the node's own, is.
fn assert_told_no_id_that_holds_a_name(relay: &Node, of: &Node, told: &[u8; 32]) {
    assert!(
        !files_holding(relay, told).is_empty(),
        "the relay was told of a channel, so its ID should be on its disk"
    );
    let entity = entity_id(of);
    for needle in [cordelia_storage::naming::SWARM_CHANNEL_PREFIX, &entity] {
        let found = files_holding(relay, needle);
        assert!(
            found.is_empty(),
            "the relay was told {needle:?}: it is in {found:?}"
        );
    }
}

/// A node makes no channel that it does not use. Up to 0.2.0-alpha.7 a
/// personal node made a swarm channel for itself each time it started,
/// whose ID holds its entity ID, and told its relay of it. A node that
/// starts and reaches its relay now holds no such channel and no key for
/// one. What it tells its relay of is the channels of its own, from a
/// secret, once it follows a recovery phrase: its relay is told no channel
/// ID that begins as a swarm channel's does, and none that holds the
/// node's entity ID.
#[test]
fn a_node_makes_no_swarm_channel_and_tells_its_relay_of_none() {
    use cordelia_storage::naming::SWARM_CHANNEL_PREFIX;
    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let mut a = node("unnamed-canary", "personal", Some(relay.p2p));
    a.start();
    let all = [&relay, &a];
    wait_for("node healthy", &all, 30, || healthy(&a));
    wait_for("connected to the relay", &all, 60, || has_hot_peer(&a));

    let told = tells_its_relay_of_its_name(&a, &relay);
    assert_told_no_id_that_holds_a_name(&relay, &a, &told);

    // The node holds none, and so had none to remove.
    assert_eq!(swarm_channels_held(&a), 0);
    let channels = a.cli(&["channels"]);
    assert!(!channels.contains(SWARM_CHANNEL_PREFIX), "{channels}");
    assert_eq!(swarm_key_files(&a), Vec::<String>::new());
    let log = std::fs::read_to_string(a.log()).unwrap();
    assert!(!log.contains("removed swarm channels"), "{log}");
    // Nor had it anything of the older kind to copy and move on at its
    // first start (decision 2026-10-04 §10.1): it made no copy.
    assert_eq!(copies_made(&a), Vec::<String>::new());
    assert!(!log.contains("was copied and moved on"), "{log}");
}

/// The copies that a node made of its database, beside it, by their
/// names.
fn copies_made(n: &Node) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(n.data_dir()) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with("before-"))
        .collect()
}

/// A node that ran a version up to 0.2.0-alpha.7 holds the swarm channel
/// that version made, with its key. When it starts, the channel and the
/// key go, and the node says once that they did, with how many and not
/// which. Its relay is told nothing of the channel.
///
/// On a personal node they go with everything of the older kind that it
/// holds, at its first start on this version (decision 2026-10-04 §10.1):
/// its database is copied and moved on, and the key files of the older
/// channels are removed. A node of a role that carries the older kind
/// removes a swarm channel by itself, and keeps the rest: a relay that
/// holds one shows it.
#[test]
fn a_swarm_channel_an_earlier_version_made_is_removed_when_the_node_starts() {
    use cordelia_storage::naming::SWARM_CHANNEL_PREFIX;
    // A relay that holds one removes it, and says so once, with how many
    // and not which. It makes no copy.
    let mut older = node("older-relay", "relay", None);
    let of_the_relay = swarm_channel_as_an_earlier_version_made_it(&older);
    older.start();
    wait_for("relay healthy", &[&older], 30, || healthy(&older));
    assert_eq!(swarm_key_files(&older), Vec::<String>::new());
    let log = without_colour(&std::fs::read_to_string(older.log()).unwrap());
    let said: Vec<&str> = log
        .lines()
        .filter(|line| line.contains("removed swarm channels"))
        .collect();
    assert_eq!(said.len(), 1, "{log}");
    for count in ["INFO", "channels=1", "items=0", "key_files=1"] {
        assert!(said[0].contains(count), "{}", said[0]);
    }
    assert!(!log.contains(&of_the_relay), "{log}");
    assert_eq!(copies_made(&older), Vec::<String>::new());
    older.stop();

    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let mut b = node("earlier-canary", "personal", Some(relay.p2p));

    // What the earlier version left: the node lists the channel, and
    // keeps a key for it.
    let swarm = swarm_channel_as_an_earlier_version_made_it(&b);
    assert!(swarm.ends_with(&entity_id(&b)), "{swarm}");
    assert_eq!(swarm_channels_held(&b), 1);
    assert_eq!(swarm_key_files(&b), vec![format!("{swarm}.key")]);

    b.start();
    let all = [&relay, &b];
    wait_for("node healthy", &all, 30, || healthy(&b));
    wait_for("connected to the relay", &all, 60, || has_hot_peer(&b));
    let told = tells_its_relay_of_its_name(&b, &relay);
    assert_told_no_id_that_holds_a_name(&relay, &b, &told);

    // The channel is gone from the node, and its key with it.
    assert_eq!(swarm_channels_held(&b), 0);
    assert_eq!(swarm_key_files(&b), Vec::<String>::new());
    // The node said so once, and nowhere in its log is the channel's ID:
    // its database was copied and moved on, and the key file removed.
    let log = without_colour(&std::fs::read_to_string(b.log()).unwrap());
    let said = |what: &str| -> Vec<String> {
        let lines = log.lines().filter(|line| line.contains(what));
        lines.map(str::to_string).collect()
    };
    let moved_on = said("the database was copied and moved on");
    assert_eq!(moved_on.len(), 1, "{log}");
    assert!(moved_on[0].contains("INFO"), "{}", moved_on[0]);
    let removed = said("removed the key files of the older channels");
    assert_eq!(removed.len(), 1, "{log}");
    for count in ["INFO", "key_files=1"] {
        assert!(removed[0].contains(count), "{}", removed[0]);
    }
    assert!(said("removed swarm channels").is_empty(), "{log}");
    assert!(!log.contains(SWARM_CHANNEL_PREFIX), "{log}");
    // The copy holds what the node held, the key file among it.
    let copies = copies_made(&b);
    assert_eq!(copies.len(), 1, "{copies:?}");
    let copied_key = b
        .data_dir()
        .join(&copies[0])
        .join("channel-keys")
        .join(format!("{swarm}.key"));
    assert!(copied_key.exists(), "{}", copied_key.display());
}

/// A channel ID that holds a name is never told to a peer, though the
/// node holds the channel. No command puts a swarm channel in a node that
/// is running, and a node removes one when it starts, so the test puts it
/// there: in the database of a running node, as an earlier version made
/// it, with an entry in it that the node wrote and that no relay was
/// sent. The node goes on writing under a name it holds, and its relay is
/// sent that: what a device tells a relay of is the channels of its own,
/// from a secret, and nothing of a channel of the older kind (decision
/// 2026-10-04 §10). Nothing that the relay has written to disk holds the
/// swarm channel's ID, the node's entity ID, or the entry.
///
/// A relay carries the older kind of channel as it did, and of the
/// channels of that kind that it is told of it says how many as a matter
/// of course, and which only for debugging. A stand-in for a node that
/// holds a group shows it: it tells the relay of the group in every way a
/// node of that kind tells a relay of a channel (an announcement, a
/// request for its entries, and an entry pushed to it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_swarm_channel_that_a_running_node_holds_is_told_to_no_relay() {
    use cordelia_network::channel_announce::{announcement, send_channel_joined};
    use cordelia_network::messages::Protocol;
    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let mut c = node("held-canary", "personal", Some(relay.p2p));
    c.start();
    let all = [&relay, &c];
    wait_for("node healthy", &all, 30, || healthy(&c));
    wait_for("connected to the relay", &all, 60, || has_hot_peer(&c));
    let told = tells_its_relay_of_its_name(&c, &relay);

    // Written before the entry under the name, so that it is first among
    // what the node holds and has not sent.
    let swarm = swarm_channel_as_an_earlier_version_made_it(&c);
    let held = entry_as_an_earlier_version_wrote_it(&c, &swarm);
    let before = entries_at(&relay);
    publishes(
        &c,
        "later.md",
        serde_json::json!({ "text": "a later entry" }),
    );
    wait_for("the relay holds the later entry", &all, 90, || {
        (entries_at(&relay) > before).then_some(())
    });
    // And a pass or two of the node's own go by, in which it sends what
    // it has to send.
    std::thread::sleep(Duration::from_secs(
        2 * cordelia_core::protocol::REALTIME_SYNC_INTERVAL_SECS,
    ));
    assert_told_no_id_that_holds_a_name(&relay, &c, &told);
    assert_eq!(files_holding(&relay, &held), Vec::<PathBuf>::new());

    // The node holds the channel and its entry all the while: the relay
    // was not told because such an ID is not told, not for want of one.
    assert_eq!(swarm_channels_held(&c), 1);
    assert!(!files_holding(&c, &held).is_empty());
    // And the entry that is not sent is not counted as waiting to be.
    wait_for("nothing is left waiting to be sent", &all, 60, || {
        (c.get("/api/v1/status")?["outbox_waiting"] == 0).then_some(())
    });

    // The relay, of the older kind: what stands in for a node that holds
    // a group tells the relay of it in each of the three ways.
    const GROUP: &str = "grp_550e8400-e29b-41d4-a716-446655440000";
    let older = Arc::new(cordelia_crypto::identity::NodeIdentity::generate().unwrap());
    let (_manager, conn) = client_of(&relay, older.clone()).await;
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    cordelia_network::codec::write_protocol_byte(&mut send, Protocol::ChannelAnnounce)
        .await
        .unwrap();
    send_channel_joined(&mut send, GROUP, &announcement(&older, GROUP))
        .await
        .unwrap();
    let _ = send.finish();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    cordelia_network::codec::write_protocol_byte(&mut send, Protocol::ItemSync)
        .await
        .unwrap();
    cordelia_network::item_sync::send_sync_page(&mut send, &mut recv, GROUP, 0, 100)
        .await
        .expect("the relay answers a request for a channel's entries");
    let _ = send.finish();
    let sent = entry_in(&older, GROUP, vec![8; 40]);
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let mut stream = tokio::io::join(&mut recv, &mut send);
    let ack = cordelia_network::item_sync::send_push(&mut stream, std::slice::from_ref(&sent))
        .await
        .expect("the relay answers the push");
    assert_eq!(ack.stored, 1, "{ack:?}");
    // Of the channels it was told of, the relay says how many as a matter
    // of course, and which only for debugging. (It notes the announcement
    // and the request a moment after it has answered each.)
    wait_for("the relay notes what it was told of", &all, 60, || {
        let log = without_colour(&std::fs::read_to_string(relay.log()).ok()?);
        let names = |told_by: &str| {
            log.lines()
                .any(|line| line.contains(told_by) && line.contains(GROUP))
        };
        let counts = log.lines().any(|line| {
            line.contains("peer announced channels")
                && line.split_whitespace().nth(1) == Some("INFO")
        });
        (counts && names("peer announced channel") && names("served sync request")).then_some(())
    });
    assert_names_channels_only_for_debugging(&relay, &[GROUP]);
    // The relay has still been told nothing that holds a name.
    assert_told_no_id_that_holds_a_name(&relay, &c, &told);
}

/// A key file that cannot be removed does not stop the node. A node that
/// ran an earlier version holds the swarm channel that version made; where
/// a slot key of it would be there is a directory, which cannot be removed
/// as a file is. The node starts, removes the channel and the key it can
/// remove, and warns once that one could not be removed: how many, and not
/// which.
///
/// So does a personal node, which removes the key files of the older
/// channels after its first start on this version (decision 2026-10-04
/// §10.1), and a node of a role that carries the older kind, which
/// removes those of a swarm channel.
#[test]
fn a_key_file_that_cannot_be_removed_does_not_stop_the_node() {
    use cordelia_storage::naming::SWARM_CHANNEL_PREFIX;
    for (role, of_which) in [
        ("personal", "of the older channels"),
        ("relay", "of a swarm channel"),
    ] {
        let mut a = node("stuck-canary", role, None);
        let swarm = swarm_channel_as_an_earlier_version_made_it(&a);
        let stuck = cordelia_storage::psk::slot_key_path(&a.data_dir(), &swarm);
        std::fs::create_dir(&stuck).unwrap();

        a.start();
        wait_for("node healthy", &[&a], 30, || healthy(&a));

        assert_eq!(swarm_channels_held(&a), 0, "{role}");
        assert_eq!(swarm_key_files(&a), vec![format!("{swarm}.slot")], "{role}");
        let log = without_colour(&std::fs::read_to_string(a.log()).unwrap());
        let warned: Vec<&str> = log
            .lines()
            .filter(|line| line.contains("could not remove every key file"))
            .collect();
        assert_eq!(warned.len(), 1, "{role}: {log}");
        for said in ["WARN", "key_files=1", of_which] {
            assert!(warned[0].contains(said), "{role}: {}", warned[0]);
        }
        assert!(!log.contains(SWARM_CHANNEL_PREFIX), "{role}: {log}");
    }
}

/// An entry of `channel` with this ciphertext, signed by `author`, as it
/// travels.
fn entry_in(
    author: &cordelia_crypto::identity::NodeIdentity,
    channel: &str,
    blob: Vec<u8>,
) -> cordelia_network::messages::Item {
    let item_id = cordelia_storage::items::generate_item_id();
    let hash = cordelia_crypto::sha256(&blob);
    let published_at = "2026-10-02T00:00:00Z";
    let cbor = cordelia_crypto::signing::build_item_metadata_envelope(
        &author.public_key(),
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
        author_id: author.public_key().to_vec(),
        signature: author.sign(&cbor).to_vec(),
        key_version: 1,
        published_at: published_at.into(),
        is_tombstone: false,
        parent_id: None,
        slot: None,
        rev: None,
    }
}

/// Connect to `relay` as any node may, under `key`. The connection lasts
/// as long as what is returned is kept.
async fn client_of(
    relay: &Node,
    key: Arc<cordelia_crypto::identity::NodeIdentity>,
) -> (
    cordelia_network::connection::ConnectionManager,
    quinn::Connection,
) {
    use cordelia_network::{connection, transport};
    let endpoint = transport::create_endpoint(&key, "127.0.0.1:0".parse().unwrap()).unwrap();
    let port = endpoint.local_addr().unwrap().port();
    let mut manager =
        connection::ConnectionManager::new(key, endpoint, vec![], vec!["personal".into()], port);
    let relay_id = manager
        .connect_to(format!("127.0.0.1:{}", relay.p2p).parse().unwrap())
        .await
        .expect("the client connects, as any node may");
    let conn = manager.get_connection(&relay_id).unwrap().clone();
    (manager, conn)
}

/// Hold `items` as a device of the older kind held its channels, and
/// answer the relay at the other end of `conn` when it asks: which
/// channels are held, what each lists, and the entries. For as long as
/// the connection lasts.
///
/// A relay carries the older kind of channel as it did, and a device of
/// this version holds none of it (decision 2026-10-04 §10): what a relay
/// does for that kind is shown with this, and with [`push_to`].
fn serves_the_older_kind(conn: &quinn::Connection, items: Vec<cordelia_network::messages::Item>) {
    use cordelia_network::codec;
    use cordelia_network::messages::{
        FetchResponse, ItemHeader, Protocol, SyncChannelListResponse, SyncResponse, WireMessage,
    };
    let conn = conn.clone();
    tokio::spawn(async move {
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            if !matches!(
                codec::read_protocol_byte(&mut recv).await,
                Ok(Protocol::ItemSync)
            ) {
                continue;
            }
            while let Ok(asked) = codec::read_frame(&mut recv).await {
                let answer = match asked {
                    WireMessage::SyncChannelListRequest(_) => {
                        let mut channel_ids: Vec<String> =
                            items.iter().map(|i| i.channel_id.clone()).collect();
                        channel_ids.sort();
                        channel_ids.dedup();
                        WireMessage::SyncChannelListResponse(SyncChannelListResponse {
                            channel_ids,
                        })
                    }
                    // An entry's place in its channel's list is its place
                    // among the entries held, from 1.
                    WireMessage::SyncRequest(req) => {
                        let after = req.after_seq.unwrap_or(0);
                        let of: Vec<(u64, &cordelia_network::messages::Item)> = items
                            .iter()
                            .filter(|i| i.channel_id == req.channel_id)
                            .zip(1u64..)
                            .map(|(i, seq)| (seq, i))
                            .collect();
                        let page: Vec<&(u64, &cordelia_network::messages::Item)> = of
                            .iter()
                            .filter(|(seq, _)| *seq > after)
                            .take(req.limit as usize)
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
                    WireMessage::FetchRequest(req) => WireMessage::FetchResponse(FetchResponse {
                        items: items
                            .iter()
                            .filter(|i| req.item_ids.contains(&i.item_id))
                            .cloned()
                            .collect(),
                    }),
                    _ => break,
                };
                if codec::write_frame(&mut send, &answer).await.is_err() {
                    break;
                }
            }
        }
    });
}

/// Push `items` to `relay` in one push, as a client under `author`'s key.
/// Returns the relay's answer.
async fn push_to(
    relay: &Node,
    author: Arc<cordelia_crypto::identity::NodeIdentity>,
    items: &[cordelia_network::messages::Item],
) -> cordelia_network::messages::PushAck {
    let (_manager, conn) = client_of(relay, author).await;
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let mut stream = tokio::io::join(&mut recv, &mut send);
    cordelia_network::item_sync::send_push(&mut stream, items)
        .await
        .expect("the relay answers the push")
}

/// A relay passes on to the relays it lists what it comes to hold, and
/// nothing of a channel whose ID may not be told to a peer. Two relays
/// that list each other; a client pushes to the first an entry of a swarm
/// channel and an entry of a group, in one push. The second relay is sent
/// the group's entry, and nothing of the other: nothing it has written to
/// disk holds that entry's ID, or how a swarm channel's ID begins. Nor did
/// the first relay store it: a relay stores nothing of such a channel, and
/// says so to whoever pushed it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_passes_on_nothing_of_a_swarm_channel() {
    use cordelia_network::messages::{REFUSED_INVALID, Refusal};
    use cordelia_storage::naming::{SWARM_CHANNEL_PREFIX, swarm_channel_id};
    let mut r1 = node("relay1", "relay", None);
    let key_of = |n: &Node| n.cli(&["id"]).trim().to_string();
    let mut r2 = node_with_relays(
        "relay2",
        "relay",
        &[(format!("localhost:{}", r1.p2p), Some(key_of(&r1)))],
    );
    r1.add_relay(&format!("localhost:{}", r2.p2p), Some(&key_of(&r2)));
    let (r1_key, r2_key) = (key_of(&r1), key_of(&r2));
    r1.start();
    wait_for("relay1 healthy", &[&r1], 30, || healthy(&r1));
    r2.start();
    let both = [&r1, &r2];
    wait_for("relay2 healthy", &both, 30, || healthy(&r2));
    wait_for("the relays mesh", &both, 60, || {
        (peer_keys(&r1).contains(&r2_key) && peer_keys(&r2).contains(&r1_key)).then_some(())
    });

    let client = Arc::new(cordelia_crypto::identity::NodeIdentity::generate().unwrap());
    let held = entry_in(&client, &swarm_channel_id("pushed-canary"), vec![7; 40]);
    let sent = entry_in(
        &client,
        "grp_550e8400-e29b-41d4-a716-446655440000",
        vec![8; 40],
    );
    let ack = push_to(&r1, client, &[held.clone(), sent.clone()]).await;

    // What the second relay was sent, read from the second relay.
    wait_for(
        "the second relay is sent the group's entry",
        &both,
        90,
        || (!files_holding(&r2, &sent.item_id).is_empty()).then_some(()),
    );
    assert_eq!(files_holding(&r2, &held.item_id), Vec::<PathBuf>::new());
    assert_eq!(
        files_holding(&r2, SWARM_CHANNEL_PREFIX),
        Vec::<PathBuf>::new()
    );

    // And the first stored the one entry, and refused the other.
    assert_eq!(ack.stored, 1, "{ack:?}");
    assert_eq!(
        ack.refused,
        vec![Refusal {
            item_id: held.item_id.clone(),
            why: REFUSED_INVALID.into(),
        }],
        "{ack:?}"
    );
    let stats: serde_json::Value = serde_json::from_str(&r1.cli(&["stats", "--json"])).unwrap();
    assert_eq!(stats["items_stored"], 1, "{stats}");
}

/// A stand-in for a relay that asks. It answers a device's handshake as a
/// relay does, and hands the test each connection a device makes to it, so
/// that the test can ask the device what a relay asks. Whatever the device
/// sends it is dropped unanswered.
fn relay_that_asks() -> (u16, std::sync::mpsc::Receiver<quinn::Connection>) {
    use cordelia_network::{connection, transport};
    let identity = Arc::new(cordelia_crypto::identity::NodeIdentity::generate().unwrap());
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
    let (made, connections) = std::sync::mpsc::channel();
    tokio::spawn(async move {
        let _manager = manager; // keeps the endpoint's context alive
        while let Some(incoming) = endpoint.accept().await {
            let (ctx, made) = (ctx.clone(), made.clone());
            tokio::spawn(async move {
                let Ok(outcome) = connection::inbound_accept(&ctx, incoming).await else {
                    return;
                };
                let _ = made.send(outcome.conn.clone());
                while let Ok(streams) = outcome.conn.accept_bi().await {
                    drop(streams);
                }
            });
        }
    });
    (port, connections)
}

/// Ask a device over `conn`, as its relay does in one fetch: which
/// channels it holds, and then for a page of each of `channels`. `None` if
/// the device did not answer.
async fn ask_as_its_relay(
    conn: &quinn::Connection,
    channels: &[&str],
) -> Option<(Vec<String>, Vec<cordelia_network::messages::SyncResponse>)> {
    use cordelia_network::messages::Protocol;
    use cordelia_network::{codec, item_sync};
    let (mut send, mut recv) = conn.open_bi().await.ok()?;
    codec::write_protocol_byte(&mut send, Protocol::ItemSync)
        .await
        .ok()?;
    let listed = item_sync::send_channel_list_request(&mut send, &mut recv)
        .await
        .ok()?
        .channel_ids;
    let mut pages = Vec::new();
    for channel in channels {
        pages.push(
            item_sync::send_sync_page(&mut send, &mut recv, channel, 0, 100)
                .await
                .ok()?,
        );
    }
    let _ = send.finish();
    Some((listed, pages))
}

/// A device answers its relay with nothing of a channel whose ID may not
/// be told to a peer, though it holds the channel and an entry in it (put
/// there as in the test of what a running node tells its relay). It
/// answers its relay with nothing of any channel of the older kind: a
/// device of this version carries none (decision 2026-10-04 §10). The
/// test is the relay. It asks the device which channels it holds, and for
/// the swarm channel's entries by its ID; it pushes the device an entry
/// of that channel; and it announces the channel to it. What it asks is
/// answered with nothing, as a device that holds no such channel would
/// answer (decision 2026-10-04 §10.1): no channel, and nothing in the one
/// asked for. The push and the announcement are refused at once, and for
/// that reason; nothing of what was pushed is stored. On the same
/// connection the device does answer its relay on a stream that it
/// serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_answers_its_relay_with_nothing_of_a_swarm_channel() {
    use cordelia_network::channel_announce::{announcement, send_channel_joined};
    use cordelia_network::messages::Protocol;
    use cordelia_storage::naming::SWARM_CHANNEL_PREFIX;
    let (port, connections) = relay_that_asks();
    let mut a = node("asked-canary", "personal", Some(port));
    a.start();
    wait_for("node healthy", &[&a], 30, || healthy(&a));
    wait_for("connected to the relay", &[&a], 60, || has_hot_peer(&a));

    let swarm = swarm_channel_as_an_earlier_version_made_it(&a);
    let held = entry_as_an_earlier_version_wrote_it(&a, &swarm);

    // The control: the device answers its relay on a stream that it does
    // serve.
    let mut conn = connections
        .recv_timeout(Duration::from_secs(30))
        .expect("the device connected to its relay");
    wait_for("the device answers its relay", &[&a], 60, || {
        // The latest connection, if the device has made another.
        while let Ok(newer) = connections.try_recv() {
            conn = newer;
        }
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let asked = async {
                    let (mut send, mut recv) = conn.open_bi().await.ok()?;
                    let mut stream = tokio::io::join(&mut recv, &mut send);
                    cordelia_network::peer_sharing::request_peers(&mut stream, 8)
                        .await
                        .ok()
                };
                tokio::time::timeout(Duration::from_secs(5), asked)
                    .await
                    .ok()
                    .flatten()
            })
        })
    });

    // Asked which channels it holds, and for the swarm channel's entries
    // by its ID: it answers at once that it holds none, and that the
    // channel holds nothing, though its database holds both.
    let at_once = Duration::from_secs(cordelia_core::protocol::STREAM_TIMEOUT_SECS / 2);
    let asked = tokio::time::timeout(at_once, ask_as_its_relay(&conn, &[swarm.as_str()])).await;
    let nothing = match &asked {
        Ok(Some((listed, pages))) => {
            listed.is_empty() && pages.len() == 1 && pages[0].items.is_empty() && !pages[0].has_more
        }
        _ => false,
    };
    assert!(nothing, "the device answered its relay: {asked:?}");
    // Pushed an entry of the channel: it is not taken.
    let stranger = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
    let pushed = entry_in(&stranger, &swarm, vec![7; 40]);
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let mut stream = tokio::io::join(&mut recv, &mut send);
    let push = cordelia_network::item_sync::send_push(&mut stream, std::slice::from_ref(&pushed));
    let ack = tokio::time::timeout(at_once, push).await;
    assert!(
        matches!(ack, Ok(Err(_))),
        "the device answered a push: {ack:?}"
    );
    // Told of the channel: the device stops the stream.
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    cordelia_network::codec::write_protocol_byte(&mut send, Protocol::ChannelAnnounce)
        .await
        .unwrap();
    let _ = send_channel_joined(&mut send, &swarm, &announcement(&stranger, &swarm)).await;
    let stopped = tokio::time::timeout(at_once, send.stopped()).await;
    assert!(
        matches!(stopped, Ok(Ok(Some(_)))),
        "the device heard an announcement out: {stopped:?}"
    );
    // The two were refused because a device carries no channel of that
    // kind, and the device says so, for debugging; and it says that it
    // answered the sync with nothing.
    let log = without_colour(&std::fs::read_to_string(a.log()).unwrap());
    for stream in ["item_push", "channel_announce"] {
        let refused = log.lines().any(|line| {
            line.contains("refused: a personal node carries no channel of the older kind")
                && line.contains(&format!("protocol=\"{stream}\""))
        });
        assert!(refused, "{stream}: {log}");
    }
    assert!(
        log.contains("answered a sync of the older kind with nothing"),
        "{log}"
    );

    // Nothing of what was pushed is stored, and the device's database
    // holds the channel and its own entry all the while. (`cordelia
    // channels` says nothing of them: on a personal node it lists the
    // names that the device holds.)
    assert_eq!(files_holding(&a, &pushed.item_id), Vec::<PathBuf>::new());
    assert_eq!(swarm_channels_held(&a), 1);
    let channels = a.cli(&["channels"]);
    assert!(!channels.contains(SWARM_CHANNEL_PREFIX), "{channels}");
    assert!(!files_holding(&a, &held).is_empty());
}

/// A relay warns of an announcement that is not valid, and what it names
/// in the warning is text that the peer chose. A client announces a
/// channel under a name of thousands of characters that has a line break
/// in it and what looks like a line of a log after that, with a signature
/// that is not its own. The relay's warning has the first 64 characters
/// of the name, with the line break shown as an escape: it is one line, of
/// ordinary length, and nothing in the relay's log is the line that the
/// peer wrote.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_warns_of_what_a_peer_announced_in_a_few_safe_characters() {
    use cordelia_network::channel_announce::{announcement, send_channel_joined};
    use cordelia_network::messages::Protocol;
    const FORGED: &str = "2026-10-05T00:00:00.000000Z  INFO a line the peer wrote";
    let mut relay = node("relay", "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));

    let key = Arc::new(cordelia_crypto::identity::NodeIdentity::generate().unwrap());
    let named = format!("grp_canary\n{FORGED}{}", "x".repeat(5000));
    // An announcement that does not verify, whose own channel ID has a
    // line break too: the reason the relay gives holds that one.
    let mut descriptor = announcement(&key, &format!("grp_inner\n{FORGED}"));
    descriptor.signature[0] ^= 0xFF;
    let (_manager, conn) = client_of(&relay, key).await;
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    cordelia_network::codec::write_protocol_byte(&mut send, Protocol::ChannelAnnounce)
        .await
        .unwrap();
    send_channel_joined(&mut send, &named, &descriptor)
        .await
        .unwrap();
    let _ = send.finish();

    let warned = wait_for("the relay warns of the announcement", &[&relay], 60, || {
        let log = without_colour(&std::fs::read_to_string(relay.log()).ok()?);
        log.lines()
            .find(|line| line.contains("channel-announce: invalid descriptor"))
            .map(String::from)
    });
    assert!(warned.contains("WARN"), "{warned}");
    assert!(
        warned.contains(r"channel=grp_canary\n2026-10-05"),
        "{warned}"
    );
    assert!(warned.contains(r"grp_inner\n2026-10-05"), "{warned}");
    assert!(warned.len() < 400, "{} characters: {warned}", warned.len());
    let log = std::fs::read_to_string(relay.log()).unwrap();
    assert!(!log.lines().any(|line| line.starts_with(FORGED)), "{log}");
    assert!(!log.contains(&"x".repeat(100)));
}
