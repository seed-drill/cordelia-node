//! End to end, with real processes: a relay and two personal nodes on
//! localhost, talking QUIC. Device A runs `add-device B`, B runs
//! `accept A`, B joins A's personal channel through the relay, and an item
//! A then publishes in that channel reaches B, decrypted with the key B
//! received (decision 2026-09-30-agent-memory-sync §3, §4.1).
//!
//! Uses only the CLI and the local HTTP API, as a person would.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_cordelia");

struct Node {
    name: &'static str,
    child: Option<Child>,
    dir: tempfile::TempDir,
    http: u16,
    p2p: u16,
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // CORDELIA_E2E_KEEP=1 keeps each node's directory (config, data, log).
        if std::env::var_os("CORDELIA_E2E_KEEP").is_some() {
            let dir = std::mem::replace(&mut self.dir, tempfile::tempdir().unwrap());
            eprintln!("kept {} at {}", self.name, dir.keep().display());
        }
    }
}

impl Node {
    fn config(&self) -> PathBuf {
        self.dir.path().join("config.toml")
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn log(&self) -> PathBuf {
        self.dir.path().join("node.log")
    }

    fn token(&self) -> String {
        std::fs::read_to_string(self.data_dir().join("node-token"))
            .unwrap()
            .trim()
            .to_string()
    }

    /// Run a CLI command against this node and return its stdout.
    fn cli(&self, args: &[&str]) -> String {
        let out = Command::new(BIN)
            .arg("--config")
            .arg(self.config())
            .args(args)
            .env("CORDELIA_DATA_DIR", self.data_dir())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}: cordelia {args:?} failed:\n{}{}",
            self.name,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// This node's stand-in home directory (for the sync adapter).
    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    fn start(&mut self) {
        let log = std::fs::File::create(self.log()).unwrap();
        std::fs::create_dir_all(self.home()).unwrap();
        let child = Command::new(BIN)
            .arg("--config")
            .arg(self.config())
            .arg("start")
            .env("CORDELIA_DATA_DIR", self.data_dir())
            .env("HOME", self.home())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        self.child = Some(child);
    }

    /// Stop the node as a service manager would (SIGTERM), so it closes
    /// its connections on the way out.
    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status();
            let _ = child.wait();
        }
    }

    /// Kill the node outright, as a crash or power loss would: its peers
    /// only find out when the connection times out.
    fn crash(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn get(&self, path: &str) -> Option<serde_json::Value> {
        let url = format!("http://127.0.0.1:{}{path}", self.http);
        let mut resp = ureq::get(&url)
            .header("Authorization", &format!("Bearer {}", self.token()))
            .call()
            .ok()?;
        resp.body_mut().read_json().ok()
    }

    fn get_text(&self, path: &str) -> String {
        let url = format!("http://127.0.0.1:{}{path}", self.http);
        ureq::get(&url)
            .header("Authorization", &format!("Bearer {}", self.token()))
            .call()
            .unwrap_or_else(|e| panic!("{}: GET {path} failed: {e}", self.name))
            .body_mut()
            .read_to_string()
            .unwrap()
    }

    fn post(&self, path: &str, body: serde_json::Value) -> serde_json::Value {
        let url = format!("http://127.0.0.1:{}{path}", self.http);
        let mut resp = ureq::post(&url)
            .header("Authorization", &format!("Bearer {}", self.token()))
            .send_json(&body)
            .unwrap_or_else(|e| panic!("{}: POST {path} failed: {e}", self.name));
        resp.body_mut().read_json().unwrap()
    }

    fn log_tail(&self) -> String {
        let log = std::fs::read_to_string(self.log()).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }
}

fn free_port() -> u16 {
    // Reserve the same number for TCP (HTTP) and UDP (QUIC) where possible.
    loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok() {
            return port;
        }
    }
}

fn node(name: &'static str, role: &str, relay_p2p: Option<u16>) -> Node {
    node_with_bootnode(
        name,
        role,
        relay_p2p.map(|port| format!("127.0.0.1:{port}")),
    )
}

/// A node whose one bootnode is `bootnode` (`host:port`; a name, like the
/// default relays, or an address).
fn node_with_bootnode(name: &'static str, role: &str, bootnode: Option<String>) -> Node {
    node_with_bootnodes(name, role, &bootnode.into_iter().collect::<Vec<_>>())
}

/// A node with these bootnodes (`host:port` each).
fn node_with_bootnodes(name: &'static str, role: &str, bootnode_addrs: &[String]) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let http = free_port();
    let mut p2p = free_port();
    while p2p == http {
        p2p = free_port();
    }
    let bootnodes: String = bootnode_addrs
        .iter()
        .map(|addr| format!("[[network.bootnodes]]\naddr = \"{addr}\"\n"))
        .collect();
    let (hot_min, hot_max) = if role == "relay" { (1, 10) } else { (1, 2) };
    let config = format!(
        r#"[identity]
entity_id = "{name}"

[node]
http_port = {http}
p2p_port = {p2p}
data_dir = "{data}"

[network]
listen_addr = "0.0.0.0:{p2p}"
role = "{role}"
allow_private_addresses = true
dns_discovery = ""

{bootnodes}
[governor]
hot_min = {hot_min}
hot_max = {hot_max}
warm_min = 1
warm_max = 10
cold_max = 20
tick_interval_secs = 2
min_warm_tenure_secs = 5
keepalive_timeout_secs = 30

[api]
bind_address = "127.0.0.1"

[logging]
level = "debug"
"#,
        data = dir.path().join("data").display(),
    );
    std::fs::write(dir.path().join("config.toml"), config).unwrap();

    let n = Node {
        name,
        child: None,
        dir,
        http,
        p2p,
    };
    n.cli(&["init", "--non-interactive", "--name", name]);
    n
}

/// Poll `check` until it returns Some, or fail with every node's log tail.
fn wait_for<T>(what: &str, nodes: &[&Node], secs: u64, mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = check() {
            return v;
        }
        if Instant::now() > deadline {
            let logs: String = nodes
                .iter()
                .map(|n| format!("\n===== {} =====\n{}", n.name, n.log_tail()))
                .collect();
            panic!("timed out after {secs}s waiting for: {what}{logs}");
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn healthy(n: &Node) -> Option<()> {
    let url = format!("http://127.0.0.1:{}/api/v1/health", n.http);
    ureq::get(&url).call().ok().map(|_| ())
}

fn has_hot_peer(n: &Node) -> Option<()> {
    let status = n.get("/api/v1/status")?;
    (status["peers_hot"].as_u64()? >= 1).then_some(())
}

fn groups(n: &Node) -> Vec<String> {
    n.post("/api/v1/channels/list-groups", serde_json::json!({}))["groups"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|g| g["channel_id"].as_str().map(String::from))
        .collect()
}

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
    // exist yet when the node starts: its startup dial fails, and it must
    // keep resolving and retrying the name rather than give up.
    let mut relay = node("relay", "relay", None);
    let mut a = node_with_bootnode(
        "early",
        "personal",
        Some(format!("localhost:{}", relay.p2p)),
    );
    a.start();
    wait_for("a healthy", &[&a], 30, || healthy(&a));
    wait_for("a's startup dial to give up", &[&a], 60, || {
        std::fs::read_to_string(a.log())
            .ok()?
            .contains("bootstrap complete")
            .then_some(())
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

/// A Claude Code project folder under `home` whose sessions ran in `cwd`;
/// returns its memory folder.
fn claude_folder(home: &std::path::Path, cwd: &std::path::Path) -> PathBuf {
    let slug = cwd.display().to_string().replace(['/', '.'], "-");
    let folder = home.join(".claude/projects").join(slug);
    std::fs::create_dir_all(folder.join("memory")).unwrap();
    std::fs::write(
        folder.join("session.jsonl"),
        format!(
            "{{\"cwd\":{:?},\"type\":\"user\"}}\n",
            cwd.display().to_string()
        ),
    )
    .unwrap();
    folder.join("memory")
}

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

/// The product, end to end: two machines, each with its own home, Claude
/// Code folder, and clone of the same repository at a different path.
/// After pairing and `cordelia sync claude` on both, memory Claude writes
/// on one machine appears on the other, in the home and project folders.
#[test]
fn claude_memory_syncs_between_two_machines() {
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

    // Each machine: home memory, and a clone at a different path.
    let a_home_mem = claude_folder(&a.home(), &a.home());
    let b_home_mem = claude_folder(&b.home(), &b.home());
    let a_proj_mem = claude_folder(&a.home(), &clone_at(&a.home(), "Work/cordelia-node"));
    let b_proj_mem = claude_folder(&b.home(), &clone_at(&b.home(), "code/cn"));

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
        let claude_dir = n.home().join(".claude");
        n.cli(&["sync", "claude", "--dir", claude_dir.to_str().unwrap()]);
    }

    // Claude writes memories on A.
    std::fs::write(a_home_mem.join("user_role.md"), "Russ is the CPO.\n").unwrap();
    std::fs::write(
        a_proj_mem.join("decision.md"),
        "Invite-only channels only.\n",
    )
    .unwrap();

    let read = |p: &std::path::Path| std::fs::read_to_string(p).ok();
    wait_for("b gets a's home memory", &all, 120, || {
        (read(&b_home_mem.join("user_role.md"))?.as_str() == "Russ is the CPO.\n").then_some(())
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

    let status = b.cli(&["sync", "status"]);
    assert!(
        status.contains("github.com/seed-drill/cordelia-node"),
        "{status}"
    );

    // The status indicator: once everything has reached the relay, both
    // devices say so.
    let state = |n: &Node| -> serde_json::Value {
        serde_json::from_str(&n.cli(&["status", "--json"])).unwrap()
    };
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
    // each project with its settings.
    let snapshot = state(&a);
    assert_eq!(snapshot["peers"]["list"][0]["role"], "relay", "{snapshot}");
    assert_eq!(
        snapshot["devices"].as_array().unwrap().len(),
        2,
        "{snapshot}"
    );
    assert!(
        snapshot["sync"]["projects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["project"] == "github.com/seed-drill/cordelia-node"),
        "{snapshot}"
    );

    // One setting changes at a time; the others stay as they were.
    a.cli(&["sync", "home", "off"]);
    a.cli(&["sync", "exclude", "github.com/Client-Co/App.git"]);
    let s = state(&a);
    assert_eq!(s["sync"]["home"], false, "{s}");
    assert_eq!(
        s["sync"]["exclude"],
        serde_json::json!(["github.com/client-co/app"])
    );
    assert_eq!(s["sync"]["enabled"], true);
    a.cli(&["sync", "include", "github.com/client-co/app"]);
    a.cli(&["sync", "home", "on"]);
    let s = state(&a);
    assert_eq!(s["sync"]["home"], true, "{s}");
    assert_eq!(s["sync"]["exclude"], serde_json::json!([]));
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
