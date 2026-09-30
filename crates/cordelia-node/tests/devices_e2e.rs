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

    fn get(&self, path: &str) -> Option<serde_json::Value> {
        let url = format!("http://127.0.0.1:{}{path}", self.http);
        let mut resp = ureq::get(&url)
            .header("Authorization", &format!("Bearer {}", self.token()))
            .call()
            .ok()?;
        resp.body_mut().read_json().ok()
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
    let dir = tempfile::tempdir().unwrap();
    let http = free_port();
    let mut p2p = free_port();
    while p2p == http {
        p2p = free_port();
    }
    let bootnodes = relay_p2p
        .map(|port| format!("[[network.bootnodes]]\naddr = \"127.0.0.1:{port}\"\n"))
        .unwrap_or_default();
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
}
