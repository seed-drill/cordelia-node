//! The harness the real-process tests share: nodes started as separate
//! processes on localhost, driven only through the CLI and the local HTTP
//! API, as a person would.

// Each test file uses a different part of this.
#![allow(dead_code)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const BIN: &str = env!("CARGO_BIN_EXE_cordelia");

pub struct Node {
    pub name: &'static str,
    pub child: Option<Child>,
    pub dir: tempfile::TempDir,
    pub http: u16,
    pub p2p: u16,
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
    pub fn config(&self) -> PathBuf {
        self.dir.path().join("config.toml")
    }

    pub fn data_dir(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    pub fn log(&self) -> PathBuf {
        self.dir.path().join("node.log")
    }

    /// Add a relay to this node's configuration: where to dial and, if
    /// given, the key that must answer there. For before the node starts.
    pub fn add_relay(&self, addr: &str, key: Option<&str>) {
        let key = key.map(|k| format!("key = \"{k}\"\n")).unwrap_or_default();
        let mut config = std::fs::read_to_string(self.config()).unwrap();
        config.push_str(&format!(
            "\n[[network.bootnodes]]\naddr = \"{addr}\"\n{key}"
        ));
        std::fs::write(self.config(), config).unwrap();
    }

    pub fn token(&self) -> String {
        std::fs::read_to_string(self.data_dir().join("node-token"))
            .unwrap()
            .trim()
            .to_string()
    }

    /// A CLI command against this node, run as on its machine.
    pub fn command(&self, args: &[&str]) -> std::process::Output {
        Command::new(BIN)
            .arg("--config")
            .arg(self.config())
            .args(args)
            .env("CORDELIA_DATA_DIR", self.data_dir())
            .env("HOME", self.home())
            .output()
            .unwrap()
    }

    /// Run a CLI command against this node and return its stdout.
    pub fn cli(&self, args: &[&str]) -> String {
        let out = self.command(args);
        assert!(
            out.status.success(),
            "{}: cordelia {args:?} failed:\n{}{}",
            self.name,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// Run a CLI command that must be refused, and return what it says.
    pub fn refused(&self, args: &[&str]) -> String {
        let out = self.command(args);
        assert!(
            !out.status.success(),
            "{}: cordelia {args:?} should have been refused:\n{}",
            self.name,
            String::from_utf8_lossy(&out.stdout)
        );
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    /// This node's stand-in home directory (for the sync adapter): a real
    /// path, as Claude Code records them.
    pub fn home(&self) -> PathBuf {
        self.dir.path().canonicalize().unwrap().join("home")
    }

    pub fn start(&mut self) {
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
    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status();
            let _ = child.wait();
        }
    }

    /// Kill the node outright, as a crash or power loss would: its peers
    /// only find out when the connection times out.
    pub fn crash(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    pub fn get(&self, path: &str) -> Option<serde_json::Value> {
        let url = format!("http://127.0.0.1:{}{path}", self.http);
        let mut resp = ureq::get(&url)
            .header("Authorization", &format!("Bearer {}", self.token()))
            .call()
            .ok()?;
        resp.body_mut().read_json().ok()
    }

    pub fn get_text(&self, path: &str) -> String {
        let url = format!("http://127.0.0.1:{}{path}", self.http);
        ureq::get(&url)
            .header("Authorization", &format!("Bearer {}", self.token()))
            .call()
            .unwrap_or_else(|e| panic!("{}: GET {path} failed: {e}", self.name))
            .body_mut()
            .read_to_string()
            .unwrap()
    }

    pub fn post(&self, path: &str, body: serde_json::Value) -> serde_json::Value {
        let url = format!("http://127.0.0.1:{}{path}", self.http);
        let mut resp = ureq::post(&url)
            .header("Authorization", &format!("Bearer {}", self.token()))
            .send_json(&body)
            .unwrap_or_else(|e| panic!("{}: POST {path} failed: {e}", self.name));
        resp.body_mut().read_json().unwrap()
    }

    /// Set `max_storage_bytes` for this node, before it is started: the
    /// most a relay's database may hold.
    pub fn max_storage_bytes(&self, bytes: u64) {
        let config = std::fs::read_to_string(self.config()).unwrap();
        let (before, after) = config
            .split_once("[network]")
            .expect("the config has a [network] section after [node]");
        std::fs::write(
            self.config(),
            format!("{before}max_storage_bytes = {bytes}\n\n[network]{after}"),
        )
        .unwrap();
    }

    pub fn log_tail(&self) -> String {
        let log = std::fs::read_to_string(self.log()).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }
}

/// A port for a test node, free for TCP (its HTTP API) and UDP (QUIC).
///
/// It is taken from below the range the system gives to outgoing
/// connections, and one test process never gives the same one out twice.
/// A port found by binding port 0 and letting go is in that range, so by
/// the time the node binds it, some client's connection may have been
/// given the same number, and the node fails to start. A test that starts
/// a node late (a relay that comes up after its device) hit that in CI.
pub fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    const FIRST: u16 = 20_000;
    const COUNT: u16 = 10_000;
    static NEXT: AtomicU16 = AtomicU16::new(0);
    // Each test binary starts somewhere of its own, so that binaries run
    // one after another do not walk over each other's lingering sockets.
    let start = (std::process::id() % u32::from(COUNT)) as u16;
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed) % COUNT;
        let port = FIRST + (start + n) % COUNT;
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
            && std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok()
        {
            return port;
        }
    }
}

pub fn node(name: &'static str, role: &str, relay_p2p: Option<u16>) -> Node {
    node_with_bootnode(
        name,
        role,
        relay_p2p.map(|port| format!("127.0.0.1:{port}")),
    )
}

/// A node whose one bootnode is `bootnode` (`host:port`; a name, like the
/// default relays, or an address).
pub fn node_with_bootnode(name: &'static str, role: &str, bootnode: Option<String>) -> Node {
    node_with_bootnodes(name, role, &bootnode.into_iter().collect::<Vec<_>>())
}

/// A node with these bootnodes (`host:port` each).
pub fn node_with_bootnodes(name: &'static str, role: &str, bootnode_addrs: &[String]) -> Node {
    let relays: Vec<(String, Option<String>)> =
        bootnode_addrs.iter().map(|a| (a.clone(), None)).collect();
    node_with_relays(name, role, &relays)
}

/// A node with these relays: `host:port`, and the key that must answer
/// there if one is given.
pub fn node_with_relays(
    name: &'static str,
    role: &str,
    relays: &[(String, Option<String>)],
) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let http = free_port();
    let mut p2p = free_port();
    while p2p == http {
        p2p = free_port();
    }
    let bootnodes: String = relays
        .iter()
        .map(|(addr, key)| {
            let key = key
                .as_ref()
                .map(|k| format!("key = \"{k}\"\n"))
                .unwrap_or_default();
            format!("[[network.bootnodes]]\naddr = \"{addr}\"\n{key}")
        })
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
pub fn wait_for<T>(
    what: &str,
    nodes: &[&Node],
    secs: u64,
    mut check: impl FnMut() -> Option<T>,
) -> T {
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

pub fn healthy(n: &Node) -> Option<()> {
    let url = format!("http://127.0.0.1:{}/api/v1/health", n.http);
    ureq::get(&url).call().ok().map(|_| ())
}

pub fn has_hot_peer(n: &Node) -> Option<()> {
    let status = n.get("/api/v1/status")?;
    (status["peers_hot"].as_u64()? >= 1).then_some(())
}

/// Pair `b` with `a` as the documented flow does, one key copied in each
/// direction; `a` labels `b` with `label`. Returns the personal channel,
/// once `b` has joined it.
pub fn pair(a: &Node, b: &Node, label: &str, all: &[&Node]) -> String {
    let b_key = b.cli(&["id"]).trim().to_string();
    let added = a.cli(&["add-device", &b_key, "--name", label]);
    let a_key = added
        .lines()
        .find_map(|l| l.trim().strip_prefix("cordelia accept "))
        .unwrap_or_else(|| panic!("add-device output lacks the accept line:\n{added}"))
        .to_string();
    b.cli(&["accept", &a_key]);
    let personal = groups(a)
        .into_iter()
        .next()
        .expect("a has a personal channel");
    wait_for("b joins a's personal channel", all, 90, || {
        groups(b).contains(&personal).then_some(())
    });
    personal
}

pub fn groups(n: &Node) -> Vec<String> {
    n.post("/api/v1/channels/list-groups", serde_json::json!({}))["groups"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|g| g["channel_id"].as_str().map(String::from))
        .collect()
}

/// The folder Claude Code keeps for a session started in `dir`.
pub fn claude_project(home: &std::path::Path, dir: &std::path::Path) -> PathBuf {
    let name: String = dir
        .display()
        .to_string()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    home.join(".claude/projects").join(name)
}

/// Record a Claude Code session started in `cwd` under `home`; returns the
/// memory folder of its project folder (created).
pub fn claude_folder(home: &std::path::Path, cwd: &std::path::Path) -> PathBuf {
    let folder = claude_project(home, cwd);
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

/// Where a node stands with each relay it was configured with, from
/// `cordelia peers --json`.
pub fn relays_of(n: &Node) -> Vec<serde_json::Value> {
    let out = n.command(&["peers", "--json"]);
    if !out.status.success() {
        return Vec::new();
    }
    serde_json::from_slice::<serde_json::Value>(&out.stdout)
        .ok()
        .and_then(|v| v["relays"].as_array().cloned())
        .unwrap_or_default()
}
