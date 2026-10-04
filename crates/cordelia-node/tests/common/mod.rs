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
        assert_on_this_machine(self.name, addr);
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

    /// The binary, told to use this node's configuration, data directory
    /// and home, and without three things of whoever runs the tests: any
    /// `CORDELIA_` variable and `RUST_LOG` (either would stand in place of
    /// the node's configuration), and any proxy (the tests of what a
    /// command does with one set their own). What else the binary reads
    /// from the environment is left: `NO_COLOR`, which no test asks of.
    fn binary(&self) -> Command {
        self.binary_given(std::env::vars_os().map(|(name, _)| name))
    }

    /// [`Self::binary`], given the names of the variables it would
    /// inherit: the environment's, except in the test of this.
    pub fn binary_given(&self, inherited: impl Iterator<Item = std::ffi::OsString>) -> Command {
        let mut command = Command::new(BIN);
        for name in inherited {
            let theirs = name.to_str().is_some_and(|name| {
                name.starts_with("CORDELIA_")
                    || name == "RUST_LOG"
                    || name.to_lowercase().ends_with("_proxy")
            });
            if theirs {
                command.env_remove(&name);
            }
        }
        command
            .arg("--config")
            .arg(self.config())
            .env("CORDELIA_DATA_DIR", self.data_dir())
            .env("HOME", self.home());
        command
    }

    /// A CLI command against this node, run as on its machine.
    pub fn command(&self, args: &[&str]) -> std::process::Output {
        self.binary().args(args).output().unwrap()
    }

    /// A CLI command against this node, with `vars` set for it, not yet
    /// run: the caller's own are taken out first, as for any command.
    pub fn command_for(&self, vars: &[(&str, &str)], args: &[&str]) -> Command {
        let mut command = self.binary();
        command.envs(vars.iter().copied()).args(args);
        command
    }

    /// [`Self::command_for`], run.
    pub fn command_given(&self, vars: &[(&str, &str)], args: &[&str]) -> std::process::Output {
        self.command_for(vars, args).output().unwrap()
    }

    /// As [`Self::command`], run in the directory `dir`: for what a
    /// command makes of a relative path.
    pub fn command_in(&self, dir: &std::path::Path, args: &[&str]) -> std::process::Output {
        self.binary().args(args).current_dir(dir).output().unwrap()
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

    /// The relays the node will dial if it is started now: its
    /// configuration, read with the node's own reader, and given to the
    /// function the node itself asks when it starts
    /// (`bootstrap::relays_dialled`). So the harness and the node cannot
    /// come to differ on it. Those relays are all a personal node or a
    /// relay dials, and a configuration with any other role is refused
    /// here (see [`assert_a_role_that_is_checked`]).
    pub fn will_dial(&self) -> Vec<String> {
        let config = cordelia_core::config::Config::load(&self.config())
            .unwrap_or_else(|e| panic!("{}: its configuration cannot be read: {e}", self.name));
        assert_a_role_that_is_checked(self.name, &config.network.role);
        let named: Vec<(String, Option<String>)> = config
            .network
            .bootnodes
            .iter()
            .map(|b| (b.addr.clone(), b.key.clone()))
            .collect();
        cordelia_network::bootstrap::relays_dialled(&config.network.role, &named)
            .unwrap_or_else(|e| panic!("{}: its relays cannot be read: {e}", self.name))
            .into_iter()
            .map(|relay| relay.host)
            .collect()
    }

    /// Start the node. Its configuration is read first, and the node is
    /// not started if a relay it would dial is not on this machine, or if
    /// its role is one whose dialling cannot be known beforehand: whatever
    /// wrote the configuration, and whatever a test did to it since. (The
    /// node is given no `CORDELIA_` variable but its data directory, and
    /// no `RUST_LOG`, so its settings are the file's.)
    pub fn start(&mut self) {
        for host in self.will_dial() {
            assert_on_this_machine(self.name, &host);
        }
        let log = std::fs::File::create(self.log()).unwrap();
        std::fs::create_dir_all(self.home()).unwrap();
        let child = self
            .binary()
            .arg("start")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        self.child = Some(child);
    }

    /// Tell the node to stop with SIGTERM, as a service manager does, so
    /// that it closes its connections on the way out.
    pub fn stop(&mut self) {
        self.stop_with("TERM");
    }

    /// Tell the node to stop with `signal` (TERM, INT or QUIT). A node that
    /// is told to stop exits within a bounded time, and with success, which
    /// it has only if every part of it stopped in time and without
    /// failing. One that does not exit is killed. Either way the test fails
    /// with the node's log: a node that never exits would otherwise hang
    /// the whole run, and one that gave up on a part of itself would pass
    /// unnoticed.
    pub fn stop_with(&mut self, signal: &str) {
        use cordelia_core::protocol::{NODE_STOP_TIMEOUT_SECS, STREAM_TIMEOUT_SECS};
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = Command::new("kill")
            .args([&format!("-{signal}"), &child.id().to_string()])
            .status();
        // The node's own bound, the stream timeout it then gives work that
        // cannot be interrupted, and a margin.
        let allowed = Duration::from_secs(NODE_STOP_TIMEOUT_SECS + STREAM_TIMEOUT_SECS + 5);
        let told = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if told.elapsed() < allowed => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                _ => break None,
            }
        };
        let Some(status) = status else {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "{} did not exit within {}s of being told to stop\n{}",
                self.name,
                allowed.as_secs(),
                self.log_tail()
            );
        };
        if !status.success() {
            panic!(
                "{} did not stop as it should ({status})\n{}",
                self.name,
                self.log_tail()
            );
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
        let mut resp = direct()
            .get(&url)
            .header("Authorization", &format!("Bearer {}", self.token()))
            .call()
            .ok()?;
        resp.body_mut().read_json().ok()
    }

    pub fn get_text(&self, path: &str) -> String {
        let url = format!("http://127.0.0.1:{}{path}", self.http);
        direct()
            .get(&url)
            .header("Authorization", &format!("Bearer {}", self.token()))
            .call()
            .unwrap_or_else(|e| panic!("{}: GET {path} failed: {e}", self.name))
            .body_mut()
            .read_to_string()
            .unwrap()
    }

    pub fn post(&self, path: &str, body: serde_json::Value) -> serde_json::Value {
        let url = format!("http://127.0.0.1:{}{path}", self.http);
        let mut resp = direct()
            .post(&url)
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

    /// How long this relay waits before it asks a device again which
    /// channels it holds, and before it takes again a channel it dropped.
    /// For before the node starts.
    pub fn relay_ask_again_secs(&self, secs: u64) {
        let mut config = std::fs::read_to_string(self.config()).unwrap();
        config.push_str(&format!("\n[replication]\nrelay_ask_again_secs = {secs}\n"));
        std::fs::write(self.config(), config).unwrap();
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

/// A node whose one relay is the one on this machine at `relay_p2p`, or
/// that has no relay at all ([`NOWHERE`]).
pub fn node(name: &'static str, role: &str, relay_p2p: Option<u16>) -> Node {
    node_with_bootnode(
        name,
        role,
        relay_p2p.map(|port| format!("127.0.0.1:{port}")),
    )
}

/// The one address a personal node is given where a test gives it no
/// relay: this machine, at a port where nothing listens.
///
/// A personal node that is configured with no relay dials the default
/// ones, and those are real and public. A test node that reached them
/// would be counted there as somebody's device, and would leave its
/// channels behind. So no test node is ever left with none.
pub const NOWHERE: &str = "127.0.0.1:9";

/// A test node dials nothing that is not on this machine, whatever a test
/// gives it: a loopback address with its port, read as the node first
/// reads what it is given (so `[::1]:9474` is one, and `[127.0.0.1]:9`,
/// which the node would take for a name, is not); or `localhost` where
/// the machine's own resolver gives that name loopback addresses and no
/// other. No other name is looked up to find out, so none passes,
/// wherever it leads.
pub fn assert_on_this_machine(name: &str, addr: &str) {
    use std::net::{SocketAddr, ToSocketAddrs};
    let host = addr.rsplit_once(':').map_or(addr, |(host, _)| host);
    let here = match addr.parse::<SocketAddr>() {
        Ok(literal) => literal.ip().is_loopback(),
        Err(_) if host == "localhost" => addr
            .to_socket_addrs()
            .is_ok_and(|mut found| found.all(|a| a.ip().is_loopback())),
        Err(_) => false,
    };
    assert!(
        here,
        "the test node {name} would dial {addr}, which is not on this machine"
    );
}

/// A personal node and a relay dial relays and nothing else: the ones
/// their configuration names, or for a personal node that names none,
/// the default ones. So what they will dial can be known before they are
/// started ([`Node::will_dial`]). A node of any other role dials the
/// addresses its peers hand it, which nothing read beforehand can show.
/// The harness makes no such node, and starts none.
pub fn assert_a_role_that_is_checked(name: &str, role: &str) {
    assert!(
        role == "personal" || role == "relay",
        "the test node {name} has the role {role:?}: where such a node dials cannot be \
         read from its configuration, and the harness does not run one"
    );
}

/// The relays a node is configured with: those it is given, or
/// [`NOWHERE`] for a personal node that is given none, which is the one
/// kind of node that dials the default relays where it has none of its
/// own. (A relay that is given none dials nothing, and is left with
/// none.)
fn relays_for(role: &str, relays: &[(String, Option<String>)]) -> Vec<(String, Option<String>)> {
    if relays.is_empty() && role == "personal" {
        return vec![(NOWHERE.to_string(), None)];
    }
    relays.to_vec()
}

/// A node whose one bootnode is `bootnode` (`host:port`: `localhost`, or a
/// loopback address).
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
    assert_a_role_that_is_checked(name, role);
    let dir = tempfile::tempdir().unwrap();
    let http = free_port();
    let mut p2p = free_port();
    while p2p == http {
        p2p = free_port();
    }
    let relays = relays_for(role, relays);
    for (addr, _) in &relays {
        assert_on_this_machine(name, addr);
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
    direct().get(&url).call().ok().map(|_| ())
}

/// An HTTP client that goes straight to the address it is given. The
/// default one takes a proxy from the environment, and a test's requests
/// to this machine, with a node's token in them, are not for a proxy.
pub fn direct() -> ureq::Agent {
    ureq::Agent::config_builder().proxy(None).build().into()
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
