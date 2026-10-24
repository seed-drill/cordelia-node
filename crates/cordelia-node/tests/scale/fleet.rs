//! The nodes of a run, as processes (decision 2026-10-22 §4.3, rules 1 and
//! 6): each made and checked before anything starts, started in a process
//! group of its own with `PR_SET_PDEATHSIG` set to SIGKILL from one thread
//! that lives as long as the run, stopped, frozen, and sampled from outside
//! and through its route of counters, which takes no lock (§1.1).

use std::collections::HashMap;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use crate::common::Node;
use crate::configs::Settings;
use crate::machine::{self, ProcRead};

// ── The clock of a run ───────────────────────────────────────────────

/// Seconds since the run's time zero, the relays' start (step 2).
#[derive(Debug, Clone, Copy)]
pub struct Clock {
    pub zero: Instant,
    pub wall: std::time::SystemTime,
}

impl Clock {
    pub fn new() -> Clock {
        Clock {
            zero: Instant::now(),
            wall: std::time::SystemTime::now(),
        }
    }

    pub fn now(&self) -> f64 {
        self.zero.elapsed().as_secs_f64()
    }

    /// The run's second of a time on the wall clock (a log's), in seconds
    /// since the epoch.
    pub fn of_wall(&self, epoch_secs: f64) -> f64 {
        let zero = self
            .wall
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        epoch_secs - zero
    }
}

// ── The thread that starts every node ───────────────────────────────

type Start = (Command, mpsc::Sender<std::io::Result<Child>>);

/// One thread, for the run's length, from which every node is started:
/// the signal a node is given when its parent goes follows the thread that
/// started it (§4.3, rule 6).
pub struct Starter {
    asks: Mutex<Option<mpsc::Sender<Start>>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Starter {
    pub fn new() -> Starter {
        let (asks, asked) = mpsc::channel::<Start>();
        let thread = std::thread::Builder::new()
            .name("starts the nodes".into())
            .spawn(move || {
                for (mut command, back) in asked {
                    let _ = back.send(command.spawn());
                }
            })
            .unwrap();
        Starter {
            asks: Mutex::new(Some(asks)),
            thread: Mutex::new(Some(thread)),
        }
    }

    pub fn spawn(&self, command: Command) -> std::io::Result<Child> {
        let (back, answer) = mpsc::channel();
        let asks = self.asks.lock().unwrap().clone();
        let asks = asks.ok_or_else(|| std::io::Error::other("the run has ended"))?;
        asks.send((command, back))
            .map_err(|_| std::io::Error::other("the starter is gone"))?;
        answer
            .recv()
            .map_err(|_| std::io::Error::other("the starter is gone"))?
    }

    /// End the thread, once every node has stopped.
    pub fn end(&self) {
        self.asks.lock().unwrap().take();
        if let Some(thread) = self.thread.lock().unwrap().take() {
            let _ = thread.join();
        }
    }
}

/// `command`, in a process group of its own and given SIGKILL when the
/// thread that starts it goes.
fn as_a_node(command: &mut Command) {
    command.process_group(0);
    // SAFETY: between fork and exec only async-signal-safe calls are
    // made: one prctl.
    unsafe {
        command.pre_exec(|| {
            rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
                .map_err(std::io::Error::from)
        });
    }
}

// ── The nodes ───────────────────────────────────────────────────────

/// Which node a process is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum What {
    Relay(usize),
    Device { person: usize, device: usize },
}

/// Where a node is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Is {
    NotStarted,
    Running,
    Frozen,
    Stopped,
}

/// What changes of a node.
#[derive(Debug)]
pub struct State {
    pub child: Option<Child>,
    pub is: Is,
    pub since: f64,
    /// The harness told it to stop: an exit is no fault.
    pub told: bool,
}

/// What a change of a node's state was, for the summary and the bars.
#[derive(Debug, Clone, PartialEq)]
pub struct Change {
    pub t: f64,
    pub node: usize,
    pub is: Is,
    /// How a stop ended: its seconds, and its status.
    pub ended: Option<(f64, String)>,
}

/// What does not change of a node.
pub struct Made {
    pub node: Node,
    pub what: What,
    pub label: String,
    pub key: String,
    pub key_hex: String,
    pub token: String,
    pub settings: Mutex<Settings>,
    /// The cores of its mask, where it has one.
    pub mask: Option<String>,
}

/// Every node of a run.
pub struct Fleet {
    pub made: Vec<Made>,
    pub state: Vec<Mutex<State>>,
    pub relays: Vec<usize>,
    pub devices: HashMap<(usize, usize), usize>,
    pub clock: Clock,
    pub starter: Starter,
    pub changes: Mutex<Vec<Change>>,
    pids: Mutex<std::fs::File>,
    pub faults: Mutex<Vec<String>>,
    pub stop_early: AtomicBool,
}

/// A node's name, as `common::Node` keeps it.
fn leaked(name: &str) -> &'static str {
    Box::leak(name.to_string().into_boxed_str())
}

/// A node made in `dir` with `settings`: its configuration written and
/// checked, and `cordelia init` run on it. Nothing is started.
pub fn make(dir: &Path, settings: &Settings) -> Result<(Node, String, String, String), String> {
    settings.check()?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tmp = tempfile::Builder::new()
        .prefix(&format!("{}-", settings.name))
        .tempdir_in(dir)
        .map_err(|e| e.to_string())?;
    let node = Node {
        name: leaked(&settings.name),
        child: None,
        dir: tmp,
        http: settings.http,
        p2p: settings.p2p,
        bin: None,
    };
    let mut settings = settings.clone();
    settings.data_dir = node.data_dir();
    std::fs::write(node.config(), settings.render()).map_err(|e| e.to_string())?;
    crate::configs::check_written(&node.config())?;
    node.cli(&["init", "--non-interactive", "--name", &settings.name]);
    let key = crate::common::key_of(&node);
    let key_hex = cordelia_crypto::bech32::decode_public_key(&key)
        .map(hex::encode)
        .map_err(|e| format!("{}: its key {key}: {e}", settings.name))?;
    let token = node.token();
    Ok((node, key, key_hex, token))
}

impl Fleet {
    pub fn new(clock: Clock, out: &Path) -> std::io::Result<Fleet> {
        let pids = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(out.join("pids"))?;
        Ok(Fleet {
            made: Vec::new(),
            state: Vec::new(),
            relays: Vec::new(),
            devices: HashMap::new(),
            clock,
            starter: Starter::new(),
            changes: Mutex::new(Vec::new()),
            pids: Mutex::new(pids),
            faults: Mutex::new(Vec::new()),
            stop_early: AtomicBool::new(false),
        })
    }

    pub fn add(&mut self, made: Made) -> usize {
        let i = self.made.len();
        match made.what {
            What::Relay(_) => self.relays.push(i),
            What::Device { person, device } => {
                self.devices.insert((person, device), i);
            }
        }
        self.made.push(made);
        self.state.push(Mutex::new(State {
            child: None,
            is: Is::NotStarted,
            since: 0.0,
            told: false,
        }));
        i
    }

    pub fn device(&self, person: usize, device: usize) -> usize {
        self.devices[&(person, device)]
    }

    pub fn is(&self, i: usize) -> (Is, f64) {
        let state = self.state[i].lock().unwrap();
        (state.is, state.since)
    }

    pub fn fault(&self, why: String) {
        eprintln!("scale: {why}");
        self.faults.lock().unwrap().push(why);
        self.stop_early.store(true, Ordering::SeqCst);
    }

    fn changed(&self, i: usize, is: Is, ended: Option<(f64, String)>) {
        let t = self.clock.now();
        self.changes.lock().unwrap().push(Change {
            t,
            node: i,
            is,
            ended,
        });
    }

    /// Start node `i`: what it will dial is read first, with the node's
    /// own reader, and it is not started where any of it is not one of
    /// the run's relays (§4.3, rule 1).
    pub fn start(&self, i: usize, relays: &[SocketAddr]) -> Result<(), String> {
        let made = &self.made[i];
        let node = &made.node;
        crate::configs::check_written(&node.config())?;
        for host in node.will_dial() {
            crate::common::assert_on_this_machine(node.name, &host);
            let is_ours = host
                .parse::<SocketAddr>()
                .is_ok_and(|addr| relays.contains(&addr));
            if !is_ours {
                return Err(format!(
                    "{}: it would dial {host}, no relay of the run",
                    made.label
                ));
            }
        }
        std::fs::create_dir_all(node.home()).map_err(|e| e.to_string())?;
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(node.log())
            .map_err(|e| e.to_string())?;
        let base = node.command_for(&[], &["start"]);
        let mut command = match &made.mask {
            None => base,
            Some(cores) => {
                let mut masked = Command::new("taskset");
                masked
                    .arg("-c")
                    .arg(cores)
                    .arg(base.get_program())
                    .args(base.get_args());
                for (name, value) in base.get_envs() {
                    match value {
                        Some(value) => masked.env(name, value),
                        None => masked.env_remove(name),
                    };
                }
                masked
            }
        };
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
            .stderr(Stdio::from(log));
        as_a_node(&mut command);
        let child = self
            .starter
            .spawn(command)
            .map_err(|e| format!("{}: not started: {e}", made.label))?;
        let line = machine::pid_line(child.id(), &node.config());
        let _ = self.pids.lock().unwrap().write_all(line.as_bytes());
        let mut state = self.state[i].lock().unwrap();
        state.child = Some(child);
        state.is = Is::Running;
        state.since = self.clock.now();
        state.told = false;
        drop(state);
        self.changed(i, Is::Running, None);
        Ok(())
    }

    pub fn pid(&self, i: usize) -> Option<u32> {
        self.state[i].lock().unwrap().child.as_ref().map(Child::id)
    }

    fn signal(pid: u32, signal: rustix::process::Signal) {
        if let Some(pid) = rustix::process::Pid::from_raw(pid as i32) {
            let _ = rustix::process::kill_process(pid, signal);
        }
    }

    /// Tell node `i` to stop with SIGTERM, and wait for it: how long it
    /// took, and whether it stopped as it should within
    /// NODE_STOP_TIMEOUT_SECS. One that has not stopped in half as long
    /// again is killed.
    pub fn stop(&self, i: usize) -> Option<(f64, bool)> {
        use cordelia_core::protocol::NODE_STOP_TIMEOUT_SECS;
        let mut child = {
            let mut state = self.state[i].lock().unwrap();
            let child = state.child.take()?;
            if state.is == Is::Frozen {
                Self::signal(child.id(), rustix::process::Signal::CONT);
            }
            state.told = true;
            child
        };
        Self::signal(child.id(), rustix::process::Signal::TERM);
        let told = Instant::now();
        let allowed = Duration::from_secs(NODE_STOP_TIMEOUT_SECS);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if told.elapsed() < allowed + allowed / 2 => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                _ => break None,
            }
        };
        let took = told.elapsed().as_secs_f64();
        let (well, said) = match status {
            Some(status) => (
                status.success() && took <= allowed.as_secs_f64(),
                format!("{status}"),
            ),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                (false, "killed: it did not stop".to_string())
            }
        };
        let mut state = self.state[i].lock().unwrap();
        state.is = Is::Stopped;
        state.since = self.clock.now();
        drop(state);
        self.changed(i, Is::Stopped, Some((took, said)));
        Some((took, well))
    }

    /// Freeze node `i` (SIGSTOP), or let it go on (SIGCONT).
    pub fn freeze(&self, i: usize, frozen: bool) {
        let mut state = self.state[i].lock().unwrap();
        let Some(child) = &state.child else { return };
        let (signal, is) = match frozen {
            true => (rustix::process::Signal::STOP, Is::Frozen),
            false => (rustix::process::Signal::CONT, Is::Running),
        };
        Self::signal(child.id(), signal);
        state.is = is;
        state.since = self.clock.now();
        drop(state);
        self.changed(i, is, None);
    }

    /// Whether node `i` has exited when it was not told to: it is then
    /// marked stopped, and the reason is given.
    pub fn exited_untold(&self, i: usize) -> Option<String> {
        let mut state = self.state[i].lock().unwrap();
        let status = state.child.as_mut()?.try_wait().ok()??;
        state.child = None;
        state.is = Is::Stopped;
        state.since = self.clock.now();
        drop(state);
        self.changed(i, Is::Stopped, Some((0.0, format!("{status}"))));
        Some(format!(
            "{} exited when it was not told to ({status})",
            self.made[i].label
        ))
    }

    /// Kill every node that is left: for a run that ends on a fault.
    pub fn kill_all(&self) {
        for state in &self.state {
            let mut state = state.lock().unwrap();
            if let Some(mut child) = state.child.take() {
                let _ = child.kill();
                let _ = child.wait();
                state.is = Is::Stopped;
            }
        }
    }
}

// ── Reads through the local API ─────────────────────────────────────

/// An HTTP client that goes straight to this machine, with a bound on
/// each request: a node that does not answer holds up no read.
pub fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .proxy(None)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(5)))
        .build()
        .into()
}

/// GET `path` of the node at `http`, with its token: its text, where it
/// answered with success.
pub fn get_text(agent: &ureq::Agent, http: u16, token: &str, path: &str) -> Option<String> {
    let mut resp = agent
        .get(&format!("http://127.0.0.1:{http}{path}"))
        .header("Authorization", &format!("Bearer {token}"))
        .call()
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.body_mut().read_to_string().ok()
}

/// The lines of `/api/v1/metrics/load` that hold a value, by their name
/// and labels.
pub fn parse_metrics(text: &str) -> HashMap<String, f64> {
    text.lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .filter_map(|line| {
            let (name, value) = line.rsplit_once(' ')?;
            Some((name.to_string(), value.parse().ok()?))
        })
        .collect()
}

/// The kinds of request on the streams of entries, as the route names
/// them, in their order.
pub const KINDS: [&str; 6] = [
    "show_whole",
    "show_short",
    "proof",
    "pull",
    "push",
    "relays",
];

/// What a device counts of each relay of the run, as it was read.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct DeviceCounts {
    pub asked: [[f64; 6]; 2],
    pub asked_bytes: [[f64; 6]; 2],
    pub held_back: [f64; 2],
    pub refused_for_now: [f64; 2],
    /// Waits for its lock over 100 ms, of every kind.
    pub waits_over_100: f64,
    /// Waits given up (a `msg summary` that did not have the lock).
    pub given_up: f64,
    /// Takes of its lock, of every kind.
    pub takes: f64,
}

impl DeviceCounts {
    pub fn of(metrics: &HashMap<String, f64>, relays: &[String]) -> DeviceCounts {
        let mut counts = DeviceCounts::default();
        for (r, key) in relays.iter().enumerate().take(2) {
            for (k, kind) in KINDS.iter().enumerate() {
                let at = format!("{{relay=\"{key}\",kind=\"{kind}\"}}");
                counts.asked[r][k] = metrics
                    .get(&format!("cordelia_device_requests_total{at}"))
                    .copied()
                    .unwrap_or(0.0);
                counts.asked_bytes[r][k] = metrics
                    .get(&format!("cordelia_device_request_bytes_total{at}"))
                    .copied()
                    .unwrap_or(0.0);
            }
            let at = format!("{{relay=\"{key}\"}}");
            counts.held_back[r] = metrics
                .get(&format!("cordelia_device_held_back_total{at}"))
                .copied()
                .unwrap_or(0.0);
            counts.refused_for_now[r] = metrics
                .get(&format!("cordelia_device_refused_for_now_total{at}"))
                .copied()
                .unwrap_or(0.0);
        }
        for (name, value) in metrics {
            if name.starts_with("cordelia_lock_wait_microseconds_over{")
                && name.ends_with(",ms=\"100\"}")
            {
                counts.waits_over_100 += value;
            }
            if name.starts_with("cordelia_lock_given_up_total{") {
                counts.given_up += value;
            }
            if name.starts_with("cordelia_lock_wait_microseconds_count{") {
                counts.takes += value;
            }
        }
        counts
    }
}

// ── Samples ─────────────────────────────────────────────────────────

/// One sample of one node.
#[derive(Debug, Clone, Default)]
pub struct Sample {
    pub t: f64,
    pub node: usize,
    pub frozen: bool,
    pub proc: Option<ProcRead>,
    /// A relay's every counter.
    pub metrics: Option<HashMap<String, f64>>,
    /// A device's counts.
    pub device: Option<DeviceCounts>,
    /// A device's status: its connections, and what waits to be sent.
    pub connections: Option<f64>,
    pub outbox_waiting: Option<f64>,
    /// A relay's peers: each one's key, and its address.
    pub peers: Option<Vec<(String, String)>>,
    /// A relay's room: bytes as entries are counted, and channels held.
    pub room: Option<(u64, u64)>,
}

/// One sample of the machine.
#[derive(Debug, Clone, Copy, Default)]
pub struct MachineSample {
    pub t: f64,
    pub read: machine::MachineRead,
}

/// Every sample of a run, as they are taken; each is also written to
/// `samples.jsonl` as it is.
pub struct Samples {
    pub nodes: Vec<Sample>,
    pub machine: Vec<MachineSample>,
    file: std::fs::File,
}

impl Samples {
    pub fn new(out: &Path) -> std::io::Result<Samples> {
        Ok(Samples {
            nodes: Vec::new(),
            machine: Vec::new(),
            file: std::fs::File::create(out.join("samples.jsonl"))?,
        })
    }

    pub fn add(&mut self, fleet: &Fleet, sample: Sample) {
        let made = &fleet.made[sample.node];
        let mut line = serde_json::json!({
            "t": (sample.t * 10.0).round() / 10.0,
            "node": made.label,
            "frozen": sample.frozen,
        });
        if let Some(p) = sample.proc {
            line["rss_kib"] = p.rss_kib.into();
            line["hwm_kib"] = p.hwm_kib.into();
            line["threads"] = p.threads.into();
            line["fds"] = p.fds.into();
            line["cpu_ticks"] = p.ticks.into();
        }
        if let Some(m) = &sample.metrics {
            let kept: serde_json::Map<String, serde_json::Value> = m
                .iter()
                .filter(|(k, _)| !k.contains("_bucket{"))
                .map(|(k, v)| (k.clone(), (*v).into()))
                .collect();
            line["metrics"] = kept.into();
        }
        if let Some(d) = &sample.device {
            line["asked"] = serde_json::json!(d.asked);
            line["asked_bytes"] = serde_json::json!(d.asked_bytes);
            line["held_back"] = serde_json::json!(d.held_back);
            line["refused_for_now"] = serde_json::json!(d.refused_for_now);
            line["lock_waits_over_100ms"] = d.waits_over_100.into();
            line["lock_waits_given_up"] = d.given_up.into();
        }
        if let Some(c) = sample.connections {
            line["connections"] = c.into();
        }
        if let Some(o) = sample.outbox_waiting {
            line["outbox_waiting"] = o.into();
        }
        if let Some(peers) = &sample.peers {
            line["peers"] = peers.len().into();
        }
        if let Some((bytes, channels)) = sample.room {
            line["room_bytes"] = bytes.into();
            line["room_channels"] = channels.into();
        }
        let _ = writeln!(self.file, "{line}");
        self.nodes.push(sample);
    }

    pub fn add_machine(&mut self, sample: MachineSample) {
        let r = &sample.read;
        let line = serde_json::json!({
            "t": (sample.t * 10.0).round() / 10.0,
            "node": "machine",
            "cpu_all": r.cpu_all, "cpu_idle": r.cpu_idle, "cpu_iowait": r.cpu_iowait,
            "mem_available_kib": r.mem_available_kib, "disk_free": r.disk_free,
            "writes": r.writes, "write_ms": r.write_ms, "harness_ticks": r.harness_ticks,
        });
        let _ = writeln!(self.file, "{line}");
        self.machine.push(sample);
    }
}

/// A relay's room, read through a read-only connection to its database:
/// it neither waits for the node's writer nor holds it up (§1.1, rule 2).
pub fn read_room(data_dir: &Path) -> Option<(u64, u64)> {
    use rusqlite::OpenFlags;
    let db = data_dir.join("cordelia.db");
    let conn = rusqlite::Connection::open_with_flags(
        &db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    conn.busy_timeout(Duration::from_secs(5)).ok()?;
    conn.query_row(
        "SELECT COALESCE(SUM(bytes), 0), COUNT(*) FROM relay_channels",
        [],
        |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
    )
    .ok()
}

/// One sample of node `i`: /proc from outside, and for a node that is not
/// frozen its counters; for a device its status, and for a relay its
/// peers, and its room where `room` is asked.
pub fn sample(
    fleet: &Fleet,
    agent: &ureq::Agent,
    i: usize,
    room: bool,
    relay_keys: &[String],
) -> Option<Sample> {
    let (is, _) = fleet.is(i);
    if !matches!(is, Is::Running | Is::Frozen) {
        return None;
    }
    let pid = fleet.pid(i)?;
    let made = &fleet.made[i];
    let mut s = Sample {
        t: fleet.clock.now(),
        node: i,
        frozen: is == Is::Frozen,
        proc: machine::read_proc(pid),
        ..Sample::default()
    };
    if is == Is::Running {
        let (http, token) = (made.node.http, made.token.as_str());
        let metrics =
            get_text(agent, http, token, "/api/v1/metrics/load").map(|t| parse_metrics(&t));
        match made.what {
            What::Relay(_) => {
                s.metrics = metrics;
                s.peers = get_text(agent, http, token, "/api/v1/peers").and_then(|text| {
                    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
                    Some(
                        v["peers"]
                            .as_array()?
                            .iter()
                            .map(|p| {
                                (
                                    p["key"].as_str().unwrap_or_default().to_string(),
                                    p["address"].as_str().unwrap_or_default().to_string(),
                                )
                            })
                            .collect(),
                    )
                });
            }
            What::Device { .. } => {
                s.device = metrics.map(|m| DeviceCounts::of(&m, relay_keys));
                if let Some(text) = get_text(agent, http, token, "/api/v1/status")
                    && let Ok(v) = serde_json::from_str::<serde_json::Value>(&text)
                {
                    s.connections = v["peers_hot"].as_f64();
                    s.outbox_waiting = v["outbox_waiting"].as_f64();
                }
            }
        }
    }
    if room && matches!(made.what, What::Relay(_)) {
        s.room = read_room(&made.node.data_dir());
    }
    Some(s)
}

/// The address a relay says a peer has, as an IP.
pub fn ip_of(address: &str) -> Option<IpAddr> {
    address
        .parse::<SocketAddr>()
        .map(|a| a.ip())
        .or_else(|_| address.parse::<IpAddr>())
        .ok()
}

/// Where a node's memory folder of a name is: Claude Code's project folder
/// for a session in `~/<name>`, and its `memory`.
pub fn memory_folder(node: &Node, name: &str) -> PathBuf {
    crate::common::claude_project(&node.home(), &node.home().join(name)).join("memory")
}
