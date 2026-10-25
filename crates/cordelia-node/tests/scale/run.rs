//! A run, step by step (decision 2026-10-22 §4.2): the checks before it,
//! the relays, the people ten at a time, the office's move, the window
//! with its edits, its times off, its relay that stops and its removals,
//! the end, and what it leaves (§4.4).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::common::{self, Node};
use crate::configs::{RELAY_ADDRESS, Role, Settings};
use crate::fleet::{self, Clock, Fleet, Is, Made, Samples, What};
use crate::machine::{self, ThreadPlan};
use crate::observer::{self, Observer, Written};
use crate::population::{
    self, How, OFFICE_ADDRESS, Off, Offs, PersonPlan, Population, Rng, Session, Stage,
};
use crate::removal;
use crate::steps::{Act, Steps, Timing};

/// What a run is to do.
#[derive(Debug, Clone)]
pub struct Plan {
    pub stage: Stage,
    pub seed: u64,
    pub relays: usize,
    pub timing: Timing,
    pub population: Population,
    pub offs: Offs,
    /// Section 6's test 5: a device of this person stopped this many
    /// seconds into the window, and not started again.
    pub stopped_for_good: Option<(usize, f64)>,
    /// The threshold of bar 6 from stage 100, in MiB an hour, where it is
    /// given (`CORDELIA_SCALE_DEVICE_GROWTH`).
    pub device_growth: Option<f64>,
}

impl Plan {
    /// A stage of §2.2, as the record runs it.
    pub fn of_a_stage(stage: Stage, seed: u64, relays: usize) -> Plan {
        Plan {
            stage,
            seed,
            relays,
            timing: Timing::of_a_stage(),
            population: Population::of(stage, seed, relays),
            offs: Offs::Drawn,
            stopped_for_good: None,
            device_growth: None,
        }
    }

    /// Section 6's test 4: two relays and seven devices of three people,
    /// one device off and on, the second relay stopped and started, churn
    /// every two minutes, and one removal.
    pub fn small(seed: u64) -> Plan {
        let mut plan = Plan::of_a_stage(Stage::Small, seed, 2);
        plan.timing = Timing::of_the_small_run();
        plan.offs = Offs::Fixed(vec![Off {
            person: 0,
            device: 1,
            start: 300.0,
            end: 450.0,
            how: How::Stop,
        }]);
        plan
    }

    /// Section 6's test 5: the small run, where one device of a casual
    /// person is stopped in the middle of the window and not started
    /// again: the person split between the relays, or else the other, as
    /// the seed's plan gives one of them an edit after it, 20 s after the
    /// stop. `None` where the seed gives neither such an edit.
    pub fn small_that_fails(seed: u64) -> Option<Plan> {
        let mut plan = Plan::small(seed);
        let at = [2, 0].into_iter().find_map(|k| {
            let person = &plan.population.people[k];
            let mut first =
                PersonPlan::new(person, seed, plan.timing.first_files, &plan.offs).next_session();
            first.edits.retain(|e| (170.0..420.0).contains(&e.at));
            first.edits.first().map(|e| (k, e.at - 20.0))
        })?;
        plan.stopped_for_good = Some(at);
        Some(plan)
    }
}

/// A removal, as it went (bar 10).
#[derive(Debug, Clone, Default)]
pub struct Removal {
    pub person: usize,
    pub remover: usize,
    pub removed: usize,
    /// When "The change is made (change N)" was read, and N.
    pub line_at: Option<f64>,
    pub change: Option<u64>,
    /// When each other remaining device applied it.
    pub applied: Vec<(usize, Option<f64>)>,
    /// When each relay was said to hold it.
    pub relays_hold: Vec<(String, Option<f64>)>,
    /// When the carry ended: every remaining device said that each had
    /// applied the change and sent what it held, and had nothing to send.
    pub carry_end: Option<f64>,
    /// The bytes of the largest carry, as entries are counted, and the
    /// bound on the carry window that follows (bar 10b).
    pub carried_bytes: u64,
    pub bound: f64,
    pub command_ended: Option<(f64, bool)>,
    pub failed: Option<String>,
}

/// The second relay's outage.
#[derive(Debug, Clone, Default)]
pub struct Outage {
    pub stopped: Option<f64>,
    pub started: Option<f64>,
    /// When each device set up with it was connected to it again.
    pub back: Vec<(usize, Option<f64>)>,
}

/// The setup, as it went (step 3).
#[derive(Debug, Clone, Default)]
pub struct Setup {
    pub started: f64,
    pub ended: f64,
    pub office_moved: Option<(f64, bool)>,
    pub thread_plan: String,
    pub machine: String,
}

/// Everything a run keeps, shared by its threads.
pub struct Run {
    pub plan: Plan,
    pub out: PathBuf,
    pub fleet: Arc<Fleet>,
    pub relay_addrs: Vec<SocketAddr>,
    pub relay_keys: Vec<String>,
    pub samples: Arc<Mutex<Samples>>,
    pub observer: Arc<Mutex<Observer>>,
    pub plans: Mutex<Vec<PersonPlan>>,
    pub sessions: Mutex<Vec<Session>>,
    /// Times off as they went: the plan's, and when each began and ended.
    pub offs: Mutex<Vec<(Off, f64, Option<f64>)>>,
    pub busy: Mutex<HashSet<usize>>,
    /// Devices removed, or stopped for good: nothing is done to them.
    pub gone: Mutex<HashSet<(usize, usize)>>,
    /// Devices removed from their person (step 8).
    pub removed: Mutex<HashSet<(usize, usize)>>,
    pub stopped_for_good: Mutex<Option<(usize, usize, f64)>>,
    pub words: Mutex<HashMap<usize, String>>,
    pub folders: HashMap<(usize, usize, usize), PathBuf>,
    pub next_edit: AtomicU64,
    pub window: Mutex<Option<(f64, Option<f64>)>>,
    pub cut: AtomicBool,
    ended: AtomicBool,
    pub removals: Mutex<Vec<Removal>>,
    /// How many removals step 8 planned.
    pub removals_planned: Mutex<usize>,
    pub outage: Mutex<Outage>,
    pub setup: Mutex<Setup>,
    /// Each relay that did not answer a read, since its first such read.
    pub last_answer: Mutex<HashMap<usize, f64>>,
    pub steps: Mutex<Option<Steps>>,
    /// Each relay's peers' keys at the end: whether every one is of the run.
    pub peers_at_end: Mutex<Vec<(usize, Vec<String>)>>,
    pub stops_at_end: Mutex<Vec<(usize, f64, bool)>>,
    pub pids_left: Mutex<Vec<u32>>,
    pub stopped_why: Mutex<Option<String>>,
}

/// What a panic in a thread said.
fn said_by(panic: Box<dyn std::any::Any + Send>) -> String {
    match panic.downcast::<String>() {
        Ok(s) => *s,
        Err(panic) => panic
            .downcast::<&str>()
            .map(|s| s.to_string())
            .unwrap_or_else(|_| "a panic".into()),
    }
}

/// Sleep for `secs`, or less where the run is to stop early.
fn sleep_for(fleet: &Fleet, secs: f64) {
    let until = fleet.clock.now() + secs;
    while fleet.clock.now() < until && !fleet.stop_early.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100).min(Duration::from_secs_f64(secs.max(0.0))));
    }
}

/// Wait up to `secs` for `check`, each call of which is bounded (every
/// request the harness makes in a wait goes through [`fleet::agent`]):
/// `Err` with what was waited for, where the time runs out.
fn wait_within<T>(
    what: &str,
    secs: u64,
    mut check: impl FnMut() -> Option<T>,
) -> Result<T, String> {
    let until = std::time::Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = check() {
            return Ok(v);
        }
        if std::time::Instant::now() > until {
            return Err(format!("waited {secs} s for: {what}"));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// A node's status, read within a bound.
fn status_of(made: &Made) -> Option<serde_json::Value> {
    let text = fleet::get_text(
        &fleet::agent(),
        made.node.http,
        &made.token,
        "/api/v1/status",
    )?;
    serde_json::from_str(&text).ok()
}

/// Whether the node answers, and is not in the middle of the copy of its
/// first start, read within a bound (as `common::healthy` reads it, with
/// no bound).
fn healthy(made: &Made) -> Option<()> {
    let status = status_of(made)?;
    let under_way = status["held"]["why"]
        .as_str()
        .is_some_and(|why| why.contains("is under way"));
    (!under_way).then_some(())
}

/// A CLI command against `node`, given `secs` to end, and killed then:
/// what it wrote to its output, where it ended with success.
fn cli_within(node: &Node, args: &[&str], secs: u64) -> Result<String, String> {
    let mut child = node
        .command_for(&[], args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: cordelia {args:?}: {e}", node.name))?;
    let until = std::time::Instant::now() + Duration::from_secs(secs);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{}: cordelia {args:?} did not end in {secs} s",
                    node.name
                ));
            }
        }
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    match out.status.success() {
        true => Ok(said),
        false => Err(format!(
            "{}: cordelia {args:?} failed: {said}{}",
            node.name,
            String::from_utf8_lossy(&out.stderr)
        )),
    }
}

/// The labels of a person's devices, as `cordelia add-device` names them.
const LABELS: [&str; 3] = ["desktop", "laptop", "tablet"];

/// The device's node name.
fn device_label(person: usize, device: usize) -> String {
    format!("p{person:03}-d{device}")
}

/// Step 1: what is checked before anything starts. Refused with why.
pub fn before_anything(plan: &Plan, out: &Path) -> Result<(ThreadPlan, String), String> {
    machine::check_earlier_pids(&out.join("pids"))?;
    let devices = plan.population.devices() as u64;
    let (threads, said) = machine::plan_threads(
        &machine::read_limits(),
        plan.relays as u64,
        devices,
        machine::cores(),
    );
    if let ThreadPlan::Refused(why) = &threads {
        return Err(why.clone());
    }
    // Memory: 30 MiB for each device and bar 7 for each relay (§2.4), and
    // the 2 GiB a run needs available (§6, rule 5).
    let need_kib = devices * 30 * 1024 + plan.relays as u64 * 256 * 1024 + 2 * 1024 * 1024;
    let available = machine::meminfo("MemAvailable").unwrap_or(0);
    if available < need_kib {
        return Err(format!(
            "memory available is {} MiB; the run needs {} MiB",
            available / 1024,
            need_kib / 1024
        ));
    }
    // Disk: about 100 MiB for each node with its log, and 1 GiB more.
    let need = (devices + plan.relays as u64) * 100 * 1024 * 1024 + (1 << 30);
    let free = machine::disk_free(out).unwrap_or(0);
    if free < need {
        return Err(format!(
            "the disk has {} MiB free; the run needs {} MiB",
            free >> 20,
            need >> 20
        ));
    }
    Ok((threads, said))
}

/// Make every node of the run: configurations written and checked,
/// `init` run, and the relays listed to each other by address and key.
/// Nothing is started.
fn make_the_nodes(plan: &Plan, out: &Path, fleet: &mut Fleet, masked: bool) -> Result<(), String> {
    let nodes = out.join("nodes");
    let mut relay_settings = Vec::new();
    for r in 0..plan.relays {
        let (http, mut p2p) = (common::free_port(), common::free_port());
        while p2p == http {
            p2p = common::free_port();
        }
        relay_settings.push(Settings {
            name: format!("relay{}", r + 1),
            role: Role::Relay,
            http,
            p2p,
            listen: IpAddr::V4(RELAY_ADDRESS),
            relays: Vec::new(),
            churn_secs: plan.timing.churn_secs,
            data_dir: PathBuf::new(),
        });
    }
    let mut relays = Vec::new();
    for settings in &relay_settings {
        relays.push(fleet::make(&nodes, settings)?);
    }
    let addrs: Vec<SocketAddr> = relay_settings
        .iter()
        .map(|s| SocketAddr::new(IpAddr::V4(RELAY_ADDRESS), s.p2p))
        .collect();
    for (r, (node, key, key_hex, token)) in relays.into_iter().enumerate() {
        let mut settings = relay_settings[r].clone();
        settings.data_dir = node.data_dir();
        fleet.add(Made {
            node,
            what: What::Relay(r),
            label: settings.name.clone(),
            key,
            key_hex,
            token,
            settings: Mutex::new(settings),
            mask: None,
        });
    }
    // The relays' keys are known only once each is made: each lists the
    // other, by address and by key, from now (rule 3 of §2.2).
    let keys: Vec<String> = fleet
        .relays
        .iter()
        .map(|i| fleet.made[*i].key.clone())
        .collect();
    for (r, i) in fleet.relays.clone().into_iter().enumerate() {
        let mut settings = fleet.made[i].settings.lock().unwrap().clone();
        settings.relays = (0..plan.relays)
            .filter(|o| *o != r)
            .map(|o| (addrs[o], keys[o].clone()))
            .collect();
        settings.check()?;
        std::fs::write(fleet.made[i].node.config(), settings.render())
            .map_err(|e| e.to_string())?;
        crate::configs::check_written(&fleet.made[i].node.config())?;
        *fleet.made[i].settings.lock().unwrap() = settings;
    }
    let cores = machine::cores();
    let mut n = 0u64;
    for person in &plan.population.people {
        for d in 0..person.devices {
            let (http, mut p2p) = (common::free_port(), common::free_port());
            while p2p == http {
                p2p = common::free_port();
            }
            let settings = Settings {
                name: device_label(person.index, d),
                role: Role::Device,
                http,
                p2p,
                listen: IpAddr::V4(person.address),
                relays: person
                    .relays_of(d, plan.relays)
                    .into_iter()
                    .map(|r| (addrs[r], keys[r].clone()))
                    .collect(),
                churn_secs: None,
                data_dir: PathBuf::new(),
            };
            let (node, key, key_hex, token) = fleet::make(&nodes, &settings)?;
            let mut settings = settings;
            settings.data_dir = node.data_dir();
            // A mask of four cores, spread over the machine's.
            let mask = masked.then(|| {
                let first = (n * machine::MASK_CORES) % cores.max(1);
                (0..machine::MASK_CORES.min(cores))
                    .map(|c| ((first + c) % cores).to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            });
            n += 1;
            fleet.add(Made {
                node,
                what: What::Device {
                    person: person.index,
                    device: d,
                },
                label: settings.name.clone(),
                key,
                key_hex,
                token,
                settings: Mutex::new(settings),
                mask,
            });
        }
    }
    Ok(())
}

/// The memory folders of every device, by (person, device, name).
fn folders_of(plan: &Plan, fleet: &Fleet) -> HashMap<(usize, usize, usize), PathBuf> {
    let mut folders = HashMap::new();
    for person in &plan.population.people {
        for d in 0..person.devices {
            let node = &fleet.made[fleet.device(person.index, d)].node;
            for k in 0..person.profile.names() {
                folders.insert(
                    (person.index, d, k),
                    fleet::memory_folder(node, &population::name_of(k)),
                );
            }
        }
    }
    folders
}

impl Run {
    fn node(&self, person: usize, device: usize) -> &Node {
        &self.fleet.made[self.fleet.device(person, device)].node
    }

    fn now(&self) -> f64 {
        self.fleet.clock.now()
    }

    /// The relay's every counter, read now.
    fn relay_metrics(&self, r: usize) -> Option<HashMap<String, f64>> {
        let made = &self.fleet.made[self.fleet.relays[r]];
        let text = fleet::get_text(
            &fleet::agent(),
            made.node.http,
            &made.token,
            "/api/v1/metrics/load",
        )?;
        Some(fleet::parse_metrics(&text))
    }

    fn sample_now(&self, i: usize) {
        if let Some(s) = fleet::sample(&self.fleet, &fleet::agent(), i, false, &self.relay_keys) {
            self.samples.lock().unwrap().add(&self.fleet, s);
        }
    }

    /// A sample of every node that runs, the relays first.
    fn sample_every_node(&self) {
        for i in 0..self.fleet.made.len() {
            self.sample_now(i);
        }
    }

    /// Stop node `i`, with a sample just before, so that what it counted
    /// up to then is kept.
    fn stop_node(&self, i: usize) -> Option<(f64, bool)> {
        self.sample_now(i);
        self.fleet.stop(i)
    }

    fn start_node(&self, i: usize) {
        if let Err(why) = self.fleet.start(i, &self.relay_addrs) {
            self.fleet.fault(why);
        }
    }

    /// Wait until the device's node answers, and is connected to each
    /// relay it is set up with.
    fn wait_connected(&self, person: usize, device: usize, secs: u64) -> Result<(), String> {
        let made = &self.fleet.made[self.fleet.device(person, device)];
        let relays = self.plan.population.people[person]
            .relays_of(device, self.plan.relays)
            .len() as u64;
        wait_within(&format!("{} answers", made.label), secs, || healthy(made))?;
        wait_within(&format!("{} reaches its relays", made.label), secs, || {
            let status = status_of(made)?;
            (status["peers_hot"].as_u64()? >= relays).then_some(())
        })
    }

    /// Step 3, for one person: devices started, the phrase, each other
    /// device added, names mapped, the first files written, and every
    /// device holding every file.
    fn set_up(&self, k: usize) {
        let person = self.plan.population.people[k].clone();
        for d in 0..person.devices {
            self.start_node(self.fleet.device(k, d));
        }
        for d in 0..person.devices {
            self.wait_connected(k, d, 120)
                .unwrap_or_else(|why| panic!("{why}"));
        }
        let mut words = None;
        for (d, label) in LABELS.iter().enumerate().take(person.devices).skip(1) {
            let made = self
                .pair_within(k, d, label)
                .unwrap_or_else(|why| panic!("{why}"));
            words = words.or(made);
        }
        let words = words.expect("the first device made the phrase");
        self.words.lock().unwrap().insert(k, words);
        for d in 0..person.devices {
            let node = self.node(k, d);
            let claude = node.home().join(".claude");
            let out = cli_within(
                node,
                &["sync", "claude", "--dir", claude.to_str().unwrap()],
                60,
            )
            .unwrap_or_else(|why| panic!("{why}"));
            assert!(out.starts_with("Sync turned on."), "{}: {out}", node.name);
            for n in 0..person.profile.names() {
                let name = population::name_of(n);
                let folder = node.home().join(&name);
                std::fs::create_dir_all(&folder).unwrap();
                common::claude_folder(&node.home(), &folder);
                cli_within(node, &["sync", "map", folder.to_str().unwrap(), &name], 60)
                    .unwrap_or_else(|why| panic!("{why}"));
            }
        }
        // The first files, 10 in each name at the profile's sizes.
        let mut rng = Rng::of(self.plan.seed, &format!("person {k}/first files"));
        let (lo, hi) = person.profile.sizes();
        let mut wanted = Vec::new();
        for n in 0..person.profile.names() {
            for f in 0..self.plan.timing.first_files {
                let number = self.next_edit.fetch_add(1, Ordering::SeqCst);
                let size = rng.log_between(lo, hi);
                let file = population::first_file(f);
                let folder = &self.folders[&(k, 0, n)];
                std::fs::write(folder.join(&file), observer::text_of(number, size, number))
                    .unwrap();
                wanted.push((n, file.clone(), number));
                self.observer.lock().unwrap().edits.push(Written {
                    number,
                    person: k,
                    writer: 0,
                    name: n,
                    file,
                    size,
                    at: self.now(),
                    burst: false,
                    new: true,
                    replaced: None,
                });
            }
        }
        wait_within(
            "every device of the person holds every first file",
            1800,
            || {
                let held = (1..person.devices).all(|d| {
                    wanted.iter().all(|(n, file, number)| {
                        observer::first_line(&self.folders[&(k, d, *n)].join(file)).as_deref()
                            == Some(observer::line_of(*number).as_str())
                    })
                });
                held.then_some(())
            },
        )
        .unwrap_or_else(|why| panic!("{why}"));
    }

    /// Make device `d` a device of person `k`, as `common::pair` does it: a
    /// phrase on the first device where it follows none, then `add-device`
    /// there and `accept` here, each at a terminal with its yes; then until
    /// the new device has applied the change. Every read of a node is
    /// within a bound. The words, where the phrase was made here.
    fn pair_within(&self, k: usize, d: usize, label: &str) -> Result<Option<String>, String> {
        let first = &self.fleet.made[self.fleet.device(k, 0)];
        let new = &self.fleet.made[self.fleet.device(k, d)];
        let seen = |m: &Made| {
            fleet::post_json(
                m.node.http,
                &m.token,
                "/api/v1/devices/list",
                &serde_json::json!({}),
            )
        };
        let state =
            seen(first).ok_or_else(|| format!("{}: its person was not read", first.label))?;
        let words =
            (state["state"] == "no_phrase").then(|| common::makes_a_phrase(&first.node, "desktop"));
        let mut at = first
            .node
            .at_terminal(&["add-device", &new.key, "--name", label]);
        at.says("Type yes to go on").types("yes");
        let added = at.done();
        let accept = added
            .lines()
            .find_map(|line| line.trim().strip_prefix("cordelia accept "))
            .map(|key| key.trim().to_string())
            .ok_or_else(|| format!("add-device printed no accept line:\n{added}"))?;
        if accept != first.key {
            return Err(format!("add-device named {accept}, not {}", first.key));
        }
        let mut at = new.node.at_terminal(&["accept", &accept]);
        at.says("Type yes to go on").types("yes");
        let accepted = at.done();
        if accepted.contains("Nothing was taken yet") {
            wait_within(
                "a hand-over is read with the key typed at accept",
                600,
                || {
                    let seen = seen(new)?;
                    let typed = seen["accepting"]
                        .as_array()?
                        .iter()
                        .find(|typed| typed["key"] == accept.as_str())?
                        .clone();
                    let said = typed["said"].as_str().is_some_and(|said| !said.is_empty());
                    (typed["taken"] == true || said).then_some(())
                },
            )?;
        }
        let change = seen(first)
            .and_then(|s| s["change"].as_u64())
            .ok_or_else(|| format!("{}: no change applied", first.label))?;
        wait_within(
            &format!("{} applies change {change}", new.label),
            90,
            || (seen(new)?["change"].as_u64() == Some(change)).then_some(()),
        )?;
        Ok(words)
    }

    /// Step 4: the office's devices stopped, given its one address, and
    /// started again in the seed's order; then until each relay holds 5
    /// connections from it, or two minutes.
    fn move_the_office(&self) -> bool {
        let order = self.plan.population.office_order.clone();
        if order.is_empty() {
            return true;
        }
        for (k, d) in &order {
            let i = self.fleet.device(*k, *d);
            self.stop_node(i);
            let made = &self.fleet.made[i];
            let mut settings = made.settings.lock().unwrap();
            settings.listen = IpAddr::V4(OFFICE_ADDRESS);
            if let Err(why) = settings.check() {
                self.fleet.fault(why);
                return false;
            }
            std::fs::write(made.node.config(), settings.render()).unwrap();
        }
        for (k, d) in &order {
            self.start_node(self.fleet.device(*k, *d));
        }
        let until = self.now() + 120.0;
        while self.now() < until {
            let five = (0..self.plan.relays).all(|r| {
                self.office_connections(r)
                    .is_some_and(|n| n >= cordelia_core::protocol::MAX_CONNECTIONS_PER_IP)
            });
            if five {
                return true;
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        false
    }

    /// The connections relay `r` holds from the office's address.
    fn office_connections(&self, r: usize) -> Option<usize> {
        let made = &self.fleet.made[self.fleet.relays[r]];
        let text = fleet::get_text(
            &fleet::agent(),
            made.node.http,
            &made.token,
            "/api/v1/peers",
        )?;
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        Some(
            v["peers"]
                .as_array()?
                .iter()
                .filter(|p| {
                    p["address"]
                        .as_str()
                        .and_then(fleet::ip_of)
                        .is_some_and(|ip| ip == IpAddr::V4(OFFICE_ADDRESS))
                })
                .count(),
        )
    }

    /// The keys a relay holds connections from.
    fn peers_of(&self, r: usize) -> Option<Vec<String>> {
        let made = &self.fleet.made[self.fleet.relays[r]];
        let text = fleet::get_text(
            &fleet::agent(),
            made.node.http,
            &made.token,
            "/api/v1/peers",
        )?;
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        Some(
            v["peers"]
                .as_array()?
                .iter()
                .filter_map(|p| p["key"].as_str().map(str::to_string))
                .collect(),
        )
    }

    /// One edit, written as an editor writes a file: the whole file at
    /// once. The edit whose line began the file before is the one it
    /// replaced.
    fn write(&self, planned: &population::Planned) {
        let number = self.next_edit.fetch_add(1, Ordering::SeqCst);
        let folder = &self.folders[&(planned.person, planned.device, planned.name)];
        let path = folder.join(&planned.file);
        let replaced = observer::first_line(&path).and_then(|l| observer::edit_of(&l));
        if let Err(e) = std::fs::write(&path, observer::text_of(number, planned.size, number)) {
            self.fleet.fault(format!(
                "an edit was not written at {}: {e}",
                path.display()
            ));
            return;
        }
        let at = self.now();
        let person = &self.plan.population.people[planned.person];
        // A device that was removed is the person's no longer; one stopped
        // for good (test 5) still is, and is waited for.
        let removed = self.removed.lock().unwrap().clone();
        let others: Vec<(usize, PathBuf)> = (0..person.devices)
            .filter(|d| *d != planned.device && !removed.contains(&(planned.person, *d)))
            .map(|d| (d, self.folders[&(planned.person, d, planned.name)].clone()))
            .collect();
        self.observer.lock().unwrap().wrote(
            Written {
                number,
                person: planned.person,
                writer: planned.device,
                name: planned.name,
                file: planned.file.clone(),
                size: planned.size,
                at,
                burst: planned.burst,
                new: planned.new,
                replaced,
            },
            others,
        );
    }

    /// The thread of edits (step 6): every person's edits at their times,
    /// a session at a time; the times off of each session are handed to
    /// the thread that turns devices off and on.
    fn edits(self: &Arc<Self>, start: f64, queue: Arc<Mutex<Vec<(f64, bool, Off)>>>) {
        let people = self.plan.population.people.len();
        let mut current: Vec<std::collections::VecDeque<population::Planned>> =
            vec![Default::default(); people];
        while !self.ended.load(Ordering::SeqCst) && !self.fleet.stop_early.load(Ordering::SeqCst) {
            let now = self.now() - start;
            for (k, queued) in current.iter_mut().enumerate() {
                // The plan's own end of the session under way: a removal can
                // end it early.
                let end = self.plans.lock().unwrap()[k].session_end();
                if now + 5.0 >= end {
                    let next = self.plans.lock().unwrap()[k].next_session();
                    self.sessions.lock().unwrap().push(Session {
                        start: next.session.start + start,
                        end: next.session.end + start,
                        ..next.session
                    });
                    queued.extend(next.edits);
                    let mut queue = queue.lock().unwrap();
                    for off in next.offs {
                        queue.push((off.start, true, off));
                        queue.push((off.end, false, off));
                    }
                }
                while queued.front().is_some_and(|e| e.at <= now) {
                    let planned = queued.pop_front().unwrap();
                    if self.gone.lock().unwrap().contains(&(k, planned.device)) {
                        continue;
                    }
                    self.write(&planned);
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The thread that turns devices off and on (step 6; §2.1, item 4).
    fn offs(self: &Arc<Self>, start: f64, queue: Arc<Mutex<Vec<(f64, bool, Off)>>>) {
        let mut skipped: Vec<Off> = Vec::new();
        while !self.ended.load(Ordering::SeqCst) && !self.fleet.stop_early.load(Ordering::SeqCst) {
            let now = self.now() - start;
            let due: Vec<(f64, bool, Off)> = {
                let mut queue = queue.lock().unwrap();
                queue.sort_by(|a, b| a.0.total_cmp(&b.0));
                let n = queue.iter().take_while(|e| e.0 <= now).count();
                queue.drain(..n).collect()
            };
            for (_, goes_off, off) in due {
                let i = self.fleet.device(off.person, off.device);
                let gone = self
                    .gone
                    .lock()
                    .unwrap()
                    .contains(&(off.person, off.device));
                if goes_off {
                    let busy = self.busy.lock().unwrap().contains(&off.person);
                    if gone || busy || self.fleet.is(i).0 != Is::Running {
                        skipped.push(off);
                        continue;
                    }
                    let at = self.now();
                    match off.how {
                        How::Stop => {
                            self.stop_node(i);
                        }
                        How::Freeze => {
                            self.sample_now(i);
                            self.fleet.freeze(i, true);
                        }
                    }
                    self.offs.lock().unwrap().push((off, at, None));
                } else {
                    if skipped.contains(&off) || gone {
                        continue;
                    }
                    self.turn_on(i, off.how);
                    let at = self.now();
                    if let Some(o) = self
                        .offs
                        .lock()
                        .unwrap()
                        .iter_mut()
                        .rev()
                        .find(|(o, _, end)| *o == off && end.is_none())
                    {
                        o.2 = Some(at);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn turn_on(&self, i: usize, how: How) {
        match (how, self.fleet.is(i).0) {
            (_, Is::Frozen) => self.fleet.freeze(i, false),
            (_, Is::Stopped) => self.start_node(i),
            _ => {}
        }
    }

    /// The thread that samples every process once in each `sample_every`,
    /// spread over it (§1.2; step 6), and looks for faults (§4.3, rule 5).
    fn sampler(self: &Arc<Self>, done: Arc<AtomicBool>) {
        let agent = fleet::agent();
        let every = self.plan.timing.sample_every;
        let mut next_room = 0.0;
        while !done.load(Ordering::SeqCst) {
            let round = self.now();
            let room = round >= next_room;
            if room {
                next_room = round + self.plan.timing.room_every;
            }
            let n = self.fleet.made.len().max(1);
            for i in 0..self.fleet.made.len() {
                if done.load(Ordering::SeqCst) {
                    return;
                }
                if let Some(why) = self.fleet.exited_untold(i) {
                    self.fleet.fault(why);
                }
                let mut answered = false;
                if let Some(s) = fleet::sample(&self.fleet, &agent, i, room, &self.relay_keys) {
                    answered = s.metrics.is_some() || s.device.is_some();
                    self.samples.lock().unwrap().add(&self.fleet, s);
                }
                // A relay that does not answer for a minute, outside step 7:
                // from the first read it did not answer, through every read
                // after it until one answers.
                if let What::Relay(_) = self.fleet.made[i].what {
                    let (is, since) = self.fleet.is(i);
                    // One being stopped has no pid for that while.
                    let stopping = self.fleet.pid(i).is_none();
                    let mut failing = self.last_answer.lock().unwrap();
                    match (answered, is == Is::Running && !stopping) {
                        (true, _) | (false, false) => {
                            failing.remove(&i);
                        }
                        (false, true) => {
                            let first = *failing.entry(i).or_insert(self.now().max(since));
                            if self.now() - first >= 60.0 {
                                self.fleet.fault(format!(
                                    "{} did not answer for a minute",
                                    self.fleet.made[i].label
                                ));
                            }
                        }
                    }
                }
                let at = round + every * (i + 1) as f64 / n as f64 * 0.8;
                let wait = at - self.now();
                if wait > 0.0 {
                    std::thread::sleep(Duration::from_secs_f64(wait.min(every)));
                }
            }
            let read = machine::read_machine(&self.out);
            if read.mem_available_kib > 0 && read.mem_available_kib < 2 * 1024 * 1024 {
                self.fleet.fault(format!(
                    "the machine's memory available fell to {} MiB, under 2 GiB",
                    read.mem_available_kib / 1024
                ));
                *self.stopped_why.lock().unwrap() =
                    Some("the machine's memory available fell under 2 GiB".into());
            }
            self.samples
                .lock()
                .unwrap()
                .add_machine(fleet::MachineSample {
                    t: self.now(),
                    read,
                });
            let wait = round + every - self.now();
            if wait > 0.0 {
                let until = self.now() + wait;
                while self.now() < until && !done.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    /// The people with three devices who are not in the office, a tenth of
    /// them chosen by the seed, at least one (step 8).
    fn to_remove(&self) -> Vec<usize> {
        let mut three: Vec<usize> = self
            .plan
            .population
            .people
            .iter()
            .filter(|p| p.devices == 3 && !p.office)
            .map(|p| p.index)
            .collect();
        Rng::of(self.plan.seed, "removals").shuffle(&mut three);
        let n = ((three.len() as f64) / 10.0).round().max(1.0) as usize;
        three.truncate(n.min(three.len()));
        three
    }

    /// One removal (step 8; bar 10): `cordelia remove-device` at a
    /// terminal with the phrase, its line timestamped, the removed device
    /// stopped for good, and the spread and the carry read.
    ///
    /// The seed alone chooses the device removed, among those added (not
    /// the first, which made the phrase); the first removes it, as it is in
    /// every change. Where the device removed is the active one, its
    /// session ends at the line, and the next is drawn among the others.
    fn remove(self: &Arc<Self>, k: usize) {
        self.busy.lock().unwrap().insert(k);
        let mut removal = Removal {
            person: k,
            ..Removal::default()
        };
        let person = self.plan.population.people[k].clone();
        let removed =
            1 + Rng::of(self.plan.seed, &format!("removal {k}")).below(person.devices - 1);
        let remover = 0;
        removal.remover = remover;
        removal.removed = removed;
        let remaining: Vec<usize> = (0..person.devices).filter(|d| *d != removed).collect();
        // The remaining devices are on for the removal and its carry; the
        // one removed is left as it is.
        for d in &remaining {
            self.turn_on(self.fleet.device(k, *d), How::Stop);
        }
        for d in &remaining {
            if let Err(why) = self.wait_connected(k, *d, 120) {
                removal.failed = Some(why);
            }
        }
        removal.carried_bytes = self.carried_bytes(k);
        removal.bound = 60.0 * removal.carried_bytes as f64 / 1_572_864.0 + 60.0;
        let words = self
            .words
            .lock()
            .unwrap()
            .get(&k)
            .cloned()
            .unwrap_or_default();
        let key = self.fleet.made[self.fleet.device(k, removed)].key.clone();
        let mut at = self.node(k, remover).at_terminal(&["remove-device", &key]);
        let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            loop {
                // Of each other device added since the last change: it
                // stays. Of the remover, where it was added since (it is
                // not, being the first device): it is listed, in the words
                // of either version of the prompt.
                let which = at.says_one_of(&[
                    "Type `stays` or `removed`",
                    "Type `list` to list this machine",
                    "Type `stays` to list this device",
                    "Make this change?",
                ]);
                match which {
                    0 | 2 => at.types("stays"),
                    1 => at.types("list"),
                    _ => break,
                };
            }
            at.says("Type yes to go on").types("yes");
            at.says(common::ASKS_THE_PHRASE).types(&words);
            at.says("The change is made (change ");
        }));
        if let Err(e) = ran {
            removal.failed = Some(said_by(e));
            self.removals.lock().unwrap().push(removal);
            self.busy.lock().unwrap().remove(&k);
            return;
        }
        let line_at = self.now();
        removal.line_at = Some(line_at);
        removal.change = at
            .said
            .rsplit("The change is made (change ")
            .next()
            .and_then(|rest| rest.split(')').next())
            .and_then(|n| n.trim().parse().ok());
        // The removed device is the person's no longer, and is stopped for
        // good. What it had no chance at is waited for no more.
        let i_removed = self.fleet.device(k, removed);
        let up = match self.fleet.is(i_removed) {
            (Is::Running, since) => Some(since),
            _ => None,
        };
        self.removed.lock().unwrap().insert((k, removed));
        self.gone.lock().unwrap().insert((k, removed));
        self.plans.lock().unwrap()[k].remove(removed, line_at - self.window_start());
        self.observer.lock().unwrap().gone(k, removed, line_at, up);
        self.stop_node(i_removed);
        let index = {
            let mut removals = self.removals.lock().unwrap();
            removals.push(removal.clone());
            removals.len() - 1
        };
        // The command stays until its relays hold the change and it has
        // sent what it carried: it is read to its end in a thread.
        let bound = removal.bound.max(600.0) + 300.0;
        let ended = std::thread::spawn(move || {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                at.ends_within(Duration::from_secs_f64(bound))
            }));
            r.map(|(ok, _)| ok).unwrap_or(false)
        });
        let change = removal.change.unwrap_or(0);
        let mut applied: HashMap<usize, f64> = HashMap::new();
        let mut holds: HashMap<String, f64> = HashMap::new();
        let mut carry_end = None;
        let keys: HashMap<usize, String> = remaining
            .iter()
            .map(|d| (*d, self.fleet.made[self.fleet.device(k, *d)].key.clone()))
            .collect();
        // What each remaining device holds at the line: what it carries.
        let mut carried: HashMap<usize, removal::Held> = HashMap::new();
        let mut last_look = f64::MIN;
        let until = line_at + bound;
        while self.now() < until
            && carry_end.is_none()
            && !self.fleet.stop_early.load(Ordering::SeqCst)
        {
            for d in &remaining {
                if !carried.contains_key(d)
                    && let Some(held) = self.entries_of(k, *d)
                {
                    carried.insert(*d, held);
                }
            }
            let seen: Vec<(usize, serde_json::Value)> = remaining
                .iter()
                .filter_map(|d| Some((*d, self.person_seen_by(k, *d)?)))
                .collect();
            let round = removal::read_round(change, &remaining, &seen, &keys);
            let now = self.now();
            for d in &round.applied {
                applied.entry(*d).or_insert(now);
            }
            for relay in &round.holding {
                holds.entry(relay.clone()).or_insert(now);
            }
            // Once every device has sent what it carried, each must hold
            // the versions the others carried, read from it (every 2 s).
            if round.settled && carried.len() == remaining.len() && now - last_look >= 2.0 {
                last_look = now;
                let all = remaining.iter().all(|d| {
                    self.entries_of(k, *d)
                        .is_some_and(|held| removal::holds_what_was_carried(*d, &held, &carried))
                });
                if all {
                    carry_end = Some(self.now());
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        let command_ended = ended.join().unwrap_or(false);
        let mut removals = self.removals.lock().unwrap();
        let r = &mut removals[index];
        // Of each other remaining device: the remover applies at once.
        r.applied = remaining
            .iter()
            .filter(|d| **d != remover)
            .map(|d| (*d, applied.get(d).copied()))
            .collect();
        r.relays_hold = self
            .relay_addrs
            .iter()
            .map(|a| {
                let name = a.to_string();
                let at = holds.get(&name).copied();
                (name, at)
            })
            .collect();
        r.carry_end = carry_end;
        r.command_ended = Some((self.now(), command_ended));
        drop(removals);
        self.busy.lock().unwrap().remove(&k);
    }

    /// When the window began, in seconds of the run.
    fn window_start(&self) -> f64 {
        self.window.lock().unwrap().map_or(0.0, |(start, _)| start)
    }

    /// What device `d` of person `k` holds of each of the person's names,
    /// each request within a bound; `None` where any is not read.
    fn entries_of(&self, k: usize, d: usize) -> Option<removal::Held> {
        let made = &self.fleet.made[self.fleet.device(k, d)];
        let mut held = removal::Held::new();
        for n in 0..self.plan.population.people[k].profile.names() {
            let name = population::name_of(n);
            let answer = fleet::post_json(
                made.node.http,
                &made.token,
                "/api/v1/channels/entries",
                &serde_json::json!({ "channel": name }),
            )?;
            removal::read_entries(&name, &answer, &mut held);
        }
        Some(held)
    }

    /// What device `d` of person `k` says of its person (`POST
    /// /api/v1/devices/list`, as `cordelia devices --json` asks), within a
    /// bound.
    fn person_seen_by(&self, k: usize, d: usize) -> Option<serde_json::Value> {
        let made = &self.fleet.made[self.fleet.device(k, d)];
        let seen = fleet::post_json(
            made.node.http,
            &made.token,
            "/api/v1/devices/list",
            &serde_json::json!({}),
        )?;
        seen.is_object().then_some(seen)
    }

    /// The bytes, as entries are counted, of what one device of person `k`
    /// carries: every current version of every name it holds (bar 10b).
    pub fn carried_bytes(&self, k: usize) -> u64 {
        let observer = self.observer.lock().unwrap();
        let mut latest: HashMap<(usize, String), usize> = HashMap::new();
        for e in observer.edits.iter().filter(|e| e.person == k) {
            latest.insert((e.name, e.file.clone()), e.size);
        }
        latest
            .iter()
            .map(|((_, file), size)| crate::report::entry_cost_of(file, *size))
            .sum()
    }

    /// Step 7: the second relay's outage.
    fn stop_second(&self) {
        let i = self.fleet.relays[1];
        self.stop_node(i);
        self.outage.lock().unwrap().stopped = Some(self.now());
    }

    fn start_second(self: &Arc<Self>) {
        let i = self.fleet.relays[1];
        self.start_node(i);
        let started = self.now();
        self.outage.lock().unwrap().started = Some(started);
        // When each device set up with it is connected to it again (bar
        // 15), read from its peers every two seconds.
        let run = self.clone();
        std::thread::spawn(move || {
            let expected: Vec<(usize, String)> = run
                .plan
                .population
                .each_device()
                .filter(|(k, d)| {
                    let p = &run.plan.population.people[*k];
                    p.relays_of(*d, run.plan.relays).contains(&1) && !p.office
                })
                .map(|(k, d)| {
                    let i = run.fleet.device(k, d);
                    (i, run.fleet.made[i].key.clone())
                })
                .collect();
            let mut back: HashMap<usize, f64> = HashMap::new();
            while run.now() < started + 180.0 && back.len() < expected.len() {
                if let Some(keys) = run.peers_of(1) {
                    for (i, key) in &expected {
                        if keys.contains(key) {
                            back.entry(*i).or_insert_with(|| run.now());
                        }
                    }
                }
                std::thread::sleep(Duration::from_secs(2));
            }
            let mut outage = run.outage.lock().unwrap();
            outage.back = expected
                .iter()
                .map(|(i, _)| (*i, back.get(i).copied()))
                .collect();
        });
    }

    /// Test 5: the device of a person that is not active now, stopped and
    /// never started again.
    fn stop_for_good(&self, k: usize) {
        let active = self.plans.lock().unwrap()[k].active().unwrap_or(0);
        let d = (0..self.plan.population.people[k].devices)
            .find(|d| *d != active)
            .unwrap_or(0);
        let at = self.now();
        self.gone.lock().unwrap().insert((k, d));
        self.plans.lock().unwrap()[k].remove(d, at - self.window_start());
        self.stop_node(self.fleet.device(k, d));
        *self.stopped_for_good.lock().unwrap() = Some((k, d, at));
    }
}

/// What a run came to.
#[derive(Debug, Clone, Default)]
pub struct Outcome {
    pub verdict: String,
    pub summary: String,
    pub out: PathBuf,
    /// Each bar's title and its word: PASS, FAIL or REPORTED.
    pub bars: Vec<(String, String)>,
    /// Each check's title and whether it held.
    pub checks: Vec<(String, bool)>,
    /// Each relay's pulls in the window, and the model's for the minutes
    /// each device was on (bar 12).
    pub pulls: Vec<(f64, f64)>,
    /// Of the edits waited for on other devices: how many, arrived, not
    /// arrived, and on a device removed meanwhile.
    pub waited: (usize, usize, usize, usize),
}

impl Run {
    /// The state of a run of `plan` over `fleet`, nothing started:
    /// `relays` are the relays' addresses and their keys in hex.
    pub fn of(
        plan: Plan,
        out: &Path,
        fleet: Fleet,
        relays: (Vec<SocketAddr>, Vec<String>),
        folders: HashMap<(usize, usize, usize), PathBuf>,
        plans: Vec<PersonPlan>,
        thread_said: String,
    ) -> Run {
        Run {
            samples: Arc::new(Mutex::new(Samples::new(out).unwrap())),
            observer: Arc::new(Mutex::new(Observer::default())),
            plan,
            out: out.to_path_buf(),
            fleet: Arc::new(fleet),
            relay_addrs: relays.0,
            relay_keys: relays.1,
            plans: Mutex::new(plans),
            sessions: Mutex::new(Vec::new()),
            offs: Mutex::new(Vec::new()),
            busy: Mutex::new(HashSet::new()),
            gone: Mutex::new(HashSet::new()),
            removed: Mutex::new(HashSet::new()),
            stopped_for_good: Mutex::new(None),
            words: Mutex::new(HashMap::new()),
            folders,
            next_edit: AtomicU64::new(1),
            window: Mutex::new(None),
            cut: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            removals: Mutex::new(Vec::new()),
            removals_planned: Mutex::new(0),
            outage: Mutex::new(Outage::default()),
            setup: Mutex::new(Setup {
                thread_plan: thread_said,
                machine: machine::machine_words(),
                ..Setup::default()
            }),
            last_answer: Mutex::new(HashMap::new()),
            steps: Mutex::new(None),
            peers_at_end: Mutex::new(Vec::new()),
            stops_at_end: Mutex::new(Vec::new()),
            pids_left: Mutex::new(Vec::new()),
            stopped_why: Mutex::new(None),
        }
    }

    /// The state of a run of `plan` over nodes that are made up and never
    /// started: no configuration, no `init`, no process. For the tests of
    /// the report, which give it the samples and the changes they read.
    pub fn made_up(plan: Plan, out: &Path) -> Run {
        let mut fleet = Fleet::new(Clock::new(), out).unwrap();
        let mut made = |name: String, what: What| {
            let key_bytes = [fleet.made.len() as u8 + 1; 32];
            let settings = Settings {
                name: name.clone(),
                role: match what {
                    What::Relay(_) => Role::Relay,
                    What::Device { .. } => Role::Device,
                },
                http: 0,
                p2p: 0,
                listen: IpAddr::V4(RELAY_ADDRESS),
                relays: Vec::new(),
                churn_secs: None,
                data_dir: PathBuf::new(),
            };
            fleet.add(Made {
                node: Node {
                    name: Box::leak(name.clone().into_boxed_str()),
                    child: None,
                    dir: tempfile::tempdir_in(out).unwrap(),
                    http: 0,
                    p2p: 0,
                    bin: None,
                },
                what,
                label: name,
                key: cordelia_crypto::bech32::encode_public_key(&key_bytes).unwrap(),
                key_hex: hex::encode(key_bytes),
                token: String::new(),
                settings: Mutex::new(settings),
                mask: None,
            });
        };
        for r in 0..plan.relays {
            made(format!("relay{}", r + 1), What::Relay(r));
        }
        for (person, device) in plan.population.each_device() {
            made(
                device_label(person, device),
                What::Device { person, device },
            );
        }
        let addrs = (0..plan.relays)
            .map(|r| SocketAddr::new(IpAddr::V4(RELAY_ADDRESS), 21_000 + r as u16))
            .collect();
        let keys = fleet
            .relays
            .iter()
            .map(|i| fleet.made[*i].key_hex.clone())
            .collect();
        Run::of(
            plan,
            out,
            fleet,
            (addrs, keys),
            HashMap::new(),
            Vec::new(),
            String::new(),
        )
    }
}

/// A run of `plan`, leaving what it leaves in `out` (§4.4).
pub fn run(plan: Plan, out: &Path) -> Outcome {
    std::fs::create_dir_all(out).unwrap();
    // Step 1.
    let (threads, thread_said) = match before_anything(&plan, out) {
        Ok(planned) => planned,
        Err(why) => return crate::report::refused(&plan, out, &why),
    };
    let clock = Clock::new();
    let mut fleet = Fleet::new(clock, out).unwrap();
    if let Err(why) = make_the_nodes(&plan, out, &mut fleet, threads == ThreadPlan::Masked) {
        return crate::report::refused(&plan, out, &why);
    }
    let relay_addrs: Vec<SocketAddr> = fleet
        .relays
        .iter()
        .map(|i| SocketAddr::new(IpAddr::V4(RELAY_ADDRESS), fleet.made[*i].node.p2p))
        .collect();
    let relay_keys: Vec<String> = fleet
        .relays
        .iter()
        .map(|i| fleet.made[*i].key_hex.clone())
        .collect();
    let folders = folders_of(&plan, &fleet);
    let plans = plan
        .population
        .people
        .iter()
        .map(|p| PersonPlan::new(p, plan.seed, plan.timing.first_files, &plan.offs))
        .collect();
    // Time zero: the relays' start.
    fleet.clock = Clock::new();
    let run = Arc::new(Run::of(
        plan,
        out,
        fleet,
        (relay_addrs, relay_keys),
        folders,
        plans,
        thread_said,
    ));
    let fleet = run.fleet.clone();

    // Step 2: the relays, each healthy and holding the other's connection.
    for r in 0..run.plan.relays {
        run.start_node(fleet.relays[r]);
    }
    let sampling = Arc::new(AtomicBool::new(false));
    let sampler = {
        let (run, done) = (run.clone(), sampling.clone());
        std::thread::spawn(move || run.sampler(done))
    };
    let observing = Arc::new(AtomicBool::new(false));
    let observer_thread = {
        let (run, done) = (run.clone(), observing.clone());
        std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let now = run.now();
                run.observer.lock().unwrap().tick(now);
                std::thread::sleep(Duration::from_millis(250));
            }
        })
    };
    let relays_up = (|| -> Result<(), String> {
        for i in &fleet.relays {
            let made = &fleet.made[*i];
            wait_within(&format!("{} answers", made.label), 60, || healthy(made))?;
        }
        if run.plan.relays == 2 {
            for r in 0..2 {
                let other = fleet.made[fleet.relays[1 - r]].key.clone();
                wait_within("each relay holds the other's connection", 120, || {
                    run.peers_of(r)?.contains(&other).then_some(())
                })?;
            }
        }
        Ok(())
    })();
    if let Err(why) = relays_up {
        fleet.fault(format!("the relays did not come up: {why}"));
    }

    // Step 3: the people, ten at a time.
    run.setup.lock().unwrap().started = run.now();
    let people = run.plan.population.people.len();
    let mut k = 0;
    while k < people && !fleet.stop_early.load(Ordering::SeqCst) {
        let group: Vec<usize> = (k..(k + 10).min(people)).collect();
        let threads: Vec<_> = group
            .iter()
            .map(|k| {
                let (run, k) = (run.clone(), *k);
                std::thread::spawn(move || run.set_up(k))
            })
            .collect();
        for (t, k) in threads.into_iter().zip(&group) {
            if let Err(e) = t.join() {
                fleet.fault(format!("the setup of person {k} failed: {}", said_by(e)));
            }
        }
        k += 10;
    }
    run.setup.lock().unwrap().ended = run.now();

    // Step 4: the office moves to its address.
    if !fleet.stop_early.load(Ordering::SeqCst) && run.plan.stage.has_office() {
        let moved = run.move_the_office();
        run.setup.lock().unwrap().office_moved = Some((run.now(), moved));
    }

    // Step 5: the window begins after the settle.
    sleep_for(&fleet, run.plan.timing.settle);
    let start = run.now();
    *run.window.lock().unwrap() = Some((start, None));
    // A sample of every node at each edge of the window, so that what a
    // counter gained in the window is read from inside it, and none of it
    // is lost to a pair of samples that straddles an edge.
    run.sample_every_node();
    let churns_now: Vec<u64> = (0..run.plan.relays)
        .map(|r| {
            run.relay_metrics(r)
                .and_then(|m| m.get("cordelia_churns_total").copied())
                .unwrap_or(0.0) as u64
        })
        .collect();
    let mut steps = Steps::new(
        &run.plan.timing,
        run.plan.relays,
        start,
        [churns_now[0], churns_now.get(1).copied().unwrap_or(0)],
    );

    // Step 6: edits, and devices off and on.
    let queue = Arc::new(Mutex::new(Vec::new()));
    let edits = {
        let (run, queue) = (run.clone(), queue.clone());
        std::thread::spawn(move || run.edits(start, queue))
    };
    let offs = {
        let (run, queue) = (run.clone(), queue.clone());
        std::thread::spawn(move || run.offs(start, queue))
    };
    let mut removals = Vec::new();
    let mut stopped_for_good_done = false;
    // Steps 7 to 9, at each minute.
    while !fleet.stop_early.load(Ordering::SeqCst) {
        sleep_for(&fleet, run.plan.timing.sample_every);
        if fleet.stop_early.load(Ordering::SeqCst) {
            break;
        }
        let t = run.now();
        if let Some((k, at)) = run.plan.stopped_for_good
            && !stopped_for_good_done
            && t - start >= at
        {
            run.stop_for_good(k);
            stopped_for_good_done = true;
        }
        let second_is = run.plan.relays == 2 && fleet.is(fleet.relays[1]).0 == Is::Running;
        let churns = [
            run.relay_metrics(0)
                .and_then(|m| m.get("cordelia_churns_total").copied())
                .map(|c| c as u64),
            match second_is {
                true => run
                    .relay_metrics(1)
                    .and_then(|m| m.get("cordelia_churns_total").copied())
                    .map(|c| c as u64),
                false => None,
            },
        ];
        match steps.at(t, churns) {
            Some(Act::StopSecond) => run.stop_second(),
            Some(Act::StartSecond) => run.start_second(),
            Some(Act::Remove) => {
                let chosen = run.to_remove();
                *run.removals_planned.lock().unwrap() = chosen.len();
                let n = chosen.len().max(1) as f64;
                for (i, k) in chosen.into_iter().enumerate() {
                    let run = run.clone();
                    let wait = run.plan.timing.removal_spread * i as f64 / n;
                    removals.push(std::thread::spawn(move || {
                        sleep_for(&run.fleet, wait);
                        run.remove(k);
                    }));
                }
            }
            Some(Act::End { cut }) => {
                run.cut.store(cut, Ordering::SeqCst);
                break;
            }
            None => {}
        }
    }
    *run.steps.lock().unwrap() = Some(steps);
    run.sample_every_node();
    let end = run.now();
    *run.window.lock().unwrap() = Some((start, Some(end)));

    // Step 10: it ends.
    run.ended.store(true, Ordering::SeqCst);
    // A thread of the run that panicked is a fault of the run.
    for (what, thread) in [("edits", edits), ("devices off and on", offs)] {
        if let Err(e) = thread.join() {
            fleet.fault(format!("the thread of {what} failed: {}", said_by(e)));
        }
    }
    for r in removals {
        if let Err(e) = r.join() {
            fleet.fault(format!("a removal's thread failed: {}", said_by(e)));
        }
    }
    if fleet.is(fleet.relays.last().copied().unwrap()).0 == Is::Stopped && run.plan.relays == 2 {
        run.start_second();
    }
    // Devices off are brought back, and what was written is waited for.
    let gone = run.gone.lock().unwrap().clone();
    for (k, d) in run.plan.population.each_device() {
        if !gone.contains(&(k, d)) {
            run.turn_on(fleet.device(k, d), How::Stop);
        }
    }
    let drain_until = run.now() + run.plan.timing.arrival_wait;
    while run.now() < drain_until && !fleet.stop_early.load(Ordering::SeqCst) {
        let waiting: usize = run
            .plan
            .population
            .each_device()
            .filter(|kd| !gone.contains(kd))
            .map(|(k, d)| run.observer.lock().unwrap().pending_on(k, d))
            .sum();
        if waiting == 0 {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    // Each relay's peers: every key one of the run's (§4.3, rule 1).
    for r in 0..run.plan.relays {
        let keys = run.peers_of(r).unwrap_or_default();
        run.peers_at_end.lock().unwrap().push((r, keys));
    }
    // A last sample of every node, and the relays' room.
    for i in 0..fleet.made.len() {
        if let Some(s) = fleet::sample(&fleet, &fleet::agent(), i, true, &run.relay_keys) {
            run.samples.lock().unwrap().add(&fleet, s);
        }
    }
    let mut order: Vec<usize> = (0..fleet.made.len())
        .filter(|i| matches!(fleet.made[*i].what, What::Device { .. }))
        .collect();
    order.extend(fleet.relays.iter().copied());
    for chunk in order.chunks(16) {
        let stops: Vec<_> = chunk
            .iter()
            .map(|i| {
                let (run, i) = (run.clone(), *i);
                std::thread::spawn(move || (i, run.fleet.stop(i)))
            })
            .collect();
        for s in stops {
            if let Ok((i, Some((took, well)))) = s.join() {
                run.stops_at_end.lock().unwrap().push((i, took, well));
            }
        }
    }
    fleet.kill_all();
    sampling.store(true, Ordering::SeqCst);
    observing.store(true, Ordering::SeqCst);
    let _ = sampler.join();
    let _ = observer_thread.join();
    fleet.starter.end();
    // Every pid it started has gone.
    let pids = std::fs::read_to_string(out.join("pids")).unwrap_or_default();
    let left: Vec<u32> = pids
        .lines()
        .filter_map(|l| l.split(' ').next()?.parse().ok())
        .filter(|pid| Path::new(&format!("/proc/{pid}")).exists())
        .collect();
    *run.pids_left.lock().unwrap() = left;

    // Step 11: the summary.
    crate::report::write(&run)
}
