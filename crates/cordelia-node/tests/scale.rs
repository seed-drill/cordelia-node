//! The scale test of R1's gate 10 (decision 2026-10-22, the record of a
//! scale test for R1, §4 and §6): a harness of real processes, the release
//! binary run as a person runs it, two relays and a stage's devices on
//! one machine's loopback network.
//!
//! A stage is run so (§4.1), and runs for hours:
//!
//! ```bash
//! cargo build --release -p cordelia-node
//! CORDELIA_SCALE_STAGE=100 CORDELIA_SCALE_SEED=1 CORDELIA_SCALE_OUT=/path/to/out \
//!   cargo test --release -p cordelia-node --test scale a_stage_of_the_scale_test \
//!   -- --ignored --nocapture
//! ```
//!
//! `CORDELIA_SCALE_STAGE` is `100` or `190`, the stages of gate 10 for R1;
//! `small` runs section 6's small run of test 4 (two relays and seven
//! devices, some minutes). Stages 250 and 500 come after change B and are
//! refused. Section 6's tests 4 and 5, the small runs, run only where
//! `CORDELIA_SCALE_SMALL` is set, each some minutes and one after the
//! other; without it they return at once, as the run of a stage does
//! without `CORDELIA_SCALE_STAGE`, so that `-- --ignored` passes over
//! them:
//!
//! ```bash
//! CORDELIA_SCALE_SMALL=1 cargo test --release -p cordelia-node --test scale a_small_run \
//!   -- --ignored --nocapture
//! ```
//! `CORDELIA_SCALE_RELAYS=1` runs a stage with one relay (rule 3
//! of §2.2). `CORDELIA_SCALE_DEVICE_GROWTH` gives bar 6 the threshold from
//! stage 100 for stage 190, in MiB an hour. `CORDELIA_E2E_KEEP` keeps each
//! node's directory and log in the output.
//!
//! The harness reads `/proc`, so it runs on Linux.

#![cfg(target_os = "linux")]

mod common;

#[path = "scale/configs.rs"]
mod configs;
#[path = "scale/fleet.rs"]
mod fleet;
#[path = "scale/machine.rs"]
mod machine;
#[path = "scale/observer.rs"]
mod observer;
#[path = "scale/population.rs"]
mod population;
#[path = "scale/removal.rs"]
mod removal;
#[path = "scale/report.rs"]
mod report;
#[path = "scale/run.rs"]
mod run;
#[path = "scale/steps.rs"]
mod steps;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use population::{Off, Offs, PersonPlan, Population, Profile, Rng, Stage};
use steps::{Act, Steps, Timing};

/// One run at a time in this process: two at once would share the
/// machine, and its checks of validity (§6, rule 5) would measure that.
static ONE_RUN_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn one_run_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    ONE_RUN_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Where a run leaves what it leaves: `CORDELIA_SCALE_OUT`, or a folder of
/// the test's own.
fn out_for(what: &str) -> (PathBuf, Option<tempfile::TempDir>) {
    match std::env::var_os("CORDELIA_SCALE_OUT") {
        Some(out) => (PathBuf::from(out).join(what), None),
        None => {
            let dir = tempfile::Builder::new()
                .prefix(&format!("cordelia-scale-{what}-"))
                .tempdir()
                .unwrap();
            (dir.path().to_path_buf(), Some(dir))
        }
    }
}

/// A stage, run as section 4 says. Without `CORDELIA_SCALE_STAGE` it says
/// so and returns at once, so that the job that runs the ignored tests
/// does not start a run of hours.
#[test]
#[ignore = "a run of hours: set CORDELIA_SCALE_STAGE (decision 2026-10-22 §4.1)"]
fn a_stage_of_the_scale_test() {
    let Some(stage) = std::env::var_os("CORDELIA_SCALE_STAGE") else {
        eprintln!("CORDELIA_SCALE_STAGE is not set: no stage is run (decision 2026-10-22 §4.1)");
        return;
    };
    let stage = Stage::parse(&stage.to_string_lossy()).unwrap_or_else(|why| panic!("{why}"));
    let seed: u64 = std::env::var("CORDELIA_SCALE_SEED")
        .ok()
        .map(|s| s.parse().expect("CORDELIA_SCALE_SEED is a number"))
        .unwrap_or(1);
    let relays: usize = std::env::var("CORDELIA_SCALE_RELAYS")
        .ok()
        .map(|s| s.parse().expect("CORDELIA_SCALE_RELAYS is 1 or 2"))
        .unwrap_or(2);
    assert!(
        relays == 1 || relays == 2,
        "a stage runs with one relay or two"
    );
    let mut plan = match stage {
        Stage::Small => run::Plan::small(seed),
        _ => run::Plan::of_a_stage(stage, seed, relays),
    };
    if relays == 1 {
        plan = run::Plan {
            relays: 1,
            population: Population::of(stage, seed, 1),
            ..plan
        };
    }
    plan.device_growth = std::env::var("CORDELIA_SCALE_DEVICE_GROWTH").ok().map(|g| {
        g.parse()
            .expect("CORDELIA_SCALE_DEVICE_GROWTH is MiB an hour")
    });
    let name = format!("stage-{}-seed-{seed}-relays-{relays}", stage.name());
    let (out, _kept) = out_for(&name);
    let _one = one_run_at_a_time();
    let outcome = run::run(plan, &out);
    println!("{}", outcome.summary);
    assert_eq!(
        outcome.verdict,
        "PASS",
        "the stage did not pass: {}",
        outcome.out.join("SUMMARY.md").display()
    );
}

// ── 1. The population ───────────────────────────────────────────────

/// For each stage the population has exactly the stage's devices, the mix
/// of §2.2, the office, the split people, a /24 for each person at setup
/// and the office's one address in the window, and no address outside
/// 127.0.0.0/8; the same seed gives the same population, and another seed
/// another.
#[test]
fn the_population_of_each_stage_is_the_records() {
    // Each stage's devices, people and channels at a relay (§2.2's table);
    // the small stage is test 4's.
    let expected = [
        (Stage::Small, 7, 3, 29),
        (Stage::Hundred, 100, 40, 548),
        (Stage::OneNinety, 190, 76, 1034),
    ];
    assert_eq!(expected.map(|e| e.0), Stage::ALL);
    for (stage, devices, people, channels) in expected {
        let p = Population::of(stage, 1, 2);
        assert_eq!(p.devices(), devices, "{stage:?}");
        assert_eq!(p.people.len(), people, "{stage:?}");
        if stage != Stage::Small {
            assert_eq!(
                (stage.devices(), stage.people()),
                (devices, people),
                "{stage:?}"
            );
        }
        let at_a_relay: usize = p.people.iter().map(|q| q.profile.channels()).sum();
        assert_eq!(at_a_relay, channels, "{stage:?}");
        for (profile, n) in stage.mix() {
            let of = p.people.iter().filter(|q| q.profile == profile).count();
            let n = match stage {
                Stage::Small => [2, 1, 0][profile as usize],
                _ => n,
            };
            assert_eq!(of, n, "{stage:?} {profile:?}");
            assert!(
                p.people
                    .iter()
                    .filter(|q| q.profile == profile)
                    .all(|q| q.devices == profile.devices())
            );
        }
        let office: Vec<_> = p.people.iter().filter(|q| q.office).collect();
        match stage.has_office() {
            true => {
                assert_eq!(office.len(), 3, "{stage:?}");
                assert!(office.iter().all(|q| q.profile == Profile::Heavy));
                assert_eq!(p.office_order.len(), 9);
                let mut order = p.office_order.clone();
                order.sort();
                order.dedup();
                assert_eq!(order.len(), 9);
            }
            false => assert!(office.is_empty() && p.office_order.is_empty()),
        }
        let split: Vec<_> = p.people.iter().filter(|q| q.split).collect();
        let want = match stage {
            Stage::Small => 1,
            _ => (people as f64 / 10.0).round() as usize,
        };
        assert_eq!(split.len(), want, "{stage:?}");
        assert!(split.iter().all(|q| !q.office));
        for q in &split {
            assert_eq!(q.relays_of(0, 2), [0]);
            assert!((1..q.devices).all(|d| q.relays_of(d, 2) == [1]));
        }
        // A /24 for each person at setup, and the office's one in the window.
        let mut nets = HashSet::new();
        for q in &p.people {
            let o = q.address.octets();
            assert_eq!(o[0], 127);
            assert_ne!(q.address, population::OFFICE_ADDRESS);
            assert!(nets.insert((o[1], o[2])), "a /24 of their own");
            let w = q.address_in_window();
            assert_eq!(w.octets()[0], 127);
            assert_eq!(q.office, w == population::OFFICE_ADDRESS);
        }
        assert!(!nets.contains(&(10, 0)), "no person in the office's /24");
        assert_eq!(Population::of(stage, 1, 2), p, "the same seed");
        if stage != Stage::Small {
            assert_ne!(Population::of(stage, 2, 2), p, "another seed");
        }
        // With one relay nobody is split.
        assert!(Population::of(stage, 1, 1).people.iter().all(|q| !q.split));
    }
    assert!(Stage::parse("250").unwrap_err().contains("change B"));
    assert!(Stage::parse("500").unwrap_err().contains("change B"));
}

// ── 2. The schedule ─────────────────────────────────────────────────

/// Over a simulated ten hours, each profile's steady edits an hour are
/// within 5% of §2.1; its bursts come once each 30 minutes; every edit of
/// a session is on its active device; no file is written twice on one
/// device within 15 s; the active device is never off in its session; and
/// each profile's share of time off is within 5% of what item 4 gives.
#[test]
fn the_schedule_is_the_records_over_ten_hours() {
    const HOURS: f64 = 10.0;
    for profile in Profile::ALL {
        // Enough people of the profile for the figures to settle.
        let people = match profile {
            Profile::Heavy => 40,
            _ => 400,
        };
        let (mut steady, mut bursts) = (0usize, 0usize);
        let (mut off_secs, mut not_active_secs) = (0.0, 0.0);
        for k in 0..people {
            let person = population::Person {
                index: k,
                profile,
                devices: profile.devices(),
                office: false,
                split: false,
                address: population::person_address(k),
            };
            let mut plan = PersonPlan::new(&person, 7, 10, &Offs::Drawn);
            let mut sessions = Vec::new();
            let mut offs: Vec<Off> = Vec::new();
            let mut last: HashMap<(usize, usize, String), f64> = HashMap::new();
            let mut burst_starts = HashSet::new();
            loop {
                let s = plan.next_session();
                if s.session.start >= HOURS * 3600.0 {
                    break;
                }
                for e in &s.edits {
                    assert_eq!(e.device, s.session.device, "an edit off the active device");
                    assert!(e.at >= s.session.start && e.at < s.session.end);
                    let key = (e.device, e.name, e.file.clone());
                    if let Some(t) = last.get(&key) {
                        assert!(
                            e.at - t >= population::REWRITE_GAP_SECS,
                            "written twice within 15 s"
                        );
                    }
                    last.insert(key, e.at);
                    if e.at < HOURS * 3600.0 {
                        match e.burst {
                            true => {
                                burst_starts.insert((e.at / population::BLOCK_SECS) as u64);
                            }
                            false => steady += 1,
                        }
                    }
                }
                for o in &s.offs {
                    assert_ne!(
                        o.device, s.session.device,
                        "the active device off in its session"
                    );
                }
                offs.extend(&s.offs);
                sessions.push(s.session);
            }
            bursts += burst_starts.len();
            // The active device is never off in any session.
            for s in &sessions {
                assert!(
                    !offs
                        .iter()
                        .any(|o| o.device == s.device && o.start < s.end && o.end > s.start)
                );
            }
            // The share of time off of a device that is not active.
            let horizon = sessions.last().map_or(0.0, |s| s.end).min(HOURS * 3600.0);
            for d in 0..profile.devices() {
                let active: f64 = sessions
                    .iter()
                    .filter(|s| s.device == d)
                    .map(|s| s.end.min(horizon) - s.start.min(horizon))
                    .sum();
                not_active_secs += horizon - active;
                off_secs += offs
                    .iter()
                    .filter(|o| o.device == d)
                    .map(|o| o.end.min(horizon) - o.start.min(horizon))
                    .sum::<f64>();
            }
        }
        let rate = steady as f64 / people as f64 / HOURS;
        assert!(
            (rate - profile.edits_an_hour()).abs() <= 0.05 * profile.edits_an_hour(),
            "{profile:?}: {rate:.2} edits an hour"
        );
        let blocks = (HOURS * 3600.0 / population::BLOCK_SECS) as usize;
        assert_eq!(
            bursts,
            people * blocks,
            "{profile:?}: a burst in each 30 minutes"
        );
        let share = off_secs / not_active_secs;
        let want = profile.share_off();
        assert!(
            (share - want).abs() <= 0.05 * want.max(1e-9) || (want == 0.0 && share == 0.0),
            "{profile:?}: off {:.2}% of the time, item 4 gives {:.2}%",
            share * 100.0,
            want * 100.0
        );
    }
}

/// A relay's churns from its start at `from`: an hour apart, each with up
/// to 300 s of jitter, from `seed`, as `churn` places them.
fn churns_from(seed: u64, what: &str, from: f64, until: f64) -> Vec<f64> {
    let mut jitter = Rng::of(seed, what);
    let mut at = from + 3600.0 + jitter.between(0.0, 300.0);
    let mut churns = Vec::new();
    while at < until {
        churns.push(at);
        at += 3600.0 + jitter.between(0.0, 300.0);
    }
    churns
}

fn counted(churns: &[f64], from: f64, t: f64) -> u64 {
    churns.iter().filter(|c| **c > from && **c <= t).count() as u64
}

/// The steps follow the churns given to them: with the churns of a slow
/// setup they still place two churns of each relay in the window, and with
/// no churn after five hours they cut the window and say INVALID.
#[test]
fn the_steps_follow_the_churns_they_are_given() {
    let timing = Timing::of_a_stage();
    for (setup, seed) in [
        (0.0, 1),
        (1234.0, 2),
        (3599.0, 3),
        (7000.0, 4),
        (12345.0, 5),
    ] {
        let until = setup + 8.0 * 3600.0;
        let first = churns_from(seed, "first", 0.0, until);
        let second = churns_from(seed, "second", 0.0, until);
        let mut again: Vec<f64> = Vec::new();
        let start = setup + timing.settle;
        let mut steps = Steps::new(
            &timing,
            2,
            start,
            [counted(&first, 0.0, start), counted(&second, 0.0, start)],
        );
        let (mut stopped, mut started, mut removals, mut ended) = (None, None, None, None);
        let mut t = start;
        while ended.is_none() {
            t += 60.0;
            // The second relay's churns: since its start, or since its
            // start again; none while it is stopped.
            let second_now = match (stopped, started) {
                (None, _) => Some(counted(&second, 0.0, t)),
                (Some(_), None) => None,
                (Some(_), Some(s)) => Some(counted(&again, s, t)),
            };
            match steps.at(t, [Some(counted(&first, 0.0, t)), second_now]) {
                Some(Act::StopSecond) => stopped = Some(t),
                Some(Act::StartSecond) => {
                    started = Some(t);
                    // Its clock is in memory: its next churn is 60 to 65
                    // minutes after its start again.
                    again = churns_from(seed, "second again", t, until);
                }
                Some(Act::Remove) => removals = Some(t),
                Some(Act::End { cut }) => ended = Some((t, cut)),
                None => {}
            }
        }
        let (end, cut) = ended.unwrap();
        assert!(!cut, "setup {setup}: the window was cut");
        let (stopped, started, removals) = (stopped.unwrap(), started.unwrap(), removals.unwrap());
        // The first relay: two churns in the window.
        assert!(counted(&first, start, end) >= 2, "setup {setup}");
        // The second: one before its outage, one after its start again.
        assert!(counted(&second, start, stopped) >= 1, "setup {setup}");
        assert!(started >= stopped + timing.outage);
        assert!(counted(&again, started, removals) >= 1, "setup {setup}");
        assert!(end >= removals + timing.removal_spread + timing.after_removal);
        assert!(
            end - start < timing.cut,
            "setup {setup}: {:.0} s",
            end - start
        );
    }
    // With no churn: the window is cut at five hours, and the run is
    // INVALID.
    let mut steps = Steps::new(&timing, 2, 100.0, [0, 0]);
    let mut t = 100.0;
    let cut = loop {
        t += 60.0;
        if let Some(Act::End { cut }) = steps.at(t, [Some(0), Some(0)]) {
            break cut;
        }
        assert!(t < 100.0 + 6.0 * 3600.0, "never cut");
    };
    assert!(cut);
    assert!(t >= 100.0 + timing.cut);
    // With one relay: the removals after its first churn in the window.
    let mut steps = Steps::new(&timing, 1, 0.0, [3, 0]);
    assert_eq!(steps.at(60.0, [Some(3), None]), None);
    assert_eq!(steps.at(120.0, [Some(4), None]), Some(Act::Remove));
}

// ── 3. The observer ─────────────────────────────────────────────────

/// With two folders and no node: a file copied from one to the other
/// after 3 s is observed at 3 s within 0.3 s; a file never copied is
/// counted as not arrived; a later edit of the same file that arrives
/// first does not count the earlier one as arrived, and the earlier one's
/// line in a copy kept beside the file does; a file copied with other
/// content does not count. The observer is given its times, every 250 ms,
/// as its thread gives them in a run, so that nothing hangs on the
/// machine's load.
#[test]
fn the_observer_counts_an_edit_only_by_its_own_line() {
    use observer::{Observer, Written, text_of};
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    let written = |number: u64, file: &str| Written {
        number,
        person: 0,
        writer: 0,
        name: 0,
        file: file.into(),
        size: 600,
        at: 0.0,
        burst: false,
        new: true,
        replaced: None,
    };
    let mut o = Observer::default();
    // Copied after 3 s, observed at 3 s within 0.3 s.
    std::fs::write(a.join("copied.md"), text_of(1, 600, 1)).unwrap();
    o.wrote(written(1, "copied.md"), vec![(1, b.clone())]);
    // Never copied.
    std::fs::write(a.join("never.md"), text_of(2, 600, 2)).unwrap();
    o.wrote(written(2, "never.md"), vec![(1, b.clone())]);
    // Two edits of one file; the later arrives first.
    o.wrote(written(3, "twice.md"), vec![(1, b.clone())]);
    o.wrote(written(4, "twice.md"), vec![(1, b.clone())]);
    // A file copied with other content.
    o.wrote(written(5, "other.md"), vec![(1, b.clone())]);
    let mut t = 0.0;
    let ticks_to = |o: &mut Observer, until: f64, t: &mut f64| {
        while *t < until - 1e-9 {
            o.tick(*t);
            *t += 0.25;
        }
    };
    ticks_to(&mut o, 2.9, &mut t);
    // The copy lands just before the tick at 3 s.
    let copied_at = 2.9;
    std::fs::copy(a.join("copied.md"), b.join("copied.md")).unwrap();
    std::fs::write(b.join("twice.md"), text_of(4, 600, 4)).unwrap();
    std::fs::write(b.join("other.md"), text_of(9, 600, 9)).unwrap();
    ticks_to(&mut o, 4.0, &mut t);
    let at = o.arrivals[&(1, 1)].at;
    assert!(
        at >= copied_at && at - copied_at <= 0.3,
        "observed at {at:.2}, copied at {copied_at:.2}"
    );
    assert!(o.arrivals.contains_key(&(4, 1)), "the later edit arrived");
    assert!(
        !o.arrivals.contains_key(&(3, 1)),
        "the earlier one is not arrived by the later's line"
    );
    assert!(
        !o.arrivals.contains_key(&(5, 1)),
        "other content does not count"
    );
    // The earlier one's line in a copy kept beside the file does count.
    std::fs::write(b.join("twice.conflict-abcd.md"), text_of(3, 600, 3)).unwrap();
    ticks_to(&mut o, 5.0, &mut t);
    assert!(
        o.arrivals[&(3, 1)].in_copy,
        "found in the copy kept beside the file"
    );
    // Never copied: still waited for at 300 s, so not arrived.
    ticks_to(&mut o, 300.0, &mut t);
    assert!(!o.arrivals.contains_key(&(2, 1)));
    assert!(!o.arrivals.contains_key(&(5, 1)));
    assert_eq!(o.pending(), 2);
    assert_eq!(o.waited.len(), 5);
    assert!(
        o.gaps.iter().all(|g| (*g - 0.25).abs() < 1e-6),
        "the pace is its own"
    );
    // A device removed at 400 s: an edit it lacked for 400 s while it ran
    // is a miss, and stays waited for; one written in the 120 s before the
    // line is waited for no more.
    let mut late = written(6, "late.md");
    late.at = 350.0;
    o.wrote(late, vec![(1, b.clone())]);
    o.gone(0, 1, 400.0, Some(0.0));
    assert_eq!(o.gone, [(6, 1)]);
    assert_eq!(o.pending(), 2, "the old misses stay waited for");
    // Where it was not running, nothing more is waited for on it.
    o.gone(0, 1, 400.0, None);
    assert_eq!(o.pending(), 0);
    assert_eq!(o.gone.len(), 3);
}

// ── 6. The configurations ───────────────────────────────────────────

/// A configuration the harness writes names nothing to dial but its
/// relays (every device's `will_dial` is a subset of them), binds a
/// loopback address and no other, lists each relay to the other by
/// address and key, and lists in the summary every setting beyond the
/// defaults; one with an address outside loopback is refused before any
/// process starts.
#[test]
fn a_configuration_the_harness_writes_dials_only_its_relays() {
    use configs::{Role, Settings, check_written};
    let dir = tempfile::tempdir().unwrap();
    let relays: Vec<SocketAddr> = vec![
        "127.0.0.1:21001".parse().unwrap(),
        "127.0.0.1:21002".parse().unwrap(),
    ];
    let keys = [1u8, 2].map(|n| cordelia_crypto::bech32::encode_public_key(&[n; 32]).unwrap());
    let keys = [keys[0].as_str(), keys[1].as_str()];
    let node = |name: &'static str, settings: &Settings| {
        let tmp = tempfile::tempdir_in(dir.path()).unwrap();
        let mut settings = settings.clone();
        settings.data_dir = tmp.path().join("data");
        std::fs::write(tmp.path().join("config.toml"), settings.render()).unwrap();
        common::Node {
            name,
            child: None,
            dir: tmp,
            http: settings.http,
            p2p: settings.p2p,
            bin: None,
        }
    };
    let relay = |r: usize| Settings {
        name: format!("relay{}", r + 1),
        role: Role::Relay,
        http: 22000 + r as u16,
        p2p: relays[r].port(),
        listen: IpAddr::V4(configs::RELAY_ADDRESS),
        relays: vec![(relays[1 - r], keys[1 - r].to_string())],
        churn_secs: None,
        data_dir: PathBuf::new(),
    };
    for r in 0..2 {
        let settings = relay(r);
        settings.check().unwrap();
        let n = node(if r == 0 { "relay1" } else { "relay2" }, &settings);
        check_written(&n.config()).unwrap();
        let config = cordelia_core::config::Config::load(&n.config()).unwrap();
        assert_eq!(
            config.network.listen_addr,
            format!("127.0.0.1:{}", relays[r].port())
        );
        assert_eq!(config.network.bootnodes.len(), 1);
        assert_eq!(config.network.bootnodes[0].addr, relays[1 - r].to_string());
        assert_eq!(
            config.network.bootnodes[0].key.as_deref(),
            Some(keys[1 - r])
        );
        assert_eq!(config.governor.hot_max, 50);
        assert_eq!(config.governor.warm_max, 50);
        assert_eq!(config.governor.cold_max, 200);
        // The record's figures for churn: the defaults.
        assert_eq!(
            config.governor.churn_interval_secs as u64,
            cordelia_core::protocol::CHURN_INTERVAL_SECS
        );
        assert!(
            n.will_dial()
                .iter()
                .all(|h| relays.contains(&h.parse().unwrap()))
        );
    }
    let device = Settings {
        name: "p000-d0".into(),
        role: Role::Device,
        http: 23000,
        p2p: 23001,
        listen: IpAddr::V4(population::person_address(0)),
        relays: relays
            .iter()
            .zip(keys)
            .map(|(a, k)| (*a, k.to_string()))
            .collect(),
        churn_secs: None,
        data_dir: PathBuf::new(),
    };
    device.check().unwrap();
    let n = node("p000-d0", &device);
    check_written(&n.config()).unwrap();
    let dialled = n.will_dial();
    assert_eq!(dialled.len(), 2);
    assert!(dialled.iter().all(|h| relays.contains(&h.parse().unwrap())));
    let config = cordelia_core::config::Config::load(&n.config()).unwrap();
    assert_eq!(config.network.listen_addr, "127.20.0.1:23001");
    assert!(config.network.allow_private_addresses);
    assert_eq!(config.network.dns_discovery, "");
    assert_eq!(config.logging.level, "info");
    // Every setting beyond the defaults is listed.
    let said = device.beyond_defaults().join("\n") + &relay(0).beyond_defaults().join("\n");
    for setting in [
        "listen_addr",
        "by key",
        "dns_discovery",
        "allow_private_addresses",
        "log level",
        "data directory",
        "governor",
    ] {
        assert!(said.contains(setting), "{setting} is not listed:\n{said}");
    }
    // Outside loopback: refused before anything starts.
    let mut away = device.clone();
    away.listen = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    assert!(away.check().unwrap_err().contains("127.0.0.0/8"));
    let mut away = device.clone();
    away.relays[0].0 = "192.0.2.1:9474".parse().unwrap();
    assert!(away.check().unwrap_err().contains("127.0.0.0/8"));
    let mut wide = relay(0);
    wide.listen = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    assert!(wide.check().is_err());
    // A file that would bind 0.0.0.0, as the real-process tests' do, is
    // refused when read.
    let file = dir.path().join("wide.toml");
    std::fs::write(&file, device.render().replace("127.20.0.1:", "0.0.0.0:")).unwrap();
    assert!(check_written(&file).unwrap_err().contains("127.0.0.0/8"));
    std::fs::write(
        &file,
        device
            .render()
            .replace("127.0.0.1:21001", "203.0.113.9:21001"),
    )
    .unwrap();
    assert!(check_written(&file).unwrap_err().contains("127.0.0.0/8"));
}

// ── 7. The checks before a run ──────────────────────────────────────

/// Given limits on threads, the harness plans the mask of 4 cores where a
/// limit is under one and a half times what it needs without it, and
/// refuses only where a limit is short with it too; it reads `pids.max`
/// from a cgroup file given to it; and with a pid file of an earlier run
/// whose pid is live and a node of that run, it refuses to start.
#[test]
fn the_checks_before_a_run_mask_refuse_and_find_what_an_earlier_run_left() {
    use machine::{Limits, ThreadPlan, plan_threads};
    let (relays, devices, cores) = (2, 190, 16);
    let unmasked = (relays + devices) * machine::threads_of_a_node(cores);
    let masked =
        relays * machine::threads_of_a_node(cores) + devices * machine::threads_of_a_node(4);
    let limits = |n: u64| Limits {
        pid_max: 4_194_304,
        threads_max: 1_000_000,
        nproc: Some(n),
        pids_max: None,
        pids_current: None,
        threads_now: 1000,
    };
    let room = |need: u64| (need as f64 * 1.5) as u64 + 1000 + 1;
    assert_eq!(
        plan_threads(&limits(room(unmasked)), relays, devices, cores).0,
        ThreadPlan::Unmasked
    );
    assert_eq!(
        plan_threads(&limits(room(unmasked) - 2), relays, devices, cores).0,
        ThreadPlan::Masked
    );
    assert_eq!(
        plan_threads(&limits(room(masked)), relays, devices, cores).0,
        ThreadPlan::Masked
    );
    let (refused, _) = plan_threads(&limits(room(masked) - 2), relays, devices, cores);
    assert!(
        matches!(&refused, ThreadPlan::Refused(why) if why.contains("ulimit -u")),
        "{refused:?}"
    );
    // The cgroup's pids.max, the least of it and its parents', counts too.
    let root = tempfile::tempdir().unwrap();
    let own = root.path().join("user.slice/run.scope");
    std::fs::create_dir_all(&own).unwrap();
    // 3,000 less 40 is under one and a half times what the masked run
    // needs (3,528).
    std::fs::write(root.path().join("user.slice/pids.max"), "3000\n").unwrap();
    std::fs::write(own.join("pids.max"), "max\n").unwrap();
    std::fs::write(own.join("pids.current"), "40\n").unwrap();
    let (max, current) = machine::cgroup_pids("0::/user.slice/run.scope\n", root.path());
    assert_eq!((max, current), (Some(3000), Some(40)));
    let short = Limits {
        pids_max: max,
        pids_current: current,
        ..limits(10_000_000)
    };
    let (plan, _) = plan_threads(&short, relays, devices, cores);
    assert!(
        matches!(&plan, ThreadPlan::Refused(why) if why.contains("pids.max")),
        "{plan:?}"
    );
    // A pid file of an earlier run, whose pid lives and runs a node of it.
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("p000-d0/config.toml");
    let mut node = std::process::Command::new("sh")
        .args(["-c", "sleep 30; true", "sh", "--config"])
        .arg(&config)
        .spawn()
        .unwrap();
    let pids = dir.path().join("pids");
    std::fs::write(&pids, machine::pid_line(node.id(), &config)).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200));
    let refused = machine::check_earlier_pids(&pids).unwrap_err();
    assert!(refused.contains(&node.id().to_string()), "{refused}");
    // A pid that lives and is not a node of that run: no refusal.
    std::fs::write(&pids, machine::pid_line(std::process::id(), &config)).unwrap();
    machine::check_earlier_pids(&pids).unwrap();
    node.kill().unwrap();
    node.wait().unwrap();
    std::fs::write(&pids, machine::pid_line(node.id(), &config)).unwrap();
    machine::check_earlier_pids(&pids).unwrap();
    // No pid file: no earlier run.
    machine::check_earlier_pids(&dir.path().join("none")).unwrap();
}

// ── 4 and 5. A small run, end to end, and one that must fail ────────

/// Each measure of §1.2 is in the summary with a value.
fn every_measure_has_a_value(summary: &str) {
    for label in report::MEASURES_OF_A_RELAY
        .iter()
        .chain(&report::MEASURES_OF_A_DEVICE)
        .chain(&report::MEASURES_OF_THE_MESH)
    {
        let found: Vec<&str> = summary
            .lines()
            .filter_map(|l| l.strip_prefix(&format!("- {label}: ")))
            .collect();
        assert!(
            !found.is_empty(),
            "the measure {label:?} is not in the summary:\n{summary}"
        );
        assert!(
            found
                .iter()
                .all(|v| !v.trim().is_empty() && !v.contains("no value")),
            "the measure {label:?} lacks a value: {found:?}"
        );
    }
}

/// A small run, end to end (§6, test 4): two relays and seven devices of
/// three people, one device off and on, the second relay stopped and
/// started, churn every two minutes, and one removal. Every measure of
/// §1.2 is in the summary with a value; the pulls at each relay agree with
/// the model for those devices within a fifth; and what was written
/// equals what arrived and did not.
#[test]
#[ignore = "a run of some minutes: set CORDELIA_SCALE_SMALL (decision 2026-10-22 §6, test 4)"]
fn a_small_run_end_to_end() {
    if !small_runs_asked() {
        return;
    }
    let (out, _kept) = out_for("small");
    let _one = one_run_at_a_time();
    let outcome = run::run(run::Plan::small(1), &out);
    println!("{}", outcome.summary);
    let summary = std::fs::read_to_string(out.join("SUMMARY.md")).unwrap();
    every_measure_has_a_value(&summary);
    assert_eq!(outcome.pulls.len(), 2);
    for (pulls, model) in &outcome.pulls {
        assert!(
            *model > 0.0 && (pulls - model).abs() <= model / 5.0,
            "{pulls} pulls, the model's {model}"
        );
    }
    let (_, arrived, _, _) = outcome.waited;
    assert!(arrived > 0);
    for file in ["SUMMARY.md", "samples.jsonl", "edits.csv", "pids"] {
        assert!(out.join(file).exists(), "{file}");
    }
    // The run measured what it says (§6), the edits adding up among the
    // checks: on a machine of its own it does, and where it does not the
    // summary says why.
    assert!(
        outcome.checks.iter().all(|(_, held)| *held),
        "the run is INVALID: {:?}",
        outcome.checks
    );
}

/// Whether the small runs are asked for (`CORDELIA_SCALE_SMALL`): without
/// it they say so and return at once.
fn small_runs_asked() -> bool {
    let asked = std::env::var_os("CORDELIA_SCALE_SMALL").is_some();
    if !asked {
        eprintln!(
            "CORDELIA_SCALE_SMALL is not set: the small run is not run (decision 2026-10-22 §6)"
        );
    }
    asked
}

/// A run that must fail (§6, test 5): the small run, where one device is
/// stopped in the middle of the window and not started again. Its
/// person's later edits do not arrive at it, bar 3 fails, and the
/// summary's first line says FAIL.
#[test]
#[ignore = "a run of some minutes: set CORDELIA_SCALE_SMALL (decision 2026-10-22 §6, test 5)"]
fn a_small_run_that_must_fail() {
    if !small_runs_asked() {
        return;
    }
    let (out, _kept) = out_for("small-that-fails");
    let _one = one_run_at_a_time();
    // The first seed whose plan writes an edit after the stop.
    let plan = (1..100)
        .find_map(run::Plan::small_that_fails)
        .expect("a seed whose plan writes after the stop");
    let outcome = run::run(plan, &out);
    println!("{}", outcome.summary);
    let bar_3 = &outcome.bars[2];
    assert!(bar_3.0.starts_with("No edit is lost"), "{bar_3:?}");
    assert_eq!(bar_3.1, "FAIL", "{}", outcome.summary);
    assert!(outcome.summary.starts_with("FAIL "), "{}", outcome.summary);
    assert!(Path::new(&out.join("SUMMARY.md")).exists());
}

// ── What the harness reads of a removal, from made-up answers ───────

/// A device still on the change before says `holds_latest` of that one: a
/// relay is taken to hold change N only on the word of a device that has
/// applied N (bar 10a).
#[test]
fn a_relay_holds_the_change_only_on_the_word_of_a_device_that_applied_it() {
    use serde_json::json;
    let keys: HashMap<usize, String> = [(0, "key-0".to_string()), (1, "key-1".to_string())].into();
    let says = |change: u64, holds: bool| {
        json!({
            "change": change,
            "relays": [{ "relay": "127.0.0.1:21000", "holds_latest": holds }],
            "names": { "to_go": [] },
            "waiting": [{ "waits": 0 }],
            "devices": [
                { "key": "key-0", "applied": change, "sent": true },
                { "key": "key-1", "applied": change, "sent": true },
            ],
        })
    };
    let round = removal::read_round(
        2,
        &[0, 1],
        &[(0, says(2, false)), (1, says(1, true))],
        &keys,
    );
    assert_eq!(round.applied, [0]);
    assert!(round.holding.is_empty(), "{round:?}");
    assert!(!round.settled);
    let round = removal::read_round(2, &[0, 1], &[(0, says(2, true)), (1, says(2, true))], &keys);
    assert_eq!(round.holding, ["127.0.0.1:21000"]);
    assert!(round.settled);
    // A device that did not answer: not settled.
    let round = removal::read_round(2, &[0, 1], &[(0, says(2, true))], &keys);
    assert!(!round.settled);
}

/// The carry ends only when each remaining device holds every version the
/// others carried, read from it: the same version (its revision and its
/// content), or a later one (bar 10b). An older revision, or another
/// content at the same revision, is not it; whose entry holds it does not
/// matter.
#[test]
fn a_carry_ends_only_where_each_device_holds_what_the_others_carried() {
    use serde_json::json;
    let entries = |rev: u64, content: &str, authors: &[&str]| {
        let mut held = removal::Held::new();
        removal::read_entries(
            "n01",
            &json!({ "entries": [
                { "key": "f001.md", "rev": rev, "content": content, "authors": authors },
            ] }),
            &mut held,
        );
        held
    };
    let carried: HashMap<usize, removal::Held> = [
        (1, entries(5, "the fifth", &["key-1"])),
        (0, removal::Held::new()),
    ]
    .into();
    let holds = |held: removal::Held| removal::holds_what_was_carried(0, &held, &carried);
    assert!(
        holds(entries(5, "the fifth", &["key-0"])),
        "the version, by its own entry"
    );
    assert!(holds(entries(6, "the sixth", &["key-0"])), "a later one");
    assert!(
        !holds(entries(4, "the fourth", &["key-0", "key-1"])),
        "an older one"
    );
    assert!(
        !holds(entries(5, "another fifth", &["key-0"])),
        "another version at its revision"
    );
    assert!(!holds(removal::Held::new()), "nothing of the key");
}

// ── Every read of a node is bounded ─────────────────────────────────

/// A node that accepts a request and never answers holds up a read of the
/// harness for no more than the agent's bound (5 s), so no wait of a run
/// hangs.
#[test]
fn a_read_of_a_node_that_never_answers_ends_within_its_bound() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming().flatten() {
            held.push(stream);
        }
    });
    let (done, ended) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let read = fleet::get_text(&fleet::agent(), port, "token", "/api/v1/status");
        let posted = fleet::post_json(
            port,
            "token",
            "/api/v1/devices/list",
            &serde_json::json!({}),
        );
        let _ = done.send((read, posted));
    });
    let (read, posted) = ended
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("the reads ended within their bounds");
    assert!(read.is_none() && posted.is_none());
}

// ── A node goes with the harness ────────────────────────────────────

/// A process started as a node is (in a group of its own, from the thread
/// that starts nodes) is killed when that thread's process ends outright
/// (§4.3, rule 6): the harness is started again as a child that starts a
/// stand-in and exits at once, and the stand-in is gone within seconds.
#[test]
fn a_node_goes_when_the_harness_that_started_it_goes() {
    if let Some(pid_file) = std::env::var_os("CORDELIA_SCALE_DEATH_CHILD") {
        let starter = fleet::Starter::new();
        let mut stand_in = std::process::Command::new("sleep");
        stand_in.arg("60");
        fleet::as_a_node(&mut stand_in);
        let child = starter.spawn(stand_in).unwrap();
        std::fs::write(pid_file, child.id().to_string()).unwrap();
        std::process::exit(0);
    }
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("pid");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "a_node_goes_when_the_harness_that_started_it_goes",
        ])
        .env("CORDELIA_SCALE_DEATH_CHILD", &pid_file)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let pid: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let alive = || {
        std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
            stat.rsplit_once(')')
                .is_some_and(|(_, rest)| !rest.trim_start().starts_with('Z'))
        })
    };
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while alive() && std::time::Instant::now() < until {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let survived = alive();
    if survived {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }
    assert!(
        !survived,
        "the stand-in outlived the harness that started it"
    );
}
