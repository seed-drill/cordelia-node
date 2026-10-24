//! What a run leaves (decision 2026-10-22 §4.4): `SUMMARY.md`, each bar of
//! section 3 and each check of section 6 worked out from what the run
//! kept, the measures of section 1.2, the parts treated apart, the setup,
//! and every setting beyond the defaults; and `edits.csv`.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::Path;

use cordelia_core::protocol::{ENTRY_OVERHEAD_BYTES, MIN_ENTRY_CONTENT_BYTES};

use crate::fleet::{Change, Is, KINDS, Sample, What};
use crate::population::Profile;
use crate::run::{Outcome, Plan, Run};

// ── What is counted ─────────────────────────────────────────────────

/// What an edit of `size` bytes of text in `file` counts as at a relay:
/// its content, the text with its name and its chain about it (taken as
/// 96 bytes), sealed in a power of two from 256 bytes, and the overhead
/// every entry is counted with (`entry_cost`).
pub fn entry_cost_of(file: &str, size: usize) -> u64 {
    let said = size + file.len() + 96 + 28;
    let content = said.next_power_of_two().max(MIN_ENTRY_CONTENT_BYTES);
    (content + ENTRY_OVERHEAD_BYTES) as u64
}

/// The changes the build has (the first line of the summary). Changes C
/// and D are merged, and this build uses what they made; changes A and B
/// are not built.
const CHANGES: &str = "changes C in, D in, B not in, A not in";

/// The commit the binary was built from, and whether the tree differed.
fn commit() -> String {
    let dir = env!("CARGO_MANIFEST_DIR");
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(["-C", dir])
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    let head = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let dirty =
        git(&["status", "--porcelain", "--untracked-files=no"]).is_some_and(|s| !s.is_empty());
    match dirty {
        true => format!("{head}-dirty"),
        false => head,
    }
}

// ── The lines of the summary ────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Reported,
}

impl Verdict {
    fn word(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Reported => "REPORTED",
        }
    }
}

struct Line {
    title: String,
    figure: String,
    bar: String,
    verdict: Verdict,
}

fn line(title: &str, figure: String, bar: &str, holds: bool) -> Line {
    Line {
        title: title.into(),
        figure,
        bar: bar.into(),
        verdict: if holds { Verdict::Pass } else { Verdict::Fail },
    }
}

fn reported(title: &str, figure: String, bar: &str) -> Line {
    Line {
        title: title.into(),
        figure,
        bar: bar.into(),
        verdict: Verdict::Reported,
    }
}

// ── Where each node was ─────────────────────────────────────────────

struct Lives {
    of: Vec<Vec<(f64, Is)>>,
}

impl Lives {
    fn new(changes: &[Change], nodes: usize) -> Lives {
        let mut of = vec![Vec::new(); nodes];
        for c in changes {
            of[c.node].push((c.t, c.is));
        }
        for each in &mut of {
            each.sort_by(|a, b| a.0.total_cmp(&b.0));
        }
        Lives { of }
    }

    fn at(&self, node: usize, t: f64) -> Is {
        self.of[node]
            .iter()
            .take_while(|(at, _)| *at <= t)
            .last()
            .map_or(Is::NotStarted, |(_, is)| *is)
    }

    /// Since when it has been running, where it runs at `t`.
    fn running_since(&self, node: usize, t: f64) -> Option<f64> {
        let mut since = None;
        for (at, is) in self.of[node].iter().take_while(|(at, _)| *at <= t) {
            match is {
                Is::Running => since = since.or(Some(*at)),
                _ => since = None,
            }
        }
        since
    }

    /// Whether it ran all through [a, b].
    fn ran_through(&self, node: usize, a: f64, b: f64) -> bool {
        self.at(node, a) == Is::Running
            && !self.of[node]
                .iter()
                .any(|(at, is)| *at > a && *at <= b && *is != Is::Running)
    }

    fn frozen_within(&self, node: usize, t: f64, secs: f64) -> bool {
        self.at(node, t - secs) == Is::Frozen
            || self.of[node]
                .iter()
                .any(|(at, is)| *at > t - secs && *at <= t && *is == Is::Frozen)
    }

    /// Each time it was not running within [a, b]: from when, to when it
    /// ran again, if it did.
    fn downs(&self, node: usize, a: f64, b: f64) -> Vec<(f64, Option<f64>)> {
        let mut downs = Vec::new();
        let mut down: Option<f64> = None;
        for (at, is) in &self.of[node] {
            match (*is == Is::Running, down) {
                (false, None) if *at >= a && *at <= b => down = Some(*at),
                (true, Some(from)) => {
                    downs.push((from, Some(*at)));
                    down = None;
                }
                _ => {}
            }
        }
        if let Some(from) = down {
            downs.push((from, None));
        }
        downs
    }

    /// Whether it began to run in [a, b]: a start, or going on after a
    /// freeze.
    fn starts_in(&self, node: usize, a: f64, b: f64) -> bool {
        self.of[node]
            .iter()
            .any(|(at, is)| *at >= a && *at <= b && *is == Is::Running)
    }

    /// Whether its process started in [a, b]: its counters count from
    /// nothing then. Going on after a freeze is no start.
    fn restarts_in(&self, node: usize, a: f64, b: f64) -> bool {
        self.of[node]
            .windows(2)
            .any(|w| w[1].0 >= a && w[1].0 <= b && w[1].1 == Is::Running && w[0].1 != Is::Frozen)
            || self.of[node]
                .first()
                .is_some_and(|(at, is)| *at >= a && *at <= b && *is == Is::Running)
    }
}

// ── Reading counters over the window ────────────────────────────────

fn metric(s: &Sample, key: &str) -> Option<f64> {
    s.metrics.as_ref()?.get(key).copied()
}

/// Each pair of samples one after the other of a node, both in [a, b].
fn pairs<'a>(
    series: &'a [&'a Sample],
    a: f64,
    b: f64,
) -> impl Iterator<Item = (&'a Sample, &'a Sample)> {
    series
        .windows(2)
        .map(|w| (w[0], w[1]))
        .filter(move |(s0, s1)| s0.t >= a && s1.t <= b)
}

/// What a counter rose by over a pair: a node that started again counts
/// from nothing.
fn rose(v0: f64, v1: f64) -> f64 {
    if v1 >= v0 { v1 - v0 } else { v1 }
}

/// What `key` rose by over each pair of a relay's samples in [a, b] that
/// `keep` keeps.
fn rise(series: &[&Sample], key: &str, a: f64, b: f64, keep: &dyn Fn(f64, f64) -> bool) -> f64 {
    pairs(series, a, b)
        .filter(|(s0, s1)| keep(s0.t, s1.t))
        .filter_map(|(s0, s1)| Some(rose(metric(s0, key)?, metric(s1, key)?)))
        .sum()
}

/// The bounds of a histogram's buckets, in µs, as the route names them.
fn bounds() -> Vec<String> {
    let mut b: Vec<String> = (0..cordelia_core::protocol::LOAD_HISTOGRAM_BUCKETS)
        .map(|i| (1u64 << i).to_string())
        .collect();
    b.push("+Inf".into());
    b
}

/// A histogram's quantiles over what it gained in the pairs kept: the
/// count, and the bound of the bucket each of `qs` falls in (µs; `None`
/// for the last).
fn quantiles(
    series: &[&Sample],
    name: &str,
    label: &str,
    a: f64,
    b: f64,
    keep: &dyn Fn(f64, f64) -> bool,
    qs: &[f64],
) -> (f64, Vec<Option<u64>>) {
    let cumulative: Vec<(String, f64)> = bounds()
        .into_iter()
        .map(|le| {
            let key = format!("{name}_bucket{{{label},le=\"{le}\"}}");
            let n = rise(series, &key, a, b, keep);
            (le, n)
        })
        .collect();
    let total = cumulative.last().map_or(0.0, |(_, n)| *n);
    let at = qs
        .iter()
        .map(|q| {
            if total == 0.0 {
                return Some(0);
            }
            cumulative
                .iter()
                .find(|(_, n)| *n >= q * total)
                .and_then(|(le, _)| le.parse().ok())
        })
        .collect();
    (total, at)
}

fn us(v: Option<u64>) -> String {
    match v {
        Some(v) if v >= 1000 => format!("{:.1} ms", v as f64 / 1000.0),
        Some(v) => format!("{v} µs"),
        None => "over 16 s".into(),
    }
}

/// The median and the most of `values`.
fn median_most(values: &[f64]) -> Option<(f64, f64)> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    Some((v[v.len() / 2], v[v.len() - 1]))
}

fn quantile(values: &[f64], q: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    let i = ((q * v.len() as f64).ceil() as usize).clamp(1, v.len()) - 1;
    Some(v[i])
}

fn mm(values: &[f64], unit: &str) -> String {
    match median_most(values) {
        Some((m, w)) => format!("median {m:.2} {unit}, worst {w:.2} {unit}"),
        None => "no value".into(),
    }
}

// ── The run, as the report reads it ─────────────────────────────────

struct Read<'a> {
    run: &'a Run,
    lives: Lives,
    samples: Vec<Sample>,
    machine: Vec<crate::fleet::MachineSample>,
    start: f64,
    end: f64,
    apart: Vec<(f64, f64)>,
    tps: f64,
}

impl Read<'_> {
    fn series(&self, node: usize) -> Vec<&Sample> {
        let mut s: Vec<&Sample> = self.samples.iter().filter(|s| s.node == node).collect();
        s.sort_by(|a, b| a.t.total_cmp(&b.t));
        s
    }

    fn is_apart(&self, t0: f64, t1: f64) -> bool {
        self.apart.iter().any(|(a, b)| t0 < *b && t1 > *a)
    }

    fn hours(&self) -> f64 {
        (self.end - self.start) / 3600.0
    }

    fn person_of(&self, node: usize) -> Option<(usize, usize)> {
        match self.run.fleet.made[node].what {
            What::Device { person, device } => Some((person, device)),
            What::Relay(_) => None,
        }
    }

    fn devices(&self) -> Vec<usize> {
        (0..self.run.fleet.made.len())
            .filter(|i| self.person_of(*i).is_some())
            .collect()
    }
}

/// The summary of a run that did not start, and why (step 1).
pub fn refused(plan: &Plan, out: &Path, why: &str) -> Outcome {
    let summary = format!(
        "INVALID stage {} seed {} commit {} ({CHANGES})\n\nThe run did not start: {why}.\n",
        plan.stage.name(),
        plan.seed,
        commit()
    );
    std::fs::write(out.join("SUMMARY.md"), &summary).unwrap();
    Outcome {
        verdict: "INVALID".into(),
        summary,
        out: out.to_path_buf(),
        ..Outcome::default()
    }
}

/// The parts treated apart: each relay's outage and the five minutes
/// after it, and each removal's carry window (§3).
fn parts_apart(run: &Run) -> Vec<(f64, f64)> {
    let mut apart = Vec::new();
    let outage = run.outage.lock().unwrap().clone();
    if let (Some(a), Some(b)) = (outage.stopped, outage.started) {
        apart.push((a, b + run.plan.timing.after_start));
    }
    for r in run.removals.lock().unwrap().iter() {
        if let Some(line) = r.line_at {
            apart.push((line, r.carry_end.unwrap_or(line + r.bound)));
        }
    }
    apart
}

/// Write what the run leaves, and say what it came to.
pub fn write(run: &Run) -> Outcome {
    let (start, end) = match *run.window.lock().unwrap() {
        Some((s, e)) => (s, e.unwrap_or_else(|| run.fleet.clock.now())),
        None => (run.fleet.clock.now(), run.fleet.clock.now()),
    };
    let samples = run.samples.lock().unwrap();
    let read = Read {
        run,
        lives: Lives::new(&run.fleet.changes.lock().unwrap(), run.fleet.made.len()),
        samples: samples.nodes.clone(),
        machine: samples.machine.clone(),
        start,
        end,
        apart: parts_apart(run),
        tps: crate::machine::ticks_a_second() as f64,
    };
    drop(samples);
    let observer = run.observer.lock().unwrap();
    let edits = Edits::of(&read, &observer);
    drop(observer);

    let (b6, rises) = bar_6(&read);
    let (b12, pulls) = bar_12(&read, &edits);
    let b12_holds = b12.verdict != Verdict::Fail;
    let bars = vec![
        bar_1(&read),
        bar_2(&read, &edits),
        bar_3(&read, &edits),
        bar_4(&read),
        bar_5(&read),
        b6,
        bar_7(&read),
        bar_8(&read),
        bar_9(&read),
        bar_10(&read, &edits),
        bar_11(&read),
        b12,
        bar_13(&read, &edits),
        bar_14(&read, &edits),
        bar_15(&read, &edits),
    ];
    let checks = checks(&read, &edits, b12_holds);

    let faults = run.fleet.faults.lock().unwrap().clone();
    let machine_fault = run.stopped_why.lock().unwrap().clone();
    let ending = the_end(run);
    let invalid = checks.iter().any(|c| c.verdict == Verdict::Fail) || machine_fault.is_some();
    let failed = bars.iter().any(|b| b.verdict == Verdict::Fail)
        || !faults.is_empty()
        || ending.iter().any(|(_, well)| !well);
    let verdict = match (invalid, failed) {
        (true, _) => "INVALID",
        (false, true) => "FAIL",
        (false, false) => "PASS",
    };

    let plan = &run.plan;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{verdict} stage {} seed {} commit {} ({CHANGES})\n",
        plan.stage.name(),
        plan.seed,
        commit()
    );
    let setup = run.setup.lock().unwrap().clone();
    let _ = writeln!(
        s,
        "Stage {}, seed {}: {} relays, {} devices of {} people, on {}. The window ran from {:.0} s \
         to {:.0} s of the run ({:.1} minutes){}.\n",
        plan.stage.name(),
        plan.seed,
        plan.relays,
        plan.population.devices(),
        plan.population.people.len(),
        setup.machine,
        start,
        end,
        (end - start) / 60.0,
        if run.cut.load(std::sync::atomic::Ordering::SeqCst) {
            ", and was cut: INVALID"
        } else {
            ""
        }
    );
    if !faults.is_empty() {
        let _ = writeln!(s, "It stopped early: {}.\n", faults.join("; "));
    }
    let _ = writeln!(s, "## The bars (decision 2026-10-22 §3)\n");
    for (n, b) in bars.iter().enumerate() {
        let _ = writeln!(
            s,
            "{}. {}: {}. Bar: {}. **{}**",
            n + 1,
            b.title,
            b.figure,
            b.bar,
            b.verdict.word()
        );
    }
    let _ = writeln!(s, "\n## Whether the run measured what it says (§6)\n");
    for (n, c) in checks.iter().enumerate() {
        let word = match c.verdict {
            Verdict::Fail => "INVALID",
            _ => "VALID",
        };
        let _ = writeln!(
            s,
            "{}. {}: {}. Check: {}. **{word}**",
            n + 1,
            c.title,
            c.figure,
            c.bar
        );
    }
    measures(&mut s, &read, &edits);
    let _ = writeln!(s, "\n## The end (step 10)\n");
    for (said, well) in &ending {
        let _ = writeln!(
            s,
            "- {said}: **{}**",
            if *well { "as it should" } else { "FAIL" }
        );
    }
    let _ = writeln!(s, "\n## The parts treated apart\n");
    let outage = run.outage.lock().unwrap().clone();
    match (outage.stopped, outage.started) {
        (Some(a), Some(b)) => {
            let _ = writeln!(
                s,
                "- the second relay's outage: stopped at {a:.0} s, started again at {b:.0} s, and \
                 treated apart to {:.0} s",
                b + plan.timing.after_start
            );
        }
        _ => {
            let _ = writeln!(s, "- no outage of a relay");
        }
    }
    for r in run.removals.lock().unwrap().iter() {
        let _ = writeln!(
            s,
            "- the carry window of person {}'s removal: from {} to {}",
            r.person,
            r.line_at.map_or("no line".into(), |t| format!("{t:.0} s")),
            r.carry_end
                .map_or("its bound".into(), |t| format!("{t:.0} s"))
        );
    }
    let _ = writeln!(s, "\n## The setup\n");
    let _ = writeln!(
        s,
        "- it took {:.0} s (from {:.0} s to {:.0} s of the run), ten people at a time",
        setup.ended - setup.started,
        setup.started,
        setup.ended
    );
    for r in 0..plan.relays {
        let i = run.fleet.relays[r];
        let series = read.series(i);
        let rss: Vec<f64> = series
            .iter()
            .filter(|x| x.t >= setup.started && x.t <= setup.ended)
            .filter_map(|x| x.proc.map(|p| p.rss_kib as f64 / 1024.0))
            .collect();
        let share = held_shares(&series, setup.started, setup.ended, &|_, _| true);
        let _ = writeln!(
            s,
            "- relay {}: memory {}; the lock held {}",
            r + 1,
            mm(&rss, "MiB"),
            mm(&share, "of a minute")
        );
    }
    if let Some((t, moved)) = setup.office_moved {
        let _ = writeln!(
            s,
            "- the office moved to its address by {t:.0} s: {}",
            if moved {
                "each relay held 5 connections from it"
            } else {
                "a relay did not hold 5 connections from it within two minutes"
            }
        );
    }
    let _ = writeln!(s, "- threads: {}", setup.thread_plan);
    let _ = writeln!(s, "\n## Every setting beyond the defaults\n");
    let relay = run.fleet.made[run.fleet.relays[0]]
        .settings
        .lock()
        .unwrap()
        .clone();
    let device = run
        .fleet
        .made
        .iter()
        .find(|m| matches!(m.what, What::Device { .. }))
        .map(|m| m.settings.lock().unwrap().clone());
    let _ = writeln!(s, "A relay:");
    for said in relay.beyond_defaults() {
        let _ = writeln!(s, "- {said}");
    }
    if let Some(device) = device {
        let _ = writeln!(s, "A device:");
        for said in device.beyond_defaults() {
            let _ = writeln!(s, "- {said}");
        }
    }
    let _ = writeln!(s, "The run:");
    let _ = writeln!(
        s,
        "- each relay lists the other by address and by key, since the run's relays have keys \
         of their own (rule 3 of §2.2)"
    );
    for said in plan.timing.beyond_the_record() {
        let _ = writeln!(s, "- {said}");
    }
    if plan.stage == crate::population::Stage::Small {
        let _ = writeln!(
            s,
            "- the small run of §6 test 4: its times off are fixed (one device off and on), and \
             edits a minute are reported and not barred in bar 12, since a window of minutes \
             holds too few edits for a tenth"
        );
    }
    let _ = writeln!(s, "- the threshold of bar 6: {}", growth_said(plan));
    let _ = writeln!(
        s,
        "- the p99 of the devices' rises in this run, for bar 6 at a later stage: {}",
        quantile(&rises, 0.99).map_or("no value".into(), |r| format!("{r:.2} MiB an hour"))
    );
    std::fs::write(run.out.join("SUMMARY.md"), &s).unwrap();
    std::fs::write(run.out.join("edits.csv"), edits.csv(&read)).unwrap();
    changes_written(run);
    let arrived = edits.pairs.iter().filter(|p| p.arrived.is_some()).count();
    let gone = edits
        .pairs
        .iter()
        .filter(|p| p.arrived.is_none() && p.gone)
        .count();
    Outcome {
        verdict: verdict.into(),
        summary: s,
        out: run.out.clone(),
        bars: bars
            .iter()
            .map(|b| (b.title.clone(), b.verdict.word().to_string()))
            .collect(),
        checks: checks
            .iter()
            .map(|c| (c.title.clone(), c.verdict != Verdict::Fail))
            .collect(),
        pulls,
        waited: (
            edits.pairs.len(),
            arrived,
            edits.pairs.len() - arrived - gone,
            gone,
        ),
    }
}

/// How the run ended (step 10): each node told to stop stopped within
/// NODE_STOP_TIMEOUT_SECS; no pid it started is left; and every key each
/// relay held a connection from at the end is one of the run's (§4.3,
/// rule 1).
fn the_end(run: &Run) -> Vec<(String, bool)> {
    use cordelia_core::protocol::NODE_STOP_TIMEOUT_SECS;
    let mut said = Vec::new();
    let stops = run.stops_at_end.lock().unwrap().clone();
    let slowest = stops.iter().map(|(_, took, _)| *took).fold(0.0, f64::max);
    let badly: Vec<String> = stops
        .iter()
        .filter(|(_, _, well)| !well)
        .map(|(i, took, _)| format!("{} ({took:.1} s)", run.fleet.made[*i].label))
        .collect();
    said.push((
        format!(
            "{} nodes told to stop, the slowest in {slowest:.1} s; {} not stopped as they should within {NODE_STOP_TIMEOUT_SECS} s{}",
            stops.len(),
            badly.len(),
            match badly.is_empty() {
                true => String::new(),
                false => format!(" ({})", badly.join(", ")),
            }
        ),
        badly.is_empty(),
    ));
    let left = run.pids_left.lock().unwrap().clone();
    said.push((
        format!("{} of the pids it started are left", left.len()),
        left.is_empty(),
    ));
    let ours: HashSet<String> = run.fleet.made.iter().map(|m| m.key.clone()).collect();
    for (r, keys) in run.peers_at_end.lock().unwrap().iter() {
        let strangers = keys.iter().filter(|k| !ours.contains(*k)).count();
        said.push((
            format!(
                "relay {} held connections from {} keys at the end, {strangers} of them not the run's",
                r + 1,
                keys.len()
            ),
            strangers == 0,
        ));
    }
    said
}

/// Each start, freeze, going on and stop of each node, and how each stop
/// ended, as lines of `samples.jsonl` (§1.3): what the harness did to each
/// process, beside what it read of it.
fn changes_written(run: &Run) {
    use std::io::Write as _;
    let Ok(mut file) = std::fs::OpenOptions::new()
        .append(true)
        .open(run.out.join("samples.jsonl"))
    else {
        return;
    };
    for c in run.fleet.changes.lock().unwrap().iter() {
        let became = match c.is {
            Is::NotStarted => "not started",
            Is::Running => "running",
            Is::Frozen => "frozen",
            Is::Stopped => "stopped",
        };
        let mut line = serde_json::json!({
            "t": (c.t * 10.0).round() / 10.0,
            "node": run.fleet.made[c.node].label,
            "became": became,
        });
        if let Some((took, status)) = &c.ended {
            line["stopped_in_secs"] = ((took * 10.0).round() / 10.0).into();
            line["status"] = status.clone().into();
        }
        let _ = writeln!(file, "{line}");
    }
}

fn growth_said(plan: &Plan) -> String {
    match (plan.stage, plan.device_growth) {
        (_, Some(g)) => format!("{:.2} MiB an hour (stage 100's p99, given)", g.max(2.0)),
        (crate::population::Stage::OneNinety, None) => {
            "2 MiB an hour: stage 100's p99 was not given (CORDELIA_SCALE_DEVICE_GROWTH)".into()
        }
        _ => "2 MiB an hour".into(),
    }
}

// ── The edits ───────────────────────────────────────────────────────

/// One edit on one other device of its person.
#[derive(Debug, Clone)]
struct Pair {
    edit: crate::observer::Written,
    device: usize,
    node: usize,
    arrived: Option<crate::observer::Arrival>,
    /// Replaced by intent: its writer's next edit held it.
    replaced: bool,
    gone: bool,
}

struct Edits {
    window: Vec<crate::observer::Written>,
    pairs: Vec<Pair>,
    written: usize,
    conflict_copies: usize,
    pending_at_end: usize,
    gaps: Vec<f64>,
}

impl Edits {
    fn of(read: &Read, observer: &crate::observer::Observer) -> Edits {
        let replaced: HashSet<u64> = observer.edits.iter().filter_map(|e| e.replaced).collect();
        let gone: HashSet<(u64, usize)> = observer.gone.iter().copied().collect();
        let window: Vec<_> = observer
            .edits
            .iter()
            .filter(|e| e.at >= read.start)
            .cloned()
            .collect();
        let mut pairs = Vec::new();
        for (number, device) in &observer.waited {
            let Some(edit) = observer.edit(*number) else {
                continue;
            };
            pairs.push(Pair {
                edit: edit.clone(),
                device: *device,
                node: read.run.fleet.device(edit.person, *device),
                arrived: observer.arrivals.get(&(*number, *device)).copied(),
                replaced: replaced.contains(number),
                gone: gone.contains(&(*number, *device)),
            });
        }
        let mut conflict_copies = 0;
        for folder in read.run.folders.values() {
            conflict_copies += std::fs::read_dir(folder)
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().contains(".conflict-"))
                .count();
        }
        Edits {
            written: window.len(),
            window,
            pairs,
            conflict_copies,
            pending_at_end: observer.pending(),
            gaps: observer.gaps.clone(),
        }
    }

    fn of_person(&self, read: &Read, office: bool) -> impl Iterator<Item = &Pair> {
        let people = &read.run.plan.population.people;
        self.pairs
            .iter()
            .filter(move |p| people[p.edit.person].office == office)
    }

    fn latency(p: &Pair) -> Option<f64> {
        p.arrived.map(|a| a.at - p.edit.at)
    }

    fn csv(&self, read: &Read) -> String {
        let mut out = String::from(
            "edit,person,profile,writer,device,name,file,size,burst,new,written_s,arrived_s,latency_s,in_copy,replaced_by_intent,outcome\n",
        );
        for p in &self.pairs {
            let profile = read.run.plan.population.people[p.edit.person]
                .profile
                .name();
            let outcome = match (p.arrived, p.gone, p.replaced) {
                (Some(_), _, _) => "arrived",
                (None, true, _) => "device removed",
                (None, false, true) => "replaced by intent",
                (None, false, false) => "not arrived",
            };
            let _ = writeln!(
                out,
                "{},{},{},{},{},{},{},{},{},{},{:.2},{},{},{},{},{}",
                p.edit.number,
                p.edit.person,
                profile,
                p.edit.writer,
                p.device,
                crate::population::name_of(p.edit.name),
                p.edit.file,
                p.edit.size,
                p.edit.burst,
                p.edit.new,
                p.edit.at,
                p.arrived.map_or(String::new(), |a| format!("{:.2}", a.at)),
                Self::latency(p).map_or(String::new(), |l| format!("{l:.2}")),
                p.arrived.is_some_and(|a| a.in_copy),
                p.replaced,
                outcome
            );
        }
        out
    }
}

// ── The bars ────────────────────────────────────────────────────────

fn relay_series<'a>(read: &'a Read, r: usize) -> Vec<&'a Sample> {
    read.series(read.run.fleet.relays[r])
}

/// Whether a device's interval holds the minute of a connection's proofs:
/// it started or went on within a minute, a relay started again within a
/// minute, warm churn closed a connection at a relay, or its connections
/// changed.
fn proofs_minute(read: &Read, node: usize, s0: &Sample, s1: &Sample) -> bool {
    let (a, b) = (s0.t - 60.0, s1.t);
    if read.lives.starts_in(node, a, b) {
        return true;
    }
    for r in 0..read.run.plan.relays {
        let i = read.run.fleet.relays[r];
        if read.lives.starts_in(i, a, b) {
            return true;
        }
        let series = read.series(i);
        let closed = |key: &str| rise(&series, key, a, b + 60.0, &|_, _| true);
        if closed("cordelia_closed_by_warm_churn_total{peer=\"device\"}") > 0.0 {
            return true;
        }
    }
    s0.connections != s1.connections
}

fn bar_1(read: &Read) -> Line {
    let keep = |t0: f64, t1: f64| !read.is_apart(t0, t1);
    let mut at_relays = 0.0;
    for r in 0..read.run.plan.relays {
        let series = relay_series(read, r);
        for kind in KINDS {
            let key =
                format!("cordelia_answers_total{{kind=\"{kind}\",answer=\"refused_for_rate\"}}");
            at_relays += rise(&series, &key, read.start, read.end, &keep);
        }
    }
    let (mut held, mut excused) = (0.0, 0.0);
    for i in read.devices() {
        let series = read.series(i);
        for (s0, s1) in pairs(&series, read.start, read.end) {
            let (Some(d0), Some(d1)) = (s0.device, s1.device) else {
                continue;
            };
            let n: f64 = (0..2).map(|r| rose(d0.held_back[r], d1.held_back[r])).sum();
            if n == 0.0 {
                continue;
            }
            if read.is_apart(s0.t, s1.t) || proofs_minute(read, i, s0, s1) {
                excused += n;
            } else {
                held += n;
            }
        }
    }
    line(
        "No request is refused for rate",
        format!(
            "{at_relays:.0} refused for rate at the relays; {held:.0} held back by a device's own \
             pace outside a connection's proofs and the carry windows, and {excused:.0} within them"
        ),
        "none refused at either relay, and none held back but in a connection's proofs or a carry",
        at_relays == 0.0 && held == 0.0,
    )
}

/// Bar 2's figures over `pairs`: p50, p95, the most, and those that did
/// not arrive within 120 s while their device ran.
fn latencies<'a>(read: &Read, pairs: impl Iterator<Item = &'a Pair>) -> (Vec<f64>, usize) {
    let mut l = Vec::new();
    let mut late = 0;
    for p in pairs {
        if p.gone || p.edit.at < read.start {
            continue;
        }
        match Edits::latency(p) {
            Some(latency)
                if read
                    .lives
                    .ran_through(p.node, p.edit.at, p.edit.at + latency) =>
            {
                l.push(latency);
            }
            Some(_) => {}
            None if !p.replaced && read.lives.ran_through(p.node, p.edit.at, p.edit.at + 120.0) => {
                late += 1;
            }
            None => {}
        }
    }
    (l, late)
}

/// When an edit's way to a device ends: its arrival there, or 120 s after
/// it was written where it did not arrive.
fn journey_end(p: &Pair) -> f64 {
    p.arrived.map_or(p.edit.at + 120.0, |a| a.at)
}

fn bar_2(read: &Read, edits: &Edits) -> Line {
    let people = &read.run.plan.population.people;
    // An edit whose way from its writing to its arrival (or to 120 s, where
    // it did not arrive) crosses a part treated apart is treated apart.
    let outside = |p: &&Pair| !read.is_apart(p.edit.at, journey_end(p));
    let (both, late_both) = latencies(
        read,
        edits
            .of_person(read, false)
            .filter(|p| !people[p.edit.person].split)
            .filter(outside),
    );
    let (split, late_split) = latencies(
        read,
        edits
            .of_person(read, false)
            .filter(|p| people[p.edit.person].split)
            .filter(outside),
    );
    let p50 = quantile(&both, 0.5).unwrap_or(0.0);
    let p95 = quantile(&both, 0.95).unwrap_or(0.0);
    let most = both.iter().copied().fold(0.0, f64::max);
    let sp95 = quantile(&split, 0.95).unwrap_or(0.0);
    let smost = split.iter().copied().fold(0.0, f64::max);
    let holds = !both.is_empty()
        && p50 <= 12.0
        && p95 <= 25.0
        && most <= 120.0
        && late_both == 0
        && sp95 <= 40.0
        && smost <= 120.0
        && late_split == 0;
    line(
        "Sync latency",
        format!(
            "set up with both relays: {} arrivals, p50 {p50:.1} s, p95 {p95:.1} s, the most \
             {most:.1} s, {late_both} not arrived within 120 s; split between the relays: {} \
             arrivals, p95 {sp95:.1} s, the most {smost:.1} s, {late_split} not arrived within 120 s",
            both.len(),
            split.len()
        ),
        "p50 at most 12 s, p95 at most 25 s, every edit within 120 s; split: p95 at most 40 s, \
         every edit within 120 s",
        holds,
    )
}

fn bar_3(read: &Read, edits: &Edits) -> Line {
    let lost: Vec<&Pair> = edits
        .of_person(read, false)
        .filter(|p| p.edit.at >= read.start && p.arrived.is_none() && !p.gone && !p.replaced)
        .collect();
    // Catching up: each time a device was off in the window, the edits its
    // person made meanwhile, within 60 s of its running again.
    let mut worst: f64 = 0.0;
    let mut slow = 0;
    let mut times_off = 0;
    for i in read.devices() {
        let Some((k, _)) = read.person_of(i) else {
            continue;
        };
        if read.run.plan.population.people[k].office {
            continue;
        }
        for (off, on) in read.lives.downs(i, read.start, read.end) {
            let Some(on) = on else { continue };
            times_off += 1;
            for p in edits.pairs.iter().filter(|p| {
                p.node == i && p.edit.at >= off && p.edit.at <= on && !p.replaced && !p.gone
            }) {
                match p.arrived {
                    Some(a) => {
                        worst = worst.max(a.at - on);
                        if a.at - on > 60.0 {
                            slow += 1;
                        }
                    }
                    None => slow += 1,
                }
            }
        }
    }
    let examples: Vec<String> = lost
        .iter()
        .take(3)
        .map(|p| {
            format!(
                "edit {} at person {}'s device {}",
                p.edit.number, p.edit.person, p.device
            )
        })
        .collect();
    line(
        "No edit is lost, and a device catches up",
        format!(
            "{} edits of the window on other devices; {} not found by the end{}; after {} times \
             off, the slowest catch-up {:.1} s, {} edits not held within 60 s",
            edits
                .of_person(read, false)
                .filter(|p| p.edit.at >= read.start && !p.gone)
                .count(),
            lost.len(),
            match examples.is_empty() {
                true => String::new(),
                false => format!(" ({})", examples.join(", ")),
            },
            times_off,
            worst,
            slow
        ),
        "every edit's own line on every other device by the end; a device that was off holds \
         its person's edits within 60 s of running again",
        lost.is_empty() && slow == 0,
    )
}

const LOCK: &str = "cordelia_lock";
const READS: [&str; 3] = ["pull", "show_short", "proof"];
const RELAY_TAKES: [&str; 10] = [
    "show_whole",
    "show_short",
    "proof",
    "pull",
    "push",
    "relays",
    "sweep",
    "checkpoint",
    "api",
    "other",
];

/// The share of each pair's time that the lock was held, of every kind.
fn held_shares(series: &[&Sample], a: f64, b: f64, keep: &dyn Fn(f64, f64) -> bool) -> Vec<f64> {
    pairs(series, a, b)
        .filter(|(s0, s1)| keep(s0.t, s1.t) && s1.t > s0.t)
        .map(|(s0, s1)| {
            let held: f64 = RELAY_TAKES
                .iter()
                .chain(["pass", "cycle"].iter())
                .filter_map(|k| {
                    let key = format!("{LOCK}_hold_microseconds_sum{{kind=\"{k}\"}}");
                    Some(rose(metric(s0, &key)?, metric(s1, &key)?))
                })
                .sum();
            held / 1e6 / (s1.t - s0.t)
        })
        .collect()
}

/// Whether a quantile read as the bound of its bucket, `bound` µs, meets
/// a bar of `bar` µs: the buckets are powers of two, so the bucket that
/// holds the bar (to 1,024 µs for 1 ms, to 16,384 µs for 10 ms) cannot be
/// told from it.
fn within_bucket(bound: u64, bar: u64) -> bool {
    bound <= bar.next_power_of_two()
}

fn bar_4(read: &Read) -> Line {
    let keep = |t0: f64, t1: f64| !read.is_apart(t0, t1);
    let mut said = Vec::new();
    let mut holds = true;
    for r in 0..read.run.plan.relays {
        let series = relay_series(read, r);
        let mut worst_wait = (0u64, "");
        let mut worst_read = (0u64, "");
        let (mut over_250, mut over_50) = (0.0, 0.0);
        for kind in RELAY_TAKES {
            let label = format!("kind=\"{kind}\"");
            let (n, w) = quantiles(
                &series,
                &format!("{LOCK}_wait_microseconds"),
                &label,
                read.start,
                read.end,
                &keep,
                &[0.99],
            );
            if n > 0.0 {
                let w99 = w[0].unwrap_or(u64::MAX);
                if w99 > worst_wait.0 {
                    worst_wait = (w99, kind);
                }
                holds &= within_bucket(w99, 10_000);
            }
            if READS.contains(&kind) {
                let (n, h) = quantiles(
                    &series,
                    &format!("{LOCK}_hold_microseconds"),
                    &label,
                    read.start,
                    read.end,
                    &keep,
                    &[0.99],
                );
                if n > 0.0 {
                    let h99 = h[0].unwrap_or(u64::MAX);
                    if h99 > worst_read.0 {
                        worst_read = (h99, kind);
                    }
                    holds &= within_bucket(h99, 1_000);
                }
            } else {
                let at = |ms: &str| {
                    rise(
                        &series,
                        &format!("{LOCK}_hold_microseconds_over{{{label},ms=\"{ms}\"}}"),
                        read.start,
                        read.end,
                        &keep,
                    )
                };
                over_250 += at("250");
                over_50 += at("50");
            }
        }
        let shares = held_shares(&series, read.start, read.end, &keep);
        let most_share = shares.iter().copied().fold(0.0, f64::max);
        holds &= over_250 == 0.0 && over_50 <= 10.0 && most_share <= 0.25;
        said.push(format!(
            "relay {}: wait p99 at most {} ({}), a read's hold p99 at most {} ({}), {over_250:.0} \
             other holds over 250 ms and {over_50:.0} over 50 ms, the lock held at most {:.1}% of \
             a minute",
            r + 1,
            us(Some(worst_wait.0)),
            if worst_wait.1.is_empty() {
                "none"
            } else {
                worst_wait.1
            },
            us(Some(worst_read.0)),
            if worst_read.1.is_empty() {
                "none"
            } else {
                worst_read.1
            },
            most_share * 100.0
        ));
    }
    line(
        "A relay's lock, by kind",
        said.join("; "),
        "each kind's wait p99 at most 10 ms; a read's hold p99 at most 1 ms; every other hold \
         under 250 ms and at most 10 over 50 ms; held at most a quarter of any minute (a p99 is \
         read as its bucket's bound, a power of two of µs: the bucket that holds 1 ms ends at \
         1,024 µs, and the one that holds 10 ms at 16,384 µs)",
        holds,
    )
}

fn bar_5(read: &Read) -> Line {
    let keep = |t0: f64, t1: f64| !read.is_apart(t0, t1);
    let allowed = read.hours().ceil().max(1.0);
    let (mut worst, mut over, mut given_up) = (0.0f64, 0, 0.0);
    for i in read.devices() {
        let series = read.series(i);
        let mut n = 0.0;
        for (s0, s1) in pairs(&series, read.start, read.end) {
            let (Some(d0), Some(d1)) = (s0.device, s1.device) else {
                continue;
            };
            given_up += rose(d0.given_up, d1.given_up);
            if keep(s0.t, s1.t) {
                n += rose(d0.waits_over_100, d1.waits_over_100);
            }
        }
        worst = worst.max(n);
        if n > allowed {
            over += 1;
        }
    }
    line(
        "A device's lock",
        format!(
            "the most waits over 100 ms of one device: {worst:.0}; {over} devices over the bar; \
             {given_up:.0} waits given up (a summary that did not have the lock)"
        ),
        &format!(
            "no more than one wait over 100 ms for each device in each hour ({allowed:.0} here)"
        ),
        over == 0,
    )
}

/// What a series rose by in each half of the window, in MiB an hour, over
/// its longest stretch in that half with no start; `None` where that
/// stretch is under a quarter of the half.
fn halves(series: &[&Sample], read: &Read, node: usize) -> Option<(f64, f64)> {
    let mid = (read.start + read.end) / 2.0;
    let half = (mid - read.start).max(1.0);
    let rise_in = |a: f64, b: f64| -> Option<f64> {
        let mut best: Option<(f64, f64, f64)> = None;
        let mut first: Option<&Sample> = None;
        let rss = |s: &Sample| s.proc.map_or(0.0, |p| p.rss_kib as f64);
        // Outside the parts treated apart: a relay that starts again warms
        // up there.
        for s in series
            .iter()
            .filter(|s| s.t >= a && s.t <= b && s.proc.is_some() && !read.is_apart(s.t, s.t))
        {
            // A start between two samples, or a part treated apart, begins
            // a stretch of its own.
            if let Some(f) = first
                && (read.lives.starts_in(node, f.t, s.t) || read.is_apart(f.t, s.t))
            {
                first = None;
            }
            let f = *first.get_or_insert(s);
            let long = s.t - f.t;
            if best.is_none_or(|(_, _, b)| long > b) {
                best = Some((rss(f), rss(s), long));
            }
        }
        let (from, to, long) = best?;
        (long >= half / 4.0).then(|| (to - from) / 1024.0 / (long / 3600.0))
    };
    Some((rise_in(read.start, mid)?, rise_in(mid, read.end)?))
}

fn bar_6(read: &Read) -> (Line, Vec<f64>) {
    let threshold = read.run.plan.device_growth.unwrap_or(2.0).max(2.0);
    let (mut worst, mut grows, mut tested) = (0.0f64, Vec::new(), 0);
    let mut rises = Vec::new();
    for i in read.devices() {
        let series = read.series(i);
        for s in series
            .iter()
            .filter(|s| s.t >= read.start && s.t <= read.end)
        {
            if let Some(p) = s.proc {
                worst = worst.max(p.rss_kib as f64 / 1024.0);
            }
        }
        if let Some((a, b)) = halves(&series, read, i) {
            tested += 1;
            rises.push(a.max(b));
            if a > threshold && b > threshold {
                grows.push(read.run.fleet.made[i].label.clone());
            }
        }
    }
    let n = read.devices().len().max(1);
    let holds = worst <= 64.0 && (grows.len() as f64) <= 0.01 * n as f64;
    (
        line(
            "A device's memory",
            format!(
                "the most RSS of a device {worst:.1} MiB; {} of {tested} devices tested grow in \
                 both halves{}",
                grows.len(),
                match grows.is_empty() {
                    true => String::new(),
                    false => format!(" ({})", grows.join(", ")),
                }
            ),
            &format!(
                "RSS at most 64 MiB at every sample, and no more than 1% of devices growing by \
                 over {threshold:.1} MiB an hour in both halves (one device growing in two runs \
                 of three is read across the stage's summaries)"
            ),
            holds,
        ),
        rises,
    )
}

fn bar_7(read: &Read) -> Line {
    let mut said = Vec::new();
    let mut holds = true;
    for r in 0..read.run.plan.relays {
        let i = read.run.fleet.relays[r];
        let series = read.series(i);
        let mut over = 0;
        let mut worst = 0.0f64;
        for s in series
            .iter()
            .filter(|s| s.t >= read.start && s.t <= read.end)
        {
            let (Some(p), Some(open)) = (s.proc, metric(s, "cordelia_connections_open")) else {
                continue;
            };
            let rss = p.rss_kib as f64 / 1024.0;
            worst = worst.max(rss);
            if rss > 64.0 + open * 384.0 / 1024.0 {
                over += 1;
            }
        }
        let grows = halves(&series, read, i).is_some_and(|(a, b)| {
            let base = series
                .first()
                .and_then(|s| s.proc)
                .map_or(20.0, |p| p.rss_kib as f64 / 1024.0);
            a > 0.02 * base && b > 0.02 * base
        });
        holds &= over == 0 && !grows;
        said.push(format!(
            "relay {}: the most RSS {worst:.1} MiB, {over} samples over the bar, {}",
            r + 1,
            if grows {
                "growing in both halves"
            } else {
                "no persistent growth"
            }
        ));
    }
    line(
        "A relay's memory in ordinary use",
        said.join("; "),
        "RSS at most 64 MiB and 384 KiB for each open connection, and no growth of 2% of its \
         RSS an hour in both halves",
        holds,
    )
}

/// A relay's share of a core over each pair, and over all of them.
fn cpu(read: &Read, series: &[&Sample]) -> (Vec<f64>, f64) {
    let mut each = Vec::new();
    let (mut ticks, mut secs) = (0.0, 0.0);
    for (s0, s1) in pairs(series, read.start, read.end) {
        let (Some(p0), Some(p1)) = (s0.proc, s1.proc) else {
            continue;
        };
        if s1.t <= s0.t {
            continue;
        }
        let t = rose(p0.ticks as f64, p1.ticks as f64) / read.tps;
        each.push(t / (s1.t - s0.t));
        ticks += t;
        secs += s1.t - s0.t;
    }
    let mean = if secs > 0.0 { ticks / secs } else { 0.0 };
    (each, mean)
}

fn bar_8(read: &Read) -> Line {
    let mut said = Vec::new();
    let mut holds = true;
    for r in 0..read.run.plan.relays {
        let series = relay_series(read, r);
        let (each, mean) = cpu(read, &series);
        let most = each.iter().copied().fold(0.0, f64::max);
        holds &= mean <= 0.5 && most <= 1.0;
        said.push(format!(
            "relay {}: {:.1}% of a core on average, {:.1}% in its busiest minute",
            r + 1,
            mean * 100.0,
            most * 100.0
        ));
    }
    line(
        "A relay's CPU",
        said.join("; "),
        "at most half a core on average over the window, and one core in any minute",
        holds,
    )
}

fn bar_9(read: &Read) -> Line {
    let plan = &read.run.plan;
    let people = &plan.population.people;
    let has_office = plan.stage.has_office();
    let mut said = Vec::new();
    let mut holds = true;
    for r in 0..plan.relays {
        let i = read.run.fleet.relays[r];
        let other = (plan.relays == 2).then(|| read.run.fleet.relays[1 - r]);
        let series = read.series(i);
        let (mut samples, mut outside) = (0, Vec::new());
        for (n, s) in series.iter().enumerate() {
            if s.t < read.start || s.t > read.end {
                continue;
            }
            let Some(open) = metric(s, "cordelia_connections_open") else {
                continue;
            };
            // Within 120 s of this relay's start again: not checked.
            if read
                .lives
                .running_since(i, s.t)
                .is_some_and(|since| s.t - since < 120.0 && since > read.start)
            {
                continue;
            }
            samples += 1;
            let (mut lo, mut hi) = (0.0, 0.0);
            for (k, d) in plan.population.each_device() {
                let p = &people[k];
                if p.office || !p.relays_of(d, plan.relays).contains(&r) {
                    continue;
                }
                let node = read.run.fleet.device(k, d);
                match read.lives.at(node, s.t) {
                    Is::Running => {
                        hi += 1.0;
                        if read
                            .lives
                            .running_since(node, s.t)
                            .is_some_and(|since| s.t - since >= 120.0)
                        {
                            lo += 1.0;
                        }
                    }
                    _ if read.lives.frozen_within(node, s.t, 90.0) => hi += 1.0,
                    _ => {}
                }
            }
            if has_office && read.run.setup.lock().unwrap().office_moved.is_some() {
                lo += 5.0;
                hi += 5.0;
            }
            // The other relay: one or two, but none while it is down or
            // within 120 s of its start again.
            let other_up = other.is_none_or(|o| {
                read.lives
                    .running_since(o, s.t)
                    .is_some_and(|since| s.t - since >= 120.0)
            });
            lo += if other.is_some() && other_up {
                1.0
            } else {
                0.0
            };
            hi += if other.is_some() { 2.0 } else { 0.0 };
            // A device whose connection warm churn closed dials the relay
            // again 10 s later at the soonest (the record of a relay out of
            // reach §2): those closed in the last 150 s are not looked for.
            let since = s.t - 150.0;
            let closed: f64 = series[..=n]
                .windows(2)
                .filter(|w| w[1].t >= since)
                .filter_map(|w| {
                    let key = "cordelia_closed_by_warm_churn_total{peer=\"device\"}";
                    Some(rose(metric(w[0], key)?, metric(w[1], key)?))
                })
                .sum();
            lo = (lo - closed).max(0.0);
            if open < lo || open > hi {
                outside.push(format!(
                    "{open:.0} at {:.0} s (band {lo:.0} to {hi:.0})",
                    s.t
                ));
            }
        }
        let keep = |_: f64, _: f64| true;
        let bound = rise(
            &series,
            "cordelia_connections_turned_away_total{why=\"bound\"}",
            read.start,
            read.end,
            &keep,
        );
        let subnet = rise(
            &series,
            "cordelia_connections_turned_away_total{why=\"subnet\"}",
            read.start,
            read.end,
            &keep,
        );
        holds &= outside.is_empty() && bound == 0.0 && subnet == 0.0;
        said.push(format!(
            "relay {}: {} of {samples} samples outside the band{}; turned away for the bound \
             {bound:.0}, for the subnet {subnet:.0}",
            r + 1,
            outside.len(),
            match outside.is_empty() {
                true => String::new(),
                false => format!(
                    " ({})",
                    outside
                        .iter()
                        .take(3)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
        ));
    }
    line(
        "Every running device stays connected",
        said.join("; "),
        "at each sample, between the devices running 120 s or more and every device running \
         or frozen in the last 90 s, with one or two for the other relay and the office's 5 \
         (less those warm churn closed in the last 150 s); none turned away for the bound or \
         the subnet",
        holds,
    )
}

fn bar_10(read: &Read, edits: &Edits) -> Line {
    let removals = read.run.removals.lock().unwrap().clone();
    if removals.is_empty() {
        return line(
            "A removal reaches every device, and its carry ends within its bound",
            "no removal was made".into(),
            "each other device applies within 30 s and each relay holds it within 30 s; the \
             carry window within T",
            false,
        );
    }
    let mut said = Vec::new();
    let mut holds = true;
    for r in &removals {
        let Some(line_at) = r.line_at else {
            holds = false;
            said.push(format!(
                "person {}: the change was not made ({})",
                r.person,
                r.failed.clone().unwrap_or_default()
            ));
            continue;
        };
        let spread = r
            .applied
            .iter()
            .map(|(_, at)| at.map_or(f64::INFINITY, |t| t - line_at))
            .fold(0.0, f64::max);
        let held = r
            .relays_hold
            .iter()
            .map(|(_, at)| at.map_or(f64::INFINITY, |t| t - line_at))
            .fold(0.0, f64::max);
        let carry = r.carry_end.map_or(f64::INFINITY, |t| t - line_at);
        let window_end = r.carry_end.unwrap_or(line_at + r.bound);
        // (c) The person's edits in the carry window arrive by its end and
        // 25 s.
        let late = edits
            .pairs
            .iter()
            .filter(|p| {
                p.edit.person == r.person && p.edit.at >= line_at && p.edit.at <= window_end
            })
            .filter(|p| !p.gone && !p.replaced)
            .filter(|p| p.arrived.is_none_or(|a| a.at > window_end + 25.0))
            .count();
        holds &= spread <= 30.0 && held <= 30.0 && carry <= r.bound && late == 0;
        said.push(format!(
            "person {} (change {}): applied by every other device in {spread:.1} s, held by \
             every relay in {held:.1} s; the carry window {carry:.1} s against T = {:.1} s for \
             {} bytes; {late} of the person's edits late in it",
            r.person,
            r.change.map_or("?".into(), |c| c.to_string()),
            r.bound,
            r.carried_bytes
        ));
    }
    line(
        "A removal reaches every device within 30 s, and its carry ends within its bound",
        said.join("; "),
        "(a) each other running device applies within 30 s, each relay holds it within 30 s; \
         (b) the carry window within T = 60 × B / 1,572,864 + 60 s; (c) each of the person's \
         edits in it by its end and 25 s",
        holds,
    )
}

/// From each device's log, the times a connection to a relay was closed
/// in the window, and how long until it was made again.
fn reconnects(read: &Read) -> Vec<f64> {
    let relay_hex: HashMap<String, usize> = (0..read.run.plan.relays)
        .map(|r| {
            (
                read.run.fleet.made[read.run.fleet.relays[r]]
                    .key_hex
                    .clone(),
                r,
            )
        })
        .collect();
    let outage = read.run.outage.lock().unwrap().clone();
    let in_outage = |t: f64| {
        outage.stopped.is_some_and(|a| t >= a - 5.0) && outage.started.is_none_or(|b| t <= b + 5.0)
    };
    let mut gaps = Vec::new();
    for i in read.devices() {
        let log = std::fs::read_to_string(read.run.fleet.made[i].node.log()).unwrap_or_default();
        let mut closed: HashMap<String, f64> = HashMap::new();
        for raw in log.lines() {
            let text = strip_ansi(raw);
            let Some(t) = text.split_whitespace().next().and_then(log_time) else {
                continue;
            };
            let t = read.run.fleet.clock.of_wall(t);
            let Some(peer) = text
                .split("peer=")
                .nth(1)
                .and_then(|r| r.split_whitespace().next())
            else {
                continue;
            };
            if !relay_hex.contains_key(peer) {
                continue;
            }
            if text.contains("peer connection closed")
                && t >= read.start
                && t <= read.end
                && !in_outage(t)
            {
                closed.insert(peer.to_string(), t);
            } else if text.contains("post_connect: checking peer roles")
                && let Some(at) = closed.remove(peer)
            {
                gaps.push(t - at);
            }
        }
    }
    gaps
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A log line's time, RFC 3339, in seconds since the epoch.
fn log_time(word: &str) -> Option<f64> {
    let t = chrono::DateTime::parse_from_rfc3339(word).ok()?;
    Some(t.timestamp() as f64 + f64::from(t.timestamp_subsec_micros()) / 1e6)
}

fn bar_11(read: &Read) -> Line {
    let keep = |_: f64, _: f64| true;
    let mut said = Vec::new();
    for r in 0..read.run.plan.relays {
        let series = relay_series(read, r);
        let at = |key: &str| rise(&series, key, read.start, read.end, &keep);
        let links: f64 = series
            .last()
            .and_then(|s| s.metrics.as_ref())
            .map(|m| {
                m.iter()
                    .filter(|(k, _)| k.starts_with("cordelia_relay_link_closures_total{"))
                    .map(|(_, v)| v)
                    .sum()
            })
            .unwrap_or(0.0);
        said.push(format!(
            "relay {}: {:.0} churns in the window, warm churn closed {:.0} connections of devices \
             and {:.0} of relays, {links:.0} closures of the link to the other relay since its \
             start",
            r + 1,
            at("cordelia_churns_total"),
            at("cordelia_closed_by_warm_churn_total{peer=\"device\"}"),
            at("cordelia_closed_by_warm_churn_total{peer=\"relay\"}"),
        ));
    }
    let gaps = reconnects(read);
    said.push(format!(
        "devices' connections to a relay closed in the window outside the outage and made \
         again: {}, {}",
        gaps.len(),
        mm(&gaps, "s")
    ));
    reported(
        "Churn",
        said.join("; "),
        "on the build without change A, reported and not barred: it decides whether change A \
         goes in before R1",
    )
}

/// The spans between a relay's samples that `keep` keeps in the window.
/// Pairs one after the other make one stretch, so that an edit near the
/// end of one pair has its push counted in the next.
fn kept_spans(series: &[&Sample], read: &Read, keep: &dyn Fn(f64, f64) -> bool) -> Vec<(f64, f64)> {
    let mut spans: Vec<(f64, f64)> = Vec::new();
    for (s0, s1) in pairs(series, read.start, read.end).filter(|(s0, s1)| keep(s0.t, s1.t)) {
        match spans.last_mut() {
            Some(last) if last.1 == s0.t => last.1 = s1.t,
            _ => spans.push((s0.t, s1.t)),
        }
    }
    spans
}

/// What the model asks of relay `r` over `spans`, for the time each device
/// set up with it ran there (§2.3): its pulls, six a minute of each
/// channel it pulls, and its shows, one for each pass, six a minute.
fn model_of(read: &Read, r: usize, spans: &[(f64, f64)]) -> (f64, f64) {
    let plan = &read.run.plan;
    let step = 5.0;
    let (mut pulls, mut shows) = (0.0, 0.0);
    let kept = |t: f64| spans.iter().any(|(a, b)| t >= *a && t < *b);
    for (k, d) in plan.population.each_device() {
        let p = &plan.population.people[k];
        if !p.relays_of(d, plan.relays).contains(&r) || p.office {
            continue;
        }
        let node = read.run.fleet.device(k, d);
        let mut t = read.start;
        while t < read.end {
            if kept(t) && read.lives.at(node, t) == Is::Running {
                pulls += p.profile.pulled() as f64 * 6.0 * step / 60.0;
                shows += 6.0 * step / 60.0;
            }
            t += step;
        }
    }
    // The office's 5 connected devices at each relay, all heavy.
    if plan.stage.has_office() {
        let minutes: f64 = spans.iter().map(|(a, b)| b - a).sum::<f64>() / 60.0;
        pulls += 5.0 * Profile::Heavy.pulled() as f64 * 6.0 * minutes;
        shows += 5.0 * 6.0 * minutes;
    }
    (pulls, shows)
}

fn bar_12(read: &Read, edits: &Edits) -> (Line, Vec<(f64, f64)>) {
    let plan = &read.run.plan;
    // Outside the parts treated apart (§3).
    let keep = |t0: f64, t1: f64| !read.is_apart(t0, t1);
    let mut said = Vec::new();
    let mut holds = true;
    let mut figures = Vec::new();
    let minutes = (read.end - read.start) / 60.0;
    for r in 0..plan.relays {
        let series = relay_series(read, r);
        let at = |kind: &str| {
            rise(
                &series,
                &format!("cordelia_requests_total{{kind=\"{kind}\"}}"),
                read.start,
                read.end,
                &keep,
            )
        };
        let spans = kept_spans(&series, read, &keep);
        let minutes = (spans.iter().map(|(a, b)| b - a).sum::<f64>() / 60.0).max(1e-9);
        let pulls = at("pull");
        let (model, model_shows) = model_of(read, r, &spans);
        let shows = at("show_whole") + at("show_short");
        let pushes = at("push");
        let writer_pushes = cycles_pushed(read, edits, r, &spans) as f64;
        figures.push((pulls, model));
        let within = model > 0.0 && (pulls - model).abs() <= model / 5.0;
        holds &= within && shows >= model_shows * 0.95 && pushes >= writer_pushes * 0.95;
        said.push(format!(
            "relay {}: pulls {:.0} a minute against the model's {:.0}; shows {:.0} a minute, at \
             least {:.0}; pushes {pushes:.0}, at least {writer_pushes:.0}",
            r + 1,
            pulls / minutes.max(1e-9),
            model / minutes.max(1e-9),
            shows / minutes.max(1e-9),
            model_shows / minutes.max(1e-9)
        ));
    }
    let model_edits: f64 = plan
        .population
        .people
        .iter()
        .map(|p| p.profile.model_edits_an_hour())
        .sum::<f64>()
        / 60.0;
    let measured = edits.written as f64 / minutes.max(1e-9);
    let edits_hold = (measured - model_edits).abs() <= model_edits / 10.0;
    let small = plan.stage == crate::population::Stage::Small;
    if !small {
        holds &= edits_hold;
    }
    said.push(format!(
        "edits {measured:.2} a minute against the model's {model_edits:.2} (the steady edits and \
         the bursts){}",
        if small {
            ", reported in the small run"
        } else {
            ""
        }
    ));
    (
        line(
            "The model holds",
            said.join("; "),
            "pulls within a fifth of §2.3 for the minutes each device was on; edits within a \
             tenth of §2.1; shows no fewer than one for each pass, and pushes no fewer than one \
             for each cycle of a writer's adapter that published an edit (both within 5% for \
             the edges of the window)",
            holds,
        ),
        figures,
    )
}

/// The pushes relay `r` is sent at the least for the window's edits in
/// `spans`: a device publishes what one cycle of its adapter found in one
/// push to each relay (`CYCLE_SECS`), so edits on a device less than a
/// cycle apart may share one, and edits further apart cannot. Each group
/// of a writer's edits that begins at least a cycle after the last began
/// is one push; a group is counted where it and the cycle after it lie in
/// one span, so that its push falls in that span too.
fn cycles_pushed(read: &Read, edits: &Edits, r: usize, spans: &[(f64, f64)]) -> usize {
    let plan = &read.run.plan;
    let cycle = cordelia_sync::claude::CYCLE_SECS as f64;
    let mut by_writer: HashMap<(usize, usize), Vec<f64>> = HashMap::new();
    for e in &edits.window {
        if plan.population.people[e.person]
            .relays_of(e.writer, plan.relays)
            .contains(&r)
        {
            by_writer
                .entry((e.person, e.writer))
                .or_default()
                .push(e.at);
        }
    }
    let mut pushes = 0;
    for times in by_writer.values_mut() {
        times.sort_by(f64::total_cmp);
        let mut begun: Option<f64> = None;
        for t in times.iter() {
            if begun.is_some_and(|b| *t < b + cycle) {
                continue;
            }
            begun = Some(*t);
            let within = spans
                .iter()
                .any(|(a, b)| *t >= *a && *t + 2.0 * cycle <= *b);
            pushes += usize::from(within);
        }
    }
    pushes
}

/// The room's model of one person: what a relay holds of them at the
/// least and at the most, as entries are counted (bar 13).
fn room_of(read: &Read, edits: &[&crate::observer::Written], k: usize) -> (f64, f64) {
    use cordelia_core::protocol::{CHANGE_ENTRY_BYTES, MAX_HAND_OVER_BYTES, entry_cost};
    let plan = &read.run.plan;
    let p = &plan.population.people[k];
    let removal = read
        .run
        .removals
        .lock()
        .unwrap()
        .iter()
        .find(|r| r.person == k)
        .and_then(|r| r.line_at.map(|t| (t, r.removed)));
    let mut least = 0.0;
    let mut most = 0.0;
    // Each slot: each author's newest entry, in each generation.
    let mut slots: HashMap<(usize, String), Vec<&crate::observer::Written>> = HashMap::new();
    for e in edits.iter().filter(|e| e.person == k) {
        slots.entry((e.name, e.file.clone())).or_default().push(e);
    }
    let remaining = p.devices - usize::from(removal.is_some());
    for writes in slots.values() {
        let before = |e: &&&crate::observer::Written| removal.is_none_or(|(t, _)| e.at < t);
        let mut newest: HashMap<usize, f64> = HashMap::new();
        for e in writes.iter().filter(before) {
            newest.insert(e.writer, entry_cost_of(&e.file, e.size) as f64);
        }
        let old: f64 = newest.values().sum();
        least += old;
        most += old;
        if let Some((t, removed)) = removal {
            // The new generation: each carried version once at the least,
            // once for each remaining device at the most, and what is
            // written after.
            let current = writes.iter().rfind(|e| e.at < t);
            let mut after: HashMap<usize, f64> = HashMap::new();
            for e in writes.iter().filter(|e| e.at >= t) {
                after.insert(e.writer, entry_cost_of(&e.file, e.size) as f64);
            }
            let written_after: f64 = after.values().sum();
            let carried = current.map_or(0.0, |e| entry_cost_of(&e.file, e.size) as f64);
            least += written_after + if after.is_empty() { carried } else { 0.0 };
            let not_rewritten = (0..p.devices)
                .filter(|d| *d != removed && !after.contains_key(d))
                .count() as f64;
            most += written_after + carried * not_rewritten.min(remaining as f64);
        }
    }
    // The other channels: the change entries of the phrase's channel; at
    // the most, a hand-over in each pair channel and the personal
    // channel's words.
    let changes = 1.0 + f64::from(u8::from(removal.is_some()));
    let generations = changes;
    least += changes * entry_cost(CHANGE_ENTRY_BYTES) as f64;
    most += changes * entry_cost(CHANGE_ENTRY_BYTES) as f64;
    least += generations * p.profile.names() as f64 * entry_cost(256) as f64;
    most += (p.devices - 1) as f64 * entry_cost(MAX_HAND_OVER_BYTES) as f64;
    most +=
        generations * ((p.profile.names() * 2 + p.devices * 4 + 8) as f64) * entry_cost(512) as f64;
    (least, most)
}

fn bar_13(read: &Read, edits: &Edits) -> Line {
    let observer = read.run.observer.lock().unwrap();
    let all: Vec<&crate::observer::Written> = observer.edits.iter().collect();
    let (mut least, mut most) = (0.0, 0.0);
    for k in 0..read.run.plan.population.people.len() {
        let (l, m) = room_of(read, &all, k);
        least += l;
        most += m;
    }
    drop(observer);
    // The conflict copies, each once.
    let copies = edits.conflict_copies as f64 * 2048.0;
    least += copies / 2.0;
    most += copies;
    let mut said = Vec::new();
    let mut holds = true;
    for r in 0..read.run.plan.relays {
        let series = relay_series(read, r);
        let room = series.iter().rev().find_map(|s| s.room);
        let keep = |_: f64, _: f64| true;
        let refused: f64 = KINDS
            .iter()
            .map(|kind| {
                rise(&series, &format!("cordelia_entries_refused_total{{kind=\"{kind}\",answer=\"refused_for_room\"}}"), 0.0, read.end + 1e9, &keep)
            })
            .sum();
        let Some((bytes, channels)) = room else {
            holds = false;
            said.push(format!("relay {}: its room was not read", r + 1));
            continue;
        };
        let b = bytes as f64;
        let within = b >= least * 0.95 && b <= most * 1.05;
        holds &= within && refused == 0.0;
        said.push(format!(
            "relay {}: {bytes} bytes in {channels} channels at the end, the model's {:.0} to {:.0}; \
             {refused:.0} entries refused for room",
            r + 1,
            least,
            most
        ));
    }
    line(
        "Room",
        said.join("; "),
        "each relay's room at the end between the model's least and most, each within 5%, and \
         nothing refused for room",
        holds,
    )
}

fn bar_14(read: &Read, edits: &Edits) -> Line {
    if !read.run.plan.stage.has_office() {
        return reported(
            "The office is as expected",
            "the small run has no office".into(),
            "exactly 5 connections from its address at each relay",
        );
    }
    let keep = |_: f64, _: f64| true;
    let mut said = Vec::new();
    let mut holds = true;
    let outage = read.run.outage.lock().unwrap().clone();
    for r in 0..read.run.plan.relays {
        let i = read.run.fleet.relays[r];
        let series = read.series(i);
        let mut off = Vec::new();
        for s in series
            .iter()
            .filter(|s| s.t >= read.start && s.t <= read.end)
        {
            let Some(peers) = &s.peers else { continue };
            if r == 1
                && outage.stopped.is_some_and(|a| s.t >= a)
                && outage.started.is_none_or(|b| s.t <= b + 120.0)
            {
                continue;
            }
            let n = peers
                .iter()
                .filter(|(_, a)| {
                    crate::fleet::ip_of(a)
                        == Some(std::net::IpAddr::V4(crate::population::OFFICE_ADDRESS))
                })
                .count();
            if n != 5 {
                off.push(format!("{n} at {:.0} s", s.t));
            }
        }
        let away = rise(
            &series,
            "cordelia_connections_turned_away_total{why=\"address\"}",
            read.start,
            read.end,
            &keep,
        );
        let for_a_time = rise(
            &series,
            "cordelia_connections_turned_away_total{why=\"refused_for_a_time\"}",
            read.start,
            read.end,
            &keep,
        );
        holds &= off.is_empty() && away > 0.0 && for_a_time == 0.0;
        said.push(format!(
            "relay {}: {} samples not 5 from the office's address{}; {away:.0} dials turned away \
             for the address, {for_a_time:.0} refusals for a time",
            r + 1,
            off.len(),
            if off.is_empty() {
                String::new()
            } else {
                format!(
                    " ({})",
                    off.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
                )
            }
        ));
    }
    let (office, late) = latencies(read, edits.of_person(read, true));
    said.push(format!(
        "the office's people: {} arrivals, {}, {late} not arrived within 120 s",
        office.len(),
        mm(&office, "s")
    ));
    line(
        "The office is as expected",
        said.join("; "),
        "exactly 5 from its address at each relay at every sample but the outage and the 120 s \
         after; other dials turned away and counted; no refusal for a time",
        holds,
    )
}

fn bar_15(read: &Read, edits: &Edits) -> Line {
    let outage = read.run.outage.lock().unwrap().clone();
    let (Some(stopped), Some(started)) = (outage.stopped, outage.started) else {
        return line(
            "A relay that stops is come back to",
            "the second relay did not stop".into(),
            "each device connected again within 120 s of its start",
            read.run.plan.relays == 1,
        );
    };
    // Of each device set up with it that ran through the 120 s after its
    // start.
    let back: Vec<f64> = outage
        .back
        .iter()
        .filter(|(i, _)| read.lives.ran_through(*i, started, started + 120.0))
        .map(|(_, at)| at.map_or(f64::INFINITY, |t| t - started))
        .collect();
    let slowest = back.iter().copied().fold(0.0, f64::max);
    let people = &read.run.plan.population.people;
    // Held up by the outage: its way from its writing to its arrival
    // crosses the outage.
    let during = |p: &&Pair| p.edit.at <= started && journey_end(p) >= stopped;
    let (both, late_both) = latencies(
        read,
        edits
            .of_person(read, false)
            .filter(|p| !people[p.edit.person].split)
            .filter(during),
    );
    let p50 = quantile(&both, 0.5).unwrap_or(0.0);
    let p95 = quantile(&both, 0.95).unwrap_or(0.0);
    let most = both.iter().copied().fold(0.0, f64::max);
    let split_late = edits
        .of_person(read, false)
        .filter(|p| people[p.edit.person].split)
        .filter(during)
        .filter(|p| !p.gone && !p.replaced)
        .filter(|p| p.arrived.is_none_or(|a| a.at - started > 120.0))
        .count();
    let keep = |_: f64, _: f64| true;
    let mut refused = 0.0;
    for r in 0..read.run.plan.relays {
        let series = relay_series(read, r);
        for kind in KINDS {
            refused += rise(
                &series,
                &format!("cordelia_answers_total{{kind=\"{kind}\",answer=\"refused_for_rate\"}}"),
                started,
                started + 300.0,
                &keep,
            );
        }
    }
    let series = relay_series(read, 1);
    let after = |key: &str| rise(&series, key, started, started + 300.0, &keep);
    let rss: Vec<f64> = series
        .iter()
        .filter(|s| s.t >= started && s.t <= started + 300.0)
        .filter_map(|s| s.proc.map(|p| p.rss_kib as f64 / 1024.0))
        .collect();
    let holds = slowest <= 120.0
        && (both.is_empty() || (p50 <= 12.0 && p95 <= 25.0 && most <= 120.0))
        && late_both == 0
        && split_late == 0
        && refused == 0.0;
    line(
        "A relay that stops is come back to",
        format!(
            "{} devices connected again, the slowest {slowest:.0} s after its start; through the \
             outage, {} arrivals at p50 {p50:.1} s, p95 {p95:.1} s, the most {most:.1} s, \
             {late_both} not within 120 s; {split_late} split people's edits later than 120 s \
             after the start; {refused:.0} refused for rate in the five minutes after; in those \
             minutes the relay was asked {:.0} pulls and {:.0} pushes, held its lock {} of a \
             minute, and its memory was {}",
            back.len(),
            both.len(),
            after("cordelia_requests_total{kind=\"pull\"}"),
            after("cordelia_requests_total{kind=\"push\"}"),
            mm(
                &held_shares(&series, started, started + 300.0, &keep)
                    .iter()
                    .map(|x| x * 100.0)
                    .collect::<Vec<_>>(),
                "%"
            ),
            mm(&rss, "MiB")
        ),
        "each device set up with it connected again within 120 s; bar 2 through the outage for \
         people with both; held-up split edits within 120 s of its start; none refused for rate \
         in the five minutes after",
        holds,
    )
}

// ── The checks of §6 ────────────────────────────────────────────────

fn checks(read: &Read, edits: &Edits, bar_12: bool) -> Vec<Line> {
    let mut c = Vec::new();
    // 1. Every process was sampled.
    let mut worst_gap: f64 = 0.0;
    let mut who = String::new();
    for i in 0..read.run.fleet.made.len() {
        let series = read.series(i);
        let mut t = read.start;
        while t <= read.end {
            if let Some(since) = read.lives.running_since(i, t) {
                let seen = series
                    .iter()
                    .filter(|s| s.t <= t)
                    .map(|s| s.t)
                    .fold(f64::MIN, f64::max);
                let gap = t - seen.max(since).max(read.start);
                if gap > worst_gap {
                    worst_gap = gap;
                    who = read.run.fleet.made[i].label.clone();
                }
            }
            t += 10.0;
        }
    }
    c.push(line(
        "Every process was sampled",
        format!("the longest a running process went without a sample: {worst_gap:.0} s ({who})"),
        "none for more than two minutes",
        worst_gap <= 120.0,
    ));
    // 2. The counts agree, over the run: each process's last sample of each
    // time it ran.
    let lasts = |node: usize| -> Vec<&Sample> {
        let series = read.series(node);
        let mut out = Vec::new();
        for (n, s) in series.iter().enumerate() {
            let next = series.get(n + 1);
            let restarted = next.is_some_and(|x| read.lives.restarts_in(node, s.t, x.t));
            if next.is_none() || restarted {
                out.push(*s);
            }
        }
        out
    };
    let mut worst = 0.0f64;
    let mut said = Vec::new();
    let mut bytes_worst = 0.0f64;
    for r in 0..read.run.plan.relays {
        let relay_lasts = lasts(read.run.fleet.relays[r]);
        for (k, kind) in KINDS.iter().enumerate().take(5) {
            let at_relay: f64 = relay_lasts
                .iter()
                .filter_map(|s| metric(s, &format!("cordelia_requests_total{{kind=\"{kind}\"}}")))
                .sum();
            let by_devices: f64 = read
                .devices()
                .into_iter()
                .flat_map(&lasts)
                .filter_map(|s| s.device.map(|d| d.asked[r][k]))
                .sum();
            let off = (at_relay - by_devices).abs() / at_relay.max(by_devices).max(1.0);
            if off > worst {
                worst = off;
            }
            said.push(format!(
                "relay {} {kind}: {at_relay:.0} read, {by_devices:.0} sent",
                r + 1
            ));
            if *kind == "push" {
                let bytes_in: f64 = relay_lasts
                    .iter()
                    .filter_map(|s| {
                        metric(
                            s,
                            "cordelia_stream_bytes_total{kind=\"push\",direction=\"in\"}",
                        )
                    })
                    .sum();
                let sent: f64 = read
                    .devices()
                    .into_iter()
                    .flat_map(&lasts)
                    .filter_map(|s| s.device.map(|d| d.asked_bytes[r][k]))
                    .sum();
                bytes_worst =
                    bytes_worst.max((bytes_in - sent).abs() / bytes_in.max(sent).max(1.0));
            }
        }
    }
    c.push(line(
        "The counts agree",
        format!(
            "the most apart {:.2}% ({}); pushed bytes apart {:.2}%",
            worst * 100.0,
            said.join(", "),
            bytes_worst * 100.0
        ),
        "what devices count they asked and what each relay counts it was asked within 1% for \
         each kind, over the run; pushed bytes within 5%",
        worst <= 0.01 && bytes_worst <= 0.05,
    ));
    // 3. The edits add up.
    let waited = edits.pairs.len();
    let arrived = edits.pairs.iter().filter(|p| p.arrived.is_some()).count();
    let not = edits
        .pairs
        .iter()
        .filter(|p| p.arrived.is_none() && !p.gone)
        .count();
    let gone = edits
        .pairs
        .iter()
        .filter(|p| p.arrived.is_none() && p.gone)
        .count();
    c.push(line(
        "The edits add up",
        format!(
            "{waited} waited for on other devices: {arrived} arrived, {not} not arrived, {gone} on a \
             device removed meanwhile; {} still waited for at the end",
            edits.pending_at_end
        ),
        "written equals arrived and not arrived, for each other device",
        waited == arrived + not + gone,
    ));
    // 4. The observer kept its pace.
    let p99 = quantile(&edits.gaps, 0.99).unwrap_or(0.0);
    c.push(line(
        "The observer kept its pace",
        format!("its reads were {:.0} ms apart at p99", p99 * 1000.0),
        "at most 500 ms apart at p99",
        p99 <= 0.5,
    ));
    // 5. The machine was not the bottleneck.
    let mut worst_idle: f64 = 1.0;
    let mut worst_iowait: f64 = 0.0;
    let mut worst_write: f64 = 0.0;
    let mut least_mem = u64::MAX;
    let mut worst_harness: f64 = 0.0;
    for w in read.machine.windows(2) {
        let (a, b) = (&w[0], &w[1]);
        if a.t < read.start || b.t > read.end || b.t <= a.t {
            continue;
        }
        let all = rose(a.read.cpu_all as f64, b.read.cpu_all as f64).max(1.0);
        worst_idle = worst_idle.min(rose(a.read.cpu_idle as f64, b.read.cpu_idle as f64) / all);
        worst_iowait =
            worst_iowait.max(rose(a.read.cpu_iowait as f64, b.read.cpu_iowait as f64) / all);
        let writes = rose(a.read.writes as f64, b.read.writes as f64);
        if writes > 0.0 {
            worst_write =
                worst_write.max(rose(a.read.write_ms as f64, b.read.write_ms as f64) / writes);
        }
        least_mem = least_mem.min(b.read.mem_available_kib);
        worst_harness = worst_harness.max(
            rose(a.read.harness_ticks as f64, b.read.harness_ticks as f64) / read.tps / (b.t - a.t),
        );
    }
    let least_mem = if least_mem == u64::MAX { 0 } else { least_mem };
    c.push(line(
        "The machine was not the bottleneck",
        format!(
            "CPU idle at least {:.0}%, iowait at most {:.1}%, a write at most {worst_write:.1} ms \
             on average, memory available at least {} MiB, the harness at most {:.2} of a core",
            worst_idle * 100.0,
            worst_iowait * 100.0,
            least_mem / 1024,
            worst_harness
        ),
        "in every minute: CPU at least 20% idle, iowait at most 10%, a write at most 20 ms, \
         memory available above 2 GiB, the harness under one core",
        worst_idle >= 0.2
            && worst_iowait <= 0.1
            && worst_write <= 20.0
            && least_mem > 2 * 1024 * 1024
            && worst_harness < 1.0,
    ));
    // 6. The load was the load.
    c.push(line(
        "The load was the load",
        format!("bar 12 {}", if bar_12 { "holds" } else { "does not hold" }),
        "bar 12 holds",
        bar_12,
    ));
    // 7. Churn had its chance.
    let keep = |_: f64, _: f64| true;
    let outage = read.run.outage.lock().unwrap().clone();
    let mut said = Vec::new();
    let mut had = !read.run.cut.load(std::sync::atomic::Ordering::SeqCst);
    let mut closed = 0.0;
    for r in 0..read.run.plan.relays {
        let series = relay_series(read, r);
        let churns = |a: f64, b: f64| rise(&series, "cordelia_churns_total", a, b, &keep);
        let cold = series
            .iter()
            .filter(|s| s.t >= read.start && s.t <= read.end)
            .any(|s| metric(s, "cordelia_governor_peers{state=\"cold\"}").is_some_and(|n| n > 0.0));
        closed += rise(
            &series,
            "cordelia_closed_by_warm_churn_total{peer=\"device\"}",
            read.start,
            read.end,
            &keep,
        ) + rise(
            &series,
            "cordelia_closed_by_warm_churn_total{peer=\"relay\"}",
            read.start,
            read.end,
            &keep,
        );
        if r == 1 {
            let before = churns(read.start, outage.stopped.unwrap_or(read.end));
            let after = outage.started.map_or(0.0, |s| churns(s, read.end));
            had &= before >= 1.0 && after >= 1.0 && cold;
            said.push(format!("relay 2: {before:.0} churns before its outage and {after:.0} after, a cold peer {}", if cold { "seen" } else { "not seen" }));
        } else {
            let n = churns(read.start, read.end);
            had &= n >= 2.0 && cold;
            said.push(format!(
                "relay 1: {n:.0} churns, a cold peer {}",
                if cold { "seen" } else { "not seen" }
            ));
        }
    }
    had &= closed > 0.0;
    said.push(format!("warm churn closed {closed:.0} connections"));
    c.push(line(
        "Churn had its chance",
        said.join("; "),
        "the first relay two churns, the second one before its outage and one after, a cold \
         peer at each, the window not cut; without change A, some churn closed a connection",
        had,
    ));
    c
}

// ── The measures of §1.2 ────────────────────────────────────────────

/// The labels of the measures of §1.2, as the summary says them, each
/// with its value: section 6's test 4 looks for each.
pub const MEASURES_OF_A_RELAY: [&str; 11] = [
    "requests by kind",
    "what became of them",
    "bytes",
    "the lock's wait and hold, by kind",
    "the nested mutexes",
    "memory",
    "CPU",
    "connections",
    "room used",
    "the governor",
    "the lock held, a share of each minute",
];

pub const MEASURES_OF_A_DEVICE: [&str; 8] = [
    "sync latency",
    "catching up",
    "memory, CPU, threads, descriptors",
    "requests",
    "requests refused for rate",
    "the lock's wait",
    "what waits to be sent",
    "conflict copies",
];

pub const MEASURES_OF_THE_MESH: [&str; 5] = [
    "a removal's spread",
    "a removal's carry",
    "churn",
    "a relay that stops",
    "between the relays",
];

fn measures(s: &mut String, read: &Read, edits: &Edits) {
    let keep = |t0: f64, t1: f64| !read.is_apart(t0, t1);
    let all = |_: f64, _: f64| true;
    let minutes = ((read.end - read.start) / 60.0).max(1e-9);
    let _ = writeln!(s, "\n## The measures (§1.2), over the window\n");
    for r in 0..read.run.plan.relays {
        let series = relay_series(read, r);
        let per_min = |key: &str| rise(&series, key, read.start, read.end, &all) / minutes;
        let _ = writeln!(s, "### Relay {}\n", r + 1);
        let kinds: Vec<String> = KINDS
            .iter()
            .map(|k| {
                format!(
                    "{k} {:.1}",
                    per_min(&format!("cordelia_requests_total{{kind=\"{k}\"}}"))
                )
            })
            .collect();
        let _ = writeln!(s, "- requests by kind: {} a minute", kinds.join(", "));
        let mut answers = Vec::new();
        for answer in [
            "answered",
            "not_now",
            "refused_for_rate",
            "not_served",
            "stray",
            "large_later",
        ] {
            let n: f64 = KINDS
                .iter()
                .map(|k| {
                    per_min(&format!(
                        "cordelia_answers_total{{kind=\"{k}\",answer=\"{answer}\"}}"
                    ))
                })
                .sum();
            answers.push(format!("{answer} {n:.1}"));
        }
        for why in ["refused_for_room", "refused_for_new_channels"] {
            let n: f64 = KINDS
                .iter()
                .map(|k| {
                    per_min(&format!(
                        "cordelia_entries_refused_total{{kind=\"{k}\",answer=\"{why}\"}}"
                    ))
                })
                .sum();
            answers.push(format!("entries {why} {n:.1}"));
        }
        let _ = writeln!(s, "- what became of them: {} a minute", answers.join(", "));
        let bytes: Vec<String> = KINDS
            .iter()
            .map(|k| {
                format!(
                    "{k} {:.0} in, {:.0} out",
                    per_min(&format!(
                        "cordelia_stream_bytes_total{{kind=\"{k}\",direction=\"in\"}}"
                    )),
                    per_min(&format!(
                        "cordelia_stream_bytes_total{{kind=\"{k}\",direction=\"out\"}}"
                    ))
                )
            })
            .collect();
        let _ = writeln!(s, "- bytes: {} a minute", bytes.join("; "));
        let mut lock = Vec::new();
        for kind in RELAY_TAKES {
            let label = format!("kind=\"{kind}\"");
            let (n, w) = quantiles(
                &series,
                &format!("{LOCK}_wait_microseconds"),
                &label,
                read.start,
                read.end,
                &keep,
                &[0.5, 0.99, 0.999],
            );
            if n == 0.0 {
                continue;
            }
            let (_, h) = quantiles(
                &series,
                &format!("{LOCK}_hold_microseconds"),
                &label,
                read.start,
                read.end,
                &keep,
                &[0.5, 0.99, 0.999],
            );
            let most = series
                .last()
                .and_then(|x| metric(x, &format!("{LOCK}_hold_microseconds_max{{{label}}}")))
                .unwrap_or(0.0);
            let over = |ms: &str| {
                rise(
                    &series,
                    &format!("{LOCK}_hold_microseconds_over{{{label},ms=\"{ms}\"}}"),
                    read.start,
                    read.end,
                    &keep,
                )
            };
            lock.push(format!(
                "{kind}: {n:.0} takes, wait p50/p99/p99.9 {}/{}/{}, hold p50/p99/p99.9 {}/{}/{}, \
                 the most held {most:.0} µs, {:.0} over 5 ms and {:.0} over 50 ms",
                us(w[0]),
                us(w[1]),
                us(w[2]),
                us(h[0]),
                us(h[1]),
                us(h[2]),
                over("5"),
                over("50")
            ));
        }
        let _ = writeln!(
            s,
            "- the lock's wait and hold, by kind: {}",
            if lock.is_empty() {
                "no value".into()
            } else {
                lock.join("; ")
            }
        );
        let nested: Vec<String> = ["rates", "room"]
            .iter()
            .map(|m| {
                let label = format!("mutex=\"{m}\"");
                let (n, q) = quantiles(
                    &series,
                    &format!("{LOCK}_nested_wait_microseconds"),
                    &label,
                    read.start,
                    read.end,
                    &all,
                    &[0.99],
                );
                format!("{m}: {n:.0} waits, p99 {}", us(q[0]))
            })
            .collect();
        let _ = writeln!(s, "- the nested mutexes: {}", nested.join("; "));
        let in_window: Vec<&&Sample> = series
            .iter()
            .filter(|x| x.t >= read.start && x.t <= read.end)
            .collect();
        let rss: Vec<f64> = in_window
            .iter()
            .filter_map(|x| x.proc.map(|p| p.rss_kib as f64 / 1024.0))
            .collect();
        let hwm = in_window
            .iter()
            .filter_map(|x| x.proc.map(|p| p.hwm_kib as f64 / 1024.0))
            .fold(0.0, f64::max);
        let _ = writeln!(
            s,
            "- memory: RSS {}, its peak {hwm:.1} MiB",
            mm(&rss, "MiB")
        );
        let (each, mean) = cpu(read, &series);
        let _ = writeln!(
            s,
            "- CPU: {:.1}% of a core on average, {}",
            mean * 100.0,
            mm(
                &each.iter().map(|x| x * 100.0).collect::<Vec<_>>(),
                "% in a minute"
            )
        );
        let open: Vec<f64> = in_window
            .iter()
            .filter_map(|x| metric(x, "cordelia_connections_open"))
            .collect();
        let away: Vec<String> = ["bound", "address", "subnet", "refused_for_a_time"]
            .iter()
            .map(|w| {
                format!(
                    "{w} {:.0}",
                    rise(
                        &series,
                        &format!("cordelia_connections_turned_away_total{{why=\"{w}\"}}"),
                        read.start,
                        read.end,
                        &all
                    )
                )
            })
            .collect();
        let _ = writeln!(
            s,
            "- connections: open {}; turned away {}",
            mm(&open, ""),
            away.join(", ")
        );
        let room = series.iter().rev().find_map(|x| x.room);
        let _ = writeln!(
            s,
            "- room used: {}",
            room.map_or("no value".into(), |(b, c)| format!(
                "{b} bytes in {c} channels at the end"
            ))
        );
        let peer = |state: &str| -> Vec<f64> {
            in_window
                .iter()
                .filter_map(|x| metric(x, &format!("cordelia_governor_peers{{state=\"{state}\"}}")))
                .collect()
        };
        let _ = writeln!(
            s,
            "- the governor: hot {}, warm {}, cold {}; {:.0} churns, warm churn closed {:.0} of devices and {:.0} of relays, {:.0} connections gone",
            mm(&peer("hot"), ""),
            mm(&peer("warm"), ""),
            mm(&peer("cold"), ""),
            rise(&series, "cordelia_churns_total", read.start, read.end, &all),
            rise(
                &series,
                "cordelia_closed_by_warm_churn_total{peer=\"device\"}",
                read.start,
                read.end,
                &all
            ),
            rise(
                &series,
                "cordelia_closed_by_warm_churn_total{peer=\"relay\"}",
                read.start,
                read.end,
                &all
            ),
            rise(
                &series,
                "cordelia_connections_closed_total",
                read.start,
                read.end,
                &all
            ),
        );
        let shares = held_shares(&series, read.start, read.end, &keep);
        let _ = writeln!(
            s,
            "- the lock held, a share of each minute: {}\n",
            mm(&shares.iter().map(|x| x * 100.0).collect::<Vec<_>>(), "%")
        );
    }
    for profile in Profile::ALL {
        let nodes: Vec<usize> = read
            .devices()
            .into_iter()
            .filter(|i| {
                read.person_of(*i)
                    .is_some_and(|(k, _)| read.run.plan.population.people[k].profile == profile)
            })
            .collect();
        if nodes.is_empty() {
            continue;
        }
        let _ = writeln!(s, "### Devices, {}\n", profile.name());
        let of: Vec<&Pair> = edits
            .pairs
            .iter()
            .filter(|p| nodes.contains(&p.node))
            .collect();
        let (l, late) = latencies(read, of.iter().copied());
        let _ = writeln!(
            s,
            "- sync latency: {} arrivals, p50 {}, p95 {}, the most {}; {late} not within 120 s",
            l.len(),
            quantile(&l, 0.5).map_or("no value".into(), |v| format!("{v:.1} s")),
            quantile(&l, 0.95).map_or("no value".into(), |v| format!("{v:.1} s")),
            l.iter()
                .copied()
                .reduce(f64::max)
                .map_or("no value".into(), |v| format!("{v:.1} s"))
        );
        let mut catch = Vec::new();
        for i in &nodes {
            for (off, on) in read.lives.downs(*i, read.start, read.end) {
                let Some(on) = on else { continue };
                let last = edits
                    .pairs
                    .iter()
                    .filter(|p| p.node == *i && p.edit.at >= off && p.edit.at <= on)
                    .filter_map(|p| p.arrived.map(|a| a.at - on))
                    .fold(0.0, f64::max);
                catch.push(last);
            }
        }
        let _ = writeln!(
            s,
            "- catching up: {}",
            match catch.is_empty() {
                true => "none of these devices was off in the window: 0 times off".into(),
                false => format!("{} times off, {}", catch.len(), mm(&catch, "s")),
            }
        );
        let mut rss = Vec::new();
        let mut cpus = Vec::new();
        let mut threads = Vec::new();
        let mut fds = Vec::new();
        let mut waits = Vec::new();
        let (mut asked, mut held, mut refused, mut over, mut given) =
            ([[0.0; 6]; 2], 0.0, 0.0, 0.0, 0.0);
        for i in &nodes {
            let series = read.series(*i);
            for x in series
                .iter()
                .filter(|x| x.t >= read.start && x.t <= read.end)
            {
                if let Some(p) = x.proc {
                    rss.push(p.rss_kib as f64 / 1024.0);
                    threads.push(p.threads as f64);
                    fds.push(p.fds as f64);
                }
                if let Some(o) = x.outbox_waiting {
                    waits.push(o);
                }
            }
            let (each, _) = cpu(read, &series);
            cpus.extend(each.iter().map(|x| x * 100.0));
            for (s0, s1) in pairs(&series, read.start, read.end) {
                let (Some(d0), Some(d1)) = (s0.device, s1.device) else {
                    continue;
                };
                for (r, of) in asked.iter_mut().enumerate() {
                    for (k, n) in of.iter_mut().enumerate() {
                        *n += rose(d0.asked[r][k], d1.asked[r][k]);
                    }
                    held += rose(d0.held_back[r], d1.held_back[r]);
                    refused += rose(d0.refused_for_now[r], d1.refused_for_now[r]);
                }
                over += rose(d0.waits_over_100, d1.waits_over_100);
                given += rose(d0.given_up, d1.given_up);
            }
        }
        let _ = writeln!(
            s,
            "- memory, CPU, threads, descriptors: RSS {}; CPU {}; threads {}; descriptors {}",
            mm(&rss, "MiB"),
            mm(&cpus, "% of a core"),
            mm(&threads, ""),
            mm(&fds, "")
        );
        let n = nodes.len() as f64;
        let req: Vec<String> = (0..read.run.plan.relays)
            .map(|r| {
                let kinds: Vec<String> = KINDS
                    .iter()
                    .enumerate()
                    .take(5)
                    .map(|(k, kind)| format!("{kind} {:.1}", asked[r][k] / n / minutes))
                    .collect();
                format!("to relay {}: {}", r + 1, kinds.join(", "))
            })
            .collect();
        let _ = writeln!(
            s,
            "- requests: a device's a minute {}; {held:.0} held back by its own pace",
            req.join("; ")
        );
        let _ = writeln!(
            s,
            "- requests refused for rate: {refused:.0} refused for now (for rate or not now, which a device cannot tell apart)"
        );
        let _ = writeln!(
            s,
            "- the lock's wait: {over:.0} waits over 100 ms; {given:.0} given up"
        );
        let _ = writeln!(s, "- what waits to be sent: {}", mm(&waits, "entries"));
        let _ = writeln!(
            s,
            "- conflict copies: {} on every device of the run at the end\n",
            edits.conflict_copies
        );
    }
    let _ = writeln!(s, "### Across the mesh\n");
    let removals = read.run.removals.lock().unwrap().clone();
    let spread: Vec<String> = removals
        .iter()
        .map(|r| {
            let line = r.line_at.unwrap_or(f64::NAN);
            let applied: Vec<String> = r
                .applied
                .iter()
                .map(|(d, at)| {
                    format!(
                        "device {d} {}",
                        at.map_or("never".into(), |t| format!("{:.1} s", t - line))
                    )
                })
                .collect();
            let held: Vec<String> = r
                .relays_hold
                .iter()
                .enumerate()
                .map(|(n, (_, at))| {
                    format!(
                        "relay {} {}",
                        n + 1,
                        at.map_or("never".into(), |t| format!("{:.1} s", t - line))
                    )
                })
                .collect();
            format!(
                "person {}: {}; {}",
                r.person,
                applied.join(", "),
                held.join(", ")
            )
        })
        .collect();
    let _ = writeln!(
        s,
        "- a removal's spread: {}",
        if spread.is_empty() {
            "no value".into()
        } else {
            spread.join("; ")
        }
    );
    let carry: Vec<String> = removals
        .iter()
        .map(|r| {
            format!(
                "person {}: {} for {} bytes carried (T {:.0} s)",
                r.person,
                match (r.line_at, r.carry_end) {
                    (Some(a), Some(b)) => format!("{:.1} s", b - a),
                    _ => "not ended".into(),
                },
                r.carried_bytes,
                r.bound
            )
        })
        .collect();
    let _ = writeln!(
        s,
        "- a removal's carry: {}",
        if carry.is_empty() {
            "no value".into()
        } else {
            carry.join("; ")
        }
    );
    let gaps = reconnects(read);
    let churns: Vec<String> = (0..read.run.plan.relays)
        .map(|r| {
            let series = relay_series(read, r);
            format!(
                "relay {}: {:.0} churns, {:.0} of devices and {:.0} of relays closed by warm churn",
                r + 1,
                rise(&series, "cordelia_churns_total", read.start, read.end, &all),
                rise(
                    &series,
                    "cordelia_closed_by_warm_churn_total{peer=\"device\"}",
                    read.start,
                    read.end,
                    &all
                ),
                rise(
                    &series,
                    "cordelia_closed_by_warm_churn_total{peer=\"relay\"}",
                    read.start,
                    read.end,
                    &all
                )
            )
        })
        .collect();
    let _ = writeln!(
        s,
        "- churn: {}; connections made again after a closure: {}, {}",
        churns.join("; "),
        gaps.len(),
        mm(&gaps, "s")
    );
    let outage = read.run.outage.lock().unwrap().clone();
    let back: Vec<f64> = outage
        .back
        .iter()
        .filter_map(|(_, at)| Some(at.as_ref()? - outage.started?))
        .collect();
    let _ = writeln!(
        s,
        "- a relay that stops: {}",
        match outage.started {
            Some(_) => format!(
                "{} of {} devices connected to it again, {}",
                back.len(),
                outage.back.len(),
                mm(&back, "s after its start")
            ),
            None => "no value".into(),
        }
    );
    if read.run.plan.relays == 2 {
        let series = relay_series(read, 0);
        let relays_min = rise(
            &series,
            "cordelia_requests_total{kind=\"relays\"}",
            read.start,
            read.end,
            &all,
        ) / minutes;
        let bytes_min = rise(
            &series,
            "cordelia_stream_bytes_total{kind=\"relays\",direction=\"in\"}",
            read.start,
            read.end,
            &all,
        ) / minutes;
        let people = &read.run.plan.population.people;
        let (split, _) = latencies(
            read,
            edits
                .of_person(read, false)
                .filter(|p| people[p.edit.person].split),
        );
        let links: f64 = series
            .last()
            .and_then(|x| x.metrics.as_ref())
            .map(|m| {
                m.iter()
                    .filter(|(k, _)| k.starts_with("cordelia_relay_link_closures_total{"))
                    .map(|(_, v)| v)
                    .sum()
            })
            .unwrap_or(0.0);
        let _ = writeln!(
            s,
            "- between the relays: {relays_min:.1} requests and {bytes_min:.0} bytes a minute on the streams between relays at relay 1; split people's latency {}; {links:.0} closures of the link at relay 1",
            mm(&split, "s")
        );
    } else {
        let _ = writeln!(s, "- between the relays: one relay alone: 0 entries passed");
    }
}
