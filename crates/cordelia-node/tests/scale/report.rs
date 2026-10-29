//! What a run leaves (decision 2026-10-22 §4.4): `SUMMARY.md`, each bar of
//! section 3 and each check of section 6 worked out from what the run
//! kept, the measures of section 1.2, the parts treated apart, the setup,
//! and every setting beyond the defaults; and `edits.csv`.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::Path;

use cordelia_core::protocol::{ENTRY_OVERHEAD_BYTES, MIN_ENTRY_CONTENT_BYTES};

use crate::fleet::{Change, Is, KINDS, Sample, What};
use crate::kept::Kept;
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
            .args(["--no-optional-locks", "-C", dir])
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
    /// The figure cannot be told apart from the bar.
    NotResolved,
}

impl Verdict {
    fn word(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Reported => "REPORTED",
            Verdict::NotResolved => "NOT RESOLVED",
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

    /// When it ran again after the last time it was not running in
    /// [a, b] (from `a`, where it was not running then); `None` where it
    /// never ran again. For a device that did not run all through [a, b].
    fn ran_again_after(&self, node: usize, a: f64, b: f64) -> Option<f64> {
        let of = &self.of[node];
        let from = of
            .iter()
            .rposition(|(at, is)| *at > a && *at <= b && *is != Is::Running)
            .map_or_else(|| of.partition_point(|(at, _)| *at <= a), |i| i + 1);
        of[from..]
            .iter()
            .find(|(_, is)| *is == Is::Running)
            .map(|(at, _)| *at)
    }

    /// When it had first run `secs` without a stop or a freeze from `from`
    /// on: the end of that stretch, or `None` where it never did. A device
    /// still running at its last change runs on.
    fn ran_for_after(&self, node: usize, from: f64, secs: f64) -> Option<f64> {
        let mut since = (self.at(node, from) == Is::Running).then_some(from);
        for (at, is) in self.of[node].iter().filter(|(at, _)| *at > from) {
            if let Some(s) = since
                && *at - s >= secs
            {
                return Some(s + secs);
            }
            match is {
                Is::Running => since = since.or(Some(*at)),
                _ => since = None,
            }
        }
        since.map(|s| s + secs)
    }

    /// The longest stretch it ran without a stop or a freeze inside [a, b].
    fn longest_run_within(&self, node: usize, a: f64, b: f64) -> f64 {
        let mut longest: f64 = 0.0;
        let mut since = (self.at(node, a) == Is::Running).then_some(a);
        for (at, is) in self.of[node].iter().filter(|(at, _)| *at > a && *at <= b) {
            match (is, since) {
                (Is::Running, None) => since = Some(*at),
                (Is::Running, Some(_)) => {}
                (_, Some(from)) => {
                    longest = longest.max(at - from);
                    since = None;
                }
                (_, None) => {}
            }
        }
        if let Some(from) = since {
            longest = longest.max(b - from);
        }
        longest
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

    /// When its process started: its counters count from nothing then.
    /// Going on after a freeze is no start.
    fn starts(&self, node: usize) -> Vec<f64> {
        let mut starts = Vec::new();
        let mut was = Is::NotStarted;
        for (at, is) in &self.of[node] {
            if *is == Is::Running && was != Is::Frozen && was != Is::Running {
                starts.push(*at);
            }
            was = *is;
        }
        starts
    }
}

// ── Reading counters over the window ────────────────────────────────

fn metric(s: &Sample, key: &str) -> Option<f64> {
    s.metrics.as_ref()?.get(key).copied()
}

/// A node's samples in their order, and when its process started: a
/// counter counts from nothing at each start.
pub(crate) struct Series<'a> {
    samples: Vec<&'a Sample>,
    starts: Vec<f64>,
}

impl<'a> std::ops::Deref for Series<'a> {
    type Target = [&'a Sample];

    fn deref(&self) -> &Self::Target {
        &self.samples
    }
}

impl Series<'_> {
    /// Whether its process started between `t0` and `t1`.
    fn started(&self, t0: f64, t1: f64) -> bool {
        self.starts.iter().any(|s| *s > t0 && *s <= t1)
    }
}

/// Each pair of samples of a node, both in [a, b], that carry what `has`
/// asks for, the one after the other among those that carry it: a sample
/// whose read failed lies between them and loses nothing. With whether
/// the process started between them.
fn pairs_having<'a>(
    series: &Series<'a>,
    a: f64,
    b: f64,
    has: impl Fn(&Sample) -> bool,
) -> Vec<(&'a Sample, &'a Sample, bool)> {
    let with: Vec<&'a Sample> = series.iter().copied().filter(|s| has(s)).collect();
    with.windows(2)
        .filter(|w| w[0].t >= a && w[1].t <= b)
        .map(|w| (w[0], w[1], series.started(w[0].t, w[1].t)))
        .collect()
}

/// The pairs of a device's samples that carry its counts.
fn device_pairs<'a>(series: &Series<'a>, a: f64, b: f64) -> Vec<(&'a Sample, &'a Sample, bool)> {
    pairs_having(series, a, b, |s| s.device.is_some())
}

/// What a counter rose by over a pair: a process that started between
/// them counts from nothing, and so does a counter that fell.
fn rose_over(v0: f64, v1: f64, started: bool) -> f64 {
    if started || v1 < v0 { v1 } else { v1 - v0 }
}

/// What a counter of the machine rose by: it never starts again.
fn rose(v0: f64, v1: f64) -> f64 {
    rose_over(v0, v1, false)
}

/// What `key` rose by over each pair of a node's samples in [a, b] that
/// `keep` keeps, among the samples that carry it.
fn rise(series: &Series, key: &str, a: f64, b: f64, keep: &dyn Fn(f64, f64) -> bool) -> f64 {
    pairs_having(series, a, b, |s| metric(s, key).is_some())
        .into_iter()
        .filter(|(s0, s1, _)| keep(s0.t, s1.t))
        .map(|(s0, s1, started)| {
            let (v0, v1) = (metric(s0, key).unwrap(), metric(s1, key).unwrap());
            rose_over(v0, v1, started)
        })
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
    series: &Series,
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

struct Read {
    /// The run, as its inputs were kept: every input the report reads.
    run: Kept,
    lives: Lives,
    samples: Vec<Sample>,
    machine: Vec<crate::fleet::MachineSample>,
    start: f64,
    end: f64,
    apart: Vec<(f64, f64)>,
    tps: f64,
}

impl Read {
    fn series(&self, node: usize) -> Series<'_> {
        let mut s: Vec<&Sample> = self.samples.iter().filter(|s| s.node == node).collect();
        s.sort_by(|a, b| a.t.total_cmp(&b.t));
        Series {
            samples: s,
            starts: self.lives.starts(node),
        }
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
fn parts_apart(run: &Kept) -> Vec<(f64, f64)> {
    let mut apart = Vec::new();
    let outage = &run.outage;
    if let (Some(a), Some(b)) = (outage.stopped, outage.started) {
        apart.push((a, b + run.plan.timing.after_start));
    }
    for r in &run.removals {
        if let Some(line) = r.line_at {
            apart.push((line, r.carry_end.unwrap_or(line + r.bound)));
        }
    }
    apart
}

/// What a run keeps for its report, as it is now.
fn kept_of(run: &Run) -> Kept {
    Kept::of(
        run,
        commit(),
        CHANGES,
        crate::machine::ticks_a_second() as f64,
    )
}

/// What the report reads of a run's inputs: its window, where each node
/// was, its samples, and the parts treated apart.
fn read_of_kept(mut run: Kept) -> Read {
    let (start, end) = match run.window {
        Some((s, e)) => (s, e.unwrap_or(run.kept_at)),
        None => (run.kept_at, run.kept_at),
    };
    Read {
        lives: Lives::new(&run.fleet.changes, run.fleet.made.len()),
        samples: std::mem::take(&mut run.samples),
        machine: std::mem::take(&mut run.machine),
        start,
        end,
        apart: parts_apart(&run),
        tps: run.ticks_a_second,
        run,
    }
}

/// What the report reads of a run, as it is now.
fn read_of(run: &Run) -> Read {
    read_of_kept(kept_of(run))
}

/// The edits, as the report reads them of `read`'s run.
fn edits_of(read: &Read) -> Edits {
    Edits::of(read, &read.run.observer)
}

/// The summary of the run whose inputs are in `folder` (`INPUTS_FILE`),
/// made again: the same `SUMMARY.md` as the run wrote, where the report
/// has not changed since. A folder of a run that did not keep its inputs,
/// or kept another version of them, is refused, and the error says why.
pub fn again(folder: &Path) -> Result<Outcome, String> {
    let kept = Kept::load(folder)?;
    let read = read_of_kept(kept);
    let edits = edits_of(&read);
    Ok(summary_of(&read, &edits, folder))
}

/// Write what the run leaves, and say what it came to: its inputs, kept
/// so that the report can be made again from them, `SUMMARY.md` and
/// `edits.csv` made from them, and each change of each node in
/// `samples.jsonl`.
pub fn write(run: &Run) -> Outcome {
    let kept = kept_of(run);
    let saved = kept.save(&run.out);
    let read = read_of_kept(kept);
    let edits = edits_of(&read);
    let outcome = summary_of(&read, &edits, &run.out);
    std::fs::write(run.out.join("SUMMARY.md"), &outcome.summary).unwrap();
    std::fs::write(run.out.join("edits.csv"), edits.csv(&read)).unwrap();
    changes_written(&read.run, &run.out);
    // The inputs give this summary again, or the harness says so.
    match saved.and_then(|()| again(&run.out)) {
        Ok(again) if again.summary == outcome.summary => {}
        Ok(_) => eprintln!(
            "the report made again from {} differs from SUMMARY.md: it will not be made again \
             faithfully from them",
            crate::kept::INPUTS_FILE
        ),
        Err(why) => eprintln!("the report's inputs were not kept as they should be: {why}"),
    }
    outcome
}

/// The summary of `read`'s run, and what it came to.
fn summary_of(read: &Read, edits: &Edits, out: &Path) -> Outcome {
    let run = &read.run;
    let (start, end) = (read.start, read.end);

    let (b6, rises) = bar_6(read);
    let (b12, pulls) = bar_12(read, edits);
    let b12_holds = b12.verdict != Verdict::Fail;
    let bars = vec![
        bar_1(read),
        bar_2(read, edits),
        bar_3(read, edits),
        bar_4(read),
        bar_5(read),
        b6,
        bar_7(read),
        bar_8(read),
        bar_9(read),
        bar_10(read, edits),
        bar_11(read),
        b12,
        bar_13(read, edits),
        bar_14(read, edits),
        bar_15(read, edits),
    ];
    let checks = checks(read, edits, b12_holds);

    let faults = run.fleet.faults.clone();
    let machine_fault = run.stopped_why.clone();
    let ending = the_end(run);
    let invalid = checks.iter().any(|c| c.verdict == Verdict::Fail) || machine_fault.is_some();
    let failed = bars.iter().any(|b| b.verdict == Verdict::Fail)
        || !faults.is_empty()
        || ending.iter().any(|(_, well)| !well);
    // A bar that cannot be told apart from its figure keeps the run from
    // passing, and is no failure: the run says NOT RESOLVED.
    let unresolved = bars.iter().any(|b| b.verdict == Verdict::NotResolved);
    let verdict = match (invalid, failed, unresolved) {
        (true, _, _) => "INVALID",
        (false, true, _) => "FAIL",
        (false, false, true) => "NOT RESOLVED",
        (false, false, false) => "PASS",
    };

    let plan = &run.plan;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{verdict} stage {} seed {} commit {} ({})\n",
        plan.stage.name(),
        plan.seed,
        run.commit,
        run.built_with
    );
    let setup = &run.setup;
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
        if run.cut {
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
    measures(&mut s, read, edits);
    let _ = writeln!(s, "\n## The end (step 10)\n");
    for (said, well) in &ending {
        let _ = writeln!(
            s,
            "- {said}: **{}**",
            if *well { "as it should" } else { "FAIL" }
        );
    }
    let _ = writeln!(s, "\n## The parts treated apart\n");
    let outage = &run.outage;
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
    for r in &run.removals {
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
    let relay = &run.fleet.made[run.fleet.relays[0]].settings;
    let device = run
        .fleet
        .made
        .iter()
        .find(|m| matches!(m.what, What::Device { .. }))
        .map(|m| &m.settings);
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
    let arrived = edits.pairs.iter().filter(|p| p.arrived.is_some()).count();
    let gone = edits
        .pairs
        .iter()
        .filter(|p| p.arrived.is_none() && p.gone)
        .count();
    Outcome {
        verdict: verdict.into(),
        summary: s,
        out: out.to_path_buf(),
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
fn the_end(run: &Kept) -> Vec<(String, bool)> {
    use cordelia_core::protocol::NODE_STOP_TIMEOUT_SECS;
    let mut said = Vec::new();
    let stops = &run.stops_at_end;
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
    let left = &run.pids_left;
    said.push((
        format!("{} of the pids it started are left", left.len()),
        left.is_empty(),
    ));
    let ours: HashSet<String> = run.fleet.made.iter().map(|m| m.key.clone()).collect();
    for (r, keys) in &run.peers_at_end {
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
fn changes_written(run: &Kept, out: &Path) {
    use std::io::Write as _;
    let Ok(mut file) = std::fs::OpenOptions::new()
        .append(true)
        .open(out.join("samples.jsonl"))
    else {
        return;
    };
    for c in &run.fleet.changes {
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
    /// The line of the removal of its device, where it was removed.
    gone_at: Option<f64>,
}

struct Edits {
    window: Vec<crate::observer::Written>,
    pairs: Vec<Pair>,
    written: usize,
    conflict_copies: usize,
    gaps: Vec<f64>,
    counted: Counted,
}

/// What was counted apart, for check 3: the edits numbered and those the
/// observer recorded; the waits begun, and of them those arrived, still
/// waited for, and ended on a device removed.
#[derive(Debug, Clone, Copy, Default)]
struct Counted {
    numbered: usize,
    recorded: usize,
    waited: usize,
    arrived: usize,
    pending: usize,
    gone: usize,
}

/// Whether edit `n` was replaced by intent as device `node` sees it: a
/// later edit M was written over it where its line headed the file (M's
/// writer held it), the device ran no stretch of a minute between the two
/// (bar 3's catch-up: it had no time to take `n` while `n` was the newest),
/// and M arrived at the device, or was itself so replaced. A device that
/// ran a minute while `n` was the newest had its chance, and is owed it;
/// and so is one that ran all through from `n` to M where M came
/// [`HELD_BY_A_RUNNING_DEVICE_SECS`] or more after `n`: a running device
/// holds an edit within that, and the record calls `n` lost (bar 3).
fn replaced_at(
    read: &Read,
    n: &crate::observer::Written,
    device: usize,
    node: usize,
    by: &HashMap<u64, Vec<&crate::observer::Written>>,
    arrivals: &HashMap<(u64, usize), crate::observer::Arrival>,
    depth: usize,
) -> bool {
    if depth > 64 {
        return false;
    }
    by.get(&n.number).into_iter().flatten().any(|m| {
        m.writer != device
            && read.lives.longest_run_within(node, n.at, m.at) < CATCH_UP_SECS
            && !(read.lives.ran_through(node, n.at, m.at)
                && m.at - n.at >= HELD_BY_A_RUNNING_DEVICE_SECS)
            && (arrivals.contains_key(&(m.number, device))
                || replaced_at(read, m, device, node, by, arrivals, depth + 1))
    })
}

/// The time a device that runs is given to take an edit it lacks (bar 3:
/// a device that was off holds its person's edits within 60 s of running
/// again).
const CATCH_UP_SECS: f64 = 60.0;

/// Within this a device that runs holds an edit of its person (bar 2's
/// four waits, of 20 s at most; §2.1 item 8 writes nothing twice on a
/// device within 15 s): an edit replaced sooner may never be seen.
const HELD_BY_A_RUNNING_DEVICE_SECS: f64 = 20.0;

impl Edits {
    fn of(read: &Read, observer: &crate::kept::KeptObserver) -> Edits {
        let mut by: HashMap<u64, Vec<&crate::observer::Written>> = HashMap::new();
        for e in &observer.edits {
            if let Some(n) = e.replaced {
                by.entry(n).or_default().push(e);
            }
        }
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
            let node = read.run.fleet.device(edit.person, *device);
            let gone_at = read
                .run
                .removals
                .iter()
                .find(|r| r.person == edit.person && r.removed == *device)
                .and_then(|r| r.line_at);
            pairs.push(Pair {
                gone_at,
                edit: edit.clone(),
                device: *device,
                node,
                arrived: observer.arrivals.get(&(*number, *device)).copied(),
                replaced: replaced_at(read, edit, *device, node, &by, &observer.arrivals, 0),
                gone: gone.contains(&(*number, *device)),
            });
        }
        let conflict_copies = read.run.conflict_copies.len();
        Edits {
            written: window.len(),
            window,
            pairs,
            conflict_copies,
            gaps: observer.gaps.clone(),
            counted: Counted {
                numbered: read.run.next_edit.saturating_sub(1) as usize,
                recorded: observer.edits.len(),
                waited: observer.waited.len(),
                arrived: observer.arrivals.len(),
                pending: observer.pending(),
                gone: observer.gone.len(),
            },
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

fn relay_series<'a>(read: &'a Read, r: usize) -> Series<'a> {
    read.series(read.run.fleet.relays[r])
}

/// The carry windows of person `k`'s removals.
fn carry_windows(read: &Read, k: usize) -> Vec<(f64, f64)> {
    read.run
        .removals
        .iter()
        .filter(|r| r.person == k)
        .filter_map(|r| Some((r.line_at?, r.carry_end.unwrap_or(r.line_at? + r.bound))))
        .collect()
}

/// Whether a device's pair of samples holds the minute of its own
/// connection's proofs (decision 2026-10-17 §3): its process started or
/// went on, or a connection it counts was made or closed, within the
/// minute before the pair or in it. Nothing another device or a relay
/// did excuses it.
fn own_proofs_minute(read: &Read, series: &Series, node: usize, s0: &Sample, s1: &Sample) -> bool {
    let from = s0.t - 60.0;
    if read.lives.starts_in(node, from, s1.t) {
        return true;
    }
    // Its own counts, from the last sample before that minute to the end
    // of the pair: a change in either is a connection made or closed.
    let before = series
        .iter()
        .rev()
        .find(|s| s.t < from && s.device.is_some())
        .and_then(|s| s.device);
    let counts: Vec<crate::fleet::DeviceCounts> = before
        .into_iter()
        .chain(
            series
                .iter()
                .filter(|s| s.t >= from && s.t <= s1.t)
                .filter_map(|s| s.device),
        )
        .collect();
    counts
        .windows(2)
        .any(|w| w[0].open != w[1].open || w[0].closed != w[1].closed)
}

/// The requests the devices held back by their own pace in [a, b]: those
/// outside the minute of their own connection's proofs and their own
/// person's carry window, and those within them.
fn held_back(read: &Read, a: f64, b: f64) -> (f64, f64) {
    let (mut held, mut excused) = (0.0, 0.0);
    for i in read.devices() {
        let Some((k, _)) = read.person_of(i) else {
            continue;
        };
        let carries = carry_windows(read, k);
        let series = read.series(i);
        for (s0, s1, started) in device_pairs(&series, a, b) {
            let (Some(d0), Some(d1)) = (s0.device, s1.device) else {
                continue;
            };
            let n: f64 = (0..2)
                .map(|r| rose_over(d0.held_back[r], d1.held_back[r], started))
                .sum();
            if n == 0.0 {
                continue;
            }
            let in_carry = carries.iter().any(|(c0, c1)| s0.t < *c1 && s1.t > *c0);
            if in_carry || own_proofs_minute(read, &series, i, s0, s1) {
                excused += n;
            } else {
                held += n;
            }
        }
    }
    (held, excused)
}

/// Each relay's refusals for rate in [a, b], of every kind: a breach, at
/// any time of the window, fails bar 1, the parts treated apart with it
/// (bar 10c).
fn refused_for_rate(read: &Read, a: f64, b: f64) -> f64 {
    let all = |_: f64, _: f64| true;
    let mut refused = 0.0;
    for r in 0..read.run.plan.relays {
        let series = relay_series(read, r);
        for kind in KINDS {
            let key =
                format!("cordelia_answers_total{{kind=\"{kind}\",answer=\"refused_for_rate\"}}");
            refused += rise(&series, &key, a, b, &all);
        }
    }
    refused
}

fn bar_1(read: &Read) -> Line {
    let at_relays = refused_for_rate(read, read.start, read.end);
    let (held, excused) = held_back(read, read.start, read.end);
    line(
        "No request is refused for rate",
        format!(
            "{at_relays:.0} refused for rate at the relays in the window; {held:.0} held back by \
             a device's own pace outside the minute of its own connection's proofs and its \
             person's carry window, and {excused:.0} within them"
        ),
        "none refused at either relay in the window, and none held back but in the minute of \
         the device's own connection's proofs or its person's carry window",
        at_relays == 0.0 && held == 0.0,
    )
}

/// Bar 2's figures over `pairs`: p50, p95, the most, and those that did
/// not arrive within 120 s while their device ran.
fn latencies<'a>(read: &Read, pairs: impl Iterator<Item = &'a Pair>) -> (Vec<f64>, usize) {
    let mut l = Vec::new();
    let mut late = 0;
    for p in pairs {
        if p.edit.at < read.start {
            continue;
        }
        // A device removed later was still owed what it ran 120 s through
        // before its removal's line.
        if p.gone {
            let owed = p.arrived.is_none()
                && !p.replaced
                && p.gone_at.is_some_and(|line| p.edit.at + 120.0 <= line)
                && read.lives.ran_through(p.node, p.edit.at, p.edit.at + 120.0);
            late += usize::from(owed);
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
/// The kinds of take of the requests a device makes of a relay, on the
/// streams of entries 0x10 to 0x13: the kinds whose waits bar 4 (a) bars.
/// A device gives each up after STREAM_TIMEOUT_SECS. The relay's other
/// kinds (the streams between relays and its own passing on and pulls,
/// its sweeps and the uses it writes, its checkpoint, its API and any
/// other) have their waits reported: no device's request waits on them.
const REQUESTS: [&str; 5] = ["show_whole", "show_short", "proof", "pull", "push"];
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
fn held_shares(series: &Series, a: f64, b: f64, keep: &dyn Fn(f64, f64) -> bool) -> Vec<f64> {
    pairs_having(series, a, b, |s| s.metrics.is_some())
        .into_iter()
        .filter(|(s0, s1, _)| keep(s0.t, s1.t) && s1.t > s0.t)
        .map(|(s0, s1, started)| {
            let held: f64 = RELAY_TAKES
                .iter()
                .chain(["pass", "cycle"].iter())
                .filter_map(|k| {
                    let key = format!("{LOCK}_hold_microseconds_sum{{kind=\"{k}\"}}");
                    Some(rose_over(metric(s0, &key)?, metric(s1, &key)?, started))
                })
                .sum();
            held / 1e6 / (s1.t - s0.t)
        })
        .collect()
}

/// How a quantile read as the bound of its bucket, `bound` µs, meets a bar
/// of `bar` µs. The buckets are powers of two: where the bucket ends at or
/// under the bar the quantile is within it, where it begins at or over the
/// bar it is over it, and where the bucket holds the bar (to 1,024 µs for
/// 1 ms, to 16,384 µs for 10 ms) it cannot be told, and is not resolved.
fn against(bound: Option<u64>, bar: u64) -> Verdict {
    match bound {
        Some(bound) if bound <= bar => Verdict::Pass,
        Some(bound) if bound / 2 < bar => Verdict::NotResolved,
        _ => Verdict::Fail,
    }
}

/// What `key` rose by over the pairs kept, as [`rise`] reads it, where the
/// node counts it: `None` where no sample of the node carries it (a node
/// of a version that does not count it), which is no count of nothing.
fn rise_counted(
    series: &Series,
    key: &str,
    a: f64,
    b: f64,
    keep: &dyn Fn(f64, f64) -> bool,
) -> Option<f64> {
    series
        .iter()
        .any(|s| metric(s, key).is_some())
        .then(|| rise(series, key, a, b, keep))
}

/// The most of a histogram, `key` its `_max`, in µs, over every life of
/// the node up to `b`: the largest that any sample at or before `b`
/// carries, since each life's most counts from its start. It bounds every
/// take of the window, and of what came before it. `None` where no sample
/// carries it.
fn most_up_to(series: &Series, key: &str, b: f64) -> Option<f64> {
    series
        .iter()
        .filter(|s| s.t <= b)
        .filter_map(|s| metric(s, key))
        .reduce(f64::max)
}

/// How the p99 of `n` takes meets a bar of `bar` µs (decision 2026-10-22
/// §3, bar 4). Where the takes over the bar are counted (`over_bar`), that
/// settles it: the p99 is within the bar where at most 1% of the takes are
/// over it, and over the bar where more are. Otherwise the p99 is read as
/// its bucket's bound, `bound` ([`against`]); where that bucket holds the
/// bar, the most held, `most`, settles it where it is within the bar, and
/// nothing else does.
fn p99_against(
    n: f64,
    bound: Option<u64>,
    bar: u64,
    over_bar: Option<f64>,
    most: Option<f64>,
) -> Verdict {
    if let Some(over) = over_bar {
        return match over <= 0.01 * n {
            true => Verdict::Pass,
            false => Verdict::Fail,
        };
    }
    match against(bound, bar) {
        Verdict::NotResolved if most.is_some_and(|m| m <= bar as f64) => Verdict::Pass,
        judged => judged,
    }
}

/// The worse of two verdicts: a failure, then what is not resolved.
fn worse(a: Verdict, b: Verdict) -> Verdict {
    match (a, b) {
        (Verdict::Fail, _) | (_, Verdict::Fail) => Verdict::Fail,
        (Verdict::NotResolved, _) | (_, Verdict::NotResolved) => Verdict::NotResolved,
        _ => a,
    }
}

fn bar_4(read: &Read) -> Line {
    let keep = |t0: f64, t1: f64| !read.is_apart(t0, t1);
    let mut said = Vec::new();
    let mut verdict = Verdict::Pass;
    for r in 0..read.run.plan.relays {
        let series = relay_series(read, r);
        // The worst wait p99 of a request's kind, which is barred, and of
        // the relay's own, which is reported: each with its kind, its
        // verdict and its count over 10 ms of its waits.
        let mut worst_wait = (0u64, "", Verdict::Pass, None);
        let mut worst_own = (0u64, "", Verdict::Pass, None);
        let mut worst_read = (0u64, "", Verdict::Pass);
        let (mut over_250, mut over_50) = (0.0, 0.0);
        for kind in RELAY_TAKES {
            let label = format!("kind=\"{kind}\"");
            let over = |what: &str, ms: &str| {
                rise(
                    &series,
                    &format!("{LOCK}_{what}_microseconds_over{{{label},ms=\"{ms}\"}}"),
                    read.start,
                    read.end,
                    &keep,
                )
            };
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
                // The count over 10 ms settles the p99 against 10 ms. A
                // node that does not count it: at most 1% over 5 ms, the
                // p99 is within 10 ms whatever its bucket; over 1% over
                // 50 ms, it is over; else its bucket, or its most.
                let over_10 = rise_counted(
                    &series,
                    &format!("{LOCK}_wait_microseconds_over{{{label},ms=\"10\"}}"),
                    read.start,
                    read.end,
                    &keep,
                );
                let most = most_up_to(
                    &series,
                    &format!("{LOCK}_wait_microseconds_max{{{label}}}"),
                    read.end,
                );
                let judged = match (over_10, over("wait", "5"), over("wait", "50")) {
                    (None, five, _) if five <= 0.01 * n => Verdict::Pass,
                    (None, _, fifty) if fifty > 0.01 * n => Verdict::Fail,
                    _ => p99_against(n, w[0], 10_000, over_10, most),
                };
                let w99 = w[0].unwrap_or(u64::MAX);
                let request = REQUESTS.contains(&kind);
                let worst = match request {
                    true => &mut worst_wait,
                    false => &mut worst_own,
                };
                if w99 > worst.0 {
                    *worst = (w99, kind, judged, over_10.map(|ten| (ten, n)));
                }
                // Only a request's wait is barred (bar 4 (a)): nothing
                // waits on the relay's own takes, whose holds (c) and (d)
                // bar for the requests they hold up.
                if request {
                    verdict = worse(verdict, judged);
                }
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
                    let most = most_up_to(
                        &series,
                        &format!("{LOCK}_hold_microseconds_max{{{label}}}"),
                        read.end,
                    );
                    let judged = p99_against(n, h[0], 1_000, None, most);
                    let h99 = h[0].unwrap_or(u64::MAX);
                    if h99 > worst_read.0 {
                        worst_read = (h99, kind, judged);
                    }
                    verdict = worse(verdict, judged);
                }
            } else {
                over_250 += over("hold", "250");
                over_50 += over("hold", "50");
            }
        }
        let shares = held_shares(&series, read.start, read.end, &keep);
        let most_share = shares.iter().copied().fold(0.0, f64::max);
        if over_250 > 0.0 || over_50 > 10.0 || most_share > 0.25 {
            verdict = Verdict::Fail;
        }
        let named = |kind: &str, verdict: Verdict| match kind.is_empty() {
            true => "none".to_string(),
            false => format!("{kind}, {}", verdict.word().to_lowercase()),
        };
        let counted = |over_10: Option<(f64, f64)>| match over_10 {
            Some((ten, n)) => format!("; {ten:.0} of {n:.0} over 10 ms"),
            None => String::new(),
        };
        said.push(format!(
            "relay {}: a request's wait p99 at most {} ({}{}), the relay's own wait p99 at most {} \
             ({}{}; reported, not barred), a read's hold p99 at most {} ({}), {over_250:.0} other \
             holds over 250 ms and {over_50:.0} over 50 ms, the lock held at most {:.1}% of a \
             minute",
            r + 1,
            us(Some(worst_wait.0)),
            named(worst_wait.1, worst_wait.2),
            counted(worst_wait.3),
            us(Some(worst_own.0)),
            named(worst_own.1, worst_own.2),
            counted(worst_own.3),
            us(Some(worst_read.0)),
            named(worst_read.1, worst_read.2),
            most_share * 100.0
        ));
    }
    Line {
        title: "A relay's lock, by kind".into(),
        figure: said.join("; "),
        bar: "the wait p99 of each kind of a device's request (show_whole, show_short, proof, \
              pull, push) at most 10 ms, the relay's own kinds' waits reported and not barred; a \
              read's hold p99 at most 1 ms; every other hold under 250 ms and at most 10 over 50 \
              ms; held at most a quarter of any minute (a p99 is read as its bucket's bound, a \
              power of two of µs; where its bucket holds the bar, a wait's p99 is settled by the \
              count over 10 ms, within the bar where at most 1% are over it, and a read's hold by \
              its most, where that is at most 1 ms; NOT RESOLVED only where nothing counted \
              settles it)"
            .into(),
        verdict,
    }
}

fn bar_5(read: &Read) -> Line {
    let keep = |t0: f64, t1: f64| !read.is_apart(t0, t1);
    let allowed = read.hours().ceil().max(1.0);
    let (mut worst, mut over, mut given_up) = (0.0f64, 0, 0.0);
    for i in read.devices() {
        let series = read.series(i);
        let mut n = 0.0;
        for (s0, s1, started) in device_pairs(&series, read.start, read.end) {
            let (Some(d0), Some(d1)) = (s0.device, s1.device) else {
                continue;
            };
            given_up += rose_over(d0.given_up, d1.given_up, started);
            if keep(s0.t, s1.t) {
                n += rose_over(d0.waits_over_100, d1.waits_over_100, started);
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
/// its longest stretch in that half with no start, and the RSS in MiB it
/// rose from: the RSS at that stretch's start, or what it held before the
/// start that began it where that is higher, so that filling again to it
/// is no growth. `None` where that stretch is under a quarter of the half.
fn halves(series: &[&Sample], read: &Read, node: usize) -> Option<[(f64, f64); 2]> {
    let mid = (read.start + read.end) / 2.0;
    let half = (mid - read.start).max(1.0);
    let rss = |s: &Sample| s.proc.map_or(0.0, |p| p.rss_kib as f64);
    let starts = read.lives.starts(node);
    let held_before_start = |t: f64| -> f64 {
        let Some(start) = starts
            .iter()
            .copied()
            .filter(|s| *s <= t)
            .max_by(f64::total_cmp)
        else {
            return 0.0;
        };
        series
            .iter()
            .filter(|s| s.t < start && s.proc.is_some())
            .max_by(|x, y| x.t.total_cmp(&y.t))
            .map_or(0.0, |s| rss(s))
    };
    let rise_in = |a: f64, b: f64| -> Option<(f64, f64)> {
        let mut best: Option<(&Sample, &Sample, f64)> = None;
        let mut first: Option<&Sample> = None;
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
                best = Some((f, s, long));
            }
        }
        let (f, s, long) = best?;
        let from = rss(f).max(held_before_start(f.t));
        (long >= half / 4.0).then(|| ((rss(s) - from) / 1024.0 / (long / 3600.0), from / 1024.0))
    };
    Some([rise_in(read.start, mid)?, rise_in(mid, read.end)?])
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
        if let Some([(a, _), (b, _)]) = halves(&series, read, i) {
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
                 over {threshold:.1} MiB an hour in both halves (filling again to what it held \
                 before a start is no growth; one device growing in two runs of three is read \
                 across the stage's summaries)"
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
        // The connections it held, as last counted: a sample whose counters
        // did not answer is held against the count before it.
        let mut open = None;
        for s in series.iter().filter(|s| s.t <= read.end) {
            open = metric(s, "cordelia_connections_open").or(open);
            if s.t < read.start {
                continue;
            }
            let (Some(p), Some(open)) = (s.proc, open) else {
                continue;
            };
            let rss = p.rss_kib as f64 / 1024.0;
            worst = worst.max(rss);
            if rss > 64.0 + open * 384.0 / 1024.0 {
                over += 1;
            }
        }
        // The 2% an hour is of the RSS it rose from in each half: its first
        // sample is taken as it starts, at a few MiB, and a start again in
        // the window lowers its median.
        let rises = halves(&series, read, i);
        let grows = rises.is_some_and(|h| h.iter().all(|&(rise, from)| rise > 0.02 * from));
        holds &= over == 0 && !grows;
        said.push(format!(
            "relay {}: the most RSS {worst:.1} MiB, {over} samples over the bar, {}",
            r + 1,
            match rises {
                None => "growth not tested (a half's longest stretch is under a quarter of it)"
                    .to_string(),
                Some([(a, fa), (b, fb)]) => format!(
                    "{} (rises of {a:.2} and {b:.2} MiB an hour, from {fa:.1} and {fb:.1} MiB)",
                    if grows {
                        "growing in both halves"
                    } else {
                        "no persistent growth"
                    }
                ),
            }
        ));
    }
    line(
        "A relay's memory in ordinary use",
        said.join("; "),
        "RSS at most 64 MiB and 384 KiB for each open connection, and no growth of 2% of its \
         RSS an hour in both halves (from the RSS each half rose from: where a start began the \
         stretch, what it held before, if higher)",
        holds,
    )
}

/// A process's share of a core over each pair of its samples from /proc,
/// and over all of them. A pair across a start is left out: the new
/// process's CPU would be spread over the time it was not there.
fn cpu(read: &Read, series: &Series) -> (Vec<f64>, f64) {
    let mut each = Vec::new();
    let (mut ticks, mut secs) = (0.0, 0.0);
    for (s0, s1, started) in pairs_having(series, read.start, read.end, |s| s.proc.is_some()) {
        let (Some(p0), Some(p1)) = (s0.proc, s1.proc) else {
            continue;
        };
        if s1.t <= s0.t || started {
            continue;
        }
        let t = rose_over(p0.ticks as f64, p1.ticks as f64, false) / read.tps;
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
        for s in series.iter() {
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
                        // A device that this relay's warm churn closed on in
                        // the last 150 s dials again 10 s later at the
                        // soonest (the record of a relay out of reach §2):
                        // it is not looked for. A closure with no churn, or
                        // start, of this relay is not excused.
                        if read
                            .lives
                            .running_since(node, s.t)
                            .is_some_and(|since| s.t - since >= 120.0)
                            && !(closed_lately(read, node, s.t) && churned_lately(read, i, s.t))
                        {
                            lo += 1.0;
                        }
                    }
                    _ if read.lives.frozen_within(node, s.t, 90.0) => hi += 1.0,
                    _ => {}
                }
            }
            if has_office && read.run.setup.office_moved.is_some() {
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
         (a device that counts a connection closed in the last 150 s is not looked for where \
         this relay's warm churn closed a device's connection, or it started, then); none \
         turned away for the bound or the subnet",
        holds,
    )
}

/// Whether device `node` counts a connection of its own closed in the 150 s
/// before `t`: from its last sample of counts before then to its first at
/// or after `t`, where a closure just before `t` is first counted.
fn closed_lately(read: &Read, node: usize, t: f64) -> bool {
    let series = read.series(node);
    let from = t - 150.0;
    let counted: Vec<&Sample> = series
        .iter()
        .copied()
        .filter(|s| s.device.is_some())
        .collect();
    let first = counted.iter().rposition(|s| s.t < from).unwrap_or(0);
    let last = counted
        .iter()
        .position(|s| s.t >= t)
        .unwrap_or(counted.len().saturating_sub(1));
    counted
        .get(first..=last.max(first))
        .unwrap_or_default()
        .windows(2)
        .any(|w| w[1].device.map(|d| d.closed) != w[0].device.map(|d| d.closed))
}

/// Whether relay `relay` closed a device's connection by warm churn, or
/// started, in the 150 s before `t`: read as [`closed_lately`] reads a
/// device, from its last sample that carries the count before then to its
/// first at or after `t`.
fn churned_lately(read: &Read, relay: usize, t: f64) -> bool {
    read.lives
        .running_since(relay, t)
        .is_some_and(|since| since > t - 150.0)
        || warm_churn_closed_lately(read, relay, t)
}

/// Whether relay `relay`'s warm churn closed a device's connection in the
/// 150 s before `t`, read as [`churned_lately`] reads it: from its last
/// sample that carries the count before then to its first at or after `t`.
fn warm_churn_closed_lately(read: &Read, relay: usize, t: f64) -> bool {
    let from = t - 150.0;
    let key = "cordelia_closed_by_warm_churn_total{peer=\"device\"}";
    let series = read.series(relay);
    let carrying = || series.iter().filter(|s| metric(s, key).is_some());
    let a = carrying().rev().find(|s| s.t < from).map_or(from, |s| s.t);
    let b = carrying().find(|s| s.t >= t).map_or(t, |s| s.t);
    rise(&series, key, a, b, &|_, _| true) > 0.0
}

fn bar_10(read: &Read, edits: &Edits) -> Line {
    let removals = read.run.removals.clone();
    let planned = read.run.removals_planned;
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
        let command = match r.command_ended {
            Some((t, true)) => format!("the command ended {:.0} s after the line", t - line_at),
            Some((_, false)) => "the command did not end as it should".into(),
            None => "the command's end was not read".into(),
        };
        said.push(format!(
            "person {} (change {}): applied by every other device in {spread:.1} s, held by \
             every relay in {held:.1} s; the carry window {carry:.1} s against T = {:.1} s for \
             {} bytes; {late} of the person's edits late in it; {command}",
            r.person,
            r.change.map_or("?".into(), |c| c.to_string()),
            r.bound,
            r.carried_bytes
        ));
    }
    if removals.len() < planned {
        holds = false;
        said.push(format!(
            "{} of the {planned} removals planned were made",
            removals.len()
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
    let outage = read.run.outage.clone();
    let in_outage = |t: f64| {
        outage.stopped.is_some_and(|a| t >= a - 5.0) && outage.started.is_none_or(|b| t <= b + 5.0)
    };
    let mut gaps = Vec::new();
    for i in read.devices() {
        let mut closed: HashMap<String, f64> = HashMap::new();
        for raw in &read.run.fleet.made[i].log {
            let text = strip_ansi(raw);
            let Some(t) = text.split_whitespace().next().and_then(log_time) else {
                continue;
            };
            let t = read.run.fleet.of_wall(t);
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

pub(crate) fn strip_ansi(s: &str) -> String {
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
fn kept_spans(series: &Series, read: &Read, keep: &dyn Fn(f64, f64) -> bool) -> Vec<(f64, f64)> {
    let mut spans: Vec<(f64, f64)> = Vec::new();
    for (s0, s1, _) in pairs_having(series, read.start, read.end, |s| s.metrics.is_some())
        .into_iter()
        .filter(|(s0, s1, _)| keep(s0.t, s1.t))
    {
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
    // Whom the relay held a connection from, as each of its samples read
    // it: a device that is on and not connected to it (warm churn closed
    // its connection, and it dials again later) asks it nothing.
    let series = relay_series(read, r);
    let peers: Vec<(f64, HashSet<&str>)> = series
        .iter()
        .filter_map(|s| {
            let keys = s
                .peers
                .as_ref()?
                .iter()
                .map(|(key, _)| key.as_str())
                .collect();
            Some((s.t, keys))
        })
        .collect();
    let gap = 2.0 * read.run.plan.timing.sample_every;
    let connected = |key: &str, t: f64| {
        peers
            .iter()
            .rev()
            .find(|(at, _)| *at <= t)
            .filter(|(at, _)| t - at <= gap)
            .is_none_or(|(_, keys)| keys.contains(key))
    };
    for (k, d) in plan.population.each_device() {
        let p = &plan.population.people[k];
        if !p.relays_of(d, plan.relays).contains(&r) || p.office {
            continue;
        }
        let node = read.run.fleet.device(k, d);
        let key = read.run.fleet.made[node].key.as_str();
        let mut t = read.start;
        while t < read.end {
            if kept(t) && read.lives.at(node, t) == Is::Running && connected(key, t) {
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
            "pulls within a fifth of §2.3 for the minutes each device was on and connected to the \
             relay (in the relay's peers at its last sample); edits within a \
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
    let observer = &read.run.observer;
    let all: Vec<&crate::observer::Written> = observer.edits.iter().collect();
    let (mut least, mut most) = (0.0, 0.0);
    for k in 0..read.run.plan.population.people.len() {
        let (l, m) = room_of(read, &all, k);
        least += l;
        most += m;
    }
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
    let outage = read.run.outage.clone();
    for r in 0..read.run.plan.relays {
        let i = read.run.fleet.relays[r];
        let series = read.series(i);
        let (mut off, mut after_churn) = (Vec::new(), 0);
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
            // Fewer within 150 s after this relay's warm churn closed a
            // device's connection, as bar 9 allows: the churn may close
            // one of the office's, and its next dial takes the place
            // again 10 s later at the soonest (the record of a relay out
            // of reach §2). More than 5 is never excused.
            if n < 5 && warm_churn_closed_lately(read, i, s.t) {
                after_churn += 1;
            } else if n != 5 {
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
            "relay {}: {} samples not 5 from the office's address{}, {after_churn} fewer within \
             150 s after a warm churn closed a device; {away:.0} dials turned away for the \
             address, {for_a_time:.0} refusals for a time",
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
         after, and fewer only within 150 s after that relay's warm churn closed a device's \
         connection; other dials turned away and counted; no refusal for a time",
        holds,
    )
}

/// Whether an edit of a split person held up by the second relay's
/// outage (stopped at `stopped`, started at `started`) came late (bar 15).
/// It is owed within 120 s of the start where the device it waits on ran
/// through those 120 s and its writer ran until it could push: for
/// [`HELD_BY_A_RUNNING_DEVICE_SECS`] from the edit where it had a relay
/// that ran then (the first relay, or the second where it ran those
/// seconds before its stop), and through the 120 s otherwise, as the edit
/// waits on it until the relay is back. Where either did not, it is owed
/// once the later of the two, after it ran again, has run
/// [`CATCH_UP_SECS`] without a stop or a freeze (bar 3's catch-up), and
/// never sooner; one that never arrives is late there only where both
/// devices were running at the end.
fn split_edit_late(read: &Read, p: &Pair, stopped: f64, started: f64) -> bool {
    let person = &read.run.plan.population.people[p.edit.person];
    let writer = read.run.fleet.device(p.edit.person, p.edit.writer);
    let pushed = p.edit.at + HELD_BY_A_RUNNING_DEVICE_SECS;
    let up = person
        .relays_of(p.edit.writer, read.run.plan.relays)
        .contains(&0)
        || (pushed <= stopped && read.lives.ran_through(writer, p.edit.at, pushed));
    let writer_until = if up { pushed } else { started + 120.0 };
    let mut deadline = started + 120.0;
    let mut held = false;
    for (node, a, b) in [
        (p.node, started, started + 120.0),
        (writer, p.edit.at, writer_until),
    ] {
        if read.lives.ran_through(node, a, b) {
            continue;
        }
        held = true;
        // One that never ran again holds nothing up: where it is the
        // writer and the edit arrived, it had pushed before it stopped.
        // One that ran again is owed its catch-up once it has run that long
        // without a stop or a freeze.
        if let Some(t) = read.lives.ran_again_after(node, a, b) {
            let caught_up = read.lives.ran_for_after(node, t, CATCH_UP_SECS);
            deadline = deadline.max(caught_up.unwrap_or(f64::INFINITY));
        }
    }
    match p.arrived {
        Some(a) => a.at > deadline,
        None => {
            !held
                || (deadline <= read.end
                    && [writer, p.node]
                        .iter()
                        .all(|&n| read.lives.at(n, read.end) == Is::Running))
        }
    }
}

fn bar_15(read: &Read, edits: &Edits) -> Line {
    let outage = read.run.outage.clone();
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
        .filter(|p| split_edit_late(read, p, stopped, started))
        .count();
    let keep = |_: f64, _: f64| true;
    // None refused at a relay, and none held back by a device's own pace
    // but for the minute of its own connection's proofs.
    let refused = refused_for_rate(read, started, started + 300.0);
    let (held, _) = held_back(read, started, started + 300.0);
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
        && refused == 0.0
        && held == 0.0;
    line(
        "A relay that stops is come back to",
        format!(
            "{} devices connected again, the slowest {slowest:.0} s after its start; through the \
             outage, {} arrivals at p50 {p50:.1} s, p95 {p95:.1} s, the most {most:.1} s, \
             {late_both} not within 120 s; {split_late} split people's edits late (past 120 s \
             after the start, or 60 s after their devices ran again); {refused:.0} refused for rate at the relays and {held:.0} held \
             back by a device outside its own connection's proofs in the five minutes after; in \
             those minutes the relay was asked {:.0} pulls and {:.0} pushes, held its lock {} of a \
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
         people with both; held-up split edits within 120 s of its start, or within 60 s of \
         the later of their devices running again where one was held up; none refused for \
         rate in the five minutes after, and none held back but for what the minute of a \
         connection's proofs holds back",
        holds,
    )
}

// ── The checks of §6 ────────────────────────────────────────────────

/// Whether a sample carries the node's counters: a relay's, or a
/// device's.
fn carries_counters(s: &Sample) -> bool {
    s.metrics.is_some() || s.device.is_some()
}

fn checks(read: &Read, edits: &Edits, bar_12: bool) -> Vec<Line> {
    let mut c = Vec::new();
    // 1. Every process was sampled: by a sample that carries its counters,
    // not /proc alone.
    let mut worst_gap: f64 = 0.0;
    let mut who = String::new();
    for i in 0..read.run.fleet.made.len() {
        let series = read.series(i);
        let mut t = read.start;
        while t <= read.end {
            if let Some(since) = read.lives.running_since(i, t) {
                let seen = series
                    .iter()
                    .filter(|s| s.t <= t && carries_counters(s))
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
    // 2. The counts agree, over the run: each process's last sample that
    // carries its counters, of each time it ran.
    let lasts = |node: usize| -> Vec<&Sample> {
        let series = read.series(node);
        let counted: Vec<&Sample> = series
            .iter()
            .copied()
            .filter(|s| carries_counters(s))
            .collect();
        let mut out = Vec::new();
        for (n, s) in counted.iter().enumerate() {
            let next = counted.get(n + 1);
            if next.is_none_or(|x| series.started(s.t, x.t)) {
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
    // 3. The edits add up, by counts kept apart: every edit numbered was
    // recorded; every wait begun ended once, arrived, still waited for at
    // the end (not arrived), or on a device removed; and each other device
    // of each edit of the window was waited for.
    let k = &edits.counted;
    let others: usize = edits
        .window
        .iter()
        .map(|e| read.run.plan.population.people[e.person].devices - 1)
        .sum();
    let removed_before: usize = edits
        .window
        .iter()
        .map(|e| {
            read.run
                .removals
                .iter()
                .filter(|r| r.person == e.person && r.line_at.is_some_and(|line| line <= e.at))
                .count()
        })
        .sum();
    let window_waited = edits
        .pairs
        .iter()
        .filter(|p| p.edit.at >= read.start)
        .count();
    c.push(line(
        "The edits add up",
        format!(
            "{} edits numbered, {} recorded; {} waits begun: {} arrived, {} still waited for at \
             the end (not arrived), {} on a device removed meanwhile; {window_waited} waits for \
             the window's edits against {} other devices of their people",
            k.numbered,
            k.recorded,
            k.waited,
            k.arrived,
            k.pending,
            k.gone,
            others - removed_before
        ),
        "every edit numbered is recorded; every wait ends once, as arrived, not arrived or on a \
         device removed; each edit is waited for on each other device of its person",
        k.numbered == k.recorded
            && k.waited == k.arrived + k.pending + k.gone
            && window_waited == others - removed_before,
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
    let outage = read.run.outage.clone();
    let mut said = Vec::new();
    let mut had = !read.run.cut;
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
                 the most held {most:.0} µs, {:.0} over 5 ms, {:.0} over 10 ms and {:.0} over 50 \
                 ms; {:.0} waits over 10 ms",
                us(w[0]),
                us(w[1]),
                us(w[2]),
                us(h[0]),
                us(h[1]),
                us(h[2]),
                over("5"),
                over("10"),
                over("50"),
                rise(
                    &series,
                    &format!("{LOCK}_wait_microseconds_over{{{label},ms=\"10\"}}"),
                    read.start,
                    read.end,
                    &keep,
                )
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
        let nested: Vec<String> = ["rates", "room", "uses"]
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
            for (s0, s1, started) in device_pairs(&series, read.start, read.end) {
                let (Some(d0), Some(d1)) = (s0.device, s1.device) else {
                    continue;
                };
                let rose = |v0: f64, v1: f64| rose_over(v0, v1, started);
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
    let removals = read.run.removals.clone();
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
    let outage = read.run.outage.clone();
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

// The tests of the report's logic, from made-up samples: no process.
#[path = "report_tests.rs"]
mod made_up;
