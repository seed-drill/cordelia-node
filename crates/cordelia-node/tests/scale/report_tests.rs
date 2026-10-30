//! The report's logic, from made-up samples: a run whose nodes are never
//! started (`Run::made_up`, section 6's small population: relays 0 and 1;
//! person 0's devices 2 and 3; person 1's 4, 5 and 6; person 2's 7 and 8),
//! given the samples, the changes and the edits each test reads.

use std::collections::BTreeMap;

use super::*;
use crate::fleet::{DeviceCounts, MachineSample};
use crate::observer::{Arrival, Written};
use crate::run::{Outage, Plan, Removal};

fn made_up() -> (tempfile::TempDir, Run) {
    let dir = tempfile::tempdir().unwrap();
    let run = Run::made_up(Plan::small(1), dir.path());
    (dir, run)
}

/// Every node runs from `t`.
fn all_running(run: &Run, t: f64) {
    let mut changes = run.fleet.changes.lock().unwrap();
    for node in 0..run.fleet.made.len() {
        changes.push(Change {
            t,
            node,
            is: Is::Running,
            ended: None,
        });
    }
}

fn becomes(run: &Run, node: usize, t: f64, is: Is) {
    run.fleet.changes.lock().unwrap().push(Change {
        t,
        node,
        is,
        ended: None,
    });
}

fn window(run: &Run, a: f64, b: f64) {
    *run.window.lock().unwrap() = Some((a, Some(b)));
}

/// A sample of a relay at `t` with these counters (none where `metrics`
/// is `None`: a read that failed, /proc alone).
fn relay_at(run: &Run, node: usize, t: f64, metrics: Option<&[(&str, f64)]>) {
    run.samples.lock().unwrap().nodes.push(Sample {
        t,
        node,
        proc: Some(crate::machine::ProcRead::default()),
        metrics: metrics.map(|m| m.iter().map(|(k, v)| (k.to_string(), *v)).collect()),
        ..Sample::default()
    });
}

fn device_at(run: &Run, node: usize, t: f64, counts: Option<DeviceCounts>) {
    run.samples.lock().unwrap().nodes.push(Sample {
        t,
        node,
        proc: Some(crate::machine::ProcRead::default()),
        device: counts,
        ..Sample::default()
    });
}

const PULLS: &str = "cordelia_requests_total{kind=\"pull\"}";

// ── High 2: bar 1 counts a relay's refusal for rate in the whole window ──

/// A relay that refuses a request for rate inside the parts treated apart
/// (here the five minutes after the second relay's start again) fails bar
/// 1: a breach fails it at any time of the window (bar 10c).
#[test]
fn bar_1_counts_a_relays_refusal_for_rate_inside_a_part_treated_apart() {
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    window(&run, 0.0, 600.0);
    *run.outage.lock().unwrap() = Outage {
        stopped: Some(200.0),
        started: Some(320.0),
        back: Vec::new(),
    };
    let key = "cordelia_answers_total{kind=\"pull\",answer=\"refused_for_rate\"}";
    for t in (0..=10).map(|n| n as f64 * 60.0) {
        let refused = if t >= 360.0 { 1.0 } else { 0.0 };
        relay_at(&run, 0, t, Some(&[(key, refused)]));
    }
    let read = read_of(&run);
    assert!(
        read.is_apart(300.0, 360.0),
        "the refusal lies in a part apart"
    );
    let bar = bar_1(&read);
    assert_eq!(bar.verdict, Verdict::Fail, "{}", bar.figure);
    assert!(bar.figure.starts_with("1 refused"), "{}", bar.figure);
}

// ── High 3: replaced by intent only where the device was not there ──

/// Edit 10 by device 0 reaches device 1, which writes edit 11 over it;
/// edit 11 reaches device 2, edit 10 never does. Device 2 ran all through:
/// it was owed edit 10, which is lost. Had device 2 been off between the
/// two, edit 11 would have replaced it by intent.
#[test]
fn an_edit_is_replaced_by_intent_only_where_the_device_was_off_between() {
    for off_between in [false, true] {
        let (_dir, run) = made_up();
        all_running(&run, 0.0);
        window(&run, 0.0, 1000.0);
        let (n, m) = (10u64, 11u64);
        if off_between {
            becomes(&run, 6, 220.0, Is::Stopped);
            becomes(&run, 6, 280.0, Is::Running);
        }
        {
            let mut o = run.observer.lock().unwrap();
            let edit = |number: u64, writer: usize, at: f64, replaced: Option<u64>| Written {
                number,
                person: 1,
                writer,
                name: 0,
                file: "f001.md".into(),
                size: 600,
                at,
                burst: false,
                new: false,
                replaced,
            };
            let dir = run.out.clone();
            o.wrote(
                edit(n, 0, 200.0, None),
                vec![(1, dir.clone()), (2, dir.clone())],
            );
            o.wrote(edit(m, 1, 300.0, Some(n)), vec![(0, dir.clone()), (2, dir)]);
            for (number, device, at) in [(n, 1, 210.0), (m, 0, 305.0), (m, 2, 310.0)] {
                o.arrivals
                    .insert((number, device), Arrival { at, in_copy: false });
            }
        }
        let read = read_of(&run);
        let edits = edits_of(&read);
        let at_2 = edits
            .pairs
            .iter()
            .find(|p| p.edit.number == n && p.device == 2)
            .unwrap();
        assert_eq!(at_2.replaced, off_between, "off between: {off_between}");
        let bar = bar_3(&read, &edits);
        let want = match off_between {
            true => Verdict::Pass,
            false => Verdict::Fail,
        };
        assert_eq!(
            bar.verdict, want,
            "off between: {off_between}: {}",
            bar.figure
        );
    }
}

// ── Medium 4: a failed read loses nothing, and a start counts from zero ──

/// A relay's read that failed (a sample of /proc alone) lies between two
/// that carry the counter: the rise across it is kept. A process that
/// started again between two samples counts from nothing, even where its
/// new count is higher than the old.
#[test]
fn a_failed_read_loses_no_count_and_a_start_counts_from_nothing() {
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    window(&run, 0.0, 1000.0);
    relay_at(&run, 0, 100.0, Some(&[(PULLS, 0.0)]));
    relay_at(&run, 0, 160.0, None);
    relay_at(&run, 0, 220.0, Some(&[(PULLS, 100.0)]));
    relay_at(&run, 0, 280.0, Some(&[(PULLS, 160.0)]));
    becomes(&run, 1, 150.0, Is::Stopped);
    becomes(&run, 1, 200.0, Is::Running);
    relay_at(&run, 1, 100.0, Some(&[(PULLS, 50.0)]));
    relay_at(&run, 1, 260.0, Some(&[(PULLS, 80.0)]));
    let read = read_of(&run);
    let all = |_: f64, _: f64| true;
    assert_eq!(rise(&read.series(0), PULLS, 0.0, 1000.0, &all), 160.0);
    assert_eq!(rise(&read.series(1), PULLS, 0.0, 1000.0, &all), 80.0);
}

/// Check 1 counts only a sample that carries a process's counters: a
/// device read by /proc alone for five minutes was not sampled.
#[test]
fn a_process_read_by_proc_alone_was_not_sampled() {
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    window(&run, 0.0, 600.0);
    for node in 0..run.fleet.made.len() {
        for t in (0..=10).map(|n| n as f64 * 60.0) {
            let read_failed = node == 2 && (100.0..=400.0).contains(&t);
            match (node < 2, read_failed) {
                (true, _) => relay_at(&run, node, t, Some(&[(PULLS, 0.0)])),
                (false, true) => device_at(&run, node, t, None),
                (false, false) => device_at(&run, node, t, Some(DeviceCounts::default())),
            }
        }
    }
    let read = read_of(&run);
    let edits = edits_of(&read);
    let checks = checks(&read, &edits, true);
    assert_eq!(checks[0].verdict, Verdict::Fail, "{}", checks[0].figure);
    assert!(checks[0].figure.contains("p000-d0"), "{}", checks[0].figure);
}

// ── Medium 5: a p99 in the bucket that holds the bar is not resolved ──

/// The counters of one kind's histogram: `counts` of takes in buckets
/// ending at each bound, the counts over each length of `over` (ms), and
/// its most where `most` is given. A length not in `over` is not counted,
/// as by a node of a version that does not count it.
fn histogram(
    name: &str,
    kind: &str,
    counts: &[(u64, f64)],
    over: &[(u64, f64)],
    most: Option<f64>,
) -> Vec<(String, f64)> {
    let mut lines = Vec::new();
    let mut summed = 0.0;
    for i in 0..cordelia_core::protocol::LOAD_HISTOGRAM_BUCKETS {
        let bound = 1u64 << i;
        summed += counts
            .iter()
            .filter(|(b, _)| *b == bound)
            .map(|(_, n)| n)
            .sum::<f64>();
        lines.push((
            format!("{name}_bucket{{kind=\"{kind}\",le=\"{bound}\"}}"),
            summed,
        ));
    }
    lines.push((
        format!("{name}_bucket{{kind=\"{kind}\",le=\"+Inf\"}}"),
        summed,
    ));
    for (ms, n) in over {
        lines.push((format!("{name}_over{{kind=\"{kind}\",ms=\"{ms}\"}}"), *n));
    }
    if let Some(most) = most {
        lines.push((format!("{name}_max{{kind=\"{kind}\"}}"), most));
    }
    lines
}

/// The waits and the holds of one kind, pull unless it says, at relay 1.
struct Takes<'a> {
    kind: &'a str,
    waits: &'a [(u64, f64)],
    wait_over: &'a [(u64, f64)],
    wait_most: Option<f64>,
    holds: &'a [(u64, f64)],
    hold_most: Option<f64>,
}

const FAST: [(u64, f64); 1] = [(64, 100.0)];

impl Default for Takes<'_> {
    fn default() -> Self {
        Takes {
            kind: "pull",
            waits: &FAST,
            wait_over: &[(5, 0.0), (10, 0.0), (50, 0.0)],
            wait_most: None,
            holds: &FAST,
            hold_most: None,
        }
    }
}

fn bar_4_with(takes: Takes) -> Line {
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    window(&run, 0.0, 200.0);
    let mut lines = histogram(
        &format!("{LOCK}_wait_microseconds"),
        takes.kind,
        takes.waits,
        takes.wait_over,
        takes.wait_most,
    );
    lines.extend(histogram(
        &format!("{LOCK}_hold_microseconds"),
        takes.kind,
        takes.holds,
        &[(5, 0.0), (10, 0.0), (50, 0.0)],
        takes.hold_most,
    ));
    let zero: Vec<(&str, f64)> = lines.iter().map(|(k, _)| (k.as_str(), 0.0)).collect();
    let after: Vec<(&str, f64)> = lines.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    relay_at(&run, 0, 0.0, Some(&zero));
    relay_at(&run, 0, 100.0, Some(&after));
    let read = read_of(&run);
    bar_4(&read)
}

/// A node that counts its waits over 5 and 50 ms and not over 10 ms.
fn bar_4_of(waits: &[(u64, f64)], over_5: f64, over_50: f64, holds: &[(u64, f64)]) -> Line {
    bar_4_with(Takes {
        waits,
        wait_over: &[(5, over_5), (50, over_50)],
        holds,
        ..Takes::default()
    })
}

/// A node that does not count its waits over 10 ms: a wait p99 between
/// 8.192 and 16.384 ms, where the waits over 5 ms do not settle it, cannot
/// be told from the bar of 10 ms: NOT RESOLVED, not PASS. Within the
/// bucket that ends under the bar it passes, and in the one that begins
/// over it it fails. A read's hold p99 between 513 and 1,024 µs is not
/// resolved against 1 ms where its most is not given.
#[test]
fn a_p99_in_the_bucket_that_holds_the_bar_is_not_resolved() {
    let fast = FAST;
    // 98 waits under 4 ms and 2 between 8.2 and 16.4 ms: 2% over 5 ms.
    let straddle = bar_4_of(&[(4096, 98.0), (16384, 2.0)], 2.0, 0.0, &fast);
    assert_eq!(
        straddle.verdict,
        Verdict::NotResolved,
        "{}",
        straddle.figure
    );
    let within = bar_4_of(&[(4096, 100.0)], 0.0, 0.0, &fast);
    assert_eq!(within.verdict, Verdict::Pass, "{}", within.figure);
    let over = bar_4_of(&[(4096, 98.0), (32768, 2.0)], 2.0, 0.0, &fast);
    assert_eq!(over.verdict, Verdict::Fail, "{}", over.figure);
    // At most 1% over 5 ms: within the bar whatever the bucket says.
    let settled = bar_4_of(&[(4096, 99.0), (16384, 1.0)], 1.0, 0.0, &fast);
    assert_eq!(settled.verdict, Verdict::Pass, "{}", settled.figure);
    let read_straddle = bar_4_of(&[(4096, 100.0)], 0.0, 0.0, &[(64, 98.0), (1024, 2.0)]);
    assert_eq!(
        read_straddle.verdict,
        Verdict::NotResolved,
        "{}",
        read_straddle.figure
    );
}

/// The waits of stage 190's relay 2, of kind sweep (decision 2026-10-22
/// §7.3): 104 waits, 2 over 5 ms, none over 50 ms, the most 17,004 µs; so
/// the p99, the second largest, is in the bucket of 8,193 to 16,384 µs.
/// The count over 10 ms settles it: with one wait over 10 ms (under 1% of
/// 104, 1.04) the p99 is within the bar, and with two it is over it.
/// Without that count it is NOT RESOLVED, as it was.
#[test]
fn the_count_over_10_ms_settles_a_wait_p99_in_the_bucket_that_holds_the_bar() {
    let waits = [(4096, 102.0), (16384, 1.0), (32768, 1.0)];
    let with = |ten: Option<f64>| {
        let mut over = vec![(5, 2.0), (50, 0.0)];
        over.extend(ten.map(|ten| (10, ten)));
        bar_4_with(Takes {
            waits: &waits,
            wait_over: &over,
            wait_most: Some(17_004.0),
            ..Takes::default()
        })
    };
    let one = with(Some(1.0));
    assert_eq!(one.verdict, Verdict::Pass, "{}", one.figure);
    assert!(one.figure.contains("1 of 104 over 10 ms"), "{}", one.figure);
    let two = with(Some(2.0));
    assert_eq!(two.verdict, Verdict::Fail, "{}", two.figure);
    assert!(two.figure.contains("2 of 104 over 10 ms"), "{}", two.figure);
    let none = with(None);
    assert_eq!(none.verdict, Verdict::NotResolved, "{}", none.figure);
    assert!(!none.figure.contains("over 10 ms"), "{}", none.figure);
}

/// The count over 10 ms rules where it is counted: the waits over 5 ms
/// alone would pass a p99 that more than 1% over 10 ms puts over the bar,
/// and they cannot (two in 100 over 5 and over 10 ms fails; one passes).
#[test]
fn the_count_over_10_ms_is_read_against_1_percent_of_the_kinds_waits() {
    let waits = [(4096, 98.0), (16384, 2.0)];
    let at = |ten: f64| {
        bar_4_with(Takes {
            waits: &waits,
            wait_over: &[(5, 2.0), (10, ten), (50, 0.0)],
            ..Takes::default()
        })
    };
    assert_eq!(at(0.0).verdict, Verdict::Pass, "{}", at(0.0).figure);
    assert_eq!(at(1.0).verdict, Verdict::Pass, "{}", at(1.0).figure);
    assert_eq!(at(2.0).verdict, Verdict::Fail, "{}", at(2.0).figure);
}

/// The most held settles a read's hold p99 in the bucket of 513 to 1,024
/// µs where it is at most 1 ms (bar 4 (b)), and nothing else does: with
/// the most at 1,000 µs it passes, at 1,001 µs it is NOT RESOLVED. A wait
/// of a node that does not count over 10 ms is settled so too.
#[test]
fn the_most_held_settles_a_p99_in_the_bucket_that_holds_the_bar_where_it_is_within() {
    let holds = [(64, 98.0), (1024, 2.0)];
    let held = |most: f64| {
        bar_4_with(Takes {
            holds: &holds,
            hold_most: Some(most),
            ..Takes::default()
        })
    };
    assert_eq!(
        held(1_000.0).verdict,
        Verdict::Pass,
        "{}",
        held(1_000.0).figure
    );
    assert_eq!(
        held(1_001.0).verdict,
        Verdict::NotResolved,
        "{}",
        held(1_001.0).figure
    );
    let waits = [(4096, 98.0), (16384, 2.0)];
    let waited = |most: f64| {
        bar_4_with(Takes {
            waits: &waits,
            wait_over: &[(5, 2.0), (50, 0.0)],
            wait_most: Some(most),
            ..Takes::default()
        })
    };
    assert_eq!(waited(10_000.0).verdict, Verdict::Pass);
    assert_eq!(waited(10_001.0).verdict, Verdict::NotResolved);
}

/// Stage 190's relay 1, seed 1: its waits of kind sweep, 131 takes, 2 over
/// 10 ms (the most 10,648 µs), in the minute of its hourly sweep. Bar 4 (a)
/// bars the waits of a device's requests alone: the sweep's p99 is over
/// 10 ms and is reported, and the bar passes. A request's kind with the
/// same waits fails it.
#[test]
fn bar_4_bars_the_wait_of_a_devices_request_and_reports_the_relays_own() {
    let waits = [(4096, 129.0), (16384, 2.0)];
    let of = |kind| {
        bar_4_with(Takes {
            kind,
            waits: &waits,
            wait_over: &[(5, 2.0), (10, 2.0), (50, 0.0)],
            wait_most: Some(10_648.0),
            ..Takes::default()
        })
    };
    let sweep = of("sweep");
    assert_eq!(sweep.verdict, Verdict::Pass, "{}", sweep.figure);
    assert!(
        sweep.figure.contains(
            "the relay's own wait p99 at most 16.4 ms (sweep, fail; 2 of 131 over 10 ms; \
             reported, not barred)"
        ),
        "{}",
        sweep.figure
    );
    for kind in ["show_whole", "show_short", "proof", "pull", "push"] {
        let request = of(kind);
        assert_eq!(request.verdict, Verdict::Fail, "{kind}: {}", request.figure);
        assert!(
            request.figure.contains(&format!(
                "a request's wait p99 at most 16.4 ms ({kind}, fail; 2 of 131 over 10 ms)"
            )),
            "{}",
            request.figure
        );
    }
    for kind in ["relays", "checkpoint", "api", "other"] {
        assert_eq!(
            of(kind).verdict,
            Verdict::Pass,
            "{kind}: {}",
            of(kind).figure
        );
    }
}

/// Bar 14 at a stage with an office: each relay sampled every minute, 5
/// connections from the office's address at each sample but relay 1's at
/// 300 s, which holds `held`. With `churned`, relay 1's warm churn closed a
/// device's connection between its samples at 240 s and 300 s. With
/// `started`, relay 1 is down from 180 s to 200 s: no churn, and not the
/// outage of step 7, which is the second relay's.
fn bar_14_with(churned: bool, held: usize, started: bool) -> Line {
    let dir = tempfile::tempdir().unwrap();
    let mut plan = Plan::small(1);
    plan.stage = crate::population::Stage::OneNinety;
    let run = Run::made_up(plan, dir.path());
    all_running(&run, 0.0);
    if started {
        becomes(&run, 0, 180.0, Is::Stopped);
        becomes(&run, 0, 200.0, Is::Running);
    }
    window(&run, 0.0, 600.0);
    let office = format!("{}:4000", crate::population::OFFICE_ADDRESS);
    let closed = "cordelia_closed_by_warm_churn_total{peer=\"device\"}";
    let away = "cordelia_connections_turned_away_total{why=\"address\"}";
    for node in 0..2 {
        for t in (0..=10).map(|n| n as f64 * 60.0) {
            let n = if node == 0 && t == 300.0 { held } else { 5 };
            let peers = (0..n).map(|k| (format!("o{k}"), office.clone())).collect();
            let churn = if churned && node == 0 && t >= 300.0 {
                32.0
            } else {
                0.0
            };
            let metrics = [(closed, churn), (away, t / 60.0)]
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect();
            run.samples.lock().unwrap().nodes.push(Sample {
                t,
                node,
                metrics: Some(metrics),
                peers: Some(peers),
                ..Sample::default()
            });
        }
    }
    let read = read_of(&run);
    let edits = edits_of(&read);
    bar_14(&read, &edits)
}

/// A sample of 4 from the office's address right after the relay's warm
/// churn closed a device's connection passes bar 14, and is counted; the
/// same sample with no churn near it fails, and so do one of 6 after the
/// churn and one of 4 100 s after relay 1 started again (a start is no
/// churn: bar 14 excuses the second relay's outage alone).
#[test]
fn bar_14_allows_fewer_than_5_only_after_a_warm_churn() {
    let churned = bar_14_with(true, 4, false);
    assert_eq!(churned.verdict, Verdict::Pass, "{}", churned.figure);
    assert!(
        churned.figure.contains(
            "relay 1: 0 samples not 5 from the office's address, 1 fewer within 150 s after a \
             warm churn closed a device"
        ),
        "{}",
        churned.figure
    );
    let more = bar_14_with(true, 6, false);
    assert_eq!(more.verdict, Verdict::Fail, "{}", more.figure);
    let not = bar_14_with(false, 4, false);
    assert_eq!(not.verdict, Verdict::Fail, "{}", not.figure);
    assert!(
        not.figure
            .contains("relay 1: 1 samples not 5 from the office's address (4 at 300 s)"),
        "{}",
        not.figure
    );
    let started = bar_14_with(false, 4, true);
    assert_eq!(started.verdict, Verdict::Fail, "{}", started.figure);
}

// ── Medium 8: a device is excused only by its own proofs and carry ──

/// Device 2 (person 0) holds back requests in a pair where another device
/// made a connection, warm churn closed one at a relay, and person 1's
/// carry window was open: none of that is its own, and bar 1 fails. Where
/// a connection of its own closed in the minute, it is excused; and
/// person 1's device is excused in its own person's carry window.
#[test]
fn a_device_is_excused_only_by_its_own_proofs_and_its_own_persons_carry() {
    for own in [false, true] {
        let (_dir, run) = made_up();
        all_running(&run, 0.0);
        window(&run, 0.0, 600.0);
        run.removals.lock().unwrap().push(Removal {
            person: 1,
            line_at: Some(290.0),
            carry_end: Some(400.0),
            ..Removal::default()
        });
        let warm = "cordelia_closed_by_warm_churn_total{peer=\"device\"}";
        for t in (0..=10).map(|n| n as f64 * 60.0) {
            relay_at(
                &run,
                0,
                t,
                Some(&[(warm, if t >= 360.0 { 1.0 } else { 0.0 })]),
            );
            let at_or_after = |at: f64, v: f64| if t >= at { v } else { 0.0 };
            // Device 2, person 0: held back 3 between 300 and 360.
            device_at(
                &run,
                2,
                t,
                Some(DeviceCounts {
                    held_back: [at_or_after(360.0, 3.0), 0.0],
                    open: 2.0,
                    closed: if own { at_or_after(360.0, 1.0) } else { 0.0 },
                    ..DeviceCounts::default()
                }),
            );
            // Device 4, person 1: its connections change, and it holds back
            // in its person's carry window.
            device_at(
                &run,
                4,
                t,
                Some(DeviceCounts {
                    held_back: [at_or_after(360.0, 5.0), 0.0],
                    open: if t >= 360.0 { 1.0 } else { 2.0 },
                    ..DeviceCounts::default()
                }),
            );
        }
        let read = read_of(&run);
        let (held, excused) = held_back(&read, 0.0, 600.0);
        match own {
            false => assert_eq!((held, excused), (3.0, 5.0)),
            true => assert_eq!((held, excused), (0.0, 8.0)),
        }
        let want = if own { Verdict::Pass } else { Verdict::Fail };
        assert_eq!(bar_1(&read).verdict, want);
    }
}

// ── Check 3: the edits add up, by counts kept apart ──

/// An edit numbered and never recorded, or a wait that ended twice, makes
/// check 3 fail: its counts are kept apart.
#[test]
fn the_edits_add_up_only_where_the_counts_kept_apart_agree() {
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    window(&run, 0.0, 600.0);
    run.samples
        .lock()
        .unwrap()
        .machine
        .push(MachineSample::default());
    {
        let mut o = run.observer.lock().unwrap();
        o.wrote(
            Written {
                number: 1,
                person: 0,
                writer: 0,
                name: 0,
                file: "f001.md".into(),
                size: 600,
                at: 100.0,
                burst: false,
                new: false,
                replaced: None,
            },
            vec![(1, run.out.clone())],
        );
    }
    run.next_edit.store(2, std::sync::atomic::Ordering::SeqCst);
    let check_3 = |run: &Run| {
        let read = read_of(run);
        let edits = edits_of(&read);
        checks(&read, &edits, true)[2].verdict
    };
    assert_eq!(check_3(&run), Verdict::Pass);
    // An edit numbered that the observer never recorded.
    run.next_edit.store(3, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(check_3(&run), Verdict::Fail);
    run.next_edit.store(2, std::sync::atomic::Ordering::SeqCst);
    // A wait that arrived and also ended on a device removed.
    run.observer.lock().unwrap().gone.push((1, 1));
    run.observer.lock().unwrap().arrivals.insert(
        (1, 1),
        Arrival {
            at: 110.0,
            in_copy: false,
        },
    );
    assert_eq!(check_3(&run), Verdict::Fail);
}

// ── Bar 9: a device that counts a closure of its own is not looked for ──

/// A relay's sample at 502 s finds a device's connection gone; the device
/// counts the closure in its first sample after it, at 510 s. It is not
/// looked for at 502 s, and is once 150 s have gone by with no closure.
#[test]
fn a_device_closed_lately_is_read_up_to_its_next_sample() {
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    window(&run, 0.0, 900.0);
    for (t, closed) in [
        (450.0, 0.0),
        (480.0, 0.0),
        (510.0, 1.0),
        (540.0, 1.0),
        (840.0, 1.0),
    ] {
        device_at(
            &run,
            2,
            t,
            Some(DeviceCounts {
                closed,
                ..DeviceCounts::default()
            }),
        );
    }
    let read = read_of(&run);
    assert!(closed_lately(&read, 2, 502.0));
    assert!(closed_lately(&read, 2, 600.0));
    assert!(!closed_lately(&read, 2, 845.0));
}

// ── High 1, second round: replaced by intent only without a minute's run ──

/// Two edits of one file by person 0's first device: `n` at `n_at`, and
/// `m` over it at `m_at`, which reaches the second device (node 3) at
/// `m_at` + 10 s; `n` never reaches it.
fn n_then_m(run: &Run, n_at: f64, m_at: f64) {
    let mut o = run.observer.lock().unwrap();
    let edit = |number: u64, at: f64, replaced: Option<u64>| Written {
        number,
        person: 0,
        writer: 0,
        name: 0,
        file: "f001.md".into(),
        size: 600,
        at,
        burst: false,
        new: false,
        replaced,
    };
    let dir = run.out.clone();
    o.wrote(edit(10, n_at, None), vec![(1, dir.clone())]);
    o.wrote(edit(11, m_at, Some(10)), vec![(1, dir)]);
    o.arrivals.insert(
        (11, 1),
        Arrival {
            at: m_at + 10.0,
            in_copy: false,
        },
    );
}

/// The review's catch-up: the second device is off from 220 s to 280 s,
/// `n` is written at 230 s, the device then runs to 1500 s and never takes
/// `n`, and `m` is written over it at 1500 s. It ran twenty minutes while
/// `n` was the newest: `n` is not replaced by intent there, it is lost, and
/// the device did not catch up.
#[test]
fn an_edit_a_device_ran_twenty_minutes_without_is_lost_though_replaced_later() {
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    window(&run, 0.0, 2000.0);
    becomes(&run, 3, 220.0, Is::Stopped);
    becomes(&run, 3, 280.0, Is::Running);
    n_then_m(&run, 230.0, 1500.0);
    let read = read_of(&run);
    let edits = edits_of(&read);
    let n_at_d = edits.pairs.iter().find(|p| p.edit.number == 10).unwrap();
    assert!(!n_at_d.replaced);
    let bar = bar_3(&read, &edits);
    assert_eq!(bar.verdict, Verdict::Fail, "{}", bar.figure);
    assert!(bar.figure.contains("1 not found"), "{}", bar.figure);
    assert!(
        bar.figure.contains("1 edits not held within 60 s"),
        "{}",
        bar.figure
    );
}

/// The review's late edit: the second device runs from 200 s to 1000 s and
/// never takes `n`, written at 200 s; it is off from 1000 s to 1100 s; `m`
/// is written over `n` at 1200 s. A running device missed `n` for 120 s:
/// bar 2 counts it late.
#[test]
fn an_edit_a_running_device_missed_for_two_minutes_is_late_though_replaced_later() {
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    window(&run, 0.0, 2000.0);
    becomes(&run, 3, 1000.0, Is::Stopped);
    becomes(&run, 3, 1100.0, Is::Running);
    n_then_m(&run, 200.0, 1200.0);
    let read = read_of(&run);
    let edits = edits_of(&read);
    let Latencies { late, .. } =
        latencies(&read, edits.pairs.iter().filter(|p| p.edit.number == 10));
    assert_eq!(late, 1);
    // Where the device ran no minute between the two, `m` replaced `n` by
    // intent there, and nothing is late.
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    window(&run, 0.0, 2000.0);
    becomes(&run, 3, 190.0, Is::Stopped);
    becomes(&run, 3, 1240.0, Is::Running);
    n_then_m(&run, 200.0, 1200.0);
    let read = read_of(&run);
    let edits = edits_of(&read);
    assert!(
        edits
            .pairs
            .iter()
            .find(|p| p.edit.number == 10)
            .unwrap()
            .replaced
    );
    let Latencies { late, .. } =
        latencies(&read, edits.pairs.iter().filter(|p| p.edit.number == 10));
    assert_eq!(late, 0);
}

// ── Medium 2, second round: a removed device's old misses stay misses ──

/// The review's sequence: person 1's second device runs from 1000 s to
/// 2000 s and never takes `n`, written at 1000 s; it goes off at 2000 s and
/// is removed at 2100 s while off. It had its chance at `n`: `n` is not
/// gone, it is lost (bar 3) and late (bar 2). What was written in the
/// 120 s before it went down is gone.
#[test]
fn a_device_removed_while_off_still_owed_what_it_ran_through() {
    let (_dir, run) = made_up();
    all_running(&run, 1000.0);
    window(&run, 1000.0, 2400.0);
    becomes(&run, 5, 2000.0, Is::Stopped);
    run.removals.lock().unwrap().push(Removal {
        person: 1,
        removed: 1,
        line_at: Some(2100.0),
        carry_end: Some(2150.0),
        ..Removal::default()
    });
    let since = crate::observer::no_chance_from(&[(1000.0, true), (2000.0, false)], 2100.0);
    assert_eq!(since, 1880.0);
    {
        let mut o = run.observer.lock().unwrap();
        let edit = |number: u64, at: f64| Written {
            number,
            person: 1,
            writer: 0,
            name: 0,
            file: format!("f{number:03}.md"),
            size: 600,
            at,
            burst: false,
            new: false,
            replaced: None,
        };
        let dir = run.out.clone();
        o.wrote(edit(10, 1000.0), vec![(1, dir.clone())]);
        o.wrote(edit(12, 1990.0), vec![(1, dir)]);
        o.gone(1, 1, since);
        assert_eq!(o.gone, [(12, 1)], "only what it had no chance at");
    }
    let read = read_of(&run);
    let edits = edits_of(&read);
    let bar = bar_3(&read, &edits);
    assert_eq!(bar.verdict, Verdict::Fail, "{}", bar.figure);
    let Latencies { late, .. } = latencies(&read, edits.pairs.iter());
    assert_eq!(late, 1);
    // Back less than a minute before the line: the time down before counts.
    let back = [(0.0, true), (500.0, false), (2060.0, true)];
    assert_eq!(crate::observer::no_chance_from(&back, 2100.0), 380.0);
    // Running long before the line: the 120 s before it alone.
    assert_eq!(
        crate::observer::no_chance_from(&[(0.0, true)], 2100.0),
        1980.0
    );
    // Down at the line after a run of 30 s, too short for its catch-up: the
    // time down before that run counts too. Only the run of 100 s before it
    // gave it a chance.
    let short = [(0.0, true), (100.0, false), (200.0, true), (230.0, false)];
    assert_eq!(crate::observer::no_chance_from(&short, 300.0), -20.0);
}

// ── The third round: replaced soon, and the floor of bar 9 ──

/// A device that runs all through from `n` to `m` is owed `n` where `m`
/// came 20 s or more after it; where `m` came sooner, `n` may never be
/// seen, and is replaced by intent.
#[test]
fn a_running_device_is_owed_an_edit_not_replaced_within_twenty_seconds() {
    for (m_at, replaced) in [(230.0, false), (210.0, true)] {
        let (_dir, run) = made_up();
        all_running(&run, 0.0);
        window(&run, 0.0, 2000.0);
        n_then_m(&run, 200.0, m_at);
        let read = read_of(&run);
        let edits = edits_of(&read);
        let n_at_d = edits.pairs.iter().find(|p| p.edit.number == 10).unwrap();
        assert_eq!(n_at_d.replaced, replaced, "m at {m_at}");
        let bar = bar_3(&read, &edits);
        assert_eq!(bar.verdict == Verdict::Fail, !replaced, "{}", bar.figure);
    }
}

/// The low end of bar 9's band for relay 1 at 300 s, from its figure,
/// where person 0's first device (node 2) counts a closure between 100 s
/// and 310 s, and relay 1 counts `churned` warm-churn closures of devices
/// over the same time. With `restarted`, relay 1 is down from 180 s to
/// 200 s, and the band is read at 330 s, the first sample checked after
/// its start (each time 30 s later).
fn bar_9_floor(closed: bool, churned: f64, restarted: bool) -> f64 {
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    window(&run, 150.0, 900.0);
    let at = if restarted {
        becomes(&run, 0, 180.0, Is::Stopped);
        becomes(&run, 0, 200.0, Is::Running);
        330.0
    } else {
        300.0
    };
    let key = "cordelia_closed_by_warm_churn_total{peer=\"device\"}";
    relay_at(&run, 0, 100.0, Some(&[(key, 0.0)]));
    relay_at(
        &run,
        0,
        at,
        Some(&[(key, churned), ("cordelia_connections_open", 0.0)]),
    );
    for (t, n) in [(100.0, 0.0), (at + 10.0, if closed { 1.0 } else { 0.0 })] {
        device_at(
            &run,
            2,
            t,
            Some(DeviceCounts {
                closed: n,
                ..DeviceCounts::default()
            }),
        );
    }
    let read = read_of(&run);
    let bar = bar_9(&read);
    let said = format!("0 at {at:.0} s (band ");
    let from = bar.figure.find(&said).expect(&bar.figure);
    let rest = &bar.figure[from + said.len()..];
    rest.split(' ').next().unwrap().parse().unwrap()
}

/// A device that counts a closure of its own is left out of the floor only
/// where this relay's warm churn closed a device's connection then: a
/// relay that keeps closing connections for another reason is seen.
#[test]
fn bar_9_leaves_out_a_closed_device_only_where_its_relay_churned() {
    let floor = bar_9_floor(false, 0.0, false);
    assert!(floor >= 1.0, "{floor}");
    assert_eq!(
        bar_9_floor(true, 0.0, false),
        floor,
        "a closure with no churn"
    );
    assert_eq!(
        bar_9_floor(true, 1.0, false),
        floor - 1.0,
        "a closure by churn"
    );
    // A relay that started in those 150 s closed every connection.
    let floor = bar_9_floor(false, 0.0, true);
    assert_eq!(
        bar_9_floor(true, 0.0, true),
        floor - 1.0,
        "a closure by a start"
    );
}

// ── Bar 12: the model counts a device where its relay holds it ──

/// Person 0's first device (node 2) is on all through, but relay 1 lists no
/// connection of it from 300 s to 480 s: warm churn closed it, and it
/// dialled again later. The model asks nothing of it there: its six
/// channels' pulls, six a minute, for three minutes.
#[test]
fn the_model_counts_a_device_only_where_its_relay_holds_its_connection() {
    let model = |away: bool| {
        let (_dir, run) = made_up();
        all_running(&run, 0.0);
        window(&run, 0.0, 600.0);
        let keys: Vec<(String, String)> = (2..run.fleet.made.len())
            .map(|i| (run.fleet.made[i].key.clone(), "127.20.0.1:1".to_string()))
            .collect();
        // Every 20 s, as the small run samples.
        for t in (0..=30).map(|n| n as f64 * 20.0) {
            let listed: Vec<(String, String)> = keys
                .iter()
                .filter(|(key, _)| {
                    !(away && (300.0..480.0).contains(&t) && *key == run.fleet.made[2].key)
                })
                .cloned()
                .collect();
            run.samples.lock().unwrap().nodes.push(Sample {
                t,
                node: 0,
                metrics: Some(HashMap::new()),
                peers: Some(listed),
                ..Sample::default()
            });
        }
        let read = read_of(&run);
        model_of(&read, 0, &[(0.0, 600.0)])
    };
    let (all, _) = model(false);
    let (less, _) = model(true);
    assert_eq!(all - less, 6.0 * 6.0 * 3.0);
}

// ── Bars 6 and 7: what a process rose from ──

/// A sample of a process's RSS at `t`, with ten connections open.
fn rss_at(run: &Run, node: usize, t: f64, mib: f64) {
    run.samples.lock().unwrap().nodes.push(Sample {
        t,
        node,
        proc: Some(crate::machine::ProcRead {
            rss_kib: (mib * 1024.0) as u64,
            ..Default::default()
        }),
        metrics: Some(HashMap::from([(
            "cordelia_connections_open".to_string(),
            10.0,
        )])),
        ..Sample::default()
    });
}

/// Every five minutes from 600 s to 11,400 s: the window.
fn every_five_minutes() -> impl Iterator<Item = f64> {
    (2..=38).map(|n| n as f64 * 300.0)
}

/// A relay's first sample is taken as it starts, at a few MiB. Bar 7's 2%
/// an hour is of the RSS it rose from: a relay of 60 MiB that rises 1 MiB
/// an hour does not grow, and one that rises 2 MiB an hour does.
#[test]
fn bar_7_takes_its_two_percent_of_the_rss_it_rose_from() {
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    window(&run, 600.0, 11_400.0);
    for node in [0, 1] {
        rss_at(&run, node, 0.0, 2.0);
    }
    for t in every_five_minutes() {
        rss_at(&run, 0, t, 60.0 + (t - 600.0) / 3600.0);
        rss_at(&run, 1, t, 60.0 + 2.0 * (t - 600.0) / 3600.0);
    }
    let read = read_of(&run);
    let bar = bar_7(&read);
    assert_eq!(bar.verdict, Verdict::Fail, "{}", bar.figure);
    let said: Vec<&str> = bar.figure.split("; ").collect();
    assert_eq!(
        said,
        [
            "relay 1: the most RSS 63.0 MiB, 0 samples over the bar, no persistent growth \
             (rises of 1.00 and 1.00 MiB an hour, from 60.0 and 61.5 MiB)",
            "relay 2: the most RSS 66.0 MiB, 0 samples over the bar, growing in both halves \
             (rises of 2.00 and 2.00 MiB an hour, from 60.0 and 63.0 MiB)",
        ]
    );
}

/// After a start, a stretch rises from what the process held before it,
/// where that is higher: a relay or a device that fills again to it does
/// not grow in that half, and one that comes back above it and rises does.
#[test]
fn filling_again_to_what_a_process_held_before_a_start_is_no_growth() {
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    for node in [0, 1, 2] {
        becomes(&run, node, 4400.0, Is::Stopped);
        becomes(&run, node, 4500.0, Is::Running);
    }
    window(&run, 600.0, 11_400.0);
    for t in every_five_minutes() {
        let (before, after) = (t - 600.0, t - 4500.0);
        match t < 4400.0 {
            true => {
                rss_at(&run, 0, t, 60.0 + 1.5 * before / 3600.0);
                rss_at(&run, 1, t, 60.0 + 2.0 * before / 3600.0);
                rss_at(&run, 2, t, 20.0 + 3.0 * before / 3600.0);
            }
            false => {
                rss_at(&run, 0, t, 30.0 + 4.0 * after / 3600.0);
                rss_at(&run, 1, t, 63.0 + 2.0 * after / 3600.0);
                rss_at(&run, 2, t, 10.0 + 4.0 * after / 3600.0);
            }
        }
    }
    let read = read_of(&run);
    let bar = bar_7(&read);
    let said: Vec<&str> = bar.figure.split("; ").collect();
    assert_eq!(
        said,
        [
            "relay 1: the most RSS 61.5 MiB, 0 samples over the bar, no persistent growth \
             (rises of 1.50 and -15.89 MiB an hour, from 60.0 and 61.5 MiB)",
            "relay 2: the most RSS 66.8 MiB, 0 samples over the bar, growing in both halves \
             (rises of 2.00 and 2.00 MiB an hour, from 60.0 and 63.8 MiB)",
        ]
    );
    let (devices, _) = bar_6(&read);
    assert_eq!(devices.verdict, Verdict::Pass, "{}", devices.figure);
    assert_eq!(
        devices.figure,
        "the most RSS of a device 23.0 MiB; 0 of 1 devices tested grow in both halves"
    );
}

/// Where a half's longest stretch is under a quarter of it, bar 7 says the
/// growth was not tested, not that there was none.
#[test]
fn bar_7_says_where_growth_was_not_tested() {
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    window(&run, 600.0, 11_400.0);
    for t in every_five_minutes().filter(|t| *t < 6000.0) {
        rss_at(&run, 0, t, 60.0);
    }
    let read = read_of(&run);
    let bar = bar_7(&read);
    for said in bar.figure.split("; ") {
        assert!(
            said.ends_with("growth not tested (a half's longest stretch is under a quarter of it)"),
            "{}",
            bar.figure
        );
    }
}

// ── Bar 15: a split edit held up by the outage ──

/// An edit of a split person (device 0 set up with the first relay, device
/// 1 with the second, which stops at 400 and starts at 520), written at
/// 450 and held up by the outage, judged by bar 15. It is owed within 120
/// s of the start where the device it waits on ran through those 120 s and
/// its writer ran until it could push; else within 60 s of the later of
/// the two running again, never sooner. One that never arrives is late
/// there where both ran at the end. Each case: the writer, the changes of
/// each device (device, at, is; `None` for "never started" before them),
/// the arrival, and whether it is late.
#[test]
fn bar_15_gives_a_held_up_split_edit_a_later_deadline_and_never_drops_it() {
    use Is::{Frozen, Running, Stopped};
    type Changes = &'static [(usize, f64, Is)];
    /// The case, the writer, the changes, the device never started, the
    /// arrival, and whether it is late.
    type Case = (
        &'static str,
        usize,
        Changes,
        Option<usize>,
        Option<f64>,
        bool,
    );
    let cases: [Case; 23] = [
        (
            "the receiver frozen 630 to 639, off 645 to 1500, arrived at 1510",
            0,
            &[
                (1, 630.0, Frozen),
                (1, 639.0, Running),
                (1, 645.0, Stopped),
                (1, 1500.0, Running),
            ],
            None,
            Some(1510.0),
            false,
        ),
        (
            "the writer stopped 600 to 610, after it pushed, arrived at 660",
            0,
            &[(0, 600.0, Stopped), (0, 610.0, Running)],
            None,
            Some(660.0),
            true,
        ),
        (
            "the receiver off 460 to 2480, never arrived (the window ends at 2500)",
            0,
            &[(1, 460.0, Stopped), (1, 2480.0, Running)],
            None,
            None,
            false,
        ),
        ("both ran", 0, &[], None, Some(700.0), true),
        ("both ran, on time", 0, &[], None, Some(630.0), false),
        (
            "both ran, never arrived, the receiver stopped later",
            0,
            &[(1, 1400.0, Stopped)],
            None,
            None,
            true,
        ),
        (
            "the receiver off 460 to 900, arrived 5 s after",
            0,
            &[(1, 460.0, Stopped), (1, 900.0, Running)],
            None,
            Some(905.0),
            false,
        ),
        (
            "the receiver off 460 to 900, arrived at 2000",
            0,
            &[(1, 460.0, Stopped), (1, 900.0, Running)],
            None,
            Some(2000.0),
            true,
        ),
        (
            "the receiver off 460 to 900, arrived at 1000",
            0,
            &[(1, 460.0, Stopped), (1, 900.0, Running)],
            None,
            Some(1000.0),
            true,
        ),
        (
            "the receiver off 460 to 900, never arrived, running at the end",
            0,
            &[(1, 460.0, Stopped), (1, 900.0, Running)],
            None,
            None,
            true,
        ),
        (
            "the receiver off from 460 to the end, never arrived",
            0,
            &[(1, 460.0, Stopped)],
            None,
            None,
            false,
        ),
        (
            "the receiver off 460 to 900 and from 1400, never arrived",
            0,
            &[
                (1, 460.0, Stopped),
                (1, 900.0, Running),
                (1, 1400.0, Stopped),
            ],
            None,
            None,
            false,
        ),
        (
            "the writer stopped at 460 for good, arrived at 2000",
            0,
            &[(0, 460.0, Stopped)],
            None,
            Some(2000.0),
            true,
        ),
        (
            "the receiver frozen 600 to 605, arrived at 2000",
            0,
            &[(1, 600.0, Frozen), (1, 605.0, Running)],
            None,
            Some(2000.0),
            true,
        ),
        (
            "the receiver frozen 600 to 605, arrived at 660",
            0,
            &[(1, 600.0, Frozen), (1, 605.0, Running)],
            None,
            Some(660.0),
            false,
        ),
        (
            "the receiver frozen 530 to 535 and 600 to 605, arrived at 650",
            0,
            &[
                (1, 530.0, Frozen),
                (1, 535.0, Running),
                (1, 600.0, Frozen),
                (1, 605.0, Running),
            ],
            None,
            Some(650.0),
            false,
        ),
        (
            "the receiver first ran at 560, arrived at 2000",
            0,
            &[(1, 560.0, Running)],
            Some(1),
            Some(2000.0),
            true,
        ),
        (
            "the receiver first ran at 560, arrived at 625",
            0,
            &[(1, 560.0, Running)],
            Some(1),
            Some(625.0),
            false,
        ),
        (
            "the writer off 460 to 900, arrived 5 s after",
            0,
            &[(0, 460.0, Stopped), (0, 900.0, Running)],
            None,
            Some(905.0),
            false,
        ),
        (
            "the writer off 460 to 900, arrived at 2000",
            0,
            &[(0, 460.0, Stopped), (0, 900.0, Running)],
            None,
            Some(2000.0),
            true,
        ),
        (
            "the writer stopped 600 to 610, after it pushed, arrived at 2000",
            0,
            &[(0, 600.0, Stopped), (0, 610.0, Running)],
            None,
            Some(2000.0),
            true,
        ),
        (
            "a writer on the second relay off 530 to 900, arrived 5 s after",
            1,
            &[(1, 530.0, Stopped), (1, 900.0, Running)],
            None,
            Some(905.0),
            false,
        ),
        (
            "a writer on the second relay off 530 to 900, arrived at 2000",
            1,
            &[(1, 530.0, Stopped), (1, 900.0, Running)],
            None,
            Some(2000.0),
            true,
        ),
    ];
    for (case, writer, changes, never_started, arrived, late) in cases {
        let bar = split_edit_at_the_outage(writer, 450.0, changes, never_started, arrived);
        assert_eq!(
            bar.figure.contains("1 split people's edits late"),
            late,
            "{case}: {}",
            bar.figure
        );
        assert_eq!(bar.verdict == Verdict::Fail, late, "{case}: {}", bar.figure);
    }
    // A writer on the second relay that wrote 30 s before its stop had
    // pushed: a stop of its own after the start holds nothing up, so it is
    // owed by 640.
    let bar = split_edit_at_the_outage(
        1,
        370.0,
        &[(1, 600.0, Is::Stopped), (1, 610.0, Is::Running)],
        None,
        Some(660.0),
    );
    assert!(
        bar.figure.contains("1 split people's edits late") && bar.verdict == Verdict::Fail,
        "a writer that pushed before the stop: {}",
        bar.figure
    );
}

/// A writer on the second relay alone that wrote 30 s before the stop but
/// froze before it could push, then was off from before the start to
/// 1000, holds its edit until it runs again: arriving at 1010, it is not
/// late, as no relay could have handed it sooner.
#[test]
fn bar_15_waits_for_a_writer_that_froze_before_it_pushed() {
    use Is::{Frozen, Running, Stopped};
    let bar = split_edit_at_the_outage(
        1,
        370.0,
        &[
            (1, 375.0, Frozen),
            (1, 398.0, Running),
            (1, 519.0, Stopped),
            (1, 1000.0, Running),
        ],
        None,
        Some(1010.0),
    );
    assert!(
        bar.figure.contains("0 split people's edits late"),
        "{}",
        bar.figure
    );
}

/// Bar 15 of a run whose second relay stops at 400 and starts at 520, and
/// whose split person's device `writer` wrote an edit at `at` that the
/// other device received at `arrived`, given each device's changes after
/// all ran from 0 (or, for `never_started`, only those).
fn split_edit_at_the_outage(
    writer: usize,
    at: f64,
    changes: &[(usize, f64, Is)],
    never_started: Option<usize>,
    arrived: Option<f64>,
) -> Line {
    let receiver = 1 - writer;
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    window(&run, 0.0, 2500.0);
    *run.outage.lock().unwrap() = Outage {
        stopped: Some(400.0),
        started: Some(520.0),
        back: Vec::new(),
    };
    let person = run
        .plan
        .population
        .people
        .iter()
        .position(|p| p.split && !p.office)
        .unwrap();
    if let Some(device) = never_started {
        let node = run.fleet.device(person, device);
        run.fleet.changes.lock().unwrap().retain(|c| c.node != node);
    }
    for &(device, t, is) in changes {
        becomes(&run, run.fleet.device(person, device), t, is);
    }
    {
        let mut o = run.observer.lock().unwrap();
        let edit = Written {
            number: 20,
            person,
            writer,
            name: 0,
            file: "f001.md".into(),
            size: 600,
            at,
            burst: false,
            new: false,
            replaced: None,
        };
        o.wrote(edit, vec![(receiver, run.out.clone())]);
        if let Some(at) = arrived {
            o.arrivals
                .insert((20, receiver), Arrival { at, in_copy: false });
        }
    }
    let read = read_of(&run);
    let edits = edits_of(&read);
    bar_15(&read, &edits)
}

// ── The report made again from a run's folder ──

/// A made-up run with something of every input the report reads: changes
/// of state, a window that was cut, samples of the relays (with buckets,
/// and counters that are not finite) and of the devices (counters not
/// finite among them) and the machine, at times that are no round
/// numbers, edits waited for, arrived and gone, the observer's pace, an
/// outage, a removal and its carry window, the setup, a copy kept beside a
/// file, a device's log, the end, faults, why the harness stopped it, and
/// the plan's device stopped for good and threshold of bar 6. No field of
/// its inputs is left at its default
/// (`every_field_of_the_made_up_inputs_is_set`).
fn a_run_with_every_input(dir: &Path) -> Run {
    let mut plan = Plan::small(1);
    plan.stopped_for_good = Some((2, 123.5));
    plan.device_growth = Some(3.25);
    plan.timing.removal_spread = 30.0;
    if let crate::population::Offs::Fixed(offs) = &mut plan.offs {
        offs.push(crate::population::Off {
            person: 2,
            device: 1,
            start: 610.0,
            end: 640.0,
            how: crate::population::How::Freeze,
        });
    }
    // Person 1 at the office, as at stage 190.
    plan.population.people[1].office = true;
    plan.population.office_order = vec![(1, 2), (1, 0), (1, 1)];
    let mut run = Run::made_up(plan, dir);
    all_running(&run, 0.0);
    becomes(&run, 3, 250.123_456_789, Is::Frozen);
    becomes(&run, 3, 260.987_654_321, Is::Running);
    becomes(&run, 5, 400.0, Is::Stopped);
    run.fleet.changes.lock().unwrap().push(Change {
        t: 401.5,
        node: 5,
        is: Is::Stopped,
        ended: Some((1.234_567_890_123, "exit status: 0".into())),
    });
    becomes(&run, 5, 470.0, Is::Running);
    window(&run, 60.0 + 0.1 + 0.2, 1_260.000_000_001);
    *run.outage.lock().unwrap() = Outage {
        stopped: Some(500.0 + 1.0 / 3.0),
        started: Some(620.0 + 2.0 / 3.0),
        back: vec![(2, Some(640.5)), (3, None)],
    };
    run.removals.lock().unwrap().push(Removal {
        person: 1,
        remover: 1,
        removed: 2,
        line_at: Some(900.0 + 1e-9),
        change: Some(2),
        applied: vec![(1, Some(905.25))],
        relays_hold: vec![("127.0.0.1:21000".into(), Some(906.75))],
        carry_end: Some(930.0 / 7.0 + 800.0),
        carried_bytes: 123_456,
        bound: 64.7,
        command_ended: Some((931.0, true)),
        failed: Some("a made-up failure of the removal".into()),
    });
    *run.removals_planned.lock().unwrap() = 1;
    {
        let mut setup = run.setup.lock().unwrap();
        setup.started = 1.5;
        setup.ended = 40.0 / 3.0;
        setup.office_moved = Some((45.0, false));
        setup.thread_plan = "unmasked: room for every thread".into();
        setup.machine = "a machine of 16 cores and 64 GiB".into();
    }
    // Every relay: counters of each kind, buckets, and words for a value.
    for n in 0..=20 {
        let t = 60.0 * n as f64 + 0.123_456_789;
        for relay in [0, 1] {
            let m = n as f64 * (relay as f64 + 1.0);
            let mut metrics: HashMap<String, f64> = HashMap::from([
                (PULLS.to_string(), 30.0 * m),
                ("cordelia_churns_total".to_string(), (n / 5) as f64),
                (
                    "cordelia_lock_held_microseconds_sum{kind=\"pull\"}".to_string(),
                    1e6 * m / 7.0,
                ),
                (
                    "cordelia_lock_held_microseconds_count{kind=\"pull\"}".to_string(),
                    100.0 * m,
                ),
                (
                    "cordelia_lock_wait_microseconds_bucket{kind=\"pull\",le=\"1024\"}".to_string(),
                    90.0 * m,
                ),
                (
                    "cordelia_lock_wait_microseconds_bucket{kind=\"pull\",le=\"+Inf\"}".to_string(),
                    100.0 * m,
                ),
                ("cordelia_connections_open".to_string(), 7.0),
                ("cordelia_made_up{value=\"subnormal\"}".to_string(), 1e-310),
                ("cordelia_made_up{value=\"third\"}".to_string(), 1.0 / 3.0),
            ]);
            if n == 7 {
                metrics.insert("cordelia_made_up{value=\"nan\"}".into(), f64::NAN);
                metrics.insert("cordelia_made_up{value=\"inf\"}".into(), f64::INFINITY);
                metrics.insert("cordelia_made_up{value=\"-inf\"}".into(), f64::NEG_INFINITY);
            }
            run.samples.lock().unwrap().nodes.push(Sample {
                t: t + relay as f64 * 0.01,
                node: relay,
                frozen: false,
                proc: Some(crate::machine::ProcRead {
                    rss_kib: 40_000 + 37 * n,
                    hwm_kib: 50_000,
                    threads: 20,
                    fds: 64,
                    ticks: 1000 * n,
                }),
                metrics: Some(metrics),
                peers: Some(vec![(
                    run.fleet.made[2].key.clone(),
                    "127.20.0.1:5000".into(),
                )]),
                room: (n % 5 == 0).then_some((1_000_000 + n, 29)),
                ..Sample::default()
            });
        }
        for node in 2..run.fleet.made.len() {
            let m = n as f64;
            let counts = DeviceCounts {
                asked: [
                    [m, 0.0, 0.0, 3.0 * m, 0.0, 0.0],
                    [0.0, m, 0.0, 0.0, 0.0, 0.0],
                ],
                asked_bytes: [[4096.0 * m / 3.0; 6], [0.0, 0.0, 0.0, 512.0 * m, 0.0, 0.0]],
                held_back: [0.0, (n / 10) as f64],
                refused_for_now: [(n / 10) as f64, 0.0],
                // A counter of a device read as not a number, or infinite.
                waits_over_100: if n == 7 { f64::INFINITY } else { 0.0 },
                given_up: if n == 7 && node == 4 { f64::NAN } else { 1.0 },
                open: 2.0,
                closed: (n / 5) as f64,
            };
            run.samples.lock().unwrap().nodes.push(Sample {
                t: t + 0.5 + node as f64 / 100.0,
                node,
                frozen: node == 3 && n == 4,
                proc: Some(crate::machine::ProcRead {
                    rss_kib: 20_000 + 13 * n * node as u64,
                    hwm_kib: 30_000,
                    threads: 12,
                    fds: 40,
                    ticks: 300 * n,
                }),
                device: Some(counts),
                connections: Some(if n == 7 && node == 5 { f64::NAN } else { 2.0 }),
                outbox_waiting: Some(n as f64 / 3.0),
                ..Sample::default()
            });
        }
        let machine = crate::machine::MachineRead {
            cpu_all: 100_000 * n,
            cpu_idle: 80_000 * n,
            cpu_iowait: 100 * n,
            mem_available_kib: 10_000_000,
            disk_free: 50_000_000_000,
            writes: 30 * n,
            write_ms: 12 * n,
            harness_ticks: 7 * n,
        };
        run.samples
            .lock()
            .unwrap()
            .machine
            .push(MachineSample { t, read: machine });
    }
    // Edits: arrived, arrived in a copy, still waited for, and gone.
    {
        let mut o = run.observer.lock().unwrap();
        let folder = run.out.clone();
        for (number, person, writer, at) in [
            (1u64, 0usize, 0usize, 100.1),
            (2, 0, 1, 200.2),
            (3, 1, 0, 300.3),
            (4, 1, 1, 880.8),
            (5, 2, 0, 1000.0 / 3.0),
        ] {
            let devices = run.plan.population.people[person].devices;
            let others: Vec<(usize, std::path::PathBuf)> = (0..devices)
                .filter(|d| *d != writer)
                .map(|d| (d, folder.clone()))
                .collect();
            o.wrote(
                Written {
                    number,
                    person,
                    writer,
                    name: usize::from(number == 4),
                    file: format!("f{number:03}.md"),
                    size: 600 + number as usize,
                    at,
                    burst: number == 2,
                    new: number % 2 == 1,
                    replaced: (number == 2).then_some(1),
                },
                others,
            );
        }
        o.arrivals.insert(
            (1, 1),
            Arrival {
                at: 101.7,
                in_copy: false,
            },
        );
        o.arrivals.insert(
            (2, 0),
            Arrival {
                at: 203.9,
                in_copy: true,
            },
        );
        o.arrivals.insert(
            (3, 1),
            Arrival {
                at: 301.0 + 1.0 / 7.0,
                in_copy: false,
            },
        );
        o.gone(1, 2, 880.0);
        // The observer's pace: its reads 317 ms apart.
        o.gaps = vec![0.317; 40];
    }
    run.next_edit.store(6, std::sync::atomic::Ordering::SeqCst);
    // A copy kept beside a file.
    let folder = dir.join("p001-d1-n01");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("f003.conflict-abcd.md"), "a copy").unwrap();
    run.folders.insert((1, 1, 0), folder);
    // A device's log: its connection to the first relay closed and made
    // again, in the window and outside the outage, in colour as a node
    // writes it.
    let relay_hex = run.fleet.made[0].key_hex.clone();
    let at = |secs: f64| {
        let t = run.fleet.clock.wall + std::time::Duration::from_secs_f64(secs);
        chrono::DateTime::<chrono::Utc>::from(t)
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
    };
    let log = format!(
        "{}  \x1b[32mINFO\x1b[0m cordelia_network: peer connection closed \
         \x1b[3mpeer\x1b[0m\x1b[2m=\x1b[0m{relay_hex}\n\
         {}  INFO cordelia_network: an unrelated line\n\
         {}  INFO cordelia_network: post_connect: checking peer roles peer={relay_hex}\n",
        at(700.25),
        at(701.0),
        at(703.5)
    );
    let device_log = run.fleet.made[4].node.log();
    std::fs::create_dir_all(device_log.parent().unwrap()).unwrap();
    std::fs::write(device_log, log).unwrap();
    // The end.
    *run.peers_at_end.lock().unwrap() = vec![
        (0, vec![run.fleet.made[2].key.clone(), "a stranger".into()]),
        (1, vec![run.fleet.made[3].key.clone()]),
    ];
    *run.stops_at_end.lock().unwrap() = vec![(2, 0.4, true), (0, 31.5, false)];
    *run.pids_left.lock().unwrap() = vec![4242];
    run.fleet.fault("a made-up fault".into());
    *run.stopped_why.lock().unwrap() = Some("a made-up machine fell short".into());
    run.cut.store(true, std::sync::atomic::Ordering::SeqCst);
    run
}

/// A run's folder holds every input of its report: reported from it again,
/// it gives the same summary, byte for byte, as the run wrote; and a run
/// that has nothing in it the report reads gives the same too.
#[test]
fn the_report_made_again_from_a_runs_folder_is_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let run = a_run_with_every_input(dir.path());
    let outcome = write(&run);
    // Compared as text, byte for byte: a difference shows as lines.
    let written = std::fs::read_to_string(dir.path().join("SUMMARY.md")).unwrap();
    assert_eq!(written, outcome.summary);
    assert!(dir.path().join(crate::kept::INPUTS_FILE).exists());
    // What the made-up inputs come to, so that the round trip is of a
    // summary with something in it.
    for said in [
        "the second relay's outage: stopped at 500 s",
        "the carry window of person 1's removal: from 900 s to 933 s",
        "It stopped early: a made-up fault.",
        "devices' connections to a relay closed in the window outside the outage and made \
         again: 1, median 3.25 s",
        "1 of the pids it started are left",
        "It is INVALID: the harness stopped it, as a made-up machine fell short.",
        "and was cut: INVALID",
        "its reads were 317 ms apart at p99",
        "- the threshold of bar 6: 3.25 MiB an hour (stage 100's p99, given to the run by \
         CORDELIA_SCALE_DEVICE_GROWTH)",
    ] {
        assert!(
            outcome.summary.contains(said),
            "{said}\n{}",
            outcome.summary
        );
    }
    assert!(
        outcome.summary.starts_with("INVALID "),
        "{}",
        outcome.summary
    );
    let made_again = again(dir.path(), None).unwrap();
    assert_eq!(made_again.summary, written);
    assert_eq!(made_again.verdict, outcome.verdict);
    assert_eq!(made_again.bars, outcome.bars);
    assert_eq!(made_again.checks, outcome.checks);
    assert_eq!(made_again.pulls, outcome.pulls);
    assert_eq!(made_again.waited, outcome.waited);
    // Read back, the inputs are what was kept, and give the same again.
    let kept = crate::kept::Kept::load(dir.path()).unwrap();
    let mut back = serde_json::to_value(&kept).unwrap();
    let mut now = kept_value(&run);
    for v in [&mut back, &mut now] {
        v.as_object_mut().unwrap().remove("kept_at");
    }
    assert_eq!(back, now);
    assert_eq!(
        kept.stopped_why.as_deref(),
        Some("a made-up machine fell short")
    );
    assert_eq!(kept.observer.gaps, vec![0.317; 40]);
    assert_eq!(kept.plan.device_growth, Some(3.25));
    assert_eq!(kept.plan.stopped_for_good, Some((2, 123.5)));
    assert!(kept.cut);
    let given_up = |kept: &crate::kept::Kept| {
        kept.samples
            .iter()
            .filter_map(|s| s.device.map(|d| (d.given_up, d.waits_over_100)))
            .filter(|(g, w)| g.is_nan() || w.is_infinite())
            .count()
    };
    assert_eq!(
        given_up(&kept),
        7,
        "the device counters not finite are kept"
    );
    assert!(
        kept.samples
            .iter()
            .any(|s| s.connections.is_some_and(f64::is_nan))
    );
    let first = serde_json::to_string(&kept).unwrap();
    kept.save(dir.path()).unwrap();
    let second = serde_json::to_string(&crate::kept::Kept::load(dir.path()).unwrap()).unwrap();
    assert_eq!(first, second);
    assert_eq!(again(dir.path(), None).unwrap().summary, written);

    // A run with nothing to read.
    let (empty, run) = made_up();
    let outcome = write(&run);
    assert_eq!(again(empty.path(), None).unwrap().summary, outcome.summary);
}

/// The inputs a run keeps, as JSON.
fn kept_value(run: &Run) -> serde_json::Value {
    serde_json::to_value(kept_of(run)).unwrap()
}

/// Each place in `value` (array indices left out, so that a list's items
/// are one place) and whether some value there is not a default: not
/// null, false, zero, an empty string or an empty list or map.
fn set_somewhere(value: &serde_json::Value, at: &str, places: &mut BTreeMap<String, bool>) {
    use serde_json::Value;
    let set = match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    };
    *places.entry(at.to_string()).or_default() |= set;
    match value {
        Value::Array(a) => a
            .iter()
            .for_each(|v| set_somewhere(v, &format!("{at}/[]"), places)),
        // A relay's counters are keyed by their names: one place.
        Value::Object(o) if at.ends_with("/metrics") => o
            .values()
            .for_each(|v| set_somewhere(v, &format!("{at}/{{}}"), places)),
        Value::Object(o) => o
            .iter()
            .for_each(|(k, v)| set_somewhere(v, &format!("{at}/{k}"), places)),
        _ => {}
    }
}

/// The made-up run sets something of every field of the inputs, at every
/// depth: a field the report reads and the file dropped would change the
/// summary made again. The places left at their defaults are the settings
/// a node is given at their defaults (the report says only what is beyond
/// them) and the plan's offs and timing that the small run leaves so.
#[test]
fn every_field_of_the_made_up_inputs_is_set() {
    let dir = tempfile::tempdir().unwrap();
    let run = a_run_with_every_input(dir.path());
    let mut places = BTreeMap::new();
    set_somewhere(&kept_value(&run), "", &mut places);
    let unset: Vec<&String> = places
        .iter()
        .filter(|(at, set)| !**set && !at.starts_with("/fleet/made/[]/settings/"))
        .map(|(at, _)| at)
        .collect();
    assert_eq!(unset, Vec::<&String>::new());
}

/// The inputs of the made-up run, written to `dir`, as JSON, and `change`d,
/// written back.
fn inputs_changed(dir: &Path, change: impl FnOnce(&mut serde_json::Value)) {
    let path = dir.join(crate::kept::INPUTS_FILE);
    let mut value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    change(&mut value);
    std::fs::write(&path, serde_json::to_string(&value).unwrap()).unwrap();
}

/// A file with a key missing (an `Option` among them, which serde would
/// read as `None`) or a key it does not know is refused with a line that
/// names it, never misread; a key given as null reads as `None`.
#[test]
fn a_file_with_a_key_missing_or_not_known_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let run = a_run_with_every_input(dir.path());
    let written = write(&run).summary;
    let original = std::fs::read_to_string(dir.path().join(crate::kept::INPUTS_FILE)).unwrap();
    let restore = || {
        std::fs::write(dir.path().join(crate::kept::INPUTS_FILE), &original).unwrap();
    };
    for (key, why) in [
        ("/stopped_why", "the key /stopped_why is missing"),
        ("/window", "the key /window is missing"),
        ("/samples/0/room", "the key /samples/0/room is missing"),
        (
            "/removals/0/carry_end",
            "the key /removals/0/carry_end is missing",
        ),
        (
            "/plan/device_growth",
            "the key /plan/device_growth is missing",
        ),
    ] {
        restore();
        inputs_changed(dir.path(), |v| {
            let (parent, last) = key.rsplit_once('/').unwrap();
            v.pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(last)
                .unwrap();
        });
        let refused = again(dir.path(), None).unwrap_err();
        assert!(refused.contains(why), "{key}: {refused}");
        assert!(
            refused.contains("is not as this harness writes version 2"),
            "{refused}"
        );
    }
    for (parent, why) in [
        ("", "the key /extra is not one this harness knows"),
        ("/plan", "the key /plan/extra is not one this harness knows"),
        (
            "/samples/3",
            "the key /samples/3/extra is not one this harness knows",
        ),
    ] {
        restore();
        inputs_changed(dir.path(), |v| {
            v.pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("extra".into(), 1.into());
        });
        let refused = again(dir.path(), None).unwrap_err();
        assert!(refused.contains(why), "{parent}: {refused}");
    }
    // Given as null, the reason the harness stopped it reads as none: the
    // summary made again is not INVALID for it.
    restore();
    assert_eq!(again(dir.path(), None).unwrap().summary, written);
    inputs_changed(dir.path(), |v| v["stopped_why"] = serde_json::Value::Null);
    let kept = crate::kept::Kept::load(dir.path()).unwrap();
    assert_eq!(kept.stopped_why, None);
    let made_again = again(dir.path(), None).unwrap().summary;
    assert!(
        !made_again.contains("It is INVALID: the harness"),
        "{made_again}"
    );
}

/// Bar 6's threshold given to the report made again is used over the
/// run's, and the summary says which it used and where it came from; not
/// given, the run's is used, and the summary is the run's.
#[test]
fn the_report_made_again_takes_the_threshold_of_bar_6_given_to_it() {
    let dir = tempfile::tempdir().unwrap();
    // A device that rises 3 MiB an hour in both halves: over 2 and 2.5 MiB
    // an hour, within 3.25.
    let mut plan = Plan::small(1);
    plan.device_growth = Some(3.25);
    let run = Run::made_up(plan, dir.path());
    all_running(&run, 0.0);
    window(&run, 600.0, 11_400.0);
    for t in every_five_minutes() {
        rss_at(&run, 2, t, 20.0 + 3.0 * (t - 600.0) / 3600.0);
    }
    let written = write(&run).summary;
    let bar_6_of = |summary: &str| {
        summary
            .lines()
            .find(|l| l.starts_with("6. "))
            .unwrap()
            .to_string()
    };
    assert!(bar_6_of(&written).ends_with("**PASS**"), "{written}");
    assert_eq!(again(dir.path(), None).unwrap().summary, written);
    let given = again(dir.path(), Some(2.5)).unwrap().summary;
    assert!(bar_6_of(&given).ends_with("**FAIL**"), "{given}");
    assert!(
        given.contains(
            "- the threshold of bar 6: 2.50 MiB an hour (stage 100's p99, given to the report \
             made again by CORDELIA_SCALE_DEVICE_GROWTH; the run was given 3.25 MiB an hour)"
        ),
        "{given}"
    );
    // A run given none.
    let dir = tempfile::tempdir().unwrap();
    let run = Run::made_up(Plan::small(1), dir.path());
    write(&run);
    let given = again(dir.path(), Some(4.0)).unwrap().summary;
    assert!(
        given.contains(
            "4.00 MiB an hour (stage 100's p99, given to the report made again by \
                        CORDELIA_SCALE_DEVICE_GROWTH; the run was given none)"
        ),
        "{given}"
    );
}

/// The report reads the constants of the run's build, as they were kept,
/// not this build's.
#[test]
fn the_report_reads_the_constants_the_run_was_built_with() {
    let dir = tempfile::tempdir().unwrap();
    let run = a_run_with_every_input(dir.path());
    let written = write(&run).summary;
    let ours = cordelia_core::protocol::NODE_STOP_TIMEOUT_SECS;
    assert!(written.contains(&format!("within {ours} s")), "{written}");
    inputs_changed(dir.path(), |v| {
        v["constants"]["node_stop_timeout_secs"] = (ours + 7).into();
    });
    let made_again = again(dir.path(), None).unwrap().summary;
    assert!(
        made_again.contains(&format!("within {} s", ours + 7)),
        "{made_again}"
    );
}

/// A report made again by another harness names it on its second line;
/// by the run's own, it does not.
#[test]
fn a_report_made_again_by_another_harness_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let run = a_run_with_every_input(dir.path());
    let written = write(&run).summary;
    let by = again_by(dir.path(), None, "0123456789ab (changes of another)".into())
        .unwrap()
        .summary;
    let lines: Vec<&str> = by.lines().collect();
    assert_eq!(lines[0], written.lines().next().unwrap());
    assert_eq!(
        lines[2],
        "Made again from report-inputs.json by the harness of commit 0123456789ab (changes of \
         another)."
    );
    assert!(!written.contains("Made again from"));
}

/// Where the inputs could not be kept, `SUMMARY.md` says so at its end, and
/// a folder without them says why.
#[test]
fn a_run_whose_inputs_were_not_kept_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let run = a_run_with_every_input(dir.path());
    // A folder where the file is to be: it cannot be written.
    std::fs::create_dir(dir.path().join(crate::kept::INPUTS_FILE)).unwrap();
    let outcome = write(&run);
    let summary = std::fs::read_to_string(dir.path().join("SUMMARY.md")).unwrap();
    assert_eq!(summary, outcome.summary);
    let end = summary
        .split("## The end (step 10)")
        .nth(1)
        .unwrap()
        .split("## The parts treated apart")
        .next()
        .unwrap();
    assert!(
        end.contains("- the report's inputs were not kept: ")
            && end.contains("its report will not be made again faithfully from them"),
        "{end}"
    );
}

/// A folder without the inputs (a run of a harness before them), with
/// another version of them, or with something else in their place, is
/// refused with a line that says why: never misread.
#[test]
fn a_folder_without_the_inputs_of_this_version_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("SUMMARY.md"), "PASS stage 100\n").unwrap();
    std::fs::write(dir.path().join("samples.jsonl"), "{\"t\":0.0}\n").unwrap();
    let why = again(dir.path(), None).unwrap_err();
    assert!(why.contains("holds no report-inputs.json"), "{why}");
    assert!(why.contains("run it again"), "{why}");
    let inputs = dir.path().join(crate::kept::INPUTS_FILE);
    // Version 1, the shape before the build's constants were kept.
    std::fs::write(&inputs, "{\"version\":1,\"plan\":{}}").unwrap();
    let why = again(dir.path(), None).unwrap_err();
    assert!(why.contains("is version 1"), "{why}");
    assert!(why.contains("reads version 2 only"), "{why}");
    std::fs::write(&inputs, "[1, 2, 3]").unwrap();
    let why = again(dir.path(), None).unwrap_err();
    assert!(why.contains("is not the inputs of a run's report"), "{why}");
    std::fs::write(&inputs, "{\"version\":2,\"plan\":{}}").unwrap();
    let why = again(dir.path(), None).unwrap_err();
    assert!(why.contains("could not be read"), "{why}");
    let why = again(&dir.path().join("none"), None).unwrap_err();
    assert!(why.contains("is not a folder"), "{why}");
    // A run refused before it started keeps no inputs, and is told apart.
    let dir = tempfile::tempdir().unwrap();
    refused(&Plan::small(1), dir.path(), "a made-up refusal");
    let why = again(dir.path(), None).unwrap_err();
    assert!(why.contains("the run did not start"), "{why}");
}

// ── After stage 190, seed 2: bars 3 and 9 read what the record means ──

/// A change of a node: when, to what, and how a stop ended (its seconds
/// and its status; none where it is not known).
type Became<'a> = (f64, Is, Option<(f64, &'a str)>);

/// The high end of bar 9's band for relay 1 at 1000 s, where person 0's
/// first device (node 2) changes as `changes` says.
fn bar_9_ceiling(changes: &[Became]) -> f64 {
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    window(&run, 150.0, 1500.0);
    for (t, is, ended) in changes {
        run.fleet.changes.lock().unwrap().push(Change {
            t: *t,
            node: 2,
            is: *is,
            ended: ended.map(|(took, said)| (took, said.to_string())),
        });
    }
    relay_at(&run, 0, 1000.0, Some(&[("cordelia_connections_open", 0.0)]));
    let read = read_of(&run);
    let bar = bar_9(&read);
    let said = "0 at 1000 s (band ";
    let from = bar.figure.find(said).expect(&bar.figure);
    let rest = &bar.figure[from + said.len()..];
    let hi = rest.split(" to ").nth(1).unwrap();
    hi.split(')').next().unwrap().parse().unwrap()
}

/// Bar 9's high end counts a device stopped cleanly only until the relay's
/// governor has had its tick after the exit (10 s, and 2 s for the tick's
/// turn): one stopped 0.5 s and 0.2 s before the sample counts, as at
/// stage 190, seed 2, where relay 2 held 178 against a band of 174 to 177;
/// one that exited exactly 12 s before counts, one 12.5 s before or 50 s
/// before does not. A device frozen, or stopped without a clean exit
/// (killed, an exit with failure, a stop slower than
/// `NODE_STOP_TIMEOUT_SECS`, or how it ended not known), counts for 90 s:
/// at 89.5 s, and not at exactly 90 s.
#[test]
fn bar_9_counts_a_device_stopped_cleanly_only_until_the_relays_tick() {
    let running = bar_9_ceiling(&[]);
    let clean = Some((0.3, "exit status: 0"));
    let stop = |t: f64, ended: Option<(f64, &'static str)>| (t, Is::Stopped, ended);
    for (case, changes, counted) in [
        (
            "stopped cleanly 0.5 s before",
            vec![stop(999.5, clean)],
            true,
        ),
        (
            "stopped cleanly 0.2 s before",
            vec![stop(999.8, clean)],
            true,
        ),
        (
            "exited cleanly exactly 12 s before",
            vec![stop(987.5, Some((0.5, "exit status: 0")))],
            true,
        ),
        (
            "exited cleanly 12.5 s before",
            vec![stop(987.0, Some((0.5, "exit status: 0")))],
            false,
        ),
        (
            "stopped cleanly 50 s before",
            vec![stop(950.0, clean)],
            false,
        ),
        (
            "killed 89.5 s before",
            vec![stop(910.5, Some((45.0, "killed: it did not stop")))],
            true,
        ),
        (
            "killed exactly 90 s before",
            vec![stop(910.0, Some((45.0, "killed: it did not stop")))],
            false,
        ),
        (
            "exited with failure 89.5 s before",
            vec![stop(910.5, Some((0.3, "exit status: 1")))],
            true,
        ),
        (
            "exited with success, but slower than its 30 s, 60 s before",
            vec![stop(940.0, Some((31.0, "exit status: 0")))],
            true,
        ),
        (
            "how it ended not known, 89.5 s before",
            vec![stop(910.5, None)],
            true,
        ),
        (
            "frozen, then stopped cleanly 89 s before",
            vec![(900.0, Is::Frozen, None), stop(911.0, clean)],
            true,
        ),
        (
            "frozen, then stopped cleanly exactly 90 s before",
            vec![(900.0, Is::Frozen, None), stop(910.0, clean)],
            false,
        ),
        ("stopped 100 s before", vec![stop(900.0, None)], false),
    ] {
        let want = match counted {
            true => running,
            false => running - 1.0,
        };
        assert_eq!(bar_9_ceiling(&changes), want, "{case}");
    }
}

/// Edit 10 of person 0, written at 1000 s by its first device (node 2),
/// which then `lives` as the case says; it never reaches the second device
/// (node 3), which runs all through. The window is 0 to 2000 s. Bar 3, as
/// the case reads it. With `reader_off`, the second device is off from
/// 990 s to 1100 s, so the edit is one of its catch-up too.
fn bar_3_of_a_writer(lives: &[(f64, Is)], reader_off: bool) -> Line {
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    window(&run, 0.0, 2000.0);
    for (t, is) in lives {
        becomes(&run, 2, *t, *is);
    }
    if reader_off {
        becomes(&run, 3, 990.0, Is::Stopped);
        becomes(&run, 3, 1100.0, Is::Running);
    }
    run.observer.lock().unwrap().wrote(
        Written {
            number: 10,
            person: 0,
            writer: 0,
            name: 0,
            file: "f001.md".into(),
            size: 600,
            at: 1000.0,
            burst: false,
            new: false,
            replaced: None,
        },
        vec![(1, run.out.clone())],
    );
    let read = read_of(&run);
    let edits = edits_of(&read);
    bar_3(&read, &edits)
}

/// An edit not found by the end is passed over only where its writer was
/// told to stop within a cycle (5 s) of writing it, so that its cycle had
/// at most that turn to read it, and did not run 60 s again 120 s or more
/// before the end. Its writer stopped 36 ms after writing and off to the
/// end (as at stage 190, seed 2, where the writer was removed), or back
/// only for 30 s, or back too late: passed over, and counted. Its writer
/// ran on, ran 5.5 s or 10 s and then stopped, froze, or ran again in
/// time: lost. Either way with the reader off when it was written, as the
/// catch-up reads it.
#[test]
fn bar_3_passes_over_an_edit_only_where_its_writer_stopped_within_a_cycle() {
    let stopped = (1000.036, Is::Stopped);
    for (case, lives, lost) in [
        ("stopped 36 ms after, off to the end", vec![stopped], false),
        (
            "back for 30 s only",
            vec![stopped, (1300.0, Is::Running), (1330.0, Is::Stopped)],
            false,
        ),
        (
            "back too late to send before the end",
            vec![stopped, (1850.0, Is::Running)],
            false,
        ),
        ("ran on", vec![], true),
        ("ran 20 s, then stopped", vec![(1020.5, Is::Stopped)], true),
        (
            "ran again in time",
            vec![stopped, (1300.0, Is::Running)],
            true,
        ),
        (
            "frozen, then went on in time",
            vec![(1000.036, Is::Frozen), (1300.0, Is::Running)],
            true,
        ),
        // Its cycle had the time to read it and push it: owed, wherever
        // it went after.
        (
            "ran 10 s, then stopped for good",
            vec![(1010.0, Is::Stopped)],
            true,
        ),
        (
            "ran 5.5 s, then stopped for good",
            vec![(1005.5, Is::Stopped)],
            true,
        ),
        (
            "frozen 36 ms after, then stopped for good",
            vec![(1000.036, Is::Frozen), (1060.0, Is::Stopped)],
            true,
        ),
        // The edges: a stop told exactly a cycle (5 s) after the edit; a
        // writer back at 1820 s, whose 60 s end exactly 120 s before the
        // end, and one back half a second later.
        (
            "stopped exactly 5 s after",
            vec![(1005.0, Is::Stopped)],
            false,
        ),
        (
            "back with exactly 120 s left after its catch-up",
            vec![stopped, (1820.0, Is::Running)],
            true,
        ),
        (
            "back with 119.5 s left after its catch-up",
            vec![stopped, (1820.5, Is::Running)],
            false,
        ),
    ] {
        bar_3_reads(case, &lives, lost);
    }
}

/// Bar 3 of [`bar_3_of_a_writer`], with the reader on and off: the edit
/// is lost (and, with the reader off, not held within 60 s) or passed
/// over, as `lost` says.
fn bar_3_reads(case: &str, lives: &[(f64, Is)], lost: bool) {
    for reader_off in [false, true] {
        let bar = bar_3_of_a_writer(lives, reader_off);
        let want = match lost {
            true => Verdict::Fail,
            false => Verdict::Pass,
        };
        let case = format!("{case}, the reader off: {reader_off}");
        assert_eq!(bar.verdict, want, "{case}: {}", bar.figure);
        let (found, passed) = match lost {
            true => ("1 not found by the end", "0 not found and passed over"),
            false => ("0 not found by the end", "1 not found and passed over"),
        };
        assert!(bar.figure.contains(found), "{case}: {}", bar.figure);
        assert!(bar.figure.contains(passed), "{case}: {}", bar.figure);
        // An edit passed over is not one the reader failed to catch up
        // on; one lost is.
        let slow = match lost && reader_off {
            true => "1 edits not held within 60 s",
            false => "0 edits not held within 60 s",
        };
        assert!(bar.figure.contains(slow), "{case}: {}", bar.figure);
    }
}

/// An edit written while its writer was already off (stopped or frozen),
/// as when a removed device is left as it is and the person edits on in
/// its folder: nothing could read it before the writer ran, so it is
/// passed over where the writer did not then run 60 s ending 120 s or more
/// before the end (the hand-off bar 2 makes, "left to bar 3"), and lost
/// where it did. Bar 2 leaves the first to bar 3, and bar 3 passes over it.
#[test]
fn bar_3_passes_over_an_edit_written_while_its_writer_was_off() {
    let stopped = (900.0, Is::Stopped);
    for (case, lives, lost) in [
        ("stopped before, never back", vec![stopped], false),
        (
            "frozen before, then stopped for good",
            vec![(900.0, Is::Frozen), (1100.0, Is::Stopped)],
            false,
        ),
        (
            "stopped before, back for 30 s only",
            vec![stopped, (1300.0, Is::Running), (1330.0, Is::Stopped)],
            false,
        ),
        (
            "stopped before, back too late to send before the end",
            vec![stopped, (1850.0, Is::Running)],
            false,
        ),
        (
            "stopped before, back in time",
            vec![stopped, (1300.0, Is::Running)],
            true,
        ),
        (
            "frozen before, went on in time",
            vec![(900.0, Is::Frozen), (1300.0, Is::Running)],
            true,
        ),
    ] {
        bar_3_reads(case, &lives, lost);
    }
    // Bar 2 leaves the edit whose writer never ran again to bar 3.
    let (_, l) = bar_2_of_a_writer(0, 2, &[stopped], &[], None);
    assert_eq!((l.not_judged, l.late), (1, 0));
}

// ── Bar 2 after stage 100: an edit written while its writer was off ──

/// Edit 10 of `person`, written at 1000 s by its first device (`writer`),
/// which then `lives` as the case says, and arriving at its second device
/// (`writer` + 1, which runs all through but where `reader` says) at
/// `arrived`; and edit 11 of person 1 (set up with both relays, not in the
/// office), written at 500 s by its first device and arriving at its second
/// 5 s later, so that bar 2 never fails for want of an edit. The window is
/// 0 to 2000 s, and `then` adds to the run what a case needs (a part
/// treated apart, a removal, an outage). The run, as the report reads it.
#[allow(clippy::too_many_arguments)]
fn an_edit_of_a_writer(
    plan: Plan,
    person: usize,
    writer: usize,
    lives: &[(f64, Is)],
    reader: &[(f64, Is)],
    arrived: Option<f64>,
    then: impl FnOnce(&Run),
) -> (Read, Edits) {
    let dir = tempfile::tempdir().unwrap();
    let run = Run::made_up(plan, dir.path());
    let other = &run.plan.population.people[1];
    assert!(!other.split && !other.office);
    all_running(&run, 0.0);
    window(&run, 0.0, 2000.0);
    for (t, is) in lives {
        becomes(&run, writer, *t, *is);
    }
    for (t, is) in reader {
        becomes(&run, writer + 1, *t, *is);
    }
    {
        let mut o = run.observer.lock().unwrap();
        let edit = |number: u64, person: usize, at: f64| Written {
            number,
            person,
            writer: 0,
            name: 0,
            file: format!("f{number:03}.md"),
            size: 600,
            at,
            burst: false,
            new: false,
            replaced: None,
        };
        o.wrote(edit(10, person, 1000.0), vec![(1, run.out.clone())]);
        if let Some(at) = arrived {
            o.arrivals.insert((10, 1), Arrival { at, in_copy: false });
        }
        o.wrote(edit(11, 1, 500.0), vec![(1, run.out.clone())]);
        o.arrivals.insert(
            (11, 1),
            Arrival {
                at: 505.0,
                in_copy: false,
            },
        );
    }
    then(&run);
    let read = read_of(&run);
    let edits = edits_of(&read);
    (read, edits)
}

/// Bar 2 of [`an_edit_of_a_writer`] in a run of section 6's small
/// population, and its figures over `person`'s edits.
fn bar_2_of_a_writer(
    person: usize,
    writer: usize,
    lives: &[(f64, Is)],
    reader: &[(f64, Is)],
    arrived: Option<f64>,
) -> (Line, Latencies) {
    bar_2_of_a_writer_and(person, writer, lives, reader, arrived, |_| {})
}

/// [`bar_2_of_a_writer`], with `then` adding to the run.
fn bar_2_of_a_writer_and(
    person: usize,
    writer: usize,
    lives: &[(f64, Is)],
    reader: &[(f64, Is)],
    arrived: Option<f64>,
    then: impl FnOnce(&Run),
) -> (Line, Latencies) {
    let plan = Plan::small(1);
    let (read, edits) = an_edit_of_a_writer(plan, person, writer, lives, reader, arrived, then);
    let l = latencies(
        &read,
        edits.pairs.iter().filter(|p| p.edit.person == person),
    );
    (bar_2(&read, &edits), l)
}

/// The run of stage 100, seed 1: the person went on editing while a
/// device's sync was off, and the edit reached the other device 6.7 s
/// after its writer ran again. An edit written while its writer was off
/// (stopped or frozen) is timed from its writer's return: within 120 s of
/// it, and inside p50 and p95, it passes; beyond 120 s of it, it fails.
/// One whose writer never ran again is left to bar 3, and bar 2 passes
/// (its other edit within the bars). One not arrived is late only where
/// its device ran the 120 s after its writer's return.
#[test]
fn bar_2_times_an_edit_written_while_its_writer_was_off_from_its_return() {
    let off = |is: Is| vec![(900.0, is), (1300.0, Is::Running)];
    for (case, lives, arrived, verdict, l50, late, from_return, not_judged) in [
        (
            "stopped, back at 1300 s, arrived 6.7 s after",
            off(Is::Stopped),
            Some(1306.7),
            Verdict::Pass,
            Some(6.7),
            0,
            1,
            0,
        ),
        (
            "frozen, back at 1300 s, arrived 6.7 s after",
            off(Is::Frozen),
            Some(1306.7),
            Verdict::Pass,
            Some(6.7),
            0,
            1,
            0,
        ),
        (
            "stopped, back at 1300 s, arrived 130 s after",
            off(Is::Stopped),
            Some(1430.0),
            Verdict::Fail,
            Some(130.0),
            0,
            1,
            0,
        ),
        (
            "stopped, back at 1300 s, never arrived",
            off(Is::Stopped),
            None,
            Verdict::Fail,
            None,
            1,
            1,
            0,
        ),
        (
            "stopped, never back, never arrived",
            vec![(900.0, Is::Stopped)],
            None,
            Verdict::Pass,
            None,
            0,
            0,
            1,
        ),
    ] {
        let (bar, l) = bar_2_of_a_writer(0, 2, &lives, &[], arrived);
        assert_eq!(bar.verdict, verdict, "{case}: {}", bar.figure);
        match l50 {
            Some(want) => {
                assert_eq!(l.of.len(), 1, "{case}");
                assert!((l.of[0] - want).abs() < 1e-6, "{case}: {:?}", l.of);
            }
            None => assert!(l.of.is_empty(), "{case}: {:?}", l.of),
        }
        assert_eq!(l.late, late, "{case}");
        assert_eq!(l.from_return, from_return, "{case}");
        assert_eq!(l.not_judged, not_judged, "{case}");
        let said = format!("{from_return} timed from their writer's return, {not_judged} left");
        assert!(bar.figure.contains(&said), "{case}: {}", bar.figure);
    }
    // Not arrived, and its device stopped 50 s after the writer's return:
    // it did not run the 120 s, and nothing is late.
    let (_, l) = bar_2_of_a_writer(0, 2, &off(Is::Stopped), &[(1350.0, Is::Stopped)], None);
    assert_eq!((l.late, l.from_return), (0, 0));
    // Arrived 6.7 s after its writer's return, its device off between the
    // write and the return: it ran from the return to the arrival, and is
    // timed.
    let (bar, l) = bar_2_of_a_writer(
        0,
        2,
        &off(Is::Stopped),
        &[(1100.0, Is::Stopped), (1200.0, Is::Running)],
        Some(1306.7),
    );
    assert_eq!(bar.verdict, Verdict::Pass, "{}", bar.figure);
    assert_eq!((l.of.len(), l.from_return), (1, 1));
    // A person split between the relays: the same, in their figures.
    let (bar, l) = bar_2_of_a_writer(2, 7, &off(Is::Stopped), &[], Some(1306.7));
    assert_eq!((l.of.len(), l.from_return), (1, 1));
    assert!((l.of[0] - 6.7).abs() < 1e-6, "{:?}", l.of);
    assert!(
        bar.figure.contains(
            "split between the relays: 1 arrivals, p95 6.7 s, the most 6.7 s, 0 not arrived \
             within 120 s, 1 timed from their writer's return"
        ),
        "{}",
        bar.figure
    );
}

/// An edit written while its writer ran is timed from the write, as
/// before, whatever its writer did after: a writer that ran on, and one
/// that stopped 5 s after the write and ran again at 1300 s, each with the
/// edit arriving at 1306.7 s, are 306.7 s and fail bar 2. A slow relay or
/// reader is not hidden by a stop after the write. Within the bars they
/// pass, and none is timed from a return.
#[test]
fn bar_2_times_an_edit_written_while_its_writer_ran_from_the_write() {
    let later = vec![(1005.0, Is::Stopped), (1300.0, Is::Running)];
    for (case, lives) in [("ran on", vec![]), ("stopped 5 s after, back later", later)] {
        let (bar, l) = bar_2_of_a_writer(0, 2, &lives, &[], Some(1306.7));
        assert_eq!(bar.verdict, Verdict::Fail, "{case}: {}", bar.figure);
        assert_eq!(l.of.len(), 1, "{case}");
        assert!((l.of[0] - 306.7).abs() < 1e-6, "{case}: {:?}", l.of);
        assert_eq!((l.from_return, l.not_judged), (0, 0), "{case}");
        assert!(
            bar.figure.contains("the most 306.7 s"),
            "{case}: {}",
            bar.figure
        );
        let (bar, l) = bar_2_of_a_writer(0, 2, &lives, &[], Some(1008.0));
        assert_eq!(bar.verdict, Verdict::Pass, "{case}: {}", bar.figure);
        assert!((l.of[0] - 8.0).abs() < 1e-6, "{case}: {:?}", l.of);
        assert_eq!(l.from_return, 0, "{case}");
    }
    // Never arrived, its writer ran at the write and its device ran the
    // 120 s after: late, timed from the write.
    let (bar, l) = bar_2_of_a_writer(0, 2, &[(1005.0, Is::Stopped)], &[], None);
    assert_eq!(bar.verdict, Verdict::Fail, "{}", bar.figure);
    assert_eq!((l.late, l.from_return), (1, 0));
}

// ── Bar 2's writer off: the fix round ──

/// An edit written after its writer was told to stop that arrived before
/// its writer ran again was sent by the stopping process (a stop is
/// recorded when the node is told, and its process may run on while it
/// shuts down): it is timed from the write, not from the return, so it
/// counts no negative latency. The same where its writer never ran again:
/// it arrived, and bar 2 judges it.
#[test]
fn an_edit_that_arrived_before_its_writers_return_is_timed_from_the_write() {
    for (case, lives) in [
        (
            "back at 1300 s",
            vec![(990.0, Is::Stopped), (1300.0, Is::Running)],
        ),
        ("never back", vec![(990.0, Is::Stopped)]),
    ] {
        let (bar, l) = bar_2_of_a_writer(0, 2, &lives, &[], Some(1003.0));
        assert_eq!(l.of.len(), 1, "{case}");
        assert!((l.of[0] - 3.0).abs() < 1e-6, "{case}: {:?}", l.of);
        assert_eq!((l.from_return, l.not_judged), (0, 0), "{case}");
        assert_eq!(bar.verdict, Verdict::Pass, "{case}: {}", bar.figure);
        assert!(
            bar.figure.contains("2 arrivals, p50 3.0 s"),
            "{case}: {}",
            bar.figure
        );
    }
}

/// A part treated apart (here another person's carry window) is read over
/// the edit's way from when it is timed: a window while its writer was off
/// holds nothing up, and the edit is judged from its writer's return. One
/// that arrived 300 s after the return fails; one 6.7 s after passes, and
/// is timed. A window after the return, over the 120 s of an edit not
/// arrived, treats it apart (it is not late).
#[test]
fn bar_2_reads_the_parts_apart_from_when_an_edit_is_timed() {
    let off = [(900.0, Is::Stopped), (1300.0, Is::Running)];
    let carry = |line: f64, end: f64| {
        move |run: &Run| {
            run.removals.lock().unwrap().push(Removal {
                person: 1,
                removed: 2,
                line_at: Some(line),
                carry_end: Some(end),
                ..Removal::default()
            })
        }
    };
    let (bar, l) = bar_2_of_a_writer_and(0, 2, &off, &[], Some(1600.0), carry(1100.0, 1200.0));
    assert_eq!(bar.verdict, Verdict::Fail, "{}", bar.figure);
    assert!(bar.figure.contains("the most 300.0 s"), "{}", bar.figure);
    assert_eq!((l.of.len(), l.from_return), (1, 1));
    let (bar, _) = bar_2_of_a_writer_and(0, 2, &off, &[], Some(1306.7), carry(1100.0, 1200.0));
    assert_eq!(bar.verdict, Verdict::Pass, "{}", bar.figure);
    assert!(bar.figure.contains("2 arrivals"), "{}", bar.figure);
    // Not arrived: its way ends 120 s after the return (1420 s), and a
    // window from 1350 s crosses it.
    let (bar, l) = bar_2_of_a_writer_and(0, 2, &off, &[], None, carry(1350.0, 1400.0));
    assert_eq!(l.late, 1, "late, were it judged");
    assert_eq!(bar.verdict, Verdict::Pass, "{}", bar.figure);
    assert!(
        bar.figure.contains("0 not arrived within 120 s"),
        "{}",
        bar.figure
    );
}

/// A device removed later is owed what it ran 120 s through before its
/// removal's line, from when the edit is timed: written while its writer
/// was off (back at 1300 s), the edit is owed by a line at 1500 s, and not
/// by one at 1400 s, where its 120 s from the return reach past the line.
#[test]
fn a_device_removed_later_is_owed_an_edit_from_its_writers_return() {
    let off = [(900.0, Is::Stopped), (1300.0, Is::Running)];
    for (line, late) in [(1400.0, 0), (1500.0, 1)] {
        let (_, l) = bar_2_of_a_writer_and(0, 2, &off, &[], None, |run| {
            run.observer.lock().unwrap().gone(0, 1, 950.0);
            run.removals.lock().unwrap().push(Removal {
                person: 0,
                removed: 1,
                line_at: Some(line),
                carry_end: Some(line + 50.0),
                ..Removal::default()
            });
        });
        assert_eq!((l.late, l.from_return), (late, late), "line at {line} s");
    }
}

/// Bar 3's catch-up takes an edit not arrived when its device's off
/// began, where it could be sent by the time the device ran again: bar 2
/// skips it (its device did not run from the writer's return to the
/// arrival), so bar 3 judges it. Written at 1000 s while its writer was off
/// (back at 1300 s), the reader off from 1100 s to 1400 s: arrived 100 s
/// after the reader's return, it is slow; 10 s after, it is not. One that
/// arrived before the off began, and one whose writer came back after the
/// reader did (bar 2 times it), are no part of the off's catch-up.
#[test]
fn bar_3_catches_up_on_an_edit_not_arrived_when_the_off_began() {
    let reader = [(1100.0, Is::Stopped), (1400.0, Is::Running)];
    let bar_3_of = |lives: &[(f64, Is)], arrived: f64| {
        let plan = Plan::small(1);
        let (read, edits) = an_edit_of_a_writer(plan, 0, 2, lives, &reader, Some(arrived), |_| {});
        bar_3(&read, &edits)
    };
    let off = [(900.0, Is::Stopped), (1300.0, Is::Running)];
    for (case, lives, arrived, verdict, said) in [
        (
            "writer back at 1300 s, arrived at 1500 s",
            &off[..],
            1500.0,
            Verdict::Fail,
            "the slowest catch-up 100.0 s, 1 edits not held within 60 s",
        ),
        (
            "writer back at 1300 s, arrived at 1410 s",
            &off[..],
            1410.0,
            Verdict::Pass,
            "the slowest catch-up 10.0 s, 0 edits not held",
        ),
        (
            "writer ran, arrived at 1090 s",
            &[][..],
            1090.0,
            Verdict::Pass,
            "the slowest catch-up 0.0 s, 0 edits not held",
        ),
        (
            "writer back at 1500 s, arrived at 1600 s",
            &[(900.0, Is::Stopped), (1500.0, Is::Running)][..],
            1600.0,
            Verdict::Pass,
            "the slowest catch-up 0.0 s, 0 edits not held",
        ),
    ] {
        let bar = bar_3_of(lives, arrived);
        assert_eq!(bar.verdict, verdict, "{case}: {}", bar.figure);
        assert!(bar.figure.contains(said), "{case}: {}", bar.figure);
    }
}

/// The office's line in bar 14 times an edit written while its writer was
/// off from its writer's return, and counts it; and one whose writer never
/// ran again is counted as not judged.
#[test]
fn bar_14_times_the_offices_edit_from_its_writers_return() {
    let mut plan = Plan::small(1);
    plan.stage = crate::population::Stage::OneNinety;
    plan.population.people[0].office = true;
    for (lives, arrived, said) in [
        (
            vec![(900.0, Is::Stopped), (1300.0, Is::Running)],
            Some(1306.7),
            "the office's people: 1 arrivals, median 6.70 s, worst 6.70 s, 0 not arrived within \
             120 s, 1 timed from their writer's return, 0 not judged",
        ),
        (
            vec![(900.0, Is::Stopped)],
            None,
            "the office's people: 0 arrivals, no value, 0 not arrived within 120 s, 0 timed from \
             their writer's return, 1 not judged",
        ),
    ] {
        let (read, edits) = an_edit_of_a_writer(plan.clone(), 0, 2, &lives, &[], arrived, |_| {});
        let bar = bar_14(&read, &edits);
        assert!(bar.figure.contains(said), "{}", bar.figure);
    }
}

/// Bar 15's bar 2 through the outage (the second relay stopped from
/// 1100 s to 1220 s) times an edit written while its writer was off from
/// its writer's return (at 1150 s, during the outage): it arrived 7 s
/// after, and passes; timed from the write it would be 157 s.
#[test]
fn bar_15_times_an_edit_written_while_its_writer_was_off_from_its_return() {
    let outage = |run: &Run| {
        *run.outage.lock().unwrap() = Outage {
            stopped: Some(1100.0),
            started: Some(1220.0),
            back: Vec::new(),
        };
    };
    let off = [(900.0, Is::Stopped), (1150.0, Is::Running)];
    let (read, edits) = an_edit_of_a_writer(Plan::small(1), 0, 2, &off, &[], Some(1157.0), outage);
    let bar = bar_15(&read, &edits);
    assert_eq!(bar.verdict, Verdict::Pass, "{}", bar.figure);
    assert!(
        bar.figure.contains(
            "1 arrivals at p50 7.0 s, p95 7.0 s, the most 7.0 s, 0 not within 120 s, 1 timed \
             from their writer's return, 0 timed from their device's connection to the first \
             relay made again after its warm churn closed it in the outage, 0 left to bar 3"
        ),
        "{}",
        bar.figure
    );
    let (read, edits) = an_edit_of_a_writer(Plan::small(1), 0, 2, &off[..1], &[], None, outage);
    let bar = bar_15(&read, &edits);
    assert!(
        bar.figure
            .contains("0 timed from their writer's return, 0 timed from their device's")
            && bar.figure.contains("in the outage, 1 left to bar 3"),
        "{}",
        bar.figure
    );
}

// ── Bar 15: the first relay's warm churn during the outage ──

/// Edit 10 of person 0 (set up with both relays), written at 1000 s by
/// device 2 and arriving at device 3 at `arrived`, through the second
/// relay's outage (stopped from 1100 s to 1220 s). The first relay is
/// sampled every 10 s from 1000 s to 1300 s, listing every device; `cut`
/// leaves `node` out of its list from `gone` until `back` (to the end where
/// it is `None`), and where `churned` the relay's count of devices'
/// connections closed by warm churn rises by 16 at `gone`. Bar 15, and its
/// figures over person 0's edit, as bar 15 times it.
fn bar_15_through_a_churn(
    cut: Option<(usize, f64, Option<f64>)>,
    churned: bool,
    arrived: Option<f64>,
) -> (Line, Latencies) {
    let (stopped, started) = (1100.0, 1220.0);
    let then = |run: &Run| {
        *run.outage.lock().unwrap() = Outage {
            stopped: Some(stopped),
            started: Some(started),
            back: Vec::new(),
        };
        let relay = run.fleet.relays[0];
        for step in 0..=30 {
            let t = 1000.0 + 10.0 * step as f64;
            let off = |node: usize| {
                cut.is_some_and(|(n, gone, back)| {
                    n == node && t >= gone && back.is_none_or(|b| t < b)
                })
            };
            let peers = (2..run.fleet.made.len())
                .filter(|node| !off(*node))
                .map(|node| (run.fleet.made[node].key.clone(), "127.0.0.1:1".into()))
                .collect();
            let closed = match cut {
                Some((_, gone, _)) if churned && t >= gone => 16.0,
                _ => 0.0,
            };
            run.samples.lock().unwrap().nodes.push(Sample {
                t,
                node: relay,
                proc: Some(crate::machine::ProcRead::default()),
                metrics: Some([(CLOSED_BY_WARM_CHURN.to_string(), closed)].into()),
                peers: Some(peers),
                ..Sample::default()
            });
        }
    };
    let (read, edits) = an_edit_of_a_writer(Plan::small(1), 0, 2, &[], &[], arrived, then);
    let l = latencies_after(
        &read,
        edits.pairs.iter().filter(|p| p.edit.person == 0),
        |p, from| timed_after_a_churn(&read, p, from, stopped, started),
    );
    (bar_15(&read, &edits), l)
}

/// The runs of stage 100, seed 3: the first relay's hourly warm churn fell
/// inside the second relay's outage and closed the one path of people set
/// up with both relays; they connected again about 5 s later and caught
/// up. An edit whose reader or writer the churn cut off during the outage
/// is timed from when that device was connected to the first relay again
/// (here the sample at 1150 s, the last that does not list it before the
/// one at 1160 s that does): arriving 10 s after, it passes, and is
/// counted; arriving 130 s after, it fails; not arrived (cut at 1110 s,
/// within the 120 s from its write), it is late, timed so. Where
/// the relay is never seen to list it again, it is timed from the last
/// sample that listed it and bars 9 and 14's 150 s.
#[test]
fn bar_15_times_an_edit_cut_off_by_a_churn_in_the_outage_from_the_connection_again() {
    for (case, cut, arrived, verdict, latency, late) in [
        (
            "reader cut, arrived 10 s after",
            (3, 1150.0, Some(1160.0)),
            Some(1160.0),
            Verdict::Pass,
            Some(10.0),
            0,
        ),
        (
            "writer cut, arrived 10 s after",
            (2, 1150.0, Some(1160.0)),
            Some(1160.0),
            Verdict::Pass,
            Some(10.0),
            0,
        ),
        (
            "reader cut, arrived 130 s after",
            (3, 1150.0, Some(1160.0)),
            Some(1280.0),
            Verdict::Fail,
            Some(130.0),
            0,
        ),
        (
            "reader cut at 1110 s, never arrived",
            (3, 1110.0, Some(1120.0)),
            None,
            Verdict::Fail,
            None,
            1,
        ),
        (
            "reader cut, not seen again: 150 s from the last sample that listed it",
            (3, 1150.0, None),
            Some(1300.0),
            Verdict::Pass,
            Some(10.0),
            0,
        ),
    ] {
        let (bar, l) = bar_15_through_a_churn(Some(cut), true, arrived);
        assert_eq!(bar.verdict, verdict, "{case}: {}", bar.figure);
        match latency {
            Some(want) => {
                assert_eq!(l.of.len(), 1, "{case}: {:?}", l.of);
                assert!((l.of[0] - want).abs() < 1e-6, "{case}: {:?}", l.of);
            }
            None => assert!(l.of.is_empty(), "{case}: {:?}", l.of),
        }
        assert_eq!(
            (l.late, l.from_churn, l.from_return),
            (late, 1, 0),
            "{case}"
        );
        assert!(
            bar.figure.contains(
                "1 timed from their device's connection to the first relay made again after its \
                 warm churn closed it in the outage"
            ),
            "{case}: {}",
            bar.figure
        );
    }
}

/// An edit no churn cut off is timed from its write, as before: with no
/// closure, and with its reader's connection closed in the outage while
/// the relay's warm churn closed nothing (a closure for another reason),
/// arriving at 1170 s it is 170 s, fails, and none is timed from a
/// connection again.
#[test]
fn bar_15_times_an_edit_no_churn_cut_off_from_the_write() {
    for (case, cut) in [
        ("no closure", None),
        ("closed without a churn", Some((3, 1150.0, Some(1160.0)))),
    ] {
        let (bar, l) = bar_15_through_a_churn(cut, false, Some(1170.0));
        assert_eq!(bar.verdict, Verdict::Fail, "{case}: {}", bar.figure);
        assert_eq!(l.of.len(), 1, "{case}");
        assert!((l.of[0] - 170.0).abs() < 1e-6, "{case}: {:?}", l.of);
        assert_eq!(l.from_churn, 0, "{case}");
        assert!(
            bar.figure
                .contains("0 timed from their device's connection"),
            "{case}: {}",
            bar.figure
        );
    }
}

/// A churn outside the outage changes nothing in bar 15: one that closed
/// the reader after the second relay's start (at 1250 s, back at 1260 s),
/// and one before its stop (at 1080 s, back at 1090 s), each with the edit
/// arriving 10 s after the connection again, are timed from the write and
/// fail, and none is timed from a connection again.
#[test]
fn bar_15_is_not_changed_by_a_churn_outside_the_outage() {
    for (case, cut, arrived, latency) in [
        ("after the start", (3, 1250.0, Some(1260.0)), 1260.0, 260.0),
        ("before the stop", (3, 1080.0, Some(1090.0)), 1100.0, 100.0),
    ] {
        let (bar, l) = bar_15_through_a_churn(Some(cut), true, Some(arrived));
        assert_eq!(bar.verdict, Verdict::Fail, "{case}: {}", bar.figure);
        assert_eq!(l.of.len(), 1, "{case}");
        assert!((l.of[0] - latency).abs() < 1e-6, "{case}: {:?}", l.of);
        assert_eq!(l.from_churn, 0, "{case}");
    }
}
