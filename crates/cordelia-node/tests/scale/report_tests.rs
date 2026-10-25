//! The report's logic, from made-up samples: a run whose nodes are never
//! started (`Run::made_up`, section 6's small population: relays 0 and 1;
//! person 0's devices 2 and 3; person 1's 4, 5 and 6; person 2's 7 and 8),
//! given the samples, the changes and the edits each test reads.

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
/// ending at each bound, with the counts over 5 and 50 ms.
fn histogram(
    name: &str,
    kind: &str,
    counts: &[(u64, f64)],
    over_5: f64,
    over_50: f64,
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
    lines.push((format!("{name}_over{{kind=\"{kind}\",ms=\"5\"}}"), over_5));
    lines.push((format!("{name}_over{{kind=\"{kind}\",ms=\"50\"}}"), over_50));
    lines
}

fn bar_4_of(waits: &[(u64, f64)], over_5: f64, over_50: f64, holds: &[(u64, f64)]) -> Line {
    let (_dir, run) = made_up();
    all_running(&run, 0.0);
    window(&run, 0.0, 200.0);
    let mut lines = histogram(
        &format!("{LOCK}_wait_microseconds"),
        "pull",
        waits,
        over_5,
        over_50,
    );
    lines.extend(histogram(
        &format!("{LOCK}_hold_microseconds"),
        "pull",
        holds,
        0.0,
        0.0,
    ));
    let zero: Vec<(&str, f64)> = lines.iter().map(|(k, _)| (k.as_str(), 0.0)).collect();
    let after: Vec<(&str, f64)> = lines.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    relay_at(&run, 0, 0.0, Some(&zero));
    relay_at(&run, 0, 100.0, Some(&after));
    let read = read_of(&run);
    bar_4(&read)
}

/// A wait p99 between 8.192 and 16.384 ms, where the waits over 5 ms do
/// not settle it, cannot be told from the bar of 10 ms: NOT RESOLVED, not
/// PASS. Within the bucket that ends under the bar it passes, and in the
/// one that begins over it it fails. A read's hold p99 between 513 and
/// 1,024 µs is not resolved against 1 ms.
#[test]
fn a_p99_in_the_bucket_that_holds_the_bar_is_not_resolved() {
    let fast = [(64, 100.0)];
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
