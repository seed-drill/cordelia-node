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
    let (_, late) = latencies(&read, edits.pairs.iter().filter(|p| p.edit.number == 10));
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
    let (_, late) = latencies(&read, edits.pairs.iter().filter(|p| p.edit.number == 10));
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
    let (_, late) = latencies(&read, edits.pairs.iter());
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
