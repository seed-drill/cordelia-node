//! The steps of the window that follow the relays' churns (decision
//! 2026-10-22 §4.2, steps 5 to 9): when the second relay stops and starts
//! again, when the removals are made, and when the window ends. Given the
//! churns each relay has counted at each minute, it says what to do; it
//! starts nothing itself, so that section 6's test 2 can give it churns.

/// How long each part of a run lasts, in seconds. A stage takes the
/// record's figures ([`Timing::of_a_stage`]); the small run of test 4
/// takes shorter ones, which its summary lists.
#[derive(Debug, Clone, PartialEq)]
pub struct Timing {
    /// From the office's move to the window's start (step 5).
    pub settle: f64,
    /// The second relay's outage (step 7).
    pub outage: f64,
    /// What is treated apart after a relay's start again (§3).
    pub after_start: f64,
    /// The removals are spread over this (step 8).
    pub removal_spread: f64,
    /// The window lasts at least this long after the last removal (step
    /// 9).
    pub after_removal: f64,
    /// A window this long is cut, and the run is INVALID (step 9).
    pub cut: f64,
    /// Each process is sampled once in this (§1.2).
    pub sample_every: f64,
    /// A relay's room is read once in this (§1.2).
    pub room_every: f64,
    /// The relays' churn interval, with no jitter, where it is set: only
    /// in the small run (§6, test 4).
    pub churn_secs: Option<u64>,
    /// The first files each person writes in each name (step 3).
    pub first_files: usize,
    /// An edit not found within this much of a device's running is not
    /// arrived (§1.3).
    pub arrival_wait: f64,
}

impl Timing {
    /// The record's figures, for every stage.
    pub fn of_a_stage() -> Timing {
        Timing {
            settle: 600.0,
            outage: 120.0,
            after_start: 300.0,
            removal_spread: 300.0,
            after_removal: 1500.0,
            cut: 5.0 * 3600.0,
            sample_every: 60.0,
            room_every: 300.0,
            churn_secs: None,
            first_files: 10,
            arrival_wait: 300.0,
        }
    }

    /// The small run of section 6's test 4: churn every two minutes, and
    /// each wait cut down to fit a run of some minutes.
    pub fn of_the_small_run() -> Timing {
        Timing {
            settle: 60.0,
            outage: 120.0,
            after_start: 120.0,
            removal_spread: 0.0,
            after_removal: 240.0,
            cut: 1800.0,
            sample_every: 20.0,
            room_every: 60.0,
            churn_secs: Some(120),
            first_files: 10,
            arrival_wait: 300.0,
        }
    }

    /// What differs from the record's figures, said for the summary.
    pub fn beyond_the_record(&self) -> Vec<String> {
        let record = Timing::of_a_stage();
        let mut said = Vec::new();
        let mut differs = |what: &str, ours: f64, theirs: f64| {
            if ours != theirs {
                said.push(format!("{what}: {ours} s (the record's {theirs} s)"));
            }
        };
        differs("the wait before the window", self.settle, record.settle);
        differs("the second relay's outage", self.outage, record.outage);
        differs(
            "what is treated apart after a relay's start",
            self.after_start,
            record.after_start,
        );
        differs(
            "the removals' spread",
            self.removal_spread,
            record.removal_spread,
        );
        differs(
            "the window after the last removal",
            self.after_removal,
            record.after_removal,
        );
        differs("the window's cut", self.cut, record.cut);
        differs(
            "a sample of each process",
            self.sample_every,
            record.sample_every,
        );
        differs(
            "a read of a relay's room",
            self.room_every,
            record.room_every,
        );
        if let Some(secs) = self.churn_secs {
            said.push(format!(
                "the relays' churn interval: {secs} s with no jitter (the default: an hour, \
                 and up to 300 s of jitter); the only run in which a governor's interval is set"
            ));
        }
        if self.first_files != record.first_files {
            said.push(format!(
                "first files in each name: {} (the record's {})",
                self.first_files, record.first_files
            ));
        }
        said
    }
}

/// What the steps say to do.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Act {
    /// Stop the second relay (step 7).
    StopSecond,
    /// Start it again on the same data directory (step 7).
    StartSecond,
    /// Make the removals (step 8).
    Remove,
    /// End the window (step 9); `cut` where it reached its cut without
    /// the churns, and the run is INVALID.
    End { cut: bool },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Phase {
    /// Waiting for the second relay's first churn in the window; with one
    /// relay, for the first relay's.
    BeforeStop,
    /// The second relay is stopped, since this time.
    Out(f64),
    /// The second relay started again at this time; waiting for its first
    /// churn since.
    BeforeRemovals,
    /// The removals were begun; the last is at this time.
    Ending(f64),
    Ended,
}

/// The steps of one window.
#[derive(Debug, Clone)]
pub struct Steps {
    timing: Timing,
    relays: usize,
    start: f64,
    /// The first relay's churns at the window's start.
    first_before: u64,
    /// The second relay's at the window's start.
    second_before: u64,
    phase: Phase,
    /// When the second relay stopped, and started again.
    pub stopped_at: Option<f64>,
    pub started_at: Option<f64>,
    /// When the removals began.
    pub removals_at: Option<f64>,
}

impl Steps {
    /// The steps of a window that starts at `start`, where the relays have
    /// counted `churns` churns by then (the second's is ignored with one
    /// relay).
    pub fn new(timing: &Timing, relays: usize, start: f64, churns: [u64; 2]) -> Steps {
        Steps {
            timing: timing.clone(),
            relays,
            start,
            first_before: churns[0],
            second_before: churns[1],
            phase: Phase::BeforeStop,
            stopped_at: None,
            started_at: None,
            removals_at: None,
        }
    }

    /// The churns the first relay has counted in the window, given what it
    /// has counted in all.
    pub fn first_in_window(&self, first: u64) -> u64 {
        first.saturating_sub(self.first_before)
    }

    /// What to do at `t`, given the churns each relay has counted so far:
    /// the first relay's since its start, the second's since its start or
    /// its start again (`None` while it is stopped or not read).
    pub fn at(&mut self, t: f64, churns: [Option<u64>; 2]) -> Option<Act> {
        if self.phase == Phase::Ended {
            return None;
        }
        if t >= self.start + self.timing.cut {
            self.phase = Phase::Ended;
            return Some(Act::End { cut: true });
        }
        match self.phase {
            Phase::BeforeStop if self.relays == 1 => {
                let first = churns[0]?;
                (first > self.first_before).then(|| self.begin_removals(t))
            }
            Phase::BeforeStop => {
                let second = churns[1]?;
                (second > self.second_before).then(|| {
                    self.phase = Phase::Out(t);
                    self.stopped_at = Some(t);
                    Act::StopSecond
                })
            }
            Phase::Out(since) => (t >= since + self.timing.outage).then(|| {
                self.phase = Phase::BeforeRemovals;
                self.started_at = Some(t);
                Act::StartSecond
            }),
            Phase::BeforeRemovals => {
                let second = churns[1]?;
                (second >= 1).then(|| self.begin_removals(t))
            }
            Phase::Ending(last) => {
                let first = churns[0]?;
                let ends =
                    self.first_in_window(first) >= 2 && t >= last + self.timing.after_removal;
                ends.then(|| {
                    self.phase = Phase::Ended;
                    Act::End { cut: false }
                })
            }
            Phase::Ended => None,
        }
    }

    fn begin_removals(&mut self, t: f64) -> Act {
        self.phase = Phase::Ending(t + self.timing.removal_spread);
        self.removals_at = Some(t);
        Act::Remove
    }
}
