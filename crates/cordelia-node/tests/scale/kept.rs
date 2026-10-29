//! What a run keeps for its report (decision 2026-10-22 §4.4): every input
//! the report reads, written to `report-inputs.json` beside `SUMMARY.md`,
//! so that the report can be made again from the run's folder alone
//! (`report::again`) when its reading of a bar is corrected, and a run of
//! hours need not be made again to be judged by it.
//!
//! The file carries its version. A harness reads only the version it
//! writes, and refuses any other, and a folder without the file (a run of
//! a harness before this one), with a line that says why: a run is never
//! misread.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};

use crate::configs::Settings;
use crate::fleet::{Change, MachineSample, Sample, What};
use crate::observer::{Arrival, Written};
use crate::run::{Outage, Plan, Removal, Run, Setup};

/// The file, in a run's folder.
pub const INPUTS_FILE: &str = "report-inputs.json";

/// The version of the file this harness writes, and the only one it
/// reads. A change to what the file holds, or to what a field means, is a
/// new version.
pub const INPUTS_VERSION: u32 = 1;

/// One node, as the report reads it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeptNode {
    pub label: String,
    pub what: What,
    pub key: String,
    pub key_hex: String,
    pub settings: Settings,
    /// The lines of its log that name one of the run's relays as a peer
    /// (`peer=<its key in hex>`), as the log wrote them: what the report
    /// reads of a device's connections to the relays (bar 11).
    pub log: Vec<String>,
}

/// The nodes, and what the harness did to each process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeptFleet {
    pub made: Vec<KeptNode>,
    /// The relays' nodes, in order.
    pub relays: Vec<usize>,
    /// Each start, freeze, going on and stop of each node.
    pub changes: Vec<Change>,
    /// Why the run stopped early, where it did.
    pub faults: Vec<String>,
    /// The run's time zero on the wall clock, in seconds since the epoch:
    /// a log's times are read against it.
    pub wall_zero: f64,
    /// Each device's node, by (person, device).
    #[serde(skip)]
    devices: HashMap<(usize, usize), usize>,
}

impl KeptFleet {
    fn indexed(mut self) -> KeptFleet {
        self.devices = self
            .made
            .iter()
            .enumerate()
            .filter_map(|(i, m)| match m.what {
                What::Device { person, device } => Some(((person, device), i)),
                What::Relay(_) => None,
            })
            .collect();
        self
    }

    /// The node of device `device` of person `person`.
    pub fn device(&self, person: usize, device: usize) -> usize {
        self.devices[&(person, device)]
    }

    /// The run's second of a time on the wall clock (a log's), in seconds
    /// since the epoch.
    pub fn of_wall(&self, epoch_secs: f64) -> f64 {
        epoch_secs - self.wall_zero
    }
}

/// What the observer kept.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeptObserver {
    pub edits: Vec<Written>,
    pub waited: Vec<(u64, usize)>,
    #[serde(with = "as_pairs")]
    pub arrivals: HashMap<(u64, usize), Arrival>,
    pub gone: Vec<(u64, usize)>,
    pub gaps: Vec<f64>,
    /// The waits that had not ended when the run did.
    pub still_waited: Vec<(u64, usize)>,
    /// By edit number, its place in `edits`.
    #[serde(skip)]
    at: HashMap<u64, usize>,
}

impl KeptObserver {
    fn indexed(mut self) -> KeptObserver {
        self.at = self
            .edits
            .iter()
            .enumerate()
            .map(|(i, e)| (e.number, i))
            .collect();
        self
    }

    pub fn edit(&self, number: u64) -> Option<&Written> {
        self.at.get(&number).map(|at| &self.edits[*at])
    }

    pub fn pending(&self) -> usize {
        self.still_waited.len()
    }
}

/// Every input of the report, as the run ended.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Kept {
    pub version: u32,
    /// The commit the run's harness and binary were built from, and the
    /// changes it had: the summary's first line names the run's.
    pub commit: String,
    pub built_with: String,
    /// The clock's ticks a second on the run's machine.
    pub ticks_a_second: f64,
    pub plan: Plan,
    pub fleet: KeptFleet,
    pub samples: Vec<Sample>,
    pub machine: Vec<MachineSample>,
    pub observer: KeptObserver,
    /// The edits numbered: the next number, less one.
    pub next_edit: u64,
    /// Each copy the adapter kept beside a file, in each memory folder of
    /// the run: (person, device, name, the copy's file name).
    pub conflict_copies: Vec<(usize, usize, usize, String)>,
    /// The window, and the run's second when its inputs were kept (the
    /// end of a window that never ended).
    pub window: Option<(f64, Option<f64>)>,
    pub kept_at: f64,
    pub cut: bool,
    pub removals: Vec<Removal>,
    pub removals_planned: usize,
    pub outage: Outage,
    pub setup: Setup,
    pub peers_at_end: Vec<(usize, Vec<String>)>,
    pub stops_at_end: Vec<(usize, f64, bool)>,
    pub pids_left: Vec<u32>,
    pub stopped_why: Option<String>,
}

impl Kept {
    /// What `run` holds for its report, as it is now.
    pub fn of(run: &Run, commit: String, built_with: &str, ticks_a_second: f64) -> Kept {
        let fleet = &run.fleet;
        let relay_hex: Vec<String> = fleet
            .relays
            .iter()
            .map(|i| format!("peer={}", fleet.made[*i].key_hex))
            .collect();
        let made = fleet
            .made
            .iter()
            .map(|m| KeptNode {
                label: m.label.clone(),
                what: m.what,
                key: m.key.clone(),
                key_hex: m.key_hex.clone(),
                settings: m.settings.lock().unwrap().clone(),
                log: match m.what {
                    What::Device { .. } => std::fs::read_to_string(m.node.log())
                        .unwrap_or_default()
                        .lines()
                        .filter(|l| relay_hex.iter().any(|h| l.contains(h.as_str())))
                        .map(str::to_string)
                        .collect(),
                    What::Relay(_) => Vec::new(),
                },
            })
            .collect();
        let wall_zero = fleet
            .clock
            .wall
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        let observer = {
            let o = run.observer.lock().unwrap();
            KeptObserver {
                edits: o.edits.clone(),
                waited: o.waited.clone(),
                arrivals: o.arrivals.clone(),
                gone: o.gone.clone(),
                gaps: o.gaps.clone(),
                still_waited: o.still_waited(),
                at: HashMap::new(),
            }
        };
        let mut conflict_copies = Vec::new();
        for ((person, device, name), folder) in &run.folders {
            for e in std::fs::read_dir(folder).into_iter().flatten().flatten() {
                let file = e.file_name().to_string_lossy().into_owned();
                if file.contains(".conflict-") {
                    conflict_copies.push((*person, *device, *name, file));
                }
            }
        }
        conflict_copies.sort();
        let (samples, machine) = {
            let s = run.samples.lock().unwrap();
            (s.nodes.clone(), s.machine.clone())
        };
        Kept {
            version: INPUTS_VERSION,
            commit,
            built_with: built_with.to_string(),
            ticks_a_second,
            plan: run.plan.clone(),
            fleet: KeptFleet {
                made,
                relays: fleet.relays.clone(),
                changes: fleet.changes.lock().unwrap().clone(),
                faults: fleet.faults.lock().unwrap().clone(),
                wall_zero,
                devices: HashMap::new(),
            }
            .indexed(),
            samples,
            machine,
            observer: observer.indexed(),
            next_edit: run.next_edit.load(Ordering::SeqCst),
            conflict_copies,
            window: *run.window.lock().unwrap(),
            kept_at: fleet.clock.now(),
            cut: run.cut.load(Ordering::SeqCst),
            removals: run.removals.lock().unwrap().clone(),
            removals_planned: *run.removals_planned.lock().unwrap(),
            outage: run.outage.lock().unwrap().clone(),
            setup: run.setup.lock().unwrap().clone(),
            peers_at_end: run.peers_at_end.lock().unwrap().clone(),
            stops_at_end: run.stops_at_end.lock().unwrap().clone(),
            pids_left: run.pids_left.lock().unwrap().clone(),
            stopped_why: run.stopped_why.lock().unwrap().clone(),
        }
    }

    /// Write the inputs into `folder`.
    pub fn save(&self, folder: &Path) -> Result<(), String> {
        let path = folder.join(INPUTS_FILE);
        let file = std::fs::File::create(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut file = std::io::BufWriter::new(file);
        serde_json::to_writer(&mut file, self).map_err(|e| format!("{}: {e}", path.display()))?;
        std::io::Write::flush(&mut file).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Read the inputs a run wrote into `folder`. A folder without them,
    /// or with another version of them, is refused, and the error says
    /// why.
    pub fn load(folder: &Path) -> Result<Kept, String> {
        let path = folder.join(INPUTS_FILE);
        if !folder.is_dir() {
            return Err(format!("{} is not a folder", folder.display()));
        }
        if !path.exists() {
            return Err(format!(
                "{} holds no {INPUTS_FILE}: the run was made by a harness that did not keep \
                 what its report reads, before version {INPUTS_VERSION} of the inputs (decision \
                 2026-10-22 §4.4), and its report cannot be made again; run it again",
                folder.display()
            ));
        }
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        #[derive(Deserialize)]
        struct Head {
            version: u32,
        }
        let head: Head = serde_json::from_str(&text).map_err(|e| {
            format!(
                "{} is not the inputs of a run's report: {e}",
                path.display()
            )
        })?;
        if head.version != INPUTS_VERSION {
            return Err(format!(
                "{} is version {} of a run's inputs, and this harness reads version \
                 {INPUTS_VERSION} only: its report is made again by a harness of its version",
                path.display(),
                head.version
            ));
        }
        let kept: Kept = serde_json::from_str(&text)
            .map_err(|e| format!("{} could not be read: {e}", path.display()))?;
        Ok(Kept {
            fleet: kept.fleet.indexed(),
            observer: kept.observer.indexed(),
            ..kept
        })
    }
}

/// A map whose keys are not strings, as a list of pairs in the keys'
/// order.
mod as_pairs {
    use super::*;

    pub fn serialize<K, V, S>(map: &HashMap<K, V>, s: S) -> Result<S::Ok, S::Error>
    where
        K: Serialize + Ord,
        V: Serialize,
        S: serde::Serializer,
    {
        let mut pairs: Vec<(&K, &V)> = map.iter().collect();
        pairs.sort_by(|a, b| a.0.cmp(b.0));
        pairs.serialize(s)
    }

    pub fn deserialize<'de, K, V, D>(d: D) -> Result<HashMap<K, V>, D::Error>
    where
        K: Deserialize<'de> + std::hash::Hash + Eq,
        V: Deserialize<'de>,
        D: serde::Deserializer<'de>,
    {
        Ok(Vec::<(K, V)>::deserialize(d)?.into_iter().collect())
    }
}

/// A node's counters: a value JSON cannot hold (not a number, or
/// infinite) is written as its word, and read back as it was.
pub mod counters {
    use super::*;

    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    enum Value {
        Number(f64),
        Word(String),
    }

    pub fn serialize<S>(map: &Option<HashMap<String, f64>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        map.as_ref()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| {
                        let v = match v.is_finite() {
                            true => Value::Number(*v),
                            false => Value::Word(v.to_string()),
                        };
                        (k, v)
                    })
                    .collect::<BTreeMap<_, _>>()
            })
            .serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<HashMap<String, f64>>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let Some(map) = Option::<HashMap<String, Value>>::deserialize(d)? else {
            return Ok(None);
        };
        map.into_iter()
            .map(|(k, v)| match v {
                Value::Number(n) => Ok((k, n)),
                Value::Word(w) => w
                    .parse()
                    .map(|n| (k, n))
                    .map_err(|_| serde::de::Error::custom(format!("not a number: {w}"))),
            })
            .collect::<Result<_, _>>()
            .map(Some)
    }
}
