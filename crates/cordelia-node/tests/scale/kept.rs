//! What a run keeps for its report (decision 2026-10-22 §4.4): every input
//! the report reads, written to `report-inputs.json` beside `SUMMARY.md`,
//! so that the report can be made again from the run's folder alone
//! (`report::again`) when its reading of a bar is corrected, and a run of
//! hours need not be made again to be judged by it.
//!
//! The file carries its version. A harness reads only the version it
//! writes, and refuses any other, and a folder without the file (a run of
//! a harness before this one), with a line that says why: a run is never
//! misread. Within its version, a file is read only where it is as this
//! harness writes it: a key missing (an `Option` among them, which would
//! otherwise read as `None`) or a key it does not know is refused, and the
//! line says which.

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
/// new version. Version 2 keeps the build's constants the report reads,
/// and a device's counters that are not finite as words.
pub const INPUTS_VERSION: u32 = 2;

/// The constants of the run's build that the report reads, kept with the
/// run: a report made again by a later build judges the run by the values
/// it ran with, not by its own.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Constants {
    /// `protocol::ENTRY_OVERHEAD_BYTES`: what each entry is counted with.
    pub entry_overhead_bytes: usize,
    /// `protocol::MIN_ENTRY_CONTENT_BYTES`: the least content of an entry.
    pub min_entry_content_bytes: usize,
    /// `protocol::CHANGE_ENTRY_BYTES`: a change entry's content.
    pub change_entry_bytes: usize,
    /// `protocol::MAX_HAND_OVER_BYTES`: the largest hand-over.
    pub max_hand_over_bytes: usize,
    /// `protocol::LOAD_HISTOGRAM_BUCKETS`: the buckets of a histogram.
    pub load_histogram_buckets: usize,
    /// `protocol::NODE_STOP_TIMEOUT_SECS`: the time a node has to stop.
    pub node_stop_timeout_secs: u64,
    /// `cordelia_sync::claude::CYCLE_SECS`: the adapter's cycle.
    pub cycle_secs: u64,
}

impl Constants {
    /// The constants of the build this harness was built with.
    pub fn of_this_build() -> Constants {
        use cordelia_core::protocol as p;
        Constants {
            entry_overhead_bytes: p::ENTRY_OVERHEAD_BYTES,
            min_entry_content_bytes: p::MIN_ENTRY_CONTENT_BYTES,
            change_entry_bytes: p::CHANGE_ENTRY_BYTES,
            max_hand_over_bytes: p::MAX_HAND_OVER_BYTES,
            load_histogram_buckets: p::LOAD_HISTOGRAM_BUCKETS,
            node_stop_timeout_secs: p::NODE_STOP_TIMEOUT_SECS,
            cycle_secs: cordelia_sync::claude::CYCLE_SECS,
        }
    }

    /// What an entry of `ciphertext` bytes counts as (`protocol::entry_cost`).
    pub fn entry_cost(&self, ciphertext: usize) -> u64 {
        (ciphertext + self.entry_overhead_bytes) as u64
    }

    /// What an edit of `size` bytes of text in `file` counts as at a relay:
    /// its content, the text with its name and its chain about it (taken
    /// as 96 bytes), sealed in a power of two from the least content, and
    /// the overhead every entry is counted with.
    pub fn entry_cost_of(&self, file: &str, size: usize) -> u64 {
        let said = size + file.len() + 96 + 28;
        let content = said.next_power_of_two().max(self.min_entry_content_bytes);
        self.entry_cost(content)
    }
}

/// One node, as the report reads it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeptNode {
    pub label: String,
    pub what: What,
    pub key: String,
    pub key_hex: String,
    pub settings: Settings,
    /// The lines of its log that name one of the run's relays as a peer
    /// (`peer=<its key in hex>`, once the log's colours are taken out), as
    /// the log wrote them: what the report reads of a device's
    /// connections to the relays (bar 11).
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
    /// The constants of the run's build that the report reads.
    pub constants: Constants,
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
                        .filter(|l| {
                            let text = crate::report::strip_ansi(l);
                            relay_hex.iter().any(|h| text.contains(h.as_str()))
                        })
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
            constants: Constants::of_this_build(),
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
    /// with another version of them, or with a file that is not as this
    /// harness writes them (a key missing or not known), is refused, and
    /// the error says why.
    pub fn load(folder: &Path) -> Result<Kept, String> {
        let path = folder.join(INPUTS_FILE);
        if !folder.is_dir() {
            return Err(format!("{} is not a folder", folder.display()));
        }
        if !path.exists() {
            let summary = std::fs::read_to_string(folder.join("SUMMARY.md")).unwrap_or_default();
            if summary.contains(DID_NOT_START) {
                return Err(format!(
                    "{} holds no {INPUTS_FILE}: the run did not start (its SUMMARY.md says \
                     why), and has no report to make again",
                    folder.display()
                ));
            }
            return Err(format!(
                "{} holds no {INPUTS_FILE}: the run was made by a harness that did not keep \
                 what its report reads (decision 2026-10-22 §4.4), or its inputs were not \
                 kept (its SUMMARY.md says so), and its report cannot be made again; run it \
                 again",
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
        // Read only as it was written: what was read, written again, is
        // the file. A key missing reads as `None` where it is an `Option`,
        // and a key not known is passed over: both are refused here.
        let file: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("{} could not be read: {e}", path.display()))?;
        let back = serde_json::to_value(&kept)
            .map_err(|e| format!("{} could not be read: {e}", path.display()))?;
        if let Some(why) = first_difference(&file, &back, "") {
            return Err(format!(
                "{} is not as this harness writes version {INPUTS_VERSION}: {why}; it is not \
                 read, so that the run is not misread",
                path.display()
            ));
        }
        Ok(Kept {
            fleet: kept.fleet.indexed(),
            observer: kept.observer.indexed(),
            ..kept
        })
    }
}

/// What the summary of a run that did not start says (`report::refused`):
/// such a run keeps no inputs.
pub const DID_NOT_START: &str = "\n\nThe run did not start: ";

/// Where `file`, the inputs as read, differs from `back`, what was read of
/// them written again, at the JSON pointer `at`: a key missing, a key not
/// known, or a value that does not read as it is written.
fn first_difference(
    file: &serde_json::Value,
    back: &serde_json::Value,
    at: &str,
) -> Option<String> {
    use serde_json::Value;
    match (file, back) {
        (Value::Object(f), Value::Object(b)) => {
            for (k, bv) in b {
                let here = format!("{at}/{k}");
                match f.get(k) {
                    None => return Some(format!("the key {here} is missing")),
                    Some(fv) => {
                        if let Some(why) = first_difference(fv, bv, &here) {
                            return Some(why);
                        }
                    }
                }
            }
            f.keys()
                .find(|k| !b.contains_key(*k))
                .map(|k| format!("the key {at}/{k} is not one this harness knows"))
        }
        (Value::Array(f), Value::Array(b)) if f.len() == b.len() => f
            .iter()
            .zip(b)
            .enumerate()
            .find_map(|(i, (fv, bv))| first_difference(fv, bv, &format!("{at}/{i}"))),
        _ if file == back => None,
        _ => {
            let mut said = file.to_string();
            if said.len() > 80 {
                said = format!("{}...", said.chars().take(80).collect::<String>());
            }
            Some(format!(
                "the value at {} ({said}) does not read as it is written",
                if at.is_empty() { "/" } else { at }
            ))
        }
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

/// A number, or its word where JSON cannot hold it (not a number, or
/// infinite), read back as it was.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Word {
    Number(f64),
    Word(String),
}

impl Word {
    fn of(v: f64) -> Word {
        match v.is_finite() {
            true => Word::Number(v),
            false => Word::Word(v.to_string()),
        }
    }

    fn read<E: serde::de::Error>(self) -> Result<f64, E> {
        match self {
            Word::Number(n) => Ok(n),
            Word::Word(w) => w
                .parse()
                .map_err(|_| E::custom(format!("not a number: {w}"))),
        }
    }
}

/// A node's counters, each a number or its word.
pub mod counters {
    use super::*;

    pub fn serialize<S>(map: &Option<HashMap<String, f64>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        map.as_ref()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k, Word::of(*v)))
                    .collect::<BTreeMap<_, _>>()
            })
            .serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<HashMap<String, f64>>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let Some(map) = Option::<HashMap<String, Word>>::deserialize(d)? else {
            return Ok(None);
        };
        map.into_iter()
            .map(|(k, v)| v.read().map(|n| (k, n)))
            .collect::<Result<_, _>>()
            .map(Some)
    }
}

/// A number, or its word.
pub mod number {
    use super::*;

    pub fn serialize<S: serde::Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
        Word::of(*v).serialize(s)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
        Word::deserialize(d)?.read()
    }
}

/// A number or none, the number or its word.
pub mod maybe_number {
    use super::*;

    pub fn serialize<S: serde::Serializer>(v: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
        v.map(Word::of).serialize(s)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<f64>, D::Error> {
        Option::<Word>::deserialize(d)?.map(Word::read).transpose()
    }
}

/// Numbers in a row, each the number or its word.
pub mod numbers {
    use super::*;

    pub fn serialize<const N: usize, S>(row: &[f64; N], s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        row.iter()
            .map(|v| Word::of(*v))
            .collect::<Vec<_>>()
            .serialize(s)
    }

    pub fn deserialize<'de, const N: usize, D>(d: D) -> Result<[f64; N], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        row_of(Vec::<Word>::deserialize(d)?)
    }

    pub(super) fn row_of<const N: usize, E: serde::de::Error>(
        words: Vec<Word>,
    ) -> Result<[f64; N], E> {
        let row: Vec<f64> = words
            .into_iter()
            .map(Word::read)
            .collect::<Result<_, E>>()?;
        let len = row.len();
        row.try_into()
            .map_err(|_| E::invalid_length(len, &format!("{N} numbers").as_str()))
    }
}

/// Rows of numbers, each the number or its word.
pub mod number_rows {
    use super::*;

    pub fn serialize<const N: usize, const M: usize, S>(
        rows: &[[f64; M]; N],
        s: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        rows.iter()
            .map(|row| row.iter().map(|v| Word::of(*v)).collect::<Vec<_>>())
            .collect::<Vec<_>>()
            .serialize(s)
    }

    pub fn deserialize<'de, const N: usize, const M: usize, D>(
        d: D,
    ) -> Result<[[f64; M]; N], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let rows: Vec<[f64; M]> = Vec::<Vec<Word>>::deserialize(d)?
            .into_iter()
            .map(super::numbers::row_of)
            .collect::<Result<_, _>>()?;
        let len = rows.len();
        rows.try_into()
            .map_err(|_| serde::de::Error::invalid_length(len, &format!("{N} rows").as_str()))
    }
}
