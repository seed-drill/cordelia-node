//! What several devices come to over a sequence of edits, deletes, syncs
//! and changes of the person's devices, for the rule that a version is
//! taken with nothing kept only where it is known to follow the text a
//! folder agreed (decision 2026-09-30 §4.5, decision 2026-10-04 §7.3).
//!
//! Two things are checked for that rule, each over written and generated
//! sequences (and three more for the index line of a memory that comes
//! back, further down, with a kind of device and steps of their own):
//!
//! - **The property.** The rule changes one thing: where a file would be
//!   replaced by a version at a higher revision that is not known to
//!   follow the one the folder agreed, what the file held is kept first.
//!   So a run with every device as it is built, and a run of the same
//!   sequence with every device planning by revision alone, end every
//!   step with the same files, the same versions in the channel and the
//!   same records, on every device that is still the person's. Only the
//!   conflict files may differ, and only by there being more of them.
//! - **The keep.** With every device as built, no text that an edit wrote
//!   is in no file at the end, unless someone edited or deleted a file
//!   while it held that text.
//!
//!   "Let go" goes by the text, on any device and for good: once a step
//!   has edited or deleted a file that held a text, that text is not
//!   looked for again, on any device. So this check does not see a text
//!   that is lost after it was put back by hand: the adapter's own tests
//!   have that case (`a_text_overtaken_twice_is_kept_twice`). An index
//!   line is let go of only when a step deletes or edits a copy of the
//!   index that holds it while the device's index does not.
//!
//!   A text is looked for where the folder of a device that is still the
//!   person's has held it. What only a removed device's folder ever held
//!   is gone with that device (decision 2026-10-04 §7.4).
//!
//! **A change of the person's devices** is a step like any other: one
//! device makes a statement with the phrase, which removes a device or
//! nobody, and each device that is shown it applies it and carries what it
//! holds into the name's new channel. Until a device is shown the change
//! it goes on in the channel that the others have left, and nothing
//! passes between the two. What the plan does once a device has applied
//! has five cases (decision 2026-10-04 §7.3), and each cycle that meets
//! one of them is held to it there and then ([`World::meets`],
//! [`World::held_to`]):
//!
//! 1. a file as its record, where the new channel has that version:
//!    nothing;
//! 2. the new channel comes to be ahead: the file takes its version, by
//!    the rule above;
//! 3. the file was edited and not yet published: the edit is published
//!    over the version that the device carried, and says so;
//! 4. two devices carried one version: the two entries are one version,
//!    and nothing follows;
//! 5. two devices carried two versions at one revision: a tie, and the
//!    text that loses is kept beside the file.
//!
//! A tie between two versions at one revision goes to the higher hash of
//! the text, and a text beats a delete. Here every text that a step writes
//! ends with a number, chosen so that its hash begins where the seed and
//! the step say ([`World::placed`]). So one sequence has one outcome, in
//! every run. Two seeds that differ only in their last bit put every such
//! text at the other end of the order: every tie between two texts that
//! steps wrote goes the other way. A text that a cycle makes (a merged
//! index), an index that a step has taken lines out of, and a delete are
//! not placed so: their ties go as the hashes fall, the same in every run
//! of one seed.
//!
//! What the sequences do not vary: what one device passes to another
//! arrives in the order it was stored.
//!
//! **How much is run.** A device checks the two signatures of every entry
//! each time it reads a slot. In a test build that takes most of a
//! cycle's time, and a sequence of some seventy steps takes seconds. So by
//! default a part is run: one generated sequence for two devices and one
//! for three; and the written sequences, without those that vary
//! another, each with one seed and at most one mix of kinds. The checks
//! that a good part of the generated sequences reach a rule are made
//! only where everything is run, which `CORDELIA_SEQUENCES=12` does
//! ([`sequences`], [`everything`]). A written sequence is run once for
//! each kind of world, whichever tests ask about it ([`came`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use cordelia_api::{adding, change, take};
use cordelia_crypto::derive;
use cordelia_crypto::entry::CheckedEntry;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::phrase::Phrase;
use cordelia_crypto::version::{self, Slot, Version};
use cordelia_storage::entries as stored;
use cordelia_storage::person as held_rows;

use super::*;
use crate::memory_md::INDEX_FILE;

/// The name that every folder of a sequence syncs.
const NAME: &str = "x";

/// How a device behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// As it is built: the plan, with its rule for a version that is not
    /// known to follow, and the index line of a memory that comes back.
    Built,
    /// As a device that plans by revision alone ([`plan_before`]). It
    /// writes its entries as any device does, each with its chain, and
    /// keeps the records that any device keeps: only its plan differs. It
    /// has no record of its index lines either.
    Before,
    /// As it is built, without the index line of a memory that comes back
    /// ([`lines`]): what the rule for an overtaken edit shipped as.
    Lineless,
}

/// The plan without its rule for a version that is not known to follow: a
/// higher revision follows, and that is all. Nothing is asked of a chain,
/// or of who counts. Everything else is as [`plan::plan`] has it. Frozen
/// here so that the plan can be compared with it.
fn plan_before(
    key: &str,
    local: Option<&Content>,
    remote: Option<&Remote>,
    agreed: Option<&Agreed>,
    deleted_files: &HashSet<String>,
    _counting: &Counting,
) -> Vec<Action> {
    let local_hash = local.map(|c| c.hash);
    let remote_hash = remote.and_then(|r| r.content.as_ref().map(|c| c.hash));
    let local_changed = match agreed {
        None => local.is_some(),
        Some(a) => local_hash != a.hash,
    };
    let remote_changed = match (remote, agreed) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(_), Some(a)) => remote_hash != a.hash,
    };
    let follows = match (remote, agreed) {
        (Some(r), Some(a)) => r.rev > a.rev,
        _ => true,
    };
    let is_index = key == INDEX_FILE;
    let record = |r: &Remote, hash: Option<[u8; 32]>| Action::Record(r.agreed_with(hash));
    let pull = |r: &Remote, c: &Content| Action::Pull {
        text: c.text.clone(),
        agreed: r.agreed_with(Some(c.hash)),
    };
    let merged = |r: &Remote, c: &Content, l: &Content| {
        let text = crate::memory_md::merge(&c.text, &l.text, deleted_files);
        if text == c.text {
            pull(r, c)
        } else {
            Action::Merge(text)
        }
    };
    match (local_changed, remote_changed) {
        (false, false) => match (remote, agreed) {
            (Some(r), Some(a)) if *a != r.agreed_with(a.hash) => vec![record(r, a.hash)],
            _ => vec![],
        },
        (true, false) => match local {
            Some(c) => vec![Action::Publish(c.text.clone())],
            None => match remote {
                Some(r) if r.content.is_some() => vec![Action::PublishDelete],
                Some(r) => vec![record(r, None)],
                None => vec![],
            },
        },
        (false, true) => {
            let r = remote.expect("remote_changed implies remote");
            match (&r.content, local) {
                (None, None) => vec![record(r, None)],
                (None, Some(_)) if follows => vec![Action::RemoveFile {
                    agreed: r.agreed_with(None),
                }],
                (None, Some(l)) => vec![Action::Publish(l.text.clone())],
                (Some(c), None) => vec![pull(r, c)],
                (Some(c), Some(_)) if follows => vec![pull(r, c)],
                (Some(c), Some(l)) if is_index => vec![merged(r, c, l)],
                (Some(c), Some(l)) => vec![Action::SaveConflict(l.text.clone()), pull(r, c)],
            }
        }
        (true, true) => {
            let r = remote.expect("remote_changed implies remote");
            match (local, &r.content) {
                (l, rc) if l.map(|c| c.hash) == rc.as_ref().map(|c| c.hash) => {
                    vec![record(r, local_hash)]
                }
                (None, Some(c)) => vec![pull(r, c)],
                (Some(l), None) => vec![Action::Publish(l.text.clone())],
                (Some(l), Some(c)) if is_index => vec![merged(r, c, l)],
                (Some(l), Some(c)) => vec![Action::SaveConflict(l.text.clone()), pull(r, c)],
                (None, None) => vec![record(r, None)],
            }
        }
    }
}

/// One step of a sequence. Devices are numbered from 0.
#[derive(Clone, Debug)]
enum Step {
    /// The device writes a text of its own to the file: one no other step
    /// writes.
    Edit(usize, &'static str),
    /// The device adds a line of its own to the index.
    Line(usize),
    /// The device deletes the file, if it has it.
    Delete(usize, &'static str),
    /// The device runs a cycle.
    Cycle(usize),
    /// Everything the first device holds of the name's channel reaches
    /// the second.
    Pass(usize, usize),
    /// The first device's entry for one file reaches the second.
    PassOne(usize, usize, &'static str),
    /// From now on the device plans by revision alone. Only for a test of
    /// the check itself: a fault, put where the test wants it.
    AsBefore(usize),
    /// The first device removes the second, with the phrase: it makes the
    /// statement, applies it and carries what it holds, and every other
    /// device that remains is shown the change at once, and applies it
    /// and carries. From then on the second's folder is no longer one of
    /// the person's. The second is not shown the change: it goes on in
    /// the channel that the others have left, and what it writes there is
    /// refused by each of them.
    Remove(usize, usize),
    /// The same, with no other device shown the change yet: each goes on
    /// in the channel that was left, where it still takes what the
    /// removed device writes, until it is shown the change ([`Step::Hear`]).
    RemoveUnheard(usize, usize),
    /// The device makes a change that removes nobody, as a renewal does,
    /// applies it and carries what it holds. No other device is shown it
    /// yet.
    Renew(usize),
    /// The device is shown the latest change, as a relay that holds it
    /// shows it: it applies it and carries what it holds, or, where the
    /// change removes it, stops.
    Hear(usize),
    /// The device deletes the first conflict file it has, if any.
    DropCopy(usize),
    /// The device writes a text of its own to its first conflict file.
    EditCopy(usize),
    /// The device puts the text of its first conflict file into the file
    /// it is a copy of, after what the file holds, and deletes the copy.
    MergeCopy(usize),
    /// The device adds a line for the file to its index: one with a link.
    Listed(usize, &'static str),
    /// The device takes every line for the file out of its index.
    Unlist(usize, &'static str),
    /// A minute of looks on the device: thirteen cycles, five seconds
    /// apart by its clock.
    Minute(usize),
}

impl Step {
    /// The device that the step is a step of: the one whose folder it can
    /// change, where it changes one.
    fn on(&self) -> usize {
        match self {
            Step::Edit(d, _)
            | Step::Line(d)
            | Step::Delete(d, _)
            | Step::Cycle(d)
            | Step::Pass(d, _)
            | Step::PassOne(d, _, _)
            | Step::AsBefore(d)
            | Step::Remove(d, _)
            | Step::RemoveUnheard(d, _)
            | Step::Renew(d)
            | Step::Hear(d)
            | Step::DropCopy(d)
            | Step::EditCopy(d)
            | Step::MergeCopy(d)
            | Step::Listed(d, _)
            | Step::Unlist(d, _)
            | Step::Minute(d) => *d,
        }
    }
}

/// A device in a sequence.
struct Device {
    st: AppState,
    mem: PathBuf,
    kind: Kind,
    /// The entries of this device's own that have been looked at for a
    /// tie, each by what it is named by.
    looked_at: HashSet<[u8; 32]>,
    /// Whether it has applied a change and run no cycle since.
    moved: bool,
    /// The versions it carried when it last applied a change: for each
    /// file, the revision and the hash of what the version holds.
    carried: BTreeMap<String, (u64, [u8; 32])>,
    /// Each text that its folder held when a step of its own ended, by
    /// the file it is a text of.
    held: BTreeSet<(String, String)>,
    /// Each line that an index in its folder, or a copy of one, held then.
    held_lines: BTreeSet<String>,
    /// Who counts for it under the statement of this number, once that
    /// has been read ([`World::counting`]).
    counting: RefCell<Option<(u64, Counting)>>,
}

/// What a device has for the files that are not conflict files, and the
/// conflict files it has, each as the file it is a copy of and its text.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Has {
    files: BTreeMap<String, String>,
    /// The channel's version of each file as this device reads it:
    /// revision, and text (`None` for a delete).
    channel: BTreeMap<String, (u64, Option<String>)>,
    /// What the folder has recorded for each file: hash and revision.
    records: BTreeMap<String, (Option<[u8; 32]>, u64)>,
    copies: BTreeSet<(String, String)>,
}

/// The file a conflict file is a copy of, however many times over.
fn root_of(name: &str) -> String {
    let mut name = name.to_string();
    while names::is_conflict_name(&name) {
        let (stem, rest) = name.rsplit_once(".conflict-").expect("a conflict name");
        let ext = rest
            .split_once('.')
            .map(|(_, ext)| format!(".{ext}"))
            .unwrap_or_default();
        name = format!("{stem}{ext}");
    }
    name
}

/// What decides a tie at one revision, the greater winning: the hash of
/// the text, and a delete is below every text.
fn rank(value: &Value) -> (Option<[u8; 32]>, bool) {
    (value.hash(), matches!(value, Value::Text(_)))
}

/// One of the five cases of what the plan does once a device has applied
/// a change and carried (decision 2026-10-04 §7.3), as a cycle is about to
/// meet it for one file: what the device had then.
struct Met {
    /// Which of the five, from 0.
    case: usize,
    file: String,
    /// What the file held, if it was there.
    local: Option<String>,
    /// The channel's version of the file, as the device read it.
    version: Version,
    /// What its slot held, as a publish is planned against it.
    planned: PlannedAgainst,
    /// Whether that version was known to follow what the folder agreed.
    known: bool,
    /// The conflict files that the device had.
    copies: BTreeSet<(String, String)>,
}

/// Several devices of one person, whose folders sync one name.
struct World {
    devices: Vec<Device>,
    /// The phrase the devices follow: what a change is made with.
    phrase: Phrase,
    /// The latest change entry: what a relay would show a device.
    change: CheckedEntry,
    /// What places each text that a step writes, with the step.
    seed: u64,
    /// The step being run.
    step: usize,
    /// The devices that have been removed, each with the number of the
    /// statement that removed it.
    removed: BTreeMap<usize, u64>,
    /// What each entry that a device carried is named by.
    carried: HashSet<[u8; 32]>,
    /// Each entry that the harness has read from a device's store, by
    /// what it is named by, as it passed the check that needs no key. An
    /// entry is checked once here, as a device checks it once when it
    /// arrives.
    checked: RefCell<HashMap<[u8; 32], CheckedEntry>>,
    /// How many times a cycle met each of the five cases of what the plan
    /// does once a device has applied a change.
    reached: [usize; 5],
    /// Each text a step wrote to a file, by the file it is a text of.
    wrote: BTreeSet<(String, String)>,
    /// Each line a step added to the index.
    lines: BTreeSet<String>,
    /// Each text that a file held when a step edited or deleted that
    /// file: someone saw it and let it go.
    let_go: BTreeSet<(String, String)>,
    /// Each index line that a copy of the index held when a step edited
    /// or deleted that copy, and that the device's index did not have.
    let_go_lines: BTreeSet<String>,
    /// The time, in seconds, by every device's clock. Only a minute of
    /// looks moves it on.
    now: i64,
    /// Each file that a step deleted on some device.
    deleted: BTreeSet<String>,
    /// How many times a cycle put index lines back, on any device.
    put_back: u64,
    /// Each tie that a publish made: the file, and whether the version
    /// published later won it.
    ties: BTreeSet<(String, bool)>,
    _tmp: tempfile::TempDir,
}

/// The key pair of the device numbered `i`: the same in every run, so that
/// a device's conflict files have the same names in every run.
fn identity_of(i: usize) -> NodeIdentity {
    NodeIdentity::from_seed([i as u8 + 1; 32]).unwrap()
}

/// What a world of some number of devices starts from: the database of
/// each device as the set-up left it, and the words of the phrase that
/// they follow.
struct Start {
    databases: Vec<Vec<u8>>,
    words: String,
}

impl Start {
    /// The start of a world of `n` devices. It is set up once for each
    /// number of devices, and every world of that many begins from a copy
    /// of it: a phrase, a hand-over and an accept each take longer than a
    /// harness of many worlds can give them.
    fn of(n: usize) -> Arc<Start> {
        static STARTS: Mutex<BTreeMap<usize, Arc<Start>>> = Mutex::new(BTreeMap::new());
        let mut starts = STARTS.lock().unwrap_or_else(|e| e.into_inner());
        let start = starts.entry(n).or_insert_with(|| Arc::new(Self::set_up(n)));
        Arc::clone(start)
    }

    /// Set `n` devices up as the commands do: the first makes a phrase,
    /// adds each of the others, which accepts what it is handed, and each
    /// holds the name.
    fn set_up(n: usize) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let path = |i: usize| tmp.path().join(format!("{i}.db"));
        let now = STARTS_AT;
        let devices: Vec<(rusqlite::Connection, NodeIdentity)> = (0..n)
            .map(|i| {
                (
                    cordelia_storage::db::open(&path(i)).unwrap(),
                    identity_of(i),
                )
            })
            .collect();
        let phrase = Phrase::generate().unwrap();
        let (first, first_key) = (&devices[0].0, &devices[0].1);
        person::first_statement(first, first_key, &phrase, "desktop", now).unwrap();
        person::hold_name(first, NAME, now).unwrap();
        for (i, (db, identity)) in devices.iter().enumerate().skip(1) {
            let label = format!("laptop {i}");
            let added =
                adding::add_device(first, first_key, &identity.public_key(), &label, now).unwrap();
            let typed = first_key.public_key();
            let accepted =
                adding::accept(db, identity, &typed, now, false, &added.hand_over, now).unwrap();
            assert!(
                matches!(accepted, adding::Accepted::Joined(_)),
                "{accepted:?}"
            );
            person::hold_name(db, NAME, now).unwrap();
        }
        // The record of each addition is in the first device's personal
        // channel. Every other device is given that channel, twice over (an
        // entry that a key signed before a record made that key count is
        // given again): from then on every device counts every other, and
        // no entry that passes between two of them is a record.
        let records: Vec<CheckedEntry> = {
            let person = held_rows::applied_secret(first).unwrap().unwrap();
            let personal = derive::personal_secret(&person.secret).unwrap();
            let channel = derive::channel_id(&personal).unwrap();
            let held = stored::channel_entries_after(first, &channel, 0, 10_000).unwrap();
            held.into_iter()
                .map(|held| held.entry.check().unwrap())
                .collect()
        };
        for (db, identity) in &devices[1..] {
            for entry in records.iter().chain(&records) {
                take::take(db, identity, entry, now).unwrap();
            }
        }
        for (db, _) in &devices {
            let counting = person::who_counts(db).unwrap();
            let mut keys = devices.iter().map(|(_, identity)| identity.public_key());
            assert!(keys.all(|key| counting.counts(&key)));
            // Everything is in the one file before it is read.
            db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .unwrap();
        }
        drop(devices);
        Self {
            databases: (0..n).map(|i| std::fs::read(path(i)).unwrap()).collect(),
            words: phrase.words().unwrap().to_string(),
        }
    }
}

/// The time at which a world starts, in seconds.
const STARTS_AT: i64 = 1_800_000_000;

impl World {
    /// Devices of the kinds given, of one person, each holding the name,
    /// with nothing written yet ([`Start`]).
    fn new(kinds: &[Kind], seed: u64) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let start = Start::of(kinds.len());
        let devices: Vec<Device> = kinds
            .iter()
            .enumerate()
            .map(|(i, kind)| {
                let dir = tmp.path().join(format!("d{i}"));
                let mem = dir.join("memory");
                std::fs::create_dir_all(&mem).unwrap();
                let home = dir.join("node");
                std::fs::create_dir_all(&home).unwrap();
                let path = home.join("cordelia.db");
                std::fs::write(&path, &start.databases[i]).unwrap();
                let db = cordelia_storage::db::open(&path).unwrap();
                // Nothing here waits for a disk.
                db.execute_batch("PRAGMA synchronous = OFF;").unwrap();
                let st = AppState {
                    db: Mutex::new(db),
                    identity: identity_of(i),
                    bearer_token: "t".into(),
                    home_dir: home,
                    started_at: std::time::Instant::now(),
                    sync_errors: std::sync::atomic::AtomicU64::new(0),
                    peers_hot: std::sync::atomic::AtomicU64::new(0),
                    peers_warm: std::sync::atomic::AtomicU64::new(0),
                    push_tx: None,
                    announce_tx: None,
                    peers: Default::default(),
                    relays: Default::default(),
                    outbox_refused: Default::default(),
                    relist: Default::default(),
                    sync_control: Default::default(),
                    own_channels: Default::default(),
                    history: Default::default(),
                };
                // Set up with no relay: a folder's first cycle waits for
                // none.
                st.own_channels.set_up_with(0);
                Device {
                    st,
                    mem,
                    kind: *kind,
                    looked_at: HashSet::new(),
                    moved: false,
                    carried: BTreeMap::new(),
                    held: BTreeSet::new(),
                    held_lines: BTreeSet::new(),
                    counting: RefCell::new(None),
                }
            })
            .collect();
        let change = {
            let db = devices[0].st.db.lock().unwrap();
            let kept = held_rows::change_entry(&db, held_rows::Kept::Latest);
            kept.unwrap().unwrap().check().unwrap()
        };
        Self {
            devices,
            phrase: Phrase::parse(&start.words).unwrap(),
            change,
            seed,
            step: 0,
            removed: BTreeMap::new(),
            carried: HashSet::new(),
            checked: RefCell::new(HashMap::new()),
            reached: [0; 5],
            wrote: BTreeSet::new(),
            lines: BTreeSet::new(),
            let_go: BTreeSet::new(),
            let_go_lines: BTreeSet::new(),
            now: STARTS_AT,
            deleted: BTreeSet::new(),
            put_back: 0,
            ties: BTreeSet::new(),
            _tmp: tmp,
        }
    }

    /// The device's key.
    fn key(&self, d: usize) -> [u8; 32] {
        self.devices[d].st.identity.public_key()
    }

    /// The number of the statement the device has applied.
    fn number(&self, d: usize) -> u64 {
        let db = self.devices[d].st.db.lock().unwrap();
        held_rows::applied_secret(&db).unwrap().unwrap().number
    }

    /// The secret of the name's channel in the generation the device has
    /// applied.
    fn secret(&self, d: usize) -> [u8; 32] {
        let db = self.devices[d].st.db.lock().unwrap();
        let person = held_rows::applied_secret(&db).unwrap().unwrap();
        derive::own_secret(&person.secret, NAME).unwrap()
    }

    /// The ID of that channel as it is written: what the folder's records
    /// are kept by.
    fn channel(&self, d: usize) -> String {
        encode_channel_id(&derive::channel_id(&self.secret(d)).unwrap()).unwrap()
    }

    /// Whether the device has stopped: it was removed, and has been shown
    /// the change that removed it.
    fn stopped(&self, d: usize) -> bool {
        let db = self.devices[d].st.db.lock().unwrap();
        !matches!(at_relays::stands(&db).unwrap(), Stands::Applied)
    }

    /// Who counts for the device, under the statement it has applied. It
    /// is read once for each statement: after the set-up no record of an
    /// addition arrives, so nothing but a statement changes it.
    fn counting(&self, d: usize) -> Counting {
        let number = self.number(d);
        let device = &self.devices[d];
        let mut known = device.counting.borrow_mut();
        match &*known {
            Some((of, counting)) if *of == number => counting.clone(),
            _ => {
                let db = device.st.db.lock().unwrap();
                let counting = person::who_counts(&db).unwrap();
                *known = Some((number, counting.clone()));
                counting
            }
        }
    }

    /// What the device holds of the name's channel, in the generation it
    /// has applied, in the order it stored them. Each entry is checked
    /// when the harness first reads it, and not again.
    fn held(&self, d: usize) -> Vec<CheckedEntry> {
        let channel = derive::channel_id(&self.secret(d)).unwrap();
        let db = self.devices[d].st.db.lock().unwrap();
        let held = stored::channel_entries_after(&db, &channel, 0, 100_000).unwrap();
        let mut checked = self.checked.borrow_mut();
        held.into_iter()
            .map(|held| {
                let entry = checked
                    .entry(held.entry.id())
                    .or_insert_with(|| held.entry.check().unwrap());
                entry.clone()
            })
            .collect()
    }

    /// Each slot of the name's channel that holds a version, as the
    /// device reads it: its current version with every entry that is it,
    /// and the versions that lost a tie. The slots are in the order in
    /// which the device stored each slot's oldest entry.
    ///
    /// It is what a read of the name gives the device
    /// ([`publish::read_name`]), by the same reading of each slot, without
    /// the check of every entry's signatures that a read of the store
    /// makes each time (`the_harness_reads_a_channel_as_a_device_does`).
    fn slots(&self, d: usize) -> Vec<Slot> {
        let (secret, number, counting) = (self.secret(d), self.number(d), self.counting(d));
        let mut by_slot: Vec<Vec<CheckedEntry>> = Vec::new();
        for entry in self.held(d) {
            match by_slot.iter_mut().find(|held| held[0].slot == entry.slot) {
                Some(held) => held.push(entry),
                None => by_slot.push(vec![entry]),
            }
        }
        by_slot
            .iter()
            .map(|held| {
                version::current(held, &secret, number, |key| counting.counts(key)).unwrap()
            })
            .filter(|slot| slot.current.is_some())
            .collect()
    }

    /// The slot of one file, as the device reads it, where it holds a
    /// version.
    fn slot(&self, d: usize, file: &str) -> Option<Slot> {
        let mut slots = self.slots(d).into_iter();
        slots.find(|slot| slot.current.as_ref().is_some_and(|v| v.name == file))
    }

    fn read(&self, d: usize, name: &str) -> Option<String> {
        std::fs::read_to_string(self.devices[d].mem.join(name)).ok()
    }

    /// The names of the device's files, sorted.
    fn names(&self, d: usize) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.devices[d].mem)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|name| !name.starts_with('.'))
            .collect();
        names.sort();
        names
    }

    /// The device's first conflict file, if it has one.
    fn first_copy(&self, d: usize) -> Option<String> {
        self.names(d)
            .into_iter()
            .find(|name| names::is_conflict_name(name))
    }

    /// A step writes `text` to `name` on a device, or deletes the file.
    /// Whatever the file held there is let go of, knowingly. Of a copy of
    /// the index, the lines that the device's index does not have are let
    /// go of: the others are still in front of whoever does this.
    fn put(&mut self, d: usize, name: &str, text: Option<&str>) {
        if let Some(held) = self.read(d, name) {
            let root = root_of(name);
            if root == INDEX_FILE {
                let index = self.read(d, INDEX_FILE).unwrap_or_default();
                let there: BTreeSet<&str> = index.lines().collect();
                let gone = held.lines().filter(|line| !there.contains(line));
                self.let_go_lines.extend(gone.map(String::from));
            }
            self.let_go.insert((root, held));
        }
        let path = self.devices[d].mem.join(name);
        match text {
            Some(text) => std::fs::write(path, text).unwrap(),
            None => {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    /// A text that this step writes: `write` of the first number for which
    /// the text's hash begins where the seed and the step say. Returns
    /// the number with the text.
    ///
    /// The place is the hash's first byte: three bits that the seed and
    /// the step decide, and then the step's last five, so that two steps
    /// of one sequence seldom share a place. With a seed whose last bit is
    /// set it is the other end of the order: of two texts that steps
    /// wrote in a sequence, the one whose hash is higher with one seed
    /// has the lower with the next (2 and 3, say).
    fn placed(&self, write: impl Fn(u32) -> String) -> (u32, String) {
        let said = format!("{}/{}", self.seed >> 1, self.step);
        let chance = cordelia_crypto::sha256(said.as_bytes())[0] >> 5;
        let mut place = (chance << 5) | (self.step as u8 & 0x1f);
        if self.seed & 1 == 1 {
            place = !place;
        }
        (0u32..)
            .map(|n| (n, write(n)))
            .find(|(_, text)| cordelia_crypto::sha256(text.as_bytes())[0] == place)
            .expect("a number that places the text")
    }

    /// One step. A step that has nothing to act on (a file that is not
    /// there to delete, no conflict file to resolve, a change on a device
    /// that has stopped) does nothing.
    fn run(&mut self, step: &Step) {
        self.step += 1;
        let at = self.step;
        match step {
            Step::Edit(d, name) => {
                let (_, text) =
                    self.placed(|n| format!("{name}, written on {d} at step {at} ({n})\n"));
                self.wrote.insert((name.to_string(), text.clone()));
                self.put(*d, name, Some(&text));
            }
            Step::Line(d) => {
                // No link in it: a merge drops a line that points at a
                // deleted file, which is not what is under test here.
                let line = |n: u32| format!("- written on {d} at step {at} ({n})");
                let index = self.read(*d, INDEX_FILE).unwrap_or_default();
                let (n, text) = self.placed(|n| format!("{index}{}\n", line(n)));
                self.lines.insert(line(n));
                // Not let go: every line that was there is still there.
                std::fs::write(self.devices[*d].mem.join(INDEX_FILE), text).unwrap();
            }
            Step::Delete(d, name) => {
                self.deleted.insert(name.to_string());
                self.put(*d, name, None);
            }
            Step::Listed(d, name) => {
                let line = |n: u32| format!("- [{name}]({name}) listed on {d} at step {at} ({n})");
                let index = self.read(*d, INDEX_FILE).unwrap_or_default();
                let (_, text) = self.placed(|n| format!("{index}{}\n", line(n)));
                std::fs::write(self.devices[*d].mem.join(INDEX_FILE), text).unwrap();
            }
            Step::Unlist(d, name) => {
                if let Some(index) = self.read(*d, INDEX_FILE) {
                    let kept: String = index
                        .lines()
                        .filter(|line| lines::line_for(line) != Some(*name))
                        .map(|line| format!("{line}\n"))
                        .collect();
                    let path = self.devices[*d].mem.join(INDEX_FILE);
                    std::fs::write(path, kept).unwrap();
                }
            }
            Step::Minute(d) => {
                for _ in 0..13 {
                    self.now += 5;
                    self.cycle(*d);
                }
            }
            Step::Cycle(d) => self.cycle(*d),
            Step::Pass(from, to) => self.send(*from, *to, None),
            Step::PassOne(from, to, name) => self.send(*from, *to, Some(name)),
            Step::AsBefore(d) => self.devices[*d].kind = Kind::Before,
            Step::Remove(by, who) => {
                if self.change(*by, Some(*who)) {
                    for d in self.remaining() {
                        self.hear(d);
                    }
                }
            }
            Step::RemoveUnheard(by, who) => {
                self.change(*by, Some(*who));
            }
            Step::Renew(by) => {
                self.change(*by, None);
            }
            Step::Hear(d) => self.hear(*d),
            Step::DropCopy(d) => {
                if let Some(copy) = self.first_copy(*d) {
                    self.put(*d, &copy, None);
                }
            }
            Step::EditCopy(d) => {
                if let Some(copy) = self.first_copy(*d) {
                    let (_, text) =
                        self.placed(|n| format!("{copy}, written on {d} at step {at} ({n})\n"));
                    self.wrote.insert((root_of(&copy), text.clone()));
                    self.put(*d, &copy, Some(&text));
                }
            }
            Step::MergeCopy(d) => {
                if let Some(copy) = self.first_copy(*d) {
                    let root = root_of(&copy);
                    let kept = self.read(*d, &copy).unwrap();
                    let held = self.read(*d, &root).unwrap_or_default();
                    // With a line of its own: a text that no other step
                    // writes, like every other.
                    let line = |n: u32| format!("- merged on {d} at step {at} ({n})");
                    let (n, both) = self.placed(|n| format!("{held}{kept}{}\n", line(n)));
                    let mem = self.devices[*d].mem.clone();
                    if root == INDEX_FILE {
                        // Every line of the index and of the copy is in
                        // the index afterwards, with one more: nothing is
                        // let go of, and the new line is one to look for.
                        self.lines.insert(line(n));
                        std::fs::write(mem.join(&root), both).unwrap();
                        std::fs::remove_file(mem.join(&copy)).unwrap();
                    } else {
                        self.wrote.insert((root.clone(), both.clone()));
                        self.put(*d, &root, Some(&both));
                        self.put(*d, &copy, None);
                    }
                }
            }
        }
        self.note_held(step.on());
    }

    /// Write down what the device's folder holds now: each text, by the
    /// file it is a text of, and each line of an index or of a copy of
    /// one. A text is looked for at the end where a device that is still
    /// the person's has held it ([`World::lost`]).
    fn note_held(&mut self, d: usize) {
        for name in self.names(d) {
            let text = self.read(d, &name).unwrap();
            let root = root_of(&name);
            let device = &mut self.devices[d];
            if root == INDEX_FILE {
                device.held_lines.extend(text.lines().map(String::from));
            }
            device.held.insert((root, text));
        }
    }

    /// The device is shown the latest change entry, where it keeps
    /// another, through the one door for an entry from outside and as the
    /// node applies a change: it waits for no cycle here, and counts as a
    /// change of settings. The device applies the change and carries
    /// what it holds, or, where the change removes it, stops. A device
    /// that has stopped is shown nothing more.
    fn hear(&mut self, d: usize) {
        if self.stopped(d) {
            return;
        }
        let st = &self.devices[d].st;
        let kept = {
            let db = st.db.lock().unwrap();
            let kept = held_rows::change_entry(&db, held_rows::Kept::Latest);
            kept.unwrap().unwrap().id()
        };
        if kept == self.change.id() {
            return;
        }
        let (change, now) = (&self.change, self.now);
        let taken = st
            .as_a_change(|db| take::take(db, &st.identity, change, now))
            .unwrap();
        match taken {
            take::Taken::Shown(person::Shown::Applied(applied)) => {
                let all = applied.no_version.is_empty() && applied.not_carried.is_empty();
                assert!(all, "device {d}: {applied:?}");
                self.carried_by(d);
            }
            take::Taken::Shown(person::Shown::Removed) => {
                assert!(self.removed.contains_key(&d), "device {d} has stopped");
            }
            other => panic!("device {d} was shown the change: {other:?}"),
        }
    }

    /// The device makes a change with the phrase, which removes the
    /// device `gone` or, with none, nobody; applies it, as the node does
    /// for the command that made it; and carries what it holds. It is
    /// shown the latest change first, as that command is. Says whether a
    /// change was made: none is made on a device that has stopped, and no
    /// device is removed twice, or by itself.
    fn change(&mut self, by: usize, gone: Option<usize>) -> bool {
        self.hear(by);
        let cannot = |who: usize| who == by || self.removed.contains_key(&who);
        if self.stopped(by) || gone.is_some_and(cannot) {
            return false;
        }
        let st = &self.devices[by].st;
        let gone_key = gone.map(|who| self.key(who));
        let (entry, over) = {
            let db = st.db.lock().unwrap();
            let held = person::held(&db).unwrap().unwrap();
            let latest = held_rows::change_entry(&db, held_rows::Kept::Latest);
            let latest = latest.unwrap().unwrap().check().unwrap();
            let stay = person::who_counts(&db)
                .unwrap()
                .keys()
                .into_iter()
                .filter(|key| Some(*key) != gone_key)
                .map(|key| cordelia_crypto::statement::Device::new(key, "device").unwrap())
                .collect();
            let removed: Vec<[u8; 32]> = gone_key.into_iter().collect();
            let own = st.identity.public_key();
            let entry =
                change::make_change(&self.phrase, &held.statement, &latest, &own, stay, &removed);
            (entry.unwrap(), latest.id())
        };
        let now = self.now;
        let applied = st
            .as_a_change(|db| person::apply_made(db, &st.identity, &entry, &over, None, now))
            .unwrap();
        let all = applied.no_version.is_empty() && applied.not_carried.is_empty();
        assert!(all, "device {by}: {applied:?}");
        if let Some(who) = gone {
            self.removed.insert(who, applied.number);
        }
        self.change = entry;
        self.carried_by(by);
        true
    }

    /// The device has just applied a change: what it holds of the name's
    /// channel now is what it carried, each version in one entry of its
    /// own.
    fn carried_by(&mut self, d: usize) {
        let slots = self.slots(d);
        let mut carried = BTreeMap::new();
        for version in slots.iter().filter_map(|slot| slot.current.as_ref()) {
            self.carried
                .extend(version.entries.iter().map(|one| one.id));
            let held = (version.rev, publish::value_hash(&version.value));
            carried.insert(version.name.clone(), held);
        }
        let device = &mut self.devices[d];
        device.carried = carried;
        device.moved = true;
    }

    /// What `from` holds reaches `to`: all of it, or its entries for one
    /// file. Each goes through the one door for an entry from outside. An
    /// entry that is no newer than what `to` holds from the same device in
    /// that slot is not given: the store would not take it.
    ///
    /// An entry is taken where the two are in one generation, and refused
    /// otherwise: what a device that has not been shown a change holds is
    /// of a channel that the others have left, and what they hold is of
    /// one it does not have. So what a removed device writes is refused
    /// by every device that has applied its removal.
    fn send(&mut self, from: usize, to: usize, only: Option<&str>) {
        let slot = only.map(|name| {
            let slot_key = derive::slot_key(&self.secret(from)).unwrap();
            cordelia_crypto::slots::slot_id(&slot_key, name)
        });
        let entries = self.held(from);
        let together = self.number(from) == self.number(to) && !self.stopped(to);
        let device = &self.devices[to];
        let db = device.st.db.lock().unwrap();
        let channel = derive::channel_id(&self.secret(from)).unwrap();
        let theirs = stored::channel_entries_after(&db, &channel, 0, 100_000).unwrap();
        let holds = |entry: &CheckedEntry| {
            let mut theirs = theirs.iter().map(|held| &held.entry);
            theirs.any(|held| {
                held.slot == entry.slot && held.author == entry.author && held.rev >= entry.rev
            })
        };
        for entry in &entries {
            if slot.is_some_and(|slot| entry.slot != slot) || holds(entry) {
                continue;
            }
            let taken = take::take(&db, &device.st.identity, entry, self.now).unwrap();
            let refused = matches!(taken, take::Taken::Refused(_));
            assert_eq!(refused, !together, "from {from} to {to}: {taken:?}");
        }
    }

    /// One cycle of the device's folder, held to each of the five cases
    /// that it meets. A device that has stopped runs none: its folder is
    /// left as it is.
    fn cycle(&mut self, d: usize) {
        if self.stopped(d) {
            return;
        }
        let channel = self.channel(d);
        let met = self.meets(d, &channel);
        let device = &self.devices[d];
        let tag = hex::encode(&device.st.identity.public_key()[..4]);
        let hooks = Hooks {
            plan: match device.kind {
                Kind::Built | Kind::Lineless => plan::plan,
                Kind::Before => plan_before,
            },
            listed: &|| {},
            between: &|| {},
            flushed: &|_| {},
            // A device that plans by revision alone has no record of its
            // lines either.
            lines: device.kind == Kind::Built,
            before_hold: &|| {},
        };
        device.st.sync_control.set_now(Some(self.now));
        let (records, counted) = self.line_records(d);
        let generation = device.st.sync_control.generation();
        let report = sync_folder_with(
            &device.st,
            &device.mem,
            &channel,
            NAME,
            &tag,
            generation,
            &hooks,
        )
        .unwrap();
        assert!(
            report.failed.is_empty() && report.error.is_none() && !report.stopped,
            "{report:?}"
        );
        // A cycle that put lines back counted each record that was due in
        // it. (A third time takes the record with it, and is not seen
        // here: nothing that reads the count needs it to be.)
        let (records_now, counted_now) = self.line_records(d);
        self.put_back += counted_now.saturating_sub(counted);
        // While the device has a record of a line, a cycle may put the
        // line back: an edit of the index that the cycle makes itself.
        self.held_to(d, met, records + records_now > 0);
        self.devices[d].moved = false;
        if report.published > 0 {
            self.note_ties(d);
        }
    }

    /// How many records of index lines the device has, and how many
    /// times they say their lines were put back.
    fn line_records(&self, d: usize) -> (u64, u64) {
        let db = self.devices[d].st.db.lock().unwrap();
        db.query_row(
            "SELECT COUNT(*), COALESCE(SUM(put_back), 0) FROM index_lines",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
    }

    /// For each version that the device has published and that has not
    /// been looked at: where another device holds another version of the
    /// file at that revision, the two tie, and which of them wins is
    /// written down.
    fn note_ties(&mut self, d: usize) {
        let own = self.key(d);
        let mut fresh = Vec::new();
        for slot in &self.slots(d) {
            for version in slot.current.iter().chain(&slot.lost) {
                for one in version.entries.iter().filter(|one| one.author == own) {
                    if self.devices[d].looked_at.insert(one.id) {
                        fresh.push(version.clone());
                    }
                }
            }
        }
        for version in fresh {
            let rivals: Vec<Value> = (0..self.devices.len())
                .filter(|other| *other != d)
                .filter_map(|other| self.slot(other, &version.name)?.current)
                .filter(|theirs| theirs.rev == version.rev && theirs.value != version.value)
                .map(|theirs| theirs.value)
                .collect();
            if rivals.is_empty() {
                continue;
            }
            let wins = rivals
                .iter()
                .all(|theirs| rank(&version.value) > rank(theirs));
            self.ties.insert((version.name, wins));
        }
    }

    /// The cases that a cycle of the device is about to meet, of the five
    /// that follow a change (decision 2026-10-04 §7.3), each with what
    /// the device has for the file now. `channel` is the name's channel,
    /// as the device's records are kept by it.
    ///
    /// A case is met for a file whose record in the folder is of the
    /// version that the device carried when it applied the change:
    ///
    /// 1. the file is as its record, the channel holds that version in
    ///    the one entry that the device carried, and this is the device's
    ///    first cycle since it applied;
    /// 2. the file is as its record, and the channel's version is another
    ///    at a higher revision;
    /// 3. the file is not as its record, the channel's version is the one
    ///    carried, and this is the device's first cycle since it applied;
    /// 4. the file is as its record, and the channel holds that version
    ///    in two entries that devices carried, or more;
    /// 5. the file is as its record, and the channel's version is another
    ///    at that revision, which a device carried: the one that this
    ///    device carried lost the tie.
    fn meets(&self, d: usize, channel: &str) -> Vec<Met> {
        let device = &self.devices[d];
        if device.carried.is_empty() {
            return Vec::new();
        }
        let own = self.key(d);
        let (slots, counting) = (self.slots(d), self.counting(d));
        let agreed = {
            let db = device.st.db.lock().unwrap();
            let folder = device.mem.display().to_string();
            sync_state::load(&db, &folder, channel).unwrap()
        };
        let carried = |version: &Version| -> usize {
            let entries = version.entries.iter();
            entries.filter(|one| self.carried.contains(&one.id)).count()
        };
        let mut met = Vec::new();
        let mut copies = None;
        for slot in &slots {
            let Some(version) = &slot.current else {
                continue;
            };
            let file = &version.name;
            let (Some(a), Some(held)) = (agreed.get(file), device.carried.get(file)) else {
                continue;
            };
            let agreed_hash = a.hash.unwrap_or([0u8; 32]);
            if (a.rev, agreed_hash) != *held {
                continue;
            }
            let local = self.read(d, file);
            let as_record = local.as_ref().map(|text| Content::new(text.as_str()).hash) == a.hash;
            let same = publish::value_hash(&version.value) == agreed_hash;
            let lost_here = slot.lost.iter().any(|lost| {
                let mut entries = lost.entries.iter();
                entries.any(|one| one.author == own && self.carried.contains(&one.id))
            });
            let case = if version.rev == a.rev && same {
                match as_record {
                    true if carried(version) >= 2 => 3,
                    true if device.moved && version.entries.len() == 1 && carried(version) == 1 => {
                        0
                    }
                    false if device.moved => 2,
                    _ => continue,
                }
            } else if version.rev > a.rev && !same && as_record {
                1
            } else if version.rev == a.rev && as_record && carried(version) >= 1 && lost_here {
                4
            } else {
                continue;
            };
            let copies = copies.get_or_insert_with(|| self.has(d).copies);
            met.push(Met {
                case,
                file: file.clone(),
                local,
                version: version.clone(),
                planned: PlannedAgainst::what_is_in(slot),
                known: publish::follows(version, &agreed_hash, &counting),
                copies: copies.clone(),
            });
        }
        met
    }

    /// The cycle of the device that met these cases has run: each is
    /// counted, and the device is held to what the plan does in it.
    /// `lines` says that the cycle may have put index lines back, which
    /// is an edit of the index that the cycle makes itself: the index is
    /// then held to nothing.
    fn held_to(&mut self, d: usize, met: Vec<Met>, lines: bool) {
        if met.is_empty() {
            return;
        }
        let own = self.key(d);
        let kind = self.devices[d].kind;
        let has = self.has(d);
        for met in met {
            self.reached[met.case] += 1;
            let file = &met.file;
            if file == INDEX_FILE && lines {
                continue;
            }
            let at = format!(
                "case {} for {file} on device {d} ({kind:?}), step {}",
                met.case + 1,
                self.step
            );
            let slot = self
                .slot(d, file)
                .expect("a slot that held a version holds one");
            let now = self.read(d, file);
            let root = root_of(file);
            let kept = |text: &String| has.copies.contains(&(root.clone(), text.clone()));
            let kept_now =
                |text: &String| kept(text) && !met.copies.contains(&(root.clone(), text.clone()));
            let theirs = match &met.version.value {
                Value::Text(text) => Some(text.clone()),
                _ => None,
            };
            match met.case {
                // Nothing: the file is as it was, nothing was published,
                // and nothing was kept beside it.
                0 | 3 => {
                    assert_eq!(now, met.local, "the file: {at}");
                    let planned = PlannedAgainst::what_is_in(&slot);
                    assert_eq!(planned, met.planned, "the channel: {at}");
                    assert!(!met.local.iter().any(kept_now), "a copy: {at}");
                }
                // The file takes the channel's version. Nothing is kept
                // where that version is known to follow, and what the
                // file held is kept where it is not.
                1 => {
                    assert_eq!(now, theirs, "the file: {at}");
                    if kind != Kind::Before {
                        match (&met.local, met.known) {
                            (Some(text), true) => assert!(!kept_now(text), "a copy: {at}"),
                            (Some(text), false) => assert!(kept(text), "no copy: {at}"),
                            (None, _) => {}
                        }
                    }
                }
                // The edit is published over the version that the device
                // carried: its chain names that version first, as this
                // device signed it.
                2 => {
                    let version = slot.current.expect("a version");
                    let edit = met.local.clone().map_or(Value::Delete, Value::Text);
                    assert_eq!(version.value, edit, "the channel: {at}");
                    let entry = version.entries.iter().find(|one| one.author == own);
                    let chain = entry.and_then(|one| one.chain.clone()).expect("its chain");
                    let over = Link::of(&met.version.value, own);
                    assert_eq!(chain.first(), Some(&over), "the chain: {at}");
                }
                // The file takes the version that won the tie, and the
                // text that lost is kept beside it. (The index is merged
                // instead: its lines are looked for at the end.)
                _ => {
                    if file != INDEX_FILE {
                        assert_eq!(now, theirs, "the file: {at}");
                        assert!(met.local.iter().all(kept), "no copy: {at}");
                    }
                }
            }
        }
    }

    /// What the device has now.
    fn has(&self, d: usize) -> Has {
        let device = &self.devices[d];
        let mut files = BTreeMap::new();
        let mut copies = BTreeSet::new();
        for name in self.names(d) {
            let text = self.read(d, &name).unwrap();
            if names::is_conflict_name(&name) {
                copies.insert((root_of(&name), text));
            } else {
                files.insert(name, text);
            }
        }
        let channel_id = self.channel(d);
        let channel = self
            .slots(d)
            .into_iter()
            .filter_map(|slot| slot.current)
            .filter(|version| !names::is_conflict_name(&version.name))
            .map(|version| {
                let text = match version.value {
                    Value::Text(text) => Some(text),
                    _ => None,
                };
                (version.name, (version.rev, text))
            })
            .collect();
        let db = device.st.db.lock().unwrap();
        let folder = device.mem.display().to_string();
        let records = sync_state::load(&db, &folder, &channel_id)
            .unwrap()
            .into_iter()
            .filter(|(name, _)| !names::is_conflict_name(name))
            .map(|(name, agreed)| (name, (agreed.hash, agreed.rev)))
            .collect();
        Has {
            files,
            channel,
            records,
            copies,
        }
    }

    /// Everything about a device that a step can change: its files, the
    /// statement it has applied, the entries it holds, and what its
    /// folder has recorded.
    fn whole(&self, d: usize) -> impl PartialEq + use<> {
        let files: Vec<(String, String)> = self
            .names(d)
            .into_iter()
            .map(|name| {
                let text = self.read(d, &name).unwrap();
                (name, text)
            })
            .collect();
        let mut held: Vec<[u8; 32]> = self.held(d).iter().map(|entry| entry.id()).collect();
        held.sort();
        let channel = self.channel(d);
        let db = self.devices[d].st.db.lock().unwrap();
        let folder = self.devices[d].mem.display().to_string();
        let mut records: Vec<(String, Agreed)> = sync_state::load(&db, &folder, &channel)
            .unwrap()
            .into_iter()
            .collect();
        records.sort_by(|a, b| a.0.cmp(&b.0));
        (files, channel, held, records)
    }

    /// What the device's folder has recorded for a file, if anything.
    fn record_of(&self, d: usize, name: &str) -> Option<Agreed> {
        let channel = self.channel(d);
        let device = &self.devices[d];
        let db = device.st.db.lock().unwrap();
        let folder = device.mem.display().to_string();
        sync_state::load(&db, &folder, &channel)
            .unwrap()
            .remove(name)
    }

    /// The devices that are still the person's.
    fn remaining(&self) -> Vec<usize> {
        (0..self.devices.len())
            .filter(|d| !self.removed.contains_key(d))
            .collect()
    }

    /// Every device that remains is shown the latest change, gets
    /// everything the others hold, and runs cycles, until nothing changes
    /// anywhere.
    fn rest(&mut self) {
        let devices = self.remaining();
        for _ in 0..20 {
            let before: Vec<_> = devices.iter().map(|d| self.whole(*d)).collect();
            for d in &devices {
                self.run(&Step::Hear(*d));
            }
            for from in &devices {
                for to in &devices {
                    if from != to {
                        self.run(&Step::Pass(*from, *to));
                    }
                }
            }
            for d in &devices {
                self.run(&Step::Cycle(*d));
            }
            let after: Vec<_> = devices.iter().map(|d| self.whole(*d)).collect();
            if after == before {
                return;
            }
        }
        panic!("the devices did not come to rest");
    }

    /// The texts that a step wrote and that the folder of no device that
    /// remains has ever held: what was gone with a removed device.
    fn gone_with_a_device(&self) -> Vec<&(String, String)> {
        let remaining = self.remaining();
        let held = |text: &(String, String)| {
            let mut folders = remaining.iter().map(|d| &self.devices[*d].held);
            folders.any(|held| held.contains(text))
        };
        self.wrote.iter().filter(|text| !held(text)).collect()
    }

    /// The texts and index lines that a step wrote, that the folder of a
    /// device which remains has held, and that are now in no file on any
    /// such device, though no step edited or deleted a file while it held
    /// them. A removed device's folder is gone with it.
    fn lost(&self) -> Vec<String> {
        let mut in_a_file: BTreeSet<(String, String)> = BTreeSet::new();
        let mut index_lines: BTreeSet<String> = BTreeSet::new();
        let mut note = |root: String, text: String| {
            if root == INDEX_FILE {
                index_lines.extend(text.lines().map(String::from));
            }
            in_a_file.insert((root, text));
        };
        let remaining = self.remaining();
        for d in &remaining {
            let has = self.has(*d);
            for (name, text) in has.files {
                note(name, text);
            }
            for (root, text) in has.copies {
                note(root, text);
            }
        }
        let gone = self.gone_with_a_device();
        let held_line = |line: &String| {
            let mut folders = remaining.iter().map(|d| &self.devices[*d].held_lines);
            folders.any(|held| held.contains(line))
        };
        let mut lost: Vec<String> = self
            .wrote
            .iter()
            .filter(|text| !gone.contains(text))
            .filter(|text| !in_a_file.contains(*text) && !self.let_go.contains(*text))
            .map(|(root, text)| format!("{root}: {text:?}"))
            .collect();
        lost.extend(
            self.lines
                .iter()
                .filter(|line| held_line(line))
                .filter(|line| !index_lines.contains(*line) && !self.let_go_lines.contains(*line))
                .map(|line| format!("{INDEX_FILE}: the line {line:?}")),
        );
        lost
    }
}

/// Run `steps` on devices of `kinds`, and say what each device has after
/// each step, with the device's number: each device that remains, since
/// one that was removed is no longer the person's. With the world as the
/// steps left it.
fn ran(kinds: &[Kind], seed: u64, steps: &[Step]) -> (Vec<Vec<(usize, Has)>>, World) {
    let mut world = World::new(kinds, seed);
    let had = steps
        .iter()
        .map(|step| {
            world.run(step);
            let devices = world.remaining();
            devices.into_iter().map(|d| (d, world.has(d))).collect()
        })
        .collect();
    (had, world)
}

/// [`ran`], without the world.
fn run(kinds: &[Kind], seed: u64, steps: &[Step]) -> Vec<Vec<(usize, Has)>> {
    ran(kinds, seed, steps).0
}

/// Every device hears from every other and runs a cycle, twice over: what
/// a quiet minute does.
fn sync(n: usize) -> Vec<Step> {
    let mut steps = Vec::new();
    for _ in 0..2 {
        for from in 0..n {
            for to in 0..n {
                if from != to {
                    steps.push(Step::Pass(from, to));
                }
            }
        }
        steps.extend((0..n).map(Step::Cycle));
    }
    steps
}

/// Steps from a seed: a small generator, the same on every machine.
struct Dice(u64);

impl Dice {
    fn roll(&mut self, sides: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % sides as u64) as usize
    }

    /// A sequence of `len` steps for `n` devices. With `copies`, some
    /// steps resolve conflict files.
    fn steps(&mut self, n: usize, len: usize, copies: bool) -> Vec<Step> {
        const FILES: [&str; 2] = ["a.md", "b"];
        (0..len)
            .map(|_| {
                let d = self.roll(n);
                let other = (d + 1 + self.roll(n - 1)) % n;
                let file = FILES[self.roll(FILES.len())];
                match self.roll(if copies { 23 } else { 20 }) {
                    0..=3 => Step::Edit(d, file),
                    4..=5 => Step::Line(d),
                    6 => Step::Delete(d, file),
                    7..=12 => Step::Cycle(d),
                    13..=17 => Step::Pass(d, other),
                    18 => Step::PassOne(d, other, file),
                    19 => Step::PassOne(d, other, INDEX_FILE),
                    20 => Step::DropCopy(d),
                    21 => Step::EditCopy(d),
                    _ => Step::MergeCopy(d),
                }
            })
            .collect()
    }
}

use Kind::{Before, Built};
use Step::*;

impl Dice {
    /// The same steps with changes of the person's devices among them:
    /// two renewals, one in each half, and, with three devices or more,
    /// in every other sequence one removal, of which every other device
    /// hears at once or not. Now and then a device is shown the latest
    /// change. So a device applies a change with whatever it holds then:
    /// a file as its record, an edit not yet published, a version that
    /// another device has too, or one that ties with another's.
    fn with_changes(&mut self, steps: Vec<Step>, n: usize) -> Vec<Step> {
        let half = steps.len() / 2;
        let renewals = [self.roll(half), half + self.roll(half)];
        let removal = (n >= 3 && self.roll(2) == 0).then(|| self.roll(2 * half));
        let mut all = Vec::new();
        for (i, step) in steps.into_iter().enumerate() {
            if renewals.contains(&i) {
                all.push(Renew(self.roll(n)));
            }
            if removal == Some(i) {
                let by = self.roll(n);
                let who = (by + 1 + self.roll(n - 1)) % n;
                all.push(match self.roll(2) {
                    0 => Remove(by, who),
                    _ => RemoveUnheard(by, who),
                });
            }
            if self.roll(6) == 0 {
                all.push(Hear(self.roll(n)));
            }
            all.push(step);
        }
        all
    }
}

/// Whether the generated sequence of `seed` for `n` devices is one with
/// changes of the person's devices among its steps: every other one is,
/// for each number of devices, and the first of them for an odd number.
fn through_changes(n: usize, seed: u64) -> bool {
    (seed + n as u64).is_multiple_of(2)
}

/// Every device is shown the latest change.
fn heard(n: usize) -> Vec<Step> {
    (0..n).map(Hear).collect()
}

/// How many generated sequences are run for each number of devices:
/// `CORDELIA_SEQUENCES`, or a number that keeps the tests short.
///
/// A device checks both signatures of every entry each time it reads a
/// slot, and in a test build that is most of what a cycle takes. So the
/// number that keeps the tests short is one, and below [`EVERYTHING`]
/// only a part of the written sequences, of their seeds and of the mixes
/// of kinds is run ([`everything`]). `CORDELIA_SEQUENCES=12` runs all of
/// it.
fn sequences() -> u64 {
    std::env::var("CORDELIA_SEQUENCES")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(1)
}

/// The number of generated sequences from which everything is run.
const EVERYTHING: u64 = 12;

/// Whether everything is run: every written sequence, with every seed
/// and every mix of kinds, as well as that many generated ones.
fn everything() -> bool {
    sequences() >= EVERYTHING
}

/// The numbers of devices that generated sequences are made for: two,
/// three and four, and two and three where not everything is run.
fn devices() -> std::ops::RangeInclusive<usize> {
    match everything() {
        true => 2..=4,
        false => 2..=3,
    }
}

/// The seeds that a written sequence is run with: 2 and 3, which decide
/// every tie between two texts that steps wrote the two ways round. One
/// of the two, by the sequence's name, where not everything is run.
fn seeds_of(name: &str) -> Vec<u64> {
    match everything() {
        true => vec![2, 3],
        false => vec![2 + u64::from(cordelia_crypto::sha256(name.as_bytes())[0] & 1)],
    }
}

/// What a world was once everything in it had met.
struct AtRest {
    /// What each device that remained had.
    has: Vec<(usize, Has)>,
    /// What was lost ([`World::lost`]).
    lost: Vec<String>,
    /// How many texts were gone with a removed device
    /// ([`World::gone_with_a_device`]).
    gone: usize,
    /// Each tie that a publish had made by then.
    ties: BTreeSet<(String, bool)>,
    /// How many times a cycle had put index lines back by then.
    put_back: u64,
    /// Each file that a step had deleted on some device.
    deleted: BTreeSet<String>,
    /// Every line of an index on a device that remained.
    listed: BTreeSet<String>,
    /// Every line of an index, or of a copy of one, on such a device.
    listed_or_kept: BTreeSet<String>,
    /// For each device that remained, the files that were back and not
    /// listed ([`World::unlisted`]). It is read only once the lines are
    /// settled, and is empty before.
    unlisted: Vec<(usize, Vec<String>)>,
}

impl AtRest {
    fn of(world: &World, settled: bool) -> Self {
        let remaining = world.remaining();
        Self {
            has: remaining.iter().map(|d| (*d, world.has(*d))).collect(),
            lost: world.lost(),
            gone: world.gone_with_a_device().len(),
            ties: world.ties.clone(),
            put_back: world.put_back,
            deleted: world.deleted.clone(),
            listed: world.lines_listed(false),
            listed_or_kept: world.lines_listed(true),
            unlisted: match settled {
                true => remaining.iter().map(|d| (*d, world.unlisted(*d))).collect(),
                false => Vec::new(),
            },
        }
    }
}

/// How far a world is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Until {
    /// To the end of its steps.
    Steps,
    /// And then until everything has met ([`World::rest`]).
    Met,
    /// And then until no index line goes back ([`World::settle_lines`]).
    Settled,
}

/// What a world came to over a sequence of steps.
struct Came {
    /// What each device that remained had after each step, with the
    /// device's number.
    had: Vec<Vec<(usize, Has)>>,
    /// How many times a cycle had met each of the five cases of what the
    /// plan does after a change, by the end of the steps.
    reached: [usize; 5],
    /// What the world was once everything had met, where it was taken
    /// that far.
    met: Option<AtRest>,
    /// What it was once no index line went back any more, where it was
    /// taken that far.
    settled: Option<AtRest>,
}

impl Came {
    fn of(kinds: &[Kind], seed: u64, steps: &[Step], until: Until) -> Self {
        let (had, mut world) = ran(kinds, seed, steps);
        let reached = world.reached;
        let mut came = Self {
            had,
            reached,
            met: None,
            settled: None,
        };
        if until != Until::Steps {
            world.rest();
            came.met = Some(AtRest::of(&world, false));
        }
        if until == Until::Settled {
            world.settle_lines();
            came.settled = Some(AtRest::of(&world, true));
        }
        came
    }

    /// The world once everything had met.
    fn met(&self) -> &AtRest {
        self.met.as_ref().expect("a world taken until all had met")
    }

    /// The world once no index line went back any more.
    fn settled(&self) -> &AtRest {
        let settled = self.settled.as_ref();
        settled.expect("a world taken until its lines were settled")
    }
}

/// What a world of devices of `kinds` came to over the written sequence
/// `name`, with `seed`. It is run once, whichever tests ask and however
/// many: a written sequence is asked about by several tests, and one run
/// answers them all. (`name` stands for the steps: no two written
/// sequences share a name.)
fn came(name: &str, kinds: &[Kind], seed: u64, steps: &[Step], until: Until) -> Arc<Came> {
    type Run = Arc<std::sync::OnceLock<Arc<Came>>>;
    static RUNS: Mutex<BTreeMap<String, Run>> = Mutex::new(BTreeMap::new());
    let key = format!("{name}: {kinds:?}, seed {seed}, {until:?}");
    let run = {
        let mut runs = RUNS.lock().unwrap_or_else(|e| e.into_inner());
        Arc::clone(runs.entry(key).or_default())
    };
    Arc::clone(run.get_or_init(|| Arc::new(Came::of(kinds, seed, steps, until))))
}

/// [`came`], for a world of `n` devices of one kind, taken until
/// everything has met: what the tests of the rule ask about.
fn all(kind: Kind, name: &str, n: usize, seed: u64, steps: &[Step]) -> Arc<Came> {
    came(name, &vec![kind; n], seed, steps, Until::Met)
}

/// A run with every device as built, and local history on or off: what
/// each device has after each step, and how many records were kept.
fn run_with_history(n: usize, seed: u64, steps: &[Step], on: bool) -> (Vec<Vec<Has>>, usize) {
    let mut world = World::new(&vec![Kind::Built; n], seed);
    if on {
        for device in &world.devices {
            let store = cordelia_storage::history::Store::new(&device.st.home_dir, 30, 1 << 30);
            device.st.history.open(store);
        }
    }
    let had = steps
        .iter()
        .map(|step| {
            world.run(step);
            (0..n).map(|d| world.has(d)).collect()
        })
        .collect();
    let kept = world
        .devices
        .iter()
        .filter_map(|device| device.st.history.store())
        .map(|store| store.list().unwrap().records.len())
        .sum();
    (had, kept)
}

/// Local history changes nothing in what sync does. Each written
/// sequence, and some generated ones, are run with every device as built,
/// once with history off and once with it on: after every step every
/// device has the same files, the same conflict files, the same versions
/// of the channel's and the same records. And with history on texts are
/// kept, so that the two runs are not the same for having done nothing.
/// (Where not everything is run: three of the written sequences, and one
/// generated sequence.)
#[test]
fn local_history_changes_nothing_in_what_sync_does() {
    let mut sequences = all_written();
    let mut devices = devices();
    if !everything() {
        let asked = [
            "the index overtaken",
            NOT_YET_PUBLISHED,
            TWO_AT_ONE_REVISION,
        ];
        sequences.retain(|(name, ..)| asked.contains(&name.as_str()));
        devices = 3..=3;
    }
    for n in devices {
        for seed in 1..=self::sequences().min(3) {
            let mut dice = Dice(seed * 7919 + n as u64);
            let mut steps = dice.steps(n, 60, true);
            // Every other one with changes of the person's devices.
            if through_changes(n, seed) {
                steps = dice.with_changes(steps, n);
                steps.extend(heard(n));
            }
            steps.extend(sync(n));
            sequences.push((format!("generated, {n} devices, seed {seed}"), n, steps));
        }
    }
    for (name, n, steps) in sequences {
        for seed in seeds_of(&name) {
            let (off, none) = run_with_history(n, seed, &steps, false);
            let (on, kept) = run_with_history(n, seed, &steps, true);
            assert_eq!(none, 0, "{name}");
            assert!(kept > 0, "{name}, seed {seed}: nothing was kept");
            for (i, (off, on)) in off.iter().zip(&on).enumerate() {
                assert_eq!(off, on, "{name}, seed {seed}, after step {i}");
            }
        }
    }
}

/// The property, for one sequence: run with every device as before
/// (`before`), and with devices of `kinds` (`built`), it leaves every
/// device that remains, after every step, with the same files that are
/// not conflict files, the same versions in the channel and the same
/// records. Every conflict file of the first run is in the second.
/// Returns whether the second run ends with conflict files that the first
/// does not have: whether the rule made a difference.
fn compared(
    before: &[Vec<(usize, Has)>],
    built: &[Vec<(usize, Has)>],
    kinds: &[Kind],
    seed: u64,
    steps: &[Step],
) -> bool {
    assert_eq!(before.len(), built.len(), "the steps");
    for (i, (was, is)) in before.iter().zip(built).enumerate() {
        assert_eq!(was.len(), is.len(), "the devices that remain, step {i}");
        for ((d, was), (same, is)) in was.iter().zip(is) {
            assert_eq!(d, same, "the devices that remain, step {i}");
            let at = format!(
                "seed {seed}, kinds {kinds:?}, device {d}, after step {i} ({:?}) of {steps:?}",
                steps[i]
            );
            assert_eq!(was.files, is.files, "files: {at}");
            assert_eq!(was.channel, is.channel, "the channel: {at}");
            assert_eq!(was.records, is.records, "records: {at}");
            assert!(was.copies.is_subset(&is.copies), "conflict files: {at}");
        }
    }
    let copies =
        |last: &[(usize, Has)]| -> usize { last.iter().map(|(_, has)| has.copies.len()).sum() };
    copies(built.last().unwrap()) > copies(before.last().unwrap())
}

/// The mixes of devices as built and as before that a written sequence
/// for `n` devices is run with, each as the bits of a number, besides
/// every device as built: every other mix with a device as built, where
/// everything is run. Otherwise one, and none for four devices: every
/// other device as built, the first of them with one seed and the second
/// with the next.
fn mixes(n: usize, seed: u64) -> Vec<u32> {
    let all = (1u32 << n) - 1;
    if everything() {
        return (1..all).collect();
    }
    let every_other = match seed % 2 {
        0 => 0b0101 & all,
        _ => 0b1010 & all,
    };
    match n {
        4 => Vec::new(),
        _ => vec![every_other],
    }
}

/// The kinds of `n` devices in a mix: as built where its bit is set.
fn kinds_of(n: usize, mix: u32) -> Vec<Kind> {
    (0..n)
        .map(|d| if mix & (1 << d) != 0 { Built } else { Before })
        .collect()
}

/// The names of the written sequences that are left out where not
/// everything is run: each varies another, and takes as long as it.
const VARIANTS: [&str; 4] = [
    "a text overtaken by a delete",
    "a file with no extension",
    "a change heard late, a delete",
    "a change heard late, the index",
];

/// The written sequences: each makes the rule fire, and then goes on.
fn written() -> Vec<(&'static str, usize, Vec<Step>)> {
    let agreed = |n: usize, file: &'static str| {
        let mut steps = vec![Edit(0, file), Line(0), Cycle(0)];
        steps.extend(sync(n));
        steps
    };
    // One edit on device 1 against two on device 0, with device 2 holding
    // device 1's edit and device 3 behind. Then everything meets.
    let overtaken = |file: &'static str, second: Step| {
        let mut steps = agreed(4, file);
        steps.extend([Edit(1, file), Cycle(1), Pass(1, 2), Cycle(2)]);
        steps.extend([Edit(0, file), Cycle(0), second, Cycle(0)]);
        steps.extend([Pass(0, 1), Cycle(1), Pass(0, 2), Cycle(2)]);
        steps.extend(sync(4));
        // And it goes on: a tie, and an edit not yet published when the
        // other device's arrives.
        steps.extend([Edit(0, file), Edit(1, file), Cycle(0), Cycle(1)]);
        steps.extend(sync(4));
        steps.extend([Edit(2, file), Cycle(2), Edit(3, file), Pass(2, 3), Cycle(3)]);
        steps.extend(sync(4));
        steps
    };
    let mut index = agreed(3, "a.md");
    index.extend([Line(1), Cycle(1), Pass(1, 2), Cycle(2)]);
    index.extend([Line(0), Cycle(0), Line(0), Cycle(0)]);
    index.extend([Pass(0, 1), Cycle(1), Pass(0, 2), Cycle(2)]);
    index.extend(sync(3));
    index.extend([Line(0), Line(1), Cycle(0), Cycle(1)]);
    index.extend(sync(3));
    index.extend([Line(2), Cycle(2), Line(1), Pass(2, 1), Cycle(1)]);
    index.extend(sync(3));

    // A tie between devices 0 and 1, and device 2 writing over one of the
    // two before it has the other.
    let mut tie = agreed(3, "a.md");
    tie.extend([Edit(0, "a.md"), Edit(1, "a.md"), Cycle(0), Cycle(1)]);
    tie.extend([Pass(0, 2), Cycle(2), Edit(2, "a.md"), Cycle(2)]);
    tie.extend([Pass(2, 1), Cycle(1), Pass(1, 0), Pass(2, 0), Cycle(0)]);
    tie.extend(sync(3));

    // A tie between devices 0 and 1 that device 2 holds whole. Device 2
    // takes the one that wins and writes over it, and each of the two
    // then hears of that before anything else: the one whose version lost
    // the tie was not written over.
    let mut whole = agreed(3, "a.md");
    whole.extend([Edit(0, "a.md"), Edit(1, "a.md"), Cycle(0), Cycle(1)]);
    whole.extend([Pass(0, 2), Pass(1, 2), Cycle(2), Edit(2, "a.md"), Cycle(2)]);
    whole.extend([PassOne(2, 0, "a.md"), Cycle(0)]);
    whole.extend([PassOne(2, 1, "a.md"), Cycle(1)]);
    whole.extend(sync(3));

    // A file deleted, and written again while another device still holds
    // the text from before.
    let mut again = agreed(3, "a.md");
    again.extend([Delete(0, "a.md"), Cycle(0), Pass(0, 1), Cycle(1)]);
    again.extend([Edit(1, "a.md"), Cycle(1), Edit(1, "a.md"), Cycle(1)]);
    again.extend([Edit(2, "a.md"), Cycle(2)]);
    again.extend(sync(3));

    let mut all = vec![
        ("a text overtaken", 4, overtaken("a.md", Edit(0, "a.md"))),
        (
            "a text overtaken by a delete",
            4,
            overtaken("a.md", Delete(0, "a.md")),
        ),
        ("a file with no extension", 4, overtaken("b", Edit(0, "b"))),
        ("the index overtaken", 3, index),
        ("a tie beside a higher revision", 3, tie),
        ("a tie written over by a device that holds both", 3, whole),
        ("written again after a delete", 3, again),
    ];
    if !everything() {
        all.retain(|(name, ..)| !VARIANTS.contains(name));
    }
    all
}

/// The names of the written sequences through a change that a test asks
/// more of.
const NOTHING_TO_DO: &str = "a change with nothing to do";
const AHEAD: &str = "the new channel comes to be ahead";
const NOT_YET_PUBLISHED: &str = "an edit not yet published at a change";
const TWO_AT_ONE_REVISION: &str = "two versions at one revision carried";
const HEARD_LATE: &str = "a change heard late";

/// The written sequences through a change of the person's devices: each
/// reaches cases of what the plan does once a device has applied a change
/// and carried (decision 2026-10-04 §7.3), and then goes on. None of them
/// makes the rule fire by itself: a tie is settled alike with the rule
/// and without it.
fn written_through_a_change() -> Vec<(String, usize, Vec<Step>)> {
    let file = "a.md";
    let agreed = || {
        let mut steps = vec![Edit(0, file), Line(0), Cycle(0)];
        steps.extend(sync(2));
        steps
    };
    let goes_on = |mut steps: Vec<Step>| {
        steps.extend(sync(2));
        steps.extend([Edit(1, file), Line(1), Cycle(1)]);
        steps.extend(sync(2));
        steps
    };
    let mut all = Vec::new();

    // Each device has its files as its records when it applies, and runs
    // a cycle before it hears from the other: there is nothing to do.
    // Then the two meet: they carried one version of each file, and
    // there is nothing to do.
    let mut nothing = agreed();
    nothing.extend([Renew(0), Hear(1), Cycle(0), Cycle(1)]);
    all.push((NOTHING_TO_DO.to_string(), 2, goes_on(nothing)));

    // One device edits the file once both have applied, and the other
    // takes the edit: it is known to follow the version that it carried.
    // The index is as both carried it.
    let mut ahead = agreed();
    ahead.extend([Renew(0), Hear(1), Cycle(0)]);
    ahead.extend([Edit(0, file), Cycle(0), Pass(0, 1), Cycle(1)]);
    all.push((AHEAD.to_string(), 2, goes_on(ahead)));

    // A device has edited the file, and the index, and deleted a second
    // file, when it applies the change: each is published over the
    // version that it carried, and the other device takes each.
    let mut edited = vec![Edit(0, file), Edit(0, "b"), Line(0), Cycle(0)];
    edited.extend(sync(2));
    edited.extend([Edit(1, file), Delete(1, "b"), Line(1)]);
    edited.extend([Renew(0), Hear(1), Cycle(1), Pass(1, 0), Cycle(0)]);
    all.push((NOT_YET_PUBLISHED.to_string(), 2, goes_on(edited)));

    // Each device has published an edit of the file, and a line of the
    // index, that the other has not heard of when the two apply: each
    // carries its own, and the two meet as a tie.
    let mut tied = agreed();
    tied.extend([Edit(0, file), Line(0), Cycle(0)]);
    tied.extend([Edit(1, file), Line(1), Cycle(1)]);
    tied.extend([Renew(1), Hear(0), Cycle(0), Cycle(1)]);
    all.push((TWO_AT_ONE_REVISION.to_string(), 2, goes_on(tied)));

    // One device makes a change and edits in the new channel. The other
    // has not heard: what the first passes to it is refused, it goes on
    // in the channel that was left, and what it passes is refused too.
    // When it hears, it carries what it wrote meanwhile.
    let late = |what: Step| {
        let mut steps = agreed();
        steps.extend([Edit(1, file), Cycle(1)]);
        steps.extend(sync(2));
        steps.extend([Renew(0), Edit(0, file), Line(0), Cycle(0)]);
        steps.extend([Pass(0, 1), Cycle(1), what, Cycle(1)]);
        steps.extend([Pass(1, 0), Cycle(0), Hear(1), Cycle(1)]);
        goes_on(steps)
    };
    all.push((format!("{HEARD_LATE}, an edit"), 2, late(Edit(1, file))));
    all.push((format!("{HEARD_LATE}, a delete"), 2, late(Delete(1, file))));
    all.push((format!("{HEARD_LATE}, the index"), 2, late(Line(1))));
    if !everything() {
        all.retain(|(name, ..)| !VARIANTS.contains(&name.as_str()));
    }
    all
}

/// Every written sequence: those that make the rule fire, and those
/// through a change.
fn all_written() -> Vec<(String, usize, Vec<Step>)> {
    let fire = written().into_iter();
    let fire = fire.map(|(name, n, steps)| (name.to_string(), n, steps));
    fire.chain(written_through_a_change()).collect()
}

/// The property, over the written sequences: with every device as built,
/// and with mixes of devices as built and as before ([`mixes`]).
#[test]
fn every_file_is_as_it_was_before_in_the_written_sequences() {
    for (name, n, steps) in all_written() {
        // Each tie both ways: the two seeds decide every tie between two
        // texts that steps wrote the other way from each other.
        for seed in seeds_of(&name) {
            let before = all(Before, &name, n, seed, &steps);
            let built = all(Built, &name, n, seed, &steps);
            compared(&before.had, &built.had, &[Built; 4][..n], seed, &steps);
            for mix in mixes(n, seed) {
                let kinds = kinds_of(n, mix);
                eprintln!("{name}: {kinds:?}, seed {seed}");
                let mixed = came(&name, &kinds, seed, &steps, Until::Steps);
                compared(&before.had, &mixed.had, &kinds, seed, &steps);
            }
        }
    }
}

/// The property, over generated sequences of two, three and four devices
/// ([`devices`]), every other one with changes of the person's devices
/// among its steps. Where everything is run, the rule makes a difference
/// in a good part of them: a generator that stopped reaching it would
/// leave the property true of nothing. And the sequences with changes
/// reach each of the five cases of what the plan does after one.
#[test]
fn every_file_is_as_it_was_before_in_generated_sequences() {
    let (mut run_all, mut fired) = (0, 0);
    let mut reached = [0; 5];
    for n in devices() {
        for seed in 1..=sequences() {
            let mut dice = Dice(seed * 7919 + n as u64);
            let mut steps = dice.steps(n, 60, false);
            if through_changes(n, seed) {
                steps = dice.with_changes(steps, n);
                steps.extend(heard(n));
            }
            steps.extend(sync(n));
            run_all += 1;
            let before = run(&vec![Before; n], seed, &steps);
            let (built, world) = ran(&vec![Built; n], seed, &steps);
            let more = compared(&before, &built, &[Built; 4][..n], seed, &steps);
            fired += usize::from(more);
            for (case, times) in world.reached.iter().enumerate() {
                reached[case] += times;
            }
            // And a mix, chosen by the seed.
            let kinds: Vec<Kind> = (0..n)
                .map(|_| if dice.roll(2) == 0 { Built } else { Before })
                .collect();
            compared(&before, &run(&kinds, seed, &steps), &kinds, seed, &steps);
        }
    }
    eprintln!("the rule fired in {fired} of {run_all}; the five cases were met {reached:?} times");
    if everything() {
        assert!(
            3 * fired >= run_all,
            "the rule fired in {fired} of {run_all}"
        );
        assert!(reached.iter().all(|times| *times > 0), "{reached:?}");
    }
}

/// The written sequences do make the rule fire: each run with every
/// device as built ends with a conflict file that the run with every
/// device as before does not have. Without this the property could hold
/// because nothing happened.
#[test]
fn the_written_sequences_make_the_rule_fire() {
    // From the last: the test of the property asks about the same runs
    // from the first, and each then finds the other's made.
    for (name, n, steps) in written().into_iter().rev() {
        for seed in seeds_of(name) {
            let copies = |kind: Kind| -> usize {
                let came = all(kind, name, n, seed, &steps);
                let last = came.had.last().unwrap();
                last.iter().map(|(_, has)| has.copies.len()).sum()
            };
            assert!(copies(Built) > copies(Before), "{name}, seed {seed}");
        }
    }
}

/// The keep, over the written sequences and generated ones, with steps
/// that resolve conflict files, and in every other generated one with
/// changes of the person's devices: when everything has met, no text an
/// edit wrote is in no file, unless a step let go of it.
#[test]
fn no_text_is_lost_that_nobody_let_go_of() {
    let mut written = all_written();
    // From the middle: see `the_written_sequences_make_the_rule_fire`.
    let middle = written.len() / 2;
    written.rotate_left(middle);
    for (name, n, steps) in written {
        for seed in seeds_of(&name) {
            let came = all(Built, &name, n, seed, &steps);
            let lost = &came.met().lost;
            assert!(lost.is_empty(), "seed {seed}: {lost:?} after {steps:?}");
            // No device is removed in these: every text is looked for.
            assert_eq!(came.met().gone, 0, "{name}");
        }
    }
    for n in devices() {
        for seed in 1..=2 * sequences() {
            let mut dice = Dice(seed * 104_729 + n as u64);
            let mut steps = dice.steps(n, 60, true);
            if through_changes(n, seed) {
                steps = dice.with_changes(steps, n);
            }
            let mut world = World::new(&vec![Built; n], seed);
            for step in &steps {
                world.run(step);
            }
            world.rest();
            let lost = world.lost();
            assert!(lost.is_empty(), "seed {seed}: {lost:?} after {steps:?}");
        }
    }
}

/// Each device that held an entry that is overtaken keeps it, under its
/// own name. Here two devices held it: once everything has met, every
/// device has two conflict files with the one text.
#[test]
fn each_device_that_held_an_overtaken_entry_keeps_it() {
    let mut steps = vec![Edit(0, "a.md"), Cycle(0)];
    steps.extend(sync(3));
    steps.extend([Edit(1, "a.md"), Cycle(1), Pass(1, 2), Cycle(2)]);
    steps.extend([Edit(0, "a.md"), Cycle(0), Edit(0, "a.md"), Cycle(0)]);
    let mut world = World::new(&[Built; 3], 1);
    for step in &steps {
        world.run(step);
    }
    world.rest();
    let tag = |d: usize| hex::encode(&world.devices[d].st.identity.public_key()[..4]);
    let mut expected = vec![
        format!("a.conflict-{}.md", tag(1)),
        format!("a.conflict-{}.md", tag(2)),
    ];
    expected.sort();
    for d in 0..3 {
        let copies: Vec<String> = world
            .names(d)
            .into_iter()
            .filter(|name| names::is_conflict_name(name))
            .collect();
        assert_eq!(copies, expected, "device {d}");
        for copy in &copies {
            let text = world.read(d, copy).unwrap();
            assert!(text.starts_with("a.md, written on 1 at step"), "{text}");
        }
    }
}

/// The steps of [`a_text_is_kept_through_a_removal`]: those up to the
/// cycle in which device 2 meets the version that device 1 carried, and
/// the rest.
fn a_removal_and_then_a_tie() -> (Vec<Step>, Vec<Step>) {
    let mut until = vec![Edit(0, "a.md"), Cycle(0)];
    until.extend(sync(4));
    until.extend([Edit(0, "a.md"), Cycle(0), Pass(0, 2), Cycle(2)]);
    until.extend([Edit(3, "a.md"), Cycle(3)]);
    // Device 1 holds device 0's entry, and has run no cycle since it came.
    until.extend([Pass(0, 1), Remove(1, 0), Pass(1, 2), Cycle(2)]);
    let then = vec![
        Pass(3, 1),
        Cycle(1),
        Edit(1, "a.md"),
        Cycle(1),
        Pass(1, 2),
        Cycle(2),
    ];
    (until, then)
}

/// The steps of [`an_edit_that_tied_with_a_version_carried_at_a_removal_is_kept`].
fn a_tie_and_then_a_removal() -> Vec<Step> {
    let mut steps = vec![Edit(0, "a.md"), Cycle(0)];
    steps.extend(sync(3));
    steps.extend([Edit(0, "a.md"), Cycle(0), Pass(0, 1), Cycle(1)]);
    steps.extend([Edit(2, "a.md"), Cycle(2)]);
    steps.extend([Remove(1, 0), Edit(1, "a.md"), Cycle(1)]);
    steps.extend([Pass(1, 2), Cycle(2)]);
    steps
}

/// A text is kept through a removal. Device 0 writes a text and is then
/// removed by device 1, which never had that text in its folder: it holds
/// the entry, and carries the version into the new channel as an entry
/// of its own, whose chain names device 0's key first. Device 2 holds the
/// text, and carries it too. Device 3 edited the file without it, at the
/// same revision, and carries that.
///
/// Device 3's version reaches device 1 after the removal, and ties there
/// with the version device 1 carried. Where device 3's wins, device 1's
/// file takes device 3's text, and its next edit is written from a folder
/// that never held device 0's text: the chain of that edit does not name
/// it. So the edit is not known to follow device 0's text on device 2,
/// which keeps the text beside the file. Taken by its revision alone, the
/// edit would have replaced the text with nothing kept, and it would have
/// been in no file anywhere. (The tie is between two texts that steps
/// wrote, so it goes the one way with one seed and the other with the
/// next: the sequence is run with two seeds, or with four such pairs.)
#[test]
fn a_text_is_kept_through_a_removal() {
    let (until, then) = a_removal_and_then_a_tie();
    let mut kept = 0;
    let seeds = if everything() { 8 } else { 2 };
    for seed in 0..seeds {
        let mut world = World::new(&[Built; 4], seed);
        for step in &until {
            world.run(step);
        }
        // Devices 1 and 2 each carried the version, and device 2 has met
        // the entry that device 1 carried: the two are one version, and
        // nothing followed. Its record named device 0 as the signer. Now
        // it is of the entry that device 2 carried itself, whose chain
        // names device 0's key for that text first.
        let record = world.record_of(2, "a.md").expect("a record");
        assert_eq!(record.signer, Some(world.key(2)), "{seed}");
        let text = Value::Text(world.read(2, "a.md").unwrap());
        assert!(text.hash() == record.hash, "{seed}");
        let chain = record.chain.expect("the chain of the entry it carried");
        assert_eq!(chain[0], Link::of(&text, world.key(0)), "{seed}");
        let version = world.slot(2, "a.md").unwrap().current.unwrap();
        assert_eq!(version.entries.len(), 2, "{seed}");
        for step in &then {
            world.run(step);
        }
        world.rest();
        let lost = world.lost();
        assert!(lost.is_empty(), "seed {seed}: {lost:?}");
        // Every text that device 0 wrote was in a folder that remains.
        assert!(world.gone_with_a_device().is_empty(), "seed {seed}");
        // Where the removed device's text was overtaken on device 2 by
        // an entry that did not follow it, it is in a copy there.
        let theirs = |text: &String| text.starts_with("a.md, written on 0 at step");
        let copied = world.has(2).copies.iter().any(|(_, text)| theirs(text));
        kept += usize::from(copied);
    }
    assert!(kept > 0, "no seed sent the tie the way this is for");
}

/// An edit that tied with a version which was then carried at a removal
/// is kept. Device 0 writes a text, device 1 takes it, and device 2 edits
/// the file without it: a tie. Device 1 removes device 0, carries device
/// 0's version as its own, and edits the file. The chain of that edit
/// names the version it was written over and those before it, and device
/// 2's own edit is not among them: so the edit is not known to follow
/// device 2's, whose text is kept. Taken by its revision alone, it would
/// have replaced that text with nothing kept. (No tie is read here, so
/// every seed runs alike: two are run, to show that.)
#[test]
fn an_edit_that_tied_with_a_version_carried_at_a_removal_is_kept() {
    let steps = a_tie_and_then_a_removal();
    for seed in 0..2 {
        let mut world = World::new(&[Built; 3], seed);
        for step in &steps {
            world.run(step);
        }
        // Device 2 has device 1's edit in the file, and its own beside it.
        let has = world.has(2);
        let file = &has.files["a.md"];
        assert!(file.starts_with("a.md, written on 1 at step"), "{file}");
        let own = |text: &String| text.starts_with("a.md, written on 2 at step");
        let copies: Vec<&String> = has.copies.iter().map(|(_, text)| text).collect();
        assert!(
            copies.iter().any(|text| own(text)),
            "seed {seed}: {copies:?}"
        );
        world.rest();
        let lost = world.lost();
        assert!(lost.is_empty(), "seed {seed}: {lost:?}");
        assert!(world.gone_with_a_device().is_empty(), "seed {seed}");
    }
}

/// The devices that remain of `n`, once device 0 is removed, hear from
/// each other and run a cycle, twice over: what [`sync`] is for all.
fn sync_the_rest(n: usize) -> Vec<Step> {
    let mut steps = Vec::new();
    for _ in 0..2 {
        for from in 1..n {
            for to in 1..n {
                if from != to {
                    steps.push(Pass(from, to));
                }
            }
        }
        steps.extend((1..n).map(Cycle));
    }
    steps
}

/// The rule changes no file through a removal either. In the two
/// sequences above, each gone on with until the devices that remain have
/// met, with the rule and without it and in mixes of the two, every
/// device that remains has the same files, the same versions in the
/// channel and the same records after every step, and the rule only adds
/// conflict files. With every device as built it does add one, in each of
/// the two, for some seed. (The harness's removal reaches every device
/// that remains at once. Every device writes its entries with their
/// chains, whatever its plan: so the two runs differ wherever a device
/// that holds a text which is overtaken is as built.)
#[test]
fn the_rule_changes_no_file_through_a_removal() {
    let (until, then) = a_removal_and_then_a_tie();
    let mut first: Vec<Step> = until.into_iter().chain(then).collect();
    first.extend(sync_the_rest(4));
    let mut second = a_tie_and_then_a_removal();
    second.extend(sync_the_rest(3));
    let seeds = if everything() { 4 } else { 2 };
    let sequences = [
        ("a removal and then a tie", 4, &first),
        ("a tie and then a removal", 3, &second),
    ];
    for (name, n, steps) in sequences {
        let mut made_a_difference = 0;
        for seed in 0..seeds {
            let before = came(name, &vec![Before; n], seed, steps, Until::Steps);
            let built = came(name, &vec![Built; n], seed, steps, Until::Steps);
            let more = compared(&before.had, &built.had, &[Built; 4][..n], seed, steps);
            made_a_difference += usize::from(more);
            for mix in mixes(n, seed) {
                let kinds = kinds_of(n, mix);
                let mixed = came(name, &kinds, seed, steps, Until::Steps);
                compared(&before.had, &mixed.had, &kinds, seed, steps);
            }
        }
        assert!(made_a_difference > 0, "{n} devices");
    }
}

/// What a removal can cost, on the side of keeping, and what it does not.
///
/// It costs nothing on a device that held the removed device's last
/// version. Device 0 writes a text, every device takes it, and device 0
/// is removed by device 1, which then edits the file once or twice.
/// Device 2 runs no cycle until the edits are there. Its file holds the
/// version that it carried, each edit's chain names that text, and every
/// link that is newer was signed by device 1: nothing is kept.
///
/// It costs a copy on a device that was behind the removed device's last
/// version. Device 0 writes a second text, which device 1 takes and
/// device 2 does not, before it is removed. What device 1 carries, and
/// whatever it writes over that, names device 0 as the signer of a
/// version that is newer than the text device 2 holds: so device 2 keeps
/// that text beside the file, though each version was written from the
/// one before it.
#[test]
fn a_removal_can_cost_a_copy_that_was_not_needed() {
    let theirs = |text: &String| text.starts_with("a.md, written on 0 at step");
    let copies_of_the_removed = |behind: bool, edits: usize| -> usize {
        let mut steps = vec![Edit(0, "a.md"), Cycle(0)];
        steps.extend(sync(3));
        if behind {
            steps.extend([Edit(0, "a.md"), Cycle(0), Pass(0, 1), Cycle(1)]);
        }
        steps.push(Remove(1, 0));
        for _ in 0..edits {
            steps.extend([Edit(1, "a.md"), Cycle(1)]);
        }
        steps.extend([Pass(1, 2), Cycle(2)]);
        let mut world = World::new(&[Built; 3], 0);
        for step in &steps {
            world.run(step);
        }
        let has = world.has(2);
        let by = if edits == 0 { 0 } else { 1 };
        let expected = format!("a.md, written on {by} at step");
        assert!(has.files["a.md"].starts_with(&expected), "{has:?}");
        has.copies.iter().filter(|(_, text)| theirs(text)).count()
    };
    assert_eq!(copies_of_the_removed(false, 1), 0);
    assert_eq!(copies_of_the_removed(false, 2), 0);
    assert_eq!(copies_of_the_removed(true, 0), 1);
    assert_eq!(copies_of_the_removed(true, 1), 1);
}

/// What a removed device writes once the others have applied its removal
/// reaches none of them: each refuses it, and their files stay as they
/// are. A device that has not heard of the removal still takes it, as it
/// takes any device's. When that device hears, it carries the version as
/// its own, with the removed device's key first in its chain: every
/// device that had not taken that version keeps what its file held
/// beside it.
#[test]
fn what_a_removed_device_writes_later_reaches_only_a_device_that_has_not_heard() {
    let mut steps = vec![Edit(0, "a.md"), Cycle(0)];
    steps.extend(sync(3));
    // Device 1 removes device 0, and device 2 has not heard.
    steps.extend([RemoveUnheard(1, 0), Cycle(1)]);
    steps.extend([Edit(0, "a.md"), Cycle(0), Pass(0, 1), Pass(0, 2)]);
    steps.extend([Cycle(1), Cycle(2)]);
    let mut world = World::new(&[Built; 3], 0);
    for step in &steps {
        world.run(step);
    }
    let file = |d: usize| world.read(d, "a.md").unwrap();
    // Device 1 refused it (`World::send` holds every pass to that), and
    // its file is as it was. Device 2 took it.
    assert!(file(1).contains("at step 1 "), "{}", file(1));
    assert_eq!(file(2), file(0));
    assert_eq!(world.first_copy(1), None);
    assert_eq!(world.first_copy(2), None);

    // Device 2 hears, and carries the version: device 1 takes it, with
    // its own text kept beside the file.
    let was = file(1);
    for step in [Hear(2), Cycle(2), Pass(2, 1), Cycle(1)] {
        world.run(&step);
    }
    let theirs = world.read(0, "a.md").unwrap();
    assert_eq!(world.read(1, "a.md").unwrap(), theirs);
    let copies = world.has(1).copies;
    assert!(copies.contains(&("a.md".to_string(), was)), "{copies:?}");
    let version = world.slot(2, "a.md").unwrap().current.unwrap();
    let chain = version.entries[0].chain.clone().unwrap();
    assert_eq!(chain[0], Link::of(&Value::Text(theirs), world.key(0)));
    world.rest();
    assert_eq!(world.lost(), Vec::<String>::new());
}

/// The check that nothing is lost can see what the rule is for: on
/// devices that plan by revision alone, one edit against two loses the
/// one, and the check says so.
#[test]
fn the_check_sees_an_edit_that_is_overtaken_and_lost() {
    let mut steps = vec![Edit(0, "a.md"), Line(0), Cycle(0)];
    steps.extend(sync(2));
    steps.extend([Edit(1, "a.md"), Line(1), Cycle(1)]);
    steps.extend([
        Edit(0, "a.md"),
        Line(0),
        Cycle(0),
        Edit(0, "a.md"),
        Line(0),
        Cycle(0),
    ]);
    let lost_on = |kind: Kind| {
        let mut world = World::new(&[kind, kind], 1);
        for step in &steps {
            world.run(step);
        }
        world.rest();
        world.lost()
    };
    let lost = lost_on(Before);
    assert_eq!(lost.len(), 2, "{lost:?}");
    assert!(
        lost[0].starts_with("a.md: \"a.md, written on 1 at step"),
        "{lost:?}"
    );
    assert!(
        lost[1].starts_with("MEMORY.md: the line \"- written on 1 at step"),
        "{lost:?}"
    );
    assert_eq!(lost_on(Built), Vec::<String>::new());
}

/// The check goes on seeing after a copy of the index has been resolved.
/// Device 1's index is overtaken and kept, and the copy is merged back
/// into the index by hand, which lets go of no line. Then the index is
/// overtaken again, and this time device 1 plans by revision alone: the
/// lines it had are in no index and in no copy, and the check says so.
#[test]
fn the_check_sees_a_line_lost_after_a_copy_was_merged() {
    let mut steps = vec![Line(0), Cycle(0)];
    steps.extend(sync(2));
    steps.extend([Line(1), Cycle(1)]);
    steps.extend([Line(0), Cycle(0), Line(0), Cycle(0)]);
    steps.extend([Pass(0, 1), Cycle(1), MergeCopy(1), Cycle(1)]);
    steps.extend([Line(0), Cycle(0), Line(0), Cycle(0)]);
    steps.extend([AsBefore(1), Pass(0, 1), Cycle(1)]);
    let mut world = World::new(&[Built, Built], 2);
    for step in &steps {
        world.run(step);
    }
    world.rest();
    let lost = world.lost();
    assert_eq!(lost.len(), 2, "{lost:?}");
    for line in ["- written on 1 at step", "- merged on 1 at step"] {
        assert!(lost.iter().any(|l| l.contains(line)), "{line}: {lost:?}");
    }
}

/// Each written sequence through a change meets the cases it is written
/// for, with every device as built and with every device planning by
/// revision alone, whichever way its ties go. (What the plan does in each
/// case, a cycle that meets it is held to: [`World::held_to`].)
#[test]
fn the_written_sequences_through_a_change_meet_the_five_cases() {
    let mut met_by_any = [0; 5];
    for (name, n, steps) in written_through_a_change() {
        // The cases that the sequence is for, from 1.
        let cases: &[usize] = match name.as_str() {
            NOTHING_TO_DO => &[1, 4],
            AHEAD => &[1, 2, 4],
            NOT_YET_PUBLISHED => &[2, 3],
            TWO_AT_ONE_REVISION => &[1, 5],
            // A change heard late: the device that made it had edited,
            // and the other carries what it wrote meanwhile, as its
            // record has it.
            _ => &[1, 3],
        };
        for kind in [Built, Before] {
            for seed in seeds_of(&name) {
                let came = all(kind, &name, n, seed, &steps);
                for case in cases {
                    let times = came.reached[case - 1];
                    assert!(times > 0, "{name}, {kind:?}, seed {seed}: case {case}");
                }
                for (case, times) in came.reached.iter().enumerate() {
                    met_by_any[case] += times;
                }
            }
        }
    }
    assert!(met_by_any.iter().all(|times| *times > 0), "{met_by_any:?}");
}

/// The harness reads a channel as a device does. What it takes a device
/// to hold in each slot ([`World::slots`]), and who it takes to count for
/// the device, are what a read of the name gives that device: asked
/// after every fifth step of a generated sequence with changes of the
/// person's devices in it, and at its end.
#[test]
fn the_harness_reads_a_channel_as_a_device_does() {
    let n = 3;
    let mut dice = Dice(7919);
    let steps = dice.steps(n, 40, true);
    let mut steps = dice.with_changes(steps, n);
    steps.extend(heard(n));
    steps.extend(sync(n));
    let mut world = World::new(&vec![Built; n], 2);
    let mut versions = 0;
    for (i, step) in steps.iter().enumerate() {
        world.run(step);
        if i % 5 != 4 && i + 1 != steps.len() {
            continue;
        }
        for d in 0..n {
            let read = {
                let db = world.devices[d].st.db.lock().unwrap();
                publish::read_name(&db, NAME).unwrap()
            };
            assert_eq!(world.slots(d), read.slots, "device {d} after {step:?}");
            assert_eq!(
                world.counting(d),
                read.counting,
                "device {d} after {step:?}"
            );
            versions += read.slots.len();
        }
    }
    assert!(versions > 0);
    assert!(
        world.reached.iter().sum::<usize>() > 0,
        "no change was applied"
    );
}
// ── The index line of a memory that comes back ─────────────────────
//
// [`lines`] over sequences in which memories are deleted with their lines
// and come back. Three properties, each over written and generated
// sequences:
//
// - **A.** Every file but the index and its copies is, on every device
//   after every step, as in a run of the same steps on devices without
//   the change.
// - **B.** When everything has met, every line that the run without the
//   change has in an index, and that has no link or whose file no step
//   deleted, is in an index or in a copy of the index in the run with it.
// - **C.** When everything has met and a minute of looks has passed on
//   every device, as often as it takes for no line to go back, no device
//   holds a whole record for a file that it has at rest as a text while
//   its index, at rest, has no line for that file.

use Kind::Lineless;

/// The two memories of these sequences. One sorts before the index, and
/// so is planned before it in a cycle; the other after.
const MEMORIES: [&str; 2] = ["A.md", "notes.md"];

impl Dice {
    /// A sequence for `n` devices in which memories are listed, edited,
    /// deleted with their lines and without, and minutes pass: both
    /// memories written, listed and agreed, and then `len` rolls.
    fn line_steps(&mut self, n: usize, len: usize) -> Vec<Step> {
        let mut steps = Vec::new();
        for file in MEMORIES {
            steps.extend([Edit(0, file), Listed(0, file)]);
        }
        steps.push(Cycle(0));
        steps.extend(sync(n));
        for _ in 0..len {
            let d = self.roll(n);
            let other = (d + 1 + self.roll(n - 1)) % n;
            let file = MEMORIES[self.roll(MEMORIES.len())];
            match self.roll(24) {
                0..=2 => steps.push(Edit(d, file)),
                3 => steps.push(Listed(d, file)),
                4 => steps.push(Line(d)),
                5 => steps.push(Delete(d, file)),
                6 => steps.push(Unlist(d, file)),
                // A memory deleted with its line: the two acts in either
                // order, in one cycle or in two, or with something
                // arriving between them.
                7..=10 => {
                    let mut acts = [Unlist(d, file), Delete(d, file)];
                    if self.roll(2) == 0 {
                        acts.reverse();
                    }
                    let [first, second] = acts;
                    steps.push(first);
                    match self.roll(3) {
                        0 => {}
                        1 => steps.push(Cycle(d)),
                        _ => steps.push(Pass(other, d)),
                    }
                    steps.extend([second, Cycle(d)]);
                }
                11..=15 => steps.push(Cycle(d)),
                16..=19 => steps.push(Pass(d, other)),
                20 => steps.push(PassOne(d, other, file)),
                21 => steps.push(PassOne(d, other, INDEX_FILE)),
                _ => steps.push(Minute(d)),
            }
        }
        steps
    }
}

/// One device deletes a memory with its line while another, apart, edits
/// the memory; then everything meets, and a minute passes on the device
/// that deleted. `line_first`: the line goes before the file. `two`: the
/// two acts are published in two cycles.
fn deleted_and_edited_apart(n: usize, line_first: bool, two: bool) -> Vec<Step> {
    let file = "notes.md";
    let mut steps = vec![Edit(0, file), Listed(0, file), Line(0), Cycle(0)];
    steps.extend(sync(n));
    let mut acts = [Unlist(0, file), Delete(0, file)];
    if !line_first {
        acts.reverse();
    }
    let [first, second] = acts;
    steps.push(first);
    if two {
        steps.push(Cycle(0));
    }
    steps.extend([second, Cycle(0)]);
    steps.extend([Edit(1, file), Cycle(1)]);
    steps.extend(sync(n));
    steps.push(Minute(0));
    steps.extend(sync(n));
    steps
}

/// The written sequences for the index line.
fn written_for_lines() -> Vec<(String, usize, Vec<Step>)> {
    let mut all = Vec::new();
    for line_first in [true, false] {
        for two in [true, false] {
            let steps = deleted_and_edited_apart(2, line_first, two);
            all.push((deleted_apart(line_first, two), 2, steps));
        }
    }
    // Two devices delete the memory with its line, from one agreed index,
    // and the third's edit brings it back. A minute passes on both.
    let file = "notes.md";
    let mut both = vec![Edit(0, file), Listed(0, file), Cycle(0)];
    both.extend(sync(3));
    for d in [0, 1] {
        both.extend([Unlist(d, file), Delete(d, file), Cycle(d)]);
    }
    both.extend([Edit(2, file), Cycle(2)]);
    both.extend(sync(3));
    both.extend([Minute(0), Minute(1)]);
    both.extend(sync(3));
    all.push((TWO_DELETED.to_string(), 3, both));

    // The cost: the other device edits its index while apart, and its
    // edit is heard only after the put-back.
    let mut apart = vec![Edit(0, file), Listed(0, file), Cycle(0)];
    apart.extend(sync(2));
    apart.extend([Unlist(0, file), Delete(0, file), Cycle(0)]);
    apart.extend([Edit(1, file), Cycle(1), Pass(1, 0), Cycle(0)]);
    apart.extend([Line(1), Cycle(1)]);
    apart.push(Minute(0));
    apart.extend(sync(2));
    all.push((OVERTAKEN.to_string(), 2, apart));

    // The other device adds a line to its index meanwhile: a tie on the
    // file and a tie on the index. Everything reaches the device that
    // deleted at once; or the file's entry a cycle before the index's; or
    // a cycle after it.
    for first in [None, Some(file), Some(INDEX_FILE)] {
        let mut steps = vec![Edit(0, file), Listed(0, file), Cycle(0)];
        steps.extend(sync(2));
        steps.extend([Unlist(0, file), Delete(0, file), Cycle(0)]);
        steps.extend([Edit(1, file), Line(1), Cycle(1)]);
        if let Some(first) = first {
            let second = if first == file { INDEX_FILE } else { file };
            steps.extend([PassOne(1, 0, first), Cycle(0)]);
            steps.extend([PassOne(1, 0, second), Cycle(0)]);
        }
        steps.extend(sync(2));
        steps.push(Minute(0));
        steps.extend(sync(2));
        let name = match first {
            None => TWO_TIES.to_string(),
            Some(first) if first == file => FILE_FIRST.to_string(),
            Some(_) => INDEX_FIRST.to_string(),
        };
        all.push((name, 2, steps));
    }

    // The other device changes the memory's own line meanwhile. Everything
    // reaches the device that deleted at once; or the other device's index
    // a cycle before its edit of the memory, so that the two indexes meet
    // while the memory is still deleted for the device that deleted it.
    for index_first in [false, true] {
        let mut changed = vec![Edit(0, file), Listed(0, file), Cycle(0)];
        changed.extend(sync(2));
        changed.extend([Unlist(0, file), Delete(0, file), Cycle(0)]);
        changed.extend([Unlist(1, file), Listed(1, file), Edit(1, file), Cycle(1)]);
        if index_first {
            changed.extend([PassOne(1, 0, INDEX_FILE), Cycle(0)]);
            changed.extend([PassOne(1, 0, file), Cycle(0)]);
        }
        changed.extend(sync(2));
        changed.push(Minute(0));
        changed.extend(sync(2));
        let name = match index_first {
            false => OWN_LINE.to_string(),
            true => format!("{OWN_LINE}, {INDEX_FILE} first"),
        };
        all.push((name, 2, changed));
    }

    // The other device, apart, edits the memory and deletes a second
    // memory with its line, and runs no cycle before the first device's
    // minute is up.
    let second = "second.md";
    let mut two = vec![Edit(0, file), Listed(0, file)];
    two.extend([Edit(0, second), Listed(0, second), Cycle(0)]);
    two.extend(sync(2));
    two.extend([Unlist(0, file), Delete(0, file), Cycle(0)]);
    two.extend([
        Edit(1, file),
        Unlist(1, second),
        Delete(1, second),
        Cycle(1),
    ]);
    two.extend([Pass(1, 0), Cycle(0), Minute(0)]);
    two.extend(sync(2));
    all.push(("a second memory deleted apart".to_string(), 2, two));

    // Three devices: one deletes the memory with its line, one adds a
    // line, and the third had taken the first's index; the second's index
    // entry reaches the third a cycle before its edit of the file.
    let mut three = vec![Edit(0, file), Listed(0, file), Cycle(0)];
    three.extend(sync(3));
    three.extend([Unlist(0, file), Delete(0, file), Cycle(0)]);
    three.extend([Line(1), Cycle(1)]);
    three.extend([PassOne(0, 2, INDEX_FILE), Cycle(2)]);
    three.extend([PassOne(1, 2, INDEX_FILE), Cycle(2)]);
    three.extend([Edit(2, file), Cycle(2)]);
    three.extend(sync(3));
    three.push(Minute(0));
    three.extend(sync(3));
    all.push((A_THIRD.to_string(), 3, three));

    // A version of the index stands beside the channel's when the line
    // goes back: two devices added a line each, at one revision.
    let mut beside = vec![Edit(0, file), Listed(0, file), Cycle(0)];
    beside.extend(sync(3));
    beside.extend([Unlist(0, file), Delete(0, file), Cycle(0)]);
    beside.extend([Edit(1, file), Cycle(1)]);
    beside.extend(sync(3));
    beside.extend([Line(0), Line(2), Cycle(0), Cycle(2), Pass(2, 0), Cycle(0)]);
    beside.push(Minute(0));
    beside.extend(sync(3));
    all.push((BESIDE.to_string(), 3, beside));
    if !everything() {
        all.retain(|(name, ..)| {
            RUN_ALWAYS.contains(&name.as_str()) || name == &deleted_apart(true, true)
        });
    }
    all
}

/// The name of the written sequence in which a memory is deleted with its
/// line and edited apart ([`deleted_and_edited_apart`]).
fn deleted_apart(line_first: bool, two: bool) -> String {
    format!("deleted and edited apart (line first: {line_first}, two cycles: {two})")
}

/// The names of the written sequences that a test asks more of.
const TWO_TIES: &str = "a line added apart";
const FILE_FIRST: &str = "a line added apart, notes.md first";
const INDEX_FIRST: &str = "a line added apart, MEMORY.md first";
const TWO_DELETED: &str = "two devices deleted it";
const OWN_LINE: &str = "its own line changed apart";
const A_THIRD: &str = "one deletes, one adds a line, a third edits";
const OVERTAKEN: &str = "an index edited apart";
const BESIDE: &str = "a version beside";

/// The written sequences in which no line is put back. In each, the
/// device that deleted the memory hears of another device's edit of it no
/// later than of the index that still lists it. A text beats a delete at
/// one revision, so the memory is back at once, and is deleted for nobody
/// when the two indexes are merged: the merge keeps the line that the
/// other index still has, before the minute is up. (A line goes back
/// where the index arrives first, and is merged while the memory is still
/// deleted for the device that merges.)
const BACK_BY_A_MERGE: [&str; 4] = [TWO_TIES, FILE_FIRST, OWN_LINE, A_THIRD];

/// The written sequences that are run where not everything is, with the
/// first of those in which a memory is deleted and edited apart: one for
/// each thing that a test asks of a sequence by its name.
const RUN_ALWAYS: [&str; 5] = [TWO_DELETED, OVERTAKEN, TWO_TIES, INDEX_FIRST, BESIDE];

/// The seeds the written sequences for the index line run with: four
/// pairs, each pair deciding every tie between two texts that steps wrote
/// the two ways round, and the pairs deciding them apart from each other.
/// The first seed alone, where not everything is run ([`everything`]).
fn seeds() -> Vec<u64> {
    match everything() {
        true => vec![2, 3, 4, 5, 6, 7, 8, 9],
        false => vec![2],
    }
}

/// What a world of devices of `kinds` came to over a sequence for the
/// index line: taken until its lines are settled where a device has the
/// change, and until everything has met where none has.
fn for_lines(name: &str, kinds: &[Kind], seed: u64, steps: &[Step]) -> Arc<Came> {
    let until = match kinds.contains(&Built) {
        true => Until::Settled,
        false => Until::Met,
    };
    came(name, kinds, seed, steps, until)
}

/// What a device has, without the index and its copies.
fn but_the_index(has: &Has) -> Has {
    let mut has = has.clone();
    has.files.remove(INDEX_FILE);
    has.channel.remove(INDEX_FILE);
    has.records.remove(INDEX_FILE);
    has.copies.retain(|(root, _)| root != INDEX_FILE);
    has
}

/// Property A, for one sequence.
fn every_other_file_is_as_without_it(name: &str, n: usize, seed: u64, steps: &[Step]) {
    let without = for_lines(name, &vec![Lineless; n], seed, steps);
    let with = for_lines(name, &vec![Built; n], seed, steps);
    assert_eq!(without.had.len(), with.had.len(), "the steps");
    for (i, (was, is)) in without.had.iter().zip(&with.had).enumerate() {
        assert_eq!(was.len(), is.len(), "the devices that remain, step {i}");
        for ((d, was), (_, is)) in was.iter().zip(is) {
            assert_eq!(
                but_the_index(was),
                but_the_index(is),
                "seed {seed}, device {d}, after step {i} ({:?}) of {steps:?}",
                steps[i]
            );
        }
    }
}

impl World {
    /// Every line of an index on a device that remains, and with `copies`
    /// every line of a copy of the index too.
    fn lines_listed(&self, copies: bool) -> BTreeSet<String> {
        let mut lines = BTreeSet::new();
        for d in self.remaining() {
            let has = self.has(d);
            if let Some(index) = has.files.get(INDEX_FILE) {
                lines.extend(index.lines().map(String::from));
            }
            for (root, text) in &has.copies {
                if copies && root == INDEX_FILE {
                    lines.extend(text.lines().map(String::from));
                }
            }
        }
        lines
    }

    /// Everything meets and a minute of looks passes on every device,
    /// again and again until nothing changes.
    fn settle_lines(&mut self) {
        for _ in 0..40 {
            self.rest();
            let devices = self.remaining();
            let before: Vec<_> = devices.iter().map(|d| self.whole(*d)).collect();
            for d in &devices {
                self.run(&Step::Minute(*d));
            }
            let after: Vec<_> = devices.iter().map(|d| self.whole(*d)).collect();
            if after == before {
                return;
            }
        }
        panic!("lines were still going back");
    }

    /// The files for which the device holds a whole record, has the file
    /// at rest as a text, and has an index at rest with no line for it.
    fn unlisted(&self, d: usize) -> Vec<String> {
        let has = self.has(d);
        let at_rest = |name: &str| -> Option<&String> {
            let text = has.files.get(name)?;
            let (_, there) = has.channel.get(name)?;
            let (hash, _) = has.records.get(name)?;
            let same =
                there.as_ref() == Some(text) && *hash == Some(Content::new(text.as_str()).hash);
            same.then_some(text)
        };
        let Some(index) = at_rest(INDEX_FILE) else {
            return Vec::new();
        };
        let channel = self.channel(d);
        let device = &self.devices[d];
        let db = device.st.db.lock().unwrap();
        let folder = device.mem.display().to_string();
        let records =
            cordelia_storage::index_lines::whole(&db, &folder, &channel, self.now).unwrap();
        records
            .into_iter()
            .map(|record| record.file)
            .filter(|file| at_rest(file).is_some())
            .filter(|file| {
                !index
                    .lines()
                    .any(|line| lines::line_for(line) == Some(file))
            })
            .collect()
    }
}

/// A line as its step wrote it, without the number that it ends with.
/// That number places the index that the line was written into
/// ([`World::placed`]), so one step's line ends with another number in a
/// run where the index held other lines.
fn without_its_number(line: &str) -> &str {
    line.rsplit_once(" (").map_or(line, |(said, _)| said)
}

/// Property B, for one sequence; `settled` asks it after the minutes of
/// property C as well.
fn no_line_is_lost_to_a_put_back(name: &str, n: usize, seed: u64, steps: &[Step]) {
    let without = for_lines(name, &vec![Lineless; n], seed, steps);
    let with = for_lines(name, &vec![Built; n], seed, steps);
    let without = without.met();
    let listed = without.listed.iter();
    let expected: Vec<&String> = listed
        .filter(|line| lines::line_for(line).is_none_or(|file| !without.deleted.contains(file)))
        .collect();
    for (settled, there) in [(false, with.met()), (true, with.settled())] {
        let there = there.listed_or_kept.iter();
        let there: BTreeSet<&str> = there.map(|line| without_its_number(line)).collect();
        for line in &expected {
            assert!(
                there.contains(without_its_number(line)),
                "seed {seed}, settled: {settled}: the line {line:?} is in no index and no copy \
                 after {steps:?}"
            );
        }
    }
}

/// Property C, for one sequence. Returns whether a line was put back.
fn a_line_that_is_due_goes_back(name: &str, n: usize, seed: u64, steps: &[Step]) -> bool {
    let came = for_lines(name, &vec![Built; n], seed, steps);
    for (d, unlisted) in &came.settled().unlisted {
        assert!(
            unlisted.is_empty(),
            "seed {seed}, device {d}: {unlisted:?} back and not listed after {steps:?}"
        );
    }
    came.settled().put_back > 0
}

/// The generated sequences for the index line, each with its name: for
/// two, three and four devices ([`devices`]), every other one with
/// changes of the person's devices among its steps.
fn generated_for_lines() -> Vec<(String, usize, u64, Vec<Step>)> {
    let mut all = Vec::new();
    for n in devices() {
        for seed in 1..=sequences() {
            let mut dice = Dice(seed * 15_485_863 + n as u64);
            let mut steps = dice.line_steps(n, 50);
            // Every other one with changes of the person's devices.
            if through_changes(n, seed) {
                steps = dice.with_changes(steps, n);
                steps.extend(heard(n));
            }
            steps.extend(sync(n));
            let name = format!("generated for the index line, {n} devices, seed {seed}");
            all.push((name, n, seed, steps));
        }
    }
    all
}

/// Property A: the index line of a memory that comes back changes no
/// file but the index and its copies.
#[test]
fn the_index_line_changes_no_other_file() {
    for (name, n, steps) in written_for_lines() {
        for seed in seeds() {
            eprintln!("{name}, seed {seed}");
            every_other_file_is_as_without_it(&name, n, seed, &steps);
        }
    }
    for (name, n, seed, steps) in generated_for_lines() {
        every_other_file_is_as_without_it(&name, n, seed, &steps);
    }
}

/// Property B: a put-back loses no line.
#[test]
fn a_put_back_loses_no_line() {
    // From the last: the test of property A asks about the same runs
    // from the first, and each then finds the other's made.
    for (name, n, steps) in written_for_lines().into_iter().rev() {
        for seed in seeds() {
            eprintln!("{name}, seed {seed}");
            no_line_is_lost_to_a_put_back(&name, n, seed, &steps);
        }
    }
    for (name, n, seed, steps) in generated_for_lines() {
        no_line_is_lost_to_a_put_back(&name, n, seed, &steps);
    }
}

/// Property C: where a memory is back and its line is due, the line goes
/// back. And the sequences reach the rule: in each written one that can,
/// and, where everything is run, in a good part of the generated ones, a
/// line is put back. Without that the three properties could be true of
/// nothing.
#[test]
fn a_memory_that_is_back_is_listed() {
    for (name, n, steps) in written_for_lines() {
        // With a tie on the index in it, a sequence can leave the line in
        // place one way round (the other device's index wins, and has the
        // line in it): it reaches the rule the other way.
        let reached: Vec<bool> = seeds()
            .into_iter()
            .map(|seed| {
                eprintln!("{name}, seed {seed}");
                a_line_that_is_due_goes_back(&name, n, seed, &steps)
            })
            .collect();
        match BACK_BY_A_MERGE.contains(&name.as_str()) {
            false => assert!(reached.contains(&true), "{name}: no line went back"),
            true => assert!(!reached.contains(&true), "{name}: a line went back"),
        }
    }
    let (mut run, mut reached) = (0, 0);
    for (name, n, seed, steps) in generated_for_lines() {
        run += 1;
        reached += usize::from(a_line_that_is_due_goes_back(&name, n, seed, &steps));
    }
    eprintln!("a line went back in {reached} of {run} generated sequences");
    if everything() {
        assert!(4 * reached >= run, "a line went back in {reached} of {run}");
    }
}

/// The written sequences end as they should: every device has the memory
/// and one line for it.
#[test]
fn a_memory_deleted_here_and_edited_there_is_listed_once_everywhere() {
    for (name, n, steps) in written_for_lines() {
        for seed in seeds() {
            let mut each = vec![vec![Built; n]];
            // The other devices without the change: the device that
            // deleted puts the line back all the same. (Two devices
            // deleted it: both have the change.) Where everything is run.
            if everything() && name != TWO_DELETED {
                let mut kinds = vec![Lineless; n];
                kinds[0] = Built;
                each.push(kinds);
            }
            for kinds in each {
                let came = for_lines(&name, &kinds, seed, &steps);
                for (d, has) in &came.settled().has {
                    let at = format!("{name}, seed {seed}, {kinds:?}, device {d}");
                    assert!(has.files.contains_key("notes.md"), "{at}");
                    let index = &has.files[INDEX_FILE];
                    let listed = index
                        .lines()
                        .filter(|line| lines::line_for(line) == Some("notes.md"))
                        .count();
                    assert_eq!(listed, 1, "{at}: {index}");
                }
            }
        }
    }
}

/// The written sequence with a tie on the file and a tie on the index
/// runs with each way the two can go, over its seeds. The file's tie is
/// between a delete and a text, and has one way: a text beats a delete.
/// The index's has two: the properties above are asked of both where
/// everything is run. (Two seeds are enough to show the two ways, and are
/// run here whatever else is.)
#[test]
fn the_two_ties_go_each_way_they_can() {
    let (name, n, steps) = written_for_lines()
        .into_iter()
        .find(|(name, ..)| name == TWO_TIES)
        .unwrap();
    let mut ways = BTreeSet::new();
    let seeds = if everything() { seeds() } else { vec![2, 3] };
    for seed in seeds {
        let came = for_lines(&name, &vec![Built; n], seed, &steps);
        let won = |name: &str| -> Vec<bool> {
            let ties = came.met().ties.iter().filter(|(tied, _)| tied == name);
            ties.map(|(_, won)| *won).collect()
        };
        let (file, index) = (won("notes.md"), won(INDEX_FILE));
        assert_eq!(
            (file.len(), index.len()),
            (1, 1),
            "seed {seed}: one tie each"
        );
        // The edit of the memory was published after its delete, and wins.
        assert!(file[0], "seed {seed}: a delete beat a text");
        ways.insert(index[0]);
    }
    assert_eq!(ways.len(), 2, "{ways:?}");
}

/// What a put-back costs a device whose index it overtakes, and no more.
///
/// - A device that edited its index while apart, and whose edit is heard
///   only after the put-back, has its index kept as a copy: the put-back
///   is at a higher revision and is not known to follow what it holds.
/// - A device whose version stood beside the channel's finds its lines in
///   the index: every line of a copy of its index is in its index, or is
///   for a file that a step deleted.
#[test]
fn a_put_back_overtakes_an_index_into_a_copy() {
    let mut overtaken = 0;
    for (name, n, steps) in written_for_lines() {
        if name != OVERTAKEN && name != BESIDE {
            continue;
        }
        for seed in seeds() {
            let came = for_lines(&name, &vec![Built; n], seed, &steps);
            let at = format!("{name}, seed {seed}");
            if name == OVERTAKEN {
                // The line went back before the other device's index edit
                // was heard: the memory's edit won its tie at once, since
                // a text beats a delete.
                let met = came.met();
                if met.put_back > 0 {
                    overtaken += 1;
                    let (_, has) = met.has.iter().find(|(d, _)| *d == 1).unwrap();
                    assert!(
                        has.copies.iter().any(|(root, _)| root == INDEX_FILE),
                        "{at}: the overtaken index is in no copy"
                    );
                }
                continue;
            }
            let settled = came.settled();
            for (d, has) in &settled.has {
                let index = has.files.get(INDEX_FILE).cloned().unwrap_or_default();
                for (_, copy) in has.copies.iter().filter(|(root, _)| root == INDEX_FILE) {
                    for line in copy.lines() {
                        let gone = lines::line_for(line)
                            .is_some_and(|file| settled.deleted.contains(file));
                        assert!(
                            gone || index.lines().any(|listed| listed == line),
                            "{at}, device {d}: {line:?} is in a copy and not in the index"
                        );
                    }
                }
            }
        }
    }
    assert!(
        overtaken > 0,
        "no seed staged an index overtaken by a put-back"
    );
}
