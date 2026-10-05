//! What several devices come to over a sequence of edits, deletes and
//! syncs, for the rule that an entry says what it was written after
//! (decision 2026-09-30 §4.5).
//!
//! Two things are checked for that rule, each over written and generated
//! sequences (and three more for the index line of a memory that comes
//! back, further down, with a kind of device and steps of their own):
//!
//! - **The property.** The rule changes one thing: where a file would be
//!   replaced by a version at a higher revision that is not known to
//!   follow the one the folder agreed, what the file held is kept first.
//!   So a run with every device as it is built, and a run of the same
//!   sequence with every device as it was before, end every step with
//!   the same files, the same versions in the channel and the same
//!   records, on every device that is still the person's. Only the
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
//! A tie between two devices' entries goes by the hash of the sealed
//! entry, which is random. Here the sequence says who wins each tie, and
//! the entry just published is sealed again until its hash says the same.
//! So one sequence has one outcome, in every run. Two seeds that differ
//! only in their last bit decide every tie the other way from each other.
//!
//! What the sequences do not vary: of three entries tied at one revision
//! the newest is first or last, never between the other two; and what one
//! device passes to another arrives in the order it was published.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::memory_md::INDEX_FILE;

/// How a device behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// As it is built: the plan, entries that say what they were written
    /// after, records that carry the writer.
    Built,
    /// As it was before: the plan as it was, entries that say nothing,
    /// records that say nothing of the writer.
    Before,
    /// As it is built, without the index line of a memory that comes back
    /// ([`lines`]): what the rule for an overtaken edit shipped as.
    Lineless,
}

/// The plan as it was before entries said what they were written after: a
/// higher revision follows, and that is all. Frozen here so that the
/// plan can be compared with it.
fn plan_before(
    key: &str,
    local: Option<&Content>,
    remote: Option<&Remote>,
    agreed: Option<&Agreed>,
    deleted_files: &HashSet<String>,
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
    let record = |r: &Remote, hash: Option<[u8; 32]>| {
        Action::Record(Agreed {
            hash,
            rev: r.rev,
            writer: Writer::NotRecorded,
        })
    };
    let pull = |r: &Remote, c: &Content| Action::Pull {
        text: c.text.clone(),
        rev: r.rev,
        writer: Writer::NotRecorded,
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
            (Some(r), Some(a)) if r.rev != a.rev => vec![record(r, a.hash)],
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
                    rev: r.rev,
                    writer: Writer::NotRecorded,
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
    /// Everything the first device holds reaches the second.
    Pass(usize, usize),
    /// The first device's entry for one file reaches the second.
    PassOne(usize, usize, &'static str),
    /// The device's records lose their writers, as records made before
    /// the writer was kept.
    NoWriters(usize),
    /// From now on the device behaves as devices did before. Only for a
    /// test of the check itself: a fault, put where the test wants it.
    AsBefore(usize),
    /// The first device removes the second, as the node does: it
    /// publishes again, under its own name, each entry that counts and
    /// that the second wrote, and from then on the second's entries count
    /// on no device, and its folder is no longer one of the person's.
    Remove(usize, usize),
    /// The device moves the channel to a new key, as a device that
    /// removes another does, and writes under it from now on.
    NewKey(usize),
    /// The device gets the channel's newest key.
    GetKey(usize),
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

/// A device in a sequence.
struct Device {
    st: AppState,
    mem: PathBuf,
    kind: Kind,
    /// The entries of this device's that have been looked at for a tie.
    settled: HashSet<String>,
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

/// Several devices of one person in one channel.
struct World {
    devices: Vec<Device>,
    channel: String,
    /// What decides each tie, with the step and the file's name.
    seed: u64,
    /// The step being run.
    step: usize,
    /// How many times the channel's key has been changed.
    keys: u8,
    /// The device that changed it last.
    key_by: usize,
    /// The devices that have been removed.
    removed: BTreeSet<usize>,
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
    /// Each tie that was settled: the file, and whether the entry
    /// published later won it.
    ties: BTreeSet<(String, bool)>,
    _tmp: tempfile::TempDir,
}

impl World {
    /// Devices of the kinds given, all in one channel and all holding its
    /// first key, with nothing written yet.
    fn new(kinds: &[Kind], seed: u64) -> Self {
        use cordelia_storage::psk;
        let tmp = tempfile::tempdir().unwrap();
        let devices: Vec<Device> = kinds
            .iter()
            .enumerate()
            .map(|(i, kind)| {
                let dir = tmp.path().join(format!("d{i}"));
                let mem = dir.join("memory");
                std::fs::create_dir_all(&mem).unwrap();
                let st = AppState {
                    db: std::sync::Mutex::new(cordelia_storage::db::open_in_memory().unwrap()),
                    // The same keys in every run, so that a device's
                    // conflict files have the same names in every run.
                    identity: cordelia_crypto::identity::NodeIdentity::from_seed([i as u8 + 1; 32])
                        .unwrap(),
                    bearer_token: "t".into(),
                    home_dir: dir.join("node"),
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
                    usable_keys: Default::default(),
                    own_channels: Default::default(),
                    history: Default::default(),
                };
                Device {
                    st,
                    mem,
                    kind: *kind,
                    settled: HashSet::new(),
                }
            })
            .collect();

        let first = &devices[0].st;
        membership::ensure_own_inbox(first).unwrap();
        let channel = membership::create_project_group(first, "project:x").unwrap();
        let key = psk::read_psk(&first.home_dir, &channel).unwrap();
        let slot_key = psk::read_slot_key(&first.home_dir, &channel).unwrap();
        let creator = first.identity.public_key();
        let members: Vec<[u8; 32]> = devices.iter().map(|d| d.st.identity.public_key()).collect();
        for (i, device) in devices.iter().enumerate() {
            let db = device.st.db.lock().unwrap();
            if i > 0 {
                psk::write_psk(&device.st.home_dir, &channel, &key).unwrap();
                psk::write_slot_key(&device.st.home_dir, &channel, &slot_key).unwrap();
                channels::ensure_group(&db, &channel, None, "realtime", &creator).unwrap();
                let hash = cordelia_crypto::sha256(&key);
                channels::set_state(&db, &channel, 1, &creator, 1, &hash).unwrap();
            }
            for member in &members {
                if !channels::is_member(&db, &channel, member).unwrap() {
                    channels::add_member(&db, &channel, member, "owner").unwrap();
                }
            }
        }
        Self {
            devices,
            channel,
            seed,
            step: 0,
            keys: 0,
            key_by: 0,
            removed: BTreeSet::new(),
            wrote: BTreeSet::new(),
            lines: BTreeSet::new(),
            let_go: BTreeSet::new(),
            let_go_lines: BTreeSet::new(),
            now: 1_800_000_000,
            deleted: BTreeSet::new(),
            put_back: 0,
            ties: BTreeSet::new(),
            _tmp: tmp,
        }
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

    /// One step. A step that has nothing to act on (a file that is not
    /// there to delete, no conflict file to resolve) does nothing.
    fn run(&mut self, step: &Step) {
        self.step += 1;
        match step {
            Step::Edit(d, name) => {
                let text = format!("{name}, written on {d} at step {}\n", self.step);
                self.wrote.insert((name.to_string(), text.clone()));
                self.put(*d, name, Some(&text));
            }
            Step::Line(d) => {
                // No link in it: a merge drops a line that points at a
                // deleted file, which is not what is under test here.
                let line = format!("- written on {d} at step {}", self.step);
                let index = self.read(*d, INDEX_FILE).unwrap_or_default();
                self.lines.insert(line.clone());
                // Not let go: every line that was there is still there.
                let path = self.devices[*d].mem.join(INDEX_FILE);
                std::fs::write(path, format!("{index}{line}\n")).unwrap();
            }
            Step::Delete(d, name) => {
                self.deleted.insert(name.to_string());
                self.put(*d, name, None);
            }
            Step::Listed(d, name) => {
                let line = format!("- [{name}]({name}) listed on {d} at step {}", self.step);
                let index = self.read(*d, INDEX_FILE).unwrap_or_default();
                let path = self.devices[*d].mem.join(INDEX_FILE);
                std::fs::write(path, format!("{index}{line}\n")).unwrap();
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
            Step::NoWriters(d) => {
                let db = self.devices[*d].st.db.lock().unwrap();
                db.execute("UPDATE sync_files SET author = NULL", [])
                    .unwrap();
            }
            Step::AsBefore(d) => self.devices[*d].kind = Kind::Before,
            Step::Remove(by, who) => {
                let leaving = self.devices[*who].st.identity.public_key();
                {
                    // While the leaving device's entries still count
                    // here, as the node does it.
                    let st = &self.devices[*by].st;
                    let db = st.db.lock().unwrap();
                    entries::take_over(st, &db, &self.channel, &leaving).unwrap();
                }
                // The removal has reached every device.
                for device in &self.devices {
                    let db = device.st.db.lock().unwrap();
                    channels::remove_member(&db, &self.channel, &leaving).unwrap();
                }
                self.removed.insert(*who);
                self.settle_ties(*by);
            }
            Step::NewKey(d) => {
                self.keys += 1;
                self.key_by = *d;
                self.give_key(*d);
            }
            Step::GetKey(d) => self.give_key(*d),
            Step::DropCopy(d) => {
                if let Some(copy) = self.first_copy(*d) {
                    self.put(*d, &copy, None);
                }
            }
            Step::EditCopy(d) => {
                if let Some(copy) = self.first_copy(*d) {
                    let text = format!("{copy}, written on {d} at step {}\n", self.step);
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
                    let line = format!("- merged on {d} at step {}", self.step);
                    let both = format!("{held}{kept}{line}\n");
                    let mem = &self.devices[*d].mem;
                    if root == INDEX_FILE {
                        // Every line of the index and of the copy is in
                        // the index afterwards, with one more: nothing is
                        // let go of, and the new line is one to look for.
                        self.lines.insert(line);
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
    }

    /// The device holds the channel's newest key, if the key has been
    /// changed and it does not hold it yet.
    fn give_key(&mut self, d: usize) {
        use cordelia_storage::psk;
        let st = &self.devices[d].st;
        let by = self.devices[self.key_by].st.identity.public_key();
        let db = st.db.lock().unwrap();
        // The first key is version 1, and each change of key is one more.
        let newest = u32::from(self.keys) + 1;
        let mut version = channels::get_by_id(&db, &self.channel).unwrap().key_version as u32;
        while version < newest {
            let key = [0x70 + version as u8; 32];
            version += 1;
            psk::rotate_psk(&st.home_dir, &self.channel, &key, "2026-10-03T00:00:00Z").unwrap();
            let hash = cordelia_crypto::sha256(&key);
            channels::set_state(&db, &self.channel, u64::from(version), &by, version, &hash)
                .unwrap();
        }
    }

    /// What the device holds in the channel, as stored.
    fn held(&self, d: usize) -> Vec<cordelia_storage::items::StoredItem> {
        let db = self.devices[d].st.db.lock().unwrap();
        cordelia_storage::items::query_sync(&db, &self.channel, None, 100_000).unwrap()
    }

    /// The slot of a file's entries.
    fn slot_of(&self, name: &str) -> Vec<u8> {
        use cordelia_storage::psk;
        let home = &self.devices[0].st.home_dir;
        let slot_key = psk::read_slot_key(home, &self.channel).unwrap();
        cordelia_crypto::slots::slot_id(&slot_key, name).to_vec()
    }

    /// What `from` holds reaches `to`: all of it, or its entries for one
    /// file. An entry that is no newer than what `to` holds from the same
    /// device is not taken, as at a relay.
    fn send(&mut self, from: usize, to: usize, only: Option<&str>) {
        use cordelia_storage::items;
        let slot = only.map(|name| self.slot_of(name));
        let db = self.devices[to].st.db.lock().unwrap();
        for it in self.held(from) {
            if slot.is_some() && it.slot != slot {
                continue;
            }
            let at: Option<[u8; 32]> = it.slot.as_deref().map(|s| s.try_into().unwrap());
            // `false` for an entry that is not taken; an error is a fault
            // of this harness.
            items::insert_item(
                &db,
                &items::NewItem {
                    item_id: &it.item_id,
                    channel_id: &it.channel_id,
                    author_id: it.author_id.as_slice().try_into().unwrap(),
                    item_type: &it.item_type,
                    published_at: &it.published_at,
                    parent_id: it.parent_id.as_deref(),
                    key_version: it.key_version,
                    content_hash: &it.content_hash,
                    signature: &it.signature,
                    encrypted_blob: &it.encrypted_blob,
                    is_tombstone: it.is_tombstone,
                    slot: at.as_ref(),
                    rev: it.rev,
                },
            )
            .unwrap();
        }
    }

    /// One cycle of the device's folder, and then each tie that an entry
    /// it has just published is in is settled as the sequence says.
    fn cycle(&mut self, d: usize) {
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
            says_nothing: device.kind == Kind::Before,
            // A device as it was before entries said anything has no
            // record of its lines either.
            lines: device.kind == Kind::Built,
            before_hold: &|| {},
        };
        device.st.sync_control.set_now(Some(self.now));
        let counted = self.times_put_back(d);
        let device = &self.devices[d];
        let generation = device.st.sync_control.generation();
        let report = sync_folder_with(
            &device.st,
            &device.mem,
            &self.channel,
            "x",
            "",
            &tag,
            generation,
            &hooks,
        )
        .unwrap();
        assert!(
            report.failed.is_empty() && report.error.is_none(),
            "{report:?}"
        );
        // A cycle that put lines back counted each record that was due in
        // it. (A third time takes the record with it, and is not seen
        // here: nothing below needs it to be.)
        self.put_back += self.times_put_back(d).saturating_sub(counted);
        self.settle_ties(d);
    }

    /// How many times the device's records say their lines were put back.
    fn times_put_back(&self, d: usize) -> u64 {
        let db = self.devices[d].st.db.lock().unwrap();
        db.query_row(
            "SELECT COALESCE(SUM(put_back), 0) FROM index_lines",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    /// Whether, of two entries for `name` at one revision, the one
    /// published in this step wins: decided by the sequence, so that it
    /// is the same in every run. A seed and the next one (2 and 3, say)
    /// decide every tie the other way from each other.
    fn new_entry_wins(&self, name: &str) -> bool {
        let said = format!("{}/{}/{name}", self.seed >> 1, self.step);
        let wins = cordelia_crypto::sha256(said.as_bytes())[0] & 1 == 1;
        wins ^ (self.seed & 1 == 1)
    }

    /// For each entry the device has published and that has not been
    /// looked at: if another device's entry for the same file at the same
    /// revision is held anywhere, seal this one again until its hash is
    /// on the side of that entry's that the sequence says.
    fn settle_ties(&mut self, d: usize) {
        use cordelia_crypto::signing::ItemMetadata;
        use cordelia_crypto::slots::item_aad;
        use cordelia_storage::psk;
        let me = self.devices[d].st.identity.public_key();
        let fresh: Vec<_> = self
            .held(d)
            .into_iter()
            .filter(|it| it.author_id == me && it.slot.is_some())
            .filter(|it| !self.devices[d].settled.contains(&it.item_id))
            .collect();
        for it in fresh {
            self.devices[d].settled.insert(it.item_id.clone());
            let rivals: BTreeSet<Vec<u8>> = (0..self.devices.len())
                .flat_map(|other| self.held(other))
                .filter(|o| o.slot == it.slot && o.rev == it.rev && o.author_id != me)
                .map(|o| o.content_hash)
                .collect();
            // It wins against every one of them or loses to every one: a
            // place among them would leave it to chance which of two it
            // beats, and a device can hold any two of them.
            let (Some(lowest), Some(highest)) = (rivals.first(), rivals.last()) else {
                continue;
            };
            let st = &self.devices[d].st;
            let now = {
                let db = st.db.lock().unwrap();
                channels::get_by_id(&db, &self.channel).unwrap().key_version
            };
            let envelope = entries::decrypt(st, now, &it).expect("its own entry");
            let name = envelope["key"].as_str().unwrap().to_string();
            let wins = self.new_entry_wins(&name);
            self.ties.insert((name.clone(), wins));
            let key = psk::read_psk_for_version(&st.home_dir, &self.channel, it.key_version, now)
                .unwrap();
            let aad = item_aad(&self.channel, it.slot.as_deref(), it.rev);
            let plaintext = cordelia_crypto::item_decrypt(&key, &it.encrypted_blob, &aad).unwrap();
            // No bound: each try lands on the right side with the chance
            // that the rivals' hashes leave, so it ends, and now and then
            // takes many thousands of tries.
            let (blob, hash) = loop {
                let blob = cordelia_crypto::item_encrypt(&key, &plaintext, &aad).unwrap();
                let hash = cordelia_crypto::sha256(&blob);
                let placed = match wins {
                    true => hash.as_slice() > highest.as_slice(),
                    false => hash.as_slice() < lowest.as_slice(),
                };
                if placed {
                    break (blob, hash);
                }
            };
            let slot: [u8; 32] = it.slot.as_deref().unwrap().try_into().unwrap();
            let signed = ItemMetadata {
                author_id: &me,
                channel_id: &self.channel,
                content_hash: &hash,
                is_tombstone: it.is_tombstone,
                item_id: &it.item_id,
                key_version: it.key_version,
                published_at: &it.published_at,
                slot: Some(&slot),
                rev: it.rev,
            }
            .encode()
            .unwrap();
            let signature = st.identity.sign(&signed);
            let db = st.db.lock().unwrap();
            let changed = db
                .execute(
                    "UPDATE items SET encrypted_blob = ?1, content_hash = ?2, signature = ?3
                     WHERE item_id = ?4",
                    rusqlite::params![blob, hash.to_vec(), signature.to_vec(), it.item_id],
                )
                .unwrap();
            assert_eq!(changed, 1);
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
        let db = device.st.db.lock().unwrap();
        let channel = entries::current(&device.st, &db, &self.channel)
            .unwrap()
            .into_iter()
            .filter(|e| !names::is_conflict_name(&e.key))
            .map(|e| {
                let text = e.current.content.as_str().map(String::from);
                (e.key, (e.current.rev, text))
            })
            .collect();
        let folder = device.mem.display().to_string();
        let records = sync_state::load(&db, &folder, &self.channel)
            .unwrap()
            .into_iter()
            .filter(|(name, _)| !names::is_conflict_name(name))
            .map(|(name, (hash, rev, _))| (name, (hash, rev)))
            .collect();
        Has {
            files,
            channel,
            records,
            copies,
        }
    }

    /// Everything about a device that a step can change: its files, the
    /// entries it holds, and what its folder has recorded.
    fn whole(&self, d: usize) -> impl PartialEq + use<> {
        let files: Vec<(String, String)> = self
            .names(d)
            .into_iter()
            .map(|name| {
                let text = self.read(d, &name).unwrap();
                (name, text)
            })
            .collect();
        let mut held: Vec<String> = self.held(d).into_iter().map(|it| it.item_id).collect();
        held.sort();
        let db = self.devices[d].st.db.lock().unwrap();
        let folder = self.devices[d].mem.display().to_string();
        let mut records: Vec<_> = sync_state::load(&db, &folder, &self.channel)
            .unwrap()
            .into_iter()
            .collect();
        records.sort();
        (files, held, records)
    }

    /// What the device's record of a file says of who wrote the entry it
    /// agreed, if it has a record of the file.
    fn writer_of(&self, d: usize, name: &str) -> Option<Writer> {
        let device = &self.devices[d];
        let db = device.st.db.lock().unwrap();
        let folder = device.mem.display().to_string();
        let records = sync_state::load(&db, &folder, &self.channel).unwrap();
        records.get(name).map(|(_, _, writer)| *writer)
    }

    /// The devices that are still the person's.
    fn remaining(&self) -> Vec<usize> {
        (0..self.devices.len())
            .filter(|d| !self.removed.contains(d))
            .collect()
    }

    /// Every device that remains gets the newest key and everything the
    /// others hold, and runs cycles, until nothing changes anywhere.
    fn rest(&mut self) {
        let devices = self.remaining();
        for _ in 0..20 {
            let before: Vec<_> = devices.iter().map(|d| self.whole(*d)).collect();
            for d in &devices {
                self.run(&Step::GetKey(*d));
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

    /// The texts and index lines that a step wrote and that are now in no
    /// file on any device that remains, though no step edited or deleted a
    /// file while it held them. A removed device's folder is gone with it.
    fn lost(&self) -> Vec<String> {
        let mut in_a_file: BTreeSet<(String, String)> = BTreeSet::new();
        let mut index_lines: BTreeSet<String> = BTreeSet::new();
        let mut note = |root: String, text: String| {
            if root == INDEX_FILE {
                index_lines.extend(text.lines().map(String::from));
            }
            in_a_file.insert((root, text));
        };
        for d in self.remaining() {
            let has = self.has(d);
            for (name, text) in has.files {
                note(name, text);
            }
            for (root, text) in has.copies {
                note(root, text);
            }
        }
        let mut lost: Vec<String> = self
            .wrote
            .iter()
            .filter(|text| !in_a_file.contains(*text) && !self.let_go.contains(*text))
            .map(|(root, text)| format!("{root}: {text:?}"))
            .collect();
        lost.extend(
            self.lines
                .iter()
                .filter(|line| !index_lines.contains(*line) && !self.let_go_lines.contains(*line))
                .map(|line| format!("{INDEX_FILE}: the line {line:?}")),
        );
        lost
    }
}

/// Run `steps` on devices of `kinds`, and say what each device has after
/// each step, with the device's number: each device that remains, since
/// one that was removed is in the channel no longer.
fn run(kinds: &[Kind], seed: u64, steps: &[Step]) -> Vec<Vec<(usize, Has)>> {
    let mut world = World::new(kinds, seed);
    steps
        .iter()
        .map(|step| {
            world.run(step);
            let devices = world.remaining();
            devices.into_iter().map(|d| (d, world.has(d))).collect()
        })
        .collect()
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
#[test]
fn local_history_changes_nothing_in_what_sync_does() {
    let mut sequences: Vec<(String, usize, Vec<Step>)> = written()
        .into_iter()
        .map(|(name, n, steps)| (name.to_string(), n, steps))
        .collect();
    for n in 2..=4 {
        for seed in 1..=3 {
            let mut steps = Dice(seed * 7919 + n as u64).steps(n, 60, true);
            steps.extend(sync(n));
            sequences.push((format!("generated, {n} devices, seed {seed}"), n, steps));
        }
    }
    for (name, n, steps) in sequences {
        for seed in [2, 3] {
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

/// The property, for one sequence: run with every device as before, and
/// with devices of `kinds`, it leaves every device that remains, after
/// every step, with the same files that are not conflict files, the same
/// versions in the channel and the same records. Every conflict file of
/// the first run is in the second. Returns whether the second run ends
/// with conflict files that the first does not have: whether the rule
/// made a difference.
fn same_as_before(kinds: &[Kind], seed: u64, steps: &[Step]) -> bool {
    let before = run(&vec![Kind::Before; kinds.len()], seed, steps);
    let built = run(kinds, seed, steps);
    for (i, (was, is)) in before.iter().zip(&built).enumerate() {
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
        steps.extend([Pass(0, 1), Cycle(1), Pass(0, 2), NoWriters(2), Cycle(2)]);
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
    // takes the one that counts and writes over it, and each of the two
    // then hears of that before anything else: the one whose entry lost
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

    // Device 0 moves the channel to a new key and edits under it. Device
    // 1 holds that entry before it has the key, and edits meanwhile.
    let waits = |what: Step| {
        let mut steps = agreed(2, "a.md");
        steps.extend([Edit(1, "a.md"), Cycle(1)]);
        steps.extend(sync(2));
        steps.extend([Edit(0, "a.md"), Line(0), Cycle(0)]);
        steps.extend(sync(2));
        steps.extend([NewKey(0), Edit(0, "a.md"), Line(0), Cycle(0)]);
        steps.extend([Pass(0, 1), Cycle(1), what, Cycle(1)]);
        steps.extend([Pass(1, 0), Cycle(0), GetKey(1), Cycle(1)]);
        steps.extend(sync(2));
        steps
    };
    vec![
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
        ("waiting for a key, an edit", 2, waits(Edit(1, "a.md"))),
        ("waiting for a key, a delete", 2, waits(Delete(1, "a.md"))),
        ("waiting for a key, the index", 2, waits(Line(1))),
    ]
}

/// The property, over the written sequences: with every device as built,
/// and with each mix of devices as built and as before.
#[test]
fn every_file_is_as_it_was_before_in_the_written_sequences() {
    for (name, n, steps) in written() {
        for mix in 1..(1u32 << n) {
            let kinds: Vec<Kind> = (0..n)
                .map(|d| if mix & (1 << d) != 0 { Built } else { Before })
                .collect();
            // Each tie both ways: the two seeds decide every tie the
            // other way from each other.
            for seed in [2, 3] {
                eprintln!("{name}: {kinds:?}, seed {seed}");
                same_as_before(&kinds, seed, &steps);
            }
        }
    }
}

/// How many generated sequences are run for each number of devices:
/// `CORDELIA_SEQUENCES`, or a number that keeps the tests short.
fn sequences() -> u64 {
    std::env::var("CORDELIA_SEQUENCES")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(12)
}

/// The property, over generated sequences of two, three and four devices.
/// The rule makes a difference in a good part of them: a generator that
/// stopped reaching it would leave the property true of nothing.
#[test]
fn every_file_is_as_it_was_before_in_generated_sequences() {
    let (mut run, mut fired) = (0, 0);
    for n in 2..=4 {
        for seed in 1..=sequences() {
            let mut dice = Dice(seed * 7919 + n as u64);
            let mut steps = dice.steps(n, 60, false);
            steps.extend(sync(n));
            run += 1;
            fired += usize::from(same_as_before(&vec![Built; n], seed, &steps));
            // And a mix, chosen by the seed.
            let kinds: Vec<Kind> = (0..n)
                .map(|_| if dice.roll(2) == 0 { Built } else { Before })
                .collect();
            same_as_before(&kinds, seed, &steps);
        }
    }
    assert!(3 * fired >= run, "the rule fired in {fired} of {run}");
}

/// The written sequences do make the rule fire: each run with every
/// device as built ends with a conflict file that the run with every
/// device as before does not have. Without this the property could hold
/// because nothing happened.
#[test]
fn the_written_sequences_make_the_rule_fire() {
    for (name, n, steps) in written() {
        for seed in [2, 3] {
            let copies = |kind: Kind| -> usize {
                let last = run(&vec![kind; n], seed, &steps).pop().unwrap();
                last.iter().map(|(_, has)| has.copies.len()).sum()
            };
            assert!(copies(Built) > copies(Before), "{name}, seed {seed}");
        }
    }
}

/// The keep, over the written sequences and generated ones, with steps
/// that resolve conflict files: when everything has met, no text an edit
/// wrote is in no file, unless a step let go of it.
#[test]
fn no_text_is_lost_that_nobody_let_go_of() {
    let at_rest = |n: usize, seed: u64, steps: &[Step]| {
        let mut world = World::new(&vec![Built; n], seed);
        for step in steps {
            world.run(step);
        }
        world.rest();
        let lost = world.lost();
        assert!(lost.is_empty(), "seed {seed}: {lost:?} after {steps:?}");
    };
    for (_, n, steps) in written() {
        for seed in [2, 3] {
            at_rest(n, seed, &steps);
        }
    }
    for n in 2..=4 {
        for seed in 1..=2 * sequences() {
            let steps = Dice(seed * 104_729 + n as u64).steps(n, 60, true);
            at_rest(n, seed, &steps);
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
/// cycle in which device 2 takes the entry published again, and the rest.
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

/// The steps of [`an_edit_that_tied_with_an_entry_published_again_is_kept`].
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
/// the entry, and publishes it again under its own name, saying nothing,
/// as the node does. Device 2 holds the text. Device 3 edited the file
/// without it, at the same revision.
///
/// Device 3's entry reaches device 1 after the removal, and ties there
/// with the entry device 1 published again. Where device 3's wins, device
/// 1's file takes device 3's text, and its next edit is written from a
/// folder that never held device 0's text. Recorded as the writer of the
/// entry it published again, device 1 was then taken to follow that text
/// on device 2, where it was replaced with nothing kept, and it was in no
/// file anywhere. The record of an entry that says nothing names nobody,
/// and the text is kept. (Each tie goes as the seed says, so the sequence
/// is run with seeds enough for the tie to go each way.)
#[test]
fn a_text_is_kept_through_a_removal() {
    let (until, then) = a_removal_and_then_a_tie();
    let mut kept = 0;
    for seed in 0..8 {
        let mut world = World::new(&[Built; 4], seed);
        for step in &until {
            world.run(step);
        }
        // The entry was published again, and device 2 has taken it for
        // the one it held: its record named device 0, and names nobody.
        assert_eq!(world.writer_of(2, "a.md"), Some(Writer::Nobody), "{seed}");
        for step in &then {
            world.run(step);
        }
        world.rest();
        let lost = world.lost();
        assert!(lost.is_empty(), "seed {seed}: {lost:?}");
        // Where the removed device's text was overtaken on device 2 by
        // an entry that did not follow it, it is in a copy there.
        let theirs = |text: &String| text.starts_with("a.md, written on 0 at step");
        let copied = world.has(2).copies.iter().any(|(_, text)| theirs(text));
        kept += usize::from(copied);
    }
    assert!(kept > 0, "no seed sent the tie the way this is for");
}

/// An edit that tied with an entry which was then published again at a
/// removal is kept. Device 0 writes a text, device 1 takes it, and device
/// 2 edits the file without it: a tie. Device 1 removes device 0,
/// publishing its entry again, and edits the file. That edit says that
/// everything below the entry it was written over is left to its
/// revision, and at that revision whatever said nothing. Device 2's own
/// edit is at that revision, and said what it was written after: so it is
/// not the entry that was written over, and its text is kept. It was
/// replaced with nothing kept. (No tie is read here, so every seed runs
/// alike: two are run, to show that.)
#[test]
fn an_edit_that_tied_with_an_entry_published_again_is_kept() {
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
/// met, with the rule and without it and in every mix of the two, every
/// device that remains has the same files, the same versions in the
/// channel and the same records after every step, and the rule only adds
/// conflict files. With every device as built it does add one, in each of
/// the two, for some seed. (The harness's removal reaches every device at
/// once, and changes no key: what a node does besides is not in it. And
/// the two runs can differ only in the mixes where the device that removes
/// and the device that holds the overtaken text (in the first sequence
/// device 2 or device 3, as the tie goes) are both as built: in the
/// others either nothing that is published after the removal says
/// anything, or the device that holds the overtaken text reads none of
/// it, and the two runs come to the same.)
#[test]
fn the_rule_changes_no_file_through_a_removal() {
    let (until, then) = a_removal_and_then_a_tie();
    let mut first: Vec<Step> = until.into_iter().chain(then).collect();
    first.extend(sync_the_rest(4));
    let mut second = a_tie_and_then_a_removal();
    second.extend(sync_the_rest(3));
    for (n, steps) in [(4, &first), (3, &second)] {
        let mut made_a_difference = 0;
        for mix in 1..(1u32 << n) {
            let kinds: Vec<Kind> = (0..n)
                .map(|d| if mix & (1 << d) != 0 { Built } else { Before })
                .collect();
            for seed in 0..4 {
                let more = same_as_before(&kinds, seed, steps);
                if kinds.iter().all(|kind| *kind == Built) {
                    made_a_difference += usize::from(more);
                }
            }
        }
        assert!(made_a_difference > 0, "{n} devices");
    }
}

/// What an entry published again can cost, on the side of keeping. Device
/// 0 writes a text and is removed by device 1, which then edits the file
/// twice. Device 2 runs no cycle until both edits are there: its record
/// still names device 0, the second edit is not known to follow it, and
/// device 0's text is kept beside the file though both edits were made
/// from it. With one edit the text published over is the one device 2
/// holds, and nothing is kept.
#[test]
fn a_removal_can_cost_a_copy_that_was_not_needed() {
    let theirs = |text: &String| text.starts_with("a.md, written on 0 at step");
    let copies_of_the_removed = |edits: usize| -> usize {
        let mut steps = vec![Edit(0, "a.md"), Cycle(0)];
        steps.extend(sync(3));
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
        assert!(has.files["a.md"].starts_with("a.md, written on 1 at step"));
        has.copies.iter().filter(|(_, text)| theirs(text)).count()
    };
    assert_eq!(copies_of_the_removed(1), 0);
    assert_eq!(copies_of_the_removed(2), 1);
}

/// A record made before the writer was kept says nothing of who wrote
/// the entry, and a version at a higher revision is then taken as it was
/// before, with nothing kept. Here device 2's records are such when the
/// version arrives that overtakes the entry it holds: it keeps nothing,
/// and device 1, which wrote that entry, is the only one that does.
#[test]
fn a_device_whose_records_are_from_before_keeps_nothing() {
    let mut steps = vec![Edit(0, "a.md"), Cycle(0)];
    steps.extend(sync(3));
    steps.extend([Edit(1, "a.md"), Cycle(1), Pass(1, 2), Cycle(2)]);
    steps.extend([Edit(0, "a.md"), Cycle(0), Edit(0, "a.md"), Cycle(0)]);
    steps.extend([NoWriters(2), Pass(0, 2), Cycle(2)]);
    let mut world = World::new(&[Built; 3], 2);
    for step in &steps {
        world.run(step);
    }
    assert!(world.read(2, "a.md").unwrap().contains("written on 0"));
    assert_eq!(world.first_copy(2), None);
    world.rest();
    let only = format!(
        "a.conflict-{}.md",
        hex::encode(&world.devices[1].st.identity.public_key()[..4])
    );
    for d in 0..3 {
        let copies: Vec<String> = world
            .names(d)
            .into_iter()
            .filter(|name| names::is_conflict_name(name))
            .collect();
        assert_eq!(copies, std::slice::from_ref(&only), "device {d}");
    }
}

/// The check that nothing is lost can see what the rule is for: on
/// devices as they were before, one edit against two loses the one, and
/// the check says so.
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
/// overtaken again, and this time device 1 behaves as devices did before:
/// the lines it had are in no index and in no copy, and the check says so.
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
            let name =
                format!("deleted and edited apart (line first: {line_first}, two cycles: {two})");
            all.push((name, 2, deleted_and_edited_apart(2, line_first, two)));
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
    all.push(("two devices deleted it".to_string(), 3, both));

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
            Some(first) => format!("{TWO_TIES}, {first} first"),
        };
        all.push((name, 2, steps));
    }

    // The other device changes the memory's own line meanwhile.
    let mut changed = vec![Edit(0, file), Listed(0, file), Cycle(0)];
    changed.extend(sync(2));
    changed.extend([Unlist(0, file), Delete(0, file), Cycle(0)]);
    changed.extend([Unlist(1, file), Listed(1, file), Edit(1, file), Cycle(1)]);
    changed.extend(sync(2));
    changed.push(Minute(0));
    changed.extend(sync(2));
    all.push(("its own line changed apart".to_string(), 2, changed));

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
    let name = "one deletes, one adds a line, a third edits";
    all.push((name.to_string(), 3, three));

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
    all
}

/// The names of the written sequences that a test asks more of.
const TWO_TIES: &str = "a line added apart";
const OVERTAKEN: &str = "an index edited apart";
const BESIDE: &str = "a version beside";

/// The seeds the written sequences for the index line run with: four
/// pairs, each pair deciding every tie the two ways round, and the pairs
/// deciding them apart from each other. So a sequence with a tie on the
/// file and a tie on the index runs with each of the four ways those two
/// can go (`the_two_ties_go_each_of_the_four_ways` holds that).
fn seeds() -> [u64; 8] {
    [2, 3, 4, 5, 6, 7, 8, 9]
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
fn every_other_file_is_as_without_it(n: usize, seed: u64, steps: &[Step]) {
    let without = run(&vec![Lineless; n], seed, steps);
    let with = run(&vec![Built; n], seed, steps);
    for (i, (was, is)) in without.iter().zip(&with).enumerate() {
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
    /// The world after `steps`, with everything met.
    fn after(kinds: &[Kind], seed: u64, steps: &[Step]) -> World {
        let mut world = World::new(kinds, seed);
        for step in steps {
            world.run(step);
        }
        world.rest();
        world
    }

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
        let device = &self.devices[d];
        let db = device.st.db.lock().unwrap();
        let folder = device.mem.display().to_string();
        let records =
            cordelia_storage::index_lines::whole(&db, &folder, &self.channel, self.now).unwrap();
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

/// Property B, for one sequence; `settled` asks it after the minutes of
/// property C as well.
fn no_line_is_lost_to_a_put_back(n: usize, seed: u64, steps: &[Step]) {
    let without = World::after(&vec![Lineless; n], seed, steps);
    let mut with = World::after(&vec![Built; n], seed, steps);
    let expected: Vec<String> = without
        .lines_listed(false)
        .into_iter()
        .filter(|line| lines::line_for(line).is_none_or(|file| !without.deleted.contains(file)))
        .collect();
    for settled in [false, true] {
        if settled {
            with.settle_lines();
        }
        let there = with.lines_listed(true);
        for line in &expected {
            assert!(
                there.contains(line),
                "seed {seed}, settled: {settled}: the line {line:?} is in no index and no copy \
                 after {steps:?}"
            );
        }
    }
}

/// Property C, for one sequence. Returns whether a line was put back.
fn a_line_that_is_due_goes_back(n: usize, seed: u64, steps: &[Step]) -> bool {
    let mut world = World::after(&vec![Built; n], seed, steps);
    world.settle_lines();
    for d in world.remaining() {
        let unlisted = world.unlisted(d);
        assert!(
            unlisted.is_empty(),
            "seed {seed}, device {d}: {unlisted:?} back and not listed after {steps:?}"
        );
    }
    world.put_back > 0
}

/// The generated sequences for the index line: for two, three and four
/// devices.
fn generated_for_lines() -> Vec<(usize, u64, Vec<Step>)> {
    let mut all = Vec::new();
    for n in 2..=4 {
        for seed in 1..=sequences() {
            let mut steps = Dice(seed * 15_485_863 + n as u64).line_steps(n, 50);
            steps.extend(sync(n));
            all.push((n, seed, steps));
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
            every_other_file_is_as_without_it(n, seed, &steps);
        }
    }
    for (n, seed, steps) in generated_for_lines() {
        every_other_file_is_as_without_it(n, seed, &steps);
    }
}

/// Property B: a put-back loses no line.
#[test]
fn a_put_back_loses_no_line() {
    for (name, n, steps) in written_for_lines() {
        for seed in seeds() {
            eprintln!("{name}, seed {seed}");
            no_line_is_lost_to_a_put_back(n, seed, &steps);
        }
    }
    for (n, seed, steps) in generated_for_lines() {
        no_line_is_lost_to_a_put_back(n, seed, &steps);
    }
}

/// Property C: where a memory is back and its line is due, the line goes
/// back. And the sequences reach the rule: in each written one, and in a
/// good part of the generated ones, a line is put back. Without that the
/// three properties could be true of nothing.
#[test]
fn a_memory_that_is_back_is_listed() {
    for (name, n, steps) in written_for_lines() {
        // With a tie in it, a sequence can leave the line in place one
        // way round (the delete wins, the other device's index arrives
        // with the line in it): it reaches the rule the other way.
        let reached = seeds().map(|seed| {
            eprintln!("{name}, seed {seed}");
            a_line_that_is_due_goes_back(n, seed, &steps)
        });
        assert!(reached.contains(&true), "{name}: no line went back");
    }
    let (mut run, mut reached) = (0, 0);
    for (n, seed, steps) in generated_for_lines() {
        run += 1;
        reached += usize::from(a_line_that_is_due_goes_back(n, seed, &steps));
    }
    eprintln!("a line went back in {reached} of {run} generated sequences");
    assert!(4 * reached >= run, "a line went back in {reached} of {run}");
}

/// The written sequences end as they should: every device has the memory
/// and one line for it.
#[test]
fn a_memory_deleted_here_and_edited_there_is_listed_once_everywhere() {
    for (name, n, steps) in written_for_lines() {
        for seed in seeds() {
            for kinds in [vec![Built; n], {
                // The other devices without the change: the device that
                // deleted puts the line back all the same.
                let mut kinds = vec![Lineless; n];
                kinds[0] = Built;
                kinds
            }] {
                // Two devices deleted it: both have the change.
                let kinds = match name.starts_with("two devices") {
                    true => vec![Built; n],
                    false => kinds,
                };
                let mut world = World::after(&kinds, seed, &steps);
                world.settle_lines();
                world.rest();
                for d in world.remaining() {
                    let at = format!("{name}, seed {seed}, {kinds:?}, device {d}");
                    assert!(world.read(d, "notes.md").is_some(), "{at}");
                    let index = world.read(d, INDEX_FILE).unwrap();
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
/// runs with each of the four ways the two can go: the properties above
/// are asked of all four.
#[test]
fn the_two_ties_go_each_of_the_four_ways() {
    let (_, n, steps) = written_for_lines()
        .into_iter()
        .find(|(name, ..)| name == TWO_TIES)
        .unwrap();
    let mut ways = BTreeSet::new();
    for seed in seeds() {
        let world = World::after(&vec![Built; n], seed, &steps);
        let won = |name: &str| -> Vec<bool> {
            let ties = world.ties.iter().filter(|(tied, _)| tied == name);
            ties.map(|(_, won)| *won).collect()
        };
        let (file, index) = (won("notes.md"), won(INDEX_FILE));
        assert_eq!(
            (file.len(), index.len()),
            (1, 1),
            "seed {seed}: one tie each"
        );
        ways.insert((file[0], index[0]));
    }
    assert_eq!(ways.len(), 4, "{ways:?}");
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
            let mut world = World::after(&vec![Built; n], seed, &steps);
            let at = format!("{name}, seed {seed}");
            if name == OVERTAKEN {
                // The line went back before the other device's index edit
                // was heard where the memory's edit won its tie at once:
                // the other way round the memory comes back only when
                // the two have met, and the indexes have merged by then.
                if world.put_back > 0 {
                    overtaken += 1;
                    let copies = world.has(1).copies;
                    assert!(
                        copies.iter().any(|(root, _)| root == INDEX_FILE),
                        "{at}: the overtaken index is in no copy"
                    );
                }
                continue;
            }
            world.settle_lines();
            world.rest();
            for d in world.remaining() {
                let has = world.has(d);
                let index = has.files.get(INDEX_FILE).cloned().unwrap_or_default();
                for (_, copy) in has.copies.iter().filter(|(root, _)| root == INDEX_FILE) {
                    for line in copy.lines() {
                        let gone =
                            lines::line_for(line).is_some_and(|file| world.deleted.contains(file));
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
