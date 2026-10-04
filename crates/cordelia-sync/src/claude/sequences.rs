//! What several devices come to over a sequence of edits, deletes and
//! syncs, for the rule that an entry says what it was written after
//! (decision 2026-09-30 §4.5).
//!
//! Two things are checked, each over written and generated sequences:
//!
//! - **The property.** The rule changes one thing: where a file would be
//!   replaced by a version at a higher revision that is not known to
//!   follow the one the folder agreed, what the file held is kept first.
//!   So a run with every device as it is built, and a run of the same
//!   sequence with every device as it was before, end every step with
//!   the same files, the same versions in the channel and the same
//!   records. Only the conflict files may differ, and only by there being
//!   more of them.
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
    /// records with no writer.
    Before,
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
            author: Some(r.author),
        })
    };
    let pull = |r: &Remote, c: &Content| Action::Pull {
        text: c.text.clone(),
        rev: r.rev,
        author: r.author,
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
                    author: r.author,
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
            wrote: BTreeSet::new(),
            lines: BTreeSet::new(),
            let_go: BTreeSet::new(),
            let_go_lines: BTreeSet::new(),
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
            Step::Delete(d, name) => self.put(*d, name, None),
            Step::Cycle(d) => self.cycle(*d),
            Step::Pass(from, to) => self.send(*from, *to, None),
            Step::PassOne(from, to, name) => self.send(*from, *to, Some(name)),
            Step::NoWriters(d) => {
                let db = self.devices[*d].st.db.lock().unwrap();
                db.execute("UPDATE sync_files SET author = NULL", [])
                    .unwrap();
            }
            Step::AsBefore(d) => self.devices[*d].kind = Kind::Before,
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
                Kind::Built => plan::plan,
                Kind::Before => plan_before,
            },
            listed: &|| {},
            between: &|| {},
            flushed: &|_| {},
            says_nothing: device.kind == Kind::Before,
        };
        let generation = device.st.sync_control.generation();
        let report = sync_folder_with(
            &device.st,
            &device.mem,
            &self.channel,
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
        self.settle_ties(d);
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

    /// Every device gets the newest key and everything the others hold,
    /// and runs cycles, until nothing changes anywhere.
    fn rest(&mut self) {
        let n = self.devices.len();
        for _ in 0..20 {
            let before: Vec<_> = (0..n).map(|d| self.whole(d)).collect();
            for d in 0..n {
                self.run(&Step::GetKey(d));
            }
            for from in 0..n {
                for to in 0..n {
                    if from != to {
                        self.run(&Step::Pass(from, to));
                    }
                }
            }
            for d in 0..n {
                self.run(&Step::Cycle(d));
            }
            let after: Vec<_> = (0..n).map(|d| self.whole(d)).collect();
            if after == before {
                return;
            }
        }
        panic!("the devices did not come to rest");
    }

    /// The texts and index lines that a step wrote and that are now in no
    /// file on any device, though no step edited or deleted a file while
    /// it held them.
    fn lost(&self) -> Vec<String> {
        let n = self.devices.len();
        let mut in_a_file: BTreeSet<(String, String)> = BTreeSet::new();
        let mut index_lines: BTreeSet<String> = BTreeSet::new();
        let mut note = |root: String, text: String| {
            if root == INDEX_FILE {
                index_lines.extend(text.lines().map(String::from));
            }
            in_a_file.insert((root, text));
        };
        for d in 0..n {
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
/// each step.
fn run(kinds: &[Kind], seed: u64, steps: &[Step]) -> Vec<Vec<Has>> {
    let mut world = World::new(kinds, seed);
    steps
        .iter()
        .map(|step| {
            world.run(step);
            (0..kinds.len()).map(|d| world.has(d)).collect()
        })
        .collect()
}

/// The property, for one sequence: run with every device as before, and
/// with devices of `kinds`, it leaves every device after every step with
/// the same files that are not conflict files, the same versions in the
/// channel and the same records. Every conflict file of the first run is
/// in the second. Returns whether the second run ends with conflict files
/// that the first does not have: whether the rule made a difference.
fn same_as_before(kinds: &[Kind], seed: u64, steps: &[Step]) -> bool {
    let before = run(&vec![Kind::Before; kinds.len()], seed, steps);
    let built = run(kinds, seed, steps);
    for (i, (was, is)) in before.iter().zip(&built).enumerate() {
        for (d, (was, is)) in was.iter().zip(is).enumerate() {
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
    let copies = |last: &[Has]| -> usize { last.iter().map(|has| has.copies.len()).sum() };
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
                last.iter().map(|has| has.copies.len()).sum()
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
