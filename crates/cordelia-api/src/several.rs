//! Several devices of one person: a fixture for tests, and the tests that
//! take more than one device (decision 2026-10-04 §4 to §8).
//!
//! Each device has a database of its own, in memory, and a key of its
//! own. Nothing is shared between two of them. What one device wrote
//! reaches another through the two doors a node has: an entry of a
//! channel goes through [`take`], and the entry of a pair channel is
//! given to [`accept`] with the key that a person typed.

use std::collections::HashMap;
use std::ops::Index;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use rusqlite::types::ValueRef;

use cordelia_core::protocol::{
    CHANGE_ENTRY_DEVICES_PART_BYTES, LABEL_CHANGE_DEVICES, LABEL_ENTRY_AUTHOR, LABEL_ENTRY_CHANNEL,
    SEALED_SECRET_BYTES,
};
use cordelia_crypto::change_entry::{self, ForPhrase};
use cordelia_crypto::derive;
use cordelia_crypto::ecies::ecies_encrypt;
use cordelia_crypto::entry::{CheckedEntry, Entry, Inside, Link, Value};
use cordelia_crypto::identity::{NodeIdentity, x25519_pub_from_ed25519_pub};
use cordelia_crypto::phrase::Phrase;
use cordelia_crypto::slots::slot_id;
use cordelia_crypto::statement::{Device, SignedStatement};
use cordelia_crypto::version::{self, Slot};
use cordelia_crypto::{item_decrypt, item_encrypt};
use cordelia_storage::db;
use cordelia_storage::entries;
use cordelia_storage::meta;
use cordelia_storage::person::{self as held_rows, Kept, State};

use crate::adding::{Accepted, Added, accept, add_device};
use crate::carry::{Allows, Word};
use crate::change::make_change;
use crate::person::{
    Applied, Held, Shown, applied_name, applied_secret, first_statement, held, hold_name,
    kept_entry, latest_entry, shown, who_counts,
};
use crate::publish::{PlannedAgainst, Published, Write, publish, read, value_hash};
use crate::state::{AppState, DoorAsk, LeftAt, LeftRead, ProvedBy};
use crate::take::{Taken, take};

pub(crate) const WORDS: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
pub(crate) const OTHER_WORDS: &str =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

/// When the clock of a fixture starts, in seconds.
pub(crate) const START: i64 = 1_800_000_000;

/// One device: its database, its key, and what a person calls it.
pub(crate) struct Machine {
    pub(crate) conn: Connection,
    pub(crate) identity: NodeIdentity,
    pub(crate) label: String,
}

/// The key pair of the device numbered `n`.
pub(crate) fn identity_of(n: u16) -> NodeIdentity {
    let mut seed = [0x5a; 32];
    seed[..2].copy_from_slice(&n.to_be_bytes());
    NodeIdentity::from_seed(seed).unwrap()
}

/// The device numbered `n`, as a statement lists it.
pub(crate) fn listed_as(n: u16) -> Device {
    Device::new(identity_of(n).public_key(), &format!("device {n}")).unwrap()
}

impl Machine {
    /// The device numbered `n`: a new install, which follows no phrase.
    pub(crate) fn new(n: u16) -> Self {
        Self {
            conn: db::open_in_memory().unwrap(),
            identity: identity_of(n),
            label: format!("device {n}"),
        }
    }

    pub(crate) fn key(&self) -> [u8; 32] {
        self.identity.public_key()
    }

    /// The device as a statement lists it.
    pub(crate) fn listed(&self) -> Device {
        Device::new(self.key(), &self.label).unwrap()
    }

    /// What the device holds of its person. It follows a phrase.
    pub(crate) fn held(&self) -> Held {
        held(&self.conn).unwrap().unwrap()
    }

    pub(crate) fn follows_a_phrase(&self) -> bool {
        held(&self.conn).unwrap().is_some()
    }

    pub(crate) fn state(&self) -> State {
        self.held().state
    }

    /// The number of the statement the device has applied.
    pub(crate) fn number(&self) -> u64 {
        self.held().statement.statement.number
    }

    /// The person secret of the statement the device has applied.
    pub(crate) fn secret(&self) -> [u8; 32] {
        applied_secret(&self.conn, &self.held().statement.statement).unwrap()
    }

    /// The secret of the personal channel in the generation applied.
    pub(crate) fn personal(&self) -> [u8; 32] {
        derive::personal_secret(&self.secret()).unwrap()
    }

    /// The secret of the channel of `name` in the generation applied.
    pub(crate) fn own(&self, name: &str) -> [u8; 32] {
        derive::own_secret(&self.secret(), name).unwrap()
    }

    /// Whether `key` counts for this device.
    pub(crate) fn counts(&self, key: &[u8; 32]) -> bool {
        who_counts(&self.conn).unwrap().counts(key)
    }

    /// The change entry the device keeps as the latest it has seen.
    pub(crate) fn latest(&self) -> CheckedEntry {
        latest_entry(&self.conn).unwrap()
    }

    /// The change entry the device keeps of a statement made apart.
    pub(crate) fn apart(&self) -> Option<CheckedEntry> {
        kept_entry(&self.conn, Kept::Apart).unwrap()
    }

    /// Every entry the device's store holds, of every channel, in the
    /// order it stored them.
    pub(crate) fn stored(&self) -> Vec<CheckedEntry> {
        let channels: Vec<[u8; 32]> = self
            .conn
            .prepare("SELECT DISTINCT channel_id FROM entries")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let mut all = Vec::new();
        for channel in channels {
            all.extend(entries::channel_entries_after(&self.conn, &channel, 0, 100_000).unwrap());
        }
        all.sort_by_key(|held| held.seq);
        all.into_iter()
            .map(|held| held.entry.check().unwrap())
            .collect()
    }

    /// The entries the store holds of the channel whose secret is
    /// `channel`, in the order it stored them.
    pub(crate) fn stored_in(&self, channel: &[u8; 32]) -> Vec<CheckedEntry> {
        let id = derive::channel_id(channel).unwrap();
        entries::channel_entries_after(&self.conn, &id, 0, 100_000)
            .unwrap()
            .into_iter()
            .map(|held| held.entry.check().unwrap())
            .collect()
    }

    /// The slot of `file` in the name `name`, as the device reads it.
    pub(crate) fn slot(&self, name: &str, file: &str) -> Slot {
        read(&self.conn, name, file).unwrap().slot
    }

    /// Whether the current version of `file` in `name`, as the device
    /// reads it, is known to follow the text `said`.
    pub(crate) fn follows(&self, name: &str, file: &str, said: &str) -> bool {
        let agreed = value_hash(&text(said));
        read(&self.conn, name, file).unwrap().follows(&agreed)
    }

    /// The text that is the current version of `file` in `name`.
    pub(crate) fn text(&self, name: &str, file: &str) -> Option<String> {
        match self.slot(name, file).current?.value {
            Value::Text(text) => Some(text),
            other => Some(format!("{other:?}")),
        }
    }

    /// The word of the device whose key is `key` that it has applied a
    /// statement, as this device holds it in the personal channel: that
    /// device's own entry under its own name there.
    pub(crate) fn word_of(&self, key: &[u8; 32]) -> Option<Value> {
        let personal = self.personal();
        let name = applied_name(key).unwrap();
        let slot = slot_id(&derive::slot_key(&personal).unwrap(), &name);
        let id = derive::channel_id(&personal).unwrap();
        let held = entries::slot_entries(&self.conn, &id, &slot).unwrap();
        let read = version::current(&held, &personal, self.number(), |by| by == key).unwrap();
        read.current.map(|version| version.value)
    }

    /// Everything the device holds: every row of the store of entries, of
    /// its counter, and of what the device holds of its person.
    pub(crate) fn everything(&self) -> Vec<String> {
        let mut all = Vec::new();
        for table in [
            "entries",
            "counters",
            "person",
            "person_secrets",
            "person_change_entries",
            "person_additions",
            "person_names",
            "person_hand_overs",
        ] {
            let mut stmt = self
                .conn
                .prepare(&format!("SELECT * FROM {table}"))
                .unwrap();
            let columns = stmt.column_count();
            let rows = stmt
                .query_map([], |row| {
                    let mut said = format!("{table}:");
                    for column in 0..columns {
                        said.push(' ');
                        said.push_str(&match row.get_ref(column)? {
                            ValueRef::Null => "null".to_string(),
                            ValueRef::Integer(n) => n.to_string(),
                            ValueRef::Real(n) => n.to_string(),
                            ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                            ValueRef::Blob(b) => hex::encode(b),
                        });
                    }
                    Ok(said)
                })
                .unwrap();
            all.extend(rows.map(Result::unwrap));
        }
        all.sort_unstable();
        all
    }
}

/// Several devices, the phrase of the person they come to be devices of,
/// and a clock that every act moves on by a second.
pub(crate) struct Several {
    pub(crate) phrase: Phrase,
    pub(crate) machines: Vec<Machine>,
    pub(crate) now: i64,
}

impl Index<usize> for Several {
    type Output = Machine;

    fn index(&self, n: usize) -> &Machine {
        &self.machines[n]
    }
}

impl Several {
    /// `count` new installs, numbered from 0. None follows a phrase.
    pub(crate) fn new(count: u16) -> Self {
        Self {
            phrase: Phrase::parse(WORDS).unwrap(),
            machines: (0..count).map(Machine::new).collect(),
            now: START,
        }
    }

    /// `count` devices of one person: the phrase is made on device 0,
    /// which adds each of the others, and each has then been given what
    /// every other holds.
    pub(crate) fn of_one_person(count: u16) -> Self {
        let mut several = Self::new(count);
        several.make_phrase(0);
        for new in 1..usize::from(count) {
            assert!(matches!(several.add(0, new), Accepted::Joined(_)));
        }
        let all: Vec<usize> = (0..usize::from(count)).collect();
        several.meet(&all);
        several
    }

    /// The clock moves on by a second.
    pub(crate) fn tick(&mut self) -> i64 {
        self.now += 1;
        self.now
    }

    /// The key of device `n`.
    pub(crate) fn key(&self, n: usize) -> [u8; 32] {
        self[n].key()
    }

    /// The devices numbered so, as a statement lists them.
    pub(crate) fn listed(&self, numbers: &[usize]) -> Vec<Device> {
        numbers.iter().map(|n| self[*n].listed()).collect()
    }

    /// The fixture's phrase is made on device `n`, which follows it.
    pub(crate) fn make_phrase(&mut self, n: usize) -> Applied {
        let now = self.tick();
        let on = &self.machines[n];
        first_statement(&on.conn, &on.identity, &self.phrase, &on.label, now).unwrap()
    }

    /// Device `adder` adds device `new`: the first half, on the device
    /// that adds.
    pub(crate) fn hand(&mut self, adder: usize, new: usize) -> Added {
        let now = self.tick();
        let (from, to) = (&self[adder], &self[new]);
        add_device(&from.conn, &from.identity, &to.key(), &to.label, now).unwrap()
    }

    /// Device `new` accepts `hand_over` with the key of device `adder`,
    /// typed just now, and with sync off.
    pub(crate) fn accept(
        &mut self,
        new: usize,
        adder: usize,
        hand_over: &CheckedEntry,
    ) -> Accepted {
        let now = self.tick();
        let (from, to) = (&self[adder], &self[new]);
        accept(
            &to.conn,
            &to.identity,
            &from.key(),
            now,
            false,
            hand_over,
            now,
        )
        .unwrap()
    }

    /// Device `adder` adds device `new`, and device `new` accepts.
    pub(crate) fn add(&mut self, adder: usize, new: usize) -> Accepted {
        let added = self.hand(adder, new);
        self.accept(new, adder, &added.hand_over)
    }

    /// Device `to` is given everything that device `from` holds: the
    /// change entry it keeps, which is shown before everything, and then
    /// every entry of its store, in the order it stored them. Each goes
    /// through the one door, and what became of each is returned.
    pub(crate) fn pass(&mut self, from: usize, to: usize) -> Vec<Taken> {
        let now = self.tick();
        let mut given = Vec::new();
        let kept = held_rows::change_entry(&self[from].conn, Kept::Latest).unwrap();
        given.extend(kept.map(|entry| entry.check().unwrap()));
        given.extend(self[from].stored());
        let to = &self[to];
        given
            .iter()
            .map(|entry| take(&to.conn, &to.identity, entry, now).unwrap())
            .collect()
    }

    /// Each of the devices numbered so is given what each other holds.
    pub(crate) fn meet(&mut self, who: &[usize]) {
        for from in who {
            for to in who {
                if from != to {
                    self.pass(*from, *to);
                }
            }
        }
    }

    /// Each of the devices numbered so holds the name `name`.
    pub(crate) fn hold(&mut self, who: &[usize], name: &str) {
        let now = self.tick();
        for n in who {
            hold_name(&self[*n].conn, name, now).unwrap();
        }
    }

    /// Device `n` writes the text `said` under `file` in `name`, over
    /// what it reads there: what a publish does that was planned just
    /// now.
    pub(crate) fn publish(&mut self, n: usize, name: &str, file: &str, said: &str) -> Published {
        let now = self.tick();
        let on = &self[n];
        let write = Write {
            name,
            file,
            value: text(said),
            planned: PlannedAgainst::what_is_in(&on.slot(name, file)),
            merge: None,
        };
        publish(&on.conn, &on.identity, &write, now).unwrap()
    }

    /// [`Several::publish`], where the entry is made.
    pub(crate) fn write(&mut self, n: usize, name: &str, file: &str, said: &str) -> CheckedEntry {
        match self.publish(n, name, file, said) {
            Published::Made(entry) => *entry,
            other => panic!("{other:?}"),
        }
    }

    /// A change is made on device `maker`, with the phrase: the devices
    /// numbered in `stay` stay, and those in `removed` are removed. The
    /// maker is shown the entry, and applies it. Returns the change entry.
    pub(crate) fn change(
        &mut self,
        maker: usize,
        stay: &[usize],
        removed: &[usize],
    ) -> CheckedEntry {
        let now = self.tick();
        let removed: Vec<[u8; 32]> = removed.iter().map(|n| self.key(*n)).collect();
        let on = &self[maker];
        let entry = make_change(
            &self.phrase,
            &on.held().statement,
            &on.latest(),
            &on.key(),
            self.listed(stay),
            &removed,
        )
        .unwrap();
        let outcome = shown(&on.conn, &on.identity, &entry, now).unwrap();
        assert!(matches!(outcome, Shown::Applied(_)), "{outcome:?}");
        entry
    }
}

/// A node's state over the database and the key of `machine`, with no
/// network: what a handler is given.
pub(crate) fn state_of(machine: Machine) -> crate::state::AppState {
    crate::state::AppState {
        db: std::sync::Mutex::new(machine.conn),
        identity: machine.identity,
        bearer_token: "t".into(),
        home_dir: std::env::temp_dir().join("cordelia-several-test-no-such-directory"),
        started_at: std::time::Instant::now(),
        sync_errors: Default::default(),
        peers_hot: Default::default(),
        peers_warm: Default::default(),
        push_tx: None,
        announce_tx: None,
        peers: Default::default(),
        relays: Default::default(),
        outbox_refused: Default::default(),
        relist: Default::default(),
        sync_control: Default::default(),
        own_channels: Default::default(),
        held: Default::default(),
        history: Default::default(),
    }
}

// ── A node with a network, and a stand-in for its loop ───────────────

fn db(state: &AppState) -> std::sync::MutexGuard<'_, Connection> {
    state.db.lock().unwrap_or_else(|e| e.into_inner())
}

/// The clock that a route goes by, in seconds.
fn wall_clock() -> i64 {
    chrono::Utc::now().timestamp()
}

/// What the relay of a test holds: for each channel, its entries, as
/// their bytes on the wire.
pub(crate) type AtTheRelay = Arc<Mutex<HashMap<[u8; 32], Vec<Vec<u8>>>>>;

/// What was asked through the door: each channel, with whether the
/// node proved its key itself.
pub(crate) type Asked = Arc<Mutex<Vec<([u8; 32], bool)>>>;

/// A node of a test: its state, with a network; what its one relay
/// holds; and what was asked through the door, each channel with
/// whether the node proved its key itself.
pub(crate) struct Node {
    pub(crate) state: Arc<AppState>,
    pub(crate) relay: AtTheRelay,
    pub(crate) asked: Asked,
    /// What the stand-in did, in order: `pass` for a whole pass, which
    /// shows the change entry to every relay first, and `read` for a
    /// channel read through the door.
    pub(crate) did: Arc<Mutex<Vec<&'static str>>>,
    /// Whether the relay hands a channel in part, and not to its end.
    pub(crate) in_part: Arc<std::sync::atomic::AtomicBool>,
    /// How many of the next whole passes end before they have read every
    /// channel to its end.
    pub(crate) short_passes: Arc<std::sync::atomic::AtomicUsize>,
    /// Whether the relay is not connected: it has no session.
    pub(crate) not_connected: Arc<std::sync::atomic::AtomicBool>,
    /// How many of the next reads through the door find that the
    /// connection has no room left for a proof.
    pub(crate) no_room: Arc<std::sync::atomic::AtomicUsize>,
    /// How often the connection to the relay was made again: each has a
    /// session of its own ([`session_after`]).
    pub(crate) remade: Arc<std::sync::atomic::AtomicUsize>,
    /// How many askings for the sessions it takes, once a connection is
    /// to be made again, until the new one is there: until then the old
    /// session is said, and a read finds the old connection, with no
    /// room.
    pub(crate) remake_takes: Arc<std::sync::atomic::AtomicUsize>,
    /// At each read through the door: the channels that a folder's first
    /// cycle waits for a carry in, and would still wait for a second
    /// short of the longest that a carry holds one back, measured from
    /// the read.
    pub(crate) held_back_at_reads: Arc<Mutex<Vec<std::collections::BTreeSet<[u8; 32]>>>>,
}

/// The session of the connection to the relay of a test.
pub(crate) const SESSION: [u8; 32] = [5; 32];

/// The session of the connection to the relay of a test once it was
/// made again so often: [`SESSION`], while it was not.
pub(crate) fn session_after(remade: usize) -> [u8; 32] {
    [SESSION[0] + remade as u8; 32]
}

impl Node {
    /// The node of `machine`, with a stand-in for its loop: asked for
    /// a whole pass it makes one; asked through the door it answers
    /// for its one relay, `relay`, with what that holds of the
    /// channel.
    pub(crate) fn of(machine: Machine) -> Self {
        let mut state = state_of(machine);
        state.push_tx = Some(tokio::sync::mpsc::unbounded_channel().0);
        let state = Arc::new(state);
        let relay: AtTheRelay = Default::default();
        let asked: Asked = Default::default();
        let did: Arc<Mutex<Vec<&'static str>>> = Default::default();
        let (passes, order) = (Arc::clone(&state), Arc::clone(&did));
        let short_passes: Arc<std::sync::atomic::AtomicUsize> = Default::default();
        let short = Arc::clone(&short_passes);
        tokio::spawn(async move {
            use std::sync::atomic::Ordering::SeqCst;
            loop {
                passes.own_channels.wait_asked().await;
                let pass = passes.own_channels.whole_pass_begins();
                order.lock().unwrap().push("pass");
                let ends_short = short
                    .fetch_update(SeqCst, SeqCst, |left| left.checked_sub(1))
                    .is_ok();
                if ends_short {
                    passes.own_channels.whole_pass_was_short(pass);
                }
                passes.own_channels.whole_pass_ended(pass);
            }
        });
        let (node, holds, log) = (Arc::clone(&state), Arc::clone(&relay), Arc::clone(&asked));
        let order = Arc::clone(&did);
        let in_part: Arc<std::sync::atomic::AtomicBool> = Default::default();
        let part = Arc::clone(&in_part);
        let not_connected: Arc<std::sync::atomic::AtomicBool> = Default::default();
        let away = Arc::clone(&not_connected);
        let no_room: Arc<std::sync::atomic::AtomicUsize> = Default::default();
        let full = Arc::clone(&no_room);
        let remade: Arc<std::sync::atomic::AtomicUsize> = Default::default();
        let made_again = Arc::clone(&remade);
        let remake_takes: Arc<std::sync::atomic::AtomicUsize> = Default::default();
        let takes = Arc::clone(&remake_takes);
        let held_back_at_reads: Arc<Mutex<Vec<std::collections::BTreeSet<[u8; 32]>>>> =
            Default::default();
        let held_back = Arc::clone(&held_back_at_reads);
        tokio::spawn(async move {
            use std::sync::atomic::Ordering::SeqCst;
            // How many askings for the sessions are still answered with
            // the session of the connection that is being made again.
            let mut not_there_for = 0usize;
            loop {
                match node.own_channels.wait_door().await {
                    DoorAsk::Sessions { answer } => {
                        let made = made_again.load(SeqCst);
                        let session = match (away.load(SeqCst), not_there_for) {
                            (true, _) => None,
                            (false, 0) => Some(session_after(made)),
                            (false, _) => Some(session_after(made - 1)),
                        };
                        not_there_for = not_there_for.saturating_sub(1);
                        let _ = answer.send(vec![("relay".to_string(), session)]);
                    }
                    DoorAsk::Remake { answer, .. } => {
                        order.lock().unwrap().push("remake");
                        made_again.fetch_add(1, SeqCst);
                        // The asking that notes the session from before
                        // is answered with it, and so many after it.
                        not_there_for = takes.load(SeqCst);
                        let _ = answer.send(true);
                    }
                    DoorAsk::Read { answer, .. }
                        if not_there_for > 0
                            || full
                                .fetch_update(SeqCst, SeqCst, |left| left.checked_sub(1))
                                .is_ok() =>
                    {
                        order.lock().unwrap().push("no room");
                        let _ = answer.send(vec![LeftAt {
                            relay: "relay".into(),
                            read: LeftRead::NoRoom,
                        }]);
                    }
                    // Proofs that were made over another session than
                    // the connection's hold nowhere: the connection
                    // changed.
                    DoorAsk::Read {
                        by: ProvedBy::Proofs(made),
                        answer,
                        ..
                    } if !made.iter().any(|made| {
                        made.relay == "relay"
                            && made.session == session_after(made_again.load(SeqCst))
                    }) =>
                    {
                        order.lock().unwrap().push("changed");
                        let _ = answer.send(vec![LeftAt {
                            relay: "relay".into(),
                            read: LeftRead::Changed,
                        }]);
                    }
                    DoorAsk::Read {
                        channel,
                        by,
                        answer,
                        ..
                    } => {
                        let by_secret = matches!(by, ProvedBy::Secret(_));
                        log.lock().unwrap().push((channel, by_secret));
                        order.lock().unwrap().push("read");
                        let nearly = std::time::Duration::from_secs(
                            cordelia_core::protocol::CARRY_FIRST_MAX_SECS - 1,
                        );
                        let then = std::time::Instant::now() + nearly;
                        let waits = node.own_channels.carried_into(then);
                        held_back.lock().unwrap().push(waits);
                        let read = match holds.lock().unwrap().get(&channel) {
                            None => LeftRead::NotHeld,
                            Some(entries) => LeftRead::Read {
                                entries: entries.clone(),
                                whole: !part.load(std::sync::atomic::Ordering::SeqCst),
                            },
                        };
                        let _ = answer.send(vec![LeftAt {
                            relay: "relay".into(),
                            read,
                        }]);
                    }
                }
            }
        });
        Self {
            state,
            relay,
            asked,
            did,
            in_part,
            short_passes,
            not_connected,
            no_room,
            remade,
            remake_takes,
            held_back_at_reads,
        }
    }

    /// The relay holds `entries` of the channel whose secret is
    /// `secret`.
    pub(crate) fn relay_holds(&self, secret: &[u8; 32], entries: &[CheckedEntry]) {
        let channel = derive::channel_id(secret).unwrap();
        let wire = entries.iter().map(|entry| entry.to_wire()).collect();
        self.relay.lock().unwrap().insert(channel, wire);
    }

    /// The text of `file` in `name`, as the node reads it.
    pub(crate) fn text(&self, name: &str, file: &str) -> Option<String> {
        let conn = db(&self.state);
        match read(&conn, name, file).ok()?.slot.current?.value {
            Value::Text(text) => Some(text),
            other => Some(format!("{other:?}")),
        }
    }

    /// How many entries the node's store holds.
    pub(crate) fn stored(&self) -> i64 {
        let conn = db(&self.state);
        conn.query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
            .unwrap()
    }

    /// A word of `phrase` for `allows`, given now on this node's
    /// device, under the change entry that it keeps.
    pub(crate) fn word(&self, phrase: &Phrase, allows: &Allows) -> Word {
        let under = latest_entry(&db(&self.state)).unwrap().id();
        let own = self.state.identity.public_key();
        Word::give(phrase, &own, &under, allows.says().unwrap(), wall_clock()).unwrap()
    }

    /// A folder of this device's is mapped to `name`.
    pub(crate) fn maps_a_folder(&self, name: &str) {
        let mapped = serde_json::json!([{ "folder": "/home/sam/notes", "name": name }]).to_string();
        meta::set(&db(&self.state), meta::SYNC_CLAUDE_MAPPINGS, &mapped).unwrap();
    }
}

pub(crate) fn text(said: &str) -> Value {
    Value::Text(said.to_string())
}

/// What a device can write after `name/` in the personal channel that is
/// no name as this version would map one (decision 2026-10-04 §16): an
/// escape sequence, a new line, a name of great length, and names in
/// another spelling. Each holds `NOT-A-NAME`, so that a test can look for
/// any of them in what is shown.
pub(crate) fn words_that_are_no_names() -> Vec<String> {
    vec![
        "\x1b[2J\x1b[31mNOT-A-NAME-escape".to_string(),
        "NOT-A-NAME-two\nlines".to_string(),
        format!("NOT-A-NAME-long-{}", "x".repeat(60_000)),
        "NOT-A-NAME-In-Capitals".to_string(),
        "not-a-name-NOT-A-NAME.git".to_string(),
        " NOT-A-NAME-with-space ".to_string(),
    ]
}

/// Device `by` writes a word in its personal channel for each of
/// [`words_that_are_no_names`], as only a device that does not run this
/// code would, and device `to` is given all that `by` holds. Returns how
/// many it wrote.
pub(crate) fn writes_words_that_are_no_names(s: &mut Several, by: usize, to: usize) -> usize {
    let now = s.tick();
    let personal = s[by].personal();
    let no_names = words_that_are_no_names();
    for no_name in &no_names {
        let word = entry_by(
            &s[by].identity,
            &personal,
            1,
            &format!("{}{no_name}", cordelia_core::protocol::PERSONAL_NAME_PREFIX),
            text(""),
            &[],
        );
        entries::store(&s[by].conn, &word, now).unwrap();
    }
    s.pass(by, to);
    no_names.len()
}

/// The link of a version that held the text `said`, taken from an entry
/// that the key `signer` signed.
pub(crate) fn link(said: &str, signer: [u8; 32]) -> Link {
    Link::of(&text(said), signer)
}

/// The entry that `author` writes of `value` under `name` at `rev`, with
/// `chain`, in the channel whose secret is `channel`: whoever the author
/// is to the device that is given it.
pub(crate) fn entry_by(
    author: &NodeIdentity,
    channel: &[u8; 32],
    rev: u64,
    name: &str,
    value: Value,
    chain: &[Link],
) -> CheckedEntry {
    let inside = Inside {
        name: name.to_string(),
        value,
        chain: Some(chain.to_vec()),
    };
    Entry::seal(channel, author, rev, &inside)
        .unwrap()
        .check()
        .unwrap()
}

/// An entry of the channel whose secret is `channel`, with these clear
/// fields, signed by `author` and by the channel: whatever its content
/// says. It passes the check, which reads no content.
pub(crate) fn signed_in(
    channel: &[u8; 32],
    author: &NodeIdentity,
    slot: [u8; 32],
    rev: u64,
    content: Vec<u8>,
) -> CheckedEntry {
    let channel_key = derive::signing_key(channel).unwrap();
    let mut entry = Entry {
        channel: channel_key.public_key(),
        slot,
        author: author.public_key(),
        rev,
        delete: false,
        content,
        author_signature: [0u8; 64],
        channel_signature: [0u8; 64],
    };
    let form = entry.signed_bytes();
    entry.author_signature = author.sign(&[LABEL_ENTRY_AUTHOR, &form[..]].concat());
    entry.channel_signature = channel_key.sign(&[LABEL_ENTRY_CHANNEL, &form[..]].concat());
    entry.check().unwrap()
}

/// The change entry of `statement`, which commits to `secret`, as the
/// phrase makes it, but for what is sealed to the device at `place` among
/// its devices: that was sealed to the device for another use, and does
/// not open as the statement's secret.
pub(crate) fn change_that_does_not_open_for(
    phrase: &Phrase,
    statement: &SignedStatement,
    secret: [u8; 32],
    place: usize,
) -> CheckedEntry {
    let entry = change_entry::entry_of(phrase, statement, &ForPhrase::first(secret)).unwrap();
    let statement_key = phrase.statement_key().unwrap();
    let mut bound = LABEL_CHANGE_DEVICES.to_vec();
    bound.extend_from_slice(&statement.statement.number.to_be_bytes());
    bound.extend_from_slice(&phrase.public_key().unwrap());

    let (for_devices, for_phrase) = entry.content.split_at(CHANGE_ENTRY_DEVICES_PART_BYTES);
    let mut said = item_decrypt(&statement_key, for_devices, &bound).unwrap();
    // The statement behind its length, a count, and then what is sealed
    // to each device.
    let at = 2 + statement.to_bytes().unwrap().len() + 2 + place * SEALED_SECRET_BYTES;
    let to = x25519_pub_from_ed25519_pub(&statement.statement.devices[place].key).unwrap();
    let for_another_use = ecies_encrypt(&to, &secret).unwrap().to_bytes();
    said[at..at + SEALED_SECRET_BYTES].copy_from_slice(&for_another_use);

    let mut content = item_encrypt(&statement_key, &said, &bound).unwrap();
    content.extend_from_slice(for_phrase);
    signed_in(
        &phrase.channel_secret().unwrap(),
        &phrase.signing_key().unwrap(),
        entry.slot,
        entry.rev,
        content,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use cordelia_storage::entries::Outcome;

    use crate::change::make_settlement;
    use crate::person::PersonError;
    use crate::publish::Kind;
    use crate::take::NotTaken;

    /// An ordinary entry that the store took.
    const STORED: Taken = Taken::Own {
        stored: Outcome::Stored,
        record: None,
        came_to_count: 0,
        came_to_add: 0,
    };

    fn hash(said: &str) -> [u8; 32] {
        value_hash(&text(said))
    }

    /// A phrase is made on one device, and two more are added by
    /// hand-over. Each then counts for the others, holds the secret, keeps
    /// the change entry, and has written that it has applied.
    #[test]
    fn test_two_devices_added_by_hand_over_count_for_each_other_and_hold_the_secret() {
        let mut s = Several::new(3);
        let made = s.make_phrase(0);
        assert_eq!(
            made,
            Applied {
                number: 1,
                left: None,
                carried: 0,
                no_version: Vec::new(),
                not_carried: Vec::new(),
            }
        );
        // Until it is added, a device follows no phrase.
        assert!(!s[1].follows_a_phrase() && !s[2].follows_a_phrase());

        for new in [1, 2] {
            assert_eq!(
                s.add(0, new),
                Accepted::Joined(Applied {
                    number: 1,
                    left: None,
                    carried: 0,
                    no_version: Vec::new(),
                    not_carried: Vec::new(),
                })
            );
        }
        // Each counts the device that added it, and itself. The two that
        // were added know of each other once they are given what device 0
        // wrote.
        for new in [1, 2] {
            assert!(s[new].counts(&s.key(0)) && s[new].counts(&s.key(new)));
            assert!(s[0].counts(&s.key(new)));
        }
        assert!(!s[1].counts(&s.key(2)) && !s[2].counts(&s.key(1)));
        s.meet(&[0, 1, 2]);

        let phrase_key = s.phrase.public_key().unwrap();
        for n in 0..3 {
            let on = &s[n];
            assert_eq!((on.state(), on.number()), (State::Applied, 1), "{n}");
            assert_eq!(on.held().following.phrase_key, phrase_key);
            assert_eq!(on.secret(), s[0].secret(), "{n}");
            assert_eq!(on.latest().id(), s[0].latest().id(), "{n}");
            for other in 0..3 {
                assert!(on.counts(&s.key(other)), "{n} {other}");
                // The word of each that it has applied statement 1.
                assert_eq!(on.word_of(&s.key(other)), Some(text("1")), "{n} {other}");
            }
            assert_eq!(who_counts(&on.conn).unwrap().devices(), 3);
        }
        // The statement lists the one device it was made on: the other
        // two count by their records.
        assert_eq!(s[1].held().statement.statement.devices.len(), 1);
    }

    #[test]
    fn test_a_file_published_on_one_device_is_the_current_version_on_the_others() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        let made = s.write(1, "notes", "a.md", "what device 1 wrote");
        assert_eq!((made.rev, made.author), (1, s.key(1)));
        assert_eq!(s[0].slot("notes", "a.md").current, None);

        assert!(s.pass(1, 0).contains(&STORED));
        assert!(s.pass(1, 2).contains(&STORED));
        for n in 0..3 {
            let version = s[n].slot("notes", "a.md").current.unwrap();
            assert_eq!(version.value, text("what device 1 wrote"), "{n}");
            assert_eq!(version.rev, 1);
            assert_eq!(version.entries.len(), 1);
            assert_eq!(version.entries[0].author, s.key(1));
            assert_eq!(version.entries[0].id, made.id());
            assert_eq!(version.entries[0].chain, Some(Vec::new()));
        }

        // An edit on another device, over that version, is the current
        // version on each in its turn: its chain names what it was
        // written over, and who signed that.
        let edit = s.write(2, "notes", "a.md", "what device 2 made of it");
        assert_eq!(edit.rev, 2);
        s.pass(2, 0);
        s.pass(2, 1);
        for n in 0..3 {
            let version = s[n].slot("notes", "a.md").current.unwrap();
            assert_eq!(version.value, text("what device 2 made of it"), "{n}");
            assert_eq!(
                version.entries[0].chain,
                Some(vec![link("what device 1 wrote", s.key(1))])
            );
            // It is known to follow the text it was written over.
            assert!(s[n].follows("notes", "a.md", "what device 1 wrote"));
            assert!(!s[n].follows("notes", "a.md", "another text"));
        }
    }

    /// Device 1 reads a version and plans an edit against it. Before it
    /// publishes, another version arrives. The edit is not made, and
    /// nothing is written: planned again, against what is there now, it
    /// is.
    #[test]
    fn test_an_edit_planned_against_a_version_that_has_since_changed_is_not_made() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        let one = s.write(0, "notes", "a.md", "one");
        s.pass(0, 1);
        let planned = PlannedAgainst::what_is_in(&s[1].slot("notes", "a.md"));
        assert_eq!(
            planned,
            PlannedAgainst::Version {
                rev: 1,
                kind: Kind::Text,
                hash: hash("one"),
                entries: vec![one.id()],
            }
        );

        s.write(0, "notes", "a.md", "two");
        s.pass(0, 1);
        let before = s[1].everything();
        let now = s.tick();
        let write = Write {
            name: "notes",
            file: "a.md",
            value: text("an edit of one"),
            planned,
            merge: None,
        };
        let on = &s[1];
        assert_eq!(
            publish(&on.conn, &on.identity, &write, now).unwrap(),
            Published::Changed
        );
        assert_eq!(on.everything(), before);
        assert_eq!(on.text("notes", "a.md").as_deref(), Some("two"));

        // Planned against what is there now.
        let made = s.write(1, "notes", "a.md", "an edit of two");
        assert_eq!(made.rev, 3);
        assert_eq!(
            s[1].slot("notes", "a.md").current.unwrap().entries[0].chain,
            Some(vec![link("two", s.key(0)), link("one", s.key(0))])
        );
    }

    /// Two devices each wrote the index while apart. Device 1 merges the
    /// two, and writes the merge over the channel's version with the
    /// version its own file held as the other source. The chain says both,
    /// and each device's text is known to follow.
    #[test]
    fn test_a_merged_index_says_both_of_its_sources_in_its_chain() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        let (keys, index) = ([s.key(0), s.key(1)], "MEMORY.md");
        s.write(0, "notes", index, "first");
        s.pass(0, 1);
        // Device 0 goes on: two more versions.
        s.write(0, "notes", index, "second of 0");
        s.write(0, "notes", index, "third of 0");
        // Device 1, apart, wrote two of its own over the first. What its
        // folder agreed is the later: its hash, its signer and its chain.
        let own = crate::publish::OtherSource {
            hash: hash("third of 1"),
            signer: keys[1],
            chain: Some(vec![link("second of 1", keys[1]), link("first", keys[0])]),
        };
        s.pass(0, 1);

        let now = s.tick();
        let on = &s[1];
        let write = Write {
            name: "notes",
            file: index,
            value: text("the two, merged"),
            planned: PlannedAgainst::what_is_in(&on.slot("notes", index)),
            merge: Some(&own),
        };
        let Published::Made(merged) = publish(&on.conn, &on.identity, &write, now).unwrap() else {
            panic!("not made");
        };
        assert_eq!(merged.rev, 4);
        // The channel's version first, the other source second, and then
        // one link from each chain in turn, the channel's first. "first"
        // stands in both, and is said once: at its place in the other
        // source's chain, behind every link of that chain that is newer.
        let chain = on.slot("notes", index).current.unwrap().entries[0]
            .chain
            .clone()
            .unwrap();
        assert_eq!(
            chain,
            [
                link("third of 0", keys[0]),
                link("third of 1", keys[1]),
                link("second of 0", keys[0]),
                link("second of 1", keys[1]),
                link("first", keys[0]),
            ]
        );

        s.pass(1, 0);
        for n in 0..2 {
            for said in [
                "third of 0",
                "third of 1",
                "second of 0",
                "second of 1",
                "first",
            ] {
                assert!(s[n].follows("notes", index, said), "{n} {said}");
            }
            assert!(!s[n].follows("notes", index, "another"));
        }

        // Where the other source's hash is in the channel's chain already,
        // nothing is added: the channel's version descends from it.
        let descended = crate::publish::OtherSource {
            hash: hash("second of 0"),
            signer: keys[0],
            chain: Some(vec![link("first", keys[0])]),
        };
        let now = s.tick();
        let on = &s[0];
        let write = Write {
            name: "notes",
            file: index,
            value: text("merged again"),
            planned: PlannedAgainst::what_is_in(&on.slot("notes", index)),
            merge: Some(&descended),
        };
        assert!(matches!(
            publish(&on.conn, &on.identity, &write, now).unwrap(),
            Published::Made(_)
        ));
        let mut over = vec![link("the two, merged", keys[1])];
        over.extend(chain);
        assert_eq!(
            on.slot("notes", index).current.unwrap().entries[0].chain,
            Some(over)
        );
    }

    /// Four devices, each holding the name `notes`, with a file that each
    /// of devices 0, 1 and 2 wrote. Every device has every file.
    fn four_with_notes() -> Several {
        let mut s = Several::of_one_person(4);
        s.hold(&[0, 1, 2, 3], "notes");
        s.write(0, "notes", "a.md", "a one");
        s.write(1, "notes", "b.md", "b one");
        s.write(2, "notes", "c.md", "c one");
        s.meet(&[0, 1, 2, 3]);
        s
    }

    /// Device 2 is removed by a change made on device 0. The others apply
    /// it when they are shown the entry, and carry what they hold. From
    /// then they take nothing that the removed device signs: in the old
    /// channels, or in the new.
    #[test]
    fn test_a_device_is_removed_and_the_others_apply_carry_and_take_nothing_it_signs() {
        let mut s = four_with_notes();
        let old_secret = s[0].secret();
        let change = s.change(0, &[0, 1, 3], &[2]);
        assert_eq!((change.rev, s[0].number()), (2, 2));
        assert_ne!(s[0].secret(), old_secret);

        // Each device that stays is shown the entry before anything, and
        // applies it in that step: the three files it holds are carried.
        for n in [1, 3] {
            let taken = s.pass(0, n);
            assert_eq!(
                taken[0],
                Taken::Shown(Shown::Applied(Applied {
                    number: 2,
                    left: Some(1),
                    carried: 3,
                    no_version: Vec::new(),
                    not_carried: Vec::new(),
                })),
                "{n}"
            );
            assert_eq!(s[n].secret(), s[0].secret(), "{n}");
        }
        s.meet(&[0, 1, 3]);
        let statement = s[1].held().statement.statement;
        assert!(statement.removes(&s.key(2)));
        for n in [0, 1, 3] {
            let on = &s[n];
            assert_eq!(on.state(), State::Applied);
            assert!(!on.counts(&s.key(2)), "{n}");
            // What the removed device wrote before is kept, as the
            // version of each device that carried it: its text, at its
            // revision, with the removed device's key in a first link.
            for (file, said) in [("a.md", "a one"), ("b.md", "b one"), ("c.md", "c one")] {
                let version = on.slot("notes", file).current.unwrap();
                assert_eq!((version.value, version.rev), (text(said), 1), "{n} {file}");
                assert_eq!(version.entries.len(), 3, "{n} {file}");
            }
            let version = on.slot("notes", "c.md").current.unwrap();
            for one in &version.entries {
                assert_eq!(one.chain, Some(vec![link("c one", s.key(2))]));
            }
            // Each says that it has applied the change, and each other
            // holds its word.
            for other in [0, 1, 3] {
                assert_eq!(on.word_of(&s.key(other)), Some(text("2")), "{n} {other}");
            }
        }

        // The removed device has not heard. It writes on, in the channels
        // that were left: nothing of that is taken, by any device.
        s.write(2, "notes", "c.md", "c two, written late");
        s.write(2, "notes", "a.md", "a two, written late");
        for n in [0, 1, 3] {
            let before = s[n].everything();
            let taken = s.pass(2, n);
            assert_eq!(taken[0], Taken::Shown(Shown::Behind), "{n}");
            assert!(taken.len() > 4);
            for one in &taken[1..] {
                assert_eq!(*one, Taken::Refused(NotTaken::OldChannel), "{n}");
            }
            assert_eq!(s[n].everything(), before, "{n}");
        }

        // Nor is what it signs taken in the new channels, were it to
        // write there.
        let removed = &s[2].identity;
        let in_notes = entry_by(removed, &s[0].own("notes"), 9, "a.md", text("late"), &[]);
        let in_personal = entry_by(removed, &s[0].personal(), 9, "syncing", text("notes"), &[]);
        for n in [0, 1, 3] {
            let on = &s[n];
            let before = on.everything();
            for entry in [&in_notes, &in_personal] {
                assert_eq!(
                    take(&on.conn, &on.identity, entry, s.now).unwrap(),
                    Taken::Refused(NotTaken::SignerDoesNotCount),
                    "{n}"
                );
            }
            assert_eq!(on.everything(), before, "{n}");
            assert_eq!(on.text("notes", "a.md").as_deref(), Some("a one"));
        }
    }

    /// The removed device is shown the entry: it stops, says that it was
    /// removed, publishes nothing more, and takes nothing in its own
    /// channels.
    #[test]
    fn test_the_removed_device_shown_the_entry_stops_and_says_it_was_removed() {
        let mut s = four_with_notes();
        let change = s.change(0, &[0, 1, 3], &[2]);
        let before = s[2].stored();

        let taken = s.pass(0, 2);
        assert_eq!(taken[0], Taken::Shown(Shown::Removed));
        let removed = &s[2];
        assert_eq!(removed.state(), State::Removed);
        // It keeps the entry that removed it, and the statement, the
        // secret and the store it had.
        assert_eq!(removed.latest().id(), change.id());
        assert_eq!(removed.number(), 1);
        assert_eq!(removed.stored(), before);
        // Everything else that device 0 holds is of channels that the
        // removed device cannot derive.
        for one in &taken[1..] {
            assert_eq!(*one, Taken::Refused(NotTaken::AnotherChannel));
        }

        // It publishes nothing more.
        let write = Write {
            name: "notes",
            file: "c.md",
            value: text("after it was removed"),
            planned: PlannedAgainst::what_is_in(&removed.slot("notes", "c.md")),
            merge: None,
        };
        assert!(matches!(
            publish(&removed.conn, &removed.identity, &write, s.now),
            Err(PersonError::Stopped(State::Removed))
        ));
        // And takes nothing in the channels it still reads: device 3 has
        // not heard, and writes there.
        s.write(3, "notes", "a.md", "a two");
        let stopped = s[2].everything();
        let taken = s.pass(3, 2);
        assert!(taken.len() > 4);
        for one in &taken[1..] {
            assert!(
                matches!(
                    one,
                    Taken::Refused(NotTaken::Stopped(State::Removed) | NotTaken::AnotherChannel)
                ),
                "{one:?}"
            );
        }
        assert!(taken.contains(&Taken::Refused(NotTaken::Stopped(State::Removed))));
        assert_eq!(s[2].everything(), stopped);
        assert_eq!(s[2].text("notes", "a.md").as_deref(), Some("a one"));
    }

    /// Device 3 is not shown the change, and goes on. It takes what the
    /// removed device writes late, and edits it. When it is shown the
    /// change it carries the edit. On every other device the edit is the
    /// current version, and is known to follow no text but the one it was
    /// written over: the removed device signed a version between.
    #[test]
    fn test_an_edit_of_what_a_removed_device_wrote_late_is_known_to_follow_no_other_text() {
        let mut s = four_with_notes();
        s.change(0, &[0, 1, 3], &[2]);
        s.pass(0, 1);
        assert_eq!((s[1].number(), s[3].number()), (2, 1));

        // The removed device writes late, where device 3 still reads.
        let late = s.write(2, "notes", "a.md", "a two, written late");
        assert_eq!(late.rev, 2);
        assert!(s.pass(2, 3).contains(&STORED));
        assert_eq!(
            s[3].text("notes", "a.md").as_deref(),
            Some("a two, written late")
        );
        // Device 3 edits it, and edits a file that the removed device has
        // not touched.
        let edit = s.write(3, "notes", "a.md", "a three, by device 3");
        assert_eq!(edit.rev, 3);
        s.write(3, "notes", "b.md", "b two, by device 3");

        // It is shown the change, applies it, and carries what it holds.
        let taken = s.pass(0, 3);
        assert!(matches!(
            taken[0],
            Taken::Shown(Shown::Applied(Applied {
                number: 2,
                left: Some(1),
                carried: 3,
                ..
            }))
        ));
        s.pass(3, 0);
        s.pass(3, 1);

        let (maker, removed) = (s.key(0), s.key(2));
        for n in [0, 1] {
            let version = s[n].slot("notes", "a.md").current.unwrap();
            assert_eq!(
                (version.value, version.rev),
                (text("a three, by device 3"), 3),
                "{n}"
            );
            assert_eq!(version.entries.len(), 1);
            assert_eq!(version.entries[0].author, s.key(3));
            // The chain says who signed each version: the removed device
            // signed the one between.
            assert_eq!(
                version.entries[0].chain,
                Some(vec![
                    link("a two, written late", removed),
                    link("a one", maker)
                ])
            );
            // This device's text is "a one": the edit is not known to
            // follow it, and the folder keeps its text.
            assert!(!s[n].follows("notes", "a.md", "a one"));
            // Known only for the text it was written over, which no
            // device under the statement has as its own.
            assert!(s[n].follows("notes", "a.md", "a two, written late"));

            // The control: the edit of a file that the removed device did
            // not touch is known to follow this device's text.
            let version = s[n].slot("notes", "b.md").current.unwrap();
            assert_eq!(version.value, text("b two, by device 3"));
            assert!(s[n].follows("notes", "b.md", "b one"));
        }
    }

    /// A device added by a device that was itself added counts: a chain
    /// is two long. A device added by that one does not, and that one may
    /// not add.
    #[test]
    fn test_a_device_added_by_an_added_device_counts_and_one_added_by_that_one_does_not() {
        let mut s = Several::new(4);
        s.make_phrase(0);
        assert!(matches!(s.add(0, 1), Accepted::Joined(_)));
        // Device 1 was added by a device of the statement: it may add.
        // What it hands over has the record of its own addition with it.
        let added = s.hand(1, 2);
        assert!(matches!(
            s.accept(2, 1, &added.hand_over),
            Accepted::Joined(_)
        ));
        for n in 0..3 {
            assert!(s[2].counts(&s.key(n)), "{n}");
        }
        s.meet(&[0, 1, 2]);
        for n in 0..3 {
            assert!(s[n].counts(&s.key(2)), "{n}");
            assert_eq!(who_counts(&s[n].conn).unwrap().devices(), 3);
            assert!(!who_counts(&s[n].conn).unwrap().may_add(&s.key(2)));
        }

        // Device 2 may not add: it was added by a device added since.
        let (third, new) = (&s[2], &s[3]);
        let before = third.everything();
        assert!(matches!(
            add_device(&third.conn, &third.identity, &new.key(), "device 3", s.now),
            Err(PersonError::MayNotAdd)
        ));
        assert_eq!(third.everything(), before);

        // Were it to write the record all the same, no device counts the
        // key it adds: the record is kept as not counted.
        let record = cordelia_crypto::addition::Addition::under(
            &third.held().statement.statement,
            new.listed(),
            third.key(),
            s.now as u64,
        )
        .unwrap()
        .sign(&third.identity)
        .unwrap();
        let entry = entry_by(
            &third.identity,
            &third.personal(),
            1,
            &crate::person::added_name(&new.key()).unwrap(),
            Value::Other(record.to_bytes().unwrap()),
            &[],
        );
        for n in 0..3 {
            let on = &s[n];
            assert_eq!(
                take(&on.conn, &on.identity, &entry, s.now).unwrap(),
                Taken::Own {
                    stored: Outcome::Stored,
                    record: Some(crate::take::Record::Seen(
                        crate::person::AdditionSeen::NotCounted(
                            crate::person::NotCounted::MayNotAdd
                        )
                    )),
                    came_to_count: 0,
                    came_to_add: 0,
                },
                "{n}"
            );
            assert!(!on.counts(&new.key()), "{n}");
            assert_eq!(who_counts(&on.conn).unwrap().devices(), 3);
        }
    }

    /// What a device that is being added wrote reaches device 1 before the
    /// record of its addition: its word that it has applied, a file, and
    /// a record that it signed in its turn. Each is refused, and nothing
    /// is kept. The record arrives, and the key comes to count: given the
    /// same entries again, device 1 takes them. It ends with the same
    /// entries and the same answers as device 2, which was given the
    /// records first.
    ///
    /// So does device 5, which is given them again in the very order that
    /// failed the first time: its caller gives everything again for as
    /// long as a key came to count.
    #[test]
    fn test_what_arrives_before_the_record_is_taken_when_it_is_given_again() {
        use crate::person::AdditionSeen;
        use crate::take::Record;
        use std::collections::BTreeSet;

        let mut s = Several::new(6);
        s.make_phrase(0);
        for new in [1, 2, 5] {
            assert!(matches!(s.add(0, new), Accepted::Joined(_)));
        }
        s.hold(&[0, 1, 2, 5], "notes");
        s.meet(&[0, 1, 2, 5]);
        // Device 0 adds device 3, and device 3 adds device 4. Each writes
        // that it has applied, and a file.
        assert!(matches!(s.add(0, 3), Accepted::Joined(_)));
        s.hold(&[3], "notes");
        s.write(3, "notes", "a.md", "by device 3");
        assert!(matches!(s.add(3, 4), Accepted::Joined(_)));
        s.hold(&[4], "notes");
        s.write(4, "notes", "b.md", "by device 4");

        const REFUSED: Taken = Taken::Refused(NotTaken::SignerDoesNotCount);
        const HELD: Taken = Taken::Own {
            stored: Outcome::AlreadyHeld,
            record: None,
            came_to_count: 0,
            came_to_add: 0,
        };
        const OF_A_PAIR: Taken = Taken::Refused(NotTaken::AnotherChannel);
        // A record by which a key came to count, and may add or not.
        let a_record = |came_to_add: usize| Taken::Own {
            stored: Outcome::Stored,
            record: Some(Record::Seen(AdditionSeen::Counted)),
            came_to_count: 1,
            came_to_add,
        };
        let before = s[1].stored();
        let before_on_5 = s[5].stored();

        for to in [1, 5] {
            // The device is given what device 4 holds: its word, and its
            // file.
            let taken = s.pass(4, to);
            assert_eq!(taken[0], Taken::Shown(Shown::Held));
            assert_eq!(taken[1..], [REFUSED, REFUSED]);
            // And what device 3 holds: its word, its file, its record
            // that it added device 4, and the hand-over, which is of a
            // pair channel.
            let taken = s.pass(3, to);
            assert_eq!(taken[1..], [REFUSED, REFUSED, REFUSED, OF_A_PAIR]);
        }
        // Nothing of it is kept, and neither key counts.
        assert_eq!(s[1].stored(), before);
        assert_eq!(s[5].stored(), before_on_5);
        for to in [1, 5] {
            assert!(!s[to].counts(&s.key(3)) && !s[to].counts(&s.key(4)));
        }

        // The record that device 0 added device 3 arrives: a key came to
        // count, and may add, since a device of the statement added it.
        // The caller gives again what it gave before.
        for to in [1, 5] {
            let taken = s.pass(0, to);
            assert_eq!(taken.iter().filter(|one| **one == a_record(1)).count(), 1);
            assert!(s[to].counts(&s.key(3)) && !s[to].counts(&s.key(4)));
        }

        // Device 5 is given it in the order that failed the first time:
        // what device 4 holds, and then what device 3 holds. What device
        // 4 signed is refused again. The record that device 3 signed is
        // read, and a further key came to count by it: the caller gives
        // everything again.
        let taken = s.pass(4, 5);
        assert_eq!(taken[1..], [REFUSED, REFUSED]);
        let taken = s.pass(3, 5);
        // The key it adds counts, and may not add: device 3 was added
        // since the statement.
        assert_eq!(taken[1..], [STORED, STORED, a_record(0), OF_A_PAIR]);
        assert!(s[5].counts(&s.key(4)));
        // In that order again: what device 4 signed is taken, and the
        // store holds the rest. No key came to count, and it is done.
        let taken = s.pass(4, 5);
        assert_eq!(taken[1..], [STORED, STORED]);
        let taken = s.pass(3, 5);
        assert_eq!(taken[1..], [HELD, HELD, HELD, OF_A_PAIR]);

        // What device 3 holds, again: its word and its file are stored,
        // and its record is read. A further key came to count by it.
        let taken = s.pass(3, 1);
        assert_eq!(
            taken[1..],
            [
                STORED,
                STORED,
                a_record(0),
                Taken::Refused(NotTaken::AnotherChannel)
            ]
        );
        assert!(s[1].counts(&s.key(4)));
        // And what device 4 holds, again.
        let taken = s.pass(4, 1);
        assert_eq!(taken[1..], [STORED, STORED]);

        // Device 2 is given the records first, and nothing twice.
        for from in [0, 3, 4] {
            let taken = s.pass(from, 2);
            assert!(!taken.contains(&REFUSED), "{from}");
        }

        // The three hold the same entries, and give the same answers.
        let entries = |n: usize| -> BTreeSet<[u8; 32]> {
            s[n].stored().iter().map(|entry| entry.id()).collect()
        };
        assert_eq!(entries(1), entries(2));
        assert_eq!(entries(5), entries(2));
        assert_eq!(entries(1).len(), before.len() + 6);
        let answers = |n: usize| {
            let on = &s[n];
            let counting = who_counts(&on.conn).unwrap();
            let keys: Vec<[u8; 32]> = (0..5).map(|m| s.key(m)).collect();
            (
                keys.iter()
                    .map(|key| counting.counts(key))
                    .collect::<Vec<_>>(),
                keys.iter()
                    .map(|key| counting.may_add(key))
                    .collect::<Vec<_>>(),
                keys.iter().map(|key| on.word_of(key)).collect::<Vec<_>>(),
                on.slot("notes", "a.md"),
                on.slot("notes", "b.md"),
            )
        };
        assert_eq!(answers(1), answers(2));
        assert_eq!(answers(5), answers(2));
        let (counts, may_add, words, a, b) = answers(1);
        assert_eq!(counts, [true; 5]);
        // Device 4 was added by a device added since: it may not add.
        assert_eq!(may_add, [true, true, true, true, false]);
        assert_eq!(words, vec![Some(text("1")); 5]);
        assert_eq!(a.current.unwrap().value, text("by device 3"));
        assert_eq!(b.current.unwrap().value, text("by device 4"));
    }

    /// Two changes are made apart: one on device 0, one on device 1.
    /// Every device that sees both is in a fork, and neither publishes in
    /// its own channels nor takes from them. The settlement, made on a
    /// device that has seen both, ends it on each: what was written under
    /// both branches comes together.
    #[test]
    fn test_two_changes_made_apart_are_a_fork_and_the_settlement_ends_it_on_each() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        let first = s[0].secret();
        let by_0 = s.change(0, &[0, 1, 2], &[]);
        let by_1 = s.change(1, &[0, 1, 2], &[]);
        assert_eq!((by_0.rev, by_1.rev), (2, 2));
        let branches = [s[0].secret(), s[1].secret()];
        assert_ne!(branches[0], branches[1]);
        // Each writes under its own branch.
        s.write(0, "notes", "a.md", "written under the change of 0");
        s.write(1, "notes", "b.md", "written under the change of 1");

        // Device 2 is shown one, and applies it. Shown the other, it is in
        // a fork. So is each maker, shown the other's.
        assert!(matches!(
            s.pass(0, 2)[0],
            Taken::Shown(Shown::Applied(Applied { number: 2, .. }))
        ));
        assert_eq!(s.pass(1, 2)[0], Taken::Shown(Shown::Fork));
        assert_eq!(s.pass(1, 0)[0], Taken::Shown(Shown::Fork));
        assert_eq!(s.pass(0, 1)[0], Taken::Shown(Shown::Fork));
        for n in 0..3 {
            assert_eq!(s[n].state(), State::Fork, "{n}");
            assert_eq!(s[n].number(), 2);
        }
        // Each keeps both entries: the one it had applied, and the other.
        assert_eq!(
            (s[0].latest().id(), s[0].apart().unwrap().id()),
            (by_0.id(), by_1.id())
        );
        assert_eq!(
            (s[1].latest().id(), s[1].apart().unwrap().id()),
            (by_1.id(), by_0.id())
        );
        assert_eq!(s[2].apart().unwrap().id(), by_1.id());

        // In a fork a device publishes nothing, and takes nothing in its
        // own channels.
        for n in 0..3 {
            let on = &s[n];
            let write = Write {
                name: "notes",
                file: "c.md",
                value: text("in a fork"),
                planned: PlannedAgainst::NoVersion,
                merge: None,
            };
            assert!(matches!(
                publish(&on.conn, &on.identity, &write, s.now),
                Err(PersonError::Stopped(State::Fork))
            ));
        }
        let stopped = s[2].everything();
        let taken = s.pass(0, 2);
        assert_eq!(taken[0], Taken::Shown(Shown::Held));
        assert!(taken.contains(&Taken::Refused(NotTaken::Stopped(State::Fork))));
        assert!(!taken.iter().any(|one| matches!(one, Taken::Own { .. })));
        assert_eq!(s[2].everything(), stopped);

        // The settlement, with the phrase, on device 0: it has seen both.
        let now = s.tick();
        let on = &s[0];
        let settlement = make_settlement(
            &s.phrase,
            &on.held().statement,
            &on.latest(),
            &on.apart().unwrap(),
            &on.key(),
            s.listed(&[0, 1, 2]),
            &[],
        )
        .unwrap();
        assert_eq!(settlement.rev, 3);
        assert!(matches!(
            shown(&on.conn, &on.identity, &settlement, now).unwrap(),
            Shown::Applied(Applied {
                number: 3,
                left: Some(2),
                carried: 1,
                ..
            })
        ));
        for n in [1, 2] {
            assert!(
                matches!(
                    s.pass(0, n)[0],
                    Taken::Shown(Shown::Applied(Applied {
                        number: 3,
                        left: Some(2),
                        ..
                    }))
                ),
                "{n}"
            );
        }
        s.meet(&[0, 1, 2]);
        for n in 0..3 {
            let on = &s[n];
            assert_eq!((on.state(), on.number()), (State::Applied, 3), "{n}");
            assert_eq!(on.apart(), None);
            assert_eq!(on.latest().id(), settlement.id());
            assert_eq!(on.secret(), s[0].secret());
            // What was written under each branch is there.
            assert_eq!(
                on.text("notes", "a.md").as_deref(),
                Some("written under the change of 0"),
                "{n}"
            );
            assert_eq!(
                on.text("notes", "b.md").as_deref(),
                Some("written under the change of 1"),
                "{n}"
            );
        }

        // The part of the settlement's entry that is for the phrase holds
        // the secrets of both branches, and of the generation before.
        let phrase = &s.phrase;
        let for_phrase = change_entry::open_for_phrase(
            &settlement,
            &phrase.public_key().unwrap(),
            &derive::channel_id(&phrase.channel_secret().unwrap()).unwrap(),
            &phrase.seal_key().unwrap(),
        )
        .unwrap();
        assert_eq!(for_phrase.secret, s[0].secret());
        let numbers: Vec<u64> = for_phrase.earlier.iter().map(|one| one.number).collect();
        assert_eq!(numbers, [2, 2, 1]);
        let secrets: Vec<[u8; 32]> = for_phrase.earlier.iter().map(|one| one.secret).collect();
        assert!(secrets[..2].contains(&branches[0]) && secrets[..2].contains(&branches[1]));
        assert_eq!(secrets[2], first);
    }

    // ── A folder's records, names, and what was carried ─────────────

    use cordelia_core::protocol::REV_BAND_HALF;
    use cordelia_core::revision::lifted;
    use cordelia_crypto::bech32::encode_channel_id;
    use cordelia_storage::at_relays as kept_rows;
    use cordelia_storage::sync_state::{self, Agreed};
    use cordelia_storage::{index_lines, meta};

    use crate::at_relays::{carried_waits_at, channels, say_sent};
    use crate::leaving::names_to_go;
    use crate::look::{NotCarried, look};
    use crate::names;
    use crate::person::key_signed_as;
    use crate::state::AtRelays;

    /// The ID of the channel of `name` on `on`, as it is written: what a
    /// folder's records are kept by.
    fn written(on: &Machine, name: &str) -> String {
        encode_channel_id(&derive::channel_id(&on.own(name)).unwrap()).unwrap()
    }

    fn agreed(on: &Machine, rev: u64, said: &str) -> Agreed {
        Agreed {
            hash: Some(hash(said)),
            rev,
            signer: Some(on.key()),
            chain: Some(Vec::new()),
        }
    }

    /// How many records of index lines the store holds for a channel.
    fn index_records(conn: &Connection, channel: &str) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM index_lines WHERE channel_id = ?1",
            [channel],
            |row| row.get(0),
        )
        .unwrap()
    }

    /// When a device applies a statement, each folder's records, which
    /// are kept by channel, are moved to the name's new channel, with its
    /// records of index lines, and each revision in them is renumbered as
    /// a version's is (decision 2026-10-04 §4.2). A record in whose slot
    /// the store holds no version at all is dropped, so that its file
    /// meets the new channel as a new file does, and the device says
    /// which files.
    #[test]
    fn test_a_folders_records_move_with_the_name_and_one_with_no_version_is_dropped() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "lab");
        let kept = s.write(0, "lab", "kept.md", "one");
        // A version at a revision in the top half of its band: a device
        // jumped there. It crosses the statement to the next band.
        let high = (1u64 << 44) + REV_BAND_HALF + 5;
        assert_ne!(lifted(high), high);
        let now = s.tick();
        let up = entry_by(
            &s[0].identity,
            &s[0].own("lab"),
            high,
            "high.md",
            text("up"),
            &[],
        );
        assert_eq!(take(&s[0].conn, &s[0].identity, &up, now).unwrap(), STORED);

        let old = written(&s[0], "lab");
        let conn = &s[0].conn;
        let folder = "/home/sam/memory";
        for (file, record) in [
            ("kept.md", agreed(&s[0], kept.rev, "one")),
            ("high.md", agreed(&s[0], high, "up")),
            // The store holds nothing in this file's slot.
            ("ghost.md", agreed(&s[0], 3, "gone")),
        ] {
            sync_state::save(conn, folder, &old, file, &record).unwrap();
        }
        index_lines::line_removed(conn, folder, &old, "kept.md", "- [k](kept.md)", now).unwrap();
        // Another channel's records are another matter.
        let other = agreed(&s[0], 9, "elsewhere");
        sync_state::save(conn, folder, "another-channel", "x.md", &other).unwrap();

        // A renewal: the device applies statement 2.
        s.change(0, &[0, 1], &[]);
        let new = written(&s[0], "lab");
        assert_ne!(new, old);
        let conn = &s[0].conn;
        assert!(sync_state::load(conn, folder, &old).unwrap().is_empty());
        let moved = sync_state::load(conn, folder, &new).unwrap();
        let mut files: Vec<&String> = moved.keys().collect();
        files.sort();
        assert_eq!(files, ["high.md", "kept.md"]);
        assert_eq!(moved["kept.md"], agreed(&s[0], kept.rev, "one"));
        assert_eq!(moved["high.md"], agreed(&s[0], lifted(high), "up"));
        // The version itself is where its record says, in the new channel.
        assert_eq!(
            s[0].slot("lab", "high.md").current.unwrap().rev,
            lifted(high)
        );
        assert_eq!(
            (index_records(conn, &old), index_records(conn, &new)),
            (0, 1)
        );
        let elsewhere = sync_state::load(conn, folder, "another-channel").unwrap();
        assert_eq!(elsewhere["x.md"], other);

        // The file whose record was dropped is said, until the next
        // statement.
        let now = s.tick();
        let seen = look(&s[0].conn, &s[0].identity, &AtRelays::default(), now).unwrap();
        let ghost = NotCarried {
            name: "lab".into(),
            file: "ghost.md".into(),
        };
        assert_eq!(seen.not_carried, std::slice::from_ref(&ghost));
        assert!(
            seen.says.iter().any(|line| line.contains("ghost.md in lab")
                && line.contains("meets its channel as a new file does")),
            "{:?}",
            seen.says
        );
        s.change(0, &[0, 1], &[]);
        let now = s.tick();
        let seen = look(&s[0].conn, &s[0].identity, &AtRelays::default(), now).unwrap();
        assert!(seen.not_carried.is_empty());
        assert_eq!(
            meta::get(&s[0].conn, meta::PERSON_NOT_CARRIED).unwrap(),
            None
        );

        // A file is said no longer once it has met its channel: a folder
        // has a record of it in the channel of its name. Until then it
        // stays, whatever else the folder has a record of there, and
        // whatever a folder has a record of under that file's name in
        // another channel. A file under a name that the device does not
        // hold stays too: the name may be one that could not be held in
        // this cycle, for an error. It goes where the device stops the
        // name, on purpose.
        let conn = &s[0].conn;
        let noted = |conn: &rusqlite::Connection| -> Vec<NotCarried> {
            let now = crate::several::START;
            let seen = look(conn, &s[0].identity, &AtRelays::default(), now).unwrap();
            seen.not_carried
        };
        let gone = NotCarried {
            name: "held-no-more".into(),
            file: "left.md".into(),
        };
        let note = |files: &[&NotCarried]| {
            let files: Vec<(String, String)> = files
                .iter()
                .map(|file| (file.name.clone(), file.file.clone()))
                .collect();
            crate::look::note_not_carried(conn, &files).unwrap();
        };
        assert_eq!(crate::look::clear_not_carried_that_met(conn).unwrap(), 0);
        note(&[&ghost, &gone]);
        let channel = written(&s[0], "lab");
        let record = agreed(&s[0], 1, "met");
        sync_state::save(conn, folder, &channel, "other.md", &record).unwrap();
        sync_state::save(conn, folder, "another-channel", "ghost.md", &record).unwrap();
        assert_eq!(crate::look::clear_not_carried_that_met(conn).unwrap(), 0);
        assert_eq!(noted(conn), [ghost.clone(), gone.clone()]);
        sync_state::save(conn, folder, &channel, "ghost.md", &record).unwrap();
        assert_eq!(crate::look::clear_not_carried_that_met(conn).unwrap(), 1);
        assert_eq!(noted(conn), std::slice::from_ref(&gone));
        assert_eq!(crate::look::clear_not_carried_that_met(conn).unwrap(), 0);
        assert_eq!(noted(conn), std::slice::from_ref(&gone));
        // The name is stopped: its files are noted no longer, and those
        // of another name are.
        note(&[&ghost, &gone]);
        let now = crate::several::START;
        names::stop(conn, &s[0].identity, "held-no-more", now).unwrap();
        assert_eq!(noted(conn), std::slice::from_ref(&ghost));
        names::stop(conn, &s[0].identity, "lab", now).unwrap();
        assert!(noted(conn).is_empty());
        assert_eq!(meta::get(conn, meta::PERSON_NOT_CARRIED).unwrap(), None);
        assert_eq!(crate::look::clear_not_carried_that_met(conn).unwrap(), 0);
    }

    /// Each device that applies a statement writes so in the new personal
    /// channel, and, once it has, that it has sent what it carried
    /// (decision 2026-10-04 §8): where nothing that it carried waits at
    /// any relay it is set up with. It says so once, and a look shows it
    /// of each device whose word of the statement applied says so.
    #[test]
    fn test_a_device_writes_that_it_has_sent_what_it_carried_once_it_has() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "lab");
        s.write(0, "lab", "notes.md", "one");
        s.meet(&[0, 1]);
        let (relay, other_relay) = ([7u8; 32], [8u8; 32]);
        let said = |s: &Several, n: usize| match s[n].word_of(&s.key(n)) {
            Some(Value::Text(word)) => word,
            other => panic!("{other:?}"),
        };

        // Under the first statement nothing was carried. With no relay
        // nothing is sent, and nothing is said.
        let now = s.tick();
        assert_eq!(said(&s, 0), "1");
        assert!(!say_sent(&s[0].conn, &s[0].identity, &[], now).unwrap());
        assert!(!carried_waits_at(&s[0].conn, &s[0].identity, &relay).unwrap());
        assert!(say_sent(&s[0].conn, &s[0].identity, &[relay], now).unwrap());
        assert_eq!(said(&s, 0), "1 sent");
        // Said once.
        assert!(!say_sent(&s[0].conn, &s[0].identity, &[relay], now).unwrap());

        // A change: device 0 carries the file, and its own words.
        let change = s.change(0, &[0, 1], &[]);
        let now = s.tick();
        assert_eq!(said(&s, 0), "2");
        let (conn, identity) = (&s[0].conn, &s[0].identity);
        assert!(carried_waits_at(conn, identity, &relay).unwrap());
        assert!(!say_sent(conn, identity, &[relay], now).unwrap());

        // It is sent to one relay of the two it is set up with: not yet.
        let far = i64::MAX / 2;
        for channel in channels(conn, identity).unwrap() {
            kept_rows::sent(conn, &relay, &channel.id, far).unwrap();
            kept_rows::carried(conn, &relay, &channel.id, far).unwrap();
        }
        assert!(!carried_waits_at(conn, identity, &relay).unwrap());
        assert!(carried_waits_at(conn, identity, &other_relay).unwrap());
        assert!(!say_sent(conn, identity, &[relay, other_relay], now).unwrap());
        assert_eq!(said(&s, 0), "2");
        // To each of them: it says so, in an entry above its word.
        for channel in channels(conn, identity).unwrap() {
            kept_rows::sent(conn, &other_relay, &channel.id, far).unwrap();
            kept_rows::carried(conn, &other_relay, &channel.id, far).unwrap();
        }
        assert!(say_sent(conn, identity, &[relay, other_relay], now).unwrap());
        assert_eq!(said(&s, 0), "2 sent");
        assert!(!say_sent(conn, identity, &[relay, other_relay], now).unwrap());

        // The other device applies the change and is given the word: it
        // shows device 0 as having sent what it held, and itself not.
        let now = s.tick();
        take(&s[1].conn, &s[1].identity, &change, now).unwrap();
        s.pass(0, 1);
        let now = s.tick();
        let seen = look(&s[1].conn, &s[1].identity, &AtRelays::default(), now).unwrap();
        let sent: Vec<(Option<u64>, bool)> = seen
            .devices
            .iter()
            .map(|device| (device.applied, device.sent))
            .collect();
        assert_eq!(sent, [(Some(2), true), (Some(2), false)]);

        // A word that says so of another statement says nothing of this
        // one: the device is shown as still sending.
        s.change(1, &[0, 1], &[]);
        s.pass(0, 1);
        let now = s.tick();
        let seen = look(&s[1].conn, &s[1].identity, &AtRelays::default(), now).unwrap();
        assert!(seen.devices.iter().all(|device| !device.sent));
        // So too where that word stands in the personal channel of the
        // statement applied: device 0 says there that it applied the
        // statement before, and sent what it carried then.
        let of_the_one_before = entry_by(
            &s[0].identity,
            &s[1].personal(),
            (3 << cordelia_core::protocol::REV_COUNT_BITS) + 1,
            &crate::person::applied_name(&s.key(0)).unwrap(),
            Value::Text(crate::person::applied_word(2, true)),
            &[],
        );
        let now = s.tick();
        assert_eq!(
            take(&s[1].conn, &s[1].identity, &of_the_one_before, now).unwrap(),
            STORED
        );
        let seen = look(&s[1].conn, &s[1].identity, &AtRelays::default(), now).unwrap();
        let sent: Vec<(Option<u64>, bool)> = seen
            .devices
            .iter()
            .map(|device| (device.applied, device.sent))
            .collect();
        assert_eq!(sent, [(Some(2), false), (Some(3), false)]);
    }

    /// A look shows each name that a device had listed before the last
    /// change and that no device lists yet, with who had listed it and
    /// for how long it can still be brought in; a name that only a key
    /// which no longer counts had listed is said apart (decision
    /// 2026-10-04 §7.3, §8).
    #[test]
    fn test_a_look_shows_the_names_that_no_device_lists_yet() {
        let mut s = Several::of_one_person(3);
        let now = s.tick();
        for (n, name) in [(0, "lab"), (1, "team"), (2, "only-the-tablets")] {
            s.hold(&[n], name);
            names::say(&s[n].conn, &s[n].identity, name, now).unwrap();
        }
        s.meet(&[0, 1, 2]);
        let change = s.change(0, &[0, 1], &[2]);
        let now = s.tick();
        let seen = look(&s[0].conn, &s[0].identity, &AtRelays::default(), now).unwrap();
        let shown: Vec<(&str, usize, usize, i64)> = seen
            .names_not_listed
            .iter()
            .map(|name| {
                (
                    name.name.as_str(),
                    name.by.len(),
                    name.by_gone.len(),
                    name.days_left,
                )
            })
            .collect();
        assert_eq!(shown, [("only-the-tablets", 0, 1, 89), ("team", 1, 0, 89)]);
        assert_eq!(seen.names_not_listed[1].by[0].label, "device 1");
        let says = seen.says.join("\n");
        assert!(
            says.contains(
                "1 name that your devices synced before the last change is listed by no device \
                 yet: team."
            ),
            "{says}"
        );
        assert!(
            says.contains(
                "1 name that only a device which no longer counts had synced is listed by no \
                 device: only-the-tablets. It stays behind"
            ),
            "{says}"
        );
        // A day short of ninety days later it can be brought in for one
        // more day, and then no more.
        let day = 24 * 60 * 60;
        let late = look(
            &s[0].conn,
            &s[0].identity,
            &AtRelays::default(),
            now + 88 * day,
        )
        .unwrap();
        assert_eq!(late.names_not_listed[0].days_left, 1);
        let past = look(
            &s[0].conn,
            &s[0].identity,
            &AtRelays::default(),
            now + 200 * day,
        )
        .unwrap();
        assert_eq!(past.names_not_listed[0].days_left, 0);
        // A device that has stopped says nothing of names.
        take(&s[1].conn, &s[1].identity, &change, now).unwrap();
        s.change(1, &[1], &[0]);
        s.pass(1, 0);
        assert_eq!(s[0].state(), State::Removed);
        let seen = look(&s[0].conn, &s[0].identity, &AtRelays::default(), now).unwrap();
        assert!(seen.names_not_listed.is_empty());
    }

    /// What a device has still to send, by name (decision 2026-10-04
    /// §7.1): a name of whose channel something waits at any relay asked
    /// about is one to go, and the others are sent.
    #[test]
    fn test_what_is_still_to_send_is_said_by_name() {
        let mut s = Several::of_one_person(1);
        s.hold(&[0], "lab");
        s.hold(&[0], "team");
        s.write(0, "lab", "notes.md", "one");
        s.write(0, "team", "notes.md", "one");
        let (conn, identity) = (&s[0].conn, &s[0].identity);
        let (relay, other_relay) = ([7u8; 32], [8u8; 32]);
        let to_go = |relays: &[[u8; 32]]| names_to_go(conn, identity, relays).unwrap();
        let both =
            |lab: bool, team: bool| vec![("lab".to_string(), lab), ("team".to_string(), team)];

        assert_eq!(to_go(&[relay]), both(true, true));
        // No relay is asked about: nothing is known to wait.
        assert_eq!(to_go(&[]), both(false, false));
        let lab = held_rows::channel_of_name(conn, "lab").unwrap().unwrap();
        kept_rows::sent(conn, &relay, &lab, i64::MAX / 2).unwrap();
        assert_eq!(to_go(&[relay]), both(false, true));
        // It waits at another relay still, wherever that relay comes
        // among those asked about.
        assert_eq!(to_go(&[relay, other_relay]), both(true, true));
        assert_eq!(to_go(&[other_relay, relay]), both(true, true));
        // What a relay had no room for waits too.
        let held = entries::channel_entries_after(conn, &lab, 0, 1).unwrap();
        kept_rows::refused(conn, &relay, &lab, held[0].seq).unwrap();
        assert_eq!(to_go(&[relay]), both(true, true));
        // A device that follows no phrase sends nothing, and holds none.
        let alone = Machine::new(7);
        assert!(
            names_to_go(&alone.conn, &alone.identity, &[relay])
                .unwrap()
                .is_empty()
        );
    }

    /// Since when names have waited to be sent (decision 2026-10-04
    /// §10.1): the earliest time from which the first entry that waits
    /// at one of the relays asked about has waited there. An entry waits
    /// at a relay from the later of when the device stored it and when
    /// that relay was last connected. Nothing where nothing waits, and
    /// nothing where no relay is asked about.
    #[test]
    fn test_since_when_names_have_waited_to_be_sent() {
        use crate::leaving::names_waiting_since;
        let mut s = Several::of_one_person(1);
        s.hold(&[0], "lab");
        s.hold(&[0], "team");
        s.write(0, "lab", "notes.md", "one");
        s.write(0, "team", "notes.md", "one");
        s.write(0, "team", "more.md", "two");
        let (conn, identity) = (&s[0].conn, &s[0].identity);
        let (relay, other_relay) = ([7u8; 32], [8u8; 32]);
        // Each relay with when it was last connected.
        let since = |relays: &[([u8; 32], i64)]| {
            names_waiting_since(conn, identity, relays, &|_| true).unwrap()
        };
        // Both connected before anything was stored.
        let long = |relays: &[[u8; 32]]| {
            let relays: Vec<([u8; 32], i64)> = relays.iter().map(|relay| (*relay, 0)).collect();
            since(&relays)
        };
        let channel = |name: &str| held_rows::channel_of_name(conn, name).unwrap().unwrap();
        let (lab, team) = (channel("lab"), channel("team"));
        // Each entry was stored at a time of its own.
        let held =
            |channel: &[u8; 32]| entries::channel_entries_after(conn, channel, 0, 8).unwrap();
        let stored = |channel: &[u8; 32], at: &[i64]| {
            for (held, at) in held(channel).iter().zip(at) {
                conn.execute(
                    "UPDATE entries SET stored_at = ?1 WHERE seq = ?2",
                    rusqlite::params![at, held.seq],
                )
                .unwrap();
            }
        };
        stored(&lab, &[500]);
        stored(&team, &[300, 400]);

        // The first that waits, of the earliest name.
        assert_eq!(long(&[relay]), Some(300));
        assert_eq!(long(&[]), None);
        // A relay that connected after the entries were stored: they
        // have waited there since it connected, and no longer.
        assert_eq!(since(&[(relay, 450)]), Some(450));
        assert_eq!(since(&[(relay, 350)]), Some(350));
        assert_eq!(since(&[(relay, 9_000)]), Some(9_000));
        // Of two relays, the earlier of the two times: at the one that
        // has been there throughout, since the entry was stored.
        assert_eq!(since(&[(relay, 9_000), (other_relay, 0)]), Some(300));
        assert_eq!(since(&[(relay, 9_000), (other_relay, 8_000)]), Some(8_000));
        // The first of `team` is sent: its second waits, from when it
        // was stored.
        kept_rows::sent(conn, &relay, &team, held(&team)[0].seq).unwrap();
        assert_eq!(long(&[relay]), Some(400));
        // What was stored after the relay connected waits from when it
        // was stored.
        assert_eq!(since(&[(relay, 350)]), Some(400));
        assert_eq!(since(&[(relay, 450)]), Some(450));
        // At another relay everything waits still.
        assert_eq!(long(&[relay, other_relay]), Some(300));
        assert_eq!(long(&[other_relay, relay]), Some(300));
        // Everything is sent to the one: nothing waits there.
        kept_rows::sent(conn, &relay, &team, i64::MAX / 2).unwrap();
        assert_eq!(long(&[relay]), Some(500));
        kept_rows::sent(conn, &relay, &lab, i64::MAX / 2).unwrap();
        assert_eq!(long(&[relay]), None);
        assert_eq!(since(&[(relay, 9_000)]), None);
        // What a relay had no room for waits from when it was stored,
        // or from when the relay connected.
        kept_rows::refused(conn, &relay, &team, held(&team)[1].seq).unwrap();
        assert_eq!(long(&[relay]), Some(400));
        assert_eq!(since(&[(relay, 700)]), Some(700));
        // The personal channel is no name: what waits of it is not said.
        let alone = Machine::new(7);
        assert_eq!(
            names_waiting_since(&alone.conn, &alone.identity, &[(relay, 0)], &|_| true).unwrap(),
            None
        );
    }

    /// A look says when the device applied the change that stands: when
    /// it left the generation before, where it left one (decision
    /// 2026-10-04 §10.1). A status counts some things only for a time
    /// from then.
    #[test]
    fn test_a_look_says_when_the_device_applied_the_change() {
        let mut s = Several::of_one_person(2);
        let seen = |s: &Several, n: usize| {
            look(&s[n].conn, &s[n].identity, &AtRelays::default(), 0).unwrap()
        };
        // Under the first statement, no generation was left.
        assert_eq!(seen(&s, 0).applied_at, None);
        assert_eq!(seen(&s, 1).applied_at, None);
        let change = s.change(0, &[0, 1], &[]);
        let made = s.now;
        assert_eq!(seen(&s, 0).applied_at, Some(made));
        assert_eq!(seen(&s, 1).applied_at, None, "it has not applied it");
        let later = s.tick() + 600;
        take(&s[1].conn, &s[1].identity, &change, later).unwrap();
        assert_eq!(seen(&s, 1).change, Some(2));
        assert_eq!(seen(&s, 1).applied_at, Some(later));
        // The later of two.
        s.change(0, &[0, 1], &[]);
        assert_eq!(seen(&s, 0).applied_at, Some(s.now));
        assert_eq!(seen(&s, 0).change, Some(3));
    }

    /// A look says whether the change that the device applied removed a
    /// key that the statement before had not, as the device found it
    /// when it applied the change (decision 2026-10-04 §10.1). A renewal
    /// removes nobody, though its statement lists every key removed so
    /// far: a status does not then say that a removal is not yet applied.
    #[test]
    fn test_a_look_says_whether_the_change_removed_a_key() {
        let mut s = Several::of_one_person(3);
        let seen = |s: &Several, n: usize| {
            look(&s[n].conn, &s[n].identity, &AtRelays::default(), 0).unwrap()
        };
        let removed = |s: &Several, n: usize| {
            let seen = seen(s, n);
            (seen.removed_a_key, seen.removed.len())
        };
        // Under the first statement nobody was removed.
        assert_eq!(removed(&s, 0), (false, 0));
        // Device 2 is removed: on the device that made the change, and
        // on one that applies it.
        let removal = s.change(0, &[0, 1], &[2]);
        assert_eq!(removed(&s, 0), (true, 1));
        assert_eq!(removed(&s, 1), (false, 0));
        let now = s.tick();
        take(&s[1].conn, &s[1].identity, &removal, now).unwrap();
        assert_eq!(removed(&s, 1), (true, 1));
        // A renewal: its statement lists the key removed before, and
        // removes nobody.
        let renewal = s.change(0, &[0, 1], &[]);
        assert_eq!(removed(&s, 0), (false, 1));
        let now = s.tick();
        take(&s[1].conn, &s[1].identity, &renewal, now).unwrap();
        assert_eq!(seen(&s, 1).change, Some(3));
        assert_eq!(removed(&s, 1), (false, 1));
        // A device that leaves its phrase keeps nothing of it.
        s.change(0, &[0], &[1]);
        assert_eq!(removed(&s, 0), (true, 2));
        let now = s.tick();
        crate::leaving::forget(&s[0].conn, &s[0].identity, false, now).unwrap();
        assert_eq!(
            meta::get(&s[0].conn, meta::PERSON_REMOVED_A_KEY).unwrap(),
            None
        );
    }

    /// A device that applies a removal after it was behind sees the key
    /// removed against the statement it held (decision 2026-10-04 §10.1):
    /// where it comes to a renewal that was made after a removal it never
    /// applied, a key was removed since what it held.
    #[test]
    fn test_a_device_that_was_behind_sees_a_key_removed_since_what_it_held() {
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1], &[2]);
        let renewal = s.change(0, &[0, 1], &[]);
        let now = s.tick();
        take(&s[1].conn, &s[1].identity, &renewal, now).unwrap();
        let seen = look(&s[1].conn, &s[1].identity, &AtRelays::default(), now).unwrap();
        assert_eq!((seen.change, seen.removed_a_key), (Some(3), true));
    }

    /// What another device wrote as a name and is none is not shown by a
    /// look, in anything it says or lists: it is counted, and said as a
    /// number (decision 2026-10-04 §16). So neither `cordelia devices` nor
    /// `cordelia status`, with `--json` or without, shows it.
    #[test]
    fn test_a_look_counts_what_is_listed_and_is_no_name_and_shows_none_of_it() {
        let mut s = Several::of_one_person(2);
        let now = s.tick();
        s.hold(&[1], "lab");
        names::say(&s[1].conn, &s[1].identity, "lab", now).unwrap();
        let no_names = writes_words_that_are_no_names(&mut s, 1, 0);
        let look_of = |s: &Several| {
            let seen = look(&s[0].conn, &s[0].identity, &AtRelays::default(), s.now).unwrap();
            let as_json = serde_json::to_string(&seen).unwrap();
            (seen, as_json)
        };

        let (seen, as_json) = look_of(&s);
        assert_eq!(seen.names_not_shown, no_names);
        assert!(
            seen.says.contains(&format!(
                "{no_names} names that cannot be shown are listed by a device: what they are \
                 called is not a name as this version writes one"
            )),
            "{:?}",
            seen.says
        );
        assert!(!as_json.to_uppercase().contains("NOT-A-NAME"), "{as_json}");
        assert!(as_json.len() < 10_000, "{}", as_json.len());

        // Device 1 is removed: what it listed and was a name is shown as
        // listed by no device yet, and what was none is not noted at all.
        s.change(0, &[0], &[1]);
        let (seen, as_json) = look_of(&s);
        let shown: Vec<&str> = seen
            .names_not_listed
            .iter()
            .map(|name| name.name.as_str())
            .collect();
        assert_eq!(shown, ["lab"]);
        assert_eq!(seen.names_not_shown, 0);
        assert!(!as_json.to_uppercase().contains("NOT-A-NAME"), "{as_json}");
        // One that an earlier build noted is counted, and not shown.
        let noted = &words_that_are_no_names()[0];
        held_rows::note_name_before(&s[0].conn, noted, &s.key(1), s.now).unwrap();
        let (seen, as_json) = look_of(&s);
        assert_eq!(seen.names_not_listed.len(), 1);
        assert_eq!(seen.names_not_shown, 1);
        assert!(
            seen.says
                .iter()
                .any(|line| line.starts_with("1 name that cannot be shown is listed")),
            "{:?}",
            seen.says
        );
        assert!(!as_json.to_uppercase().contains("NOT-A-NAME"), "{as_json}");
    }

    fn maps(on: &Machine, name: &str, sync_on: bool) {
        let mappings = serde_json::json!([{ "folder": "/home/sam/notes", "name": name }]);
        meta::set(&on.conn, meta::SYNC_CLAUDE_MAPPINGS, &mappings.to_string()).unwrap();
        if sync_on {
            meta::set(&on.conn, meta::SYNC_CLAUDE_DIR, "/home/sam/.claude").unwrap();
        }
    }

    /// A device that comes to follow a phrase holds a name for each
    /// folder it maps (decision 2026-10-04 §5.2, §6): by making a phrase,
    /// and by accepting a device that follows one. With sync on it says
    /// that it syncs them. And where a phrase is replaced, or a device
    /// leaves, its folders forget what they had agreed.
    #[test]
    fn test_a_device_that_comes_to_follow_a_phrase_holds_its_folders_names() {
        let mut s = Several::new(3);
        maps(&s[0], "lab", true);
        maps(&s[1], "lab", true);
        maps(&s[2], "notes", false);
        let holds = |s: &Several, n: usize| -> Vec<String> {
            let names = held_rows::names(&s[n].conn).unwrap();
            names.into_iter().map(|name| name.name).collect()
        };
        let says = |s: &Several, n: usize| -> Vec<String> {
            let said = names::said_here(&s[n].conn, &s[n].identity).unwrap();
            said.into_iter().collect()
        };

        // `cordelia phrase`: the node's half is `start_again`.
        let now = s.tick();
        let made = crate::person::first_entry(&s.phrase, &s.key(0), "device 0").unwrap();
        crate::leaving::start_again(
            &s[0].conn,
            &s[0].identity,
            crate::leaving::Among::NoPhrase,
            &made.entry,
            &made.statement_key,
            now,
        )
        .unwrap();
        assert_eq!(
            (holds(&s, 0), says(&s, 0)),
            (vec!["lab".into()], vec!["lab".into()])
        );

        // `cordelia accept`: a device that followed no phrase joins.
        assert!(matches!(s.add(0, 1), Accepted::Joined(_)));
        assert_eq!(
            (holds(&s, 1), says(&s, 1)),
            (vec!["lab".into()], vec!["lab".into()])
        );
        // With sync off it holds the name, and says nothing.
        assert!(matches!(s.add(0, 2), Accepted::Joined(_)));
        assert_eq!(
            (holds(&s, 2), says(&s, 2)),
            (vec!["notes".to_string()], vec![])
        );

        // Its folders have agreed something, and a name was listed before
        // a change. Then the device leaves: both are forgotten, and it
        // keeps the names it held.
        let channel = written(&s[1], "lab");
        let record = agreed(&s[1], 1, "one");
        sync_state::save(&s[1].conn, "/home/sam/memory", &channel, "a.md", &record).unwrap();
        held_rows::note_name_before(&s[1].conn, "old", &s.key(0), now).unwrap();
        let noted = serde_json::json!([{ "name": "lab", "file": "x.md" }]).to_string();
        meta::set(&s[1].conn, meta::PERSON_NOT_CARRIED, &noted).unwrap();
        let now = s.tick();
        assert!(crate::leaving::forget(&s[1].conn, &s[1].identity, false, now).unwrap());
        assert!(!sync_state::any(&s[1].conn, "/home/sam/memory", &channel).unwrap());
        assert!(held_rows::names_before(&s[1].conn).unwrap().is_empty());
        assert_eq!(
            meta::get(&s[1].conn, meta::PERSON_NOT_CARRIED).unwrap(),
            None
        );
        assert_eq!(holds(&s, 1), ["lab"]);
    }

    /// The key that a chain names by its first 16 bytes is one that the
    /// device knows of with those bytes: a device of the statement, a key
    /// it removed, a key added since. It is no key where the device
    /// knows of none.
    #[test]
    fn test_a_links_signer_is_the_one_key_the_device_knows_of_with_those_bytes() {
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1], &[2]);
        let nine = Machine::new(9);
        s.machines.push(nine);
        s.hand(0, 3);
        let conn = &s[0].conn;
        for known in [0, 1, 2, 3] {
            let key = s.key(known);
            let signer = Link::signer_of(&key);
            assert_eq!(
                key_signed_as(conn, &signer).unwrap(),
                Some(key),
                "device {known}"
            );
        }
        assert_eq!(key_signed_as(conn, &[0xee; 16]).unwrap(), None);
        // A device that follows no phrase knows of none.
        let alone = Machine::new(7);
        let signer = Link::signer_of(&s.key(0));
        assert_eq!(key_signed_as(&alone.conn, &signer).unwrap(), None);
    }
}
