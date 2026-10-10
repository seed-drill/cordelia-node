//! End to end: a device's side of its relays, for the channels of its own
//! (decision 2026-10-04 §2.4, §4.6, §7.3).
//!
//! The device is in this process: the node's own engine, over real
//! connections, with a database of its own. What a device holds of its
//! person is set up through the functions that the commands will call.
//! The relays are processes of their own, started through the harness on
//! this machine, and what one holds is read from its database. Where a
//! test says what a relay answers, a stand-in answers in this process.
//!
//! Each device reads the time from a clock of its own, which a test runs
//! ahead where a wait is tested.

mod common;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use cordelia_api::adding::{Accepted, accept, add_device};
use cordelia_api::at_relays::{self, Stands};
use cordelia_api::change::make_change;
use cordelia_api::marks;
use cordelia_api::person::{Shown, first_statement, held, hold_name, shown};
use cordelia_api::publish::{PlannedAgainst, Published, Write, publish, read};
use cordelia_api::sender::{self, At, NotSent, Request, Sent};
use cordelia_api::state::{
    AppState, AtRelay, AtRelays, CannotGoOn, DoorAsk, LeftAt, LeftRead, ProofMade, ProvedBy,
};
use cordelia_api::take::take;
use cordelia_core::protocol::{
    CHANNEL_PROOF_AGAIN_SECS, ENTRY_PAGE_MAX_ENTRIES, HAND_OVER_KEPT_SECS,
    MAX_CHANNELS_PROVED_ON_A_CONNECTION, OUTBOX_REFUSED_RETRY_MAX_SECS,
    OWN_ENTRY_REQUESTS_PER_MINUTE, SHOW_LEAVE_SECS, WAKE_WAIT_SECS, entry_cost,
};
use cordelia_crypto::addition::Addition;
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Entry, Inside, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::message;
use cordelia_crypto::phrase::Phrase;
use cordelia_crypto::slots::slot_id;
use cordelia_crypto::statement::Device as Listed;
use cordelia_network::messages::{
    ChannelProve, ChannelProved, EntryPull, EntryPulled, EntryPush, EntryPushed, EntryRefused,
    EntryShown, Protocol, PushAnswer, ShowAnswer, WireMessage,
};
use cordelia_network::{codec, connection, transport};
use cordelia_node::device_entries::{
    Asked, Clock, Counts, DeviceEntries, LeftRefused, Link, NoLeave, PairRead, Pass, Refused, Relay,
};
use cordelia_storage::acts::{self, TypedKey};
use cordelia_storage::person::State;
use cordelia_storage::{
    at_relays as kept_rows, entries, messages as held_messages, meta, person as held_rows,
};

use common::*;

const WORDS: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const OTHER_WORDS: &str =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

fn phrase() -> Phrase {
    Phrase::parse(WORDS).unwrap()
}

// ── A device, in this process ────────────────────────────────────────

/// A device: its database, its key, a clock of its own, the node's engine
/// for its side of its relays, and its connections.
struct Device {
    label: &'static str,
    state: Arc<AppState>,
    clock: Clock,
    engine: Arc<DeviceEntries>,
    manager: connection::ConnectionManager,
    /// The relays it is set up with, each with its connection where it
    /// has one.
    relays: Vec<Relay>,
    _dir: tempfile::TempDir,
}

impl Device {
    /// A new install, which follows no phrase and is set up with no relay.
    fn new(label: &'static str) -> Self {
        Self::proving_at_most(label, MAX_CHANNELS_PROVED_ON_A_CONNECTION)
    }

    /// [`Self::new`], for a device whose relays remember the proofs of
    /// `most_proved` channels for one connection.
    fn proving_at_most(label: &'static str, most_proved: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::generate().unwrap();
        let for_transport = Arc::new(NodeIdentity::from_seed(*identity.seed()).unwrap());
        let endpoint =
            transport::create_endpoint(&for_transport, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        let manager = connection::ConnectionManager::new(
            for_transport,
            endpoint,
            vec![],
            vec!["personal".into()],
            port,
        );
        let state = Arc::new(AppState {
            db: Mutex::new(cordelia_storage::db::open_in_memory().unwrap()),
            identity,
            bearer_token: "t".into(),
            home_dir: dir.path().to_path_buf(),
            started_at: std::time::Instant::now(),
            sync_errors: AtomicU64::new(0),
            peers_hot: AtomicU64::new(0),
            peers_warm: AtomicU64::new(0),
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
        });
        let clock = Clock::system();
        let engine = DeviceEntries::proving_at_most(state.clone(), clock.clone(), most_proved);
        Self {
            label,
            state,
            clock,
            engine,
            manager,
            relays: Vec::new(),
            _dir: dir,
        }
    }

    fn db(&self) -> MutexGuard<'_, rusqlite::Connection> {
        self.state.db.lock().unwrap()
    }

    fn key(&self) -> [u8; 32] {
        self.state.identity.public_key()
    }

    fn now(&self) -> i64 {
        self.clock.unix()
    }

    // ── Its relays ───────────────────────────────────────────────────

    /// The device is set up with a relay that it calls `name`, and has
    /// not reached it.
    fn set_up_with(&mut self, name: &str) {
        if !self.relays.iter().any(|relay| relay.name == name) {
            self.relays.push(Relay {
                name: name.to_string(),
                link: None,
            });
        }
        self.state.own_channels.set_up_with(self.relays.len());
    }

    /// The device connects to `relay`, which it calls `name`: on a new
    /// connection, whatever it had.
    async fn connects(&mut self, name: &str, relay: &Node) {
        self.connects_to(name, relay.p2p, key_of(relay)).await;
    }

    /// [`Self::connects`], to whoever listens at `port` on this machine
    /// with the key `key`.
    async fn connects_to(&mut self, name: &str, port: u16, key: [u8; 32]) {
        self.disconnects(name);
        let relay = self
            .manager
            .connect_to(format!("127.0.0.1:{port}").parse().unwrap())
            .await
            .unwrap_or_else(|e| panic!("{} does not reach {name}: {e}", self.label));
        assert_eq!(relay.0, key, "another key answered at the port of {name}");
        let conn = self.manager.get_connection(&relay).unwrap().clone();
        self.set_up_with(name);
        let link = Link::new(name, relay, conn);
        self.relay_mut(name).link = Some(link);
    }

    /// The device is set up no longer with the relay it calls `name`.
    fn sets_up_no_longer(&mut self, name: &str) {
        self.disconnects(name);
        self.relays.retain(|relay| relay.name != name);
        self.state.own_channels.set_up_with(self.relays.len());
    }

    /// The device's connection to the relay it calls `name` is closed. It
    /// is still set up with it.
    fn disconnects(&mut self, name: &str) {
        let link = self
            .relays
            .iter_mut()
            .find(|relay| relay.name == name)
            .and_then(|relay| relay.link.take());
        if let Some(link) = link {
            self.manager.disconnect(link.relay());
        }
    }

    fn relay_mut(&mut self, name: &str) -> &mut Relay {
        self.relays
            .iter_mut()
            .find(|relay| relay.name == name)
            .unwrap()
    }

    /// Its connection to the relay it calls `name`.
    fn link(&self, name: &str) -> Link {
        let relay = self.relays.iter().find(|relay| relay.name == name);
        relay.and_then(|relay| relay.link.clone()).unwrap()
    }

    /// The connection itself to the relay it calls `name`, for a test
    /// that opens streams of its own on it.
    fn connection(&self, name: &str) -> quinn::Connection {
        let link = self.link(name);
        self.manager.get_connection(link.relay()).unwrap().clone()
    }

    /// The whole pass, as the node makes it each time it fetches.
    async fn passes(&self) {
        self.engine.pass(&self.relays, Pass::Whole).await;
    }

    /// The pass that sends, as the node makes it on the timer of what
    /// waits to be sent, and when something is published.
    async fn sends(&self) {
        self.engine.pass(&self.relays, Pass::Send).await;
    }

    fn counts(&self, name: &str) -> Counts {
        self.engine.counts(name)
    }

    /// What a status reads.
    fn status(&self) -> AtRelays {
        self.state.own_channels.read()
    }

    /// What a status reads of the relay it calls `name`.
    fn at(&self, name: &str) -> AtRelay {
        let status = self.status();
        let at = status.relays.iter().find(|at| at.relay == name);
        at.unwrap_or_else(|| panic!("the status says nothing of {name}"))
            .clone()
    }

    /// Whether there is leave to use its connection to `name`.
    fn has_leave(&self, name: &str) -> Result<(), NoLeave> {
        self.engine.leave().has(&self.db(), &self.link(name))
    }

    /// Open a stream for a channel of the device's own on `link`, through
    /// the one way in: `request` is built under the change entry that the
    /// device keeps now, and nothing is kept of its being opened.
    async fn opens<R, T>(
        &self,
        link: &Link,
        request: &WireMessage,
        read: impl FnOnce(WireMessage) -> R,
        take: impl FnOnce(&rusqlite::Connection, R) -> T,
    ) -> Result<T, Refused> {
        let under = self.latest().id();
        let asked = Asked {
            under: &under,
            request,
        };
        self.engine
            .leave()
            .open(&self.state.db, link, asked, |_| (), read, take)
            .await
    }

    // ── What it holds of its person ──────────────────────────────────

    /// The phrase is made on this device, which follows it.
    fn makes_the_phrase(&self, phrase: &Phrase) {
        first_statement(
            &self.db(),
            &self.state.identity,
            phrase,
            self.label,
            self.now(),
        )
        .unwrap();
    }

    /// This device adds `new`, which accepts. The hand-over is given
    /// across by the test, as the pair channel would carry it.
    fn adds(&self, new: &Device) {
        let now = self.now();
        let added = add_device(&self.db(), &self.state.identity, &new.key(), new.label, now);
        let hand_over = added.unwrap().hand_over;
        let accepted = accept(
            &new.db(),
            &new.state.identity,
            &self.key(),
            now,
            false,
            &hand_over,
            now,
        );
        let accepted = accepted.unwrap();
        assert!(matches!(accepted, Accepted::Joined(_)), "{accepted:?}");
    }

    fn holds(&self, name: &str) {
        hold_name(&self.db(), name, self.now()).unwrap();
    }

    /// The device writes the text `said` under `file` in `name`, over
    /// what it reads there.
    fn writes(&self, name: &str, file: &str, said: &str) -> CheckedEntry {
        self.puts(name, file, Value::Text(said.to_string()))
    }

    /// The device deletes `file` in `name`, over what it reads there.
    fn deletes(&self, name: &str, file: &str) -> CheckedEntry {
        self.puts(name, file, Value::Delete)
    }

    /// The device writes `value` under `file` in `name`, over what it
    /// reads there.
    fn puts(&self, name: &str, file: &str, value: Value) -> CheckedEntry {
        let db = self.db();
        let slot = read(&db, name, file).unwrap().slot;
        let write = Write {
            name,
            file,
            value,
            planned: PlannedAgainst::what_is_in(&slot),
            merge: None,
        };
        match publish(&db, &self.state.identity, &write, self.now()).unwrap() {
            Published::Made(entry) => *entry,
            other => panic!("{other:?}"),
        }
    }

    /// The text that is the current version of `file` in `name`.
    fn text(&self, name: &str, file: &str) -> Option<String> {
        match read(&self.db(), name, file).ok()?.slot.current?.value {
            Value::Text(text) => Some(text),
            other => Some(format!("{other:?}")),
        }
    }

    /// The latest change entry it keeps.
    fn latest(&self) -> CheckedEntry {
        at_relays::to_show(&self.db()).unwrap().unwrap().entry
    }

    fn stands(&self) -> Stands {
        at_relays::stands(&self.db()).unwrap()
    }

    /// A change is made on this device, with the phrase: `stay` stay, and
    /// `removed` are removed. It applies it. Returns the change entry.
    fn changes(&self, phrase: &Phrase, stay: &[&Device], removed: &[&Device]) -> CheckedEntry {
        let entry = self.makes_change(phrase, stay, removed);
        let outcome = shown(&self.db(), &self.state.identity, &entry, self.now()).unwrap();
        assert!(matches!(outcome, Shown::Applied(_)), "{outcome:?}");
        entry
    }

    /// [`Self::changes`], but the change is not applied: the change entry
    /// is returned, for whatever shows it to the device later.
    fn makes_change(&self, phrase: &Phrase, stay: &[&Device], removed: &[&Device]) -> CheckedEntry {
        let db = self.db();
        let applied = held(&db).unwrap().unwrap().statement;
        let latest = at_relays::to_show(&db).unwrap().unwrap().entry;
        let stay: Vec<Listed> = stay
            .iter()
            .map(|device| Listed::new(device.key(), device.label).unwrap())
            .collect();
        let removed: Vec<[u8; 32]> = removed.iter().map(|device| device.key()).collect();
        make_change(phrase, &applied, &latest, &self.key(), stay, &removed).unwrap()
    }

    /// The person secret of the statement it has applied.
    fn secret(&self) -> [u8; 32] {
        held_rows::applied_secret(&self.db())
            .unwrap()
            .unwrap()
            .secret
    }

    /// The secret of the personal channel in the generation applied.
    fn personal_secret(&self) -> [u8; 32] {
        derive::personal_secret(&self.secret()).unwrap()
    }

    /// The ID of the personal channel in the generation applied.
    fn personal(&self) -> [u8; 32] {
        derive::channel_id(&self.personal_secret()).unwrap()
    }

    /// The secret of the channel of `name` in the generation applied.
    fn name_secret(&self, name: &str) -> [u8; 32] {
        derive::own_secret(&self.secret(), name).unwrap()
    }

    /// The ID of the channel of `name` in the generation applied.
    fn channel(&self, name: &str) -> [u8; 32] {
        derive::channel_id(&self.name_secret(name)).unwrap()
    }

    /// Sync is on here, or off: the node's settings hold a Claude Code
    /// directory, or none. Where it is on, the device has the messages
    /// channel (decision 2026-10-09 §2.1).
    fn syncs(&self, on: bool) {
        let db = self.db();
        match on {
            true => meta::set(&db, meta::SYNC_CLAUDE_DIR, "/home/sam/.claude").unwrap(),
            false => meta::remove(&db, meta::SYNC_CLAUDE_DIR).unwrap(),
        }
    }

    /// The secret of the messages channel in the generation applied.
    fn messages_secret(&self) -> [u8; 32] {
        derive::messages_secret(&self.secret()).unwrap()
    }

    /// The ID of the messages channel in the generation applied.
    fn messages(&self) -> [u8; 32] {
        derive::channel_id(&self.messages_secret()).unwrap()
    }

    /// The device writes its message numbered `number`, to `to`, in the
    /// slot of its own that the number names, at the number's revision:
    /// an entry of the messages channel, through its store, as a sender
    /// will write it (decision 2026-10-09 §2.2, §2.3).
    fn writes_message(&self, number: u64, to: &str, body: &str) -> CheckedEntry {
        let said = message::Message {
            asks: false,
            sent: self.now() as u64,
            nonce: [number as u8; 16],
            thread: [0; 16],
            answers: [0; 16],
            from: "github.com/owner/repo".into(),
            to: message::To::Name(to.into()),
            link: None,
            body: body.into(),
        };
        let value = said.to_value(|_| true).unwrap();
        let name = message::message_name(&self.key(), number).unwrap();
        let rev = message::message_rev(number).unwrap();
        let inside = message::inside(name, value);
        let entry = Entry::seal(&self.messages_secret(), &self.state.identity, rev, &inside);
        let entry = entry.unwrap().check().unwrap();
        entries::store(&self.db(), &entry, self.now()).unwrap();
        entry
    }

    /// The device says, in its personal channel, that it syncs `name`.
    fn says_it_syncs(&self, name: &str) {
        cordelia_api::names::say(&self.db(), &self.state.identity, name, self.now()).unwrap();
    }

    /// The agent of `from` on this device sends `body` to `to`, through
    /// the sender of messages, at the device's clock: as a route will
    /// (decision 2026-10-09 §2.3, §4.3).
    fn sends_message(&self, from: &str, to: message::To, body: &str) -> Result<Sent, NotSent> {
        let db = self.db();
        let own_channels = &self.state.own_channels;
        let at = At {
            now: self.engine.unix(),
            fetched: sender::fetched(&db, own_channels, self.clock.now()).unwrap(),
            no_place: own_channels.no_place(),
            per_folder_per_hour: 20,
        };
        let request = Request {
            from: from.into(),
            to,
            asks: false,
            link: None,
            body: body.into(),
            thread: [0; 16],
            answers: [0; 16],
        };
        sender::send(&db, &self.state.identity, &at, &request)
    }

    /// The bodies of the messages it shows now, oldest first, once it has
    /// given places as a show does.
    fn shows_messages(&self) -> Vec<String> {
        let db = self.db();
        let now = self.engine.unix();
        held_messages::give_places(&db, &self.key(), now).unwrap();
        held_messages::shown(&db, now)
            .unwrap()
            .into_iter()
            .map(|shown| shown.body)
            .collect()
    }

    /// The agent of `name` on this device reads message `id`, as a read
    /// will: once places are given, at the node's clock, its list written
    /// where it may be (decision 2026-10-09 §7.2).
    fn reads_message(&self, name: &str, id: &[u8; 16]) -> marks::Marked {
        let db = self.db();
        let now = self.engine.unix();
        held_messages::give_places(&db, &self.key(), now).unwrap();
        let fetched = sender::fetched(&db, &self.state.own_channels, self.clock.now()).unwrap();
        marks::read_here(&db, &self.state.identity, name, id, now, fetched).unwrap()
    }

    /// The bodies of the messages that the agent of `name` has not read,
    /// here or by another device's list, once places are given.
    fn unread_by(&self, name: &str) -> Vec<String> {
        let db = self.db();
        let now = self.engine.unix();
        held_messages::give_places(&db, &self.key(), now).unwrap();
        marks::unread(&db, &self.state.identity, name, now)
            .unwrap()
            .into_iter()
            .map(|shown| shown.body)
            .collect()
    }

    /// The slot of its list of what its agents read, in the messages
    /// channel of the generation applied.
    fn list_slot(&self) -> [u8; 32] {
        let key = derive::slot_key(&self.messages_secret()).unwrap();
        slot_id(&key, &message::read_name(&self.key()).unwrap())
    }

    /// Its list among `held`, as its revision and its marks.
    fn list_in(&self, held: &[Entry]) -> Option<(u64, Vec<[u8; 16]>)> {
        let slot = self.list_slot();
        let entry = held
            .iter()
            .find(|entry| entry.author == self.key() && entry.slot == slot)?;
        let entry = entry.clone().check().unwrap();
        let inside = entry.open(&self.messages_secret()).unwrap();
        let list = message::ReadMarks::from_value(&inside.value).unwrap();
        Some((entry.rev, list.marks))
    }

    /// The numbers it keeps its own message `id` sent under, where it
    /// keeps it: until every relay it is set up with has taken it.
    fn keeps_message(&self, id: &[u8; 16]) -> Option<Vec<u64>> {
        let kept = held_messages::kept(&self.db()).unwrap();
        kept.into_iter()
            .find(|kept| kept.id == *id)
            .map(|kept| kept.numbers)
    }

    /// What its store holds of `channel`, each by what it is named by.
    fn holds_of(&self, channel: &[u8; 32]) -> BTreeSet<[u8; 32]> {
        entries::channel_entries_after(&self.db(), channel, 0, 100_000)
            .unwrap()
            .iter()
            .map(|held| held.entry.id())
            .collect()
    }

    /// Its place at the relay it calls `name` in `channel`.
    fn place(&self, name: &str, channel: &[u8; 32]) -> ([u8; 8], u64) {
        at_relays::place(&self.db(), &self.link(name).relay().0, channel).unwrap()
    }
}

/// Each of `devices` makes a whole pass, `rounds` times over: what one
/// sent in a round, the others take in that round or the next.
async fn all_pass(devices: &[&Device], rounds: usize) {
    for _ in 0..rounds {
        for device in devices {
            device.passes().await;
        }
    }
}

// ── The relays ───────────────────────────────────────────────────────

/// A relay of the test's own, started, that may hold `max_bytes` where
/// that is given.
fn relay_started(name: &'static str, max_bytes: Option<u64>) -> Node {
    let mut relay = node(name, "relay", None);
    if let Some(max_bytes) = max_bytes {
        relay.max_storage_bytes(max_bytes);
    }
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    relay
}

/// The node key of `node`, as the node itself says it.
fn key_of(node: &Node) -> [u8; 32] {
    cordelia_crypto::bech32::decode_public_key(node.cli(&["id"]).trim())
        .expect("a node prints its key")
}

/// A node's database, opened for reading while the node runs.
fn store_of(node: &Node) -> rusqlite::Connection {
    let db = rusqlite::Connection::open_with_flags(
        node.data_dir().join("cordelia.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.busy_timeout(Duration::from_secs(10)).unwrap();
    db
}

/// What `relay` holds of `channel`, in the order in which it stored it,
/// read from its database.
fn held_at(relay: &Node, channel: &[u8; 32]) -> Vec<Entry> {
    entries::channel_entries_after(&store_of(relay), channel, 0, 100_000)
        .unwrap()
        .into_iter()
        .map(|held| held.entry)
        .collect()
}

/// Whether `relay` holds the entry named by `id` in `channel`.
fn holds_at(relay: &Node, channel: &[u8; 32], id: &[u8; 32]) -> bool {
    held_at(relay, channel)
        .iter()
        .any(|entry| entry.id() == *id)
}

/// How many channels from their secrets `relay` holds.
fn channels_at(relay: &Node) -> i64 {
    store_of(relay)
        .query_row("SELECT COUNT(*) FROM relay_channels", [], |row| row.get(0))
        .unwrap()
}

// ── A stand-in for a relay, which answers as the test says ───────────

/// What a stand-in does with a show.
#[derive(Debug, Clone)]
enum Say {
    /// It answers with this.
    Answer(ShowAnswer),
    /// It resets the stream.
    Reset,
    /// It answers nothing, and keeps the stream open.
    Nothing,
}

/// What a test has a stand-in do as each request arrives, before it is
/// answered: for a show, `Some` is what this one is answered with, in the
/// place of what the script says. For a push, `Some` that is no answer
/// has the stand-in take the push and answer nothing: it resets the
/// stream, or keeps it open. For a proof, `Some(Say::Nothing)` has it
/// answer nothing, and keep the stream open, and `Some(Say::Answer(_))`
/// has it answer with that answer of a show, which is no answer to a
/// proof.
type Hook = Box<dyn FnMut(&WireMessage) -> Option<Say> + Send>;

struct Script {
    /// What a show in short is answered with.
    short: Say,
    /// What a show of the whole entry is answered with.
    whole: Say,
    /// Every request that arrived, with the stream it came on.
    seen: Vec<(Protocol, WireMessage)>,
    /// What the test does as each request arrives.
    hook: Option<Hook>,
    /// Whether it answers nothing at all, to any request, and keeps each
    /// stream open.
    silent: bool,
    /// What a pull is answered with, where a test says: a page of
    /// nothing otherwise.
    pulled: Option<Pulled>,
    /// What each entry of a push is answered with, where a test says:
    /// "stored" otherwise.
    pushed: Option<Pushed>,
    /// Whether a proof is answered as one that holds, for a channel
    /// that is held: it is answered with no otherwise.
    proves: bool,
}

/// What a test has a stand-in answer a pull with.
type Pulled = Box<dyn FnMut(&EntryPull) -> EntryPulled + Send>;

/// What a test has a stand-in answer one entry of a push with.
type Pushed = Box<dyn FnMut(&Entry) -> PushAnswer + Send>;

impl Default for Script {
    fn default() -> Self {
        Self {
            short: Say::Answer(ShowAnswer::Held),
            whole: Say::Answer(ShowAnswer::Held),
            seen: Vec::new(),
            hook: None,
            silent: false,
            pulled: None,
            pushed: None,
            proves: false,
        }
    }
}

/// A stand-in for a relay: it takes connections as a relay does, and
/// answers a show as its script says: "held", until a test says
/// otherwise. A proof it answers with no, a pull with a page of nothing,
/// and a push with "stored" for each entry.
struct StandIn {
    port: u16,
    key: [u8; 32],
    script: Arc<Mutex<Script>>,
}

impl StandIn {
    async fn started() -> Self {
        let identity = Arc::new(NodeIdentity::generate().unwrap());
        let key = identity.public_key();
        let endpoint =
            transport::create_endpoint(&identity, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        let manager = connection::ConnectionManager::new(
            identity,
            endpoint.clone(),
            vec![],
            vec!["relay".into()],
            port,
        );
        let ctx = manager.connect_context();
        let script = Arc::new(Mutex::new(Script::default()));
        let shared = script.clone();
        tokio::spawn(async move {
            let _manager = manager; // keeps the endpoint's context alive
            while let Some(incoming) = endpoint.accept().await {
                let Ok(outcome) = connection::inbound_accept(&ctx, incoming).await else {
                    continue;
                };
                let (conn, script) = (outcome.conn, shared.clone());
                tokio::spawn(async move {
                    while let Ok((send, recv)) = conn.accept_bi().await {
                        tokio::spawn(Self::answers(script.clone(), send, recv));
                    }
                });
            }
        });
        Self { port, key, script }
    }

    /// Answer one stream.
    async fn answers(
        script: Arc<Mutex<Script>>,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) {
        let Ok(protocol) = codec::read_protocol_byte(&mut recv).await else {
            return;
        };
        let Ok(request) = codec::read_frame(&mut recv).await else {
            return;
        };
        // What it does with the request: `Ok` with the answer, or with
        // none where the stream is reset, and `Err` where nothing is
        // answered and the stream is kept open.
        let does = {
            let mut script = script.lock().unwrap();
            let hooked = script.hook.as_mut().and_then(|hook| hook(&request));
            let does = match &request {
                WireMessage::EntryShow(_) | WireMessage::EntryShowShort(_) => {
                    let whole = matches!(request, WireMessage::EntryShow(_));
                    let say = if whole { &script.whole } else { &script.short };
                    match hooked.unwrap_or_else(|| say.clone()) {
                        Say::Answer(answer) => {
                            Ok(Some(WireMessage::EntryShown(EntryShown { answer })))
                        }
                        Say::Reset => Ok(None),
                        Say::Nothing => Err(()),
                    }
                }
                WireMessage::ChannelProve(_) if matches!(hooked, Some(Say::Nothing)) => Err(()),
                // An answer of a show, which is no answer to a proof.
                WireMessage::ChannelProve(_) if matches!(hooked, Some(Say::Answer(_))) => {
                    let Some(Say::Answer(answer)) = hooked else {
                        unreachable!()
                    };
                    Ok(Some(WireMessage::EntryShown(EntryShown { answer })))
                }
                WireMessage::ChannelProve(_) => {
                    Ok(Some(WireMessage::ChannelProved(ChannelProved {
                        proved: script.proves,
                    })))
                }
                WireMessage::EntryPull(pull) => {
                    let page = match script.pulled.as_mut() {
                        Some(pulled) => pulled(pull),
                        None => EntryPulled {
                            entries: Vec::new(),
                            next: pull.after,
                            mark: pull.mark,
                        },
                    };
                    Ok(Some(WireMessage::EntryPulled(page)))
                }
                WireMessage::EntryPush(_) if matches!(hooked, Some(Say::Reset)) => Ok(None),
                WireMessage::EntryPush(_) if matches!(hooked, Some(Say::Nothing)) => Err(()),
                WireMessage::EntryPush(push) => {
                    let answers = match script.pushed.as_mut() {
                        Some(pushed) => push
                            .entries
                            .iter()
                            .map(|entry| pushed(&Entry::from_wire(entry).unwrap()))
                            .collect(),
                        None => vec![PushAnswer::Stored; push.entries.len()],
                    };
                    Ok(Some(WireMessage::EntryPushed(EntryPushed { answers })))
                }
                _ => Ok(None),
            };
            script.seen.push((protocol, request));
            match script.silent {
                true => Err(()),
                false => does,
            }
        };
        match does {
            Ok(Some(answer)) => {
                let _ = codec::write_frame(&mut send, &answer).await;
                let _ = send.finish();
            }
            Ok(None) => {
                let _ = send.reset(0u32.into());
            }
            Err(()) => tokio::time::sleep(Duration::from_secs(120)).await,
        }
    }

    /// From now on it answers a show in short with `short`, and a show
    /// of the whole entry with `whole`.
    fn says(&self, short: Say, whole: Say) {
        let mut script = self.script.lock().unwrap();
        (script.short, script.whole) = (short, whole);
    }

    /// From now on it answers nothing, to any request, and keeps each
    /// stream open: as a relay that has stopped, whose connection has
    /// not yet been found dead.
    fn goes_silent(&self) {
        self.script.lock().unwrap().silent = true;
    }

    /// From now on a proof is answered as one that holds, for a channel
    /// that is held, or as one for a channel that is not, as `holds`
    /// says.
    fn holds_what_is_proved(&self, holds: bool) {
        self.script.lock().unwrap().proves = holds;
    }

    /// From now on a pull is answered with what `pulled` gives.
    fn pulls(&self, pulled: impl FnMut(&EntryPull) -> EntryPulled + Send + 'static) {
        self.script.lock().unwrap().pulled = Some(Box::new(pulled));
    }

    /// From now on each entry of a push is answered with what `pushed`
    /// gives.
    fn pushes(&self, pushed: impl FnMut(&Entry) -> PushAnswer + Send + 'static) {
        self.script.lock().unwrap().pushed = Some(Box::new(pushed));
    }

    /// From now on `hook` is called as each request arrives, before it is
    /// answered.
    fn hook(&self, hook: impl FnMut(&WireMessage) -> Option<Say> + Send + 'static) {
        self.script.lock().unwrap().hook = Some(Box::new(hook));
    }

    /// Every request that arrived since this, or [`Self::seen`], was last
    /// asked, as it arrived.
    fn requests(&self) -> Vec<WireMessage> {
        let seen = std::mem::take(&mut self.script.lock().unwrap().seen);
        seen.into_iter().map(|(_, request)| request).collect()
    }

    /// Every request that arrived since this was last asked: each as the
    /// stream it came on, and for a show whether it was whole.
    fn seen(&self) -> Vec<Seen> {
        let seen = std::mem::take(&mut self.script.lock().unwrap().seen);
        seen.iter()
            .map(|(_, request)| match request {
                WireMessage::EntryShow(_) => Seen::Whole,
                WireMessage::EntryShowShort(_) => Seen::Short,
                WireMessage::ChannelProve(_) => Seen::Prove,
                WireMessage::EntryPull(_) => Seen::Pull,
                WireMessage::EntryPush(_) => Seen::Push,
                _ => Seen::Other,
            })
            .collect()
    }
}

/// A request that a stand-in saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    Whole,
    Short,
    Prove,
    Pull,
    Push,
    Other,
}

/// Whether any of `seen` is on a stream for a channel of a device's own.
fn any_of_a_channel(seen: &[Seen]) -> bool {
    seen.iter()
        .any(|one| matches!(one, Seen::Prove | Seen::Pull | Seen::Push | Seen::Other))
}

// ── The show, whole once and short after ─────────────────────────────

/// A device shows its change entry on every pass. On one connection it
/// shows it whole once, and in short from then on: counted by its bytes.
/// On a new connection it is whole once more, and so is an entry that the
/// device comes to keep, which it has not shown there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_shows_its_entry_whole_once_on_a_connection_and_in_short_after() {
    let relay = relay_started("relay", None);
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.connects("relay", &relay).await;
    let entry = device.latest();
    let whole = entry.to_wire().len() as u64;
    assert!(whole > 32 * 1024, "{whole}");

    device.passes().await;
    let first = device.counts("relay");
    assert_eq!((first.whole_shows, first.short_shows), (1, 0));
    assert!(first.shown_bytes >= whole && first.shown_bytes < whole + 256);
    // The relay took it, and holds it.
    assert!(holds_at(&relay, &entry.channel, &entry.id()));
    assert_eq!(device.at("relay").holds_latest, Some(true));

    // Nine passes more: nine shows in short, of some two hundred bytes
    // each, where the whole entry is 32 KB.
    for _ in 0..9 {
        device.passes().await;
    }
    let after = device.counts("relay");
    assert_eq!((after.whole_shows, after.short_shows), (1, 9));
    let in_short = after.shown_bytes - first.shown_bytes;
    assert!(in_short < 9 * 256, "{in_short}");
    assert!(in_short > 9 * 128, "{in_short}");

    // A new connection: the relay remembers nothing of the one before,
    // and the entry is shown whole once. The leave that the old
    // connection had is not the new one's.
    assert_eq!(device.has_leave("relay"), Ok(()));
    device.connects("relay", &relay).await;
    assert_eq!(device.has_leave("relay"), Err(NoLeave::NotGiven));
    device.passes().await;
    device.passes().await;
    let again = device.counts("relay");
    assert_eq!((again.whole_shows, again.short_shows), (2, 10));

    // A change is made on the device: the entry it keeps is another,
    // which it has not shown on this connection. Whole once, and then in
    // short.
    let change = device.changes(&phrase(), &[&device], &[]);
    for _ in 0..3 {
        device.passes().await;
    }
    let changed = device.counts("relay");
    assert_eq!((changed.whole_shows, changed.short_shows), (3, 12));
    assert!(holds_at(&relay, &change.channel, &change.id()));
}

// ── Leave ────────────────────────────────────────────────────────────

/// A proof of the channel of `name`, as `device` makes it for its
/// connection to the relay it calls `relay`.
fn proof_on(device: &Device, relay: &str, name: &str) -> WireMessage {
    let link = device.link(relay);
    let channel = device.channel(name);
    let made = cordelia_crypto::proof::make(
        &device.name_secret(name),
        &link.session().unwrap(),
        &device.key(),
    );
    WireMessage::ChannelProve(ChannelProve {
        channel,
        proof: made.unwrap(),
    })
}

/// Leave is 10 seconds from an answer which says that the relay holds no
/// later change. A stream for a channel of the device's own is refused
/// once it has run out, and opened again after a fresh show. Leave is
/// asked again before what came back on a stream is taken: what arrives
/// after it ran out is dropped, and asked for again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leave_lasts_ten_seconds_from_an_answer_and_is_asked_again_before_anything_is_taken() {
    assert_eq!(SHOW_LEAVE_SECS, 10);
    let relay = relay_started("relay", None);
    let (mut writer, mut reader) = (Device::new("desktop"), Device::new("laptop"));
    writer.makes_the_phrase(&phrase());
    writer.adds(&reader);
    for device in [&writer, &reader] {
        device.holds("notes");
    }
    writer.connects("relay", &relay).await;
    reader.connects("relay", &relay).await;
    all_pass(&[&writer, &reader], 2).await;

    // The device has leave, and a stream is opened: here, a proof.
    let link = writer.link("relay");
    let proof = proof_on(&writer, "relay", "notes");
    async fn proves(device: &Device, link: &Link, proof: &WireMessage) -> Result<bool, Refused> {
        let read = |answer| matches!(answer, WireMessage::ChannelProved(_));
        device.opens(link, proof, read, |_, proved| proved).await
    }
    assert_eq!(writer.has_leave("relay"), Ok(()));
    assert_eq!(proves(&writer, &link, &proof).await, Ok(true));
    // Some seconds short of ten, it still has. (The test's own steps take
    // time too, so it does not ask at nine.)
    writer.clock.run_ahead(Duration::from_secs(6));
    assert_eq!(writer.has_leave("relay"), Ok(()));
    assert_eq!(proves(&writer, &link, &proof).await, Ok(true));
    // At ten seconds it has none, and the stream is refused.
    writer.clock.run_ahead(Duration::from_secs(4));
    assert_eq!(writer.has_leave("relay"), Err(NoLeave::NotGiven));
    assert_eq!(
        proves(&writer, &link, &proof).await,
        Err(Refused::NoLeave(NoLeave::NotGiven))
    );
    // A fresh show gives it again.
    writer.passes().await;
    assert_eq!(writer.has_leave("relay"), Ok(()));
    assert_eq!(proves(&writer, &link, &proof).await, Ok(true));
    // Only a proof, a pull or a push is asked on a stream of a channel.
    let stray = WireMessage::ChannelProved(ChannelProved { proved: true });
    let asked = writer.opens(&link, &stray, |_| (), |_, _| ()).await;
    assert_eq!(asked, Err(Refused::NotARequest));

    // The writer writes a file, and the relay holds it.
    let file = writer.writes("notes", "a.md", "what the file holds");
    writer.passes().await;
    let notes = writer.channel("notes");
    assert!(holds_at(&relay, &notes, &file.id()));

    // The reader pulls the page, and its leave runs out while the page is
    // on its way: nothing of it is taken, and its place is where it was.
    reader.passes().await;
    assert!(reader.holds_of(&notes).contains(&file.id()));
    let second = writer.writes("notes", "b.md", "what the second holds");
    writer.passes().await;
    reader.clock.run_ahead(Duration::from_secs(10));
    assert_eq!(reader.has_leave("relay"), Err(NoLeave::NotGiven));
    // (A fresh show, by a pass that pulls nothing new: the personal
    // channel and the name are read to their ends first.)
    let (mark, after) = reader.place("relay", &notes);
    assert_eq!(after, 1);
    let pull = WireMessage::EntryPull(EntryPull {
        channel: notes,
        mark,
        after,
        limit: ENTRY_PAGE_MAX_ENTRIES,
    });
    // It shows, and has leave.
    let link = reader.link("relay");
    let shown = reader.latest();
    reader
        .engine
        .leave()
        .show(&link, &shown, false)
        .await
        .unwrap();
    assert_eq!(reader.has_leave("relay"), Ok(()));
    let taken = AtomicBool::new(false);
    let late = reader
        .opens(
            &link,
            &pull,
            |answer| {
                // The page has come, and holds the entry. Ten seconds go
                // by before it is taken.
                let WireMessage::EntryPulled(page) = answer else {
                    panic!("not a page");
                };
                assert_eq!(page.entries.len(), 1);
                reader.clock.run_ahead(Duration::from_secs(10));
                page
            },
            |_, _| taken.store(true, Ordering::SeqCst),
        )
        .await;
    assert_eq!(late, Err(Refused::NoLeave(NoLeave::NotGiven)));
    assert!(
        !taken.load(Ordering::SeqCst),
        "a page was taken without leave"
    );
    assert!(!reader.holds_of(&notes).contains(&second.id()));
    assert_eq!(reader.place("relay", &notes), (mark, 1));
    // It is asked for again, by the next pass, and taken.
    reader.passes().await;
    assert!(reader.holds_of(&notes).contains(&second.id()));
    assert_eq!(reader.place("relay", &notes), (mark, 2));
}

/// The timer that sends, and a publish, go through the same leave as the
/// pass: what finds no leave shows again by itself, in short, and then
/// sends. With leave it sends, and shows nothing. With nothing waiting it
/// opens no stream at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_timer_that_sends_and_a_publish_show_again_where_they_find_no_leave() {
    let relay = relay_started("relay", None);
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.connects("relay", &relay).await;
    device.passes().await;
    // Its word that it has sent what it carried is written by that pass
    // (decision 2026-10-04 §8), and goes now: what is counted below is
    // of the notes alone.
    device.sends().await;
    let notes = device.channel("notes");
    let before = device.counts("relay");
    assert_eq!((before.whole_shows, before.short_shows), (1, 0));

    // With leave: what is written is sent, and nothing is shown.
    let first = device.writes("notes", "a.md", "the first");
    device.sends().await;
    assert!(holds_at(&relay, &notes, &first.id()));
    let sent = device.counts("relay");
    assert_eq!((sent.whole_shows, sent.short_shows), (1, 0));
    assert_eq!(sent.pushes, before.pushes + 1);
    // It sends, and neither proves nor pulls.
    assert_eq!((sent.proofs, sent.pages), (before.proofs, before.pages));

    // The leave runs out. With nothing waiting, the pass that sends
    // opens no stream: it does not show either.
    device.clock.run_ahead(Duration::from_secs(SHOW_LEAVE_SECS));
    assert_eq!(device.has_leave("relay"), Err(NoLeave::NotGiven));
    device.sends().await;
    assert_eq!(device.counts("relay"), sent);
    assert_eq!(device.has_leave("relay"), Err(NoLeave::NotGiven));

    // Something is written: the pass that sends finds no leave, shows
    // again by itself, in short, and sends.
    let second = device.writes("notes", "b.md", "the second");
    device.sends().await;
    assert!(holds_at(&relay, &notes, &second.id()));
    let again = device.counts("relay");
    assert_eq!((again.whole_shows, again.short_shows), (1, 1));
    assert_eq!(again.pushes, sent.pushes + 1);
    assert_eq!(again.pushed, sent.pushed + 1);
    assert_eq!(device.has_leave("relay"), Ok(()));
}

/// Leave ends at once, at every relay, when the entry that the device
/// keeps changes: it was given for the entry that was shown.
///
/// **A leave lasts SHOW_LEAVE_SECS by the clock, and this looks at one
/// after a pass at two relays.** On a machine that is busy a pass can
/// take longer than a leave lasts: the leave that it was given has then
/// run out when it is looked at, and that says nothing of the pass. So
/// each pass after which a leave is looked at says when it began. Where
/// there is leave at each relay, the test goes on. Where there is not,
/// **and the pass took less long than a leave lasts, the test fails:**
/// the pass gave none. Where it took longer, the step is made again:
/// the whole pass again, and the change again, with a file more. The
/// first try is the test as it stands on a machine that is not busy, and
/// each later one asserts the same, counted from what stood before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leave_ends_at_once_at_every_relay_when_the_entry_kept_changes() {
    /// How long a leave lasts.
    const LEAVE: Duration = Duration::from_secs(SHOW_LEAVE_SECS);
    /// How often a step is made again where the machine took longer
    /// than a leave lasts over a pass.
    const TRIES: usize = 12;
    let (first, second) = (relay_started("first", None), relay_started("second", None));
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.connects("first", &first).await;
    device.connects("second", &second).await;
    let names = ["first", "second"];
    let leave_at_each = |device: &Device| names.map(|relay| device.has_leave(relay));
    let whole_shows = |device: &Device| names.map(|relay| device.counts(relay).whole_shows);
    let given = [Ok(()), Ok(())];
    // What is said where a pass that took less long than a leave lasts
    // left no leave at a relay, and where every try took longer.
    let no_leave = |after: &str, took: Duration, leave: &[Result<(), NoLeave>; 2]| {
        assert!(
            took >= LEAVE,
            "{after} took {took:?}, which is less than a leave lasts, and there is no leave at \
             each relay: {leave:?}"
        );
    };
    // How many changes were made, and how many passes were made again.
    let (mut changes, mut again) = (0, 0);
    loop {
        assert!(
            again < TRIES,
            "the machine took longer than a leave lasts over a pass, {TRIES} times"
        );
        // The whole pass gives leave at each relay.
        let began = std::time::Instant::now();
        device.passes().await;
        let leave = leave_at_each(&device);
        if leave != given {
            no_leave("the whole pass", began.elapsed(), &leave);
            // Past the leave, and past the longest wait after a show
            // that got none.
            again += 1;
            device
                .clock
                .run_ahead(Duration::from_secs(OUTBOX_REFUSED_RETRY_MAX_SECS));
            continue;
        }
        // The first show on a connection is whole, and no other show of
        // an entry that was shown there is.
        if again == 0 {
            assert_eq!(whole_shows(&device), [1, 1]);
        }
        let shown_before = whole_shows(&device);

        // A change is made on it. No time goes by.
        changes += 1;
        let file = format!("{changes}.md");
        let waiting = device.writes("notes", &file, "written before the change");
        let old_notes = device.channel("notes");
        let change = device.changes(&phrase(), &[&device], &[]);
        for relay in names {
            assert_eq!(device.has_leave(relay), Err(NoLeave::NotGiven));
        }
        // The pass that sends shows the new entry at each, whole, and
        // only then sends: there is leave again at each.
        let began = std::time::Instant::now();
        device.sends().await;
        let leave = leave_at_each(&device);
        let took = began.elapsed();
        if leave != given {
            no_leave("the pass that sends", took, &leave);
            again += 1;
            device
                .clock
                .run_ahead(Duration::from_secs(OUTBOX_REFUSED_RETRY_MAX_SECS));
            continue;
        }
        // Each relay holds the change, and what was carried is not sent
        // by the pass that sends.
        let new_notes = device.channel("notes");
        for relay in [&first, &second] {
            assert!(holds_at(relay, &change.channel, &change.id()));
            assert!(!holds_at(relay, &old_notes, &waiting.id()));
            assert!(held_at(relay, &new_notes).is_empty());
        }
        // One whole show more at each relay, of the new entry.
        assert_eq!(whole_shows(&device), shown_before.map(|shown| shown + 1));
        // The whole pass fetches the name's new channel from each relay,
        // and then sends what it carried: each file that was written
        // before a change.
        device.passes().await;
        for relay in [&first, &second] {
            assert_eq!(held_at(relay, &new_notes).len(), changes);
            assert!(!holds_at(relay, &old_notes, &waiting.id()));
        }
        break;
    }
}

/// Leave is given by an answer which says that the relay holds no later
/// change than the one the device keeps: held, taken, or refused for room
/// or for the allowance, with the refusal kept for the status. Nothing
/// else gives it: not "show it whole", not word of another, not what is
/// no entry, and not a stream that is reset. A short show that is not
/// answered is followed by a whole one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_an_answer_that_says_no_later_change_is_held_gives_leave() {
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.connects_to("relay", relay.port, relay.key).await;
    // Past the leave, and past the longest wait after a show that got
    // none.
    let later = || {
        device
            .clock
            .run_ahead(Duration::from_secs(OUTBOX_REFUSED_RETRY_MAX_SECS))
    };
    let refused = |why: EntryRefused| Say::Answer(ShowAnswer::Refused(why));
    let held = Say::Answer(ShowAnswer::Held);
    let whole = Say::Answer(ShowAnswer::Whole);
    let other = Say::Answer(ShowAnswer::Other {
        rev: 9,
        id: [7; 32],
    });

    // Held: leave, and the pass goes on to the device's channels.
    later();
    device.passes().await;
    assert_eq!(device.has_leave("relay"), Ok(()));
    let seen = relay.seen();
    assert_eq!(seen[0], Seen::Whole);
    assert!(any_of_a_channel(&seen));
    assert_eq!(device.at("relay").holds_latest, Some(true));
    assert_eq!(device.at("relay").no_room, None);

    // "Show it whole", to the short show and then to the whole one,
    // which it is no answer to: no leave, and no stream of a channel.
    relay.says(whole.clone(), whole.clone());
    later();
    device.passes().await;
    assert_eq!(device.has_leave("relay"), Err(NoLeave::NotGiven));
    assert_eq!(relay.seen(), [Seen::Short, Seen::Whole]);
    // With no leave, no stream for a channel is opened at all: the relay
    // sees none, whoever asks for one.
    let proof = proof_on(&device, "relay", "notes");
    let opened = device
        .opens(&device.link("relay"), &proof, |_| (), |_, _| ())
        .await;
    assert_eq!(opened, Err(Refused::NoLeave(NoLeave::NotGiven)));
    assert_eq!(relay.seen(), []);

    // Word of another, which the device does not keep: it shows its own
    // whole, and is answered with what is no entry. No leave, and nothing
    // is done with it.
    let kept = device.latest().id();
    relay.says(
        other.clone(),
        Say::Answer(ShowAnswer::Another(vec![1, 2, 3])),
    );
    later();
    device.passes().await;
    assert_eq!(device.has_leave("relay"), Err(NoLeave::NotGiven));
    assert_eq!(relay.seen(), [Seen::Short, Seen::Whole]);
    assert_eq!(device.latest().id(), kept);
    assert_eq!(device.at("relay").holds_latest, Some(false));
    // Word of another, to the whole show, which it is no answer to.
    relay.says(whole.clone(), other.clone());
    later();
    device.passes().await;
    assert_eq!(device.has_leave("relay"), Err(NoLeave::NotGiven));
    assert_eq!(relay.seen(), [Seen::Short, Seen::Whole]);

    // A stream that is reset: the short show is not answered, and a
    // whole one follows. That is reset too: no leave.
    let before = device.counts("relay");
    relay.says(Say::Reset, Say::Reset);
    later();
    device.passes().await;
    assert_eq!(device.has_leave("relay"), Err(NoLeave::NotGiven));
    assert_eq!(relay.seen(), [Seen::Short, Seen::Whole]);
    assert_eq!(device.counts("relay"), before);
    // The short show is not answered, and the whole one that follows is:
    // held. It is made at once: a show that was not answered at all
    // starts no wait.
    relay.says(Say::Reset, held.clone());
    device.passes().await;
    assert_eq!(device.has_leave("relay"), Ok(()));
    let seen = relay.seen();
    assert_eq!(seen[..2], [Seen::Short, Seen::Whole]);
    assert!(any_of_a_channel(&seen));
    let counts = device.counts("relay");
    assert_eq!(
        (counts.whole_shows, counts.short_shows),
        (before.whole_shows + 1, before.short_shows)
    );

    // Refused for room: the relay holds no later change, and would have
    // taken this one. Leave, and the refusal is in what a status reads.
    later();
    relay.says(whole.clone(), refused(EntryRefused::NoRoom));
    let at = device.now();
    device.passes().await;
    assert_eq!(device.has_leave("relay"), Ok(()));
    assert!(any_of_a_channel(&relay.seen()));
    let status = device.at("relay");
    assert_eq!(status.holds_latest, Some(false));
    let no_room = status.no_room.expect("the refusal is kept");
    assert!(no_room.of_the_change && !no_room.over_allowance);
    assert!((at..at + 5).contains(&no_room.at));
    // Refused for the address's allowance: the same.
    later();
    relay.says(whole.clone(), refused(EntryRefused::OverLimit));
    device.passes().await;
    assert_eq!(device.has_leave("relay"), Ok(()));
    let no_room = device.at("relay").no_room.unwrap();
    assert!(no_room.of_the_change && no_room.over_allowance);
    // Refused as not signed as it must be: that says nothing of what the
    // relay holds. No leave.
    later();
    relay.seen();
    relay.says(whole.clone(), refused(EntryRefused::NotSigned));
    device.passes().await;
    assert_eq!(device.has_leave("relay"), Err(NoLeave::NotGiven));
    assert_eq!(relay.seen(), [Seen::Short, Seen::Whole]);

    // Taken: leave.
    relay.says(whole, Say::Answer(ShowAnswer::Taken));
    later();
    device.passes().await;
    assert_eq!(device.has_leave("relay"), Ok(()));
    assert_eq!(device.at("relay").holds_latest, Some(true));
    // And in short, held: leave again, by a show of some two hundred
    // bytes.
    later();
    relay.seen();
    relay.says(held.clone(), held);
    device.passes().await;
    assert_eq!(device.has_leave("relay"), Ok(()));
    assert_eq!(relay.seen()[0], Seen::Short);
}

/// A show that gets no leave is made again after a wait that doubles, as
/// what a relay refuses for room is sent again: four seconds, eight,
/// sixteen, up to ten minutes. Nothing is shown while a wait lasts, by
/// either pass. The wait is for that relay and that entry: another relay
/// is shown as before, an answer that gives leave ends it, and so does
/// another entry to show.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_show_that_gets_no_leave_is_made_again_after_a_wait_that_doubles() {
    let (stuck, good) = (StandIn::started().await, StandIn::started().await);
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.writes("notes", "a.md", "waiting to be sent");
    device.connects_to("stuck", stuck.port, stuck.key).await;
    device.connects_to("good", good.port, good.key).await;
    device.passes().await;
    stuck.seen();
    good.seen();
    let shows = |relay: &StandIn| -> Vec<Seen> {
        let shown = |one: &Seen| matches!(one, Seen::Whole | Seen::Short);
        relay.seen().into_iter().filter(shown).collect()
    };
    let secs = |secs: u64| device.clock.run_ahead(Duration::from_secs(secs));

    // The one relay asks for the whole entry, each time it is shown it.
    let whole = Say::Answer(ShowAnswer::Whole);
    stuck.says(whole.clone(), whole.clone());
    secs(SHOW_LEAVE_SECS);
    device.passes().await;
    assert_eq!(shows(&stuck), [Seen::Short, Seen::Whole]);
    assert_eq!(shows(&good), [Seen::Short]);
    // At once, and three seconds on: nothing is shown there, by either
    // pass, though something waits to be sent. The other relay is shown
    // as on any pass.
    for _ in 0..2 {
        device.passes().await;
        device.sends().await;
        assert_eq!(shows(&stuck), []);
        assert_eq!(shows(&good), [Seen::Short]);
        secs(3);
    }
    // Past four seconds it is shown again, and gets no leave again.
    device.passes().await;
    assert_eq!(shows(&stuck), [Seen::Short, Seen::Whole]);
    // Then after eight, and not after four more.
    secs(4);
    device.passes().await;
    assert_eq!(shows(&stuck), []);
    secs(4);
    device.passes().await;
    assert_eq!(shows(&stuck), [Seen::Short, Seen::Whole]);
    // And so on: over an hour of passes every ten seconds, it is shown
    // the whole entry a handful of times, where it would have been shown
    // it 360 times.
    let before = device.counts("stuck").whole_shows;
    for _ in 0..360 {
        secs(10);
        device.passes().await;
    }
    let in_an_hour = device.counts("stuck").whole_shows - before;
    assert!((5..=12).contains(&in_an_hour), "{in_an_hour}");
    assert_eq!(device.has_leave("stuck"), Err(NoLeave::NotGiven));

    // An answer that gives leave ends the wait: the next show that gets
    // none starts again at four seconds.
    let held = Say::Answer(ShowAnswer::Held);
    stuck.says(held.clone(), held);
    secs(OUTBOX_REFUSED_RETRY_MAX_SECS);
    device.passes().await;
    assert_eq!(device.has_leave("stuck"), Ok(()));
    stuck.says(whole.clone(), whole.clone());
    secs(SHOW_LEAVE_SECS);
    shows(&stuck);
    device.passes().await;
    assert_eq!(shows(&stuck), [Seen::Short, Seen::Whole]);
    secs(4);
    device.passes().await;
    assert_eq!(shows(&stuck), [Seen::Short, Seen::Whole]);

    // Another entry to show is shown at once, whatever the wait: a
    // change is made on the device.
    device.passes().await;
    assert_eq!(shows(&stuck), []);
    device.changes(&phrase(), &[&device], &[]);
    device.passes().await;
    assert_eq!(shows(&stuck), [Seen::Whole]);
}

/// An answer to a show that gives no leave ends, at once, what leave
/// there was: the leave that an earlier answer gave does not last out
/// its ten seconds beside it. A show that is not answered at all changes
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_that_gives_no_leave_ends_the_leave_there_was() {
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.connects_to("relay", relay.port, relay.key).await;
    device.passes().await;
    assert_eq!(device.has_leave("relay"), Ok(()));
    let (link, shown) = (device.link("relay"), device.latest());
    let leave = device.engine.leave();

    // Within the ten seconds, the relay answers the next show with one
    // that gives none.
    let whole = Say::Answer(ShowAnswer::Whole);
    relay.says(whole.clone(), whole);
    let answered = leave.show(&link, &shown, false).await.unwrap();
    assert_eq!(answered.answer, ShowAnswer::Whole);
    assert_eq!(device.has_leave("relay"), Err(NoLeave::NotGiven));

    // The control: an answer that gives leave gives it again, and a
    // show that the relay resets, which is no answer, leaves it.
    let held = Say::Answer(ShowAnswer::Held);
    relay.says(held.clone(), held);
    leave.show(&link, &shown, false).await.unwrap();
    assert_eq!(device.has_leave("relay"), Ok(()));
    relay.says(Say::Reset, Say::Reset);
    assert!(leave.show(&link, &shown, false).await.is_err());
    assert_eq!(device.has_leave("relay"), Ok(()));
}

/// A relay that answers the proof of a channel with no does not hold it.
/// Whatever the device kept of having sent the channel there is
/// forgotten, and the relay is sent everything of it again, from the
/// start. A relay that answers yes is sent nothing a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_that_answers_a_proof_with_no_is_sent_the_channel_again() {
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    let notes = device.channel("notes");
    let written = device.writes("notes", "a.md", "what the file holds");
    let pushed_of_notes = |relay: &StandIn| -> Vec<[u8; 32]> {
        relay
            .requests()
            .iter()
            .filter_map(|request| match request {
                WireMessage::EntryPush(push) => Some(push.entries.clone()),
                _ => None,
            })
            .flatten()
            .map(|entry| Entry::from_wire(&entry).unwrap())
            .filter(|entry| entry.channel == notes)
            .map(|entry| entry.id())
            .collect()
    };
    // The relay holds what a proof is of, and is sent the file.
    relay.holds_what_is_proved(true);
    device.connects_to("relay", relay.port, relay.key).await;
    device.passes().await;
    assert_eq!(pushed_of_notes(&relay), [written.id()]);
    // On a new connection the channel is proved again. The relay still
    // holds it: nothing is sent a second time.
    device.connects_to("relay", relay.port, relay.key).await;
    device.passes().await;
    device.sends().await;
    assert!(pushed_of_notes(&relay).is_empty());

    // The relay holds it no more, and says so to the next proof: it is
    // sent the file again.
    relay.holds_what_is_proved(false);
    device.connects_to("relay", relay.port, relay.key).await;
    device.passes().await;
    assert_eq!(pushed_of_notes(&relay), [written.id()]);
}

/// While a device wakes, every relay is shown the change entry, also one
/// whose last show got no leave and is waiting out its wait (decision
/// 2026-10-04 §16). Otherwise that relay would not be heard from, and
/// the device would wait its whole half minute at every wake. It is
/// shown once, is heard, and the device is awake at the other relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_wakes_shows_also_a_relay_whose_show_is_waiting() {
    let (stuck, good) = (StandIn::started().await, StandIn::started().await);
    let slow = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.connects_to("stuck", stuck.port, stuck.key).await;
    device.connects_to("good", good.port, good.key).await;
    device.connects_to("slow", slow.port, slow.key).await;
    device.passes().await;
    let shows = |relay: &StandIn| -> Vec<Seen> {
        let shown = |one: &Seen| matches!(one, Seen::Whole | Seen::Short);
        relay.seen().into_iter().filter(shown).collect()
    };
    let secs = |secs: u64| device.clock.run_ahead(Duration::from_secs(secs));

    // The one relay gives no leave, time after time: its wait grows to
    // minutes.
    let whole = Say::Answer(ShowAnswer::Whole);
    stuck.says(whole.clone(), whole);
    for _ in 0..8 {
        secs(OUTBOX_REFUSED_RETRY_MAX_SECS);
        device.passes().await;
    }
    shows(&stuck);
    device.passes().await;
    assert_eq!(shows(&stuck), [], "its show waits");
    assert_eq!(device.has_leave("good"), Ok(()));

    // The machine sleeps, and wakes: it reaches no relay, and then all
    // three again. The third does not answer yet.
    for name in ["stuck", "good", "slow"] {
        device.disconnects(name);
    }
    device.passes().await;
    slow.says(Say::Reset, Say::Reset);
    device.connects_to("stuck", stuck.port, stuck.key).await;
    device.connects_to("good", good.port, good.key).await;
    device.connects_to("slow", slow.port, slow.key).await;
    assert_eq!(device.has_leave("good"), Err(NoLeave::Waking));
    shows(&stuck);
    device.passes().await;
    // Each was shown, the one whose show was waiting among them, and it
    // was heard. The device still wakes: the third has not answered.
    assert_eq!(shows(&stuck), [Seen::Whole]);
    assert!(device.at("stuck").heard_since_woke);
    assert!(!device.at("slow").heard_since_woke);
    assert_eq!(device.has_leave("good"), Err(NoLeave::Waking));
    // Once heard, it is shown no more while its wait lasts, though the
    // device still wakes.
    device.passes().await;
    assert_eq!(shows(&stuck), []);
    assert_eq!(device.has_leave("good"), Err(NoLeave::Waking));

    // The third answers: every relay has, and the device is awake. The
    // one that gives no leave did not hold it up.
    let held = Say::Answer(ShowAnswer::Held);
    slow.says(held.clone(), held);
    device.passes().await;
    assert_eq!(device.has_leave("good"), Ok(()));
    assert_eq!(device.has_leave("stuck"), Err(NoLeave::NotGiven));
    assert_eq!(shows(&stuck), []);
}

/// A request is written only under the change entry that it was built
/// under (decision 2026-10-04 §16). The one way in asks which entry the
/// device keeps before it opens a stream, and a relay can hold the
/// opening back: here, by having every stream that a connection may have
/// open at once in use. The device applies a change while it waits. Once
/// the stream opens, nothing is written on it: the request was for a
/// channel of the generation that the device has left.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_is_not_written_once_the_entry_it_was_built_under_is_kept_no_more() {
    use cordelia_core::protocol::QUIC_MAX_BIDI_STREAMS;
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.connects_to("relay", relay.port, relay.key).await;
    device.passes().await;
    relay.seen();
    assert_eq!(device.has_leave("relay"), Ok(()));
    let link = device.link("relay");
    let proof = proof_on(&device, "relay", "notes");
    async fn proves(device: &Device, link: &Link, proof: &WireMessage) -> Result<bool, Refused> {
        let read = |answer| matches!(answer, WireMessage::ChannelProved(_));
        device.opens(link, proof, read, |_, proved| proved).await
    }
    // The control: with a stream to be had at once, the proof is asked.
    assert_eq!(proves(&device, &link, &proof).await, Ok(true));
    assert_eq!(relay.seen(), [Seen::Prove]);

    // Every stream that the connection may have open is held by the
    // test: the next is held back until one is let go.
    let conn = device.connection("relay");
    let mut held = Vec::new();
    loop {
        let opened = tokio::time::timeout(Duration::from_millis(300), conn.open_bi()).await;
        match opened {
            Ok(stream) => held.push(stream.expect("a stream is opened")),
            // The relay holds the next one back.
            Err(_) => break,
        }
        assert!(held.len() <= 4 * QUIC_MAX_BIDI_STREAMS as usize);
    }
    assert!(!held.is_empty());
    let asks = proves(&device, &link, &proof);
    let meanwhile = async {
        // The request has leave, and waits for its stream. Nothing has
        // reached the relay.
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(relay.seen().is_empty());
        // The device applies a change: it keeps another entry now.
        device.changes(&phrase(), &[&device], &[]);
        // One stream is let go, and the relay lets another be opened.
        let (mut send, mut recv) = held.pop().unwrap();
        let _ = send.reset(0u32.into());
        let _ = recv.stop(0u32.into());
    };
    let (asked, ()) = tokio::join!(asks, meanwhile);
    assert_eq!(asked, Err(Refused::KeptAnother));
    // The stream was opened, and nothing was written on it: the relay
    // was asked for no proof.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let seen = relay.seen();
    assert!(!seen.contains(&Seen::Prove), "{seen:?}");
    drop(held);
}

/// Only an answer starts the wait that doubles (decision 2026-10-04
/// §16). A whole show whose stream is reset was not answered: that is how
/// a relay says "not now" to an asker that is over its bytes for the
/// minute. It is made again at the next pass, and at the one after. An
/// answer to the whole entry that gives no leave starts the wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_whole_show_that_is_reset_is_made_again_at_the_next_pass() {
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.connects_to("relay", relay.port, relay.key).await;
    device.passes().await;
    relay.seen();
    let shows = |relay: &StandIn| -> Vec<Seen> {
        let shown = |one: &Seen| matches!(one, Seen::Whole | Seen::Short);
        relay.seen().into_iter().filter(shown).collect()
    };
    let secs = |secs: u64| device.clock.run_ahead(Duration::from_secs(secs));

    // The relay asks for the whole entry, and resets the stream that
    // brings it.
    relay.says(Say::Answer(ShowAnswer::Whole), Say::Reset);
    secs(SHOW_LEAVE_SECS);
    for pass in 0..3 {
        device.passes().await;
        assert_eq!(shows(&relay), [Seen::Short, Seen::Whole], "pass {pass}");
        assert_eq!(device.has_leave("relay"), Err(NoLeave::NotGiven));
    }
    // The control: the whole entry is answered, with no leave. The show
    // is made once, and then waits.
    let whole = Say::Answer(ShowAnswer::Whole);
    relay.says(whole.clone(), whole);
    device.passes().await;
    assert_eq!(shows(&relay), [Seen::Short, Seen::Whole]);
    device.passes().await;
    assert_eq!(shows(&relay), []);
    secs(4);
    device.passes().await;
    assert_eq!(shows(&relay), [Seen::Short, Seen::Whole]);
}

/// A relay that holds, in the place of the device's change entry, one
/// that the phrase signed and that the device does not take: here, a
/// statement that undoes a removal. The device is answered with it,
/// refuses it, and has no leave at that relay for as long as the relay
/// holds it. What a status reads says so, for that relay, and no more
/// once the relay gives leave.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_that_holds_a_change_the_device_refuses_is_said_to() {
    use cordelia_crypto::change_entry::{self, ForPhrase};
    use cordelia_crypto::statement::{self, Statement};
    let relay = StandIn::started().await;
    let (mut device, gone) = (Device::new("laptop"), Device::new("tablet"));
    device.makes_the_phrase(&phrase());
    device.adds(&gone);
    // The device removes the other: the statement it has applied lists
    // that key as removed.
    device.changes(&phrase(), &[&device], &[&gone]);
    let applied = held(&device.db()).unwrap().unwrap().statement.statement;
    assert_eq!(applied.removed, [gone.key()]);
    // A statement that the phrase signed, made after that one, which
    // lists nobody as removed.
    let secret = statement::new_secret().unwrap();
    let mut chain = applied.chain.clone();
    chain.push(applied.link().unwrap());
    let undoes = Statement {
        number: applied.number + 1,
        maker: device.key(),
        chain,
        commitment: statement::commitment(&secret),
        devices: applied.devices.clone(),
        removed: Vec::new(),
        phrase_key: applied.phrase_key,
    };
    let signed = undoes.sign(&phrase().signing_key().unwrap()).unwrap();
    let entry = change_entry::entry_of(&phrase(), &signed, &ForPhrase::first(secret)).unwrap();

    device.connects_to("relay", relay.port, relay.key).await;
    let other = Say::Answer(ShowAnswer::Other {
        rev: entry.rev,
        id: entry.id(),
    });
    relay.says(other, Say::Answer(ShowAnswer::Another(entry.to_wire())));
    let kept = device.latest().id();
    device.passes().await;
    assert_eq!(device.latest().id(), kept);
    assert_eq!(device.stands(), Stands::Applied);
    assert_eq!(device.has_leave("relay"), Err(NoLeave::NotGiven));
    let said = device.at("relay").refuses.expect("the status says so");
    assert!(
        said.contains("lacks a key that the applied one removed"),
        "{said}"
    );
    assert_eq!(device.status().cannot_go_on, None);

    // The relay holds the device's own entry again: leave, and nothing
    // more is said of it.
    let held_it = Say::Answer(ShowAnswer::Held);
    relay.says(held_it.clone(), held_it);
    device
        .clock
        .run_ahead(Duration::from_secs(OUTBOX_REFUSED_RETRY_MAX_SECS));
    device.passes().await;
    assert_eq!(device.has_leave("relay"), Ok(()));
    assert_eq!(device.at("relay").refuses, None);
}

/// With leave, a device still asks only so much of a relay in a minute on
/// the streams of a channel. At that it opens no more, and its passes
/// stop there: what they did not ask, they ask later. Its shows go on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_asks_only_so_much_of_a_relay_in_a_minute() {
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.connects_to("relay", relay.port, relay.key).await;
    let of_a_channel = |seen: &[Seen]| {
        let asked = |one: &&Seen| matches!(one, Seen::Prove | Seen::Pull | Seen::Push);
        seen.iter().filter(asked).count()
    };
    device.passes().await;
    let mut seen_there = of_a_channel(&relay.seen());
    assert!(seen_there > 0);

    // It asks, and asks, with a fresh show now and then: the leave lasts
    // ten seconds. The relay answers every one.
    let most = OWN_ENTRY_REQUESTS_PER_MINUTE as usize;
    let link = device.link("relay");
    let proof = proof_on(&device, "relay", "notes");
    let entry = device.latest();
    let under = entry.id();
    let mut refused = None;
    for n in 0..most {
        if n % 200 == 0 {
            let shown = device.engine.leave().show(&link, &entry, true).await;
            shown.unwrap();
        }
        let asked = Asked {
            under: &under,
            request: &proof,
        };
        let asked = device
            .engine
            .leave()
            .open(&device.state.db, &link, asked, |_| (), |_| (), |_, _| ())
            .await;
        if let Err(why) = asked {
            refused = Some(why);
            break;
        }
    }
    // It stopped itself, at what a device asks of a relay in a minute:
    // the relay saw that many requests, and no more. That is fewer than
    // a relay lets a connection make, so the device is never the one
    // that is refused for going over.
    assert_eq!(refused, Some(Refused::AskedEnough));
    seen_there += of_a_channel(&relay.seen());
    assert_eq!(seen_there, most);
    assert!(most < cordelia_core::protocol::ENTRY_REQUESTS_PER_PEER_PER_MINUTE as usize);

    // Its passes open no stream of a channel now. They still show.
    device.writes("notes", "a.md", "waiting to be sent");
    let before = device.counts("relay");
    device.passes().await;
    device.sends().await;
    let seen = relay.seen();
    assert_eq!(of_a_channel(&seen), 0, "{seen:?}");
    assert!(seen.contains(&Seen::Short));
    let after = device.counts("relay");
    assert_eq!(after.short_shows, before.short_shows + 1);
    assert_eq!(after.pushes, before.pushes);
    assert_eq!(device.has_leave("relay"), Ok(()));

    // The count is the relay's, and not the connection's: on a new
    // connection to it, within the minute, the device still asks nothing
    // on a stream of a channel. (A relay counts by the device's key.)
    device.connects_to("relay", relay.port, relay.key).await;
    device.passes().await;
    device.sends().await;
    let seen = relay.seen();
    assert_eq!(of_a_channel(&seen), 0, "{seen:?}");
    assert!(seen.contains(&Seen::Whole));
    assert_eq!(device.has_leave("relay"), Ok(()));
}

/// A show that is not answered in time gives no leave, and the device
/// opens no stream for a channel of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_show_that_times_out_gives_no_leave() {
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.writes("notes", "a.md", "waiting to be sent");
    device.connects_to("relay", relay.port, relay.key).await;
    relay.says(Say::Nothing, Say::Nothing);
    let began = std::time::Instant::now();
    device.passes().await;
    // It waited the one timeout that a stream has.
    assert!(
        began.elapsed() >= Duration::from_secs(9),
        "{:?}",
        began.elapsed()
    );
    assert_eq!(device.has_leave("relay"), Err(NoLeave::Waking));
    assert_eq!(relay.seen(), [Seen::Whole]);
    assert_eq!(device.counts("relay"), Counts::default());
    assert!(!device.at("relay").heard_since_woke);
    assert_eq!(device.at("relay").holds_latest, None);
}

// ── The show comes first ─────────────────────────────────────────────

/// Three devices of one person, each holding the name `notes`, connected
/// to `relay` and in step: the first made the phrase and added the other
/// two.
async fn three_in_step(relay: &Node) -> [Device; 3] {
    let mut devices = [
        Device::new("desktop"),
        Device::new("laptop"),
        Device::new("tablet"),
    ];
    devices[0].makes_the_phrase(&phrase());
    devices[0].adds(&devices[1]);
    devices[0].adds(&devices[2]);
    for device in &mut devices {
        device.holds("notes");
        device.connects("relay", relay).await;
    }
    let [a, b, c] = &devices;
    all_pass(&[a, b, c], 3).await;
    devices
}

/// The show comes before everything. A device with an entry waiting,
/// whose relay holds a later change that lists it, applies the change
/// before anything is sent: what was waiting for the old channel is not
/// sent there, and goes into the new one. A device that the later change
/// removed sends nothing and takes nothing, and says why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_applies_the_change_that_its_relay_holds_before_it_sends_anything() {
    let relay = relay_started("relay", None);
    let [maker, mut stays, mut removed] = three_in_step(&relay).await;
    let old_notes = maker.channel("notes");
    // They are in step: what one writes, the others read.
    let shared = maker.writes("notes", "shared.md", "read by all three");
    all_pass(&[&maker, &stays, &removed], 2).await;
    for device in [&stays, &removed] {
        assert_eq!(
            device.text("notes", "shared.md").as_deref(),
            Some("read by all three")
        );
    }
    assert!(holds_at(&relay, &old_notes, &shared.id()));

    // Two of them are closed, each with an edit that it has not sent.
    stays.disconnects("relay");
    removed.disconnects("relay");
    let waiting = stays.writes("notes", "mine.md", "written while it was closed");
    let never_sent = removed.writes("notes", "late.md", "written by a device that is removed");
    // A change is made meanwhile: one of the two stays, and the other is
    // removed. The relay holds it.
    let change = maker.changes(&phrase(), &[&maker, &stays], &[&removed]);
    maker.passes().await;
    assert!(holds_at(&relay, &change.channel, &change.id()));
    let new_notes = maker.channel("notes");
    assert_ne!(new_notes, old_notes);

    // The one that stays is opened. It shows its entry, is answered with
    // the change, and applies it before anything else.
    stays.connects("relay", &relay).await;
    stays.passes().await;
    assert_eq!(stays.latest().id(), change.id());
    assert_eq!(stays.stands(), Stands::Applied);
    assert_eq!(stays.status().cannot_go_on, None);
    // What was waiting was not sent to the old channel.
    assert!(!holds_at(&relay, &old_notes, &waiting.id()));
    assert_eq!(held_at(&relay, &old_notes).len(), 1);
    // It was carried, and is in the new channel as that device's own.
    assert_eq!(stays.channel("notes"), new_notes);
    assert_eq!(
        stays.text("notes", "mine.md").as_deref(),
        Some("written while it was closed")
    );
    let by_it = |entry: &Entry| entry.author == stays.key();
    assert_eq!(
        held_at(&relay, &new_notes)
            .iter()
            .filter(|e| by_it(e))
            .count(),
        1
    );
    // The maker reads it there.
    maker.passes().await;
    assert_eq!(
        maker.text("notes", "mine.md").as_deref(),
        Some("written while it was closed")
    );

    // The one that was removed is opened. It shows its entry, is answered
    // with the change, and stops: it sends nothing and takes nothing.
    removed.connects("relay", &relay).await;
    let before = removed.counts("relay");
    let held_before = removed.holds_of(&old_notes);
    removed.passes().await;
    removed.passes().await;
    removed.sends().await;
    assert_eq!(removed.stands(), Stands::Stopped(State::Removed));
    assert_eq!(removed.status().cannot_go_on, Some(CannotGoOn::Removed));
    assert_eq!(
        removed.has_leave("relay"),
        Err(NoLeave::Stopped(State::Removed))
    );
    let after = removed.counts("relay");
    assert_eq!(
        (after.proofs, after.pages, after.pushes),
        (before.proofs, before.pages, before.pushes)
    );
    // It showed once, whole on its new connection, and shows no more.
    assert_eq!(after.whole_shows, before.whole_shows + 1);
    assert_eq!(after.short_shows, before.short_shows);
    assert!(!holds_at(&relay, &old_notes, &never_sent.id()));
    assert!(!holds_at(&relay, &new_notes, &never_sent.id()));
    assert_eq!(removed.holds_of(&old_notes), held_before);
    assert!(removed.holds_of(&new_notes).is_empty());
}

/// A device that shows its entry in short, on a connection where it has
/// shown it whole, and is told of another that it does not keep: it
/// shows its own whole, is answered with the entry, applies the change,
/// and shows what it keeps then.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_told_of_a_later_change_shows_its_own_whole_and_is_answered_with_it() {
    let relay = relay_started("relay", None);
    let (mut maker, mut other) = (Device::new("desktop"), Device::new("laptop"));
    maker.makes_the_phrase(&phrase());
    maker.adds(&other);
    for device in [&mut maker, &mut other] {
        device.holds("notes");
        device.connects("relay", &relay).await;
    }
    all_pass(&[&maker, &other], 2).await;
    let before = other.counts("relay");
    assert_eq!(before.whole_shows, 1);

    let change = maker.changes(&phrase(), &[&maker, &other], &[]);
    maker.passes().await;
    other.passes().await;
    assert_eq!(other.latest().id(), change.id());
    let after = other.counts("relay");
    // One show in short, which was told of another. Then its own entry
    // whole, which was answered with the change. Then the change, whole,
    // since it had not shown that one on this connection.
    assert_eq!(after.short_shows, before.short_shows + 1);
    assert_eq!(after.whole_shows, before.whole_shows + 2);
    assert_eq!(other.has_leave("relay"), Ok(()));
    assert_eq!(other.at("relay").holds_latest, Some(true));
    // From then on, in short again.
    other.passes().await;
    let later = other.counts("relay");
    assert_eq!(
        (later.whole_shows, later.short_shows),
        (after.whole_shows, after.short_shows + 1)
    );
}

/// A device that was answered with a change and could not apply it has no
/// leave anywhere until it has: it sends nothing to the relay that lacks
/// the change either, and says why it cannot go on. Once it has applied
/// what it was answered with, it goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_could_not_apply_a_change_has_no_leave_anywhere_until_it_has() {
    let (lacks, has) = (relay_started("lacks", None), relay_started("has", None));
    let (mut maker, mut behind) = (Device::new("desktop"), Device::new("laptop"));
    maker.makes_the_phrase(&phrase());
    maker.adds(&behind);
    for device in [&mut maker, &mut behind] {
        device.holds("notes");
        device.connects("lacks", &lacks).await;
        device.connects("has", &has).await;
    }
    all_pass(&[&maker, &behind], 3).await;
    let old_notes = maker.channel("notes");
    // A change reaches one relay, and not the other.
    maker.disconnects("lacks");
    let change = maker.changes(&phrase(), &[&maker, &behind], &[]);
    maker.passes().await;
    let waiting = behind.writes("notes", "a.md", "written before it heard of the change");

    // The device cannot write what applying the change writes: its store
    // fails where it applies.
    behind
        .db()
        .execute_batch("ALTER TABLE person_carried RENAME TO elsewhere")
        .unwrap();
    let before = (behind.counts("lacks"), behind.counts("has"));
    let counted = behind.state.sync_control.generation();
    behind.passes().await;
    behind.sends().await;
    // It applied nothing, and has no leave: not at the relay that
    // answered with the change, and not at the one that answered "held".
    assert_ne!(behind.latest().id(), change.id());
    // Nor was anything counted as a change of settings: not the answer,
    // and not the pass that tried the change again.
    behind.passes().await;
    assert_eq!(behind.state.sync_control.generation(), counted);
    assert_eq!(behind.has_leave("has"), Err(NoLeave::NotApplied));
    assert_eq!(behind.has_leave("lacks"), Err(NoLeave::NotApplied));
    for (relay, before) in [("lacks", before.0), ("has", before.1)] {
        let after = behind.counts(relay);
        assert_eq!(
            (after.proofs, after.pages, after.pushes),
            (before.proofs, before.pages, before.pushes),
            "{relay}"
        );
    }
    assert!(!holds_at(&lacks, &old_notes, &waiting.id()));
    assert!(!holds_at(&has, &old_notes, &waiting.id()));
    assert!(matches!(
        behind.status().cannot_go_on,
        Some(CannotGoOn::NotApplied { relay, .. }) if relay == "has"
    ));

    // Its store is whole again: it is answered with the change again,
    // applies it, and goes on.
    behind
        .db()
        .execute_batch("ALTER TABLE elsewhere RENAME TO person_carried")
        .unwrap();
    behind.passes().await;
    assert_eq!(behind.latest().id(), change.id());
    assert_eq!(behind.status().cannot_go_on, None);
    // The statement was applied: that is a change of settings, counted
    // before the work and again once it is done.
    assert_eq!(behind.state.sync_control.generation(), counted + 2);
    behind.passes().await;
    for relay in ["lacks", "has"] {
        assert_eq!(behind.has_leave(relay), Ok(()), "{relay}");
    }
    assert!(!holds_at(&lacks, &old_notes, &waiting.id()));
    assert!(holds_at(&lacks, &change.channel, &change.id()));
}

/// A change that could not be applied is kept, whatever becomes of the
/// connection it came on. With that connection closed, the device still
/// sends nothing and takes nothing at its other relay, which lacks the
/// change, and still says why. At each pass it tries the change again:
/// once its store is whole it applies it, with no relay to answer it
/// again, and shows it to the relay that lacked it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_that_could_not_be_applied_is_kept_when_its_connection_closes() {
    let (lacks, has) = (relay_started("lacks", None), relay_started("has", None));
    let (mut maker, mut behind) = (Device::new("desktop"), Device::new("laptop"));
    maker.makes_the_phrase(&phrase());
    maker.adds(&behind);
    for device in [&mut maker, &mut behind] {
        device.holds("notes");
        device.connects("lacks", &lacks).await;
        device.connects("has", &has).await;
    }
    all_pass(&[&maker, &behind], 3).await;
    let old_notes = maker.channel("notes");
    maker.disconnects("lacks");
    let change = maker.changes(&phrase(), &[&maker, &behind], &[]);
    maker.passes().await;
    let waiting = behind.writes("notes", "a.md", "written before it heard of the change");

    // Its store fails where it applies: it is answered with the change,
    // by the relay that has it, and cannot apply it.
    behind
        .db()
        .execute_batch("ALTER TABLE person_carried RENAME TO elsewhere")
        .unwrap();
    behind.passes().await;
    assert_ne!(behind.latest().id(), change.id());
    assert_eq!(behind.has_leave("lacks"), Err(NoLeave::NotApplied));

    // The connection that the change came on closes. Nothing is taken
    // back by that: there is still no leave at the relay that lacks the
    // change, pass after pass, and nothing goes to it.
    behind.disconnects("has");
    let before = behind.counts("lacks");
    for _ in 0..2 {
        behind.passes().await;
        behind.sends().await;
    }
    assert_eq!(behind.has_leave("lacks"), Err(NoLeave::NotApplied));
    let after = behind.counts("lacks");
    assert_eq!(
        (after.proofs, after.pages, after.pushes),
        (before.proofs, before.pages, before.pushes)
    );
    assert!(!holds_at(&lacks, &old_notes, &waiting.id()));
    assert!(matches!(
        behind.status().cannot_go_on,
        Some(CannotGoOn::NotApplied { relay, .. }) if relay == "has"
    ));

    // Its store is whole again. The next pass tries the change that it
    // kept, and applies it: no relay it reaches holds that change. Then
    // it shows it to the relay that lacked it, and goes on.
    behind
        .db()
        .execute_batch("ALTER TABLE elsewhere RENAME TO person_carried")
        .unwrap();
    behind.passes().await;
    assert_eq!(behind.latest().id(), change.id());
    assert_eq!(behind.status().cannot_go_on, None);
    assert!(holds_at(&lacks, &change.channel, &change.id()));
    behind.passes().await;
    assert_eq!(behind.has_leave("lacks"), Ok(()));
    assert!(!holds_at(&lacks, &old_notes, &waiting.id()));
}

/// A device that follows no phrase opens no stream, and says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_follows_no_phrase_opens_no_stream() {
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.connects_to("relay", relay.port, relay.key).await;
    device.passes().await;
    device.sends().await;
    device.clock.run_ahead(Duration::from_secs(WAKE_WAIT_SECS));
    device.passes().await;
    assert_eq!(relay.seen(), []);
    assert_eq!(device.counts("relay"), Counts::default());
    let status = device.status();
    assert_eq!(status.cannot_go_on, Some(CannotGoOn::NoPhrase));
    assert_eq!(device.has_leave("relay"), Err(NoLeave::Waking));
    assert!(!status.relays[0].heard_since_woke);
}

/// A relay that answers a show with an entry that does not check, with
/// one that is behind the one shown, or with one of another phrase:
/// nothing is applied, and no leave is given. **Nor is any of them a
/// change of settings** (decision 2026-10-04 §4.2): a relay answers so as
/// often as it is shown an entry, and no sync cycle is stopped for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_that_does_not_check_is_behind_or_is_anothers_changes_nothing() {
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    let first = device.latest();
    let second = device.changes(&phrase(), &[&device], &[]);
    device.writes("notes", "a.md", "waiting to be sent");
    // The entry of another person's phrase.
    let stranger = Device::new("stranger");
    stranger.makes_the_phrase(&Phrase::parse(OTHER_WORDS).unwrap());
    let anothers = stranger.latest();
    // The device's own entry, changed after it was signed.
    let mut changed = second.clone().into_entry();
    changed.rev += 1;
    assert!(changed.clone().check().is_err());
    // And a later change, whole but for one byte of a signature.
    let mut forged = second.clone().into_entry();
    forged.channel_signature[0] ^= 1;

    device.connects_to("relay", relay.port, relay.key).await;
    let other = Say::Answer(ShowAnswer::Other {
        rev: 9,
        id: [7; 32],
    });
    let answers = [
        first.to_wire(),
        anothers.to_wire(),
        changed.to_wire(),
        forged.to_wire(),
        Vec::new(),
    ];
    let counted = device.state.sync_control.generation();
    for (n, answer) in answers.into_iter().enumerate() {
        // A show in short is told of another, and the whole entry is
        // answered with this one. (The wait after a show that got no
        // leave has gone by.)
        device
            .clock
            .run_ahead(Duration::from_secs(OUTBOX_REFUSED_RETRY_MAX_SECS));
        relay.says(other.clone(), Say::Answer(ShowAnswer::Another(answer)));
        device.passes().await;
        let seen = relay.seen();
        assert!(!any_of_a_channel(&seen), "{n}: {seen:?}");
        assert_eq!(seen.last(), Some(&Seen::Whole), "{n}");
        // The pass that sends has something to send, and finds no leave.
        // The show that would give it was made a moment ago, and got
        // none: it is not made again yet, and nothing is sent.
        device.sends().await;
        assert_eq!(relay.seen(), [], "{n}");
        assert_eq!(device.has_leave("relay"), Err(NoLeave::NotGiven), "{n}");
        assert_eq!(device.latest().id(), second.id(), "{n}");
        assert_eq!(device.stands(), Stands::Applied, "{n}");
        assert_eq!(device.status().cannot_go_on, None, "{n}");
        assert_eq!(device.at("relay").holds_latest, Some(false), "{n}");
        assert_eq!(
            device.state.sync_control.generation(),
            counted,
            "{n}: counted as a change of settings"
        );
    }
    // The control: a relay that holds the entry is shown it, once the
    // wait has gone by, and the device goes on.
    let held = Say::Answer(ShowAnswer::Held);
    relay.says(held.clone(), held);
    device
        .clock
        .run_ahead(Duration::from_secs(OUTBOX_REFUSED_RETRY_MAX_SECS));
    device.passes().await;
    assert_eq!(device.has_leave("relay"), Ok(()));
    assert!(any_of_a_channel(&relay.seen()));
}

/// Two changes made apart. The device that is answered with the other
/// keeps both, stops, and has no leave. From then on it shows the one it
/// had applied in short, is told of the other, which it keeps, and asks
/// no more: it does not show whole again, and the entry is not handed to
/// it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_in_a_fork_keeps_both_entries_and_asks_the_relay_no_more() {
    let relay = relay_started("relay", None);
    let (mut one, mut other) = (Device::new("desktop"), Device::new("laptop"));
    one.makes_the_phrase(&phrase());
    one.adds(&other);
    for device in [&mut one, &mut other] {
        device.holds("notes");
        device.connects("relay", &relay).await;
    }
    all_pass(&[&one, &other], 2).await;

    // Each makes a change, apart from the other's. The relay holds the
    // first that it is shown.
    let by_one = one.changes(&phrase(), &[&one, &other], &[]);
    let by_other = other.changes(&phrase(), &[&one, &other], &[]);
    assert_eq!(by_one.rev, by_other.rev);
    let waiting = other.writes("notes", "a.md", "written under its own change");
    one.passes().await;
    assert!(holds_at(&relay, &by_one.channel, &by_one.id()));

    // The other shows its own, whole, and is answered with that one.
    let before = other.counts("relay");
    other.passes().await;
    assert_eq!(other.stands(), Stands::Stopped(State::Fork));
    let shows = at_relays::to_show(&other.db()).unwrap().unwrap();
    assert_eq!(
        (shows.entry.id(), shows.apart),
        (by_other.id(), Some(by_one.id()))
    );
    assert_eq!(other.status().cannot_go_on, Some(CannotGoOn::Fork));
    assert_eq!(other.has_leave("relay"), Err(NoLeave::Stopped(State::Fork)));
    let forked = other.counts("relay");
    assert_eq!(forked.whole_shows, before.whole_shows + 1);

    // Its whole show got no leave: the next is made after a wait, and
    // nothing is shown while it lasts.
    other.passes().await;
    assert_eq!(other.counts("relay"), forked);
    other.clock.run_ahead(Duration::from_secs(4));
    // From then on, pass after pass: one short show each, answered with
    // word of the entry that it keeps. Nothing whole, and no stream of a
    // channel. (A show in short that gets no leave costs little, and
    // starts no wait.)
    for _ in 0..4 {
        other.passes().await;
        other.sends().await;
    }
    let after = other.counts("relay");
    assert_eq!(after.whole_shows, forked.whole_shows);
    assert_eq!(after.short_shows, forked.short_shows + 4);
    assert_eq!(
        (after.proofs, after.pages, after.pushes),
        (forked.proofs, forked.pages, forked.pushes)
    );
    assert!(after.shown_bytes - forked.shown_bytes < 4 * 256);
    assert_eq!(other.at("relay").holds_latest, Some(false));
    // The relay holds the one it was shown first, and nothing that the
    // other wrote under its own.
    let held = held_at(&relay, &by_one.channel);
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].id(), by_one.id());
    assert!(!holds_at(&relay, &other.channel("notes"), &waiting.id()));
    assert_eq!(other.stands(), Stands::Stopped(State::Fork));
}

/// **A statement that no relay held, shown later** (decision 2026-10-04
/// §7.6). The desktop makes a change with no relay in reach, and is
/// lost. The laptop, which has seen no statement, makes the change
/// again: it has the number that the lost one had, and its relay holds
/// it. The other relay holds the entry from before.
///
/// The lost device comes to light at that other relay: **the relay,
/// which holds an earlier change entry, takes the one it is shown.** The
/// tablet, **which is behind, is answered with it there and applies
/// it:** it is with the lost device. The laptop, **which has applied the
/// other statement at that number, is shown it there and is in a
/// fork;** and so is the tablet, once it is shown the laptop's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_statement_that_no_relay_held_comes_to_light_at_a_relay_that_holds_an_earlier_one() {
    let (near, far) = (relay_started("near", None), relay_started("far", None));
    let (mut lost, mut remains, mut behind) = (
        Device::new("desktop"),
        Device::new("laptop"),
        Device::new("tablet"),
    );
    lost.makes_the_phrase(&phrase());
    lost.adds(&remains);
    lost.adds(&behind);
    // The laptop is at one relay and the tablet at the other. The
    // desktop is at both: each relay holds the first change entry.
    lost.connects("near", &near).await;
    lost.connects("far", &far).await;
    remains.connects("near", &near).await;
    behind.connects("far", &far).await;
    all_pass(&[&lost, &remains, &behind], 3).await;
    let first = lost.latest();
    for relay in [&near, &far] {
        assert!(holds_at(relay, &first.channel, &first.id()));
    }

    // The desktop makes a change with no relay in reach, and is lost:
    // no relay held it. The tablet is off.
    lost.disconnects("near");
    lost.disconnects("far");
    behind.disconnects("far");
    let unheard = lost.changes(&phrase(), &[&lost, &remains, &behind], &[]);
    // The laptop has seen no statement. The change that it makes, which
    // removes the desktop, has the number that the lost one had. Its
    // relay holds it, and the other holds the entry from before.
    let again = remains.changes(&phrase(), &[&remains, &behind], &[&lost]);
    assert_eq!(again.rev, unheard.rev);
    assert_ne!(again.id(), unheard.id());
    remains.passes().await;
    assert!(holds_at(&near, &again.channel, &again.id()));
    assert!(holds_at(&far, &first.channel, &first.id()));

    // The lost device comes to light at the relay that holds the
    // earlier entry: the relay takes the one it is shown.
    lost.connects("far", &far).await;
    lost.passes().await;
    let at_far = held_at(&far, &unheard.channel);
    assert_eq!(at_far.len(), 1);
    assert_eq!(at_far[0].id(), unheard.id());

    // The tablet, which is behind, is answered with it there, and
    // applies it: it is with the lost device.
    assert_eq!(behind.latest().id(), first.id());
    behind.connects("far", &far).await;
    behind.passes().await;
    assert_eq!(behind.latest().id(), unheard.id());
    assert_eq!(behind.stands(), Stands::Applied);

    // The laptop has applied the other statement at that number. Shown
    // the lost one's at that relay, it is in a fork, and keeps both.
    remains.connects("far", &far).await;
    remains.passes().await;
    assert_eq!(remains.stands(), Stands::Stopped(State::Fork));
    let shows = at_relays::to_show(&remains.db()).unwrap().unwrap();
    assert_eq!(
        (shows.entry.id(), shows.apart),
        (again.id(), Some(unheard.id()))
    );
    // And the tablet, which applied the lost one's, is in a fork once it
    // is shown the laptop's, at the relay that holds that one.
    behind.connects("near", &near).await;
    behind.passes().await;
    assert_eq!(behind.stands(), Stands::Stopped(State::Fork));
    let shows = at_relays::to_show(&behind.db()).unwrap().unwrap();
    assert_eq!(
        (shows.entry.id(), shows.apart),
        (unheard.id(), Some(again.id()))
    );
}

/// The channels that `request` names: the one that is proved or pulled,
/// and the channel of each entry that is pushed. None for a show.
fn channels_named(request: &WireMessage) -> Vec<[u8; 32]> {
    match request {
        WireMessage::ChannelProve(prove) => vec![prove.channel],
        WireMessage::EntryPull(pull) => vec![pull.channel],
        WireMessage::EntryPush(push) => push
            .entries
            .iter()
            .map(|entry| Entry::from_wire(entry).unwrap().channel)
            .collect(),
        _ => Vec::new(),
    }
}

/// A request that was built before a show applied a change is not sent
/// after it. A pass has a push in hand when its leave runs out: it shows
/// again, is answered with a later change, applies it, and has leave
/// again under the entry it then keeps. The push in hand is of a channel
/// that the device has left: it is not sent again, the pass ends there,
/// and the next reads the device's channels afresh. Nothing that names a
/// channel of the generation left is sent after the apply, on that
/// connection or on any other, and nothing is kept of one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_applied_at_a_show_inside_a_pass_ends_the_pass_and_nothing_goes_to_a_channel_left()
{
    let (relay, other) = (StandIn::started().await, StandIn::started().await);
    let (maker, mut device) = (Device::new("desktop"), Device::new("laptop"));
    maker.makes_the_phrase(&phrase());
    maker.adds(&device);
    device.holds("notes");
    device.writes("notes", "a.md", "written before the change");
    let first = device.latest();
    let old = [device.personal(), device.channel("notes")];
    // A change that the device has not heard of.
    let change = maker.changes(&phrase(), &[&maker, &device], &[]);
    device.connects_to("relay", relay.port, relay.key).await;
    device.connects_to("other", other.port, other.key).await;

    // The relay answers as one that holds nothing later, until the first
    // push arrives. As that push is in hand, ten seconds go by: the
    // device's leave runs out. From then on the relay holds the change:
    // shown the first entry in short it tells of the change, shown it
    // whole it answers with the change, and shown the change it holds
    // it.
    let clock = device.clock.clone();
    let (first_id, change_id, change_rev) = (first.id(), change.id(), change.rev);
    let change_wire = change.to_wire();
    let mut pushed = false;
    relay.hook(move |request| match request {
        WireMessage::EntryPush(_) if !pushed => {
            pushed = true;
            clock.run_ahead(Duration::from_secs(SHOW_LEAVE_SECS));
            None
        }
        WireMessage::EntryShowShort(show) if pushed && show.id == first_id => {
            Some(Say::Answer(ShowAnswer::Other {
                rev: change_rev,
                id: change_id,
            }))
        }
        WireMessage::EntryShow(show) if pushed => {
            let shown = Entry::from_wire(&show.entry).unwrap();
            Some(Say::Answer(match shown.id() == first_id {
                true => ShowAnswer::Another(change_wire.clone()),
                false => ShowAnswer::Held,
            }))
        }
        _ => None,
    });

    device.passes().await;
    // It applied the change, at the show inside the pass.
    assert_eq!(device.latest().id(), change.id());
    assert_eq!(device.has_leave("relay"), Ok(()));
    let seen = relay.requests();
    let applied_at = seen
        .iter()
        .position(|request| {
            matches!(request, WireMessage::EntryShow(show)
                if Entry::from_wire(&show.entry).unwrap().id() == first_id)
                && seen
                    .iter()
                    .any(|one| matches!(one, WireMessage::EntryPush(_)))
        })
        .and_then(|_| {
            seen.iter().rposition(|request| {
                matches!(request, WireMessage::EntryShow(show)
                    if Entry::from_wire(&show.entry).unwrap().id() == first_id)
            })
        })
        .expect("the first entry was shown whole again, inside the pass");
    // The push that was in hand went out once, before the change was
    // applied: it named a channel that the device was in then.
    let before: Vec<&WireMessage> = seen[..applied_at]
        .iter()
        .filter(|request| matches!(request, WireMessage::EntryPush(_)))
        .collect();
    assert_eq!(before.len(), 1, "{seen:?}");
    // After it, nothing names a channel of the generation left: the push
    // is not sent again, and the pass does not walk on.
    let after = &seen[applied_at + 1..];
    for request in after {
        for channel in channels_named(request) {
            assert!(!old.contains(&channel), "sent in a channel that was left");
        }
    }
    assert!(
        after
            .iter()
            .all(|request| channels_named(request).is_empty()),
        "the pass went on after the change: {after:?}"
    );
    // And nothing is kept of a channel that was left, at any relay.
    let kept: i64 = device
        .db()
        .query_row(
            "SELECT COUNT(*) FROM at_relays WHERE channel IN (?1, ?2)",
            rusqlite::params![old[0].as_slice(), old[1].as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(kept, 0);

    // On the other connection: a request that was built under the entry
    // before is refused, though there is leave there for the entry that
    // the device keeps now. The relay sees nothing of it.
    let link = device.link("other");
    device
        .engine
        .leave()
        .show(&link, &device.latest(), false)
        .await
        .unwrap();
    assert_eq!(device.has_leave("other"), Ok(()));
    other.requests();
    let stale = WireMessage::EntryPull(EntryPull {
        channel: old[0],
        mark: [0; 8],
        after: 0,
        limit: ENTRY_PAGE_MAX_ENTRIES,
    });
    let marked = AtomicBool::new(false);
    let refused = device
        .engine
        .leave()
        .open(
            &device.state.db,
            &link,
            Asked {
                under: &first_id,
                request: &stale,
            },
            |_| marked.store(true, Ordering::SeqCst),
            |_| (),
            |_, _| (),
        )
        .await;
    assert_eq!(refused, Err(Refused::KeptAnother));
    assert!(!marked.load(Ordering::SeqCst));
    assert_eq!(other.requests().len(), 0);
    // Built under the entry it keeps, the same stream is opened.
    assert_eq!(device.opens(&link, &stale, |_| (), |_, _| ()).await, Ok(()));

    // The next pass reads the device's channels afresh: what it sends
    // names the channels of the generation it has come to, and no other.
    relay.requests();
    device.passes().await;
    let fresh = [device.personal(), device.channel("notes")];
    let named: Vec<[u8; 32]> = relay.requests().iter().flat_map(channels_named).collect();
    assert!(!named.is_empty());
    for channel in named {
        assert!(fresh.contains(&channel), "another channel than its own now");
    }
}

/// A relay that was never sent a hand-over is never sent the delete over
/// it. A push that finds no leave is not sent, and nothing is kept of it:
/// so when the hand-over goes from the store, two hours on, there is no
/// relay to write over it at, and the pair channel reaches no relay as a
/// channel of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_that_was_never_sent_a_hand_over_is_not_sent_a_delete_over_it() {
    let relay = StandIn::started().await;
    let (mut adder, new) = (Device::new("desktop"), Device::new("laptop"));
    adder.makes_the_phrase(&phrase());
    adder.connects_to("relay", relay.port, relay.key).await;
    // The relay gives no leave: it asks for the whole entry, each time.
    let whole = Say::Answer(ShowAnswer::Whole);
    relay.says(whole.clone(), whole);
    let now = adder.now();
    let added = add_device(
        &adder.db(),
        &adder.state.identity,
        &new.key(),
        "laptop",
        now,
    );
    let pair = added.unwrap().hand_over.channel;
    adder.passes().await;
    adder.sends().await;
    // The hand-over waits, and nothing was sent: nothing is kept of the
    // push that found no leave.
    assert!(
        relay
            .requests()
            .iter()
            .all(|one| channels_named(one).is_empty())
    );
    let sent_anywhere = |device: &Device| {
        cordelia_storage::at_relays::keeps_any_anywhere(&device.db(), &pair).unwrap()
    };
    assert!(!sent_anywhere(&adder));

    // Two hours on, the hand-over goes from the store, and the relay
    // gives leave. No delete is written over what no relay was sent, and
    // nothing of the pair channel goes to the relay.
    adder
        .clock
        .run_ahead(Duration::from_secs(HAND_OVER_KEPT_SECS as u64));
    let held = Say::Answer(ShowAnswer::Held);
    relay.says(held.clone(), held);
    adder.passes().await;
    adder.passes().await;
    adder.sends().await;
    let named: Vec<[u8; 32]> = relay.requests().iter().flat_map(channels_named).collect();
    assert!(
        named.contains(&adder.personal()),
        "it went on in its own channels"
    );
    assert!(!named.contains(&pair));
    assert!(adder.holds_of(&pair).is_empty());
    assert!(!sent_anywhere(&adder));
}

/// A hand-over that was sent to a relay whose answer was lost is still
/// written over there (decision 2026-10-04 §6): that a relay is sent
/// something of a pair channel is kept from before it is sent, whatever
/// comes back. Here the relay takes each push of the pair channel and
/// answers none. Two hours on, when the hand-over goes from the store,
/// the delete over it is pushed to that relay all the same: no relay
/// goes on holding that generation's secret sealed to a key because an
/// answer was lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hand_over_whose_push_was_not_answered_is_still_written_over_at_that_relay() {
    let relay = StandIn::started().await;
    let (mut adder, new) = (Device::new("desktop"), Device::new("laptop"));
    adder.makes_the_phrase(&phrase());
    adder.connects_to("relay", relay.port, relay.key).await;
    let now = adder.now();
    let added = add_device(
        &adder.db(),
        &adder.state.identity,
        &new.key(),
        "laptop",
        now,
    );
    let hand_over = added.unwrap().hand_over;
    let pair = hand_over.channel;
    let of_the_pair = move |request: &WireMessage| {
        matches!(request, WireMessage::EntryPush(_)) && channels_named(request).contains(&pair)
    };
    // What the relay was pushed of the pair channel, since it was last
    // asked: each entry by what it is named by, and whether it is a
    // delete.
    let pushed = |relay: &StandIn| -> Vec<([u8; 32], bool)> {
        relay
            .requests()
            .iter()
            .filter_map(|request| match request {
                WireMessage::EntryPush(push) => Some(push.entries.clone()),
                _ => None,
            })
            .flatten()
            .map(|entry| Entry::from_wire(&entry).unwrap())
            .filter(|entry| entry.channel == pair)
            .map(|entry| (entry.id(), entry.delete))
            .collect()
    };
    let sent_anywhere = |device: &Device| {
        cordelia_storage::at_relays::keeps_any_anywhere(&device.db(), &pair).unwrap()
    };

    // The relay is sent the hand-over, and its answer is lost: the
    // stream is reset.
    relay.hook(move |request| of_the_pair(request).then_some(Say::Reset));
    adder.passes().await;
    adder.sends().await;
    let sent = pushed(&relay);
    assert!(sent.contains(&(hand_over.id(), false)), "{sent:?}");
    assert!(
        sent_anywhere(&adder),
        "nothing is kept of a push that was sent and not answered"
    );

    // Two hours on, the hand-over goes from the store. The relay answers
    // again, and is sent the delete over it.
    relay.hook(|_| None);
    adder
        .clock
        .run_ahead(Duration::from_secs(HAND_OVER_KEPT_SECS as u64));
    for _ in 0..3 {
        adder.passes().await;
        adder.sends().await;
    }
    assert!(!adder.holds_of(&pair).contains(&hand_over.id()));
    let sent = pushed(&relay);
    assert!(
        sent.iter().any(|(_, delete)| *delete),
        "the relay was sent no delete over the hand-over: {sent:?}"
    );
}

/// What came back on a stream is not taken where the device applied a
/// change while it was on its way: the request was built under the entry
/// before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_comes_back_after_a_change_was_applied_is_not_taken() {
    let relay = StandIn::started().await;
    let (maker, mut device) = (Device::new("desktop"), Device::new("laptop"));
    maker.makes_the_phrase(&phrase());
    maker.adds(&device);
    device.holds("notes");
    let change = maker.changes(&phrase(), &[&maker, &device], &[]);
    device.connects_to("relay", relay.port, relay.key).await;
    device.passes().await;
    assert_eq!(device.has_leave("relay"), Ok(()));
    let link = device.link("relay");
    let pull = WireMessage::EntryPull(EntryPull {
        channel: device.channel("notes"),
        mark: [0; 8],
        after: 0,
        limit: ENTRY_PAGE_MAX_ENTRIES,
    });
    let taken = AtomicBool::new(false);
    let late = device
        .opens(
            &link,
            &pull,
            |_| {
                // The page is on its way back, and a change is applied
                // meanwhile: shown on another connection, say.
                let applied = shown(&device.db(), &device.state.identity, &change, device.now());
                assert!(matches!(applied.unwrap(), Shown::Applied(_)));
            },
            |_, _| taken.store(true, Ordering::SeqCst),
        )
        .await;
    assert!(late.is_err(), "{late:?}");
    assert!(
        !taken.load(Ordering::SeqCst),
        "a page was taken under an entry left"
    );
    assert_eq!(device.latest().id(), change.id());
}

// ── A device that wakes ──────────────────────────────────────────────

/// One relay never holds up another, once the device is awake. A relay
/// that answered one show and then answers nothing keeps its own turn
/// waiting, for as long as a stream waits. The device goes on pulling
/// from its other relay and pushing to it at its usual pace, pass after
/// pass, while the turn at the silent one is still waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_that_stops_answering_holds_up_no_other_relay() {
    let real = relay_started("real", None);
    let silent = StandIn::started().await;
    let (mut writer, mut reader) = (Device::new("desktop"), Device::new("laptop"));
    writer.makes_the_phrase(&phrase());
    writer.adds(&reader);
    // The reader is set up with the silent relay first: it is the first
    // that each of its passes comes to.
    reader.connects_to("silent", silent.port, silent.key).await;
    for device in [&mut writer, &mut reader] {
        device.holds("notes");
        device.connects("real", &real).await;
    }
    all_pass(&[&writer, &reader], 3).await;
    let notes = writer.channel("notes");
    assert_eq!(reader.has_leave("real"), Ok(()));
    assert_eq!(reader.has_leave("silent"), Ok(()));

    // The one relay answers nothing from now on.
    silent.goes_silent();
    // The reader's passes, as the node makes them: each is started, and
    // none is waited for. (The turn at the silent relay waits for as
    // long as a stream does, which is longer than the leave lasts.)
    let pass = |kind: Pass| {
        let (engine, relays) = (reader.engine.clone(), reader.relays.clone());
        tokio::spawn(async move { engine.pass(&relays, kind).await })
    };
    let within = |what: &str, check: &dyn Fn() -> bool| {
        let began = std::time::Instant::now();
        while !check() {
            assert!(
                began.elapsed() < Duration::from_secs(4),
                "{what}: not within four seconds"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    let began = std::time::Instant::now();
    for round in 0..4 {
        // What the writer writes, the reader pulls from the real relay.
        let file = writer.writes("notes", &format!("w{round}.md"), "by the writer");
        writer.passes().await;
        let whole = pass(Pass::Whole);
        within("the reader pulls from the relay that answers", &|| {
            reader.holds_of(&notes).contains(&file.id())
        });
        // And what the reader writes, it pushes there.
        let own = reader.writes("notes", &format!("r{round}.md"), "by the reader");
        let sends = pass(Pass::Send);
        within("the reader pushes to the relay that answers", &|| {
            holds_at(&real, &notes, &own.id())
        });
        // The first round's turn at the silent relay is still waiting.
        if round == 0 {
            assert!(!whole.is_finished());
        }
        drop((whole, sends));
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    // All four rounds went by while one stream's wait had not, twice
    // over: nothing here waited for the silent relay.
    let took = began.elapsed();
    assert!(took < Duration::from_secs(30), "{took:?}");
    assert!(took > Duration::from_secs(8), "{took:?}");
    // The silent relay was asked, and answered nothing since.
    assert!(!silent.seen().is_empty());

    // One turn runs at a time at a relay. Once every turn above has
    // ended, a pass is started: its turn at the silent relay waits. A
    // second pass then finds that turn running, leaves the silent relay
    // out, and comes back at once.
    tokio::time::sleep(Duration::from_secs(12)).await;
    silent.seen();
    let waiting = pass(Pass::Whole);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let began = std::time::Instant::now();
    reader.passes().await;
    let took = began.elapsed();
    assert!(took < Duration::from_secs(4), "{took:?}");
    assert!(!waiting.is_finished());
    assert_eq!(silent.seen(), [Seen::Short]);
}

/// While a device wakes, one pass at a time asks its relays. A second
/// pass that finds the first still asking does nothing, and asks no relay
/// again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn while_a_device_wakes_one_pass_at_a_time_asks_its_relays() {
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.connects_to("relay", relay.port, relay.key).await;
    relay.says(Say::Nothing, Say::Nothing);
    let (engine, relays) = (device.engine.clone(), device.relays.clone());
    let first = tokio::spawn(async move { engine.pass(&relays, Pass::Whole).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(relay.seen(), [Seen::Whole]);
    // The second comes back at once, and has asked nothing.
    let began = std::time::Instant::now();
    device.passes().await;
    device.sends().await;
    let took = began.elapsed();
    assert!(took < Duration::from_secs(2), "{took:?}");
    assert_eq!(relay.seen(), []);
    assert!(!first.is_finished());
    assert_eq!(device.has_leave("relay"), Err(NoLeave::Waking));
}

/// A device that wakes asks every relay first. With two relays, of which
/// the first lacks a change and the second holds it: nothing is taken
/// from the first, or sent to it, until the second has answered. So what
/// waited for the old channel is not sent there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_wakes_takes_and_sends_nothing_until_every_relay_has_answered() {
    let (lacks, has) = (relay_started("lacks", None), relay_started("has", None));
    let (mut maker, mut wakes) = (Device::new("desktop"), Device::new("laptop"));
    maker.makes_the_phrase(&phrase());
    maker.adds(&wakes);
    for device in [&mut maker, &mut wakes] {
        device.holds("notes");
        device.connects("lacks", &lacks).await;
        device.connects("has", &has).await;
    }
    all_pass(&[&maker, &wakes], 3).await;
    let old_notes = maker.channel("notes");

    // The laptop is closed, with an edit that it has not sent.
    wakes.disconnects("lacks");
    wakes.disconnects("has");
    wakes.passes().await;
    let waiting = wakes.writes("notes", "mine.md", "written while it was closed");
    // A change is made, and reaches only the second relay. The first
    // also holds something that the laptop has not read.
    let unread = maker.writes("notes", "unread.md", "written before the change");
    maker.passes().await;
    maker.disconnects("lacks");
    let change = maker.changes(&phrase(), &[&maker, &wakes], &[]);
    maker.passes().await;
    assert!(holds_at(&has, &change.channel, &change.id()));
    assert!(!holds_at(&lacks, &change.channel, &change.id()));
    assert!(holds_at(&lacks, &old_notes, &unread.id()));

    // The laptop is opened, and its connections come up one at a time:
    // the relay that lacks the change first.
    wakes.connects("lacks", &lacks).await;
    let before = wakes.counts("lacks");
    wakes.passes().await;
    wakes.sends().await;
    wakes.passes().await;
    // It showed there, and was answered "held". It has not heard from the
    // other, and neither takes nor sends.
    assert_eq!(wakes.has_leave("lacks"), Err(NoLeave::Waking));
    let asked = wakes.counts("lacks");
    assert!(asked.whole_shows + asked.short_shows > before.whole_shows + before.short_shows);
    assert_eq!(
        (asked.proofs, asked.pages, asked.pushes),
        (before.proofs, before.pages, before.pushes)
    );
    assert!(!holds_at(&lacks, &old_notes, &waiting.id()));
    assert!(!wakes.holds_of(&old_notes).contains(&unread.id()));
    assert!(wakes.at("lacks").heard_since_woke);
    assert!(!wakes.at("has").heard_since_woke);

    // The second connection comes up. It is answered with the change,
    // and applies it: and only then does anything go anywhere.
    wakes.connects("has", &has).await;
    wakes.passes().await;
    assert_eq!(wakes.latest().id(), change.id());
    assert!(wakes.at("has").heard_since_woke);
    wakes.passes().await;
    let new_notes = wakes.channel("notes");
    for relay in [&lacks, &has] {
        // What waited is in no relay's copy of the old channel, and the
        // first relay was shown the change by the device that woke.
        assert!(!holds_at(relay, &old_notes, &waiting.id()));
        assert!(holds_at(relay, &change.channel, &change.id()));
        let by_it = held_at(relay, &new_notes)
            .iter()
            .filter(|entry| entry.author == wakes.key())
            .count();
        assert_eq!(by_it, 1, "{}", relay.name);
    }
    // It did not take from the old channel what it had not read.
    assert!(!wakes.holds_of(&old_notes).contains(&unread.id()));
}

/// With a relay out of reach, a device that wakes does nothing for 30
/// seconds, and then makes its pass with the relays it reaches. The relay
/// that it has not heard from is named in what a status reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_a_relay_out_of_reach_a_device_waits_half_a_minute_and_then_goes_on() {
    assert_eq!(WAKE_WAIT_SECS, 30);
    let relay = relay_started("reached", None);
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    let waiting = device.writes("notes", "a.md", "waiting to be sent");
    let notes = device.channel("notes");
    device.set_up_with("out of reach");
    // It reaches none yet: there is nothing to have leave on.
    device.passes().await;
    assert!(device.status().relays.iter().all(|at| !at.heard_since_woke));

    // It reaches one. Whichever pass comes first asks it: here, the pass
    // that sends. And it is asked once: it has answered.
    device.connects("reached", &relay).await;
    device.sends().await;
    assert!(device.at("reached").heard_since_woke);
    let asked = device.counts("reached");
    assert_eq!((asked.whole_shows, asked.short_shows), (1, 0));
    device.sends().await;
    assert_eq!(device.counts("reached"), asked);
    device.passes().await;
    device.sends().await;
    // The one it reaches has answered. The other has not, and the device
    // waits.
    assert_eq!(device.has_leave("reached"), Err(NoLeave::Waking));
    assert!(device.at("reached").heard_since_woke);
    assert!(!device.at("out of reach").heard_since_woke);
    assert_eq!(device.at("reached").holds_latest, Some(true));
    assert_eq!(device.counts("reached").pushes, 0);
    assert!(!holds_at(&relay, &notes, &waiting.id()));
    // Some seconds short of the wait: still nothing.
    device
        .clock
        .run_ahead(Duration::from_secs(WAKE_WAIT_SECS - 10));
    device.passes().await;
    device.sends().await;
    assert_eq!(device.counts("reached").pushes, 0);
    assert!(!holds_at(&relay, &notes, &waiting.id()));
    // At the wait it goes on, with the relay that it reaches.
    device.clock.run_ahead(Duration::from_secs(10));
    device.passes().await;
    assert!(holds_at(&relay, &notes, &waiting.id()));
    assert_eq!(device.has_leave("reached"), Ok(()));
    // The other is still named as not heard from.
    assert!(!device.at("out of reach").heard_since_woke);
    assert_eq!(device.at("out of reach").holds_latest, None);
    assert_eq!(device.status().cannot_go_on, None);
    // It woke once: later passes do not wait again.
    let next = device.writes("notes", "b.md", "written once it was awake");
    device.sends().await;
    assert!(holds_at(&relay, &notes, &next.id()));
}

/// A machine that slept wakes. Its connections still look open, and its
/// leave is measured by a clock that stood still while it slept. Where
/// the time of day has run ahead of that clock by more than a leave
/// lasts since the pass before, every leave is dropped, and the device
/// asks every relay first, as when it starts: it neither takes nor sends
/// until each has answered, or half a minute has gone by. A clock that
/// simply ran on, however far, wakes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_machine_that_slept_asks_every_relay_first_when_it_wakes() {
    let relay = relay_started("reached", None);
    let unreached = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.connects("reached", &relay).await;
    device
        .connects_to("unreached", unreached.port, unreached.key)
        .await;
    device.passes().await;
    let notes = device.channel("notes");
    for name in ["reached", "unreached"] {
        assert_eq!(device.has_leave(name), Ok(()));
    }

    // Time goes by with the machine awake: both clocks run on together.
    // The leave runs out, and the next pass that sends shows and sends.
    device.clock.run_ahead(Duration::from_secs(3600));
    let first = device.writes("notes", "a.md", "written while it was awake");
    device.sends().await;
    assert!(holds_at(&relay, &notes, &first.id()));
    assert!(device.at("unreached").heard_since_woke);

    // The lid is closed for an hour. One relay answers nothing when it
    // opens: its connection still looks open.
    unreached.says(Say::Reset, Say::Reset);
    device.clock.slept(Duration::from_secs(3600));
    let waiting = device.writes("notes", "b.md", "written before the lid was closed");
    let before = device.counts("reached");
    device.sends().await;
    device.passes().await;
    device.sends().await;
    // It woke: the relay that answers was asked, and nothing was sent to
    // it, since the other has not answered.
    assert_eq!(device.has_leave("reached"), Err(NoLeave::Waking));
    assert!(device.at("reached").heard_since_woke);
    assert!(!device.at("unreached").heard_since_woke);
    let asked = device.counts("reached");
    assert!(asked.whole_shows + asked.short_shows > before.whole_shows + before.short_shows);
    assert_eq!(asked.pushes, before.pushes);
    assert!(!holds_at(&relay, &notes, &waiting.id()));
    // Half a minute on, it goes on with the relay that answers.
    device.clock.run_ahead(Duration::from_secs(WAKE_WAIT_SECS));
    device.sends().await;
    assert!(holds_at(&relay, &notes, &waiting.id()));
    assert_eq!(device.has_leave("reached"), Ok(()));
}

// ── Pulling ──────────────────────────────────────────────────────────

/// A second pull starts where the first ended: the device keeps its place
/// at a relay, with the mark of the relay's holding. A relay that dropped
/// the channel and took it again holds it under another mark, and is read
/// from the start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_pull_starts_where_the_first_ended_and_a_new_holding_is_read_from_the_start() {
    let mut relay = relay_started("relay", None);
    let (mut writer, mut reader) = (Device::new("desktop"), Device::new("laptop"));
    writer.makes_the_phrase(&phrase());
    writer.adds(&reader);
    for device in [&mut writer, &mut reader] {
        device.holds("notes");
        device.connects("relay", &relay).await;
    }
    all_pass(&[&writer, &reader], 3).await;
    let notes = writer.channel("notes");

    let first: Vec<CheckedEntry> = ["a.md", "b.md", "c.md"]
        .iter()
        .map(|file| writer.writes("notes", file, "a text"))
        .collect();
    writer.passes().await;
    let before = reader.counts("relay");
    reader.passes().await;
    let (mark, place) = reader.place("relay", &notes);
    assert_eq!(place, 3);
    assert_ne!(mark, [0; 8]);
    assert_eq!(reader.counts("relay").pulled, before.pulled + 3);
    // Nothing new: nothing is handed again.
    reader.passes().await;
    assert_eq!(reader.counts("relay").pulled, before.pulled + 3);

    // Two more are written. The second pull hands those two, and no
    // other.
    for file in ["d.md", "e.md"] {
        writer.writes("notes", file, "a text");
    }
    writer.passes().await;
    reader.passes().await;
    assert_eq!(reader.place("relay", &notes), (mark, 5));
    assert_eq!(reader.counts("relay").pulled, before.pulled + 5);
    let held = reader.holds_of(&notes);
    assert_eq!(held.len(), 5);
    assert!(first.iter().all(|entry| held.contains(&entry.id())));

    // The relay drops the channel: nobody used it for 90 days. (While it
    // is stopped, time goes by for what it holds.)
    relay.stop();
    {
        let db = rusqlite::Connection::open(relay.data_dir().join("cordelia.db")).unwrap();
        let changed = db
            .execute(
                "UPDATE relay_channels SET used_at = used_at - ?1 WHERE channel_id = ?2",
                rusqlite::params![91 * 24 * 60 * 60, notes.as_slice()],
            )
            .unwrap();
        assert_eq!(changed, 1);
    }
    relay.start();
    wait_for("relay healthy again", &[&relay], 30, || healthy(&relay));
    wait_for("the unused channel goes", &[&relay], 30, || {
        held_at(&relay, &notes).is_empty().then_some(())
    });

    // The writer proves the channel on its new connection, is answered
    // no, and sends it all again: the relay holds it anew.
    writer.connects("relay", &relay).await;
    writer.passes().await;
    writer.passes().await;
    assert_eq!(held_at(&relay, &notes).len(), 5);
    // The reader's place was in the other holding: it is handed the
    // channel from the start, and keeps its place in the new one.
    reader.connects("relay", &relay).await;
    let before = reader.counts("relay");
    reader.passes().await;
    let (new_mark, place) = reader.place("relay", &notes);
    assert_eq!(place, 5);
    assert_ne!(new_mark, mark);
    assert_eq!(reader.counts("relay").pulled, before.pulled + 5);
    assert_eq!(reader.holds_of(&notes), held);
}

/// A relay that drops a channel while a device's connection lasts answers
/// the device's next pull with the mark of no holding: the device proved
/// the channel there, and the relay holds it no more. The device then
/// knows that nothing it sent is there, and sends it all again, on the
/// same connection and with no proof more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_that_dropped_a_channel_says_so_and_is_sent_it_again() {
    let relay = relay_started("relay", None);
    let mut writer = Device::new("desktop");
    writer.makes_the_phrase(&phrase());
    writer.holds("notes");
    writer.connects("relay", &relay).await;
    let written: Vec<CheckedEntry> = ["a.md", "b.md", "c.md"]
        .iter()
        .map(|file| writer.writes("notes", file, "a text"))
        .collect();
    writer.passes().await;
    writer.passes().await;
    let notes = writer.channel("notes");
    assert_eq!(held_at(&relay, &notes).len(), 3);
    let (mark, _) = writer.place("relay", &notes);
    assert_ne!(mark, [0; 8]);
    let proofs = writer.counts("relay").proofs;

    // The relay drops the channel, as it does for room or where nobody
    // has used it: here its rows are taken out while it runs.
    {
        let db = rusqlite::Connection::open(relay.data_dir().join("cordelia.db")).unwrap();
        db.busy_timeout(Duration::from_secs(10)).unwrap();
        let entries = db
            .execute(
                "DELETE FROM entries WHERE channel_id = ?1",
                rusqlite::params![notes.as_slice()],
            )
            .unwrap();
        let channels = db
            .execute(
                "DELETE FROM relay_channels WHERE channel_id = ?1",
                rusqlite::params![notes.as_slice()],
            )
            .unwrap();
        assert_eq!((entries, channels), (3, 1));
    }
    assert!(held_at(&relay, &notes).is_empty());

    // The next pass pulls from the place it keeps, is told that there is
    // no holding, and sends the channel again.
    writer.passes().await;
    writer.passes().await;
    let held: BTreeSet<[u8; 32]> = held_at(&relay, &notes).iter().map(Entry::id).collect();
    let all: BTreeSet<[u8; 32]> = written.iter().map(|entry| entry.id()).collect();
    assert_eq!(held, all);
    // It made no proof more: the connection is the one it proved on.
    assert_eq!(writer.counts("relay").proofs, proofs);
    // Its place is in the new holding, under another mark.
    writer.passes().await;
    let (new_mark, place) = writer.place("relay", &notes);
    assert_ne!(new_mark, mark);
    assert_ne!(new_mark, [0; 8]);
    assert_eq!(place, 3);
}

/// A pull goes on only while it gets somewhere. A relay that answers
/// every pull of a channel with a full page of entries that the device
/// holds, under no mark, or under a mark with a place that does not
/// move, is asked for that channel once in a pass, and not ten times.
///
/// Such a pass has not read the channel to its end, and says so: a
/// command that waited for it is not told that everything was fetched
/// (decision 2026-10-04 §7.1, step 1). A pass that read every channel to
/// its end does not say so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pull_that_gets_nowhere_ends_for_the_pass() {
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    let held: Vec<Vec<u8>> = ["a.md", "b.md", "c.md"]
        .iter()
        .map(|file| device.writes("notes", file, "a text").to_wire())
        .collect();
    let notes = device.channel("notes");
    device.connects_to("relay", relay.port, relay.key).await;
    let pulls_of_notes = |relay: &StandIn| {
        let of_notes = |one: &WireMessage| matches!(one, WireMessage::EntryPull(pull) if pull.channel == notes);
        relay.requests().iter().filter(|one| of_notes(one)).count()
    };

    // Under no mark: the same page, of what the device holds, whatever
    // place is asked after.
    let page = held.clone();
    relay.pulls(move |pull| EntryPulled {
        entries: if pull.channel == notes {
            page.iter().map(|entry| entry.clone().into()).collect()
        } else {
            Vec::new()
        },
        next: 0,
        mark: [0; 8],
    });
    // The whole passes that the device has ended, and the last of them
    // that ended before it had read every channel to its end.
    let passes = |device: &Device| {
        let own = &device.state.own_channels;
        (own.whole_passes().1, own.last_short_pass())
    };
    assert_eq!(passes(&device), (0, 0));
    device.passes().await;
    assert_eq!(pulls_of_notes(&relay), 1);
    assert_eq!(passes(&device), (1, 1));
    let pulled = device.counts("relay").pulled;
    assert_eq!(pulled, 3);
    // And once in the next pass.
    device.clock.run_ahead(Duration::from_secs(SHOW_LEAVE_SECS));
    device.passes().await;
    assert_eq!(pulls_of_notes(&relay), 1);

    // Under a mark, with a place that does not move on from the one
    // asked after: once to find the holding, once more from its place,
    // and then no more in that pass.
    let page = held.clone();
    relay.pulls(move |pull| EntryPulled {
        entries: if pull.channel == notes {
            page.iter().map(|entry| entry.clone().into()).collect()
        } else {
            Vec::new()
        },
        next: pull.after,
        mark: [7; 8],
    });
    device.clock.run_ahead(Duration::from_secs(SHOW_LEAVE_SECS));
    device.passes().await;
    assert_eq!(pulls_of_notes(&relay), 2);
    device.clock.run_ahead(Duration::from_secs(SHOW_LEAVE_SECS));
    device.passes().await;
    assert_eq!(pulls_of_notes(&relay), 1);

    // The control: a place that moves on is followed, page after page,
    // to the end of what the relay holds.
    let page = held.clone();
    relay.pulls(move |pull| {
        let after = if pull.mark == [9; 8] {
            pull.after as usize
        } else {
            0
        };
        let entries: Vec<_> = if pull.channel == notes {
            page.iter()
                .skip(after)
                .take(1)
                .map(|entry| entry.clone().into())
                .collect()
        } else {
            Vec::new()
        };
        EntryPulled {
            next: (after + entries.len()) as u64,
            entries,
            mark: [9; 8],
        }
    });
    device.clock.run_ahead(Duration::from_secs(SHOW_LEAVE_SECS));
    let (before, short) = passes(&device);
    assert_eq!(short, before);
    device.passes().await;
    // Three pages of one entry each, and the page of nothing at the end.
    assert_eq!(pulls_of_notes(&relay), 4);
    // That pass read the channel to its end: it is not one that ended
    // early.
    assert_eq!(passes(&device), (before + 1, before));
}

/// What a device takes from one relay in a minute is bounded at what a
/// relay may hand a connection, and is counted for the relay, not for the
/// connection: a relay that hands page after page of the largest entries
/// is pulled from until that much was handed, and then not again in that
/// minute, on that connection or on a new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_takes_from_one_relay_only_so_much_in_a_minute() {
    use cordelia_core::protocol::{
        MAX_ENTRY_NAME_AND_VALUE_BYTES, MAX_ITEM_BYTES, PUSH_BYTES_PER_PEER_PER_MINUTE,
    };
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    let notes = device.channel("notes");
    // Entries of the largest size, by a key that counts: each page holds
    // new ones, and the place moves on, without end.
    let secret = device.name_secret("notes");
    let author = NodeIdentity::from_seed(*device.state.identity.seed()).unwrap();
    let largest = move |n: u64| -> Vec<u8> {
        let name = format!("{n}.md");
        let text = "x".repeat(MAX_ENTRY_NAME_AND_VALUE_BYTES - name.len());
        let entry = sealed(&author, &secret, 1, &name, Value::Text(text));
        assert_eq!(entry.content.len(), MAX_ITEM_BYTES);
        entry.to_wire()
    };
    const A_PAGE: u64 = 13;
    relay.pulls(move |pull| {
        if pull.channel != notes {
            return EntryPulled {
                entries: Vec::new(),
                next: pull.after,
                mark: pull.mark,
            };
        }
        let after = if pull.mark == [5; 8] { pull.after } else { 0 };
        EntryPulled {
            entries: (after..after + A_PAGE).map(|n| largest(n).into()).collect(),
            next: after + A_PAGE,
            mark: [5; 8],
        }
    });
    device.connects_to("relay", relay.port, relay.key).await;
    let pulls_of_notes = |relay: &StandIn| {
        let of_notes = |one: &WireMessage| matches!(one, WireMessage::EntryPull(pull) if pull.channel == notes);
        relay.requests().iter().filter(|one| of_notes(one)).count() as u64
    };

    device.passes().await;
    // It pulled until the relay had handed it what a relay may hand a
    // connection in a minute, and one page that took it over.
    let a_page = A_PAGE * entry_cost(MAX_ITEM_BYTES);
    let most = PUSH_BYTES_PER_PEER_PER_MINUTE / a_page + 1;
    let first = pulls_of_notes(&relay);
    assert_eq!(first, most);
    assert!(most < 10, "fewer than a pass would otherwise ask");
    assert_eq!(device.counts("relay").pulled, most * A_PAGE);
    // Not again in that minute: on this connection, or on a new one.
    device.clock.run_ahead(Duration::from_secs(SHOW_LEAVE_SECS));
    device.passes().await;
    assert_eq!(pulls_of_notes(&relay), 0);
    device.connects_to("relay", relay.port, relay.key).await;
    device.passes().await;
    device.passes().await;
    assert_eq!(pulls_of_notes(&relay), 0);
    assert_eq!(device.has_leave("relay"), Ok(()));
}

/// An entry that is sealed by `author` in the channel whose secret is
/// `secret`: for what a test writes with a key that is no device's here.
fn sealed(author: &NodeIdentity, secret: &[u8; 32], rev: u64, name: &str, value: Value) -> Entry {
    let inside = Inside {
        name: name.to_string(),
        value,
        chain: Some(Vec::new()),
    };
    Entry::seal(secret, author, rev, &inside).unwrap()
}

/// The entry in which the key `adder` adds the key of `new`, in the
/// personal channel of `under`, under the statement it has applied.
fn record_by(under: &Device, adder: &NodeIdentity, new: &NodeIdentity, label: &str) -> Entry {
    let statement = held(&under.db()).unwrap().unwrap().statement.statement;
    let device = Listed::new(new.public_key(), label).unwrap();
    let record = Addition::under(&statement, device, adder.public_key(), 1)
        .unwrap()
        .sign(adder)
        .unwrap();
    let name = cordelia_api::person::added_name(&new.public_key()).unwrap();
    let value = Value::Other(record.to_bytes().unwrap());
    sealed(adder, &under.personal_secret(), 1, &name, value)
}

/// Push `pushed` to the relay that `through` calls `relay`, on its
/// connection, as whoever holds an entry may.
async fn pushed_by_hand(through: &Device, relay: &str, pushed: &[&Entry]) -> Vec<PushAnswer> {
    let link = through.link(relay);
    let shown = through.latest();
    through
        .engine
        .leave()
        .show(&link, &shown, false)
        .await
        .unwrap();
    let request = WireMessage::EntryPush(EntryPush {
        entries: pushed.iter().map(|entry| entry.to_wire().into()).collect(),
    });
    let answered = through
        .opens(
            &link,
            &request,
            |answer| match answer {
                WireMessage::EntryPushed(pushed) => pushed.answers,
                other => panic!("not an answer to a push: {other:?}"),
            },
            |_, answers| answers,
        )
        .await;
    answered.unwrap()
}

/// A record of an addition that arrives after entries of the new device:
/// every channel is read again from the start, and the entries are held.
/// A device that was handed the record first holds the same. And the same
/// where a key comes to may add: what the key that it had added wrote is
/// read again, and held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_that_arrives_after_a_devices_entries_has_them_read_again_and_held() {
    let relay = relay_started("relay", None);
    let [adder, early, mut late] = three_in_step(&relay).await;
    let (personal, notes) = (adder.personal(), adder.channel("notes"));
    let stored = [PushAnswer::Stored];

    // The adder adds a fourth device, which holds the name and writes.
    // What it wrote reaches the relay before the record of its addition
    // does: the adder is closed.
    let mut fourth = Device::new("phone");
    adder.adds(&fourth);
    fourth.holds("notes");
    let by_fourth = fourth.writes("notes", "a.md", "by the device that was added");
    fourth.connects("relay", &relay).await;
    fourth.passes().await;
    fourth.passes().await;
    assert!(holds_at(&relay, &notes, &by_fourth.id()));

    // One device reads now: what the fourth wrote is refused, since its
    // key does not count yet, and the device's place moves past it.
    late.disconnects("relay");
    early.passes().await;
    assert!(!early.holds_of(&notes).contains(&by_fourth.id()));
    let (mark, place) = early.place("relay", &notes);
    assert_eq!(place, held_at(&relay, &notes).len() as u64);

    // The record arrives. That device reads it, the key comes to count,
    // and every channel is read again from the start: it holds what the
    // fourth wrote, in that same pass.
    adder.passes().await;
    early.passes().await;
    assert!(early.holds_of(&notes).contains(&by_fourth.id()));
    assert_eq!(early.place("relay", &notes), (mark, place));
    assert_eq!(
        early.text("notes", "a.md").as_deref(),
        Some("by the device that was added")
    );

    // A key that the fourth device adds counts, and may not add: the
    // fourth was added since the statement. It adds another all the same,
    // which writes a file. Each is written by hand here, with keys that
    // are no device's.
    let (eighth, ninth) = (
        NodeIdentity::generate().unwrap(),
        NodeIdentity::generate().unwrap(),
    );
    let fourth_adds = record_by(&adder, &fourth.state.identity, &eighth, "eighth");
    let eighth_adds = record_by(&adder, &eighth, &ninth, "ninth");
    let by_ninth = sealed(
        &ninth,
        &adder.name_secret("notes"),
        1,
        "b.md",
        Value::Text("by a key that a key added which might not".into()),
    );
    assert_eq!(
        pushed_by_hand(&fourth, "relay", &[&fourth_adds, &eighth_adds, &by_ninth]).await,
        [PushAnswer::Stored; 3]
    );
    early.passes().await;
    assert!(early.holds_of(&personal).contains(&eighth_adds.id()));
    assert!(!early.holds_of(&notes).contains(&by_ninth.id()));
    // A device of the statement adds the eighth too: it may add from now
    // on. The record that it had signed comes to count, and everything is
    // read again: what the ninth wrote is held.
    let lets_add = record_by(&adder, &adder.state.identity, &eighth, "eighth");
    assert_eq!(pushed_by_hand(&adder, "relay", &[&lets_add]).await, stored);
    early.passes().await;
    assert!(early.holds_of(&notes).contains(&by_ninth.id()));
    assert_eq!(
        early.text("notes", "b.md").as_deref(),
        Some("by a key that a key added which might not")
    );

    // The device that was closed is opened now, with everything at the
    // relay: it reads the records before the name, and holds the same.
    late.connects("relay", &relay).await;
    late.passes().await;
    late.passes().await;
    early.passes().await;
    assert_eq!(late.holds_of(&notes), early.holds_of(&notes));
    let at_the_relay: BTreeSet<[u8; 32]> = held_at(&relay, &personal)
        .iter()
        .map(|entry| entry.id())
        .collect();
    for device in [&early, &late] {
        assert!(device.holds_of(&personal).is_superset(&at_the_relay));
    }
    assert_eq!(late.holds_of(&notes).len(), held_at(&relay, &notes).len());
}

// ── Sending ──────────────────────────────────────────────────────────

/// An entry that is pushed to one relay reaches a second relay, which is
/// not listed with the first, through a device that is connected to
/// both. It is not sent back to the relay it came from, and not sent
/// twice to a relay that answered that it holds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_entry_reaches_a_second_relay_through_a_device_that_is_connected_to_both() {
    let (first, second) = (relay_started("first", None), relay_started("second", None));
    let (mut writer, mut between) = (Device::new("desktop"), Device::new("laptop"));
    writer.makes_the_phrase(&phrase());
    writer.adds(&between);
    for device in [&writer, &between] {
        device.holds("notes");
    }
    writer.connects("first", &first).await;
    between.connects("first", &first).await;
    between.connects("second", &second).await;
    all_pass(&[&writer, &between], 3).await;
    let notes = writer.channel("notes");
    assert!(held_at(&second, &notes).is_empty());

    let entry = writer.writes("notes", "a.md", "written at the first relay");
    writer.passes().await;
    assert!(holds_at(&first, &notes, &entry.id()));
    assert!(!holds_at(&second, &notes, &entry.id()));

    // The device between them takes it from the first, and sends it to
    // the second: with the pass that takes it, or with the next, since a
    // pass goes to its relays side by side.
    let before = (between.counts("first"), between.counts("second"));
    between.passes().await;
    between.sends().await;
    assert!(holds_at(&second, &notes, &entry.id()));
    let after = (between.counts("first"), between.counts("second"));
    assert_eq!(after.0.pulled, before.0.pulled + 1);
    assert_eq!(after.1.pushed, before.1.pushed + 1);
    // Not back to the relay it came from.
    assert_eq!(after.0.pushed, before.0.pushed);

    // Pass after pass, it is sent to neither again.
    for _ in 0..3 {
        between.passes().await;
        between.sends().await;
    }
    let later = (between.counts("first"), between.counts("second"));
    assert_eq!(
        (later.0.pushed, later.1.pushed),
        (after.0.pushed, after.1.pushed)
    );
    assert_eq!(later.0.pulled, after.0.pulled);
    // The second relay holds one entry of that slot, as the writer made
    // it.
    let held = held_at(&second, &notes);
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].author, writer.key());
}

/// A relay with no room for an entry: the entry is kept, and sent again
/// later, a little later each time, and the refusal is in what a status
/// reads. What the relay did take is not sent again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_entry_that_a_relay_has_no_room_for_is_kept_and_sent_again_later() {
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    let fits = device.writes("notes", "a.md", "this one fits");
    let does_not = device.writes("notes", "b.md", "and this one does not");
    let notes = device.channel("notes");
    // The relay has room for the change entry, the device's word that it
    // applied it, and one entry of the name: and for no more.
    let cost = |entry: &Entry| entry_cost(entry.content.len());
    let personal = device.personal();
    let personal: u64 = entries::channel_entries_after(&device.db(), &personal, 0, 100)
        .unwrap()
        .iter()
        .map(|held| cost(&held.entry))
        .sum();
    let room = cost(&device.latest()) + personal + cost(&fits);
    let relay = relay_started("relay", Some(room));
    device.connects("relay", &relay).await;

    let at = device.now();
    device.passes().await;
    assert!(holds_at(&relay, &notes, &fits.id()));
    assert!(!holds_at(&relay, &notes, &does_not.id()));
    // The show was taken: the refusal is of an entry, and for room.
    let status = device.at("relay");
    assert_eq!(status.holds_latest, Some(true));
    let no_room = status.no_room.expect("the refusal is kept for the status");
    assert!(!no_room.of_the_change && !no_room.over_allowance);
    assert!((at..at + 5).contains(&no_room.at));
    // Its word that it has sent what it carried is written by that pass
    // (decision 2026-10-04 §8), over its word in the personal channel,
    // and goes now: what is counted below is of the notes alone.
    device.sends().await;
    let first = device.counts("relay");

    // It is left for a while: nothing is sent at once, by either pass.
    device.passes().await;
    device.sends().await;
    assert_eq!(device.counts("relay").pushes, first.pushes);
    // Four seconds on it is sent again: that entry, and not the one that
    // the relay holds.
    device.clock.run_ahead(Duration::from_secs(4));
    device.sends().await;
    let second = device.counts("relay");
    assert_eq!(
        (second.pushes, second.pushed),
        (first.pushes + 1, first.pushed + 1)
    );
    assert!(!holds_at(&relay, &notes, &does_not.id()));
    // And then after eight: not after four.
    device.clock.run_ahead(Duration::from_secs(4));
    device.sends().await;
    assert_eq!(device.counts("relay").pushes, second.pushes);
    device.clock.run_ahead(Duration::from_secs(4));
    device.sends().await;
    assert_eq!(device.counts("relay").pushes, second.pushes + 1);
    // The device still holds it, and the status still says why it waits.
    assert!(device.holds_of(&notes).contains(&does_not.id()));
    assert!(device.at("relay").no_room.is_some());
    assert_eq!(held_at(&relay, &notes).len(), 1);
}

/// A device goes on past what a relay refuses for room (decision
/// 2026-10-04 §16). A relay at its cap has no room for an entry: what
/// follows that entry is still offered, at once, and the entry is not
/// sent again while its wait lasts. A delete behind it reaches the
/// relay, which makes room, and the refused entry then fits. An entry
/// that is refused while the wait lasts does not make the wait longer.
/// Nothing that the relay holds is sent twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delete_behind_an_entry_that_found_no_room_reaches_the_relay_and_the_entry_then_fits() {
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    let large = device.writes("notes", "a.md", &"a".repeat(8000));
    let refused = device.writes("notes", "b.md", &"b".repeat(3000));
    let notes = device.channel("notes");
    // The relay has room for the change entry, what the personal channel
    // holds, and the large entry: and for no entry more.
    let cost = |entry: &Entry| entry_cost(entry.content.len());
    let personal = device.personal();
    let personal: u64 = entries::channel_entries_after(&device.db(), &personal, 0, 100)
        .unwrap()
        .iter()
        .map(|held| cost(&held.entry))
        .sum();
    let slack = 512;
    let room = cost(&device.latest()) + personal + cost(&large) + slack;
    let relay = relay_started("relay", Some(room));
    device.connects("relay", &relay).await;

    device.passes().await;
    assert!(holds_at(&relay, &notes, &large.id()));
    assert!(!holds_at(&relay, &notes, &refused.id()));
    assert!(device.at("relay").no_room.is_some());
    // Its word that it has sent what it carried is written by that pass
    // (decision 2026-10-04 §8), over its word in the personal channel,
    // and goes now: what is counted below is of the notes alone.
    device.sends().await;
    let first = device.counts("relay");

    // What is written behind the refused entry is offered at once, and
    // alone: the relay has no room for it either.
    let behind = device.writes("notes", "c.md", &"c".repeat(500));
    device.sends().await;
    let second = device.counts("relay");
    assert_eq!(
        (second.pushes, second.pushed),
        (first.pushes + 1, first.pushed + 1),
        "what follows a refused entry is offered, and the refused one is not sent while it waits"
    );
    assert!(!holds_at(&relay, &notes, &behind.id()));

    // A delete of the large entry, behind both: it reaches the relay
    // while they wait, and the relay holds it over the large one.
    let delete = device.deletes("notes", "a.md");
    assert!(
        cost(&delete) + cost(&refused) + cost(&behind) <= cost(&large) + slack,
        "the delete makes room for both"
    );
    device.sends().await;
    let third = device.counts("relay");
    assert_eq!(
        (third.pushes, third.pushed),
        (second.pushes + 1, second.pushed + 1)
    );
    assert!(holds_at(&relay, &notes, &delete.id()));
    assert!(!holds_at(&relay, &notes, &large.id()));
    assert!(!holds_at(&relay, &notes, &refused.id()));
    // Nothing more goes while the wait lasts.
    device.sends().await;
    device.passes().await;
    assert_eq!(device.counts("relay").pushes, third.pushes);

    // Four seconds after the first refusal both are sent again, and
    // fit: the second refusal, which came while the wait lasted, did not
    // make it longer.
    device.clock.run_ahead(Duration::from_secs(4));
    device.sends().await;
    let fourth = device.counts("relay");
    assert_eq!(
        (fourth.pushes, fourth.pushed),
        (third.pushes + 1, third.pushed + 2)
    );
    let held: BTreeSet<[u8; 32]> = held_at(&relay, &notes).iter().map(Entry::id).collect();
    assert_eq!(
        held,
        BTreeSet::from([delete.id(), refused.id(), behind.id()])
    );
    // And nothing is sent after that, at once or once any wait is over:
    // nothing waits.
    device.sends().await;
    device
        .clock
        .run_ahead(Duration::from_secs(OUTBOX_REFUSED_RETRY_MAX_SECS));
    device.sends().await;
    device.passes().await;
    assert_eq!(device.counts("relay").pushes, fourth.pushes);
    assert_eq!(held_at(&relay, &notes).len(), 3);
}

/// A relay that will not begin a channel, because the device's address
/// is over its allowance of new channels there, is sent nothing of that
/// channel until a wait has gone by: nothing that follows makes room for
/// it. It is then sent the channel from where it stopped, and the wait
/// doubles while it refuses. The other channels go on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_channel_that_a_relay_will_not_begin_is_left_whole_until_the_wait_has_gone_by() {
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    let written = [
        device.writes("notes", "a.md", "one"),
        device.writes("notes", "b.md", "two"),
    ];
    let notes = device.channel("notes");
    // What the stand-in says of an entry of the name's channel: that it
    // will not begin the channel, until the test says that it takes it,
    // and that it has no room where the test says so.
    const TAKES: u64 = 1;
    const NO_ROOM: u64 = 2;
    let says = Arc::new(AtomicU64::new(0));
    let said = says.clone();
    relay.pushes(move |entry| match entry.channel == notes {
        true => match said.load(Ordering::SeqCst) {
            TAKES => PushAnswer::Stored,
            NO_ROOM => PushAnswer::Refused(EntryRefused::NoRoom),
            _ => PushAnswer::Refused(EntryRefused::OverLimit),
        },
        false => PushAnswer::Stored,
    });
    device.connects_to("relay", relay.port, relay.key).await;
    // What was pushed of the name's channel, by what each entry is named
    // by, one list for each push.
    let pushed_of_notes = |relay: &StandIn| -> Vec<Vec<[u8; 32]>> {
        relay
            .requests()
            .iter()
            .filter_map(|request| match request {
                WireMessage::EntryPush(push) => Some(
                    push.entries
                        .iter()
                        .map(|entry| Entry::from_wire(entry).unwrap())
                        .filter(|entry| entry.channel == notes)
                        .map(|entry| entry.id())
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .filter(|ids| !ids.is_empty())
            .collect()
    };
    let both = vec![written[0].id(), written[1].id()];

    device.passes().await;
    assert_eq!(pushed_of_notes(&relay), std::slice::from_ref(&both));
    let no_room = device.at("relay").no_room.expect("the refusal is kept");
    assert!(no_room.over_allowance && !no_room.of_the_change);

    // While the wait lasts nothing of the channel goes, what is written
    // meanwhile among it.
    let third = device.writes("notes", "c.md", "three");
    device.sends().await;
    device.passes().await;
    assert!(pushed_of_notes(&relay).is_empty());
    // After four seconds, all of it from where it stopped: nothing was
    // passed by.
    let all = vec![written[0].id(), written[1].id(), third.id()];
    device.clock.run_ahead(Duration::from_secs(4));
    device.sends().await;
    assert_eq!(pushed_of_notes(&relay), std::slice::from_ref(&all));
    // Refused again: then after eight, and not after four.
    device.clock.run_ahead(Duration::from_secs(4));
    device.sends().await;
    assert!(pushed_of_notes(&relay).is_empty());
    device.clock.run_ahead(Duration::from_secs(4));
    says.store(TAKES, Ordering::SeqCst);
    device.sends().await;
    assert_eq!(pushed_of_notes(&relay), [all]);
    // The relay took it: there is nothing more, and what is written next
    // goes at once.
    device.sends().await;
    assert!(pushed_of_notes(&relay).is_empty());
    let fourth = device.writes("notes", "d.md", "four");
    device.sends().await;
    assert_eq!(pushed_of_notes(&relay), [vec![fourth.id()]]);

    // Nothing waited there any more, so no wait was kept: the next
    // refusal is the first again, and what it refused is sent after
    // four seconds, and not after the sixteen that a third would give.
    says.store(NO_ROOM, Ordering::SeqCst);
    let fifth = device.writes("notes", "e.md", "five");
    device.sends().await;
    assert_eq!(pushed_of_notes(&relay), [vec![fifth.id()]]);
    device.sends().await;
    assert!(pushed_of_notes(&relay).is_empty());
    device.clock.run_ahead(Duration::from_secs(4));
    device.sends().await;
    assert_eq!(pushed_of_notes(&relay), [vec![fifth.id()]]);
}

/// A relay that holds another entry from a device in a slot, at the
/// revision of the one it is pushed, says so, and does not say "held":
/// the device signed two at one revision, as one that was put back from
/// a copy does. The device sends that entry there no more, and what a
/// status reads says that an entry of its own is at that relay in
/// another form. Its next edit goes above both, and is stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_that_holds_another_entry_at_that_revision_says_so_and_is_sent_it_no_more() {
    let relay = relay_started("relay", None);
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.connects("relay", &relay).await;
    device.passes().await;
    // Its word that it has sent what it carried is written by that pass
    // (decision 2026-10-04 §8), and goes now: what is counted below is
    // of the notes alone.
    device.sends().await;
    assert_eq!(device.at("relay").another_form, 0);

    // The device writes a file. Before it is sent, the relay comes to
    // hold another entry that the device's key signed in that slot at
    // that revision, with another text.
    let own = device.writes("notes", "a.md", "what the device holds");
    let other = sealed(
        &device.state.identity,
        &device.name_secret("notes"),
        own.rev,
        "a.md",
        Value::Text("what an earlier copy of it held".into()),
    );
    assert_eq!((other.slot, other.author), (own.slot, own.author));
    assert_ne!(other.id(), own.id());
    assert_eq!(
        pushed_by_hand(&device, "relay", &[&other]).await,
        [PushAnswer::Stored]
    );
    // Pushed by hand, the device's own is answered as that: another is
    // held there. And the very entry that is held is answered "held".
    let notes = device.channel("notes");
    let own_entry = own.clone().into_entry();
    assert_eq!(
        pushed_by_hand(&device, "relay", &[&own_entry, &other]).await,
        [PushAnswer::Another, PushAnswer::Held]
    );

    // The device's pass sends its own, is told the same, and says so
    // where a status reads it. The relay holds the other, and not this
    // one.
    let before = device.counts("relay");
    device.passes().await;
    let after = device.counts("relay");
    assert_eq!(after.pushed, before.pushed + 1);
    assert_eq!(device.at("relay").another_form, 1);
    assert!(holds_at(&relay, &notes, &other.id()));
    assert!(!holds_at(&relay, &notes, &own.id()));
    // It is sent no more, by either pass.
    device.passes().await;
    device.sends().await;
    assert_eq!(device.counts("relay").pushed, after.pushed);
    assert_eq!(device.at("relay").another_form, 1);

    // The next edit goes above both, and is stored.
    let next = device.writes("notes", "a.md", "the next edit");
    assert!(next.rev > own.rev);
    device.sends().await;
    assert!(holds_at(&relay, &notes, &next.id()));
    assert!(!holds_at(&relay, &notes, &other.id()));
    // And nothing of the device's own is at the relay in another form
    // any more: what a status says is counted from what the store
    // holds, and the entry that was there in another form is replaced
    // (decision 2026-10-04 §16).
    device.passes().await;
    assert_eq!(device.at("relay").another_form, 0);
}

/// A device proves the key of each channel of its own once on a
/// connection, and that of each name that its personal channel lists and
/// that it does not hold. Again on a new connection, and again after a
/// day on one that lasts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proof_is_made_once_for_a_connection_again_on_a_new_one_and_again_after_a_day() {
    assert_eq!(CHANNEL_PROOF_AGAIN_SECS, 24 * 60 * 60);
    let relay = relay_started("relay", None);
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    // Its personal channel lists a name that it does not hold.
    let word = sealed(
        &device.state.identity,
        &device.personal_secret(),
        1,
        "name/work",
        Value::Text(String::new()),
    );
    let word = word.check().unwrap();
    take(&device.db(), &device.state.identity, &word, device.now()).unwrap();
    device.connects("relay", &relay).await;

    // The personal channel, the name it holds, and the name that is
    // listed: three proofs, once.
    device.passes().await;
    assert_eq!(device.counts("relay").proofs, 3);
    for _ in 0..3 {
        device.passes().await;
        device.sends().await;
    }
    assert_eq!(device.counts("relay").proofs, 3);
    // The relay holds the two channels that the device wrote in, and was
    // handed nothing of the third.
    assert!(!held_at(&relay, &device.personal()).is_empty());
    assert!(held_at(&relay, &device.channel("work")).is_empty());

    // A minute short of a day: none. At a day: each again.
    device
        .clock
        .run_ahead(Duration::from_secs(CHANNEL_PROOF_AGAIN_SECS - 60));
    device.passes().await;
    assert_eq!(device.counts("relay").proofs, 3);
    device.clock.run_ahead(Duration::from_secs(60));
    device.passes().await;
    assert_eq!(device.counts("relay").proofs, 6);
    device.passes().await;
    assert_eq!(device.counts("relay").proofs, 6);

    // A new connection: each again, at once.
    device.connects("relay", &relay).await;
    device.passes().await;
    assert_eq!(device.counts("relay").proofs, 9);
    device.passes().await;
    assert_eq!(device.counts("relay").proofs, 9);
}

// ── What the adder of a device owes ──────────────────────────────────

/// A hand-over goes from the store of the device that made it two hours
/// after it was made, on the node's timer. A delete is written over it
/// and pushed, and the relay then holds the delete, and the hand-over no
/// more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hand_over_is_dropped_after_two_hours_and_the_relay_then_holds_a_delete() {
    assert_eq!(HAND_OVER_KEPT_SECS, 2 * 60 * 60);
    let relay = relay_started("relay", None);
    let (mut adder, new) = (Device::new("desktop"), Device::new("laptop"));
    adder.makes_the_phrase(&phrase());
    let now = adder.now();
    let added = add_device(
        &adder.db(),
        &adder.state.identity,
        &new.key(),
        "laptop",
        now,
    );
    let hand_over = added.unwrap().hand_over;
    let pair = hand_over.channel;
    adder.connects("relay", &relay).await;

    // The hand-over is sent, and the relay holds it.
    adder.passes().await;
    let held = held_at(&relay, &pair);
    assert_eq!(held.len(), 1);
    assert_eq!((held[0].id(), held[0].delete), (hand_over.id(), false));
    // A minute short of two hours it is still in the device's store.
    adder
        .clock
        .run_ahead(Duration::from_secs(HAND_OVER_KEPT_SECS as u64 - 60));
    adder.passes().await;
    assert!(adder.holds_of(&pair).contains(&hand_over.id()));
    assert_eq!(held_at(&relay, &pair)[0].id(), hand_over.id());

    // At two hours the pass drops it, writes the delete over it, and
    // pushes the delete.
    adder.clock.run_ahead(Duration::from_secs(60));
    adder.passes().await;
    assert!(!adder.holds_of(&pair).contains(&hand_over.id()));
    let held = held_at(&relay, &pair);
    assert_eq!(held.len(), 1, "the relay holds one entry of the slot");
    assert_eq!(
        (held[0].author, held[0].slot, held[0].rev, held[0].delete),
        (adder.key(), hand_over.slot, hand_over.rev + 1, true)
    );
    // What the device keeps of the hand-over is its revision.
    let kept = held_rows::handed_over(&adder.db(), &new.key()).unwrap();
    let kept = kept.unwrap();
    assert_eq!((kept.rev, kept.held), (hand_over.rev, false));
    // The delete is sent once.
    let sent = adder.counts("relay").pushed;
    for _ in 0..2 {
        adder.passes().await;
    }
    assert_eq!(adder.counts("relay").pushed, sent);
    // It went to every relay that was sent the hand-over: nothing is
    // kept of the pair channel at any relay after the next pass, and the
    // delete stays in the store, above the hand-over.
    let (relay_key, personal) = (key_of(&relay), adder.personal());
    let db = adder.db();
    assert!(!kept_rows::keeps_any_anywhere(&db, &pair).unwrap());
    let stored = entries::channel_entries_after(&db, &pair, 0, 10).unwrap();
    assert_eq!(stored.len(), 1);
    assert!(stored[0].entry.delete);
    // What is kept of the device's own channels there stays.
    assert!(kept_rows::keeps_any(&db, &relay_key, &personal).unwrap());
}

/// What a device keeps of a relay that it is set up with no longer is
/// forgotten at the next whole pass in which every relay it is set up
/// with is connected, and not while one of them is out of reach: a
/// relay's key is known while it is connected. What it keeps in memory
/// goes with it: set up with that relay again, it is sent everything
/// from the start, at once, and not after the wait that a refusal there
/// had begun.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_is_kept_of_a_relay_that_is_set_up_no_longer_is_forgotten() {
    let (stays, goes) = (StandIn::started().await, StandIn::started().await);
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    let written = device.writes("notes", "a.md", "one");
    let (notes, personal) = (device.channel("notes"), device.personal());
    // The relay that will go does not begin the name's channel: nothing
    // of that channel is sent there until a wait has gone by.
    let begins = Arc::new(AtomicBool::new(false));
    let begun = begins.clone();
    goes.pushes(
        move |entry| match entry.channel == notes && !begun.load(Ordering::SeqCst) {
            true => PushAnswer::Refused(EntryRefused::OverLimit),
            false => PushAnswer::Stored,
        },
    );
    // What was pushed of the name's channel to the relay that goes.
    let pushed_of_notes = |goes: &StandIn| -> Vec<[u8; 32]> {
        goes.requests()
            .iter()
            .filter_map(|request| match request {
                WireMessage::EntryPush(push) => Some(push.entries.clone()),
                _ => None,
            })
            .flatten()
            .map(|entry| Entry::from_wire(&entry).unwrap())
            .filter(|entry| entry.channel == notes)
            .map(|entry| entry.id())
            .collect()
    };
    let keeps = |device: &Device, relay: &[u8; 32]| {
        kept_rows::keeps_any(&device.db(), relay, &personal).unwrap()
    };
    device.connects_to("stays", stays.port, stays.key).await;
    device.connects_to("goes", goes.port, goes.key).await;
    device.passes().await;
    assert!(keeps(&device, &stays.key) && keeps(&device, &goes.key));
    assert_eq!(pushed_of_notes(&goes), [written.id()]);
    // The wait lasts: nothing of the channel goes there.
    device.passes().await;
    assert!(pushed_of_notes(&goes).is_empty());

    // A pass is given the relays whose names resolved, which may be
    // fewer than the device is set up with. One that is not among them
    // is not taken for one that went: nothing is forgotten.
    let link = device.link("goes");
    device.relays.retain(|relay| relay.name != "goes");
    device.passes().await;
    assert!(keeps(&device, &goes.key));
    device.relays.push(Relay {
        name: "goes".into(),
        link: Some(link),
    });

    // Set up with it no longer, and the relay that stays is out of
    // reach: nothing is forgotten, since which relays the device is set
    // up with is not known by their keys.
    device.sets_up_no_longer("goes");
    device.disconnects("stays");
    device.passes().await;
    assert!(keeps(&device, &goes.key));
    // The pass that sends forgets nothing either.
    device.connects_to("stays", stays.port, stays.key).await;
    device.sends().await;
    assert!(keeps(&device, &goes.key));
    // The whole pass, with every relay connected: what was kept of the
    // one that went is forgotten, and of the one that stays, kept.
    device.passes().await;
    assert!(!keeps(&device, &goes.key));
    assert!(keeps(&device, &stays.key));

    // Set up with it again: it is sent everything from the start, and
    // the name's channel at once. The wait that its refusal had begun
    // went with the rest.
    begins.store(true, Ordering::SeqCst);
    device.connects_to("goes", goes.port, goes.key).await;
    device.passes().await;
    assert_eq!(pushed_of_notes(&goes), [written.id()]);
    assert!(keeps(&device, &goes.key));
}

// ── The pair channel of a key typed at `accept` ──────────────────────

/// The row of §5.1 that `on` stands in, by its name.
fn row_of(on: &Device) -> &'static str {
    let stands = cordelia_api::leaving::among(&on.db(), &on.state.identity).unwrap();
    cordelia_api::adding::Row::of(stands)
        .expect("a device that takes a key")
        .name()
}

/// The key of `of`, as `on` keeps it typed now, in the row it stands in.
fn types(on: &Device, of: &Device) -> TypedKey {
    // The row is read first: the database is held for one thing at a time.
    let row = row_of(on);
    acts::type_key(&on.db(), &of.key(), row, on.now()).unwrap();
    acts::typed_key(&on.db(), &of.key()).unwrap().unwrap()
}

/// Ask the relay that `device` calls `relay` for what the device of the
/// key `typed` hands over, through the one door for that.
async fn asks_for_hand_over(
    device: &Device,
    relay: &str,
    typed: &TypedKey,
) -> Result<PairRead, Refused> {
    let link = device.link(relay);
    let leave = device.engine.leave();
    leave.pair(&device.state, &link, typed, |_| false).await
}

/// One channel is read without leave: the pair channel of a key typed at
/// `accept`, within its hour (decision 2026-10-04 §4.6, §5.1). A device
/// that follows no phrase has no leave anywhere, and nothing to show: its
/// whole pass asks its relay for what the device of the typed key hands
/// over, and it is accepted. The key is then spent, nothing of the pair
/// channel is in the device's store, and no place is kept in it. The pass
/// that sends asks for no hand-over.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_typed_keys_pair_channel_is_read_without_leave_and_its_hand_over_accepted() {
    let relay = relay_started("relay", None);
    let (mut adder, mut new) = (Device::new("desktop"), Device::new("laptop"));
    adder.makes_the_phrase(&phrase());
    let added = add_device(
        &adder.db(),
        &adder.state.identity,
        &new.key(),
        "laptop",
        adder.now(),
    );
    let pair = added.unwrap().hand_over.channel;
    adder.connects("relay", &relay).await;
    adder.passes().await;
    assert_eq!(held_at(&relay, &pair).len(), 1);

    // The new device follows no phrase: it has no leave, and no channel
    // of its own.
    new.connects("relay", &relay).await;
    new.passes().await;
    assert_eq!(new.stands(), Stands::NoPhrase);
    assert!(new.has_leave("relay").is_err());
    assert_eq!(new.counts("relay"), Counts::default());

    // A person types the key. The pass that sends asks for nothing.
    let typed = types(&new, &adder);
    new.sends().await;
    assert_eq!(new.stands(), Stands::NoPhrase);
    // The whole pass asks, and what the relay holds is accepted: the
    // device follows the phrase, and has applied its statement. That is
    // a change of settings, counted before the work and once it is done.
    let counted = new.state.sync_control.generation();
    new.passes().await;
    assert_eq!(new.stands(), Stands::Applied);
    assert_eq!(new.latest().id(), adder.latest().id());
    assert_eq!(new.state.sync_control.generation(), counted + 2);
    // The key is spent, and reads nothing more.
    let kept = acts::typed_key(&new.db(), &adder.key()).unwrap().unwrap();
    assert!(kept.taken_at.is_some());
    assert!(kept.said.unwrap().contains("this device has joined"));
    assert_eq!(
        asks_for_hand_over(&new, "relay", &typed).await,
        Ok(PairRead::NotNow)
    );
    // Nothing of the pair channel is in its store, and it keeps no
    // place in it: what came through the door went to `accept`, and
    // nowhere else.
    assert!(new.holds_of(&pair).is_empty());
    assert!(!kept_rows::keeps_any_anywhere(&new.db(), &pair).unwrap());
    // A whole pass is counted as it begins and as it ends.
    let (begun, ended) = new.state.own_channels.whole_passes();
    assert_eq!((begun, ended), (2, 2));
    new.sends().await;
    assert_eq!(new.state.own_channels.whole_passes(), (2, 2));
}

/// The hour of a typed key is judged by the node's clock, the one a test
/// sets (decision 2026-10-04 §6, decision 2026-10-09 §13): set to the end
/// of that hour, the key reads nothing, and nothing is asked of the
/// relay; set a second before it, the hand-over is read and taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hour_of_a_typed_key_is_judged_by_the_nodes_clock() {
    let relay = relay_started("relay", None);
    let (mut adder, mut new) = (Device::new("desktop"), Device::new("laptop"));
    adder.makes_the_phrase(&phrase());
    let added = add_device(
        &adder.db(),
        &adder.state.identity,
        &new.key(),
        "laptop",
        adder.now(),
    );
    added.unwrap();
    adder.connects("relay", &relay).await;
    adder.passes().await;
    new.connects("relay", &relay).await;
    let typed = types(&new, &adder);
    let an_hour = cordelia_core::protocol::PAIR_KEY_TYPED_SECS;

    new.state
        .sync_control
        .set_now(Some(typed.typed_at + an_hour));
    assert_eq!(
        asks_for_hand_over(&new, "relay", &typed).await,
        Ok(PairRead::NotNow)
    );
    assert_eq!(new.stands(), Stands::NoPhrase);

    new.state
        .sync_control
        .set_now(Some(typed.typed_at + an_hour - 1));
    assert_ne!(
        asks_for_hand_over(&new, "relay", &typed).await,
        Ok(PairRead::NotNow)
    );
    assert_eq!(new.stands(), Stands::Applied);
}

/// A hand-over that is read from a pair channel and is not taken is no
/// change of settings (decision 2026-10-04 §4.2): nothing is counted, and
/// no sync cycle is stopped for it. Here the key was typed while the
/// device followed no phrase, and the device has made a phrase of its own
/// since: the yes was for another row, and the hand-over is refused.
///
/// Typed again where the device stands, the hand-over is taken, and that
/// is a change. The device is moved: it has left the phrase it had made,
/// and keeps no note of which relays had handed the channels it held, so
/// that a folder's first cycle in a channel it comes to waits until the
/// channel was fetched (§6).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hand_over_is_a_change_of_settings_only_where_it_is_taken() {
    let relay = relay_started("relay", None);
    let (mut adder, mut new) = (Device::new("desktop"), Device::new("laptop"));
    adder.makes_the_phrase(&phrase());
    let added = add_device(
        &adder.db(),
        &adder.state.identity,
        &new.key(),
        "laptop",
        adder.now(),
    );
    added.unwrap();
    adder.connects("relay", &relay).await;
    adder.passes().await;

    let typed = types(&new, &adder);
    new.makes_the_phrase(&Phrase::parse(OTHER_WORDS).unwrap());
    let its_own = new.latest().id();
    new.connects("relay", &relay).await;
    let counted = new.state.sync_control.generation();
    let read = asks_for_hand_over(&new, "relay", &typed).await;
    let Ok(PairRead::Read(read)) = read else {
        panic!("{read:?}");
    };
    assert!(
        matches!(read.as_slice(), [Accepted::Refused(_)]),
        "{read:?}"
    );
    assert_eq!(new.latest().id(), its_own);
    assert_eq!(new.state.sync_control.generation(), counted);

    new.state.own_channels.set_up_with(1);
    let channel = [8u8; 32];
    let noted = std::time::Instant::now();
    new.state
        .own_channels
        .fetched_from(&channel, "relay", noted);
    assert!(new.state.own_channels.first_fetch_done(&channel, noted));
    let typed = types(&new, &adder);
    let read = asks_for_hand_over(&new, "relay", &typed).await;
    let Ok(PairRead::Read(read)) = read else {
        panic!("{read:?}");
    };
    assert!(matches!(read.as_slice(), [Accepted::Moved(_)]), "{read:?}");
    assert_eq!(new.latest().id(), adder.latest().id());
    assert_eq!(new.state.sync_control.generation(), counted + 2);
    assert!(!new.state.own_channels.first_fetch_done(&channel, noted));
}

/// The door for a typed key can do nothing else. It asks the relay
/// nothing for a key that the device does not keep as typed, or whose
/// hour has gone. For one it keeps, it proves the pair channel of that
/// key and this device, and pulls that channel's first page, and makes
/// no other request. Of what comes back, only an entry of that channel
/// that the typed key signed is given to `accept`: anything else is
/// dropped, and nothing is stored. What it asks is counted with what
/// the device asks of a relay in a minute.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_door_for_a_typed_key_proves_and_pulls_that_keys_pair_channel_and_nothing_else() {
    let relay = StandIn::started().await;
    let (adder, mut new) = (Device::new("desktop"), Device::new("laptop"));
    adder.makes_the_phrase(&phrase());
    let now = adder.now();
    let added = add_device(
        &adder.db(),
        &adder.state.identity,
        &new.key(),
        "laptop",
        now,
    );
    let hand_over = added.unwrap().hand_over;
    let pair_secret = derive::pair_secret(&new.state.identity, &adder.key()).unwrap();
    let pair = derive::channel_id(&pair_secret).unwrap();
    assert_eq!(hand_over.channel, pair);
    new.connects_to("relay", relay.port, relay.key).await;
    relay.requests();
    let stored = |device: &Device| -> i64 {
        let db = device.db();
        db.query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
            .unwrap()
    };

    // A key that the device does not keep as typed: nothing is asked.
    let not_typed = TypedKey {
        key: adder.key(),
        typed_at: new.now(),
        taken_at: None,
        said: None,
        stood: "no_phrase".into(),
    };
    assert_eq!(
        asks_for_hand_over(&new, "relay", &not_typed).await,
        Ok(PairRead::NotNow)
    );
    // A key that was typed an hour ago, and one typed at another time
    // than the device keeps it: nothing either.
    let an_hour = cordelia_core::protocol::PAIR_KEY_TYPED_SECS;
    let row = row_of(&new);
    acts::type_key(&new.db(), &adder.key(), row, new.now() - an_hour).unwrap();
    let old = acts::typed_key(&new.db(), &adder.key()).unwrap().unwrap();
    assert_eq!(
        asks_for_hand_over(&new, "relay", &old).await,
        Ok(PairRead::NotNow)
    );
    let typed = types(&new, &adder);
    let typed_before = TypedKey {
        typed_at: typed.typed_at - 5,
        ..typed.clone()
    };
    assert_eq!(
        asks_for_hand_over(&new, "relay", &typed_before).await,
        Ok(PairRead::NotNow)
    );
    // And another key than the one it keeps, though it is said to have
    // been typed at that very time.
    let another = TypedKey {
        key: Device::new("tablet").key(),
        ..typed.clone()
    };
    assert_eq!(
        asks_for_hand_over(&new, "relay", &another).await,
        Ok(PairRead::NotNow)
    );
    assert!(relay.requests().is_empty());

    // A key it keeps: the proof, of the pair channel and of no other.
    // The relay does not hold the channel, and is asked no more.
    assert_eq!(
        asks_for_hand_over(&new, "relay", &typed).await,
        Ok(PairRead::NotHeld)
    );
    let asked = relay.requests();
    assert_eq!(asked.len(), 1);
    assert!(
        matches!(&asked[0], WireMessage::ChannelProve(prove) if prove.channel == pair),
        "{asked:?}"
    );

    // The relay holds it, and hands a page: an entry of another channel
    // that the typed key signed, an entry of the pair channel that
    // another key signed, and bytes that are no entry. None is given to
    // `accept`, and none is stored.
    relay.holds_what_is_proved(true);
    let elsewhere = sealed(
        &adder.state.identity,
        &adder.personal_secret(),
        7,
        "hand-over",
        Value::Text("not here".into()),
    );
    let by_another = sealed(
        &new.state.identity,
        &pair_secret,
        9,
        "hand-over",
        Value::Text("not by the typed key".into()),
    );
    let handed = Arc::new(Mutex::new(vec![
        elsewhere.to_wire(),
        by_another.to_wire(),
        vec![1, 2, 3],
    ]));
    let hands = handed.clone();
    relay.pulls(move |pull| EntryPulled {
        entries: hands
            .lock()
            .unwrap()
            .iter()
            .map(|bytes| bytes.clone().into())
            .collect(),
        next: 3,
        mark: pull.mark,
    });
    assert_eq!(
        asks_for_hand_over(&new, "relay", &typed).await,
        Ok(PairRead::Read(Vec::new()))
    );
    let asked = relay.requests();
    assert_eq!(asked.len(), 2, "{asked:?}");
    assert!(matches!(&asked[0], WireMessage::ChannelProve(prove) if prove.channel == pair));
    match &asked[1] {
        WireMessage::EntryPull(pull) => {
            assert_eq!((pull.channel, pull.after), (pair, 0));
            assert_eq!(pull.mark, [0u8; 8], "from the start, under no mark");
        }
        other => panic!("not a pull: {other:?}"),
    }
    assert_eq!(new.stands(), Stands::NoPhrase);
    assert_eq!(stored(&new), 0);
    let kept = acts::typed_key(&new.db(), &adder.key()).unwrap().unwrap();
    assert_eq!((kept.taken_at, kept.said), (None, None));

    // The hand-over, among the rest: it is given to `accept`, and the
    // device follows the phrase. The rest is still dropped.
    handed.lock().unwrap().push(hand_over.to_wire());
    let read = asks_for_hand_over(&new, "relay", &typed).await.unwrap();
    match read {
        PairRead::Read(each) => {
            assert_eq!(each.len(), 1);
            assert!(matches!(each[0], Accepted::Joined(_)), "{each:?}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(new.stands(), Stands::Applied);
    // Of the page, nothing is in its store: what it holds now is what
    // applying the statement wrote.
    assert!(new.holds_of(&pair).is_empty());
    assert!(!kept_rows::keeps_any_anywhere(&new.db(), &pair).unwrap());
    // Every request was a proof or a pull, of that one channel.
    let asked = relay.requests();
    assert!(asked.iter().all(|request| match request {
        WireMessage::ChannelProve(prove) => prove.channel == pair,
        WireMessage::EntryPull(pull) => pull.channel == pair,
        _ => false,
    }));

    // What the door asks is counted with what a device asks of a relay
    // in a minute: a key typed again and again is refused before the
    // relay would count a breach.
    relay.holds_what_is_proved(false);
    let mut refused = None;
    for _ in 0..OWN_ENTRY_REQUESTS_PER_MINUTE {
        let typed = types(&new, &adder);
        match asks_for_hand_over(&new, "relay", &typed).await {
            Ok(_) => {}
            Err(why) => {
                refused = Some(why);
                break;
            }
        }
    }
    assert_eq!(refused, Some(Refused::AskedEnough));
    assert!(relay.requests().len() <= OWN_ENTRY_REQUESTS_PER_MINUTE as usize);
}

// ── The door for a carry that a person asked for ─────────────────────

/// Ask the device's engine to read `channel` at each relay through the
/// door for a carry, as the node does where a command's work asked.
async fn reads_left(device: &Device, channel: [u8; 32], by: ProvedBy) -> Vec<LeftAt> {
    reads_left_at(device, channel, by, None).await
}

/// [`reads_left`], at the relays named in `only` alone where it names
/// some.
async fn reads_left_at(
    device: &Device,
    channel: [u8; 32],
    by: ProvedBy,
    only: Option<Vec<String>>,
) -> Vec<LeftAt> {
    let (answer, answered) = tokio::sync::oneshot::channel();
    let until = std::time::Instant::now() + Duration::from_secs(30);
    let ask = DoorAsk::Read {
        channel,
        by,
        only,
        until,
        answer,
    };
    device.engine.door(&device.relays, ask).await;
    answered.await.unwrap()
}

/// The entries that one relay handed through the door, each by what it
/// is named by; `None` where it handed none of the channel.
fn handed_ids(read: &LeftRead) -> Option<(BTreeSet<[u8; 32]>, bool)> {
    match read {
        LeftRead::Read { entries, whole } => {
            let ids = entries
                .iter()
                .map(|bytes| Entry::from_wire(bytes).unwrap().id())
                .collect();
            Some((ids, *whole))
        }
        _ => None,
    }
}

/// The door for a carry that a person asked for (decision 2026-10-04
/// §7.3, §7.5, §9), against a relay: a device that has applied a change
/// reads, at its relay, the channel of a name in the generation that it
/// left. It is handed everything that the relay holds of it, to its end.
/// It stores none of it, keeps no place, and the relay holds what it
/// held. A device that follows no phrase reads the same way, with the
/// channel's secret, as a recovery does: no leave is asked. A relay that
/// is not connected is said to be that, and a relay that does not hold
/// the channel, or is given a proof that does not hold, says no.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_door_for_a_carry_reads_a_channel_that_was_left_and_stores_nothing() {
    let relay = relay_started("relay", None);
    let (mut a, mut b) = (Device::new("laptop"), Device::new("desktop"));
    a.makes_the_phrase(&phrase());
    a.adds(&b);
    for device in [&mut a, &mut b] {
        device.connects("relay", &relay).await;
        device.holds("lab");
    }
    a.writes("lab", "first.md", "what both hold");
    all_pass(&[&a, &b], 3).await;
    // The desktop writes, the relay is sent it, and the laptop does not
    // take it before it makes a change.
    b.writes("lab", "late.md", "the desktop's last words");
    b.passes().await;
    let (old_secret, old) = (b.name_secret("lab"), b.channel("lab"));
    let at_the_relay: BTreeSet<[u8; 32]> = held_at(&relay, &old).iter().map(Entry::id).collect();
    assert_eq!(at_the_relay.len(), 2);
    a.changes(&phrase(), &[&a, &b], &[]);
    a.passes().await;
    assert_ne!(a.channel("lab"), old);
    assert_eq!(a.text("lab", "late.md"), None);
    let stored = |device: &Device| -> i64 {
        let db = device.db();
        db.query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
            .unwrap()
    };
    let (stored_before, pulled_before) = (stored(&a), a.counts("relay").pulled);

    // With the secret of the generation that it left: everything that
    // the relay holds of the channel, to its end.
    let by_secret = || ProvedBy::Secret(zeroize::Zeroizing::new(old_secret));
    let read = reads_left(&a, old, by_secret()).await;
    assert_eq!(read.len(), 1);
    assert_eq!(read[0].relay, "relay");
    assert_eq!(
        handed_ids(&read[0].read),
        Some((at_the_relay.clone(), true))
    );
    // Nothing of it is stored, and no place is kept there.
    assert_eq!(stored(&a), stored_before);
    assert!(a.holds_of(&old).is_empty());
    assert!(!kept_rows::keeps_any_anywhere(&a.db(), &old).unwrap());
    assert_eq!(a.place("relay", &old), ([0u8; 8], 0));
    // What it was handed is counted with what it takes of the relay.
    assert_eq!(a.counts("relay").pulled, pulled_before + 2);
    // And the relay holds what it held: nothing was pushed there.
    let after: BTreeSet<[u8; 32]> = held_at(&relay, &old).iter().map(Entry::id).collect();
    assert_eq!(after, at_the_relay);

    // A device that follows no phrase reads the same way: no leave is
    // asked, and it has none to give.
    let mut new = Device::new("tablet");
    new.connects("relay", &relay).await;
    assert_eq!(new.stands(), Stands::NoPhrase);
    let read = reads_left(&new, old, by_secret()).await;
    assert_eq!(
        handed_ids(&read[0].read),
        Some((at_the_relay.clone(), true))
    );
    assert_eq!(stored(&new), 0);
    assert_eq!(new.stands(), Stands::NoPhrase);

    // With proofs that were made elsewhere, over the value of each
    // connection's session: the same. A proof that was made for another
    // connection does not hold, and a relay with no proof is not asked.
    let (answer, answered) = tokio::sync::oneshot::channel();
    a.engine.door(&a.relays, DoorAsk::Sessions { answer }).await;
    let sessions = answered.await.unwrap();
    assert_eq!(sessions.len(), 1);
    let (name, session) = (&sessions[0].0, sessions[0].1.unwrap());
    assert_eq!(name, "relay");
    let proof = cordelia_crypto::proof::make(&old_secret, &session, &a.key()).unwrap();
    let made = |relay: &str, session: [u8; 32], proof: [u8; 64]| {
        ProvedBy::Proofs(vec![ProofMade {
            relay: relay.into(),
            session,
            proof,
        }])
    };
    let read = reads_left(&a, old, made("relay", session, proof)).await;
    assert_eq!(
        handed_ids(&read[0].read),
        Some((at_the_relay.clone(), true))
    );
    let for_another = cordelia_crypto::proof::make(&old_secret, &session, &new.key()).unwrap();
    let read = reads_left(&a, old, made("relay", session, for_another)).await;
    assert_eq!(read[0].read, LeftRead::NotHeld);
    // **A proof goes with the session that it was made over** (§16),
    // and is sent on the connection with that session alone. One that
    // is said to be made over another is not sent, though it would
    // hold: the relay is answered for as one whose connection changed,
    // and never as one that holds none. So is a relay that no proof
    // was made for: it had no connection when the proofs were made.
    let pulled = a.counts("relay").pulled;
    let read = reads_left(&a, old, made("relay", [7; 32], proof)).await;
    assert_eq!(read[0].read, LeftRead::Changed);
    let read = reads_left(&a, old, made("other", session, proof)).await;
    assert_eq!(read[0].read, LeftRead::Changed);
    assert_eq!(a.counts("relay").pulled, pulled);

    // A channel that the relay does not hold, and a secret that is not
    // the channel's: no, with nothing handed.
    let never = derive::own_secret(&old_secret, "never-held").unwrap();
    let not_held = derive::channel_id(&never).unwrap();
    let read = reads_left(
        &a,
        not_held,
        ProvedBy::Secret(zeroize::Zeroizing::new(never)),
    )
    .await;
    assert_eq!(read[0].read, LeftRead::NotHeld);
    let read = reads_left(&a, old, ProvedBy::Secret(zeroize::Zeroizing::new(never))).await;
    assert_eq!(read[0].read, LeftRead::NotHeld);

    // A relay that the device is set up with and does not reach is
    // answered for as that, in the order of the relays.
    a.set_up_with("far");
    let read = reads_left(&a, old, by_secret()).await;
    let said: Vec<(&str, bool)> = read
        .iter()
        .map(|at| (at.relay.as_str(), at.read == LeftRead::NotReached))
        .collect();
    assert_eq!(said, [("relay", false), ("far", true)]);
    // Asked for at some of them, it is read at those alone, and no
    // other is answered for.
    for (only, reached) in [("relay", true), ("far", false)] {
        let read = reads_left_at(&a, old, by_secret(), Some(vec![only.to_string()])).await;
        assert_eq!(read.len(), 1, "{read:?}");
        assert_eq!(read[0].relay, only);
        assert_eq!(read[0].read != LeftRead::NotReached, reached);
    }
    let nowhere = reads_left_at(&a, old, by_secret(), Some(Vec::new())).await;
    assert!(nowhere.is_empty(), "{nowhere:?}");

    // A node that is held up reads nothing.
    a.state
        .held
        .hold(cordelia_api::state::Held::FirstStart("not done".into()));
    let read = reads_left(&a, old, by_secret()).await;
    assert!(matches!(&read[0].read, LeftRead::NotRead(why) if why.contains("held up")));
    a.state.held.release();
}

/// The door for a carry proves and pulls, and does nothing else
/// (decision 2026-10-04 §7.3, §7.5), against a stand-in that records
/// every request. It makes one proof, of that channel, and then pulls of
/// that channel alone: from the start under no mark, and then from each
/// place that it was handed, until a page holds nothing. It shows
/// nothing, and pushes nothing. An entry of another channel, and bytes
/// that are no entry, are dropped. **A channel of the device's own is
/// refused, with nothing asked of the relay:** there is one way in to
/// those. And what it asks is counted with what a device asks of a relay
/// in a minute.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_door_for_a_carry_proves_and_pulls_and_does_nothing_else() {
    let relay = StandIn::started().await;
    let mut a = Device::new("laptop");
    a.makes_the_phrase(&phrase());
    a.holds("lab");
    let (old_secret, old) = (a.name_secret("lab"), a.channel("lab"));
    let personal_before = a.personal_secret();
    let of_the_old = |rev: u64, file: &str| {
        sealed(
            &a.state.identity,
            &old_secret,
            rev,
            file,
            Value::Text(format!("{file} {rev}")),
        )
    };
    let pages = vec![
        vec![
            of_the_old(1, "a.md").to_wire(),
            of_the_old(1, "b.md").to_wire(),
        ],
        vec![
            of_the_old(1, "c.md").to_wire(),
            // An entry of another channel, and bytes that are no entry.
            sealed(
                &a.state.identity,
                &personal_before,
                3,
                "elsewhere",
                Value::Delete,
            )
            .to_wire(),
            vec![1, 2, 3],
        ],
        vec![],
    ];
    // What of those pages is an entry of the channel: three.
    let of_the_channel: BTreeSet<[u8; 32]> = pages
        .iter()
        .flatten()
        .filter_map(|bytes| Entry::from_wire(bytes).ok()?.check().ok())
        .filter(|entry| entry.channel == old)
        .map(|entry| entry.id())
        .collect();
    assert_eq!(of_the_channel.len(), 3);
    a.changes(&phrase(), &[&a], &[]);
    a.connects_to("relay", relay.port, relay.key).await;
    relay.requests();

    // The relay answers the proof with no: it is asked no more.
    let by_secret = || ProvedBy::Secret(zeroize::Zeroizing::new(old_secret));
    let read = reads_left(&a, old, by_secret()).await;
    assert_eq!(read[0].read, LeftRead::NotHeld);
    let asked = relay.requests();
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert!(matches!(&asked[0], WireMessage::ChannelProve(prove) if prove.channel == old));

    // It holds the channel, and hands it in three pages.
    relay.holds_what_is_proved(true);
    let mark = [7u8; 8];
    let hands = pages.clone();
    relay.pulls(move |pull| {
        let page = hands.get(pull.after as usize).cloned().unwrap_or_default();
        EntryPulled {
            next: pull.after + u64::from(!page.is_empty()),
            entries: page.into_iter().map(Into::into).collect(),
            mark,
        }
    });
    let read = reads_left(&a, old, by_secret()).await;
    let (ids, whole) = handed_ids(&read[0].read).unwrap();
    assert!(whole);
    assert_eq!(ids, of_the_channel);
    // One proof, and then pulls of that channel alone: from the start
    // under no mark, and then from each place that it was handed.
    let asked = relay.requests();
    assert!(matches!(&asked[0], WireMessage::ChannelProve(prove) if prove.channel == old));
    let pulls: Vec<([u8; 8], u64)> = asked[1..]
        .iter()
        .map(|request| match request {
            WireMessage::EntryPull(pull) => {
                assert_eq!(pull.channel, old);
                (pull.mark, pull.after)
            }
            other => panic!("neither a proof nor a pull: {other:?}"),
        })
        .collect();
    assert_eq!(pulls, [([0u8; 8], 0), (mark, 1), (mark, 2)]);
    assert!(a.holds_of(&old).is_empty());

    // A page that does not move the place ends the reading: a relay
    // that hands the same page again and again is not asked for ever.
    let again = pages[0].clone();
    relay.pulls(move |pull| EntryPulled {
        entries: again.iter().cloned().map(Into::into).collect(),
        next: pull.after,
        mark: pull.mark,
    });
    let read = reads_left(&a, old, by_secret()).await;
    assert!(handed_ids(&read[0].read).unwrap().1);
    assert_eq!(relay.requests().len(), 2);

    // **A page of which nothing is an entry of the channel is not the
    // channel's end.** The relay hands a page of the channel, and then
    // one that holds an entry of another channel and bytes that are no
    // entry: the reading stops there, with what it had, and the channel
    // is said to be read in part.
    let (first, junk) = (pages[0].clone(), pages[1][1..].to_vec());
    relay.pulls(move |pull| {
        let page = match pull.after {
            0 => first.clone(),
            _ => junk.clone(),
        };
        EntryPulled {
            next: pull.after + 1,
            entries: page.into_iter().map(Into::into).collect(),
            mark,
        }
    });
    let read = reads_left(&a, old, by_secret()).await;
    let (ids, whole) = handed_ids(&read[0].read).unwrap();
    assert!(!whole, "{read:?}");
    assert_eq!(ids.len(), 2);
    assert_eq!(relay.requests().len(), 3);

    // A channel of the device's own is refused, and the relay is asked
    // nothing: the name's channel in the generation applied, and the
    // personal channel.
    for (channel, secret) in [
        (a.channel("lab"), a.name_secret("lab")),
        (a.personal(), a.personal_secret()),
    ] {
        let read = reads_left(
            &a,
            channel,
            ProvedBy::Secret(zeroize::Zeroizing::new(secret)),
        )
        .await;
        assert!(
            matches!(&read[0].read, LeftRead::NotRead(why) if why.contains("this device's own")),
            "{read:?}"
        );
    }
    assert!(relay.requests().is_empty());

    // What the door asks is counted with what a device asks of a relay
    // in a minute: a channel read again and again is refused before the
    // relay would count a breach.
    relay.holds_what_is_proved(false);
    let until = std::time::Instant::now() + Duration::from_secs(5);
    let mut asked_enough = false;
    for _ in 0..OWN_ENTRY_REQUESTS_PER_MINUTE {
        let proof = a
            .link("relay")
            .session()
            .and_then(|session| cordelia_crypto::proof::make(&old_secret, &session, &a.key()).ok())
            .unwrap();
        let page = a
            .engine
            .leave()
            .left(
                &a.state,
                &a.link("relay"),
                &old,
                &proof,
                ([0u8; 8], 0),
                true,
            )
            .await;
        if page == Err(LeftRefused::AskedEnough) {
            asked_enough = true;
            break;
        }
        assert!(
            std::time::Instant::now() < until || page.is_ok(),
            "{page:?}"
        );
    }
    assert!(asked_enough);
    assert!(relay.requests().len() <= OWN_ENTRY_REQUESTS_PER_MINUTE as usize);
}

/// **A read of a generation that was left counts each proof it sends,
/// and keeps places back for the device's own channels** (decision
/// 2026-10-04 §16), against a stand-in that sees every request. A relay
/// remembers the proofs of so many channels for one connection, of
/// channels that it holds or not, and looks at none beyond them: here
/// twelve.
///
/// The device holds four channels of its own, and reads thirty of a
/// generation that was left, of which the relay holds none: it answers
/// each proof with no. Each of those proofs is counted all the same. On
/// one connection the device sends twelve proofs and not one more:
/// eight for what it reads, and one for each channel of its own, whether
/// the pass or the read comes first there. **Where a read finds no room
/// it asks nothing of the relay, and says so;** on a connection that is
/// made again it goes on from the channel it was at, and every channel
/// is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_of_what_was_left_counts_its_proofs_and_keeps_places_for_the_devices_own() {
    const MOST: usize = 12;
    let relay = StandIn::started().await;
    let mut a = Device::proving_at_most("laptop", MOST);
    a.makes_the_phrase(&phrase());
    for name in ["one", "two", "three"] {
        a.holds(name);
    }
    let own: BTreeSet<[u8; 32]> = ["one", "two", "three"]
        .iter()
        .map(|name| a.channel(name))
        .chain([a.personal()])
        .collect();
    // Thirty channels of a generation that was left, and three more:
    // names that the device does not hold, each with its secret.
    let left: Vec<([u8; 32], [u8; 32])> = (0..33)
        .map(|n| {
            let secret = derive::own_secret(&a.secret(), &format!("left-{n}")).unwrap();
            (secret, derive::channel_id(&secret).unwrap())
        })
        .collect();
    // The proofs that the relay saw since it was last asked: those of
    // the device's own channels, and those of channels that were left.
    let proofs = |relay: &StandIn| -> (usize, usize) {
        let proved: Vec<[u8; 32]> = relay
            .requests()
            .iter()
            .filter_map(|request| match request {
                WireMessage::ChannelProve(prove) => Some(prove.channel),
                _ => None,
            })
            .collect();
        let of_its_own = proved.iter().filter(|channel| own.contains(*channel));
        let of_its_own = of_its_own.count();
        (of_its_own, proved.len() - of_its_own)
    };

    a.connects_to("relay", relay.port, relay.key).await;
    // On the first connection the pass comes first: a proof for each
    // channel of the device's own.
    a.passes().await;
    let mut on_this_connection = proofs(&relay);
    assert_eq!(on_this_connection, (4, 0));
    let mut connections = vec![];
    for (secret, channel) in &left[..30] {
        loop {
            let by = ProvedBy::Secret(zeroize::Zeroizing::new(*secret));
            let read = reads_left(&a, *channel, by).await;
            let (of_its_own, of_what_was_left) = proofs(&relay);
            on_this_connection.0 += of_its_own;
            on_this_connection.1 += of_what_was_left;
            match &read[0].read {
                // The relay holds none of it: the proof was sent, and
                // is counted.
                LeftRead::NotHeld => {
                    assert_eq!(of_what_was_left, 1);
                    break;
                }
                // No room: nothing was asked of the relay. The pass
                // still has a place for each channel of the device's
                // own, and the connection then has as many proofs as a
                // relay remembers, and not one more.
                LeftRead::NoRoom => {
                    assert_eq!((of_its_own, of_what_was_left), (0, 0));
                    a.passes().await;
                    on_this_connection.0 += proofs(&relay).0;
                    assert_eq!(on_this_connection, (4, MOST - 4));
                    connections.push(on_this_connection);
                    // Made again, a connection starts with none
                    // remembered: here the read comes first.
                    a.connects_to("relay", relay.port, relay.key).await;
                    on_this_connection = (0, 0);
                }
                other => panic!("{other:?}"),
            }
        }
    }
    // Thirty channels, eight on a connection: three connections that
    // were filled, and six on the fourth, where the pass then proves
    // each channel of the device's own.
    assert_eq!(connections, vec![(4, 8); 3]);
    assert_eq!(on_this_connection, (0, 6));
    a.passes().await;
    assert_eq!(proofs(&relay), (4, 0));
    // Two more are read there, and the connection is full: a third has
    // no room.
    let reads = |n: usize| {
        let (secret, channel) = left[n];
        reads_left(
            &a,
            channel,
            ProvedBy::Secret(zeroize::Zeroizing::new(secret)),
        )
    };
    for n in [30, 31] {
        assert_eq!(reads(n).await[0].read, LeftRead::NotHeld);
    }
    assert_eq!(reads(32).await[0].read, LeftRead::NoRoom);
    assert_eq!(proofs(&relay), (0, 2));
    // A channel that was read on this connection has its place there,
    // which the relay remembers: it is read again with no room asked.
    assert_eq!(reads(29).await[0].read, LeftRead::NotHeld);
    assert_eq!(proofs(&relay), (0, 1));
}

// ── The node, as a process ───────────────────────────────────────────

/// A personal node, as a process of its own, with its timers: one that
/// follows no phrase opens no stream of this kind and says nothing of it
/// in its log. One whose store holds a phrase and an entry shows its
/// change entry to its relay, and sends what its store holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_personal_node_makes_its_passes_on_its_timers_and_none_without_a_phrase() {
    let relay = relay_started("relay", None);

    // A node that follows no phrase, as every device does until the
    // commands exist.
    let mut without = node("without", "personal", Some(relay.p2p));
    without.start();
    wait_for(
        "the node reaches its relay",
        &[&without, &relay],
        60,
        || has_hot_peer(&without),
    );
    // More than one whole pass, and several of the pass that sends.
    tokio::time::sleep(Duration::from_secs(13)).await;
    assert_eq!(channels_at(&relay), 0);
    let log = std::fs::read_to_string(without.log()).unwrap();
    let of_this: Vec<&str> = log
        .lines()
        .filter(|line| line.contains("device_entries"))
        .collect();
    assert!(of_this.is_empty(), "{of_this:?}");
    without.stop();

    // A node whose store holds a phrase, a name and an entry, written
    // there before it starts by the functions that the commands will
    // call.
    let mut with = node("with", "personal", Some(relay.p2p));
    let (change, file, notes) = {
        let db = cordelia_storage::db::open(&with.data_dir().join("cordelia.db")).unwrap();
        let identity = NodeIdentity::from_file(&with.data_dir().join("identity.key")).unwrap();
        let now = chrono::Utc::now().timestamp();
        first_statement(&db, &identity, &phrase(), "with", now).unwrap();
        let notes = hold_name(&db, "notes", now).unwrap();
        let write = Write {
            name: "notes",
            file: "a.md",
            value: Value::Text("what the node's store holds".into()),
            planned: PlannedAgainst::NoVersion,
            merge: None,
        };
        let Published::Made(file) = publish(&db, &identity, &write, now).unwrap() else {
            panic!("the entry was not made");
        };
        let change = at_relays::to_show(&db).unwrap().unwrap().entry;
        (change, *file, notes)
    };
    with.start();
    wait_for(
        "the relay holds what the node sent",
        &[&with, &relay],
        90,
        || {
            (holds_at(&relay, &change.channel, &change.id())
                && holds_at(&relay, &notes, &file.id()))
            .then_some(())
        },
    );
    // The change entry, the personal channel and the name.
    assert_eq!(channels_at(&relay), 3);
}

/// A device drops from its own store each slot whose delete it has held
/// for 90 days (decision 2026-10-04 §2.3, §7.3), by its own clock.
/// **Once a day** (§16): the node's hourly timer asks, and the device
/// sweeps where a day has gone by since it last did, so that a channel
/// is read again from its start once a day at most. A node that is held
/// up sweeps nothing, and sweeps when it is held up no more. **The time
/// of a sweep is noted once it has succeeded:** one that failed is tried
/// again when the device is next asked, and not a day later.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_sweeps_the_deletes_it_has_held_for_90_days() {
    use cordelia_api::state::Held;
    use cordelia_core::protocol::{
        DEVICE_DELETE_SWEEP_INTERVAL_SECS, KEYED_TOMBSTONE_RETENTION_DAYS,
    };
    let device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.writes("notes", "stays.md", "a text");
    device.writes("notes", "gone.md", "a text that is deleted");
    device.deletes("notes", "gone.md");
    let channel = device.channel("notes");
    assert_eq!(device.holds_of(&channel).len(), 2);

    let held_for = Duration::from_secs(u64::from(KEYED_TOMBSTONE_RETENTION_DAYS) * 24 * 60 * 60);
    device.clock.run_ahead(held_for - Duration::from_secs(60));
    device.engine.sweep_deletes();
    assert_eq!(device.holds_of(&channel).len(), 2);

    // The delete comes of age. The device swept two minutes ago: asked
    // again, within the day, it does not sweep.
    assert_eq!(DEVICE_DELETE_SWEEP_INTERVAL_SECS, 24 * 60 * 60);
    let (day, hour) = (
        Duration::from_secs(DEVICE_DELETE_SWEEP_INTERVAL_SECS),
        Duration::from_secs(60 * 60),
    );
    device.clock.run_ahead(Duration::from_secs(120));
    device.engine.sweep_deletes();
    assert_eq!(device.holds_of(&channel).len(), 2, "swept twice in a day");
    device.clock.run_ahead(day - hour);
    device.engine.sweep_deletes();
    assert_eq!(device.holds_of(&channel).len(), 2, "swept twice in a day");
    // A day after it last swept.
    device.clock.run_ahead(hour);
    let held = Held::FirstStart("the first start on this version is not done".into());
    device.state.held.hold(held);
    device.engine.sweep_deletes();
    assert_eq!(device.holds_of(&channel).len(), 2, "swept while held up");
    device.state.held.release();
    // A sweep that fails: the store cannot be written. Nothing went, and
    // no time is noted for it. Asked again, with no time gone by, the
    // device sweeps.
    let written = |can_be: bool| {
        device
            .db()
            .pragma_update(None, "query_only", !can_be)
            .unwrap()
    };
    written(false);
    device.engine.sweep_deletes();
    assert_eq!(
        device.holds_of(&channel).len(),
        2,
        "swept a store that cannot be written"
    );
    written(true);
    device.engine.sweep_deletes();
    assert_eq!(
        device.holds_of(&channel).len(),
        1,
        "a sweep that failed is tried a day later"
    );
    assert_eq!(device.text("notes", "stays.md").as_deref(), Some("a text"));
    assert_eq!(device.text("notes", "gone.md"), None);
}

/// **A file made again under a swept name reaches a device that swept
/// later** (decision 2026-10-04 §16), against a relay. The laptop writes
/// a file and deletes it. Ninety days on, by the laptop's clock and by
/// the relay's, each has swept the delete, and the laptop makes the file
/// again: at the first revision. The desktop is behind: it still holds
/// the delete, of the same author, at a higher revision. It pulls the new
/// entry, keeps nothing of it, and its place at the relay moves past it.
///
/// When the desktop's own 90 days have passed, its sweep takes the
/// delete and forgets its place in that channel, and in no other. Its
/// next whole pass reads the channel from the start: the file is there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_made_again_under_a_swept_name_reaches_a_device_that_swept_later() {
    use cordelia_core::protocol::KEYED_TOMBSTONE_RETENTION_DAYS;
    const HELD_SECS: u64 = KEYED_TOMBSTONE_RETENTION_DAYS as u64 * 24 * 60 * 60;
    let mut relay = relay_started("relay", None);
    let (mut laptop, mut desktop) = (Device::new("laptop"), Device::new("desktop"));
    laptop.makes_the_phrase(&phrase());
    laptop.adds(&desktop);
    for device in [&mut laptop, &mut desktop] {
        device.connects("relay", &relay).await;
        device.holds("lab");
    }
    let first = laptop.writes("lab", "again.md", "first");
    laptop.writes("lab", "other.md", "stays");
    all_pass(&[&laptop, &desktop], 3).await;
    laptop.deletes("lab", "again.md");
    all_pass(&[&laptop, &desktop], 3).await;
    let lab = laptop.channel("lab");
    for device in [&laptop, &desktop] {
        assert_eq!(device.holds_of(&lab).len(), 2);
        assert_eq!(device.text("lab", "again.md").as_deref(), Some("Delete"));
    }
    assert_eq!(held_at(&relay, &lab).len(), 2);

    // Ninety days on for the laptop: its delete goes, and its slot holds
    // nothing.
    laptop.clock.run_ahead(Duration::from_secs(HELD_SECS + 60));
    laptop.engine.sweep_deletes();
    assert_eq!(laptop.holds_of(&lab).len(), 1);
    // And for the relay. (While it is stopped, time goes by for the
    // delete that it holds.)
    relay.stop();
    {
        let db = rusqlite::Connection::open(relay.data_dir().join("cordelia.db")).unwrap();
        let changed = db
            .execute(
                "UPDATE entries SET stored_at = stored_at - ?1
                 WHERE channel_id = ?2 AND is_delete = 1",
                rusqlite::params![(HELD_SECS + 60) as i64, lab.as_slice()],
            )
            .unwrap();
        assert_eq!(changed, 1);
    }
    relay.start();
    wait_for("relay healthy again", &[&relay], 30, || healthy(&relay));
    wait_for("the relay sweeps the old delete", &[&relay], 30, || {
        (held_at(&relay, &lab).len() == 1).then_some(())
    });
    for device in [&mut laptop, &mut desktop] {
        device.connects("relay", &relay).await;
    }

    // The laptop makes the file again: at the first revision. The relay
    // takes it.
    let again = laptop.writes("lab", "again.md", "made again");
    assert_eq!(again.rev, first.rev);
    all_pass(&[&laptop], 2).await;
    assert!(holds_at(&relay, &lab, &again.id()));

    // The desktop still holds the delete. Whatever it is handed from
    // the place it has reached, it keeps nothing of the new entry: that
    // is below the delete, and of the delete's author.
    all_pass(&[&desktop], 2).await;
    let at = desktop.place("relay", &lab);
    assert_ne!(at, ([0u8; 8], 0));
    assert!(!desktop.holds_of(&lab).contains(&again.id()));
    assert_eq!(desktop.text("lab", "again.md").as_deref(), Some("Delete"));
    let personal = derive::channel_id(&desktop.personal_secret()).unwrap();
    let in_personal = desktop.place("relay", &personal);
    assert_ne!(in_personal.1, 0);

    // The desktop's own 90 days: its delete goes, and its place in that
    // channel is forgotten. Its place in its personal channel stays.
    desktop.clock.run_ahead(Duration::from_secs(HELD_SECS + 60));
    desktop.engine.sweep_deletes();
    assert_eq!(desktop.holds_of(&lab).len(), 1);
    assert_eq!(desktop.text("lab", "again.md"), None);
    assert_eq!(desktop.place("relay", &lab), ([0u8; 8], 0));
    assert_eq!(desktop.place("relay", &personal), in_personal);
    // The next whole pass reads the channel from its start: the file is
    // there.
    desktop.passes().await;
    assert_ne!(desktop.place("relay", &lab), ([0u8; 8], 0));
    assert!(desktop.holds_of(&lab).contains(&again.id()));
    assert_eq!(
        desktop.text("lab", "again.md").as_deref(),
        Some("made again")
    );
    assert_eq!(desktop.text("lab", "other.md").as_deref(), Some("stays"));
}

/// A channel whose proof is not sent is passed by, and the whole pass
/// has not read every channel to its end: it says so, as a pass does
/// whose pull stopped short (decision 2026-10-04 §7.1, step 1). A device
/// proves no more channels on a connection than a relay remembers for
/// one: here, one. A device that proves each of its channels makes a
/// pass that says no such thing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pass_that_passed_a_channel_by_for_its_proof_has_not_read_everything() {
    // The whole passes that a device has ended, and the last of them
    // that ended before it had read every channel to its end.
    let passes = |device: &Device| {
        let own = &device.state.own_channels;
        (own.whole_passes().1, own.last_short_pass())
    };
    for (most_proved, short) in [(1, 1), (MAX_CHANNELS_PROVED_ON_A_CONNECTION, 0)] {
        let relay = StandIn::started().await;
        let mut device = Device::proving_at_most("laptop", most_proved);
        device.makes_the_phrase(&phrase());
        device.holds("notes");
        device.writes("notes", "a.md", "a text");
        device.connects_to("relay", relay.port, relay.key).await;
        assert_eq!(passes(&device), (0, 0));
        device.passes().await;
        // The personal channel and the name's: each is proved and
        // pulled where there is room for its proof, and where there is
        // none the channel is not pulled.
        let asked = relay.requests();
        let proved = |one: &&WireMessage| matches!(one, WireMessage::ChannelProve(_));
        let pulled = |one: &&WireMessage| matches!(one, WireMessage::EntryPull(_));
        let both = most_proved.min(2);
        assert_eq!(asked.iter().filter(proved).count(), both, "{most_proved}");
        assert_eq!(asked.iter().filter(pulled).count(), both, "{most_proved}");
        assert_eq!(passes(&device), (1, short), "{most_proved}");
    }
}

/// A node that is held up makes no pass (decision 2026-10-04 §10.1):
/// nothing is shown, asked, sent or taken, by the whole pass or by the
/// pass that sends, and no whole pass is counted. Held up no longer, it
/// passes as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_is_held_up_makes_no_pass() {
    use cordelia_api::state::Held;
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.writes("notes", "a.md", "a text");
    device.connects_to("relay", relay.port, relay.key).await;

    let held = Held::FirstStart("the first start on this version is not done".into());
    device.state.held.hold(held);
    device.passes().await;
    device.sends().await;
    assert!(relay.requests().is_empty(), "{:?}", relay.requests());
    assert_eq!(device.state.own_channels.whole_passes(), (0, 0));

    device.state.held.release();
    device.passes().await;
    assert!(!relay.requests().is_empty());
    assert_eq!(device.state.own_channels.whole_passes(), (1, 1));
}

// ── The messages channel (decision 2026-10-09 §2.1, §8) ──────────────

/// The channels that each of `requests` is of: a proof's, a pull's, and
/// those of the entries of a push.
fn of_channels(requests: &[WireMessage]) -> Vec<[u8; 32]> {
    requests
        .iter()
        .flat_map(|request| match request {
            WireMessage::ChannelProve(prove) => vec![prove.channel],
            WireMessage::EntryPull(pull) => vec![pull.channel],
            WireMessage::EntryPush(push) => push
                .entries
                .iter()
                .map(|entry| Entry::from_wire(entry).unwrap().channel)
                .collect(),
            _ => Vec::new(),
        })
        .collect()
}

/// What a stand-in saw of the channel `channel` since it was last asked:
/// how many proofs, pulls and entries pushed.
fn asked_of(relay: &StandIn, channel: &[u8; 32]) -> (usize, usize, usize) {
    let mut asked = (0, 0, 0);
    for request in relay.requests() {
        let of = of_channels(std::slice::from_ref(&request));
        let here = of.iter().filter(|one| *one == channel).count();
        match request {
            WireMessage::ChannelProve(_) => asked.0 += here,
            WireMessage::EntryPull(_) => asked.1 += here,
            WireMessage::EntryPush(_) => asked.2 += here,
            _ => {}
        }
    }
    asked
}

/// Two devices of one person, each with sync on, each hold the messages
/// channel of their generation after a pass: the same channel, the last
/// that each goes through, which each has fetched whole from the relay
/// since it started.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_devices_of_one_person_each_hold_the_messages_channel_after_a_pass() {
    let relay = relay_started("relay", None);
    let (mut laptop, mut desktop) = (Device::new("laptop"), Device::new("desktop"));
    laptop.makes_the_phrase(&phrase());
    laptop.adds(&desktop);
    for device in [&mut laptop, &mut desktop] {
        device.holds("notes");
        device.syncs(true);
        device.connects("relay", &relay).await;
    }
    let messages = laptop.messages();
    assert_eq!(desktop.messages(), messages);
    let not_yet = std::time::Instant::now();
    for device in [&laptop, &desktop] {
        assert!(
            !device
                .state
                .own_channels
                .first_fetch_done(&messages, not_yet)
        );
    }

    all_pass(&[&laptop, &desktop], 2).await;
    for device in [&laptop, &desktop] {
        let own = at_relays::channels(&device.db(), &device.state.identity).unwrap();
        let last = own.last().unwrap();
        assert_eq!(
            (&last.kind, last.id),
            (&at_relays::Kind::Messages, messages)
        );
        let now = std::time::Instant::now();
        assert!(device.state.own_channels.first_fetch_done(&messages, now));
        assert!(!device.state.own_channels.no_place());
    }
    // Nothing of it was pushed: no device wrote in it.
    assert!(held_at(&relay, &messages).is_empty());
}

/// An entry that one device writes in a slot of its own in the messages
/// channel reaches the other through a relay: the relay holds it, as it
/// holds any entry of a channel from its secret, and the other device's
/// store takes it through the one door. One that a key which does not
/// count writes there is taken by neither.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_entry_in_the_messages_channel_reaches_the_other_device_through_a_relay() {
    let relay = relay_started("relay", None);
    let (mut laptop, mut desktop) = (Device::new("laptop"), Device::new("desktop"));
    laptop.makes_the_phrase(&phrase());
    laptop.adds(&desktop);
    for device in [&mut laptop, &mut desktop] {
        device.holds("notes");
        device.syncs(true);
        device.connects("relay", &relay).await;
    }
    all_pass(&[&laptop, &desktop], 2).await;
    let messages = laptop.messages();
    let channels_before = channels_at(&relay);

    let sent = laptop.writes_message(1, "notes", "the branch is ready to look at");
    assert_eq!(sent.channel, messages);
    laptop.sends().await;
    assert!(holds_at(&relay, &messages, &sent.id()));
    assert_eq!(channels_at(&relay), channels_before + 1);
    // Every entry of it is of one size at the relay.
    assert_eq!(sent.content.len(), 2048);

    desktop.passes().await;
    assert_eq!(desktop.holds_of(&messages), BTreeSet::from([sent.id()]));
    let secret = desktop.messages_secret();
    let held = entries::channel_entries_after(&desktop.db(), &messages, 0, 10).unwrap();
    let held = held[0].entry.clone().check().unwrap();
    let inside = held.open(&secret).unwrap();
    let taken = message::take(&inside.name, &laptop.key(), held.rev, &inside.value, |_| {
        true
    });
    match taken.unwrap() {
        message::Taken::Message { number, message } => {
            assert_eq!(number, 1);
            assert_eq!(message.body, "the branch is ready to look at");
        }
        other => panic!("{other:?}"),
    }

    // A key that does not count writes in the channel: the relay holds
    // it, and the desktop does not take it.
    let stranger = NodeIdentity::generate().unwrap();
    let name = message::message_name(&stranger.public_key(), 1).unwrap();
    let value = message::clearing_value();
    let theirs = sealed(
        &stranger,
        &laptop.messages_secret(),
        3,
        &name,
        Value::Other(value),
    );
    assert_eq!(
        pushed_by_hand(&laptop, "relay", &[&theirs]).await,
        [PushAnswer::Stored]
    );
    desktop.passes().await;
    assert!(!desktop.holds_of(&messages).contains(&theirs.id()));
    assert_eq!(desktop.holds_of(&messages).len(), 1);
}

/// What a device's pass gives the door, and so when its reader first
/// holds a message, is read from the node's clock, the one a test sets,
/// and so are the 30 days and the hourly task of messages (decision
/// 2026-10-09 §13): with desktop's clock set ten days behind the
/// system's, laptop's message is first held then, is shown until 30 days
/// after that and not at them, and the hourly task drops it then.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_is_first_held_shown_and_dropped_by_the_nodes_clock() {
    const DAY: i64 = 24 * 60 * 60;
    let relay = relay_started("relay", None);
    let (mut laptop, mut desktop) = (Device::new("laptop"), Device::new("desktop"));
    laptop.makes_the_phrase(&phrase());
    laptop.adds(&desktop);
    for device in [&mut laptop, &mut desktop] {
        device.holds("notes");
        device.syncs(true);
        device.connects("relay", &relay).await;
    }
    all_pass(&[&laptop, &desktop], 2).await;
    let set = laptop.now() - 10 * DAY;
    desktop.state.sync_control.set_now(Some(set));

    laptop.writes_message(1, "notes", "by the node's clock");
    laptop.sends().await;
    desktop.passes().await;
    let first_held: i64 = desktop
        .db()
        .query_row("SELECT first_held FROM message_first_held", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(first_held, set);

    let shown_at = |at: i64| -> usize {
        desktop.state.sync_control.set_now(Some(at));
        let now = desktop.state.sync_control.now();
        let db = desktop.db();
        cordelia_storage::messages::give_places(&db, &desktop.key(), now).unwrap();
        cordelia_storage::messages::shown(&db, now).unwrap().len()
    };
    let indexed = || -> i64 {
        desktop
            .db()
            .query_row("SELECT COUNT(*) FROM message_index", [], |row| row.get(0))
            .unwrap()
    };
    assert_eq!(shown_at(set + 30 * DAY - 1), 1);
    desktop.engine.messages_hourly();
    assert_eq!(indexed(), 1);
    assert_eq!(shown_at(set + 30 * DAY), 0);
    desktop.engine.messages_hourly();
    assert_eq!(indexed(), 0);
}

/// Where sync is off, the device neither proves, pulls nor pushes the
/// messages channel (decision 2026-10-09 §2.1, C12), though its store
/// holds an entry of it. With sync on, it does each.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_sync_off_the_messages_channel_is_neither_pushed_nor_pulled() {
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.writes_message(1, "notes", "written while sync was on");
    let messages = device.messages();
    device.connects_to("relay", relay.port, relay.key).await;

    device.syncs(false);
    device.passes().await;
    device.sends().await;
    let requests = relay.requests();
    assert!(!requests.is_empty());
    assert!(!of_channels(&requests).contains(&messages));
    assert!(
        !device
            .state
            .own_channels
            .first_fetch_done(&messages, std::time::Instant::now())
    );

    device.syncs(true);
    device.clock.run_ahead(Duration::from_secs(SHOW_LEAVE_SECS));
    device.passes().await;
    assert_eq!(asked_of(&relay, &messages), (1, 1, 1));
}

/// A whole pass that reads the messages channel to its end records that
/// the relay has handed it (decision 2026-10-09 §2.3): before that a
/// device writes nothing in it after it starts. A pull of it that does
/// not reach its end records nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pass_that_reads_the_messages_channel_to_its_end_records_its_first_fetch() {
    for to_its_end in [false, true] {
        let relay = StandIn::started().await;
        let mut device = Device::new("laptop");
        device.makes_the_phrase(&phrase());
        device.syncs(true);
        let messages = device.messages();
        let handed = device.writes_message(1, "notes", "a message").to_wire();
        // A relay that hands page after page of it, without end; or none.
        if !to_its_end {
            relay.pulls(move |pull| {
                let after = if pull.mark == [5; 8] { pull.after } else { 0 };
                let entries = match pull.channel == messages {
                    true => vec![handed.clone().into()],
                    false => Vec::new(),
                };
                EntryPulled {
                    entries,
                    next: after + 1,
                    mark: [5; 8],
                }
            });
        }
        device.connects_to("relay", relay.port, relay.key).await;
        let now = std::time::Instant::now();
        assert!(!device.state.own_channels.first_fetch_done(&messages, now));
        device.passes().await;
        let now = std::time::Instant::now();
        assert_eq!(
            device.state.own_channels.first_fetch_done(&messages, now),
            to_its_end
        );
    }
}

/// Past the limit on proofs a device has no messages, and says so
/// (decision 2026-10-09 §2.1, D13). Here a relay remembers the proofs of
/// three channels for one connection, and the personal channel and two
/// names come before the messages channel: it is not proved, pulled or
/// pushed, `no_place` is said, and the pass is not short. With room for
/// four it is proved, and nothing is said.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn past_the_limit_on_proofs_a_device_has_no_messages_and_says_so() {
    for (most_proved, no_place) in [(3, true), (4, false)] {
        let relay = StandIn::started().await;
        let mut device = Device::proving_at_most("laptop", most_proved);
        device.makes_the_phrase(&phrase());
        device.holds("notes");
        device.holds("lab");
        device.syncs(true);
        device.writes_message(1, "notes", "a message");
        let messages = device.messages();
        device.connects_to("relay", relay.port, relay.key).await;
        device.passes().await;
        let own = &device.state.own_channels;
        assert_eq!(own.no_place(), no_place, "{most_proved}");
        let asked = asked_of(&relay, &messages);
        match no_place {
            true => assert_eq!(asked, (0, 0, 0)),
            false => assert_eq!(asked, (1, 1, 1)),
        }
        assert_eq!(own.whole_passes().1, 1);
        assert_eq!(own.last_short_pass(), 0, "{most_proved}");

        // The device writes in the channel, and sends: past the limit the
        // relay is asked nothing of it in the pass that sends either.
        device.writes_message(2, "notes", "another message");
        device.sends().await;
        let asked = asked_of(&relay, &messages);
        match no_place {
            true => assert_eq!(asked, (0, 0, 0), "{most_proved}"),
            false => assert_eq!(asked, (0, 0, 1), "{most_proved}"),
        }
        assert_eq!(device.state.own_channels.no_place(), no_place);
    }
}

/// A filled messages channel makes no pass short (decision 2026-10-09
/// §2.1, §8, D13): a relay that holds more of it than one pass takes, one
/// that does not answer its proof, and one that answers it with what is no
/// answer to a proof, leave the pass whole, so a command
/// that waits for a fetch is not told that it ended early. The same of a
/// name's channel makes the pass short. What the commands then print is
/// for the record's real-process test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_filled_messages_channel_makes_no_pass_short() {
    let short = |device: &Device| device.state.own_channels.last_short_pass();
    // More than a pass takes: page after page, without end, of the
    // messages channel or of a name's.
    for of_messages in [true, false] {
        let relay = StandIn::started().await;
        let mut device = Device::new("laptop");
        device.makes_the_phrase(&phrase());
        device.holds("notes");
        device.syncs(true);
        let filled = match of_messages {
            true => device.messages(),
            false => device.channel("notes"),
        };
        let handed = match of_messages {
            true => device.writes_message(1, "notes", "a message"),
            false => device.writes("notes", "a.md", "a text"),
        };
        let handed = handed.to_wire();
        relay.pulls(move |pull| {
            let after = if pull.mark == [5; 8] { pull.after } else { 0 };
            let entries = match pull.channel == filled {
                true => vec![handed.clone().into()],
                false => Vec::new(),
            };
            EntryPulled {
                entries,
                next: after + 1,
                mark: [5; 8],
            }
        });
        device.connects_to("relay", relay.port, relay.key).await;
        device.passes().await;
        assert_eq!(
            asked_of(&relay, &filled).1,
            cordelia_core::protocol::RELAY_ENTRY_PULL_PAGES
        );
        assert_eq!(device.state.own_channels.whole_passes().1, 1);
        assert_eq!(short(&device), u64::from(!of_messages), "{of_messages}");
    }

    // A proof of the messages channel that is not answered.
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.syncs(true);
    let messages = device.messages();
    relay.hook(move |request| match request {
        WireMessage::ChannelProve(prove) if prove.channel == messages => Some(Say::Nothing),
        _ => None,
    });
    device.connects_to("relay", relay.port, relay.key).await;
    device.passes().await;
    assert_eq!(asked_of(&relay, &messages), (1, 0, 0));
    assert_eq!(device.state.own_channels.whole_passes().1, 1);
    assert_eq!(short(&device), 0);

    // A proof of the messages channel answered with what is no answer to
    // a proof: the channel is passed by, and the pass is not short.
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.syncs(true);
    let messages = device.messages();
    relay.hook(move |request| match request {
        WireMessage::ChannelProve(prove) if prove.channel == messages => {
            Some(Say::Answer(ShowAnswer::Held))
        }
        _ => None,
    });
    device.connects_to("relay", relay.port, relay.key).await;
    device.passes().await;
    assert_eq!(asked_of(&relay, &messages), (1, 0, 0));
    assert_eq!(device.state.own_channels.whole_passes().1, 1);
    assert_eq!(short(&device), 0);
}

/// A refusal for room of the messages channel, or for the address's
/// allowance of new channels, is said of no relay (decision 2026-10-09
/// §8): no refusal is said for the relay, and the messages channel is not
/// counted among what waits there, which are the facts a status reads. It
/// is sent again, as anything a relay refused is. The same refusal of a
/// name's entry is said. What the commands then print is for the record's
/// real-process test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_for_room_of_the_messages_channel_is_said_of_no_relay() {
    for refused in [EntryRefused::NoRoom, EntryRefused::OverLimit] {
        let relay = StandIn::started().await;
        let mut device = Device::new("laptop");
        device.makes_the_phrase(&phrase());
        device.holds("notes");
        device.syncs(true);
        let (messages, notes) = (device.messages(), device.channel("notes"));
        let refuses = Arc::new(AtomicBool::new(false));
        let notes_refused = refuses.clone();
        relay.pushes(move |entry| {
            let of_notes = entry.channel == notes && notes_refused.load(Ordering::SeqCst);
            match entry.channel == messages || of_notes {
                true => PushAnswer::Refused(refused),
                false => PushAnswer::Stored,
            }
        });
        device.connects_to("relay", relay.port, relay.key).await;
        device.passes().await;
        device.sends().await;
        let waits = || {
            let key = relay.key;
            cordelia_api::leaving::waits_at(&device.db(), &device.state.identity, &key).unwrap()
        };
        assert_eq!(waits(), 0);
        let before = device.at("relay");
        assert_eq!(before.no_room, None);

        device.writes_message(1, "notes", "a message");
        device.sends().await;
        assert_eq!(asked_of(&relay, &messages).2, 1, "{refused:?}");
        let after = device.at("relay");
        assert_eq!(after.no_room, None, "{refused:?}");
        assert_eq!(after, before);
        assert_eq!(waits(), 0, "{refused:?}");
        // It is sent again once the wait has gone by.
        device
            .clock
            .run_ahead(Duration::from_secs(OUTBOX_REFUSED_RETRY_MAX_SECS));
        device.sends().await;
        assert_eq!(asked_of(&relay, &messages).2, 1, "{refused:?}");

        // The control: a name's entry refused so is said.
        refuses.store(true, Ordering::SeqCst);
        device.writes("notes", "a.md", "a text");
        device.sends().await;
        assert!(device.at("relay").no_room.is_some(), "{refused:?}");
        assert_eq!(waits(), 1, "{refused:?}");
    }
}

/// A relay that answers that it holds another entry from the device at
/// the revision of an entry of the messages channel is not said to hold
/// one of the device's own in another form (decision 2026-10-09 §8, F7):
/// what `cordelia devices` prints of that relay is as it was. The same
/// answer to a name's entry is said.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_answered_another_is_not_said_in_another_form() {
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.syncs(true);
    let (messages, notes) = (device.messages(), device.channel("notes"));
    relay.pushes(
        move |entry| match entry.channel == messages || entry.channel == notes {
            true => PushAnswer::Another,
            false => PushAnswer::Stored,
        },
    );
    device.connects_to("relay", relay.port, relay.key).await;
    device.passes().await;
    device.sends().await;

    device.writes_message(1, "notes", "a message");
    device.sends().await;
    device.passes().await;
    assert_eq!(asked_of(&relay, &messages).2, 1);
    assert_eq!(device.at("relay").another_form, 0);

    device.writes("notes", "a.md", "a text");
    device.sends().await;
    device.passes().await;
    assert_eq!(device.at("relay").another_form, 1);
}

/// A pass that stops at the messages channel because the device came to
/// keep another change entry is short (decision 2026-10-09 §2.1, decision
/// 2026-10-04 §16): a statement was applied elsewhere in the middle of
/// it, here as the relay is asked the proof of the messages channel, and
/// the channels of the new generation were not read at this relay. The
/// control: where only that proof goes unanswered, the pass is not short.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pass_that_stops_at_the_messages_channel_after_a_statement_is_short() {
    for applied_elsewhere in [false, true] {
        let relay = StandIn::started().await;
        let mut device = Device::new("laptop");
        device.makes_the_phrase(&phrase());
        device.holds("notes");
        device.syncs(true);
        let messages = device.messages();
        let change = device.makes_change(&phrase(), &[&device], &[]);
        let (state, now) = (device.state.clone(), device.now());
        relay.hook(move |request| match request {
            WireMessage::ChannelProve(prove) if prove.channel == messages => {
                if !applied_elsewhere {
                    return Some(Say::Nothing);
                }
                let db = state.db.lock().unwrap();
                let outcome = shown(&db, &state.identity, &change, now).unwrap();
                assert!(matches!(outcome, Shown::Applied(_)), "{outcome:?}");
                None
            }
            _ => None,
        });
        device.connects_to("relay", relay.port, relay.key).await;
        device.passes().await;
        assert_eq!(asked_of(&relay, &messages), (1, 0, 0));
        assert_eq!(device.messages() != messages, applied_elsewhere);
        let own = &device.state.own_channels;
        assert_eq!(own.whole_passes().1, 1);
        assert_eq!(
            own.last_short_pass(),
            u64::from(applied_elsewhere),
            "{applied_elsewhere}"
        );
    }
}

/// What the device says of the place of the messages channel is the room
/// that `prove` finds for it on the connection (decision 2026-10-09
/// §2.1). Here a relay remembers the proofs of four channels for one,
/// and the device proved four with sync off: the personal channel and
/// three names. It holds one of those names no more, and sync is on: its
/// own channels, with the messages channel, are four, but the place of
/// the name it dropped is still taken on the connection. The messages
/// channel is not proved, and `no_place` is said. With room for five it
/// is proved, and nothing is said.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_place_taken_by_a_channel_held_no_more_leaves_the_messages_channel_none() {
    for (most_proved, no_place) in [(4, true), (5, false)] {
        let relay = StandIn::started().await;
        let mut device = Device::proving_at_most("laptop", most_proved);
        device.makes_the_phrase(&phrase());
        for name in ["lab", "notes", "old"] {
            device.holds(name);
        }
        device.connects_to("relay", relay.port, relay.key).await;
        device.passes().await;
        assert_eq!(device.counts("relay").proofs, 4);

        held_rows::drop_name(&device.db(), "old").unwrap();
        device.syncs(true);
        let own = at_relays::channels(&device.db(), &device.state.identity).unwrap();
        assert_eq!(own.len(), 4);
        let messages = device.messages();
        relay.requests();
        device.clock.run_ahead(Duration::from_secs(SHOW_LEAVE_SECS));
        device.passes().await;
        let proved = usize::from(!no_place);
        assert_eq!(asked_of(&relay, &messages), (proved, proved, 0));
        let own = &device.state.own_channels;
        assert_eq!(own.no_place(), no_place, "{most_proved}");
        assert_eq!(own.last_short_pass(), 0, "{most_proved}");
    }
}

/// The messages channel of the generation that the device stands applied
/// under is not read through the door for a carry (decision 2026-10-09
/// §2.1), with sync off as with it on: the relay is asked nothing. The
/// control: a channel of a generation that was left is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_messages_channel_is_not_read_through_the_door_for_a_carry() {
    let relay = StandIn::started().await;
    let mut device = Device::new("laptop");
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.connects_to("relay", relay.port, relay.key).await;
    device.passes().await;
    let (old, old_secret) = (device.personal(), device.personal_secret());
    device.changes(&phrase(), &[&device], &[]);
    device.passes().await;
    relay.requests();

    let by = |secret: [u8; 32]| ProvedBy::Secret(zeroize::Zeroizing::new(secret));
    for sync in [false, true] {
        device.syncs(sync);
        let read = reads_left(&device, device.messages(), by(device.messages_secret())).await;
        assert!(
            matches!(&read[0].read, LeftRead::NotRead(why) if why.contains("this device's own")),
            "{sync}: {read:?}"
        );
        assert!(relay.requests().is_empty(), "{sync}");

        // The control.
        let read = reads_left(&device, old, by(old_secret)).await;
        assert!(
            !matches!(&read[0].read, LeftRead::NotRead(_)),
            "{sync}: {read:?}"
        );
        assert!(!relay.requests().is_empty(), "{sync}");
    }
}

/// What the device says of the place of the messages channel is said
/// afresh as every pass ends (decision 2026-10-09 §2.1): past the limit
/// on proofs it is said; with no relay connected it is said no more; on a
/// connection made again it is said again; and a device that has stopped,
/// and makes no pass at a relay, has no messages channel, and says
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_word_that_the_messages_channel_has_no_place_is_said_afresh() {
    let relay = StandIn::started().await;
    let mut device = Device::proving_at_most("laptop", 3);
    device.makes_the_phrase(&phrase());
    device.holds("notes");
    device.holds("lab");
    device.syncs(true);
    let no_place = |device: &Device| device.state.own_channels.no_place();
    device.connects_to("relay", relay.port, relay.key).await;
    device.passes().await;
    assert!(no_place(&device));

    device.disconnects("relay");
    device.passes().await;
    assert!(!no_place(&device));

    device.connects_to("relay", relay.port, relay.key).await;
    device.passes().await;
    assert!(no_place(&device));

    held_rows::set_state(&device.db(), State::Removed).unwrap();
    device.passes().await;
    device.sends().await;
    assert!(!no_place(&device));
}

// ── The sender of messages, across a relay ───────────────────────────

/// Laptop and desktop of one person, each saying that it syncs `notes`
/// and `work`, with sync on, each connected to `relay` and having passed
/// twice: each has fetched the messages channel.
async fn two_that_message(relay: &Node) -> (Device, Device) {
    let (mut laptop, mut desktop) = (Device::new("laptop"), Device::new("desktop"));
    laptop.makes_the_phrase(&phrase());
    laptop.adds(&desktop);
    for device in [&mut laptop, &mut desktop] {
        device.holds("notes");
        device.syncs(true);
        device.says_it_syncs("notes");
        device.says_it_syncs("work");
        device.connects("relay", relay).await;
    }
    all_pass(&[&laptop, &desktop], 2).await;
    (laptop, desktop)
}

/// A message that the sender writes reaches the other device through a
/// relay, and is shown there; the sender keeps its value only until
/// every relay it is set up with has taken it (decision 2026-10-09 §2.3).
/// Before the first fetch nothing is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_sent_reaches_the_other_device_and_is_kept_until_every_relay_took_it() {
    let relay = relay_started("relay", None);
    let fresh = Device::new("fresh");
    fresh.makes_the_phrase(&phrase());
    fresh.syncs(true);
    assert!(matches!(
        fresh.sends_message("notes", message::To::All, "too soon"),
        Err(NotSent::Refused(sender::Refused::NotFetched))
    ));

    let (laptop, desktop) = two_that_message(&relay).await;
    let sent = laptop
        .sends_message(
            "notes",
            message::To::Name("work".into()),
            "the branch is ready",
        )
        .unwrap();
    assert_eq!(sent.number, 1);
    assert_eq!(laptop.keeps_message(&sent.id), Some(vec![1]));
    laptop.sends().await;
    assert_eq!(laptop.keeps_message(&sent.id), None);
    desktop.passes().await;
    assert_eq!(desktop.shows_messages(), ["the branch is ready"]);
}

/// The device's store goes back to before a message it sent; offline,
/// after its first fetch, it sends again at that number. The relay holds
/// the other entry at that revision, and answers so: the message is
/// written again under the next number in that pass, and reaches the
/// other device, which shows both messages once each (decision 2026-10-09
/// §2.3, case 1, §11 "A device restored from a backup").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_sent_offline_after_a_first_fetch_reaches_the_other_device_under_a_new_number() {
    let relay = relay_started("relay", None);
    let (mut laptop, desktop) = two_that_message(&relay).await;
    let to_work = || message::To::Name("work".into());
    laptop.sends_message("notes", to_work(), "one").unwrap();
    laptop.sends().await;
    let dir = tempfile::tempdir().unwrap();
    let backup = dir.path().join("laptop.db");
    laptop
        .db()
        .execute("VACUUM INTO ?1", [backup.to_str().unwrap()])
        .unwrap();
    laptop
        .sends_message("notes", to_work(), "two, in a life forgotten")
        .unwrap();
    laptop.sends().await;

    *laptop.db() = cordelia_storage::db::open(&backup).unwrap();
    laptop.disconnects("relay");
    let sent = laptop
        .sends_message("notes", to_work(), "two, again")
        .unwrap();
    assert_eq!(sent.number, 2);
    laptop.connects("relay", &relay).await;
    laptop.passes().await;
    assert_eq!(laptop.keeps_message(&sent.id), None);
    let messages = laptop.messages();
    let revs: Vec<u64> = held_at(&relay, &messages)
        .iter()
        .filter(|entry| entry.author == laptop.key())
        .map(|entry| entry.rev)
        .collect();
    assert_eq!(BTreeSet::from_iter(revs), BTreeSet::from([2, 4, 6]));

    desktop.passes().await;
    let mut shown = desktop.shows_messages();
    shown.sort();
    assert_eq!(shown, ["one", "two, again", "two, in a life forgotten"]);
}

/// A relay that answers another to a message has it written again under
/// the next number in the same pass, and pushed there; one that answers
/// a higher revision is not written again (decision 2026-10-09 §2.3,
/// F6): the push answers are read as the record says.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relays_answer_to_a_message_is_read_for_sending_again() {
    for (answer, written) in [(PushAnswer::Another, true), (PushAnswer::Older, false)] {
        let relay = StandIn::started().await;
        relay.holds_what_is_proved(true);
        let mut device = Device::new("laptop");
        device.makes_the_phrase(&phrase());
        device.syncs(true);
        device.says_it_syncs("notes");
        let messages = device.messages();
        let first = Arc::new(AtomicBool::new(true));
        let once = first.clone();
        relay.pushes(move |entry| {
            let is_first_message = entry.channel == messages && entry.rev == 2;
            match is_first_message && once.swap(false, Ordering::SeqCst) {
                true => answer,
                false => PushAnswer::Stored,
            }
        });
        device.connects_to("relay", relay.port, relay.key).await;
        device.passes().await;
        let sent = device
            .sends_message("notes", message::To::All, "a message")
            .unwrap();
        relay.requests();
        device.passes().await;
        let pushed: Vec<u64> = relay
            .requests()
            .iter()
            .filter_map(|request| match request {
                WireMessage::EntryPush(push) => Some(push.entries.clone()),
                _ => None,
            })
            .flatten()
            .map(|bytes| Entry::from_wire(&bytes).unwrap())
            .filter(|entry| entry.channel == messages)
            .map(|entry| entry.rev)
            .collect();
        match written {
            true => {
                assert_eq!(pushed, [2, 4], "{answer:?}");
                assert_eq!(device.keeps_message(&sent.id), None);
            }
            false => {
                assert_eq!(pushed, [2], "{answer:?}");
                assert_eq!(device.keeps_message(&sent.id), Some(vec![1]));
            }
        }
    }
}

/// 30 days after a message was sent, its sender's hourly task writes the
/// entry that clears it, once the messages channel was fetched; the
/// relay takes it, and the other device that pulls it drops the message
/// (decision 2026-10-09 §2.3, §7.1, property 12).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_cleared_by_its_sender_leaves_the_other_devices_index() {
    let relay = relay_started("relay", None);
    let (laptop, desktop) = two_that_message(&relay).await;
    laptop
        .sends_message("notes", message::To::All, "for a month")
        .unwrap();
    laptop.sends().await;
    desktop.passes().await;
    assert_eq!(desktop.shows_messages(), ["for a month"]);

    laptop
        .clock
        .run_ahead(Duration::from_secs(30 * 24 * 60 * 60));
    laptop.engine.messages_hourly();
    let messages = laptop.messages();
    laptop.sends().await;
    let revs: Vec<u64> = held_at(&relay, &messages)
        .iter()
        .filter(|entry| entry.author == laptop.key())
        .map(|entry| entry.rev)
        .collect();
    assert_eq!(revs, [3]);
    desktop.passes().await;
    let rows: i64 = desktop
        .db()
        .query_row("SELECT COUNT(*) FROM message_index", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 0);
}

// ── What an agent read, across a relay (decision 2026-10-09 §7.2) ────

/// A mark made on one device reaches the other through a relay: the
/// desktop's agent of `work` reads a message, its list is pushed, the
/// relay holds it in the desktop's slot `read/<its key>`, and the laptop
/// keeps it as the desktop's latest list.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mark_made_on_one_device_reaches_the_other_through_a_relay() {
    let relay = relay_started("relay", None);
    let (laptop, desktop) = two_that_message(&relay).await;
    let to_work = message::To::Name("work".into());
    let sent = laptop.sends_message("notes", to_work, "a request").unwrap();
    laptop.sends().await;
    desktop.passes().await;
    let marked = desktop.reads_message("work", &sent.id);
    assert_eq!(
        marked,
        marks::Marked {
            marked: true,
            list: Some(1)
        }
    );
    desktop.sends().await;
    let mark = message::read_mark(&sent.id, "work");
    let at_relay = desktop.list_in(&held_at(&relay, &laptop.messages()));
    assert_eq!(at_relay, Some((1, vec![mark])));

    laptop.passes().await;
    let kept: Vec<(Vec<u8>, Vec<u8>)> = laptop
        .db()
        .prepare("SELECT key, mark FROM message_lists")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(kept, [(desktop.key().to_vec(), mark.to_vec())]);
}

/// A message that an agent of a name read on one device is not counted
/// unread for that name on the other, once the other has its list
/// (decision 2026-10-09 §7.2): the laptop's agent of `work` is shown the
/// laptop's own message from `notes` as unread until the desktop's agent
/// of `work` reads it and the laptop takes the desktop's list; it is still
/// unread for `notes` on the desktop, which no agent of that name read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_read_on_one_device_is_not_counted_unread_on_the_other() {
    let relay = relay_started("relay", None);
    let (laptop, desktop) = two_that_message(&relay).await;
    let sent = laptop
        .sends_message("notes", message::To::All, "for every agent")
        .unwrap();
    laptop.sends().await;
    desktop.passes().await;
    assert_eq!(laptop.unread_by("work"), ["for every agent"]);
    assert!(desktop.reads_message("work", &sent.id).marked);
    desktop.sends().await;
    assert_eq!(laptop.unread_by("work"), ["for every agent"]);

    laptop.passes().await;
    assert_eq!(laptop.unread_by("work"), Vec::<String>::new());
    assert_eq!(desktop.unread_by("work"), Vec::<String>::new());
    assert_eq!(desktop.unread_by("notes"), ["for every agent"]);
    let read_on = marks::read_on(&laptop.db(), &sent.id, "work").unwrap();
    assert_eq!(read_on.devices, [desktop.key()]);
}

/// A store restored from before a read takes its own later list back from
/// the relay, and the list it writes next holds both lives' marks, above
/// the relay's (decision 2026-10-09 §2.4, §7.2, §11): after the restore,
/// which is a start, an agent reads before the first fetch and nothing is
/// written; the pass pulls the later list, merges it, and writes the next.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restored_device_merges_its_later_list_from_a_relay_and_writes_above_it() {
    let relay = relay_started("relay", None);
    let (laptop, desktop) = two_that_message(&relay).await;
    let to_work = || message::To::Name("work".into());
    let first = laptop.sends_message("notes", to_work(), "first").unwrap();
    let second = laptop.sends_message("notes", to_work(), "second").unwrap();
    laptop.sends().await;
    desktop.passes().await;
    let dir = tempfile::tempdir().unwrap();
    let backup = dir.path().join("desktop.db");
    desktop
        .db()
        .execute("VACUUM INTO ?1", [backup.to_str().unwrap()])
        .unwrap();
    assert_eq!(desktop.reads_message("work", &first.id).list, Some(1));
    desktop.sends().await;

    *desktop.db() = cordelia_storage::db::open(&backup).unwrap();
    let messages = desktop.messages();
    desktop.state.own_channels.forget_fetched(&messages);
    assert_eq!(desktop.reads_message("work", &second.id).list, None);
    desktop.passes().await;
    let both = vec![
        message::read_mark(&second.id, "work"),
        message::read_mark(&first.id, "work"),
    ];
    assert_eq!(
        desktop.list_in(&held_at(&relay, &messages)),
        Some((2, both))
    );
    laptop.passes().await;
    assert_eq!(laptop.unread_by("work"), Vec::<String>::new());
}

/// After a statement, the first list in the new generation is written by
/// the pass once the new messages channel is fetched, and holds the marks
/// of what is still shown (decision 2026-10-09 §2.4, §9.1, F8): the
/// desktop's agent read a message before a renewal; the laptop keeps the
/// desktop's list across it, and takes the new one from the new channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_list_after_a_statement_is_written_by_the_pass_in_the_new_channel() {
    let relay = relay_started("relay", None);
    let (laptop, desktop) = two_that_message(&relay).await;
    let sent = laptop
        .sends_message("notes", message::To::All, "before the renewal")
        .unwrap();
    laptop.sends().await;
    desktop.passes().await;
    desktop.reads_message("work", &sent.id);
    desktop.sends().await;
    laptop.passes().await;
    let old = laptop.messages();

    laptop.changes(&phrase(), &[&laptop, &desktop], &[]);
    all_pass(&[&laptop, &desktop], 3).await;
    let messages = desktop.messages();
    assert_eq!(laptop.messages(), messages);
    assert_ne!(messages, old);
    assert_eq!(laptop.unread_by("work"), Vec::<String>::new());
    let mark = message::read_mark(&sent.id, "work");
    assert_eq!(
        desktop.list_in(&held_at(&relay, &messages)),
        Some((1, vec![mark]))
    );
    // The laptop took the new list from the new channel.
    let list = held_at(&relay, &messages)
        .into_iter()
        .find(|entry| entry.author == desktop.key() && entry.slot == desktop.list_slot())
        .unwrap();
    assert!(laptop.holds_of(&messages).contains(&list.id()));
    laptop
        .db()
        .execute("DELETE FROM message_lists", [])
        .unwrap();
    assert_eq!(laptop.unread_by("work"), ["before the renewal"]);
}

/// A relay that answers that it holds another list of the device's at the
/// revision pushed has the list written again above it, and pushed; one
/// that answers that it holds a later one has nothing written (decision
/// 2026-10-09 §2.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_that_a_relay_holds_another_of_is_written_again_above_it() {
    for (answer, revs) in [
        (PushAnswer::Another, vec![1, 2]),
        (PushAnswer::Older, vec![1]),
    ] {
        let relay = StandIn::started().await;
        relay.holds_what_is_proved(true);
        let mut device = Device::new("laptop");
        device.makes_the_phrase(&phrase());
        device.syncs(true);
        device.says_it_syncs("notes");
        device.says_it_syncs("work");
        let slot = device.list_slot();
        let first = Arc::new(AtomicBool::new(true));
        let once = first.clone();
        relay.pushes(
            move |entry| match entry.slot == slot && once.swap(false, Ordering::SeqCst) {
                true => answer,
                false => PushAnswer::Stored,
            },
        );
        device.connects_to("relay", relay.port, relay.key).await;
        device.passes().await;
        let to_work = message::To::Name("work".into());
        let sent = device.sends_message("notes", to_work, "a request").unwrap();
        assert_eq!(device.reads_message("work", &sent.id).list, Some(1));
        relay.requests();
        device.passes().await;
        device.passes().await;
        let pushed: Vec<u64> = relay
            .requests()
            .iter()
            .filter_map(|request| match request {
                WireMessage::EntryPush(push) => Some(push.entries.clone()),
                _ => None,
            })
            .flatten()
            .map(|bytes| Entry::from_wire(&bytes).unwrap())
            .filter(|entry| entry.slot == slot)
            .map(|entry| entry.rev)
            .collect();
        assert_eq!(pushed, revs, "{answer:?}");
    }
}
