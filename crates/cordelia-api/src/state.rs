//! Shared application state for actix-web handlers.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use cordelia_crypto::identity::NodeIdentity;
use rusqlite::Connection;

use crate::publish::PlannedAgainst;

/// An item to be pushed to hot peers via P2P.
#[derive(Debug, Clone)]
pub struct PushItem {
    pub channel_id: String,
    pub item_id: String,
    pub encrypted_blob: Vec<u8>,
    pub content_hash: Vec<u8>,
    pub author_id: Vec<u8>,
    pub signature: Vec<u8>,
    pub key_version: u32,
    pub published_at: String,
    pub item_type: String,
    pub is_tombstone: bool,
    pub parent_id: Option<String>,
    /// Replaceable-item slot and revision (decision 2026-09-30 §4.3).
    pub slot: Option<Vec<u8>>,
    pub rev: Option<u64>,
    /// If set, don't push back to this peer (relay re-push loop prevention).
    pub exclude_peer: Option<cordelia_core::NodeId>,
}

/// Shared state accessible from all request handlers.
pub struct AppState {
    pub db: Mutex<Connection>,
    pub identity: NodeIdentity,
    pub bearer_token: String,
    pub home_dir: PathBuf,
    /// Instant when the node was started (for uptime).
    pub started_at: Instant,
    /// Cumulative sync errors (Phase 2+, incremented by replication).
    pub sync_errors: AtomicU64,
    /// Number of peers in Hot state (updated by governor tick).
    pub peers_hot: AtomicU64,
    /// Number of peers in Warm state (updated by governor tick).
    pub peers_warm: AtomicU64,
    /// Channel for sending items to the P2P layer for push delivery.
    /// None if P2P is not running (e.g., in tests).
    pub push_tx: Option<tokio::sync::mpsc::UnboundedSender<PushItem>>,
    /// Channel for notifying P2P layer of local channel subscriptions.
    /// Triggers channel-announce (0x04) to hot peers.
    /// None if P2P is not running (e.g., in tests).
    pub announce_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    /// The peers this node is connected to, refreshed on each governor tick.
    pub peers: std::sync::RwLock<Vec<PeerSnapshot>>,
    /// The relays this node was configured with and whether each is
    /// connected, refreshed by the P2P loop.
    pub relays: std::sync::RwLock<Vec<RelaySnapshot>>,
    /// Items written here that a relay refused to store, refreshed by the
    /// P2P loop. They stay in the outbox and are offered again.
    pub outbox_refused: std::sync::RwLock<Vec<RefusedSnapshot>>,
    /// Channels whose members have changed since the P2P loop last looked.
    /// A device stores only what a channel's members wrote, so entries by
    /// a member it had not heard of yet were refused; the loop lists these
    /// channels again from the start, and fetches what it lacks.
    pub relist: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Tells the sync adapter when its settings change.
    pub sync_control: SyncControl,
    /// Local history, and the turn its users take.
    pub history: History,
    /// Where this device stands at its relays for the channels of its
    /// own, as the node last said it, and the word that something was
    /// written in one.
    pub own_channels: OwnChannels,
    /// Whether the node is held up, and why.
    pub held: HeldUp,
}

/// Why a node is held up (decision 2026-10-04 §10.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Held {
    /// Its first start on this version has not succeeded: the copy could
    /// not be made, or the step failed. It is tried again each time a
    /// cycle would have run. It says why, in words for a person.
    FirstStart(String),
    /// Its database is from a later version than its own: the node runs
    /// over a database of its own in memory, and nothing of the one on
    /// disk is read or changed, for as long as the node runs. It says
    /// so, with both versions.
    LaterDatabase(String),
}

impl Held {
    /// Why the node is held up, in words for a person.
    pub fn says(&self) -> &str {
        match self {
            Held::FirstStart(why) | Held::LaterDatabase(why) => why,
        }
    }

    /// What it is held up by, as a status names it.
    pub fn kind(&self) -> &'static str {
        match self {
            Held::FirstStart(_) => "first_start",
            Held::LaterDatabase(_) => "later_database",
        }
    }
}

/// Whether a node is held up, and why (decision 2026-10-04 §10.1).
///
/// A node that is held up does not stop: under a service that restarts
/// what stops, stopping would be a loop, and a stopped node can say
/// nothing. It stays up, and says why.
///
/// It is kept in memory: a step that fails because the database cannot
/// be written has nowhere else to put it.
///
/// With it is what one start of the node keeps of its first start on this
/// version: what its tries keep between them, and how many key files of
/// an older version were left in place.
#[derive(Default)]
pub struct HeldUp {
    why: Mutex<Option<Held>>,
    tries: Mutex<crate::first_start::Tries>,
    key_files_in_place: std::sync::atomic::AtomicUsize,
}

impl HeldUp {
    /// What the tries at the first start keep between them. One try is
    /// made at a time: the next waits here for it.
    pub fn tries(&self) -> std::sync::MutexGuard<'_, crate::first_start::Tries> {
        self.tries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// How many key files of an older version were left in place at this
    /// start, since no copy holds them (decision 2026-10-04 §10.1).
    pub fn key_files_in_place(&self) -> usize {
        self.key_files_in_place.load(Ordering::Relaxed)
    }

    /// Note how many key files of an older version were left in place.
    pub fn set_key_files_in_place(&self, files: usize) {
        self.key_files_in_place.store(files, Ordering::Relaxed);
    }

    /// Why the node is held up, where it is.
    pub fn why(&self) -> Option<Held> {
        self.why.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The node is held up, by `why`.
    pub fn hold(&self, why: Held) {
        *self.why.lock().unwrap_or_else(|e| e.into_inner()) = Some(why);
    }

    /// The node is held up no longer.
    pub fn release(&self) {
        *self.why.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// What a status will read of a device's side of its relays, for the
/// channels of its own (decision 2026-10-04 §4.6, §8).
///
/// The node says it as it goes ([`OwnChannels::say`]), and [`OwnChannels::
/// read`] is the one function that reads it. It is in memory: a node that
/// starts has heard from no relay.
///
/// It also carries the word that something was written in a channel of
/// the device's own ([`OwnChannels::written`]), for which the node sends
/// what waits without waiting for its timer.
///
/// And it carries a command's asking for a whole pass
/// ([`OwnChannels::ask_whole`]): a command that prepares a change has the
/// device show its change entry to each relay and fetch its channels
/// first (decision 2026-10-04 §7.1, step 1), and waits for a pass that
/// began after it asked ([`OwnChannels::whole_passes`]).
///
/// And it carries how many relays the node is configured with
/// ([`OwnChannels::set_up_with`]). The node says it from the list that
/// each pass is given, which is every relay of its configuration, whether
/// or not its name resolves. What a device keeps of a relay is forgotten
/// as of one that it is set up with no longer only while every relay it
/// is configured with is connected.
///
/// And it carries which relays have handed the whole of each name's
/// channel since the node started ([`OwnChannels::fetched_from`]): a
/// folder with no record in a channel yet waits for that before its
/// first cycle there ([`OwnChannels::first_fetch_done`], decision
/// 2026-10-04 §6).
///
/// And it carries since when each relay has been connected, and since
/// when none has, by the node's own clock ([`OwnChannels::
/// relays_connected`]): what a status says of a device that is offline,
/// and of a relay that does not hold the latest change (decision
/// 2026-10-04 §10.1).
///
/// And it carries what a command's work asks through the door for a
/// carry ([`OwnChannels::ask_door`], decision 2026-10-04 §7.3, §9): a
/// channel of a generation that the device has left, or never followed,
/// read at each relay. The node takes each asking up and answers it.
/// And which channels a carry is being made into, before a folder's
/// first cycle there ([`OwnChannels::carrying`]).
#[derive(Default)]
pub struct OwnChannels {
    said: Mutex<AtRelays>,
    /// How many relays the node is configured with, and one more: 0
    /// where it has not said.
    set_up_with: AtomicU64,
    written: tokio::sync::Notify,
    asked: tokio::sync::Notify,
    /// How many whole passes the node has begun, and the number of the
    /// last that it ended.
    begun: AtomicU64,
    ended: AtomicU64,
    /// The number of the last whole pass that ended before it had read
    /// every channel to its end at every relay it reached.
    short: AtomicU64,
    /// For each channel of a name, by its ID: the relays that have handed
    /// the whole of it, and when the first of them had.
    fetched: Mutex<std::collections::HashMap<[u8; 32], FirstFetch>>,
    /// Since when each relay has been connected, and since when none has.
    connected: Mutex<Connected>,
    /// What was asked through the door for a carry, and is not taken up
    /// yet.
    door: Mutex<std::collections::VecDeque<DoorAsk>>,
    door_asked: tokio::sync::Notify,
    /// The channels that a carry is being made into, each with when that
    /// began.
    carrying: Mutex<std::collections::HashMap<[u8; 32], Instant>>,
    /// What was last read at the relays for a command, with what that
    /// reading is named by: kept until the command has been handed it.
    shelf: Mutex<(u64, Vec<Vec<u8>>)>,
    /// How far the look of a recovery is, and what it found, where this
    /// node has made one since it started (decision 2026-10-04 §9).
    look: Mutex<Option<serde_json::Value>>,
}

/// How a channel's key is proved to a relay, through the door for a carry.
pub enum ProvedBy {
    /// The node holds the channel's secret: it makes the proof for each
    /// connection itself. The secret is of a generation that the device
    /// left, or was handed at a recovery (decision 2026-10-04 §3, §9).
    Secret(zeroize::Zeroizing<[u8; 32]>),
    /// The proofs were made by whoever holds the channel's secret, one
    /// for each relay by its name: the command that was typed the phrase,
    /// in its own process, over the value of each connection's session
    /// ([`DoorAsk::Sessions`]). The node is handed no secret.
    Proofs(Vec<(String, [u8; 64])>),
}

/// What one relay handed through the door for a carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeftRead {
    /// The node is not connected to the relay.
    NotReached,
    /// The relay does not hold the channel, or the proof did not hold
    /// there: a relay says neither which.
    NotHeld,
    /// Nothing was read, and why.
    NotRead(String),
    /// What it handed of the channel, each entry as its bytes on the
    /// wire, and whether the channel was read to its end.
    Read { entries: Vec<Vec<u8>>, whole: bool },
}

/// A relay that the device is set up with, by its name, with what it
/// handed through the door for a carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftAt {
    pub relay: String,
    pub read: LeftRead,
}

/// What a command's work asks of the node through the door for a carry
/// (decision 2026-10-04 §7.3, §9).
pub enum DoorAsk {
    /// Each relay that the device is set up with, by its name, with the
    /// value of the session of the connection to it, where there is one:
    /// what a proof for that connection is made over.
    Sessions {
        answer: tokio::sync::oneshot::Sender<Vec<(String, Option<[u8; 32]>)>>,
    },
    /// Read the channel whose ID is `channel` at each relay, until
    /// `until`: it is of a generation that the device has left, or never
    /// followed.
    Read {
        channel: [u8; 32],
        by: ProvedBy,
        until: Instant,
        answer: tokio::sync::oneshot::Sender<Vec<LeftAt>>,
    },
}

/// How long a channel that a carry is being made into holds back a
/// folder's first cycle there, at most: a carry that never says it has
/// ended holds nothing up for longer.
const CARRYING_WAIT: std::time::Duration =
    std::time::Duration::from_secs(cordelia_core::protocol::CARRY_FIRST_MAX_SECS);

/// Since when the node's relays have been connected, by the node's own
/// clock.
#[derive(Debug, Default)]
struct Connected {
    /// Each relay that is connected, by its name, with since when.
    since: std::collections::HashMap<String, Instant>,
    /// Since when no relay has been connected: `None` while one is, and
    /// before the node has said.
    none_since: Option<Instant>,
}

/// Which relays have handed the whole of one channel, by name, and when
/// the first of them had.
#[derive(Debug, Clone)]
struct FirstFetch {
    first: Instant,
    from: std::collections::BTreeSet<String>,
}

/// How long a folder's first cycle waits for the other relays once one
/// has handed its channel.
const FIRST_FETCH_WAIT: std::time::Duration =
    std::time::Duration::from_secs(cordelia_core::protocol::FIRST_FETCH_WAIT_SECS);

impl OwnChannels {
    /// Where the device stands at its relays, as the node last said it.
    pub fn read(&self) -> AtRelays {
        self.said.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The node says where the device stands at its relays now.
    pub fn say(&self, now: AtRelays) {
        *self.said.lock().unwrap_or_else(|e| e.into_inner()) = now;
    }

    /// The node is configured with `relays` relays, whether or not it
    /// reaches each.
    pub fn set_up_with(&self, relays: usize) {
        self.set_up_with.store(relays as u64 + 1, Ordering::SeqCst);
    }

    /// How many relays the node is configured with, where it has said.
    pub fn relays_set_up(&self) -> Option<usize> {
        let said = self.set_up_with.load(Ordering::SeqCst);
        said.checked_sub(1).map(|relays| relays as usize)
    }

    /// Something was written in a channel of the device's own: the node
    /// sends what waits. One word is kept where the node is not waiting
    /// for one, and no more than one.
    pub fn written(&self) {
        self.written.notify_one();
    }

    /// Wait for the word that something was written.
    pub async fn wait_written(&self) {
        self.written.notified().await;
    }

    /// A command asks for a whole pass now: the show on every connection,
    /// and then the proving, pulling and pushing that its answers give
    /// leave for. One asking is kept where the node is not waiting for
    /// one, and no more than one. A pass that finds another running does
    /// nothing, so whoever asks goes on asking until a pass that began
    /// after it asked has ended.
    pub fn ask_whole(&self) {
        self.asked.notify_one();
    }

    /// Wait for a command to ask for a whole pass.
    pub async fn wait_asked(&self) {
        self.asked.notified().await;
    }

    /// A command's work asks something through the door for a carry: the
    /// node takes it up, and answers on the asking's own channel.
    pub fn ask_door(&self, ask: DoorAsk) {
        self.door
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(ask);
        self.door_asked.notify_one();
    }

    /// Wait for something to be asked through the door for a carry, and
    /// take it up: each asking is taken up once.
    pub async fn wait_door(&self) -> DoorAsk {
        loop {
            let asked = self
                .door
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pop_front();
            if let Some(asked) = asked {
                return asked;
            }
            self.door_asked.notified().await;
        }
    }

    /// A carry is being made into the channel whose ID is `channel`, from
    /// `now`: a folder with no record in it yet waits for the carry
    /// before its first cycle there ([`Self::first_fetch_done`]).
    pub fn carrying(&self, channel: &[u8; 32], now: Instant) {
        let mut carrying = self.carrying.lock().unwrap_or_else(|e| e.into_inner());
        carrying.insert(*channel, now);
    }

    /// The carry into the channel whose ID is `channel` has ended.
    pub fn carried(&self, channel: &[u8; 32]) {
        let mut carrying = self.carrying.lock().unwrap_or_else(|e| e.into_inner());
        carrying.remove(channel);
    }

    /// Whether a carry is being made into the channel at `now`: one
    /// began, has not said that it ended, and its wait has not gone by.
    fn is_carrying(&self, channel: &[u8; 32], now: Instant) -> bool {
        let carrying = self.carrying.lock().unwrap_or_else(|e| e.into_inner());
        carrying
            .get(channel)
            .is_some_and(|began| now.saturating_duration_since(*began) < CARRYING_WAIT)
    }

    /// Keep how far the look of a recovery is, or what it found (decision
    /// 2026-10-04 §9, step 5), for the command that waits for it. It is
    /// kept in memory alone: a look that is interrupted is not taken up
    /// again by itself, and a node that starts again says nothing of one.
    pub fn set_look(&self, said: serde_json::Value) {
        *self.look.lock().unwrap_or_else(|e| e.into_inner()) = Some(said);
    }

    /// What was last kept of the look of a recovery ([`Self::set_look`]).
    pub fn look(&self) -> Option<serde_json::Value> {
        self.look.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Keep `entries`, which were read at the relays for a command that
    /// holds a secret the node does not (decision 2026-10-04 §7.3, §9),
    /// until the command has been handed them, a part at a time
    /// ([`Self::shelved`]). What was kept of an earlier reading goes.
    /// Returns what this reading is named by.
    pub fn shelve(&self, entries: Vec<Vec<u8>>) -> u64 {
        let mut shelf = self.shelf.lock().unwrap_or_else(|e| e.into_inner());
        shelf.0 += 1;
        shelf.1 = entries;
        shelf.0
    }

    /// A part of the reading named `id`, from the entry numbered `from`
    /// on: as many entries as hold `max_bytes` between them, and one at
    /// least; and where the next part begins, where there is one. `None`
    /// where that reading is kept no longer. **Once its last part is
    /// handed, nothing is kept of it.**
    pub fn shelved(
        &self,
        id: u64,
        from: usize,
        max_bytes: usize,
    ) -> Option<(Vec<Vec<u8>>, Option<usize>)> {
        let mut shelf = self.shelf.lock().unwrap_or_else(|e| e.into_inner());
        if shelf.0 != id || from > shelf.1.len() {
            return None;
        }
        let mut part: Vec<Vec<u8>> = Vec::new();
        let mut bytes = 0;
        for entry in &shelf.1[from..] {
            if !part.is_empty() && bytes + entry.len() > max_bytes {
                break;
            }
            bytes += entry.len();
            part.push(entry.clone());
        }
        let next = from + part.len();
        if next >= shelf.1.len() {
            shelf.1 = Vec::new();
            // What it was named by names nothing from now on.
            shelf.0 += 1;
            return Some((part, None));
        }
        Some((part, Some(next)))
    }

    /// The node begins a whole pass. Returns the pass's number, which it
    /// gives back when the pass ends.
    pub fn whole_pass_begins(&self) -> u64 {
        self.begun.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// The node has ended the whole pass numbered `pass`.
    pub fn whole_pass_ended(&self, pass: u64) {
        self.ended.fetch_max(pass, Ordering::SeqCst);
    }

    /// The whole pass numbered `pass` ends before it has read every
    /// channel of the device's own to its end at every relay it reached:
    /// a relay gave no leave or stopped answering, or holds more of a
    /// channel than one pass takes. The node says so before it says that
    /// the pass has ended, so that whoever waited for the pass reads
    /// both.
    pub fn whole_pass_was_short(&self, pass: u64) {
        self.short.fetch_max(pass, Ordering::SeqCst);
    }

    /// The number of the last whole pass that ended short
    /// ([`Self::whole_pass_was_short`]): 0 where none has. A pass that
    /// began after a moment has a number above the count at that moment.
    pub fn last_short_pass(&self) -> u64 {
        self.short.load(Ordering::SeqCst)
    }

    /// How many whole passes the node has begun, and the number of the
    /// last that it ended. A pass that began after a moment has a number
    /// above the count at that moment.
    pub fn whole_passes(&self) -> (u64, u64) {
        (
            self.begun.load(Ordering::SeqCst),
            self.ended.load(Ordering::SeqCst),
        )
    }

    /// The relay called `relay` has handed the whole of the channel whose
    /// ID is `channel`, at `now`: the device pulled it there to its end,
    /// or the relay answered that it holds none of it.
    pub fn fetched_from(&self, channel: &[u8; 32], relay: &str, now: Instant) {
        let mut fetched = self.fetched.lock().unwrap_or_else(|e| e.into_inner());
        let of = fetched.entry(*channel).or_insert_with(|| FirstFetch {
            first: now,
            from: Default::default(),
        });
        of.from.insert(relay.to_string());
    }

    /// Whether a folder with no record in the channel whose ID is
    /// `channel` may have its first cycle there at `now` (decision
    /// 2026-10-04 §6): the channel was fetched from at least one relay,
    /// and from each other relay that the device is set up with, or the
    /// wait for those has gone by since the first had handed it. It waits
    /// for a relay, and never for a device.
    ///
    /// Where the node has not said how many relays it is set up with,
    /// only the wait says that the others had their time. A node that is
    /// set up with no relay has none to wait for, and nobody to publish
    /// to: its folders do not wait.
    ///
    /// **A device that comes to sync a name carries it first** (decision
    /// 2026-10-04 §7.3): while a carry is being made into the channel,
    /// the folder waits for that too, so that what it publishes is
    /// written over what was carried, and not beside it.
    pub fn first_fetch_done(&self, channel: &[u8; 32], now: Instant) -> bool {
        if self.is_carrying(channel, now) {
            return false;
        }
        if self.relays_set_up() == Some(0) {
            return true;
        }
        let fetched = self.fetched.lock().unwrap_or_else(|e| e.into_inner());
        let Some(of) = fetched.get(channel) else {
            return false;
        };
        let from_each = self
            .relays_set_up()
            .is_some_and(|set_up| of.from.len() >= set_up);
        from_each || now.saturating_duration_since(of.first) >= FIRST_FETCH_WAIT
    }

    /// Keep nothing of which relays have handed the channel whose ID is
    /// `channel`: the device holds it no more. Held again, it is fetched
    /// again before a folder's first cycle there.
    pub fn forget_fetched(&self, channel: &[u8; 32]) {
        let mut fetched = self.fetched.lock().unwrap_or_else(|e| e.into_inner());
        fetched.remove(channel);
    }

    /// The node says which of the relays it is set up with are connected
    /// at `now`, each by its name: it does so as often as it looks.
    ///
    /// A relay that was connected the last time it said so has been
    /// connected since it first said so; one that is connected now and
    /// was not has been since `now`. And where none is connected, none
    /// has been since the node first said so: at its start, a node says
    /// that none is.
    ///
    /// `now` is the node's own clock, which does not run while the
    /// machine sleeps: a machine that wakes has not been without a relay
    /// for the time it slept (decision 2026-10-04 §10.1).
    pub fn relays_connected(&self, relays: &[&str], now: Instant) {
        let mut connected = self.connected.lock().unwrap_or_else(|e| e.into_inner());
        connected
            .since
            .retain(|relay, _| relays.contains(&relay.as_str()));
        for relay in relays {
            connected.since.entry(relay.to_string()).or_insert(now);
        }
        match relays.is_empty() {
            true => {
                connected.none_since.get_or_insert(now);
            }
            false => connected.none_since = None,
        }
    }

    /// For how long no relay has been connected, at `now`. `None` while
    /// one is connected, and where the node has not said.
    pub fn no_relay_for(&self, now: Instant) -> Option<std::time::Duration> {
        let connected = self.connected.lock().unwrap_or_else(|e| e.into_inner());
        let since = connected.none_since?;
        Some(now.saturating_duration_since(since))
    }

    /// For how long the relay called `relay` has been connected, at
    /// `now`. `None` where it is not connected.
    pub fn connected_for(&self, relay: &str, now: Instant) -> Option<std::time::Duration> {
        let connected = self.connected.lock().unwrap_or_else(|e| e.into_inner());
        let since = connected.since.get(relay)?;
        Some(now.saturating_duration_since(*since))
    }

    /// Keep nothing of which relays have handed any channel: the device
    /// has left the phrase it followed, its store holds nothing of the
    /// channels it held, and its folders have forgotten what they had
    /// agreed. Whatever channel it comes to hold is fetched again before
    /// a folder's first cycle there, though it be one that it held
    /// before: a device that comes back to the generation it left has the
    /// same channel for each name.
    pub fn forget_every_fetched(&self) {
        let mut fetched = self.fetched.lock().unwrap_or_else(|e| e.into_inner());
        fetched.clear();
    }
}

/// Where a device stands at the relays it is set up with, for the
/// channels of its own.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AtRelays {
    /// Each relay the device is set up with, in the order of its
    /// configuration.
    pub relays: Vec<AtRelay>,
    /// Why the device cannot go on, where it cannot.
    pub cannot_go_on: Option<CannotGoOn>,
}

/// Where a device stands at one relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtRelay {
    /// The relay, as the device's configuration calls it.
    pub relay: String,
    /// Whether it holds the latest change entry that the device keeps, as
    /// it last answered a show of that entry. `None` where it has not
    /// answered one.
    pub holds_latest: Option<bool>,
    /// Whether the device has heard from it since it woke: it answered a
    /// show. Where it has not, a change made while the device was off may
    /// not have reached the device (§4.6).
    pub heard_since_woke: bool,
    /// The last time it refused something for room, where it has.
    pub no_room: Option<NoRoom>,
    /// How many entries of this device's own it holds in another form,
    /// as it answered since the node started: another entry from this
    /// device in that slot at that revision. The device sends such an
    /// entry there no more, and the next edit goes above both.
    pub another_form: usize,
    /// Why the device refuses the entry that the relay last answered a
    /// show with, where it does: the relay holds, in the place of the
    /// device's change entry, one that the phrase signed and that the
    /// device does not take (it undoes a removal, or commits to the
    /// secret already applied). It gives no leave for as long as it
    /// does.
    pub refuses: Option<String>,
}

/// A relay's refusal of something that it would have taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoRoom {
    /// When, in seconds, in UTC.
    pub at: i64,
    /// Whether it was for the address's allowance of new channels, and
    /// not for the relay's room.
    pub over_allowance: bool,
    /// Whether it was the change entry that was refused, and not an entry
    /// of a channel of the device's own.
    pub of_the_change: bool,
}

/// Why a device cannot go on in the channels of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CannotGoOn {
    /// It follows no phrase yet.
    NoPhrase,
    /// It was removed.
    Removed,
    /// It is in no list.
    NotListed,
    /// Two changes were made apart, and it keeps both.
    Fork,
    /// A change lists it, and it could not open the change.
    NotOpened,
    /// It was answered with a change that it could not apply, by the
    /// relay of this name. It says why.
    NotApplied { relay: String, why: String },
}

/// An item of this node's that a relay refused, for status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedSnapshot {
    pub item_id: String,
    /// The relay's reason, as a short code ("invalid", "storage").
    pub why: String,
    /// How many times in a row it has been refused.
    pub refusals: u32,
}

/// What the sync adapter wrote down when it kept a text in a conflict
/// file, beside a file. The copy is relied on only while the file has
/// still to take the version the text was kept against, and what was
/// written down may go sooner (decision 2026-09-30 §4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    /// What the channel held under the file's name, as the plan read it:
    /// the version that the file is to take, with every entry held of
    /// it, or no version. A record made against one matches only a plan
    /// that read the same.
    pub version: PlannedAgainst,
    /// The name of the conflict file the text is kept in.
    pub copy: String,
    /// The hash of the text.
    pub hash: [u8; 32],
    /// What the channel holds under the conflict file's name: what was
    /// there when the name was taken, and then the entry that the folder
    /// published the copy as.
    pub under: PlannedAgainst,
}

/// What is kept, for each (memory folder, channel, file).
type KeptByFile = std::collections::HashMap<(String, String, String), Kept>;

/// What a look at the index found for one file with a record of its line
/// (decision 2026-09-30 §4.5, the index line of a memory that comes back).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineFound {
    /// The file is back, the index has no line for it, and both are at
    /// rest: the line is due.
    Due,
    /// The index has a line for it, and both are at rest.
    Back,
    /// Neither.
    Neither,
}

/// What the last look found for one file, since when it has found that
/// at every look, and when that look was. Times are seconds, in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Look {
    pub found: LineFound,
    pub since: i64,
    pub at: i64,
}

/// The minute of looking, for each (memory folder, channel): what the
/// last look found for each file with a record, and the entries that
/// stood beside the index's then.
#[derive(Default)]
struct Looks {
    files: std::collections::HashMap<(String, String, String), Look>,
    beside: std::collections::HashMap<(String, String), Vec<String>>,
}

/// How the settings handlers and the sync adapter's loop keep in step.
#[derive(Default)]
pub struct SyncControl {
    wake: tokio::sync::Notify,
    generation: AtomicU64,
    /// What the adapter has written down as kept beside files. It is held
    /// here and not in the database, so that it lasts no longer than one
    /// run of the node, and no longer than until the node next takes a
    /// settings command: a record that outlived either could be of a
    /// conflict that is over (see [`Self::changed`]).
    kept: Mutex<KeptByFile>,
    /// The minute of looking before an index line is put back, or its
    /// record dropped. Held here as `kept` is, and for the same reasons: a
    /// restart, and a settings command, each start the minute again.
    looks: Mutex<Looks>,
    /// The time the adapter reads for those records, where a test has set
    /// one. Otherwise it is the system's clock.
    clock: Mutex<Option<i64>>,
    /// How many cycles the node has begun, and the number of the last
    /// that it ended.
    cycles_begun: AtomicU64,
    cycles_ended: AtomicU64,
    /// The number of the last cycle that stopped before its end.
    cycles_cut_short: AtomicU64,
    /// When the node last stored a cycle's report in this run, by its
    /// own clock.
    report_stored: Mutex<Option<Instant>>,
}

impl SyncControl {
    /// A setting is changing: count it, and wake the adapter so that the
    /// change takes effect now rather than at its next cycle.
    ///
    /// It is called with the database lock held, which is what `_db` is
    /// for: a cycle reads the count under that lock before each entry it
    /// publishes, so no entry is published under settings that a handler
    /// has already replaced and answered for. A handler calls it before
    /// the first thing it writes, so that a change that fails part-way has
    /// still stopped the cycle that was running.
    ///
    /// A handler calls it for every settings command it takes: once the
    /// command has passed the handler's checks, and whether or not the
    /// command then changes anything. (The handler of `status` takes that
    /// command too, and does not call this: `status` sets nothing.) So the
    /// count is of settings commands taken, and where these comments say
    /// that the settings have changed, they mean that the count has moved.
    ///
    /// What the adapter had kept beside files is forgotten with it: the
    /// change may be one that makes a folder forget what it had agreed,
    /// and every handler that does so counts the change first.
    pub fn changed(&self, _db: &rusqlite::Connection) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.kept().clear();
        *self.looks() = Looks::default();
        self.wake.notify_one();
    }

    fn looks(&self) -> std::sync::MutexGuard<'_, Looks> {
        self.looks.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What the last look found for `file` of `folder`, if there was one
    /// since the node started and since it last took a settings command.
    pub fn look(&self, folder: &str, channel: &str, file: &str) -> Option<Look> {
        let key = (folder.to_string(), channel.to_string(), file.to_string());
        self.looks().files.get(&key).copied()
    }

    /// Write down what a look found for `file`.
    pub fn looked(&self, folder: &str, channel: &str, file: &str, look: Look) {
        let key = (folder.to_string(), channel.to_string(), file.to_string());
        self.looks().files.insert(key, look);
    }

    /// Forget what was found for `file`: its minute starts again. With no
    /// file, for every file of the folder.
    pub fn look_again(&self, folder: &str, channel: &str, file: Option<&str>) {
        self.looks().files.retain(|(in_folder, in_channel, of), _| {
            in_folder != folder || in_channel != channel || file.is_some_and(|file| file != of)
        });
    }

    /// The entries that stood beside the index's at the last look, by ID.
    pub fn stood_beside(&self, folder: &str, channel: &str) -> Option<Vec<String>> {
        let key = (folder.to_string(), channel.to_string());
        self.looks().beside.get(&key).cloned()
    }

    /// Write down which entries stand beside the index's at this look.
    pub fn stands_beside(&self, folder: &str, channel: &str, entries: Vec<String>) {
        let key = (folder.to_string(), channel.to_string());
        self.looks().beside.insert(key, entries);
    }

    /// The time, in seconds, in UTC: the one place the adapter reads it
    /// for the records of index lines, so that a test can set it.
    pub fn now(&self) -> i64 {
        let set = *self.clock.lock().unwrap_or_else(|e| e.into_inner());
        set.unwrap_or_else(|| chrono::Utc::now().timestamp())
    }

    /// Set the time that [`Self::now`] gives, or give it back to the
    /// system's clock. For tests.
    pub fn set_now(&self, now: Option<i64>) {
        *self.clock.lock().unwrap_or_else(|e| e.into_inner()) = now;
    }

    fn kept(&self) -> std::sync::MutexGuard<'_, KeptByFile> {
        self.kept.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What `folder` has kept beside `key`, if anything.
    pub fn kept_beside(&self, folder: &str, channel: &str, key: &str) -> Option<Kept> {
        let file = (folder.to_string(), channel.to_string(), key.to_string());
        self.kept().get(&file).cloned()
    }

    /// Record what `folder` is keeping beside `key`, in place of whatever
    /// it had recorded for that file.
    ///
    /// It is called with the database lock held, which is what `_db` is
    /// for: the caller has read the count under that lock and found it
    /// unchanged, so the record cannot be made after a change of settings
    /// that has already forgotten the rest.
    pub fn keep(
        &self,
        _db: &rusqlite::Connection,
        folder: &str,
        channel: &str,
        key: &str,
        kept: Kept,
    ) {
        let file = (folder.to_string(), channel.to_string(), key.to_string());
        self.kept().insert(file, kept);
    }

    /// Forget what `folder` has kept beside `key`.
    pub fn unkeep(&self, folder: &str, channel: &str, key: &str) {
        let file = (folder.to_string(), channel.to_string(), key.to_string());
        self.kept().remove(&file);
    }

    /// `folder` has published the conflict file `copy` itself, with the
    /// text of `hash`, as the entry that is all of `under`: a text it has
    /// kept in that file is under that entry now.
    pub fn kept_published(
        &self,
        folder: &str,
        channel: &str,
        copy: &str,
        hash: &[u8; 32],
        under: &PlannedAgainst,
    ) {
        for ((in_folder, in_channel, _), kept) in self.kept().iter_mut() {
            if in_folder == folder
                && in_channel == channel
                && kept.copy == copy
                && kept.hash == *hash
            {
                kept.under = under.clone();
            }
        }
    }

    /// Forget what every folder has kept, except the (folder, channel)
    /// pairs in `syncing`: as a cycle forgets what a folder that no
    /// longer syncs had agreed.
    pub fn forget_kept_except(&self, syncing: &[(String, String)]) {
        self.kept().retain(|(folder, channel, _), _| {
            syncing.iter().any(|(f, c)| f == folder && c == channel)
        });
    }

    /// How many times the settings have changed since the node started. A
    /// sync report says which generation it was made under, so a reader
    /// can tell a report from before a change from one after it.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// [`Self::generation`], read with the database lock held, which is
    /// what `_db` is for. Read this way, the count cannot move between the
    /// read and whatever is done next under the same hold of the lock: a
    /// handler counts only while it holds it (see [`Self::changed`]).
    pub fn generation_under(&self, _db: &rusqlite::Connection) -> u64 {
        self.generation()
    }

    /// Resolves when a setting has changed, or a cycle was asked for.
    pub async fn woken(&self) {
        self.wake.notified().await;
    }

    /// Ask for a cycle now, with no setting changed: a command that
    /// prepares a change has the folders made as current as they can be
    /// first (decision 2026-10-04 §7.1, step 1). Whoever asks waits for a
    /// cycle that began after it asked ([`Self::cycles`]).
    pub fn ask_cycle(&self) {
        self.wake.notify_one();
    }

    /// The node has stored a cycle's report, at `now` by its own clock.
    pub fn report_stored(&self, now: Instant) {
        *self.report_stored.lock().unwrap_or_else(|e| e.into_inner()) = Some(now);
    }

    /// For how long the node has stored no report of a cycle, at `now`:
    /// since the later of `started`, when the node started, and the last
    /// report it stored in this run (decision 2026-10-04 §10.1).
    ///
    /// Both are read by the node's own clock, which does not run while
    /// the machine sleeps. A status says that the cycle has stalled by
    /// this alone: were the report's age read by the wall clock, a
    /// machine that wakes would be stalled until its next cycle, and
    /// were only the start read by the node's own, a report of an
    /// earlier run would make a node that has just started stalled.
    pub fn no_report_for(&self, started: Instant, now: Instant) -> std::time::Duration {
        let stored = *self.report_stored.lock().unwrap_or_else(|e| e.into_inner());
        let since = stored.map_or(started, |stored| stored.max(started));
        now.saturating_duration_since(since)
    }

    /// The node begins a cycle. Returns the cycle's number, which it
    /// gives back when the cycle ends.
    pub fn cycle_begins(&self) -> u64 {
        self.cycles_begun.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// The node has ended the cycle numbered `cycle`.
    pub fn cycle_ended(&self, cycle: u64) {
        self.cycles_ended.fetch_max(cycle, Ordering::SeqCst);
    }

    /// The cycle numbered `cycle` stops before its end: the settings
    /// changed under it, or it could not be run. The node says so before
    /// it says that the cycle has ended, so that whoever waited for the
    /// cycle reads both.
    pub fn cycle_was_cut_short(&self, cycle: u64) {
        self.cycles_cut_short.fetch_max(cycle, Ordering::SeqCst);
    }

    /// The number of the last cycle that stopped before its end
    /// ([`Self::cycle_was_cut_short`]): 0 where none has.
    pub fn last_cycle_cut_short(&self) -> u64 {
        self.cycles_cut_short.load(Ordering::SeqCst)
    }

    /// How many cycles the node has begun, and the number of the last
    /// that it ended. A cycle that began after a moment has a number
    /// above the count at that moment.
    pub fn cycles(&self) -> (u64, u64) {
        (
            self.cycles_begun.load(Ordering::SeqCst),
            self.cycles_ended.load(Ordering::SeqCst),
        )
    }
}

/// Local history (decision 2026-09-30 §4.5b): where the text that sync
/// replaced is kept, and the turn that everything that touches it takes.
///
/// A sync cycle, a restore, a drop and the sweep of old records each hold
/// the turn from start to end, so none of them sees a memory folder or the
/// store half-changed by another. The database lock is taken only inside
/// a turn, never the other way round.
#[derive(Default)]
pub struct History {
    store: std::sync::RwLock<Option<cordelia_storage::history::Store>>,
    turn: Mutex<()>,
}

impl History {
    /// Set when the node starts: the store, or `None` with history off.
    pub fn open(&self, store: Option<cordelia_storage::history::Store>) {
        if let Ok(mut held) = self.store.write() {
            *held = store;
        }
    }

    /// The store, or `None` with history turned off.
    pub fn store(&self) -> Option<cordelia_storage::history::Store> {
        self.store.read().ok().and_then(|held| held.clone())
    }

    /// Take the turn, waiting for whoever has it. A sync cycle does: it
    /// has nobody to answer to.
    pub fn turn(&self) -> std::sync::MutexGuard<'_, ()> {
        self.turn.lock().unwrap_or_else(|held| held.into_inner())
    }

    /// Take the turn if it comes free within `wait`. A command does: it
    /// answers that the node is busy rather than leave something to be
    /// carried out after it has given up.
    pub fn turn_within(&self, wait: std::time::Duration) -> Option<std::sync::MutexGuard<'_, ()>> {
        let until = Instant::now() + wait;
        loop {
            match self.turn.try_lock() {
                Ok(turn) => return Some(turn),
                Err(std::sync::TryLockError::Poisoned(held)) => return Some(held.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) if Instant::now() < until => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(std::sync::TryLockError::WouldBlock) => return None,
            }
        }
    }

    /// Drop what is too old or over the size, in a turn of its own: the
    /// node does every hour that the machine is awake, whether or not
    /// sync is on.
    pub fn sweep(&self, now: chrono::DateTime<chrono::Utc>) {
        if let Some(store) = self.store() {
            let _turn = self.turn();
            swept(store.sweep(now));
        }
    }

    /// The same, for whoever holds the turn already, and only where
    /// enough has been kept since the last sweep: a sync cycle does as it
    /// ends, so that what one busy hour keeps cannot take the store far
    /// over its size.
    pub fn sweep_if_grown(&self, now: chrono::DateTime<chrono::Utc>) {
        if let Some(store) = self.store().filter(|store| store.has_grown()) {
            swept(store.sweep(now));
        }
    }
}

/// Say what a sweep of local history did.
fn swept(swept: std::io::Result<cordelia_storage::history::Swept>) {
    match swept {
        Ok(swept) => {
            if swept.aged + swept.over > 0 {
                tracing::info!(
                    aged = swept.aged,
                    over = swept.over,
                    "history: dropped old records"
                );
            }
            if swept.failed > 0 {
                tracing::warn!(
                    records = swept.failed,
                    "history: some old records could not be removed"
                );
            }
        }
        Err(e) => tracing::warn!(error = %e, "history: could not drop old records"),
    }
}

/// What work on something from outside came to, for whoever syncs the
/// device's folders ([`AppState::as_a_change_where`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Came {
    /// No statement was applied, and the device stands where it stood.
    Nothing,
    /// A statement was applied, or the device's state changed.
    Changed,
    /// The device left the phrase it followed, and follows another.
    Left,
}

/// One connected peer, as `cordelia peers` shows it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerSnapshot {
    /// The peer's public key (bech32).
    pub key: String,
    /// `relay`, `bootnode` or `node`.
    pub role: String,
    /// `hot` or `warm`.
    pub state: String,
    pub address: String,
    /// Seconds since the connection was made.
    pub connected_secs: u64,
    /// Seconds since anything was last heard from the peer.
    pub idle_secs: u64,
}

/// One configured relay, as `cordelia peers` shows it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RelaySnapshot {
    /// The name the relay is dialled at (`host:port`).
    pub host: String,
    /// The key it must answer with (bech32), if one is configured.
    pub key: Option<String>,
    /// `connected`, `connecting`, `unreachable` or `wrong key`.
    pub state: String,
    /// Seconds since the attempts that are failing began.
    pub unreachable_secs: Option<u64>,
    /// Seconds since the last attempt.
    pub last_tried_secs: Option<u64>,
    /// Why the last attempt failed.
    pub error: Option<String>,
}

impl AppState {
    /// Do `work` as what may change which channels are the device's own
    /// is done: applying a statement, following a phrase, or leaving one
    /// (decision 2026-10-04 §4.2). It is given the database, locked.
    ///
    /// - **It waits for a sync cycle that is running to stop.** The
    ///   change is counted first, so that the cycle stops at its next
    ///   look at the count and not at its end, and the turn that a cycle
    ///   holds is then taken.
    /// - **It counts as a change of settings,** under the hold of the
    ///   database's lock that the work is done under: no cycle that began
    ///   before it publishes or records anything after it, and the
    ///   adapter's notes of the copies it has kept beside files are
    ///   cleared with it.
    ///
    /// It is counted whether or not the work then changes anything, as a
    /// settings command is.
    pub fn as_a_change<T>(&self, work: impl FnOnce(&Connection) -> T) -> T {
        self.as_a_leaving(work, |_| false)
    }

    /// [`Self::as_a_change`], for work that may have the device leave the
    /// phrase it follows: `left` says of what was done whether it did.
    ///
    /// A device that leaves a phrase drops what its store holds of every
    /// channel of its own, and its folders forget what they had agreed.
    /// Where it has, the node keeps nothing more of which relays had
    /// handed each channel ([`OwnChannels::forget_every_fetched`]), under
    /// the hold of the database's lock that the work was done under: a
    /// device that comes back to the generation it left, in the same run
    /// of the node, has the same channel for each name, and a folder's
    /// first cycle there waits until that channel was fetched again
    /// (decision 2026-10-04 §6). Otherwise the cycle would run on an
    /// empty copy of the channel, and publish every file a second time.
    pub fn as_a_leaving<T>(
        &self,
        work: impl FnOnce(&Connection) -> T,
        left: impl FnOnce(&T) -> bool,
    ) -> T {
        let locked = || self.db.lock().unwrap_or_else(|e| e.into_inner());
        self.sync_control.changed(&locked());
        let _turn = self.history.turn();
        let db = locked();
        let done = work(&db);
        if left(&done) {
            self.own_channels.forget_every_fetched();
        }
        self.sync_control.changed(&db);
        done
    }

    /// Do `work` on what came from outside and may change which channels
    /// are the device's own, or where the device stands: an entry that a
    /// relay answered a show with, one that a pass tries again, and one
    /// read from a pair channel (decision 2026-10-04 §4.2, §4.6). `came`
    /// says of what the work came to whether it did ([`Came`]).
    ///
    /// **Only then is it a change of settings.** Most of what arrives so
    /// changes nothing: an entry that the device keeps, one behind the
    /// statement it has applied, one that is refused. Counted each time,
    /// such an entry would stop the cycle that is running, and a relay
    /// could stop every cycle at the rate of its answers.
    ///
    /// So the work is done first with the database alone, in a
    /// transaction of its own. Where it comes to nothing in that sense,
    /// that stands: nothing is counted, and no cycle is waited for. Where
    /// it comes to something, the transaction is undone, and the work is
    /// done again as a change is ([`Self::as_a_change`], or
    /// [`Self::as_a_leaving`] where the device left a phrase by it): the
    /// change is counted, a cycle that is running stops, and the work is
    /// done once that cycle's turn has ended. What the second doing
    /// comes to is what is said, whatever the first came to: the
    /// database may have changed between the two.
    ///
    /// `work` writes nowhere but in the database it is given: whatever
    /// else it did could not be undone.
    pub fn as_a_change_where<T>(
        &self,
        work: impl Fn(&Connection) -> T,
        came: impl Fn(&T) -> Came,
    ) -> T {
        {
            let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
            // Undone where it is dropped: also where the work unwinds.
            let first =
                rusqlite::Transaction::new_unchecked(&db, rusqlite::TransactionBehavior::Immediate);
            if let Ok(first) = first {
                let done = work(&first);
                if came(&done) == Came::Nothing && first.commit().is_ok() {
                    return done;
                }
            }
        }
        self.as_a_leaving(work, |done| came(done) == Came::Left)
    }

    /// Uptime in seconds since node start.
    pub fn uptime_secs(&self) -> f64 {
        self.started_at.elapsed().as_secs_f64()
    }

    /// Increment sync error counter.
    pub fn inc_sync_errors(&self) {
        self.sync_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Read sync error counter.
    pub fn sync_error_count(&self) -> u64 {
        self.sync_errors.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node's state over a database in memory, with no network.
    fn test_state() -> AppState {
        AppState {
            db: Mutex::new(cordelia_storage::db::open_in_memory().unwrap()),
            identity: NodeIdentity::generate().unwrap(),
            bearer_token: "t".into(),
            home_dir: std::env::temp_dir().join("cordelia-state-test-no-such-directory"),
            started_at: Instant::now(),
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

    /// A whole pass has a number, which is above the count of passes
    /// begun at any moment before it began: whoever asked at that moment
    /// knows a pass that began after by its number, once it has ended.
    #[test]
    fn test_a_pass_that_began_after_a_moment_is_known_by_its_number() {
        let own = OwnChannels::default();
        assert_eq!(own.whole_passes(), (0, 0));
        let first = own.whole_pass_begins();
        assert_eq!((first, own.whole_passes()), (1, (1, 0)));
        // A command asks while the first pass runs: that pass does not
        // count for it, and the next does.
        let (begun, _) = own.whole_passes();
        own.whole_pass_ended(first);
        assert!(own.whole_passes().1 <= begun);
        let second = own.whole_pass_begins();
        own.whole_pass_ended(second);
        assert!(own.whole_passes().1 > begun);
        assert_eq!(own.whole_passes(), (2, 2));
        // The number of the last pass ended never goes back.
        own.whole_pass_ended(first);
        assert_eq!(own.whole_passes(), (2, 2));
        // A pass that ended early is known by its number, as one that
        // ended is.
        assert_eq!(own.last_short_pass(), 0);
        let third = own.whole_pass_begins();
        own.whole_pass_was_short(third);
        own.whole_pass_ended(third);
        assert_eq!((own.whole_passes(), own.last_short_pass()), ((3, 3), 3));
        let fourth = own.whole_pass_begins();
        own.whole_pass_ended(fourth);
        assert_eq!((own.whole_passes(), own.last_short_pass()), ((4, 4), 3));
    }

    /// How many relays a node is configured with is not known until it
    /// says, and is then what it last said.
    #[test]
    fn test_how_many_relays_a_node_is_configured_with_is_known_once_it_has_said() {
        let own = OwnChannels::default();
        assert_eq!(own.relays_set_up(), None);
        // With none is something said, and is not "not said".
        own.set_up_with(0);
        assert_eq!(own.relays_set_up(), Some(0));
        own.set_up_with(2);
        assert_eq!(own.relays_set_up(), Some(2));
        own.set_up_with(1);
        assert_eq!(own.relays_set_up(), Some(1));
    }

    /// One asking for a whole pass is kept where nobody is waiting for
    /// one, as one word that something was written is.
    #[test]
    fn test_one_asking_for_a_whole_pass_is_kept_until_it_is_waited_for() {
        let own = OwnChannels::default();
        own.ask_whole();
        own.ask_whole();
        let waited = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                let wait = std::time::Duration::from_millis(50);
                let first = tokio::time::timeout(wait, own.wait_asked()).await.is_ok();
                let second = tokio::time::timeout(wait, own.wait_asked()).await.is_ok();
                (first, second)
            });
        assert_eq!(waited, (true, false));
    }

    /// A folder's first cycle in a channel waits for the channel to be
    /// fetched: from one relay at least, and from each other relay that
    /// the device is set up with, or until the wait for those has gone by
    /// since the first had handed it. One relay handing the channel twice
    /// is one relay. A channel that is held no more is fetched again.
    #[test]
    fn test_a_first_cycle_waits_for_one_relay_and_for_the_others_so_long() {
        let own = OwnChannels::default();
        let (channel, other) = ([1u8; 32], [2u8; 32]);
        let start = Instant::now();
        let later = |secs: u64| start + std::time::Duration::from_secs(secs);
        own.set_up_with(2);
        // Not fetched from any relay: it waits, however long.
        assert!(!own.first_fetch_done(&channel, later(0)));
        assert!(!own.first_fetch_done(&channel, later(3600)));

        // One of two relays has handed it: the other has 30 seconds.
        own.fetched_from(&channel, "one", later(10));
        own.fetched_from(&channel, "one", later(12));
        assert!(!own.first_fetch_done(&channel, later(12)));
        assert!(!own.first_fetch_done(&channel, later(39)));
        assert!(own.first_fetch_done(&channel, later(40)));
        // Another channel is another matter.
        assert!(!own.first_fetch_done(&other, later(40)));

        // Both have handed it: nothing more is waited for.
        own.fetched_from(&channel, "two", later(13));
        assert!(own.first_fetch_done(&channel, later(13)));

        // Held no more, it is fetched again before a first cycle there.
        own.forget_fetched(&channel);
        assert!(!own.first_fetch_done(&channel, later(3600)));
        // And so is every channel, once the device has left its phrase.
        own.fetched_from(&channel, "one", later(10));
        own.fetched_from(&channel, "two", later(10));
        own.fetched_from(&other, "one", later(10));
        own.fetched_from(&other, "two", later(10));
        assert!(own.first_fetch_done(&channel, later(10)));
        own.forget_every_fetched();
        assert!(!own.first_fetch_done(&channel, later(3600)));
        assert!(!own.first_fetch_done(&other, later(3600)));

        // A device set up with one relay waits for that one, and no longer.
        own.set_up_with(1);
        own.fetched_from(&other, "one", later(50));
        assert!(own.first_fetch_done(&other, later(50)));

        // A node that has not said how many relays it is set up with
        // cannot tell that each has handed the channel: the wait says so.
        let unsaid = OwnChannels::default();
        unsaid.fetched_from(&channel, "one", later(0));
        unsaid.fetched_from(&channel, "two", later(0));
        assert!(!unsaid.first_fetch_done(&channel, later(29)));
        assert!(unsaid.first_fetch_done(&channel, later(30)));
    }

    /// What may change which channels are the device's own is done as a
    /// change of settings is (decision 2026-10-04 §4.2): it is counted
    /// before it waits, so that a cycle that is running stops, it waits
    /// for that cycle's turn to end, and it is counted again under the
    /// hold of the database's lock that the work was done under. The
    /// adapter's notes of the copies it has kept are cleared with it.
    #[test]
    fn test_what_changes_a_devices_channels_waits_for_a_cycle_and_counts_as_a_change() {
        let state = std::sync::Arc::new(test_state());
        let before = state.sync_control.generation();
        {
            let db = state.db.lock().unwrap();
            let kept = Kept {
                version: PlannedAgainst::NoVersion,
                copy: "a.conflict-x.md".into(),
                hash: [1; 32],
                under: PlannedAgainst::NoVersion,
            };
            state.sync_control.keep(&db, "/m", "channel", "a.md", kept);
        }

        // A cycle holds the turn. It sees the count move while it still
        // holds it, and only when it gives the turn up is the work done.
        let turn = state.history.turn();
        let other = std::sync::Arc::clone(&state);
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let did = std::sync::Arc::clone(&done);
        let change = std::thread::spawn(move || {
            other.as_a_change(|_db| {
                did.store(true, Ordering::SeqCst);
                other.sync_control.generation()
            })
        });
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        while state.sync_control.generation() == before {
            assert!(Instant::now() < deadline, "the change was not counted");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            !done.load(Ordering::SeqCst),
            "the work did not wait for the cycle"
        );
        assert_eq!(state.sync_control.generation(), before + 1);
        drop(turn);
        let during = change.join().unwrap();
        assert!(done.load(Ordering::SeqCst));
        // Counted before the work, and again after it.
        assert_eq!(during, before + 1);
        assert_eq!(state.sync_control.generation(), before + 2);
        assert!(
            state
                .sync_control
                .kept_beside("/m", "channel", "a.md")
                .is_none()
        );
    }

    /// For how long the node has stored no report of a cycle (decision
    /// 2026-10-04 §10.1): since it started, until it stores one, and
    /// then since the last it stored. A time before the start counts
    /// from the start.
    #[test]
    fn test_for_how_long_no_report_was_stored_is_by_the_nodes_own_clock() {
        let control = SyncControl::default();
        let start = Instant::now();
        let at = |secs: u64| start + std::time::Duration::from_secs(secs);
        let secs = |now: Instant| control.no_report_for(at(100), now).as_secs();
        // Started at 100, and no report yet.
        assert_eq!(secs(at(100)), 0);
        assert_eq!(secs(at(170)), 70);
        assert_eq!(secs(at(50)), 0);
        control.report_stored(at(160));
        assert_eq!(secs(at(170)), 10);
        assert_eq!(secs(at(400)), 240);
        control.report_stored(at(395));
        assert_eq!(secs(at(400)), 5);
        // A report from before the start, were there one: from the
        // start.
        control.report_stored(at(20));
        assert_eq!(secs(at(400)), 300);
    }

    /// Since when no relay has been connected, and since when each has
    /// been, by the clock that the node gives (decision 2026-10-04
    /// §10.1). Nothing is said before the node has: a relay that stays
    /// connected has been since it first was, one that comes back has
    /// been since it came back, and none has been connected since the
    /// last of them went.
    #[test]
    fn test_since_when_each_relay_is_connected_and_since_when_none_is() {
        let own = OwnChannels::default();
        let start = Instant::now();
        let at = |secs: u64| start + std::time::Duration::from_secs(secs);
        let secs = |time: Option<std::time::Duration>| time.map(|time| time.as_secs());
        assert_eq!(secs(own.no_relay_for(at(100))), None);
        assert_eq!(secs(own.connected_for("one", at(100))), None);

        // The node starts: none is connected.
        own.relays_connected(&[], at(0));
        own.relays_connected(&[], at(2));
        assert_eq!(secs(own.no_relay_for(at(40))), Some(40));
        // One connects, and then the other: no relay is missing, and
        // each has been connected since it was first said to be.
        own.relays_connected(&["one"], at(50));
        own.relays_connected(&["one", "two"], at(60));
        own.relays_connected(&["one", "two"], at(70));
        assert_eq!(secs(own.no_relay_for(at(400))), None);
        assert_eq!(secs(own.connected_for("one", at(400))), Some(350));
        assert_eq!(secs(own.connected_for("two", at(400))), Some(340));
        // One goes and comes back: it has been connected since it came
        // back. With the other still there, a relay was connected
        // throughout.
        own.relays_connected(&["two"], at(500));
        assert_eq!(secs(own.connected_for("one", at(510))), None);
        assert_eq!(secs(own.no_relay_for(at(510))), None);
        own.relays_connected(&["one", "two"], at(520));
        assert_eq!(secs(own.connected_for("one", at(600))), Some(80));
        assert_eq!(secs(own.connected_for("two", at(600))), Some(540));
        // Both go: none has been connected since then, however often
        // the node says so.
        own.relays_connected(&[], at(700));
        own.relays_connected(&[], at(900));
        assert_eq!(secs(own.no_relay_for(at(1000))), Some(300));
        assert_eq!(secs(own.connected_for("two", at(1000))), None);
        // A time before the one that was noted is no time at all.
        assert_eq!(secs(own.no_relay_for(at(650))), Some(0));
    }

    /// Work that has the device leave the phrase it follows is done as a
    /// change of settings is, and the node then keeps nothing of which
    /// relays had handed each channel: a folder's first cycle in a
    /// channel that the device comes back to waits until it was fetched
    /// again (decision 2026-10-04 §6). Work that leaves nothing keeps
    /// what was noted.
    #[test]
    fn test_a_device_that_leaves_its_phrase_keeps_no_note_of_what_was_fetched() {
        let state = test_state();
        state.own_channels.set_up_with(1);
        let channel = [1u8; 32];
        let now = Instant::now();
        state.own_channels.fetched_from(&channel, "one", now);
        let before = state.sync_control.generation();

        // It did not leave: what was noted stands, and the change counts.
        let done = state.as_a_leaving(|_db| Ok::<bool, ()>(false), |done| *done == Ok(true));
        assert_eq!(done, Ok(false));
        assert!(state.own_channels.first_fetch_done(&channel, now));
        assert_eq!(state.sync_control.generation(), before + 2);
        // Nor where the work failed.
        let failed = state.as_a_leaving(|_db| Err::<bool, ()>(()), |done| *done == Ok(true));
        assert_eq!(failed, Err(()));
        assert!(state.own_channels.first_fetch_done(&channel, now));

        // It left: nothing is noted any more, by the time the work's hold
        // of the database is given up.
        let done = state.as_a_leaving(|_db| Ok::<bool, ()>(true), |done| *done == Ok(true));
        assert_eq!(done, Ok(true));
        assert!(!state.own_channels.first_fetch_done(&channel, now));
        assert_eq!(state.sync_control.generation(), before + 6);
    }

    /// What comes from outside is a change of settings only where it
    /// applies a statement or changes the device's state (decision
    /// 2026-10-04 §4.2). Work that changes neither is done with the
    /// database alone: nothing is counted, what the adapter keeps beside
    /// files stands, and it does not wait for a cycle that is running.
    /// Work that does is undone and done again as a change is: counted
    /// before and after, and only once the cycle's turn has ended. And
    /// what work that failed wrote is not kept, nor counted.
    #[test]
    fn test_what_comes_from_outside_counts_as_a_change_only_where_it_changes_something() {
        let state = std::sync::Arc::new(test_state());
        // The work: it counts, in the database, how often it was done.
        let done = |db: &Connection| -> i64 {
            let so_far = cordelia_storage::meta::get(db, "test.done").unwrap();
            let now = so_far.map_or(0, |n| n.parse::<i64>().unwrap()) + 1;
            cordelia_storage::meta::set(db, "test.done", &now.to_string()).unwrap();
            now
        };
        let channel = [1u8; 32];
        let noted = Instant::now();
        state.own_channels.set_up_with(1);
        state.own_channels.fetched_from(&channel, "one", noted);
        let before = state.sync_control.generation();
        {
            let db = state.db.lock().unwrap();
            let kept = Kept {
                version: PlannedAgainst::NoVersion,
                copy: "a.conflict-x.md".into(),
                hash: [1; 32],
                under: PlannedAgainst::NoVersion,
            };
            state.sync_control.keep(&db, "/m", "channel", "a.md", kept);
        }

        // It changes nothing: done once, while a cycle holds the turn,
        // with nothing counted and nothing forgotten.
        let turn = state.history.turn();
        assert_eq!(state.as_a_change_where(done, |_| Came::Nothing), 1);
        assert_eq!(state.sync_control.generation(), before);
        assert!(
            state
                .sync_control
                .kept_beside("/m", "channel", "a.md")
                .is_some()
        );

        // It changes something: what the first doing wrote is undone, the
        // change is counted so that the cycle stops, and the work is done
        // again once the cycle's turn has ended.
        let other = std::sync::Arc::clone(&state);
        let change = std::thread::spawn(move || other.as_a_change_where(done, |_| Came::Changed));
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        while state.sync_control.generation() == before {
            assert!(Instant::now() < deadline, "the change was not counted");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!change.is_finished(), "the work did not wait for the cycle");
        assert_eq!(state.sync_control.generation(), before + 1);
        drop(turn);
        // Written once more, and no more: the first doing was undone.
        assert_eq!(change.join().unwrap(), 2);
        assert_eq!(state.sync_control.generation(), before + 2);
        assert!(
            state
                .sync_control
                .kept_beside("/m", "channel", "a.md")
                .is_none()
        );
        // Neither had the device leave a phrase: what was noted of the
        // relays that handed its channels stands. Where it did leave,
        // nothing is noted any more.
        assert!(state.own_channels.first_fetch_done(&channel, noted));
        assert_eq!(state.as_a_change_where(done, |_| Came::Left), 3);
        assert_eq!(state.sync_control.generation(), before + 4);
        assert!(!state.own_channels.first_fetch_done(&channel, noted));
    }

    /// A cycle has a number, which is above the count of cycles begun at
    /// any moment before it began: whoever asked for one at that moment
    /// knows a cycle that began after by its number, once it has ended.
    #[test]
    fn test_a_cycle_that_began_after_a_moment_is_known_by_its_number() {
        let control = SyncControl::default();
        assert_eq!(control.cycles(), (0, 0));
        let first = control.cycle_begins();
        let (begun, _) = control.cycles();
        control.cycle_ended(first);
        assert!(control.cycles().1 <= begun);
        let second = control.cycle_begins();
        control.cycle_ended(second);
        assert!(control.cycles().1 > begun);
        control.cycle_ended(first);
        assert_eq!(control.cycles(), (2, 2));
        // A cycle that stopped before its end is known by its number.
        assert_eq!(control.last_cycle_cut_short(), 0);
        let third = control.cycle_begins();
        control.cycle_was_cut_short(third);
        control.cycle_ended(third);
        assert_eq!(
            (control.cycles(), control.last_cycle_cut_short()),
            ((3, 3), 3)
        );
    }

    /// The sweep of local history takes its turn with a sync cycle and a
    /// restore: while one of them holds the turn nothing is swept, and
    /// when the turn is free what is too old goes. With history off there
    /// is nothing to sweep.
    #[test]
    fn test_the_sweep_of_history_takes_its_turn() {
        use cordelia_storage::history::{About, Change, Replacement, Store, Whose, kept};
        let at = |days: i64| chrono::DateTime::from_timestamp(1_800_000_000 + days * 86_400, 0);
        let (then, now) = (at(0).unwrap(), at(31).unwrap());
        let dir = tempfile::tempdir().unwrap();
        let history = History::default();
        history.sweep(now);
        history.sweep_if_grown(now);

        let store = Store::new(dir.path(), 30, 1 << 20).unwrap();
        let about = About {
            at: String::new(),
            agent: "lab".into(),
            folder: "/m".into(),
            file: "notes.md".into(),
            change: Change::Pulled,
            kept: Some(kept(Whose::Here { agreed: None }, "old\n")),
            replaced_by: Replacement::Nothing,
            behind: false,
        };
        let pending = store.keep(about, Some("old\n"), then).unwrap();
        store.settle(pending).unwrap();
        history.open(Some(store.clone()));
        let kept_now = || store.list().unwrap().records.len();

        // Not enough has been kept for a sweep at a cycle's end.
        history.sweep_if_grown(now);
        assert_eq!(kept_now(), 1);

        std::thread::scope(|scope| {
            let turn = history.turn();
            let sweep = scope.spawn(|| history.sweep(now));
            std::thread::sleep(std::time::Duration::from_millis(300));
            assert!(!sweep.is_finished(), "swept while the turn was held");
            assert_eq!(kept_now(), 1);
            drop(turn);
            sweep.join().unwrap();
        });
        assert_eq!(kept_now(), 0);
    }

    /// What a plan reads where the slot holds one text at revision 3, in
    /// the one entry named `entry`.
    fn version(entry: u8) -> PlannedAgainst {
        PlannedAgainst::Version {
            rev: 3,
            kind: crate::publish::Kind::Text,
            hash: [9; 32],
            entries: vec![[entry; 32]],
        }
    }

    fn kept(copy: &str, hash: u8) -> Kept {
        Kept {
            version: version(1),
            copy: copy.into(),
            hash: [hash; 32],
            under: PlannedAgainst::NoVersion,
        }
    }

    /// What is kept beside a file is held for that file, in that folder
    /// and channel; replaced by the next thing kept beside it; brought up
    /// to date when that copy is published with that text, and for no
    /// other record; and gone when asked.
    #[test]
    fn test_what_is_kept_beside_a_file() {
        let db = Connection::open_in_memory().unwrap();
        let control = SyncControl::default();
        assert_eq!(control.kept_beside("/m", "grp_a", "notes.md"), None);
        control.keep(&db, "/m", "grp_a", "notes.md", kept("first", 7));
        assert_eq!(
            control.kept_beside("/m", "grp_a", "notes.md"),
            Some(kept("first", 7))
        );
        assert_eq!(control.kept_beside("/m", "grp_a", "other.md"), None);
        assert_eq!(control.kept_beside("/m", "grp_b", "notes.md"), None);
        assert_eq!(control.kept_beside("/n", "grp_a", "notes.md"), None);

        control.keep(&db, "/m", "grp_a", "notes.md", kept("second", 8));
        assert_eq!(
            control.kept_beside("/m", "grp_a", "notes.md"),
            Some(kept("second", 8))
        );

        control.keep(&db, "/n", "grp_a", "notes.md", kept("second", 8));
        control.keep(&db, "/m", "grp_b", "notes.md", kept("second", 8));
        let under = |folder: &str, channel: &str| {
            let kept = control.kept_beside(folder, channel, "notes.md");
            kept.map(|kept| kept.under)
        };
        let none = Some(PlannedAgainst::NoVersion);
        let published = |copy: &str, hash: u8| {
            control.kept_published("/m", "grp_a", copy, &[hash; 32], &version(2));
            under("/m", "grp_a")
        };
        assert_eq!(published("first", 8), none);
        assert_eq!(published("second", 7), none);
        assert_eq!(published("notes.md", 8), none);
        assert_eq!(published("second", 8), Some(version(2)));
        assert_eq!(under("/n", "grp_a"), none);
        assert_eq!(under("/m", "grp_b"), none);

        control.unkeep("/m", "grp_a", "notes.md");
        assert_eq!(control.kept_beside("/m", "grp_a", "notes.md"), None);
        assert!(control.kept_beside("/n", "grp_a", "notes.md").is_some());
        // Nothing to forget is nothing done.
        control.unkeep("/m", "grp_a", "notes.md");
    }

    /// What is kept is forgotten for every folder but those that still
    /// sync, and for every folder when a setting changes.
    #[test]
    fn test_what_is_kept_is_forgotten_with_what_is_agreed() {
        let db = Connection::open_in_memory().unwrap();
        let control = SyncControl::default();
        let fill = || {
            control.keep(&db, "/m", "grp_a", "notes.md", kept("a", 1));
            control.keep(&db, "/m", "grp_b", "notes.md", kept("b", 1));
            control.keep(&db, "/n", "grp_a", "notes.md", kept("c", 1));
        };
        let left = || -> Vec<bool> {
            [("/m", "grp_a"), ("/m", "grp_b"), ("/n", "grp_a")]
                .iter()
                .map(|(folder, channel)| control.kept_beside(folder, channel, "notes.md").is_some())
                .collect()
        };
        fill();
        control.forget_kept_except(&[("/m".to_string(), "grp_a".to_string())]);
        assert_eq!(left(), [true, false, false]);
        fill();
        control.forget_kept_except(&[]);
        assert_eq!(left(), [false, false, false]);

        fill();
        let before = control.generation();
        control.changed(&db);
        assert_eq!(control.generation(), before + 1);
        assert_eq!(left(), [false, false, false]);
    }
}
