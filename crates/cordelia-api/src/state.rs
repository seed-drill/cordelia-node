//! Shared application state for actix-web handlers.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use cordelia_crypto::identity::NodeIdentity;
use rusqlite::Connection;

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
    /// Which keys have been found usable, and which not, while this node
    /// has run.
    pub usable_keys: UsableKeys,
    /// Local history, and the turn its users take.
    pub history: History,
}

/// Whether a key is a usable public key
/// ([`cordelia_crypto::identity::is_usable_public_key`]), as this node has
/// found so far.
///
/// The answer for a key never changes, and finding it costs a
/// multiplication on the curve. A channel state that waits is looked at
/// again every few seconds, with up to 1,024 keys in it. So the answer is
/// kept, in memory, for as long as the node runs.
///
/// Nothing depends on what is kept: a key that is not here is checked, and
/// what is kept for a key is what the check gave. Each node has its own.
///
/// It saves the checks only while the keys the node looks at fit in it.
/// Once they do not, a look at a state checks its keys again, at most a
/// multiplication for each: what is kept is dropped before the keys kept
/// from the last look are come to. (A key that several states list can
/// still be answered from what is kept.) Never more checks than with
/// nothing kept.
pub struct UsableKeys {
    known: Mutex<std::collections::HashMap<[u8; 32], bool>>,
    most: usize,
}

impl UsableKeys {
    /// The most answers kept: those of 64 states that each list as many
    /// members as a state may (1,024).
    pub const MOST: usize = 65_536;

    /// One that keeps at most `most` answers (one, if `most` is nought).
    /// When one more is to be kept, all are dropped first.
    pub fn keeping(most: usize) -> Self {
        Self {
            known: Mutex::default(),
            most,
        }
    }

    /// Whether `key` is a usable public key.
    pub fn is_usable(&self, key: &[u8; 32]) -> bool {
        // A lock that a panic left poisoned still guards answers that are
        // each right, so it is used as it is.
        let mut known = self.known.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(usable) = known.get(key) {
            return *usable;
        }
        let usable = cordelia_crypto::identity::is_usable_public_key(key);
        if known.len() >= self.most {
            known.clear();
        }
        known.insert(*key, usable);
        usable
    }

    /// How many answers are kept now.
    pub fn kept(&self) -> usize {
        self.known.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Default for UsableKeys {
    fn default() -> Self {
        Self::keeping(Self::MOST)
    }
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
    /// The channel's version that the file is to take (its item ID), as
    /// the plan read it. `None` where the plan read no version: a record
    /// made against none matches only a plan that read none.
    pub version: Option<String>,
    /// The name of the conflict file the text is kept in.
    pub copy: String,
    /// The hash of the text.
    pub hash: [u8; 32],
    /// The channel's entry under the conflict file's name (its item ID),
    /// if there is one: the entry that was there when the name was taken,
    /// and then the entry that the folder published the copy as.
    pub under: Option<String>,
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
    /// text of `hash`, as the entry `under`: a text it has kept in that
    /// file is under that entry now.
    pub fn kept_published(
        &self,
        folder: &str,
        channel: &str,
        copy: &str,
        hash: &[u8; 32],
        under: &str,
    ) {
        for ((in_folder, in_channel, _), kept) in self.kept().iter_mut() {
            if in_folder == folder
                && in_channel == channel
                && kept.copy == copy
                && kept.hash == *hash
            {
                kept.under = Some(under.to_string());
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

    /// Resolves when a setting has changed.
    pub async fn woken(&self) {
        self.wake.notified().await;
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
    use cordelia_crypto::identity::{is_usable_public_key, key_checks};

    /// `n` keys that are usable and `n` that are not, each different.
    fn keys(n: usize) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
        let usable: Vec<[u8; 32]> = (0..n)
            .map(|_| NodeIdentity::generate().unwrap().public_key())
            .collect();
        let not: Vec<[u8; 32]> = (0..4096u32)
            .map(|i| {
                let mut key = [0x42; 32];
                key[..4].copy_from_slice(&i.to_le_bytes());
                key
            })
            .filter(|key| !is_usable_public_key(key))
            .take(n)
            .collect();
        assert_eq!(not.len(), n);
        (usable, not)
    }

    /// What is remembered for a key is what the check gives, for a key
    /// that is usable and for one that is not, the first time it is asked
    /// and every time after. A key is checked once.
    #[test]
    fn test_what_is_remembered_of_a_key_is_what_the_check_gives() {
        let (usable, not) = keys(3);
        let known = UsableKeys::default();
        for _ in 0..3 {
            for key in &usable {
                assert!(known.is_usable(key));
            }
            for key in &not {
                assert!(!known.is_usable(key));
            }
        }
        assert_eq!(known.kept(), 6);
        let before = key_checks();
        for key in usable.iter().chain(&not) {
            known.is_usable(key);
        }
        assert_eq!(
            key_checks(),
            before,
            "a key that is kept is not checked again"
        );
    }

    /// Each node has its own: what one has found costs another the same
    /// to find.
    #[test]
    fn test_each_node_remembers_for_itself() {
        let (usable, not) = keys(2);
        let (one, other) = (UsableKeys::default(), UsableKeys::default());
        for known in [&one, &other] {
            let before = key_checks();
            for key in usable.iter().chain(&not) {
                known.is_usable(key);
            }
            assert_eq!(key_checks() - before, 4);
        }
        assert_eq!((one.kept(), other.kept()), (4, 4));
    }

    /// No more than so many are kept. When one more is to be kept, all are
    /// dropped first, and nothing depends on that: a key that was dropped
    /// is checked again, with the same answer.
    #[test]
    fn test_what_is_remembered_is_bounded_and_dropping_it_changes_no_answer() {
        let (usable, not) = keys(3);
        let known = UsableKeys::keeping(4);
        let all: Vec<([u8; 32], bool)> = usable
            .iter()
            .map(|key| (*key, true))
            .chain(not.iter().map(|key| (*key, false)))
            .collect();
        for (i, (key, want)) in all.iter().enumerate() {
            assert_eq!(known.is_usable(key), *want);
            // Four are kept; the fifth empties them and is kept alone.
            assert_eq!(known.kept(), i % 4 + 1, "after {}", i + 1);
        }
        // Round again. Six keys do not fit in four, so nothing is saved:
        // the two that were kept are dropped before they are come to,
        // and every key is checked again. The answers are the same.
        let before = key_checks();
        for (key, want) in &all {
            assert_eq!(known.is_usable(key), *want);
        }
        assert_eq!(key_checks() - before, 6);
        assert_eq!(known.kept(), 4);
        // Four keys do fit: the second time round costs nothing.
        let known = UsableKeys::keeping(4);
        for _ in 0..2 {
            for (key, want) in &all[..4] {
                assert_eq!(known.is_usable(key), *want);
            }
        }
        let before = key_checks();
        for (key, want) in &all[..4] {
            assert_eq!(known.is_usable(key), *want);
        }
        assert_eq!(key_checks(), before);
        assert_eq!(UsableKeys::MOST, 65_536);
        assert_eq!(UsableKeys::default().most, UsableKeys::MOST);
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

    fn kept(copy: &str, hash: u8) -> Kept {
        Kept {
            version: Some("ci_version".into()),
            copy: copy.into(),
            hash: [hash; 32],
            under: None,
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
            kept.and_then(|kept| kept.under)
        };
        let published = |copy: &str, hash: u8| {
            control.kept_published("/m", "grp_a", copy, &[hash; 32], "ci_published");
            under("/m", "grp_a")
        };
        assert_eq!(published("first", 8), None);
        assert_eq!(published("second", 7), None);
        assert_eq!(published("notes.md", 8), None);
        assert_eq!(published("second", 8).as_deref(), Some("ci_published"));
        assert_eq!(under("/n", "grp_a"), None);
        assert_eq!(under("/m", "grp_b"), None);

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
