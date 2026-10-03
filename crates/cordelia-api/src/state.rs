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
pub struct UsableKeys {
    known: Mutex<std::collections::HashMap<[u8; 32], bool>>,
    most: usize,
}

impl UsableKeys {
    /// The most answers kept: those of 64 states that each list as many
    /// keys as a state may.
    pub const MOST: usize = 64 * cordelia_core::protocol::MAX_STATE_KEYS;

    /// One that keeps at most `most` answers. When one more is to be
    /// kept, all are dropped first.
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

/// How the settings handlers and the sync adapter's loop keep in step.
#[derive(Default)]
pub struct SyncControl {
    wake: tokio::sync::Notify,
    generation: AtomicU64,
}

impl SyncControl {
    /// A setting changed: count it, and wake the adapter so that the change
    /// takes effect now rather than at its next cycle.
    pub fn changed(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.wake.notify_one();
    }

    /// How many times the settings have changed since the node started. A
    /// sync report says which generation it was made under, so a reader
    /// can tell a report from before a change from one after it.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Resolves when a setting has changed.
    pub async fn woken(&self) {
        self.wake.notified().await;
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
        // Twice round: a key dropped the first time round is checked
        // again, and one kept is not.
        let before = key_checks();
        for (key, want) in &all {
            assert_eq!(known.is_usable(key), *want);
        }
        assert!(known.kept() <= 4);
        assert!(key_checks() - before >= 4, "the four that were dropped");
        assert_eq!(UsableKeys::MOST, 65_536);
        assert_eq!(UsableKeys::default().most, UsableKeys::MOST);
    }
}
