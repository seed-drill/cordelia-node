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
    ///
    /// It is called with the database lock held, which is what `_db` is
    /// for: a cycle reads the count under that lock before each entry it
    /// publishes, so no entry is published under settings that a handler
    /// has already replaced and answered for.
    pub fn changed(&self, _db: &rusqlite::Connection) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.wake.notify_one();
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
