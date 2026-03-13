//! Shared application state for actix-web handlers.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use cordelia_crypto::identity::NodeIdentity;
use rusqlite::Connection;

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
