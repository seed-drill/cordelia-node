//! Shared application state for actix-web handlers.

use std::path::PathBuf;
use std::sync::Mutex;

use cordelia_crypto::identity::NodeIdentity;
use rusqlite::Connection;

/// Shared state accessible from all request handlers.
pub struct AppState {
    pub db: Mutex<Connection>,
    pub identity: NodeIdentity,
    pub bearer_token: String,
    pub home_dir: PathBuf,
}
