//! SQLite storage: channels, items, PSK management, search indexes, migrations.
//!
//! Spec: seed-drill/specs/data-formats.md, seed-drill/specs/channels-api.md

pub mod channels;
pub mod db;
pub mod items;
pub mod naming;
pub mod psk;
pub mod schema;
// TODO(WP4): L2 encryption integration.
// TODO(WP8): FTS5 search indexing.

/// Storage-level errors (wraps rusqlite and IO errors).
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
