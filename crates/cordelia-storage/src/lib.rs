//! SQLite storage: channels, items, PSK management, search indexes, migrations.
//!
//! Spec: seed-drill/specs/data-formats.md, seed-drill/specs/channels-api.md

pub mod atomic;
pub mod channels;
pub mod db;
pub mod entries;
pub mod history;
pub mod index_lines;
pub mod invites;
pub mod items;
pub mod meta;
pub mod naming;
pub mod offers;
pub mod psk;
pub mod schema;
pub mod search;
pub mod sync_state;
pub mod trust;
pub mod usage;

/// Storage-level errors (wraps rusqlite and IO errors).
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("migration failed: {0}")]
    Migration(String),
}
