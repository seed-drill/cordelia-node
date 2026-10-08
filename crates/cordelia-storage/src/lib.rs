//! SQLite storage: channels, items, PSK management, search indexes, migrations.
//!
//! Spec: seed-drill/specs/data-formats.md, seed-drill/specs/channels-api.md

pub mod acts;
pub mod at_relays;
pub mod atomic;
pub mod channels;
pub mod db;
pub mod entries;
pub mod first_start;
pub mod history;
pub mod index_lines;
pub mod items;
pub mod meta;
pub mod naming;
pub mod person;
pub mod psk;
pub mod relay;
pub mod schema;
pub mod search;
pub mod sync_state;
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

    /// The database was written by a later version of the program than
    /// this one (decision 2026-10-04 §10.1): it is at schema version
    /// `found`, and this version knows `own` and none after. Nothing of
    /// it was changed.
    #[error(
        "the database is at schema version {found}, and this version of Cordelia knows schema \
         version {own} and none after: a later version wrote it, and nothing was changed"
    )]
    LaterVersion { found: u32, own: u32 },
}
