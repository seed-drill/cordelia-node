//! SQLite storage: what a device and a relay hold of channels from their
//! secrets, and the steps of the schema.
//!
//! Spec: seed-drill/specs/data-formats.md, seed-drill/specs/channels-api.md

pub mod acts;
pub mod arrivals;
pub mod at_relays;
pub mod atomic;
pub mod db;
pub mod entries;
pub mod follows;
pub mod history;
pub mod index_lines;
pub mod messages;
pub mod meta;
pub mod person;
pub mod relay;
pub mod schema;
pub mod shared;
pub mod shared_anew;
pub mod shared_lists;
pub mod shared_messages;
pub mod shared_pass;
pub mod shared_sharing;
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

    /// The database is from a Cordelia before 0.2.0-alpha.19 (decision
    /// 2026-11-10 (older kind), rule 6): at schema step `found`, 1 to 32,
    /// or at no step with something in it. This version takes over only
    /// alpha.19's, and changed nothing of it.
    #[error(
        "the database is at schema step {found}, from a Cordelia before 0.2.0-alpha.19: this \
         version cannot open it, and changed nothing"
    )]
    EarlierVersion { found: u32 },
}
