//! SQLite schema definitions and migrations.
//!
//! Spec: seed-drill/specs/data-formats.md §3, §5

use rusqlite::Connection;

use crate::StorageError;

/// Current schema version (incremented per migration).
pub const SCHEMA_VERSION: u32 = 12;

/// Migration v1: Phase 1 initial schema.
///
/// All DDL from data-formats.md §3.1-§3.5.
/// Search tables (§2 of search-indexing.md) deferred to WP8.
const MIGRATION_V1: &str = r#"
-- Core tables (data-formats.md §3)

CREATE TABLE IF NOT EXISTS channels (
    channel_id    TEXT PRIMARY KEY,
    channel_name  TEXT,
    channel_type  TEXT NOT NULL CHECK(channel_type IN ('named', 'dm', 'group')),
    mode          TEXT NOT NULL CHECK(mode IN ('realtime', 'batch')),
    access        TEXT NOT NULL CHECK(access IN ('open', 'invite_only')),
    creator_id    BLOB NOT NULL,
    key_version   INTEGER NOT NULL DEFAULT 1,
    psk_hash      BLOB,
    descriptor    BLOB,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_channels_name ON channels(channel_name)
    WHERE channel_name IS NOT NULL AND channel_type = 'named';

CREATE TABLE IF NOT EXISTS channel_members (
    channel_id   TEXT NOT NULL REFERENCES channels(channel_id),
    entity_key   BLOB NOT NULL,
    role         TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'member')),
    posture      TEXT NOT NULL DEFAULT 'active' CHECK(posture IN ('active', 'removed')),
    joined_at    TEXT NOT NULL,
    removed_at   TEXT,
    PRIMARY KEY (channel_id, entity_key)
);

CREATE INDEX IF NOT EXISTS idx_members_entity ON channel_members(entity_key);

CREATE TABLE IF NOT EXISTS channel_keys (
    channel_id     TEXT PRIMARY KEY REFERENCES channels(channel_id),
    encrypted_psk  BLOB NOT NULL,
    key_version    INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS items (
    item_id         TEXT PRIMARY KEY,
    channel_id      TEXT NOT NULL REFERENCES channels(channel_id),
    author_id       BLOB NOT NULL,
    item_type       TEXT NOT NULL,
    published_at    TEXT NOT NULL,
    is_tombstone    INTEGER NOT NULL DEFAULT 0,
    parent_id       TEXT,
    key_version     INTEGER NOT NULL DEFAULT 1,
    content_hash    BLOB NOT NULL,
    signature       BLOB NOT NULL,
    encrypted_blob  BLOB NOT NULL,
    content_length  INTEGER NOT NULL,
    received_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_items_channel_published ON items(channel_id, published_at);
CREATE INDEX IF NOT EXISTS idx_items_channel_type      ON items(channel_id, item_type);
CREATE INDEX IF NOT EXISTS idx_items_content_hash      ON items(content_hash);

CREATE TABLE IF NOT EXISTS dm_peers (
    channel_id   TEXT PRIMARY KEY REFERENCES channels(channel_id),
    peer_key     BLOB NOT NULL
);
"#;

/// Migration v2: FTS5 search indexing (search-indexing.md §2).
const MIGRATION_V2: &str = r#"
CREATE TABLE IF NOT EXISTS search_content (
    rowid         INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id       TEXT NOT NULL UNIQUE,
    channel_id    TEXT NOT NULL,
    item_type     TEXT NOT NULL,
    published_at  TEXT NOT NULL,
    is_tombstone  INTEGER NOT NULL DEFAULT 0,
    name          TEXT NOT NULL DEFAULT '',
    summary       TEXT NOT NULL DEFAULT '',
    content_text  TEXT NOT NULL DEFAULT '',
    tags_text     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_search_content_channel ON search_content(channel_id);
CREATE INDEX IF NOT EXISTS idx_search_content_item_id ON search_content(item_id);
CREATE INDEX IF NOT EXISTS idx_search_content_type    ON search_content(channel_id, item_type);

CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
    name,
    summary,
    content_text,
    tags_text,
    content = 'search_content',
    content_rowid = 'rowid',
    tokenize = 'unicode61'
);

CREATE TRIGGER IF NOT EXISTS search_fts_insert AFTER INSERT ON search_content BEGIN
    INSERT INTO search_fts(rowid, name, summary, content_text, tags_text)
    VALUES (NEW.rowid, NEW.name, NEW.summary, NEW.content_text, NEW.tags_text);
END;

CREATE TRIGGER IF NOT EXISTS search_fts_delete AFTER DELETE ON search_content BEGIN
    INSERT INTO search_fts(search_fts, rowid, name, summary, content_text, tags_text)
    VALUES ('delete', OLD.rowid, OLD.name, OLD.summary, OLD.content_text, OLD.tags_text);
END;

CREATE TRIGGER IF NOT EXISTS search_fts_update AFTER UPDATE ON search_content BEGIN
    INSERT INTO search_fts(search_fts, rowid, name, summary, content_text, tags_text)
    VALUES ('delete', OLD.rowid, OLD.name, OLD.summary, OLD.content_text, OLD.tags_text);
    INSERT INTO search_fts(rowid, name, summary, content_text, tags_text)
    VALUES (NEW.rowid, NEW.name, NEW.summary, NEW.content_text, NEW.tags_text);
END;
"#;

/// Migration v3: Channel scope for PAN ephemeral local channels (§8.2.2).
const MIGRATION_V3: &str = r#"
ALTER TABLE channels ADD COLUMN scope TEXT NOT NULL DEFAULT 'network'
    CHECK(scope IN ('network', 'local'));
"#;

/// Migration v4: device invites (decision 2026-09-30-agent-memory-sync §4.1).
///
/// Rebuilds `channels` to admit the `inbox` channel type (SQLite cannot
/// alter a CHECK constraint in place), then adds explicit trust, invite
/// processing state, and node metadata. Runs with foreign keys disabled,
/// per SQLite's table-rebuild procedure; `init_db` verifies integrity with
/// `PRAGMA foreign_key_check` before committing.
const MIGRATION_V4: &str = r#"
CREATE TABLE channels_v4 (
    channel_id    TEXT PRIMARY KEY,
    channel_name  TEXT,
    channel_type  TEXT NOT NULL CHECK(channel_type IN ('named', 'dm', 'group', 'inbox')),
    mode          TEXT NOT NULL CHECK(mode IN ('realtime', 'batch')),
    access        TEXT NOT NULL CHECK(access IN ('open', 'invite_only')),
    creator_id    BLOB NOT NULL,
    key_version   INTEGER NOT NULL DEFAULT 1,
    psk_hash      BLOB,
    descriptor    BLOB,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    scope         TEXT NOT NULL DEFAULT 'network' CHECK(scope IN ('network', 'local')),
    -- Membership/key epoch: the highest channel-state message applied
    -- (§4.1). States with a lower epoch are stale and ignored; equal
    -- epochs are ordered by author key, so all members converge.
    epoch         INTEGER NOT NULL DEFAULT 0,
    epoch_author  BLOB
);

INSERT INTO channels_v4 (channel_id, channel_name, channel_type, mode, access, creator_id,
                         key_version, psk_hash, descriptor, created_at, updated_at, scope)
    SELECT channel_id, channel_name, channel_type, mode, access, creator_id,
           key_version, psk_hash, descriptor, created_at, updated_at, scope
    FROM channels;

DROP TABLE channels;
ALTER TABLE channels_v4 RENAME TO channels;

CREATE UNIQUE INDEX IF NOT EXISTS idx_channels_name ON channels(channel_name)
    WHERE channel_name IS NOT NULL AND channel_type = 'named';

-- Keys this node trusts to invite it into channels without asking:
-- set by `add-device` and `accept`. A person's other devices are also
-- trusted through membership of the personal channel (not stored here).
CREATE TABLE IF NOT EXISTS trusted_keys (
    entity_key  BLOB PRIMARY KEY,
    kind        TEXT NOT NULL CHECK(kind IN ('device', 'person')),
    label       TEXT,
    added_at    TEXT NOT NULL,
    revoked_at  TEXT
);

-- Processing state for invite items received in this node's inbox.
-- The invite itself stays in `items`; nothing secret is copied here.
CREATE TABLE IF NOT EXISTS invites (
    item_id     TEXT PRIMARY KEY,
    inviter     BLOB NOT NULL,
    channel_id  TEXT NOT NULL,
    status      TEXT NOT NULL
                CHECK(status IN ('pending', 'accepted', 'rejected', 'invalid', 'superseded')),
    received_at TEXT NOT NULL,
    decided_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_invites_status ON invites(status, received_at);

CREATE TABLE IF NOT EXISTS node_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"#;

/// Migration v5: replaceable items and arrival-order sync (decision
/// 2026-09-30-agent-memory-sync §4.3, §4.4a).
///
/// - `seq`: this node's arrival sequence, from a counter that never goes
///   backwards (deleting the newest row must not let a later item reuse its
///   number, or a peer paging by `seq` would skip it). Existing rows take
///   their rowid, which is already in insertion order.
/// - `slot`, `rev`: set together on replaceable items.
const MIGRATION_V5: &str = r#"
ALTER TABLE items ADD COLUMN seq INTEGER;
ALTER TABLE items ADD COLUMN slot BLOB;
ALTER TABLE items ADD COLUMN rev INTEGER;
-- Outbox: when a relay acknowledged storing this node's own item. NULL
-- items authored by this node are re-sent until one does.
ALTER TABLE items ADD COLUMN relayed_at TEXT;
UPDATE items SET seq = rowid;

CREATE TABLE IF NOT EXISTS counters (
    name   TEXT PRIMARY KEY,
    value  INTEGER NOT NULL
);
INSERT OR REPLACE INTO counters (name, value)
    VALUES ('item_seq', (SELECT COALESCE(MAX(seq), 0) FROM items));

CREATE INDEX IF NOT EXISTS idx_items_channel_seq ON items(channel_id, seq);
CREATE INDEX IF NOT EXISTS idx_items_slot ON items(channel_id, slot, author_id)
    WHERE slot IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_items_unrelayed ON items(author_id, seq)
    WHERE relayed_at IS NULL;
"#;

/// Migration v6: sync adapter state (decision 2026-09-30 §4.5). For each
/// local memory folder, channel, and key: what the folder and the channel
/// last agreed on (content hash, or NULL for "deleted", and revision).
const MIGRATION_V6: &str = r#"
CREATE TABLE IF NOT EXISTS sync_files (
    folder      TEXT NOT NULL,
    channel_id  TEXT NOT NULL,
    key         TEXT NOT NULL,
    hash        BLOB,
    rev         INTEGER NOT NULL,
    PRIMARY KEY (folder, channel_id, key)
);
"#;

/// Migration v7: aggregate usage counts for relay operators
/// (`crate::usage`). Peers are stored as a keyed hash, never as a key.
const MIGRATION_V7: &str = r#"
CREATE TABLE IF NOT EXISTS peer_sightings (
    peer_hash   BLOB PRIMARY KEY,
    is_relay    INTEGER NOT NULL DEFAULT 0,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_peer_sightings_last ON peer_sightings(last_seen);
CREATE INDEX IF NOT EXISTS idx_items_received ON items(received_at);
"#;

/// Migration v8: the newest channel state this node has sent to each member
/// of each channel, kept until that member is seen to hold it
/// (`crate::offers`, decision 2026-09-30 §4.1). Times are Unix seconds.
const MIGRATION_V8: &str = r#"
CREATE TABLE IF NOT EXISTS state_offers (
    channel_id      TEXT NOT NULL,
    member          BLOB NOT NULL,
    epoch           INTEGER NOT NULL,
    item_id         TEXT NOT NULL,
    sent_at         INTEGER NOT NULL,
    last_offered_at INTEGER NOT NULL,
    offers          INTEGER NOT NULL DEFAULT 1,
    confirmed_at    INTEGER,
    PRIMARY KEY (channel_id, member)
);
"#;

/// Migration v9: who wrote the entry a folder agreed (decision 2026-09-30
/// §4.5): a device's 32-byte key, or an empty value for nobody. NULL for a
/// row from before, until the folder next records that file.
const MIGRATION_V9: &str = r#"
ALTER TABLE sync_files ADD COLUMN author BLOB;
"#;

/// Migration v10: the memories this device deleted with their index
/// lines (decision 2026-09-30 §4.5, `index_lines`): for each file of a
/// folder, the line this device removed for it and when, when it
/// published the file's delete, whether the two were within an hour of
/// each other, and how many times the line has been put back. Times are
/// seconds, in UTC.
const MIGRATION_V10: &str = r#"
CREATE TABLE index_lines (
    folder      TEXT NOT NULL,
    channel_id  TEXT NOT NULL,
    file        TEXT NOT NULL,
    line        TEXT,
    line_at     INTEGER,
    deleted_at  INTEGER,
    whole       INTEGER NOT NULL DEFAULT 0,
    put_back    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (folder, channel_id, file)
);
"#;

/// Migration v11: entries in the form of a channel from its secret
/// (decision 2026-10-04 §2.3, §2.4, `entries`), beside `items`, which
/// stays as it is. One row for each author in each slot of each channel:
/// the newest revision that author signed there. A channel is known by
/// its ID, and the table refers to no other: a relay stores an entry with
/// no list of members and no state of the channel.
///
/// `seq` is the order in which this node stored its entries, from a
/// counter of its own that never goes backwards, as the arrival order of
/// `items` is. `stored_at` is in seconds, in UTC.
const MIGRATION_V11: &str = r#"
CREATE TABLE entries (
    channel_id   BLOB NOT NULL CHECK(length(channel_id) = 32),
    slot         BLOB NOT NULL CHECK(length(slot) = 32),
    author       BLOB NOT NULL CHECK(length(author) = 32),
    rev          INTEGER NOT NULL CHECK(rev >= 1),
    is_delete    INTEGER NOT NULL CHECK(is_delete IN (0, 1)),
    content      BLOB NOT NULL,
    author_sig   BLOB NOT NULL CHECK(length(author_sig) = 64),
    channel_sig  BLOB NOT NULL CHECK(length(channel_sig) = 64),
    seq          INTEGER NOT NULL,
    stored_at    INTEGER NOT NULL,
    PRIMARY KEY (channel_id, slot, author)
);

CREATE UNIQUE INDEX idx_entries_channel_seq ON entries(channel_id, seq);

INSERT OR IGNORE INTO counters (name, value) VALUES ('entry_seq', 0);
"#;

/// Migration v12: what a device holds of its person (decision 2026-10-04
/// §3 to §6, `person`), beside everything that is there, which stays as it
/// is. It is in the node's database so that it changes in one transaction
/// with a statement (§3).
///
/// - `person`: one row, or none where the device follows no phrase. What
///   it follows (the phrase's public key, the statement key and the ID of
///   the phrase's channel: never the words), the statement it has applied
///   as its signed bytes, and the state it is in.
/// - `person_secrets`: its secrets by statement number. The one it has
///   applied has no time. Each one it left has the time it left it, by
///   its own clock, in seconds.
/// - `person_change_entries`: the latest change entry it has seen, whole,
///   and the one made apart from it where it is in a fork.
/// - `person_additions`: the records of additions it has seen under the
///   applied statement, in the order it saw them, each counted or not.
/// - `person_names`: the names it holds in the current generation, each
///   with its channel's ID, so that either is found from the other.
const MIGRATION_V12: &str = r#"
CREATE TABLE person (
    one             INTEGER PRIMARY KEY CHECK(one = 1),
    state           TEXT NOT NULL
                    CHECK(state IN ('applied', 'fork', 'removed', 'not_listed', 'not_opened')),
    phrase_key      BLOB NOT NULL CHECK(length(phrase_key) = 32),
    statement_key   BLOB NOT NULL CHECK(length(statement_key) = 32),
    phrase_channel  BLOB NOT NULL CHECK(length(phrase_channel) = 32),
    statement       BLOB NOT NULL
);

CREATE TABLE person_secrets (
    number   INTEGER NOT NULL CHECK(number BETWEEN 1 AND 256),
    secret   BLOB NOT NULL CHECK(length(secret) = 32),
    left_at  INTEGER,
    PRIMARY KEY (number, secret)
);

CREATE UNIQUE INDEX idx_person_secrets_applied ON person_secrets((left_at IS NULL))
    WHERE left_at IS NULL;

CREATE TABLE person_change_entries (
    kept            TEXT PRIMARY KEY CHECK(kept IN ('latest', 'apart')),
    channel         BLOB NOT NULL CHECK(length(channel) = 32),
    slot            BLOB NOT NULL CHECK(length(slot) = 32),
    author          BLOB NOT NULL CHECK(length(author) = 32),
    rev             INTEGER NOT NULL CHECK(rev BETWEEN 1 AND 256),
    content         BLOB NOT NULL,
    author_sig      BLOB NOT NULL CHECK(length(author_sig) = 64),
    channel_sig     BLOB NOT NULL CHECK(length(channel_sig) = 64)
);

CREATE TABLE person_additions (
    seen     INTEGER PRIMARY KEY,
    record   BLOB NOT NULL UNIQUE,
    key      BLOB NOT NULL CHECK(length(key) = 32),
    adder    BLOB NOT NULL CHECK(length(adder) = 32),
    counted  INTEGER NOT NULL CHECK(counted IN (0, 1)),
    seen_at  INTEGER NOT NULL
);

CREATE TABLE person_names (
    name     TEXT PRIMARY KEY CHECK(length(name) >= 1),
    channel  BLOB NOT NULL UNIQUE CHECK(length(channel) = 32),
    held_at  INTEGER NOT NULL
);
"#;

/// Run `sql` and set the schema version to `version` as one transaction:
/// both happen, or neither. For a step that cannot be run twice (a column
/// added), so that a start cut short between the two leaves it to be run
/// again from the beginning.
///
/// The version is read again inside the transaction, and the step is not
/// run if the database is already at `version`. The node and a command
/// each open the database for themselves, and two that open it at one
/// moment both read the version from before: the second would otherwise
/// run the step a second time, and fail.
fn migrate_in_one(conn: &Connection, sql: &str, version: u32) -> Result<(), StorageError> {
    conn.execute_batch("BEGIN IMMEDIATE;")?;
    let step = || -> rusqlite::Result<()> {
        let now: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if now >= version {
            return Ok(());
        }
        conn.execute_batch(sql)?;
        conn.pragma_update(None, "user_version", version)
    };
    match step() {
        Ok(()) => Ok(conn.execute_batch("COMMIT;")?),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(e.into())
        }
    }
}

/// Initialise the database: set pragmas and run pending migrations.
pub fn init_db(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;",
    )?;

    let current: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;

    if current < 1 {
        tracing::info!("applying migration v1 (initial schema)");
        conn.execute_batch(MIGRATION_V1)?;
        conn.pragma_update(None, "user_version", 1)?;
    }

    if current < 2 {
        tracing::info!("applying migration v2 (FTS5 search)");
        conn.execute_batch(MIGRATION_V2)?;
        conn.pragma_update(None, "user_version", 2)?;
    }

    if current < 3 {
        tracing::info!("applying migration v3 (channel scope)");
        conn.execute_batch(MIGRATION_V3)?;
        conn.pragma_update(None, "user_version", 3)?;
    }

    if current < 4 {
        tracing::info!("applying migration v4 (device invites)");
        migrate_v4(conn)?;
    }

    if current < 5 {
        tracing::info!("applying migration v5 (replaceable items, arrival order)");
        conn.execute_batch("BEGIN IMMEDIATE;")?;
        match conn
            .execute_batch(MIGRATION_V5)
            .and_then(|_| conn.pragma_update(None, "user_version", 5))
        {
            Ok(()) => conn.execute_batch("COMMIT;")?,
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(e.into());
            }
        }
    }

    if current < 6 {
        tracing::info!("applying migration v6 (sync adapter state)");
        conn.execute_batch(MIGRATION_V6)?;
        conn.pragma_update(None, "user_version", 6)?;
    }

    if current < 7 {
        tracing::info!("applying migration v7 (usage counts)");
        conn.execute_batch(MIGRATION_V7)?;
        conn.pragma_update(None, "user_version", 7)?;
    }

    if current < 8 {
        tracing::info!("applying migration v8 (channel states sent, until confirmed)");
        conn.execute_batch(MIGRATION_V8)?;
        conn.pragma_update(None, "user_version", 8)?;
    }

    if current < 9 {
        tracing::info!("applying migration v9 (who wrote what a folder agreed)");
        migrate_in_one(conn, MIGRATION_V9, 9)?;
    }

    if current < 10 {
        tracing::info!("applying migration v10 (the lines of memories deleted here)");
        migrate_in_one(conn, MIGRATION_V10, 10)?;
    }

    if current < 11 {
        tracing::info!("applying migration v11 (entries of a channel from its secret)");
        migrate_in_one(conn, MIGRATION_V11, 11)?;
    }

    if current < 12 {
        tracing::info!("applying migration v12 (what a device holds of its person)");
        migrate_in_one(conn, MIGRATION_V12, 12)?;
    }

    let actual: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    tracing::debug!(schema_version = actual, "database initialised");

    Ok(())
}

/// Apply migration v4 inside one transaction, with foreign keys disabled
/// for the `channels` rebuild and integrity checked before commit.
fn migrate_v4(conn: &Connection) -> Result<(), StorageError> {
    // PRAGMA foreign_keys is a no-op inside a transaction, so toggle it outside.
    conn.execute_batch("PRAGMA foreign_keys = OFF;")?;

    let result = (|| -> Result<(), StorageError> {
        conn.execute_batch("BEGIN IMMEDIATE;")?;
        conn.execute_batch(MIGRATION_V4)?;

        // Every child row must still reference an existing channel.
        let violations: i64 =
            conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })?;
        if violations > 0 {
            return Err(StorageError::Migration(format!(
                "v4: {violations} foreign key violations after channels rebuild"
            )));
        }

        conn.pragma_update(None, "user_version", 4)?;
        conn.execute_batch("COMMIT;")?;
        Ok(())
    })();

    if result.is_err() {
        let _ = conn.execute_batch("ROLLBACK;");
    }
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_fresh_db() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();

        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn test_init_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        init_db(&conn).unwrap(); // second call should be a no-op

        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn test_tables_exist() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();

        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"channels".to_string()));
        assert!(tables.contains(&"channel_members".to_string()));
        assert!(tables.contains(&"channel_keys".to_string()));
        assert!(tables.contains(&"items".to_string()));
        assert!(tables.contains(&"dm_peers".to_string()));
    }

    #[test]
    fn test_channel_type_check_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();

        let result = conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('test', 'invalid', 'realtime', 'open', X'00', '2026-01-01', '2026-01-01')",
            [],
        );
        assert!(result.is_err());
    }

    // T3-1 (HIGH): mode CHECK constraint
    #[test]
    fn test_mode_check_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        let result = conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('test', 'named', 'invalid_mode', 'open', X'00', '2026-01-01', '2026-01-01')",
            [],
        );
        assert!(result.is_err(), "mode CHECK should reject 'invalid_mode'");
    }

    // T3-1: access CHECK constraint
    #[test]
    fn test_access_check_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        let result = conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('test', 'named', 'realtime', 'invalid_access', X'00', '2026-01-01', '2026-01-01')",
            [],
        );
        assert!(
            result.is_err(),
            "access CHECK should reject 'invalid_access'"
        );
    }

    // T3-1: role CHECK constraint
    #[test]
    fn test_role_check_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('ch1', 'named', 'realtime', 'open', X'00', '2026-01-01', '2026-01-01')",
            [],
        ).unwrap();
        let result = conn.execute(
            "INSERT INTO channel_members (channel_id, entity_id, role, joined_at)
             VALUES ('ch1', X'01', 'superadmin', '2026-01-01')",
            [],
        );
        assert!(result.is_err(), "role CHECK should reject 'superadmin'");
    }

    #[test]
    fn test_scope_check_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        let result = conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, scope, creator_id, created_at, updated_at)
             VALUES ('test_scope', 'named', 'realtime', 'open', 'invalid_scope', X'00', '2026-01-01', '2026-01-01')",
            [],
        );
        assert!(result.is_err(), "scope CHECK should reject 'invalid_scope'");
    }

    #[test]
    fn test_scope_default_is_network() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('test_default_scope', 'named', 'realtime', 'open', X'00', '2026-01-01', '2026-01-01')",
            [],
        ).unwrap();
        let scope: String = conn
            .query_row(
                "SELECT scope FROM channels WHERE channel_id = 'test_default_scope'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(scope, "network");
    }

    #[test]
    fn test_inbox_channel_type_accepted() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('inbox_ab', 'inbox', 'realtime', 'invite_only', X'00', '2026-01-01', '2026-01-01')",
            [],
        )
        .expect("v4 admits the inbox channel type");
    }

    #[test]
    fn test_v4_tables_and_checks() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();

        let bad_kind = conn.execute(
            "INSERT INTO trusted_keys (entity_key, kind, added_at) VALUES (X'01', 'robot', '2026-01-01')",
            [],
        );
        assert!(
            bad_kind.is_err(),
            "trusted_keys.kind CHECK should reject 'robot'"
        );

        let bad_status = conn.execute(
            "INSERT INTO invites (item_id, inviter, channel_id, status, received_at)
             VALUES ('ci_1', X'01', 'grp_x', 'maybe', '2026-01-01')",
            [],
        );
        assert!(
            bad_status.is_err(),
            "invites.status CHECK should reject 'maybe'"
        );

        conn.execute(
            "INSERT INTO node_meta (key, value) VALUES ('personal_channel_id', 'grp_x')",
            [],
        )
        .unwrap();
    }

    /// Upgrading a populated v3 database must keep every row and every
    /// foreign key intact across the `channels` rebuild.
    #[test]
    fn test_upgrade_from_v3_preserves_data() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute_batch(MIGRATION_V1).unwrap();
        conn.execute_batch(MIGRATION_V2).unwrap();
        conn.execute_batch(MIGRATION_V3).unwrap();
        conn.pragma_update(None, "user_version", 3).unwrap();

        conn.execute_batch(
            "INSERT INTO channels (channel_id, channel_name, channel_type, mode, access, creator_id,
                                   key_version, psk_hash, created_at, updated_at, scope)
             VALUES ('named1', 'research', 'named', 'realtime', 'open', X'AA', 2, X'BB',
                     '2026-01-01', '2026-01-02', 'network'),
                    ('grp_1', NULL, 'group', 'batch', 'invite_only', X'AA', 1, NULL,
                     '2026-01-01', '2026-01-01', 'local');
             INSERT INTO channel_members (channel_id, entity_key, role, joined_at)
             VALUES ('named1', X'AA', 'owner', '2026-01-01'),
                    ('grp_1', X'CC', 'member', '2026-01-01');
             INSERT INTO items (item_id, channel_id, author_id, item_type, published_at,
                                content_hash, signature, encrypted_blob, content_length)
             VALUES ('ci_1', 'named1', X'AA', 'message', '2026-01-01', X'01', X'02', X'03', 1);",
        )
        .unwrap();

        init_db(&conn).unwrap();

        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        // v5: existing items got an arrival sequence, and the counter
        // continues after it.
        let (seq, counter): (i64, i64) = conn
            .query_row(
                "SELECT (SELECT seq FROM items WHERE item_id = 'ci_1'),
                        (SELECT value FROM counters WHERE name = 'item_seq')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(seq > 0);
        assert_eq!(counter, seq);

        let fk_on: i64 = conn
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        assert_eq!(fk_on, 1, "foreign keys must be re-enabled after v4");

        let (name, kv, scope): (String, i64, String) = conn
            .query_row(
                "SELECT channel_name, key_version, scope FROM channels WHERE channel_id = 'named1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (name.as_str(), kv, scope.as_str()),
            ("research", 2, "network")
        );

        let counts: (i64, i64, i64) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM channels),
                        (SELECT COUNT(*) FROM channel_members),
                        (SELECT COUNT(*) FROM items)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts, (2, 2, 1));

        let violations: i64 = conn
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(violations, 0);

        // Foreign keys still enforced against the rebuilt table.
        let orphan = conn.execute(
            "INSERT INTO items (item_id, channel_id, author_id, item_type, published_at,
                                content_hash, signature, encrypted_blob, content_length)
             VALUES ('ci_2', 'missing', X'AA', 'message', '2026-01-01', X'04', X'02', X'03', 1)",
            [],
        );
        assert!(
            orphan.is_err(),
            "items.channel_id FK must survive the rebuild"
        );

        // Named-channel uniqueness index was recreated.
        let dup = conn.execute(
            "INSERT INTO channels (channel_id, channel_name, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('named2', 'research', 'named', 'realtime', 'open', X'AA', '2026-01-01', '2026-01-01')",
            [],
        );
        assert!(dup.is_err(), "idx_channels_name must survive the rebuild");
    }

    // T3-1: verify all valid enum values are accepted
    #[test]
    fn test_valid_enum_values_accepted() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        for (i, ct) in ["named", "dm", "group"].iter().enumerate() {
            let id = format!("ch_{i}");
            conn.execute(
                &format!(
                    "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
                     VALUES ('{id}', '{ct}', 'realtime', 'open', X'00', '2026-01-01', '2026-01-01')"
                ),
                [],
            ).unwrap_or_else(|e| panic!("channel_type '{ct}' should be valid: {e}"));
        }
    }

    /// A database at version 8, as the version before this step leaves
    /// it, with what a folder had agreed for two files.
    fn at_v8() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        for sql in [MIGRATION_V1, MIGRATION_V2, MIGRATION_V3] {
            conn.execute_batch(sql).unwrap();
        }
        migrate_v4(&conn).unwrap();
        for sql in [MIGRATION_V5, MIGRATION_V6, MIGRATION_V7, MIGRATION_V8] {
            conn.execute_batch(sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 8).unwrap();
        conn.execute_batch(
            "INSERT INTO sync_files (folder, channel_id, key, hash, rev)
             VALUES ('/m', 'grp_a', 'notes.md', X'07', 2), ('/m', 'grp_a', 'gone.md', NULL, 5);",
        )
        .unwrap();
        conn
    }

    /// The step to version 9 adds a column, which cannot be done twice. The
    /// column and the version change together or not at all, so a start
    /// that fails between the two leaves a database that the next start
    /// takes from the beginning. The rows are kept, and say nothing of
    /// the writer.
    #[test]
    fn test_v9_adds_the_writer_and_its_version_as_one() {
        let conn = at_v8();
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        let has_writer = |conn: &Connection| conn.prepare("SELECT author FROM sync_files").is_ok();

        // The column is added, and then something fails before the version
        // is set.
        let failing = format!("{MIGRATION_V9} SELECT no_such_function();");
        assert!(migrate_in_one(&conn, &failing, 9).is_err());
        assert_eq!(version(&conn), 8);
        assert!(!has_writer(&conn), "the column goes with the version");

        // The next start runs the step from the beginning (and the steps
        // after it).
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        let rows: Vec<(String, i64, Option<Vec<u8>>)> = conn
            .prepare("SELECT key, rev, author FROM sync_files ORDER BY key")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            rows,
            [
                ("gone.md".to_string(), 5, None),
                ("notes.md".to_string(), 2, None)
            ]
        );

        // And a start after that changes nothing.
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert!(has_writer(&conn));

        // Nor does the step itself, asked for again by a process that
        // read the version before another had run it.
        migrate_in_one(&conn, MIGRATION_V9, 9).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
    }

    /// The table of the memories a device deleted is made in one step
    /// with its version, as the step before it is: a failure between the
    /// two leaves neither, and the step asked for twice is run once.
    #[test]
    fn test_v10_adds_the_table_of_lines_and_its_version_as_one() {
        let conn = at_v8();
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        let has_table = |conn: &Connection| conn.prepare("SELECT file FROM index_lines").is_ok();
        migrate_in_one(&conn, MIGRATION_V9, 9).unwrap();

        let failing = format!("{MIGRATION_V10} SELECT no_such_function();");
        assert!(migrate_in_one(&conn, &failing, 10).is_err());
        assert_eq!(version(&conn), 9);
        assert!(!has_table(&conn), "the table goes with the version");

        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert!(has_table(&conn));
        conn.execute(
            "INSERT INTO index_lines (folder, channel_id, file) VALUES ('/m', 'grp_a', 'a.md')",
            [],
        )
        .unwrap();
        // A start after that, and the step asked for again, change nothing.
        init_db(&conn).unwrap();
        migrate_in_one(&conn, MIGRATION_V10, 10).unwrap();
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM index_lines", [], |row| row.get(0))
            .unwrap();
        assert_eq!((version(&conn), rows), (SCHEMA_VERSION, 1));
    }

    /// A database at version 10, as the version before the entries of a
    /// channel from its secret leaves it: with a channel, entries of the
    /// old form in `items`, the counter of their arrival order, what a
    /// folder agreed, and a line.
    fn at_v10() -> Connection {
        let conn = at_v8();
        migrate_in_one(&conn, MIGRATION_V9, 9).unwrap();
        migrate_in_one(&conn, MIGRATION_V10, 10).unwrap();
        conn.execute_batch(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id,
                                   created_at, updated_at)
             VALUES ('grp_a', 'group', 'realtime', 'invite_only', X'AA',
                     '2026-01-01', '2026-01-01');
             INSERT INTO items (item_id, channel_id, author_id, item_type, published_at,
                                content_hash, signature, encrypted_blob, content_length,
                                seq, slot, rev)
             VALUES ('ci_1', 'grp_a', X'AA', 'memory', '2026-01-01', X'01', X'02', X'03', 1,
                     41, X'0505', 3),
                    ('ci_2', 'grp_a', X'BB', 'memory', '2026-01-02', X'04', X'05', X'0607', 2,
                     42, X'0505', 4);
             UPDATE counters SET value = 42 WHERE name = 'item_seq';
             INSERT INTO index_lines (folder, channel_id, file, line, line_at)
             VALUES ('/m', 'grp_a', 'gone.md', '- [Gone](gone.md)', 1800000000);",
        )
        .unwrap();
        conn
    }

    /// Everything a database holds but the new table and its index: each
    /// table's definition, and each row of the tables an older binary
    /// wrote. What a later step adds is left out too: the tables of what
    /// a device holds of its person.
    fn held_before_v11(conn: &Connection) -> Vec<String> {
        let mut held: Vec<String> = conn
            .prepare(
                "SELECT name || ': ' || COALESCE(sql, '') FROM sqlite_master
                 WHERE name NOT IN ('entries', 'idx_entries_channel_seq')
                   AND name NOT LIKE 'sqlite_autoindex_entries%'
                   AND name NOT LIKE '%person%'
                 ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for rows in [
            "SELECT item_id || channel_id || hex(author_id) || item_type || published_at
                 || is_tombstone || hex(content_hash) || hex(signature) || hex(encrypted_blob)
                 || content_length || seq || hex(slot) || rev FROM items ORDER BY item_id",
            "SELECT channel_id || channel_type || scope || epoch FROM channels",
            "SELECT name || value FROM counters WHERE name != 'entry_seq'",
            "SELECT folder || channel_id || key || COALESCE(hex(hash), '') || rev FROM sync_files
                 ORDER BY key",
            "SELECT folder || channel_id || file || line || line_at FROM index_lines",
        ] {
            let rows: Vec<String> = conn
                .prepare(rows)
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert!(!rows.is_empty());
            held.extend(rows);
        }
        held
    }

    /// The table of entries is made in one step with its version and the
    /// counter of its order, as the steps before it are: a failure between
    /// them leaves none, and the step asked for twice is run once.
    #[test]
    fn test_v11_adds_the_table_of_entries_and_its_version_as_one() {
        let conn = at_v10();
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        let has_table = |conn: &Connection| conn.prepare("SELECT rev FROM entries").is_ok();
        let counter = |conn: &Connection| -> Option<i64> {
            conn.query_row(
                "SELECT value FROM counters WHERE name = 'entry_seq'",
                [],
                |row| row.get(0),
            )
            .ok()
        };
        assert_eq!(version(&conn), 10);
        assert!(!has_table(&conn));

        let failing = format!("{MIGRATION_V11} SELECT no_such_function();");
        assert!(migrate_in_one(&conn, &failing, 11).is_err());
        assert_eq!(version(&conn), 10);
        assert!(!has_table(&conn), "the table goes with the version");
        assert_eq!(counter(&conn), None, "and so does its counter");

        // The next start runs the step from the beginning.
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert!(has_table(&conn));
        assert_eq!(counter(&conn), Some(0));

        // A start after that, and the step asked for again, change
        // nothing: the counter stays where storing has brought it.
        conn.execute("UPDATE counters SET value = 7 WHERE name = 'entry_seq'", [])
            .unwrap();
        init_db(&conn).unwrap();
        migrate_in_one(&conn, MIGRATION_V11, 11).unwrap();
        assert_eq!((version(&conn), counter(&conn)), (SCHEMA_VERSION, Some(7)));
    }

    /// A database at version 10 that an older binary wrote is taken to
    /// version 11 with everything it held as it was: the step adds a
    /// table, an index and a counter, and touches nothing else. Entries of
    /// the old form stay in `items`, and none is moved to the new table.
    #[test]
    fn test_a_database_at_v10_that_an_older_binary_wrote_is_taken_to_v11() {
        let conn = at_v10();
        let before = held_before_v11(&conn);
        assert!(before.iter().any(|row| row.starts_with("items: ")));
        assert!(before.iter().any(|row| row.starts_with("ci_2grp_a")));

        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        assert_eq!(version(&conn), 10);

        // The step by itself, and then a start, which has no more to do
        // for it.
        migrate_in_one(&conn, MIGRATION_V11, 11).unwrap();
        assert_eq!(version(&conn), 11);
        assert_eq!(held_before_v11(&conn), before);
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(held_before_v11(&conn), before);

        // What is new: the table, with nothing in it, its index, and its
        // counter beside the old one.
        let new: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE name IN ('entries', 'idx_entries_channel_seq') ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(new, ["entries", "idx_entries_channel_seq"]);
        let (entries, entry_seq, item_seq): (i64, i64, i64) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM entries),
                        (SELECT value FROM counters WHERE name = 'entry_seq'),
                        (SELECT value FROM counters WHERE name = 'item_seq')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((entries, entry_seq, item_seq), (0, 0, 42));

        // The old table is written as before, by its own counter.
        conn.execute_batch(
            "UPDATE counters SET value = value + 1 WHERE name = 'item_seq';
             INSERT INTO items (item_id, channel_id, author_id, item_type, published_at,
                                content_hash, signature, encrypted_blob, content_length, seq)
             VALUES ('ci_3', 'grp_a', X'AA', 'memory', '2026-01-03', X'08', X'02', X'03', 1, 43);",
        )
        .unwrap();
        let (items, entry_seq): (i64, i64) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM items),
                        (SELECT value FROM counters WHERE name = 'entry_seq')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((items, entry_seq), (3, 0));
    }

    /// A database at version 11, as the version before what a device
    /// holds of its person leaves it: what [`at_v10`] holds, and an entry
    /// in the new form with the counter of its order.
    fn at_v11() -> Connection {
        let conn = at_v10();
        migrate_in_one(&conn, MIGRATION_V11, 11).unwrap();
        conn.execute_batch(
            "UPDATE counters SET value = 9 WHERE name = 'entry_seq';
             INSERT INTO entries (channel_id, slot, author, rev, is_delete, content,
                                  author_sig, channel_sig, seq, stored_at)
             VALUES (zeroblob(32), zeroblob(32), zeroblob(32), 7, 0, X'0A0B',
                     zeroblob(64), zeroblob(64), 9, 1800000000);",
        )
        .unwrap();
        conn
    }

    /// The tables and the index that the step to version 12 adds.
    const NEW_IN_V12: [&str; 6] = [
        "idx_person_secrets_applied",
        "person",
        "person_additions",
        "person_change_entries",
        "person_names",
        "person_secrets",
    ];

    /// Everything a database at version 11 holds: each table's definition
    /// but those of the step to version 12, and each row of every table an
    /// older binary wrote, the entries of the new form among them.
    fn held_before_v12(conn: &Connection) -> Vec<String> {
        let mut held = held_before_v11(conn);
        for rows in [
            "SELECT name || ': ' || COALESCE(sql, '') FROM sqlite_master
                 WHERE name IN ('entries', 'idx_entries_channel_seq')
                    OR name LIKE 'sqlite_autoindex_entries%' ORDER BY name",
            "SELECT hex(channel_id) || hex(slot) || hex(author) || rev || is_delete
                 || hex(content) || hex(author_sig) || hex(channel_sig) || seq || stored_at
                 FROM entries",
            "SELECT name || value FROM counters ORDER BY name",
        ] {
            let rows: Vec<String> = conn
                .prepare(rows)
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert!(!rows.is_empty());
            held.extend(rows);
        }
        held
    }

    /// What a database holds of the step to version 12, by name.
    fn new_in_v12(conn: &Connection) -> Vec<String> {
        conn.prepare(
            "SELECT name FROM sqlite_master
             WHERE name LIKE '%person%' AND name NOT LIKE 'sqlite_autoindex%' ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    /// The tables of what a device holds of its person are made in one
    /// step with their version, as the steps before it are: a failure
    /// between them leaves none, and the step asked for twice is run once.
    #[test]
    fn test_v12_adds_what_a_device_holds_of_its_person_and_its_version_as_one() {
        let conn = at_v11();
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        assert_eq!(version(&conn), 11);
        assert!(new_in_v12(&conn).is_empty());

        let failing = format!("{MIGRATION_V12} SELECT no_such_function();");
        assert!(migrate_in_one(&conn, &failing, 12).is_err());
        assert_eq!(version(&conn), 11);
        assert!(
            new_in_v12(&conn).is_empty(),
            "the tables go with the version"
        );

        // The next start runs the step from the beginning.
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), 12);
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(new_in_v12(&conn), NEW_IN_V12);

        // A start after that, and the step asked for again, change
        // nothing: what the device holds stays.
        conn.execute(
            "INSERT INTO person_names (name, channel, held_at) VALUES ('team', zeroblob(32), 7)",
            [],
        )
        .unwrap();
        init_db(&conn).unwrap();
        migrate_in_one(&conn, MIGRATION_V12, 12).unwrap();
        let names: i64 = conn
            .query_row("SELECT COUNT(*) FROM person_names", [], |row| row.get(0))
            .unwrap();
        assert_eq!((version(&conn), names), (SCHEMA_VERSION, 1));
    }

    /// A database at version 11 that an older binary wrote is taken to
    /// version 12 with everything it held as it was: the step adds five
    /// tables and an index, with nothing in them, and touches nothing
    /// else. A device that takes this version follows no phrase.
    #[test]
    fn test_a_database_at_v11_that_an_older_binary_wrote_is_taken_to_v12() {
        let conn = at_v11();
        let before = held_before_v12(&conn);
        assert!(before.iter().any(|row| row.starts_with("entries: ")));
        assert!(before.iter().any(|row| row.starts_with("entry_seq9")));
        assert!(before.iter().any(|row| row.starts_with("ci_2grp_a")));

        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        assert_eq!(version(&conn), 11);

        // The step by itself, and then a start, which has no more to do
        // for it.
        migrate_in_one(&conn, MIGRATION_V12, 12).unwrap();
        assert_eq!(version(&conn), 12);
        assert_eq!(held_before_v12(&conn), before);
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(held_before_v12(&conn), before);

        // What is new: the tables, with nothing in them, and the index.
        assert_eq!(new_in_v12(&conn), NEW_IN_V12);
        for table in NEW_IN_V12.iter().filter(|name| !name.starts_with("idx_")) {
            let rows: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "{table}");
        }

        // The store of entries is written as before, by its own counter.
        conn.execute_batch(
            "UPDATE counters SET value = value + 1 WHERE name = 'entry_seq';
             INSERT INTO entries (channel_id, slot, author, rev, is_delete, content,
                                  author_sig, channel_sig, seq, stored_at)
             VALUES (zeroblob(32), zeroblob(32),
                     X'0101010101010101010101010101010101010101010101010101010101010101',
                     8, 0, X'0C', zeroblob(64), zeroblob(64), 10, 1800000001);",
        )
        .unwrap();
        let entries: i64 = conn
            .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(entries, 2);
    }
}
