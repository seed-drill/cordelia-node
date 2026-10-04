//! SQLite schema definitions and migrations.
//!
//! Spec: seed-drill/specs/data-formats.md §3, §5

use rusqlite::Connection;

use crate::StorageError;

/// Current schema version (incremented per migration).
pub const SCHEMA_VERSION: u32 = 9;

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

/// Migration v9: a text that a folder has kept beside a file (decision
/// 2026-09-30 §4.5). For each file that is still to take a version of the
/// channel's: the conflict file its text was kept in, the version it was
/// kept against, the hash of the text, and the entry the channel has under
/// the conflict file's name: the one that was there when it was written,
/// and then the one its folder published it as. The row goes when the file
/// is replaced or removed, and when the file and the channel next agree.
const MIGRATION_V9: &str = r#"
CREATE TABLE IF NOT EXISTS sync_kept (
    folder      TEXT NOT NULL,
    channel_id  TEXT NOT NULL,
    key         TEXT NOT NULL,
    version     TEXT NOT NULL,
    copy        TEXT NOT NULL,
    hash        BLOB NOT NULL,
    under       TEXT,
    PRIMARY KEY (folder, channel_id, key)
);
"#;

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
        tracing::info!("applying migration v9 (texts kept beside a file)");
        conn.execute_batch(MIGRATION_V9)?;
        conn.pragma_update(None, "user_version", 9)?;
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
}
