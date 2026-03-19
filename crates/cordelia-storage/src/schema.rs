//! SQLite schema definitions and migrations.
//!
//! Spec: seed-drill/specs/data-formats.md §3, §5

use rusqlite::Connection;

use crate::StorageError;

/// Current schema version (incremented per migration).
pub const SCHEMA_VERSION: u32 = 3;

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

    let actual: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    tracing::debug!(schema_version = actual, "database initialised");

    Ok(())
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
        let scope: String = conn.query_row(
            "SELECT scope FROM channels WHERE channel_id = 'test_default_scope'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(scope, "network");
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
