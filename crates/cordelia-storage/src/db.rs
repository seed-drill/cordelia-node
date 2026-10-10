//! Database connection management.

use rusqlite::Connection;
use std::path::Path;

use crate::StorageError;
use crate::schema;

/// Open (or create) the Cordelia database and run migrations.
pub fn open(path: &Path) -> Result<Connection, StorageError> {
    open_as(path, false)
}

/// Open (or create) the Cordelia database and run migrations, with
/// `secure_delete` set on the connection first where `secure_delete` is
/// true ([`secure_delete_on`]), as a personal node opens it: a step that
/// rewrites a table then writes zeros over what it frees (decision
/// 2026-10-09 §7.1).
pub fn open_as(path: &Path, secure_delete: bool) -> Result<Connection, StorageError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    if secure_delete {
        secure_delete_on(&conn)?;
    }
    schema::init_db(&conn)?;
    Ok(conn)
}

/// Have SQLite write zeros over the content of every row this connection
/// deletes or moves, in every table (decision 2026-10-09 §7.1, D10). The
/// node sets it on a personal node's connection where it opens its store,
/// and on no relay's: it is a pragma of the connection and not a step of
/// the schema, so a relay pays nothing for it.
pub fn secure_delete_on(conn: &Connection) -> Result<(), StorageError> {
    conn.pragma_update(None, "secure_delete", true)?;
    Ok(())
}

/// Write the write-ahead log back into the database file and truncate it
/// (decision 2026-10-09 §7.1): a personal node runs it after each hourly
/// clearing, so that a body overwritten in its row does not stand in the
/// log for longer than an hour. Returns whether the log was written back
/// whole: a reader that holds the database open can keep a part of it,
/// which the next checkpoint writes back.
pub fn checkpoint_truncating(conn: &Connection) -> Result<bool, StorageError> {
    let busy: i64 = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
    Ok(busy == 0)
}

/// Open an in-memory database with schema initialised: for testing, and
/// for what a command reads in its own process and keeps in no file.
pub fn open_in_memory() -> Result<Connection, StorageError> {
    let conn = Connection::open_in_memory()?;
    schema::init_db(&conn)?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_file_db() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cordelia.db");
        let conn = open(&path).unwrap();

        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, schema::SCHEMA_VERSION);
    }

    #[test]
    fn test_open_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("dir").join("cordelia.db");
        let _conn = open(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn test_open_in_memory() {
        let _conn = open_in_memory().unwrap();
    }

    /// The truncating checkpoint answers whether it wrote the log back
    /// whole and truncated it (decision 2026-10-09 §7.1): while a reader
    /// on another connection holds a read transaction, it cannot, and
    /// says so; once that reader is gone, it does.
    #[test]
    fn the_truncating_checkpoint_answers_false_while_a_reader_holds_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cordelia.db");
        let conn = open(&path).unwrap();
        conn.busy_timeout(std::time::Duration::ZERO).unwrap();
        conn.execute(
            "INSERT INTO node_meta (key, value) VALUES ('a.setting', 'one')",
            [],
        )
        .unwrap();

        let reader = Connection::open(&path).unwrap();
        reader.execute_batch("BEGIN").unwrap();
        let read: String = reader
            .query_row(
                "SELECT value FROM node_meta WHERE key = 'a.setting'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(read, "one");
        conn.execute(
            "UPDATE node_meta SET value = 'two' WHERE key = 'a.setting'",
            [],
        )
        .unwrap();
        assert!(!checkpoint_truncating(&conn).unwrap(), "a reader holds it");

        reader.execute_batch("COMMIT").unwrap();
        drop(reader);
        assert!(checkpoint_truncating(&conn).unwrap(), "the reader is gone");
        assert_eq!(
            std::fs::metadata(path.with_extension("db-wal"))
                .unwrap()
                .len(),
            0
        );
    }

    fn secure_delete(conn: &Connection) -> i64 {
        conn.pragma_query_value(None, "secure_delete", |row| row.get(0))
            .unwrap()
    }

    /// A store opened by its schema alone, as a relay's is, has no
    /// `secure_delete` (decision 2026-10-09 §7.1): it is not a step. Set
    /// on, it writes zeros over a row deleted from any table, not the
    /// index's alone, and the truncating checkpoint leaves nothing of it
    /// in the file or the log. Without it a deleted row's text stays in
    /// the file.
    #[test]
    fn a_store_has_secure_delete_only_where_it_is_set_and_then_in_every_table() {
        let words = "the value of a setting, petrel-anchovy-saffron";
        let dir = tempfile::tempdir().unwrap();
        let in_file = |path: &Path| -> bool {
            let bytes = std::fs::read(path).unwrap();
            bytes.windows(words.len()).any(|at| at == words.as_bytes())
        };
        let deleted = |conn: &Connection, path: &Path| -> bool {
            conn.execute(
                "INSERT INTO node_meta (key, value) VALUES ('a.setting', ?1)",
                [words],
            )
            .unwrap();
            assert!(checkpoint_truncating(conn).unwrap());
            assert!(in_file(path));
            conn.execute("DELETE FROM node_meta WHERE key = 'a.setting'", [])
                .unwrap();
            assert!(checkpoint_truncating(conn).unwrap());
            assert_eq!(
                std::fs::metadata(path.with_extension("db-wal"))
                    .unwrap()
                    .len(),
                0
            );
            in_file(path)
        };

        let relay = dir.path().join("relay.db");
        let conn = open(&relay).unwrap();
        assert_eq!(secure_delete(&conn), 0);
        assert!(deleted(&conn, &relay), "a delete leaves the text");
        drop(conn);
        assert_eq!(secure_delete(&open(&relay).unwrap()), 0);

        let personal = dir.path().join("personal.db");
        let conn = open(&personal).unwrap();
        secure_delete_on(&conn).unwrap();
        assert_eq!(secure_delete(&conn), 1);
        assert!(!deleted(&conn, &personal), "a delete leaves nothing");
    }
}
