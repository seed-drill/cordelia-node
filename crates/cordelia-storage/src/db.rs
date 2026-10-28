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

/// Turn SQLite's automatic checkpoint off on this connection, and keep
/// its log's file at RELAY_LOG_KEPT_BYTES once the log starts again
/// (issue #224): a relay's node sets it where it opens its store.
/// Otherwise the checkpoint runs inside whichever commit crosses about
/// 1,000 pages of log, and the request that made that commit pays for it
/// with the lock held. A connection with it off checkpoints on a timer of
/// its own ([`checkpoint_passive`]).
pub fn automatic_checkpoint_off(conn: &Connection) -> Result<(), StorageError> {
    conn.pragma_update(None, "wal_autocheckpoint", 0)?;
    conn.pragma_update(
        None,
        "journal_size_limit",
        cordelia_core::protocol::RELAY_LOG_KEPT_BYTES,
    )?;
    Ok(())
}

/// The pages this connection has written to its write-ahead log since the
/// count was last cleared, clearing it where `clear` (issue #224): SQLite's
/// own count of the pages a connection writes, which in write-ahead mode
/// are the log's frames (SQLITE_DBSTATUS_CACHE_WRITE). A relay's timer
/// reads it to checkpoint only once the log holds
/// RELAY_CHECKPOINT_LOG_PAGES, and clears it when a checkpoint writes the
/// log back whole: the next commit starts the log again.
pub fn log_pages_written(conn: &Connection, clear: bool) -> Result<u64, StorageError> {
    use rusqlite::ffi;
    let (mut now, mut most) = (0, 0);
    // SAFETY: the handle is this connection's, open for as long as `conn`
    // is borrowed; sqlite3_db_status writes the two integers it is given
    // and nothing else.
    let rc = unsafe {
        ffi::sqlite3_db_status(
            conn.handle(),
            ffi::SQLITE_DBSTATUS_CACHE_WRITE,
            &mut now,
            &mut most,
            i32::from(clear),
        )
    };
    if rc != ffi::SQLITE_OK {
        return Err(rusqlite::Error::SqliteFailure(ffi::Error::new(rc), None).into());
    }
    Ok(u64::try_from(now).unwrap_or(0))
}

/// Write the write-ahead log back into the database file, as much of it
/// as no reader holds, without waiting for a reader (issue #224): SQLite's
/// passive checkpoint, which calls no busy handler. Returns whether the
/// log was written back whole. The log's file is not truncated here: the
/// next commit after a whole one starts the log again from its start,
/// over what the file holds, and cuts the file to RELAY_LOG_KEPT_BYTES
/// where it is longer ([`automatic_checkpoint_off`]). Where a reader in
/// another process holds a part of the log, the rest is written back, and
/// the next checkpoint, once the reader is gone, writes back what is
/// left.
pub fn checkpoint_passive(conn: &Connection) -> Result<bool, StorageError> {
    let (busy, log, written): (i64, i64, i64) =
        conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    Ok(busy == 0 && log == written)
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

    fn wal_bytes(path: &Path) -> u64 {
        std::fs::metadata(path.with_extension("db-wal")).map_or(0, |file| file.len())
    }

    /// With the automatic checkpoint off (issue #224), the log grows past
    /// the 1,000 pages at which SQLite would have checkpointed inside a
    /// commit; with it on, as a store is opened, it does not. A passive
    /// checkpoint then writes it back whole, and the next commit starts the
    /// log again over its file, which is shorter than RELAY_LOG_KEPT_BYTES
    /// and so kept.
    #[test]
    fn with_the_automatic_checkpoint_off_no_commit_checkpoints() {
        use cordelia_core::protocol::RELAY_LOG_KEPT_BYTES;
        let dir = tempfile::tempdir().unwrap();
        let insert = |conn: &Connection, i: usize, value: &str| {
            conn.execute(
                "INSERT INTO node_meta (key, value) VALUES (?1, ?2)",
                rusqlite::params![format!("k{i}"), value],
            )
            .unwrap();
        };
        let grown = |off: bool| -> (i64, i64, u64, Connection, std::path::PathBuf) {
            let path = dir.path().join(format!("{off}.db"));
            let conn = open(&path).unwrap();
            if off {
                automatic_checkpoint_off(&conn).unwrap();
            }
            let pragma = |name: &str| -> i64 {
                conn.pragma_query_value(None, name, |row| row.get(0))
                    .unwrap()
            };
            let (every, kept, page) = (
                pragma("wal_autocheckpoint"),
                pragma("journal_size_limit"),
                pragma("page_size") as u64,
            );
            let value = "v".repeat(page as usize);
            for i in 0..1_500 {
                insert(&conn, i, &value);
            }
            (every, kept, wal_bytes(&path) / page, conn, path)
        };
        let (every, kept, pages, _, _) = grown(false);
        assert_eq!((every, kept), (1000, -1));
        assert!(pages < 1_500, "the automatic checkpoint ran: {pages}");
        let (every, kept, pages, conn, path) = grown(true);
        assert_eq!((every, kept), (0, RELAY_LOG_KEPT_BYTES));
        assert!(pages > 3_000, "a commit checkpointed: {pages} pages");
        let before = wal_bytes(&path);
        assert!(checkpoint_passive(&conn).unwrap());
        assert_eq!(
            wal_bytes(&path),
            before,
            "a passive checkpoint cuts nothing"
        );
        insert(&conn, 1_500, "w");
        assert!(before < RELAY_LOG_KEPT_BYTES as u64);
        assert_eq!(wal_bytes(&path), before, "the log starts again in place");
    }

    /// Writes `bytes` of log in one transaction, in rows of a page each,
    /// with keys from `from`.
    fn log_of(conn: &Connection, from: usize, bytes: u64) {
        let page: u64 = conn
            .pragma_query_value(None, "page_size", |row| row.get(0))
            .unwrap();
        let value = "v".repeat(page as usize);
        conn.execute_batch("BEGIN").unwrap();
        for i in 0..bytes / page {
            conn.execute(
                "INSERT INTO node_meta (key, value) VALUES (?1, ?2)",
                rusqlite::params![format!("k{}", from as u64 + i), value],
            )
            .unwrap();
        }
        conn.execute_batch("COMMIT").unwrap();
    }

    /// A log as long as a second's at a thousand pushes a second (27 MiB,
    /// issue #224), written back whole, keeps its file when the next commit
    /// starts it again: the next second's commits write over it and do not
    /// grow it. A log longer than RELAY_LOG_KEPT_BYTES, as one a reader
    /// held for long, is cut back to it.
    #[test]
    fn a_seconds_log_keeps_its_file_and_a_longer_one_is_cut() {
        use cordelia_core::protocol::RELAY_LOG_KEPT_BYTES;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cordelia.db");
        let conn = open(&path).unwrap();
        automatic_checkpoint_off(&conn).unwrap();
        let one = |key: &str| {
            conn.execute("INSERT INTO node_meta (key, value) VALUES (?1, 'w')", [key])
                .unwrap();
        };
        log_of(&conn, 0, 27 << 20);
        let second = wal_bytes(&path);
        assert!(second > 27 << 20);
        assert!(checkpoint_passive(&conn).unwrap());
        one("after the second");
        assert_eq!(wal_bytes(&path), second, "the log's file was cut");

        log_of(&conn, 1 << 20, RELAY_LOG_KEPT_BYTES as u64 + (8 << 20));
        assert!(wal_bytes(&path) > RELAY_LOG_KEPT_BYTES as u64);
        assert!(checkpoint_passive(&conn).unwrap());
        one("after the long one");
        assert!(wal_bytes(&path) <= RELAY_LOG_KEPT_BYTES as u64);
    }

    /// The pages written to the log are counted from the connection's
    /// start, as the log's frames are: a commit of a row a page long adds
    /// at least a page, a read adds none, and a clear starts the count
    /// again (issue #224).
    #[test]
    fn the_pages_written_to_the_log_are_counted_and_cleared() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cordelia.db");
        let conn = open(&path).unwrap();
        automatic_checkpoint_off(&conn).unwrap();
        assert!(checkpoint_truncating(&conn).unwrap());
        log_pages_written(&conn, true).unwrap();
        assert_eq!(log_pages_written(&conn, false).unwrap(), 0);
        log_of(&conn, 0, 400 * 4096);
        let page: u64 = conn
            .pragma_query_value(None, "page_size", |row| row.get(0))
            .unwrap();
        let frames = (wal_bytes(&path) - 32) / (page + 24);
        let written = log_pages_written(&conn, false).unwrap();
        assert!(written >= 400, "{written}");
        assert_eq!(written, frames, "the count is the log's frames");
        let _: i64 = conn
            .query_row("SELECT count(*) FROM node_meta", [], |row| row.get(0))
            .unwrap();
        assert_eq!(log_pages_written(&conn, true).unwrap(), written);
        assert_eq!(log_pages_written(&conn, false).unwrap(), 0);
    }

    /// A passive checkpoint answers at once where a reader holds the log,
    /// whatever the busy timeout (issue #224); once the reader is gone,
    /// the next writes it back whole.
    #[test]
    fn a_passive_checkpoint_answers_at_once_while_a_reader_holds_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cordelia.db");
        let conn = open(&path).unwrap();
        automatic_checkpoint_off(&conn).unwrap();
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        conn.execute(
            "INSERT INTO node_meta (key, value) VALUES ('a.setting', 'one')",
            [],
        )
        .unwrap();
        let reader = Connection::open(&path).unwrap();
        reader.execute_batch("BEGIN").unwrap();
        let _: String = reader
            .query_row("SELECT value FROM node_meta", [], |row| row.get(0))
            .unwrap();
        conn.execute("UPDATE node_meta SET value = 'two'", [])
            .unwrap();

        let started = std::time::Instant::now();
        assert!(!checkpoint_passive(&conn).unwrap(), "a reader holds it");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "it waited {:?}",
            started.elapsed()
        );
        reader.execute_batch("COMMIT").unwrap();
        drop(reader);
        assert!(checkpoint_passive(&conn).unwrap(), "the reader is gone");
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
