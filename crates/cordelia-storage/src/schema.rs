//! The schema: one baseline, and the steps after it (decision 2026-11-10
//! (older kind), rule 5).
//!
//! **The baseline is alpha.19's schema, exactly** ([`BASELINE`], made from
//! that release's own database): what its 33 steps left, at step 33. What
//! each of its tables holds is said where those steps made them:
//! <https://github.com/seed-drill/cordelia-node/blob/c3cc5756/crates/cordelia-storage/src/schema.rs>.
//! **Step 34 drops the older kind of channel** ([`STEP_34`]). A new
//! database runs the baseline, then step 34.
//!
//! **Only alpha.19's database or a new one is taken** (rules 4 and 6): one
//! at steps 1 to 32 is refused, as one from a later version is, before
//! any pragma is set, and nothing of it is changed.
//!
//! Spec: seed-drill/specs/data-formats.md §3, §5

use std::time::Instant;

use rusqlite::Connection;

use crate::StorageError;

/// The schema's version: the last step's number.
pub const SCHEMA_VERSION: u32 = 34;

/// The step that alpha.19's schema, the baseline, is at.
pub const ALPHA_19_VERSION: u32 = 33;

/// alpha.19's schema, and the rows its steps put in an empty database
/// (decision 2026-11-10 (older kind), rule 5). It was made from alpha.19's
/// own `cordelia init`, as the file's head says how; a test checks it
/// against what that binary makes. Never edited: a change is a step.
pub const BASELINE: &str = include_str!("baseline.sql");

/// Step 34: the older kind of channel goes (decision 2026-11-10 (older
/// kind), rules 1 and 5). Its tables are dropped, children first and
/// `channels` last, as they refer to it with foreign keys on; each
/// table's triggers and indexes go with it, the guard that a personal
/// node's first start set on `channels` among them. Then the counters of
/// `items`, and the keys of `node_meta` that only the older kind and the
/// first start read. `sync.claude.last_change` and `sync.claude.activity`
/// stay: the sync loop uses them.
const STEP_34: &str = r#"
DROP TABLE channel_members;
DROP TABLE channel_keys;
DROP TABLE dm_peers;
DROP TABLE items;
DROP TABLE search_content;
DROP TABLE search_fts;
DROP TABLE invites;
DROP TABLE state_offers;
DROP TABLE trusted_keys;
DROP TABLE channels;

DELETE FROM counters WHERE name GLOB 'item_*';

DELETE FROM node_meta WHERE key IN (
    'personal_channel_id',
    'membership.accepted_personal_from',
    'first_start.done',
    'sync.claude.all',
    'sync.claude.notice'
);
"#;

/// Run `sql` and set the schema version to `version` as one transaction:
/// both happen, or neither. So a start cut short between the two leaves
/// it to be run again from the beginning.
///
/// The version is read again inside the transaction, and the step is not
/// run if the database is already at `version`. The node and a command
/// each open the database for themselves, and two that open it at one
/// moment, a new file among them, both read the version from before: the
/// second would otherwise run the step a second time, and fail.
fn migrate_in_one(conn: &Connection, sql: &str, version: u32) -> Result<(), StorageError> {
    conn.execute_batch("BEGIN IMMEDIATE;")?;
    let step = || -> rusqlite::Result<()> {
        if version_of(conn)? >= version {
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

/// The schema's version that the database says it is at.
fn version_of(conn: &Connection) -> rusqlite::Result<u32> {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
}

/// Initialise the database: set pragmas and run the steps it has not had.
///
/// **A database from a later version is refused** (decision 2026-10-04
/// §10.1): one whose version is above this schema's was written by a
/// later version of the program, which may keep in it what this one
/// would not know to keep. **So is one from before alpha.19** (decision
/// 2026-11-10 (older kind), rule 6): this version takes over only
/// alpha.19's ([`refuse_an_earlier_version`]). The version is read before
/// anything else is done, and nothing is changed: no pragma is set, and
/// no step is run. Whoever opens the database is told the versions
/// ([`StorageError::LaterVersion`], [`StorageError::EarlierVersion`]).
pub fn init_db(conn: &Connection) -> Result<(), StorageError> {
    refuse_a_later_version(conn, SCHEMA_VERSION)?;
    refuse_an_earlier_version(conn)?;
    pragmas(conn)?;
    let current = version_of(conn)?;
    if current < ALPHA_19_VERSION {
        tracing::info!("making a new database: alpha.19's schema, then the steps after it");
        migrate_in_one(conn, BASELINE, ALPHA_19_VERSION)
            .map_err(|e| failed(ALPHA_19_VERSION, e))?;
    }
    if current < 34 {
        // Timed, so that the step can be timed on a copy of a relay's
        // database before a release (decision 2026-11-10 (older kind), §8).
        let began = Instant::now();
        migrate_in_one(conn, STEP_34, 34).map_err(|e| failed(34, e))?;
        tracing::info!(
            ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX),
            "applied schema step 34 (the older kind of channel dropped)"
        );
    }
    Ok(())
}

/// What is said of step `step` that did not finish, with why, where the
/// disk is full or could not be written (decision 2026-11-10 (older kind),
/// rule 9): SQLite's `SQLITE_FULL` and `SQLITE_IOERR`, with their extended
/// codes. A node is held for these until its next start. Any other error,
/// a busy lock among them, goes on as it is: the node stops, and a service
/// starts it again.
fn failed(step: u32, e: StorageError) -> StorageError {
    use rusqlite::ErrorCode::{DiskFull, SystemIoFailure};
    match e {
        StorageError::Sqlite(rusqlite::Error::SqliteFailure(found, ref said))
            if matches!(found.code, DiskFull | SystemIoFailure) =>
        {
            let why = said.clone().unwrap_or_else(|| found.to_string());
            StorageError::StepFailed { step, why }
        }
        e => e,
    }
}

/// The pragmas of every connection to the database: write-ahead logging,
/// and foreign keys checked.
fn pragmas(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;",
    )?;
    Ok(())
}

/// Refuse a database whose version is above `own`, as a schema at version
/// `own` refuses it.
fn refuse_a_later_version(conn: &Connection, own: u32) -> Result<(), StorageError> {
    let found = version_of(conn)?;
    if found > own {
        return Err(StorageError::LaterVersion { found, own });
    }
    Ok(())
}

/// Refuse a database from a Cordelia before alpha.19 (decision 2026-11-10
/// (older kind), rules 4 and 6): one at steps 1 to 32, or at no step with
/// anything in it. Only alpha.19's, at step 33, is taken over, and a new
/// one made: a file with nothing in it, at no step, is new.
///
/// The version and whether the file holds anything are read in one
/// statement, so in one snapshot: another process that makes a new file
/// at the same moment is seen whole, or not at all.
fn refuse_an_earlier_version(conn: &Connection) -> Result<(), StorageError> {
    let (found, holds_something): (u32, bool) = conn.query_row(
        "SELECT user_version, EXISTS (SELECT 1 FROM sqlite_master) FROM pragma_user_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let earlier = match found {
        0 => holds_something,
        found => found < ALPHA_19_VERSION,
    };
    if earlier {
        return Err(StorageError::EarlierVersion { found });
    }
    Ok(())
}

/// Make `conn`, a database with nothing in it, one as alpha.19 left it:
/// the pragmas, and the baseline, at step 33, and no step after. For a
/// test of what this version does with alpha.19's database.
pub fn init_db_as_alpha_19(conn: &Connection) -> Result<(), StorageError> {
    pragmas(conn)?;
    migrate_in_one(conn, BASELINE, ALPHA_19_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(conn: &Connection) -> u32 {
        version_of(conn).unwrap()
    }

    /// The tables of the older kind of channel, which step 34 drops, in
    /// its order.
    const OLDER_TABLES: [&str; 10] = [
        "channel_members",
        "channel_keys",
        "dm_peers",
        "items",
        "search_content",
        "search_fts",
        "invites",
        "state_offers",
        "trusted_keys",
        "channels",
    ];

    /// The keys of `node_meta` that step 34 removes.
    const OLDER_KEYS: [&str; 5] = [
        "personal_channel_id",
        "membership.accepted_personal_from",
        "first_start.done",
        "sync.claude.all",
        "sync.claude.notice",
    ];

    /// Each definition a database holds, as type, name, table and text,
    /// sorted.
    fn definitions(conn: &Connection) -> Vec<String> {
        let mut found: Vec<String> = conn
            .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master")
            .unwrap()
            .query_map([], |row| {
                Ok(format!(
                    "{}|{}|{}|{}",
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?.unwrap_or_default()
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        found.sort();
        found
    }

    /// Each row of each of the tables named, as text, by table.
    fn rows_of(conn: &Connection, tables: &[String]) -> Vec<String> {
        let mut found = Vec::new();
        for table in tables {
            let mut rows: Vec<String> = conn
                .prepare(&format!("SELECT * FROM \"{table}\""))
                .unwrap()
                .query_map([], |row| {
                    use rusqlite::types::ValueRef;
                    let mut cells = Vec::new();
                    for at in 0..row.as_ref().column_count() {
                        cells.push(match row.get_ref(at)? {
                            ValueRef::Text(text) => format!("{:?}", String::from_utf8_lossy(text)),
                            other => format!("{other:?}"),
                        });
                    }
                    Ok(format!("{table}: {}", cells.join(", ")))
                })
                .unwrap()
                .map(Result::unwrap)
                .collect();
            rows.sort();
            found.extend(rows);
        }
        found
    }

    /// The ordinary tables a database holds, but those named.
    fn tables_but(conn: &Connection, left_out: &[&str]) -> Vec<String> {
        conn.prepare(
            "SELECT name FROM pragma_table_list WHERE schema = 'main' AND type = 'table' \
             AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .filter(|name| !left_out.contains(&name.as_str()))
        .collect()
    }

    #[test]
    fn test_init_fresh_db() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
    }

    #[test]
    fn test_init_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        init_db(&conn).unwrap(); // second call should be a no-op
        assert_eq!(version(&conn), SCHEMA_VERSION);
    }

    /// A new database is the baseline and then step 34 (decision
    /// 2026-11-10 (older kind), rule 5): it holds nothing of the older
    /// kind, no table, trigger, counter or key, and everything else that
    /// alpha.19's schema holds.
    #[test]
    fn a_new_database_is_the_baseline_and_then_step_34() {
        let new = Connection::open_in_memory().unwrap();
        init_db(&new).unwrap();
        let alpha_19 = Connection::open_in_memory().unwrap();
        init_db_as_alpha_19(&alpha_19).unwrap();
        assert_eq!((version(&new), version(&alpha_19)), (34, 33));

        let of_the_older_kind = |definition: &String| {
            let table = definition.split('|').nth(2).unwrap();
            OLDER_TABLES.contains(&table) || table.starts_with("search_fts_")
        };
        let kept: Vec<String> = definitions(&alpha_19)
            .into_iter()
            .filter(|definition| !of_the_older_kind(definition))
            .collect();
        assert_eq!(definitions(&new), kept);
        assert!(definitions(&alpha_19).iter().any(of_the_older_kind));
        for table in ["entries", "person", "relay_channels", "shared_follows"] {
            assert!(
                kept.iter()
                    .any(|d| d.starts_with(&format!("table|{table}|")))
            );
        }

        let counters: Vec<(String, i64)> = new
            .prepare("SELECT name, value FROM counters")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(counters, [("entry_seq".to_string(), 0)]);
        let marks: i64 = new
            .query_row("SELECT COUNT(*) FROM person_clear_mark", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(marks, 1);
    }

    /// alpha.19's database, at step 33, holding rows of the older kind and
    /// of every key step 34 removes, as a device or a relay held them, with
    /// the guard that a personal node's first start set on `channels`; and
    /// rows that stay, of the new kind and of settings.
    fn alpha_19_holding_the_older_kind(path: &std::path::Path) {
        let conn = Connection::open(path).unwrap();
        init_db_as_alpha_19(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id,
                                   created_at, updated_at)
                 VALUES ('grp_older', 'group', 'batch', 'open', zeroblob(32), 't', 't');
             INSERT INTO channel_members (channel_id, entity_key, role, joined_at)
                 VALUES ('grp_older', zeroblob(32), 'owner', 't');
             INSERT INTO channel_keys (channel_id, encrypted_psk)
                 VALUES ('grp_older', zeroblob(48));
             INSERT INTO items (item_id, channel_id, author_id, item_type, published_at,
                                content_hash, signature, encrypted_blob, content_length,
                                seq)
                 VALUES ('ci_one', 'grp_older', zeroblob(32), 'memory', 't', zeroblob(32),
                         zeroblob(64), zeroblob(40), 40, 1);
             UPDATE counters SET value = 1 WHERE name = 'item_seq';
             INSERT INTO search_content (item_id, channel_id, item_type, published_at, name)
                 VALUES ('ci_one', 'grp_older', 'memory', 't', 'a word');
             INSERT INTO invites (item_id, inviter, channel_id, status, received_at)
                 VALUES ('ci_two', zeroblob(32), 'grp_older', 'pending', 't');
             INSERT INTO state_offers (channel_id, member, epoch, item_id, sent_at,
                                       last_offered_at)
                 VALUES ('grp_older', zeroblob(32), 1, 'ci_three', 1, 1);
             INSERT INTO trusted_keys (entity_key, kind, added_at)
                 VALUES (zeroblob(32), 'device', 't');
             INSERT INTO entries (channel_id, slot, author, rev, is_delete, content,
                                  author_sig, channel_sig, seq, stored_at, channel_place)
                 VALUES (zeroblob(32), zeroblob(32), zeroblob(32), 1, 0, X'01',
                         zeroblob(64), zeroblob(64), 1, 1, 1);
             UPDATE counters SET value = 1 WHERE name = 'entry_seq';
             INSERT INTO node_meta (key, value) VALUES
                 ('personal_channel_id', 'grp_older'),
                 ('membership.accepted_personal_from', 'a key'),
                 ('first_start.done', 'stepped by 0.2.0-alpha.19'),
                 ('sync.claude.all', 'off'),
                 ('sync.claude.notice', '[]'),
                 ('sync.claude.dir', '/home/a/.claude'),
                 ('sync.claude.last_change', '2026-11-09T10:00:00Z'),
                 ('sync.claude.activity', '{\"notes\": {}}');
             CREATE TRIGGER moved_on_takes_no_channel BEFORE INSERT ON channels BEGIN
                 SELECT RAISE(ABORT, 'this database was moved on');
             END;",
        )
        .unwrap();
        let count = |sql: &str| -> i64 { conn.query_row(sql, [], |row| row.get(0)).unwrap() };
        assert_eq!(
            count("SELECT value FROM counters WHERE name = 'item_count'"),
            1
        );
        assert_eq!(count("SELECT COUNT(*) FROM search_fts"), 1);
    }

    /// Step 34 takes over alpha.19's database (decision 2026-11-10 (older
    /// kind), rule 5): each table of the older kind goes, with its
    /// triggers, the guard among them, and with the counters of `items`
    /// and the keys only the older kind and the first start read. Every
    /// other definition and row stays as it was, `sync.claude.last_change`
    /// and `sync.claude.activity` among them.
    #[test]
    fn step_34_drops_the_older_kind_and_keeps_everything_else() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cordelia.db");
        alpha_19_holding_the_older_kind(&path);
        let (kept_definitions, kept_rows) = {
            let conn = Connection::open(&path).unwrap();
            let older = |definition: &String| {
                let table = definition.split('|').nth(2).unwrap();
                OLDER_TABLES.contains(&table) || table.starts_with("search_fts_")
            };
            let mut tables = tables_but(&conn, &OLDER_TABLES);
            tables.retain(|table| !table.starts_with("search_fts_"));
            let rows: Vec<String> = rows_of(&conn, &tables)
                .into_iter()
                .filter(|row| {
                    !row.starts_with("counters: \"item_")
                        && !OLDER_KEYS
                            .iter()
                            .any(|key| row.starts_with(&format!("node_meta: \"{key}\",")))
                })
                .collect();
            let definitions: Vec<String> = definitions(&conn)
                .into_iter()
                .filter(|definition| !older(definition))
                .collect();
            (definitions, rows)
        };

        let conn = crate::db::open(&path).unwrap();
        assert_eq!(version(&conn), 34);
        assert_eq!(definitions(&conn), kept_definitions);
        let tables = tables_but(&conn, &[]);
        assert!(
            tables
                .iter()
                .all(|table| !OLDER_TABLES.contains(&table.as_str())
                    && !table.starts_with("search_fts")),
            "{tables:?}"
        );
        assert_eq!(rows_of(&conn, &tables), kept_rows);
        let kept_keys: Vec<String> = conn
            .prepare("SELECT key FROM node_meta ORDER BY key")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            kept_keys,
            [
                "sync.claude.activity",
                "sync.claude.dir",
                "sync.claude.last_change"
            ]
        );
        let counters: Vec<String> = conn
            .prepare("SELECT name FROM counters")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(counters, ["entry_seq"]);
        // Again: nothing more.
        drop(conn);
        let conn = crate::db::open(&path).unwrap();
        assert_eq!(definitions(&conn), kept_definitions);
    }

    /// Two that open a new database at one moment both read it as at no
    /// step: the second to step finds each step made, inside its
    /// transaction, and makes none again.
    #[test]
    fn a_new_database_opened_twice_at_once_is_made_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cordelia.db");
        let first = Connection::open(&path).unwrap();
        let second = Connection::open(&path).unwrap();
        assert_eq!((version(&first), version(&second)), (0, 0));
        init_db(&first).unwrap();
        // The second goes on as it would have, having read no step.
        pragmas(&second).unwrap();
        migrate_in_one(&second, BASELINE, ALPHA_19_VERSION).unwrap();
        migrate_in_one(&second, STEP_34, 34).unwrap();
        assert_eq!(version(&second), SCHEMA_VERSION);
        assert_eq!(definitions(&first), definitions(&second));
    }

    /// A database from a later version, or from a Cordelia before alpha.19,
    /// is refused, by whoever opens it, with its version named, and
    /// nothing of it is changed (decision 2026-10-04 §10.1; decision
    /// 2026-11-10 (older kind), rule 6): not its version, not a row, not
    /// the way it is journalled, not a byte of its file. Before alpha.19 is
    /// any step from 1 to 32, alpha.18's 32 and alpha.8's 10 among them,
    /// and no step with something in it. A new file, and one at this
    /// schema's version or alpha.19's, is opened.
    #[test]
    fn test_a_database_from_a_later_or_an_earlier_version_is_refused_and_not_changed() {
        let dir = tempfile::tempdir().unwrap();
        let later = SCHEMA_VERSION + 1;
        for found in [later, 32, 10, 1, 0] {
            let path = dir.path().join(format!("at-{found}.db"));
            {
                let conn = Connection::open(&path).unwrap();
                match found {
                    // alpha.18's: alpha.19's schema, but for what its step
                    // 33 added, at step 32.
                    32 => init_db_as_alpha_19(&conn).unwrap(),
                    _ => conn
                        .execute_batch(
                            "PRAGMA journal_mode = DELETE;
                             CREATE TABLE of_another_version (what TEXT);
                             INSERT INTO of_another_version VALUES ('kept');",
                        )
                        .unwrap(),
                }
                conn.execute_batch("PRAGMA journal_mode = DELETE;").unwrap();
                conn.pragma_update(None, "user_version", found).unwrap();
            }
            let before = std::fs::read(&path).unwrap();

            let refused = match crate::db::open(&path) {
                Err(e) => e,
                Ok(_) => panic!("a database at step {found} was opened"),
            };
            let says = refused.to_string();
            match found {
                _ if found == later => {
                    assert!(
                        matches!(refused, StorageError::LaterVersion { found, own }
                            if found == later && own == SCHEMA_VERSION),
                        "{refused:?}"
                    );
                    assert!(
                        says.contains(&format!("schema version {later}"))
                            && says.contains(&format!("schema version {SCHEMA_VERSION} "))
                            && says.contains("nothing was changed"),
                        "{says}"
                    );
                }
                _ => {
                    assert!(
                        matches!(refused, StorageError::EarlierVersion { found: f } if f == found),
                        "{refused:?}"
                    );
                    assert!(
                        says.contains(&format!("schema step {found},"))
                            && says.contains("before 0.2.0-alpha.19")
                            && says.contains("changed nothing"),
                        "{says}"
                    );
                }
            }
            assert_eq!(std::fs::read(&path).unwrap(), before, "{found}");
            let conn = Connection::open(&path).unwrap();
            assert!(init_db(&conn).is_err(), "{found}");
            let journal: String = conn
                .pragma_query_value(None, "journal_mode", |row| row.get(0))
                .unwrap();
            assert_eq!((version(&conn), journal.as_str()), (found, "delete"));
            drop(conn);
            assert_eq!(std::fs::read(&path).unwrap(), before, "{found}");
        }

        // A new file, and one at alpha.19's step or at this schema's:
        // opened, and nothing refused.
        let new = dir.path().join("new.db");
        drop(std::fs::File::create(&new).unwrap());
        drop(crate::db::open(&new).unwrap());
        assert!(crate::db::open(&new).is_ok());
        let alpha_19 = dir.path().join("alpha-19.db");
        init_db_as_alpha_19(&Connection::open(&alpha_19).unwrap()).unwrap();
        assert_eq!(
            version(&crate::db::open(&alpha_19).unwrap()),
            SCHEMA_VERSION
        );
    }

    /// A step that does not finish changes nothing: the database is at
    /// the step before, with every table it had (decision 2026-11-10
    /// (older kind), rule 9). Here a trigger stops the step's last write,
    /// an error that is neither a full disk nor one of I/O: it goes on as
    /// it is, and is not a step that did not finish for want of room.
    #[test]
    fn a_step_that_does_not_finish_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cordelia.db");
        {
            let conn = Connection::open(&path).unwrap();
            init_db_as_alpha_19(&conn).unwrap();
            conn.execute_batch(
                "INSERT INTO node_meta (key, value) VALUES ('personal_channel_id', 'grp_x');
                 CREATE TRIGGER step_34_cannot_finish BEFORE DELETE ON node_meta
                 BEGIN SELECT RAISE(ABORT, 'stopped'); END;",
            )
            .unwrap();
        }
        let before = definitions(&Connection::open(&path).unwrap());
        let refused = match crate::db::open(&path) {
            Err(e) => e,
            Ok(_) => panic!("the step finished"),
        };
        assert!(
            matches!(&refused, StorageError::Sqlite(e) if e.to_string().contains("stopped")),
            "{refused:?}"
        );
        let conn = Connection::open(&path).unwrap();
        assert_eq!(version(&conn), ALPHA_19_VERSION);
        assert_eq!(definitions(&conn), before);
    }

    /// Only a full disk, or a write or read that failed, is a step that did
    /// not finish for want of room (rule 9): `SQLITE_FULL` and
    /// `SQLITE_IOERR`, with their extended codes. A busy lock, and any
    /// other error, goes on as it is.
    #[test]
    fn only_a_full_disk_or_an_io_error_is_a_step_that_did_not_finish() {
        use rusqlite::ffi;
        let sqlite = |code: i32| {
            StorageError::Sqlite(rusqlite::Error::SqliteFailure(ffi::Error::new(code), None))
        };
        for code in [ffi::SQLITE_FULL, ffi::SQLITE_IOERR, ffi::SQLITE_IOERR_WRITE] {
            assert!(
                matches!(
                    failed(34, sqlite(code)),
                    StorageError::StepFailed { step: 34, .. }
                ),
                "{code}"
            );
        }
        let full = failed(34, sqlite(ffi::SQLITE_FULL));
        assert!(full.to_string().contains("database is full"), "{full}");
        for code in [
            ffi::SQLITE_BUSY,
            ffi::SQLITE_LOCKED,
            ffi::SQLITE_CONSTRAINT_TRIGGER,
        ] {
            assert!(
                matches!(failed(34, sqlite(code)), StorageError::Sqlite(_)),
                "{code}"
            );
        }
        assert!(matches!(
            failed(34, StorageError::Migration("x".into())),
            StorageError::Migration(_)
        ));
    }

    /// A store opened as a personal node opens it has `secure_delete` on
    /// before the schema's steps run (decision 2026-10-09 §7.1): step 34,
    /// which drops the older kind's tables, leaves nothing of what they
    /// held in the file. Opened as a relay's is, it stays in pages that
    /// are free.
    #[test]
    fn step_34_writes_zeros_where_the_store_is_opened_so() {
        let words = "an item of grebe-tamarind-cobalt";
        let dir = tempfile::tempdir().unwrap();
        let held_after_the_steps = |name: &str, secure_delete: bool| -> usize {
            let path = dir.path().join(name);
            let at_33 = Connection::open(&path).unwrap();
            init_db_as_alpha_19(&at_33).unwrap();
            at_33
                .execute_batch(
                    "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id,
                                           created_at, updated_at)
                     VALUES ('c', 'group', 'batch', 'open', zeroblob(32), 't', 't');",
                )
                .unwrap();
            at_33
                .execute(
                    "INSERT INTO items (item_id, channel_id, author_id, item_type,
                                        published_at, content_hash, signature,
                                        encrypted_blob, content_length)
                     VALUES ('i', 'c', zeroblob(32), 'memory', 't', zeroblob(32),
                             zeroblob(64), ?1, 32)",
                    [words.as_bytes()],
                )
                .unwrap();
            drop(at_33);

            let conn = crate::db::open_as(&path, secure_delete).unwrap();
            assert_eq!(version(&conn), SCHEMA_VERSION);
            assert!(crate::db::checkpoint_truncating(&conn).unwrap());
            let bytes = std::fs::read(&path).unwrap();
            bytes
                .windows(words.len())
                .filter(|at| *at == words.as_bytes())
                .count()
        };
        assert_eq!(held_after_the_steps("relay.db", false), 1);
        assert_eq!(held_after_the_steps("personal.db", true), 0);
    }

    /// The text of what alpha.19's steps made for `tables`: each table's,
    /// with its indexes' and triggers', as the baseline keeps it.
    fn made_for(tables: &[&str]) -> String {
        let conn = Connection::open_in_memory().unwrap();
        init_db_as_alpha_19(&conn).unwrap();
        let mut texts = Vec::new();
        for table in tables {
            let mut found: Vec<String> = conn
                .prepare(
                    "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL AND tbl_name = ?1 \
                     ORDER BY rowid",
                )
                .unwrap()
                .query_map([table], |row| row.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert!(!found.is_empty(), "{table}");
            texts.append(&mut found);
        }
        texts.join("\n")
    }

    /// The tables of messages between the person's own agents, which
    /// alpha.19's step 19 made (decision 2026-10-09).
    const STEP_19_TABLES: [&str; 14] = [
        "message_generations",
        "message_index",
        "message_numbers",
        "message_first_held",
        "message_signers",
        "message_places",
        "message_lists",
        "message_read_here",
        "message_announced",
        "message_read_by_a_person",
        "message_sends",
        "message_kept",
        "message_kept_numbers",
        "message_kept_taken",
    ];

    /// The bounds that step 19 wrote as numbers in its SQL are those of
    /// protocol.rs (decision 2026-10-09 §2.2, §2.3): a value's length, the
    /// highest number of a message, and the highest statement. Each is
    /// written where a column takes it, and nowhere with another value.
    #[test]
    fn step_19s_bounds_are_those_of_protocol_rs() {
        use cordelia_core::protocol::{
            AGENT_MESSAGE_NUMBER_MAX, AGENT_MESSAGE_VALUE_BYTES, MAX_STATEMENT_NUMBER,
        };
        let made = made_for(&STEP_19_TABLES);
        let count = |text: &str| made.matches(text).count();
        assert_eq!(
            count(&format!("length(value) = {AGENT_MESSAGE_VALUE_BYTES})")),
            1
        );
        assert_eq!(count("length(value)"), 1);
        assert_eq!(count(&format!("number <= {AGENT_MESSAGE_NUMBER_MAX})")), 3);
        assert_eq!(count(&format!("highest <= {AGENT_MESSAGE_NUMBER_MAX})")), 1);
        assert_eq!(count(&AGENT_MESSAGE_NUMBER_MAX.to_string()), 4);
        assert_eq!(count(&format!("statement <= {MAX_STATEMENT_NUMBER})")), 1);
        assert_eq!(count("statement <="), 1);
        assert_eq!(count("counted_from <= highest"), 1);
    }

    /// The bounds that step 27 wrote as numbers in its SQL are those of
    /// protocol.rs (decision 2026-10-10 §3.4): a list's value at every
    /// bound and an empty list, a revision's most, and the last statement.
    #[test]
    fn the_bounds_of_step_27_are_those_of_protocol_rs() {
        use cordelia_core::protocol::{MAX_REV, MAX_STATEMENT_NUMBER, SHARED_LIST_MAX_VALUE_BYTES};
        let made = made_for(&["shared_lists", "shared_list_taken"]);
        let count = |text: &str| made.matches(text).count();
        assert_eq!(
            count(&format!("length(list) <= {SHARED_LIST_MAX_VALUE_BYTES})")),
            1
        );
        assert_eq!(count(&SHARED_LIST_MAX_VALUE_BYTES.to_string()), 1);
        // An empty list: its form and four counts of nothing.
        assert_eq!(count("length(list) >= 5 "), 1);
        assert_eq!(count(&format!("rev <= {MAX_REV})")), 1);
        assert_eq!(count(&format!("generation <= {MAX_STATEMENT_NUMBER})")), 1);
    }

    /// The bounds that step 28 wrote as numbers in its SQL are those of
    /// protocol.rs (decision 2026-10-10 §2.1, §2.3, §6.3): a card of one
    /// relay and of two, a name at its longest, a revision kept below the
    /// half of band 0, and a message's highest number.
    #[test]
    fn step_28s_bounds_are_those_of_protocol_rs() {
        use cordelia_core::protocol::{
            AGENT_MESSAGE_NAME_MAX_BYTES, AGENT_MESSAGE_NUMBER_MAX, REV_BAND_HALF,
            SHARED_MAX_RELAYS, SHARED_SEED_BYTES,
        };
        let made = made_for(&[
            "shared_channels",
            "shared_keys",
            "shared_unopened",
            "shared_labelled",
            "shared_index",
            "shared_numbers",
            "shared_first_held",
            "shared_signers",
            "shared_places",
        ]);
        let count = |text: &str| made.matches(text).count();
        let card = |relays: usize| SHARED_SEED_BYTES + 1 + 32 * relays;
        assert_eq!(SHARED_MAX_RELAYS, 2);
        assert_eq!(
            count(&format!("length(card) IN ({}, {}))", card(1), card(2))),
            1
        );
        assert_eq!(
            count(&format!(
                "length(CAST(name AS BLOB)) <= {AGENT_MESSAGE_NAME_MAX_BYTES})"
            )),
            1
        );
        assert_eq!(count(&format!("_rev < {REV_BAND_HALF}))")), 2);
        assert_eq!(count(&REV_BAND_HALF.to_string()), 2);
        assert_eq!(count(&format!("number <= {AGENT_MESSAGE_NUMBER_MAX})")), 2);
        assert_eq!(count(&format!("highest <= {AGENT_MESSAGE_NUMBER_MAX})")), 1);
    }

    /// The bound that step 29 wrote as a number in its SQL is that of
    /// protocol.rs: a revision of a shared channel is below the half of
    /// band 0.
    #[test]
    fn the_bounds_of_step_29_are_those_of_protocol_rs() {
        use cordelia_core::protocol::REV_BAND_HALF;
        let made = made_for(&[
            "shared_relay_places",
            "shared_relay_sent",
            "shared_take_out_channels",
            "shared_take_out_keys",
        ]);
        let count = |text: &str| made.matches(text).count();
        assert_eq!(count(&format!("rev < {REV_BAND_HALF})")), 1);
        assert_eq!(count(&REV_BAND_HALF.to_string()), 1);
    }

    /// Each column of step 19 takes only its type and its bound (decision
    /// 2026-10-09 §9.2): a channel's ID, a signer, a key, a mark, an ID, a
    /// thread, an answer, a relay and a value are blobs of their length,
    /// and a text of that length is refused; every count, number and time
    /// is an integer, and a real or a text is refused; a statement's
    /// number is at most the highest statement; `counted_from` is at most
    /// `highest`; and a flag is 0 or 1 as an integer. Each refused value
    /// is taken in its place where it is of its type.
    #[test]
    fn step_19s_columns_take_only_their_type_and_their_bound() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        let id = "X'01010101010101010101010101010101'";
        conn.execute_batch(&format!(
            "INSERT INTO message_generations (id, channel, statement, first_held)
                 VALUES (1, zeroblob(32), 1, 8);
             INSERT INTO message_index (id, signer, label, generation, to_kind, to_name,
                                        from_name, sent, subject, thread, answers, asks,
                                        link, body, first_held, placed_at)
                 VALUES ({id}, zeroblob(32), 'laptop', 1, 1, 'notes', '~', 9, 'a',
                         zeroblob(16), zeroblob(16), 0, NULL, 'a', 9, NULL);
             INSERT INTO message_kept (id, generation, value, sent, kept_at)
                 VALUES ({id}, 1, zeroblob(1936), 9, 9);"
        ))
        .unwrap();
        let text = |bytes: usize| format!("'{}'", "a".repeat(bytes));
        let other = "X'03030303030303030303030303030303'";
        let index = |at: usize, value: &str| -> String {
            let mut values = [
                other.to_string(),
                "zeroblob(32)".into(),
                "'laptop'".into(),
                "1".into(),
                "1".into(),
                "'notes'".into(),
                "'~'".into(),
                "9".into(),
                "'a'".into(),
                "zeroblob(16)".into(),
                "zeroblob(16)".into(),
                "0".into(),
                "NULL".into(),
                "'a'".into(),
                "9".into(),
                "NULL".into(),
            ];
            values[at] = value.to_string();
            format!(
                "INSERT INTO message_index (id, signer, label, generation, to_kind, to_name,
                                            from_name, sent, subject, thread, answers, asks,
                                            link, body, first_held, placed_at)
                 VALUES ({})",
                values.join(", ")
            )
        };
        // Each: what is refused, and the same row with a value of its type
        // and bound, which is taken and then taken out again.
        let cases: Vec<(String, String, &str)> = vec![
            (
                format!(
                    "INSERT INTO message_generations (channel, statement, first_held)
                     VALUES ({}, 1, 9)",
                    text(32)
                ),
                format!(
                    "INSERT INTO message_generations (channel, statement, first_held)
                     VALUES (X'{}', 1, 9)",
                    "05".repeat(32)
                ),
                "DELETE FROM message_generations WHERE id <> 1",
            ),
            (
                format!(
                    "INSERT INTO message_generations (channel, statement, first_held)
                     VALUES (X'{}', 257, 9)",
                    "05".repeat(32)
                ),
                format!(
                    "INSERT INTO message_generations (channel, statement, first_held)
                     VALUES (X'{}', 256, 9)",
                    "05".repeat(32)
                ),
                "DELETE FROM message_generations WHERE id <> 1",
            ),
            (
                format!(
                    "INSERT INTO message_generations (channel, statement, first_held)
                     VALUES (X'{}', 1.5, 9)",
                    "05".repeat(32)
                ),
                format!(
                    "INSERT INTO message_generations (channel, statement, first_held)
                     VALUES (X'{}', 2, 9)",
                    "05".repeat(32)
                ),
                "DELETE FROM message_generations WHERE id <> 1",
            ),
            (
                format!(
                    "INSERT INTO message_generations (channel, statement, first_held)
                     VALUES (X'{}', 1, 'soon')",
                    "05".repeat(32)
                ),
                format!(
                    "INSERT INTO message_generations (channel, statement, first_held)
                     VALUES (X'{}', 1, 10)",
                    "05".repeat(32)
                ),
                "DELETE FROM message_generations WHERE id <> 1",
            ),
            (
                index(0, &text(16)),
                index(0, other),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(1, &text(32)),
                index(1, "zeroblob(32)"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(9, &text(16)),
                index(9, "zeroblob(16)"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(10, &text(16)),
                index(10, "zeroblob(16)"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(7, "9.5"),
                index(7, "10"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(11, "'1'||'x'"),
                index(11, "1"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(11, "0.5"),
                index(11, "1"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(14, "'then'"),
                index(14, "9"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(15, "10.5"),
                index(15, "10"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(3, "'1'||'x'"),
                index(3, "1"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                format!(
                    "INSERT INTO message_numbers (signer, generation, number, id)
                     VALUES (zeroblob(32), 1, 2.5, {id})"
                ),
                format!(
                    "INSERT INTO message_numbers (signer, generation, number, id)
                     VALUES (zeroblob(32), 1, 2, {id})"
                ),
                "DELETE FROM message_numbers",
            ),
            (
                format!(
                    "INSERT INTO message_numbers (signer, generation, number, id)
                     VALUES ({}, 1, 2, {id})",
                    text(32)
                ),
                format!(
                    "INSERT INTO message_numbers (signer, generation, number, id)
                     VALUES (zeroblob(32), 1, 2, {id})"
                ),
                "DELETE FROM message_numbers",
            ),
            (
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2, {}, 9, 9)",
                    text(16)
                ),
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2, {id}, 9, 9)"
                ),
                "DELETE FROM message_first_held",
            ),
            (
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2, {id}, 9.5, 9)"
                ),
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2, {id}, 9, 9)"
                ),
                "DELETE FROM message_first_held",
            ),
            (
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES ({}, 1, 2, {id}, 9, 9)",
                    text(32)
                ),
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2, {id}, 9, 9)"
                ),
                "DELETE FROM message_first_held",
            ),
            (
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2.5, {id}, 9, 9)"
                ),
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2, {id}, 9, 9)"
                ),
                "DELETE FROM message_first_held",
            ),
            (
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2, {id}, 9, 'then')"
                ),
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2, {id}, 9, 9)"
                ),
                "DELETE FROM message_first_held",
            ),
            (
                format!(
                    "INSERT INTO message_signers (signer, generation, highest)
                     VALUES ({}, 1, 5)",
                    text(32)
                ),
                "INSERT INTO message_signers (signer, generation, highest)
                 VALUES (zeroblob(32), 1, 5)"
                    .into(),
                "DELETE FROM message_signers",
            ),
            (
                "INSERT INTO message_signers (signer, generation, highest, counted_from)
                 VALUES (zeroblob(32), 1, 5, 4.5)"
                    .into(),
                "INSERT INTO message_signers (signer, generation, highest, counted_from)
                 VALUES (zeroblob(32), 1, 5, 4)"
                    .into(),
                "DELETE FROM message_signers",
            ),
            (
                "INSERT INTO message_signers (signer, generation, highest, counted_from)
                 VALUES (zeroblob(32), 1, 5, 6)"
                    .into(),
                "INSERT INTO message_signers (signer, generation, highest, counted_from)
                 VALUES (zeroblob(32), 1, 5, 5)"
                    .into(),
                "DELETE FROM message_signers",
            ),
            (
                "INSERT INTO message_signers (signer, generation, highest)
                 VALUES (zeroblob(32), 1, 5.5)"
                    .into(),
                "INSERT INTO message_signers (signer, generation, highest)
                 VALUES (zeroblob(32), 1, 5)"
                    .into(),
                "DELETE FROM message_signers",
            ),
            (
                "INSERT INTO message_signers (signer, generation, highest, overwritten)
                 VALUES (zeroblob(32), 1, 5, 'many')"
                    .into(),
                "INSERT INTO message_signers (signer, generation, highest, overwritten)
                 VALUES (zeroblob(32), 1, 5, 7)"
                    .into(),
                "DELETE FROM message_signers",
            ),
            (
                "INSERT INTO message_signers (signer, generation, highest, not_messages)
                 VALUES (zeroblob(32), 1, 5, 0.5)"
                    .into(),
                "INSERT INTO message_signers (signer, generation, highest, not_messages)
                 VALUES (zeroblob(32), 1, 5, 1)"
                    .into(),
                "DELETE FROM message_signers",
            ),
            (
                format!(
                    "INSERT INTO message_places (signer, generation, placed_at)
                     VALUES ({}, 1, 10)",
                    text(32)
                ),
                "INSERT INTO message_places (signer, generation, placed_at)
                 VALUES (zeroblob(32), 1, 10)"
                    .into(),
                "DELETE FROM message_places",
            ),
            (
                "INSERT INTO message_places (signer, generation, placed_at)
                 VALUES (zeroblob(32), 1, 10.5)"
                    .into(),
                "INSERT INTO message_places (signer, generation, placed_at)
                 VALUES (zeroblob(32), 1, 10)"
                    .into(),
                "DELETE FROM message_places",
            ),
            (
                format!(
                    "INSERT INTO message_lists (key, mark) VALUES ({}, zeroblob(16))",
                    text(32)
                ),
                "INSERT INTO message_lists (key, mark) VALUES (zeroblob(32), zeroblob(16))".into(),
                "DELETE FROM message_lists",
            ),
            (
                format!(
                    "INSERT INTO message_lists (key, mark) VALUES (zeroblob(32), {})",
                    text(16)
                ),
                "INSERT INTO message_lists (key, mark) VALUES (zeroblob(32), zeroblob(16))".into(),
                "DELETE FROM message_lists",
            ),
            (
                format!(
                    "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                     VALUES ({}, 1, 8, 9)",
                    text(16)
                ),
                "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (zeroblob(16), 1, 8, 9)"
                    .into(),
                "DELETE FROM message_read_here",
            ),
            (
                "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (zeroblob(16), 1.5, 8, 9)"
                    .into(),
                "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (zeroblob(16), 1, 8, 9)"
                    .into(),
                "DELETE FROM message_read_here",
            ),
            (
                "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (zeroblob(16), 1, 8, 'then')"
                    .into(),
                "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (zeroblob(16), 1, 8, 9)"
                    .into(),
                "DELETE FROM message_read_here",
            ),
            (
                "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (zeroblob(16), 1, 8.5, 9)"
                    .into(),
                "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (zeroblob(16), 1, 8, 9)"
                    .into(),
                "DELETE FROM message_read_here",
            ),
            (
                "INSERT INTO message_sends (sent_at, name, to_all) VALUES (9, 'notes', 0.5)".into(),
                "INSERT INTO message_sends (sent_at, name, to_all) VALUES (9, 'notes', 0)".into(),
                "DELETE FROM message_sends",
            ),
            (
                "INSERT INTO message_sends (sent_at, name, to_all) VALUES ('now', 'notes', 0)"
                    .into(),
                "INSERT INTO message_sends (sent_at, name, to_all) VALUES (9, 'notes', 0)".into(),
                "DELETE FROM message_sends",
            ),
            (
                format!(
                    "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES ({other}, 1, {}, 9, 9)",
                    text(1936)
                ),
                format!(
                    "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES ({other}, 1, zeroblob(1936), 9, 9)"
                ),
                "DELETE FROM message_kept WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                format!(
                    "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES ({}, 1, zeroblob(1936), 9, 9)",
                    text(16)
                ),
                format!(
                    "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES ({other}, 1, zeroblob(1936), 9, 9)"
                ),
                "DELETE FROM message_kept WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                format!(
                    "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES ({other}, 1, zeroblob(1936), 9.5, 9)"
                ),
                format!(
                    "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES ({other}, 1, zeroblob(1936), 9, 9)"
                ),
                "DELETE FROM message_kept WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                format!(
                    "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES ({other}, 1, zeroblob(1936), 9, 'then')"
                ),
                format!(
                    "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES ({other}, 1, zeroblob(1936), 9, 9)"
                ),
                "DELETE FROM message_kept WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                format!("INSERT INTO message_kept_numbers (id, number) VALUES ({id}, 2.5)"),
                format!("INSERT INTO message_kept_numbers (id, number) VALUES ({id}, 2)"),
                "DELETE FROM message_kept_numbers",
            ),
            (
                format!("INSERT INTO message_kept_numbers (id, number) VALUES ({id}, '2'||'x')"),
                format!("INSERT INTO message_kept_numbers (id, number) VALUES ({id}, 2)"),
                "DELETE FROM message_kept_numbers",
            ),
            (
                format!(
                    "INSERT INTO message_kept_taken (id, relay) VALUES ({id}, {})",
                    text(32)
                ),
                format!("INSERT INTO message_kept_taken (id, relay) VALUES ({id}, zeroblob(32))"),
                "DELETE FROM message_kept_taken",
            ),
            (
                "UPDATE message_index SET not_every_relay = 0.5".into(),
                "UPDATE message_index SET not_every_relay = 1".into(),
                "UPDATE message_index SET not_every_relay = 0",
            ),
        ];
        for (refused, taken, undo) in cases {
            assert!(conn.execute(&refused, []).is_err(), "{refused}");
            assert_eq!(conn.execute(&taken, []), Ok(1), "{taken}");
            conn.execute_batch(undo).unwrap();
        }
    }

    /// The table takes no row that cannot be a channel a relay holds: an
    /// ID of another length, a second row for one channel, a channel that
    /// holds less than nothing, and a holding with no mark, with a mark
    /// of another length, or with the mark of no holding.
    #[test]
    fn test_the_table_of_a_relays_channels_refuses_a_row_that_is_no_channel() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        let marked = |channel: &[u8], bytes: i64, mark: &[u8]| {
            conn.execute(
                "INSERT INTO relay_channels (channel_id, held_since, used_at, bytes, mark)
                 VALUES (?1, 7, 8, ?2, ?3)",
                rusqlite::params![channel, bytes, mark],
            )
        };
        let insert = |channel: &[u8], bytes: i64| marked(channel, bytes, &[9u8; 8]);
        assert!(insert(&[1u8; 31], 0).is_err());
        assert!(insert(&[1u8; 33], 0).is_err());
        assert!(insert(&[1u8; 32], -1).is_err());
        assert_eq!(insert(&[1u8; 32], 0), Ok(1));
        assert!(insert(&[1u8; 32], 0).is_err());
        assert_eq!(insert(&[2u8; 32], 1280), Ok(1));

        // The mark of a holding: 8 bytes, and not all zeros.
        for mark in [&[9u8; 7][..], &[9u8; 9], &[9u8; 32], &[], &[0u8; 8]] {
            assert!(marked(&[3u8; 32], 0, mark).is_err(), "{mark:?}");
        }
        assert!(
            conn.execute(
                "INSERT INTO relay_channels (channel_id, held_since, used_at, bytes)
                 VALUES (?1, 7, 8, 0)",
                [&[3u8; 32][..]],
            )
            .is_err(),
            "a holding with no mark was taken"
        );
        assert_eq!(marked(&[3u8; 32], 0, &[0, 0, 0, 0, 0, 0, 0, 1]), Ok(1));
        // Two holdings may have one mark: it is told apart by its channel.
        assert_eq!(marked(&[4u8; 32], 0, &[9u8; 8]), Ok(1));
    }
}
