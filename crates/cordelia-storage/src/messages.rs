//! What a device keeps of messages between the person's own agents
//! (decision 2026-10-09 §2.3, §2.5, §6, §7): the tables of schema step 19.
//!
//! The index of opened messages (`message_index`) holds each message's
//! body, link, subject and names in the clear, as it was opened. **A row
//! that goes is overwritten first** (§7.1): its body, link, subject,
//! `from_name` and `to_name` are written over with zeros of the same
//! length, and then the row is deleted, with its marks, in one
//! transaction. On a personal node `secure_delete` is on as well
//! ([`crate::db::secure_delete_on`]), and the log is truncated after each
//! hourly clearing ([`crate::db::checkpoint_truncating`]).

use rusqlite::{Connection, params};

use crate::StorageError;

/// The length of a message's value: every entry of the messages channel
/// holds one of exactly this many bytes (decision 2026-10-09 §2.2). The
/// table of kept values holds no value of another length. Moves to
/// protocol.rs with slice 1.
#[cfg(test)]
const AGENT_MESSAGE_VALUE_BYTES: usize = 1936;

/// The highest number of a message: the clearing of number k is at
/// revision 2k + 1, which stays below 2^43 (decision 2026-10-09 §2.3). No
/// number of the tables, and no highest number held, is above it. Moves
/// to protocol.rs with slice 1.
#[cfg(test)]
const AGENT_MESSAGE_NUMBER_MAX: i64 = (1 << 42) - 1;

/// Drop the index row of the message `id` (decision 2026-10-09 §7.1): at
/// its 30 days, at a clearing, or when none of its numbers is live. Its
/// body, link, subject, `from_name` and `to_name` are first written over
/// with zeros of the same length, then the row is deleted, and its marks
/// and its rows of numbers held with it, in one transaction. The rows of
/// first holding stay. A field that holds nothing (no link, and no
/// `to_name` for every name) is left so. Returns whether the device held
/// the row.
///
/// It runs in a savepoint, so it is whole by itself, and part of the
/// caller's transaction where there is one: the door's write that takes a
/// clearing, or raises H, drops its rows in that write.
pub fn drop_row(conn: &Connection, id: &[u8]) -> Result<bool, StorageError> {
    conn.execute_batch("SAVEPOINT drop_row")?;
    let dropped = overwritten_and_deleted(conn, id);
    let end = match dropped {
        Ok(_) => "RELEASE drop_row",
        Err(_) => "ROLLBACK TO drop_row; RELEASE drop_row",
    };
    conn.execute_batch(end)?;
    dropped
}

fn overwritten_and_deleted(conn: &Connection, id: &[u8]) -> Result<bool, StorageError> {
    conn.execute(
        "UPDATE message_index SET
             body = zeroblob(length(CAST(body AS BLOB))),
             link = CASE WHEN link IS NULL THEN NULL
                         ELSE zeroblob(length(CAST(link AS BLOB))) END,
             subject = zeroblob(length(CAST(subject AS BLOB))),
             from_name = zeroblob(length(CAST(from_name AS BLOB))),
             to_name = CASE WHEN to_name IS NULL THEN NULL
                            ELSE zeroblob(length(CAST(to_name AS BLOB))) END
         WHERE id = ?1",
        params![id],
    )?;
    let dropped = conn.execute("DELETE FROM message_index WHERE id = ?1", params![id])?;
    Ok(dropped == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    /// Words that nothing else in a database says: one for each field
    /// that is overwritten before its row goes.
    const BODY: &str = "a body that says plover-quartz-lantern and nothing else";
    const LINK: &str = "owner/repo-of-heron-marmalade#4242";
    const SUBJECT: &str = "the subject of kestrel-umbrella";
    const FROM: &str = "github.com/owner/agent-of-walrus-tangent";
    const TO: &str = "github.com/owner/agent-of-otter-quince";
    const WORDS: [&str; 5] = [BODY, LINK, SUBJECT, FROM, TO];

    /// The generation 1: a messages channel of zeros, begun by statement 1.
    fn generation_1(conn: &Connection) {
        conn.execute(
            "INSERT OR IGNORE INTO message_generations (id, channel, statement, first_held)
             VALUES (1, zeroblob(32), 1, 100)",
            [],
        )
        .unwrap();
    }

    /// Put a message `id` from `signer` in the index, held at `number`
    /// in the generation 1, with a mark of each kind, a row of first
    /// holding, and its text in `WORDS`.
    fn indexed(conn: &Connection, id: u8, number: i64) {
        generation_1(conn);
        let id = [id; 16];
        conn.execute(
            "INSERT INTO message_index (id, signer, label, generation, to_kind, to_name,
                                        from_name, sent, subject, thread, answers, asks,
                                        link, body, first_held, placed_at)
             VALUES (?1, ?2, 'laptop', 1, 1, ?3, ?4, 100, ?5, zeroblob(16), zeroblob(16), 1,
                     ?6, ?7, 100, 101)",
            params![&id[..], &[7u8; 32][..], TO, FROM, SUBJECT, LINK, BODY],
        )
        .unwrap();
        conn.execute_batch(&format!(
            "INSERT INTO message_numbers (signer, generation, number, id)
                 VALUES (zeroblob(32), 1, {number}, X'{hex}');
             INSERT INTO message_first_held (signer, generation, number, id, sent, first_held)
                 VALUES (zeroblob(32), 1, {number}, X'{hex}', 100, 100);
             INSERT INTO message_announced (id, name) VALUES (X'{hex}', 'notes');
             INSERT INTO message_read_by_a_person (id) VALUES (X'{hex}');
             INSERT INTO message_read_here (mark, seq, id, name, made_at)
                 VALUES (X'{hex}', {number}, X'{hex}', 'notes', 102);",
            hex = hex::encode(id),
        ))
        .unwrap();
    }

    fn count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    /// Which of `WORDS` the bytes of `file` hold.
    fn words_in(file: &std::path::Path) -> Vec<&'static str> {
        let bytes = std::fs::read(file).unwrap_or_default();
        WORDS
            .into_iter()
            .filter(|words| bytes.windows(words.len()).any(|at| at == words.as_bytes()))
            .collect()
    }

    /// The database file and its write-ahead log, of a store at `path`.
    fn file_and_log(path: &std::path::Path) -> [std::path::PathBuf; 2] {
        [path.to_path_buf(), path.with_extension("db-wal")]
    }

    /// A row that is overwritten and dropped, on a store with
    /// `secure_delete` on, leaves nothing of its text in the database
    /// file or its write-ahead log after the truncating checkpoint, and
    /// the log is empty (decision 2026-10-09 §7.1, D10). Before the
    /// checkpoint the log still holds the text: the checkpoint is what
    /// takes it out.
    #[test]
    fn a_row_overwritten_and_dropped_leaves_nothing_of_its_text_in_the_file_or_its_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cordelia.db");
        let conn = db::open(&path).unwrap();
        db::secure_delete_on(&conn).unwrap();
        let [file, log] = file_and_log(&path);
        indexed(&conn, 1, 1);
        assert!(db::checkpoint_truncating(&conn).unwrap());
        assert_eq!(words_in(&file), WORDS);
        // A write after the checkpoint puts the page in the log again.
        conn.execute("UPDATE message_index SET placed_at = 102", [])
            .unwrap();
        assert_eq!(words_in(&log), WORDS);

        assert!(drop_row(&conn, &[1; 16]).unwrap());
        assert_eq!(count(&conn, "message_index"), 0);
        assert!(!words_in(&log).is_empty(), "the log holds the page before");
        assert!(db::checkpoint_truncating(&conn).unwrap());
        assert_eq!(words_in(&file), Vec::<&str>::new());
        assert_eq!(words_in(&log), Vec::<&str>::new());
        assert_eq!(std::fs::metadata(&log).unwrap().len(), 0);
    }

    /// The fields are written over before the row is deleted, as the
    /// record asks (decision 2026-10-09 §7.1), and a row deleted without
    /// that leaves its text in the file. Here, on a connection with no
    /// `secure_delete`, the overwrite leaves nothing of the dropped row's
    /// text only because its cell never moved: a row that was updated and
    /// grew leaves its text in the cells it moved from, which only
    /// `secure_delete` writes over. That nothing is left rests on
    /// `secure_delete`; the overwrite is what the record asks for besides.
    #[test]
    fn a_dropped_row_is_overwritten_before_it_is_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cordelia.db");
        let conn = db::open(&path).unwrap();
        let [file, _] = file_and_log(&path);
        indexed(&conn, 1, 1);
        indexed(&conn, 2, 2);
        assert!(db::checkpoint_truncating(&conn).unwrap());

        assert!(drop_row(&conn, &[1; 16]).unwrap());
        assert!(db::checkpoint_truncating(&conn).unwrap());
        // The other row still holds the words: count them.
        let held = |file: &std::path::Path| -> Vec<usize> {
            let bytes = std::fs::read(file).unwrap();
            WORDS
                .iter()
                .map(|words| {
                    bytes
                        .windows(words.len())
                        .filter(|at| *at == words.as_bytes())
                        .count()
                })
                .collect()
        };
        assert_eq!(held(&file), [1; 5]);

        // A row deleted as it is leaves its words where they were.
        conn.execute("DELETE FROM message_index WHERE id = ?1", [&[2u8; 16][..]])
            .unwrap();
        assert!(db::checkpoint_truncating(&conn).unwrap());
        assert_eq!(
            held(&file),
            [1; 5],
            "without secure_delete, a delete keeps the text"
        );
    }

    /// A row as the trigger caught it: its ID, label and `sent`, its
    /// text fields one after another, and how many of them held nothing.
    type AsDeleted = (Vec<u8>, String, i64, Vec<u8>, i64);

    /// What a row holds as it is deleted: its body, link, subject,
    /// `from_name` and `to_name` are already zeros, each as many bytes
    /// as the text it held (decision 2026-10-09 §7.1), and the fields
    /// that are not text a person wrote are as they were. A message to
    /// every name, with no `to_name` and no link, is dropped as well,
    /// and what it does not hold it still does not hold.
    #[test]
    fn a_dropped_row_is_written_over_with_zeros_of_the_same_length_first() {
        let conn = db::open_in_memory().unwrap();
        indexed(&conn, 1, 1);
        conn.execute_batch(
            "INSERT INTO message_index (id, signer, label, generation, to_kind, to_name,
                                        from_name, sent, subject, thread, answers, asks,
                                        link, body, first_held, placed_at)
             VALUES (X'02020202020202020202020202020202', zeroblob(32), 'desktop', 1, 2, NULL,
                     '~', 9, 'x', zeroblob(16), zeroblob(16), 0, NULL, 'x', 9, NULL);
             CREATE TEMP TABLE as_deleted (id BLOB, label TEXT, sent INTEGER, fields BLOB,
                                          none INTEGER);
             CREATE TEMP TRIGGER caught BEFORE DELETE ON main.message_index BEGIN
                 INSERT INTO as_deleted VALUES (OLD.id, OLD.label, OLD.sent,
                     CAST(CAST(OLD.body AS BLOB) || CAST(COALESCE(OLD.link, '') AS BLOB)
                          || CAST(OLD.subject AS BLOB) || CAST(OLD.from_name AS BLOB)
                          || CAST(COALESCE(OLD.to_name, '') AS BLOB) AS BLOB),
                     (OLD.link IS NULL) + (OLD.to_name IS NULL));
             END;",
        )
        .unwrap();

        assert!(drop_row(&conn, &[1; 16]).unwrap());
        assert!(drop_row(&conn, &[2; 16]).unwrap());
        let caught: Vec<AsDeleted> = conn
            .prepare("SELECT id, label, sent, fields, none FROM as_deleted ORDER BY id")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let bytes: usize = WORDS.iter().map(|words| words.len()).sum();
        assert_eq!(
            caught,
            [
                (vec![1; 16], "laptop".to_string(), 100, vec![0; bytes], 0),
                (vec![2; 16], "desktop".to_string(), 9, vec![0; 3], 2),
            ]
        );
    }

    /// A row that goes takes its marks and its rows of numbers held with
    /// it, and leaves its rows of first holding, and every other row
    /// (decision 2026-10-09 §7.1, §7.2). A mark merged from the device's
    /// own list, with no message, stays. Dropping a row the device does
    /// not hold changes nothing.
    #[test]
    fn a_dropped_row_takes_its_marks_and_leaves_its_first_holding() {
        let conn = db::open_in_memory().unwrap();
        indexed(&conn, 1, 1);
        indexed(&conn, 2, 2);
        conn.execute_batch(
            "INSERT INTO message_numbers (signer, generation, number, id)
                 VALUES (zeroblob(32), 1, 65, X'01010101010101010101010101010101');
             INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (X'09090909090909090909090909090909', 0, 90, 103);",
        )
        .unwrap();

        assert!(drop_row(&conn, &[1; 16]).unwrap());
        let held = |table: &str, id: u8| -> i64 {
            conn.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE id = ?1"),
                [&[id; 16][..]],
                |row| row.get(0),
            )
            .unwrap()
        };
        for table in [
            "message_index",
            "message_numbers",
            "message_announced",
            "message_read_by_a_person",
            "message_read_here",
        ] {
            assert_eq!((held(table, 1), held(table, 2)), (0, 1), "{table}");
        }
        assert_eq!(
            (held("message_first_held", 1), held("message_first_held", 2)),
            (1, 1)
        );
        assert_eq!(count(&conn, "message_read_here"), 2);

        assert!(!drop_row(&conn, &[1; 16]).unwrap());
        assert!(!drop_row(&conn, &[3; 16]).unwrap());
        assert_eq!(count(&conn, "message_index"), 1);
    }

    /// The table of kept values holds a value of exactly the length of a
    /// message's (decision 2026-10-09 §2.2, §2.3), and its numbers and
    /// relays go with it.
    #[test]
    fn a_kept_value_is_of_a_messages_length_and_takes_its_numbers_and_relays_with_it() {
        let conn = db::open_in_memory().unwrap();
        generation_1(&conn);
        let keep = |id: u8, bytes: usize| {
            conn.execute(
                "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                 VALUES (?1, 1, zeroblob(?2), 100, 100)",
                params![&[id; 16][..], bytes as i64],
            )
        };
        assert!(keep(1, AGENT_MESSAGE_VALUE_BYTES - 1).is_err());
        assert!(keep(1, AGENT_MESSAGE_VALUE_BYTES + 1).is_err());
        assert_eq!(keep(1, AGENT_MESSAGE_VALUE_BYTES), Ok(1));
        conn.execute_batch(
            "INSERT INTO message_kept_numbers (id, number)
                 VALUES (X'01010101010101010101010101010101', 3),
                        (X'01010101010101010101010101010101', 70);
             INSERT INTO message_kept_taken (id, relay)
                 VALUES (X'01010101010101010101010101010101', zeroblob(32));",
        )
        .unwrap();
        conn.execute("DELETE FROM message_kept", []).unwrap();
        assert_eq!(count(&conn, "message_kept_numbers"), 0);
        assert_eq!(count(&conn, "message_kept_taken"), 0);
    }

    /// `drop_row` nests in the caller's write (decision 2026-10-09 §7.1):
    /// inside an open transaction and inside a savepoint it overwrites
    /// and deletes the row as a part of that write, which the caller then
    /// keeps or takes back whole.
    #[test]
    fn a_row_is_dropped_inside_a_transaction_or_a_savepoint_of_the_callers() {
        let conn = db::open_in_memory().unwrap();
        indexed(&conn, 1, 1);
        let body = |conn: &Connection| -> Option<Vec<u8>> {
            conn.query_row(
                "SELECT CAST(body AS BLOB) FROM message_index WHERE id = ?1",
                [&[1u8; 16][..]],
                |row| row.get(0),
            )
            .ok()
        };

        for begin in ["BEGIN", "SAVEPOINT the_doors_write"] {
            conn.execute_batch(begin).unwrap();
            assert!(drop_row(&conn, &[1; 16]).unwrap(), "{begin}");
            assert_eq!(count(&conn, "message_index"), 0, "{begin}");
            assert!(!conn.is_autocommit(), "{begin}: the caller's write is open");
            let back = if begin == "BEGIN" {
                "ROLLBACK"
            } else {
                "ROLLBACK TO the_doors_write; RELEASE the_doors_write"
            };
            conn.execute_batch(back).unwrap();
            assert_eq!(body(&conn), Some(BODY.as_bytes().to_vec()), "{begin}");
        }

        conn.execute_batch("BEGIN").unwrap();
        assert!(drop_row(&conn, &[1; 16]).unwrap());
        conn.execute_batch("COMMIT").unwrap();
        assert_eq!(body(&conn), None);
        assert_eq!(count(&conn, "message_numbers"), 0);
    }

    /// A generation is the messages channel, not the number of the
    /// statement that began it (decision 2026-10-09 §7.1, §9.2): two
    /// channels begun under statement 1, as a device alone under a phrase
    /// that makes a new one has, are two generations, and the same signer
    /// at the same number in each is two rows that do not collide. A
    /// channel is one generation, and a generation that the device never
    /// held is refused in every table.
    #[test]
    fn two_channels_under_one_statements_number_are_two_generations() {
        let conn = db::open_in_memory().unwrap();
        let begin = |channel: u8| {
            conn.execute(
                "INSERT INTO message_generations (channel, statement, first_held)
                 VALUES (?1, 1, 100)",
                [&[channel; 32][..]],
            )
            .map(|_| conn.last_insert_rowid())
        };
        let first = begin(1).unwrap();
        let second = begin(2).unwrap();
        assert_ne!(first, second);
        assert!(begin(1).is_err(), "a channel is one generation");

        for (generation, id) in [(first, 1u8), (second, 2)] {
            conn.execute(
                "INSERT INTO message_index (id, signer, label, generation, to_kind, to_name,
                                            from_name, sent, subject, thread, answers, asks,
                                            link, body, first_held, placed_at)
                 VALUES (?1, zeroblob(32), 'laptop', ?2, 2, NULL, '~', 9, 'x', zeroblob(16),
                         zeroblob(16), 0, NULL, 'x', 9, NULL)",
                params![&[id; 16][..], generation],
            )
            .unwrap();
            conn.execute_batch(&format!(
                "INSERT INTO message_numbers (signer, generation, number, id)
                     VALUES (zeroblob(32), {generation}, 1, X'{hex}');
                 INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                 first_held)
                     VALUES (zeroblob(32), {generation}, 1, X'{hex}', 9, 9);
                 INSERT INTO message_signers (signer, generation, highest, counted_from)
                     VALUES (zeroblob(32), {generation}, 1, 1);
                 INSERT INTO message_places (signer, generation, placed_at)
                     VALUES (zeroblob(32), {generation}, 10);
                 INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES (X'{hex}', {generation}, zeroblob(1936), 9, 9);",
                hex = hex::encode([id; 16]),
            ))
            .unwrap();
        }
        let held: Vec<(i64, i64)> = conn
            .prepare(
                "SELECT g.statement, n.generation FROM message_numbers n
                 JOIN message_generations g ON g.id = n.generation ORDER BY n.generation",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(held, [(1, first), (1, second)]);

        let never = second + 1;
        for refused in [
            format!(
                "INSERT INTO message_index (id, signer, label, generation, to_kind, to_name,
                                            from_name, sent, subject, thread, answers, asks,
                                            link, body, first_held, placed_at)
                 VALUES (zeroblob(16), zeroblob(32), 'laptop', {never}, 2, NULL, '~', 9, 'x',
                         zeroblob(16), zeroblob(16), 0, NULL, 'x', 9, NULL)"
            ),
            format!(
                "INSERT INTO message_numbers (signer, generation, number, id)
                 VALUES (zeroblob(32), {never}, 1, X'{}')",
                hex::encode([1u8; 16])
            ),
            format!(
                "INSERT INTO message_first_held (signer, generation, number, id, sent, first_held)
                 VALUES (zeroblob(32), {never}, 1, zeroblob(16), 9, 9)"
            ),
            format!(
                "INSERT INTO message_signers (signer, generation, highest)
                 VALUES (zeroblob(32), {never}, 1)"
            ),
            format!(
                "INSERT INTO message_places (signer, generation, placed_at)
                 VALUES (zeroblob(32), {never}, 10)"
            ),
            format!(
                "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                 VALUES (zeroblob(16), {never}, zeroblob(1936), 9, 9)"
            ),
        ] {
            assert!(conn.execute(&refused, []).is_err(), "{refused}");
        }
    }

    /// A number, the highest number held, and the number counted from
    /// are at most the highest number of a message (decision 2026-10-09
    /// §2.3, §2.5): each table takes it, and refuses one above it.
    #[test]
    fn no_number_is_above_the_highest_number_of_a_message() {
        let conn = db::open_in_memory().unwrap();
        indexed(&conn, 1, 1);
        conn.execute_batch(
            "INSERT INTO message_kept (id, generation, value, sent, kept_at)
             VALUES (X'01010101010101010101010101010101', 1, zeroblob(1936), 9, 9);",
        )
        .unwrap();
        let id = format!("X'{}'", hex::encode([1u8; 16]));
        let at = |number: i64| -> Vec<String> {
            vec![
                format!(
                    "INSERT INTO message_numbers (signer, generation, number, id)
                     VALUES (zeroblob(32), 1, {number}, {id})"
                ),
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, {number}, {id}, 9, 9)"
                ),
                format!(
                    "INSERT INTO message_signers (signer, generation, highest)
                     VALUES (zeroblob(32), 1, {number})"
                ),
                format!(
                    "INSERT INTO message_signers (signer, generation, highest, counted_from)
                     VALUES (X'{}', 1, 1, {number})",
                    hex::encode([2u8; 32])
                ),
                format!("INSERT INTO message_kept_numbers (id, number) VALUES ({id}, {number})"),
            ]
        };
        for refused in at(AGENT_MESSAGE_NUMBER_MAX + 1) {
            assert!(conn.execute(&refused, []).is_err(), "{refused}");
        }
        for taken in at(AGENT_MESSAGE_NUMBER_MAX) {
            assert_eq!(conn.execute(&taken, []), Ok(1), "{taken}");
        }
    }
}
