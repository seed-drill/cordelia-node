//! The index line of a memory that this device deleted (decision
//! 2026-09-30-agent-memory-sync §4.5).
//!
//! Deleting a memory is two acts on one device: its line goes from the
//! index, and its file goes from the folder. The sync adapter writes each
//! down when it publishes it: the line it removed, and when; and when it
//! published the file's delete. A record that has both, written within an
//! hour of each other, is whole. Only a whole record is ever acted on: if
//! the file comes back, and its line does not, the adapter puts the line
//! back, up to three times.
//!
//! This module keeps the records and decides nothing else. Times are in
//! seconds, in UTC, by this device's clock, and each caller passes the
//! time in. A time that is later than now is read as now, and written back
//! as now.

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;
use cordelia_core::protocol::{
    INDEX_LINE_KEPT_DAYS, INDEX_LINE_MAX_PUT_BACKS, INDEX_LINE_MAX_RECORDS, INDEX_LINE_PAIR_SECS,
};

/// How long a whole record lasts after its later half.
const KEPT_SECS: i64 = INDEX_LINE_KEPT_DAYS as i64 * 24 * 60 * 60;

/// A whole record: a memory this device deleted with its line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The memory file's name.
    pub file: String,
    /// The line this device removed for it.
    pub line: String,
    /// How many times the line has been put back.
    pub put_back: u32,
}

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

/// One of the two things a record is made of.
enum Half<'a> {
    Line(&'a str),
    Delete,
}

/// A row as it is stored. A record that is not whole has one half.
struct Row {
    line_at: Option<i64>,
    deleted_at: Option<i64>,
    whole: bool,
}

/// This device published an edit of the index that removed `line`, a line
/// for `file`.
pub fn line_removed(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
    file: &str,
    line: &str,
    now: i64,
) -> Result<(), CordeliaError> {
    write_half(conn, folder, channel_id, file, Half::Line(line), now)
}

/// This device published a delete of `file`.
pub fn delete_published(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
    file: &str,
    now: i64,
) -> Result<(), CordeliaError> {
    write_half(conn, folder, channel_id, file, Half::Delete, now)
}

/// Write one half of `file`'s record.
///
/// - No record: the half starts one.
/// - A whole record: the half and its time are replaced, and nothing else
///   changes. Whole is decided once.
/// - A record with this half only: it is replaced, with its new time. The
///   hour runs from the later writing.
/// - A record with the other half only: within an hour of it the record
///   is whole. After that the other half has gone, and this one starts the
///   record again.
fn write_half(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
    file: &str,
    half: Half,
    now: i64,
) -> Result<(), CordeliaError> {
    conn.execute_batch("SAVEPOINT index_line")
        .map_err(storage)?;
    let written = written(conn, folder, channel_id, file, half, now);
    let end = match written {
        Ok(()) => "RELEASE index_line",
        Err(_) => "ROLLBACK TO index_line; RELEASE index_line",
    };
    conn.execute_batch(end).map_err(storage)?;
    written
}

fn written(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
    file: &str,
    half: Half,
    now: i64,
) -> Result<(), CordeliaError> {
    let row: Option<Row> = conn
        .query_row(
            "SELECT line_at, deleted_at, whole FROM index_lines
             WHERE folder = ?1 AND channel_id = ?2 AND file = ?3",
            params![folder, channel_id, file],
            |row| {
                Ok(Row {
                    line_at: row.get(0)?,
                    deleted_at: row.get(1)?,
                    whole: row.get::<_, i64>(2)? != 0,
                })
            },
        )
        .optional()
        .map_err(storage)?;
    // The other half's time, and whether it joins this one: it is there,
    // and was written no more than an hour ago.
    let other = match (&row, &half) {
        (Some(row), Half::Line(_)) => row.deleted_at,
        (Some(row), Half::Delete) => row.line_at,
        (None, _) => None,
    };
    let joined = other.is_some_and(|at| now - at.min(now) <= INDEX_LINE_PAIR_SECS);
    let whole = row.as_ref().is_some_and(|row| row.whole) || joined;
    // A half that waited longer than its hour goes.
    let other_goes = other.is_some() && !whole;

    if row.is_none() {
        conn.execute(
            "INSERT INTO index_lines (folder, channel_id, file) VALUES (?1, ?2, ?3)",
            params![folder, channel_id, file],
        )
        .map_err(storage)?;
    }
    let set = match (&half, other_goes) {
        (Half::Line(_), false) => "line = ?4, line_at = ?5",
        (Half::Line(_), true) => "line = ?4, line_at = ?5, deleted_at = NULL",
        (Half::Delete, false) => "deleted_at = ?5",
        (Half::Delete, true) => "deleted_at = ?5, line = NULL, line_at = NULL",
    };
    let line = match half {
        Half::Line(line) => Some(line),
        Half::Delete => None,
    };
    conn.execute(
        &format!(
            "UPDATE index_lines SET {set}, whole = ?6
             WHERE folder = ?1 AND channel_id = ?2 AND file = ?3"
        ),
        params![folder, channel_id, file, line, now, whole as i64],
    )
    .map_err(storage)?;
    if row.is_none() {
        make_room(conn, folder, channel_id, file)?;
    }
    Ok(())
}

/// A folder has at most [`INDEX_LINE_MAX_RECORDS`] records. Past that one
/// goes, and not the one just written (`but`): a record with one half
/// before any that is whole (an index written anew drops many lines at
/// once, and those halves go within the hour anyway); among those of one
/// kind, the one whose later half is oldest; and of two as old, the one
/// whose file's name sorts first.
fn make_room(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
    but: &str,
) -> Result<(), CordeliaError> {
    let records: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM index_lines WHERE folder = ?1 AND channel_id = ?2",
            params![folder, channel_id],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if records <= INDEX_LINE_MAX_RECORDS as i64 {
        return Ok(());
    }
    conn.execute(
        "DELETE FROM index_lines WHERE rowid = (
             SELECT rowid FROM index_lines
             WHERE folder = ?1 AND channel_id = ?2 AND file != ?3
             ORDER BY whole, MAX(COALESCE(line_at, deleted_at), COALESCE(deleted_at, line_at)), file
             LIMIT 1)",
        params![folder, channel_id, but],
    )
    .map_err(storage)?;
    Ok(())
}

/// The whole records of a folder, in the order of their files' names.
///
/// What has run out goes first: a half that no other joined within its
/// hour, and a whole record 90 days after its later half. A time that is
/// later than `now` is read as now, and written back as now.
pub fn whole(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
    now: i64,
) -> Result<Vec<Record>, CordeliaError> {
    let of_folder = "folder = ?1 AND channel_id = ?2";
    conn.execute(
        &format!(
            "UPDATE index_lines
             SET line_at = MIN(line_at, ?3), deleted_at = MIN(deleted_at, ?3)
             WHERE {of_folder} AND (line_at > ?3 OR deleted_at > ?3)"
        ),
        params![folder, channel_id, now],
    )
    .map_err(storage)?;
    conn.execute(
        &format!(
            "DELETE FROM index_lines
             WHERE {of_folder} AND whole = 0 AND COALESCE(line_at, deleted_at) + ?4 < ?3"
        ),
        params![folder, channel_id, now, INDEX_LINE_PAIR_SECS],
    )
    .map_err(storage)?;
    conn.execute(
        &format!(
            "DELETE FROM index_lines
             WHERE {of_folder} AND whole = 1 AND MAX(line_at, deleted_at) + ?4 <= ?3"
        ),
        params![folder, channel_id, now, KEPT_SECS],
    )
    .map_err(storage)?;
    let mut stmt = conn
        .prepare(&format!(
            "SELECT file, line, put_back FROM index_lines
             WHERE {of_folder} AND whole = 1 AND line IS NOT NULL ORDER BY file"
        ))
        .map_err(storage)?;
    let records = stmt
        .query_map(params![folder, channel_id], |row| {
            Ok(Record {
                file: row.get(0)?,
                line: row.get(1)?,
                put_back: row.get::<_, i64>(2)?.try_into().unwrap_or(u32::MAX),
            })
        })
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    Ok(records)
}

/// The lines of these files' records were put back: each counts one more,
/// and a record whose line has been put back [`INDEX_LINE_MAX_PUT_BACKS`]
/// times goes.
pub fn put_back(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
    files: &[&str],
) -> Result<(), CordeliaError> {
    for file in files {
        conn.execute(
            "UPDATE index_lines SET put_back = put_back + 1
             WHERE folder = ?1 AND channel_id = ?2 AND file = ?3",
            params![folder, channel_id, file],
        )
        .map_err(storage)?;
    }
    conn.execute(
        "DELETE FROM index_lines WHERE folder = ?1 AND channel_id = ?2 AND put_back >= ?3",
        params![folder, channel_id, INDEX_LINE_MAX_PUT_BACKS],
    )
    .map_err(storage)?;
    Ok(())
}

/// Drop `file`'s record, whole or not: its line has stayed, this device
/// has made a file of that name itself, or its line cannot be put back.
pub fn drop_record(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
    file: &str,
) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM index_lines WHERE folder = ?1 AND channel_id = ?2 AND file = ?3",
        params![folder, channel_id, file],
    )
    .map_err(storage)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    const HOUR: i64 = INDEX_LINE_PAIR_SECS;
    const DAY: i64 = 24 * 60 * 60;
    /// A time to count from.
    const T: i64 = 1_800_000_000;

    fn line(conn: &Connection, file: &str, line: &str, at: i64) {
        line_removed(conn, "/m", "grp_a", file, line, at).unwrap();
    }

    fn delete(conn: &Connection, file: &str, at: i64) {
        delete_published(conn, "/m", "grp_a", file, at).unwrap();
    }

    /// The whole records, as (file, line, times put back).
    fn records(conn: &Connection, now: i64) -> Vec<(String, String, u32)> {
        whole(conn, "/m", "grp_a", now)
            .unwrap()
            .into_iter()
            .map(|r| (r.file, r.line, r.put_back))
            .collect()
    }

    fn one(file: &str, line: &str, put_back: u32) -> Vec<(String, String, u32)> {
        vec![(file.to_string(), line.to_string(), put_back)]
    }

    /// Every row of the folder, whole or not: (file, has a line, has a
    /// delete, whole).
    fn rows(conn: &Connection) -> Vec<(String, bool, bool, bool)> {
        conn.prepare(
            "SELECT file, line_at IS NOT NULL, deleted_at IS NOT NULL, whole
             FROM index_lines ORDER BY file",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    /// A record is whole when its two halves are written within an hour of
    /// each other, in either order, and not when they are further apart:
    /// the half that waited goes, and the other starts the record again.
    #[test]
    fn test_two_halves_within_an_hour_make_a_record_whole() {
        let conn = db::open_in_memory().unwrap();
        // One half is no record to act on.
        line(&conn, "a.md", "- [A](a.md) one", T);
        assert!(records(&conn, T).is_empty());
        delete(&conn, "b.md", T);
        assert!(records(&conn, T).is_empty());
        // The other, an hour later to the second: whole, in either order.
        delete(&conn, "a.md", T + HOUR);
        line(&conn, "b.md", "- [B](b.md) two", T + HOUR);
        assert_eq!(
            records(&conn, T + HOUR),
            [
                ("a.md".to_string(), "- [A](a.md) one".to_string(), 0),
                ("b.md".to_string(), "- [B](b.md) two".to_string(), 0),
            ]
        );

        // A second later than that: the first half has gone, and the
        // second starts the record again.
        line(&conn, "c.md", "- [C](c.md) three", T);
        delete(&conn, "c.md", T + HOUR + 1);
        delete(&conn, "d.md", T);
        line(&conn, "d.md", "- [D](d.md) four", T + HOUR + 1);
        assert_eq!(records(&conn, T + HOUR + 1).len(), 2);
        assert_eq!(
            rows(&conn)[2..],
            [
                ("c.md".to_string(), false, true, false),
                ("d.md".to_string(), true, false, false),
            ]
        );
        // And the half that is then joined within its own hour makes it
        // whole after all.
        line(&conn, "c.md", "- [C](c.md) again", T + 2 * HOUR);
        assert_eq!(
            records(&conn, T + 2 * HOUR)[2],
            ("c.md".to_string(), "- [C](c.md) again".to_string(), 0)
        );
    }

    /// Whole is decided once. A half written again later replaces that
    /// half and its time, and changes nothing else: the record stays
    /// whole, and keeps its count.
    #[test]
    fn test_a_half_written_again_leaves_a_whole_record_whole() {
        let conn = db::open_in_memory().unwrap();
        line(&conn, "a.md", "- [A](a.md) one", T);
        delete(&conn, "a.md", T + 5);
        put_back(&conn, "/m", "grp_a", &["a.md"]).unwrap();
        // A day later, each half again, a day apart.
        line(&conn, "a.md", "- [A](a.md) new words", T + DAY);
        assert_eq!(
            records(&conn, T + DAY),
            one("a.md", "- [A](a.md) new words", 1)
        );
        delete(&conn, "a.md", T + 2 * DAY);
        assert_eq!(
            records(&conn, T + 2 * DAY),
            one("a.md", "- [A](a.md) new words", 1)
        );
        // It lasts 90 days from its later half, as it was last written.
        let later = T + 2 * DAY;
        assert_eq!(records(&conn, later + 90 * DAY - 1).len(), 1);
        assert!(records(&conn, later + 90 * DAY).is_empty());
        assert!(rows(&conn).is_empty());
    }

    /// A lone half that is written again is replaced, with its new time:
    /// the hour runs from the later writing. One that no other joins
    /// within its hour goes.
    #[test]
    fn test_a_lone_half_lasts_an_hour_from_its_last_writing() {
        let conn = db::open_in_memory().unwrap();
        line(&conn, "a.md", "- [A](a.md) one", T);
        line(&conn, "a.md", "- [A](a.md) two", T + HOUR - 1);
        // An hour after the first writing, and within the hour of the
        // second: whole, with the line as it was last removed.
        delete(&conn, "a.md", T + HOUR + 10);
        assert_eq!(
            records(&conn, T + HOUR + 10),
            one("a.md", "- [A](a.md) two", 0)
        );

        // A lone half is still there an hour on, and gone a second later.
        // (It is no record to act on at any time.)
        delete(&conn, "b.md", T + HOUR + 10);
        let only_a = one("a.md", "- [A](a.md) two", 0);
        assert_eq!(records(&conn, T + 2 * HOUR + 10), only_a);
        assert_eq!(rows(&conn).len(), 2);
        assert_eq!(records(&conn, T + 2 * HOUR + 11), only_a);
        assert_eq!(rows(&conn).len(), 1);
    }

    /// A line is put back three times and no more: the record goes at the
    /// third. A memory deleted with its line again after that is a new
    /// record, and its count starts at nought.
    #[test]
    fn test_a_line_is_put_back_three_times_and_no_more() {
        let conn = db::open_in_memory().unwrap();
        for file in ["a.md", "b.md"] {
            line(&conn, file, "- a line", T);
            delete(&conn, file, T);
        }
        let back = |files: &[&str]| put_back(&conn, "/m", "grp_a", files).unwrap();
        back(&["a.md"]);
        back(&["a.md", "b.md"]);
        assert_eq!(
            records(&conn, T),
            [
                ("a.md".to_string(), "- a line".to_string(), 2),
                ("b.md".to_string(), "- a line".to_string(), 1),
            ]
        );
        // Both halves written again at two: the count is kept, and the
        // line goes back once more and no more.
        line(&conn, "a.md", "- a line", T + 10);
        delete(&conn, "a.md", T + 10);
        assert_eq!(records(&conn, T + 10)[0].2, 2);
        back(&["a.md"]);
        assert_eq!(records(&conn, T + 10), one("b.md", "- a line", 1));
        // Deleted with its line again: a new record.
        line(&conn, "a.md", "- a line", T + 20);
        delete(&conn, "a.md", T + 20);
        assert_eq!(
            records(&conn, T + 20)[0],
            ("a.md".to_string(), "- a line".to_string(), 0)
        );
        // A file with no record is no error.
        back(&["none.md"]);
    }

    /// A record that is dropped is gone, whole or not, and no other is.
    #[test]
    fn test_a_record_is_dropped_by_its_file() {
        let conn = db::open_in_memory().unwrap();
        for file in ["a.md", "b.md"] {
            line(&conn, file, "- a line", T);
            delete(&conn, file, T);
        }
        line(&conn, "c.md", "- a line", T);
        line_removed(&conn, "/other", "grp_a", "a.md", "- a line", T).unwrap();
        line_removed(&conn, "/m", "grp_b", "a.md", "- a line", T).unwrap();
        for file in ["a.md", "c.md", "none.md"] {
            drop_record(&conn, "/m", "grp_a", file).unwrap();
        }
        assert_eq!(records(&conn, T), one("b.md", "- a line", 0));
        assert_eq!(
            rows(&conn).len(),
            3,
            "the other folder's and channel's stay"
        );
    }

    /// A time that is later than now is read as now, and written back as
    /// now: a clock that was ahead does not keep a half past its hour, or
    /// a record past its 90 days, counted from when it is first read.
    #[test]
    fn test_a_time_later_than_now_is_read_as_now() {
        let conn = db::open_in_memory().unwrap();
        // Written with the clock a year ahead.
        let ahead = T + 365 * DAY;
        delete(&conn, "a.md", ahead);
        line(&conn, "b.md", "- [B](b.md)", ahead);
        delete(&conn, "b.md", ahead);
        // Read with the clock right: the half's hour runs from now.
        assert_eq!(records(&conn, T), one("b.md", "- [B](b.md)", 0));
        assert_eq!(rows(&conn).len(), 2);
        assert_eq!(records(&conn, T + HOUR + 1).len(), 1);
        assert_eq!(
            rows(&conn).len(),
            1,
            "the half went an hour after it was read"
        );
        // And the record's 90 days.
        assert_eq!(records(&conn, T + 90 * DAY - 1).len(), 1);
        assert!(records(&conn, T + 90 * DAY).is_empty());

        // A half that joins one written with the clock ahead joins it as
        // if it had been written now.
        delete(&conn, "c.md", ahead);
        line(&conn, "c.md", "- [C](c.md)", T);
        assert_eq!(records(&conn, T), one("c.md", "- [C](c.md)", 0));
    }

    /// What a folder wrote down goes when the folder forgets what it had
    /// agreed, by each of the three ways a folder forgets, and for a
    /// folder that has nothing agreed too.
    #[test]
    fn test_a_folder_that_forgets_loses_its_records() {
        use crate::sync_state::{self, Writer};
        let conn = db::open_in_memory().unwrap();
        let fill = || {
            let agreed = [("/m", "grp_a"), ("/m", "grp_b"), ("/other", "grp_a")];
            for (folder, channel) in agreed {
                let nobody = (None, 1, Writer::Nobody);
                sync_state::save(&conn, folder, channel, "a.md", nobody).unwrap();
            }
            // And a folder that has nothing agreed.
            for (folder, channel) in agreed.into_iter().chain([("/bare", "grp_a")]) {
                line_removed(&conn, folder, channel, "a.md", "- a line", T).unwrap();
                delete_published(&conn, folder, channel, "a.md", T).unwrap();
            }
        };
        let left = || -> Vec<(String, String)> {
            conn.prepare("SELECT folder, channel_id FROM index_lines ORDER BY folder, channel_id")
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        let pair = |folder: &str, channel: &str| (folder.to_string(), channel.to_string());

        // One folder, with every channel.
        fill();
        sync_state::forget_folder(&conn, "/bare").unwrap();
        sync_state::forget_folder(&conn, "/m").unwrap();
        assert_eq!(left(), [pair("/other", "grp_a")]);
        // Every folder and channel but those kept.
        fill();
        sync_state::forget_except(&conn, &[pair("/m", "grp_a")]).unwrap();
        assert_eq!(left(), [pair("/m", "grp_a")]);
        // Every folder but those kept.
        fill();
        sync_state::forget_folders_except(&conn, &["/other".to_string()]).unwrap();
        assert_eq!(left(), [pair("/other", "grp_a")]);
    }

    /// A folder has at most 1,024 records. The one that goes for a new
    /// one is never the new one: a record with one half before any that
    /// is whole; of those of one kind, the one whose later half is oldest;
    /// of two as old, the one whose file's name sorts first.
    #[test]
    fn test_past_its_limit_a_folder_drops_one_record_for_each_new_one() {
        let conn = db::open_in_memory().unwrap();
        let max = INDEX_LINE_MAX_RECORDS as i64;
        let has = |file: &str| rows(&conn).iter().any(|row| row.0 == file);
        let count = || rows(&conn).len() as i64;
        let whole = |file: &str, at: i64| {
            line(&conn, file, "- a line", at);
            delete(&conn, file, at);
        };
        // Whole records up to the limit: two as old as each other, and
        // the rest newer, each a second after the one before.
        for file in ["old-b.md", "old-a.md"] {
            delete(&conn, file, T);
            line(&conn, file, "- a line", T + 5);
        }
        for n in 0..max - 2 {
            whole(&format!("w{n:04}.md"), T + 10 + n);
        }
        assert_eq!(count(), max);

        // One more, with every other record whole: the whole one whose
        // later half is oldest goes, and of two as old the first by name.
        line(&conn, "new-1.md", "- a line", T + 5000);
        assert_eq!(count(), max);
        assert!(!has("old-a.md") && has("old-b.md") && has("new-1.md"));
        // One more, with a record of one half among the others: that one
        // goes, before any whole record, and not the one just written.
        line(&conn, "new-2.md", "- a line", T + 5001);
        assert_eq!(count(), max);
        assert!(!has("new-1.md") && has("old-b.md") && has("new-2.md"));
        // Made whole, it is safe from the next, which sends the oldest
        // whole record out.
        delete(&conn, "new-2.md", T + 5002);
        whole("new-3.md", T + 5003);
        assert!(!has("old-b.md") && has("new-2.md") && has("w0000.md"));

        // Of records with one half, the oldest goes first, and of two as
        // old the first by name. (Room is made for two of them.)
        for file in ["w0000.md", "w0001.md"] {
            drop_record(&conn, "/m", "grp_a", file).unwrap();
        }
        line(&conn, "half-b.md", "- a line", T + 6000);
        delete(&conn, "half-a.md", T + 6000);
        assert_eq!(count(), max);
        line(&conn, "half-c.md", "- a line", T + 6001);
        assert!(!has("half-a.md") && has("half-b.md") && has("half-c.md"));
        line(&conn, "half-d.md", "- a line", T + 6002);
        assert!(!has("half-b.md") && has("half-c.md") && has("half-d.md"));
        // And no whole record went for any of them.
        assert!(has("w0002.md") && has("new-2.md") && has("new-3.md"));
        assert_eq!(count(), max);

        // A half written again is no new record, and nothing goes for it.
        line(&conn, "half-d.md", "- another line", T + 6004);
        assert!(has("half-c.md") && has("half-d.md"));
        assert_eq!(count(), max);
        // Another folder's records are not counted with these.
        line_removed(&conn, "/other", "grp_a", "x.md", "- a line", T).unwrap();
        assert_eq!(count(), max + 1);
    }
}
