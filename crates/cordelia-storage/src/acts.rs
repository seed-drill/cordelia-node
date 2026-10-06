//! What a person did on this device at a terminal, and what the device
//! still has to tell them (decision 2026-10-04 §5.1, §6, §8).
//!
//! Four tables, in the node's database beside what a device holds of its
//! person ([`crate::person`]), so that each changes in one transaction
//! with a statement:
//!
//! - **The keys a person typed** at `cordelia accept`
//!   (`person_typed_keys`), each with when it was typed, and with the row
//!   of §5.1 that the device stood in when its yes was said. A pair
//!   channel is read only with such a key, and only for an hour after it
//!   was typed (§2.2). A key with which a hand-over was taken is spent:
//!   it stays, to say what became of it, and reads nothing more.
//! - **The keys that a statement left out** (`person_left_out`): each key
//!   that this device counted as a device before a statement it applied,
//!   and that is in neither of that statement's lists (§8). Such a device
//!   holds the secret before, and may not know. It is shown, by its label,
//!   until a person clears it here or a later statement lists it.
//! - **The notices a person cleared** (`person_cleared`), each by what it
//!   is named by. A device added since the last change, and a device that
//!   has left, are shown on every device until a person clears them
//!   there, at a terminal (§5.2, §6).
//!
//! - **The words "left" that outlive a statement** (`person_left`): a
//!   device's word that it left is in the personal channel of the
//!   generation it left, which a device reads no more once it applies a
//!   statement. Where that statement still lists the device's key, and
//!   nobody had cleared the word here, it is kept: the key, and what its
//!   notice is named by. It is shown until a person clears it, or a
//!   statement lists the key no more (§5.2, §7.1).
//!
//! Nothing here decides anything: whether a key is still within its hour,
//! and what a notice is named by, are decided where these are read.

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

// ── The keys a person typed ──────────────────────────────────────────

/// A key that a person typed at `cordelia accept`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedKey {
    /// The key: the device that is to hand this one what it needs.
    pub key: [u8; 32],
    /// When it was typed, in seconds, by this device's clock.
    pub typed_at: i64,
    /// When a hand-over was taken with it. A key that has one is spent.
    pub taken_at: Option<i64>,
    /// What became of the last hand-over that was read with it.
    pub said: Option<String>,
    /// Where the device stood, of the rows of §5.1, when the key was
    /// typed and its yes was said: the name of that row. Empty for a key
    /// typed before rows were kept, which stands in none.
    pub stood: String,
}

fn typed_from_row(row: &rusqlite::Row) -> rusqlite::Result<TypedKey> {
    Ok(TypedKey {
        key: row.get(0)?,
        typed_at: row.get(1)?,
        taken_at: row.get(2)?,
        said: row.get(3)?,
        stood: row.get(4)?,
    })
}

/// A person typed `key` at `now`, where the device stood in the row
/// named `stood`. It takes the place of what was kept of that key: typed
/// again, a key that was spent reads again, for its hour, in the row it
/// was typed in this time.
pub fn type_key(
    conn: &Connection,
    key: &[u8; 32],
    stood: &str,
    now: i64,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO person_typed_keys (key, typed_at, taken_at, said, stood)
         VALUES (?1, ?2, NULL, NULL, ?3)
         ON CONFLICT(key) DO UPDATE SET
             typed_at = excluded.typed_at, taken_at = NULL, said = NULL,
             stood = excluded.stood",
        params![key.as_slice(), now, stood],
    )
    .map_err(storage)?;
    Ok(())
}

/// Every key that a person typed and that the device still keeps, in the
/// order they were typed.
pub fn typed_keys(conn: &Connection) -> Result<Vec<TypedKey>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT key, typed_at, taken_at, said, stood FROM person_typed_keys
             ORDER BY typed_at ASC, key ASC",
        )
        .map_err(storage)?;
    let rows = stmt.query_map([], typed_from_row).map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// What the device keeps of `key`, where a person typed it.
pub fn typed_key(conn: &Connection, key: &[u8; 32]) -> Result<Option<TypedKey>, CordeliaError> {
    conn.query_row(
        "SELECT key, typed_at, taken_at, said, stood FROM person_typed_keys WHERE key = ?1",
        params![key.as_slice()],
        typed_from_row,
    )
    .optional()
    .map_err(storage)
}

/// What became of a hand-over that was read with `key`, as it was typed
/// at `typed_at`, and was not taken: `said` is kept for a person to read.
/// A key that was typed again since, or is spent, is left as it is.
/// Returns whether it was kept.
pub fn say_of_typed_key(
    conn: &Connection,
    key: &[u8; 32],
    typed_at: i64,
    said: &str,
) -> Result<bool, CordeliaError> {
    conn.execute(
        "UPDATE person_typed_keys SET said = ?3
         WHERE key = ?1 AND typed_at = ?2 AND taken_at IS NULL",
        params![key.as_slice(), typed_at, said],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

/// A hand-over was taken with `key`, as it was typed at `typed_at`: the
/// key is spent at `now`, and `said` is what became of the hand-over. A
/// key that was typed again since, or is spent already, is left as it is.
/// Returns whether it was spent now.
pub fn spend_typed_key(
    conn: &Connection,
    key: &[u8; 32],
    typed_at: i64,
    now: i64,
    said: &str,
) -> Result<bool, CordeliaError> {
    conn.execute(
        "UPDATE person_typed_keys SET taken_at = ?3, said = ?4
         WHERE key = ?1 AND typed_at = ?2 AND taken_at IS NULL",
        params![key.as_slice(), typed_at, now, said],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

/// Keep nothing of the keys that were typed before `before`: what became
/// of them has been said for long enough. Returns how many went.
pub fn forget_typed_keys(conn: &Connection, before: i64) -> Result<usize, CordeliaError> {
    conn.execute(
        "DELETE FROM person_typed_keys WHERE typed_at < ?1",
        params![before],
    )
    .map_err(storage)
}

/// Keep nothing of any key that a person typed but `but`: the device has
/// come to follow a phrase with that key, and no other key that was typed
/// before reads anything after (decision 2026-10-04 §16). Returns how
/// many went.
pub fn forget_other_typed_keys(conn: &Connection, but: &[u8; 32]) -> Result<usize, CordeliaError> {
    conn.execute(
        "DELETE FROM person_typed_keys WHERE key != ?1",
        params![but.as_slice()],
    )
    .map_err(storage)
}

/// Keep nothing of any key that a person typed: the device has made a
/// phrase of its own (decision 2026-10-04 §16). Returns how many went.
pub fn forget_every_typed_key(conn: &Connection) -> Result<usize, CordeliaError> {
    conn.execute("DELETE FROM person_typed_keys", [])
        .map_err(storage)
}

// ── The keys that a statement left out ───────────────────────────────

/// A key that this device counted before a statement, and that is in
/// neither of that statement's lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftOut {
    pub key: [u8; 32],
    /// The label the key was known by: the statement's before, or the
    /// record's that added it.
    pub label: String,
    /// The number of the statement that left it out.
    pub number: u64,
    /// When this device applied that statement.
    pub noted_at: i64,
}

/// Every key that a statement left out and that is still shown, in order
/// of key.
pub fn left_out(conn: &Connection) -> Result<Vec<LeftOut>, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT key, label, number, noted_at FROM person_left_out ORDER BY key ASC")
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(LeftOut {
                key: row.get(0)?,
                label: row.get(1)?,
                number: row.get::<_, i64>(2)?.max(0) as u64,
                noted_at: row.get(3)?,
            })
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// The statement numbered `number`, applied at `now`, lists `key` in
/// neither of its lists, and this device counted it before, under
/// `label`. A key that is noted already stays as it was noted: the first
/// statement that left it out is the one named.
pub fn note_left_out(
    conn: &Connection,
    key: &[u8; 32],
    label: &str,
    number: u64,
    now: i64,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO person_left_out (key, label, number, noted_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(key) DO NOTHING",
        params![
            key.as_slice(),
            label,
            i64::try_from(number).unwrap_or(i64::MAX),
            now
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// Show `key` no longer as left out: a person cleared it, or a statement
/// lists it. Returns whether it was shown.
pub fn clear_left_out(conn: &Connection, key: &[u8; 32]) -> Result<bool, CordeliaError> {
    conn.execute(
        "DELETE FROM person_left_out WHERE key = ?1",
        params![key.as_slice()],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

// ── The words "left" that outlive a statement ────────────────────────

/// A device's word that it left, kept across a statement that still
/// lists its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftWord {
    /// The key of the device that said it left.
    pub key: [u8; 32],
    /// What the notice of it is named by: what a person clears.
    pub notice: [u8; 32],
    /// The number of the statement under which the device said so.
    pub number: u64,
    /// When this device noted it: when it applied the next statement.
    pub noted_at: i64,
}

/// The device whose key is `key` said that it left, under the statement
/// numbered `number`, and the statement that this device applies at `now`
/// still lists it: its word is kept, named by `notice`. A key whose word
/// is kept already keeps the one it has.
pub fn note_left(
    conn: &Connection,
    key: &[u8; 32],
    notice: &[u8; 32],
    number: u64,
    now: i64,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO person_left (key, notice, number, noted_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(key) DO NOTHING",
        params![
            key.as_slice(),
            notice.as_slice(),
            i64::try_from(number).unwrap_or(i64::MAX),
            now
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// Every word "left" that the device keeps, in order of key.
pub fn left_words(conn: &Connection) -> Result<Vec<LeftWord>, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT key, notice, number, noted_at FROM person_left ORDER BY key ASC")
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(LeftWord {
                key: row.get(0)?,
                notice: row.get(1)?,
                number: row.get::<_, i64>(2)?.max(0) as u64,
                noted_at: row.get(3)?,
            })
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Keep the word of `key` no longer: a person cleared it, or a statement
/// lists the key no more. Returns whether it was kept.
pub fn clear_left(conn: &Connection, key: &[u8; 32]) -> Result<bool, CordeliaError> {
    conn.execute(
        "DELETE FROM person_left WHERE key = ?1",
        params![key.as_slice()],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

// ── The notices a person cleared ─────────────────────────────────────

/// A person cleared the notice named `notice`, at `now`. Cleared twice,
/// it is cleared.
pub fn clear_notice(conn: &Connection, notice: &[u8; 32], now: i64) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO person_cleared (notice, cleared_at) VALUES (?1, ?2)
         ON CONFLICT(notice) DO NOTHING",
        params![notice.as_slice(), now],
    )
    .map_err(storage)?;
    Ok(())
}

/// Whether a person cleared the notice named `notice` on this device.
pub fn is_cleared(conn: &Connection, notice: &[u8; 32]) -> Result<bool, CordeliaError> {
    conn.query_row(
        "SELECT 1 FROM person_cleared WHERE notice = ?1",
        params![notice.as_slice()],
        |_| Ok(()),
    )
    .optional()
    .map(|found| found.is_some())
    .map_err(storage)
}

/// Keep no word of what was cleared: the notices were of a statement that
/// the device has left, and none of them is shown again. Returns how many
/// there were.
pub fn forget_cleared(conn: &Connection) -> Result<usize, CordeliaError> {
    conn.execute("DELETE FROM person_cleared", [])
        .map_err(storage)
}

/// Keep nothing of what a person typed, cleared or is to be told: for a
/// device that leaves the phrase it followed (decision 2026-10-04 §5.2).
/// Returns how many rows went.
pub fn forget_all(conn: &Connection) -> Result<usize, CordeliaError> {
    let mut gone = 0;
    for table in [
        "person_typed_keys",
        "person_left_out",
        "person_cleared",
        "person_left",
    ] {
        gone += conn
            .execute(&format!("DELETE FROM {table}"), [])
            .map_err(storage)?;
    }
    Ok(gone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    /// A typed key is kept with its time. Typed again it reads again from
    /// the new time, and what was said of the old typing is gone.
    #[test]
    fn test_a_typed_key_is_kept_with_its_time_and_typed_again_starts_again() {
        let conn = db::open_in_memory().unwrap();
        let (one, other) = ([1u8; 32], [2u8; 32]);
        assert_eq!(typed_key(&conn, &one).unwrap(), None);
        type_key(&conn, &one, "no_phrase", 100).unwrap();
        type_key(&conn, &other, "alone", 90).unwrap();
        let kept = typed_key(&conn, &one).unwrap().unwrap();
        assert_eq!(
            (kept.key, kept.typed_at, kept.taken_at, kept.said.clone()),
            (one, 100, None, None)
        );
        // With the row that the device stood in when it was typed.
        assert_eq!(kept.stood, "no_phrase");
        assert_eq!(typed_keys(&conn).unwrap()[0].stood, "alone");
        // In the order they were typed.
        let all: Vec<[u8; 32]> = typed_keys(&conn)
            .unwrap()
            .iter()
            .map(|typed| typed.key)
            .collect();
        assert_eq!(all, [other, one]);

        assert!(say_of_typed_key(&conn, &one, 100, "nothing was handed yet").unwrap());
        assert!(spend_typed_key(&conn, &one, 100, 130, "joined").unwrap());
        type_key(&conn, &one, "several", 200).unwrap();
        let again = typed_key(&conn, &one).unwrap().unwrap();
        assert_eq!(
            (again.typed_at, again.taken_at, again.said),
            (200, None, None)
        );
        // In the row it was typed in this time.
        assert_eq!(again.stood, "several");
        assert_eq!(typed_keys(&conn).unwrap().len(), 2);

        // Every key but one is forgotten, and then every key.
        type_key(&conn, &[7u8; 32], "several", 300).unwrap();
        assert_eq!(forget_other_typed_keys(&conn, &one).unwrap(), 2);
        let left: Vec<[u8; 32]> = typed_keys(&conn)
            .unwrap()
            .iter()
            .map(|typed| typed.key)
            .collect();
        assert_eq!(left, [one]);
        assert_eq!(forget_every_typed_key(&conn).unwrap(), 1);
        assert!(typed_keys(&conn).unwrap().is_empty());
    }

    /// A key is spent once, by the typing that took the hand-over: a
    /// spent key is not spent again, nothing more is said of it, and what
    /// came through under an older typing spends nothing.
    #[test]
    fn test_a_key_is_spent_once_and_only_by_the_typing_that_took_the_hand_over() {
        let conn = db::open_in_memory().unwrap();
        let key = [3u8; 32];
        type_key(&conn, &key, "no_phrase", 100).unwrap();
        // Another typing's time, and another key: nothing.
        assert!(!spend_typed_key(&conn, &key, 99, 110, "joined").unwrap());
        assert!(!spend_typed_key(&conn, &[4u8; 32], 100, 110, "joined").unwrap());
        assert!(!say_of_typed_key(&conn, &key, 99, "an old one").unwrap());
        assert_eq!(typed_key(&conn, &key).unwrap().unwrap().taken_at, None);

        assert!(spend_typed_key(&conn, &key, 100, 110, "joined").unwrap());
        let spent = typed_key(&conn, &key).unwrap().unwrap();
        assert_eq!(
            (spent.taken_at, spent.said.as_deref()),
            (Some(110), Some("joined"))
        );
        assert!(!spend_typed_key(&conn, &key, 100, 120, "again").unwrap());
        assert!(!say_of_typed_key(&conn, &key, 100, "again").unwrap());
        let spent = typed_key(&conn, &key).unwrap().unwrap();
        assert_eq!(
            (spent.taken_at, spent.said.as_deref()),
            (Some(110), Some("joined"))
        );

        // What was typed long ago goes when it is asked to.
        type_key(&conn, &[5u8; 32], "no_phrase", 500).unwrap();
        assert_eq!(forget_typed_keys(&conn, 500).unwrap(), 1);
        assert_eq!(typed_keys(&conn).unwrap().len(), 1);
    }

    /// A key that a statement left out is noted once, by the first
    /// statement that left it out, and is shown until it is cleared.
    #[test]
    fn test_a_key_that_a_statement_left_out_is_noted_once_and_shown_until_cleared() {
        let conn = db::open_in_memory().unwrap();
        let (one, other) = ([9u8; 32], [8u8; 32]);
        note_left_out(&conn, &one, "laptop", 2, 100).unwrap();
        note_left_out(&conn, &other, "desktop", 2, 100).unwrap();
        // A later statement that leaves it out too changes nothing.
        note_left_out(&conn, &one, "another name", 3, 200).unwrap();
        let shown = left_out(&conn).unwrap();
        assert_eq!(shown.len(), 2);
        assert_eq!(
            shown[1],
            LeftOut {
                key: one,
                label: "laptop".into(),
                number: 2,
                noted_at: 100
            }
        );
        assert_eq!(shown[0].key, other);
        assert!(clear_left_out(&conn, &one).unwrap());
        assert!(!clear_left_out(&conn, &one).unwrap());
        assert_eq!(left_out(&conn).unwrap().len(), 1);
    }

    /// A notice that was cleared is cleared, and no other is. A device
    /// that leaves its phrase keeps nothing of any of the three.
    #[test]
    fn test_a_notice_that_was_cleared_is_cleared_and_no_other() {
        let conn = db::open_in_memory().unwrap();
        let (one, other) = ([1u8; 32], [2u8; 32]);
        assert!(!is_cleared(&conn, &one).unwrap());
        clear_notice(&conn, &one, 100).unwrap();
        clear_notice(&conn, &one, 200).unwrap();
        assert!(is_cleared(&conn, &one).unwrap());
        assert!(!is_cleared(&conn, &other).unwrap());
        assert_eq!(forget_cleared(&conn).unwrap(), 1);
        assert!(!is_cleared(&conn, &one).unwrap());

        clear_notice(&conn, &one, 100).unwrap();
        type_key(&conn, &one, "no_phrase", 100).unwrap();
        note_left_out(&conn, &one, "laptop", 2, 100).unwrap();
        note_left(&conn, &one, &other, 2, 100).unwrap();
        assert_eq!(forget_all(&conn).unwrap(), 4);
        assert!(!is_cleared(&conn, &one).unwrap());
        assert!(typed_keys(&conn).unwrap().is_empty());
        assert!(left_out(&conn).unwrap().is_empty());
        assert!(left_words(&conn).unwrap().is_empty());
    }

    /// A word "left" is kept once for a key, as it was first noted, and
    /// until it is cleared.
    #[test]
    fn test_a_word_left_is_kept_once_for_a_key_until_it_is_cleared() {
        let conn = db::open_in_memory().unwrap();
        let (one, other) = ([9u8; 32], [8u8; 32]);
        assert!(left_words(&conn).unwrap().is_empty());
        note_left(&conn, &one, &[1u8; 32], 2, 100).unwrap();
        note_left(&conn, &other, &[2u8; 32], 2, 100).unwrap();
        // Noted again at a later statement, it keeps what it had.
        note_left(&conn, &one, &[3u8; 32], 3, 200).unwrap();
        let kept = left_words(&conn).unwrap();
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].key, other);
        assert_eq!(
            kept[1],
            LeftWord {
                key: one,
                notice: [1u8; 32],
                number: 2,
                noted_at: 100
            }
        );
        assert!(clear_left(&conn, &one).unwrap());
        assert!(!clear_left(&conn, &one).unwrap());
        let kept: Vec<[u8; 32]> = left_words(&conn)
            .unwrap()
            .iter()
            .map(|word| word.key)
            .collect();
        assert_eq!(kept, [other]);
    }
}
