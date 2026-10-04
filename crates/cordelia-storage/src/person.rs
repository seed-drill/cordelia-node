//! What a device holds of its person (decision 2026-10-04 §3 to §6).
//!
//! Five tables, in the node's database, so that everything here changes in
//! one transaction with a statement (§3):
//!
//! - **What it follows, and where it stands** (`person`, one row). The
//!   phrase's public key, the statement key and the ID of the phrase's
//!   channel: never the words (§5). The statement it has applied, as its
//!   signed bytes. And its state ([`State`]). A device with no row follows
//!   no phrase.
//! - **Its secrets, by statement number** (`person_secrets`). The one it
//!   has applied, and each one it left with the time it left it. A secret
//!   that was left is kept 90 days by the device's own clock, and then
//!   forgotten ([`forget_left_secrets`]).
//! - **The change entries it keeps** (`person_change_entries`). The latest
//!   it has seen, whole, to show to a relay; and, where it is in a fork,
//!   the one that was made apart (§4.5).
//! - **The records of additions it has seen** under the applied statement
//!   (`person_additions`), in the order it saw them, each counted or not
//!   (§6).
//! - **The names it holds** in the current generation (`person_names`),
//!   each with its channel's ID, so that either is found from the other.
//!
//! Nothing here decides anything: what a statement is to a device, who
//! counts and what is carried are decided where these are read. A function
//! that writes more than one row does so as one, with a savepoint, so that
//! it is whole inside a transaction of the caller's and whole without one.

use std::fmt;

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;
use cordelia_core::protocol::LEFT_SECRET_KEPT_DAYS;
use cordelia_crypto::entry::{CheckedEntry, Entry};

/// How long a secret that was left is kept, in seconds.
const KEPT_SECS: i64 = LEFT_SECRET_KEPT_DAYS as i64 * 24 * 60 * 60;

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

/// Where a device that follows a phrase stands (decision 2026-10-04 §4.2,
/// §4.3, §4.5). In every state but the first it has stopped: it neither
/// publishes in its own channels nor takes from them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// It has applied a statement, and is a device under it.
    Applied,
    /// It has seen a statement that was made apart from the one it has
    /// applied. It keeps both change entries until the two are settled.
    Fork,
    /// A statement made after the one it has applied lists its key as
    /// removed.
    Removed,
    /// A statement made after the one it has applied lists its key in
    /// neither list.
    NotListed,
    /// A statement made after the one it has applied lists it, and the
    /// secret that came with it did not open, or was not there.
    NotOpened,
}

impl State {
    fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Fork => "fork",
            Self::Removed => "removed",
            Self::NotListed => "not_listed",
            Self::NotOpened => "not_opened",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [
            Self::Applied,
            Self::Fork,
            Self::Removed,
            Self::NotListed,
            Self::NotOpened,
        ]
        .into_iter()
        .find(|state| state.as_str() == text)
    }
}

/// What a device follows (decision 2026-10-04 §5): never the words.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Following {
    /// The public half of the phrase's signing key.
    pub phrase_key: [u8; 32],
    /// The statement key, which opens the part of a change entry that is
    /// for the devices.
    pub statement_key: [u8; 32],
    /// The ID of the phrase's channel, where the change entry is.
    pub phrase_channel: [u8; 32],
}

/// The one row of `person`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub state: State,
    pub following: Following,
    /// The statement the device has applied: its canonical form and then
    /// its signature.
    pub statement: Vec<u8>,
}

/// A person secret that the device holds.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
    /// The number of the statement that commits to it.
    pub number: u64,
    pub secret: [u8; 32],
    /// When the device left its generation, in seconds, by its own clock.
    /// `None` for the one it has applied.
    pub left_at: Option<i64>,
}

/// Which of the change entries a device keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kept {
    /// The latest it has seen: the one it shows to a relay.
    Latest,
    /// The one that was made apart from it, where the device is in a fork.
    Apart,
}

impl Kept {
    fn as_str(self) -> &'static str {
        match self {
            Self::Latest => "latest",
            Self::Apart => "apart",
        }
    }
}

/// A record of an addition, as the device keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeptAddition {
    /// Its place in the order in which the device saw the records.
    pub seen: i64,
    /// The signed record.
    pub record: Vec<u8>,
    /// The key it adds.
    pub key: [u8; 32],
    /// The key of the device that added it.
    pub adder: [u8; 32],
    /// Whether the key counts by this record.
    pub counted: bool,
    /// When the device saw it, in seconds.
    pub seen_at: i64,
}

/// A name the device holds, with its channel in the current generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldName {
    pub name: String,
    pub channel: [u8; 32],
    /// When the device came to hold it, in seconds.
    pub held_at: i64,
}

// ── What it follows, and where it stands ─────────────────────────────

/// What the device follows, the statement it has applied and its state.
/// `None` where it follows no phrase.
pub fn person(conn: &Connection) -> Result<Option<Person>, CordeliaError> {
    let row: Option<(String, Following, Vec<u8>)> = conn
        .query_row(
            "SELECT state, phrase_key, statement_key, phrase_channel, statement FROM person",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    Following {
                        phrase_key: row.get(1)?,
                        statement_key: row.get(2)?,
                        phrase_channel: row.get(3)?,
                    },
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?;
    let Some((state, following, statement)) = row else {
        return Ok(None);
    };
    let state = State::parse(&state)
        .ok_or_else(|| CordeliaError::Storage(format!("a device is in no state called {state}")))?;
    Ok(Some(Person {
        state,
        following,
        statement,
    }))
}

/// Write the one row: what the device follows, the statement it has
/// applied and its state, in the place of what was there.
pub fn put_person(conn: &Connection, person: &Person) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO person (one, state, phrase_key, statement_key, phrase_channel, statement)
         VALUES (1, ?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(one) DO UPDATE SET
             state = excluded.state, phrase_key = excluded.phrase_key,
             statement_key = excluded.statement_key,
             phrase_channel = excluded.phrase_channel, statement = excluded.statement",
        params![
            person.state.as_str(),
            person.following.phrase_key.as_slice(),
            person.following.statement_key.as_slice(),
            person.following.phrase_channel.as_slice(),
            person.statement,
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// Change the state of a device that follows a phrase, and nothing else
/// of its row. A device that follows none has no state to change.
pub fn set_state(conn: &Connection, state: State) -> Result<(), CordeliaError> {
    let changed = conn
        .execute("UPDATE person SET state = ?1", params![state.as_str()])
        .map_err(storage)?;
    if changed != 1 {
        return Err(CordeliaError::Storage(
            "a device that follows no phrase has no state".into(),
        ));
    }
    Ok(())
}

// ── Its secrets ──────────────────────────────────────────────────────

/// Every secret the device holds: the one it has applied first, and then
/// those it left, the one it left last first.
pub fn secrets(conn: &Connection) -> Result<Vec<Secret>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT number, secret, left_at FROM person_secrets
             ORDER BY left_at IS NOT NULL, left_at DESC, number DESC, secret",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(Secret {
                number: row.get::<_, i64>(0)?.max(0) as u64,
                secret: row.get(1)?,
                left_at: row.get(2)?,
            })
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// The secret of the statement the device has applied, with its number.
pub fn applied_secret(conn: &Connection) -> Result<Option<Secret>, CordeliaError> {
    Ok(secrets(conn)?
        .into_iter()
        .find(|secret| secret.left_at.is_none()))
}

/// The device applies the secret of statement `number`: the one it had
/// applied is kept as left at `now`, and this one is the applied one. Both
/// happen, or neither.
pub fn apply_secret(
    conn: &Connection,
    number: u64,
    secret: &[u8; 32],
    now: i64,
) -> Result<(), CordeliaError> {
    conn.execute_batch("SAVEPOINT person_secret")
        .map_err(storage)?;
    let applied = (|| {
        conn.execute(
            "UPDATE person_secrets SET left_at = ?1 WHERE left_at IS NULL",
            params![now],
        )?;
        conn.execute(
            "INSERT INTO person_secrets (number, secret, left_at) VALUES (?1, ?2, NULL)",
            params![i64::try_from(number).unwrap_or(i64::MAX), secret.as_slice()],
        )
    })()
    .map(|_| ())
    .map_err(storage);
    let end = match applied {
        Ok(()) => "RELEASE person_secret",
        Err(_) => "ROLLBACK TO person_secret; RELEASE person_secret",
    };
    conn.execute_batch(end).map_err(storage)?;
    applied
}

/// Forget each secret that the device left 90 days ago or longer, by its
/// own clock: `now` is that clock, in seconds. The secret it has applied
/// is never forgotten here. Returns how many were forgotten.
pub fn forget_left_secrets(conn: &Connection, now: i64) -> Result<usize, CordeliaError> {
    conn.execute(
        "DELETE FROM person_secrets WHERE left_at IS NOT NULL AND left_at + ?1 <= ?2",
        params![KEPT_SECS, now],
    )
    .map_err(storage)
}

// ── The change entries it keeps ──────────────────────────────────────

/// A change entry the device keeps, as it was stored: whoever reads it
/// checks it.
pub fn change_entry(conn: &Connection, kept: Kept) -> Result<Option<Entry>, CordeliaError> {
    conn.query_row(
        "SELECT channel, slot, author, rev, content, author_sig, channel_sig
         FROM person_change_entries WHERE kept = ?1",
        params![kept.as_str()],
        |row| {
            Ok(Entry {
                channel: row.get(0)?,
                slot: row.get(1)?,
                author: row.get(2)?,
                rev: row.get::<_, i64>(3)?.max(0) as u64,
                delete: false,
                content: row.get(4)?,
                author_signature: row.get(5)?,
                channel_signature: row.get(6)?,
            })
        },
    )
    .optional()
    .map_err(storage)
}

/// Keep a change entry, whole, in the place of the one kept there. Only
/// an entry that passed the check is kept. An entry that says it is a
/// delete is no change entry, and is refused.
pub fn keep_change_entry(
    conn: &Connection,
    kept: Kept,
    entry: &CheckedEntry,
) -> Result<(), CordeliaError> {
    if entry.delete {
        return Err(CordeliaError::Validation(
            "a change entry is no delete".into(),
        ));
    }
    conn.execute(
        "INSERT INTO person_change_entries
             (kept, channel, slot, author, rev, content, author_sig, channel_sig)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(kept) DO UPDATE SET
             channel = excluded.channel, slot = excluded.slot, author = excluded.author,
             rev = excluded.rev, content = excluded.content,
             author_sig = excluded.author_sig, channel_sig = excluded.channel_sig",
        params![
            kept.as_str(),
            entry.channel.as_slice(),
            entry.slot.as_slice(),
            entry.author.as_slice(),
            i64::try_from(entry.rev).unwrap_or(i64::MAX),
            entry.content,
            entry.author_signature.as_slice(),
            entry.channel_signature.as_slice(),
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// Keep a change entry no longer. Returns whether one was kept there.
pub fn drop_change_entry(conn: &Connection, kept: Kept) -> Result<bool, CordeliaError> {
    conn.execute(
        "DELETE FROM person_change_entries WHERE kept = ?1",
        params![kept.as_str()],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

// ── The records of additions it has seen ─────────────────────────────

/// Every record of an addition the device keeps, in the order it saw
/// them.
pub fn additions(conn: &Connection) -> Result<Vec<KeptAddition>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT seen, record, key, adder, counted, seen_at FROM person_additions
             ORDER BY seen ASC",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(KeptAddition {
                seen: row.get(0)?,
                record: row.get(1)?,
                key: row.get(2)?,
                adder: row.get(3)?,
                counted: row.get(4)?,
                seen_at: row.get(5)?,
            })
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Keep a record of an addition, after every record seen before it.
/// `record` is the signed record, `key` the key it adds and `adder` the
/// key that added it. Returns whether it was kept: a record that the
/// device already keeps is not kept twice, and stays as it was, counted
/// or not.
pub fn keep_addition(
    conn: &Connection,
    record: &[u8],
    key: &[u8; 32],
    adder: &[u8; 32],
    counted: bool,
    now: i64,
) -> Result<bool, CordeliaError> {
    conn.execute(
        "INSERT INTO person_additions (record, key, adder, counted, seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(record) DO NOTHING",
        params![record, key.as_slice(), adder.as_slice(), counted, now],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

/// Keep no record of an addition: the next statement's own list is what
/// stands (decision 2026-10-04 §6). Returns how many were kept.
pub fn clear_additions(conn: &Connection) -> Result<usize, CordeliaError> {
    conn.execute("DELETE FROM person_additions", [])
        .map_err(storage)
}

// ── The names it holds ───────────────────────────────────────────────

/// Every name the device holds, in order of name.
pub fn names(conn: &Connection) -> Result<Vec<HeldName>, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT name, channel, held_at FROM person_names ORDER BY name ASC")
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(HeldName {
                name: row.get(0)?,
                channel: row.get(1)?,
                held_at: row.get(2)?,
            })
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Hold `name`, whose channel in the current generation is `channel`.
/// Returns whether it is newly held: a name that the device already holds
/// stays as it is, with the time it came to hold it.
///
/// A channel is one name's: a second name with the channel of one that is
/// held is refused.
pub fn hold_name(
    conn: &Connection,
    name: &str,
    channel: &[u8; 32],
    now: i64,
) -> Result<bool, CordeliaError> {
    conn.execute(
        "INSERT INTO person_names (name, channel, held_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(name) DO NOTHING",
        params![name, channel.as_slice(), now],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

/// The channel of a name the device holds is `channel` from now on: the
/// name's channel in the generation the device has come to.
pub fn move_name(conn: &Connection, name: &str, channel: &[u8; 32]) -> Result<(), CordeliaError> {
    let changed = conn
        .execute(
            "UPDATE person_names SET channel = ?2 WHERE name = ?1",
            params![name, channel.as_slice()],
        )
        .map_err(storage)?;
    if changed != 1 {
        return Err(CordeliaError::Storage(format!(
            "the device does not hold the name {name}"
        )));
    }
    Ok(())
}

/// Hold a name no longer. Returns whether it was held.
pub fn drop_name(conn: &Connection, name: &str) -> Result<bool, CordeliaError> {
    conn.execute("DELETE FROM person_names WHERE name = ?1", params![name])
        .map(|rows| rows > 0)
        .map_err(storage)
}

/// The channel, in the current generation, of a name the device holds.
pub fn channel_of_name(conn: &Connection, name: &str) -> Result<Option<[u8; 32]>, CordeliaError> {
    conn.query_row(
        "SELECT channel FROM person_names WHERE name = ?1",
        params![name],
        |row| row.get(0),
    )
    .optional()
    .map_err(storage)
}

/// The name whose channel, in the current generation, is `channel`.
pub fn name_of_channel(
    conn: &Connection,
    channel: &[u8; 32],
) -> Result<Option<String>, CordeliaError> {
    conn.query_row(
        "SELECT name FROM person_names WHERE channel = ?1",
        params![channel.as_slice()],
        |row| row.get(0),
    )
    .optional()
    .map_err(storage)
}

// A secret and the statement key are not printed for debugging: what is
// shown is which statement a secret is of, and which phrase is followed.

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("number", &self.number)
            .field("left_at", &self.left_at)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Following {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Following")
            .field("phrase_key", &hex::encode(&self.phrase_key[..4]))
            .field("phrase_channel", &hex::encode(&self.phrase_channel[..4]))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use cordelia_crypto::entry::{Inside, Value};
    use cordelia_crypto::identity::NodeIdentity;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 24 * 60 * 60;

    fn following(n: u8) -> Following {
        Following {
            phrase_key: [n; 32],
            statement_key: [n + 1; 32],
            phrase_channel: [n + 2; 32],
        }
    }

    fn sample(state: State) -> Person {
        Person {
            state,
            following: following(0x20),
            statement: vec![1, 2, 3, 4],
        }
    }

    /// An entry that passed the check, of the channel whose secret is
    /// `secret`, at `rev`. A change entry is kept as any checked entry is:
    /// what is in it is for whoever reads it to say.
    fn entry(secret: u8, rev: u64, value: Value) -> CheckedEntry {
        let inside = Inside {
            name: "change".to_string(),
            value,
            chain: Some(Vec::new()),
        };
        let author = NodeIdentity::from_seed([0x31; 32]).unwrap();
        Entry::seal(&[secret; 32], &author, rev, &inside)
            .unwrap()
            .check()
            .unwrap()
    }

    fn text(secret: u8, rev: u64) -> CheckedEntry {
        entry(secret, rev, Value::Text("what it holds".to_string()))
    }

    // ── What it follows, and where it stands ─────────────────────────

    #[test]
    fn test_a_device_with_no_row_follows_no_phrase() {
        let conn = db::open_in_memory().unwrap();
        assert_eq!(person(&conn).unwrap(), None);
        assert_eq!(applied_secret(&conn).unwrap(), None);
        assert!(secrets(&conn).unwrap().is_empty());
        assert_eq!(change_entry(&conn, Kept::Latest).unwrap(), None);
        assert_eq!(change_entry(&conn, Kept::Apart).unwrap(), None);
        assert!(additions(&conn).unwrap().is_empty());
        assert!(names(&conn).unwrap().is_empty());
        // It has no state to change.
        assert!(set_state(&conn, State::Fork).is_err());
        assert_eq!(person(&conn).unwrap(), None);
    }

    #[test]
    fn test_what_a_device_follows_is_read_back_as_it_was_written() {
        let conn = db::open_in_memory().unwrap();
        for state in [
            State::Applied,
            State::Fork,
            State::Removed,
            State::NotListed,
            State::NotOpened,
        ] {
            put_person(&conn, &sample(state)).unwrap();
            assert_eq!(person(&conn).unwrap(), Some(sample(state)));
        }

        // There is one row: a second writing takes the place of the first.
        let other = Person {
            state: State::Applied,
            following: following(0x40),
            statement: vec![9; 300],
        };
        put_person(&conn, &other).unwrap();
        assert_eq!(person(&conn).unwrap(), Some(other.clone()));
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM person", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1);

        // A change of state changes the state, and nothing else.
        set_state(&conn, State::Removed).unwrap();
        assert_eq!(
            person(&conn).unwrap(),
            Some(Person {
                state: State::Removed,
                ..other
            })
        );
    }

    /// The six states a device can be in: no row, and five that the table
    /// names. It takes no other.
    #[test]
    fn test_a_device_is_in_one_of_six_states() {
        let conn = db::open_in_memory().unwrap();
        put_person(&conn, &sample(State::Applied)).unwrap();
        let names: Vec<&str> = [
            State::Applied,
            State::Fork,
            State::Removed,
            State::NotListed,
            State::NotOpened,
        ]
        .iter()
        .map(|state| state.as_str())
        .collect();
        assert_eq!(
            names,
            ["applied", "fork", "removed", "not_listed", "not_opened"]
        );
        for name in names {
            assert_eq!(
                conn.execute("UPDATE person SET state = ?1", params![name]),
                Ok(1)
            );
            assert_eq!(State::parse(name).map(State::as_str), Some(name));
        }
        assert!(
            conn.execute("UPDATE person SET state = 'settled'", [])
                .is_err()
        );
        assert_eq!(State::parse("settled"), None);
        // A second row, and a key of another length.
        assert!(
            conn.execute(
                "INSERT INTO person (one, state, phrase_key, statement_key, phrase_channel,
                                     statement)
                 SELECT 2, state, phrase_key, statement_key, phrase_channel, statement
                 FROM person",
                [],
            )
            .is_err()
        );
        for column in ["phrase_key", "statement_key", "phrase_channel"] {
            assert!(
                conn.execute(&format!("UPDATE person SET {column} = X'0102'"), [])
                    .is_err(),
                "{column}"
            );
        }
    }

    // ── Its secrets ──────────────────────────────────────────────────

    #[test]
    fn test_the_secret_it_has_applied_and_each_one_it_left_with_its_time() {
        let conn = db::open_in_memory().unwrap();
        apply_secret(&conn, 1, &[0xa1; 32], NOW).unwrap();
        assert_eq!(
            secrets(&conn).unwrap(),
            [Secret {
                number: 1,
                secret: [0xa1; 32],
                left_at: None
            }]
        );
        assert_eq!(applied_secret(&conn).unwrap().unwrap().number, 1);

        // The next is the applied one, and the first is left, with the
        // time. A device that was two statements behind leaves one.
        apply_secret(&conn, 2, &[0xa2; 32], NOW + 5).unwrap();
        apply_secret(&conn, 4, &[0xa4; 32], NOW + 9).unwrap();
        let held = secrets(&conn).unwrap();
        let said: Vec<(u64, u8, Option<i64>)> = held
            .iter()
            .map(|secret| (secret.number, secret.secret[0], secret.left_at))
            .collect();
        assert_eq!(
            said,
            [
                (4, 0xa4, None),
                (2, 0xa2, Some(NOW + 9)),
                (1, 0xa1, Some(NOW + 5))
            ]
        );
        assert_eq!(
            applied_secret(&conn).unwrap(),
            Some(Secret {
                number: 4,
                secret: [0xa4; 32],
                left_at: None
            })
        );
    }

    /// The table holds one applied secret at most, and a secret once. A
    /// writing that would break either changes nothing: the secret that
    /// was applied is still the applied one.
    #[test]
    fn test_one_secret_is_the_applied_one() {
        let conn = db::open_in_memory().unwrap();
        apply_secret(&conn, 1, &[0xa1; 32], NOW).unwrap();
        apply_secret(&conn, 2, &[0xa2; 32], NOW + 1).unwrap();

        // The secret it left, given again as one to apply: it is held
        // already, and both writings are undone.
        assert!(apply_secret(&conn, 1, &[0xa1; 32], NOW + 2).is_err());
        let applied = applied_secret(&conn).unwrap().unwrap();
        assert_eq!((applied.number, applied.left_at), (2, None));
        assert_eq!(secrets(&conn).unwrap().len(), 2);

        // A second secret with no time, written past the function.
        assert!(
            conn.execute(
                "INSERT INTO person_secrets (number, secret, left_at)
                 VALUES (3, zeroblob(32), NULL)",
                [],
            )
            .is_err()
        );
        // A number that no statement has, and a secret of another length.
        assert!(apply_secret(&conn, 0, &[0xa3; 32], NOW).is_err());
        assert!(apply_secret(&conn, 257, &[0xa3; 32], NOW).is_err());
        assert!(
            conn.execute(
                "INSERT INTO person_secrets (number, secret, left_at) VALUES (3, X'01', 5)",
                [],
            )
            .is_err()
        );
        assert_eq!(applied_secret(&conn).unwrap().unwrap().number, 2);

        // Two secrets of one number, where two changes were made apart.
        conn.execute(
            "INSERT INTO person_secrets (number, secret, left_at) VALUES (1, zeroblob(32), 5)",
            [],
        )
        .unwrap();
        assert_eq!(secrets(&conn).unwrap().len(), 3);
    }

    /// A secret that was left is kept 90 days by the device's own clock,
    /// and then forgotten. The applied one is never forgotten here.
    #[test]
    fn test_a_secret_that_was_left_is_forgotten_after_90_days() {
        let conn = db::open_in_memory().unwrap();
        apply_secret(&conn, 1, &[0xa1; 32], NOW - 400 * DAY).unwrap();
        apply_secret(&conn, 2, &[0xa2; 32], NOW).unwrap();
        apply_secret(&conn, 3, &[0xa3; 32], NOW + DAY).unwrap();
        let numbers = |conn: &Connection| -> Vec<u64> {
            secrets(conn)
                .unwrap()
                .iter()
                .map(|secret| secret.number)
                .collect()
        };
        assert_eq!(numbers(&conn), [3, 2, 1]);

        // One second short of 90 days after the first was left: all kept.
        assert_eq!(forget_left_secrets(&conn, NOW + 90 * DAY - 1).unwrap(), 0);
        assert_eq!(numbers(&conn), [3, 2, 1]);
        // A clock that has gone back forgets nothing.
        assert_eq!(forget_left_secrets(&conn, NOW - 500 * DAY).unwrap(), 0);
        assert_eq!(forget_left_secrets(&conn, 0).unwrap(), 0);

        // At 90 days the first is forgotten, and the second a day later.
        assert_eq!(forget_left_secrets(&conn, NOW + 90 * DAY).unwrap(), 1);
        assert_eq!(numbers(&conn), [3, 2]);
        assert_eq!(forget_left_secrets(&conn, NOW + 90 * DAY).unwrap(), 0);
        assert_eq!(forget_left_secrets(&conn, NOW + 91 * DAY).unwrap(), 1);
        assert_eq!(numbers(&conn), [3]);

        // The applied one stays, however long ago it was applied.
        assert_eq!(forget_left_secrets(&conn, NOW + 9000 * DAY).unwrap(), 0);
        assert_eq!(forget_left_secrets(&conn, i64::MAX).unwrap(), 0);
        let applied = applied_secret(&conn).unwrap().unwrap();
        assert_eq!((applied.number, applied.secret), (3, [0xa3; 32]));
        assert_eq!(KEPT_SECS, 7_776_000);
    }

    // ── The change entries it keeps ──────────────────────────────────

    #[test]
    fn test_a_change_entry_is_kept_whole_and_read_back_as_it_was() {
        let conn = db::open_in_memory().unwrap();
        let (latest, apart) = (text(0x51, 3), text(0x51, 4));
        keep_change_entry(&conn, Kept::Latest, &latest).unwrap();
        let read = change_entry(&conn, Kept::Latest).unwrap().unwrap();
        assert_eq!(read, *latest);
        // It is whole: it passes the check again, as it must to be shown
        // to a relay.
        assert_eq!(read.check().unwrap(), latest);
        assert_eq!(change_entry(&conn, Kept::Apart).unwrap(), None);

        // The second one, where the device is in a fork: each is kept in
        // its own place.
        keep_change_entry(&conn, Kept::Apart, &apart).unwrap();
        assert_eq!(change_entry(&conn, Kept::Latest).unwrap().unwrap(), *latest);
        assert_eq!(change_entry(&conn, Kept::Apart).unwrap().unwrap(), *apart);

        // A later one takes the place of the latest, and no other's.
        let later = text(0x51, 5);
        keep_change_entry(&conn, Kept::Latest, &later).unwrap();
        assert_eq!(change_entry(&conn, Kept::Latest).unwrap().unwrap(), *later);
        assert_eq!(change_entry(&conn, Kept::Apart).unwrap().unwrap(), *apart);

        assert!(drop_change_entry(&conn, Kept::Apart).unwrap());
        assert!(!drop_change_entry(&conn, Kept::Apart).unwrap());
        assert_eq!(change_entry(&conn, Kept::Apart).unwrap(), None);
        assert_eq!(change_entry(&conn, Kept::Latest).unwrap().unwrap(), *later);
    }

    #[test]
    fn test_what_is_no_change_entry_is_not_kept() {
        let conn = db::open_in_memory().unwrap();
        // A delete.
        let delete = entry(0x51, 3, Value::Delete);
        assert!(keep_change_entry(&conn, Kept::Latest, &delete).is_err());
        // A revision that no statement's number is.
        assert!(keep_change_entry(&conn, Kept::Latest, &text(0x51, 257)).is_err());
        assert_eq!(change_entry(&conn, Kept::Latest).unwrap(), None);

        // The table takes two rows, each in a place it names.
        keep_change_entry(&conn, Kept::Latest, &text(0x51, 256)).unwrap();
        assert!(
            conn.execute("UPDATE person_change_entries SET kept = 'third'", [])
                .is_err()
        );
        for column in ["channel", "slot", "author", "author_sig", "channel_sig"] {
            assert!(
                conn.execute(
                    &format!("UPDATE person_change_entries SET {column} = X'0102'"),
                    []
                )
                .is_err(),
                "{column}"
            );
        }
    }

    // ── The records of additions it has seen ─────────────────────────

    #[test]
    fn test_records_are_kept_in_the_order_they_were_seen() {
        let conn = db::open_in_memory().unwrap();
        let record = |n: u8| vec![n; 100];
        for (n, counted) in [(3u8, true), (1, false), (2, true)] {
            let kept = keep_addition(
                &conn,
                &record(n),
                &[n; 32],
                &[0xd0; 32],
                counted,
                NOW + i64::from(n),
            );
            assert!(kept.unwrap());
        }
        let held = additions(&conn).unwrap();
        let said: Vec<(u8, bool, i64)> = held
            .iter()
            .map(|kept| (kept.key[0], kept.counted, kept.seen_at))
            .collect();
        assert_eq!(
            said,
            [(3, true, NOW + 3), (1, false, NOW + 1), (2, true, NOW + 2)]
        );
        assert!(held.windows(2).all(|pair| pair[0].seen < pair[1].seen));
        assert_eq!(held[0].record, record(3));
        assert_eq!(held[0].adder, [0xd0; 32]);

        // A record that is kept is not kept twice, and stays as it was:
        // not counted, though it is given as counted.
        assert!(!keep_addition(&conn, &record(1), &[1; 32], &[0xd0; 32], true, NOW + 50).unwrap());
        assert_eq!(additions(&conn).unwrap(), held);

        // At the next statement none is kept.
        assert_eq!(clear_additions(&conn).unwrap(), 3);
        assert!(additions(&conn).unwrap().is_empty());
        assert_eq!(clear_additions(&conn).unwrap(), 0);
        // And the order starts again.
        keep_addition(&conn, &record(9), &[9; 32], &[0xd0; 32], true, NOW).unwrap();
        assert_eq!(additions(&conn).unwrap().len(), 1);

        // Whether a record is counted is yes or no, and a key is 32 bytes.
        assert!(
            conn.execute("UPDATE person_additions SET counted = 2", [])
                .is_err()
        );
        for column in ["key", "adder"] {
            assert!(
                conn.execute(
                    &format!("UPDATE person_additions SET {column} = X'0102'"),
                    []
                )
                .is_err(),
                "{column}"
            );
        }
    }

    // ── The names it holds ───────────────────────────────────────────

    #[test]
    fn test_a_channels_id_is_found_from_a_name_and_a_name_from_it() {
        let conn = db::open_in_memory().unwrap();
        assert!(hold_name(&conn, "team", &[0x71; 32], NOW).unwrap());
        assert!(hold_name(&conn, "github.com/owner/repo", &[0x72; 32], NOW + 1).unwrap());
        assert_eq!(channel_of_name(&conn, "team").unwrap(), Some([0x71; 32]));
        assert_eq!(
            name_of_channel(&conn, &[0x72; 32]).unwrap().as_deref(),
            Some("github.com/owner/repo")
        );
        assert_eq!(channel_of_name(&conn, "other").unwrap(), None);
        assert_eq!(name_of_channel(&conn, &[0x73; 32]).unwrap(), None);
        let held = names(&conn).unwrap();
        assert_eq!(
            held,
            [
                HeldName {
                    name: "github.com/owner/repo".to_string(),
                    channel: [0x72; 32],
                    held_at: NOW + 1
                },
                HeldName {
                    name: "team".to_string(),
                    channel: [0x71; 32],
                    held_at: NOW
                },
            ]
        );

        // A name that is held stays as it is.
        assert!(!hold_name(&conn, "team", &[0x79; 32], NOW + 9).unwrap());
        assert_eq!(names(&conn).unwrap(), held);
        // A channel is one name's, and a name is at least one byte.
        assert!(hold_name(&conn, "other", &[0x71; 32], NOW).is_err());
        assert!(hold_name(&conn, "", &[0x74; 32], NOW).is_err());
        assert_eq!(names(&conn).unwrap(), held);
        // A channel's ID is 32 bytes.
        assert!(
            conn.execute("UPDATE person_names SET channel = X'0102'", [])
                .is_err()
        );

        // At a statement a name's channel is another: the name is found
        // from the new one, and from the old one no more.
        move_name(&conn, "team", &[0x81; 32]).unwrap();
        assert_eq!(channel_of_name(&conn, "team").unwrap(), Some([0x81; 32]));
        assert_eq!(
            name_of_channel(&conn, &[0x81; 32]).unwrap().as_deref(),
            Some("team")
        );
        assert_eq!(name_of_channel(&conn, &[0x71; 32]).unwrap(), None);
        assert_eq!(names(&conn).unwrap()[1].held_at, NOW);
        // A name that is not held has no channel to move.
        assert!(move_name(&conn, "other", &[0x82; 32]).is_err());

        assert!(drop_name(&conn, "team").unwrap());
        assert!(!drop_name(&conn, "team").unwrap());
        assert_eq!(channel_of_name(&conn, "team").unwrap(), None);
        assert_eq!(names(&conn).unwrap().len(), 1);
    }

    #[test]
    fn test_what_a_device_holds_prints_no_secret() {
        let secret = Secret {
            number: 3,
            secret: [0x9c; 32],
            left_at: Some(7),
        };
        assert_eq!(
            format!("{secret:?}"),
            "Secret { number: 3, left_at: Some(7), .. }"
        );
        let person = Person {
            state: State::Applied,
            following: Following {
                phrase_key: [0x9a; 32],
                statement_key: [0x9d; 32],
                phrase_channel: [0x9b; 32],
            },
            statement: Vec::new(),
        };
        let printed = format!("{person:?}");
        assert!(printed.contains("phrase_key: \"9a9a9a9a\""), "{printed}");
        assert!(!printed.contains("9d9d") && !printed.contains("157"));
    }
}
