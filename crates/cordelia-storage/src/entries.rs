//! Entries of a channel from its secret, as a node stores them (decision
//! 2026-10-04 §2.3, §2.4).
//!
//! They are in a table of their own, `entries`, beside `items`. A channel
//! is known here by its ID alone: a relay stores an entry with no list of
//! members and no state of the channel.
//!
//! The store's rule (§2.4, item 2): **it keeps the newest revision for
//! each author in each slot.** An entry at the revision of one it holds
//! from that author in that slot is not stored, and neither is a lower
//! one. Nothing here compares one author's entries with another's, so no
//! author can hide or displace what another stored.
//!
//! The rule is in the statement that writes: a row is replaced only by a
//! higher revision, whoever else is writing to the database. What became
//! of an entry is read from what that statement did.
//!
//! [`store`] takes only an entry that passed the check
//! ([`cordelia_crypto::entry::Entry::check`]), so nothing unchecked is
//! stored. What is read from a slot is checked again as it is read, and
//! handed out as checked ([`slot_entries`]). What is read to be sent is
//! handed out as it is stored ([`channel_entries_after`]): whoever
//! receives it checks it.

use rusqlite::{Connection, params};

use cordelia_core::CordeliaError;
use cordelia_core::protocol::ENTRY_OVERHEAD_BYTES;
use cordelia_crypto::entry::{CheckedEntry, Entry};

/// What became of an entry that the store was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// It was stored: the store held none from its author in its slot, or
    /// one at a lower revision, which it replaces.
    Stored,
    /// The store holds one at that revision from that author in that slot:
    /// this entry, or another that its author signed at that revision. It
    /// was not stored.
    AlreadyHeld,
    /// The store holds one at a higher revision from that author in that
    /// slot. It was not stored.
    OlderThanHeld,
}

/// An entry as the store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEntry {
    pub entry: Entry,
    /// Its place in the order in which this node stored its entries.
    pub seq: i64,
    /// When this node stored it, in seconds, in UTC.
    pub stored_at: i64,
}

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

/// The columns that [`stored_entry_from_row`] reads, in its order.
const ENTRY_COLUMNS: &str = "channel_id, slot, author, rev, is_delete, content,
    author_sig, channel_sig, seq, stored_at";

/// Store an entry, by the store's rule, and say what became of it. `now`
/// is this node's time, in seconds, in UTC.
///
/// An entry that is stored takes the next place in this node's order of
/// storing, also where it replaces a lower revision: a peer that pages by
/// that order is handed the newer entry after the place it has reached.
pub fn store(conn: &Connection, entry: &CheckedEntry, now: i64) -> Result<Outcome, CordeliaError> {
    conn.execute_batch("SAVEPOINT store_entry")
        .map_err(storage)?;
    let stored = stored(conn, entry, now);
    let end = match stored {
        Ok(_) => "RELEASE store_entry",
        Err(_) => "ROLLBACK TO store_entry; RELEASE store_entry",
    };
    conn.execute_batch(end).map_err(storage)?;
    stored
}

fn stored(conn: &Connection, entry: &CheckedEntry, now: i64) -> Result<Outcome, CordeliaError> {
    let rev = rev_to_sql(entry.rev);
    // One statement stores the entry or leaves what is held, by the
    // store's own rule: a row from that author in that slot is replaced
    // only by a higher revision. Nothing is read first and decided on, so
    // no other writer can come between the reading and the writing. The
    // entry's place is the next in this node's order.
    let changed = conn
        .execute(
            "INSERT INTO entries (channel_id, slot, author, rev, is_delete, content,
                                  author_sig, channel_sig, seq, stored_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                     (SELECT value + 1 FROM counters WHERE name = 'entry_seq'), ?9)
             ON CONFLICT(channel_id, slot, author) DO UPDATE SET
                 rev = excluded.rev, is_delete = excluded.is_delete,
                 content = excluded.content, author_sig = excluded.author_sig,
                 channel_sig = excluded.channel_sig, seq = excluded.seq,
                 stored_at = excluded.stored_at
             WHERE excluded.rev > entries.rev",
            params![
                entry.channel.as_slice(),
                entry.slot.as_slice(),
                entry.author.as_slice(),
                rev,
                entry.delete,
                entry.content,
                entry.author_signature.as_slice(),
                entry.channel_signature.as_slice(),
                now,
            ],
        )
        .map_err(storage)?;
    if changed == 1 {
        // The place is taken: the next entry that is stored has the next.
        conn.execute(
            "UPDATE counters SET value = value + 1 WHERE name = 'entry_seq'",
            [],
        )
        .map_err(storage)?;
        return Ok(Outcome::Stored);
    }

    // It was not stored: the store holds one from that author in that
    // slot, at this revision or at a higher one. Which, is read from the
    // row that the statement left, and that no other writer has changed
    // since: the statement took the database for writing.
    let held: i64 = conn
        .query_row(
            "SELECT rev FROM entries WHERE channel_id = ?1 AND slot = ?2 AND author = ?3",
            params![
                entry.channel.as_slice(),
                entry.slot.as_slice(),
                entry.author.as_slice()
            ],
            |row| row.get(0),
        )
        .map_err(storage)?;
    Ok(if held == rev {
        Outcome::AlreadyHeld
    } else {
        Outcome::OlderThanHeld
    })
}

/// Every entry that the store holds in one slot of a channel, in the
/// order they were stored: at most one for each author.
///
/// Each is checked again as it is read, and handed out as checked. Only
/// checked entries are stored, so one that does not pass was changed
/// where it lay. It is left out, with a warning: it is no entry.
pub fn slot_entries(
    conn: &Connection,
    channel: &[u8; 32],
    slot: &[u8; 32],
) -> Result<Vec<CheckedEntry>, CordeliaError> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {ENTRY_COLUMNS} FROM entries
             WHERE channel_id = ?1 AND slot = ?2
             ORDER BY seq ASC"
        ))
        .map_err(storage)?;
    let rows = stmt
        .query_map(
            params![channel.as_slice(), slot.as_slice()],
            stored_entry_from_row,
        )
        .map_err(storage)?;
    let mut entries = Vec::new();
    for row in rows {
        let held = row.map_err(storage)?;
        match held.entry.check() {
            Ok(entry) => entries.push(entry),
            Err(e) => tracing::warn!(
                seq = held.seq,
                "a stored entry does not pass the check, and is left out: {e}"
            ),
        }
    }
    Ok(entries)
}

/// Every slot of a channel in which the store holds an entry, in the order
/// in which each slot's oldest entry was stored. A device reads a whole
/// channel of its own by its slots, to carry what it holds of it (decision
/// 2026-10-04 §7.3).
pub fn channel_slots(
    conn: &Connection,
    channel: &[u8; 32],
) -> Result<Vec<[u8; 32]>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT slot FROM entries WHERE channel_id = ?1
             GROUP BY slot
             ORDER BY MIN(seq)",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map(params![channel.as_slice()], |row| row.get(0))
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// The entries of a channel that this node stored after the place
/// `after_seq`, in the order it stored them, and at most `limit` of them:
/// one page of the channel, for sending. The place of the last one is
/// where the next page starts, and 0 is before the first.
///
/// The order is this node's own. An entry that replaced a lower revision
/// has a later place than the one it replaced, so a peer that pages with
/// it never misses the newest revision.
pub fn channel_entries_after(
    conn: &Connection,
    channel: &[u8; 32],
    after_seq: i64,
    limit: u32,
) -> Result<Vec<StoredEntry>, CordeliaError> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {ENTRY_COLUMNS} FROM entries
             WHERE channel_id = ?1 AND seq > ?2
             ORDER BY seq ASC
             LIMIT ?3"
        ))
        .map_err(storage)?;
    let rows = stmt
        .query_map(
            params![channel.as_slice(), after_seq, limit],
            stored_entry_from_row,
        )
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Remove every entry of a channel. Returns how many there were.
pub fn remove_channel(conn: &Connection, channel: &[u8; 32]) -> Result<usize, CordeliaError> {
    conn.execute(
        "DELETE FROM entries WHERE channel_id = ?1",
        params![channel.as_slice()],
    )
    .map_err(storage)
}

/// The bytes that a channel holds here: each entry counted at its
/// content's size and what an entry takes beyond it
/// ([`cordelia_core::protocol::entry_cost`]). A relay counts its room by
/// this, so that an entry which replaces one of its size changes nothing
/// (decision 2026-10-04 §16).
pub fn channel_cost(conn: &Connection, channel: &[u8; 32]) -> Result<u64, CordeliaError> {
    conn.query_row(
        "SELECT COALESCE(SUM(length(content)), 0) + COUNT(*) * ?2 FROM entries
         WHERE channel_id = ?1",
        params![channel.as_slice(), ENTRY_OVERHEAD_BYTES as i64],
        |row| row.get::<_, i64>(0),
    )
    .map(|bytes| bytes.max(0) as u64)
    .map_err(storage)
}

/// A revision is a number below 2^53, on the wire and here: a checked
/// entry's always fits.
fn rev_to_sql(rev: u64) -> i64 {
    i64::try_from(rev).unwrap_or(i64::MAX)
}

/// Map a row selected with [`ENTRY_COLUMNS`] to a [`StoredEntry`].
fn stored_entry_from_row(row: &rusqlite::Row) -> rusqlite::Result<StoredEntry> {
    Ok(StoredEntry {
        entry: Entry {
            channel: row.get(0)?,
            slot: row.get(1)?,
            author: row.get(2)?,
            rev: row.get::<_, i64>(3)?.max(0) as u64,
            delete: row.get(4)?,
            content: row.get(5)?,
            author_signature: row.get(6)?,
            channel_signature: row.get(7)?,
        },
        seq: row.get(8)?,
        stored_at: row.get(9)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use cordelia_core::protocol::entry_cost;
    use cordelia_crypto::derive;
    use cordelia_crypto::entry::{Inside, Link, Value};
    use cordelia_crypto::identity::NodeIdentity;
    use cordelia_crypto::slots::slot_id;

    const SECRET: [u8; 32] = [0x11; 32];
    const OTHER_SECRET: [u8; 32] = [0x12; 32];
    const NOW: i64 = 1_800_000_000;

    fn device(n: u8) -> NodeIdentity {
        NodeIdentity::from_seed([n; 32]).unwrap()
    }

    fn key(n: u8) -> [u8; 32] {
        device(n).public_key()
    }

    fn channel() -> [u8; 32] {
        derive::channel_id(&SECRET).unwrap()
    }

    fn other_channel() -> [u8; 32] {
        derive::channel_id(&OTHER_SECRET).unwrap()
    }

    fn slot(name: &str) -> [u8; 32] {
        slot_id(&derive::slot_key(&SECRET).unwrap(), name)
    }

    /// An entry of the channel whose secret is `secret`, that device `n`
    /// made of `value` under `name` at `rev`, checked.
    fn made(secret: &[u8; 32], n: u8, rev: u64, name: &str, value: Value) -> CheckedEntry {
        let inside = Inside {
            name: name.to_string(),
            value,
            chain: Some(Vec::new()),
        };
        Entry::seal(secret, &device(n), rev, &inside)
            .unwrap()
            .check()
            .unwrap()
    }

    /// A text of [`SECRET`]'s channel.
    fn text(n: u8, rev: u64, name: &str, said: &str) -> CheckedEntry {
        made(&SECRET, n, rev, name, Value::Text(said.to_string()))
    }

    /// Every entry of [`SECRET`]'s channel, in the order it was stored.
    fn held(conn: &Connection) -> Vec<StoredEntry> {
        channel_entries_after(conn, &channel(), 0, 1000).unwrap()
    }

    /// The names by which the held entries of [`SECRET`]'s channel are
    /// known, in the order they were stored.
    fn ids(conn: &Connection) -> Vec<[u8; 32]> {
        held(conn).iter().map(|held| held.entry.id()).collect()
    }

    #[test]
    fn test_an_entry_is_stored_and_read_back_as_it_was() {
        let conn = db::open_in_memory().unwrap();
        let inside = Inside {
            name: "notes.md".to_string(),
            value: Value::Text("what the file holds".to_string()),
            chain: Some(vec![
                Link {
                    hash: [0x7e; 16],
                    signer: Link::signer_of(&key(3)),
                },
                Link {
                    hash: [0; 16],
                    signer: Link::signer_of(&key(2)),
                },
            ]),
        };
        // One with a chain of two links, one of a new name, and a delete.
        let saying = Entry::seal(&SECRET, &device(1), 5, &inside)
            .unwrap()
            .check()
            .unwrap();
        let own = text(2, 4, "notes.md", "another text");
        let delete = made(&SECRET, 4, 3, "notes.md", Value::Delete);
        for (place, entry) in [&saying, &own, &delete].into_iter().enumerate() {
            assert_eq!(
                store(&conn, entry, NOW + place as i64).unwrap(),
                Outcome::Stored
            );
        }

        let read = slot_entries(&conn, &channel(), &slot("notes.md")).unwrap();
        assert_eq!(read, [saying.clone(), own.clone(), delete.clone()]);
        assert_eq!(read[0].author, key(1));
        assert_eq!(read[0].open(&SECRET).unwrap(), inside);
        assert_eq!((read[1].rev, read[1].delete), (4, false));
        assert!(read[2].delete);

        // For sending: as it is stored, with its place and its time.
        let stored = held(&conn);
        let entries: Vec<&Entry> = stored.iter().map(|held| &held.entry).collect();
        assert_eq!(entries, [&*saying, &*own, &*delete]);
        let places: Vec<(i64, i64)> = stored
            .iter()
            .map(|held| (held.seq, held.stored_at))
            .collect();
        assert_eq!(places, [(1, NOW), (2, NOW + 1), (3, NOW + 2)]);
    }

    /// Stored, already held, older than held: the store's three answers,
    /// for one author in one slot.
    #[test]
    fn test_the_store_gives_one_of_three_answers() {
        let conn = db::open_in_memory().unwrap();
        let first = text(1, 5, "notes.md", "at five");

        // It holds none from that author in that slot: stored.
        assert_eq!(store(&conn, &first, NOW).unwrap(), Outcome::Stored);
        assert_eq!(ids(&conn), [first.id()]);

        // The entry it holds, given again: already held.
        assert_eq!(store(&conn, &first, NOW + 1).unwrap(), Outcome::AlreadyHeld);
        // Another entry that its author signed at that revision: not
        // stored, and the one it holds stays, with its place and time.
        let another = text(1, 5, "notes.md", "also at five");
        assert_ne!(another.id(), first.id());
        assert_eq!(
            store(&conn, &another, NOW + 1).unwrap(),
            Outcome::AlreadyHeld
        );
        assert_eq!(ids(&conn), [first.id()]);
        assert_eq!((held(&conn)[0].seq, held(&conn)[0].stored_at), (1, NOW));

        // A lower one: older than held, by one revision or by many.
        for rev in [4, 1] {
            let lower = text(1, rev, "notes.md", "lower");
            assert_eq!(
                store(&conn, &lower, NOW + 1).unwrap(),
                Outcome::OlderThanHeld
            );
            assert_eq!(ids(&conn), [first.id()]);
        }

        // A higher one: stored, in the place of the one it held.
        let newer = text(1, 6, "notes.md", "at six");
        assert_eq!(store(&conn, &newer, NOW + 2).unwrap(), Outcome::Stored);
        assert_eq!(ids(&conn), [newer.id()]);
        assert_eq!(held(&conn)[0].stored_at, NOW + 2);
        // And then the first is the older one.
        assert_eq!(
            store(&conn, &first, NOW + 3).unwrap(),
            Outcome::OlderThanHeld
        );
        assert_eq!(store(&conn, &newer, NOW + 3).unwrap(), Outcome::AlreadyHeld);
        assert_eq!(ids(&conn), [newer.id()]);
    }

    /// Two connections on one database file, as a node and a command have.
    /// A lower revision never takes the place of a higher, whichever is
    /// written last and by whichever connection, and each writer is given
    /// one of the three answers.
    #[test]
    fn test_a_lower_revision_never_takes_the_place_of_a_higher_whichever_writes_last() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cordelia.db");
        let (one, other) = (db::open(&path).unwrap(), db::open(&path).unwrap());
        let at = |rev: u64, name: &str| text(1, rev, name, &format!("at {rev}"));
        // The revision that each connection reads in the slot of `name`.
        let held_rev = |name: &str| -> u64 {
            let revs: Vec<u64> = [&one, &other]
                .iter()
                .map(|conn| {
                    let read = slot_entries(conn, &channel(), &slot(name)).unwrap();
                    assert_eq!(read.len(), 1, "{name}");
                    read[0].rev
                })
                .collect();
            assert_eq!(revs[0], revs[1], "{name}");
            revs[0]
        };

        // The higher is written first, and the lower last.
        assert_eq!(store(&one, &at(7, "a.md"), NOW).unwrap(), Outcome::Stored);
        assert_eq!(
            store(&other, &at(5, "a.md"), NOW).unwrap(),
            Outcome::OlderThanHeld
        );
        assert_eq!(held_rev("a.md"), 7);
        // The lower first, and the higher last.
        assert_eq!(store(&other, &at(5, "b.md"), NOW).unwrap(), Outcome::Stored);
        assert_eq!(store(&one, &at(7, "b.md"), NOW).unwrap(), Outcome::Stored);
        assert_eq!(held_rev("b.md"), 7);
        // And the lower again, from each: it is the older one to both.
        for conn in [&one, &other] {
            assert_eq!(
                store(conn, &at(5, "b.md"), NOW).unwrap(),
                Outcome::OlderThanHeld
            );
        }
        assert_eq!(held_rev("b.md"), 7);

        // One revision from each: the one written first stays, and the
        // other is told that one is held.
        let (first, second) = (at(9, "c.md"), text(1, 9, "c.md", "also at 9"));
        assert_ne!(first.id(), second.id());
        assert_eq!(store(&one, &first, NOW).unwrap(), Outcome::Stored);
        assert_eq!(store(&other, &second, NOW).unwrap(), Outcome::AlreadyHeld);
        assert_eq!(store(&other, &first, NOW).unwrap(), Outcome::AlreadyHeld);
        assert_eq!(
            slot_entries(&other, &channel(), &slot("c.md")).unwrap(),
            [first]
        );

        // The two write in one order: an entry that was not stored took no
        // place, and no place was given twice.
        for conn in [&one, &other] {
            let places: Vec<(i64, u64)> = channel_entries_after(conn, &channel(), 0, 100)
                .unwrap()
                .iter()
                .map(|held| (held.seq, held.entry.rev))
                .collect();
            assert_eq!(places, [(1, 7), (3, 7), (4, 9)]);
        }
    }

    /// Two writers at once, each with a connection of its own, offer the
    /// same author's revisions of one slot: one from the lowest up, and
    /// one from the highest down. Neither is ever refused for the other's
    /// writing: each offer is given one of the three answers. What the
    /// store holds never goes down, and ends at the highest.
    #[test]
    fn test_two_writers_at_once_are_each_given_one_of_the_three_answers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cordelia.db");
        // The database is made before either writes.
        drop(db::open(&path).unwrap());
        let offers: Vec<CheckedEntry> = (1..=60)
            .map(|rev| text(1, rev, "notes.md", &format!("at {rev}")))
            .collect();

        let writer = |order: Vec<CheckedEntry>| {
            let path = path.clone();
            std::thread::spawn(move || {
                let conn = db::open(&path).unwrap();
                let mut answers = Vec::new();
                let mut seen = 0;
                for entry in order {
                    let answer = store(&conn, &entry, NOW).expect("one of the three answers");
                    let held = slot_entries(&conn, &channel(), &entry.slot).unwrap();
                    assert_eq!(held.len(), 1);
                    // What is held is at least what was offered, and at
                    // least what this writer saw held before.
                    assert!(
                        held[0].rev >= entry.rev,
                        "{} below {}",
                        held[0].rev,
                        entry.rev
                    );
                    assert!(held[0].rev >= seen, "{} after {seen}", held[0].rev);
                    seen = held[0].rev;
                    answers.push((entry.rev, answer));
                }
                answers
            })
        };
        let up = writer(offers.clone());
        let down = writer(offers.iter().rev().cloned().collect());
        let (up, down) = (up.join().unwrap(), down.join().unwrap());
        assert_eq!((up.len(), down.len()), (60, 60));

        let conn = db::open(&path).unwrap();
        let held = slot_entries(&conn, &channel(), &slot("notes.md")).unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].rev, 60);
        // The highest was stored once, by whichever offered it first, and
        // no revision was stored by both.
        for rev in 1..=60u64 {
            let stored = up
                .iter()
                .chain(&down)
                .filter(|(offered, answer)| *offered == rev && *answer == Outcome::Stored)
                .count();
            assert!(stored <= 1, "revision {rev} stored {stored} times");
            if rev == 60 {
                assert_eq!(stored, 1);
            }
        }
        // The writer that went down stored its first offer or found it
        // held, and nothing it offered after that was stored.
        assert!(
            down[1..]
                .iter()
                .all(|(_, answer)| *answer == Outcome::OlderThanHeld)
        );
        // Each entry that was stored took the next place: the counter is
        // at the number of entries stored, and the row has the last.
        let stored = up
            .iter()
            .chain(&down)
            .filter(|(_, answer)| *answer == Outcome::Stored)
            .count() as i64;
        let (counter, place): (i64, i64) = conn
            .query_row(
                "SELECT (SELECT value FROM counters WHERE name = 'entry_seq'),
                        (SELECT seq FROM entries)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((counter, place), (stored, stored));
    }

    /// One row for each author in each slot of each channel. Nothing
    /// compares one author's entries with another's: none displaces
    /// another's, whatever its revision.
    #[test]
    fn test_the_store_keeps_the_newest_revision_for_each_author_in_each_slot() {
        let conn = db::open_in_memory().unwrap();
        let one = text(1, 5, "notes.md", "by one");
        assert_eq!(store(&conn, &one, NOW).unwrap(), Outcome::Stored);

        // Another author in that slot: below, at and above its revision.
        let lower = text(2, 3, "notes.md", "by another, lower");
        assert_eq!(store(&conn, &lower, NOW).unwrap(), Outcome::Stored);
        let same = text(3, 5, "notes.md", "by a third, at the same");
        assert_eq!(store(&conn, &same, NOW).unwrap(), Outcome::Stored);
        let higher = text(4, 9, "notes.md", "by a fourth, higher");
        assert_eq!(store(&conn, &higher, NOW).unwrap(), Outcome::Stored);
        assert_eq!(ids(&conn), [one.id(), lower.id(), same.id(), higher.id()]);

        // That author in another slot, at a lower revision: it is that
        // slot's first.
        let elsewhere = text(1, 2, "other.md", "by one, elsewhere");
        assert_eq!(store(&conn, &elsewhere, NOW).unwrap(), Outcome::Stored);
        // And in another channel.
        let another_channels = made(&OTHER_SECRET, 1, 2, "notes.md", Value::Delete);
        assert_eq!(
            store(&conn, &another_channels, NOW).unwrap(),
            Outcome::Stored
        );
        assert_eq!(held(&conn).len(), 5);

        // What became of an entry that is not stored is said by its own
        // author's row in its own slot: not by another author's higher
        // revision there, nor by that author's higher revision elsewhere.
        assert_eq!(store(&conn, &one, NOW).unwrap(), Outcome::AlreadyHeld);
        assert_eq!(store(&conn, &elsewhere, NOW).unwrap(), Outcome::AlreadyHeld);
        assert_eq!(held(&conn).len(), 5);

        // A newer revision by one author replaces that author's alone.
        let newer = text(2, 4, "notes.md", "by another, newer");
        assert_eq!(store(&conn, &newer, NOW).unwrap(), Outcome::Stored);
        assert_eq!(
            ids(&conn),
            [one.id(), same.id(), higher.id(), elsewhere.id(), newer.id()]
        );
        let in_slot = slot_entries(&conn, &channel(), &slot("notes.md")).unwrap();
        assert_eq!(
            in_slot,
            [one.clone(), same.clone(), higher.clone(), newer.clone()]
        );
    }

    #[test]
    fn test_one_slots_entries_are_read_alone() {
        let conn = db::open_in_memory().unwrap();
        let (a1, a2) = (text(1, 5, "a.md", "one"), text(2, 5, "a.md", "two"));
        let b1 = text(1, 7, "b.md", "three");
        let others = made(&OTHER_SECRET, 1, 5, "a.md", Value::Text("four".into()));
        for entry in [&a1, &b1, &a2, &others] {
            store(&conn, entry, NOW).unwrap();
        }
        assert_eq!(
            slot_entries(&conn, &channel(), &slot("a.md")).unwrap(),
            [a1, a2]
        );
        assert_eq!(
            slot_entries(&conn, &channel(), &slot("b.md")).unwrap(),
            [b1]
        );
        // A slot with nothing in it, and this channel's slot in another
        // channel.
        assert!(
            slot_entries(&conn, &channel(), &slot("c.md"))
                .unwrap()
                .is_empty()
        );
        assert!(
            slot_entries(&conn, &other_channel(), &slot("a.md"))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            slot_entries(&conn, &other_channel(), &others.slot).unwrap(),
            [others]
        );
    }

    /// A channel is paged in the order this node stored its entries, with
    /// a page size and the place of the last entry of the page before.
    #[test]
    fn test_a_channels_entries_are_paged_in_the_order_they_were_stored() {
        let conn = db::open_in_memory().unwrap();
        let entries: Vec<CheckedEntry> = (1..=5u8)
            .map(|n| text(n, 5, &format!("{n}.md"), "a text"))
            .collect();
        for entry in &entries {
            store(&conn, entry, NOW).unwrap();
        }
        // Another channel's entries are in no page of this one.
        let others = made(&OTHER_SECRET, 1, 5, "1.md", Value::Delete);
        store(&conn, &others, NOW).unwrap();

        let page = |after: i64, limit: u32| -> Vec<(i64, [u8; 32])> {
            channel_entries_after(&conn, &channel(), after, limit)
                .unwrap()
                .iter()
                .map(|held| (held.seq, held.entry.id()))
                .collect()
        };
        let id = |n: usize| entries[n - 1].id();
        assert_eq!(page(0, 2), [(1, id(1)), (2, id(2))]);
        assert_eq!(page(2, 2), [(3, id(3)), (4, id(4))]);
        assert_eq!(page(4, 2), [(5, id(5))]);
        assert!(page(5, 2).is_empty());
        assert!(page(0, 0).is_empty());
        assert_eq!(page(0, 100).len(), 5);
        assert_eq!(
            channel_entries_after(&conn, &other_channel(), 0, 100)
                .unwrap()
                .len(),
            1
        );

        // An entry that is not stored takes no place.
        assert_eq!(
            store(&conn, &entries[0], NOW).unwrap(),
            Outcome::AlreadyHeld
        );
        // A newer revision takes a new place, after every place handed out
        // so far: a peer that had paged past the one it replaces is handed
        // it on its next page.
        let newer = text(2, 6, "2.md", "a newer text");
        assert_eq!(store(&conn, &newer, NOW).unwrap(), Outcome::Stored);
        assert_eq!(page(5, 2), [(7, newer.id())]);
        assert_eq!(
            page(0, 100),
            [
                (1, id(1)),
                (3, id(3)),
                (4, id(4)),
                (5, id(5)),
                (7, newer.id())
            ]
        );

        // A place is never given twice, also not once its entry is gone.
        assert_eq!(remove_channel(&conn, &channel()).unwrap(), 5);
        store(&conn, &entries[0], NOW).unwrap();
        assert_eq!(page(0, 100), [(8, id(1))]);
    }

    /// A channel's slots are each given once, in the order in which the
    /// first of their entries was stored, and no other channel's.
    #[test]
    fn test_a_channels_slots_are_each_given_once() {
        let conn = db::open_in_memory().unwrap();
        assert!(channel_slots(&conn, &channel()).unwrap().is_empty());

        for entry in [
            text(1, 5, "b.md", "one"),
            text(2, 5, "a.md", "two"),
            text(2, 7, "b.md", "three"),
            text(3, 1, "c.md", "four"),
        ] {
            store(&conn, &entry, NOW).unwrap();
        }
        let others = made(&OTHER_SECRET, 1, 5, "d.md", Value::Delete);
        store(&conn, &others, NOW).unwrap();
        assert_eq!(
            channel_slots(&conn, &channel()).unwrap(),
            [slot("b.md"), slot("a.md"), slot("c.md")]
        );
        assert_eq!(
            channel_slots(&conn, &other_channel()).unwrap(),
            [others.slot]
        );

        // A newer revision by one author moves no slot: its other entry is
        // where it was. Once every entry of a slot is replaced, the slot's
        // oldest entry is a later one.
        store(&conn, &text(1, 6, "b.md", "five"), NOW).unwrap();
        assert_eq!(
            channel_slots(&conn, &channel()).unwrap(),
            [slot("a.md"), slot("b.md"), slot("c.md")]
        );

        // A channel that was removed has none.
        remove_channel(&conn, &channel()).unwrap();
        assert!(channel_slots(&conn, &channel()).unwrap().is_empty());
        assert_eq!(channel_slots(&conn, &other_channel()).unwrap().len(), 1);
    }

    #[test]
    fn test_removing_a_channel_removes_its_entries_and_no_others() {
        let conn = db::open_in_memory().unwrap();
        for n in 1..=3u8 {
            store(&conn, &text(n, 5, "notes.md", "a text"), NOW).unwrap();
        }
        store(&conn, &text(1, 5, "other.md", "a text"), NOW).unwrap();
        let others = made(&OTHER_SECRET, 1, 5, "notes.md", Value::Delete);
        store(&conn, &others, NOW).unwrap();

        assert_eq!(remove_channel(&conn, &channel()).unwrap(), 4);
        assert!(held(&conn).is_empty());
        assert!(
            slot_entries(&conn, &channel(), &slot("notes.md"))
                .unwrap()
                .is_empty()
        );
        assert_eq!(channel_cost(&conn, &channel()).unwrap(), 0);
        // The other channel's entry is where it was.
        assert_eq!(
            slot_entries(&conn, &other_channel(), &others.slot).unwrap(),
            [others]
        );
        // A channel with nothing to remove.
        assert_eq!(remove_channel(&conn, &channel()).unwrap(), 0);
        // What was removed can be stored again: nothing of it is held.
        let again = text(1, 1, "notes.md", "a text");
        assert_eq!(store(&conn, &again, NOW).unwrap(), Outcome::Stored);
    }

    /// A channel's bytes are each entry's content and what an entry takes
    /// beyond it, so that many small entries count for what they take, and
    /// an entry that replaces one of its size changes nothing.
    #[test]
    fn test_a_channel_holds_each_entrys_content_and_what_it_takes_beyond_it() {
        let conn = db::open_in_memory().unwrap();
        assert_eq!(channel_cost(&conn, &channel()).unwrap(), 0);

        let small = text(1, 5, "a.md", "a small text");
        let large = text(2, 5, "a.md", &"x".repeat(3000));
        let delete = made(&SECRET, 3, 5, "b.md", Value::Delete);
        assert_eq!(
            (small.content.len(), large.content.len()),
            (256, 4096),
            "each a size class"
        );
        for entry in [&small, &large, &delete] {
            store(&conn, entry, NOW).unwrap();
        }
        assert_eq!(
            channel_cost(&conn, &channel()).unwrap(),
            (256 + 1024) + (4096 + 1024) + (256 + 1024)
        );
        let by_entry: u64 = held(&conn)
            .iter()
            .map(|held| entry_cost(held.entry.content.len()))
            .sum();
        assert_eq!(channel_cost(&conn, &channel()).unwrap(), by_entry);

        // Another channel's entries are that channel's.
        let others = made(&OTHER_SECRET, 1, 5, "a.md", Value::Delete);
        store(&conn, &others, NOW).unwrap();
        assert_eq!(channel_cost(&conn, &channel()).unwrap(), by_entry);
        assert_eq!(channel_cost(&conn, &other_channel()).unwrap(), 256 + 1024);

        // A newer revision of the same size takes the room of the one it
        // replaces, and one that is not stored takes none.
        store(&conn, &text(1, 6, "a.md", "another small text"), NOW).unwrap();
        store(&conn, &text(1, 4, "a.md", &"x".repeat(3000)), NOW).unwrap();
        assert_eq!(channel_cost(&conn, &channel()).unwrap(), by_entry);
        // A larger one takes the difference.
        store(&conn, &text(1, 7, "a.md", &"x".repeat(300)), NOW).unwrap();
        assert_eq!(channel_cost(&conn, &channel()).unwrap(), by_entry + 256);
    }

    /// Only a checked entry is stored, and what a slot hands out is
    /// checked again as it is read. A row that was changed where it lay
    /// passes no check, and is no entry of the slot.
    #[test]
    fn test_a_row_that_was_changed_where_it_lay_is_not_read_from_a_slot() {
        let conn = db::open_in_memory().unwrap();
        let (one, other) = (text(1, 5, "a.md", "one"), text(2, 5, "a.md", "two"));
        store(&conn, &one, NOW).unwrap();
        store(&conn, &other, NOW).unwrap();

        // Its revision is raised, under the signatures it had.
        let changed = conn
            .execute(
                "UPDATE entries SET rev = 9 WHERE author = ?1",
                params![key(1).as_slice()],
            )
            .unwrap();
        assert_eq!(changed, 1);
        assert_eq!(
            slot_entries(&conn, &channel(), &slot("a.md")).unwrap(),
            [other]
        );

        // So is one whose content was changed.
        conn.execute(
            "UPDATE entries SET content = zeroblob(256) WHERE author = ?1",
            params![key(2).as_slice()],
        )
        .unwrap();
        assert!(
            slot_entries(&conn, &channel(), &slot("a.md"))
                .unwrap()
                .is_empty()
        );
        // For sending, a row is handed out as it is: whoever receives it
        // checks it, and refuses these.
        let stored = held(&conn);
        assert_eq!(stored.len(), 2);
        for held in stored {
            assert!(held.entry.check().is_err());
        }
    }

    /// The table takes no row that cannot be an entry: a key, a slot or a
    /// signature of another length, a revision of 0, a second row for one
    /// author in one slot, and a second row at one place in a channel.
    #[test]
    fn test_the_table_refuses_a_row_that_is_no_entry() {
        let conn = db::open_in_memory().unwrap();
        // A row with a channel, an author, a revision, the two signatures
        // and a place, and the rest as an entry has it.
        type Row<'a> = (&'a [u8], &'a [u8], i64, &'a [u8], &'a [u8], i64);
        let insert = |(channel, author, rev, by_author, by_channel, seq): Row| {
            conn.execute(
                "INSERT INTO entries (channel_id, slot, author, rev, is_delete, content,
                                      author_sig, channel_sig, seq, stored_at)
                 VALUES (?1, X'0202020202020202020202020202020202020202020202020202020202020202',
                         ?2, ?3, 0, X'00', ?4, ?5, ?6, 0)",
                params![channel, author, rev, by_author, by_channel, seq],
            )
        };
        let (key, other_key, signed) = ([1u8; 32], [3u8; 32], [4u8; 64]);

        assert!(insert((&key[..31], &other_key, 1, &signed, &signed, 1)).is_err());
        assert!(insert((&[1u8; 33], &other_key, 1, &signed, &signed, 1)).is_err());
        assert!(insert((&key, &other_key[..31], 1, &signed, &signed, 1)).is_err());
        assert!(insert((&key, &other_key, 0, &signed, &signed, 1)).is_err());
        assert!(insert((&key, &other_key, 1, &signed[..63], &signed, 1)).is_err());
        assert!(insert((&key, &other_key, 1, &signed, &signed[..63], 1)).is_err());

        // The control. Then a second row for that author in that slot, and
        // a second row at one place in that channel.
        assert_eq!(insert((&key, &other_key, 1, &signed, &signed, 1)), Ok(1));
        assert!(insert((&key, &other_key, 2, &signed, &signed, 2)).is_err());
        assert!(insert((&key, &key, 2, &signed, &signed, 1)).is_err());
        assert_eq!(insert((&key, &key, 2, &signed, &signed, 2)), Ok(1));

        // Whether a row is a delete is yes or no.
        assert!(
            conn.execute("UPDATE entries SET is_delete = 2", [])
                .is_err()
        );
        assert_eq!(conn.execute("UPDATE entries SET is_delete = 1", []), Ok(2));
        // A slot is 32 bytes.
        assert!(conn.execute("UPDATE entries SET slot = X'02'", []).is_err());
    }
}
