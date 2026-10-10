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
//!
//! ## What a reader keeps
//!
//! For each signer and generation a reader keeps H, the highest number it
//! has held of a message or a clearing, and rows only for the numbers
//! above H less the ring, the live numbers (§2.5): [`hold_number`] raises
//! H, counts what leaves the live numbers before it was shown, and drops
//! the rows of each number that leaves. [`index`] writes a message's row,
//! its row of numbers held and its row of first holding; the reader calls
//! it when it takes a message, and the sender when it writes one.
//!
//! **A message is shown** while it has a place, while one of its numbers
//! is live, and until 30 days after its shown time, the earlier of its
//! `sent` and when the device first held it (§7.1, [`shown_at`]). A place
//! is given when a message is first shown ([`give_places`]): newest first,
//! at most one lap of the ring to one signer in an hour in one generation,
//! counted over every place given in that hour (§6). Every time here is
//! the node's, passed in.

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::protocol::{
    AGENT_MESSAGE_ID_BYTES, AGENT_MESSAGE_KEPT_DAYS, AGENT_MESSAGE_RING,
    AGENT_MESSAGE_SUBJECT_CHARS,
};
use cordelia_crypto::message::{Message, To};

use crate::StorageError;

/// An hour, and a day, in seconds.
const HOUR_SECS: i64 = 60 * 60;
const DAY_SECS: i64 = 24 * HOUR_SECS;

/// The ring, as a count of numbers: the live numbers of a signer, and the
/// places a reader gives one signer in an hour (§2.5, §6).
const RING: i64 = AGENT_MESSAGE_RING as i64;

/// A message's ID.
pub type Id = [u8; AGENT_MESSAGE_ID_BYTES];

/// The generation of the messages channel whose ID is `channel`: the ID
/// of its row in `message_generations`, made the first time the device
/// holds that channel, with the number of the statement it was held
/// under (decision 2026-10-09 §9.2). A channel is one generation, under
/// whatever statement it is held again.
pub fn generation(
    conn: &Connection,
    channel: &[u8; 32],
    statement: u64,
    now: i64,
) -> Result<i64, StorageError> {
    conn.execute(
        "INSERT INTO message_generations (channel, statement, first_held) VALUES (?1, ?2, ?3)
         ON CONFLICT(channel) DO NOTHING",
        params![&channel[..], to_sql(statement), now],
    )?;
    Ok(conn.query_row(
        "SELECT id FROM message_generations WHERE channel = ?1",
        [&channel[..]],
        |row| row.get(0),
    )?)
}

/// What a reader keeps of one signer in one generation (decision
/// 2026-10-09 §2.5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Signer {
    /// H: the highest number held, of a message or a clearing. 0 where
    /// none is held.
    pub highest: u64,
    /// The numbers that left the live numbers before their message had a
    /// place, and the entries taken at a number that was not live.
    pub overwritten: u64,
    /// The entries of that signer that were no message (§2.2).
    pub not_messages: u64,
    /// The number from which what is overwritten is counted: the first
    /// held, or a lower one held after it while it was live.
    pub counted_from: Option<u64>,
}

/// What the device keeps of `signer` in `generation`, where it keeps
/// anything.
pub fn signer(
    conn: &Connection,
    signer: &[u8; 32],
    generation: i64,
) -> Result<Option<Signer>, StorageError> {
    Ok(conn
        .query_row(
            "SELECT highest, overwritten, not_messages, counted_from FROM message_signers
             WHERE signer = ?1 AND generation = ?2",
            params![&signer[..], generation],
            |row| {
                Ok(Signer {
                    highest: from_sql(row.get(0)?),
                    overwritten: from_sql(row.get(1)?),
                    not_messages: from_sql(row.get(2)?),
                    counted_from: row.get::<_, Option<i64>>(3)?.map(from_sql),
                })
            },
        )
        .optional()?)
}

fn keep_signer(
    conn: &Connection,
    of: &[u8; 32],
    generation: i64,
    kept: &Signer,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO message_signers (signer, generation, highest, overwritten, not_messages,
                                      counted_from)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(signer, generation) DO UPDATE SET
             highest = excluded.highest, overwritten = excluded.overwritten,
             not_messages = excluded.not_messages, counted_from = excluded.counted_from",
        params![
            &of[..],
            generation,
            to_sql(kept.highest),
            to_sql(kept.overwritten),
            to_sql(kept.not_messages),
            kept.counted_from.map(to_sql),
        ],
    )?;
    Ok(())
}

/// Count an entry of `of` in `generation` that is no message, no
/// clearing and no list (decision 2026-10-09 §2.2): it is never shown,
/// and `log` says how many there were.
pub fn not_a_message(
    conn: &Connection,
    of: &[u8; 32],
    generation: i64,
) -> Result<(), StorageError> {
    let mut kept = signer(conn, of, generation)?.unwrap_or_default();
    kept.not_messages += 1;
    keep_signer(conn, of, generation, &kept)
}

/// A reader holds an entry of `of` in `generation` at `number`, in the
/// slot of that number in the signer's ring (decision 2026-10-09 §2.5).
/// The caller has checked the slot before opening anything: nothing but
/// such an entry is given here. Returns whether `number` is live, after
/// it is held: only then is the entry opened.
///
/// - **Above H, it raises H.** Every number that was live and is no
///   longer leaves the reader's rows: its row of numbers held, its row of
///   first holding, and the index row of its message where none of that
///   message's numbers is left (overwritten first, [`drop_row`]). Each of
///   them from the number counted from is counted as overwritten, unless
///   its message had a place, or was held and has gone (it expired, or
///   was cleared): those it never held, and those it held and had not
///   shown.
/// - **At a live number,** it changes nothing but the number counted
///   from, where it is below it.
/// - **At a number that is not live,** the entry is counted as
///   overwritten, where it is below the number counted from: a number
///   at or above it was counted, or not, as it left.
pub fn hold_number(
    conn: &Connection,
    of: &[u8; 32],
    generation: i64,
    number: u64,
) -> Result<bool, StorageError> {
    let mut kept = signer(conn, of, generation)?.unwrap_or_default();
    let number_sql = to_sql(number);
    let highest = to_sql(kept.highest);
    let live = if number_sql > highest {
        if let Some(from) = kept.counted_from.map(to_sql) {
            // From the lowest live number under the old H, to the highest
            // that is not live under the new.
            let lowest = (highest - RING + 1).max(from);
            let left = number_sql - RING;
            if left >= lowest {
                kept.overwritten += from_sql(left_unshown(conn, of, generation, lowest, left)?);
            }
            leave_up_to(conn, of, generation, left)?;
        }
        kept.highest = number;
        kept.counted_from = Some(kept.counted_from.unwrap_or(number));
        true
    } else if number_sql > highest - RING {
        if kept.counted_from.is_none_or(|from| number < from) {
            kept.counted_from = Some(number);
        }
        true
    } else {
        if kept.counted_from.is_none_or(|from| number < from) {
            kept.overwritten += 1;
        }
        false
    };
    keep_signer(conn, of, generation, &kept)?;
    Ok(live)
}

/// How many of the numbers from `lowest` to `highest` of `of` left the
/// live numbers before their message had a place: all of them but those
/// held at a message that has a place, or that was held and has gone.
fn left_unshown(
    conn: &Connection,
    of: &[u8; 32],
    generation: i64,
    lowest: i64,
    highest: i64,
) -> Result<i64, StorageError> {
    let shown_or_gone: i64 = conn.query_row(
        "SELECT COUNT(*) FROM message_first_held f
         LEFT JOIN message_index i ON i.id = f.id
         WHERE f.signer = ?1 AND f.generation = ?2 AND f.number BETWEEN ?3 AND ?4
           AND (i.id IS NULL OR i.placed_at IS NOT NULL)",
        params![&of[..], generation, lowest, highest],
        |row| row.get(0),
    )?;
    Ok(highest - lowest + 1 - shown_or_gone)
}

/// Drop the rows of each number of `of` at or below `highest`, which are
/// live no longer: its rows of numbers held and of first holding, and
/// the index row of a message that is then held at no number.
fn leave_up_to(
    conn: &Connection,
    of: &[u8; 32],
    generation: i64,
    highest: i64,
) -> Result<(), StorageError> {
    let ids: Vec<Vec<u8>> = conn
        .prepare(
            "SELECT DISTINCT id FROM message_numbers
             WHERE signer = ?1 AND generation = ?2 AND number <= ?3",
        )?
        .query_map(params![&of[..], generation, highest], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    conn.execute(
        "DELETE FROM message_numbers WHERE signer = ?1 AND generation = ?2 AND number <= ?3",
        params![&of[..], generation, highest],
    )?;
    conn.execute(
        "DELETE FROM message_first_held WHERE signer = ?1 AND generation = ?2 AND number <= ?3",
        params![&of[..], generation, highest],
    )?;
    for id in ids {
        let held: i64 = conn.query_row(
            "SELECT COUNT(*) FROM message_numbers WHERE id = ?1",
            [&id],
            |row| row.get(0),
        )?;
        if held == 0 {
            drop_row(conn, &id)?;
        }
    }
    Ok(())
}

/// A message as it enters the index (decision 2026-10-09 §7.1): opened
/// by a reader from an entry it took, or written by its own sender.
#[derive(Debug, Clone, Copy)]
pub struct Opened<'a> {
    pub id: &'a Id,
    pub signer: &'a [u8; 32],
    /// The label the device knows the signer by.
    pub label: &'a str,
    pub generation: i64,
    /// The number it is held at.
    pub number: u64,
    pub message: &'a Message,
    /// When the device first held it: now.
    pub first_held: i64,
    /// Its place: none where a reader takes it, which gives it one when
    /// it first shows it, and the time it was written where it is the
    /// device's own (§2.3, §6).
    pub placed_at: Option<i64>,
}

/// What became of a message given to [`index`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Indexed {
    /// It was not held: it has its row now.
    New,
    /// It is held under another number of its signer: the number is added
    /// to its row, which is one row by its ID.
    AnotherNumber,
    /// It is not shown again: the device first held this number before,
    /// or held the message at another live number and its row has gone,
    /// at its 30 days or at a clearing (§7.1, D11).
    NotAgain,
}

/// Write a message into the index (decision 2026-10-09 §7.1), in the
/// caller's write: its row of first holding at its number, its index row
/// with every field it was opened to, and its row of numbers held. The
/// caller has held its number with [`hold_number`], and it is live.
///
/// A number whose row of first holding is there was held before: what is
/// taken again there is not shown again. A message held at another live
/// number is one row, with a row of numbers held for each.
pub fn index(conn: &Connection, opened: &Opened) -> Result<Indexed, StorageError> {
    let Opened {
        id,
        signer,
        generation,
        number,
        message,
        ..
    } = *opened;
    let number = to_sql(number);
    let held_before: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM message_first_held
             WHERE signer = ?1 AND generation = ?2 AND number = ?3",
            params![&signer[..], generation, number],
            |row| row.get(0),
        )
        .optional()?;
    if held_before.is_some() {
        return Ok(Indexed::NotAgain);
    }
    let first_held_before: i64 = conn.query_row(
        "SELECT COUNT(*) FROM message_first_held WHERE signer = ?1 AND generation = ?2 AND id = ?3",
        params![&signer[..], generation, &id[..]],
        |row| row.get(0),
    )?;
    // A `sent` past what the store's integer holds is later than any
    // first holding, and so is never the shown time.
    let sent = i64::try_from(message.sent).unwrap_or(i64::MAX);
    conn.execute(
        "INSERT INTO message_first_held (signer, generation, number, id, sent, first_held)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            &signer[..],
            generation,
            number,
            &id[..],
            sent,
            opened.first_held
        ],
    )?;
    let in_index: i64 = conn.query_row(
        "SELECT COUNT(*) FROM message_index WHERE id = ?1",
        [&id[..]],
        |row| row.get(0),
    )?;
    let indexed = match (in_index, first_held_before) {
        (0, 0) => {
            let (to_kind, to_name) = match &message.to {
                To::Name(name) => (1, Some(name.as_str())),
                To::All => (2, None),
            };
            let subject: String = message
                .subject()
                .chars()
                .take(AGENT_MESSAGE_SUBJECT_CHARS)
                .collect();
            conn.execute(
                "INSERT INTO message_index (id, signer, label, generation, to_kind, to_name,
                                            from_name, sent, subject, thread, answers, asks,
                                            link, body, first_held, placed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                params![
                    &id[..],
                    &signer[..],
                    opened.label,
                    generation,
                    to_kind,
                    to_name,
                    message.from,
                    sent,
                    subject,
                    &message.thread[..],
                    &message.answers[..],
                    message.asks,
                    message.link,
                    message.body,
                    opened.first_held,
                    opened.placed_at,
                ],
            )?;
            Indexed::New
        }
        (0, _) => return Ok(Indexed::NotAgain),
        _ => Indexed::AnotherNumber,
    };
    conn.execute(
        "INSERT INTO message_numbers (signer, generation, number, id) VALUES (?1, ?2, ?3, ?4)",
        params![&signer[..], generation, number, &id[..]],
    )?;
    Ok(indexed)
}

/// A reader takes the entry that clears message `number` of `of` in
/// `generation` (decision 2026-10-09 §2.3, D11): it drops the index row
/// of the message it holds at that number, whichever other numbers that
/// row was held at, in the caller's write. Its rows of first holding
/// stay, so that it is not shown again. Returns whether a row went.
pub fn clear(
    conn: &Connection,
    of: &[u8; 32],
    generation: i64,
    number: u64,
) -> Result<bool, StorageError> {
    let id: Option<Vec<u8>> = conn
        .query_row(
            "SELECT id FROM message_numbers WHERE signer = ?1 AND generation = ?2 AND number = ?3",
            params![&of[..], generation, to_sql(number)],
            |row| row.get(0),
        )
        .optional()?;
    match id {
        Some(id) => drop_row(conn, &id),
        None => Ok(false),
    }
}

/// A message's shown time: the earlier of its `sent` and when the device
/// first held it (decision 2026-10-09 §7.1, F1). Everything a device says
/// of when a message was sent is from it, and it is never later than the
/// first holding, so a `sent` ahead of the reader's clock gains nothing.
pub fn shown_at(sent: i64, first_held: i64) -> i64 {
    sent.min(first_held)
}

/// Whether a message of `sent` and `first_held` has expired at `now`: 30
/// days after its shown time (decision 2026-10-09 §7.1, property 11).
pub fn has_expired(sent: i64, first_held: i64, now: i64) -> bool {
    now.saturating_sub(shown_at(sent, first_held)) >= i64::from(AGENT_MESSAGE_KEPT_DAYS) * DAY_SECS
}

/// The SQL of the moment a row of `message_index` as `i` expires: its
/// shown time, and 30 days.
fn expires_sql() -> String {
    format!(
        "(MIN(i.sent, i.first_held) + {})",
        i64::from(AGENT_MESSAGE_KEPT_DAYS) * DAY_SECS
    )
}

/// The SQL of whether a row of `message_index` as `i` is held at a live
/// number: one above its signer's H, less the ring.
fn live_sql() -> String {
    format!(
        "EXISTS (SELECT 1 FROM message_numbers n
                 LEFT JOIN message_signers s
                     ON s.signer = n.signer AND s.generation = n.generation
                 WHERE n.id = i.id AND n.number > COALESCE(s.highest, 0) - {RING})"
    )
}

/// Give places to the messages that a reader is about to show (decision
/// 2026-10-09 §6, D2, F5), at `now` by its clock: to each signer's live
/// messages that have none and have not expired, **newest first, by
/// number**, while fewer than one lap of the ring (64) of that signer's
/// places in that generation lie in the hour before `now`. Every place
/// given in that hour counts, whatever became of its message since; one
/// whose time lies after `now` keeps its message's place and is not
/// counted. A message held at several numbers is one place, by the
/// highest. Returns how many were given.
///
/// **The device's own messages** (signed by `own`) take no place from
/// any signer's 64: one that has none, as one a relay handed back to a
/// store restored from before it was written, is given one with no time
/// in the hour (§2.3).
pub fn give_places(conn: &Connection, own: &[u8; 32], now: i64) -> Result<usize, StorageError> {
    // The times kept are those of the hour before now: no other counts.
    conn.execute(
        "DELETE FROM message_places WHERE placed_at <= ?1 OR placed_at > ?2",
        params![now - HOUR_SECS, now],
    )?;
    let waiting: Vec<(Vec<u8>, Vec<u8>, i64)> = conn
        .prepare(&format!(
            "SELECT i.id, i.signer, i.generation FROM message_index i
             JOIN message_numbers n ON n.id = i.id
             WHERE i.placed_at IS NULL AND ?1 < {expires} AND {live}
             GROUP BY i.id
             ORDER BY i.signer, i.generation, MAX(n.number) DESC",
            expires = expires_sql(),
            live = live_sql(),
        ))?
        .query_map([now], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let mut given = 0;
    let mut room: Option<(Vec<u8>, i64, i64)> = None;
    for (id, signer, generation) in waiting {
        let is_own = signer.as_slice() == own.as_slice();
        if !is_own {
            let left = match &room {
                Some((of, at, left)) if *of == signer && *at == generation => *left,
                _ => {
                    let placed: i64 = conn.query_row(
                        "SELECT COUNT(*) FROM message_places
                         WHERE signer = ?1 AND generation = ?2",
                        params![&signer, generation],
                        |row| row.get(0),
                    )?;
                    RING - placed
                }
            };
            room = Some((signer.clone(), generation, left));
            if left <= 0 {
                continue;
            }
            conn.execute(
                "INSERT INTO message_places (signer, generation, placed_at) VALUES (?1, ?2, ?3)",
                params![&signer, generation, now],
            )?;
            room = Some((signer.clone(), generation, left - 1));
        }
        conn.execute(
            "UPDATE message_index SET placed_at = ?2 WHERE id = ?1",
            params![&id, now],
        )?;
        given += 1;
    }
    Ok(given)
}

/// A message that is shown (decision 2026-10-09 §7.1): it has a place,
/// one of its numbers is live, and its 30 days are not up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    pub id: Vec<u8>,
    pub signer: Vec<u8>,
    pub label: String,
    pub generation: i64,
    /// The name it is to, or none for every name.
    pub to: Option<String>,
    pub from: String,
    pub sent: i64,
    pub first_held: i64,
    /// Its shown time ([`shown_at`]).
    pub shown_at: i64,
    /// Its first line, cut to 80 Unicode scalar values.
    pub subject: String,
    pub thread: Vec<u8>,
    pub answers: Vec<u8>,
    pub asks: bool,
    pub link: Option<String>,
    pub body: String,
    pub placed_at: i64,
}

/// Every message shown at `now`, oldest first: by shown time, and between
/// two of one shown time by ID (decision 2026-10-09 §4.1, F9). It gives
/// no place: a show gives places first ([`give_places`]).
pub fn shown(conn: &Connection, now: i64) -> Result<Vec<Shown>, StorageError> {
    let shown = conn
        .prepare(&format!(
            "SELECT i.id, i.signer, i.label, i.generation, i.to_name, i.from_name, i.sent,
                    i.first_held, MIN(i.sent, i.first_held) AS shown_at, i.subject, i.thread,
                    i.answers, i.asks, i.link, i.body, i.placed_at
             FROM message_index i
             WHERE i.placed_at IS NOT NULL AND ?1 < {expires} AND {live}
             ORDER BY shown_at, i.id",
            expires = expires_sql(),
            live = live_sql(),
        ))?
        .query_map([now], |row| {
            Ok(Shown {
                id: row.get(0)?,
                signer: row.get(1)?,
                label: row.get(2)?,
                generation: row.get(3)?,
                to: row.get(4)?,
                from: row.get(5)?,
                sent: row.get(6)?,
                first_held: row.get(7)?,
                shown_at: row.get(8)?,
                subject: row.get(9)?,
                thread: row.get(10)?,
                answers: row.get(11)?,
                asks: row.get(12)?,
                link: row.get(13)?,
                body: row.get(14)?,
                placed_at: row.get(15)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(shown)
}

/// How many live messages of `of` in `generation` that have not expired
/// wait for a place at `now`: held back by the reader's hour (§6).
pub fn held_back(
    conn: &Connection,
    of: &[u8; 32],
    generation: i64,
    now: i64,
) -> Result<u64, StorageError> {
    let held: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM message_index i
             WHERE i.signer = ?1 AND i.generation = ?2 AND i.placed_at IS NULL
               AND ?3 < {expires} AND {live}",
            expires = expires_sql(),
            live = live_sql(),
        ),
        params![&of[..], generation, now],
        |row| row.get(0),
    )?;
    Ok(from_sql(held))
}

/// What the hourly task dropped ([`drop_gone`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Gone {
    /// Index rows whose 30 days were up.
    pub expired: usize,
    /// Index rows that were held at no live number.
    pub not_live: usize,
}

/// The first part of the hourly task (decision 2026-10-09 §7.1), at `now`:
/// each index row whose 30 days are up, and each held at no live number,
/// is overwritten and dropped ([`drop_row`]), whatever the device's state;
/// the rows of first holding of numbers that are not live go, and the
/// times of places from before the hour. In the caller's write.
pub fn drop_gone(conn: &Connection, now: i64) -> Result<Gone, StorageError> {
    let ids = |condition: String| -> Result<Vec<Vec<u8>>, StorageError> {
        Ok(conn
            .prepare(&format!(
                "SELECT i.id FROM message_index i WHERE {condition}"
            ))?
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?)
    };
    let mut gone = Gone::default();
    for id in ids(format!("{now} >= {}", expires_sql()))? {
        gone.expired += usize::from(drop_row(conn, &id)?);
    }
    for id in ids(format!("NOT {}", live_sql()))? {
        gone.not_live += usize::from(drop_row(conn, &id)?);
    }
    conn.execute(
        &format!(
            "DELETE FROM message_first_held AS f WHERE f.number <= COALESCE(
                 (SELECT s.highest FROM message_signers s
                  WHERE s.signer = f.signer AND s.generation = f.generation), 0) - {RING}"
        ),
        [],
    )?;
    conn.execute(
        "DELETE FROM message_places WHERE placed_at <= ?1",
        [now - HOUR_SECS],
    )?;
    Ok(gone)
}

/// A count or a number as the store's integer holds it. Every number of
/// a message is at most 2^42 - 1, and a count of entries far less.
fn to_sql(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn from_sql(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

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
    use cordelia_core::protocol::{AGENT_MESSAGE_NUMBER_MAX, AGENT_MESSAGE_VALUE_BYTES};

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
            assert_eq!(drop_row(&conn, &[1; 16]).ok(), Some(true), "{begin}");
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
        assert_eq!(drop_row(&conn, &[1; 16]).ok(), Some(true));
        conn.execute_batch("COMMIT").unwrap();
        assert_eq!(body(&conn), None);
        assert_eq!(count(&conn, "message_numbers"), 0);
    }

    /// The message saying `body`, sent at `sent`, from `~` to every name.
    fn message(body: &str, sent: i64) -> Message {
        Message {
            asks: false,
            sent: u64::try_from(sent).unwrap(),
            nonce: [0; 16],
            thread: [0; 16],
            answers: [0; 16],
            from: "~".into(),
            to: To::All,
            link: None,
            body: body.into(),
        }
    }

    /// Hold message `number` of `signer` in generation 1, saying `body`,
    /// first held and sent at `at`, as a reader takes it. Its ID is its
    /// body's first byte and its number.
    fn taken(conn: &Connection, signer: u8, number: u64, body: &str, at: i64) -> Indexed {
        generation_1(conn);
        assert!(hold_number(conn, &[signer; 32], 1, number).unwrap());
        let message = message(body, at);
        let mut id = [signer; 16];
        id[0] = body.as_bytes()[0];
        id[1] = u8::try_from(number % 256).unwrap();
        index(
            conn,
            &Opened {
                id: &id,
                signer: &[signer; 32],
                label: "laptop",
                generation: 1,
                number,
                message: &message,
                first_held: at,
                placed_at: None,
            },
        )
        .unwrap()
    }

    /// A number that leaves the live numbers is counted as overwritten
    /// where its message had no place, or was never held, and not where
    /// it had a place or was held and went (decision 2026-10-09 §2.5):
    /// with 1 shown, 2 not shown, 3 cleared and 4 never held, H at 68
    /// counts 2 and 4, and every row of those numbers goes.
    #[test]
    fn a_number_that_leaves_the_live_numbers_is_counted_unless_its_message_had_a_place_or_went() {
        let conn = db::open_in_memory().unwrap();
        for (number, body) in [(1, "one"), (2, "two"), (3, "three")] {
            assert_eq!(taken(&conn, 7, number, body, 100), Indexed::New);
        }
        conn.execute(
            "UPDATE message_index SET placed_at = 100 WHERE body = 'one'",
            [],
        )
        .unwrap();
        assert!(clear(&conn, &[7; 32], 1, 3).unwrap());
        assert!(hold_number(&conn, &[7; 32], 1, 5).unwrap());
        assert_eq!(signer(&conn, &[7; 32], 1).unwrap().unwrap().overwritten, 0);

        assert!(hold_number(&conn, &[7; 32], 1, 68).unwrap());
        assert_eq!(
            signer(&conn, &[7; 32], 1).unwrap(),
            Some(Signer {
                highest: 68,
                overwritten: 2,
                not_messages: 0,
                counted_from: Some(1),
            })
        );
        assert_eq!(count(&conn, "message_index"), 0);
        assert_eq!(count(&conn, "message_numbers"), 0);
        assert_eq!(count(&conn, "message_first_held"), 0);
        // 5 is live still, and 4 is not: taken now, 4 is not opened and
        // not counted again, being above the number counted from.
        assert!(hold_number(&conn, &[7; 32], 1, 5).unwrap());
        assert!(!hold_number(&conn, &[7; 32], 1, 4).unwrap());
        assert_eq!(signer(&conn, &[7; 32], 1).unwrap().unwrap().overwritten, 2);
    }

    /// The device's own messages are given places with no time in the
    /// hour, and take none of another signer's 64 (decision 2026-10-09
    /// §2.3, §6): with 64 of another signer's and two of its own waiting,
    /// all are placed, and the hour holds 64 times.
    #[test]
    fn the_devices_own_messages_take_no_place_from_the_hour() {
        let conn = db::open_in_memory().unwrap();
        for number in 1..=64 {
            taken(&conn, 7, number, "a", 100);
        }
        for number in 1..=2 {
            taken(&conn, 9, number, "o", 100);
        }
        assert_eq!(give_places(&conn, &[9; 32], 100).unwrap(), 66);
        assert_eq!(count(&conn, "message_places"), 64);
        let own: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM message_places WHERE signer = ?1",
                [&[9u8; 32][..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(own, 0);
        assert_eq!(shown(&conn, 100).unwrap().len(), 66);
    }

    /// Places are given newest first, by number, while the hour has room
    /// (decision 2026-10-09 §6): with 60 of a signer's 64 places given,
    /// and 61 to 70 waiting, 67 to 70 are placed and 61 to 66 wait.
    #[test]
    fn places_are_given_newest_first_while_the_hour_has_room() {
        let conn = db::open_in_memory().unwrap();
        for number in 1..=60 {
            taken(&conn, 7, number, "a", 100);
        }
        assert_eq!(give_places(&conn, &[0; 32], 100).unwrap(), 60);
        for number in 61..=70 {
            taken(&conn, 7, number, "b", 100);
        }
        assert_eq!(give_places(&conn, &[0; 32], 110).unwrap(), 4);
        let placed: Vec<i64> = conn
            .prepare(
                "SELECT n.number FROM message_numbers n JOIN message_index i ON i.id = n.id
                 WHERE i.placed_at = 110 ORDER BY n.number",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(placed, [67, 68, 69, 70]);
        assert_eq!(held_back(&conn, &[7; 32], 1, 110).unwrap(), 6);
    }

    /// The first part of the hourly task drops what has expired and what
    /// is held at no live number, overwritten first, and the rows of
    /// first holding that are not live and the times of places from
    /// before the hour (decision 2026-10-09 §7.1). What is live and
    /// within its 30 days stays, and so does the row of first holding of
    /// a live number whose message went.
    #[test]
    fn the_hourly_drop_takes_what_expired_what_is_not_live_and_the_old_places() {
        let conn = db::open_in_memory().unwrap();
        let day = 24 * 60 * 60;
        taken(&conn, 7, 2, "dead", 100 + day);
        taken(&conn, 7, 3, "new", 100 + day);
        taken(&conn, 7, 4, "old", 100);
        give_places(&conn, &[0; 32], 100 + day).unwrap();
        assert_eq!(count(&conn, "message_places"), 3);
        // H stands where 2 is no longer live, as a store can hold it.
        conn.execute_batch("UPDATE message_signers SET highest = 66")
            .unwrap();

        let now = 100 + 30 * day;
        assert_eq!(
            drop_gone(&conn, now - 1).unwrap(),
            Gone {
                expired: 0,
                not_live: 1
            }
        );
        assert_eq!(
            drop_gone(&conn, now).unwrap(),
            Gone {
                expired: 1,
                not_live: 0
            }
        );
        let bodies: Vec<String> = conn
            .prepare("SELECT body FROM message_index ORDER BY body")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(bodies, ["new"]);
        let left: Vec<i64> = conn
            .prepare("SELECT number FROM message_first_held ORDER BY number")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(left, [3, 4]);
        assert_eq!(count(&conn, "message_places"), 0);
    }

    /// A drop refused part-way, by a delete that fails after the fields
    /// were written over, takes back the overwrite (decision 2026-10-09
    /// §7.1): with no transaction open the row's text is as it was, and
    /// inside a caller's transaction it is as it was too, and the caller's
    /// transaction is still open and still writes and commits.
    #[test]
    fn a_drop_refused_part_way_leaves_the_row_and_the_callers_write() {
        let conn = db::open_in_memory().unwrap();
        indexed(&conn, 1, 1);
        conn.execute_batch(
            "CREATE TEMP TRIGGER refused BEFORE DELETE ON main.message_index
             BEGIN SELECT RAISE(ABORT, 'the delete is refused'); END;",
        )
        .unwrap();
        let text = |conn: &Connection| -> [Vec<u8>; 5] {
            conn.query_row(
                "SELECT CAST(body AS BLOB), CAST(link AS BLOB), CAST(subject AS BLOB),
                        CAST(from_name AS BLOB), CAST(to_name AS BLOB)
                 FROM message_index WHERE id = ?1",
                [&[1u8; 16][..]],
                |row| {
                    Ok([
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ])
                },
            )
            .unwrap()
        };
        let as_written = [BODY, LINK, SUBJECT, FROM, TO].map(|text| text.as_bytes().to_vec());

        assert!(drop_row(&conn, &[1; 16]).is_err());
        assert!(conn.is_autocommit(), "nothing is left open");
        assert_eq!(text(&conn), as_written);

        conn.execute_batch("BEGIN").unwrap();
        conn.execute("UPDATE message_index SET placed_at = 7", [])
            .unwrap();
        assert!(drop_row(&conn, &[1; 16]).is_err());
        assert!(!conn.is_autocommit(), "the caller's write is open");
        assert_eq!(text(&conn), as_written);
        conn.execute("UPDATE message_index SET asks = 0", [])
            .unwrap();
        conn.execute_batch("COMMIT").unwrap();
        let after: (i64, i64) = conn
            .query_row("SELECT placed_at, asks FROM message_index", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(after, (7, 0));
        assert_eq!(text(&conn), as_written);
        assert_eq!(count(&conn, "message_index"), 1);
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
        let at = |number: u64| -> Vec<String> {
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
                     VALUES (X'{}', 1, {number}, {number})",
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
