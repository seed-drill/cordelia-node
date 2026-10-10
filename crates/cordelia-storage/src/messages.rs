//! What a device keeps of messages between the person's own agents
//! (decision 2026-10-09 §2.3, §2.5, §6, §7): the tables of schema step 19.
//!
//! The index of opened messages (`message_index`) holds each message's
//! body, link, subject and names in the clear, as it was opened. **A row
//! that goes is overwritten first** (§7.1): its body, link, subject,
//! `from_name` and `to_name` are written over with zeros of the same
//! length, and then the row is deleted, in one transaction, its marks
//! staying as bare hashes. On a personal node `secure_delete` is on as well
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
//!
//! ## Marks read by an agent
//!
//! The device keeps its own table of what its agents read
//! (`message_read_here`, [`mark_read`]), each mark with the message's ID
//! and the name, or as a bare hash where it was merged from the device's
//! own list and no message was found for it ([`merge_own_list`]), or
//! where its message's row went ([`drop_row`]); and the latest list of
//! each other device ([`keep_list`]). Neither is matched
//! to a message when it is taken: whether a message is read is worked out
//! when it is shown ([`read_by`], decision 2026-10-09 §7.2).

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::protocol::{
    AGENT_MESSAGE_AHEAD_MAX_SECS, AGENT_MESSAGE_ID_BYTES, AGENT_MESSAGE_KEPT_DAYS,
    AGENT_MESSAGE_READ_MARK_BYTES, AGENT_MESSAGE_READ_MARKS_MAX, AGENT_MESSAGE_RING,
    AGENT_MESSAGE_SUBJECT_CHARS,
};
use cordelia_crypto::message::{Message, To, read_mark};

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

/// The generation of the messages channel whose ID is `channel`, where
/// the device has held it.
pub fn generation_of(conn: &Connection, channel: &[u8; 32]) -> Result<Option<i64>, StorageError> {
    Ok(conn
        .query_row(
            "SELECT id FROM message_generations WHERE channel = ?1",
            [&channel[..]],
            |row| row.get(0),
        )
        .optional()?)
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
/// slot of that number in the signer's ring (decision 2026-10-09 §2.5),
/// a clearing where `clearing` (its revision is odd). The caller has
/// checked the slot before opening anything: nothing but such an entry
/// is given here. Returns whether `number` is live, after it is held:
/// only then is the entry opened.
///
/// - **Above H, it raises H.** Every number that was live and is no
///   longer leaves the reader's rows: its row of numbers held, its row of
///   first holding, and the index row of its message where none of that
///   message's numbers is left (overwritten first, [`drop_row`], at `now`). Each of
///   them from the number counted from is counted as overwritten, unless
///   its message had a place, or was held and has gone (it expired, or
///   was cleared), or its clearing was held ([`clear`]): those it never
///   held, and those it held and had not shown.
/// - **At a live number,** it changes nothing but the number counted
///   from, where it is below it.
/// - **At a number that is not live,** a message is counted as
///   overwritten, where it is below the number counted from: a number
///   at or above it was counted, or not, as it left. A clearing is not:
///   its number is gone, and a message of that number that the store
///   held before it was counted when it was taken, so a number is
///   counted once, however many of its entries are handed.
pub fn hold_number(
    conn: &Connection,
    of: &[u8; 32],
    generation: i64,
    number: u64,
    clearing: bool,
    now: i64,
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
            leave_up_to(conn, of, generation, left, now)?;
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
        if !clearing && kept.counted_from.is_none_or(|from| number < from) {
            kept.overwritten += 1;
        }
        false
    };
    keep_signer(conn, of, generation, &kept)?;
    Ok(live)
}

/// How many of the numbers from `lowest` to `highest` of `of` left the
/// live numbers before their message had a place: all of them but those
/// held at a message that has a place, or that was held and has gone,
/// and those held as a clearing (a row of first holding with no ID).
fn left_unshown(
    conn: &Connection,
    of: &[u8; 32],
    generation: i64,
    lowest: i64,
    highest: i64,
) -> Result<i64, StorageError> {
    let shown_or_gone: i64 = conn.query_row(
        "SELECT COUNT(*) FROM message_first_held f
         LEFT JOIN message_index i ON i.id = f.id AND i.generation = f.generation
         WHERE f.signer = ?1 AND f.generation = ?2 AND f.number BETWEEN ?3 AND ?4
           AND (i.id IS NULL OR i.placed_at IS NOT NULL)",
        params![&of[..], generation, lowest, highest],
        |row| row.get(0),
    )?;
    Ok(highest - lowest + 1 - shown_or_gone)
}

/// Drop the rows of each number of `of` at or below `highest`, which are
/// live no longer: its rows of numbers held and of first holding, and
/// the index row of a message that is then held at no number, at `now`.
fn leave_up_to(
    conn: &Connection,
    of: &[u8; 32],
    generation: i64,
    highest: i64,
    now: i64,
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
            drop_row(conn, &id, now)?;
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
    /// at its 30 days or at a clearing (§7.1, D11), or holds it in
    /// another generation.
    NotAgain,
}

/// Write a message into the index (decision 2026-10-09 §7.1), in the
/// caller's write: its row of first holding at its number, its index row
/// with every field it was opened to, and its row of numbers held. The
/// caller has held its number with [`hold_number`], and it is live.
///
/// A number whose row of first holding is there was held before: what is
/// taken again there is not shown again. A message held at another live
/// number is one row, with a row of numbers held for each. A message is
/// looked up by its ID and its generation: one held in another
/// generation is not shown again here, and is not held at this number.
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
    // A message is of its generation: the same ID in a generation the
    // device held before is that generation's message, which is not
    // shown again and takes nothing of this generation's.
    let held_in: Option<i64> = conn
        .query_row(
            "SELECT generation FROM message_index WHERE id = ?1",
            [&id[..]],
            |row| row.get(0),
        )
        .optional()?;
    let indexed = match (held_in, first_held_before) {
        (None, 0) => {
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
        (Some(held_in), _) if held_in == generation => Indexed::AnotherNumber,
        _ => return Ok(Indexed::NotAgain),
    };
    conn.execute(
        "INSERT INTO message_numbers (signer, generation, number, id) VALUES (?1, ?2, ?3, ?4)",
        params![&signer[..], generation, number, &id[..]],
    )?;
    Ok(indexed)
}

/// A reader takes the entry that clears message `number` of `of` in
/// `generation`, a live number, at `now` (decision 2026-10-09 §2.3, §2.5,
/// D11): it drops the index row of the message it holds at that number,
/// whichever other numbers that row was held at, in the caller's write.
/// Its rows of first holding stay, so that it is not shown again. Where
/// the number has no row of first holding, as where the reader came
/// after its sender cleared it, it is given one with no ID: the number is
/// gone, never counted as overwritten, and a message taken there after
/// is not shown. Returns whether a row went.
pub fn clear(
    conn: &Connection,
    of: &[u8; 32],
    generation: i64,
    number: u64,
    now: i64,
) -> Result<bool, StorageError> {
    conn.execute(
        "INSERT INTO message_first_held (signer, generation, number, id, sent, first_held)
         VALUES (?1, ?2, ?3, NULL, NULL, ?4)
         ON CONFLICT(signer, generation, number) DO NOTHING",
        params![&of[..], generation, to_sql(number), now],
    )?;
    let id: Option<Vec<u8>> = conn
        .query_row(
            "SELECT id FROM message_numbers WHERE signer = ?1 AND generation = ?2 AND number = ?3",
            params![&of[..], generation, to_sql(number)],
            |row| row.get(0),
        )
        .optional()?;
    match id {
        Some(id) => drop_row(conn, &id, now),
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
/// times of places from before the hour, and the device's record of when
/// it sent from before the hour (§6).
///
/// Then what is kept of each generation the device has left (decision
/// 2026-10-09 §9.1), by `applied`, the messages channel it stands applied
/// under:
///
/// - **Its kept values,** where the device stands applied: they may not
///   have reached every relay, and go with their generation.
/// - **Then each such generation** that holds no index row and no kept
///   value any more goes whole: its rows of first holding, its signers'
///   rows, its places and then its own row, since no entry of it is taken
///   again. So one run leaves nothing of a generation whose messages have
///   all gone.
/// - **Where the device stands applied under none,** the most recent
///   generation stays, with its counts and its rows of first holding: it
///   is the one the device last stood under, and may stand under again.
/// - **Where which one is not known,** no generation goes, and no kept
///   value: only what has expired, or is not live, goes.
///
/// In the caller's write.
pub fn drop_gone(conn: &Connection, now: i64, applied: &Applied) -> Result<Gone, StorageError> {
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
        gone.expired += usize::from(drop_row(conn, &id, now)?);
    }
    for id in ids(format!("NOT {}", live_sql()))? {
        gone.not_live += usize::from(drop_row(conn, &id, now)?);
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
    // The device's record of when it sent is kept for the hour of its
    // rates, and no longer (§6).
    conn.execute(
        "DELETE FROM message_sends WHERE sent_at <= ?1",
        [now - HOUR_SECS],
    )?;
    let applied = match applied {
        Applied::NotKnown => return Ok(gone),
        Applied::Nowhere => None,
        Applied::Under(channel) => {
            let generation = generation_of(conn, channel)?;
            for kept in kept(conn)? {
                if Some(kept.generation) != generation {
                    drop_kept(conn, &kept.id, false)?;
                }
            }
            Some(channel)
        }
    };
    let left: Vec<i64> = conn
        .prepare(
            "SELECT g.id FROM message_generations g
             WHERE g.channel IS NOT ?1
               AND (?1 IS NOT NULL OR g.id < (SELECT MAX(id) FROM message_generations))
               AND NOT EXISTS (SELECT 1 FROM message_index i WHERE i.generation = g.id)
               AND NOT EXISTS (SELECT 1 FROM message_kept k WHERE k.generation = g.id)",
        )?
        .query_map([applied.map(|channel| &channel[..])], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    for generation in left {
        for table in ["message_first_held", "message_signers", "message_places"] {
            conn.execute(
                &format!("DELETE FROM {table} WHERE generation = ?1"),
                [generation],
            )?;
        }
        conn.execute(
            "DELETE FROM message_generations WHERE id = ?1",
            [generation],
        )?;
    }
    Ok(gone)
}

// ── The sender's own ─────────────────────────────────────────────────

/// The device writes in its record that it sent at `at` by its clock
/// (decision 2026-10-09 §6, C10): as the agent of the folder `name`, to
/// one name or to every name; or, with no name, a message sent again.
pub fn record_send(
    conn: &Connection,
    at: i64,
    name: Option<&str>,
    to_all: bool,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO message_sends (sent_at, name, to_all) VALUES (?1, ?2, ?3)",
        params![at, name, to_all],
    )?;
    Ok(())
}

/// What the device's record says it sent in the hour before `now`, each
/// as the time it sent, oldest first (decision 2026-10-09 §6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SentLately {
    /// The sends of one folder's agent.
    pub by_folder: Vec<i64>,
    /// Every send of the device's, a message to every name as one.
    pub sends: Vec<i64>,
    /// Every message sent again.
    pub again: Vec<i64>,
}

/// What the device's record says it sent in the last hour of its clock,
/// at `now`, of the folder's agent `folder` and of the device: every row
/// within the hour, **or later than its clock**, so that a clock that went
/// back does not free the hour (decision 2026-10-09 §6, C10).
pub fn sent_lately(conn: &Connection, folder: &str, now: i64) -> Result<SentLately, StorageError> {
    let rows: Vec<(i64, Option<String>)> = conn
        .prepare("SELECT sent_at, name FROM message_sends WHERE sent_at > ?1 ORDER BY sent_at")?
        .query_map([now - HOUR_SECS], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let mut lately = SentLately::default();
    for (at, name) in rows {
        match name {
            Some(name) => {
                if name == folder {
                    lately.by_folder.push(at);
                }
                lately.sends.push(at);
            }
            None => lately.again.push(at),
        }
    }
    Ok(lately)
}

/// The newest `sent` of the device's own messages in its index that is
/// not more than `AGENT_MESSAGE_AHEAD_MAX_SECS` ahead of `now` (decision
/// 2026-10-09 §7.1, D8): a row of its own further ahead is passed over,
/// so that a clock that was ahead for a moment does not lock it out.
pub fn newest_own_sent(
    conn: &Connection,
    own: &[u8; 32],
    now: i64,
) -> Result<Option<i64>, StorageError> {
    let ahead = i64::try_from(AGENT_MESSAGE_AHEAD_MAX_SECS).unwrap_or(i64::MAX);
    Ok(conn.query_row(
        "SELECT MAX(sent) FROM message_index WHERE signer = ?1 AND sent <= ?2",
        params![&own[..], now.saturating_add(ahead)],
        |row| row.get(0),
    )?)
}

/// The other side of a pair of agents: a name, or every name.
pub type Other = Option<String>;

/// For each pair with the agent of `name` on one side, how many of its
/// messages count towards the hold at `now` (decision 2026-10-09 §6, C8,
/// F2): those the device holds, that have a place, that have not expired,
/// that are live, and that no person has read on this device. A message
/// to one name is of the pair of its sender and its recipient, in either
/// direction; a message to every name is of the pair of its sender and
/// all (`None`). In order of the other name, and all last.
pub fn pairs_with(
    conn: &Connection,
    name: &str,
    now: i64,
) -> Result<Vec<(Other, u64)>, StorageError> {
    let rows: Vec<(String, Option<String>)> = conn
        .prepare(&format!(
            "SELECT i.from_name, i.to_name FROM message_index i
             WHERE i.placed_at IS NOT NULL AND ?1 < {expires} AND {live}
               AND NOT EXISTS (SELECT 1 FROM message_read_by_a_person p WHERE p.id = i.id)
               AND (i.from_name = ?2 OR i.to_name = ?2)",
            expires = expires_sql(),
            live = live_sql(),
        ))?
        .query_map(params![now, name], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let mut pairs: std::collections::BTreeMap<(bool, String), u64> = Default::default();
    for (from, to) in rows {
        let other = match to {
            // To every name: only the sender's side is this agent's.
            None if from == name => (true, String::new()),
            None => continue,
            Some(to) if from == name => (false, to),
            Some(_) => (false, from),
        };
        *pairs.entry(other).or_default() += 1;
    }
    Ok(pairs
        .into_iter()
        .map(|((all, other), count)| (if all { None } else { Some(other) }, count))
        .collect())
}

/// A message of the device's own, kept apart until every relay the device
/// is set up with has taken it (decision 2026-10-09 §2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    pub id: Id,
    pub generation: i64,
    /// Its value as it was sent.
    pub value: Vec<u8>,
    pub sent: i64,
    /// The numbers it was sent under, lowest first.
    pub numbers: Vec<u64>,
    /// Whether it waits to be sent again under the next number.
    pub again: bool,
}

/// Keep the value of the device's own message `id`, sent under `number`
/// in `generation`, in the caller's write (decision 2026-10-09 §2.3).
/// Where a 65th would be kept, the oldest goes, and its index row says
/// that it may not have reached every relay: returns its ID.
pub fn keep(conn: &Connection, kept: &Kept, now: i64) -> Result<Option<Id>, StorageError> {
    conn.execute(
        "INSERT INTO message_kept (id, generation, value, sent, kept_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![&kept.id[..], kept.generation, kept.value, kept.sent, now],
    )?;
    for number in &kept.numbers {
        kept_under(conn, &kept.id, *number)?;
    }
    let held: i64 = conn.query_row("SELECT COUNT(*) FROM message_kept", [], |row| row.get(0))?;
    if held <= RING {
        return Ok(None);
    }
    let oldest: Vec<u8> = conn.query_row(
        "SELECT id FROM message_kept ORDER BY kept_at, rowid LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    drop_kept(conn, &oldest, false)?;
    Ok(Some(id_of(&oldest)))
}

/// The kept message `id` was sent again under `number`: it waits no more.
pub fn kept_under(conn: &Connection, id: &Id, number: u64) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR IGNORE INTO message_kept_numbers (id, number) VALUES (?1, ?2)",
        params![&id[..], to_sql(number)],
    )?;
    conn.execute("UPDATE message_kept SET again = 0 WHERE id = ?1", [&id[..]])?;
    Ok(())
}

/// The kept message that was sent under `number` in `generation`.
pub fn kept_at(
    conn: &Connection,
    generation: i64,
    number: u64,
) -> Result<Option<Id>, StorageError> {
    let id: Option<Vec<u8>> = conn
        .query_row(
            "SELECT k.id FROM message_kept k JOIN message_kept_numbers n ON n.id = k.id
             WHERE k.generation = ?1 AND n.number = ?2",
            params![generation, to_sql(number)],
            |row| row.get(0),
        )
        .optional()?;
    Ok(id.map(|id| id_of(&id)))
}

/// The relay `relay` has taken the kept message `id`: it answered a push
/// of it that it stored it, or holds it (decision 2026-10-09 §2.3).
pub fn taken_by(conn: &Connection, id: &Id, relay: &[u8; 32]) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR IGNORE INTO message_kept_taken (id, relay) VALUES (?1, ?2)",
        params![&id[..], &relay[..]],
    )?;
    Ok(())
}

/// The kept message `id` waits to be sent again under the next number.
pub fn send_again(conn: &Connection, id: &Id) -> Result<(), StorageError> {
    conn.execute("UPDATE message_kept SET again = 1 WHERE id = ?1", [&id[..]])?;
    Ok(())
}

/// Every message the device keeps, oldest first.
pub fn kept(conn: &Connection) -> Result<Vec<Kept>, StorageError> {
    let mut all: Vec<Kept> = conn
        .prepare(
            "SELECT id, generation, value, sent, again FROM message_kept ORDER BY kept_at, rowid",
        )?
        .query_map([], |row| {
            Ok(Kept {
                id: id_of(&row.get::<_, Vec<u8>>(0)?),
                generation: row.get(1)?,
                value: row.get(2)?,
                sent: row.get(3)?,
                numbers: Vec::new(),
                again: row.get(4)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    for kept in &mut all {
        let numbers: Vec<i64> = conn
            .prepare("SELECT number FROM message_kept_numbers WHERE id = ?1 ORDER BY number")?
            .query_map([&kept.id[..]], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        kept.numbers = numbers.into_iter().map(from_sql).collect();
    }
    Ok(all)
}

/// The relays that have taken the kept message `id`.
pub fn taken_at(conn: &Connection, id: &Id) -> Result<Vec<[u8; 32]>, StorageError> {
    let relays: Vec<Vec<u8>> = conn
        .prepare("SELECT relay FROM message_kept_taken WHERE id = ?1 ORDER BY relay")?
        .query_map([&id[..]], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(relays
        .into_iter()
        .filter_map(|relay| relay.try_into().ok())
        .collect())
}

/// Drop the kept message `id` (decision 2026-10-09 §2.3). Where not every
/// relay took it, its index row says that it may not have reached every
/// relay. Returns whether the device kept it.
pub fn drop_kept(
    conn: &Connection,
    id: &[u8],
    taken_everywhere: bool,
) -> Result<bool, StorageError> {
    if !taken_everywhere {
        conn.execute(
            "UPDATE message_index SET not_every_relay = 1 WHERE id = ?1",
            [id],
        )?;
    }
    Ok(conn.execute("DELETE FROM message_kept WHERE id = ?1", [id])? == 1)
}

/// Drop each kept message that every one of `relays` has taken: the
/// relays the device is set up with (decision 2026-10-09 §2.3). With no
/// relay, what the device sends stays in its own store, and nothing is
/// kept for a relay. Returns how many went.
pub fn drop_taken_by_every(conn: &Connection, relays: &[[u8; 32]]) -> Result<usize, StorageError> {
    let mut dropped = 0;
    for kept in kept(conn)? {
        let taken = taken_at(conn, &kept.id)?;
        if relays.iter().all(|relay| taken.contains(relay)) {
            dropped += usize::from(drop_kept(conn, &kept.id, true)?);
        }
    }
    Ok(dropped)
}

/// Drop each kept message that is not of `generation`, or whose `sent` is
/// 30 days or more before `now` (decision 2026-10-09 §2.3, §9.1): it may
/// not have reached every relay. Returns how many went.
pub fn drop_kept_gone(conn: &Connection, generation: i64, now: i64) -> Result<usize, StorageError> {
    let mut dropped = 0;
    for kept in kept(conn)? {
        if kept.generation != generation || has_expired(kept.sent, kept.sent, now) {
            dropped += usize::from(drop_kept(conn, &kept.id, false)?);
        }
    }
    Ok(dropped)
}

fn id_of(bytes: &[u8]) -> Id {
    let mut id = [0; AGENT_MESSAGE_ID_BYTES];
    let len = bytes.len().min(id.len());
    id[..len].copy_from_slice(&bytes[..len]);
    id
}

// ── Marks ────────────────────────────────────────────────────────────

/// The mark that a message was read by the agent of a name (decision
/// 2026-10-09 §2.2): [`read_mark`] of its ID and the name.
pub type Mark = [u8; AGENT_MESSAGE_READ_MARK_BYTES];

/// The agent of `name` read message `id` on this device, at `now`
/// (decision 2026-10-09 §7.2): its mark is kept in the device's own table,
/// with the ID and the name, as the newest there, in the caller's write.
/// A mark the table kept as a bare hash is given its ID and its name, and
/// one it kept already is made the newest. The message is in the index;
/// when its row goes, the mark stays as a bare hash ([`drop_row`]).
/// Returns whether the table lacked the mark.
pub fn mark_read(conn: &Connection, id: &Id, name: &str, now: i64) -> Result<bool, StorageError> {
    let mark = read_mark(id, name);
    let held: i64 = conn.query_row(
        "SELECT COUNT(*) FROM message_read_here WHERE mark = ?1",
        [&mark[..]],
        |row| row.get(0),
    )?;
    conn.execute(
        "INSERT INTO message_read_here (mark, seq, id, name, made_at)
         VALUES (?1, (SELECT COALESCE(MAX(seq), 0) + 1 FROM message_read_here), ?2, ?3, ?4)
         ON CONFLICT(mark) DO UPDATE SET
             seq = excluded.seq, id = excluded.id, name = excluded.name,
             made_at = excluded.made_at, merged_at = NULL",
        params![&mark[..], &id[..], name, now],
    )?;
    Ok(held == 0)
}

/// The marks that the device's list holds (decision 2026-10-09 §2.4,
/// §7.2, §9.1): the newest of its own table, as many as a list holds
/// (120), newest first, whatever became of their messages, the marks it
/// keeps as a bare hash among them. Whether a message is shown is each
/// device's own (its place, its first holding, its clock), so a list
/// leaves out no mark for what this device no longer shows.
pub fn marks_to_list(conn: &Connection) -> Result<Vec<Mark>, StorageError> {
    let marks: Vec<Vec<u8>> = conn
        .prepare(&format!(
            "SELECT r.mark FROM message_read_here r
             ORDER BY r.seq DESC
             LIMIT {AGENT_MESSAGE_READ_MARKS_MAX}"
        ))?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(marks.iter().map(|mark| mark_of(mark)).collect())
}

/// The ID and the name of each mark that the device can make of what it
/// holds (decision 2026-10-09 §7.2, F8): the mark of each message in its
/// index with each of `names`, and with the name it is to.
fn marks_held(
    conn: &Connection,
    names: &[String],
) -> Result<std::collections::HashMap<Mark, (Id, String)>, StorageError> {
    let rows: Vec<(Vec<u8>, Option<String>)> = conn
        .prepare("SELECT id, to_name FROM message_index")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let mut held = std::collections::HashMap::new();
    for (id, to) in rows {
        let id = id_of(&id);
        for name in names.iter().chain(to.as_ref()) {
            held.insert(read_mark(&id, name), (id, name.clone()));
        }
    }
    Ok(held)
}

/// The device took its own list from a relay, and the store kept it
/// (decision 2026-10-09 §2.4, §7.2, D7, F8): each of its `marks` that the
/// table lacks is merged into the table as older than any it holds, in
/// the list's order, in the caller's write. Each is given the ID and the
/// name of a message it holds, found by making the mark of each message
/// with each of `names`, the names mapped here, and with the name it is
/// to; one that matches none is kept as a bare hash, merged at `now`. At
/// most 120 bare hashes are kept, and the oldest goes first. Returns how
/// many were merged.
pub fn merge_own_list(
    conn: &Connection,
    marks: &[Mark],
    names: &[String],
    now: i64,
) -> Result<usize, StorageError> {
    let held = marks_held(conn, names)?;
    let lowest: Option<i64> =
        conn.query_row("SELECT MIN(seq) FROM message_read_here", [], |row| {
            row.get(0)
        })?;
    let mut seq = lowest.map_or(0, |lowest| lowest - 1);
    let mut merged = 0;
    for mark in marks {
        let inserted = match held.get(mark) {
            Some((id, name)) => conn.execute(
                "INSERT OR IGNORE INTO message_read_here (mark, seq, id, name, made_at, merged_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                params![&mark[..], seq, &id[..], name, now],
            )?,
            None => conn.execute(
                "INSERT OR IGNORE INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (?1, ?2, ?3, ?3)",
                params![&mark[..], seq, now],
            )?,
        };
        if inserted == 1 {
            seq -= 1;
            merged += 1;
        }
    }
    keep_120_bare(conn)?;
    Ok(merged)
}

/// Keep at most 120 marks as a bare hash (`AGENT_MESSAGE_READ_MARKS_MAX`,
/// decision 2026-10-09 §7.2), the oldest going first, whether each was
/// merged or became bare when its message's row went.
fn keep_120_bare(conn: &Connection) -> Result<(), StorageError> {
    conn.execute(
        &format!(
            "DELETE FROM message_read_here WHERE id IS NULL AND seq <
                 (SELECT seq FROM message_read_here WHERE id IS NULL
                  ORDER BY seq DESC LIMIT 1 OFFSET {})",
            AGENT_MESSAGE_READ_MARKS_MAX - 1
        ),
        [],
    )?;
    Ok(())
}

/// The part of the hourly task that is the marks' (decision 2026-10-09
/// §7.2), at `now`, in the caller's write: each mark kept as a bare hash
/// for which the device now holds a message is given its ID and its name,
/// made with each of `names` and the name the message is to; and each
/// still bare 30 days after it became bare, merged or left by its
/// message's row, goes. Returns how many went.
pub fn keep_bare_marks(
    conn: &Connection,
    names: &[String],
    now: i64,
) -> Result<usize, StorageError> {
    let held = marks_held(conn, names)?;
    let bare: Vec<Vec<u8>> = conn
        .prepare("SELECT mark FROM message_read_here WHERE id IS NULL")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    for mark in bare {
        if let Some((id, name)) = held.get(&mark_of(&mark)) {
            conn.execute(
                "UPDATE message_read_here SET id = ?2, name = ?3 WHERE mark = ?1",
                params![mark, &id[..], name],
            )?;
        }
    }
    Ok(conn.execute(
        "DELETE FROM message_read_here WHERE id IS NULL AND merged_at <= ?1",
        [now - i64::from(AGENT_MESSAGE_KEPT_DAYS) * DAY_SECS],
    )?)
}

/// The store kept a newer list of the device `key`, another than this one
/// (decision 2026-10-09 §7.2): its marks, each once, are kept in place of
/// what was kept of that key, in the caller's write.
pub fn keep_list(conn: &Connection, key: &[u8; 32], marks: &[Mark]) -> Result<(), StorageError> {
    conn.execute("DELETE FROM message_lists WHERE key = ?1", [&key[..]])?;
    for mark in marks {
        conn.execute(
            "INSERT OR IGNORE INTO message_lists (key, mark) VALUES (?1, ?2)",
            params![&key[..], &mark[..]],
        )?;
    }
    Ok(())
}

/// Drop the list of each key that is not among `counting`, the keys that
/// count (decision 2026-10-09 §7.2). Returns how many lists went.
pub fn drop_lists_but(conn: &Connection, counting: &[[u8; 32]]) -> Result<usize, StorageError> {
    let keys: Vec<Vec<u8>> = conn
        .prepare("SELECT DISTINCT key FROM message_lists")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    let mut dropped = 0;
    for key in keys {
        if !counting.iter().any(|counts| counts[..] == key[..]) {
            conn.execute("DELETE FROM message_lists WHERE key = ?1", [&key])?;
            dropped += 1;
        }
    }
    Ok(dropped)
}

/// Where it is said that message `id` was read by an agent of `name`
/// (decision 2026-10-09 §7.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadBy {
    /// The device's own table holds its mark, with its ID and name or as
    /// a bare hash.
    pub here: bool,
    /// The keys whose latest list holds its mark, in order of key.
    pub lists: Vec<[u8; 32]>,
}

/// Where it is said that message `id` was read by an agent of `name`
/// (decision 2026-10-09 §7.2): worked out when it is shown, from the
/// device's own table and the latest list kept of each other device.
/// Which of those keys count is the caller's to say.
pub fn read_by(conn: &Connection, id: &Id, name: &str) -> Result<ReadBy, StorageError> {
    let mark = read_mark(id, name);
    let here: i64 = conn.query_row(
        "SELECT COUNT(*) FROM message_read_here WHERE mark = ?1",
        [&mark[..]],
        |row| row.get(0),
    )?;
    let lists: Vec<Vec<u8>> = conn
        .prepare("SELECT key FROM message_lists WHERE mark = ?1 ORDER BY key")?
        .query_map([&mark[..]], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(ReadBy {
        here: here > 0,
        lists: lists
            .into_iter()
            .filter_map(|key| key.try_into().ok())
            .collect(),
    })
}

fn mark_of(bytes: &[u8]) -> Mark {
    let mut mark = [0; AGENT_MESSAGE_READ_MARK_BYTES];
    let len = bytes.len().min(mark.len());
    mark[..len].copy_from_slice(&bytes[..len]);
    mark
}

/// The messages channel the device stands applied under, as the hourly
/// task is told it ([`drop_gone`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// This channel, by its ID.
    Under([u8; 32]),
    /// None: the device follows no phrase, or does not stand applied.
    Nowhere,
    /// It could not be read.
    NotKnown,
}

/// A count or a number as the store's integer holds it. Every number of
/// a message is at most 2^42 - 1, and a count of entries far less.
fn to_sql(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn from_sql(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// Drop the index row of the message `id` at `now` (decision 2026-10-09
/// §7.1): at its 30 days, at a clearing, or when none of its numbers is
/// live, in whatever generation. Its body, link, subject, `from_name` and
/// `to_name` are first written over with zeros of the same length, then
/// the row is deleted, and its rows of numbers held with it, in one
/// transaction. The rows of first holding stay. A field that holds
/// nothing (no link, and no `to_name` for every name) is left so. Returns
/// whether the device held the row.
///
/// **Each mark of it in the device's own table stays, as a bare hash**
/// (§7.2): its ID and its name are dropped, and it became bare at `now`.
/// Another device may show the message for longer than this one (its
/// place, its first holding, its clock), and its agent is not to act on
/// it twice: the mark goes in the lists as it did, by the bounds of a
/// bare hash, at most 120 and for 30 days. This is the one statement that
/// deletes a row of the index, and the table's key to it has no cascade.
///
/// It runs in a savepoint, so it is whole by itself, and part of the
/// caller's transaction where there is one: the door's write that takes a
/// clearing, or raises H, drops its rows in that write.
pub fn drop_row(conn: &Connection, id: &[u8], now: i64) -> Result<bool, StorageError> {
    conn.execute_batch("SAVEPOINT drop_row")?;
    let dropped = overwritten_and_deleted(conn, id, now);
    let end = match dropped {
        Ok(_) => "RELEASE drop_row",
        Err(_) => "ROLLBACK TO drop_row; RELEASE drop_row",
    };
    conn.execute_batch(end)?;
    dropped
}

fn overwritten_and_deleted(conn: &Connection, id: &[u8], now: i64) -> Result<bool, StorageError> {
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
    conn.execute(
        "UPDATE message_read_here SET id = NULL, name = NULL, merged_at = ?2 WHERE id = ?1",
        params![id, now],
    )?;
    keep_120_bare(conn)?;
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

        assert!(drop_row(&conn, &[1; 16], 200).unwrap());
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

        assert!(drop_row(&conn, &[1; 16], 200).unwrap());
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

        // A row deleted as it is leaves its words where they were. Its
        // mark goes first: the index row that a mark names is refused to
        // any delete but `drop_row`'s.
        let delete = "DELETE FROM message_index WHERE id = ?1";
        assert!(conn.execute(delete, [&[2u8; 16][..]]).is_err());
        conn.execute(
            "DELETE FROM message_read_here WHERE id = ?1",
            [&[2u8; 16][..]],
        )
        .unwrap();
        conn.execute(delete, [&[2u8; 16][..]]).unwrap();
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

        assert!(drop_row(&conn, &[1; 16], 200).unwrap());
        assert!(drop_row(&conn, &[2; 16], 200).unwrap());
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

    /// A mark as the table keeps it: the mark, its ID and name, and when it
    /// became bare.
    type AsKept = (Vec<u8>, Option<Vec<u8>>, Option<String>, Option<i64>);

    /// A row that goes takes its rows of numbers held with it, leaves its
    /// marks as bare hashes that became bare as it went, and leaves its
    /// rows of first holding, and every other row (decision 2026-10-09
    /// §7.1, §7.2). A mark merged from the device's own list, with no
    /// message, stays as it was. Dropping a row the device does not hold
    /// changes nothing.
    #[test]
    fn a_dropped_row_leaves_its_marks_as_bare_hashes_and_its_first_holding() {
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

        assert!(drop_row(&conn, &[1; 16], 200).unwrap());
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
        let marks: Vec<AsKept> = conn
            .prepare("SELECT mark, id, name, merged_at FROM message_read_here ORDER BY mark")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            marks,
            [
                (vec![1; 16], None, None, Some(200)),
                (vec![2; 16], Some(vec![2; 16]), Some("notes".into()), None),
                (vec![9; 16], None, None, Some(103)),
            ]
        );

        assert!(!drop_row(&conn, &[1; 16], 200).unwrap());
        assert!(!drop_row(&conn, &[3; 16], 200).unwrap());
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
            assert_eq!(drop_row(&conn, &[1; 16], 200).ok(), Some(true), "{begin}");
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
        assert_eq!(drop_row(&conn, &[1; 16], 200).ok(), Some(true));
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
        assert!(hold_number(conn, &[signer; 32], 1, number, false, at).unwrap());
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
        assert!(clear(&conn, &[7; 32], 1, 3, 100).unwrap());
        assert!(hold_number(&conn, &[7; 32], 1, 5, false, 100).unwrap());
        assert_eq!(signer(&conn, &[7; 32], 1).unwrap().unwrap().overwritten, 0);

        assert!(hold_number(&conn, &[7; 32], 1, 68, false, 100).unwrap());
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
        assert!(hold_number(&conn, &[7; 32], 1, 5, false, 100).unwrap());
        assert!(!hold_number(&conn, &[7; 32], 1, 4, false, 100).unwrap());
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
            drop_gone(&conn, now - 1, &Applied::Nowhere).unwrap(),
            Gone {
                expired: 0,
                not_live: 1
            }
        );
        assert_eq!(
            drop_gone(&conn, now, &Applied::Nowhere).unwrap(),
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

    /// Where the device stands applied under none, the hourly drop keeps
    /// the most recent generation, though nothing of it is left but its
    /// counts and rows of first holding, and drops the older ones that are
    /// empty; where which one it stands under is not known, it drops no
    /// generation, and still drops what has expired (decision 2026-10-09
    /// §7.1, §9.1).
    #[test]
    fn the_hourly_drop_keeps_the_last_generation_and_drops_none_where_it_is_not_known() {
        let conn = db::open_in_memory().unwrap();
        for channel in 1..=3u8 {
            generation(&conn, &[channel; 32], 1, 100).unwrap();
        }
        // The third holds an expired message, and the row of first holding
        // of a clearing.
        conn.execute_batch(
            "INSERT INTO message_index (id, signer, label, generation, to_kind, to_name,
                                        from_name, sent, subject, thread, answers, asks,
                                        link, body, first_held, placed_at)
                 VALUES (zeroblob(16), zeroblob(32), 'laptop', 3, 2, NULL, '~', 100, 'a',
                         zeroblob(16), zeroblob(16), 0, NULL, 'a', 100, 100);
             INSERT INTO message_numbers (signer, generation, number, id)
                 VALUES (zeroblob(32), 3, 1, zeroblob(16));
             INSERT INTO message_signers (signer, generation, highest, counted_from)
                 VALUES (zeroblob(32), 3, 2, 1);
             INSERT INTO message_first_held (signer, generation, number, id, sent, first_held)
                 VALUES (zeroblob(32), 3, 2, NULL, NULL, 100);",
        )
        .unwrap();
        let generations = || -> Vec<i64> {
            conn.prepare("SELECT id FROM message_generations ORDER BY id")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        let later = 100 + 30 * DAY_SECS;
        let gone = drop_gone(&conn, later, &Applied::NotKnown).unwrap();
        assert_eq!(gone.expired, 1);
        assert_eq!(generations(), [1, 2, 3]);

        drop_gone(&conn, later, &Applied::Nowhere).unwrap();
        assert_eq!(generations(), [3]);
        assert_eq!(count(&conn, "message_first_held"), 1);
        assert_eq!(count(&conn, "message_signers"), 1);

        drop_gone(&conn, later, &Applied::Under([4; 32])).unwrap();
        assert!(generations().is_empty());
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

        assert!(drop_row(&conn, &[1; 16], 200).is_err());
        assert!(conn.is_autocommit(), "nothing is left open");
        assert_eq!(text(&conn), as_written);

        conn.execute_batch("BEGIN").unwrap();
        conn.execute("UPDATE message_index SET placed_at = 7", [])
            .unwrap();
        assert!(drop_row(&conn, &[1; 16], 200).is_err());
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

    /// A holder of a device's key writes its 64 slots with rising numbers
    /// ten thousand times over, and the store takes each as the reader
    /// does, by `hold_number` and `index`, with nothing sealed or opened:
    /// after every lap no table holds more than one lap's rows, the
    /// signer is one row, and every lap but the last is counted as
    /// overwritten (decision 2026-10-09 §2.5, property 21, D1, T22). The
    /// whole path, through the door, is run for a hundred laps in the
    /// reader's test of the same name.
    #[test]
    fn a_signer_that_rewrites_its_ring_ten_thousand_times_leaves_one_lap_in_the_store() {
        const LAPS: u64 = 10_000;
        let conn = db::open_in_memory().unwrap();
        generation_1(&conn);
        let tables = [
            "message_index",
            "message_numbers",
            "message_first_held",
            "message_signers",
            "message_places",
        ];
        let message = message("a lap", 100);
        for lap in 0..LAPS {
            conn.execute_batch("BEGIN").unwrap();
            for place in 1..=RING as u64 {
                let number = lap * RING as u64 + place;
                assert!(hold_number(&conn, &[7; 32], 1, number, false, 100).unwrap());
                let mut id = [0; 16];
                id[..8].copy_from_slice(&number.to_be_bytes());
                let opened = Opened {
                    id: &id,
                    signer: &[7; 32],
                    label: "laptop",
                    generation: 1,
                    number,
                    message: &message,
                    first_held: 100,
                    placed_at: None,
                };
                assert_eq!(index(&conn, &opened).unwrap(), Indexed::New);
            }
            conn.execute_batch("COMMIT").unwrap();
            let rows: Vec<i64> = tables.iter().map(|table| count(&conn, table)).collect();
            assert_eq!(rows, [RING, RING, RING, 1, 0], "lap {lap}");
        }
        let kept = signer(&conn, &[7; 32], 1).unwrap().unwrap();
        assert_eq!(kept.highest, LAPS * RING as u64);
        assert_eq!(kept.overwritten, (LAPS - 1) * RING as u64);
    }

    // ── Marks ───────────────────────────────────────────────────────

    /// The ID that [`taken`] gives message `number` of `signer` saying
    /// `body`.
    fn id_taken(signer: u8, number: u64, body: &str) -> Id {
        let mut id = [signer; 16];
        id[0] = body.as_bytes()[0];
        id[1] = u8::try_from(number % 256).unwrap();
        id
    }

    /// Messages 1 to `count` of signer 7, each saying `m`, taken and
    /// given places at `at`: their IDs, by number.
    fn shown_messages(conn: &Connection, count: u64, at: i64) -> Vec<Id> {
        let ids = (1..=count)
            .map(|number| {
                taken(conn, 7, number, "m", at);
                id_taken(7, number, "m")
            })
            .collect();
        give_places(conn, &[1; 32], at).unwrap();
        ids
    }

    /// The device's table, as (mark, seq, whether it has an ID), by seq.
    fn table(conn: &Connection) -> Vec<(Mark, i64, bool)> {
        conn.prepare("SELECT mark, seq, id IS NOT NULL FROM message_read_here ORDER BY seq")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    mark_of(&row.get::<_, Vec<u8>>(0)?),
                    row.get(1)?,
                    row.get(2)?,
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// A mark is of a message and a name (decision 2026-10-09 §2.2, §7.2):
    /// a message to every name that the agent of `notes` read is read for
    /// `notes` and not for `~`, here and in another device's list; and the
    /// mark is not the message's ID. Read again, a mark is not added twice,
    /// and is made the newest.
    #[test]
    fn a_mark_is_of_a_message_and_a_name() {
        let conn = db::open_in_memory().unwrap();
        let ids = shown_messages(&conn, 2, 100);
        assert!(mark_read(&conn, &ids[0], "notes", 101).unwrap());
        assert_eq!(
            read_by(&conn, &ids[0], "notes").unwrap(),
            ReadBy {
                here: true,
                lists: vec![]
            }
        );
        assert_eq!(read_by(&conn, &ids[0], "~").unwrap(), ReadBy::default());
        assert_eq!(read_by(&conn, &ids[1], "notes").unwrap(), ReadBy::default());
        let marks = marks_to_list(&conn).unwrap();
        assert_eq!(marks, [read_mark(&ids[0], "notes")]);
        assert_ne!(marks[0][..], ids[0][..]);

        keep_list(&conn, &[3; 32], &[read_mark(&ids[1], "~")]).unwrap();
        assert_eq!(
            read_by(&conn, &ids[1], "~").unwrap(),
            ReadBy {
                here: false,
                lists: vec![[3; 32]]
            }
        );
        assert_eq!(read_by(&conn, &ids[1], "notes").unwrap(), ReadBy::default());

        assert!(mark_read(&conn, &ids[1], "notes", 103).unwrap());
        assert!(!mark_read(&conn, &ids[0], "notes", 104).unwrap());
        assert_eq!(
            marks_to_list(&conn).unwrap(),
            [read_mark(&ids[0], "notes"), read_mark(&ids[1], "notes")]
        );
        assert_eq!(count(&conn, "message_read_here"), 2);
    }

    /// A list holds the newest 120 marks of the table, the newest first,
    /// whatever became of their messages, the bare hashes among them
    /// (decision 2026-10-09 §2.4, §7.2); and of each other device only its
    /// latest list is kept, each mark once, until its key no longer counts.
    #[test]
    fn a_list_holds_the_newest_120_and_only_the_latest_list_of_each_device_is_kept() {
        let conn = db::open_in_memory().unwrap();
        let ids = shown_messages(&conn, 60, 100);
        for (k, id) in ids.iter().enumerate() {
            let at = 200 + i64::try_from(k).unwrap();
            mark_read(&conn, id, "notes", at).unwrap();
            mark_read(&conn, id, "~", at).unwrap();
        }
        merge_own_list(&conn, &[[0xb1; 16], [0xb2; 16]], &[], 300).unwrap();
        // 122 marks: the newest 120 are listed, newest first.
        let newest: Vec<Mark> = ids
            .iter()
            .rev()
            .flat_map(|id| [read_mark(id, "~"), read_mark(id, "notes")])
            .collect();
        assert_eq!(marks_to_list(&conn).unwrap(), newest[..120]);
        // With room, the bare hashes are listed, the oldest last.
        conn.execute("DELETE FROM message_read_here WHERE seq > 100", [])
            .unwrap();
        let listed = marks_to_list(&conn).unwrap();
        assert_eq!(listed.len(), 102);
        assert_eq!(listed[100..], [[0xb1; 16], [0xb2; 16]]);
        // Whatever became of its message here, a mark is listed: one with
        // no place, and one held at no live number.
        conn.execute(
            "UPDATE message_index SET placed_at = NULL WHERE id = ?1",
            [&ids[49][..]],
        )
        .unwrap();
        conn.execute("UPDATE message_signers SET highest = 64 + 30", [])
            .unwrap();
        assert_eq!(marks_to_list(&conn).unwrap(), listed);

        keep_list(&conn, &[3; 32], &[[1; 16], [2; 16], [1; 16]]).unwrap();
        keep_list(&conn, &[4; 32], &[[1; 16]]).unwrap();
        assert_eq!(count(&conn, "message_lists"), 3);
        keep_list(&conn, &[3; 32], &[[5; 16]]).unwrap();
        let held: Vec<(Vec<u8>, Vec<u8>)> = conn
            .prepare("SELECT key, mark FROM message_lists ORDER BY key, mark")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            held,
            [(vec![3; 32], vec![5; 16]), (vec![4; 32], vec![1; 16])]
        );
        assert_eq!(drop_lists_but(&conn, &[[4; 32], [9; 32]]).unwrap(), 1);
        let left: Vec<Vec<u8>> = conn
            .prepare("SELECT key FROM message_lists")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(left, [vec![4; 32]]);
    }

    /// The device's own list taken from a relay is merged as older than
    /// any mark the table holds, in the list's order (decision 2026-10-09
    /// §7.2, D7): a mark it holds is not merged again, one whose message
    /// it holds is given the ID and the name, by the names mapped here or
    /// the name the message is to, and the rest are bare hashes.
    #[test]
    fn a_device_merges_its_own_list_as_older_than_any_mark_it_holds() {
        let conn = db::open_in_memory().unwrap();
        let ids = shown_messages(&conn, 3, 100);
        mark_read(&conn, &ids[0], "notes", 101).unwrap();
        let list = [
            read_mark(&ids[1], "work"),
            [0xb1; 16],
            read_mark(&ids[0], "notes"),
            read_mark(&ids[2], "~"),
            [0xb1; 16],
        ];
        let names = ["work".to_string()];
        assert_eq!(merge_own_list(&conn, &list, &names, 200).unwrap(), 3);
        let held: Vec<(Mark, bool)> = table(&conn).iter().map(|row| (row.0, row.2)).collect();
        assert_eq!(
            held,
            [
                (read_mark(&ids[2], "~"), false),
                ([0xb1; 16], false),
                (read_mark(&ids[1], "work"), true),
                (read_mark(&ids[0], "notes"), true),
            ]
        );
        let seqs: Vec<i64> = table(&conn).iter().map(|row| row.1).collect();
        assert_eq!(seqs, [-2, -1, 0, 1]);
        let name: String = conn
            .query_row(
                "SELECT name FROM message_read_here WHERE mark = ?1",
                [&read_mark(&ids[1], "work")[..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "work");
        assert_eq!(
            marks_to_list(&conn).unwrap(),
            [
                read_mark(&ids[0], "notes"),
                read_mark(&ids[1], "work"),
                [0xb1; 16],
                read_mark(&ids[2], "~"),
            ]
        );
        assert!(read_by(&conn, &ids[2], "~").unwrap().here);
        // The same list merged again adds nothing.
        assert_eq!(merge_own_list(&conn, &list, &names, 201).unwrap(), 0);
        assert_eq!(count(&conn, "message_read_here"), 4);
        // Read here, a bare hash is given its ID and name, as the newest.
        assert!(!mark_read(&conn, &ids[2], "~", 202).unwrap());
        let newest: (Vec<u8>, Option<Vec<u8>>, Option<String>) = conn
            .query_row(
                "SELECT mark, id, name FROM message_read_here ORDER BY seq DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            newest,
            (
                read_mark(&ids[2], "~").to_vec(),
                Some(ids[2].to_vec()),
                Some("~".to_string())
            )
        );
    }

    /// At most 120 marks are kept as a bare hash, and the oldest goes
    /// first; a bare hash whose message the device comes to hold is given
    /// its ID and name, and one still bare 30 days after it was merged
    /// goes (decision 2026-10-09 §7.2, F8).
    #[test]
    fn a_bare_hash_is_kept_at_most_120_and_30_days_where_no_message_is_found() {
        let conn = db::open_in_memory().unwrap();
        let ids = shown_messages(&conn, 1, 100);
        mark_read(&conn, &ids[0], "notes", 100).unwrap();
        let bare = |k: u8| [k; 16];
        let first: Vec<Mark> = (1..=100).map(bare).collect();
        merge_own_list(&conn, &first, &[], 200).unwrap();
        // The oldest of the second list is found, and is below the bound:
        // the bound is on bare hashes alone.
        let mut second: Vec<Mark> = (101..=130).map(bare).collect();
        let to_work = read_mark(&ids[0], "work");
        second.push(to_work);
        merge_own_list(&conn, &second, &["work".to_string()], 300).unwrap();
        let held = table(&conn);
        assert_eq!(held.len(), 122);
        assert!(held.iter().any(|row| row.0 == to_work && row.2));
        let bare_held: Vec<Mark> = held.iter().filter(|row| !row.2).map(|row| row.0).collect();
        // The oldest are the last of the second list, merged last.
        let mut want: Vec<Mark> = (101..=120).rev().map(bare).collect();
        want.extend((1..=100).rev().map(bare));
        assert_eq!(bare_held, want);

        // Message 2 comes, and is the one a bare hash marks.
        taken(&conn, 7, 2, "m", 400);
        let found = read_mark(&id_taken(7, 2, "m"), "work");
        // Merged as the oldest, it is the first to go at the bound: with
        // one bare hash fewer, it is kept.
        merge_own_list(&conn, &[found], &[], 400).unwrap();
        assert!(!table(&conn).iter().any(|row| row.0 == found));
        conn.execute(
            "DELETE FROM message_read_here WHERE mark = ?1",
            [&bare(1)[..]],
        )
        .unwrap();
        merge_own_list(&conn, &[found], &[], 400).unwrap();
        assert_eq!(table(&conn).len(), 122);
        let names = ["work".to_string()];
        let month = i64::from(AGENT_MESSAGE_KEPT_DAYS) * DAY_SECS;
        assert_eq!(keep_bare_marks(&conn, &names, 200 + month - 1).unwrap(), 0);
        assert!(table(&conn).iter().any(|row| row.0 == found && row.2));
        assert_eq!(keep_bare_marks(&conn, &names, 200 + month).unwrap(), 99);
        assert_eq!(keep_bare_marks(&conn, &names, 300 + month).unwrap(), 20);
        let left: Vec<(Mark, bool)> = table(&conn).iter().map(|row| (row.0, row.2)).collect();
        assert_eq!(
            left,
            [
                (found, true),
                (to_work, true),
                (read_mark(&ids[0], "notes"), true)
            ]
        );
    }

    /// Each mark of the table, by seq: its mark, whether it has an ID, and
    /// when it became bare.
    fn bare_at(conn: &Connection) -> Vec<(Mark, bool, Option<i64>)> {
        conn.prepare("SELECT mark, id IS NOT NULL, merged_at FROM message_read_here ORDER BY seq")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    mark_of(&row.get::<_, Vec<u8>>(0)?),
                    row.get(1)?,
                    row.get(2)?,
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// A mark whose message's row goes from the index stays in the table
    /// as a bare hash, from the moment it went, and is in the list and
    /// read here, whichever way the row went (decision 2026-10-09 §7.1,
    /// §7.2): a clearing, leaving the live numbers at the door, held at no
    /// live number at the hourly task, and its 30 days in a generation the
    /// device has left, which then goes whole.
    #[test]
    fn a_mark_whose_messages_row_goes_stays_as_a_bare_hash_for_each_reason() {
        let conn = db::open_in_memory().unwrap();
        let ids: Vec<Id> = (1..=4)
            .map(|number| {
                taken(&conn, 7, number, "m", 100);
                id_taken(7, number, "m")
            })
            .collect();
        give_places(&conn, &[1; 32], 100).unwrap();
        for (k, id) in ids.iter().enumerate() {
            mark_read(&conn, id, "notes", 101 + i64::try_from(k).unwrap()).unwrap();
        }
        let marks: Vec<Mark> = ids.iter().map(|id| read_mark(id, "notes")).collect();
        generation(&conn, &[2; 32], 1, 100).unwrap();

        // A clearing.
        assert!(clear(&conn, &[7; 32], 1, 1, 150).unwrap());
        // Number 2 leaves the live numbers, at the door.
        assert!(hold_number(&conn, &[7; 32], 1, 2 + 64, false, 160).unwrap());
        // Number 3 is held at no live number at the hourly task.
        conn.execute("UPDATE message_signers SET highest = 3 + 64", [])
            .unwrap();
        let gone = drop_gone(&conn, 170, &Applied::NotKnown).unwrap();
        assert_eq!(gone.not_live, 1);
        // Number 4's 30 days are up, in the generation the device left.
        let month = i64::from(AGENT_MESSAGE_KEPT_DAYS) * DAY_SECS;
        let gone = drop_gone(&conn, 100 + month, &Applied::Under([2; 32])).unwrap();
        assert_eq!(gone.expired, 1);
        assert_eq!(count(&conn, "message_index"), 0);
        let generations: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM message_generations WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(generations, 0, "the generation left goes whole");

        assert_eq!(
            bare_at(&conn),
            [
                (marks[0], false, Some(150)),
                (marks[1], false, Some(160)),
                (marks[2], false, Some(170)),
                (marks[3], false, Some(100 + month)),
            ]
        );
        let newest_first: Vec<Mark> = marks.iter().rev().copied().collect();
        assert_eq!(marks_to_list(&conn).unwrap(), newest_first);
        for id in &ids {
            assert!(read_by(&conn, id, "notes").unwrap().here);
        }
    }

    /// A mark left bare by its message's row is bound as a merged bare
    /// hash is (decision 2026-10-09 §7.2): at most 120 are kept, the oldest
    /// going first, and each goes 30 days after it became bare, not after
    /// it was made. Two devices' shown times of one message differ by less
    /// than 30 days, so another device that still shows it is told.
    #[test]
    fn a_mark_left_bare_is_kept_at_most_120_and_30_days_after_it_became_bare() {
        let conn = db::open_in_memory().unwrap();
        let mut ids: Vec<Id> = Vec::new();
        for (signer, count) in [(7, 60), (8, 61)] {
            for number in 1..=count {
                taken(&conn, signer, number, "m", 100);
                ids.push(id_taken(signer, number, "m"));
            }
        }
        give_places(&conn, &[1; 32], 100).unwrap();
        for (k, id) in ids.iter().enumerate() {
            mark_read(&conn, id, "notes", 101 + i64::try_from(k).unwrap()).unwrap();
        }
        let month = i64::from(AGENT_MESSAGE_KEPT_DAYS) * DAY_SECS;
        let expired = 100 + month;
        assert_eq!(
            drop_gone(&conn, expired, &Applied::NotKnown)
                .unwrap()
                .expired,
            121
        );
        // The mark made first, the oldest, is the one that went.
        let kept = bare_at(&conn);
        assert_eq!(kept.len(), 120);
        assert!(kept.iter().all(|row| !row.1 && row.2 == Some(expired)));
        let newest: Vec<Mark> = ids[1..]
            .iter()
            .rev()
            .map(|id| read_mark(id, "notes"))
            .collect();
        assert_eq!(marks_to_list(&conn).unwrap(), newest);

        assert_eq!(keep_bare_marks(&conn, &[], expired + month - 1).unwrap(), 0);
        assert_eq!(count(&conn, "message_read_here"), 120);
        assert_eq!(keep_bare_marks(&conn, &[], expired + month).unwrap(), 120);
        assert_eq!(count(&conn, "message_read_here"), 0);
    }
}
