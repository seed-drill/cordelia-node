//! What a device keeps of subscribing and of messages in a shared channel
//! (decision 2026-10-10 §4.1, §6.1, §6.2, §6.4): the tables of schema step
//! 25.
//!
//! - **Subscriptions' starts** (`shared_msg_subscribed`): a subscription in
//!   force on this device, with when this device first took it in that
//!   state. A subscription is consent from a moment on each device.
//! - **Shared marks** (`shared_msg_marks`): this device's own table of the
//!   marks of shared messages its agents read and sent, each binding the
//!   channel; and the latest `sread/` list of each other device
//!   (`shared_msg_lists`).
//! - **A person's reads** of shared messages on this device
//!   (`shared_msg_read_by_a_person`), never said to another device.
//! - **The channel's hour** (`shared_msg_sends`) and **the kept values** of
//!   the device's own messages that not every relay has taken
//!   (`shared_msg_kept`, `shared_msg_kept_numbers`).
//!
//! Nothing here decides who is shown what: that is decided where these are
//! read (`cordelia_api::shared_messages`). Every time here is the node's,
//! passed in.

use std::collections::HashSet;

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;
use cordelia_core::protocol::{AGENT_MESSAGE_KEPT_DAYS, AGENT_MESSAGE_READ_MARKS_MAX};

use crate::messages::{Id, Mark};

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

const HOUR_SECS: i64 = 60 * 60;
const DAY_SECS: i64 = 24 * HOUR_SECS;

// ── Subscriptions ────────────────────────────────────────────────────

/// A subscription in force on this device, and its start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribed {
    pub channel: [u8; 32],
    pub agent: String,
    pub start: i64,
}

/// Every subscription in force on this device, by channel and agent.
pub fn subscribed(conn: &Connection) -> Result<Vec<Subscribed>, CordeliaError> {
    conn.prepare("SELECT channel, agent, start FROM shared_msg_subscribed ORDER BY channel, agent")
        .map_err(storage)?
        .query_map([], |row| {
            Ok(Subscribed {
                channel: row.get(0)?,
                agent: row.get(1)?,
                start: row.get(2)?,
            })
        })
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)
}

/// Keep the starts with what is in force, `in_force`, at `now` (decision
/// 2026-10-10 §4.1): one in force that has no start starts now; one that
/// keeps its state keeps its start; one no longer in force goes, so that it
/// starts again when it is taken again.
pub fn keep_subscribed(
    conn: &Connection,
    in_force: &[([u8; 32], String)],
    now: i64,
) -> Result<(), CordeliaError> {
    for held in subscribed(conn)? {
        if !in_force
            .iter()
            .any(|(channel, agent)| *channel == held.channel && *agent == held.agent)
        {
            conn.execute(
                "DELETE FROM shared_msg_subscribed WHERE channel = ?1 AND agent = ?2",
                params![&held.channel[..], held.agent],
            )
            .map_err(storage)?;
        }
    }
    for (channel, agent) in in_force {
        conn.execute(
            "INSERT INTO shared_msg_subscribed (channel, agent, start) VALUES (?1, ?2, ?3)
             ON CONFLICT(channel, agent) DO NOTHING",
            params![&channel[..], agent, now],
        )
        .map_err(storage)?;
    }
    Ok(())
}

// ── Shared marks ─────────────────────────────────────────────────────

/// `mark` is made at `now`: the newest in the table, whether or not it was
/// held.
pub fn mark(conn: &Connection, mark: &Mark, now: i64) -> Result<(), CordeliaError> {
    let next: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM shared_msg_marks",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    conn.execute(
        "INSERT INTO shared_msg_marks (mark, seq, made_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(mark) DO UPDATE SET seq = excluded.seq, made_at = excluded.made_at",
        params![&mark[..], next, now],
    )
    .map_err(storage)?;
    Ok(())
}

/// Whether the table holds `mark`.
pub fn has_mark(conn: &Connection, mark: &Mark) -> Result<bool, CordeliaError> {
    conn.query_row(
        "SELECT COUNT(*) > 0 FROM shared_msg_marks WHERE mark = ?1",
        [&mark[..]],
        |row| row.get(0),
    )
    .map_err(storage)
}

/// The marks a list holds: the newest 120 of the table, newest first.
pub fn marks_to_list(conn: &Connection) -> Result<Vec<Mark>, CordeliaError> {
    conn.prepare("SELECT mark FROM shared_msg_marks ORDER BY seq DESC LIMIT ?1")
        .map_err(storage)?
        .query_map([AGENT_MESSAGE_READ_MARKS_MAX as i64], |row| row.get(0))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)
}

/// The device's own list from its later life, `marks`, is merged into its
/// table, each mark it lacks older than every mark it holds, in the list's
/// order (the newest first), at `now`. Returns how many it lacked.
pub fn merge_own_list(conn: &Connection, marks: &[Mark], now: i64) -> Result<usize, CordeliaError> {
    let mut lowest: i64 = conn
        .query_row(
            "SELECT COALESCE(MIN(seq), 1) FROM shared_msg_marks",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    let mut merged = 0;
    for mark in marks {
        if has_mark(conn, mark)? {
            continue;
        }
        lowest -= 1;
        conn.execute(
            "INSERT INTO shared_msg_marks (mark, seq, made_at) VALUES (?1, ?2, ?3)",
            params![&mark[..], lowest, now],
        )
        .map_err(storage)?;
        merged += 1;
    }
    Ok(merged)
}

/// The list of another device, `key`, in place of what was kept of it.
pub fn keep_list(conn: &Connection, key: &[u8; 32], marks: &[Mark]) -> Result<(), CordeliaError> {
    conn.execute("DELETE FROM shared_msg_lists WHERE key = ?1", [&key[..]])
        .map_err(storage)?;
    for mark in marks {
        conn.execute(
            "INSERT OR IGNORE INTO shared_msg_lists (key, mark) VALUES (?1, ?2)",
            params![&key[..], &mark[..]],
        )
        .map_err(storage)?;
    }
    Ok(())
}

/// Every mark this device holds: of its own table, and of each other
/// device's latest list, with its key.
pub struct Marks {
    pub here: HashSet<Mark>,
    pub lists: Vec<([u8; 32], Mark)>,
}

/// What [`Marks`] holds, read with two statements.
pub fn marks(conn: &Connection) -> Result<Marks, CordeliaError> {
    let here = conn
        .prepare("SELECT mark FROM shared_msg_marks")
        .map_err(storage)?
        .query_map([], |row| row.get(0))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    let lists = conn
        .prepare("SELECT key, mark FROM shared_msg_lists ORDER BY key")
        .map_err(storage)?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    Ok(Marks { here, lists })
}

/// The lists of every key but `keys` go (the hourly task: a key that no
/// longer counts says nothing); and each mark of this device's table made
/// more than 30 days before `now`, whose message has expired, since a
/// message expires 30 days from its shown time, which is no later than
/// when this device first held it, and a mark is made after.
pub fn keep_within(conn: &Connection, keys: &[[u8; 32]], now: i64) -> Result<(), CordeliaError> {
    let held: Vec<[u8; 32]> = conn
        .prepare("SELECT DISTINCT key FROM shared_msg_lists")
        .map_err(storage)?
        .query_map([], |row| row.get(0))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    for key in held {
        if !keys.contains(&key) {
            conn.execute("DELETE FROM shared_msg_lists WHERE key = ?1", [&key[..]])
                .map_err(storage)?;
        }
    }
    conn.execute(
        "DELETE FROM shared_msg_marks WHERE made_at < ?1",
        [now - i64::from(AGENT_MESSAGE_KEPT_DAYS) * DAY_SECS],
    )
    .map_err(storage)?;
    Ok(())
}

// ── A person's reads ─────────────────────────────────────────────────

/// A person read the shared message `id` of the channel of row `channel`
/// on this device. Nothing where the index does not hold it.
pub fn mark_read_by_a_person(
    conn: &Connection,
    channel: i64,
    id: &Id,
) -> Result<bool, CordeliaError> {
    let held: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM shared_index WHERE channel = ?1 AND id = ?2",
            params![channel, &id[..]],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if !held {
        return Ok(false);
    }
    conn.execute(
        "INSERT OR IGNORE INTO shared_msg_read_by_a_person (channel, id) VALUES (?1, ?2)",
        params![channel, &id[..]],
    )
    .map_err(storage)?;
    Ok(true)
}

/// The shared messages of the channel of row `channel` that a person read
/// here.
pub fn read_by_a_person(conn: &Connection, channel: i64) -> Result<HashSet<Id>, CordeliaError> {
    conn.prepare("SELECT id FROM shared_msg_read_by_a_person WHERE channel = ?1")
        .map_err(storage)?
        .query_map([channel], |row| row.get(0))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)
}

// ── The channel's hour ───────────────────────────────────────────────

/// This device wrote a number in the channel of row `channel` at `now`: a
/// send again where `again`.
pub fn record_send(
    conn: &Connection,
    channel: i64,
    now: i64,
    again: bool,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO shared_msg_sends (channel, sent_at, again) VALUES (?1, ?2, ?3)",
        params![channel, now, again],
    )
    .map_err(storage)?;
    Ok(())
}

/// The numbers this device wrote in the channel of row `channel` in the
/// hour before `now`, oldest first: the first sends, and the sends again.
pub fn sends_lately(
    conn: &Connection,
    channel: i64,
    now: i64,
) -> Result<(Vec<i64>, Vec<i64>), CordeliaError> {
    let rows: Vec<(i64, bool)> = conn
        .prepare(
            "SELECT sent_at, again FROM shared_msg_sends
             WHERE channel = ?1 AND sent_at > ?2 AND sent_at <= ?3 ORDER BY sent_at",
        )
        .map_err(storage)?
        .query_map(params![channel, now - HOUR_SECS, now], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    let (again, sends): (Vec<_>, Vec<_>) = rows.into_iter().partition(|(_, again)| *again);
    Ok((
        sends.into_iter().map(|(at, _)| at).collect(),
        again.into_iter().map(|(at, _)| at).collect(),
    ))
}

/// The sends of every channel from before the hour go.
pub fn drop_old_sends(conn: &Connection, now: i64) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM shared_msg_sends WHERE sent_at <= ?1",
        [now - HOUR_SECS],
    )
    .map_err(storage)?;
    Ok(())
}

// ── Kept values ──────────────────────────────────────────────────────

/// A message of the device's own in a shared channel that not every relay
/// of its card has taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    /// The channel's row.
    pub channel: i64,
    pub id: Id,
    pub value: Vec<u8>,
    pub sent: i64,
    /// The numbers it was sent under, the newest last.
    pub numbers: Vec<u64>,
    /// It waits to be sent again under the next number.
    pub again: bool,
}

/// Keep `kept`, at `now`.
pub fn keep(conn: &Connection, kept: &Kept, now: i64) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO shared_msg_kept (channel, id, value, sent, kept_at, again)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            kept.channel,
            &kept.id[..],
            kept.value,
            kept.sent,
            now,
            kept.again
        ],
    )
    .map_err(storage)?;
    for number in &kept.numbers {
        kept_under(conn, kept.channel, &kept.id, *number)?;
    }
    Ok(())
}

/// The kept message `id` of the channel of row `channel` was written again
/// under `number`: it waits no more.
pub fn kept_under(
    conn: &Connection,
    channel: i64,
    id: &Id,
    number: u64,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT OR IGNORE INTO shared_msg_kept_numbers (channel, id, number) VALUES (?1, ?2, ?3)",
        params![channel, &id[..], i64::try_from(number).unwrap_or(i64::MAX)],
    )
    .map_err(storage)?;
    conn.execute(
        "UPDATE shared_msg_kept SET again = 0 WHERE channel = ?1 AND id = ?2",
        params![channel, &id[..]],
    )
    .map_err(storage)?;
    Ok(())
}

/// Every kept message, in the order kept.
pub fn kept(conn: &Connection) -> Result<Vec<Kept>, CordeliaError> {
    let rows: Vec<(i64, Id, Vec<u8>, i64, bool)> = conn
        .prepare(
            "SELECT channel, id, value, sent, again FROM shared_msg_kept
             ORDER BY kept_at, channel, id",
        )
        .map_err(storage)?
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    let mut all = Vec::with_capacity(rows.len());
    for (channel, id, value, sent, again) in rows {
        let numbers: Vec<i64> = conn
            .prepare(
                "SELECT number FROM shared_msg_kept_numbers WHERE channel = ?1 AND id = ?2
                 ORDER BY number",
            )
            .map_err(storage)?
            .query_map(params![channel, &id[..]], |row| row.get(0))
            .map_err(storage)?
            .collect::<Result<_, _>>()
            .map_err(storage)?;
        all.push(Kept {
            channel,
            id,
            value,
            sent,
            numbers: numbers
                .into_iter()
                .map(|n| u64::try_from(n).unwrap_or(0))
                .collect(),
            again,
        });
    }
    Ok(all)
}

/// The kept message held at `number` in the channel of row `channel`.
pub fn kept_at(conn: &Connection, channel: i64, number: u64) -> Result<Option<Id>, CordeliaError> {
    conn.query_row(
        "SELECT id FROM shared_msg_kept_numbers WHERE channel = ?1 AND number = ?2",
        params![channel, i64::try_from(number).unwrap_or(i64::MAX)],
        |row| row.get(0),
    )
    .optional()
    .map_err(storage)
}

/// The kept message `id` waits to be sent again under the next number.
pub fn send_again(conn: &Connection, channel: i64, id: &Id) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE shared_msg_kept SET again = 1 WHERE channel = ?1 AND id = ?2",
        params![channel, &id[..]],
    )
    .map_err(storage)?;
    Ok(())
}

/// The kept message `id` goes: every relay took it, or it would need a
/// number past what a message may be sent under.
pub fn drop_kept(conn: &Connection, channel: i64, id: &Id) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM shared_msg_kept WHERE channel = ?1 AND id = ?2",
        params![channel, &id[..]],
    )
    .map_err(storage)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::schema::init_db(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO shared_channels (id, channel, card, name, came, state, first_held)
                 VALUES (1, zeroblob(32), zeroblob(65), 'review', 1, 1, 9);",
        )
        .unwrap();
        conn
    }

    /// A start is kept while the subscription stays in force, and goes with
    /// it (decision 2026-10-10 §4.1).
    #[test]
    fn a_start_is_kept_while_the_subscription_stays() {
        let conn = store();
        let item = ([1; 32], "notes".to_string());
        keep_subscribed(&conn, std::slice::from_ref(&item), 10).unwrap();
        keep_subscribed(&conn, std::slice::from_ref(&item), 20).unwrap();
        assert_eq!(subscribed(&conn).unwrap()[0].start, 10);
        keep_subscribed(&conn, &[], 30).unwrap();
        assert!(subscribed(&conn).unwrap().is_empty());
        keep_subscribed(&conn, &[item], 40).unwrap();
        assert_eq!(subscribed(&conn).unwrap()[0].start, 40);
    }

    /// The list holds the newest marks first, and a list merged from the
    /// device's later life goes below what it holds.
    #[test]
    fn marks_newest_first_and_merged_below() {
        let conn = store();
        mark(&conn, &[1; 16], 1).unwrap();
        mark(&conn, &[2; 16], 2).unwrap();
        mark(&conn, &[1; 16], 3).unwrap();
        assert_eq!(marks_to_list(&conn).unwrap(), vec![[1; 16], [2; 16]]);
        assert_eq!(merge_own_list(&conn, &[[3; 16], [1; 16]], 4).unwrap(), 1);
        assert_eq!(
            marks_to_list(&conn).unwrap(),
            vec![[1; 16], [2; 16], [3; 16]]
        );
        keep_within(&conn, &[], 3 + 30 * DAY_SECS).unwrap();
        assert_eq!(marks_to_list(&conn).unwrap(), vec![[1; 16], [3; 16]]);
    }

    /// The channel's hour counts first sends and sends again apart.
    #[test]
    fn the_channels_hour() {
        let conn = store();
        record_send(&conn, 1, 100, false).unwrap();
        record_send(&conn, 1, 200, true).unwrap();
        assert_eq!(sends_lately(&conn, 1, 300).unwrap(), (vec![100], vec![200]));
        assert_eq!(
            sends_lately(&conn, 1, 100 + HOUR_SECS).unwrap(),
            (vec![], vec![200])
        );
    }
}
