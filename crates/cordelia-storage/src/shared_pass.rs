//! What the shared pass keeps, and the take-outs begun and not ended
//! (decision 2026-10-10 §8.4, §6.3; §19, item 19): the tables of schema
//! step 23.
//!
//! - **The place at each relay** (`shared_relay_places`): for each shared
//!   channel the device holds, and each relay of its card, the relay's mark
//!   and the place in its holding to ask after next.
//! - **What each relay answered of a push** (`shared_relay_sent`): of each
//!   entry of the device's own in a shared channel, by its slot, the
//!   revision a relay answered and how. What waits at a relay is each entry
//!   of the device's own there that the relay has not answered at its
//!   revision or above.
//! - **The take-outs begun** (`shared_take_out_channels`,
//!   `shared_take_out_keys`): what a take-out takes out is written in its
//!   first step, so that the door stores nothing more of it and the reader
//!   shows nothing of it; each step after takes out one key's entries, and
//!   a take-out cut short by a stop goes on at the next start.
//!
//! Nothing here decides what is pulled, pushed or taken out: that is
//! decided where these are read (`cordelia_api::shared`).

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;

use crate::relay::Mark;

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

fn to_sql(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

// ── Places ───────────────────────────────────────────────────────────

/// The place the device keeps at `relay` in the shared channel of row
/// `id`: `None` where it keeps none, and asks from the start.
pub fn place(
    conn: &Connection,
    id: i64,
    relay: &[u8; 32],
) -> Result<Option<(Mark, u64)>, CordeliaError> {
    conn.query_row(
        "SELECT mark, next FROM shared_relay_places WHERE channel = ?1 AND relay = ?2",
        params![id, &relay[..]],
        |row| Ok((row.get::<_, Mark>(0)?, row.get::<_, i64>(1)?.max(0) as u64)),
    )
    .optional()
    .map_err(storage)
}

/// The device's place at `relay` in the channel of row `id` is now `next`
/// in the holding of `mark`.
pub fn keep_place(
    conn: &Connection,
    id: i64,
    relay: &[u8; 32],
    mark: &Mark,
    next: u64,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO shared_relay_places (channel, relay, mark, next) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(channel, relay) DO UPDATE SET mark = excluded.mark, next = excluded.next",
        params![id, &relay[..], &mark[..], to_sql(next)],
    )
    .map_err(storage)?;
    Ok(())
}

/// The relay `relay` holds nothing of the channel of row `id` that the
/// device knows of: its place there goes, and so does every answer it gave
/// a push, so that the channel is read from the start and everything of
/// the device's own there is sent again.
pub fn start_again(conn: &Connection, id: i64, relay: &[u8; 32]) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM shared_relay_places WHERE channel = ?1 AND relay = ?2",
        params![id, &relay[..]],
    )
    .map_err(storage)?;
    conn.execute(
        "DELETE FROM shared_relay_sent WHERE channel = ?1 AND relay = ?2",
        params![id, &relay[..]],
    )
    .map_err(storage)?;
    Ok(())
}

/// Every place the device keeps in the channel of row `id` goes, at every
/// relay: it is read again from its start (§6.3).
pub fn forget_places(conn: &Connection, id: i64) -> Result<(), CordeliaError> {
    conn.execute("DELETE FROM shared_relay_places WHERE channel = ?1", [id])
        .map_err(storage)?;
    Ok(())
}

/// Everything here of the channel of row `id` goes: its places, the
/// answers to its pushes, and a take-out of it or of its keys.
pub fn forget(conn: &Connection, id: i64) -> Result<(), CordeliaError> {
    for table in [
        "shared_relay_places",
        "shared_relay_sent",
        "shared_take_out_channels",
        "shared_take_out_keys",
    ] {
        conn.execute(&format!("DELETE FROM {table} WHERE channel = ?1"), [id])
            .map_err(storage)?;
    }
    Ok(())
}

// ── What each relay answered of a push ───────────────────────────────

/// How a relay answered a push of one entry of the device's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// It holds it: it stored it, or held it already.
    Holds,
    /// It holds a later one of the device's in that slot.
    HoldsLater,
    /// It holds another of the device's at that revision.
    HoldsAnother,
    /// It refused it as not signed as it must be: it is not sent there
    /// again.
    DoesNotCheck,
}

impl Answer {
    fn to_sql(self) -> i64 {
        match self {
            Answer::Holds => 1,
            Answer::HoldsLater => 2,
            Answer::HoldsAnother => 3,
            Answer::DoesNotCheck => 4,
        }
    }

    fn from_sql(answer: i64) -> rusqlite::Result<Self> {
        match answer {
            1 => Ok(Answer::Holds),
            2 => Ok(Answer::HoldsLater),
            3 => Ok(Answer::HoldsAnother),
            4 => Ok(Answer::DoesNotCheck),
            other => Err(rusqlite::Error::IntegralValueOutOfRange(0, other)),
        }
    }
}

/// `relay` answered a push of the entry of the device's own in `slot` of
/// the channel of row `id`, at `rev`, with `answer`. An answer at a lower
/// revision is replaced; one at a higher revision stays.
pub fn answered(
    conn: &Connection,
    id: i64,
    relay: &[u8; 32],
    slot: &[u8; 32],
    rev: u64,
    answer: Answer,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO shared_relay_sent (channel, relay, slot, rev, answer)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(channel, relay, slot) DO UPDATE SET
             rev = excluded.rev, answer = excluded.answer
         WHERE excluded.rev >= shared_relay_sent.rev",
        params![id, &relay[..], &slot[..], to_sql(rev), answer.to_sql()],
    )
    .map_err(storage)?;
    Ok(())
}

/// What `relay` last answered of the entry of the device's own in `slot`
/// of the channel of row `id`: its revision and how.
pub fn answer(
    conn: &Connection,
    id: i64,
    relay: &[u8; 32],
    slot: &[u8; 32],
) -> Result<Option<(u64, Answer)>, CordeliaError> {
    conn.query_row(
        "SELECT rev, answer FROM shared_relay_sent
         WHERE channel = ?1 AND relay = ?2 AND slot = ?3",
        params![id, &relay[..], &slot[..]],
        |row| {
            Ok((
                row.get::<_, i64>(0)?.max(0) as u64,
                Answer::from_sql(row.get(1)?)?,
            ))
        },
    )
    .optional()
    .map_err(storage)
}

// ── The take-outs begun ──────────────────────────────────────────────

/// Why every entry of a channel is taken out (decision 2026-10-10 §3.4,
/// §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelOut {
    /// It was dropped: every row of it goes at the end.
    Dropped,
    /// It was moved from: its index stays.
    Moved,
    /// No list carries a valid act on it: it is forgotten at the end.
    Forgotten,
}

impl ChannelOut {
    fn to_sql(self) -> i64 {
        match self {
            ChannelOut::Dropped => 1,
            ChannelOut::Moved => 2,
            ChannelOut::Forgotten => 3,
        }
    }

    fn from_sql(how: i64) -> rusqlite::Result<Self> {
        match how {
            1 => Ok(ChannelOut::Dropped),
            2 => Ok(ChannelOut::Moved),
            3 => Ok(ChannelOut::Forgotten),
            other => Err(rusqlite::Error::IntegralValueOutOfRange(0, other)),
        }
    }
}

/// A take-out of every entry of the channel of row `id` is begun, as
/// `how`. One begun already keeps its kind, but a channel to be forgotten
/// is forgotten.
pub fn begin_channel(conn: &Connection, id: i64, how: ChannelOut) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO shared_take_out_channels (channel, how) VALUES (?1, ?2)
         ON CONFLICT(channel) DO UPDATE SET how = MAX(how, excluded.how)",
        params![id, how.to_sql()],
    )
    .map_err(storage)?;
    Ok(())
}

/// How every entry of the channel of row `id` is being taken out, where a
/// take-out of it is begun and not ended.
pub fn channel_out(conn: &Connection, id: i64) -> Result<Option<ChannelOut>, CordeliaError> {
    conn.query_row(
        "SELECT how FROM shared_take_out_channels WHERE channel = ?1",
        [id],
        |row| ChannelOut::from_sql(row.get(0)?),
    )
    .optional()
    .map_err(storage)
}

/// The take-out of the channel of row `id` has ended.
pub fn channel_ended(conn: &Connection, id: i64) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM shared_take_out_channels WHERE channel = ?1",
        [id],
    )
    .map_err(storage)?;
    Ok(())
}

/// The first channel whose take-out is begun and not ended, by its row,
/// with how.
pub fn next_channel_out(conn: &Connection) -> Result<Option<(i64, ChannelOut)>, CordeliaError> {
    conn.query_row(
        "SELECT channel, how FROM shared_take_out_channels ORDER BY channel LIMIT 1",
        [],
        |row| Ok((row.get(0)?, ChannelOut::from_sql(row.get(1)?)?)),
    )
    .optional()
    .map_err(storage)
}

/// A take-out of the entries of `key` in the channel of row `id` is begun:
/// `as_refused` notes their bytes as refused when it is made. One begun
/// already is noted as refused where either says so.
pub fn begin_key(
    conn: &Connection,
    id: i64,
    key: &[u8; 32],
    as_refused: bool,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO shared_take_out_keys (channel, key, as_refused) VALUES (?1, ?2, ?3)
         ON CONFLICT(channel, key) DO UPDATE SET as_refused = MAX(as_refused, excluded.as_refused)",
        params![id, &key[..], as_refused],
    )
    .map_err(storage)?;
    Ok(())
}

/// A take-out is begun of the entries of every key of the channel of row
/// `id` that the person does not know, that stores an entry, and of which
/// this device first held its last entry there at or before `before`: the
/// quiet keys (decision 2026-10-10 §6.3), chosen by first holding alone, in
/// one statement. A key whose take-out is begun already is left as it is.
/// Returns how many were begun.
pub fn begin_quiet_keys(conn: &Connection, id: i64, before: i64) -> Result<usize, CordeliaError> {
    conn.execute(
        "INSERT INTO shared_take_out_keys (channel, key, as_refused)
         SELECT channel, key, 0 FROM shared_keys
         WHERE channel = ?1 AND known = 0 AND bytes_stored > 0
           AND last_held IS NOT NULL AND last_held <= ?2
         ORDER BY held_order
         ON CONFLICT(channel, key) DO NOTHING",
        params![id, before],
    )
    .map_err(storage)
}

/// Whether a take-out of the entries of `key` in the channel of row `id` is
/// begun and not ended: the door stores nothing more of it, and the reader
/// shows nothing of it.
pub fn key_going(conn: &Connection, id: i64, key: &[u8; 32]) -> Result<bool, CordeliaError> {
    conn.query_row(
        "SELECT 1 FROM shared_take_out_keys WHERE channel = ?1 AND key = ?2",
        params![id, &key[..]],
        |_| Ok(()),
    )
    .optional()
    .map(|found| found.is_some())
    .map_err(storage)
}

/// The first key whose take-out is begun and not ended, in the order they
/// were begun, with its channel's row and whether it is as refused.
pub fn next_key_out(conn: &Connection) -> Result<Option<(i64, [u8; 32], bool)>, CordeliaError> {
    conn.query_row(
        "SELECT channel, key, as_refused FROM shared_take_out_keys ORDER BY rowid LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .optional()
    .map_err(storage)
}

/// The take-out of the entries of `key` in the channel of row `id` has
/// ended.
pub fn key_ended(conn: &Connection, id: i64, key: &[u8; 32]) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM shared_take_out_keys WHERE channel = ?1 AND key = ?2",
        params![id, &key[..]],
    )
    .map_err(storage)?;
    Ok(())
}

/// The bytes, as a relay counts them, that the take-outs of keys begun in
/// the channel of row `id` will take out of its room: what the keys going
/// that the person does not know store.
pub fn going_from_room(conn: &Connection, id: i64) -> Result<u64, CordeliaError> {
    conn.query_row(
        "SELECT COALESCE(SUM(k.bytes_stored), 0) FROM shared_take_out_keys o
         JOIN shared_keys k ON k.channel = o.channel AND k.key = o.key
         WHERE o.channel = ?1 AND k.known = 0",
        [id],
        |row| row.get::<_, i64>(0),
    )
    .map(|bytes| bytes.max(0) as u64)
    .map_err(storage)
}

/// Whether any take-out is begun and not ended.
pub fn any_going(conn: &Connection) -> Result<bool, CordeliaError> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM shared_take_out_channels)
             OR EXISTS (SELECT 1 FROM shared_take_out_keys)",
        [],
        |row| row.get(0),
    )
    .map_err(storage)
}
