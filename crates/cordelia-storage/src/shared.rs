//! What a device keeps of the shared channels it holds (decision 2026-10-10
//! §2.2, §2.3, §2.4, §6.3): the tables of schema step 22.
//!
//! - **The table of shared channels** (`shared_channels`): each channel by
//!   its ID, with its card, the name the person files it under, how it
//!   came, and whether it is held, dropped, moved from, or filed by no act
//!   in force on this device ([`State`]). A channel ID of the person's own
//!   is in no such table: those are derived each time from the secret the
//!   device holds.
//! - **The table of keys of each channel** (`shared_keys`): a row for each
//!   key that has stored an entry there or been refused one for room, with
//!   when it was first held or first refused, when it last wrote, the bytes
//!   stored and refused, the revisions a row keeps of a key that was let
//!   go, and whether the key was one the person knows when the row was last
//!   kept. The bytes stored of the keys the person does not know are kept
//!   summed on the channel's row, as the room ([`room`]).
//! - **The entries stored and not opened** (`shared_unopened`): of a key
//!   beyond the 64 that the device shows, each slot whose entry the store
//!   holds and the reader has not read.
//! - **The keys labelled when the device last kept its channels**
//!   (`shared_labelled`): a key labelled since starts a read again.
//! - **The index of shared messages** (`shared_index`, `shared_numbers`,
//!   `shared_first_held`, `shared_signers`, `shared_places`), in tables of
//!   the shape of step 19's, keyed by the shared channel's row and not by a
//!   generation of the messages channel. A message is known by its channel
//!   and its ID (§4.2). **A row that goes is overwritten first,** as step
//!   19's are (decision 2026-10-09 §7.1, [`drop_row`]).
//!
//! Nothing here decides who is known, who is shown or what is refused:
//! that is decided where these are read (`cordelia_api::shared`). Every
//! time here is the node's, passed in.

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;
use cordelia_core::protocol::{
    AGENT_MESSAGE_ID_BYTES, AGENT_MESSAGE_KEPT_DAYS, AGENT_MESSAGE_RING,
    AGENT_MESSAGE_SUBJECT_CHARS,
};
use cordelia_crypto::shared::SharedMessage;

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

/// An hour, and a day, in seconds.
const HOUR_SECS: i64 = 60 * 60;
const DAY_SECS: i64 = 24 * HOUR_SECS;

/// The ring, as a count of numbers: the live numbers of a signer, the
/// places a reader gives one signer in an hour, and the places of every
/// key the person has not labelled together (§2.4).
const RING: i64 = AGENT_MESSAGE_RING as i64;

/// A message's ID.
pub type Id = [u8; AGENT_MESSAGE_ID_BYTES];

// ── The table of shared channels ─────────────────────────────────────

/// What a channel of the table is on this device (decision 2026-10-10
/// §2.3, rule 1; §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Filed by an act in force: the door takes its entries.
    Held,
    /// Dropped: every entry and every row of it went, and its seed is kept
    /// until the drop is freed.
    Dropped,
    /// Moved from to a channel made anew: its entries went, and the index
    /// rows of what it showed stay until each expires.
    Moved,
    /// Held by this device's lists, by no act in force: past a bound, or by
    /// a maker in no list. Its entries stay, and the door takes none.
    NotInForce,
}

impl State {
    fn to_sql(self) -> i64 {
        match self {
            State::Held => 1,
            State::Dropped => 2,
            State::Moved => 3,
            State::NotInForce => 4,
        }
    }

    fn from_sql(state: i64) -> rusqlite::Result<Self> {
        match state {
            1 => Ok(State::Held),
            2 => Ok(State::Dropped),
            3 => Ok(State::Moved),
            4 => Ok(State::NotInForce),
            other => Err(rusqlite::Error::IntegralValueOutOfRange(0, other)),
        }
    }
}

/// How a channel came to be held, as its filing says: made here, taken
/// from a key's share, or moved to from a channel made anew.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Came {
    Made,
    Taken([u8; 32]),
    Moved([u8; 32]),
}

impl Came {
    fn to_sql(self) -> (i64, Option<[u8; 32]>) {
        match self {
            Came::Made => (1, None),
            Came::Taken(key) => (2, Some(key)),
            Came::Moved(channel) => (3, Some(channel)),
        }
    }

    fn from_sql(came: i64, from: Option<[u8; 32]>) -> rusqlite::Result<Self> {
        match (came, from) {
            (1, None) => Ok(Came::Made),
            (2, Some(key)) => Ok(Came::Taken(key)),
            (3, Some(channel)) => Ok(Came::Moved(channel)),
            (other, _) => Err(rusqlite::Error::IntegralValueOutOfRange(0, other)),
        }
    }
}

/// A row of the table of shared channels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channel {
    /// The row's own number, which the other tables are keyed by.
    pub id: i64,
    pub channel: [u8; 32],
    /// The card, as a filing writes it: the seed and the relays.
    pub card: Vec<u8>,
    pub name: String,
    pub came: Came,
    pub state: State,
    /// When this device first held the channel.
    pub first_held: i64,
    /// When it was dropped or moved from, where it was.
    pub left_at: Option<i64>,
    /// The bytes stored of the keys the person does not know, as a relay
    /// counts them, as of the last time each key's row was kept.
    pub room: u64,
    /// How many rows of keys that store nothing the table let go (§6.3).
    pub let_go: u64,
    /// When a read again was asked and has not begun.
    pub read_asked: Option<i64>,
    /// When the last read again began.
    pub read_begun: Option<i64>,
}

const CHANNEL_COLUMNS: &str = "id, channel, card, name, came, came_from, state, first_held,
    left_at, room, let_go, read_asked, read_begun";

fn channel_from_row(row: &rusqlite::Row) -> rusqlite::Result<Channel> {
    Ok(Channel {
        id: row.get(0)?,
        channel: row.get(1)?,
        card: row.get(2)?,
        name: row.get(3)?,
        came: Came::from_sql(row.get(4)?, row.get(5)?)?,
        state: State::from_sql(row.get(6)?)?,
        first_held: row.get(7)?,
        left_at: row.get(8)?,
        room: from_sql(row.get(9)?),
        let_go: from_sql(row.get(10)?),
        read_asked: row.get(11)?,
        read_begun: row.get(12)?,
    })
}

/// The device holds the channel `channel` of `card`, filed under `name`,
/// as `came`, at `now`: a row made, or one it had made held again, with
/// the name and card of the filing. When it first held it stays.
pub fn hold(
    conn: &Connection,
    channel: &[u8; 32],
    card: &[u8],
    name: &str,
    came: Came,
    now: i64,
) -> Result<i64, CordeliaError> {
    let (came, from) = came.to_sql();
    conn.execute(
        "INSERT INTO shared_channels (channel, card, name, came, came_from, state, first_held)
         VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)
         ON CONFLICT(channel) DO UPDATE SET
             card = excluded.card, name = excluded.name, came = excluded.came,
             came_from = excluded.came_from, state = 1, left_at = NULL",
        params![
            &channel[..],
            card,
            name,
            came,
            from.as_ref().map(|from| &from[..]),
            now
        ],
    )
    .map_err(storage)?;
    conn.query_row(
        "SELECT id FROM shared_channels WHERE channel = ?1",
        [&channel[..]],
        |row| row.get(0),
    )
    .map_err(storage)
}

/// The channel of row `id` is now in `state`, at `now`. Dropped or moved
/// from, it is noted when it left, once.
pub fn set_state(conn: &Connection, id: i64, state: State, now: i64) -> Result<(), CordeliaError> {
    let left = matches!(state, State::Dropped | State::Moved).then_some(now);
    conn.execute(
        "UPDATE shared_channels SET state = ?2,
             left_at = CASE WHEN ?3 IS NULL THEN NULL ELSE COALESCE(left_at, ?3) END
         WHERE id = ?1",
        params![id, state.to_sql(), left],
    )
    .map_err(storage)?;
    Ok(())
}

/// The row of the channel `channel`, where the table has one.
pub fn channel(conn: &Connection, channel: &[u8; 32]) -> Result<Option<Channel>, CordeliaError> {
    conn.query_row(
        &format!("SELECT {CHANNEL_COLUMNS} FROM shared_channels WHERE channel = ?1"),
        [&channel[..]],
        channel_from_row,
    )
    .optional()
    .map_err(storage)
}

/// The row `id` of the table, where it has one.
pub fn channel_of_row(conn: &Connection, id: i64) -> Result<Option<Channel>, CordeliaError> {
    conn.query_row(
        &format!("SELECT {CHANNEL_COLUMNS} FROM shared_channels WHERE id = ?1"),
        [id],
        channel_from_row,
    )
    .optional()
    .map_err(storage)
}

/// Every row of the table, in the order they were made.
pub fn channels(conn: &Connection) -> Result<Vec<Channel>, CordeliaError> {
    let rows = conn
        .prepare(&format!(
            "SELECT {CHANNEL_COLUMNS} FROM shared_channels ORDER BY id"
        ))
        .map_err(storage)?
        .query_map([], channel_from_row)
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    Ok(rows)
}

/// A read again of the channel of row `id` is asked at `now`: it begins
/// when the pass next reads the channel, at most once a day ([`read_again_due`]).
/// One asked already keeps its time.
pub fn ask_read_again(conn: &Connection, id: i64, now: i64) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE shared_channels SET read_asked = COALESCE(read_asked, ?2) WHERE id = ?1",
        params![id, now],
    )
    .map_err(storage)?;
    Ok(())
}

/// The channels held whose read again is asked and may begin at `now`:
/// none began one in the `again_secs` before (decision 2026-10-10 §6.3).
pub fn read_again_due(
    conn: &Connection,
    now: i64,
    again_secs: i64,
) -> Result<Vec<Channel>, CordeliaError> {
    let rows = conn
        .prepare(&format!(
            "SELECT {CHANNEL_COLUMNS} FROM shared_channels
             WHERE state = 1 AND read_asked IS NOT NULL
               AND (read_begun IS NULL OR ?1 - read_begun >= ?2)
             ORDER BY id"
        ))
        .map_err(storage)?
        .query_map(params![now, again_secs], channel_from_row)
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    Ok(rows)
}

/// The read again of the channel of row `id` begins at `now`.
pub fn read_again_begun(conn: &Connection, id: i64, now: i64) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE shared_channels SET read_asked = NULL, read_begun = ?2 WHERE id = ?1",
        params![id, now],
    )
    .map_err(storage)?;
    Ok(())
}

/// Every row of the channel of row `id` but its own goes: its table of
/// keys, what waits to be opened, and, unless `index_stays`, its index
/// and the reader's rows (decision 2026-10-10 §6.3). A move keeps the
/// index; a drop keeps nothing.
pub fn drop_rows(conn: &Connection, id: i64, index_stays: bool) -> Result<(), CordeliaError> {
    for table in ["shared_keys", "shared_unopened"] {
        conn.execute(&format!("DELETE FROM {table} WHERE channel = ?1"), [id])
            .map_err(storage)?;
    }
    conn.execute("UPDATE shared_channels SET room = 0 WHERE id = ?1", [id])
        .map_err(storage)?;
    if !index_stays {
        drop_index(conn, id)?;
    }
    Ok(())
}

/// The index of the channel of row `id` goes, each row overwritten first,
/// and the reader's rows with it.
pub fn drop_index(conn: &Connection, id: i64) -> Result<(), CordeliaError> {
    for message in index_ids(conn, id, None)? {
        drop_row(conn, id, &message)?;
    }
    for table in ["shared_first_held", "shared_signers", "shared_places"] {
        conn.execute(&format!("DELETE FROM {table} WHERE channel = ?1"), [id])
            .map_err(storage)?;
    }
    Ok(())
}

/// The channel of row `id` is forgotten, its seed with it: every row of
/// it goes (§3.4: when its drop is freed).
pub fn forget(conn: &Connection, id: i64) -> Result<(), CordeliaError> {
    drop_rows(conn, id, false)?;
    crate::shared_pass::forget(conn, id)?;
    conn.execute("DELETE FROM shared_channels WHERE id = ?1", [id])
        .map_err(storage)?;
    Ok(())
}

/// Everything here goes: a device that leaves its person forgets what it
/// held of the person's shared channels.
pub fn forget_all(conn: &Connection) -> Result<(), CordeliaError> {
    for channel in channels(conn)? {
        forget(conn, channel.id)?;
    }
    conn.execute("DELETE FROM shared_labelled", [])
        .map_err(storage)?;
    Ok(())
}

// ── The table of keys ────────────────────────────────────────────────

/// A key's row in a channel's table of keys (decision 2026-10-10 §6.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Key {
    pub key: [u8; 32],
    /// Whether the key was one the person knows when its row was last
    /// kept: its bytes stored are then not in the room.
    pub known: bool,
    /// When it stopped being known, where it did and has not been since.
    pub unknown_since: Option<i64>,
    /// Its place in the order this device first held an entry of each key
    /// in the channel, where it has held one.
    pub held_order: Option<i64>,
    pub first_held: Option<i64>,
    /// When this device last first held an entry of the key there.
    pub last_held: Option<i64>,
    pub first_refused: Option<i64>,
    pub last_refused: Option<i64>,
    /// Its place in the order of the keys' last writes and refusals.
    pub last_seq: i64,
    /// The bytes of its entries the store holds, as a relay counts them.
    pub bytes_stored: u64,
    /// The bytes refused for room, or taken out when it stopped being
    /// known, as a relay counts them.
    pub bytes_refused: u64,
    /// The highest revision it held in its ring when it was let go.
    pub kept_message_rev: Option<u64>,
    /// The revision of its anew record that it held when it was let go.
    pub kept_anew_rev: Option<u64>,
}

const KEY_COLUMNS: &str = "key, known, unknown_since, held_order, first_held, last_held,
    first_refused, last_refused, last_seq, bytes_stored, bytes_refused, kept_message_rev,
    kept_anew_rev";

fn key_from_row(row: &rusqlite::Row) -> rusqlite::Result<Key> {
    Ok(Key {
        key: row.get(0)?,
        known: row.get(1)?,
        unknown_since: row.get(2)?,
        held_order: row.get(3)?,
        first_held: row.get(4)?,
        last_held: row.get(5)?,
        first_refused: row.get(6)?,
        last_refused: row.get(7)?,
        last_seq: row.get(8)?,
        bytes_stored: from_sql(row.get(9)?),
        bytes_refused: from_sql(row.get(10)?),
        kept_message_rev: row.get::<_, Option<i64>>(11)?.map(from_sql),
        kept_anew_rev: row.get::<_, Option<i64>>(12)?.map(from_sql),
    })
}

/// The row of `key` in the channel of row `id`, where it has one.
pub fn key(conn: &Connection, id: i64, key: &[u8; 32]) -> Result<Option<Key>, CordeliaError> {
    conn.query_row(
        &format!("SELECT {KEY_COLUMNS} FROM shared_keys WHERE channel = ?1 AND key = ?2"),
        params![id, &key[..]],
        key_from_row,
    )
    .optional()
    .map_err(storage)
}

/// Every row of the channel of row `id`'s table of keys: those first held
/// in the order they were, and then those only refused, in the order of
/// their refusals.
pub fn keys(conn: &Connection, id: i64) -> Result<Vec<Key>, CordeliaError> {
    let rows = conn
        .prepare(&format!(
            "SELECT {KEY_COLUMNS} FROM shared_keys WHERE channel = ?1
             ORDER BY held_order IS NULL, held_order, last_seq"
        ))
        .map_err(storage)?
        .query_map([id], key_from_row)
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    Ok(rows)
}

/// The keys first held in the channel of row `id`, in the order this
/// device first held an entry of each, at most `limit` of them.
pub fn keys_held_in_order(
    conn: &Connection,
    id: i64,
    limit: usize,
) -> Result<Vec<[u8; 32]>, CordeliaError> {
    let rows = conn
        .prepare(
            "SELECT key FROM shared_keys
             WHERE channel = ?1 AND held_order IS NOT NULL AND bytes_stored > 0
               AND key NOT IN (SELECT key FROM shared_take_out_keys WHERE channel = ?1)
             ORDER BY held_order LIMIT ?2",
        )
        .map_err(storage)?
        .query_map(params![id, to_sql(limit as u64)], |row| row.get(0))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    Ok(rows)
}

/// The next place in the order of last writes and refusals.
fn next_seq(conn: &Connection, id: i64) -> Result<i64, CordeliaError> {
    conn.query_row(
        "SELECT COALESCE(MAX(last_seq), 0) + 1 FROM shared_keys WHERE channel = ?1",
        [id],
        |row| row.get(0),
    )
    .map_err(storage)
}

/// The room of the channel of row `id`: the bytes stored of the keys the
/// person does not know, as a relay counts them (decision 2026-10-10
/// §6.3).
pub fn room(conn: &Connection, id: i64) -> Result<u64, CordeliaError> {
    conn.query_row(
        "SELECT room FROM shared_channels WHERE id = ?1",
        [id],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map(|room| room.map_or(0, from_sql))
    .map_err(storage)
}

fn add_to_room(conn: &Connection, id: i64, bytes: i64) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE shared_channels SET room = MAX(room + ?2, 0) WHERE id = ?1",
        params![id, bytes],
    )
    .map_err(storage)?;
    Ok(())
}

/// The store kept an entry of `key` in the channel of row `id` at `now`,
/// which changes the bytes it holds of the key by `more` (an entry in a
/// new slot, or one written again in a slot it held). `known` says
/// whether the key is one the person knows, for a row made now. The key
/// is first held now where it never was.
pub fn stored(
    conn: &Connection,
    id: i64,
    key: &[u8; 32],
    known: bool,
    more: i64,
    now: i64,
) -> Result<(), CordeliaError> {
    let seq = next_seq(conn, id)?;
    let order: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(held_order), 0) + 1 FROM shared_keys WHERE channel = ?1",
            [id],
            |row| row.get(0),
        )
        .map_err(storage)?;
    conn.execute(
        "INSERT INTO shared_keys (channel, key, known, held_order, first_held, last_held,
                                  last_seq, bytes_stored)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, MAX(?7, 0))
         ON CONFLICT(channel, key) DO UPDATE SET
             held_order = COALESCE(held_order, excluded.held_order),
             first_held = COALESCE(first_held, excluded.first_held),
             last_held = excluded.last_held, last_seq = excluded.last_seq,
             bytes_stored = MAX(bytes_stored + ?7, 0)",
        params![id, &key[..], known, order, now, seq, more],
    )
    .map_err(storage)?;
    if !key_known(conn, id, key)? {
        add_to_room(conn, id, more)?;
    }
    Ok(())
}

fn key_known(conn: &Connection, id: i64, key: &[u8; 32]) -> Result<bool, CordeliaError> {
    conn.query_row(
        "SELECT known FROM shared_keys WHERE channel = ?1 AND key = ?2",
        params![id, &key[..]],
        |row| row.get(0),
    )
    .optional()
    .map(|known| known.unwrap_or(false))
    .map_err(storage)
}

/// The door refused an entry of `key` in the channel of row `id` for room
/// at `now`, of `bytes` as a relay counts it: its row notes it, made now
/// where there was none.
pub fn refused(
    conn: &Connection,
    id: i64,
    key: &[u8; 32],
    bytes: u64,
    now: i64,
) -> Result<(), CordeliaError> {
    let seq = next_seq(conn, id)?;
    conn.execute(
        "INSERT INTO shared_keys (channel, key, known, first_refused, last_refused, last_seq,
                                  bytes_refused)
         VALUES (?1, ?2, 0, ?3, ?3, ?4, ?5)
         ON CONFLICT(channel, key) DO UPDATE SET
             first_refused = COALESCE(first_refused, excluded.first_refused),
             last_refused = excluded.last_refused, last_seq = excluded.last_seq,
             bytes_refused = bytes_refused + excluded.bytes_refused",
        params![id, &key[..], now, seq, to_sql(bytes)],
    )
    .map_err(storage)?;
    Ok(())
}

/// The key `key` is now known, or not, in the channel of row `id`, at
/// `now`: its bytes stored leave the room, or join it. One that stops
/// being known is noted when. The revisions a row kept stay: the door
/// refuses nothing of a key the person knows for room, and refuses again
/// what was taken out once it is not known.
pub fn set_known(
    conn: &Connection,
    id: i64,
    key: &[u8; 32],
    known: bool,
    now: i64,
) -> Result<(), CordeliaError> {
    let Some(row) = self::key(conn, id, key)? else {
        return Ok(());
    };
    if row.known == known {
        return Ok(());
    }
    if known {
        conn.execute(
            "UPDATE shared_keys SET known = 1, unknown_since = NULL
             WHERE channel = ?1 AND key = ?2",
            params![id, &key[..]],
        )
        .map_err(storage)?;
        add_to_room(conn, id, -to_sql(row.bytes_stored))?;
    } else {
        conn.execute(
            "UPDATE shared_keys SET known = 0, unknown_since = ?3 WHERE channel = ?1 AND key = ?2",
            params![id, &key[..], now],
        )
        .map_err(storage)?;
        add_to_room(conn, id, to_sql(row.bytes_stored))?;
    }
    Ok(())
}

/// The entries of `key` in the channel `channel` (of row `id`) are taken
/// out of the store at `now` (decision 2026-10-10 §6.3), with its index
/// rows and what waited to be opened. Its row keeps the highest revision
/// it held of its ring, and of its anew record in `anew_slot`; and, where
/// `as_refused`, it notes their bytes as refused. Returns the bytes taken
/// out, as a relay counts them.
pub fn take_out(
    conn: &Connection,
    id: i64,
    channel: &[u8; 32],
    key: &[u8; 32],
    anew_slot: &[u8; 32],
    as_refused: bool,
    now: i64,
) -> Result<u64, CordeliaError> {
    let Some(row) = self::key(conn, id, key)? else {
        return Ok(0);
    };
    let highest = |anew: bool| -> Result<Option<i64>, CordeliaError> {
        conn.query_row(
            &format!(
                "SELECT MAX(rev) FROM entries WHERE channel_id = ?1 AND author = ?2
                 AND slot {} ?3",
                if anew { "=" } else { "<>" }
            ),
            params![&channel[..], &key[..], &anew_slot[..]],
            |row| row.get(0),
        )
        .map_err(storage)
    };
    let (message_rev, anew_rev) = (highest(false)?, highest(true)?);
    conn.execute(
        "DELETE FROM entries WHERE channel_id = ?1 AND author = ?2",
        params![&channel[..], &key[..]],
    )
    .map_err(storage)?;
    conn.execute(
        "DELETE FROM shared_unopened WHERE channel = ?1 AND key = ?2",
        params![id, &key[..]],
    )
    .map_err(storage)?;
    take_out_index(conn, id, key)?;
    let bytes = row.bytes_stored;
    let seq = next_seq(conn, id)?;
    conn.execute(
        "UPDATE shared_keys SET bytes_stored = 0,
             kept_message_rev = MAX(COALESCE(kept_message_rev, 0), COALESCE(?3, 0)),
             kept_anew_rev = MAX(COALESCE(kept_anew_rev, 0), COALESCE(?4, 0)),
             bytes_refused = bytes_refused + CASE WHEN ?5 THEN ?6 ELSE 0 END,
             first_refused = CASE WHEN ?5 THEN COALESCE(first_refused, ?7) ELSE first_refused END,
             last_refused = CASE WHEN ?5 THEN ?7 ELSE last_refused END,
             last_seq = CASE WHEN ?5 THEN ?8 ELSE last_seq END
         WHERE channel = ?1 AND key = ?2",
        params![
            id,
            &key[..],
            message_rev,
            anew_rev,
            as_refused,
            to_sql(bytes),
            now,
            seq
        ],
    )
    .map_err(storage)?;
    if !row.known {
        add_to_room(conn, id, -to_sql(bytes))?;
    }
    Ok(bytes)
}

/// Whether any key of the channel of row `id` has bytes refused for room.
pub fn any_refused(conn: &Connection, id: i64) -> Result<bool, CordeliaError> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM shared_keys WHERE channel = ?1 AND bytes_refused > 0)",
        [id],
        |row| row.get(0),
    )
    .map_err(storage)
}

/// What one step of a take-out of every entry of a channel did (decision
/// 2026-10-10 §6.3, "taken out in steps").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelStep {
    /// It took out entries of this key, at most `most`, and what waited to
    /// be opened of it, and, where the index goes too, its index rows.
    Key([u8; 32]),
    /// The store held no entry of the channel: it took out the index rows
    /// of this signer.
    Signer([u8; 32]),
    /// Nothing of the channel's entries, and where the index goes, of its
    /// index, is left.
    Done,
}

/// One step of a take-out of every entry of the channel `channel` (of row
/// `id`): one key's entries, at most `most` of them, with what waits to be
/// opened of it and, where `index_too`, its index rows, each overwritten
/// first. Once no entry is left, one signer's index rows a step, where
/// `index_too`. In the caller's write.
pub fn take_out_channel_step(
    conn: &Connection,
    id: i64,
    channel: &[u8; 32],
    index_too: bool,
    most: usize,
) -> Result<ChannelStep, CordeliaError> {
    let author: Option<[u8; 32]> = conn
        .query_row(
            "SELECT author FROM entries WHERE channel_id = ?1 LIMIT 1",
            [&channel[..]],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    if let Some(author) = author {
        conn.execute(
            "DELETE FROM entries WHERE rowid IN (
                 SELECT rowid FROM entries WHERE channel_id = ?1 AND author = ?2 LIMIT ?3)",
            params![&channel[..], &author[..], to_sql(most as u64)],
        )
        .map_err(storage)?;
        conn.execute(
            "DELETE FROM shared_unopened WHERE channel = ?1 AND key = ?2",
            params![id, &author[..]],
        )
        .map_err(storage)?;
        if index_too {
            for message in index_ids(conn, id, Some(&author))? {
                drop_row(conn, id, &message)?;
            }
        }
        return Ok(ChannelStep::Key(author));
    }
    if index_too {
        let signer: Option<[u8; 32]> = conn
            .query_row(
                "SELECT signer FROM shared_index WHERE channel = ?1 LIMIT 1",
                [id],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        if let Some(signer) = signer {
            for message in index_ids(conn, id, Some(&signer))? {
                drop_row(conn, id, &message)?;
            }
            return Ok(ChannelStep::Signer(signer));
        }
    }
    Ok(ChannelStep::Done)
}

/// The channel of row `id` keeps the rows of at most `kept` keys that
/// store nothing (decision 2026-10-10 §6.3): past that, the rows whose
/// keys last wrote or were last refused least lately go, and are counted
/// as let go. Every row of a key that stores an entry stays. Returns how
/// many went.
pub fn keep_rows_within(conn: &Connection, id: i64, kept: usize) -> Result<usize, CordeliaError> {
    let gone = conn
        .execute(
            "DELETE FROM shared_keys WHERE channel = ?1 AND bytes_stored = 0 AND key IN (
                 SELECT key FROM shared_keys WHERE channel = ?1 AND bytes_stored = 0
                 ORDER BY last_seq DESC LIMIT -1 OFFSET ?2)",
            params![id, to_sql(kept as u64)],
        )
        .map_err(storage)?;
    if gone > 0 {
        conn.execute(
            "UPDATE shared_channels SET let_go = let_go + ?2 WHERE id = ?1",
            params![id, to_sql(gone as u64)],
        )
        .map_err(storage)?;
    }
    Ok(gone)
}

// ── What waits to be opened ──────────────────────────────────────────

/// The store holds the entry of `key` in `slot` of the channel of row
/// `id`, and the reader did not read it: its key is beyond the 64 that
/// the device shows (decision 2026-10-10 §2.3, rule 6).
pub fn unopened(
    conn: &Connection,
    id: i64,
    key: &[u8; 32],
    slot: &[u8; 32],
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO shared_unopened (channel, key, slot) VALUES (?1, ?2, ?3)
         ON CONFLICT DO NOTHING",
        params![id, &key[..], &slot[..]],
    )
    .map_err(storage)?;
    Ok(())
}

/// The slots of `key` in the channel of row `id` whose entries wait to be
/// opened, and they wait no longer: the caller opens them.
pub fn to_open(conn: &Connection, id: i64, key: &[u8; 32]) -> Result<Vec<[u8; 32]>, CordeliaError> {
    let slots = conn
        .prepare("SELECT slot FROM shared_unopened WHERE channel = ?1 AND key = ?2")
        .map_err(storage)?
        .query_map(params![id, &key[..]], |row| row.get(0))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    conn.execute(
        "DELETE FROM shared_unopened WHERE channel = ?1 AND key = ?2",
        params![id, &key[..]],
    )
    .map_err(storage)?;
    Ok(slots)
}

/// The keys of the channel of row `id` with entries that wait to be
/// opened, and how many each: what `log` counts as from a key beyond the
/// 64 this device shows.
pub fn waiting_to_open(conn: &Connection, id: i64) -> Result<Vec<([u8; 32], u64)>, CordeliaError> {
    let rows: Vec<([u8; 32], i64)> = conn
        .prepare(
            "SELECT key, COUNT(*) FROM shared_unopened WHERE channel = ?1 GROUP BY key ORDER BY key",
        )
        .map_err(storage)?
        .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    Ok(rows
        .into_iter()
        .map(|(key, n)| (key, from_sql(n)))
        .collect())
}

// ── The keys labelled ────────────────────────────────────────────────

/// The keys labelled when the device last kept its channels.
pub fn labelled(conn: &Connection) -> Result<Vec<[u8; 32]>, CordeliaError> {
    let keys = conn
        .prepare("SELECT key FROM shared_labelled ORDER BY key")
        .map_err(storage)?
        .query_map([], |row| row.get(0))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    Ok(keys)
}

/// The keys labelled are `keys`, from now. Where they are already,
/// nothing is written: a device works its lists out at every whole pass.
pub fn set_labelled(conn: &Connection, keys: &[[u8; 32]]) -> Result<(), CordeliaError> {
    let mut wanted = keys.to_vec();
    wanted.sort();
    wanted.dedup();
    if labelled(conn)? == wanted {
        return Ok(());
    }
    conn.execute("DELETE FROM shared_labelled", [])
        .map_err(storage)?;
    for key in keys {
        conn.execute(
            "INSERT INTO shared_labelled (key) VALUES (?1) ON CONFLICT DO NOTHING",
            [&key[..]],
        )
        .map_err(storage)?;
    }
    Ok(())
}

// ── The index of shared messages ─────────────────────────────────────

/// What a reader keeps of one signer in one shared channel: as step 19
/// keeps it of a signer in a generation (decision 2026-10-09 §2.5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Signer {
    /// H: the highest number held, of a message or a clearing.
    pub highest: u64,
    /// The numbers that left the live numbers before their message had a
    /// place, and the entries taken at a number that was not live.
    pub overwritten: u64,
    /// The entries of that signer that were no message.
    pub not_messages: u64,
    /// The number from which what is overwritten is counted.
    pub counted_from: Option<u64>,
}

/// What the device keeps of `signer` in the channel of row `id`.
pub fn signer(
    conn: &Connection,
    id: i64,
    signer: &[u8; 32],
) -> Result<Option<Signer>, CordeliaError> {
    conn.query_row(
        "SELECT highest, overwritten, not_messages, counted_from FROM shared_signers
         WHERE channel = ?1 AND signer = ?2",
        params![id, &signer[..]],
        |row| {
            Ok(Signer {
                highest: from_sql(row.get(0)?),
                overwritten: from_sql(row.get(1)?),
                not_messages: from_sql(row.get(2)?),
                counted_from: row.get::<_, Option<i64>>(3)?.map(from_sql),
            })
        },
    )
    .optional()
    .map_err(storage)
}

fn keep_signer(
    conn: &Connection,
    id: i64,
    of: &[u8; 32],
    kept: &Signer,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO shared_signers (channel, signer, highest, overwritten, not_messages,
                                     counted_from)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(channel, signer) DO UPDATE SET
             highest = excluded.highest, overwritten = excluded.overwritten,
             not_messages = excluded.not_messages, counted_from = excluded.counted_from",
        params![
            id,
            &of[..],
            to_sql(kept.highest),
            to_sql(kept.overwritten),
            to_sql(kept.not_messages),
            kept.counted_from.map(to_sql),
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// Count an entry of `of` in the channel of row `id` that is no message,
/// no clearing and no anew record of its form: it is never shown.
pub fn not_a_message(conn: &Connection, id: i64, of: &[u8; 32]) -> Result<(), CordeliaError> {
    let mut kept = signer(conn, id, of)?.unwrap_or_default();
    kept.not_messages += 1;
    keep_signer(conn, id, of, &kept)
}

/// A reader holds an entry of `of` in the channel of row `id` at
/// `number`, in the slot of that number in the signer's ring, a clearing
/// where `clearing`: as step 19's reader holds one (decision 2026-10-09
/// §2.5; `crate::messages::hold_number`). Returns whether `number` is
/// live, after it is held: only then is the entry opened.
pub fn hold_number(
    conn: &Connection,
    id: i64,
    of: &[u8; 32],
    number: u64,
    clearing: bool,
) -> Result<bool, CordeliaError> {
    let mut kept = signer(conn, id, of)?.unwrap_or_default();
    let number_sql = to_sql(number);
    let highest = to_sql(kept.highest);
    let live = if number_sql > highest {
        if let Some(from) = kept.counted_from.map(to_sql) {
            let lowest = (highest - RING + 1).max(from);
            let left = number_sql - RING;
            if left >= lowest {
                kept.overwritten += from_sql(left_unshown(conn, id, of, lowest, left)?);
            }
            leave_up_to(conn, id, of, left)?;
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
    keep_signer(conn, id, of, &kept)?;
    Ok(live)
}

/// How many of the numbers from `lowest` to `highest` of `of` left the
/// live numbers before their message had a place.
fn left_unshown(
    conn: &Connection,
    id: i64,
    of: &[u8; 32],
    lowest: i64,
    highest: i64,
) -> Result<i64, CordeliaError> {
    let shown_or_gone: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM shared_first_held f
             LEFT JOIN shared_index i ON i.channel = f.channel AND i.id = f.id
             WHERE f.channel = ?1 AND f.signer = ?2 AND f.number BETWEEN ?3 AND ?4
               AND (i.id IS NULL OR i.placed_at IS NOT NULL)",
            params![id, &of[..], lowest, highest],
            |row| row.get(0),
        )
        .map_err(storage)?;
    Ok(highest - lowest + 1 - shown_or_gone)
}

/// Drop the rows of each number of `of` at or below `highest`, which are
/// live no longer, and the index row of a message then held at no number.
fn leave_up_to(
    conn: &Connection,
    id: i64,
    of: &[u8; 32],
    highest: i64,
) -> Result<(), CordeliaError> {
    let ids: Vec<Vec<u8>> = conn
        .prepare(
            "SELECT DISTINCT id FROM shared_numbers
             WHERE channel = ?1 AND signer = ?2 AND number <= ?3",
        )
        .map_err(storage)?
        .query_map(params![id, &of[..], highest], |row| row.get(0))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    for table in ["shared_numbers", "shared_first_held"] {
        conn.execute(
            &format!("DELETE FROM {table} WHERE channel = ?1 AND signer = ?2 AND number <= ?3"),
            params![id, &of[..], highest],
        )
        .map_err(storage)?;
    }
    for message in ids {
        let held: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM shared_numbers WHERE channel = ?1 AND id = ?2",
                params![id, &message],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if held == 0 {
            drop_row(conn, id, &message)?;
        }
    }
    Ok(())
}

/// A shared message as it enters the index (decision 2026-10-10 §6.1).
#[derive(Debug, Clone, Copy)]
pub struct Opened<'a> {
    /// The channel's row.
    pub channel: i64,
    pub id: &'a Id,
    pub signer: &'a [u8; 32],
    /// The number it is held at.
    pub number: u64,
    pub message: &'a SharedMessage,
    /// When the device first held it: now.
    pub first_held: i64,
    /// Its place: none where a reader takes it.
    pub placed_at: Option<i64>,
}

/// What became of a message given to [`index`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Indexed {
    /// It was not held: it has its row now.
    New,
    /// It is held under another number of its signer.
    AnotherNumber,
    /// Its row was taken out with its key's entries, and it is read again:
    /// its row is as it was, under its first holding and its place, and it
    /// is not new (decision 2026-10-10 §6.3).
    Again,
    /// It is not shown again: the device first held this number before,
    /// or held the message and its row went at its 30 days or a clearing.
    NotAgain,
}

/// Write a shared message into the index, in the caller's write: as step
/// 19's reader writes a message (`crate::messages::index`), keyed by the
/// channel and the ID (decision 2026-10-10 §4.2). The caller has held its
/// number with [`hold_number`], and it is live.
///
/// A message whose row was taken out with its key's entries is written
/// again as it was, with its first holding and its place: a key taken out
/// and read again is not shown as new.
pub fn index(conn: &Connection, opened: &Opened) -> Result<Indexed, CordeliaError> {
    let Opened {
        channel,
        id,
        signer,
        number,
        message,
        ..
    } = *opened;
    let number = to_sql(number);
    let held_before: Option<(Option<Vec<u8>>, bool)> = conn
        .query_row(
            "SELECT id, taken_out FROM shared_first_held
             WHERE channel = ?1 AND signer = ?2 AND number = ?3",
            params![channel, &signer[..], number],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(storage)?;
    let in_index: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM shared_index WHERE channel = ?1 AND id = ?2",
            params![channel, &id[..]],
            |row| row.get(0),
        )
        .map_err(storage)?;
    // A sent past what the store's integer holds is later than any first
    // holding, and so is never the shown time.
    let sent = i64::try_from(message.sent).unwrap_or(i64::MAX);
    let (first_held, placed_at, indexed) = match held_before {
        Some((Some(held), true)) if held == id[..] && !in_index => {
            let (first_held, placed_at) = taken_out_at(conn, channel, id)?;
            (first_held, placed_at, Indexed::Again)
        }
        Some(_) => return Ok(Indexed::NotAgain),
        None => {
            let first_held_before: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM shared_first_held
                     WHERE channel = ?1 AND signer = ?2 AND id = ?3",
                    params![channel, &signer[..], &id[..]],
                    |row| row.get(0),
                )
                .map_err(storage)?;
            conn.execute(
                "INSERT INTO shared_first_held (channel, signer, number, id, sent, first_held)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    channel,
                    &signer[..],
                    number,
                    &id[..],
                    sent,
                    opened.first_held
                ],
            )
            .map_err(storage)?;
            match (in_index, first_held_before) {
                (true, _) => {
                    conn.execute(
                        "INSERT INTO shared_numbers (channel, signer, number, id)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![channel, &signer[..], number, &id[..]],
                    )
                    .map_err(storage)?;
                    return Ok(Indexed::AnotherNumber);
                }
                (false, 0) => (opened.first_held, opened.placed_at, Indexed::New),
                (false, _) => {
                    let out: bool = conn
                        .query_row(
                            "SELECT COUNT(*) > 0 FROM shared_first_held
                             WHERE channel = ?1 AND id = ?2 AND taken_out = 1",
                            params![channel, &id[..]],
                            |row| row.get(0),
                        )
                        .map_err(storage)?;
                    if !out {
                        return Ok(Indexed::NotAgain);
                    }
                    let (first_held, placed_at) = taken_out_at(conn, channel, id)?;
                    (first_held, placed_at, Indexed::Again)
                }
            }
        }
    };
    let subject: String = message
        .subject()
        .chars()
        .take(AGENT_MESSAGE_SUBJECT_CHARS)
        .collect();
    conn.execute(
        "INSERT INTO shared_index (channel, id, signer, sent, subject, thread, answers, asks,
                                   link, body, first_held, placed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            channel,
            &id[..],
            &signer[..],
            sent,
            subject,
            &message.thread[..],
            &message.answers[..],
            message.asks,
            message.link,
            message.body,
            first_held,
            placed_at,
        ],
    )
    .map_err(storage)?;
    conn.execute(
        "UPDATE shared_first_held SET taken_out = 0, placed_at = NULL
         WHERE channel = ?1 AND id = ?2",
        params![channel, &id[..]],
    )
    .map_err(storage)?;
    conn.execute(
        "INSERT INTO shared_numbers (channel, signer, number, id) VALUES (?1, ?2, ?3, ?4)",
        params![channel, &signer[..], number, &id[..]],
    )
    .map_err(storage)?;
    Ok(indexed)
}

/// When the message `id` of the channel of row `id` was first held, and
/// its place, as its rows of first holding kept them when it was taken
/// out: the earliest.
fn taken_out_at(
    conn: &Connection,
    channel: i64,
    id: &Id,
) -> Result<(i64, Option<i64>), CordeliaError> {
    conn.query_row(
        "SELECT first_held, placed_at FROM shared_first_held
         WHERE channel = ?1 AND id = ?2 AND taken_out = 1
         ORDER BY first_held LIMIT 1",
        params![channel, &id[..]],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .map_err(storage)
}

/// The index rows of `key` in the channel of row `id` go with its entries
/// (decision 2026-10-10 §6.3): each row overwritten and dropped, its rows
/// of first holding kept, marked as taken out, with its place.
fn take_out_index(conn: &Connection, id: i64, key: &[u8; 32]) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE shared_first_held AS f SET taken_out = 1,
             placed_at = (SELECT i.placed_at FROM shared_index i
                          WHERE i.channel = f.channel AND i.id = f.id)
         WHERE f.channel = ?1 AND f.signer = ?2 AND f.id IS NOT NULL
           AND EXISTS (SELECT 1 FROM shared_index i WHERE i.channel = f.channel AND i.id = f.id)",
        params![id, &key[..]],
    )
    .map_err(storage)?;
    for message in index_ids(conn, id, Some(key))? {
        drop_row(conn, id, &message)?;
    }
    Ok(())
}

/// The signers of the index rows of the channel of row `id`, in order.
pub fn index_signers(conn: &Connection, id: i64) -> Result<Vec<[u8; 32]>, CordeliaError> {
    let signers = conn
        .prepare("SELECT DISTINCT signer FROM shared_index WHERE channel = ?1 ORDER BY signer")
        .map_err(storage)?
        .query_map([id], |row| row.get(0))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    Ok(signers)
}

/// The ID of each index row of the channel of row `id`, with when this
/// device first held it, whether or not it is shown.
pub fn index_first_held(conn: &Connection, id: i64) -> Result<Vec<(Vec<u8>, i64)>, CordeliaError> {
    conn.prepare("SELECT id, first_held FROM shared_index WHERE channel = ?1 ORDER BY id")
        .map_err(storage)?
        .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)
}

/// The IDs of the index rows of the channel of row `id`, of `signer` only
/// where it is given.
fn index_ids(
    conn: &Connection,
    id: i64,
    signer: Option<&[u8; 32]>,
) -> Result<Vec<Vec<u8>>, CordeliaError> {
    let ids = conn
        .prepare(
            "SELECT id FROM shared_index WHERE channel = ?1 AND (?2 IS NULL OR signer = ?2)
             ORDER BY id",
        )
        .map_err(storage)?
        .query_map(params![id, signer.map(|key| &key[..])], |row| row.get(0))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    Ok(ids)
}

/// A reader takes the entry that clears message `number` of `of` in the
/// channel of row `id`, a live number, at `now`: as step 19's
/// (`crate::messages::clear`). Returns whether an index row went.
pub fn clear(
    conn: &Connection,
    id: i64,
    of: &[u8; 32],
    number: u64,
    now: i64,
) -> Result<bool, CordeliaError> {
    conn.execute(
        "INSERT INTO shared_first_held (channel, signer, number, id, sent, first_held)
         VALUES (?1, ?2, ?3, NULL, NULL, ?4)
         ON CONFLICT(channel, signer, number) DO UPDATE SET taken_out = 0, placed_at = NULL",
        params![id, &of[..], to_sql(number), now],
    )
    .map_err(storage)?;
    let message: Option<Vec<u8>> = conn
        .query_row(
            "SELECT id FROM shared_numbers WHERE channel = ?1 AND signer = ?2 AND number = ?3",
            params![id, &of[..], to_sql(number)],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    match message {
        Some(message) => drop_row(conn, id, &message),
        None => Ok(false),
    }
}

/// The SQL of the moment a row of `shared_index` as `i` expires: its shown
/// time, and 30 days.
fn expires_sql() -> String {
    format!(
        "(MIN(i.sent, i.first_held) + {})",
        i64::from(AGENT_MESSAGE_KEPT_DAYS) * DAY_SECS
    )
}

/// The SQL of whether a row of `shared_index` as `i` is held at a live
/// number.
fn live_sql() -> String {
    format!(
        "EXISTS (SELECT 1 FROM shared_numbers n
                 LEFT JOIN shared_signers s ON s.channel = n.channel AND s.signer = n.signer
                 WHERE n.channel = i.channel AND n.id = i.id
                   AND n.number > COALESCE(s.highest, 0) - {RING})"
    )
}

/// Which keys of a channel are shown, as a show gives places
/// ([`give_places`]): each with whether it is a key the person has not
/// labelled and that is no device of the person's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShownKey {
    pub key: [u8; 32],
    pub unlabelled: bool,
}

/// Give places to the messages of the channel of row `id` that a reader is
/// about to show, at `now` (decision 2026-10-10 §2.4, rule 4): only to the
/// live messages of the keys of `shown` that have none and have not
/// expired, **newest first, by number, for one signer**, while fewer than
/// 64 of that signer's places in that channel lie in the hour before
/// `now`; and, of the keys that are unlabelled, while fewer than 64 places
/// of all of them lie in that hour, given newest first by shown time. The
/// device's own messages (signed by `own`) take no place from either.
/// Returns how many were given.
pub fn give_places(
    conn: &Connection,
    id: i64,
    own: &[u8; 32],
    shown: &[ShownKey],
    now: i64,
) -> Result<usize, CordeliaError> {
    conn.execute(
        "DELETE FROM shared_places WHERE channel = ?1 AND (placed_at <= ?2 OR placed_at > ?3)",
        params![id, now - HOUR_SECS, now],
    )
    .map_err(storage)?;
    let placed = |signer: Option<&[u8; 32]>| -> Result<i64, CordeliaError> {
        conn.query_row(
            "SELECT COUNT(*) FROM shared_places WHERE channel = ?1
             AND ((?2 IS NULL AND unlabelled = 1) OR signer = ?2)",
            params![id, signer.map(|key| &key[..])],
            |row| row.get(0),
        )
        .map_err(storage)
    };
    // Each shown signer's waiting messages, newest first by number, up to
    // its own room in the hour.
    let mut candidates: Vec<(Vec<u8>, ShownKey, i64)> = Vec::new();
    for key in shown {
        let waiting: Vec<(Vec<u8>, i64)> = conn
            .prepare(&format!(
                "SELECT i.id, MIN(i.sent, i.first_held) FROM shared_index i
                 JOIN shared_numbers n ON n.channel = i.channel AND n.id = i.id
                 WHERE i.channel = ?1 AND i.signer = ?2 AND i.placed_at IS NULL
                   AND ?3 < {expires} AND {live}
                 GROUP BY i.id
                 ORDER BY MAX(n.number) DESC",
                expires = expires_sql(),
                live = live_sql(),
            ))
            .map_err(storage)?
            .query_map(params![id, &key.key[..], now], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(storage)?
            .collect::<Result<_, _>>()
            .map_err(storage)?;
        let room = if key.key == *own {
            usize::MAX
        } else {
            usize::try_from(RING - placed(Some(&key.key))?).unwrap_or(0)
        };
        candidates.extend(
            waiting
                .into_iter()
                .take(room)
                .map(|(message, shown_at)| (message, *key, shown_at)),
        );
    }
    // The keys the person has not labelled share one hour: the newest
    // first among them all.
    let mut pool_room = usize::try_from(RING - placed(None)?).unwrap_or(0);
    let mut given_to: Vec<(Vec<u8>, ShownKey)> = Vec::new();
    let (mut pooled, others): (Vec<_>, Vec<_>) = candidates
        .into_iter()
        .partition(|(_, key, _)| key.unlabelled && key.key != *own);
    pooled.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
    for (message, key, _) in pooled {
        if pool_room == 0 {
            break;
        }
        pool_room -= 1;
        given_to.push((message, key));
    }
    given_to.extend(others.into_iter().map(|(message, key, _)| (message, key)));
    for (message, key) in &given_to {
        if key.key != *own {
            conn.execute(
                "INSERT INTO shared_places (channel, signer, placed_at, unlabelled)
                 VALUES (?1, ?2, ?3, ?4)",
                params![id, &key.key[..], now, key.unlabelled],
            )
            .map_err(storage)?;
        }
        conn.execute(
            "UPDATE shared_index SET placed_at = ?3 WHERE channel = ?1 AND id = ?2",
            params![id, message, now],
        )
        .map_err(storage)?;
    }
    Ok(given_to.len())
}

/// A shared message that is shown: it has a place, one of its numbers is
/// live, and its 30 days are not up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    pub id: Vec<u8>,
    pub signer: [u8; 32],
    pub sent: i64,
    pub first_held: i64,
    pub shown_at: i64,
    pub subject: String,
    pub thread: Vec<u8>,
    pub answers: Vec<u8>,
    pub asks: bool,
    pub link: Option<String>,
    pub body: String,
    pub placed_at: i64,
}

/// Every message of the channel of row `id` shown at `now`, of a key of
/// `shown`, oldest first: by shown time, and between two of one shown
/// time by ID. It gives no place.
pub fn shown(
    conn: &Connection,
    id: i64,
    shown: &[[u8; 32]],
    now: i64,
) -> Result<Vec<Shown>, CordeliaError> {
    let rows: Vec<Shown> = conn
        .prepare(&format!(
            "SELECT i.id, i.signer, i.sent, i.first_held, MIN(i.sent, i.first_held) AS shown_at,
                    i.subject, i.thread, i.answers, i.asks, i.link, i.body, i.placed_at
             FROM shared_index i
             WHERE i.channel = ?1 AND i.placed_at IS NOT NULL AND ?2 < {expires} AND {live}
             ORDER BY shown_at, i.id",
            expires = expires_sql(),
            live = live_sql(),
        ))
        .map_err(storage)?
        .query_map(params![id, now], |row| {
            Ok(Shown {
                id: row.get(0)?,
                signer: row.get(1)?,
                sent: row.get(2)?,
                first_held: row.get(3)?,
                shown_at: row.get(4)?,
                subject: row.get(5)?,
                thread: row.get(6)?,
                answers: row.get(7)?,
                asks: row.get(8)?,
                link: row.get(9)?,
                body: row.get(10)?,
                placed_at: row.get(11)?,
            })
        })
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    Ok(rows
        .into_iter()
        .filter(|row| shown.contains(&row.signer))
        .collect())
}

/// How many live messages of `of` in the channel of row `id`, not
/// expired, wait for a place at `now`.
pub fn held_back(
    conn: &Connection,
    id: i64,
    of: &[u8; 32],
    now: i64,
) -> Result<u64, CordeliaError> {
    let held: i64 = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM shared_index i
                 WHERE i.channel = ?1 AND i.signer = ?2 AND i.placed_at IS NULL
                   AND ?3 < {expires} AND {live}",
                expires = expires_sql(),
                live = live_sql(),
            ),
            params![id, &of[..], now],
            |row| row.get(0),
        )
        .map_err(storage)?;
    Ok(from_sql(held))
}

/// The index of the shared channels' part of the hourly task (decision
/// 2026-10-09 §7.1, as the messages record has it, for a shared channel):
/// each index row whose 30 days are up, and each held at no live number,
/// is overwritten and dropped; the rows of first holding of numbers that
/// are not live go, and the places from before the hour. Of a channel
/// moved from, once its index holds nothing, the reader's rows go too.
/// Returns how many rows went.
pub fn drop_gone(conn: &Connection, now: i64) -> Result<usize, CordeliaError> {
    let ids = |condition: String| -> Result<Vec<(i64, Vec<u8>)>, CordeliaError> {
        conn.prepare(&format!(
            "SELECT i.channel, i.id FROM shared_index i WHERE {condition}"
        ))
        .map_err(storage)?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)
    };
    let mut gone = 0;
    for (channel, id) in ids(format!("{now} >= {}", expires_sql()))? {
        gone += usize::from(drop_row(conn, channel, &id)?);
    }
    for (channel, id) in ids(format!("NOT {}", live_sql()))? {
        gone += usize::from(drop_row(conn, channel, &id)?);
    }
    conn.execute(
        &format!(
            "DELETE FROM shared_first_held AS f WHERE f.number <= COALESCE(
                 (SELECT s.highest FROM shared_signers s
                  WHERE s.channel = f.channel AND s.signer = f.signer), 0) - {RING}"
        ),
        [],
    )
    .map_err(storage)?;
    conn.execute(
        "DELETE FROM shared_places WHERE placed_at <= ?1",
        [now - HOUR_SECS],
    )
    .map_err(storage)?;
    let emptied: Vec<i64> = conn
        .prepare(
            "SELECT c.id FROM shared_channels c WHERE c.state = 3
             AND NOT EXISTS (SELECT 1 FROM shared_index i WHERE i.channel = c.id)",
        )
        .map_err(storage)?
        .query_map([], |row| row.get(0))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    for channel in emptied {
        drop_index(conn, channel)?;
    }
    Ok(gone)
}

/// Drop the index row of the message `message` of the channel of row `id`:
/// its body, link and subject are first written over with zeros
/// of the same length, then the row is deleted, and its rows of numbers
/// held with it, in a savepoint of its own (decision 2026-10-09 §7.1, as
/// `crate::messages::drop_row`). Returns whether the device held the row.
pub fn drop_row(conn: &Connection, id: i64, message: &[u8]) -> Result<bool, CordeliaError> {
    conn.execute_batch("SAVEPOINT shared_drop_row")
        .map_err(storage)?;
    let dropped = overwritten_and_deleted(conn, id, message);
    let end = match dropped {
        Ok(_) => "RELEASE shared_drop_row",
        Err(_) => "ROLLBACK TO shared_drop_row; RELEASE shared_drop_row",
    };
    conn.execute_batch(end).map_err(storage)?;
    dropped
}

fn overwritten_and_deleted(
    conn: &Connection,
    id: i64,
    message: &[u8],
) -> Result<bool, CordeliaError> {
    conn.execute(
        "UPDATE shared_index SET
             body = zeroblob(length(CAST(body AS BLOB))),
             link = CASE WHEN link IS NULL THEN NULL
                         ELSE zeroblob(length(CAST(link AS BLOB))) END,
             subject = zeroblob(length(CAST(subject AS BLOB)))
         WHERE channel = ?1 AND id = ?2",
        params![id, message],
    )
    .map_err(storage)?;
    conn.execute(
        "DELETE FROM shared_numbers WHERE channel = ?1 AND id = ?2",
        params![id, message],
    )
    .map_err(storage)?;
    let dropped = conn
        .execute(
            "DELETE FROM shared_index WHERE channel = ?1 AND id = ?2",
            params![id, message],
        )
        .map_err(storage)?;
    Ok(dropped == 1)
}

/// A count or a number as the store's integer holds it.
fn to_sql(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn from_sql(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}
