//! What a device keeps of making, sharing and taking a shared channel
//! (decision 2026-10-10 §3.1, §3.2; schema step 24): the keys a person
//! typed at `cordelia accept --channel`, with what became of each; and the
//! shares this device wrote, with what each relay answered of them.

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

// ── The keys typed for channels ──────────────────────────────────────

/// A key typed at `cordelia accept --channel`, as the device keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedForChannel {
    pub key: [u8; 32],
    /// The name the channel taken is to be filed under.
    pub name: String,
    pub typed_at: i64,
    /// When a share was taken under this typing, and of which channel.
    pub taken: Option<(i64, [u8; 32])>,
    /// What became of it: a word, where anything did.
    pub became: Option<String>,
    /// What the line of that word names.
    pub detail: Option<String>,
}

const TYPED_COLUMNS: &str = "key, name, typed_at, taken_at, channel, became, detail";

fn typed_from_row(row: &rusqlite::Row) -> rusqlite::Result<TypedForChannel> {
    let taken_at: Option<i64> = row.get(3)?;
    let channel: Option<[u8; 32]> = row.get(4)?;
    Ok(TypedForChannel {
        key: row.get(0)?,
        name: row.get(1)?,
        typed_at: row.get(2)?,
        taken: taken_at.zip(channel),
        became: row.get(5)?,
        detail: row.get(6)?,
    })
}

/// `key` was typed for a channel to be filed as `name`, at `now`: kept in
/// the place of what it was typed for before, with nothing yet become of it.
pub fn type_key(
    conn: &Connection,
    key: &[u8; 32],
    name: &str,
    now: i64,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO shared_typed_keys (key, name, typed_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET name = excluded.name, typed_at = excluded.typed_at,
             taken_at = NULL, channel = NULL, became = NULL, detail = NULL",
        params![&key[..], name, now],
    )
    .map_err(storage)?;
    Ok(())
}

/// Every key typed for a channel, in the order they were typed.
pub fn typed_keys(conn: &Connection) -> Result<Vec<TypedForChannel>, CordeliaError> {
    let rows = conn
        .prepare(&format!(
            "SELECT {TYPED_COLUMNS} FROM shared_typed_keys ORDER BY typed_at, key"
        ))
        .map_err(storage)?
        .query_map([], typed_from_row)
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    Ok(rows)
}

/// The key `key`, where it was typed for a channel.
pub fn typed_key(
    conn: &Connection,
    key: &[u8; 32],
) -> Result<Option<TypedForChannel>, CordeliaError> {
    conn.query_row(
        &format!("SELECT {TYPED_COLUMNS} FROM shared_typed_keys WHERE key = ?1"),
        [&key[..]],
        typed_from_row,
    )
    .optional()
    .map_err(storage)
}

/// What became of the key `key`, typed at `typed_at`: a word, and what its
/// line names. A typing since is left as it is.
pub fn became(
    conn: &Connection,
    key: &[u8; 32],
    typed_at: i64,
    word: &str,
    detail: Option<&str>,
) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE shared_typed_keys SET became = ?3, detail = ?4 WHERE key = ?1 AND typed_at = ?2",
        params![&key[..], typed_at, word, detail],
    )
    .map_err(storage)?;
    Ok(())
}

/// A share of the channel `channel` was taken under the key `key`, typed at
/// `typed_at`, at `now`: the typing is spent.
pub fn taken(
    conn: &Connection,
    key: &[u8; 32],
    typed_at: i64,
    channel: &[u8; 32],
    now: i64,
) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE shared_typed_keys SET taken_at = ?3, channel = ?4, became = 'taken', detail = NULL
         WHERE key = ?1 AND typed_at = ?2",
        params![&key[..], typed_at, now, &channel[..]],
    )
    .map_err(storage)?;
    Ok(())
}

/// What was typed before `before` is forgotten. Returns how many went.
pub fn forget_typed_keys(conn: &Connection, before: i64) -> Result<usize, CordeliaError> {
    conn.execute(
        "DELETE FROM shared_typed_keys WHERE typed_at < ?1",
        [before],
    )
    .map_err(storage)
}

// ── The shares this device wrote ─────────────────────────────────────

/// A share this device wrote, as it keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareRow {
    /// The key it is for: the taker's.
    pub key: [u8; 32],
    /// The shared channel it hands.
    pub channel: [u8; 32],
    /// The share pair channel it is in.
    pub pair: [u8; 32],
    /// The card's relays, in their one form.
    pub relays: Vec<u8>,
    /// The revision of the share, or of the delete written over it.
    pub rev: u64,
    /// The time the share says, by this device's clock.
    pub made: i64,
    /// Whether a delete was written over it.
    pub gone: bool,
}

const SHARE_COLUMNS: &str = "key, channel, pair, relays, rev, made, gone";

fn share_from_row(row: &rusqlite::Row) -> rusqlite::Result<ShareRow> {
    Ok(ShareRow {
        key: row.get(0)?,
        channel: row.get(1)?,
        pair: row.get(2)?,
        relays: row.get(3)?,
        rev: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
        made: row.get(5)?,
        gone: row.get(6)?,
    })
}

/// The share `share` was written: kept in the place of one of the same
/// key and channel, and with no answer of any relay.
pub fn note_share(conn: &Connection, share: &ShareRow) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM shared_shares WHERE key = ?1 AND channel = ?2",
        params![&share.key[..], &share.channel[..]],
    )
    .map_err(storage)?;
    conn.execute(
        &format!("INSERT INTO shared_shares ({SHARE_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"),
        params![
            &share.key[..],
            &share.channel[..],
            &share.pair[..],
            &share.relays,
            i64::try_from(share.rev).unwrap_or(i64::MAX),
            share.made,
            share.gone
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// A delete was written over the share of `key` and `channel`, at `rev`.
pub fn share_gone(
    conn: &Connection,
    key: &[u8; 32],
    channel: &[u8; 32],
    rev: u64,
) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE shared_shares SET gone = 1, rev = ?3 WHERE key = ?1 AND channel = ?2",
        params![
            &key[..],
            &channel[..],
            i64::try_from(rev).unwrap_or(i64::MAX)
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// Every share this device keeps, waiting or gone, in the order they were
/// made.
pub fn shares(conn: &Connection) -> Result<Vec<ShareRow>, CordeliaError> {
    let rows = conn
        .prepare(&format!(
            "SELECT {SHARE_COLUMNS} FROM shared_shares ORDER BY made, key, channel"
        ))
        .map_err(storage)?
        .query_map([], share_from_row)
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    Ok(rows)
}

/// The share of `key` and `channel` is forgotten, with every answer of it.
pub fn forget_share(
    conn: &Connection,
    key: &[u8; 32],
    channel: &[u8; 32],
) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM shared_share_sent WHERE key = ?1 AND channel = ?2",
        params![&key[..], &channel[..]],
    )
    .map_err(storage)?;
    conn.execute(
        "DELETE FROM shared_shares WHERE key = ?1 AND channel = ?2",
        params![&key[..], &channel[..]],
    )
    .map_err(storage)?;
    Ok(())
}

/// The relay `relay` answered a push of the share of `key` and `channel`,
/// or of the delete over it, at `rev`. An answer at a lower revision does
/// not undo one at a higher.
pub fn share_answered(
    conn: &Connection,
    key: &[u8; 32],
    channel: &[u8; 32],
    relay: &[u8; 32],
    rev: u64,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO shared_share_sent (key, channel, relay, rev) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(key, channel, relay) DO UPDATE SET rev = MAX(rev, excluded.rev)",
        params![
            &key[..],
            &channel[..],
            &relay[..],
            i64::try_from(rev).unwrap_or(i64::MAX)
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// The revision at which the relay `relay` last answered a push of the
/// share of `key` and `channel`, where it did.
pub fn share_answer(
    conn: &Connection,
    key: &[u8; 32],
    channel: &[u8; 32],
    relay: &[u8; 32],
) -> Result<Option<u64>, CordeliaError> {
    conn.query_row(
        "SELECT rev FROM shared_share_sent WHERE key = ?1 AND channel = ?2 AND relay = ?3",
        params![&key[..], &channel[..], &relay[..]],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map(|rev| rev.map(|rev| u64::try_from(rev).unwrap_or(0)))
    .map_err(storage)
}

/// Everything here goes: a device that leaves its person keeps nothing of
/// what it typed or shared.
pub fn forget_all(conn: &Connection) -> Result<(), CordeliaError> {
    conn.execute_batch(
        "DELETE FROM shared_share_sent; DELETE FROM shared_shares; DELETE FROM shared_typed_keys;",
    )
    .map_err(storage)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::schema::init_db(&conn).unwrap();
        conn
    }

    /// A key typed again takes the place of its typing before, and what
    /// became of it then goes; a share taken spends the typing it was taken
    /// under, and not a later one.
    #[test]
    fn a_key_typed_for_a_channel_is_kept_with_what_became_of_it() {
        let conn = db();
        type_key(&conn, &[1; 32], "review", 10).unwrap();
        became(&conn, &[1; 32], 10, "more_than_one_share", Some("2")).unwrap();
        let kept = typed_key(&conn, &[1; 32]).unwrap().unwrap();
        assert_eq!(kept.became.as_deref(), Some("more_than_one_share"));
        type_key(&conn, &[1; 32], "design", 20).unwrap();
        let kept = typed_key(&conn, &[1; 32]).unwrap().unwrap();
        assert_eq!(
            (kept.name.as_str(), kept.typed_at, kept.became),
            ("design", 20, None)
        );
        taken(&conn, &[1; 32], 10, &[9; 32], 30).unwrap();
        assert_eq!(typed_key(&conn, &[1; 32]).unwrap().unwrap().taken, None);
        taken(&conn, &[1; 32], 20, &[9; 32], 30).unwrap();
        assert_eq!(
            typed_key(&conn, &[1; 32]).unwrap().unwrap().taken,
            Some((30, [9; 32]))
        );
        assert_eq!(forget_typed_keys(&conn, 21).unwrap(), 1);
        assert!(typed_keys(&conn).unwrap().is_empty());
    }

    /// A share is kept by its key and channel, a delete over it is noted,
    /// and a relay's answer at a lower revision does not undo a higher.
    #[test]
    fn a_share_is_kept_with_what_each_relay_answered() {
        let conn = db();
        let share = ShareRow {
            key: [1; 32],
            channel: [2; 32],
            pair: [3; 32],
            relays: vec![0; 33],
            rev: 100,
            made: 100,
            gone: false,
        };
        note_share(&conn, &share).unwrap();
        share_answered(&conn, &[1; 32], &[2; 32], &[7; 32], 100).unwrap();
        share_answered(&conn, &[1; 32], &[2; 32], &[7; 32], 99).unwrap();
        assert_eq!(
            share_answer(&conn, &[1; 32], &[2; 32], &[7; 32]).unwrap(),
            Some(100)
        );
        share_gone(&conn, &[1; 32], &[2; 32], 101).unwrap();
        let kept = shares(&conn).unwrap();
        assert_eq!((kept[0].gone, kept[0].rev), (true, 101));
        // Written again: no answer of any relay is kept.
        note_share(&conn, &share).unwrap();
        assert_eq!(
            share_answer(&conn, &[1; 32], &[2; 32], &[7; 32]).unwrap(),
            None
        );
        share_answered(&conn, &[1; 32], &[2; 32], &[7; 32], 100).unwrap();
        forget_share(&conn, &[1; 32], &[2; 32]).unwrap();
        assert!(shares(&conn).unwrap().is_empty());
        assert_eq!(
            share_answer(&conn, &[1; 32], &[2; 32], &[7; 32]).unwrap(),
            None
        );
    }
}
