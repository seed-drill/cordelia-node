//! Aggregate usage counts for whoever runs this node as a relay: how many
//! distinct peers it has seen lately, how many channels are active, and how
//! much it stores. Counts only.
//!
//! A peer is remembered as a keyed hash of its public key, made with a
//! secret that never leaves this node, with the times it was first and last
//! seen. The row is dropped once the peer has not been seen for
//! `SIGHTING_RETENTION_DAYS`, so nothing here outlives the weekly count.

use cordelia_core::CordeliaError;
use rusqlite::{Connection, params};

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

/// Note that the peer with this hash is connected at `now` (unix seconds).
pub fn record_sighting(
    conn: &Connection,
    peer_hash: &[u8; 32],
    is_relay: bool,
    now: i64,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO peer_sightings (peer_hash, is_relay, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?3)
         ON CONFLICT(peer_hash) DO UPDATE SET last_seen = ?3, is_relay = ?2",
        params![peer_hash.as_slice(), is_relay, now],
    )
    .map_err(storage)?;
    Ok(())
}

/// Distinct peers seen since `since` (unix seconds): `(relays, others)`.
pub fn peers_seen(conn: &Connection, since: i64) -> Result<(u64, u64), CordeliaError> {
    conn.query_row(
        "SELECT COALESCE(SUM(is_relay), 0), COALESCE(SUM(1 - is_relay), 0)
         FROM peer_sightings WHERE last_seen >= ?1",
        params![since],
        |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
    )
    .map_err(storage)
}

/// Forget peers not seen since `before` (unix seconds). Returns how many.
pub fn prune_sightings(conn: &Connection, before: i64) -> Result<usize, CordeliaError> {
    conn.execute(
        "DELETE FROM peer_sightings WHERE last_seen < ?1",
        params![before],
    )
    .map_err(storage)
}

/// Channels that received an item in the last `days` days.
pub fn channels_active(conn: &Connection, days: u32) -> Result<u64, CordeliaError> {
    conn.query_row(
        "SELECT COUNT(DISTINCT channel_id) FROM items
         WHERE received_at >= datetime('now', ?1)",
        params![format!("-{days} days")],
        |row| row.get::<_, i64>(0),
    )
    .map(|n| n as u64)
    .map_err(storage)
}

/// What this node stores: `(items, bytes of encrypted content)`.
pub fn stored(conn: &Connection) -> Result<(u64, u64), CordeliaError> {
    conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(content_length), 0) FROM items",
        [],
        |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
    )
    .map_err(storage)
}

/// The usage counts at `now` (unix seconds). Peers exclude relays.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub peers_1d: u64,
    pub relays_1d: u64,
    pub peers_7d: u64,
    pub relays_7d: u64,
    pub channels_active_1d: u64,
    pub channels_active_7d: u64,
    pub items_stored: u64,
    pub bytes_stored: u64,
}

/// What a device stores of the channels of its own, from their secrets:
/// `(entries, bytes of their content)`.
pub fn stored_of_own(conn: &Connection) -> Result<(u64, u64), CordeliaError> {
    conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(length(content)), 0) FROM entries",
        [],
        |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
    )
    .map_err(storage)
}

/// The channels of a device's own in which it stored an entry since
/// `since` (unix seconds).
pub fn own_channels_active(conn: &Connection, since: i64) -> Result<u64, CordeliaError> {
    conn.query_row(
        "SELECT COUNT(DISTINCT channel_id) FROM entries WHERE stored_at >= ?1",
        params![since],
        |row| row.get::<_, i64>(0),
    )
    .map(|n| n as u64)
    .map_err(storage)
}

/// What a device stores of one channel of its own: how many entries, and
/// when it stored the last of them (unix seconds), where it holds any.
pub fn stored_of_channel(
    conn: &Connection,
    channel: &[u8; 32],
) -> Result<(u64, Option<i64>), CordeliaError> {
    conn.query_row(
        "SELECT COUNT(*), MAX(stored_at) FROM entries WHERE channel_id = ?1",
        params![channel.as_slice()],
        |row| Ok((row.get::<_, i64>(0)? as u64, row.get(1)?)),
    )
    .map_err(storage)
}

/// The usage counts of a device at `now` (unix seconds): the peers it
/// has seen, and what it stores of the channels of its own. Nothing of
/// the older kind of channel is counted: a personal node carries none
/// (decision 2026-10-04 §10), whatever its database once held.
pub fn snapshot_of_a_device(conn: &Connection, now: i64) -> Result<Usage, CordeliaError> {
    let (relays_1d, peers_1d) = peers_seen(conn, now - 86_400)?;
    let (relays_7d, peers_7d) = peers_seen(conn, now - 7 * 86_400)?;
    let (items_stored, bytes_stored) = stored_of_own(conn)?;
    Ok(Usage {
        peers_1d,
        relays_1d,
        peers_7d,
        relays_7d,
        channels_active_1d: own_channels_active(conn, now - 86_400)?,
        channels_active_7d: own_channels_active(conn, now - 7 * 86_400)?,
        items_stored,
        bytes_stored,
    })
}

pub fn snapshot(conn: &Connection, now: i64) -> Result<Usage, CordeliaError> {
    let (relays_1d, peers_1d) = peers_seen(conn, now - 86_400)?;
    let (relays_7d, peers_7d) = peers_seen(conn, now - 7 * 86_400)?;
    let (items_stored, bytes_stored) = stored(conn)?;
    Ok(Usage {
        peers_1d,
        relays_1d,
        peers_7d,
        relays_7d,
        channels_active_1d: channels_active(conn, 1)?,
        channels_active_7d: channels_active(conn, 7)?,
        items_stored,
        bytes_stored,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    const DAY: i64 = 86_400;

    #[test]
    fn test_distinct_peers_are_counted_by_window_and_role() {
        let conn = db::open_in_memory().unwrap();
        let now = 1_800_000_000;
        let (a, b, relay) = ([1u8; 32], [2u8; 32], [3u8; 32]);

        record_sighting(&conn, &a, false, now - 3 * DAY).unwrap();
        record_sighting(&conn, &b, false, now - 100).unwrap();
        record_sighting(&conn, &relay, true, now - 50).unwrap();
        // Seen again: still one peer, with a later last_seen.
        record_sighting(&conn, &b, false, now).unwrap();

        assert_eq!(peers_seen(&conn, now - DAY).unwrap(), (1, 1));
        assert_eq!(peers_seen(&conn, now - 7 * DAY).unwrap(), (1, 2));
        let usage = snapshot(&conn, now).unwrap();
        assert_eq!((usage.peers_1d, usage.peers_7d), (1, 2));
        assert_eq!((usage.relays_1d, usage.relays_7d), (1, 1));

        // A peer not seen for the retention period is forgotten.
        assert_eq!(prune_sightings(&conn, now - 2 * DAY).unwrap(), 1);
        assert_eq!(peers_seen(&conn, 0).unwrap(), (1, 1));
    }

    /// A device's usage counts are of the channels of its own: the
    /// entries it stores and the bytes of their content, and the channels
    /// in which it stored one lately. Nothing that the table of the
    /// older kind holds is counted (decision 2026-10-04 §10).
    #[test]
    fn test_a_device_counts_the_entries_of_its_own_channels_and_nothing_older() {
        let conn = db::open_in_memory().unwrap();
        let now = 1_800_000_000;
        // Of the older kind: a channel with an item, which is not a
        // device's to count.
        conn.execute_batch(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id,
                                   created_at, updated_at)
             VALUES ('grp_a', 'group', 'realtime', 'invite_only', X'AA', '2026-01-01',
                     '2026-01-01');
             INSERT INTO items (item_id, channel_id, author_id, item_type, published_at,
                                content_hash, signature, encrypted_blob, content_length)
             VALUES ('ci_1', 'grp_a', X'AA', 'memory', '2026-01-01', X'01', X'02', X'0303', 2);",
        )
        .unwrap();
        assert_eq!(stored(&conn).unwrap(), (1, 2));
        assert_eq!(stored_of_own(&conn).unwrap(), (0, 0));
        let none = snapshot_of_a_device(&conn, now).unwrap();
        assert_eq!((none.items_stored, none.bytes_stored), (0, 0));
        assert_eq!((none.channels_active_1d, none.channels_active_7d), (0, 0));

        // Three entries in two channels of its own: one stored today,
        // one three days ago, one long ago.
        let entry = |channel: u8, slot: u8, content: &[u8], stored_at: i64| {
            conn.execute(
                "INSERT INTO entries (channel_id, slot, author, rev, is_delete, content,
                                      author_sig, channel_sig, seq, stored_at, channel_place)
                 VALUES (?1, ?2, zeroblob(32), 1, 0, ?3, zeroblob(64), zeroblob(64), ?4, ?5, ?4)",
                params![
                    [channel; 32].as_slice(),
                    [slot; 32].as_slice(),
                    content,
                    i64::from(slot),
                    stored_at
                ],
            )
            .unwrap();
        };
        entry(1, 1, b"12345", now - 100);
        entry(2, 2, b"123", now - 3 * 86_400);
        entry(2, 3, b"1", now - 30 * 86_400);
        assert_eq!(stored_of_own(&conn).unwrap(), (3, 9));
        assert_eq!(own_channels_active(&conn, now - 86_400).unwrap(), 1);
        assert_eq!(own_channels_active(&conn, now - 7 * 86_400).unwrap(), 2);
        assert_eq!(
            stored_of_channel(&conn, &[2; 32]).unwrap(),
            (2, Some(now - 3 * 86_400))
        );
        assert_eq!(stored_of_channel(&conn, &[9; 32]).unwrap(), (0, None));
        let own = snapshot_of_a_device(&conn, now).unwrap();
        assert_eq!((own.items_stored, own.bytes_stored), (3, 9));
        assert_eq!((own.channels_active_1d, own.channels_active_7d), (1, 2));
        // A node that carries the older kind counts that kind, as it did.
        let older = snapshot(&conn, now).unwrap();
        assert_eq!((older.items_stored, older.bytes_stored), (1, 2));
        // Both count the peers that were seen.
        record_sighting(&conn, &[4; 32], true, now - 50).unwrap();
        assert_eq!(snapshot_of_a_device(&conn, now).unwrap().relays_1d, 1);
    }

    #[test]
    fn test_empty_node_counts_nothing() {
        let conn = db::open_in_memory().unwrap();
        assert_eq!(peers_seen(&conn, 0).unwrap(), (0, 0));
        assert_eq!(channels_active(&conn, 7).unwrap(), 0);
        assert_eq!(stored(&conn).unwrap(), (0, 0));
    }
}
