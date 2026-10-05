//! What a device keeps of each relay it is set up with, for each channel
//! of its own (decision 2026-10-04 §4.6, §7.3).
//!
//! Two tables, in the node's database, beside what a device holds of its
//! person:
//!
//! - **Where it stands at a relay in a channel** (`at_relays`, one row for
//!   each relay and channel). Three things:
//!   - its place in the relay's holding of the channel, with the mark of
//!     that holding: where its next pull goes on from. A relay that drops
//!     a channel and takes it again counts its places from the start,
//!     under another mark, so a place means something only with its mark.
//!     No mark is no place: the channel is read from the start;
//!   - how far it has sent the relay what its own store holds of the
//!     channel, in the order in which the store took its entries
//!     ([`crate::entries::StoredEntry::seq`]): everything up to there was
//!     sent, or is known to be held there, or is not to be sent there;
//!   - the same for what the device carried into the channel when it
//!     applied a statement, which is sent by a rule of its own (§7.3).
//! - **How far what the store holds is what the device carried**
//!   (`person_carried`, one row): the store's order as it stood when the
//!   device last applied a statement. An entry of the device's own, in the
//!   channel of a name, that the store took no later than that, is one it
//!   carried.
//!
//! - **What a relay refused for room** (`at_relays_refused`, one row for
//!   each relay, channel and entry): an entry that the relay had no room
//!   for, by its place in the store's own order. How far the relay was
//!   sent the channel goes on past it, so that what follows is still
//!   offered, and the entry is kept here to be sent again after a wait
//!   (§16).
//!
//! A relay is known here by its node key. Nothing here decides anything:
//! what is sent, what is taken and when a channel is read again are
//! decided where these are read.

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;

use crate::relay::Mark;

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

/// What a device keeps of one relay for one channel of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeptThere {
    /// Its place in the relay's holding of the channel, with the mark of
    /// that holding. `None` where it has none: the channel is read from
    /// the start.
    pub place: Option<(Mark, u64)>,
    /// How far it has sent the relay what its store holds of the channel,
    /// in the store's own order. 0 is before the first.
    pub sent_to: i64,
    /// How far it has sent the relay what it carried into the channel, or
    /// found that the relay needs none of it.
    pub carried_to: i64,
}

/// A place or a count as the database holds it.
fn to_sql(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// What the device keeps of `relay` for `channel`. Nothing kept is the
/// start of everything: no place, and nothing sent.
pub fn kept(
    conn: &Connection,
    relay: &[u8; 32],
    channel: &[u8; 32],
) -> Result<KeptThere, CordeliaError> {
    let row: Option<(Option<Mark>, i64, i64, i64)> = conn
        .query_row(
            "SELECT mark, place, sent_to, carried_to FROM at_relays
             WHERE relay = ?1 AND channel = ?2",
            params![relay.as_slice(), channel.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(storage)?;
    Ok(
        row.map_or_else(KeptThere::default, |(mark, place, sent_to, carried_to)| {
            KeptThere {
                place: mark.map(|mark| (mark, place.max(0) as u64)),
                sent_to,
                carried_to,
            }
        }),
    )
}

/// Make sure there is a row for `relay` and `channel`: one that keeps
/// nothing yet.
fn row(conn: &Connection, relay: &[u8; 32], channel: &[u8; 32]) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO at_relays (relay, channel) VALUES (?1, ?2)
         ON CONFLICT(relay, channel) DO NOTHING",
        params![relay.as_slice(), channel.as_slice()],
    )
    .map_err(storage)?;
    Ok(())
}

/// The device's place in the holding that `relay` has of `channel` is
/// `place`, in the holding marked `mark`. The mark of no holding is no
/// mark, and is refused.
pub fn keep_place(
    conn: &Connection,
    relay: &[u8; 32],
    channel: &[u8; 32],
    mark: &Mark,
    place: u64,
) -> Result<(), CordeliaError> {
    row(conn, relay, channel)?;
    conn.execute(
        "UPDATE at_relays SET mark = ?3, place = ?4 WHERE relay = ?1 AND channel = ?2",
        params![
            relay.as_slice(),
            channel.as_slice(),
            mark.as_slice(),
            to_sql(place)
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// Forget every place, at every relay, in every channel: each channel is
/// read again from the start (decision 2026-10-04 §16). What was sent is
/// kept as it is. Returns how many places there were.
pub fn forget_places(conn: &Connection) -> Result<usize, CordeliaError> {
    conn.execute(
        "UPDATE at_relays SET mark = NULL, place = 0 WHERE mark IS NOT NULL",
        [],
    )
    .map_err(storage)
}

/// Everything that the store took of `channel` up to `up_to`, in its own
/// order, is sent to `relay`, or needs no sending there. It never goes
/// back: an earlier place than the one kept changes nothing.
pub fn sent(
    conn: &Connection,
    relay: &[u8; 32],
    channel: &[u8; 32],
    up_to: i64,
) -> Result<(), CordeliaError> {
    row(conn, relay, channel)?;
    conn.execute(
        "UPDATE at_relays SET sent_to = ?3
         WHERE relay = ?1 AND channel = ?2 AND sent_to < ?3",
        params![relay.as_slice(), channel.as_slice(), up_to],
    )
    .map_err(storage)?;
    Ok(())
}

/// [`sent`], for what the device carried into the channel.
pub fn carried(
    conn: &Connection,
    relay: &[u8; 32],
    channel: &[u8; 32],
    up_to: i64,
) -> Result<(), CordeliaError> {
    row(conn, relay, channel)?;
    conn.execute(
        "UPDATE at_relays SET carried_to = ?3
         WHERE relay = ?1 AND channel = ?2 AND carried_to < ?3",
        params![relay.as_slice(), channel.as_slice(), up_to],
    )
    .map_err(storage)?;
    Ok(())
}

/// `relay` holds nothing of `channel`, or holds it anew: nothing is kept
/// of what it was sent, and there is no place in it. Everything the store
/// holds of the channel is to be sent there again, what it refused
/// before among it. Returns whether anything was kept.
pub fn start_again(
    conn: &Connection,
    relay: &[u8; 32],
    channel: &[u8; 32],
) -> Result<bool, CordeliaError> {
    conn.execute(
        "DELETE FROM at_relays_refused WHERE relay = ?1 AND channel = ?2",
        params![relay.as_slice(), channel.as_slice()],
    )
    .map_err(storage)?;
    conn.execute(
        "DELETE FROM at_relays WHERE relay = ?1 AND channel = ?2",
        params![relay.as_slice(), channel.as_slice()],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

/// Keep nothing of `channel`, at any relay: the device holds the channel
/// no more. Returns how many relays something was kept for.
pub fn forget_channel(conn: &Connection, channel: &[u8; 32]) -> Result<usize, CordeliaError> {
    conn.execute(
        "DELETE FROM at_relays_refused WHERE channel = ?1",
        params![channel.as_slice()],
    )
    .map_err(storage)?;
    conn.execute(
        "DELETE FROM at_relays WHERE channel = ?1",
        params![channel.as_slice()],
    )
    .map_err(storage)
}

/// The device is about to send `relay` something of `channel`: it keeps
/// that it did, whatever comes back, and whether or not anything does.
pub fn sending(
    conn: &Connection,
    relay: &[u8; 32],
    channel: &[u8; 32],
) -> Result<(), CordeliaError> {
    row(conn, relay, channel)
}

/// Whether the device keeps anything of `relay` for `channel`: a place, or
/// that it sent it something of the channel, or set out to.
pub fn keeps_any(
    conn: &Connection,
    relay: &[u8; 32],
    channel: &[u8; 32],
) -> Result<bool, CordeliaError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM at_relays WHERE relay = ?1 AND channel = ?2)",
        params![relay.as_slice(), channel.as_slice()],
        |row| row.get(0),
    )
    .map_err(storage)
}

/// Whether the device keeps anything of any relay for `channel`.
pub fn keeps_any_anywhere(conn: &Connection, channel: &[u8; 32]) -> Result<bool, CordeliaError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM at_relays WHERE channel = ?1)",
        params![channel.as_slice()],
        |row| row.get(0),
    )
    .map_err(storage)
}

// ── What a relay refused for room ────────────────────────────────────

/// `relay` had no room for the entry of `channel` at the place `seq` in
/// the store's own order: it is kept, to be sent there again after a
/// wait. Kept twice, it is kept.
///
/// What is kept is for entries that the store holds. An entry that it
/// holds no more waits no more: a later revision took its place, at a
/// place of its own, and is sent as anything new is. Each such row of
/// the relay and the channel goes as this one is written.
pub fn refused(
    conn: &Connection,
    relay: &[u8; 32],
    channel: &[u8; 32],
    seq: i64,
) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM at_relays_refused
         WHERE relay = ?1 AND channel = ?2
           AND seq NOT IN (SELECT seq FROM entries WHERE channel_id = ?2)",
        params![relay.as_slice(), channel.as_slice()],
    )
    .map_err(storage)?;
    conn.execute(
        "INSERT INTO at_relays_refused (relay, channel, seq) VALUES (?1, ?2, ?3)
         ON CONFLICT(relay, channel, seq) DO NOTHING",
        params![relay.as_slice(), channel.as_slice(), seq],
    )
    .map_err(storage)?;
    Ok(())
}

/// The entry of `channel` at the place `seq` waits for `relay` no more:
/// the relay holds it, or will not take it. Returns whether it was
/// waiting.
pub fn not_refused(
    conn: &Connection,
    relay: &[u8; 32],
    channel: &[u8; 32],
    seq: i64,
) -> Result<bool, CordeliaError> {
    conn.execute(
        "DELETE FROM at_relays_refused WHERE relay = ?1 AND channel = ?2 AND seq = ?3",
        params![relay.as_slice(), channel.as_slice(), seq],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

/// The places, in the store's own order, of the entries of `channel`
/// that `relay` had no room for and that wait to be sent there again, in
/// that order: those that the store holds still. Nothing is written.
pub fn waiting_refused(
    conn: &Connection,
    relay: &[u8; 32],
    channel: &[u8; 32],
) -> Result<Vec<i64>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT refused.seq FROM at_relays_refused AS refused
             JOIN entries ON entries.channel_id = refused.channel
                         AND entries.seq = refused.seq
             WHERE refused.relay = ?1 AND refused.channel = ?2
             ORDER BY refused.seq ASC",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map(params![relay.as_slice(), channel.as_slice()], |row| {
            row.get(0)
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

// ── What the device carried ──────────────────────────────────────────

/// How far what the store holds is what the device carried: the store's
/// order as it stood when the device last applied a statement, and 0
/// where it has applied none.
pub fn carried_up_to(conn: &Connection) -> Result<i64, CordeliaError> {
    conn.query_row("SELECT up_to FROM person_carried", [], |row| row.get(0))
        .optional()
        .map(|up_to| up_to.unwrap_or(0))
        .map_err(storage)
}

/// The device has carried what it holds: everything that the store has
/// taken up to now, of its own, in the channel of a name, is what it
/// carried. Called in the transaction that applies a statement, once the
/// carry is written and before anything else is.
pub fn carried_to_here(conn: &Connection) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO person_carried (one, up_to)
         VALUES (1, (SELECT value FROM counters WHERE name = 'entry_seq'))
         ON CONFLICT(one) DO UPDATE SET up_to = excluded.up_to",
        [],
    )
    .map_err(storage)?;
    Ok(())
}

// ── The store's own order, by channel ────────────────────────────────

/// The place, in the store's own order, of the entry of `channel` that it
/// took last. 0 where it holds none.
pub fn last_taken(conn: &Connection, channel: &[u8; 32]) -> Result<i64, CordeliaError> {
    conn.query_row(
        "SELECT COALESCE(MAX(seq), 0) FROM entries WHERE channel_id = ?1",
        params![channel.as_slice()],
        |row| row.get(0),
    )
    .map_err(storage)
}

/// Whether the store holds an entry of `channel` that `author` signed.
pub fn holds_by(
    conn: &Connection,
    channel: &[u8; 32],
    author: &[u8; 32],
) -> Result<bool, CordeliaError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM entries WHERE channel_id = ?1 AND author = ?2)",
        params![channel.as_slice(), author.as_slice()],
        |row| row.get(0),
    )
    .map_err(storage)
}

/// Every channel in which the store holds an entry that `author` signed,
/// in the order of their IDs.
pub fn channels_written_by(
    conn: &Connection,
    author: &[u8; 32],
) -> Result<Vec<[u8; 32]>, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT DISTINCT channel_id FROM entries WHERE author = ?1 ORDER BY channel_id")
        .map_err(storage)?;
    let rows = stmt
        .query_map(params![author.as_slice()], |row| row.get(0))
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db, entries};
    use cordelia_crypto::derive;
    use cordelia_crypto::entry::{CheckedEntry, Entry, Inside, Value};
    use cordelia_crypto::identity::NodeIdentity;

    const RELAY: [u8; 32] = [0xa1; 32];
    const OTHER_RELAY: [u8; 32] = [0xa2; 32];
    const MARK: Mark = [0x4d, 1, 2, 3, 4, 5, 6, 7];
    const OTHER_MARK: Mark = [0x4e, 1, 2, 3, 4, 5, 6, 7];

    fn secret(c: u8) -> [u8; 32] {
        [c; 32]
    }

    fn channel(c: u8) -> [u8; 32] {
        derive::channel_id(&secret(c)).unwrap()
    }

    fn device(d: u8) -> NodeIdentity {
        NodeIdentity::from_seed([d; 32]).unwrap()
    }

    /// An entry of channel `c` that device `d` made under `name` at `rev`.
    fn made(c: u8, d: u8, rev: u64, name: &str) -> CheckedEntry {
        let inside = Inside {
            name: name.to_string(),
            value: Value::Text("a text".to_string()),
            chain: Some(Vec::new()),
        };
        Entry::seal(&secret(c), &device(d), rev, &inside)
            .unwrap()
            .check()
            .unwrap()
    }

    /// Nothing kept is the start of everything. A place is kept with its
    /// mark, for one relay and one channel, and what is kept for another
    /// relay or another channel is another thing.
    #[test]
    fn test_a_place_is_kept_with_its_mark_for_one_relay_and_one_channel() {
        let conn = db::open_in_memory().unwrap();
        assert_eq!(
            kept(&conn, &RELAY, &channel(1)).unwrap(),
            KeptThere::default()
        );
        assert_eq!(KeptThere::default().place, None);

        keep_place(&conn, &RELAY, &channel(1), &MARK, 7).unwrap();
        assert_eq!(
            kept(&conn, &RELAY, &channel(1)).unwrap().place,
            Some((MARK, 7))
        );
        // Another relay, and another channel: nothing.
        assert_eq!(kept(&conn, &OTHER_RELAY, &channel(1)).unwrap().place, None);
        assert_eq!(kept(&conn, &RELAY, &channel(2)).unwrap().place, None);
        // Kept again, it is the later one: also an earlier place, and
        // under another mark.
        keep_place(&conn, &RELAY, &channel(1), &MARK, 9).unwrap();
        keep_place(&conn, &OTHER_RELAY, &channel(1), &OTHER_MARK, 2).unwrap();
        keep_place(&conn, &RELAY, &channel(1), &OTHER_MARK, 3).unwrap();
        assert_eq!(
            kept(&conn, &RELAY, &channel(1)).unwrap().place,
            Some((OTHER_MARK, 3))
        );
        assert_eq!(
            kept(&conn, &OTHER_RELAY, &channel(1)).unwrap().place,
            Some((OTHER_MARK, 2))
        );
        // The furthest place there is, is kept as the furthest the
        // database holds.
        keep_place(&conn, &RELAY, &channel(1), &MARK, u64::MAX).unwrap();
        assert_eq!(
            kept(&conn, &RELAY, &channel(1)).unwrap().place,
            Some((MARK, i64::MAX as u64))
        );
        // The mark of no holding is no mark: it is refused, and what was
        // kept stays.
        assert!(keep_place(&conn, &RELAY, &channel(1), &[0; 8], 1).is_err());
        assert!(keep_place(&conn, &RELAY, &channel(3), &[0; 8], 1).is_err());
        assert_eq!(
            kept(&conn, &RELAY, &channel(1)).unwrap().place,
            Some((MARK, i64::MAX as u64))
        );
    }

    /// How far a relay was sent what the store holds only goes on, and so
    /// does how far it was sent what was carried: each by itself, and
    /// neither touches the place.
    #[test]
    fn test_how_far_a_relay_was_sent_a_channel_only_goes_on() {
        let conn = db::open_in_memory().unwrap();
        keep_place(&conn, &RELAY, &channel(1), &MARK, 4).unwrap();
        sent(&conn, &RELAY, &channel(1), 12).unwrap();
        carried(&conn, &RELAY, &channel(1), 5).unwrap();
        let all = KeptThere {
            place: Some((MARK, 4)),
            sent_to: 12,
            carried_to: 5,
        };
        assert_eq!(kept(&conn, &RELAY, &channel(1)).unwrap(), all);
        // Earlier, and the same: nothing changes, after any one of them.
        for up_to in [0, 5, 11, 12] {
            sent(&conn, &RELAY, &channel(1), up_to).unwrap();
            assert_eq!(kept(&conn, &RELAY, &channel(1)).unwrap(), all, "{up_to}");
        }
        for up_to in [0, 4, 5] {
            carried(&conn, &RELAY, &channel(1), up_to).unwrap();
            assert_eq!(kept(&conn, &RELAY, &channel(1)).unwrap(), all, "{up_to}");
        }
        sent(&conn, &RELAY, &channel(1), 13).unwrap();
        carried(&conn, &RELAY, &channel(1), 6).unwrap();
        assert_eq!(
            kept(&conn, &RELAY, &channel(1)).unwrap(),
            KeptThere {
                place: Some((MARK, 4)),
                sent_to: 13,
                carried_to: 6,
            }
        );
        // With no row yet, each makes one, and there is no place.
        sent(&conn, &OTHER_RELAY, &channel(2), 3).unwrap();
        carried(&conn, &OTHER_RELAY, &channel(3), 2).unwrap();
        assert_eq!(
            kept(&conn, &OTHER_RELAY, &channel(2)).unwrap(),
            KeptThere {
                place: None,
                sent_to: 3,
                carried_to: 0,
            }
        );
        assert_eq!(
            kept(&conn, &OTHER_RELAY, &channel(3)).unwrap(),
            KeptThere {
                place: None,
                sent_to: 0,
                carried_to: 2,
            }
        );
    }

    /// Setting out to send a relay something of a channel is kept,
    /// whatever comes back: for that relay and that channel, and with
    /// nothing else changed.
    #[test]
    fn test_that_a_relay_was_sent_something_of_a_channel_is_kept() {
        let conn = db::open_in_memory().unwrap();
        assert!(!keeps_any(&conn, &RELAY, &channel(1)).unwrap());
        assert!(!keeps_any_anywhere(&conn, &channel(1)).unwrap());
        sending(&conn, &RELAY, &channel(1)).unwrap();
        assert!(keeps_any(&conn, &RELAY, &channel(1)).unwrap());
        assert!(keeps_any_anywhere(&conn, &channel(1)).unwrap());
        assert!(!keeps_any(&conn, &OTHER_RELAY, &channel(1)).unwrap());
        assert!(!keeps_any(&conn, &RELAY, &channel(2)).unwrap());
        assert!(!keeps_any_anywhere(&conn, &channel(2)).unwrap());
        assert_eq!(
            kept(&conn, &RELAY, &channel(1)).unwrap(),
            KeptThere::default()
        );
        // Said again, with something kept: it stays.
        sent(&conn, &RELAY, &channel(1), 12).unwrap();
        keep_place(&conn, &RELAY, &channel(1), &MARK, 4).unwrap();
        sending(&conn, &RELAY, &channel(1)).unwrap();
        assert_eq!(
            kept(&conn, &RELAY, &channel(1)).unwrap(),
            KeptThere {
                place: Some((MARK, 4)),
                sent_to: 12,
                carried_to: 0,
            }
        );
        // A place, and what was sent, are something kept too.
        keep_place(&conn, &OTHER_RELAY, &channel(2), &MARK, 1).unwrap();
        assert!(keeps_any(&conn, &OTHER_RELAY, &channel(2)).unwrap());
        // And nothing is, once the relay holds the channel anew or the
        // device holds it no more.
        start_again(&conn, &RELAY, &channel(1)).unwrap();
        assert!(!keeps_any(&conn, &RELAY, &channel(1)).unwrap());
        forget_channel(&conn, &channel(2)).unwrap();
        assert!(!keeps_any_anywhere(&conn, &channel(2)).unwrap());
    }

    /// Reading again forgets every place, at every relay, and nothing of
    /// what was sent. A relay that holds a channel anew keeps nothing of
    /// it, and a channel that the device holds no more is kept at no
    /// relay.
    #[test]
    fn test_what_is_forgotten_and_what_is_started_again() {
        let conn = db::open_in_memory().unwrap();
        for (relay, c) in [(RELAY, 1), (RELAY, 2), (OTHER_RELAY, 1)] {
            keep_place(&conn, &relay, &channel(c), &MARK, 9).unwrap();
            sent(&conn, &relay, &channel(c), 20).unwrap();
            carried(&conn, &relay, &channel(c), 8).unwrap();
        }
        sent(&conn, &OTHER_RELAY, &channel(2), 20).unwrap();
        let sent_only = KeptThere {
            place: None,
            sent_to: 20,
            carried_to: 8,
        };

        // Three places, and one row that had none.
        assert_eq!(forget_places(&conn).unwrap(), 3);
        for (relay, c) in [(RELAY, 1), (RELAY, 2), (OTHER_RELAY, 1)] {
            assert_eq!(kept(&conn, &relay, &channel(c)).unwrap(), sent_only);
        }
        assert_eq!(forget_places(&conn).unwrap(), 0);

        // One relay holds one channel anew: nothing is kept of it there.
        keep_place(&conn, &RELAY, &channel(1), &MARK, 9).unwrap();
        assert!(start_again(&conn, &RELAY, &channel(1)).unwrap());
        assert!(!start_again(&conn, &RELAY, &channel(1)).unwrap());
        assert_eq!(
            kept(&conn, &RELAY, &channel(1)).unwrap(),
            KeptThere::default()
        );
        assert_eq!(kept(&conn, &RELAY, &channel(2)).unwrap(), sent_only);
        assert_eq!(kept(&conn, &OTHER_RELAY, &channel(1)).unwrap(), sent_only);

        // The device holds a channel no more: it is kept at no relay.
        assert_eq!(forget_channel(&conn, &channel(2)).unwrap(), 2);
        assert_eq!(forget_channel(&conn, &channel(2)).unwrap(), 0);
        for relay in [RELAY, OTHER_RELAY] {
            assert_eq!(
                kept(&conn, &relay, &channel(2)).unwrap(),
                KeptThere::default()
            );
        }
        assert_eq!(kept(&conn, &OTHER_RELAY, &channel(1)).unwrap(), sent_only);
    }

    /// What a relay had no room for is kept by its place in the store's
    /// order, for that relay and that channel, until the relay holds it
    /// or the store holds it no more. A relay that holds a channel anew
    /// keeps nothing of it, and a channel that the device holds no more
    /// is kept at no relay.
    #[test]
    fn test_what_a_relay_refused_for_room_waits_while_the_store_holds_it() {
        let conn = db::open_in_memory().unwrap();
        let rows = || -> i64 {
            conn.query_row("SELECT COUNT(*) FROM at_relays_refused", [], |row| {
                row.get(0)
            })
            .unwrap()
        };
        for name in ["a.md", "b.md", "c.md"] {
            entries::store(&conn, &made(1, 1, 5, name), 100).unwrap();
        }
        entries::store(&conn, &made(2, 1, 5, "a.md"), 100).unwrap();
        assert!(
            waiting_refused(&conn, &RELAY, &channel(1))
                .unwrap()
                .is_empty()
        );

        // Kept in the store's order, whatever the order of the refusals,
        // and once however often it is said.
        for seq in [3, 1, 3] {
            refused(&conn, &RELAY, &channel(1), seq).unwrap();
        }
        refused(&conn, &OTHER_RELAY, &channel(1), 2).unwrap();
        refused(&conn, &RELAY, &channel(2), 4).unwrap();
        assert_eq!(waiting_refused(&conn, &RELAY, &channel(1)).unwrap(), [1, 3]);
        assert_eq!(
            waiting_refused(&conn, &OTHER_RELAY, &channel(1)).unwrap(),
            [2]
        );
        assert_eq!(waiting_refused(&conn, &RELAY, &channel(2)).unwrap(), [4]);
        assert_eq!(rows(), 4);

        // The relay holds one: it waits no more, and the others do.
        assert!(not_refused(&conn, &RELAY, &channel(1), 1).unwrap());
        assert!(!not_refused(&conn, &RELAY, &channel(1), 1).unwrap());
        assert!(!not_refused(&conn, &OTHER_RELAY, &channel(1), 3).unwrap());
        assert_eq!(waiting_refused(&conn, &RELAY, &channel(1)).unwrap(), [3]);
        assert_eq!(rows(), 3);

        // The store holds one no more: a later revision took its place.
        // It waits no more, and asking writes nothing: its row goes when
        // the next refusal of that relay and channel is written.
        entries::store(&conn, &made(1, 1, 6, "c.md"), 100).unwrap();
        assert!(
            waiting_refused(&conn, &RELAY, &channel(1))
                .unwrap()
                .is_empty()
        );
        assert_eq!(rows(), 3);
        refused(&conn, &RELAY, &channel(1), 2).unwrap();
        assert_eq!(waiting_refused(&conn, &RELAY, &channel(1)).unwrap(), [2]);
        assert_eq!(
            rows(),
            3,
            "one written, and the one of the entry that is gone taken out"
        );
        // Another relay's rows, and another channel's, are as they were.
        assert_eq!(
            waiting_refused(&conn, &OTHER_RELAY, &channel(1)).unwrap(),
            [2]
        );
        assert_eq!(waiting_refused(&conn, &RELAY, &channel(2)).unwrap(), [4]);

        // A relay that holds the channel anew is sent all of it: nothing
        // of it waits there apart. Another relay's rows stay.
        sent(&conn, &RELAY, &channel(1), 3).unwrap();
        start_again(&conn, &RELAY, &channel(1)).unwrap();
        assert!(
            waiting_refused(&conn, &RELAY, &channel(1))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            waiting_refused(&conn, &OTHER_RELAY, &channel(1)).unwrap(),
            [2]
        );
        assert_eq!(waiting_refused(&conn, &RELAY, &channel(2)).unwrap(), [4]);
        // And with no row of what was sent, what was refused goes too.
        refused(&conn, &RELAY, &channel(1), 2).unwrap();
        assert!(!start_again(&conn, &RELAY, &channel(1)).unwrap());
        assert!(
            waiting_refused(&conn, &RELAY, &channel(1))
                .unwrap()
                .is_empty()
        );

        // A channel that the device holds no more: at no relay.
        refused(&conn, &RELAY, &channel(1), 2).unwrap();
        forget_channel(&conn, &channel(1)).unwrap();
        assert!(
            waiting_refused(&conn, &RELAY, &channel(1))
                .unwrap()
                .is_empty()
        );
        assert!(
            waiting_refused(&conn, &OTHER_RELAY, &channel(1))
                .unwrap()
                .is_empty()
        );
        assert_eq!(waiting_refused(&conn, &RELAY, &channel(2)).unwrap(), [4]);
        assert_eq!(rows(), 1);
    }

    /// What the device carried is everything the store had taken when it
    /// said so: the store's order then. It has carried nothing until it
    /// says so, and says so again at each statement.
    #[test]
    fn test_what_was_carried_is_what_the_store_had_taken_when_it_was_said() {
        let conn = db::open_in_memory().unwrap();
        assert_eq!(carried_up_to(&conn).unwrap(), 0);
        carried_to_here(&conn).unwrap();
        assert_eq!(carried_up_to(&conn).unwrap(), 0);

        for (n, name) in ["a.md", "b.md", "c.md"].iter().enumerate() {
            entries::store(&conn, &made(1, 1, 5, name), 100 + n as i64).unwrap();
        }
        assert_eq!(carried_up_to(&conn).unwrap(), 0);
        carried_to_here(&conn).unwrap();
        assert_eq!(carried_up_to(&conn).unwrap(), 3);
        // What is taken afterwards is not what was carried.
        entries::store(&conn, &made(1, 1, 5, "d.md"), 200).unwrap();
        entries::store(&conn, &made(1, 1, 6, "a.md"), 200).unwrap();
        assert_eq!(carried_up_to(&conn).unwrap(), 3);
        assert_eq!(last_taken(&conn, &channel(1)).unwrap(), 5);
        carried_to_here(&conn).unwrap();
        assert_eq!(carried_up_to(&conn).unwrap(), 5);
        // One row, whatever is said and however often.
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM person_carried", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1);
    }

    /// The store's own order, by channel, and the channels that a key
    /// wrote in.
    #[test]
    fn test_the_last_entry_taken_of_a_channel_and_the_channels_a_key_wrote_in() {
        let conn = db::open_in_memory().unwrap();
        assert_eq!(last_taken(&conn, &channel(1)).unwrap(), 0);
        assert!(
            channels_written_by(&conn, &device(1).public_key())
                .unwrap()
                .is_empty()
        );
        entries::store(&conn, &made(1, 1, 5, "a.md"), 100).unwrap();
        entries::store(&conn, &made(2, 2, 5, "a.md"), 100).unwrap();
        entries::store(&conn, &made(1, 2, 5, "a.md"), 100).unwrap();
        entries::store(&conn, &made(3, 1, 5, "a.md"), 100).unwrap();
        assert_eq!(last_taken(&conn, &channel(1)).unwrap(), 3);
        assert_eq!(last_taken(&conn, &channel(2)).unwrap(), 2);
        assert_eq!(last_taken(&conn, &channel(3)).unwrap(), 4);
        assert_eq!(last_taken(&conn, &channel(4)).unwrap(), 0);
        // A newer revision takes a later place.
        entries::store(&conn, &made(2, 2, 6, "a.md"), 100).unwrap();
        assert_eq!(last_taken(&conn, &channel(2)).unwrap(), 5);

        let mut of_1 = vec![channel(1), channel(3)];
        of_1.sort();
        let mut of_2 = vec![channel(1), channel(2)];
        of_2.sort();
        assert_eq!(
            channels_written_by(&conn, &device(1).public_key()).unwrap(),
            of_1
        );
        assert_eq!(
            channels_written_by(&conn, &device(2).public_key()).unwrap(),
            of_2
        );
        assert!(
            channels_written_by(&conn, &device(3).public_key())
                .unwrap()
                .is_empty()
        );
        // And whether a channel holds an entry that a key signed.
        for (c, d, holds) in [(1, 1, true), (1, 2, true), (2, 1, false), (3, 2, false)] {
            assert_eq!(
                holds_by(&conn, &channel(c), &device(d).public_key()).unwrap(),
                holds,
                "channel {c}, device {d}"
            );
        }
        assert!(!holds_by(&conn, &channel(4), &device(1).public_key()).unwrap());
    }

    /// The table takes no row that cannot be what a device keeps: a relay
    /// or a channel of another length, a second row for one relay and
    /// channel, a mark of another length or of no holding, and a place or
    /// a count below nothing.
    #[test]
    fn test_the_table_refuses_a_row_that_is_not_what_a_device_keeps() {
        let conn = db::open_in_memory().unwrap();
        let insert = |relay: &[u8], channel: &[u8], mark: Option<&[u8]>, n: [i64; 3]| {
            conn.execute(
                "INSERT INTO at_relays (relay, channel, mark, place, sent_to, carried_to)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![relay, channel, mark, n[0], n[1], n[2]],
            )
        };
        let (r, c) = ([1u8; 32], [2u8; 32]);
        assert_eq!(insert(&r, &c, Some(&MARK), [1, 2, 3]), Ok(1));
        assert!(insert(&r, &c, Some(&MARK), [1, 2, 3]).is_err());
        assert_eq!(insert(&r, &[3u8; 32], None, [0, 0, 0]), Ok(1));
        for bad in [&[1u8; 31][..], &[1u8; 33], &[]] {
            assert!(insert(bad, &[4u8; 32], None, [0, 0, 0]).is_err());
            assert!(insert(&[5u8; 32], bad, None, [0, 0, 0]).is_err());
        }
        for mark in [&[9u8; 7][..], &[9u8; 9], &[], &[0u8; 8]] {
            assert!(
                insert(&[6u8; 32], &c, Some(mark), [0, 0, 0]).is_err(),
                "{mark:?}"
            );
        }
        for n in [[-1, 0, 0], [0, -1, 0], [0, 0, -1]] {
            assert!(insert(&[7u8; 32], &c, None, n).is_err(), "{n:?}");
        }
        // What was carried is one row.
        conn.execute("INSERT INTO person_carried (one, up_to) VALUES (1, 7)", [])
            .unwrap();
        for (one, up_to) in [(1, 8), (2, 8), (0, 8)] {
            assert!(
                conn.execute(
                    "INSERT INTO person_carried (one, up_to) VALUES (?1, ?2)",
                    params![one, up_to],
                )
                .is_err()
            );
        }
        assert!(
            conn.execute("UPDATE person_carried SET up_to = -1", [])
                .is_err()
        );
    }
}
