//! Channel states this node has sent to other members, and whether each
//! member has been seen to hold it (decision 2026-09-30-agent-memory-sync
//! §4.1).
//!
//! A state carries a channel's keys and its member list, and a removal is a
//! state. Sending it once is not enough: a relay can lose it, and the
//! member may be away for weeks. So the newest state sent to each member is
//! remembered here until that member is seen to hold it, and is offered
//! again in the meantime.

use rusqlite::{Connection, params};

use cordelia_core::CordeliaError;

/// The newest state sent to one member of one channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub channel_id: String,
    pub member: [u8; 32],
    pub epoch: u64,
    /// The inbox item that carries it.
    pub item_id: String,
    /// When this epoch was first sent, and when it was last offered (Unix
    /// seconds).
    pub sent_at: i64,
    pub last_offered_at: i64,
    /// How many times it has been offered.
    pub offers: u32,
    pub confirmed_at: Option<i64>,
}

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

fn offer_from_row(row: &rusqlite::Row) -> rusqlite::Result<Offer> {
    let member: Vec<u8> = row.get(1)?;
    Ok(Offer {
        channel_id: row.get(0)?,
        member: member.as_slice().try_into().unwrap_or([0u8; 32]),
        epoch: row.get::<_, i64>(2)?.max(0) as u64,
        item_id: row.get(3)?,
        sent_at: row.get(4)?,
        last_offered_at: row.get(5)?,
        offers: row.get::<_, i64>(6)?.max(0) as u32,
        confirmed_at: row.get(7)?,
    })
}

const COLUMNS: &str =
    "channel_id, member, epoch, item_id, sent_at, last_offered_at, offers, confirmed_at";

/// Remember that the state of `channel_id` at `epoch` was sent to `member`
/// in `item_id`. It replaces what was remembered for that member, unless
/// the member has already confirmed that epoch or a later one: sending the
/// same state again asks for no new confirmation.
pub fn record(
    conn: &Connection,
    channel_id: &str,
    member: &[u8; 32],
    epoch: u64,
    item_id: &str,
    now: i64,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO state_offers
             (channel_id, member, epoch, item_id, sent_at, last_offered_at, offers, confirmed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1, NULL)
         ON CONFLICT(channel_id, member) DO UPDATE SET
             epoch = excluded.epoch,
             item_id = excluded.item_id,
             sent_at = excluded.sent_at,
             last_offered_at = excluded.last_offered_at,
             offers = 1,
             confirmed_at = NULL
         WHERE NOT (state_offers.confirmed_at IS NOT NULL AND state_offers.epoch >= excluded.epoch)",
        params![channel_id, member.as_slice(), epoch as i64, item_id, now],
    )
    .map_err(storage)?;
    Ok(())
}

/// `member` has been seen to hold `channel_id` at `epoch`. Confirms what
/// was sent to it, if that was this epoch or an earlier one. Returns
/// whether anything was waiting for it.
pub fn confirm(
    conn: &Connection,
    channel_id: &str,
    member: &[u8; 32],
    epoch: u64,
    now: i64,
) -> Result<bool, CordeliaError> {
    let changed = conn
        .execute(
            "UPDATE state_offers SET confirmed_at = ?4
             WHERE channel_id = ?1 AND member = ?2 AND epoch <= ?3 AND confirmed_at IS NULL",
            params![channel_id, member.as_slice(), epoch as i64, now],
        )
        .map_err(storage)?;
    Ok(changed > 0)
}

/// What has been sent and not confirmed, oldest first.
pub fn unconfirmed(conn: &Connection) -> Result<Vec<Offer>, CordeliaError> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {COLUMNS} FROM state_offers
             WHERE confirmed_at IS NULL ORDER BY sent_at ASC, channel_id ASC"
        ))
        .map_err(storage)?;
    let rows = stmt.query_map([], offer_from_row).map_err(storage)?;
    let mut offers = Vec::new();
    for row in rows {
        offers.push(row.map_err(storage)?);
    }
    Ok(offers)
}

/// What was last sent to `member` for `channel_id`, if anything.
pub fn get(
    conn: &Connection,
    channel_id: &str,
    member: &[u8; 32],
) -> Result<Option<Offer>, CordeliaError> {
    match conn.query_row(
        &format!("SELECT {COLUMNS} FROM state_offers WHERE channel_id = ?1 AND member = ?2"),
        params![channel_id, member.as_slice()],
        offer_from_row,
    ) {
        Ok(offer) => Ok(Some(offer)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(storage(e)),
    }
}

/// The state sent to `member` for `channel_id` was offered again.
pub fn offered_again(
    conn: &Connection,
    channel_id: &str,
    member: &[u8; 32],
    now: i64,
) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE state_offers SET last_offered_at = ?3, offers = offers + 1
         WHERE channel_id = ?1 AND member = ?2",
        params![channel_id, member.as_slice(), now],
    )
    .map_err(storage)?;
    Ok(())
}

/// Forget what was sent to `member` for `channel_id`: it is no longer a
/// member there.
pub fn forget(conn: &Connection, channel_id: &str, member: &[u8; 32]) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM state_offers WHERE channel_id = ?1 AND member = ?2",
        params![channel_id, member.as_slice()],
    )
    .map_err(storage)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    const CH: &str = "grp_550e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn what_was_sent_waits_until_the_member_holds_it() {
        let conn = db::open_in_memory().unwrap();
        let (b, c) = ([0xB2u8; 32], [0xC3u8; 32]);
        record(&conn, CH, &b, 5, "ci_1", 100).unwrap();
        record(&conn, CH, &c, 5, "ci_2", 100).unwrap();
        assert_eq!(unconfirmed(&conn).unwrap().len(), 2);

        // An earlier epoch confirms nothing; this one or a later one does.
        assert!(!confirm(&conn, CH, &b, 4, 110).unwrap());
        assert!(confirm(&conn, CH, &b, 5, 120).unwrap());
        assert!(
            !confirm(&conn, CH, &b, 6, 130).unwrap(),
            "already confirmed"
        );
        let waiting = unconfirmed(&conn).unwrap();
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].member, c);
        assert_eq!(get(&conn, CH, &b).unwrap().unwrap().confirmed_at, Some(120));

        // The same epoch sent again asks for no new confirmation...
        record(&conn, CH, &b, 5, "ci_3", 140).unwrap();
        assert_eq!(get(&conn, CH, &b).unwrap().unwrap().item_id, "ci_1");
        // ...a later one does, and replaces it.
        record(&conn, CH, &b, 6, "ci_4", 150).unwrap();
        let offer = get(&conn, CH, &b).unwrap().unwrap();
        assert_eq!(
            (offer.epoch, offer.item_id.as_str(), offer.confirmed_at),
            (6, "ci_4", None)
        );

        offered_again(&conn, CH, &c, 200).unwrap();
        let offer = get(&conn, CH, &c).unwrap().unwrap();
        assert_eq!(
            (offer.offers, offer.sent_at, offer.last_offered_at),
            (2, 100, 200)
        );

        forget(&conn, CH, &c).unwrap();
        assert_eq!(get(&conn, CH, &c).unwrap(), None);
    }
}
