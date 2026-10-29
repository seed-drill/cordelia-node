//! What a device keeps of channels made anew (decision 2026-10-10 §3.5,
//! §7; decision 2026-10-24, rules 23 to 26): the tables of schema step 26.
//!
//! - **The offers read** (`shared_anew_offers`): for each channel and each
//!   key that wrote an offer there that this device read, what the offer
//!   says, kept apart from the store, so that a key let go keeps its offer
//!   (§6.3, "a quiet key is let go"), and a channel moved from keeps the
//!   keys its offer sealed to ("not moved yet"). The seal for this
//!   device's own key is kept with it, where the offer seals to it.
//! - **The channels this device made anew** (`shared_anew_made`): the old
//!   channel, the new one, the offer's revision, and whether the old
//!   channel's entries wait for the offer to be at each relay of its card.
//! - **The channels not yet clean** (`shared_anew_not_clean`): each shared
//!   channel this device held when it applied a statement that removed a
//!   key, with when; and whether this device owes the channel its making
//!   anew itself, once it has read it (a recovery).
//!
//! Nothing here judges an offer: that is done where these are read
//! (`cordelia_api::shared_anew`). Every time here is the node's.

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

// ── Offers read ──────────────────────────────────────────────────────

/// An offer that this device read in a shared channel (§7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferRow {
    /// The channel it makes anew: the old one.
    pub channel: [u8; 32],
    /// The key that wrote it, in whose slot it is.
    pub maker: [u8; 32],
    /// The revision of the record this device read.
    pub rev: u64,
    /// The time it says it was made, by its maker's clock.
    pub made: u64,
    /// The new channel's ID.
    pub new_channel: [u8; 32],
    /// The new card's relays, as a card holds them.
    pub relays: Vec<u8>,
    /// Each key it seals to, in its order.
    pub sealed_to: Vec<[u8; 32]>,
    /// The seal for this device's key, where it seals to it.
    pub own_seal: Option<Vec<u8>>,
    /// When this device first held this revision of it.
    pub first_held: i64,
    /// Whether a person said, at a terminal, to stay in the old channel
    /// after this device read it (decision 2026-10-24, rule 26).
    pub stayed: bool,
}

fn offer_of(row: &rusqlite::Row<'_>) -> rusqlite::Result<OfferRow> {
    let sealed: Vec<u8> = row.get(6)?;
    Ok(OfferRow {
        channel: row.get(0)?,
        maker: row.get(1)?,
        rev: row.get::<_, i64>(2)? as u64,
        made: row.get::<_, i64>(3)? as u64,
        new_channel: row.get(4)?,
        relays: row.get(5)?,
        sealed_to: sealed.as_chunks::<32>().0.to_vec(),
        own_seal: row.get(7)?,
        first_held: row.get(8)?,
        stayed: row.get::<_, i64>(9)? == 1,
    })
}

const OFFER_COLUMNS: &str = "channel, maker, rev, made, new_channel, relays, sealed_to, \
                             own_seal, first_held, stayed";

/// Keep `offer`, read at its revision: it takes the place of what was kept
/// of that key's record in that channel. A revision this device read before,
/// and a later revision that says the same (the record written again above
/// a relay's other entry), keep its first holding and whether a person
/// stayed after it: a stay is undone only by an offer that says something
/// else.
pub fn keep_offer(conn: &Connection, offer: &OfferRow) -> Result<(), CordeliaError> {
    let kept = offer_from(conn, &offer.channel, &offer.maker)?;
    let (first_held, stayed) = match kept {
        Some(kept)
            if kept.rev == offer.rev
                || (kept.made == offer.made
                    && kept.new_channel == offer.new_channel
                    && kept.relays == offer.relays
                    && kept.sealed_to == offer.sealed_to
                    && kept.own_seal == offer.own_seal) =>
        {
            (kept.first_held, kept.stayed)
        }
        _ => (offer.first_held, offer.stayed),
    };
    let sealed: Vec<u8> = offer.sealed_to.iter().flatten().copied().collect();
    conn.execute(
        &format!(
            "INSERT OR REPLACE INTO shared_anew_offers ({OFFER_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
        ),
        params![
            &offer.channel[..],
            &offer.maker[..],
            offer.rev as i64,
            offer.made as i64,
            &offer.new_channel[..],
            offer.relays,
            sealed,
            offer.own_seal,
            first_held,
            stayed as i64,
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// What was kept of the offer of `maker` in `channel`.
pub fn offer_from(
    conn: &Connection,
    channel: &[u8; 32],
    maker: &[u8; 32],
) -> Result<Option<OfferRow>, CordeliaError> {
    conn.query_row(
        &format!(
            "SELECT {OFFER_COLUMNS} FROM shared_anew_offers WHERE channel = ?1 AND maker = ?2"
        ),
        params![&channel[..], &maker[..]],
        offer_of,
    )
    .optional()
    .map_err(storage)
}

/// The key `maker` wrote an empty record over its offer in `channel`, at a
/// higher revision: it offers nothing there now.
pub fn forget_offer(
    conn: &Connection,
    channel: &[u8; 32],
    maker: &[u8; 32],
) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM shared_anew_offers WHERE channel = ?1 AND maker = ?2",
        params![&channel[..], &maker[..]],
    )
    .map_err(storage)?;
    Ok(())
}

/// Every offer read in `channel`, in the order this device first held them.
pub fn offers_in(conn: &Connection, channel: &[u8; 32]) -> Result<Vec<OfferRow>, CordeliaError> {
    conn.prepare(&format!(
        "SELECT {OFFER_COLUMNS} FROM shared_anew_offers WHERE channel = ?1
             ORDER BY first_held, maker"
    ))
    .map_err(storage)?
    .query_map([&channel[..]], offer_of)
    .map_err(storage)?
    .collect::<Result<_, _>>()
    .map_err(storage)
}

/// Every offer read anywhere whose new channel is `new_channel`.
pub fn offers_into(
    conn: &Connection,
    new_channel: &[u8; 32],
) -> Result<Vec<OfferRow>, CordeliaError> {
    conn.prepare(&format!(
        "SELECT {OFFER_COLUMNS} FROM shared_anew_offers WHERE new_channel = ?1
             ORDER BY first_held, maker"
    ))
    .map_err(storage)?
    .query_map([&new_channel[..]], offer_of)
    .map_err(storage)?
    .collect::<Result<_, _>>()
    .map_err(storage)
}

/// A person said, at a terminal, to stay in `channel`: every offer read
/// there so far is stayed after (decision 2026-10-24, rule 26). Returns
/// how many.
pub fn stay(conn: &Connection, channel: &[u8; 32]) -> Result<usize, CordeliaError> {
    conn.execute(
        "UPDATE shared_anew_offers SET stayed = 1 WHERE channel = ?1",
        [&channel[..]],
    )
    .map_err(storage)
}

/// Every offer read in `channel` goes: the channel is dropped, or forgotten.
pub fn forget_offers_in(conn: &Connection, channel: &[u8; 32]) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM shared_anew_offers WHERE channel = ?1",
        [&channel[..]],
    )
    .map_err(storage)?;
    Ok(())
}

// ── Channels made anew here ──────────────────────────────────────────

/// A channel this device made anew (§7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MadeRow {
    /// The old channel, in which the offer is written.
    pub channel: [u8; 32],
    /// The new channel.
    pub new_channel: [u8; 32],
    /// The offer's revision in the old channel.
    pub rev: u64,
    /// When it was made, by this device's clock.
    pub made_at: i64,
    /// Whether a removal made it (decision 2026-10-24, rule 24).
    pub at_removal: bool,
    /// Whether the old channel's entries wait in the store for the offer
    /// to be at each relay of its card.
    pub delivering: bool,
    /// At a removal, how many keys of the table it left out past the 64
    /// that stay (decision 2026-10-10, property 7).
    pub past_64: u64,
    /// At a removal, how many rows the table had let go, left out.
    pub let_go: u64,
}

fn made_of(row: &rusqlite::Row<'_>) -> rusqlite::Result<MadeRow> {
    Ok(MadeRow {
        channel: row.get(0)?,
        new_channel: row.get(1)?,
        rev: row.get::<_, i64>(2)? as u64,
        made_at: row.get(3)?,
        at_removal: row.get::<_, i64>(4)? == 1,
        delivering: row.get::<_, i64>(5)? == 1,
        past_64: row.get::<_, i64>(6)?.max(0) as u64,
        let_go: row.get::<_, i64>(7)?.max(0) as u64,
    })
}

/// This device made `channel` anew: the offer waits to be delivered.
pub fn made(conn: &Connection, made: &MadeRow) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT OR REPLACE INTO shared_anew_made
             (channel, new_channel, rev, made_at, at_removal, delivering, past_64, let_go)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            &made.channel[..],
            &made.new_channel[..],
            made.rev as i64,
            made.made_at,
            made.at_removal as i64,
            made.delivering as i64,
            i64::try_from(made.past_64).unwrap_or(i64::MAX),
            i64::try_from(made.let_go).unwrap_or(i64::MAX),
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// What this device made of `channel` anew, where it did.
pub fn made_of_channel(
    conn: &Connection,
    channel: &[u8; 32],
) -> Result<Option<MadeRow>, CordeliaError> {
    conn.query_row(
        "SELECT channel, new_channel, rev, made_at, at_removal, delivering, past_64, let_go
             FROM shared_anew_made WHERE channel = ?1",
        [&channel[..]],
        made_of,
    )
    .optional()
    .map_err(storage)
}

/// Every channel this device made anew, oldest first.
pub fn made_all(conn: &Connection) -> Result<Vec<MadeRow>, CordeliaError> {
    conn.prepare(
        "SELECT channel, new_channel, rev, made_at, at_removal, delivering, past_64, let_go
             FROM shared_anew_made ORDER BY made_at, channel",
    )
    .map_err(storage)?
    .query_map([], made_of)
    .map_err(storage)?
    .collect::<Result<_, _>>()
    .map_err(storage)
}

/// The offer in `channel` is delivered, or waits no more.
pub fn delivered(conn: &Connection, channel: &[u8; 32]) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE shared_anew_made SET delivering = 0 WHERE channel = ?1",
        [&channel[..]],
    )
    .map_err(storage)?;
    Ok(())
}

/// What this device made of `channel` anew goes.
pub fn forget_made(conn: &Connection, channel: &[u8; 32]) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM shared_anew_made WHERE channel = ?1",
        [&channel[..]],
    )
    .map_err(storage)?;
    Ok(())
}

// ── Channels not yet clean ───────────────────────────────────────────

/// A channel not yet clean (decision 2026-10-24, rules 23 and 25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotClean {
    pub channel: [u8; 32],
    /// When this device applied the statement that removed a key that held
    /// it.
    pub since: i64,
    /// Whether this device makes it anew itself once it has read it: the
    /// machine of a recovery (decision 2026-10-10 §3.5).
    pub owed: bool,
    /// Whether the removal on this device left it not clean because this
    /// device does not reach its relays: it is made anew on one that does.
    pub unreached: bool,
}

fn not_clean_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NotClean> {
    Ok(NotClean {
        channel: row.get(0)?,
        since: row.get(1)?,
        owed: row.get::<_, i64>(2)? == 1,
        unreached: row.get::<_, i64>(3)? == 1,
    })
}

/// `channel` is not clean from `since`; a mark kept already keeps its time,
/// and is owed where either says so.
pub fn not_clean(
    conn: &Connection,
    channel: &[u8; 32],
    since: i64,
    owed: bool,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO shared_anew_not_clean (channel, since, owed) VALUES (?1, ?2, ?3)
             ON CONFLICT (channel) DO UPDATE SET owed = MAX(owed, excluded.owed)",
        params![&channel[..], since, owed as i64],
    )
    .map_err(storage)?;
    Ok(())
}

/// The mark of `channel`, where it is not clean.
pub fn not_clean_of(
    conn: &Connection,
    channel: &[u8; 32],
) -> Result<Option<NotClean>, CordeliaError> {
    conn.query_row(
        "SELECT channel, since, owed, unreached FROM shared_anew_not_clean WHERE channel = ?1",
        [&channel[..]],
        not_clean_row,
    )
    .optional()
    .map_err(storage)
}

/// Every channel marked not clean.
pub fn not_clean_all(conn: &Connection) -> Result<Vec<NotClean>, CordeliaError> {
    conn.prepare(
        "SELECT channel, since, owed, unreached FROM shared_anew_not_clean
             ORDER BY since, channel",
    )
    .map_err(storage)?
    .query_map([], not_clean_row)
    .map_err(storage)?
    .collect::<Result<_, _>>()
    .map_err(storage)
}

/// The removal on this device left `channel` not clean, since it does not
/// reach its relays (decision 2026-10-24, rule 24): it is made anew on a
/// device that does.
pub fn unreached(conn: &Connection, channel: &[u8; 32]) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE shared_anew_not_clean SET unreached = 1 WHERE channel = ?1",
        [&channel[..]],
    )
    .map_err(storage)?;
    Ok(())
}

/// `channel` is clean, or held no more: its mark goes.
pub fn clean(conn: &Connection, channel: &[u8; 32]) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM shared_anew_not_clean WHERE channel = ?1",
        [&channel[..]],
    )
    .map_err(storage)?;
    Ok(())
}

/// Everything of step 26 goes: the device leaves its person.
pub fn forget_all(conn: &Connection) -> Result<(), CordeliaError> {
    conn.execute_batch(
        "DELETE FROM shared_anew_offers; DELETE FROM shared_anew_made;
         DELETE FROM shared_anew_not_clean;",
    )
    .map_err(storage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::schema::init_db(&conn).unwrap();
        conn
    }

    fn offer(maker: u8, rev: u64) -> OfferRow {
        OfferRow {
            channel: [1; 32],
            maker: [maker; 32],
            rev,
            made: 9,
            new_channel: [2; 32],
            relays: vec![1; 33],
            sealed_to: vec![[3; 32], [4; 32]],
            own_seal: None,
            first_held: 10 + rev as i64,
            stayed: false,
        }
    }

    /// An offer read again at its revision keeps its first holding and a
    /// stay; so does the same offer at a later revision (the record written
    /// again above a relay's other entry: the review of slice 8, low 7); an
    /// offer that says something else is new; an empty record over it ends
    /// it.
    #[test]
    fn an_offer_is_kept_by_its_revision() {
        let conn = conn();
        keep_offer(&conn, &offer(5, 1)).unwrap();
        assert_eq!(stay(&conn, &[1; 32]).unwrap(), 1);
        keep_offer(&conn, &offer(5, 1)).unwrap();
        let kept = offer_from(&conn, &[1; 32], &[5; 32]).unwrap().unwrap();
        assert_eq!((kept.first_held, kept.stayed), (11, true));
        assert_eq!(kept.sealed_to, vec![[3; 32], [4; 32]]);
        keep_offer(&conn, &offer(5, 2)).unwrap();
        let kept = offer_from(&conn, &[1; 32], &[5; 32]).unwrap().unwrap();
        assert_eq!((kept.rev, kept.first_held, kept.stayed), (2, 11, true));
        let other = OfferRow {
            new_channel: [6; 32],
            ..offer(5, 3)
        };
        keep_offer(&conn, &other).unwrap();
        let kept = offer_from(&conn, &[1; 32], &[5; 32]).unwrap().unwrap();
        assert_eq!((kept.rev, kept.first_held, kept.stayed), (3, 13, false));
        assert_eq!(offers_into(&conn, &[6; 32]).unwrap().len(), 1);
        keep_offer(&conn, &offer(5, 4)).unwrap();
        assert_eq!(offers_into(&conn, &[2; 32]).unwrap().len(), 1);
        forget_offer(&conn, &[1; 32], &[5; 32]).unwrap();
        assert!(offers_in(&conn, &[1; 32]).unwrap().is_empty());
    }

    /// A mark of not clean keeps its first time; owed once, it stays owed.
    #[test]
    fn a_mark_of_not_clean_keeps_its_time() {
        let conn = conn();
        not_clean(&conn, &[1; 32], 5, true).unwrap();
        not_clean(&conn, &[1; 32], 9, false).unwrap();
        let mark = not_clean_of(&conn, &[1; 32]).unwrap().unwrap();
        assert_eq!((mark.since, mark.owed, mark.unreached), (5, true, false));
        unreached(&conn, &[1; 32]).unwrap();
        not_clean(&conn, &[1; 32], 9, false).unwrap();
        assert!(not_clean_of(&conn, &[1; 32]).unwrap().unwrap().unreached);
        clean(&conn, &[1; 32]).unwrap();
        assert!(not_clean_all(&conn).unwrap().is_empty());
    }
}
