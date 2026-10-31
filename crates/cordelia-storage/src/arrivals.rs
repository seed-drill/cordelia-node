//! The arrivals of each file (decision 2026-10-24 (removal), rule 7).
//!
//! When the door stores an entry in the channel of a name, each arrival it
//! makes is kept: the version, where another key than the device's own
//! signed it, and each link of its chain that stands there more times than
//! in any chain of the file stored before. An arrival is a key (its first
//! 16 bytes, as a link names a key) and, for a link, the link's hash and
//! how many times it stands. They are kept by the store event that made
//! them ([`Stored`]), with the generation the device was in, when it stored
//! the entry, and the version that was current in the file before it: what
//! a carry goes back to where it cuts that arrival.
//!
//! A file is its channel and slot. At a carry its arrivals go with it to
//! the new channel and slot ([`move_file`]), and the versions to go back to
//! are sealed again there by the caller ([`set_before`]). At most
//! `MAX_FILE_ARRIVALS` a file: past it the oldest events go first, and what
//! went is kept as the newest time of each generation's, with the version
//! before the first event of it that went ([`Dropped`]).
//!
//! Nothing here decides what is cut: that is the carry's.

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;
use cordelia_core::protocol::MAX_FILE_ARRIVALS;
use cordelia_crypto::entry::Entry;

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

/// One arrival of a store event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arrival {
    /// The first 16 bytes of the key: the version's signer, or the link's.
    pub signer: [u8; 16],
    /// The link's hash, for a link; `None` for a version.
    pub link: Option<[u8; 16]>,
    /// How many times the link stands in the chain it arrived in; 1 for a
    /// version.
    pub times: u32,
}

/// An entry that the door stored in a file and that made arrivals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    /// Its place among the events of every file, in the order they were
    /// kept.
    pub place: i64,
    /// The generation it came in: the change the device followed, by its
    /// statement's number and hash.
    pub number: u64,
    pub hash: [u8; 16],
    /// When the device stored it, by its own clock.
    pub stored_at: i64,
    /// Where its chain was full, the other keys that its links name: a
    /// removed key's link among them is cut all the same.
    pub full_signers: Vec<[u8; 16]>,
    /// Whether its chain may have dropped what it was written after
    /// ([`noted_unknown`]): it is judged as an arrival of every removed key.
    pub unknown: bool,
    /// The version that was current in the file before it, as one entry:
    /// `None` where there was none.
    pub before: Option<Entry>,
    /// The ID of the entry it stored, as sealed where the file is now:
    /// `None` where no entry the store holds, or a carry sealed again, is
    /// that entry. A version gone back to counts as brought where it is
    /// one of these (decision 2026-10-24 (removal), rule 7).
    pub stored_id: Option<[u8; 32]>,
    pub arrivals: Vec<Arrival>,
}

/// What went past the bound, for one generation of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropped {
    pub number: u64,
    pub hash: [u8; 16],
    /// The newest time an event that went was stored.
    pub newest_at: i64,
    /// The place of the first event of this generation that went.
    pub first_place: i64,
    /// The version that was current in the file before that event, as one
    /// entry: `None` where there was none. Where what went is cut, the file
    /// goes back to it, and not to before the oldest event kept, which may
    /// be a removed key's own.
    pub before: Option<Entry>,
    /// The ID of the entry that first event stored, as [`Stored::stored_id`].
    pub first_stored_id: Option<[u8; 32]>,
}

/// The entry of the six columns from `at` (`before_author` to
/// `before_channel_sig`) of a row, in the file `slot` of `channel`.
fn before_of(
    row: &rusqlite::Row<'_>,
    at: usize,
    channel: &[u8; 32],
    slot: &[u8; 32],
) -> rusqlite::Result<Option<Entry>> {
    let author: Option<Vec<u8>> = row.get(at)?;
    let Some(author) = author.and_then(|a| <[u8; 32]>::try_from(a).ok()) else {
        return Ok(None);
    };
    let author_sig: Vec<u8> = row.get(at + 4)?;
    let channel_sig: Vec<u8> = row.get(at + 5)?;
    let (Ok(author_signature), Ok(channel_signature)) = (
        <[u8; 64]>::try_from(author_sig),
        <[u8; 64]>::try_from(channel_sig),
    ) else {
        return Ok(None);
    };
    Ok(Some(Entry {
        channel: *channel,
        slot: *slot,
        author,
        rev: row.get::<_, i64>(at + 1)?.max(0) as u64,
        delete: row.get::<_, i64>(at + 2)? != 0,
        content: row.get(at + 3)?,
        author_signature,
        channel_signature,
    }))
}

/// An entry's ID, as a column holds it: `None` where it holds none, or
/// what is no ID.
fn id_of(column: Option<Vec<u8>>) -> Option<[u8; 32]> {
    column.and_then(|id| id.try_into().ok())
}

/// Keep a store event of the file `slot` in `channel` and its arrivals,
/// and keep the file to its bound. `stored_id` is the ID of the entry it
/// stored. Returns its place.
///
/// **It is stamped no earlier than the newest event kept,** of any file
/// (the second read of slice 8, a low finding): `stored_at` is the device's
/// clock, and a clock stepped back would otherwise stamp a late arrival
/// before a removal's cut time.
#[allow(clippy::too_many_arguments)]
pub fn note(
    conn: &Connection,
    channel: &[u8; 32],
    slot: &[u8; 32],
    number: u64,
    hash: &[u8; 16],
    stored_at: i64,
    full_signers: &[[u8; 16]],
    before: Option<&Entry>,
    stored_id: Option<&[u8; 32]>,
    arrivals: &[Arrival],
) -> Result<i64, CordeliaError> {
    conn.execute_batch("SAVEPOINT file_arrivals")
        .map_err(storage)?;
    let noted = (|| {
        let newest: Option<i64> = conn.query_row(
            "SELECT MAX(at) FROM (SELECT MAX(stored_at) AS at FROM file_arrivals_stored
                                  UNION ALL SELECT MAX(newest_at) FROM file_arrivals_dropped)",
            [],
            |row| row.get(0),
        )?;
        let stored_at = newest.map_or(stored_at, |newest| stored_at.max(newest));
        let full = (!full_signers.is_empty()).then(|| full_signers.concat());
        conn.execute(
            "INSERT INTO file_arrivals_stored (channel_id, slot, number, hash, stored_at,
                 full_signers, before_author, before_rev, before_delete, before_content,
                 before_author_sig, before_channel_sig, stored_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                channel.as_slice(),
                slot.as_slice(),
                i64::try_from(number).unwrap_or(i64::MAX),
                hash.as_slice(),
                stored_at,
                full,
                before.map(|entry| entry.author.to_vec()),
                before.map(|entry| i64::try_from(entry.rev).unwrap_or(i64::MAX)),
                before.map(|entry| entry.delete),
                before.map(|entry| entry.content.clone()),
                before.map(|entry| entry.author_signature.to_vec()),
                before.map(|entry| entry.channel_signature.to_vec()),
                stored_id.map(|id| id.to_vec()),
            ],
        )?;
        let place = conn.last_insert_rowid();
        for arrival in arrivals {
            conn.execute(
                "INSERT INTO file_arrivals (stored, signer, link_hash, times)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    place,
                    arrival.signer.as_slice(),
                    arrival.link.map(|hash| hash.to_vec()),
                    i64::from(arrival.times.max(1)),
                ],
            )?;
        }
        keep_to_the_bound(conn, channel, slot)?;
        Ok(place)
    })();
    let end = match noted {
        Ok(_) => "RELEASE file_arrivals",
        Err(_) => "ROLLBACK TO file_arrivals; RELEASE file_arrivals",
    };
    conn.execute_batch(end).map_err(storage)?;
    noted.map_err(storage)
}

/// The event at `place` ([`note`]) stored an entry whose chain may have
/// dropped what it was written after (decision 2026-10-24 (removal), rule
/// 7): it was missing, or full, or the index's (the fourth read of slice
/// 8).
/// A removed key's link may have fallen off it, so a carry judges it as an
/// arrival of every removed key.
pub fn noted_unknown(conn: &Connection, place: i64) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE file_arrivals_stored SET unknown = 1 WHERE place = ?1",
        params![place],
    )
    .map(|_| ())
    .map_err(storage)
}

/// How a file counts toward its bound: each arrival, and an event that
/// has none of its own (its chain was full) as one.
fn counted(conn: &Connection, channel: &[u8; 32], slot: &[u8; 32]) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COALESCE(SUM(MAX(1, (SELECT COUNT(*) FROM file_arrivals a
                                     WHERE a.stored = s.place))), 0)
         FROM file_arrivals_stored s WHERE s.channel_id = ?1 AND s.slot = ?2",
        params![channel.as_slice(), slot.as_slice()],
        |row| row.get(0),
    )
}

/// Past `MAX_FILE_ARRIVALS`, the oldest events of the file go, whole, and
/// the newest time of what went is kept for each generation.
fn keep_to_the_bound(
    conn: &Connection,
    channel: &[u8; 32],
    slot: &[u8; 32],
) -> rusqlite::Result<()> {
    while counted(conn, channel, slot)? > MAX_FILE_ARRIVALS as i64 {
        let oldest: Option<i64> = conn
            .query_row(
                "SELECT place FROM file_arrivals_stored
                 WHERE channel_id = ?1 AND slot = ?2 ORDER BY place LIMIT 1",
                params![channel.as_slice(), slot.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(place) = oldest else {
            return Ok(());
        };
        // The first event of a generation that goes keeps the version
        // before it with what went: a later one leaves it as it was.
        conn.execute(
            "INSERT INTO file_arrivals_dropped (channel_id, slot, number, hash, newest_at,
                 first_place, before_author, before_rev, before_delete, before_content,
                 before_author_sig, before_channel_sig, first_stored_id)
             SELECT channel_id, slot, number, hash, stored_at, place, before_author,
                    before_rev, before_delete, before_content, before_author_sig,
                    before_channel_sig, stored_id
             FROM file_arrivals_stored WHERE place = ?1
             ON CONFLICT(channel_id, slot, number, hash)
             DO UPDATE SET newest_at = MAX(newest_at, excluded.newest_at)",
            params![place],
        )?;
        drop_event(conn, place)?;
    }
    Ok(())
}

fn drop_event(conn: &Connection, place: i64) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM file_arrivals WHERE stored = ?1",
        params![place],
    )?;
    conn.execute(
        "DELETE FROM file_arrivals_stored WHERE place = ?1",
        params![place],
    )?;
    Ok(())
}

/// The store events of the file `slot` in `channel`, the oldest first,
/// each with its arrivals; and what went past the bound.
pub fn of_file(
    conn: &Connection,
    channel: &[u8; 32],
    slot: &[u8; 32],
) -> Result<(Vec<Stored>, Vec<Dropped>), CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT place, number, hash, stored_at, full_signers, before_author, before_rev,
                    before_delete, before_content, before_author_sig, before_channel_sig,
                    stored_id, unknown
             FROM file_arrivals_stored WHERE channel_id = ?1 AND slot = ?2 ORDER BY place",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map(params![channel.as_slice(), slot.as_slice()], |row| {
            let full: Option<Vec<u8>> = row.get(4)?;
            let before = before_of(row, 5, channel, slot)?;
            Ok(Stored {
                place: row.get(0)?,
                number: row.get::<_, i64>(1)?.max(0) as u64,
                hash: row.get::<_, Vec<u8>>(2)?.try_into().unwrap_or_default(),
                stored_at: row.get(3)?,
                full_signers: full
                    .map(|bytes| bytes.as_chunks::<16>().0.to_vec())
                    .unwrap_or_default(),
                before,
                stored_id: id_of(row.get(11)?),
                unknown: row.get(12)?,
                arrivals: Vec::new(),
            })
        })
        .map_err(storage)?;
    let mut events = rows.collect::<Result<Vec<_>, _>>().map_err(storage)?;
    let mut arrivals = conn
        .prepare("SELECT signer, link_hash, times FROM file_arrivals WHERE stored = ?1")
        .map_err(storage)?;
    for event in &mut events {
        let rows = arrivals
            .query_map(params![event.place], |row| {
                let signer: Vec<u8> = row.get(0)?;
                let link: Option<Vec<u8>> = row.get(1)?;
                Ok(Arrival {
                    signer: signer.try_into().unwrap_or_default(),
                    link: link.and_then(|hash| hash.try_into().ok()),
                    times: row.get::<_, i64>(2)?.clamp(1, u32::MAX as i64) as u32,
                })
            })
            .map_err(storage)?;
        event.arrivals = rows.collect::<Result<Vec<_>, _>>().map_err(storage)?;
    }
    let mut stmt = conn
        .prepare(
            "SELECT number, hash, newest_at, first_place, before_author, before_rev,
                    before_delete, before_content, before_author_sig, before_channel_sig,
                    first_stored_id
             FROM file_arrivals_dropped
             WHERE channel_id = ?1 AND slot = ?2 ORDER BY first_place",
        )
        .map_err(storage)?;
    let dropped = stmt
        .query_map(params![channel.as_slice(), slot.as_slice()], |row| {
            Ok(Dropped {
                number: row.get::<_, i64>(0)?.max(0) as u64,
                hash: row.get::<_, Vec<u8>>(1)?.try_into().unwrap_or_default(),
                newest_at: row.get(2)?,
                first_place: row.get(3)?,
                before: before_of(row, 4, channel, slot)?,
                first_stored_id: id_of(row.get(10)?),
            })
        })
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    Ok((events, dropped))
}

/// The most times the link `hash` of `signer` stood in an arrival of the
/// file: 0 where it never arrived.
pub fn link_times(
    conn: &Connection,
    channel: &[u8; 32],
    slot: &[u8; 32],
    hash: &[u8; 16],
    signer: &[u8; 16],
) -> Result<u32, CordeliaError> {
    conn.query_row(
        "SELECT COALESCE(MAX(a.times), 0) FROM file_arrivals a
         JOIN file_arrivals_stored s ON s.place = a.stored
         WHERE s.channel_id = ?1 AND s.slot = ?2 AND a.link_hash = ?3 AND a.signer = ?4",
        params![
            channel.as_slice(),
            slot.as_slice(),
            hash.as_slice(),
            signer.as_slice()
        ],
        |row| row.get::<_, i64>(0),
    )
    .map(|times| times.clamp(0, u32::MAX as i64) as u32)
    .map_err(storage)
}

/// Keep no event of the file from `place` on: what a carry left out.
pub fn drop_from(
    conn: &Connection,
    channel: &[u8; 32],
    slot: &[u8; 32],
    place: i64,
) -> Result<usize, CordeliaError> {
    let places: Vec<i64> = {
        let mut stmt = conn
            .prepare(
                "SELECT place FROM file_arrivals_stored
                 WHERE channel_id = ?1 AND slot = ?2 AND place >= ?3",
            )
            .map_err(storage)?;
        stmt.query_map(params![channel.as_slice(), slot.as_slice(), place], |row| {
            row.get(0)
        })
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?
    };
    for place in &places {
        drop_event(conn, *place).map_err(storage)?;
    }
    Ok(places.len())
}

/// Keep no more what went past the bound in the file: a carry that cut
/// back before every event left it out.
pub fn forget_dropped(
    conn: &Connection,
    channel: &[u8; 32],
    slot: &[u8; 32],
) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM file_arrivals_dropped WHERE channel_id = ?1 AND slot = ?2",
        params![channel.as_slice(), slot.as_slice()],
    )
    .map(|_| ())
    .map_err(storage)
}

/// The version to go back to before the event at `place`, sealed again
/// where the file now is (`None`: none).
pub fn set_before(
    conn: &Connection,
    place: i64,
    before: Option<&Entry>,
) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE file_arrivals_stored SET before_author = ?2, before_rev = ?3,
             before_delete = ?4, before_content = ?5, before_author_sig = ?6,
             before_channel_sig = ?7
         WHERE place = ?1",
        params![
            place,
            before.map(|entry| entry.author.to_vec()),
            before.map(|entry| i64::try_from(entry.rev).unwrap_or(i64::MAX)),
            before.map(|entry| entry.delete),
            before.map(|entry| entry.content.clone()),
            before.map(|entry| entry.author_signature.to_vec()),
            before.map(|entry| entry.channel_signature.to_vec()),
        ],
    )
    .map(|_| ())
    .map_err(storage)
}

/// The version to go back to before what went past the bound of the file
/// `slot` in `channel`, in the generation `number` and `hash`, sealed
/// again where the file now is (`None`: none).
pub fn set_dropped_before(
    conn: &Connection,
    channel: &[u8; 32],
    slot: &[u8; 32],
    number: u64,
    hash: &[u8; 16],
    before: Option<&Entry>,
) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE file_arrivals_dropped SET before_author = ?5, before_rev = ?6,
             before_delete = ?7, before_content = ?8, before_author_sig = ?9,
             before_channel_sig = ?10
         WHERE channel_id = ?1 AND slot = ?2 AND number = ?3 AND hash = ?4",
        params![
            channel.as_slice(),
            slot.as_slice(),
            i64::try_from(number).unwrap_or(i64::MAX),
            hash.as_slice(),
            before.map(|entry| entry.author.to_vec()),
            before.map(|entry| i64::try_from(entry.rev).unwrap_or(i64::MAX)),
            before.map(|entry| entry.delete),
            before.map(|entry| entry.content.clone()),
            before.map(|entry| entry.author_signature.to_vec()),
            before.map(|entry| entry.channel_signature.to_vec()),
        ],
    )
    .map(|_| ())
    .map_err(storage)
}

/// The ID of the entry that the event at `place` stored, as sealed where
/// the file now is (`None`: no entry is that one any more).
pub fn set_stored_id(
    conn: &Connection,
    place: i64,
    stored_id: Option<&[u8; 32]>,
) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE file_arrivals_stored SET stored_id = ?2 WHERE place = ?1",
        params![place, stored_id.map(|id| id.to_vec())],
    )
    .map(|_| ())
    .map_err(storage)
}

/// The same, for the first event that went past the bound of the file
/// `slot` in `channel`, in the generation `number` and `hash`.
pub fn set_dropped_stored_id(
    conn: &Connection,
    channel: &[u8; 32],
    slot: &[u8; 32],
    number: u64,
    hash: &[u8; 16],
    stored_id: Option<&[u8; 32]>,
) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE file_arrivals_dropped SET first_stored_id = ?5
         WHERE channel_id = ?1 AND slot = ?2 AND number = ?3 AND hash = ?4",
        params![
            channel.as_slice(),
            slot.as_slice(),
            i64::try_from(number).unwrap_or(i64::MAX),
            hash.as_slice(),
            stored_id.map(|id| id.to_vec()),
        ],
    )
    .map(|_| ())
    .map_err(storage)
}

/// The file `from_slot` in `from` is the file `to_slot` in `to` from now
/// on, with every event and what went past its bound: a carry (rule 7).
pub fn move_file(
    conn: &Connection,
    from: &[u8; 32],
    from_slot: &[u8; 32],
    to: &[u8; 32],
    to_slot: &[u8; 32],
) -> Result<(), CordeliaError> {
    for table in ["file_arrivals_stored", "file_arrivals_dropped"] {
        conn.execute(
            &format!(
                "UPDATE {table} SET channel_id = ?3, slot = ?4
                 WHERE channel_id = ?1 AND slot = ?2"
            ),
            params![
                from.as_slice(),
                from_slot.as_slice(),
                to.as_slice(),
                to_slot.as_slice()
            ],
        )
        .map_err(storage)?;
    }
    Ok(())
}

/// A conflict copy that a folder made and has not yet published
/// (decision 2026-10-24 (removal), rule 7): the file of its name, the
/// folder, its name, and the chain of the text it keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Copy {
    pub slot: [u8; 32],
    pub folder: String,
    pub key: String,
    /// Each link as its hash and then its signer, 16 bytes each.
    pub chain: Vec<[u8; 32]>,
}

/// A folder (`folder`) makes `key`, the file `to_slot` in `channel`, a
/// conflict copy of the file `from_slot` there, keeping a text written
/// after `chain`: every event of the file and what went past its bound are
/// the copy's too from now on, each with no version to go back to (the copy
/// held none), and the copy is kept as not yet published. Its first version
/// is written after `chain` ([`copy_chain`]). All of it, or none.
///
/// **`None`: what the text was written after is not known** (the folder's
/// record names no signer, or no chain): the copy is kept as one that is
/// never published ([`copy_held`]; the third read of slice 8, its second
/// low finding).
pub fn copy_file(
    conn: &Connection,
    channel: &[u8; 32],
    from_slot: &[u8; 32],
    to_slot: &[u8; 32],
    folder: &str,
    key: &str,
    chain: Option<&[[u8; 32]]>,
) -> Result<(), CordeliaError> {
    let held = chain.is_none();
    let chain = chain.unwrap_or_default();
    conn.execute_batch("SAVEPOINT file_copy").map_err(storage)?;
    let copied = (|| -> rusqlite::Result<()> {
        let places: Vec<i64> = {
            let mut stmt = conn.prepare(
                "SELECT place FROM file_arrivals_stored
                 WHERE channel_id = ?1 AND slot = ?2 ORDER BY place",
            )?;
            stmt.query_map(params![channel.as_slice(), from_slot.as_slice()], |row| {
                row.get(0)
            })?
            .collect::<Result<_, _>>()?
        };
        for place in places {
            conn.execute(
                "INSERT INTO file_arrivals_stored (channel_id, slot, number, hash, stored_at,
                     full_signers, unknown)
                 SELECT channel_id, ?2, number, hash, stored_at, full_signers, unknown
                 FROM file_arrivals_stored WHERE place = ?1",
                params![place, to_slot.as_slice()],
            )?;
            let copy = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO file_arrivals (stored, signer, link_hash, times)
                 SELECT ?2, signer, link_hash, times FROM file_arrivals WHERE stored = ?1",
                params![place, copy],
            )?;
        }
        conn.execute(
            "INSERT INTO file_arrivals_dropped (channel_id, slot, number, hash, newest_at,
                 first_place)
             SELECT channel_id, ?3, number, hash, newest_at, first_place
             FROM file_arrivals_dropped WHERE channel_id = ?1 AND slot = ?2
             ON CONFLICT(channel_id, slot, number, hash)
             DO UPDATE SET newest_at = MAX(newest_at, excluded.newest_at),
                           first_place = MIN(first_place, excluded.first_place),
                           before_author = NULL, before_rev = NULL, before_delete = NULL,
                           before_content = NULL, before_author_sig = NULL,
                           before_channel_sig = NULL, first_stored_id = NULL",
            params![channel.as_slice(), from_slot.as_slice(), to_slot.as_slice()],
        )?;
        keep_to_the_bound(conn, channel, to_slot)?;
        conn.execute(
            "INSERT INTO file_copies (channel_id, slot, folder, key, chain, held)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(channel_id, slot) DO UPDATE SET folder = excluded.folder,
                 key = excluded.key, chain = excluded.chain, held = excluded.held",
            params![
                channel.as_slice(),
                to_slot.as_slice(),
                folder,
                key,
                chain.concat(),
                held
            ],
        )?;
        Ok(())
    })();
    let end = match copied {
        Ok(()) => "RELEASE file_copy",
        Err(_) => "ROLLBACK TO file_copy; RELEASE file_copy",
    };
    conn.execute_batch(end).map_err(storage)?;
    copied.map_err(storage)
}

/// The chain that the first version of the conflict copy in the file
/// `slot` of `channel` is written after, where the copy is not yet
/// published ([`copy_file`]): `None` where it is no such copy.
pub fn copy_chain(
    conn: &Connection,
    channel: &[u8; 32],
    slot: &[u8; 32],
) -> Result<Option<Vec<[u8; 32]>>, CordeliaError> {
    let chain: Option<Vec<u8>> = conn
        .query_row(
            "SELECT chain FROM file_copies WHERE channel_id = ?1 AND slot = ?2",
            params![channel.as_slice(), slot.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    Ok(chain.map(|chain| chain.as_chunks::<32>().0.to_vec()))
}

/// Whether the conflict copy in the file `slot` of `channel` is one whose
/// text's history was not known when it was made ([`copy_file`]): it is
/// never published. A carry that leaves it out puts it back to none; one
/// that does not moves it, still so.
pub fn copy_held(
    conn: &Connection,
    channel: &[u8; 32],
    slot: &[u8; 32],
) -> Result<bool, CordeliaError> {
    let held: Option<bool> = conn
        .query_row(
            "SELECT held FROM file_copies WHERE channel_id = ?1 AND slot = ?2",
            params![channel.as_slice(), slot.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    Ok(held == Some(true))
}

/// The conflict copy in the file `slot` of `channel` is published, or put
/// back: it is kept as a copy not yet published no more.
pub fn copy_done(
    conn: &Connection,
    channel: &[u8; 32],
    slot: &[u8; 32],
) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM file_copies WHERE channel_id = ?1 AND slot = ?2",
        params![channel.as_slice(), slot.as_slice()],
    )
    .map(|_| ())
    .map_err(storage)
}

/// Every conflict copy not yet published in `channel`.
pub fn copies_of_channel(
    conn: &Connection,
    channel: &[u8; 32],
) -> Result<Vec<Copy>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT slot, folder, key, chain FROM file_copies WHERE channel_id = ?1
             ORDER BY folder, key",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map(params![channel.as_slice()], |row| {
            let slot: Vec<u8> = row.get(0)?;
            let chain: Vec<u8> = row.get(3)?;
            Ok(Copy {
                slot: slot.try_into().unwrap_or_default(),
                folder: row.get(1)?,
                key: row.get(2)?,
                chain: chain.as_chunks::<32>().0.to_vec(),
            })
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// The conflict copy not yet published in the file `slot` of `channel` is
/// the one in the file `to_slot` of `to` from now on, with its arrivals: a
/// carry (rule 7).
pub fn move_copy(
    conn: &Connection,
    channel: &[u8; 32],
    slot: &[u8; 32],
    to: &[u8; 32],
    to_slot: &[u8; 32],
) -> Result<(), CordeliaError> {
    move_file(conn, channel, slot, to, to_slot)?;
    conn.execute(
        "UPDATE file_copies SET channel_id = ?3, slot = ?4 WHERE channel_id = ?1 AND slot = ?2",
        params![
            channel.as_slice(),
            slot.as_slice(),
            to.as_slice(),
            to_slot.as_slice()
        ],
    )
    .map(|_| ())
    .map_err(storage)
}

/// Every file that holds an event or what went past its bound in
/// `channel`: a conflict copy not yet published holds no entry, and is one
/// of them.
pub fn files_of_channel(
    conn: &Connection,
    channel: &[u8; 32],
) -> Result<Vec<[u8; 32]>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT slot FROM file_arrivals_stored WHERE channel_id = ?1
             UNION SELECT slot FROM file_arrivals_dropped WHERE channel_id = ?1
             ORDER BY 1",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map(params![channel.as_slice()], |row| {
            let slot: Vec<u8> = row.get(0)?;
            Ok(slot.try_into().unwrap_or_default())
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Keep nothing of the files of `channel`: it was left, or dropped.
pub fn forget_channel(conn: &Connection, channel: &[u8; 32]) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM file_arrivals WHERE stored IN
             (SELECT place FROM file_arrivals_stored WHERE channel_id = ?1)",
        params![channel.as_slice()],
    )
    .map_err(storage)?;
    for table in [
        "file_arrivals_stored",
        "file_arrivals_dropped",
        "file_copies",
    ] {
        conn.execute(
            &format!("DELETE FROM {table} WHERE channel_id = ?1"),
            params![channel.as_slice()],
        )
        .map_err(storage)?;
    }
    Ok(())
}

/// Keep nothing of any file: the device leaves its phrase.
pub fn forget_all(conn: &Connection) -> Result<(), CordeliaError> {
    for table in [
        "file_arrivals",
        "file_arrivals_stored",
        "file_arrivals_dropped",
        "file_copies",
    ] {
        conn.execute(&format!("DELETE FROM {table}"), [])
            .map_err(storage)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn arrival(signer: u8) -> Arrival {
        Arrival {
            signer: [signer; 16],
            link: None,
            times: 1,
        }
    }

    /// Events are kept by file, with their arrivals and the version
    /// before, and go with the file at a carry.
    #[test]
    fn test_arrivals_are_kept_by_file_and_moved_with_it() {
        let conn = db::open_in_memory().unwrap();
        let (c, s) = ([1u8; 32], [2u8; 32]);
        let before = Entry {
            channel: c,
            slot: s,
            author: [7; 32],
            rev: 3,
            delete: false,
            content: vec![1, 2, 3],
            author_signature: [8; 64],
            channel_signature: [9; 64],
        };
        let link = Arrival {
            signer: [5; 16],
            link: Some([6; 16]),
            times: 2,
        };
        let place = note(
            &conn,
            &c,
            &s,
            2,
            &[2; 16],
            100,
            &[],
            Some(&before),
            Some(&[3; 32]),
            &[arrival(5), link],
        )
        .unwrap();
        note(&conn, &c, &s, 2, &[2; 16], 101, &[[4; 16]], None, None, &[]).unwrap();
        assert_eq!(link_times(&conn, &c, &s, &[6; 16], &[5; 16]).unwrap(), 2);
        assert_eq!(link_times(&conn, &c, &s, &[6; 16], &[4; 16]).unwrap(), 0);
        let (events, dropped) = of_file(&conn, &c, &s).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].place, place);
        assert_eq!(events[0].before.as_ref(), Some(&before));
        assert_eq!(events[0].arrivals, vec![arrival(5), link]);
        assert_eq!(events[0].stored_id, Some([3; 32]));
        assert_eq!(events[1].before, None);
        assert_eq!(events[1].stored_id, None);
        assert_eq!(events[1].full_signers, vec![[4; 16]]);
        assert!(dropped.is_empty());

        move_file(&conn, &c, &s, &[3; 32], &[4; 32]).unwrap();
        assert!(of_file(&conn, &c, &s).unwrap().0.is_empty());
        assert_eq!(of_file(&conn, &[3; 32], &[4; 32]).unwrap().0.len(), 2);
        assert_eq!(drop_from(&conn, &[3; 32], &[4; 32], place + 1).unwrap(), 1);
        forget_channel(&conn, &[3; 32]).unwrap();
        assert!(of_file(&conn, &[3; 32], &[4; 32]).unwrap().0.is_empty());
    }

    /// An event is stamped no earlier than the newest kept, of any file:
    /// a clock stepped back stamps nothing before what came already.
    #[test]
    fn test_an_event_is_stamped_no_earlier_than_the_newest_kept() {
        let conn = db::open_in_memory().unwrap();
        let (c, s) = ([1u8; 32], [2u8; 32]);
        note(
            &conn,
            &c,
            &s,
            2,
            &[2; 16],
            100,
            &[],
            None,
            None,
            &[arrival(5)],
        )
        .unwrap();
        note(
            &conn,
            &c,
            &[3; 32],
            2,
            &[2; 16],
            40,
            &[],
            None,
            None,
            &[arrival(5)],
        )
        .unwrap();
        note(
            &conn,
            &c,
            &s,
            2,
            &[2; 16],
            150,
            &[],
            None,
            None,
            &[arrival(5)],
        )
        .unwrap();
        let at = |slot: &[u8; 32]| -> Vec<i64> {
            of_file(&conn, &c, slot)
                .unwrap()
                .0
                .iter()
                .map(|event| event.stored_at)
                .collect()
        };
        assert_eq!(at(&s), [100, 150]);
        assert_eq!(at(&[3; 32]), [100]);
    }

    /// Past 1,024 arrivals a file, the oldest events go, and the newest
    /// time of what went is kept for its generation.
    #[test]
    fn test_a_file_keeps_its_arrivals_to_the_bound() {
        let conn = db::open_in_memory().unwrap();
        let (c, s) = ([1u8; 32], [2u8; 32]);
        // Each event holds the version before it: the first, version 0.
        let version = |rev: u64| Entry {
            channel: c,
            slot: s,
            author: [7; 32],
            rev,
            delete: false,
            content: vec![rev as u8],
            author_signature: [8; 64],
            channel_signature: [9; 64],
        };
        let mut first = 0;
        for at in 0..MAX_FILE_ARRIVALS as i64 + 3 {
            let place = note(
                &conn,
                &c,
                &s,
                2,
                &[2; 16],
                at,
                &[],
                Some(&version(at as u64)),
                Some(&[at as u8; 32]),
                &[arrival(5)],
            )
            .unwrap();
            if at == 0 {
                first = place;
            }
        }
        let (events, dropped) = of_file(&conn, &c, &s).unwrap();
        assert_eq!(events.len(), MAX_FILE_ARRIVALS);
        assert_eq!(events[0].stored_at, 3);
        // What went keeps the version before the first event that went,
        // and not before the oldest kept (decision 2026-10-24 (removal),
        // rule 7): the events in between may be a removed key's own.
        assert_eq!(
            dropped,
            vec![Dropped {
                number: 2,
                hash: [2; 16],
                newest_at: 2,
                first_place: first,
                before: Some(version(0)),
                first_stored_id: Some([0; 32]),
            }]
        );
        // Sealed again at a carry, it is what the carry set.
        set_dropped_before(&conn, &c, &s, 2, &[2; 16], Some(&version(40))).unwrap();
        assert_eq!(
            of_file(&conn, &c, &s).unwrap().1[0].before,
            Some(version(40))
        );
        set_dropped_before(&conn, &c, &s, 2, &[2; 16], None).unwrap();
        assert_eq!(of_file(&conn, &c, &s).unwrap().1[0].before, None);
        // Another file is not touched.
        note(
            &conn,
            &c,
            &[3; 32],
            2,
            &[2; 16],
            9,
            &[],
            None,
            None,
            &[arrival(5)],
        )
        .unwrap();
        assert_eq!(of_file(&conn, &c, &s).unwrap().0.len(), MAX_FILE_ARRIVALS);
    }
}
