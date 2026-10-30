//! What a device holds of its person (decision 2026-10-04 §3 to §6).
//!
//! Ten tables, in the node's database, so that everything here changes in
//! one transaction with a statement (§3):
//!
//! - **What it follows, and where it stands** (`person`, one row). The
//!   phrase's public key, the statement key and the ID of the phrase's
//!   channel: never the words (§5). The statement it has applied, as its
//!   signed bytes. And its state ([`State`]). A device with no row follows
//!   no phrase.
//! - **Its secrets, by statement number** (`person_secrets`). The one it
//!   has applied, and each one it left with the time it left it. A secret
//!   that was left is kept 90 days by the device's own clock, and then
//!   forgotten ([`forget_left_secrets`]).
//! - **The change entries it keeps** (`person_change_entries`, decision
//!   2026-10-24 (removal), rule 1). The change it follows, whole, to show
//!   to a relay, and up to seven heads set aside, each with when it was
//!   set aside: eight in all. And the time of each change it has applied
//!   or kept, by the change's own lineage, kept after the change goes
//!   (`person_change_times`, rule 2).
//! - **The records of additions it has seen** under the applied statement
//!   (`person_additions`), in the order it saw them, each counted or not
//!   (§6).
//! - **The names it holds** in the current generation (`person_names`),
//!   each with its channel's ID, so that either is found from the other.
//! - **The names that were listed before** (`person_names_before`): each
//!   name that a key had said it syncs, in the personal channel of a
//!   generation the device left, with when it left it. A device shows the
//!   names among them that no device lists yet in the generation it has
//!   applied (§7.3, §8).
//! - **The last hand-over it made for each key** (`person_hand_overs`):
//!   its revision, so that the next is above it, when it says it was
//!   made, and whether the store still holds it. Never the hand-over,
//!   which holds the secret (§6).
//!
//! - **What it knows of removals** (`person_removed_keys`,
//!   `person_holders`, `person_holders_past`; decision 2026-10-24
//!   (removal), rules 2 and 3): every key that a change it has seen lists
//!   as removed, which only grow; and for a change, each key that a record
//!   of an addition under it adds, kept apart from the records and their
//!   bound, with whether more were added than are kept.
//!
//! Nothing here decides anything: what a statement is to a device, who
//! counts and what is carried are decided where these are read. A function
//! that writes more than one row does so as one, with a savepoint, so that
//! it is whole inside a transaction of the caller's and whole without one.

use std::fmt;

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;
use cordelia_core::protocol::{LEFT_SECRET_KEPT_DAYS, MAX_KNOWN_HOLDERS, MAX_KNOWN_REMOVED};
use cordelia_crypto::entry::{CheckedEntry, Entry};

/// How long a secret that was left is kept, in seconds.
const KEPT_SECS: i64 = LEFT_SECRET_KEPT_DAYS as i64 * 24 * 60 * 60;

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

/// Where a device that follows a phrase stands (decision 2026-10-04 §4.2,
/// §4.3, §4.5). In every state but the first it has stopped: it neither
/// publishes in its own channels nor takes from them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// It has applied a statement, and is a device under it.
    Applied,
    /// It is closed (decision 2026-10-24 (removal), rule 10): it follows
    /// no clear change. It seals nothing, sends nothing and takes nothing
    /// in a channel of its own, until it is shown a clear change that
    /// counts it. Stored under the name a fork had.
    Fork,
    /// A statement made after the one it has applied lists its key as
    /// removed.
    Removed,
    /// A statement made after the one it has applied lists its key in
    /// neither list.
    NotListed,
    /// A statement made after the one it has applied lists it, and the
    /// secret that came with it did not open, or was not there.
    NotOpened,
}

impl State {
    fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Fork => "fork",
            Self::Removed => "removed",
            Self::NotListed => "not_listed",
            Self::NotOpened => "not_opened",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [
            Self::Applied,
            Self::Fork,
            Self::Removed,
            Self::NotListed,
            Self::NotOpened,
        ]
        .into_iter()
        .find(|state| state.as_str() == text)
    }
}

/// What a device follows (decision 2026-10-04 §5): never the words.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Following {
    /// The public half of the phrase's signing key.
    pub phrase_key: [u8; 32],
    /// The statement key, which opens the part of a change entry that is
    /// for the devices.
    pub statement_key: [u8; 32],
    /// The ID of the phrase's channel, where the change entry is.
    pub phrase_channel: [u8; 32],
}

/// The one row of `person`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub state: State,
    pub following: Following,
    /// The statement the device has applied: its canonical form and then
    /// its signature.
    pub statement: Vec<u8>,
}

/// A person secret that the device holds.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
    /// The number of the statement that commits to it.
    pub number: u64,
    pub secret: [u8; 32],
    /// When the device left its generation, in seconds, by its own clock.
    /// `None` for the one it has applied.
    pub left_at: Option<i64>,
}

/// A head that a device keeps set aside (decision 2026-10-24 (removal),
/// rule 1): a change entry that no other change it keeps was made after,
/// and that it does not follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetAside {
    /// Its row: what it is dropped by.
    pub place: i64,
    /// The entry, as it was stored: whoever reads it checks it.
    pub entry: Entry,
    /// When the device set it aside, in seconds, by its own clock.
    pub set_aside_at: i64,
}

/// A record of an addition, as the device keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeptAddition {
    /// Its place in the order in which the device saw the records.
    pub seen: i64,
    /// The signed record.
    pub record: Vec<u8>,
    /// The key it adds.
    pub key: [u8; 32],
    /// The key of the device that added it.
    pub adder: [u8; 32],
    /// Whether the key counts by this record.
    pub counted: bool,
    /// When the device saw it, in seconds.
    pub seen_at: i64,
}

/// A name the device holds, with its channel in the current generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldName {
    pub name: String,
    pub channel: [u8; 32],
    /// When the device came to hold it, in seconds.
    pub held_at: i64,
}

// ── What it follows, and where it stands ─────────────────────────────

/// What the device follows, the statement it has applied and its state.
/// `None` where it follows no phrase.
pub fn person(conn: &Connection) -> Result<Option<Person>, CordeliaError> {
    let row: Option<(String, Following, Vec<u8>)> = conn
        .query_row(
            "SELECT state, phrase_key, statement_key, phrase_channel, statement FROM person",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    Following {
                        phrase_key: row.get(1)?,
                        statement_key: row.get(2)?,
                        phrase_channel: row.get(3)?,
                    },
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?;
    let Some((state, following, statement)) = row else {
        return Ok(None);
    };
    let state = State::parse(&state)
        .ok_or_else(|| CordeliaError::Storage(format!("a device is in no state called {state}")))?;
    Ok(Some(Person {
        state,
        following,
        statement,
    }))
}

/// Write the one row: what the device follows, the statement it has
/// applied and its state, in the place of what was there.
pub fn put_person(conn: &Connection, person: &Person) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO person (one, state, phrase_key, statement_key, phrase_channel, statement)
         VALUES (1, ?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(one) DO UPDATE SET
             state = excluded.state, phrase_key = excluded.phrase_key,
             statement_key = excluded.statement_key,
             phrase_channel = excluded.phrase_channel, statement = excluded.statement",
        params![
            person.state.as_str(),
            person.following.phrase_key.as_slice(),
            person.following.statement_key.as_slice(),
            person.following.phrase_channel.as_slice(),
            person.statement,
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// Change the state of a device that follows a phrase, and nothing else
/// of its row. A device that follows none has no state to change.
pub fn set_state(conn: &Connection, state: State) -> Result<(), CordeliaError> {
    let changed = conn
        .execute("UPDATE person SET state = ?1", params![state.as_str()])
        .map_err(storage)?;
    if changed != 1 {
        return Err(CordeliaError::Storage(
            "a device that follows no phrase has no state".into(),
        ));
    }
    Ok(())
}

/// The device follows no phrase from now on (decision 2026-10-04 §5.2):
/// the one row goes, and so the phrase it followed and the statement it
/// had applied. Returns whether it followed one.
///
/// What else a device holds of its person is forgotten by the functions
/// of its own tables: its secrets ([`forget_secrets`]), the change
/// entries it keeps ([`drop_change_entries`]), its records of additions
/// ([`clear_additions`]) and what it keeps of its hand-overs
/// ([`forget_hand_overs`]). The names it holds stay: they are its
/// folders' names.
pub fn forget_person(conn: &Connection) -> Result<bool, CordeliaError> {
    conn.execute("DELETE FROM person", [])
        .map(|rows| rows > 0)
        .map_err(storage)
}

// ── Its secrets ──────────────────────────────────────────────────────

/// Every secret the device holds: the one it has applied first, and then
/// those it left, by the number of their statement, the highest first. Of
/// two at one number, the greater secret is first.
///
/// The time a secret was left is not what orders them: it is the device's
/// own clock, and a clock that was set back would list an older secret
/// ahead of a newer one.
pub fn secrets(conn: &Connection) -> Result<Vec<Secret>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT number, secret, left_at FROM person_secrets
             ORDER BY left_at IS NOT NULL, number DESC, secret DESC",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(Secret {
                number: row.get::<_, i64>(0)?.max(0) as u64,
                secret: row.get(1)?,
                left_at: row.get(2)?,
            })
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// The secret of the statement the device has applied, with its number.
pub fn applied_secret(conn: &Connection) -> Result<Option<Secret>, CordeliaError> {
    Ok(secrets(conn)?
        .into_iter()
        .find(|secret| secret.left_at.is_none()))
}

/// The device applies the secret of statement `number`: the one it had
/// applied is kept as left at `now`, and this one is the applied one. Both
/// happen, or neither.
pub fn apply_secret(
    conn: &Connection,
    number: u64,
    secret: &[u8; 32],
    now: i64,
) -> Result<(), CordeliaError> {
    conn.execute_batch("SAVEPOINT person_secret")
        .map_err(storage)?;
    let applied = (|| {
        conn.execute(
            "UPDATE person_secrets SET left_at = ?1 WHERE left_at IS NULL",
            params![now],
        )?;
        conn.execute(
            "INSERT INTO person_secrets (number, secret, left_at) VALUES (?1, ?2, NULL)",
            params![i64::try_from(number).unwrap_or(i64::MAX), secret.as_slice()],
        )
    })()
    .map(|_| ())
    .map_err(storage);
    let end = match applied {
        Ok(()) => "RELEASE person_secret",
        Err(_) => "ROLLBACK TO person_secret; RELEASE person_secret",
    };
    conn.execute_batch(end).map_err(storage)?;
    applied
}

/// Keep `secret`, of statement `number`, as a secret that the device left
/// at `now` (decision 2026-10-04 §3, §9). A machine that recovers is
/// handed the secret of the generation it recovered from, and those
/// before it that the change entry gave the phrase: it keeps each as a
/// device keeps a secret it left, for 90 days from then. One that the
/// device holds already, applied or left, stays as it is. Says whether it
/// was kept anew.
pub fn keep_left_secret(
    conn: &Connection,
    number: u64,
    secret: &[u8; 32],
    now: i64,
) -> Result<bool, CordeliaError> {
    conn.execute(
        "INSERT INTO person_secrets (number, secret, left_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(number, secret) DO NOTHING",
        params![
            i64::try_from(number).unwrap_or(i64::MAX),
            secret.as_slice(),
            now
        ],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

/// Forget each secret that the device left 90 days ago or longer, by its
/// own clock: `now` is that clock, in seconds. The secret it has applied
/// is never forgotten here. Returns how many were forgotten.
pub fn forget_left_secrets(conn: &Connection, now: i64) -> Result<usize, CordeliaError> {
    conn.execute(
        "DELETE FROM person_secrets WHERE left_at IS NOT NULL AND left_at + ?1 <= ?2",
        params![KEPT_SECS, now],
    )
    .map_err(storage)
}

/// Forget every secret the device holds, the applied one among them: it
/// leaves the phrase it followed, and starts afresh under another
/// (decision 2026-10-04 §4.2, §5.1). Returns how many were forgotten.
pub fn forget_secrets(conn: &Connection) -> Result<usize, CordeliaError> {
    conn.execute("DELETE FROM person_secrets", [])
        .map_err(storage)
}

// ── The change entries it keeps ──────────────────────────────────────

/// The change entry of the change the device follows, as it was stored:
/// whoever reads it checks it. On a device that has stopped, the entry
/// that stopped it; on a closed one, the change it applied last.
pub fn followed_entry(conn: &Connection) -> Result<Option<Entry>, CordeliaError> {
    conn.query_row(
        "SELECT channel, slot, author, rev, content, author_sig, channel_sig
         FROM person_change_entries WHERE followed = 1",
        [],
        entry_from_row,
    )
    .optional()
    .map_err(storage)
}

fn entry_from_row(row: &rusqlite::Row) -> rusqlite::Result<Entry> {
    Ok(Entry {
        channel: row.get(0)?,
        slot: row.get(1)?,
        author: row.get(2)?,
        rev: row.get::<_, i64>(3)?.max(0) as u64,
        delete: false,
        content: row.get(4)?,
        author_signature: row.get(5)?,
        channel_signature: row.get(6)?,
    })
}

/// Keep `entry` as the change entry of the change the device follows, in
/// the place of the one kept there. The heads set aside stay. Only an
/// entry that passed the check is kept; one that says it is a delete is
/// no change entry, and is refused.
pub fn keep_followed(conn: &Connection, entry: &CheckedEntry) -> Result<(), CordeliaError> {
    if entry.delete {
        return Err(CordeliaError::Validation(
            "a change entry is no delete".into(),
        ));
    }
    conn.execute_batch("SAVEPOINT person_followed")
        .map_err(storage)?;
    let kept = conn
        .execute("DELETE FROM person_change_entries WHERE followed = 1", [])
        .and_then(|_| insert_entry(conn, entry, None));
    let end = match kept {
        Ok(()) => "RELEASE person_followed",
        Err(_) => "ROLLBACK TO person_followed; RELEASE person_followed",
    };
    conn.execute_batch(end).map_err(storage)?;
    kept.map_err(storage)
}

fn insert_entry(
    conn: &Connection,
    entry: &CheckedEntry,
    set_aside_at: Option<i64>,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO person_change_entries
             (followed, set_aside_at, channel, slot, author, rev, content, author_sig,
              channel_sig)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            set_aside_at.is_none(),
            set_aside_at,
            entry.channel.as_slice(),
            entry.slot.as_slice(),
            entry.author.as_slice(),
            i64::try_from(entry.rev).unwrap_or(i64::MAX),
            entry.content,
            entry.author_signature.as_slice(),
            entry.channel_signature.as_slice(),
        ],
    )
    .map(|_| ())
}

/// Every head the device keeps set aside, the highest number first, and
/// of two at one number the one set aside first.
pub fn set_aside_entries(conn: &Connection) -> Result<Vec<SetAside>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT place, set_aside_at, channel, slot, author, rev, content, author_sig,
                    channel_sig
             FROM person_change_entries WHERE followed = 0
             ORDER BY rev DESC, place ASC",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(SetAside {
                place: row.get(0)?,
                set_aside_at: row.get(1)?,
                entry: Entry {
                    channel: row.get(2)?,
                    slot: row.get(3)?,
                    author: row.get(4)?,
                    rev: row.get::<_, i64>(5)?.max(0) as u64,
                    delete: false,
                    content: row.get(6)?,
                    author_signature: row.get(7)?,
                    channel_signature: row.get(8)?,
                },
            })
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Keep `entry` as a head set aside at `now` (decision 2026-10-24
/// (removal), rule 1). Whether it may be kept, and which heads it puts
/// out, is decided where it is read: this keeps it, and refuses only a
/// delete and an entry it keeps already, as the change followed or set
/// aside. Returns its place.
pub fn set_aside(conn: &Connection, entry: &CheckedEntry, now: i64) -> Result<i64, CordeliaError> {
    if entry.delete {
        return Err(CordeliaError::Validation(
            "a change entry is no delete".into(),
        ));
    }
    let kept: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM person_change_entries
                           WHERE author_sig = ?1 AND channel_sig = ?2)",
            params![
                entry.author_signature.as_slice(),
                entry.channel_signature.as_slice()
            ],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if kept {
        return Err(CordeliaError::Validation(
            "the device keeps that change entry already".into(),
        ));
    }
    insert_entry(conn, entry, Some(now)).map_err(storage)?;
    Ok(conn.last_insert_rowid())
}

/// Keep no longer the head set aside at `place`. Returns whether one was
/// there. The change followed is never dropped here.
pub fn drop_set_aside(conn: &Connection, place: i64) -> Result<bool, CordeliaError> {
    conn.execute(
        "DELETE FROM person_change_entries WHERE place = ?1 AND followed = 0",
        params![place],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

/// Keep no head set aside. Returns how many went.
pub fn drop_all_set_aside(conn: &Connection) -> Result<usize, CordeliaError> {
    conn.execute("DELETE FROM person_change_entries WHERE followed = 0", [])
        .map_err(storage)
}

/// Keep no change entry at all: the device leaves its phrase. Returns
/// how many went.
pub fn drop_change_entries(conn: &Connection) -> Result<usize, CordeliaError> {
    conn.execute("DELETE FROM person_change_entries", [])
        .map_err(storage)
}

/// Note the time of the change whose statement is numbered `number` and
/// hashes to `hash`, as its lineage says it was made (decision 2026-10-24
/// (removal), rule 2): `None` for a change made on the version before,
/// which has no lineage. A change noted already stays as it was. It is
/// kept after the change goes, for the cut time of rule 7.
pub fn note_change_time(
    conn: &Connection,
    number: u64,
    hash: &[u8; 16],
    made_at: Option<i64>,
) -> Result<(), CordeliaError> {
    note_change(conn, number, hash, made_at, None, None, None, None).map(|_| ())
}

/// A change as the device noted it ([`note_change`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotedChange {
    pub number: u64,
    pub hash: [u8; 16],
    /// The time its lineage says it was made; `None` where it has none,
    /// or none was known when it was noted.
    pub made_at: Option<i64>,
    /// The keys its statement lists as removed, where they were noted.
    pub removed: Option<Vec<[u8; 32]>>,
    /// Its statement's chain, each link by number and hash, where it was
    /// noted.
    pub chain: Option<Vec<(u64, [u8; 16])>>,
    /// The keys its statement lists as devices, where they were noted.
    pub devices: Option<Vec<[u8; 32]>>,
    /// Its statement's commitment to its secret, where it was noted.
    pub commitment: Option<[u8; 32]>,
}

/// Note the change whose statement is numbered `number` and hashes to
/// `hash` (decision 2026-10-24 (removal), rule 2): its time, as its
/// lineage says it (`None` for a change of the version before, or where
/// the entry is not at hand), the keys its statement lists as removed and
/// its chain. What was noted of it before stays; what was not is filled.
/// It is kept after the change goes, for the cut time of rules 6 and 7.
/// Says whether anything was filled that was not noted before, its time or
/// its lists: a cut time may then have moved, and records are judged again.
/// With its lists, `commitment` is its statement's commitment to its
/// secret, noted where it was not.
#[allow(clippy::too_many_arguments)]
pub fn note_change(
    conn: &Connection,
    number: u64,
    hash: &[u8; 16],
    made_at: Option<i64>,
    removed: Option<&[[u8; 32]]>,
    chain: Option<&[(u64, [u8; 16])]>,
    devices: Option<&[[u8; 32]]>,
    commitment: Option<&[u8; 32]>,
) -> Result<bool, CordeliaError> {
    let number = i64::try_from(number).unwrap_or(i64::MAX);
    let had: Option<Option<i64>> = conn
        .query_row(
            "SELECT made_at FROM person_change_times WHERE number = ?1 AND hash = ?2",
            params![number, hash.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    let mut filled = made_at.is_some() && had.flatten().is_none();
    conn.execute(
        "INSERT INTO person_change_times (number, hash, made_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(number, hash) DO UPDATE SET made_at = COALESCE(made_at, excluded.made_at)",
        params![number, hash.as_slice(), made_at],
    )
    .map_err(storage)?;
    if let (Some(removed), Some(chain), Some(devices)) = (removed, chain, devices) {
        let mut row = Vec::with_capacity(chain.len() * 24);
        for (number, hash) in chain {
            row.extend_from_slice(&number.to_be_bytes());
            row.extend_from_slice(hash);
        }
        filled |= conn
            .execute(
                "INSERT INTO person_change_times_lists (number, hash, removed, chain, devices)
                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(number, hash) DO NOTHING",
                params![
                    number,
                    hash.as_slice(),
                    removed.concat(),
                    row,
                    devices.concat()
                ],
            )
            .map_err(storage)?
            > 0;
        if let Some(commitment) = commitment {
            conn.execute(
                "UPDATE person_change_times_lists SET commitment = ?3
                 WHERE number = ?1 AND hash = ?2 AND commitment IS NULL",
                params![number, hash.as_slice(), commitment.as_slice()],
            )
            .map_err(storage)?;
        }
    }
    Ok(filled)
}

/// Every change the device noted ([`note_change`]), in order of number
/// and hash. A list that does not read as one is taken as not noted.
pub fn changes_noted(conn: &Connection) -> Result<Vec<NotedChange>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT t.number, t.hash, t.made_at, l.removed, l.chain, l.devices, l.commitment
             FROM person_change_times t
             LEFT JOIN person_change_times_lists l ON l.number = t.number AND l.hash = t.hash
             ORDER BY t.number, t.hash",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
            ))
        })
        .map_err(storage)?;
    let mut noted = Vec::new();
    for row in rows {
        let (number, hash, made_at, removed, chain, devices, commitment) = row.map_err(storage)?;
        let Ok(hash) = <[u8; 16]>::try_from(hash) else {
            continue;
        };
        let keys = |row: Vec<u8>| {
            let (keys, rest) = row.as_chunks::<32>();
            rest.is_empty().then(|| keys.to_vec())
        };
        let removed = removed.and_then(keys);
        let devices = devices.and_then(keys);
        let chain = chain.and_then(|row| {
            let (links, rest) = row.as_chunks::<24>();
            rest.is_empty().then(|| {
                links
                    .iter()
                    .map(|link| {
                        let (number, hash) = link.split_at(8);
                        (
                            u64::from_be_bytes(number.try_into().unwrap_or_default()),
                            hash.try_into().unwrap_or_default(),
                        )
                    })
                    .collect()
            })
        });
        noted.push(NotedChange {
            number: number.max(0) as u64,
            hash,
            made_at,
            removed,
            chain,
            devices,
            commitment: commitment.and_then(|bytes| bytes.try_into().ok()),
        });
    }
    Ok(noted)
}

/// The time of the change whose statement is numbered `number` and hashes
/// to `hash`, as the device noted it: `None` where it noted none, and
/// `Some(None)` where it noted the change, which has no time.
pub fn change_time(
    conn: &Connection,
    number: u64,
    hash: &[u8; 16],
) -> Result<Option<Option<i64>>, CordeliaError> {
    conn.query_row(
        "SELECT made_at FROM person_change_times WHERE number = ?1 AND hash = ?2",
        params![i64::try_from(number).unwrap_or(i64::MAX), hash.as_slice()],
        |row| row.get(0),
    )
    .optional()
    .map_err(storage)
}

/// Forget the time of every change: the device leaves its phrase, and
/// under another they would be another person's. Returns how many went.
pub fn forget_change_times(conn: &Connection) -> Result<usize, CordeliaError> {
    conn.execute("DELETE FROM person_change_times_lists", [])
        .map_err(storage)?;
    conn.execute("DELETE FROM person_change_times", [])
        .map_err(storage)
}

/// Whether the device is to judge what it kept at its first start on
/// this version (decision 2026-10-24 (removal), rule 12): step 22 marks a
/// device that follows a phrase (`meta::PERSON_JUDGE_KEPT`).
pub fn to_judge_kept(conn: &Connection) -> Result<bool, CordeliaError> {
    Ok(crate::meta::get(conn, crate::meta::PERSON_JUDGE_KEPT)?.is_some())
}

/// The device has judged what it kept at its first start on this version.
pub fn judged_kept(conn: &Connection) -> Result<(), CordeliaError> {
    crate::meta::remove(conn, crate::meta::PERSON_JUDGE_KEPT)
}

// ── The records of additions it has seen ─────────────────────────────

/// Every record of an addition the device keeps, in the order it saw
/// them.
pub fn additions(conn: &Connection) -> Result<Vec<KeptAddition>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT seen, record, key, adder, counted, seen_at FROM person_additions
             ORDER BY seen ASC",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(KeptAddition {
                seen: row.get(0)?,
                record: row.get(1)?,
                key: row.get(2)?,
                adder: row.get(3)?,
                counted: row.get(4)?,
                seen_at: row.get(5)?,
            })
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Keep a record of an addition, after every record seen before it.
/// `record` is the signed record, `key` the key it adds and `adder` the
/// key that added it. Returns whether it was kept: a record that the
/// device already keeps is not kept twice, and stays as it was, counted
/// or not.
pub fn keep_addition(
    conn: &Connection,
    record: &[u8],
    key: &[u8; 32],
    adder: &[u8; 32],
    counted: bool,
    now: i64,
) -> Result<bool, CordeliaError> {
    conn.execute(
        "INSERT INTO person_additions (record, key, adder, counted, seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(record) DO NOTHING",
        params![record, key.as_slice(), adder.as_slice(), counted, now],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

/// A record that was kept as not counted counts from now on (decision
/// 2026-10-04 §6): `seen` is its place in the order the device saw the
/// records, which it keeps. A place that holds no record is refused.
pub fn count_addition(conn: &Connection, seen: i64) -> Result<(), CordeliaError> {
    let changed = conn
        .execute(
            "UPDATE person_additions SET counted = 1 WHERE seen = ?1",
            params![seen],
        )
        .map_err(storage)?;
    if changed != 1 {
        return Err(CordeliaError::Storage(format!(
            "the device keeps no record at place {seen}"
        )));
    }
    Ok(())
}

/// A record that counted counts no more (decision 2026-10-24 (removal),
/// rule 6): a removed key signed it after its cut time. `seen` is its
/// place, which it keeps. A place that holds no record is refused.
pub fn uncount_addition(conn: &Connection, seen: i64) -> Result<(), CordeliaError> {
    let changed = conn
        .execute(
            "UPDATE person_additions SET counted = 0 WHERE seen = ?1",
            params![seen],
        )
        .map_err(storage)?;
    if changed != 1 {
        return Err(CordeliaError::Storage(format!(
            "the device keeps no record at place {seen}"
        )));
    }
    Ok(())
}

/// Keep no longer a record that is not counted: `seen` is its place in
/// the order the device saw the records. The records that stay keep
/// their places. A record that counts is never dropped here: a place
/// that holds one, or holds no record, is refused.
pub fn drop_not_counted(conn: &Connection, seen: i64) -> Result<(), CordeliaError> {
    let dropped = conn
        .execute(
            "DELETE FROM person_additions WHERE seen = ?1 AND counted = 0",
            params![seen],
        )
        .map_err(storage)?;
    if dropped != 1 {
        return Err(CordeliaError::Storage(format!(
            "the device keeps no record that is not counted at place {seen}"
        )));
    }
    Ok(())
}

/// Keep no record of an addition: the next statement's own list is what
/// stands (decision 2026-10-04 §6). Returns how many were kept.
pub fn clear_additions(conn: &Connection) -> Result<usize, CordeliaError> {
    conn.execute("DELETE FROM person_additions", [])
        .map_err(storage)
}

// ── What it knows of removals ────────────────────────────────────────

/// Keep `keys` as removed (decision 2026-10-24 (removal), rule 2): each
/// that the device does not keep already, with `now`, its own clock, or
/// the newest time an event of a file was stamped where that is later
/// ([`crate::arrivals::newest_stamp`]): the close of a window of rule 27,
/// which a clock once ahead cannot then put before what was stored in it
/// (the review of rule 27, its clock). A key
/// is never taken out here. Where keeping them would pass
/// `MAX_KNOWN_REMOVED`, those beyond it are not kept and the device is
/// marked past the bound (`meta::PERSON_REMOVED_PAST_BOUND`): it is then
/// closed. Returns how many were kept anew. In the caller's transaction,
/// or whole by itself.
pub fn keep_removed(
    conn: &Connection,
    keys: &[[u8; 32]],
    now: i64,
) -> Result<usize, CordeliaError> {
    let mut kept = 0;
    let now = crate::arrivals::newest_stamp(conn)?.map_or(now, |newest| now.max(newest));
    for key in keys {
        let held: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM person_removed_keys WHERE key = ?1)",
                params![key.as_slice()],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if held {
            continue;
        }
        if removed_count(conn)? >= MAX_KNOWN_REMOVED {
            crate::meta::set(conn, crate::meta::PERSON_REMOVED_PAST_BOUND, "1")?;
            continue;
        }
        conn.execute(
            "INSERT INTO person_removed_keys (key, seen_at) VALUES (?1, ?2)",
            params![key.as_slice(), now],
        )
        .map_err(storage)?;
        kept += 1;
    }
    Ok(kept)
}

/// Keep `key` as removed because a record that `adder`, a removed key,
/// signed added it after `adder`'s cut time, or in a generation made apart
/// from its removal (decision 2026-10-24 (removal), rule 6). Its cut is
/// `adder`'s. As [`keep_removed`]: a key kept already stays as it was.
/// Returns whether it was kept anew.
pub fn keep_removed_added_by(
    conn: &Connection,
    key: &[u8; 32],
    adder: &[u8; 32],
    now: i64,
) -> Result<bool, CordeliaError> {
    if keep_removed(conn, &[*key], now)? == 0 {
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO person_removed_keys_by (key, added_by) VALUES (?1, ?2)
         ON CONFLICT(key) DO NOTHING",
        params![key.as_slice(), adder.as_slice()],
    )
    .map_err(storage)?;
    Ok(true)
}

/// Keep `key` as one that the person said, at the terminal of the
/// recovery numbered `number` made on this device, is a device they still
/// have (decision 2026-10-24 (removal), rule 6): it was shown to the
/// person with the phrase, so a record of a removed key's that added it
/// does not remove it. The first answer stays.
pub fn keep_by_answer(conn: &Connection, key: &[u8; 32], number: u64) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO person_removed_keys_spared (key, number) VALUES (?1, ?2)
         ON CONFLICT(key) DO NOTHING",
        params![key.as_slice(), i64::try_from(number).unwrap_or(i64::MAX)],
    )
    .map_err(storage)?;
    Ok(())
}

/// Whether the person said, at the terminal of a recovery made on this
/// device, that `key` is a device they still have ([`keep_by_answer`]).
pub fn is_kept_by_answer(conn: &Connection, key: &[u8; 32]) -> Result<bool, CordeliaError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM person_removed_keys_spared WHERE key = ?1)",
        params![key.as_slice()],
        |row| row.get(0),
    )
    .map_err(storage)
}

/// A key the device keeps as removed, with the removed key whose record
/// added it where rule 6 removed it.
pub type RemovedBy = ([u8; 32], Option<[u8; 32]>);

/// Every key the device keeps as removed, in order of key, each with the
/// removed key whose record added it where rule 6 removed it.
pub fn removed_with_adders(conn: &Connection) -> Result<Vec<RemovedBy>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT k.key, b.added_by FROM person_removed_keys k
             LEFT JOIN person_removed_keys_by b ON b.key = k.key ORDER BY k.key ASC",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Every key the device keeps as removed, with when it first kept it: the
/// moment it knew (decision 2026-10-24 (removal), rules 2, 5 and 27).
pub fn removed_seen(conn: &Connection) -> Result<Vec<([u8; 32], i64)>, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT key, seen_at FROM person_removed_keys ORDER BY key ASC")
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// How many keys the device keeps as removed.
fn removed_count(conn: &Connection) -> Result<usize, CordeliaError> {
    conn.query_row("SELECT COUNT(*) FROM person_removed_keys", [], |row| {
        row.get::<_, i64>(0)
    })
    .map(|count| count.max(0) as usize)
    .map_err(storage)
}

/// Every key the device keeps as removed, in order of key.
pub fn removed_keys(conn: &Connection) -> Result<Vec<[u8; 32]>, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT key FROM person_removed_keys ORDER BY key ASC")
        .map_err(storage)?;
    let rows = stmt.query_map([], |row| row.get(0)).map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Whether a change the device saw would have had it keep more keys as
/// removed than it keeps ([`keep_removed`]).
pub fn removed_past_bound(conn: &Connection) -> Result<bool, CordeliaError> {
    Ok(crate::meta::get(conn, crate::meta::PERSON_REMOVED_PAST_BOUND)?.is_some())
}

/// Keep `key` as holding the secret of the change whose statement is
/// numbered `number` and hashes to `hash` (decision 2026-10-24 (removal),
/// rule 3): a record of an addition under that change adds it. Where the
/// change has `MAX_KNOWN_HOLDERS` already and this key is not among them,
/// it is not kept, and the change is marked past the bound: it is then not
/// clear. Returns whether it was kept anew.
pub fn keep_holder(
    conn: &Connection,
    number: u64,
    hash: &[u8; 16],
    key: &[u8; 32],
) -> Result<bool, CordeliaError> {
    let number = i64::try_from(number).unwrap_or(i64::MAX);
    let held: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM person_holders
                           WHERE number = ?1 AND hash = ?2 AND key = ?3)",
            params![number, hash.as_slice(), key.as_slice()],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if held {
        return Ok(false);
    }
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM person_holders WHERE number = ?1 AND hash = ?2",
            params![number, hash.as_slice()],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if count.max(0) as usize >= MAX_KNOWN_HOLDERS {
        conn.execute(
            "INSERT INTO person_holders_past (number, hash) VALUES (?1, ?2)
             ON CONFLICT(number, hash) DO NOTHING",
            params![number, hash.as_slice()],
        )
        .map_err(storage)?;
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO person_holders (number, hash, key) VALUES (?1, ?2, ?3)",
        params![number, hash.as_slice(), key.as_slice()],
    )
    .map_err(storage)?;
    Ok(true)
}

/// The keys the device keeps as holding the secret of the change whose
/// statement is numbered `number` and hashes to `hash`, by the records it
/// has seen under it, in order of key.
pub fn holders(
    conn: &Connection,
    number: u64,
    hash: &[u8; 16],
) -> Result<Vec<[u8; 32]>, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT key FROM person_holders WHERE number = ?1 AND hash = ?2 ORDER BY key ASC")
        .map_err(storage)?;
    let rows = stmt
        .query_map(
            params![i64::try_from(number).unwrap_or(i64::MAX), hash.as_slice()],
            |row| row.get(0),
        )
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Whether a record would have given the change whose statement is
/// numbered `number` and hashes to `hash` more holders than are kept
/// ([`keep_holder`]).
pub fn holders_past_bound(
    conn: &Connection,
    number: u64,
    hash: &[u8; 16],
) -> Result<bool, CordeliaError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM person_holders_past WHERE number = ?1 AND hash = ?2)",
        params![i64::try_from(number).unwrap_or(i64::MAX), hash.as_slice()],
        |row| row.get(0),
    )
    .map_err(storage)
}

/// Keep the holders, and the mark past their bound, of no change but
/// those in `kept`, each by its statement's number and hash: the change
/// the device comes to follow and every change it keeps as a head set
/// aside (decision 2026-10-24 (removal), rule 3). A head is judged by them
/// for as long as it is kept, so what made it not clear stays. Returns how
/// many rows went.
pub fn forget_holders_but(
    conn: &Connection,
    kept: &[(u64, [u8; 16])],
) -> Result<usize, CordeliaError> {
    let kept: Vec<(i64, [u8; 16])> = kept
        .iter()
        .map(|(number, hash)| (i64::try_from(*number).unwrap_or(i64::MAX), *hash))
        .collect();
    let mut gone = 0;
    for table in ["person_holders", "person_holders_past"] {
        let mut stmt = conn
            .prepare(&format!("SELECT DISTINCT number, hash FROM {table}"))
            .map_err(storage)?;
        let held = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?;
        for (number, hash) in held {
            if kept
                .iter()
                .any(|(n, h)| *n == number && h.as_slice() == hash.as_slice())
            {
                continue;
            }
            gone += conn
                .execute(
                    &format!("DELETE FROM {table} WHERE number = ?1 AND hash = ?2"),
                    params![number, hash],
                )
                .map_err(storage)?;
        }
    }
    Ok(gone)
}

/// The mark that every write of what says whether the change followed is
/// clear makes anew (schema step 21, `person_clear_mark`): the row of the
/// person, its records, the removed keys, the holders, the changes past
/// the bound of holders, and the mark past the bound of removed keys. What
/// is worked out from them under one mark holds for as long as the
/// database holds that mark. `None` where the row is not there, and then
/// nothing is to be taken as worked out.
pub fn clear_mark(conn: &Connection) -> Result<Option<[u8; 16]>, CordeliaError> {
    conn.prepare_cached("SELECT mark FROM person_clear_mark WHERE one = 1")
        .and_then(|mut stmt| stmt.query_row([], |row| row.get(0)).optional())
        .map_err(storage)
}

/// Forget what the device knows of removals: the keys it keeps as
/// removed, with the mark past their bound, every holder, and the time of
/// every change (decision 2026-10-24 (removal), rule 2). Only a
/// device that leaves its phrase does this: under another phrase they are
/// another person's.
pub fn forget_removals(conn: &Connection) -> Result<(), CordeliaError> {
    for table in [
        "person_removed_keys",
        "person_removed_keys_by",
        "person_removed_keys_spared",
        "person_holders",
        "person_holders_past",
        "person_change_times",
        "person_change_times_lists",
    ] {
        conn.execute(&format!("DELETE FROM {table}"), [])
            .map_err(storage)?;
    }
    crate::meta::remove(conn, crate::meta::PERSON_REMOVED_PAST_BOUND)?;
    Ok(())
}

// ── The names it holds ───────────────────────────────────────────────

/// Every name the device holds, in order of name.
pub fn names(conn: &Connection) -> Result<Vec<HeldName>, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT name, channel, held_at FROM person_names ORDER BY name ASC")
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(HeldName {
                name: row.get(0)?,
                channel: row.get(1)?,
                held_at: row.get(2)?,
            })
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Hold `name`, whose channel in the current generation is `channel`.
/// Returns whether it is newly held: a name that the device already holds
/// stays as it is, with the time it came to hold it.
///
/// A channel is one name's: a second name with the channel of one that is
/// held is refused.
pub fn hold_name(
    conn: &Connection,
    name: &str,
    channel: &[u8; 32],
    now: i64,
) -> Result<bool, CordeliaError> {
    conn.execute(
        "INSERT INTO person_names (name, channel, held_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(name) DO NOTHING",
        params![name, channel.as_slice(), now],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

/// The channel of a name the device holds is `channel` from now on: the
/// name's channel in the generation the device has come to.
pub fn move_name(conn: &Connection, name: &str, channel: &[u8; 32]) -> Result<(), CordeliaError> {
    let changed = conn
        .execute(
            "UPDATE person_names SET channel = ?2 WHERE name = ?1",
            params![name, channel.as_slice()],
        )
        .map_err(storage)?;
    if changed != 1 {
        return Err(CordeliaError::Storage(format!(
            "the device does not hold the name {name}"
        )));
    }
    Ok(())
}

/// Hold a name no longer. Returns whether it was held.
pub fn drop_name(conn: &Connection, name: &str) -> Result<bool, CordeliaError> {
    conn.execute("DELETE FROM person_names WHERE name = ?1", params![name])
        .map(|rows| rows > 0)
        .map_err(storage)
}

/// The channel, in the current generation, of a name the device holds.
pub fn channel_of_name(conn: &Connection, name: &str) -> Result<Option<[u8; 32]>, CordeliaError> {
    conn.query_row(
        "SELECT channel FROM person_names WHERE name = ?1",
        params![name],
        |row| row.get(0),
    )
    .optional()
    .map_err(storage)
}

/// The name whose channel, in the current generation, is `channel`.
pub fn name_of_channel(
    conn: &Connection,
    channel: &[u8; 32],
) -> Result<Option<String>, CordeliaError> {
    conn.query_row(
        "SELECT name FROM person_names WHERE channel = ?1",
        params![channel.as_slice()],
        |row| row.get(0),
    )
    .optional()
    .map_err(storage)
}

// ── The names that were listed before a statement ────────────────────

/// A name that a key had said it syncs, in the personal channel of a
/// generation that the device left (decision 2026-10-04 §7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameBefore {
    pub name: String,
    /// The key that had said so.
    pub key: [u8; 32],
    /// When the device left that generation, in seconds, by its own
    /// clock.
    pub left_at: i64,
}

/// Every name that was listed in a generation the device left, with each
/// key that had listed it, in order of name and then of key.
pub fn names_before(conn: &Connection) -> Result<Vec<NameBefore>, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT name, said_by, left_at FROM person_names_before ORDER BY name, said_by")
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(NameBefore {
                name: row.get(0)?,
                key: row.get(1)?,
                left_at: row.get(2)?,
            })
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Note that the key `key` had said it syncs `name`, in the personal
/// channel of the generation that the device leaves at `now`. A name and
/// key that are noted already are noted as of now: the generation that
/// is left is the newest that listed them.
pub fn note_name_before(
    conn: &Connection,
    name: &str,
    key: &[u8; 32],
    now: i64,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO person_names_before (name, said_by, left_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(name, said_by) DO UPDATE SET left_at = excluded.left_at",
        params![name, key.as_slice(), now],
    )
    .map_err(storage)?;
    Ok(())
}

/// Note `name` no longer as listed before, whichever keys had listed it:
/// a device lists it in the generation applied. Returns how many rows
/// went.
pub fn forget_name_before(conn: &Connection, name: &str) -> Result<usize, CordeliaError> {
    conn.execute(
        "DELETE FROM person_names_before WHERE name = ?1",
        params![name],
    )
    .map_err(storage)
}

/// Note no longer that the key `key` had listed `name`: that key has said
/// since, in a generation that the device came to, whether it syncs the
/// name there. What other keys had listed stays noted. Returns whether a
/// row went.
pub fn forget_name_said_by(
    conn: &Connection,
    name: &str,
    key: &[u8; 32],
) -> Result<bool, CordeliaError> {
    let rows = conn
        .execute(
            "DELETE FROM person_names_before WHERE name = ?1 AND said_by = ?2",
            params![name, key.as_slice()],
        )
        .map_err(storage)?;
    Ok(rows > 0)
}

/// Forget each name that was listed in a generation which the device left
/// 90 days ago or longer, by its own clock: that generation's secret is
/// forgotten then ([`forget_left_secrets`]), and the name can be brought
/// in no more. With `None`, forget them all: the device leaves its
/// phrase. Returns how many rows went.
pub fn forget_names_before(conn: &Connection, now: Option<i64>) -> Result<usize, CordeliaError> {
    match now {
        Some(now) => conn.execute(
            "DELETE FROM person_names_before WHERE left_at + ?1 <= ?2",
            params![KEPT_SECS, now],
        ),
        None => conn.execute("DELETE FROM person_names_before", []),
    }
    .map_err(storage)
}

// ── The last hand-over it made for each key ──────────────────────────

/// What a device keeps of the last hand-over it made for a key (decision
/// 2026-10-04 §6): where it is, and how it is ordered. Never what it
/// holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandedOver {
    /// The key it was made for.
    pub key: [u8; 32],
    /// The ID of the pair channel of this device and that key.
    pub channel: [u8; 32],
    /// The revision of its entry there: the next is above it.
    pub rev: u64,
    /// When it says it was made, in seconds.
    pub made_at: i64,
    /// Whether the store still holds its entry.
    pub held: bool,
}

fn handed_over_from_row(row: &rusqlite::Row) -> rusqlite::Result<HandedOver> {
    Ok(HandedOver {
        key: row.get(0)?,
        channel: row.get(1)?,
        rev: row.get::<_, i64>(2)?.max(0) as u64,
        made_at: row.get(3)?,
        held: row.get(4)?,
    })
}

/// What the device keeps of the last hand-over it made for `key`. `None`
/// where it has made none for it.
pub fn handed_over(conn: &Connection, key: &[u8; 32]) -> Result<Option<HandedOver>, CordeliaError> {
    conn.query_row(
        "SELECT key, channel, rev, made_at, held FROM person_hand_overs WHERE key = ?1",
        params![key.as_slice()],
        handed_over_from_row,
    )
    .optional()
    .map_err(storage)
}

/// The last hand-over for each key whose entry the store still holds, in
/// order of the time each says it was made.
pub fn hand_overs_held(conn: &Connection) -> Result<Vec<HandedOver>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT key, channel, rev, made_at, held FROM person_hand_overs
             WHERE held = 1 ORDER BY made_at ASC, key ASC",
        )
        .map_err(storage)?;
    let rows = stmt.query_map([], handed_over_from_row).map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// The last hand-over for each key whose entry the store holds no longer,
/// in order of key.
pub fn hand_overs_gone(conn: &Connection) -> Result<Vec<HandedOver>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT key, channel, rev, made_at, held FROM person_hand_overs
             WHERE held = 0 ORDER BY key ASC",
        )
        .map_err(storage)?;
    let rows = stmt.query_map([], handed_over_from_row).map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// The device has made a hand-over for `key`, and its store holds it: in
/// the pair channel whose ID is `channel`, at revision `rev`, saying it
/// was made at `made_at`. It takes the place of what was kept of the one
/// before for that key.
pub fn note_hand_over(
    conn: &Connection,
    key: &[u8; 32],
    channel: &[u8; 32],
    rev: u64,
    made_at: i64,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO person_hand_overs (key, channel, rev, made_at, held)
         VALUES (?1, ?2, ?3, ?4, 1)
         ON CONFLICT(key) DO UPDATE SET
             channel = excluded.channel, rev = excluded.rev,
             made_at = excluded.made_at, held = 1",
        params![
            key.as_slice(),
            channel.as_slice(),
            i64::try_from(rev).unwrap_or(i64::MAX),
            made_at,
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// The store holds the last hand-over for `key` no longer. Its revision
/// is kept, so that the next one made for that key is above it. Returns
/// whether the store was said to hold it.
pub fn hand_over_gone(conn: &Connection, key: &[u8; 32]) -> Result<bool, CordeliaError> {
    conn.execute(
        "UPDATE person_hand_overs SET held = 0 WHERE key = ?1 AND held = 1",
        params![key.as_slice()],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

/// Keep nothing of any hand-over: for a device that leaves its phrase
/// (decision 2026-10-04 §6). Each row names a key that it added under the
/// phrase it leaves. Returns how many there were.
pub fn forget_hand_overs(conn: &Connection) -> Result<usize, CordeliaError> {
    conn.execute("DELETE FROM person_hand_overs", [])
        .map_err(storage)
}

// A secret and the statement key are not printed for debugging: what is
// shown is which statement a secret is of, and which phrase is followed.

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("number", &self.number)
            .field("left_at", &self.left_at)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Following {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Following")
            .field("phrase_key", &hex::encode(&self.phrase_key[..4]))
            .field("phrase_channel", &hex::encode(&self.phrase_channel[..4]))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use cordelia_crypto::entry::{Inside, Value};
    use cordelia_crypto::identity::NodeIdentity;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 24 * 60 * 60;

    fn following(n: u8) -> Following {
        Following {
            phrase_key: [n; 32],
            statement_key: [n + 1; 32],
            phrase_channel: [n + 2; 32],
        }
    }

    fn sample(state: State) -> Person {
        Person {
            state,
            following: following(0x20),
            statement: vec![1, 2, 3, 4],
        }
    }

    /// An entry that passed the check, of the channel whose secret is
    /// `secret`, at `rev`. A change entry is kept as any checked entry is:
    /// what is in it is for whoever reads it to say.
    fn entry(secret: u8, rev: u64, value: Value) -> CheckedEntry {
        let inside = Inside {
            name: "change".to_string(),
            value,
            chain: Some(Vec::new()),
        };
        let author = NodeIdentity::from_seed([0x31; 32]).unwrap();
        Entry::seal(&[secret; 32], &author, rev, &inside)
            .unwrap()
            .check()
            .unwrap()
    }

    fn text(secret: u8, rev: u64) -> CheckedEntry {
        entry(secret, rev, Value::Text("what it holds".to_string()))
    }

    // ── What it knows of removals ────────────────────────────────────

    /// The removed keys only grow (decision 2026-10-24 (removal), rule 2):
    /// a key kept is kept once, with the time it was first kept, and none
    /// is taken out but where the device leaves its phrase. Past their
    /// bound none more is kept, and the device is marked past it.
    #[test]
    fn test_the_removed_keys_only_grow_and_are_marked_past_their_bound() {
        let conn = db::open_in_memory().unwrap();
        assert!(removed_keys(&conn).unwrap().is_empty());
        assert!(!removed_past_bound(&conn).unwrap());
        assert_eq!(keep_removed(&conn, &[[2; 32], [1; 32]], NOW).unwrap(), 2);
        assert_eq!(
            keep_removed(&conn, &[[1; 32], [3; 32]], NOW + 9).unwrap(),
            1
        );
        assert_eq!(
            removed_keys(&conn).unwrap(),
            vec![[1; 32], [2; 32], [3; 32]]
        );
        let seen_at: i64 = conn
            .query_row(
                "SELECT seen_at FROM person_removed_keys WHERE key = ?1",
                params![[1u8; 32].as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(seen_at, NOW);
        assert!(!removed_past_bound(&conn).unwrap());

        // To the bound, and one past it.
        let many: Vec<[u8; 32]> = (0..MAX_KNOWN_REMOVED as u32)
            .map(|n| {
                let mut key = [0xee; 32];
                key[..4].copy_from_slice(&n.to_be_bytes());
                key
            })
            .collect();
        keep_removed(&conn, &many, NOW).unwrap();
        assert_eq!(removed_keys(&conn).unwrap().len(), MAX_KNOWN_REMOVED);
        assert!(removed_past_bound(&conn).unwrap());
        // One it keeps already is no more than it was.
        assert_eq!(keep_removed(&conn, &[[1; 32]], NOW).unwrap(), 0);

        forget_removals(&conn).unwrap();
        assert!(removed_keys(&conn).unwrap().is_empty());
        assert!(!removed_past_bound(&conn).unwrap());
    }

    /// The holders of a change are kept by its number and hash (decision
    /// 2026-10-24 (removal), rule 3): each key once, at most
    /// `MAX_KNOWN_HOLDERS`, and a change that a record would take past that
    /// is marked so. The device keeps those of one change when it comes to
    /// follow it, and none once it leaves its phrase.
    #[test]
    fn test_the_holders_of_a_change_are_kept_to_their_bound_and_marked_past_it() {
        let conn = db::open_in_memory().unwrap();
        let (three, four) = ([3; 16], [4; 16]);
        assert!(keep_holder(&conn, 3, &three, &[1; 32]).unwrap());
        assert!(!keep_holder(&conn, 3, &three, &[1; 32]).unwrap());
        assert!(keep_holder(&conn, 3, &four, &[2; 32]).unwrap());
        assert!(keep_holder(&conn, 4, &four, &[5; 32]).unwrap());
        assert_eq!(holders(&conn, 3, &three).unwrap(), vec![[1; 32]]);
        assert_eq!(holders(&conn, 3, &four).unwrap(), vec![[2; 32]]);
        assert!(!holders_past_bound(&conn, 3, &three).unwrap());

        for n in 1..MAX_KNOWN_HOLDERS as u32 {
            let mut key = [0xdd; 32];
            key[..4].copy_from_slice(&n.to_be_bytes());
            assert!(keep_holder(&conn, 3, &three, &key).unwrap());
        }
        assert_eq!(holders(&conn, 3, &three).unwrap().len(), MAX_KNOWN_HOLDERS);
        assert!(!holders_past_bound(&conn, 3, &three).unwrap());
        // One it keeps is no more; one more is not kept, and marks it.
        assert!(!keep_holder(&conn, 3, &three, &[1; 32]).unwrap());
        assert!(!holders_past_bound(&conn, 3, &three).unwrap());
        assert!(!keep_holder(&conn, 3, &three, &[9; 32]).unwrap());
        assert!(holders_past_bound(&conn, 3, &three).unwrap());
        assert!(!holders_past_bound(&conn, 3, &four).unwrap());

        // A change still kept keeps its holders and its mark past the
        // bound; one that is not loses both.
        forget_holders_but(&conn, &[(4, four), (3, three)]).unwrap();
        assert_eq!(holders(&conn, 3, &three).unwrap().len(), MAX_KNOWN_HOLDERS);
        assert!(holders_past_bound(&conn, 3, &three).unwrap());
        assert!(holders(&conn, 3, &four).unwrap().is_empty());
        forget_holders_but(&conn, &[(4, four)]).unwrap();
        assert!(holders(&conn, 3, &three).unwrap().is_empty());
        assert!(!holders_past_bound(&conn, 3, &three).unwrap());
        assert_eq!(holders(&conn, 4, &four).unwrap(), vec![[5; 32]]);
        forget_removals(&conn).unwrap();
        assert!(holders(&conn, 4, &four).unwrap().is_empty());
    }

    /// Every write of what says whether the change followed is clear makes
    /// the mark anew, whatever writes it (schema step 21): an insert, an
    /// update and a delete of the person's row, its records, the removed
    /// keys, the holders and the changes past their bound, and of the mark
    /// past the bound of removed keys. A write undone puts back the mark
    /// with what it undid. A write of anything else leaves it.
    #[test]
    fn test_every_write_that_can_change_whether_a_change_is_clear_makes_a_new_mark() {
        let conn = db::open_in_memory().unwrap();
        let mark = || clear_mark(&conn).unwrap().unwrap();
        let writes = [
            "INSERT INTO person (one, state, phrase_key, statement_key, phrase_channel, statement)
                 VALUES (1, 'applied', zeroblob(32), zeroblob(32), zeroblob(32), X'01')",
            "UPDATE person SET statement = X'02'",
            "INSERT INTO person_additions (record, key, adder, counted, seen_at)
                 VALUES (X'01', zeroblob(32), zeroblob(32), 0, 9)",
            "UPDATE person_additions SET counted = 1",
            "DELETE FROM person_additions",
            "INSERT INTO person_removed_keys (key, seen_at) VALUES (zeroblob(32), 9)",
            "UPDATE person_removed_keys SET seen_at = 10",
            "DELETE FROM person_removed_keys",
            "INSERT INTO person_holders (number, hash, key) VALUES (3, zeroblob(16), zeroblob(32))",
            "UPDATE person_holders SET number = 4",
            "DELETE FROM person_holders",
            "INSERT INTO person_holders_past (number, hash) VALUES (3, zeroblob(16))",
            "UPDATE person_holders_past SET number = 4",
            "DELETE FROM person_holders_past",
            "DELETE FROM person",
        ];
        for write in writes {
            let before = mark();
            conn.execute_batch("SAVEPOINT one").unwrap();
            conn.execute_batch(write).unwrap();
            let after = mark();
            assert_ne!(after, before, "{write}");
            conn.execute_batch("ROLLBACK TO one").unwrap();
            assert_eq!(mark(), before, "undone: {write}");
            conn.execute_batch(write).unwrap();
            conn.execute_batch("RELEASE one").unwrap();
            assert_ne!(mark(), before, "{write}");
        }
        // The mark past the bound, by the key that `meta` names.
        let key = crate::meta::PERSON_REMOVED_PAST_BOUND;
        let before = mark();
        crate::meta::set(&conn, key, "1").unwrap();
        assert_ne!(mark(), before);
        let before = mark();
        crate::meta::set(&conn, key, "2").unwrap();
        assert_ne!(mark(), before);
        let before = mark();
        crate::meta::remove(&conn, key).unwrap();
        assert_ne!(mark(), before);
        // Anything else leaves it.
        let before = mark();
        crate::meta::set(&conn, "person.something_else", "1").unwrap();
        crate::meta::remove(&conn, "person.something_else").unwrap();
        conn.execute(
            "INSERT INTO person_names (name, channel, held_at) VALUES ('notes', zeroblob(32), 9)",
            [],
        )
        .unwrap();
        assert_eq!(mark(), before);
    }

    // ── What it follows, and where it stands ─────────────────────────

    #[test]
    fn test_a_device_with_no_row_follows_no_phrase() {
        let conn = db::open_in_memory().unwrap();
        assert_eq!(person(&conn).unwrap(), None);
        assert_eq!(applied_secret(&conn).unwrap(), None);
        assert!(secrets(&conn).unwrap().is_empty());
        assert_eq!(followed_entry(&conn).unwrap(), None);
        assert!(set_aside_entries(&conn).unwrap().is_empty());
        assert!(additions(&conn).unwrap().is_empty());
        assert!(names(&conn).unwrap().is_empty());
        // It has no state to change.
        assert!(set_state(&conn, State::Fork).is_err());
        assert_eq!(person(&conn).unwrap(), None);
    }

    /// A device that forgets what it follows has no row, and so follows
    /// no phrase. Its names stay, and so does whatever its other tables
    /// hold: each is forgotten by a function of its own.
    #[test]
    fn test_a_device_that_forgets_what_it_follows_has_no_row_and_keeps_its_names() {
        let conn = db::open_in_memory().unwrap();
        assert!(!forget_person(&conn).unwrap());
        put_person(&conn, &sample(State::Removed)).unwrap();
        apply_secret(&conn, 1, &[7; 32], 100).unwrap();
        hold_name(&conn, "notes", &[8; 32], 100).unwrap();
        assert!(forget_person(&conn).unwrap());
        assert_eq!(person(&conn).unwrap(), None);
        assert!(!forget_person(&conn).unwrap());
        assert_eq!(names(&conn).unwrap().len(), 1);
        assert_eq!(secrets(&conn).unwrap().len(), 1);
    }

    #[test]
    fn test_what_a_device_follows_is_read_back_as_it_was_written() {
        let conn = db::open_in_memory().unwrap();
        for state in [
            State::Applied,
            State::Fork,
            State::Removed,
            State::NotListed,
            State::NotOpened,
        ] {
            put_person(&conn, &sample(state)).unwrap();
            assert_eq!(person(&conn).unwrap(), Some(sample(state)));
        }

        // There is one row: a second writing takes the place of the first.
        let other = Person {
            state: State::Applied,
            following: following(0x40),
            statement: vec![9; 300],
        };
        put_person(&conn, &other).unwrap();
        assert_eq!(person(&conn).unwrap(), Some(other.clone()));
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM person", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1);

        // A change of state changes the state, and nothing else.
        set_state(&conn, State::Removed).unwrap();
        assert_eq!(
            person(&conn).unwrap(),
            Some(Person {
                state: State::Removed,
                ..other
            })
        );
    }

    /// The six states a device can be in: no row, and five that the table
    /// names. It takes no other.
    #[test]
    fn test_a_device_is_in_one_of_six_states() {
        let conn = db::open_in_memory().unwrap();
        put_person(&conn, &sample(State::Applied)).unwrap();
        let names: Vec<&str> = [
            State::Applied,
            State::Fork,
            State::Removed,
            State::NotListed,
            State::NotOpened,
        ]
        .iter()
        .map(|state| state.as_str())
        .collect();
        assert_eq!(
            names,
            ["applied", "fork", "removed", "not_listed", "not_opened"]
        );
        for name in names {
            assert_eq!(
                conn.execute("UPDATE person SET state = ?1", params![name]),
                Ok(1)
            );
            assert_eq!(State::parse(name).map(State::as_str), Some(name));
        }
        assert!(
            conn.execute("UPDATE person SET state = 'settled'", [])
                .is_err()
        );
        assert_eq!(State::parse("settled"), None);
        // A second row, and a key of another length.
        assert!(
            conn.execute(
                "INSERT INTO person (one, state, phrase_key, statement_key, phrase_channel,
                                     statement)
                 SELECT 2, state, phrase_key, statement_key, phrase_channel, statement
                 FROM person",
                [],
            )
            .is_err()
        );
        for column in ["phrase_key", "statement_key", "phrase_channel"] {
            assert!(
                conn.execute(&format!("UPDATE person SET {column} = X'0102'"), [])
                    .is_err(),
                "{column}"
            );
        }
    }

    // ── Its secrets ──────────────────────────────────────────────────

    #[test]
    fn test_the_secret_it_has_applied_and_each_one_it_left_with_its_time() {
        let conn = db::open_in_memory().unwrap();
        apply_secret(&conn, 1, &[0xa1; 32], NOW).unwrap();
        assert_eq!(
            secrets(&conn).unwrap(),
            [Secret {
                number: 1,
                secret: [0xa1; 32],
                left_at: None
            }]
        );
        assert_eq!(applied_secret(&conn).unwrap().unwrap().number, 1);

        // The next is the applied one, and the first is left, with the
        // time. A device that was two statements behind leaves one.
        apply_secret(&conn, 2, &[0xa2; 32], NOW + 5).unwrap();
        apply_secret(&conn, 4, &[0xa4; 32], NOW + 9).unwrap();
        let held = secrets(&conn).unwrap();
        let said: Vec<(u64, u8, Option<i64>)> = held
            .iter()
            .map(|secret| (secret.number, secret.secret[0], secret.left_at))
            .collect();
        assert_eq!(
            said,
            [
                (4, 0xa4, None),
                (2, 0xa2, Some(NOW + 9)),
                (1, 0xa1, Some(NOW + 5))
            ]
        );
        assert_eq!(
            applied_secret(&conn).unwrap(),
            Some(Secret {
                number: 4,
                secret: [0xa4; 32],
                left_at: None
            })
        );
    }

    /// The secrets that were left are listed by the number of their
    /// statement, the highest first, and not by the time they were left: a
    /// clock that was set back does not reorder them.
    #[test]
    fn test_the_secrets_that_were_left_are_listed_by_number_and_not_by_time() {
        let conn = db::open_in_memory().unwrap();
        apply_secret(&conn, 1, &[0xa1; 32], NOW).unwrap();
        apply_secret(&conn, 2, &[0xa2; 32], NOW + 50).unwrap();
        // The clock was set back before the next two were applied: secret
        // 2 was left before secret 1 by the clock, and secret 4 at the
        // very time that secret 2 was.
        apply_secret(&conn, 4, &[0xa4; 32], NOW - 1000).unwrap();
        apply_secret(&conn, 5, &[0xa5; 32], NOW - 1000).unwrap();
        apply_secret(&conn, 9, &[0xa9; 32], NOW + 7).unwrap();
        let said: Vec<(u64, Option<i64>)> = secrets(&conn)
            .unwrap()
            .iter()
            .map(|secret| (secret.number, secret.left_at))
            .collect();
        assert_eq!(
            said,
            [
                (9, None),
                (5, Some(NOW + 7)),
                (4, Some(NOW - 1000)),
                (2, Some(NOW - 1000)),
                (1, Some(NOW + 50)),
            ]
        );

        // Two that were left at one number, as a device holds that was
        // written to past the rule: the greater secret first, whichever
        // was left last.
        let conn = db::open_in_memory().unwrap();
        apply_secret(&conn, 3, &[0xb3; 32], NOW).unwrap();
        apply_secret(&conn, 3, &[0xa3; 32], NOW + 1).unwrap();
        apply_secret(&conn, 3, &[0xc3; 32], NOW + 2).unwrap();
        apply_secret(&conn, 4, &[0xa4; 32], NOW + 3).unwrap();
        let said: Vec<u8> = secrets(&conn)
            .unwrap()
            .iter()
            .map(|secret| secret.secret[0])
            .collect();
        assert_eq!(said, [0xa4, 0xc3, 0xb3, 0xa3]);
    }

    /// The table holds one applied secret at most, and a secret once. A
    /// writing that would break either changes nothing: the secret that
    /// was applied is still the applied one.
    #[test]
    fn test_one_secret_is_the_applied_one() {
        let conn = db::open_in_memory().unwrap();
        apply_secret(&conn, 1, &[0xa1; 32], NOW).unwrap();
        apply_secret(&conn, 2, &[0xa2; 32], NOW + 1).unwrap();

        // The secret it left, given again as one to apply: it is held
        // already, and both writings are undone.
        assert!(apply_secret(&conn, 1, &[0xa1; 32], NOW + 2).is_err());
        let applied = applied_secret(&conn).unwrap().unwrap();
        assert_eq!((applied.number, applied.left_at), (2, None));
        assert_eq!(secrets(&conn).unwrap().len(), 2);

        // A second secret with no time, written past the function.
        assert!(
            conn.execute(
                "INSERT INTO person_secrets (number, secret, left_at)
                 VALUES (3, zeroblob(32), NULL)",
                [],
            )
            .is_err()
        );
        // A number that no statement has, and a secret of another length.
        assert!(apply_secret(&conn, 0, &[0xa3; 32], NOW).is_err());
        assert!(apply_secret(&conn, 257, &[0xa3; 32], NOW).is_err());
        assert!(
            conn.execute(
                "INSERT INTO person_secrets (number, secret, left_at) VALUES (3, X'01', 5)",
                [],
            )
            .is_err()
        );
        assert_eq!(applied_secret(&conn).unwrap().unwrap().number, 2);

        // Two secrets of one number, where two changes were made apart.
        conn.execute(
            "INSERT INTO person_secrets (number, secret, left_at) VALUES (1, zeroblob(32), 5)",
            [],
        )
        .unwrap();
        assert_eq!(secrets(&conn).unwrap().len(), 3);
    }

    /// A secret that was left is kept 90 days by the device's own clock,
    /// and then forgotten. The applied one is never forgotten here.
    #[test]
    fn test_a_secret_that_was_left_is_forgotten_after_90_days() {
        let conn = db::open_in_memory().unwrap();
        apply_secret(&conn, 1, &[0xa1; 32], NOW - 400 * DAY).unwrap();
        apply_secret(&conn, 2, &[0xa2; 32], NOW).unwrap();
        apply_secret(&conn, 3, &[0xa3; 32], NOW + DAY).unwrap();
        let numbers = |conn: &Connection| -> Vec<u64> {
            secrets(conn)
                .unwrap()
                .iter()
                .map(|secret| secret.number)
                .collect()
        };
        assert_eq!(numbers(&conn), [3, 2, 1]);

        // One second short of 90 days after the first was left: all kept.
        assert_eq!(forget_left_secrets(&conn, NOW + 90 * DAY - 1).unwrap(), 0);
        assert_eq!(numbers(&conn), [3, 2, 1]);
        // A clock that has gone back forgets nothing.
        assert_eq!(forget_left_secrets(&conn, NOW - 500 * DAY).unwrap(), 0);
        assert_eq!(forget_left_secrets(&conn, 0).unwrap(), 0);

        // At 90 days the first is forgotten, and the second a day later.
        assert_eq!(forget_left_secrets(&conn, NOW + 90 * DAY).unwrap(), 1);
        assert_eq!(numbers(&conn), [3, 2]);
        assert_eq!(forget_left_secrets(&conn, NOW + 90 * DAY).unwrap(), 0);
        assert_eq!(forget_left_secrets(&conn, NOW + 91 * DAY).unwrap(), 1);
        assert_eq!(numbers(&conn), [3]);

        // The applied one stays, however long ago it was applied.
        assert_eq!(forget_left_secrets(&conn, NOW + 9000 * DAY).unwrap(), 0);
        assert_eq!(forget_left_secrets(&conn, i64::MAX).unwrap(), 0);
        let applied = applied_secret(&conn).unwrap().unwrap();
        assert_eq!((applied.number, applied.secret), (3, [0xa3; 32]));
        assert_eq!(KEPT_SECS, 7_776_000);
    }

    /// A machine that recovers keeps the secret of the generation it
    /// recovered from, and those before it, as secrets it left then
    /// (decision 2026-10-04 §3, §9): each is listed with the left ones,
    /// and forgotten 90 days after. One that the device holds already
    /// stays as it is, and the applied one stays the applied one.
    #[test]
    fn test_a_secret_that_a_recovery_hands_over_is_kept_as_one_that_was_left() {
        let conn = db::open_in_memory().unwrap();
        apply_secret(&conn, 4, &[0xa4; 32], NOW).unwrap();
        assert!(keep_left_secret(&conn, 3, &[0xa3; 32], NOW).unwrap());
        assert!(keep_left_secret(&conn, 2, &[0xa2; 32], NOW).unwrap());
        // Two generations can have one number, after two changes made
        // apart: each is kept.
        assert!(keep_left_secret(&conn, 2, &[0xb2; 32], NOW).unwrap());
        // Kept twice, it is kept once, and as it was first kept.
        assert!(!keep_left_secret(&conn, 3, &[0xa3; 32], NOW + 50 * DAY).unwrap());
        // The applied one is not made a left one by it.
        assert!(!keep_left_secret(&conn, 4, &[0xa4; 32], NOW).unwrap());
        let held: Vec<(u64, [u8; 32], Option<i64>)> = secrets(&conn)
            .unwrap()
            .into_iter()
            .map(|secret| (secret.number, secret.secret, secret.left_at))
            .collect();
        assert_eq!(
            held,
            [
                (4, [0xa4; 32], None),
                (3, [0xa3; 32], Some(NOW)),
                (2, [0xb2; 32], Some(NOW)),
                (2, [0xa2; 32], Some(NOW)),
            ]
        );
        // For 90 days from when the recovery was made, and no longer.
        assert_eq!(forget_left_secrets(&conn, NOW + 90 * DAY - 1).unwrap(), 0);
        assert_eq!(forget_left_secrets(&conn, NOW + 90 * DAY).unwrap(), 3);
        let applied = applied_secret(&conn).unwrap().unwrap();
        assert_eq!((applied.number, applied.secret), (4, [0xa4; 32]));
        // A number that no statement has is refused by the table.
        assert!(keep_left_secret(&conn, 0, &[1; 32], NOW).is_err());
        assert!(keep_left_secret(&conn, 257, &[1; 32], NOW).is_err());
    }

    /// A device that leaves its phrase forgets every secret it holds, the
    /// applied one among them, and can then apply the first it is given
    /// under another.
    #[test]
    fn test_a_device_that_leaves_its_phrase_forgets_every_secret() {
        let conn = db::open_in_memory().unwrap();
        assert_eq!(forget_secrets(&conn).unwrap(), 0);
        apply_secret(&conn, 1, &[0xa1; 32], NOW).unwrap();
        apply_secret(&conn, 2, &[0xa2; 32], NOW + 1).unwrap();
        apply_secret(&conn, 3, &[0xa3; 32], NOW + 2).unwrap();
        assert_eq!(forget_secrets(&conn).unwrap(), 3);
        assert!(secrets(&conn).unwrap().is_empty());
        assert_eq!(applied_secret(&conn).unwrap(), None);

        // Under another phrase a secret of a number it held before.
        apply_secret(&conn, 2, &[0xb2; 32], NOW + 3).unwrap();
        assert_eq!(
            secrets(&conn).unwrap(),
            [Secret {
                number: 2,
                secret: [0xb2; 32],
                left_at: None
            }]
        );
    }

    // ── The change entries it keeps ──────────────────────────────────

    #[test]
    fn test_a_change_entry_is_kept_whole_and_read_back_as_it_was() {
        let conn = db::open_in_memory().unwrap();
        let (followed, apart) = (text(0x51, 3), text(0x51, 4));
        keep_followed(&conn, &followed).unwrap();
        let read = followed_entry(&conn).unwrap().unwrap();
        assert_eq!(read, *followed);
        // It is whole: it passes the check again, as it must to be shown
        // to a relay.
        assert_eq!(read.check().unwrap(), followed);
        assert!(set_aside_entries(&conn).unwrap().is_empty());

        // A head set aside is kept beside it, with when it was set aside.
        let place = set_aside(&conn, &apart, NOW).unwrap();
        assert_eq!(followed_entry(&conn).unwrap().unwrap(), *followed);
        let aside = set_aside_entries(&conn).unwrap();
        assert_eq!(
            aside,
            vec![SetAside {
                place,
                entry: (*apart).clone(),
                set_aside_at: NOW,
            }]
        );
        assert_eq!(aside[0].entry.clone().check().unwrap(), apart);

        // A later one takes the place of the change followed, and no
        // other's.
        let later = text(0x51, 5);
        keep_followed(&conn, &later).unwrap();
        assert_eq!(followed_entry(&conn).unwrap().unwrap(), *later);
        assert_eq!(set_aside_entries(&conn).unwrap().len(), 1);

        assert!(drop_set_aside(&conn, place).unwrap());
        assert!(!drop_set_aside(&conn, place).unwrap());
        assert!(set_aside_entries(&conn).unwrap().is_empty());
        assert_eq!(followed_entry(&conn).unwrap().unwrap(), *later);
        assert_eq!(drop_change_entries(&conn).unwrap(), 1);
        assert_eq!(followed_entry(&conn).unwrap(), None);
    }

    /// The heads set aside are listed the highest number first, and of
    /// two at one number the first set aside first (decision 2026-10-24
    /// (removal), rule 1). One kept already, as followed or set aside, is
    /// not kept twice; the change followed is never dropped as one set
    /// aside; and there is one change followed at most.
    #[test]
    fn test_the_heads_set_aside_are_listed_by_number_and_kept_once() {
        let conn = db::open_in_memory().unwrap();
        let followed = text(0x51, 3);
        keep_followed(&conn, &followed).unwrap();
        let (three, five, five_again) = (text(0x52, 3), text(0x53, 5), text(0x54, 5));
        let p3 = set_aside(&conn, &three, NOW).unwrap();
        let p5 = set_aside(&conn, &five, NOW + 1).unwrap();
        let p5b = set_aside(&conn, &five_again, NOW + 2).unwrap();
        let places: Vec<i64> = set_aside_entries(&conn)
            .unwrap()
            .iter()
            .map(|head| head.place)
            .collect();
        assert_eq!(places, vec![p5, p5b, p3]);
        assert!(set_aside(&conn, &five, NOW + 3).is_err());
        assert!(set_aside(&conn, &followed, NOW + 3).is_err());
        assert!(set_aside(&conn, &entry(0x55, 4, Value::Delete), NOW).is_err());
        let followed_place: i64 = conn
            .query_row(
                "SELECT place FROM person_change_entries WHERE followed = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!drop_set_aside(&conn, followed_place).unwrap());
        assert!(
            conn.execute(
                "UPDATE person_change_entries SET followed = 1, set_aside_at = NULL
                 WHERE place = ?1",
                params![p3],
            )
            .is_err(),
            "a second change followed"
        );
        assert_eq!(drop_all_set_aside(&conn).unwrap(), 3);
        assert_eq!(followed_entry(&conn).unwrap().unwrap(), *followed);
    }

    /// A change noted says whether it filled what was not noted before:
    /// its time, or its lists (decision 2026-10-24 (removal), rule 6, where
    /// records are judged again).
    #[test]
    fn test_a_change_noted_says_whether_it_filled_anything() {
        let conn = db::open_in_memory().unwrap();
        let lists = |conn: &Connection, made_at| {
            note_change(
                conn,
                3,
                &[3; 16],
                made_at,
                Some(&[[9; 32]]),
                Some(&[(2, [2; 16])]),
                Some(&[]),
                Some(&[5; 32]),
            )
            .unwrap()
        };
        assert!(!note_change(&conn, 3, &[3; 16], None, None, None, None, None).unwrap());
        assert!(lists(&conn, None));
        assert!(!lists(&conn, None));
        assert!(lists(&conn, Some(NOW)));
        assert!(!lists(&conn, Some(NOW + 9)));
        assert!(note_change(&conn, 4, &[4; 16], Some(NOW), None, None, None, None).unwrap());
        // The commitment is noted with the lists.
        let noted = changes_noted(&conn).unwrap();
        assert_eq!(noted[0].commitment, Some([5; 32]));
        assert_eq!(noted[1].commitment, None);
    }

    /// The time of each change is kept by its number and hash, once, as
    /// its lineage says it, or as none (decision 2026-10-24 (removal), rule
    /// 2); it goes only where the device leaves its phrase.
    #[test]
    fn test_the_time_of_each_change_is_kept_once_until_the_phrase_is_left() {
        let conn = db::open_in_memory().unwrap();
        assert_eq!(change_time(&conn, 3, &[3; 16]).unwrap(), None);
        note_change_time(&conn, 3, &[3; 16], Some(NOW)).unwrap();
        note_change_time(&conn, 3, &[3; 16], Some(NOW + 9)).unwrap();
        note_change_time(&conn, 2, &[2; 16], None).unwrap();
        assert_eq!(change_time(&conn, 3, &[3; 16]).unwrap(), Some(Some(NOW)));
        assert_eq!(change_time(&conn, 2, &[2; 16]).unwrap(), Some(None));
        assert_eq!(change_time(&conn, 3, &[4; 16]).unwrap(), None);
        forget_removals(&conn).unwrap();
        assert_eq!(change_time(&conn, 3, &[3; 16]).unwrap(), None);
        note_change_time(&conn, 3, &[3; 16], Some(NOW)).unwrap();
        assert_eq!(forget_change_times(&conn).unwrap(), 1);
    }

    #[test]
    fn test_what_is_no_change_entry_is_not_kept() {
        let conn = db::open_in_memory().unwrap();
        // A delete.
        let delete = entry(0x51, 3, Value::Delete);
        assert!(keep_followed(&conn, &delete).is_err());
        // A revision that no statement's number is.
        assert!(keep_followed(&conn, &text(0x51, 257)).is_err());
        assert_eq!(followed_entry(&conn).unwrap(), None);

        keep_followed(&conn, &text(0x51, 256)).unwrap();
        // A change followed has no time it was set aside, and a head set
        // aside has one.
        assert!(
            conn.execute("UPDATE person_change_entries SET set_aside_at = 9", [])
                .is_err()
        );
        for column in ["channel", "slot", "author", "author_sig", "channel_sig"] {
            assert!(
                conn.execute(
                    &format!("UPDATE person_change_entries SET {column} = X'0102'"),
                    []
                )
                .is_err(),
                "{column}"
            );
        }
    }

    // ── The records of additions it has seen ─────────────────────────

    #[test]
    fn test_records_are_kept_in_the_order_they_were_seen() {
        let conn = db::open_in_memory().unwrap();
        let record = |n: u8| vec![n; 100];
        for (n, counted) in [(3u8, true), (1, false), (2, true)] {
            let kept = keep_addition(
                &conn,
                &record(n),
                &[n; 32],
                &[0xd0; 32],
                counted,
                NOW + i64::from(n),
            );
            assert!(kept.unwrap());
        }
        let held = additions(&conn).unwrap();
        let said: Vec<(u8, bool, i64)> = held
            .iter()
            .map(|kept| (kept.key[0], kept.counted, kept.seen_at))
            .collect();
        assert_eq!(
            said,
            [(3, true, NOW + 3), (1, false, NOW + 1), (2, true, NOW + 2)]
        );
        assert!(held.windows(2).all(|pair| pair[0].seen < pair[1].seen));
        assert_eq!(held[0].record, record(3));
        assert_eq!(held[0].adder, [0xd0; 32]);

        // A record that is kept is not kept twice, and stays as it was:
        // not counted, though it is given as counted.
        assert!(!keep_addition(&conn, &record(1), &[1; 32], &[0xd0; 32], true, NOW + 50).unwrap());
        assert_eq!(additions(&conn).unwrap(), held);

        // At the next statement none is kept.
        assert_eq!(clear_additions(&conn).unwrap(), 3);
        assert!(additions(&conn).unwrap().is_empty());
        assert_eq!(clear_additions(&conn).unwrap(), 0);
        // And the order starts again.
        keep_addition(&conn, &record(9), &[9; 32], &[0xd0; 32], true, NOW).unwrap();
        assert_eq!(additions(&conn).unwrap().len(), 1);

        // Whether a record is counted is yes or no, and a key is 32 bytes.
        assert!(
            conn.execute("UPDATE person_additions SET counted = 2", [])
                .is_err()
        );
        for column in ["key", "adder"] {
            assert!(
                conn.execute(
                    &format!("UPDATE person_additions SET {column} = X'0102'"),
                    []
                )
                .is_err(),
                "{column}"
            );
        }
    }

    /// A record that was kept as not counted comes to count, and keeps its
    /// place in the order the records were seen. No other record changes.
    #[test]
    fn test_a_record_kept_as_not_counted_comes_to_count_in_its_place() {
        let conn = db::open_in_memory().unwrap();
        for (n, counted) in [(3u8, true), (1, false), (2, false)] {
            keep_addition(&conn, &[n; 100], &[n; 32], &[0xd0; 32], counted, NOW).unwrap();
        }
        let before = additions(&conn).unwrap();
        count_addition(&conn, before[1].seen).unwrap();
        let after = additions(&conn).unwrap();
        let said: Vec<(u8, bool)> = after
            .iter()
            .map(|kept| (kept.key[0], kept.counted))
            .collect();
        assert_eq!(said, [(3, true), (1, true), (2, false)]);
        let places = |kept: &[KeptAddition]| kept.iter().map(|one| one.seen).collect::<Vec<_>>();
        assert_eq!(places(&after), places(&before));
        assert_eq!(after[1].record, before[1].record);

        // One that counts already stays so, and a place that holds no
        // record is refused.
        count_addition(&conn, before[0].seen).unwrap();
        assert!(count_addition(&conn, before[2].seen + 1).is_err());
        assert_eq!(additions(&conn).unwrap(), after);
    }

    /// A record that is not counted is dropped by its place. A record
    /// that counts stays, and those that stay keep their places.
    #[test]
    fn test_a_record_that_is_not_counted_is_dropped_by_its_place() {
        let conn = db::open_in_memory().unwrap();
        // Five records, of which the first and the fourth count.
        for n in 1..=5u8 {
            let counted = [1, 4].contains(&n);
            keep_addition(&conn, &[n; 100], &[n; 32], &[0xd0; 32], counted, NOW).unwrap();
        }
        let before = additions(&conn).unwrap();
        let places: Vec<i64> = before.iter().map(|one| one.seen).collect();

        // The third goes, and no other.
        drop_not_counted(&conn, places[2]).unwrap();
        let mut after = before.clone();
        after.remove(2);
        assert_eq!(additions(&conn).unwrap(), after);

        // A record that counts is not dropped, and nor is a place that
        // holds none: the one that went, and one beyond the last.
        for place in [places[0], places[3], places[2], places[4] + 1] {
            assert!(drop_not_counted(&conn, place).is_err(), "{place}");
        }
        assert_eq!(additions(&conn).unwrap(), after);
    }

    // ── The names it holds ───────────────────────────────────────────

    #[test]
    fn test_a_channels_id_is_found_from_a_name_and_a_name_from_it() {
        let conn = db::open_in_memory().unwrap();
        assert!(hold_name(&conn, "team", &[0x71; 32], NOW).unwrap());
        assert!(hold_name(&conn, "github.com/owner/repo", &[0x72; 32], NOW + 1).unwrap());
        assert_eq!(channel_of_name(&conn, "team").unwrap(), Some([0x71; 32]));
        assert_eq!(
            name_of_channel(&conn, &[0x72; 32]).unwrap().as_deref(),
            Some("github.com/owner/repo")
        );
        assert_eq!(channel_of_name(&conn, "other").unwrap(), None);
        assert_eq!(name_of_channel(&conn, &[0x73; 32]).unwrap(), None);
        let held = names(&conn).unwrap();
        assert_eq!(
            held,
            [
                HeldName {
                    name: "github.com/owner/repo".to_string(),
                    channel: [0x72; 32],
                    held_at: NOW + 1
                },
                HeldName {
                    name: "team".to_string(),
                    channel: [0x71; 32],
                    held_at: NOW
                },
            ]
        );

        // A name that is held stays as it is.
        assert!(!hold_name(&conn, "team", &[0x79; 32], NOW + 9).unwrap());
        assert_eq!(names(&conn).unwrap(), held);
        // A channel is one name's, and a name is at least one byte.
        assert!(hold_name(&conn, "other", &[0x71; 32], NOW).is_err());
        assert!(hold_name(&conn, "", &[0x74; 32], NOW).is_err());
        assert_eq!(names(&conn).unwrap(), held);
        // A channel's ID is 32 bytes. A row with another length, written
        // by SQL past the function, is refused: as a new name's, and as
        // the channel of one name that is held.
        for other in ["X'0102'", "zeroblob(0)", "zeroblob(31)", "zeroblob(33)"] {
            let written = conn.execute(
                &format!(
                    "INSERT INTO person_names (name, channel, held_at)
                     VALUES ('of another length', {other}, 5)"
                ),
                [],
            );
            assert!(written.is_err(), "{other}");
            let changed = conn.execute(
                &format!("UPDATE person_names SET channel = {other} WHERE name = 'team'"),
                [],
            );
            assert!(changed.is_err(), "{other}");
        }
        assert_eq!(names(&conn).unwrap(), held);
        // The control: one of 32 bytes, written the same way, is taken.
        conn.execute(
            "INSERT INTO person_names (name, channel, held_at)
             VALUES ('of 32 bytes', zeroblob(32), 5)",
            [],
        )
        .unwrap();
        assert!(drop_name(&conn, "of 32 bytes").unwrap());
        assert_eq!(names(&conn).unwrap(), held);

        // At a statement a name's channel is another: the name is found
        // from the new one, and from the old one no more.
        move_name(&conn, "team", &[0x81; 32]).unwrap();
        assert_eq!(channel_of_name(&conn, "team").unwrap(), Some([0x81; 32]));
        assert_eq!(
            name_of_channel(&conn, &[0x81; 32]).unwrap().as_deref(),
            Some("team")
        );
        assert_eq!(name_of_channel(&conn, &[0x71; 32]).unwrap(), None);
        assert_eq!(names(&conn).unwrap()[1].held_at, NOW);
        // A name that is not held has no channel to move.
        assert!(move_name(&conn, "other", &[0x82; 32]).is_err());

        assert!(drop_name(&conn, "team").unwrap());
        assert!(!drop_name(&conn, "team").unwrap());
        assert_eq!(channel_of_name(&conn, "team").unwrap(), None);
        assert_eq!(names(&conn).unwrap().len(), 1);
    }

    // ── The last hand-over it made for each key ──────────────────────

    /// A device keeps, of the last hand-over it made for each key, where
    /// it is and how it is ordered. Once the store holds it no longer,
    /// its revision stays.
    #[test]
    fn test_the_last_hand_over_for_a_key_is_kept_by_its_revision_and_no_more() {
        let conn = db::open_in_memory().unwrap();
        assert_eq!(handed_over(&conn, &[1; 32]).unwrap(), None);
        assert!(hand_overs_held(&conn).unwrap().is_empty());
        assert!(!hand_over_gone(&conn, &[1; 32]).unwrap());

        note_hand_over(&conn, &[1; 32], &[0x71; 32], 500, NOW + 9).unwrap();
        note_hand_over(&conn, &[2; 32], &[0x72; 32], 7, NOW).unwrap();
        let first = HandedOver {
            key: [1; 32],
            channel: [0x71; 32],
            rev: 500,
            made_at: NOW + 9,
            held: true,
        };
        assert_eq!(handed_over(&conn, &[1; 32]).unwrap(), Some(first.clone()));
        // Those the store holds, in order of when they were made.
        let held = hand_overs_held(&conn).unwrap();
        assert_eq!(held.len(), 2);
        assert_eq!((held[0].key, held[1].clone()), ([2; 32], first.clone()));

        // The store holds one no longer: its revision stays.
        assert!(hand_overs_gone(&conn).unwrap().is_empty());
        assert!(hand_over_gone(&conn, &[1; 32]).unwrap());
        assert!(!hand_over_gone(&conn, &[1; 32]).unwrap());
        let gone = hand_overs_gone(&conn).unwrap();
        assert_eq!(gone.len(), 1);
        assert_eq!(
            (gone[0].key, gone[0].rev, gone[0].held),
            ([1; 32], 500, false)
        );
        let gone = HandedOver {
            held: false,
            ..first
        };
        assert_eq!(handed_over(&conn, &[1; 32]).unwrap(), Some(gone));
        assert_eq!(hand_overs_held(&conn).unwrap().len(), 1);
        assert_eq!(handed_over(&conn, &[2; 32]).unwrap().unwrap().rev, 7);

        // The next one for that key takes the place of what was kept.
        note_hand_over(&conn, &[1; 32], &[0x71; 32], 501, NOW + 60).unwrap();
        let next = handed_over(&conn, &[1; 32]).unwrap().unwrap();
        assert_eq!((next.rev, next.made_at, next.held), (501, NOW + 60, true));
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM person_hand_overs", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 2);

        // A key and a channel's ID are 32 bytes, a revision is at least
        // 1, and whether the store holds it is yes or no: one row is not
        // changed to say otherwise.
        assert!(note_hand_over(&conn, &[3; 32], &[0x73; 32], 0, NOW).is_err());
        for change in ["key = X'0102'", "channel = X'0102'", "rev = 0", "held = 2"] {
            let one_row = format!("UPDATE person_hand_overs SET {change} WHERE rev = 7");
            assert!(conn.execute(&one_row, []).is_err(), "{change}");
        }
        // The control: that row can be changed.
        let one_row = "UPDATE person_hand_overs SET held = 0 WHERE rev = 7";
        assert_eq!(conn.execute(one_row, []).unwrap(), 1);
        assert_eq!(handed_over(&conn, &[3; 32]).unwrap(), None);

        // A device that leaves its phrase keeps nothing of any: not the
        // one its store held, and not the revision of one that had gone.
        assert_eq!(forget_hand_overs(&conn).unwrap(), 2);
        assert_eq!(handed_over(&conn, &[1; 32]).unwrap(), None);
        assert_eq!(handed_over(&conn, &[2; 32]).unwrap(), None);
        assert!(hand_overs_held(&conn).unwrap().is_empty());
        assert_eq!(forget_hand_overs(&conn).unwrap(), 0);
    }

    /// The names that were listed before a statement are kept by name
    /// and by the key that had listed each, with when the generation was
    /// left: noted again, a name and key are noted as of the later time.
    /// A name that a device lists again is noted no more, whoever had
    /// listed it; each goes 90 days after its generation was left; and
    /// all go when the device leaves its phrase.
    #[test]
    fn test_the_names_that_were_listed_before_are_kept_until_listed_or_ninety_days() {
        let conn = db::open_in_memory().unwrap();
        assert!(names_before(&conn).unwrap().is_empty());
        let (a, b) = ([1u8; 32], [2u8; 32]);
        note_name_before(&conn, "notes", &b, NOW).unwrap();
        note_name_before(&conn, "notes", &a, NOW).unwrap();
        note_name_before(&conn, "app", &a, NOW).unwrap();
        let before = |name: &str, key: [u8; 32], left_at: i64| NameBefore {
            name: name.into(),
            key,
            left_at,
        };
        assert_eq!(
            names_before(&conn).unwrap(),
            [
                before("app", a, NOW),
                before("notes", a, NOW),
                before("notes", b, NOW)
            ]
        );
        // Noted again as of a later generation: one row still, of that
        // time.
        note_name_before(&conn, "notes", &a, NOW + DAY).unwrap();
        assert_eq!(
            names_before(&conn).unwrap()[1],
            before("notes", a, NOW + DAY)
        );
        assert_eq!(names_before(&conn).unwrap().len(), 3);

        // Ninety days after its generation was left, and not before.
        assert_eq!(
            forget_names_before(&conn, Some(NOW + 90 * DAY - 1)).unwrap(),
            0
        );
        assert_eq!(forget_names_before(&conn, Some(NOW + 90 * DAY)).unwrap(), 2);
        assert_eq!(
            names_before(&conn).unwrap(),
            [before("notes", a, NOW + DAY)]
        );

        // A name that is listed again goes, with every key that had
        // listed it, and no other name with it.
        note_name_before(&conn, "notes", &b, NOW).unwrap();
        note_name_before(&conn, "app", &b, NOW).unwrap();
        assert_eq!(forget_name_before(&conn, "notes").unwrap(), 2);
        assert_eq!(forget_name_before(&conn, "notes").unwrap(), 0);
        assert_eq!(names_before(&conn).unwrap(), [before("app", b, NOW)]);
        // One key's note of a name goes, and no other key's, and no other
        // name's.
        note_name_before(&conn, "app", &a, NOW).unwrap();
        note_name_before(&conn, "notes", &a, NOW).unwrap();
        assert!(forget_name_said_by(&conn, "app", &a).unwrap());
        assert!(!forget_name_said_by(&conn, "app", &a).unwrap());
        assert_eq!(
            names_before(&conn).unwrap(),
            [before("app", b, NOW), before("notes", a, NOW)]
        );
        assert!(forget_name_said_by(&conn, "notes", &a).unwrap());

        // All of them, where the device leaves its phrase.
        assert_eq!(forget_names_before(&conn, None).unwrap(), 1);
        assert!(names_before(&conn).unwrap().is_empty());
    }

    #[test]
    fn test_what_a_device_holds_prints_no_secret() {
        let secret = Secret {
            number: 3,
            secret: [0x9c; 32],
            left_at: Some(7),
        };
        assert_eq!(
            format!("{secret:?}"),
            "Secret { number: 3, left_at: Some(7), .. }"
        );
        let person = Person {
            state: State::Applied,
            following: Following {
                phrase_key: [0x9a; 32],
                statement_key: [0x9d; 32],
                phrase_channel: [0x9b; 32],
            },
            statement: Vec::new(),
        };
        let printed = format!("{person:?}");
        assert!(printed.contains("phrase_key: \"9a9a9a9a\""), "{printed}");
        assert!(!printed.contains("9d9d") && !printed.contains("157"));
    }
}
