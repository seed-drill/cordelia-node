//! What a device keeps of the repositories it follows (decision 2026-11-06
//! (joining), rules 2 to 6): the tables of schema step 33.
//!
//! - **The follows** (`shared_follows`): each repository this device
//!   follows, by its identity (`host/owner/name`), with the clone's remote
//!   and path, the last commit read with when and from where and when the
//!   person's git had last fetched it, the bytes of the last list read, the
//!   last key the node handed the channel to,
//!   after which its next turn starts (rule 4.2), and why the latest read
//!   counted for nothing, where it did (rules 1 and 3). Following again
//!   starts never-back over, and keeps the rest (rule 2.5).
//! - **The node's typings** (`shared_follow_typed`): the listed keys the node
//!   looks for shares from (rule 4.4), apart from the person's own typings
//!   (`shared_typed_keys`), with what became of each.
//! - **The notices** (`shared_follow_notices`): a key that joined from the
//!   list and a changed channel line, until a person clears them with
//!   `cordelia shared seen` (rules 4.5 and 6); and a key the list dropped,
//!   until it leaves the channel (rule 4.6). Each with its commit, and a
//!   key's with its label, which its line may no longer give.

//! - **The node's shares** (`shared_shares.by_node`), and **what a making
//!   anew left out, the line it printed and how many keys it was cut short
//!   of** (`shared_anew_made.left_out`, `line` and `cut`, rule 5).
//!
//! Nothing here reads a list or decides anything: that is done where these
//! are read. Every time here is the node's.
//!
//! Each write here runs in a savepoint of its own, so that it is one
//! write whether or not the caller holds a transaction.

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;
use cordelia_core::protocol::{MEMBERS_FILE_MAX_BYTES, SHARED_KEYS_KEPT};

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

/// `write` in a savepoint: done whole, or not at all, inside the caller's
/// transaction or alone.
fn in_savepoint<T>(
    conn: &Connection,
    write: impl FnOnce() -> Result<T, CordeliaError>,
) -> Result<T, CordeliaError> {
    conn.execute_batch("SAVEPOINT follows").map_err(storage)?;
    match write() {
        Ok(done) => match conn.execute_batch("RELEASE follows") {
            Ok(()) => Ok(done),
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK TO follows; RELEASE follows");
                Err(storage(e))
            }
        },
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK TO follows; RELEASE follows");
            Err(e)
        }
    }
}

// ── The follows ──────────────────────────────────────────────────────

/// A repository this device follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Follow {
    /// `host/owner/name`, in lower case.
    pub identity: String,
    /// The remote of the clone whose address names the identity.
    pub remote: String,
    /// The clone's path.
    pub clone: String,
    pub followed_at: i64,
    /// The last list read, where one was.
    pub last: Option<LastRead>,
    /// When the person's git had last fetched the branch the last list was
    /// read from, as the clone said then, where it said: for the status's
    /// "fetched 2 hours ago" (rule 3).
    pub fetched_at: Option<i64>,
    /// The bytes of the last list read.
    pub list: Option<Vec<u8>>,
    /// The last key the node handed the channel to: its next turn starts
    /// after it, in the list's order.
    pub last_handed: Option<[u8; 32]>,
    /// Why the latest read counted for nothing, where it did: the last
    /// list read stands.
    pub not_read: Option<NotRead>,
}

/// Why a read of the list counted for nothing (rules 1 and 3): a word, as
/// a status's JSON carries it, and why, said plainly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotRead {
    pub word: String,
    pub why: String,
}

/// When the last list was read, its commit, and whether it came from the
/// clone (or from the host).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastRead {
    pub commit: String,
    pub at: i64,
    pub from_clone: bool,
}

const FOLLOW_COLUMNS: &str = "identity, remote, clone, followed_at, last_commit, last_read_at, \
                              read_from, list, last_handed, not_read, not_read_why, fetched_at";

fn follow_of_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Follow> {
    let commit: Option<String> = row.get(4)?;
    let at: Option<i64> = row.get(5)?;
    let from: Option<i64> = row.get(6)?;
    let last_handed: Option<Vec<u8>> = row.get(8)?;
    let word: Option<String> = row.get(9)?;
    let why: Option<String> = row.get(10)?;
    Ok(Follow {
        identity: row.get(0)?,
        remote: row.get(1)?,
        clone: row.get(2)?,
        followed_at: row.get(3)?,
        last: match (commit, at, from) {
            (Some(commit), Some(at), Some(from)) => Some(LastRead {
                commit,
                at,
                from_clone: from == 1,
            }),
            _ => None,
        },
        fetched_at: row.get(11)?,
        list: row.get(7)?,
        last_handed: last_handed.and_then(|key| key.try_into().ok()),
        not_read: match (word, why) {
            (Some(word), Some(why)) => Some(NotRead { word, why }),
            _ => None,
        },
    })
}

/// This device follows `identity`, through `remote` of the clone at
/// `clone`, from `at`.
///
/// Following a repository again (rule 2.5) takes the remote and the clone
/// given, and forgets only the last commit read, with when and from
/// where: the caller sets them again in the same write
/// ([`set_last_read`]), at the commit the person's yes named, where
/// never-back starts over, for a history that was rewritten. It keeps the
/// rest: the list last read, which the next read is compared with (rule
/// 4.6); the notices, which go only as rules 4.5 and 4.6 say; the last key
/// handed and the node's typings; and when it was first followed, before
/// which no key's join is noticed (rule 4.5).
pub fn follow(
    conn: &Connection,
    identity: &str,
    remote: &str,
    clone: &str,
    at: i64,
) -> Result<(), CordeliaError> {
    in_savepoint(conn, || {
        let again = conn
            .execute(
                "UPDATE shared_follows SET remote = ?2, clone = ?3, last_commit = NULL,
                     last_read_at = NULL, read_from = NULL
                 WHERE identity = ?1",
                params![identity, remote, clone],
            )
            .map_err(storage)?;
        if again == 0 {
            conn.execute(
                "INSERT INTO shared_follows (identity, remote, clone, followed_at)
                     VALUES (?1, ?2, ?3, ?4)",
                params![identity, remote, clone, at],
            )
            .map_err(storage)?;
        }
        Ok(())
    })
}

/// Everything kept of `identity`, in the caller's write.
fn forget(conn: &Connection, identity: &str) -> Result<(), CordeliaError> {
    for table in [
        "shared_follows",
        "shared_follow_typed",
        "shared_follow_notices",
    ] {
        conn.execute(
            &format!("DELETE FROM {table} WHERE identity = ?1"),
            [identity],
        )
        .map_err(storage)?;
    }
    Ok(())
}

/// This device stops following `identity` (a `shared drop` of its channel,
/// rule 2.5): nothing of it is kept.
pub fn unfollow(conn: &Connection, identity: &str) -> Result<(), CordeliaError> {
    in_savepoint(conn, || forget(conn, identity))
}

/// This device follows nothing: it left its person (rule 2.5).
pub fn unfollow_all(conn: &Connection) -> Result<(), CordeliaError> {
    in_savepoint(conn, || {
        conn.execute_batch(
            "DELETE FROM shared_follows; DELETE FROM shared_follow_typed;
             DELETE FROM shared_follow_notices;",
        )
        .map_err(storage)
    })
}

/// Every repository this device follows, by identity.
pub fn follows(conn: &Connection) -> Result<Vec<Follow>, CordeliaError> {
    conn.prepare(&format!(
        "SELECT {FOLLOW_COLUMNS} FROM shared_follows ORDER BY identity"
    ))
    .map_err(storage)?
    .query_map([], follow_of_row)
    .map_err(storage)?
    .collect::<Result<_, _>>()
    .map_err(storage)
}

/// The follow of `identity`, where this device follows it.
pub fn follow_of(conn: &Connection, identity: &str) -> Result<Option<Follow>, CordeliaError> {
    conn.query_row(
        &format!("SELECT {FOLLOW_COLUMNS} FROM shared_follows WHERE identity = ?1"),
        [identity],
        follow_of_row,
    )
    .optional()
    .map_err(storage)
}

/// A list of `identity` was read: its commit, when, from where, its
/// bytes, and when the person's git had last fetched it, where the clone
/// said. Why an earlier read counted for nothing goes. Nothing is done for
/// a repository this device does not follow.
pub fn read_done(
    conn: &Connection,
    identity: &str,
    read: &LastRead,
    list: &[u8],
    fetched_at: Option<i64>,
) -> Result<bool, CordeliaError> {
    let changed = conn
        .execute(
            "UPDATE shared_follows SET last_commit = ?2, last_read_at = ?3, read_from = ?4,
                 list = ?5, fetched_at = ?6, not_read = NULL, not_read_why = NULL
             WHERE identity = ?1",
            params![
                identity,
                read.commit,
                read.at,
                read.from_clone as i64,
                list,
                fetched_at
            ],
        )
        .map_err(storage)?;
    Ok(changed == 1)
}

/// The last commit read of `identity`, when and from where, with the list
/// kept as it was: a person's yes to follow it again, whose commit is
/// where never-back starts over (rule 2.5), while the next read is
/// compared with the list last read (rule 4.6). Nothing is done for a
/// repository this device does not follow.
pub fn set_last_read(
    conn: &Connection,
    identity: &str,
    read: &LastRead,
) -> Result<bool, CordeliaError> {
    let changed = conn
        .execute(
            "UPDATE shared_follows SET last_commit = ?2, last_read_at = ?3, read_from = ?4
             WHERE identity = ?1",
            params![identity, read.commit, read.at, read.from_clone as i64],
        )
        .map_err(storage)?;
    Ok(changed == 1)
}

/// A read of the list of `identity` counted for nothing, for `not`: the
/// last list read stands, and this is kept until a read counts. A `why`
/// longer than the row keeps is cut, at a character.
pub fn not_read(conn: &Connection, identity: &str, not: &NotRead) -> Result<(), CordeliaError> {
    let why = cut(&not.why, NOT_READ_WHY_MAX_BYTES);
    conn.execute(
        "UPDATE shared_follows SET not_read = ?2, not_read_why = ?3 WHERE identity = ?1",
        params![identity, not.word, why],
    )
    .map_err(storage)?;
    Ok(())
}

/// The most of why a read counted for nothing that a row keeps, as schema
/// step 33 bounds it.
const NOT_READ_WHY_MAX_BYTES: usize = 1024;

/// The most of the line of what became of a typing that a row keeps, as
/// schema step 33 bounds it.
const TYPED_DETAIL_MAX_BYTES: usize = 1024;

/// `text`, cut at a character so that it is at most `max` bytes.
fn cut(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The last key the node handed the channel of `identity` to: its next
/// turn starts after it.
pub fn set_last_handed(
    conn: &Connection,
    identity: &str,
    key: &[u8; 32],
) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE shared_follows SET last_handed = ?2 WHERE identity = ?1",
        params![identity, &key[..]],
    )
    .map_err(storage)?;
    Ok(())
}

// ── The node's typings ───────────────────────────────────────────────

/// A listed key the node looks for a share from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Typed {
    pub key: [u8; 32],
    pub typed_at: i64,
    pub became: Option<String>,
    pub detail: Option<String>,
}

/// The node types `key` for `identity` at `at`, again where it had: what
/// became of it before goes.
pub fn type_key(
    conn: &Connection,
    identity: &str,
    key: &[u8; 32],
    at: i64,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT OR REPLACE INTO shared_follow_typed (identity, key, typed_at)
             VALUES (?1, ?2, ?3)",
        params![identity, &key[..], at],
    )
    .map_err(storage)?;
    Ok(())
}

/// What became of the node's typing of `key` for `identity`. A `detail`
/// longer than the row keeps is cut, at a character, so that what became
/// of it is always kept.
pub fn typed_became(
    conn: &Connection,
    identity: &str,
    key: &[u8; 32],
    became: &str,
    detail: Option<&str>,
) -> Result<(), CordeliaError> {
    let detail = detail.map(|detail| cut(detail, TYPED_DETAIL_MAX_BYTES));
    conn.execute(
        "UPDATE shared_follow_typed SET became = ?3, detail = ?4
             WHERE identity = ?1 AND key = ?2",
        params![identity, &key[..], became, detail],
    )
    .map_err(storage)?;
    Ok(())
}

/// The node's typings for `identity`, by key.
pub fn typed(conn: &Connection, identity: &str) -> Result<Vec<Typed>, CordeliaError> {
    conn.prepare(
        "SELECT key, typed_at, became, detail FROM shared_follow_typed
             WHERE identity = ?1 ORDER BY key",
    )
    .map_err(storage)?
    .query_map([identity], |row| {
        let key: Vec<u8> = row.get(0)?;
        Ok(Typed {
            key: key.try_into().unwrap_or([0; 32]),
            typed_at: row.get(1)?,
            became: row.get(2)?,
            detail: row.get(3)?,
        })
    })
    .map_err(storage)?
    .collect::<Result<_, _>>()
    .map_err(storage)
}

/// The node no longer looks for a share from `key` for `identity`.
pub fn untype(conn: &Connection, identity: &str, key: &[u8; 32]) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM shared_follow_typed WHERE identity = ?1 AND key = ?2",
        params![identity, &key[..]],
    )
    .map_err(storage)?;
    Ok(())
}

// ── The notices ──────────────────────────────────────────────────────

/// What a notice is of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoticeOf {
    /// A key that joined the channel from the list, with its label there
    /// (rule 4.5). Kept until a person clears it.
    Joined { key: [u8; 32], label: String },
    /// The list's channel line changed (rule 6). Kept until a person clears
    /// it; a later change takes the place of an earlier one not yet cleared.
    LineChanged,
    /// A key that an earlier read listed and the latest does not, with its
    /// label then (rule 4.6). Kept until it leaves the channel.
    Dropped { key: [u8; 32], label: String },
}

/// A notice, with the commit it was read at and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub of: NoticeOf,
    pub commit: String,
    pub at: i64,
}

/// A notice for `identity`. A key's notice already kept stays as it is;
/// a changed line takes the place of one not yet cleared, with its commit.
/// Returns whether anything was written.
pub fn notice(conn: &Connection, identity: &str, notice: &Notice) -> Result<bool, CordeliaError> {
    let (kind, key, label): (i64, Vec<u8>, Option<&str>) = match &notice.of {
        NoticeOf::Joined { key, label } => (1, key.to_vec(), Some(label)),
        NoticeOf::LineChanged => (2, Vec::new(), None),
        NoticeOf::Dropped { key, label } => (3, key.to_vec(), Some(label)),
    };
    let on_conflict = match kind {
        2 => {
            "DO UPDATE SET at_commit = excluded.at_commit, at = excluded.at
                  WHERE at_commit != excluded.at_commit"
        }
        _ => "DO NOTHING",
    };
    let written = conn
        .execute(
            &format!(
                "INSERT INTO shared_follow_notices (identity, kind, key, label, at_commit, at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (identity, kind, key) {on_conflict}"
            ),
            params![identity, kind, key, label, notice.commit, notice.at],
        )
        .map_err(storage)?;
    Ok(written == 1)
}

/// The notices of `identity`, oldest first.
pub fn notices(conn: &Connection, identity: &str) -> Result<Vec<Notice>, CordeliaError> {
    conn.prepare(
        "SELECT kind, key, label, at_commit, at FROM shared_follow_notices
             WHERE identity = ?1 ORDER BY at, kind, key",
    )
    .map_err(storage)?
    .query_map([identity], |row| {
        let kind: i64 = row.get(0)?;
        let key: Vec<u8> = row.get(1)?;
        let key: [u8; 32] = key.try_into().unwrap_or([0; 32]);
        let label: String = row.get::<_, Option<String>>(2)?.unwrap_or_default();
        Ok(Notice {
            of: match kind {
                1 => NoticeOf::Joined { key, label },
                3 => NoticeOf::Dropped { key, label },
                _ => NoticeOf::LineChanged,
            },
            commit: row.get(3)?,
            at: row.get(4)?,
        })
    })
    .map_err(storage)?
    .collect::<Result<_, _>>()
    .map_err(storage)
}

/// A person cleared the notices of `identity` (`cordelia shared seen`): the
/// joins and a changed line. A dropped key's stays until it leaves the
/// channel. Returns how many went.
pub fn seen(conn: &Connection, identity: &str) -> Result<usize, CordeliaError> {
    conn.execute(
        "DELETE FROM shared_follow_notices WHERE identity = ?1 AND kind IN (1, 2)",
        [identity],
    )
    .map_err(storage)
}

/// The key `key`, dropped from the list of `identity`, has left the channel,
/// or the list names it again: its notice goes. A key dropped again later
/// is then noticed afresh, with its new commit.
pub fn clear_dropped(
    conn: &Connection,
    identity: &str,
    key: &[u8; 32],
) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM shared_follow_notices WHERE identity = ?1 AND kind = 3 AND key = ?2",
        params![identity, &key[..]],
    )
    .map_err(storage)?;
    Ok(())
}

// ── The node's shares, and what a making anew printed ────────────────

/// The share of `channel` to `key` was made by the node, not a person.
pub fn by_node(conn: &Connection, key: &[u8; 32], channel: &[u8; 32]) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE shared_shares SET by_node = 1 WHERE key = ?1 AND channel = ?2",
        params![&key[..], &channel[..]],
    )
    .map_err(storage)?;
    Ok(())
}

/// A share the node made, not a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeShare {
    pub key: [u8; 32],
    pub channel: [u8; 32],
    pub made: i64,
}

/// The shares the node made, oldest first.
pub fn shares_by_node(conn: &Connection) -> Result<Vec<NodeShare>, CordeliaError> {
    conn.prepare(
        "SELECT key, channel, made FROM shared_shares WHERE by_node = 1 AND gone = 0
             ORDER BY made, key, channel",
    )
    .map_err(storage)?
    .query_map([], |row| {
        let key: Vec<u8> = row.get(0)?;
        let channel: Vec<u8> = row.get(1)?;
        Ok(NodeShare {
            key: key.try_into().unwrap_or([0; 32]),
            channel: channel.try_into().unwrap_or([0; 32]),
            made: row.get(2)?,
        })
    })
    .map_err(storage)?
    .collect::<Result<_, _>>()
    .map_err(storage)
}

/// What the making anew of `channel` here left out, the channel line it
/// printed, and how many keys that line was cut short of, to fit a list
/// (rule 5). Nothing is done where this device did not make it anew. Write
/// it after `shared_anew::made`, in the same write: `made` writes its row
/// afresh. The row keeps the first of the keys up to the 1,024 rows a table
/// keeps, and a line no longer than a list, as schema step 33 bounds them,
/// so that a making anew never fails on them: a longer line is not kept.
pub fn made_line(
    conn: &Connection,
    channel: &[u8; 32],
    left_out: &[[u8; 32]],
    line: &str,
    cut: u64,
) -> Result<bool, CordeliaError> {
    let left_out: Vec<u8> = left_out[..left_out.len().min(SHARED_KEYS_KEPT)].concat();
    let line = (line.len() <= MEMBERS_FILE_MAX_BYTES).then_some(line);
    let cut = i64::try_from(cut).unwrap_or(i64::MAX);
    let changed = conn
        .execute(
            "UPDATE shared_anew_made SET left_out = ?2, line = ?3, cut = ?4 WHERE channel = ?1",
            params![&channel[..], left_out, line, cut],
        )
        .map_err(storage)?;
    Ok(changed == 1)
}

/// A channel this device made anew, with the keys it left out and the line
/// it printed, where it kept them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MadeLine {
    pub channel: [u8; 32],
    pub new_channel: [u8; 32],
    pub left_out: Vec<[u8; 32]>,
    pub line: Option<String>,
    /// How many keys the line was cut short of, to fit a list.
    pub cut: u64,
}

/// Every channel this device made anew, with what it left out and printed.
pub fn made_lines(conn: &Connection) -> Result<Vec<MadeLine>, CordeliaError> {
    conn.prepare(
        "SELECT channel, new_channel, left_out, line, cut FROM shared_anew_made
             ORDER BY made_at, channel",
    )
    .map_err(storage)?
    .query_map([], |row| {
        let channel: Vec<u8> = row.get(0)?;
        let new_channel: Vec<u8> = row.get(1)?;
        let left_out: Option<Vec<u8>> = row.get(2)?;
        Ok(MadeLine {
            channel: channel.try_into().unwrap_or([0; 32]),
            new_channel: new_channel.try_into().unwrap_or([0; 32]),
            left_out: left_out.unwrap_or_default().as_chunks::<32>().0.to_vec(),
            line: row.get(3)?,
            cut: row.get::<_, i64>(4)?.max(0) as u64,
        })
    })
    .map_err(storage)?
    .collect::<Result<_, _>>()
    .map_err(storage)
}

#[cfg(test)]
mod tests;
