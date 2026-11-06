//! What a device keeps of the repositories it follows (decision 2026-11-06
//! (joining), rules 2 to 6): the tables of schema step 33.
//!
//! - **The follows** (`shared_follows`): each repository this device
//!   follows, by its identity (`host/owner/name`), with the clone's remote
//!   and path, the last commit read with when and from where, the bytes of
//!   the last list read, and the node's turn among the keys it hands over
//!   to (rule 4.2). Following again starts the row afresh (rule 2.5).
//! - **The node's typings** (`shared_follow_typed`): the listed keys the node
//!   looks for shares from (rule 4.4), apart from the person's own typings
//!   (`shared_typed_keys`), with what became of each.
//! - **The notices** (`shared_follow_notices`): a key that joined from the
//!   list, and a changed channel line, each with its commit, until a person
//!   clears them with `cordelia shared seen` (rules 4.5 and 6).
//! - **The node's shares** (`shared_shares.by_node`), and **what a making
//!   anew left out and the line it printed** (`shared_anew_made.left_out`
//!   and `line`, rule 5).
//!
//! Nothing here reads a list or decides anything: that is done where these
//! are read. Every time here is the node's.

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
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
    /// The bytes of the last list read.
    pub list: Option<Vec<u8>>,
    /// Where the node's next hand-over starts, among the keys it hands to.
    pub turn: u64,
}

/// When the last list was read, its commit, and whether it came from the
/// clone (or from the host).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastRead {
    pub commit: String,
    pub at: i64,
    pub from_clone: bool,
}

const FOLLOW_COLUMNS: &str =
    "identity, remote, clone, followed_at, last_commit, last_read_at, read_from, list, turn";

fn follow_of_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Follow> {
    let commit: Option<String> = row.get(4)?;
    let at: Option<i64> = row.get(5)?;
    let from: Option<i64> = row.get(6)?;
    let turn: i64 = row.get(8)?;
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
        list: row.get(7)?,
        turn: turn as u64,
    })
}

/// This device follows `identity`, through `remote` of the clone at
/// `clone`, from `at`. Following a repository again starts afresh: its
/// last read, its list, its turn, the node's typings and the notices go
/// (rule 2.5).
pub fn follow(
    conn: &Connection,
    identity: &str,
    remote: &str,
    clone: &str,
    at: i64,
) -> Result<(), CordeliaError> {
    let tx = conn.unchecked_transaction().map_err(storage)?;
    forget(&tx, identity)?;
    tx.execute(
        "INSERT INTO shared_follows (identity, remote, clone, followed_at)
             VALUES (?1, ?2, ?3, ?4)",
        params![identity, remote, clone, at],
    )
    .map_err(storage)?;
    tx.commit().map_err(storage)
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
    let tx = conn.unchecked_transaction().map_err(storage)?;
    forget(&tx, identity)?;
    tx.commit().map_err(storage)
}

/// This device follows nothing: it left its person (rule 2.5).
pub fn unfollow_all(conn: &Connection) -> Result<(), CordeliaError> {
    conn.execute_batch(
        "DELETE FROM shared_follows; DELETE FROM shared_follow_typed;
         DELETE FROM shared_follow_notices;",
    )
    .map_err(storage)
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

/// A list of `identity` was read: its commit, when, from where, and its
/// bytes. Nothing is done for a repository this device does not follow.
pub fn read_done(
    conn: &Connection,
    identity: &str,
    read: &LastRead,
    list: &[u8],
) -> Result<bool, CordeliaError> {
    let changed = conn
        .execute(
            "UPDATE shared_follows SET last_commit = ?2, last_read_at = ?3, read_from = ?4,
                 list = ?5
             WHERE identity = ?1",
            params![identity, read.commit, read.at, read.from_clone as i64, list],
        )
        .map_err(storage)?;
    Ok(changed == 1)
}

/// Where the node's next hand-over for `identity` starts.
pub fn set_turn(conn: &Connection, identity: &str, turn: u64) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE shared_follows SET turn = ?2 WHERE identity = ?1",
        params![identity, turn as i64],
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

/// What became of the node's typing of `key` for `identity`.
pub fn typed_became(
    conn: &Connection,
    identity: &str,
    key: &[u8; 32],
    became: &str,
    detail: Option<&str>,
) -> Result<(), CordeliaError> {
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
    /// A key that joined the channel from the list (rule 4.5).
    Joined([u8; 32]),
    /// The list's channel line changed (rule 6).
    LineChanged,
}

/// A notice, with the commit it was read at and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub of: NoticeOf,
    pub commit: String,
    pub at: i64,
}

/// A notice for `identity`. One already kept of the same thing stays as
/// it is. Returns whether it is new.
pub fn notice(conn: &Connection, identity: &str, notice: &Notice) -> Result<bool, CordeliaError> {
    let (kind, key): (i64, Vec<u8>) = match &notice.of {
        NoticeOf::Joined(key) => (1, key.to_vec()),
        NoticeOf::LineChanged => (2, Vec::new()),
    };
    let added = conn
        .execute(
            "INSERT OR IGNORE INTO shared_follow_notices (identity, kind, key, at_commit, at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            params![identity, kind, key, notice.commit, notice.at],
        )
        .map_err(storage)?;
    Ok(added == 1)
}

/// The notices of `identity`, oldest first.
pub fn notices(conn: &Connection, identity: &str) -> Result<Vec<Notice>, CordeliaError> {
    conn.prepare(
        "SELECT kind, key, at_commit, at FROM shared_follow_notices
             WHERE identity = ?1 ORDER BY at, kind, key",
    )
    .map_err(storage)?
    .query_map([identity], |row| {
        let kind: i64 = row.get(0)?;
        let key: Vec<u8> = row.get(1)?;
        Ok(Notice {
            of: match kind {
                1 => NoticeOf::Joined(key.try_into().unwrap_or([0; 32])),
                _ => NoticeOf::LineChanged,
            },
            commit: row.get(2)?,
            at: row.get(3)?,
        })
    })
    .map_err(storage)?
    .collect::<Result<_, _>>()
    .map_err(storage)
}

/// A person cleared the notices of `identity` (`cordelia shared seen`).
/// Returns how many went.
pub fn seen(conn: &Connection, identity: &str) -> Result<usize, CordeliaError> {
    conn.execute(
        "DELETE FROM shared_follow_notices WHERE identity = ?1",
        [identity],
    )
    .map_err(storage)
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

/// What the making anew of `channel` here left out, and the channel line
/// it printed (rule 5). Nothing is done where this device did not make it
/// anew.
pub fn made_line(
    conn: &Connection,
    channel: &[u8; 32],
    left_out: &[[u8; 32]],
    line: &str,
) -> Result<bool, CordeliaError> {
    let left_out: Vec<u8> = left_out.concat();
    let changed = conn
        .execute(
            "UPDATE shared_anew_made SET left_out = ?2, line = ?3 WHERE channel = ?1",
            params![&channel[..], left_out, line],
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
}

/// Every channel this device made anew, with what it left out and printed.
pub fn made_lines(conn: &Connection) -> Result<Vec<MadeLine>, CordeliaError> {
    conn.prepare(
        "SELECT channel, new_channel, left_out, line FROM shared_anew_made
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
        })
    })
    .map_err(storage)?
    .collect::<Result<_, _>>()
    .map_err(storage)
}

#[cfg(test)]
mod tests;
