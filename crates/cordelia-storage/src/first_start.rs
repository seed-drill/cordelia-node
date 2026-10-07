//! What a personal node does to its own database at its first start on a
//! version that carries no channel of the older kind (decision 2026-10-04
//! §10, §10.1).
//!
//! A device takes such a version alone. It keeps its key, its memory
//! folders, its settings and its mappings; its folders forget what they
//! had agreed, and it reads none of the older channels, keys or rows
//! again.
//!
//! **A copy first** ([`copy`]): the database, as its opening left it, and
//! the key files of the older channels, into a folder beside them named
//! `before-<version>`. Nothing of the node's own is changed by it.
//!
//! 1. **A copy first** ([`copy`]): the database, as its opening left it,
//!    and the key files of the older channels, into a folder beside them
//!    named `before-<version>`. Where the copy cannot be made the step is
//!    not taken.
//! 2. **Then one step, in one transaction** ([`step`]): every folder
//!    forgets what it had agreed; every table and key of the older kind
//!    is emptied ([`OLDER_TABLES`], [`AGREED_TABLES`], [`OLDER_KEYS`]); a
//!    device whose stored scope was on is left a notice of what stopped
//!    ([`Notice`]); the stored report is removed and the scope is written
//!    off; a guard is set against a version that does not know of the
//!    step ([`GUARD`]); and the mark is written ([`Mark`]).
//!
//! Nothing here reads or writes a memory folder, the device's key file,
//! its token or its configuration; local history, which is in files of
//! its own, is not touched either.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, params};

use crate::schema;

// ── The key files of the older channels ──────────────────────────────

/// The folder, beside the database, of the key files of the older
/// channels.
const KEYS_FOLDER: &str = "channel-keys";

/// How the name of a key file of an older channel ends: its key, the ring
/// of its earlier keys, and its slot key (see [`crate::psk`]).
const KEY_FILE_ENDINGS: [&str; 3] = [".key", ".ring.json", ".slot"];

/// The key files of the older channels, found by their place and their
/// names: each file in the folder of channel keys whose name ends as a
/// key file's does, in order. A link is not one, and nothing is followed.
/// None where there is no such folder.
pub fn older_key_files(data_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(data_dir.join(KEYS_FOLDER)) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry?;
        let named_as_one = entry
            .file_name()
            .to_str()
            .is_some_and(|name| KEY_FILE_ENDINGS.iter().any(|ending| name.ends_with(ending)));
        if named_as_one && entry.file_type()?.is_file() {
            found.push(entry.path());
        }
    }
    found.sort();
    Ok(found)
}

// ── The copy ─────────────────────────────────────────────────────────

/// The name of the database's file, in the node's folder and in a copy.
const DATABASE: &str = "cordelia.db";

/// How the name of a copy ends while it is being made.
const PARTIAL: &str = ".partial";

/// How the name of the copy from before ends, where a start found a whole
/// copy and no mark.
const EARLIER: &str = ".earlier";

/// The name of the folder that the copy is made in, beside the database:
/// `before-<version>`. A character of the version that a file's name
/// might not hold is written as a dash.
pub fn copy_name(version: &str) -> String {
    let plain: String = version
        .chars()
        .map(|c| match c {
            c if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_') => c,
            _ => '-',
        })
        .collect();
    format!("before-{plain}")
}

/// Why a copy could not be made, and the room that one needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotCopied {
    /// What failed, in words.
    pub why: String,
    /// The bytes that the copy takes: the database as the store counts
    /// its pages, and the key files of the older channels.
    pub room_needed: u64,
}

/// The bytes that a copy takes.
fn room_needed(conn: &Connection, data_dir: &Path) -> u64 {
    let pragma = |name: &str| -> u64 {
        conn.pragma_query_value(None, name, |row| row.get::<_, i64>(0))
            .map(|n| n.max(0) as u64)
            .unwrap_or(0)
    };
    let key_files: u64 = older_key_files(data_dir)
        .unwrap_or_default()
        .iter()
        .filter_map(|file| std::fs::metadata(file).ok())
        .map(|file| file.len())
        .sum();
    pragma("page_count") * pragma("page_size") + key_files
}

/// Make a folder that only its owner can read or enter.
fn make_private_folder(folder: &Path) -> std::io::Result<()> {
    std::fs::create_dir(folder)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Let only its owner read or write a file, and flush it to the disk.
fn private_and_flushed(file: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))?;
    }
    crate::atomic::flush(&std::fs::File::open(file)?)
}

/// Flush the names in a folder to the disk, as far as the volume can.
fn flush_names(folder: &Path) {
    if let Err(error) = std::fs::File::open(folder).and_then(|folder| folder.sync_all()) {
        tracing::debug!(folder = %folder.display(), %error, "could not flush a folder's names");
    }
}

/// Remove whatever is at `path`: a folder with all that is in it, or a
/// file. Nothing there is no failure.
fn remove_whatever(path: &Path) -> std::io::Result<()> {
    let removed = match std::fs::symlink_metadata(path) {
        Ok(found) if found.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(e) => Err(e),
    };
    match removed {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        done => done,
    }
}

/// Open a copy's database again and check it (decision 2026-10-04 §10.1):
/// it opens, it is whole by the store's own check, and it is at this
/// schema's version. It is opened for reading only, and nothing is
/// written beside it.
fn checked(database: &Path) -> Result<(), String> {
    let copy = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("the copy does not open: {e}"))?;
    let whole: String = copy
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|e| format!("the copy could not be checked: {e}"))?;
    if whole != "ok" {
        return Err(format!("the copy is not whole: {whole}"));
    }
    let version: u32 = copy
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| format!("the copy's version could not be read: {e}"))?;
    if version != schema::SCHEMA_VERSION {
        return Err(format!(
            "the copy is at schema version {version}, and not at {}",
            schema::SCHEMA_VERSION
        ));
    }
    Ok(())
}

/// [`copy`], saying only why it failed.
fn make_copy(conn: &Connection, data_dir: &Path, version: &str) -> Result<PathBuf, String> {
    let name = copy_name(version);
    let whole = data_dir.join(&name);
    let partial = data_dir.join(format!("{name}{PARTIAL}"));
    let earlier = data_dir.join(format!("{name}{EARLIER}"));
    let at = |what: &str, path: &Path, e: &dyn std::fmt::Display| {
        format!("{what} {}: {e}", path.display())
    };

    // A copy that a start left unfinished is removed, and made again.
    remove_whatever(&partial).map_err(|e| at("could not remove", &partial, &e))?;
    make_private_folder(&partial).map_err(|e| at("could not make", &partial, &e))?;

    // The database, by the store's own statement for a consistent copy
    // into a new file: never by copying a file that is open.
    let database = partial.join(DATABASE);
    let Some(path) = database.to_str() else {
        return Err(format!("{} is no text", database.display()));
    };
    conn.execute("VACUUM INTO ?1", params![path])
        .map_err(|e| at("could not copy the database to", &database, &e))?;
    private_and_flushed(&database).map_err(|e| at("could not flush", &database, &e))?;

    // The key files of the older channels, with it.
    let keys = older_key_files(data_dir).map_err(|e| at("could not list", data_dir, &e))?;
    if !keys.is_empty() {
        let folder = partial.join(KEYS_FOLDER);
        make_private_folder(&folder).map_err(|e| at("could not make", &folder, &e))?;
        for key in &keys {
            let Some(name) = key.file_name() else {
                continue;
            };
            let to = folder.join(name);
            std::fs::copy(key, &to).map_err(|e| at("could not copy", key, &e))?;
            private_and_flushed(&to).map_err(|e| at("could not flush", &to, &e))?;
        }
        flush_names(&folder);
    }
    flush_names(&partial);

    // Opened again and checked, and only then given its name.
    checked(&database)?;
    // A whole copy that a start finds, with no mark in the database, is
    // from a start that did not finish or from a going back: it is kept
    // as the earlier one, in the place of any before it. So there are at
    // most two.
    if std::fs::symlink_metadata(&whole).is_ok() {
        remove_whatever(&earlier).map_err(|e| at("could not remove", &earlier, &e))?;
        std::fs::rename(&whole, &earlier).map_err(|e| at("could not keep", &whole, &e))?;
    }
    std::fs::rename(&partial, &whole).map_err(|e| at("could not name", &whole, &e))?;
    flush_names(data_dir);
    Ok(whole)
}

/// Copy the database, as its opening left it, and the key files of the
/// older channels, into the folder `before-<version>` beside them
/// (decision 2026-10-04 §10.1). Returns the folder.
///
/// - The folder can be read and entered only by its owner (mode 0700),
///   and each file in it read and written only by its owner (0600).
/// - The database is copied by the store's own statement for a consistent
///   copy into a new file (`VACUUM INTO`).
/// - The copy is made under a name that ends `.partial`, flushed, opened
///   again and checked (it opens, it is whole, it is at this schema's
///   version), and only then renamed.
/// - A `.partial` that is found is removed and made again. A whole folder
///   that is found is kept as `before-<version>.earlier`, in the place of
///   any before it, once the new copy is checked.
///
/// The connection is in no transaction. Where the copy cannot be made
/// (no room, no leave to write) nothing of the node's own is changed, and
/// the answer says why, with the room that a copy needs.
pub fn copy(conn: &Connection, data_dir: &Path, version: &str) -> Result<PathBuf, NotCopied> {
    let room_needed = room_needed(conn, data_dir);
    make_copy(conn, data_dir, version).map_err(|why| NotCopied { why, room_needed })
}

// ── A node of the released version, for tests ────────────────────────

/// A database and its key files as the released version (0.2.0-alpha.8)
/// leaves them, for the tests of the first start: those of this module,
/// and those that start a node on one.
pub mod released {
    use std::path::Path;

    use rusqlite::Connection;

    use cordelia_core::CordeliaError;

    use crate::{StorageError, meta, schema};

    /// The last cycle's report in the released version's own bytes.
    ///
    /// Where they come from, at the tag `v0.2.0-alpha.8`: the sync loop
    /// in `crates/cordelia-node/src/main.rs` stores
    /// `serde_json::to_value(&report)` with the time added under `at`,
    /// written by `to_string`; the report is `CycleReport` in
    /// `crates/cordelia-sync/src/claude.rs`, with a `FolderReport` for
    /// each folder and a `Found` for each folder that does not sync. So
    /// the keys of each object are in the order of their bytes, nothing
    /// is between them, a time is as `to_rfc3339` writes it, and a
    /// folder's `failed`, `failed_more` and `stopped` are left out where
    /// they are empty, zero and false.
    ///
    /// It shows three folders that synced: one that is mapped, and two
    /// that synced because everything found did, of which the second is
    /// home memory, still waiting for its channel.
    pub const REPORT: &str = concat!(
        r#"{"at":"2026-10-05T09:12:44.512203817+00:00","#,
        r#""available":["github.com/sam/site"],"errors":[],"#,
        r#""excluded":["github.com/sam/private"],"folders":["#,
        r#"{"channel_id":"grp_lab","conflict_files":[],"conflicts":0,"#,
        r#""cwd":"/home/sam/work/lab","error":null,"#,
        r#""folder":"/home/sam/.claude/projects/-home-sam-work-lab","#,
        r#""last_published_at":"2026-10-05T09:12:40.118734522+00:00","#,
        r#""last_pulled_at":null,"mapped":true,"project":"github.com/sam/lab","#,
        r#""published":1,"pulled":0,"skipped":[],"too_large":[],"waiting":false},"#,
        r#"{"channel_id":"grp_tools","conflict_files":[],"conflicts":0,"#,
        r#""cwd":"/home/sam/work/tools","error":null,"#,
        r#""folder":"/home/sam/.claude/projects/-home-sam-work-tools","#,
        r#""last_published_at":null,"last_pulled_at":null,"mapped":false,"#,
        r#""project":"github.com/sam/tools","published":0,"pulled":0,"#,
        r#""skipped":[],"too_large":[],"waiting":false},"#,
        r#"{"channel_id":null,"conflict_files":[],"conflicts":0,"#,
        r#""cwd":"/home/sam","error":null,"#,
        r#""folder":"/home/sam/.claude/projects/-home-sam","#,
        r#""last_published_at":null,"last_pulled_at":null,"mapped":false,"#,
        r#""project":"~","published":0,"pulled":0,"#,
        r#""skipped":[],"too_large":[],"waiting":true}],"#,
        r#""generation":4,"#,
        r#""unmapped":[{"cwd":"/home/sam/scratch","#,
        r#""folder":"/home/sam/.claude/projects/-home-sam-scratch","name":null}],"#,
        r#""unsynced":["/home/sam/.claude/projects/-home-sam-scratch"]}"#,
    );

    /// The key under which the released version notes the device whose
    /// offer of its personal channel it has decided to take, and when.
    const ACCEPTED_PERSONAL_FROM: &str = "membership.accepted_personal_from";

    /// The key files that [`fill`] writes, by their names in the folder
    /// of channel keys: a key, a ring of earlier keys and a slot key for
    /// one channel, and a key and a slot key for another.
    pub const KEY_FILES: [&str; 5] = [
        "grp_lab.key",
        "grp_lab.slot",
        "grp_personal.key",
        "grp_personal.ring.json",
        "grp_personal.slot",
    ];

    /// Make the database at `path` by the schema's own steps up to the
    /// released version's, and none after
    /// ([`schema::init_db_as_released`]).
    pub fn database(path: &Path) -> Result<Connection, StorageError> {
        let conn = Connection::open(path)?;
        schema::init_db_as_released(&conn)?;
        Ok(conn)
    }

    /// Fill a database of the released version's form with rows of every
    /// table that version has, and write the key files of its channels
    /// beside it, in `data_dir`:
    ///
    /// - channels of each type (the personal channel and a project's,
    ///   which are groups; an inbox; a direct channel; a named channel,
    ///   and one that is local), with their members and keys;
    /// - items held of them: one that a relay took, and two that wait to
    ///   be sent, of which one was written through the local API, with
    ///   its text in the search index;
    /// - a device that is trusted, with its label; an invitation; a
    ///   channel's state that was offered to a member;
    /// - what a folder had agreed, and a record kept for an index line;
    /// - what the node noted for itself: its personal channel, whom it
    ///   accepted, when it last synced, and the last cycle's report
    ///   ([`REPORT`]);
    /// - what stays: the counter of arrival order, a peer that was seen,
    ///   and the settings: sync on for a Claude Code directory, with the
    ///   scope off, one mapping, an exclusion, and home memory off.
    pub fn fill(conn: &Connection, data_dir: &Path) -> Result<(), CordeliaError> {
        let storage = |e: rusqlite::Error| CordeliaError::Storage(e.to_string());
        conn.execute_batch(ROWS).map_err(storage)?;
        for (key, value) in [
            (meta::PERSONAL_CHANNEL_ID, "grp_personal"),
            (
                ACCEPTED_PERSONAL_FROM,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 1790000000",
            ),
            (
                meta::SYNC_CLAUDE_LAST_CHANGE,
                "2026-10-05T09:12:40.118734522+00:00",
            ),
            (
                meta::SYNC_CLAUDE_ACTIVITY,
                r#"{"github.com/sam/lab":{"published":"2026-10-05T09:12:40.118734522+00:00"}}"#,
            ),
            (meta::SYNC_CLAUDE_REPORT, REPORT),
            (meta::SYNC_CLAUDE_DIR, "/home/sam/.claude"),
            (meta::SYNC_CLAUDE_ALL, "off"),
            (
                meta::SYNC_CLAUDE_MAPPINGS,
                r#"[{"folder":"/home/sam/work/lab","name":"github.com/sam/lab"}]"#,
            ),
            (meta::SYNC_CLAUDE_EXCLUDE, r#"["github.com/sam/private"]"#),
            (meta::SYNC_CLAUDE_HOME, "off"),
            (meta::SYNC_CLAUDE_HOME_NAME, "~"),
            (
                meta::USAGE_SIGHTING_SECRET,
                "0707070707070707070707070707070707070707070707070707070707070707",
            ),
        ] {
            meta::set(conn, key, value)?;
        }
        let io = |e: std::io::Error| CordeliaError::Storage(e.to_string());
        let keys = data_dir.join(super::KEYS_FOLDER);
        std::fs::create_dir_all(&keys).map_err(io)?;
        for (n, name) in KEY_FILES.iter().enumerate() {
            let held: Vec<u8> = match name.ends_with(".json") {
                true => br#"{"channel_id":"grp_personal","current_version":2,"keys":[]}"#.to_vec(),
                false => vec![n as u8 + 1; 32],
            };
            std::fs::write(keys.join(name), held).map_err(io)?;
        }
        Ok(())
    }

    /// The rows that [`fill`] writes.
    const ROWS: &str = "
        INSERT INTO channels (channel_id, channel_name, channel_type, mode, access, creator_id,
                              created_at, updated_at, scope, epoch)
        VALUES ('grp_personal', NULL, 'group', 'realtime', 'invite_only', zeroblob(32),
                '2026-09-30T10:00:00Z', '2026-09-30T10:00:00Z', 'network', 3),
               ('grp_lab', NULL, 'group', 'realtime', 'invite_only', zeroblob(32),
                '2026-09-30T10:00:00Z', '2026-09-30T10:00:00Z', 'network', 1),
               ('inbox_a', NULL, 'inbox', 'realtime', 'open', zeroblob(32),
                '2026-09-30T10:00:00Z', '2026-09-30T10:00:00Z', 'network', 0),
               ('dm_a_b', NULL, 'dm', 'realtime', 'invite_only', zeroblob(32),
                '2026-09-30T10:00:00Z', '2026-09-30T10:00:00Z', 'network', 0),
               ('notes', 'notes', 'named', 'realtime', 'open', zeroblob(32),
                '2026-09-30T10:00:00Z', '2026-09-30T10:00:00Z', 'network', 0),
               ('local_scratch', 'scratch', 'named', 'batch', 'open', zeroblob(32),
                '2026-09-30T10:00:00Z', '2026-09-30T10:00:00Z', 'local', 0);
        INSERT INTO channel_members (channel_id, entity_key, role, joined_at)
        VALUES ('grp_personal', zeroblob(32), 'owner', '2026-09-30T10:00:00Z'),
               ('grp_personal', X'BB', 'member', '2026-09-30T10:05:00Z'),
               ('grp_lab', zeroblob(32), 'owner', '2026-09-30T10:00:00Z'),
               ('dm_a_b', zeroblob(32), 'member', '2026-09-30T10:00:00Z'),
               ('notes', zeroblob(32), 'owner', '2026-09-30T10:00:00Z');
        INSERT INTO channel_keys (channel_id, encrypted_psk, key_version)
        VALUES ('grp_personal', X'0102', 2), ('grp_lab', X'0304', 1);
        INSERT INTO dm_peers (channel_id, peer_key) VALUES ('dm_a_b', X'BB');
        INSERT INTO items (item_id, channel_id, author_id, item_type, published_at,
                           content_hash, signature, encrypted_blob, content_length,
                           seq, slot, rev, relayed_at)
        VALUES ('ci_sent', 'grp_lab', zeroblob(32), 'memory', '2026-10-05T09:00:00Z',
                X'01', X'02', X'0303', 2, 40, X'0505', 3, '2026-10-05T09:00:02Z'),
               ('ci_waiting', 'grp_lab', zeroblob(32), 'memory', '2026-10-05T09:12:40Z',
                X'04', X'05', X'060606', 3, 41, X'0505', 4, NULL),
               ('ci_by_the_api', 'notes', zeroblob(32), 'note', '2026-10-05T09:12:41Z',
                X'07', X'08', X'09', 1, 42, NULL, NULL, NULL);
        UPDATE counters SET value = 42 WHERE name = 'item_seq';
        INSERT INTO search_content (item_id, channel_id, item_type, published_at, name,
                                    content_text)
        VALUES ('ci_by_the_api', 'notes', 'note', '2026-10-05T09:12:41Z', 'plan',
                'the plan for tuesday');
        INSERT INTO trusted_keys (entity_key, kind, label, added_at)
        VALUES (X'BB', 'device', 'laptop', '2026-09-30T10:05:00Z');
        INSERT INTO invites (item_id, inviter, channel_id, status, received_at, decided_at)
        VALUES ('ci_invite', X'BB', 'grp_lab', 'accepted', '2026-09-30T10:06:00Z',
                '2026-09-30T10:06:01Z');
        INSERT INTO state_offers (channel_id, member, epoch, item_id, sent_at, last_offered_at)
        VALUES ('grp_lab', X'BB', 1, 'ci_state', 1790000000, 1790000060);
        INSERT INTO sync_files (folder, channel_id, key, hash, rev, author)
        VALUES ('/home/sam/.claude/projects/-home-sam-work-lab/memory', 'grp_lab', 'notes.md',
                X'0A', 4, zeroblob(32));
        INSERT INTO index_lines (folder, channel_id, file, line, line_at, deleted_at, whole)
        VALUES ('/home/sam/.claude/projects/-home-sam-work-lab/memory', 'grp_lab', 'gone.md',
                '- [Gone](gone.md)', 1790000000, 1790000050, 1);
        INSERT INTO peer_sightings (peer_hash, is_relay, first_seen, last_seen)
        VALUES (zeroblob(32), 1, 1790000000, 1790000500);";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    /// The version that makes the copy, and the step, in these tests.
    const VERSION: &str = "0.2.0-test";

    /// A node's folder with a database and key files in the released
    /// version's form ([`released`]), and beside them what a node keeps
    /// there that is no part of this: the device's key, its token, and a
    /// record of local history. `before` is done to the database while it
    /// is in that form. The database is then opened as this version opens
    /// any: the schema's steps have run.
    fn released_node(before: impl FnOnce(&Connection)) -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DATABASE);
        {
            let conn = released::database(&path).unwrap();
            released::fill(&conn, dir.path()).unwrap();
            before(&conn);
        }
        std::fs::write(dir.path().join("identity.key"), [9u8; 32]).unwrap();
        std::fs::write(dir.path().join("node-token"), "a token").unwrap();
        std::fs::create_dir(dir.path().join("history")).unwrap();
        std::fs::write(dir.path().join("history").join("a-record"), "kept").unwrap();
        let conn = db::open(&path).unwrap();
        (dir, conn)
    }

    fn rows(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    /// Everything a database holds, as far as these tests tell it apart:
    /// how many rows each of its tables has, each thing that the node
    /// notes for itself, each counter, and each trigger.
    fn everything(conn: &Connection) -> Vec<String> {
        let listed = |sql: &str| -> Vec<String> {
            conn.prepare(sql)
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        let tables = listed(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        );
        let mut held: Vec<String> = tables
            .iter()
            .map(|table| format!("{table}: {}", rows(conn, table)))
            .collect();
        held.extend(listed(
            "SELECT 'noted ' || key || '=' || value FROM node_meta ORDER BY key",
        ));
        held.extend(listed(
            "SELECT 'counter ' || name || '=' || value FROM counters ORDER BY name",
        ));
        held.extend(listed(
            "SELECT 'trigger ' || name FROM sqlite_master WHERE type = 'trigger' ORDER BY name",
        ));
        held
    }

    /// How many items of the search index hold `word`.
    fn found_in_search(conn: &Connection, word: &str) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM search_fts WHERE search_fts MATCH ?1",
            params![word],
            |row| row.get(0),
        )
        .unwrap()
    }

    /// The names in a folder, in order.
    fn names_in(folder: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(folder)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// The names in a node's folder that are of a copy.
    fn copies_in(folder: &Path) -> Vec<String> {
        let mut names = names_in(folder);
        names.retain(|name| name.starts_with("before-"));
        names
    }

    /// What a node keeps in its folder that is no part of this: the
    /// device's key, its token and its local history.
    fn its_own_files(data: &Path) -> (Vec<u8>, String, Vec<String>) {
        (
            std::fs::read(data.join("identity.key")).unwrap(),
            std::fs::read_to_string(data.join("node-token")).unwrap(),
            names_in(&data.join("history")),
        )
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// The bytes of each key file of the older channels, by its name.
    fn key_files_held(data: &Path) -> Vec<(String, Vec<u8>)> {
        older_key_files(data)
            .unwrap()
            .iter()
            .map(|file| {
                let name = file.file_name().unwrap().to_string_lossy().into_owned();
                (name, std::fs::read(file).unwrap())
            })
            .collect()
    }

    /// What is left of a copy that cannot be removed: a folder in it that
    /// cannot be looked into. Returns that folder.
    #[cfg(unix)]
    fn a_partial_copy_that_cannot_be_removed(data: &Path) -> PathBuf {
        let closed = data.join("before-0.2.0-test.partial").join("closed");
        std::fs::create_dir_all(&closed).unwrap();
        std::fs::write(closed.join("a-file"), "x").unwrap();
        set_mode(&closed, 0o000);
        closed
    }

    // ── The copy ─────────────────────────────────────────────────────

    /// The copy of a database in the released version's form, with
    /// folders that had agreed files, older channels of each type, a
    /// queue of things to send and a device trusted (decision 2026-10-04
    /// §10.1): it is in the folder `before-<version>` beside the
    /// database, at this schema's version, whole by the store's own
    /// check, with every row and each key file, and only its owner can
    /// read it. Nothing of the node's own is changed by it.
    #[test]
    fn a_copy_holds_every_row_and_each_key_file_and_only_its_owner_reads_it() {
        let (dir, conn) = released_node(|_| {});
        let data = dir.path();
        let (before, own_files) = (everything(&conn), its_own_files(data));
        let key_files = key_files_held(data);
        let names: Vec<&str> = key_files.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, released::KEY_FILES);

        let copy = copy(&conn, data, VERSION).unwrap();
        assert_eq!(copy, data.join("before-0.2.0-test"));
        assert_eq!(copies_in(data), ["before-0.2.0-test"]);
        // The database and the key files, and nothing else.
        assert_eq!(names_in(&copy), ["channel-keys", "cordelia.db"]);
        assert_eq!(names_in(&copy.join("channel-keys")), released::KEY_FILES);
        #[cfg(unix)]
        {
            assert_eq!(mode(&copy), 0o700);
            assert_eq!(mode(&copy.join("channel-keys")), 0o700);
            assert_eq!(mode(&copy.join("cordelia.db")), 0o600);
        }
        for (name, bytes) in &key_files {
            let file = copy.join("channel-keys").join(name);
            assert_eq!(&std::fs::read(&file).unwrap(), bytes, "{name}");
            #[cfg(unix)]
            assert_eq!(mode(&file), 0o600, "{name}");
        }
        // At this schema's version, whole by the store's own check, and
        // with every row: the text that was in the search index too.
        let database = copy.join("cordelia.db");
        assert_eq!(checked(&database), Ok(()));
        let copied =
            Connection::open_with_flags(&database, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let version: u32 = copied
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, schema::SCHEMA_VERSION);
        let whole: String = copied
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(whole, "ok");
        assert_eq!(everything(&copied), before);
        assert_eq!(found_in_search(&copied, "tuesday"), 1);
        drop(copied);
        assert_eq!(names_in(&copy), ["channel-keys", "cordelia.db"]);

        // The node's own is as it was.
        assert_eq!(everything(&conn), before);
        assert_eq!(key_files_held(data), key_files);
        assert_eq!(its_own_files(data), own_files);
    }

    /// A copy is given its name only once it has been opened again and
    /// checked: it opens, it is whole, and it is at this schema's version
    /// (decision 2026-10-04 §10.1).
    #[test]
    fn a_copy_is_checked_before_it_is_named() {
        let dir = tempfile::tempdir().unwrap();
        let at = |name: &str| dir.path().join(name);
        // No database at all.
        std::fs::write(at("no.db"), "not a database, though it has a name like one").unwrap();
        let refused = checked(&at("no.db")).unwrap_err();
        assert!(refused.contains("could not be checked"), "{refused}");
        assert!(
            checked(&at("not-there.db"))
                .unwrap_err()
                .contains("does not open")
        );
        // A database at another version than this schema's.
        drop(released::database(&at("as-released.db")).unwrap());
        let refused = checked(&at("as-released.db")).unwrap_err();
        assert!(refused.contains("is at schema version 10"), "{refused}");
        // One that is not whole: its pages are cut short.
        drop(db::open(&at("cut.db")).unwrap());
        let whole = std::fs::read(at("cut.db")).unwrap();
        std::fs::write(at("cut.db"), &whole[..whole.len() / 2]).unwrap();
        let _ = std::fs::remove_file(at("cut.db-wal"));
        let _ = std::fs::remove_file(at("cut.db-shm"));
        assert!(checked(&at("cut.db")).is_err());
        // And one that is all three.
        drop(db::open(&at("whole.db")).unwrap());
        let conn = db::open(&at("whole.db")).unwrap();
        conn.execute("VACUUM INTO ?1", params![at("copy.db").to_str().unwrap()])
            .unwrap();
        assert_eq!(checked(&at("copy.db")), Ok(()));
    }

    /// A `.partial` that a start finds is removed and made again: what
    /// was in it is no part of the copy (decision 2026-10-04 §10.1).
    #[test]
    fn a_partial_copy_left_by_a_start_that_died_is_made_again() {
        let (dir, conn) = released_node(|_| {});
        let data = dir.path();
        let partial = data.join("before-0.2.0-test.partial");
        std::fs::create_dir(&partial).unwrap();
        std::fs::write(partial.join("cordelia.db"), "half a database").unwrap();
        std::fs::write(partial.join("left-over"), "x").unwrap();

        let copy = copy(&conn, data, VERSION).unwrap();
        assert_eq!(copies_in(data), ["before-0.2.0-test"]);
        assert_eq!(names_in(&copy), ["channel-keys", "cordelia.db"]);
        assert_eq!(checked(&copy.join("cordelia.db")), Ok(()));
    }

    /// A whole folder that a start finds is from a start that did not
    /// finish, or from a going back: it is kept as the earlier one, in
    /// the place of any before it, and a new copy is made. So there are
    /// at most two (decision 2026-10-04 §10.1).
    #[test]
    fn a_whole_copy_that_is_found_is_kept_as_the_earlier_one() {
        let (dir, conn) = released_node(|_| {});
        let data = dir.path();
        let (whole, earlier) = (
            data.join("before-0.2.0-test"),
            data.join("before-0.2.0-test.earlier"),
        );
        for (folder, holds) in [(&whole, "from-the-start-before"), (&earlier, "older-still")] {
            std::fs::create_dir(folder).unwrap();
            std::fs::write(folder.join(holds), "x").unwrap();
        }
        let both = ["before-0.2.0-test", "before-0.2.0-test.earlier"];

        copy(&conn, data, VERSION).unwrap();
        assert_eq!(copies_in(data), both);
        assert_eq!(names_in(&earlier), ["from-the-start-before"]);
        assert_eq!(names_in(&whole), ["channel-keys", "cordelia.db"]);
        // And again: the one just made is now the earlier one.
        copy(&conn, data, VERSION).unwrap();
        assert_eq!(copies_in(data), both);
        assert_eq!(names_in(&earlier), ["channel-keys", "cordelia.db"]);
        assert_eq!(names_in(&whole), ["channel-keys", "cordelia.db"]);
    }

    /// Where the copy cannot be made, the answer says why, with the room
    /// that a copy needs, and nothing of the node's own is changed: no
    /// row, and no key file (decision 2026-10-04 §10.1). A whole copy
    /// from before is left where it is.
    #[cfg(unix)]
    #[test]
    fn a_copy_that_cannot_be_made_says_why_and_changes_nothing() {
        let (dir, conn) = released_node(|_| {});
        let data = dir.path();
        let (before, key_files) = (everything(&conn), key_files_held(data));
        let whole = data.join("before-0.2.0-test");
        std::fs::create_dir(&whole).unwrap();
        std::fs::write(whole.join("from-the-start-before"), "x").unwrap();
        let closed = a_partial_copy_that_cannot_be_removed(data);

        let not_copied = copy(&conn, data, VERSION).unwrap_err();
        assert!(
            not_copied.why.contains("could not remove"),
            "{not_copied:?}"
        );
        assert!(
            not_copied.why.contains("before-0.2.0-test.partial"),
            "{not_copied:?}"
        );
        // The room: the database as the store counts its pages, and the
        // key files.
        let pages: u64 = conn
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .unwrap();
        let page: u64 = conn
            .pragma_query_value(None, "page_size", |row| row.get(0))
            .unwrap();
        let keys: u64 = key_files.iter().map(|(_, bytes)| bytes.len() as u64).sum();
        assert!(pages > 1 && keys > 0);
        assert_eq!(not_copied.room_needed, pages * page + keys);
        assert_eq!(everything(&conn), before);
        assert_eq!(key_files_held(data), key_files);
        assert_eq!(names_in(&whole), ["from-the-start-before"]);

        set_mode(&closed, 0o700);
        copy(&conn, data, VERSION).unwrap();
        assert_eq!(
            copies_in(data),
            ["before-0.2.0-test", "before-0.2.0-test.earlier"]
        );
    }

    /// The copy is for the version before, which opens it as it opens
    /// any database: it knows nothing of the tables added since, and
    /// changes none of what the copy holds (decision 2026-10-04 §10.1).
    #[test]
    fn the_copy_opens_as_the_released_version_opens_a_database() {
        let (dir, conn) = released_node(|_| {});
        let before = everything(&conn);
        let copy = copy(&conn, dir.path(), VERSION).unwrap();
        let copied = Connection::open(copy.join("cordelia.db")).unwrap();
        schema::init_db_as_released(&copied).unwrap();
        assert_eq!(everything(&copied), before);
        let version: u32 = copied
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, schema::SCHEMA_VERSION);
    }

    /// The name of a copy's folder holds the version, and nothing that a
    /// file's name could not.
    #[test]
    fn a_copy_is_named_for_the_version() {
        assert_eq!(copy_name("0.2.0-alpha.9"), "before-0.2.0-alpha.9");
        assert_eq!(copy_name("1.0.0+build_7"), "before-1.0.0+build_7");
        assert_eq!(copy_name("../a b"), "before-..-a-b");
    }

    /// The key files of the older channels are found by their place and
    /// their names, and nothing else is: not the device's key, which is
    /// beside the folder; not a file of another name in it; not a folder;
    /// not a link.
    #[test]
    fn only_the_key_files_of_the_older_channels_are_found() {
        let (dir, _conn) = released_node(|_| {});
        let data = dir.path();
        let keys = data.join("channel-keys");
        std::fs::write(keys.join("notes.txt"), "not a key").unwrap();
        std::fs::write(keys.join("key"), "not one either").unwrap();
        std::fs::create_dir(keys.join("a-folder.key")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(data.join("identity.key"), keys.join("linked.key")).unwrap();
        let found: Vec<String> = key_files_held(data)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(found, released::KEY_FILES);
        // No folder of channel keys is no key file.
        let none = tempfile::tempdir().unwrap();
        assert!(older_key_files(none.path()).unwrap().is_empty());
    }
}
