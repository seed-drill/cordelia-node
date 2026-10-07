//! What a personal node does to its own database at its first start on a
//! version that carries no channel of the older kind (decision 2026-10-04
//! §10, §10.1).
//!
//! A device takes such a version alone. It keeps its key, its memory
//! folders, its settings and its mappings; its folders forget what they
//! had agreed, and it reads none of the older channels, keys or rows
//! again.
//! So a personal node that has no mark of the step makes it when it
//! starts ([`first_start`]):
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
//! 3. **After the commit the key files of the older channels are
//!    removed** ([`remove_older_key_files`]): found by their place and
//!    their names, and looked for again at every start, whatever the mark
//!    says.
//!
//! A database that holds nothing of the older kind (a first install), or
//! in which the device already follows a recovery phrase, gets the mark
//! and nothing else. Any mark means done, in this version and in every
//! later one.
//!
//! What stays: the counters, the device's settings and mappings, what the
//! node keeps for its usage counts, and everything that a later step of
//! the schema added.
//!
//! Nothing here reads or writes a memory folder, the device's key file,
//! its token or its configuration; local history, which is in files of
//! its own, is not touched either.
//!
//! A relay and a bootnode make no copy and take no step: their databases
//! are stepped as any version steps them, and they go on carrying the
//! older kind. A relay that is started on a database which a personal
//! node stepped removes the guard ([`remove_guard`]).

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};

use cordelia_core::CordeliaError;

use crate::{meta, schema};

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

// ── What is of the older kind ────────────────────────────────────────

/// The tables of the older kind of channel that a device holds, each of
/// which the step empties (decision 2026-10-04 §10.1): the members of its
/// channels, their keys as the database held them, the peers of its
/// direct channels, the items it held (what waited to be sent among
/// them), the search index of what was published through the local API,
/// the invitations, what it had offered the members of its channels, the
/// trust of other devices' keys with the labels it gave them, and the
/// channels themselves, of every type.
///
/// They are in an order in which a row goes before the row it refers to.
pub const OLDER_TABLES: [&str; 9] = [
    "channel_members",
    "channel_keys",
    "dm_peers",
    "items",
    "search_content",
    "invites",
    "state_offers",
    "trusted_keys",
    "channels",
];

/// What every folder had agreed with its channel, and the records kept
/// for index lines: the step empties both (decision 2026-10-04 §10, step
/// 3). The tables stay, since a folder agrees with a channel from the
/// person's secret in the same ones.
pub const AGREED_TABLES: [&str; 2] = ["sync_files", "index_lines"];

/// The key under which a node of the older kind noted the device whose
/// offer of its personal channel it had decided to take. Nothing in this
/// version writes it.
pub const ACCEPTED_PERSONAL_FROM: &str = "membership.accepted_personal_from";

/// What a node noted of the older kind for itself, each of which the step
/// removes (decision 2026-10-04 §10.1): its personal channel, whom it
/// accepted, and when it last synced (the time of the last change, and
/// the times for each name).
pub const OLDER_KEYS: [&str; 4] = [
    meta::PERSONAL_CHANNEL_ID,
    ACCEPTED_PERSONAL_FROM,
    meta::SYNC_CLAUDE_LAST_CHANGE,
    meta::SYNC_CLAUDE_ACTIVITY,
];

/// The folder, beside the database, of the key files of the older
/// channels.
const KEYS_FOLDER: &str = "channel-keys";

/// How the name of a key file of an older channel ends: its key, the ring
/// of its earlier keys, and its slot key (see [`crate::psk`]).
const KEY_FILE_ENDINGS: [&str; 3] = [".key", ".ring.json", ".slot"];

/// Whatever is in the folder of channel keys under a name that ends as a
/// key file's does, in order, each with whether it is a file: what is
/// found by its place and its name. Nothing is followed. None where there
/// is no such folder.
fn named_as_key_files(data_dir: &Path) -> std::io::Result<Vec<(PathBuf, bool)>> {
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
        if named_as_one {
            found.push((entry.path(), entry.file_type()?.is_file()));
        }
    }
    found.sort();
    Ok(found)
}

/// The key files of the older channels, found by their place and their
/// names: each file in the folder of channel keys whose name ends as a
/// key file's does, in order. They are what a copy holds. A link under
/// such a name is not one, nor a folder: neither is read.
pub fn older_key_files(data_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let named = named_as_key_files(data_dir)?;
    Ok(named
        .into_iter()
        .filter(|(_, is_a_file)| *is_a_file)
        .map(|(path, _)| path)
        .collect())
}

/// Whether the node holds anything of the older kind: a row in one of
/// its tables, one of its keys, or anything under the name of a key file
/// of an older channel.
pub fn holds_older(conn: &Connection, data_dir: &Path) -> Result<bool, CordeliaError> {
    for table in OLDER_TABLES {
        let any: bool = conn
            .query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table})"),
                [],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if any {
            return Ok(true);
        }
    }
    for key in OLDER_KEYS {
        if meta::get(conn, key)?.is_some() {
            return Ok(true);
        }
    }
    let named = named_as_key_files(data_dir)
        .map_err(|e| CordeliaError::Storage(format!("the folder of channel keys: {e}")))?;
    Ok(!named.is_empty())
}

// ── The mark ─────────────────────────────────────────────────────────

/// How the mark begins where the step was made, before the version.
const STEPPED: &str = "stepped by ";

/// How the mark begins where there was nothing to step, before the
/// version.
const NOTHING_TO_STEP: &str = "nothing to step, marked by ";

/// The mark that the first start on this version is done (decision
/// 2026-10-04 §10.1). Any mark means done, in this version and in every
/// later one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    /// Whether the step was made: the node held something of the older
    /// kind, and followed no phrase. Where it was not, the mark was
    /// written and nothing else.
    pub stepped: bool,
    /// The version that wrote the mark.
    pub version: String,
}

/// The mark, where the database has one. A mark that is not in either
/// form is still a mark: it is read as one of a start that had nothing to
/// step, by a version that is what the mark says.
pub fn mark(conn: &Connection) -> Result<Option<Mark>, CordeliaError> {
    Ok(meta::get(conn, meta::FIRST_START)?.map(|value| {
        let (stepped, version) = match value.strip_prefix(STEPPED) {
            Some(version) => (true, version),
            None => (false, value.strip_prefix(NOTHING_TO_STEP).unwrap_or(&value)),
        };
        Mark {
            stepped,
            version: version.to_string(),
        }
    }))
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

// ── The notice ───────────────────────────────────────────────────────

/// A folder that synced because everything found did, and syncs no
/// longer: the three things the stored report had for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoppedFolder {
    /// Claude Code's folder for it.
    pub folder: String,
    /// The directory it belongs to, where the report had one.
    pub cwd: Option<String>,
    /// The name it synced under, where the report had one.
    pub name: Option<String>,
}

/// What a device whose stored scope was on is told, once for each time
/// it was stored (decision 2026-10-04 §10.1): the date, the Claude Code
/// directory it was made under, and the folders that stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    /// When it was stored (RFC 3339).
    pub at: String,
    /// The Claude Code directory that sync was on for, or last was.
    pub dir: Option<String>,
    /// Each folder that the last stored report showed as syncing without
    /// a mapping. `None` where that is not known: there was no stored
    /// report, or it could not be read, or it was of a cycle that failed
    /// before it came to a folder. The notice then has the date alone.
    pub folders: Option<Vec<StoppedFolder>>,
}

/// What the last stored report shows of the folders that synced without
/// a mapping.
#[derive(Debug, PartialEq, Eq)]
enum Reported {
    /// There is no report, or it cannot be read, or it has no folders
    /// and has errors.
    NotKnown,
    /// It has no folders and no errors, or every folder in it is mapped:
    /// nothing stopped.
    Nothing,
    /// These stopped.
    Folders(Vec<StoppedFolder>),
}

/// Read a report as the released version stored it, as plain JSON and
/// through no type of the sync adapter's: an object with the folders of
/// the cycle under `folders`, each an object with Claude Code's folder
/// under `folder`, the directory under `cwd`, the name under `project`,
/// and whether it was mapped under `mapped`; and the cycle's errors under
/// `errors`.
///
/// Every folder that is not said to be mapped counts, whatever else the
/// report says of it: one that was waiting, one that had failed, and one
/// of a report from before mappings, which has no `mapped` and no
/// directory. A report that is not in this form cannot be read, and is as
/// none.
fn reported(stored: Option<&str>) -> Reported {
    use serde_json::Value;
    let Some(Ok(Value::Object(report))) = stored.map(serde_json::from_str::<Value>) else {
        return Reported::NotKnown;
    };
    let Some(Value::Array(folders)) = report.get("folders") else {
        return Reported::NotKnown;
    };
    if folders.is_empty() {
        let failed = report
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(|errors| !errors.is_empty());
        return match failed {
            true => Reported::NotKnown,
            false => Reported::Nothing,
        };
    }
    let mut stopped = Vec::new();
    for folder in folders {
        let text = |key: &str| folder.get(key).and_then(Value::as_str).map(str::to_string);
        let Some(claude_folder) = text("folder") else {
            return Reported::NotKnown;
        };
        if folder.get("mapped").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        stopped.push(StoppedFolder {
            folder: claude_folder,
            cwd: text("cwd"),
            name: text("project"),
        });
    }
    match stopped.is_empty() {
        true => Reported::Nothing,
        false => Reported::Folders(stopped),
    }
}

/// The notice that the step stores, where it stores one: for a device
/// whose stored scope is on, or absent with a directory set, whether
/// sync is on or off. (The last directory that is kept while sync is off
/// is no directory set.) None where the report shows that nothing
/// stopped.
fn notice_for(
    conn: &Connection,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<Notice>, CordeliaError> {
    let dir = meta::get(conn, meta::SYNC_CLAUDE_DIR)?;
    let scope_was_on = match meta::get(conn, meta::SYNC_CLAUDE_ALL)? {
        Some(scope) => scope == "on",
        None => dir.is_some(),
    };
    if !scope_was_on {
        return Ok(None);
    }
    let report = meta::get(conn, meta::SYNC_CLAUDE_REPORT)?;
    let folders = match reported(report.as_deref()) {
        Reported::Nothing => return Ok(None),
        Reported::NotKnown => None,
        Reported::Folders(folders) => Some(folders),
    };
    let dir = match dir {
        Some(dir) => Some(dir),
        None => meta::get(conn, meta::SYNC_CLAUDE_LAST_DIR)?,
    };
    Ok(Some(Notice {
        at: now.to_rfc3339(),
        dir,
        folders,
    }))
}

/// The notices that are stored, oldest first. What is stored and cannot
/// be read is as none.
pub fn notices(conn: &Connection) -> Result<Vec<Notice>, CordeliaError> {
    Ok(meta::get(conn, meta::SYNC_CLAUDE_NOTICE)?
        .and_then(|stored| serde_json::from_str(&stored).ok())
        .unwrap_or_default())
}

/// Store `notice` after those that are stored: a later record is added,
/// and none is replaced.
fn store_notice(conn: &Connection, notice: &Notice) -> Result<(), CordeliaError> {
    let mut all = notices(conn)?;
    all.push(notice.clone());
    let json = serde_json::to_string(&all).map_err(|e| CordeliaError::Storage(e.to_string()))?;
    meta::set(conn, meta::SYNC_CLAUDE_NOTICE, &json)
}

// ── The guard ────────────────────────────────────────────────────────

/// The name of the guard against a version that does not know of the
/// step (decision 2026-10-04 §10.1): a trigger on the older kind's table
/// of channels, which refuses every new row.
pub const GUARD: &str = "moved_on_takes_no_channel";

/// What the guard says: that the database was moved on, by which
/// version, and where the copy is.
pub fn guard_words(version: &str) -> String {
    format!(
        "this database was moved on by Cordelia {version} and takes no channel of this kind: \
         a version from before that cannot use it. The copy of the database from before is in \
         the folder {} beside it.",
        copy_name(version)
    )
}

/// The statement that sets the guard.
fn guard_sql(version: &str) -> String {
    format!(
        "CREATE TRIGGER {GUARD} BEFORE INSERT ON channels BEGIN
             SELECT RAISE(ABORT, '{}');
         END;",
        guard_words(version).replace('\'', "''")
    )
}

/// Remove the guard, where the database has it. Returns whether it had.
/// A relay does so when it starts: the guard is a device's, and a relay
/// goes on taking channels of the older kind (decision 2026-10-04
/// §10.1). Where there is none, nothing is written.
pub fn remove_guard(conn: &Connection) -> Result<bool, CordeliaError> {
    let there: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?1)",
            params![GUARD],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if there {
        conn.execute_batch(&format!("DROP TRIGGER IF EXISTS {GUARD};"))
            .map_err(storage)?;
    }
    Ok(there)
}

// ── The step ─────────────────────────────────────────────────────────

/// What the step did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stepped {
    /// How many rows went from the tables it empties.
    pub rows: usize,
    /// The notice it stored, where it stored one.
    pub notice: Option<Notice>,
}

/// The step, in one transaction: all of it or none (decision 2026-10-04
/// §10.1). `version` is the version that makes it, and `now` the date of
/// a notice.
///
/// - Every folder forgets what it had agreed, and the records kept for
///   index lines go with it ([`AGREED_TABLES`]).
/// - Every row of the older kind that a device holds is emptied
///   ([`OLDER_TABLES`], and the search index with its content), and what
///   the node noted of the older kind for itself is removed
///   ([`OLDER_KEYS`]). The counters stay, and so do the device's settings
///   and its mappings.
/// - Where the stored scope is on, or absent with a directory set, the
///   notice is stored ([`Notice`]): made from the report as it is
///   stored, before that is removed.
/// - The stored report is removed, and the scope is written off.
/// - The guard is set ([`GUARD`]).
/// - The mark is written, with the version.
///
/// Where any of it fails, the transaction is undone and nothing of the
/// step is left. It is made once: on a database that has the guard, it
/// fails there.
pub fn step(
    conn: &Connection,
    version: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Stepped, CordeliaError> {
    let batch =
        rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)
            .map_err(storage)?;
    let notice = notice_for(&batch, now)?;
    let mut rows = 0;
    for table in AGREED_TABLES.iter().chain(&OLDER_TABLES) {
        rows += batch
            .execute(&format!("DELETE FROM {table}"), [])
            .map_err(storage)?;
    }
    // The index itself, once its content is gone: none of its words stay.
    batch
        .execute(
            "INSERT INTO search_fts(search_fts) VALUES('delete-all')",
            [],
        )
        .map_err(storage)?;
    for key in OLDER_KEYS {
        meta::remove(&batch, key)?;
    }
    if let Some(notice) = &notice {
        store_notice(&batch, notice)?;
    }
    meta::remove(&batch, meta::SYNC_CLAUDE_REPORT)?;
    meta::set(&batch, meta::SYNC_CLAUDE_ALL, "off")?;
    batch.execute_batch(&guard_sql(version)).map_err(storage)?;
    meta::set(&batch, meta::FIRST_START, &format!("{STEPPED}{version}"))?;
    batch.commit().map_err(storage)?;
    Ok(Stepped { rows, notice })
}

/// Remove the key files of the older channels (decision 2026-10-04
/// §10.1): whatever is in the folder of channel keys under a name that
/// ends as a key file's does, as a file is removed. So a link goes, and
/// not what it points to; and a folder under such a name cannot be
/// removed so, and is left.
///
/// Returns how many went, and how many are left: those that could not be
/// removed. Nothing here fails: one that cannot be removed is counted,
/// for the node to say, and looked for again at the next start. (Where
/// the folder of channel keys itself cannot be read, that counts as one
/// left.)
pub fn remove_older_key_files(data_dir: &Path) -> (usize, usize) {
    let Ok(named) = named_as_key_files(data_dir) else {
        return (0, 1);
    };
    let (mut removed, mut left) = (0, 0);
    for (file, _) in named {
        match std::fs::remove_file(&file) {
            Ok(()) => removed += 1,
            Err(_) => left += 1,
        }
    }
    (removed, left)
}

// ── The whole of it ──────────────────────────────────────────────────

/// What a first start came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Done {
    /// The database had the mark: there was nothing to do.
    Already(Mark),
    /// The node held nothing of the older kind, or the device follows a
    /// recovery phrase: the mark was written, and nothing else.
    Marked,
    /// The copy was made, in this folder, and the step was taken.
    Stepped {
        copy: PathBuf,
        /// The notice that was stored, where one was.
        notice: Option<Notice>,
    },
}

/// A first start that is done, and what became of the key files of the
/// older channels after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstStart {
    pub done: Done,
    /// How many key files of the older channels were removed.
    pub key_files_removed: usize,
    /// How many could not be removed, and are still there.
    pub key_files_left: usize,
}

/// Why a first start is not done. Nothing of the node's own was changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotDone {
    /// The copy could not be made, so the step was not taken.
    NotCopied(NotCopied),
    /// The database could not be read, or the step failed and left
    /// nothing of itself.
    Failed(String),
}

impl From<CordeliaError> for NotDone {
    fn from(e: CordeliaError) -> Self {
        NotDone::Failed(e.to_string())
    }
}

impl std::fmt::Display for NotDone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotDone::NotCopied(not) => write!(
                f,
                "the copy of the database from before this version could not be made ({}). It \
                 needs {} bytes of room",
                not.why, not.room_needed
            ),
            NotDone::Failed(why) => write!(f, "{why}"),
        }
    }
}

/// What a personal node does when it starts, to a database that its
/// opening has stepped as any version steps it (decision 2026-10-04
/// §10.1). `data_dir` is the folder of the database and of the key files,
/// `version` the node's own, and `now` the date of a notice.
///
/// - **With a mark** nothing is stepped.
/// - **With no mark,** where the device already follows a recovery
///   phrase, or the node holds no row and no key file of the older kind,
///   the mark is written and nothing else.
/// - **Otherwise** the copy is made and then the step is taken
///   ([`copy`], [`step`]). Where the copy cannot be made the step is not
///   taken, and where the step fails nothing of it is left: either way
///   there is no mark, and a later call tries again.
///
/// Then, whichever of these it was, the key files of the older channels
/// are removed ([`remove_older_key_files`]): a start that was cut short
/// after the step's commit must not leave them for good.
pub fn first_start(
    conn: &Connection,
    data_dir: &Path,
    version: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<FirstStart, NotDone> {
    let done = match mark(conn)? {
        Some(mark) => Done::Already(mark),
        None => {
            let follows_a_phrase = crate::person::person(conn)?.is_some();
            if follows_a_phrase || !holds_older(conn, data_dir)? {
                meta::set(
                    conn,
                    meta::FIRST_START,
                    &format!("{NOTHING_TO_STEP}{version}"),
                )?;
                Done::Marked
            } else {
                let copy = copy(conn, data_dir, version).map_err(NotDone::NotCopied)?;
                let stepped = step(conn, version, now)?;
                Done::Stepped {
                    copy,
                    notice: stepped.notice,
                }
            }
        }
    };
    let (key_files_removed, key_files_left) = remove_older_key_files(data_dir);
    Ok(FirstStart {
        done,
        key_files_removed,
        key_files_left,
    })
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

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-10-07T08:00:00+00:00")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

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

    fn key(conn: &Connection, key: &str) -> Option<String> {
        meta::get(conn, key).unwrap()
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
    /// beside the folder; not a file of another name in it. A copy holds
    /// those that are files. What is removed is whatever has such a name,
    /// as a file is removed: a link goes, and not what it points to; a
    /// folder cannot go so, and is counted as left.
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

        // A copy holds the files, and neither the link nor the folder.
        let conn = db::open(&data.join(DATABASE)).unwrap();
        let copy = copy(&conn, data, VERSION).unwrap();
        assert_eq!(names_in(&copy.join("channel-keys")), released::KEY_FILES);

        // Removing them removes whatever has such a name, as a file is
        // removed, and nothing else.
        let links = usize::from(cfg!(unix));
        assert_eq!(
            remove_older_key_files(data),
            (released::KEY_FILES.len() + links, 1)
        );
        assert_eq!(names_in(&keys), ["a-folder.key", "key", "notes.txt"]);
        assert_eq!(std::fs::read(data.join("identity.key")).unwrap(), [9u8; 32]);
        assert_eq!(remove_older_key_files(data), (0, 1));
        assert_eq!(remove_older_key_files(none.path()), (0, 0));
    }

    // ── The step ─────────────────────────────────────────────────────

    fn has_guard(conn: &Connection) -> bool {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = ?1)",
            params![GUARD],
            |row| row.get(0),
        )
        .unwrap()
    }

    /// A new row in the older kind's table of channels.
    fn new_channel(conn: &Connection, id: &str) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id,
                                   created_at, updated_at)
             VALUES (?1, 'group', 'realtime', 'invite_only', X'AA', '2026-10-07', '2026-10-07')",
            params![id],
        )
    }

    /// The step empties every table and key of the older kind, each by
    /// its name, and what a folder agreed with the records for index
    /// lines; and it keeps the counters, what was seen of peers, and the
    /// settings (decision 2026-10-04 §10.1). Every table that the
    /// released version has is one that the step empties or one that it
    /// keeps: there is no third kind.
    #[test]
    fn each_table_and_key_of_the_older_kind_is_emptied_by_its_name() {
        const EMPTIED: [&str; 11] = [
            "channels",
            "channel_members",
            "channel_keys",
            "dm_peers",
            "items",
            "search_content",
            "invites",
            "state_offers",
            "trusted_keys",
            "sync_files",
            "index_lines",
        ];
        const KEPT: [&str; 3] = ["counters", "node_meta", "peer_sightings"];
        const KEYS_REMOVED: [&str; 5] = [
            "personal_channel_id",
            "membership.accepted_personal_from",
            "sync.claude.last_change",
            "sync.claude.activity",
            "sync.claude.report",
        ];
        const KEYS_KEPT: [&str; 6] = [
            "sync.claude.dir",
            "sync.claude.mappings",
            "sync.claude.exclude",
            "sync.claude.home",
            "sync.claude.home_name",
            "usage.sighting_secret",
        ];

        // The tables of the released version, by its own schema: but for
        // the search index's own, which hold what its content holds.
        let dir = tempfile::tempdir().unwrap();
        let as_released = released::database(&dir.path().join("as-released.db")).unwrap();
        let tables: Vec<String> = as_released
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                   AND name NOT LIKE 'search_fts%' ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let mut listed: Vec<&str> = EMPTIED.iter().chain(&KEPT).copied().collect();
        listed.sort();
        assert_eq!(tables, listed);
        // The lists in the code are these, and no other.
        let mut in_code: Vec<&str> = OLDER_TABLES.iter().chain(&AGREED_TABLES).copied().collect();
        in_code.sort();
        let mut emptied = EMPTIED.to_vec();
        emptied.sort();
        assert_eq!(in_code, emptied);
        let mut keys_in_code = OLDER_KEYS.to_vec();
        keys_in_code.push(meta::SYNC_CLAUDE_REPORT);
        assert_eq!(keys_in_code, KEYS_REMOVED);

        let (_dir, conn) = released_node(|_| {});
        let kept: Vec<i64> = KEPT.iter().map(|table| rows(&conn, table)).collect();
        for table in EMPTIED {
            assert!(rows(&conn, table) > 0, "{table} holds no row to begin with");
        }
        for name in KEYS_REMOVED.iter().chain(&KEYS_KEPT) {
            assert!(
                key(&conn, name).is_some(),
                "{name} is not set to begin with"
            );
        }
        let values: Vec<Option<String>> = KEYS_KEPT.iter().map(|name| key(&conn, name)).collect();
        // How many pages of words the search index keeps in its own
        // store: every row there but the two it keeps of itself.
        let pages_of_the_index = || -> i64 {
            conn.query_row(
                "SELECT COUNT(*) FROM search_fts_data WHERE id > 10",
                [],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert_eq!(found_in_search(&conn, "tuesday"), 1);
        assert!(pages_of_the_index() > 0);

        let stepped = step(&conn, VERSION, now()).unwrap();
        assert!(stepped.rows >= EMPTIED.len(), "{stepped:?}");
        for table in EMPTIED {
            assert_eq!(rows(&conn, table), 0, "{table}");
        }
        for name in KEYS_REMOVED {
            assert_eq!(key(&conn, name), None, "{name}");
        }
        // No word of what was published stays in the search index: none
        // is found there, and none is in what the index is kept in.
        assert_eq!(found_in_search(&conn, "tuesday"), 0);
        assert_eq!(pages_of_the_index(), 0);
        for (table, before) in KEPT.iter().zip(&kept) {
            // The table of what the node notes for itself loses the keys
            // that are removed, and gains the mark.
            let after = rows(&conn, table);
            match *table {
                "node_meta" => assert_eq!(after, before - KEYS_REMOVED.len() as i64 + 1),
                _ => assert_eq!(after, *before, "{table}"),
            }
        }
        let after: Vec<Option<String>> = KEYS_KEPT.iter().map(|name| key(&conn, name)).collect();
        assert_eq!(after, values);
        // The counter of arrival order stays where it was, and the counts
        // of what the table of items holds follow its rows.
        let counted = |name: &str| -> i64 {
            conn.query_row(
                "SELECT value FROM counters WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert_eq!(counted("item_seq"), 42);
        assert_eq!((counted("item_count"), counted("item_bytes")), (0, 0));
        // The scope is written off, and the mark says which version made
        // the step.
        assert_eq!(key(&conn, meta::SYNC_CLAUDE_ALL).as_deref(), Some("off"));
        assert_eq!(
            mark(&conn).unwrap(),
            Some(Mark {
                stepped: true,
                version: VERSION.into()
            })
        );
    }

    /// The step, with `scope` stored (or none), sync on or off, and
    /// `report` stored (or none): the notice it stored.
    fn notice_of(scope: Option<&str>, sync_on: bool, report: Option<&str>) -> Option<Notice> {
        let (_dir, conn) = released_node(|conn| {
            match scope {
                Some(scope) => meta::set(conn, meta::SYNC_CLAUDE_ALL, scope).unwrap(),
                None => meta::remove(conn, meta::SYNC_CLAUDE_ALL).unwrap(),
            }
            if !sync_on {
                let dir = meta::get(conn, meta::SYNC_CLAUDE_DIR).unwrap().unwrap();
                meta::set(conn, meta::SYNC_CLAUDE_LAST_DIR, &dir).unwrap();
                meta::remove(conn, meta::SYNC_CLAUDE_DIR).unwrap();
            }
            match report {
                Some(report) => meta::set(conn, meta::SYNC_CLAUDE_REPORT, report).unwrap(),
                None => meta::remove(conn, meta::SYNC_CLAUDE_REPORT).unwrap(),
            }
        });
        let notice = step(&conn, VERSION, now()).unwrap().notice;
        // Whatever the scope was, it is off afterwards, and the stored
        // report and the times that each name last synced are removed:
        // nothing says that a folder syncs on a device that follows no
        // phrase.
        assert_eq!(key(&conn, meta::SYNC_CLAUDE_ALL).as_deref(), Some("off"));
        assert_eq!(key(&conn, meta::SYNC_CLAUDE_REPORT), None);
        assert_eq!(key(&conn, meta::SYNC_CLAUDE_ACTIVITY), None);
        assert_eq!(key(&conn, meta::SYNC_CLAUDE_LAST_CHANGE), None);
        // What is stored is what the step says it stored.
        let stored: Vec<Notice> = notice.clone().into_iter().collect();
        assert_eq!(notices(&conn).unwrap(), stored);
        notice
    }

    /// With the scope stored on, the notice names what the last report
    /// showed as syncing without a mapping, with sync on and with it off
    /// (decision 2026-10-04 §10.1): the date, the Claude Code directory,
    /// and each such folder with its directory and its name. A scope
    /// that is absent with a directory set is on. With the scope off, or
    /// absent with sync off, nothing is stored.
    #[test]
    fn a_device_whose_scope_was_on_is_left_a_notice_of_what_stopped() {
        let report = Some(released::REPORT);
        let stopped = |folder: &str, cwd: &str, name: &str| StoppedFolder {
            folder: folder.into(),
            cwd: Some(cwd.into()),
            name: Some(name.into()),
        };
        // The two folders that the released version's report shows as
        // syncing without a mapping: not the one that is mapped, and not
        // the one that was found and did not sync.
        let told = Notice {
            at: "2026-10-07T08:00:00+00:00".into(),
            dir: Some("/home/sam/.claude".into()),
            folders: Some(vec![
                stopped(
                    "/home/sam/.claude/projects/-home-sam-work-tools",
                    "/home/sam/work/tools",
                    "github.com/sam/tools",
                ),
                stopped("/home/sam/.claude/projects/-home-sam", "/home/sam", "~"),
            ]),
        };
        assert_eq!(notice_of(Some("on"), true, report), Some(told.clone()));
        assert_eq!(notice_of(Some("on"), false, report), Some(told.clone()));
        assert_eq!(notice_of(None, true, report), Some(told));
        assert_eq!(notice_of(None, false, report), None);
        assert_eq!(notice_of(Some("off"), true, report), None);
        assert_eq!(notice_of(Some("off"), false, report), None);
    }

    /// A report that cannot be read is as none, and the notice then has
    /// the date alone: so has one of a cycle that failed before it came
    /// to a folder. Where the report shows that nothing synced without a
    /// mapping, nothing stopped, and no notice is stored (decision
    /// 2026-10-04 §10.1).
    #[test]
    fn a_report_that_cannot_be_read_leaves_a_notice_with_the_date_alone() {
        let the_date_alone = Some(Notice {
            at: "2026-10-07T08:00:00+00:00".into(),
            dir: Some("/home/sam/.claude".into()),
            folders: None,
        });
        for unread in [
            None,
            Some(""),
            Some("{\"folders\":[{\"folder\":\"/a\""),
            Some("[]"),
            Some("{}"),
            Some("{\"folders\":7,\"errors\":[]}"),
            Some("{\"folders\":[7],\"errors\":[]}"),
            Some("{\"folders\":[{\"project\":\"a\"}],\"errors\":[]}"),
            Some("{\"folders\":[],\"errors\":[\"the folder could not be listed\"]}"),
        ] {
            let stored = notice_of(Some("on"), true, unread);
            assert_eq!(stored, the_date_alone, "{unread:?}");
        }
        for nothing_stopped in [
            "{\"folders\":[],\"errors\":[]}",
            "{\"folders\":[]}",
            "{\"folders\":[{\"folder\":\"/a\",\"mapped\":true}],\"errors\":[\"x\"]}",
        ] {
            let stored = notice_of(Some("on"), true, Some(nothing_stopped));
            assert_eq!(stored, None, "{nothing_stopped}");
        }
        // A report from before mappings has no `mapped` and no directory
        // for a folder: every folder in it counts.
        let before_mappings = "{\"folders\":[{\"folder\":\"/a\",\"project\":\"one\"},\
                               {\"folder\":\"/b\",\"project\":\"two\",\"waiting\":true}]}";
        let stored = notice_of(Some("on"), true, Some(before_mappings)).unwrap();
        let named = |folder: &str, name: &str| StoppedFolder {
            folder: folder.into(),
            cwd: None,
            name: Some(name.into()),
        };
        assert_eq!(
            stored.folders,
            Some(vec![named("/a", "one"), named("/b", "two")])
        );
    }

    /// A notice is one record for each time it was stored: a later one
    /// is added, and none is replaced. What is stored and cannot be read
    /// is as none.
    #[test]
    fn a_later_notice_is_added_and_none_is_replaced() {
        let conn = db::open_in_memory().unwrap();
        assert!(notices(&conn).unwrap().is_empty());
        meta::set(&conn, meta::SYNC_CLAUDE_NOTICE, "not a list").unwrap();
        assert!(notices(&conn).unwrap().is_empty());
        let notice = |at: &str| Notice {
            at: at.into(),
            dir: None,
            folders: None,
        };
        store_notice(&conn, &notice("one")).unwrap();
        store_notice(&conn, &notice("two")).unwrap();
        assert_eq!(notices(&conn).unwrap(), [notice("one"), notice("two")]);
    }

    /// A step that fails half way leaves nothing of it: every row and
    /// key is as it was, no notice is stored, and there is no guard and
    /// no mark (decision 2026-10-04 §10.1).
    #[test]
    fn a_step_that_fails_half_way_leaves_nothing_of_it() {
        let (_dir, conn) = released_node(|conn| {
            meta::set(conn, meta::SYNC_CLAUDE_ALL, "on").unwrap();
            // The table that the step empties last but one refuses.
            conn.execute_batch(
                "CREATE TRIGGER no_row BEFORE DELETE ON trusted_keys BEGIN
                     SELECT RAISE(ABORT, 'this row stays');
                 END;",
            )
            .unwrap();
        });
        let before = everything(&conn);

        let failed = step(&conn, VERSION, now()).unwrap_err().to_string();
        assert!(failed.contains("this row stays"), "{failed}");
        assert!(conn.is_autocommit());
        assert_eq!(everything(&conn), before);
        assert_eq!(found_in_search(&conn, "tuesday"), 1);
        assert!(notices(&conn).unwrap().is_empty());
        assert_eq!(mark(&conn).unwrap(), None);
        assert!(!has_guard(&conn));

        conn.execute_batch("DROP TRIGGER no_row").unwrap();
        let stepped = step(&conn, VERSION, now()).unwrap();
        assert!(stepped.notice.is_some());
        assert_eq!(rows(&conn, "channels"), 0);
    }

    /// The guard: once the step is made, a new row in the older kind's
    /// table of channels is refused, with words that say the database
    /// was moved on and where the copy is. A relay's start removes it
    /// (decision 2026-10-04 §10.1).
    #[test]
    fn the_guard_refuses_a_new_channel_with_its_words_until_a_relay_removes_it() {
        let (dir, conn) = released_node(|_| {});
        assert!(new_channel(&conn, "grp_before").is_ok());
        assert!(!has_guard(&conn));
        assert!(!remove_guard(&conn).unwrap());
        step(&conn, "0.2.0-it's", now()).unwrap();
        assert!(has_guard(&conn));

        let refused = new_channel(&conn, "grp_after").unwrap_err().to_string();
        let words = guard_words("0.2.0-it's");
        assert!(refused.contains(&words), "{refused}");
        assert!(
            words.contains("was moved on by Cordelia 0.2.0-it's"),
            "{words}"
        );
        assert!(
            words.contains("in the folder before-0.2.0-it-s beside it"),
            "{words}"
        );
        assert_eq!(rows(&conn, "channels"), 0);
        // A connection that opens the database afterwards meets it too.
        let other = Connection::open(dir.path().join(DATABASE)).unwrap();
        assert!(new_channel(&other, "grp_other").is_err());
        // The step is made once: where the guard is, it fails there.
        assert!(step(&conn, VERSION, now()).is_err());

        assert!(remove_guard(&conn).unwrap());
        assert!(!has_guard(&conn));
        assert!(new_channel(&conn, "grp_after").is_ok());
        assert!(!remove_guard(&conn).unwrap());
    }

    /// A mark says whether the step was made, and which version wrote
    /// it. A mark in another form is still a mark.
    #[test]
    fn a_mark_in_any_form_is_a_mark() {
        let conn = db::open_in_memory().unwrap();
        assert_eq!(mark(&conn).unwrap(), None);
        let read = |value: &str| {
            meta::set(&conn, meta::FIRST_START, value).unwrap();
            let mark = mark(&conn).unwrap().unwrap();
            (mark.stepped, mark.version)
        };
        assert_eq!(read("stepped by 0.3.0"), (true, "0.3.0".to_string()));
        assert_eq!(
            read("nothing to step, marked by 0.3.0"),
            (false, "0.3.0".to_string())
        );
        assert_eq!(read("done"), (false, "done".to_string()));
        assert_eq!(read(""), (false, String::new()));
    }

    // ── The key files, after the step ────────────────────────────────

    /// The key files of the older channels are removed, and one that
    /// cannot be removed is counted and left (decision 2026-10-04
    /// §10.1): nothing fails by it.
    #[cfg(unix)]
    #[test]
    fn a_key_file_that_cannot_be_removed_is_counted_and_left() {
        let (dir, _conn) = released_node(|_| {});
        let data = dir.path();
        let files = released::KEY_FILES.len();
        // The folder of channel keys cannot be written: none can go.
        set_mode(&data.join("channel-keys"), 0o500);
        assert_eq!(remove_older_key_files(data), (0, files));
        assert_eq!(older_key_files(data).unwrap().len(), files);
        // Nor can it be read: that counts as one left.
        set_mode(&data.join("channel-keys"), 0o000);
        assert_eq!(remove_older_key_files(data), (0, 1));
        set_mode(&data.join("channel-keys"), 0o700);

        assert_eq!(remove_older_key_files(data), (files, 0));
        assert!(older_key_files(data).unwrap().is_empty());
        // The folder itself stays, and so does the device's own key.
        assert!(names_in(&data.join("channel-keys")).is_empty());
        assert_eq!(std::fs::read(data.join("identity.key")).unwrap(), [9u8; 32]);
        assert_eq!(remove_older_key_files(data), (0, 0));
    }

    // ── The whole of a first start ───────────────────────────────────

    fn stepped_by_this_version() -> Mark {
        Mark {
            stepped: true,
            version: VERSION.into(),
        }
    }

    /// A database in the released version's form is started on this
    /// version (decision 2026-10-04 §10.1). The copy is there, with every
    /// older row and each key file. The records, every older row and the
    /// older key files are gone from the node's own. The key, the
    /// settings, the mappings, the counters and local history are as
    /// they were.
    #[test]
    fn a_database_of_the_released_version_is_copied_and_then_stepped() {
        let (dir, conn) = released_node(|_| {});
        let data = dir.path();
        let (before, own_files) = (everything(&conn), its_own_files(data));
        assert!(holds_older(&conn, data).unwrap());
        let settings = |conn: &Connection| -> Vec<Option<String>> {
            [
                meta::SYNC_CLAUDE_DIR,
                meta::SYNC_CLAUDE_MAPPINGS,
                meta::SYNC_CLAUDE_EXCLUDE,
                meta::SYNC_CLAUDE_HOME,
                meta::SYNC_CLAUDE_HOME_NAME,
            ]
            .iter()
            .map(|name| key(conn, name))
            .collect()
        };
        let settings_before = settings(&conn);
        assert!(settings_before.iter().all(Option::is_some));

        let started = first_start(&conn, data, VERSION, now()).unwrap();
        let copy = data.join("before-0.2.0-test");
        assert_eq!(
            started,
            FirstStart {
                done: Done::Stepped {
                    copy: copy.clone(),
                    notice: None
                },
                key_files_removed: released::KEY_FILES.len(),
                key_files_left: 0,
            }
        );
        // The copy holds what the node held: it has no mark, and no
        // guard.
        assert_eq!(copies_in(data), ["before-0.2.0-test"]);
        assert_eq!(names_in(&copy.join("channel-keys")), released::KEY_FILES);
        let copied =
            Connection::open_with_flags(copy.join("cordelia.db"), OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        assert_eq!(everything(&copied), before);
        assert_eq!(mark(&copied).unwrap(), None);
        drop(copied);

        // The node's own: nothing of the older kind, and no key file.
        for table in AGREED_TABLES.iter().chain(&OLDER_TABLES) {
            assert_eq!(rows(&conn, table), 0, "{table}");
        }
        for name in OLDER_KEYS {
            assert_eq!(key(&conn, name), None, "{name}");
        }
        assert!(!holds_older(&conn, data).unwrap());
        assert!(older_key_files(data).unwrap().is_empty());
        assert!(names_in(&data.join("channel-keys")).is_empty());
        // What stays is as it was.
        assert_eq!(settings(&conn), settings_before);
        assert_eq!(rows(&conn, "peer_sightings"), 1);
        assert_eq!(its_own_files(data), own_files);
        assert_eq!(mark(&conn).unwrap(), Some(stepped_by_this_version()));
        assert!(has_guard(&conn));
    }

    /// A second start changes nothing and makes no second copy, and nor
    /// does a start in a later version: any mark means done (decision
    /// 2026-10-04 §10.1).
    #[test]
    fn a_second_start_changes_nothing_and_makes_no_second_copy() {
        let (dir, conn) = released_node(|conn| {
            meta::set(conn, meta::SYNC_CLAUDE_ALL, "on").unwrap();
        });
        let data = dir.path();
        first_start(&conn, data, VERSION, now()).unwrap();
        assert_eq!(notices(&conn).unwrap().len(), 1);
        // A setting made since is not the step's to change.
        meta::set(&conn, meta::SYNC_CLAUDE_ALL, "on").unwrap();
        let before = everything(&conn);
        let copy = data.join("before-0.2.0-test");
        let copied = std::fs::read(copy.join("cordelia.db")).unwrap();

        for version in [VERSION, "9.9.9"] {
            let again = first_start(&conn, data, version, now()).unwrap();
            assert_eq!(
                again,
                FirstStart {
                    done: Done::Already(stepped_by_this_version()),
                    key_files_removed: 0,
                    key_files_left: 0,
                }
            );
            assert_eq!(everything(&conn), before, "{version}");
            assert_eq!(copies_in(data), ["before-0.2.0-test"], "{version}");
            assert_eq!(std::fs::read(copy.join("cordelia.db")).unwrap(), copied);
        }
        // A mark in another form is still a mark.
        meta::set(&conn, meta::FIRST_START, "done").unwrap();
        let again = first_start(&conn, data, VERSION, now()).unwrap();
        assert!(matches!(again.done, Done::Already(_)), "{again:?}");
        assert_eq!(copies_in(data), ["before-0.2.0-test"]);
    }

    /// A first install writes the mark and makes no copy: it holds
    /// nothing of the older kind (decision 2026-10-04 §10.1). No guard is
    /// set, and nothing else is written.
    #[test]
    fn a_first_install_gets_the_mark_and_no_copy() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open(&dir.path().join(DATABASE)).unwrap();
        std::fs::create_dir(dir.path().join("channel-keys")).unwrap();
        assert!(!holds_older(&conn, dir.path()).unwrap());
        assert_eq!(mark(&conn).unwrap(), None);
        let before = everything(&conn);

        let started = first_start(&conn, dir.path(), VERSION, now()).unwrap();
        assert_eq!(started.done, Done::Marked);
        assert!(copies_in(dir.path()).is_empty());
        let marked = Mark {
            stepped: false,
            version: VERSION.into(),
        };
        assert_eq!(mark(&conn).unwrap(), Some(marked));
        // The mark, and nothing else.
        let mut with_the_mark = before;
        with_the_mark.retain(|line| line != "node_meta: 0");
        with_the_mark.push("node_meta: 1".into());
        with_the_mark.push(format!(
            "noted {}=nothing to step, marked by {VERSION}",
            meta::FIRST_START
        ));
        with_the_mark.sort();
        let mut after = everything(&conn);
        after.sort();
        assert_eq!(after, with_the_mark);
        let again = first_start(&conn, dir.path(), VERSION, now()).unwrap();
        assert!(matches!(again.done, Done::Already(_)), "{again:?}");
    }

    /// Each thing of the older kind, alone, is something to step: a row
    /// in one of its tables, one of its keys, or a key file.
    #[test]
    fn a_node_holds_something_of_the_older_kind_by_any_one_of_them() {
        let fresh = || {
            let dir = tempfile::tempdir().unwrap();
            let conn = db::open(&dir.path().join(DATABASE)).unwrap();
            (dir, conn)
        };
        let (dir, conn) = fresh();
        assert!(!holds_older(&conn, dir.path()).unwrap());
        // What a folder agreed, a setting and the counters are not of it.
        meta::set(&conn, meta::SYNC_CLAUDE_DIR, "/home/sam/.claude").unwrap();
        meta::set(&conn, meta::SYNC_CLAUDE_ALL, "on").unwrap();
        assert!(!holds_older(&conn, dir.path()).unwrap());

        for name in OLDER_KEYS {
            let (dir, conn) = fresh();
            meta::set(&conn, name, "x").unwrap();
            assert!(holds_older(&conn, dir.path()).unwrap(), "{name}");
        }
        let (dir, conn) = fresh();
        new_channel(&conn, "grp_one").unwrap();
        assert!(holds_older(&conn, dir.path()).unwrap());
        let (dir, conn) = fresh();
        conn.execute(
            "INSERT INTO trusted_keys (entity_key, kind, added_at)
             VALUES (X'BB', 'device', '2026-10-07')",
            [],
        )
        .unwrap();
        assert!(holds_older(&conn, dir.path()).unwrap());
        let (dir, conn) = fresh();
        std::fs::create_dir(dir.path().join("channel-keys")).unwrap();
        assert!(!holds_older(&conn, dir.path()).unwrap());
        std::fs::write(
            dir.path().join("channel-keys").join("grp_one.slot"),
            [1u8; 32],
        )
        .unwrap();
        assert!(holds_older(&conn, dir.path()).unwrap());
        // And it is stepped, with its copy.
        let started = first_start(&conn, dir.path(), VERSION, now()).unwrap();
        assert!(matches!(started.done, Done::Stepped { .. }), "{started:?}");
        assert_eq!(started.key_files_removed, 1);
        // So is a folder under the name of a key file: it is found by
        // its place and its name, whatever it is, and is left, and said.
        let (dir, conn) = fresh();
        std::fs::create_dir_all(dir.path().join("channel-keys").join("grp_one.key")).unwrap();
        assert!(holds_older(&conn, dir.path()).unwrap());
        let started = first_start(&conn, dir.path(), VERSION, now()).unwrap();
        assert!(matches!(started.done, Done::Stepped { .. }), "{started:?}");
        assert_eq!((started.key_files_removed, started.key_files_left), (0, 1));
    }

    /// A database in which the device follows a recovery phrase, and that
    /// has no mark, is not stepped (decision 2026-10-04 §10.1): it is
    /// from a build that already left the older channels. The mark is
    /// written, no copy is made, and every row stays.
    #[test]
    fn a_database_that_follows_a_phrase_is_marked_and_not_stepped() {
        use crate::person::{Following, Person, State, put_person};
        let (dir, conn) = released_node(|_| {});
        let follows = Person {
            state: State::Applied,
            following: Following {
                phrase_key: [1; 32],
                statement_key: [2; 32],
                phrase_channel: [3; 32],
            },
            statement: vec![4, 5, 6],
        };
        put_person(&conn, &follows).unwrap();
        let before: Vec<i64> = OLDER_TABLES
            .iter()
            .map(|table| rows(&conn, table))
            .collect();
        assert!(before.iter().all(|rows| *rows > 0));

        let started = first_start(&conn, dir.path(), VERSION, now()).unwrap();
        assert_eq!(started.done, Done::Marked);
        let after: Vec<i64> = OLDER_TABLES
            .iter()
            .map(|table| rows(&conn, table))
            .collect();
        assert_eq!(after, before);
        assert!(key(&conn, meta::SYNC_CLAUDE_REPORT).is_some());
        assert!(copies_in(dir.path()).is_empty());
        assert!(!has_guard(&conn));
        assert_eq!(mark(&conn).unwrap().map(|mark| mark.stepped), Some(false));
        // The key files of the older channels are looked for at every
        // start, whatever the mark says.
        assert_eq!(started.key_files_removed, released::KEY_FILES.len());
    }

    /// Where the copy cannot be made, the step is not taken: no older
    /// row or key file is changed, and there is no mark (decision
    /// 2026-10-04 §10.1). The answer says why, with the room a copy
    /// needs. Once it can be made, the next call makes it.
    #[cfg(unix)]
    #[test]
    fn a_copy_that_cannot_be_made_takes_no_step() {
        let (dir, conn) = released_node(|_| {});
        let data = dir.path();
        let (before, key_files) = (everything(&conn), key_files_held(data));
        let closed = a_partial_copy_that_cannot_be_removed(data);

        let not_done = first_start(&conn, data, VERSION, now()).unwrap_err();
        let NotDone::NotCopied(not_copied) = &not_done else {
            panic!("{not_done:?}");
        };
        let says = not_done.to_string();
        assert!(says.contains("could not be made"), "{says}");
        assert!(
            says.contains(&format!("needs {} bytes of room", not_copied.room_needed)),
            "{says}"
        );
        assert_eq!(everything(&conn), before);
        assert_eq!(mark(&conn).unwrap(), None);
        assert_eq!(key_files_held(data), key_files);
        assert_eq!(copies_in(data), ["before-0.2.0-test.partial"]);

        set_mode(&closed, 0o700);
        let started = first_start(&conn, data, VERSION, now()).unwrap();
        assert!(matches!(started.done, Done::Stepped { .. }), "{started:?}");
        assert_eq!(copies_in(data), ["before-0.2.0-test"]);
        assert_eq!(mark(&conn).unwrap(), Some(stepped_by_this_version()));
    }

    /// Where the step fails, nothing of it is left, and the key files are
    /// where they were: the next start makes the copy again, keeping the
    /// one from before as the earlier one, and takes the step (decision
    /// 2026-10-04 §10.1).
    #[test]
    fn a_first_start_whose_step_fails_is_made_whole_by_the_next() {
        let (dir, conn) = released_node(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER no_row BEFORE DELETE ON trusted_keys BEGIN
                     SELECT RAISE(ABORT, 'this row stays');
                 END;",
            )
            .unwrap();
        });
        let data = dir.path();
        let (before, key_files) = (everything(&conn), key_files_held(data));

        let not_done = first_start(&conn, data, VERSION, now()).unwrap_err();
        assert!(
            matches!(&not_done, NotDone::Failed(why) if why.contains("this row stays")),
            "{not_done:?}"
        );
        assert_eq!(everything(&conn), before);
        assert_eq!(key_files_held(data), key_files);
        assert_eq!(copies_in(data), ["before-0.2.0-test"]);

        conn.execute_batch("DROP TRIGGER no_row").unwrap();
        let started = first_start(&conn, data, VERSION, now()).unwrap();
        assert!(matches!(started.done, Done::Stepped { .. }), "{started:?}");
        assert_eq!(
            copies_in(data),
            ["before-0.2.0-test", "before-0.2.0-test.earlier"]
        );
        assert!(older_key_files(data).unwrap().is_empty());
    }

    /// A start that is cut short after the step's commit, before the key
    /// files are removed: the next start removes them (decision
    /// 2026-10-04 §10.1). One that cannot be removed is counted, and the
    /// start is done all the same.
    #[cfg(unix)]
    #[test]
    fn a_start_cut_short_after_the_commit_still_removes_the_key_files() {
        let (dir, conn) = released_node(|_| {});
        let data = dir.path();
        copy(&conn, data, VERSION).unwrap();
        step(&conn, VERSION, now()).unwrap();
        let files = released::KEY_FILES.len();
        assert_eq!(older_key_files(data).unwrap().len(), files);

        // The folder of channel keys cannot be written: none can go.
        set_mode(&data.join("channel-keys"), 0o500);
        let started = first_start(&conn, data, VERSION, now()).unwrap();
        assert_eq!(started.done, Done::Already(stepped_by_this_version()));
        assert_eq!(
            (started.key_files_removed, started.key_files_left),
            (0, files)
        );
        set_mode(&data.join("channel-keys"), 0o700);

        let started = first_start(&conn, data, VERSION, now()).unwrap();
        assert_eq!(
            (started.key_files_removed, started.key_files_left),
            (files, 0)
        );
        assert!(older_key_files(data).unwrap().is_empty());
        assert_eq!(copies_in(data), ["before-0.2.0-test"]);
    }
}
