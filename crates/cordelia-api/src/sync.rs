//! Switching sync adapters on and off, and reporting on them (decision
//! 2026-09-30-agent-memory-sync §4.5). The adapter itself runs in the node
//! (cordelia-sync); these handlers only set and read its settings.
//!
//! A mapped folder syncs a name, whose channel comes from the person's
//! secret (decision 2026-10-04 §2.2). So a handler that changes which
//! names this device syncs also says so in the personal channel, under
//! the hold of the database's lock that it changed the setting under
//! ([`names_follow`]): it holds a name and says that it syncs it when it
//! maps the name, and says so no longer, and holds the name no more, when
//! it unmaps it. Turning sync off takes back what it said of every name.
//! A device that follows no phrase says nothing: what is in its folders
//! stays on the machine (§5.2).

use actix_web::{HttpRequest, HttpResponse, web};

use cordelia_storage::{meta, sync_state};

use crate::auth;
use crate::error::ApiError;
use crate::state::{AppState, SyncControl};
use crate::types::*;

/// The name home memory syncs under unless it is given another. No other
/// folder may take it: every device shows it as home memory.
pub(crate) const HOME_NAME: &str = "~";

pub(crate) fn mappings(db: &rusqlite::Connection) -> Result<Vec<SyncMapping>, ApiError> {
    Ok(meta::get(db, meta::SYNC_CLAUDE_MAPPINGS)?
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default())
}

fn store_mappings(db: &rusqlite::Connection, list: &[SyncMapping]) -> Result<(), ApiError> {
    let json = serde_json::to_string(list).map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(meta::set(db, meta::SYNC_CLAUDE_MAPPINGS, &json)?)
}

/// The exclude list, each entry read as it would be stored now
/// ([`clean_exclusion`]). A name is read in its one spelling: an earlier
/// version could store one that ended in `.git`. A folder keeps a space
/// at the end of its name; its separators are tidied, and one with `..`
/// in it is dropped.
fn exclusions(db: &rusqlite::Connection) -> Result<Vec<String>, ApiError> {
    let stored: Vec<String> = meta::get(db, meta::SYNC_CLAUDE_EXCLUDE)?
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default();
    Ok(stored
        .iter()
        .filter_map(|entry| clean_exclusion(entry))
        .collect())
}

fn store_exclusions(db: &rusqlite::Connection, list: &[String]) -> Result<(), ApiError> {
    let json = serde_json::to_string(list).map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(meta::set(db, meta::SYNC_CLAUDE_EXCLUDE, &json)?)
}

fn status(state: &AppState) -> Result<SyncStatusResponse, ApiError> {
    use cordelia_storage::person::State;
    // What a stored notice names is asked of the disk and of git once
    // the database's lock is let go.
    let (mut status, notices, last_dir) = {
        let db = state
            .db
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let dir = meta::get(&db, meta::SYNC_CLAUDE_DIR)?;
        let report =
            meta::get(&db, meta::SYNC_CLAUDE_REPORT)?.and_then(|r| serde_json::from_str(&r).ok());
        let home = meta::get(&db, meta::SYNC_CLAUDE_HOME)?.is_none_or(|v| v != "off");
        let last_change_at = meta::get(&db, meta::SYNC_CLAUDE_LAST_CHANGE)?;
        let stands = match crate::at_relays::stands(&db) {
            Ok(crate::at_relays::Stands::NoPhrase) => "no_phrase",
            Ok(crate::at_relays::Stands::Applied) => "applied",
            Ok(crate::at_relays::Stands::Stopped(State::Fork)) => "fork",
            Ok(crate::at_relays::Stands::Stopped(State::Removed)) => "removed",
            Ok(crate::at_relays::Stands::Stopped(State::NotListed)) => "not_listed",
            Ok(crate::at_relays::Stands::Stopped(_)) => "not_opened",
            Err(e) => return Err(ApiError::Internal(e.to_string())),
        };
        let status = SyncStatusResponse {
            enabled: dir.is_some(),
            dir,
            // Whatever is stored: only mapped folders sync.
            all: false,
            mappings: mappings(&db)?,
            exclude: exclusions(&db)?,
            home,
            home_name: meta::get(&db, meta::SYNC_CLAUDE_HOME_NAME)?,
            generation: state.sync_control.generation(),
            report,
            no_report_secs: state
                .sync_control
                .no_report_for(state.started_at, std::time::Instant::now())
                .as_secs(),
            last_change_at,
            stands,
            held: state.held.why().map(|held| held.says().to_string()),
            moved_on: crate::look::moved_on(&db)?,
            notice: None,
            carried: None,
            let_go: None,
            let_go_alone: None,
            let_go_versions: None,
            reading: None,
            not_let_go: None,
            let_go_discarded: None,
            let_go_stopped: None,
            still_held: None,
            still_held_stopped: None,
        };
        let notices = cordelia_storage::first_start::notices(&db)?;
        let last_dir = meta::get(&db, meta::SYNC_CLAUDE_LAST_DIR)?;
        (status, notices, last_dir)
    };
    if !notices.is_empty() {
        // Asked against the Claude Code directory that is set, or, with
        // sync off, the one that turning sync on would use: the last one
        // kept, or the default (decision 2026-10-04 §10.1).
        let default = || {
            std::env::var("HOME")
                .map(|home| format!("{home}/.claude"))
                .ok()
        };
        let against_dir = status
            .dir
            .clone()
            .or(last_dir)
            .or_else(default)
            .unwrap_or_default();
        let home = home_dir().ok();
        let against = crate::found::Against {
            claude_dir: std::path::Path::new(&against_dir),
            home: home.as_deref(),
            mappings: &status.mappings,
        };
        status.notice = crate::found::notice_shown(&notices, &against, &crate::found::Remembered);
    }
    Ok(status)
}

/// A person has seen the notice of what stopped syncing (decision
/// 2026-10-04 §10.1): it is taken away, every record of it. This is the
/// one request that takes it away. It counts no change of settings: a
/// cycle that is running goes on, and what a report was made under is
/// still what stands. With no notice stored it does nothing, and answers
/// as done.
pub async fn seen(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    {
        let db = state
            .db
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        if cordelia_storage::first_start::clear_notices(&db)? {
            tracing::info!("sync: the notice of what stopped syncing was seen, and is put away");
        }
    }
    Ok(HttpResponse::Ok().json(status(&state)?))
}

/// What is stored as the scope: that only mapped folders sync. There is
/// no other scope (decision 2026-10-04 §10.1).
const SCOPE_OFF: &str = "off";

/// What a request that asks for everything found to sync is told. The
/// command line says the same before it sends anything.
pub const EVERYTHING_FOUND_IS_REFUSED: &str = "syncing everything found is no more: only mapped \
    folders sync, and nothing was changed. `cordelia sync status` lists what is found on this \
    machine, with the command that maps each folder (`cordelia sync map <folder>`).";

/// The stored scope is off whenever sync is on (decision 2026-10-04
/// §10.1): a node writes it so when it starts with sync on, whatever was
/// stored, and where nothing was. Returns whether it wrote. With sync off
/// nothing is written: the request that turns sync on writes it
/// ([`set_claude`]).
///
/// Nothing reads the scope to say what syncs. It is written for what
/// reads the settings as an earlier version did: there, a directory that
/// is set with no scope stored is a scope that is on.
///
/// A node whose first start on this version is still to be made does not
/// ask this: the step of the first start reads the scope as it is
/// stored, and writes it off itself.
pub fn scope_off_at_start(state: &AppState) -> Result<bool, ApiError> {
    let db = state
        .db
        .lock()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    if meta::get(&db, meta::SYNC_CLAUDE_DIR)?.is_none() {
        return Ok(false);
    }
    let stored = meta::get(&db, meta::SYNC_CLAUDE_ALL)?;
    if stored.as_deref() == Some(SCOPE_OFF) {
        return Ok(false);
    }
    meta::set(&db, meta::SYNC_CLAUDE_ALL, SCOPE_OFF)?;
    tracing::warn!(
        "sync: what was stored said that everything found on this machine syncs. Only mapped \
         folders sync: `cordelia sync status` lists what is found, with the command that maps \
         each"
    );
    Ok(true)
}

/// A name a folder can sync under: `~` for home memory, or 1 to 200
/// characters of lower-case letters, digits and `. _ - / ~ + % @`. That
/// covers a normalised git remote (`github.com/owner/repo`,
/// `git.sr.ht/~sam/proj`) and a label (`my-workspace`). No empty or
/// dot-only segments, so a name can never be read as a path elsewhere, and
/// nothing a shell or a terminal would act on. It does not start with `-`,
/// which a command line reads as an option, or with `~`, which a shell
/// reads as a path.
pub fn valid_sync_name(name: &str) -> bool {
    if name == HOME_NAME {
        return true;
    }
    !name.is_empty()
        && name.len() <= 200
        && !name.starts_with(['-', '~'])
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-/~+%@".contains(&b))
        && name
            .split('/')
            .all(|segment| !segment.is_empty() && segment.bytes().any(|b| b != b'.'))
}

/// An absolute path with one spelling: no `..`, no doubled or trailing
/// separators. `None` if it is not such a path.
pub(crate) fn clean_path(path: &str) -> Option<String> {
    use std::path::Component;
    let path = std::path::Path::new(path);
    let plain = path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::RootDir));
    plain.then(|| {
        path.components()
            .collect::<std::path::PathBuf>()
            .display()
            .to_string()
    })
}

/// An exclusion as it is stored, for a panel that still sends a list of
/// them: a folder (an absolute path), or a project name or prefix in its
/// one spelling (`cordelia_core::sync_name::tidy`). `None` for what is
/// neither: a name of which nothing is left, or a path with `..` in it.
/// Nothing reads the list to say what syncs (decision 2026-10-04 §10.1).
///
/// A folder keeps a space at the end of its name: a folder's name can end
/// in one. Its separators are tidied. So a list that is sent back as it
/// was stored is stored as it was.
fn clean_exclusion(entry: &str) -> Option<String> {
    if entry.starts_with('/') {
        return clean_path(entry);
    }
    let entry = entry.trim();
    if entry.starts_with('/') {
        return clean_path(entry);
    }
    let name = cordelia_core::sync_name::tidy(entry);
    (!name.is_empty()).then_some(name)
}

// ── POST /api/v1/sync/claude ───────────────────────────────────────

/// The memory folder the adapter syncs for a mapped `folder` under the
/// Claude Code directory `claude_dir`, spelled as the adapter spells it
/// where it records what a folder agreed with its channel.
pub fn memory_folder(claude_dir: &str, folder: &str) -> String {
    std::path::Path::new(claude_dir)
        .join("projects")
        .join(cordelia_core::claude_code::folder_name(folder))
        .join("memory")
        .display()
        .to_string()
}

/// Forget what every folder that is not mapped agreed with its channel,
/// under the Claude Code directory `claude_dir`.
///
/// A folder that stops syncing starts afresh if it syncs again: what it
/// lost in between is fetched back, never sent as deletes (decision
/// 2026-09-30 §4.5). Only a mapped folder syncs (decision 2026-10-04
/// §10.1), so every folder that is not mapped forgets: the folder of a
/// mapping just removed among them.
///
/// It is done here, by the handler and under the lock it holds, so that it
/// is true by the time the command answers.
fn forget_what_is_not_mapped(db: &rusqlite::Connection, claude_dir: &str) -> Result<(), ApiError> {
    let mapped: Vec<String> = mappings(db)?
        .iter()
        .map(|m| memory_folder(claude_dir, &m.folder))
        .collect();
    let forgotten = sync_state::forget_folders_except(db, &mapped)?;
    if forgotten > 0 {
        tracing::info!(
            files = forgotten,
            "sync: folders that are not mapped forgot what they had agreed"
        );
    }
    Ok(())
}

/// What `POST /api/v1/sync/claude` does, with the database lock held.
/// `home` is the home directory, when it is known.
///
/// A setting that is not given keeps its stored value, so running it again
/// changes nothing. Only declared mappings sync (decision 2026-10-04
/// §10.1):
///
/// - **A request that turns sync on, or leaves it on, and asks for
///   everything found (`all: true`) is refused whole.** Nothing is
///   written, and no change is counted, whatever else it carries. A
///   request that turns sync off is never refused for it.
/// - `all: false` is taken: it is the only scope there is, and the
///   stored scope is written off whatever is asked.
/// - `reset` puts the Claude Code directory back to its default, and
///   touches nothing else: declared mappings stay, and so do the stored
///   list of exclusions and the switch for home memory.
/// - An `exclude` list and the `home` switch are stored as they were,
///   for a panel that still sends them: nothing reads either to say what
///   syncs. Turning home memory off also unmaps the home directory,
///   whatever name it has.
pub fn set_claude(
    control: &SyncControl,
    db: &rusqlite::Connection,
    body: &SyncClaudeRequest,
    home: Option<&std::path::Path>,
) -> Result<(), ApiError> {
    if body.enabled {
        // Refused before anything is read or written, and before the
        // change is counted: a cycle that is running goes on.
        if body.all == Some(true) {
            return Err(ApiError::BadRequest(EVERYTHING_FOUND_IS_REFUSED.into()));
        }
        let stored = meta::get(db, meta::SYNC_CLAUDE_DIR)?;
        // The directory in use, or the one in use when sync was last on.
        let remembered = match &stored {
            Some(dir) => Some(dir.clone()),
            None => meta::get(db, meta::SYNC_CLAUDE_LAST_DIR)?,
        };
        let was = remembered.clone();
        let dir = match (&body.dir, remembered) {
            (Some(d), _) => d.clone(),
            (None, Some(d)) if !body.reset => d,
            _ => std::env::var("HOME")
                .map(|h| format!("{h}/.claude"))
                .map_err(|_| ApiError::BadRequest("HOME is not set; pass dir".into()))?,
        };
        if !std::path::Path::new(&dir).is_absolute() {
            return Err(ApiError::BadRequest("dir must be an absolute path".into()));
        }
        // Turning home memory off unmaps the home directory, so it has to
        // be known. Checked before anything is written: a request that
        // cannot be carried out changes nothing.
        if body.home == Some(false) && home.is_none() {
            return Err(ApiError::BadRequest("HOME is not set".into()));
        }

        // Counted before anything is written (see `SyncControl::changed`).
        control.changed(db);

        // The stored scope is off whenever sync is on (decision
        // 2026-10-04 §10.1): it is written so at every request that
        // turns sync on or leaves it on, whatever was stored. It is
        // written before the directory that turns sync on, and the key
        // is never removed: an earlier version reads a directory that is
        // set, with no scope stored, as a scope that is on.
        meta::set(db, meta::SYNC_CLAUDE_ALL, SCOPE_OFF)?;
        // Whether a folder stopped syncing by this request: the home
        // directory's, where home memory is turned off and it was mapped.
        // Nothing else that a request can set says what syncs.
        let mut unmapped = false;
        let excluded_before = exclusions(db)?;
        let home_was = meta::get(db, meta::SYNC_CLAUDE_HOME)?.is_none_or(|v| v != "off");

        // Stored as before, for a panel that still sends one: nothing
        // reads the list to say what syncs.
        if let Some(exclude) = &body.exclude {
            let cleaned: Vec<String> = exclude.iter().filter_map(|e| clean_exclusion(e)).collect();
            if cleaned != excluded_before {
                tracing::info!(exclude = ?cleaned, "sync: exclusions changed");
            }
            store_exclusions(db, &cleaned)?;
        }
        if let Some(on) = body.home {
            if on != home_was {
                tracing::info!(home = on, "sync: home memory setting changed");
            }
            if on {
                meta::remove(db, meta::SYNC_CLAUDE_HOME)?;
            } else {
                // Off means off: the home directory is not mapped,
                // whatever name it was mapped under. Its folder then
                // forgets with the rest that is not mapped, below.
                meta::set(db, meta::SYNC_CLAUDE_HOME, "off")?;
                let mut list = mappings(db)?;
                if let Some(home) = home
                    && let Some(mapping) = unmap_home(&mut list, home)
                {
                    store_mappings(db, &list)?;
                    unmapped = true;
                    tracing::info!(name = %mapping.name, "sync: home memory unmapped");
                }
            }
        }

        // A folder that is mapped no longer starts afresh if it is mapped
        // again. When the Claude Code directory changes, every folder
        // does. The directory is the string that is stored: the adapter
        // is started again for a new spelling of the same path, and
        // records what its folders agree under that.
        //
        // Sync turned off and on again is a node stopped and started: a
        // folder that stays mapped keeps what it agreed, so what was
        // edited here meanwhile is sent, and this device's own last
        // version is not taken for the other side of a conflict. Turned
        // on at another directory than the one it was last on, or with
        // none remembered, every folder forgets; at the same one, only
        // what is not mapped, such as a folder unmapped while it was off.
        let dir_changed = was.as_deref().is_none_or(|was| was != dir);
        if dir_changed {
            let forgotten = sync_state::forget_folders_except(db, &[])?;
            if forgotten > 0 {
                tracing::info!(
                    files = forgotten,
                    "sync: every folder forgot what it had agreed"
                );
            }
        } else if unmapped || stored.is_none() {
            forget_what_is_not_mapped(db, &dir)?;
        }

        if stored.as_deref() != Some(dir.as_str()) {
            tracing::info!(%dir, "sync: Claude Code directory set");
        }
        meta::set(db, meta::SYNC_CLAUDE_DIR, &dir)?;
        meta::remove(db, meta::SYNC_CLAUDE_LAST_DIR)?;
    } else {
        control.changed(db);
        if let Some(dir) = meta::get(db, meta::SYNC_CLAUDE_DIR)? {
            meta::set(db, meta::SYNC_CLAUDE_LAST_DIR, &dir)?;
        }
        meta::remove(db, meta::SYNC_CLAUDE_DIR)?;
        // Nothing syncs now. A mapped folder keeps what it agreed, as it
        // does while the node is stopped: turned on again, it goes on
        // from there.
        tracing::info!("sync: turned off");
    }
    meta::remove(db, meta::SYNC_CLAUDE_REPORT)?;
    Ok(())
}

/// The names that this device's folders are mapped to.
fn mapped_names(db: &rusqlite::Connection) -> Result<Vec<String>, ApiError> {
    Ok(mappings(db)?.into_iter().map(|m| m.name).collect())
}

/// What this device says of the names it syncs follows a change of
/// settings (decision 2026-10-04 §2.2, §16), under the hold of the
/// database's lock that the change was made under. `before` is the names
/// its folders were mapped to before the change.
///
/// - A name that was mapped and is mapped no longer: the device says no
///   longer that it syncs it, and holds it no more
///   ([`crate::names::stop`]). What it kept of which relays had handed
///   the name's channel goes too: mapped again, the channel is fetched
///   before the folder's first cycle there (§6).
/// - **But a name that a carry or a recovery holds is not let go with a
///   folder that was mapped to it** ([`crate::names::carried`], decision
///   2026-10-04 §16): what was brought in there, and no relay was sent,
///   is nowhere else in the generation applied. The name is then held as
///   it was before the folder was mapped, with everything its channel
///   holds. **Nor is a name that a carry brought versions into while the
///   folder was mapped** ([`crate::names::brought_in`], decision
///   2026-10-17 §4.3): it is held from then as a carry holds a name. Such
///   a name is let go by its name, once a relay holds each version of it
///   that this device signed ([`let_go_of_a_carried_name`]).
/// - With sync on, it holds each name that is mapped, and says that it
///   syncs it ([`crate::names::hold_mapped`]).
/// - With sync off, it says of no name that it syncs it
///   ([`crate::names::unsay_all`]). It goes on holding the names its
///   folders are mapped to.
///
/// A device that follows no phrase, or has stopped, has nothing to say
/// and no name to hold: nothing is done, and nothing is refused. Where
/// something was written, the node is woken to send it.
pub fn names_follow(state: &AppState, db: &rusqlite::Connection, before: &[String]) {
    let now = chrono::Utc::now().timestamp();
    let done = || -> Result<(), crate::person::PersonError> {
        let mapped = mapped_names(db).unwrap_or_default();
        // A name that a carry or a recovery holds stays held when its
        // folder is unmapped; and so does one that a carry brought
        // versions into while the folder was mapped (decision 2026-10-17
        // §4.3), which is held from now as a carry holds a name.
        let carried = crate::names::carried(db)?;
        let brought_in = crate::names::brought_in(db)?;
        let let_go = |name: &&String| !mapped.contains(name) && !carried.contains(*name);
        for name in before.iter().filter(let_go) {
            if brought_in.contains(name) {
                crate::names::held_after_its_folder(db, &state.identity, name, now)?;
                continue;
            }
            if let Some(channel) = crate::names::stop(db, &state.identity, name, now)? {
                state.own_channels.forget_fetched(&channel);
            }
        }
        match meta::get(db, meta::SYNC_CLAUDE_DIR)?.is_some() {
            true => crate::names::hold_mapped(db, &state.identity, now)?,
            false => crate::names::unsay_all(db, &state.identity, now)?,
        };
        Ok(())
    };
    // The setting stands whatever becomes of this: the next cycle says
    // what is still to be said, and takes back what is not.
    if let Err(error) = done() {
        tracing::warn!(%error, "sync: could not say which names this device syncs");
    }
    state.own_channels.written();
}

/// Turn sync off on a node whose first start on this version is not done
/// (decision 2026-10-04 §10.1): a request that turns sync off is never
/// refused. The directory goes, and is kept as the last one.
///
/// Nothing else is touched, since the step is still to read it: the
/// stored report, which a notice of what stopped is made from, and what
/// folders had agreed, which the step forgets. A scope that was on by
/// being absent with a directory set is written down as on first, so
/// that the step still finds it so once the directory is gone.
fn turn_off_while_held(control: &SyncControl, db: &rusqlite::Connection) -> Result<(), ApiError> {
    control.changed(db);
    if let Some(dir) = meta::get(db, meta::SYNC_CLAUDE_DIR)? {
        if meta::get(db, meta::SYNC_CLAUDE_ALL)?.is_none() {
            meta::set(db, meta::SYNC_CLAUDE_ALL, "on")?;
        }
        meta::set(db, meta::SYNC_CLAUDE_LAST_DIR, &dir)?;
    }
    meta::remove(db, meta::SYNC_CLAUDE_DIR)?;
    tracing::info!("sync: turned off, while the first start on this version is not done");
    Ok(())
}

/// Turn the adapter on or off, and set what it syncs (see [`set_claude`]).
///
/// A node that is held up takes this only where it turns sync off
/// ([`turn_off_while_held`]), and refuses the rest with why it is held
/// up.
pub async fn claude(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SyncClaudeRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    if let Some(held) = state.held.why() {
        if body.enabled {
            return Err(ApiError::Held(held.says().to_string()));
        }
        {
            let db = state
                .db
                .lock()
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            turn_off_while_held(&state.sync_control, &db)?;
        }
        return Ok(HttpResponse::Ok().json(status(&state)?));
    }
    let home = home_dir().ok();
    {
        let db = state
            .db
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let before = mapped_names(&db)?;
        set_claude(&state.sync_control, &db, &body, home.as_deref())?;
        names_follow(&state, &db, &before);
    }
    Ok(HttpResponse::Ok().json(status(&state)?))
}

// ── POST /api/v1/sync/map ──────────────────────────────────────────

/// A mapping as it is stored, or why it is refused: when it could sync
/// more than was meant (the home directory unless asked for, a folder
/// outside the home directory), or cannot be told apart from another (a
/// second name for a folder, a second folder for a name, two folders that
/// Claude Code keeps in one, the name of home memory for a folder that is
/// not the home directory). The home directory takes any name. `Ok(None)`
/// if exactly this mapping is already declared, whatever else is asked.
///
/// A folder that is mapped under another name is refused for that last, with
/// the advice to unmap it: unmapping is not free (the folder stops syncing,
/// forgets what it agreed and is excluded), so a request that would be
/// refused anyway is refused for its own reason. `cordelia sync map` asks
/// this of the mappings without the folder's own, to tell the two apart.
pub fn check_mapping(
    request: &SyncMapRequest,
    home_dir: &std::path::Path,
    existing: &[SyncMapping],
) -> Result<Option<SyncMapping>, String> {
    use cordelia_core::claude_code::{FOLDER_NAME_MAX, folder_name};

    // One spelling per folder, so the same folder is never mapped twice.
    let Some(folder) = clean_path(&request.folder) else {
        return Err("the folder must be an absolute path without `..`".into());
    };
    let path = std::path::Path::new(&folder);
    let claude_folder = folder_name(&folder);
    if claude_folder.len() > FOLDER_NAME_MAX {
        return Err(format!(
            "paths longer than {FOLDER_NAME_MAX} characters cannot be mapped yet"
        ));
    }

    if !path.starts_with(home_dir) {
        return Err(format!("{folder} is outside the home directory"));
    }
    let name = request.name.trim();
    // Declaring a mapping again changes nothing, and is never refused: not
    // for a flag left out, nor for a name that could not be given today.
    let mapped = existing.iter().find(|m| m.folder == folder);
    if mapped.is_some_and(|m| m.name == name) {
        return Ok(None);
    }

    let is_home = path == home_dir;
    if is_home && !request.home {
        return Err("that is the home directory: map it with --home to sync home memory".into());
    }
    if request.home && !is_home {
        return Err("--home maps the home directory itself".into());
    }
    if !valid_sync_name(name) {
        return Err(format!(
            "{name:?} is not a usable name: use lower-case letters, digits and . _ - / ~ + % @, \
             and do not start it with - or ~"
        ));
    }
    // A name has its channel by its one spelling (decision 2026-10-04
    // §2.2): another spelling would be another channel, and has none.
    let tidy = cordelia_core::sync_name::tidy(name);
    if tidy != name {
        return Err(format!(
            "{name:?} is not a name in its one spelling: map the folder as {tidy:?}"
        ));
    }
    if name == HOME_NAME && !is_home {
        return Err(format!(
            "{name:?} is the name of home memory, which every device maps from its home \
             directory: give this folder another name"
        ));
    }

    if let Some(mapped) = existing.iter().find(|m| m.name == name) {
        return Err(format!(
            "{name:?} is already mapped from {}: one folder per name on a device",
            mapped.folder
        ));
    }
    // Claude Code names its folder after the path with every other
    // character turned into a dash, so two paths can share one.
    if let Some(mapped) = existing
        .iter()
        .find(|m| m.folder != folder && folder_name(&m.folder) == claude_folder)
    {
        return Err(format!(
            "Claude Code keeps {folder} and {} in one folder, and that one is mapped to {:?}",
            mapped.folder, mapped.name
        ));
    }
    if let Some(mapped) = mapped {
        return Err(format!(
            "{folder} is already mapped to {:?}: unmap it first",
            mapped.name
        ));
    }
    Ok(Some(SyncMapping {
        folder,
        name: name.to_string(),
    }))
}

/// Whether `mapping` is the one that syncs home memory: the mapping of the
/// home directory, whatever its name.
fn is_home_mapping(mapping: &SyncMapping, home_dir: &std::path::Path) -> bool {
    std::path::Path::new(&mapping.folder) == home_dir
}

/// Take the mapping that syncs home memory out of `list`, and return it,
/// if there was one.
fn unmap_home(list: &mut Vec<SyncMapping>, home_dir: &std::path::Path) -> Option<SyncMapping> {
    let at = list.iter().position(|m| is_home_mapping(m, home_dir))?;
    Some(list.remove(at))
}

/// The home directory as Claude Code sees it: a real path.
fn home_dir() -> Result<std::path::PathBuf, ApiError> {
    let home = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .map_err(|_| ApiError::BadRequest("HOME is not set".into()))?;
    Ok(home.canonicalize().unwrap_or(home))
}

/// What `POST /api/v1/sync/map` does, for a caller that holds the
/// database's lock throughout: declare that Claude's memory for a folder
/// syncs under a name ([`add_mapping_looked`]), after the check of what
/// was found for the folder's directory ([`map_asked`], [`map_looked`]).
///
/// The node's own route asks the disk and git with the lock let go
/// ([`map`]). This is for a caller that has no other holder to keep
/// waiting.
pub fn add_mapping(
    control: &SyncControl,
    db: &rusqlite::Connection,
    body: &SyncMapRequest,
    home_dir: &std::path::Path,
) -> Result<(), ApiError> {
    let asked = map_asked(control, db, body, home_dir)?;
    let looked = asked.as_ref().map(|asked| map_looked(asked, home_dir));
    add_mapping_looked(control, db, body, home_dir, looked.as_ref())
}

/// Declare that Claude's memory for a folder syncs under a name, with the
/// database lock held. `looked` is what the check of what was found said
/// for this mapping ([`map_looked`]), where one was made.
///
/// The folder is taken as given: the adapter syncs the Claude Code folder
/// named after it and no other. (Claude Code keeps one memory per git
/// repository, under its main working tree; `cordelia sync map` resolves
/// a folder to that before calling this.) Mapping the home directory,
/// under any name, turns the home setting on, and that name is the one it
/// is put back under after home memory has been turned off.
///
/// **The folder that a mapping adds forgets what it had agreed** (decision
/// 2026-10-04 §10.1): whatever an earlier version, or a cycle that was
/// stopped, left of it. So a folder that is mapped always merges: it
/// meets its channel as on any first sync, and nothing that it lost while
/// it did not sync is sent as a delete. Mapping what is already mapped
/// adds nothing, and forgets nothing.
///
/// **A mapping is added only with its check, made under the settings as
/// they stand.** The check is of this folder, under this Claude Code
/// directory, at this count of settings commands: where a setting has
/// changed since it was made, or none was made, nothing is mapped, and
/// the request says to run it again.
pub fn add_mapping_looked(
    control: &SyncControl,
    db: &rusqlite::Connection,
    body: &SyncMapRequest,
    home_dir: &std::path::Path,
    looked: Option<&MapLooked>,
) -> Result<(), ApiError> {
    let Some(claude_dir) = meta::get(db, meta::SYNC_CLAUDE_DIR)? else {
        return Err(ApiError::BadRequest(
            "sync is off: turn it on with `cordelia sync claude` first".into(),
        ));
    };
    let mut list = mappings(db)?;
    let checked = check_mapping(body, home_dir, &list).map_err(ApiError::BadRequest)?;
    if let Some(mapping) = &checked {
        let of_this = |looked: &&MapLooked| {
            looked.generation == control.generation_under(db)
                && looked.claude_dir == claude_dir
                && looked.folder == mapping.folder
        };
        match looked.filter(of_this) {
            Some(looked) => {
                if let Some(why) = &looked.refused {
                    return Err(ApiError::BadRequest(why.clone()));
                }
            }
            None => return Err(ApiError::BadRequest(SETTINGS_CHANGED_UNDER_MAP.into())),
        }
    }
    control.changed(db);
    if let Some(mapping) = checked {
        tracing::info!(folder = %mapping.folder, name = %mapping.name, "sync: mapping added");
        let forgotten =
            sync_state::forget_folder(db, &memory_folder(&claude_dir, &mapping.folder))?;
        if forgotten > 0 {
            tracing::info!(
                files = forgotten,
                "sync: the folder that is mapped forgot what it had agreed"
            );
        }
        if is_home_mapping(&mapping, home_dir) {
            meta::remove(db, meta::SYNC_CLAUDE_HOME)?;
            meta::set(db, meta::SYNC_CLAUDE_HOME_NAME, &mapping.name)?;
        }
        list.push(mapping);
        store_mappings(db, &list)?;
        meta::remove(db, meta::SYNC_CLAUDE_REPORT)?;
    }
    Ok(())
}

/// What a mapping is refused with where a setting changed between its
/// check and the moment it would be stored.
pub const SETTINGS_CHANGED_UNDER_MAP: &str = "the sync settings changed while this mapping was \
    being checked: nothing was mapped. Run it again.";

/// The folders that were found and are not mapped, as the last stored
/// report lists them, and the folders that a stored notice names: each as
/// Claude Code's folder, its directory, and the name it has. A folder
/// with no directory is left out. Where a notice names a folder again,
/// the later directory and name stand.
fn found_and_named(
    db: &rusqlite::Connection,
) -> Result<Vec<(String, String, Option<String>)>, ApiError> {
    let mut out = Vec::new();
    let report: Option<serde_json::Value> =
        meta::get(db, meta::SYNC_CLAUDE_REPORT)?.and_then(|r| serde_json::from_str(&r).ok());
    let text = |value: &serde_json::Value| value.as_str().map(str::to_string);
    for entry in report
        .iter()
        .flat_map(|r| r["unmapped"].as_array())
        .flatten()
    {
        // Its directory is under `cwd` where `map` would sync the folder,
        // and under `directory` where it would not.
        let directory = text(&entry["cwd"]).or_else(|| text(&entry["directory"]));
        if let (Some(folder), Some(directory)) = (text(&entry["folder"]), directory) {
            out.push((folder, directory, text(&entry["name"])));
        }
    }
    for named in crate::found::named_in(&cordelia_storage::first_start::notices(db)?) {
        if let Some(directory) = named.cwd {
            out.push((named.folder, directory, named.name));
        }
    }
    Ok(out)
}

/// What the check of a mapping goes by, as it is read with the database's
/// lock held ([`map_asked`]): everything that is then asked of the disk
/// and of git with the lock let go ([`map_looked`]).
#[derive(Debug, Clone)]
pub struct MapAsked {
    /// The count of settings commands that it was read under.
    generation: u64,
    /// The Claude Code directory that is set.
    claude_dir: String,
    /// The mapping that would be stored.
    mapping: SyncMapping,
    /// The mappings that are declared.
    mappings: Vec<SyncMapping>,
    /// What was found, and what a notice names ([`found_and_named`]).
    entries: Vec<(String, String, Option<String>)>,
    /// Whether a report of a cycle is stored: what was found is read
    /// from it. Where none is, the node looks itself.
    report_stored: bool,
}

/// What the check of a mapping said ([`map_looked`]): why it is refused,
/// where it is, for one folder under one Claude Code directory, at one
/// count of settings commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapLooked {
    generation: u64,
    claude_dir: String,
    folder: String,
    /// Why the mapping is refused, where it would sync another folder
    /// than one that was found for its directory.
    pub refused: Option<String>,
}

/// Read what the check of the mapping that `body` asks for goes by, with
/// the database's lock held (decision 2026-10-04 §10.1). `None` where
/// there is nothing to check: sync is off, the request is refused for a
/// reason of its own, or it declares what is declared already. Whoever
/// stores the mapping says which ([`add_mapping_looked`]).
pub fn map_asked(
    control: &SyncControl,
    db: &rusqlite::Connection,
    body: &SyncMapRequest,
    home_dir: &std::path::Path,
) -> Result<Option<MapAsked>, ApiError> {
    let Some(claude_dir) = meta::get(db, meta::SYNC_CLAUDE_DIR)? else {
        return Ok(None);
    };
    let mappings = mappings(db)?;
    let Ok(Some(mapping)) = check_mapping(body, home_dir, &mappings) else {
        return Ok(None);
    };
    Ok(Some(MapAsked {
        generation: control.generation_under(db),
        claude_dir,
        mapping,
        mappings,
        entries: found_and_named(db)?,
        report_stored: meta::get(db, meta::SYNC_CLAUDE_REPORT)?.is_some(),
    }))
}

/// Why the mapping that was asked for is refused, where it would sync
/// another folder than one that was found, or that a notice names, with
/// the directory it gives (decision 2026-10-04 §10.1): `map` checks
/// whenever it is run, however the request was come by
/// ([`crate::found::in_the_way`]). The reason is the one that stands in
/// the place of a command for that folder, as the one function gives it.
///
/// **It asks the disk and git, and is called with the database's lock let
/// go:** git may take its time, and nothing else waits on it then.
///
/// **Where no report of a cycle is stored, it looks at what is found for
/// the directory itself** ([`crate::found::found_for`]): a request that
/// changes a setting removes the report, and until the next cycle stores
/// one there would be nothing to check against. A command waits for a
/// report; a panel does not.
pub fn map_looked(asked: &MapAsked, home_dir: &std::path::Path) -> MapLooked {
    use crate::found;
    use std::path::Path;

    let claude_dir = Path::new(&asked.claude_dir);
    let given = Path::new(&asked.mapping.folder);
    let refused = || -> Option<String> {
        let would_sync = found::claude_folder(claude_dir, given)?;
        let to_map = found::ToMap {
            given,
            would_sync: &would_sync,
            claude_dir,
        };
        // What was found is read from the last cycle's report, which
        // every request that changes a setting removes. Where none is
        // stored, the node looks at what is found for this directory
        // itself, before it answers.
        let mut entries = asked.entries.clone();
        if !asked.report_stored {
            let looked = found::found_for(claude_dir, given, &found::ThisMachine);
            entries.extend(
                looked
                    .into_iter()
                    .map(|(folder, directory)| (folder, directory, None)),
            );
        }
        let entries = &entries;
        let pairs = entries
            .iter()
            .map(|(folder, directory, _)| (folder.as_str(), directory.as_str()));
        let (folder, recorded) = found::in_the_way(&to_map, pairs, &found::ThisMachine)?;
        let name = entries
            .iter()
            .find(|(of, directory, _)| of == folder && directory == recorded)
            .and_then(|(_, _, name)| name.as_deref());
        // The folder is asked with its directory as it was recorded:
        // where that is a link, the reason says so.
        let folder_asked = found::Asked {
            folder: Path::new(folder),
            directory: Some(Path::new(recorded)),
            name,
        };
        let against = found::Against {
            claude_dir,
            home: Some(home_dir),
            mappings: &asked.mappings,
        };
        let reason = match found::would_map(&folder_asked, &against, &found::ThisMachine) {
            found::Maps::No(why) => Some(why.says()),
            _ => None,
        };
        Some(found::map_refused(
            &to_map,
            folder,
            reason.as_deref(),
            &found::ThisMachine,
        ))
    };
    MapLooked {
        generation: asked.generation,
        claude_dir: asked.claude_dir.clone(),
        folder: asked.mapping.folder.clone(),
        refused: refused(),
    }
}

/// How many times `map` reads, looks and comes back to store a mapping
/// before it gives up: each time a setting changed while it looked.
const MAP_TRIES: usize = 3;

/// Declare that Claude's memory for a folder syncs under a name (see
/// [`add_mapping_looked`]).
///
/// **The disk and git are asked first, and then the database's lock is
/// taken** (decision 2026-10-04 §10.1): what the check goes by is read
/// under a short hold of the lock ([`map_asked`]), the check is made with
/// the lock let go ([`map_looked`]), and the mapping is stored under a
/// second hold, where no setting has changed in between. Where one has,
/// the check is made again, a few times; and then the request is refused,
/// with nothing mapped.
///
/// **A device that comes to sync a name carries it first** (decision
/// 2026-10-04 §7.3). Where the mapping has the device hold a name that
/// it did not hold, and it still holds the secret of a generation that
/// it left, the name's channel in those generations is read at the
/// relays before this answers, and what keys that count signed there is
/// carried, where the new channel holds nothing for the name
/// ([`crate::carrying::carry_name`]). The folder's first cycle waits for
/// that ([`crate::state::OwnChannels::carrying`]), so that what it
/// publishes is written over what was carried. The answer says what was
/// carried.
pub async fn map(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SyncMapRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    let home_dir = home_dir()?;
    let lock = || {
        state
            .db
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))
    };
    let mut carries_first: Vec<(String, [u8; 32])> = Vec::new();
    for tried in 1..=MAP_TRIES {
        let asked = map_asked(&state.sync_control, &*lock()?, &body, &home_dir)?;
        let looked = asked.as_ref().map(|asked| map_looked(asked, &home_dir));
        let db = lock()?;
        let moved =
            |looked: &MapLooked| looked.generation != state.sync_control.generation_under(&db);
        if looked.as_ref().is_some_and(moved) && tried < MAP_TRIES {
            continue;
        }
        let before = mapped_names(&db)?;
        add_mapping_looked(&state.sync_control, &db, &body, &home_dir, looked.as_ref())?;
        names_follow(&state, &db, &before);
        carries_first = carries_first_for(&state, &db, &before);
        break;
    }
    // The carry, with the lock let go: it waits on the relays.
    let mut carried = None;
    for (name, channel) in carries_first {
        let done = crate::carrying::carry_name(&state, &name, true).await;
        state.own_channels.carried(&channel);
        match done {
            Ok(done) => carried = Some(done.says(&name)),
            Err(error) => {
                tracing::warn!(%error, "sync: the name that was mapped could not be carried")
            }
        }
    }
    let mut status = status(&state)?;
    status.carried = carried;
    Ok(HttpResponse::Ok().json(status))
}

/// The names that a mapping has this device hold anew, each with the ID
/// of its channel, where the device carries a name before its folder's
/// first cycle (decision 2026-10-04 §7.3): it has applied a statement,
/// and still holds the secret of a generation that it left. `before` is
/// the names its folders were mapped to before the mapping.
///
/// The folder's first cycle is held back for each from here on
/// ([`crate::state::OwnChannels::carrying`]), under the hold of the
/// database's lock that the mapping was stored under: no cycle runs
/// between the two.
fn carries_first_for(
    state: &AppState,
    db: &rusqlite::Connection,
    before: &[String],
) -> Vec<(String, [u8; 32])> {
    use cordelia_storage::person as held_rows;
    let applied = matches!(
        crate::at_relays::stands(db),
        Ok(crate::at_relays::Stands::Applied)
    );
    let left_one = held_rows::secrets(db)
        .is_ok_and(|secrets| secrets.iter().any(|secret| secret.left_at.is_some()));
    if !applied || !left_one {
        return Vec::new();
    }
    let mut anew = Vec::new();
    for name in mapped_names(db).unwrap_or_default() {
        if before.contains(&name) {
            continue;
        }
        if let Ok(Some(channel)) = held_rows::channel_of_name(db, &name) {
            state
                .own_channels
                .carrying(&channel, std::time::Instant::now());
            anew.push((name, channel));
        }
    }
    anew
}

// ── POST /api/v1/sync/unmap ────────────────────────────────────────

/// What `POST /api/v1/sync/unmap` does, with the database lock held: stop
/// syncing a mapped folder, given as the folder or as its name.
///
/// Its files stay where they are, and the name stays with this person's
/// other devices. What the folder had agreed with its channel is forgotten,
/// so that mapped again it merges, and nothing it lost in between is sent
/// as a delete ([`forget_what_is_not_mapped`]). Nothing else is written
/// of it: a folder that is not mapped does not sync, and needs no
/// exclusion to stay out (decision 2026-10-04 §10.1).
pub fn remove_mapping(
    control: &SyncControl,
    db: &rusqlite::Connection,
    body: &SyncUnmapRequest,
) -> Result<(), ApiError> {
    let list = mappings(db)?;
    let (gone, kept): (Vec<SyncMapping>, Vec<SyncMapping>) = list
        .into_iter()
        .partition(|m| m.folder == body.folder || m.name == body.folder);
    if gone.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "{} is not mapped on this device",
            body.folder
        )));
    }
    control.changed(db);
    for mapping in &gone {
        tracing::info!(folder = %mapping.folder, name = %mapping.name, "sync: mapping removed");
    }
    store_mappings(db, &kept)?;
    // The folder forgets, and so does whatever else is not mapped.
    if let Some(dir) = meta::get(db, meta::SYNC_CLAUDE_DIR)? {
        forget_what_is_not_mapped(db, &dir)?;
    }
    meta::remove(db, meta::SYNC_CLAUDE_REPORT)?;
    Ok(())
}

/// Let go of the name `name`, where this device holds it by a carry that
/// a person asked for, or by a recovery, with no folder mapped to it
/// ([`crate::names::carried`], decision 2026-10-04 §7.3): the device says
/// no longer that it syncs the name, and holds it no more, as for a name
/// whose folder is unmapped ([`crate::names::stop`]). What its store held
/// of the name's channel goes with it. Says whether the name was let go:
/// not where the device does not hold it so, and nothing is done then.
///
/// **On a device that sends, it is let go only by the read made before
/// it** (decision 2026-10-17 §4.2), the read named `read`, which found
/// `found` ([`crate::let_go::round`]); `None` on a device that has
/// stopped, which reads no relay. With a read, it is refused:
///
/// - where the node keeps the read no more
///   ([`crate::let_go::started_again_says`]);
/// - where the store has taken anything of the name's channel since the
///   read ended, or the name's channel is another (item 8,
///   [`crate::let_go::took_something_says`]): what would be let go is not
///   what the read asked about;
/// - where a folder is mapped to the name now: one was mapped while the
///   relays were read ([`crate::let_go::folder_mapped_says`]);
/// - where no relay held an entry of the name that this device signed
///   ([`crate::let_go::not_held_says`]): what a carry or a recovery
///   brought in here, and no relay holds, is nowhere else in the
///   generation applied.
///
/// A name that is let go ends the read it was bound to.
pub fn let_go_of_a_carried_name(
    state: &AppState,
    db: &rusqlite::Connection,
    name: &str,
    read: Option<(&crate::own_read::ReadId, &crate::let_go::Found)>,
) -> Result<bool, ApiError> {
    use crate::commands::refused;
    use crate::let_go as check;
    if !crate::names::carried(db).map_err(refused)?.contains(name) {
        return Ok(false);
    }
    if let Some((read, found)) = read {
        let reads = state.own_channels.reads();
        let kept = bound_to_its_read(state, db, name, read, found)?;
        if !found.each_held() {
            let said = state.own_channels.read();
            let now = chrono::Utc::now().timestamp();
            let relays = check::relays_say(db, &kept, found, &said, now).map_err(refused)?;
            return Err(ApiError::Conflict(check::not_held_says(
                name,
                found.not_held.len(),
                &relays,
            )));
        }
        reads.forget(read);
    }
    let now = chrono::Utc::now().timestamp();
    let held = crate::names::stop(db, &state.identity, name, now).map_err(refused)?;
    if let Some(channel) = held {
        state.own_channels.forget_fetched(&channel);
    }
    tracing::info!(%name, "sync: a name that was held by a carry, with no folder, is let go");
    state.own_channels.written();
    Ok(true)
}

/// The read named `read`, which found `found`, as the node keeps it,
/// where a let-go of `name` may still be bound to it (decision 2026-10-17
/// §4.2 item 8): refused where the node keeps the read no more
/// ([`crate::let_go::started_again_says`]); where the store has taken
/// anything of the name's channel since the read ended, or the name's
/// channel is another ([`crate::let_go::took_something_says`]); and where
/// a folder was mapped to the name since, which holds it now
/// ([`crate::let_go::folder_mapped_says`]).
fn bound_to_its_read(
    state: &AppState,
    db: &rusqlite::Connection,
    name: &str,
    read: &crate::own_read::ReadId,
    found: &crate::let_go::Found,
) -> Result<crate::own_read::OwnRead, ApiError> {
    use crate::let_go as check;
    let reads = state.own_channels.reads();
    let Some(kept) = reads.get(read, std::time::Instant::now()) else {
        return Err(ApiError::Conflict(check::started_again_says(name)));
    };
    let channel = cordelia_storage::person::channel_of_name(db, name)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let taken = cordelia_storage::at_relays::last_taken(db, &kept.channel)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    if channel != Some(kept.channel) || taken != found.taken {
        return Err(ApiError::Conflict(check::took_something_says(name)));
    }
    // The lock was let go while the relays were read: a folder that was
    // mapped to the name since holds it, and takes nothing into the store
    // until its first cycle.
    if crate::names::has_folder(db, name).map_err(crate::commands::refused)? {
        return Err(ApiError::Conflict(check::folder_mapped_says(name)));
    }
    Ok(kept)
}

/// Let go of `name`, a carried name, on the word `discard` (decision
/// 2026-10-17 §5.2, §1 properties 5, 8 and 9), with the entries of it
/// that no relay held in the read named `read`, or that the notes of a
/// device that has stopped say it sent to none ([`crate::let_go::noted`]).
/// `versions` is the number that the command said would go. Returns how
/// many went with it, or `None` where the device does not hold the name
/// by a carry, and nothing is done then.
///
/// **What is let go is what was shown, and nothing else.** Refused, with
/// [`crate::let_go::changed_says`], where the read no longer stands at
/// `now`, on the node's monotonic clock, for its age or because another
/// read of the name took its place ([`crate::own_read::OwnReads::gone`]);
/// where it has found nothing yet; where `versions` is not the number it
/// found; and where the store has taken anything of the name's channel
/// since it ended, or the name's channel is another. Where a folder was
/// mapped to the name since, which holds it now, it is refused with
/// [`crate::let_go::folder_mapped_says`]. A read that this
/// node never made, as after it was started again, is refused with
/// [`crate::let_go::started_again_says`]. `wall` is the time in seconds
/// that the name's word is taken back at: nothing of the word's time
/// turns on it.
pub fn discard_a_carried_name(
    state: &AppState,
    db: &rusqlite::Connection,
    name: &str,
    read: &crate::own_read::ReadId,
    versions: usize,
    now: std::time::Instant,
    wall: i64,
) -> Result<Option<usize>, ApiError> {
    use crate::commands::refused;
    use crate::let_go as check;
    if !crate::names::carried(db).map_err(refused)?.contains(name) {
        return Ok(None);
    }
    let reads = state.own_channels.reads();
    let changed = || ApiError::Conflict(check::changed_says(name));
    let Some(kept) = reads.get(read, now) else {
        return Err(match reads.gone(read, now) {
            true => changed(),
            false => ApiError::Conflict(check::started_again_says(name)),
        });
    };
    let Some(found) = &kept.found else {
        return Err(changed());
    };
    let channel = cordelia_storage::person::channel_of_name(db, name)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let taken = cordelia_storage::at_relays::last_taken(db, &kept.channel)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let bound = channel == Some(kept.channel) && taken == found.taken;
    if !bound || versions != found.not_held.len() {
        return Err(changed());
    }
    // A folder mapped to the name while the word was asked holds it now.
    if crate::names::has_folder(db, name).map_err(refused)? {
        return Err(ApiError::Conflict(check::folder_mapped_says(name)));
    }
    reads.forget(read);
    let held = crate::names::stop(db, &state.identity, name, wall).map_err(refused)?;
    if let Some(channel) = held {
        state.own_channels.forget_fetched(&channel);
    }
    tracing::info!(%name, versions, "sync: a carried name is let go on the word, with what no relay held");
    state.own_channels.written();
    Ok(Some(versions))
}

/// The name that a folder was mapped to before a change of settings,
/// where no folder is mapped to it now and the device holds it by a
/// carry or a recovery ([`crate::names::carried`], decision 2026-10-04
/// §16): the folder's unmapping left it held ([`names_follow`]). `before`
/// is the names that the device's folders were mapped to before. The
/// answer to the unmapping names it, so that the command says that the
/// name is still held, and what lets go of it. It decides nothing, and
/// where it cannot be read it says nothing.
fn still_held_by_a_carry(db: &rusqlite::Connection, before: &[String]) -> Option<String> {
    let mapped = mapped_names(db).ok()?;
    let carried = crate::names::carried(db).ok()?;
    let still_held = |name: &&String| !mapped.contains(name) && carried.contains(*name);
    before.iter().find(still_held).cloned()
}

/// Stop syncing a mapped folder (see [`remove_mapping`]). **Where no
/// folder is mapped so, a name that the device holds by a carry is let
/// go** ([`let_go_of_a_carried_name`]), and the answer says so: such a
/// name has no folder to unmap, and is held until a person says this.
/// **Where the folder was mapped to a name that a carry or a recovery
/// holds, the name is still held, and the answer says so**
/// ([`still_held_by_a_carry`]).
///
/// **On a device that sends, a carried name is let go only after a read
/// of its channel at the relays** (decision 2026-10-17 §4.2): the read
/// runs outside the database's lock, a round at each request. Where it
/// goes on, the answer carries `reading`, with the read's ID, which the
/// command sends back to ask for the next round. Where it has ended, the
/// lock is taken and the name is let go by what it found.
///
/// **Where an entry of the name is held by no relay, it is let go only on
/// the word `discard`** (decision 2026-10-17 §5.2): a command that asks at
/// a terminal says so (`asks`), and is answered with what it asks by
/// (`not_let_go`); any other is refused with the lines of §4.6. The word
/// comes back with the read's ID and the number found
/// ([`discard_a_carried_name`]). **A device that has stopped reads no
/// relay** (§4.4): where its own notes say that it sent a version of the
/// name to no relay, the same word is asked, bound to the count it took
/// from them ([`crate::let_go::noted`]); where they say none, the name
/// goes at once.
pub async fn unmap(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SyncUnmapRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    Ok(HttpResponse::Ok().json(unmapped(&state, &body).await?))
}

/// What [`unmap`] does once the request is let in, and its answer.
pub async fn unmapped(
    state: &AppState,
    body: &SyncUnmapRequest,
) -> Result<SyncStatusResponse, ApiError> {
    let status = |let_go: Option<String>, still_held: Option<String>| {
        let mut status = status(state)?;
        status.let_go = let_go;
        status.still_held = still_held;
        Ok::<_, ApiError>(status)
    };
    let name = &body.folder;
    let read = match body.read.as_deref() {
        None => None,
        Some(read) => Some(read_named(read)?),
    };
    if let Some(word) = &body.word {
        return discarded(state, name, word, read, body.versions);
    }
    if read.is_none() {
        let db = state
            .db
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let before = mapped_names(&db)?;
        match remove_mapping(&state.sync_control, &db, body) {
            Ok(()) => {
                names_follow(state, &db, &before);
                let still_held = still_held_by_a_carry(&db, &before);
                // A device that has stopped sends nothing more, and the
                // command says so (decision 2026-10-17 §4.6).
                let stopped = still_held.is_some().then(|| {
                    let stands = crate::at_relays::stands(&db);
                    !matches!(stands, Ok(crate::at_relays::Stands::Applied))
                });
                drop(db);
                let mut status = status(None, still_held)?;
                status.still_held_stopped = stopped;
                return Ok(status);
            }
            Err(not_mapped) => {
                use crate::commands::refused;
                if !crate::names::carried(&db).map_err(refused)?.contains(name) {
                    return Err(not_mapped);
                }
                // A device that has stopped reads no relay: its own notes
                // decide (decision 2026-10-17 §4.4).
                let stands = crate::at_relays::stands(&db).map_err(refused)?;
                if let crate::at_relays::Stands::Stopped(stopped) = stands {
                    let reads = state.own_channels.reads();
                    let now = std::time::Instant::now();
                    let noted = crate::let_go::noted(&db, &state.identity, reads, name, now)
                        .map_err(refused)?;
                    if let Some((read, found)) = noted {
                        let n = found.not_held.len();
                        let said = crate::let_go::stopped_says(name, stopped, n);
                        if !body.asks {
                            let terminal = crate::let_go::at_a_terminal_says(name, n);
                            return Err(ApiError::Conflict(format!("{said} {terminal}")));
                        }
                        let wall = chrono::Utc::now().timestamp();
                        let asked =
                            crate::let_go::word_asked(&db, name, &read, n, said, wall, true)
                                .map_err(refused)?;
                        drop(db);
                        let mut status = status(None, None)?;
                        status.not_let_go = Some(asked);
                        return Ok(status);
                    }
                }
                if stands != crate::at_relays::Stands::Applied {
                    let_go_of_a_carried_name(state, &db, name, None)?;
                    let alone = listed_alone(state, &db);
                    drop(db);
                    let mut status = status(Some(name.clone()), None)?;
                    status.let_go_alone = Some(alone);
                    return Ok(status);
                }
            }
        }
    }
    // The read, with the lock let go: it waits on the relays.
    match crate::let_go::round(state, name, read).await? {
        crate::let_go::Round::Reading { read, at } => {
            let relays: Vec<serde_json::Value> = at
                .at
                .iter()
                .filter(|at| at.read.reads_on())
                .map(|at| serde_json::json!({ "relay": at.relay, "bytes": at.bytes }))
                .collect();
            let mut status = status(None, None)?;
            status.reading = Some(serde_json::json!({
                "read": hex::encode(read),
                "relays": relays,
            }));
            Ok(status)
        }
        crate::let_go::Round::Ended { read, found, .. } => {
            let alone = {
                let db = state
                    .db
                    .lock()
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
                // At a terminal, what was held by no relay is said, and the
                // word is asked (decision 2026-10-17 §5.2).
                let carried = crate::names::carried(&db).map_err(crate::commands::refused)?;
                if body.asks && !found.each_held() && carried.contains(name) {
                    let asked = word_asked_after_a_read(state, &db, name, &read, &found)?;
                    drop(db);
                    let mut status = status(None, None)?;
                    status.not_let_go = Some(asked);
                    return Ok(status);
                }
                if !let_go_of_a_carried_name(state, &db, name, Some((&read, &found)))? {
                    return Err(ApiError::BadRequest(format!(
                        "{name} is not mapped on this device"
                    )));
                }
                listed_alone(state, &db)
            };
            let mut status = status(Some(name.clone()), None)?;
            status.let_go_alone = Some(alone);
            status.let_go_versions = Some(found.asked);
            Ok(status)
        }
    }
}

/// What the node answers a command that asks at a terminal where the read
/// named `read` found entries of `name` that no relay held (decision
/// 2026-10-17 §5.2, §5.3): the lines of §4.6 but the last, and where the
/// versions may still be, with the read's ID and the number found
/// ([`crate::let_go::word_asked`]). Refused as a let-go is where the read
/// no longer binds it ([`bound_to_its_read`]).
fn word_asked_after_a_read(
    state: &AppState,
    db: &rusqlite::Connection,
    name: &str,
    read: &crate::own_read::ReadId,
    found: &crate::let_go::Found,
) -> Result<serde_json::Value, ApiError> {
    use crate::commands::refused;
    use crate::let_go as check;
    let kept = bound_to_its_read(state, db, name, read, found)?;
    let said = state.own_channels.read();
    let wall = chrono::Utc::now().timestamp();
    let relays = check::relays_say(db, &kept, found, &said, wall).map_err(refused)?;
    let lines = check::not_held_lines(name, found.not_held.len(), &relays);
    let n = found.not_held.len();
    check::word_asked(db, name, read, n, lines, wall, false).map_err(refused)
}

/// What [`unmapped`] does where the command sends the word that the person
/// typed (decision 2026-10-17 §5.2): only `discard` is one, sent with the
/// read's ID and the number that was said ([`discard_a_carried_name`]).
fn discarded(
    state: &AppState,
    name: &str,
    word: &str,
    read: Option<crate::own_read::ReadId>,
    versions: Option<usize>,
) -> Result<SyncStatusResponse, ApiError> {
    let (Some(read), Some(versions), "discard") = (read, versions, word) else {
        return Err(ApiError::BadRequest(
            "a name is let go with what no relay holds on the word `discard`, sent with the ID \
             of its read and the number of versions found"
                .into(),
        ));
    };
    let (gone, alone, stopped) = {
        let db = state
            .db
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let now = std::time::Instant::now();
        let wall = chrono::Utc::now().timestamp();
        let Some(gone) = discard_a_carried_name(state, &db, name, &read, versions, now, wall)?
        else {
            return Err(ApiError::BadRequest(format!(
                "{name} is not mapped on this device"
            )));
        };
        // A device that has stopped read no relay: what went is what its
        // own notes said it sent to none (decision 2026-10-17 §5.3).
        let stopped = !matches!(
            crate::at_relays::stands(&db),
            Ok(crate::at_relays::Stands::Applied)
        );
        (gone, listed_alone(state, &db), stopped)
    };
    let mut status = status(state)?;
    status.let_go = Some(name.to_string());
    status.let_go_alone = Some(alone);
    status.let_go_discarded = Some(gone);
    status.let_go_stopped = Some(stopped);
    Ok(status)
}

/// The ID of a read, as a command sends it: hex of sixteen bytes.
fn read_named(read: &str) -> Result<crate::own_read::ReadId, ApiError> {
    let bytes = hex::decode(read).map_err(|_| ApiError::BadRequest("a read's ID is hex".into()))?;
    bytes
        .try_into()
        .map_err(|_| ApiError::BadRequest("a read's ID is sixteen bytes".into()))
}

/// Whether the statement that this device has applied lists this device
/// and no other: then no other device of the person's holds anything of
/// a name, as after a recovery (decision 2026-10-04 §9, step 4).
fn listed_alone(state: &AppState, db: &rusqlite::Connection) -> bool {
    let own = state.identity.public_key();
    let held = crate::person::held(db).ok().flatten();
    held.is_some_and(|held| {
        let devices = &held.statement.statement.devices;
        !devices.is_empty() && devices.iter().all(|device| device.key == own)
    })
}

// ── POST /api/v1/sync/status ───────────────────────────────────────

pub async fn sync_status(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    Ok(HttpResponse::Ok().json(status(&state)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_names() {
        for ok in [
            "~",
            "github.com/seed-drill/cordelia-node",
            "my-workspace",
            "notes_2026",
            "a",
            // What a git remote can normalise to.
            "git.sr.ht/~sam/proj",
            "dev.azure.com/org/project/_git/repo",
            "host.example/a%20b/c+d",
            "host.example/user@team/repo",
            "a-b~c",
        ] {
            assert!(valid_sync_name(ok), "{ok}");
        }
        for bad in [
            "",
            "My-Workspace",
            "has space",
            "../etc",
            "a/../b",
            "a//b",
            "/leading",
            "trailing/",
            ".",
            "semi;colon",
            "back`tick",
            "dollar$(x)",
            "quote'",
            "new\nline",
            "star*",
            "caf\u{e9}",
            // Read as an option by a command line.
            "-x",
            "--stays-here",
            // Read as a path by a shell, unless quoted.
            "~x",
            "~/x",
            "~+",
            "~sam/proj",
        ] {
            assert!(!valid_sync_name(bad), "{bad}");
        }
        assert!(!valid_sync_name(&"a".repeat(201)));
    }

    /// A message's `from` and `to` are bounded at a name's own bound
    /// (decision 2026-10-09 §2.2, §6): every name fits, and the bound is no
    /// wider than a name.
    #[test]
    fn a_names_bound_is_the_bound_of_a_name_in_a_message() {
        use cordelia_core::protocol::AGENT_MESSAGE_NAME_MAX_BYTES;
        let longest = "a".repeat(AGENT_MESSAGE_NAME_MAX_BYTES);
        assert!(valid_sync_name(&longest));
        assert!(!valid_sync_name(&format!("{longest}a")));
    }

    fn request(folder: &str, name: &str, home: bool) -> SyncMapRequest {
        SyncMapRequest {
            folder: folder.into(),
            name: name.into(),
            home,
        }
    }

    #[test]
    fn test_mappings_that_are_accepted() {
        let home = std::path::Path::new("/home/sam");
        let stored = |folder: &str, name: &str| SyncMapping {
            folder: folder.into(),
            name: name.into(),
        };
        let check = |req: SyncMapRequest, existing: &[SyncMapping]| {
            check_mapping(&req, home, existing).unwrap()
        };

        // A project under its remote, a folder under a label.
        assert_eq!(
            check(request("/home/sam/Work/cn", "github.com/o/cn", false), &[]),
            Some(stored("/home/sam/Work/cn", "github.com/o/cn"))
        );
        assert_eq!(
            check(request("/home/sam/notes", " lab-notes ", false), &[]),
            Some(stored("/home/sam/notes", "lab-notes"))
        );
        // The home directory, asked for: as `~`, or under any name.
        assert_eq!(
            check(request("/home/sam", "~", true), &[]),
            Some(stored("/home/sam", "~"))
        );
        assert_eq!(
            check(request("/home/sam/", "team", true), &[]),
            Some(stored("/home/sam", "team"))
        );
        // One spelling per folder.
        for spelling in ["/home/sam//notes/", "/home/sam/./notes"] {
            assert_eq!(
                check(request(spelling, "lab-notes", false), &[]),
                Some(stored("/home/sam/notes", "lab-notes"))
            );
        }
        // Declaring the same mapping again changes nothing.
        let existing = [stored("/home/sam/notes", "lab-notes")];
        assert_eq!(
            check(request("/home/sam/notes/", "lab-notes", false), &existing),
            None
        );
    }

    #[test]
    fn test_mappings_that_are_refused() {
        let home = std::path::Path::new("/home/sam");
        let existing = [
            SyncMapping {
                folder: "/home/sam/notes".into(),
                name: "lab-notes".into(),
            },
            SyncMapping {
                folder: "/home/sam/no-tes".into(),
                name: "dashed".into(),
            },
        ];
        let long = format!("/home/sam/{}", "a".repeat(200));
        for (req, why) in [
            (request("notes", "n", false), "absolute"),
            (request("/home/sam/../other", "n", false), "absolute"),
            // Home memory only when asked for, under any name: a slip
            // must not sync a whole home.
            (request("/home/sam", "everything", false), "--home"),
            (request("/home/sam/", "~", false), "--home"),
            (request("/home/sam/Work", "work", true), "--home"),
            // `~` names home memory and nothing else.
            (
                request("/home/sam/Work", "~", false),
                "the name of home memory",
            ),
            (
                request("/home/sam/Work", "Has Spaces", false),
                "not a usable name",
            ),
            (
                request("/home/sam/Work", "../x", false),
                "not a usable name",
            ),
            // Read as an option, or as a path.
            (request("/home/sam", "-team", true), "not a usable name"),
            (request("/home/sam/Work", "~x", false), "not a usable name"),
            (request("/home/sam/Work", "~/x", false), "not a usable name"),
            // A name has its channel by its one spelling.
            (
                request("/home/sam/Work", "github.com/sam/work.git", false),
                "in its one spelling: map the folder as \"github.com/sam/work\"",
            ),
            // Nothing outside the home directory.
            (request("/srv/code/app", "app", false), "outside the home"),
            (
                request("/home/samantha/notes", "n", false),
                "outside the home",
            ),
            (request("/", "root", false), "outside the home"),
            // One name per folder and one folder per name.
            (
                request("/home/sam/notes", "other", false),
                "already mapped to",
            ),
            (
                request("/home/sam/Work", "lab-notes", false),
                "already mapped from",
            ),
            // Claude Code keeps these in the folder it keeps `notes` in.
            (request("/home/sam/no.tes", "other", false), "in one folder"),
            (request("/home/sam/no/tes", "other", false), "in one folder"),
            (request(&long, "n", false), "longer than 200"),
        ] {
            let got = check_mapping(&req, home, &existing).unwrap_err();
            assert!(got.contains(why), "{} as {:?}: {got}", req.folder, req.name);
        }
    }

    /// A folder mapped under another name is told to unmap it first only
    /// when nothing else refuses the request. Unmapping is not free, and a
    /// request that is refused for another reason would be refused again
    /// once the folder was unmapped.
    #[test]
    fn test_an_unmap_is_the_last_thing_asked_for() {
        let home = std::path::Path::new("/home/sam");
        let stored = |folder: &str, name: &str| SyncMapping {
            folder: folder.into(),
            name: name.into(),
        };
        let existing = [
            stored("/home/sam", "team"),
            stored("/home/sam/notes", "lab-notes"),
            stored("/home/sam/Work", "work"),
        ];
        for (req, why) in [
            // Each of these folders is mapped under another name.
            (
                request("/home/sam/notes", "Lab Notes", false),
                "not a usable name",
            ),
            (
                request("/home/sam/notes", "~", false),
                "the name of home memory",
            ),
            (request("/home/sam/notes", "other", true), "--home"),
            (request("/home/sam", "other", false), "--home"),
            (request("/home/sam", "my team", true), "not a usable name"),
            (
                request("/home/sam/notes", "work", false),
                "already mapped from /home/sam/Work",
            ),
            (
                request("/home/sam", "work", true),
                "already mapped from /home/sam/Work",
            ),
            // Nothing else refuses these.
            (request("/home/sam/notes", "other", false), "unmap it first"),
            (request("/home/sam", "other", true), "unmap it first"),
            (request("/home/sam", "~", true), "unmap it first"),
        ] {
            let got = check_mapping(&req, home, &existing).unwrap_err();
            assert!(got.contains(why), "{} as {:?}: {got}", req.folder, req.name);
        }
        // What `cordelia sync map` asks: without the folder's own mapping,
        // a request that was told to unmap is taken, and one that was
        // refused for another reason is refused for it still.
        let others = [
            stored("/home/sam", "team"),
            stored("/home/sam/Work", "work"),
        ];
        assert_eq!(
            check_mapping(&request("/home/sam/notes", "other", false), home, &others),
            Ok(Some(stored("/home/sam/notes", "other")))
        );
        let got = check_mapping(&request("/home/sam/notes", "work", false), home, &others);
        assert!(got.unwrap_err().contains("already mapped from"));
    }

    /// The home directory has one name on a device, like any folder.
    #[test]
    fn test_the_home_directory_is_mapped_once() {
        let home = std::path::Path::new("/home/sam");
        let existing = [SyncMapping {
            folder: "/home/sam".into(),
            name: "team".into(),
        }];
        for other in ["~", "other"] {
            let got = check_mapping(&request("/home/sam", other, true), home, &existing);
            assert!(got.unwrap_err().contains("already mapped to"), "{other}");
        }
        let got = check_mapping(&request("/home/sam/Work", "team", false), home, &existing);
        assert!(got.unwrap_err().contains("already mapped from"));
    }

    /// Declaring a mapping that is already stored changes nothing and is
    /// not refused: not for the flag, and not for a name that was valid
    /// when it was stored and could not be given now.
    #[test]
    fn test_a_mapping_already_stored_is_no_change() {
        let home = std::path::Path::new("/home/sam");
        let existing = [
            SyncMapping {
                folder: "/home/sam".into(),
                name: "team".into(),
            },
            SyncMapping {
                folder: "/home/sam/old".into(),
                name: "-old".into(),
            },
        ];
        for flag in [false, true] {
            assert_eq!(
                check_mapping(&request("/home/sam", "team", flag), home, &existing),
                Ok(None)
            );
            assert_eq!(
                check_mapping(&request("/home/sam/old", "-old", flag), home, &existing),
                Ok(None)
            );
        }
        // The same name for a new folder is refused as before.
        let got = check_mapping(&request("/home/sam/new", "-old", false), home, &existing);
        assert!(got.unwrap_err().contains("not a usable name"));
    }

    /// "Stop syncing home memory" goes by the folder: it takes out the home
    /// directory's mapping whatever that is called, and no other.
    #[test]
    fn test_home_memory_is_unmapped_by_its_folder() {
        let home = std::path::Path::new("/home/sam");
        let stored = |folder: &str, name: &str| SyncMapping {
            folder: folder.into(),
            name: name.into(),
        };
        for name in ["~", "team"] {
            let mut list = vec![
                stored("/home/sam/notes", "lab-notes"),
                stored("/home/sam", name),
                stored("/home/sam/Work", "work"),
            ];
            assert_eq!(unmap_home(&mut list, home), Some(stored("/home/sam", name)));
            assert_eq!(
                list,
                vec![
                    stored("/home/sam/notes", "lab-notes"),
                    stored("/home/sam/Work", "work")
                ]
            );
            assert_eq!(unmap_home(&mut list, home), None, "{name}");
        }
    }

    // ── The settings, as the handlers change them ──────────────────

    const HOME: &str = "/home/sam";
    const DIR: &str = "/home/sam/.claude";

    /// Every entry that the store holds of `channel`, checked.
    fn stored_of(
        db: &rusqlite::Connection,
        channel: &[u8; 32],
    ) -> Vec<cordelia_crypto::entry::CheckedEntry> {
        cordelia_storage::entries::channel_entries_after(db, channel, 0, 100_000)
            .unwrap()
            .into_iter()
            .map(|held| held.entry.check().unwrap())
            .collect()
    }

    /// A relay of [`read_at`]: its name, its key where it was reached, and
    /// what it handed, or `None` where it was not reached.
    type ReadAtRelay<'a> = (
        &'a str,
        Option<[u8; 32]>,
        Option<&'a [cordelia_crypto::entry::CheckedEntry]>,
    );

    /// A read of the channel of `name` before it is let go, as the node
    /// keeps it once its round has ended, and what it found: at each relay,
    /// by its name and with its key where it was reached, what it handed
    /// of the channel, to its end, or `None` where it was not reached.
    fn read_at(
        state: &AppState,
        db: &rusqlite::Connection,
        name: &str,
        relays: &[ReadAtRelay],
    ) -> (crate::own_read::ReadId, crate::let_go::Found) {
        use crate::own_read::Handed;
        use crate::several::RELAY_MARK;
        let channel = cordelia_storage::person::channel_of_name(db, name)
            .unwrap()
            .unwrap();
        let under = crate::at_relays::kept_id(db).unwrap().unwrap();
        let names: Vec<String> = relays.iter().map(|(name, ..)| name.to_string()).collect();
        let reads = state.own_channels.reads();
        let now = std::time::Instant::now();
        let read = reads.begin(&channel, &under, &names, now).unwrap();
        let (_, _, mut at) = reads.to_read(&read, now).unwrap();
        for (one, (_, key, handed)) in at.iter_mut().zip(relays) {
            one.key = *key;
            let Some(entries) = handed else {
                one.not_reached();
                continue;
            };
            let next = entries.len() as u64;
            for entries in [*entries, &[]] {
                let counted = 0;
                let mark = RELAY_MARK;
                one.handed(Handed::Page {
                    entries,
                    counted,
                    mark,
                    next,
                });
            }
        }
        reads.read(&read, at, now);
        let kept = reads.get(&read, now).unwrap();
        let found = crate::let_go::found(db, &state.identity, name, &kept).unwrap();
        (read, found)
    }

    /// [`read_at`], at relays that were each reached and handed so much.
    fn read_of(
        state: &AppState,
        db: &rusqlite::Connection,
        name: &str,
        relays: &[(&str, &[cordelia_crypto::entry::CheckedEntry])],
    ) -> (crate::own_read::ReadId, crate::let_go::Found) {
        let relays: Vec<_> = relays
            .iter()
            .map(|(name, handed)| (*name, None, Some(*handed)))
            .collect();
        read_at(state, db, name, &relays)
    }

    /// A database with sync on, and a way to run each handler's work.
    struct Settings {
        db: rusqlite::Connection,
        control: SyncControl,
    }

    impl Settings {
        fn on() -> Self {
            let s = Self {
                db: cordelia_storage::db::open_in_memory().unwrap(),
                control: SyncControl::default(),
            };
            s.claude(serde_json::json!({ "dir": DIR }));
            s
        }

        fn claude(&self, mut body: serde_json::Value) {
            if body.get("enabled").is_none() {
                body["enabled"] = true.into();
            }
            let body: SyncClaudeRequest = serde_json::from_value(body).unwrap();
            let home = std::path::Path::new(HOME);
            set_claude(&self.control, &self.db, &body, Some(home)).unwrap();
        }

        fn map(&self, folder: &str, name: &str) {
            let body = request(folder, name, folder == HOME);
            add_mapping(&self.control, &self.db, &body, std::path::Path::new(HOME)).unwrap();
        }

        fn unmap(&self, folder_or_name: &str) {
            let body = SyncUnmapRequest {
                folder: folder_or_name.into(),
                read: None,
                ..Default::default()
            };
            remove_mapping(&self.control, &self.db, &body).unwrap();
        }

        fn names(&self) -> Vec<String> {
            let mut names: Vec<String> = mappings(&self.db)
                .unwrap()
                .into_iter()
                .map(|m| m.name)
                .collect();
            names.sort();
            names
        }

        fn home_name(&self) -> Option<String> {
            meta::get(&self.db, meta::SYNC_CLAUDE_HOME_NAME).unwrap()
        }

        /// As the adapter records it: `folder` agreed something with a channel.
        fn agreed(&self, folder: &str) {
            let memory = memory_folder(DIR, folder);
            sync_state::save(
                &self.db,
                &memory,
                "grp_x",
                "notes.md",
                &sync_state::Agreed {
                    hash: Some([7; 32]),
                    rev: 1,
                    signer: None,
                    chain: None,
                },
            )
            .unwrap();
        }

        fn remembers(&self, folder: &str) -> bool {
            let memory = memory_folder(DIR, folder);
            !sync_state::load(&self.db, &memory, "grp_x")
                .unwrap()
                .is_empty()
        }
    }

    /// A folder that a command stops syncing has forgotten what it agreed
    /// with its channel by the time the command answers, and the folders
    /// that stay mapped have not. So if it syncs again it merges: a file
    /// it lost in between is fetched back, and never sent as a delete,
    /// whether or not a cycle ran in between. Turning sync off and on
    /// again stops no mapped folder: it is a node stopped and started.
    #[test]
    fn test_a_folder_that_is_stopped_forgets_what_it_agreed() {
        let s = Settings::on();
        s.map(HOME, "team");
        s.map("/home/sam/notes", "lab");
        s.map("/home/sam/Work", "work");
        let all = [HOME, "/home/sam/notes", "/home/sam/Work"];
        let agree = |s: &Settings| all.iter().for_each(|f| s.agreed(f));
        let remembered = |s: &Settings| -> Vec<&str> {
            all.iter().copied().filter(|f| s.remembers(f)).collect()
        };

        // Home memory turned off: home forgets, the others do not.
        agree(&s);
        s.claude(serde_json::json!({ "home": false }));
        assert_eq!(s.names(), ["lab", "work"]);
        assert_eq!(remembered(&s), ["/home/sam/notes", "/home/sam/Work"]);

        // Unmapped, by name or by folder.
        s.map(HOME, "team");
        agree(&s);
        s.unmap("lab");
        assert_eq!(remembered(&s), [HOME, "/home/sam/Work"]);
        s.unmap("/home/sam/Work");
        assert_eq!(remembered(&s), [HOME]);

        // Sync turned off is a node stopped: the folders that stay mapped
        // keep what they agreed, so that turned on again they go on from
        // there, and what was edited here meanwhile is sent.
        s.map("/home/sam/notes", "lab");
        agree(&s);
        s.claude(serde_json::json!({ "enabled": false }));
        let kept = remembered(&s);
        assert!(kept.contains(&HOME) && kept.contains(&"/home/sam/notes"));

        // Unmapped while sync is off, and turned on at the directory it
        // was last on: what is not mapped forgets, and nothing else.
        s.unmap("lab");
        s.claude(serde_json::json!({}));
        assert_eq!(remembered(&s), [HOME]);
        // Run again while it is on, it forgets nothing.
        agree(&s);
        s.claude(serde_json::json!({}));
        assert_eq!(remembered(&s).len(), 3);
    }

    /// A mapping is stored only with its check, made under the settings
    /// as they stand (decision 2026-10-04 §10.1). The check asks the disk
    /// and git, and is made with the database's lock let go: it is of
    /// one folder, under one Claude Code directory, at one count of
    /// settings commands. Where a setting has changed since, or the
    /// check is of another folder, or there is none, nothing is mapped
    /// and nothing is counted; and what the check refused is refused.
    #[test]
    fn test_a_mapping_is_stored_only_with_its_check_under_the_settings_as_they_stand() {
        let s = Settings::on();
        let home = std::path::Path::new(HOME);
        let body = request("/home/sam/code/app", "app", false);
        let asked =
            |s: &Settings, body: &SyncMapRequest| map_asked(&s.control, &s.db, body, home).unwrap();
        let store = |s: &Settings, body: &SyncMapRequest, looked: Option<&MapLooked>| {
            add_mapping_looked(&s.control, &s.db, body, home, looked)
        };
        let refused = |s: &Settings, body: &SyncMapRequest, looked: Option<&MapLooked>| {
            let before = s.control.generation();
            let why = store(s, body, looked).unwrap_err().to_string();
            assert!(mappings(&s.db).unwrap().is_empty(), "{why}");
            assert_eq!(s.control.generation(), before, "{why}");
            why
        };

        // The check is read under the lock, and made without the
        // database: it is handed nothing of it.
        let read = asked(&s, &body).expect("something to check");
        let looked = map_looked(&read, home);
        assert_eq!(looked.refused, None);
        // With no check: nothing is mapped.
        assert!(refused(&s, &body, None).contains(SETTINGS_CHANGED_UNDER_MAP));
        // A check of another folder is no check of this one.
        let other = request("/home/sam/code/lib", "lib", false);
        let of_another = map_looked(&asked(&s, &other).unwrap(), home);
        assert!(refused(&s, &body, Some(&of_another)).contains(SETTINGS_CHANGED_UNDER_MAP));
        // A setting changes between the check and the store: the check
        // is of settings that stand no longer.
        s.control.changed(&s.db);
        assert!(refused(&s, &body, Some(&looked)).contains(SETTINGS_CHANGED_UNDER_MAP));
        // So too where the Claude Code directory is another now.
        let read = asked(&s, &body).unwrap();
        let looked = map_looked(&read, home);
        s.claude(serde_json::json!({ "dir": "/home/sam/.claude-two" }));
        let mut of_this_count = looked.clone();
        of_this_count.generation = s.control.generation();
        assert!(refused(&s, &body, Some(&of_this_count)).contains(SETTINGS_CHANGED_UNDER_MAP));
        // What the check refused is refused, in its words.
        let read = asked(&s, &body).unwrap();
        let mut said_no = map_looked(&read, home);
        said_no.refused = Some("another folder was found for it".into());
        assert!(refused(&s, &body, Some(&said_no)).contains("another folder was found for it"));
        // And a check made under the settings as they stand is stored.
        let looked = map_looked(&asked(&s, &body).unwrap(), home);
        store(&s, &body, Some(&looked)).unwrap();
        assert_eq!(mappings(&s.db).unwrap().len(), 1);

        // Nothing to check: sync off, a request that is refused for a
        // reason of its own, and a mapping that is declared already. The
        // store says which, with or without a check.
        assert!(asked(&s, &body).is_none());
        store(&s, &body, None).unwrap();
        let outside = request("/srv/app", "app", false);
        assert!(asked(&s, &outside).is_none());
        let why = store(&s, &outside, None).unwrap_err().to_string();
        assert!(why.contains("outside the home directory"), "{why}");
        s.claude(serde_json::json!({ "enabled": false }));
        assert!(asked(&s, &other).is_none());
        let why = store(&s, &other, None).unwrap_err().to_string();
        assert!(why.contains("sync is off"), "{why}");
    }

    /// A folder that a mapping adds forgets what it had agreed, whatever
    /// was left of it (decision 2026-10-04 §10.1): so it always merges.
    /// No other folder forgets for it. Mapping what is already mapped
    /// adds nothing, and forgets nothing: nor does a mapping that is
    /// refused.
    #[test]
    fn test_a_folder_that_is_mapped_forgets_what_it_had_agreed() {
        let s = Settings::on();
        s.map("/home/sam/Work", "work");
        // What an earlier version, or a cycle that was stopped, left.
        let left = ["/home/sam/notes", "/home/sam/Work", "/home/sam/other"];
        left.iter().for_each(|folder| s.agreed(folder));
        s.map("/home/sam/notes", "lab");
        assert!(!s.remembers("/home/sam/notes"));
        assert!(s.remembers("/home/sam/Work") && s.remembers("/home/sam/other"));

        // It syncs, and agrees its files. Declared again, it is mapped
        // already: nothing is added, and nothing is forgotten.
        s.agreed("/home/sam/notes");
        for spelled in ["/home/sam/notes", "/home/sam/notes/", "/home/sam//notes"] {
            s.map(spelled, "lab");
            assert!(s.remembers("/home/sam/notes"), "{spelled}");
        }
        // A mapping that is refused forgets nothing either: the folder
        // under another name, and another folder under its name.
        let home = std::path::Path::new(HOME);
        for (folder, name) in [("/home/sam/notes", "other"), ("/home/sam/other", "lab")] {
            let body = request(folder, name, false);
            assert!(add_mapping(&s.control, &s.db, &body, home).is_err());
            assert!(s.remembers("/home/sam/notes") && s.remembers("/home/sam/other"));
        }
        // The home directory, mapped, forgets as any folder does.
        s.agreed(HOME);
        s.map(HOME, "team");
        assert!(!s.remembers(HOME));
        assert!(s.remembers("/home/sam/notes"));
    }

    /// Only a mapping says what syncs (decision 2026-10-04 §10.1). So
    /// what a request says of a scope, of exclusions or of home memory
    /// stops no folder, where the home directory is not mapped, and
    /// forgets nothing. A folder that is unmapped forgets, with every
    /// other folder that is not mapped: whatever an earlier version left
    /// of one. A change of the Claude Code directory moves every folder,
    /// so all of them forget.
    #[test]
    fn test_only_an_unmapping_and_a_change_of_directory_forget() {
        let found = "/home/sam/code/app";
        let requests = [
            serde_json::json!({ "all": false }),
            serde_json::json!({ "exclude": ["github.com/client-co/*"] }),
            serde_json::json!({ "exclude": [] }),
            serde_json::json!({ "home": false }),
            serde_json::json!({ "home": true }),
            serde_json::json!({ "reset": true, "dir": DIR }),
            serde_json::json!({}),
        ];
        for request in requests {
            let s = Settings::on();
            s.map("/home/sam/notes", "lab");
            s.agreed("/home/sam/notes");
            s.agreed(found);
            s.claude(request.clone());
            assert!(s.remembers(found), "{request}");
            assert!(s.remembers("/home/sam/notes"), "{request}");
            assert_eq!(s.names(), ["lab"], "{request}");
        }

        // Unmapping a folder forgets whatever is not mapped.
        let s = Settings::on();
        s.map("/home/sam/notes", "lab");
        s.map("/home/sam/Work", "work");
        for folder in [found, "/home/sam/notes", "/home/sam/Work"] {
            s.agreed(folder);
        }
        s.unmap("lab");
        assert!(!s.remembers(found) && !s.remembers("/home/sam/notes"));
        assert!(s.remembers("/home/sam/Work"));

        // Every folder, a mapped one too, and whatever directory it was
        // recorded under.
        let s = Settings::on();
        let other = "/home/sam/.claude-other";
        let there = memory_folder(other, "/home/sam/notes");
        s.map("/home/sam/notes", "lab");
        s.agreed("/home/sam/notes");
        sync_state::save(
            &s.db,
            &there,
            "grp_x",
            "notes.md",
            &sync_state::Agreed {
                hash: Some([7; 32]),
                rev: 1,
                signer: None,
                chain: None,
            },
        )
        .unwrap();
        s.claude(serde_json::json!({ "dir": other }));
        assert!(!s.remembers("/home/sam/notes"));
        assert!(sync_state::load(&s.db, &there, "grp_x").unwrap().is_empty());
        // The directory is the string: another spelling of the same path
        // is a change of it.
        s.agreed("/home/sam/notes");
        s.claude(serde_json::json!({ "dir": "/home/sam//.claude-other" }));
        assert!(!s.remembers("/home/sam/notes"));

        // The same where sync was off between: turned on at another
        // directory than the one it was last on, every folder forgets,
        // the mapped folder's record under that directory too.
        let agreed_there = |s: &Settings| {
            let agreed = sync_state::Agreed {
                hash: Some([7; 32]),
                rev: 1,
                signer: None,
                chain: None,
            };
            sync_state::save(&s.db, &there, "grp_x", "notes.md", &agreed).unwrap();
        };
        s.claude(serde_json::json!({ "dir": DIR }));
        s.agreed("/home/sam/notes");
        agreed_there(&s);
        s.claude(serde_json::json!({ "enabled": false }));
        assert!(s.remembers("/home/sam/notes"));
        s.claude(serde_json::json!({ "dir": other }));
        assert!(!s.remembers("/home/sam/notes"));
        assert!(sync_state::load(&s.db, &there, "grp_x").unwrap().is_empty());

        // With no directory remembered, neither the one in use nor the
        // one sync was last on, every folder forgets when sync is turned
        // on: a mapped folder's record too, whatever left it.
        let s = Settings::on();
        s.map("/home/sam/notes", "lab");
        s.agreed("/home/sam/notes");
        meta::remove(&s.db, meta::SYNC_CLAUDE_DIR).unwrap();
        meta::remove(&s.db, meta::SYNC_CLAUDE_LAST_DIR).unwrap();
        assert!(s.remembers("/home/sam/notes"));
        s.claude(serde_json::json!({ "dir": DIR }));
        assert!(!s.remembers("/home/sam/notes"));
    }

    /// Turning home memory off unmaps the home directory, so the node has
    /// to know where that is. Where it does not, the request is refused
    /// whole: nothing in it is stored, and nothing is counted as changed.
    #[test]
    fn test_home_memory_is_not_turned_off_where_home_is_not_known() {
        let s = Settings::on();
        s.map(HOME, "team");
        let count = s.control.generation();
        let other = "/home/sam/.claude-other";
        let body = serde_json::json!({ "enabled": true, "dir": other, "home": false });
        let body: SyncClaudeRequest = serde_json::from_value(body).unwrap();
        assert!(set_claude(&s.control, &s.db, &body, None).is_err());
        assert_eq!(s.names(), ["team"]);
        let dir = || meta::get(&s.db, meta::SYNC_CLAUDE_DIR).unwrap();
        assert_eq!(dir().as_deref(), Some(DIR));
        assert_eq!(s.control.generation(), count);

        // Everything else is carried out without it.
        let body = serde_json::json!({ "enabled": true, "dir": other });
        let body: SyncClaudeRequest = serde_json::from_value(body).unwrap();
        set_claude(&s.control, &s.db, &body, None).unwrap();
        assert_eq!(s.names(), ["team"]);
        assert_eq!(dir().as_deref(), Some(other));
        assert!(s.control.generation() > count);
    }

    /// The name home memory is put back under is the name that the home
    /// directory was last mapped under on this device. Turning it off
    /// does not change that, and nothing else records one: home memory
    /// syncs only where the home directory is mapped (decision 2026-10-04
    /// §10.1).
    #[test]
    fn test_the_name_home_last_synced_under_is_remembered() {
        let s = Settings::on();
        assert_eq!(s.home_name(), None);
        // No request names it by being asked to turn sync on, or home
        // memory on, with the home directory not mapped.
        s.claude(serde_json::json!({ "home": true }));
        s.claude(serde_json::json!({ "reset": true, "dir": DIR }));
        assert_eq!(s.home_name(), None);

        s.map(HOME, "team");
        assert_eq!(s.home_name().as_deref(), Some("team"));
        s.claude(serde_json::json!({ "home": false }));
        assert_eq!(s.names(), Vec::<String>::new());
        assert_eq!(s.home_name().as_deref(), Some("team"));
        s.claude(serde_json::json!({ "home": true }));
        s.claude(serde_json::json!({ "reset": true, "dir": DIR }));
        assert_eq!(s.home_name().as_deref(), Some("team"));

        // Mapped under another name, then unmapped: it is that name.
        s.map(HOME, "crew");
        s.unmap("crew");
        assert_eq!(s.home_name().as_deref(), Some("crew"));
        s.map(HOME, "~");
        assert_eq!(s.home_name().as_deref(), Some("~"));
    }

    /// The stored scope is off whenever sync is on (decision 2026-10-04
    /// §10.1). A start with sync on writes it off, from a stored `on` and
    /// from no scope stored with a directory set; a start with sync off
    /// writes nothing. A request that turns sync on, or leaves it on,
    /// writes it off over whatever is stored. And the key is never
    /// removed: read as an earlier version reads the settings, the scope
    /// is off from the first time sync is turned on.
    #[test]
    fn test_the_stored_scope_is_off_whenever_sync_is_on() {
        use crate::several::{Machine, state_of};
        let stored = |db: &rusqlite::Connection| meta::get(db, meta::SYNC_CLAUDE_ALL).unwrap();
        // As an earlier version reads the settings: on where the key says
        // so, and where a directory is set and there is no key.
        let on_as_it_was_read = |db: &rusqlite::Connection| {
            let dir = meta::get(db, meta::SYNC_CLAUDE_DIR).unwrap();
            stored(db).map_or(dir.is_some(), |scope| scope == "on")
        };
        let set = |db: &rusqlite::Connection, dir: Option<&str>, scope: Option<&str>| {
            for (key, value) in [(meta::SYNC_CLAUDE_DIR, dir), (meta::SYNC_CLAUDE_ALL, scope)] {
                match value {
                    Some(value) => meta::set(db, key, value).unwrap(),
                    None => meta::remove(db, key).unwrap(),
                }
            }
        };

        // At a start.
        let state = state_of(Machine::new(1));
        for (dir, scope, wrote, then) in [
            (Some(DIR), Some("on"), true, Some("off")),
            (Some(DIR), None, true, Some("off")),
            (Some(DIR), Some("off"), false, Some("off")),
            (Some(DIR), Some("something else"), true, Some("off")),
            // Sync is off: nothing is written, whatever is stored.
            (None, Some("on"), false, Some("on")),
            (None, None, false, None),
        ] {
            set(&state.db.lock().unwrap(), dir, scope);
            assert_eq!(
                scope_off_at_start(&state).unwrap(),
                wrote,
                "{dir:?} {scope:?}"
            );
            let db = state.db.lock().unwrap();
            assert_eq!(stored(&db).as_deref(), then, "{dir:?} {scope:?}");
            assert_eq!(
                on_as_it_was_read(&db),
                then == Some("on"),
                "{dir:?} {scope:?}"
            );
        }

        // At a request that turns sync on, or leaves it on.
        for (dir, scope) in [
            (Some(DIR), Some("on")),
            (Some(DIR), None),
            (None, Some("on")),
            (None, None),
        ] {
            let s = Settings {
                db: cordelia_storage::db::open_in_memory().unwrap(),
                control: SyncControl::default(),
            };
            set(&s.db, dir, scope);
            s.claude(serde_json::json!({ "dir": DIR }));
            assert_eq!(stored(&s.db).as_deref(), Some("off"), "{dir:?} {scope:?}");
            assert!(!on_as_it_was_read(&s.db));
        }

        // Turned on for the first time on this version, the scope is
        // stored, and off. Whatever is asked after, the key is there.
        let s = Settings::on();
        assert_eq!(stored(&s.db).as_deref(), Some("off"));
        s.map(HOME, "team");
        s.map("/home/sam/notes", "lab");
        for request in [
            serde_json::json!({ "reset": true }),
            serde_json::json!({ "reset": true, "dir": DIR }),
            serde_json::json!({ "home": false }),
            serde_json::json!({ "all": false }),
            serde_json::json!({ "exclude": ["x"] }),
            serde_json::json!({ "enabled": false }),
            serde_json::json!({ "enabled": true }),
        ] {
            s.claude(request.clone());
            assert_eq!(stored(&s.db).as_deref(), Some("off"), "{request}");
        }
        s.unmap("lab");
        assert_eq!(stored(&s.db).as_deref(), Some("off"));
    }

    /// A handler counts its change before the first thing it writes. One
    /// that fails part-way has then still stopped the cycle that was
    /// running. Otherwise that cycle would go on from what it read before,
    /// with whatever the handler did get written under it.
    #[test]
    fn test_a_change_that_fails_part_way_is_still_counted() {
        let home = std::path::Path::new(HOME);
        let claude = |s: &Settings, body: serde_json::Value| {
            let body: SyncClaudeRequest = serde_json::from_value(body).unwrap();
            set_claude(&s.control, &s.db, &body, Some(home))
        };
        let change = |s: &Settings, which: &str| match which {
            "sync off" => claude(s, serde_json::json!({ "enabled": false })),
            "sync left on" => claude(s, serde_json::json!({ "enabled": true })),
            "home memory off" => claude(s, serde_json::json!({ "enabled": true, "home": false })),
            // Its first write is the list of mappings; of home, its name.
            "a mapping" => {
                let body = request("/home/sam/new", "new", false);
                add_mapping(&s.control, &s.db, &body, home)
            }
            "a mapping of a folder that was unmapped" => {
                let body = request("/home/sam/Work", "work", false);
                add_mapping(&s.control, &s.db, &body, home)
            }
            "a mapping of home" => {
                let body = request(HOME, "team", true);
                add_mapping(&s.control, &s.db, &body, home)
            }
            _ => {
                let body = SyncUnmapRequest {
                    folder: "lab".into(),
                    read: None,
                    ..Default::default()
                };
                remove_mapping(&s.control, &s.db, &body)
            }
        };
        // The first thing each writes is a setting, and no setting can be
        // written: the change is counted, once, and nothing came of it.
        for which in [
            "sync off",
            "sync left on",
            "home memory off",
            "a mapping",
            "a mapping of a folder that was unmapped",
            "a mapping of home",
            "an unmapping",
        ] {
            let s = Settings::on();
            s.map("/home/sam/notes", "lab");
            s.map("/home/sam/Work", "work");
            s.unmap("work");
            let before = s.control.generation();
            let held = (mappings(&s.db).unwrap(), exclusions(&s.db).unwrap());
            for write in ["INSERT", "UPDATE", "DELETE"] {
                s.db.execute_batch(&format!(
                    "CREATE TRIGGER no_{write} BEFORE {write} ON node_meta
                     BEGIN SELECT RAISE(ABORT, 'no setting can be written'); END;"
                ))
                .unwrap();
            }
            assert!(change(&s, which).is_err(), "{which}");
            assert_eq!(s.control.generation(), before + 1, "{which}");
            assert_eq!(
                (mappings(&s.db).unwrap(), exclusions(&s.db).unwrap()),
                held,
                "{which}"
            );
        }
        // Two of them also forget, later on, and the table of what
        // folders agreed is gone: counted all the same. (Turning sync off
        // forgets nothing: a mapped folder keeps what it agreed.)
        for which in ["home memory off", "an unmapping"] {
            let s = Settings::on();
            s.map(HOME, "team");
            s.map("/home/sam/notes", "lab");
            let before = s.control.generation();
            s.db.execute("DROP TABLE sync_files", []).unwrap();
            assert!(change(&s, which).is_err(), "{which}");
            assert_eq!(s.control.generation(), before + 1, "{which}");
        }
        // A request that is refused before anything is written counts
        // nothing.
        let s = Settings::on();
        let before = s.control.generation();
        assert!(
            claude(
                &s,
                serde_json::json!({ "enabled": true, "dir": "relative" })
            )
            .is_err()
        );
        let body = SyncUnmapRequest {
            folder: "nothing".into(),
            read: None,
            ..Default::default()
        };
        assert!(remove_mapping(&s.control, &s.db, &body).is_err());
        let body = request("/srv/outside", "outside", false);
        assert!(add_mapping(&s.control, &s.db, &body, home).is_err());
        assert_eq!(s.control.generation(), before);
    }

    /// A list of exclusions that a panel sends is stored, each entry in
    /// its one spelling, however it was typed and however often it is
    /// sent: sent back as it was stored, it is stored as it was. Nothing
    /// reads the list to say what syncs, and nothing else writes it: not
    /// a folder that is unmapped, and not one that is mapped (decision
    /// 2026-10-04 §10.1).
    #[test]
    fn test_a_list_of_exclusions_is_stored_as_it_is_sent() {
        let s = Settings::on();
        let typed = ["X.GIT", " Repo.git ", "client-co/*", "/home/sam//old/"];
        let stored = ["x", "repo", "client-co/*", "/home/sam/old"];
        s.claude(serde_json::json!({ "exclude": typed }));
        assert_eq!(exclusions(&s.db).unwrap(), stored);
        s.claude(serde_json::json!({ "exclude": stored }));
        assert_eq!(exclusions(&s.db).unwrap(), stored);
        for typed in ["X.GIT", "x.git", "X", "x.git.GIT", "x .git", "x/", "X.git/"] {
            assert_eq!(clean_exclusion(typed).as_deref(), Some("x"), "{typed}");
        }
        // Nothing left is no exclusion.
        for nothing in [".git", "  ", ".GIT.git"] {
            assert_eq!(clean_exclusion(nothing), None, "{nothing:?}");
        }
        // A name an earlier version stored with `.git` at its end is read
        // in its one spelling. A folder keeps a space at the end of its
        // name.
        let stored = r#"["x.git","owner/repo/","/home/sam/old","/home/sam/odd "]"#;
        meta::set(&s.db, meta::SYNC_CLAUDE_EXCLUDE, stored).unwrap();
        let read = ["x", "owner/repo", "/home/sam/old", "/home/sam/odd "];
        assert_eq!(exclusions(&s.db).unwrap(), read);
        // A folder that is mapped, and one that is unmapped, write
        // nothing to the list: what is stored is as it was.
        s.map("/home/sam/old", "old");
        assert_eq!(
            meta::get(&s.db, meta::SYNC_CLAUDE_EXCLUDE)
                .unwrap()
                .as_deref(),
            Some(stored)
        );
        s.map("/home/sam/notes", "lab");
        s.unmap("lab");
        s.unmap("old");
        assert_eq!(
            meta::get(&s.db, meta::SYNC_CLAUDE_EXCLUDE)
                .unwrap()
                .as_deref(),
            Some(stored)
        );
        // The whole list sent back as it was read is stored so.
        s.claude(serde_json::json!({ "exclude": read }));
        assert_eq!(exclusions(&s.db).unwrap(), read);
        // Space before a path is not part of it; `..` is not taken.
        assert_eq!(
            clean_exclusion(" /home/sam//old/").as_deref(),
            Some("/home/sam/old")
        );
        assert_eq!(clean_exclusion("/home/sam/../old"), None);
        // A stored folder is read by the same rule: its separators are
        // tidied, and one with `..` in it is no folder and is dropped.
        let stored = r#"["/home/sam//old/","/home/sam/./notes","/home/sam/../x"]"#;
        meta::set(&s.db, meta::SYNC_CLAUDE_EXCLUDE, stored).unwrap();
        assert_eq!(
            exclusions(&s.db).unwrap(),
            ["/home/sam/old", "/home/sam/notes"]
        );
    }

    /// Asking for everything found to sync is refused whole (decision
    /// 2026-10-04 §10.1): a request that turns sync on, or leaves it on,
    /// with `all: true` changes nothing and counts no change, alone and
    /// with a directory, a reset, home memory turned off or a list of
    /// exclusions beside it. A request that turns sync off is never
    /// refused for it. `all: false` is taken.
    #[test]
    fn test_a_request_for_everything_found_is_refused_whole() {
        let home = std::path::Path::new(HOME);
        let asks = |s: &Settings, body: serde_json::Value| {
            let body: SyncClaudeRequest = serde_json::from_value(body).unwrap();
            set_claude(&s.control, &s.db, &body, Some(home))
        };
        let everything = |s: &Settings| -> Vec<(String, Option<String>)> {
            let mut stmt =
                s.db.prepare("SELECT key, value FROM node_meta ORDER BY key")
                    .unwrap();
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap();
            rows.collect::<Result<_, _>>().unwrap()
        };
        let other = "/home/sam/.claude-other";
        for sync_on in [true, false] {
            let s = Settings::on();
            s.map(HOME, "team");
            s.map("/home/sam/notes", "lab");
            s.claude(serde_json::json!({ "exclude": ["kept-out"] }));
            // What a cycle stored, and what the folders agreed.
            meta::set(&s.db, meta::SYNC_CLAUDE_REPORT, r#"{"folders":[]}"#).unwrap();
            s.agreed("/home/sam/notes");
            if !sync_on {
                s.claude(serde_json::json!({ "enabled": false }));
                meta::set(&s.db, meta::SYNC_CLAUDE_REPORT, r#"{"folders":[]}"#).unwrap();
            }
            let (before, count) = (everything(&s), s.control.generation());
            for with in [
                serde_json::json!({}),
                serde_json::json!({ "dir": other }),
                serde_json::json!({ "reset": true }),
                serde_json::json!({ "home": false }),
                serde_json::json!({ "exclude": [] }),
                serde_json::json!({ "dir": other, "reset": true, "home": false, "exclude": ["x"] }),
            ] {
                let mut body = with.clone();
                body["enabled"] = true.into();
                body["all"] = true.into();
                let refused = asks(&s, body).unwrap_err();
                assert!(matches!(refused, ApiError::BadRequest(_)), "{with}");
                assert!(
                    refused.to_string().contains("only mapped folders sync"),
                    "{refused}"
                );
                assert_eq!(everything(&s), before, "{with}, sync on: {sync_on}");
                assert_eq!(s.control.generation(), count, "{with}");
                // A mapped folder keeps what it agreed, with sync on or
                // off, and a refused request forgets nothing of it.
                assert!(s.remembers("/home/sam/notes"), "{with}");
            }
        }

        // Turning sync off is never refused for it.
        let s = Settings::on();
        asks(&s, serde_json::json!({ "enabled": false, "all": true })).unwrap();
        assert_eq!(meta::get(&s.db, meta::SYNC_CLAUDE_DIR).unwrap(), None);
        // And the only scope there is, is taken: with sync off, and on.
        asks(&s, serde_json::json!({ "enabled": true, "all": false })).unwrap();
        asks(&s, serde_json::json!({ "enabled": true, "all": false })).unwrap();
        assert_eq!(
            meta::get(&s.db, meta::SYNC_CLAUDE_DIR).unwrap().as_deref(),
            Some(DIR)
        );
        assert_eq!(
            meta::get(&s.db, meta::SYNC_CLAUDE_ALL).unwrap().as_deref(),
            Some("off")
        );
    }

    /// A reset puts the Claude Code directory back to its default, and
    /// touches nothing else: not the list of exclusions that is stored,
    /// not the switch for home memory, and not the mappings. The switch
    /// is stored as it is sent: off unmaps the home directory, and on
    /// maps nothing.
    #[test]
    fn test_a_reset_leaves_the_stored_exclusions_and_the_home_switch() {
        let s = Settings::on();
        let other = "/home/sam/.claude-other";
        let switch = |s: &Settings| meta::get(&s.db, meta::SYNC_CLAUDE_HOME).unwrap();
        let dir = |s: &Settings| meta::get(&s.db, meta::SYNC_CLAUDE_DIR).unwrap();
        s.map(HOME, "team");
        s.map("/home/sam/notes", "lab");
        s.claude(serde_json::json!({ "dir": other, "exclude": ["kept-out"], "home": false }));
        assert_eq!(s.names(), ["lab"]);
        assert_eq!(switch(&s).as_deref(), Some("off"));

        s.claude(serde_json::json!({ "reset": true, "dir": DIR }));
        assert_eq!(dir(&s).as_deref(), Some(DIR));
        assert_eq!(exclusions(&s.db).unwrap(), ["kept-out"]);
        assert_eq!(switch(&s).as_deref(), Some("off"));
        assert_eq!(s.names(), ["lab"]);

        // The switch turned on is stored so, and maps nothing: `cordelia
        // sync home on` maps the home directory.
        s.claude(serde_json::json!({ "home": true }));
        assert_eq!(switch(&s), None);
        assert_eq!(s.names(), ["lab"]);
        s.claude(serde_json::json!({ "reset": true, "dir": other }));
        assert_eq!(switch(&s), None);
        assert_eq!(exclusions(&s.db).unwrap(), ["kept-out"]);
    }

    /// Every handler counts its change, with the lock held, so that a
    /// cycle that started before it stops (see `SyncControl::changed`).
    #[test]
    fn test_every_change_of_settings_is_counted() {
        let s = Settings::on();
        let mut last = s.control.generation();
        let mut counted = |s: &Settings, what: &str| {
            let now = s.control.generation();
            assert!(now > last, "{what}");
            last = now;
        };
        s.claude(serde_json::json!({ "all": false }));
        counted(&s, "the scope");
        s.map("/home/sam/notes", "lab");
        counted(&s, "a mapping");
        s.map("/home/sam/notes", "lab");
        counted(&s, "a mapping declared again");
        s.unmap("lab");
        counted(&s, "an unmapping");
        s.claude(serde_json::json!({ "enabled": false }));
        counted(&s, "sync off");
    }

    /// A device that comes to sync a name carries it first (decision
    /// 2026-10-04 §7.3): a mapping names, for that, each name that the
    /// device holds anew by it, where the device has applied a statement
    /// and still holds the secret of a generation that it left; and the
    /// first cycle of a folder there is held back from then. A name that
    /// was mapped before is not carried again, and nor is anything on a
    /// device that has left no generation, or follows no phrase.
    #[test]
    fn test_a_mapping_carries_first_only_a_name_that_it_holds_anew() {
        use crate::several::{Machine, Several, state_of};
        use cordelia_storage::person as held_rows;
        let home = std::path::Path::new("/home/sam");
        let maps = |state: &AppState, folder: &str, name: &str| -> Vec<String> {
            let db = state.db.lock().unwrap();
            let on: SyncClaudeRequest =
                serde_json::from_value(serde_json::json!({ "enabled": true, "dir": DIR })).unwrap();
            set_claude(&state.sync_control, &db, &on, Some(home)).unwrap();
            let before = mapped_names(&db).unwrap();
            let body = request(folder, name, false);
            add_mapping(&state.sync_control, &db, &body, home).unwrap();
            names_follow(state, &db, &before);
            let anew = carries_first_for(state, &db, &before);
            anew.into_iter().map(|(name, _)| name).collect()
        };
        let waits = |state: &AppState, name: &str| -> bool {
            let channel = {
                let db = state.db.lock().unwrap();
                held_rows::channel_of_name(&db, name).unwrap().unwrap()
            };
            let now = std::time::Instant::now();
            state.own_channels.fetched_from(&channel, "relay", now);
            !state.own_channels.first_fetch_done(&channel, now)
        };

        // Under its first statement the device has left no generation.
        let mut s = Several::of_one_person(1);
        s.change(0, &[0], &[]);
        let mut first = Several::of_one_person(1);
        let no_left = state_of(first.machines.remove(0));
        no_left.own_channels.set_up_with(1);
        assert!(maps(&no_left, "/home/sam/notes", "lab").is_empty());
        assert!(!waits(&no_left, "lab"));

        // It has left one: the name that it comes to hold is carried
        // first, and its folder's first cycle waits for that.
        let state = state_of(s.machines.remove(0));
        state.own_channels.set_up_with(1);
        assert_eq!(maps(&state, "/home/sam/notes", "lab"), ["lab"]);
        assert!(waits(&state, "lab"));
        // A second mapping: only the name that is new by it.
        assert_eq!(maps(&state, "/home/sam/work", "team"), ["team"]);
        // The same mapping again holds nothing anew.
        assert!(maps(&state, "/home/sam/work", "team").is_empty());

        // A device that follows no phrase holds no name.
        let alone = state_of(Machine::new(7));
        assert!(maps(&alone, "/home/sam/notes", "lab").is_empty());
    }

    /// What a device says of the names it syncs follows its settings
    /// (decision 2026-10-04 §2.2, §16): it holds a name and says that it
    /// syncs it when it maps the name, says so no longer and holds it no
    /// more when it unmaps it, and takes every word back when sync is
    /// turned off. A device that follows no phrase says nothing, and its
    /// settings are set all the same.
    #[test]
    fn test_what_a_device_says_of_its_names_follows_its_settings() {
        use crate::several::{Machine, Several, state_of};
        use cordelia_storage::person as held_rows;

        let home = std::path::Path::new("/home/sam");
        let on = |on: bool| -> SyncClaudeRequest {
            serde_json::from_value(serde_json::json!({ "enabled": on, "dir": DIR })).unwrap()
        };
        let held = |db: &rusqlite::Connection| -> Vec<String> {
            let names = held_rows::names(db).unwrap();
            names.into_iter().map(|name| name.name).collect()
        };
        let said = |state: &AppState, db: &rusqlite::Connection| -> Vec<String> {
            let said = crate::names::said_here(db, &state.identity).unwrap();
            said.into_iter().collect()
        };
        // One settings command, as its handler runs it.
        let does = |state: &AppState, command: &dyn Fn(&rusqlite::Connection)| {
            let db = state.db.lock().unwrap();
            let before = mapped_names(&db).unwrap();
            command(&db);
            names_follow(state, &db, &before);
        };
        let turns = |state: &AppState, to: bool| {
            does(state, &|db| {
                set_claude(&state.sync_control, db, &on(to), Some(home)).unwrap()
            })
        };
        let maps = |state: &AppState, folder: &str, name: &str| {
            does(state, &|db| {
                let body = request(folder, name, false);
                add_mapping(&state.sync_control, db, &body, home).unwrap()
            })
        };
        let unmaps = |state: &AppState, name: &str| {
            does(state, &|db| {
                let body = SyncUnmapRequest {
                    folder: name.to_string(),
                    read: None,
                    ..Default::default()
                };
                remove_mapping(&state.sync_control, db, &body).unwrap()
            })
        };

        let mut s = Several::of_one_person(1);
        let state = state_of(s.machines.remove(0));
        state.own_channels.set_up_with(1);
        turns(&state, true);
        maps(&state, "/home/sam/notes", "lab");
        maps(&state, "/home/sam/work", "team");
        let lab = {
            let db = state.db.lock().unwrap();
            assert_eq!(held(&db), ["lab", "team"]);
            assert_eq!(said(&state, &db), ["lab", "team"]);
            held_rows::channel_of_name(&db, "lab").unwrap().unwrap()
        };
        // Its channel was fetched from the relay.
        let now = std::time::Instant::now();
        state.own_channels.fetched_from(&lab, "relay", now);
        assert!(state.own_channels.first_fetch_done(&lab, now));

        // Both names were listed before the last change, as the device
        // noted when it applied it.
        let noted = |db: &rusqlite::Connection| -> Vec<String> {
            let before = held_rows::names_before(db).unwrap();
            before.into_iter().map(|before| before.name).collect()
        };
        {
            let db = state.db.lock().unwrap();
            for name in ["lab", "team"] {
                held_rows::note_name_before(&db, name, &state.identity.public_key(), 1).unwrap();
            }
        }

        // Unmapped: said no longer, held no more, and fetched again
        // before a folder's first cycle there. Nor is it noted any more
        // as a name that was listed before: it is not shown as one that
        // no device lists yet, where a person stopped it on purpose.
        unmaps(&state, "lab");
        {
            let db = state.db.lock().unwrap();
            assert_eq!(held(&db), ["team"]);
            assert_eq!(said(&state, &db), ["team"]);
            assert_eq!(noted(&db), ["team"]);
        }
        assert!(!state.own_channels.first_fetch_done(&lab, now));

        // Sync is turned off: every word is taken back, and the name is
        // held still. Turned on again, it is said again.
        turns(&state, false);
        {
            let db = state.db.lock().unwrap();
            assert_eq!(held(&db), ["team"]);
            assert!(said(&state, &db).is_empty());
        }
        turns(&state, true);
        assert_eq!(said(&state, &state.db.lock().unwrap()), ["team"]);

        // A device that follows no phrase: its settings are set, and it
        // holds no name and says nothing.
        let alone = state_of(Machine::new(7));
        turns(&alone, true);
        maps(&alone, "/home/sam/notes", "lab");
        let db = alone.db.lock().unwrap();
        assert_eq!(mapped_names(&db).unwrap(), ["lab"]);
        assert!(held(&db).is_empty());
        assert!(said(&alone, &db).is_empty());
    }

    /// **A folder's unmapping does not let go of a name that a carry or a
    /// recovery holds** (decision 2026-10-04 §16). A name is held by a
    /// carry, with versions that no relay was sent; a folder is mapped to
    /// it, and unmapped before its first cycle. The name is then held as
    /// it was before the folder was mapped: with every version it had,
    /// said still, and by a carry. Unmapping the name is refused while no
    /// relay held a version of it that this device signed, when the
    /// relays were read (decision 2026-10-17 §4.2).
    ///
    /// Where nothing of the name waits, the folder's unmapping leaves it
    /// held all the same: it is the unmapping of the name that lets it
    /// go. A name that no carry holds goes with its folder, as it did.
    ///
    /// **The answer to the folder's unmapping names the name that is
    /// still held,** so that the command says so, and what lets go of
    /// it: and names none where the name went with its folder.
    #[test]
    fn test_a_folders_unmapping_does_not_let_go_of_a_name_that_a_carry_holds() {
        use crate::several::{Several, state_of};
        use cordelia_storage::at_relays as kept_rows;
        use cordelia_storage::person as held_rows;
        let home = std::path::Path::new("/home/sam");
        let mut s = Several::of_one_person(1);
        let now = s.tick();
        crate::names::hold_for_a_carry(&s[0].conn, &s[0].identity, "lab", now).unwrap();
        s.write(0, "lab", "a.md", "brought in by a carry");
        s.write(0, "lab", "b.md", "and this");
        let state = state_of(s.machines.remove(0));
        state.own_channels.set_up_with(1);
        let db = state.db.lock().unwrap();
        let on: SyncClaudeRequest =
            serde_json::from_value(serde_json::json!({ "enabled": true, "dir": DIR })).unwrap();
        set_claude(&state.sync_control, &db, &on, Some(home)).unwrap();

        // One settings command, as its handler runs it.
        let maps = |folder: &str, name: &str| {
            let before = mapped_names(&db).unwrap();
            let body = request(folder, name, false);
            add_mapping(&state.sync_control, &db, &body, home).unwrap();
            names_follow(&state, &db, &before);
        };
        // And what its answer says is still held.
        let unmaps = |word: &str| -> Option<String> {
            let before = mapped_names(&db).unwrap();
            let body = SyncUnmapRequest {
                folder: word.to_string(),
                read: None,
                ..Default::default()
            };
            remove_mapping(&state.sync_control, &db, &body).unwrap();
            names_follow(&state, &db, &before);
            still_held_by_a_carry(&db, &before)
        };
        let held = || -> Vec<String> {
            let names = held_rows::names(&db).unwrap();
            names.into_iter().map(|name| name.name).collect()
        };
        let said = || -> Vec<String> {
            let said = crate::names::said_here(&db, &state.identity).unwrap();
            said.into_iter().collect()
        };
        let by_a_carry =
            || -> Vec<String> { crate::names::carried(&db).unwrap().into_iter().collect() };
        let lab = held_rows::channel_of_name(&db, "lab").unwrap().unwrap();
        // The entries that the store holds of the name's channel, each
        // by what it is named by.
        let of_lab = || -> Vec<[u8; 32]> {
            let held = cordelia_storage::entries::channel_entries_after(&db, &lab, 0, 10).unwrap();
            held.iter().map(|held| held.entry.id()).collect()
        };
        let waits = || crate::names::waits_to_be_sent(&db, &state.identity, "lab").unwrap();
        // The name as the carry holds it, before any folder: with two
        // versions, which no relay was sent.
        let as_before_the_folder = || {
            (
                held(),
                said(),
                by_a_carry(),
                held_rows::channel_of_name(&db, "lab").unwrap(),
            )
        };
        let before_the_folder = as_before_the_folder();
        let carried_in = of_lab();
        let lab_alone = vec!["lab".to_string()];
        assert_eq!(
            before_the_folder,
            (
                lab_alone.clone(),
                lab_alone.clone(),
                lab_alone.clone(),
                Some(lab)
            )
        );
        assert_eq!((carried_in.len(), waits()), (2, 2));
        let at = std::time::Instant::now();
        state.own_channels.fetched_from(&lab, "relay", at);

        // A folder is mapped to the name, and unmapped before its first
        // cycle: by its folder, and by the name it is mapped to.
        for unmapped_by in ["/home/sam/notes", "lab"] {
            maps("/home/sam/notes", "lab");
            assert_eq!(mapped_names(&db).unwrap(), ["lab"]);
            // While the folder is mapped, nothing is said to be held
            // beside it.
            let mapped_now = mapped_names(&db).unwrap();
            assert_eq!(still_held_by_a_carry(&db, &mapped_now), None);
            assert_eq!(unmaps(unmapped_by).as_deref(), Some("lab"), "{unmapped_by}");
            assert!(mapped_names(&db).unwrap().is_empty());
            // Held as it was before the folder, with every version.
            assert_eq!(as_before_the_folder(), before_the_folder, "{unmapped_by}");
            assert_eq!(of_lab(), carried_in, "{unmapped_by}");
            assert_eq!(waits(), 2);
            assert!(state.own_channels.first_fetch_done(&lab, at));
        }
        // Unmapping the name meets the check before a let-go: it is
        // refused while no relay held what was brought in, when the
        // relays were read (decision 2026-10-17 §4.2).
        let (read, found) = read_of(&state, &db, "lab", &[("relay-one", &[])]);
        assert_eq!((found.asked, found.not_held.len()), (2, 2));
        let refusal = let_go_of_a_carried_name(&state, &db, "lab", Some((&read, &found)));
        let Err(ApiError::Conflict(why)) = &refusal else {
            panic!("{refusal:?}");
        };
        assert!(
            why.starts_with(
                "lab is not let go: no relay that this device is set up with held 2 of its \
                 versions when it was read just now."
            ),
            "{why}"
        );
        assert_eq!(of_lab(), carried_in);

        // A relay holds what was brought in, and the notes say so: the
        // folder's unmapping leaves the name held all the same, and the
        // unmapping of the name lets it go, once a read finds it there.
        let last = kept_rows::last_taken(&db, &lab).unwrap();
        kept_rows::sent(&db, &[0xa1; 32], &lab, last).unwrap();
        assert_eq!(waits(), 0);
        maps("/home/sam/notes", "lab");
        assert_eq!(unmaps("/home/sam/notes").as_deref(), Some("lab"));
        assert_eq!(as_before_the_folder(), before_the_folder);
        assert_eq!(of_lab(), carried_in);
        let at_the_relay = stored_of(&db, &lab);
        let (read, found) = read_of(&state, &db, "lab", &[("relay-one", &at_the_relay)]);
        assert!(found.each_held());
        assert!(let_go_of_a_carried_name(&state, &db, "lab", Some((&read, &found))).unwrap());
        assert!(held().is_empty() && said().is_empty() && by_a_carry().is_empty());
        assert!(of_lab().is_empty());
        assert!(!state.own_channels.first_fetch_done(&lab, at));
        assert!(!state.own_channels.reads().stands(&read));

        // A name that no carry holds is let go with its folder.
        maps("/home/sam/work", "team");
        assert_eq!(
            (held(), said()),
            (vec!["team".to_string()], vec!["team".to_string()])
        );
        assert_eq!(unmaps("/home/sam/work"), None);
        assert!(held().is_empty() && said().is_empty());
    }

    /// A name that the device holds by a carry, with no folder mapped to
    /// it, has no folder to unmap (decision 2026-10-04 §7.3): unmapping
    /// its name lets go of it. The device says no longer that it syncs
    /// it, and holds it no more; what its store held of the name's
    /// channel goes, and the channel is fetched again before a folder's
    /// first cycle there. Nothing is let go of that it does not hold so:
    /// a name that a folder is mapped to, and one that it does not hold.
    #[test]
    fn test_a_name_that_a_carry_holds_with_no_folder_is_let_go() {
        use crate::several::{Several, state_of};
        use cordelia_storage::person as held_rows;
        let home = std::path::Path::new("/home/sam");
        let mut s = Several::of_one_person(1);
        let now = s.tick();
        crate::names::hold_for_a_carry(&s[0].conn, &s[0].identity, "lab", now).unwrap();
        s.write(0, "lab", "a.md", "brought in by a carry");
        let state = state_of(s.machines.remove(0));
        state.own_channels.set_up_with(1);
        let db = state.db.lock().unwrap();
        let on: SyncClaudeRequest =
            serde_json::from_value(serde_json::json!({ "enabled": true, "dir": DIR })).unwrap();
        set_claude(&state.sync_control, &db, &on, Some(home)).unwrap();
        let before = mapped_names(&db).unwrap();
        let body = request("/home/sam/work", "team", false);
        add_mapping(&state.sync_control, &db, &body, home).unwrap();
        names_follow(&state, &db, &before);

        let held = |db: &rusqlite::Connection| -> Vec<String> {
            let names = held_rows::names(db).unwrap();
            names.into_iter().map(|name| name.name).collect()
        };
        let said = |db: &rusqlite::Connection| -> Vec<String> {
            let said = crate::names::said_here(db, &state.identity).unwrap();
            said.into_iter().collect()
        };
        let by_a_carry = |db: &rusqlite::Connection| -> Vec<String> {
            crate::names::carried(db).unwrap().into_iter().collect()
        };
        let lab = held_rows::channel_of_name(&db, "lab").unwrap().unwrap();
        let of_lab = |db: &rusqlite::Connection| {
            cordelia_storage::entries::channel_entries_after(db, &lab, 0, 10)
                .unwrap()
                .len()
        };
        assert_eq!(held(&db), ["lab", "team"]);
        assert_eq!(said(&db), ["lab", "team"]);
        assert_eq!(by_a_carry(&db), ["lab"]);
        assert_eq!(of_lab(&db), 1);
        let at = std::time::Instant::now();
        state.own_channels.fetched_from(&lab, "relay", at);
        assert!(state.own_channels.first_fetch_done(&lab, at));

        // A name that a folder is mapped to, and one that is not held:
        // neither is let go of, and nothing changes.
        for not_so in ["team", "never"] {
            assert!(!let_go_of_a_carried_name(&state, &db, not_so, None).unwrap());
        }
        assert_eq!(held(&db), ["lab", "team"]);
        assert_eq!(of_lab(&db), 1);

        // The name that the carry holds, while no relay held what was
        // brought in when it was read: it is not let go, the refusal says
        // how many versions and what each relay did, and nothing changes.
        // A relay had no room for it two minutes ago, by what the node
        // last said, and the other was not reached.
        let relay = [0xa1; 32];
        let last = cordelia_storage::at_relays::last_taken(&db, &lab).unwrap();
        cordelia_storage::at_relays::sent(&db, &relay, &lab, last).unwrap();
        cordelia_storage::at_relays::refused(&db, &relay, &lab, last).unwrap();
        let wall = chrono::Utc::now().timestamp();
        state.own_channels.say(crate::state::AtRelays {
            relays: vec![crate::state::AtRelay {
                relay: "relay-one".into(),
                holds_latest: Some(true),
                heard_since_woke: true,
                no_room: Some(crate::state::NoRoom {
                    at: wall - 150,
                    over_allowance: false,
                    of_the_change: false,
                }),
                another_form: 0,
                refuses: None,
                reach: Default::default(),
                key: None,
            }],
            cannot_go_on: None,
            word_to_come: false,
        });
        let (read, found) = read_at(
            &state,
            &db,
            "lab",
            &[
                ("relay-one", Some(relay), Some(&[])),
                ("relay-two", None, None),
            ],
        );
        let refusal = let_go_of_a_carried_name(&state, &db, "lab", Some((&read, &found)));
        let Err(ApiError::Conflict(why)) = &refusal else {
            panic!("{refusal:?}");
        };
        assert_eq!(
            *why,
            "lab is not let go: no relay that this device is set up with held 1 of its versions \
             when it was read just now.\n  relay-one: read to its end. It had no room for it, \
             the last time 2 minutes ago.\n  relay-two: not reached.\nThis device goes on \
             sending it, and lab can be let go once a relay holds it. To let it go now, with \
             it, run `cordelia sync unmap lab` at a terminal."
        );
        assert_eq!(held(&db), ["lab", "team"]);
        assert_eq!(said(&db), ["lab", "team"]);
        assert_eq!(by_a_carry(&db), ["lab"]);
        assert_eq!(of_lab(&db), 1);
        assert!(state.own_channels.first_fetch_done(&lab, at));
        // The read stands still: what was refused is not let go of it.
        assert!(state.own_channels.reads().stands(&read));

        // Of three versions, where a relay had no room for two of them:
        // so many are said, and of the relay.
        assert_eq!(
            crate::let_go::not_held_says(
                "lab",
                3,
                &["  relay-one: read in part. It had no room for 2 of them.".into()]
            ),
            "lab is not let go: no relay that this device is set up with held 3 of its versions \
             when it was read just now.\n  relay-one: read in part. It had no room for 2 of \
             them.\nThis device goes on sending them, and lab can be let go once a relay holds \
             them. To let it go now, with them, run `cordelia sync unmap lab` at a terminal."
        );

        // The relay holds it: the name is let go.
        let at_the_relay = stored_of(&db, &lab);
        let (read, found) = read_of(&state, &db, "lab", &[("relay-one", &at_the_relay)]);
        assert!(listed_alone(&state, &db));
        assert!(let_go_of_a_carried_name(&state, &db, "lab", Some((&read, &found))).unwrap());
        assert_eq!(held(&db), ["team"]);
        assert_eq!(said(&db), ["team"]);
        assert!(by_a_carry(&db).is_empty());
        assert_eq!(of_lab(&db), 0);
        assert!(!state.own_channels.first_fetch_done(&lab, at));
        // Once.
        assert!(!let_go_of_a_carried_name(&state, &db, "lab", None).unwrap());

        // A statement that lists another device does not list this one
        // alone: here, the device that added this one.
        let mut two = Several::of_one_person(2);
        let added = state_of(two.machines.remove(1));
        assert!(!listed_alone(&added, &added.db.lock().unwrap()));
    }

    // ── The read before a carried name is let go (decision 2026-10-17) ──

    /// The relay keys of the tests below.
    const ONE: [u8; 32] = [0xa1; 32];
    const TWO: [u8; 32] = [0xa2; 32];

    /// Device 0 of two, as a node, holding `lab` by a carry with no folder
    /// mapped to it, with a file of its own there: the entry that a read
    /// asks about. Returns the node, that entry, and the secret of the
    /// name's channel. The relays of a read are set by each test.
    fn holds_lab_by_a_carry() -> (
        crate::several::Node,
        cordelia_crypto::entry::CheckedEntry,
        [u8; 32],
    ) {
        let mut s = crate::several::Several::of_one_person(2);
        let now = s.tick();
        crate::names::hold_for_a_carry(&s[0].conn, &s[0].identity, "lab", now).unwrap();
        let mine = s.write(0, "lab", "a.md", "brought in by a carry");
        let secret = s[0].own("lab");
        let node = crate::several::Node::of(s.machines.remove(0));
        node.state.own_channels.set_up_with(1);
        (node, mine, secret)
    }

    /// A relay of a read that holds `entries` of the channel whose secret
    /// is `secret`.
    fn holding(
        name: &str,
        key: [u8; 32],
        secret: &[u8; 32],
        entries: &[cordelia_crypto::entry::CheckedEntry],
    ) -> crate::several::OwnRelay {
        let mut relay = crate::several::OwnRelay::new(name, key);
        let channel = cordelia_crypto::derive::channel_id(secret).unwrap();
        relay.holds.insert(channel, entries.to_vec());
        relay
    }

    /// `cordelia sync unmap <name>`, as the command asks it of the node:
    /// round after round, while the read goes on. Answers with the name
    /// that was let go and how many versions the read asked about, or the
    /// refusal.
    async fn lets_go(
        node: &crate::several::Node,
        name: &str,
    ) -> Result<(Option<String>, Option<usize>), ApiError> {
        let mut read = None;
        loop {
            let body = SyncUnmapRequest {
                folder: name.to_string(),
                read: read.take(),
                ..Default::default()
            };
            let answer = unmapped(&node.state, &body).await?;
            match &answer.reading {
                Some(reading) => read = Some(reading["read"].as_str().unwrap().to_string()),
                None => return Ok((answer.let_go, answer.let_go_versions)),
            }
        }
    }

    /// Whether the node still holds `name`.
    fn still_holds(node: &crate::several::Node, name: &str) -> bool {
        let db = node.state.db.lock().unwrap();
        cordelia_storage::person::channel_of_name(&db, name)
            .unwrap()
            .is_some()
    }

    /// **A version is held only where a relay that the device is set up
    /// with handed it, in a read that began after the person asked**
    /// (decision 2026-10-17 §4.2, §1 property 6). Each of these leaves the
    /// name held: a relay that the device is no longer set up with; one
    /// that refused the entry as not checking; one that holds another
    /// entry of the device's at that revision with another text; one that
    /// dropped the channel after the push; one that had no room; one read
    /// in part; the same version signed by a key that holds the secret and
    /// does not count. In each but the one with no room, the device's
    /// notes say that a relay was sent it. Each of these lets it go: the
    /// entry itself; the same version signed by another key that counts;
    /// an entry at a higher revision by a key that counts.
    #[actix_web::test]
    async fn test_a_version_is_held_only_where_a_relay_read_after_the_ask_handed_it() {
        use crate::several::{OwnRelay, entry_by, identity_of, text};
        use cordelia_storage::at_relays as kept_rows;
        let said = text("brought in by a carry");
        // What device 1, which counts, wrote in another slot: a relay
        // that holds the channel without the entry holds it.
        fn beside(secret: &[u8; 32]) -> cordelia_crypto::entry::CheckedEntry {
            crate::several::entry_by(&identity_of(1), secret, 1, "b.md", text("b"), &[])
        }
        type Case = Box<dyn Fn(&cordelia_crypto::entry::CheckedEntry, &[u8; 32]) -> Vec<OwnRelay>>;
        let held_by_none: Vec<(&str, [u8; 32], Case)> = vec![
            (
                "sent to a relay that it is no longer set up with",
                [0xa9; 32],
                Box::new(|_, secret| vec![holding("relay-one", ONE, secret, &[beside(secret)])]),
            ),
            (
                "refused as not checking",
                ONE,
                Box::new(|_, secret| vec![holding("relay-one", ONE, secret, &[beside(secret)])]),
            ),
            (
                "another entry of the device's at that revision",
                ONE,
                Box::new(|mine, secret| {
                    let other = text("another text at the same revision");
                    let another = entry_by(&identity_of(0), secret, mine.rev, "a.md", other, &[]);
                    vec![holding("relay-one", ONE, secret, &[another])]
                }),
            ),
            (
                "dropped the channel after the push",
                ONE,
                Box::new(|_, _| vec![OwnRelay::new("relay-one", ONE)]),
            ),
            (
                "read in part",
                ONE,
                Box::new(|mine, secret| {
                    let mut relay =
                        holding("relay-one", ONE, secret, &[beside(secret), mine.clone()]);
                    relay.per_round = 1;
                    relay.rounds_reached = Some(std::sync::Arc::new(1.into()));
                    vec![relay]
                }),
            ),
            (
                "the same version by a key that does not count",
                ONE,
                Box::new(|mine, secret| {
                    let said = text("brought in by a carry");
                    let not_counted =
                        entry_by(&identity_of(9), secret, mine.rev, "a.md", said, &[]);
                    vec![holding("relay-one", ONE, secret, &[not_counted])]
                }),
            ),
        ];
        for (case, sent_to, relays) in &held_by_none {
            let (node, mine, secret) = holds_lab_by_a_carry();
            {
                let db = node.state.db.lock().unwrap();
                let lab = cordelia_storage::person::channel_of_name(&db, "lab")
                    .unwrap()
                    .unwrap();
                let last = kept_rows::last_taken(&db, &lab).unwrap();
                kept_rows::sent(&db, sent_to, &lab, last).unwrap();
                // By the notes, nothing waits to be sent.
                assert_eq!(
                    crate::names::waits_to_be_sent(&db, &node.state.identity, "lab").unwrap(),
                    0,
                    "{case}"
                );
            }
            node.own_relays_are(relays(&mine, &secret));
            let refused = lets_go(&node, "lab").await;
            assert!(
                matches!(&refused, Err(ApiError::Conflict(why)) if why.starts_with(
                    "lab is not let go: no relay that this device is set up with held 1 of its \
                     versions"
                )),
                "{case}: {refused:?}"
            );
            assert!(still_holds(&node, "lab"), "{case}");
        }
        // A relay that had no room for it.
        let (node, mine, secret) = holds_lab_by_a_carry();
        {
            let db = node.state.db.lock().unwrap();
            let lab = cordelia_storage::person::channel_of_name(&db, "lab")
                .unwrap()
                .unwrap();
            let last = kept_rows::last_taken(&db, &lab).unwrap();
            kept_rows::sent(&db, &ONE, &lab, last).unwrap();
            kept_rows::refused(&db, &ONE, &lab, last).unwrap();
        }
        node.own_relays_are(vec![holding("relay-one", ONE, &secret, &[beside(&secret)])]);
        let refused = lets_go(&node, "lab").await;
        assert!(
            matches!(&refused, Err(ApiError::Conflict(why)) if why.contains(
                "  relay-one: read to its end. It had no room for it."
            )),
            "{refused:?}"
        );
        assert!(still_holds(&node, "lab"));
        let _ = mine;

        // Held, and let go: the entry itself, at one relay of two; the same
        // version by another key that counts; an entry above it by a key
        // that counts.
        let lets_it_go: Vec<(&str, Case)> = vec![
            (
                "the entry itself, at one relay",
                Box::new(|mine, secret| {
                    let mut away = OwnRelay::new("relay-two", TWO);
                    away.reached = false;
                    vec![
                        holding("relay-one", ONE, secret, std::slice::from_ref(mine)),
                        away,
                    ]
                }),
            ),
            (
                "the entry itself, at the second relay alone",
                Box::new(|mine, secret| {
                    vec![
                        OwnRelay::new("relay-one", ONE),
                        holding("relay-two", TWO, secret, std::slice::from_ref(mine)),
                    ]
                }),
            ),
            (
                "the same version by another key that counts",
                Box::new(|mine, secret| {
                    let said = text("brought in by a carry");
                    let same = entry_by(&identity_of(1), secret, mine.rev, "a.md", said, &[]);
                    vec![holding("relay-one", ONE, secret, &[same])]
                }),
            ),
            (
                "a version above it by a key that counts",
                Box::new(|mine, secret| {
                    let later = text("a later text");
                    let above = entry_by(&identity_of(1), secret, mine.rev + 1, "a.md", later, &[]);
                    vec![holding("relay-one", ONE, secret, &[above])]
                }),
            ),
        ];
        for (case, relays) in &lets_it_go {
            let (node, mine, secret) = holds_lab_by_a_carry();
            node.own_relays_are(relays(&mine, &secret));
            let done = lets_go(&node, "lab").await;
            assert!(
                matches!(&done, Ok((Some(name), Some(1))) if name == "lab"),
                "{case}: {done:?}"
            );
            assert!(!still_holds(&node, "lab"), "{case}");
        }
        let _ = said;
    }

    /// **An entry of this device's that lost a tie is held only where it
    /// was handed** (decision 2026-10-17 §4.2 items 4 and 5): the winner
    /// of the tie, handed alone, does not hold it, and the name stays
    /// held. Handed with the winner, it is held.
    #[actix_web::test]
    async fn test_an_entry_that_lost_a_tie_is_held_only_where_it_was_handed() {
        use crate::publish::value_hash;
        use crate::several::{Node, Several, text};
        // Two texts written apart at one revision: this device's is the
        // one with the lower hash, which loses.
        let (mine_said, theirs_said) = (0..)
            .map(|n| (format!("mine {n}"), "theirs".to_string()))
            .find(|(mine, theirs)| value_hash(&text(mine)) < value_hash(&text(theirs)))
            .unwrap();
        let fixture = || {
            let mut s = Several::of_one_person(2);
            let now = s.tick();
            crate::names::hold_for_a_carry(&s[0].conn, &s[0].identity, "lab", now).unwrap();
            s.hold(&[1], "lab");
            let mine = s.write(0, "lab", "a.md", &mine_said);
            let theirs = s.write(1, "lab", "a.md", &theirs_said);
            assert_eq!(mine.rev, theirs.rev);
            s.pass(1, 0);
            let current = s[0].slot("lab", "a.md").current.unwrap();
            assert_eq!(current.entries[0].author, s.key(1));
            let secret = s[0].own("lab");
            let node = Node::of(s.machines.remove(0));
            node.state.own_channels.set_up_with(1);
            (node, mine, theirs, secret)
        };
        let (node, _, theirs, secret) = fixture();
        node.own_relays_are(vec![holding("relay-one", ONE, &secret, &[theirs])]);
        let refused = lets_go(&node, "lab").await;
        assert!(matches!(refused, Err(ApiError::Conflict(_))), "{refused:?}");
        assert!(still_holds(&node, "lab"));

        let (node, mine, theirs, secret) = fixture();
        node.own_relays_are(vec![holding("relay-one", ONE, &secret, &[theirs, mine])]);
        let done = lets_go(&node, "lab").await;
        assert!(matches!(&done, Ok((Some(_), Some(1)))), "{done:?}");
        assert!(!still_holds(&node, "lab"));
    }

    /// **An entry that is no version moves nothing on** (decision
    /// 2026-10-17 §4.2 item 5): a relay hands, above the device's entry,
    /// an entry by a key that counts in a band above the statement, and
    /// one that does not open. Neither holds it, and the name stays held.
    #[actix_web::test]
    async fn test_an_entry_that_is_no_version_moves_nothing_on() {
        use crate::several::{entry_by, identity_of, signed_in, text};
        use cordelia_core::protocol::REV_COUNT_BITS;
        let (node, mine, secret) = holds_lab_by_a_carry();
        let band_above = (2u64 << REV_COUNT_BITS) + 1;
        let above_the_statement = entry_by(
            &identity_of(1),
            &secret,
            band_above,
            "a.md",
            text("above"),
            &[],
        );
        let does_not_open = signed_in(
            &secret,
            &identity_of(1),
            mine.slot,
            mine.rev + 1,
            vec![7; 256],
        );
        assert_eq!(above_the_statement.slot, mine.slot);
        for handed in [vec![above_the_statement], vec![does_not_open]] {
            node.own_relays_are(vec![holding("relay-one", ONE, &secret, &handed)]);
            let refused = lets_go(&node, "lab").await;
            assert!(matches!(refused, Err(ApiError::Conflict(_))), "{refused:?}");
            assert!(still_holds(&node, "lab"));
        }
        // Handed beside them, the entry itself is held.
        node.own_relays_are(vec![holding("relay-one", ONE, &secret, &[mine])]);
        assert!(lets_go(&node, "lab").await.is_ok());
    }

    /// **The read before a let-go keeps its own places** (decision
    /// 2026-10-17 §4.2 item 2): after it, the place that the device keeps
    /// at each relay, and how far it has sent each relay the channel, are
    /// as they were, though the read took a page there, and what another
    /// device wrote came in through the door.
    #[actix_web::test]
    async fn test_the_read_before_a_let_go_keeps_its_own_places() {
        use crate::several::{entry_by, identity_of, text};
        use cordelia_storage::at_relays as kept_rows;
        let (node, mine, secret) = holds_lab_by_a_carry();
        let theirs = entry_by(&identity_of(1), &secret, 1, "b.md", text("b"), &[]);
        let lab = cordelia_crypto::derive::channel_id(&secret).unwrap();
        let kept_at = |key: &[u8; 32]| {
            let db = node.state.db.lock().unwrap();
            kept_rows::kept(&db, key, &lab).unwrap()
        };
        {
            let db = node.state.db.lock().unwrap();
            kept_rows::keep_place(&db, &ONE, &lab, &[3; 8], 1).unwrap();
            kept_rows::sent(&db, &ONE, &lab, 1).unwrap();
        }
        let before = (kept_at(&ONE), kept_at(&TWO));
        // Each relay hands what another device wrote, and neither holds
        // the version: the name stays held, with what the read took.
        node.own_relays_are(vec![
            holding("relay-one", ONE, &secret, std::slice::from_ref(&theirs)),
            holding("relay-two", TWO, &secret, std::slice::from_ref(&theirs)),
        ]);
        assert!(lets_go(&node, "lab").await.is_err());
        let took = {
            let db = node.state.db.lock().unwrap();
            cordelia_storage::at_relays::holds_by(&db, &lab, &identity_of(1).public_key()).unwrap()
        };
        assert!(took);
        assert_eq!((kept_at(&ONE), kept_at(&TWO)), before);
        let _ = mine;
        assert_eq!(before.0.place, Some(([3; 8], 1)));
        assert_eq!(before.1, kept_rows::KeptThere::default());
    }

    /// **A let-go reads on until each version is found** (decision
    /// 2026-10-17 §4.2 item 1): a relay that hands a third of the channel
    /// at each round hands the device's entry in the third, and the name
    /// is let go then, with no fourth round. Each round but the last is
    /// answered with what each relay has handed so far.
    #[actix_web::test]
    async fn test_a_let_go_reads_on_until_each_version_is_found() {
        use crate::several::{entry_by, identity_of, text};
        use std::sync::atomic::Ordering::SeqCst;
        let (node, mine, secret) = holds_lab_by_a_carry();
        let mut channel: Vec<_> = (0..8)
            .map(|n| {
                let file = format!("{n}.md");
                entry_by(&identity_of(1), &secret, 1, &file, text("by device 1"), &[])
            })
            .collect();
        channel.push(mine);
        let mut relay = holding("relay-one", ONE, &secret, &channel);
        relay.per_round = 3;
        // The second holds none of it: it is not read on, nor said.
        node.own_relays_are(vec![relay, crate::several::OwnRelay::new("relay-two", TWO)]);
        // The first round, as the command sees it.
        let body = SyncUnmapRequest {
            folder: "lab".into(),
            read: None,
            ..Default::default()
        };
        let first = unmapped(&node.state, &body).await.unwrap();
        let reading = first.reading.unwrap();
        assert_eq!(reading["relays"][0]["relay"], "relay-one");
        assert_eq!(reading["relays"].as_array().unwrap().len(), 1);
        assert!(reading["relays"][0]["bytes"].as_u64().unwrap() > 3 * 1024);
        assert_eq!(first.let_go, None);
        let done = lets_go_on(&node, reading["read"].as_str().unwrap()).await;
        assert!(matches!(&done, Ok((Some(_), Some(1)))), "{done:?}");
        assert_eq!(node.own_rounds.load(SeqCst), 3);
        assert!(!still_holds(&node, "lab"));
    }

    /// [`lets_go`], from the read named `read`.
    async fn lets_go_on(
        node: &crate::several::Node,
        read: &str,
    ) -> Result<(Option<String>, Option<usize>), ApiError> {
        let mut read = Some(read.to_string());
        loop {
            let body = SyncUnmapRequest {
                folder: "lab".into(),
                read: read.take(),
                ..Default::default()
            };
            let answer = unmapped(&node.state, &body).await?;
            match &answer.reading {
                Some(reading) => read = Some(reading["read"].as_str().unwrap().to_string()),
                None => return Ok((answer.let_go, answer.let_go_versions)),
            }
        }
    }

    /// **A let-go lets go only of what was read** (decision 2026-10-17
    /// §4.2 item 8, §1 property 9): a read is made, and then the store
    /// takes an entry of the name: the let-go is refused, and says to run
    /// the command again. An ID that the node does not know is refused, and
    /// so is the ID of a read of another channel.
    #[actix_web::test]
    async fn test_a_let_go_lets_go_only_of_what_was_read() {
        use crate::several::{entry_by, identity_of, text};
        let (node, mine, secret) = holds_lab_by_a_carry();
        let state = &node.state;
        {
            let db = state.db.lock().unwrap();
            let (read, found) = read_of(state, &db, "lab", &[("relay-one", &[mine])]);
            assert!(found.each_held());
            let theirs = entry_by(&identity_of(1), &secret, 1, "b.md", text("b"), &[]);
            crate::take::take(&db, &state.identity, &theirs, 1).unwrap();
            let refused = let_go_of_a_carried_name(state, &db, "lab", Some((&read, &found)));
            let Err(ApiError::Conflict(why)) = &refused else {
                panic!("{refused:?}");
            };
            assert_eq!(
                *why,
                "lab is not let go: this device took something of it while it was read. Run \
                 `cordelia sync unmap lab` again."
            );
            assert!(
                cordelia_storage::person::channel_of_name(&db, "lab")
                    .unwrap()
                    .is_some()
            );
            // A read that the node keeps no more: it was started again.
            state.own_channels.reads().forget(&read);
            let refused = let_go_of_a_carried_name(state, &db, "lab", Some((&read, &found)));
            assert!(
                matches!(&refused, Err(ApiError::Conflict(why)) if *why == crate::let_go::started_again_says("lab")),
                "{refused:?}"
            );
        }
        for unknown in [hex::encode([9u8; 16])] {
            let body = SyncUnmapRequest {
                folder: "lab".into(),
                read: Some(unknown),
                ..Default::default()
            };
            let refused = unmapped(state, &body).await;
            assert!(
                matches!(&refused, Err(ApiError::Conflict(why)) if *why
                    == "lab is still held: the node was started again since lab was read. Run \
                        `cordelia sync unmap lab` again."),
                "{:?}",
                refused.err()
            );
        }
        // A read of another channel is not this name's.
        let other = {
            let db = state.db.lock().unwrap();
            let under = crate::at_relays::kept_id(&db).unwrap().unwrap();
            let now = std::time::Instant::now();
            state
                .own_channels
                .reads()
                .begin(&[4; 32], &under, &[], now)
                .unwrap()
        };
        let body = SyncUnmapRequest {
            folder: "lab".into(),
            read: Some(hex::encode(other)),
            ..Default::default()
        };
        assert!(matches!(
            unmapped(state, &body).await,
            Err(ApiError::Conflict(why)) if why == crate::let_go::started_again_says("lab")
        ));

        // A read that the node forgets while its round is asked for: the
        // node no longer keeps it when the round would read.
        let mut relay = holding("relay-one", ONE, &secret, &[]);
        relay.per_round = 1;
        relay.holds.values_mut().for_each(|held| {
            held.push(entry_by(
                &identity_of(1),
                &secret,
                1,
                "c.md",
                text("c"),
                &[],
            ));
            held.push(entry_by(
                &identity_of(1),
                &secret,
                1,
                "d.md",
                text("d"),
                &[],
            ));
        });
        node.own_relays_are(vec![relay]);
        let first = unmapped(
            state,
            &SyncUnmapRequest {
                folder: "lab".into(),
                read: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let read = first.reading.unwrap()["read"].as_str().unwrap().to_string();
        let held_round = node.own_round_waits.lock().await;
        let next = SyncUnmapRequest {
            folder: "lab".into(),
            read: Some(read.clone()),
            ..Default::default()
        };
        let (asked, ()) = tokio::join!(unmapped(state, &next), async {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            let id: crate::own_read::ReadId = hex::decode(&read).unwrap().try_into().unwrap();
            state.own_channels.reads().forget(&id);
            drop(held_round);
        });
        assert!(matches!(
            asked,
            Err(ApiError::Conflict(why)) if why == crate::let_go::started_again_says("lab")
        ));

        // A name that the device does not hold by a carry is no name to
        // let go.
        let never = SyncUnmapRequest {
            folder: "never".into(),
            read: None,
            ..Default::default()
        };
        assert!(matches!(
            unmapped(state, &never).await,
            Err(ApiError::BadRequest(_))
        ));

        // The name's channel is another since the read: it is not let go.
        {
            let db = state.db.lock().unwrap();
            let (read, found) = read_of(state, &db, "lab", &[]);
            assert_eq!(found.asked, 1);
            db.execute(
                "UPDATE person_names SET channel = ?1 WHERE name = 'lab'",
                [[8u8; 32].as_slice()],
            )
            .unwrap();
            let refused = let_go_of_a_carried_name(state, &db, "lab", Some((&read, &found)));
            assert!(
                matches!(&refused, Err(ApiError::Conflict(why)) if *why == crate::let_go::took_something_says("lab")),
                "{refused:?}"
            );
        }
        assert!(still_holds(&node, "lab"));

        // ── The word lets go only of what was read (decision 2026-10-17
        // §5.2, §1 property 9) ──
        use cordelia_core::protocol::LET_GO_READ_STANDS_SECS;
        let stands = std::time::Duration::from_secs(LET_GO_READ_STANDS_SECS);
        let changed = crate::let_go::changed_says("lab");
        fn refused_so<T>(refused: &Result<T, ApiError>, said: &str) -> bool {
            matches!(refused, Err(ApiError::Conflict(why)) if why == said)
        }
        // No relay holds the entry. A read is made, and then the store
        // takes an entry of the name: the word is refused.
        let (node, _, secret) = holds_lab_by_a_carry();
        let state = &node.state;
        node.own_relays_are(vec![holding("relay-one", ONE, &secret, &[])]);
        let asked = asked_the_word(&node, "lab").await;
        assert_eq!(asked["versions"], 1);
        {
            let db = state.db.lock().unwrap();
            let theirs = entry_by(&identity_of(1), &secret, 1, "b.md", text("b"), &[]);
            crate::take::take(&db, &state.identity, &theirs, 1).unwrap();
        }
        let refused = unmapped(state, &the_word("lab", &asked, 1)).await;
        assert!(refused_so(&refused, &changed), "{:?}", refused.err());
        assert!(still_holds(&node, "lab"));
        // A read older than LET_GO_READ_STANDS_SECS on the monotonic clock,
        // whatever the wall clock says.
        let asked = asked_the_word(&node, "lab").await;
        let read = word_read(&asked);
        {
            let db = state.db.lock().unwrap();
            let wall = chrono::Utc::now().timestamp();
            let late = std::time::Instant::now() + stands;
            let refused = discard_a_carried_name(state, &db, "lab", &read, 1, late, wall);
            assert!(refused_so(&refused, &changed), "{refused:?}");
        }
        assert!(still_holds(&node, "lab"));

        // A number that is not the one found; an ID the node does not
        // know; a word that is not the word: each is refused.
        let asked = asked_the_word(&node, "lab").await;
        let refused = unmapped(state, &the_word("lab", &asked, 2)).await;
        assert!(refused_so(&refused, &changed), "{:?}", refused.err());
        let unknown = SyncUnmapRequest {
            read: Some(hex::encode([9u8; 16])),
            ..the_word("lab", &asked, 1)
        };
        let refused = unmapped(state, &unknown).await;
        let again = crate::let_go::started_again_says("lab");
        assert!(refused_so(&refused, &again), "{:?}", refused.err());
        let yes = SyncUnmapRequest {
            word: Some("yes".into()),
            ..the_word("lab", &asked, 1)
        };
        let refused = unmapped(state, &yes).await;
        assert!(matches!(refused, Err(ApiError::BadRequest(_))));
        assert!(still_holds(&node, "lab"));
        // The name's channel is another since the read.
        let asked_again = asked_the_word(&node, "lab").await;
        {
            let db = state.db.lock().unwrap();
            let lab = cordelia_storage::person::channel_of_name(&db, "lab")
                .unwrap()
                .unwrap();
            db.execute(
                "UPDATE person_names SET channel = ?1 WHERE name = 'lab'",
                [[8u8; 32].as_slice()],
            )
            .unwrap();
            let read_again = word_read(&asked_again);
            let now = std::time::Instant::now();
            let wall = chrono::Utc::now().timestamp();
            let refused = discard_a_carried_name(state, &db, "lab", &read_again, 1, now, wall);
            assert!(refused_so(&refused, &changed), "{refused:?}");
            db.execute(
                "UPDATE person_names SET channel = ?1 WHERE name = 'lab'",
                [lab.as_slice()],
            )
            .unwrap();
        }
        let asked = asked_the_word(&node, "lab").await;
        let read = word_read(&asked);
        // In time on the monotonic clock, with the wall clock a day ahead:
        // the name goes, with the version, and the read with it.
        {
            let db = state.db.lock().unwrap();
            let in_time = std::time::Instant::now() + stands - std::time::Duration::from_secs(1);
            let wall = chrono::Utc::now().timestamp() + 86_400;
            let gone = discard_a_carried_name(state, &db, "lab", &read, 1, in_time, wall);
            assert!(matches!(gone, Ok(Some(1))), "{gone:?}");
        }
        assert!(!still_holds(&node, "lab"));
        assert!(!state.own_channels.reads().stands(&read));
    }

    /// **The read before a let-go does not hold the database's lock**
    /// (decision 2026-10-17 §4.2 item 3): while its round runs, another
    /// request is answered.
    #[actix_web::test]
    async fn test_the_read_before_a_let_go_does_not_hold_the_lock() {
        let (node, mine, secret) = holds_lab_by_a_carry();
        node.own_relays_are(vec![holding("relay-one", ONE, &secret, &[mine])]);
        let node = std::sync::Arc::new(node);
        let round = node.own_round_waits.clone().lock_owned().await;
        let asked = {
            let node = std::sync::Arc::clone(&node);
            tokio::spawn(async move { lets_go(&node, "lab").await.map_err(|e| e.to_string()) })
        };
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(!asked.is_finished());
        assert!(node.state.db.try_lock().is_ok());
        assert!(status(&node.state).is_ok());
        drop(round);
        let done = asked.await.unwrap();
        assert!(matches!(&done, Ok((Some(_), _))), "{done:?}");
    }

    /// **A folder's unmapping does not let go of a name that a carry
    /// brought versions into while the folder was mapped** (decision
    /// 2026-10-17 §4.3, §1 property 7): `cordelia sync carry` brings a
    /// version in through the carry by command, and the folder is
    /// unmapped. The name is held, and is a carried name: what a carry
    /// holds with no folder. It stays among those brought in, until the
    /// device stops it.
    #[actix_web::test]
    async fn test_a_name_a_carry_brought_versions_into_under_a_folder_is_held_after_the_folders_unmapping()
     {
        let node = left_a_version_of_lab();
        let home = std::path::Path::new("/home/sam");
        maps_lab(&node, home);
        let done = crate::carrying::carry_name(&node.state, "lab", false)
            .await
            .unwrap();
        assert_eq!(done.tally.carried, 1);
        let db = node.state.db.lock().unwrap();
        let lab = BTreeSetOf::from(["lab".to_string()]);
        assert_eq!(crate::names::brought_in(&db).unwrap(), lab);
        assert!(crate::names::carried(&db).unwrap().is_empty());
        // Sync is turned off: the word of the folder's name is taken back.
        let said = || crate::names::said_here(&db, &node.state.identity).unwrap();
        let off: SyncClaudeRequest =
            serde_json::from_value(serde_json::json!({ "enabled": false })).unwrap();
        let before = mapped_names(&db).unwrap();
        set_claude(&node.state.sync_control, &db, &off, Some(home)).unwrap();
        names_follow(&node.state, &db, &before);
        assert!(!said().contains("lab"));
        let before = mapped_names(&db).unwrap();
        assert_eq!(before, ["lab"]);
        let body = SyncUnmapRequest {
            folder: "/home/sam/notes".into(),
            read: None,
            ..Default::default()
        };
        remove_mapping(&node.state.sync_control, &db, &body).unwrap();
        names_follow(&node.state, &db, &before);
        assert_eq!(still_held_by_a_carry(&db, &before).as_deref(), Some("lab"));
        assert!(
            cordelia_storage::person::channel_of_name(&db, "lab")
                .unwrap()
                .is_some()
        );
        assert_eq!(crate::names::carried(&db).unwrap(), lab);
        assert_eq!(crate::names::brought_in(&db).unwrap(), lab);
        // It is said again, with sync off, as a name that a carry holds.
        assert!(said().contains("lab"));
        // The device stops it: it is among neither list any more.
        crate::names::stop(&db, &node.state.identity, "lab", 1).unwrap();
        assert!(crate::names::brought_in(&db).unwrap().is_empty());
        assert!(crate::names::carried(&db).unwrap().is_empty());
    }

    type BTreeSetOf = std::collections::BTreeSet<String>;

    /// Device 0 of three, as a node, after device 2 was removed: the relay
    /// holds, in the generation left, a file of `lab` that device 1 wrote,
    /// which device 0 never held. Sync is on.
    fn left_a_version_of_lab() -> crate::several::Node {
        use crate::several::{Node, Several};
        let mut s = Several::of_one_person(3);
        s.hold(&[1], "lab");
        let old = s[1].own("lab");
        s.write(1, "lab", "stays.md", "of device 1");
        let at_the_relay = s[1].stored_in(&old);
        s.change(0, &[0, 1], &[2]);
        let node = Node::of(s.machines.remove(0));
        node.relay_holds(&old, &at_the_relay);
        let db = node.state.db.lock().unwrap();
        let on: SyncClaudeRequest =
            serde_json::from_value(serde_json::json!({ "enabled": true, "dir": DIR })).unwrap();
        set_claude(
            &node.state.sync_control,
            &db,
            &on,
            Some(std::path::Path::new("/home/sam")),
        )
        .unwrap();
        drop(db);
        node
    }

    /// A folder is mapped to `lab`, as `cordelia sync map` stores it.
    fn maps_lab(node: &crate::several::Node, home: &std::path::Path) {
        let db = node.state.db.lock().unwrap();
        let before = mapped_names(&db).unwrap();
        add_mapping(
            &node.state.sync_control,
            &db,
            &request("/home/sam/notes", "lab", false),
            home,
        )
        .unwrap();
        names_follow(&node.state, &db, &before);
    }

    /// **Only a version brought in marks a name** (decision 2026-10-17
    /// §4.3): the carry that `cordelia sync map` makes brings a version
    /// into the folder's own name, and sets no mark; a carry by command
    /// that brings nothing, since the name holds it already, sets none.
    /// The folder's unmapping then stops the name, as any folder's.
    #[actix_web::test]
    async fn test_only_a_version_brought_in_marks_a_name() {
        let node = left_a_version_of_lab();
        maps_lab(&node, std::path::Path::new("/home/sam"));
        let mapped = crate::carrying::carry_name(&node.state, "lab", true)
            .await
            .unwrap();
        assert_eq!(mapped.tally.carried, 1);
        let again = crate::carrying::carry_name(&node.state, "lab", false)
            .await
            .unwrap();
        assert_eq!((again.tally.carried, again.tally.held), (0, 1));
        let db = node.state.db.lock().unwrap();
        assert!(crate::names::brought_in(&db).unwrap().is_empty());
        let before = mapped_names(&db).unwrap();
        let body = SyncUnmapRequest {
            folder: "lab".into(),
            read: None,
            ..Default::default()
        };
        remove_mapping(&node.state.sync_control, &db, &body).unwrap();
        names_follow(&node.state, &db, &before);
        assert_eq!(still_held_by_a_carry(&db, &before), None);
        assert!(
            cordelia_storage::person::channel_of_name(&db, "lab")
                .unwrap()
                .is_none()
        );
    }

    /// `cordelia sync unmap <name>` at a terminal, as the command asks it
    /// of the node: round after round, while the read goes on, until the
    /// node answers with what the command asks the word by. Any other
    /// answer fails the test.
    async fn asked_the_word(node: &crate::several::Node, name: &str) -> serde_json::Value {
        let mut read = None;
        loop {
            let body = SyncUnmapRequest {
                folder: name.to_string(),
                read: read.take(),
                asks: true,
                ..Default::default()
            };
            let answer = unmapped(&node.state, &body).await.unwrap();
            if let Some(reading) = &answer.reading {
                read = Some(reading["read"].as_str().unwrap().to_string());
                continue;
            }
            let Some(asked) = answer.not_let_go else {
                panic!("not asked: let go {:?}", answer.let_go);
            };
            return asked;
        }
    }

    /// The ID of the read that the node asks the word by.
    fn word_read(asked: &serde_json::Value) -> crate::own_read::ReadId {
        let read = hex::decode(asked["read"].as_str().unwrap()).unwrap();
        read.try_into().unwrap()
    }

    /// The word `discard`, as the command sends it after `asked`, with
    /// `versions` as the number shown.
    fn the_word(name: &str, asked: &serde_json::Value, versions: usize) -> SyncUnmapRequest {
        SyncUnmapRequest {
            folder: name.to_string(),
            read: asked["read"].as_str().map(str::to_string),
            word: Some("discard".into()),
            versions: Some(versions),
            ..Default::default()
        }
    }

    /// **On a device that reads the relays, a carried name is let go with
    /// an entry that no relay holds only on the word** (decision
    /// 2026-10-17 §5.2, §1 property 5). With no terminal, the node refuses
    /// with the lines of §4.6, and the name stays. At a terminal, it
    /// answers in place of the refusal with those lines but the last, where
    /// the version may still be (here, for as long as the device holds the
    /// secret it left), the number found, and the ID the word is bound to:
    /// the name stays until the word comes. With the word, it goes, and
    /// the answer says how many versions went with it.
    #[actix_web::test]
    async fn test_a_carried_name_that_no_relay_holds_is_let_go_only_on_the_word() {
        let (node, _, secret) = holds_lab_by_a_carry();
        let state = &node.state;
        {
            let db = state.db.lock().unwrap();
            let left = chrono::Utc::now().timestamp() - 3600;
            cordelia_storage::person::keep_left_secret(&db, 9, &[9; 32], left).unwrap();
            // A folder was mapped to it, and was unmapped since.
            meta::set(&db, meta::PERSON_NAMES_BROUGHT_IN, r#"["lab"]"#).unwrap();
        }
        node.own_relays_are(vec![holding("relay-one", ONE, &secret, &[])]);
        let refused = lets_go(&node, "lab").await;
        let Err(ApiError::Conflict(why)) = &refused else {
            panic!("{refused:?}");
        };
        assert!(
            why.ends_with("run `cordelia sync unmap lab` at a terminal."),
            "{why}"
        );
        assert!(still_holds(&node, "lab"));

        let asked = asked_the_word(&node, "lab").await;
        assert!(still_holds(&node, "lab"));
        assert_eq!(asked["versions"], 1);
        assert_eq!(
            asked["said"],
            "lab is not let go: no relay that this device is set up with held 1 of its versions \
             when it was read just now.\n  relay-one: read to its end.\nThis device goes on \
             sending it, and lab can be let go once a relay holds it."
        );
        let held_for = asked["where"].as_str().unwrap();
        assert!(held_for.contains("for 90 more days at most"), "{held_for}");
        assert!(
            held_for.contains("A folder that was mapped to lab keeps its files"),
            "{held_for}"
        );
        assert_eq!(
            *why,
            format!(
                "{} {}",
                asked["said"].as_str().unwrap(),
                crate::let_go::at_a_terminal_says("lab", 1)
            )
        );
        // A let-go with no word, by the same read, is still refused.
        let read = word_read(&asked);
        let kept = state
            .own_channels
            .reads()
            .get(&read, std::time::Instant::now());
        let found = kept.and_then(|kept| kept.found).unwrap();
        assert_eq!(found.not_held.len(), 1);
        {
            let db = state.db.lock().unwrap();
            let refused = let_go_of_a_carried_name(state, &db, "lab", Some((&read, &found)));
            assert!(matches!(refused, Err(ApiError::Conflict(_))), "{refused:?}");
        }
        let gone = unmapped(state, &the_word("lab", &asked, 1)).await.unwrap();
        assert_eq!(gone.let_go.as_deref(), Some("lab"));
        assert_eq!(gone.let_go_discarded, Some(1));
        assert_eq!(gone.let_go_stopped, Some(false));
        assert_eq!(gone.let_go_versions, None);
        assert!(!still_holds(&node, "lab"));
        // The word again: the name is no longer held.
        let again = unmapped(state, &the_word("lab", &asked, 1)).await;
        assert!(
            matches!(again, Err(ApiError::BadRequest(_))),
            "{:?}",
            again.err()
        );
    }

    /// **The answer to a folder's unmapping that leaves a carried name held
    /// says whether this device has stopped** (decision 2026-10-17 §4.6):
    /// the command then says that nothing is sent again, and not that a
    /// relay is waited for.
    #[actix_web::test]
    async fn test_the_answer_to_a_folders_unmapping_says_whether_the_device_has_stopped() {
        for stopped in [false, true] {
            let node = left_a_version_of_lab();
            maps_lab(&node, std::path::Path::new("/home/sam"));
            let done = crate::carrying::carry_name(&node.state, "lab", false)
                .await
                .unwrap();
            assert_eq!(done.tally.carried, 1);
            if stopped {
                let db = node.state.db.lock().unwrap();
                let removed = cordelia_storage::person::State::Removed;
                cordelia_storage::person::set_state(&db, removed).unwrap();
            }
            let body = SyncUnmapRequest {
                folder: "/home/sam/notes".into(),
                ..Default::default()
            };
            let answer = unmapped(&node.state, &body).await.unwrap();
            assert_eq!(answer.still_held.as_deref(), Some("lab"));
            assert_eq!(answer.still_held_stopped, Some(stopped));
        }
    }

    /// **The word is asked only where the read still binds the let-go**
    /// (decision 2026-10-17 §4.2 item 8, §5.2): at a terminal, where the
    /// store took something of the name's channel since the read ended,
    /// the node answers with that refusal and asks no word; and where a
    /// folder was mapped to the name while the relays were read, it says
    /// that the folder holds the name, in place of the prompt.
    #[actix_web::test]
    async fn test_the_word_is_asked_only_where_the_read_still_binds_the_let_go() {
        use crate::several::{entry_by, identity_of, text};
        let (node, _, secret) = holds_lab_by_a_carry();
        let state = &node.state;
        // The store takes an entry of the name after the read has ended.
        {
            let db = state.db.lock().unwrap();
            let (read, found) = read_of(state, &db, "lab", &[]);
            assert!(!found.each_held());
            let theirs = entry_by(&identity_of(1), &secret, 1, "b.md", text("b"), &[]);
            crate::take::take(&db, &state.identity, &theirs, 1).unwrap();
            let asked = word_asked_after_a_read(state, &db, "lab", &read, &found);
            assert!(
                matches!(&asked, Err(ApiError::Conflict(why)) if *why == crate::let_go::took_something_says("lab")),
                "{asked:?}"
            );
        }
        // A folder is mapped to the name while the relays are read.
        let home = std::path::Path::new("/home/sam");
        {
            let db = state.db.lock().unwrap();
            let on: SyncClaudeRequest =
                serde_json::from_value(serde_json::json!({ "enabled": true, "dir": DIR })).unwrap();
            set_claude(&state.sync_control, &db, &on, Some(home)).unwrap();
        }
        node.own_relays_are(vec![holding("relay-one", ONE, &secret, &[])]);
        let held_round = node.own_round_waits.lock().await;
        let first = SyncUnmapRequest {
            folder: "lab".into(),
            asks: true,
            ..Default::default()
        };
        let (asked, ()) = tokio::join!(unmapped(state, &first), async {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            {
                let db = state.db.lock().unwrap();
                let before = mapped_names(&db).unwrap();
                let body = request("/home/sam/notes", "lab", false);
                add_mapping(&state.sync_control, &db, &body, home).unwrap();
                names_follow(state, &db, &before);
            }
            drop(held_round);
        });
        let Err(ApiError::Conflict(why)) = &asked else {
            panic!("asked the word: {:?}", asked.map(|a| a.not_let_go));
        };
        assert_eq!(*why, crate::let_go::folder_mapped_says("lab"));
        assert!(still_holds(&node, "lab"));
    }

    /// **A folder mapped to a carried name while the word is asked keeps
    /// the name** (decision 2026-10-17 §4.2 item 8, §5.2): the word is
    /// refused with a line of its own, which says that the folder holds
    /// the name now and gives no command to run again, since running the
    /// unmap again would unmap that folder. The folder stays mapped, and
    /// the name keeps its version. Once the folder is unmapped, a new read
    /// and the word let it go.
    #[actix_web::test]
    async fn test_a_folder_mapped_while_the_word_is_asked_keeps_the_name() {
        let (node, _, secret) = holds_lab_by_a_carry();
        let state = &node.state;
        let home = std::path::Path::new("/home/sam");
        {
            let db = state.db.lock().unwrap();
            let on: SyncClaudeRequest =
                serde_json::from_value(serde_json::json!({ "enabled": true, "dir": DIR })).unwrap();
            set_claude(&state.sync_control, &db, &on, Some(home)).unwrap();
        }
        node.own_relays_are(vec![holding("relay-one", ONE, &secret, &[])]);
        let asked = asked_the_word(&node, "lab").await;
        {
            let db = state.db.lock().unwrap();
            let before = mapped_names(&db).unwrap();
            let body = request("/home/sam/notes", "lab", false);
            add_mapping(&state.sync_control, &db, &body, home).unwrap();
            names_follow(state, &db, &before);
        }
        let refused = unmapped(state, &the_word("lab", &asked, 1)).await;
        let Err(ApiError::Conflict(why)) = &refused else {
            panic!("{:?}", refused.err());
        };
        assert_eq!(*why, crate::let_go::folder_mapped_says("lab"));
        assert_ne!(*why, crate::let_go::changed_says("lab"));
        assert!(!why.contains("unmap"), "{why}");
        assert!(still_holds(&node, "lab"));
        {
            let db = state.db.lock().unwrap();
            assert_eq!(mapped_names(&db).unwrap(), ["lab"]);
            let before = mapped_names(&db).unwrap();
            let body = SyncUnmapRequest {
                folder: "/home/sam/notes".into(),
                ..Default::default()
            };
            remove_mapping(&state.sync_control, &db, &body).unwrap();
            names_follow(state, &db, &before);
        }
        let asked = asked_the_word(&node, "lab").await;
        let gone = unmapped(state, &the_word("lab", &asked, 1)).await.unwrap();
        assert_eq!(gone.let_go_discarded, Some(1));
        assert!(!still_holds(&node, "lab"));
    }

    /// **A device that has stopped lets a carried name go at once where
    /// its own notes show nothing that it sent to no relay, and otherwise
    /// only on the word** (decision 2026-10-17 §4.4, §1 property 8). It
    /// reads no relay either way. Where its notes say that it sent the
    /// version it wrote to no relay, the name is not let go: with no
    /// terminal the node refuses, saying why the device stopped and what
    /// its notes say, and how to let it go now; at a terminal it answers
    /// with the count it took from its notes, under an ID. A `discard`
    /// with another number is refused, and so is one with that ID once
    /// it is older than LET_GO_READ_STANDS_SECS on the monotonic clock.
    /// With the number, in time, the name goes, with the version.
    #[actix_web::test]
    async fn test_a_stopped_device_lets_go_at_once_where_its_notes_show_nothing_unsent() {
        use cordelia_core::protocol::LET_GO_READ_STANDS_SECS;
        use cordelia_storage::at_relays as kept_rows;
        use cordelia_storage::person::{State, set_state};
        use std::sync::atomic::Ordering::SeqCst;
        let stands = std::time::Duration::from_secs(LET_GO_READ_STANDS_SECS);
        // Its notes say that it sent what it wrote to a relay: the name goes
        // at once, though no relay is read, and the relay holds none of it.
        let (node, _, secret) = holds_lab_by_a_carry();
        node.own_relays_are(vec![holding("relay-one", ONE, &secret, &[])]);
        {
            let db = node.state.db.lock().unwrap();
            let lab = cordelia_storage::person::channel_of_name(&db, "lab")
                .unwrap()
                .unwrap();
            let last = kept_rows::last_taken(&db, &lab).unwrap();
            kept_rows::sent(&db, &ONE, &lab, last).unwrap();
            set_state(&db, State::NotListed).unwrap();
        }
        let done = lets_go(&node, "lab").await;
        assert!(
            matches!(&done, Ok((Some(name), None)) if name == "lab"),
            "{done:?}"
        );
        assert_eq!(node.own_rounds.load(SeqCst), 0);
        assert!(!still_holds(&node, "lab"));
        // A name that it does not hold by a carry is no name to let go.
        let never = SyncUnmapRequest {
            folder: "never".into(),
            ..Default::default()
        };
        let refused = unmapped(&node.state, &never).await;
        assert!(matches!(refused, Err(ApiError::BadRequest(_))));

        // Its notes say that it sent what it wrote to no relay, though a
        // relay holds it: the device cannot know, and does not ask.
        let (node, mine, secret) = holds_lab_by_a_carry();
        node.own_relays_are(vec![holding("relay-one", ONE, &secret, &[mine])]);
        {
            let db = node.state.db.lock().unwrap();
            set_state(&db, State::Removed).unwrap();
        }
        let refused = lets_go(&node, "lab").await;
        let Err(ApiError::Conflict(why)) = &refused else {
            panic!("{refused:?}");
        };
        assert_eq!(
            *why,
            "This device has stopped (it was removed), and sends nothing more. It cannot read the \
             relays to learn whether they hold lab. Its own notes say that it sent 1 version of \
             lab, which it wrote or carried, to no relay. To let it go now, with it, run \
             `cordelia sync unmap lab` at a terminal."
        );
        assert!(still_holds(&node, "lab"));
        let asked = asked_the_word(&node, "lab").await;
        assert_eq!(asked["versions"], 1);
        assert_eq!(
            asked["said"],
            crate::let_go::stopped_says("lab", State::Removed, 1)
        );
        assert_eq!(
            asked["where"],
            "Letting lab go now drops that version from this device: it is on this device alone."
        );
        assert_eq!(node.own_rounds.load(SeqCst), 0);
        assert!(still_holds(&node, "lab"));
        // Another number.
        let changed = crate::let_go::changed_says("lab");
        let refused = unmapped(&node.state, &the_word("lab", &asked, 2)).await;
        assert!(
            matches!(&refused, Err(ApiError::Conflict(why)) if *why == changed),
            "{:?}",
            refused.err()
        );
        // Too old, on the monotonic clock.
        let read = word_read(&asked);
        {
            let db = node.state.db.lock().unwrap();
            let late = std::time::Instant::now() + stands;
            let wall = chrono::Utc::now().timestamp();
            let refused = discard_a_carried_name(&node.state, &db, "lab", &read, 1, late, wall);
            assert!(
                matches!(&refused, Err(ApiError::Conflict(why)) if *why == changed),
                "{refused:?}"
            );
        }
        assert!(still_holds(&node, "lab"));
        // Counted again, with the number and in time: the name goes. The
        // device holds a secret it left, and has stopped: the prompt says
        // that another device brings in again what a carry brought, and
        // not the days that this device holds the secret for.
        assert!(
            node.state
                .own_channels
                .reads()
                .gone(&read, std::time::Instant::now())
        );
        {
            let db = node.state.db.lock().unwrap();
            let left = chrono::Utc::now().timestamp() - 3600;
            cordelia_storage::person::keep_left_secret(&db, 9, &[9; 32], left).unwrap();
        }
        let asked = asked_the_word(&node, "lab").await;
        let held_for = asked["where"].as_str().unwrap();
        assert!(
            held_for.contains(
                "This device carries nothing while it has stopped: on another of your devices, \
                 `cordelia sync carry lab` brings in again"
            ),
            "{held_for}"
        );
        assert!(!held_for.contains("more days"), "{held_for}");
        let gone = unmapped(&node.state, &the_word("lab", &asked, 1))
            .await
            .unwrap();
        assert_eq!(gone.let_go.as_deref(), Some("lab"));
        assert_eq!(gone.let_go_discarded, Some(1));
        // It read no relay: what went is what its notes said.
        assert_eq!(gone.let_go_stopped, Some(true));
        // The statement lists this device alone: device 1 was added since.
        assert_eq!(gone.let_go_alone, Some(true));
        assert!(!still_holds(&node, "lab"));
        assert_eq!(node.own_rounds.load(SeqCst), 0);
        // The name is stopped: nothing is kept of its read that went.
        assert!(
            !node
                .state
                .own_channels
                .reads()
                .gone(&read, std::time::Instant::now())
        );
    }

    /// What is said of each relay where a carried name is not let go
    /// (decision 2026-10-17 §4.6): how its read ended.
    #[actix_web::test]
    async fn test_what_is_said_of_each_relay_where_a_name_is_not_let_go() {
        use crate::own_read::Handed;
        use crate::several::{RELAY_MARK, entry_by, identity_of, text};
        use cordelia_storage::relay::NO_MARK;
        let (node, _, secret) = holds_lab_by_a_carry();
        let state = &node.state;
        let db = state.db.lock().unwrap();
        let beside = [entry_by(
            &identity_of(1),
            &secret,
            1,
            "b.md",
            text("b"),
            &[],
        )];
        let lab = cordelia_storage::person::channel_of_name(&db, "lab")
            .unwrap()
            .unwrap();
        let under = crate::at_relays::kept_id(&db).unwrap().unwrap();
        let names: Vec<String> = ["one", "two", "three", "four", "five"]
            .iter()
            .map(|n| format!("relay-{n}"))
            .collect();
        let reads = state.own_channels.reads();
        let now = std::time::Instant::now();
        let read = reads.begin(&lab, &under, &names, now).unwrap();
        let (_, _, mut at) = reads.to_read(&read, now).unwrap();
        let page = |entries, mark, next| Handed::Page {
            entries,
            counted: 0,
            mark,
            next,
        };
        // To its end; none of it; part and then none; not reached; and
        // still reading at the bound.
        at[0].handed(page(&[], RELAY_MARK, 0));
        at[1].handed(page(&[], NO_MARK, 0));
        at[2].handed(page(&beside, RELAY_MARK, 1));
        at[2].handed(page(&[], NO_MARK, 0));
        at[3].not_reached();
        at[4].handed(page(&beside, RELAY_MARK, 1));
        reads.read(&read, at, now);
        let kept = reads.get(&read, now).unwrap();
        let found = crate::let_go::found(&db, &state.identity, "lab", &kept).unwrap();
        let said = crate::let_go::relays_say(&db, &kept, &found, &Default::default(), 0).unwrap();
        assert_eq!(
            said,
            [
                "  relay-one: read to its end.",
                "  relay-two: holds none of it.",
                "  relay-three: read in part.",
                "  relay-four: not reached.",
                "  relay-five: read in part, for 10 minutes.",
            ]
        );
    }

    /// **A folder mapped to a carried name while its relays were read keeps
    /// the name** (decision 2026-10-17 §4.2 item 8, §4.3): the lock is let
    /// go during the read, and a folder that is mapped takes nothing into
    /// the store until its first cycle, so the store's order does not show
    /// it. The let-go is refused, the folder stays mapped, and the name
    /// keeps its channel. Once the folder is unmapped again, a new read
    /// lets the name go.
    #[test]
    fn test_a_folder_mapped_while_the_relays_are_read_keeps_the_name() {
        use crate::several::{Several, state_of};
        use cordelia_storage::person as held_rows;
        let home = std::path::Path::new("/home/sam");
        let mut s = Several::of_one_person(1);
        let now = s.tick();
        crate::names::hold_for_a_carry(&s[0].conn, &s[0].identity, "lab", now).unwrap();
        s.write(0, "lab", "a.md", "brought in by a carry");
        let state = state_of(s.machines.remove(0));
        state.own_channels.set_up_with(1);
        let db = state.db.lock().unwrap();
        let on: SyncClaudeRequest =
            serde_json::from_value(serde_json::json!({ "enabled": true, "dir": DIR })).unwrap();
        set_claude(&state.sync_control, &db, &on, Some(home)).unwrap();
        let lab = held_rows::channel_of_name(&db, "lab").unwrap().unwrap();
        let at_the_relay = stored_of(&db, &lab);
        let (read, found) = read_of(&state, &db, "lab", &[("relay-one", &at_the_relay)]);
        assert!(found.each_held());

        // A folder is mapped to the name before the let-go takes the lock.
        let before = mapped_names(&db).unwrap();
        let body = request("/home/sam/notes", "lab", false);
        add_mapping(&state.sync_control, &db, &body, home).unwrap();
        names_follow(&state, &db, &before);
        let refused = let_go_of_a_carried_name(&state, &db, "lab", Some((&read, &found)));
        let Err(ApiError::Conflict(why)) = &refused else {
            panic!("{refused:?}");
        };
        assert_eq!(
            *why,
            "lab is still held: a folder was mapped to lab while the relays were read, and lab is \
             held by that folder now. Nothing was let go."
        );
        // Not the line of a refused word, and nothing that would unmap the
        // folder were it followed.
        assert_ne!(*why, crate::let_go::changed_says("lab"));
        assert!(!why.contains("unmap"), "{why}");
        assert_eq!(mapped_names(&db).unwrap(), ["lab"]);
        assert_eq!(held_rows::channel_of_name(&db, "lab").unwrap(), Some(lab));
        assert_eq!(stored_of(&db, &lab).len(), at_the_relay.len());

        // Unmapped again, the name is held by the carry, and a new read
        // lets it go.
        let before = mapped_names(&db).unwrap();
        let body = SyncUnmapRequest {
            folder: "/home/sam/notes".into(),
            read: None,
            ..Default::default()
        };
        remove_mapping(&state.sync_control, &db, &body).unwrap();
        names_follow(&state, &db, &before);
        let (read, found) = read_of(&state, &db, "lab", &[("relay-one", &at_the_relay)]);
        assert!(let_go_of_a_carried_name(&state, &db, "lab", Some((&read, &found))).unwrap());
        assert_eq!(held_rows::channel_of_name(&db, "lab").unwrap(), None);
    }

    /// Home memory's name is said as that in what the node says of a
    /// let-go, as the command says it, and is quoted in the command to
    /// copy.
    #[test]
    fn test_what_the_node_says_of_a_let_go_names_home_memory_as_that() {
        use crate::let_go::*;
        for said in [
            started_again_says("~"),
            took_something_says("~"),
            not_read_says("~"),
            not_held_says("~", 1, &[]),
            changed_says("~"),
        ] {
            assert!(said.starts_with("home memory is "), "{said}");
            assert!(said.contains("`cordelia sync unmap '~'`"), "{said}");
            assert!(!said.contains("~ is"), "{said}");
        }
        assert!(not_held_says("~", 2, &[]).contains(", and home memory can be let go once"));
        assert!(started_again_says("~").contains("since home memory was read"));
        // The line of a folder mapped during the read names it so, and
        // gives no command: the command would unmap that folder.
        let folder = folder_mapped_says("~");
        assert!(
            folder.starts_with("home memory is still held: a folder was mapped to home memory")
        );
        assert!(
            !folder.contains("~") && !folder.contains("cordelia"),
            "{folder}"
        );
        // The lines before a discard name it so too.
        let stopped = stopped_says("~", cordelia_storage::person::State::Removed, 1);
        assert!(
            stopped.contains("whether they hold home memory."),
            "{stopped}"
        );
        assert!(!stopped.contains("~"), "{stopped}");
    }
}
