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
const HOME_NAME: &str = "~";

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
/// version could store one that ended in `.git`, which is read here as the
/// name a project is found under. A folder keeps a space at the end of
/// its name, since that is the text the adapter compares a directory
/// with; its separators are tidied, and one with `..` in it is dropped.
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
    let db = state
        .db
        .lock()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let dir = meta::get(&db, meta::SYNC_CLAUDE_DIR)?;
    let report =
        meta::get(&db, meta::SYNC_CLAUDE_REPORT)?.and_then(|r| serde_json::from_str(&r).ok());
    let home = meta::get(&db, meta::SYNC_CLAUDE_HOME)?.is_none_or(|v| v != "off");
    let last_change_at = meta::get(&db, meta::SYNC_CLAUDE_LAST_CHANGE)?;
    use cordelia_storage::person::State;
    let stands = match crate::at_relays::stands(&db) {
        Ok(crate::at_relays::Stands::NoPhrase) => "no_phrase",
        Ok(crate::at_relays::Stands::Applied) => "applied",
        Ok(crate::at_relays::Stands::Stopped(State::Fork)) => "fork",
        Ok(crate::at_relays::Stands::Stopped(State::Removed)) => "removed",
        Ok(crate::at_relays::Stands::Stopped(State::NotListed)) => "not_listed",
        Ok(crate::at_relays::Stands::Stopped(_)) => "not_opened",
        Err(e) => return Err(ApiError::Internal(e.to_string())),
    };
    Ok(SyncStatusResponse {
        enabled: dir.is_some(),
        dir,
        all: meta::get(&db, meta::SYNC_CLAUDE_ALL)?.is_some_and(|v| v == "on"),
        mappings: mappings(&db)?,
        exclude: exclusions(&db)?,
        home,
        home_name: meta::get(&db, meta::SYNC_CLAUDE_HOME_NAME)?,
        generation: state.sync_control.generation(),
        report,
        last_change_at,
        stands,
        held: state.held.why().map(|held| held.says().to_string()),
    })
}

/// An install from before mappings synced everything it found. Keep that
/// scope on upgrade, rather than silently stopping its sync: the scope is
/// only ever narrowed by its owner.
pub fn keep_earlier_scope(state: &AppState) -> Result<(), ApiError> {
    let db = state
        .db
        .lock()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    if meta::get(&db, meta::SYNC_CLAUDE_DIR)?.is_some()
        && meta::get(&db, meta::SYNC_CLAUDE_ALL)?.is_none()
    {
        meta::set(&db, meta::SYNC_CLAUDE_ALL, "on")?;
        tracing::info!(
            "sync: keeping the earlier scope (everything found); `cordelia sync claude --mapped-only` narrows it"
        );
    }
    Ok(())
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
fn clean_path(path: &str) -> Option<String> {
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

/// An exclusion as it is stored: a folder (an absolute path) that is never
/// found by `all`, or a project name or prefix in its one spelling
/// (`cordelia_core::sync_name::tidy`), which is the spelling a project is
/// found under. `None` for what is neither: a name of which nothing is
/// left, or a path with `..` in it.
///
/// A folder keeps a space at the end of its name: a folder's name can end
/// in one, and what is stored is the text a directory is compared with.
/// Its separators are tidied. So a list that is sent back as it was
/// stored is stored as it was.
///
/// The command line uses this too, so that what `include` looks for in
/// the list is spelled as the list spells it.
pub fn clean_exclusion(entry: &str) -> Option<String> {
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
/// 2026-09-30 §4.5). A handler knows which mapping it removes. It does not
/// know which folders a narrower scope no longer finds: that is known only
/// to a cycle. So every folder that is not mapped forgets, the folder of a
/// mapping just removed among them. A folder that is found and goes on
/// syncing pays for that with a merge it did not need.
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
/// changes nothing. `reset` puts the directory, scope, home and exclude
/// settings back to their defaults (declared mappings stay). When first
/// turned on, only declared mappings sync. Turning home memory off also
/// unmaps the home directory, whatever name it has.
pub fn set_claude(
    control: &SyncControl,
    db: &rusqlite::Connection,
    body: &SyncClaudeRequest,
    home: Option<&std::path::Path>,
) -> Result<(), ApiError> {
    if body.enabled {
        let stored = meta::get(db, meta::SYNC_CLAUDE_DIR)?;
        // The directory in use, or the one in use when sync was last on.
        let remembered = match &stored {
            Some(dir) => Some(dir.clone()),
            None => meta::get(db, meta::SYNC_CLAUDE_LAST_DIR)?,
        };
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

        // The scope is stored before the directory that turns sync on, so
        // that sync is never on with its scope left to be implied.
        let was_all = meta::get(db, meta::SYNC_CLAUDE_ALL)?.is_some_and(|v| v == "on");
        let all = body.all.unwrap_or(was_all && !body.reset);
        if all != was_all {
            tracing::info!(all, "sync: scope changed");
        }
        meta::set(db, meta::SYNC_CLAUDE_ALL, if all { "on" } else { "off" })?;
        // Whether anything found by `all` may have stopped syncing. It is
        // judged against what was set before this request: a reset with
        // the same setting given again narrows nothing.
        let mut narrowed = was_all && !all;
        let excluded_before = exclusions(db)?;
        let home_was = meta::get(db, meta::SYNC_CLAUDE_HOME)?.is_none_or(|v| v != "off");

        if body.reset {
            meta::remove(db, meta::SYNC_CLAUDE_EXCLUDE)?;
            meta::remove(db, meta::SYNC_CLAUDE_HOME)?;
            tracing::info!("sync: exclusions and the home setting reset");
        }
        if let Some(exclude) = &body.exclude {
            let cleaned: Vec<String> = exclude.iter().filter_map(|e| clean_exclusion(e)).collect();
            if cleaned != excluded_before {
                tracing::info!(exclude = ?cleaned, "sync: exclusions changed");
            }
            narrowed |= cleaned.iter().any(|e| !excluded_before.contains(e));
            store_exclusions(db, &cleaned)?;
        }
        if let Some(on) = body.home {
            if on != home_was {
                tracing::info!(home = on, "sync: home memory setting changed");
            }
            if on {
                meta::remove(db, meta::SYNC_CLAUDE_HOME)?;
            } else {
                // Off means off: not found by `all`, and not mapped,
                // whatever name the home directory was mapped under. Its
                // folder then forgets with the rest that is not mapped,
                // below: the setting was on if it was mapped, since
                // mapping it turns the setting on.
                meta::set(db, meta::SYNC_CLAUDE_HOME, "off")?;
                narrowed |= home_was;
                let mut list = mappings(db)?;
                if let Some(home) = home
                    && let Some(mapping) = unmap_home(&mut list, home)
                {
                    store_mappings(db, &list)?;
                    tracing::info!(name = %mapping.name, "sync: home memory unmapped");
                }
            }
        }

        // What is no longer found starts afresh if it is found again.
        // When the Claude Code directory changes, every folder does. The
        // directory is the string that is stored: the adapter is started
        // again for a new spelling of the same path, and records what its
        // folders agree under that.
        //
        // Nothing is agreed while sync is off. Turning it off forgets, and
        // so does turning it on, for whatever was left: an older version
        // forgot only later, in its loop, and a write may have failed.
        let dir_changed = stored.as_deref().is_some_and(|was| was != dir);
        if dir_changed || stored.is_none() {
            let forgotten = sync_state::forget_folders_except(db, &[])?;
            if forgotten > 0 {
                tracing::info!(
                    files = forgotten,
                    "sync: every folder forgot what it had agreed"
                );
            }
        } else if narrowed {
            forget_what_is_not_mapped(db, &dir)?;
        }

        if stored.as_deref() != Some(dir.as_str()) {
            tracing::info!(%dir, "sync: Claude Code directory set");
        }
        meta::set(db, meta::SYNC_CLAUDE_DIR, &dir)?;
        meta::remove(db, meta::SYNC_CLAUDE_LAST_DIR)?;

        // A home directory that is found, and not mapped, syncs as `~`.
        // That is then the name it has, to be put back under after an off.
        if let Some(home) = home
            && all
            && meta::get(db, meta::SYNC_CLAUDE_HOME)?.is_none_or(|v| v != "off")
            && !mappings(db)?.iter().any(|m| is_home_mapping(m, home))
            && !exclusions(db)?
                .iter()
                .any(|e| std::path::Path::new(e) == home)
        {
            meta::set(db, meta::SYNC_CLAUDE_HOME_NAME, HOME_NAME)?;
        }
    } else {
        control.changed(db);
        if let Some(dir) = meta::get(db, meta::SYNC_CLAUDE_DIR)? {
            meta::set(db, meta::SYNC_CLAUDE_LAST_DIR, &dir)?;
        }
        meta::remove(db, meta::SYNC_CLAUDE_DIR)?;
        // Nothing syncs now. Turned on again, every folder merges.
        sync_state::forget_folders_except(db, &[])?;
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
        for name in before.iter().filter(|name| !mapped.contains(name)) {
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

/// What `POST /api/v1/sync/map` does, with the database lock held: declare
/// that Claude's memory for a folder syncs under a name.
///
/// The folder is taken as given: the adapter syncs the Claude Code folder
/// named after it and no other. (Claude Code keeps one memory per git
/// repository, under its main working tree; `cordelia sync map` resolves
/// a folder to that before calling this.) Mapping a folder ends any
/// exclusion of it. Mapping the home directory, under any name, turns the
/// home setting on, and that name is the one it is put back under after
/// home memory has been turned off.
pub fn add_mapping(
    control: &SyncControl,
    db: &rusqlite::Connection,
    body: &SyncMapRequest,
    home_dir: &std::path::Path,
) -> Result<(), ApiError> {
    if meta::get(db, meta::SYNC_CLAUDE_DIR)?.is_none() {
        return Err(ApiError::BadRequest(
            "sync is off: turn it on with `cordelia sync claude` first".into(),
        ));
    }
    let mut list = mappings(db)?;
    let checked = check_mapping(body, home_dir, &list).map_err(ApiError::BadRequest)?;
    control.changed(db);
    if let Some(mapping) = checked {
        tracing::info!(folder = %mapping.folder, name = %mapping.name, "sync: mapping added");
        let excluded = exclusions(db)?;
        if excluded.contains(&mapping.folder) {
            let kept: Vec<String> = excluded
                .into_iter()
                .filter(|e| *e != mapping.folder)
                .collect();
            store_exclusions(db, &kept)?;
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

/// Declare that Claude's memory for a folder syncs under a name (see
/// [`add_mapping`]).
pub async fn map(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SyncMapRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    let home_dir = home_dir()?;
    {
        let db = state
            .db
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let before = mapped_names(&db)?;
        add_mapping(&state.sync_control, &db, &body, &home_dir)?;
        names_follow(&state, &db, &before);
    }
    Ok(HttpResponse::Ok().json(status(&state)?))
}

// ── POST /api/v1/sync/unmap ────────────────────────────────────────

/// What `POST /api/v1/sync/unmap` does, with the database lock held: stop
/// syncing a mapped folder, given as the folder or as its name.
///
/// Its files stay where they are, and the name stays with this person's
/// other devices. What the folder had agreed with its channel is forgotten,
/// so that mapped again it merges, and nothing it lost in between is sent
/// as a delete. The folder is also excluded, so that a device set to sync
/// everything it finds does not pick it up again under another name; it
/// syncs again when it is mapped again. That exclusion is a narrowing like
/// any other (see [`forget_what_is_not_mapped`]).
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
    let mut excluded = exclusions(db)?;
    for mapping in &gone {
        if !excluded.contains(&mapping.folder) {
            excluded.push(mapping.folder.clone());
        }
        tracing::info!(folder = %mapping.folder, name = %mapping.name, "sync: mapping removed");
    }
    store_exclusions(db, &excluded)?;
    store_mappings(db, &kept)?;
    // The folder forgets, and so does whatever else is not mapped: the
    // exclusion also keeps out anything found for the same directory (a
    // Claude Code folder laid out by hand can name it).
    if let Some(dir) = meta::get(db, meta::SYNC_CLAUDE_DIR)? {
        forget_what_is_not_mapped(db, &dir)?;
    }
    meta::remove(db, meta::SYNC_CLAUDE_REPORT)?;
    Ok(())
}

/// Stop syncing a mapped folder (see [`remove_mapping`]).
pub async fn unmap(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SyncUnmapRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    {
        let db = state
            .db
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let before = mapped_names(&db)?;
        remove_mapping(&state.sync_control, &db, &body)?;
        names_follow(&state, &db, &before);
    }
    Ok(HttpResponse::Ok().json(status(&state)?))
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
    /// whether or not a cycle ran in between.
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

        // Sync turned off: every folder.
        s.map("/home/sam/notes", "lab");
        agree(&s);
        s.claude(serde_json::json!({ "enabled": false }));
        assert_eq!(remembered(&s), Vec::<&str>::new());

        // And turned on: whatever was left agreed while it was off, as an
        // older version could leave it.
        agree(&s);
        s.claude(serde_json::json!({}));
        assert_eq!(remembered(&s), Vec::<&str>::new());
        // Run again while it is on, it forgets nothing.
        agree(&s);
        s.claude(serde_json::json!({}));
        assert_eq!(remembered(&s).len(), 3);
    }

    /// Narrowing what is found (`all` turned off, an exclusion added, home
    /// memory turned off, a folder unmapped and so kept out) stops folders
    /// the handler cannot name: which folders are found is known only to a
    /// cycle. So every folder that is not mapped forgets, and mapped
    /// folders do not. A request that narrows nothing forgets nothing. A
    /// change of the Claude Code directory moves every folder, so all of
    /// them forget.
    #[test]
    fn test_a_narrower_scope_forgets_what_was_found() {
        let found = "/home/sam/code/app";
        let kept_out = "github.com/client-co/*";
        let narrowings = [
            serde_json::json!({ "all": false }),
            serde_json::json!({ "exclude": [kept_out] }),
            serde_json::json!({ "home": false }),
        ];
        for narrowing in narrowings {
            let s = Settings::on();
            s.claude(serde_json::json!({ "all": true }));
            s.map("/home/sam/notes", "lab");
            s.agreed("/home/sam/notes");
            s.agreed(found);

            // Running it again, or widening, forgets nothing.
            s.claude(serde_json::json!({}));
            s.claude(serde_json::json!({ "all": true, "home": true, "exclude": [] }));
            assert!(s.remembers(found) && s.remembers("/home/sam/notes"));

            s.claude(narrowing.clone());
            assert!(!s.remembers(found), "{narrowing}");
            assert!(s.remembers("/home/sam/notes"), "{narrowing}");

            // The same request again narrows nothing more.
            s.agreed(found);
            s.claude(narrowing.clone());
            assert!(s.remembers(found), "{narrowing}, again");
        }

        // Nor does a reset with the same settings given again, or the
        // same exclusions in another order.
        let s = Settings::on();
        let narrow =
            serde_json::json!({ "all": true, "home": false, "exclude": [kept_out, "b/*"] });
        s.claude(narrow.clone());
        s.agreed(found);
        let mut again = narrow.clone();
        again["reset"] = true.into();
        again["dir"] = DIR.into();
        s.claude(again);
        s.claude(serde_json::json!({ "exclude": ["b/*", kept_out] }));
        assert!(s.remembers(found));

        // Unmapping a folder keeps out whatever is found for it too.
        let s = Settings::on();
        s.claude(serde_json::json!({ "all": true }));
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
    }

    /// Turning home memory off unmaps the home directory, so the node has
    /// to know where that is. Where it does not, the request is refused
    /// whole: nothing in it is stored, and nothing is counted as changed.
    #[test]
    fn test_home_memory_is_not_turned_off_where_home_is_not_known() {
        let s = Settings::on();
        s.map(HOME, "team");
        let count = s.control.generation();
        let body = serde_json::json!({ "enabled": true, "all": true, "home": false });
        let body: SyncClaudeRequest = serde_json::from_value(body).unwrap();
        assert!(set_claude(&s.control, &s.db, &body, None).is_err());
        assert_eq!(s.names(), ["team"]);
        let all = meta::get(&s.db, meta::SYNC_CLAUDE_ALL).unwrap();
        assert_ne!(all.as_deref(), Some("on"));
        assert_eq!(s.control.generation(), count);

        // Everything else is carried out without it.
        let body = serde_json::json!({ "enabled": true, "all": true });
        let body: SyncClaudeRequest = serde_json::from_value(body).unwrap();
        set_claude(&s.control, &s.db, &body, None).unwrap();
        assert_eq!(s.names(), ["team"]);
        let all = meta::get(&s.db, meta::SYNC_CLAUDE_ALL).unwrap();
        assert_eq!(all.as_deref(), Some("on"));
        assert!(s.control.generation() > count);
    }

    /// The name home memory is put back under is the name it last synced
    /// under on this device: the one it was mapped as, or `~` if it was
    /// found and not mapped. Turning it off does not change that, and
    /// neither does a setting that only looks as if home were found.
    #[test]
    fn test_the_name_home_last_synced_under_is_remembered() {
        let s = Settings::on();
        assert_eq!(s.home_name(), None);

        s.map(HOME, "team");
        assert_eq!(s.home_name().as_deref(), Some("team"));
        s.claude(serde_json::json!({ "home": false }));
        assert_eq!(s.names(), Vec::<String>::new());
        assert_eq!(s.home_name().as_deref(), Some("team"));

        // Everything found is turned on with home still off, and after a
        // reset: home is not found, so it has not synced as `~`.
        s.claude(serde_json::json!({ "all": true }));
        s.claude(serde_json::json!({ "reset": true, "all": true, "home": false }));
        assert_eq!(s.home_name().as_deref(), Some("team"));

        // Mapped under another name, then unmapped: an unmapped folder
        // stays out of what is found, so it is still that name, whatever
        // is set afterwards.
        s.map(HOME, "crew");
        s.unmap("crew");
        s.claude(serde_json::json!({ "all": true }));
        assert_eq!(s.home_name().as_deref(), Some("crew"));

        // Found, and syncing as `~`: once it is no longer kept out.
        s.claude(serde_json::json!({ "exclude": [] }));
        assert_eq!(s.home_name().as_deref(), Some("~"));
        // Turned off in the same request that stops everything found.
        s.claude(serde_json::json!({ "all": false, "home": false }));
        assert_eq!(s.home_name().as_deref(), Some("~"));

        // Not found while it is mapped: the name is the mapping's.
        s.map(HOME, "team");
        s.claude(serde_json::json!({ "all": true }));
        assert_eq!(s.home_name().as_deref(), Some("team"));
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
            "a narrower scope" => claude(s, serde_json::json!({ "enabled": true, "all": false })),
            // Its first write is the list of mappings; of a folder that
            // was unmapped, the exclusion that goes; of home, its name.
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
                };
                remove_mapping(&s.control, &s.db, &body)
            }
        };
        // The first thing each writes is a setting, and no setting can be
        // written: the change is counted, once, and nothing came of it.
        for which in [
            "sync off",
            "a narrower scope",
            "a mapping",
            "a mapping of a folder that was unmapped",
            "a mapping of home",
            "an unmapping",
        ] {
            let s = Settings::on();
            s.claude(serde_json::json!({ "all": true }));
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
        // Three of them also forget, later on, and the table of what
        // folders agreed is gone: counted all the same.
        for which in ["sync off", "a narrower scope", "an unmapping"] {
            let s = Settings::on();
            s.claude(serde_json::json!({ "all": true }));
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
        };
        assert!(remove_mapping(&s.control, &s.db, &body).is_err());
        let body = request("/srv/outside", "outside", false);
        assert!(add_mapping(&s.control, &s.db, &body, home).is_err());
        assert_eq!(s.control.generation(), before);
    }

    /// An exclusion is stored in the one spelling a project is found
    /// under, however it was typed and however often it is sent: the
    /// command tidies it, the node tidies it, and the node tidies the whole
    /// list again each time the list changes.
    #[test]
    fn test_an_exclusion_has_one_spelling() {
        let s = Settings::on();
        let typed = ["X.GIT", " Repo.git ", "client-co/*", "/home/sam//old/"];
        let stored = ["x", "repo", "client-co/*", "/home/sam/old"];
        s.claude(serde_json::json!({ "exclude": typed }));
        assert_eq!(exclusions(&s.db).unwrap(), stored);
        // Sent again as it is stored, as `exclude` and `include` send it.
        s.claude(serde_json::json!({ "exclude": stored }));
        assert_eq!(exclusions(&s.db).unwrap(), stored);
        // What the command looks for in the list is what the list holds:
        // the name as typed, tidied once by the command.
        for typed in ["X.GIT", "x.git", "X", "x.git.GIT", "x .git", "x/", "X.git/"] {
            let looked_for = cordelia_core::sync_name::tidy(typed);
            assert_eq!(looked_for, "x", "{typed}");
            assert_eq!(clean_exclusion(typed).as_deref(), Some("x"), "{typed}");
            assert_eq!(clean_exclusion(&looked_for).as_deref(), Some("x"));
        }
        // Nothing left is no exclusion.
        for nothing in [".git", "  ", ".GIT.git"] {
            assert_eq!(clean_exclusion(nothing), None, "{nothing:?}");
        }
        // A name an earlier version stored with `.git` at its end is read
        // as the name a project is found under, so the command finds it.
        // A folder keeps a space at the end of its name: it is the text
        // a directory is compared with.
        let stored = r#"["x.git","owner/repo/","/home/sam/old","/home/sam/odd "]"#;
        meta::set(&s.db, meta::SYNC_CLAUDE_EXCLUDE, stored).unwrap();
        assert_eq!(
            exclusions(&s.db).unwrap(),
            ["x", "owner/repo", "/home/sam/old", "/home/sam/odd "]
        );
        // And it is there, as it was, after a change that writes the list
        // again.
        s.map("/home/sam/notes", "lab");
        s.unmap("lab");
        let after = exclusions(&s.db).unwrap();
        assert!(after.contains(&"/home/sam/odd ".to_string()), "{after:?}");
        // The same when the whole list is sent back as it was read, which
        // is what `exclude` and `include` do.
        s.claude(serde_json::json!({ "exclude": after }));
        assert_eq!(exclusions(&s.db).unwrap(), after);
        assert_eq!(
            clean_exclusion("/home/sam/odd ").as_deref(),
            Some("/home/sam/odd ")
        );
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
        s.claude(serde_json::json!({ "all": true }));
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

        // Unmapped: said no longer, held no more, and fetched again
        // before a folder's first cycle there.
        unmaps(&state, "lab");
        {
            let db = state.db.lock().unwrap();
            assert_eq!(held(&db), ["team"]);
            assert_eq!(said(&state, &db), ["team"]);
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
}
