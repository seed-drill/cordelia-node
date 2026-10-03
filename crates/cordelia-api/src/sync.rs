//! Switching sync adapters on and off, and reporting on them (decision
//! 2026-09-30-agent-memory-sync §4.5). The adapter itself runs in the node
//! (cordelia-sync); these handlers only set and read its settings.

use actix_web::{HttpRequest, HttpResponse, web};

use cordelia_storage::{meta, sync_state};

use crate::auth;
use crate::error::ApiError;
use crate::state::{AppState, SyncControl};
use crate::types::*;

/// The name home memory syncs under unless it is given another. No other
/// folder may take it: every device shows it as home memory.
const HOME_NAME: &str = "~";

fn mappings(db: &rusqlite::Connection) -> Result<Vec<SyncMapping>, ApiError> {
    Ok(meta::get(db, meta::SYNC_CLAUDE_MAPPINGS)?
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default())
}

fn store_mappings(db: &rusqlite::Connection, list: &[SyncMapping]) -> Result<(), ApiError> {
    let json = serde_json::to_string(list).map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(meta::set(db, meta::SYNC_CLAUDE_MAPPINGS, &json)?)
}

fn exclusions(db: &rusqlite::Connection) -> Result<Vec<String>, ApiError> {
    Ok(meta::get(db, meta::SYNC_CLAUDE_EXCLUDE)?
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default())
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
/// found by `all`, or a project name or prefix, lower case and without
/// `.git`.
fn clean_exclusion(entry: &str) -> Option<String> {
    let entry = entry.trim();
    if entry.starts_with('/') {
        return clean_path(entry);
    }
    let name = entry.trim_end_matches(".git").to_lowercase();
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

/// Forget what a mapped folder agreed with its channel. A folder that
/// stops syncing starts afresh if it syncs again: what it lost in between
/// is fetched back, never sent as deletes (decision 2026-09-30 §4.5). It is
/// done here, by the handler that stops the folder and under the lock it
/// holds, so that it is true by the time the command answers.
fn forget_mapping(db: &rusqlite::Connection, mapping: &SyncMapping) -> Result<(), ApiError> {
    if let Some(dir) = meta::get(db, meta::SYNC_CLAUDE_DIR)? {
        let forgotten = sync_state::forget_folder(db, &memory_folder(&dir, &mapping.folder))?;
        if forgotten > 0 {
            tracing::info!(folder = %mapping.folder, files = forgotten, "sync: forgot what the folder had agreed");
        }
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

        // The scope is stored before the directory that turns sync on, so
        // that sync is never on with its scope left to be implied.
        let was_all = meta::get(db, meta::SYNC_CLAUDE_ALL)?.is_some_and(|v| v == "on");
        let all = body.all.unwrap_or(was_all && !body.reset);
        if all != was_all {
            tracing::info!(all, "sync: scope changed");
        }
        meta::set(db, meta::SYNC_CLAUDE_ALL, if all { "on" } else { "off" })?;
        // Whether anything found by `all` may have stopped syncing.
        let mut narrowed = was_all && !all;

        if body.reset {
            meta::remove(db, meta::SYNC_CLAUDE_EXCLUDE)?;
            meta::remove(db, meta::SYNC_CLAUDE_HOME)?;
            tracing::info!("sync: exclusions and the home setting reset");
        }
        if let Some(exclude) = &body.exclude {
            let cleaned: Vec<String> = exclude.iter().filter_map(|e| clean_exclusion(e)).collect();
            let before = exclusions(db)?;
            if cleaned != before {
                tracing::info!(exclude = ?cleaned, "sync: exclusions changed");
            }
            narrowed |= cleaned.iter().any(|e| !before.contains(e));
            store_exclusions(db, &cleaned)?;
        }
        if let Some(on) = body.home {
            let was = meta::get(db, meta::SYNC_CLAUDE_HOME)?.is_none_or(|v| v != "off");
            if on != was {
                tracing::info!(home = on, "sync: home memory setting changed");
            }
            if on {
                meta::remove(db, meta::SYNC_CLAUDE_HOME)?;
            } else {
                // Off means off: not found by `all`, and not mapped,
                // whatever name the home directory was mapped under.
                meta::set(db, meta::SYNC_CLAUDE_HOME, "off")?;
                narrowed |= was;
                let mut list = mappings(db)?;
                if let Some(home) = home
                    && let Some(mapping) = unmap_home(&mut list, home)
                {
                    store_mappings(db, &list)?;
                    forget_mapping(db, &mapping)?;
                    tracing::info!(name = %mapping.name, "sync: home memory unmapped");
                }
            }
        }

        // What is no longer found starts afresh if it is found again.
        // Which folders those are is known only to a cycle, so every
        // folder that is not mapped forgets what it had agreed. So does
        // every folder when the Claude Code directory changes.
        let dir_changed = stored.as_deref().is_some_and(|was| was != dir);
        if narrowed || dir_changed {
            let mapped: Vec<String> = if dir_changed {
                Vec::new()
            } else {
                mappings(db)?
                    .iter()
                    .map(|m| memory_folder(&dir, &m.folder))
                    .collect()
            };
            sync_state::forget_folders_except(db, &mapped)?;
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
        if let Some(dir) = meta::get(db, meta::SYNC_CLAUDE_DIR)? {
            meta::set(db, meta::SYNC_CLAUDE_LAST_DIR, &dir)?;
        }
        meta::remove(db, meta::SYNC_CLAUDE_DIR)?;
        // Nothing syncs now. Turned on again, every folder merges.
        sync_state::forget_folders_except(db, &[])?;
        tracing::info!("sync: turned off");
    }
    meta::remove(db, meta::SYNC_CLAUDE_REPORT)?;
    control.changed(db);
    Ok(())
}

/// Turn the adapter on or off, and set what it syncs (see [`set_claude`]).
pub async fn claude(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SyncClaudeRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    let home = home_dir().ok();
    {
        let db = state
            .db
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        set_claude(&state.sync_control, &db, &body, home.as_deref())?;
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
fn check_mapping(
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
    if name == HOME_NAME && !is_home {
        return Err(format!(
            "{name:?} is the name of home memory, which every device maps from its home \
             directory: give this folder another name"
        ));
    }

    if let Some(mapped) = mapped {
        return Err(format!(
            "{folder} is already mapped to {:?}: unmap it first",
            mapped.name
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
        .find(|m| folder_name(&m.folder) == claude_folder)
    {
        return Err(format!(
            "Claude Code keeps {folder} and {} in one folder, and that one is mapped to {:?}",
            mapped.folder, mapped.name
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
    if let Some(mapping) = check_mapping(body, home_dir, &list).map_err(ApiError::BadRequest)? {
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
    control.changed(db);
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
        add_mapping(&state.sync_control, &db, &body, &home_dir)?;
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
/// syncs again when it is mapped again.
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
    let mut excluded = exclusions(db)?;
    for mapping in &gone {
        if !excluded.contains(&mapping.folder) {
            excluded.push(mapping.folder.clone());
        }
        forget_mapping(db, mapping)?;
        tracing::info!(folder = %mapping.folder, name = %mapping.name, "sync: mapping removed");
    }
    store_exclusions(db, &excluded)?;
    store_mappings(db, &kept)?;
    meta::remove(db, meta::SYNC_CLAUDE_REPORT)?;
    control.changed(db);
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
        remove_mapping(&state.sync_control, &db, &body)?;
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
            sync_state::save(&self.db, &memory, "grp_x", "notes.md", (Some([7; 32]), 1)).unwrap();
        }

        fn remembers(&self, folder: &str) -> bool {
            let memory = memory_folder(DIR, folder);
            !sync_state::load(&self.db, &memory, "grp_x")
                .unwrap()
                .is_empty()
        }
    }

    /// A folder that a command stops syncing has forgotten what it agreed
    /// with its channel by the time the command answers, and the others
    /// have not. So if it syncs again it merges: a file it lost in between
    /// is fetched back, and never sent as a delete, whether or not a cycle
    /// ran in between.
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
    }

    /// Narrowing what is found (`all` turned off, an exclusion added, home
    /// memory turned off) stops folders the handler cannot name: which
    /// folders are found is known only to a cycle. So every folder that is
    /// not mapped forgets, and mapped folders do not. A change of the
    /// Claude Code directory moves every folder, so all of them forget.
    #[test]
    fn test_a_narrower_scope_forgets_what_was_found() {
        let found = "/home/sam/code/app";
        let narrowings = [
            serde_json::json!({ "all": false }),
            serde_json::json!({ "exclude": ["github.com/client-co/*"] }),
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
        }

        let s = Settings::on();
        s.map("/home/sam/notes", "lab");
        s.agreed("/home/sam/notes");
        s.claude(serde_json::json!({ "dir": "/home/sam/.claude-other" }));
        assert!(!s.remembers("/home/sam/notes"));
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
        // stays out of what is found, so it is still that name.
        s.map(HOME, "crew");
        s.unmap("crew");
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
}
