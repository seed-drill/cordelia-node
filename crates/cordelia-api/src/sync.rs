//! Switching sync adapters on and off, and reporting on them (decision
//! 2026-09-30-agent-memory-sync §4.5). The adapter itself runs in the node
//! (cordelia-sync); these handlers only set and read its settings.

use actix_web::{HttpRequest, HttpResponse, web};

use cordelia_storage::meta;

use crate::auth;
use crate::error::ApiError;
use crate::state::AppState;
use crate::types::*;

/// The name home memory syncs under.
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
/// nothing a shell or a terminal would act on.
pub fn valid_sync_name(name: &str) -> bool {
    if name == HOME_NAME {
        return true;
    }
    !name.is_empty()
        && name.len() <= 200
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

/// Turn the adapter on or off, and set what it syncs. A setting that is
/// not given keeps its stored value, so running it again changes nothing,
/// and so does turning sync off and on again. `reset` puts the directory,
/// scope, home and exclude settings back to their defaults (declared
/// mappings stay). When first turned on, only declared mappings sync.
/// Turning home memory off also unmaps it.
pub async fn claude(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SyncClaudeRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    {
        let db = state
            .db
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        if body.enabled {
            let stored = meta::get(&db, meta::SYNC_CLAUDE_DIR)?;
            // The directory in use, or the one in use when sync was last on.
            let remembered = match &stored {
                Some(dir) => Some(dir.clone()),
                None => meta::get(&db, meta::SYNC_CLAUDE_LAST_DIR)?,
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

            // The scope is stored before the directory that turns sync on,
            // so that sync is never on with its scope left to be implied.
            let was_all = meta::get(&db, meta::SYNC_CLAUDE_ALL)?.is_some_and(|v| v == "on");
            let all = body.all.unwrap_or(was_all && !body.reset);
            if all != was_all {
                tracing::info!(all, "sync: scope changed");
            }
            meta::set(&db, meta::SYNC_CLAUDE_ALL, if all { "on" } else { "off" })?;

            if body.reset {
                meta::remove(&db, meta::SYNC_CLAUDE_EXCLUDE)?;
                meta::remove(&db, meta::SYNC_CLAUDE_HOME)?;
                tracing::info!("sync: exclusions and the home setting reset");
            }
            if let Some(exclude) = &body.exclude {
                let cleaned: Vec<String> =
                    exclude.iter().filter_map(|e| clean_exclusion(e)).collect();
                if cleaned != exclusions(&db)? {
                    tracing::info!(exclude = ?cleaned, "sync: exclusions changed");
                }
                store_exclusions(&db, &cleaned)?;
            }
            if let Some(home) = body.home {
                let was = meta::get(&db, meta::SYNC_CLAUDE_HOME)?.is_none_or(|v| v != "off");
                if home != was {
                    tracing::info!(home, "sync: home memory setting changed");
                }
                if home {
                    meta::remove(&db, meta::SYNC_CLAUDE_HOME)?;
                } else {
                    // Off means off: not found by `all`, and not mapped.
                    meta::set(&db, meta::SYNC_CLAUDE_HOME, "off")?;
                    let mut list = mappings(&db)?;
                    let before = list.len();
                    list.retain(|m| m.name != HOME_NAME);
                    if list.len() != before {
                        store_mappings(&db, &list)?;
                        tracing::info!("sync: home memory unmapped");
                    }
                }
            }

            if stored.as_deref() != Some(dir.as_str()) {
                tracing::info!(%dir, "sync: Claude Code directory set");
            }
            meta::set(&db, meta::SYNC_CLAUDE_DIR, &dir)?;
            meta::remove(&db, meta::SYNC_CLAUDE_LAST_DIR)?;
        } else {
            if let Some(dir) = meta::get(&db, meta::SYNC_CLAUDE_DIR)? {
                meta::set(&db, meta::SYNC_CLAUDE_LAST_DIR, &dir)?;
            }
            meta::remove(&db, meta::SYNC_CLAUDE_DIR)?;
            tracing::info!("sync: turned off");
        }
        meta::remove(&db, meta::SYNC_CLAUDE_REPORT)?;
    }
    state.sync_control.changed();
    Ok(HttpResponse::Ok().json(status(&state)?))
}

// ── POST /api/v1/sync/map ──────────────────────────────────────────

/// A mapping as it is stored, or why it is refused: when it could sync
/// more than was meant (the home directory unless asked for, a folder
/// outside the home directory), or cannot be told apart from another (a
/// second name for a folder, a second folder for a name, two folders that
/// Claude Code keeps in one). `Ok(None)` if exactly this mapping is
/// already declared.
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
    let is_home = path == home_dir;
    if is_home && !request.home {
        return Err("that is the home directory: map it with --home to sync home memory".into());
    }
    if request.home && !is_home {
        return Err("--home maps the home directory itself".into());
    }
    let name = request.name.trim();
    if !valid_sync_name(name) || (name == HOME_NAME) != is_home {
        return Err(format!(
            "{name:?} is not a usable name: use lower-case letters, digits and . _ - / ~ + % @"
        ));
    }

    if let Some(mapped) = existing.iter().find(|m| m.folder == folder) {
        if mapped.name == name {
            return Ok(None);
        }
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

/// The home directory as Claude Code sees it: a real path.
fn home_dir() -> Result<std::path::PathBuf, ApiError> {
    let home = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .map_err(|_| ApiError::BadRequest("HOME is not set".into()))?;
    Ok(home.canonicalize().unwrap_or(home))
}

/// Declare that Claude's memory for a folder syncs under a name. The
/// folder is taken as given: the adapter syncs the Claude Code folder
/// named after it and no other. (Claude Code keeps one memory per git
/// repository, under its main working tree; `cordelia sync map` resolves
/// a folder to that before calling this.) Mapping a folder ends any
/// exclusion of it, and mapping home memory turns the home setting on.
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
        if meta::get(&db, meta::SYNC_CLAUDE_DIR)?.is_none() {
            return Err(ApiError::BadRequest(
                "sync is off: turn it on with `cordelia sync claude` first".into(),
            ));
        }
        let mut list = mappings(&db)?;
        if let Some(mapping) =
            check_mapping(&body, &home_dir, &list).map_err(ApiError::BadRequest)?
        {
            tracing::info!(folder = %mapping.folder, name = %mapping.name, "sync: mapping added");
            let excluded = exclusions(&db)?;
            if excluded.contains(&mapping.folder) {
                let kept: Vec<String> = excluded
                    .into_iter()
                    .filter(|e| *e != mapping.folder)
                    .collect();
                store_exclusions(&db, &kept)?;
            }
            if mapping.name == HOME_NAME {
                meta::remove(&db, meta::SYNC_CLAUDE_HOME)?;
            }
            list.push(mapping);
            store_mappings(&db, &list)?;
            meta::remove(&db, meta::SYNC_CLAUDE_REPORT)?;
        }
    }
    state.sync_control.changed();
    Ok(HttpResponse::Ok().json(status(&state)?))
}

// ── POST /api/v1/sync/unmap ────────────────────────────────────────

/// Stop syncing a mapped folder, given as the folder or as its name. Its
/// files stay where they are, and the name stays with this person's other
/// devices. The folder is also excluded, so that a device set to sync
/// everything it finds does not pick it up again under another name; it
/// syncs again when it is mapped again.
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
        let list = mappings(&db)?;
        let (gone, kept): (Vec<SyncMapping>, Vec<SyncMapping>) = list
            .into_iter()
            .partition(|m| m.folder == body.folder || m.name == body.folder);
        if gone.is_empty() {
            return Err(ApiError::BadRequest(format!(
                "{} is not mapped on this device",
                body.folder
            )));
        }
        let mut excluded = exclusions(&db)?;
        for mapping in &gone {
            if !excluded.contains(&mapping.folder) {
                excluded.push(mapping.folder.clone());
            }
            tracing::info!(folder = %mapping.folder, name = %mapping.name, "sync: mapping removed");
        }
        store_exclusions(&db, &excluded)?;
        store_mappings(&db, &kept)?;
        meta::remove(&db, meta::SYNC_CLAUDE_REPORT)?;
    }
    state.sync_control.changed();
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

        // A project under its remote, a folder under a label, home as `~`.
        assert_eq!(
            check(request("/home/sam/Work/cn", "github.com/o/cn", false), &[]),
            Some(stored("/home/sam/Work/cn", "github.com/o/cn"))
        );
        assert_eq!(
            check(request("/home/sam/notes", " lab-notes ", false), &[]),
            Some(stored("/home/sam/notes", "lab-notes"))
        );
        assert_eq!(
            check(request("/home/sam", "~", true), &[]),
            Some(stored("/home/sam", "~"))
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
            // Home memory only when asked for by name.
            (request("/home/sam", "everything", false), "--home"),
            (request("/home/sam/", "~", false), "--home"),
            (request("/home/sam/Work", "~", true), "--home"),
            (request("/home/sam/Work", "~", false), "not a usable name"),
            (request("/home/sam", "home", true), "not a usable name"),
            (
                request("/home/sam/Work", "Has Spaces", false),
                "not a usable name",
            ),
            (
                request("/home/sam/Work", "../x", false),
                "not a usable name",
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
}
