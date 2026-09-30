//! Switching sync adapters on and off, and reporting on them (decision
//! 2026-09-30-agent-memory-sync §4.5). The adapter itself runs in the node
//! (cordelia-sync); these handlers only set and read its settings.

use actix_web::{HttpRequest, HttpResponse, web};

use cordelia_storage::meta;

use crate::auth;
use crate::error::ApiError;
use crate::state::AppState;
use crate::types::*;

fn status(state: &AppState) -> Result<SyncStatusResponse, ApiError> {
    let db = state
        .db
        .lock()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let dir = meta::get(&db, meta::SYNC_CLAUDE_DIR)?;
    let report =
        meta::get(&db, meta::SYNC_CLAUDE_REPORT)?.and_then(|r| serde_json::from_str(&r).ok());
    Ok(SyncStatusResponse {
        enabled: dir.is_some(),
        dir,
        report,
    })
}

// ── POST /api/v1/sync/claude ───────────────────────────────────────

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
            let dir = match &body.dir {
                Some(d) => d.clone(),
                None => std::env::var("HOME")
                    .map(|h| format!("{h}/.claude"))
                    .map_err(|_| ApiError::BadRequest("HOME is not set; pass dir".into()))?,
            };
            if !std::path::Path::new(&dir).is_absolute() {
                return Err(ApiError::BadRequest("dir must be an absolute path".into()));
            }
            meta::set(&db, meta::SYNC_CLAUDE_DIR, &dir)?;
        } else {
            meta::remove(&db, meta::SYNC_CLAUDE_DIR)?;
        }
        meta::remove(&db, meta::SYNC_CLAUDE_REPORT)?;
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
