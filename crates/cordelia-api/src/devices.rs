//! Handlers for devices and invites (decision 2026-09-30-agent-memory-sync
//! §4.1). The logic lives in [`crate::membership`]; these only translate
//! between JSON and it.

use actix_web::{HttpRequest, HttpResponse, web};

use cordelia_crypto::bech32::{decode_public_key, encode_public_key};

use crate::auth;
use crate::error::ApiError;
use crate::membership;
use crate::state::AppState;
use crate::types::*;

fn decode_key(field: &str, value: &str) -> Result<[u8; 32], ApiError> {
    decode_public_key(value).map_err(|e| ApiError::BadRequest(format!("invalid {field}: {e}")))
}

fn encode_key(key: &[u8; 32]) -> Result<String, ApiError> {
    encode_public_key(key).map_err(|e| ApiError::Internal(e.to_string()))
}

fn summary_response(s: membership::InboxSummary) -> InboxSummaryResponse {
    InboxSummaryResponse {
        applied: s.applied,
        pending: s.pending,
        superseded: s.superseded,
        invalid: s.invalid,
        held: s.held,
        notes: s.notes,
    }
}

// ── POST /api/v1/devices/add ───────────────────────────────────────

pub async fn add(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<AddDeviceRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    let device = decode_key("device", &body.device)?;
    let outcome = membership::add_device(&state, &device, body.name.as_deref())?;
    Ok(HttpResponse::Ok().json(AddDeviceResponse {
        device: body.device.clone(),
        this_device: encode_key(&state.identity.public_key())?,
        personal_channel_id: outcome.personal_channel_id,
        channels: outcome.channels,
    }))
}

// ── POST /api/v1/devices/accept ────────────────────────────────────

pub async fn accept(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<AcceptRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    let key = decode_key("key", &body.key)?;
    let summary = membership::accept(&state, &key, body.name.as_deref())?;
    Ok(HttpResponse::Ok().json(summary_response(summary)))
}

// ── POST /api/v1/devices/remove ────────────────────────────────────

pub async fn remove(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<RemoveDeviceRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    let device = decode_key("device", &body.device)?;
    let outcome = membership::remove_device(&state, &device)?;
    Ok(HttpResponse::Ok().json(RemoveDeviceResponse {
        device: body.device.clone(),
        channels_rotated: outcome.channels_rotated,
    }))
}

// ── POST /api/v1/devices/list ──────────────────────────────────────

pub async fn list(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    let devices = membership::list_devices(&state)?
        .into_iter()
        .map(|d| {
            Ok(DeviceEntry {
                key: encode_key(&d.key)?,
                name: d.label,
                this_device: d.this_device,
                in_personal_channel: d.in_personal_channel,
                explicitly_trusted: d.explicitly_trusted,
                unconfirmed_since: d
                    .unconfirmed_since
                    .and_then(|at| chrono::DateTime::from_timestamp(at, 0))
                    .map(|at| at.to_rfc3339()),
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(HttpResponse::Ok().json(ListDevicesResponse { devices }))
}

// ── POST /api/v1/invites/list ──────────────────────────────────────

pub async fn list_invites(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    let pending = membership::list_pending(&state)?
        .into_iter()
        .map(|p| {
            Ok(PendingInviteEntry {
                item_id: p.item_id,
                from: encode_key(&p.inviter)?,
                channel_id: p.channel_id,
                received_at: p.received_at,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(HttpResponse::Ok().json(ListInvitesResponse { pending }))
}

// ── POST /api/v1/invites/process ───────────────────────────────────

/// Process the inbox now instead of waiting for the next sync cycle.
pub async fn process(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    let summary = membership::process_inbox(&state)?;
    Ok(HttpResponse::Ok().json(summary_response(summary)))
}
