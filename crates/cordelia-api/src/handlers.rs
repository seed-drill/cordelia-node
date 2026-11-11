//! Request handlers of the routes that a relay serves beside those of
//! any role: its status, metrics, peers, health and identity. Every
//! route of the older kind of channel is gone (decision 2026-11-10
//! (older kind), rule 2).
//!
//! Spec: seed-drill/specs/channels-api.md §3

use actix_web::{HttpRequest, HttpResponse, web};

use cordelia_crypto::bech32::{HRP_X25519_PK, encode_public_key};

use crate::auth;
use crate::error::ApiError;
use crate::state::AppState;
use crate::types::*;

// ── POST /api/v1/channels/identity ─────────────────────────────────

pub async fn identity(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    identity_with(req, state, true).await
}

/// How many channels a node says it has. No node carries the older kind
/// (decision 2026-11-10 (older kind), rule 3): a relay (`relay`) counts
/// the channels it holds, and a personal node the names that it holds,
/// each with its channel from the person's secret.
fn channels_it_has(db: &rusqlite::Connection, relay: bool) -> Result<usize, ApiError> {
    Ok(match relay {
        true => cordelia_storage::relay::count_held(db)? as usize,
        false => cordelia_storage::person::names(db)?.len(),
    })
}

/// A node's identity. `relay` says which channels it counts
/// ([`channels_it_has`]).
pub(crate) async fn identity_with(
    req: HttpRequest,
    state: web::Data<AppState>,
    relay: bool,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    let pk = state.identity.public_key();
    let ed_bech32 = encode_public_key(&pk).map_err(|e| ApiError::Internal(e.to_string()))?;

    let x_pub = state.identity.x25519_public_key();
    let x_bech32 = cordelia_crypto::bech32::bech32_encode(HRP_X25519_PK, &x_pub)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let db = state
        .db
        .lock()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let subscribed = channels_it_has(&db, relay)? as i64;

    Ok(HttpResponse::Ok().json(IdentityResponse {
        entity_id: String::new(), // TODO: load from config
        ed25519_public_key: ed_bech32.clone(),
        x25519_public_key: x_bech32,
        node_id: ed_bech32,
        channels_subscribed: subscribed,
        peers_connected: state.peers_hot.load(std::sync::atomic::Ordering::Relaxed) as i64,
    }))
}

// ── GET /api/v1/metrics/load ───────────────────────────────────────

/// The counters of the scale test (decision 2026-10-22 §1.1, rule 3;
/// §7.3), in the text form of `/api/v1/metrics`: what a relay is asked,
/// the waits and holds of the lock by kind, the connections, the governor,
/// and what a device asked of each relay.
///
/// **It takes no lock.** The bearer token is checked, and nothing else: a
/// GET is answered whether or not the node is held up, and whether it is
/// is read under a lock. Then the atomics are read. So a read neither
/// waits for the node's work nor holds it up, and reading it once a minute
/// changes nothing it measures; `/api/v1/metrics` takes the store's lock
/// to count channels and items, and is not used for this.
pub async fn metrics_load(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    auth::check_token(&req, &state)?;
    let body = cordelia_core::load::render(&state.load, state.db.times(), state.uptime_secs());
    Ok(HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(body))
}

// ── GET /api/v1/metrics ────────────────────────────────────────────

pub async fn metrics(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    metrics_with(req, state, true).await
}

/// A node's metrics. `relay` says whether the node is a relay, which
/// counts the channels it holds; a personal node counts the names it
/// holds. What either stores is counted as a device counts it: the
/// entries of channels from their secrets (decision 2026-11-10 (older
/// kind), rule 3).
pub(crate) async fn metrics_with(
    req: HttpRequest,
    state: web::Data<AppState>,
    relay: bool,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    let db = state
        .db
        .lock()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let uptime = state.uptime_secs();
    let channel_count = channels_it_has(&db, relay)?;

    // Storage bytes
    let db_path = state.home_dir.join("cordelia.db");
    let storage_bytes = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);

    let sync_errors = state.sync_error_count();
    let peers_hot = state.peers_hot.load(std::sync::atomic::Ordering::Relaxed);
    let peers_warm = state.peers_warm.load(std::sync::atomic::Ordering::Relaxed);
    let now = chrono::Utc::now().timestamp();
    let usage = cordelia_storage::usage::snapshot_of_a_device(&db, now)?;
    let usage_lines = format!(
        "# HELP cordelia_peers_seen Distinct peers connected in the window (counts only)\n\
         # TYPE cordelia_peers_seen gauge\n\
         cordelia_peers_seen{{window=\"1d\",role=\"node\"}} {}\n\
         cordelia_peers_seen{{window=\"1d\",role=\"relay\"}} {}\n\
         cordelia_peers_seen{{window=\"7d\",role=\"node\"}} {}\n\
         cordelia_peers_seen{{window=\"7d\",role=\"relay\"}} {}\n\
         \n\
         # HELP cordelia_channels_active Channels that received an item in the window\n\
         # TYPE cordelia_channels_active gauge\n\
         cordelia_channels_active{{window=\"1d\"}} {}\n\
         cordelia_channels_active{{window=\"7d\"}} {}\n\
         \n\
         # HELP cordelia_items_stored Items held by this node\n\
         # TYPE cordelia_items_stored gauge\n\
         cordelia_items_stored {}\n\
         \n\
         # HELP cordelia_content_bytes_stored Encrypted content held by this node\n\
         # TYPE cordelia_content_bytes_stored gauge\n\
         cordelia_content_bytes_stored {}\n",
        usage.peers_1d,
        usage.relays_1d,
        usage.peers_7d,
        usage.relays_7d,
        usage.channels_active_1d,
        usage.channels_active_7d,
        usage.items_stored,
        usage.bytes_stored,
    );

    let body = format!(
        "# HELP cordelia_uptime_seconds Node uptime\n\
         # TYPE cordelia_uptime_seconds gauge\n\
         cordelia_uptime_seconds {uptime:.1}\n\
         \n\
         # HELP cordelia_channels_subscribed Number of channels this node is subscribed to\n\
         # TYPE cordelia_channels_subscribed gauge\n\
         cordelia_channels_subscribed {channel_count}\n\
         \n\
         # HELP cordelia_storage_bytes Total storage used by SQLite database\n\
         # TYPE cordelia_storage_bytes gauge\n\
         cordelia_storage_bytes {storage_bytes}\n\
         \n\
         # HELP cordelia_sync_errors_total Cumulative replication sync errors\n\
         # TYPE cordelia_sync_errors_total counter\n\
         cordelia_sync_errors_total {sync_errors}\n\
         \n\
         # HELP cordelia_peers_hot Number of peers in Hot state\n\
         # TYPE cordelia_peers_hot gauge\n\
         cordelia_peers_hot {peers_hot}\n\
         \n\
         # HELP cordelia_peers_warm Number of peers in Warm state\n\
         # TYPE cordelia_peers_warm gauge\n\
         cordelia_peers_warm {peers_warm}\n\
         \n\
         {usage_lines}"
    );

    Ok(HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(body))
}

// ── GET /api/v1/peers ──────────────────────────────────────────────

/// The peers this node is connected to, and the relays it was configured
/// with, connected or not (`cordelia peers`).
pub async fn peers(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    let peers = state
        .peers
        .read()
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .clone();
    let relays = state
        .relays
        .read()
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .clone();
    Ok(HttpResponse::Ok().json(serde_json::json!({ "peers": peers, "relays": relays })))
}

// ── Health + Status ────────────────────────────────────────────────

/// GET /api/v1/health -- unauthenticated, returns 200 if node is running.
/// Used by Docker healthcheck and load balancers.
pub async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
}

/// GET /api/v1/status -- authenticated, returns node status with peer counts.
pub async fn status(
    state: web::Data<crate::state::AppState>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, crate::error::ApiError> {
    status_with(state, req, true).await
}

/// The status of a node. `relay` says whether the node is a relay: it
/// counts the channels it holds, and says nothing of messages or shared
/// channels. No node carries the older kind (decision 2026-11-10 (older
/// kind), rule 3): what a database may still hold of it is no part of
/// what waits to be sent.
pub(crate) async fn status_with(
    state: web::Data<crate::state::AppState>,
    req: actix_web::HttpRequest,
    relay: bool,
) -> Result<HttpResponse, crate::error::ApiError> {
    crate::auth::check_bearer(&req, &state)?;

    let uptime = state.uptime_secs();
    let peers_hot = state.peers_hot.load(std::sync::atomic::Ordering::Relaxed);
    let peers_warm = state.peers_warm.load(std::sync::atomic::Ordering::Relaxed);
    let sync_errors = state.sync_error_count();

    // What waits in a channel of the device's own, from its secret
    // (decision 2026-10-04 §8).
    let outbox_waiting = crate::commands::channels_waiting(&state);
    // What the `shared` object reads beside the database (decision
    // 2026-10-10 §9): the relays known by their keys, those connected, and
    // what the shared pass said. Read before the database is held.
    let own_relays = crate::sharing::own_relays(&state);
    let connected: Vec<[u8; 32]> = state
        .relays
        .read()
        .map(|relays| {
            relays
                .iter()
                .filter(|relay| relay.state == "connected")
                .filter_map(|relay| relay.key.as_deref())
                .filter_map(|key| cordelia_crypto::bech32::decode_public_key(key).ok())
                .collect()
        })
        .unwrap_or_default();
    let said = state.own_channels.shared_said();
    let db = state.db.lock().unwrap();
    let channels = channels_it_has(&db, relay).unwrap_or(0);

    // What a personal node that stands applied says of messages between
    // its person's agents (decision 2026-10-09 §8): an object of its own.
    // Of it, the command's level reads only `held_pairs`, the pairs held
    // for their person, an amber hold (decision 2026-10-25, rule 4). A
    // node that is held up reads nothing of its database.
    let messages = match relay || state.held.why().is_some() {
        true => None,
        false => crate::messages::status_of(
            &db,
            &state.identity,
            &state.own_channels,
            state.sync_control.now(),
        )
        .unwrap_or_else(|e| {
            // So that a field which comes and goes can be explained.
            tracing::warn!(error = %e, "the status says nothing of messages");
            None
        }),
    };
    // What it says of its shared channels (decision 2026-10-10 §9): an
    // object of its own, apart from `messages`, absent where the device
    // does not stand applied. Only one fact of it sets a level, and that
    // in the command.
    let shared = match relay || state.held.why().is_some() {
        true => None,
        false => {
            let beside = crate::shared_status::Beside {
                own_relays: &own_relays,
                connected: &connected,
                said: &said,
            };
            crate::shared_status::status_of(&db, &state.identity, &beside, state.sync_control.now())
                .unwrap_or_else(|e| {
                    tracing::debug!(error = %e, "the status says nothing of shared channels");
                    None
                })
        }
    };
    drop(db);

    let no_relay_secs = state
        .own_channels
        .no_relay_for(std::time::Instant::now())
        .map(|none_for| none_for.as_secs());

    // Why the node is held up, where it is (decision 2026-10-04 §10.1):
    // by what, and why in words for a person.
    let held = state
        .held
        .why()
        .map(|held| serde_json::json!({ "by": held.kind(), "why": held.says() }));

    let mut status = serde_json::json!({
        "status": "running",
        "held": held,
        // How many key files of an older version were left in place at
        // this start, since no copy holds them (decision 2026-10-04
        // §10.1).
        "key_files_in_place": state.held.key_files_in_place(),
        // So that a command can tell when the node is not the version it is.
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": uptime as u64,
        "peers_hot": peers_hot,
        "peers_warm": peers_warm,
        "channels_subscribed": channels,
        "sync_errors": sync_errors,
        "outbox_waiting": outbox_waiting,
        // For how long no relay has been connected, by the node's own
        // clock, which does not run while the machine sleeps (decision
        // 2026-10-04 §10.1). Null while one is connected.
        "no_relay_secs": no_relay_secs,
    });
    if let Some(messages) = messages {
        status["messages"] = messages.answered();
    }
    if let Some(shared) = shared {
        status["shared"] = shared;
    }
    Ok(HttpResponse::Ok().json(status))
}
