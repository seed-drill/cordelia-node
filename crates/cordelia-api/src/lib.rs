//! REST API endpoints, bearer token auth, Prometheus metrics, health checks.
//!
//! Spec: seed-drill/specs/channels-api.md

pub mod auth;
pub mod devices;
pub mod error;
pub mod handlers;
pub mod membership;
pub mod state;
pub mod types;
pub mod verify;

use actix_web::web;

/// Configure all Channels API routes on the given scope.
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1/channels")
            // Named channels
            .route("/subscribe", web::post().to(handlers::subscribe))
            .route("/publish", web::post().to(handlers::publish))
            .route("/listen", web::post().to(handlers::listen))
            .route("/list", web::post().to(handlers::list))
            .route("/info", web::post().to(handlers::info))
            .route("/unsubscribe", web::post().to(handlers::unsubscribe))
            // DM
            .route("/dm", web::post().to(handlers::dm))
            .route("/list-dms", web::post().to(handlers::list_dms))
            // Groups
            .route("/group", web::post().to(handlers::group_create))
            .route("/group/invite", web::post().to(handlers::group_invite))
            .route("/group/remove", web::post().to(handlers::group_remove))
            .route("/list-groups", web::post().to(handlers::list_groups))
            // Key management
            .route("/rotate-psk", web::post().to(handlers::rotate_psk_handler))
            .route("/delete-item", web::post().to(handlers::delete_item))
            // Search
            .route("/search", web::post().to(handlers::search_handler))
            // Identity
            .route("/identity", web::post().to(handlers::identity)),
    );

    // Devices and invites (decision 2026-09-30-agent-memory-sync §4.1)
    cfg.service(
        web::scope("/api/v1/devices")
            .route("/add", web::post().to(devices::add))
            .route("/accept", web::post().to(devices::accept))
            .route("/remove", web::post().to(devices::remove))
            .route("/list", web::post().to(devices::list)),
    );
    cfg.service(
        web::scope("/api/v1/invites")
            .route("/list", web::post().to(devices::list_invites))
            .route("/process", web::post().to(devices::process)),
    );

    // Health check (GET, unauthenticated, operations.md §8)
    cfg.route("/api/v1/health", web::get().to(handlers::health));

    // Status (GET, authenticated, operations.md §8)
    cfg.route("/api/v1/status", web::get().to(handlers::status));

    // Prometheus metrics (GET, outside /channels scope per spec §3.15)
    cfg.route("/api/v1/metrics", web::get().to(handlers::metrics));
}
