//! REST API endpoints, bearer token auth, Prometheus metrics, health checks.
//!
//! Spec: seed-drill/specs/channels-api.md
//!
//! Also here, and not yet used by the node, is what a device does under a
//! channel from its secret (decision 2026-10-04), as plain functions over
//! the node's database: what it holds of its person, who counts and how a
//! statement is applied ([`person`]); publishing in a name it holds, and
//! reading one ([`publish`]); the one door for an entry from outside
//! ([`take`]); adding a device, in its two halves ([`adding`]); the part
//! of a change that needs the phrase ([`change`]); and what a device does
//! at a relay for the channels of its own ([`at_relays`]), which the node
//! asks when it has leave to use a connection. No handler, command or
//! adapter calls them yet.

pub mod adding;
pub mod at_relays;
pub mod auth;
pub mod change;
pub mod devices;
pub mod entries;
pub mod error;
pub mod handlers;
pub mod history;
pub mod membership;
pub mod person;
pub mod publish;
#[cfg(test)]
mod several;
pub mod state;
pub mod sync;
pub mod take;
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
            .route("/entries", web::post().to(handlers::entries))
            .route("/delete-key", web::post().to(handlers::delete_key))
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

    // Sync adapters (decision 2026-09-30-agent-memory-sync §4.5)
    cfg.service(
        web::scope("/api/v1/sync")
            .route("/claude", web::post().to(sync::claude))
            .route("/map", web::post().to(sync::map))
            .route("/unmap", web::post().to(sync::unmap))
            .route("/status", web::post().to(sync::sync_status)),
    );
    // Local history (decision 2026-09-30-agent-memory-sync §4.5b)
    cfg.service(
        web::scope("/api/v1/history")
            .route("/list", web::post().to(history::list_handler))
            .route("/show", web::post().to(history::show_handler))
            .route("/restore", web::post().to(history::restore_handler))
            .route("/drop", web::post().to(history::drop_handler)),
    );

    // Health check (GET, unauthenticated, operations.md §8)
    cfg.route("/api/v1/health", web::get().to(handlers::health));

    // Connected peers (GET, authenticated)
    cfg.route("/api/v1/peers", web::get().to(handlers::peers));

    // Status (GET, authenticated, operations.md §8)
    cfg.route("/api/v1/status", web::get().to(handlers::status));

    // Prometheus metrics (GET, outside /channels scope per spec §3.15)
    cfg.route("/api/v1/metrics", web::get().to(handlers::metrics));
}
