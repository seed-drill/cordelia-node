//! REST API endpoints, bearer token auth, Prometheus metrics, health checks.
//!
//! Spec: seed-drill/specs/channels-api.md
//!
//! Also here is what a device does under a channel from its secret
//! (decision 2026-10-04), as plain functions over the node's database:
//! what it holds of its person, who counts and how a statement is applied
//! ([`person`]); publishing in a name it holds, and reading one
//! ([`publish`]); the one door for an entry from outside ([`take`]);
//! adding a device, in its two halves ([`adding`]); the part of a change
//! that needs the phrase ([`change`]); leaving a phrase ([`leaving`]);
//! what a device says of its person ([`look`]); and what a device does at
//! a relay for the channels of its own ([`at_relays`]), which the node
//! asks when it has leave to use a connection.
//!
//! The commands a person types reach those through the routes of
//! [`commands`]. The sync adapter does not yet: it still syncs the older
//! kind of channel, whose devices and invites have the routes of
//! [`devices`], under names that begin `old-`.

pub mod adding;
pub mod at_relays;
pub mod auth;
pub mod change;
pub mod commands;
pub mod devices;
pub mod entries;
pub mod error;
pub mod handlers;
pub mod history;
pub mod leaving;
pub mod look;
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

    // The devices and invites of the older kind of channel (decision
    // 2026-09-30-agent-memory-sync §4.1), which the sync adapter still
    // syncs.
    cfg.service(
        web::scope("/api/v1/old-devices")
            .route("/add", web::post().to(devices::add))
            .route("/accept", web::post().to(devices::accept))
            .route("/remove", web::post().to(devices::remove))
            .route("/list", web::post().to(devices::list)),
    );
    cfg.service(
        web::scope("/api/v1/old-invites")
            .route("/list", web::post().to(devices::list_invites))
            .route("/process", web::post().to(devices::process)),
    );

    // A person's devices, under a recovery phrase (decision 2026-10-04 §5
    // to §8). No route takes a phrase, and none asks a yes: the command
    // does both, at a terminal.
    cfg.service(
        web::scope("/api/v1/devices")
            .route("/list", web::post().to(commands::list))
            .route("/clear", web::post().to(commands::clear))
            .route("/add/look", web::post().to(commands::add_look))
            .route("/add", web::post().to(commands::add))
            .route("/accept", web::post().to(commands::accept))
            .route("/leave", web::post().to(commands::leave))
            .route("/leave/sent", web::post().to(commands::leave_sent))
            .route("/forget", web::post().to(commands::forget)),
    );
    cfg.route("/api/v1/phrase/make", web::post().to(commands::phrase_make));
    cfg.service(
        web::scope("/api/v1/change")
            .route("/prepare", web::post().to(commands::change_prepare))
            .route("/make", web::post().to(commands::change_make)),
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
