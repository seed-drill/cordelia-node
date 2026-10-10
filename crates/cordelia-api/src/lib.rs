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
//! What a relay holds of a generation that was left comes in only where
//! a person asks: the one function that judges a version for such a
//! carry, and a person's word for it, given with the phrase ([`carry`]);
//! the node's half of `cordelia sync carry` ([`carrying`]); and recovery,
//! on a machine that follows no phrase ([`recover`]).
//!
//! The commands a person types reach those through the routes of
//! [`commands`]. The sync adapter reads and publishes through [`publish`],
//! says which names a device syncs through [`names`], and a device's
//! local API for the names it holds is [`local`], through the same path.
//!
//! A personal node serves [`configure_device_routes`]: it carries no
//! channel of the older kind (decision 2026-10-04 §10). A node of any
//! other role serves [`configure_routes`], with the Channels API of the
//! older kind as it was.

pub mod adding;
pub mod at_relays;
pub mod auth;
pub mod carry;
pub mod carrying;
pub mod change;
pub mod commands;
pub mod entries;
pub mod error;
pub mod first_start;
pub mod found;
pub mod handlers;
pub mod history;
pub mod leaving;
pub mod local;
pub mod look;
pub mod names;
pub mod person;
pub mod publish;
pub mod reader;
pub mod recover;
pub mod sender;
#[cfg(test)]
mod several;
pub mod state;
pub mod swept;
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

    // Status (GET, authenticated, operations.md §8)
    cfg.route("/api/v1/status", web::get().to(handlers::status));
    // Prometheus metrics (GET, outside /channels scope per spec §3.15)
    cfg.route("/api/v1/metrics", web::get().to(handlers::metrics));
    shared_routes(cfg);
}

/// Configure the routes of a personal node (decision 2026-10-04 §10,
/// §16). It carries no channel of the older kind, so none of the Channels
/// API of that kind is served: no subscribing, no groups, no direct
/// channels, no keys to rotate. What it serves under the same paths is
/// the local API for the names it holds ([`local`]), whose publish goes
/// through the path that the sync adapter's goes through and says what
/// it was published over.
pub fn configure_device_routes(cfg: &mut web::ServiceConfig) {
    // How much of a request's body is read as JSON, and no more: what a
    // command hands the node is sized against it (§16).
    cfg.app_data(
        web::JsonConfig::default().limit(cordelia_core::protocol::LOCAL_API_BODY_MAX_BYTES),
    );
    cfg.service(
        web::scope("/api/v1/channels")
            .route("/publish", web::post().to(local::publish))
            .route("/entries", web::post().to(local::entries))
            .route("/delete-key", web::post().to(local::delete_key))
            .route("/identity", web::post().to(local::identity)),
    );
    // Status and metrics (GET, authenticated): of the device's own
    // channels, and of nothing of the older kind.
    cfg.route("/api/v1/status", web::get().to(local::status));
    cfg.route("/api/v1/metrics", web::get().to(local::metrics));
    shared_routes(cfg);
}

/// The routes that a node of any role serves.
fn shared_routes(cfg: &mut web::ServiceConfig) {
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
            .route("/leave/back", web::post().to(commands::leave_back))
            .route("/forget", web::post().to(commands::forget)),
    );
    cfg.route("/api/v1/phrase/make", web::post().to(commands::phrase_make));
    cfg.service(
        web::scope("/api/v1/change")
            .route("/prepare", web::post().to(commands::change_prepare))
            .route("/make", web::post().to(commands::change_make)),
    );
    // A carry that a person asks for (decision 2026-10-04 §7.3): of one
    // name, from the generations that the device left.
    // With the recovery phrase, which the command is typed and the node
    // never sees: what a removed key signed (`/from`), and what the
    // command read in a generation that this device never held
    // (`/phrase/look`, `/read`, `/handed`). What comes in by those comes
    // in under a word that the phrase signed.
    cfg.service(
        web::scope("/api/v1/carry")
            .route("", web::post().to(carrying::carry))
            .route("/from/look", web::post().to(carrying::from_look))
            .route("/from", web::post().to(carrying::from_take))
            .route("/phrase/look", web::post().to(carrying::phrase_look))
            .route("/sessions", web::post().to(carrying::sessions_now))
            .route("/read", web::post().to(carrying::read_proved))
            .route("/read/part", web::post().to(carrying::read_part))
            .route("/handed", web::post().to(carrying::handed_take)),
    );

    // Recovery (decision 2026-10-04 §9): the phrase is typed at the
    // command, which hands the node the change entry that it made, the
    // secrets of the generations before, which the machine keeps, and a
    // word for the look.
    cfg.service(
        web::scope("/api/v1/recover")
            .route("/look", web::post().to(recover::look))
            .route("/make", web::post().to(recover::make))
            .route("/progress", web::post().to(recover::progress)),
    );

    // Sync adapters (decision 2026-09-30-agent-memory-sync §4.5)
    cfg.service(
        web::scope("/api/v1/sync")
            .route("/claude", web::post().to(sync::claude))
            .route("/map", web::post().to(sync::map))
            .route("/unmap", web::post().to(sync::unmap))
            .route("/status", web::post().to(sync::sync_status))
            .route("/seen", web::post().to(sync::seen)),
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
}
