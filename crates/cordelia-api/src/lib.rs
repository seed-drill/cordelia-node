//! REST API endpoints, bearer token auth, Prometheus metrics, health checks.
//!
//! Spec: seed-drill/specs/channels-api.md

pub mod auth;
pub mod error;
pub mod handlers;
pub mod state;
pub mod types;

// TODO(WP5): Enrollment CLI endpoints.
// TODO(WP8): Search endpoint.
// TODO(WP13): CLI stats + Prometheus metrics.

use actix_web::web;

/// Configure all Channels API routes on the given scope.
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1/channels")
            .route("/subscribe", web::post().to(handlers::subscribe))
            .route("/publish", web::post().to(handlers::publish))
            .route("/listen", web::post().to(handlers::listen))
            .route("/list", web::post().to(handlers::list))
            .route("/info", web::post().to(handlers::info))
            .route("/unsubscribe", web::post().to(handlers::unsubscribe))
            .route("/identity", web::post().to(handlers::identity)),
    );
}
