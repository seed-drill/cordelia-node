//! Bearer token authentication.
//!
//! Spec: seed-drill/specs/channels-api.md §1.3

use actix_web::HttpRequest;

use crate::error::ApiError;
use crate::state::AppState;

/// Verify the bearer token from the Authorization header.
///
/// A request with the node's token is then refused where the node is
/// held up and does not answer it ([`crate::first_start::
/// refuse_while_held`], decision 2026-10-04 §10.1): every handler comes
/// through here before it does anything.
pub fn check_bearer(req: &HttpRequest, state: &AppState) -> Result<(), ApiError> {
    let header = req
        .headers()
        .get("authorization")
        .ok_or(ApiError::Unauthorized)?;

    let value = header.to_str().map_err(|_| ApiError::Unauthorized)?;

    if !value.starts_with("Bearer ") {
        return Err(ApiError::Unauthorized);
    }

    let token = &value[7..];
    if token != state.bearer_token {
        return Err(ApiError::Unauthorized);
    }

    crate::first_start::refuse_while_held(req, state)
}
