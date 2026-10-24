//! Bearer token authentication.
//!
//! Spec: seed-drill/specs/channels-api.md §1.3

use actix_web::HttpRequest;
use subtle::ConstantTimeEq;

use crate::error::ApiError;
use crate::state::AppState;

/// Verify the bearer token from the Authorization header.
///
/// A request with the node's token is then refused where the node is
/// held up and does not answer it ([`crate::first_start::
/// refuse_while_held`], decision 2026-10-04 §10.1): every handler comes
/// through here before it does anything.
pub fn check_bearer(req: &HttpRequest, state: &AppState) -> Result<(), ApiError> {
    check_token(req, state)?;
    crate::first_start::refuse_while_held(req, state)
}

/// Verify the bearer token from the Authorization header, and nothing
/// else: no lock is taken. For a route that is answered whether or not the
/// node is held up, and that must take no lock (decision 2026-10-22 §1.1,
/// rule 3): whether a node is held up is read under a lock.
pub fn check_token(req: &HttpRequest, state: &AppState) -> Result<(), ApiError> {
    let header = req
        .headers()
        .get("authorization")
        .ok_or(ApiError::Unauthorized)?;

    let value = header.to_str().map_err(|_| ApiError::Unauthorized)?;

    if !value.starts_with("Bearer ") {
        return Err(ApiError::Unauthorized);
    }

    let token = &value[7..];
    if !is_the_token(token, &state.bearer_token) {
        return Err(ApiError::Unauthorized);
    }
    Ok(())
}

/// Whether `given` is the node's token, compared in constant time: how
/// long the comparison takes says nothing of how much of the token was
/// right. One of another length is refused, and that it is says only its
/// length.
fn is_the_token(given: &str, token: &str) -> bool {
    bool::from(given.as_bytes().ct_eq(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "a-token-of-the-node-0123456789";

    fn state() -> AppState {
        AppState {
            load: Default::default(),
            db: cordelia_core::lock::TimedLock::new(
                cordelia_storage::db::open_in_memory().unwrap(),
            ),
            identity: cordelia_crypto::identity::NodeIdentity::generate().unwrap(),
            bearer_token: TOKEN.into(),
            home_dir: std::env::temp_dir().join("cordelia-auth-test-no-such-directory"),
            started_at: std::time::Instant::now(),
            sync_errors: Default::default(),
            peers_hot: Default::default(),
            peers_warm: Default::default(),
            push_tx: None,
            announce_tx: None,
            peers: Default::default(),
            relays: Default::default(),
            outbox_refused: Default::default(),
            relist: Default::default(),
            sync_control: Default::default(),
            own_channels: Default::default(),
            held: Default::default(),
            history: Default::default(),
        }
    }

    /// Whether a request that carries `header` as its authorization is
    /// let through.
    fn lets_through(state: &AppState, header: &str) -> bool {
        let req = actix_web::test::TestRequest::default()
            .insert_header(("authorization", header))
            .to_http_request();
        check_bearer(&req, state).is_ok()
    }

    /// The node's token is let through; one of another length, longer or
    /// shorter, is refused, and so is one that differs from it only in
    /// its last byte, or only in its first.
    #[test]
    fn test_a_token_of_another_length_or_that_differs_in_its_last_byte_is_refused() {
        let state = state();
        assert!(lets_through(&state, &format!("Bearer {TOKEN}")));

        let mut last = TOKEN.to_string();
        last.pop();
        let shorter = last.clone();
        last.push('8');
        let mut first = TOKEN.to_string();
        first.replace_range(0..1, "b");
        let refused = [
            shorter,
            format!("{TOKEN}0"),
            last,
            first,
            String::new(),
            TOKEN.to_uppercase(),
        ];
        for token in refused {
            assert!(
                !lets_through(&state, &format!("Bearer {token}")),
                "{token:?}"
            );
            assert!(!is_the_token(&token, TOKEN), "{token:?}");
        }
        assert!(!lets_through(&state, TOKEN));
        assert!(!lets_through(&state, &format!("Basic {TOKEN}")));
    }
}
