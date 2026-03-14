//! PSK-Exchange mini-protocol (0x07, §4.7).
//!
//! Request-response for channel PSK distribution. Used when a subscriber
//! needs the PSK for an open or gated channel from another node.
//!
//! Spec: seed-drill/specs/network-protocol.md §4.7

use crate::codec::{read_frame, read_protocol_byte, write_frame, write_protocol_byte};
use crate::messages::*;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, Error)]
pub enum PskExchangeError {
    #[error("codec error: {0}")]
    Codec(#[from] crate::codec::CodecError),

    #[error("unexpected message type")]
    UnexpectedMessage,

    #[error("PSK denied: {0}")]
    Denied(String),
}

/// PSK denial reasons (§4.7).
pub const REASON_NOT_FOUND: &str = "not_found";
pub const REASON_NOT_AUTHORIZED: &str = "not_authorized";
pub const REASON_NOT_AVAILABLE: &str = "not_available";

/// Request a PSK from a peer (subscriber side).
///
/// `subscriber_xpk` is the subscriber's X25519 public key for ECIES envelope.
pub async fn request_psk<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    channel_id: &str,
    subscriber_xpk: &[u8; 32],
) -> Result<PskResponse, PskExchangeError> {
    write_protocol_byte(stream, Protocol::PskExchange).await?;

    let req = WireMessage::PskRequest(PskRequest {
        channel_id: channel_id.to_string(),
        subscriber_xpk: subscriber_xpk.to_vec(),
    });
    write_frame(stream, &req).await?;

    let resp = read_frame(stream).await?;
    match resp {
        WireMessage::PskResponse(r) => {
            if r.status == "denied" {
                Err(PskExchangeError::Denied(r.reason.unwrap_or_default()))
            } else {
                Ok(r)
            }
        }
        _ => Err(PskExchangeError::UnexpectedMessage),
    }
}

/// Handle a PSK request (holder side).
///
/// `evaluate` receives (channel_id, subscriber_xpk) and returns a PskResponse.
pub async fn handle_psk_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    evaluate: impl FnOnce(&str, &[u8]) -> PskResponse,
) -> Result<String, PskExchangeError> {
    let proto = read_protocol_byte(stream).await?;
    if proto != Protocol::PskExchange {
        return Err(PskExchangeError::UnexpectedMessage);
    }

    let msg = read_frame(stream).await?;
    let req = match msg {
        WireMessage::PskRequest(r) => r,
        _ => return Err(PskExchangeError::UnexpectedMessage),
    };

    let response = evaluate(&req.channel_id, &req.subscriber_xpk);

    let resp = WireMessage::PskResponse(response);
    write_frame(stream, &resp).await?;

    Ok(req.channel_id)
}

/// Build a successful PSK response.
pub fn psk_ok(ecies_envelope: Vec<u8>, key_version: u32) -> PskResponse {
    PskResponse {
        status: "ok".into(),
        reason: None,
        ecies_envelope: Some(ecies_envelope),
        key_version: Some(key_version),
    }
}

/// Build a denied PSK response.
pub fn psk_denied(reason: &str) -> PskResponse {
    PskResponse {
        status: "denied".into(),
        reason: Some(reason.to_string()),
        ecies_envelope: None,
        key_version: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_psk_exchange_success() {
        let (mut client, mut server) = tokio::io::duplex(8192);

        let server_task = tokio::spawn(async move {
            handle_psk_request(&mut server, |ch, xpk| {
                assert_eq!(ch, "test_channel");
                assert_eq!(xpk.len(), 32);
                psk_ok(vec![0xEE; 92], 1)
            })
            .await
            .unwrap()
        });

        let xpk = [0xDD; 32];
        let resp = request_psk(&mut client, "test_channel", &xpk)
            .await
            .unwrap();
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.ecies_envelope.unwrap().len(), 92);
        assert_eq!(resp.key_version.unwrap(), 1);

        let channel = server_task.await.unwrap();
        assert_eq!(channel, "test_channel");
    }

    #[tokio::test]
    async fn test_psk_exchange_denied() {
        let (mut client, mut server) = tokio::io::duplex(8192);

        let server_task = tokio::spawn(async move {
            handle_psk_request(&mut server, |_ch, _xpk| psk_denied(REASON_NOT_FOUND))
                .await
                .unwrap()
        });

        let xpk = [0xDD; 32];
        let result = request_psk(&mut client, "unknown_channel", &xpk).await;
        assert!(matches!(result, Err(PskExchangeError::Denied(_))));
        if let Err(PskExchangeError::Denied(reason)) = result {
            assert_eq!(reason, REASON_NOT_FOUND);
        }

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_psk_exchange_not_authorized() {
        let (mut client, mut server) = tokio::io::duplex(8192);

        let server_task = tokio::spawn(async move {
            handle_psk_request(&mut server, |_ch, _xpk| psk_denied(REASON_NOT_AUTHORIZED))
                .await
                .unwrap()
        });

        let xpk = [0xDD; 32];
        let result = request_psk(&mut client, "invite_only_ch", &xpk).await;
        assert!(matches!(result, Err(PskExchangeError::Denied(_))));

        server_task.await.unwrap();
    }
}
