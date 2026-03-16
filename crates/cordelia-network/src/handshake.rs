//! Handshake mini-protocol (0x01, §4.1).
//!
//! One round-trip on stream 0, immediately after QUIC connection.
//! Both sides must complete before any other protocol stream opens.
//!
//! Validates: magic, version range, timestamp skew, identity binding.
//!
//! Spec: seed-drill/specs/network-protocol.md §4.1

use crate::codec::{read_frame, read_protocol_byte, write_frame, write_protocol_byte};
use crate::messages::*;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

/// Maximum clock skew tolerance (seconds, §4.1.5).
const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// Handshake timeout (seconds, §4.1.3).
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("codec error: {0}")]
    Codec(#[from] crate::codec::CodecError),

    #[error("rejected: {0}")]
    Rejected(String),

    #[error("invalid magic: 0x{0:08X}")]
    InvalidMagic(u32),

    #[error("incompatible version range")]
    IncompatibleVersion,

    #[error("clock skew too large: {delta}s (max {MAX_CLOCK_SKEW_SECS}s)")]
    ClockSkew { delta: u64 },

    #[error("identity mismatch: TLS node_id does not match handshake node_id")]
    IdentityMismatch,

    #[error("timeout")]
    Timeout,

    #[error("unexpected message type")]
    UnexpectedMessage,
}

impl HandshakeError {
    /// Safe reject_reason string for the peer (no information leakage).
    /// Per spec §4.1.5: clock skew reject MUST NOT include local time or delta.
    pub fn reject_reason(&self) -> String {
        match self {
            Self::InvalidMagic(_) => "invalid magic".to_string(),
            Self::IncompatibleVersion => "incompatible version range".to_string(),
            Self::ClockSkew { .. } => "clock skew".to_string(),
            Self::IdentityMismatch => "identity mismatch".to_string(),
            other => other.to_string(),
        }
    }
}

/// Result of a successful handshake.
#[derive(Debug, Clone)]
pub struct HandshakeResult {
    pub peer_node_id: [u8; 32],
    pub negotiated_version: u16,
    pub peer_channel_digest: [u8; 32],
    pub peer_channel_count: u16,
    pub peer_roles: Vec<String>,
    /// Peer's advertised P2P listening port (for peer-sharing address construction).
    pub peer_p2p_port: u16,
}

/// Compute the channel digest: SHA-256 of sorted channel IDs joined by newline.
pub fn compute_channel_digest(channel_ids: &[String]) -> [u8; 32] {
    let mut sorted: Vec<&str> = channel_ids.iter().map(|s| s.as_str()).collect();
    sorted.sort();
    let joined = sorted.join("\n");
    let hash = Sha256::digest(joined.as_bytes());
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hash);
    digest
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Initiate handshake (client side).
///
/// Writes protocol byte + HandshakePropose, reads HandshakeAccept.
/// `tls_peer_node_id` is the Ed25519 key extracted from the peer's TLS cert.
pub async fn initiate_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    local_node_id: &[u8; 32],
    channel_ids: &[String],
    roles: &[String],
    tls_peer_node_id: &[u8; 32],
    local_p2p_port: u16,
) -> Result<HandshakeResult, HandshakeError> {
    let channel_digest = compute_channel_digest(channel_ids);

    // Write protocol byte
    write_protocol_byte(stream, Protocol::Handshake).await?;

    // Send propose
    let propose = WireMessage::HandshakePropose(HandshakePropose {
        magic: HANDSHAKE_MAGIC,
        version_min: PROTOCOL_VERSION,
        version_max: PROTOCOL_VERSION,
        node_id: local_node_id.to_vec(),
        timestamp: now_unix_secs(),
        channel_digest: channel_digest.to_vec(),
        channel_count: channel_ids.len() as u16,
        roles: roles.to_vec(),
        p2p_port: local_p2p_port,
    });
    write_frame(stream, &propose).await?;

    // Read accept
    let response = read_frame(stream).await?;
    match response {
        WireMessage::HandshakeAccept(accept) => validate_accept(&accept, tls_peer_node_id),
        _ => Err(HandshakeError::UnexpectedMessage),
    }
}

/// Accept handshake (server side).
///
/// Reads protocol byte + HandshakePropose, validates, writes HandshakeAccept.
/// `tls_peer_node_id` is the Ed25519 key extracted from the peer's TLS cert.
pub async fn accept_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    local_node_id: &[u8; 32],
    channel_ids: &[String],
    roles: &[String],
    tls_peer_node_id: &[u8; 32],
    local_p2p_port: u16,
) -> Result<HandshakeResult, HandshakeError> {
    // Read protocol byte
    let proto = read_protocol_byte(stream).await?;
    if proto != Protocol::Handshake {
        return Err(HandshakeError::UnexpectedMessage);
    }

    // Read propose
    let msg = read_frame(stream).await?;
    let propose = match msg {
        WireMessage::HandshakePropose(p) => p,
        _ => return Err(HandshakeError::UnexpectedMessage),
    };

    // Validate propose
    if let Err(reject_reason) = validate_propose(&propose, tls_peer_node_id) {
        // Send rejection
        let channel_digest = compute_channel_digest(channel_ids);
        let reject = WireMessage::HandshakeAccept(HandshakeAccept {
            version: 0,
            node_id: local_node_id.to_vec(),
            timestamp: now_unix_secs(),
            channel_digest: channel_digest.to_vec(),
            channel_count: channel_ids.len() as u16,
            roles: roles.to_vec(),
            reject_reason: Some(reject_reason.reject_reason()),
            p2p_port: local_p2p_port,
        });
        write_frame(stream, &reject).await?;
        return Err(reject_reason);
    }

    // Negotiate version
    let negotiated = PROTOCOL_VERSION.min(propose.version_max);

    // Send accept
    let channel_digest = compute_channel_digest(channel_ids);
    let accept = WireMessage::HandshakeAccept(HandshakeAccept {
        version: negotiated,
        node_id: local_node_id.to_vec(),
        timestamp: now_unix_secs(),
        channel_digest: channel_digest.to_vec(),
        channel_count: channel_ids.len() as u16,
        roles: roles.to_vec(),
        reject_reason: None,
        p2p_port: local_p2p_port,
    });
    write_frame(stream, &accept).await?;

    // Build result from propose
    let mut peer_digest = [0u8; 32];
    if propose.channel_digest.len() == 32 {
        peer_digest.copy_from_slice(&propose.channel_digest);
    }
    let mut peer_node_id = [0u8; 32];
    if propose.node_id.len() == 32 {
        peer_node_id.copy_from_slice(&propose.node_id);
    }

    Ok(HandshakeResult {
        peer_node_id,
        negotiated_version: negotiated,
        peer_channel_digest: peer_digest,
        peer_channel_count: propose.channel_count,
        peer_roles: propose.roles,
        peer_p2p_port: propose.p2p_port,
    })
}

fn validate_propose(
    propose: &HandshakePropose,
    tls_peer_node_id: &[u8; 32],
) -> Result<(), HandshakeError> {
    // Magic check (§4.1.3)
    if propose.magic != HANDSHAKE_MAGIC {
        return Err(HandshakeError::InvalidMagic(propose.magic));
    }

    // Version negotiation (§4.1.4)
    if propose.version_min > PROTOCOL_VERSION || propose.version_max < PROTOCOL_VERSION {
        return Err(HandshakeError::IncompatibleVersion);
    }

    // Timestamp validation (§4.1.5)
    let now = now_unix_secs();
    let delta = propose.timestamp.abs_diff(now);
    if delta > MAX_CLOCK_SKEW_SECS {
        return Err(HandshakeError::ClockSkew { delta });
    }

    // Identity verification (§4.1.6)
    if propose.node_id.len() != 32 || propose.node_id.as_slice() != tls_peer_node_id {
        return Err(HandshakeError::IdentityMismatch);
    }

    Ok(())
}

fn validate_accept(
    accept: &HandshakeAccept,
    tls_peer_node_id: &[u8; 32],
) -> Result<HandshakeResult, HandshakeError> {
    // Check for rejection
    if accept.version == 0 {
        return Err(HandshakeError::Rejected(
            accept.reject_reason.clone().unwrap_or_default(),
        ));
    }

    // Identity verification (§4.1.6)
    if accept.node_id.len() != 32 || accept.node_id.as_slice() != tls_peer_node_id {
        return Err(HandshakeError::IdentityMismatch);
    }

    // Timestamp validation (§4.1.5)
    let now = now_unix_secs();
    let delta = accept.timestamp.abs_diff(now);
    if delta > MAX_CLOCK_SKEW_SECS {
        return Err(HandshakeError::ClockSkew { delta });
    }

    let mut peer_digest = [0u8; 32];
    if accept.channel_digest.len() == 32 {
        peer_digest.copy_from_slice(&accept.channel_digest);
    }
    let mut peer_node_id = [0u8; 32];
    peer_node_id.copy_from_slice(&accept.node_id);

    Ok(HandshakeResult {
        peer_node_id,
        negotiated_version: accept.version,
        peer_channel_digest: peer_digest,
        peer_channel_count: accept.channel_count,
        peer_roles: accept.roles.clone(),
        peer_p2p_port: accept.p2p_port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn test_node_id() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn test_peer_id() -> [u8; 32] {
        [0x43u8; 32]
    }

    #[test]
    fn test_channel_digest_empty() {
        let digest = compute_channel_digest(&[]);
        // SHA-256 of empty string
        let expected = Sha256::digest(b"");
        assert_eq!(digest, expected.as_slice());
    }

    #[test]
    fn test_channel_digest_deterministic() {
        let ids_a = vec!["beta".into(), "alpha".into(), "gamma".into()];
        let ids_b = vec!["gamma".into(), "alpha".into(), "beta".into()];
        assert_eq!(
            compute_channel_digest(&ids_a),
            compute_channel_digest(&ids_b),
        );
    }

    #[test]
    fn test_channel_digest_different_channels() {
        let a = compute_channel_digest(&["alpha".into()]);
        let b = compute_channel_digest(&["beta".into()]);
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn test_handshake_success() {
        let node_a = test_node_id();
        let node_b = test_peer_id();
        let channels_a: Vec<String> = vec!["ch1".into(), "ch2".into()];
        let channels_b: Vec<String> = vec!["ch2".into(), "ch3".into()];
        let roles: Vec<String> = vec!["personal".into()];

        let (mut client, mut server) = duplex(8192);

        let server_task = tokio::spawn({
            let roles = roles.clone();
            let channels_b = channels_b.clone();
            async move {
                accept_handshake(&mut server, &node_b, &channels_b, &roles, &node_a, 9474).await
            }
        });

        let client_result =
            initiate_handshake(&mut client, &node_a, &channels_a, &roles, &node_b, 9474)
                .await
                .unwrap();

        assert_eq!(client_result.peer_node_id, node_b);
        assert_eq!(client_result.negotiated_version, PROTOCOL_VERSION);
        assert_eq!(client_result.peer_channel_count, 2);
        assert_eq!(client_result.peer_roles, vec!["personal"]);
        assert_eq!(
            client_result.peer_channel_digest,
            compute_channel_digest(&channels_b),
        );

        let server_result = server_task.await.unwrap().unwrap();
        assert_eq!(server_result.peer_node_id, node_a);
        assert_eq!(server_result.peer_channel_count, 2);
    }

    #[tokio::test]
    async fn test_handshake_invalid_magic() {
        let node_a = test_node_id();
        let node_b = test_peer_id();

        let (mut client, mut server) = duplex(8192);

        // Manually send a propose with wrong magic
        let server_task = tokio::spawn(async move {
            accept_handshake(&mut server, &node_b, &[], &[], &node_a, 9474).await
        });

        write_protocol_byte(&mut client, Protocol::Handshake)
            .await
            .unwrap();
        let bad_propose = WireMessage::HandshakePropose(HandshakePropose {
            magic: 0xDEADBEEF,
            version_min: 1,
            version_max: 1,
            node_id: node_a.to_vec(),
            timestamp: now_unix_secs(),
            channel_digest: vec![0; 32],
            channel_count: 0,
            roles: vec![],
            p2p_port: 9474,
        });
        write_frame(&mut client, &bad_propose).await.unwrap();

        // Read rejection
        let response = read_frame(&mut client).await.unwrap();
        match response {
            WireMessage::HandshakeAccept(a) => {
                assert_eq!(a.version, 0);
                assert!(a.reject_reason.is_some());
            }
            _ => panic!("expected HandshakeAccept rejection"),
        }

        let server_err = server_task.await.unwrap();
        assert!(matches!(server_err, Err(HandshakeError::InvalidMagic(_))));
    }

    #[tokio::test]
    async fn test_handshake_identity_mismatch() {
        let node_a = test_node_id();
        let node_b = test_peer_id();
        let wrong_id = [0xFF; 32]; // TLS says one thing, handshake says another

        let (mut client, mut server) = duplex(8192);

        let server_task = tokio::spawn(async move {
            // Server expects TLS peer to be wrong_id but handshake sends node_a
            accept_handshake(&mut server, &node_b, &[], &[], &wrong_id, 9474).await
        });

        // Client sends valid propose with node_a
        let _ = initiate_handshake(&mut client, &node_a, &[], &[], &node_b, 9474).await;

        let server_err = server_task.await.unwrap();
        assert!(matches!(server_err, Err(HandshakeError::IdentityMismatch)));
    }

    // T3-01 (CRITICAL): Clock skew rejection (§4.1.5)
    #[tokio::test]
    async fn test_handshake_clock_skew_rejected() {
        let node_a = test_node_id();
        let node_b = test_peer_id();

        let (mut client, mut server) = duplex(8192);

        let server_task = tokio::spawn(async move {
            accept_handshake(&mut server, &node_b, &[], &[], &node_a, 9474).await
        });

        write_protocol_byte(&mut client, Protocol::Handshake)
            .await
            .unwrap();
        let bad_propose = WireMessage::HandshakePropose(HandshakePropose {
            magic: HANDSHAKE_MAGIC,
            version_min: 1,
            version_max: 1,
            node_id: node_a.to_vec(),
            timestamp: now_unix_secs() - 600, // 600s in the past (>300s tolerance)
            channel_digest: vec![0; 32],
            channel_count: 0,
            roles: vec![],
            p2p_port: 9474,
        });
        write_frame(&mut client, &bad_propose).await.unwrap();

        // Read rejection -- verify reject_reason doesn't leak clock delta (BV-17)
        let response = read_frame(&mut client).await.unwrap();
        match response {
            WireMessage::HandshakeAccept(a) => {
                assert_eq!(a.version, 0);
                assert_eq!(a.reject_reason.as_deref(), Some("clock skew"));
                // Must NOT contain the delta value or local time
                assert!(!a.reject_reason.as_deref().unwrap().contains("600"));
            }
            _ => panic!("expected HandshakeAccept rejection"),
        }

        let server_err = server_task.await.unwrap();
        assert!(matches!(server_err, Err(HandshakeError::ClockSkew { .. })));
    }

    // T3-01 variant: clock skew in the future
    #[tokio::test]
    async fn test_handshake_clock_skew_future_rejected() {
        let node_a = test_node_id();
        let node_b = test_peer_id();

        let (mut client, mut server) = duplex(8192);

        let server_task = tokio::spawn(async move {
            accept_handshake(&mut server, &node_b, &[], &[], &node_a, 9474).await
        });

        write_protocol_byte(&mut client, Protocol::Handshake)
            .await
            .unwrap();
        let bad_propose = WireMessage::HandshakePropose(HandshakePropose {
            magic: HANDSHAKE_MAGIC,
            version_min: 1,
            version_max: 1,
            node_id: node_a.to_vec(),
            timestamp: now_unix_secs() + 600, // 600s in the future
            channel_digest: vec![0; 32],
            channel_count: 0,
            roles: vec![],
            p2p_port: 9474,
        });
        write_frame(&mut client, &bad_propose).await.unwrap();

        let _ = read_frame(&mut client).await.unwrap(); // read rejection
        let server_err = server_task.await.unwrap();
        assert!(matches!(server_err, Err(HandshakeError::ClockSkew { .. })));
    }

    // T1-01 / T3-04 (HIGH): Version negotiation rejection (§4.1.4)
    #[tokio::test]
    async fn test_handshake_incompatible_version() {
        let node_a = test_node_id();
        let node_b = test_peer_id();

        let (mut client, mut server) = duplex(8192);

        let server_task = tokio::spawn(async move {
            accept_handshake(&mut server, &node_b, &[], &[], &node_a, 9474).await
        });

        write_protocol_byte(&mut client, Protocol::Handshake)
            .await
            .unwrap();
        let bad_propose = WireMessage::HandshakePropose(HandshakePropose {
            magic: HANDSHAKE_MAGIC,
            version_min: 99,
            version_max: 100, // We only support version 1
            node_id: node_a.to_vec(),
            timestamp: now_unix_secs(),
            channel_digest: vec![0; 32],
            channel_count: 0,
            roles: vec![],
            p2p_port: 9474,
        });
        write_frame(&mut client, &bad_propose).await.unwrap();

        let response = read_frame(&mut client).await.unwrap();
        match response {
            WireMessage::HandshakeAccept(a) => {
                assert_eq!(a.version, 0);
                assert_eq!(
                    a.reject_reason.as_deref(),
                    Some("incompatible version range")
                );
            }
            _ => panic!("expected HandshakeAccept rejection"),
        }

        let server_err = server_task.await.unwrap();
        assert!(matches!(
            server_err,
            Err(HandshakeError::IncompatibleVersion)
        ));
    }

    // T2-03 (LOW): Channel digest known vector
    #[test]
    fn test_channel_digest_known_vector() {
        let ids: Vec<String> = vec!["alpha".into(), "beta".into(), "gamma".into()];
        let digest = compute_channel_digest(&ids);
        // SHA-256("alpha\nbeta\ngamma")
        let expected = Sha256::digest(b"alpha\nbeta\ngamma");
        assert_eq!(digest, expected.as_slice());
    }
}
