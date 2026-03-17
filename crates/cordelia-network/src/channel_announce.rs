//! Channel-Announce mini-protocol (0x04, §4.4).
//!
//! Event-driven announcements with periodic reconciliation on a long-lived
//! bidirectional QUIC stream. Five message types:
//!   - ChannelJoined: push on subscribe (includes descriptor)
//!   - ChannelLeft: push on unsubscribe
//!   - ChannelStateHash: periodic reconciliation digest
//!   - ChannelListRequest: request full list on digest mismatch
//!   - ChannelListResponse: full descriptor list response
//!
//! Spec: seed-drill/specs/network-protocol.md §4.4

use crate::codec::write_frame;
use crate::handshake::compute_channel_digest;
use crate::messages::*;
use cordelia_core::protocol;
use cordelia_crypto::identity::verify_signature;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::AsyncWrite;
use tracing::{debug, warn};

/// Reconciliation interval (§4.4.2, sourced from protocol.rs).
pub const RECONCILIATION_INTERVAL: Duration =
    Duration::from_secs(protocol::CHANNEL_RECONCILIATION_INTERVAL_SECS);

/// Responder stagger offset (§4.4.2, sourced from protocol.rs).
pub const RESPONDER_OFFSET: Duration =
    Duration::from_secs(protocol::CHANNEL_RESPONDER_OFFSET_SECS);

/// Minimum warm tenure before responding to ChannelListRequest (§4.4.5, sourced from protocol.rs).
pub const MIN_WARM_TENURE: Duration = Duration::from_secs(protocol::MIN_WARM_TENURE_SECS);

/// Maximum serialized descriptor size (§4.4.6, sourced from protocol.rs).
pub const MAX_DESCRIPTOR_SIZE: usize = protocol::MAX_DESCRIPTOR_SIZE;

/// Maximum channel name length (§4.4.6, sourced from protocol.rs).
pub const MAX_CHANNEL_NAME_LEN: usize = protocol::MAX_CHANNEL_NAME_LEN;

#[derive(Debug, Error)]
pub enum ChannelAnnounceError {
    #[error("codec error: {0}")]
    Codec(#[from] crate::codec::CodecError),

    #[error("unexpected message type")]
    UnexpectedMessage,

    #[error("invalid descriptor signature for channel {0}")]
    InvalidSignature(String),

    #[error("descriptor too large: {0} bytes (max {MAX_DESCRIPTOR_SIZE})")]
    DescriptorTooLarge(usize),

    #[error("creator conflict for channel {channel_id}: expected {expected}, got {got}")]
    CreatorConflict {
        channel_id: String,
        expected: String,
        got: String,
    },
}

/// Tracks channel-announce state for one peer connection.
#[derive(Debug)]
pub struct ChannelAnnounceState {
    /// Channels the peer has announced (channel_id -> descriptor).
    pub peer_channels: HashMap<String, ChannelDescriptor>,
    /// Channels we share with this peer (intersection).
    pub shared_channels: Vec<String>,
    /// Last reconciliation time.
    pub last_reconciliation: Option<Instant>,
    /// When the peer reached Warm/Hot state (for tenure check).
    pub peer_tenure_start: Instant,
    /// Whether we are the connection initiator (affects reconciliation timing).
    pub is_initiator: bool,
}

impl ChannelAnnounceState {
    pub fn new(is_initiator: bool) -> Self {
        Self {
            peer_channels: HashMap::new(),
            shared_channels: Vec::new(),
            last_reconciliation: None,
            peer_tenure_start: Instant::now(),
            is_initiator,
        }
    }

    /// Update the channel intersection between us and this peer.
    pub fn recompute_intersection(&mut self, our_channels: &[String]) {
        self.shared_channels = our_channels
            .iter()
            .filter(|c| self.peer_channels.contains_key(c.as_str()))
            .cloned()
            .collect();
    }

    /// Whether reconciliation should fire now.
    pub fn should_reconcile(&self) -> bool {
        let offset = if self.is_initiator {
            Duration::ZERO
        } else {
            RESPONDER_OFFSET
        };

        match self.last_reconciliation {
            None => {
                // First reconciliation: fire after offset
                self.peer_tenure_start.elapsed() >= offset
            }
            Some(last) => last.elapsed() >= RECONCILIATION_INTERVAL,
        }
    }

    /// Whether the peer has sufficient tenure for full list response (§4.4.5).
    pub fn has_sufficient_tenure(&self) -> bool {
        self.peer_tenure_start.elapsed() >= MIN_WARM_TENURE
    }
}

/// Send a ChannelJoined announcement.
pub async fn send_channel_joined<W: AsyncWrite + Unpin>(
    writer: &mut W,
    channel_id: &str,
    descriptor: &ChannelDescriptor,
) -> Result<(), ChannelAnnounceError> {
    let msg = WireMessage::ChannelJoined(ChannelJoined {
        channel_id: channel_id.to_string(),
        descriptor: descriptor.clone(),
    });
    write_frame(writer, &msg).await?;
    Ok(())
}

/// Send a ChannelLeft announcement.
pub async fn send_channel_left<W: AsyncWrite + Unpin>(
    writer: &mut W,
    channel_id: &str,
) -> Result<(), ChannelAnnounceError> {
    let msg = WireMessage::ChannelLeft(ChannelLeft {
        channel_id: channel_id.to_string(),
    });
    write_frame(writer, &msg).await?;
    Ok(())
}

/// Send a ChannelStateHash for reconciliation.
pub async fn send_state_hash<W: AsyncWrite + Unpin>(
    writer: &mut W,
    channel_ids: &[String],
) -> Result<(), ChannelAnnounceError> {
    let digest = compute_channel_digest(channel_ids);
    let msg = WireMessage::ChannelStateHash(ChannelStateHash {
        digest: digest.to_vec(),
        count: channel_ids.len() as u16,
    });
    write_frame(writer, &msg).await?;
    Ok(())
}

/// Send a ChannelListRequest.
pub async fn send_list_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
) -> Result<(), ChannelAnnounceError> {
    let msg = WireMessage::ChannelListRequest(ChannelListRequest {});
    write_frame(writer, &msg).await?;
    Ok(())
}

/// Send a ChannelListResponse.
pub async fn send_list_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    descriptors: &[ChannelDescriptor],
) -> Result<(), ChannelAnnounceError> {
    let msg = WireMessage::ChannelListResponse(ChannelListResponse {
        channels: descriptors.to_vec(),
    });
    write_frame(writer, &msg).await?;
    Ok(())
}

/// Process a received channel-announce message.
///
/// Returns the type of action taken for the caller to decide next steps.
pub fn handle_channel_joined(
    state: &mut ChannelAnnounceState,
    joined: &ChannelJoined,
    our_channels: &[String],
    known_descriptors: &HashMap<String, ChannelDescriptor>,
) -> Result<ChannelAnnounceAction, ChannelAnnounceError> {
    // Validate descriptor signature
    validate_descriptor(&joined.descriptor)?;

    // Check for creator conflict
    if let Some(existing) = known_descriptors.get(&joined.channel_id)
        && existing.creator_id != joined.descriptor.creator_id
    {
        warn!(
            channel = %joined.channel_id,
            "creator conflict: dropping descriptor from different creator"
        );
        return Err(ChannelAnnounceError::CreatorConflict {
            channel_id: joined.channel_id.clone(),
            expected: hex::encode(&existing.creator_id),
            got: hex::encode(&joined.descriptor.creator_id),
        });
    }

    state
        .peer_channels
        .insert(joined.channel_id.clone(), joined.descriptor.clone());
    state.recompute_intersection(our_channels);

    debug!(channel = %joined.channel_id, "peer joined channel");
    Ok(ChannelAnnounceAction::ChannelAdded(
        joined.channel_id.clone(),
    ))
}

/// Process a ChannelLeft message.
pub fn handle_channel_left(
    state: &mut ChannelAnnounceState,
    left: &ChannelLeft,
    our_channels: &[String],
) -> ChannelAnnounceAction {
    state.peer_channels.remove(&left.channel_id);
    state.recompute_intersection(our_channels);
    debug!(channel = %left.channel_id, "peer left channel");
    ChannelAnnounceAction::ChannelRemoved(left.channel_id.clone())
}

/// Process a ChannelStateHash -- check if it matches what we expect.
pub fn check_state_hash(state: &ChannelAnnounceState, hash: &ChannelStateHash) -> bool {
    let peer_ids: Vec<String> = state.peer_channels.keys().cloned().collect();
    let expected_digest = compute_channel_digest(&peer_ids);
    let expected_count = peer_ids.len() as u16;

    hash.count == expected_count && hash.digest == expected_digest
}

/// Actions the caller should take after processing a channel-announce message.
#[derive(Debug, Clone)]
pub enum ChannelAnnounceAction {
    ChannelAdded(String),
    ChannelRemoved(String),
    DigestMatch,
    DigestMismatch,
    ListReceived(Vec<ChannelDescriptor>),
}

/// Validate a channel descriptor: field limits, signature.
///
/// Checks channel_name length (§4.4.6: max 63 chars), serialized size
/// (§4.4.6: max 512 bytes CBOR), and Ed25519 signature.
fn validate_descriptor(desc: &ChannelDescriptor) -> Result<(), ChannelAnnounceError> {
    // Field size limits (§4.4.6)
    if let Some(ref name) = desc.channel_name
        && name.len() > MAX_CHANNEL_NAME_LEN
    {
        return Err(ChannelAnnounceError::DescriptorTooLarge(name.len()));
    }

    // Serialized size limit (§4.4.6: max 512 bytes before signature)
    let payload = build_descriptor_signing_payload(desc);
    if payload.len() > MAX_DESCRIPTOR_SIZE {
        return Err(ChannelAnnounceError::DescriptorTooLarge(payload.len()));
    }

    if desc.creator_id.len() != 32 || desc.signature.len() != 64 {
        return Err(ChannelAnnounceError::InvalidSignature(
            desc.channel_id.clone(),
        ));
    }

    // Build the signed payload (all fields except signature)
    let payload = build_descriptor_signing_payload(desc);

    let creator: [u8; 32] = desc.creator_id.as_slice().try_into().unwrap();
    let sig: [u8; 64] = desc.signature.as_slice().try_into().unwrap();

    if !verify_signature(&creator, &payload, &sig) {
        return Err(ChannelAnnounceError::InvalidSignature(
            desc.channel_id.clone(),
        ));
    }

    Ok(())
}

/// Build the CBOR payload that gets signed for a descriptor.
///
/// Uses deterministic CBOR encoding (RFC 8949 §4.2.1).
/// Key order by encoded byte length first, then lexicographic:
/// mode, access, psk_hash, channel_id, created_at, creator_id, key_version, channel_name
pub fn build_descriptor_signing_payload(desc: &ChannelDescriptor) -> Vec<u8> {
    use std::collections::BTreeMap;

    // Use ciborium Value for deterministic encoding
    let mut map = BTreeMap::new();
    map.insert("mode".to_string(), ciborium::Value::Text(desc.mode.clone()));
    map.insert(
        "access".to_string(),
        ciborium::Value::Text(desc.access.clone()),
    );
    map.insert(
        "psk_hash".to_string(),
        ciborium::Value::Bytes(desc.psk_hash.clone()),
    );
    map.insert(
        "channel_id".to_string(),
        ciborium::Value::Text(desc.channel_id.clone()),
    );
    map.insert(
        "created_at".to_string(),
        ciborium::Value::Text(desc.created_at.clone()),
    );
    map.insert(
        "creator_id".to_string(),
        ciborium::Value::Bytes(desc.creator_id.clone()),
    );
    map.insert(
        "key_version".to_string(),
        ciborium::Value::Integer(desc.key_version.into()),
    );
    match &desc.channel_name {
        Some(name) => {
            map.insert(
                "channel_name".to_string(),
                ciborium::Value::Text(name.clone()),
            );
        }
        None => {
            map.insert("channel_name".to_string(), ciborium::Value::Null);
        }
    }

    // CBOR deterministic: ciborium sorts BTreeMap keys by encoded form
    let cbor_map = ciborium::Value::Map(
        map.into_iter()
            .map(|(k, v)| (ciborium::Value::Text(k), v))
            .collect(),
    );

    let mut buf = Vec::new();
    ciborium::into_writer(&cbor_map, &mut buf).unwrap();
    buf
}

/// Create and sign a channel descriptor.
#[allow(clippy::too_many_arguments)]
pub fn create_signed_descriptor(
    identity: &cordelia_crypto::identity::NodeIdentity,
    channel_id: &str,
    channel_name: Option<&str>,
    access: &str,
    mode: &str,
    psk_hash: &[u8; 32],
    key_version: u32,
    created_at: &str,
) -> ChannelDescriptor {
    let mut desc = ChannelDescriptor {
        channel_id: channel_id.to_string(),
        channel_name: channel_name.map(|s| s.to_string()),
        access: access.to_string(),
        mode: mode.to_string(),
        key_version,
        psk_hash: psk_hash.to_vec(),
        creator_id: identity.public_key().to_vec(),
        created_at: created_at.to_string(),
        signature: vec![0; 64], // placeholder
    };

    let payload = build_descriptor_signing_payload(&desc);
    let sig = identity.sign(&payload);
    desc.signature = sig.to_vec();
    desc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::read_frame;
    use cordelia_crypto::identity::NodeIdentity;
    use sha2::{Digest, Sha256};

    fn make_test_descriptor(identity: &NodeIdentity) -> ChannelDescriptor {
        let psk = [0xAA; 32];
        let psk_hash: [u8; 32] = Sha256::digest(psk).into();
        create_signed_descriptor(
            identity,
            "test_channel_abc123",
            Some("research"),
            "open",
            "realtime",
            &psk_hash,
            1,
            "2026-03-10T14:30:00Z",
        )
    }

    #[test]
    fn test_descriptor_sign_verify() {
        let id = NodeIdentity::generate().unwrap();
        let desc = make_test_descriptor(&id);
        assert!(validate_descriptor(&desc).is_ok());
    }

    #[test]
    fn test_descriptor_tampered_signature() {
        let id = NodeIdentity::generate().unwrap();
        let mut desc = make_test_descriptor(&id);
        desc.signature[0] ^= 0xFF; // Tamper with signature
        assert!(matches!(
            validate_descriptor(&desc),
            Err(ChannelAnnounceError::InvalidSignature(_))
        ));
    }

    #[test]
    fn test_descriptor_tampered_field() {
        let id = NodeIdentity::generate().unwrap();
        let mut desc = make_test_descriptor(&id);
        desc.mode = "batch".into(); // Change field after signing
        assert!(matches!(
            validate_descriptor(&desc),
            Err(ChannelAnnounceError::InvalidSignature(_))
        ));
    }

    #[test]
    fn test_handle_channel_joined() {
        let id = NodeIdentity::generate().unwrap();
        let desc = make_test_descriptor(&id);

        let mut state = ChannelAnnounceState::new(true);
        let our_channels = vec!["test_channel_abc123".to_string(), "other".to_string()];

        let joined = ChannelJoined {
            channel_id: "test_channel_abc123".into(),
            descriptor: desc,
        };

        let action =
            handle_channel_joined(&mut state, &joined, &our_channels, &HashMap::new()).unwrap();
        assert!(matches!(action, ChannelAnnounceAction::ChannelAdded(_)));
        assert_eq!(state.peer_channels.len(), 1);
        assert_eq!(state.shared_channels, vec!["test_channel_abc123"]);
    }

    #[test]
    fn test_handle_channel_left() {
        let id = NodeIdentity::generate().unwrap();
        let desc = make_test_descriptor(&id);

        let mut state = ChannelAnnounceState::new(true);
        state
            .peer_channels
            .insert("test_channel_abc123".into(), desc);
        state.shared_channels = vec!["test_channel_abc123".into()];

        let left = ChannelLeft {
            channel_id: "test_channel_abc123".into(),
        };
        let our_channels = vec!["test_channel_abc123".to_string()];
        let action = handle_channel_left(&mut state, &left, &our_channels);
        assert!(matches!(action, ChannelAnnounceAction::ChannelRemoved(_)));
        assert_eq!(state.peer_channels.len(), 0);
        assert!(state.shared_channels.is_empty());
    }

    #[test]
    fn test_check_state_hash_match() {
        let id = NodeIdentity::generate().unwrap();
        let desc = make_test_descriptor(&id);

        let mut state = ChannelAnnounceState::new(true);
        state
            .peer_channels
            .insert("test_channel_abc123".into(), desc);

        let digest = compute_channel_digest(&["test_channel_abc123".into()]);
        let hash = ChannelStateHash {
            digest: digest.to_vec(),
            count: 1,
        };
        assert!(check_state_hash(&state, &hash));
    }

    #[test]
    fn test_check_state_hash_mismatch() {
        let state = ChannelAnnounceState::new(true);
        let hash = ChannelStateHash {
            digest: vec![0xFF; 32],
            count: 5,
        };
        assert!(!check_state_hash(&state, &hash));
    }

    #[test]
    fn test_creator_conflict_rejected() {
        let id_a = NodeIdentity::generate().unwrap();
        let id_b = NodeIdentity::generate().unwrap();
        let desc_a = make_test_descriptor(&id_a);
        let desc_b = make_test_descriptor(&id_b);

        // Store desc_a first
        let mut known = HashMap::new();
        known.insert("test_channel_abc123".to_string(), desc_a);

        let mut state = ChannelAnnounceState::new(true);
        let joined = ChannelJoined {
            channel_id: "test_channel_abc123".into(),
            descriptor: desc_b,
        };

        let result = handle_channel_joined(&mut state, &joined, &[], &known);
        assert!(matches!(
            result,
            Err(ChannelAnnounceError::CreatorConflict { .. })
        ));
    }

    #[tokio::test]
    async fn test_send_and_read_joined() {
        let id = NodeIdentity::generate().unwrap();
        let desc = make_test_descriptor(&id);

        let (mut writer, mut reader) = tokio::io::duplex(8192);

        send_channel_joined(&mut writer, "test_channel_abc123", &desc)
            .await
            .unwrap();

        let msg = read_frame(&mut reader).await.unwrap();
        match msg {
            WireMessage::ChannelJoined(cj) => {
                assert_eq!(cj.channel_id, "test_channel_abc123");
                assert!(validate_descriptor(&cj.descriptor).is_ok());
            }
            _ => panic!("expected ChannelJoined"),
        }
    }

    #[test]
    fn test_reconciliation_timing_initiator() {
        let state = ChannelAnnounceState::new(true);
        // Initiator should reconcile immediately (offset = 0)
        assert!(state.should_reconcile());
    }

    #[test]
    fn test_reconciliation_timing_responder() {
        let state = ChannelAnnounceState::new(false);
        // Responder should wait 150s before first reconciliation
        assert!(!state.should_reconcile());
    }

    #[test]
    fn test_tenure_check() {
        let state = ChannelAnnounceState::new(true);
        // Freshly created -- not enough tenure
        assert!(!state.has_sufficient_tenure());
    }

    // T1-04 (MEDIUM): channel_name max 63 chars (§4.4.6)
    #[test]
    fn test_channel_name_too_long_rejected() {
        let id = NodeIdentity::generate().unwrap();
        let psk_hash: [u8; 32] = Sha256::digest([0xAA; 32]).into();
        let long_name = "a".repeat(64); // 64 chars > 63 limit
        let desc = create_signed_descriptor(
            &id,
            "test_channel",
            Some(&long_name),
            "open",
            "realtime",
            &psk_hash,
            1,
            "2026-03-14T10:00:00Z",
        );
        assert!(matches!(
            validate_descriptor(&desc),
            Err(ChannelAnnounceError::DescriptorTooLarge(_))
        ));
    }

    // T1-04 variant: exactly 63 chars should be accepted
    #[test]
    fn test_channel_name_at_limit_accepted() {
        let id = NodeIdentity::generate().unwrap();
        let psk_hash: [u8; 32] = Sha256::digest([0xAA; 32]).into();
        let name = "a".repeat(63); // exactly at limit
        let desc = create_signed_descriptor(
            &id,
            "test_channel",
            Some(&name),
            "open",
            "realtime",
            &psk_hash,
            1,
            "2026-03-14T10:00:00Z",
        );
        assert!(validate_descriptor(&desc).is_ok());
    }

    // T1-03 (MEDIUM): Descriptor CBOR too large
    #[test]
    fn test_descriptor_oversized_rejected() {
        let id = NodeIdentity::generate().unwrap();
        let psk_hash: [u8; 32] = Sha256::digest([0xAA; 32]).into();
        // Use a very long channel_id to push CBOR over 512 bytes
        let long_id = "x".repeat(400);
        let desc = create_signed_descriptor(
            &id,
            &long_id,
            Some("research"),
            "open",
            "realtime",
            &psk_hash,
            1,
            "2026-03-14T10:00:00Z",
        );
        assert!(matches!(
            validate_descriptor(&desc),
            Err(ChannelAnnounceError::DescriptorTooLarge(_))
        ));
    }

    // T3-06 variant: empty channel_id
    #[test]
    fn test_empty_channel_id_descriptor() {
        let id = NodeIdentity::generate().unwrap();
        let psk_hash: [u8; 32] = Sha256::digest([0xAA; 32]).into();
        let desc = create_signed_descriptor(
            &id,
            "",
            None,
            "open",
            "batch",
            &psk_hash,
            1,
            "2026-03-14T10:00:00Z",
        );
        // Empty channel_id is structurally valid (signature verifies)
        // Policy enforcement is at the API layer, not descriptor validation
        assert!(validate_descriptor(&desc).is_ok());
    }
}
