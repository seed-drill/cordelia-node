//! Wire message types for all 8 mini-protocols.
//!
//! Each message is CBOR-encoded on the wire. The protocol byte (§3.3)
//! identifies which mini-protocol a QUIC stream carries; message framing
//! (4-byte big-endian length prefix) is handled by the codec module.
//!
//! Spec: seed-drill/specs/network-protocol.md §3–§4

use serde::{Deserialize, Serialize};

// ── Protocol identifiers (§3.3) ────────────────────────────────────

/// Protocol byte written as the first byte of each QUIC stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    Handshake = 0x01,
    KeepAlive = 0x02,
    PeerSharing = 0x03,
    ChannelAnnounce = 0x04,
    ItemSync = 0x05,
    ItemPush = 0x06,
    PskExchange = 0x07,
    Pairing = 0x08,
}

impl Protocol {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Handshake),
            0x02 => Some(Self::KeepAlive),
            0x03 => Some(Self::PeerSharing),
            0x04 => Some(Self::ChannelAnnounce),
            0x05 => Some(Self::ItemSync),
            0x06 => Some(Self::ItemPush),
            0x07 => Some(Self::PskExchange),
            0x08 => Some(Self::Pairing),
            _ => None,
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

// ── Handshake (0x01, §4.1) ─────────────────────────────────────────

/// Magic number for handshake validation.
pub const HANDSHAKE_MAGIC: u32 = 0xC0DE_11A1;

/// Current protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakePropose {
    pub magic: u32,
    pub version_min: u16,
    pub version_max: u16,
    #[serde(with = "serde_bytes")]
    pub node_id: Vec<u8>, // 32 bytes
    pub timestamp: u64,
    #[serde(with = "serde_bytes")]
    pub channel_digest: Vec<u8>, // 32 bytes
    pub channel_count: u16,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeAccept {
    pub version: u16,
    #[serde(with = "serde_bytes")]
    pub node_id: Vec<u8>, // 32 bytes
    pub timestamp: u64,
    #[serde(with = "serde_bytes")]
    pub channel_digest: Vec<u8>, // 32 bytes
    pub channel_count: u16,
    pub roles: Vec<String>,
    pub reject_reason: Option<String>,
}

// ── Keep-Alive (0x02, §4.2) ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ping {
    pub seq: u64,
    pub sent_at_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pong {
    pub seq: u64,
    pub sent_at_ns: u64,
    pub recv_at_ns: u64,
}

// ── Peer-Sharing (0x03, §4.3) ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerShareRequest {
    pub max_peers: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerShareResponse {
    pub peers: Vec<PeerAddress>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAddress {
    #[serde(with = "serde_bytes")]
    pub node_id: Vec<u8>, // 32 bytes
    pub addrs: Vec<String>, // SocketAddr as string for CBOR portability
    pub last_seen: u64,
    pub exclude: bool,
}

// ── Channel-Announce (0x04, §4.4) ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelJoined {
    pub channel_id: String,
    pub descriptor: ChannelDescriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelLeft {
    pub channel_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelStateHash {
    #[serde(with = "serde_bytes")]
    pub digest: Vec<u8>, // 32 bytes
    pub count: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelListRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelListResponse {
    pub channels: Vec<ChannelDescriptor>,
}

/// Channel descriptor (§4.4.6). Signed by creator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelDescriptor {
    pub channel_id: String,
    pub channel_name: Option<String>,
    pub access: String,
    pub mode: String,
    pub key_version: u32,
    #[serde(with = "serde_bytes")]
    pub psk_hash: Vec<u8>, // 32 bytes
    #[serde(with = "serde_bytes")]
    pub creator_id: Vec<u8>, // 32 bytes
    pub created_at: String,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>, // 64 bytes
}

// ── Item-Sync (0x05, §4.5) ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub channel_id: String,
    pub since: Option<String>,
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub items: Vec<ItemHeader>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemHeader {
    pub item_id: String,
    pub channel_id: String,
    pub item_type: String,
    #[serde(with = "serde_bytes")]
    pub content_hash: Vec<u8>, // 32 bytes
    #[serde(with = "serde_bytes")]
    pub author_id: Vec<u8>, // 32 bytes
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>, // 64 bytes
    pub key_version: u32,
    pub published_at: String,
    pub is_tombstone: bool,
    pub parent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchRequest {
    pub item_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchResponse {
    pub items: Vec<Item>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub item_id: String,
    pub channel_id: String,
    pub item_type: String,
    #[serde(with = "serde_bytes")]
    pub encrypted_blob: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub content_hash: Vec<u8>, // 32 bytes
    pub content_length: u32,
    #[serde(with = "serde_bytes")]
    pub author_id: Vec<u8>, // 32 bytes
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>, // 64 bytes
    pub key_version: u32,
    pub published_at: String,
    pub is_tombstone: bool,
    pub parent_id: Option<String>,
}

// ── Item-Push (0x06, §4.6) ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushPayload {
    pub items: Vec<Item>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushAck {
    pub stored: u32,
    pub dedup_dropped: u32,
    pub policy_rejected: u32,
    pub verification_failed: u32,
}

// ── PSK-Exchange (0x07, §4.7) ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PskRequest {
    pub channel_id: String,
    #[serde(with = "serde_bytes")]
    pub subscriber_xpk: Vec<u8>, // 32 bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PskResponse {
    pub status: String,
    pub reason: Option<String>,
    #[serde(with = "serde_bytes")]
    pub ecies_envelope: Option<Vec<u8>>, // 92 bytes when present
    pub key_version: Option<u32>,
}

// ── Pairing (0x08, §4.8) ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRequest {
    #[serde(with = "serde_bytes")]
    pub node_id: Vec<u8>, // 32 bytes
    pub pairing_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingResponse {
    pub status: String,
    pub reason: Option<String>,
}

// ── Unified message envelope ───────────────────────────────────────

/// Top-level enum for dispatching any wire message by protocol.
/// Each variant maps 1:1 to a protocol's message set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg_type")]
pub enum WireMessage {
    // Handshake
    HandshakePropose(HandshakePropose),
    HandshakeAccept(HandshakeAccept),

    // Keep-Alive
    Ping(Ping),
    Pong(Pong),

    // Peer-Sharing
    PeerShareRequest(PeerShareRequest),
    PeerShareResponse(PeerShareResponse),

    // Channel-Announce
    ChannelJoined(ChannelJoined),
    ChannelLeft(ChannelLeft),
    ChannelStateHash(ChannelStateHash),
    ChannelListRequest(ChannelListRequest),
    ChannelListResponse(ChannelListResponse),

    // Item-Sync
    SyncRequest(SyncRequest),
    SyncResponse(SyncResponse),
    FetchRequest(FetchRequest),
    FetchResponse(FetchResponse),

    // Item-Push
    PushPayload(PushPayload),
    PushAck(PushAck),

    // PSK-Exchange
    PskRequest(PskRequest),
    PskResponse(PskResponse),

    // Pairing
    PairingRequest(PairingRequest),
    PairingResponse(PairingResponse),
}
