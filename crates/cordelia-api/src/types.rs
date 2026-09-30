//! Request and response types for the Channels API.
//!
//! Spec: seed-drill/specs/channels-api.md §3

use serde::{Deserialize, Serialize};

// ── Subscribe ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SubscribeRequest {
    pub channel: String,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_access")]
    pub access: String,
}

#[derive(Serialize)]
pub struct SubscribeResponse {
    pub channel: String,
    pub channel_id: String,
    pub is_new: bool,
    pub role: String,
    pub mode: String,
    pub access: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub joined_at: Option<String>,
}

// ── Publish ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PublishRequest {
    pub channel: String,
    pub content: serde_json::Value,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(default = "default_item_type")]
    pub item_type: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    /// Publish a new revision of this key instead of appending an item
    /// (decision 2026-09-30 §4.3). Group channels only.
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Serialize)]
pub struct PublishResponse {
    pub item_id: String,
    pub channel: String,
    pub published_at: String,
    pub author: String,
    pub item_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev: Option<u64>,
}

// ── Listen ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ListenRequest {
    pub channel: String,
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

#[derive(Serialize)]
pub struct ListenResponse {
    pub channel: String,
    pub items: Vec<ListenItem>,
    pub cursor: String,
    pub has_more: bool,
}

#[derive(Serialize)]
pub struct ListenItem {
    pub item_id: String,
    pub content: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub item_type: String,
    pub parent_id: Option<String>,
    pub author: String,
    pub published_at: String,
    pub signature_valid: bool,
}

// ── List ───────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ListResponse {
    pub channels: Vec<ListChannel>,
}

#[derive(Serialize)]
pub struct ListChannel {
    pub channel: String,
    pub channel_id: String,
    pub role: String,
    pub mode: String,
    pub access: String,
    pub item_count: i64,
    pub last_activity: Option<String>,
    pub created_at: String,
}

// ── Info ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct InfoRequest {
    pub channel: String,
}

#[derive(Serialize)]
pub struct InfoResponse {
    pub channel: String,
    pub channel_id: String,
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

// ── Unsubscribe ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UnsubscribeRequest {
    pub channel: String,
}

#[derive(Serialize)]
pub struct UnsubscribeResponse {
    pub ok: bool,
    pub channel: String,
}

// ── Identity ───────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct IdentityResponse {
    pub entity_id: String,
    pub ed25519_public_key: String,
    pub x25519_public_key: String,
    pub node_id: String,
    pub channels_subscribed: i64,
    pub peers_connected: i64,
}

// ── DM ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DmRequest {
    pub peer: String, // Bech32 Ed25519 public key
}

#[derive(Serialize)]
pub struct DmResponse {
    pub channel_id: String,
    pub is_new: bool,
    pub peer: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct ListDmsResponse {
    pub dms: Vec<DmChannel>,
}

#[derive(Serialize)]
pub struct DmChannel {
    pub channel_id: String,
    pub peer: String,
    pub item_count: i64,
    pub last_activity: Option<String>,
    pub created_at: String,
}

// ── Group ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GroupCreateRequest {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Serialize)]
pub struct GroupCreateResponse {
    pub channel_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub mode: String,
    pub member_count: i64,
    pub is_new: bool,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct GroupInviteRequest {
    pub channel_id: String,
    pub member: String, // Bech32 Ed25519 public key of invitee
}

#[derive(Serialize)]
pub struct GroupInviteResponse {
    pub ok: bool,
    pub channel_id: String,
    pub member: String,
    pub member_count: i64,
}

#[derive(Deserialize)]
pub struct GroupRemoveRequest {
    pub channel_id: String,
    pub member: String,
}

#[derive(Serialize)]
pub struct GroupRemoveResponse {
    pub ok: bool,
    pub channel_id: String,
    pub removed: String,
    pub psk_rotated: bool,
    pub new_key_version: i64,
}

#[derive(Serialize)]
pub struct ListGroupsResponse {
    pub groups: Vec<GroupChannel>,
}

#[derive(Serialize)]
pub struct GroupChannel {
    pub channel_id: String,
    pub role: String,
    pub mode: String,
    pub member_count: i64,
    pub item_count: i64,
    pub last_activity: Option<String>,
    pub created_at: String,
}

// ── Rotate PSK ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RotatePskRequest {
    pub channel: String,
}

#[derive(Serialize)]
pub struct RotatePskResponse {
    pub ok: bool,
    pub channel: String,
    pub new_key_version: i64,
    pub members_notified: i64,
}

// ── Delete Item ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DeleteItemRequest {
    pub channel: String,
    pub item_id: String,
}

#[derive(Serialize)]
pub struct DeleteItemResponse {
    pub ok: bool,
    pub item_id: String,
    pub tombstoned_at: String,
}

// ── Search ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SearchRequest {
    pub channel: String,
    pub query: String,
    #[serde(default = "default_search_limit")]
    pub limit: u32,
    #[serde(default)]
    pub types: Option<Vec<String>>,
    #[serde(default)]
    pub since: Option<String>,
}

#[derive(Serialize)]
pub struct SearchResponse {
    pub channel: String,
    pub results: Vec<SearchHitResponse>,
    pub total: usize,
    pub semantic_available: bool,
}

#[derive(Serialize)]
pub struct SearchHitResponse {
    pub item_id: String,
    pub content: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub item_type: String,
    pub parent_id: Option<String>,
    pub author: String,
    pub published_at: String,
    pub signature_valid: bool,
    pub score: f64,
}

fn default_search_limit() -> u32 {
    20
}

// ── Defaults ───────────────────────────────────────────────────────

fn default_mode() -> String {
    "realtime".into()
}

fn default_access() -> String {
    "open".into()
}

fn default_item_type() -> String {
    "message".into()
}

fn default_limit() -> u32 {
    50
}

// ── Devices and invites (decision 2026-09-30-agent-memory-sync §4.1) ──

#[derive(Deserialize)]
pub struct AddDeviceRequest {
    /// Bech32 Ed25519 key of the device being added.
    pub device: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Serialize)]
pub struct AddDeviceResponse {
    pub device: String,
    /// This node's key: the other device runs `cordelia accept <this_device>`.
    pub this_device: String,
    pub personal_channel_id: String,
    pub channels: Vec<String>,
}

#[derive(Deserialize)]
pub struct AcceptRequest {
    /// Bech32 Ed25519 key of the device that ran `add-device` for this node.
    pub key: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Serialize)]
pub struct InboxSummaryResponse {
    pub applied: Vec<String>,
    pub pending: usize,
    pub superseded: usize,
    pub invalid: usize,
}

#[derive(Deserialize)]
pub struct RemoveDeviceRequest {
    pub device: String,
}

#[derive(Serialize)]
pub struct RemoveDeviceResponse {
    pub device: String,
    pub channels_rotated: Vec<String>,
}

#[derive(Serialize)]
pub struct DeviceEntry {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub this_device: bool,
    pub in_personal_channel: bool,
    pub explicitly_trusted: bool,
}

#[derive(Serialize)]
pub struct ListDevicesResponse {
    pub devices: Vec<DeviceEntry>,
}

#[derive(Serialize)]
pub struct PendingInviteEntry {
    pub item_id: String,
    pub from: String,
    pub channel_id: String,
    pub received_at: String,
}

#[derive(Serialize)]
pub struct ListInvitesResponse {
    pub pending: Vec<PendingInviteEntry>,
}

// ── Keyed entries (decision 2026-09-30-agent-memory-sync §4.3) ──

#[derive(Deserialize)]
pub struct EntriesRequest {
    pub channel: String,
}

#[derive(Serialize)]
pub struct VersionResponse {
    pub item_id: String,
    pub author: String,
    pub rev: u64,
    pub published_at: String,
    pub deleted: bool,
    pub content: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct EntryResponse {
    pub key: String,
    #[serde(flatten)]
    pub current: VersionResponse,
    /// Other versions at the same revision: concurrent edits.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<VersionResponse>,
}

#[derive(Serialize)]
pub struct EntriesResponse {
    pub channel: String,
    pub entries: Vec<EntryResponse>,
}
