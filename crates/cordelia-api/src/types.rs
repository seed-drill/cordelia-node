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
}

#[derive(Serialize)]
pub struct PublishResponse {
    pub item_id: String,
    pub channel: String,
    pub published_at: String,
    pub author: String,
    pub item_type: String,
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
    pub ed25519_public_key: String,
    pub x25519_public_key: String,
    pub node_id: String,
    pub channels_subscribed: i64,
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
