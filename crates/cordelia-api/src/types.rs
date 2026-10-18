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

#[derive(Deserialize)]
pub struct DeleteKeyRequest {
    pub channel: String,
    pub key: String,
}

#[derive(Serialize)]
pub struct DeleteKeyResponse {
    pub channel: String,
    pub key: String,
    /// Revision of the tombstone.
    pub rev: u64,
    pub item_id: String,
}

// ── Sync adapters (decision 2026-09-30-agent-memory-sync §4.5) ──

#[derive(Deserialize)]
pub struct SyncClaudeRequest {
    pub enabled: bool,
    /// Claude Code directory; defaults to ~/.claude of the user running the node.
    #[serde(default)]
    pub dir: Option<String>,
    /// A list of exclusions, as a panel that is not yet brought up to
    /// date sends one. It is stored in the place of the current list, and
    /// nothing reads it to say what syncs: only mapped folders do
    /// (decision 2026-10-04 §10.1).
    #[serde(default)]
    pub exclude: Option<Vec<String>>,
    /// The switch for home memory. `false` unmaps the home directory and
    /// stores the switch off; `true` stores it on. Home memory syncs
    /// where the home directory is mapped.
    #[serde(default)]
    pub home: Option<bool>,
    /// `true` asked for everything found to sync, and is refused where
    /// the request turns sync on or leaves it on: nothing is changed.
    /// `false` is taken: only mapped folders sync, which is the only
    /// scope there is.
    #[serde(default)]
    pub all: Option<bool>,
    /// Put the Claude Code directory back to its default. Nothing else is
    /// touched: a setting that is not given keeps its stored value.
    #[serde(default)]
    pub reset: bool,
}

/// A declared mapping: Claude's memory for sessions started in `folder`
/// syncs under `name`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncMapping {
    pub folder: String,
    pub name: String,
}

#[derive(Deserialize)]
pub struct SyncMapRequest {
    /// The working directory, absolute.
    pub folder: String,
    /// The name to sync under. For the home directory it is `~` unless
    /// another is given.
    pub name: String,
    /// Required to map the home directory itself, and refused for any
    /// other folder: a slip must not sync a whole home under some name.
    #[serde(default)]
    pub home: bool,
}

#[derive(Deserialize, Default)]
pub struct SyncUnmapRequest {
    pub folder: String,
    /// The read before a carried name is let go, where the command asks
    /// for its next round (decision 2026-10-17 §4.2): its ID, as hex.
    #[serde(default)]
    pub read: Option<String>,
    /// Whether the command asks at a terminal (decision 2026-10-17
    /// §5.2): where a carried name is let go only on the word `discard`,
    /// the node then answers with what the command asks it by
    /// (`not_let_go`), and not with its refusal.
    #[serde(default)]
    pub asks: bool,
    /// The word that the person typed, which lets the name go with what
    /// no relay holds: `discard`, sent with `read` and `versions`.
    #[serde(default)]
    pub word: Option<String>,
    /// With `word`: how many versions the command said would go, as the
    /// node found them.
    #[serde(default)]
    pub versions: Option<usize>,
}

#[derive(Serialize)]
pub struct SyncStatusResponse {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    /// Always false: only the declared mappings sync (decision 2026-10-04
    /// §10.1). It is kept for whoever reads a status as an earlier
    /// version wrote it.
    pub all: bool,
    pub mappings: Vec<SyncMapping>,
    /// The list of exclusions that is stored, as a panel sent it:
    /// nothing reads it to say what syncs.
    pub exclude: Vec<String>,
    /// The switch for home memory, as it is stored.
    pub home: bool,
    /// The name home memory syncs under on this device, or last did: the
    /// name the home directory is or was mapped under. Turning home
    /// memory on again uses it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_name: Option<String>,
    /// How many times the settings have changed since the node started.
    /// The report carries the generation it was made under.
    pub generation: u64,
    /// The last cycle's report, once one has run.
    pub report: Option<serde_json::Value>,
    /// For how long the node has stored no report, in seconds, by its
    /// own clock, which does not run while the machine sleeps: since the
    /// later of its start and the last report it stored (decision
    /// 2026-10-04 §10.1). A status says by this that the cycle has
    /// stalled.
    pub no_report_secs: u64,
    /// When a cycle last sent or received a memory (RFC 3339).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_change_at: Option<String>,
    /// Where the device stands under a recovery phrase (decision
    /// 2026-10-04 §5.2): `no_phrase`, `applied`, or why it has stopped
    /// (`fork`, `removed`, `not_listed`, `not_opened`). Only a device
    /// that has applied a statement publishes anything.
    pub stands: &'static str,
    /// Why the node is held up, where it is (decision 2026-10-04 §10.1):
    /// it runs no cycle and no pass until it is so no longer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub held: Option<String>,
    /// Whether this device took this version with what an earlier one
    /// held: the step of its first start was made here (decision
    /// 2026-10-04 §10.1). With no phrase, such a device is "not added
    /// yet".
    pub moved_on: bool,
    /// What a device whose stored scope was on is told, while it is
    /// stored (decision 2026-10-04 §10.1): the folders that stopped
    /// syncing when only mapped folders came to sync, each with whether
    /// `cordelia sync map` would sync it now. It is there with sync on
    /// and with it off, until a person says that it has been seen
    /// (`POST /api/v1/sync/seen`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notice: Option<crate::found::NoticeShown>,
    /// What a mapping carried for the name that the device came to sync
    /// by it (decision 2026-10-04 §7.3): only in the answer to the
    /// request that mapped the folder, and only where a carry was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub carried: Option<serde_json::Value>,
    /// The name that this device let go of (decision 2026-10-04 §7.3):
    /// one that it held by a carry or a recovery, with no folder mapped
    /// to it. Only in the answer to the request that unmapped it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub let_go: Option<String>,
    /// Beside `let_go`: whether the statement that this device has
    /// applied lists it alone (decision 2026-10-04 §9, step 4). No other
    /// device of the person's then holds anything of the name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub let_go_alone: Option<bool>,
    /// Beside `let_go`: how many versions of the name that this device
    /// signed were asked about, each of which a relay held when it was
    /// read just now (decision 2026-10-17 §4.2). Not there where the name
    /// was let go with no read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub let_go_versions: Option<usize>,
    /// The read before a carried name is let go, where it goes on
    /// (decision 2026-10-17 §4.2): `read`, its ID as hex, which the
    /// command sends to ask for its next round, and `relays`, each relay
    /// still read in part with what it has handed so far (`relay`,
    /// `bytes`, counted as a relay counts against its cap).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reading: Option<serde_json::Value>,
    /// Where the command asks at a terminal and a carried name is let go
    /// only on the word `discard` (decision 2026-10-17 §5.2): `read`, the
    /// ID that the word is bound to, as hex; `versions`, how many versions
    /// no relay held, or the notes of a device that has stopped say it
    /// sent to none; `said`, what is said first; and `where`, where they
    /// may still be.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_let_go: Option<serde_json::Value>,
    /// Beside `let_go`, where it was let go on the word `discard`: how
    /// many versions that no relay held went with it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub let_go_discarded: Option<usize>,
    /// Beside `still_held`: whether this device has stopped, and sends
    /// nothing more (decision 2026-10-17 §4.6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub still_held_stopped: Option<bool>,
    /// The name that a folder was mapped to, where this device still
    /// holds it once the folder is unmapped (decision 2026-10-04 §16): a
    /// carry or a recovery brought it, and it is held as it was before
    /// the folder. Only in the answer to the request that unmapped the
    /// folder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub still_held: Option<String>,
}
