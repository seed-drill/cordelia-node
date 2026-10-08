# Channels API Specification

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-10
**Scope**: Phase 1 (Encrypted Pub/Sub MVP)
**Implements**: WP3 (Pub/Sub API Endpoints)
**Depends on**: specs/ecies-envelope-encryption.md, decisions/2026-03-09-mvp-implementation-plan.md
**Reference**: cordelia-core/docs/reference/api.md (existing node API, pre-pivot)

> **v1 status.** A node serves one of two sets of routes, by its role
> (`crates/cordelia-api/src/lib.rs`).
>
> - **A personal node** carries no channel of the older kind
>   ([decision record of 2026-10-04](../decisions/2026-10-04-a-persons-devices.md)
>   §10). Under `/api/v1/channels/` it serves four routes, for the names the
>   device holds: `publish`, `entries`, `delete-key` and `identity` (§3.16).
>   It does not serve `subscribe`, `listen`, `list`, `info`, `unsubscribe`,
>   `dm`, `list-dms`, `group`, `group/invite`, `group/remove`, `list-groups`,
>   `rotate-psk`, `delete-item` or `search`: there is nothing to subscribe
>   to, create, join or rotate.
> - **A relay or a bootnode** serves the Channels API of the older kind, as
>   §3.1 to §3.15 have it, with the changes below.
> - **Every node** serves the routes of a person's devices, of a carry that
>   a person asks for and of recovery (§3.17), sync and local history (§3.18;
>   `/api/v1/history/{list,show,restore,drop}`, decision 2026-09-30 §4.5b),
>   `GET /api/v1/health` and `GET /api/v1/peers`.
> - **Gone from every node:** `/api/v1/devices/remove` and
>   `/api/v1/invites/{list,process}`. A device is removed by a statement that
>   the command signs with the recovery phrase (`/api/v1/change/*`), and
>   nothing arrives in an inbox.
>
> For the older kind, per the
> [decision record of 2026-09-30](../decisions/2026-09-30-agent-memory-sync.md);
> request and response types are in `crates/cordelia-api/src/types.rs`:
>
> - **`publish`** takes an optional `key`: it publishes a new revision of that
>   key instead of appending an item (group channels only).
> - `POST /api/v1/channels/entries` returns the current value of every
>   key in a channel, with any conflicts, and `POST /api/v1/channels/delete-key`
>   deletes a key.
> - **`delete-item` (§3.12)** deletes only the caller's own items, in the
>   channel named.
> - **Not used by v1:** `dm` (§3.7), `group/invite` (§3.9), `group/remove`
>   (§3.10) and `rotate-psk` (§3.11) still write key envelopes into the
>   channel itself, which never reach other nodes. Open channels and PSK
>   discovery (§6.1, §11) are deferred. Search (§3.13) is deferred and its spec
>   archived; the SDK mapping (§8) applies to the deferred SDK.

---

## 1. Overview

The Channels API is the developer-facing REST interface for Cordelia's encrypted pub/sub system. It sits alongside the existing node API (L1/L2/groups) and provides higher-level abstractions for channel operations.

### 1.1 Design Principles

1. **All POST** (one exception: `GET /metrics` for Prometheus convention, §3.15). Consistent with existing node API. No verb-based routing.
2. **Bearer token auth.** Same `Authorization: Bearer <token>` as existing endpoints.
3. **JSON in, JSON out.** Request and response bodies are `application/json`.
4. **Node encrypts.** The API accepts and returns plaintext. Encryption is transparent.
5. **Channel names, not IDs.** Developers work with human-readable names. The node resolves to internal IDs.

### 1.2 Base URL

```
http://localhost:9473/api/v1/channels/
```

Port 9473 (default). Localhost only in Phase 1 (bearer token auth over localhost is the trust boundary).

### 1.3 Authentication

All endpoints require:

```
Authorization: Bearer <token>
```

Token from `~/.cordelia/node-token`. Returns `401` if missing or invalid.

All endpoints return `401 unauthorized` with body `{"error": {"code": "unauthorized", "message": "Missing or invalid bearer token"}}` when the Authorization header is missing, malformed, or contains an invalid token. This is not repeated in individual endpoint error lists.

---

## 2. Error Format

The Channels API returns structured JSON errors (an upgrade from the existing API's plain text errors):

```json
{
  "error": {
    "code": "not_found",
    "message": "Channel 'research' not found"
  }
}
```

**Base format:**

```json
{"error": {"code": "<string>", "message": "<string>"}}
```

**Status-specific extensions:**

- `413` responses add `used_bytes` (integer) and `quota_bytes` (integer) to the error object.
- `429` responses add `retry_after_seconds` (integer) to the error object.

Clients MUST handle unknown fields by ignoring them.

### Error Codes

| HTTP Status | Code | Meaning |
|-------------|------|---------|
| `400` | `bad_request` | Invalid request body, missing required fields |
| `401` | `unauthorized` | Missing or invalid bearer token |
| `403` | `not_authorized` | Valid token but insufficient access (e.g., private channel) |
| `404` | `not_found` | Channel or item not found |
| `409` | `conflict` | Channel name already exists with different parameters |
| `413` | `payload_too_large` | Content exceeds maximum size |
| `429` | `rate_limited` | Too many requests (keeper-enforced) |
| `500` | `internal_error` | Storage or crypto failure |

Error codes are stable identifiers. Once published, a code is never removed or changed in meaning. New codes may be added. Clients MUST handle unknown codes as `internal_error`.

### 2.1 Error Retryability

| Status | Code | Retryable | Guidance |
|--------|------|-----------|----------|
| 400 | `bad_request` | No | Fix request |
| 401 | `unauthorized` | No | Check token |
| 403 | `not_authorized` | No | Permission denied |
| 404 | `not_found` | No | Resource doesn't exist |
| 409 | `conflict` | Yes | Exponential backoff, max 3 retries |
| 413 | `payload_too_large` / `quota_exceeded` | No | Reduce payload or free storage |
| 429 | `rate_limited` | Yes | Use `retry_after_seconds`, else exponential backoff |
| 500 | `internal_error` | Yes | Exponential backoff, max 5 retries |

---

## 3. Endpoints

### 3.1 POST /api/v1/channels/subscribe

Join or create an encrypted channel. This is the primary entry point for developers.

**Request:**
```json
{
  "channel": "research-findings",
  "mode": "realtime",
  "access": "open"
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `channel` | string | yes | -- | Channel name (RFC 1035 label: 3-63 chars, lowercase alphanumeric + hyphens, starts with letter) |
| `mode` | string | no | `"realtime"` | `"realtime"` (eager push to peers) or `"batch"` (pull-based, anti-entropy sync) |
| `access` | string | no | `"open"` | `"open"` (auto-approve subscribers) or `"invite_only"` (PSK distributed manually) |

**Response (200) -- new channel created:**
```json
{
  "channel": "research-findings",
  "channel_id": "a1b2c3d4e5f6...",
  "is_new": true,
  "role": "owner",
  "mode": "realtime",
  "access": "open",
  "created_at": "2026-03-10T19:30:00Z"
}
```

**Response (200) -- joined existing channel:**
```json
{
  "channel": "research-findings",
  "channel_id": "a1b2c3d4e5f6...",
  "is_new": false,
  "role": "member",
  "mode": "realtime",
  "access": "open",
  "created_at": "2026-03-10T19:30:00Z",
  "joined_at": "2026-03-10T19:35:00Z"
}
```

**Behaviour:**

1. Compute `channel_id = hex(SHA-256("cordelia:channel:" + lowercase(channel)))` (deterministic, domain-separated)
2. If channel exists locally:
   - If caller is already a member: return current state
   - If channel is open and PSK is held locally: add caller as member, return (no ECIES envelope needed -- same node holds PSK)
   - If channel is open and PSK is NOT local: request PSK from a peer via PSK-Exchange (§11), then add member
   - If channel is invite_only: return `403 not_authorized`
3. If channel does not exist:
   - Create channel with specified mode and access
   - Generate 32-byte PSK (CSPRNG)
   - Add caller as owner
   - Store PSK at `~/.cordelia/channel-keys/<channel_id>.key`
   - Create ChannelDescriptor: set `psk_hash = SHA-256(psk)`, `creator_id = caller's Ed25519 pubkey`, sign with caller's key (network-protocol.md §4.4.6)
   - Store descriptor locally
   - Send `ChannelJoined` with descriptor to all hot peers (Channel-Announce)
   - Start replication (realtime: eager push to peers)

**Errors:**
- `400` if channel name violates RFC 1035 rules
- `403` if channel is invite_only and caller is not invited
- `409` if channel exists with different `mode` (mode is immutable after creation)

**Notes:**
- `mode` and `access` are only used when creating a new channel. Ignored when joining an existing channel.
- The `channel_id` is the hex-encoded SHA-256 hash, exposed for debugging. Developers should use channel names in all subsequent calls.

---

### 3.2 POST /api/v1/channels/publish

Publish content to a channel. Content is encrypted by the node before storage and replication.

**Request:**
```json
{
  "channel": "research-findings",
  "content": {
    "type": "insight",
    "text": "Vector search alone is insufficient for agent memory retrieval..."
  },
  "metadata": {
    "tags": ["research", "memory"],
    "priority": "normal"
  }
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `channel` | string | yes | -- | Channel name |
| `content` | any | yes | -- | Arbitrary JSON. Encrypted by node with channel PSK. |
| `metadata` | object | no | -- | Application-level metadata. Encrypted alongside content. |
| `item_type` | string | no | `"message"` | Content type hint. Stored in plaintext metadata for filtering. |
| `parent_id` | string | no | -- | Parent item ID for threading/replies. |

**Valid `item_type` values:**

| Value | Source | Description |
|-------|--------|-------------|
| `message` | API (default) | Standard published content |
| `event` | API | Event/notification |
| `state` | API | State update (e.g., key-value) |
| `kv` | Node-internal | Personal memory key-value (system channel) |
| `psk_envelope` | Node-internal | ECIES-wrapped PSK for a new member |
| `attestation` | Node-internal | Operator-agent attestation |
| `descriptor` | Node-internal | Channel descriptor update notification |
| `probe` | Node-internal | Relay health probe (network-protocol.md §16.1.2) |
| `memory:entity` | API (memory convention) | Memory item: person, org, concept, system (memory-model.md §5.3) |
| `memory:learning` | API (memory convention) | Memory item: pattern, insight, skill (memory-model.md §5.3) |
| `memory:session` | API (memory convention) | Memory item: session record (memory-model.md §5.3) |

Node-internal types are written by the node itself (during subscribe, PSK rotation, init, relay probing). The API rejects requests with node-internal `item_type` values. Memory types use the `memory:` prefix convention to avoid collision with application-defined types (see memory-model.md §5.2). Custom application types are permitted -- `item_type` is not a closed enum.

**Response (200):**
```json
{
  "item_id": "ci_01JARC9B0ETZFGV8QKM3DVNX5P",
  "channel": "research-findings",
  "published_at": "2026-03-10T19:36:00Z",
  "author": "cordelia_pk1...",
  "item_type": "message"
}
```

**Behaviour:**

1. Resolve channel name to channel_id
2. Verify caller is a member of the channel
3. Reject if `item_type` is a node-internal value
4. Generate item_id: `ci_<ulid_26>` where ULID is a Universally Unique Lexicographically Sortable Identifier (Crockford Base32, 26 chars, monotonic within the same millisecond on the same node). This ensures deterministic ordering across replicas. For cross-node conflicts with identical `published_at` and `author_id`, the node deduplicates by `content_hash` (first-observed wins). (ci = channel item)
5. Serialize `{ content, metadata }` as JSON bytes
6. Encrypt with channel PSK (AES-256-GCM, per ECIES spec §5)
7. Sign CBOR-encoded item metadata envelope with author's Ed25519 key (per ECIES spec §11)
8. Store encrypted blob + plaintext metadata (item_type, parent_id, timestamps)
9. If realtime channel: trigger eager push to peers

**Errors:**
- `400` if content is missing or not valid JSON, or if `item_type` (32 bytes at most), or `parent_id` (64) when no `key` is given, is longer than it may be; the message names the field. An entry under a key has no parent.
- `404` if channel not found
- `403` if caller is not a member
- `413` if the item would exceed 64 KB as it travels: its serialized content plus the 28 bytes that encryption adds

**Notes:**
- The `author` field is the publisher's Ed25519 public key in Bech32 encoding. The REST API uses `author` (short form); the wire protocol and CBOR signed envelope use `author_id` (raw 32-byte key). The SDK transforms `author` to camelCase. This deliberate rename (author_id -> author) simplifies the developer-facing API.
- `metadata` is encrypted alongside content -- it is NOT stored as plaintext metadata. The plaintext metadata fields (§3.2 of ECIES spec, item_type, timestamps, etc.) are generated by the node.

---

### 3.3 POST /api/v1/channels/listen

Retrieve items published to a channel since a given point. Phase 1 uses REST polling. The SDK abstracts the poll interval.

**Request:**
```json
{
  "channel": "research-findings",
  "since": "2026-03-10T19:30:00Z",
  "limit": 50
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `channel` | string | yes | -- | Channel name |
| `since` | string | no | -- | ISO 8601 timestamp. Return items published after this time. If omitted, returns latest items. |
| `limit` | integer | no | `50` | Maximum items to return (1-500) |

**Response (200):**
```json
{
  "channel": "research-findings",
  "items": [
    {
      "item_id": "ci_01JARC9B0ETZFGV8QKM3DVNX5P",
      "content": {
        "type": "insight",
        "text": "Vector search alone is insufficient..."
      },
      "metadata": {
        "tags": ["research", "memory"],
        "priority": "normal"
      },
      "item_type": "message",
      "parent_id": null,
      "author": "cordelia_pk1...",
      "published_at": "2026-03-10T19:36:00Z",
      "signature_valid": true
    }
  ],
  "cursor": "2026-03-10T19:36:00Z",
  "has_more": false
}
```

**Behaviour:**

1. Resolve channel name to channel_id
2. Verify caller is a member
3. Query items for this channel_id, `published_at > since`, ordered by `published_at ASC`, limit + 1 (to detect `has_more`)
4. Decrypt each item with channel PSK
5. Verify author signature on each item
6. Return decrypted content, author, timestamp

**Cursor semantics:** Cursor semantics are strictly-greater-than: `published_at > since`. Items with `published_at` equal to `since` are NOT included in the response (they were included in the previous response). Tombstones are items and are included in responses if their `published_at > since`. The SDK is responsible for handling tombstones (typically: filter from display, update local state).

**Pagination contract:**
- Use the `cursor` value from the response as `since` in the next request
- `has_more: true` means there are more items beyond the limit
- `cursor` is the `published_at` of the last returned item
- If no items are returned (empty result): `cursor` is the current server time (ISO 8601), `has_more: false`. This prevents re-scanning the same empty range on the next poll.
- Items with identical timestamps are ordered by `item_id` (deterministic tiebreak)

**Polling contract (SDK guidance):**
- Default poll interval: 2 seconds for realtime channels, 30 seconds for batch
- SDK stores the last `cursor` and passes it as `since` on each poll
- Phase 2: SSE endpoint (`GET /api/v1/channels/listen/stream`) for push-based delivery

**Errors:**
- `404` if channel not found
- `403` if caller is not a member

---

### 3.4 POST /api/v1/channels/list

List channels the caller is subscribed to.

**Request:**
```json
{}
```

**Response (200):**
```json
{
  "channels": [
    {
      "channel": "research-findings",
      "channel_id": "a1b2c3d4e5f6...",
      "role": "owner",
      "mode": "realtime",
      "access": "open",
      "item_count": 47,
      "last_activity": "2026-03-10T19:36:00Z",
      "created_at": "2026-03-10T19:30:00Z"
    },
    {
      "channel": "engineering",
      "channel_id": "b2c3d4e5f6a1...",
      "role": "member",
      "mode": "realtime",
      "access": "open",
      "item_count": 123,
      "last_activity": "2026-03-10T19:20:00Z",
      "created_at": "2026-03-08T10:00:00Z"
    }
  ]
}
```

**Notes:**
- Only returns channels the caller has subscribed to (has PSK for)
- `item_count` is the local count (may differ across nodes during replication)
- DM channels and group conversations are NOT included (use §3.4.1 and §3.4.2 below)

---

### 3.4.1 POST /api/v1/channels/list-dms

List DM channels the caller participates in.

**Request:**
```json
{}
```

**Response (200):**
```json
{
  "dms": [
    {
      "channel_id": "dm_c56ea36e17c1c3db...",
      "peer": "cordelia_pk1...",
      "item_count": 12,
      "last_activity": "2026-03-10T19:45:00Z"
    }
  ]
}
```

**Notes:**
- Only returns DMs where caller holds the PSK
- `peer` is the other party's Ed25519 public key in Bech32

---

### 3.4.2 POST /api/v1/channels/list-groups

List group conversations the caller participates in.

**Request:**
```json
{}
```

**Response (200):**
```json
{
  "groups": [
    {
      "channel_id": "grp_550e8400-e29b-41d4-a716-446655440000",
      "name": "project-x",
      "member_count": 3,
      "item_count": 87,
      "last_activity": "2026-03-10T19:50:00Z"
    }
  ]
}
```

**Notes:**
- Only returns groups where caller holds the PSK
- `name` may be null (groups are not required to have names)

---

### 3.5 POST /api/v1/channels/unsubscribe

Leave a channel. Removes local membership and deletes the channel PSK.

**Request:**
```json
{
  "channel": "research-findings"
}
```

**Response (200):**
```json
{
  "ok": true,
  "channel": "research-findings"
}
```

**Behaviour:**

1. Resolve channel name to channel_id
2. Remove caller from local membership
3. Delete PSK file (`~/.cordelia/channel-keys/<channel_id>.key`)
4. Stop replicating this channel
5. Local items are NOT deleted (encrypted, unreadable without PSK)

**Errors:**
- `404` if channel not found or caller is not a member

**Notes:**
- If the caller is the owner and no other members exist, the channel is tombstoned
- Items already replicated to other nodes remain (encrypted)
- Re-subscribing to an open channel re-distributes the PSK

---

### 3.6 POST /api/v1/channels/info

Read channel metadata without subscribing.

**Request:**
```json
{
  "channel": "research-findings"
}
```

**Response (200):**
```json
{
  "channel": "research-findings",
  "channel_id": "a1b2c3d4e5f6...",
  "exists": true,
  "mode": "realtime",
  "access": "open",
  "owner": "cordelia_pk1...",
  "member_count": 5,
  "created_at": "2026-03-10T19:30:00Z"
}
```

**Response (200) -- channel does not exist:**
```json
{
  "channel": "research-findings",
  "channel_id": "a1b2c3d4e5f6...",
  "exists": false
}
```

**Notes:**
- Does not require membership
- Does not reveal content or member identities (only count and owner public key)
- `channel_id` is always returned (deterministic from name) even if channel doesn't exist
- Useful for the SDK to check existence before subscribing

---

### 3.7 POST /api/v1/channels/dm

Create or connect to a bilateral DM channel. Deterministic channel derivation from two public keys.

**Request:**
```json
{
  "peer": "cordelia_pk1..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `peer` | string | yes | Peer's Ed25519 public key (Bech32) or entity name |

**Response (200):**
```json
{
  "channel_id": "dm_a1b2c3d4e5f6...",
  "peer": "cordelia_pk1...",
  "is_new": true,
  "created_at": "2026-03-10T19:40:00Z"
}
```

**Behaviour:**

1. Resolve peer key (decode Bech32 or look up by entity name)
2. Compute `channel_id = "dm_" + hex(SHA-256("cordelia:dm:" || sort([my_pk, peer_pk])))`
3. If channel exists locally: return handle
4. If new:
   - Create channel: invite_only access, realtime mode
   - Generate PSK (32 bytes, CSPRNG)
   - Store PSK locally
   - Create ChannelDescriptor: `channel_name = null`, `psk_hash = SHA-256(psk)`, `creator_id = caller's key`, sign (network-protocol.md §4.4.6)
   - Create ECIES envelope wrapping PSK for peer's X25519 public key
   - Store envelope as a channel item with `item_type = "psk_envelope"` (peer retrieves via replication)
   - Membership: exactly 2 (immutable)
   - Send `ChannelJoined` with descriptor to hot peers

**Errors:**
- `400` if peer key is invalid or self-referential

**Notes:**
- DM channels are always invite_only and realtime
- Membership is immutable (exactly these two keys)
- The deterministic channel ID means both parties derive the same channel independently
- Publish and listen use the same endpoints (§3.2, §3.3) with `channel_id` instead of channel name

---

### 3.8 POST /api/v1/channels/group

Create a group conversation (3+ people) with mutable membership.

**Request:**
```json
{
  "members": [
    "cordelia_pk1...",
    "cordelia_pk1..."
  ],
  "name": "project-x"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `members` | string[] | yes | Array of member public keys (Bech32) or entity names. Minimum 1 (+ caller = 2). |
| `name` | string | no | Human-readable label (not globally unique, not in namespace) |

**Response (200):**
```json
{
  "channel_id": "grp_<uuid>",
  "name": "project-x",
  "member_count": 3,
  "is_new": true,
  "created_at": "2026-03-10T19:45:00Z"
}
```

**Behaviour:**

1. Generate UUID v4 for channel_id (prefixed `grp_`)
2. Create channel: invite_only access, realtime mode
3. Generate PSK (32 bytes, CSPRNG)
4. Store PSK locally
5. Create ChannelDescriptor: `channel_name = name` (or null), `psk_hash = SHA-256(psk)`, `creator_id = caller's key`, sign (network-protocol.md §4.4.6)
6. For each member: create ECIES envelope wrapping PSK for their X25519 public key
7. Store envelopes as channel items with `item_type = "psk_envelope"` (members retrieve via replication)
8. Caller is owner
9. Send `ChannelJoined` with descriptor to hot peers

**Errors:**
- `400` if fewer than 1 member specified (need at least 2 total including caller)
- `400` if any member key is invalid

---

### 3.9 POST /api/v1/channels/group/invite

Invite a new member to a group conversation.

**Request:**
```json
{
  "channel_id": "grp_<uuid>",
  "member": "cordelia_pk1..."
}
```

**Response (200):**
```json
{
  "ok": true,
  "channel_id": "grp_<uuid>",
  "member": "cordelia_pk1...",
  "member_count": 4
}
```

**Behaviour:**

1. Verify caller is owner or admin of the group
2. Create ECIES envelope wrapping channel PSK for new member's X25519 public key
3. Add member to local membership
4. Store envelope as channel item

**Errors:**
- `403` if caller is not owner/admin
- `404` if channel not found

---

### 3.10 POST /api/v1/channels/group/remove

Remove a member from a group conversation. Triggers PSK rotation.

**Request:**
```json
{
  "channel_id": "grp_<uuid>",
  "member": "cordelia_pk1..."
}
```

**Response (200):**
```json
{
  "ok": true,
  "channel_id": "grp_<uuid>",
  "removed": "cordelia_pk1...",
  "member_count": 3,
  "psk_rotated": true,
  "new_key_version": 2
}
```

**Behaviour:**

1. Verify caller is owner or admin
2. Soft-remove member (posture = "removed")
3. Generate new PSK (32 bytes, CSPRNG)
4. Increment `key_version`
5. Wrap new PSK in ECIES envelope for each remaining member's X25519 public key
6. Store envelopes as channel items (members receive via replication)
7. Old PSK retained in key ring for decrypting historical items
8. New items encrypted with new PSK

**Errors:**
- `403` if caller is not owner/admin
- `404` if channel or member not found

**Notes:**
- Removed member retains the old PSK and can decrypt items published before rotation. This is accepted per the threat model (same as Signal: historical items already received are not re-encrypted).
- Removed member CANNOT decrypt items published after rotation (they don't have the new PSK).
- The `key_version` field in item metadata selects which PSK from the key ring to use for decryption.

---

### 3.11 POST /api/v1/channels/rotate-psk

Manually rotate a channel's PSK. Use when key compromise is suspected. Only the channel owner can trigger this.

**Request:**
```json
{
  "channel": "research-findings"
}
```

**Response (200):**
```json
{
  "ok": true,
  "channel": "research-findings",
  "new_key_version": 2,
  "members_notified": 5
}
```

**Behaviour:**

1. Verify caller is owner of the channel
2. Generate new PSK (32 bytes, CSPRNG)
3. Increment `key_version`
4. Wrap new PSK in ECIES envelope for each member's X25519 public key
5. Store envelopes as channel items with `item_type = "psk_envelope"`
6. Update channel descriptor: new `key_version`, new `psk_hash`, re-sign
7. Send updated `ChannelJoined` to hot peers
8. Old PSK retained in key ring (file format per ECIES spec §6.3-6.4; rotation trigger and distribution in §3.10/§3.11 above)

**Errors:**
- `403` if caller is not the channel owner
- `404` if channel not found

**Notes:**
- Automatic rotation on member removal (§3.10) is the common case. This endpoint is for manual rotation when key compromise is suspected without a member removal trigger.
- After rotation, all new items are encrypted with the new PSK. Historical items remain decryptable via the key ring.

---

### 3.12 POST /api/v1/channels/delete-item

Delete (tombstone) an item from a channel. Propagates via replication.

**Request:**
```json
{
  "channel": "research-findings",
  "item_id": "ci_01JARC9B0ETZFGV8QKM3DVNX5P"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `channel` | string | yes | Channel name or channel_id |
| `item_id` | string | yes | Item to tombstone |

**Response (200):**
```json
{
  "ok": true,
  "item_id": "ci_01JARC9B0ETZFGV8QKM3DVNX5P",
  "tombstoned_at": "2026-03-10T20:00:00Z"
}
```

**Behaviour:**

1. Resolve channel, verify caller is a member
2. Verify item exists and belongs to this channel
3. Mark item as tombstone (`is_tombstone = true`)
4. Tombstone replicates to peers via normal replication (CoW invariant: no hard deletes)
5. Peers receiving the tombstone mark their local copy as deleted

**Errors:**
- `403` if caller is not the item's author or a channel owner/admin
- `404` if channel or item not found

**Notes:**
- Only the author or a channel owner/admin can delete an item
- Tombstoned items are excluded from listen and search results
- The encrypted blob is retained (tombstone flag in metadata) until GC

---

### 3.13 POST /api/v1/channels/search

Hybrid search within a channel (FTS5 keyword + semantic similarity, scored by dominant-signal formula). See search-indexing.md for full implementation.

**Request:**
```json
{
  "channel": "research-findings",
  "query": "vector embeddings retrieval",
  "limit": 20
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `channel` | string | yes | -- | Channel name or channel_id (for DMs/groups) |
| `query` | string | yes | -- | Search query string. Runs against both FTS5 (keyword) and sqlite-vec (semantic similarity) indexes. |
| `limit` | integer | no | `20` | Maximum results (1-100) |
| `types` | string[] | no | -- | Filter by `item_type` (e.g., `["memory:learning", "memory:entity"]`). If omitted, all types returned. |
| `since` | string | no | -- | ISO 8601 timestamp. Only return items published after this time. |

**Response (200):**
```json
{
  "channel": "research-findings",
  "results": [
    {
      "item_id": "ci_01JARC9B0ETZFGV8QKM3DVNX5P",
      "content": { "type": "insight", "text": "Vector search alone..." },
      "metadata": { "tags": ["research", "memory"] },
      "item_type": "message",
      "parent_id": null,
      "author": "cordelia_pk1...",
      "published_at": "2026-03-10T19:36:00Z",
      "signature_valid": true,
      "score": 0.85
    }
  ],
  "total": 1,
  "semantic_available": true
}
```

**Behaviour:**

1. Resolve channel name to channel_id
2. Verify caller is a member
3. Query FTS5 and semantic indexes filtered by channel_id, combine with hybrid scorer (search-indexing.md §4.3)
4. Decrypt matching items
5. Return decrypted content with relevance score
6. Include `semantic_available` flag in response metadata

**Query sanitization:**
- Maximum query length: 200 characters (return `400` if exceeded)
- Maximum terms: 20 (split on whitespace, reject if exceeded)
- Prefix queries (`term*`): minimum 3 characters before `*` (reject `a*`, `ab*`)
- Query timeout: 5 seconds (return `500` with `"code": "query_timeout"` on exceed)
- FTS5 operators (`AND`, `OR`, `NOT`, `NEAR`) are permitted but bounded by term limit

**Notes:**
- FTS5 indexes are local-only (never replicated). Built from decrypted content on write.
- New items replicated from peers are decrypted and indexed on arrival.
- Index rebuild: `POST /api/v1/channels/reindex` (not in Phase 1 MVP, added with WP8).

**Errors:**
- `400` if query exceeds length/term limits or prefix is too short
- `404` if channel not found
- `403` if caller is not a member

---

### 3.14 POST /api/v1/channels/identity

Return the node's identity information (public keys, entity name).

**Request:**
```json
{}
```

**Response (200):**
```json
{
  "entity_id": "russwing",
  "ed25519_public_key": "cordelia_pk1...",
  "x25519_public_key": "cordelia_xpk1...",
  "node_id": "cordelia_pk1...",
  "channels_subscribed": 5,
  "peers_connected": 3
}
```

**Notes:**
- Bearer token authentication required (consistent with all other endpoints, §1.3)
- `node_id` is the Ed25519 public key in Bech32 encoding (`cordelia_pk1...`), same as `ed25519_public_key`
- Useful for DM initiation (caller needs peer's public key)
- `entity_id` is the human-readable name set during `cordelia init`
- SDK field mapping: the SDK transforms `ed25519_public_key` -> `publicKey` and `x25519_public_key` -> `encryptionKey` (custom mapping, not simple snake_case -> camelCase). See sdk-api-reference.md §7.1.

---

### 3.15 GET /api/v1/metrics

Prometheus exposition format metrics endpoint. Bearer token authentication required.

**Response (200):** `text/plain; version=0.0.4`

```
# HELP cordelia_peers_hot Number of peers in Hot state
# TYPE cordelia_peers_hot gauge
cordelia_peers_hot 5

# HELP cordelia_peers_warm Number of peers in Warm state
# TYPE cordelia_peers_warm gauge
cordelia_peers_warm 12

# HELP cordelia_channels_subscribed Number of channels this node is subscribed to
# TYPE cordelia_channels_subscribed gauge
cordelia_channels_subscribed 7

# HELP cordelia_items_total Total items per channel
# TYPE cordelia_items_total gauge
cordelia_items_total{channel="fe028fda"} 142
cordelia_items_total{channel="c56e1a3b"} 38

# HELP cordelia_storage_bytes Total storage used by SQLite database
# TYPE cordelia_storage_bytes gauge
cordelia_storage_bytes 2457600

# HELP cordelia_replication_lag_seconds Seconds since last successful sync per channel
# TYPE cordelia_replication_lag_seconds gauge
cordelia_replication_lag_seconds{channel="fe028fda"} 12.5

# HELP cordelia_sync_errors_total Cumulative replication sync errors
# TYPE cordelia_sync_errors_total counter
cordelia_sync_errors_total 3

# HELP cordelia_bandwidth_bytes_total Cumulative P2P bandwidth
# TYPE cordelia_bandwidth_bytes_total counter
cordelia_bandwidth_bytes_total{direction="in"} 1048576
cordelia_bandwidth_bytes_total{direction="out"} 524288

# HELP cordelia_uptime_seconds Node uptime
# TYPE cordelia_uptime_seconds gauge
cordelia_uptime_seconds 86400

# HELP cordelia_items_pushed_total Items pushed to peers (realtime channels)
# TYPE cordelia_items_pushed_total counter
cordelia_items_pushed_total 97

# HELP cordelia_items_synced_total Items received via anti-entropy sync
# TYPE cordelia_items_synced_total counter
cordelia_items_synced_total 45
```

**Notes:**
- This is the only GET endpoint (Prometheus convention). All other endpoints are POST.
- Channel labels use the first 8 hex characters of channel_id, never channel names, to prevent metadata leakage if the metrics port is exposed.
- `cordelia_replication_lag_seconds` is computed as `now() - last_successful_sync_at` per channel. High values indicate replication problems.
- SPOs already run Prometheus/Grafana for Cardano nodes. Same stack, zero learning curve.

---

### 3.16 The Local API of a Device, for the Names It Holds

> **v1 status.** What a personal node serves under `/api/v1/channels/`
> (decision 2026-10-04 §2.3, §16; `crates/cordelia-api/src/local.rs`). There
> are four routes. Nothing is created, joined or subscribed to: a request
> names a name that this device holds, and the channel is the name's, derived
> from the person's secret.

A device holds a name once it follows a recovery phrase and a folder of its
own is mapped to the name (`cordelia sync map`), or a carry that a person
asked for, or a recovery, brought the name in (§3.17). A request for a name that it
does not hold is `404`, and says how to hold one. On a device that follows no
recovery phrase each route below but `identity` is `400`, with the way on in
its message: such a device has no secret, and publishes nothing. A device
that has stopped (it was removed, is in no list, is in a fork, or could not
open a change) publishes nothing either: `publish`, and a `delete-key` of a
key that holds a version, are `400`. `entries` still answers there, with
what the device holds.

**A publish here goes through the path that the sync adapter's goes through,**
and so does a delete: one path for every entry that a node writes in a name.
So an entry written through the local API says what it was written after, as
the adapter's does.

#### POST /api/v1/channels/publish

**Request:**
```json
{ "channel": "github.com/owner/repo", "key": "notes.md", "content": "..." }
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `channel` | string | yes | The name, which this device holds |
| `key` | string | yes | What the value is published under: for a memory file, the file's name. There is no publishing without one |
| `content` | any | yes | A string is published as a text, which is what a memory file holds. Any other JSON is published as bytes that are no text: the sync adapter takes it for no version of a file |

**Response (200):**
```json
{
  "channel": "github.com/owner/repo",
  "key": "notes.md",
  "rev": 7,
  "entry": "<hex: the entry's ID>",
  "author": "cordelia_pk1...",
  "over": { "rev": 6, "kind": "text", "entries": ["<hex>"] }
}
```

`over` is what the entry was published over: the version that the slot held
when the request was read (its revision, which of `text`, `delete` and
`other` its value was, and the entries that the device held of it), or `null`
where the slot held no version. The read and the publish are made under one
hold of the database's lock.

**Errors:**
- `400` if `key` is missing, or the key and what is published under it are
  more than 60 KB together.
- `404` if this device does not hold the name.
- `409` if no revision is left under that key until the next change of
  devices (decision 2026-10-04 §2.3): nothing was written.

#### POST /api/v1/channels/entries

**Request:** `{ "channel": "github.com/owner/repo" }`

**Response (200):** the current version under each key, in order of key, as
the device's own store has it under the statement it has applied.

```json
{
  "channel": "github.com/owner/repo",
  "entries": [
    { "key": "notes.md", "rev": 7, "kind": "text", "deleted": false,
      "content": "...", "authors": ["cordelia_pk1..."], "conflicts": 0 }
  ]
}
```

A deleted key is listed, with `deleted: true` and `content: null`. `authors`
is every key that signed an entry which is that version. `conflicts` is how
many other versions stand at that revision: they lost the tie.

#### POST /api/v1/channels/delete-key

**Request:** `{ "channel": "github.com/owner/repo", "key": "notes.md" }`

A delete is published over the version that the slot holds, as any value is,
and the answer is the answer of a publish. `404` where the key holds no
version, or a delete already.

#### POST /api/v1/channels/identity, GET /api/v1/status, GET /api/v1/metrics

As §3.14 and §3.15, of the device's own channels: the channels counted are
the names that it holds, and what waits to be sent is what waits in a channel
of the device's own. Nothing of the older kind is read.

---

### 3.17 A Person's Devices

> **v1 status.** The routes behind `cordelia phrase`, `add-device`, `accept`,
> `devices`, `remove-device`, `renew`, `settle` and `init --new-key` (decision
> 2026-10-04 §5 to §8; `crates/cordelia-api/src/commands.rs`), and behind
> `cordelia sync carry` and `cordelia recover` (§7.3, §9;
> `crates/cordelia-api/src/carrying.rs`, `recover.rs`). Every node serves
> them.

- **No route takes a recovery phrase, and none is given one.** A command
  that needs the phrase reads it at its own terminal, signs and seals in its
  own process, and hands the node what it made: a change entry; for a new
  phrase and at a recovery the statement key; for a carry and for the look
  of a recovery a word that the phrase signed (below); proofs of a channel's
  key, each made for one connection; and at a recovery the secrets of the
  generation recovered from and of those before it, which the machine keeps.
  An entry and a statement travel as hex of their bytes.
- **No route asks a yes.** Every yes is asked by the command, at a terminal.
  A program that holds the node's token can make these calls itself. What it
  cannot do is have a phrase sign what a person was not shown (decision §5,
  and the threat model's T17).
- **Every route here is `409` once the device was given a new key** and the
  node has not been started again.
- **A node whose first start on this version is not done** (§3.18) answers
  `devices/list` and refuses the rest.

| Route | What it does |
|-------|--------------|
| `POST /api/v1/devices/list` | Everything `cordelia devices` and `cordelia status` say of this device and its person: where it stands (`state`: `no_phrase`, `applied`, `fork`, `removed`, `not_listed`, `not_opened`); the devices of the statement it has applied, each with whether it has applied the statement and sent what it carried; the devices added since, with who added each; the removed keys, each with the label that this device knew it by; the keys that are in neither list of the last change; the devices that have said they left; for each relay, whether it holds the latest change entry; the keys typed at `accept`; the notices that a person has not cleared; the names that no device lists yet; and what this device has still to send. Each device is shown with its label and the first four words of its key's fingerprint. What a status goes by for its level is here too: for each relay `holds_latest`, `heard_since_woke`, `connected_secs` (for how long the node has been connected to it, by the node's own clock) and `no_room_at` (when it last refused something for room, or for the address's allowance); `applied_at` (when this device applied the change) and `removed_a_key` (whether that change removed a key that the statement before had not); `names` (`sent`, `to_go`, and `to_go_since`, since when the first of them has waited); `not_reached` (the relays it is set up with and is not connected to); and `waiting` (for each connected relay, how many of the device's channels have something still to send there); and `sent_to_no_relay` (`versions` and `names`: how many versions, of how many names, this device holds that it has sent to no relay, which `cordelia phrase` and `cordelia init --new-key` say before their yes; both are 0 on a device that has stopped) |
| `POST /api/v1/devices/clear` | `{ "notice": "<hex>" }`: a person clears a notice on this device. `404` where it shows no such notice |
| `POST /api/v1/devices/add/look` | `{ "device": "cordelia_pk1...", "label": "desktop" }`: what adding that key would do, with nothing written: `would` is `add`, or `hand_again` for a key that the statement already lists |
| `POST /api/v1/devices/add` | The same body with `would`, which says what the yes was for. The device writes the hand-over in the pair channel and, where a record is made, the record in the personal channel. `409` where adding the key would by then do the other |
| `POST /api/v1/devices/accept` | `{ "key": "cordelia_pk1...", "row": "no_phrase" }`: a person typed a key. It is kept with its time and the row of the record's 5.1 that the yes named (`no_phrase`, `alone`, `several`, `not_listed`), and the node asks its relays for what that device hands over until it is taken or the hour is gone. Answers `typed_at` and `until`. Refused where no hand-over could be taken as the device stands, and a ninth key |
| `POST /api/v1/phrase/make` | `{ "entry": "<hex>", "statement_key": "<hex>", "from": "no_phrase" }`: the device starts alone under a new phrase. It is handed the first statement's change entry and the statement key, and never the words. `from` is where the device stood when the command asked its yes (`no_phrase`, `alone`, `several`) |
| `POST /api/v1/change/prepare` | `{ "settle": false }`: the device shows its change entry to each relay and fetches, for two minutes at most, runs a sync cycle, and hands the command what it signs over and shows: the statement applied and the change entry kept, as their signed bytes; the record of each device added since; in a fork, the statement made apart and its entry; the names that the personal channel lists, each with the keys that list it; how much each device wrote that this one received in the last day and week; and what it could not fetch |
| `POST /api/v1/change/make` | `{ "entry": "<hex>", "over": "<hex>", "apart": null }`: the node's half of a change that a command made with the phrase. One transaction, in which what the prompt showed is checked again: `409` where a statement arrived meanwhile, and nothing is made. Answers the change's number, how much was carried, and the files whose record could not be carried |
| `POST /api/v1/devices/leave` | What a device owes the devices it leaves, before it is given a new key: its word that it has left, and a delete over each hand-over that a relay was sent |
| `POST /api/v1/devices/leave/sent` | For each relay the node is connected to, how many of the device's channels still have something waiting to be sent there |
| `POST /api/v1/devices/leave/back` | The device takes back its word that it has left: for `cordelia init --new-key` that a person stops at its second yes |
| `POST /api/v1/devices/forget` | The device forgets what it holds of its person, and then follows no phrase: for a device that is given a new key |

A refusal says the way on in its message: "this device follows no recovery
phrase yet. Make one here (`cordelia phrase`), or add this device from one
that has one", and so on. What a person did that is refused is `400`, and what
changed under a prompt is `409`.

**A carry that a person asks for, and recovery** (decision 2026-10-04 §7.3,
§9). The command reads the recovery phrase, as the commands above do. What a
removed key signed, and what a command read in a generation that this device
never held, comes in only under **a word that the phrase signed:**

```json
{ "what": "{\"from\":{\"name\":\"lab\",\"keys\":[\"<hex>\"],\"above\":[]}}",
  "until": 1791000600, "signature": "<hex>" }
```

- `what` is the text that was signed, and the node reads what it is to do
  from that text and from nothing beside it. It is one of `{"from": {"name",
  "keys", "above"}}` (`sync carry --from`: the removed keys, and the files
  that a second yes named), `{"handed": {"name"}}` (`sync carry --phrase`) and
  `{"look": {"names", "takes"}}` (`recover`: the names that are carried, and
  the keys that the look takes from).
- The phrase's key signs it under the label `cordelia v2 carry word`, with
  this device's key, the ID of the change entry that the device keeps, and
  `until`. It stands for ten minutes (`CARRY_WORD_SECS`), for that device and
  under that change entry: a change that reaches the device meanwhile ends
  it. A program that holds the node's token cannot make one.

| Route | What it does |
|-------|--------------|
| `POST /api/v1/carry` | `{ "name": "lab" }`: carry one name, with no phrase. The device comes to hold the name, fetches its new channel, and reads the name's channel at each relay in each generation that it left and still holds the secret of, for two minutes at most. What keys that count signed comes in, each version as this device's own entry at the revision it had, where the new channel holds neither that version nor an entry at a higher revision. Answers `name`; `held_anew` (the device came to hold the name by this); `generations` (for each, its `number`, `relays`, each with its `relay`, how it was `read`: `whole`, `part`, `not held`, `not reached` or `not read: <why>`, and `entries`, how many entries of the channel that relay handed; and `by_other_keys`); `carried`, `held` (the new channel held that version already) and `higher` (it holds a higher revision), as counts; `ties` and `above`, by file; `deletes`; `by_other_keys` (entries that other keys signed, which are left); `read_all`; and `nothing`, which says why where nothing was tried |
| `POST /api/v1/carry/from/look` | `{ "name": "lab", "from": ["desktop"] }`: what `sync carry --from` says before it asks anything. Nothing is taken. Each of `from` names a removed key by the label that this device knew it by, or by the first six words of its key's fingerprint: `400` where it matches two removed keys, or none. Answers `signed`: each removed key that signed there, with its `key` (hex), `words` (the six), `shown` (the four that a device is shown by), `label` and `entries`. With keys named it also answers `keys`; `empty` (how many versions would go into slots where the new channel holds nothing); `above` (the files of which a version stands above one that the new channel holds); `held`, `higher`, `ties` and `deletes`; `has_folder` (whether a folder of this device's is mapped to the name); and `under`, the ID of the change entry that the device keeps, which the word is given under |
| `POST /api/v1/carry/from` | `{ "word": { ... } }`: take what the word allows, and nothing beyond it. For each file the newest version among the named keys is judged once: it comes in where the new channel holds nothing in that slot, and above a version that it holds only for a file that the word names. A delete that a removed key signed is never taken. Answers as `/carry` does. Refused, with nothing taken: a word that does not hold; a key that the statement applied does not list as removed; and a file named to come in above a version, for a name that no folder of this device's is mapped to |
| `POST /api/v1/carry/phrase/look` | `{ "name": "lab" }`: what `sync carry --phrase` is handed before it asks for the phrase. The device comes to hold the name, and fetches its new channel. Answers `entry`, the change entry that the device keeps (hex), whose part for the phrase the command opens in its own process, and `under`, its ID; `held`, the ID of the name's channel in each generation whose secret the device holds, which the plain command reads; `counts`, the keys that count; and `sessions`, each relay by its name with the value of its connection's session (hex, or null where it is not reached), over which the command makes its proofs |
| `POST /api/v1/carry/read` | `{ "channel": "<hex>", "proofs": [{ "relay": "relay1.example:9474", "proof": "<hex>" }] }`: read, at each relay, a channel whose secret the node does not hold, with proofs that the command made. The node proves and pulls, and is handed no secret. It is how a command reads the phrase's own channel, and a channel of a generation that this device never held. Answers `relays` (what is said of each, as above), `entries` (how many were handed) and `read`, what the reading is named by |
| `POST /api/v1/carry/read/part` | `{ "read": 7, "from": 0 }`: a part of that reading, from the entry numbered `from`: as many entries as fit 512 KB (`CARRY_PART_MAX_BYTES`), each as hex of its bytes, and `next`, where the next part begins, or null. Only the last reading is kept: an older one is `400` |
| `POST /api/v1/carry/handed` | `{ "word": { ... }, "versions": [{ "name": "notes.md", "rev": 7, "text": "...", "signer": "<hex>", "chain": ["<hex>"] }] }`: the versions that the command read in generations whose secret this device never held, in the clear. `text` is null for a delete, and `chain` is each link as hex, or null where the entry lacked its chain. Each is judged as `/carry` judges a version that the node read itself. One whose signer does not count is counted, and not taken. Answers as `/carry` does |
| `POST /api/v1/recover/look` | What `cordelia recover` asks before anything else: `this_device`; `follows_a_phrase` (a recovery is refused where the device does); and `sessions`, each relay that the device is set up with, with the value of its connection's session. A relay with no session is not reached |
| `POST /api/v1/recover/make` | `{ "entry": "<hex>", "statement_key": "<hex>", "left": [{ "number": 3, "secret": "<hex>" }], "gone": [{ "key": "<hex>", "label": "laptop" }], "still_have": [], "word": { ... } }`: the node's half of a recovery, in one transaction. `entry` is the change entry of the recovery's statement, which the command made; `left` the secrets of the generation recovered from and of those before it, which the machine keeps as a device keeps a secret it left; `gone` the keys that the statement newly removes, and `still_have` the devices that the person still has, each with the label it was shown by; and `word` the phrase's word for the look, under this very entry. The statement is applied, the names of the look are listed in the new personal channel, and the node is woken: it shows the change entry to every relay before anything is carried. Answers `{ "change": <number> }`. The look is begun, and goes on after the answer |
| `POST /api/v1/recover/progress` | `{ "look": ... }`: how far the look is. While it runs: `change`, `finished: false`, `names` (how many it reads) and `read` (how many it has read). Once it has ended, also `carried` and `carried_names`; `held` and `higher`; `ties`; `not_read`, each name that could not be read to its end, with the `change` (the generation), the `relay` and how it was `read`; `failed`; and `lacking`, for each removed key how many `versions` that key signed in what was read that the new channels lack, with the `names` they are in, its `key` and its `label`. `null` where this node has made no look since it started: one that was interrupted is not taken up again by itself |

**What binds what a command hands the node** (decision 2026-10-04 §16):

- **A word is taken once.** The node keeps a taken word's signature until the
  word is void (ten minutes), and refuses it a second time.
- **A batch is signed by the key of its run.** The word names a key that the
  command makes for that one run. `POST /api/v1/carry/handed` takes
  `{ "word", "number", "signature", "versions" }`: the signature is that key's,
  under a label of its own (`cordelia v2 carry batch`), over the batch's number
  and the hash of its versions as they are handed, and the node takes each
  number once. A version at a revision that no entry may have under the
  applied statement refuses the batch whole. A batch holds 512 KB of versions
  at most (`CARRY_HANDED_MAX_BYTES`), and the body of any request to a device's
  routes 2 MB (`LOCAL_API_BODY_MAX_BYTES`): a larger body is refused and not
  read.
- **A proof goes with its session.** `POST /api/v1/carry/sessions` answers
  each relay that the device is set up with and the value of its connection's
  session, as `/recover/look` does. Each proof in `/carry/read` carries the
  `session` it was made over. Where the connection has changed since, that
  relay is answered "not read: the connection changed", and the command makes
  its proofs again (twice at most, `CARRY_PROOFS_MADE_AGAIN`); where a
  connection has no place left for a proof it is "not read: no room left for a
  proof", and the node makes the connection again. Neither is ever "the relay
  holds none".
- **Nothing is taken where the new channel was not fetched whole.**
  `/carry/from/look` answers `new_read`, whether it was; a recovery's progress
  answers `new_not_read`. Keys in both carry `by_words`, how to name them to
  `--from` where a label would not tell them apart (a key written whole is
  taken too).
- **A recovery that could not show every row** hands `not_shown` to
  `/recover/make`, the keys it did not show, and `/devices/list` then carries
  each as left out with its `key`. A name that a carry or a recovery brought in
  and has not yet sent is in `/devices/list` as `carried_to_go`, with
  `carried_to_go_since`.
- **`POST /api/v1/sync/unmap`** with a name that no folder maps and that a carry
  holds lets go of it, and answers `let_go`.

---

### 3.18 Sync, and a Node That Is Held Up

> **v1 status.** `/api/v1/sync/{claude,map,unmap,status,seen}`, per the
> decision record of 2026-09-30 §4.5, with what the decision record of
> 2026-10-04 §10.1 changes.

- **Only what is mapped syncs.** A folder syncs because `map` declared it,
  and for no other reason. A request to `sync/claude` that turns on a scope
  of everything found (`all`) is refused. `exclude` and `home`, which a panel
  of the version before may still send, are accepted and stored as before:
  there is nothing left to exclude. A request that turns sync off is never
  refused.
- **`map`** forgets what the folder it adds had agreed, and its first cycle
  in the name's channel waits until a relay has handed that channel. Where
  the device comes to hold the name by it, it carries the name first
  (decision 2026-10-04 §7.3), and the answer has what was carried under
  `carried`, in the form that `/api/v1/carry` answers.
- **`POST /api/v1/sync/seen`** takes the notice of what stopped syncing
  away: a person has seen it. It is the one request that does. It changes no
  setting, and answers as `sync/status` does. With no notice stored it does
  nothing.
- **`sync/status`** answers, as `claude`, `map`, `unmap` and `seen` do:

  | Field | What it is |
  |-------|------------|
  | `enabled`, `dir` | Whether sync is on, and the Claude Code directory it is on for |
  | `all` | Always `false`: only the declared mappings sync |
  | `mappings` | The declared mappings, each a `folder` and a `name` |
  | `exclude`, `home`, `home_name` | The stored list of exclusions, which nothing reads to say what syncs; the switch for home memory; and the name that home memory syncs under, or last did |
  | `generation` | How many times the settings have changed since the node started. A report carries the generation it was made under |
  | `report` | The last cycle's report, once one has run: each folder that syncs, what was found and is not mapped (`unmapped`, each a found entry, below), and the cycle's errors |
  | `no_report_secs` | For how long the node has stored no report, by its own clock, which does not run while the machine sleeps: since the later of its start and the last report. A status says by it that the cycle has stalled |
  | `last_change_at` | When a cycle last sent or received a memory |
  | `stands` | Where the device stands under a recovery phrase: `no_phrase`, `applied`, or why it has stopped (`fork`, `removed`, `not_listed`, `not_opened`) |
  | `held` | Why the node is held up, in words, where it is |
  | `moved_on` | Whether the device took this version with what an earlier one held: with no phrase it is then "not added yet" |
  | `notice` | The notice of the folders that stopped syncing, while one is stored, with sync on and with it off: `records`, one for each time a notice was stored (`at`, `dir`, and `folders`, how many it names, or null where which stopped is not known); `not_known`, whether some record names none; `dir`, the Claude Code directory that its folders are asked against; `folders`, each folder that the records name, once, as a found entry with `synced_under` (the Claude Code directory it synced under) and `at`; and `stopped`, how many of them no mapping syncs now |

  **A found entry** is a folder that was found and is not mapped:

  | Field | What it is |
  |-------|------------|
  | `folder` | Claude Code's folder for it |
  | `cwd` | The directory to map to sync it. It is carried only where `cordelia sync map`, given this directory, would sync this folder |
  | `directory` | The directory it belongs to, where one is known and `map` would not sync this folder: to show, and never to map |
  | `name` | The name it would sync under, or did: `~` for home, the remote for a git project, none for any other folder |
  | `mappable` | Whether `map`, given the directory under `cwd`, would sync this folder |
  | `needs_name` | Present and true where it can be mapped only under a name that a person gives it |
  | `home` | Present and true where it is the home directory's own folder |
  | `mapped` | Present and true where a mapping syncs it now, as a folder of a notice can be |
  | `why_not` | Why `map` would not sync it, in a word: `another_claude_dir`, `laid_out_by_hand`, `no_directory`, `home_not_set`, `outside_home`, `path_too_long`, `directory_gone`, `through_a_link`, `git_not_run` or `memory_elsewhere` |
  | `says` | Why not, or why a name is needed, in words |
- **`GET /api/v1/status`** answers `status`; `version`, so that a command
  can tell a node of another version; `uptime_secs`; `peers_hot` and
  `peers_warm`; `channels_subscribed`; `sync_errors`; `outbox_waiting` and
  `outbox_refused`; `held`, which is null, or by what the node is held up
  (`by`: `first_start` or `later_database`) and why (`why`);
  `key_files_in_place`, how many key files of an older version were left in
  place at this start because no copy holds them; and `no_relay_secs`, for
  how long no relay has been connected, by the node's own clock, or null
  while one is.
- **`cordelia status --json`,** which a panel reads, is worked out by the
  command from `GET /api/v1/status` and `sync/status`, and carries what
  `devices/list` answers under `person`. Its `state` is one of seven names
  (`synced`, `syncing`, `offline`, `attention`, `off`, `stopped`,
  `uninitialised`). Where the node runs and sync is on, a device with a
  folder mapped and no recovery phrase, and one with a notice of what
  stopped at the first start, has the state `attention`, so that a panel
  which draws from the state alone does not show it as synced. So has a
  device that has stopped, and a node that is held up, with sync on or off.
  - **`level`** is `red`, `amber`, or null where none holds (decision
    2026-10-04 §10.1). Only the command works it out: a panel draws it.
  - **`summary`** is the first thing of that level, and with no level what
    the state says.
  - **`holds`** is everything that holds, red first, each with its `level`,
    `what` it is in a word, and what the line `says` of it. `what` is one of
    `stopped`, `held`, `no_phrase`, `errors`, `stalled`, `stopped_syncing`,
    `conflicts` and `too_large` (red), and `no_relay`, `refused`,
    `other_version`, `removal_not_applied`, `added`, `left`,
    `relay_without_latest`, `relay_no_room` and `names` (amber).
  - Of the node: `running` (null where the command did not ask it, with why
    under `not_asked`); `version`, the command's own, and `node_version`;
    `held` and `key_files_in_place`, where they are set; `uptime_secs`;
    `no_relay_secs`; `peers`; `outbox_waiting` and `outbox_refused`.
  - Under `sync`: the settings; `projects`, one for each folder that syncs;
    `unmapped`, the found entries; `available`; `stands` and `moved_on`;
    `publishes_nothing`, why nothing is published from this device where
    nothing is; `conflicts` and `errors`; and `notice`, as `sync/status`
    answers it, or null where the node stores none.
- **A node whose first start on this version is not done** (decision
  2026-10-04 §10.1) runs no cycle and no pass. It answers every `GET`,
  `sync/status`, `devices/list`, `history/list`, `history/show`,
  `channels/entries` and `channels/identity`, and a request to `sync/claude`
  that turns sync off. It refuses every other request with `503`, the code
  `held_up`, and why it is held up. A node whose database is from a later
  version answers every `GET` and nothing else: it writes nothing, so there
  even turning sync off is refused.

---

## 4. Channel ID Formats

> **v1 status.** These are the IDs of the older kind. The ID of a channel
> from its secret is the public half of a signing key derived from that
> secret, written `cordelia_ch1...` (data-formats.md §9.1). The local API of
> a device takes a name and never an ID.

Three channel types, three ID formats:

| Type | ID Format | Example | Derivation |
|------|-----------|---------|-----------|
| Named channel | `hex(SHA-256("cordelia:channel:" + name))` | `a1b2c3...` (64 hex chars) | Deterministic, domain-separated |
| DM | `"dm_" + hex(SHA-256("cordelia:dm:" \|\| sort([pk_a, pk_b])))` | `dm_d4e5f6...` | Deterministic, domain-separated |
| Group conversation | `grp_<uuid>` | `grp_550e8400-e29b-41d4-a716-446655440000` | Random UUID v4 |

**Channel name resolution:**
- Named channels: use the `channel` field (string name) in all endpoints
- DMs: use `channel_id` returned from `/channels/dm` in publish/listen
- Group conversations: use `channel_id` returned from `/channels/group` in publish/listen

**Resolution rules:**
- Named channels: always use the channel name (string). The node computes the SHA-256 internally. Raw hex channel_ids are NOT accepted for named channels -- the name is the canonical identifier.
- DMs: use the `dm_` prefixed channel_id returned from `/channels/dm`
- Group conversations: use the `grp_` prefixed channel_id returned from `/channels/group`

The node disambiguates by prefix: `dm_` → DM lookup, `grp_` → group lookup, anything else → named channel (SHA-256 hash). This is safe because `dm_` and `grp_` contain underscores, which are illegal in RFC 1035 channel names.

---

## 5. Channel Name Rules

Channel names follow RFC 1035 label syntax (same as DNS labels):

| Rule | Constraint |
|------|-----------|
| Length | 3-63 characters |
| Characters | Lowercase `a-z`, digits `0-9`, hyphens `-` |
| Start | Must start with a letter |
| End | Must not end with a hyphen |
| Case | Lowercase only (uppercased input is lowercased before hashing) |
| Reserved prefix | `cordelia:` reserved for protocol channels |
| Reserved character | `/` reserved for future hierarchical namespaces |

**Protocol channels** (Phase 2+):
- `cordelia:directory` -- decentralised keeper directory
- `cordelia:channels` -- public channel registry

These use a well-known PSK (technically encrypted, practically public). See architecture ADR §9.

---

## 6. PSK Distribution

> **v1 status.** Of the older kind of channel. A channel from its secret has
> no key to distribute for each channel: every device of a person derives
> every channel of that person's own from the one person secret, and a device
> is handed that secret once, when it is added (decision 2026-10-04 §2.2, §6).

### 6.1 Open Channels

When a new member subscribes to an open channel:

1. The node already holds the channel PSK (if it created the channel or received it from a keeper)
2. Node wraps PSK in ECIES envelope for the new subscriber's X25519 public key
3. PSK distribution happens within the subscribe response (the node stores the PSK locally)

In a multi-node scenario (subscriber connects to a different node than the creator):
see §11 (PSK Discovery) for the full P2P flow via QUIC.

### 6.2 Invite-Only Channels

PSK distribution happens out-of-band:
1. Owner calls `/channels/group/invite` with the invitee's public key
2. Node creates ECIES envelope for the invitee
3. Envelope is stored as a channel item and replicated to the invitee's node
4. Invitee's node detects the envelope, decrypts with their X25519 private key, stores PSK

### 6.3 DMs

Same as invite-only but automated:
1. Initiator creates DM channel and PSK
2. ECIES envelope for peer stored as first channel item
3. Replicated to peer's node via eager push
4. Peer's node auto-decrypts and stores PSK

---

## 7. API Surface (Greenfield)

Phase 1 is a greenfield build. The existing node API (L1/L2/groups) is reference material, not baseline. The Phase 1 node exposes:

| Namespace | Endpoints | Purpose |
|-----------|-----------|---------|
| `/api/v1/channels/*` | 14 endpoints (this spec, §3.1-§3.14) | Pub/sub, DMs, groups, search, identity, PSK rotation |
| `/api/v1/health` | 1 endpoint (no auth) | Liveness check (`healthy` / `degraded`). See operations.md §8. |
| `/api/v1/status` | 1 endpoint | Node health (authenticated, detailed) |
| `/api/v1/peers` | 1 endpoint | Peer list |
| `/api/v1/diagnostics` | 1 endpoint | Full diagnostics |
| `/api/v1/metrics` | 1 endpoint (§3.15) | Prometheus exposition (WP13) |

**Not carried forward from the existing API:**
- `l2/*` endpoints -- superseded by channels/publish, channels/listen, channels/delete-item, channels/search
- `groups/*` endpoints -- superseded by channels/subscribe, channels/group, channels/group/invite, channels/group/remove
- `l1/*` endpoints -- personal memory is a personal channel in the greenfield model (auto-created at `cordelia init`)
- `devices/*` endpoints -- portal enrollment deprecated, replaced by local `cordelia init`

This is a clean break. Zero backward compatibility with the pre-pivot API. No migration path needed (no external adoption to protect).

> **v1 status.** The namespaces a node serves in this version, by role:
>
> | Namespace | Personal node | Relay, bootnode |
> |-----------|---------------|-----------------|
> | `/api/v1/channels/*` | `publish`, `entries`, `delete-key`, `identity` for the names it holds (§3.16) | The Channels API of the older kind (§3.1 to §3.14) |
> | `/api/v1/devices/*`, `/api/v1/phrase/make`, `/api/v1/change/*` | A person's devices (§3.17) | Served |
> | `/api/v1/sync/*`, `/api/v1/history/*` | Sync and local history (§3.18) | Served |
> | `/api/v1/status`, `/api/v1/metrics`, `/api/v1/health`, `/api/v1/peers` | Yes | Yes |
>
> `/api/v1/diagnostics` is not served.

---

## 8. SDK Mapping

How the TypeScript SDK maps to API endpoints:

```typescript
const c = new Cordelia()

// Maps to: POST /channels/subscribe
await c.subscribe('research-findings')
await c.subscribe('archive', { mode: 'batch' })

// Maps to: POST /channels/publish
await c.publish('research-findings', { type: 'insight', text: '...' })

// Maps to: POST /channels/listen (polling loop)
const items = await c.listen('research-findings')
const items = await c.listen('research-findings', { since: cursor })

// Maps to: POST /channels/dm
const dm = await c.dm('cordelia_pk1...')
await dm.send({ text: 'Hey, thoughts on the pivot?' })    // POST /channels/publish
const msgs = await dm.listen()                              // POST /channels/listen

// Maps to: POST /channels/group
const group = await c.group(['cordelia_pk1...', 'cordelia_pk1...'], { name: 'project-x' })
await group.invite('cordelia_pk1...')                        // POST /channels/group/invite
await group.remove('cordelia_pk1...')                        // POST /channels/group/remove

// Maps to: POST /channels/search
const results = await c.search('research-findings', 'vector embeddings')

// Maps to: POST /channels/list
const channels = await c.channels()

// Maps to: POST /channels/identity
const identity = await c.identity()
```

---

## 9. Rate Limits and Quotas

### 9.1 Phase 1 Rate Limits (localhost)

Phase 1 runs on localhost (bearer-auth), but still enforces creation rate limits to prevent local resource exhaustion and Sybil-adjacent abuse. Rate-limited requests return `429 rate_limited` with the format defined in §9.4. The table below lists per-endpoint limits.

| Operation | Endpoint | Limit | Rationale |
|-----------|----------|-------|-----------|
| Subscribe (channel creation) | `POST /channels/subscribe` | 1/second per entity | Prevent ephemeral channel griefing (E13) |
| DM creation | `POST /channels/dm` | 5/minute per entity | Prevent DM spam (E12) |
| Publish | `POST /channels/publish` | 100/minute per channel | Prevent storage flooding |
| Channel creation (total) | `POST /channels/subscribe` | 50 channels per entity | Hard cap on local PSK/metadata storage |

Exceeding creation limits returns `429`. Exceeding the channel cap returns `403` with `code: "channel_limit_reached"`.

### 9.2 Phase 2+ Rate Limits (keeper-enforced, remote access)

- Subscribe: 10/minute per entity
- Publish: 100/minute per channel per entity
- Listen: 60/minute per channel (polling)
- Search: 30/minute per channel
- DM creation: 5/minute per entity
- Group creation: 5/minute per entity

### 9.3 Storage Quota Enforcement (E5)

Keepers enforce per-entity storage quotas. The node enforces local storage limits.

**Quota check on publish (§3.2):**

After step 2 (resolve channel), before step 3 (encrypt):

```
IF entity_storage_used + content_size > entity_quota THEN
    return 413 Payload Too Large {
        "code": "quota_exceeded",
        "used_bytes": <current>,
        "quota_bytes": <limit>,
        "message": "Storage quota exceeded"
    }
```

**Quota tiers (keeper-enforced, Phase 3):**

| Tier | Storage | Channels | Requirement |
|------|---------|----------|-------------|
| Free | 10 MB | 2 | None |
| Supporter | 100 MB | 20 | 500 ADA delegation |
| Premium | 1 GB | 100 | 5000 ADA delegation |
| Unlimited | No cap | No cap | Direct ADA payment (Phase 4) |

**Phase 1 local defaults:** 1 GB storage, 50 channels per entity. These are local resource limits, not commercial tiers.

**Replication vs quota:** Items replicated from peers are stored regardless of quota (the node cannot reject replicated items without breaking convergence). Quota applies only to local writes via the API. If replicated storage exceeds local capacity, the node applies LRU eviction for relay-cached items (ciphertext only, not subscribed channels).

### 9.4 Rate Limit Response Format

Rate limit responses return `429` with:
```json
{
  "error": {
    "code": "rate_limited",
    "message": "Rate limit exceeded",
    "retry_after_seconds": 5
  }
}
```

---

## 10. Delivery Model

### 10.1 Semantics

Cordelia's delivery model is **durable log with cursor-based consumption.** Items are persisted and replicated -- they are not volatile messages.

| Property | Cordelia Phase 1 | Comparison |
|----------|-----------------|------------|
| Persistence | Items stored in SQLite, replicated to peers | Like Kafka (persistent log), unlike MQTT QoS 0 (fire-and-forget) |
| Delivery | Eventual (replication to all subscribers' nodes) | Like NATS JetStream |
| Consumption | Cursor-based polling (timestamp) | Like Atom/RSS (RFC 4287), Kafka consumer offset |
| Ordering | Timestamp-ordered, `item_id` tiebreak | Like Kafka partition ordering |
| Missed items | Never lost. Items arrive via replication. Listen returns whatever has arrived. | Unlike MQTT QoS 0 where missed = gone |
| Duplicates | Possible during replication. Clients should deduplicate by `item_id`. | Standard for distributed logs |
| Deletion | Tombstone propagation (CoW). Tombstoned items excluded from listen. | Like Kafka compaction |

### 10.2 Guarantees

1. **Items are durable.** Once published, an item is persisted locally and replicated to peers. It will not be lost unless all replicas are destroyed.
2. **Delivery is eventual.** A subscriber's node will receive all items for its channels via replication, but latency depends on network conditions and replication mode (realtime = seconds, batch = minutes).
3. **Listen is a window.** The listen endpoint returns items that have arrived at the local node. If replication is delayed, recently published items from remote peers may not yet be available.
4. **Cursors are best-effort.** If an item is tombstoned between polls, the listener never sees it. This is consistent with pub/sub semantics and is the expected behaviour for deleted content.
5. **Ordering is local.** Items are ordered by `published_at` timestamp at the local node. Clock skew between publishers may cause items to appear out of causal order. Phase 2 may introduce vector clocks if needed.

### 10.3 Phase 2: Server-Sent Events

Phase 2 adds `GET /api/v1/channels/listen/stream` for push-based delivery via SSE (W3C Server-Sent Events). The `Last-Event-ID` header maps to our cursor, enabling resumption after disconnection.

### 10.4 Reference Standards

- **RFC 4287** (Atom Syndication Format): poll-based feed consumption with `<updated>` cursor
- **RFC 5005** (Feed Paging and Archiving): pagination model for feed-style data
- **W3C Server-Sent Events**: push delivery with `Last-Event-ID` resumption (Phase 2)
- **Apache Kafka**: durable log with consumer offset -- closest architectural model
- **NATS JetStream**: persistent streaming with consumer acknowledgment

---

## 11. PSK Discovery (Multi-Node)

Phase 1 PSK distribution has two distinct flows:

1. **Channel creation** (first subscriber): The creating node generates the PSK, creates the ChannelDescriptor, and becomes the initial PSK holder. The channel exists locally first.
2. **Channel join** (subsequent subscribers): The joining node discovers the channel via Channel-Announce, then requests the PSK via PSK-Exchange (network-protocol.md §4.7) from any peer that holds it. The node retries up to 3 times across different peers with 5-second exponential backoff before returning an error.

There is no designated keeper in Phase 1. Any subscriber holding the PSK may respond to PSK-Exchange requests for open channels. Simultaneous creation of the same named channel on two disconnected nodes results in two independent channels with the same name but different channel_ids and PSKs. These are reconciled when nodes connect: the first-seen descriptor wins per node (network-protocol.md §4.4.6).

When a subscriber's node doesn't already hold the PSK for an open channel, it requests it from any peer that holds the PSK via the existing P2P transport (QUIC):

```
1. Subscriber calls POST /channels/subscribe
2. Local node resolves channel_id from name
3. Local node checks ~/.cordelia/channel-keys/<channel_id>.key
4. PSK not found locally
5. Node selects a hot peer that advertises the channel (via Channel-Announce, network-protocol.md §4.4)
6. Node sends PSKRequest(channel_id, subscriber_xpk) via PSK-Exchange mini-protocol (network-protocol.md §4.7)
7. Peer verifies channel access policy (open → auto-approve)
8. Peer wraps PSK in ECIES envelope for subscriber's X25519 public key
9. Peer returns envelope via QUIC
10. Subscriber's node decrypts envelope, stores PSK locally
11. Subscribe response returns to caller
```

No new HTTP endpoint needed. Uses the same QUIC transport as replication. In Phase 1, there is no designated keeper -- any subscriber holding the PSK can respond to PSK-Exchange requests for open channels (network-protocol.md §4.7). Phase 2 introduces anchor keepers with a dedicated field in the channel descriptor.

For invite-only channels: step 7 fails (`not_authorized`). PSK must be distributed via `/channels/group/invite` by an existing member.

---

## 12. Resolved Questions

1. **Channel name vs channel_id**: Named channels always use names. DMs use `dm_` prefix, groups use `grp_` prefix. No raw hex IDs. Prefix disambiguation is safe (underscore is illegal in RFC 1035 names).

2. **PSK discovery**: P2P request to any peer holding the PSK via QUIC (§11). No new HTTP endpoints. Phase 2 adds anchor keeper role.

3. **Item deletion**: Dedicated `POST /channels/delete-item` endpoint (§3.12). Clean break from pre-pivot `l2/delete`.

4. **Cursor stability**: Accepted. Tombstoned items between polls are simply never seen. Consistent with durable log consumption semantics (§10).

---

## 13. References

- **specs/ecies-envelope-encryption.md**: Cryptographic primitives (ECIES, AES-256-GCM, Bech32 encoding, CBOR signing, AAD binding)
- **cordelia-core/docs/reference/api.md**: Pre-pivot node API (reference only, not carried forward)
- **decisions/2026-03-09-mvp-implementation-plan.md**: WP3 scope and endpoint definitions
- **decisions/2026-03-09-architecture-simplification.md**: Provider interface, channel encryption model
- **decisions/2026-03-10-identity-privacy-model.md**: DM derivation, namespace rules, access policies
- **decisions/2026-03-10-phase1-design-decisions.md**: Node is encryption boundary, greenfield build
- **RFC 4287**: Atom Syndication Format (cursor-based polling model)
- **W3C Server-Sent Events**: Push delivery specification (Phase 2)

---

*Draft: 2026-03-10. Review with Martin before implementation.*
