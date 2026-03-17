# Data Formats Specification

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-12
**Scope**: Phase 1 (Encrypted Pub/Sub MVP)
**Implements**: Storage layer for WP2, WP3, WP4, WP8
**Depends on**: specs/ecies-envelope-encryption.md, specs/channels-api.md, specs/channel-naming.md, specs/search-indexing.md, specs/identity.md

---

## 1. Purpose

This spec defines the SQLite schema and internal data structures that sit between the Channels API (developer-facing) and the wire protocol (network-facing). It is the authoritative reference for:

- SQLite table definitions (DDL)
- PSK envelope item structure (special-case items not encrypted with channel PSK)
- Schema migration framework
- Column-to-API field mappings

The specs that describe *what* happens (channels-api.md, ecies-envelope-encryption.md) depend on this spec for *how* data is stored.

---

## 2. SQLite Database

Single file: `~/.cordelia/cordelia.db` (mode 0600). WAL mode enabled for concurrent read/write.

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA user_version = 1;      -- schema version, incremented per migration
```

### 2.1 Schema Version

The node checks `PRAGMA user_version` on startup and applies pending migrations in order. Each migration is idempotent (re-running a migration on an already-migrated database is a no-op). Migrations are embedded in the binary, not external SQL files.

---

## 3. Core Tables

### 3.1 channels

Channel metadata. One row per channel the node knows about (subscribed or observed via Channel-Announce).

```sql
CREATE TABLE channels (
    channel_id    TEXT PRIMARY KEY,     -- hex SHA-256 (named), "dm_"+hex (DM), "grp_"+UUID (group)
    channel_name  TEXT,                 -- human-readable name (NULL for DMs and unnamed groups)
    channel_type  TEXT NOT NULL,        -- "named" | "dm" | "group"
    mode          TEXT NOT NULL,        -- "realtime" | "batch"
    access        TEXT NOT NULL,        -- "open" | "invite_only"
    creator_id    BLOB NOT NULL,        -- Ed25519 public key (32 bytes)
    key_version   INTEGER NOT NULL DEFAULT 1,  -- current PSK version
    psk_hash      BLOB,                -- SHA-256 of current PSK (32 bytes). NULL if node does not hold PSK.
    descriptor    BLOB,                -- CBOR-encoded signed ChannelDescriptor (network-protocol.md §4.4.6)
    created_at    TEXT NOT NULL,        -- ISO 8601
    updated_at    TEXT NOT NULL         -- ISO 8601, updated on descriptor change or key rotation
);

CREATE UNIQUE INDEX idx_channels_name ON channels(channel_name)
    WHERE channel_name IS NOT NULL AND channel_type = 'named';
```

**Relay auto-creation:** When a relay node receives an Item-Push for a `channel_id` not present in its `channels` table, it MUST insert a minimal row before storing the item:

```sql
INSERT OR IGNORE INTO channels
    (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
VALUES (?1, 'named', 'realtime', 'open', X'00', datetime('now'), datetime('now'));
```

This satisfies the foreign key constraint on `items.channel_id` without requiring the relay to subscribe. The `creator_id = X'00'` (null key) distinguishes relay-created rows from user-subscribed channels.

**Phase 1 (transparent relay):** Relays store all received items and auto-create channel rows as above.

**Phase 2+ (lazy storage, network-protocol.md §7.2):** Relays only store items for channels that at least one hot peer has announced interest in via Channel-Announce (§4.4). Items for channels with no local interest are forwarded but not persisted. The auto-creation INSERT is conditional on routing table membership.

**Notes:**
- `channel_name` is unique only for named channels. DMs and groups may have NULL or non-unique labels.
- `psk_hash` is `SHA-256(psk)`, not the PSK itself. Used for descriptor verification (network-protocol.md §4.4.6). NULL means this node has observed the channel via Channel-Announce but does not hold the PSK (not subscribed).
- `descriptor` stores the full signed CBOR descriptor for forwarding to new peers. Updated on rotation.

### 3.2 channel_members

Membership roster per channel. Local view — may lag behind the network during replication.

```sql
CREATE TABLE channel_members (
    channel_id   TEXT NOT NULL REFERENCES channels(channel_id),
    entity_key   BLOB NOT NULL,        -- Ed25519 public key (32 bytes)
    role         TEXT NOT NULL,         -- "owner" | "admin" | "member"
    posture      TEXT NOT NULL DEFAULT 'active',  -- "active" | "removed"
    joined_at    TEXT NOT NULL,         -- ISO 8601
    removed_at   TEXT,                  -- ISO 8601, set when posture = "removed"
    PRIMARY KEY (channel_id, entity_key)
);

CREATE INDEX idx_members_entity ON channel_members(entity_key);
```

**Notes:**
- `posture = "removed"` is a soft removal. Row retained for audit and PSK rotation history.
- The local node's own membership is a row where `entity_key` matches the local Ed25519 public key.
- `role` is set at join time and can be changed by the owner.

### 3.3 channel_keys

Encrypted PSK storage. The node's own channel PSKs, encrypted at rest with the node's personal channel PSK. One row per channel the node is subscribed to.

```sql
CREATE TABLE channel_keys (
    channel_id     TEXT PRIMARY KEY REFERENCES channels(channel_id),
    encrypted_psk  BLOB NOT NULL,      -- AES-256-GCM encrypted PSK (iv || ct || tag = 12 + 32 + 16 = 60 bytes)
    key_version    INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
```

**Encryption at rest:**
- The channel PSK is encrypted using the personal channel PSK (the PSK of `__personal`).
- Format: `iv (12 bytes) || ciphertext (32 bytes) || auth_tag (16 bytes)` = 60 bytes.
- AAD: UTF-8 bytes of `channel_id` (same AAD pattern as item encryption, ecies-envelope-encryption.md §5.5).
- The personal channel PSK is stored in `~/.cordelia/channel-keys/__personal.key` as raw 32 bytes (not in the database).

**Why encrypted:** If the database file is compromised (stolen, leaked backup), the attacker cannot read channel PSKs without also possessing the personal channel PSK (which is in a separate file with 0600 permissions).

**Relationship to filesystem PSK files:**
- `~/.cordelia/channel-keys/<channel_id>.key` files (ecies-envelope-encryption.md §6.3) are the primary PSK store, used at runtime for fast access.
- The `channel_keys` table is the durable store, used for recovery if key files are deleted but the database and personal PSK survive.
- On startup, the node reconciles: if a `.key` file is missing but a `channel_keys` row exists, decrypt and restore the file. If a `.key` file exists but no row, encrypt and insert.

### 3.4 items

All channel items (messages, PSK envelopes, attestations, descriptors, tombstones).

```sql
CREATE TABLE items (
    item_id         TEXT PRIMARY KEY,     -- "ci_" + ULID (26 chars Crockford Base32)
    channel_id      TEXT NOT NULL REFERENCES channels(channel_id),
    author_id       BLOB NOT NULL,        -- Ed25519 public key (32 bytes)
    item_type       TEXT NOT NULL,         -- "message", "event", "state", "psk_envelope", "kv", "attestation", "descriptor", "probe", "memory:entity", etc.
    published_at    TEXT NOT NULL,         -- ISO 8601
    is_tombstone    INTEGER NOT NULL DEFAULT 0,  -- 1 = soft-deleted
    parent_id       TEXT,                  -- item_id of parent (threading). NULL if top-level.
    key_version     INTEGER NOT NULL DEFAULT 1,  -- PSK version used for encryption. 0 = not PSK-encrypted (see §4).
    content_hash    BLOB NOT NULL,         -- SHA-256 of encrypted_blob (32 bytes)
    signature       BLOB NOT NULL,         -- Ed25519 signature over CBOR metadata envelope (64 bytes)
    encrypted_blob  BLOB NOT NULL,         -- iv || ciphertext || auth_tag (normal items) OR raw ECIES envelope (PSK envelopes, §4)
    content_length  INTEGER NOT NULL,      -- byte length of encrypted_blob. Node-internal, not exposed via REST API.
    received_at     TEXT NOT NULL DEFAULT (datetime('now'))  -- local receipt timestamp (not replicated)
);

CREATE INDEX idx_items_channel_published ON items(channel_id, published_at);
CREATE INDEX idx_items_channel_type      ON items(channel_id, item_type);
CREATE INDEX idx_items_content_hash      ON items(content_hash);
```

**Notes:**
- `item_id` uses ULID (Crockford Base32, 26 chars) prefixed with `ci_`. ULIDs are monotonic within the same millisecond on the same node.
- `content_hash` is SHA-256 of the `encrypted_blob` column value (computed over ciphertext, not plaintext). Used for deduplication: `INSERT OR IGNORE` with content_hash check.
- `received_at` is local-only. Not signed. Not replicated. Used for local diagnostics and GC.
- `key_version = 0` is reserved for items not encrypted with the channel PSK. See §4.

**Deduplication:** On insert, check for existing item with same `channel_id + content_hash`. If found, skip (first-observed wins). This handles replication convergence where the same item arrives from multiple peers.

### 3.5 dm_peers

Maps DM channel IDs to the peer's public key for efficient lookup.

```sql
CREATE TABLE dm_peers (
    channel_id   TEXT PRIMARY KEY REFERENCES channels(channel_id),
    peer_key     BLOB NOT NULL         -- the other party's Ed25519 public key (32 bytes)
);
```

**Notes:**
- Populated when a DM is created or when a `psk_envelope` item is received for a `dm_` channel.
- Used by `POST /api/v1/channels/list-dms` to return the `peer` field without scanning items.

---

## 4. PSK Envelope Items

PSK envelopes are channel items with `item_type = "psk_envelope"` that carry an ECIES-wrapped PSK for a specific recipient. They require special handling because the recipient does not yet hold the channel PSK, so the item content cannot be encrypted with it.

### 4.1 Storage Convention

PSK envelope items use `key_version = 0` to signal that `encrypted_blob` is **not** encrypted with the channel PSK. Instead, the blob contains a self-authenticated ECIES envelope plus recipient metadata.

```
key_version = 0  →  encrypted_blob is NOT AES-encrypted with channel PSK.
                     Content is a CBOR structure defined in §4.2.
key_version >= 1 →  encrypted_blob is AES-256-GCM encrypted with the PSK
                     at that version (normal items, ecies-envelope-encryption.md §5).
```

### 4.2 PSK Envelope Blob Format

The `encrypted_blob` for `item_type = "psk_envelope"` is CBOR-encoded (deterministic, RFC 8949 §4.2.1):

```cbor
{
  "envelope":       h'<92 bytes>',     -- ECIES envelope (ecies-envelope-encryption.md §4.4)
  "key_version":    <integer>,         -- PSK version being distributed (>= 1)
  "recipient_xpk":  h'<32 bytes>'     -- recipient's X25519 public key
}
```

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `envelope` | CBOR byte string | 92 bytes | ECIES binary envelope: `eph_pk (32) \|\| iv (12) \|\| ct (32) \|\| tag (16)` |
| `key_version` | CBOR unsigned integer | 1-3 bytes | The PSK version this envelope distributes. Matches the `key_version` the recipient should use to decrypt subsequent items. |
| `recipient_xpk` | CBOR byte string | 32 bytes | X25519 public key of the intended recipient. Allows nodes to quickly check if an envelope is addressed to them without attempting ECIES decryption. |

**Total blob size:** CBOR overhead (~15 bytes) + 92 + 4 + 32 = ~143 bytes.

### 4.3 Processing Flow

**On item arrival** (publish or replication):

```
1. Read item_type from plaintext metadata
2. If item_type != "psk_envelope": normal flow (decrypt with channel PSK at key_version)
3. If item_type == "psk_envelope":
   a. Decode encrypted_blob as CBOR (§4.2)
   b. Compare recipient_xpk with local X25519 public key
   c. If no match: store item as-is (may be for another subscriber on this node, or relay)
   d. If match:
      i.   Decrypt ECIES envelope with local X25519 private key (ecies-envelope-encryption.md §4.3)
      ii.  Extract 32-byte PSK
      iii. Store PSK at ~/.cordelia/channel-keys/<channel_id>.key
      iv.  Insert/update channel_keys table row (encrypted with personal PSK)
      v.   If key_version > local channel key_version: update channels.key_version
      vi.  Log info: "Received PSK for channel {channel_name} (key_version {v})"
```

**On publish** (creating a PSK envelope):

```
1. Look up recipient's X25519 public key
2. Encrypt channel PSK using ECIES envelope (ecies-envelope-encryption.md §4.2)
3. Encode CBOR blob per §4.2 (envelope, key_version, recipient_xpk)
4. Set item fields:
   - item_type = "psk_envelope"
   - key_version = 0                     (signals: not PSK-encrypted)
   - author_id = local Ed25519 public key
   - content_hash = SHA-256(cbor_blob)
5. Sign metadata envelope (ecies-envelope-encryption.md §11.7)
6. Store and replicate as normal item
```

### 4.4 Signature Verification

PSK envelope items are signed by the author like all other items. The CBOR metadata envelope (§11.7 of ecies-envelope-encryption.md) includes `key_version = 0`. Peers verify the signature over this metadata envelope. The `encrypted_blob` (CBOR PSK envelope) is bound via `content_hash`.

### 4.5 Security Properties

| Property | Status |
|----------|--------|
| Confidentiality | ECIES envelope: only the recipient's X25519 private key can decrypt |
| Recipient privacy | `recipient_xpk` is visible in plaintext CBOR. Accepted: relays can see who receives PSK envelopes. The X25519 key is pseudonymous (derived from Ed25519 identity). |
| Authenticity | Author signs the item metadata. ECIES GCM tag authenticates the envelope. |
| Replay | Deduplication by content_hash prevents duplicate processing. Replayed envelopes produce the same PSK — no harm. |

### 4.6 Visibility Rules

PSK envelope items are **not returned by the listen endpoint** (channels-api.md §3.3). They are internal to the node. The node processes them silently on arrival.

Specifically, the listen query filters: `WHERE item_type NOT IN ('psk_envelope', 'kv', 'attestation', 'descriptor', 'probe') AND is_tombstone = 0`.

---

## 5. Schema Migration Framework

### 5.1 Version Tracking

```sql
PRAGMA user_version;     -- returns current schema version (integer)
```

### 5.2 Migration Procedure

On startup:

```
1. current = PRAGMA user_version
2. For each migration M where M.version > current, in order:
   a. BEGIN TRANSACTION
   b. Execute M.sql
   c. PRAGMA user_version = M.version
   d. COMMIT
3. If any migration fails: ROLLBACK, log CRITICAL, refuse to start
```

### 5.3 Migration v1 (Initial Schema)

The complete Phase 1 schema. Comprises all DDL from §3 and §4, plus the search tables from search-indexing.md §2.

```sql
-- Migration v1: Phase 1 initial schema

-- Core tables (this spec, §3)
-- channels, channel_members, channel_keys, items, dm_peers
-- [DDL as defined in §3.1-§3.5 above]

-- Search tables (search-indexing.md §2)
-- search_content, search_fts, search_vec_map, search_vec, search_embedding_meta, search_index_state
-- [DDL as defined in search-indexing.md §2.2-§2.6]

PRAGMA user_version = 1;
```

The full DDL is the concatenation of §3.1-§3.5 above and search-indexing.md §2.2-§2.6. Both are authoritative for their respective tables.

### 5.4 Additive Migrations Only

Phase 1 migrations are additive (new tables, new columns with defaults, new indexes). No column drops, no type changes, no destructive ALTER TABLE. This ensures forward-compatibility for rollback (operations.md §10.4).

If a future migration requires destructive changes, the release notes MUST state this and the rollback section MUST document the procedure.

---

## 6. Column-to-API Field Mapping

How SQLite columns map to REST API response fields (channels-api.md) and SDK types (sdk-api-reference.md).

### 6.1 Items

| SQLite Column | REST API Field | SDK Field | Notes |
|---------------|---------------|-----------|-------|
| `item_id` | `item_id` | `itemId` | |
| `channel_id` | (resolved to `channel` name) | `channel` | API returns channel name, not ID |
| `author_id` | `author` | `author` | BLOB → Bech32 (`cordelia_pk1...`) |
| `item_type` | `item_type` | `itemType` | |
| `published_at` | `published_at` | `publishedAt` | |
| `is_tombstone` | (filtered out) | (filtered out) | Tombstones excluded from listen/search |
| `parent_id` | `parent_id` | `parentId` | NULL → `null` in JSON |
| `key_version` | (not exposed) | (not exposed) | Internal encryption metadata |
| `content_hash` | (not exposed) | (not exposed) | Internal deduplication |
| `signature` | (not exposed) | (not exposed) | Verified server-side, result in `signature_valid` |
| `encrypted_blob` | (decrypted → `content` + `metadata`) | `content` + `metadata` | Decrypt, parse JSON, split |
| `content_length` | (not exposed) | (not exposed) | Internal only |

### 6.2 Channels

| SQLite Column | REST API Field | SDK Field | Notes |
|---------------|---------------|-----------|-------|
| `channel_id` | `channel_id` | `channelId` | |
| `channel_name` | `channel` | `channel` | |
| `mode` | `mode` | `mode` | |
| `access` | `access` | `access` | |
| `creator_id` | `owner` (in info endpoint) | `owner` | BLOB → Bech32 |
| `key_version` | (not exposed) | (not exposed) | |
| `created_at` | `created_at` | `createdAt` | |

### 6.3 Signature Verification

The `signature_valid` field in listen/search responses is computed at query time:

```
1. Load item row
2. Reconstruct CBOR metadata envelope from stored fields
3. Verify Ed25519 signature (item.signature) against author_id public key
4. Return boolean result as signature_valid
```

If verification fails (corrupted item, key mismatch), the item is still returned with `signature_valid: false`. The SDK/application decides how to handle unverified items.

---

## 7. Item Content Serialisation

### 7.1 Normal Items (key_version >= 1)

The `encrypted_blob` column stores: `iv (12) || ciphertext (variable) || auth_tag (16)`.

The plaintext (before encryption) is a JSON object:

```json
{
  "content": <any>,
  "metadata": <object | null>
}
```

The `content` and `metadata` fields from the API request (channels-api.md §3.2) are wrapped into this JSON envelope, serialised to UTF-8 bytes, then encrypted with the channel PSK.

On decryption, the node parses this JSON and splits `content` and `metadata` into separate response fields.

### 7.2 PSK Envelope Items (key_version = 0)

See §4. The `encrypted_blob` column stores a CBOR structure containing the ECIES envelope, key_version, and recipient X25519 public key.

### 7.3 System Items

Items with node-internal `item_type` values (`kv`, `attestation`, `descriptor`, `probe`) follow the normal encryption path (key_version >= 1). Their content is JSON, same as user items. The difference is:
- They are created by the node, not via the API.
- They are filtered from listen/search responses (§4.6).
- Their content schemas are type-specific (e.g., `kv` items have `{"key": "...", "value": ...}`).

---

## 8. References

| Document | What It Defines |
|----------|----------------|
| specs/ecies-envelope-encryption.md | ECIES envelope format (§4.4), item encryption (§5), key ring (§6.4), CBOR signing (§11) |
| specs/channels-api.md | REST API endpoints, item_type values (§3.2), error codes |
| specs/channel-naming.md | Channel ID derivation (§4), prefix disambiguation (§5) |
| specs/search-indexing.md | FTS5 + sqlite-vec DDL (§2), indexing pipeline |
| specs/identity.md | Key types, entity ID format |
| specs/network-protocol.md | ChannelDescriptor CBOR format (§4.4.6), PSK-Exchange (§4.7) |

---

*Draft: 2026-03-12. Closes buildability gaps for WP2/WP3/WP4 implementation.*
