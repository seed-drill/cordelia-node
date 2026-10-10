# Data Formats Specification

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-12
**Scope**: Phase 1 (Encrypted Pub/Sub MVP)
**Implements**: Storage layer for WP2, WP3, WP4, WP8
**Depends on**: specs/ecies-envelope-encryption.md, specs/channels-api.md, specs/channel-naming.md, specs/search-indexing.md, specs/identity.md

> **v1 status.** The schema is at version 18. There are two kinds of channel
> in it, and each has tables of its own:
>
> - **The older kind** (a random ID, a ring of keys, a list of members): §3
>   and §4 below, with steps 4 to 10. **These are a relay's tables.** A relay
>   carries the older kind for one version more. A personal node empties them
>   at its first start on this version, after a copy (§12), and writes none of
>   them again.
> - **A channel from its secret** (the
>   [decision record of 2026-10-04](../decisions/2026-10-04-a-persons-devices.md)):
>   §9 to §11 below, with steps 11 to 18. A device's own channels are all of
>   this kind.
>
> Steps 4 to 10, per the
> [decision record of 2026-09-30](../decisions/2026-09-30-agent-memory-sync.md):
>
> - **v4:** `channels` admits type `inbox` and gains `epoch` and
>   `epoch_author`; new tables `trusted_keys`, `invites` and `node_meta`.
> - **v5:** `items` gains `seq` (arrival order), `slot`, `rev` and
>   `relayed_at` (the outbox), with a `counters` table.
> - **v6:** `sync_files`, the adapter's record of each file it has synced.
> - **v7:** `peer_sightings`, a relay's keyed-hash record for usage counts.
> - **v8:** `state_offers`, the newest channel state sent to each member of
>   each channel, kept until the member is seen to hold it (decision §4.1).
> - **v9:** `sync_files` gains `author`: the key that signed the entry a
>   folder agreed (32 bytes), or `NULL` in a row that does not say (decision
>   §4.5; decision 2026-10-04 §16).
> - **v10:** `index_lines`, the adapter's record of each memory that this
>   device deleted with its line in the index (decision §4.5): for a memory
>   folder, a channel and a file, the line that was taken out and when, when
>   the file's delete was published, whether both were within an hour (the
>   record is then whole), and how many times the line has been put back.
>   Times are seconds, in UTC. It holds index lines as text, where the rest
>   of the database holds names and hashes of memory.
>
> Steps 11 to 18, per the decision record of 2026-10-04 (each is set out in
> §10):
>
> - **v11:** `entries`, the entries of channels from their secrets, and the
>   counter `entry_seq`.
> - **v12:** what a device holds of its person: `person`, `person_secrets`,
>   `person_change_entries`, `person_additions`, `person_names`.
> - **v13:** `relay_channels`, the channels a relay holds; `entries` gains
>   `channel_place`; `person_hand_overs`; and the counters `item_count` and
>   `item_bytes`, kept by three triggers on `items`.
> - **v14:** `at_relays` and `person_carried`: where a device stands at each
>   relay in each channel of its own.
> - **v15:** `person_typed_keys`, `person_left_out`, `person_cleared`: what a
>   person did at a terminal, and what the device has still to tell them.
> - **v16:** `at_relays_refused`: what a relay refused for room, kept to be
>   sent again.
> - **v17:** `sync_files` gains `chain`; `person_names_before`.
> - **v18:** `person_typed_keys` gains `stood`; `person_left_out` gains
>   `cleared_at`; `person_left`.
>
> Step 19, per the decision record of 2026-10-09 (set out in §10.7):
>
> - **v19:** the tables of messages between the person's own agents:
>   `message_generations` (a generation is the messages channel, not its
>   statement's number), `message_index`, `message_numbers`,
>   `message_first_held`, `message_signers`, `message_places`,
>   `message_lists`, `message_read_here`, `message_announced`,
>   `message_read_by_a_person`, `message_sends`, `message_kept`,
>   `message_kept_numbers` and `message_kept_taken`. It changes no older
>   row.
>
> No step from 11 on changes a row of the older kind. A database at a later
> version than the program's own is refused, and nothing in it is changed
> (§5.2).
>
> PSK envelope items (§4) are replaced by sealed channel states, items of type
> `invite` in inbox channels (decision 2026-09-30 §4.1). The search index
> (`search-indexing.md`, now in [`docs/archive/`](../archive/README.md)) is built
> from what is published through the Channels API of the older kind, and v1
> does not use it. A personal node serves none of that API, and the step of
> §12 empties the index.

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

> **v1 status.** §3.1 to §3.5 are the tables of the older kind of channel.
> A relay and a bootnode hold them. On a personal node they are empty from its
> first start on this version (§12), and a trigger refuses a new row in
> `channels` (§11.3). The tables of a channel from its secret are in §10.

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
- `content_hash` is SHA-256 of the `encrypted_blob` column value (computed over ciphertext, not plaintext). Used for deduplication (below).
- `received_at` is local-only. Not signed. Not replicated. Used for local diagnostics and GC.
- `key_version = 0` is reserved for items not encrypted with the channel PSK. See §4.

**Deduplication:** On insert, check for an existing item with the same `channel_id`, `content_hash` and `author_id`. If found, skip. This handles replication convergence where the same item arrives from multiple peers. The author is part of the check so that a copy of an item under another key cannot keep the item itself out (decision 2026-09-30 §4.3).

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

> **v1 status.** Of the older kind of channel, as §3 is. Nothing here is the
> form of an entry in a channel from its secret: that is §9.

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

> **v1 status.** The version is read before anything else is done. **A
> database at a later version than the program's own is refused:** no pragma
> is set and no step is run, and whoever opened it is told both versions. A
> relay or a bootnode then does not start. A personal node stays up over an
> empty database in memory, writes nothing to the one on disk, and says so in
> its status (decision 2026-10-04 §10.1). Each step from 9 on is run in one
> transaction with its change of version, and reads the version again inside
> it: the node and a command each open the database, and two that open it at
> one moment run a step once.

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

> **v1 status.** Steps 11 to 18 are additive. What a personal node does at its
> first start on this version is not a step of the schema: it empties rows,
> after a copy, and §12 and operations.md §10.5 say how to go back.

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

## 8. Local History Files

Local history (decision 2026-09-30 §4.5b) is not in the database. It is a
directory, `history/`, in the node's data directory, mode `0700`, with one
file for each record, mode `0600`.

**A record's name is its id:** 14 lower-case hex digits. The first eight are
the second it was written, by this device's clock; the next three are the
millisecond within it; the last three are random. So names sort by age, two
records made in different milliseconds are in the order they were made, and a
record that cannot be read still has an age. A record whose change has not been
made yet has `.pending` after its id. One that was pending and belonged to
no change in hand (found when the node started, at a sweep, or before a drop)
has `.interrupted`: its change may or may not have been made. Nothing else in
the directory is a record.

**A record's content** is one line of JSON, a line break, and then the text
as it was, byte for byte (nothing, where the record keeps no text). The JSON:

| Field | Type | Meaning |
|---|---|---|
| `at` | string | When it was written (RFC 3339, UTC, to the second) |
| `agent` | string | The name the folder syncs under |
| `folder` | string | The memory folder the file is in |
| `file` | string | The file's name |
| `change` | string | `pulled`, `removed`, `merged`, `edited_here`, `deleted_here`, `restored` or `arrived` |
| `kept` | object or null | `whose`: `{"here": {"agreed": <revision or null>}}` for this device's file (null: it had agreed none, or the record is of what a restore replaced, which does not look), or `{"channel": {"device": <key>, "rev": <revision>}}` for the channel's version; and `sha256`, the hash of the text in hex. Null where no text is kept |
| `replaced_by` | object or string | `{"entry": {"device": <key>, "rev": <revision>}}`, `{"record": <id>}` for a restore, or `"nothing"` |
| `behind` | boolean | This device's file was the version it had agreed, and a later one replaced it |

The text is flushed to the disk before the change it was kept for is made.
It is read back only while its hash is the one the record carries: a record
that was cut short, or changed on the disk, is refused.

> **v1 status.** A version that a device carried into a channel when it
> applied a statement is named, in `kept` and in `replaced_by`, by the key
> that signed the entry it was carried from, and not by the device that
> carried it (decision 2026-10-04 §16). A chain names a key by its first 16
> bytes: where the device knows of no key, or of two, with those bytes, the
> record says `a key that begins` and the bytes in hex. A record names the
> revision that an entry had when the text was kept: local history is not
> renumbered when a statement is applied.

A name or a path is never taken from a record's content to make a path in
the history directory, and an id from the command line is checked for its
shape before any path is made from it. A restore does write to the `folder`
and `file` its record names: it refuses a `file` that is not a plain file
name, and a `folder` that is not there.

## 9. A Channel From Its Secret

The forms of the [decision record of 2026-10-04](../decisions/2026-10-04-a-persons-devices.md),
as `crates/cordelia-crypto/src` has them. The record says what each is for;
this section says what the bytes are. In every form below a number is eight
bytes and a count or a length is two, the higher byte first, unless the form
says otherwise. Reading is strict throughout: bytes that end early, bytes
after the end, and a list over its bound are refused, so each thing has one
form. The derivations have published vectors in
[`docs/reference/step4-test-vectors.json`](../reference/step4-test-vectors.json),
and a test checks the code against that file.

### 9.1 What Is Derived (decision §2.1, §2.2, §5)

A channel is a secret of 32 bytes. Each thing is derived from it with
HKDF-SHA256, with an empty salt, under a label of its own. The labels are in
`protocol.rs`, and no label begins another.

| What | From | Label (`info`) |
|---|---|---|
| A channel's entry key (AES-256-GCM) | the channel's secret | `cordelia v2 entry` |
| A channel's slot key (HMAC-SHA256) | the channel's secret | `cordelia v2 slot` |
| The seed of a channel's signing key (Ed25519) | the channel's secret | `cordelia v2 sign` |
| The personal channel's secret | the person secret | `cordelia v2 personal` |
| The secret of a channel of the person's own, by name | the person secret | `cordelia v2 own`, the name's length, the name |
| A pair channel's secret | X25519 of the two devices' keys | `cordelia v2 pair`, the two public keys, the lower first |
| A locked channel's secret (its derivation only, decision §11) | the person secret and the lock's key, 64 bytes | `cordelia v2 locked`, the name's length, the name |
| The secret of the phrase's channel | the phrase's 16 bytes | `cordelia v2 recovery` |
| The seed of the phrase's signing key | the phrase's 16 bytes | `cordelia v2 phrase sign` |
| The statement key | the phrase's 16 bytes | `cordelia v2 phrase statement` |
| The key that seals the part of a change entry for the phrase | the phrase's 16 bytes | `cordelia v2 phrase seal` |

- **A channel's ID** is the public half of its signing key: 32 bytes. As text
  it is `cordelia_ch1...` (Bech32, 70 characters), beside a device's key,
  which is `cordelia_pk1...`. Neither is read as the other.
- **A name** is in its one spelling (decision 2026-09-30 §4.5), at least one
  byte, and another spelling is refused and not tidied.
- **A pair channel** refuses a key that is not a usable public key, the
  device's own key, and a shared secret that is all zeros.
- **A slot** is `HMAC-SHA256(slot key, "cordelia:slot:v1:" || name)`, as for
  the older kind. The slot key is derived, so it changes with the channel's
  secret. One slot is not under a slot key: the change entry's (§9.6).
- **The person secret** is 32 random bytes. It is never derived from the
  phrase.
- **The recovery phrase** is twelve words of the BIP39 English list: 128
  bits and a checksum. Everything that comes from it is derived from the 16
  bytes that the words encode.
- **A key's fingerprint** is SHA-256 of `cordelia v2 fingerprint` and the
  key. It is shown as words of the same list, eleven bits to a word from the
  hash's first bit, and the first four are shown beside a label. They are no
  recovery phrase: they have no checksum.

### 9.2 An Entry (decision §2.3)

**On the wire, and as a relay stores it** (`wire.rs`):

```text
channel's ID   32
slot           32
author         32   the key that signed it
revision       8    from 1 to 2^53 - 1
delete         1    1 where the entry is a delete, and otherwise 0
length         4    the content's length
content        that many bytes: a power of two from 256 to 65536
author's       64   the author's signature
channel's      64   the signature of the channel's signing key
```

That is 237 bytes and the content (`ENTRY_WIRE_OVERHEAD_BYTES`). Refused as
no entry: a length that is not the length of the content that is there, a
content of a size that no entry's is, a delete that is neither 0 nor 1, and a
revision that no entry has.

**What is signed** is 137 bytes:

```text
channel's ID   32
slot           32
author         32
revision       8
delete         1
content        32   SHA-256 of the content
```

The author signs `cordelia v2 author` and those bytes. The channel's signing
key signs `cordelia v2 channel` and the same bytes. Each signature has its
label, so that neither is taken for the other.

**An entry's ID** is SHA-256 of what is signed. There is no random ID. An
author can sign two entries at one revision, and they have two IDs.

**The check that needs no key** (`Entry::check`), which a relay makes before
it stores an entry and a device makes on what it is sent: the revision is
within its bound; the content is of an allowed size; the author's key and the
channel's ID are usable public keys (under a point of small order anyone can
make a signature that is accepted); and both signatures hold.

**The content** is a nonce (12), a ciphertext and a tag (16), AES-256-GCM
under the channel's entry key. Its associated data is `cordelia v2 content`,
the channel's ID, the slot and the revision: content that is moved to another
channel, slot or revision does not open. What it says is filled up with zeros,
inside the encryption, to the smallest of the nine sizes that holds it: a
relay sees a size class and no length.

**Inside the ciphertext:**

```text
name     its length, then the name: UTF-8, at least one byte
value    1 byte: 0 nothing (a delete), 1 a text, 2 other bytes;
         and for a text and for other bytes its length, then the bytes
chain    a count, from 0 to 100, then for each link 32 bytes:
           16   the first 16 bytes of SHA-256 of a version's value
                (zeros for a delete)
           16   the first 16 bytes of the key that signed the entry
                that version was taken from
         then zeros, to the content's size
```

- **The chain** is what the entry was written after: the versions it descends
  from, the newest first (decision §7.3). A new name's chain is empty. A link
  may stand twice, and the newest link with a hash decides.
- **A name and a value may together be 61,440 bytes** (60 KB,
  `MAX_ENTRY_NAME_AND_VALUE_BYTES`). At that bound, with 100 links, the
  content is 64,675 bytes of the 65,536 it may be: the chain always fits, and
  no link is left out for room.
- **The chain is read strictly.** A count over 100, a link that is not whole,
  or anything after the last link but the zeros that fill the smallest size
  which holds what is said: the entry then lacks what it should say. It is a
  version all the same, and is known to follow nothing.
- **An entry that is no version:** one whose content does not open; one that
  opens to something that is not this form (a name of no bytes, a name or a
  text that is not UTF-8, a kind of value that there is not); one whose name
  and value are over their bound; one whose slot is not the slot of its name;
  one that is a delete in clear and not inside, or the other way round; and
  one whose revision is in no band it may be in (§9.3).
- **Other bytes** (kind 2) are what the local API writes that is not a text.
  They are tagged so, and a text is never read from them.

**Which entry of a slot is current** (`version.rs`). A store keeps one entry
for each author in each slot. A device looks only at entries whose signer
counts (decision §4.4). The current version is the one at the highest
revision among versions. At one revision a text beats a delete, and of two
texts the one with the higher SHA-256 of the text wins. Two entries with one
value at one revision are one version, whoever signed them.

### 9.3 A Revision (decision §2.3)

A revision is one number below 2^53, compared as one. Its top nine bits are
its **band** and the 44 below them its **count** (`revision.rs`).

- Band 0 is ordinary editing: a name's first revision is 1. A statement's
  band is its number, 1 to 256. Revision 0 is no entry's.
- **Under statement n an entry's revision is in band n, or in the bottom half
  of a lower band** (a count below 2^43). Any other is no version.
- **The next revision** is one above the highest that counts. Where that is
  in the top half of a band below n, it is moved as a move would move it.
  Where it would be in a band above n, there is none until the next
  statement.
- **At a move** (a device applies a statement) a revision in the top half of
  a band goes to the same place in the bottom half of the next band: 2^43 is
  added. Any other is unchanged, and so is one in band 256, which has no
  next. It is a function of the number alone, the same on every device, and
  applying it twice is applying it once.

Outside a generation's channels a revision is a plain number: a change
entry's is its statement's number.

### 9.4 The Statement (decision §4.1)

Canonical form (`statement.rs`):

```text
number        8                   from 1 to 256
maker         32                  the key of the device it was made on
chain         count, then for each: number 8, hash 16
commitment    32                  to the new secret
devices       count, then for each: key 32, label's length, label
removed       count, then for each: key 32
phrase's key  32                  the public half of the phrase's signing key
reserved      length, which is 0
```

A signed statement is this form and then 64 bytes: the phrase's key signs
`cordelia v2 statement` and the form.

- **The commitment** is SHA-256 of `cordelia v2 commitment` and the secret.
- **A statement's hash**, as a chain names it, is the first 16 bytes of
  SHA-256 of its canonical form, without the signature.
- **The chain** is in order of number and then hash, with none named twice.
  Its numbers start at 1 and leave none out up to the one before this
  statement's. Two statements that were made apart and then settled have one
  number.
- **The devices** keep the order their maker gave them, which is the order
  of the secrets sealed to them in the change entry. None is listed twice,
  each key is a usable public key, and the maker is among them.
- **The removed keys** are in order, with none listed twice, and none of
  them is among the devices.
- **A label** is 1 to 64 bytes of printable ASCII (0x20 to 0x7E), with no
  space at either end.
- **The reserved field** is empty, and a statement in which it is not is
  refused.
- **Bounds:** 64 devices, 256 removed keys, 256 statements on a chain. At
  every bound together a signed statement is 20,784 bytes
  (`MAX_STATEMENT_BYTES`).

### 9.5 The Record of an Addition (decision §6)

Canonical form (`addition.rs`):

```text
key        32                  the new device's
label      its length, then the label, as a statement's
time       8                   when it was added, in seconds, in UTC,
                               by the clock of the device that adds
statement  number 8, hash 16   the statement it is made under
adder      32                  the device that adds, which signs
```

A signed record is this form and then 64 bytes: the adder signs
`cordelia v2 addition` and the form. At its longest it is 226 bytes
(`MAX_ADDITION_BYTES`). Refused: a label that a statement could not carry, a
key that is no usable public key, and a device that adds itself.

A record is the value of an entry in the personal channel, under the name
`added/` and the new device's key as a device's key is written (§9.7), and
it travels in a hand-over (§9.8).

### 9.6 The Change Entry (decision §4.6, §9)

One entry in the phrase's channel (`change_entry.rs`). Its author is the
phrase's key, its revision is the statement's number, and it is no delete.
**Its slot is `HMAC-SHA256(channel's ID, "cordelia:slot:v1:change")`:** under
the channel's ID and not under a slot key, since no device holds a key of the
phrase's channel and each has to know the change entry's slot from any other.
It is signed by the phrase's key and by the key of the phrase's channel, as
every entry is by its author and its channel.

**Its content is always 32,768 bytes,** in two parts. Each part is a nonce
(12), a ciphertext and a tag (16), and is one size whatever it says: what it
says is filled up with zeros inside the encryption.

```text
the part for the devices   28672 bytes, under the statement key
the part for the phrase     4096 bytes, under the phrase's sealing key
```

The associated data of the part for the devices is
`cordelia v2 change devices`, the statement's number and the phrase's public
key; of the part for the phrase, `cordelia v2 change phrase` and the same
two. So a part is no part of another entry.

```text
for the devices   the signed statement's length, the signed statement,
                  a count, and for each device of the statement, in the
                  statement's order, the secret sealed to its key (92)
for the phrase    the secret (32), a count from 0 to 8, and for each
                  earlier generation its number (8) and its secret (32),
                  the newest first
```

- **A secret sealed to a device** is 92 bytes: an ephemeral X25519 key (32),
  a nonce (12), the 32 bytes and a tag (16), as the node seals to a key
  (`ecies-envelope-encryption.md` §4). The wrapping key is derived under
  `cordelia v2 change secret`, the statement's number and the phrase's key:
  what was sealed to a device for any other use, or for another statement,
  does not open as this statement's secret.
- **The earlier secrets** are in order of number, and by the secret where
  two generations have one number, the newer first, none twice, each of a
  statement before this one.
- **Opening** takes an entry that passed the check, the phrase key that the
  reader follows and the ID of that phrase's channel. Refused: an entry of
  another channel, one that the phrase's key did not write, one in another
  slot, one that says it is a delete, a statement under another phrase, and a
  statement whose number is not the entry's revision.
- **A list of sealed secrets that is missing or short** (a count below the
  number of devices) is a change that was made with a fault. A device that
  the statement lists reads the statement, and that its secret did not open.
  A reader that the statement does not list is refused the entry.
- **A count above the number of devices, or anything after the sealed
  secrets but zeros,** is refused, whoever reads.

### 9.7 The Names of the Personal Channel, and of the Other Two

Each is the name of an entry, inside the ciphertext, in the channel named.

| Channel | Name | Value | Decision |
|---|---|---|---|
| Personal | `name/<the name>` | A device's word that it syncs the name: its own entry there that is no delete. A delete when it unmaps the name, or turns sync off | §2.2, §7.3 |
| Personal | `added/<the new device's key>` | A signed record of an addition (§9.5). Each device that adds the key has an entry of its own there | §6 |
| Personal | `applied/<the device's key>` | The number of the statement the device has applied, in digits; and ` sent` after it once the device has sent what it carried | §8 |
| Personal | `left/<the device's key>` | A device's word that it has left, written before it starts again under another phrase or with another key | §5.2 |
| The phrase's | `change` | The change entry (§9.6). The name gives the slot, and the content holds no name | §2.2, §4.6 |
| A pair channel | `hand-over` | The hand-over (§9.8). Nothing else in a pair channel is read | §2.2, §6 |

A key is written `cordelia_pk1...`. Only a device's own entry under
`applied/` and `left/` with its key, and under a `name/`, is its word,
whatever another key wrote there. A word under `name/` is read as a name only
where it is one that this version would itself map, in its one spelling:
anything else is counted and never shown (decision §16).

### 9.8 The Hand-over (decision §6)

The value of the entry `hand-over` in a pair channel (`hand_over.rs`):

```text
made           8      when it was made, in seconds, in UTC, by the clock
                      of the device that adds
statement      its length, then the signed statement the adder has applied
secret         32     the person secret of that statement
statement key  32
change entry   channel's ID 32, slot 32, author's signature 64,
               channel's signature 64, content 32768
records        1 byte: how many, from 0 to 2; then for each its length and
               the signed record
```

- The change entry is carried whole, so that the new device can keep it and
  show it to a relay. Its author and its revision are the statement's phrase
  key and number, and are not written a second time.
- The first record is the record of the addition. The second, where there
  is one, is the record of the adder's own addition. A key that the statement
  already lists is handed the change with no record.
- At every bound together it is 54,275 bytes (`MAX_HAND_OVER_BYTES`), which
  with its name is within what one entry may hold.
- **A hand-over that is read holds together,** and one that does not is
  refused, by whoever makes it and by whoever reads it: the phrase's key
  signed the statement; the statement commits to the secret; the change entry
  passes the check, is in the change entry's slot of its channel, and opens
  under the statement key to that very statement; each record was signed by
  its adder and is made under that statement; no record adds a key that the
  statement lists, as a device or as removed; and the adder is a device of
  the statement, or comes with the record of its own addition by one.
- The revision of the entry that carries it is the time it was made, or one
  above the adder's last (decision §2.2): it orders the hand-overs of one
  device to another, and can run ahead of any clock. The time that is judged
  is the one inside.

---

## 10. Tables of a Channel From Its Secret (Steps 11 to 19)

Times are in seconds, in UTC, by the clock of the node that writes them. A
key, a channel's ID and a slot are each 32 bytes, and a signature 64: in the
tables of §10.1 to §10.5 each such column is checked for its length.

### 10.1 entries (v11, v13; decision §2.3, §2.4)

One row for each author in each slot of each channel: the newest revision
that author signed there. A relay holds here what it carries, and a device
what it holds of its own channels.

```sql
CREATE TABLE entries (
    channel_id   BLOB NOT NULL CHECK(length(channel_id) = 32),
    slot         BLOB NOT NULL CHECK(length(slot) = 32),
    author       BLOB NOT NULL CHECK(length(author) = 32),
    rev          INTEGER NOT NULL CHECK(rev >= 1),
    is_delete    INTEGER NOT NULL CHECK(is_delete IN (0, 1)),
    content      BLOB NOT NULL,
    author_sig   BLOB NOT NULL CHECK(length(author_sig) = 64),
    channel_sig  BLOB NOT NULL CHECK(length(channel_sig) = 64),
    seq          INTEGER NOT NULL,
    stored_at    INTEGER NOT NULL,
    channel_place INTEGER NOT NULL DEFAULT 0,      -- v13
    PRIMARY KEY (channel_id, slot, author)
);

CREATE UNIQUE INDEX idx_entries_channel_seq   ON entries(channel_id, seq);
CREATE UNIQUE INDEX idx_entries_channel_place ON entries(channel_id, channel_place);
```

- The table refers to no other: an entry is stored with no list of members
  and no state of the channel.
- **A row is replaced only by a higher revision** from that author in that
  slot. An entry at the revision of the one held is not stored. Nothing
  compares one author's entries with another's.
- `seq` is the order in which this node stored all of its entries, from the
  counter `entry_seq`, which never goes backwards.
- `channel_place` is the entry's place in its channel alone: a count from 1.
  A channel is handed to a holder of its key in pages by that count, so the
  places say nothing of what the node stored for anyone else in between.
- Only an entry that passed the check (§9.2) is stored, and what is read
  from a slot is checked again as it is read.
- **Old deletes are swept by these two columns** (decision §2.3): `is_delete`
  says in clear that an entry is a delete, and `stored_at` is when this node
  stored it. Once an hour a node looks for each slot that holds a delete
  which it stored 90 days ago or longer (`KEYED_TOMBSTONE_RETENTION_DAYS`).
  A slot goes whole, or not at all.
  - **A relay** drops a slot where every row in it is such a delete. The
    channel's `bytes` in `relay_channels` (§10.2) follows, and a channel of
    which nothing is left loses its row.
  - **A device** drops a slot of a name it holds where the slot's current
    version is a delete, and every row that is that delete is 90 days old.
    The slot stays while a row of `sync_files` (§10.6) names a text for that
    file. When it goes, the rows of `sync_files` that say the file is deleted
    go with it. In its personal channel and in a pair channel it drops a slot
    as a relay does.

### 10.2 relay_channels (v13; decision §2.4, §2.5): a relay's

One row for each channel from its secret that this node holds as a relay.

```sql
CREATE TABLE relay_channels (
    channel_id  BLOB PRIMARY KEY CHECK(length(channel_id) = 32),
    held_since  INTEGER NOT NULL,
    used_at     INTEGER NOT NULL,
    bytes       INTEGER NOT NULL CHECK(bytes >= 0),
    mark        BLOB NOT NULL CHECK(length(mark) = 8 AND mark != zeroblob(8))
);

CREATE INDEX idx_relay_channels_held ON relay_channels(held_since);
CREATE INDEX idx_relay_channels_used ON relay_channels(used_at);
```

- `held_since`: when the relay first took the channel, or an earlier time
  that a relay its operator lists says it has held it since. Over its cap a
  relay drops the channels it has held for the shortest time first.
- `used_at`: when the channel's key was last proved, or an entry of it last
  shown that the relay holds. It is written at most once an hour, and never
  an earlier time than the one kept. What nobody uses for 90 days is dropped.
- `bytes`: what the channel holds, as entries are counted (content and 1 KB
  each), and not as the database's pages count it.
- `mark`: 8 random bytes that are this holding's own. A channel that is
  dropped loses its row and its entries, and is taken again under another
  mark: a place in a channel means something only with its mark.

A device keeps nothing here. The functions that write or drop here refuse a
database in which a device follows a phrase.

### 10.3 What a Device Holds of Its Person (v12, v13, v17; decision §3 to §6)

They are in the node's database so that they change in one transaction with
a statement. A relay keeps nothing in any of them.

```sql
CREATE TABLE person (
    one             INTEGER PRIMARY KEY CHECK(one = 1),
    state           TEXT NOT NULL
                    CHECK(state IN ('applied', 'fork', 'removed', 'not_listed', 'not_opened')),
    phrase_key      BLOB NOT NULL CHECK(length(phrase_key) = 32),
    statement_key   BLOB NOT NULL CHECK(length(statement_key) = 32),
    phrase_channel  BLOB NOT NULL CHECK(length(phrase_channel) = 32),
    statement       BLOB NOT NULL
);

CREATE TABLE person_secrets (
    number   INTEGER NOT NULL CHECK(number BETWEEN 1 AND 256),
    secret   BLOB NOT NULL CHECK(length(secret) = 32),
    left_at  INTEGER,
    PRIMARY KEY (number, secret)
);
CREATE UNIQUE INDEX idx_person_secrets_applied ON person_secrets((left_at IS NULL))
    WHERE left_at IS NULL;

CREATE TABLE person_change_entries (
    kept            TEXT PRIMARY KEY CHECK(kept IN ('latest', 'apart')),
    channel         BLOB NOT NULL CHECK(length(channel) = 32),
    slot            BLOB NOT NULL CHECK(length(slot) = 32),
    author          BLOB NOT NULL CHECK(length(author) = 32),
    rev             INTEGER NOT NULL CHECK(rev BETWEEN 1 AND 256),
    content         BLOB NOT NULL,
    author_sig      BLOB NOT NULL CHECK(length(author_sig) = 64),
    channel_sig     BLOB NOT NULL CHECK(length(channel_sig) = 64)
);

CREATE TABLE person_additions (
    seen     INTEGER PRIMARY KEY,
    record   BLOB NOT NULL UNIQUE,
    key      BLOB NOT NULL CHECK(length(key) = 32),
    adder    BLOB NOT NULL CHECK(length(adder) = 32),
    counted  INTEGER NOT NULL CHECK(counted IN (0, 1)),
    seen_at  INTEGER NOT NULL
);

CREATE TABLE person_names (
    name     TEXT PRIMARY KEY CHECK(length(name) >= 1),
    channel  BLOB NOT NULL UNIQUE CHECK(length(channel) = 32),
    held_at  INTEGER NOT NULL
);

CREATE TABLE person_hand_overs (                    -- v13
    key      BLOB PRIMARY KEY CHECK(length(key) = 32),
    channel  BLOB NOT NULL CHECK(length(channel) = 32),
    rev      INTEGER NOT NULL CHECK(rev >= 1),
    made_at  INTEGER NOT NULL,
    held     INTEGER NOT NULL CHECK(held IN (0, 1))
);

CREATE TABLE person_names_before (                  -- v17
    name     TEXT NOT NULL CHECK(length(name) >= 1),
    said_by  BLOB NOT NULL CHECK(length(said_by) = 32),
    left_at  INTEGER NOT NULL,
    PRIMARY KEY (name, said_by)
);
```

| Table | What it holds | Decision |
|---|---|---|
| `person` | One row, or none where the device follows no phrase. What it follows: the phrase's public key, the statement key and the ID of the phrase's channel, never the words. The statement it has applied, as its signed bytes. And its state: `applied`; `fork` (it has seen a statement made apart from the one applied); `removed`; `not_listed` (a later statement has its key in neither list); `not_opened` (a later statement lists it, and the secret that came with it did not open) | §4.2 to §4.5, §5 |
| `person_secrets` | The person secret it has applied (`left_at` is NULL: at most one such row), and each one it left, with when it left it. A secret that was left is kept 90 days by the device's own clock and then forgotten. Two generations can have one number, after a fork. A machine that recovers is handed the secret of the generation it recovered from, and of those before it that the change entry gave the phrase (nine in all at most), and keeps each as a secret it left then | §3, §9 |
| `person_change_entries` | The latest change entry it has seen (`latest`), whole, to show to a relay; and, in a fork, the one made apart (`apart`) | §4.5, §4.6 |
| `person_additions` | The records of additions it has seen under the applied statement, in the order it saw them, each counted or not. At most 64 devices count in all, and at most 256 records are kept as not counted | §6 |
| `person_names` | The names it holds in the generation it has applied, each with its channel's ID, so that either is found from the other: the names its folders are mapped to, and those that a carry by command or a recovery brought in (`person.names_carried`, §11.1) | §2.2, §7.3 |
| `person_hand_overs` | For each key it made a hand-over for, the last one: its pair channel, its revision there (the next is above it), when it says it was made, and whether the store still holds it. Never the hand-over, which holds the secret | §6 |
| `person_names_before` | Each name that a key had said it syncs, in the personal channel of a generation the device left, with when it left it. Written in the transaction that applies a statement. It is what a device shows of the names that no device lists yet in the new generation | §7.3, §8 |

**The person secret is in the database,** which its owner alone can read
(mode 0600), and not in a file beside it: it changes in one transaction with
the statement (decision §3). Whoever reads a device's database has the
person secret (decision §12).

### 10.4 Where a Device Stands at Each Relay (v14, v16; decision §4.6, §7.3, §16)

```sql
CREATE TABLE at_relays (
    relay       BLOB NOT NULL CHECK(length(relay) = 32),
    channel     BLOB NOT NULL CHECK(length(channel) = 32),
    mark        BLOB CHECK(mark IS NULL OR (length(mark) = 8 AND mark != zeroblob(8))),
    place       INTEGER NOT NULL DEFAULT 0 CHECK(place >= 0),
    sent_to     INTEGER NOT NULL DEFAULT 0 CHECK(sent_to >= 0),
    carried_to  INTEGER NOT NULL DEFAULT 0 CHECK(carried_to >= 0),
    PRIMARY KEY (relay, channel)
);
CREATE INDEX idx_at_relays_channel ON at_relays(channel);

CREATE TABLE person_carried (
    one    INTEGER PRIMARY KEY CHECK(one = 1),
    up_to  INTEGER NOT NULL CHECK(up_to >= 0)
);

CREATE TABLE at_relays_refused (                    -- v16
    relay BLOB NOT NULL CHECK(length(relay) = 32),
    channel BLOB NOT NULL CHECK(length(channel) = 32),
    seq INTEGER NOT NULL CHECK(seq > 0),
    PRIMARY KEY (relay, channel, seq)
);
CREATE INDEX idx_at_relays_refused_channel ON at_relays_refused(channel);
```

- `at_relays`: one row for each relay, by its node key, and channel of the
  device's own. `mark` and `place` are the device's place in the relay's
  holding of the channel, where its next pull goes on from: no mark is no
  place, and the channel is read from the start. `sent_to` is how far the
  device has sent the relay what its own store holds of the channel, in the
  store's order (`entries.seq`). `carried_to` is the same for what the device
  carried into the channel when it applied a statement, which is sent by a
  rule of its own (decision §7.3).
- `person_carried`: one row. The store's order as it stood when the device
  last applied a statement: an entry of the device's own, in the channel of
  a name, that the store took no later than that, is one it carried.
- `at_relays_refused`: an entry that a relay had no room for, by its place in
  the store's order. How far the relay was sent the channel goes on past it,
  so that what follows is still offered; the entry is sent again after a
  wait, and its row goes when the relay holds it or the store holds it no
  more.

A relay keeps nothing in any of them.

### 10.5 What a Person Did at a Terminal (v15, v18; decision §5.1, §6, §8)

```sql
CREATE TABLE person_typed_keys (
    key       BLOB PRIMARY KEY CHECK(length(key) = 32),
    typed_at  INTEGER NOT NULL,
    taken_at  INTEGER,
    said      TEXT,
    stood     TEXT NOT NULL DEFAULT ''               -- v18
);

CREATE TABLE person_left_out (
    key        BLOB PRIMARY KEY CHECK(length(key) = 32),
    label      TEXT NOT NULL,
    number     INTEGER NOT NULL CHECK(number >= 1),
    noted_at   INTEGER NOT NULL,
    cleared_at INTEGER                               -- v18
);

CREATE TABLE person_cleared (
    notice      BLOB PRIMARY KEY CHECK(length(notice) = 32),
    cleared_at  INTEGER NOT NULL
);

CREATE TABLE person_left (                           -- v18
    key       BLOB PRIMARY KEY CHECK(length(key) = 32),
    notice    BLOB NOT NULL CHECK(length(notice) = 32),
    number    INTEGER NOT NULL CHECK(number >= 1),
    noted_at  INTEGER NOT NULL
);
```

| Table | What it holds | Decision |
|---|---|---|
| `person_typed_keys` | A key that a person typed at `cordelia accept`, with when. A pair channel is read only with such a key, and only for an hour after it was typed. `stood` is the row of the record's 5.1 that the device stood in when its yes was said: `no_phrase`, `alone`, `several` or `not_listed`. A hand-over is taken with the key only while the device stands there. `taken_at` is when a hand-over was taken with it: the key is then spent. `said` is what became of the last hand-over read with it, in words for a person. At most 8 keys are within their hour at one time, and a ninth is refused. A row is kept for a day, to say what became of the key: one whose hour has gone holds no place | §2.2, §5.1, §16 |
| `person_left_out` | A key that this device counted as a device before a statement it applied, and that is in neither of that statement's lists, with the label it was known by and the statement's number. It is shown until a person clears it (`cleared_at`) or a later statement lists it. Cleared, the row stays, so that adding that key still says what it is | §8 |
| `person_cleared` | A notice that a person has cleared here, by the 32 bytes the notice is named by. It is shown no more on this device | §5.2, §6 |
| `person_left` | A device's word that it left, kept when a statement is applied that still lists its key, where nobody had cleared it: the word itself is in a personal channel that the device reads no more. Shown until a person clears it here, or a statement lists the key no more | §5.2, §7.1 |

A relay keeps nothing in any of them.

### 10.6 sync_files and index_lines (v6, v9, v10, v17)

The adapter's records are in the tables they were in. In this version a row
is of a channel from the person's secret: `channel_id` is the channel's ID as
it is written (`cordelia_ch1...`).

```sql
CREATE TABLE sync_files (
    folder      TEXT NOT NULL,
    channel_id  TEXT NOT NULL,
    key         TEXT NOT NULL,
    hash        BLOB,                -- SHA-256 of the agreed text; NULL: deleted
    rev         INTEGER NOT NULL,
    author      BLOB,                -- v9: the key that signed the entry agreed
    chain       BLOB,                -- v17: that entry's chain
    PRIMARY KEY (folder, channel_id, key)
);
```

- A folder's record of a file is of one entry: the hash of its text, its
  revision, the key that signed it and its chain (decision §2.3, §16). Where
  a version is held in several entries, it is the one that a device writes
  over: its own where it holds one, and otherwise the one whose signer has
  the lowest key.
- `chain` is the links one after another, 32 bytes each (§9.2), with no
  count. NULL where that entry lacked what it should say.
- **When a device applies a statement** the rows of each folder go with the
  name to the name's new channel, with its rows of `index_lines`, and each
  revision in them is renumbered as §9.3 says. Local history is left as it
  is.
- At a personal node's first start on this version both tables are emptied:
  every folder forgets what it had agreed (§12).

### 10.7 Messages Between the Person's Own Agents (v19; decision 2026-10-09 §2.3, §2.5, §6, §7, §9.2)

What a device keeps of the messages channel beside its entries, which are in
`entries` as every channel's are. A signer is the key that signed a
message's entry, a generation is the messages channel an entry is in, kept
as the ID of its row in `message_generations`, a message's ID is 16 bytes, a
mark 16, and a time is by the device's own clock. A number, and the highest
number held, is at most 2^42 - 1 (§2.3), and a statement's number at most
256. Each column takes only its type and its bound: a blob of its length,
or an integer, and a flag 0 or 1. A flag, and a kind of `to`, need no
check of their type besides their `IN (...)`: a column of integer affinity
that holds 0 or 1 holds an integer. Nor does a generation, whose foreign
key to the integer key of `message_generations` refuses what is not one.
The fields that a row is overwritten in
before it goes take any type, since they are written over with a blob of
zeros. A test ties each bound written in the SQL to `protocol.rs`.

```sql
CREATE TABLE message_generations (
    id          INTEGER PRIMARY KEY,
    channel     BLOB NOT NULL UNIQUE CHECK(typeof(channel) = 'blob' AND length(channel) = 32),
    statement   INTEGER NOT NULL CHECK(typeof(statement) = 'integer'
                                       AND statement >= 1 AND statement <= 256),
    first_held  INTEGER NOT NULL CHECK(typeof(first_held) = 'integer')
);

CREATE TABLE message_index (
    id               BLOB PRIMARY KEY CHECK(typeof(id) = 'blob' AND length(id) = 16),
    signer           BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),
    label            TEXT NOT NULL,
    generation       INTEGER NOT NULL REFERENCES message_generations(id),
    to_kind          INTEGER NOT NULL CHECK(to_kind IN (1, 2)),
    to_name          TEXT CHECK((to_kind = 1) = (to_name IS NOT NULL)),
    from_name        TEXT NOT NULL,
    sent             INTEGER NOT NULL CHECK(typeof(sent) = 'integer'),
    subject          TEXT NOT NULL,
    thread           BLOB NOT NULL CHECK(typeof(thread) = 'blob' AND length(thread) = 16),
    answers          BLOB NOT NULL CHECK(typeof(answers) = 'blob' AND length(answers) = 16),
    asks             INTEGER NOT NULL CHECK(asks IN (0, 1)),
    link             TEXT,
    body             TEXT NOT NULL,
    first_held       INTEGER NOT NULL CHECK(typeof(first_held) = 'integer'),
    placed_at        INTEGER CHECK(placed_at IS NULL OR typeof(placed_at) = 'integer'),
    not_every_relay  INTEGER NOT NULL DEFAULT 0
                         CHECK(not_every_relay IN (0, 1))
);

CREATE INDEX idx_message_index_signer ON message_index(signer, generation);

CREATE TABLE message_numbers (
    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),
    generation  INTEGER NOT NULL REFERENCES message_generations(id),
    number      INTEGER NOT NULL CHECK(typeof(number) = 'integer'
                                       AND number >= 1 AND number <= 4398046511103),
    id          BLOB NOT NULL REFERENCES message_index(id) ON DELETE CASCADE,
    PRIMARY KEY (signer, generation, number)
);

CREATE INDEX idx_message_numbers_id ON message_numbers(id);

CREATE TABLE message_first_held (
    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),
    generation  INTEGER NOT NULL REFERENCES message_generations(id),
    number      INTEGER NOT NULL CHECK(typeof(number) = 'integer'
                                       AND number >= 1 AND number <= 4398046511103),
    id          BLOB CHECK(id IS NULL OR (typeof(id) = 'blob' AND length(id) = 16)),
    sent        INTEGER CHECK(sent IS NULL OR typeof(sent) = 'integer'),
    first_held  INTEGER NOT NULL CHECK(typeof(first_held) = 'integer'),
    CHECK((id IS NULL) = (sent IS NULL)),
    PRIMARY KEY (signer, generation, number)
);

CREATE TABLE message_signers (
    signer        BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),
    generation    INTEGER NOT NULL REFERENCES message_generations(id),
    highest       INTEGER NOT NULL CHECK(typeof(highest) = 'integer'
                                         AND highest >= 0 AND highest <= 4398046511103),
    overwritten   INTEGER NOT NULL DEFAULT 0
                      CHECK(typeof(overwritten) = 'integer' AND overwritten >= 0),
    not_messages  INTEGER NOT NULL DEFAULT 0
                      CHECK(typeof(not_messages) = 'integer' AND not_messages >= 0),
    counted_from  INTEGER CHECK(counted_from IS NULL
                                OR (typeof(counted_from) = 'integer'
                                    AND counted_from >= 1 AND counted_from <= highest)),
    PRIMARY KEY (signer, generation)
);

CREATE TABLE message_places (
    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),
    generation  INTEGER NOT NULL REFERENCES message_generations(id),
    placed_at   INTEGER NOT NULL CHECK(typeof(placed_at) = 'integer')
);

CREATE INDEX idx_message_places ON message_places(signer, generation, placed_at);

-- A list is stored without repeats: whoever writes the taking of a list
-- must keep each of its marks once, since a row is keyed by the device's
-- key and the mark.
CREATE TABLE message_lists (
    key   BLOB NOT NULL CHECK(typeof(key) = 'blob' AND length(key) = 32),
    mark  BLOB NOT NULL CHECK(typeof(mark) = 'blob' AND length(mark) = 16),
    PRIMARY KEY (key, mark)
);

CREATE INDEX idx_message_lists_mark ON message_lists(mark);

CREATE TABLE message_read_here (
    mark       BLOB PRIMARY KEY CHECK(typeof(mark) = 'blob' AND length(mark) = 16),
    seq        INTEGER NOT NULL UNIQUE CHECK(typeof(seq) = 'integer'),
    id         BLOB REFERENCES message_index(id) ON DELETE CASCADE,
    name       TEXT CHECK(name IS NULL OR length(name) >= 1),
    made_at    INTEGER NOT NULL CHECK(typeof(made_at) = 'integer'),
    merged_at  INTEGER CHECK(merged_at IS NULL OR typeof(merged_at) = 'integer'),
    CHECK((id IS NULL) = (name IS NULL)),
    CHECK(id IS NOT NULL OR merged_at IS NOT NULL)
);

CREATE INDEX idx_message_read_here_id ON message_read_here(id);

CREATE TABLE message_announced (
    id    BLOB NOT NULL REFERENCES message_index(id) ON DELETE CASCADE,
    name  TEXT NOT NULL CHECK(length(name) >= 1),
    PRIMARY KEY (id, name)
);

CREATE TABLE message_read_by_a_person (
    id  BLOB PRIMARY KEY REFERENCES message_index(id) ON DELETE CASCADE
);

CREATE TABLE message_sends (
    sent_at  INTEGER NOT NULL CHECK(typeof(sent_at) = 'integer'),
    name     TEXT CHECK(name IS NULL OR length(name) >= 1),
    to_all   INTEGER NOT NULL CHECK(to_all IN (0, 1)),
    CHECK(name IS NOT NULL OR to_all = 0)
);

CREATE INDEX idx_message_sends_at ON message_sends(sent_at);

CREATE TABLE message_kept (
    id          BLOB PRIMARY KEY CHECK(typeof(id) = 'blob' AND length(id) = 16),
    generation  INTEGER NOT NULL REFERENCES message_generations(id),
    value       BLOB NOT NULL CHECK(typeof(value) = 'blob' AND length(value) = 1936),
    sent        INTEGER NOT NULL CHECK(typeof(sent) = 'integer'),
    kept_at     INTEGER NOT NULL CHECK(typeof(kept_at) = 'integer'),
    again       INTEGER NOT NULL DEFAULT 0 CHECK(typeof(again) = 'integer' AND again IN (0, 1))
);

CREATE TABLE message_kept_numbers (
    id      BLOB NOT NULL REFERENCES message_kept(id) ON DELETE CASCADE,
    number  INTEGER NOT NULL CHECK(typeof(number) = 'integer'
                                   AND number >= 1 AND number <= 4398046511103),
    PRIMARY KEY (id, number)
);

CREATE TABLE message_kept_taken (
    id     BLOB NOT NULL REFERENCES message_kept(id) ON DELETE CASCADE,
    relay  BLOB NOT NULL CHECK(typeof(relay) = 'blob' AND length(relay) = 32),
    PRIMARY KEY (id, relay)
);
```

- `message_generations`: one row for each messages channel the device has
  held, by an integer ID that is the generation in every other table, with
  the channel's ID (unique), the number of the statement that began it, and
  when the device first held it. A statement's number is not a generation: a
  device alone under a phrase that makes a new phrase is at statement 1
  again, with a new messages channel (§9.2). A generation other than the one
  the device stands applied under goes at the hourly task once it holds no
  index row and no kept value, with its rows of first holding, its signers
  and its places (§7.1).
- `message_index`: one row for each message the device holds opened, by its
  ID, with every field it was opened to (decision 2026-10-09 §2.2): the label
  the device knew its signer by, `to_kind` (1: one name, in `to_name`; 2:
  every name, and no `to_name`), `from_name`, `sent`, the subject, `thread`
  and `answers` (zeros where none), whether it asks for an answer, the link
  (NULL where none), the body, when the device first held it, and its place:
  when it was first shown, NULL until then (§6, §7.1); and `not_every_relay`,
  1 where it is the device's own and its kept value was dropped before every
  relay had taken it, which `log` says (§2.3, §4.1). `summary`, `read` and
  `log` read it, and open no entry. A message is looked up by its ID and its
  generation: one held in another generation is not shown again, and is not
  held at a number of this one. **A row that goes is overwritten first:**
  its body, link, subject, `from_name` and `to_name` are written over with
  zeros of the same length, and then it is deleted, with its marks and its
  rows of numbers held, in one transaction (§7.1).
- `message_numbers`: the numbers each message is held at. A message held at
  two numbers is one row of the index and two here.
- `message_first_held`: one row for each live number held, with its ID,
  `sent` and when it was first held; or with no ID and no `sent` where the
  number was first held as a clearing, which counts it as gone and never as
  overwritten (§2.5). It outlives the index row, so that an entry taken
  again at a live number after its 30 days is not shown again.
- `message_signers`: for each signer and generation, H (`highest`), the
  highest number held of a message or a clearing, and the counts of numbers
  overwritten before they were shown and of entries that were not messages,
  and `counted_from`, the first number of that signer held in that
  generation, or a lower one held after it while it was live, from which
  the overwritten are counted, NULL until one is held, and never above H
  (§2.5).
- `message_places`: the time of each place given to a signer, kept for the
  hour of the reader's rate (§6).
- `message_lists`: the marks of the latest list of each other device, by its
  key (§7.2). A list is stored without repeats, which whoever writes the
  taking of a list must do.
- `message_read_here`: the device's own table of what its agents read: each
  mark, with the message's ID and the name that read it, and when it was
  made; or the mark alone, where it was merged from the device's own list on
  a relay and no message has been found for it, with when (§7.2). `seq` is
  the table's order, unique on the device: the newest is the highest, and a
  mark merged as older than any held takes one below the lowest.
- `message_announced` and `message_read_by_a_person`: the device's own marks,
  that `summary` announced a message to the agent of a name here, and that a
  person read it here. They are never synced.
- `message_sends`: one row for each send, by the device's clock, with the name
  of the folder's agent and whether it was to every name; a send again has no
  name (§6).
- `message_kept`, `message_kept_numbers` and `message_kept_taken`: each
  message of the device's own that not every relay has taken: its value as it
  was sent (always 1,936 bytes), the numbers it was sent under, and the relays
  that have taken it (§2.3); and `again`, 1 where it waits to be sent again
  under the next number: a relay answered that it holds another entry of the
  device's at its newest number, or handed back the device's own entry over it.
  What a relay answered of a push of the messages channel is kept here in the
  write that moves `sent_to` for it (`at_relays`), so that neither is kept
  without the other.

**`secure_delete` is not a step.** A personal node sets SQLite's
`secure_delete` on its store's connection where it opens it, before the
schema's steps run, and on no relay's: on a personal node it covers every table. After each hourly clearing
a personal node runs `PRAGMA wal_checkpoint(TRUNCATE)` (§7.1). A relay keeps
nothing in any of these tables.

---

## 11. Stored Keys, Counters and the Guard

### 11.1 node_meta

`node_meta` (v4) is a table of keys and values. The keys of this version:

| Key | Value | Whose |
|---|---|---|
| `sync.claude.dir`, `sync.claude.last_dir` | The Claude Code directory that sync is on for; and the one it last ran with, kept while sync is off | A device's settings: kept |
| `sync.claude.mappings` | JSON array of declared mappings, `[{"folder": "/abs/path", "name": "..."}]` | Kept |
| `sync.claude.home`, `sync.claude.home_name` | Whether home memory is off on this device, and the name that home memory syncs under or last did | Kept |
| `sync.claude.exclude` | JSON array of the project names, and the folders, kept off this device while everything found synced. Only what is mapped syncs, so there is nothing left to exclude; what an older panel sends is still stored (decision §10.1, rule 5) | Kept |
| `sync.claude.all` | The stored scope of everything found. It is written `off` at the first start, and is off whenever sync is on (decision §10.1, rule 2) | Kept, as `off` |
| `sync.claude.report` | JSON report of the last sync cycle. Removed at the first start, and written again by the next cycle | |
| `sync.claude.notice` | JSON array of what a device whose stored scope was on has been told: for each time, the date, the Claude Code directory, and the folders that stopped syncing (`null` where that is not known: there was no stored report, it could not be read, or it was of a cycle that failed before it came to a folder) | Decision §10.1 |
| `first_start.done` | The mark that the first start on this version is done: `stepped by <version>`, or `nothing to step, marked by <version>`. Any mark means done, in this version and in every later one | Decision §10.1 |
| `person.not_carried` | JSON of the files whose record could not be carried when the device applied the statement it has applied: each as the name it syncs under and the file. Replaced at each statement applied. A file goes from it once it has met its channel (a folder has a record of it there at the end of a cycle), and a name's files go when the device stops the name | Decision §4.2 |
| `person.removed_a_key` | Present where the statement that the device has applied removes a key that the statement it held before did not, as the device found it when it applied the statement. A renewal removes nobody, though its list of removed keys names every key removed so far. Written at each statement applied. A status shows a removal as not yet applied by every device only where it is present | Decision §10.1 |
| `person.names_carried` | JSON array of the names that the device holds by a carry that a person asked for, or by a recovery, with no folder of its own mapped to them. It holds each, and lists it in the personal channel, whether or not sync is on. A name goes from the list when the device stops it | Decision §7.3, §9 |
| `person.look_pending` | Present while the look of a recovery that was made on this machine has not ended: set where the recovery's statement is applied, and removed when the look has carried what it takes, or when a later statement is applied. While it is present the machine does not write that it has sent what it carried | Decision §8, §9 |
| `person.removed_labels` | JSON object of what the device called each key that a statement it applied removed, by the key in hex. A statement lists removed keys bare, and a person names one by its label at `cordelia sync carry --from`. A key that the device never knew by a label is not in it | Decision §7.3 |
| `usage.sighting_secret` | The secret a node hashes peer keys with for its usage counts. It never leaves the node | Kept |

Four keys are of the older kind, and a personal node's first start removes
them: `personal_channel_id`, `membership.accepted_personal_from`,
`sync.claude.last_change` and `sync.claude.activity`.

The four `person.*` keys that a device writes under a phrase, and
`person.not_carried`, go when the device leaves its phrase. The notice
(`sync.claude.notice`) goes only when a person says that it was seen
(`cordelia sync status --seen`).

### 11.2 counters

| Name | Value |
|---|---|
| `item_seq` | The arrival order of `items` (v5) |
| `entry_seq` | The order in which this node stored its `entries` (v11) |
| `item_count`, `item_bytes` | How many rows `items` holds, and the bytes of their content together (v13). Three triggers on `items` keep them, in the write that changes a row. A relay's cap for the older kind of channel is set against these, with 1 KB for each item, and not against the database's pages, which hold the table of entries too (decision §2.5, §16) |

The counters stay at a personal node's first start: `item_seq` and
`entry_seq` keep their values, and `item_count` and `item_bytes` come to 0
as the items go.

### 11.3 The Guard

A personal node's first start sets a trigger, `moved_on_takes_no_channel`,
on the older kind's table of channels: `BEFORE INSERT ON channels`, it aborts
with words that say the database was moved on, by which version, and where
the copy is. It is set wherever the mark is written: on a database that had
nothing to step, its words say which version marked it, and that no copy
was made. A version from before this one makes a channel at every start;
started on this database by mistake, it stops there with those words, and
has changed nothing before it. A relay or a bootnode that is started on a
database which a personal node stepped removes the trigger: a node of that
role goes on taking channels of the older kind.

---

## 12. The First Start of a Personal Node, and the Copy

Decision 2026-10-04 §10.1, as `crates/cordelia-storage/src/first_start.rs`
has it. A relay and a bootnode make no copy and take no step.

**The lock.** A data directory is one node's. A node of any role takes an
advisory lock on a file in it, `node.lock` (mode 0600, and empty), after the
port of its local API is bound and before it opens the database, and holds
it for as long as the process lives. A second node that is started on the
same directory says that another is running there, and stops, with nothing
changed. On a volume that knows no such lock the node starts, and says so in
its log.

**When.** A personal node whose database has no mark (§11.1) makes it at its
start: after the port of its local API is bound, so that a node which cannot
bind changes nothing; after the lock is taken; and before its first cycle
and its first pass. Where there is only a mark to write, it is written
before anything else is started. Where a copy is to be made, the node is
held up from its start, and the copy and the step are made by the first turn
of its sync loop: its server answers meanwhile, and its status says that a
copy is being made.

**Who.** Where the device already follows a phrase, or the node holds no row
of the older tables, none of the four older keys and nothing under the name
of a key file of an older channel, the mark is written with the guard
(§11.3), and nothing else. Otherwise:

1. **The copy.** The database, as its opening left it, and the key files of
   the older channels, into a folder beside them named `before-<version>`
   (mode 0700, each file 0600). The database is copied with `VACUUM INTO`,
   never by copying a file that is open, on a connection of its own that is
   opened for reading only. The copy is made under a name that ends
   `.partial`, flushed, opened again read-only and checked (it opens,
   `PRAGMA integrity_check` says `ok`, and it is at this schema's version),
   and only then renamed. A `.partial` that a start finds is removed and made
   again. A whole folder that a start finds, with no mark in the database, is
   kept as `before-<version>.earlier`, in the place of any before it, once
   the new copy is checked: so there are at most two.
   - **Before anything is written the free room on the volume is compared
     with what the copy needs:** the database's pages (`page_count` ×
     `page_size`) and the key files. Where there is less, no copy is begun.
     Where the room cannot be learned the copy is tried.
   - **Where the copy cannot be made, the step is not taken,** and the node
     says why, with the bytes of room that a copy needs and the bytes there
     are. What was written of a copy that failed is removed at once.
   - A copy that was made and checked is used again by a later try of the
     same start where only the step failed, and only where the database
     (what the node notes for itself in `node_meta`, and how many rows each
     older table and each of `sync_files` and `index_lines` has) and the key
     files still hold what the copy holds. One that no longer does is
     removed, and made again.
   - The tries back off: five seconds after the first that failed, and twice
     as long after each further one, up to ten minutes (parameter-rationale.md
     §12.11).
2. **The step, in one transaction, all of it or none.** `sync_files` and
   `index_lines` are emptied. Every table of the older kind is emptied, in
   this order: `channel_members`, `channel_keys`, `dm_peers`, `items`,
   `search_content` (and the index over it), `invites`, `state_offers`,
   `trusted_keys`, `channels`. The four older keys of §11.1 are removed.
   Where the stored scope was on (or absent with a directory set) the notice
   is stored, made from the report as it is stored, unless that report shows
   that nothing stopped. The report is removed and
   the scope is written `off`. The guard is set (§11.3). The mark is written.
3. **After the commit, the key files of the older channels are removed.**
   They are found by their place and their names: whatever is in the folder
   `channel-keys` under a name that ends `.key`, `.ring.json` or `.slot`.
   They are looked for again at every start of a personal node, whatever the
   mark says. **At a start that makes no copy, one is removed only where a
   whole `before-` folder beside the database holds a file of that name with
   the same bytes:** any other is left where it is, and the status says how
   many (`key_files_in_place`). One that cannot be removed is counted and
   said, and the node goes on.

**What stays:** the device's key, its token and its configuration, which are
files and are not touched; its settings and its mappings; the counters;
`peer_sightings`; every table of §10.1 to §10.5; and local history, which is
in files of its own (§8).

**What the copy holds.** What the device held: sealed entries, the keys of
channels that relays keep for up to 90 days more, and also text in the clear
(the search index of what was published through the local API, removed lines
of the index, the names and paths of memory files). The version before opens
it as it opens any database: it knows nothing of the tables added since and
ignores them. It can be deleted once the person is content. Going back is in
operations.md §10.5.

---

## 13. References

| Document | What It Defines |
|----------|----------------|
| specs/ecies-envelope-encryption.md | ECIES envelope format (§4.4), item encryption (§5), key ring (§6.4), CBOR signing (§11) |
| specs/channels-api.md | REST API endpoints, item_type values (§3.2), error codes |
| specs/channel-naming.md | Channel ID derivation (§4), prefix disambiguation (§5) |
| specs/search-indexing.md | FTS5 + sqlite-vec DDL (§2), indexing pipeline |
| specs/identity.md | Key types, entity ID format |
| specs/network-protocol.md | ChannelDescriptor CBOR format (§4.4.6), PSK-Exchange (§4.7), the streams of entries (§4.9) |
| decisions/2026-10-04-a-persons-devices.md | A channel from its secret, the statement, the change entry, adding, removing and recovery: what §9 to §12 are the forms of |
| reference/step4-test-vectors.json | Vectors for the derivations of §9.1 |

---

*Draft: 2026-03-12. Closes buildability gaps for WP2/WP3/WP4 implementation.*
