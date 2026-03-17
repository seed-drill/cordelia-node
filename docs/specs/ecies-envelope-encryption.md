# ECIES Envelope Encryption Specification

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-10
**Scope**: Phase 1 (Encrypted Pub/Sub MVP)
**Supersedes**: cordelia-core/docs/design/encryption-specification.md (pre-pivot, reference only)
**References**: cordelia-core/docs/design/encryption-test-vectors.md (test vectors remain valid)
**Depends on**: specs/channel-naming.md (§4.2 system channels), specs/network-protocol.md (§4.4 Channel-Announce, §4.7 PSK-Exchange)

---

## 1. Overview

This specification defines Cordelia's cryptographic primitives for Phase 1: key encoding, ECIES envelope encryption for PSK distribution, and item-level encryption. It is the authoritative document for all cryptographic operations in the greenfield implementation.

### 1.1 Scope

Phase 1 is a greenfield build. The existing Cordelia codebase (proxy encryption, portal vault, scrypt key derivation) is reference material, not baseline. This spec defines what ships.

**In scope:**
- Bech32 key encoding (human-readable key representation)
- ECIES envelope encryption (PSK distribution between entities)
- Channel item encryption (AES-256-GCM with channel PSK)
- Key types and lifecycle
- Wire formats

**Out of scope (Phase 2+):**
- Vault passphrase recovery (requires multi-device, Phase 1.5+)
- W3C Verifiable Credentials (Phase 3)
- Sealed group descriptors (Phase 4+)

### 1.2 Architecture Context

Phase 1 decision (2026-03-10): **the node is the encryption boundary.**

```
Agent/SDK ── plaintext ──► Node ── encrypted ──► Network
              (localhost,        (AES-256-GCM,
               bearer token)     channel PSK)
```

The SDK sends and receives plaintext over a bearer-token-authenticated localhost connection. The node encrypts on write and decrypts on read. No crypto code in the SDK.

### 1.3 Threat Model

| Threat | Protection |
|--------|-----------|
| Network eavesdropper | All items AES-256-GCM encrypted with per-channel PSK |
| Compromised relay/bootnode | Relays never hold PSKs. Store and forward encrypted blobs only. |
| Compromised keeper (open channel) | Anchor keeper holds PSK for open/gated channels. Accepted: keeper can read these channels. |
| Compromised keeper (private channel) | Keeper never holds PSK for invite-only channels or DMs. Cannot decrypt. |
| Key compromise | PSK rotation on member removal (§6.4). Forward secrecy not a Phase 1 goal. |
| Metadata analysis | Channel IDs are opaque hashes. DM channels derived from sorted keys. Timestamps exposed (accepted). |

**Out of scope**: Side-channel attacks, hardware compromise, nation-state adversaries, quantum computing.

---

## 2. Key Types

### 2.1 Identity Keypair

Each entity has one Ed25519 keypair, generated at `cordelia init`.

| Property | Value |
|----------|-------|
| Algorithm | Ed25519 (RFC 8032) |
| Seed | 32 bytes, CSPRNG |
| Public key | 32 bytes (compressed Edwards point) |
| Storage | `~/.cordelia/identity.key` (seed, file mode 0600) |
| Purpose | Signing (items, attestations), identity, X25519 derivation |

### 2.2 Encryption Keypair (Derived)

X25519 keypair derived deterministically from the Ed25519 identity.

| Property | Value |
|----------|-------|
| Algorithm | X25519 (RFC 7748) |
| Private key | SHA-512(ed25519_seed)[0..32], clamped |
| Public key | Edwards → Montgomery point conversion |
| Storage | Derived on demand (never persisted separately) |
| Purpose | ECDH for ECIES envelope encryption |

**Derivation** (see test vectors §8.1):
1. `h = SHA-512(ed25519_seed)` → 64 bytes
2. `scalar = h[0..32]` → 32 bytes
3. Clamp: `scalar[0] &= 0xF8; scalar[31] &= 0x7F; scalar[31] |= 0x40`
4. Result is the X25519 private key

Public key: `u = (1 + y) / (1 - y) mod p` where `y` is the Ed25519 public key's Edwards y-coordinate.

### 2.3 Channel PSK

Each channel has a pre-shared key for item encryption.

| Property | Value |
|----------|-------|
| Algorithm | AES-256-GCM key |
| Size | 32 bytes, CSPRNG |
| Generation | At channel creation |
| Distribution | ECIES envelope to each subscriber (§4) |
| Storage | `~/.cordelia/channel-keys/<channel_id>.key` (raw bytes, file mode 0600) |

### 2.4 Ephemeral Keypair

Generated per ECIES encryption operation. Never persisted.

| Property | Value |
|----------|-------|
| Algorithm | X25519 (RFC 7748) |
| Private key | 32 bytes, CSPRNG |
| Public key | X25519 base point multiplication |
| Lifetime | Single encryption operation, then discarded |

### 2.5 Bearer Token

Authentication for SDK → node localhost connection.

| Property | Value |
|----------|-------|
| Size | 32 bytes, CSPRNG, hex-encoded (64 chars) |
| Generation | At `cordelia init` |
| Storage | `~/.cordelia/node-token` (file mode 0600) |
| Transport | `Authorization: Bearer <hex>` header |

---

## 3. Bech32 Key Encoding

### 3.1 Rationale

Keys are 32-byte (or 64-byte) binary values. For display, interchange, config files, CLI output, and attestation documents, Cordelia uses Bech32 encoding (BIP-173) with type-specific human-readable parts (HRPs).

Bech32 (not Bech32): aligned with Cardano CIP-19 convention. SPOs and Cardano tooling use Bech32 throughout. Same variant avoids mixed-encoding friction in Phase 3 (ADA Handles, Calidus verification, on-chain registration).

### 3.2 Human-Readable Parts

| HRP | Payload | Size | Example Use |
|-----|---------|------|-------------|
| `cordelia_pk` | Ed25519 public key | 32 bytes | Identity display, attestation subjects, channel membership |
| `cordelia_sk` | Ed25519 seed | 32 bytes | Key export/backup (DANGER: secret material) |
| `cordelia_xpk` | X25519 public key | 32 bytes | ECIES envelope recipient, key agreement |
| `cordelia_sig` | Ed25519 signature | 64 bytes | Signed attestations, item signatures |
| `cordelia_psk` | Channel PSK | 32 bytes | Manual PSK import/export (DANGER: secret material) |

### 3.3 Encoding Rules

1. Use **Bech32** (BIP-173), aligned with Cardano CIP-19
2. All HRP characters are lowercase ASCII
3. Data payload is the raw key bytes, 5-bit grouped per Bech32 convention
4. No length limit enforced (64-byte signatures produce ~122 characters, acceptable)
5. Implementations MUST validate the Bech32 checksum on decode
6. Implementations MUST reject unknown HRPs with a clear error

### 3.4 String Lengths

| Type | HRP Length | Data Chars | Checksum | Total |
|------|-----------|------------|----------|-------|
| `cordelia_pk` | 11 | 52 | 6 | 70 |
| `cordelia_sk` | 11 | 52 | 6 | 70 |
| `cordelia_xpk` | 12 | 52 | 6 | 71 |
| `cordelia_sig` | 12 | 103 | 6 | 122 |
| `cordelia_psk` | 12 | 52 | 6 | 71 |

### 3.5 Display Conventions

- Secret keys (`cordelia_sk`, `cordelia_psk`) MUST be masked in logs and CLI output
- Public keys MAY be truncated for display: `cordelia_pk1abc...xyz` (first 8 + last 4 data chars)
- The `1` separator is part of the Bech32 format, not the HRP itself

### 3.6 Test Vectors

Using Ed25519 seed from RFC 8032 Section 7.1 (test vector 1 from encryption-test-vectors.md):

```
Ed25519 seed (hex):
  9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60

Ed25519 public key (hex):
  d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a

X25519 public key (hex):
  d85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e

Ed25519 signature (RFC 8032 §7.1, signing empty message):
  e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b

Test PSK (arbitrary 32-byte key):
  a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
```

**Bech32 encodings** (generated by BIP-173 reference implementation, round-trip verified):

| ID | HRP | Input | Bech32 | Length |
|----|-----|-------|--------|--------|
| TV-B1 | `cordelia_pk` | Ed25519 public key (32 bytes) | `cordelia_pk16adfsqvzky9t042tlmfujeq88g8wzuhnm2nzxfd0qgdx3ac82ydqlx0asz` | 70 |
| TV-B2 | `cordelia_sk` | Ed25519 seed (32 bytes) | `cordelia_sk1n4smr800l4dxpw5yft6f9mpvc3zyn3tf0vexjxts8wkqx89w0asqcef9k6` | 70 |
| TV-B3 | `cordelia_xpk` | X25519 public key (32 bytes) | `cordelia_xpk1mp0q0mpzkzkcs9fhct6y6e3drg2re7psc4av5sc9mpw84y8kkchqsefgnd` | 71 |
| TV-B4 | `cordelia_sig` | Ed25519 signature (64 bytes) | `cordelia_sig1u4tyxqxrvzk89yyxutxgqm5z32zgwlc7hrjajaxcw0sx2gjfq924lwyzzkg2xwavcc0rjuqulx6xh5jm7hc9jka7y3j4zs2r3eapqzcjyfx4e` | 122 |
| TV-B5 | `cordelia_psk` | Channel PSK (32 bytes) | `cordelia_psk15xev848976nm3jwsu8e28dx96mnl32dsc8fw8a99kmra360s5xeq6lzazn` | 71 |

**Error cases:**

| ID | Input | Expected Result |
|----|-------|-----------------|
| TV-B6 | `cordelia_pk16adfsqvzky9t042tlmfujeq88g8wzuhnm2nzxfd0qgdx3ac82ydqlx0asq` | REJECT: invalid checksum (last char flipped) |
| TV-B7 | `cordelia_foo16adfsqvzky9t042tlmfujeq88g8wzuhnm2nzxfd0qgdx3ac82ydqpdgfjj` | REJECT: unknown HRP `cordelia_foo` |

All lengths match §3.4 predictions. Implementations MUST produce identical Bech32 strings for these inputs and MUST reject both error cases.

---

## 4. ECIES Envelope Encryption

### 4.1 Purpose

ECIES (Elliptic Curve Integrated Encryption Scheme) wraps a channel PSK for a specific recipient using their X25519 public key. The sender needs only the recipient's public key. The recipient decrypts with their private key. No prior shared secret required.

Used for:
- Channel PSK distribution on subscribe
- DM channel PSK exchange (both parties)
- Agent provisioning (operator distributes PSK to agent)

### 4.2 Construction

```
Inputs:
  recipient_xpk : X25519 public key (32 bytes)
  plaintext_psk : Channel PSK to wrap (32 bytes)

Steps:
  1. Generate ephemeral X25519 keypair:
       eph_sk = CSPRNG(32 bytes)
       eph_pk = X25519_basepoint(eph_sk)

  2. ECDH key agreement:
       shared_secret = X25519(eph_sk, recipient_xpk)    -- 32 bytes

  3. Key derivation (HKDF-SHA256):
       salt = 0x00 * 32                                  -- 32 zero bytes
       info = "cordelia-key-wrap-v1"                     -- UTF-8, 20 bytes
       PRK  = HMAC-SHA256(salt, shared_secret)           -- extract
       wrapping_key = HMAC-SHA256(PRK, info || 0x01)     -- expand (single block)

  4. Symmetric encryption (AES-256-GCM):
       iv        = CSPRNG(12 bytes)
       (ct, tag) = AES-256-GCM-Encrypt(wrapping_key, iv, plaintext_psk, aad="")

Output:
  ECIES envelope = (eph_pk, iv, ct, tag)
```

### 4.3 Decryption

```
Inputs:
  recipient_sk  : X25519 private key (derived from Ed25519 seed)
  envelope       : (eph_pk, iv, ct, tag)

Steps:
  1. shared_secret = X25519(recipient_sk, eph_pk)
  2. Derive wrapping_key (same HKDF as §4.2 step 3)
  3. plaintext_psk = AES-256-GCM-Decrypt(wrapping_key, iv, ct, tag, aad="")
  4. If tag verification fails: reject (authentication failure)
```

### 4.4 Wire Format (Binary)

The ECIES envelope is a fixed-size 92-byte binary structure:

```
Offset  Size  Field
──────  ────  ─────
0       32    ephemeral_public_key (X25519)
32      12    iv (AES-256-GCM nonce)
44      32    ciphertext (encrypted PSK)
76      16    auth_tag (GCM authentication tag)
──────  ────
Total:  92 bytes
```

**Properties:**
- Fixed size (PSK is always 32 bytes → ciphertext is always 32 bytes)
- No version byte (version changes would be a new message type, not a field)
- No padding required (fixed size prevents length fingerprinting)
- Wire-order is the same as processing order (parse left to right)

### 4.5 JSON Representation

For REST API responses and config files, the envelope is JSON-encoded:

```json
{
  "ephemeral_public_key": "<base64url, 32 bytes>",
  "iv": "<base64url, 12 bytes>",
  "ciphertext": "<base64url, 32 bytes>",
  "auth_tag": "<base64url, 16 bytes>"
}
```

Base64url (RFC 4648 §5) without padding. Not standard base64. This matches modern API conventions and avoids `+`/`/` characters in URLs and JSON.

### 4.6 Security Properties

| Property | Status |
|----------|--------|
| Confidentiality | AES-256-GCM encrypts PSK |
| Authenticity | GCM auth tag (AEAD) |
| Forward secrecy per envelope | Yes (ephemeral key per operation) |
| Forward secrecy per message | No (same channel PSK for all messages until rotation) |
| Replay protection | Not at this layer (handled by item deduplication at storage layer) |
| Key confirmation | Implicit (GCM decryption succeeds or fails) |

---

## 5. Item Encryption

### 5.1 Construction

All items written to a channel are encrypted with the channel's PSK.

```
Inputs:
  channel_psk : 32-byte AES-256-GCM key
  channel_id  : channel identifier (UTF-8 bytes, used as AAD)
  plaintext   : JSON-serialised item content (UTF-8 bytes)

Steps:
  1. iv = CSPRNG(12 bytes)
  2. aad = UTF-8 bytes of channel_id string
  3. (ciphertext, auth_tag) = AES-256-GCM-Encrypt(channel_psk, iv, plaintext, aad)

Output:
  encrypted_item = (iv, ciphertext, auth_tag)
```

### 5.2 Storage Format

Items are stored in SQLite as a single blob column: `iv || ciphertext || auth_tag`.

```
Offset    Size      Field
──────    ────      ─────
0         12        iv
12        variable  ciphertext (length = plaintext length)
12+len    16        auth_tag
```

The item metadata (channel_id, item_id, author_id, timestamps) is stored in separate columns, unencrypted. This is an accepted trade-off for routing and replication (see §7).

### 5.3 Decryption

```
Inputs:
  channel_psk    : 32-byte key
  channel_id     : channel identifier (UTF-8 bytes, same AAD used during encryption)
  encrypted_blob : iv || ciphertext || auth_tag

Steps:
  1. Parse: iv = blob[0..12], ciphertext = blob[12..len-16], auth_tag = blob[len-16..len]
  2. aad = UTF-8 bytes of channel_id string
  3. plaintext = AES-256-GCM-Decrypt(channel_psk, iv, ciphertext, auth_tag, aad)
  4. If tag verification fails: reject (includes AAD mismatch -- item was moved between channels)
  5. Parse plaintext as UTF-8 JSON
```

### 5.4 Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-256-GCM |
| Key size | 256 bits (32 bytes) |
| IV size | 96 bits (12 bytes), random per item |
| Auth tag size | 128 bits (16 bytes) |
| AAD | channel_id (UTF-8 bytes) -- binds ciphertext to its channel |
| Max plaintext | No protocol limit. Practical limit: SQLite row size (~1GB). Recommended: <256KB. |

### 5.5 AAD Binding

The `channel_id` is bound as AAD (Additional Authenticated Data) in the GCM encryption. This means:

1. **Ciphertext relocation is detected.** Moving an encrypted item from channel A to channel B causes GCM authentication to fail on decryption (AAD mismatch).
2. **Zero runtime cost.** AAD is authenticated but not encrypted -- no additional ciphertext bytes.
3. **channel_id is the only AAD field.** `item_id` is not included because items can be legitimately copied (replication). The channel binding is sufficient.

---

## 6. Channel PSK Lifecycle

### 6.1 Generation

At channel creation, the creator generates a 32-byte PSK from a CSPRNG.

```
channel_psk = CSPRNG(32)
```

The PSK is stored locally and distributed to subscribers via ECIES envelope.

### 6.2 Distribution Flow

**Open channel (auto-approve):**
```
1. Subscriber's node sends PSKRequest to any peer holding the PSK (Phase 1: peer-to-peer; Phase 2+: anchor keeper)
2. Responding peer holds the channel PSK (accepted trust boundary for open channels)
3. Peer wraps PSK in ECIES envelope for subscriber's X25519 public key
4. Peer sends envelope to subscriber via QUIC
5. Subscriber decrypts with their X25519 private key
6. Subscriber stores PSK at ~/.cordelia/channel-keys/<channel_id>.key
```

**Invite-only channel (private):**
```
1. Channel creator wraps PSK in ECIES envelope for each invitee's X25519 public key
2. Envelopes distributed via a side channel (DM, out-of-band, provisioning bundle)
3. Invitee decrypts and stores PSK
4. Keeper never sees the PSK (cannot decrypt private channel content)
```

**DM channel:**
```
1. Initiator generates channel PSK
2. Channel ID = "dm_" + hex(SHA-256("cordelia:dm:" || sort([initiator_pk, peer_pk])))  -- deterministic, domain-separated (channel-naming.md §4.2)
3. Initiator wraps PSK in ECIES envelope for peer's X25519 public key
4. Envelope stored as a channel item (the peer retrieves it via replication)
5. Both parties derive the same channel ID independently
6. Keeper never holds PSK
```

### 6.3 Key File Format

Channel PSK files are raw 32 bytes. No wrapper, no JSON, no encoding.

```
~/.cordelia/channel-keys/
  <channel_id>.key    # 32 bytes, mode 0600
```

`channel_id` is the hex-encoded SHA-256 hash (64 characters) for named channels and DMs, or a UUID string for group conversations.

### 6.4 Rotation

PSK rotation is Phase 1 scope. Triggered by member removal or suspected key compromise.

**Rotation procedure:**

```
1. Generate new PSK (32 bytes, CSPRNG)
2. Increment key_version (e.g., 1 → 2)
3. For each remaining member:
   - Wrap new PSK in ECIES envelope for their X25519 public key
   - Store envelope as channel item (distributed via replication)
4. Store new PSK locally at ~/.cordelia/channel-keys/<channel_id>.key
5. Retain old PSK in key ring for decrypting historical items
6. All new items encrypted with new PSK (new key_version in metadata)
```

**Key ring format:**

```
~/.cordelia/channel-keys/
  <channel_id>.key          # Current PSK (latest version), 32 bytes
  <channel_id>.ring.json    # Key ring with all historical PSKs
```

**Ring file structure** (`<channel_id>.ring.json`):

```json
{
  "channel_id": "a1b2c3...",
  "current_version": 2,
  "keys": [
    { "version": 1, "psk": "<base64url, 32 bytes>", "created_at": "2026-03-10T19:30:00Z", "retired_at": "2026-03-11T10:00:00Z" },
    { "version": 2, "psk": "<base64url, 32 bytes>", "created_at": "2026-03-11T10:00:00Z", "retired_at": null }
  ]
}
```

The `.key` file always contains the raw bytes of the current PSK (version = `current_version`). The `.ring.json` file is created on first rotation. Before any rotation, only the `.key` file exists and `key_version` is implicitly 1.

**Decryption key selection:**

```
1. Read key_version from item plaintext metadata (§7)
2. If key_version == current_version:
     Use PSK from <channel_id>.key (fast path, no ring lookup)
3. If key_version < current_version:
     Load <channel_id>.ring.json
     Find entry where entry.version == key_version
     Use entry.psk
4. If key_version > current_version:
     This node hasn't received the rotation yet.
     Queue item for retry after next replication sync.
     Log warning: "key_version {v} ahead of local {current}"
     Bounded retry: max 1000 items queued per channel.
     If items remain undecryptable after 10 minutes:
       re-request PSK via PSK-Exchange (network-protocol.md §4.7) from a peer holding the channel.
     If still unresolved after 60 minutes: drop queued items, log error.
5. If version not found in ring:
     Decryption failure. Log error. Item stored but marked undecryptable.
```

**Encryption always uses `current_version`.** The `key_version` field is written into the item's plaintext metadata (§7) so that any receiver can select the correct PSK without trial decryption.

**Key retention policy:** All historical PSKs are retained indefinitely. Removed members keep old PSKs (they already received items encrypted with those keys). There is no benefit to purging old keys from the ring since the items encrypted with them already exist on the removed member's node.

**Channel descriptor update:** On rotation, the channel owner increments `key_version` in the channel descriptor, re-signs it, and distributes via Channel-Announce (network-protocol.md §4.4.6).

**Security property:** Removed members retain old PSKs and can decrypt items published before rotation. They cannot decrypt items published after rotation. This matches Signal's model: historical items already received are not re-encrypted.

---

## 7. Plaintext Metadata

The following metadata is stored and replicated in plaintext. This is an accepted trade-off for routing, deduplication, and replication protocol operation.

| Field | Purpose |
|-------|---------|
| `channel_id` | Route item to correct channel (opaque hash or UUID) |
| `item_id` | Deduplication across replicas |
| `author_id` | Attribution (Ed25519 public key) |
| `item_type` | Schema hint for applications |
| `published_at` | Ordering and LWW conflict resolution (with content_hash tiebreak) |
| `is_tombstone` | Soft delete (CoW invariant: no hard deletes) |
| `parent_id` | Threading |
| `key_version` | PSK version for decryption (key ring index, starts at 1) |
| `content_hash` | SHA-256 of ciphertext (bound into author signature) |
| `signature` | Ed25519 signature over CBOR-encoded metadata envelope (§11.7) |
| `content_length` | Encrypted blob size (present in full Item messages only, not in ItemHeader digests -- see network-protocol.md §4.5). Node-internal. Not exposed via REST API or SDK. |

**Privacy mitigation:**
- Channel IDs for named channels are SHA-256 hashes of the name -- the name itself is not exposed in metadata
- DM channel IDs are SHA-256 of sorted public keys -- reveals that two entities communicate but not content
- `author_id` is an Ed25519 public key (pseudonymous unless voluntarily linked to identity)

**Plaintext metadata visibility by observer role:**

| Field | Relay | Bootnode | Malicious Peer (5min+) | Honest Peer |
|-------|:-----:|:--------:|:---------------------:|:-----------:|
| item_id | Y | -- | Y | Y |
| author_id | Y | -- | Y | Y |
| channel_id | Y | -- | Y | Y |
| published_at | Y | -- | Y | Y |
| content_hash | Y | -- | Y | Y |
| item_type | Y | -- | Y | Y |
| key_version | Y | -- | Y | Y |
| is_tombstone | Y | -- | Y | Y |
| signature | Y | -- | Y | Y |
| content (plaintext) | -- | -- | -- | Y (decrypted) |
| metadata (app-level) | -- | -- | -- | Y (decrypted) |

Bootnodes never receive items (discovery-only role). Malicious peers can observe metadata via free-rider attack (fake ChannelJoined) until demoted by governor scoring. Content and application metadata are encrypted with channel PSK and visible only to honest peers holding the key. See specs/review-privacy.md for full analysis.

---

## 8. Test Vectors

### 8.1 Ed25519 → X25519 Derivation

Four test vectors are defined in `cordelia-core/docs/design/encryption-test-vectors.md` §1. They remain valid and authoritative for Phase 1.

Summary:
1. RFC 8032 Section 7.1 seed
2. All-zeros seed (degenerate case)
3. libsodium `ed25519_convert.c` seed
4. ed2curve-js cross-verified seed

Plus 3 invalid public key rejection cases.

### 8.2 ECDH Shared Secret

Defined in `encryption-test-vectors.md` §2. IETF hackathon test vector with two-party ECDH verification. Remains valid.

### 8.3 HKDF-SHA256

Defined in `encryption-test-vectors.md` §3. Standalone HKDF test vector with `cordelia-key-wrap-v1` info string. Remains valid.

### 8.4 Full ECIES Round-Trip

Defined in `encryption-test-vectors.md` §4. End-to-end: Ed25519 → X25519 → ECDH → HKDF → AES-256-GCM. Remains valid.

### 8.5 Bech32 Encoding

Seven test vectors (TV-B1 through TV-B7) are defined in §3.6 above. Generated by BIP-173 reference implementation, all round-trip verified.

**Cross-implementation verification checklist:**

1. TV-B1: `cordelia_pk1...` (32-byte Ed25519 public key) -- encode and decode match
2. TV-B2: `cordelia_sk1...` (32-byte Ed25519 seed) -- encode and decode match
3. TV-B3: `cordelia_xpk1...` (32-byte X25519 public key) -- encode and decode match
4. TV-B4: `cordelia_sig1...` (64-byte Ed25519 signature) -- encode and decode match. Note: exceeds Bech32's standard 90-char limit (122 chars). Implementations MUST NOT enforce the 90-char limit for `cordelia_sig`.
5. TV-B5: `cordelia_psk1...` (32-byte channel PSK) -- encode and decode match
6. TV-B6: Invalid checksum -- MUST reject
7. TV-B7: Unknown HRP (`cordelia_foo`) -- MUST reject with clear error message

**Critical implementation note:** Use Bech32 (BIP-173) constant `1`, NOT Bech32m (BIP-350) constant `0x2bc830a3`. Aligned with Cardano CIP-19. Using Bech32m will produce different checksums and fail cross-implementation verification.

### 8.6 CBOR Deterministic Encoding

Three CBOR test vectors verify deterministic encoding (RFC 8949 §4.2.1) across Rust (`ciborium`) and TypeScript (`cbor-x`). Generated by Python `cbor2` with `canonical=True`.

**Critical note on key ordering:** CBOR deterministic encoding sorts map keys by **encoded byte length first, then lexicographic**. This is NOT simple alphabetical order. For example, `"item_id"` (7 chars, encoded as 8 bytes) sorts before `"author_id"` (9 chars, encoded as 10 bytes) despite coming after it alphabetically.

#### TV-C1: Item Metadata Envelope (§11.7)

Input fields:
```
{
  "author_id":    h'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
  "channel_id":   "fe028fdaf943c16ec8a1fc496818274ce7e86e921ad926f9712886fa26d309d6",
  "content_hash": h'355e3caf62b8121affe7a3ae801b20d586968a64e231cde1c0ed7714d4c31184',
  "is_tombstone": false,
  "item_id":      "ci_a1b2c3d4e5f6",
  "key_version":  1,
  "published_at": "2026-03-10T19:36:00Z"
}
```

Derived values:
- `channel_id` = SHA-256(`"cordelia:channel:research-findings"`) = `fe028fda...`
- `content_hash` = SHA-256(`b"encrypted_content_placeholder_for_test_vector"`) = `355e3caf...`

CBOR key order (by encoded byte length, then lexicographic):
```
item_id (8B) < author_id (10B) < channel_id (11B) < key_version (12B)
< content_hash (13B) = is_tombstone (13B) = published_at (13B)
  [tie-broken lexicographically: content_hash < is_tombstone < published_at]
```

Expected CBOR (hex, 254 bytes):
```
a7676974656d5f69646f63695f613162326333643465356636
69617574686f725f69645820d75a980182b10ab7d54bfed3c9
64073a0ee172f3daa62325af021a68f707511a6a6368616e6e
656c5f6964784066653032386664616639343363313665633861
31666334393638313832373463653765383665393231616439
3236663937313238383666613236643330396436
6b6b65795f76657273696f6e016c636f6e74656e745f686173
685820355e3caf62b8121affe7a3ae801b20d586968a64e231
cde1c0ed7714d4c311846c69735f746f6d6273746f6e65f4
6c7075626c69736865645f617474323032362d30332d313054
31393a33363a30305a
```

**This is the byte sequence that gets signed** by `Ed25519-Sign(author_sk, cbor_bytes)`.

#### TV-C2: Channel Descriptor (network-protocol.md §4.4.6)

Input fields:
```
{
  "access":       "open",
  "channel_id":   "fe028fdaf943c16ec8a1fc496818274ce7e86e921ad926f9712886fa26d309d6",
  "channel_name": "research-findings",
  "created_at":   "2026-03-10T14:00:00Z",
  "creator_id":   h'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
  "key_version":  1,
  "mode":         "realtime",
  "psk_hash":     h'5d0797db4078ee57088c0bb7f158b8f1977fdb3f0455af38326cc792af8c571f'
}
```

Derived values:
- `psk_hash` = SHA-256(test PSK `a1b2c3d4...a1b2`) = `5d0797db...`

CBOR key order:
```
mode (5B) < access (7B) < psk_hash (9B) < channel_id (11B) = created_at (11B) = creator_id (11B)
  [tie: channel_id < created_at < creator_id]
< key_version (12B) < channel_name (13B)
```

Expected CBOR (hex, 276 bytes):
```
a8646d6f64657073756273637269626572735f6f6e6c796661
636365737364 6f70656e6870736b5f686173685820
5d0797db4078ee57088c0bb7f158b8f1977fdb3f0455af3832
6cc792af8c571f6a6368616e6e656c5f6964784066653032
38666461663934336331366563386131666334393638313832
37346365376538366539323161643932366639373132383836
666132366433303964366a637265617465645f617474323032
362d30332d31305431343a30303a30305a6a63726561746f72
5f69645820d75a980182b10ab7d54bfed3c964073a0ee172f3
daa62325af021a68f707511a6b6b65795f76657273696f6e01
6c6368616e6e656c5f6e616d657172657365617263682d6669
6e64696e6773
```

Note: CBOR hex must be recomputed after mode value correction.

#### TV-C3: Operator Attestation (§14)

Input fields:
```
{
  "agent_id":     h'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
  "attested_at":  "2026-03-10T12:00:00Z",
  "operator_id":  h'3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
  "scope":        ["memory_read", "memory_write", "channel_subscribe"],
  "type":         "operator_attestation",
  "version":      1
}
```

CBOR key order:
```
type (5B) < scope (6B) < version (8B) < agent_id (9B) < attested_at (12B) = operator_id (12B)
  [tie: attested_at < operator_id]
```

Expected CBOR (hex, 208 bytes):
```
a66474797065746f70657261746f725f6174746573746174696f6e
6573636f7065836b6d656d6f72795f726561646c6d656d6f72795f
7772697465716368616e6e656c5f737562736372696265
6776657273696f6e01686167656e745f69645820d75a980182b10a
b7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
6b61747465737465645f617474323032362d30332d31305431323a
30303a30305a6b6f70657261746f725f696458203d4017c3e84389
5a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
```

#### Cross-implementation verification

Both Rust (`ciborium`) and TypeScript (`cbor-x`) MUST produce byte-identical output for all three test vectors. Common failure modes:

1. **Key ordering**: Must use RFC 8949 §4.2.1 (length-first, then lexicographic on encoded bytes). Simple alphabetical sort will produce WRONG output.
2. **Bytes vs strings**: `author_id`, `content_hash`, `creator_id`, `psk_hash`, `agent_id`, `operator_id` are CBOR byte strings (major type 2), NOT text strings.
3. **Integer encoding**: `key_version: 1` and `version: 1` are CBOR unsigned integers (major type 0), encoded as single byte `01`.
4. **Boolean encoding**: `is_tombstone: false` is CBOR simple value `f4` (0xf4).

### 8.7 Item Encryption (AES-256-GCM)

Item encryption test vectors are defined in `cordelia-core/docs/design/encryption-test-vectors.md` §4 (full ECIES round-trip). The round-trip covers: Ed25519 → X25519 → ECDH → HKDF → AES-256-GCM encrypt → decrypt → verify.

For channel PSK encryption (the common case in Phase 1), the flow is simpler:
```
1. iv = random 12 bytes (use deterministic IV for test only, NEVER in production)
2. (ciphertext, tag) = AES-256-GCM-Encrypt(psk, iv, plaintext, aad=channel_id)
3. blob = iv || ciphertext || tag
```

Test vector using existing ECIES TV4 inputs remains authoritative. No additional item encryption test vector needed -- the PSK path is a subset of the ECIES path with the HKDF step replaced by a direct PSK.

---

## 9. Implementation Guidance

### 9.1 Rust (cordelia-node)

| Operation | Recommended Crate |
|-----------|------------------|
| Ed25519 | `ed25519-dalek` |
| X25519 ECDH | `x25519-dalek` |
| Ed25519 → X25519 conversion | `curve25519-dalek` (`EdwardsPoint::to_montgomery()`) |
| HKDF-SHA256 | `hkdf` + `sha2` |
| AES-256-GCM | `aes-gcm` or `ring::aead` |
| Bech32 | `bech32` (rust-bitcoin) |
| CSPRNG | `rand::rngs::OsRng` |

### 9.2 TypeScript (cordelia-sdk, thin adapter)

| Operation | Recommended Library |
|-----------|-------------------|
| Ed25519 | `@noble/curves/ed25519` |
| X25519 | `@noble/curves/ed25519` (`edwardsToMontgomeryPriv/Pub`) |
| HKDF-SHA256 | `@noble/hashes/hkdf` |
| AES-256-GCM | Web Crypto API (`subtle.encrypt/decrypt`) |
| Bech32 | `bech32` (bitcoinjs) |

Note: The SDK itself does NOT perform encryption in Phase 1 (node is the encryption boundary). These libraries are listed for completeness and for the thin MCP adapter if it needs to decode Bech32 keys for display.

### 9.3 Cross-Implementation Invariants

Both implementations MUST produce identical output for all test vectors. Common failure modes:

1. **Clamping**: Apply to SHA-512 output, not raw seed. `byte[0] &= 0xF8`, `byte[31] &= 0x7F`, `byte[31] |= 0x40`.
2. **Edwards → Montgomery**: Use `u = (1 + y) / (1 - y) mod p`, not the inverse.
3. **HKDF empty salt**: 32 zero bytes as HMAC key, not omitted.
4. **AES-256-GCM tag**: Cordelia stores IV, ciphertext, and tag as a single contiguous blob. Libraries that return tag separately must concatenate.
5. **Bech32 variant**: Use Bech32 (BIP-173) constant (`1`), NOT Bech32m (`0x2bc830a3`). Aligned with Cardano CIP-19.
6. **Base64url**: No padding (`=`). Alphabet: `A-Z a-z 0-9 - _`.

---

## 10. Algorithm Parameters Summary

| Parameter | Value |
|-----------|-------|
| Identity algorithm | Ed25519 (RFC 8032) |
| Key agreement | X25519 (RFC 7748) |
| KDF | HKDF-SHA256 (RFC 5869) |
| HKDF salt | 32 zero bytes |
| HKDF info | `cordelia-key-wrap-v1` (UTF-8) |
| Symmetric encryption | AES-256-GCM |
| IV size | 12 bytes (96 bits), random |
| Auth tag size | 16 bytes (128 bits) |
| PSK size | 32 bytes (256 bits) |
| Key encoding | Bech32 (BIP-173) |
| Signed payload encoding | CBOR deterministic (RFC 8949 §4.2.1) |
| Channel ID (named) | SHA-256(canonical_name) |
| Channel ID (DM) | "dm_" + hex(SHA-256("cordelia:dm:" \|\| sort([pk_a, pk_b]))) |
| Channel ID (group conv) | UUID v4 |

---

## 11. Signed Payload Encoding

### 11.1 Rationale

Attestations, item signatures, and verifiable credentials all require signing a payload. Signing requires deterministic serialization -- the same logical document must produce the same bytes every time, across implementations.

JSON does not guarantee this. Key ordering, whitespace, number formatting, and Unicode escaping are all implementation-dependent. RFC 8785 (JSON Canonicalization Scheme) exists but has limited tooling and adoption.

CBOR (RFC 8949) defines deterministic encoding rules in §4.2.1 (Core Deterministic Encoding Requirements). Cardano uses CBOR throughout its transaction and metadata formats. Adopting CBOR for signed payloads aligns with Cardano tooling and provides a natural upgrade path to COSE_Sign1 (RFC 9052) in Phase 3.

### 11.2 Rule

**All signed payloads in Cordelia use CBOR deterministic encoding.**

The bytes that are signed are the CBOR-encoded payload, not a JSON representation. JSON is used for display, API responses, and human-readable config. CBOR is used for the canonical byte representation that gets signed and verified.

### 11.3 Signing Construction

```
Inputs:
  signer_sk  : Ed25519 private key (seed)
  payload    : structured data (attestation, item content, credential)

Steps:
  1. Encode payload as CBOR (deterministic encoding, RFC 8949 §4.2.1)
  2. signature = Ed25519-Sign(signer_sk, cbor_bytes)

Output:
  (cbor_bytes, signature)     -- 64-byte Ed25519 signature
```

Verification:
```
  1. Ed25519-Verify(signer_pk, cbor_bytes, signature)
  2. Decode cbor_bytes as CBOR to recover payload
```

### 11.4 CBOR Deterministic Encoding Rules (Summary)

Per RFC 8949 §4.2.1:
- Integers: smallest encoding
- Map keys: sorted by encoded bytes (length-first, then lexicographic)
- No indefinite-length encoding
- No duplicate map keys
- Floating-point: smallest precise representation

### 11.5 Phase 3: COSE_Sign1 Wrapping

In Phase 3 (Cardano integration), signed payloads will be wrapped in COSE_Sign1 (RFC 9052) structures:

```
COSE_Sign1 = [
  protected: { 1: -8 },           -- alg: EdDSA
  unprotected: {},
  payload: cbor_bytes,             -- the CBOR-encoded payload (same as Phase 1)
  signature: ed25519_signature     -- 64 bytes
]
```

Because Phase 1 already signs CBOR bytes, the Phase 3 upgrade is additive: wrap the existing (payload, signature) pair in the COSE_Sign1 CBOR array. No re-signing. No format migration. Cardano wallets can verify directly.

### 11.6 What Gets Signed

| Structure | Signed? | Phase |
|-----------|---------|-------|
| Operator attestation | Yes (operator signs agent's attestation) | 1 |
| Channel item metadata | Yes (author signs metadata envelope) | 1 |
| Channel descriptor | Yes (creator signs descriptor) | 1 |
| Verifiable credential | Yes (issuer signs claim) | 1 (simplified), 3 (W3C VC) |
| ECIES envelope | No (authenticated by GCM, not signed) | -- |
| Profile metadata | No (self-declared, no signature needed) | -- |

### 11.7 Item Signature Construction

Items are signed **over the metadata envelope, not the plaintext content.** This allows relays and keepers to verify authorship without holding the channel PSK (anti-spam, anti-forgery at the network layer).

**Signed payload (CBOR-encoded):**

```
{
  "author_id":    h'<32 bytes Ed25519 public key>',
  "channel_id":   "e5b7e094...",
  "content_hash": h'<32 bytes SHA-256 of ciphertext>',
  "is_tombstone": false,
  "item_id":      "ci_a1b2c3d4e5f6",
  "key_version":  1,
  "published_at": "2026-03-10T19:36:00Z"
}
```

**Encoding notes:**
- `author_id` is raw bytes (CBOR major type 2), not Bech32 string. Bech32 (`cordelia_pk1...`) is used in REST API and SDK responses (human-readable contexts). The signed envelope uses raw bytes for compactness and to avoid encoding ambiguity.
- `content_hash` is raw bytes (CBOR major type 2), not hex string. Same rationale.
- `is_tombstone` MUST be included in the signed envelope. Without it, a malicious relay could flip an item's tombstone flag to `true`, causing deletion across the network without the author's consent.
- `key_version` MUST be included in the signed envelope. Without it, a malicious relay could modify the key_version to cause targeted decryption failures (the receiver selects the wrong PSK, or queues the item indefinitely for a version that never arrives).
- CBOR map keys are sorted by **encoded byte length first, then lexicographic** per RFC 8949 §4.2.1. This is NOT simple alphabetical order. The correct sort order for item metadata is: `item_id`, `author_id`, `channel_id`, `key_version`, `content_hash`, `is_tombstone`, `published_at`. See TV-C1 (§8.6) for the verified CBOR encoding.

**Construction:**

```
1. Encrypt plaintext content with channel PSK (§5.1)
2. Compute content_hash = SHA-256(ciphertext) (raw 32 bytes)
3. Assemble metadata envelope (author_id, channel_id, content_hash, is_tombstone, item_id, key_version, published_at)
4. Encode metadata envelope as CBOR (deterministic, §11.4)
5. signature = Ed25519-Sign(author_sk, cbor_bytes)
```

**Verification (by any peer, no PSK required):**

```
1. Decode metadata envelope from CBOR
2. Verify: Ed25519-Verify(author_pk, cbor_bytes, signature)
3. Verify: SHA-256(stored_ciphertext) == content_hash from envelope
4. If both pass: item is authentic and untampered
```

**Properties:**

| Property | How |
|----------|-----|
| Author authenticity | Ed25519 signature over author_id |
| Content integrity | content_hash binds ciphertext to signature |
| Channel binding | channel_id in signed envelope (complements AAD binding in §5.5) |
| Relay verification | No PSK needed -- relays verify before storing |
| Non-repudiation | Author cannot deny publishing (signature is proof) |

**Storage:** The 64-byte Ed25519 signature is stored in plaintext item metadata alongside `author_id`, `item_id`, etc. It is NOT inside the encrypted blob.

### 11.8 Implementation

| Language | Recommended Library |
|----------|-------------------|
| Rust | `ciborium` or `minicbor` |
| TypeScript | `cbor-x` or `cborg` |

---

## 12. Security Considerations

### 12.1 IV Reuse

AES-256-GCM is catastrophically broken if an IV is reused with the same key. With 12-byte random IVs and 32-byte keys:
- Birthday bound: ~2^48 items per channel before collision risk becomes non-negligible
- At 1000 items/second: ~8,900 years per channel
- Acceptable for Phase 1. Monitor and alert if any channel exceeds 2^32 items.

### 12.2 PSK as Static Key

Channel PSK is a static symmetric key used for all items in the channel. This means:
- No forward secrecy within a channel (compromise of PSK reveals all items)
- Mitigated by: PSK rotation on member removal (§6.4), channel-level isolation (one PSK per channel)
- Accepted trade-off: static PSK enables any subscriber to decrypt any item without key ratcheting state

### 12.3 ECIES Ephemeral Key Reuse

Each ECIES envelope operation MUST generate a fresh ephemeral keypair. Reusing an ephemeral key across multiple recipients leaks the shared secret relationship. Implementations MUST NOT cache or reuse ephemeral keys.

### 12.4 Bearer Token Scope

The bearer token authenticates the SDK to the local node over localhost. It is NOT a cryptographic key and does NOT appear in any encryption operation. Compromise of the bearer token allows an attacker on the same machine to read/write plaintext via the node API -- but if the attacker is on the same machine, the threat model already assumes device compromise.

### 12.5 Post-Quantum Migration

Post-quantum migration: The cryptographic primitives (Ed25519, X25519, AES-256-GCM) are not quantum-resistant. Phase 5 should evaluate hybrid key exchange (X25519 + ML-KEM) per NIST PQC standards and UK NCSC guidance. No action required for Phase 1.

---

## 13. Resolved Questions

1. **AAD binding**: **Yes.** `channel_id` bound as GCM AAD (§5.5). Zero cost, prevents ciphertext relocation.

2. **PSK distribution for DMs**: **Channel item.** Envelope stored as a channel item, replicated to peer via eager push. NOT in the channel descriptor (which is plaintext metadata visible to all peers via Channel-Announce).

## 14. Node Initialization (`cordelia init`)

First-device setup. Creates identity, personal channel, config, and starts the node. Device pairing (`cordelia pair`/`cordelia join`) is deferred to Phase 1.5/2.

### 14.1 Initialization Flow

```
$ cordelia init [--name <name>]

Steps (in order):

1. IDENTITY GENERATION
   a. Generate Ed25519 seed: 32 bytes from CSPRNG
   b. Derive Ed25519 public key
   c. Derive X25519 keypair (§2.2)
   d. Write seed to ~/.cordelia/identity.key (mode 0600)
   e. If --name not provided: prompt for name (required)
      entity_id = <name> + "_" + hex(SHA-256(pubkey))[0..4]  (e.g., "russwing_a1b2")

2. BEARER TOKEN
   a. Generate 32 bytes from CSPRNG
   b. Hex-encode (64 chars)
   c. Write to ~/.cordelia/node-token (mode 0600)

3. PERSONAL CHANNEL
   a. Generate personal channel PSK: 32 bytes from CSPRNG
   b. Channel name: "__personal"  (double underscore = system channel, not user-creatable)
   c. Channel ID: hex(SHA-256("cordelia:channel:__personal:" + hex(ed25519_pubkey)))
      - Domain-separated, entity-specific (each entity's personal channel has a unique ID)
      - Personal channel ID derivation per channel-naming.md §2.1 (canonical reference).
   d. Store PSK at ~/.cordelia/channel-keys/<channel_id>.key (mode 0600)
   e. Create channel descriptor (signed by identity key):
      - access: "invite_only"
      - mode: "realtime"
      - key_version: 1
   f. Personal channel is used for:
      - L1-equivalent personal memory (key-value via item_type = "kv")
      - PSK envelope distribution (item_type = "psk_envelope")
      - Agent attestation storage (item_type = "attestation")

4. CONFIGURATION
   a. Write ~/.cordelia/config.toml:

   [identity]
   entity_id = "<entity_id>"
   public_key = "<cordelia_pk1...>"

   [network]
   listen_addr = "0.0.0.0:9474"
   role = "personal"
   api_addr = "127.0.0.1:9473"

   [[network.bootnodes]]
   addr = "boot1.cordelia.seeddrill.ai:9474"

   [[network.bootnodes]]
   addr = "boot2.cordelia.seeddrill.ai:9474"

5. TLS CERTIFICATE
   a. Generate self-signed X.509 certificate binding Ed25519 public key (§2.2 of network-protocol.md)
   b. Store at ~/.cordelia/tls/node.crt and ~/.cordelia/tls/node.key (mode 0600)
   c. Certificate contains Ed25519 public key in SubjectPublicKeyInfo (RFC 8410)

6. STORAGE
   a. Create ~/.cordelia/cordelia.db (SQLite)
   b. Run schema migrations (all tables for channels, items, members, FTS5)
   c. Insert personal channel into channels table
   d. Insert self as channel owner in members table

7. START NODE
   a. Bind P2P listener on configured port
   b. Bind HTTP API on configured localhost port
   c. Load bootnodes into cold peer table
   d. Start governor tick loop
   e. Begin bootstrap flow (network-protocol.md §10.3)
```

### 14.2 Directory Structure

After `cordelia init`, the filesystem layout is:

```
~/.cordelia/                          # Directory mode 0700
  identity.key              # Ed25519 seed (32 bytes, mode 0600)
  node-token                # Bearer token (64 hex chars, mode 0600)
  config.toml               # Node configuration (mode 0600)
  cordelia.db               # SQLite database (mode 0600 -- contains FTS5 plaintext indexes)
  tls/
    node.crt                # Self-signed X.509 certificate (mode 0644)
    node.key                # TLS private key (mode 0600)
  channel-keys/             # Directory mode 0700
    <channel_id>.key        # Personal channel PSK (32 bytes, mode 0600)
```

### 14.3 Idempotency

If `~/.cordelia/identity.key` already exists, skip key generation and use the existing identity. Print the existing entity_id and public key. Use `--force` to regenerate (overwrites existing identity).

### 14.4 Agent Provisioning (Phase 1)

Operators can provision agent identities using the same init flow with an attestation:

```
$ cordelia init --name "research-agent" --operator <operator_pubkey>
```

This creates a standard identity plus an operator attestation item (identity ADR §4) stored in the agent's personal channel. The attestation links the agent to its operator, enabling accountability without sacrificing the agent's operational autonomy.

---

## 15. Outstanding TODOs

~~1. **Bech32 test vectors**: Generated (§3.6, §8.5). 7 vectors, all round-trip verified.~~

~~2. **CBOR test vectors**: Generated (§8.6). 3 vectors (item metadata, channel descriptor, operator attestation). Deterministic encoding verified.~~

No outstanding TODOs. Spec ready for Martin's review and implementation.

---

## 16. References

- **RFC 8032**: Ed25519 signatures
- **RFC 7748**: X25519 key agreement
- **RFC 5869**: HKDF specification
- **BIP-173**: Bech32 encoding
- **CIP-19**: Cardano binary data encoding (Bech32 for keys and addresses)
- **RFC 8949**: CBOR (Concise Binary Object Representation), §4.2.1 deterministic encoding
- **RFC 9052**: COSE (CBOR Object Signing and Encryption), COSE_Sign1 for Phase 3
- **NIST SP 800-38D**: AES-GCM specification
- **cordelia-core/docs/design/encryption-specification.md**: Pre-pivot encryption architecture (reference)
- **cordelia-core/docs/design/encryption-test-vectors.md**: Cryptographic test vectors (authoritative, remains valid)
- **decisions/2026-03-10-phase1-design-decisions.md**: Node encryption boundary, greenfield build
- **decisions/2026-03-10-identity-privacy-model.md**: Identity stack, Bech32 key usage in examples
- **decisions/2026-03-09-architecture-simplification.md**: Architecture pivot, channel encryption model

---

*Draft: 2026-03-10. Updated 2026-03-11: Bech32 test vectors (§3.6, §8.5) and CBOR test vectors (§8.6) generated and verified. All TODOs resolved. Ready for Martin's review.*
