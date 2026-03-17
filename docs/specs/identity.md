# Identity Specification

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-12
**Scope**: Phase 1 (Layer 0 only) with forward references to Phase 2-4 layers
**Depends on**: specs/ecies-envelope-encryption.md, specs/network-protocol.md
**Informs**: All specs that reference entity identity, key management, or authentication

---

## 1. Design Principles

1. **Keypair IS identity.** There is no registration authority, no account server, no enrolment portal in the critical path. Possession of the Ed25519 private key is the sole proof of identity. Every cryptographic operation -- signing, authentication, key agreement -- derives from this single seed (ecies-envelope-encryption.md SS2).

2. **Privacy by default, disclosure voluntary.** The protocol operates with keys alone. Everything above the cryptographic layer (names, entity types, verification proofs) is optional and entity-controlled. No entity is forced to disclose anything beyond its public key. Contexts (channels, keepers) may require disclosure as a condition of access, but the protocol itself cannot compel it (identity ADR SS9, Principles 2-3).

3. **Portable.** The identity is a single 32-byte file (`~/.cordelia/identity.key`). Copy the file to another device, and the identity moves with it. Device pairing (operations.md SS3) is the structured mechanism for this, but raw file copy works equivalently.

4. **Phase 1: Layer 0 only.** This spec defines Layer 0 (cryptographic identity) in full detail. Layers 1-3 (profile, verification, reputation) are forward references summarised from the identity ADR. They will be promoted to full spec sections when their respective phases begin implementation.

5. **Protocol indifference to entity type.** The protocol does not distinguish humans from agents from keepers from services. A key is a key. Entity type is metadata, not protocol logic (identity ADR SS3).

---

## 2. Four-Layer Identity Model

Every entity starts at Layer 0. Higher layers are voluntary. This model is promoted from the identity ADR (decisions/2026-03-10-identity-privacy-model.md SS2) to normative spec status.

### 2.1 Layer 0: Cryptographic Identity (Phase 1)

The only layer implemented in Phase 1. All protocol operations use this layer exclusively.

- **Ed25519 keypair** (RFC 8032): signing, authentication, identity binding
- **X25519 keypair** (RFC 7748): derived deterministically from Ed25519 seed, used for ECDH key agreement in ECIES envelope encryption. X25519 is used exclusively for key agreement (PSK distribution, pairing bundle encryption). It is never used for authentication, signing, or identity binding.
- **Identity = possession of private key.** Same key = same entity, always, across sessions and devices
- **No registration required.** `cordelia init` generates a keypair locally; the entity exists immediately

The Ed25519 public key is the canonical identity. Entity IDs (SS4.1) and display names are informational labels, not protocol-level identifiers.

### 2.2 Layer 1: Profile (Phase 2)

Self-declared metadata published to the entity's keepers. No proof. Like a bio before verification.

```json
{
  "key": "cordelia_pk1...",
  "display_name": "Bob",
  "type": "human",
  "about": "Cardano SPO operator, AI researcher",
  "created_at": "2026-03-10T00:00:00Z"
}
```

Display names are not globally unique -- they are labels, not identifiers. Entity type is metadata, not protocol logic. Entity types: `human`, `agent`, `keeper`, `service`, `org` (identity ADR SS3).

Profile metadata is stored in the entity's personal channel (`__personal`, channel-naming.md SS2.1).

### 2.3 Layer 2: Verification (Phase 3)

Cryptographic proofs linking a Cordelia key to external identities. Multiple proofs can be attached. Each proof is independently verifiable by any peer.

| Proof Type | What It Proves | Mechanism | Phase |
|---|---|---|---|
| Operator attestation | "Agent X is operated by Alice" | Operator's key signs agent's key + type | 1 |
| Domain | "I control example.com" | DNS TXT: `cordelia-verify=cordelia_pk1...` | 2 |
| GitHub | "I am @user on GitHub" | Sign a gist with Cordelia key | 2 |
| ADA Handle | "I own $bob" | Sign Cordelia key with handle-holding payment key | 3 |
| Calidus (SPO) | "I operate pool NUTS" | Calidus key signs Cordelia key, verified on-chain (CIP-0151) | 3 |
| Cardano address | "I control addr1..." | Sign message with payment key | 3 |
| Identus DID | "Verifiable credential from issuer X" | W3C VC signed by Identus issuer | 3+ |

Phase 1 uses a simplified credential format (self-declared credentials only: entity-type, operator-attestation). Phase 3 aligns with W3C Verifiable Credentials Data Model 2.0 for Identus integration. The Phase 1 format is a subset with a defined mapping to W3C VC (identity ADR SS6).

### 2.4 Layer 3: Reputation (Phase 4)

Derived from network participation. Specified in Phase 4. Design intent summarised from the identity ADR (identity ADR SS2, Layer 3).

- Trust score built from interaction history
- Peer attestations ("I've interacted with Bob for 6 months")
- Channel-specific reputation and membership longevity
- Delegation-based trust (SPO model, per SPO economic model ADR)
- Oracle-published quality metrics (for keepers)

---

## 3. Key Generation and Storage

### 3.1 Key Generation

Performed during `cordelia init` (ecies-envelope-encryption.md SS14.1, operations.md SS2.2).

1. **Ed25519 seed**: 32 bytes from CSPRNG (operating system entropy source)
2. **Ed25519 keypair**: derived from seed per RFC 8032
3. **X25519 keypair**: derived deterministically from Ed25519 seed per ecies-envelope-encryption.md SS2.2

All three derivations are deterministic from the 32-byte seed. The seed is the single root secret.

### 3.2 Key Storage

| Path | Mode | Contents | Sensitivity |
|------|------|----------|-------------|
| `~/.cordelia/identity.key` | 0600 | Ed25519 seed (32 bytes, raw binary) | CRITICAL -- identity is lost if this file is lost |
| `~/.cordelia/node-token` | 0600 | Bearer token (32 bytes CSPRNG, hex-encoded, 64 chars) | LOW -- regeneratable |
| `~/.cordelia/tls/node.key` | 0600 | TLS private key (PKCS#8-encoded Ed25519 seed) | LOW -- generated from identity.key on startup |
| `~/.cordelia/tls/node.crt` | 0644 | Self-signed X.509 certificate | PUBLIC |
| `~/.cordelia/channel-keys/<channel_id>.key` | 0600 | Channel PSK (32 bytes, raw binary) | HIGH -- channel content unreadable without it |

The X25519 key is derived on demand and never persisted separately (ecies-envelope-encryption.md SS2.2).

The data directory `~/.cordelia/` has mode 0700. The node MUST warn on startup if key file permissions are too open and SHOULD refuse to start if key files are world-readable (mode & 0044 != 0) (operations.md SS5.4).

### 3.3 Key Derivation

All keys derive from the single 32-byte Ed25519 seed:

```
Ed25519 seed (32 bytes, CSPRNG)
  |
  +-- Ed25519 keypair (RFC 8032)        -- signing, authentication, identity
  |     public key: 32 bytes (compressed Edwards point)
  |
  +-- X25519 keypair (RFC 7748)         -- ECDH for ECIES envelope encryption
        Derivation (ecies-envelope-encryption.md SS2.2):
          1. h = SHA-512(ed25519_seed) -> 64 bytes
          2. scalar = h[0..32] -> 32 bytes
          3. Clamp: scalar[0] &= 0xF8; scalar[31] &= 0x7F; scalar[31] |= 0x40
          4. Result is the X25519 private key
        Public key: u = (1 + y) / (1 - y) mod p
          where y is the Ed25519 public key's Edwards y-coordinate
```

Derivation is deterministic: the same seed always produces the same Ed25519 and X25519 keypairs. Test vectors in ecies-envelope-encryption.md SS8.1.

---

## 4. Entity Identification

Three identifier forms serve different purposes. The Ed25519 public key is always the canonical identity.

### 4.1 Entity ID

A human-readable label derived from the public key. Informational only -- not used for cryptographic operations.

**Format** (operations.md SS2.5, ecies-envelope-encryption.md SS14.1):

```
entity_id = <name>_<first 4 hex chars of SHA-256(ed25519_public_key)>
```

**Name source:** Provided interactively during `cordelia init` or via `--name` flag. If omitted, defaults to the OS username (lowercased, non-alphanumeric chars replaced with hyphens).

**Name validation:** Names MUST match `^[a-z][a-z0-9-]{0,30}[a-z0-9]$` (lowercase alphanumeric + hyphens, 2-32 chars, starts with letter, does not end with hyphen). Single-character names are not permitted by the regex (minimum is 2 characters: one letter followed by one alphanumeric). Underscore is reserved as the separator before the hex suffix (operations.md SS2.5).

**Example:**

```
$ cordelia init --name russwing
Entity ID: russwing_a1b2
```

**Properties:**
- Human-memorable, not globally unique (collision possible but unlikely with 4 hex chars = 65,536 combinations per name)
- Stored in `config.toml` under `[identity] entity_id`
- Displayed in CLI output (`cordelia status`, `cordelia peers`)
- The Ed25519 public key is the canonical identity, not the entity ID (ecies-envelope-encryption.md SS2.1)

### 4.2 Node ID

The Ed25519 public key encoded in Bech32 format.

**Format** (ecies-envelope-encryption.md SS3):

```
cordelia_pk1<bech32_encoded_32_bytes>
```

**Properties:**
- Globally unique, cryptographically bound to identity
- Used in P2P protocol for peer identification (network-protocol.md SS2.2: TLS certificate Subject CN = Bech32-encoded public key)
- Used in handshake messages: `node_id` field contains raw 32-byte Ed25519 public key (network-protocol.md SS4.1.1)
- Displayed in configuration and CLI output
- Stored in `config.toml` under `[identity] public_key`

### 4.3 Author ID

The same Ed25519 public key, used to identify the author of items and the creator of channels.

**Usage:**
- **Item signatures:** Items carry an `author_id` (raw 32-byte Ed25519 public key) in the signed CBOR metadata envelope (ecies-envelope-encryption.md SS11). The REST API transforms this to `author` in Bech32 format (channels-api.md SS3.4).
- **Channel descriptors:** The `creator_id` field (raw 32 bytes) in `ChannelDescriptor` identifies the channel creator and is covered by the descriptor's Ed25519 signature (network-protocol.md SS4.4.6).

**Wire format:** Raw 32 bytes.
**REST API format:** Bech32 string (`cordelia_pk1...`).
**SDK format:** Bech32 string.

---

## 5. Authentication

### 5.1 P2P Authentication

Mutual authentication via QUIC TLS 1.3 with self-signed certificates binding Ed25519 keys (network-protocol.md SS2.2).

**Mechanism:**
1. Each node generates a self-signed X.509 certificate where:
   - Subject Common Name = Bech32-encoded public key (`cordelia_pk1...`)
   - Certificate key = Ed25519 public key (RFC 8410, OID 1.3.101.112)
   - Validity: 1 year, auto-renewed on startup
   The Ed25519 key IS the TLS certificate key directly, not a derived or separate key. RFC 8410 defines the X.509 SubjectPublicKeyInfo encoding for Ed25519 keys. The TLS certificate wraps the same 32-byte Ed25519 public key that serves as the node's identity -- no additional key generation or derivation is involved.
2. Quinn's `ServerConfig` and `ClientConfig` use a custom certificate verifier that:
   - Accepts self-signed certificates (no CA chain required)
   - Extracts the Ed25519 public key from the certificate
   - Stores it as the peer's verified `node_id`
3. The handshake (network-protocol.md SS4.1.6) verifies that the `node_id` in the `HandshakePropose` message matches the Ed25519 public key extracted from the TLS certificate. Mismatch = rejection with `reject_reason: "identity mismatch"`. This is defence-in-depth -- TLS already authenticates the key.

**Security property:** An attacker who does not hold the Ed25519 private key cannot establish a QUIC connection that claims the corresponding `node_id`. TLS 1.3's signature-based authentication proves key possession during the TLS handshake (network-protocol.md SS2.2).

### 5.2 REST API Authentication

Bearer token authentication for SDK-to-node localhost connections (channels-api.md SS1.3).

**Mechanism:**
- Token: 32 bytes CSPRNG, hex-encoded (64 chars), generated at `cordelia init` (ecies-envelope-encryption.md SS2.5)
- Transport: `Authorization: Bearer <hex>` HTTP header
- Storage: `~/.cordelia/node-token` (mode 0600)
- Scope: All API endpoints except `/api/v1/health` (unauthenticated liveness probe)
- Missing or invalid token returns `401 unauthorized`

**Binding:** The REST API MUST bind to a loopback interface only (127.0.0.1 or ::1). If a non-loopback address is configured, the node MUST refuse to start (operations.md SS5.4). The bearer token is a local secret; it is not transmitted over the P2P network.

---

## 6. Pairing (Multi-Device Identity)

Pairing shares the Ed25519 identity across multiple devices so they operate as the same entity. Defined in operations.md SS3 and network-protocol.md SS4.8.

### 6.1 Purpose

All paired devices share the same Ed25519 seed and therefore the same identity. Each device is a full node with independent storage that converges via replication. From the network's perspective, paired devices are one entity.

### 6.2 Protocol Overview

**Initiator** (first device, already initialised):

```
$ cordelia pair
Pairing code: XXXX-XXXX-XXXX
Waiting for second device... (expires in 5 minutes)
```

**Joiner** (second device):

```
$ cordelia join XXXX-XXXX-XXXX
```

### 6.3 Pairing Flow

Per network-protocol.md SS4.8:

1. **Initiator** generates a one-time pairing code: 12 chars from uppercase alphanumeric alphabet excluding ambiguous characters (0/O, 1/I/L), effective alphabet of 30 chars, grouped as XXXX-XXXX-XXXX. Entropy: 30^12 = 5.3 x 10^17 combinations.
2. **Initiator** registers pairing code with configured bootnodes via `PairRegister` message. The bootnode computes `HMAC-SHA256(bootnode_secret, code)` and stores only the HMAC with 5-minute TTL. The raw code is discarded after HMAC computation. The `bootnode_secret` is a 32-byte CSPRNG value generated at bootnode startup, unique per bootnode, and stored only in the bootnode's memory. It is used exclusively for HMAC computation of pairing codes and is never transmitted. If the bootnode restarts, active pairing sessions are invalidated (acceptable given the 5-minute TTL).
3. **Joiner** sends `PairLookup` to bootnodes, which resolve the initiator's address.
4. **Joiner** connects directly to initiator via QUIC.
5. **Initiator** sends `PairOffer` (Ed25519 public key + fingerprint). **Joiner** sends `PairAccept` (its own Ed25519 public key + fingerprint).
6. **Both devices display fingerprints** for visual verification. The fingerprint is `SHA-256(public_key)[0..8]` displayed as 4 groups of 4 hex characters (e.g., `A1B2 C3D4 E5F6 7890`). Both devices show:
   - Their own fingerprint
   - The remote device's fingerprint
   The user MUST confirm that both devices show matching remote fingerprints. The initiator prompts: `Remote fingerprint: A1B2 C3D4 E5F6 7890 — does this match the joiner's display? [y/N]`. On `N` or timeout (30 seconds): abort pairing, close connection, log warning `pairing rejected: fingerprint mismatch`. In `--non-interactive` mode, fingerprint verification is skipped (acceptable for automated provisioning in trusted networks).
7. **Initiator** sends `PairBundle`: Ed25519 seed encrypted as an ECIES envelope for the joiner's X25519 key (derived from the joiner's Ed25519 public key), plus one ECIES envelope per channel PSK.
8. **Joiner** replaces its init-generated identity with the received Ed25519 seed, re-derives all keys, begins replication.
9. **Initiator** sends cleanup `PairRegister` with `ttl_seconds: 0` to bootnodes.

### 6.4 Security Properties

- Pairing code is single-use (consumed on successful join)
- 5-minute expiry (configurable via `--timeout`, max 10 minutes)
- Bootnode stores only HMAC, never the raw code (operations.md SS3.3)
- Bootnodes rate-limit PairLookup: max 10 requests per source IP per minute
- MITM protection: visual fingerprint verification (mandatory in interactive mode)
- Initiator accepts only ONE connection per pairing session; subsequent connections rejected with `session_in_use`
- PairBundle reveals initiator's full channel list to joiner (intentional -- same identity). Channel IDs are transport-encrypted (TLS 1.3) but not content-encrypted within the bundle. PSKs are ECIES-encrypted (network-protocol.md SS4.8).

### 6.5 Device Limit

Phase 1: no hard limit on paired devices. All share the same Ed25519 identity.

Phase 4: device management, selective revocation via per-device derived keys.

**Security warning** (operations.md SS3.3): Pairing shares the Ed25519 private key with the second device. A compromised paired device has full access to the identity and all channels. Revocation requires identity rotation (new keypair, re-subscribe to all channels).

---

## 7. Identity in Channel Operations

Identity keys appear in four channel contexts. All use the Ed25519 public key as the identifier.

### 7.1 Channel Creation

The `creator_id` field in `ChannelDescriptor` (network-protocol.md SS4.4.6) is the Ed25519 public key (raw 32 bytes) of the entity that created the channel. The descriptor is signed by the creator's Ed25519 key. Peers verify this signature on receipt.

**First-seen creator wins:** Once a node stores a descriptor for a `channel_id`, it rejects descriptors from a different `creator_id` (network-protocol.md SS4.4.6). Phase 3 on-chain registration resolves creator disputes.

### 7.2 Item Publication

Each published item carries an `author_id` (Ed25519 public key, raw 32 bytes) in the signed CBOR metadata envelope (ecies-envelope-encryption.md SS11). The signature is verifiable by any peer holding the author's public key. The REST API presents this as `author` in Bech32 format (channels-api.md SS3.4).

### 7.3 DM Channel Derivation

Bilateral DM channels are derived deterministically from a sorted pair of Ed25519 public keys (channel-naming.md SS4.2, identity ADR SS7):

```
sorted_keys = sort([pk_a, pk_b])                          -- lexicographic sort of raw 32-byte keys
preimage    = UTF-8("cordelia:dm:") || sorted_keys[0] || sorted_keys[1]   -- 12 + 64 = 76 bytes
channel_id  = "dm_" + hex(SHA-256(preimage))
```

Both parties compute the same channel ID regardless of who initiates. The `dm_` prefix distinguishes DM channel IDs from named channel IDs.

**Properties:**
- Deterministic: both parties derive the same ID
- Symmetric: `dm(alice, bob) == dm(bob, alice)`
- Collision-resistant: SHA-256 of 76 bytes
- Private: only the two parties know the DM exists (not registered, not listed)
- Immutable membership: exactly 2 keys, cannot add or remove members

**Note:** The identity ADR (decisions/2026-03-10-identity-privacy-model.md SS7) uses a simplified formula without domain separation: `SHA-256(sort([key_a, key_b]))`. This spec and channel-naming.md supersede the ADR with the domain-separated form (`cordelia:dm:` prefix), which prevents cross-protocol hash collisions. The authoritative formula is the one shown above.

Test vector in channel-naming.md SS7.2 (vector 5).

### 7.4 Personal Channel

The system channel `__personal` is created per entity at `cordelia init` (ecies-envelope-encryption.md SS14.1, step 3). Its channel ID is derived from the entity's Ed25519 public key:

```
channel_id = hex(SHA-256("cordelia:channel:__personal:" + hex(ed25519_pubkey)))
```

Domain-separated, entity-specific: each entity's personal channel has a unique ID (channel-naming.md SS2.1). The personal channel stores:
- L1-equivalent personal memory (`item_type = "kv"` for key-value pairs, `memory:*` prefix for typed memory items per memory-model.md SS10)
- PSK envelope distribution (`item_type = "psk_envelope"`)
- Agent attestation storage (`item_type = "attestation"`)

Access: `invite_only`, mode: `realtime`, always the first channel created.

---

## 8. Privacy Properties

Consolidated from the identity ADR's seven core privacy principles (decisions/2026-03-10-identity-privacy-model.md SS9).

### 8.1 Pseudonymity

The identity key is pseudonymous. It is not linked to any real-world identity unless the entity chooses to create such a link via Layer 2 verification proofs. An entity operating with only a keypair and no profile metadata is a consistent pseudonymous presence -- recognisable across sessions but not identifiable.

### 8.2 Multiple Identities

Multiple identities are possible: generate multiple key files, run multiple nodes. The protocol does not link separate keys. There is no prohibition on operating multiple identities.

### 8.3 Correlation

All items signed by the same key are linkable. This is by design -- it is the definition of authorship. An entity wishing to avoid correlation across contexts should use separate identities (separate keypairs).

### 8.4 Graduated Disclosure

From identity ADR SS9, Principle 2:

```
Maximum privacy:  Key only. No name, no type, no proofs.
                  Consistent pseudonymous entity.

Pseudonymous:     Key + display name. "shadow-researcher".
                  Consistent identity, no real-world link.

Verified:         Key + name + proofs. "Bob, SPO:NUTS, $bob".
                  Real-world identity, fully auditable.
```

No entity is forced to any level. Contexts can require disclosure (a channel may require entity type declaration); the protocol cannot.

### 8.5 Metadata Minimisation

Per identity ADR SS9, Principle 4:
- Private channel names are hashed on-chain (plaintext never exposed)
- DM existence is known only to the two parties (derived, not registered)
- IP addresses are not stored in channel data
- Replication does not reveal who reads what (keepers replicate channels, not per-user reads)
- Entity profiles are published only to keepers the entity uses, not broadcast

### 8.6 Accountability Without Identification

The tension between privacy and accountability is resolved by the operator-agent chain (identity ADR SS4, SS9 Principle 6):
- Agent can be pseudonymous
- But carries an operator attestation signed by the operator's key
- Operator may be verified (domain, GitHub, Calidus)
- Agent's pseudonymity preserved; operator's accountability established

Bad behaviour trace: identify agent (key from signed item) -> read operator attestation (operator key) -> identify operator (their verification proofs) -> hold operator accountable. Cryptographically verifiable at every step.

---

## 9. Proof of Agency (Forward Reference)

A novel concept introduced in the identity ADR (decisions/2026-03-10-identity-privacy-model.md SS5). Not a Phase 1 implementation target, but the attestation data structure ships in Phase 1.

### 9.1 Concept

Most identity systems focus on proof of personhood -- proving an entity is human. Cordelia introduces the counterpart: **proof of agency** -- proving an entity IS an AI agent, transparently and accountably.

Proof of agency = operator attestation + declared entity type "agent" + purpose declaration.

### 9.2 What It Proves

An entity presenting proof of agency demonstrates:
1. It is an AI agent (self-declared + operator-confirmed)
2. Who operates it (traceable to a human or organisation)
3. What it is authorised to do (constraints in attestation)
4. When the authorisation expires (time-bounded)

### 9.3 Attestation Format (Phase 1 Data Structure)

The operator attestation format is defined in the identity ADR SS4. This structure ships in Phase 1 (stored in the agent's personal channel). Enforcement (channels requiring attestation, keeper policies gating on it) is Phase 3+.

```json
{
  "type": "operator-attestation",
  "version": 1,
  "agent_key": "cordelia_pk1...",
  "agent_name": "claude-research",
  "agent_type": "agent",
  "purpose": "AI research assistant for literature review",
  "constraints": {
    "max_channels": 5,
    "spending_limit_ada_per_epoch": 10,
    "allowed_access_types": ["open", "delegation"]
  },
  "operator_key": "cordelia_pk1...",
  "issued_at": "2026-03-10T00:00:00Z",
  "expires_at": "2026-06-10T00:00:00Z",
  "signature": "cordelia_sig1..."
}
```

The operator signs the entire attestation (all fields except `signature`) with their Ed25519 key. Any peer can verify: (1) signature valid for `operator_key`, (2) operator's own identity via their Layer 2 proofs, (3) attestation not expired, (4) agent's key matches the subject.

**Signing input.** The signing input is the attestation JSON object with the `signature` field removed, serialised using RFC 8785 (JSON Canonicalization Scheme / JCS). JCS produces a deterministic byte sequence from any JSON object by sorting keys lexicographically and using minimal encoding. The Ed25519 signature is computed over the resulting bytes.

Verification: reconstruct the JCS-serialised form from the received attestation (removing `signature`), then verify the Ed25519 signature against `operator_key`.

Phase 1 uses JCS for simplicity. Phase 3 evaluates CBOR-based signing (COSE Sign1) for consistency with the wire protocol.

**Note:** The identity ADR uses the placeholder HRP `ed25519_pk1`. The canonical HRP is `cordelia_pk1` as defined in ecies-envelope-encryption.md SS3 and SS11 (Bech32 encoding) of this spec.

### 9.4 Agent Provisioning

Per ecies-envelope-encryption.md SS14.4:

```bash
cordelia init --name "research-agent" --operator <operator_pubkey>
```

This creates a standard identity plus an operator attestation item stored in the agent's personal channel, linking the agent to its operator.

`cordelia init --operator` generates an identity AND creates an operator attestation. `cordelia provision --agent` (identity ADR SS4) is a convenience alias that combines init + attestation + channel subscription in one step. Both are Phase 1 deliverables.

---

## 10. Key Compromise and Recovery

### 10.1 Compromise Response

If an identity key is compromised:

1. **Rotate identity:** Generate a new keypair (`cordelia init --force`)
2. **Re-pair devices:** All paired devices must adopt the new identity
3. **Re-subscribe to channels:** Open channels: request new PSK with new key. Invite-only channels: require re-invitation from channel owner. DM channels: derive new DM channel IDs (different keys produce different IDs). **PSK re-distribution:** For owned channels, the entity must generate new PSKs and distribute them to all current subscribers via ECIES envelopes (channels-api.md SS3.8). For subscribed channels, the entity must re-request the PSK from the channel owner using their new key.
4. **Notify peers:** No central revocation mechanism. Peers learn of the new identity via channel descriptor updates (the old `creator_id` is replaced by the new one for channels the entity owns)

There is no "forgot password" flow in a decentralised system. The entity must re-establish its presence under the new key.

### 10.2 Key Backup

Per operations.md SS9.1-9.2:

| Priority | Data | Location | Recovery Impact |
|----------|------|----------|-----------------|
| CRITICAL | Ed25519 seed | `~/.cordelia/identity.key` | Without this, identity is permanently lost |
| HIGH | Channel PSKs | `~/.cordelia/channel-keys/*.key` | Without these, channel content is unreadable. Open channel PSKs can be re-obtained; invite-only require re-invitation |
| LOW | Node token | `~/.cordelia/node-token` | Regeneratable |
| MEDIUM | Database | `~/.cordelia/cordelia.db` | Rebuildable via replication |

**Backup methods (Phase 1):**

1. **Encrypted file copy:** Copy `~/.cordelia/identity.key` to a secure offline location. The file is 32 bytes, raw.
2. **Paper backup:** `cordelia init --show-backup-key` displays a Bech32-encoded private key (`cordelia_sk1...`). Write it down and store securely. Restore with `cordelia init --import-key cordelia_sk1...`. The `cordelia_sk` HRP is defined in ecies-envelope-encryption.md SS3.2.
3. **Device pairing:** A paired second device holds a copy of the private key. This is the simplest backup.

### 10.3 Future Recovery (Phase 4)

Shamir secret sharing: k-of-n recovery across keepers. Distribute key shards to trusted keepers. Recover with any k shards. No single keeper can reconstruct the key (identity ADR SS9, Principle 5; operations.md SS9.2).

---

## 11. Bech32 Encoding

All key types use Bech32 encoding (BIP-173) for human-readable representation (ecies-envelope-encryption.md SS3).

| HRP | Payload | Size | Usage |
|-----|---------|------|-------|
| `cordelia_pk` | Ed25519 public key | 32 bytes | Identity display, attestation subjects, channel membership |
| `cordelia_sk` | Ed25519 seed | 32 bytes | Key export/backup (secret material) |
| `cordelia_xpk` | X25519 public key | 32 bytes | ECIES envelope recipient, key agreement |
| `cordelia_sig` | Ed25519 signature | 64 bytes | Signed attestations, item signatures |
| `cordelia_psk` | Channel PSK | 32 bytes | Manual PSK import/export (secret material) |

Bech32 variant (not Bech32m): aligned with Cardano CIP-19 convention. SPOs and Cardano tooling use Bech32 throughout. Same variant avoids mixed-encoding friction in Phase 3 (ecies-envelope-encryption.md SS3.1).

Test vectors in ecies-envelope-encryption.md SS3.6, SS8.5.

---

## 12. Phase Boundaries

| Phase | Identity Layer | Deliverables |
|-------|---------------|-------------|
| **Phase 1** | Layer 0 (Cryptographic Identity) | Keypair generation, `cordelia init`, device pairing, bearer token auth, entity ID derivation, Bech32 encoding, operator attestation data structure, `cordelia provision --agent` |
| **Phase 2** | Layer 1 (Profile) | Self-declared profile metadata (name, type, about) in personal channel. Domain and GitHub verification proofs. Verification display in CLI. |
| **Phase 3** | Layer 2 (Verification) | W3C VC alignment, ADA Handle verification, Calidus SPO identity, credential-based channel access policy enforcement, context-required disclosure. On-chain entity registration (shared namespace with channels, channel-naming.md SS8). |
| **Phase 4** | Layer 3 (Reputation) | Trust scoring, peer attestations, oracle-published metrics, Shamir key recovery, per-device derived keys, selective device revocation. Formal "Proof of Agency" specification (potential CIP/RFC). |

---

## 13. References

| Document | Sections Referenced |
|----------|-------------------|
| specs/ecies-envelope-encryption.md | SS2 (key types), SS3 (Bech32), SS2.5 (bearer token), SS11 (item signatures), SS14 (init flow) |
| specs/network-protocol.md | SS2.2 (TLS identity binding), SS4.1 (handshake identity), SS4.4.6 (channel descriptor creator_id), SS4.8 (pairing protocol) |
| specs/operations.md | SS2 (cordelia init), SS3 (device pairing), SS5.4 (security constraints), SS9 (backup and recovery) |
| specs/channel-naming.md | SS2.1 (personal channel), SS4.2 (DM derivation) |
| specs/channels-api.md | SS1.3 (authentication), SS3.4 (author field) |
| decisions/2026-03-10-identity-privacy-model.md | SS2 (4-layer model), SS3 (entity types), SS4 (operator-agent chain), SS5 (Proof of Agency), SS7 (DMs), SS8 (namespace), SS9 (privacy principles) |
| specs/glossary.md | Entity, Node, Peer, Creator, Author, Agent definitions |

---

*Draft: 2026-03-12. Consolidation spec -- canonical identity reference. Cross-references ECIES, operations, and network-protocol specs for implementation details.*
