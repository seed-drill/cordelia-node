# Network Protocol Specification

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-10
**Scope**: Phase 1 (Encrypted Pub/Sub MVP)
**Implements**: WP3 (Pub/Sub API network layer), WP12 (Bootnode DNS)
**Depends on**: specs/ecies-envelope-encryption.md, specs/channels-api.md, specs/channel-naming.md

---

## 1. Overview

This specification defines the peer-to-peer network protocol for Cordelia Phase 1. It covers transport, wire format, mini-protocols, peer management, replication, routing, bootstrap, rate limiting, and security.

### 1.1 Design Principles

1. **Each node's view is bounded.** A node tracks a fixed-size peer set regardless of network size. Per-node cost is constant. (Coutts architectural insight from Cardano's Ouroboros networking.)
2. **Pull over push.** Prefer pull-based protocols with receiver-side flow control. Push only for latency-sensitive delivery (realtime channels). This prevents flooding and gives the receiver control over bandwidth.
3. **Relays are expendable.** Compromising any reachable node yields only ciphertext. Channel PSKs live on subscriber nodes, never on relays.
4. **Channels are opaque.** The P2P layer moves encrypted items by channel ID. It never decrypts, never inspects content, never evaluates semantics. Encryption is the node's local concern (ECIES spec §5).
5. **Simplify for Phase 1.** Only what's needed for MVP. Forward-compatibility notes where future phases require protocol extension.

### 1.2 Relationship to Existing Documentation

This spec consolidates and supersedes the following pre-pivot documents for Phase 1:

| Document | Disposition |
|----------|------------|
| `cordelia-core/docs/reference/protocol.md` | Superseded. Wire format, mini-protocols replaced. |
| `cordelia-core/docs/architecture/network-model.md` | Reference. Scaling analysis, TLA+ specs remain valid research. |
| `cordelia-core/docs/design/replication-routing.md` | Superseded. Three-gate model retained, terminology updated. |
| `cordelia-core/docs/architecture/threat-model.md` | Supplementary. Pre-pivot trust boundaries updated here. |
| `cordelia-core/docs/architecture/hld.md` | Supplementary. Component architecture updated by pivot. |

Pre-pivot documents remain valuable reference material. This spec is the Phase 1 authority for network behaviour.

---

## 2. Transport

### 2.1 QUIC (RFC 9000)

All peer-to-peer communication uses QUIC. One QUIC connection per peer pair.

**Why QUIC:**
- Multiplexed streams: one stream per mini-protocol instance, no head-of-line blocking
- TLS 1.3 built-in: encrypted transport without additional handshake
- Connection migration: survives network changes (laptop WiFi → mobile)
- Flow control: per-stream and per-connection, receiver-side backpressure for free

**Implementation**: `quinn` 0.11.x (Rust), backed by `rustls`.

**Firewall and NAT considerations:**

cordelia-core (pre-pivot) switched from QUIC/UDP to TCP+Noise+yamux over firewall and NAT concerns. Phase 1 returns to QUIC for the following reasons:

1. **Personal nodes make outbound connections only** (§8.1). Outbound UDP is rarely blocked by firewalls -- doing so would break DNS, HTTP/3, video conferencing, and gaming. The firewall concern applies primarily to inbound UDP, which personal nodes do not accept.
2. **Relays and bootnodes have public IPs** (§8.2, §8.3). No NAT, no firewall restrictions on listening ports.
3. **30-second keep-alive (§4.2) solves NAT mapping expiry.** UDP NAT mappings typically expire after 30-120 seconds. Our keep-alive interval (30s) refreshes mappings before expiry.
4. **QUIC adoption is now ubiquitous.** HTTP/3 (QUIC-based) is supported by all major browsers, CDNs, and cloud providers. Network infrastructure has adapted.

**Accepted risk:** Some restrictive corporate networks may block all UDP. Personal nodes in such environments will be unable to connect to peers. **Phase 2 mitigation:** TCP+TLS fallback transport (quinn supports both QUIC and TCP). If real-world deployments surface UDP blocking, add TCP as a secondary transport with automatic fallback. The mini-protocol layer (§3, §4) is transport-agnostic -- CBOR-framed messages work identically over QUIC streams or TCP connections.

**Ports:**
- P2P listen: `9474/UDP` (configurable)
- Local API: `9473/TCP` (HTTP, localhost only -- not part of this spec, see channels-api.md)

### 2.2 TLS 1.3 Identity Binding

QUIC mandates TLS 1.3. Cordelia binds TLS certificates to Ed25519 node identities:

1. Each node generates an Ed25519 keypair at `cordelia init` (see ECIES spec §2)
2. The node derives a self-signed X.509 certificate where:
   - Subject Common Name = Bech32-encoded public key (`cordelia_pk1...`)
   - Certificate key = Ed25519 public key (RFC 8410, OID 1.3.101.112)
   - Validity: 1 year, auto-renewed on startup
3. Quinn's `ServerConfig` and `ClientConfig` use a custom certificate verifier that:
   - Accepts self-signed certificates (no CA chain required)
   - Extracts the Ed25519 public key from the certificate
   - Stores it as the peer's verified `node_id`

This binds the TLS session to a specific Ed25519 identity. The peer's `node_id` is authenticated by TLS -- no separate proof of possession needed in the application-layer handshake.

**Security property:** An attacker who does not hold the Ed25519 private key cannot establish a QUIC connection that claims the corresponding `node_id`. TLS 1.3's signature-based authentication proves key possession during the TLS handshake.

**Implementation notes (rustls 0.23 / quinn 0.11):**
- rustls 0.23 requires an explicit `CryptoProvider`. Use `builder_with_provider(Arc::new(ring::default_provider()))` instead of `builder()`. The latter panics if no global provider is installed.
- Custom verifiers (`ServerCertVerifier`, `ClientCertVerifier`) must cache `signature_verification_algorithms` (e.g., via `OnceLock`) to avoid re-instantiating the provider on each TLS callback.
- `ClientCertVerifier::client_auth_mandatory()` must return `true` (both sides present certificates).
- `rcgen` 0.13 generates self-signed Ed25519 certs from PKCS#8 DER. Raw 32-byte seeds must be wrapped in PKCS#8 v1 DER (48 bytes) before passing to `KeyPair::from_pkcs8_der_and_sign_algo()`.
- `x509-parser` 0.16 extracts the Subject CN via `parsed.subject().iter_common_name()`.

### 2.3 Connection Lifecycle

```
Initiator                                    Responder
    |                                            |
    |--- QUIC ClientHello (TLS 1.3) ----------->|
    |<-- QUIC ServerHello + Certificate ---------|
    |--- TLS Finished -------------------------->|
    |                                            |
    |  [QUIC connection established]             |
    |  [Both sides know peer's Ed25519 pubkey]   |
    |                                            |
    |--- First bidi stream: Handshake Propose -->|
    |<-- First bidi stream: Handshake Accept ---|
    |                                            |
    |  [Channel intersection computed]           |
    |  [Peer added to governor peer table]       |
    |                                            |
    |--- Stream N: Keep-Alive, Sync, Push ------>|
```

**Stream ownership:** The initiator opens the first bidirectional stream (`open_bi()`), writes the protocol byte and `HandshakePropose`. The responder accepts the stream (`accept_bi()`), reads the protocol byte, and dispatches. For quinn, `open_bi()` returns split `(SendStream, RecvStream)`; use `tokio::io::join(&mut recv, &mut send)` to combine into a single bidirectional `AsyncRead + AsyncWrite` stream for the handshake functions. The responder's `accept_bi()` MUST run concurrently with the initiator's `open_bi().await` (e.g., via `tokio::spawn`), otherwise mutual TLS with client certs will deadlock.

**Transport parameters:** The QUIC transport MUST configure:
- `keep_alive_interval = 15s` -- sends QUIC PING frames to prevent idle disconnection. This is independent of the application-level Keep-Alive protocol (§4.2).
- `max_idle_timeout = 60s` -- connections with no traffic (including PING) for this duration are closed.

These parameters apply to both client and server transport configs on the quinn endpoint.

**Incoming connection accept:** The `incoming.await` call (QUIC/TLS handshake for inbound connections) MUST have a 10-second timeout. Without this, a stalled handshake blocks the accept loop and prevents ALL other protocol operations on the node. (See BV-23.)

**Endpoint shutdown lifecycle:** On SIGTERM or graceful shutdown, the node MUST:
1. Call `endpoint.close()` to send CONNECTION_CLOSE to all peers
2. Call `endpoint.wait_idle()` to drain in-flight streams and release the UDP socket
3. Only then exit the process

Without `wait_idle()`, the UDP socket may not be released before the OS recycles the port. The next process on the same IP:port may receive stale QUIC packets from peers that haven't processed the CONNECTION_CLOSE yet, causing `open_bi()` hangs (MAX_STREAMS not granted on confused connection state).

Docker containers SHOULD set `stop_grace_period: 30s` to allow time for `wait_idle()`.

**Host kernel tuning for QUIC/UDP:** Production and test hosts running QUIC nodes MUST apply:
```
net.core.rmem_max = 7500000          # UDP receive buffer (default 212992 too small)
net.core.wmem_max = 7500000          # UDP send buffer
net.core.rmem_default = 1048576      # Default per-socket receive buffer
net.core.wmem_default = 1048576      # Default per-socket send buffer
```
Without enlarged buffers, UDP packets are silently dropped under load, causing intermittent QUIC connection failures.

---

## 3. Wire Format

### 3.1 Message Framing

Each QUIC stream carries one mini-protocol instance. Messages on a stream are framed as:

```
┌──────────────────┬──────────────────────────────┐
│  Length (4 bytes) │  Payload (Length bytes)       │
│  big-endian u32   │  CBOR-encoded message         │
└──────────────────┴──────────────────────────────┘
```

Maximum message size: 1 MB (`max_message_bytes`). Messages exceeding this are rejected and the stream is reset.

### 3.2 CBOR Encoding (RFC 8949)

All wire messages use CBOR (Concise Binary Object Representation) with deterministic encoding (RFC 8949 §4.2.1).

**Why CBOR over JSON:**
- Consistent with signed payload encoding (ECIES spec §11)
- Smaller attack surface than JSON parsing (no string escaping, no Unicode edge cases)
- More compact on the wire (~30% smaller for typical messages)
- Schema-friendly: CDDL (RFC 8610) can define message schemas
- Forward-compatible: unknown fields are preserved, not rejected

**Deterministic encoding rules:**
- Map keys in lexicographic order of their encoded form
- Integers use minimal-length encoding
- No indefinite-length items

**Timestamp encoding:**
- Performance-critical timestamps (handshake `timestamp`, keep-alive `sent_at_ns`) use CBOR unsigned integers (u64 seconds / u64 nanoseconds).
- Application-layer timestamps (`published_at`, `created_at`, listen `since` cursor) use CBOR text strings (major type 3) containing ISO 8601 values (e.g., `"2026-03-10T14:30:00Z"`). CBOR **tag 0** (RFC 8949 §3.4.1) wrapping is RECOMMENDED but not required for Phase 1. Tag 0 adds self-description for generic CBOR decoders; omitting it has no impact when both sides know the field is a timestamp. Phase 2 SHOULD add tag 0 for Cardano CDDL alignment.

**Implementation**: `ciborium` (Rust). Note: `ciborium` with serde derive emits plain text strings (major type 3) for `String` fields; adding tag 0 requires a custom serde wrapper or explicit `ciborium::Value::Tag(0, ...)` construction.

**Forward-compatibility rules:** Unknown fields within a known message type MUST be logged at DEBUG level and ignored (forward-compatible). Unknown message types (unknown protocol byte or unknown serde variant) MUST be rejected at the dispatch layer -- stream reset for unknown protocol byte (application error `0x02`), decode error for unknown variant. New capabilities are added as new protocol bytes (§3.3), not as new variants within existing protocol message sets. The handshake version negotiation (§4.1.4) ensures both sides speak the same protocol version.

**Cross-language implementation notes:**
- `cbor-x` (TypeScript) encodes `Uint8Array` with CBOR tag 64 (typed byte array). Use `Buffer.from()` instead for spec-compliant CBOR byte strings (major type 2).
- `ciborium` (Rust) with `#[serde(with = "serde_bytes")]` produces correct CBOR byte strings (major type 2).
- Bech32 encoding (BIP-173): use plain Bech32, NOT Bech32m (BIP-350). The checksum algorithms differ. See ECIES spec §3.5.

### 3.3 Protocol Byte

The first byte of each new QUIC stream identifies the mini-protocol:

| Byte | Protocol | Direction | §Reference |
|------|----------|-----------|-----------|
| `0x01` | Handshake | Bidirectional (one round-trip) | §4.1 |
| `0x02` | Keep-Alive | Bidirectional (ongoing) | §4.2 |
| `0x03` | Peer-Sharing | Request-Response | §4.3 |
| `0x04` | Channel-Announce | Push with reconciliation | §4.4 |
| `0x05` | Item-Sync | Request-Response (pull) | §4.5 |
| `0x06` | Item-Push | Sender-initiated (push) | §4.6 |
| `0x07` | PSK-Exchange | Request-Response | §4.7 |
| `0x08` | Pairing | Request-Response | §4.8 |

Stream lifecycle: the initiator opens a bidirectional QUIC stream, writes the protocol byte, then the first message. The responder reads the protocol byte to determine the handler. Unknown protocol bytes (0x09+) cause the stream to be reset with application error code `0x02` (unknown protocol).

---

## 4. Mini-Protocols

### 4.1 Handshake (0x01)

One round-trip on the first bidirectional stream opened after QUIC connection establishment. Both sides must complete the handshake before any other protocol stream is opened.

#### 4.1.1 Messages

```
HandshakePropose {
    magic:           u32         // 0xC0DE11A1
    version_min:     u16         // Minimum protocol version supported
    version_max:     u16         // Maximum protocol version supported
    node_id:         bytes(32)   // Ed25519 public key (verified by TLS)
    timestamp:       u64         // Unix timestamp (seconds)
    channel_digest:  bytes(32)   // SHA-256 of sorted channel ID list
    channel_count:   u16         // Number of channels subscribed
    roles:           [string]    // Node roles: ["personal"], ["bootnode"], ["relay"], ["keeper"]
}

HandshakeAccept {
    version:         u16         // Negotiated version (0 = rejected)
    node_id:         bytes(32)   // Responder's Ed25519 public key
    timestamp:       u64         // Unix timestamp (seconds)
    channel_digest:  bytes(32)   // SHA-256 of sorted channel ID list
    channel_count:   u16         // Number of channels subscribed
    roles:           [string]    // Responder's roles
    reject_reason:   ?string     // Present only if version == 0
}
```

#### 4.1.2 Handshake Design: Privacy-First

**Key change from pre-pivot:** The handshake no longer includes the full channel list. Instead, it sends a `channel_digest` (SHA-256 of the sorted list of channel IDs). This reveals channel count but not channel identities.

Channel intersection is computed lazily via the Channel-Announce protocol (§4.4) after the handshake completes. This prevents a connecting peer from learning the full channel membership in a single message.

**Rationale:** In the pre-pivot design, `HandshakePropose` included `groups: Vec<GroupId>`. A Sybil attacker connecting to multiple nodes could build a complete membership graph of the network. With `channel_digest`, the attacker learns only that a change occurred (different digest), not what channels exist.

#### 4.1.3 Handshake Validation

The responder MUST reject the handshake if:
- `magic != 0xC0DE11A1` (reject reason: "invalid magic")
- Handshake not received within 10 seconds of QUIC connection establishment (close connection)

#### 4.1.4 Version Negotiation

Phase 1 defines protocol version `1`. The version range allows future protocol evolution without breaking changes:

- If `version_min <= peer_version_max` AND `version_max >= peer_version_min`: negotiate the highest common version
- Otherwise: reject with `version: 0` and `reject_reason: "incompatible version range"`

#### 4.1.5 Timestamp Validation

Reject handshakes where `|local_time - peer_time| > 300s` (5-minute clock skew tolerance). This prevents replay of captured handshakes (in addition to TLS 1.3's own replay protection). Reject with `reject_reason: "clock skew"`. The reject message MUST NOT include the responder's local time or the computed delta (information disclosure -- reveals the responder's clock to the peer).

Note: Handshake `timestamp` uses seconds (u64). Keep-Alive `sent_at_ns` (§4.2) uses nanoseconds for RTT precision. Different granularity is intentional.

#### 4.1.6 Identity Verification

The `node_id` in the handshake MUST match the Ed25519 public key extracted from the peer's TLS certificate (§2.2). If they differ, reject with `reject_reason: "identity mismatch"`. This is a defence-in-depth check -- TLS already authenticates the key, but verifying at the application layer catches implementation bugs.

### 4.2 Keep-Alive (0x02)

Bidirectional on a long-lived stream. 30-second interval.

```
Ping { seq: u64, sent_at_ns: u64 }
Pong { seq: u64, sent_at_ns: u64, recv_at_ns: u64 }
```

**Dead detection:** 3 missed pings (90s) → peer demoted (Hot→Warm or Warm→Cold).

**RTT measurement:** `rtt_ms = (local_now_ns - sent_at_ns) / 1_000_000`. Stored in governor's `PeerInfo` for scoring.

**Monotonic sequence:** `seq` must be strictly increasing. Out-of-order or duplicate `seq` values are logged and ignored (no ban -- clock issues are common).

### 4.3 Peer-Sharing (0x03)

Request-response. Initiated periodically (every 5 minutes) to 2-3 random warm/hot peers.

```
PeerShareRequest {
    max_peers: u16       // Maximum peers to return (default: 20)
}

PeerShareResponse {
    peers: [PeerAddress]
}

PeerAddress {
    node_id:    bytes(32)       // Ed25519 public key
    addrs:      [string]        // IP:port pairs as "addr:port" strings (CBOR text, parsed to SocketAddr on receive)
    last_seen:  u64             // Unix timestamp
    exclude:    bool            // true = reporting node has banned this peer for defection (§16.1.2)
}
```

**Key change from pre-pivot:** `PeerAddress` no longer includes `groups: Vec<GroupId>`. Channel membership is private information, not gossiped. Peer-sharing provides connectivity (addresses), not membership intelligence.

**Rationale:** In the pre-pivot design, gossiping group lists let any node map the full network's channel membership. Removing channel lists from peer-sharing closes this metadata leak. Peers discover shared channels via Channel-Announce (§4.4), which is point-to-point, not broadcast.

**Peer selection for sharing:** Prefer peers with:
1. Recent activity (last_seen within 1 hour)
2. Diverse IP subnets (avoid returning peers on the same /24)
3. Exclude banned peers

**Address filtering on share:** The node MUST only share addresses of relay and bootnode peers. Personal node addresses are never shared (§8.2: personal nodes are outbound-only and should not receive unsolicited inbound connections).

**Address validation on receive:** Before adding received addresses to the cold peer table, the node MUST filter out:
- RFC 1918 private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Loopback (127.0.0.0/8, ::1)
- Link-local (169.254.0.0/16, fe80::/10)
- The node's own listen address
- Addresses with port 0

Outbound connections to peer-shared addresses SHOULD be rate-limited to 1/second to prevent being used as a connection amplifier against third-party services.

### 4.4 Channel-Announce (0x04)

Event-driven announcements with periodic reconciliation. This replaces the pre-pivot GroupExchange protocol.

**Purpose:** Channel-Announce serves channel membership discovery between peers and governor scoring (§5.5). When a relay receives ChannelJoined/ChannelLeft from a hot peer, it tracks channel interest for metrics, relay affinity scoring, and future optimisation. Channel-Announce is **informational** -- it is NOT used for push routing decisions. Relay re-push targets all hot relay peers (broadcast, §7.2); personal nodes and keepers receive items via pull-sync (§4.5).

**Relay participation:** Relays are **receive-only** for Channel-Announce. They listen to peers' announcements but do NOT send `ChannelJoined` for channels they carry. This prevents metadata amplification across the relay mesh.

**Stream direction:** QUIC connections support bidirectional stream creation. Either side (initiator or responder) can open new streams at any time. This is critical for secret keeper connectivity (§8.5): the keeper initiates the connection to its relay, but the relay opens streams to push items back to the keeper.

#### 4.4.1 Design: Push IDs, Pull Delta

Inspired by Cardano's tx-submission mini-protocol: the sender pushes lightweight identifiers, the receiver decides what to fetch. The receiver controls bandwidth.

Five message types on a long-lived bidirectional stream:

```
// Sender pushes when joining a new channel (includes full descriptor)
ChannelJoined {
    channel_id:   string            // Channel ID (hex SHA-256, dm_..., or grp_...)
    descriptor:   ChannelDescriptor // Full signed descriptor (§4.4.6)
}

// Sender pushes when leaving a channel (§4.4.4)
ChannelLeft {
    channel_id: string      // Channel ID being left
}

// Periodic reconciliation (every 5 minutes)
ChannelStateHash {
    digest: bytes(32)       // SHA-256 of sorted channel ID list (see below)
    count:  u16             // Number of channels
}

// Digest computation (deterministic, same as handshake channel_digest):
//   1. Collect all subscribed channel IDs as UTF-8 strings
//   2. Sort lexicographically (byte-order, ASCII/UTF-8 safe)
//   3. Join with newline (\n) separator
//   4. SHA-256 the resulting byte string

// Receiver requests full list on digest mismatch
ChannelListRequest {}

// Response includes full descriptors (not just IDs)
ChannelListResponse {
    channels: [ChannelDescriptor]   // Full signed descriptors for all shared channels
}
```

#### 4.4.2 Protocol Flow

**Event-driven (immediate):**
```
Node A joins channel "research" (channel_id = SHA-256("cordelia:channel:research"))

A -> B: ChannelJoined { channel_id: "a1b2c3..." }
B updates intersection(A) locally. No response needed.
```

**Periodic reconciliation (every 5 minutes, initiated by both sides independently, staggered):**

Each side of a Channel-Announce stream sends `ChannelStateHash` on its own 5-minute timer. Timers are offset by the peer's role in the connection: the connection initiator sends at 0:00, 5:00, 10:00...; the responder sends at 2:30, 7:30, 12:30... (150-second offset). This avoids simultaneous full-list exchanges.
```
A -> B: ChannelStateHash { digest: 0xabc..., count: 7 }
B computes: does digest match what B expects for A?

If match:  no action (common case)
If mismatch:
    B -> A: ChannelListRequest {}
    A -> B: ChannelListResponse { channels: [ChannelDescriptor, ...] }
    B recomputes intersection(A)
```

**Digest computation** (same algorithm as handshake `channel_digest`):

The digest is computed identically to §4.4.1: collect all subscribed channel IDs as UTF-8 strings, sort lexicographically, join with newline (`\n`) separator, SHA-256 the resulting byte string. One canonical algorithm, used in both the handshake and reconciliation.

The `count` field is the number of channels in the set (allows quick mismatch detection before comparing the 32-byte digest).

**Reconciliation is immediate on first mismatch.** There is no retry or backoff -- a single digest mismatch triggers a full list exchange. This is acceptable because:
1. Mismatches are rare (only on actual channel changes between reconciliation intervals)
2. The full list is bounded by subscribed channels (~100 descriptors, ~10-20 KB)
3. The tenure guard (§4.4.5) prevents abuse by newly-connected peers

#### 4.4.3 Bandwidth Analysis

**Pre-pivot (GroupExchange every 60s):**
- 5 hot peers × 10 channels × 64 bytes/ID × every 60s = 53 bytes/s per node
- Plus: full channel list exposed to all peers every minute

**Phase 1 (Channel-Announce):**
- Steady state: 5 hot peers × 32-byte digest × every 300s = 0.5 bytes/s per node (106x reduction)
- Join event: 1 message × 64 bytes × 5 peers = 320 bytes total (one-time)
- Mismatch recovery: rare, only on actual channel changes

#### 4.4.4 ChannelLeft Semantics

Nodes MUST send `ChannelLeft` when unsubscribing. This allows immediate intersection update. Without it, peers continue pushing items to the unsubscribed node until the next reconciliation (up to 5 minutes), wasting bandwidth.

On node restart, all locally subscribed channels MUST be re-announced via `ChannelJoined` within 30 seconds. Items received for channels not in `node_subscribed_channels` are silently dropped at Gate 3 (§7.1).

#### 4.4.5 Privacy Properties

- `ChannelStateHash` reveals channel count and whether the set changed, but not which channels
- `ChannelJoined` / `ChannelLeft` reveal a single channel ID, only to existing hot peers (already trusted for replication)
- `ChannelListResponse` reveals the full list, but only when (a) digests mismatch AND (b) the requesting peer has been in Hot or Warm state for at least `min_warm_tenure` (300s, §5.4). Peers below this tenure receive an empty response. This prevents a newly-connected Sybil attacker from sending a spoofed digest to extract the full channel list.
- Channel lists are never gossiped to third parties (unlike pre-pivot PeerShareResponse)

**Accepted limitation:** A peer that maintains Hot status for 5+ minutes (by behaving well) can eventually learn the full channel list via digest manipulation. This is accepted because: (a) the peer is already trusted enough for item replication at that point, (b) it could learn channel membership by observing pushed items over time anyway, and (c) the min tenure makes mass reconnaissance via Sybil impractical (each identity requires 5+ minutes of good behaviour).

**Free-rider risk:** A non-relay peer can send `ChannelJoined` for channels it doesn't actually subscribe to (the descriptor is signed by the creator, not the sender). This causes the receiver to push items to the free-rider, who collects metadata (author_id, timestamps, blob sizes) without contributing. In Phase 1 this is accepted -- the governor's scoring mechanism (§5.5) detects free-riders (low `items_delivered` → demotion → eventual eviction). Phase 2 should add proof-of-membership for non-relay peers: `HMAC-SHA256(psk, "membership:" || node_id || channel_id)` included in `ChannelJoined`, verifiable by any PSK holder.

#### 4.4.6 Channel Descriptor

A channel descriptor is the metadata record for a channel. It is created by the channel creator, signed, and replicated via Channel-Announce messages.

```
ChannelDescriptor {
    channel_id:     string        // Channel ID (hex SHA-256, dm_..., or grp_...)
    channel_name:   ?string       // Human-readable name (null for DMs and groups)
    access:         string        // "open" | "invite_only"
    mode:           string        // "realtime" | "batch"
    key_version:    u32           // Current PSK version (incremented on rotation)
    psk_hash:       bytes(32)     // SHA-256(current PSK) -- allows subscribers to verify PSK authenticity
    creator_id:     bytes(32)     // Creator's Ed25519 public key
    created_at:     string        // ISO 8601 timestamp
    signature:      bytes(64)     // Ed25519 signature over CBOR-encoded descriptor (all fields except signature)
}
```

**Signed payload** (CBOR deterministic encoding, per ECIES spec §11.4):

The signature covers all fields except `signature` itself. CBOR map keys are sorted by **encoded byte length first, then lexicographic** per RFC 8949 §4.2.1 (not simple alphabetical). The canonical key order for Phase 1 fields is: `mode`, `access`, `psk_hash`, `channel_id`, `created_at`, `creator_id`, `key_version`, `channel_name`. See TV-C2 in ECIES spec §8.6 for the verified CBOR encoding.

**Implementation note:** For Phase 1 fields, alphabetical sorting (e.g., Rust `BTreeMap`) and RFC 8949 encoded-byte-length sorting produce identical results. This is coincidental -- all Phase 1 field names are ASCII with no shared length prefixes. If new descriptor fields are added in future phases, use explicit key ordering rather than BTreeMap to avoid subtle signing mismatches between implementations.

**PSK authenticity:** The `psk_hash` field binds the PSK to the signed descriptor. After receiving a PSK via PSK-Exchange (§4.7), the subscriber MUST verify `SHA-256(received_psk) == descriptor.psk_hash`. On mismatch: discard the PSK, ban the responding peer (identity mismatch severity, §5.6), and retry with a different peer. This prevents a malicious subscriber from distributing a fake PSK for an open channel.

**Security property:** The `psk_hash` is a one-way hash, safe to include in the plaintext descriptor. Relays see the hash but cannot reverse it to obtain the PSK (SHA-256 preimage resistance, 256-bit security). The hash does allow offline verification of whether a candidate PSK matches a channel, but the PSK is 32 bytes of CSPRNG output -- brute force is infeasible.

**Descriptor distribution:**

Descriptors piggyback on Channel-Announce messages (§4.4.1). `ChannelJoined` carries the full descriptor; `ChannelListResponse` carries an array of descriptors. Message definitions are in §4.4.1.

When a node receives a descriptor, it:
1. Verifies the `signature` against `creator_id` and the CBOR-encoded fields
2. Stores the descriptor locally (keyed by `channel_id`)
3. If `key_version` is higher than the stored version, updates the stored descriptor

**Descriptor updates:** When a channel's PSK is rotated (member removal, ECIES spec §6.4), the owner increments `key_version`, updates `psk_hash` to `SHA-256(new_psk)`, re-signs the descriptor, and sends a new `ChannelJoined` to all hot peers. Receivers update their stored descriptor if the new `key_version` is strictly higher and the `creator_id` matches.

**Conflict resolution:** Once a node stores a descriptor for a channel_id, it rejects descriptors from a different `creator_id` (first-seen creator wins). All received descriptors MUST have their signature verified before any storage decision. Invalid signatures are rejected and the sending peer's ban severity is escalated. For the same `channel_id`, if a descriptor arrives from a different `creator_id`, it is silently dropped and a WARNING is logged with both `creator_id` values. The sending peer is NOT banned (legitimate network partition scenario). Phase 3 on-chain registration resolves creator disputes.

**PSK discovery:** When a subscriber needs a PSK for an open channel, they identify PSK holders from their Channel-Announce data (peers that share the channel). Any existing subscriber can respond to PSKRequest (§4.7) for open channels. In Phase 2+, the descriptor gains an `anchor_keeper` field (Ed25519 key of the designated keeper node).

**Field size limits:**
- `channel_name`: max 63 characters (aligned with RFC 1035 label limit for named channels, same limit for group labels)
- `access`: enum, max 11 characters
- `mode`: enum, max 8 characters
- Total serialized descriptor: max 512 bytes (CBOR-encoded, before signature). Reject oversized descriptors on receive.

**Phase 1 simplification:** No `anchor_keeper` field. PSK distribution is peer-to-peer -- any subscriber holding the PSK can distribute it to new subscribers of open channels. The creator's node is the initial PSK holder; as more nodes subscribe, PSK availability increases organically.

### 4.5 Item-Sync (0x05)

Pull-based anti-entropy. Each node periodically syncs with a random hot peer per channel. The receiver controls what it fetches.

```
SyncRequest {
    channel_id: string          // Channel to sync
    since:      ?string         // ISO 8601 cursor (items newer than this)
    limit:      u32             // Max headers to return (default: 100)
}

SyncResponse {
    items:    [ItemHeader]      // Headers of items the responder has
    has_more: bool              // More items available beyond limit
}

ItemHeader {
    item_id:      string        // Unique item identifier
    channel_id:   string        // Channel this item belongs to
    item_type:    string        // Content type (e.g., "message", "event", "state")
    content_hash: bytes(32)     // SHA-256 of encrypted payload
    author_id:    bytes(32)     // Author's Ed25519 public key (raw, not Bech32)
    signature:    bytes(64)     // Ed25519 signature over metadata envelope (ECIES spec §11)
    key_version:  u32           // PSK version used for encryption
    published_at: string        // ISO 8601 timestamp
    is_tombstone: bool          // True if this is a deletion marker
    parent_id:    ?string       // Parent item ID (threading, replies)
}

Note: `author_id` is raw bytes(32) on the wire for compactness. The signed metadata envelope (ECIES spec §11.7) uses the same raw bytes in CBOR encoding. Bech32 encoding (`cordelia_pk1...`) is used only in the REST API and SDK (human-readable contexts). The signed metadata envelope covers: `author_id`, `channel_id`, `content_hash`, `is_tombstone`, `item_id`, `key_version`, `published_at`. Both `is_tombstone` and `key_version` MUST be signed -- without them, a malicious relay could forge deletions or cause targeted decryption failures by manipulating the PSK version.
```

**Sync flow:**

Phase 0 (relay channel discovery): Before per-channel sync, relay nodes send a `SyncChannelListRequest` to learn which channels the peer has items for. The responder returns `SyncChannelListResponse` with its stored channel IDs. The initiator merges these into its `relay_learned_channels` set for this and future sync cycles. This solves the bootstrap problem: a relay with 0 items can discover channels from its peers, then sync items for those channels.

```
SyncChannelListRequest {}           // "What channels do you have?"

SyncChannelListResponse {
    channel_ids: [string]           // Channels the responder has stored items for
}
```

Phase 0 runs on every relay sync cycle, on the same stream before per-channel SyncRequests. Personal nodes skip Phase 0 (they know their subscribed channels). The overhead is one extra round-trip per peer per cycle -- acceptable given it also serves as a liveness signal.

Phase 1-4 (per-channel sync, unchanged):
1. Initiator sends `SyncRequest` for a channel, with cursor from last successful sync
2. Responder returns `SyncResponse` with item headers since the cursor
3. Initiator compares headers to local storage:
   - Unknown item_id → queue for fetch
   - Known item_id, different content_hash → compare `published_at`, keep latest (LWW)
   - Known item_id, same content_hash → skip (already have it)
   - is_tombstone → mark local item as deleted
4. Initiator fetches missing items via Item-Fetch (piggybacked on sync stream)

**Item-Fetch (on same stream, after SyncResponse):**

```
FetchRequest {
    item_ids: [string]          // Items to fetch (max 100)
}

FetchResponse {
    items: [Item]
}

Item {
    item_id:        string
    channel_id:     string
    item_type:      string      // Content type
    encrypted_blob: bytes       // Opaque ciphertext (AES-256-GCM, ECIES spec §5)
    content_hash:   bytes(32)   // SHA-256 of encrypted_blob
    content_length: u32         // Length of encrypted_blob in bytes
    author_id:      bytes(32)   // Ed25519 public key (raw)
    signature:      bytes(64)   // Ed25519 signature (ECIES spec §11)
    key_version:    u32         // PSK version
    published_at:   string      // ISO 8601
    is_tombstone:   bool
    parent_id:      ?string     // Parent item ID (threading)
}
```

**Sync intervals by channel delivery mode:**

| Mode | SDK name | Sync interval | Push on write? |
|------|----------|---------------|----------------|
| Realtime | `realtime` | 10s (primary delivery for personal/keeper) | Yes (to hot relays only) |
| Batch | `batch` | 900s (15 min) | No |

**Pull-sync is the primary delivery mechanism for personal nodes and secret keepers.** Relays push items to other relays (single-hop, §7.2), but personal nodes and keepers receive items exclusively via pull-sync. This makes personal nodes responsible for fetching what they need, eliminates relay-side routing state, and bounds relay complexity to store-and-forward.

**Sync targets: Hot peers only (§5.1, §5.4.2).** Item-Sync runs exclusively on Hot peers. Warm peers maintain connections for keepalive and peer-sharing but do NOT participate in data exchange. Bootnode peers (§8.2) are never sync targets -- they do not store or replicate items.

**Peer selection for pull-sync:** The node MUST sync from all **hot** peers each cycle (governor state = Hot, §5). Each peer sync is independent and MAY run concurrently (separate tasks). This ensures O(hot_max) sync cost per cycle, bounded by the governor's hot peer set regardless of total network size.

**Channel source for pull-sync:** Personal nodes sync their subscribed channels (`list_for_entity`). Relay nodes sync `relay_learned_channels`: the union of channels they have stored items for (`SELECT DISTINCT channel_id FROM items`) and channels discovered from peers via Phase 0 channel discovery (`SyncChannelListResponse`). This breaks the bootstrap dependency: a relay with 0 items discovers channels from peers, then syncs items for those channels. The `relay_learned_channels` set is maintained in memory and rebuilt each sync cycle from stored items + peer responses.

The governor (§5) manages which peers are hot:
- Peers that deliver items the node didn't have are scored higher (§5.5)
- High-scoring peers are promoted to Hot (§5.4 step 4)
- Stale peers (no new items for 30 min) are demoted Hot→Warm (§5.4 step 5)
- Bootnode peers (§8.2) are never sync targets

**Convergence time bound:** After a network partition heals, convergence requires:

**Bootstrap (hot_count < hot_min):**
```
T_bootstrap = T_idle_timeout + T_tick + T_sync_interval + T_margin
            = 60s + 10s + 10s + ~5s ≈ 85s
```

Reconnecting peers are promoted to Hot immediately (§5.4.1 bypass).

**Steady state (hot_count >= hot_min):**
```
T_steady = T_idle_timeout + T_tick + T_warm_tenure + T_sync_interval + T_margin
         = 60s + 10s + 300s + 10s + ~10s ≈ 390s
```

Reconnecting peers must survive `min_warm_tenure_secs` (300s) before Hot promotion. This is the anti-eclipse cost: slower convergence in exchange for Sybil resistance.

Where:
- `max_idle_timeout` (60s): zombie QUIC connections must expire before reconnection
- `T_tick` (10s): governor tick discovers new peers via peer-sharing
- `min_warm_tenure` (300s): anti-eclipse tenure guard (steady state only)
- `sync_interval` (10s): one full pull-sync cycle covering all hot peers
- `margin`: network/scheduling jitter

Both bounds are **independent of network size N**. For relay chains of depth D, each hop adds at most `sync_interval` to convergence. This is O(D), not O(N).

**Phase 1 networks (<20 peers):** Personal nodes keep at most 2 hot peers (`hot_max=2`); relays keep up to 50. The relay backbone handles fan-out. `min_warm_tenure` only matters after churn or partition heal when a reconnecting peer must re-earn Hot status.

**Phase 2+ optimisation:** For large networks (100+ peers), sync-from-all becomes expensive. Consider prioritised sync (prefer peers with highest clock skew) or bloom filter-based set reconciliation to reduce per-cycle cost while maintaining O(1) convergence.

### 4.6 Item-Push (0x06)

Unsolicited item delivery for realtime channels. Sender opens a new stream, writes items, receiver acknowledges.

```
// Sender writes:
PushPayload {
    items: [Item]               // Same Item type as FetchResponse
}

// Receiver replies:
PushAck {
    stored:              u32    // Items successfully stored
    dedup_dropped:       u32    // Items dropped as duplicates (same item_id + content_hash)
    policy_rejected:     u32    // Items rejected by access policy or rate limit
    verification_failed: u32    // Items rejected due to invalid signature or content_hash mismatch
}
```

**When Item-Push fires:**
- On local write to a realtime channel: push to hot relay peers only. The originator (personal node or keeper) pushes to its hot relays; relays handle distribution. Non-relay peers receive items via Item-Sync pull (§4.5). Respects `push_policy` (§8.1.1).
- Relay re-push (single-hop): if a relay stores an item received from a **non-relay** peer (`stored > 0`), it re-pushes to all **hot relay peers** except the sender. Items received from other relays are stored but NOT re-pushed (single-hop, no cascade). Bootnodes (§8.2) do NOT re-push -- they are discovery-only.
- Bootnode nodes never initiate or relay Item-Push. They participate only in Handshake, Peer-Sharing, and Keep-Alive.
- Personal nodes and secret keepers receive items exclusively via Item-Sync pull (§4.5), not via relay push. This eliminates relay-side routing state and Channel-Announce dependency for push routing.

**Single-hop relay push:** Only the relay that receives an item from its originator (personal node or keeper) re-pushes to the relay mesh. Intermediate relays that receive via re-push store the item but do NOT re-push. This bounds amplification to O(R) per item (one push per relay), not O(R²). Pull-sync (§4.5) is the safety net for any items missed during re-push.

**Loop prevention:** Single-hop re-push eliminates cascading by design. Additionally, duplicate items (same `content_hash` + `item_id` already stored) yield `stored: 0`, preventing re-push even if the single-hop check were bypassed.

**Re-push item filtering:** The relay MUST only queue items that were **newly stored** (`store_item` returned true) for re-push. Items that were deduplicated or already present MUST NOT be queued, even if other items in the same batch were new.

**Signature verification:** Before storing a pushed item, the receiver MUST verify the `signature` against the `author_id` and metadata envelope (ECIES spec §11.7). Reject items with invalid signatures.

### 4.7 PSK-Exchange (0x07)

Request-response for channel PSK distribution. Used when a subscriber needs the PSK for an open or gated channel from another node that holds it.

```
PSKRequest {
    channel_id:      string        // Channel to subscribe to
    subscriber_xpk:  bytes(32)     // Subscriber's X25519 public key (for ECIES envelope)
}

PSKResponse {
    status:          string        // "ok" | "denied"
    reason:          ?string       // Present only if status == "denied": "not_found" | "not_authorized" | "not_available"
    ecies_envelope:  ?bytes(92)    // ECIES-encrypted PSK (ECIES spec §4), present only if status == "ok"
    key_version:     ?u32          // Current PSK version
}

// Rejection reason codes:
//   "not_found"      - channel unknown to this node
//   "not_authorized" - access policy denied (invite-only, gated condition failed)
//   "not_available"  - PSK not held locally (relay nodes, nodes that haven't received PSK yet)

```

**Protocol flow:**

1. Subscriber sends `PSKRequest` with their X25519 public key
2. Holder evaluates access policy:
   - Open channel: approve automatically
   - Gated channel: evaluate condition (Phase 2+)
   - Invite-only channel: deny (PSK distributed via direct invitation, not request)
3. Holder verifies `subscriber_xpk == ed25519_to_x25519(peer.node_id)` (TLS-authenticated identity). The `subscriber_xpk` field contains the raw 32-byte X25519 public key (CBOR major type 2, binary). The holder MUST compute `ed25519_to_x25519(peer.node_id)` using the algorithm in ecies-envelope-encryption.md §2.2 and verify equality with the received `subscriber_xpk`. Mismatch indicates a key confusion attack or low-order point attack; the holder rejects with status `denied`, reason `not_authorized`, and bans the peer for `identity_mismatch` (Moderate tier, §5.6).
4. If approved: ECIES-encrypt the channel PSK to the subscriber's X25519 key (92-byte envelope, ECIES spec §4)
5. Return `PSKResponse` with the encrypted envelope
6. Subscriber decrypts envelope, verifies `SHA-256(decrypted_psk) == descriptor.psk_hash` (§4.4.6). On mismatch: discard PSK, ban peer, retry with a different peer.

**Security:**
- The PSK is encrypted to the subscriber's specific key. Eavesdroppers on the QUIC stream see only ciphertext.
- Only nodes that hold the PSK can respond. Relays (which never hold PSKs) return `unknown_channel`.
- Rate limited: max 1 PSK request per channel per peer per minute (§9.2).
- Invalid or excessive requests result in ban escalation (§5.6).

**Phase 1 scope:** In Phase 1, open channels are the primary use case. The channel creator's node holds the PSK and responds to requests from any authenticated peer. Gated channels and keeper-based PSK distribution are Phase 2+.

---

### 4.8 Pairing (Device Enrollment)

Protocol byte `0x08`. Enables second-device enrollment via one-time pairing codes. Used between two personal nodes and between personal nodes and bootnodes.

**Bootnode messages (registration and lookup):**

```
PairRegister {
    code:        string       // Raw pairing code (transport-encrypted by TLS 1.3)
    address:     string       // Initiator's reachable address (ip:port)
    ttl_seconds: u32          // Expiry (default 300, max 600)
}

PairRegisterAck {
    accepted:    bool
    reason:      ?string      // "rate_limited" | "capacity" | "session_in_use" if rejected
}

PairLookup {
    code:        string       // Raw pairing code (transport-encrypted by TLS 1.3)
}

PairLookupResponse {
    found:       bool
    address:     ?string      // Initiator address if found
}
```

**HMAC storage:** The bootnode computes `HMAC-SHA256(bootnode_secret, code)` on receipt and stores only the HMAC-to-address mapping. The raw pairing code is held in memory only during HMAC computation, then discarded. The HMAC key is per-bootnode (CSPRNG, 32 bytes), never shared between bootnodes. This prevents offline brute-force even with bootnode database access. Transport encryption (TLS 1.3 via QUIC) protects the raw code in transit.

Bootnodes MUST rate-limit PairLookup: max 10 requests per source IP per minute. Exceeding returns `PairLookupResponse { found: false }`.

**Device-to-device messages (after lookup resolves address):**

```
PairOffer {
    initiator_pk:  bytes(32)  // Initiator's Ed25519 public key
    fingerprint:   string     // SHA-256(initiator_pk)[0..8] hex, for visual verification
}

PairAccept {
    joiner_pk:     bytes(32)  // Joiner's Ed25519 public key (from `cordelia init`, NOT ephemeral)
    fingerprint:   string     // SHA-256(joiner_pk)[0..8] hex
}

PairBundle {
    identity_key:  bytes(92)  // ECIES envelope: Ed25519 seed encrypted for joiner's X25519 (derived from joiner_pk per ECIES spec §2)
    channel_psks:  [bytes(92)]  // ECIES envelopes: one per channel PSK
    channel_ids:   [string]   // Corresponding channel IDs (same order as channel_psks, plaintext -- transport-encrypted only)
}

PairComplete {
    ok:            bool
    channels_received: u32    // Number of channels synced
}
```

**Flow:**
1. Initiator sends PairRegister (raw code over TLS) to configured bootnodes (`network.bootnodes`), NOT all hot peers
2. Joiner sends PairLookup (raw code over TLS) to bootnodes; bootnode HMACs and looks up
3. Joiner connects directly to initiator address via QUIC
4. Initiator sends PairOffer, joiner sends PairAccept
5. Both devices display fingerprints for visual verification (out-of-band). Initiator MUST NOT proceed to step 6 until user confirms fingerprint match. In `--non-interactive` mode, fingerprint verification is skipped (acceptable for automated provisioning in trusted networks; the threat model assumes physical proximity or secure channel for pairing code exchange).
6. Initiator sends PairBundle (ECIES-encrypted identity + all channel PSKs)
7. Joiner sends PairComplete, replaces init-generated identity with received Ed25519 seed, re-derives all keys, begins replication
8. Initiator sends PairRegister with `ttl_seconds: 0` to bootnodes (cleanup)

Initiator accepts only ONE pairing connection per session. Subsequent connections receive `PairRegisterAck { accepted: false, reason: "session_in_use" }`. The initiator MUST verify that the connecting peer's Ed25519 public key is NOT already known (not an existing peer) -- pairing is only for new devices.

Pairing codes are single-use. Bootnodes delete the registration after one successful lookup or on TTL expiry.

**Security properties:**
- Pairing code sent over TLS, never stored on bootnode (only HMAC)
- Identity key encrypted in transit (ECIES envelope for joiner's X25519)
- Visual fingerprint verification (mandatory in interactive mode) defeats active MITM
- Single-use code prevents replay
- Single-connection guard prevents malicious bootnode racing
- PairBundle reveals initiator's full channel list to joiner (intentional -- same identity). Channel IDs are transport-encrypted (TLS 1.3) but not content-encrypted within the bundle. A compromised TLS session would expose channel membership but not PSKs (which are ECIES-encrypted).

---

## 5. Peer Governor

Background tokio task, ticks every 10 seconds.

### 5.1 Peer States

```
                promote            promote
     COLD ────────────────> WARM ────────────────> HOT
      ^                   |                  |
      |      demote       |     demote       |
      |<──────────────────|<─────────────────|
      |                                      |
      +──── ban (any state → BANNED) ────────+
```

**State semantics (ref: Coutts/Davies, Cardano Ouroboros networking):**

| State | Connection | Protocols | Purpose |
|-------|-----------|-----------|---------|
| **Cold** | None | None | Address book entry. No resource cost. |
| **Warm** | **Open**, keepalive active | Keep-Alive (ss4.2), Peer-Sharing (ss4.3) | Ready reserve. Fast failover (~0 promote cost). Discovery aid. |
| **Hot** | Open, keepalive + data | All above + Push (ss4.6), Sync (ss4.5), Channel-Announce (ss4.4) | Active data peer. Items flow here. |
| **Banned** | Closed | None | Violation cooldown. Duration depends on tier (ss5.6). |

**Critical property:** When a peer is demoted Hot->Warm, the QUIC connection stays open. Only data protocols stop. This makes Warm->Hot promotion near-instant (start streams on existing connection) vs Cold->Warm (full QUIC handshake). The Warm set is a pre-connected ready reserve that provides fast failover and enables network-size-independent convergence.

**Transitions:**

| From | To | Trigger | Cost |
|------|----|---------|------|
| Cold | Warm | Governor step 3, `warm < warm_min` | QUIC handshake (~1-2 RTT) |
| Warm | Hot | Governor step 4, random promotion | ~0 (start data streams) |
| Hot | Warm | Governor step 5/6, demotion/churn | ~0 (stop data streams, keep connection) |
| Warm | Cold | Dead detection (keepalive timeout ss5.4 step 2) | Connection closed |
| Cold | Evicted | Governor step 7, excess cold | Address removed |
| Any | Banned | Protocol violation (ss5.6) | Connection closed |
| Banned | Cold | Ban expiry | -- |

**Per-node cost bounds:** O(warm_max) connections + O(hot_max) data streams. Independent of network size N.

### 5.2 Peer Data

```
PeerInfo {
    node_id:         bytes(32)      // Ed25519 public key (verified by TLS)
    addrs:           [SocketAddr]   // Known addresses
    state:           PeerState      // Cold | Warm | Hot | Banned { until, reason }
    channels:        [string]       // Channel IDs shared with this peer
    rtt_ms:          ?f64           // Latest RTT measurement
    last_activity:   Instant        // Last keepalive or item received
    items_delivered:  u64           // Cumulative items received from this peer
    items_relayed:   u64            // Items this peer has forwarded to us (§16.1.1)
    items_requested: u64            // Items we have requested from this peer
    bytes_in:        u64            // Total bytes received
    bytes_out:       u64            // Total bytes sent
    probes_sent:     u32            // Probe items expected from this peer (§16.1.2)
    probes_received: u32            // Probe items actually received
    score_ema:       f64            // Exponential moving average score
    state_changed_at: Instant       // When peer entered current state (for tenure checks)
    demoted_at:      ?Instant       // When last demoted (hysteresis)
    connection:      ?Connection    // Live QUIC connection handle (present for Warm + Hot)
}
```

### 5.3 Governor Targets

Configurable via `[governor]` in config.toml. Defaults match the Personal Node profile (§8.6). Role-specific profiles are defined in §8.6.

```
GovernorTargets {
    hot_min:        usize     // Default: 2.  Below this, promote aggressively (bypass tenure)
    hot_max:        usize     // Default: 2.  Above this, demote worst-scoring
    hot_min_relays: usize     // Default: 1.  Minimum relay peers in hot set (separate target)
    warm_min:       usize     // Default: 3.  Below this, connect cold peers
    warm_max:       usize     // Default: 10. Maximum warm+hot peers
    cold_max:       usize     // Default: 50. Maximum known peer addresses
    dial_policy:    DialPolicy // Default: "all". "all" | "relays_only" | "trusted_only"
}
```

**`hot_min_relays`:** Independent target from `hot_min`. Ensures relay backbone connectivity. On each governor tick, if fewer than `hot_min_relays` relays are in the hot set, promote a random warm relay to Hot (bypassing the regular random selection for non-relay peers). This guarantees items reach the relay backbone for fan-out.

**`dial_policy`:** Controls which peers the governor will connect to. `all` = any discovered peer. `relays_only` = only peers that identified as relay during handshake. `trusted_only` = only peers in `[[network.trusted_peers]]` config (secret keeper mode).

**Configuration validation (enforced on startup, node MUST refuse to start if violated):**
```
hot_min >= 1
hot_min <= hot_max
hot_min_relays <= hot_max
hot_max <= warm_max              (except: dial_policy = "trusted_only" exempts this)
warm_min >= hot_min              (except: dial_policy = "trusted_only" allows warm_min = 0)
cold_max >= warm_max             (except: dial_policy = "trusted_only" allows cold_max = 0)
tick_interval_secs >= 1
keepalive_timeout_secs >= 60     (>= 2x keep-alive interval of 30s)
min_warm_tenure_secs >= 60
hysteresis_secs >= tick_interval_secs
churn_fraction in (0.0, 1.0]
dial_policy in ("all", "relays_only", "trusted_only")
```

**`trusted_only` exemption:** Secret keepers (§8.5) use `dial_policy = "trusted_only"` with no gossip discovery. They connect only to configured relays, so `warm_min=0` and `cold_max=0` are valid -- there are no peers to discover.

### 5.3.1 Trusted Peers

Operators MAY configure trusted peers that the governor MUST always maintain as Warm or Hot:

```toml
[[network.trusted_peers]]
addr = "relay1.example.com:9474"

[[network.trusted_peers]]
addr = "relay2.example.com:9474"
```

Trusted peers are never demoted below Warm, never evicted by churn, and are always eligible for promotion regardless of scoring. They provide the primary defense against eclipse attacks (cf. Cardano's "local root peers"). Bootnodes are NOT automatically trusted -- they are transient discovery aids.

### 5.4 Tick Logic (every `tick_interval_secs`, default: 10s)

Executed in order:

1. **Unban expired**: Banned peers with expired ban duration → Cold.
2. **Reap dead**: No keepalive for `keepalive_timeout_secs` (default: 90s) → Hot→Warm, Warm→Cold. Connection closed.
3. **Promote Cold→Warm**: If `warm_count < warm_min`, connect to cold peers. Prefer peers with channel overlap. **Failure tracking:** After `max_connection_retries` (default: 5) consecutive failures, stop trying until the peer's backoff expires (exponential, base 30s, cap 900s). Clear failure count after `clear_failure_delay` (default: 120s) of being Hot.
4. **Promote Warm→Hot**: If `hot_count < hot_min`, promote from eligible warm peers. Guard: `min_warm_tenure_secs` (default: 300s) -- peer must be warm for 5 min, UNLESS `hot_count < hot_min` (bootstrap bypass). Guard: `hysteresis_secs` (default: 90s) -- recently demoted peers ineligible. **Anti-eclipse: promotion is RANDOM among eligible warm peers, not best-scoring.** This prevents an attacker from gaming their score to get promoted faster than honest peers (cf. Cardano's `simplePromotionPolicy`).
4a. **Ensure relay connectivity**: If fewer than `hot_min_relays` relay peers are Hot, promote a random warm relay to Hot. This bypasses the regular random selection and the tenure guard (same urgency as `hot < hot_min`). Evaluated after step 4, independent of `hot_count`.
5. **Demote Hot→Warm**: If `hot_count > hot_max`, demote worst-scoring hot peer. Stale peers (no items for `stale_threshold_secs`, default: 1800s) demoted first. Trusted peers are never demoted.
6. **Churn (hot)**: Every `churn_interval_secs` (default: 3600s) +/- `churn_jitter_secs` (default: 0-300s random), demote 1 random hot peer to Warm and promote 1 random warm peer to Hot. Trusted peers are exempt. This forces hot-tier exploration and prevents topology ossification.
7. **Churn (warm)**: Same interval, swap `churn_fraction` (default: 0.2) of warm peers with random cold peers.
8. **Evict excess cold**: If `cold_count > cold_max`, remove peers with most connection failures first, then oldest-seen.

### 5.4.1 Immediate Promotion on Connect

When a new peer connects (inbound or via peer-sharing):
- If `hot_count < hot_min`: promote directly to Hot (bootstrap urgency, bypass tenure guard). Reset `disconnect_count`.
- Otherwise: promote to Warm only. The peer must earn Hot via the `min_warm_tenure` guard and random promotion at the next tick.

This prevents Sybil attacks: an attacker connecting many identities can only get `hot_min` (default: 2) peers into Hot immediately. Additional peers must survive the 5-minute tenure guard and random selection.

### 5.4.2 Protocol-per-State Table

| Protocol | Cold | Warm | Hot |
|----------|------|------|-----|
| Handshake (0x01) | On promotion Cold→Warm | -- | -- |
| Keep-Alive (0x02) | -- | YES | YES |
| Peer-Sharing (0x03) | -- | YES (after `min_warm_tenure`) | YES |
| Channel-Announce (0x04) | -- | -- | YES |
| Item-Sync (0x05) | -- | -- | YES |
| Item-Push (0x06) | -- | -- | YES |
| PSK-Exchange (0x07) | -- | -- | YES |
| Pairing (0x08) | Bootnode only | -- | -- |

Push and Sync target Hot peers only. Peer-Sharing runs on Warm (for discovery) and Hot. Keep-Alive runs on all connected peers (Warm + Hot).

### 5.5 Peer Scoring

```
contribution_ratio = items_relayed / max(items_requested, 1)
contribution_factor = IF peer.is_relay THEN clamp(contribution_ratio, 0.1, 2.0) ELSE 1.0

score = (items_delivered / connected_duration_s)
      * (1 / (1 + rtt_ms / 100))
      * contribution_factor
score_ema = 0.1 * score + 0.9 * score_ema_prev
```

EMA prevents sudden score spikes. An attacker must sustain good behaviour for ~17 minutes to meaningfully influence their score. The `contribution_factor` penalises relays that take bandwidth but don't forward items (§16.1.2). Personal nodes are not penalised (factor = 1.0) since they are not expected to relay.

**Scoring is used for DEMOTION only, not promotion.** The worst-scoring hot peer is demoted first (§5.4 step 5). Promotion from Warm→Hot is RANDOM among eligible peers (§5.4 step 4). This is a deliberate anti-eclipse defense: an attacker cannot game their score to get promoted faster than honest peers.

**Default RTT:** If `rtt_ms` has not been measured (no Keep-Alive response received yet), use default `rtt_ms = 100` for scoring. If `rtt_ms` remains unmeasured after 600 seconds of connection tenure, demote the peer to Cold (likely broken Keep-Alive implementation).

### 5.5.1 Governor Event Wiring

The governor MUST receive these events from the P2P loop to function correctly:

| Event | When | Governor Method |
|-------|------|----------------|
| Peer connected (inbound or outbound) | After handshake completes | `add_peer()` + `mark_connected()` |
| Peer disconnected | QUIC connection closed | `mark_disconnected()` |
| Keep-Alive response received | Each pong | `record_activity(node_id, rtt_ms)` |
| Items received from peer | After storing pushed/synced items | `record_items_delivered(node_id, count)` |
| Protocol violation detected | On invalid message/signature | `ban_peer(node_id, reason, tier)` |
| Channel subscription changed | After subscribe/unsubscribe API | `set_groups(channel_ids)` |
| Connection attempt failed | On connect_to error | `mark_dial_failed(node_id)` |

Without these calls, the governor is deaf -- it cannot score, demote, ban, or reconnect peers based on real behaviour.

### 5.6 Banning

Protocol violations are classified into severity tiers:

| Tier | Action | Examples |
|------|--------|---------|
| Transient | Mark Cold, 1 hour cooldown | Malformed message, timeout, digest mismatch |
| Moderate | Ban 24 hours, escalate on repeat | Signature verification failure, policy violation, repeated rate limit breach |
| Permanent | Ban forever (no escalation) | Identity mismatch (3rd offence), cryptographic proof failure |

**Escalation schedule:** Ban duration doubles on each repeat of the same violation type: initial -> 2x -> 4x -> 8x -> cap at 24 hours -> permanent after 5th violation of the same type. Counters reset after 7 days without incidents from that peer.

**Specific violation escalation:**

| Violation | Tier | Initial ban | Escalation |
|-----------|------|------------|------------|
| Invalid message format | Transient | 1 hour | 2x per repeat, cap 24h, permanent on 5th |
| Identity mismatch | Moderate | 24 hours | Permanent on 3rd |
| Rate limit exceeded | Transient | 15 minutes | 2x per repeat, cap 24h, permanent on 5th |
| Invalid item signature | Moderate | 1 hour | 2x per repeat, cap 24h, permanent on 5th |

---

## 6. Replication

### 6.1 Culture Dispatch

When an item is written locally, the replication engine consults the channel's delivery mode:

| Mode | Action | SDK term |
|------|--------|----------|
| Realtime | Item-Push (0x06) to all hot peers sharing the channel + all hot relay peers | `realtime` |
| Batch | No push. Peers discover via Item-Sync (0x05) at the batch sync interval. | `batch` |

**Moderate culture is removed.** Two modes only. Any legacy `moderate` configuration maps to `realtime`.

### 6.2 On Remote Receive

When a node receives a pushed or synced item:

1. **Verify signature**: Check Ed25519 signature on metadata envelope (ECIES spec §11.7). Reject invalid.
2. **Check channel membership**: Item's `channel_id` must be in the node's subscribed channels (or, for relay nodes, in accepted channels). Reject otherwise.
3. **Dedup**: Same `item_id` + same `content_hash` → skip (idempotent).
4. **Conflict resolution**: Same `item_id`, different `content_hash` → last-writer-wins by `published_at`. Deterministic tiebreak compares the hex-encoded `content_hash` strings lexicographically (character-by-character, using ASCII ordering: 0-9, a-f). The item with the lexicographically smaller `content_hash` wins. This ensures all replicas converge to the same item regardless of receive order.
5. **Store**: Write encrypted blob to SQLite. Never decrypt at the P2P layer.
6. **Relay re-push (single-hop)**: If this node is a relay AND the sender is a non-relay peer AND `stored > 0`, re-push newly stored items to all hot **relay** peers except sender. Items received from other relays are NOT re-pushed.
7. **Log**: Record in access log (author_id, channel_id, item_id, action, timestamp).

### 6.3 Tombstones

Deletions are soft-delete tombstones (`is_tombstone: true`). Tombstones propagate via the same culture-governed replication as regular items. Tombstones are retained for 7 days, then garbage-collected.

### 6.4 Anti-Entropy as Safety Net

Anti-entropy sync runs periodically regardless of push success. For realtime channels, it catches items missed during push (network partition, peer churn, race conditions). For batch channels, it is the primary delivery mechanism.

**Per-channel sync state:**
```
ChannelSyncState {
    channel_id:     string
    last_synced_at: Instant     // When we last synced this channel
    cursor:         string      // ISO 8601 cursor for incremental sync
    sync_interval:  Duration    // 10s default (realtime), 900s (batch). Production: 60s realtime.
}
```

---

## 7. Channel Routing

### 7.1 Three Gates

An item must pass all three gates to reach its destination:

**Gate 1: Push Target Selection (Writer Side)**

When a node writes an item, the replication engine selects peers:

```
IF push_policy == "pull_only":
    return []   // No push targets. Rely on peers pulling via Item-Sync.

target IF:
    peer.state.is_active()
    AND NOT peer.is_bootnode
    AND (peer.is_relay OR peer.channels.contains(channel_id))
```

Relay peers are always push targets (they store-and-forward). Non-relay peers are targets only if they share the channel. Bootnode peers are never push targets (discovery-only, §8.2). Nodes with `push_policy: pull_only` (§8.1.1) return no targets -- they consume via Item-Sync only.

Gate 1 applies only for realtime channels. Batch channels return no push targets.

**Gate 2: Relay Acceptance (Intermediate Node)**

When a relay receives a pushed item:

```
accept IF channel_id IN relay_subscribed_channels
         OR channel_id IN relay_learned_channels
```

Phase 1 relays are transparent: they accept all channels. The `relay_learned_channels` set grows from two sources: (a) channels observed in stored items (`SELECT DISTINCT channel_id FROM items`) and (b) channels discovered from peers via sync Phase 0 (`SyncChannelListResponse`, §4.5). Future phases add explicit allowlists.

Bootnodes (§8.2) never reach Gate 2 -- they do not participate in item replication.

**Gate 3: Destination Acceptance (Final Recipient)**

When a non-relay node receives an item:

```
accept IF channel_id IN node_subscribed_channels
```

Strict membership check. The channel must be explicitly subscribed on the destination node.

### 7.2 Relay Re-Push

When a relay stores an item received from a **non-relay** peer (personal node or secret keeper) and `stored > 0`, it re-pushes to all **hot relay peers** except the sender. This is single-hop: items received from other relays are stored but NOT re-pushed.

**Single-hop design:** Only the first relay (that receives from the originator) re-pushes. This bounds amplification to O(R) per item. Pull-sync (§4.5) provides eventual consistency for any items missed during re-push. The relay mesh converges within one pull-sync interval (10s for realtime channels).

**Push targets: relay peers only.** Personal nodes and secret keepers receive items exclusively via Item-Sync pull (§4.5). The relay does not maintain per-channel routing tables for push delivery. This eliminates Channel-Announce as a routing dependency and makes relays stateless store-and-forward nodes.

**Channel-Announce role (informational):** Channel-Announce (§4.4) remains implemented for governor scoring and relay affinity (§5.5). Relays receive announcements from peers and track channel interest for metrics and future optimisation, but do NOT use Channel-Announce data for push routing decisions.

**Anti-censorship principle:** Relays MUST be agnostic to content. They store and forward ciphertext without knowing what's inside. Channel-aware routing is an efficiency optimisation (don't send data to peers that didn't ask for it), not a censorship mechanism. Content sovereignty resides at the edge: personal nodes and secret keepers choose what channels to subscribe to. Relays MUST NOT refuse to forward based on channel_id, content patterns, or originator identity.

**Lazy storage (future):** The relay SHOULD only store items for channels that at least one of its hot peers has announced interest in. Items for channels with no local interest are forwarded to other relays but not persisted. This reduces relay storage from O(all_channels) to O(locally_interesting_channels). Phase 1: relays store everything (transparent).

**Relay affinity:** The governor (§5.4) SHOULD prefer promoting relays that carry the node's subscribed channels. When a personal node's governor evaluates warm relay peers for promotion to Hot, it SHOULD prefer relays that have announced interest in the personal node's channels. This naturally clusters related nodes on the same relays without explicit sharding, providing self-organising channel locality.

**Loop prevention:** Single-hop re-push eliminates cascading by design. Additionally, dedup (`stored: 0` for known items) prevents re-push even if the single-hop check were bypassed. Convergence: each relay stores the item at most once, the originator's relay re-pushes at most once.

**Amplification bound:** Single-hop re-push generates exactly R-1 push messages per item (one to each relay peer except sender). This is O(R), independent of network topology or channel count.

| Scale | Total Relays | Cost/item (single-hop) |
|-------|-------------|----------------------|
| Small (<1K nodes) | 7 | 6 pushes |
| Medium (<100K nodes) | 100 | 99 pushes |
| Large (>100K nodes) | 1,000 | 999 pushes |

**Concurrency:** The relay MUST push to all hot relay peers present at the time the re-push handler executes. If a peer is being accepted concurrently, it is acceptable to miss that peer on this push cycle; the peer will receive the item via the next Item-Sync pull (§4.5).

### 7.3 Channel Intersection

`channel_intersection(peer)` determines which channels a peer and this node have in common. Computed from Channel-Announce data (§4.4) and sync Phase 0 discovery (§4.5).

```
local_channels = subscribed_channels
    UNION relay_learned_channels (if this node is a relay)
    // relay_learned_channels = stored items channels + sync Phase 0 discovered channels

channel_intersection(peer) = peer.channels INTERSECT local_channels
    (bootnode peers excluded -- they have no channel state)
```

Updated when:
- Channel-Announce receives a `ChannelJoined` from the peer
- Channel-Announce reconciliation reveals a change
- Local node subscribes to a new channel

---

## 8. Node Roles

Phase 1 defines four node roles. Each role determines which mini-protocols the node participates in, whether it accepts inbound connections, and how it handles item traffic.

**Role capability matrix:**

| Capability | Personal | Bootnode | Relay | Keeper |
|-----------|----------|----------|-------|--------|
| Accepts inbound QUIC | No (outbound-only) | Yes | Yes | Yes |
| Handshake (0x01) | Yes | Yes | Yes | Yes |
| Keep-Alive (0x02) | Yes | Yes | Yes | Yes |
| Peer-Sharing (0x03) | Yes | Yes (primary function) | Yes | Yes |
| Channel-Announce (0x04) | Yes (send) | No | Yes (receive-only) | Yes (send) |
| Item-Sync (0x05) | Yes (pull, primary delivery) | No | Yes (serve + pull) | Yes (pull, primary delivery) |
| Item-Push (0x06) | Originator push to relays only | No | Single-hop re-push to relays | Originator push to relays only |
| PSK-Exchange (0x07) | Yes (if holds PSK) | No | No | Yes |
| Stores items | Own channels only | No | Ciphertext (store-and-forward) | Yes (can decrypt anchored) |
| Holds PSKs | Own channels | Never | Never | Anchored channels |
| Receives items via | Pull-sync (§4.5) | Never | Push + pull-sync | Pull-sync (§4.5) |
| Phase | 1 | 1 | 1 | 2+ |

### 8.1 Network Topology

```
Personal Nodes <--gossip--> Relays <--gossip--> Bootnodes
                               ^
                               |
                        (defined, no gossip)
                               |
                        Secret Keepers
```

Each role has a fundamentally different relationship with the network. Personal nodes consume, relays distribute, bootnodes introduce, keepers store. The governor profiles (§8.6) reflect this -- nodes are not interchangeable peers with different numbers.

### 8.2 Personal Node

The user's local node. Runs as a daemon on the user's machine. Its job is reliable network access and occasional publishing of memories. Minimal resource footprint.

- Subscribes to channels via the local API (channels-api.md)
- Stores encrypted items in local SQLite
- Connects to bootnodes for initial discovery, then relays via gossip
- Small hot set: 1-2 relays + a few personal peers. Selection prefers lowest RTT (indicator of network colocation/quality)
- Never accepts inbound connections from the public internet (unless explicitly configured)
- MAY specify preferred peers (e.g., within the same org) via `[[network.trusted_peers]]`
- Pushes items to hot relay peers only on local write (originator push). Never pushes to other personal nodes.
- Receives items from peers exclusively via Item-Sync pull (§4.5), every 10s for realtime channels.
- Makes outbound connections only (§2.1). Rejects all inbound QUIC connections.
- `dial_policy = "relays_only"`

**Governor profile:** `hot_min=2, hot_max=2, hot_min_relays=1, warm_min=3, warm_max=10, cold_max=50`

#### 8.2.1 Push Policy

Personal nodes support a configurable `push_policy` that controls outbound item traffic:

| Policy | Behaviour | Use case |
|--------|-----------|----------|
| `relay_only` (default) | Push to hot relay peers on local write. Receive via pull-sync. | Normal operation. Minimal outbound traffic. |
| `pull_only` | Never initiate Item-Push. Only serve items via Item-Sync when requested. | Enterprise-constrained networks, bandwidth-sensitive environments. |

**Design rationale:** Personal nodes push only to their hot relays (1-2 peers). The relay mesh handles distribution to other relays (single-hop re-push, §7.2). Other personal nodes and keepers receive items by pulling from their own hot relays. This makes personal nodes lightweight: they push O(1) streams on write and pull O(hot_max) streams per sync cycle. No routing tables, no Channel-Announce dependency for push routing.

**Trade-off:** Personal nodes receive items via pull-sync with latency bounded by `sync_interval` (10s for realtime, 900s for batch). This is acceptable for AI agent memory workloads where sub-second latency is not required.

### 8.3 Bootnode

Lightweight discovery node. Its sole function is peer introduction -- Handshake and Peer-Sharing only. Once a node discovers relays and peers via a bootnode, gossip takes over and the bootnode connection can be released.

- Publicly addressable (static IP or DNS)
- Accepts inbound QUIC connections
- Does NOT participate in Channel-Announce, Item-Sync, Item-Push, or PSK-Exchange
- Does NOT store items (no SQLite, no ciphertext, no PSKs)
- Does NOT relay traffic
- Maintains a large peer table for Peer-Sharing responses (passive discovery -- learns about the network via inbound connections, does not actively crawl)
- Minimal resource footprint: ~50MB RAM, negligible storage, low bandwidth (handshakes + peer lists only)
- `dial_policy = "all"`

**Governor profile:** `hot_min=1, hot_max=5, warm_min=50, warm_max=500, cold_max=1000`

High warm/cold targets give the bootnode broad network knowledge for peer-sharing. Low hot targets because bootnodes don't participate in data protocols.

**Why separate from relay:** Splitting the roles means bootnodes are cheap to run (discovery-only) and relays are explicit infrastructure commitments. Phase 3: SPOs can register as bootnodes at near-zero marginal cost.

### 8.4 Relay

Infrastructure node forming the network backbone. Relays store-and-forward encrypted items between personal nodes and secret keepers. They are the edge proxy protecting secret keepers from direct exposure.

- Publicly addressable (static IP or DNS)
- Accepts inbound QUIC connections from personal nodes, other relays, bootnodes, and secret keepers
- Participates in all mini-protocols except PSK-Exchange (never holds PSKs)
- Stores encrypted items as ciphertext only (see data-formats.md §3.1, Relay auto-creation)
- Re-pushes items to hot **relay** peers only, single-hop from originator (§7.2)
- Serves items to personal nodes and keepers via Item-Sync pull requests
- **Highly connected to other relays** -- the relay mesh is the network backbone
- Expected to be permanently available with demanding resource requirements
- Never reveals secret keeper addresses in Peer-Sharing responses
- `dial_policy = "all"`

**Governor profile:** `hot_min=10, hot_max=50, hot_min_relays=5, warm_min=20, warm_max=100, cold_max=500`

The `hot_min_relays=5` ensures each relay maintains connections to at least 5 other relays, forming a well-connected backbone mesh. This is the critical property for network-wide convergence -- items published by any personal node reach a relay, then fan out across the relay mesh, then reach all subscribing personal nodes.

**Phase 1 relay posture:** Transparent. Accept all channels. No access control on which channels to relay.

**Phase 2+:** Dynamic and explicit relay postures (accept only learned or explicitly configured channels).

**Relay is an explicit infrastructure role.** A personal node never becomes a relay by default. Operators must set `role = "relay"` in config.toml. This prevents the Skype supernode problem where user machines silently become transit nodes for strangers' traffic.

### 8.5 Secret Keeper (Phase 2+)

Long-term durable storage and service provider for channel data. Secret keepers hold PSKs and can decrypt content. They are the most sensitive nodes in the network -- their compromise breaches channel confidentiality. Protected behind relays using the BPN (Block Producer Node) isolation model from Cardano.

- **Connects ONLY to its own relays** -- defined in config, never via gossip
- **Never advertised** -- its address MUST NOT appear in any Peer-Sharing response
- **Never accepts inbound connections from unknown peers** -- only from configured relays
- Holds PSKs for anchored channels (can decrypt content)
- All relay capabilities plus PSK-Exchange (0x07)
- Enforces commercial policies (SPO delegation, quotas)
- `dial_policy = "trusted_only"` -- only connects to explicitly configured relay node_ids

**Governor profile:** `hot_min=2, hot_max=5, hot_min_relays=2, warm_min=0, warm_max=5, cold_max=0`

Zero cold/warm targets because the keeper discovers nothing via gossip. Its entire peer set is defined in config. The `hot_min=2` ensures redundancy (at least 2 relay connections).

```toml
# Secret keeper connects ONLY to its own relays
[[network.trusted_peers]]
addr = "relay1.myorg.com:9474"
node_id = "cordelia_pk1..."    # REQUIRED -- prevents DNS hijack

[[network.trusted_peers]]
addr = "relay2.myorg.com:9474"
node_id = "cordelia_pk1..."
```

**Security properties:**
- Keeper's IP address is never leaked to the network
- Relay protects keeper from direct connection attempts
- If a relay is compromised, the attacker learns the keeper's address but still cannot decrypt items (relay has no PSKs)
- If the keeper is compromised, only its anchored channels are affected (not the network)

### 8.6 Governor Profiles Summary

| Parameter | Personal | Bootnode | Relay | Secret Keeper |
|-----------|----------|----------|-------|---------------|
| `hot_min` | 2 | 1 | 10 | 2 |
| `hot_max` | 2 | 5 | 50 | 5 |
| `hot_min_relays` | 1 | 0 | 5 | 2 |
| `warm_min` | 3 | 50 | 20 | 0 |
| `warm_max` | 10 | 500 | 100 | 5 |
| `cold_max` | 50 | 1000 | 500 | 0 |
| `dial_policy` | all | all | all | trusted_only |
| Network exposure | Behind NAT | Public | Public | Hidden |
| Inbound connections | Optional | Yes (500+) | Yes | From relays only |
| Peer discovery | Gossip | Passive (inbound) | Gossip | None (config only) |

---

## 9. Rate Limiting and Backpressure

### 9.1 Connection Limits (Phase 1)

| Limit | Default | Rationale |
|-------|---------|-----------|
| Max inbound connections | 200 | Prevent connection exhaustion |
| Max connections per IP | 5 | Block naive Sybil from single host |
| Max connections per /24 subnet | 20 | Block Sybil from single subnet |
| Max concurrent streams per connection | 64 | Prevent stream exhaustion |

The `max_inbound_connections` (200) is the hard cap. Once reached, all further inbound connections are rejected regardless of per-IP/subnet headroom. Per-IP and per-subnet limits are evaluated first: a connection from a /24 with 20 existing connections is rejected even if the global count is below 200.

Beyond limits: new connections receive QUIC `CONNECTION_CLOSE` with application error code `0x01` (capacity). The connecting node should back off exponentially.

### 9.2 Message Rate Limits

| Limit | Default | Action on exceed |
|-------|---------|-----------------|
| Writes per peer per minute | 10 | Reject with `PushAck.policy_rejected++` |
| Writes per channel per minute | 100 | Drop, log warning |
| Sync requests per peer per minute | 6 | Ignore excess, log |
| Peer-share requests per peer per minute | 2 | Ignore excess |

Exceeding rate limits 3 times in 10 minutes → ban (§5.6).

### 9.3 Size Limits

| Parameter | Value | Enforcement |
|-----------|-------|-------------|
| `max_item_bytes` | 256 KB (262,144) | API write, P2P receive, outbound replication |
| `max_message_bytes` | 1 MB (1,048,576) | Wire codec (length prefix check) |
| `max_batch_size` | 100 | Items per FetchRequest/PushPayload |

Items exceeding `max_item_bytes` are rejected at all boundaries. The 256 KB limit is consistent with the REST API (channels-api.md §3.2) and SDK (sdk-api-reference.md). Phase 1 is text-only AI memory; 95th percentile ~50KB, so 256KB provides 5x headroom. No images/media. Increasing later is non-breaking.

The `max_message_bytes` of 1 MB accommodates a batch of up to 4 max-size items, or ~100 typical items (~10 KB each). The wire codec rejects messages exceeding this before any parsing occurs.

### 9.4 Backpressure Model

Bounded inbound queue per protocol type:

| Protocol | Queue capacity | Processing |
|----------|---------------|------------|
| Handshake (0x01) | 16 | FIFO, one worker |
| Keep-Alive (0x02) | 256 | FIFO, inline |
| Peer-Sharing (0x03) | 32 | FIFO, one worker |
| Channel-Announce (0x04) | 64 | FIFO, one worker |
| Item-Sync (0x05) | 64 | FIFO, worker pool |
| Item-Push (0x06) | 128 | FIFO, worker pool |

When a queue is full, the node does not accept new streams for that protocol type. QUIC flow control handles the rest -- the sender's `open_bi()` blocks until the receiver is ready.

**Per-peer fairness:** Each peer's share of queue capacity is `queue_capacity / active_peers`. No single peer can consume more than their share.

---

## 10. Bootstrap and Discovery

### 10.1 Bootnode Addresses

Hardcoded in configuration and in the binary:

```toml
[[network.bootnodes]]
addr = "boot1.cordelia.seeddrill.ai:9474"

[[network.bootnodes]]
addr = "boot2.cordelia.seeddrill.ai:9474"
```

Phase 1 target: 2+ Seed Drill-operated bootnodes (WP12). Bootnodes are discovery-only (§8.2) -- they serve peer addresses but do not relay item traffic, making them lightweight to operate. Phase 2+ target: 5+ independent bootnodes across providers and jurisdictions.

### 10.2 DNS-Based Discovery (WP12)

DNS SRV records for bootnode discovery:

```
_cordelia._udp.seeddrill.ai. 300 IN SRV 10 0 9474 boot1.cordelia.seeddrill.ai.
_cordelia._udp.seeddrill.ai. 300 IN SRV 20 0 9474 boot2.cordelia.seeddrill.ai.
```

Nodes query SRV records on startup, falling back to hardcoded addresses if DNS fails.

### 10.3 Bootstrap Flow

```
Phase A: Discovery (bootnode interaction)
1. Node starts with empty peer table
2. Load bootnodes from config + DNS SRV
3. Add bootnodes to Cold state
4. Governor tick: promote bootnodes Cold → Warm (connect + handshake)
5. After handshake: initiate Peer-Sharing with bootnodes
6. Receive relay and peer addresses → add to Cold
7. Bootnode interaction complete. Bootnodes may be demoted/disconnected as
   real peers fill Hot/Warm slots. Bootnodes do not participate in
   Channel-Announce or Item-Sync.
```

**Bootstrap timeout:** Each bootnode connection attempt MUST use a 10-second timeout. On timeout, the node logs a warning and continues to the next bootnode. Bootstrap is best-effort: the node proceeds to Phase B after attempting all bootnodes, even if some failed.

```
Phase B: Replication (relay and peer interaction)
8. Governor tick: promote best Cold → Warm, best Warm → Hot
   (prefer relays and channel-matching peers over bootnodes)
9. Initiate Channel-Announce with hot peers (relays + personal nodes)
10. Begin Item-Sync for subscribed channels
11. Steady state: governor manages peer lifecycle autonomously
```

**Time to first sync:** ~20-30s (1-3 governor ticks to discover peers via bootnode, promote relay/peer to Hot, then immediate sync). The bootnode is a brief stepping-stone, not a long-lived connection.

### 10.4 Fallback Peers

In addition to bootnodes, the binary includes 3-5 hardcoded fallback peer addresses, rotated each release. These are last-resort addresses if bootnodes and DNS are both unreachable.

---

## 11. Security Model

### 11.1 Trust Boundaries

```
┌───────────────────────────────────────────────────────────────┐
│                        UNTRUSTED                               │
│  Internet, bootnodes, relays, other peers                      │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                  QUIC/TLS BOUNDARY                       │  │
│  │  Transport encrypted. Peer identity verified.            │  │
│  │  Content is opaque ciphertext.                          │  │
│  │                                                          │  │
│  │  ┌───────────────────────────────────────────────────┐  │  │
│  │  │              LOCAL NODE BOUNDARY                   │  │  │
│  │  │  Node holds channel PSKs. Encrypts/decrypts.     │  │  │
│  │  │  SDK sends plaintext over bearer-auth localhost.  │  │  │
│  │  │  Keys never leave this boundary.                  │  │  │
│  │  └───────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

### 11.2 Invariants

1. **PSKs never leave the subscriber node.** The P2P layer moves opaque ciphertext. Relays never hold PSKs.
2. **Items are signed.** Ed25519 signature on metadata envelope (ECIES spec §11). Verified before storage. Relays verify authorship without holding PSKs.
3. **Channel membership is private.** Not gossiped in peer-sharing. Exchanged point-to-point via Channel-Announce only with direct peers.
4. **All replication is encrypted.** QUIC provides transport encryption. Channel PSKs provide content encryption. Two independent layers.
5. **Idempotent writes.** Duplicate items (same item_id + content_hash) are no-ops. No state confusion from replays.

### 11.3 Threat Mitigations

| Threat | Mitigation | Phase |
|--------|-----------|-------|
| **Sybil** (flood with fake peers) | Connection limits per IP/subnet (§9.1). Min warm tenure before promotion (§5.4). | 1 |
| **Eclipse** (surround target with attacker peers) | 20%/hr churn (§5.4). Bootnode diversity. 25+ active peers needed at >75% network control. | 1 |
| **Amplification** (one write → many messages) | Single-hop push bounded by hot_max. Rate limits (§9.2). | 1 |
| **Replay** | TLS 1.3 (transport). Idempotent writes (application). Timestamp validation in handshake. | 1 |
| **Identity spoofing** | TLS certificate binds to Ed25519 key (§2.2). Application-layer verification (§4.1.6). | 1 |
| **Metadata leakage** | Channel lists removed from peer-sharing (§4.3). Channel digest in handshake, not full list (§4.1.2). | 1 |
| **DDoS** | Connection limits, bounded queues, per-peer fairness (§9). QUIC flow control. | 1 |
| **Governor manipulation** | EMA scoring (§5.5). Min warm tenure. Hysteresis. Escalating bans. | 1 |
| **Item forgery** | Ed25519 signature verification on all received items (§6.2). | 1 |
| **Relay compromise** | Relays see only ciphertext. No PSKs, no plaintext, no keys. Expendable by design. | 1 |
| **PSK key substitution** | `psk_hash` in signed channel descriptor (§4.4.6). Subscriber verifies after PSK-Exchange. | 1 |
| **Metadata field tampering** | `key_version` and `is_tombstone` both included in signed metadata envelope (ECIES spec §11.7). | 1 |
| **Peer-sharing poisoning** | Address validation: reject private IPs, loopback, link-local, own address (§4.3). | 1 |
| **FTS5 query DoS** | Query sanitization: max length, max terms, prefix minimum, timeout (channels-api.md §3.13). | 1 |
| **Channel name squatting** | First-seen `creator_id` wins for channel descriptors (§4.4.6). On-chain registration Phase 3. | 1 |
| **Free-rider metadata observation** | Governor scoring detects low-contribution peers (§5.5). Proof-of-membership Phase 2 (§4.4.5). | 1 |
| **Relay defection (silent drop)** | Contribution tracking + probe items + escalating bans + ban propagation (§16.1.2). | 1 |
| **Relay bandwidth free-riding** | Contribution-weighted scoring (§16.1.2). Relay credit ledger Phase 3 (§16.1.3). | 1 |
| **Bootnode exhaustion** | Bootstrap rate limits per IP/subnet (§16.2.1). Bootnodes discovery-only (§8.2). | 1 |
| **Storage quota evasion** | Quota check on API write (channels-api.md §9.3). Relay LRU eviction (§16.3). | 1 |
| **Bandwidth amplification** | Per-peer/channel/relay fanout rate limits (§16.4). pull_only mode (§8.1.1). | 1 |
| **DM spam** | DM creation rate limit 5/min (channels-api.md §9.1). | 1 |
| **Ephemeral channel griefing** | Channel creation rate limit 1/sec, cap 50/entity (channels-api.md §9.1). | 1 |

### 11.4 Accepted Risks (Phase 1)

| Risk | Rationale |
|------|-----------|
| **Metadata visible to relays**: channel_id, author_id, published_at, blob size | Relays need channel_id for routing. Content is encrypted. Acceptable for Phase 1. Phase 4+ explores onion routing. |
| **Channel count visible in handshake** | `channel_digest` reveals count but not identities. Acceptable trade-off for connection management. |
| **No reputation gating (beyond contribution scoring)** | Phase 1 has contribution-weighted peer scoring (§16.1.2) and probe-based defection detection. Full reputation oracle deferred to Phase 4. |
| **No invite graph** | Open peer discovery. Invite-based Sybil defence deferred to Phase 3. |
| **No forward secrecy on transport** | QUIC TLS 1.3 provides forward secrecy per-session. Long-term key compromise reveals identity but not past sessions. |
| **2+ bootnodes** | Bootnodes are discovery-only (§8.2), low resource cost. Sufficient for Phase 1 (<100 nodes). Expand to 5+ for Phase 2. |

### 11.5 Comparison: Pre-Pivot vs Phase 1

| Property | Pre-pivot | Phase 1 | Improvement |
|----------|-----------|---------|-------------|
| Handshake channel list | Full list sent | Digest only | Metadata privacy |
| Peer-sharing channel list | Included per peer | Removed | Metadata privacy |
| Channel exchange | Push full list every 60s | Push IDs + periodic hash reconciliation + tenure-gated list | 106x bandwidth reduction, metadata protection |
| Mutual authentication | None (self-signed, no verification) | TLS cert binds to Ed25519 key | Identity spoofing prevented |
| Rate limiting | None implemented | Connection limits, per-peer/channel rates | DoS/Sybil defence |
| Wire format | JSON | CBOR | Smaller attack surface, more compact |
| Item signatures | Not verified | Verified before storage | Forgery prevention |

---

## 12. Configuration

### 12.1 Identity Section

```toml
[identity]
entity_id = "russwing"                     # Human-readable entity name
public_key = "cordelia_pk1..."             # Ed25519 public key (Bech32, read-only)
```

### 12.2 Network Section

```toml
[network]
listen_addr = "0.0.0.0:9474"              # P2P listen address
api_addr = "127.0.0.1:9473"               # REST API listen address (loopback only, see below)
role = "personal"                           # "personal" | "bootnode" | "relay" | "keeper"
push_policy = "subscribers_only"           # "subscribers_only" | "pull_only" (personal nodes only, §8.1.1)
bootstrap_timeout_secs = 10              # Per-bootnode connection timeout during bootstrap
# All stream I/O uses STREAM_TIMEOUT (10s) at the codec layer.
# One timeout, one layer. See parameter-rationale.md §6 and protocol.rs.

[[network.bootnodes]]
addr = "boot1.cordelia.seeddrill.ai:9474"

[[network.bootnodes]]
addr = "boot2.cordelia.seeddrill.ai:9474"

# Trusted peers: always maintained as Warm/Hot, never demoted or evicted (§5.3.1)
# [[network.trusted_peers]]
# addr = "relay1.example.com:9474"
```

**API loopback binding (Phase 1):** Phase 1 nodes MUST bind the channels API (`api_addr`) to `127.0.0.1` only. If configuration specifies a non-loopback address, the node MUST log a CRITICAL error and refuse to start. Phase 2 adds TLS and allows non-loopback binding.

### 12.2 Governor Section

```toml
# Defaults match Personal Node profile (§8.6). Override per role.
[governor]
hot_min = 2                            # Below this, promote aggressively (bypass min_warm_tenure)
hot_max = 2                            # Above this, demote worst-scoring
hot_min_relays = 1                     # Minimum relay peers in hot set (§5.3)
warm_min = 3                           # Below this, connect cold peers
warm_max = 10                          # Maximum warm+hot peers
cold_max = 50                          # Maximum known peer addresses (discovery breadth)
dial_policy = "all"                    # "all" | "relays_only" | "trusted_only"
tick_interval_secs = 10                # Governor tick frequency
churn_interval_secs = 3600             # Base churn interval (1 hour)
churn_jitter_secs = 300                # Random jitter added to churn interval (0-300s)
churn_fraction = 0.2                   # Fraction of warm peers churned per cycle
min_warm_tenure_secs = 300             # Minimum time as Warm before Hot promotion (bypassed if hot < hot_min)
hysteresis_secs = 90                   # Cooldown after demotion before re-promotion
keepalive_timeout_secs = 90            # Dead detection threshold
stale_threshold_secs = 1800            # 30 min no items → priority demotion
ema_alpha = 0.1                        # Scoring EMA decay (§5.5)
max_connection_retries = 5             # Stop connecting to a peer after this many consecutive failures
clear_failure_delay_secs = 120         # Clear failure count after being Hot for this long
```

See §8.6 for role-specific profiles (Bootnode, Relay, Secret Keeper).

### 12.3 Replication Section

```toml
[replication]
sync_interval_realtime_secs = 10           # Phase 1 default (fast convergence). Production: 60s.
sync_interval_batch_secs = 900
tombstone_retention_days = 7
max_batch_size = 100
```

### 12.4 Rate Limiting Section

```toml
[limits]
max_inbound_connections = 200
max_connections_per_ip = 5
max_connections_per_subnet = 20         # /24
max_streams_per_connection = 64
max_item_bytes = 262144                 # 256 KB
max_message_bytes = 1048576             # 1 MB
writes_per_peer_per_minute = 10
writes_per_channel_per_minute = 100
max_bytes_per_peer_per_second = 10485760  # 10 MB/s (§16.4)
max_push_items_per_channel_per_minute = 1000  # (§16.4)
max_relay_fanout_per_second = 100       # relay re-push rate cap (§16.4)
max_relay_storage_bytes = 10737418240   # 10 GB relay cache (§16.3)
bootstrap_connections_per_ip_per_hour = 5  # bootnode rate limit (§16.2.1)
probe_interval_secs = 300               # relay health probe interval (§16.1.2)
probe_timeout_secs = 60                 # probe delivery timeout (§16.1.2)
```

---

## 13. Phase 1 Scope and Limitations

### 13.1 In Scope

- QUIC transport with TLS 1.3 identity binding
- 7 mini-protocols (Handshake, Keep-Alive, Peer-Sharing, Channel-Announce, Item-Sync, Item-Push, PSK-Exchange)
- Governor with configurable targets (single profile)
- Two delivery modes (realtime/batch) with configurable push policy
- Four node roles: personal (with push_policy), bootnode (discovery-only), relay (store-and-forward), keeper (Phase 2+)
- Three-gate channel routing with transparent relay, bootnode exclusion
- Bootnode-based bootstrap with DNS SRV discovery (bootnodes are discovery-only, not relays)
- Connection limits and message rate limiting
- CBOR wire format
- Ed25519 item signature verification
- Relay contribution tracking, probe-based defection detection, and ban propagation (§16)
- Bootnode rate limiting (§16.2)
- P2P bandwidth and fanout rate limits (§16.4)

### 13.2 Deferred

| Feature | Phase | Rationale |
|---------|-------|-----------|
| Ship classes (GSV/GCU/Fast Picket) | 2 | Premature optimisation. Single configurable profile sufficient. |
| Dynamic/explicit relay postures | 2 | Transparent relay sufficient for Phase 1 scale. |
| Keeper nodes (active) | 2 | Long-term storage requires commercial model (SPO economics). Role defined in §8.4. |
| Archive nodes | 3 | Read-heavy historical access. Not MVP. |
| Reputation gating | 2 | Sybil defence via connection limits sufficient for Phase 1 scale. |
| Invite graph | 3 | Social-cost Sybil defence. Requires established network. |
| SOS/Reincarnation protocol | 3+ | Over-engineered for <1000 nodes. |
| Group sharding | 3+ | Needed at >10,000 channel members. Not Phase 1. |
| DHT rendezvous | 3+ | Needed at >10^9 nodes. Not Phase 1. |
| Onion routing / metadata privacy | 4+ | Significant complexity. Accepted risk for Phase 1. |
| Protocol evolution (HFC) | 3+ | Hard-fork combinator for breaking protocol changes. |
| TLA+ model checking | 1 (WP14) | Pre-coding gate. 9 properties verified with TLC. See specs/network-protocol.tla. |

### 13.3 Forward Compatibility

The protocol version negotiation (§4.1.4) allows adding new mini-protocols and modifying existing ones without breaking older nodes. New protocol bytes (0x08+) can be added in future phases. Unknown protocol bytes cause stream reset with application error code `0x02` (unknown protocol).

CBOR's extensibility (unknown fields preserved) means message types can gain new fields without breaking existing parsers.

---

## 14. References

- **RFC 9000**: QUIC: A UDP-Based Multiplexed and Secure Transport
- **RFC 8446**: The Transport Layer Security (TLS) Protocol Version 1.3
- **RFC 8949**: Concise Binary Object Representation (CBOR)
- **RFC 8610**: Concise Data Definition Language (CDDL)
- **RFC 8032**: Edwards-Curve Digital Signature Algorithm (Ed25519)
- **RFC 8410**: Algorithm Identifiers for Ed25519 in X.509 Certificates
- **BIP-173**: Bech32 encoding (Base32 address format)
- **CIP-19**: Cardano addresses (Bech32 convention alignment)
- **specs/ecies-envelope-encryption.md**: Cryptographic primitives, ECIES construction, item signatures
- **specs/channels-api.md**: REST API endpoints (local node API, not P2P)
- **specs/channel-naming.md**: Channel ID derivation, naming rules
- **specs/sdk-api-reference.md**: TypeScript SDK interface
- **cordelia-core/docs/architecture/network-model.md**: Scaling analysis, adversarial model, TLA+ specs (reference)
- **Coutts, D. et al.**: "The Shelley Networking Protocol" -- Cardano's Ouroboros networking design (peer governor, mini-protocol multiplexing)
- **Davies, N. & Coutts, D.**: "Introduction to the design of the Data Diffusion and Networking for Cardano Shelley" (IOG technical report)

---

## 15. Cross-Spec Review

Cross-spec review completed 2026-03-10. Nine issues identified (X1-X9) and resolved across all Phase 1 specs:

- **X1-X4**: ecies-envelope-encryption.md -- DM channel ID derivation, PSK rotation phase alignment, signed metadata envelope (is_tombstone + author_id encoding)
- **X5-X8**: channels-api.md -- GroupExchange -> Channel-Announce references, published_at cursor, Bech32 node IDs, bearer auth on identity endpoint
- **X9**: sdk-api-reference.md -- nodeId type description (Bech32 Ed25519 pubkey)
- **L1**: channels-api.md -- chatty/taciturn terminology replaced with realtime/batch (developer-facing terms)

---

## 16. Economic Model and Incentive Alignment

This section addresses the economic and game-theoretic properties of the protocol. Each subsection references an issue from the economic review (s&p#10).

### 16.1 Relay Economics (E1, E6)

Relays bear bandwidth and storage costs for channels they cannot read. Without incentive alignment, rational relay operators shut down at scale.

#### 16.1.1 Relay Contribution Tracking

Each node tracks per-peer contribution metrics:

```
PeerContribution {
    items_relayed:     u64    // Items this peer has forwarded to us
    items_requested:   u64    // Items we have requested from this peer
    bytes_received:    u64    // Total bytes received from this peer
    bytes_sent:        u64    // Total bytes sent to this peer
    contribution_ratio: f64   // items_relayed / max(items_requested, 1)
}
```

Updated on every Item-Push (PushAck) and Item-Sync (FetchResponse). The `contribution_ratio` measures how much a peer gives vs how much it takes.

#### 16.1.2 Relay Reputation and Peer Eviction

The peer scoring formula (§5.5) is extended with contribution weight:

```
score = (items_delivered / connected_duration_s)
      * (1 / (1 + rtt_ms / 100))
      * contribution_factor

contribution_factor =
    IF peer.is_relay THEN
        clamp(peer.contribution_ratio, 0.1, 2.0)
    ELSE
        1.0   // Personal nodes are not penalised for low contribution
```

**Effect:** Relays that silently drop items develop a low `contribution_ratio`. The governor's scoring (§5.4, §5.5) naturally demotes low-scoring relays from Hot to Warm to Cold. Relays that consistently drop items are evicted from the peer table entirely.

**Detection mechanism for relay defection (E6):**

1. **Cross-peer verification.** When a node receives an item from peer A, it records `(item_id, channel_id, received_from)`. If the same item later arrives from peer B, the node knows both A and B are honest for that item. If items routinely arrive from B but never from relay R (which claims to serve the channel), R's contribution_ratio drops.

2. **Probe items.** Every `probe_interval` (default: 300s), a node publishes a zero-length probe item to a random subscribed channel with `item_type = "probe"`. Probe items are regular items -- signed, encrypted, replicated. The node tracks which relays deliver the probe within `probe_timeout` (default: 60s). Relays that fail to deliver >50% of probes within timeout are flagged as defecting.

3. **Escalating consequence:**

| Defection signal | Action | Recovery |
|-----------------|--------|----------|
| contribution_ratio < 0.3 for 10+ min | Demote Hot → Warm | Ratio recovers above 0.5 |
| Failed >50% probes in 1 hour | Demote to Cold, notify peers via Peer-Sharing `exclude` flag | 24 hours, then re-evaluate |
| Failed >80% probes in 1 hour | Ban 24 hours | Escalating (§5.6) |
| Repeated ban (3x in 7 days) | Permanent ban, propagate ban to peers | Manual unban only |

4. **Ban propagation.** When a node permanently bans a relay for defection, it includes the relay's `node_id` in Peer-Sharing responses with an `exclude: true` flag. Receiving nodes add the relay to a watchlist (not auto-ban -- that would enable censorship attacks). If 3+ independent peers report the same relay as defecting, the receiving node auto-bans.

```
PeerShareEntry {
    addr:       SocketAddr
    node_id:    bytes(32)
    exclude:    bool        // true = reporting node has banned this peer
}
```

#### 16.1.3 Relay Incentives (Phase 3)

Phase 1 relays are operated by Seed Drill (bootstrapping cost absorbed). Phase 3 relay incentives:

- **SPO relay bundling.** SPOs running keepers already have infrastructure. Adding relay role is marginal cost (same binary, same machine). Keeper revenue (delegation) cross-subsidises relay bandwidth.
- **Relay credit ledger.** Per-epoch (5-day) bilateral ledger between relays tracking items forwarded. Relays with positive balance earn priority in peer selection. Phase 4: settle credit imbalances via ADA micro-payments.
- **Relay metrics in cordelia:directory.** Relay operators publish `items_relayed_epoch`, `uptime_percentage`, `bandwidth_served_gb` to the directory channel. Subscribers can prefer relays with good metrics.

### 16.2 Bootnode Rate Limiting (E2)

Bootnodes are discovery-only (§8.2) with minimal resource footprint (~50MB RAM, negligible storage). The bootnode/relay split (§8.2 vs §8.3) significantly reduces the exhaustion attack surface. Remaining mitigation:

#### 16.2.1 Bootstrap Rate Limits

| Limit | Default | Rationale |
|-------|---------|-----------|
| Max bootstrap connections per IP per hour | 5 | Prevent single-host Sybil exhaustion |
| Max bootstrap connections per /24 per hour | 20 | Prevent subnet Sybil |
| Max concurrent bootstrap handshakes | 50 | Bound bootnode CPU during handshake storms |
| Handshake timeout | 10s | Drop slow/stalled connections (§4.1.3) |

Bootnodes maintain a rolling window (1 hour) of connection attempts per source IP. Exceeding the per-IP limit returns QUIC `CONNECTION_CLOSE` with application error code `0x03` (rate limited). The connecting node should back off exponentially (initial: 30s, max: 600s).

#### 16.2.2 Bootnode Operational Cost

Post-split, bootnode operational cost is minimal:
- No item storage (no SQLite)
- No relay bandwidth (no Item-Push, no Item-Sync)
- Only Handshake + Peer-Sharing traffic
- Estimated: ~$5/month per bootnode (1 vCPU, 512MB RAM, low bandwidth)

This makes it feasible to run 5-10 bootnodes at negligible cost. Phase 3 SPOs can add bootnode role at near-zero marginal cost.

### 16.3 Storage Quota Enforcement (E5)

The channels-api.md §3.2 (publish) is extended with quota enforcement. See channels-api.md §9.1 for specification.

**Protocol-level enforcement (this spec):**

When a relay receives an item via Item-Push and the relay's local storage exceeds `max_relay_storage_bytes` (default: 10 GB, configurable):

1. Stop storing new items for the least-recently-active channel (LRU eviction)
2. Continue forwarding items (relay without storing)
3. Log warning: `relay_storage_full`
4. Metric: `cordelia_relay_storage_bytes` gauge

Relays degrade gracefully: they stop caching but continue forwarding. This prevents storage exhaustion from shutting down relay service entirely.

### 16.4 Bandwidth Amplification Limits (E11)

P2P bandwidth rate limits (complement to §9.2 message rate limits):

| Limit | Default | Scope |
|-------|---------|-------|
| `max_bytes_per_peer_per_second` | 10 MB/s | Per-peer inbound bytes (all protocols) |
| `max_push_items_per_channel_per_minute` | 1000 | Per-channel Item-Push rate on receiver side |
| `max_relay_fanout_per_second` | 100 items | Relay re-push rate cap |

Exceeding `max_bytes_per_peer_per_second` triggers QUIC flow control (receiver stops reading). Exceeding per-channel push rate triggers `PushAck.policy_rejected++` and eventual ban (§9.2).

The relay fanout cap prevents a single relay from saturating its outbound bandwidth on behalf of one channel. Relay processes re-push queue with token-bucket rate limiter (100 tokens/s, burst 200).

### 16.5 DM and Channel Creation Rate Limits (E9, E12, E13)

API-level enforcement in channels-api.md. Protocol-level complementary limits:

| Limit | Default | Scope |
|-------|---------|-------|
| Channel-Announce new channel IDs per peer per minute | 10 | Prevents rapid channel creation flooding announce |
| PSK-Exchange requests per peer per minute | 1 per channel | Already specified (§9.2) |

Exceeding channel announce rate: the receiving node drops excess ChannelJoined messages and logs a warning. No ban (may be legitimate during initial sync), but the peer's contribution score is not credited for dropped announcements.

### 16.6 Channel Name Registration Economics (E4, Phase 3)

Phase 3 on-chain channel registration model (extends channel-naming.md §8):

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Registration deposit | Cardano min-UTXO (~2 ADA) | Returned on voluntary deletion |
| Annual renewal fee | 0.5 ADA | Burned (not returned). Prevents indefinite squatting. |
| Expiry period | 365 days from last renewal | Name becomes available for re-registration |
| Grace period | 30 days after expiry | Original owner can renew at 2x fee. After grace: open. |
| Proof-of-use requirement | >= 10 items from >= 2 distinct authors in last 365 days | Single-author junk items don't count. Requires genuine multi-party use. |
| Activity-weighted renewal | < 10 items/year → 5x renewal fee (2.5 ADA) | Active channels pay 0.5 ADA. Low-activity channels pay more, making squatting expensive at scale. |
| Phase 1 → Phase 3 migration | 90-day priority window | Phase 1 channel creators get first-refusal on their names (E15) |

**Anti-squatting mechanism:** A channel that has fewer than 10 items from at least 2 distinct authors in the last 365 days fails the proof-of-use check. Channels that fail proof-of-use but have *some* activity (1-9 items, or single-author) may still renew at 5x the standard renewal fee (2.5 ADA/year). Channels with zero activity cannot renew at all. The name expires after the grace period.

**Community challenge (Phase 4):** Any entity can challenge a channel name registration by demonstrating higher genuine activity on a locally-created channel with the same name. Challenges are resolved by governance arbitration (§16.10). If the challenger's channel has more items, more authors, and longer history, the registration may be transferred. This provides a last-resort mechanism against squatters who game the proof-of-use threshold.

### 16.7 Keeper Economics (E3, E7, E8, Phase 3)

#### 16.7.1 Anchor Keeper Revenue (E3)

Channel creators who anchor on a keeper receive a revenue share from that keeper's delegation rewards:

- Keeper publishes `creator_share` in commercial policy (default: 10%)
- Share is proportional to the creator's channels' storage consumption on the keeper
- Settlement: epoch-aligned (every 5 days), credited to creator's delegation balance
- Phase 4: direct ADA payment via bilateral ledger

This gives channel creators a reason to anchor on keepers that attract delegators, and gives keepers a reason to attract popular channels.

#### 16.7.2 Keeper Quality Metrics (E7)

Keepers publish per-channel quality metrics to `cordelia:directory`:

```
KeeperQualityReport {
    keeper_id:          string      // Bech32 public key
    epoch:              u64         // Cardano epoch number
    channels_served:    u32         // Number of channels anchored
    uptime_pct:         f64         // Uptime percentage this epoch
    avg_replication_lag_ms: u64     // Average replication lag across channels
    items_served:       u64         // Total items served this epoch
    storage_used_mb:    u64         // Total storage consumed
}
```

Published every epoch. Subscribers and delegators can compare keepers on objective metrics. Phase 4 trust scoring (§13.2) aggregates these reports into a reputation score.

#### 16.7.3 SPO Cost-Benefit Model (E8)

For Phase 3 viability, keeper operation must be ROI-positive for SPOs. The delegation-only model is insufficient for small pools. Three revenue streams:

1. **Delegation rewards** (primary): Delegators choose SPOs running Cordelia keepers. Marginal delegation increase from Cordelia features.
2. **Channel creator share** (§16.7.1): Creators anchor on the keeper, keeper shares delegation revenue.
3. **Premium service fees** (Phase 3+): Direct ADA payment for premium tiers (>50 channels, >500MB storage, custom SLA). Collected per-epoch, keeper retains 100%.

**Cost reduction:** Keeper runs as a sidecar to existing cardano-node infrastructure. Shared compute, storage, and network. Estimated marginal cost: ~$20-50/month (not $100/month standalone). This brings ROI positive within reach for pools with 100K+ ADA delegation.

**If delegation insufficient:** Phase 4 introduces x402-style micropayments for storage/bandwidth. Each API call includes a payment channel reference. Settlement is epoch-aligned. This is the fallback, not the primary model.

### 16.8 Delegation Verification Timing (E17, Phase 3)

Epoch-aligned delegation checks (every 5 days) create a window for exploitation.

**Mitigation:**

1. **Entry check:** Delegation verified at channel subscription time (not just epoch boundary). Subscriber must meet tier threshold at subscribe time.
2. **Epoch re-check:** Standard epoch-aligned re-verification (Cardano snapshot).
3. **Graceful downgrade:** If delegation drops below tier threshold:
   - Existing data retained (not deleted)
   - New writes capped at lower tier limit
   - 1-epoch grace period (5 days) to restore delegation before tier reduction
   - Notification item published to subscriber's personal channel

### 16.9 Entity Type and Sybil Identity (E9, E10)

#### 16.9.1 Sybil Cost (E9)

Phase 1 accepts that identity creation is cheap (`cordelia init` ~1 second, zero cost). Sybil defence relies on:

- Connection limits per IP/subnet (§9.1)
- Per-entity rate limits on channel creation and DM initiation (§16.5, channels-api.md §9)
- Governor scoring penalises low-contribution peers (§5.5, §16.1.2)

Phase 3: Minimum ADA stake (10 ADA) required for channel creation on keepers. Free-tier limited to 2 channels per entity (keeper-enforced policy). This raises the Sybil cost from ~0 to ~$2.50 per identity for channel creation.

#### 16.9.2 Entity Type Spoofing (E10)

The protocol does not distinguish entity types by design (identity-privacy-model.md §3). An agent can claim to be human. This is a deliberate privacy choice: the protocol cannot verify claims about the physical world.

**Documented limitation:** Channel policies that rely on entity type discrimination (e.g., "humans only") are vulnerable to misrepresentation. Mitigation is social, not cryptographic:
- Operator-agent attestation chain (identity-privacy-model.md §5.3) makes agent identity verifiable for those who claim it
- Channel owners can require verifiable credentials (Phase 3, W3C VC alignment)
- Proof-of-personhood protocols are out of scope; channels requiring this should use external verification services

### 16.10 Directory Channel Governance (E14, Phase 3)

`cordelia:directory` is a well-known channel where keepers publish service manifests. It must not be a single point of failure.

**Phase 1:** Seed Drill operates the initial anchor node. Discovery also works via DNS SRV (§10.2) and hardcoded seeds (§10.4), so directory channel failure doesn't prevent bootstrap.

**Phase 3 governance model:**
- Directory channel ownership transfers to a **5-of-9 multi-sig** operated by the 9 highest-delegated SPO keepers
- Ownership rotated annually at the epoch following the anniversary
- Any 5 of 9 can approve channel policy changes (access rules, PSK rotation)
- If <5 signers are available, channel continues operating (read-only for manifests)
- Fallback: on-chain bootnode registry (§10) is independent of the directory channel

### 16.11 Keeper Reputation Cold-Start (E16, Phase 3)

New keeper SPOs have no track record. Mitigation:

1. **Cardano reputation carryover.** SPOs already have reputation from block production (SMASH, Daedalus, pool.pm). Cordelia:directory displays the SPO's Cardano pool metrics alongside Cordelia quality metrics (§16.7.2). A pool with 99.9% block production uptime is a credible keeper candidate.
2. **Pilot programme.** Seed Drill runs a pilot with 5-10 SPOs before general availability. Pilot keepers get "launch partner" badge in directory.
3. **Free tier as reputation builder.** New keepers can offer generous free tiers to attract initial users and build track record. Once quality metrics accumulate (3+ epochs), delegators have data to evaluate.

### 16.12 First-Mover Registration Advantage (E15, Phase 3)

Phase 1 channel creators get a 90-day priority window when Phase 3 on-chain registration launches (§16.6). During this window:

- A Phase 1 channel creator can register their channel name at standard cost (2 ADA deposit)
- If a different entity attempts to register the same name, the Phase 1 creator is notified and has 7 days to claim priority
- After the 90-day window, registration is first-come-first-served

This rewards early adoption without creating permanent unfairness.

---

*Draft: 2026-03-11. Review with Martin before implementation.*
