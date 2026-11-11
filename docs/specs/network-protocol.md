# Network Protocol Specification

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-10
**Scope**: Phase 1 (Encrypted Pub/Sub MVP)
**Implements**: WP3 (Pub/Sub API network layer), WP12 (Bootnode DNS)
**Depends on**: specs/ecies-envelope-encryption.md, specs/channels-api.md, [channel-naming.md](https://github.com/seed-drill/cordelia-node/blob/c3cc5756/docs/specs/channel-naming.md)

> **v1 status.** Transport, framing, handshake, keep-alive, peer-sharing and
> the governor stand. One kind of channel travels:
>
> - **A channel from its secret,** on five streams of its own, `0x10` to
>   `0x14` (§4.9), per the
>   [decision record of 2026-10-04](../decisions/2026-10-04-a-persons-devices.md)
>   §2.4. Every channel of a person's own is of this kind. These streams run
>   between a device and a relay, and between relays that work together, and
>   nowhere else. The [decision record of 2026-10-24 (removal)](../decisions/2026-10-24-removal-fails-safe.md)
>   adds to them, with no new stream and no new answer: a change entry says
>   its lineage in the clear; a relay keeps every head of the phrase's
>   channel, hands each before it says it holds the entry shown, passes each
>   on until it is taken, and names the role `heads` in its handshake; and a
>   device shows each head it keeps (§4.1, §4.9.2, §4.9.4 to §4.9.6).
> - **The older kind is gone** (the
>   [decision record of 2026-11-10 (older kind)](../decisions/2026-11-10-removing-the-older-kind.md),
>   rules 1, 2 and 7). No node of any role stores, sends, fetches or serves
>   it. Every node answers an Item-Sync (`0x05`) as an alpha.19 device does,
>   with no channels and no items, and refuses a Channel-Announce (`0x04`) and
>   an Item-Push (`0x06`) at the byte; a refusal resets that one stream, and
>   the connection goes on. Only the two sync requests and their answers, with
>   `ItemHeader`, stay on the wire, since alpha.19 decodes them (§4.5).
>   PSK-Exchange (`0x07`) and Pairing (`0x08`) have no messages. The bytes
>   `0x04` to `0x08` are never used again. The handshake keeps
>   `channel_digest` and `channel_count`, which every node sends for no
>   channels (§4.1). §4.4 to §4.8, §6 and §7 say only that they are gone.
> - **Swarm (§8.2.2) is gone:** no `swarm-init`, no trusted peers, no swarm
>   children. A configuration that still sets `[swarm]` or
>   `network.trusted_peers` loads; the keys are not read.
> - **Secret keepers (§8.5)** are deferred. The bootnodes (§8.3, §10) are the
>   two relays, `relay1` and `relay2.cordelia.seeddrill.ai:9474`
>   (`FALLBACK_PEERS`).
> - Specs this one cites that are now archived (`sdk-api-reference.md`, the
>   identity ADR) are in [`docs/archive/`](https://github.com/seed-drill/cordelia-node/blob/c3cc5756/docs/archive/README.md).
>
> The TLA+ model (`network-protocol.tla`) is of the governor and of the
> replication of items of the older kind (§4.4 to §4.6), which is gone. It
> has no model of §4.9.

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

**Windows and streams** (decision 2026-10-22, memory across connections,
rules 8 to 12; parameter-rationale.md §1 and §13). They bound what one
connection's peer can make a node hold. Every connection of every node,
in either direction, carries these transport settings (`transport_config`
in `transport.rs`):

| Setting | Value | Reason |
|---|---|---|
| Receive window of a connection (`QUIC_RECEIVE_WINDOW`) | 294,912 bytes, two small messages (288 KiB) | The largest message a device of this version sends is one small message (`SMALL_MESSAGE_BYTES`, 144 KiB, §9.3). A second can arrive while the first is read |
| Receive window of a stream (`QUIC_STREAM_RECEIVE_WINDOW`) | 32,256 bytes (31.5 KiB): seven eighths of the connection's window, divided by the streams a peer may open | Checked at compile time. A node reads the streams a peer opens one at a time. Every stream a peer may have open fits within seven eighths of the connection's window, so the streams queued behind the one being read cannot hold all of its credit. A stream the node opened itself, such as a relay's own fetch, always has the eighth that is left. Quinn announces more credit for the connection only once an eighth of its window has been read back (`MAX_DATA`), and that eighth is exactly what is left. At an eighth of the window a stream (36,864 bytes), a peer the node had dialled could open all eight of its streams and fill the whole window, so the node's own fetch waited out `STREAM_TIMEOUT_SECS`. A message larger than a stream's window arrives a window at a time as the node reads it; a small message takes five round trips |
| Send window (`QUIC_SEND_WINDOW`) | 294,912 bytes, two small messages | A write beyond it waits for acknowledgements, and the codec gives it up after `STREAM_TIMEOUT_SECS` |
| Bidirectional streams a peer may have open (`QUIC_MAX_BIDI_STREAMS`, `MAX_CONCURRENT_STREAMS`) | 8 | The inbound loop serves one stream at a time, so a stream beyond the first only waits. Each open stream may hold up to 32 KiB of quinn's reassembly beyond its data |
| Unidirectional streams, datagrams | none | No node uses them; quinn's default would keep 1.25 MB of datagrams unread |

**A connection with a relay configured by key keeps the settings that
every connection had before alpha.16:** 1 MiB a stream, 2 MiB a
connection and 2 MiB unacknowledged (`QUIC_LISTED_STREAM_RECEIVE_WINDOW`,
`QUIC_LISTED_RECEIVE_WINDOW`, `QUIC_LISTED_SEND_WINDOW`), and 64 streams
(`QUIC_LISTED_MAX_BIDI_STREAMS`). Passes and pulls between relays go a
full page (896 KiB) at a time, and at the settings above a pull of ten
pages would take longer than the 10 s between pulls. Quinn fixes a
connection's settings when the connection is made, so:

- A node dials a relay configured by key with `Endpoint::connect_with`
  and those settings. A device does the same; the default relays have
  compiled keys.
- A node accepts a connection with `Incoming::accept_with` and those
  settings where the connection comes from the address and port of a
  relay configured by key. Once TLS completes, it closes the connection if
  the certificate's key is not that relay's, before it reads anything on
  it.
- A relay configured by address alone gets the settings of every peer.

The windows announced are the receiver's own. So a device that dials its
relay by key may be sent full windows, while what it sends the relay is
held to the relay's windows for an unlisted peer.

**Pages between relays listed by key.** A receive window limits what the
*other* end may send, and quinn shows neither end the other's settings,
so the end that asks for a page bounds it:

- **A relay serves every relay listed by key the full page it asks for**
  (up to `ENTRY_PAGE_MAX_BYTES`, 896 KiB). It does so by the key in the
  peer's certificate, whatever the settings of the connection.
- **A relay asks a listed relay for `SMALL_WINDOWS_PULL_ENTRIES` (1)
  entry a page** where its own end of their connection does not carry the
  listed settings (`carries_listed_settings`). That happens when the
  listed relay's connection arrives from another address than the one
  configured, for example behind a NAT that changes its port. Such a page
  is at most one entry of the largest size, 65,773 bytes on the wire,
  within a small page. A full page across every peer's windows takes about
  6.0 s at a round trip of 200 ms and fails the stream timeout past about
  0.33 s. A page of one entry of the largest size takes about 0.73 s at
  200 ms, so a pass of ten such pages fits the 10 s between pulls.
- **Entries passed on to a listed relay go a small page to a message**
  (`to_pass_on`, at most `SMALL_PAGE_BYTES` of entries), since the pusher
  cannot see the other end's windows.

Where a relay's NAT keeps the port (a static or one-to-one NAT), its
operator should configure it at the relays it works with at the public
address it dials from: it then gets the listed settings at both ends and
full pages both ways. A relay dials from the port it listens on.

**What each exchange takes at a round trip of 200, 300 and 400 ms,** at
these windows. These are the decision record's §2.3 figures, measured
over in-process endpoints through a line that delays each datagram
(`what_each_exchange_takes_at_a_round_trip_of_200_ms` in `transport.rs`,
run by hand). The last column is the round trip past which the exchange
takes longer than `STREAM_TIMEOUT_SECS` (10 s); for a pass, it is the
round trip at which one of its pages does:

| What crosses | 200 ms | 300 ms | 400 ms | Fails past |
|---|---|---|---|---|
| A device's push of 128 KiB to its relay | 1.15 s | 1.70 s | 2.25 s | about 1.7 s |
| A device's pass of 10 pages of 128 KiB, dialling its relay by key | 3.64 s | 5.37 s | 7.20 s | about 5.5 s |
| The same pass, to a relay configured by address alone | 11.2 s | 16.7 s | 22.2 s | about 1.8 s |
| A device of the version before pushes 896 KiB | 6.03 s | 8.99 s | 12.0 s | about 0.33 s |
| A full page of 896 KiB between relays listed by key | 0.41 s | 0.61 s | 0.80 s | about 4.9 s |

A message larger than a stream's window takes about one round trip for
each 31.5 KiB. A device of this version sends nothing larger than a
small message, so its exchanges work at round trips up to more than a
second. Only a node of the version before sends messages large enough to
fail the stream timeout above about 0.3 s (§9.5).

**The kernel's receive batching of UDP (`UDP_GRO`) is off** on every
node's endpoint socket. It is turned off after quinn wraps the socket,
because quinn-udp turns it on when it wraps a socket (rule 10). With it
on, a stream frame of one byte keeps the whole batch of datagrams it
arrived in, which quinn's reassembler counts as one packet.

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
    |  [Peer added to governor peer table]       |
    |                                            |
    |--- Stream N: Keep-Alive, entries --------->|
```

**Stream ownership:** The initiator opens the first bidirectional stream (`open_bi()`), writes the protocol byte and `HandshakePropose`. The responder accepts the stream (`accept_bi()`), reads the protocol byte, and dispatches. For quinn, `open_bi()` returns split `(SendStream, RecvStream)`; use `tokio::io::join(&mut recv, &mut send)` to combine into a single bidirectional `AsyncRead + AsyncWrite` stream for the handshake functions. The responder's `accept_bi()` MUST run concurrently with the initiator's `open_bi().await` (e.g., via `tokio::spawn`), otherwise mutual TLS with client certs will deadlock.

**Transport parameters:** The QUIC transport MUST configure:
- `keep_alive_interval = 15s` -- sends QUIC PING frames to prevent idle disconnection. This is independent of the application-level Keep-Alive protocol (§4.2).
- `max_idle_timeout = 60s` -- connections with no traffic (including PING) for this duration are closed.

These parameters apply to both client and server transport configs on the quinn endpoint.

**Incoming connection accept:** The `incoming.await` call (QUIC/TLS handshake for inbound connections) MUST have a 10-second timeout. Without this, a stalled handshake blocks the accept loop and prevents ALL other protocol operations on the node. (See BV-23.)

**Endpoint shutdown lifecycle:** On SIGTERM, SIGINT or SIGQUIT, the node MUST:
1. Call `endpoint.close()` to send CONNECTION_CLOSE to all peers
2. Call `endpoint.wait_idle()` to drain in-flight streams and release the UDP socket, for at most one STREAM_TIMEOUT
3. Only then exit the process: within NODE_STOP_TIMEOUT and one STREAM_TIMEOUT of being told (40 s) in all (parameter-rationale.md §6)

Without `wait_idle()`, the UDP socket may not be released before the OS recycles the port. The next process on the same IP:port may receive stale QUIC packets from peers that haven't processed the CONNECTION_CLOSE yet, causing `open_bi()` hangs (MAX_STREAMS not granted on confused connection state).

Docker containers SHOULD set `stop_grace_period: 45s` (NODE_STOP_TIMEOUT, one STREAM_TIMEOUT, and a margin), so that a node is not killed before its own bound. The relay's `deploy/relay/compose.yml` does.

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

**A bound on a list or a message is raised on the receiving side one release before any sender relies on it.** Every list and every message is bounded where it is read (below; §9.3). A release that would send more raises the bound in the release before it, so a receiver that has that bound is already deployed when the first sender uses it. Lowering what a sender sends needs no such step: a release may do it by itself, as alpha.16 does for its pages and pushes to an unlisted peer (§9.3).

**How a message is read:** a message is a CBOR map whose first key is
`msg_type`, the message's name, followed by its fields; every version
writes it so. A receiver knows a stream's protocol from its protocol byte
before its first frame, and reads each frame as one of that stream's
messages, straight into its own type. It refuses a frame that is not a
map, whose first key is not `msg_type`, that names a message of another
stream, or that holds anything after the message, before it reads the
rest. Each list in a message is bounded where it is read, and a longer one
is refused at its first element too many (parameter-rationale.md §1).
Decoding a frame of 1 MB so costs at most 3 MB at its peak, where reading
the frame first as values of no type, to find the name, cost some 32
bytes for each byte of the frame.

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
| `0x04` | Channel-Announce | Gone: refused at the byte | §4.4 |
| `0x05` | Item-Sync | Gone: answered with nothing | §4.5 |
| `0x06` | Item-Push | Gone: refused at the byte | §4.6 |
| `0x07` | PSK-Exchange | Gone: no messages | §4.7 |
| `0x08` | Pairing | Gone: no messages | §4.8 |
| `0x09` | RouteACK | Gone, never built | §7.4 |
| `0x10` | Entry-Show | Request-Response | §4.9.2 |
| `0x11` | Channel-Prove | Request-Response | §4.9.1 |
| `0x12` | Entry-Pull | Request-Response (pull) | §4.9.3 |
| `0x13` | Entry-Push | Request-Response (push) | §4.9.4 |
| `0x14` | Relay-Entries | Request-Response, between relays that work together | §4.9.5 |

Stream lifecycle: the initiator opens a bidirectional QUIC stream, writes the protocol byte, then the first message. The responder reads the protocol byte to determine the handler. Unknown protocol bytes (0x0A+) cause the stream to be reset with application error code `0x02` (unknown protocol).

> **v1 status.** `0x10` to `0x14` are the streams of a channel from its secret
> (§4.9). They begin at `0x10`, apart from the bytes of the older kind, so
> that neither is read as the other. Only a relay serves them. The bytes
> `0x04` to `0x08` are never used again (decision 2026-11-10 (older kind),
> rule 7).

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

**Every node sends `channel_digest` and `channel_count` for no channels**
(decision 2026-11-10 (older kind), rule 7): an alpha.19 node reads them,
and no node carries a channel they could count.

**A relay of this version also names the role `heads`** (`RELAY_ROLE_HEADS`)
among its roles, in both messages: it keeps every head of a change entry,
and hands each (§4.9.2; decision 2026-10-24 (removal), rule 18). A node of
`v0.2.0-alpha.17` or earlier reads only `relay` and `bootnode` there and passes the other
over, and a list holds up to 8 roles (`MAX_HANDSHAKE_ROLES`). So the
protocol's version does not change: each end offers, and accepts, only its
own.

#### 4.1.2 Handshake Design: Privacy-First

**Key change from pre-pivot:** The handshake no longer includes the full channel list. Instead, it sends a `channel_digest` (SHA-256 of the sorted list of channel IDs). This reveals channel count but not channel identities.

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

Request-response. Initiated periodically (every 5 minutes) to 2-3 random warm/hot peers, by a node that is neither a personal node nor a relay: those two never start a request.

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

**Rationale:** In the pre-pivot design, gossiping group lists let any node map the full network's channel membership. Removing channel lists from peer-sharing closes this metadata leak.

**Peer selection for sharing:** The responder MUST shuffle the peer list before returning it. Each requester receives a random subset in a random order. This prevents all bootstrapping nodes from connecting to the same relays, distributing load across the relay mesh.

Additional preferences (applied before shuffle):
1. Recent activity (last_seen within 1 hour)
2. Diverse IP subnets (avoid returning peers on the same /24)
3. Exclude banned peers

**Address filtering on share:** The node MUST only share addresses of relay and bootnode peers. Personal node addresses are never shared (§8.2: personal nodes are outbound-only and should not receive unsolicited inbound connections).

**A personal node shares no peers.** A personal node answers every `PeerShareRequest` with an empty `PeerShareResponse`, whatever it is connected to. It answers, and does not refuse the stream. Every other role answers with the peers it knows ([decision record of 2026-10-14](../decisions/2026-10-14-a-personal-node-shares-no-peers.md)).

**Address validation on receive:** Before adding received addresses to the cold peer table, the node MUST filter out:
- RFC 1918 private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Loopback (127.0.0.0/8, ::1)
- Link-local (169.254.0.0/16, fe80::/10)
- The node's own listen address
- Addresses with port 0

Outbound connections to peer-shared addresses SHOULD be rate-limited to 1/second to prevent being used as a connection amplifier against third-party services.

### 4.4 Channel-Announce (0x04)

Gone (decision 2026-11-10 (older kind), rules 2 and 7): no node sends or
hears an announcement. Every node refuses a stream of `0x04` at the byte,
which resets that stream alone. Its messages, and §4.4.1 to §4.4.6 with
them, went.

### 4.5 Item-Sync (0x05)

Gone as a sync (decision 2026-11-10 (older kind), rule 7): no node fetches
or serves the older kind. Every node answers as an alpha.19 device does: a
`SyncChannelListRequest` with no channels, and each `SyncRequest` with no
items and `has_more: false`, up to 64 answers a stream; anything else ends
the stream. These two requests and their answers stay on the wire, with
`ItemHeader`, since alpha.19 decodes them. `SyncRequest` also has an
optional `after_seq`, `SyncResponse` an optional `last_seq`, and
`ItemHeader` an optional `slot` and `rev`, each left out where absent.

```
SyncChannelListRequest {}

SyncChannelListResponse {
    channel_ids: [string]
}

SyncRequest {
    channel_id: string
    since:      ?string
    limit:      u32
}

SyncResponse {
    items:    [ItemHeader]
    has_more: bool
}

ItemHeader {
    item_id:      string
    channel_id:   string
    item_type:    string
    content_hash: bytes(32)
    author_id:    bytes(32)
    signature:    bytes(64)
    key_version:  u32
    published_at: string
    is_tombstone: bool
    parent_id:    ?string
}
```

### 4.6 Item-Push (0x06)

Gone (decision 2026-11-10 (older kind), rules 2 and 7): no node pushes or
takes an item of the older kind. Every node refuses a stream of `0x06` at
the byte, which resets that stream alone; an alpha.19 relay drops its older
pushes after three tries (rule 8). Its messages, the item's routing fields
and RouteACK (`0x09`) went.

### 4.7 PSK-Exchange (0x07)

Gone (decision 2026-11-10 (older kind), rule 2): no node asks for or hands a
channel's key. The byte `0x07` has no messages.

---

### 4.8 Pairing (Device Enrollment)

Gone (decision 2026-11-10 (older kind), rule 2): the byte `0x08` has no
messages. A device is added by a hand-over in a pair channel (decision
2026-10-04 §6), which is an entry like any other (§4.9).

---

### 4.9 Entries of a Channel From Its Secret (0x10 to 0x14)

Five streams carry the channels of the
[decision record of 2026-10-04](../decisions/2026-10-04-a-persons-devices.md)
(§2.4 there): a channel is a secret, its ID is a public key derived from that
secret, and every entry is signed by its author and by the channel's key. A
relay needs no list of members and no state of a channel to serve them.

| Byte | Stream | Who opens it | What it carries |
|------|--------|--------------|-----------------|
| `0x10` | Entry-Show | A device, to a relay | One entry shown, whole or in short; the answer says what the relay holds |
| `0x11` | Channel-Prove | A device, to a relay | A proof that the connection holds a channel's key |
| `0x12` | Entry-Pull | A device, to a relay | A request for a page of a channel proved on this connection |
| `0x13` | Entry-Push | A device, to a relay | Entries to be stored |
| `0x14` | Relay-Entries | A relay, to a relay its operator lists | Which channels it holds, a page of one without the proof, and entries passed on |

They begin at `0x10`, apart from the bytes of the older kind. A peer that
does not know them refuses the stream, and reads none of them as one of its
own. Nothing of §4.1 to §4.8 is changed by them.

**Only a relay serves them.** A personal node and a bootnode answer none of
the five. In this version these channels travel between a device and a relay,
and between relays that work together, and nowhere else: a connection between
two personal nodes carries nothing of them (decision §4.6).

**One request on a stream, and one answer.** The opener writes the protocol
byte and one framed message (§3.1); the receiver writes one framed message
back. A relay serves these streams to peers that are Warm or Hot (§5.4.2).

**An entry travels as its bytes** (data-formats.md §9.2), inside a CBOR byte
string: 237 bytes and its content. Whoever receives one reads it strictly and
checks both signatures before it does anything else with it. A channel's ID
is 32 bytes and a proof 64: a message that holds one of another length is not
read.

#### 4.9.1 The Proof (0x11)

A relay hands a channel's entries only to a connection that has proved it
holds the channel's key (decision §2.4, item 3).

```
ChannelProve {
    channel: bytes(32)          // The channel's ID
    proof:   bytes(64)          // Signature by the channel's signing key
}

ChannelProved {
    proved:  bool               // Yes: the proof holds, and the relay holds the channel
}
```

The proof is an Ed25519 signature by the channel's signing key over:

```
"cordelia v2 proof"       the proof's own label
session's value     32    what both ends export from this one TLS session
prover's key        32    the node key of the end that proves
channel's ID        32
```

- **The session's value** is 32 bytes of keying material that both ends
  export from the connection's TLS session (RFC 8446 §7.5), under the label
  `EXPORTER-cordelia v2 session` with no context. The two ends of one
  connection get the same bytes, and no other connection gets them. So a
  proof cannot be replayed on another connection or later, and it needs no
  clock.
- **The prover's key is in what is signed** because both ends export the
  same value: without it, a proof sent back to the end that made it would
  hold there. It is not in the message. The relay takes it from the
  certificate that the peer presented (§2.2), and from nothing the peer says.
- **The signature is checked before the channel is looked up.** A channel
  that the relay does not hold and a proof that fails are answered alike:
  `proved: false`. A relay tells nobody which channels it holds, the relays
  it works with aside (§4.9.5).
- **A relay remembers a proof that held** for as long as the connection
  lasts, whether or not it held the channel then: a channel that arrives
  later is handed with no proof more. It remembers at most 1,024 channels
  for one connection (`MAX_CHANNELS_PROVED_ON_A_CONNECTION`). A proof for one
  more is answered as one that fails, and is not looked at.
- **A proof is use of a channel** (decision §2.5): a relay drops a channel
  whose key nobody has proved, and of which nobody has shown an entry it
  holds, for 90 days. A device proves the personal channel, and the channel
  of each name it holds, once on a connection and again after a day; and
  once a day the channel of every name that its personal channel lists,
  whether or not it syncs the name.

#### 4.9.2 Show (0x10), and Its Short Form

A connection shows a relay an entry, and is told what the relay holds from
that author in that slot (decision §2.4, item 5). It is how a change reaches
a device (§4.9.6), and it is the one thing a relay hands to a connection that
has proved no key.

```
EntryShow {
    entry:   bytes              // The entry, as its bytes on the wire
}

EntryShowShort {
    channel: bytes(32)
    author:  bytes(32)
    slot:    bytes(32)
    rev:     u64
    id:      bytes(32)          // SHA-256 of what is signed of the entry
}

EntryShown {
    answer:  ShowAnswer
}

ShowAnswer =
    "held"                              // The relay holds that very entry
  / "taken"                             // It held none from that author in that slot,
                                        //   or an earlier one, and took this one
  / { "another": bytes }                // It holds another, at that revision or a later
                                        //   one: here it is, as its bytes on the wire
  / { "refused": EntryRefused }         // It would have taken the entry, and did not
  / "whole"                             // Short form only: show it whole
  / { "other": { rev: u64, id: bytes(32) } }
                                        // Short form only: it holds another at that
                                        //   revision or a later one, or a head not yet
                                        //   handed whole here; no more is said

EntryRefused = "not_signed" / "no_room" / "over_limit"
```

**A whole show.** The entry is read from its bytes and both signatures are
checked before the store is looked at. What is shown may be taken, so it
counts against what the connection may push (§4.9.7). An entry that answers
(`another`) is signed like any entry, and counts against what the asker may
be handed, as anything fetched does.

**A relay hands every head before it says that it holds the entry shown**
(decision 2026-10-24 (removal), rules 14 and 16). In a slot whose entries
carry a lineage (the phrase's channel, data-formats.md §9.6), a relay keeps
every head: each entry that no other it keeps was made after, by the
lineages, up to 8 (`MAX_CHANGE_HEADS`), the highest numbers first. Shown an
entry whole, it first takes it as it takes a push (§4.9.4); shown one short,
it takes nothing. It then hands, one in each answer, each head that it keeps there and that it
has neither handed whole on the connection nor been shown whole there, the
lowest number first, and of two at one number the lower ID: whole
(`another`), or, to a short show, by its revision and ID (`other`), after
which the device shows whole and is handed it whole. Only a whole hand
counts as handed. Only once none is left does it answer `held`, `taken` or
`refused`. It hands no entry that the one shown is ahead of. The answers
are those of the versions before, so a device of `v0.2.0-alpha.17` or earlier reads
each as it did.

**After the first time on a connection, a show can be short.** A relay
remembers, for a connection, each entry that it was shown whole or handed
whole there in each author's slot, where the two signatures held, whatever
it answered: up to 16 in a slot (twice `MAX_CHANGE_HEADS`: the 8 heads it
can keep there, and the 8 a device can keep), the one remembered longest
put out first. It remembers at most 8 slots
(`MAX_SLOTS_SHOWN_ON_A_CONNECTION`): a ninth is not remembered, and its
shows are handed the same lowest head each time. All are forgotten when the
connection closes.

- **A short show of anything else,** a slot that the relay does not remember
  included, is answered `whole` from the connection's memory alone. The
  store is not looked at. So the short form tells nothing, and hands
  nothing, to anyone who has not shown that very entry whole, or been
  handed it whole, on that connection.
- **A short show of an entry remembered** is answered from the store:
  `held`; `whole`, where the relay holds none or an earlier one; or `other`,
  with the revision and ID of the one it holds. The answer to a short show
  never carries an entry. A device that is told of another which it does not
  keep shows its own whole, and is answered with the entry.
- **Why.** The entry of the phrase's channel is 32 KB and a device shows it
  on every pass. Whole each time, that is some 280 MB a day from each idle
  device to each relay.

**A show is use of a channel** where the relay holds the entry shown, as a
proof is.

#### 4.9.3 Pull (0x12)

```
EntryPull {
    channel: bytes(32)
    mark:    bytes(8)           // The mark of the holding that `after` is a place in;
                                //   all zeros where the asker has no place yet
    after:   u64                // The place after which the page starts; 0 is before the first
    limit:   u32                // The most entries to hand
}

EntryPulled {
    entries: [bytes]            // Each as its bytes on the wire, in the order the relay
                                //   stored them. At most 100
    next:    u64                // The place to ask after next
    mark:    bytes(8)           // The mark of the holding that `next` is a place in
}
```

- **A place is a count of the channel's own:** the order in which the relay
  stored that channel's entries, from 1. It says nothing of any other
  channel.
- **A mark is 8 random bytes that are one holding's own.** A relay that
  drops a channel and takes it again counts from 1 again, under another
  mark. Where the mark asked with is not the mark of the holding the relay
  has now, the channel is handed from the start, whatever `after` says.
- **A channel that was not proved on this connection** is answered as one
  that is not held: no entries, and the place and the mark that were asked
  with. The store is not looked at.
- **A channel that was proved and is not held** is answered with no
  entries, the mark of no holding (all zeros) and `next` 0: whoever holds its
  key then knows that nothing it sent is there.
- **A page** holds at most 100 entries (`ENTRY_PAGE_MAX_ENTRIES`) and at
  most 896 KB of them on the wire (`ENTRY_PAGE_MAX_BYTES`, which leaves 128
  KB of the 1 MB message for what is around them). It always has room for
  one entry, whatever its size. A page that holds more than 100 entries is
  not read.

#### 4.9.4 Push (0x13)

```
EntryPush {
    entries: [bytes]            // Each as its bytes on the wire. At most 100
}

EntryPushed {
    answers: [PushAnswer]       // One for each entry, in the order they were sent
}

PushAnswer =
    "stored"
  / "held"                      // The relay holds that very entry
  / "older"                     // It holds a later one from that author in that slot
  / { "refused": EntryRefused }
  / "another"                   // It holds another entry from that author in that slot
                                //   at that revision: the author signed two
```

A relay stores an entry only if both signatures hold and it is within the
limits (decision §2.4, items 1 and 2). It keeps the newest revision for each
author in each slot, and compares no author's entries with another's. **An
entry with a lineage** (data-formats.md §9.6) is kept by its lineage instead
(decision 2026-10-24 (removal), rule 14): one that a head kept was made
after, or the same statement again, is not stored (`older`, or `another` at
that revision); one made after some heads replaces them; one made apart
from all is kept beside them, up to 8 (`MAX_CHANGE_HEADS`), the highest
numbers first. An entry with no lineage is kept only where no entry of its
author in the slot, a head among them, has its revision or a higher one,
and it replaces no head.

- **`not_signed`:** the bytes are not an entry's, or a signature does not
  hold, or a key is one that anyone can sign for.
- **`no_room`:** with the entry the relay would hold more than its cap for
  this kind of channel, or the entry's channel more than one channel may (16
  MB, `MAX_ENTRY_CHANNEL_BYTES_AT_RELAY`). A write that would take a relay
  past its cap is refused and drops nothing. A newer revision of an entry it
  holds, that is no larger, is never refused for room. A relay counts a slot
  whose entry carries a lineage at twice that entry's size, from when it
  takes the first such entry there (`CHANGE_HEADS_ROOM`, decision 2026-10-24
  (removal), rule 15): a second head there then always has room. In a slot
  that is new, the room for both is asked as for any new entry: where the
  relay has no room for both, the first entry is refused for room itself.
  Where the first such entry replaces one of the version before (a person's
  first change made on this version), it is taken as a replacement that is
  no larger, and the second share is counted only where the relay has the
  room; where it had none (a full relay, during the change-over), a second
  head there is refused for room, as any new entry is. It drops no channel
  to make room.
- **`over_limit`:** the sender's address has made the relay take as many new
  channels as one address may in an hour (256,
  `NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR`).
- **`another`:** the entry was not stored, and is not sent again: no
  receiver takes it over the other. The author's next entry in the slot goes
  above both.

A push is taken as one write: every entry is answered for, or the push is
not answered and nothing of it is stored. A push or an answer that holds
more than 100 things is not read. An answer that does not say one thing for
each entry says nothing of any.

**A device goes on past what a relay refuses for room.** What follows the
refused entry in a channel is still offered, since a delete, or a
replacement that is no larger, makes room. The refused entry is kept apart
and sent again after a wait that doubles.

**A relay sweeps old deletes** (decision §2.3). An entry says in clear
whether it is a delete, and a relay reads nothing else of it. Once an hour a
relay drops each slot in which every entry that it holds, of every author,
is a delete that it has held for 90 days (`KEYED_TOMBSTONE_RETENTION_DAYS`).
A slot in which one author's delete stands beside another author's text
stays whole: no key's delete sweeps away what another key wrote. The
channel's room follows, and a channel of which nothing is left is held no
more: a pull of it is then answered as for a channel that is not held. A
device sweeps its own store by a rule of its own (data-formats.md §10.1).

#### 4.9.5 Between Relays That Work Together (0x14)

Relays that their operator lists together pass entries between them without
the proof (decision §2.4, item 6). **A listed relay is one whose key the
operator configured** (`key` of a `[[network.bootnodes]]` entry, or one of
the two default relays, whose keys are compiled in), once its name has
resolved. The key is the one in the peer's certificate. A relay that is configured by address alone is not
listed: whoever came from that address would be handed every channel. The
stream is refused for every other peer, and a node that is no relay refuses
it from everyone.

```
RelayChannelsAsk {
    after:  bytes(32)           // The ID after which the page starts; all zeros is
                                //   before the first
    limit:  u32
}

RelayChannelsHeld {
    channels: [RelayChannel]    // In the order of their IDs. At most 1,000
}

RelayChannel {
    channel:    bytes(32)
    mark:       bytes(8)        // The mark of the sender's holding of it
    held_since: i64             // Since when the sender has held it
    used_at:    i64             // When it was last used, here or at a relay that told it
    places:     u64             // The place of the entry stored last in this holding
}

RelayPull {                     // Answered with EntryPulled; needs no proof
    channel: bytes(32)
    mark:    bytes(8)
    after:   u64
    limit:   u32
}

RelayPush {                     // Answered with EntryPushed
    entries: [RelayEntry]       // At most 100
}

RelayEntry {
    entry:      bytes           // The entry, as its bytes on the wire
    held_since: i64             // Since when the sender has held the entry's channel
    used_at:    i64             // When that channel was last used, as far as the sender knows
}
```

Each time is in seconds, in UTC, by the clock of the relay that says it.

- **What is passed on.** An entry that a relay takes, from anyone, is passed
  on to the listed relays that are connected, but for the one it came from,
  every 5 seconds (`ENTRY_OFFER_INTERVAL_SECS`). Nothing is tried again:
  what did not arrive is pulled. **A head is the exception** (decision
  2026-10-24 (removal), rule 17): each head a relay stores, from a push, a
  relay it works with or a show, is offered again at each offer to each
  listed relay that has not answered for it, connected or not when it was
  taken, until that relay answers, a refusal included. One that the relay
  no longer keeps, or that a later head was made after, waits no more. What
  waits is in memory: after a restart the pull carries what was not taken.
- **What is pulled.** Every 10 seconds (`RELAY_ENTRY_PULL_INTERVAL_SECS`) a
  relay asks each listed relay which channels it holds, and pulls what it
  lacks of them: at most 10 pages of one channel in a pass, and at most 10
  pages of the list (10,000 channels), going on in the next pass from where
  this one stopped.
- **How long a channel has been held travels with it.** A relay counts a
  channel as held from the earlier of two times: when it took it itself, and
  when a listed relay says that it took it, also for a channel it already
  holds. A relay over its cap drops the channels it has held for the
  shortest time first. So the phrase's channel, which is the channel of a
  person's that a relay has held longest, is still the last of that person's
  to go at a relay that took them from one it works with.
- **When a channel was last used travels with it too.** A relay that has a
  channel only from a relay it works with sees no proof and no show of it.
  The later of two "last used" is kept, never later than the relay's own
  clock. A channel that is new at a relay from a listed relay was last used
  when that relay says: taking it from a relay is no use of it.
- **Only a listed relay can say either,** and a listed relay is not counted
  against the limits of §4.9.7 or the allowance of new channels.

#### 4.9.6 What a Device Does: the Show First

A device is a personal node that follows a recovery phrase. One that follows
none opens none of these streams, but for the pair channel at the end of this
section.

**A show comes before everything, and it is a rule of the connection**
(decision §4.6). Each device keeps the change entry of the change it follows
(an entry of the phrase's channel, which carries the statement of the
person's devices), and of each head it sets aside, up to 8 in all
(decision 2026-10-24 (removal), rule 1). On a connection to a relay, until
the device has shown the change it follows there and dealt with what it was
answered, it sends nothing in a channel of its own and takes nothing from
one. **On every pass it shows the change it follows first, and then each
head set aside** (rule 18): at a relay that names the role `heads` (§4.1),
every one; at one that does not, none numbered above the change followed,
since such a relay would take it in place of a removal. A head set aside
that a relay answers with another entry is not shown again in that round,
and at a relay that does not name the role, not on that connection. While
the show of the change followed waits after an answer that gave no leave,
each head is still shown. A round has room for 23 shows (`SHOWS_IN_A_PASS`,
three times `MAX_CHANGE_HEADS` less one). Only the answer to the show of
the change followed is the relay's latest answer, for the status. The rule
is kept as a rule of time, called **leave**:

- **A device has leave on a connection for 10 seconds** (`SHOW_LEAVE_SECS`)
  from an answer there, to the show of the change it follows, which says
  that the relay holds no change that the device does not keep: `held`;
  `taken`; or `refused` for room or for the address's allowance (the relay
  would have taken it). **A fourth case:** at a relay that does not name the
  role `heads`, one that hands, twice in one round, a head the device keeps
  set aside: such a relay keeps one entry, and holds that head alone. At a
  relay that names the role, that ends the round and gives no leave: the
  relay lacks the change, and the status says so.
- **No other answer gives leave:** not `another`, or `other` (the device
  deals with the entry, and shows again what it then keeps; an answer that
  hands a head it keeps does not end the round); not `whole` (it shows it
  whole); not a stream that is reset or that times out. The show of a head
  set aside neither gives leave nor takes it away.
- **A stream to prove, pull or push is opened only with leave,** and leave
  is asked again before what came back on it is taken: what arrives after
  the leave has run out is dropped, and asked for again.
- **Leave ends at once, at every relay, when the entry that the device keeps
  changes.** A request is sent only under the change entry that it was built
  under.
- **A closed device has no leave anywhere** (it follows no clear change,
  decision 2026-10-24 (removal), rule 10), and nor has one that has stopped,
  or one that was answered with a change and could not apply it. A closed
  device sends the delete it wrote over a hand-over that a relay holds, and
  nothing else.
- **From the moment a device knows that the secret it follows is not
  clear,** it sends nothing more under it (rule 5): the moment is the
  commit that keeps the change or the record that makes it so, before any
  apply or move waits for the sync cycle. A request built before is not
  written, and a push open at that commit and not yet answered is reset:
  only what the relay already had whole can be stored.
- **Whatever finds no leave shows again by itself:** the pass, the timer
  that sends, and a publish. The first show on a connection is whole, and
  the later ones are short. A show that gets no leave is made again after a
  wait that doubles.

**A device that wakes asks every relay first.** When the node starts, or
reaches a relay after having reached none, it neither takes from a channel
of its own nor sends to one until each relay it is set up with has answered
a show and its answer is judged (decision 2026-10-24 (removal), rule 5),
or 30 seconds have gone since the first of them was reached
(`WAKE_WAIT_SECS`). A machine that slept wakes: where the time of day has
run ahead of the clock that leave is measured on by more than a leave lasts,
every leave is dropped.

**A pass.** Every 10 seconds, at each relay where it has leave, for the
personal channel and the channel of each name it holds: it proves the
channel's key (once on a connection, and again after a day), pulls from the
place it keeps, and pushes what that relay has not been sent. In a pair
channel in which it has something to send it only pushes: it reads nothing
there but with a typed key (below). Every 2 seconds, and when something is
written, it pushes what waits. Each relay has its turn by itself, and one
relay never holds up another once the device is awake.

**What a device checks.** The same two signatures, on what a relay sends it.
Further, in a channel of its own it stores an entry only if its signer
counts: a device of the statement it has applied, or one added since under
that statement (decision §4.4), and not a key it knows to be removed, on any
branch (decision 2026-10-24 (removal), rule 6). It takes nothing from a
channel of a generation it has left, and a closed device takes nothing in a
channel of its own.

**A carry that a person asks for reads through one door** (decision §7.3,
§9). `cordelia sync carry` and `cordelia recover` read, at each relay, a
channel of a generation that the device has left, or never held: the device
proves that channel's key and pulls it, page by page, within what it takes
from a relay in a minute, and for two minutes at most (`CARRY_READ_MAX_SECS`).
It stores nothing of what it pulls there, keeps no place, and pushes nothing.
The proof is the node's own where it holds the channel's secret; where it
does not, a command that was typed the recovery phrase makes the proof for
each connection, over the session's value, and the node is handed no secret.
What is read comes into the device's own channels only through the one
function that judges a version for a carry.

**One channel is read without leave:** the pair channel of a key typed at
`cordelia accept`, for the hour that `accept` allows. A device that follows
no phrase has nothing to show, and one that has stopped has no leave, and
each has to be handed a change. It proves that channel and pulls its first
page, and writes nothing there.

**A device paces itself.** It makes at most 2,250 requests a minute of one
relay on the streams that prove, pull and push
(`OWN_ENTRY_REQUESTS_PER_MINUTE`, three quarters of what a relay allows),
pushes at most 1.5 MB a minute (`OUTBOX_BYTES_PER_MINUTE`), and takes from
one relay in a minute no more than a relay may hand a connection. Its shows
are not held back by this, and are few.

#### 4.9.7 The Limits on These Streams

The limits on bytes are the ones the older kind of channel had, with the
same numbers. Bytes and
requests are each counted for the connection and for its address: all the
connections from one address share 5 times a connection's allowance
(`MAX_CONNECTIONS_PER_IP`). Requests on these streams have a count of their
own. New channels are counted by address alone.

| What | Limit | Counted as | Over it |
|------|-------|-----------|---------|
| Requests on the five streams, all together | 3,000 a minute for a connection (`ENTRY_REQUESTS_PER_PEER_PER_MINUTE`) | One for each stream opened | The stream is reset; a breach |
| Bytes pushed and shown | 2 MB a minute (`PUSH_BYTES_PER_PEER_PER_MINUTE`) | Each entry as its content and 1 KB (`ENTRY_OVERHEAD_BYTES`). A short show, and a frame that is no request for its stream, as bytes that are no entry's: every one of them beyond an entry's clear fields, and 1 KB | The request is refused whole; a breach |
| Bytes handed in a page | The same 2 MB a minute, less the room below | Each entry as its content and 1 KB | The pull is refused as "not now"; no breach |
| Bytes handed in the answer to a show | The same 2 MB a minute | The entry as its content and 1 KB | "Not now" once the asker is over; no breach |
| New channels from one address | 256 an hour (`NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR`) | One for each channel the relay takes that it did not hold | `over_limit` for the entry |

- **3,000 requests a minute** is sized for a device with 256 names, which
  is what an address may make a relay take in an hour: a pull of each every
  ten seconds, and of the personal channel (1,542 a minute); its day's
  proofs in one burst, as many as a relay remembers for a connection
  (1,024); a show for each pass and each time it sends; and what it pushes.
- **Three breaches in ten minutes cut a peer off,** and its address is
  refused for fifteen minutes (`BAN_TRANSIENT_SECS`, §5.6).
- **A pull that is refused for the asker's bytes is no breach:** the relay
  sized the page, and the asker cannot know its room. The stream is reset
  with the rate limit's code (`0x03`), and nothing is counted. Where the
  asker has no room for even the smallest entry, that is decided before the
  store is read.
- **The room kept for the answer to a show.** A relay sizes a page so that
  66,560 bytes are left in the key's allowance and in the address's
  (`SHOW_ANSWER_ROOM_BYTES`: one entry of the largest size, as it is
  counted), and of the requests on these streams only the entry that answers
  a show uses that room. So a device that pulls at its full rate, or shares
  its address with one that does, is still told of a removal.
- **The answer to a show is handed while the asker is not yet over its
  bytes,** so it can take the asker over by one entry and no more. After
  that a show that would be answered with an entry is refused as "not now",
  with no breach, until the minute frees. The answers that carry no entry
  are always given.
- **A relay writes that a channel was used at most once an hour**
  (`ENTRY_CHANNEL_USED_STEP_SECS`), and never an earlier time than the one it
  has: a proof, or a show, is otherwise a write to its disk for whoever
  asks.
- **Not defended** (decision §2.5): the allowance, the limit on connections
  and the limit on bytes are all by address. Whoever is at the same address
  as a device can use each up, and a change and the channels that follow it
  then wait at that relay.

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
| **Hot** | Open, keepalive + data | All above + the streams of entries (ss4.9), at a relay | Active data peer. |
| **Banned** | Closed | None | Violation cooldown. Duration depends on tier (ss5.6). |

**Critical property:** When a peer is demoted Hot->Warm, the QUIC connection stays open. Only data protocols stop. This makes Warm->Hot promotion near-instant (start streams on existing connection) vs Cold->Warm (full QUIC handshake). The Warm set is a pre-connected ready reserve that provides fast failover and enables network-size-independent convergence.

**Transitions:**

| From | To | Trigger | Cost |
|------|----|---------|------|
| Cold | Warm | Governor step 3, `warm < warm_min` | QUIC handshake (~1-2 RTT) |
| Warm | Hot | Governor step 4 or 6, random promotion | ~0 (start data streams) |
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
    rtt_ms:          ?f64           // Latest RTT measurement
    last_activity:   Instant        // Last keepalive or item received
    bytes_in:        u64            // Total bytes received
    bytes_out:       u64            // Total bytes sent
    probes_sent:     u32            // Probe items expected from this peer (§16.1.2)
    probes_received: u32            // Probe items actually received
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
    dial_policy:    DialPolicy // "all" | "relays_only": by the role (below)
}
```

**`hot_min_relays`:** Independent target from `hot_min`. Ensures relay backbone connectivity. On each governor tick, if fewer than `hot_min_relays` relays are in the hot set, promote a random warm relay to Hot (bypassing the regular random selection for non-relay peers). This guarantees items reach the relay backbone for fan-out.

**`dial_policy`:** Controls which peers the governor will connect to. `all` = any discovered peer. `relays_only` = only peers that identified as relay during handshake. A personal node dials relays only, and every other role any peer: the role sets it, and no key of the configuration does. `trusted_only` is gone with the trusted peers (decision 2026-11-10 (older kind), rule 2).

**Configuration validation (enforced on startup, node MUST refuse to start if violated):**
```
hot_min >= 1
hot_min <= hot_max
hot_min_relays <= hot_max
hot_max <= warm_max
warm_min >= hot_min
cold_max >= warm_max
tick_interval_secs >= 1
keepalive_timeout_secs >= 60     (>= 2x keep-alive interval of 30s)
min_warm_tenure_secs >= 60
hysteresis_secs >= tick_interval_secs
churn_fraction in (0.0, 1.0]
```

### 5.3.1 Trusted Peers

Gone (decision 2026-11-10 (older kind), rule 2): `network.trusted_peers` is
not read. A configuration that still sets it loads.

### 5.4 Tick Logic (every `tick_interval_secs`, default: 10s)

Executed in order:

1. **Unban expired**: Banned peers with expired ban duration → Cold.
2. **Reap dead**: No keepalive for `keepalive_timeout_secs` (default: 90s) → Hot→Warm, Warm→Cold. Connection closed.
3. **Promote Cold→Warm**: If `warm_count < warm_min`, connect to cold peers. Prefer peers with channel overlap. **Failure tracking:** After `max_connection_retries` (default: 5) consecutive failures, stop trying until the peer's backoff expires (exponential, base 30s, cap 900s). Clear failure count after `clear_failure_delay` (default: 120s) of being Hot.
4. **Promote Warm→Hot**: If `hot_count < hot_min`, promote from eligible warm peers. Guard: `min_warm_tenure_secs` (default: 300s) -- peer must be warm for 5 min, UNLESS `hot_count < hot_min` (bootstrap bypass). Guard: `hysteresis_secs` (default: 90s) -- recently demoted peers ineligible. **Anti-eclipse: promotion is RANDOM among eligible warm peers, not best-scoring.** This prevents an attacker from gaming their score to get promoted faster than honest peers (cf. Cardano's `simplePromotionPolicy`).
4a. **Ensure relay connectivity**: If fewer than `hot_min_relays` relay peers are Hot, promote a random warm relay to Hot. This bypasses the regular random selection and the tenure guard (same urgency as `hot < hot_min`). Evaluated after step 4, independent of `hot_count`.
5. **Demote Hot→Warm**: If `hot_count > hot_max`, demote hot peers until it is not. Stale peers (no keep-alive answer for `stale_threshold_secs`, default: 1800s) are demoted first; there is no score after that (§5.5).
6. **Churn (hot)**: Every `churn_interval_secs` (default: 3600s) plus a jitter drawn at random, uniform from 0 to `churn_jitter_secs` (default: 300s), once for each churn when the one before it runs, demote 1 random hot peer to Warm and promote 1 random warm peer to Hot in its place, so the hot count does not change. The peer demoted is chosen among hot peers at random, but a relay is never demoted by churn while no more than `hot_min_relays` relays are hot, so churn never leaves fewer hot relays than step 4a keeps. The peer promoted is chosen at random (as in step 4, anti-eclipse) among the warm peers that pass step 4's guards with none bypassed: `min_warm_tenure_secs` and `hysteresis_secs`, and no bootnode. It is chosen before the demotion, so the peer just demoted is never the one promoted. If no hot peer may be demoted, or no warm peer passes, nothing moves: a demotion with no peer to take its place explores nothing and only shrinks the hot set, which step 4 refills only below `hot_min`. Churn runs only while `hot_count > hot_min`. Moving a peer between Hot and Warm opens and closes no connection, so a personal node keeps the relays it is set up with (decision 2026-10-17 §2). This forces hot-tier exploration and prevents topology ossification.
7. **Churn (warm)**: Same interval, swap `churn_fraction` (default: 0.2) of warm peers with random cold peers. A personal node never closes, by churn, its connection to a relay it is set up with: each is one the person chose (decision 2026-10-17 §2).
8. **Evict excess cold**: If `cold_count > cold_max`, remove peers with most connection failures first, then oldest-seen.

### 5.4.1 Immediate Promotion on Connect

When a new peer connects (inbound or via peer-sharing):
- If `hot_count < hot_min`: promote directly to Hot (bootstrap urgency, bypass tenure guard). Reset `disconnect_count`.
- Otherwise: promote to Warm only. The peer must earn Hot via the `min_warm_tenure` guard and random promotion at the next tick.

This prevents Sybil attacks: an attacker connecting many identities can only get `hot_min` (default: 2) peers into Hot immediately. Additional peers must survive the 5-minute tenure guard and random selection.

### 5.4.2 Protocol-per-State Table

| Protocol | Cold | Warm (personal) | Warm (relay) | Hot |
|----------|------|-----------------|--------------|-----|
| Handshake (0x01) | On promotion Cold→Warm | -- | -- | -- |
| Keep-Alive (0x02) | -- | YES | YES | YES |
| Peer-Sharing (0x03) | -- | YES (after `min_warm_tenure`) | YES | YES |
| Channel-Announce (0x04), Item-Push (0x06) | -- | Refused (§4.4, §4.6) | Refused | Refused |
| Item-Sync (0x05) | -- | Answered with nothing (§4.5) | Answered with nothing | Answered with nothing |
| PSK-Exchange (0x07), Pairing (0x08) | -- | Gone (§4.7, §4.8) | Gone | Gone |
| Entries (0x10 to 0x14, §4.9) | -- | Not served | YES | Relay: YES. Personal: not served |

> **v1 status.** No node serves the data protocols of the older kind,
> whatever a peer's state (decision 2026-11-10 (older kind), rule 7): it
> answers an Item-Sync with nothing, as a device that holds no such channel
> would, so that an alpha.19 relay which asks its devices, and the relays it
> lists, what they hold asks again at its usual pace; and it refuses an
> Item-Push and a Channel-Announce at once. The streams of §4.9 are served by
> a relay alone, to peers that are Warm or Hot, and `0x14` only to a relay
> that its operator lists by key.

### 5.5 Peer Scoring

> **v1 status.** The governor scores no peer: excess demotion orders by
> staleness alone (§5.4 step 5). The score below was items delivered, which
> was always 0 once no node carried the older kind, and it is gone, with
> `ema_alpha` read by nothing (decision 2026-11-10 (older kind), rule 2).
> What follows is the design before.

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
| Protocol violation detected | On invalid message/signature | `ban_peer(node_id, reason, tier)` |
| Connection attempt failed | On connect_to error | `mark_dial_failed(node_id)` |
| Trust decay event | On rate breach, protocol violation, escalation skip | `decay_trust(node_id, reason, amount)` |
| Trust recovery event | On item delivery, sync completion | `recover_trust(node_id, amount)` |

Without these calls, the governor is deaf -- it cannot score, demote, ban, or reconnect peers based on real behaviour.

### 5.5.2 Peer Trust

Each peer carries an inverse trust score (1.0 = fully trusted, 0.0 = banned) orthogonal to the performance-based `score_ema` (§5.5). Performance measures throughput and latency; trust measures behaviour.

```
PeerTrust {
    score: f64,              // 0.0 (banned) to 1.0 (fully trusted)
    last_decay_reason: Option<String>,
    last_decay_at: Option<Instant>,
}
```

**Initial score:** New peers start at `TRUST_INITIAL = 0.5` (neutral). Existing peers with sustained good behaviour drift toward 1.0.

**Decay events** (immediate):

| Event | Decay | Rationale |
|-------|-------|-----------|
| Rate limit breach (any bucket) | -0.10 | Existing §9.2 behaviour, now continuous |
| High-TTL discovery without prior low-TTL | -0.05 | Escalation skipping pattern (§7.5) |
| Invalid content hash on forwarded item | -0.15 | Data integrity violation |
| Protocol violation (wrong message type) | -0.10 | Existing, now feeds trust score |
| Push of item we already have (duplicate) | -0.02 | Minor: may be timing, not malicious |
| Forwarding item with expired/invalid routing token | -0.05 | Possible replay or corruption |

**Recovery events** (slow):

| Event | Recovery | Cap |
|-------|----------|-----|
| Successful item delivery (new items to us) | +0.01 per item | 1.0 |
| Successful sync cycle (items exchanged) | +0.005 | 1.0 |
| Time-based passive recovery | +0.01 per hour | 1.0 |

Recovery is asymmetric by design: one bad event costs more than many good events earn. This makes sustained misbehaviour expensive even if interleaved with legitimate traffic.

**Thresholds:**

| Threshold | Action |
|-----------|--------|
| score < 0.3 | Demote from Hot to Warm (reduce influence) |
| score < 0.2 | Deprioritise in sync target selection |
| score < 0.1 | Ban (Transient tier, §5.6) |
| score = 0.0 | Ban (Systematic tier, §5.6) |

**Effective score:** Governor promotion decisions combine both dimensions:

```
effective_score = score_ema * trust_score
```

This naturally demotes high-performing bad actors and retains honest slow peers. A fast relay that breaches rate limits is demoted despite high throughput.

**Operator configuration:** All trust parameters are configurable (§12.5). Different deployments have different risk profiles -- enterprise intranets may want aggressive decay while open community relays may prefer relaxed thresholds.

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

**Trust-score-driven banning:** Peer trust score thresholds (§5.5.2) complement violation-based banning. Trust score < 0.1 triggers a Transient ban (900s base, standard escalation). Trust score = 0.0 triggers a Systematic ban (28800s base). Trust thresholds add a continuous behavioural signal to the discrete violation tiers above -- a peer that accumulates many minor infractions (each below the ban threshold individually) will eventually cross a trust threshold and be banned.

---

## 6. Replication

### 6.1 Culture Dispatch

Gone (decision 2026-11-10 (older kind), rule 2): no node writes, pushes or
syncs an item of the older kind. A channel from its secret is sent by a
device's passes (§4.9.6).

### 6.2 On Remote Receive

Gone (decision 2026-11-10 (older kind), rule 2). What a relay and a device
do with an entry they receive is in §4.9.

### 6.3 Tombstones

Gone (decision 2026-11-10 (older kind), rule 2). A delete of a channel from
its secret is an entry (§4.9.4).

### 6.4 Anti-Entropy as Safety Net

Gone (decision 2026-11-10 (older kind), rule 2).

---

## 7. Channel Routing

### 7.1 Three Gates

Gone (decision 2026-11-10 (older kind), rule 2): no node routes or forwards
an item of the older kind.

### 7.2 Relay Forwarding

Gone (decision 2026-11-10 (older kind), rule 2): no node routes or forwards
an item of the older kind.

### 7.3 Channel Intersection

Gone (decision 2026-11-10 (older kind), rule 2): no node routes or forwards
an item of the older kind.

### 7.4 Route Discovery

Gone (decision 2026-11-10 (older kind), rule 2): no node routes or forwards
an item of the older kind.

### 7.5 Expanding Ring Search

Gone (decision 2026-11-10 (older kind), rule 2): no node routes or forwards
an item of the older kind.

### 7.6 Envelope Padding (Paranoia Mode)

Gone (decision 2026-11-10 (older kind), rule 2): no node routes or forwards
an item of the older kind.

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
| Channel-Announce, Item-Sync, Item-Push, PSK-Exchange (0x04 to 0x07) | No: answers 0x05 with nothing, refuses 0x04 and 0x06 (§4.4 to §4.7) | The same | The same | -- |
| Entry-Show, Channel-Prove, Entry-Pull, Entry-Push (0x10 to 0x13) | Yes (opens them, to a relay) | No | Yes (serves them) | -- |
| Relay-Entries (0x14) | No | No | Yes (with relays its operator lists by key) | -- |
| Phase | 1 | 1 | 1 | 2+ |

> **v1 status.** No node of any role carries a channel of the older kind
> (decision 2026-11-10 (older kind), rule 1). What a personal node stores is
> the entries of its own channels: the personal channel, one for each name
> it holds, and in a pair channel the hand-over that it wrote itself. It
> receives the first two by Entry-Pull from a relay, and the change entry,
> which it keeps, in the answer to an Entry-Show. It holds one secret for
> the person, from which every channel of its own is derived, and no key for
> each channel. A relay stores the entries of channels from their secrets
> within its cap, and holds no key.

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

- Stores encrypted items in local SQLite
- Connects to bootnodes for initial discovery, then relays via gossip
- Small hot set: 1-2 relays + a few personal peers. Selection prefers lowest RTT (indicator of network colocation/quality)
- Never accepts inbound connections from the public internet (unless explicitly configured)
- Makes outbound connections only (§2.1). Rejects all inbound QUIC connections.
- `dial_policy = "relays_only"`

**Governor profile:** `hot_min=2, hot_max=2, hot_min_relays=1, warm_min=3, warm_max=10, cold_max=50`

> **v1 status.** A personal node's own channels are channels from their
> secrets. It shows, proves, pulls and pushes them at each relay it is set up
> with (§4.9.6), every 10 seconds, and sends what waits every 2 seconds. It
> subscribes to nothing through the local API, which serves the names the
> device holds (channels-api.md). Until a person gives it a recovery phrase,
> or adds it from a device that has one, it publishes nothing, and opens
> those streams only to fetch what a device whose key was typed at
> `cordelia accept` hands over.

#### 8.2.1 Push Policy

Gone (decision 2026-11-10 (older kind), rule 2): no node pushes an item of
the older kind. `push_policy` is not read.

#### 8.2.2 Personal Area Network (Agent Swarm)

Gone (decision 2026-11-10 (older kind), rule 2): its channels were of the
older kind. No `swarm-init`, no swarm children, no trusted peers; a personal
node accepts no inbound connection. A configuration that still sets
`[swarm]` or `network.trusted_peers` loads, and the keys are not read.

### 8.3 Bootnode

Lightweight discovery node. Its sole function is peer introduction -- Handshake and Peer-Sharing only. Once a node discovers relays and peers via a bootnode, gossip takes over and the bootnode connection MUST be released.

**Bootnode connection lifecycle:**
1. Node connects to bootnode(s) during bootstrap
2. Requests peer-share addresses (discovers relay addresses)
3. Connects to discovered relays
4. Once `hot_min_relays` relay connections are established, releases bootnode connection
5. Governor MUST NOT promote bootnode peers to Hot (they don't participate in data exchange)
6. Bootnode connections occupy Warm slots only, used for peer-sharing, evicted once relays are available

**Why eviction matters:** Personal nodes have `hot_max=2`. If bootnodes occupy hot slots, no room remains for relays. The node can discover relay addresses via peer-share but never connect because hot is full. Keeping bootnodes out of the hot set ensures hot slots are reserved for data-carrying peers (relays, keepers, or trusted personal nodes).

- Publicly addressable (static IP or DNS)
- Accepts inbound QUIC connections
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
- Stores entries as ciphertext only, and holds no key
- **Highly connected to other relays** -- the relay mesh is the network backbone
- Expected to be permanently available with demanding resource requirements
- Never reveals secret keeper addresses in Peer-Sharing responses
- `dial_policy = "all"`

**Governor profile:** `hot_min=10, hot_max=50, hot_min_relays=5, warm_min=20, warm_max=100, cold_max=500`

The `hot_min_relays=5` ensures each relay maintains connections to at least 5 other relays, forming a well-connected backbone mesh. This is the critical property for network-wide convergence -- items published by any personal node reach a relay, then fan out across the relay mesh, then reach all subscribing personal nodes.

**Phase 1 relay posture:** Transparent. Accept all channels. No access control on which channels to relay.

> **v1 status.** A relay carries channels from their secrets alone (decision
> 2026-11-10 (older kind), rule 1). It stores an entry only if both of its
> signatures hold, hands a channel only to a connection that proved the
> channel's key, and tells nobody which channels it holds, the relays its
> operator lists by key aside (§4.9). What it holds is counted against its
> cap (`max_storage_bytes`). Its database holds nothing of the older kind:
> step 34 of the schema drops it (rule 5). Its room, and what is not
> defended, are in the decision record of 2026-10-04, §2.5, and in
> `deploy/relay/README.md`.

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
| Max concurrent streams per connection | 8 (64 with a relay configured by key, §2.1) | Prevent stream exhaustion; bound quinn's reassembly on each connection |

The `max_inbound_connections` (200) is the hard cap. Once reached, all further inbound connections are rejected regardless of per-IP/subnet headroom. Per-IP and per-subnet limits are evaluated first: a connection from a /24 with 20 existing connections is rejected even if the global count is below 200.

Beyond limits: new connections receive QUIC `CONNECTION_CLOSE` with application error code `0x01` (capacity). The connecting node should back off exponentially.

### 9.2 Message Rate Limits

| Limit | Default | Action on exceed |
|-------|---------|-----------------|
| Writes per peer per minute | 36 | Stream reset; a breach. Counted on streams of Item-Push (0x06), each refused anyway (§4.6) |
| Writes per channel per minute | 100 | Drop, log warning |
| Sync streams per peer per minute | 18 | Stream reset; a breach. Counted on streams of Item-Sync (0x05), each answered with nothing (§4.5) |
| Peer-share requests per peer per minute | 6 | Ignore excess |
| Requests on the streams of entries (§4.9) per peer per minute, all five together | 3,000 | Stream reset; a breach (§4.9.7) |

Exceeding rate limits 3 times in 10 minutes → ban (§5.6).

All limits follow the 3x headroom principle: `limit = 3 * expected_legitimate_rate` (see `protocol.rs` derivations).

### 9.3 Size Limits

| Parameter | Value | Enforcement |
|-----------|-------|-------------|
| `max_item_bytes` | 64 KB (65,536) | The device that writes the item, each relay, the device that receives it |
| an item's other fields | ID and parent 64 bytes, channel 96, type 32, time 40 | The same; so an item as it travels is at most its ciphertext and 1 KB (`ENTRY_OVERHEAD_BYTES`) |
| `max_message_bytes` | 1 MB (1,048,576) | Wire codec (length prefix check) |
| an entry of a channel from its secret | A content that is a power of two from 256 bytes to 64 KB, and 237 bytes beside it | Whoever writes it, each relay, the device that receives it (§4.9, data-formats.md §9.2) |
| a text and its name in such an entry | 60 KB together (`MAX_ENTRY_NAME_AND_VALUE_BYTES`) | The device that writes it; one that is over is no version to a device that reads it |
| a page, and a push, of such entries | 100 entries; 128 KiB of entries (`SMALL_PAGE_BYTES`) in a page for a peer that is not a relay listed by key and in a device's push, and at least one entry; 896 KB (`ENTRY_PAGE_MAX_BYTES`) to a relay listed by key, served by its key; a listed relay asks for 1 entry a page (`SMALL_WINDOWS_PULL_ENTRIES`) where its own end of the connection lacks the listed settings (§2.1); entries passed on to a listed relay go `SMALL_PAGE_BYTES` to a message | 100: sender and receiver (a message that holds more is not read). The bytes: whoever builds the page or the push; the entries a page holds, the asker. A page that stops at its bytes says there is more, and its reader reads on |
| a small message (`SMALL_MESSAGE_BYTES`) | 144 KiB (147,456): a small page and 16 KiB | Every message a device of alpha.16 sends or is sent fits one. A node reads a longer frame from a peer that is not a relay listed by key only under a large permit (below) |

The wire codec rejects messages exceeding `max_message_bytes` before any parsing occurs.

**Large messages, under a permit** (decision 2026-10-22, memory across connections, rules 2, 6 and 7; parameter-rationale.md §13). A node reads a frame's protocol byte and length first. A frame from a peer that is not a relay listed by key whose length is over `SMALL_MESSAGE_BYTES` is read only under a large permit, which the node takes before it allocates the payload. The same holds for a stream's requests.

- A node holds at most `LARGE_MESSAGES_AT_ONCE` (4) permits across all its connections.
- It holds at most one for each /24 (IPv4) or /48 (IPv6) of the peers' addresses.
- It holds one for each stream at a time, from before the large frame is read until its answer is written.
- While a stream waits for a permit, it stays unread within the connection's window (§2.1).
- A stream with no permit after `STREAM_TIMEOUT_SECS` is refused with `ERR_LARGE_MESSAGE_LATER` (0x05, §9.5). This counts no breach.

A relay listed by key is read whatever the size. A relay configured by address alone is not exempt. A device of alpha.16 never needs a permit, because each of its messages fits a small message.

### 9.4 Backpressure Model

Bounded inbound queue per protocol type:

| Protocol | Queue capacity | Processing |
|----------|---------------|------------|
| Handshake (0x01) | 16 | FIFO, one worker |
| Keep-Alive (0x02) | 256 | FIFO, inline |
| Peer-Sharing (0x03) | 32 | FIFO, one worker |

When a queue is full, the node does not accept new streams for that protocol type. QUIC flow control handles the rest -- the sender's `open_bi()` blocks until the receiver is ready.

**Per-peer fairness:** Each peer's share of queue capacity is `queue_capacity / active_peers`. No single peer can consume more than their share.

### 9.5 Application Error Codes

The QUIC application error codes a node closes a connection or resets a stream with (`ERR_*` in `protocol.rs`):

| Code | Name | Meaning |
|------|------|---------|
| `0x01` | `ERR_CAPACITY` | The node holds no room for the connection (§9.1) |
| `0x02` | `ERR_UNKNOWN_PROTOCOL` | Unknown protocol byte (§3.3) |
| `0x03` | `ERR_RATE_LIMIT` | Over a rate limit: a stream is reset with it where a request is over, and the connection is closed with it where the peer keeps going over (§9.2) |
| `0x04` | `ERR_STREAM_TIMEOUT` | A write that did not end within `STREAM_TIMEOUT_SECS`: the stream is reset, so that what was written and not acknowledged is let go |
| `0x05` | `ERR_LARGE_MESSAGE_LATER` | A frame longer than a small message that the node could not take a large permit for within `STREAM_TIMEOUT_SECS` (§9.3). The node stops the stream's receive side and resets its send side with it. It counts no breach, and the same frame may be sent again as it is, a little later |

`0x05` is new in alpha.16. `0x01` says the node has no room for the connection; `0x05` says this one stream may be sent again.

**What a node of alpha.15 or alpha.14 meets from one of alpha.16.** Nothing changes on the wire for a message that fits a small message.

- **A stop with `0x05`.** It comes on a push of over 144 KiB (a device of those versions pushes up to 896 KiB) while every permit it could take is held. A sender blocked in its write of the payload sees the stop (`WriteError::Stopped(0x05)`), not the reset. Those versions match only `ERR_RATE_LIMIT` (`refused_for_now`), so they take `0x05` as a request not answered and send the same batch again at their next send. Nothing else in their handling changes.
- **Smaller windows and 8 streams,** announced by QUIC itself. A large message arrives a window at a time, about one round trip for each 31.5 KiB.
- **At round trips above about 0.3 s, its large messages fail the stream timeout** (§2.1's table).
  - Its pushes of up to 896 KiB to a relay of alpha.16 take about 6.0 s at 200 ms, 9.0 s at 300 ms and 12.0 s at 400 ms. They fail on every try past about 0.33 s, so its outbox does not drain at that relay over such a link.
  - A node of alpha.16 does not meet this. Its pushes and pages are small messages: a push of 128 KiB fails only past about 1.7 s. Between relays listed by key, which keep the windows from before, a full page fails only past about 4.9 s.
  - **What to do.** A person whose device runs alpha.15 or alpha.14 over a link of more than about 0.33 s should upgrade the device.
- **Small pages.** A page from a relay of alpha.16 holds at most 128 KiB of entries and says there is more. Those versions read on from such a page as from any other, except `cordelia accept`, which reads one page of the pair channel. Where an entry of the largest size comes before the typed key's hand-over, an older device does not find the hand-over. The device being added runs alpha.16, and it reads on.

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
   real peers fill Hot/Warm slots.
```

**Bootstrap timeout:** Each bootnode connection attempt MUST use a 10-second timeout. On timeout, the node logs a warning and continues to the next bootnode. Bootstrap is best-effort: the node proceeds to Phase B after attempting all bootnodes, even if some failed.

```
Phase B: Replication (relay and peer interaction)
8. Governor tick: promote best Cold → Warm, best Warm → Hot
   (prefer relays and channel-matching peers over bootnodes)
9. Steady state: governor manages peer lifecycle autonomously
```

**Time to first sync:** ~20-30s (1-3 governor ticks to discover peers via bootnode, promote relay/peer to Hot, then immediate sync). The bootnode is a brief stepping-stone, not a long-lived connection.

### 10.4 Fallback Peers

In addition to bootnodes, the binary includes 3-5 hardcoded fallback peer addresses, rotated each release. These are last-resort addresses if bootnodes and DNS are both unreachable.

---

## 11. Security Model

> **v1 status.** §11.1, §11.4 and §11.5 are written of the older kind of
> channel, which no node carries (decision 2026-11-10 (older kind), rule 1).
> For a channel from its secret: a relay holds no key, checks two signatures on
> every entry, and hands a channel only to a connection that proved the
> channel's key (§4.9.1). What a relay still learns is listed in the decision
> record of 2026-10-04, §2.4: channel IDs (all of a person's change at once
> when a device is removed), authors' keys, slots, revisions, which entries
> are deletes, sizes by class, timing, which connection proved which
> channel, each pair of devices that meet in a pair channel, each time a
> phrase is used, and the ID of the phrase's channel, which stays the same
> for a person for as long as the phrase does. The threats, each with the
> tests that keep the claim, are in
> [`docs/security/threat-model.md`](../security/threat-model.md).

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

Gone (decision 2026-11-10 (older kind), rule 2): they were of the older
kind's keys, items and announcements.

### 11.3 Threat Mitigations

| Threat | Mitigation | Phase |
|--------|-----------|-------|
| **Sybil** (flood with fake peers) | Connection limits per IP/subnet (§9.1). Min warm tenure before promotion (§5.4). | 1 |
| **Eclipse** (surround target with attacker peers) | 20%/hr churn (§5.4). Bootnode diversity. 25+ active peers needed at >75% network control. | 1 |
| **Replay** | TLS 1.3 (transport). Idempotent writes (application). Timestamp validation in handshake. | 1 |
| **Identity spoofing** | TLS certificate binds to Ed25519 key (§2.2). Application-layer verification (§4.1.6). | 1 |
| **Metadata leakage** | Channel lists removed from peer-sharing (§4.3). Channel digest in handshake, not full list (§4.1.2). | 1 |
| **DDoS** | Connection limits, bounded queues, per-peer fairness (§9). QUIC flow control. | 1 |
| **Governor manipulation** | Random promotion (§5.4 step 4). Min warm tenure. Hysteresis. Escalating bans. | 1 |
| **Relay compromise** | Relays see only ciphertext. No PSKs, no plaintext, no keys. Expendable by design. | 1 |
| **Peer-sharing poisoning** | Address validation: reject private IPs, loopback, link-local, own address (§4.3). | 1 |
| **Bootnode exhaustion** | Bootstrap rate limits per IP/subnet (§16.2.1). Bootnodes discovery-only (§8.2). | 1 |

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
api_addr = "127.0.0.1:9473"               # REST API listen address (127.0.0.1 or ::1 only, see below)
role = "personal"                           # "personal" | "bootnode" | "relay" | "keeper"
push_policy = "subscribers_only"           # "subscribers_only" | "pull_only" (personal nodes only, §8.1.1)
bootstrap_timeout_secs = 10              # Per-bootnode connection timeout during bootstrap
# All stream I/O uses STREAM_TIMEOUT (10s) at the codec layer.
# One timeout, one layer. See parameter-rationale.md §6 and protocol.rs.

[[network.bootnodes]]
addr = "boot1.cordelia.seeddrill.ai:9474"

[[network.bootnodes]]
addr = "boot2.cordelia.seeddrill.ai:9474"
```

**API loopback binding (Phase 1):** Phase 1 nodes MUST bind the channels API (`api_addr`) to `127.0.0.1` or `::1` only (configuration.md SS2.9). With any other address configured, the node refuses to start, and says why. Phase 2 adds TLS and allows non-loopback binding.

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
dial_policy = "all"                    # Set by the role, not read (§5.3)
tick_interval_secs = 10                # Governor tick frequency
churn_interval_secs = 3600             # Base churn interval (1 hour)
churn_jitter_secs = 300                # Random jitter added to churn interval (0-300s)
churn_fraction = 0.2                   # Fraction of warm peers churned per cycle
min_warm_tenure_secs = 300             # Minimum time as Warm before Hot promotion (bypassed if hot < hot_min)
hysteresis_secs = 90                   # Cooldown after demotion before re-promotion
keepalive_timeout_secs = 90            # Dead detection threshold
stale_threshold_secs = 1800            # 30 min no items → priority demotion
ema_alpha = 0.1                        # Read by nothing: no peer is scored (§5.5)
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
max_item_bytes = 65536                  # 64 KB
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

### 12.5 Trust Section

```toml
[trust]
initial_score = 0.5
recovery_per_hour = 0.01
recovery_per_item = 0.01
recovery_cap = 1.0

[trust.decay]
rate_limit_breach = 0.10
escalation_skip = 0.05
invalid_content = 0.15
protocol_violation = 0.10
duplicate_push = 0.02
invalid_token = 0.05

[trust.thresholds]
demote_hot = 0.3
deprioritise_sync = 0.2
ban_transient = 0.1
ban_systematic = 0.0
```

See §5.5.2 for trust scoring semantics and §5.6 for trust-driven banning.

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
- **[channel-naming.md](https://github.com/seed-drill/cordelia-node/blob/c3cc5756/docs/specs/channel-naming.md)**: Channel ID derivation, naming rules (the older kind's; gone)
- **decisions/2026-10-04-a-persons-devices.md**: A channel from its secret, what a relay does and its room (§2.4, §2.5), how a statement reaches a device (§4.6)
- **specs/data-formats.md §9**: An entry on the wire and inside its ciphertext, the statement, the change entry, the hand-over
- **RFC 5705**: Keying Material Exporters for TLS (the value a proof is made over, §4.9.1)
- **[specs/sdk-api-reference.md](https://github.com/seed-drill/cordelia-node/blob/c3cc5756/docs/archive/specs/sdk-api-reference.md)**: TypeScript SDK interface
- **cordelia-core/docs/architecture/network-model.md**: Scaling analysis, adversarial model, TLA+ specs (reference)
- **Coutts, D. et al.**: "The Shelley Networking Protocol" -- Cardano's Ouroboros networking design (peer governor, mini-protocol multiplexing)
- **Davies, N. & Coutts, D.**: "Introduction to the design of the Data Diffusion and Networking for Cardano Shelley" (IOG technical report)

---

## 15. Cross-Spec Review

Cross-spec review completed 2026-03-10. Nine issues identified (X1-X9) and resolved across all Phase 1 specs:

- **X1-X4**: ecies-envelope-encryption.md -- DM channel ID derivation, PSK rotation phase alignment, signed metadata envelope (is_tombstone + author_id encoding)
- **X5-X8**: channels-api.md -- GroupExchange -> Channel-Announce references, published_at cursor, Bech32 node IDs, bearer auth on identity endpoint
- **X9**: [sdk-api-reference.md](https://github.com/seed-drill/cordelia-node/blob/c3cc5756/docs/archive/specs/sdk-api-reference.md) -- nodeId type description (Bech32 Ed25519 pubkey)
- **L1**: channels-api.md -- chatty/taciturn terminology replaced with realtime/batch (developer-facing terms)

---

## 16. Economic Model and Incentive Alignment

This section addresses the economic and game-theoretic properties of the protocol. Each subsection references an issue from the economic review (s&p#10).

### 16.1 Relay Economics (E1, E6)

Relays bear bandwidth and storage costs for channels they cannot read. Without incentive alignment, rational relay operators shut down at scale.

#### 16.1.1 Relay Contribution Tracking

Gone (decision 2026-11-10 (older kind), rule 2): it counted the older kind's
pushes and fetches.

#### 16.1.2 Relay Reputation and Peer Eviction

Gone (decision 2026-11-10 (older kind), rule 2): its contribution weight and
probe items were of the older kind's items.

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

Gone (decision 2026-11-10 (older kind), rule 2). A relay's room for channels
from their secrets is in decision 2026-10-04 §2.5.

### 16.4 Bandwidth Amplification Limits (E11)

Gone (decision 2026-11-10 (older kind), rule 2): its limits were on the
older kind's pushes and re-pushes. The limits on the streams of entries are
in §4.9.7.

### 16.5 DM and Channel Creation Rate Limits (E9, E12, E13)

Gone (decision 2026-11-10 (older kind), rule 2): its limits were on
announcements and key requests of the older kind.

### 16.6 Channel Name Registration Economics (E4, Phase 3)

Phase 3 on-chain channel registration model (extends [channel-naming.md](https://github.com/seed-drill/cordelia-node/blob/c3cc5756/docs/specs/channel-naming.md) §8):

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
