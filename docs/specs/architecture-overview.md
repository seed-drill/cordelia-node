# Cordelia Architecture Overview

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-12
**Template**: arc42 (adapted as single document)
**Scope**: Phase 1 (Encrypted Pub/Sub MVP), forward references to Phases 2-5

---

## 1. Introduction and Goals

### 1.1 What Is Cordelia?

Cordelia is encrypted pub/sub for AI agents. Agents subscribe to channels, publish items, and listen for updates -- all end-to-end encrypted, replicated peer-to-peer, with zero configuration.

**One-line pitch:** Multi-agent shared memory that actually works across machines, sessions, and teams -- encrypted, decentralised, and yours.

### 1.2 Essential Requirements

| Priority | Requirement | Spec |
|----------|-------------|------|
| P0 | Subscribe, publish, listen in <5 minutes via SDK | sdk-api-reference.md |
| P0 | End-to-end encryption (AES-256-GCM via channel PSK) | ecies-envelope-encryption.md |
| P0 | Peer-to-peer replication without central server | network-protocol.md |
| P0 | Keypair IS identity (no registration, no portal) | identity.md |
| P1 | Local hybrid search (FTS5 + semantic) | search-indexing.md |
| P1 | Structured memory model (values / procedural / interrupt) | memory-model.md |
| P2 | Provider integration (Anthropic Memory Tool, OpenAI Sessions) | Phase 2 |
| P3 | SPO keeper economics (Cardano delegation-based) | Phase 3 |

### 1.3 Quality Goals

| Goal | Measure | Priority |
|------|---------|----------|
| Developer ergonomics | Subscribe-publish-listen in 3 API calls | 1 |
| Security | Zero plaintext leaves the node; relay sees only ciphertext | 2 |
| Availability | No single point of failure; works offline, syncs on reconnect | 3 |
| Simplicity | Two components (node + MCP adapter), one config file | 4 |
| Performance | <100ms search, <1s item delivery (realtime), 15-min (batch) | 5 |

### 1.4 Stakeholders

| Role | Concern |
|------|---------|
| AI agent developer | Simple API, fast integration, no crypto knowledge required |
| AI agent (runtime) | Reliable pub/sub, persistent memory across sessions |
| Node operator (personal) | Low resource footprint, zero config, runs in background |
| SPO keeper (Phase 3+) | Economic return, bounded resource commitment |
| Seed Drill team | Buildable specs, clean implementation path |

---

## 2. Constraints

### 2.1 Technical Constraints

| Constraint | Rationale |
|-----------|-----------|
| Rust for node | Performance, memory safety, async (tokio). Proven in cordelia-core. |
| TypeScript for SDK | Target developer ecosystem. Zero runtime dependencies, native fetch. |
| SQLite for storage | Embedded, zero-config, WAL mode, FTS5/sqlite-vec extensions. |
| QUIC (RFC 9000) for transport | Multiplexed streams, built-in TLS 1.3, connection migration. Personal nodes outbound-only (UDP rarely blocked outbound). TCP fallback Phase 2 if needed. See network-protocol.md §2.1. |
| CBOR (RFC 8949) for wire format | Compact, deterministic encoding, consistent with signed payloads. |
| Ed25519 / X25519 for identity | Standard curves. Ed25519 for signing, X25519 (derived) for ECDH. |

### 2.2 Organisational Constraints

| Constraint | Impact |
|-----------|--------|
| Two-person build team (Russell + Claude) | Scope discipline; no speculative features |
| Martin available for architecture review, not daily build | Specs must be self-sufficient for implementation |
| UK-based venture | GDPR awareness, UK DPA compliance awareness |
| Greenfield build (cordelia-node) | No backward compatibility with cordelia-core wire format or API |

### 2.3 Conventions

| Convention | Detail |
|-----------|--------|
| Bech32 encoding | Human-readable keys: `cordelia_pk1`, `cordelia_sk1`, `cordelia_xpk1`, `cordelia_sig1`, `cordelia_psk1` |
| RFC 2119 keywords | MUST, SHOULD, MAY used precisely in all specs |
| Channel names | RFC 1035 compliant (3-63 chars, lowercase alphanumeric + hyphens) |
| Item IDs | `ci_` + ULID (sortable, unique) |
| Timestamps | ISO 8601 (application layer), u64 seconds/nanoseconds (wire performance) |

---

## 3. System Scope and Context

### 3.1 Business Context

```
                            ┌─────────────────────┐
                            │   AI Agent (Claude,  │
                            │   GPT, custom)       │
                            └─────────┬───────────┘
                                      │ SDK / REST API
                                      ▼
┌──────────────┐           ┌─────────────────────┐           ┌──────────────┐
│ MCP Host     │──stdio──▶ │   Thin MCP Adapter   │──HTTP──▶ │              │
│ (Claude Code,│           │   (TypeScript)        │          │  Cordelia    │
│  Cursor,     │           │                       │          │  Node        │
│  Windsurf)   │           │  - MCP protocol       │          │  (Rust)      │
└──────────────┘           │  - Novelty filtering  │          │              │
                           │  - Session context    │          │  - Storage   │
                           │  - Embeddings         │          │  - Crypto    │
                           └───────────────────────┘          │  - P2P       │
                                                              │  - Search    │
┌──────────────┐                                              │  - REST API  │
│ REST Client  │──────────────────────HTTP──────────────────▶ │              │
│ (curl, app)  │                                              └──────┬───────┘
└──────────────┘                                                     │
                                                               QUIC/TLS 1.3
                                                                     │
                                              ┌──────────────────────┼──────────────────────┐
                                              ▼                      ▼                      ▼
                                     ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
                                     │  Bootnode     │      │  Relay       │      │  Other       │
                                     │  (discovery)  │      │  (store+fwd) │      │  Personal    │
                                     │               │      │              │      │  Nodes       │
                                     └──────────────┘      └──────────────┘      └──────────────┘
```

**External actors:**

| Actor | Interface | Direction | Auth |
|-------|-----------|-----------|------|
| AI agent / developer | SDK (`@seeddrill/cordelia`) | Bidirectional | Bearer token (local) |
| MCP host | Thin MCP adapter (stdio) | Bidirectional | MCP protocol |
| REST client | HTTP API (localhost:9473) | Bidirectional | Bearer token |
| Peer nodes | QUIC (port 9474) | Bidirectional | TLS 1.3 + Ed25519 |
| Ollama (local) | HTTP (localhost:11434) | Outbound only | None (local) |

### 3.2 Technical Context

```
┌─────────────────────────────────────────────────────────────────────┐
│                        User's Machine                               │
│                                                                     │
│  ┌─────────────┐     HTTP/localhost:9473      ┌──────────────────┐  │
│  │ MCP Adapter  │────────────────────────────▶│  Cordelia Node    │  │
│  │ (per-session)│                             │  (daemon)         │  │
│  └─────────────┘                             │                    │  │
│                                               │  ┌──────────────┐ │  │
│  ┌─────────────┐     HTTP/localhost:9473      │  │ REST API     │ │  │
│  │ SDK / App   │────────────────────────────▶│  │ (actix-web)  │ │  │
│  └─────────────┘                             │  └──────┬───────┘ │  │
│                                               │         │         │  │
│                                               │  ┌──────▼───────┐ │  │
│                                               │  │ Core Engine  │ │  │
│                                               │  │ - channels   │ │  │
│                                               │  │ - crypto     │ │  │
│                                               │  │ - storage    │ │  │
│                                               │  │ - search     │ │  │
│                                               │  └──────┬───────┘ │  │
│                                               │         │         │  │
│                                               │  ┌──────▼───────┐ │  │
│  ┌─────────────┐     HTTP/localhost:11434     │  │ P2P Network  │ │  │
│  │ Ollama      │◀────────────────────────────│  │ (quinn/QUIC) │ │  │
│  │ (embeddings)│                             │  └──────┬───────┘ │  │
│  └─────────────┘                             │         │         │  │
│                                               └─────────┼─────────┘  │
│                                                         │            │
└─────────────────────────────────────────────────────────┼────────────┘
                                                          │ UDP/9474
                                                          ▼
                                                    ┌───────────┐
                                                    │  Internet  │
                                                    │  (peers)   │
                                                    └───────────┘
```

**External system dependencies:**

| System | Purpose | Required? | Phase |
|--------|---------|-----------|-------|
| Ollama | Local embedding generation (nomic-embed-text-v1.5) | No (graceful degradation) | 1 |
| DNS | Bootnode discovery (SRV records) | Yes (bootstrap) | 1 |
| Cardano chain | Trust anchor, SPO verification | No | 3 |
| Anthropic API | Memory Tool adapter | No | 2 |
| OpenAI API | Sessions store adapter | No | 2 |

---

## 4. Solution Strategy

### 4.1 Key Architectural Decisions

| Decision | Choice | Alternative Rejected | Rationale |
|----------|--------|---------------------|-----------|
| Encryption boundary | Node encrypts/decrypts; SDK sees plaintext | SDK-side crypto | Simpler SDK, single trust boundary, no key management in JS |
| Transport | QUIC (quinn) | libp2p, raw TCP | Multiplexed streams, built-in TLS, no framework overhead |
| Storage | SQLite (embedded) | PostgreSQL, RocksDB | Zero-config, FTS5/sqlite-vec, WAL mode, single-file backup |
| Wire format | CBOR | JSON, Protobuf | Compact, deterministic, consistent with signed payloads |
| Identity model | Ed25519 keypair = identity | OAuth, DID (initially) | No registration, no portal, immediate usability |
| Channel naming | Deterministic SHA-256 from name | UUID, random | Human-readable, collision-free, verifiable |
| Replication | Bounded peer set + pull-based anti-entropy | Gossip flood, DHT | Constant per-node cost, receiver-controlled bandwidth |

**ADRs:** `decisions/2026-03-09-architecture-simplification.md` (§17 canonical), `decisions/2026-03-09-spo-economic-model.md`, `decisions/2026-03-09-mvp-implementation-plan.md`, `decisions/2026-03-10-identity-privacy-model.md`

### 4.2 Technology Stack

| Layer | Technology | Spec |
|-------|-----------|------|
| Node runtime | Rust (tokio async) | -- |
| HTTP framework | actix-web | channels-api.md |
| P2P transport | quinn 0.11.x (QUIC) + rustls | network-protocol.md §2 |
| Storage | SQLite (rusqlite) + WAL | data-formats.md |
| Search | FTS5 (keyword) + sqlite-vec (semantic) | search-indexing.md |
| Crypto | ring (Ed25519, X25519, AES-256-GCM, HKDF-SHA256) | ecies-envelope-encryption.md |
| Serialisation | ciborium (CBOR), serde (JSON) | network-protocol.md §3 |
| Encoding | bech32 (human-readable keys) | identity.md §10 |
| SDK | TypeScript, native fetch, zero dependencies | sdk-api-reference.md |
| MCP adapter | TypeScript, MCP stdio protocol | -- |
| Embeddings | Ollama (nomic-embed-text-v1.5, 768-dim) | search-indexing.md §3.2 |

---

## 5. Building Block View

### 5.1 Level 1: System Decomposition

```
┌──────────────────────────────────────────────────────────┐
│                    cordelia-node                          │
│                                                          │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌────────────┐ │
│  │cordelia- │  │cordelia- │  │cordelia- │  │cordelia-   │ │
│  │crypto    │  │storage   │  │network   │  │api         │ │
│  │          │  │          │  │          │  │            │ │
│  │Ed25519   │  │SQLite    │  │QUIC      │  │REST        │ │
│  │X25519    │  │channels  │  │governor  │  │endpoints   │ │
│  │ECIES     │  │items     │  │replicatn │  │auth        │ │
│  │AES-GCM   │  │search    │  │protocols │  │metrics     │ │
│  │CBOR sign │  │keys      │  │bootstrap │  │health      │ │
│  └─────────┘  └─────────┘  └─────────┘  └────────────┘ │
│       ▲              ▲            ▲            │         │
│       │              │            │            │         │
│  ┌────┴──────────────┴────────────┴────────────┴───────┐ │
│  │                 cordelia-core                        │ │
│  │  Shared types, traits, config, error types           │ │
│  └─────────────────────────────────────────────────────┘ │
│                          ▲                               │
│  ┌───────────────────────┴─────────────────────────────┐ │
│  │                 cordelia-node (binary)               │ │
│  │  CLI parsing, daemon lifecycle, tokio runtime        │ │
│  └─────────────────────────────────────────────────────┘ │
│                          ▲                               │
│  ┌───────────────────────┴─────────────────────────────┐ │
│  │                 cordelia-test                        │ │
│  │  TestNode, TestMesh, TestNodeBuilder                 │ │
│  │  (dev-dependency only)                               │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────┐
│  @seeddrill/cordelia     │
│  (TypeScript SDK)        │
│  npm package             │
└──────────────────────────┘

┌──────────────────────────┐
│  cordelia-mcp            │
│  (Thin MCP adapter)      │
│  TypeScript, per-session │
└──────────────────────────┘
```

### 5.2 Level 2: Crate Responsibilities

| Crate | Responsibility | Key Spec | Port Source |
|-------|---------------|----------|-------------|
| `cordelia-crypto` | Key generation, ECIES envelope, AES-256-GCM item encryption, CBOR signing, Bech32 encoding | ecies-envelope-encryption.md, identity.md | cordelia-core (as-is, ~650 LOC) |
| `cordelia-storage` | SQLite schema, channel/item CRUD, PSK management, migration framework | data-formats.md, channels-api.md | New |
| `cordelia-network` | QUIC transport, 8 mini-protocols, governor state machine, replication engine | network-protocol.md | Partial port: governor (~1235 LOC, trait swap PeerId->NodeId), transport new (quinn replaces libp2p) |
| `cordelia-api` | REST endpoints (actix-web), bearer token auth, Prometheus metrics, health | channels-api.md, operations.md | New |
| `cordelia-core` | Shared types (NodeId, ChannelId, Item, Error), config parsing, traits | configuration.md | New (not the old cordelia-core repo) |
| `cordelia-node` | Binary crate: CLI, daemon lifecycle, tokio runtime, signal handling | operations.md | New |
| `cordelia-test` | TestNode, TestMesh, TestNodeBuilder, assertion helpers | topology-e2e.md | cordelia-core test harness (~683 LOC) |

### 5.3 Crate Dependency Graph

```
cordelia-node (binary)
  ├── cordelia-api
  │     ├── cordelia-storage
  │     │     ├── cordelia-crypto
  │     │     └── cordelia-core
  │     └── cordelia-core
  ├── cordelia-network
  │     ├── cordelia-storage
  │     ├── cordelia-crypto
  │     └── cordelia-core
  └── cordelia-core

cordelia-test (dev-dependency)
  ├── cordelia-node (as library)
  └── cordelia-core
```

**Key trait boundaries:**

| Trait | Crate | Purpose |
|-------|-------|---------|
| `NodeIdentity` | cordelia-core | `node_id() -> NodeId`, `sign(payload) -> Signature`, `public_key() -> Ed25519PublicKey` |
| `Storage` | cordelia-core | `store_item()`, `get_item()`, `list_items()`, `channel_crud()` |
| `PeerManager` | cordelia-core | `promote()`, `demote()`, `ban()`, `score()`, `tick()` |
| `Replicator` | cordelia-core | `sync_channel()`, `push_item()`, `on_remote_receive()` |

### 5.4 SDK Package Structure

```
@seeddrill/cordelia
  ├── src/
  │     ├── index.ts          # Cordelia class, re-exports
  │     ├── client.ts         # NodeClient (HTTP wrapper)
  │     ├── types.ts          # All interfaces
  │     └── errors.ts         # CordeliaError
  ├── package.json            # Zero dependencies
  └── tsconfig.json
```

The SDK is a thin HTTP client. All crypto, storage, and search happen in the node.

---

## 6. Runtime View

### 6.1 Publish Flow

```
Developer             SDK              Node (API)          Node (Crypto)       Node (Storage)      Node (Network)
    │                  │                    │                    │                    │                    │
    │ publish(ch,msg)  │                    │                    │                    │                    │
    │─────────────────▶│                    │                    │                    │                    │
    │                  │ POST /publish      │                    │                    │                    │
    │                  │───────────────────▶│                    │                    │                    │
    │                  │                    │ encrypt(psk, msg)  │                    │                    │
    │                  │                    │───────────────────▶│                    │                    │
    │                  │                    │    encrypted_blob  │                    │                    │
    │                  │                    │◀───────────────────│                    │                    │
    │                  │                    │ sign(metadata)     │                    │                    │
    │                  │                    │───────────────────▶│                    │                    │
    │                  │                    │    signature       │                    │                    │
    │                  │                    │◀───────────────────│                    │                    │
    │                  │                    │                    │ store(item)        │                    │
    │                  │                    │                    │───────────────────▶│                    │
    │                  │                    │                    │     ok             │                    │
    │                  │                    │                    │◀───────────────────│                    │
    │                  │                    │ index(plaintext)   │                    │                    │
    │                  │                    │──────────────────────────────────────▶│                    │
    │                  │                    │                    │                    │                    │
    │                  │                    │ IF realtime: push_to_peers            │                    │
    │                  │                    │──────────────────────────────────────────────────────────▶│
    │                  │   PublishResult    │                    │                    │                    │
    │                  │◀──────────────────│                    │                    │                    │
    │  PublishResult   │                    │                    │                    │                    │
    │◀─────────────────│                    │                    │                    │                    │
```

**Key points:**
- SDK sends plaintext. Node encrypts with channel PSK (AES-256-GCM, 60-byte format: `iv || ct || tag`).
- Metadata envelope signed with Ed25519 (ECIES spec §11.7). Covers: author_id, channel_id, content_hash, is_tombstone, item_id, key_version, published_at.
- FTS5 index updated synchronously; embedding queued asynchronously (Ollama).
- For realtime channels: Item-Push (0x06) fires to all hot peers sharing the channel + relay peers.
- For batch channels: no push. Peers discover via Item-Sync polling.

### 6.2 Subscribe + PSK Acquisition Flow

```
Developer        SDK           Node (API)       Node (Network)      Remote Peer
    │              │                │                  │                  │
    │ subscribe()  │                │                  │                  │
    │─────────────▶│                │                  │                  │
    │              │ POST /subscribe│                  │                  │
    │              │───────────────▶│                  │                  │
    │              │                │                  │                  │
    │              │                │  [channel_id = SHA-256("cordelia:channel:" + name)]
    │              │                │                  │                  │
    │              │                │  IF PSK not held locally:          │
    │              │                │  PSKRequest ────▶│                  │
    │              │                │                  │ PSKRequest ────▶│
    │              │                │                  │◀── PSKResponse──│
    │              │                │                  │  (ECIES envelope │
    │              │                │                  │   92 bytes)      │
    │              │                │  decrypt PSK     │                  │
    │              │                │  verify SHA-256(psk) == descriptor.psk_hash
    │              │                │  store encrypted PSK locally       │
    │              │                │                  │                  │
    │              │                │  ChannelJoined ─▶│                  │
    │              │                │                  │ announce to hot peers
    │              │                │                  │                  │
    │              │ ChannelHandle  │                  │                  │
    │              │◀──────────────│                  │                  │
    │ ChannelHandle│                │                  │                  │
    │◀─────────────│                │                  │                  │
```

**Key points:**
- Channel ID derived deterministically from name (SHA-256).
- PSK acquired from any peer holding it (for open channels). ECIES envelope protects PSK in transit.
- `psk_hash` in signed ChannelDescriptor verifies PSK authenticity.
- ChannelJoined announced to hot peers, triggering replication of existing items.

### 6.3 Replication: Anti-Entropy Sync

```
Node A (initiator)                     Node B (responder)
    │                                       │
    │  [sync timer fires for channel X]     │
    │                                       │
    │── Stream: 0x05 Item-Sync ───────────▶│
    │   SyncRequest {                       │
    │     channel_id: X,                    │
    │     since: "2026-03-12T10:00:00Z",    │
    │     limit: 100                        │
    │   }                                   │
    │                                       │
    │◀── SyncResponse ────────────────────│
    │    items: [ItemHeader, ItemHeader...]  │
    │    has_more: false                     │
    │                                       │
    │  [compare headers to local store]     │
    │  [identify missing item_ids]          │
    │                                       │
    │── FetchRequest { item_ids: [...] } ─▶│
    │                                       │
    │◀── FetchResponse { items: [...] } ──│
    │                                       │
    │  [verify signatures]                  │
    │  [store encrypted blobs]              │
    │  [update FTS5 index after decrypt]    │
    │  [queue embedding generation]         │
```

**Sync intervals:**
- Realtime channels: 60s (safety net behind Item-Push)
- Batch channels: 900s (15 min, primary delivery mechanism)

**Conflict resolution:** Same item_id, different content_hash -> last-writer-wins by published_at. Tiebreak: lexicographically smaller content_hash wins. All replicas converge.

### 6.4 Device Pairing Flow

```
Initiator                 Bootnode              Joiner
    │                        │                      │
    │  PairRegister(code)   │                      │
    │──────────────────────▶│                      │
    │  PairRegisterAck      │                      │
    │◀──────────────────────│                      │
    │                        │   PairLookup(code)   │
    │                        │◀─────────────────────│
    │                        │   PairLookupResponse  │
    │                        │     (initiator addr)  │
    │                        │─────────────────────▶│
    │                        │                      │
    │◀──────── QUIC direct connect ────────────────│
    │                                               │
    │── PairOffer { pk, fingerprint } ────────────▶│
    │◀── PairAccept { pk, fingerprint } ───────────│
    │                                               │
    │  [visual fingerprint verification]            │
    │                                               │
    │── PairBundle { identity + PSKs (ECIES) } ──▶│
    │◀── PairComplete ─────────────────────────────│
```

**Security:** Bootnode stores only HMAC of pairing code (never raw). ECIES envelopes protect identity key and PSKs. Visual fingerprint verification defeats active MITM. Single-use code, single-connection guard.

### 6.5 Governor Tick (every 10s)

```
1. Unban expired      ─▶  Banned peers past duration → Cold
2. Reap dead          ─▶  No keepalive 90s → Hot→Warm, Warm→Cold
3. Promote Cold→Warm  ─▶  If warm_count < warm_min, connect cold peers
4. Promote Warm→Hot   ─▶  If hot_count < hot_min, promote best warm
                          Guard: min_warm_tenure (300s), hysteresis (90s)
5. Demote Hot→Warm    ─▶  If hot_count > hot_max, demote worst scorer
6. Churn              ─▶  Every churn_interval (1h), swap 20% warm
7. Evict excess cold  ─▶  If cold_count > cold_max, remove oldest
```

**Scoring:** `score = (items_delivered / duration) * (1 / (1 + rtt_ms/100)) * contribution_factor`. EMA smoothing (alpha=0.1) prevents score manipulation.

---

## 7. Deployment View

### 7.1 Personal Node (Phase 1 Primary)

```
~/.cordelia/
  ├── identity.key         # Ed25519 seed (32 bytes, mode 0600)
  ├── node-token           # Bearer token (mode 0600)
  ├── tls-cert.pem         # Self-signed X.509 (auto-generated)
  ├── tls-key.pem          # TLS private key (mode 0600)
  ├── config.toml          # Node configuration
  ├── cordelia.db          # SQLite database (WAL mode, mode 0600)
  ├── cordelia.db-wal      # WAL file
  ├── cordelia.db-shm      # Shared memory file
  └── channel-keys/        # Per-channel encrypted PSK files
        ├── <channel_id>.key
        └── ...
```

**System service:**
- macOS: LaunchAgent (`~/Library/LaunchAgents/ai.seeddrill.cordelia.plist`)
- Linux: systemd user unit (`~/.config/systemd/user/cordelia.service`)

**Resource footprint:** <50MB RAM (personal), <100MB disk (typical), negligible CPU (idle).

### 7.2 Multi-Node Topology (Phase 1 Target)

```
                    ┌──────────────┐
                    │  Bootnode 1   │  (Seed Drill operated)
                    │  (discovery)  │  DNS: _cordelia._udp.seeddrill.ai
                    └──────┬───────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
    ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
    │ Personal    │ │ Personal    │ │ Personal    │
    │ Node A      │◀────────────▶│ Node B      │ │ Node C      │
    │ (developer) │ │ (agent)     │◀────────────▶│ (team)      │
    └─────────────┘ └─────────────┘ └──────┬──────┘
                                           │
                                    ┌──────▼──────┐
                                    │  Relay       │  (Phase 1: Seed Drill)
                                    │  (store+fwd) │  (Phase 3: SPO keepers)
                                    └─────────────┘
```

**Phase 1:** 2+ Seed Drill bootnodes, 1+ Seed Drill relay. Personal nodes for developers and agents.
**Phase 3:** SPO-operated keepers and relays. Delegation-based economics.

### 7.3 Infrastructure

| Component | Phase 1 | Phase 3+ |
|-----------|---------|----------|
| Bootnodes | 2+ Seed Drill (low cost, discovery only) | SPO-operated (near-zero marginal cost) |
| Relays | 1+ Seed Drill | SPO-operated (bandwidth commitment) |
| Keepers | -- | SPO-operated (storage + PSK holding) |
| CI/CD | cordelia-test VM (pdukvm20, 32GB, 8 CPU) | Same |
| Monitoring | Prometheus + Grafana | Per-operator dashboards |

---

## 8. Cross-Cutting Concepts

### 8.1 Encryption Model

Three encryption layers, each with a distinct key and purpose:

| Layer | Key | Scope | Spec |
|-------|-----|-------|------|
| Transport | TLS 1.3 (QUIC) | Per-connection | network-protocol.md §2 |
| Item content | Channel PSK (AES-256-GCM) | Per-channel, per-item | ecies-envelope-encryption.md §5 |
| PSK distribution | ECIES envelope (X25519 + HKDF + AES-256-GCM) | Per-recipient | ecies-envelope-encryption.md §4 |

**Trust boundary:** The node is the encryption boundary. Plaintext exists only inside the node process. The SDK, MCP adapter, and REST clients see plaintext (over localhost). The P2P network sees only ciphertext. Relays handle only encrypted blobs -- they never hold PSKs.

### 8.2 Identity Model

Four layers, phased delivery:

| Layer | What | When | Spec |
|-------|------|------|------|
| L0: Cryptographic | Ed25519 keypair = identity. No registration. | Phase 1 | identity.md §2 |
| L1: Self-declared | Display name, type, about (profile metadata) | Phase 2 | identity.md §3 |
| L2: Verified | Domain, GitHub, ADA Handle, DID proofs | Phase 3 | identity.md §4 |
| L3: Reputation | Trust score, peer attestations, delegation signals | Phase 4 | identity.md §5 |

**Identifier forms:**
- Entity ID: `<name>_<4 hex>` (human-friendly, informational)
- Node ID: `cordelia_pk1...` (Bech32, canonical)
- Author ID: raw 32 bytes (wire), Bech32 (API)

### 8.3 Channel Types

| Type | ID Format | PSK Model | Membership | Example |
|------|-----------|-----------|------------|---------|
| Named | `SHA-256("cordelia:channel:" + name)` | Shared PSK | Open or invite-only | `research-findings` |
| DM | `"dm_" + SHA-256(sorted pubkeys)` | Derived per-pair | Bilateral (2 parties) | DM between Alice and Bob |
| Group | `"grp_" + UUID_v4()` | Shared PSK | Mutable (invite/remove) | Team conversation |
| System | `"__" + purpose` | Personal PSK | Single entity | `__personal` |
| Protocol | `"cordelia:" + name` | Well-known PSK | Network-wide | `cordelia:directory` |

Spec: channel-naming.md

### 8.4 Memory Model

Three domains by rate of change and value:

| Domain | Change Rate | Retention | Examples |
|--------|-------------|-----------|---------|
| Values | Slow | Indefinite | Beliefs, preferences, principles |
| Procedural | Medium | 1 year | Working patterns, recipes, protocols |
| Interrupt | Fast | 90 days | Session logs, status updates, alerts |

L1 (personal memory) stored in `__personal` channel. L2 (shared memory) stored in named channels. Prefetch budget: 50 KB per session start.

Spec: memory-model.md

### 8.5 Error Handling

Consistent error structure across all interfaces:

```json
{
  "error": {
    "code": "CHANNEL_NOT_FOUND",
    "message": "Channel 'research-findings' does not exist",
    "context": { "channel": "research-findings" }
  }
}
```

Error codes defined in channels-api.md §8. SDK maps to `CordeliaError` class with typed `code` field.

P2P rejections use typed CBOR responses (PushAck counters, PSKResponse status/reason).

---

## 9. Architecture Decisions

All ADRs live in `/decisions/`. Key decisions for Phase 1:

| ADR | Date | Decision |
|-----|------|----------|
| architecture-simplification | 2026-03-09 | Pivot to encrypted pub/sub. Portal deprecated. Two components. |
| spo-economic-model | 2026-03-09 | Delegation-based economics. No token unless proven necessary. |
| mvp-implementation-plan | 2026-03-09 | WP1-WP15 work packages. Critical path: WP1->WP3->WP6->WP9. |
| identity-privacy-model | 2026-03-10 | 4-layer identity. DM semantics. Flat namespace. |

---

## 10. Quality Requirements

### 10.1 Quality Tree

```
Quality
├── Security
│   ├── E2E encryption (all items, all channels)
│   ├── Zero plaintext on wire or relay
│   └── Keypair-based auth (no passwords, no tokens on network)
├── Usability
│   ├── <5 min from npm install to working pub/sub
│   ├── 3 API calls: subscribe, publish, listen
│   └── Zero config for personal node
├── Reliability
│   ├── Offline-first (works without network)
│   ├── Anti-entropy catches missed items
│   └── Convergent replication (LWW + tombstones)
├── Performance
│   ├── <100ms hybrid search
│   ├── <1s realtime delivery
│   └── Constant per-node cost regardless of network size
└── Maintainability
    ├── Clean crate boundaries
    ├── Spec-driven implementation
    └── E2E topology tests (TLA+ property validation)
```

### 10.2 Quality Scenarios

| Scenario | Measure | Spec |
|----------|---------|------|
| Developer publishes first item | <5 min from install | sdk-api-reference.md |
| Keyword search on 10K items | <50ms | search-indexing.md §7 |
| Hybrid search (keyword + semantic) | <100ms | search-indexing.md §7 |
| Realtime item delivery (push) | <1s peer-to-peer | network-protocol.md §4.6 |
| Batch sync convergence | <15 min | network-protocol.md §4.5 |
| Node cold start to first peer | <30s (with bootnode) | network-protocol.md §10 |
| Governor tick | 10s interval | network-protocol.md §5.4 |

---

## 11. Risks and Technical Debt

### 11.1 Technical Risks

| Risk | Impact | Mitigation | Status |
|------|--------|------------|--------|
| QUIC NAT traversal | Personal nodes behind NAT cannot accept inbound | Relay nodes accept inbound; pull-based sync works outbound-only | Accepted |
| UDP blocked by corporate firewall | Personal nodes unable to connect in restrictive networks | Outbound UDP rarely blocked; TCP fallback Phase 2 if real-world deployments confirm | Accepted (see network-protocol.md §2.1) |
| SQLite concurrency under load | Write contention on busy channels | WAL mode; single-writer architecture; Phase 2 evaluate if needed | Monitored |
| Ollama availability | Embedding generation fails | Graceful degradation: FTS5-only search without embeddings | Designed |
| PSK rotation complexity | Member removal requires re-encryption | Lazy rotation: new PSK for new items, old items remain readable with old PSK | Specified |
| Clock skew | Conflict resolution depends on timestamps | 5-min tolerance in handshake; LWW + deterministic tiebreak | Specified |

### 11.2 Accepted Technical Debt

| Debt | Reason | Resolution Phase |
|------|--------|-----------------|
| No CJK tokenizer | FTS5 default tokenizer; CJK search limited | Phase 3 |
| No cross-channel search | Security boundary: each channel has its own PSK | Phase 3 |
| Transparent relay (accept all channels) | Simplicity for Phase 1 | Phase 2 (explicit channel allowlists) |
| No proof-of-membership for channel announcements | Free-rider detection via governor scoring | Phase 2 (HMAC-based proof) |
| No rate-limit persistence across restarts | In-memory counters reset | Phase 2 |
| No TCP fallback transport | UDP-only; restrictive firewalls block connectivity | Phase 2 (if real-world deployments confirm need) |

---

## 12. Glossary

| Term | Definition |
|------|-----------|
| **Channel** | Named pub/sub topic. Items published to a channel are encrypted with the channel's PSK and replicated to all subscribers. |
| **PSK** | Pre-Shared Key. 32-byte AES-256-GCM key, unique per channel. Distributed via ECIES envelopes. |
| **ECIES envelope** | 92-byte encrypted package (ephemeral X25519 pubkey + IV + ciphertext + GCM tag) wrapping a PSK for a specific recipient. |
| **Item** | Unit of content in a channel. Encrypted blob + signed metadata. |
| **Tombstone** | Soft-delete marker for an item. Propagated via replication, garbage-collected after 7 days. |
| **Governor** | Background task managing peer lifecycle: Cold -> Warm -> Hot -> Banned. Ticks every 10s. |
| **Culture / Mode** | Channel delivery mode: realtime (push + pull) or batch (pull only). |
| **Keeper** | (Phase 2+) Node that holds PSK for a channel and provides durable storage. SPO-operated. |
| **Relay** | Infrastructure node providing store-and-forward for encrypted items. Never holds PSKs. |
| **Bootnode** | Lightweight discovery node. Peer-Sharing only. No items, no PSKs, no relay. |
| **Entity ID** | Human-friendly identifier: `<name>_<4 hex>` derived from Ed25519 public key. |
| **Node ID** | Bech32-encoded Ed25519 public key: `cordelia_pk1...`. Canonical node identifier. |
| **Anti-entropy** | Pull-based periodic sync (Item-Sync) ensuring all replicas converge. Safety net behind push. |
| **Channel descriptor** | Signed metadata record for a channel (creator_id, access, mode, key_version, psk_hash). |
| **Three gates** | Replication filter: (1) push target selection, (2) relay acceptance, (3) destination subscription check. |

---

## Spec Index

All specifications live in `/specs/`. This AOD references but does not duplicate them.

| Spec | arc42 Section | Scope |
|------|--------------|-------|
| ecies-envelope-encryption.md | §8.1 Encryption | Cryptographic primitives, key types, envelope format, item encryption, CBOR signing |
| channels-api.md | §6.1 Publish Flow | REST API (14 endpoints), error codes, auth |
| channel-naming.md | §8.3 Channel Types | Name validation, ID derivation, prefix system, test vectors |
| sdk-api-reference.md | §5.4 SDK | TypeScript SDK, all methods, BDD acceptance tests |
| identity.md | §8.2 Identity | 4-layer identity model, key generation, device pairing, privacy |
| operations.md | §7.1 Deployment | Installation, CLI, system service, backup, monitoring |
| configuration.md | §7.1 Deployment | config.toml canonical reference, all parameters with defaults |
| search-indexing.md | §8.4 (implicit) | FTS5 + sqlite-vec hybrid, index lifecycle, query processing |
| memory-model.md | §8.4 Memory | Three-domain model, L1/L2, prefetch, novelty, expiry |
| network-protocol.md | §6.2-6.5 Runtime | Transport, wire format, 8 mini-protocols, governor, replication, routing |
| topology-e2e.md | §10 Quality | Docker Compose topologies, TLA+ property validation |
| data-formats.md | §5.2 Storage | SQLite DDL, PSK envelope format, column-to-API mappings, migrations |

---

*Last updated: 2026-03-12*
