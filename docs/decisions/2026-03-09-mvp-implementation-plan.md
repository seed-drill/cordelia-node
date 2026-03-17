# Implementation Plan: Encrypted Pub/Sub MVP

**Date**: 2026-03-09
**Owner**: Russell Wing (plan), Martin Stevens (Rust implementation)
**Depends on**: decisions/2026-03-09-architecture-simplification.md (pending approval)
**Goal**: A developer can subscribe, publish, and listen on encrypted channels via the SDK in <5 minutes.

---

## 1. MVP Definition

### Done When

```javascript
import { Cordelia } from '@seeddrill/cordelia'

const c = new Cordelia()                          // connects to local node
await c.subscribe('research-findings')            // join/create encrypted channel
await c.publish('research-findings', {            // publish to channel
  type: 'insight',
  content: 'Vector search is insufficient alone...'
})
const items = await c.listen('research-findings') // stream new items
const results = await c.search('research-findings', 'vector search') // FTS
```

This works between two machines on different networks, with all data encrypted end-to-end.

### Not in MVP

- Portal, OAuth, web UI
- MCP adapter (separate, later -- Claude Code integration continues working via existing proxy during transition)
- Vector/graph indexes (FTS5 text search only for MVP)
- Anthropic Memory Tool adapter (Phase 2)
- OpenAI Sessions adapter (Phase 2)
- SPO keeper deployment (Phase 3)
- Trust scoring, group spectrum, culture modelling

---

## 2. Work Packages

### WP1: ECIES Envelope in Rust (cordelia-crypto)

**What**: Implement ECIES envelope encrypt/decrypt matching the TypeScript implementation in `cordelia-portal/src/vault.ts`.

**Why**: PSK distribution during channel subscribe requires envelope encryption. Currently only exists in TypeScript.

**Scope**:
- `envelope_encrypt(plaintext: &[u8], recipient_x25519_pub: &[u8]) -> EnvelopeCiphertext`
- `envelope_decrypt(ciphertext: &EnvelopeCiphertext, recipient_x25519_priv: &[u8]) -> Vec<u8>`
- Ephemeral X25519 keypair + ECDH + HKDF-SHA256 (`cordelia-key-wrap-v1` info) + AES-256-GCM
- Port test vectors from TypeScript to ensure cross-language compatibility

**Crates**: `x25519-dalek` (already in deps), `aes-gcm`, `hkdf`, `sha2`

**Files**:
- `cordelia-core/crates/cordelia-crypto/src/envelope.rs` (new)
- `cordelia-core/crates/cordelia-crypto/src/lib.rs` (export)
- `cordelia-core/crates/cordelia-crypto/Cargo.toml` (deps)

**Tests**: Unit tests with known test vectors. Cross-language test: encrypt in Rust, decrypt in TypeScript and vice versa.

**Deliverable: One-page crypto spec** covering ECIES parameters, key types (Ed25519/X25519), KDF info string, AEAD, channel PSK format, and Bech32 key encoding (HRPs: `cordelia_pk`, `cordelia_sk`, `cordelia_xpk`, `cordelia_sig`). This is the canonical cryptographic reference for the protocol.

**Estimate**: 1-2 days

---

### WP2: Name-Based Group Resolution (cordelia-storage, cordelia-api)

**What**: Support creating/joining groups by human-readable name instead of UUID only.

**Why**: `subscribe('research-findings')` needs to resolve a name to a group ID deterministically.

**Design**:
- Public channels: group_id = SHA-256 of canonical name (lowercase, trimmed). Content-addressed, deterministic, discoverable.
- Private channels: group_id = UUID v4 (opaque, invitation-only). Name stored as group metadata.
- New field on groups table: `channel_name TEXT` (indexed, unique for public channels).
- API: `POST /api/v1/channels/resolve` -- takes `{ name: string, create_if_missing: bool }`, returns `{ group_id, is_new, culture }`.

**Schema change** (additive -- existing UUID-based groups unaffected, new columns nullable):
```sql
ALTER TABLE groups ADD COLUMN channel_name TEXT;      -- NULL for legacy groups
ALTER TABLE groups ADD COLUMN keeper_origin TEXT;      -- NULL for legacy groups
CREATE UNIQUE INDEX idx_groups_channel_name ON groups(channel_name) WHERE channel_name IS NOT NULL;
```

**Files**:
- `cordelia-core/crates/cordelia-storage/src/lib.rs` (Storage trait: `resolve_channel`, `create_channel`)
- `cordelia-core/crates/cordelia-storage/src/schema_v6.sql` (new migration)
- `cordelia-core/crates/cordelia-api/src/lib.rs` (new endpoint)

**Estimate**: 1 day

---

### WP3: Pub/Sub API Endpoints (cordelia-api)

**What**: Developer-friendly REST endpoints for subscribe, publish, listen.

**Why**: The existing group/L2 API works but requires knowledge of group IDs, item structure, and encryption. Pub/sub endpoints abstract this.

**Endpoints**:

```
POST /api/v1/channels/subscribe
  Body: { name: string, keeper?: string }
  Response: { group_id, channel_name, keeper_origin, psk_envelope?, is_new }
  - Resolves name to group (WP2)
  - If new: creates group with chatty culture, generates PSK, adds caller as owner
    - Anchors channel to specified keeper (or default keeper)
    - Checks entity's channel quota on that keeper
  - If existing: adds caller as member (for public channels) or returns error (private, needs invite)
  - Returns ECIES-encrypted PSK envelope if new member (WP1)

POST /api/v1/channels/publish
  Body: { channel: string, content: string, metadata?: object }
  Response: { item_id, published_at }
  - Resolves channel name to group_id
  - Encrypts content with channel PSK (L2 encryption)
  - Writes as L2 item to group
  - Chatty culture triggers eager push to peers

POST /api/v1/channels/listen
  Body: { channel: string, since?: string, limit?: number }
  Response: { items: [{ item_id, content, author, published_at }], cursor }
  - Resolves channel name
  - Returns decrypted items since timestamp
  - Cursor for pagination
  - Phase 1: REST polling (stateless, simple). SDK abstracts poll interval.
  - Phase 2: SSE endpoint (GET /api/v1/channels/listen/stream) for real-time.

POST /api/v1/channels/list
  Response: { channels: [{ name, group_id, member_count, last_activity }] }
  - Lists channels the caller is subscribed to

POST /api/v1/channels/unsubscribe
  Body: { channel: string }
  - Removes caller from group
```

**L2 encryption in node**: Currently L2 encryption is proxy-side. For MVP, the node needs to encrypt/decrypt L2 items using the channel's PSK. This extends the pattern from core#40 (L1 encryption) to L2.

**Design choice**: PSKs for channels the node participates in are stored in a new `channel_keys` table (encrypted at rest with the node's personal group PSK, same pattern as L1).

```sql
CREATE TABLE channel_keys (
    group_id TEXT PRIMARY KEY,
    encrypted_psk BLOB NOT NULL,  -- AES-256-GCM encrypted with personal PSK
    key_version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

**Files**:
- `cordelia-core/crates/cordelia-api/src/channels.rs` (new module)
- `cordelia-core/crates/cordelia-api/src/lib.rs` (mount routes)
- `cordelia-core/crates/cordelia-storage/src/lib.rs` (channel_keys CRUD)

**Estimate**: 3-4 days

---

### WP4: L2 Encryption in Node (cordelia-storage)

**What**: Node encrypts/decrypts L2 items transparently, extending the L1 encryption pattern (core#40).

**Why**: Currently L2 encryption happens in the proxy. For the pub/sub API to work without a proxy, the node must handle encryption.

**Design**:
- `NodeStorageProvider` already encrypts L1 with personal group PSK
- Extend to L2: when writing to a group, encrypt with that group's PSK from `channel_keys`
- When reading, decrypt transparently
- Replication carries encrypted blobs (no change to wire protocol)

**Files**:
- `cordelia-core/crates/cordelia-storage/src/lib.rs` (extend NodeStorageProvider)
- `cordelia-core/crates/cordelia-crypto/src/lib.rs` (shared encrypt/decrypt helpers)

**Depends on**: WP1 (ECIES for PSK distribution), WP3 (channel_keys table)

**Estimate**: 2-3 days

---

### WP5: Local Enrollment CLI (cordelia-node)

**What**: `cordelia enroll` command for first-device setup and second-device key exchange.

**Why**: Replaces portal-based enrollment. Must be zero-friction.

**First device flow**:
```
$ cordelia init
Generating identity... done.
Entity ID: russwing_a1b2c3 (derived from Ed25519 public key)
Node started on port 3847.
Discovering network... connected to 2 bootnodes.
Ready. Your node is running.
```

**Second device flow**:
```
# On first device:
$ cordelia pair
Pairing code: XXXX-XXXX-XXXX
Show QR? [y/n]

# On second device:
$ cordelia join XXXX-XXXX-XXXX
Connecting to peer... done.
Receiving identity bundle... done.
Syncing channels... 3 channels, 47 items.
Ready.
```

**What happens under the hood**:
1. First device: generate Ed25519 keypair, derive X25519, create personal group, start node
2. Pair: open a temporary P2P channel, generate one-time pairing code
3. Join: connect via pairing code, exchange public keys, first device sends ECIES-encrypted PSK bundle (personal group + all channel PSKs)

**Files**:
- `cordelia-core/crates/cordelia-node/src/cli.rs` (new: init, pair, join subcommands)
- `cordelia-core/crates/cordelia-node/src/enrollment.rs` (new: P2P pairing protocol)

**Estimate**: 3-4 days

---

### WP6: SDK Package (TypeScript)

**What**: `@seeddrill/cordelia` npm package wrapping the node REST API.

**Why**: Developer experience. `npm install` and go.

**Design**:
```typescript
// src/index.ts
export class Cordelia {
  constructor(opts?: { nodeUrl?: string, token?: string })
  // Auth: bearer token. Default: read from ~/.cordelia/node-token.
  // Override via constructor for remote nodes or agent credential bundles.

  // Pub/sub (SDK uses 'realtime'/'batch' not 'chatty'/'taciturn')
  async subscribe(channel: string, opts?: { mode?: 'realtime' | 'batch' }): Promise<Channel>
  async publish(channel: string, content: any, metadata?: object): Promise<string>
  async listen(channel: string, opts?: { since?: string }): Promise<Item[]>
  async unsubscribe(channel: string): Promise<void>

  // DMs and groups
  async dm(key: string): Promise<Channel>                                    // bilateral, deterministic
  async group(keys: string[], opts?: { name?: string }): Promise<Channel>    // mutable membership

  // Query
  async search(channel: string, query: string, limit?: number): Promise<Item[]>

  // Personal memory
  async write(key: string, value: any): Promise<void>
  async read(key: string): Promise<any>

  // Channels
  async channels(): Promise<ChannelInfo[]>
  async dms(): Promise<ChannelInfo[]>
  async groups(): Promise<ChannelInfo[]>
}

export interface Channel {
  name: string
  groupId: string
  isNew: boolean
}

export interface Item {
  id: string
  content: any
  author: string
  publishedAt: string
  channel: string
}
```

**Package structure**:
```
@seeddrill/cordelia/
  src/
    index.ts          -- Cordelia class
    client.ts         -- HTTP client for node API
    types.ts          -- TypeScript types
  package.json
  tsconfig.json
  README.md           -- "Encrypted Pub/Sub in 5 Minutes"
```

**Embedded node management** (stretch): SDK auto-starts node binary if not running. Detects `~/.cordelia/node-token`, spawns node process if absent. Makes `npm install` the only required step.

**Files**: New repo `cordelia-sdk` or directory in `cordelia-proxy` repo.

**Estimate**: 2-3 days

---

### WP7: Install Script + Packaging

**What**: One-line install for the node binary.

**Why**: `curl -sSL install.seeddrill.ai | sh` must work on Mac and Linux.

**Scope**:
- Cross-compile Rust binary for x86_64-linux, aarch64-linux, x86_64-darwin, aarch64-darwin
- Install script detects platform, downloads binary, sets up systemd/launchctl
- Auto-runs `cordelia init` on first install
- GitHub Releases for binary distribution

**Existing work**: Current install script (`setup/` dir) handles proxy + node. Simplify to node-only.

**Files**:
- `cordelia-core/.github/workflows/release.yml` (cross-compile + GitHub Release)
- `cordelia-core/install.sh` (platform-detect, download, install, init)
- Update `seeddrill.ai/install` to point to new script

**Estimate**: 2 days

---

### WP8: FTS5 Search in Node (cordelia-storage)

**What**: Move full-text search from proxy's local SQLite to the node's SQLite.

**Why**: SDK search goes through the node, not the proxy. Single source of truth.

**Scope**:
- FTS5 virtual table in node schema (already has `fts_search` in Storage trait)
- Auto-index on L2 write (decrypt item, index plaintext)
- BM25 ranking (same as proxy's current implementation)
- Channel-scoped search: `search(channel, query)` filters by group_id

**Note**: Vector search (sqlite-vec) deferred to Phase 2. FTS5 is sufficient for MVP.

**Files**:
- `cordelia-core/crates/cordelia-storage/src/lib.rs` (enhance fts_search with group_id filter)
- Schema migration for FTS5 virtual table if not already present

**Estimate**: 1-2 days

---

### WP9: Documentation + Quickstart

**What**: "Encrypted Pub/Sub in 5 Minutes" quickstart guide.

**Why**: If a developer can't get started in 5 minutes, they won't try it.

**Content**:
1. Install (one line)
2. Install SDK (`npm install @seeddrill/cordelia`)
3. Subscribe to a channel (3 lines of code)
4. Publish and listen (3 lines of code)
5. "What just happened" -- brief explanation of encryption + replication
6. Next steps: personal memory, multiple agents, search

**Files**:
- `cordelia-sdk/README.md`
- `seeddrill.ai` quickstart page (or docs subdomain)

**Estimate**: 1 day

---

## 3. Dependency Graph

```
WP1 (ECIES)
  |
  +---> WP3 (Pub/Sub API) ---> WP6 (SDK)
  |       |                      |
  |       v                      v
  |     WP4 (L2 Encryption)   WP9 (Docs)
  |
  +---> WP5 (Local Enrollment)

WP2 (Name Resolution) ---> WP3 (Pub/Sub API)

WP7 (Install/Packaging) --- independent, can parallel

WP8 (FTS5 in Node) ---> WP3 (search endpoint)
```

**Critical path**: WP1 -> WP3 -> WP6 -> WP9

**Parallelisable**:
- WP1 + WP2 + WP7 + WP8 (all independent)
- WP4 + WP5 (both depend on WP1 but independent of each other)
- WP6 can start interface design while WP3 is in progress

---

## 4. Effort Summary

| WP | Description | Estimate | Owner | Depends On |
|----|-------------|----------|-------|------------|
| WP1 | ECIES envelope in Rust | 1-2 days | Martin | - |
| WP2 | Name-based group resolution | 1 day | Martin | - |
| WP3 | Pub/sub API endpoints | 3-4 days | Martin | WP1, WP2 |
| WP4 | L2 encryption in node | 2-3 days | Martin | WP1, WP3 |
| WP5 | Local enrollment CLI | 3-4 days | Martin | WP1 |
| WP6 | SDK package (TypeScript) | 2-3 days | Russell | WP3 (interface) |
| WP7 | Install script + packaging | 2 days | Martin/Russell | - |
| WP8 | FTS5 search in node | 1-2 days | Martin | - |
| WP9 | Documentation + quickstart | 1 day | Russell | WP6 |

**Total**: ~17-24 days of work. With parallelism (Martin on Rust, Russell on SDK/docs), target 3-4 weeks calendar time.

**Critical path** (serial): WP1 (2d) -> WP3 (4d) -> WP6 (3d) -> WP9 (1d) = ~10 days.

---

## 5. What Keeps Working During Transition

The existing Cordelia deployment (proxy + node + portal) continues to function unchanged. This MVP is additive:

- Existing MCP tools via proxy: unchanged
- Existing Cordelia memory (L1/L2): unchanged
- Existing P2P replication: unchanged, pub/sub uses the same protocol
- Portal: still running on Fly, just not on the critical path

The SDK is a new interface to the same node. No migration required.

---

## 6. Phase 2 Preview (Post-MVP)

After encrypted pub/sub works:

1. **Anthropic Memory Tool adapter** -- Cordelia-backed storage for Claude's client-side memory. Personal group for private, shared groups for team.
2. **OpenAI Sessions store** -- Cordelia as session backend for Agents SDK.
3. **MCP adapter thinning** -- Existing proxy stripped to session-scoped MCP adapter using node API.
4. **Vector search in node** -- Move sqlite-vec from proxy. Provider interface for external embeddings.
5. **SPO keeper guide** -- Docker image, systemd service, Cardano pool metadata.

---

## 7. Resolved Decisions

### 7.1 SDK Repo

**Decision: New repo (`cordelia-sdk`).**

Separate published npm package with its own semver and release cadence. The proxy is being thinned and the SDK is the new primary developer interface. Keeps the GitHub org clean: `cordelia-core` (Rust node), `cordelia-sdk` (TypeScript SDK), `cordelia-proxy` (MCP adapter, legacy during transition).

### 7.2 Channel Encryption Model

**Decision: Random PSK for ALL channels. Public channels auto-approve subscribers. Private channels require invitation.**

Same encryption model everywhere -- the only difference is admission policy:

| Channel Type | PSK | Admission | Encryption |
|-------------|-----|-----------|------------|
| Private (invite-only) | Random, ECIES envelope distribution | Invitation from admin/owner | Full E2E -- keeper never holds PSK |
| Public (open) | Random, ECIES envelope distribution | Any existing member auto-approves | E2E -- anchor keeper holds PSK for distribution (see architecture ADR, PSK Trust Boundary) |

How public channel join works:
1. First subscriber creates channel + random PSK, becomes owner
2. Second subscriber requests join
3. Anchor keeper (or any existing member's node) distributes PSK via ECIES envelope (no human approval)
4. New subscriber can now read/write

All data is E2E encrypted, always. For invite-only channels and DMs, keeper is pure encrypted storage (never holds PSK). For open and gated channels, anchor keeper holds PSK for availability and enforcement -- economically incentivised not to abuse this (see architecture ADR, PSK Trust Boundary).

Rejected alternatives:
- (a) PSK derived from channel name -- half-measure, narrative collapses if derivation is reverse-engineered
- (c) Transport-only encryption for public -- loses core differentiator

### 7.3 Node Binary Name

**Decision: `cordelia`.**

Single user-facing binary. Subcommands: `cordelia init`, `cordelia pair`, `cordelia join`, `cordelia status`. Cargo binary target renamed from `cordelia-node`. Installed to `~/.cordelia/bin/cordelia` or `/usr/local/bin/cordelia`.

### 7.4 Default Culture

**Decision: Chatty by default, configurable on create.**

Chatty = eager push = real-time pub/sub. This is what makes the product feel alive.

```javascript
await c.subscribe('alerts')                                    // realtime (default)
await c.subscribe('research-archive', { mode: 'batch' })       // pull-based
```

Culture is set at channel creation and changeable by owner only.

---

## 8. Additional Work Packages (MVP)

### WP14: TLA+ Protocol Verification

**What**: Formal TLA+ specification of the network protocol with model checking via TLC.

**Why**: Quantifiable confidence that protocol properties hold across all topologies up to a bound. Catches design bugs before implementation. Cardano-grade rigour (Ouroboros was TLA+ verified before coding).

**Scope**:
- TLA+ module modelling 4 node roles, push_policy, 3-gate routing, relay re-push, partition/heal
- 9 formal properties verified:

| ID | Property | Type | Statement |
|----|----------|------|-----------|
| P1 | Delivery | Liveness | Items reach all `subscribers_only` subscribers |
| P2 | Pull delivery | Liveness | Items reach `pull_only` subscribers via Item-Sync |
| P3 | Channel isolation | Safety | Personal nodes never store items for unsubscribed channels |
| P4 | Role isolation | Safety | Bootnodes never store items. Relays never hold PSKs. |
| P5 | Loop termination | Safety | Relay re-push terminates in bounded steps |
| P6 | Convergence | Liveness | Post-partition, all subscribers converge to same item set |
| P7 | Bootstrap completion | Liveness | All non-bootnode nodes reach steady state |
| P8 | Push silence | Safety | `pull_only` nodes generate zero Item-Push messages |
| P9 | Bootnode silence | Safety | Bootnodes generate zero replication messages |

- TLC model checking with default bounds: 2 personal, 1 bootnode, 1 relay, 2 channels, 2 items
- Larger bounds (2/1/2/2/3) for deeper verification on CI (self-hosted runner)

**Files**:
- `specs/network-protocol.tla` (TLA+ module)
- `specs/network-protocol.cfg` (TLC configuration)

**Estimate**: 2-3 days (draft exists, needs Martin review + TLC run + refinement)

**Owner**: Russell (draft), Martin (review, run TLC, iterate on counterexamples)

**Depends on**: Network protocol spec stable (done)

---

### WP15: Topology E2E Test Harness (Docker)

**What**: Systematic topology enumeration and Docker Compose E2E test harness that validates implementation against TLA+ properties.

**Why**: TLA+ verifies the design. E2E tests verify the implementation matches the design. Together they give a quantifiable confidence measure: `(TLA+ properties verified) x (topology coverage %) x (E2E pass rate)`.

**Scope**:
- Topology generator: parameterise node count per role, push_policy, connectivity pattern, failure mode
- 7 reference topologies (T1-T7) covering all role interactions
- Coverage metric: enumerate meaningful topology classes (~80-120), track % tested
- Assertion mapping: each TLA+ property maps to a concrete E2E assertion
- Extend existing `gen-compose-zoned.sh` with role parameterisation

| Topology | Nodes | Validates |
|----------|-------|-----------|
| T1: Minimal | 2P + 1B | Bootstrap, peer discovery, direct P2P sync |
| T2: Relay path | 2P + 1B + 1R | Store-and-forward, relay re-push, Gate 2 |
| T3: Pull-only | 2P (1 pull_only) + 1R + 1B | pull_only receives via Item-Sync only |
| T4: Multi-relay | 3P + 1B + 2R | Relay mesh fan-out, loop prevention |
| T5: Partition/heal | 2P + 2R + 1B | Network split, convergence after heal |
| T6: Bootnode loss | 3P + 1B (killed) | Steady state survives bootnode loss |
| T7: Channel isolation | 3P (different channels) + 1R | No cross-channel item leakage |

**Concrete assertions per topology:**
- P3: Query each node's SQLite, verify no cross-channel items
- P4: Bootnode has zero items in store; relay has zero PSKs
- P8: Packet capture / metrics counter, assert zero Item-Push from pull_only node
- P9: Bootnode metrics show zero Channel-Announce, Item-Sync, Item-Push
- P6: Partition via iptables, heal, assert item sets converge within timeout

**Files**:
- `cordelia-core/tests/e2e/gen-topology.sh` (topology generator)
- `cordelia-core/tests/e2e/topologies/t1-minimal.yml` through `t7-isolation.yml`
- `cordelia-core/tests/e2e/assertions/` (property assertion scripts)
- `.github/workflows/topology-e2e.yml` (CI workflow on self-hosted runner)

**Estimate**: 3-4 days

**Owner**: Martin (harness), Russell (topology enumeration, coverage metric)

**Depends on**: WP3 (pub/sub API working), WP14 (TLA+ properties defined)

---

### WP13: CLI Stats + Metrics Endpoint (cordelia-node)

**What**: Operational CLI commands and Prometheus metrics endpoint.

**Why**: Operators (and SPOs later) need visibility. Developers need to verify their node is working. Ties to core#45 (instrumentation review).

**CLI commands**:
```
cordelia status       # uptime, peer count, storage used, channels subscribed
cordelia peers        # peer list: entity, address, state (hot/warm), latency
cordelia channels     # channel list: name, item count, last activity, culture
cordelia stats        # detailed: storage bytes, bandwidth in/out, replication lag, sync errors
```

These are thin wrappers over existing node API endpoints (`/api/v1/status`, `/api/v1/peers`, `/api/v1/diagnostics`, channels/list). Formatted for terminal output.

**Metrics endpoint**:
```
GET /api/v1/metrics   # Prometheus exposition format
```

Exposes:
- `cordelia_peers_hot`, `cordelia_peers_warm` (gauges)
- `cordelia_items_total{group_id}` (gauge per channel)
- `cordelia_storage_bytes` (gauge)
- `cordelia_replication_lag_seconds` (gauge)
- `cordelia_sync_errors_total` (counter)
- `cordelia_bandwidth_bytes{direction="in|out"}` (counter)
- `cordelia_uptime_seconds` (gauge)

SPOs already run Prometheus/Grafana for Cardano nodes. Same stack, zero learning curve.

**Files**:
- `cordelia-core/crates/cordelia-node/src/cli.rs` (status, peers, channels, stats subcommands)
- `cordelia-core/crates/cordelia-api/src/metrics.rs` (new: Prometheus endpoint)

**Estimate**: 1-2 days

**Owner**: Martin

---

### WP10: Website Update (seeddrill.ai)

**What**: Update seeddrill.ai to reflect the pivot.

**Why**: Current site describes Cordelia as a memory system with portal-based onboarding. Needs to lead with "encrypted pub/sub for AI agents."

**Scope**:
- Homepage: new positioning, SDK code example, "5 minutes to encrypted channels"
- /install: updated to point to new one-line install script
- /quickstart: link to SDK README or embedded quickstart
- /whitepaper: link to updated whitepaper (WP11)
- Remove or redirect portal.seeddrill.ai references

**Estimate**: 1-2 days

**Owner**: Russell

---

### WP11: Whitepaper v2

**What**: Update the Cordelia whitepaper to reflect the simplified architecture and pub/sub positioning.

**Why**: The whitepaper (v1.0, 2026-01-31) describes a three-component architecture with portal. Needs to reflect two-component design, pub/sub channels, provider interface, and updated economics.

**Scope**:
- Architecture: two components (node + thin MCP adapter), remove portal from diagrams
- Channels: pub/sub as the primary developer abstraction
- Provider interface: standard storage contract for intelligence layers
- Economics: delegation model, SPO infrastructure (reference SPO ADR)
- Encryption: unified model (same E2E for all channels, admission policy varies)
- The five primitives, game theory, and cooperative equilibrium are unchanged

**Note**: Subsumes core#43 (architecture status doc). This is the honest gap analysis AND the updated vision in one document.

**Estimate**: 2-3 days

**Owner**: Russell (draft), Martin (review of technical accuracy)

---

### WP12: Bootnode Strategy

**What**: Define bootnode operation model for network bootstrap.

**Why**: Currently 2 Seed Drill bootnodes (boot1, boot2). Need a resilient, decentralisable discovery mechanism.

**Design**:

*MVP (Phase 1):*
- Seed Drill continues operating boot1 + boot2 (existing infrastructure)
- Add DNS-based discovery: `_cordelia._tcp.seeddrill.ai` SRV records pointing to known bootnodes. Resilient, works through firewalls, trivial to update.
- Hardcoded seed list compiled into `cordelia` binary as ultimate fallback (Bitcoin/Cardano pattern)

*Phase 3 (SPO integration):*
- SPOs can register as bootnodes: `bootnode = true` in keeper config. Same binary, stable public IP, 24/7 uptime -- SPOs have exactly this.
- Bootnode registry: Cardano on-chain metadata or Cordelia group-based registry (a "bootnodes" channel that nodes subscribe to for discovery)
- Goal: 10+ geographically distributed bootnodes, majority not operated by Seed Drill

**Implementation for MVP**:
- Add DNS SRV lookup to node discovery (Rust: `trust-dns-resolver` or `hickory-dns`)
- Add `--seed` CLI flag for manual bootnode addresses
- Compile-time seed list in `cordelia-node/src/config.rs`

**Estimate**: 1 day (DNS discovery + seed list)

**Owner**: Martin

---

## 9. Updated Dependency Graph

```
WP1 (ECIES)
  |
  +---> WP3 (Pub/Sub API) ---> WP6 (SDK) ---> WP9 (Docs)
  |       |
  |       v
  |     WP4 (L2 Encryption)
  |
  +---> WP5 (Local Enrollment)

WP2 (Name Resolution) ---> WP3 (Pub/Sub API)

WP7 (Install/Packaging) --- independent, can parallel
WP8 (FTS5 in Node) ---> WP3 (search endpoint)
WP10 (Website) --- parallel, Russell
WP11 (Whitepaper) --- parallel, Russell (after WP9)
WP12 (Bootnodes) --- parallel, Martin (alongside WP2)
WP13 (CLI Stats + Metrics) --- parallel, Martin (alongside WP5)
WP14 (TLA+ Verification) --- pre-coding, Russell draft + Martin review
WP15 (Topology E2E) ---> WP3 (API working), WP14 (properties defined)
```

**Critical path**: WP14 (2d) -> WP1 (2d) -> WP3 (4d) -> WP6 (3d) -> WP9 (1d) = ~12 days
**Note**: WP14 (TLA+ verification) is pre-coding. Must complete before WP3 implementation begins.

---

## 10. Updated Effort Summary

| WP | Description | Estimate | Owner | Depends On |
|----|-------------|----------|-------|------------|
| WP1 | ECIES envelope in Rust | 1-2 days | Martin | - |
| WP2 | Name-based group resolution | 1 day | Martin | - |
| WP3 | Pub/sub API endpoints | 3-4 days | Martin | WP1, WP2 |
| WP4 | L2 encryption in node | 2-3 days | Martin | WP1, WP3 |
| WP5 | Local enrollment CLI | 3-4 days | Martin | WP1 |
| WP6 | SDK package (TypeScript) | 2-3 days | Russell | WP3 (interface) |
| WP7 | Install script + packaging | 2 days | Martin/Russell | - |
| WP8 | FTS5 search in node | 1-2 days | Martin | - |
| WP9 | Documentation + quickstart | 1 day | Russell | WP6 |
| WP10 | Website update | 1-2 days | Russell | WP9 |
| WP11 | Whitepaper v2 | 2-3 days | Russell | WP9 |
| WP12 | Bootnode strategy (DNS + seeds) | 1 day | Martin | - |
| WP13 | CLI stats + Prometheus metrics | 1-2 days | Martin | - |
| WP14 | TLA+ protocol verification | 2-3 days | Russell/Martin | Specs stable |
| WP15 | Topology E2E test harness | 3-4 days | Martin/Russell | WP3, WP14 |

**Total**: ~27-39 days of work. With parallelism (Martin on Rust WP1-5,7-8,12-13,15; Russell on WP6,9-11,14), target 5-6 weeks calendar time.

**Verification gate**: WP14 (TLA+ model checking) must pass all 9 properties before WP3 implementation begins. This catches protocol design errors before any Rust is written.

---

## 11. What Keeps Working During Transition

The existing Cordelia deployment (proxy + node + portal) continues to function unchanged. This MVP is additive:

- Existing MCP tools via proxy: unchanged
- Existing Cordelia memory (L1/L2): unchanged
- Existing P2P replication: unchanged, pub/sub uses the same protocol
- Portal: still running on Fly, just not on the critical path
- Current bootnodes: unchanged, DNS discovery adds resilience

The SDK is a new interface to the same node. No migration required.

---

## 12. Future Phases (Post-MVP)

See architecture ADR Section 17 for full phase alignment with triggers.

**Phase 2: Developer Experience + Personal Memory** (trigger: MVP shipped)
1. Anthropic Memory Tool adapter -- Cordelia-backed storage for Claude's client-side memory
2. OpenAI Sessions store -- Cordelia as session backend for Agents SDK
3. MCP adapter thinning -- existing proxy stripped to session-scoped adapter
4. Vector search in node -- move sqlite-vec from proxy, provider interface for embeddings
5. Python SDK -- `pip install cordelia` for LangGraph/CrewAI (target: 2-4 weeks post-MVP)
6. TUI dashboard -- `cordelia monitor` (ratatui), real-time terminal UI for operators
7. Personal memory via personal group -- encrypted, auto-replicated to 2+ keepers

**Phase 3: Network Growth + SPO** (trigger: 100+ SDK installs)
1. SPO keeper deployment guide + Docker image
2. Delegation economics -- tier enforcement, Cardano on-chain verification
3. Cardano trust anchor -- keeper-to-keeper trust via pool registration/delegation
4. Bootnode decentralisation -- SPO-operated bootnodes, on-chain registry
5. Prometheus/Grafana dashboards for SPO monitoring
6. CORDELIA token policy ID registration (design only, no minting)

**Phase 4: Governance + Trust** (trigger: 10+ keepers)
1. Trust scoring (core#41) -- per-author quality signals
2. Group spectrum -- personal/restricted/public with content-addressed IDs
3. Moderate culture -- push header + demand-fetch for mid-size groups
4. Shamir secret sharing -- k-of-n recovery across keepers
5. Admission thresholds based on trust history

**Phase 5: Enterprise + Economics** (trigger: enterprise demand or asymmetric keeper costs)
1. Enterprise portal (optional web management)
2. Token deployment decision -- only if delegation model proves insufficient
3. Mem0/Letta storage adapters
4. Bilateral cross-keeper settlement (ADA or token)

---

*Plan drafted by Russell Wing (CPO), 2026-03-09*
*Decisions resolved 2026-03-09. Pending: Martin review of Rust-side feasibility and estimates.*
