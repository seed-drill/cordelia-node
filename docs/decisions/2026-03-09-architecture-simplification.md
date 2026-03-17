# Decision: Pivot to Encrypted Pub/Sub for AI Agents

**Date**: 2026-03-09
**Decision Maker(s)**: Russell Wing
**Status**: Approved in principle (Martin confirmed 2026-03-10: "Absolutely makes sense")
**Triggered by**: portal#30 scoping, competitive landscape analysis, market research
**Supersedes**: portal#30 approach (vault migration), previous Track 1-3 roadmap structure
**Related**: decisions/2026-03-07-network-architecture-review.md, decisions/2026-03-09-spo-economic-model.md, decisions/2026-03-10-identity-privacy-model.md, competitors/ai-memory-landscape-2026.md

---

## 1. Context

While scoping Track 1 item 4 (portal#30, vault to keeper), we questioned whether the portal, and the current three-component architecture, was the right direction. This led to a fundamental re-examination of Cordelia's product positioning, target market, and architecture.

### Market Analysis (2026-03-09)

Research into the AI agent memory landscape revealed:

**No standard memory interface exists.** Every layer of the stack handles memory differently:
- **Model providers**: Anthropic (client-side Memory Tool, you own storage), OpenAI (server-side Conversations API), Google (platform-native ADK). Three incompatible approaches.
- **Agent frameworks**: LangGraph (checkpointers + stores), CrewAI (ChromaDB + Mem0), OpenAI Agents SDK (sessions, explicitly defers long-term memory), Vercel AI SDK (delegates entirely).
- **Dedicated providers**: Mem0 ($249/mo for graph, 41K stars, $24M raised), Letta (OSS stateful), Cognee (graph-vector), Zep (temporal).
- **Standards bodies**: AAIF (Linux Foundation) stewarding MCP, AGENTS.md, Goose. No memory specification proposed by anyone.

**Key findings:**
1. Mem0 is the leader but is a cloud SaaS with lock-in, not an infrastructure standard. Being squeezed from above (provider-native memory) and below (framework-native memory).
2. Most common production pattern is still custom database + RAG.
3. Anthropic's Memory Tool is client-side -- you own the storage backend. This directly validates Cordelia's architecture.
4. **No major memory provider offers E2E encryption.** Not Mem0, not Letta, not Zep, not anyone. This remains uncontested whitespace.
5. Multi-agent shared memory does not exist as a product. Agents share context via in-memory state objects -- nothing persists, nothing encrypts, nothing works across machines.

### Strategic Insight

Cordelia already has the protocol primitives for encrypted group memory with pub/sub semantics (groups + culture + replication). The previous positioning as "encrypted storage layer" (S3 analogy) is technically correct but doesn't create developer pull. Nobody gets excited about storage.

**Encrypted pub/sub for AI agents** -- with group memory that actually works across machines, sessions, and teams -- is something no one else offers and developers can try in 5 minutes.

---

## 2. The Pivot

### From
"Encrypted storage and distribution layer for AI agent memory" -- infrastructure positioning, invisible to developers, competes on sovereignty.

### To
"Encrypted pub/sub for AI agents" -- developer tool positioning, immediately useful, competes on functionality AND sovereignty.

### Why This Is Stronger

1. **Agents already need to share context.** Multi-agent systems (CrewAI crews, LangGraph multi-agent, AutoGen teams) all need inter-agent communication. No encrypted solution exists.
2. **The deployment is one line.** `npm install @seeddrill/cordelia` or `curl install | sh`. Trivial.
3. **Groups are the killer feature nobody else has.** Mem0 is single-agent memory. Letta is single-agent state. Nobody does encrypted multi-agent shared memory.
4. **The Reddit/IRC model is immediately understood.** Subscribe to a channel, publish to a channel. Chatty = real-time (IRC). Taciturn = pull when ready (Reddit).
5. **Sovereign personal memory comes later.** Get traction with group pub/sub first, then expand to personal memory as the storage backend for Anthropic Memory Tool / OpenAI Sessions.

### How It Maps to Existing Primitives

| Pub/Sub Concept | Cordelia Primitive | Status |
|-----------------|-------------------|--------|
| Channel | Group | Exists |
| Subscribe | Join group (receive PSK, start replication) | Exists |
| Publish | Write item to group | Exists |
| Real-time delivery | Chatty culture (eager push) | Exists |
| Poll/pull delivery | Taciturn culture (anti-entropy) | Exists |
| Topic name | Group with human-readable name | Exists (UUID + name) |
| Channel discovery | Group gossip / registry | Partial |
| Encryption | Per-group AES-256-GCM via PSK | Exists |

The protocol is already there. What's missing is the developer experience on top of it.

---

## 3. Target Integration: Provider-Native Memory

Focus on Anthropic and OpenAI as the two acknowledged model provider leaders. Not Mem0/Letta/Cognee.

### Anthropic Memory Tool

Claude's Memory Tool is client-side: Claude makes tool calls (`view`, `create`, `str_replace`), your application executes them against local storage. You own the backend entirely. ZDR eligible.

**Cordelia as Memory Tool backend:**
- Personal group = private memory (encrypted, replicated to keeper for backup)
- Shared group = team memory (encrypted, replicated to all members)
- The Memory Tool's CRUD operations map directly to Cordelia's write/read/delete
- Encryption is transparent -- Memory Tool sees plaintext, Cordelia encrypts for storage/replication

### OpenAI Agents SDK Sessions

Sessions support multiple backends (SQLite, Redis, SQLAlchemy, OpenAI-hosted). Long-term memory explicitly deferred to external providers. Cookbook shows Mem0 integration.

**Cordelia as session backend:**
- Implement the session store interface backed by Cordelia node
- Session state encrypted and replicated
- Cross-machine session continuity via P2P replication

### SDK Interface

```javascript
import { Cordelia } from '@seeddrill/cordelia'

const c = new Cordelia()  // connects to local node

// Personal memory
await c.write('session-notes', content)
const notes = await c.read('session-notes')

// Group memory (pub/sub)
await c.subscribe('research-findings')
await c.publish('research-findings', { type: 'insight', content: '...' })
const items = await c.listen('research-findings')  // stream new items

// Search (local indexes, never sent over network)
const results = await c.search('research-findings', 'vector embeddings')

// All encrypted. All federated. Zero config.
```

---

## 4. Architecture: Two Components

### Decision: Portal Deprecation

The portal exists because we assumed web-based OAuth was required for identity. In a decentralised system, identity is your keypair. Ed25519 public key = entity_id.

| Portal Function | Required? | Alternative |
|----------------|-----------|-------------|
| OAuth login | No | Ed25519 keypair IS identity |
| RFC 8628 enrollment | No | Local enrollment, QR/manual key exchange |
| PSK generation | No | Generate locally, distribute via P2P |
| Vault (PSK/ECIES) | No | Keeper node handles vault |
| Group management | No | Protocol-level, local CLI/SDK |
| Agent provisioning | No | Generate keypair + credential bundle locally |

Portal remains available as an optional enterprise convenience. Not part of core protocol.

### Decision: Proxy Thinning

Two processes are unavoidable (MCP lifecycle vs daemon lifecycle). But the proxy shrinks from ~4,000 lines to ~800:

**Stays in proxy (session-scoped):**
- MCP stdio protocol handler
- Novelty filtering
- Session encryption context
- Default embedding generation (lightweight local model)

**Moves to node (persistent):**
- REST API, search indexing, L2 encryption, dashboard, local SQLite

### Resulting Architecture

```
Thin MCP Adapter (TypeScript)          Node (Rust)
  - MCP stdio protocol                  - Encrypted storage (replicated)
  - Novelty filtering                   - P2P networking + replication
  - Session context                      - REST API (bearer token auth)
  - Default embeddings                   - Local indexes: FTS, vector, graph
  - ~800 lines                           - Pub/sub group operations
                                         - Vault (keeper role)
                                         - Local enrollment CLI
         |                                      |
         +-------- node HTTP API ------------->+

  Spawned per session                    Daemon, always running
```

### Deployment Profiles

| Who | Runs | Components |
|-----|------|------------|
| Developer (Claude Code) | Personal node + MCP adapter | Node + adapter |
| AI agent (REST/SDK) | Talks to node directly | Node only |
| SPO keeper | Encrypted storage for the network | Node (keeper role) |
| SPO relay | Replication bandwidth | Node (relay role) |

---

## 5. Provider Interface

### The Encryption Constraint

Encrypted data cannot be searched. Therefore:
- **Encrypted blobs**: stored in node, replicated across network
- **Plaintext indexes**: maintained locally, never replicated
- Intelligence layers run locally (see plaintext), push index data to node
- Queries run against local indexes, items decrypted locally

### The Interface

```
// Storage (encrypted, replicated)
write(item_id, encrypted_blob, metadata) -> ok
read(item_id) -> encrypted_blob
delete(item_id) -> ok
list(group_id, since?, limit) -> item_headers[]

// Pub/Sub (encrypted, replicated)
subscribe(channel_name) -> { group_id, psk }
publish(channel_name, item) -> ok
listen(channel_name, since?) -> stream<item>

// Index: Vector (local-only, never replicated)
index_vector(item_id, embedding: float[]) -> ok
search_vector(query: float[], top_k, filter?) -> item_ids[]

// Index: Text (local-only, never replicated)
index_text(item_id, text: string) -> ok
search_text(query: string, limit, filter?) -> item_ids[]

// Index: Graph (local-only, never replicated)
index_edge(from_id, to_id, relation: string, weight?, metadata?) -> ok
traverse(start_id, relation?, depth?, direction?) -> edges[]
neighbors(item_id, relation?, direction?) -> item_ids[]

// Lifecycle
rebuild_indexes(group_id?) -> ok
```

### Index Implementation

| Index Type | Implementation | Maturity |
|------------|---------------|----------|
| Text (FTS) | SQLite FTS5 + BM25 | Proven (~6 months in proxy) |
| Vector | sqlite-vec cosine similarity | Proven (~6 months, 70/30 hybrid) |
| Graph | SQLite adjacency table + recursive CTE | New, simple, standard SQL |

### Embedding Resolution

**The node does not need ML inference.** Embedding generation is the intelligence layer's responsibility:
- Default: thin MCP adapter runs lightweight local model (TypeScript, current approach)
- Anthropic/OpenAI: their tools generate their own embeddings
- Custom: provider generates embeddings however they want

The node stores and searches vectors. It doesn't generate them.

### Replication and Index Rebuild

New device receives encrypted items via P2P replication -> decrypts locally -> intelligence layer rebuilds indexes from plaintext. Source of truth is encrypted items. Indexes are derived, local, rebuildable.

---

## 6. Cardano SPO Integration

This pivot strengthens the SPO angle (see decisions/2026-03-09-spo-economic-model.md):

- SPOs run keeper nodes: same Rust binary, keeper config
- Keeper stores encrypted pub/sub channel data
- Delegation-based economics: users delegate ADA to SPOs running Cordelia keepers
- SPO sets service parameters (storage, bandwidth, SLA)
- No portal needed: SPOs run the node binary, nothing else

The pitch: "Run a Cordelia keeper on your SPO infrastructure. Earn delegation for providing encrypted AI agent memory storage."

### Positioning Constraint

Cordelia's public identity leads with "encrypted pub/sub for AI agents", not Cardano infrastructure. SPO onboarding is a distribution channel, not the product identity. Detailed in decisions/2026-03-09-spo-economic-model.md Section 7.

---

## 7. What We Drop

| Item | Why |
|------|-----|
| Portal as critical path | Not needed. Keypair identity, local enrollment. |
| portal#30 (vault migration) | Dissolved. Vault is native to keeper, no migration. |
| portal#31 (portal scope reduction) | Superseded. Portal deprecated entirely from core. |
| PS8 (group invites via portal) | Superseded. Groups managed via SDK/CLI. |
| PS9 (vault polish) | Superseded. No portal vault. |
| Complex enrollment flow | Replaced by local keypair generation + P2P key exchange. |
| Proxy as full application | Thinned to MCP adapter. |
| Mem0/Letta/Cognee as integration targets | Deferred. Focus on Anthropic Memory Tool + OpenAI Sessions. |
| Graph/vector sophistication in node | Minimal viable indexes. Providers bring their own if needed. |

---

## 8. MVP: Encrypted Pub/Sub for Agents

### What "Done" Looks Like

A developer can:
1. `npm install @seeddrill/cordelia` (or curl install for the node binary)
2. `const c = new Cordelia()` -- connects to local node, auto-generates keypair
3. `await c.subscribe('my-channel')` -- creates or joins an encrypted channel
4. `await c.publish('my-channel', data)` -- publishes encrypted item, replicated to subscribers
5. `await c.listen('my-channel')` -- streams new items from other publishers
6. All data encrypted with per-channel AES-256-GCM. All replication via P2P. Zero config.

### What's Required

1. **Node: pub/sub API endpoints** -- subscribe (create/join group by name), publish (write to group), listen (stream group items since timestamp). Maps to existing group + L2 operations but with developer-friendly names.
2. **Node: name-based group resolution** -- `subscribe('research')` derives a content-addressed group ID from the name (SHA-256 of channel name for public groups, UUID for private). Currently all groups use UUID.
3. **Node: ECIES in Rust** -- envelope encrypt/decrypt for PSK distribution during subscribe. cordelia-crypto already has X25519.
4. **Node: local enrollment** -- generate keypair, discover bootnodes, join network. No portal.
5. **SDK package** -- `@seeddrill/cordelia` npm package wrapping node REST API with the subscribe/publish/listen interface.
6. **Trivial deployment** -- single binary install, zero config, auto-bootstrap.

### What's NOT Required for MVP

- Portal
- Proxy (agents use SDK directly; MCP adapter is separate, later)
- Vector/graph indexes (text search via FTS5 is sufficient for MVP)
- Anthropic Memory Tool adapter (Phase 2)
- OpenAI Sessions adapter (Phase 2)
- SPO keeper deployment (Phase 3)
- Token registration (Phase 3)

---

## 9. Phased Roadmap

### Phase 1: Encrypted Pub/Sub MVP

Goal: a developer can subscribe, publish, and listen on encrypted channels via the SDK.

1. Node: pub/sub REST endpoints (subscribe, publish, listen)
2. Node: name-based group resolution (content-addressed IDs)
3. Node: ECIES envelope in Rust (PSK distribution)
4. Node: local enrollment CLI (keypair gen, bootnode discovery)
5. SDK: `@seeddrill/cordelia` npm package
6. Install: one-line install script (node binary + systemd/launchctl)
7. Docs: "Encrypted Pub/Sub in 5 Minutes" quickstart

### Phase 2: Provider Integration + Personal Memory

Goal: Cordelia as storage backend for Claude Memory Tool and OpenAI Sessions. Sovereign personal memory.

1. Anthropic Memory Tool adapter (Cordelia-backed CRUD)
2. OpenAI Sessions store adapter
3. Personal memory via personal group (private, encrypted, replicated to keeper)
4. MCP adapter thinning (session-scoped novelty + tool definitions only)
5. Vector search in node (move sqlite-vec from proxy, provider interface for embeddings)
6. Python SDK (`pip install cordelia` for LangGraph/CrewAI)

### Phase 3: Network Growth + SPO

Goal: third-party infrastructure, economic model live.

1. SPO keeper deployment guide + Docker image
2. Delegation-based economics (Cardano)
3. Graph indexes on node (adjacency table + recursive CTE)
4. CORDELIA token registration (Cardano, policy ID only)
5. Tokenomics design document

### Phase 4: Scale

Goal: production-grade network with multiple intelligence providers.

1. Provider adapters (Mem0, Letta storage backends)
2. Trust scoring (core#41)
3. Group spectrum (personal -> restricted -> public)
4. Enterprise portal (optional, web management)

---

## 10. Assumptions / Hypotheses

1. **Agents need encrypted shared memory.** Hypothesis: multi-agent systems will pay for encrypted cross-machine context sharing. Validated by: no competing solution exists.
2. **Pub/sub is the right abstraction.** Hypothesis: subscribe/publish/listen is immediately understood by developers. The Reddit/IRC model maps to group culture naturally.
3. **Key-based identity is sufficient.** Hypothesis: agents don't need OAuth. Keypairs are natural for programmatic identity.
4. **Provider-native memory is the growth vector.** Hypothesis: Anthropic and OpenAI's client-side memory patterns drive more adoption than dedicated memory providers (Mem0/Letta).
5. **Deployment simplicity drives adoption.** Hypothesis: if it takes more than 5 minutes to get running, developers won't try it.
6. **Encryption is a buying criterion.** Hypothesis: EU AI Act (August 2026), GDPR, and enterprise security requirements make E2E encryption a real differentiator, not just a feature.

---

## 11. Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Developers don't need multi-agent memory yet | Medium | High | Market is moving toward multi-agent fast. CrewAI, LangGraph multi-agent, AutoGen teams all growing. Early mover advantage. |
| Anthropic/OpenAI build their own encrypted memory | Low | High | They're focused on intelligence, not infrastructure. Anthropic explicitly makes memory client-side. Even if they build it, Cordelia is cross-provider. |
| Pub/sub abstraction is wrong | Low | Medium | It maps directly to existing Cordelia primitives. If wrong, the underlying group/replication protocol still works -- just change the SDK surface. |
| Single binary deployment is hard (Rust + dependencies) | Medium | Medium | Static linking. Minimal dependencies. Docker as fallback. |
| ECIES reimplementation in Rust introduces crypto bugs | Medium | High | Use audited crates (x25519-dalek, aes-gcm, hkdf). Port test vectors from TypeScript. |
| SPO community doesn't engage | Medium | Medium | SPO integration is Phase 3, not MVP. Network works with Seed Drill-operated bootnodes initially. |

---

## 12. Success Criteria

**Phase 1 (60 days):**
- SDK published to npm
- A developer can subscribe/publish/listen in <5 minutes
- Encrypted channel replication working between 2+ nodes
- "Encrypted Pub/Sub in 5 Minutes" quickstart published

**Phase 2 (4 months):**
- Anthropic Memory Tool adapter functional
- Personal memory working (encrypted, replicated)
- 100+ npm installs

**Phase 3 (8 months):**
- 3+ SPO keepers running on Cardano infrastructure
- Delegation economics operational
- 500+ npm installs, 50+ GitHub stars on SDK

---

## 13. Review Date

2026-04-09 (30 days). Review:
- Phase 1 progress
- Developer feedback on pub/sub abstraction
- Any blockers to single-binary deployment

---

## 14. Resolved Design Decisions

### Channel Encryption Model (Resolved 2026-03-09)

**Random PSK for ALL channels. Same E2E encryption everywhere. Admission policy varies, not encryption.** For the full identity model, privacy position, credential-based access policies, and DM design, see decisions/2026-03-10-identity-privacy-model.md.

| Channel Type | PSK | Admission | Encryption |
|-------------|-----|-----------|------------|
| Private | Random, ECIES envelope | Invitation from admin/owner | Full E2E |
| Public | Random, ECIES envelope | Any member auto-approves new subscribers | Full E2E |

Public channel join: subscriber requests, any existing member's node auto-distributes PSK via ECIES envelope. No human approval, no derived keys, no compromise.

### PSK Trust Boundary (Resolved 2026-03-10)

**Position: The anchor keeper holds PSKs for channels it anchors. This is an honest, defensible trust boundary -- not a weakness to hide.**

The keeper is your chosen infrastructure provider. For channels it anchors, the keeper holds the PSK in order to distribute it to approved subscribers (including when no other member is online). This means the keeper COULD technically decrypt content. It is economically incentivised not to.

**Trust level by channel type:**

| Channel Type | Keeper Has PSK? | Why | Trust Required |
|---|---|---|---|
| Open | Yes (anchor keeper) | Availability: distribute PSK when no member online | Moderate |
| Invite-only | No | Owner distributes PSK directly to invitees (out-of-band or via DM) | Low -- keeper is pure encrypted storage |
| Gated (payment/credential/delegation) | Yes (anchor keeper) | Enforcement: verify condition then distribute PSK | High -- keeper is trusted gatekeeper |
| DMs | No | Both parties derive shared secret or owner ECIES-envelopes to peer | Low -- keeper is pure encrypted storage |

**What the keeper genuinely CANNOT see:**
- Channels anchored on other keepers (only stores encrypted blobs it cannot decrypt)
- Invite-only channel content (never receives PSK)
- DM content (key exchange is peer-to-peer, no keeper involvement)
- Content on channels where it is not the anchor (pure replication of encrypted blobs)

**What the keeper CAN theoretically see:**
- Content of channels it anchors (it holds the PSK for distribution purposes)

**Mitigations:**
1. **Economic**: caught snooping = delegators leave = revenue gone. Keeper's business model depends on trust.
2. **Market**: users choose keepers. Bad actors lose business to honest competitors.
3. **Transparency**: public metrics via `cordelia:directory`. Anomalous behaviour detectable by peers.
4. **Structural**: PSK rotation + re-anchor channel to different keeper at any time.
5. **Self-hosting**: run your own keeper node for channels you really care about.
6. **Phase 4**: threshold PSK (Shamir across k-of-n keepers, no single keeper can reconstruct).

**Invite-only as the zero-trust option:** For channels where you genuinely don't want ANY infrastructure provider to see content, use `invite_only`. Owner distributes PSK directly. Keeper is pure encrypted storage. Same encryption, zero PSK exposure.

**The analogy:** Your email provider can read your email. Your cloud provider could read your files. Cordelia's keeper is similar for open/gated channels -- but unlike email or cloud, you choose your keeper from a competitive market, and invite-only/DMs give you a genuinely private option that no infrastructure can read.

**Impact on claims:** All ADR text updated from "keeper never decrypts" to accurately reflect: "keeper holds PSKs for channels it anchors; invite-only and DMs are genuinely private." The narrative is honest and defensible.

### Bootnode Strategy and Decentralised Discovery (Resolved 2026-03-10)

**Principle: Seed Drill is just another participant, not a central authority.** Discovery is fully decentralised. Seed Drill seeds the network; it does not control it.

**Four-layer discovery model:**

| Layer | Name | Purpose | Trust Model |
|-------|------|---------|-------------|
| 1 | Bootstrap Seeds | Find first keeper | Operational convenience, replaceable |
| 2 | On-Chain | Authoritative keeper registry | Trustless (Cardano chain data) |
| 3 | Gossip | Real-time peer discovery | Protocol-level, existing mechanism |
| 4 | Directory Channel | Live, self-updating keeper directory | Cordelia protocol, well-known PSK |

**Layer 1 -- Bootstrap Seeds:**
- DNS SRV: `_cordelia._tcp.seeddrill.ai` returns 2-3 seed keeper addresses
- Hardcoded seeds in binary (Seed Drill + SPO volunteers)
- Any SPO can run DNS seeds on their own domain: `_cordelia._tcp.stakenuts.com`
- Purely operational. Not authoritative. Replaceable.

**Layer 2 -- On-Chain (Cardano):**
- CIP-6 extended metadata IS the keeper registry. No aggregator needed.
- Anyone queries this: Koios (decentralised), Blockfrost (self-hostable), own db-sync, cardano-cli
- CIP-10 registered metadata label for Cordelia: bootnode lists published as transaction metadata
- Anyone can publish bootnode lists (Seed Drill, SPOs, community). Readers merge, latest slot per publisher wins.
- Cost: ~0.2 ADA per transaction. Update monthly or on bootnode set change.
- Permanently on-chain. Recoverable from any Cardano full node even if all websites go down.

**Layer 3 -- Gossip:**
- Once connected to any keeper, existing group exchange/peer gossip discovers all others
- Service manifests exchanged. New keeper online → propagates to all peers within minutes.

**Layer 4 -- Directory Channel (`cordelia:directory`):**
- Well-known reserved channel. Every keeper publishes service manifests here.
- Well-known PSK (published in protocol spec). Encrypted for protocol uniformity, but readable by anyone with the spec.
- Chatty culture: eager push. New keepers discovered quickly.
- Keeper-writable only. Auto-subscribed on first boot.
- Any client subscribed gets a live, self-updating keeper directory.
- The channel IS the directory. No central aggregator.

**Cascade:** First-ever connection uses Layer 1 (DNS seed) or Layer 2 (on-chain). Client subscribes to `cordelia:directory` (Layer 4). After initial bootstrap, Layers 3+4 sustain discovery indefinitely. Layers 1+2 never needed again unless all peers lost.

**Seed Drill's role:** Runs 1-2 bootnodes (just another keeper). Maintains DNS SRV (operational convenience). Publishes bootnode metadata on-chain (anyone else can too). Develops the binary (open source). Controls nothing.

**CIP-10 metadata label registration:** Register a Cordelia-specific transaction metadata label. The label supports multiple message types:
- `bootnodes`: Keeper endpoint lists (Phase 3)
- `channel-register`: Channel name registration with deposit UTXO (Phase 3)
- `quality`: Keeper quality summaries from oracles (Phase 4+)
- `governance`: Protocol votes (Phase 5, if token deployed)

MVP: Seed Drill boot1/boot2 + DNS SRV + hardcoded seeds. On-chain bootnode registry and directory channel in Phase 3.

### SDK Repo (Resolved 2026-03-09)

New repo: `cordelia-sdk`. Separate npm package, own release cadence. Not embedded in proxy.

### Binary Name (Resolved 2026-03-09)

`cordelia` (not `cordelia-node`). Single user-facing binary with subcommands.

### Default Culture (Resolved 2026-03-09)

Chatty by default (eager push, real-time). Configurable to taciturn on channel creation.

### Developer-Facing Terminology (Resolved 2026-03-10)

The SDK uses developer-friendly terminology. The protocol/whitepaper retains original terms.

| Protocol (internal) | SDK (developer-facing) | Meaning |
|---|---|---|
| chatty | `realtime` | Eager push on write, real-time delivery |
| taciturn | `batch` | Pull-based sync, periodic |

```javascript
await c.subscribe('alerts')                              // realtime (default)
await c.subscribe('archive', { mode: 'batch' })          // pull-based
```

Node API accepts both vocabularies for backwards compatibility with internal tooling.

### SDK-to-Node Listen Mechanism (Resolved 2026-03-10)

Phase 1: REST polling (`POST /channels/listen { since }` returns items). Simple, stateless, works with any HTTP client. SDK abstracts poll interval internally.

Phase 2: Server-Sent Events (`GET /channels/listen/stream`) for real-time delivery. SDK switches transparently -- no API change for developers.

---

## 15. Further Resolved Decisions (2026-03-09)

### Passphrase Recovery Without Portal

**Position: Recovery keys on keeper + device-based redundancy. Shamir deferred to Phase 4.**

- On `cordelia init`, user sets a recovery passphrase (optional -- agents skip this)
- Recovery keys (passphrase-encrypted PSKs) stored on keeper nodes. Keeper cannot decrypt -- just stores and serves the encrypted blob on authenticated request.
- Multi-keeper redundancy: recovery keys replicated to all keepers the entity uses (same replication as any encrypted item). Losing one keeper doesn't lose recovery.
- `cordelia recover` on a new device: enter passphrase, keeper serves encrypted blob, decrypt locally.
- Second device IS automatic backup: `cordelia pair` distributes all PSKs. If you have 2 devices, either can recover without passphrase.
- For agents: no passphrase. Credential bundle generated at provisioning contains all PSKs. Operator backs up the bundle file. Standard secret management.
- Shamir secret sharing (k-of-n across keepers) is Phase 4. Desirable for high-assurance scenarios but passphrase + device redundancy covers MVP.

### Channel Governance: Keeper-Anchored Model (Resolved 2026-03-09, updated 2026-03-10)

**Position: Channels are anchored to a keeper. Channel creation consumes keeper resources. Keeper operator controls quotas. Channel names are globally unique and registered on-chain.**

A channel cannot exist without a keeper to anchor it. This links channel creation to infrastructure provisioning and prevents unbounded free-riding.

**How it works:**
- Channel creation specifies (or defaults to) a keeper. The keeper is the origin/authoritative store.
- The keeper operator (SPO) sets resource quotas via their commercial policy (see SPO economic model ADR, Section 4).
- Other keepers replicate channels only when their own members subscribe.
- Channel ownership carries responsibility: the owner's keeper is the anchor.

**Data model:** `keeper_origin` field on groups table from day one (WP2). Quota enforcement soft in MVP (Seed Drill keepers, rate limiting only), hard in Phase 3 (SPO keepers, commercial policy enforcement).

### Channel Name Registration (Resolved 2026-03-10)

**Phase 1: Channels are off-chain only.** `subscribe('name')` creates the channel locally; name uniqueness enforced by the anchor keeper (local check against known channels). No ADA deposit, no on-chain transaction. This is sufficient for MVP where Seed Drill operates the keepers.

**Phase 3: On-chain registration adds global uniqueness, ADA deposit, and dispute resolution.** Agent spending policy (`max_per_channel_ada`, `auto_approve`) is also Phase 3+ -- no on-chain payments in Phase 1 means no spending policy needed.

**Position: Channel names are globally unique, first-come-first-served, registered on-chain via Cardano transaction (Phase 3).**

**Naming rules:** RFC 1035 Section 2.3.1 (DNS label rules):
- Lowercase letters (a-z), digits (0-9), hyphens (-)
- 3-63 characters, must start with a letter, must not end with a hyphen
- Case-insensitive (normalised to lowercase)
- Reserved prefix: `cordelia:` for system channels
- No dots, no slashes (flat namespace)
- `/` reserved as illegal character (preserves option for hierarchical namespaces in Phase 4+ if demand materialises)

Designed for future CIP submission and RFC compliance. Flat now; hierarchy can be added later by allowing `/` in names with parent resolution. Removing hierarchy once added would be painful, so we defer until validated by real user demand.

**On-chain registration format** (Cordelia CIP-10 metadata label):

```json
{
  "XXXX": {
    "t": "channel-register",
    "v": 1,
    "channels": [
      {
        "name_hash": "sha256:a1b2c3...",
        "name": "ai-research",
        "anchor": "pool1abc...",
        "owner": "script_hash_or_pubkey",
        "type": 0,
        "slot": 147900000
      }
    ]
  }
}
```

| Field | Public Channel | Private Channel | Notes |
|---|---|---|---|
| `name_hash` | SHA-256 of name | SHA-256 of name | Always present, uniqueness proof |
| `name` | Plaintext | Omitted | Private names never on-chain |
| `anchor` | Anchor keeper pool_id | Anchor keeper pool_id | |
| `owner` | Script hash or pubkey | Script hash or pubkey | Supports multisig from day one |
| `type` | 0 (public) | 1 (private) | |
| `slot` | Registration slot | Registration slot | Dispute resolution: lowest slot wins |

**Channel deposit:** Cardano min-UTXO (~2 ADA) locked per channel. Returned on channel deletion/release. Drives Cardano transaction activity (benefits SPOs who earn from block production). Not burned.

**Two-phase creation:**
1. **Instant (off-chain):** User calls `subscribe('name')`, keeper creates group locally, channel immediately operational, announced in `cordelia:channels` as soft reservation.
2. **Epoch-batched (on-chain):** Keeper batches pending registrations into a single Cardano transaction. Locks deposit per channel. Channel status: registered.

**Race condition:** Two keepers register same name in same epoch window. Lowest slot number wins. Loser notified, data preserved under group_id, name reassigned.

**Channel ownership:** Uses Cardano native scripts (no smart contracts needed for basic cases):
- Single owner: `RequireSignature(ed25519_pk1)` (default)
- Team ownership: `RequireMOf(m, [keys...])` (multisig, M-of-N)
- Transfer: Cardano transaction spending channel UTXO to new owner script address. Requires current owner's signature(s).

**Anti-squatting (layered):**
1. Keeper tier limits constrain channel count per user
2. ADA deposit (~2 ADA per channel) makes mass squatting expensive
3. Keeper-level policy (operators can reject obviously squatted names)
4. Expiry: zero subscribers for 180 days = name eligible for release, deposit returned
5. Community governance (Phase 5, if token deployed)

### Channel Access and Payment Policy (Resolved 2026-03-10)

**Position: Channel owners set access policy using the unified condition schema. Keeper enforces it by gating PSK distribution. All on-chain verification is trustless.**

This is the content monetisation layer, distinct from keeper infrastructure economics. Channel access policies use the same condition types and policy structure as keeper commercial policies (see SPO economic model ADR Section 3, identity ADR Section 6).

**Channel access types** (unified condition types):

| Access Type | Who Can Subscribe | Verification | Phase |
|---|---|---|---|
| `open` | Anyone | Auto-approve, PSK distributed immediately | 1 |
| `invite_only` | Explicit invitation from admin | Admin distributes PSK manually (keeper never holds PSK) | 1 |
| `credential` | Present matching signed credential | Issuer signature verification | 1+ |
| `delegation` | Delegators to anchor keeper's pool | On-chain delegation query | 3 |
| `ada_payment` (one-time) | Anyone who pays X ADA | On-chain payment tx verification | 3+ |
| `ada_payment` (recurring) | Anyone who pays X ADA per epoch | Ongoing on-chain verification | 3+ |
| `token_gate` | Holders of specific Cardano native asset | On-chain token holding query | 4+ |

**Subscription flow (paid channel):**
1. User: `c.subscribe('premium-insights')`
2. SDK reads channel metadata → sees payment condition
3. SDK prompts user (or agent auto-approves per spending policy)
4. User submits Cardano tx: X ADA to channel owner's address
5. User provides tx_hash to anchor keeper
6. Keeper verifies payment on-chain (Blockfrost/Koios/cardano-cli)
7. Keeper distributes PSK via ECIES envelope
8. User subscribed. All content E2E encrypted regardless of payment model.

**Revenue model:** Pass-through. 100% of channel subscription revenue goes to channel owner. Keeper earns from delegation, not content. Keeper can optionally set a commission in their commercial policy (default 0%) -- market decides whether that's valued.

**Agent spending policy** (for automated agents):
```json
{
  "spending_policy": {
    "max_per_channel_ada": 10,
    "max_total_ada_per_epoch": 50,
    "auto_approve": true
  }
}
```

**Two-layer economic model:**
- Layer 1 (Infrastructure): User ↔ Keeper. Delegation-based or keeper's commercial policy. Keeper provides storage, bandwidth, channels.
- Layer 2 (Content): Subscriber ↔ Channel Owner. Payment per channel owner's access policy. Keeper enforces access; holds PSK for open/gated channels (see PSK Trust Boundary above). Invite-only channels: keeper never holds PSK.

Both layers: all payments on-chain, verifiable, auditable. All content E2E encrypted. Keeper is infrastructure + enforcer. For open/gated channels, anchor keeper holds PSK (see PSK Trust Boundary). For invite-only channels, keeper never holds PSK.

### Channel Directory (Resolved 2026-03-10)

**`cordelia:channels` -- reserved system channel for public channel listings.**

Third reserved channel alongside `cordelia:directory` and `cordelia:attestations`:

```
Reserved System Channels:
├── cordelia:directory      → keeper manifests (who runs infrastructure)
├── cordelia:channels       → public channel listings (what's available)
└── cordelia:attestations   → peer quality attestations (Phase 4+)

All: well-known PSK, chatty culture, keeper-writable, auto-subscribed
```

Each keeper periodically publishes its public channel listings:

```json
{
  "type": "channel-listing",
  "keeper_pool": "pool1abc...",
  "channels": [
    {
      "name": "ai-research",
      "id": "sha256:a1b2c3...",
      "culture": "chatty",
      "subscribers": 342,
      "keepers_replicating": 12,
      "created_at": "2026-02-01T00:00:00Z",
      "description": "AI research findings and insights",
      "tags": ["ai", "research", "ml"],
      "access": { "type": "open" },
      "on_chain_slot": 147823400,
      "status": "registered"
    }
  ],
  "updated_at": "2026-03-10T09:00:00Z"
}
```

Private channels never appear in `cordelia:channels`. Only the name_hash is registered on-chain.

### Rate Limiting and Abuse on Public Channels

**Position: Rate limiting per entity + owner moderation for MVP. Trust scoring Phase 4.**

- **Rate limiting**: configurable per channel by owner. Default: 60 writes/minute per entity. Enforced at node level.
- **Owner moderation**: channel owner and admins can remove members. Removal triggers PSK rotation (existing E4 mechanism). Removed member locked out of future reads and writes.
- **Item deletion**: owner can tombstone items (CoW soft delete). Spam removed from all subscribers via replication.
- **Auto-ban**: 3 removals from same channel = permanent ban (entity blocked from re-subscribing). Simple heuristic.
- Phase 4 adds trust scoring (core#41): per-author quality signals, admission thresholds based on trust history.

### Python SDK Timing

**Position: Phase 2, target 2-4 weeks post-MVP.**

- REST API is the contract. Python SDK is a thin HTTP client wrapper (httpx or requests). Same subscribe/publish/listen/search interface as TypeScript.
- LangGraph and CrewAI (Python agent frameworks) are where multi-agent memory demand is strongest. This is not optional -- it's the second SDK, not an afterthought.
- If REST API docs are solid (WP9), community contribution is possible. But we should own it for quality.
- `pip install cordelia` with identical developer experience to `npm install @seeddrill/cordelia`.

### CLI Stats and Observability

**Position: CLI stats and Prometheus metrics in MVP (WP13). TUI dashboard in Phase 2.**

- `cordelia status/peers/channels/stats` for terminal output
- `GET /api/v1/metrics` in Prometheus exposition format (SPOs already run Prometheus/Grafana)
- `cordelia monitor` TUI (ratatui) in Phase 2 -- real-time dashboard for operators. Same data, live-updating.

---

## 16. Federation Model (Resolved 2026-03-09)

### Keeper-to-Keeper Trust: Cardano as Trust Anchor

Keepers verify each other's identity and trustworthiness via Cardano on-chain data. No custom reputation system needed.

**Peering flow:**
1. Keepers exchange Cardano pool IDs when connecting
2. Each keeper verifies the other on-chain: pool registration, delegation, blocks minted, pool age
3. Trust score derived from on-chain signals:
   - Registered pool (500 ADA deposit) = baseline trust
   - Higher delegation = more community trust
   - More blocks minted = proven operational history
   - Older pool = established operator
4. Unregistered pool = trust 0 = won't peer. Prevents Sybil flooding.

**Cryptographic binding via Calidus keys (CIP-0151):**

Calidus keys (CIP-0151, Active since 2025-02-17) are Ed25519 key pairs registered on-chain by SPOs, authorized by their cold key. Designed for hot/daily-use authentication without exposing cold, KES, or VRF keys. ~200 pools registered on mainnet as of March 2026. Tooling: `cardano-signer` (gitmachtl), Koios API, Blockfrost API.

Keeper identity binding flow:
1. SPO registers Calidus key on-chain (one-time, cold key signs the registration)
2. SPO signs Cordelia node's Ed25519 public key with Calidus secret key (hot, daily-use key)
3. Keeper presents to peers: signature + Calidus pubkey + pool_id
4. Peer verifies:
   - Ed25519 signature valid for Calidus pubkey (local crypto, instant)
   - Calidus pubkey is active registered key for pool_id (Koios: `GET /api/v1/pool_calidus_keys?_pool_bech32=pool1...`)
   - Pool is registered, active, has delegation (same API query)

Cryptographic chain: **Cold Key (on-chain) -> authorizes Calidus Key (on-chain, CIP-0151 label 867) -> signs Cordelia node identity (off-chain)**. Unforgeable without SPO's Calidus secret key. Rotatable without pool re-registration (higher nonce replaces previous).

Ed25519 on both sides (Calidus and Cordelia node identity) -- trivially compatible, no curve translation needed.

**Calidus Deep-Dive (Resolved 2026-03-10):**

Calidus keys are independently generated Ed25519 keypairs (not derived from cold key). Registration uses CIP-0088 v2 under transaction metadata label 867. Cold key signs the registration payload; Calidus key is field 7 (32 bytes raw). Nonce-ordered (highest nonce = active key). As of 2026-03-10: 231 pools registered (~8% of active pools).

Tooling: `cardano-signer` (gitmachtl/cardano-signer) handles keygen, registration signing, arbitrary data signing, and verification. Standard Ed25519 throughout -- `ed25519-dalek` in Rust, `@noble/ed25519` in TypeScript.

Challenge-response detail:
1. Keeper claims pool_id in handshake
2. Peer sends 32-byte random nonce
3. Keeper signs nonce with Calidus secret key
4. Peer verifies: Ed25519(signature, nonce, calidus_pubkey) using on-chain Calidus key
5. Peer verifies: Calidus key is registered for claimed pool_id (Koios `pool_calidus_keys` endpoint)

Lookup: Koios `GET /api/v1/pool_calidus_keys` returns all registered keys. Blockfrost pool endpoints include Calidus data. Cache with epoch-aligned TTL (5 days) since registrations rarely change.

Gotchas: No explicit revocation (replace with higher nonce or all-zeros key). CBOR field ordering matters for hash verification. v1 vs v2 signature format difference (v2 signs blake2b-256 of hex-encoded CBOR). Cold key exposure only at registration time (air-gappable).

Requirement: Calidus key registration is a prerequisite for SPO keeper participation. This is a reasonable quality signal -- all serious operators have or can easily register one. ~231 pools is sufficient for Phase 3 pilot.

**MVP:** Seed Drill keepers (trusted by default). `pool_id` field in keeper config from day one. On-chain verification module built in Phase 3 alongside SPO deployment.

### Minimum Replication: Seamless, No Configuration

**Personal memory:** replicates to at least 2 keepers (primary + auto-selected backup).

**Channel memory:** target replication factor of min(3, keepers_with_subscribers).

**Auto-selection on `cordelia init`:**
- Node discovers available keepers via bootnodes/gossip
- Selects primary (low latency, high uptime) + backup (geographic diversity)
- If user already delegates ADA to an SPO running a keeper, prefers that keeper
- No user configuration needed. Shown in `cordelia status`.

**Underreplication handling:**
- `cordelia channels` shows replication factor per channel
- Channels on only 1 keeper flagged as "underreplicated"
- System auto-requests one additional keeper to replicate (if capacity available)
- No user intervention for default cases

**MVP:** Seed Drill operates 2-3 keepers. Auto-selection picks from those. Replication status visible. Full geographic diversity in Phase 3 with SPO keepers.

### Cross-Keeper Economics: Accept Cost, Revisit at Scale

Each keeper stores channels its own members subscribe to. Cost follows the subscriber. Accepted as cost of network participation (ISP peering model).

Review trigger: if any keeper's cross-keeper replication exceeds 2x locally-originated storage, investigate bilateral ADA settlement or token mechanisms. Flagged for Phase 5.

### On-Chain Data Architecture (Resolved 2026-03-10)

```
Cardano Blockchain
├── CIP-0151 (label 867): Calidus key registrations
│   └── SPO → Calidus pubkey (identity anchor)
│
├── CIP-6 extended metadata: Cordelia service manifest + commercial policy
│   └── SPO → keeper endpoint, plans, region, cultures
│
├── Cordelia metadata label (CIP-10 registered):
│   ├── type: "bootnodes"         → keeper endpoint lists (anyone publishes)
│   ├── type: "channel-register"  → channel name + owner + deposit UTXO
│   ├── type: "quality"           → keeper quality summaries (oracle)    [Phase 4+]
│   └── type: "governance"        → protocol votes (token holders)      [Phase 5]
│
├── Channel deposit UTXOs: ~2 ADA locked per channel (native script ownership)
│
└── Native ledger: delegation amounts, payment transactions (already exists)

Cordelia Network
├── cordelia:directory     → live keeper manifests (chatty, well-known PSK)
├── cordelia:channels      → public channel listings (chatty, well-known PSK)
├── cordelia:attestations  → peer quality attestations              [Phase 4+]
└── user channels          → encrypted pub/sub (per-channel PSK)
```

### Delegation Proof Mechanism (Resolved 2026-03-10)

**Verification cadence: epoch-aligned (every 5 days).** Delegation changes only take effect at epoch boundaries. No real-time checks needed.

**Three verification paths (keeper chooses based on available infrastructure):**

1. **cardano-cli (preferred, zero cost):** `cardano-cli conway query stake-address-info --mainnet --address stake1...` Returns current delegation pool and balance. Available on any machine with cardano-node access. Zero API dependency.

2. **Koios API (decentralised, free tier available):** `POST /pool_delegators` with pool_id. Or `GET /account_info` with stake address. Decentralised -- anyone can run an instance. Free tier sufficient for epoch-cadence checks.

3. **Blockfrost API (commercial, free tier: 50K req/day):** `GET /accounts/{stake_address}` returns pool_id + controlled_amount. Self-hostable via blockfrost-platform (open source).

**For keepers on relay nodes (Option A):** cardano-cli is present. Use it. Zero external dependency.

**For keepers on separate servers (Option B/C):** Koios or Blockfrost. Free tiers handle epoch-cadence checks for hundreds of delegators easily.

### SPO Deployment Options (Resolved 2026-03-10)

Three supported deployment scenarios:

| Option | Where | Delegation Verification | Calidus Key |
|--------|-------|------------------------|-------------|
| A: On relay node | Alongside cardano-node | cardano-cli (local, zero cost) | On same machine |
| B: Separate server | Own VPS/server | Koios or Blockfrost API | Copied to server (Ed25519 file) |
| C: Docker sidecar | Any Docker host | Koios or Blockfrost API | Mounted as volume |

`cordelia init --spo` auto-detects: if cardano-cli is found, uses it. Otherwise prompts for Blockfrost project ID or Koios token (optional, has free unauthenticated tier).

All three options are functionally identical for keeper operation. Only the delegation verification path changes.

### CIP-6 Extended Metadata for Cordelia (Resolved 2026-03-10)

SPOs advertise Cordelia capability via CIP-6 extended metadata:

**Standard metadata (512 bytes, on-chain hash-verified):** Adds `extDataUrl` + `extSigUrl` fields. If SPO already has these set, no on-chain transaction needed.

**Extended metadata (no size limit, no on-chain transaction to update):**

```json
{
  "serial": 1,
  "pool": { "...existing CIP-6 fields..." },
  "cordelia": {
    "version": "1.0",
    "keeper": true,
    "relay": true,
    "endpoint": "https://keeper.example.com:7847",
    "pubkey": "ed25519_pk1...",
    "plans": [
      { "name": "free", "conditions": [], "limits": { "storage_mb": 1, "channels": 2 } },
      { "name": "basic", "conditions": [{"type":"delegation","min_ada":500}], "limits": { "storage_mb": 10, "channels": 5 } },
      { "name": "premium", "conditions": [{"type":"delegation","min_ada":5000}], "limits": { "storage_mb": 1024, "channels": 50 } }
    ],
    "cultures": ["chatty", "taciturn"],
    "region": "eu-west"
  }
}
```

CIP-6 `plans` array uses the same unified condition schema as the keeper commercial policy (see SPO economic model ADR Section 3). Unknown fields are ignored by existing pool browsers (CIP-6/CIP-100 design). No breakage. Updates require only changing the hosted file and bumping `serial` -- no cold key, no on-chain transaction.

`cordelia init --spo` generates: (1) the cordelia metadata section, (2) merged extended-metadata.json, (3) Ed25519 signature file. For SPOs without extDataUrl, generates the re-registration transaction body (~2 ADA, one-time).

### Oracle Services Design Notes (Phase 4+)

Cordelia keepers form a distributed sensor network that can feed on-chain oracles:

**Pattern:** Keepers attest each other's quality → attestations published to `cordelia:attestations` channel → oracle node aggregates → publishes summary on-chain (Cordelia metadata label) → delegators make informed decisions → good keepers earn more delegation → quality pressure.

**On-chain quality metrics (future):** uptime attestations, storage utilisation, channel count, latency measurements. Verifiable, auditable, no central authority.

**Cardano oracle infrastructure:** Charli3, Orcfax available for integration. Or lightweight custom oracle: any keeper reads attestation channel, aggregates, publishes epoch-aligned summary transaction.

**Design constraint for now:** Keeper manifests in `cordelia:directory` should include oracle-ready fields from day one (uptime_since, storage_used, storage_total, channels_hosted, peers_connected). Schema extensible for future oracle consumption.

---

## 17. Phase Alignment (Resolved 2026-03-09)

Previous Track 1-3 structure superseded.

| Phase | Theme | Trigger | Key Deliverables |
|-------|-------|---------|-----------------|
| 1 | Encrypted Pub/Sub MVP | Now | SDK, pub/sub API, local enrollment, install script, docs, website, whitepaper v2 |
| 2 | Developer Experience + Personal Memory | MVP shipped | Anthropic Memory Tool adapter, OpenAI Sessions, Python SDK, MCP adapter thinning, vector search, TUI dashboard |
| 3 | Network Growth + SPO | 100+ SDK installs | SPO keeper deployment, delegation economics, Cardano trust anchor, bootnode decentralisation, Prometheus/Grafana |
| 4 | Governance + Trust | Network at 10+ keepers | Trust scoring (core#41), group spectrum, moderate culture, Shamir recovery, admission thresholds |
| 5 | Enterprise + Economics | Enterprise demand or asymmetric keeper costs | Enterprise portal (optional), token deployment decision, Mem0/Letta adapters, bilateral settlement |

Each phase has a clear theme and trigger. Nothing starts until its trigger condition is met.

---

## 18. Outcome (To Be Updated)

*Fill in at review date (2026-04-09) with actual results vs. expectations.*

---

*Decision proposed by Russell Wing (CPO), 2026-03-09*
*Status: approved in principle (Martin confirmed 2026-03-10)*
