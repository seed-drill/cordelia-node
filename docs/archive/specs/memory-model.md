# Memory Model Specification

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-12
**Scope**: Phase 1 (Encrypted Pub/Sub MVP) with forward references to Phase 2-4
**Depends on**: specs/channels-api.md, specs/sdk-api-reference.md, specs/ecies-envelope-encryption.md, specs/network-protocol.md
**Informs**: SDK API design, search capabilities, prefetch strategy, integration adapters
**Foundational documents**: cordelia-core/docs/design/memory-architecture.md, special-circumstances/memory-substrate-thesis.md

---

## 1. Problem Statement

### 1.1 The Groundhog Day Problem

LLMs are stateless. Every session starts fresh. Without persistent memory:
- Context accumulated in one session is lost in the next
- Preferences must be re-explained, patterns re-learned, relationships re-established
- Delegation to sub-agents produces work without continuity
- No learning compounds across sessions

This is not a feature gap -- it is the absence of the substrate on which useful long-term AI collaboration exists.

### 1.2 The Memory Dilution Problem

Naive persistence (store everything) creates a second problem. Over time, operational memories (session logs, build outcomes, bug fixes) accumulate and dominate retrieval. The foundational memories that originally made the agent effective -- reasoning frameworks, domain expertise, working patterns -- are diluted by volume.

The system must distinguish between memories that shape *how an agent thinks* (high frame value, slow-changing) and memories that record *what happened* (high recency value, fast-changing). Undifferentiated storage degrades the very quality that makes persistent memory valuable.

### 1.3 What No One Offers

As of March 2026, the AI memory landscape has converged on "memory as a service" with REST APIs, vector search, and optional knowledge graphs. Major providers (Mem0, Letta, Cognee, Zep, LangMem) offer increasingly sophisticated extraction and retrieval.

None offer:
- **End-to-end encryption** at the memory layer. Every provider stores memories in plaintext.
- **Multi-agent shared memory with access control.** Agents today share memory via application-level hacks or not at all.
- **Cross-device replication.** All systems are single-instance.
- **Data sovereignty.** Memory lives on provider infrastructure. No portability, no self-hosting, no federation.
- **A standard interface.** Every provider defines a proprietary API. MCP provides transport but no memory semantics.

Cordelia's position: encrypted, replicated, sovereign memory infrastructure with a standard interface (MCP + REST + SDK). The pub/sub architecture delivers shared agent memory that is private by default and sharable by choice.

---

## 2. Design Principles

### 2.1 Core Principles

1. **Memory is the substrate of identity.** Without memory, there is no continuity. Without continuity, there is no learning. Without learning, there is no growth. Memory is not a feature -- it is the foundation.

2. **Structural sovereignty.** The network transports opaque encrypted content and makes no assumptions about its structure. Schema interpretation is exclusively an edge concern. An entity has exclusive control over the internal representation of its memories. (Corollary to the entity sovereignty axiom.)

3. **Encryption is universal.** Every memory is encrypted at rest and in transit. Personal memories use a personal channel PSK. Shared memories use a group channel PSK. There is no plaintext memory path.

4. **The network is a dumb pipe.** Memory domains, TTLs, novelty scores, and classification metadata are edge concerns. They exist in the local index. They never appear on the wire. The P2P layer moves opaque ciphertext by channel ID.

5. **Curation over accumulation.** A 50KB context with the right memories outperforms megabytes of raw history. Memory value is measured by KL divergence reduction between the agent's default reasoning distribution and the optimal distribution for the current task. Store less, store better.

6. **Pull over push for recall.** Agents request memories when needed. The system does not flood context with everything it knows. Domain-aware prefetch seeds the initial context; search and recall extend it on demand.

### 2.2 What Memory Is Not

- Memory is not a database. It does not replace structured application storage.
- Memory is not a log. It does not record every event. It records what matters.
- Memory is not a cache. Memories have semantics (domain, lifecycle, provenance), not just TTLs.
- Memory is not conversation history. Conversation history is an input; memory is the distilled output.

---

## 3. Memory Domains

All memories, regardless of where they are stored (L1/L2/L3) or how they are shared (personal/group), belong to one of three semantic domains. The domain determines how a memory is managed, how long it lives, and how it is prioritised in recall.

### 3.1 Values

**What they are:** The slowest-changing memories. Reasoning frameworks, cultural references, aesthetic preferences, ethical commitments, conceptual vocabulary. They define *who an entity is* and *how it thinks*.

**Why they matter:** When an agent loads frame memories at session start -- game theory, information theory, domain-specific mental models -- it does not merely learn facts. It activates conceptual frameworks that shift attention and reshape reasoning. The coordinate system is pre-loaded.

**Change rate:** Very slow. Months to years. Changes are significant events.

**Lifecycle:** No TTL. Permanent until explicitly revised. Value-domain memories are never automatically expired.

**Examples:**
- Key references: Shannon's information theory, Denning's working set model, Banks' Culture ethics
- Reasoning style: first-principles, iterative, systems thinking
- Principles: entity sovereignty, privacy by default, cooperation as Nash equilibrium
- Entity profiles: who people are, their roles, their expertise

### 3.2 Procedural

**What they are:** Patterns extracted from experience. "Learning on the job." Skills, learned shortcuts, validated approaches, things that worked, things that didn't.

**Change rate:** Medium. Acquired through work, refined through repetition, eventually compressed or superseded.

**Lifecycle:** TTL based on novelty and access frequency. High-novelty procedural memories get longer TTL. Access refreshes TTL. Memories never accessed expire naturally -- Darwinian selection through use.

**Lifecycle stages:**
1. **Acquisition:** Learned during a session. Persisted with initial TTL based on novelty score.
2. **Reinforcement:** Accessed or validated in subsequent sessions. TTL extends. Confidence increases.
3. **Compression:** After repeated validation, the essential insight is promoted to L1 (compressed form) while L2 retains the detailed record.
4. **Supersession:** New learning replaces old. Old version moves to L3 or is dropped.

**Examples:**
- "QUIC requires UDP -- check firewall rules when peers can't connect"
- "FTS5 queries need sanitisation -- max length, prefix minimum, timeout"
- "Chain hash must be recomputed on every L1 patch, not just replace"

### 3.3 Interrupt

**What they are:** Current working state. What is happening right now, what was just happening, what needs attention next. Stack-based semantics: context is pushed when a task begins, popped when it completes.

**Change rate:** Fast. Per-session or per-task.

**Lifecycle:** Short TTL. Most session details are relevant for a few sessions only. The valuable content gets extracted into procedural learnings; the session record itself expires.

**Lifecycle stages:**
1. **Push:** New task begins. Added to active focus and open threads.
2. **Active:** Work proceeds. Session record accumulates context.
3. **Pop:** Task completes or is suspended. Removed from active state. Session summary persisted.
4. **Extract or drop:** Durable insights extracted as procedural or value memories. Session record expires.

**Examples:**
- "Currently running security pass against operations.md and network-protocol.md"
- "Martin's spec review pending -- 6 specs + 4 review docs"
- "Sovereign AI fund follow-up -- 16 April"

### 3.4 Domain Classification

Memories are classified at write time. The classification can be explicit (developer specifies domain) or inferred from content analysis. The novelty signal types map to domains:

| Signal | Domain |
|--------|--------|
| `correction` | Procedural |
| `preference` | Values |
| `entity_new` | Values |
| `decision` | Interrupt (current) -> Procedural (if pattern emerges) |
| `insight` | Values (fundamental) or Procedural (tactical) |
| `blocker` | Interrupt |
| `reference` | Values |
| `working_pattern` | Procedural |
| `meta_learning` | Values or Procedural |

Domain is local metadata. It is never transmitted on the wire. Different nodes may classify the same memory differently -- that is acceptable. Domain is an edge-side optimisation for retrieval, not a protocol concern.

**Classification rules:** Phase 1: domain classification is explicit (caller specifies domain). If omitted, default is `procedural`. The domain field MUST be present in stored items (default applied at write time if omitted). Phase 2 adds automatic inference via novelty signal analysis (§8.2).

---

## 4. Layer Model

### 4.1 Four Layers

```
Layer    Size         Latency      Purpose
───────  ───────────  ───────────  ──────────────────────────────────────
L0       Context      Instant      Session buffer. Current conversation.
         window                    Ephemeral. Lost on session end.

L1       ~50 KB       Session      Hot context. Loaded at session start.
                      start        Identity, active state, preferences,
                                   compressed procedural notes.

L2       ~5 MB        On-demand    Warm index. Searchable. Pulled by
                      (ms)         query or prefetch. Entities, sessions,
                                   learnings, detailed procedural records.

L3       Unbounded    Seconds      Cold archive. Compressed session
                                   history, superseded learnings, value
                                   evolution records. Rarely accessed.
                                   (Phase 3. Described for completeness.)
```

**Size limits:** L1 hard limit: 64 KB. Writes exceeding this are rejected with error `l1_size_exceeded`. L2 soft limit: 5 MB per channel (configurable via `config.toml [memory] l2_quota_mb`, default 5). At 90% quota, a warning is logged. At 100%, oldest interrupt-domain items are tombstoned to reclaim space.

### 4.2 Mapping to Pub/Sub Primitives

| Layer | Channel Primitive | Storage |
|-------|-------------------|---------|
| L0 | Not persisted (conversation context) | None |
| L1 | Personal channel, latest item (structured JSON) | Node SQLite + replication |
| L2 | Personal channel items (typed: entity, session, learning) | Node SQLite + FTS5 + sqlite-vec |
| L3 | Personal channel items (archived, compressed) | Node SQLite, no FTS5 index |

**Key insight:** The personal channel (`__personal`, auto-created at `cordelia init`, see operations.md §2.3) is the backing store for all three persistent layers. L1 is a single well-known item (item_id: `l1_hot_context`, fixed string, not a UUID) in the personal channel. System items (written by the node itself) may use non-`ci_` prefixed item_ids. The `l1_hot_context` item_id is a fixed string convention, not a ULID. All devices sharing an identity use the same item_id, enabling cross-device L1 sync. L2 items are individual memories with type/domain metadata. L3 items are archived L2 items with compressed content. The `__personal` channel uses the system prefix convention defined in channel-naming.md §3.

Shared memory works the same way -- L2 items published to a named channel are visible to all subscribers. The domain model applies identically to shared memories.

### 4.3 Domain Distribution Across Layers

```
         L1 Hot        L2 Warm           L3 Cold
         (always)      (searchable)      (archive)
         ─────────     ──────────────    ──────────────
Values   key_refs      principles,       value evolution
         style         extended refs,    history
         heroes        narrative history
                       [no TTL]          [no TTL]

Proced.  notes         patterns,         superseded
         (compressed)  insights,         learnings
                       how-tos
                       [TTL: medium]     [TTL: long]

Interr.  focus         session records,  compressed
         blockers      recent state      session history
         open_threads
                       [TTL: short]      [TTL: medium]
```

### 4.4 L1 Hot Context Schema

L1 is a structured JSON document loaded at session start. It is the single most important memory artefact -- it defines who the entity is and what it is doing.

```json
{
  "version": 1,
  "updated_at": "2026-03-12T11:42:38.052Z",
  "identity": {
    "id": "russell",
    "name": "Russell Wing",
    "roles": ["CPO", "product", "engineering"],
    "orgs": [{ "id": "seed-drill", "name": "Seed Drill", "role": "CPO" }],
    "key_refs": ["author:iain_m_banks"],
    "style": ["direct", "technical", "concise"],
    "tz": "Europe/London"
  },
  "active": {
    "project": "cordelia",
    "focus": "Writing memory model specification",
    "blockers": [],
    "next": ["Martin spec review", "SDK implementation"],
    "notes": ["Domain-aware prefetch not yet implemented"]
  },
  "prefs": {
    "verbosity": "concise",
    "emoji": false,
    "auto_commit": false
  },
  "delegation": {
    "allowed": true,
    "max_parallel": 3,
    "require_approval": ["git push", "deploy", "send messages"],
    "autonomous": ["read files", "search code", "run tests"]
  },
  "ephemeral": {
    "session_count": 58,
    "current_session_start": "2026-03-12T11:42:38.052Z",
    "last_session_end": "2026-03-11T19:50:34.306Z",
    "last_summary": "Session 57: ...",
    "open_threads": ["Martin spec review", "Sovereign AI fund"],
    "integrity": {
      "chain_hash": "c86e38d9...",
      "previous_hash": "98c83090...",
      "genesis": "2026-03-04T11:00:00Z"
    }
  }
}
```

The `identity` section is predominantly values-domain. The `active` and `ephemeral` sections are interrupt-domain. The `prefs` section contains both values (stable preferences) and procedural (learned preferences) content.

**L1 is authoritative for session bootstrap.** When an agent wakes, it reads L1. L1 provides enough context to understand who it is, what it was doing, and what to do next. L2 provides depth on demand.

**Schema versioning:** `version` increments on structural schema changes (field additions/removals). Readers MUST accept unknown fields (forward-compatible). Version 1 is the initial schema. On read, the node applies transforms when `version < current`.

### 4.5 L1 Integrity Chain

Each session extends a hash chain:

```
chain_hash = SHA-256("cordelia:l1-chain:" || previous_hash(32 bytes) || session_count(8 bytes, big-endian u64) || content_hash(32 bytes))
```

Where `content_hash` is SHA-256 of JSON-serialised L1 with the `ephemeral.integrity` object removed (all other fields including `ephemeral.session_count`, `open_threads`, etc. are included). Serialisation uses deterministic JSON (keys sorted lexicographically, no whitespace). The domain prefix `"cordelia:l1-chain:"` provides domain separation per Cordelia convention.

**Genesis:** For the first session (`session_count = 0`): `previous_hash = SHA-256("cordelia:genesis:" || entity_id)`. This anchors the chain to the entity's identity.

This provides cryptographic proof that memory has not been tampered with between sessions. Chain verification at session start is mandatory. Recovery priority on verification failure: (1) restore from most recent local backup, (2) request L1 from paired device via `__personal` channel listen, (3) reinitialise L1 from identity key (empty active/ephemeral sections). Failure at all three levels logs a CRITICAL error and starts with a fresh L1, preserving identity.

---

## 5. Personal Memory

### 5.1 The Personal Channel

Every entity has a personal channel, created automatically at `cordelia init`:
- Channel name: `__personal` (system channel, hidden from `cordelia channels` by default)
- Mode: `realtime` (eager push replication)
- Access: `invite_only` (only the entity and its paired devices)
- PSK: generated at init, shared to paired devices via pairing protocol

The personal channel contains:
- **L1 hot context** (one item, well-known item_id, updated in place)
- **L2 memories** (individual items with type and domain metadata)
- **Session records** (interrupt-domain, short TTL)

### 5.2 Memory Item Structure

Each L2 memory is published to a channel as a standard Cordelia item. The content (encrypted) contains:

```json
{
  "memory_version": 1,
  "domain": "procedural",
  "type": "learning",
  "name": "FTS5 query sanitisation required",
  "summary": "FTS5 queries need max length, prefix minimum, and timeout constraints",
  "content": "Discovered during channels-api review...",
  "context": "Cordelia Phase 1 spec review",
  "tags": ["fts5", "search", "security"],
  "confidence": 0.85,
  "source_session": 54,
  "novelty_score": 0.72,
  "ttl_days": 90
}
```

**Field requirements:**

| Field | Required | Default | Notes |
|-------|----------|---------|-------|
| `memory_version` | Yes | -- | Always `1` for Phase 1 |
| `domain` | Yes | `procedural` | Applied at write time if omitted by caller |
| `type` | Yes | -- | One of: `entity`, `session`, `learning` |
| `name` | Yes | -- | Human-readable identifier |
| `content` | Yes | -- | The memory content |
| `summary` | No | -- | Short summary for list views |
| `context` | No | -- | What was happening when this was learned |
| `tags` | No | `[]` | Searchable tags |
| `confidence` | No | `0.5` | Float [0.0, 1.0]. Certainty that this memory is accurate. Set by the writing agent. Phase 2: retrieval boost multiplier. Phase 1: stored only. |
| `source_session` | No | -- | Integer, local to originating device. Not globally unique. Cross-device dedup uses item_id. |
| `novelty_score` | No | -- | Float [0.0, 1.0]. Set by novelty analyser (§8). |
| `ttl_days` | No | Per domain (§8.3) | Override domain default if specified |

**These fields are inside the encrypted blob.** The wire protocol sees only the standard envelope (item_id, channel_id, author_id, item_type, published_at, content_hash, encrypted_blob). Schema sovereignty is preserved -- the memory structure is an edge concern. The wire envelope's `content_hash` (per ECIES spec §11.7) is SHA-256 of the encrypted blob (ciphertext), not of the plaintext content. content_hash is verified by the node transparently and is not exposed via the REST API or SDK.

The `item_type` field on the wire envelope carries the memory type with a `memory:` prefix: `memory:entity`, `memory:session`, `memory:learning`. This avoids collision with application-defined item types. The prefix is the only schema hint visible to the network, used for tombstone detection and basic content-type filtering. It does NOT carry domain information.

**Privacy note:** Memory-prefixed `item_type` values reveal that the channel is used for memory operations. Phase 1 accepts this trade-off (equivalent to any application-defined type). Phase 3 evaluates type normalisation (single `memory` type, subtype inside encrypted blob).

The SDK's `publish()` treats content as opaque. The memory item structure above is a content convention, not enforced by the Phase 1 SDK. Phase 2's `c.remember()` adds schema validation.

### 5.3 Memory Types

| Type | Wire `item_type` | Description | Typical Domain |
|------|-------------------|-------------|---------------|
| `entity` | `memory:entity` | Information about a person, organisation, concept, or system | Values |
| `learning` | `memory:learning` | A pattern, insight, principle, or skill extracted from experience | Procedural or Values |
| `session` | `memory:session` | A record of a completed work session | Interrupt |

Types are coarse and use the `memory:` prefix on the wire to avoid collision with application-defined item types. Domain is the finer-grained classification that drives lifecycle and retrieval.

---

## 6. Shared Memory

### 6.1 Channels as Shared Memory Spaces

Named channels are shared memory spaces. When multiple agents subscribe to a channel, they share a common memory pool. Each agent can publish memories and recall them via search.

```typescript
const c = new Cordelia()

// Personal memory (private)
await c.publish('__personal', { domain: 'procedural', type: 'learning', ... })

// Shared memory (visible to all subscribers)
await c.subscribe('research-findings')
await c.publish('research-findings', { type: 'insight', text: '...' })
```

### 6.2 Personal vs Shared: Key Differences

| Property | Personal Memory | Shared Memory |
|----------|----------------|---------------|
| Channel | `__personal` | Any named channel |
| Access | Owner only (+ paired devices) | All subscribers |
| Encryption | Personal PSK | Channel PSK (shared with subscribers) |
| Domain classification | Local (per-entity) | Local (each subscriber classifies independently) |
| Lifecycle policy | Domain-driven (values permanent, interrupt short TTL) | Channel policy-driven. Phase 1: no automatic TTL, items persist until explicitly deleted. Phase 4: per-channel retention policies. |
| Replication | Via paired devices | Via P2P replication to all subscribers |
| Write access | Owner only | Any subscriber (Phase 1). Owner/admin-gated (Phase 4). |

### 6.3 Knowledge Flow Between Personal and Shared

Memories can flow between personal and shared channels:

- **Share:** An entity publishes a personal learning to a group channel. The learning becomes available to all subscribers. Example: an individual insight becomes team knowledge.
- **Harvest:** An entity reads a shared memory and publishes a copy to their personal channel. The memory becomes part of their personal knowledge. Example: a team pattern becomes individual skill.

In Phase 1, sharing and harvesting are manual: share = publish the same content to a different channel; harvest = listen on a shared channel, then publish a copy to `__personal`. No dedicated API endpoint. Phase 4 adds automated suggestions (the system detects when a personal learning might benefit the group, or when a group pattern should be absorbed personally).

### 6.4 Shared Memory Use Cases

| Use Case | Channel Pattern | Example |
|----------|----------------|---------|
| Team knowledge base | Named channel, realtime | `engineering-patterns` -- team shares and evolves common practices |
| Research collaboration | Named channel, realtime | `market-research` -- multiple agents contribute findings |
| Handoff context | Named channel, realtime | `customer-onboarding` -- one agent's context becomes another's starting point |
| Audit trail | Named channel, batch | `decisions-log` -- immutable record of decisions and rationale |
| Agent swarm coordination | Named channel, realtime | `swarm-alpha` -- agents share intermediate results and coordinate |

---

## 7. Search and Recall

### 7.1 Search Architecture

Search is local. The node maintains FTS5 (keyword) and sqlite-vec (semantic) indexes over decrypted item content. Search happens on decrypted plaintext at the edge -- the network never searches encrypted content.

```
Query → FTS5 BM25 (keyword) ─────────────────────┐
                                                    ├─ Dominant-signal hybrid → Ranked results
Query → sqlite-vec cosine (semantic) ─────────────┘
```

**Hybrid scoring formula:**

```
score = 0.7 * max(semantic, keyword) + 0.3 * min(semantic, keyword)
```

The stronger signal for each result leads at 70%, the weaker boosts at 30%. This adapts per-result: keyword-precise queries (names, error codes, identifiers) are led by FTS5; conceptual queries (how does X work) are led by semantic similarity. Coefficients are configurable via `config.toml [search] dominant_weight` (default `0.7`, range `0.5-0.9`). See `cordelia-proxy/SEARCH.md` for tuning rationale.

If one index returns no results for a candidate item, that signal is 0 (e.g., a purely semantic match scores `0.7 * semantic`). If both signals are 0, the item is not returned. Empty queries are rejected (400 Bad Request).

### 7.2 Domain-Aware Retrieval (Phase 2)

Domain provides a retrieval boost signal:
- Architectural discussion → weight values-domain items higher (frameworks, principles)
- Debugging → weight procedural items higher (learned patterns)
- Status check → weight interrupt items higher (current state, recent sessions)

This is boosting, not filtering. A procedural memory may be relevant to an architectural discussion. But domain-aware boosting encodes the intuition that different types of memory matter in different contexts.

### 7.3 Prefetch Strategy

At session start, the system loads L1 and prefetches a bounded set of L2 items:

1. **Always load:** L1 hot context (mandatory, ~50 KB)
2. **Always load:** All value-domain items from L2 (few, high-value, no TTL)
3. **Relevance load:** Procedural items matching current project/context
4. **Recency load:** Most recent interrupt items (capped)

Total prefetch budget: sum of UTF-8 byte lengths of decrypted `content` fields of fetched L2 items. Default 51200 bytes (50 KB), configurable via `config.toml [memory] prefetch_budget_bytes`. Value-domain prefetch is capped at 20 items (most recently updated). If total value-domain content exceeds the budget, items are ranked by `updated_at` descending and truncated at budget. This ensures frame memories are always present regardless of how many operational memories have accumulated.

### 7.4 SDK Search Interface

```typescript
// Full-text + semantic hybrid search
const results = await c.search('research-findings', 'vector search accuracy', {
  limit: 10,
  types: ['memory:learning', 'memory:entity'],
  since: '2026-03-01T00:00:00Z'
})

// Cross-channel search (personal memory)
const personal = await c.search('__personal', 'pairing protocol security')

// Phase 2: domain-filtered search
const principles = await c.search('__personal', 'design principles', {
  domain: 'values'
})
```

### 7.5 Embedding Model

Phase 1 uses `nomic-embed-text-v1.5` (768 dimensions) via Ollama for local embedding generation.

**Embedding pipeline:**
- Model: `nomic-embed-text-v1.5` (768-dimensional float32 vectors)
- Storage: sqlite-vec `FLOAT[768]` column in local SQLite
- Generation trigger: async, on item write (non-blocking -- item is available for FTS5 immediately)
- Cache key: SHA-256 of embeddable text (concatenation of `name`, `summary`, `content` fields)
- Backfill: `memory_backfill_embeddings` MCP tool rebuilds missing/stale embeddings
- Local only -- never transmitted on the wire

Phase 2 evaluates domain-specialised embeddings (different models for values vs procedural vs interrupt) and cloud embedding APIs for environments without local GPU.

---

## 8. Novelty and Lifecycle

### 8.1 The Novelty Principle

Not everything is worth remembering. Memory quality is inversely proportional to volume. The system uses a novelty filter: only memories with sufficient information density are persisted.

**Formal statement:** Novelty = conditional entropy H(M|C), where M is the candidate memory and C is the existing corpus. High H(M|C) means the memory cannot be reconstituted from existing memories. Low H(M|C) means it is largely redundant.

**Novelty threshold:** 0.3 (configurable via `config.toml [memory] novelty_threshold`, range `0.0-1.0`). Candidates with `novelty_score < threshold` are not persisted by Phase 2 automatic writes. Phase 1 explicit writes are always persisted regardless of novelty score -- the threshold applies only to automated memory extraction.

**Automated processing note:** Phase 2 automatic novelty filtering constitutes automated processing under GDPR Art. 22. Deployments processing personal data about individuals should ensure human oversight of automatic expiry decisions, or establish that the legitimate interest basis includes automated lifecycle management. Phase 1 explicit writes are not affected.

### 8.2 Novelty Signals

The novelty analyser classifies candidate memories by signal type:

| Signal | Description | Typical Novelty |
|--------|-------------|----------------|
| `correction` | User corrected the agent's approach | High |
| `preference` | User expressed a preference or style guidance | Medium-High |
| `entity_new` | New entity (person, org, concept) encountered | Medium |
| `decision` | A decision was made with rationale | Medium |
| `insight` | A novel observation or connection | Variable |
| `blocker` | A problem that blocked progress | Medium (decays fast) |
| `reference` | A key reference or framework identified | High |
| `working_pattern` | A pattern that proved effective | Medium-High |
| `meta_learning` | Learning about how the collaboration works | High |

### 8.3 TTL Assignment

TTL is determined by domain + novelty:

| Domain | Novelty | TTL |
|--------|---------|-----|
| Values | Any | Permanent (no TTL) |
| Procedural | High | 180 days |
| Procedural | Medium | 90 days |
| Procedural | Low | 30 days |
| Interrupt | Any | 7 days (extended by access) |

Access refreshes TTL (Phase 2; Phase 1 uses static TTL only). Access = item returned in a search result, listen result, or prefetch. TTL resets to the domain default (table above) on access. Memories that are never accessed expire naturally.

### 8.4 Consolidation (Phase 2)

Over time, procedural memories that have been reinforced across multiple sessions should be consolidated:
1. Extract the essential insight
2. Promote compressed form to L1 notes
3. Archive detailed records to L3
4. Mark original L2 items as superseded

This is analogous to memory consolidation in biological systems -- episodic memories become semantic knowledge. Phase 1 supports manual consolidation (entity explicitly promotes a learning). Phase 2 adds automatic detection of consolidation candidates based on access frequency and reinforcement patterns.

### 8.5 Expiry Sweep

A periodic sweep checks for expired items. Default trigger: on session start. Configurable via `config.toml [memory] sweep_interval_hours` (default `24`, range `1-168`). Sweep is idempotent and safe to run concurrently.

**Sweep rules:**
- Value-domain items are exempt from expiry (never swept)
- Shared channel items follow channel lifecycle policy, not domain-driven TTL
- Phase 1 (no L3): expired items are tombstoned
- Phase 3+: value-domain items are archived to L3 (never deleted); procedural items are archived if accessed in the last 90 days, otherwise tombstoned; interrupt items are tombstoned

**Tombstone replication:** Expiry tombstones replicate via the personal channel to paired devices. This is intentional -- paired devices must know items were expired to maintain index consistency. Tombstones carry no content, only `item_id` and `is_tombstone=true`.

---

## 9. SDK Memory Interface

The SDK provides memory operations built on top of the pub/sub primitives. These are convenience methods -- developers can always use the lower-level publish/subscribe/listen API directly.

### 9.1 Memory-Aware Methods (Phase 2 SDK additions -- NOT in Phase 1 sdk-api-reference.md)

```typescript
// Store a memory with domain classification
await c.remember({
  channel: 'research-findings',    // or '__personal' for private
  domain: 'procedural',
  type: 'learning',
  name: 'Vector search needs hybrid scoring',
  content: 'Pure vector search misses keyword-precise queries...',
  tags: ['search', 'retrieval']
})
// Maps to: POST /channels/publish with memory-structured content

// Recall memories by query
const memories = await c.recall('vector search accuracy', {
  channel: '__personal',
  domain: 'procedural',
  limit: 5
})
// Maps to: POST /channels/search with domain filter

// Forget a specific memory
await c.forget(memory.itemId)
// Maps to: POST /channels/delete-item

// Get current session context (L1)
const context = await c.context()
// Maps to: POST /channels/listen on __personal, filter item_id = 'l1_hot_context'

// Update session context
await c.updateContext({ active: { focus: 'New task' } })
// Maps to: POST /channels/publish on __personal (L1 item update)
```

### 9.2 Phase 1 Approach

Phase 1 does not include `remember`/`recall`/`forget` as SDK methods. Developers use the publish/subscribe/listen/search primitives directly. The memory-aware methods are Phase 2 additions that add:
- Automatic domain classification
- Novelty filtering before write
- Domain-aware search boosting
- TTL assignment based on domain + novelty

Phase 1 developers can achieve the same outcomes manually:
```typescript
// Phase 1 equivalent of c.remember(...)
await c.publish('__personal', {
  domain: 'procedural',
  type: 'learning',
  name: 'Vector search needs hybrid scoring',
  content: '...'
})

// Phase 1 equivalent of c.recall(...)
const results = await c.search('__personal', 'vector search')
```

---

## 10. Integration Targets

### 10.1 Anthropic Memory Tool Adapter (Phase 2)

The Anthropic Memory Tool (`memory_20250818`) is a client-side file CRUD primitive. Claude makes tool calls with commands (`view`, `create`, `str_replace`, `insert`, `delete`, `rename`) against a `/memories` directory. The developer implements the storage backend.

**Cordelia adapter mapping:**

| Memory Tool Command | Cordelia Operation |
|---------------------|-------------------|
| `view` (list directory) | `c.listen('__personal', { limit: 100 })` -- list personal memories |
| `view` (read file) | `c.listen('__personal', { filter: { name: filename } })` |
| `create` (new file) | `c.publish('__personal', { name: filename, content: ... })` |
| `str_replace` (edit file) | Read item, modify content, publish updated item |
| `delete` (remove file) | `c.forget(itemId)` |
| `rename` (rename file) | Create new item with new name, delete old |

The adapter presents Cordelia's encrypted, replicated memory as a standard Memory Tool backend. Claude uses the familiar file abstraction; Cordelia provides encryption, replication, and search underneath.

**What Cordelia adds over a filesystem backend:**
- E2E encryption (Memory Tool + filesystem = plaintext files)
- Cross-device sync via replication
- Full-text and semantic search over memories
- Domain classification and lifecycle management
- Shared memory via channels (Memory Tool is single-user only)

### 10.2 OpenAI Sessions Adapter (Phase 2)

OpenAI's Responses API supports `previous_response_id` chaining and persistent conversations. A Cordelia adapter would provide a custom backend that stores conversation state in encrypted channels.

### 10.3 MCP Memory Server (Phase 1)

The existing Cordelia MCP server provides memory tools directly: `memory_read_hot`, `memory_write_hot`, `memory_search`, `memory_write_warm`, `memory_read_warm`, `memory_analyze_novelty`, etc. This is the primary integration path for Phase 1.

**MCP tool to memory-model mapping:**

| MCP Tool | Memory Operation | Channel | Details |
|----------|-----------------|---------|---------|
| `memory_read_hot` | Read L1 | `__personal` | Listen for `item_id = 'l1_hot_context'` |
| `memory_write_hot` | Update L1 | `__personal` | Publish with `item_id = 'l1_hot_context'` (update in place) |
| `memory_write_warm` | Create L2 memory | `__personal` | Publish with memory item structure (§5.2), type = `memory:*` |
| `memory_read_warm` | Read L2 memory | `__personal` | Listen with item_id filter |
| `memory_search` | Search L2 | `__personal` | FTS5 + sqlite-vec hybrid search (§7.1) |
| `memory_analyze_novelty` | Novelty check | -- | Compute novelty_score against existing corpus (§8.1-8.2) |
| `memory_delete_warm` | Tombstone L2 | `__personal` | Delete item (tombstone, replicates to paired devices) |
| `memory_prefetch_l2` | Prefetch L2 | `__personal` | Domain-aware prefetch per §7.3 strategy |

---

## 11. Privacy and Encryption

### 11.1 Encryption Model

Every memory is encrypted. There is no plaintext storage path.

| Memory Type | Encryption Key | Key Source |
|-------------|---------------|-----------|
| Personal (L1/L2/L3) | Personal channel PSK (AES-256-GCM) | Per ecies-envelope-encryption.md §4-5 |
| Shared (any channel) | Channel PSK (AES-256-GCM) | Per ecies-envelope-encryption.md §4-5 |

The node encrypts at write time and decrypts at read time. The SDK never sees ciphertext. The P2P layer never sees plaintext. Key storage paths and envelope format follow ecies-envelope-encryption.md §4-5 (canonical reference for all key management).

### 11.2 Search Privacy

Search indexes (FTS5, sqlite-vec) contain decrypted content. They exist only in the local node's SQLite database. Indexes are:
- Never transmitted on the wire
- Never included in replication
- Rebuilt locally from decrypted content on each node
- Protected by the node's filesystem permissions (database mode 0600)

A compromised relay or peer sees only encrypted items. A compromised local node exposes the FTS5/vec index -- this is the same threat boundary as key compromise (the node holds PSKs).

**Cross-channel isolation:** Search indexes span all subscribed channels in one SQLite database. The search endpoint MUST enforce `channel_id` as a mandatory WHERE clause -- queries without a channel parameter are rejected (400 Bad Request). FTS5 MATCH queries MUST be parameterised to prevent SQL injection per channels-api.md §3.13 constraints. No cross-channel search in Phase 1.

### 11.3 Privacy Boundaries

| Boundary | What Is Visible |
|----------|----------------|
| Relay/peer (untrusted) | Channel ID, author ID, item_type, published_at, content_hash, encrypted blob. No memory content, no domain, no tags. |
| Local node (trusted) | Everything. Decrypted content, FTS5 index, embeddings, domain, TTL, all metadata. |
| SDK/application (trusted) | Plaintext content via REST API. Bearer token required. Localhost only. |
| Paired device (trusted, same identity) | Everything (shares PSK and identity key). |
| Channel subscriber (trusted, shared PSK) | Shared channel content only. Not personal channel content. |

**Data residency:** In Phase 1, encrypted data replicates to any peer or relay without jurisdiction constraints. Because relays hold only ciphertext and never PSKs, cross-border relay storage arguably does not constitute a 'transfer of personal data' under GDPR recital 26 (data rendered unintelligible to the processor). Phase 3 keeper nodes could offer jurisdiction-pinned storage as a commercial feature.

### 11.4 GDPR Considerations

In multi-agent deployments where a shared channel contains memories about individuals:
- The channel owner (PSK holder who created the channel) is the data controller
- Right to erasure: `DELETE /channels/delete-item` + tombstone replication. **Erasure in distributed systems:** P2P tombstone-based erasure is best-effort. Tombstones replicate to all online nodes within the sync interval; offline nodes receive tombstones on reconnect within the 7-day retention window (network-protocol.md §6.3). Encrypted content without the PSK is unintelligible -- PSK rotation after deletion renders remaining ciphertext undecryptable by removed parties. This is analogous to Signal's deletion model, which regulators have accepted. The combination of tombstone propagation and encryption provides a defensible 'reasonable steps' position under GDPR Art. 17(2).
- Right to access: channel search filtered by author_id or entity reference
- Data portability: `cordelia export --channel <name>` produces decrypted JSONL

**Tombstone privacy note:** Tombstones retain `content_hash` for replication consistency (7-day retention per network-protocol.md §6.3). `content_hash` does not reveal content but does confirm content identity across observers who held the same item. Phase 3 evaluates tombstone `content_hash` zeroing after 48 hours (post-convergence window).

### 11.5 UK DPA and GDPR Compliance

The UK Data Protection Act 2018 (UK DPA) is the primary legal framework for Seed Drill's UK operations. GDPR applies for EU data subjects.

**Compliance guidance (not legal advice):**

- **DPIA:** Deployments processing personal data about individuals via AI-driven automated means should conduct a Data Protection Impact Assessment (UK DPA s.64 / GDPR Art. 35).
- **Lawful basis:** Channel owners storing memories about individuals need a lawful basis (GDPR Art. 6 / UK DPA s.8). Likely: legitimate interest for agent memory in professional contexts, consent for shared channels containing PII about third parties.
- **Data subject rights:** The architecture supports: right of access (channel search by author_id/entity reference), right to rectification (publish updated item), right to erasure (§11.4), right to data portability (`cordelia export`), right to object (unsubscribe from channel). Right not to be subject to automated decision-making (Art. 22) -- see §8.1 novelty threshold note.
- **Controller/processor:** Channel ownership provides a pragmatic mapping to controllership. In enterprise deployments, the deploying organisation is the data controller regardless of which entity created the channel. Seed Drill provides infrastructure only and does not access encrypted content, consistent with a platform provider role. Formal controller/processor agreements should be established for deployments processing personal data.

Phase 4 adds fine-grained access control, audit logging, and data retention policies per channel.

---

## 12. Competitive Differentiation

### 12.1 Positioning Matrix

```
                    Features (extraction, graph, managed)
                              ^
                              |
                    Mem0  Cognee  Zep
                              |
                    Letta     |
                              |
  Self-hosted <───────────────+───────────────> Cloud-managed
                              |
                              |
                              |
                    Cordelia   |
                              |
                              v
               Sovereignty (encryption, P2P, portable)
```

### 12.2 Feature Comparison

| Capability | Cordelia | Mem0 | Letta | Cognee | Zep |
|------------|---------|------|-------|--------|-----|
| E2E encryption | Yes (AES-256-GCM, ECIES) | No | No | No | No |
| Multi-agent shared memory | Yes (channels) | No | Shared blocks (no encryption) | No | No |
| Cross-device sync | Yes (P2P replication) | No | No | No | No |
| Self-hosted | Yes (single binary) | Yes (Docker) | Yes | Yes | Partial |
| Data sovereignty | Yes (AGPL, you own everything) | No (cloud) | Yes (OSS) | Yes (OSS) | No |
| Knowledge graph | Phase 2 | Pro tier | No | Yes | Yes |
| Semantic search | Yes (nomic-embed-text) | Yes | No | Yes | Yes |
| Full-text search | Yes (FTS5 BM25) | No | No | No | No |
| Hybrid search | Yes (dominant-signal) | No | No | No | No |
| Standard interface | MCP + REST + SDK | REST + MCP | REST + SDK | REST + SDK | REST + SDK |
| Memory lifecycle | Yes (domain-driven TTL) | No | No | No | Temporal facts |
| Compliance ready | Phase 5 | No | No | No | SOC 2, HIPAA |
| Federation | Yes (P2P) | No | No | No | No |

### 12.3 Developer Experience Comparison

```
# Mem0 (cloud, no encryption)
from mem0 import MemoryClient
m = MemoryClient(api_key="...")
m.add("User prefers dark mode", user_id="alice")
results = m.search("preferences", user_id="alice")

# Cordelia (encrypted, replicated, zero config)
import { Cordelia } from '@seeddrill/cordelia'
const c = new Cordelia()
await c.publish('__personal', { type: 'learning', content: 'User prefers dark mode' })
const results = await c.search('__personal', 'preferences')
```

Both are simple. Cordelia's advantage is not complexity -- it is what happens underneath. Cordelia encrypts, replicates, and gives you sovereignty. Mem0 stores plaintext on their servers.

---

## 13. Phase Boundaries

Phase numbers align with ROADMAP.md. Memory-specific features are scheduled within the phase they depend on. See ROADMAP.md for the canonical phase timeline and work package assignments.

### 13.1 Phase 1 (MVP)

- Personal channel as memory store (L1 + L2)
- Three memory types (entity, session, learning)
- FTS5 + sqlite-vec hybrid search
- MCP memory tools (read/write hot, read/write warm, search, novelty)
- Domain classification (metadata only, no domain-aware retrieval)
- Manual TTL (no automatic lifecycle management)
- Personal memory only via SDK (shared channels are pub/sub, not memory-typed)
- Session hooks (start/end) for L1 bootstrap
- Integrity chain for tamper detection

### 13.2 Phase 2 (Provider Integration)

- `remember`/`recall`/`forget` SDK methods
- Automatic domain classification at write time
- Domain-aware search boosting
- Automatic TTL assignment (domain + novelty)
- Expiry sweep (periodic, on session start)
- Anthropic Memory Tool adapter
- OpenAI Sessions adapter
- Prefetch strategy (values-first, then procedural, then interrupt)
- Consolidation (manual: promote L2 insight to L1 notes)
- Python SDK with same memory interface
- SSE-based listen (replacing polling)

### 13.3 Phase 3 (Network Growth)

- L3 cold archive (compressed, off-hot-path)
- Cross-channel memory search (search across all subscribed channels)
- Knowledge graph overlay (entity relationships)
- Automatic consolidation (detect reinforcement patterns)
- Memory export/import for portability

### 13.4 Phase 4 (Governance + Trust)

- Per-channel access control for writes
- Audit logging for memory operations
- Data retention policies per channel. Regulatory retention requirements (e.g., FCA 5-7 year record retention, healthcare records retention) should be configurable via per-channel retention policies in this phase.
- Shamir recovery for identity key
- Value drift detection (track changes to values-domain memories)
- Agent alignment verification (challenge-response from dense memory)

### 13.5 Phase 5 (Enterprise)

- Compliance certifications (SOC 2, HIPAA). Architectural prerequisites already in place: AES-256-GCM encryption, bearer token auth, filesystem permissions, tombstone-based deletion. Known gaps: audit logging (Phase 4), fine-grained access control (Phase 4), breach notification procedures, BAA templates.
- Organisational memory (multi-team, hierarchical channels)
- Role-based memory access
- Memory analytics and insights dashboard
- Mem0/Letta adapters (compatibility layer)

---

## 14. Glossary

| Term | Definition |
|------|-----------|
| **Domain** | Semantic classification of a memory: values, procedural, or interrupt |
| **Frame memory** | High-value memory that shapes how an agent thinks, not just what it knows |
| **Hot context (L1)** | Structured JSON loaded at session start, ~50 KB |
| **Memory dilution** | Degradation of retrieval quality as operational memories accumulate and overwhelm frame memories |
| **Novelty** | Conditional entropy H(M\|C) -- how much information a candidate memory adds given the existing corpus |
| **Personal channel** | `__personal`, auto-created, invite-only, realtime. Backs L1/L2/L3 for personal memory. |
| **Structural sovereignty** | An entity's exclusive control over the internal representation of its memories |
| **TTL** | Time-to-live. Domain-driven lifecycle policy. Values = permanent, procedural = medium, interrupt = short. |

---

## 15. References

- **cordelia-core/docs/design/memory-architecture.md**: Three-domain model, novelty analysis, schema-free wire protocol (foundational design document)
- **special-circumstances/memory-substrate-thesis.md**: Memory as identity substrate, memory lines as replicators (strategic thesis)
- **special-circumstances/claude-memory-system.md**: Four-layer hierarchy, sprint history, R1 implementation (development history)
- **cordelia-proxy/SEARCH.md**: Hybrid search architecture, dominant-signal formula, embedding pipeline
- **competitors/ai-memory-landscape-2026.md**: Competitive analysis (Mem0, Letta, Cognee, Zep, ODEI, LangMem)
- **specs/channels-api.md**: REST API endpoints that back memory operations
- **specs/sdk-api-reference.md**: TypeScript SDK that exposes memory to developers
- **specs/ecies-envelope-encryption.md**: Encryption model for memory at rest and in transit
- **specs/network-protocol.md**: Replication protocol that syncs memory across devices

---

*Draft: 2026-03-12. Foundational spec -- review before implementation alongside channels-api.md and sdk-api-reference.md.*
