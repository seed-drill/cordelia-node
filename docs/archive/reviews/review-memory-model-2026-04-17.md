# Review: memory-model.md

> Fresh review pass applying review-spec methodology to
> `memory-model.md` (Draft 2026-03-12, 870 lines). Documentation
> due-diligence before closing Phase 1.

## Application Record

| Field | Value |
|-------|-------|
| Date | 2026-04-17 |
| Reviewer | Russell Wing + Claude Opus 4.7 |
| Spec | memory-model.md (Draft 2026-03-12) |
| Passes applied | 1 (Gaps), 2 (Consistency), 3 (Clarity), 4 (Implementability), 5 (Coverage), 6 (Cross-ref integrity) |
| Reference specs | network-protocol.md, data-formats.md, parameter-rationale.md, demand-model.md, search-indexing.md, channel-naming.md, channels-api.md, configuration.md, WHITEPAPER.md, CLAUDE.md |
| Prior reviews cross-checked | review-data-formats-2026-04-17.md (DF-01), review-network-behaviour-2026-04-17.md (NB-01 receive path), review-identity-2026-04-17.md (ID-01 attestation) |

---

## Summary

17 findings. 2 CRITICAL (WHITEPAPER §2.1 L0-L3 framing conflicts with
the spec's L0-L3 definitions; §4.5 integrity chain preimage is
ambiguous in a way that forks cross-device implementations). 5 HIGH
(L1 item_id convention not anchored in data-formats.md; L2 quota
units inconsistent with `l2_quota_mb` semantics; prefetch budget
definition is ill-typed; foundational document pointers dangle;
personal-node receive path asserts push replication contra
network-protocol.md §4.6). 7 MEDIUM (tombstone replication scope,
embedding storage path overlap with search-indexing.md, deterministic
JSON canonical form, PAN/scope column silence, cross-channel search
claim, content_hash overload, automated-processing GDPR wording). 3
LOW (doc polish).

The spec is ambitious and largely coherent on its own terms. The two
material correctness issues are (a) the whitepaper's consumer-facing
L0-L3 story (fast L0 in-process cache, L3 as durable storage) does
not match what memory-model.md §4.1 says (L0 is an ephemeral
conversation buffer, L3 is a Phase 3 cold archive), and (b) the
L1 integrity chain preimage spans "deterministic JSON" without
pinning JCS (RFC 8785) or an equivalent canonical form, so two
correct implementations can disagree on the hash. Both are the same
species of bug the network-behaviour and data-formats reviews
flagged: descriptive specs ("here is what we do") competing with
prescriptive references ("here is what you must do"). Several
secondary findings trace to the spec pre-dating the 2026-03-20
schema v3 migration and the epidemic-forwarding refactor.

---

## CRITICAL

### MM-01: WHITEPAPER L0-L3 framing contradicts memory-model.md §4.1

**Spec**: memory-model.md §4.1 (Four Layers); WHITEPAPER.md §2.1
(Cache Hierarchy, lines 140-165)

**Issue**: The two authoritative documents describe L0 and L3
differently enough that an implementor or an integrator cannot
reconcile them.

| Layer | WHITEPAPER §2.1 | memory-model §4.1 |
|-------|-----------------|-------------------|
| L0 | `<1ms`, ~100 items, **in-memory cache** (MCP adapter process), holds L1 hot context and recent L2 search results | "Context window, Session buffer. Current conversation. **Ephemeral, lost on session end.**" |
| L1 | `<10ms`, ~50KB, "permanent" | ~50 KB, "Session start, hot context, loaded at session start" (**not labelled permanent here**, but implicit through persisted-item mechanism) |
| L2 | `<100ms`, **unbounded** | `~5 MB`, **5 MB per-channel soft quota** (§4.1 size limits) |
| L3 | `<1s`, unbounded, **"durable backends (S3, distributed storage)"**, described in present tense | **"Phase 3. Described for completeness."** Explicitly deferred. Uses SQLite in node, not S3. |

Two concrete consequences:

1. **L0 drift:** The whitepaper tells readers L0 is a process-local
   cache (adapter-side) that can hold search results. The spec says
   L0 is the conversation context window -- a model-side buffer the
   node does not even touch. These are not the same thing. An
   implementor reading the whitepaper will build an in-process cache
   layer that the spec does not describe or support. An integrator
   reading the spec will not find the L0 cache the whitepaper
   promises.

2. **L2/L3 capacity drift:** The whitepaper's "unbounded L2" invites
   uncapped growth; memory-model §4.1 caps L2 at 5 MB per channel
   and tombstones oldest interrupt items above the quota. At 200
   channels * 5 MB = 1 GB upper bound, not "unbounded." The
   whitepaper's S3/distributed-storage L3 is not architected
   anywhere in the Phase 1 specs.

This is the same spec-vs-reality problem DF-01 flagged for schema
v3: one document has moved on, the other hasn't, and readers guess
which is canonical.

**Resolution**:

Pick one story and propagate. Recommended reconciliation:

- **memory-model §4.1** is canonical for Phase 1-3 mechanics.
  Amend the table to match.
- Add §4.1.1 "Relationship to WHITEPAPER §2.1" with an explicit
  table that maps WHITEPAPER terms to the current implementation.
  Specifically: L0 in the whitepaper is aspirational (Phase 2 MCP
  adapter cache); L3 targets (S3) are Phase 5 enterprise, not
  Phase 1.
- Update WHITEPAPER §2.1 to replace "~100 items" with "current
  session buffer" for L0, and L3 from "S3/distributed storage" to
  "compressed SQLite archive, Phase 3". Flag capacity limits
  ("~5 MB per channel soft quota" for L2, "unbounded archive" for
  L3) so the unbounded/permanent language does not overpromise.
- Cross-ref both documents to ADR 2026-03-09 (architecture
  simplification) so the history of the L0-L3 framing is traceable.

### MM-02: L1 integrity chain preimage is ambiguous -- "deterministic JSON" is not a specification

**Spec**: §4.5 L1 Integrity Chain

**Issue**: The chain hash is defined as
`SHA-256("cordelia:l1-chain:" || previous_hash || session_count ||
content_hash)` where `content_hash = SHA-256(JSON-serialised L1)`.
The normative description of the JSON serialisation is:

> Serialisation uses deterministic JSON (keys sorted
> lexicographically, no whitespace).

This is not sufficient to yield byte-identical output across
implementations. RFC 8259 JSON has multiple points of freedom that
"lexicographic sort, no whitespace" does not pin:

- **Number representation:** `1`, `1.0`, `1e0`, `1E0` all parse
  equal. The signer's output depends on the language's
  serialiser. Rust `serde_json` emits `1` for integer-typed
  values, `1.0` for floats; TypeScript `JSON.stringify` emits
  `1` for both if the value is `Number(1)` but cannot distinguish
  integer from float.
- **Unicode escaping:** `"é"` vs `"\u00e9"` -- RFC 8259 permits
  both.
- **Sort order:** "lexicographic" does not specify UTF-8 byte
  order vs UTF-16 code-unit order. For ASCII keys these agree; for
  non-ASCII keys they diverge. `ephemeral.open_threads` contains
  free-form user text; key names in `identity.orgs[].id` could be
  anything.
- **Duplicate-key handling:** RFC 8259 undefined.
- **Nested object and array ordering:** "keys sorted
  lexicographically" applies to object keys. Array order is
  preserved. But what about `roles: ["CPO", "product",
  "engineering"]` -- if a future update reorders, does the hash
  change (desired -- yes it should)?

The chain hash drives the session-bootstrap MANDATORY verification
(§4.5, "Chain verification at session start is mandatory"). If two
devices compute different content_hash for the same semantic L1,
verification fails on the paired device, triggering recovery
(priority 2: "request L1 from paired device via __personal
channel listen"). That path gives back the same JSON, which
hashes differently, and the loop never converges.

Critically: this is a paired-device interop bug, not a single-node
bug. A single-device node will never detect the ambiguity. The
first time a second paired device joins (Phase 2-3), verification
fails non-deterministically.

**Resolution**:

1. Replace "deterministic JSON (keys sorted lexicographically, no
   whitespace)" with "**RFC 8785 JSON Canonicalization Scheme
   (JCS)**". This matches identity.md §9.3 (operator attestation
   signing input) and ecies-envelope-encryption.md §11 conventions.
2. Add explicit test vector: one example L1 object (copy of §4.4
   JSON with fixed values), its JCS encoding (hex or quoted), and
   the resulting content_hash and chain_hash for `session_count =
   1` and `previous_hash = SHA-256("cordelia:genesis:" ||
   "russell")`.
3. Specify integer/float handling: if a field is specified as an
   integer (e.g., `session_count`), implementations MUST serialise
   as an integer literal (`58`, not `58.0`).
4. Specify that Unicode text is serialised as UTF-8 literal
   characters (no `\uXXXX` escaping except for control characters
   and the mandatory `"`, `\`, U+0000..U+001F). This matches JCS.

Cross-ref: ID-01 in review-identity-2026-04-17 flagged the same
class of problem for attestation signing. The fix should be
consistent across both specs.

---

## HIGH

### MM-03: `l1_hot_context` item_id is unreserved in data-formats.md

**Spec**: memory-model §4.2 (L1 single well-known item_id);
data-formats §3.4 items (primary key); channel-naming §3

**Issue**: §4.2 states:

> L1 is a single well-known item (item_id: `l1_hot_context`, fixed
> string, not a UUID) in the personal channel. System items (written
> by the node itself) may use non-`ci_` prefixed item_ids.

Two problems:

1. **data-formats.md §3.4 DDL** says `item_id TEXT PRIMARY KEY,
   "ci_" + ULID (26 chars Crockford Base32)` and does not mention
   the `l1_hot_context` exception. An implementor reading
   data-formats.md would add a CHECK constraint like
   `CHECK(item_id LIKE 'ci_%' AND length(item_id) = 29)` and silently
   reject the L1 item. (The current schema has no such CHECK -- but
   the spec permits one.)
2. The "system items may use non-ci_ prefixed item_ids" sentence is
   permissive, not specified. Which system item_ids are reserved?
   What is the format? `l1_hot_context` is given; what about
   `probe`, `attestation`, `descriptor`, `kv` items mentioned in
   data-formats §3.4? Those have `item_type` in the spec but no
   canonical item_id rule.

**Resolution**:

1. Add to data-formats.md §3.4 items.notes:
   - "`item_id` format: default `ci_` + ULID (26 chars Crockford
     Base32). System items written by the node MAY use reserved
     item_id values (not user-visible). Reserved values: see
     channel-naming.md §X."
2. Add to channel-naming.md a new §X "Reserved item_ids" listing
   `l1_hot_context` and any other fixed strings, with derivation
   rules.
3. In memory-model §4.2, cross-link to channel-naming.md §X and
   data-formats.md §3.4 notes instead of asserting the convention
   inline.

### MM-04: L2 quota units inconsistent and per-channel vs per-node is conflated

**Spec**: §4.1 Size limits; configuration.md line 148
(`l2_quota_mb` default 5)

**Issue**: §4.1 says:

> L2 soft limit: 5 MB per channel (configurable via `config.toml
> [memory] l2_quota_mb`, default 5).

Two ambiguities:

1. **Unit scope**: "5 MB" -- 5 MB of what? UTF-8 plaintext bytes of
   the decrypted `content` field only? Total `encrypted_blob`
   bytes? Sum of all item fields including metadata? The §7.3
   prefetch budget uses "sum of UTF-8 byte lengths of decrypted
   `content` fields". §4.1 inherits this implicitly but does not
   state it.
2. **Per-channel vs per-node**: "5 MB per channel" multiplied by
   potentially hundreds of subscribed channels allows gigabytes of
   local L2. The quota enforcement rule says "oldest interrupt-
   domain items are tombstoned" but does not clarify if this is
   per-channel (most obvious reading) or aggregated across the
   node. The `__personal` channel will always be the hot
   channel -- is its quota 5 MB or do personal memories get more?

configuration.md §3 (`l2_quota_mb`) inherits the same ambiguity.

**Resolution**:

1. Specify the unit: "5 MB = 5,242,880 bytes of UTF-8-encoded
   decrypted `content` field, summed across all non-tombstone L2
   items in the channel. Metadata fields (`tags`, `context`,
   `name`, etc.) are not counted; `encrypted_blob` length is not
   counted."
2. Clarify scope: "Per channel. The node enforces separately for
   `__personal` and each shared channel. An aggregate node-level
   quota is not enforced in Phase 1."
3. Specify eviction order precisely: "On quota breach, items in
   the breached channel are evicted in this order: (1) interrupt
   domain, oldest `published_at` first, until under 90% of quota;
   (2) if still over, procedural domain, oldest first, until
   under 90%; (3) value domain is never evicted -- if still over,
   log ERROR and refuse further writes with error
   `l2_quota_exceeded`."
4. Update configuration.md §3 to match.

### MM-05: Prefetch budget definition is ill-typed

**Spec**: §7.3 Prefetch Strategy

**Issue**: §7.3 says:

> Total prefetch budget: sum of UTF-8 byte lengths of decrypted
> `content` fields of fetched L2 items. Default 51200 bytes (50
> KB), configurable via `config.toml [memory] prefetch_budget_bytes`.

But:

1. **L1 is also loaded.** Is L1 counted toward the budget? §7.3
   step 1 says "Always load: L1 hot context (mandatory, ~50 KB)"
   which is the same as the budget. If L1 is in the budget, there
   is no room for L2 prefetch. If L1 is out of the budget, the
   actual session bootstrap can deliver 50 + 50 = 100 KB, not 50
   KB as implied.
2. **Value-domain items are "always loaded" (step 2) AND capped
   at 20 items (sentence 3) AND truncated at budget (sentence 4).**
   Three rules, three outcomes. Worked example: if the node has
   25 value items totalling 80 KB and the budget is 50 KB, what
   happens? Current text permits any of: (a) load 20 items = 64 KB
   (violates budget), (b) load N items up to 50 KB (violates "20
   cap"), (c) load 20 items then truncate at 50 KB within item
   boundaries (violates "all value-domain items").
3. **Procedural and interrupt loads have no explicit budget.**
   "Relevance load" and "recency load" are labelled "capped" but
   the cap is not specified.

**Resolution**:

Rewrite §7.3 as a deterministic algorithm:

```
Let budget_bytes = config.memory.prefetch_budget_bytes (default 51200)
Let value_cap = 20

1. Load L1 (separate budget; ~50 KB, hard limit 64 KB per §4.1).
   L1 is NOT counted toward prefetch_budget_bytes.

2. Rank value-domain L2 items in the personal channel by
   updated_at DESC. Take up to value_cap items. Sum content bytes;
   call this V.

3. If V > budget_bytes: truncate the list by dropping oldest
   (lowest updated_at) items until total content bytes <= budget.

4. remaining = budget_bytes - V. If remaining <= 0: done, return
   value-domain subset.

5. Rank procedural-domain L2 items by project-context relevance
   (Phase 2: cosine similarity to L1 active.project embedding;
   Phase 1: by updated_at DESC). Add items in order until content
   bytes would exceed remaining.

6. remaining' = remaining - procedural_bytes. If remaining' <= 0:
   done.

7. Rank interrupt-domain L2 items by published_at DESC. Add up to
   remaining' bytes.
```

Also clarify: "content bytes" = UTF-8 bytes of the `content` field
only, consistent with MM-04.

### MM-06: Foundational document pointers dangle after the move

**Spec**: Header `Foundational documents:` line (top of file), §15
References

**Issue**: The header cites:
- `cordelia-core/docs/design/memory-architecture.md`
- `special-circumstances/memory-substrate-thesis.md`

§15 adds:
- `cordelia-core/docs/design/memory-architecture.md` (duplicate)
- `special-circumstances/memory-substrate-thesis.md` (duplicate)
- `special-circumstances/claude-memory-system.md`
- `cordelia-proxy/SEARCH.md`
- `competitors/ai-memory-landscape-2026.md`

Per MEMORY.md, `cordelia-core` is **archived on GitHub, do not use**,
and specs/ADRs moved from seed-drill to cordelia-node on 2026-03-17.
§7.1 also references `cordelia-proxy/SEARCH.md` (line 425, 461) --
cordelia-proxy is not in the Phase 1 repository structure (this
review's cursory check found no corresponding file in
cordelia-node).

A reader trying to follow these references to understand the
foundational reasoning gets dead links for 4 of the 6 listed
documents.

**Resolution**:

1. At the file header, replace the foundational-documents line with
   links to documents that exist (this repo's `docs/decisions/`
   ADRs, or WHITEPAPER.md §2).
2. In §15, either:
   (a) remove the cordelia-core/special-circumstances/cordelia-proxy
       references, or
   (b) prefix them with "(historical, archived -- see
       seed-drill/archive/ for originals)".
3. If cordelia-proxy/SEARCH.md has been merged into
   search-indexing.md, replace all §7.1 cross-refs with
   search-indexing.md §7.

Cross-ref: Likely the same class of drift as DF-18 in
review-data-formats.

### MM-07: "L1 via replication" asserts push that network-protocol.md does not deliver

**Spec**: §4.2 Mapping to Pub/Sub Primitives
(`L1 ... Node SQLite + replication`), §4.5 Recovery priority
("request L1 from paired device via `__personal` channel listen")

**Issue**: memory-model.md assumes personal-channel items replicate
between paired devices via push. In the current Phase 1 model,
per NB-01 (review-network-behaviour-2026-04-17.md §1), personal
nodes receive items exclusively via Item-Sync pull, not push.

Consequences:

- L1 update latency is bounded by `sync_interval` (network-protocol
  §8.2) -- 10 s for realtime, 900 s for batch -- not "immediate".
  A reader thinking L1 syncs instantly across paired devices will
  design tests and diagnostics wrong.
- Recovery priority 2 ("request L1 from paired device via
  `__personal` channel listen") depends on the listening device
  having already pulled the latest L1 via Item-Sync. If sync hasn't
  completed since the peer device's last L1 update, the response
  is stale. The priority ordering is still correct, but the
  mechanism needs clarification.
- §8.5 tombstone replication: "Expiry tombstones replicate via the
  personal channel to paired devices" -- same concern. This
  happens via pull, not push.

**Resolution**:

1. Amend §4.2 row `L1 | Personal channel, latest item ... | Node
   SQLite + replication` to "Node SQLite + Item-Sync replication
   (pull, interval per channel mode)". Link to
   network-protocol.md §8.2.
2. In §4.5 recovery priority 2, specify: "request L1 from paired
   device via `__personal` channel listen (served from the
   listener's local SQLite; remote L1 updates are pulled on the
   standard sync interval, not on-demand)."
3. Add a note in §5.1: "Personal channel replication uses the
   Phase 1 pull model (network-protocol.md §4.6, §7.2, §8.2).
   Cross-device L1 freshness is bounded by `sync_interval`."

Cross-ref: NB-01 (review-network-behaviour-2026-04-17).

---

## MEDIUM

### MM-08: Tombstone replication scope underspecified

**Spec**: §8.5 Expiry Sweep ("Tombstone replication"); §11.4 GDPR
("tombstones replicate via personal channel to paired devices");
data-formats §3.4 (is_tombstone column); network-protocol §6.3
(7-day retention)

**Issue**: §8.5 says "Expiry tombstones replicate via the personal
channel to paired devices. ... Tombstones carry no content, only
item_id and is_tombstone=true."

Gaps:

1. **For shared channels**, do tombstones propagate? §6.2 rows
   say shared channel lifecycle is "Phase 1: no automatic TTL,
   items persist until explicitly deleted" -- so there are no
   expiry tombstones on shared channels. But what about explicit
   delete-item calls (channels-api §3.6)? These produce
   tombstones. Do those replicate? To whom?
2. **For personal channel**, paired devices receive via pull per
   MM-07. The 7-day retention window in network-protocol §6.3
   applies. If a paired device is offline for >7 days, it will not
   see the tombstone. The reconstituted L2 will contain the
   expired item indefinitely. This needs to be called out.
3. **Content-hash retention**: §11.4 tombstone privacy note says
   tombstones retain `content_hash`. data-formats §3.4 does not
   say if `encrypted_blob` is zeroed on tombstone flip or left
   intact. DF-12 in review-data-formats flagged this. memory-model
   should cross-reference the resolution rather than leave it
   implicit.

**Resolution**:

1. §8.5: specify "tombstones are produced on (a) TTL-driven
   expiry in the personal channel, (b) explicit
   `delete-item`/`forget` calls in any channel". State the
   replication scope for each: (a) paired devices via personal
   channel Item-Sync pull; (b) all subscribers of the target
   channel via Item-Sync pull. Shared channels have no TTL-driven
   tombstones in Phase 1.
2. Add a paragraph: "Tombstone convergence bound: 7 days
   (network-protocol.md §6.3). Devices offline longer than 7 days
   may retain expired items until a local sweep catches them
   independently."
3. Cross-ref DF-12 once data-formats is updated.

### MM-09: Embedding storage path overlaps with search-indexing.md but does not reference it

**Spec**: §7.5 Embedding Model

**Issue**: §7.5 defines:
- Model: nomic-embed-text-v1.5 (768-dim)
- Storage: sqlite-vec `FLOAT[768]` column
- Cache key: SHA-256 of embeddable text
- Generation trigger: async, on item write
- Backfill: `memory_backfill_embeddings` MCP tool

search-indexing.md §2.5 authoritatively defines:
- `search_vec` virtual table with `FLOAT[768]` column
- `search_embedding_meta.content_hash` (SHA-256 **hex** of
  plaintext embeddable text, not raw bytes)
- `status` state machine (pending -> complete -> stale -> pending)

The two specs describe the same mechanism. memory-model §7.5 does
not reference search-indexing.md and therefore duplicates (and
risks drifting from) the authoritative source. Specifically:

- `FLOAT[768]` is defined in search-indexing.md §2.5 -- memory-model
  repeats it without cross-ref.
- "Cache key: SHA-256 of embeddable text" is the content_hash
  discipline in search-indexing.md §3.2. memory-model does not
  link.
- The backfill tool name `memory_backfill_embeddings` exists in
  the MCP tool list (visible in this session's tool schemas) and
  is not cited in search-indexing.md. Where is the canonical
  MCP-tool-to-function mapping?

**Resolution**:

1. Replace §7.5 bullets with: "Embedding pipeline is specified in
   search-indexing.md §3.2-§3.3. memory-model uses the same
   pipeline for L2 memory items in the `__personal` channel. The
   embeddable text is the concatenation of `name`, `summary`,
   `content` (order-sensitive, UTF-8, no separator)."
2. Add the `name + summary + content` concatenation rule to
   search-indexing.md §3.2 (it is the memory-specific embeddable
   text composition and belongs in the authoritative spec).
3. Add `memory_backfill_embeddings` tool mapping to §10.3 MCP
   table.

### MM-10: §8 Novelty domain default and SDK §9 domain requirement conflict

**Spec**: §3.4 Classification rules ("Phase 1: domain classification
is explicit (caller specifies domain). If omitted, default is
`procedural`."), §5.2 Field requirements (`domain` Required: Yes,
Default: `procedural`), §9.2 Phase 1 Approach (Phase 1 publish
example omits domain)

**Issue**: §3.4 and §5.2 agree: domain is REQUIRED, default
`procedural` applied at write time. §9.2 shows a Phase 1 publish
call that omits `domain` entirely -- which is permitted because
the SDK's `publish()` treats content as opaque (§5.2 final
paragraph). But then the node sees a memory-typed item
(`memory:learning`) with no domain inside the encrypted blob, and
§5.2 says "domain field MUST be present in stored items (default
applied at write time if omitted)".

Who applies the default? The SDK does not parse memory content in
Phase 1. The node decrypts on publish but the spec doesn't say
the node rewrites the plaintext to inject the default. If the
default is applied post-decryption at read time, the stored blob
is out of spec.

**Resolution**:

1. State explicitly: "Phase 1 default application happens on
   **read**, not write. If `domain` is missing from a stored
   memory item, the reader treats it as `procedural`. Phase 2's
   `c.remember()` injects the default at write time."
2. Update §9.2 Phase 1 equivalent publish to include explicit
   `domain` and note: "Setting domain explicitly is recommended
   but not required in Phase 1."

### MM-11: PAN / `scope` column silence

**Spec**: §4.2 (pub/sub primitive mapping), §5.1 (personal channel),
§6.4 (shared memory use cases)

**Issue**: data-formats migration v3 (DF-01) adds a `scope` column
to `channels` (`network` | `local`) for PAN ephemeral local
channels. memory-model.md has no awareness of this scope axis. A
PAN swarm (CLAUDE.md "Persistent swarm":
`cordelia:swarm:<lead_entity_id>` channel, local-scope) is exactly
a shared-memory use case §6.4 discusses but under "agent swarm
coordination" with realtime semantics. The spec does not tell the
reader whether PAN local-scope channels carry memory items or
whether the domain/lifecycle/prefetch rules apply.

**Resolution**:

1. Add §6.5 "Local-scope channels (PAN)": state that
   local-scope channels participate in memory operations exactly
   like network-scope channels (same item structure, same domain
   classification, same search indexing), except they are not
   replicated beyond the local host. L2 quota and prefetch rules
   apply per channel.
2. Cross-ref data-formats §3.1 `scope` column (once DF-01
   resolves).

### MM-12: Cross-channel search disallowed in spec, contradicted by SDK example

**Spec**: §11.2 ("The search endpoint MUST enforce `channel_id` as
a mandatory WHERE clause -- queries without a channel parameter
are rejected (400 Bad Request). ... No cross-channel search in
Phase 1.")

And §7.4 SDK Search Interface example:
```typescript
// Cross-channel search (personal memory)
const personal = await c.search('__personal', 'pairing protocol security')
```

**Issue**: The comment says "Cross-channel search (personal
memory)" but the code is single-channel (search within
`__personal`). This is not cross-channel search -- it is a search
in one channel. The comment is wrong and leads readers to think
Phase 1 supports something it doesn't.

Additionally, §7.3 prefetch step 2 ("Always load: All value-domain
items from L2") implicitly requires reading across all subscribed
channels to find value-domain items, OR is scoped to just
`__personal`. The spec does not say. If it means across all
channels, it contradicts §11.2.

**Resolution**:

1. Fix the §7.4 comment: replace "Cross-channel search (personal
   memory)" with "Search personal memory".
2. Clarify §7.3 step 2: "All value-domain items from L2 in the
   `__personal` channel. Cross-channel value-domain prefetch is
   Phase 3 (cross-channel memory search)."
3. Add to §13.3 Phase 3 features: "Cross-channel value-domain
   prefetch" as the complement to "Cross-channel memory search".

### MM-13: `content_hash` term is overloaded, inherited from data-formats

**Spec**: §5.2 (wire envelope `content_hash`), §4.5 (chain hash
uses `content_hash` of L1 JSON)

**Issue**: memory-model §5.2 notes:

> The wire envelope's `content_hash` (per ECIES spec §11.7) is
> SHA-256 of the encrypted blob (ciphertext), not of the plaintext
> content.

And §4.5 uses `content_hash` in the chain definition meaning
SHA-256 of **plaintext JSON L1 with integrity object removed**.
Same word, different preimage, different purpose, same spec.

DF-14 flagged this overload across data-formats and search-
indexing. memory-model adds a third sense (L1 chain content
hash). At least three concepts share the name in Phase 1 specs.

**Resolution**:

1. Rename the chain preimage hash: in §4.5, replace
   `content_hash` with `l1_content_hash` or `l1_snapshot_hash`.
   Update the chain_hash formula accordingly.
2. Add a term to §14 Glossary: "`l1_content_hash`: SHA-256 of
   canonicalised L1 JSON excluding the `ephemeral.integrity`
   object. Distinct from `content_hash` (wire envelope, SHA-256
   of ciphertext) and `search_content_hash` (FTS5 preimage hash)."
3. Cross-ref DF-14 for the resolution timeline on the wire-level
   term.

### MM-14: §8.1 GDPR automated-processing wording is conditional, not prescriptive

**Spec**: §8.1 Automated processing note

**Issue**: The note says:

> Phase 2 automatic novelty filtering constitutes automated
> processing under GDPR Art. 22. Deployments processing personal
> data about individuals should ensure human oversight of automatic
> expiry decisions, or establish that the legitimate interest basis
> includes automated lifecycle management.

Two issues:

1. "Should ensure" is not a spec obligation. The implementation
   cannot act on "should ensure" -- who ensures, how, when?
2. Art. 22 specifically relates to decisions "producing legal
   effects concerning him or her or similarly significantly
   affecting him or her". Memory expiry is unlikely to meet that
   bar. The note is overcautious but framing it as a compliance
   obligation without evidence invites legal confusion. The spec
   should either (a) state the actual mechanism that enables
   human oversight (e.g., audit log of expiry events, Phase 4
   feature), or (b) downgrade the note to a deployment guidance
   note not a normative requirement.

**Resolution**:

1. Move the paragraph to §11.5 UK DPA and GDPR Compliance, where
   similar guidance sits.
2. Rewrite: "Phase 2 automatic novelty filtering and TTL expiry
   are automated decisions about memory retention. Deployments
   subject to GDPR Art. 22 (solely automated decisions with legal
   or significant effects) should assess whether memory
   retention decisions reach that threshold; in most agent-memory
   deployments they do not (memory expiry does not produce legal
   effects on data subjects). Phase 4 adds audit logging of
   expiry events to support human review where the assessment
   concludes Art. 22 applies."
3. Remove the normative "should ensure" language from §8.1.

---

## LOW

### MM-15: §4.4 L1 JSON example contains dated session content

**Spec**: §4.4

**Issue**: The example L1 object has:
- `last_summary: "Session 57: ..."`
- `current_session_start: "2026-03-12T11:42:38.052Z"`
- `updated_at: "2026-03-12T11:42:38.052Z"`

These are clearly personal to Russell's actual session state at
spec-writing time and risk reader confusion ("is `russell` a
reserved identity id? is session 58 significant?").

**Resolution**: Replace identity-specific values with generic
placeholders (`alice`, `2026-01-01T00:00:00Z`, etc.) and add
explicit "Example L1 for entity `alice`:" caption.

### MM-16: §10.1 Memory Tool `delete` mapped to `c.forget(itemId)` but Phase 1 has no `c.forget()`

**Spec**: §10.1 Anthropic Memory Tool Adapter mapping table

**Issue**: `delete (remove file) | c.forget(itemId)` -- but §9.1
puts `c.forget()` in the Phase 2 SDK additions. The adapter is
Phase 2 per §10.1, so this is internally consistent, but a reader
cross-referencing sdk-api-reference.md Phase 1 API will find no
`forget`. Add clarifying note.

**Resolution**: Add to the §10.1 table header: "Adapter and SDK
methods below are Phase 2." Then remove the "(Phase 2)" tag from
the section header since it repeats.

### MM-17: §12 positioning matrix ASCII is ambiguous

**Spec**: §12.1 Positioning Matrix (ASCII grid)

**Issue**: The grid places Cordelia in the bottom centre on the
"Sovereignty" axis but Mem0/Letta/etc in the top. The quadrant
labels (features vs sovereignty, self-hosted vs cloud) intersect
at the origin; Cordelia at the bottom centre reads as "low
features, medium self-hosted/cloud" which contradicts §12.2
showing Cordelia has more capabilities checked than competitors.

**Resolution**: Redraw the matrix so Cordelia is in the "high
sovereignty, high features, self-hosted" quadrant (bottom-left).
Alternatively, remove the ASCII and keep only the feature
comparison table (§12.2), which is unambiguous.

---

## Passes Not Applied (per instructions)

| Pass | Reason |
|------|--------|
| 6 (Attack trees) | Out of scope for this review pass; see review-attack-trees-2026-04-17 |
| 7 (Terminology) | Light coverage only -- one terminology issue surfaces at MM-13 |
| 9 (Test vectors) | Phase 1 does not require cross-language L1 test vectors; MM-02 proposes adding one |
| 10 (Privacy) | Covered by review-privacy.md |
| 11 (Operational) | Out of scope for this pass |
| 13 (Compliance) | Covered by §11 cross-refs; MM-14 flags one paragraph |
| 14 (Data model) | Driven by data-formats.md review (DF-01 covers schema drift) |
| 15 (Build verification) | Not a post-implementation spec; L1/L2 pipeline not yet fully built |

---

## Recommended Triage

**Fix before Phase 1 close (whitepaper-spec coherence + interop):**

- **MM-01** (WHITEPAPER L0-L3 vs spec L0-L3 -- narrative
  correctness). CRITICAL.
- **MM-02** (chain hash canonical form -- interop correctness).
  CRITICAL.

**Fix in one editing session (doc correctness):**

- MM-03 (item_id convention), MM-04 (quota units),
  MM-05 (prefetch algorithm), MM-07 (push-vs-pull narrative),
  MM-12 (cross-channel comment fix).

**Fix opportunistically:**

- MM-06 (foundational doc pointers), MM-08 (tombstone scope),
  MM-09 (search-indexing cross-ref), MM-10 (domain default
  timing), MM-11 (PAN scope), MM-13 (content_hash rename),
  MM-14 (GDPR wording).

**Nice-to-have:**

- MM-15 (example polish), MM-16 (adapter phase label), MM-17
  (matrix redraw).

---

## Cross-Spec Observations

Not findings for this spec, but surfaced during review:

- `memory_backfill_embeddings` MCP tool is present in the tool
  manifest but not enumerated in memory-model §10.3's
  MCP-tool-to-function table. Add it alongside the existing
  entries (log in ACTIONS).

- `cordelia-proxy/SEARCH.md` references (§7.1, §7.5, §15) need
  resolution: either the document was merged into
  `search-indexing.md` and these references should redirect, or
  it lives in an adjacent repo and should be labelled
  cross-repo.

- §4.5 chain hash should probably be factored into a small
  dedicated "L1 chain" sub-spec or a reference-implementation
  block in `data-formats.md §7`, since three specs (memory-model,
  identity, data-formats) all describe related canonicalised-hash
  pipelines with subtle variations.

- The MEMORY.md status says cordelia-core is archived -- any spec
  still pointing at cordelia-core paths (header line of this
  spec) should be cleaned up as part of the same editing pass.

---

*Review complete 2026-04-17.*
