# Review: architecture-overview.md

> Fresh review pass applying review-spec methodology to
> `architecture-overview.md` (Draft 2026-03-12, 749 lines).
> Documentation due-diligence before closing Phase 1.

## Application Record

| Field | Value |
|-------|-------|
| Date | 2026-04-17 |
| Reviewer | Russell Wing + Claude Opus 4.7 |
| Spec | architecture-overview.md (Draft 2026-03-12) |
| Passes applied | 1 (Gaps), 2 (Consistency), 3 (Clarity), 4 (Implementability), 5 (Coverage), 6 (Cross-ref integrity) |
| Reference specs | network-protocol.md, data-formats.md, memory-model.md, parameter-rationale.md, identity.md, channels-api.md, WHITEPAPER.md, CLAUDE.md |
| Prior reviews cross-checked | review-network-behaviour-2026-04-17.md, review-data-formats-2026-04-17.md, review-memory-model-2026-04-17.md, review-parameter-rationale-2026-04-17.md, review-topology-e2e-2026-04-17.md |

---

## Summary

19 findings. 3 CRITICAL (publish flow still describes pre-pivot
"push to all hot peers sharing the channel" contra network-protocol
§4.6; governor tick §6.5 step 4 says "promote BEST warm" contra
network-protocol §5.4 which MANDATES random promotion as anti-Sybil
property; §8.4 summary of memory model mis-frames L1/L2 as
"personal vs shared" contradicting memory-model.md §4). 7 HIGH
(Phase-1 protocol count wrong -- 8 listed vs 9 in spec; entire
routing-mode/seen-table/RouteACK system absent; ADR index omits
2026-03-15 and 2026-03-20 decisions; governor defaults stale vs
parameter-rationale; quality scenario "<1s realtime" defensible
only with epidemic forwarding which isn't described; Ollama port
documented as "localhost:11434" in context diagram with arrow
direction inverted; spec-index maps memory-model to §8.4 but that
section describes identity taxonomy). 6 MEDIUM (keeper
phase-tag inconsistency Phase 2+ vs Phase 3; L1/L2 overloading
across identity and memory sections; sync interval listed as
"60s (safety net)" -- authoritative value is 10s; building-block
dependency graph missing cordelia-test path that exists in
Cargo.toml; "Quality Goals" lists 5 priorities where security is
#2 not #1; author attribution Opus 4.6 but today Opus 4.7).
3 LOW (doc polish).

The AOD is the document a new reader opens first. Every drift here
propagates into every downstream mental model. The three CRITICALs
all tell the same story: the spec describes a pre-pivot
push-to-subscribers replication model that has been replaced in
network-protocol.md by relays-push-to-relays + personal-nodes-pull,
epidemic forwarding via seen table, and random promotion for
anti-eclipse. network-protocol.md has been revised repeatedly since
2026-03-12 while the AOD has not been touched. This is the highest
load-bearing drift in the spec set -- a reviewer following the AOD
would conclude the implementation was wrong.

---

## CRITICAL

### AO-01: Publish flow contradicts network-protocol §4.6

**Spec**: §6.1 "Publish Flow", key points bullet 4, plus §10.2
Quality scenario "Realtime item delivery (push) <1s peer-to-peer".

**Issue**: AOD states: "For realtime channels: Item-Push (0x06)
fires to all hot peers sharing the channel + relay peers."
network-protocol.md §4.6 is now explicit: "On local write to a
realtime channel: push to hot **relay peers only**. The originator
(personal node or keeper) pushes to its hot relays; relays handle
distribution. Non-relay peers receive items via Item-Sync pull
(§4.5)." The AOD text is the pre-pivot model.

This is the single most important architectural correction in
Phase 1 (consolidates relay-push-to-all-hot per ADR
2026-03-20-relay-forwarding-route-discovery and personal-node
pull-primacy per network-protocol §4.5). A reader of the AOD will
build code that pushes from publishers to every hot peer.

**Resolution**: Rewrite §6.1 key points to read:
- "The publisher pushes only to its hot **relay** peers; relays
  perform epidemic forwarding to other relays (§7.2 seen table);
  personal nodes and keepers receive via Item-Sync pull (§4.5)."
- Update §10.2 realtime delivery measure to reference the two
  delivery paths (relay fan-out latency + pull-sync interval,
  see network-protocol.md §4.5 convergence bounds).

**Cross-ref**: NB-01 (network-behaviour review flagged the same
pre-pivot residue in the behaviour spec).

---

### AO-02: Governor tick says "promote best warm" -- must be random

**Spec**: §6.5 "Governor Tick (every 10s)", step 4:
`"Promote Warm->Hot  ─▶  If hot_count < hot_min, promote best warm"`.

**Issue**: network-protocol.md §5.4 step 4 is explicit and
bolded: "**Anti-eclipse: promotion is RANDOM among eligible warm
peers, not best-scoring.** This prevents an attacker from gaming
their score to get promoted faster than honest peers (cf.
Cardano's `simplePromotionPolicy`)." §5.5 reinforces: "Scoring
is used for DEMOTION only, not promotion." This is a Phase 1
security property, not an implementation detail.

"Best warm" in the AOD is the pre-pivot model and, if implemented,
degrades eclipse resistance because an attacker can game score.

**Resolution**: Replace step 4 with:
`"Promote Warm->Hot  ─▶  If hot_count < hot_min, promote a RANDOM
eligible warm peer (anti-Sybil; see network-protocol.md §5.4
step 4)."` Add a parenthetical note below the table:
"Random promotion is a security property; do not change to
best-scoring."

Also update step 5: current text "demote worst scorer" is correct
(demotion IS scoring-driven), but add "(scoring drives demotion
only, never promotion)" for symmetry and to forestall re-drift.

---

### AO-03: §8.4 Memory Model summary mis-frames L1/L2

**Spec**: §8.4 "Memory Model", closing paragraph:
"L1 (personal memory) stored in `__personal` channel. L2 (shared
memory) stored in named channels. Prefetch budget: 50 KB per
session start."

**Issue**: memory-model.md §4.1 defines L1/L2/L3 as a **cache
hierarchy** of a single identity's memory (L0 = conversation
buffer, L1 = hot context ~50 KB, L2 = warm index ~5 MB, L3 = cold
archive). §4.2 then says all three persistent layers (L1/L2/L3)
back onto the personal channel OR shared named channels identically
-- the personal-vs-shared axis is **orthogonal** to L1/L2/L3.

The AOD reduces L1/L2 to a personal/shared dichotomy, which is
both wrong on its own and flatly contradicts memory-model.md §4.2
table. New readers will conclude that L1 means "personal" and L2
means "shared", and the whole cache-hierarchy concept (frame
memory vs data memory, prefetch strategy, novelty) is lost.

**Resolution**: Rewrite §8.4 closing paragraph:
"Memory layers (L0/L1/L2/L3) are a cache hierarchy for a single
entity's memory, orthogonal to personal-vs-shared. L1 is the 50 KB
hot context loaded at session start; L2 is the searchable warm
index; L3 (Phase 3) is the cold archive. Personal memories live
in `__personal`; shared memories live in named channels; both use
the same L0-L3 hierarchy. Full model: memory-model.md §3-§5."

Also: note in a callout that "L1" and "L2" mean something
**different** in §8.2 (identity layers) and §8.4 (memory layers).
See AO-10.

---

## HIGH

### AO-04: Mini-protocol count is wrong (8 vs 9)

**Spec**: §5.2 table row for `cordelia-network`: "QUIC transport,
**8** mini-protocols, governor state machine, replication engine".
Spec Index row for network-protocol.md: "Transport, wire format,
**8** mini-protocols, governor, replication, routing".

**Issue**: network-protocol.md §3.3 protocol byte table lists
**9** protocols (0x01 Handshake through 0x09 RouteACK).
RouteACK was added with ADR 2026-03-20-relay-forwarding-
route-discovery and is Phase 1 (routed personal-memory delivery).

**Resolution**: Change both occurrences of "8 mini-protocols" to
"9 mini-protocols" and mention RouteACK explicitly in §6 (Runtime
View) alongside the other protocol flows.

---

### AO-05: Routing modes, seen table, RouteACK entirely missing

**Spec**: §6 Runtime View covers Publish, Subscribe+PSK, Item-Sync,
Device Pairing, Governor Tick. §8 Cross-cutting covers encryption,
identity, channel types, memory, errors. §11 lists risks.

**Issue**: The entire Phase 1 relay-forwarding subsystem is
absent from the AOD:

- Epidemic forwarding with seen table (network-protocol.md §7.2,
  `SEEN_TABLE_MAX=10000`, `SEEN_TABLE_TTL=600s`)
- `routing_mode` field on Item (epidemic=0 vs routed=1,
  network-protocol.md §4.6)
- Route discovery and caching (network-protocol.md §7.4,
  broadcast-discover-cache with encrypted routing tokens)
- RouteACK (0x09) return path (network-protocol.md §7.4)

CLAUDE.md confirms this is shipped, tested, and solved
cordelia-node#9 (sparse mesh partitioning). It is the defining
Phase 1 property ("epidemic forwarding" is in the current working
status line).

**Resolution**: Add §6.6 "Relay Forwarding" runtime view:
sequence diagram showing publisher -> relay_1 -> relay_2 ->
peer, seen-table dedup at each hop, pull-sync backstop.
Add §8.6 "Routing Modes" cross-cutting: epidemic (group channels,
no privacy tokens) vs routed (personal channels, encrypted route
tokens + RouteACK). Add a one-line reference in §6.1 Publish key
points.

---

### AO-06: ADR index omits 5 of 9 ADRs

**Spec**: §4.1 sentence: "ADRs: `decisions/2026-03-09-architecture-
simplification.md` (§17 canonical), `decisions/2026-03-09-spo-
economic-model.md`, `decisions/2026-03-09-mvp-implementation-
plan.md`, `decisions/2026-03-10-identity-privacy-model.md`"
and §9 "Architecture Decisions" lists the same 4 rows.

**Issue**: `docs/decisions/` contains 9 ADRs, including five
post-dating 2026-03-12 that are load-bearing for current code:
- 2026-03-10-phase1-design-decisions.md
- 2026-03-10-testing-strategy-bdd.md
- 2026-03-15-peer-state-semantics.md
- 2026-03-15-tcp-vs-udp-transport.md
- 2026-03-20-relay-forwarding-route-discovery.md

§4.1 also says "(§17 canonical)" but the AOD has only 12
numbered sections -- this points into the ADR itself, which is
unclear without context.

**Resolution**: Expand §9 table to cover all 9 ADRs. Either
remove the `(§17 canonical)` marginal note or rephrase as
"(see §17 of that ADR for canonical decision text)".

---

### AO-07: Governor defaults drift vs parameter-rationale

**Spec**: §6.5 "Governor Tick" uses natural-language parameter
names without values. §11.2 table row 5 says "lazy rotation".

**Issue**: The AOD historically cited governor values inline
(hot_max=10, sync_interval=60). Current text has stripped the
numbers, which is defensible, but §6.5 still reads:
- step 6: "Every churn_interval (**1h**), swap **20%** warm"
- §10.2: "Batch sync convergence | <15 min"
- §10.2: "Governor tick | 10s interval"

parameter-rationale.md §3 sets churn_interval=3600s ± 300s
jitter (so "1h" hides the jitter), and churn_fraction=0.2 with
warm_max=10 -> "2 peers" per cycle (not "20% warm"), and
§2.1 sets realtime sync interval to **10s** not 60s (the AOD's
§6.1 key-points references "60s (safety net)" which is a pre-
pivot value).

**Resolution**: In §6.1 key points replace the sync-interval
bullet with:
"Realtime channels: 10s sync cadence (primary pull-sync delivery
for personal/keeper, §4.5). Batch channels: 900s (15 min)."
In §6.5 step 6: "Every churn_interval (default 3600s ± 0-300s
jitter, §5.4), swap `churn_fraction` (default 0.2) of warm peers".
Add forward-reference link to parameter-rationale.md.

---

### AO-08: "<1s realtime delivery" measure needs qualification

**Spec**: §1.3 Quality Goal: "<1s item delivery (realtime)".
§10.2: "Realtime item delivery (push) | <1s peer-to-peer |
network-protocol.md §4.6".

**Issue**: network-protocol.md §4.5 convergence bound is:
- Bootstrap: ~85s
- Steady state: ~390s (dominated by `min_warm_tenure=300s`)
- Plus O(D) per relay hop, where D = relay chain depth

"<1s peer-to-peer" is only true for two Hot **relay** peers on
the same mesh with the item already in the seen-table path.
Personal nodes pull on a 10s cadence (§4.5) so first-hop
delivery to a personal node is bounded by the pull-sync
interval (up to 10s), not 1s.

**Resolution**: Change the measure to:
"Realtime delivery (relay-to-relay push) <500 ms at the same
datacentre; <2s cross-region. Personal-node first-hop delivery
bounded by pull-sync interval (10s default). Steady-state
convergence after partition heal ~390s (network-protocol.md
§4.5)."

---

### AO-09: Technical Context diagram -- Ollama arrow inverted + misleading

**Spec**: §3.2 ASCII diagram, Ollama block:
```
│  ┌─────────────┐     HTTP/localhost:11434     │  │ P2P Network  │
│  │ Ollama      │◀────────────────────────────│  │ (quinn/QUIC) │
│  │ (embeddings)│                              │  └──────┬───────┘
```

**Issue**: The arrow from the P2P Network box to Ollama is
wrong -- Ollama is called by the search/storage layer for
embedding generation, not by the P2P layer. Also the arrow
direction (`<`) is reversed relative to the legend ("Outbound
only" per §3.1 table). The net effect is that the diagram
reads as "QUIC talks to Ollama", which is nonsensical.

**Resolution**: Redraw so the Ollama arrow originates from Core
Engine (search subsystem) and points toward Ollama:
```
│  ┌──────────────┐     HTTP/localhost:11434     ┌─────────────┐
│  │ Core Engine  │─────────────────────────────▶│ Ollama      │
│  │ (search)     │                               │ (embeddings)│
│  └──────────────┘                               └─────────────┘
```

---

### AO-10: Identity L1-L3 and Memory L1-L3 collide without disambiguation

**Spec**: §8.2 Identity Model table uses L0/L1/L2/L3 for
Cryptographic/Self-declared/Verified/Reputation. §8.4 Memory
Model also says "L1 (personal memory)... L2 (shared memory)..."
(already flagged in AO-03). Additional confusion: WHITEPAPER
§2.1 uses L0-L3 for a CPU-cache-inspired hierarchy (L0 in MCP
adapter process, L3 on S3).

**Issue**: Three different L0-L3 taxonomies live in parallel.
New readers coming in via the AOD will conflate identity layers
with memory layers.

**Resolution**: In §8.2 rename the identity layers to "Identity
Layer 0..3" or "IL0..IL3", and call out at the top of §8: "The
L0..L3 taxonomy used for identity (§8.2) is distinct from the
memory cache layers defined in memory-model.md §4." Whitepaper
alignment is out of scope for this spec but should be noted for
WP11 copy work.

**Cross-ref**: MM-02 (memory-model review flagged the whitepaper
L0-L3 vs memory-model.md L0-L3 drift).

---

## MEDIUM

### AO-11: Keeper phase-tag inconsistency

**Spec**: §1.2 P3 row "SPO keeper economics | Phase 3".
§1.4 stakeholder row "SPO keeper (Phase 3+)".
§12 Glossary: "**Keeper** | (Phase 2+) Node that holds PSK
for a channel and provides durable storage. SPO-operated."

**Issue**: Glossary says Phase 2+; everywhere else says Phase 3+.

**Resolution**: Align to "Phase 3+" (the canonical ROADMAP
phase for SPO keeper economics). Fix the glossary entry.

### AO-12: §5.2 Crate table mentions cordelia-core with mixed meaning

**Spec**: §5.2 row for `cordelia-core`: "Shared types...New (not
the old cordelia-core repo)". Also §2.1 row: "Rust for node...
Proven in cordelia-core."

**Issue**: "cordelia-core" refers to two different things in
the same document: (a) the archived pre-pivot GitHub repo
(cordelia-core from the old libp2p+JSON stack) and (b) the new
`crates/cordelia-core/` workspace crate. The disambiguation
in §5.2 is easy to miss; §2.1 cites the archived repo without
flag. Given CLAUDE.md calls out "cordelia-core: ARCHIVED on
GitHub. Old libp2p+JSON+axum implementation. Do not use", this
risks readers following the trail to stale code.

**Resolution**: Retire "cordelia-core" as a reference name for
the archived repo -- call it "cordelia-core (archived, 2025)"
or "legacy cordelia-core" where the archived repo is meant. In
§2.1 first row, change "Proven in cordelia-core" to "Proven in
the pre-pivot libp2p node (legacy cordelia-core, now archived)".

### AO-13: Port convention muddled -- UDP/TCP/both?

**Spec**: §1.2 QUIC row: "Personal nodes outbound-only (UDP
rarely blocked outbound)". §3.1: "Peer nodes | QUIC (port 9474)
| Bidirectional | TLS 1.3 + Ed25519". §3.2 diagram: "UDP/9474".
§7.1: system service stanza is silent on port.

**Issue**: AOD says "Port 9474" without the `/UDP` suffix in
the Business Context table. Given the whole-document emphasis
on outbound-UDP-vs-restricted-networks (§11.1 risk row), the
transport is critical and should be unambiguous everywhere.

**Resolution**: Write all port references as "9474/UDP" and
"9473/TCP" and note `9474/UDP` is inbound on relays/bootnodes,
outbound-only on personal nodes.

### AO-14: Dependency graph omits cordelia-crypto from cordelia-api

**Spec**: §5.3 dependency graph:
```
cordelia-api
  ├── cordelia-storage
  │     ├── cordelia-crypto
  │     └── cordelia-core
  └── cordelia-core
```

**Issue**: `crates/cordelia-api/Cargo.toml` declares
`cordelia-crypto = { workspace = true }` directly, not
transitively via cordelia-storage. The REST API uses
cordelia-crypto for bearer-token signing and bech32 decoding at
the edge.

**Resolution**: Add cordelia-crypto under cordelia-api in the
dependency tree.

### AO-15: Spec Index row for memory-model is miscategorised

**Spec**: Spec Index final table:
"memory-model.md | §8.4 Memory | Three-domain model, L1/L2,
prefetch, novelty, expiry"

**Issue**: AOD §8.4 is titled "Memory Model" and does describe
memory. But §8.2 ("Identity Model") uses the same L0/L1/L2/L3
phrasing. The index row compounds the confusion in AO-10 by
confirming "L1/L2" without qualifier. Also the row says
"§8.4 (implicit)" for search-indexing.md -- which is a hedged
pointer.

**Resolution**: Relabel the scope cell to "Three-domain model
(values/procedural/interrupt), memory cache L0-L3, prefetch,
novelty, expiry". Remove "(implicit)" from the
search-indexing.md row or split §8 into explicit subsections
(§8.4 Memory, §8.5 Search).

### AO-16: Ports diagram leaves P2P key size unspecified

**Spec**: §3.1 external actors table: "Peer nodes | QUIC (port
9474) | Bidirectional | TLS 1.3 + Ed25519".

**Issue**: This is the first concrete mention of the identity
curve in the AOD and it reads as if TLS handshake is signed
with Ed25519. network-protocol.md §2.2 shows the actual binding:
TLS uses RFC 8410 Ed25519 certificates (OID 1.3.101.112)
signed by the node's Ed25519 key, with the public key carried
in the cert subject CN as Bech32. A reader of just the AOD
cannot tell whether Ed25519 is "the TLS identity" or "the
application-layer identity".

**Resolution**: Change Auth cell to "TLS 1.3 (Ed25519 cert,
RFC 8410) binding to node_id". Reference network-protocol.md
§2.2 inline.

---

## LOW

### AO-17: Author attribution Opus 4.6

**Spec**: Frontmatter: "Author: Russell Wing, Claude (Opus 4.6)".

**Issue**: Current model is Opus 4.7 per today's MEMORY.md
and CLAUDE.md. Several sibling specs are still on 4.6 too, so
a full sweep is appropriate.

**Resolution**: On next material edit, bump to current model
version; add `*Last reviewed: 2026-04-17 (Opus 4.7)*` to the
footer and leave authorship attribution as the original model.

### AO-18: "<5 min" install goal has no SDK reference point yet

**Spec**: §1.3 Quality Goal 1: "Subscribe-publish-listen in 3
API calls". §10.2: "Developer publishes first item | <5 min
from install".

**Issue**: sdk-api-reference.md is the cited source (correctly).
The scenarios are unambiguous; this is a cosmetic LOW.
Suggest adding a cross-ref to the SDK BDD acceptance tests so
the scenario is tied to verifiable output.

**Resolution**: Append "(see sdk-api-reference.md BDD suite)"
to the scenario row.

### AO-19: Footer date stale relative to network-protocol mutations

**Spec**: Footer: `*Last updated: 2026-03-12*`.

**Issue**: network-protocol.md has been revised substantially
since 2026-03-12 (relay forwarding, random promotion, routing
modes, RouteACK, parameter rationale split, pull-sync primacy).
The AOD footer should record the last review pass even if the
body hasn't changed in content.

**Resolution**: Add `*Last reviewed: 2026-04-17 -- see
review-architecture-overview-2026-04-17.md.*` next to the
`*Last updated:*` line. Bump date on fix merge.

---

## Cross-Cutting Observations

1. **Descriptive vs prescriptive.** The AOD was written 2026-03-12
   as a snapshot of the architecture at that date. Since then
   network-protocol.md has become the prescriptive source of
   truth and has moved under it. The AOD reads as descriptive
   history. This is fine provided the front-matter says so;
   currently it implies prescriptive authority.

2. **Path convergence.** The publish flow (AO-01) and the governor
   tick (AO-02) are the two highest-leverage bugs because every
   new reader's model of "how does an item get to a subscriber"
   and "how does a peer become Hot" is set here. Both contradict
   network-protocol.md in ways that would produce wrong code on
   a clean implementation.

3. **L-layer overload.** Three different L0-L3 taxonomies (identity,
   memory, whitepaper cache hierarchy) share one document. The AOD
   is the one place that should call this out; currently it
   silently uses two of the three without disambiguation
   (AO-03, AO-10).

4. **Phase-1 feature completeness.** Epidemic forwarding, seen
   table, routing modes, RouteACK, random-promotion anti-Sybil,
   pull-sync primacy for personal nodes, and the relay
   auto-creation of channel rows are all Phase 1 implemented and
   tested (CLAUDE.md, 479 tests, R=200 scale). None appear in
   the AOD. Any reader forming a mental model from this document
   will build the wrong system.

---

## Suggested Fix Order

1. **AO-01, AO-02** (CRITICAL, path-setting mental model).
2. **AO-05, AO-04** (missing Phase 1 subsystem and protocol count).
3. **AO-03, AO-10** (L1/L2 framing fixes in §8 -- tightly
   coupled).
4. **AO-07, AO-08** (parameter/measure alignment with
   parameter-rationale).
5. **AO-06** (ADR index expansion -- a few lines of work, high
   clarity dividend).
6. **AO-09, AO-13, AO-14, AO-16** (diagram and dependency
   corrections).
7. **AO-11, AO-12, AO-15, AO-17 - AO-19** (polish).

Estimated effort: half a day for the CRITICALs and HIGHs; another
half day to land the MEDIUMs and sweep the diagrams. The AOD
should then match the rest of the spec set and be safe as a
first-read for new implementers.

---

*Review complete: 2026-04-17. Russell Wing + Claude Opus 4.7.*
