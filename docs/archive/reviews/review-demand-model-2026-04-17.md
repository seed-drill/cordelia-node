# Review: demand-model.md

> Fresh review pass (first) applying the review-spec methodology to
> `demand-model.md` v1.0 (created 2026-03-16, 283 lines, unmodified
> since). Last of the "important / operational" batch ahead of Phase 1
> close.

## Application Record

| Field | Value |
|-------|-------|
| Date | 2026-04-17 |
| Reviewer | Russell Wing + Claude Opus 4.7 |
| Spec | demand-model.md v1.0 |
| Passes applied | 1 (Gaps), 2 (Consistency), 3 (Clarity), 4 (Implementability), 5 (Coverage), 6 (Cross-reference integrity) |
| Reference specs | network-protocol.md §4.5, §4.6, §7.2, §8.2; parameter-rationale.md v1.2; memory-model.md; topology-scale.md; CLAUDE.md; scale results R=50/100/200 |

---

## Summary

12 findings. 0 CRITICAL, 3 HIGH, 6 MEDIUM, 3 LOW.

Top issue: **DM-01 Personal-node bandwidth table models a "Push (receive)"
row** that contradicts the post-pivot routing model. Per
network-protocol.md §4.5/§4.6/§7.2/§8.2, personal nodes receive items
exclusively via Item-Sync pull; the relay mesh uses epidemic push
among relays only. The entire §2.4 personal-node row (and the §2.1
"writes_per_channel" fan-out derivation) needs to be recast against
that pivot. This is the same drift flagged in NB-01 -- the demand
model was written before the #9 resolution and never updated.

Second issue: **DM-02 parameter-rationale reconciliation.** The
"derived parameters" table in §3.1/§3.2 restates values that are
authoritatively defined in parameter-rationale.md but with different
(sometimes self-contradictory) derivations -- e.g. writes_per_peer=10
is derived here from a different back-of-envelope than PR §4. With
PR-01 already flagging a rate-limit reconciliation issue, this spec
becomes the third inconsistent source for the same numbers.

The spec's concept (persona-driven parameter derivation) is genuinely
useful and the personas themselves are crisp. The issues are almost
entirely that the math and the routing model frozen into v1.0 pre-date
epidemic forwarding, role-aware gating, and hot_max=2 personal node
consumer-only posture.

---

## HIGH

### DM-01: "Push (receive)" line for personal nodes contradicts pivot

**Spec**: §2.4 table "Per personal node (Casual/Dev Team) with
hot_max=2", rows "Push (receive) | 5 items/min | 2-5KB | 10-25KB/min"
and implicitly "Sync (fetch missing) | 5 items/min | 2-5KB | 10-25KB/min".

**Issue**: network-protocol.md §4.5 states: "Pull-sync is the primary
delivery mechanism for personal nodes and secret keepers. Relays push
items to other relays (§7.2), but personal nodes and keepers receive
items exclusively via pull-sync." §4.6 reinforces: push targets are
"hot relay peers only" and "personal nodes and secret keepers receive
items exclusively via Item-Sync pull". §8.2 classifies personal nodes
as outbound-only, relay-push-targeting.

The demand model's personal-node row therefore has **two inbound
paths** where the current model has **one**: there is no Push
(receive) path for personal nodes in Phase 1. The row inflates
personal-node inbound bandwidth by 10-25KB/min without justification
and gives an implementer the impression that personal-to-personal or
relay-to-personal push exists.

**Resolution**:

1. Delete the "Push (receive)" row from the §2.4 personal-node table.
   Replace with a one-line note: "Personal nodes do not receive
   via push (network-protocol.md §4.5, §8.2)."
2. Update the "Sync (fetch missing)" estimate -- since pull-sync is
   now the sole delivery path, the rate should equal the full
   incoming item rate (not "missing" items). For Dev Team, that's
   5 items/min × 2-5KB = 10-25KB/min as shown, but relabel it as
   "Sync (pull delivery)" not "Sync (fetch missing)".
3. Add a row for the bootnode / peer-share keepalive traffic
   currently lumped into "Keepalive" (NB-05 calls out two different
   keepalive timers; the demand model currently uses neither
   explicitly).

**Cross-ref**: NB-01, NB-03.

### DM-02: Derived-parameter tables restate PR values with different derivations

**Spec**: §3.1 "From Write Rates" and §3.2 "From Bandwidth and Role".

**Issue**: The derivation table values duplicate parameter-rationale.md
§4 and §3 but with different back-of-envelope arithmetic:

| Parameter | PR §4 derivation | Demand model §3 derivation |
|-----------|-----------------|----------------------------|
| `writes_per_peer_per_minute` | "typical AI agent ~1-10/min, 10x headroom" | "Enterprise peak 20/60s + headroom" (value = 10, same) |
| `hot_max` (relay) | "5 relays + 45 personal nodes" | "26MB/min / 500KB per push peer = 52" |
| `max_item_bytes` | "95th pctl ~50KB, 5x headroom" | identical wording, but table entry also adds "5x headroom" at different basis |

These are not contradictions on the numeric value -- they are
**inconsistent derivations for the same value**. review-parameter-rationale
PR-01 already flagged a 3.6x divergence inside parameter-rationale
itself (headroom table vs `writes_per_peer_per_minute`). Adding a
third derivation here makes the divergence harder to reconcile.

An implementer or external reviewer trying to check "is 10 writes
per peer per minute well-founded?" has to hold three different
stories in their head.

**Resolution**: Convert §3 tables to reference-only, not derivation-carrying:

```
| Parameter | Value | Source |
|-----------|-------|--------|
| writes_per_peer_per_minute | 10 | parameter-rationale.md §4 |
| hot_max (personal) | 2 | parameter-rationale.md §3 |
| ... |
```

If the demand model has to justify that the personas fit inside the
shipped limits (a legitimate question), add a short "headroom check"
subsection that compares persona peak rates against the PR values --
without re-deriving them.

**Cross-ref**: PR-01, PR-02 (undefined constants).

### DM-03: Relay bandwidth math omits epidemic forwarding

**Spec**: §2.4 "Per relay (hot_max=50)", row "Re-push (to hot_max=50
peers)".

**Issue**: The §2.4 relay table assumes a single-hop re-push model
(`100 × 50 = 25MB/min`). The current model (network-protocol.md
§7.2, BV-25) is **epidemic forwarding** with a `seen_table` of
SEEN_TABLE_MAX=10,000 entries and SEEN_TABLE_TTL=600s. Under the
epidemic model:

- Each relay forwards each item to **unseen** hot relay peers, not
  all hot peers.
- After a few hops the seen set converges; fan-out per relay drops
  below `hot_max`.
- The amplification bound is O(N log N) total messages across the
  mesh, not `items × hot_max` per relay (network-protocol.md §7.2).

The demand model's 26MB/min worst-case is still useful as an upper
bound for provisioning, but the spec does not distinguish "worst-case
bound" from "expected steady state" -- which matters because
hot_max=50 was derived (in §3.2) from this worst case.

Additionally, the 100 items/min number in the "Receive" row lumps all
personal nodes -- but those are 100 items received from personal-node
originators, while the epidemic mesh ALSO delivers items pushed from
**other relays**. The table does not account for the relay-to-relay
leg at all.

**Resolution**:

1. Split the relay table into "originator-push inbound" (from personal
   nodes) and "mesh-forward inbound" (from other relays). The latter
   is bounded by content_hash dedup but non-zero.
2. Annotate the "Re-push" row as "worst case, pre-dedup". Add a note:
   "At steady state, seen_table dedup reduces fan-out by ~50-80%
   in sparse meshes; see network-protocol.md §7.2 for the asymptotic
   O(N log N) bound."
3. Reconcile §3.2 `hot_max` relay derivation with the asymptotic
   bound. Keep 50 as the defensive upper-bound; note that the
   expected steady-state load is lower.

**Cross-ref**: NB-02 (same epidemic drift in network-behaviour.md),
parameter-rationale §3 `hot_max = 50 (relay)`.

---

## MEDIUM

### DM-04: Agent Swarm persona's "personal node" hot_max assumption

**Spec**: §2.1 "the Enterprise peak 20/60s = 0.33/s. Round up with
headroom: 10 writes/peer/min handles all personal node personas.
The Agent Swarm operates in a data centre where rate limits can be
tuned higher."

**Issue**: The Agent Swarm persona (§1.4) does 1-10 items/min/agent
× 10-100 agents = up to 1000 items/min. The spec hand-waves this
as "tuned higher" without specifying how. parameter-rationale.md
§4 writes_per_peer_per_minute is a **protocol constant**, not a
user-tunable. If the Agent Swarm cannot meet its specified throughput
under shipped defaults, the demand model either needs a "Phase 2
deferred" tag on the Agent Swarm persona OR a concrete multi-agent
topology that aggregates many agents behind one Cordelia node.

**Resolution**: Add a subsection "Agent Swarm deployment model":
"A single Cordelia node fronts N agents; its inbound writes come
from local IPC/HTTP, not from P2P peers, so writes_per_peer_per_minute
does not apply. The node's push rate to its hot relays is still
bounded by the limit, which caps aggregate swarm throughput at
~10 items/min per originating node. Multi-originator swarms distribute
across N nodes."

Tag the Agent Swarm persona as "Phase 2+" if the Phase 1 rate limit
doesn't serve it.

### DM-05: Storage projections ignore relay epidemic replication

**Spec**: §2.3 "Relay storage: A relay stores ALL items for channels
it carries. With 100 users at Enterprise rate... a relay storing all
channels accumulates ~300MB/day = ~100GB/year."

**Issue**: Under epidemic forwarding (§7.2), every relay that
receives an item from any hot peer stores it -- not just relays
"carrying" specific channels. There is no channel-aware routing at
the relay layer (channel-announce is informational, not routing,
per network-protocol.md §4.4). The "storing all channels" phrase is
correct but the table still under-counts: each relay sees items
from the whole mesh, bounded by its hot set, not by the channels
it nominally "carries".

Also: storage projections assume **no retention / eviction policy**.
Phase 1 has no item TTL or LRU policy specified in this spec.
A 100GB/year growth projection without any pruning strategy is an
operational hazard.

**Resolution**:

1. Rewrite "Relay storage" paragraph: "A relay stores every item
   pushed to it by any hot peer, regardless of channel (§7.2). For
   an Enterprise deployment of 50 users at 300 items/day/user × 10KB,
   each relay accumulates ~150MB/day per origin that reaches it.
   With mesh replication, this dominates over origin-rate when
   hot_max < N."
2. Add a note that Phase 1 has no item-level TTL. Refer retention
   to operations.md (or file as a gap: there is no retention spec
   yet).
3. Either delete the "1-year storage" column or footnote it with
   "assumes no pruning -- Phase 1 has no retention policy
   (see operations.md, Phase 2 topic)."

**Cross-ref**: parameter-rationale PR-04 (SEEN_TABLE_MAX/TTL missing).

### DM-06: Headroom claims conflict with parameter-rationale §4.1

**Spec**: §2.1 "10 writes/peer/min handles all personal node personas."
and §3.1 table "Handles all personal personas with 3-5x margin"

**Issue**: parameter-rationale.md §4 "3x Headroom Principle" states
that all per-peer rate limits are 3x the expected legitimate rate.
The "Writes" row shows `12/min × 3 = 36/min`, not 10/min. As noted
in review-parameter-rationale PR-01, there is already an unreconciled
3.6x divergence between the headroom table (36/min) and the shipped
`writes_per_peer_per_minute = 10`.

The demand model adds a fourth position: "Enterprise peak 20/60s =
0.33/s, round up to 10/min = 30x headroom". That is neither the 3x
from PR §4 headroom nor the 10x from PR `writes_per_peer_per_minute`.

An external reviewer reading the two specs together cannot tell
which headroom multiplier is canonical.

**Resolution**: Resolve PR-01 first, then align this spec to the
canonical headroom story. If the canonical answer is "3x headroom
over a 12/min expected rate = 36/min limit", the demand model
should show: Enterprise peak 0.33/s (20/min) fits inside 36/min
with 1.8x margin.

**Cross-ref**: PR-01.

### DM-07: Sync bandwidth derivation uses wrong multiplier

**Spec**: §2.2 "Sync rate derivation: At sync_interval=10s with 5 hot
peers and 5 channels, that's 5 × 5 = 25 sync requests per 10s =
150/min."

**Issue**: Personal nodes have hot_max=2, not 5 (the 5 number was
the pre-pivot value, superseded 2026-03). network-protocol.md §4.5
("all hot peers each cycle") × hot_max=2 × 5 channels = 10 sync
requests per 10s = 60/min, not 150/min. Also: relay nodes sync using
batched per-peer streams (one stream per peer covering all channels,
§4.5 Phase 0 relay channel discovery), so "5 channels" multiplier
does not apply for relays.

**Resolution**:

1. Replace "5 hot peers" with "hot_max=2 (personal) / hot_max=50
   (relay)" and recompute.
2. Note the batched-sync optimisation for relays (BV-24 resolution,
   network-protocol.md §4.5 Phase 0).
3. Fix the totals row: personal node sync bandwidth is ~24KB/min
   (60 requests × 400B), not 150KB/min.

### DM-08: Bootstrap_timeout derivation cites wrong parameter

**Spec**: §3.3 "bootstrap_timeout | LAN handshake ~1ms, WAN ~500ms |
10s | 20x margin for slow networks".

**Issue**: parameter-rationale.md §1 names the shipped parameter
`incoming_handshake_timeout = 10s`, not `bootstrap_timeout`.
connection-lifecycle.md §4 enumerates "bootnode resolution timeout"
and "incoming handshake timeout" as separate concerns. The demand
model collapses them into one parameter that does not exist under
either name.

**Resolution**: Replace "bootstrap_timeout" with
"incoming_handshake_timeout" (per PR §1). Add a separate row for
bootnode DNS resolution if needed. Cross-reference PR §1.

**Cross-ref**: PR doesn't define bootstrap_timeout either -- already
flagged in PR-04.

### DM-09: Sybil-cost math refers to hot_max=5 throughout §3.4

**Spec**: §3.4 "Attacker goal: fill a personal node's hot set (5
peers)" and "Governor promotes 1 random warm peer per tick when
hot < hot_max", "attacker connects 10 identities. 2 get immediate
Hot (hot_min bypass). Remaining 8 enter Warm."

**Issue**: The entire derivation assumes hot_max=5 and hot_min=5
(or close to it). Personal nodes ship with hot_max=2, hot_min=2
(parameter-rationale.md §3, network-protocol.md §16.1 Personal
governor profile). An attacker targeting a personal node needs to
fill **2** slots, not 5. The cost math therefore understates the
defensive property: with hot_max=2 and hot_min=2, both initial
slots are filled immediately by the first two connecting peers.
There is no "remaining 8 enter Warm" step -- the attacker's first
2 Sybil identities can immediately occupy the entire hot set under
hot_min bypass, before any legitimate relay connects.

This is actually **worse than the spec claims**: eclipse is
achievable at startup with 2 IPs and 2 identities, not the
10-minute / 2-IP cost the spec derives. parameter-rationale.md §3
already hints at this ("2 Hot peers means more potential for eclipse
if min_warm_tenure is bypassed").

**Resolution**: Rewrite §3.4:
- Target: 2-peer hot set, not 5.
- Startup eclipse is 2 simultaneous connections from attacker IPs
  before bootnode resolution completes. Defence is bootnode-first
  dialling, not min_warm_tenure.
- Post-bootstrap eclipse requires surviving min_warm_tenure for
  rotations only. This is the 300s × hot_max cost model.
- Refer to attack-trees.md for the full cost analysis; do not
  re-derive here with stale numbers.

**Cross-ref**: attack-trees.md, parameter-rationale PR-03
(hot_min_relays undefined -- also relevant to this defence story).

---

## LOW

### DM-10: "Phase 1 excludes images/media" repeated across three specs

**Spec**: §2.3 and §3.1.

**Issue**: Identical claim appears in parameter-rationale.md §4
`max_item_bytes`, configuration.md §13, demand-model.md §2.3, and
ecies-envelope-encryption.md §5.1 note. Four copies drift if one
changes.

**Resolution**: Cite once in parameter-rationale.md as authoritative;
link from other specs.

### DM-11: "Channels: 2-5" etc. not cross-referenced to CLAUDE.md channel caps

**Spec**: §1.1, §1.2, §1.3 channel counts.

**Issue**: Personas list channel counts (2-5 casual, 5-15 dev team,
20-100 enterprise, 10-50 swarm). parameter-rationale.md does not
document a per-node channel cap (there is none in Phase 1), but
topology-scale.md §3 uses specific per-node channel counts in its
scale scenarios. The two don't cross-reference.

**Resolution**: Either add a one-line cross-ref in §1 personas
("these channel counts inform the topology-scale.md scenarios at
§3") or drop the exact numbers in favour of "small (<10) / medium
(10-50) / large (50+)".

### DM-12: Version footer and spec-drift flag missing

**Spec**: Footer "Spec version: 1.0 | Created: 2026-03-16".

**Issue**: Not updated despite the routing model pivot (2026-03-20)
and the hot_max=5 -> hot_max=2 personal change (pre-pivot vs
post-pivot). Same pattern as NB-13. The version footer should flag
that this spec lags behind network-protocol.md.

**Resolution**: On next edit, bump to v1.1 with a changelog line
"Updated for post-#9 routing: pull-sync-only personal nodes, epidemic
relay forwarding, hot_max=2". Add "Authoritative reference:
network-protocol.md v<n>".

---

## Passes Not Applied (this session)

| Pass | Reason |
|------|--------|
| 3 (Security) -- as primary frame | Pass 4 and 5 caught the Sybil-math drift (DM-09); no novel security surface in a demand/sizing doc beyond what attack-trees.md covers |
| 6 (Attack Trees) | Fully covered by attack-trees.md and review-attack-trees-2026-04-17.md |
| 7 (Terminology) | Already consolidated via glossary.md v1.0 |
| 9 (Test Vectors) | No deterministic transforms in a demand/sizing doc |
| 10 (Privacy) | Covered by review-privacy.md; no new metadata surface here |
| 11 (Operational) | Retention/pruning gap noted in DM-05, otherwise scope is operations.md |
| 12 (Error Catalog) | Covered by review-errors.md |
| 13 (Compliance) | Out of scope for a sizing doc |
| 14 (Data Model) | Out of scope -- no schema proposals |
| 15 (Build Verification) | Phase 1 closed; this spec is sizing commentary, not protocol definition |

---

## Recommended Triage

**Fix before Phase 1 close (correctness / external-reviewer risk):**
- DM-01 (personal-node push-receive row -- same drift as NB-01;
  fixing both in one session is efficient)
- DM-02 (reconcile the three derivations for `writes_per_peer_per_minute`
  with PR-01 in the same pass)
- DM-03 (epidemic vs single-hop relay math -- blocks honest
  provisioning advice)

**Fix during next spec editing session:**
- DM-04 (Agent Swarm topology clarification -- otherwise persona
  is underspecified)
- DM-05 (relay storage under epidemic forwarding + retention gap)
- DM-06 (headroom reconciliation -- once PR-01 resolves)
- DM-07 (sync bandwidth with hot_max=2, batched-sync credit)
- DM-08 (bootstrap_timeout naming)
- DM-09 (Sybil math against hot_max=2, not 5)

**Defer / close:**
- DM-10 (media-exclusion note repetition -- cosmetic)
- DM-11 (channel count cross-ref -- minor)
- DM-12 (version footer -- tidy on next touch; same recommendation
  as NB-13 for all frozen-in-March specs)

---

## Pattern Note

This is the third spec in the 2026-04-17 review sprint
(topology-e2e, network-behaviour, demand-model) where the same
pre-pivot routing assumptions (personal-to-personal push, single-hop
re-push, hot_max=5 personal) survived into frozen v1.0 text. A
single coordinated editing pass updating all three against
network-protocol.md §4.5/§4.6/§7.2 post-pivot text would close
NB-01, NB-02, DM-01, DM-03 together. Individual fix passes will
keep rediscovering the same drift.

---

*Review complete 2026-04-17.*
