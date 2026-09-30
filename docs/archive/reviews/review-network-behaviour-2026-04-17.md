# Review: network-behaviour.md

> Fresh review pass (first) applying review-spec methodology to
> `network-behaviour.md` v1.0 (374 lines, created 2026-03-16,
> unmodified since).

## Application Record

| Field | Value |
|-------|-------|
| Date | 2026-04-17 |
| Reviewer | Russell Wing + Claude Opus 4.7 |
| Spec | network-behaviour.md v1.0 |
| Passes applied | 1 (Gaps), 2 (Consistency), 3 (Clarity), 4 (Implementability), 5 (Coverage), 6 (Cross-reference integrity) |
| Reference specs | network-protocol.md, parameter-rationale.md v1.2, data-formats.md, connection-lifecycle.md, glossary.md, CLAUDE.md |

---

## Summary

13 findings. 0 CRITICAL, 3 HIGH, 6 MEDIUM, 4 LOW.

The spec is mostly accurate against the authoritative references but
shows the classic symptoms of a doc that was frozen early and not
kept in lockstep with the protocol spec: two sections still talk
about single-hop relay re-push while network-protocol.md §7.2 is
explicitly epidemic; the failure matrix claims "items flow peer-to-peer
between personal nodes" which contradicts the §8.2 / §4.6 rule that
personal nodes only push to relays; and several parameter values
quoted here (idle timeout, personal hot_max, inbound connections) are
right but would silently drift if the authoritative spec changed.

The top issue is the **pull-sync-only story for personal nodes**
(NB-01) -- the end-to-end publish trace and the "All relays dead"
failure row both imply direct personal->personal push, which the
Phase 1 model explicitly rejects. That is a correctness bug in the
spec that would confuse an implementer.

Second is the **single-hop re-push description** in §1.1 step 8
(NB-02): it pre-dates the epidemic-forwarding resolution of
cordelia-node#9 and does not mention the seen table at all.

---

## HIGH

### NB-01: Personal nodes do not receive via push in Phase 1

**Spec**: §1.1 steps 8-9 ("R1 relay re-push" -> "P2 receives Item-Push"),
§4.1 row "All relays dead" ("Items flow peer-to-peer only (direct
push between personal nodes that share channels)"), §5.1 "Publish-to-receive
(push path)".

**Issue**: The end-to-end lifecycle depicts a relay pushing the
item to P2 (a personal node) via Item-Push, and P2 serving it via
`/listen`. But network-protocol.md §4.6 ("When Item-Push fires")
and §7.2 ("Push targets: relay peers only") explicitly state that
personal nodes receive items **exclusively** via Item-Sync pull --
relays forward only to other relays. §8.2 reinforces this:
"Receives items from peers exclusively via Item-Sync pull".

Similarly, the "All relays dead" failure row promises "direct push
between personal nodes that share channels", but personal nodes
never push to other personal nodes (originator push is to hot
relay peers only, §4.6 and §8.2).

An implementer reading this spec in isolation would build a
relay-to-personal Item-Push path and re-introduce the routing
state that §7.2 was written to eliminate.

**Resolution**:

1. Rewrite §1.1 steps 8-10 to show the relay storing the item and
   re-pushing it **to other relays** (epidemic forwarding via
   seen table), then P2 pulling it via Item-Sync on its next
   10s cycle.

2. Replace the "push path" latency budget in §5.1 with two rows:
   - "Publish-to-relay-mesh (push path)": 2-4 RTT
   - "Relay-mesh-to-personal (pull-sync)": up to sync_interval + 1 RTT

3. Correct §4.1 "All relays dead" to: "All push breaks. Personal
   nodes that share a channel AND have each other as hot peers can
   still receive via pull-sync (since they maintain outbound-only
   connections to relays, not to each other, pull-sync also breaks).
   Network is effectively down until a relay recovers."

**Cross-ref**: NB-02 (epidemic forwarding), NB-03 (outbound-only
personal topology).

---

### NB-02: Single-hop re-push language contradicts epidemic model

**Spec**: §1.1 step 8 ("R1 relay re-push ... For each hot peer: Skip P1,
skip bootnodes, Open stream, Write PushPayload"), §1.2 row "8".

**Issue**: The lifecycle describes classic single-hop re-push with
`exclude_peer = P1`. The current model (network-protocol.md §7.2,
resolved 2026-03-20, cordelia-node#9) is **epidemic forwarding**
keyed on `content_hash` via a `seen_table` bounded by
`SEEN_TABLE_MAX=10,000` entries with `SEEN_TABLE_TTL=600s`. Items
received from other relays ARE forwarded (with dedup), not dropped
as they were in the single-hop model.

The spec does not reference the seen table at all, which is
the single most important concept for understanding relay
forwarding correctness.

**Resolution**: Rewrite step 8 as:

```
8. R1 relay re-push (epidemic, §7.2)
   - stored > 0, so compute forward_targets
   - forward_targets = hot_relay_peers - seen_table[content_hash].peers
   - For each target: open stream, write PushPayload, add to seen set
   - seen_table evicts after SEEN_TABLE_TTL (600s) or LRU at SEEN_TABLE_MAX (10,000)
```

Add a note that `exclude_peer` semantics are superseded by the
content-hash-keyed seen table. Cross-reference network-protocol.md
§7.2 explicitly.

**Cross-ref**: NB-01.

---

### NB-03: Convergence numbers in §5.1 inconsistent with pull-sync spec

**Spec**: §1.1 "Latency budget (pull-sync fallback)", §5.1 table
("Publish-to-receive (sync fallback): <= sync_interval_realtime_secs
(default: 10s, production recommendation: 60s)").

**Issue**: §1.1 calls pull-sync a "fallback" from push. After the
routing pivot (§7.2, §8.2) pull-sync is the **primary** delivery
mechanism for personal nodes -- not a fallback. Calling it a
fallback is both factually wrong and gives an implementer the
impression that a direct push path exists (re-introducing the
bug in NB-01).

Additionally, the production recommendation of `sync_interval=60s`
is quoted here but parameter-rationale.md does not document it as
a parameter, and network-protocol.md §4.5 shows 10s for realtime.
The 60s value appears only as a configuration comment in
§12.2. An implementer cannot tell which is authoritative.

**Resolution**:

1. Rename the row "Publish-to-receive (sync fallback)" to
   "Publish-to-receive (pull-sync, primary for personal nodes)"
   and drop the "fallback" framing.

2. Pick one authoritative statement for the realtime sync interval
   and cite it once (suggestion: "10s default, configurable; see
   network-protocol.md §12.2 for production guidance"). Stop
   mentioning "60s production recommendation" in three different
   specs without reconciling it.

3. Add a sentence to §1.1 clarifying that push is the relay-mesh
   distribution mechanism and pull-sync is the edge delivery
   mechanism -- they are both primary, not primary/fallback.

**Cross-ref**: NB-01, NB-07.

---

## MEDIUM

### NB-04: §2.1 table "All peers lost" row conflates peer-level and global states

**Spec**: §2.1 Connection Errors, row "All peers lost".

**Issue**: The row describes recovery as "Exponential backoff
(base 30s, cap 900s). After 5 consecutive failures per peer, stop
retrying until backoff expires. Clear failure count after 120s of
stable Hot connection." These are the per-peer retry parameters
from network-protocol.md §5.4 step 3 (`max_connection_retries=5`,
`clear_failure_delay_secs=120`, base 30s, cap 900s), but the row
is labelled "All peers lost" which is a global state.

This conflates two distinct behaviours:
- **Per-peer**: exponential backoff with 5-strike failure counter
- **Global "all peers lost"**: node waits for inbound connections
  or bootnode reconnection

An implementer can't tell whether "5 consecutive failures" counts
per-peer failures or total failed attempts across the peer table.

**Resolution**: Split into two rows:

```
| Single peer fails repeatedly | mark_dial_failed | Exponential backoff per peer (base 30s, cap 900s). After max_connection_retries=5 consecutive failures, stop trying this peer until backoff expires. Clear count after clear_failure_delay_secs=120s of stable Hot connection. |
| All peers lost (hot_count=0 AND warm_count=0) | Governor counts | Node keeps retrying cold peers and bootnodes at each tick. No push delivery until a peer is regained. |
```

### NB-05: §2.1 "Network partition" row uses two different timeouts as equivalent

**Spec**: §2.1, row "Network partition" ("Keepalive stops. QUIC
idle timeout (60s) fires.").

**Issue**: "Keepalive stops" references the application-level
Keep-Alive (ping_interval=30s, keepalive_timeout=90s) but the
recovery column jumps to "QUIC idle timeout (60s)". These are
different layers (parameter-rationale.md §1 vs §2) with different
purposes:

- QUIC `max_idle_timeout=60s` closes the transport connection
- Application `keepalive_timeout=90s` demotes the peer in the governor

When both fire, the effective detection time for "network partition"
is actually `min(60s, 90s) = 60s` for transport closure but `90s`
for governor demotion. The row collapses them inconsistently.

**Resolution**: Clarify which timeout drives each effect. Suggested:

"QUIC transport closes after `max_idle_timeout` (60s). Governor
demotes Hot->Warm after `keepalive_timeout` (90s). The two layers
are independent; connection closure races with governor detection."

Also add a reference to §3.5 which already documents the 90s
demotion path.

### NB-06: Hot->Warm demotion step 3 describes behaviour not present in spec table

**Spec**: §3.4 Hot->Warm, step 3: "handle_peer_streams continues
accepting Keep-Alive and Peer-Sharing streams from this peer, but
REJECTS data protocol streams (0x04-0x07)".

**Issue**: This is the Phase 1 behaviour for **personal nodes**,
but network-protocol.md §5.4.2 (protocol-per-state table) plus
§7.2 "Relay inbound gating" show that **relays** accept data
protocols (Item-Push, Item-Sync, Channel-Announce) on Warm peers
as well. The behaviour described here only applies to personal
and keeper nodes.

An implementer following §3.4 verbatim would build a relay that
rejects pushes from Warm peers, re-introducing the asymmetric-hot-set
partition that §5.4.2 / §7.2 explicitly resolved.

**Resolution**: Update §3.4 step 3 to:

```
3. handle_peer_streams data-protocol gating (role-dependent):
   - Personal and keeper nodes: REJECT data protocols (0x04-0x07)
     from this peer until re-promoted to Hot.
   - Relays: CONTINUE accepting data protocols (0x04-0x06) from
     Warm peers -- see network-protocol.md §5.4.2 relay inbound
     gating and §7.2 asymmetric hot sets. PSK-Exchange (0x07)
     remains Hot-only for all roles.
```

### NB-07: Pull-sync convergence numbers don't match network-protocol.md

**Spec**: §5.1 table row "Convergence after partition ... ~85s
(bootstrap), ~390s (steady)".

**Issue**: These match network-protocol.md §4.5 (T_bootstrap=85s,
T_steady=390s). Good. But the table also claims "Convergence at
scale (100 nodes): 80/90 in ~60s, 89/90 in ~3 min" which are
empirical session-92 results, and "Publish-to-receive (sync
fallback): ~10-20s at 100 nodes" -- contradicted by the actual
scale results (CLAUDE.md: "R=100 302/302 in 17s, R=200 relays
200/200 converge").

The scale numbers quoted here are now stale vs the 2026-03-20
scale results in MEMORY.md.

**Resolution**: Either drop the quantitative scale numbers (they
rot quickly) or link to a test-results log with a date. Don't
embed test artefacts in a design spec without a data source.

### NB-08: §6.3 status endpoint JSON differs from debug-telemetry.md

**Spec**: §6.3 Health Dashboard Metrics.

**Issue**: The JSON example omits `sync_errors`, `streams_opened`,
and `streams_active` which debug-telemetry.md §6 lists as MUST-include.
The two specs should show the same minimum field set.

Fields in network-behaviour.md §6.3: peers_hot, peers_warm,
items_stored, items_pushed, items_received, push_timeouts,
sync_timeouts, uptime_secs (8 fields).

Fields in debug-telemetry.md §6: peers_hot, peers_warm,
sync_errors, items_stored, items_pushed, items_received,
streams_opened, streams_active, push_timeouts, sync_timeouts,
uptime_secs (11 fields).

**Resolution**: Align the two. Suggest making debug-telemetry.md
the authoritative schema and replacing the §6.3 block here with
a one-line reference: "See debug-telemetry.md §6 for the complete
field list."

### NB-09: No specification of the publish -> push_tx queue bound

**Spec**: §1.2 row 5 ("push_tx channel full | Backpressure (bounded
channel) | Item stored locally, delivered via sync").

**Issue**: The spec says the push queue is bounded but does not
specify the bound. network-protocol.md §9.4 specifies per-protocol
inbound queue capacities (Handshake=16, KeepAlive=256, PeerSharing=32,
ChannelAnnounce=64, ItemSync=64, ItemPush=128) but those are
receiver-side queues. The **sender-side** push_tx queue (publisher
-> P2P loop) has no documented bound.

An implementer has to guess. A small bound (e.g., 16) causes
backpressure on API publish; a large bound (e.g., 10000) wastes
memory during peer outages.

**Resolution**: Add the bound to parameter-rationale.md (new entry,
e.g., `push_queue_capacity = 1024`) and reference it here. Or at
minimum state the bound inline in §1.2: "push_tx channel full
(default capacity: N) | Backpressure | ...".

---

## LOW

### NB-10: Reference-style inconsistency (§, ss, §ref)

**Spec**: Whole document. Examples: "ss1.2" (line 153, §3.1),
"ss4" (line 340, §6.2), `§3.5` (line 211), "§3.1" (line 171).

**Issue**: The spec mixes three reference styles: `ss<n>` (clearly
rendered from original `§<n>` by some Markdown pipeline that
stripped Unicode section marks), `§<n>.<n>`, and plain numeric
refs. Cross-reference grepability is impaired.

**Resolution**: Normalise to `§<n>` or `§<n>.<n>` throughout.
Note: the authoritative upstream refs in other specs use
`§<n>.<n>` consistently.

### NB-11: §5.2 bandwidth formula drops units

**Spec**: §5.2 Throughput, rows "Bandwidth (push)" and
"Bandwidth (sync)".

**Issue**: "items × hot_max × item_size" has no time dimension --
an implementer cannot interpret this as bandwidth without a rate.
The formula is for per-publish bandwidth, not ongoing.

**Resolution**: Add units. Suggest: "bytes per publish = items_batch
× hot_max × item_size". For sustained bandwidth, multiply by
publish rate.

### NB-12: §4.3 "Security Failures" row references §16.1.2 undefined

**Spec**: §4.3 row "Relay defection (relay drops items)":
"contribution_ratio < 1.0 over time. Probe items detect selective
dropping."

**Issue**: `contribution_ratio` is defined in network-protocol.md
§5.5 (formula) and §16.1.2 (economic model), but network-behaviour.md
neither defines it nor links to either section. A reader does not
know whether a ratio of 0.5 or 0.3 triggers demotion.

**Resolution**: Inline the trigger threshold (network-protocol.md
§16.1.2 Scoring Weights gives "contribution_ratio < 0.3 for 10+ min
=> demote Hot -> Warm") and cross-ref explicitly.

### NB-13: Version footer not updated since creation

**Spec**: Footer ("Spec version: 1.0, Created: 2026-03-16").

**Issue**: The spec has not been revised despite (a) network-protocol.md
§7.2 being heavily revised in session 92-106 for epidemic forwarding
and (b) role-aware protocol gating being added for relays. The
version footer does not flag that this spec lags behind its
authoritative reference.

**Resolution**: On the next edit, bump to v1.1 and add
"Updated: YYYY-MM-DD" with a short changelog line. Consider adding
"Authoritative reference: network-protocol.md v<n>" with the
dependent version so drift is visible.

---

## Passes Not Applied (this session)

| Pass | Reason |
|------|--------|
| Security (3) | Covered by attack-trees.md + review-attack-trees-2026-04-17.md; this spec is behavioural, not a trust/threat surface |
| Economic / Attack-tree (5, 6) | Not applicable -- no incentive mechanisms here |
| Test vectors (9) | No deterministic transforms to vector |
| Privacy (10) | Metadata surface is covered in review-privacy.md; §6 observability does not introduce new surface |
| Terminology (7) | Already consolidated via glossary.md v1.0 |
| Error catalog (12) | Covered by review-errors.md -- network-behaviour.md's error columns mirror that structure |
| Build verification (15) | Spec predates latest implementation; Phase 1 already closed. BV findings would overlap with existing BV-19..25 |

---

## Recommended Triage

**Fix before Phase 1 close (blockers for external reviewers):**
- NB-01 (personal push path -- correctness bug)
- NB-02 (epidemic vs single-hop -- correctness bug)
- NB-06 (relay warm acceptance missing -- correctness bug)

These three together would cause a fresh implementer to rebuild the
exact bug that cordelia-node#9 resolved. They are the highest ROI
to fix.

**Fix during next spec editing session:**
- NB-03 (pull-sync primary vs fallback language)
- NB-04 (retry vs all-peers-lost row split)
- NB-05 (dual-timeout clarity)
- NB-08 (status endpoint alignment)

**Schedule as doc debt:**
- NB-07 (scale numbers, likely just remove)
- NB-09 (push_tx queue bound -- add to parameter-rationale.md in same pass as PR-04)

**Defer / close:**
- NB-10 (reference style -- cosmetic)
- NB-11 (units -- cosmetic)
- NB-12 (contribution_ratio cross-ref -- minor)
- NB-13 (version footer -- tidy on next touch)

---

*Review complete 2026-04-17.*
