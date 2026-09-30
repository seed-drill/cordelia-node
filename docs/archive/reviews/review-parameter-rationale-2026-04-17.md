# Review: parameter-rationale.md

> Fresh review pass (first) applying review-spec methodology to
> `parameter-rationale.md` v1.2 (updated 2026-03-18, 397 lines).

## Application Record

| Field | Value |
|-------|-------|
| Date | 2026-04-17 |
| Reviewer | Russell Wing + Claude Opus 4.7 |
| Spec | parameter-rationale.md v1.2 |
| Passes applied | 1 (Gaps), 2 (Consistency), 3 (Clarity), 5 (Coverage) |

---

## Summary

5 findings. 1 HIGH (rate-limit parameter reconciliation), 3 MEDIUM
(undefined references, missing parameters), 1 LOW (cross-ref gap).

The spec is well-written and follows the "no magic numbers" principle
faithfully. The issues are primarily about parameters referenced but
not defined, and an inconsistency between two different ways of
expressing write rate limits.

---

## HIGH

### PR-01: Rate-limit parameter reconciliation

**Spec**: §4 "3x Headroom Principle" table vs §4 `writes_per_peer_per_minute` vs `writes_per_channel_per_minute`

**Issue**: Three overlapping parameters describe write rate limits with
different values and unclear scopes:

| Parameter | Value | Scope (inferred) |
|-----------|-------|------------------|
| Headroom table: "Writes" | 36/min | Derivation-by-headroom, no scope |
| `writes_per_peer_per_minute` | 10 | Per-peer |
| `writes_per_channel_per_minute` | 100 | Per-channel |

The headroom table's 36/min appears to bound per-peer writes but
`writes_per_peer_per_minute` is 10 -- a 3.6x divergence. An implementor
cannot tell which limit is authoritative or whether they apply to
different enforcement points.

**Resolution**: State explicitly which parameter is enforced where.
Suggested clarification:
- Headroom table values are *derived targets* showing how the 3x
  principle applies to each protocol. They are not independent
  enforcement constants.
- `writes_per_peer_per_minute = 10` is the authoritative per-peer cap.
- `writes_per_channel_per_minute = 100` is the authoritative per-channel cap.

Either delete the headroom table's specific numbers or annotate them
as "derivation targets, not enforced constants."

---

## MEDIUM

### PR-02: Undefined constants referenced in §4 headroom table

**Spec**: §4 "3x Headroom Principle"

**Issue**: The derivation column references four constants that are
never defined in this document:
- `REPUSH_INTERVAL` (used as "60/REPUSH_INTERVAL = 12/min", implies REPUSH_INTERVAL = 5s)
- `RATE_WINDOW` (used as "RATE_WINDOW/TICK", implies some ratio)
- `TICK` (implied = 10s based on arithmetic: 60/10 = 6/min)
- `PING` (implied = 30s based on arithmetic: 60/30 = 2/min)

An implementor cannot verify the derivations without chasing these
values to their definitions (`network-protocol.md` has some, but not
all -- `REPUSH_INTERVAL` is a cordelia-node code constant).

**Resolution**: Either inline the constant values in the table (e.g.,
"60s / 5s = 12/min") or add a glossary entry at the top of §4:

```
Referenced intervals:
- REPUSH_INTERVAL = 5s (code constant; epidemic relay forwarding flush)
- TICK = 10s (governor tick, sync_interval realtime)
- PING = 30s (application keepalive ping_interval, §2)
- RATE_WINDOW = 60s (rate limit window)
```

### PR-03: Governor parameters referenced but not defined

**Spec**: §3 Governor Parameters

**Issue**: Two parameters are used in derivations but never have their
own entry:

- `warm_max` -- used in `churn_fraction` derivation ("20% with warm_max=10 = 2 peers swapped per hour"). Never defined here.
- `hot_min_relays` -- used in `hot_max` derivation ("1 relay (hot_min_relays=1) + 1 redundancy peer"). Never defined here.

**Resolution**: Add entries for both with rationale and scope
(personal vs relay).

### PR-04: Missing operationally-critical parameters

**Spec**: Whole document

**Issue**: Several Phase 1 parameters documented elsewhere (or only in
code) have no entry in this spec despite it claiming to document
"every configurable parameter":

| Parameter | Value | Referenced in |
|-----------|-------|---------------|
| `SEEN_TABLE_MAX` | 10000 | cordelia-network seen_table module; CLAUDE.md |
| `SEEN_TABLE_TTL_SECS` | 600 | cordelia-network seen_table module |
| `sync_interval` (realtime) | 10s | network-protocol.md §4.5 table |
| `sync_interval` (batch) | 900s | network-protocol.md §4.5 table |
| Ban escalation (2x, 4x, 8x, 24h cap) | -- | network-protocol.md §5.6 |
| PSK rotation queue depth | 1000 items, 10 min | review-implementability I-06 resolution |
| `warm_max` | implied 10 (personal), ? (relay) | §3 derivation |
| `hot_min_relays` | implied 1 | §3 derivation |
| `protocol_magic` | `0xC0DE11A1` | network-protocol.md §4.1 |
| Handshake version | 1 | network-protocol.md §4.1.4 |

Epidemic forwarding parameters (forward-to-all-hot-relays,
content-hash dedup) are described in network-protocol.md §7.2 without
corresponding numeric rationale here. At minimum, the relay mesh
convergence properties derived from `hot_max=20` (network converges
in one 5s repush cycle at R=200) deserve a rationale entry.

**Resolution**: Add a new section (§8 Replication Parameters or §9
Channel Parameters) covering seen-table, sync intervals, and the
epidemic forwarding convergence model.

---

## LOW

### PR-05: Cross-reference doesn't list all callers

**Spec**: Footer line 397

**Issue**: Cross-refs listed as "network-protocol.md §9, §12;
network-behaviour.md §2.2, §5". Does not mention: data-formats.md
(item size limits), connection-lifecycle.md (handshake timeout),
debug-telemetry.md (stream timeout history), review-build-verification.md
(BV-23 reference in §6).

**Resolution**: Either broaden the cross-ref list or drop it entirely
in favour of letting readers search. Suggest dropping -- the parameters
themselves reference their use sites, and cross-ref lists rot.

---

## Passes Not Applied (this session)

| Pass | Reason |
|------|--------|
| 4 (Implementability) | Already covered implicitly by "If you change to X" analyses on every parameter -- the spec is self-documenting on implementation choices |
| 6 (Privacy) | Not applicable -- no metadata surface in parameter docs |
| 7 (Terminology) | Already covered by glossary.md for overlapping terms |
| 8+ | Out of scope for a parameters doc |

---

## Recommended Triage

**Fix before Phase 1 close:** PR-01, PR-02, PR-03 -- ambiguity that
would force a future implementor (or Martin's spec audit) to
cross-reference multiple files.

**Schedule as doc debt:** PR-04 -- adds missing entries. Meaningful
uplift but not blocking. Can be handled in a single editing session
when next touching the file.

**Defer / close:** PR-05 -- recommend dropping cross-ref list
entirely.

---

*Review complete 2026-04-17.*
