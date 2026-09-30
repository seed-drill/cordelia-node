# Review Sprint Summary -- 2026-04-17

> Consolidation of the fresh-review sprint that covered the 14 Phase 1
> specs not previously reviewed (plus a fresh pass on parameter-rationale
> that had only been partially covered). Russell Wing + Claude Opus 4.7,
> running while Martin was paused.

## Scope

15 specs reviewed in 5 parallel-delegated waves:

| Wave | Specs |
|------|-------|
| 1 | parameter-rationale, attack-trees, data-formats, identity |
| 2 | connection-lifecycle, network-behaviour, topology-e2e |
| 3 | topology-scale, demand-model, memory-model |
| 4 | operations, debug-telemetry, configuration |
| 5 | search-indexing, architecture-overview |

Each pass applied: Gaps, Consistency, Clarity, Implementability,
Coverage, Cross-reference integrity. Privacy/terminology/cross-language
passes applied where relevant.

## Finding totals

| Spec | Total | CRIT | HIGH | MED | LOW |
|------|-------|------|------|-----|-----|
| parameter-rationale | 5 | 0 | 1 | 3 | 1 |
| attack-trees | 12 | 2 | 4 | 4 | 2 |
| data-formats | 18 | 1 | 6 | 8 | 3 |
| identity | 13 | 0 | 2 | 7 | 4 |
| connection-lifecycle | 13 | 2 | 4 | 5 | 2 |
| network-behaviour | 13 | 0 | 3 | 6 | 4 |
| topology-e2e | 22 | 2 | 6 | 10 | 4 |
| topology-scale | 19 | 3 | 4 | 8 | 4 |
| demand-model | 12 | 0 | 3 | 6 | 3 |
| memory-model | 17 | 2 | 5 | 7 | 3 |
| operations | 11 | 0 | 2 | 6 | 3 |
| debug-telemetry | 15 | 2 | 4 | 6 | 3 |
| configuration | 15 | 2 | 5 | 5 | 3 |
| search-indexing | 19 | 3 | 6 | 7 | 3 |
| architecture-overview | 19 | 3 | 7 | 6 | 3 |
| **Total** | **223** | **22** | **62** | **94** | **45** |

## Recurring patterns

Four distinct drift classes surfaced across nearly every spec. The same
mechanism (the post-pivot / session-92 changes landed in code and in
`network-protocol.md`, but sibling specs were not swept) explains most
CRITICAL and HIGH findings.

### 1. Pre-pivot replication residue (10+ specs)

`network-protocol.md` §4.6/§7.2/§8.2 now specify: personal nodes receive
**exclusively** via Item-Sync pull; push goes relay-to-relay only;
re-push is **epidemic** via `seen_table` content-hash dedup
(`SEEN_TABLE_MAX=10000`, `SEEN_TABLE_TTL=600s`); **role-aware** inbound
protocol gating (relays accept ItemPush/ItemSync/ChannelAnnounce from
Warm peers -- the cordelia-node#9 sparse-mesh fix).

Specs still describing the pre-pivot model:

- **AO-01** (architecture-overview §6.1 Publish Flow): "push to all hot
  peers sharing the channel + relay peers"
- **CL-01** (connection-lifecycle §2.1): pseudocode blanket-rejects
  ItemPush/ItemSync/ChannelAnnounce on Warm peers, contradicts §5.4.2
- **NB-01/02** (network-behaviour §1.1 + §4.1): lifecycle shows
  relay-to-personal-node push; step 8 describes single-hop re-push
- **DM-01/03** (demand-model §2.4): "Push (receive)" row for personal
  nodes; relay bandwidth math assumes single-hop
- **TS-02** (topology-scale): zero mention of seen_table / role-aware
  gating / batched sync / swarm hot_max exemption
- **TE-09** (topology-e2e): three Phase 1 features have no
  coverage-matrix representation

Net effect: an implementer reading *any* of these in isolation would
rebuild the exact bug cordelia-node#9 fixed.

### 2. Stale parameter values (5+ specs)

| Param | Spec says | Shipped code | Specs affected |
|-------|-----------|--------------|----------------|
| `hot_max` (personal) | 10 | 2 | TS-01, AO, topology-scale §2.3 |
| `sync_interval_realtime_secs` | 60 | 10 | CF-03 |
| `writes_per_peer_per_minute` | 10 | 36 (enforced) | CF-04, PR-01 |

PR-01 (parameter-rationale) also shows **three different numbers** for
the same write-rate concept within a single document (headroom table
36/min, per-peer 10, per-channel 100).

### 3. Stale repo / file layout refs (4+ specs)

Everything still pointing at `cordelia-core` / `cordelia-proxy` archives:

- TE-03 (topology-e2e §9): `cordelia-core/tests/e2e/`, wrong runner
  name, missing `harness/orchestrator.py` + `scale/generate-s*.sh`
- OP-03 (operations): `cordelia-core` repo refs
- MM-06 (memory-model): `cordelia-core/cordelia-proxy` refs
- AO repo-structure section: not verified against current crate layout

### 4. Schema version lag (3+ specs)

**DF-01 CRITICAL**: `data-formats.md` describes schema v1 but shipped
code is on v3 (`SCHEMA_VERSION=3` in `schema.rs`, scope column with
CHECK constraint). SI-03 CRITICAL compounds: `search-indexing.md`
documents 5 tables but only FTS5 (v2) is in migrations.

## The pattern has a single root cause

Session 92 + the cordelia-node#9 fix (2026-03-13..2026-03-20) landed a
large wave of protocol changes: role-aware gating, epidemic forwarding,
batched sync, uniform STREAM_TIMEOUT, schema v3 scope column, tightened
`hot_max`. `network-protocol.md` and `data-formats.md` were swept at
the time; **sibling specs were not**.

This explains why ~75% of CRITICAL / HIGH findings cluster on the same
mechanisms. A single coordinated editing pass on the 10 affected specs
would resolve most of the sprint's backlog.

## Implementation-layer CRITICALs

Wave 4 surfaced a different drift class -- spec-to-CODE rather than
spec-to-spec -- in the operational layer:

- **DT-01 CRITICAL** (debug-telemetry §3): every literal log-line in the
  spec disagrees with shipped code ("push delivered" vs `repush
  delivered`; several don't exist at all). Every operator workflow
  built on `grep` is broken.
- **DT-02 CRITICAL** (debug-telemetry §6): `/api/v1/status` contract is
  fiction (spec 11 fields, code 6, added fields not documented, type
  divergence on `uptime_secs`).
- **CF-01 CRITICAL** (configuration): `[memory]`, `[search]`, `[trust]`
  sections documented as canonical do not exist in shipping `Config`
  struct -- values silently ignored.
- **OP-02 HIGH** (operations): CLI reference documents `pair`, `join`,
  `--persistent`, `--json` etc. -- none exist in `cordelia-node/src/main.rs`.
  systemd/LaunchAgent units would fail at startup.
- **SI-01 CRITICAL** (search-indexing §8.1): "Phase 1 Delivered" lists
  vec0/Ollama/dominant scoring -- none exist in code. Phase 1 ships
  FTS5 only.

## New cross-cutting issues (not drift)

Some findings are original, not drift:

- **AT-01/02 CRITICAL** (attack-trees): pairing protocol + route
  discovery / expanding ring attacks absent from threat tree
- **ID-01 HIGH** (identity): attestation format split between
  JCS-over-JSON (§9.3) and CBOR (§7.4 / ecies §7) without
  reconciliation or test vector
- **MM-02 CRITICAL** (memory-model): L1 chain preimage `SHA-256(sorted
  JSON)` is not deterministic across implementations -- pin RFC 8785
  JCS + test vector (matches recommended ID-01 fix)
- **SI-09 MEDIUM** (search-indexing): `cordelia.db` backups contain
  plaintext of every channel -- a decrypted archive with no warning
- **MM-01 CRITICAL** (memory-model): WHITEPAPER L0-L3 framing
  contradicts memory-model spec L0-L3 (different layer semantics,
  different size/retention)

## Recommended triage

### Block Phase 1 close (coordinated sweep)

**Single editing session** over `architecture-overview.md`,
`connection-lifecycle.md`, `network-behaviour.md`, `demand-model.md`,
`topology-e2e.md`, `topology-scale.md`, `memory-model.md`: propagate
post-pivot terminology (pull-only personal nodes, epidemic forwarding,
seen_table, role-aware gating, batched sync). Fix stale parameter
values (hot_max=2, sync_interval=10) and repo refs (cordelia-core →
cordelia-node) in the same pass.

### Block Phase 1 close (point fixes)

- **DF-01**: Update `data-formats.md` to v3 schema
- **CF-01**: Remove phantom `[memory]/[search]/[trust]` sections from
  `configuration.md`; flag as Phase 2+ features or tie to real struct
- **DT-01/DT-02**: Align `debug-telemetry.md` §3 log-lines and §6 API
  contract with shipped code
- **SI-01/SI-03**: Correct `search-indexing.md` §8.1 Phase 1 list;
  delete schema tables not in migration v2
- **MM-02 + ID-01**: Pin JCS for signable preimages with test vector
- **OP-02**: Align operations CLI ref with shipped `main.rs`

### Schedule as doc debt (2-4 weeks)

- Parameter-rationale reconciliation (PR-01..04)
- Attack-trees pairing + route-discovery additions (AT-01/02)
- Architecture-overview refresh after the sweep

### Defer / close

- Review cross-ref lists (PR-05 and similar)
- Speculative topology additions (TE-07 PAN/swarm -- Phase 2)

## Next actions

1. **Review triage decisions** with user (this doc)
2. **Execute coordinated sweep** against the 7-spec pre-pivot cluster
3. **Point-fix CRITICAL drift** (DF-01, CF-01, DT-01/02, SI-01, OP-02)
4. **Spec v2 cadence**: consider adding a "last-pivot-check" footer so
   mass changes are auditable without 14-document reviews

---

*Sprint complete 2026-04-17 -- 15 specs, 223 findings, 22 CRITICAL.*
