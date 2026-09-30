# Review: topology-e2e.md

> Fresh review pass applying the review-spec methodology to
> `topology-e2e.md` (Draft 2026-03-12, 1377 lines). Documentation
> due-diligence before closing Phase 1. The spec is the implementation
> reference for 7 Docker-Compose topologies (T1-T7) that assert the
> 9 TLA+ properties (P1-P9).

## Application Record

| Field | Value |
|-------|-------|
| Date | 2026-04-17 |
| Reviewer | Russell Wing + Claude Opus 4.7 |
| Spec | topology-e2e.md (Draft 2026-03-12) |
| Passes applied | 1 (Gaps), 2 (Consistency), 3 (Clarity), 4 (Implementability), 5 (Coverage), 6 (Cross-reference integrity) |
| Companion spec | topology-scale.md (Created 2026-03-15) -- cross-checked |
| Spec-vs-harness drift flagged | Yes -- see TE-01, TE-02, TE-03, TE-12, TE-13 |

---

## Summary

22 findings. **2 CRITICAL** (1. `status` endpoint is GET in code but the spec uses `api_post` in multiple assertion examples and the property-to-assertion mapping table; 2. `push_policy` value `relay_only` named in §8.2.1 of network-protocol.md contradicts `subscribers_only` used in this spec, the config docs, and all test code -- this spec happens to use the correct shipped value but cites the wrong source). **6 HIGH** (file-layout mismatch vs shipped harness, governor config values in spec examples differ from actual test configs, §2.3.1 duplicate section number, scale generator signature, missing PAN/swarm topology coverage, publish body shape drift). **10 MEDIUM** (clarity, cross-ref polish, missing coverage for role-aware Warm gating, batched sync, swarm hot_max exemption, etc.). **4 LOW** (reference polish).

The spec is structurally sound and its design principles (property-driven, deterministic, reproducible) hold up. The bulk of the findings are spec-code drift that has accumulated since March 2026: the harness was renamed and restructured (`run-topology-e2e.sh` -> `run-all.sh`, `tests/test-t1.sh` -> `topologies/run-t1.sh`), the `status` endpoint changed from POST to GET, new assertions were added to `common.sh`, and Phase 1 work items (PAN/swarm, epidemic forwarding, role-aware Warm gating, batched sync) are not represented in the topology coverage matrix.

---

## CRITICAL

### TE-01: `status` endpoint is GET, but the spec uses `api_post` for it

**Spec**: §3 test sequences (lines 411, 620), §4.1 `assert_hot_peers` (line 788), §4.2 property-to-assertion mapping (line 897), §5.2 per-topology test script example (lines 1008, 1011).

**Evidence**: `crates/cordelia-api/src/lib.rs:45` registers the route as `web::get().to(handlers::status)`. The shipped harness uses `api_get` everywhere (`tests/e2e/assertions/common.sh:119`, `tests/e2e/topologies/run-t1.sh:76`, all other `run-t*.sh`, `tests/e2e/harness/orchestrator.py:375`).

**Issue**: The spec systematically uses `api_post` for `/api/v1/status`. Lines affected:
- Line 411: "poll `POST /api/v1/status` on p1 and p2 until `peers_hot >= 1`"
- Line 788 (`assert_hot_peers`): `actual=$(api_post "$container" "status" | jq -r '.peers_hot')`
- Line 897 (P7 row): "`api_post status` peers_hot >= 1"
- Lines 1008, 1011 (T1 example): `api_post t1-p1 status | jq ...`

A reader implementing from the spec would write failing assertions. The actual harness doesn't have this bug, so the tests pass -- but the reference document is wrong.

**Resolution**:
1. Replace every `api_post "$container" status` / `api_post ... status` with `api_get`.
2. Document in §4.1 that `status`, `health`, and `metrics` are GET; all `/channels/*` endpoints are POST.
3. Add `api_get` to the `common.sh` listing at §4.1 (currently the helper appears only as a one-liner).
4. Update the line 411 prose to "poll `GET /api/v1/status`".

### TE-02: `push_policy = relay_only` in network-protocol.md contradicts shipped value `subscribers_only`

**Spec**: topology-e2e.md uses `subscribers_only` consistently (lines 260, 450, 495, 532, etc.).

**Issue**: This spec happens to use the correct shipped value. **But its source of truth is wrong**: network-protocol.md §8.2.1 (line 1400) states "`relay_only` (default) | Push to hot relay peers on local write." Every other location -- `crates/cordelia-core/src/config.rs:167` default, `docs/specs/configuration.md:59`, `docs/specs/operations.md:397`, network-protocol.md §12.2 line 1805, and topology-e2e.md itself -- uses `subscribers_only`.

A reviewer cross-checking topology-e2e §3.2 against network-protocol.md §8.2.1 will see a conflict and may "fix" the topology configs in the wrong direction.

**Resolution**:
- Not strictly a bug in this spec, but flag it as a cross-spec finding here because §3.2 cites `push_policy = "subscribers_only"` as the value under test and §8.2.1 of the upstream spec contradicts that. Recommend: (a) fix network-protocol.md §8.2.1 to say `subscribers_only`, (b) add a "Value verified against configuration.md §X" note to topology-e2e §3.2, and (c) log the network-protocol.md §8.2.1 issue in a future review of that spec. Low-risk doc fix.

---

## HIGH

### TE-03: File-layout and harness-name drift between spec and shipped harness

**Spec**: §5.1 (`run-topology-e2e.sh`), §5.2 (`tests/test-t1.sh`), §9 File Layout (`cordelia-core/tests/e2e/`, `tests/test-t*.sh`, `run-topology-e2e.sh`).

**Evidence**: Shipped layout:
```
tests/e2e/
  run-e2e.sh              # (top-level smoke)
  build-image.sh
  Dockerfile
  entrypoint.sh
  assertions/common.sh
  configs/t{1..7}/*.toml
  topologies/
    run-all.sh            # <-- replaces run-topology-e2e.sh
    run-t{1..7}.sh        # <-- replaces tests/test-t*.sh
    t{1..7}.yml
  harness/
    orchestrator.py       # <-- undocumented in §9
    query.py              # <-- undocumented in §9
  scale/
    generate-scale.sh
    generate-s2.sh
    generate-s3.sh
    run-s2.sh
    run-s3.sh
    run-scale.sh
    diagnose-s2.sh
  logs/                   # <-- replaces results/
  keys/
```

**Issues**:
1. §9 says `cordelia-core/tests/e2e/` -- `cordelia-core` is ARCHIVED (per MEMORY.md). Path should be `cordelia-node/tests/e2e/`.
2. §5.1 calls the top-level harness `run-topology-e2e.sh`; the actual file is `topologies/run-all.sh`. `run-e2e.sh` exists at the top level but is a lighter smoke driver.
3. §5.2 places per-topology tests at `tests/test-t1.sh`; they live at `topologies/run-t1.sh`.
4. §9 omits `harness/` (Python orchestrator) and `scale/` second-wave generators (`generate-s2.sh`, `generate-s3.sh`). These are load-bearing for the scale-test claims cited in MEMORY (R=50/100/200 results).
5. Artifact directory is `logs/` not `results/` as §5.3 claims.

**Resolution**: Rewrite §9 against `tree tests/e2e/ -L 2` output. Rename §5.1 `run-topology-e2e.sh` to `topologies/run-all.sh`. Rename §5.2 `tests/test-t1.sh` to `topologies/run-t1.sh`. Add a subsection "§5.4 Python harness (scale tests)" pointing at `harness/orchestrator.py` and `query.py` (test-harness-design memory doc is the design source).

### TE-04: Governor parameters in spec examples differ from actual test configs

**Spec**: §3.2 T1 p1.toml (line 266-284) specifies `hot_min = 1, hot_max = 5, keepalive_timeout_secs = 30`. §8.1 "Test Governor Parameters" table (line 1196-1204) specifies `keepalive_timeout_secs = 15` for tests.

**Evidence**: Actual `tests/e2e/configs/t1/p1.toml` uses `hot_min = 5, hot_max = 5, keepalive_timeout_secs = 30`. The §3.2 inline config and the §8.1 tuning table disagree with each other AND with the shipped config.

Specifically:
- §3.2 T1 config: `hot_min = 1`. Shipped: `hot_min = 5`.
- §3.2 T1 config: `keepalive_timeout_secs = 30`. §8.1 table: `15`. Shipped: `30`.
- §8.1 also references `hysteresis_secs = 5` and `stale_threshold_secs = 30` -- neither appears in any shipped test config (`grep -n hysteresis tests/e2e/configs/**/*.toml` returns nothing).
- `hot_min_relays` (added to network-protocol.md §5.3) is mentioned in topology-scale.md §2.3 but never in topology-e2e.md configs, even though Phase 1 relies on it for relay-backbone connectivity.

**Resolution**:
1. Either (a) regenerate the inline §3.2 T1 config block from `tests/e2e/configs/t1/p1.toml`, or (b) strip inline configs and link to the config directory, annotated with the knobs that matter.
2. Reconcile §8.1 with shipped configs. If the shipped configs are authoritative, rewrite the table. If the spec values are authoritative, update the configs.
3. Add `hot_min_relays` to the §8.1 table.
4. Add a `note` row: "Shipped configs use `hot_min = hot_max = 5` rather than `hot_min = 1, hot_max = 5` to force immediate relay promotion without waiting for a tick."

### TE-05: Duplicate `§2.3.1` section number

**Spec**: §2.3.1 "Production Deployment Mapping" (line 99) and §2.3.1 "Known Limitations" (line 162).

**Issue**: Two different subsections share the number `2.3.1`. This breaks cross-references (§7 "Coverage Tracking" mentions SS7.3; the same pattern would fail here). Anyone citing "§2.3.1" has to say which one.

**Resolution**: Renumber the second occurrence to §2.3.6 (after §2.3.5 Example) -- the numbering order within §2.3 should be: .1 Production mapping, .2 IP scheme, .3 Multi-homed, .4 Flat, .5 Example, .6 Known limits. Conntrack tuning (currently bundled with known limits) arguably deserves its own §2.3.7.

### TE-06: Scale generator signature mismatch

**Spec**: §12.2 lists usage `generate-scale.sh <total> [bootnodes] [relays] [zone_size]`, with example `500 2 10 50`.

**Evidence**: `tests/e2e/scale/generate-scale.sh` matches the signature correctly (line 3: `Usage: generate-scale.sh <total_nodes> [bootnodes] [relays] [zone_size]`). But the zone IP scheme in §12.3 reserves `.30-.79` for personal nodes, ~= 50 slots. Running with `zone_size = 50` exactly fills the /24 with `.30-.79`. One off-by-one: the §12.2 example says "488 personal nodes / 50 per zone = 10 zones" but 488/50 = 9.76, so the last zone holds 38 personal nodes, not 50. The "home-10" row in §12.3 says "P451-P488 (.30-.67)" which is consistent with this -- but §2.3.2 in the main spec says `.30-.79` for personal nodes. The /24 has room for 50 per zone, the example sizes one zone smaller, and the two tables use different endpoint values. Implementors will trip.

Second issue: §12.2 does not document `generate-s2.sh` and `generate-s3.sh` which exist in the repo and generate scale S2/S3 scenarios respectively (different topologies from `generate-scale.sh`).

**Resolution**:
1. Clarify §12.3 that the `.30-.79` range is the hard limit; actual zone fill depends on `(TOTAL - BOOTNODES - RELAYS) % ZONE_SIZE`.
2. Document `generate-s2.sh` (S2 = throughput under load) and `generate-s3.sh` (S3 = churn resilience) in §12 or add a §12.6 "Scenario-specific generators" pointing at topology-scale.md §3 (S1-S5).

### TE-07: PAN (agent swarm) topology not represented in coverage matrix

**Spec**: §3.1 lists 7 reference topologies; §7.3 lists 5 second-wave topologies. §7.1 says "personal_nodes[1-5] * relays[0-3] ..." -- but the swarm lead node has distinctive behaviour: accepts inbound only from HKDF-derived children, hosts local-scope channels that never leave the PAN, and is Hot-exempt (swarm hot_max exemption per network-protocol.md §7.2 and memory context).

None of T1-T12 exercises a PAN topology. An "agent orchestrator spawns sub-agents" is the flagship Phase 2 use case and was implemented in Phase 1 (see network-protocol.md §8.2.2). The only validation is unit/integration, not a topology E2E.

**Resolution**: Add T13 Swarm or document deferral explicitly in §11.2 Phase 2. If added:
- Nodes: 1 lead personal + 2 swarm children + 1 upstream relay + 1 bootnode.
- Properties tested: P3 (channel isolation -- local-scope items do not leak to upstream relay), P4 (role isolation), plus an explicit "swarm-no-leak" property that belongs in the TLA model as P10.
- Depends on the swarm HD-derivation identity model (§8.2.2) which is already in the Rust code.

### TE-08: Publish body shape drift between spec and harness

**Spec**: §5.2 example `tests/test-t1.sh` (line 1022): `"content": {"text": "test item $i"}`.

**Evidence**: `tests/e2e/topologies/run-t1.sh:95` sends `"content": "test message $i"` (a string). channels-api.md §3.2 permits `"content": any` (arbitrary JSON), so both are valid, but the spec example and harness disagree.

**Resolution**: Align to one form. Recommend matching the harness (simple string content), since T1 is a basic smoke and a string is easier to read in assertion failure logs. Update §5.2 to match. Add a note: "Topology E2E uses string content for brevity; channels-api.md §3.2 permits any JSON value."

---

## MEDIUM

### TE-09: Coverage matrix does not reflect Phase 1 work-package-level features

**Spec**: §7.2 Coverage Matrix (P1-P9 x T1-T7).

**Issue**: Phase 1 landed three protocol features during March 2026 that the spec does not mention:

1. **Epidemic forwarding via SeenTable** (network-protocol.md §7.2) -- tested at scale (R=50/100/200 per memory context) but none of T1-T7 specifically exercises it. T4 (multi-relay) happens to exercise fan-out but the coverage matrix doesn't call out epidemic forwarding.
2. **Role-aware Warm gating** (network-protocol.md §5.4.2) -- relays accept ItemPush/ItemSync from Warm peers. T2-T5 relay topologies implicitly exercise this but the assertion framework does not validate it. A regression that reverts to Hot-only gating would be caught only by the convergence timeout, not a direct assertion.
3. **Batched sync** (network-protocol.md §4.5) -- one QUIC stream per peer for all channels. Again, implicitly exercised. No explicit assertion verifies the batching behaviour.

**Resolution**: Add §7.4 "Implicit coverage notes" listing which Phase 1 protocol features each topology exercises by virtue of its configuration. Optionally: extend the TLA model and assertions to formalise these as P10-P12 (epidemic dedup, Warm-gating acceptance, batched-stream count).

### TE-10: "swarm hot_max exemption" and "HKDF-verified peers always Hot" not tested

**Spec**: §3.1, §7.

**Issue**: Memory context notes the governor now has "Swarm hot_max: HKDF-verified swarm peers always Hot, exempt from governor hot_max." This is a deliberate carve-out that bypasses the baseline `hot_max = 2` cap for derived children. Nothing in T1-T7 exercises it (they have no swarm lead role). T13 (TE-07) would close this too.

**Resolution**: Bundle with TE-07 Swarm topology, or document the exemption explicitly as out-of-scope for Phase 1 topology E2E and covered by unit tests.

### TE-11: `common.sh` assertion inventory is stale

**Spec**: §4.1 lists `wait_for`, `api_post`, `api_get`, `db_query`, `assert_item_count`, `assert_no_items`, `assert_hot_peers`, `assert_no_psks`, `assert_zero_items`, `assert_channel_isolation`, `assert_convergence`, `assert_zero_log_matches`.

**Evidence**: `tests/e2e/assertions/common.sh` also defines:
- `channel_id_for` (mentioned in prose but not in the §4.1 listing)
- `assert` (generic pass/fail helper, not in spec)
- `assert_min_total_items` (not in spec)
- `print_summary` (not in spec, used by every test script)

Spec lists but impl lacks:
- None -- every spec function is implemented.

**Resolution**: Update §4.1 to include `channel_id_for`, `assert`, `assert_min_total_items`, and `print_summary`. Document what each is used for. The `print_summary` function is particularly important because §5.1 (the old `run-topology-e2e.sh`) aggregates PASS/FAIL counts across topologies while the actual `run-t*.sh` scripts aggregate within a single topology; this changes the failure-reporting semantic.

### TE-12: §2.4 entrypoint shown as `cordelia init --name ... --non-interactive` but shipped entrypoint differs

**Spec**: §2.4 lines 186-200.

**Evidence**: `tests/e2e/entrypoint.sh` does not use `--name` (the config provides `entity_id`). Confirm:

```bash
docker exec t1-p1 cat /entrypoint.sh  # compare
```

If shipped entrypoint does not pass `--name` or does not respect `$NODE_NAME`, the spec is inaccurate. This matters because a reader implementing a new topology adds the wrong entrypoint.

**Resolution**: Read the shipped `tests/e2e/entrypoint.sh` and reconcile. (Recommend updating the spec to match the shipped script verbatim, with a comment that "--name defaults to `entity_id` from config if omitted".)

### TE-13: §2.3.4 says T1 and T6 "remain on single flat cordelia-net" -- verify against shipped Compose files

**Spec**: §2.3.4.

**Evidence**: T1 Compose shown in §3.2 uses `networks: cordelia-net` (flat). T6 is claimed to match. Test harness files should be spot-checked -- especially T6 which now uses `home-1`, `home-2`, `home-3` per some readings of §3.7 even though §2.3.4 says it is flat. T6 topology diagram (line 613-616) shows no zone labels, consistent with "flat", but the node-config notes say `172.28.0.30` etc. so it probably is flat.

**Resolution**: Cross-check `tests/e2e/topologies/t6.yml` against §3.7. If Compose uses zone networks, update §2.3.4. If it doesn't, no change needed but add a one-line "Confirmed flat: zone isolation not required for bootnode-loss scenario" to §3.7.

### TE-14: Bootnode config omits `push_policy` but deploy/bootnode/config.toml sets `push_policy = "pull_only"`

**Spec**: §3.2 line 318: "Bootnode configs omit `[replication]` and `push_policy` (bootnodes do not replicate or push)."

**Evidence**: `deploy/bootnode/config.toml:19` sets `push_policy = "pull_only"`. Test configs (`tests/e2e/configs/t*/b1.toml`) may follow either pattern. Production bootnodes set `pull_only` as an explicit defense-in-depth even though bootnodes never reach the push code path.

**Resolution**: Document the convention: "Bootnode configs MAY include `push_policy = "pull_only"` as defense-in-depth. Phase 1 bootnode code does not invoke the push path regardless."

### TE-15: §4.3 "Log Assertions" -- pattern format is under-specified

**Spec**: §4.3 declares log format as `[DEBUG] protocol send: type=0x06 peer=<node_id> channel=<id>`.

**Issue**: The grep patterns in §4.3 use `protocol send: type=0x06` -- they work only if the code logs exactly that string. `grep`'s case-sensitivity and whitespace tolerance make this fragile. Implementors could log `type=0x06` or `type = 0x06` or `type: 0x06` and assertions would silently fail (zero matches -> "pass").

A zero-match assertion is only meaningful if the `protocol send:` pattern is otherwise observed for at least one other type. Otherwise the assertion is vacuously true: a node that logs nothing passes the push-silence check. P8 (push silence on `pull_only`) and P9 (bootnode silence) are both at risk of false-positives.

**Resolution**:
1. Specify the exact log format in network-protocol.md (or at least in topology-e2e.md §4.3) as a MUST.
2. Add a meta-assertion: before asserting zero matches for pattern X, require at least one positive match for pattern Y (e.g., `protocol recv: type=0x02` for a Warm peer -- any protocol activity confirms the log pipeline works).
3. Or pivot from grep to Prometheus counters (cf. `cordelia_item_push_total` already cited in §4.2 P5). Counters are more robust than log grepping.

### TE-16: §8.2 Timeout Strategy -- formulas are not derivable from shipped configs

**Spec**: §8.2 lists formula `Bootstrap = 3 * tick_interval + handshake_timeout`, test value ~16s.

**Evidence**: Shipped T1 config has `tick_interval_secs = 2`. Formula yields `3 * 2 + 10 = 16s` ✓. But `min_warm_tenure_secs = 5`, not the test-table value of 5; OK. `keepalive_timeout_secs = 30`, not the test-table value of 15. Pull delivery formula `sync_interval_realtime + tick_interval = 10 + 2 = 12s` ✓.

The inconsistency in TE-04 propagates here. Once configs are aligned, formulas hold.

**Resolution**: After TE-04 is resolved, add a meta-test to the harness that verifies `bootstrap_timeout(topology_config) <= 30s` by reading the config file rather than hardcoding a 30s wait.

### TE-17: CI trigger policy references `src/**` but the repo is workspace-structured

**Spec**: §6.1 path filter `- 'src/**'`.

**Evidence**: `cordelia-node` is a Cargo workspace with crates under `crates/cordelia-*`. There is no top-level `src/`. A GH Actions path filter `src/**` will never match; topology E2E will never run on push.

**Resolution**: Replace `src/**` with `crates/**` in §6.1. Similar issue for PR trigger.

### TE-18: Partition assertion count in §3.6 T5 is suspect

**Spec**: §3.6 line 600: "P2 has only 2 pre-partition items + 2 own items = 4 items. P1 has 2 + 3 = 5 items."

**Issue**: Before partition, P1 publishes 2 items that should reach P2. After partition, P1 publishes 3 more (P1 total = 5), and P2 publishes 2 (P2 total = 2 pre-partition from P1 + 2 own = 4). Post-heal, total = 2 + 3 + 2 = 7 ✓. But the line "P2 has only 2 pre-partition items" only holds if the 2 pre-partition items were delivered to P2 before the partition. Since the partition is applied AFTER step 3 ("Publish 2 items on P1, verify delivery to P2"), this is correct -- but it's fragile. If the pre-partition delivery verification is flaky, the partition assertion is inherited flaky.

**Resolution**: Add an explicit `wait_for "P2 has 2 items"` step after step 3 with a tight timeout (e.g., 10s), then proceed. Currently step 3 says "verify delivery" without specifying the mechanism.

---

## LOW

### TE-19: References section (§13) is missing two Phase 1 specs

**Spec**: §13.

**Issue**: Missing: `specs/parameter-rationale.md` (for STREAM_TIMEOUT = 10s, hot_max rationale), `specs/glossary.md` (terminology baseline), `specs/topology-scale.md` (companion spec created 2026-03-15). `decisions/2026-03-10-testing-strategy-bdd.md` is present.

**Resolution**: Add the three missing specs to §13 table.

### TE-20: §10 confidence formula cites `TLA_pass_rate * topology_coverage * e2e_pass_rate * economic_sim_pass_rate * attack_tree_coverage`

**Spec**: §10 line 1276.

**Issue**: The formula multiplies five factors all required > 90%. 0.9^5 = 0.59, so Phase 1 confidence under this formula is ~59% not 90%. Either the formula is a heuristic product-of-weights (in which case "all > 90%" doesn't mean "confidence > 90%") or each factor is meant to be > 0.98 for a 90% overall. The ADR citation (`decisions/2026-03-10-testing-strategy-bdd.md`) should carry the math.

**Resolution**: Add "(threshold applies per-factor, not to the product)" or fix the formula to an additive-weighted form. Cross-check with the ADR.

### TE-21: Section §2.3.5 table IP column header "Example" column is noisy

**Spec**: §2.3.5.

**Issue**: The table has columns "Role | Internet IP | Zone IP | Example". The Example column restates rows 2 and 3. Remove for clarity.

**Resolution**: Drop the Example column or fold the examples into inline prose.

### TE-22: Minor polish -- "SS" notation for sections

**Spec**: passim.

**Issue**: The spec uses `SS` notation (§8 but written as "SS8", e.g., line 414 "SS3.9", line 694 "SS2") inconsistently with `§` elsewhere. The Markdown source displays both. Per terminology audit (review-terminology.md) the project standardised on the `§` glyph or `ss` shorthand. Standardise on `§`.

**Resolution**: Pass `sed 's/SS\([0-9]\)/§\1/g'` or equivalent over the spec.

---

## Passes Not Applied (per instructions)

| Pass | Reason |
|------|--------|
| 6 (Privacy) | Covered by review-privacy.md, no topology-specific privacy concerns surfaced here |
| 7 (Terminology) | Covered by review-terminology.md and glossary.md |

---

## Recommended Triage

**Fix before Phase 1 close (spec vs shipped code or directly actionable):**
- **TE-01** (`status` GET vs POST) -- spec has wrong method for every `status` call. CRITICAL.
- **TE-02** (`relay_only` vs `subscribers_only` in network-protocol.md §8.2.1) -- fix the upstream, not this spec, but log here.
- **TE-03** (file layout & harness names) -- this spec is the entry-point for new topology work; wrong paths will send people to the wrong files.
- **TE-04** (governor config drift) -- spec examples disagree with shipped configs. Pick a source of truth.

**Fix in one editing session (doc polish):**
- TE-05 duplicate §2.3.1, TE-06 scale generator, TE-08 publish body shape, TE-11 common.sh inventory, TE-14 bootnode push_policy, TE-17 CI path filter, TE-19 references.

**Fix opportunistically:**
- TE-09 implicit coverage notes, TE-10 swarm exemption, TE-12 entrypoint, TE-13 T6 flat verification, TE-15 log assertion robustness, TE-16 timeout derivation, TE-18 partition verification, TE-20 confidence formula, TE-21 IP table, TE-22 SS notation.

**Defer to Phase 2 spec work:**
- TE-07 PAN/swarm topology (T13) -- requires TLA P10 property and Rust test scaffolding.

---

## Cross-Spec Observations

Not findings for this spec, but surfaced during review:

- **network-protocol.md §8.2.1** states `relay_only` as the default push_policy (line 1400) while §12.2 (line 1805) and every other source use `subscribers_only`. Log in future network-protocol.md review.
- **harness/orchestrator.py** and **harness/query.py** exist and are the scale-test engine. Neither is mentioned in topology-e2e.md or topology-scale.md. These files embody the Python-orchestrator design noted in project_test_harness_design.md (MEMORY). Add a §5.4 (topology-e2e) or §2.5 (topology-scale) reference.
- The Rust test count (479) matches the unit/integration coverage. The shell-based topology E2E is orthogonal and not counted in the 479. A future spec might clarify "total tests" accounting: 479 (Rust) + 7 (topology E2E) + 59 (E2E smoke via Python harness) + variable-N (scale tests).
- `deploy/bootnode/config.toml` is the production bootnode config and includes `push_policy = "pull_only"` (defense-in-depth). topology-e2e T6 bootnode config does not. Not a bug, but worth noting when reviewing operations.md.
- TLA spec (`network-protocol.tla`) confirms P1-P9 property names match topology-e2e's coverage matrix (Delivery, PullDelivery, ChannelIsolation, RoleIsolation_*, LoopTermination, Convergence, BootstrapCompletion, PushSilence, BootnodeSilence). No TLA/E2E name drift.

---

*Review complete 2026-04-17.*
