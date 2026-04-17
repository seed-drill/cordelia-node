# Review: topology-scale.md

> Fresh review pass applying the review-spec methodology to
> `topology-scale.md` (Spec v1.0, 2026-03-15, 259 lines). Phase 1 closing
> review. Cordelia has been scale-tested to R=200 per MEMORY.md; this
> spec predates those results and pre-dates the post-pivot network
> features (epidemic forwarding, seen_table, role-aware Warm gating,
> batched sync, swarm hot_max exemption). Companion to
> `review-topology-e2e-2026-04-17.md`.

## Application Record

| Field | Value |
|-------|-------|
| Date | 2026-04-17 |
| Reviewer | Russell Wing + Claude Opus 4.7 |
| Spec | topology-scale.md (v1.0, 2026-03-15) |
| Passes applied | 1 (Gaps), 2 (Consistency), 3 (Clarity), 4 (Implementability), 5 (Coverage), 6 (Cross-ref integrity) |
| Companion specs | topology-e2e.md (reviewed 2026-04-17), network-protocol.md, parameter-rationale.md, demand-model.md |
| Post-pivot drift flagged | Yes -- see TS-01, TS-02, TS-03, TS-04, TS-08 |

---

## Summary

19 findings. **3 CRITICAL** (1. `hot_max = 10` for personal nodes contradicts authoritative `hot_max = 2` in parameter-rationale.md §125 and demand-model.md §3.2 -- scale test would validate the wrong governor profile; 2. spec entirely omits the post-pivot protocol features that MADE convergence at R=200 work -- epidemic forwarding / SeenTable / role-aware Warm gating / batched sync -- so the scale tests as specified do not validate the actual convergence mechanism; 3. single flat `cordelia-net` network in §1.3 contradicts the zone model in topology-e2e.md §2.3, which IS the Phase 1 production model). **4 HIGH** (scenario generators diverge from spec -- shipped `generate-s2.sh` / `generate-s3.sh` generate different topologies than S2/S3 in the spec; 1000-node target never validated and infrastructure plan shows unrealistic bootstrap sequencing; `hot_min_relays` missing from governor tuning; eclipse scenario S4 requires unimplemented attacker-node and is blockingly under-specified). **8 MEDIUM** (measurement framework has no harness attribution -- the Python orchestrator that produced R=200 results is not mentioned anywhere; `run-scale.sh` is named but never defined; no convergence definition for S2/S3; dedup rate metric formula is unclear; no cross-reference to seen_table bounds; conntrack tuning from topology-e2e.md not replicated here; no 1000-node memory budget; S4 attack assumptions under-documented). **4 LOW** (reference polish, phase boundary marker missing, SS vs § notation, cross-ref to topology-e2e).

The spec is a useful planning document but has not been updated since the post-pivot protocol work landed. Its governor profile pre-dates the hot_max=2 decision (commit history suggests February 2026 parameters). Its scenario set pre-dates the Python orchestrator that actually drove the R=50/100/200 validation. Its topology model pre-dates zone-based Docker networking. The delivered R=200 convergence results in MEMORY.md were produced by shipped infrastructure that this spec does not describe.

---

## CRITICAL

### TS-01: Governor profile uses pre-pivot `hot_max = 10`, not authoritative `hot_max = 2`

**Spec**: §2.3 Governor Targets for Scale (lines 117-134).

**Evidence**: Spec specifies for personal nodes:
```toml
hot_min = 2
hot_max = 10        # Bounded: O(10) sync cost regardless of N
```

Authoritative source (`parameter-rationale.md:125`): "hot_max = 2 (personal), 50 (relay)". "Personal (2): 1 relay (hot_min_relays=1) + 1 redundancy peer. Personal nodes are consumers, not distributors. The relay does fan-out."

`demand-model.md:218` corroborates: "hot_max (personal) -- 2 -- Minimum for reliability. Halves push bandwidth vs 5." MEMORY.md "Key parameters in code: ... hot_max=2 (personal)."

**Issue**: If the scale test uses `hot_max = 10`, each personal node maintains 5x more Hot connections than production and pushes every item to 5x more peers. This:
1. Invalidates the scale test as a validator of production behaviour.
2. Hides real convergence cost -- the actual R=200 result with `hot_max = 2` was dependent on epidemic forwarding (TS-02), not on personal-node fan-out. A test with `hot_max = 10` could pass even if epidemic forwarding were broken.
3. Inflates bandwidth predictions per §4.2 reporting, producing misleading headroom numbers.

Additionally `warm_min = 5, warm_max = 20, cold_max = 200` (spec) differs from the production values in `parameter-rationale.md` (personal: warm_min=3, warm_max=10, cold_max=50) and the relay values (`hot_max=50`) match parameter-rationale but `hot_min=5, warm_min=20, warm_max=100, cold_max=500` exactly mirror an earlier revision of network-protocol.md.

**Resolution**:
1. Replace the §2.3 governor config block with the authoritative production profile (parameter-rationale.md §"hot_max = 2" section):
   ```toml
   # Personal nodes (production profile)
   [governor]
   hot_min = 2
   hot_max = 2
   hot_min_relays = 1
   warm_min = 3
   warm_max = 10
   cold_max = 50
   ```
2. Add a "Test override" sub-block that lists which knobs are accelerated for scale testing (tick_interval, min_warm_tenure, sync_interval -- as in topology-e2e.md §8.1) but keep hot_max/warm_max/cold_max at production values. The scale test's job is to prove production parameters work, not to test alternative parameters.
3. Add a cross-reference to `parameter-rationale.md §"hot_max = 2"` as the authoritative source and state "values in this section are copied from, not derived anew in, this spec."

### TS-02: Spec omits every post-pivot protocol feature that enabled R=200 convergence

**Spec**: Entire document.

**Evidence**: MEMORY.md "Build Status" (2026-03-20, Session 121):
- "Epidemic forwarding: SeenTable in cordelia-network, wired into p2p push + repush flush + pull-sync (§7.2)"
- "Role-aware protocol gating: Relays accept ItemPush/ItemSync/ChannelAnnounce from Warm peers (§5.4.2). Fixes asymmetric hot sets in sparse meshes."
- "Batched sync: one QUIC stream per peer, all channels (§4.5). Fixes rate limit exhaustion for 3+ channels."
- "Swarm hot_max: HKDF-verified swarm peers always Hot, exempt from governor hot_max."
- "Scale results (2026-03-20): R=50 152/152 (19s), R=100 302/302 (17s), R=200 relays 200/200 converge"
- "cordelia-node#9 FIXED: sparse mesh partitioning resolved by epidemic forwarding + role-aware gating"

network-protocol.md confirms these are shipped: §7.2 (SeenTable, SEEN_TABLE_MAX=10000, SEEN_TABLE_TTL=600s), §5.4.2 (role-aware protocol gating, line 1231), §4.5 (batched sync), §8.2.2 (swarm hot_max).

**Issue**: topology-scale.md specifies scenarios that IMPLICITLY exercise these features (S1 convergence, S5 partition/heal) but does not NAME them and does not assert them. Consequently:
1. The pass criteria "convergence_secs should be roughly constant as nodes increases" (line 239) is presented as a surprising empirical result. In fact it is the designed outcome of epidemic forwarding + relay-mesh fan-out -- the spec should say so and tie the measurement back to the mechanism.
2. A regression that accidentally reverted seen_table dedup, or reverted Warm-peer acceptance on relays, would show up only as a convergence slowdown -- potentially still under the 120s timeout, thus silently passing. The spec provides no mechanism-level assertion.
3. The spec proposes a 1000-node scenario (§5 step 7). At R=200 the memory context reports "R=200 relays 200/200 converge" but not full-mesh personal-node convergence; 1000 nodes has never been validated and the spec does not discuss the epidemic-hop-count implications (§7.2 of network-protocol.md states "Hops to converge" vs "Cost/item (epidemic)" for scaling -- that table should be referenced here).
4. `cordelia-node#9` (sparse mesh partitioning, now FIXED) arose precisely from missing role-aware gating. A fresh reader of this spec would not know #9 existed nor that scale tests were the mechanism that exposed it.

**Resolution**:
1. Add §3.0 "Protocol features under test" enumerating each post-pivot feature and which scenarios exercise it:
   - Epidemic forwarding / SeenTable bounds -> S1, S2, S5 (each publish exercises dedup)
   - Role-aware Warm gating (relay accepts ItemPush/ItemSync/ChannelAnnounce from Warm peers) -> S1 at R≥50 (where hot_max < R makes hot sets asymmetric), S5 (post-heal sync from warm relays)
   - Batched sync (one stream per peer, all channels) -> S2 (throughput), multi-channel variants
   - Swarm hot_max exemption -> out of scope for current scenarios (requires swarm lead, see TS-09)
2. Under each scenario, add an "Asserts mechanism" bullet naming the feature exercised.
3. Under §4.1, add assertions that check the mechanism, not just the outcome:
   - SeenTable dedup: `cordelia_seen_table_dedup_dropped` > 0 on relays during S1 fan-out.
   - Warm-peer acceptance: on R=50+, relay metric `cordelia_itempush_recv_from_warm` > 0 (new metric to add to operations.md).
   - Batched sync: relay has ≤ 1 outbound sync stream per peer during a tick (read `cordelia_sync_streams_opened` and divide by peers).
4. Add §2.3 sub-note: "`hot_max = 2` is fixed at the production value. Constant-time convergence depends on epidemic forwarding (§7.2 network-protocol.md), not on hot-set size."

### TS-03: Single flat `cordelia-net` network contradicts Phase 1 zone model

**Spec**: §1.3 Docker Network (lines 49-77), §2.2 IP Assignment (lines 108-114).

**Evidence**: topology-scale.md §1.3 specifies a single bridge network (`/24` for 50/100, `/22` for 500, `/21` for 1000). §2.2 IP Assignment puts "Personal: 172.28.0.50 - 172.28.3.255 (for /22)" -- i.e., personal nodes directly reachable from each other on the flat network.

topology-e2e.md §2.3 (lines 94-160) defines the zone-based network model as the Phase 1 production mapping: "Personal nodes sit behind NAT on isolated home networks and can only reach relays/bootnodes, not each other directly. This prevents peer-sharing from bypassing relay-mediated traffic (which caused T2 to fail on flat networks)."

topology-e2e.md §12 (lines 1314-1340) IS the scale-test topology generator, and it uses the zone model: "At scale (100+ nodes), one Docker network per personal node risks hitting kernel iptables limits. Instead, personal nodes are grouped into **neighborhoods** (zones)."

Shipped `tests/e2e/scale/generate-scale.sh` (lines 1-17): uses the zone model. "Example: generate-scale.sh 500 2 10 50 -- 488 personal / 50 per zone = 10 zones ... 12 Docker networks total (1 internet + 10 home + 1 spare)".

**Issue**: topology-scale.md's network model is obsolete. A flat /22 does not test Phase 1's production topology -- it lets personal nodes peer-share directly, bypassing relay-mediated traffic which is specifically the T2-failure mode that prompted zone isolation. Scale results on a flat network would over-estimate convergence speed (shorter paths) and under-exercise relay fan-out (the critical backbone behaviour).

Additionally:
1. §2.2 IP assignment scheme has no mapping from personal nodes to zones.
2. §1.3 kernel conntrack tuning is listed, but `nf_conntrack_udp_timeout_stream=30` and `conntrack -F` flush between runs (topology-e2e.md §2.3.1 "Known Limitations") are REQUIRED for sequential tests -- spec does not say sequential runs are supported.

**Resolution**:
1. Rewrite §1.3 and §2.2 to reference the zone model as the canonical network topology. Cite topology-e2e.md §2.3 and §12.
2. Replace the flat `/22`/`/21` subnets with a "1 internet + N home zones" model derived from `generate-scale.sh`.
3. Move the conntrack tuning into a §1.5 "Sequential run prerequisites" with the explicit `conntrack -F` flush requirement.
4. Add a note explaining why the flat model was abandoned (T2 fail mode), citing topology-e2e.md §2.3.

---

## HIGH

### TS-04: Shipped scale generators do not match spec scenarios

**Spec**: §3 Scale Test Scenarios S1-S5, §5 Implementation Plan (lines 245-253).

**Evidence**: `tests/e2e/scale/` contains:
```
generate-scale.sh    (base zone generator, accepts N)
generate-s2.sh       (S2-specific topology)
generate-s3.sh       (S3-specific topology)
run-s2.sh            (S2 runner)
run-s3.sh            (S3 runner)
run-scale.sh         (presumably top-level -- not in spec)
diagnose-s2.sh       (debug helper)
harness/orchestrator.py  (Python orchestrator, not mentioned anywhere)
```

But there is NO `generate-s1.sh`, `generate-s4.sh`, `generate-s5.sh`, or runners for S1/S4/S5. S1 is the convergence test that MEMORY.md reports as 152/152 (R=50) / 302/302 (R=100) / 200/200 (R=200). The base `generate-scale.sh` generates an S1-like topology but it is not identified as S1 in the spec.

**Issue**: The spec's scenario set does not match what was actually run. Three interpretations:
1. S2 and S3 were implemented with dedicated generators because the base generator is insufficient. If so, the spec should say what's different about the S2/S3 topologies.
2. S1 is implicit in `generate-scale.sh` but never documented as such.
3. S4 (eclipse) and S5 (500-node partition) were never implemented (§5 step 8 explicitly defers S4; S5 has no shipped generator).

The implementation plan in §5 says "Request VM resize to 64GB for 500+ nodes" -- MEMORY.md shows cordelia-test is 64GB RAM already. Status is stale.

Additionally, §5 step 5 says "Request VM resize to 64GB for 500+ nodes" but the memory budget in §1.1 says `500 nodes | 32GB | 8`. These conflict: spec says 500 nodes need 32GB in §1.1 but 64GB in §5. MEMORY.md says "64GB RAM, 12 CPU" on cordelia-test. Spec is internally inconsistent and stale.

**Resolution**:
1. Update §3 to match shipped scenarios. If `generate-s2.sh` and `generate-s3.sh` implement the S2 (throughput) and S3 (churn) scenarios, describe what they generate (sizing, zone layout, publisher count) explicitly.
2. Document `generate-scale.sh` as the S1 generator (parameterised). Rename to `generate-s1.sh` or leave as the "generic" base.
3. Mark S4 (eclipse) and S5 (partition at scale) as "Not implemented in Phase 1" with a backlog pointer.
4. Reconcile §1.1 memory sizing with §5 VM sizing. Confirm actual cordelia-test is 64GB (per MEMORY.md).
5. Add `harness/orchestrator.py` reference -- the Python orchestrator is the execution engine for scale tests and embodies the "Concurrent orchestrator (ThreadPoolExecutor), token caching, publish retries, scaled timeouts" design noted in MEMORY.md. It belongs in §4 (Measurement Framework) and §2 (generators).

### TS-05: `hot_min_relays` missing from scale governor config

**Spec**: §2.3 Governor Targets for Scale.

**Evidence**: network-protocol.md §5.3 defines `hot_min_relays` as an independent target that "Ensures relay backbone connectivity. On each governor tick, if fewer than `hot_min_relays` relays are in the hot set, promote a random warm relay to Hot". network-protocol.md §§1392, 1506, 1528 give profile values: personal `hot_min_relays = 1`, relay `hot_min_relays = 5`, keeper `hot_min_relays = 2`. MEMORY.md confirms this is wired into Phase 1. parameter-rationale.md also references it.

topology-scale.md §2.3 governor block has no `hot_min_relays` entry.

**Issue**: Without `hot_min_relays = 1` on personal nodes, the test configuration might let a personal node's Hot set be filled with 2 personal peers and no relay -- which would never deliver items to the relay backbone for epidemic fan-out. This is a showstopper for convergence and exactly the failure mode that `hot_min_relays` was added to prevent.

If the scale test isn't setting this, either (a) the test fails for the wrong reason, or (b) the test accidentally works because the generator places enough relays early in the peer list that they naturally win random promotion. Either way the test does not exercise the production guarantee.

**Resolution**:
1. Add `hot_min_relays = 1` (personal) and `hot_min_relays = 5` (relay) to §2.3 governor blocks, matching production profiles.
2. Add a bullet in "Asserts mechanism" (per TS-02): "Every personal node has ≥ 1 relay in its Hot set at convergence time" -- queryable via `/api/v1/status` + DB inspection.

### TS-06: 1000-node target never validated; bootstrap sequencing unrealistic at that scale

**Spec**: §1.1 Infrastructure (lines 17-22), §3 scenarios, §5 Implementation Plan step 7 ("Run S1, S3, S5 at 1000 nodes").

**Evidence**: MEMORY.md documents R=50/100/200 successful runs. R=200 is "relays 200/200 converge" (not full personal-node convergence). There is no R=500 or R=1000 data point. The 1000-node target is aspirational.

`/21` subnet holds 2046 usable IPs; 1000 nodes fits but with 20 relays and 5 bootnodes per §2.1, the relay:personal ratio is 20:975 = 2%. Per parameter-rationale.md the production relay ratio should be higher for backbone connectivity. Scaling to 1000 personal nodes with only 20 relays is not validated and may not converge in the 120s target.

Additionally, §1.3 says "1000 nodes: /21 (2046 usable IPs)" -- but the zone model shipped in `generate-scale.sh` uses 1 /24 per zone with ≤ 50 personal nodes per zone. 1000 nodes -> 20 zones -> 20 /24s. The /21 flat subnet plan is incompatible with the zone model (TS-03).

**Issue**: The spec promises 1000-node runs but:
1. The topology model in spec (flat /21) is obsolete.
2. The governor profile at 1000 nodes has not been designed -- `hot_max = 10` in spec is wrong (TS-01) and `hot_max = 2` gives each personal node only 2 peers regardless of scale, so convergence MUST rely entirely on epidemic forwarding through relays.
3. Epidemic-hop math: network-protocol.md §7.2 table gives "Hops to converge" -- at R=20 relays with hot_max=50, hop count is log₅₀(20) ≈ 1. At R=1000 personal nodes with 20 relays, the personal layer still converges in 1 hop (every personal node has a relay in Hot via hot_min_relays) + relay-mesh convergence. This works in theory; the spec should cite the math and predict the expected time.
4. §5 step 5 "Request VM resize to 64GB for 500+ nodes" suggests 1000 nodes needs MORE than 64GB, but §1.1 says 1000 nodes fits in 64GB. At 30-50MB per container × 1000 = 30-50GB container RSS alone; realistic target is 96GB+ for safe headroom.

**Resolution**:
1. Downgrade 1000-node target to "stretch goal, Phase 2". 500-node is the realistic Phase 1 ceiling.
2. Update §1.1 memory table. For 1000 nodes, memory budget should be ≥ 96GB, not 64GB.
3. Add a §3.0 sub-note: "Scaling beyond R=500 requires either (a) increasing relay count to maintain backbone fan-out, or (b) accepting slower convergence from increased hop count. See network-protocol.md §7.2 scaling table."
4. Confirm with Martin / capacity planning whether pdukvm20 can host 500+ containers at once.

### TS-07: S4 eclipse scenario under-specified and blocked

**Spec**: §3 S4: Eclipse Resistance (lines 186-198).

**Evidence**: S4 requires "1 victim + 20 attacker nodes" where "attacker nodes connect aggressively to victim". This is fine as a concept but:
1. "Attacker nodes" are not defined. Are they modified Cordelia binaries? Separate processes that open QUIC connections without completing handshake? The spec does not say.
2. §5 step 8 says "S4 (eclipse) requires attacker node implementation -- defer to after S1-S3."
3. attack-trees.md defines the eclipse attack and its defence (random promotion, per-IP limits, trusted peers, banning). The spec does not reference attack-trees.md.
4. The victim is supposed to have "random promotion" per §2.3 (governor) but the pass criterion "Victim's hot set is not dominated by attacker nodes" is not quantified -- what fraction of Hot is "dominated"? ≥50%? ≥1 attacker peer?

**Issue**: S4 is aspirational with no implementation path. The pass criteria are qualitative. A red team test that fails silently (victim's hot set is 5/5 attacker but metrics don't flag it) will be worse than no test.

**Resolution**:
1. Defer S4 to Phase 3 (Governance + Trust per MEMORY.md roadmap).
2. Replace §3 S4 with: "S4 is deferred to Phase 3 when attacker-node scaffolding and trust scoring are available. Phase 1 eclipse resistance is validated via unit tests (random promotion) and attack-trees.md reasoning (quantified cost/benefit)."
3. Cross-reference attack-trees.md as the Phase 1 eclipse-defence spec.
4. For any future reinstatement, specify: attacker implementation (mocked P2P client or modified cordelia binary with `--malicious` flag), victim Hot-set composition quantifier (< 40% attacker peers is pass), per-IP limit verification.

### TS-08: Infrastructure plan missing conntrack flush, Docker buildkit guidance, image build script

**Spec**: §1.2 Kernel Tuning, §1.4 Container Image.

**Evidence**: topology-e2e.md §2.2 (lines 62-85) specifies: `DOCKER_BUILDKIT=0`, `--no-cache`, `cargo build --release --target x86_64-unknown-linux-musl`, `docker builder prune -af`, `docker image prune -af`. The helper is `tests/e2e/build-image.sh`. The Dockerfile includes an `ldd` static-link check. These details are essential because of recurring GLIBC breakage (MEMORY.md: "Docker build reproducibility (added from Cordelia GLIBC recurring failures)").

topology-e2e.md §2.3.1 Known Limitations: "The `run-all.sh` master script flushes conntrack between topologies (`conntrack -F`). Without this, T5 (and other multi-hop topologies) fail intermittently when run after T1-T4."

topology-scale.md §1.4 says "Same `cordelia-test:latest` image as T1-T7. Built with `build-image.sh`." -- but the scale runs may span HOURS and accumulate stale conntrack entries. Running S1/S2/S3 sequentially likely exhibits the same conntrack-stall problem that topology-e2e.md §2.3.1 documents.

**Issue**: Scale-test spec inherits the container image but not the build/runtime hygiene. A new team member running scale tests without reading topology-e2e.md first will hit GLIBC issues, stale conntrack, or stale buildx cache, and conclude the scale tests are broken.

**Resolution**:
1. Add to §1.2: `sudo conntrack -F` between scale runs (in addition to the existing sysctl settings).
2. Add §1.4.1 "Build reproducibility": cite topology-e2e.md §2.2 verbatim or include the `DOCKER_BUILDKIT=0 --no-cache` incantation and the `ldd` check.
3. Add to §5 Implementation Plan: "Prerequisite: all kernel tuning and build hygiene from topology-e2e.md §2.2 and §2.3.1 applies."

---

## MEDIUM

### TS-09: Swarm (PAN) scale testing not mentioned

**Spec**: §3 scenarios.

**Issue**: MEMORY.md notes "Swarm hot_max: HKDF-verified swarm peers always Hot, exempt from governor hot_max." This exemption has scale implications: if a swarm lead spawns 100 children, its Hot set bypasses `hot_max = 2`. The scale test should characterise what happens when a swarm-lead's Hot set is effectively 100+ peers. Likely outcome: push bandwidth explodes for the swarm lead; topology becomes hub-and-spoke. Not necessarily bad, but un-measured.

project_pan_design_needed.md (MEMORY.md) notes PAN design is open. Scale test for PAN would feed the design.

**Resolution**: Add "S6: Swarm scale (deferred to Phase 2)" with a placeholder for: 1 swarm lead + 10/50/100 children, local-scope channel traffic confined to PAN, upstream relay sees 0 swarm-local items. Cross-reference PAN design doc.

### TS-10: `run-scale.sh` named but never defined

**Spec**: §2 generator output `tests/e2e/scale/run-s100.sh`, §5 Implementation Plan "Write `run-scale.sh` test runner with metrics collection".

**Evidence**: Shipped `tests/e2e/scale/run-scale.sh` exists but spec does not define its interface (arguments, env vars, exit codes, artifacts). `run-s2.sh` and `run-s3.sh` also exist -- per-scenario runners are the norm in the repo, not a single `run-scale.sh`.

**Resolution**: Either document the `run-scale.sh` interface (args, env, output) or restructure §5 around the shipped per-scenario runners. Prefer the latter: §5 step 2 "Write per-scenario runner (`run-s<N>.sh`) that calls the Python orchestrator with the right scenario file."

### TS-11: Convergence definition missing for S2 and S3

**Spec**: §3 S2 "Wait for all nodes to have 1000 items", S3 "Wait for convergence".

**Issue**: "Convergence" is polled in topology-e2e.md §3.6 T5 as "both nodes have identical item sets" with a specific timeout formula (3x sync_interval). topology-scale.md leaves the polling interval, timeout, and comparison method unspecified. For S2 at 1000 items × 100 nodes = 100,000 `db_query` rows, a naive poll is expensive.

**Resolution**: Define a "scale-convergence" predicate: "all nodes report `SELECT COUNT(*) FROM items WHERE channel_id = ? AND is_tombstone = 0` = expected_count, polled every 10s, max 300s (§3 S2) or 60s/600s tiers (§3 S3)." Add a ratio-based fast path: "Consider converged if 95% of nodes have the expected count; escalate to full check."

### TS-12: Dedup rate formula is unclear

**Spec**: §4.1 "Dedup rate | `dedup_dropped / (stored + dedup_dropped)` | percentage".

**Issue**: `stored` and `dedup_dropped` are not defined here. Are they per-node counters? Aggregated across the network? For S2 (1000 items × 100 nodes, fan-out expected), naive expectation is that each node stores 1000 items and dedup drops roughly (1000 × (hot_max - 1)) = 1000 (if hot_max=2). So dedup rate ≈ 50% -- not "< 10%" as the pass criteria states.

The "< 10%" target is probably wrong post-pivot. With epidemic forwarding, every relay re-push to N hot peers generates N-1 duplicates. Dedup rate > 50% is expected; < 10% would suggest dedup is BROKEN.

**Resolution**: Rewrite the metric. Use "dedup efficiency" = `dedup_dropped / total_receives` where `total_receives = stored + dedup_dropped`. Pass criterion: dedup_efficiency > 30% (confirms dedup is working); < 5% would indicate dedup is broken. Refine the exact threshold by running the test and reading the actual value.

### TS-13: `max_item_bytes` / seen_table / stream limits not bounded in scale config

**Spec**: §2.3 governor, no reference to data-plane bounds.

**Evidence**: MEMORY.md "Key parameters in code: STREAM_TIMEOUT=10s, MAX_ITEM_BYTES=256KB, hot_max=2 (personal), SEEN_TABLE_MAX=10000, SEEN_TABLE_TTL_SECS=600". network-protocol.md §7.2 specifies SEEN_TABLE_MAX as tunable. In a scale test that publishes 1000 items (S2) through 10 relays, each relay's SeenTable sees up to 1000 unique content hashes -- well under 10,000. But S2 at 100 publishers × 1000 items = 100,000 items would overflow the default SEEN_TABLE_MAX and trigger LRU eviction, changing dedup behaviour.

**Resolution**: Add §2.4 "Data-plane parameters" listing: STREAM_TIMEOUT, MAX_ITEM_BYTES, SEEN_TABLE_MAX, SEEN_TABLE_TTL, max_batch_size. Note which scenarios are near the limits. Specifically call out that S2 total items (10 publishers × 100 items = 1000) is well under SEEN_TABLE_MAX; larger-scale variants need to tune up.

### TS-14: Python orchestrator and metrics capture undocumented

**Spec**: §4 Measurement Framework.

**Evidence**: `tests/e2e/harness/orchestrator.py` and `tests/e2e/harness/query.py` are the execution engine for scale tests (per MEMORY.md: "Test harness: Concurrent orchestrator (ThreadPoolExecutor), token caching, publish retries, scaled timeouts"). They drove the R=50/100/200 results.

topology-scale.md §4 describes metrics but not the tool that collects them. `docker stats`, `grep WARN logs`, `db_query` are suggested as methods -- but the actual tool is the Python orchestrator.

project_test_harness_design.md (MEMORY.md) notes this is an open design doc.

**Resolution**: Add §4.0 "Test harness" pointing at `harness/orchestrator.py` (execution) and `harness/query.py` (post-run analysis). Add §4.3 "SQLite metrics store" referencing `harness/schema.sql` (exists in the repo, not mentioned here) which is the design artefact for the metrics pipeline.

### TS-15: Reporting CSV schema (§4.2) has stale example values

**Spec**: §4.2 Reporting example:
```
scale,nodes,convergence_secs,items_per_node,dedup_rate,push_timeouts,memory_mb
50,50,15,10,0.02,0,35
100,100,18,10,0.04,2,38
500,500,22,10,0.08,5,42
```

**Issue**: MEMORY.md reports R=50 = 19s, R=100 = 17s. The example shows 15s and 18s. Close but not matching. The `dedup_rate` example values (0.02-0.08) conflict with TS-12 where real dedup rate should be > 0.3. The 500-node row is speculative (no validation).

**Resolution**: Replace example with actual run data from the latest sessions (R=50: 152/152 at 19s, R=100: 302/302 at 17s, R=200: relays 200/200). Remove the speculative R=500 row; add an "Actual results as of 2026-03-20" section.

### TS-16: S5 partition spec has no iptables details, no heal criteria

**Spec**: §3 S5 Partition at Scale.

**Issue**: topology-e2e.md §3.6 T5 has 20+ lines of iptables partition/heal scripting. topology-scale.md §3 S5 says "Partition via iptables (relay group A cannot reach relay group B)" without specifying:
- Which relays go in group A vs B? The generator currently has no "relay group" parameter.
- How is the partition applied to N relays? For every pair (A, B), iptables DROP? That's O(N²) rules.
- What defines "heal"? Single-relay reconnect? All relays reconnect simultaneously?

At R=500 with 10 relays, splitting 5:5 with bilateral iptables rules is manageable. At R=1000 with 20 relays, splitting 10:10 is 100 bilateral rules.

**Resolution**: Add a concrete partition procedure: "Split relays into group A (first half by index) and group B (second half). Apply iptables DROP on internet interface of each relay against every relay in the opposing group. Heal by `conntrack -F` + removing drop rules in reverse." Reference topology-e2e.md §3.6 syntax.

---

## LOW

### TS-17: References section missing

**Spec**: Footer cross-ref line only: "Cross-refs: network-protocol.md §5 (Peer Governor), topology-e2e.md (T1-T7)".

**Issue**: No dedicated references section. Missing: parameter-rationale.md (governor values), demand-model.md (fan-out and bandwidth), attack-trees.md (S4 defence), operations.md (metrics, health), decisions/2026-03-10-testing-strategy-bdd.md (Layer 2 positioning).

**Resolution**: Add §6 References table modelled on topology-e2e.md §13.

### TS-18: Phase boundaries not marked

**Spec**: Entire document.

**Issue**: topology-e2e.md has explicit §11 Phase Boundaries (Phase 1 / 2 / 3). topology-scale.md does not. Readers cannot tell which scenarios are Phase 1 committed vs Phase 2+ aspirational. Based on evidence: S1 is Phase 1 (shipped), S2/S3 are Phase 1 (shipped), S4 is blocked (see TS-07), S5 is aspirational (no generator).

**Resolution**: Add §6 Phase Boundaries. S1/S2/S3 = Phase 1 (shipped). S4 = Phase 3 (requires trust scoring). S5 = Phase 2 (larger scale + partition). S6 (swarm, TS-09) = Phase 2.

### TS-19: `SS` notation for sections absent; spec uses `§` inconsistently

**Spec**: passim.

**Issue**: topology-scale.md uses `§` (the correct house style per review-topology-e2e). The only cross-reference is in the footer "network-protocol.md §5". Fine. But within the text, sections are referenced as "S1-S5", not "§3.1-§3.5". Readers cross-referencing section numbers may be confused.

**Resolution**: When referring to scenarios, use both: "S1 (§3.1)" on first mention, "S1" thereafter. Otherwise the spec is consistent.

---

## Passes Not Applied

| Pass | Reason |
|------|--------|
| 5 (Economic) | Not applicable -- scale testing spec, no direct economic incentive design |
| 6 (Attack Trees) | Covered by attack-trees.md; S4 eclipse scenario cross-references it (see TS-07) |
| 7 (Terminology) | Covered by review-terminology.md and glossary.md |
| 9 (Test Vectors) | Not applicable -- this is a runtime test spec, not a wire format spec |
| 10 (Privacy) | Not applicable -- scale testing does not expose new metadata surfaces |
| 13 (Compliance) | Not applicable at scale-test layer |
| 14 (Data Model) | Not applicable |
| 15 (Build Verification) | Partial -- the harness exists but this review is pre-implementation-check for the spec itself |

---

## Recommended Triage

**Fix before Phase 1 close (CRITICAL + directly actionable):**
- **TS-01** Governor profile `hot_max = 10` is wrong -- pick authoritative `hot_max = 2`. One-edit fix in §2.3.
- **TS-02** Add §3.0 "Protocol features under test" enumerating epidemic forwarding / seen_table / role-aware gating / batched sync and mapping each to scenarios. This is the top spec-correctness issue.
- **TS-03** Replace flat /22 /21 network model with zone model; cite topology-e2e.md §2.3 and §12.
- **TS-04** Reconcile S1/S2/S3 spec scenarios with shipped `generate-s*.sh` generators. Mark S4/S5 as not-implemented.

**Fix in one editing session (doc polish + spec corrections):**
- TS-05 add `hot_min_relays` to governor config.
- TS-06 mark 1000-node as Phase 2 stretch; reconcile §1.1 and §5 memory budgets.
- TS-08 add conntrack flush + build hygiene references to §1.
- TS-10 document or remove `run-scale.sh`.
- TS-14 document Python orchestrator + metrics schema.
- TS-17 add References table.
- TS-18 add Phase Boundaries section.

**Fix opportunistically (MEDIUM/LOW, improves quality but not blocking):**
- TS-09 swarm scale (defer to Phase 2 design doc).
- TS-11 define convergence predicate for S2/S3.
- TS-12 dedup rate formula + threshold.
- TS-13 data-plane parameters table.
- TS-15 replace stale example CSV with actual run data.
- TS-16 concretise S5 partition procedure.
- TS-19 section notation polish.

**Defer to Phase 2 / 3:**
- TS-07 S4 eclipse -- requires attacker-node implementation + trust scoring.
- TS-09 S6 swarm scale -- requires PAN design first.

---

## Cross-Spec Observations

Not findings for this spec, but surfaced during review:

- **network-protocol.md §7.2 "Hops to converge" table** (line 1223) is the authoritative scaling model that topology-scale.md should cite. Without it, the spec's claim of "constant convergence time" appears to be a wish rather than a prediction.
- **`harness/schema.sql`** exists as the SQLite metrics schema used by `harness/query.py`. It is not referenced in ANY spec. That file is the de-facto metrics ontology for scale testing and deserves a spec paragraph somewhere (either in topology-scale.md §4 or in a new measurement-framework.md).
- **MEMORY.md "R=30 PPZ=7 452/452"** -- "PPZ = personal per zone" configuration is run somewhere but not described in any spec. That scenario produced the strongest convergence data point (452/452); it belongs in the scale-scenario catalogue as S7 or as a variant of S1.
- **cordelia-node#9 (FIXED)** resolution -- the root-cause write-up belongs in a "Lessons Learned from Scale Testing" appendix or sidebar. Currently the fix is noted in MEMORY.md but not in any spec. Future reviewers will re-discover the problem.
- **Publish reliability at R=200** -- MEMORY.md notes "harness publish reliability at R=200" as remaining work. That's a harness-level issue but the scale spec should describe the expected failure mode (publish retries, idempotency).

---

*Review complete 2026-04-17.*
