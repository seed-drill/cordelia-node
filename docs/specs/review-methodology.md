# Specification Review Methodology

**Version**: 1.6
**First applied**: Cordelia Phase 1 specs (2026-03-10/11)
**Authors**: Russell Wing, Claude

---

## 1. Purpose

A systematic, repeatable process for reviewing protocol and API specifications before implementation handoff. Each review pass applies a different analytical lens. The passes are ordered so that earlier passes fix structural issues that would confuse later passes.

This methodology is designed to be:
- **Iterative**: Run passes in order, fix issues between passes, re-run if significant changes made
- **Composable**: Not all passes are needed for every spec. Use the selection matrix (§4) to choose.
- **Reusable**: Applicable to any technical specification, not project-specific
- **Cumulative**: Each application adds to the application record (§7), building institutional knowledge

---

## 2. Review Passes

### Pass 1: Gap Analysis

**Question**: Is anything missing?

**Checklist:**
- Undefined references (spec A mentions concept from spec B that doesn't exist)
- Sections promised in table of contents but not written
- Fields referenced in examples but not defined in schemas
- Edge cases mentioned in prose but not specified
- Cross-references that point to wrong section numbers
- Missing diagrams or data flow descriptions

**Output**: List of gaps with severity (CRITICAL / HIGH / MEDIUM / LOW).

### Pass 2: Underspecification

**Question**: Could two reasonable engineers implement this differently?

**Checklist:**
- Ambiguous language ("should", "may", "generally", "typically" -- use RFC 2119 keywords precisely)
- Missing field types, sizes, or encoding
- Unspecified defaults
- Ranges without bounds (e.g., "a timeout" without specifying what value)
- Conditional logic without exhaustive case coverage
- "TBD", "TODO", "TBC" markers
- Implicit ordering assumptions

**Output**: List of ambiguities, each with a proposed resolution.

### Pass 3: Security

**Question**: What can an attacker break?

**Checklist:**
- Authentication bypass paths
- Forgery vectors (unsigned fields that affect behaviour)
- Replay attack surfaces
- Injection points (SQL, command, XSS, FTS5, CBOR deserialization)
- Cryptographic misuse (nonce reuse, missing AAD binding, weak KDF parameters, variant confusion)
- Information disclosure via error messages
- Denial of service amplification
- Trust boundary violations (what crosses the encryption boundary?)

**Output**: Vulnerability list with severity, each with a proposed fix.

### Pass 4: Architecture / Cross-Spec Consistency

**Question**: Do the specs fit together?

**Checklist:**
- Data flows across spec boundaries (API -> wire format -> storage -> replication)
- Field names that differ between specs for the same concept
- Assumptions in one spec that contradict another
- Layering violations (e.g., API spec assumes wire format details)
- Missing integration points
- Topology / role interactions (do all node types behave correctly in all combinations?)

**Output**: Inconsistency list, each with the canonical resolution.

### Pass 5: Economic / Game Theory

**Question**: Can rational actors exploit the system?

**Checklist:**
- Free-riding opportunities (consume without contributing)
- Sybil attack economics (cost to create identities vs benefit)
- Griefing vectors (low-cost actions that impose high cost on others)
- Incentive alignment (do participants benefit from honest behaviour?)
- Resource exhaustion (storage, bandwidth, compute, connection slots)
- Missing rate limits or quotas
- Equilibrium analysis (is honest behaviour a Nash equilibrium?)
- Defection detection and punishment (are penalties credible and enforceable?)

**Output**: Gap list with severity (CRITICAL = broken equilibrium, HIGH = exploitable, MEDIUM = suboptimal, LOW = theoretical).

### Pass 6: Attack Trees

**Question**: For each attacker persona, is every strategy unprofitable?

**Checklist:**
- Define attacker personas (budget, goal, motivation)
- Enumerate attack strategies per persona
- Quantify cost to execute, damage to network, ROI
- Verify ROI < 1 for all attacks against specified defences
- Identify accepted risks (conscious design choices with documented Phase N mitigations)
- Verify defence mechanisms are specified, not just mentioned
- Check for multi-step / compound attacks that combine weaker vectors

**Output**: Formal cost-benefit analysis document. Gate: all ROI < 1 or explicitly accepted with documented mitigation timeline.

**Template per attack:**
```
Attack:      <name>
Persona:     <who>
Budget:      <cost to attacker>
Goal:        <what they achieve>
Strategy:    <step-by-step>
Cost:        <quantified>
Damage:      <quantified>
Defence:     <spec reference>
Residual:    <what remains>
ROI:         <gain / cost>
Verdict:     <profitable | unprofitable | accepted risk>
```

### Pass 7: Terminology Consistency

**Question**: Does the same word always mean the same thing?

**Checklist:**
- Build a glossary from all specs
- Flag terms used inconsistently across specs
- Flag terms used but never defined
- Flag synonyms that should be unified
- Verify consistent casing, hyphenation, and formatting conventions
- Check: do API field names match wire format field names match storage column names?

**Output**: Glossary additions/corrections, spec edits for consistency. Optionally a `glossary.md`.

### Pass 8: Implementability

**Question**: Can the implementer build this without asking a clarifying question?

**Checklist:**
- Walk through each spec section as if implementing it
- Flag any point where you'd need to make a judgement call
- State machines: are all states and transitions defined? Any unreachable or inescapable states?
- Error paths: every API endpoint has success AND failure cases specified (HTTP status, error body, P2P rejection reason)
- Ordering / timing: all timeouts specified, race conditions addressed, interleaving defined
- Circular dependencies between specs
- Configuration: all tuneable parameters have defaults, types, and valid ranges
- Boundary conditions: what happens at limits? (max size, max count, empty input, zero peers)

**Storage and data format completeness** (the "just build it" check, added 2026-03-12):
- Storage schemas: are all tables/collections defined with DDL or equivalent? If a spec says "stored in a table" or "persisted to disk", is the schema defined somewhere?
- Wire formats: are all message types fully specified with field order, types, and byte sizes? No "a CBOR structure containing..." without defining the fields.
- File formats: are all persisted file formats specified (binary layout, JSON schema, encoding)?
- Special-case items: are there item types or message types that bypass the normal processing path (e.g., items not encrypted with the standard key)? Is the alternate path fully specified?
- Format transitions: when data moves between layers (API request -> storage row -> wire message -> file), is each transformation explicit? Can you trace a field from API input to storage column to wire format without ambiguity?
- Column-to-API mappings: for every field in an API response, can you point to the storage column or computation that produces it?

**Output**: Question list (things the implementer would need to ask), each with a proposed answer to embed in the spec.

### Pass 9: Test Vectors

**Question**: Can we verify cross-implementation correctness?

**Checklist:**
- Identify all deterministic transformations (encoding, hashing, signing, encryption, derivation)
- Generate test vectors using a reference implementation (not hand-written)
- Verify round-trip (encode -> decode -> compare bytes)
- Include error cases (invalid input, corrupted data, wrong variant)
- Document derived values and their computation
- Verify predicted sizes/lengths match actual output

**Output**: Test vectors embedded in spec (not a separate document), with hex values, expected results, and computation steps.

### Pass 10: Metadata Privacy Analysis

**Question**: What can a passive observer learn?

**Checklist:**
- Per message type: what metadata is visible to non-subscribers?
- Connection graph leakage (who talks to whom, how often)
- Channel membership inference (from connection patterns, message sizes, timing)
- Timing correlation (message frequency, size patterns, burst detection)
- Enumerate what each role/position can observe (personal, relay, bootnode, keeper, ISP, adversary on same LAN)
- Identify what is encrypted vs plaintext at each hop
- Traffic analysis resistance (or lack thereof)

**Output**: Privacy exposure matrix (message type x observer position x what's visible). Accepted risks documented with mitigation timeline.

### Pass 11: Operational Readiness

**Question**: Can we run, monitor, and debug this in production?

**Checklist:**
- Monitoring: are all metrics defined? (names, types, labels, units)
- Logging: what gets logged at each level? Any PII or secrets in logs?
- Configuration: are all tuneable parameters documented with defaults, types, and valid ranges?
- Upgrade path: wire format versioning, rollback procedure, data migration
- Failure modes: disk full, OOM, unclean shutdown, clock skew, network partition
- Deployment: resource requirements (CPU, RAM, disk, bandwidth), scaling characteristics
- Backup / recovery: data durability, disaster recovery procedure
- Health checks: liveness, readiness, startup probes

**Output**: Operational checklist, gaps to address before production release.

### Pass 12: Error Catalog

**Question**: Are all failure modes enumerated with consistent structure?

**Checklist:**
- HTTP status codes for every API endpoint, every error case
- P2P rejection reasons for every message type
- Error body schema: consistent structure across all errors (error_code, message, details)
- Retry guidance: which errors are retryable? With what backoff?
- Client-facing error messages: clear, actionable, no information leakage
- Error code namespace: are codes unique, documented, and stable across versions?
- SDK error types: do they map cleanly to API errors?

**Output**: Error catalog document or additions to existing specs.

---

## 3. Severity Definitions

| Severity | Definition | Action |
|----------|-----------|--------|
| CRITICAL | Breaks correctness, security, or economic equilibrium | Must fix before implementation |
| HIGH | Significant ambiguity or vulnerability, likely to cause implementation bugs | Should fix before implementation |
| MEDIUM | Minor ambiguity or suboptimal design, unlikely to block implementation | Fix during implementation or before release |
| LOW | Cosmetic, stylistic, or theoretical concern | Fix when convenient |

---

## 4. Selection Matrix

Not every project needs all 12 passes. Choose based on what you're building.

| Pass | Internal API | Public API / SDK | P2P Protocol | Economic System | Regulatory |
|------|:-----------:|:---------------:|:------------:|:---------------:|:---------:|
| 1: Gap Analysis | Y | Y | Y | Y | Y |
| 2: Underspecification | Y | Y | Y | Y | Y |
| 3: Security | Y | Y | Y | Y | Y |
| 4: Architecture | -- | Y | Y | Y | -- |
| 5: Economic | -- | -- | -- | Y | -- |
| 6: Attack Trees | -- | -- | Y | Y | -- |
| 7: Terminology | -- | Y | Y | -- | Y |
| 8: Implementability | Y | Y | Y | Y | Y |
| 9: Test Vectors | -- | Y | Y | -- | -- |
| 10: Privacy | -- | -- | Y | -- | Y |
| 11: Operational | Y | Y | Y | -- | -- |
| 12: Error Catalog | -- | Y | Y | -- | -- |

**Minimum set** (any spec): Passes 1, 2, 3, 8
**Recommended for handoff**: Passes 1-4, 7-8
**Full protocol review**: All 12

---

## 5. Sequencing

Recommended execution order for a full review. Earlier passes fix structural issues that would generate false positives in later passes.

```
Phase A: Structural (fix the skeleton)
  Pass 1: Gap Analysis              find what's missing
  Pass 2: Underspecification         tighten what's vague

Phase B: Safety (find what's broken)
  Pass 3: Security                   find vulnerabilities
  Pass 4: Architecture               find contradictions
  Pass 5: Economic                   find exploitable incentives
  Pass 6: Attack Trees               validate defences quantitatively

Phase C: Verification (prove correctness)
  Pass 9: Test Vectors               generate reference values

Phase D: Handoff (prepare for implementation)
  Pass 7: Terminology                ensure shared language
  Pass 8: Implementability           eliminate ambiguity
  Pass 12: Error Catalog             enumerate failure modes

Phase E: Production (prepare for release)
  Pass 10: Privacy                   enumerate exposure
  Pass 11: Operational               enumerate ops requirements
```

Fix issues between phases. If Phase B produces significant spec changes, re-run Phase A to verify no new gaps.

---

## 6. Output Conventions

### Finding Format

Each finding across all passes uses a consistent structure:

```
ID:           <Pass>-<Number> (e.g., S-03 for Security finding 3)
Severity:     CRITICAL | HIGH | MEDIUM | LOW
Spec:         <filename> §<section>
Issue:        <what's wrong or missing>
Resolution:   <concrete fix to embed in the spec>
```

### Output Documents

| Pass | Output file |
|------|-------------|
| 1-4 | Findings embedded directly in specs (fix as you go) |
| 5 | Tracked in issue tracker (e.g., s&p#10) |
| 6 | `specs/attack-trees.md` |
| 7 | `specs/review-terminology.md` + optional `specs/glossary.md` |
| 8 | `specs/review-implementability.md` |
| 9 | Test vectors embedded in specs |
| 10 | `specs/review-privacy.md` |
| 11 | `specs/review-operational.md` |
| 12 | `specs/review-errors.md` or additions to API specs |

### Methodology Document

This document (`specs/review-methodology.md`) travels with the specs. Each project maintains its own copy with its application record (§7).

---

## 7. Application Record

### Cordelia Phase 1 (2026-03-10/11)

**Specs reviewed**: 5 (ecies-envelope-encryption.md, channels-api.md, channel-naming.md, sdk-api-reference.md, network-protocol.md)

| Pass | Status | Findings | Output |
|------|--------|----------|--------|
| 1: Gap Analysis | Complete (x2) | First pass: 20 gaps, 4 CRITICAL. Second pass (post-review): 2 HIGH + 3 MEDIUM + 3 LOW. All resolved. | Fixed in specs |
| 2: Underspecification | Complete | Multiple fields, defaults, and edge cases tightened. | Fixed in specs |
| 3: Security | Complete | 3 HIGH + 8 MEDIUM vulnerabilities found and fixed. | Fixed in specs |
| 4: Architecture | Complete (x2) | First pass: 3 critical + 7 high + 8 medium + 7 low. Second pass: merged with gap re-run, 8 findings total. All resolved. | Fixed in specs |
| 5: Economic | Complete | 2 CRITICAL + 6 HIGH + 9 MEDIUM gaps (s&p#10). All resolved. | network-protocol.md §16 |
| 6: Attack Trees | Complete | 14 attacks, 6 personas. All ROI < 1. | specs/attack-trees.md |
| 7: Terminology | Complete | 6 inconsistencies (acceptable), 5 undefined terms. Glossary produced. | specs/review-terminology.md |
| 8: Implementability | Complete | 4 CRITICAL + 11 HIGH + 10 MEDIUM. PSK flow, CBOR compat, DM derivation. | specs/review-implementability.md |
| 9: Test Vectors | Complete | 7 Bech32 + 3 CBOR vectors. All round-trip verified. | ecies-envelope-encryption.md §3.6, §8.5, §8.6 |
| 10: Privacy | Complete | 33 findings. 1 Phase 1 fix (metrics endpoint leaks channel names). Rest accepted with Phase 2-4 mitigations. Exposure matrix produced. | specs/review-privacy.md |
| 11: Operational | Not run | Deferred to pre-release. Martin will surface during implementation. | -- |
| 12: Error Catalog | Complete | 35 findings. 401 auth errors missing from all 15 endpoints. Rate limit errors not in endpoint docs. P2P rejection formats undefined. Retryability matrix produced. | specs/review-errors.md |

**Total findings**: 11 passes completed (passes 1 and 4 run twice). ~90 issues found and resolved across passes 1-6, 9. Second-pass findings: anchor keeper/peer-to-peer contradiction (G-01), missing list-dms/list-groups API endpoints (G-02), vestigial created_at/updated_at in ECIES §7 (G-04), SDK Item.id inconsistency (G-06). 25 implementability issues, 33 privacy findings, 35 error catalog findings documented for Martin review. Glossary produced.

### Operations Spec (2026-03-11)

**Spec reviewed**: operations.md (passes 1, 2, 3, 4, 8)

| Pass | Findings | Summary |
|------|----------|---------|
| 1: Gap Analysis | 6 (2 HIGH, 1 MEDIUM, 3 LOW) | Key path mismatch with ECIES spec, peer count mismatch with network-protocol, missing health endpoint in channels-api surface, missing export command, cross-platform stat command, config.toml role/listen_addr fields |
| 2: Underspecification | 5 (2 HIGH, 3 MEDIUM) | Pairing code character set unspecified, entity ID validation regex missing, daemon flag ambiguity, tilde expansion undefined, export format undefined |
| 3: Security | 5 (2 HIGH, 2 MEDIUM, 1 LOW) | Pairing shares private keys (documented risk), curl\|sh integrity, unauthenticated health endpoint info leak, pairing code storage at bootnode, GDPR for centralised logging |
| 4: Architecture | 5 (2 HIGH, 2 MEDIUM, 1 LOW) | Key path inconsistency with ECIES §2, peer counts vs network-protocol §5, channel type visibility, config.toml network section gaps, health endpoint missing from API surface |
| 8: Implementability | 6 (2 HIGH, 2 MEDIUM, 2 LOW) | Pairing wire protocol unspecified, pairing code lifecycle unspecified, init→service handoff unclear, upgrade rollback mechanism, backup key display security, p2p address split |

**Total**: 27 findings (9 HIGH, 10 MEDIUM, 8 LOW). All resolved:
- 22 findings fixed directly in operations.md
- 3 cross-spec fixes (channels-api.md health endpoint, network-protocol.md §4.8 pairing protocol + §3.3 protocol byte)
- 2 findings addressed by adding pairing wire protocol to network-protocol.md (I-01, I-02)

### Security Re-Pass (2026-03-11)

**Specs reviewed**: operations.md, network-protocol.md §4.8 (pass 3 only, post-pairing protocol addition)

| Pass | Findings | Summary |
|------|----------|---------|
| 3: Security | 13 (4 HIGH, 6 MEDIUM, 3 LOW) | HMAC computation paradox (S-12), node token in CI stdout (S-03), malicious bootnode pairing race (S-04), stale key paths x3 (S-02/S-07/S-09), fingerprint verification timing (S-05), joiner key semantics (S-06), install script RC file modification (S-01), health endpoint enumeration (S-08), secrets grep pattern (S-10), container --daemon flag + checksum (S-11), PairBundle channel list exposure (S-13) |

**Total**: 13 findings (4 HIGH, 6 MEDIUM, 3 LOW). All resolved:
- 11 findings fixed in operations.md (stale paths, token redaction, pairing trust model, container Dockerfile, security checklist)
- 5 findings fixed in network-protocol.md §4.8 (HMAC computation model, single-connection guard, fingerprint gating, joiner key clarification, channel list exposure documentation)
- Some findings touch both specs (pairing flow consistency)

### Memory Model Spec (2026-03-12)

**Spec reviewed**: memory-model.md (passes 1, 2, 3, 4, 8)

| Pass | Findings | Summary |
|------|----------|---------|
| 1: Gap Analysis | 10 (3 HIGH, 5 MEDIUM, 2 LOW) | Chain genesis undefined, item_type not registered in channels-api, key path inconsistent with ECIES spec, __personal cross-refs, embedding pipeline unspecified, sweep interval missing, share/harvest mechanics, domain inference algorithm, L3 forward reference, MCP tool mapping |
| 2: Underspecification | 11 (2 HIGH, 7 MEDIUM, 2 LOW) | L1/L2 size limits undefined, novelty threshold missing, confidence field undefined, TTL access refresh semantics, hybrid scoring configurability, chain recovery priority, source_session scope, prefetch budget definition, pre-pivot terminology residue x2, L1 schema versioning |
| 3: Security | 6 (2 HIGH, 3 MEDIUM, 1 LOW) | Integrity chain no domain separation, cross-channel FTS5 isolation, memory item_type traffic analysis, expiry tombstone replication leakage, GDPR tombstone content_hash, key path exposure |
| 4: Architecture | 8 (3 HIGH, 4 MEDIUM, 1 LOW) | item_type collision with app types, SDK search filters missing from sdk-api-reference, shared lifecycle gap, __personal in channel-naming, Phase 2 SDK methods unlabelled, content_hash ambiguity, phase boundary alignment, Anthropic adapter view mapping |
| 8: Implementability | 9 (2 HIGH, 6 MEDIUM, 1 LOW) | L1 well-known item_id undefined, domain default undefined, chain content_hash exclusion boundary, memory field requirements, hybrid scoring edge cases, archive vs delete logic, context() implementation, prefetch value-domain cap, SDK content convention |

**Total**: 44 findings (0 CRITICAL, 12 HIGH, 25 MEDIUM, 7 LOW). All resolved:
- 44 findings fixed in memory-model.md (domain separation, size limits, field tables, phase labels, sweep config, prefetch caps, novelty threshold, embedding pipeline, cross-channel isolation, tombstone semantics)
- 3 cross-spec backports: channels-api.md (memory:* item types + search types/since filters), sdk-api-reference.md (SearchOptions interface with types/since)

### New Passes: Compliance + Data Model (2026-03-12)

**Passes added**: 13 (Compliance & Regulatory Alignment), 14 (Data Model Consistency). Contributed by OSA Claude (AdaVault context), refined with GDPR/UK DPA specificity, canonical data model fallback, and Internal API column for Pass 14.

**Specs reviewed**: All 7 (ecies-envelope-encryption.md, channels-api.md, channel-naming.md, sdk-api-reference.md, network-protocol.md, operations.md, memory-model.md)

| Pass | Findings | Summary |
|------|----------|---------|
| 13: Compliance | 14 (2 HIGH, 5 MEDIUM, 7 LOW) | GDPR/UK DPA gaps (C-1), tombstone erasure legal defence (C-2), compliance phase mismatch (C-3), missing framework mapping (C-4), export security (C-5), audit trail clarification (C-6), data residency (C-7), controller determination (C-8), enterprise install (C-9), metrics token scoping (C-10), PQC forward reference (C-11), automated processing Art. 22 (C-12), breach notification (C-13), data retention config (C-14) |
| 14: Data Model | 19 (1 CRITICAL, 5 HIGH, 8 MEDIUM, 5 LOW) | Listen response missing item_type/parent_id (DM-001), identity field mapping (DM-002), search response missing fields (DM-003), entity_id derivation mismatch (DM-004), publish response missing item_type (DM-005), TV-C2 wrong mode enum (DM-006), personal channel ID cross-ref (DM-007), subscribe response gaps (DM-008/009), content_length internal (DM-010), author_id description (DM-011), author vs author_id naming (DM-012), content_hash exposure (DM-013), config.toml section (DM-014), init idempotency (DM-015), bootnode hostname (DM-016), types prefix (DM-017), key_version internal (DM-018), system item_id format (DM-019) |

**Total**: 33 findings (1 CRITICAL, 7 HIGH, 13 MEDIUM, 12 LOW). All resolved:
- 6 fixes in channels-api.md (listen/publish/search response fields, subscribe timestamps, author naming, identity field mapping note)
- 7 fixes in ecies-envelope-encryption.md (entity_id derivation, TV-C2 mode, personal channel cross-ref, author_id description, init idempotency, content_length internal, PQC note)
- 3 fixes in sdk-api-reference.md (identity field mapping, ChannelHandle fields, custom mapping exception)
- 10 fixes in memory-model.md (UK DPA §11.5, erasure defence, compliance phase, data residency, Art. 22 note, retention config, types prefix, system item_id, content_hash, C-14)
- 6 fixes in operations.md (export security, audit trail, enterprise install, breach notification, governor config, bootnode hostname)
- Skill updated: passes 13+14 added, selection matrix expanded, Phase C added to sequencing

### New Specs: Configuration, Search-Indexing, Identity (2026-03-12)

**Specs reviewed**: configuration.md, search-indexing.md, identity.md (passes 1, 2, 3, 4, 8)

| Spec | Findings | CRITICAL | HIGH | MEDIUM | LOW |
|------|----------|----------|------|--------|-----|
| configuration.md | 17 | 0 | 4 | 9 | 4 |
| search-indexing.md | 22 | 1 | 7 | 11 | 3 |
| identity.md | 18 | 0 | 5 | 8 | 5 |
| **Total** | **57** | **1** | **16** | **28** | **12** |

**Key findings resolved:**

- **CRITICAL (1)**: sqlite-vec `vec0` DDL used invalid `TEXT PRIMARY KEY`. Replaced with rowid-based mapping table (`search_vec_map`). All 6 downstream SQL references updated.
- **HIGH -- configuration.md (4)**: Missing `[search]` parameters (4 added from search-indexing.md), file permission SHOULD/MUST inconsistency fixed, validation behaviour contradiction with search-indexing.md reconciled, redundant port specification construction rule added.
- **HIGH -- search-indexing.md (7)**: channels-api.md described search as FTS5-only (updated to hybrid), `semantic_available` response field added, FTS5 special character sanitization table added, content update re-embedding path specified, deferred indexing crash recovery added, validation clamping replaced with refuse-to-start (per configuration.md), FTS5 JOIN performance note added.
- **HIGH -- identity.md (5)**: Layer numbering renumbered 0-3 (was 1-4, now matches ADR), DM domain separation noted as superseding ADR simplified formula, attestation signing input format specified (RFC 8785 JCS), pairing fingerprint verification UX expanded, TLS/Ed25519 key relationship clarified.

**Cross-spec backports (4 files touched):**

- channels-api.md: Search description updated from FTS5-only to hybrid, `semantic_available` added to response, behaviour steps updated
- configuration.md: Search parameters synchronised with search-indexing.md, cross-reference index updated
- search-indexing.md: Validation behaviour aligned with configuration.md as canonical
- identity.md: Layer numbering aligned with ADR, DM formula relationship to ADR documented

### Topology E2E Spec (2026-03-12)

**Spec reviewed**: topology-e2e.md (passes 1, 2, 3, 4, 8)

| Pass | Findings | Summary |
|------|----------|---------|
| 1: Gap Analysis | 8 (4 HIGH, 3 MEDIUM, 1 LOW) | `subscriptions` table referenced but doesn't exist (G-01), `[[network.seed_peers]]` invented (G-02), PSK file naming channel name vs channel_id hash mismatch (G-03), no container port mappings (G-04), bootnode config example missing (G-05), missing logging config section (G-06), api_query GET/POST conflation (G-07), Compose file naming inconsistency (G-08) |
| 2: Underspecification | 7 (3 HIGH, 3 MEDIUM, 1 LOW) | Harness script $? bug (U-01), artifact collection always skipped (U-02), healthcheck assumes /api/v1/health exists (U-03), Docker image tag pinning (U-04), entrypoint.sh --name flag undefined (U-05), CORDELIA_E2E=1 escape hatch undocumented (U-06), node-token generation undefined (U-07) |
| 3: Security | 2 (1 HIGH, 1 MEDIUM) | CORDELIA_E2E=1 security bypass (S-01), partition method assumes iptables available (S-02) |
| 4: Architecture | 3 (1 HIGH, 2 MEDIUM) | api_query uses POST for GET endpoints (X-01), 0.0.0.0 bind unnecessary with docker exec (X-02), channel subscribe/publish endpoints don't match channels-api.md (X-03) |
| 8: Implementability | 10 (0 HIGH, 7 MEDIUM, 3 LOW) | Artifact collection bug (I-01), harness ERRORS array quoting (I-02), PSK mounting path mismatch (I-03), wait_for eval injection risk (I-04), db_query assumes SQLite path (I-05), coverage denominator TBD (I-06), T5 iptables -F too broad (I-07), healthcheck retries math (I-08), Docker image layer caching (I-09), assert_no_psks glob edge case (I-10) |

**Total**: 30 findings (0 CRITICAL, 9 HIGH, 15 MEDIUM, 6 LOW).

**Top 4 priority fixes actioned (2026-03-12):**

1. **(U-06 + X-02 + S-01)**: Removed `CORDELIA_E2E=1` from all Compose definitions. Set `api.bind_address = "127.0.0.1"` (loopback). All queries use `docker exec` so loopback is sufficient -- no escape hatch needed.
2. **(G-01)**: Replaced `subscriptions` table reference in `assert_channel_isolation` with argument-based approach. Callers pass expected channel_ids explicitly. T7 assertion SQL replaced with bash calls. T1 test script updated.
3. **(G-02)**: Replaced invented `[[network.seed_peers]]` with `[[network.bootnodes]]` (per configuration.md SS2.2). Relay listed as additional bootnode to force relay path in T2.
4. **(G-03 + I-03)**: Added `channel_id_for()` hash function to common.sh (`SHA-256(channel_name)`, hex). PSK mounting flow specified end-to-end: harness generates key as `<channel_id>.key`, Compose mounts to `channel-keys/<channel_id>.key`. CI workflow updated. T1 test script uses `channel_id_for()` instead of API lookup.

**Remaining findings actioned (2026-03-12):**

5. **(S-02)**: Added `iptables` package to Dockerfile. Partition simulation now has required binary.
6. **(I-09)**: Reordered Dockerfile layers -- `COPY` binary last for better cache hits. `ARG BINARY` parameterised.
7. **(U-05 + U-07)**: Documented `--name` flag (operations.md SS2.1) and node-token generation (`cordelia init` produces it, operations.md SS2) in entrypoint section.
8. **(G-06)**: Added `[logging] level = "debug"` to test config example (required for P8/P9 log assertions).
9. **(G-05)**: Added full bootnode config example (`b1.toml`). Notes on relay config differences.
10. **(G-04)**: Added explicit note that no host port mappings are needed (docker exec + bridge network).
11. **(I-08)**: Reduced healthcheck retries from 12 to 6, increased start_period from 10s to 15s (total wait: 15 + 6*5 = 45s, down from 10 + 12*5 = 70s).
12. **(U-04)**: Parameterised image tag via `${CORDELIA_IMAGE:-cordelia-test:latest}` in Compose + CI builds with `cordelia-test:${GITHUB_SHA::8}`.
13. **(U-03)**: Added comment confirming `GET /api/v1/health` is defined in operations.md SS8 (unauthenticated, 200/503).
14. **(G-07 + X-01)**: Split `api_query` into `api_post` (POST with body, for all channel endpoints + status) and `api_get` (GET, for metrics/health). Updated all call sites.
15. **(I-04)**: Added safety comment to `wait_for` documenting eval constraint (test-authored strings only).
16. **(I-05)**: Extracted `DB_PATH` and `TOKEN_PATH` constants to top of common.sh. All db_query/api_post calls reference constants.
17. **(I-10)**: Fixed `assert_no_psks` to check directory existence before listing (`find` instead of `ls` glob).
18. **(U-01 + I-01)**: Fixed harness script artifact collection -- replaced broken `$?` check with `PIPESTATUS[0]` capture. Artifacts now collected inside the failure branch.
19. **(I-02)**: Moved artifact collection inside the `else` branch, eliminating the separate `$?` check. ERRORS array correctly quoted.
20. **(I-06)**: Firmed up coverage denominator: 84 meaningful combinations (enumerated formula), 7/84 topologies but 9/9 properties covered.
21. **(I-07)**: Changed T5 heal from `iptables -F` (flush all rules) to `iptables -D` (delete specific partition rules only).
22. **(G-08)**: Unified Compose file naming to `t1.yml`..`t7.yml` (matching harness `${topo}.yml` pattern). Updated file layout section.
23. **(X-03)**: Fixed channels-api.md reference section numbers (SS3.2 publish, SS3.3 listen, added SS3.15 metrics).
24. **channel_id_for domain prefix**: Fixed `channel_id_for()` to include `cordelia:channel:` domain separator per channels-api.md SS3.1. Updated CI PSK generation and PSK distribution description to match.
25. **Test sequence**: Fixed `GET /api/v1/status` to `POST /api/v1/status` (node API is POST-based).

**All 30 findings resolved.** Zero remaining.

---

### Data Formats Spec (2026-03-12)

**Spec created**: data-formats.md (new). Buildability audit of critical-path specs identified two gaps that would force design decisions mid-implementation:

1. **SQLite schema DDL**: No CREATE TABLE statements existed across any spec. Behavioural specs (channels-api, ECIES, search-indexing) described fields and flows but never defined the authoritative schema. Data-formats.md §3 provides complete DDL for 5 core tables (channels, channel_members, channel_keys, items, dm_peers) plus references to 5 search tables in search-indexing.md.

2. **PSK envelope item structure**: Items with `item_type = "psk_envelope"` cannot be encrypted with the channel PSK (the recipient doesn't have it yet). The alternate storage path (CBOR blob with ECIES envelope + recipient metadata, `key_version = 0` sentinel) was unspecified. Data-formats.md §4 provides the full CBOR format, processing flow, and security properties.

**Pass 8 enhanced**: Added "Storage and data format completeness" sub-checklist to Pass 8 (Implementability) in both the methodology and the review-spec skill. This catches: missing DDL, unspecified wire formats, special-case processing paths, and unmapped API-to-storage field transitions.

---

*Version 1.9. Created 2026-03-11. Updated: data-formats.md created, Pass 8 enhanced with storage/format completeness checklist, 2026-03-12.*
