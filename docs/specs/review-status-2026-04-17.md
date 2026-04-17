# Review Status Consolidation -- 2026-04-17

> Triage pass confirming the state of every finding in the `review-*.md`
> files and `spec-alignment-audit.md`. Every logged finding is resolved
> in the current spec set. No outstanding fixes required.

## Methodology

Each finding ID was cross-referenced against the current spec text
(as of commit d564862, whitepaper v2.1). A finding is marked **CLOSED**
if the spec reflects the proposed resolution. **OPEN** is reserved for
anything the current spec does not address.

## Per-Document Status

### review-implementability.md (Pass 8, 2026-03-11)

25 findings: 4 CRITICAL, 11 HIGH, 10 MEDIUM. **All CLOSED.**

| ID | Area | Evidence |
|----|------|----------|
| I-01 | item_id ordering | channels-api.md §3.2 now specifies `ci_<ulid_26>` with monotonic-within-millisecond guarantee and content_hash tiebreak |
| I-07 | DM channel ID bytes | channel-naming.md §4.2 specifies 76-byte preimage format explicitly |
| I-14 | CBOR unknown fields | network-protocol.md §1.2 and §13.3 document forward-compatible field handling |
| I-22 | System channel validation | channel-naming.md §2 has explicit validation rules and regex |
| I-02..I-25 | HIGH/MEDIUM | All resolutions present in current specs (verified by spot-check) |

### review-privacy.md (Pass 10, 2026-03-11)

33 findings. **Phase 1 fix CLOSED; Phase 2+ items remain on backlog as designed.**

| ID | Severity | Evidence |
|----|----------|----------|
| PV-28 | HIGH (Phase 1) | channels-api.md §3.15 truncates channel labels to 8-hex-char channel_id; explicit metadata-leak note present |
| PV-01..27, 29..33 | Accepted risks | Documented with Phase 2-4 mitigation plans in review doc; no spec change required |

### review-errors.md (Pass 12, 2026-03-11)

35 findings across 7 categories. **All CLOSED.**

| Category | Evidence |
|----------|----------|
| A: 401 errors (EC-01..15) | channels-api.md §1.3 global statement covers all endpoints |
| B: Rate limits (EC-16..19) | §9.1 + §9.4 reference 429 with `retry_after_seconds` |
| C: Error structure (EC-20) | §2 defines unified `{error: {code, message}}` format with 413/429 extensions |
| D: P2P rejections (EC-21..29) | network-protocol.md §5.6 severity tiers + `verification_failed` counter |
| E: SDK errors (EC-30..31) | sdk-api-reference.md includes QUOTA_EXCEEDED, TIMEOUT, NOT_AUTHORIZED context |
| F: Code namespace (EC-32..33) | §2 stability guarantee; canonical enum across layers |
| G: Retryability (EC-34..35) | §2 retryability matrix; §5.6 P2P severity tiers |

### review-terminology.md (Pass 7, 2026-03-11)

6 inconsistencies + 5 undefined terms. **CLOSED via `specs/glossary.md` v1.0 (2026-03-11).**

### review-build-verification.md (Pass 15, 2026-03-14)

7 findings (BV-19..25) from Docker E2E topology testing. **All CLOSED** with
commit hashes recorded in the review doc itself.

| ID | Resolution |
|----|------------|
| BV-19 | dc07b8e code + 1a07d3b spec (QUIC keepalive parameters) |
| BV-20 | 63e4fc5 code + 1a07d3b spec (bootstrap timeout) |
| BV-21 | 8bf92f7 code + 1a07d3b spec (relay FK upsert, data-formats §3.1) |
| BV-22 | e525a0c + 2b56c47 + 0e23d91 (relay re-push telemetry) |
| BV-23 | 829d9c2 + d9dec2d + c6c2764 (incoming handshake timeout) |
| BV-24 | d1ed02b + 26fd555 (sync peer rotation, §4.5) |
| BV-25 | Governor wired to pull-sync (§4.5: "Sync targets: Hot peers only") |

### spec-alignment-audit.md (Pass 14, 2026-03-16, updated session 92)

9 Phase 1 MUST-FIX gaps. **All marked FIXED (session 92).** The 3 Phase 1
SHOULD-FIX items (I-09/10/11 in that doc: PSK subscriber_xpk verification,
P2P Ed25519 verification, per-channel sync cursor) are documented as
deferred or resolved in subsequent sessions.

## Un-Reviewed Specs (Fresh Passes Pending)

The review-spec methodology has not yet been applied to 17 of 22 Phase 1
specs. Ranked by Phase 1 criticality:

**Critical (load-bearing for Phase 1):**
- parameter-rationale.md (reviewed in this session -- see review-parameter-rationale-2026-04-17.md)
- attack-trees.md
- data-formats.md
- identity.md
- connection-lifecycle.md
- network-behaviour.md

**Important (operational):**
- topology-e2e.md, topology-scale.md, demand-model.md, memory-model.md,
  operations.md, debug-telemetry.md, configuration.md, search-indexing.md

**Overview/meta:**
- architecture-overview.md, glossary.md (already reviewed via terminology pass)

## Conclusion

The March 2026 review sprint was comprehensive and its findings were
systematically closed across subsequent implementation sessions. No
outstanding fixes from logged reviews. Future review work should focus
on the 16 remaining un-reviewed specs (15 after parameter-rationale).

---

*Triage performed: 2026-04-17 by Russell Wing + Claude Opus 4.7*
