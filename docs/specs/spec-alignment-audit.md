# Spec-to-Code Alignment Audit

> Honest assessment of every section in network-protocol.md against the
> actual cordelia-node codebase. Date: 2026-03-16.

## Summary

| Status | Count | Sections |
|--------|-------|----------|
| IMPLEMENTED | 16 | ss1, ss2.1-2.3, ss3.1-3.3, ss4.1-4.6, ss5.1, ss5.4.1, ss10, ss3 data-formats |
| PARTIAL | 14 | ss5.2-5.6, ss6.1-6.4, ss7.1-7.3, ss8.1-8.4, ss8.6, ss9.1-9.2, ss11, ss12 |
| SPECIFIED ONLY | 5 | ss4.8, ss9.4, ss16.1-16.4 |
| DEFERRED (Phase 2+) | 6 | ss8.5, ss16.3, ss16.5-16.10 |

**9 gaps are Phase 1 MUST-FIX.** These are features the spec says are Phase 1
scope but the code doesn't implement (or didn't -- see status column).

---

## Phase 1 MUST-FIX (spec says do it, code doesn't)

| # | Section | Gap | Impact | Status |
|---|---------|-----|--------|--------|
| 1 | ss5.4 | min_warm_tenure not enforced | Anti-eclipse defense missing. Sybil peers promoted in 10s instead of 5 min. | FIXED (session 92) |
| 2 | ss9.1+9.2 | Rate limits defined but not enforced | No connection limits, no message rate limits. Any peer can flood. | FIXED (session 92) |
| 3 | ss5.5 | Scoring incomplete (no EMA, no contribution_factor) | Can't detect relay defection. Scores gameable. | FIXED (session 92) |
| 4 | ss5.6 | Banning too weak (5min, linear, no tiers) | Repeat offenders back in 5 min. Should be 1h minimum. | FIXED (session 92) |
| 5 | ss7.1 | Gate 1 push filtering missing | Items pushed to ALL hot peers, not channel-interested ones. Bandwidth waste + metadata leak. | FIXED (session 92) |
| 6 | ss16.1 | Relay contribution tracking unimplemented | Listed as Phase 1 in ss13.1 but no code. Can't detect freeloading relays. | FIXED (session 92) |
| 7 | ss5.2 | PeerInfo missing 7 fields | items_relayed, items_requested, bytes_in/out, probes, score_ema. | FIXED (session 92) |
| 8 | ss5.3 | Config defaults don't match spec profiles | Code defaults 2-4x higher than spec's Personal Node profile. | FIXED (session 92) |
| 9 | debug-telemetry ss5 | Per-stream timeouts missing in handle_peer_streams | 5x read_frame() with no timeout. Peer crash causes 60s hang. Exposed by test_chaos_disconnect_during_sync. | FIXED (session 92) |

## Phase 1 SHOULD-FIX (important but not spec-mandated)

| # | Section | Gap | Impact |
|---|---------|-----|--------|
| 9 | ss4.7 | PSK subscriber_xpk not verified at protocol level | Key confusion attacks possible. |
| 10 | ss6.2 | Ed25519 signature not verified at P2P receive | Forged items accepted until API layer. |
| 11 | ss6.4 | No per-channel sync cursor | Every sync re-fetches everything. |
| 12 | ss8.1-8.4 | Protocol-per-state gating not enforced | Warm peers can run all protocols. | FIXED (session 92) |

## Phase 2 DEFER (spec acknowledges, can wait)

| # | Section | Feature |
|---|---------|---------|
| 13 | ss4.8 | Pairing protocol (multi-device enrollment) |
| 14 | ss7.2 | Channel-aware relay routing (broadcast OK for Phase 1) |
| 15 | ss8.5 | Secret keeper role |
| 16 | ss9.4 | Backpressure queues |
| 17 | ss6.3 | Tombstone GC |
| 18 | ss16.3 | Relay storage quota enforcement |

---

## Decision Required

The spec (ss13.1) lists relay contribution tracking (ss16.1) and bandwidth
amplification limits (ss16.4) as Phase 1 scope. These are significant features
that are entirely unimplemented. Options:

**Option A:** Implement them now (adds 2-3 days of work).
**Option B:** Defer to Phase 2 and update ss13.1 to reflect the actual Phase 1 scope.
**Option C:** Implement a simplified version (contribution ratio from items_delivered only, no probes).

Recommendation: **Option C.** The full probe-based system is over-engineered for
a network with 7 relays operated by Seed Drill. A simplified contribution ratio
using existing items_delivered data gives 80% of the value with 20% of the effort.

---

## Spec Gaps Found During Implementation

Issues where the spec is ambiguous or incomplete, discovered while implementing
the MUST-FIX gaps.

| # | Spec Section | Issue | Discovered |
|---|-------------|-------|------------|
| S1 | ss16.1 + connection-lifecycle ss1.2 | Relay contribution tracking: spec defines `items_relayed` field but does not specify which component increments it or the data flow path. Three options exist (handle_peer_streams via gov_tx, p2p_loop inferring from delivery_rx + node_role, separate tracking channel). Implementor must guess. Suggest: add "Relay tracking wiring" step to connection-lifecycle ss1.2 or a "Data flow" subsection to ss16.1. | Session 92 |
| S2 | debug-telemetry ss5 + connection-lifecycle ss4.2 | Per-stream timeout values not specified. debug-telemetry says "every await MUST have a timeout" but doesn't specify per-protocol values. connection-lifecycle ss4.2 only mentions QUIC idle timeout (60s). Implementation used: protocol_byte=5s, push=10s, sync=10s, fetch=30s, peer_share=5s. These should be in parameter-rationale.md. | Session 92 |

---

*Audited by: Claude Opus 4.6 + Russell Wing*
*Date: 2026-03-16 (updated session 92)*
*Codebase: cordelia-node commit ac4c33c*
*Spec: network-protocol.md commit 5ef81e3*
