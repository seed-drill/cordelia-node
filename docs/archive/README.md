# Archive

Documents from before the decision of 2026-09-30 to cut Cordelia back to one
product: an AI agent's memory on every machine its operator uses
([`docs/decisions/2026-09-30-agent-memory-sync.md`](../decisions/2026-09-30-agent-memory-sync.md)).
They are kept for history and do not describe v1. Where a live spec mentions
one of these files by name, it is here.

| Path | What it was | Why it is archived |
|---|---|---|
| `whitepaper-v2.3.md` | Whitepaper v2.3 (April 2026) | Replaced by [`WHITEPAPER.md`](../../WHITEPAPER.md) (v3, what v1 is) and [`docs/vision.md`](../vision.md) (direction) |
| `specs/architecture-overview.md` | The five-phase architecture | Replaced by `WHITEPAPER.md` §3 and the decision record |
| `specs/memory-model.md` | The L0-L3 memory hierarchy, novelty engine and frame memory | Dropped: the agent decides what to remember, and Cordelia carries it |
| `specs/search-indexing.md` | FTS5 and semantic search | Deferred: v1 needs no search. The `/api/v1/channels/search` endpoint and the FTS index are still in the code. |
| `specs/sdk-api-reference.md` | The TypeScript SDK (`@seeddrill/cordelia`) | Deferred with `cordelia-sdk` |
| `reference/game-theory.md` | Game-theoretic foundations of trust and relay economics | Dropped with Bayesian trust and relay economics |
| `decisions/2026-03-09-mvp-implementation-plan.md` | The March build plan (WP1-WP12) | Replaced by the v1 build sequence |
| `decisions/2026-03-09-spo-economic-model.md` | Cardano stake pool operators as the relay network and settlement layer | Dropped 2026-09-30: no settlement layer is chosen (`docs/vision.md` §4) |
| `decisions/2026-03-10-identity-privacy-model.md` | Identity layers 1-3, proof of agency, access policies, DMs, namespaces | v1 keeps Layer 0 only: one Ed25519 key per device |
| `reviews/` | The spec review passes of March and April 2026, below | Their findings are against the pre-pivot specs |

## Reviews

The April 2026 sprint reviewed 15 specs and logged 223 findings, 22 of them
CRITICAL (`reviews/review-sprint-summary-2026-04-17.md`). Eight of the 22 are
against specs that are now archived (architecture overview, memory model,
search). AT-01, pairing attacks missing from the attack tree, no longer applies
because v1 drops seed-sharing pairing. The findings against specs that stay
live have not been re-checked against v1.

| File | Covers |
|---|---|
| `review-sprint-summary-2026-04-17.md` | The April sprint: scope, totals, recurring patterns |
| `review-status-2026-04-17.md` | Triage of the earlier review passes, all closed as of 2026-04-17 |
| `review-methodology.md` | How the reviews were run |
| `review-<spec>-2026-04-17.md` | One review per spec (15 files) |
| `review-terminology.md`, `review-implementability.md`, `review-privacy.md`, `review-errors.md` | Earlier cross-spec passes 7, 8, 10 and 12 |
| `review-build-verification.md` | Phase 1 E2E build verification |
| `spec-alignment-audit.md` | Spec-to-code alignment audit |
