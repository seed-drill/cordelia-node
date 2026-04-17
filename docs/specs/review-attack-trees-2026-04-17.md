# Review: attack-trees.md

> Fresh review pass (first) applying review-spec methodology to
> `attack-trees.md` (draft 2026-03-11, 500 lines). Due-diligence
> pre-Phase-1 close.

## Application Record

| Field | Value |
|-------|-------|
| Date | 2026-04-17 |
| Reviewer | Russell Wing + Claude Opus 4.7 |
| Spec | attack-trees.md (draft 2026-03-11) |
| Passes applied | 1 (Gaps), 2 (Consistency), 3 (Clarity), 4 (Implementability), 5 (Coverage), 9 (Security) |

---

## Summary

12 findings. 2 CRITICAL (missing attack coverage for Phase 1 protocols
that have shipped), 4 HIGH (stale parameters, unsupported quantitative
claims, undefended primitives), 4 MEDIUM (ambiguous mitigations,
omitted personas), 2 LOW (cosmetic).

The document is structurally sound — personas are well-chosen, the
cost/damage/defence template is applied consistently, and all
listed attacks do carry ROI < 1 arguments. The core issue is
**scope**: several Phase 1 protocols that introduce genuine attack
surface (pairing, route discovery, localhost API) are not analysed
at all. In addition, two parameter values in the quantitative
analyses are stale versus the current network-protocol.md (hot_max
governor values, per-peer write rate), and one threat assumption
(channel name hashing defeats adversary) contradicts a caveat
already documented in channel-naming.md §127.

---

## CRITICAL

### AT-01: Pairing protocol is absent from the attack tree

**Spec**: attack-trees.md §2-§7 (no coverage)

**Issue**: network-protocol.md §4.8 (Pairing, protocol byte 0x08) is
Phase 1 and shipped. It introduces a new attack surface that is not
analysed anywhere in attack-trees.md:

- Malicious bootnode races the intended joiner to connect to the
  initiator (acknowledged in network-protocol.md §4.8 as a real
  threat mitigated by "single-connection guard" and fingerprint
  verification).
- Pairing code brute-force against the bootnode HMAC-to-address
  table (mitigated by rate limit 10/IP/min, per-bootnode HMAC key).
- `--non-interactive` mode skips fingerprint verification. An
  attacker on the same LAN as the joiner who can redirect the
  QUIC handshake wins the entire identity keypair.
- PairBundle exposes the initiator's channel list to the joiner
  (intentional, but a pairing-gone-wrong leaks it to an attacker).

None of these are modelled. An Insider persona ("rogue bootnode
operator", or "LAN-adjacent attacker during device enrollment") is
missing from personas A-F and is directly enabled by Phase 1 code.

**Resolution**: Add §5.x Pairing Attacks to the document, covering
at minimum:
- `P1: Malicious bootnode pairing race` (rogue bootnode persona)
- `P2: LAN MITM during non-interactive pairing`
- `P3: Pairing code brute-force` (Script Kiddie budget, remote)

Each with the standard Attack/Cost/Defence/ROI template. The
defences already exist in network-protocol.md §4.8, so this is a
documentation-only fix.

### AT-02: Route discovery / broadcast attacks are absent

**Spec**: attack-trees.md §2-§7 (no coverage)

**Issue**: network-protocol.md §7.4 (Route Discovery) and §7.5
(Expanding Ring Search) are Phase 1. network-protocol.md §11.3
lists two explicit threats -- "Broadcast flood (route discovery
spam)" and "TTL skip (bypass expanding ring)" -- with defences
"TTL-proportional rate limits (§9.2)" and "Statistical escalation
detection". Neither is modelled in attack-trees.md.

The economic analysis ("TTL-proportional rate limiting makes
expanding ring search the economically rational strategy") is a
cost-benefit claim, which is exactly what attack-trees.md is
supposed to validate quantitatively. It validates nothing for this
threat class today.

Also missing: `token cache exhaustion` (relay LRU of session keys
for routed items) -- an acknowledged threat in network-protocol.md
§11.3 but not in the attack tree.

**Resolution**: Add §3.x or §7.x entries:
- `R1: Route-discovery flood (Competitor budget)` — uses routed
  mode, TTL=255, exhausts discovery budget network-wide.
- `R2: TTL skip attack` — publisher skips to high TTL to evade
  expanding-ring.
- `R3: Session-key cache exhaustion` — floods discovery messages
  to fill relay token LRU.

Each needs the ROI calculation against §9.2 rate limits + trust
decay (§5.5.2). The verdict is almost certainly "unprofitable" but
that verdict belongs in this document, not implicitly in the
rate-limits table.

---

## HIGH

### AT-03: B2 Sybil Eclipse quantitative analysis uses inconsistent parameters

**Spec**: attack-trees.md §3 B2

**Issue**: The B2 quantitative block says:
> - Target has 2 Hot + 10 Warm = 12 active peers (personal node profile)

That matches the current config (`hot_max=2`, `warm_max=10`,
network-protocol.md §8.6).

But the preceding narrative bullets inside the same attack say:
> - hot_max = 2 (personal) → target has 2 Hot peers. Attacker needs both to eclipse.
> - hot_min_relays = 1 → at least 1 Hot peer is a relay

...and then argues from "warm set of 10", "3 of 10 warm peers =
30% chance per promotion cycle." That math assumes 10 warm slots.
But `warm_max = 10` *includes* the 2 hot slots (per
network-protocol.md §5.3 `warm_max = Maximum warm+hot peers`). So
the warm-only capacity is 8, not 10. A 30% attacker share
calculation from 10 warm peers is slightly wrong.

Separately, the defence bullet says "Max connections per IP: 5 →
only 10 Sybil from 2-per-VPS (5 per IP)" but goes on to compute
"200 Sybils across diverse /24s need ~10 distinct subnets minimum"
without showing the arithmetic. 200 Sybils / 20 per-/24 = 10
subnets, OK, but the conclusion "attacker cannot maintain >75%
share for more than ~20 minutes" is stated without derivation.

**Resolution**: Fix the math: `warm_max` includes hot, so there
are `warm_max - hot_count = 10 - 2 = 8` pure-warm slots. Recompute
the attacker-share probability with the correct denominator. Show
the arithmetic from "200 Sybils ÷ 20 per-/24 = 10 subnets" to
"cannot maintain >75% share for >20 min" explicitly (what's the
churn rate times the random-promotion probability?).

### AT-04: A1 Sybil Channel Flood uses stale per-peer write rate

**Spec**: attack-trees.md §2 A1

**Issue**: The defence bullet quotes
> - Publish rate: 100/min per channel → 2.5MB at 256KB items

but does not reference the per-peer rate limit
(`writes_per_peer_per_minute`). network-protocol.md §9.2 lists
this as 36/min in the table, §12.4 config as 10/min, and
demand-model.md §209 rationale as 10. An attacker with 100
identities gets at most 100 × 10 = 1000 writes/min across all
channels, which materially changes the A1 conclusion. The
document ignores per-peer throttling and reasons only from the
per-channel cap.

Also: A1 strategy says "Publish 10MB to each channel (50GB
total)" with 100 identities × 50 channels. At 100/min per
channel × 256KB = 25MB/min, so a single channel fills 10MB in
24 seconds, which conflicts with the document's own claim "10
items = 6 seconds per channel" (10 items × 256KB = 2.5MB, not
10MB). The arithmetic is internally inconsistent.

**Resolution**: Recompute the A1 scenario with both limits
enforced. State the per-peer rate explicitly in the defence
bullets. Reconcile the "10 items = 6 seconds" and "10MB per
channel" numbers (they describe different things and should
both be shown).

### AT-05: C1 "channel names are hashed" omits the dictionary-attack caveat

**Spec**: attack-trees.md §4 C1

**Issue**: C1 Metadata Surveillance argues:
> - Channel names are hashed (SHA-256). Attacker sees channel_id, not name.
> - Cannot determine: ... channel names (only IDs)
> ... Relationship between channel ID and human-readable name

But channel-naming.md §127 explicitly documents:
> Channel IDs for named channels are vulnerable to dictionary
> attack. An attacker who knows common channel names can
> precompute their hashes and identify channels in replication
> traffic or on-chain registries.

For a nation-state persona with $100K budget, precomputing
hashes of (say) the top 10M English words and common compounds
is trivial. Channel names following RFC 1035 conventions (e.g.
`finance`, `trading`, `research`, `cordelia:directory`) will
definitely be in a rainbow table. The C1 verdict
"PARTIALLY EFFECTIVE" underestimates the information leak.

**Resolution**: Add a bullet to C1 Residual:
> Dictionary attack risk: channel_id is SHA-256(name), un-salted.
> An adversary with a precomputed rainbow table of common names
> can map channel_id back to name. This elevates C1 from "sees
> channel_id" to "sees likely channel name for common/public
> names". Private/random-named channels (e.g. UUID-like, DMs,
> groups) remain opaque. See channel-naming.md §127.

And update the verdict language accordingly.

### AT-06: D2 verdict "EFFECTIVE" but table summary says ROI "< 1"

**Spec**: attack-trees.md §5 D2 verdict (line 353) vs §8 risk matrix (line 465)

**Issue**: §5 D2 says:
> Verdict: **EFFECTIVE but high-risk for attacker.** Accepted trust model.

§8 risk matrix row for D2 says:
> ROI: >= 1? | Accepted trust model (Phase 4 Shamir)

And §8 summary line says: "Defences hold for 14/14 attacks." But
D2 explicitly has ROI >= 1 (i.e. defence does not hold, by the
document's own Methodology §1: "ROI >= 1 = defence insufficient.
Must strengthen before coding."). The document treats this as an
"accepted trust model" -- fine -- but the top-line claim "14/14
defences hold" is then misleading.

**Resolution**:
1. Rewrite the §8 summary line: "Defences hold for 12/14
   attacks. 2 are accepted trust-model risks with documented
   Phase 4 mitigations (C1 metadata, D2 PSK exfiltration)."
2. Make the ROI column definitive: "D2: ROI >= 1 (accepted)",
   not "ROI: >= 1?". The question mark suggests the analysis
   was unfinished.
3. The methodology §1 gate says all ROI must be < 1 OR
   explicitly accepted with mitigation timeline. D2 meets the
   "accepted" criterion but the document should say so in one
   sentence rather than leaving it implicit.

---

## MEDIUM

### AT-07: No attacker persona for "malicious local process on same host"

**Spec**: attack-trees.md §2-§7 (no coverage)

**Issue**: Phase 1 API is bearer-auth over localhost
(network-protocol.md §12.2 enforces `127.0.0.1` binding). The
threat model must account for a non-Cordelia process on the same
host reading `~/.cordelia/` files (identity key, PSKs, node
token) or binding a port to intercept API traffic. These are
known risks in the operations.md security checklist.

Attacks missing:
- Node-token theft from disk or environment variables
- Identity key theft via readable permissions
- PSK file readable by other local users
- Port-hijack race against daemon startup

**Resolution**: Add §2.x or §5.x `Local Process Persona`. These
are trivially unprofitable against defences in operations.md
(600 file perms, token redaction) but that verdict belongs in
this document. The file-permission threat was already a Pass 3
finding against operations.md (per review-methodology.md §7
2026-03-11 re-pass) and should be represented here.

### AT-08: "15-20 minute degradation window" in B1 has no mechanism reference

**Spec**: attack-trees.md §3 B1

**Issue**: B1 states:
> Residual: 5-15 minute degradation window before detection.

and the timeline shows
> T+10min: Second probe cycle. >50% failure detected.

But probe_interval is 300s = 5 min (§16.1.2). So the *first*
probe fires 5 min after the flip. The "second probe cycle" at
T+10min detects >50% failure. This is correct but the arithmetic
"probe every 300s, need 2 failures = 10 min detection" should be
shown. The 15-min figure in Residual also includes demotion at
T+15min -- fine, but not explicit.

Also: "cross-peer verification" (network-protocol.md §16.1.2) is
listed as a defence but no timing is given. It only works once
one honest and one defecting peer have each offered an item that
should have been offered by both. That could take arbitrarily
long depending on publish rate.

**Resolution**: Rewrite the timeline with explicit arithmetic:
`T+0: flip`, `T+5min: first probe fails`, `T+10min: second probe
fails, ratio > 50% over window`, `T+10min: demoted`, `T+15min:
ratio confirmed`, `T+60min: banned`. Note that cross-peer
verification is complementary, not timing-guaranteed.

### AT-09: F1 Storage Exhaustion does not cover replication amplification

**Spec**: attack-trees.md §7 F1

**Issue**: F1 analyses local storage impact on the target
channel. But a published 256KB item replicates to *all* other
subscribers and to all Hot relays in the mesh (epidemic
forwarding, §7.2). A griefer publishing 100/min × 256KB × 60 min
= 1.5GB generates 1.5GB × (subscriber count + relay count) of
network traffic. For a channel with 50 subscribers and 10
relays, that's ~90GB of redundant traffic. The attacker's $100
pays for 60× amplification.

The defence (quota cap, PSK rotation) still works at the
*channel* level, but the amplification itself is uncaptured in
the ROI. This matters because it elevates F1 from "nuisance in
one channel" to "bandwidth cost across 60 unrelated nodes" --
still unprofitable for the attacker, but worth showing
explicitly.

**Resolution**: Add a Damage bullet:
> Network-wide bandwidth amplification: each 256KB publish
> replicates to N_subscribers + N_hot_relays. Per-channel publish
> cap (100/min) and per-peer byte cap (10MB/s,
> max_bytes_per_peer_per_second, §16.4) bound the absolute
> outbound rate. Network-wide amplification is O(M) where M is
> replication fan-out; bounded by relay hot_max and subscriber
> count.

### AT-10: §9 Action Items says "§16.6 Updated" but the update is already in network-protocol.md

**Spec**: attack-trees.md §9

**Issue**: The document is dated 2026-03-11 and lists:
> [x] Update §16.6 proof-of-use: Strengthened to >=10 items...

As of 2026-04-17 the update is in network-protocol.md §16.6
(verified in this review). The "Resolved (strengthened)" block
at §8 shows the same change as if still pending. The document
reads as if it is a live work-plan but should be a settled
record. An implementation reader cannot tell which mitigations
are live today and which were proposals at time of writing.

**Resolution**: Either (a) restamp the document "Updated:
2026-04-17; changes incorporated" and rewrite §8/§9 in the past
tense, or (b) add a status line at top: "Supersedes
2026-03-11 review; all action items resolved in
network-protocol.md §16 revisions pre-Phase-1-close."

---

## LOW

### AT-11: Author line says "Opus 4.6" but Phase 1 close is using 4.7

**Spec**: attack-trees.md front matter (line 3)

**Issue**: Minor consistency. The co-author convention in
CLAUDE.md is to use the actual model name, and follow-up
reviews (review-parameter-rationale-2026-04-17.md) are using
Opus 4.7. Not a defect, but if the document is re-dated per
AT-10, update the author line.

**Resolution**: Leave as-is or bump on re-stamp. Cosmetic.

### AT-12: "Residual" field sometimes has ROI-like statements, sometimes has consequences

**Spec**: Template usage across §2-§7

**Issue**: The Methodology (§1) defines Residual as "what
remains" after defence. Some attacks (A1, A2) use Residual to
describe remaining damage. Others (B1, C2) mix in attacker-side
statements ("Must re-deploy monthly, permanently banned").
Harmless, but reduces skim-readability. An operational reader
looking for "what's the residual exposure for channel owners?"
has to parse each attack's Residual prose differently.

**Resolution**: Split `Residual` into two lines: `Residual
network impact` (what users/operators see) and `Residual
attacker position` (what the attacker is left with). Optional
stylistic fix.

---

## Passes Not Applied (this session)

| Pass | Reason |
|------|--------|
| 6 (Privacy) | Passes to review-privacy.md (privacy exposure matrix covered separately) |
| 7 (Terminology) | Glossary.md review is canonical; attack-trees.md does not introduce new terminology |
| 8 (Implementability) | Applied only indirectly -- the document is a validation doc, not an implementation doc. Gap flagged under AT-02 where route-discovery defences are referenced but not quantified |
| 10 (Operational) | Out of scope for attack-trees |
| 11 (Test vectors) | No deterministic transformations to verify |
| 12 (Error catalog) | Out of scope |

---

## Recommended Triage

**Must fix before Phase 1 close** (gate-blocking per methodology §6,
"all ROI < 1 or explicitly accepted with documented mitigation
timeline"):

- AT-01 (pairing attacks missing) — Phase 1 shipped code without
  an attack-tree entry. Close the gap or this document misstates
  "14/14 defences hold."
- AT-02 (route discovery attacks missing) — same reason.
- AT-06 (D2 verdict inconsistency) — one-line fix.

**Strongly recommended before close:**

- AT-03, AT-04 (quantitative errors and stale parameters) —
  arithmetic fixes, same session as AT-01/AT-02.
- AT-05 (dictionary-attack caveat) — single bullet addition.
- AT-07 (local-process persona) — add a short attack block.

**Schedule as doc debt (post-close):**

- AT-08, AT-09 (more precise timing / amplification arithmetic).
- AT-10 (restamp document, move §9 to past tense).

**Defer / close:**

- AT-11, AT-12 (cosmetic).

---

*Review complete 2026-04-17.*
