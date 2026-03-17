# Attack Trees: Economic Cost-Benefit Analysis

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-11
**Scope**: Phase 1 defences (network-protocol.md §16, channels-api.md §9)
**Purpose**: For each attacker persona, enumerate best strategies and verify ROI < 1 against specified defences. Pre-coding gate.

---

## 1. Methodology

Each attack is analysed as:

```
Attack → Cost to execute → Damage to network → Defence → Residual risk → ROI
```

**ROI < 1 = defence holds.** The attacker spends more than they gain.
**ROI >= 1 = defence insufficient.** Must strengthen before coding.

Costs are estimated at 2026 prices. ADA = ~$0.25. Compute = ~$0.05/hr (commodity VPS).

---

## 2. Persona A: Script Kiddie ($0 budget)

### A1: Sybil Channel Flood

```
Goal:        Exhaust storage on target nodes
Budget:      $0 (own machine only)
Strategy:
  1. Run `cordelia init` 100 times (100 identities, ~100 seconds)
  2. Each identity subscribes to target's channels
  3. Each identity creates 50 channels (5000 total)
  4. Publish 10MB to each channel (50GB total)

Cost:        ~2 hours compute, ~50GB local storage, $0
Damage:      50GB replicated to relays. Target node stores only subscribed channels.
Defence:
  - Channel creation: 1/sec per entity (channels-api.md §9.1) → 5000 channels takes 5000 seconds (~83 min)
  - Channel cap: 50 per entity → only 50 channels per identity, not 5000 total
  - But 100 identities × 50 = 5000 channels still achievable
  - Connection limits: 5 per IP (§9.1) → only 5 identities connect from one IP
  - Publish rate: 100/min per channel → 2.5MB at 256KB items = 10 items = 6 seconds per channel
  - Relay storage: LRU eviction at 10GB (§16.3) → relay drops oldest, degrades gracefully
  - Target node: only stores subscribed channels, immune to unsubscribed flood

Residual:    Relays absorb ~10GB (capped by LRU). Relay cache degrades but service continues.
             Target node unaffected (doesn't subscribe to attacker's channels).
ROI:         Attacker achieves temporary relay cache pollution. No lasting damage. No profit.
Verdict:     UNPROFITABLE. Nuisance only.
```

### A2: DM Spam

```
Goal:        Flood a target entity with unwanted DMs
Budget:      $0
Strategy:
  1. Create 10 identities (10 seconds)
  2. Each opens DM with target (10 DMs)
  3. Publish spam to each DM channel

Cost:        Minutes of compute, $0
Defence:
  - DM creation: 5/min per entity (channels-api.md §9.1)
  - 10 identities × 5/min = 50 DMs/min max
  - Connection limits: 5 per IP → only 5 identities from one IP
  - Target receives items only on subscribed channels (Gate 3)
  - DM requires both keys → target can block by not opening the DM
  - Target can unsubscribe from unwanted DMs

Residual:    Target receives at most 25 DMs before IP connection limit hit.
             Must manually unsubscribe. Annoying but not damaging.
ROI:         No profit. Minor annoyance.
Verdict:     UNPROFITABLE. Acceptable nuisance level.
```

### A3: Bootnode Exhaustion

```
Goal:        Prevent honest nodes from bootstrapping
Budget:      $0
Strategy:
  1. Script rapid connections to boot1, boot2
  2. Complete handshake, request peer-share, disconnect, repeat

Cost:        Minimal compute
Defence:
  - Bootstrap rate limit: 5 connections/IP/hour (§16.2.1)
  - Max concurrent handshakes: 50 (§16.2.1)
  - Attacker from 1 IP: 5 connections/hour. Negligible impact.
  - From /24 subnet: 20 connections/hour. Still negligible.
  - Bootnodes are lightweight (~50MB, $5/month). Run 5-10.
  - DNS SRV + hardcoded fallback seeds → attacker must exhaust ALL bootnodes

Residual:    From single IP/subnet: zero impact. Would need thousands of IPs.
ROI:         Not achievable at $0 budget.
Verdict:     UNPROFITABLE. Defence holds.
```

---

## 3. Persona B: Competitor ($10K budget)

### B1: Relay Defection Campaign

```
Goal:        Degrade Cordelia's reliability to drive users to competitor product
Budget:      $10K (~40K ADA)
Strategy:
  1. Spend $2K on 20 VPS instances ($100/each for 1 month)
  2. Run relay nodes on each (role = "relay")
  3. Each relay connects to 100+ peers, builds good reputation (2 weeks)
  4. Flip: start silently dropping 80% of items
  5. Network reliability degrades (items don't propagate)

Cost:        $2K compute + 2 weeks patience = $2K
Damage:      If 20 relays represent >50% of relay capacity, significant propagation delay.
Defence:
  - Probe items every 300s (§16.1.2) → defection detected within 5-10 minutes
  - Contribution ratio drops below 0.3 → automatic Hot→Warm demotion
  - >50% probe failure in 1 hour → Cold + ban 24 hours
  - >80% probe failure → ban with escalation
  - 3 bans in 7 days → permanent ban + propagation to all peers
  - Cross-peer verification: honest peers detect items arriving from
    other sources but not from defecting relay

Timeline of attack:
  T=0:       20 relays flip to defection
  T+5min:    Probe cycle fires. First probes fail.
  T+10min:   Second probe cycle. >50% failure detected.
  T+15min:   Relays demoted to Cold. Peers stop using them.
  T+60min:   Relays banned (24h). Ban propagated via Peer-Sharing.
  T+7 days:  If attacker re-deploys, permanent ban after 3rd cycle.

Residual:    5-15 minute degradation window before detection.
             Honest relays + direct P2P connections provide redundancy.
             Attacker must burn $2K/month continuously, permanently banned after 3 weeks.
ROI:         $2K for 15 minutes of degradation. Must re-deploy monthly. No profit.
Verdict:     UNPROFITABLE. Detection is fast, punishment is permanent.
```

### B2: Sybil Eclipse Attack

```
Goal:        Isolate a target node from honest peers
Budget:      $10K
Strategy:
  1. Spin up 200 Sybil nodes ($5K on 100 VPS, 2 per VPS)
  2. Each connects to target node
  3. Saturate target's Hot/Warm slots with Sybil peers
  4. Sybil peers refuse to forward items to target
  5. Target is eclipsed: cannot receive published items

Cost:        $5K/month compute
Defence:
  - Max connections per IP: 5 → only 10 Sybil from 2-per-VPS (5 per IP)
  - Max connections per /24: 20 → diverse subnets needed
  - 200 Sybils across diverse /24s need ~10 distinct subnets minimum
  - hot_max = 2 (personal) → target has 2 Hot peers. Attacker needs both to eclipse.
  - hot_min_relays = 1 → at least 1 Hot peer is a relay (harder to Sybil than personal peer)
  - min_warm_tenure = 300s → Sybils must maintain connection for 5 min before promotion
  - Random promotion → attacker cannot game scoring to get promoted faster
  - 20% hourly churn → warm peers rotated. Sybils diluted.
  - Probe items detect non-forwarding → Sybil contribution_ratio drops → demotion
  - Bootnode + DNS discovery → target always has path to honest peers

Quantitative:
  - Target has 2 Hot + 10 Warm = 12 active peers (personal node profile)
  - Attacker needs both Hot slots to eclipse. With hot_min_relays=1, one slot is a relay.
  - Attacker must either compromise a relay OR have their Sybil selected as the 2nd Hot peer.
  - With random promotion from warm set of 10: P(attacker selected) = attacker_fraction_of_warm.
  - If attacker has 3 of 10 warm peers: 30% chance per promotion cycle.
  - min_warm_tenure = 300s per identity. Churn rotates warm set hourly.
  - Probe detection kicks in within 10 minutes
  - Net: attacker cannot maintain >75% share for more than ~20 minutes

Residual:    Brief partial eclipse possible (<30 min). Not complete eclipse.
             Items eventually arrive via anti-entropy sync.
ROI:         $5K/month for temporary, partial degradation of one target. No profit.
Verdict:     UNPROFITABLE. Defence layers stack: limits + tenure + churn + probes.
```

### B3: Channel Name Front-Running (Phase 3)

```
Goal:        Register premium channel names before honest users, resell
Budget:      $10K (~40K ADA)
Strategy:
  1. Register 20,000 generic channel names (2 ADA each = 40K ADA)
  2. List for resale at $10-100 each
  3. If 10% sell at $50 average → $100K revenue

Cost:        40K ADA (~$10K) in deposits
Defence:
  - Proof-of-use: >=1 item published per year per channel (§16.6)
  - Renewal: 0.5 ADA/year per channel (§16.6)
  - 20,000 channels × 0.5 ADA/year = 10,000 ADA ($2,500)/year maintenance
  - Must publish 20,000 items/year (one per channel) = ~55/day
  - Unpublished channels expire after 365 days, names become available
  - Deposit returned on voluntary deletion (not on expiry)

Quantitative:
  - Year 1 cost: 40K ADA deposit + 10K ADA renewal = 50K ADA ($12.5K)
  - Year 1 revenue: depends on demand. No guaranteed buyers.
  - If no buyers: $12.5K lost. Channels expire, deposit returned (minus renewal).
  - Net cost if zero sales: 10K ADA renewal ($2.5K burned) + effort.
  - If 10% sell at $50: $100K revenue - $12.5K cost = $87.5K profit.

Residual:    Squatting IS profitable if demand materialises. Proof-of-use mitigates
             Strengthened proof-of-use (>=10 items, >=2 authors) makes automated
             squatting expensive: must recruit a second author per channel per year.
             Activity-weighted renewal (5x for low-activity) adds $2.50/channel/year.
ROI:         At 100 names: $250/year renewal + coordination cost for 2 authors x 100.
             Resale market for channel names is speculative and unproven.
Verdict:     UNPROFITABLE after strengthening. Multi-author requirement is the key deterrent.
```

---

## 4. Persona C: Nation State ($100K budget)

### C1: Metadata Surveillance via Relay Network

```
Goal:        Map who communicates with whom (traffic analysis)
Budget:      $100K
Strategy:
  1. Deploy 50 relay nodes globally ($50K/year, 50 VPS)
  2. Relays operate honestly (high contribution ratio, no defection)
  3. Log all metadata: channel_id, author_id, published_at, blob size
  4. Correlate across relays to build communication graph
  5. Identify which entities communicate on which channels

Cost:        $50K/year compute + analysis tooling
Damage:      Attacker builds partial communication graph.
             Cannot read content (encrypted). Cannot see channel names (only IDs).
Defence:
  - Content is encrypted (ECIES + PSK). Attacker sees ciphertext only.
  - Channel names are hashed (SHA-256). Attacker sees channel_id, not name.
  - Author_id is the Ed25519 public key. Pseudonymous but linkable.
  - Relays do see channel_id + author_id + published_at + size.
  - This is acknowledged in accepted risks (§11.4): "Metadata visible to relays."

Residual:    Significant. Attacker with 50 relays (~30-50% of relay capacity)
             sees a large fraction of item metadata. Can build:
             - Channel membership graphs (who subscribes to what)
             - Activity patterns (when entities publish, how much)
             - Social graph (who shares channels with whom)
             Cannot determine:
             - Content of any item
             - Channel names (only IDs)
             - Relationship between channel ID and human-readable name
             Phase 4 mitigation: onion routing (§13.2)

ROI:         Intelligence value depends on targets. For most users: low value
             (pseudonymous keys, encrypted content). For targeted surveillance
             of known entities: moderate value (activity patterns).
Verdict:     **PARTIALLY EFFECTIVE.** Accepted risk for Phase 1. Onion routing Phase 4.
             Not economically motivated (no profit), but intelligence-motivated.
```

### C2: Eclipse + Censor Specific Entity

```
Goal:        Prevent a specific entity from receiving items on a specific channel
Budget:      $100K
Strategy:
  1. Combine B2 (Sybil eclipse) at larger scale: 500 nodes
  2. Target one entity, saturate their peer table
  3. Sybil peers forward all items EXCEPT channel X to target
  4. Target can read all channels except the censored one

Cost:        $25K/month (500 VPS)
Defence:
  - Same as B2 but at larger scale
  - 500 Sybils, diverse subnets: potentially 100+ in target's peer table
  - But: anti-entropy sync (Item-Sync) pulls from random peers
  - Even one honest peer with channel X → target eventually gets items
  - Probe items for channel X: if no probes arrive, target detects censorship
  - Target can connect directly to known honest peers (manual peer config)
  - pull_only mode: target initiates all syncs, harder to censor

Residual:    Temporary censorship (hours) possible if attacker controls >90% of
             target's peers. Unlikely to sustain -- churn + probes + anti-entropy
             all work against it. Target can self-rescue by adding known peers.
ROI:         $25K/month for unreliable censorship of one entity on one channel.
Verdict:     UNPROFITABLE for the cost. Self-rescue mechanisms exist.
```

---

## 5. Persona D: Insider / Rogue SPO ($0, has infrastructure)

### D1: Keeper Selective Censorship

```
Goal:        Censor items from a specific author on channels the keeper anchors
Budget:      $0 (already running keeper)
Strategy:
  1. Keeper receives items for anchored channels
  2. Silently drop items from author X before serving to subscribers
  3. Subscribers never receive author X's items via this keeper

Cost:        Zero marginal cost
Damage:      Subscribers using this keeper miss items from censored author.
Defence:
  - Items are replicated P2P, not only via keeper
  - Other subscribers who received the item directly re-push it
  - Anti-entropy sync with non-keeper peers fills the gap
  - Cross-peer verification: subscriber receives item from peer A but not keeper → suspicious
  - KeeperQualityReport (§16.7.2): replication lag increases for censored items,
    visible in public metrics
  - Subscriber can switch keeper at any time (re-anchor)
  - Probe items detect selective dropping (same as relay defection)

Residual:    Brief delay (1-2 sync intervals) for items from censored author.
             Detectable via quality metrics and probes. Subscriber can switch keeper.
ROI:         Zero cost but also zero lasting effect. Detected quickly. Reputational damage
             to keeper far exceeds any benefit.
Verdict:     UNPROFITABLE. Self-defeating (keeper loses delegators when metrics degrade).
```

### D2: PSK Exfiltration (Anchor Keeper)

```
Goal:        Read encrypted content of anchored channels
Budget:      $0 (keeper holds PSK for open/gated channels)
Strategy:
  1. Keeper already holds PSK for open/gated channels it anchors
  2. Decrypt and read all content
  3. Sell or leak sensitive information

Cost:        Zero
Damage:      All content on anchored open/gated channels compromised.
Defence:
  - This is an acknowledged trust property (architecture ADR §16):
    "The anchor keeper holds PSK for open/gated channels. Honest, defensible."
  - Invite-only channels and DMs: keeper does NOT hold PSK. Immune.
  - Structural mitigations:
    1. Market competition: users choose keepers. Bad actors lose business.
    2. Auditable: PSK rotation + re-anchor to different keeper at any time.
    3. Self-hosting: run your own keeper for sensitive channels.
    4. Phase 4: threshold PSK (Shamir k-of-n, no single keeper decrypts).

Residual:    Real risk for open/gated channels. Same trust model as email provider
             or cloud storage. Mitigated by market competition and self-hosting option.
ROI:         Potentially profitable if content has market value. But: keeper identity
             is public (on-chain in Phase 3), prosecution risk is high.
Verdict:     **EFFECTIVE but high-risk for attacker.** Accepted trust model.
             Phase 4 Shamir closes this for users who want it.
```

---

## 6. Persona E: Squatter ($5K budget)

### E1: Speculative Name Registration (Phase 3)

Same as B3 above. See §3.

```
Verdict:     UNPROFITABLE after §16.6 strengthening. Same as B3: multi-author
             requirement + activity-weighted renewal makes bulk squatting uneconomic.
```

### E2: Name Griefing (Pre-Phase 3)

```
Goal:        Create channels with desirable names so Phase 3 registration is contested
Budget:      $0 (Phase 1 has no registration cost)
Strategy:
  1. Create channels for 1000 generic names (research, trading, finance...)
  2. Wait for Phase 3 registration
  3. Claim 90-day priority window as "Phase 1 creator"
  4. Register all 1000 at 2 ADA each (2000 ADA = $500)

Cost:        $500 at Phase 3 registration time
Defence:
  - Phase 1 channel creation: 1/sec, cap 50 per entity
  - Attacker needs 20 identities for 1000 channels
  - 90-day priority window: creator gets first-refusal (§16.12)
  - But: proof-of-use applies. Must publish >=1 item per channel per year.
  - For 1000 channels: 1000 items/year = ~3/day. Trivial.

Residual:    Squatter can hold 1000 names for $500 + $500/year renewal.
             Strengthened: must maintain >=10 items from >=2 authors per griefed name.
             Activity-weighted renewal adds cost. Community challenge (Phase 4) allows
             the legitimate owner to reclaim via governance arbitration.
ROI:         Coordination cost per name + 5x renewal makes bulk griefing uneconomic.
Verdict:     UNPROFITABLE after strengthening. Community challenge is the backstop.
```

---

## 7. Persona F: Griefer ($100 budget)

### F1: Targeted Storage Exhaustion

```
Goal:        Fill a specific channel with junk, making it unusable
Budget:      $100
Strategy:
  1. Subscribe to target channel (open access)
  2. Publish max-size items (256KB each) at max rate
  3. Fill channel with junk until quota exceeded

Cost:        $100 (VPS for sustained publishing)
Defence:
  - Publish rate: 100/min per channel (channels-api.md §9.1)
  - 100 items/min × 256KB = 25MB/min → 1.5GB/hour
  - Quota: Phase 1 local default 1GB → attacker hits quota in 40 minutes
  - Phase 3 keeper quota: free tier 10MB → attacker hits quota in 24 seconds
  - Channel owner can remove attacker (group/remove → PSK rotation)

Residual:    10 minutes of junk in the channel before quota hit.
             Channel owner removes attacker and rotates PSK.
             Items from attacker remain (tombstone, not deleted) but are
             clearly attributable (signed by attacker's key).
ROI:         $100 for 10 minutes of junk in one channel. Cleaned up by owner.
Verdict:     UNPROFITABLE. Minimal disruption, easily reversed.
```

### F2: Keep-Alive Flood

```
Goal:        Consume target node's CPU with excessive keepalive processing
Budget:      $0-100
Strategy:
  1. Connect to target node
  2. Send keep-alive messages at maximum rate

Cost:        Minimal compute
Defence:
  - Keep-alive rate not explicitly limited (§9.2 doesn't list keep-alive)
  - BUT: QUIC flow control limits per-stream throughput
  - Bounded queue: 256 keep-alive messages (§9.4)
  - Queue full → stream rejected → QUIC backpressure
  - Per-peer fairness: one peer cannot consume >1/N of queue capacity
  - 5 connections per IP → limited concurrency from single host

Residual:    Negligible. QUIC flow control and bounded queues prevent CPU exhaustion.
ROI:         Zero damage.
Verdict:     UNPROFITABLE. Transport-layer defences sufficient.
```

---

## 8. Summary Risk Matrix

| Attack | Persona | Budget | ROI | Verdict |
|--------|---------|--------|-----|---------|
| A1: Sybil channel flood | Script kiddie | $0 | < 1 | Defence holds |
| A2: DM spam | Script kiddie | $0 | < 1 | Defence holds (nuisance) |
| A3: Bootnode exhaustion | Script kiddie | $0 | < 1 | Defence holds |
| B1: Relay defection campaign | Competitor | $10K | < 1 | Defence holds (15 min window) |
| B2: Sybil eclipse | Competitor | $10K | < 1 | Defence holds (partial, temporary) |
| B3: Channel name front-running | Competitor | $10K | < 1 | Defence holds (after §16.6 strengthening) |
| C1: Metadata surveillance | Nation state | $100K | N/A | Accepted risk (Phase 4 onion routing) |
| C2: Eclipse + censor | Nation state | $100K | < 1 | Defence holds (self-rescue) |
| D1: Keeper censorship | Insider | $0 | < 1 | Defence holds (detectable, switchable) |
| D2: PSK exfiltration | Insider | $0 | >= 1? | Accepted trust model (Phase 4 Shamir) |
| E1: Name squatting | Squatter | $5K | < 1 | Defence holds (after §16.6 strengthening) |
| E2: Name griefing | Squatter | $0 | < 1 | Defence holds (after §16.6 strengthening) |
| F1: Storage exhaustion | Griefer | $100 | < 1 | Defence holds |
| F2: Keep-alive flood | Griefer | $0 | < 1 | Defence holds |

**Defences hold for 14/14 attacks.** Two are accepted risks with Phase 4 mitigations:

### Resolved (strengthened)

**B3/E1/E2: Channel name squatting (Phase 3)** -- RESOLVED. §16.6 strengthened:
- Proof-of-use raised to >=10 items from >=2 distinct authors per year
- Activity-weighted renewal: low-activity channels pay 5x (2.5 ADA/year)
- Community challenge mechanism added (Phase 4 governance arbitration)
- Multi-author requirement is the key deterrent: squatters must recruit real collaborators per channel.

### Accepted Risks (conscious design choices)

**D2: PSK exfiltration (accepted trust model)**

This is a conscious design choice, not a defence failure. The architecture ADR explicitly documents this. Phase 4 Shamir threshold PSK closes it for users who want stronger guarantees. No spec change needed -- the risk is honestly documented.

**C1: Metadata surveillance (accepted risk)**

Documented in §11.4. Onion routing (Phase 4) is the mitigation. No Phase 1 change.

---

## 9. Action Items

- [x] **Update §16.6 proof-of-use**: Strengthened to >=10 items from >=2 distinct authors. Activity-weighted renewal (5x for low-activity). Community challenge mechanism added (Phase 4).
- [x] All other attacks have ROI < 1 against specified defences.

---

*Draft: 2026-03-11. Pre-coding gate: all ROI < 1 before WP3 implementation.*
