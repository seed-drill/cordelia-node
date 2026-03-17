# Decision: Cardano SPO Distribution and Economic Model for Cordelia Infrastructure

**Date**: 2026-03-09
**Decision Maker(s)**: Russell Wing
**Status**: Approved in principle (Martin confirmed 2026-03-10)
**Triggered by**: strategy-and-planning#5 (economic model design)
**Related**: decisions/2026-03-07-network-architecture-review.md (Section 2.6), decisions/2026-01-31-cooperative-equilibrium-proof.md, decisions/2026-03-10-identity-privacy-model.md

---

## 1. Context

The network architecture review (2026-03-07) identified that no economic mechanism exists for third-party infrastructure operators. The whitepaper describes a service market (keepers, relays, archives) but specifies no payment protocol. Currently Seed Drill runs all infrastructure with no revenue model.

Separately, the cooperative equilibrium proof argues that tokens are redundant for memory-sharing cooperation (entities cooperate because the mechanism makes it individually rational). This proof addresses entity behaviour within the network. It does not address the infrastructure layer: why would a third party run a keeper or relay node?

These are distinct problems requiring distinct solutions:
- **Memory cooperation**: solved by mechanism design (trust calibration, sovereignty, privacy)
- **Infrastructure operation**: requires economic incentive for node operators

### Why Cardano SPOs?

Cardano Stake Pool Operators are a pre-existing global network of infrastructure operators with:
- ~3,000 active pools across 50+ countries
- 24/7 server infrastructure with monitoring and redundancy
- Understanding of staking, delegation, and infrastructure SLAs
- Excess compute and storage capacity (most pools are not saturated)
- Alignment with decentralisation values

Cordelia's P2P topology is directly inspired by the Ouroboros network design (Coutts et al.), making the technical and cultural fit natural.

---

## 2. Alternatives Considered

### Option 1: x402 / USDC Micropayments

HTTP-native payment protocol from Coinbase. Agents pay for storage/bandwidth per-request using USDC stablecoin on Base/Solana.

**Pros:**
- Standard HTTP integration (Express middleware, drop-in fetch wrapper)
- ~2s settlement, <$0.0001 gas on Base
- Institutional backing (Coinbase, Cloudflare, Stripe, Google AP2)
- Framework-agnostic -- any HTTP client can pay

**Cons:**
- USDC-only in practice (EIP-3009 dependency)
- Requires crypto wallet provisioning for every agent -- new enrollment complexity
- Facilitator economics unsustainable (relay operators eat gas costs)
- Wrong ecosystem for SPO audience (Ethereum/Solana, not Cardano)
- Regulatory gap: no built-in KYC/sanctions screening (UK/EU risk)
- Token fatigue: agents needing USDC wallets adds friction, not value

**Assessment**: Viable as a secondary payment rail for non-Cardano users, but not the primary model. Ecosystem mismatch with SPO distribution strategy.

### Option 2: Cordelia Native Token (Direct Payment)

Mint a CORDELIA token on Cardano. Node operators earn tokens for providing storage, bandwidth, and uptime. Users spend tokens to consume services.

**Pros:**
- Direct alignment: service = payment
- Programmable economics via Cardano smart contracts (Aiken/Plutus)
- Cardano native asset support is mature (no smart contract needed for basic transfers)
- SPOs already understand token mechanics
- Can model complex service tiers and quality differentiation

**Cons:**
- Token fatigue in the market -- another utility token is a hard sell in 2026
- Regulatory risk: utility token classification under UK FCA / EU MiCA
- Distortion risk: usage patterns warp around yield maximisation (DeFi failure mode, per cooperative equilibrium proof Section 7.7)
- Bootstrap problem: token has no value until network has scale
- Development overhead: tokenomics design, smart contracts, liquidity, exchange listings
- Contradicts the stated position in the cooperative equilibrium proof ("no token, no treasury")

**Assessment**: Too early and too heavy for the current stage. However, token policy ID should be reserved (Phase 3) to secure the namespace, with deployment deferred until justified by network scale and specific use cases.

### Option 3: Delegation-Based (Recommended Primary Model)

Leverage Cardano's existing delegation mechanism. Users delegate ADA to SPOs running Cordelia keeper/relay nodes. SPOs earn increased stake rewards from larger delegation, which is their economic incentive to provide Cordelia services.

**Pros:**
- Zero new token required -- uses existing ADA economics
- Zero regulatory overhead -- ADA delegation is well-established
- Natural for SPOs -- they already compete for delegation on service quality
- SPO autonomy -- operators set their own service parameters (storage quota, bandwidth cap, uptime SLA, pricing tier)
- User alignment -- delegators choose pools based on Cordelia service quality alongside existing criteria (fees, margin, performance)
- No bootstrap problem -- ADA already has value and liquidity
- Clean narrative: "Delegate to a Cordelia-enabled pool" is a single-sentence value prop
- Composable with existing Cardano tooling (pool metadata, SMASH, Daedalus/Yoroi/Eternl pool browsers)

**Cons:**
- Indirect incentive -- SPO revenue comes from increased delegation, not per-request payment
- No per-request billing -- hard to price granular services (1GB storage vs 100GB)
- Free-rider risk -- users could consume Cordelia services without delegating to the SPO
- Quality differentiation is soft -- delegation is a blunt instrument for service-level selection
- Doesn't scale to non-Cardano users (need a complementary model)

**Mitigations:**
- **Free-riding**: SPOs can gate service tiers on delegation proof (on-chain verifiable). Basic tier free, premium tiers require minimum delegation.
- **Granular billing**: Bilateral ledger for metering (off-chain), with delegation as the settlement/commitment mechanism. SPOs set quotas proportional to delegation received.
- **Non-Cardano users**: x402 or direct fiat payment as secondary rail (Option 1 as complement).

**Assessment**: Best fit for the SPO channel. Minimal friction, no new token, leverages existing economics. SPO parameter-setting creates a natural market for service quality.

### Option 4: Bilateral Ledger with Periodic ADA Settlement

Off-chain metering of storage, bandwidth, and uptime between peers. Periodic (weekly/monthly) ADA settlement on-chain.

**Pros:**
- Precise metering -- pay for what you use
- Low on-chain overhead -- batch settlements
- Flexible pricing -- SPOs set rates, market discovers equilibrium
- Works for both Cardano and non-Cardano users (settlement can be multi-rail)

**Cons:**
- Requires bilateral accounting infrastructure (new code, dispute resolution)
- Settlement disputes need arbitration mechanism
- More complex than delegation model
- Credit risk between settlement periods
- Overhead may not justify the precision for early-stage network

**Assessment**: More appropriate at scale (100+ SPOs, enterprise customers). Over-engineered for current stage. Could evolve from Option 3 as the network grows.

---

## 3. Proposed Decision

### Primary Model: Keeper Commercial Policy (Updated 2026-03-10)

Adopt a flexible commercial policy framework where each keeper/SPO sets their own terms. Seed Drill provides the mechanism; operators set the policy.

#### Principle: We Provide Mechanism, Not Policy

Instead of prescribing tier structures, we define standard condition types that keepers compose into plans however they choose. The market discovers equilibrium.

#### Unified Condition Schema (Shared with Channel Access Policy)

One condition schema, two policy contexts. Keeper commercial policy and channel access policy (see identity ADR Section 6) share the same condition types and verification engine. The keeper evaluates conditions twice: once for infrastructure access (commercial plan) and once for channel access (channel policy).

**Condition types:**

| Condition Type | Fields | Verification | Available |
|---|---|---|---|
| `open` | (none) | Auto-approve | Phase 1 |
| `invite_only` | (none) | Admin manual | Phase 1 |
| `delegation` | `min_ada`, `pool_id?` | On-chain: stake address delegated to pool, amount >= threshold | Phase 3 |
| `ada_payment` | `amount`, `recipient`, `frequency` | On-chain: payment to address | Phase 3+ |
| `token_gate` | `policy_id`, `min_quantity` | On-chain: address holds >= N of native asset | Phase 4+ |
| `credential` | `credential_type`, `issuer`, `claim` | Signature verification on signed claim | Phase 1+ |

All on-chain verification is trustless and auditable. The keeper checks the chain, not the user's claim. Credential verification checks issuer signature.

**Policy structure** (shared by both keeper and channel contexts):

```json
{
  "conditions": [ /* one or more condition objects */ ],
  "logic": "all"   // "all" (default) or "any"
}
```

#### Keeper Commercial Policy Schema

Each keeper advertises a `commercial` section in their manifest:

```json
{
  "commercial": {
    "plans": [
      {
        "name": "free",
        "policy": { "conditions": [], "logic": "all" },
        "limits": { "storage_mb": 1, "channels": 2 }
      },
      {
        "name": "supporter",
        "policy": { "conditions": [{ "type": "delegation", "min_ada": 500 }], "logic": "all" },
        "limits": { "storage_mb": 50, "channels": 10 }
      },
      {
        "name": "pro",
        "policy": { "conditions": [{ "type": "delegation", "min_ada": 5000 }], "logic": "all" },
        "limits": { "storage_mb": 1024, "channels": 100, "priority_replication": true }
      }
    ],
    "channel_commission": 0.0
  }
}
```

#### Examples of Keeper Diversity

**Delegation-based SPO** (most common):
```json
{ "plans": [
    { "name": "free", "policy": { "conditions": [] }, "limits": { "storage_mb": 1, "channels": 2 } },
    { "name": "delegator", "policy": { "conditions": [{"type":"delegation","min_ada":1000}] }, "limits": { "storage_mb": 100, "channels": 20 } }
]}
```

**Community/nonprofit keeper** (everything free):
```json
{ "plans": [
    { "name": "community", "policy": { "conditions": [] }, "limits": { "storage_mb": 50, "channels": 10 } }
]}
```

**Enterprise keeper** (direct ADA payment):
```json
{ "plans": [
    { "name": "free", "policy": { "conditions": [] }, "limits": { "storage_mb": 1, "channels": 1 } },
    { "name": "business", "policy": { "conditions": [{"type":"ada_payment","amount":10,"recipient":"addr1...","frequency":"per_epoch"}] }, "limits": { "storage_mb": 500, "channels": 50, "sla_uptime": 0.999 } }
]}
```

**Token-gated keeper** (future, native asset):
```json
{ "plans": [
    { "name": "holder", "policy": { "conditions": [{"type":"token_gate","policy_id":"abc...","min_quantity":100}] }, "limits": { "storage_mb": 100, "channels": 20 } }
]}
```

This creates a natural market: keepers compete on service quality, pricing model, and limits. Users choose keepers that match their needs and economics. No central pricing authority.

#### What We Provide vs What They Decide

| We Provide (Protocol) | They Decide (Policy) |
|---|---|
| Condition type schema and verification | Which conditions to use |
| Plan advertisement format | ADA thresholds and pricing |
| Enforcement engine on keeper | How many plans, what limits |
| Default template (optional) | Whether to use defaults or customise |

`cordelia init --spo` offers a sensible default template. Most SPOs start with defaults and tweak later.

#### Channel Access Policy (Content Layer)

Distinct from keeper infrastructure policy. Channel owners set access conditions on their channels using the same unified condition schema:

| Access Type | Who Can Subscribe | Phase |
|---|---|---|
| `open` | Anyone (auto-approve) | 1 |
| `invite_only` | Explicit invitation from admin | 1 |
| `credential` | Present a signed credential matching requirements | 1+ |
| `delegation` | Delegators to anchor keeper's pool | 3 |
| `ada_payment` | Pay X ADA (one-time or recurring) to channel owner | 3+ |
| `token_gate` | Hold specific Cardano native asset | 4+ |

Channel access policy uses the same `{ "conditions": [...], "logic": "all"|"any" }` structure as keeper commercial policy. See identity ADR Section 6 for full credential-based access policy design.

Keeper enforces access policy by gating PSK distribution. Anchor keeper holds PSK for open/gated channels (see architecture ADR, PSK Trust Boundary). Invite-only channels: keeper never holds PSK. Revenue (if any) goes to channel owner. Keeper can set an optional commission (default 0%).

**Two-layer economic model:**
- **Layer 1 (Infrastructure):** User ↔ Keeper. Pay via delegation, ADA, or free. Keeper provides storage, bandwidth, uptime.
- **Layer 2 (Content):** Subscriber ↔ Channel Owner. Pay per channel owner's policy. Keeper enforces access; holds PSK for open/gated channels (see architecture ADR, PSK Trust Boundary).

Both layers: all payments on-chain, verifiable, auditable. All content E2E encrypted regardless of payment model.

#### Channel Name Registration Cost

Channel names are globally unique, registered on-chain (see architecture ADR Section 15). Each registration locks Cardano min-UTXO (~2 ADA) as deposit, returned on channel deletion. This:
- Prevents name squatting (economic cost)
- Drives Cardano transaction activity (benefits SPOs who earn from block production)
- Creates an on-chain audit trail of channel ownership

Keeper batches channel registrations (1 tx per epoch). Registration cost is part of keeper infrastructure economics.

#### How It Works (Updated Flow)

1. **SPO Registration**: SPO installs Cordelia keeper binary. Registers Cordelia capability in CIP-6 extended pool metadata. Calidus key (CIP-0151) required.

2. **Commercial Policy**: SPO configures plans in keeper config. Published to `cordelia:directory` channel and CIP-6 metadata.

3. **Discovery**: Four-layer decentralised discovery (see architecture ADR Section 14): bootstrap seeds → on-chain → gossip → directory channel. No central registry.

4. **Condition Verification**: On-chain, epoch-aligned (every 5 days). Via cardano-cli (on relay), Koios, or Blockfrost. Delegation, payment, or token holding verified trustlessly.

5. **SPO Revenue Streams**:
   - Delegation: larger pool stake → more blocks → more ADA rewards
   - Block production fees: Cordelia channel registration transactions generate fees
   - Direct ADA payments (if commercial policy includes ada_payment plans)
   - Channel subscription commission (if set, default 0%)

6. **User Experience**: Browse keepers in `cordelia:directory`, compare plans, delegate or pay, start using. Or: `cordelia init` auto-selects best keeper, free tier works immediately.

### Secondary Rail: Token Reservation

Register a CORDELIA native token on Cardano now. Do not mint or distribute.

#### Why Reserve Now

- Policy IDs are permanent on Cardano -- first-mover on the name matters
- Tokenomics design can proceed without deployment pressure
- Provides optionality for future use cases without committing to them

#### Potential Future Token Uses (Design Only, Not Committed)

1. **Governance**: Token-weighted voting on protocol upgrades (culture defaults, encryption standards, metadata schema changes)
2. **Premium features**: Priority replication, extended retention, cross-org group hosting
3. **Enterprise billing**: Fiat-pegged service credits for organisations that need invoicing
4. **Staking for quality**: SPOs stake CORDELIA tokens as service quality bond (slashable on SLA violation)
5. **Cross-chain bridge**: Settlement for non-Cardano users (x402 bridge, fiat on-ramp)

#### Tokenomics Design Principles

To be developed, but constrained by:
- **No speculation incentive**: utility token, not investment vehicle. No ICO, no presale
- **No yield farming**: no liquidity mining, no staking rewards for holding
- **Service-backed value**: 1 CORDELIA = defined unit of service (storage-hour, bandwidth-GB, etc.)
- **Deflationary burn**: tokens consumed by service usage are burned, not recycled
- **Fair distribution**: earned by running infrastructure or contributing to the protocol, not by buying
- **MiCA compliance**: designed to meet EU Markets in Crypto-Assets classification as utility token
- **Reconciliation with cooperative equilibrium proof**: token never used for memory-sharing cooperation incentives. The proof's Section 7.7 position holds -- cooperation is mechanism-driven, not token-driven. Token is for infrastructure economics only.

---

## 4. Reconciliation with Cooperative Equilibrium Proof

The proof (decisions/2026-01-31-cooperative-equilibrium-proof.md) establishes that honest cooperation is the dominant strategy for memory-sharing entities under Cordelia's mechanism design. Section 7.7 explicitly argues against tokens:

> "Economic incentives are redundant. [...] No token is needed to incentivise participation."

This decision does not contradict the proof. The distinction:

| Layer | Problem | Solution | Token Involved? |
|-------|---------|----------|----------------|
| Memory cooperation | Why share honestly? | Mechanism design (M1 trust, M2 sovereignty, M3 privacy) | No |
| Infrastructure operation | Why run a keeper/relay? | Delegation economics (ADA staking) | No (ADA) |
| Advanced services | How to price premium features? | Reserved token (future, if justified) | Potentially |

The proof addresses entity behaviour within the network. Infrastructure operation is a service market problem below the cooperation layer. SPOs don't need to be incentivised to share memories honestly (the proof handles that). They need to be incentivised to provide storage, bandwidth, and uptime -- a straightforward service economics question.

If a CORDELIA token is ever deployed, it must never be used to incentivise memory-sharing behaviour. The cooperative equilibrium is sustained by mechanism design alone. The token, if deployed, operates strictly at the infrastructure layer.

---

## 5. SPO Deployment Options (Added 2026-03-10)

Three supported deployment scenarios. All functionally identical for keeper operation.

| Option | Where | Delegation Verification | Calidus Key | Best For |
|--------|-------|------------------------|-------------|----------|
| A: On relay node | Alongside cardano-node | cardano-cli (local, zero cost) | On same machine | SPOs with spare relay capacity |
| B: Separate server | Own VPS/server | Koios or Blockfrost API | Copied (Ed25519 file) | SPOs who don't want to touch relay infra |
| C: Docker sidecar | Any Docker host | Koios or Blockfrost API | Mounted as volume | Containerised SPO setups |

`cordelia init --spo` auto-detects environment: if cardano-cli found, uses it. Otherwise prompts for Blockfrost project ID (free: 50K req/day) or Koios token (free tier available). Delegation checks run epoch-aligned (every 5 days) -- trivial load on any API tier.

**Requirement:** Calidus key (CIP-0151) registration is prerequisite. 231 pools registered as of 2026-03-10. Reasonable quality signal for serious operators.

---

## 6. Decentralised Discovery (Added 2026-03-10)

**Principle: Seed Drill seeds the network; it does not control it.**

### CIP-6 Extended Metadata

SPOs advertise Cordelia capability in their CIP-6 extended metadata JSON (no size limit, no on-chain tx to update):

```json
{
  "serial": 1,
  "pool": { "...existing CIP-6 fields..." },
  "cordelia": {
    "version": "1.0",
    "keeper": true,
    "endpoint": "https://keeper.example.com:7847",
    "pubkey": "ed25519_pk1...",
    "plans": [
      { "name": "free", "conditions": [], "limits": { "storage_mb": 1, "channels": 2 } },
      { "name": "basic", "conditions": [{"type":"delegation","min_ada":500}], "limits": { "storage_mb": 10, "channels": 5 } },
      { "name": "premium", "conditions": [{"type":"delegation","min_ada":5000}], "limits": { "storage_mb": 1024, "channels": 50 } }
    ],
    "cultures": ["chatty", "taciturn"],
    "region": "eu-west"
  }
}
```

CIP-6 `plans` array uses the same condition schema as the commercial policy (without the `policy` wrapper for compactness in metadata). `cordelia init --spo` generates: (1) cordelia metadata section, (2) merged extended-metadata.json, (3) Ed25519 signature. For SPOs without extDataUrl, generates the re-registration transaction body (~2 ADA, one-time).

Unknown fields ignored by existing pool browsers (CIP-6/CIP-100 design). No breakage.

### On-Chain Bootnode Registry

Register a Cordelia-specific CIP-10 transaction metadata label. **Anyone** can publish bootnode lists as Cardano transaction metadata (~0.2 ADA per tx):

```json
{
  "XXXX": {
    "t": "bootnodes",
    "v": 1,
    "nodes": [
      { "e": "boot1.seeddrill.ai:7847", "p": "pool1abc..." },
      { "e": "keeper.stakenuts.com:7847", "p": "pool1def..." }
    ],
    "slot": 147900000
  }
}
```

Readers merge multiple publishers' lists. Latest slot per publisher wins. Permanently on-chain -- recoverable from any Cardano full node.

### Directory Channel

`cordelia:directory` -- a well-known reserved channel where every keeper publishes service manifests. Encrypted with a well-known PSK (published in protocol spec) for protocol uniformity. Chatty culture. Auto-subscribed on boot.

The channel IS the directory. No central aggregator. Any client subscribed gets a live, self-updating keeper registry.

### Discovery Cascade

```
1. Binary ships with hardcoded seeds (genesis, rarely updated)
2. Query chain for Cordelia metadata label → get current bootnode lists
3. Connect to best-available bootnode
4. Subscribe to cordelia:directory → live keeper directory
5. Gossip maintains ongoing discovery
```

After initial bootstrap (steps 1-3), the network is self-sustaining via steps 4-5.

---

## 7. SPO Incentives and Branding (Added 2026-03-10)

### The Differentiation Problem

~3,000 active pools, most unsaturated, all competing for delegation. Differentiation options are limited: fees (race to bottom), mission (niche), community engagement (time-intensive). Almost no pools offer concrete additional services.

### The Cordelia Value Proposition for SPOs

| What SPO Gets | How |
|---|---|
| Differentiation | "Cordelia-Powered Keeper" -- unique, concrete service offering |
| Delegation magnet | Users who want Cordelia delegate to enabled pools |
| Visibility | Listed in `cordelia:directory` channel + any community-built explorer |
| Branding assets | "Cordelia-Powered" badge, logos, templates (open, public repo) |
| Community standing | Early adoption visible via directory channel timestamps |
| Revenue | More delegation = more blocks = more ADA rewards |

### The Flywheel

SPO runs Cordelia → listed in directory → promotes to their community → delegators discover Cordelia → delegate to enabled pools → SPO gets more delegation → other SPOs notice → onboard → network effect.

**Every SPO becomes a Cordelia evangelist because it's in their economic self-interest.** We don't need marketing campaigns. Delegation economics create natural alignment.

### Design Principles

1. **Zero cost to start**: Binary is free and open source. Free tier exists. No approval process.
2. **Self-service onboarding**: `cordelia init --spo` handles everything. No manual Seed Drill approval.
3. **SPO controls their brand**: Own domain, own messaging, own welcome page. Seed Drill provides assets, not constraints.
4. **Metrics are public by default**: Keeper `/status` endpoint. Transparency builds trust.
5. **Directory is earned**: Listed automatically when keeper is online and healthy. Delisted when offline. No favouritism.
6. **Branding is open**: Published to public git repo and/or IPFS. CC-BY license. SPOs use and modify freely.
7. **"Cordelia-Powered" is self-declared**: If your keeper is in the directory, you're Cordelia-Powered. No certification needed. The network validates, not Seed Drill.

### What Seed Drill Provides vs What SPO Provides

| Seed Drill | SPO |
|---|---|
| Keeper binary (free, open source) | Server infrastructure |
| Branding assets (open, public repo) | Community promotion |
| Protocol development | Service quality |
| Technical support | Delegation relationships |
| 1-2 bootnodes (just another participant) | Geographic distribution |

---

## 8. Implementation Phases

**Phase mapping:** These are SPO-specific phases. They map to the overall project phases as follows: SPO Phase 1-2 = Project Phase 3 (Network Growth + SPO), SPO Phase 3 = Project Phase 3+, SPO Phase 4 = Project Phase 4+. See architecture ADR Section 17 for the canonical phase alignment.

### Phase 1: SPO Onboarding (Pre-Token) [Project Phase 3]

- Package Cordelia keeper as Docker image and systemd service
- `cordelia init --spo` with auto-detection (cardano-cli / Koios / Blockfrost)
- CIP-6 cordelia metadata section generator
- Define pool metadata JSON schema for Cordelia capability advertisement
- Build delegation verification module (cardano-cli + Koios/Blockfrost fallback)
- Create SPO onboarding guide ("Run a Cordelia Keeper in 15 Minutes")
- Deploy 3-5 pilot SPOs from existing Cardano community contacts
- Integrate with core#45 (instrumentation) for service quality measurement
- Publish branding assets to public repo

### Phase 2: Service Market (Delegation Model Live) [Project Phase 3]

- Service parameter configuration and advertisement via CIP-6
- Tiered access based on delegation proof (epoch-aligned verification)
- `cordelia:directory` channel live -- decentralised keeper directory
- SPO keeper `/status` endpoint for public metrics
- On-chain bootnode registry (CIP-10 metadata label)
- Monitoring and SLA reporting (ties to core#28, core#45)

### Phase 3: Token Optionality (Design + Reserve) [Project Phase 3+]

- Register CORDELIA policy ID on Cardano mainnet
- Publish tokenomics whitepaper (design only, no minting)
- Develop smart contracts for governance voting (Aiken)
- Develop service credit / premium feature billing contracts
- MiCA compliance review with legal counsel
- Decision gate: deploy token only if delegation model proves insufficient

### Phase 4+: Oracle Services (Design Notes) [Project Phase 4+]

- `cordelia:attestations` channel for peer quality attestations
- Oracle node aggregates attestations, publishes epoch-aligned summaries on-chain
- Verifiable reputation: delegators make informed choices from auditable chain data
- Potential Charli3/Orcfax integration for Cardano-native oracle infrastructure
- Feeds into delegation decisions → good keepers earn more → natural quality pressure

---

## 9. Success Criteria

**Short-term (60 days):**
- SPO metadata schema defined and reviewed by 2+ Cardano community members
- Keeper binary packaged as Docker image with <5 minute setup
- 1 pilot SPO running Cordelia keeper on testnet alongside their Cardano node

**Medium-term (6 months):**
- 10+ SPOs running Cordelia keepers on mainnet
- Delegation-based tiering operational
- Service quality metrics flowing (core#45)
- Tokenomics design document published (no deployment)

**Long-term (12 months):**
- 50+ SPOs across 10+ countries
- Organic delegation growth to Cordelia-enabled pools
- Decision on token deployment based on observed network economics

---

## 10. Positioning Constraint: Cardano-Resonant but Not Cardano-Centric

The SPO distribution strategy must achieve two goals simultaneously:

1. **Resonate with Cardano ecosystem** -- speak the language of staking, delegation, and SLAs. SPOs should see Cordelia as a natural extension of their infrastructure role.
2. **Not appear Cardano-centric** -- Cordelia's public identity leads with "encrypted AI memory", not blockchain infrastructure. Wider adoption (enterprise, non-crypto developers, other chains) requires chain-agnostic positioning.

**Resolution**: The architecture already supports this -- Cordelia's protocol layer (QUIC, groups, encryption) has zero chain dependency. Cardano integration is an economic/distribution plugin, not a foundation. The public-facing positioning (s&p#7, seeddrill.ai) leads with sovereignty and encryption. SPO onboarding materials are channel-specific, not product-defining.

**Deferred to**: s&p#7 (positioning page, Track 2) where messaging is codified. This constraint must be respected in that work.

---

## 11. Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| SPO apathy -- no interest in running Cordelia | Medium | High | Start with engaged community members. Prove low overhead, clear value prop. |
| Delegation insufficient incentive | Low | Medium | Monitor delegation flows. Fall back to bilateral ledger (Option 4) if needed. |
| Free-riding overwhelms capacity | Medium | Medium | Delegation proof gates premium tiers. Rate limiting on free tier. |
| Cardano ecosystem decline | Low | High | x402 as secondary rail. Cordelia node is chain-agnostic at protocol level. |
| Token regulatory risk (if deployed) | Medium | High | MiCA-compliant design from day one. Legal review before any minting. No presale. |
| Conflict with cooperative equilibrium positioning | Low | Medium | Clear separation: token for infrastructure, mechanism for cooperation. Document boundary. |

---

## 12. Review Date

2026-06-09 (3 months). Review:
- SPO interest level from community outreach
- Pilot SPO operational status
- Delegation model viability assessment
- Token design progress

---

## 13. Actions

**On-Chain Infrastructure:**
- [ ] Register CIP-10 transaction metadata label for Cordelia
- [ ] Define on-chain channel registration format (name_hash, owner script, deposit UTXO)
- [ ] Register CORDELIA token policy ID on Cardano mainnet
- [ ] Draft CIP proposal: "Decentralised Channel Registry via Transaction Metadata"

**Unified Condition Schema + Policy Engine:**
- [ ] Define unified condition schema (open, invite_only, delegation, ada_payment, token_gate, credential)
- [ ] Define shared policy structure (`{ conditions, logic }`) used by both keeper and channel contexts
- [ ] Build condition verification engine (on-chain for delegation/payment/token, signature for credentials)
- [ ] Build keeper commercial policy evaluation (plan matching from conditions)
- [ ] Build channel access policy evaluation (PSK distribution gating from conditions)
- [ ] Build `cordelia init --spo` flow with commercial policy wizard
- [ ] Build on-chain payment verification (tx_hash → confirmed amount → correct recipient)

**Keeper Infrastructure:**
- [ ] Define Cordelia CIP-6 extended metadata JSON schema (incl. commercial policy)
- [ ] Build CIP-6 metadata generator (cordelia section + merge + signature)
- [ ] Build delegation verification module (cardano-cli + Koios/Blockfrost fallback)
- [ ] Build Calidus key challenge-response verification module
- [ ] Package keeper binary as Docker image with SPO-oriented config

**Community and Ecosystem:**
- [ ] Publish branding assets to public repo (badges, logos, templates, CC-BY)
- [ ] Identify 3-5 pilot SPOs from Cardano community (Calidus-registered preferred)
- [ ] Draft tokenomics design document (principles, distribution, utility)
- [ ] Update whitepaper Section 9 (economics) with two-layer model + decentralised discovery
- [ ] MiCA preliminary assessment (utility token classification)

---

## 14. Outcome (To Be Updated)

*Fill in at review date (2026-06-09) with actual results vs. expectations.*

---

*Decision proposed by Russell Wing (CPO), 2026-03-09*
