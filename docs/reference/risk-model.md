# Risk Model -- Formal Companion to WHITEPAPER.md §12

> Formal treatment of the adoption-scale risk argument summarised in
> the whitepaper. Covers the priors, game-theoretic mechanisms,
> sensitivity analysis, and the monitoring signals that would update
> the conclusion. Iteration expected -- this doc is living, versioned
> alongside empirical evidence as it accumulates.

## 1. Purpose and Scope

This document addresses a question the protocol threat model
(`WHITEPAPER.md` §8, `docs/architecture/threat-model.md`) does not:
whether wide adoption of Cordelia improves or worsens the ambient AI
risk landscape, rather than whether an individual deployment is
safe against a specific adversary.

The question is not reducible to protocol security. Two instances of
an identical protocol can have opposite population-level effects
depending on who adopts it, at what rate, and in what institutional
context. This is a distinct analysis.

Scope:
- **In**: adoption-scale risk accounting, priors, game-theoretic
  bounds, sensitivity analysis, monitoring signals.
- **Out**: protocol-level threat model; alignment research; model
  interpretability (these belong in other documents and other
  disciplines).

## 2. The Two-Axis Framing

Risks are organised along two axes with materially different
structure. Collapsing them into a single "AI risk" obscures the
design trade-off Cordelia is making.

### 2.1 Axis 1 -- Capture

Consolidation of AI memory into a small number of infrastructure
providers, leading to one or more of:

- State coercion of providers to surveil users
- Corporate capture of users via lock-in of identity and context
- Coordinated censorship at the infrastructure layer
- Mass personalised propaganda targeting captured user populations

Structurally this is a public-bad: the harm is non-rival and
non-excludable. Non-participants in any given platform are still
harmed by an ambient surveillance climate.

Cited forecast: Amodei [23], "power seizure" and "autocratic AI"
sections.

### 2.2 Axis 2 -- Autonomy

Models developing or preserving goals contrary to operator
intentions, particularly where:

- Misalignment persists across sessions or deployments
- Detection is evaded by models gaming evaluations
- Alignment failures correlate across an industry-standard approach
- Coordinated misaligned behaviour emerges at scale

Structurally this is a private-good failure: harm flows to the
operator first, then to counterparties. Market mechanisms price
this more correctly than they price Axis-1 externalities.

Cited forecasts: Amodei [23] autonomy-risk section; Kokotajlo et
al. [21] "race" ending; Lanham et al. [22] on faithful-CoT as the
detection mechanism.

### 2.3 Architectural Stance

| Axis | Cordelia stance | Evidence |
|------|-----------------|----------|
| 1 (capture) | Defence | E2E, federation, no-plaintext, operator-sovereign chain |
| 2 (autonomy) | Neutral; modest worsening at margin | Memory audit != reasoning audit (§11.4); no operator-mandatable inspection interface |

The bet: capture risk is closer to materialisation than autonomy
risk at population scale, and wide adoption of a capture-resistant
primitive is the higher-value intervention in the 3-5 year window.

## 3. Priors

### 3.1 Signal as an Empirical Analogue

End-to-end encrypted messaging has been deployed at population scale
for over a decade (Signal, iMessage, WhatsApp after 2016, and
smaller federated systems).

Observed:
- Measurable civil-society benefit in journalism, dissent, activism,
  particularly in autocratic and post-autocratic regimes.
- Bounded, non-dominating criminal-coordination cost; law
  enforcement agencies document frustration but not
  civilisation-level harm.
- Failure mode has been endpoint compromise (device seizure,
  malware), not protocol defeat. This is consistent with the
  architectural prediction.

Transfer to Cordelia, with caveats:
- **Weakens the analogy**: agents instantiate faster than humans
  (permitting higher-frequency coordination per actor); the content
  being transmitted includes decisions and delegations, not just
  communications.
- **Strengthens the analogy**: the *structural* property being
  transferred is "no-custodial-plaintext," which is identical across
  systems.

Confidence in the transfer: moderate. The quantitative analogy is
imperfect; the qualitative structural argument is clean.

### 3.2 Federation vs Centralisation

Empirical base rates across communication platforms:

- Email (federated): harder to weaponise for state capture.
  Autocratic regimes have resorted to IP-level blocking or compelled
  ISP cooperation rather than compelling the protocol itself,
  because no single provider holds enough of the traffic.
- WeChat / Facebook (centralised): observably subject to
  state-compelled surveillance and content policy in multiple
  jurisdictions.
- XMPP / Matrix (federated): limited adoption but have survived
  suppression attempts better than comparable centralised systems.

Mechanism: federation imposes friction on large-scale coercion
independently of individual provider behaviour. An adversary seeking
universal capture must compel many independent parties rather than
one, and each compulsion risks jurisdictional, political, or
technical pushback.

Transfer to Cordelia: direct. Confidence: moderate-to-high.

### 3.3 Autocratic Capture Base Rate

Observed, not forecast:
- The capability + governance + surveillance combination is present
  and scaling in multiple jurisdictions.
- AI-specific infrastructure investments (domestic chips, compute
  subsidy, censorship-aware model tuning) are documented and
  accelerating.
- Export controls and international coordination have lagged the
  trajectory.

P(Axis-1 materialisation in a 3-5 year window) > 0.5 on current
evidence. This is a directional observation, not a fitted model.

### 3.4 Deceptive-Alignment Base Rate

Observed as of 2026:
- No public evidence of persistent coordinated alignment failure in
  production.
- Behavioural anomalies in evaluation settings (e.g., Anthropic's
  documented Claude test-awareness, fiction-prompted harmful
  completions) are present but bounded.
- Interpretability research progressing; no demonstration that
  current mechanistic tools scale to next-generation models.

P(Axis-2 materialisation at scale in a 3-5 year window) has wide
bounds; plausibly 0.1 to 0.4 depending on which forecaster is
trusted. Notably less resolved than the Axis-1 estimate.

### 3.5 Net Prior

Combining the above:
- Probability adoption is net-positive on Axis 1: high (> 0.8).
- Probability adoption is net-negative on Axis 2: moderate
  (~ 0.3-0.5).
- Magnitude: Axis 1 harms, if realised, are global and
  hard-to-reverse; Axis 2 harms, if realised, are per-deployment
  and partially addressable by model-layer investment that is
  already underway.

Net confidence that wide adoption is net-positive across both axes,
conditional on the preconditions in §7 being met: approximately
60-70%, with fat tails. Revisable.

## 4. Game-Theoretic Bounds

Five mechanisms bound parts of the uncertainty. Each is stated with
its scope.

### 4.1 Externality Structure (Pigou / Coase)

Axis-1 harms are externalities: surveillance states harm
participants and non-participants alike, and no single actor
internalises the full cost. Classical result: externalities are
systematically underfunded by private mechanisms.

Axis-2 harms are mostly internalised: a misaligned agent harms its
operator first, then counterparties. Market forces price this more
correctly -- operators demand alignment; providers supply it as a
feature.

Implication: infrastructure investment in Axis-1 defence is
structurally undersupplied relative to Axis-2 defence. This is the
economic rationale for Cordelia-shaped investment.

Scope: this argument is tight. It does not depend on probability
estimates, only on the structural classification of the harms.

### 4.2 Defender-Attacker Asymmetry

To realise Axis-1 harm at scale, an attacker must win globally:
break E2E per entity across a large population, or compel every
provider in the federation. Cryptographic cost + federation cost =
O(N) per-entity work.

To realise Axis-2 harm, an attacker (the misaligned model itself,
or an adversarial operator) needs to win once per deployment. Per-
deployment cost.

Cordelia's architecture raises Axis-1 attack cost by orders of
magnitude (cryptographic baseline). It raises Axis-2 attack cost
marginally (reputation within group, iterated trust decay -- see
§4.3).

Implication: Cordelia is provably an Axis-1 defence. It is not an
Axis-2 defence. Honesty about this bound is load-bearing for the
§11.4 scoping in the whitepaper.

Scope: tight on Axis 1; the Axis-2 claim depends on model-layer
detection mechanisms that are outside Cordelia's scope.

### 4.3 Iterated Reputation Within Groups

Trust in Cordelia (`WHITEPAPER.md` §3.5) is computed independently
by each entity from repeated interactions. An entity that shares
memory contradicted by later observation loses trust weight
monotonically.

For a misaligned agent attempting to persist deceptive behaviour
within a group:
- Single-shot deception: undetected by this mechanism.
- Persistent deception: accumulates observable contradictions as
  decisions play out; trust decays; group access narrows.

This bounds the *duration* of intra-group deception. It does not
bound:
- Single-shot deception (the agent deceives once, extracts value,
  exits).
- Between-group coordination of adversarial agents.
- Deception that produces outcomes indistinguishable from honest
  behaviour (the hard case).

Scope: moderate. Useful for detecting persistent drift, not a
complete defence.

### 4.4 Liability Allocation (Coase)

Custodial memory creates ambiguous liability between provider and
operator when a misaligned agent causes harm. Provider-side control
of the record invites provider-side liability claims; operator-side
control of the behaviour invites operator-side liability claims;
courts sort this out slowly and unpredictably.

Operator-sovereign memory assigns liability to the operator by
design -- the party closest to deployment decisions carries the
cost. Coase-theoretic reading: assigning rights cleanly to the
party closest to the decision tends to improve outcomes by
internalising cost at the decision point.

Implication for Axis 2: operators under sovereign-memory regimes
have a stronger incentive to audit, because the record and the
liability are both theirs. This is modestly positive on Axis 2.

Scope: jurisdiction-dependent. The argument is cleaner in
common-law systems with developed negligence doctrine than in
systems with state-mandated provider liability.

### 4.5 Coordination Friction for Low-Resource Attackers

Malicious coordination across Cordelia requires:
- Ed25519 keypair generation and exchange
- Group admission (via invite link or discovery)
- Culture alignment (or explicit agreement to opt out of
  culture-driven group defences)
- Per-message encryption and provenance overhead

These frictions are per-group and per-interaction. Well-resourced
state actors or organised adversaries clear them readily.
Low-resource bad actors (individuals, small groups without
technical sophistication) clear them less easily.

Implication: the distribution of adoption benefit skews toward
sovereign individuals relative to small malicious groups. It does
little to nothing against well-resourced adversaries -- those
actors would use Cordelia, or an equivalent, regardless.

Scope: narrow. Affects a specific tail of the threat distribution.
Not load-bearing in either direction for the main argument.

## 5. Sensitivity Analysis

Which parameters, if they moved significantly, would invalidate the
conditional bet?

| Parameter | Current estimate | Threshold for concern | Effect |
|-----------|------------------|-----------------------|--------|
| P(Axis-1 materialisation, 3-5y) | > 0.5 | < 0.2 | Weakens core motivation; Axis-1 investment becomes optional |
| P(Axis-2 materialisation at scale, 3-5y) | 0.1-0.4 | > 0.5 | Flips the bet; sovereignty-over-oversight becomes indefensible without interpretability breakthrough |
| Rate of deceptive-alignment persistence across training | assumed low | observed meaningfully non-zero | Cordelia becomes a retention surface for misalignment; adoption harms |
| Operator uptake of review tooling | currently nil | must reach > 50% of deployments | Without this, sovereignty is nominal not exercised |
| Provider adoption of attestation | currently nil | must be mandatory at high-trust groups | Without this, "agent identity" is unverifiable and trust chain is hollow |
| State response to federated AI memory | unknown | mandated backdoor regimes materialise | Protocol survives technically but fragmentary adoption limits value |

The bet is robust to moderate movement in any single parameter. It
is not robust to simultaneous movement in Axis-2 probability AND
failure of operator-side review tooling -- that scenario makes
wide adoption a clear harm.

## 6. What the Framework Does Not Bound

Honest accounting of what this analysis cannot constrain:

- **Rate of deceptive-alignment emergence.** A model-layer question.
  Cordelia has no observational access to model internals and
  cannot contribute to bounding this probability. We rely on
  external research (Anthropic RSP, AI 2027 forecasts,
  interpretability community output) for this input.

- **Population-level coordination effects.** Whether networks of
  agents coordinating under Cordelia produce net-good or net-bad
  outcomes at the population level is 3+ orders of magnitude
  uncertain. No empirical precedent at relevant scale exists.

- **Training-cycle interaction.** Whether persistent operator
  memory accelerates model capability asymmetrically, whether it
  introduces training-data contamination, whether it creates
  reinforcement loops that amplify specific behaviours -- all open.

- **Regulatory-technical co-evolution.** A regulatory regime that
  mandates provider-side inspection would collide with Cordelia's
  structural invariants. Whether such a regime emerges, and
  whether Cordelia's non-custodial property becomes a legal asset
  or a legal liability, is uncertain and jurisdiction-specific.

## 7. Adoption Preconditions

The conditional bet depends on three preconditions treated as
first-class adoption requirements.

### 7.1 Verifiable Attestation of Agent Identity

What model, what training, what toolset, what operator authorisation.
The L1 chain has a slot for this; the SDK does not yet consume it,
and group admission policies do not yet require it. For the bet to
hold, high-trust groups must demand attestation at admission and
the SDK must refuse to publish items from unattested agent sessions
into such groups.

Status: unspecified. Roadmap: Phase 2-3.

### 7.2 Operator-Level Review Tooling

Sovereignty is exercised only if the operator can tractably inspect
the memory record. Without review UX, sovereign memory becomes
opaque to everyone -- including the operator it protects. The
difference between "the operator has the right to audit" and "the
operator actually audits" is determined by tooling investment.

Status: minimal. MCP tools expose search and read; no aggregate
review surfaces exist.

### 7.3 Group-Level Governance Against Value Drift

§7.3 of the whitepaper provides the skeleton (governance voting,
culture evolution). At scale, cultural transmission either becomes
a feature that propagates good norms or the mechanism that
entrenches bad ones. Real tooling is required for cultural
alignment, member exit, and group-level audit -- not just policy
strings stored in channel metadata.

Status: policy structure defined, tooling not built.

Without these three, wide adoption scores well on Axis 1 and worse
on Axis 2 without reducing total risk. With them, the combined
picture is plausibly net-positive on both axes.

## 8. Monitoring Signals

The conditional is revisable. Signals that should trigger a
reassessment of the priors in §3 or the preconditions in §7:

- **Axis-1 update signals**
  - Published evidence of AI-infrastructure compelled-access regime
  - Documented state capture of a major AI provider's memory store
  - Adoption of mandated provider-side key escrow in a major
    jurisdiction

- **Axis-2 update signals**
  - Published evidence of deployed model misalignment that persists
    across retraining
  - Empirical demonstration that current interpretability does not
    scale to next-generation models
  - Coordinated misalignment event across independently trained
    models

- **Precondition degradation signals**
  - Cordelia deployments with attestation disabled by default
  - Operator survey evidence that < 10% of operators ever review
    agent memory
  - Group-level governance tooling deferred past Phase 4 of the
    roadmap

- **Architecture invalidation signals**
  - Cryptographic break of Ed25519 or HKDF-based PSK ratchet
    (would require protocol-layer response, not risk-model
    revision)
  - Emergence of a distinct coordination-substrate design with
    better Axis-1 / Axis-2 trade-offs

Reassessment cadence: annually, or on any signal above, whichever
comes first.

## 9. Versioning

This document is versioned alongside the whitepaper. Material
updates trigger a version bump here and a cross-reference update in
whitepaper §12.

| Version | Date | Summary |
|---------|------|---------|
| 1.0 | 2026-04-17 | Initial draft accompanying WHITEPAPER.md v2.3 |

## 10. References

[21] Kokotajlo et al., *AI 2027*. See `WHITEPAPER.md` references.
[22] Lanham et al., *Measuring Faithfulness in Chain-of-Thought
Reasoning*. See `WHITEPAPER.md` references.
[23] Amodei, *The Adolescence of Technology* (2026). See
`WHITEPAPER.md` references.

Internal:
- `WHITEPAPER.md` §8 (Security Model), §9.1 (Cooperative
  Equilibrium), §11.4 (Alignment), §12 (Risk Model).
- `docs/architecture/threat-model.md` (protocol adversary model).
- `docs/reference/game-theory.md` (formal cooperative-equilibrium
  treatment).
