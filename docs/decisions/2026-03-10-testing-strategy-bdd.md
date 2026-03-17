# Decision: Testing Strategy -- BDD with Cucumber/Gherkin

**Date**: 2026-03-10
**Decision Maker(s)**: Russell Wing, Martin Stevens
**Status**: Accepted
**Triggered by**: Martin raised Cucumber/Gherkin as a testing approach for Cordelia

---

## 1. Context

Cordelia has multiple test layers today:

- **Rust unit/integration tests** (`cargo test`) -- 173+ tests in cordelia-core
- **TypeScript tests** -- proxy unit tests
- **E2E Docker tests** -- multi-node topology, 21/21 green, shell-scripted assertions
- **Resilience tests** -- 10/10 green, workflow_dispatch

Martin proposed adopting BDD (Behavior-Driven Development) using Cucumber and Gherkin for Cordelia. The question: where does it add value, and where does it add overhead?

## 2. Options Considered

### A. Gherkin everywhere

Apply Cucumber across Rust node, proxy, SDK, and E2E tests.

- **Pro**: Uniform test language, specs double as documentation
- **Con**: `cucumber-rs` is less mature than `cucumber-js`. Significant migration cost for existing tests. Overhead for a 2-person team where both are technical.

### B. Gherkin for SDK and pub/sub API only

Apply Cucumber to the SDK acceptance tests (WP6) and pub/sub API contract (WP3). Keep Rust and E2E tests as-is.

- **Pro**: Specs-as-documentation where external developers are the audience. `cucumber-js` is mature. No migration of working tests.
- **Con**: Two test styles in the project.

### C. No Gherkin

Continue with current test infrastructure.

- **Pro**: No new tooling, no learning curve, fastest path to Phase 1.
- **Con**: Miss the documentation benefit for SDK users.

## 3. Decision

**Option B: Gherkin for SDK and pub/sub API.**

Rationale:

1. **SDK specs are external-facing.** Gherkin feature files double as living documentation for developers integrating Cordelia. This is the audience that benefits most from readable specs.

2. **Pub/sub API is the core contract.** Subscribe, publish, listen, channel creation, access control -- these are the behaviours that must be specified precisely. Gherkin scenarios are a natural fit:

```gherkin
Feature: Channel subscription
  Scenario: Subscribe and receive published message
    Given an agent with a valid keypair
    When the agent subscribes to channel "engineering"
    And another agent publishes "cache invalidation" to "engineering"
    Then the first agent receives the message within 5 seconds
    And the message content is encrypted in transit

  Scenario: Private channel requires invitation
    Given a private channel "board-updates"
    When an uninvited agent attempts to subscribe
    Then the subscription is rejected with "not_authorized"
```

3. **Rust internals stay as cargo test.** The node's storage, crypto, replication, and peer governor are internal implementation. `cargo test` is simpler, faster, and understood by Martin who maintains it. `cucumber-rs` exists but adds ceremony for no new audience.

4. **Existing E2E tests stay as-is.** The Docker topology tests (21/21, 10/10 resilience) are working infrastructure. Rewriting in Gherkin adds migration cost for zero new coverage.

5. **Team size matters.** BDD's primary value is shared understanding between spec writers and implementers. With two technical co-founders, that translation layer is less critical. The strongest argument is specs-as-documentation for the SDK, where external developers are the audience.

## 4. Implementation

- **Tooling**: `cucumber-js` in the `cordelia-sdk` repo (WP6)
- **Feature files**: `features/` directory in SDK repo
- **Step definitions**: TypeScript, alongside SDK source
- **CI**: Run as part of SDK test suite in GitHub Actions
- **Scope**: SDK acceptance tests + pub/sub API contract. Not Rust node, not existing E2E.

## 5. Revisit Triggers

- If external contributors start writing features/tests -- broader Gherkin adoption may help
- If the SDK grows to support Python -- Gherkin specs become language-neutral acceptance criteria
- If `cucumber-rs` matures significantly -- reconsider for Rust integration tests

---

## 6. Extended Testing Strategy (2026-03-11)

The BDD decision (§3) covers functional behaviour. This section extends the strategy to cover protocol correctness, economic soundness, and adversarial resilience. Five layers, each targeting a different failure class.

### 6.1 Test Layers

```
Layer 5: Red Team Wargaming          (creative attacks, social/economic)
Layer 4: Agent-Based Simulation       (equilibrium analysis, population dynamics)
Layer 3: Topology E2E                 (implementation conformance, Docker, multi-node)
Layer 2: TLA+ Model Checking          (protocol correctness, formal verification)
Layer 1: Single-Node E2E              (real binary, real filesystem, real HTTP)
Layer 0: Unit / BDD                   (functional behaviour, cargo test + cucumber-js)
```

Each layer catches failures the layer below cannot:

| Layer | What it catches | Tool | When |
|-------|----------------|------|------|
| 0: Unit/BDD | Logic bugs, API contract violations | cargo test, cucumber-js | Every commit (CI) |
| 1: Single-Node E2E | Binary startup, config loading, file permissions, real DB, real HTTP, CLI commands | Shell script + curl | Every commit (CI) |
| 2: TLA+ | Protocol design flaws (deadlocks, liveness failures, safety violations) | TLC model checker | Pre-coding gate (WP14) |
| 3: Topology E2E | Implementation doesn't match model, role interaction bugs, partition handling | Docker Compose, shell assertions | Post-WP3 (WP15) |
| 4: Agent-Based Sim | Broken economic equilibria, incentive misalignment at scale, population collapse | cadCAD or Python Monte Carlo | During WP3, validates at scale |
| 5: Red Team | Creative multi-step attacks, social engineering, economic exploits formal methods miss | Attack trees + structured wargaming | Pre-coding (attack trees), pre-release (wargaming) |

### 6.1.1 Layer 1: Single-Node E2E Smoke Test

**Gap identified:** Layer 0 tests run in-process (actix-web test server, in-memory SQLite). Layer 3 tests multi-node Docker topologies. Nothing tests the real compiled binary running as a daemon, serving real HTTP requests against real filesystem state. This is the layer where config parsing, file permissions, port binding, schema migrations on real SQLite, and CLI subcommands fail.

**Scope:** Full single-node lifecycle via the real binary:

1. `cordelia init` -- keypair generation, DB creation, personal channel, config write
2. `cordelia start` -- daemon startup, HTTP bind, bearer auth
3. API exercise -- subscribe, publish, listen, search, DM, group, identity, metrics (all 17 endpoints)
4. CLI exercise -- `cordelia status`, `cordelia channels`, `cordelia stats`, `cordelia peers`
5. Cleanup -- kill daemon, remove temp data

**Location:** `cordelia-node/tests/e2e/smoke-test.sh`

**Assertions:** HTTP status codes, JSON response field presence, Prometheus metric names, CLI output strings. Uses `curl` + `jq` for API, grep for CLI output.

**Failure semantics:** Any non-zero assertion exits the script with status 1. No retries -- if it's flaky, it's a bug.

**CI:** Runs after `cargo test` in the standard workflow. No Docker required. ~10 seconds.

### 6.2 Layer 2: TLA+ Model Checking (WP14)

**Scope:** Protocol correctness for bounded topologies.

**Module:** `specs/network-protocol.tla`

**Properties verified (9):**

| ID | Property | Type | Checks |
|----|----------|------|--------|
| P1 | Delivery | Liveness | Items reach subscribers_only subscribers |
| P2 | Pull delivery | Liveness | Items reach pull_only subscribers via Item-Sync |
| P3 | Channel isolation | Safety | No cross-channel item leakage |
| P4 | Role isolation | Safety | Bootnodes never store, relays never hold PSKs |
| P5 | Loop termination | Safety | Relay re-push terminates in bounded steps |
| P6 | Convergence | Liveness | Post-partition subscribers converge |
| P7 | Bootstrap completion | Liveness | All nodes reach steady state |
| P8 | Push silence | Safety | pull_only generates zero pushes |
| P9 | Bootnode silence | Safety | Bootnodes generate zero replication messages |

**Economic extension (additional properties):**

| ID | Property | Type | Checks |
|----|----------|------|--------|
| P10 | Defector demotion | Safety | Relay with contribution_ratio < 0.3 demoted within 2 ticks |
| P11 | Ban propagation | Liveness | Permanent ban reaches all honest nodes within 3 Peer-Sharing rounds |
| P12 | Probe detection | Safety | Relay failing >50% probes is never Hot |

**Bounds:** Default 2 personal, 1 bootnode, 1 relay, 2 channels, 2 items. Larger bounds (2/1/2/2/3) on CI.

**Gate:** All properties must pass before WP3 implementation begins.

### 6.3 Layer 3: Topology E2E (WP15)

**Scope:** Implementation conformance to TLA+ model.

**7 reference topologies (T1-T7):** See WP15 in implementation plan.

**Coverage metric:**
```
Topology space: roles x connectivity x failures x push_policy
Meaningful scenarios: ~80-120 (after pruning degenerate cases)
Coverage = tested / meaningful
Target: >80% at Phase 1 release
```

**Assertion mapping:** Each TLA+ property maps to a concrete Docker E2E assertion (SQLite queries, metrics counters, packet capture).

### 6.4 Layer 4: Agent-Based Economic Simulation

**Scope:** Verify economic equilibria hold at population scale.

**Tool:** cadCAD (Python, designed for crypto-economic simulation, used by IOG for Cardano) or custom Python Monte Carlo if cadCAD is too heavy.

**Agent types:**

| Agent | Strategy | Population % |
|-------|----------|-------------|
| Honest subscriber | Subscribe, publish, pay delegation | 60-80% |
| Honest relay | Relay all items, maintain uptime | 10-20% |
| Free-rider | Subscribe, consume, never relay | 5-15% |
| Defector relay | Accept items, silently drop 50%+ | 2-10% |
| Sybil attacker | Create many identities, flood channels | 1-5% |
| Rational SPO | Run keeper if ROI > 0, shut down otherwise | 5-10% |

**State variables:** contribution ratios, probe scores, ban states, delegation amounts, storage used, relay population count, network partition events.

**Properties checked (Monte Carlo, 1000 runs per scenario):**

| ID | Property | Pass criterion |
|----|----------|---------------|
| S1 | Relay population stability | Honest relay count >= 3 in 95%+ of runs after 50 epochs |
| S2 | Honest relay is Nash equilibrium | No agent improves payoff by switching from honest to defector |
| S3 | Defector detection rate | >90% of defectors banned within 10 probe cycles |
| S4 | SPO ROI positive | >80% of rational SPOs remain active after 20 epochs |
| S5 | Sybil cost exceeds gain | Attacker ROI < 1 for budgets up to $10K |
| S6 | Network convergence under churn | All subscribers converge within 5 sync intervals despite 20% annual relay turnover |

**Timing:** Run during WP3 implementation. Results inform parameter tuning (probe_interval, contribution thresholds, ban durations) before release.

### 6.5 Layer 5: Red Team / Attack Trees

**Scope:** Creative multi-step attacks that formal methods miss. Economic cost-benefit analysis.

**Approach:** Two complementary exercises.

#### 6.5.1 Attack Trees (pre-coding)

Formal enumeration of attacker strategies, parameterised by budget. For each attack:

```
Attack: <name>
Goal: <what the attacker achieves>
Budget: <ADA / USD / compute required>
Strategy: <step-by-step attack plan>
Cost to execute: <quantified>
Damage to network: <quantified>
Defence: <spec reference>
Residual risk: <what remains after defence>
ROI: attacker_gain / attacker_cost
Verdict: <profitable | unprofitable | breakeven at $X>
```

**Attacker personas (6):**

| Persona | Budget | Goal | Motivation |
|---------|--------|------|------------|
| Script kiddie | $0 | Disrupt | Boredom, notoriety |
| Competitor | $10K | Degrade service | Market advantage |
| Nation state | $100K | Surveillance | Intelligence |
| Insider (rogue SPO) | $0 (access) | Censor/profit | Revenge, financial |
| Squatter | $5K | Profit | Speculative name hoarding |
| Griefer | $100 | Annoy | Harassment of specific entity |

**Output:** `specs/attack-trees.md` -- formal document, reviewable by Martin, parameterised cost-benefit tables.

**Gate:** Every attack must have ROI < 1 against specified defences, or the defence must be strengthened until it does.

#### 6.5.2 Red Team Wargaming (pre-release)

Structured adversarial exercise. Russell plays attacker, Martin plays defender. Walk through each persona's best strategy against the running system. Document findings, fix vulnerabilities discovered.

**Timing:** After WP3 implementation, before Phase 1 release.

### 6.6 Confidence Measure

Quantifiable confidence formula:

```
Confidence = smoke_pass x TLA_pass_rate x topology_coverage x e2e_pass_rate x economic_sim_pass_rate x attack_tree_coverage

Where:
  smoke_pass          = single-node E2E smoke test passes (binary: 0 or 1)
  TLA_pass_rate       = properties_verified / total_properties (P1-P12)
  topology_coverage   = topologies_tested / meaningful_topologies
  e2e_pass_rate       = e2e_tests_passed / e2e_tests_total
  economic_sim_pass_rate = sim_properties_passed / sim_properties_total (S1-S6)
  attack_tree_coverage = attacks_with_ROI_lt_1 / total_attacks
```

**Phase 1 release target:** All five factors > 90%.

### 6.7 Sequencing

| Order | Activity | Effort | When | Gate for |
|-------|----------|--------|------|----------|
| 1 | Single-node E2E smoke test (§6.1.1) | 0.5 days | Now (post-WP13) | Phase 1 confidence baseline |
| 2 | Attack trees (§6.5.1) | 1-2 days | Now (pre-coding) | Validates §16 defences before implementation |
| 3 | TLA+ model check (§6.2) | 2-3 days | WP14 (pre-coding) | WP3 implementation |
| 4 | Topology E2E harness (§6.3) | 3-4 days | WP15 (during WP3) | Phase 1 release |
| 5 | cadCAD simulation (§6.4) | 3-5 days | During WP3 | Phase 1 release (parameter tuning) |
| 6 | Red team wargaming (§6.5.2) | 1 day | Post-WP3 | Phase 1 release |

---

*Extended 2026-03-11 by Russell Wing. Layers 1-4 added to cover protocol, economic, and adversarial testing.*
*Extended 2026-03-13: Layer 1 (Single-Node E2E) added to close gap between in-process unit tests and multi-node Docker topology tests. Layers renumbered (old 1-4 are now 2-5).*
