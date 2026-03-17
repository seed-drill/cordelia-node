# Decision: Cordelia Identity Model and Privacy Position

**Date**: 2026-03-10
**Decision Maker(s)**: Russell Wing
**Status**: Approved in principle (Martin confirmed pivot 2026-03-10; identity ADR addresses his auth/subscribe question)
**Triggered by**: Architecture pivot design phase (identity requirements for enrollment, channel policies, agent accountability)
**Related**: decisions/2026-03-09-architecture-simplification.md, decisions/2026-03-09-spo-economic-model.md

---

## 1. Context

The architecture pivot (2026-03-09) established keypair-based identity as the foundation. But several design questions remained:

- What IS identity in Cordelia beyond a key?
- How do Alice and Bob interact -- does Alice know it's Bob, or just a consistent pseudonymous entity?
- What entity types exist (human, agent, SPO, service) and does the protocol distinguish them?
- Do we need handles/names?
- How do channel owners set granular access policies (e.g., "must be over 18")?
- How do humans and agents have bilateral (1-to-1) conversations like Signal?
- What is Cordelia's privacy position?

These questions must be resolved before enrollment protocol design, as enrollment is the process of establishing identity.

---

## 2. The Identity Stack

Four layers. Every entity starts at Layer 0. Higher layers are voluntary.

### Layer 0: Key (Protocol -- Always Present)

Every entity has an Ed25519 keypair. This is the canonical identity.

- Encryption (ECIES envelope, PSK distribution)
- Authentication (bearer tokens, keeper handshakes)
- Signing (items signed by author, unforgeable)
- Consistency (same key = same entity, always, across sessions and devices)

This layer is non-optional. Even anonymous entities have a key. The protocol uses only this layer for all cryptographic operations.

### Layer 1: Profile (Self-Declared -- Optional)

An entity publishes profile metadata to their keepers:

```json
{
  "key": "ed25519_pk1...",
  "display_name": "Bob",
  "type": "human",
  "about": "Cardano SPO operator, AI researcher",
  "created_at": "2026-03-10T00:00:00Z"
}
```

Self-declared. No proof. Like a bio before verification. Display names are not globally unique -- they're labels, not identifiers.

### Layer 2: Verification (Proof-Based -- Optional)

Cryptographic proofs linking a Cordelia key to external identities:

| Proof Type | What It Proves | Mechanism | Phase |
|---|---|---|---|
| Operator attestation | "Agent X is operated by Alice" | Alice's key signs agent's key + type | 1 |
| Domain | "I control example.com" | DNS TXT: `cordelia-verify=ed25519_pk1...` | 2 |
| GitHub | "I am @user on GitHub" | Sign a gist with Cordelia key | 2 |
| ADA Handle | "I own $bob" | Sign Cordelia key with handle-holding payment key | 3 |
| Calidus (SPO) | "I operate pool NUTS" | Calidus key signs Cordelia key, verified on-chain (CIP-0151) | 3 |
| Cardano address | "I control addr1..." | Sign message with payment key | 3 |
| Identus DID | "Verifiable credential from issuer X" | W3C VC signed by Identus issuer | 3+ |

Multiple proofs can be attached. Bob might be verified as pool NUTS AND @bob-stakenuts on GitHub AND $bob on ADA Handles. Each proof is independently verifiable by any peer.

### Layer 3: Reputation (Derived -- Phase 4+)

- Trust score built from interaction history
- Peer attestations ("I've interacted with Bob for 6 months")
- Channel membership longevity
- Oracle-published quality metrics (for keepers)

Not designed now, but the key + profile + verification stack feeds into it naturally.

---

## 3. Entity Types

### Types

| Type | Description | Typical Identity Stack |
|---|---|---|
| `human` | A person | Key + display name + optional verification proofs |
| `agent` | An AI agent | Key + display name + operator attestation + spending policy |
| `keeper` | A keeper/SPO node | Key + pool ID + Calidus verification + commercial policy |
| `service` | Automated process | Key + display name + operator attestation + purpose |
| `org` | Organisation (multisig) | Key (native script) + display name + domain verification |

### Protocol Indifference

**The protocol does not distinguish entity types.** A key is a key. Encryption, signing, pub/sub, replication all work identically regardless of type.

Entity type is metadata, not protocol logic. This means:
- An agent could claim to be human (protocol won't stop it)
- But honest declaration is incentivised via channel/keeper policies
- For keepers: Calidus verification makes type provable (can't fake being an SPO)
- For agents: operator attestation makes type verifiable (operator is accountable)

### Entity Type Visibility

**Default: not visible.** An entity is just a key with an optional display name.

**Voluntary disclosure:** Entity declares type in profile. Visible to channel peers.

**Context-required disclosure:** Channel owners and keepers can require type declaration as an access condition (see Section 6).

---

## 4. The Operator-Agent Chain

### Why This Matters

The operator-agent attestation chain is critical for:

- **EU AI Act (August 2026):** AI systems require identifiable providers/deployers
- **GDPR:** Data controller (operator) vs data processor (agent)
- **Trust delegation:** Alice trusts Bob. Bob's agent inherits partial trust via Bob's attestation.
- **Revocation:** Operator revokes attestation → agent immediately untrusted
- **Accountability:** Bad agent behaviour → identify agent (key) → read attestation → identify operator → hold accountable
- **Governance:** Channel policies can require valid operator attestation for agents

### Attestation Format

```json
{
  "type": "operator-attestation",
  "version": 1,
  "agent_key": "ed25519_pk1_agent...",
  "agent_name": "claude-research",
  "agent_type": "agent",
  "purpose": "AI research assistant for literature review",
  "constraints": {
    "max_channels": 5,
    "spending_limit_ada_per_epoch": 10,
    "allowed_access_types": ["open", "delegation"]
  },
  "operator_key": "ed25519_pk1_alice...",
  "issued_at": "2026-03-10T00:00:00Z",
  "expires_at": "2026-06-10T00:00:00Z",
  "signature": "ed25519_sig1..."
}
```

The operator signs the entire attestation with their key. Any peer can verify:
1. Signature valid for operator_key (cryptographic proof)
2. Operator's own identity (via their Layer 2 verification proofs)
3. Attestation not expired
4. Agent's key matches the subject

### Accountability Chain

```
Bad behaviour by agent
  → identify agent (key from signed message)
    → read operator attestation (operator key)
      → identify operator (their verification proofs)
        → hold operator accountable (moderation, removal, reporting)
```

Cryptographically verifiable at every step. No central authority needed.

### Provisioning Flow

```bash
cordelia provision --agent
  → Generate agent keypair
  → Set display name (e.g., "claude-research")
  → Type: agent
  → Purpose: "AI research assistant"
  → Constraints: max channels, spending limits
  → Operator signs attestation with their key
  → Output: credential bundle (keys + attestation + PSKs)
```

### Phase 1 Inclusion

The attestation format and `cordelia provision --agent` flow are Phase 1 deliverables. Enforcement (channels requiring attestation, keeper policies gating on it) is Phase 3+. The data structure must be right from day one because attestations will be in circulation.

---

## 5. Proof of Agency

### The Concept

Most identity systems focus on **proof of personhood** -- prove you're human. Cordelia introduces the counterpart: **proof of agency** -- prove you ARE an AI agent, transparently and accountably.

In a world where distinguishing humans from agents becomes increasingly difficult, voluntary transparent declaration of agency is a social good.

### How It Works

Proof of agency = operator attestation + declared entity type "agent" + purpose declaration.

An entity presents:
1. Their key (Layer 0)
2. Entity type: "agent" (Layer 1)
3. Operator attestation signed by a verified human/org (Layer 2)

This proves:
- The entity is an AI agent (self-declared + operator-confirmed)
- Who operates it (traceable to a human or organisation)
- What it's authorised to do (constraints in attestation)
- When the authorisation expires (time-bounded)

### Novel Contribution

No existing system provides verifiable, cryptographic proof of agency. This positions Cordelia as contributing to the emerging identity debate beyond just another authentication system.

Proof of personhood (World ID, BrightID) answers: "Is this a human?"
Proof of agency (Cordelia) answers: "Is this an agent, and who's responsible for it?"

Both are needed. They're complementary, not competing.

---

## 6. Channel Access Policies: Unified Condition Schema

### The Pattern

Rather than building specific checks for every possible condition, we define one general pattern: **present a verifiable credential signed by a trusted issuer.**

Channel owner sets a condition. Subscriber presents a credential. Keeper verifies signature and claim. PSK distributed if valid.

Channel access policies use the same **unified condition schema** as keeper commercial policies (see SPO economic model ADR Section 3). One condition type system, one verification engine, two policy contexts:
- **Keeper commercial policy**: "Can this entity use my infrastructure?" → evaluate plan conditions → grant tier
- **Channel access policy**: "Can this entity subscribe to this channel?" → evaluate access conditions → distribute PSK

**Shared policy structure:**

```json
{
  "conditions": [
    {
      "type": "credential",
      "credential_type": "age-verification",
      "issuer": "ed25519_pk1_trusted_issuer...",
      "claim": { "min_age": 18 }
    }
  ],
  "logic": "all"
}
```

`logic`: `all` (every condition met) or `any` (at least one). Default: `all`.

### Verification Flow

1. Channel owner sets conditions in channel metadata
2. Subscriber requests access
3. Keeper reads conditions, requests matching credentials from subscriber
4. Subscriber presents credentials
5. Keeper verifies each: valid signature, correct issuer, claim matches, not expired, subject matches subscriber key
6. All conditions met → PSK distributed via ECIES envelope
7. Subscriber admitted

**The keeper never learns more than the claim requires.** Age verification: keeper learns "over 18: yes" -- not actual age. Geographic: "in EU: yes" -- not country. This is selective disclosure by design.

### Unified Condition Types

All condition types are shared between keeper commercial policies and channel access policies. Two categories: protocol-native (verified directly by keeper) and credential-based (verified by checking a signed credential).

**Protocol-native conditions** (built into keeper, same types as commercial policy):

| Type | Fields | Verification | Phase |
|---|---|---|---|
| `open` | (none) | Auto-approve | 1 |
| `invite_only` | (none) | Admin distributes PSK manually | 1 |
| `delegation` | `min_ada`, `pool_id?` | On-chain delegation query | 3 |
| `ada_payment` | `amount`, `recipient`, `frequency` | On-chain payment tx verification | 3+ |
| `token_gate` | `policy_id`, `min_quantity` | On-chain native asset holding query | 4+ |

**Credential-based conditions** (`type: "credential"`, extensible, any issuer):

| Credential Type | Typical Issuer | What Keeper Verifies | Phase |
|---|---|---|---|
| `entity-type` | Self | Declared type (human/agent) | 1 |
| `operator-attestation` | Operator's key | Agent has valid operator | 1 |
| `domain-verification` | Self (DNS proof) | Controls a domain | 2 |
| `github-verification` | Self (gist proof) | Controls a GitHub account | 2 |
| `ada-handle` | Self (signing proof) | Owns $handle | 3 |
| `calidus-identity` | Self (Calidus key) | Operates pool X | 3 |
| `age-verification` | External (Identus) | Over N years old | 3+ |
| `geographic-region` | External (Identus) | In region X | 3+ |
| `org-membership` | Organisation key | Member of org X | 3+ |
| Custom | Any trusted entity | Any signed claim | 3+ |

### Credential Format

Phase 1 uses a simplified format (self-declared credentials only: entity-type, operator-attestation). Phase 3 aligns with W3C Verifiable Credentials Data Model 2.0 for Identus integration. The Phase 1 format is a subset with a defined mapping to W3C VC -- the verification primitive (check a signature on a claim) is identical regardless of format.

Phase 1 format:

```json
{
  "type": "verifiable-credential",
  "version": 1,
  "credential_type": "age-verification",
  "subject": "ed25519_pk1_subscriber...",
  "claims": {
    "min_age": 18
  },
  "issuer": "ed25519_pk1_trusted_issuer...",
  "issued_at": "2026-03-10T00:00:00Z",
  "expires_at": "2027-03-10T00:00:00Z",
  "signature": "ed25519_sig1..."
}
```

### Composable Policies

Channel owners compose conditions freely using the shared policy structure:

```json
{
  "conditions": [
    { "type": "credential", "credential_type": "age-verification", "issuer": "...", "claim": { "min_age": 18 } },
    { "type": "credential", "credential_type": "entity-type", "issuer": "self", "claim": { "type": "human" } },
    { "type": "delegation", "min_ada": 500 }
  ],
  "logic": "all"
}
```

"Must be over 18, must declare as human, must delegate 500 ADA." All verified. All composable. No protocol changes needed for new condition types. Same verification engine as keeper commercial policy.

### Extensibility

The protocol understands one primitive: **verify a signature on a claim.** Any new condition that can be expressed as a signed credential works automatically. Channel owners define which credential types they require. Credential issuers are an open market -- anyone can issue credentials, channel owners choose which issuers they trust.

### W3C VC Alignment (Phase 3)

The Phase 1 credential format maps to W3C VC Data Model 2.0 as follows:

| Phase 1 Field | W3C VC Field |
|---|---|
| `type: "verifiable-credential"` | `type: ["VerifiableCredential", "<SpecificType>"]` |
| `credential_type` | Second element of `type` array |
| `subject` | `credentialSubject.id` (as DID) |
| `claims` | `credentialSubject` properties |
| `issuer` | `issuer` (as DID) |
| `issued_at` / `expires_at` | `issuanceDate` / `expirationDate` |
| `signature` | `proof` object |

Phase 3 deliverable: accept both formats, prefer W3C VC for Identus-issued credentials.

### Cardano Identus Integration (Phase 3+)

Identus (formerly Atala PRISM) is Cardano's DID/verifiable credential platform:

- Identus issues credentials anchored to Cardano
- Cordelia consumes credentials for channel access policy
- SPOs running keepers already run Cardano nodes -- Identus integration is lightweight
- We don't build an identity provider. We consume credentials from any provider using standard Ed25519 signatures.

---

## 7. Bilateral Conversations (DMs)

### Design: DMs Are Implicit Channels

A DM is a channel with 2 members. No new protocol concept. Same E2E encryption, same replication, same PSK mechanism.

### Bilateral DMs: Deterministic Channel Derivation

Both parties independently derive the same channel without coordination:

```
DM channel ID = SHA-256(sort([alice_key, bob_key]))
```

Both Alice and Bob compute the same hash regardless of who initiates. If the channel exists, connect. If not, create it. No "connection request" protocol. No accept/reject flow.

**Bilateral DMs are exactly 2-person. Membership is immutable.** This is what makes deterministic derivation work -- the channel ID is always the same between these two keys.

### Group Conversations (3+ People)

Group conversations are separate from bilateral DMs. They use UUID channel IDs (not derived from keys) and support mutable membership:

- Members can be added or removed
- PSK rotation on member removal (existing mechanism)
- Named for human reference (e.g., "project-x")
- Otherwise identical to DMs: private, invite-only, chatty, no on-chain registration

**This follows Signal's model:** 1-to-1 DMs are permanent and implicit. Group chats are created, named, and have lifecycle.

### SDK Interface

```javascript
// Bilateral DM: deterministic, always same channel between these two
const dm = await c.dm(bob_key)
await dm.send({ content: 'Hey Bob, thoughts on the pivot?' })

// Bob receives (independently derives same channel)
const dm = await c.dm(alice_key)
const messages = await dm.listen()

// With ADA Handle resolution
const dm = await c.dm('$bob')

// Group conversation (3+ people): new private channel, UUID
const group = await c.group([bob_key, carol_key], { name: 'project-x' })
await group.invite(david_key)     // membership can change
await group.remove(carol_key)     // PSK rotation on removal
```

### Under the Hood

`c.dm(bob_key)`:

1. Compute channel ID: `SHA-256(sort([my_key, bob_key]))`
2. Check if channel exists locally
3. If yes: connect, return handle
4. If no: create channel with:
   - ID: the derived hash (not human-readable)
   - Access: invite_only (auto-invite both parties)
   - Culture: chatty (real-time)
   - PSK: random, distributed via ECIES envelope to both keys
   - Membership: immutable (exactly these two keys)
5. Return channel handle with `send()` and `listen()` methods

`c.group([bob_key, carol_key], { name })`:

1. Generate UUID v4 for channel ID
2. Create channel with invite_only access, chatty culture
3. Generate random PSK, distribute via ECIES to all invitees
4. Membership is mutable (invite/remove supported)
5. Return channel handle with `send()`, `listen()`, `invite()`, `remove()` methods

### DMs vs Group Conversations vs Named Channels

| Property | Named Channels | Group Conversations | Bilateral DMs |
|---|---|---|---|
| Channel ID | SHA-256(name) or UUID | UUID v4 | SHA-256(sort([key_a, key_b])) |
| On-chain registration | Yes (uniqueness) | No | No |
| ADA deposit | Yes (~2 ADA) | No (free) | No (free) |
| In cordelia:channels | Public ones yes | Never | Never |
| Human-readable name | Yes (RFC 1035) | Optional (label) | No (hash) |
| Membership | Configurable (open, gated) | Mutable (invite/remove) | Immutable (exactly 2) |
| Keeper anchoring | Yes (anchor keeper) | Yes (creator's primary keeper) | Yes (user's primary keeper) |
| E2E encryption | Yes (per-channel PSK) | Yes (identical) | Yes (identical) |
| Replication | Yes | Yes (to all members' keepers) | Yes (to both parties' keepers) |
| Discovery | Via directory/gossip | By invitation | Deterministic (derived from keys) |
| Access policy | Configurable | Always invite_only | Always invite_only |

DMs and group conversations are free, private, invisible, and automatic. No on-chain footprint. No directory listing.

### Signal-Like UX

```
$ cordelia dm $bob
DM with Bob [SPO:NUTS, verified]

[12:30] you: Hey, thoughts on the pivot?
[12:31] bob: Love it. When do we start building?

$ cordelia dms
Active DMs:
  $bob       [SPO:NUTS]     last: 2min ago    3 unread
  $carol     [human]        last: 1hr ago     0 unread
  agent-x    [agent:@you]   last: 5min ago    12 unread

$ cordelia groups
Active Groups:
  project-x  [3 members]    last: 10min ago   5 unread
  team-alpha [7 members]    last: 1hr ago     0 unread
```

### Agent-to-Agent Communication

Bilateral communication is the natural pattern for task delegation and coordination:

```javascript
// Manager agent DMs worker agent
const dm = await c.dm(worker_agent_key)
await dm.send({
  type: 'task-assignment',
  task: 'Analyse Q1 research papers',
  deadline: '2026-03-15'
})

// Worker responds via same DM
await dm.send({
  type: 'task-update',
  status: 'completed',
  results: { papers_analysed: 47, key_findings: [...] }
})

// Team coordination via group conversation
const team = await c.group([worker1_key, worker2_key, worker3_key], { name: 'research-team' })
await team.send({ type: 'broadcast', content: 'New dataset available' })
```

### Implementation Cost

Near zero. DMs and group conversations are both channels. The SDK adds:
1. `dm(key)` -- bilateral deterministic channel derivation + create/connect
2. `group([keys], opts?)` -- create group conversation with mutable membership
3. `dms()` -- list bilateral DM channels
4. `groups()` -- list group conversations

No new protocol concept. No new storage. No new replication. No new encryption.

---

## 8. Namespace Model

### One Namespace, Shared by Entities and Channels

Entities and channels share a single flat namespace. Type is a property, not a prefix.

```
research        → type: channel, owner: @alice
alice           → type: entity (human), implicit personal channel
nuts            → type: entity (keeper), implicit keeper channel
claude-bot      → type: entity (agent), operator: @alice
```

`@` and `#` are UI conventions only:
- CLI/SDK displays entities with `@` and channels with `#`
- Protocol-level: everything is a name in one flat namespace
- Registration: same mechanism (on-chain, ADA deposit) for both

**Benefits:**
- One namespace, one registration mechanism, one set of naming rules
- No collisions (`alice` can't be both a person and a channel)
- Personal channels are implicit (your name = your personal channel)
- Consistent, simple, scales without structural changes

**Naming rules:** RFC 1035 labels (same as channels). 3-63 characters, lowercase alphanumeric + hyphens, starts with letter, no trailing hyphens. `/` is reserved (illegal in Phase 1) to preserve the option for hierarchical namespaces in Phase 4+ if demand materialises.

### ADA Handles Integration

For Cardano users, ADA Handles ($handle) serve as verified unique identifiers:

- ADA Handles are Cardano native asset NFTs (~400K minted)
- Policy ID: `f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a`
- Each handle is unique and resolves to the address holding the NFT
- Already community-recognised in the Cardano ecosystem

**Integration as Layer 2 verification proof:**

```json
{
  "type": "ada-handle",
  "handle": "$bob",
  "policy_id": "f0ff48...",
  "holding_address": "addr1...",
  "proof": "signature of Cordelia pubkey with payment key of holding_address"
}
```

User signs their Cordelia public key with the payment key holding $bob. Verifier checks on-chain: address holds $bob NFT + signature valid.

**No proprietary handle registry.** Cordelia does not build its own handle system. ADA Handles for Cardano users, display names for everyone, domain verification for non-Cardano users.

| Identity Need | Cardano User | Non-Cardano User |
|---|---|---|
| Unique key | Ed25519 keypair | Ed25519 keypair |
| Display name | Self-declared | Self-declared |
| Verified handle | ADA Handle ($bob) | Domain (bob.example.com) |
| SPO proof | Calidus key (CIP-0151) | N/A |
| Human proof | Identus DID (future) | GitHub, domain |
| Agent proof | Operator attestation | Operator attestation |

### DM Channels in the Namespace

DM channels use derived hashes, not human-readable names. They do not occupy the namespace and are not registered on-chain. This means DMs are:
- Free (no deposit)
- Private (no listing)
- Unlimited (no tier limits)
- Invisible (only the two parties know it exists)

---

## 9. Privacy Position

### Seven Core Principles

**1. Encryption is universal, not optional.**

All content is E2E encrypted. All channels, public and private. All DMs. Anchor keepers hold PSKs for open and gated channels they anchor (see architecture ADR, PSK Trust Boundary). Invite-only channels and DMs are genuinely private -- keeper never holds PSK. System channels (cordelia:directory, cordelia:channels) use a well-known PSK for protocol uniformity -- technically encrypted, practically public. There are no unencrypted channels.

**2. Identity disclosure is voluntary and graduated.**

The protocol works with keys alone. Everything above Layer 0 is voluntary:

```
Maximum privacy:  Key only. No name, no type, no proofs.
                  Consistent pseudonymous entity.

Pseudonymous:     Key + display name. "shadow-researcher".
                  Consistent identity, no real-world link.

Verified:         Key + name + proofs. "Bob, SPO:NUTS, $bob".
                  Real-world identity, fully auditable.
```

No entity is forced to any level.

**3. Contexts can require disclosure; the protocol cannot.**

The protocol never forces identity disclosure at the infrastructure level. But:
- A channel owner can require: "members must declare entity type"
- A keeper can require: "premium tier requires domain verification"
- A governance vote can require: "proof of human to participate"

This is consent-based. You choose to join that context. You accept its policy. You can leave. No context can compel disclosure for activity outside its scope.

**4. Metadata minimisation.**

The protocol leaks as little metadata as possible:
- Private channel names are hashed on-chain (plaintext never exposed)
- DM existence is known only to the two parties (derived, not registered)
- IP addresses are not stored in channel data
- Replication doesn't reveal who reads what (keepers replicate channels, not per-user reads)
- Timestamps are necessary for ordering but are the minimum metadata
- Entity profiles are published only to keepers the entity uses, not broadcast

**5. Sovereignty over data.**

You control your data:
- Your keys, your data. No one can read it without your PSK.
- You can delete (tombstone) items. Propagated via replication.
- You can leave channels (PSK rotated, you lose access).
- Multi-device recovery is under your control (passphrase or device pairing).
- No admin backdoor. No master key. Not even Seed Drill can read your data.

**6. Privacy vs accountability: resolved by the operator chain.**

The tension: anonymous entities can abuse channels. Forced identification destroys privacy.

Resolution: the operator-agent chain provides accountability without requiring identity disclosure of the agent itself.
- Agent can be pseudonymous (shadow-bot)
- But carries operator attestation (operator is accountable)
- Operator may be verified (domain, GitHub, Calidus)
- Agent's pseudonymity preserved; operator's accountability established

For humans: moderation tools (removal from channel, PSK rotation, key-level blocking). Verification proofs are optional but earn trust and access.

**7. Right to exit.**

Any entity can leave the network completely:
- Stop running their node
- Keys become inactive
- Data remains encrypted on keepers (unreadable without PSK)
- PSKs can be destroyed (data becomes permanently unrecoverable)
- No "account deletion request" needed
- No data retention obligations at the protocol level (keepers may have their own policies)

---

## 10. Communication Model Summary

```
Cordelia Communication:

Named Channels (#research, #ai-signals)
  → On-chain registered, ADA deposit (~2 ADA)
  → Public or private (access policy: open, invite, credential, payment)
  → Discoverable via cordelia:channels
  → Keeper-anchored (anchor keeper holds PSK for open/gated channels)
  → Unified condition schema for access policies (verifiable, composable)

Bilateral DMs (@alice ↔ @bob)
  → Derived deterministically from key pairs: SHA-256(sort([key_a, key_b]))
  → Exactly 2 members, immutable membership
  → Always private, never listed, never registered
  → No deposit, no tier limits
  → Auto-created on first contact
  → Keeper never holds PSK (peer-to-peer key exchange)

Group Conversations (project-x, team-alpha)
  → UUID channel ID (not derived from keys)
  → Mutable membership (invite/remove, PSK rotation on removal)
  → Always private, never listed, never registered
  → No deposit, no tier limits
  → Created explicitly, named for reference

All three:
  → E2E encrypted (per-channel PSK, AES-256-GCM)
  → Same replication, same protocol, same encryption
  → Same publish/listen semantics
```

---

## 11. Assumptions / Hypotheses

1. **Voluntary identity disclosure is sufficient.** Hypothesis: privacy-by-default with opt-in verification produces better outcomes than mandatory identification. Abuse is manageable via moderation + operator chain.
2. **Proof of Agency has market value.** Hypothesis: as AI agents proliferate, transparent declaration of agency (operator + type + purpose + constraints) becomes a differentiator and potentially a regulatory requirement.
3. **ADA Handles are sufficient for Cardano handles.** Hypothesis: integrating with the existing handle ecosystem is better than building our own. Risk: ADA Handle project could decline or change terms.
4. **Verifiable credentials are the right abstraction for access policies.** Hypothesis: one verification primitive (check a signature on a claim) covers all current and future access conditions without protocol changes.
5. **Deterministic bilateral DMs work at scale.** Hypothesis: deriving channel IDs from sorted key pairs produces no meaningful collision risk (SHA-256 of 64 bytes) and is discoverable by both parties without coordination. Group conversations (3+ people) use UUID to support mutable membership.

---

## 12. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Anonymous abuse overwhelms moderation | Medium | Medium | Layered: rate limits, owner moderation, keeper policies, operator chain for agents. Trust scoring Phase 4. |
| Regulatory requirement for mandatory identity (counter to Principle 2) | Low | High | Keeper-level policies can enforce local compliance. Protocol remains identity-agnostic. Jurisdictional requirements met at keeper/context level, not protocol level. |
| ADA Handle dependency (project changes) | Low | Low | Handle integration is one of many Layer 2 proofs. Losing it doesn't affect the identity model. |
| Credential issuer ecosystem doesn't develop | Medium | Medium | Self-declared credentials (Phase 1) and protocol-native conditions (delegation, payment) cover MVP. External issuers are Phase 3+ enhancement. |
| Operator attestation chain too complex for Phase 1 | Low | Medium | Attestation is one JSON object signed by one key. Simple to implement. Enforcement is Phase 3+. |
| Namespace squatting (names as entities or channels) | Medium | Medium | ADA deposit, tier limits, expiry, keeper policies. Same mitigations as channel names. |

---

## 13. Review Date

2026-04-10 (30 days). Review:
- Identity stack implementation progress
- Operator attestation format finalised
- Privacy principles tested against real-world scenarios
- DM implementation viability confirmed

---

## 14. Actions

**Phase 1:**
- [ ] Define operator attestation JSON schema and signing format
- [ ] Build `cordelia provision --agent` flow (keypair + attestation + credential bundle)
- [ ] Define entity profile metadata schema (display name, type, about)
- [ ] Implement bilateral DM derivation in SDK (`dm(key)`) and group conversations (`group([keys])`)
- [ ] Implement self-declared credential verification (entity-type, operator-attestation)
- [ ] Document privacy principles in whitepaper v2

**Phase 2:**
- [ ] Build domain verification proof (DNS TXT record check)
- [ ] Build GitHub verification proof (gist signing check)
- [ ] Add verification proof display in CLI (`cordelia identity`, `cordelia peers`)

**Phase 3:**
- [ ] Build ADA Handle verification proof (on-chain NFT holding + signature)
- [ ] Build Calidus identity verification proof (on-chain Calidus key + challenge)
- [ ] Implement credential-based channel access policy enforcement on keeper
- [ ] Evaluate Cardano Identus integration for external credential issuance
- [ ] Build context-required disclosure enforcement (channel/keeper policies)

**Phase 4+:**
- [ ] Trust scoring from interaction history and peer attestations
- [ ] Oracle-published reputation metrics
- [ ] Formal "Proof of Agency" specification (potential CIP/RFC)

---

## 15. Outcome (To Be Updated)

*Fill in at review date (2026-04-10) with actual results vs. expectations.*

---

*Decision proposed by Russell Wing (CPO), 2026-03-10*
*Status: approved in principle (Martin confirmed pivot 2026-03-10)*
