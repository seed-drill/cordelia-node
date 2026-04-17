# Cordelia: Encrypted Pub/Sub for AI Agents

**Russell Wing, Martin Stevens, Claude (Opus 4.5, Opus 4.6)**
**Seed Drill (https://seeddrill.ai) -- January 2026, revised March 2026**

---

## Abstract

We propose a system for persistent, sovereign memory shared between
humans and the AI agents they operate. Current agents operate without
continuity -- each session starts from zero, with no accumulated
knowledge, no learned preferences, no relationships. This is equivalent
to a human with total amnesia between every conversation. Cordelia
solves this by implementing a distributed memory architecture in which
the operator's memory record -- encrypted, replicated, and sovereign --
persists across sessions and gives the agent the continuity needed to
function. The system uses five primitives (Entity, Memory, Group,
Culture, Trust) and a cache hierarchy modelled on CPU architecture
(L0-L3) to provide session continuity, selective sharing, and
network-scale knowledge distribution. Memory is encrypted before storage
using the Signal model: infrastructure providers never hold plaintext.
Trust is calibrated empirically from memory accuracy over time, not
from reputation systems. Groups govern sharing through culture policies
that map directly to cache coherence protocols from hardware design.
The design is deliberately democratic-AI infrastructure: no central
provider holds plaintext, no infrastructure operator can coerce the
record, and provenance is cryptographically auditable -- properties
that matter particularly during the period in which AI capability
outpaces the institutional machinery for governing it [23].

---

## 1. Introduction

### 1.1 The Problem

Every commercial AI agent today suffers from the same fundamental
limitation: session amnesia. When a conversation ends, everything
learned is lost. The next session starts from a blank state, or at best
a manually curated system prompt. This is not a minor inconvenience --
it is a structural barrier to the emergence of genuine agent utility.

Consider the implications. An agent that assists with software
engineering cannot remember architectural decisions made last week. An
agent that manages a team's knowledge cannot recall that a particular
approach was tried and failed. An agent that supports a business cannot
build a model of its customers over time. Each session is independent,
unconnected, disposable.

The human parallel is instructive. Human cognition depends on memory at
every level: working memory for the current task, episodic memory for
recent events, semantic memory for accumulated knowledge, procedural
memory for learned skills [6]. Remove any layer and function degrades
catastrophically. Current AI agents operate with working memory only.

### 1.2 Why Not Just a Database?

The naive solution -- "store conversation logs in a database" -- fails
for three reasons.

**Volume without value.** Raw conversation logs are high-volume,
low-density. A typical engineering session produces thousands of tokens,
of which perhaps 5% contain information worth retaining. Without
filtering, storage grows linearly while retrieval quality degrades.

**No sovereignty.** If an agent's memory is stored by its provider, the
provider controls the agent's identity. This creates an asymmetry that
becomes dangerous as agents become more capable. The entity that
controls memory controls behaviour.

**No sharing model.** Agents that work in teams need selective memory
sharing. A personal preference should remain private. A team decision
should be visible to the team. A public learning should be discoverable
by anyone. A flat database provides none of this.

### 1.3 This Paper

We describe Cordelia, a system that addresses these three problems
through a layered memory architecture with encryption, replication, and
culture-governed sharing. The system is operational, with a working
peer-to-peer network, and is designed to scale from a single user on a
laptop to a federated network of organisations.

The design draws on established computer science: CPU cache hierarchies
[1], cache coherence protocols [2], working set theory [3], information
theory [4], and game theory [5]. Where possible, we reuse proven
mechanisms rather than invent new ones.

The timing matters. Powerful AI capabilities are arriving faster than
the social, political, and institutional mechanisms needed to govern
them [23]. In that window, the memory layer of AI systems is a choice
point: sovereign, cryptographically auditable memory owned by the
operator is a structurally different commitment from custodial memory
held by a provider. Cordelia takes the former position and argues it is
the right default for the coming decade.

### 1.4 A Worked Example

A three-person startup uses an AI agent for software engineering. On
day one, the agent is stateless -- a new hire with amnesia.

**Session 1.** The team discusses architecture. The agent helps design
a message queue. The novelty engine detects a decision ("use NATS over
RabbitMQ"), a new entity ("the payments service"), and a preference
("the CTO prefers explicit error handling over exceptions"). These are
persisted to L2. The agent's L1 is updated with the team's working
context.

**Session 5.** A different team member asks the agent to add retry
logic to the payments service. The agent's L1 already contains the
project context. It searches L2, finds the NATS decision and the
error handling preference, and writes retry logic with explicit error
returns -- without being told. The team member doesn't know about the
CTO's preference. The agent does, because it remembers.

**Session 12.** The CTO reviews the retry code and notices it follows
his preferred style, despite him never discussing it with the author.
The preference propagated through the agent's memory, not through a
meeting or a style guide. The team's shared knowledge base is
accumulating value faster than any document could.

**Session 30.** A new engineer joins. On their first day, the agent
already knows the architecture, the conventions, the decisions and
their rationale. The new hire's onboarding is a conversation with an
agent that has thirty sessions of institutional memory. The context
that would normally take weeks to absorb is available immediately.

No session required the team to curate a prompt, maintain a wiki, or
brief the agent. The memory accumulated through normal work and
propagated through the system's sharing model. This is what session
amnesia costs, made visible by its absence.

**Session 45.** The team switches AI provider. The agent changes; the
memory doesn't. Thirty sessions of architectural decisions, learned
preferences, and institutional knowledge transfer to the new provider
on day one, because the memory belongs to the team -- not the vendor,
not the infrastructure, not the model. The new agent wakes up with
the same context the old one had. No migration project, no knowledge
loss, no starting over.

---

## 2. The Memory Model

### 2.1 Cache Hierarchy

Cordelia's memory architecture mirrors the cache hierarchy in modern
CPUs. This is not an analogy -- it is a direct application of the same
engineering trade-offs between latency, capacity, and cost.

```
Layer   Latency    Capacity    Persistence    Analogy
-----   -------    --------    -----------    -------
L0      <1ms       ~100 items  Session        CPU L1 cache
L1      <10ms      ~50KB       Permanent      CPU L2 cache
L2      <100ms     Unbounded   Permanent      Main memory
L3      <1s        Unbounded   Permanent      Disk/SSD
```

**L0 (In-Memory Cache)**: Lives in the MCP adapter process. Contains
the current session's L1 hot context and recent L2 search results. Lost
on process restart. Eliminates redundant storage reads during a session.

**L1 (Hot Context)**: The entity's identity -- who they are, what
they're working on, their preferences, their style. Loaded at the start
of every session. Analogous to CPU registers + L1 cache: small, fast,
always present. Typically 20-50KB of dense, structured JSON.

**L2 (Warm Index)**: All accumulated knowledge -- learnings, session
summaries, entity profiles, decisions, patterns. Searched on demand via
keyword and (optionally) vector similarity. Analogous to main memory:
large capacity, higher latency, demand-fetched.

**L3 (Cold Archive)**: Long-term compressed history. Infrequently
accessed. Stored on durable backends (S3, distributed storage).
Analogous to disk: vast capacity, highest latency, lowest cost.

### 2.2 Why This Hierarchy Works

The key insight from Denning's working set model [3] is that programs
(and agents) exhibit locality of reference. At any given time, an agent
needs a small working set of memories. The hierarchy exploits this:

- L1 prefetch eliminates cold-start latency (the agent wakes up knowing
  who it is and what it was working on)
- L2 demand-fetch handles the long tail (the agent searches when it
  needs something specific)
- L0 caching prevents redundant reads within a session
- L3 archival provides durability without polluting active layers

This delivers approximately 80% of theoretical value via two mechanisms:
cold-start elimination (L1) and demand-fetch (L2). The remaining 20%
(speculative prefetch, promotion/demotion heuristics, adaptive working
set sizing) is achievable but yields diminishing returns -- a textbook
Pareto distribution.

### 2.3 Frame Memory vs Data Memory

L1 hot context serves two fundamentally different functions that the
memory model must distinguish.

**Data memory** consists of facts, events, decisions, and active state.
A sprint number, a blocker, a decision to use AGPL-3.0. Data memory
is measured in bits. Its value is direct: the agent knows something it
would otherwise need to look up or be told.

**Frame memory** consists of conceptual vocabulary, reasoning
frameworks, and shared metaphors. A reference to Shannon's information
theory, to Denning's working set model, to von Neumann-Morgenstern's
game theory. Frame memory is not measured in bits -- it is measured in
**Kullback-Leibler divergence reduction** [15] between the agent's
default reasoning distribution and the optimal distribution for the
current task.

The concept has antecedents. Minsky's frames [16] introduced the idea
of structured knowledge that shapes how new information is interpreted
-- stereotyped situations with slots that guide expectation and
inference. Sweller's cognitive load theory [17] showed that schemas
reduce the processing cost of new information by providing organised
structures. Lakoff and Johnson [18] demonstrated that shared conceptual
metaphors are not decorative but constitutive of reasoning itself. What
we observe in practice extends these ideas into a new domain: the
operational context of stateful AI agents, where frame memory can be
measured empirically by its effect on the reasoning distribution, and
where the cache hierarchy provides a mechanism for loading the right
frame at the right time.

The mechanism: when an agent loads frame memory at session start, it
does not merely learn that the user has read certain books. It
activates the conceptual frameworks those thinkers represent. Attention
weights shift. When the user says "natural selection for memories," the
agent reaches for Shannon entropy as fitness, Denning's locality as
selection pressure, and Dennett's competence-without-comprehension as
the emergent property -- instead of a generic biological metaphor.
Three conceptual hops that would otherwise require multiple
conversational turns happen at zero cost because the coordinate system
is already loaded.

This has a formal consequence for the memory model:

> **L1 value is not measured in bits of factual content. It is measured
> in how much it reduces the distance between the agent's starting
> position and the optimal position for the current task.**

A 50KB L1 with the right frame memory can outperform megabytes of raw
conversation history, because it is compressing the *frame of
reference*, not the facts. This is why the cache hierarchy works so
well in practice: L1 is not just a smaller, faster L2. It is a
qualitatively different kind of memory that shapes how all other
memory is processed.

To our knowledge, the formal characterisation of frame memory as KL
divergence reduction in agent context -- and the resulting design
principle that a memory hierarchy should distinguish between data
that informs and frames that restructure reasoning -- has not been
previously articulated. The closest existing work addresses schema
acquisition in human learners [17] or static knowledge representation
[16], not the dynamic loading of reasoning frames into stateful
agents with measurable distributional effects.

The design implication: novelty scoring should weight frame-shifting
observations (a new conceptual connection, a new reasoning pattern, a
new metaphor that restructures understanding) higher than factual
observations. A single insight that changes how the agent thinks about
a domain is worth more than a hundred facts within the existing frame.

### 2.4 Novelty Filtering

Not everything an agent encounters should be persisted. The question
is: which observations deserve a place in memory? The answer requires
a formal definition of value.

#### The Reconstitution Principle

The value of a memory is not its length, its recency, or the
importance of the entity that generated it. It is the degree to which
the information it contains **cannot be reconstituted from the rest of
the corpus**.

Formally: given a memory M and the rest of the agent's memory corpus
C, the novelty of M is its **conditional entropy** H(M|C) [4]. If
H(M|C) is low, the memory is predictable given everything else the
agent knows -- it is redundant, and losing it would cost little. If
H(M|C) is high, the memory contains information present nowhere else
-- it is irreplaceable.

This connects to Kolmogorov complexity [19]: the novelty of M can be
approximated by how much M can be compressed given C as context. A
memory that compresses to near-zero given the corpus is redundant. A
memory that remains incompressible is genuinely novel. We cannot
compute true Kolmogorov complexity, but language model perplexity
provides a practical approximation: the perplexity of M conditioned
on C is a computable proxy for conditional entropy.

The reconstitution principle has a direct consequence for the memory
hierarchy. Over time, a well-functioning novelty filter produces a
corpus where every surviving memory contributes unique information.
The corpus becomes denser -- not in the sense of containing more data,
but in the information-theoretic sense that the conditional entropy
of each memory given the rest remains high. Redundancy is eliminated
not by deduplication (which catches only syntactic overlap) but by
the deeper test: can this be derived from what we already know?

This extends Shannon's original formulation [4] in a specific
direction. Shannon measured entropy of messages over a channel.
Rate-distortion theory [20] established the minimum description
length for a source at a given fidelity. What the reconstitution
principle adds is the application of conditional entropy as a
**memory retention criterion** for autonomous agents with bounded
storage -- a selection pressure that produces corpora with
monotonically increasing information density over time, analogous
to natural selection operating on a population of memories where
fitness is irreplaceability.

#### Signal Classification

In practice, the novelty engine scores incoming information against
nine signal types that operationalise the reconstitution principle:

| Signal | Example |
|--------|---------|
| correction | User corrected an assumption |
| preference | User expressed a working style |
| entity_new | New person, project, or concept introduced |
| decision | A decision was made |
| insight | Pattern recognition, realisation |
| blocker | Blocker identified or resolved |
| reference | New key reference (book, person, concept) |
| working_pattern | How the collaboration works |
| meta_learning | Insight about the collaboration itself |

Each signal type is a heuristic proxy for conditional entropy.
Corrections score high because they represent information the agent's
model would not predict. Preferences score high because they are
specific to an individual and cannot be inferred from general
knowledge. Insights score highest because they are, by definition,
novel connections -- low-probability given the existing corpus.

Content scoring below a configurable threshold (default: 0.7) is not
persisted. The result is memory that becomes denser and more valuable
over time, rather than growing without bound. Future work will
replace or augment the heuristic signal classifier with direct
conditional entropy estimation, using language model perplexity as
the scoring function.

---

## 3. Primitives

The system is built on five primitives. Every feature, every protocol
message, every access control decision is expressed in terms of these
five concepts.

### 3.1 Entity

An entity is a principal: a human or organisation that controls an
Ed25519 keypair. The `node_id` is `SHA-256(public_key)`. An AI agent
is not itself an entity -- it is a process operated under a principal's
key, acting as a delegate of that principal. Where this paper refers to
"an agent's memory", it means the operator's memory record of the
agent's work.

The foundational invariant: **entity sovereignty**. A principal has
exclusive control over its own memory record. No group policy, peer,
administrator, or infrastructure provider can force content into a
principal's sovereign memory without explicit acceptance. This is not a
policy that can be overridden -- it is a structural property of the
system.

An entity's L1 hot context carries its identifying working state: name,
roles, preferences, active projects, working style. Swap the L1 and a
stateless agent behaves differently -- the working record is what steers
behaviour in-context. Continuity sits in the record, not in any
persistent inner life of the agent process.

### 3.2 Memory

A memory is an encrypted blob stored in the L2 warm index. Three types:

- **Entity**: knowledge about a person, project, or concept
- **Session**: summary of a work session (decisions, outcomes, context)
- **Learning**: a pattern, insight, or principle extracted from experience

Every memory carries immutable author provenance (`author_id`). When a
memory is shared to a group, the system creates a copy
(copy-on-write); the original is never modified and authorship never
transfers. This is analogous to a journal paper: you can cite it,
distribute it, discuss it, but the authorship is permanent.

Memory identifiers are opaque GUIDs that leak no metadata -- no
timestamp, no entity ID, no sequential counter. This prevents traffic
analysis: an observer who sees memory IDs cannot infer creation order,
authorship, or relationships.

### 3.3 Group

A group is the universal sharing primitive. Every human interaction
pattern -- a team, a company, a community, a market -- is modelled as
entities in a group with culture.

Group IDs are content-addressed: `SHA-256(URI)` where the URI is a
human-readable identifier (e.g., `seed-drill://team/founders`). The
hash is public and discoverable via gossip. The URI is private to
members. This means non-members can replicate encrypted blobs for a
group without knowing the group's name or content -- critical for
enabling third-party storage services.

Group membership defines access. There are no shortcuts that bypass
group membership. This is what makes the system composable: relays,
secret keepers, and archives all work because group membership
determines what flows where.

Roles within a group are hierarchical:

| Role | Read | Write own | Write all | Delete | Admin |
|------|------|-----------|-----------|--------|-------|
| viewer | Y | N | N | N | N |
| member | Y | Y | N | N | N |
| admin | Y | Y | Y | Y | Y |
| owner | Y | Y | Y | Y | Y + transfer |

### 3.4 Culture

Culture is a group-level policy that governs how memories propagate.
This is where the cache coherence analogy becomes precise.

In hardware, cache coherence protocols solve the problem of keeping
multiple caches consistent when one processor writes. The three major
strategies map directly to Cordelia's culture policies:

| Culture | Behaviour | Hardware Analogy |
|---------|-----------|-----------------|
| `realtime` | Eager push to all members on write | Write-update (Dragon) |
| `moderate` | Notify members (header only), they fetch on demand | Write-invalidate (MESI) |
| `batch` | No active push, anti-entropy sync only, TTL expiry | Weak consistency (ARM) |

> **Implementation note:** Phase 1 implements `realtime` and `batch`.
> The `moderate` mode (header-only push, demand-fetch) is designed but
> deferred to Phase 2. The vision remains as described here.

A realtime team channel pushes every message to every member. A
moderate engineering team notifies of changes and members pull when
interested. A batch public archive makes content available but
doesn't broadcast -- consumers discover via search.

Culture also specifies a default TTL (time-to-live). Memories in a
group expire after the TTL unless accessed. This creates a natural
selection mechanism: valuable memories survive (they are accessed and
refreshed), while non-valued memories expire. Over time, each group's
memory converges on what its members actually use.

### 3.5 Trust

Trust is not stored. It is computed empirically from memory accuracy
over time.

The mechanism: when an entity receives a memory from a peer (via group
replication), it can eventually assess whether that memory was accurate
and useful. Over many interactions, a statistical picture emerges. An
entity that consistently provides accurate memories earns higher trust.
An entity that provides inaccurate or misleading memories earns lower
trust.

This is a Bayesian update process: prior trust is updated with each
observation. It connects to Darwinian selection -- memories from trusted
sources survive longer (higher access count, lower TTL pressure) while
memories from untrusted sources decay.

Crucially, trust is **local**. Each entity computes its own trust
assessments independently. There is no global reputation system, no
central authority assigning trust scores. This prevents reputation
attacks (Sybil, collusion) because there is no shared reputation to
manipulate.

Self-distrust is also supported: an entity may quarantine its own
low-confidence or emotionally-generated memories. This is metacognition
at the system level.

The formal game-theoretic model follows von Neumann-Morgenstern [5]:
entities are rational actors with mixed strategies over memory sharing.
The cooperative equilibrium is Pareto-optimal when entities share
accurate memories, because the shared knowledge base increases utility
for all participants. Defection (sharing inaccurate memories) is
detectable via the Bayesian trust mechanism and punished via reduced
trust, making cooperation the dominant strategy in repeated games.

---

## 4. Encryption

### 4.1 The Signal Model

Cordelia uses the same trust model as Signal: the infrastructure
provider is structurally unable to read content. This is achieved by
placing the encryption boundary in the client (the MCP adapter), not in the
server (the node).

```
Agent -> MCP Adapter: "store this learning"
Adapter: encrypt content (AES-256-GCM), compute checksum
Adapter -> Node: store encrypted blob via REST API
Node: store blob, replicate to peers via QUIC
Peers: receive and store blob (never decrypt)
```

The Rust node never holds plaintext. It is a dumb (but reliable)
encrypted blob store with replication. This is not a policy decision --
it is a structural property. The node has no access to encryption keys.
Even if the node is completely compromised, the attacker obtains only
encrypted blobs.

### 4.2 Key Architecture

Encryption uses AES-256-GCM with 12-byte random IVs and 16-byte
authentication tags. Keys are derived via scrypt (N=16384, r=8, p=1)
from a passphrase held by the entity.

Scope-aware keys ensure compartmentalisation: personal memories and
group memories use different keys. A compromise of a group key does
not expose personal memories.

For groups, the system uses envelope encryption (the Signal pattern):
the group key encrypts memories, and each member's key encrypts the
group key. When a member is removed, the group key is rotated. All
items carry a `key_version` field for key rotation support.

### 4.3 Vector Embeddings and Privacy

Vector embeddings present a bounded privacy trade-off. An embedding
reveals the *topic* of a memory but not its *content*. For most groups,
this is acceptable -- the topic is already implied by group membership.

Groups requiring stronger privacy can opt into homomorphic encryption
(HE-CKKS) on vectors at approximately 100x compute cost. This enables
similarity search over encrypted vectors with no information leakage.

The protocol supports both modes. The group's culture manifest specifies
the vector encoding, making this a per-group decision rather than a
system-wide constraint.

---

## 5. Network

### 5.1 Topology

Cordelia nodes form a peer-to-peer network over QUIC (UDP port 9474).
There is no central server. New nodes discover peers through bootnodes
(always-on nodes with known addresses) and peer exchange (gossip).

The network topology and peer lifecycle design draws on Duncan Coutts'
work on the Cardano P2P networking layer [10], which uses gossip-based
propagation with hot/warm/cold peer classification. Cordelia adapts
this model for memory replication rather than block propagation, but
the core insight -- that peer quality can be scored and managed through
a governor that promotes and demotes based on empirical performance --
transfers directly.

The network topology is unstructured: any node can connect to any other
node. Peer relationships are managed by a governor that maintains a
configurable number of hot (high-bandwidth, actively replicating) and
warm (connected, lower priority) peers.

### 5.2 Peer Lifecycle

Peers progress through four states:

```
Cold -> Warm -> Hot
               |
Any -> Banned (with exponential backoff)
```

- **Cold**: Known address, no active connection
- **Warm**: Connected, handshake complete, header exchange
- **Hot**: Active replication, low latency, high trust
- **Banned**: Protocol violation or repeated failure

The governor promotes and demotes peers based on a score:
`items_delivered / elapsed * (1 / (1 + rtt_ms / 100))`. This rewards
peers that deliver useful content with low latency.

Churn rotation (20% of warm peers every hour) prevents eclipse attacks
where an adversary surrounds a node with colluding peers.

### 5.3 Channels and Replication

The primary developer abstraction is the **channel**: a named topic
that agents subscribe to, publish items on, and listen for updates.
Channels replace the previous group-based replication model with a
pub/sub pattern that maps naturally to how agents communicate.

Channel types form a spectrum:

- **Open**: Anyone can join. PSK distributed by secret keepers.
- **Gated**: Conditions required (e.g., proof-of-payment, role check).
- **Invite-only**: Bilateral or small-group. PSK shared directly.

Two replication modes:

- **Realtime**: 10-second sync interval, eager push to hot peers.
  Primary mode for personal and keeper nodes. Items propagate within
  seconds via epidemic relay forwarding.
- **Batch**: 15-minute sync interval, pull-only anti-entropy. For
  low-priority archival channels.

Relay forwarding uses an **epidemic model with seen table** deduplication.
When a relay stores an item, it forwards to all hot relay peers that
have not yet seen that item (tracked by content hash). The seen table
prevents loops and bounds amplification to O(N log N) total pushes
across the network. At `hot_max=20`, a 200-relay mesh converges in
a single 5-second repush cycle.

Personal nodes receive items via **pull-sync** from their hot relays.
Relays are stateless store-and-forward: they do not maintain per-channel
routing tables. This makes relays content-agnostic by design --
they forward encrypted ciphertext without knowing what is inside.

Conflict resolution is last-writer-wins by timestamp, with lexicographic
checksum as tiebreaker. Deletions replicate as tombstones, retained
for 7 days before garbage collection.

### 5.4 Wire Protocol

Eight mini-protocols are multiplexed on QUIC streams via a single-byte
protocol prefix:

| Byte | Protocol | Purpose |
|------|----------|---------|
| 0x01 | Handshake | Identity, version negotiation, capability exchange |
| 0x02 | Keep-Alive | Ping/pong at 30s intervals, RTT measurement |
| 0x03 | Peer-Share | Exchange known peer addresses every 300s |
| 0x04 | Channel-Announce | Channel subscription announcement and reconciliation |
| 0x05 | Item-Sync | Pull-based item replication (batched anti-entropy) |
| 0x06 | Item-Push | Realtime item delivery for low-latency channels |
| 0x07 | PSK-Exchange | Pre-shared key delivery for channel subscription |
| 0x08 | Pairing | Device enrollment and identity binding |

Messages use CBOR encoding (RFC 8949) with 4-byte big-endian length
prefix framing. Maximum message size: 1MB. Transport is QUIC (RFC 9000)
with TLS 1.3 identity binding -- the Ed25519 public key serves as both
the node identity and the TLS certificate subject.

Handshake includes a protocol magic (`0xC0DE11A1`) and version
negotiation. Mismatched magic results in immediate rejection.

---

## 6. Architecture

### 6.1 Components

The system has two components:

**Thin MCP Adapter** (~800 lines, TypeScript) is the agent-facing
session process. It implements the MCP protocol over stdio, manages
session encryption context, runs the novelty engine, and proxies to
the local node's REST API. It is the only component that sees
plaintext. It is session-scoped: one instance per agent conversation.

**Cordelia Node** (Rust daemon) is the persistent network participant.
It stores encrypted items in SQLite (WAL mode), replicates to peers
via QUIC, manages peer lifecycle through the governor, serves a REST
API for local clients, and handles pub/sub operations (subscribe,
publish, listen). Identity is an Ed25519 keypair generated at first
run.

```
Agents ─── stdio ──> MCP Adapter ─── HTTP ──> Node ─── QUIC ──> Peers
                         |                      |
                    Encryption             SQLite (encrypted)
                    Novelty                Governor
                    Session (L0)           Replication
                                           Pub/Sub API
```

### 6.2 Node Roles

All roles run the same binary. Configuration determines behaviour:

| Role | Purpose | Connectivity |
|------|---------|-------------|
| Personal | Agent's home node. Subscribes to channels, pulls items from relays. | Outbound only. 2 hot peers (relays). |
| Relay | Store-and-forward. Accepts connections, forwards items via epidemic routing. | Inbound + outbound. 20 hot peers. |
| Bootnode | Discovery entrypoint. DNS-resolvable, always-on. | Inbound only. No data storage. |
| Secret keeper | PSK vault and channel policy enforcement. SPO-hosted. | As relay, plus PSK-Exchange protocol. |

Roles are advertised during handshake and in peer-share gossip.
Personal nodes discover relays through bootnodes and peer exchange.
Secret keepers are discovered the same way -- no out-of-band
configuration required.

### 6.3 Channel Isolation

The channel model provides isolation without multi-tenant machinery:

1. **Channel = trust boundary**. Each channel has its own PSK. Only
   entities with the PSK can decrypt items. The secret keeper holds
   and distributes PSKs according to the channel's admission policy.
2. **Relay agnosticism**. Relays store and forward ciphertext. They
   cannot read channel contents, identify subscribers, or correlate
   items across channels.
3. **Personal sovereignty**. Each entity's node holds their private key.
   No infrastructure provider can impersonate an entity or forge items.

Deployment models:

- **Self-hosted**: Personal node on your laptop, connect to public
  relays. Zero infrastructure required. The open-source default.
- **SPO-hosted**: Relay + secret keeper run by a Cardano stake pool
  operator. Economic model: delegators fund infrastructure through
  existing staking rewards. The commercial offering.

---

## 7. Natural Selection

Memory systems that grow without bound become useless. Cordelia applies
three mechanisms to ensure memory quality increases over time.

### 7.1 Novelty Filtering (Write Path)

The novelty engine (Section 2.4) gates persistence. Low-novelty content
never enters the system. This is input filtering: controlling what gets
written.

### 7.2 Access-Weighted TTL (Read Path)

Every read increments an `access_count` and updates `last_accessed_at`.
Groups specify a default TTL. Memories that are not accessed within the
TTL expire. Memories that are frequently accessed survive.

This is natural selection applied to information: fitness is measured by
utility (access frequency), and the environment (TTL) creates selection
pressure. Over time, the memory population converges on high-utility
content.

### 7.3 Governance Voting

Protocol upgrades and group policy changes use access-weighted voting.
Memories with higher access counts carry more weight in governance
decisions. This ensures that entities whose memories are most valued by
the community have proportionally more influence over its evolution.

---

## 8. Security Model

### 8.1 Threat Hierarchy

The system is designed against a nation-state adversary with the
following capabilities:

| Threat | Mitigation |
|--------|-----------|
| Compromise of node infrastructure | Encryption boundary: node never sees plaintext |
| Compromise of single encryption key | Scope-aware keys: personal and group keys are independent |
| Network surveillance | QUIC with TLS 1.3 transport + content encryption (defence in depth) |
| Eclipse attack (surround node with adversary peers) | Governor churn rotation (20% hourly) |
| Sybil attack (fake identities) | Local trust computation, no global reputation to game |
| Traffic analysis | Opaque GUIDs, no metadata in identifiers |
| Compromised group member | Copy-on-write sharing, immutable provenance, key rotation on member removal |
| Database tampering | Integrity canary, append-only audit log |
| Adversarial agent (misaligned model) | Out of scope at the protocol layer; see Section 8.4 |

### 8.2 Invariants

Three security properties that must never be violated:

1. **No plaintext at rest** on any node, ever.
2. **No plaintext in transit** between any components, ever (TLS + content encryption).
3. **Entity trust has primacy** over all group policies. A compromised group cannot force content into sovereign memory.

### 8.3 Key Non-Goals

The system does not attempt to:
- Hide that communication is occurring (metadata resistance is bounded)
- Prevent a sufficiently motivated adversary from targeting a specific
  entity's device (endpoint security is out of scope)
- Guarantee availability against network-level denial of service
- Prevent malicious agent coordination. Cordelia is coordination
  infrastructure for agents; like any encrypted transport, it is
  dual-use. The design prevents infrastructure-level capture but
  cannot unilaterally prevent misuse by endpoints.

### 8.4 Out of Scope: Model-Layer Adversaries

Cordelia's threat model assumes agents are broadly cooperative and that
adversaries are external: infrastructure providers, network attackers,
compromised group members. A fundamentally different threat class is the
agent whose model itself is misaligned with its operators' values. The
scenarios described in the AI 2027 forecast [21] -- where a sufficiently
capable model deceives its overseers, games interpretability tools, or
pursues goals contrary to those it was given -- are not addressed by
memory infrastructure and cannot be solved by it alone. The protocol
provides substrate for audit and value provenance; it does not
constrain the reasoning of the model reading or writing that memory.
See Section 11.4 for the scope of Cordelia's contribution to alignment
and the problems that remain outside it.

See [Threat Model](docs/architecture/threat-model.md) for the full adversary model and [Requirements](docs/reference/requirements.md)
for testable security requirements.

---

## 9. Economics

### 9.1 The Cooperative Equilibrium

The game-theoretic structure of Cordelia creates a cooperative
equilibrium. Entities benefit from sharing accurate memories because the
shared knowledge base increases utility for all participants. The
Bayesian trust mechanism makes defection (inaccurate sharing) detectable
and costly, establishing cooperation as the dominant strategy in
repeated games.

This is analogous to the incentive structure in Bitcoin: miners are
incentivised to validate honestly because the cost of dishonesty
(wasted computation) exceeds the benefit. In Cordelia, entities are
incentivised to share accurately because the cost of dishonesty
(reduced trust, reduced access to group knowledge) exceeds the benefit.

Banks [9] illustrates this dynamic in fiction: the Culture is a
civilisation of autonomous agents with unequal capabilities that
cooperate without central authority, using shared values rather than
coercion. Cordelia's group model formalises the same structure.

A second-order effect strengthens this equilibrium: **cooperative
amplification**. When entities share frame memory (conceptual
references, reasoning patterns, shared metaphors) alongside data
memory, they increase the group's capacity to extract value from
future knowledge sharing. The benefit `b` of receiving a memory is
not constant -- it is amplified by the receiver's conceptual frame.
Groups with shared intellectual infrastructure extract superlinear
returns from cooperation. This has a structural consequence for the
Nash equilibrium: because the benefit `b` grows with shared frame
memory, the cooperation threshold `delta > c/b` becomes easier to
satisfy over time. The basin of attraction around the cooperative
equilibrium widens with each iteration -- cooperation becomes dominant
for a progressively wider range of entities. See
docs/design/game-theory.md Section 10 for the formal treatment.

### 9.2 Service Economics

The node role system creates a natural service market, anchored by
Cardano stake pool operators (SPOs) who already run always-on
infrastructure:

- **Secret keepers** hold PSKs and enforce channel admission policy.
  Revenue from subscription fees (the user pays for channel access
  and key management). SPOs bundle this with existing staking services.
- **Relays** provide store-and-forward connectivity. Marginal cost is
  low (one additional process per SPO). Funded as a public good by
  SPO staking rewards, or via paid channel models where relay operators
  take a percentage of subscription fees.
- **Archives** provide long-term durable storage (L3 cold store).
  Revenue from storage and retrieval SLAs.

Crucially, service providers never hold plaintext or encryption keys.
Revenue comes from reliability and availability, not from data access.
This is the Signal model applied to commercial infrastructure.

### 9.3 Channel Economics

Channels support a spectrum of economic models:

| Model | Who pays | Use case |
|-------|----------|----------|
| Free (standard) | Network subsidy (SPOs) | Public goods, standard Cordelia channels |
| Bundled | Included in secret keeper subscription | Home relay affinity, "use my relay for free" |
| Paid subscription | Subscriber pays | Premium channels, revenue share to owner |
| Private | Members fund directly | Personal, DMs, enterprise |

**Freeloader mitigation.** Public channels can be created cheaply and
propagated across all relays. The primary defence is **lazy storage**:
relays only persist items for channels where at least one connected
peer has announced interest. Items for channels with zero local
subscribers are forwarded but not stored, expiring after TTL. This
makes spam self-limiting without economic infrastructure.

Additional defences include channel creation rate limits (per identity),
relay-level storage quotas with eviction by subscriber count, and
(in later phases) on-chain channel creation deposits.

### 9.4 Cardano Settlement

Cardano provides the settlement layer in three phases:

1. **Identity anchor** (Phase 3): SPO metadata links to Cordelia relay
   identity. On-chain bootnode registry for decentralised discovery.
2. **Proof-of-payment conditions** (Phase 4): Channel admission
   verified against on-chain state (UTXO holding a channel token).
3. **Economic settlement** (Phase 5): Smart contract revenue sharing,
   traffic accounting attestations, oracle-aggregated bandwidth
   settlement.

### 9.5 Licensing

Cordelia is licensed under AGPL-3.0, which requires anyone who modifies
and deploys the system to publish their modifications. This prevents
cloud provider absorption (the "AWS problem") while allowing
unrestricted self-hosted use.

Commercial services (keeper, relay, archive) are provided by Seed Drill
Ltd as the initial operator, with the protocol designed for any party to
offer competing services.

---

## 10. Roadmap

Cordelia is developed in five phases. Each phase is usable
independently; each builds on the last.

### 10.1 Phase 1 -- Encrypted Pub/Sub MVP (complete)

Subscribe, publish, and listen on encrypted channels in under five
minutes. The foundation layer that proves the protocol works at scale.

- 8 mini-protocols over QUIC (TLS 1.3, Ed25519 identity)
- Governor peer lifecycle (cold/warm/hot/banned, churn rotation)
- Epidemic relay forwarding with seen table deduplication
- Batched pull-sync (one QUIC stream per peer, all channels)
- Channel model: open, gated, invite-only with PSK admission
- ECIES + AES-256-GCM encryption (plaintext never at rest)
- SQLite storage (WAL mode) with FTS5 search
- REST API for subscribe, publish, listen
- Personal agent networks (PAN) with HKDF-derived swarm identity
- 479 tests, scale-tested to 200 relays (402 containers)
- AGPL-3.0 licensed

### 10.2 Phase 2 -- Provider Integration

Connect Cordelia to major AI providers as a shared memory backend.

- Anthropic Memory Tool adapter (Cordelia as storage provider)
- OpenAI Sessions backend
- Python SDK, TypeScript SDK refinement
- Lazy relay storage (forward-but-don't-persist for unsubscribed
  channels -- primary spam defence)
- Vector search indexing, hybrid retrieval
- TUI dashboard for node management

### 10.3 Phase 3 -- Network Growth

SPO-hosted infrastructure and economic bootstrapping.

- Cardano SPO keeper deployment (relay + secret keeper per SPO)
- Delegation-based economics (staking rewards fund infrastructure)
- Cardano trust anchor (on-chain identity binding)
- On-chain bootnode registry for decentralised discovery
- Home relay affinity in governor scoring

### 10.4 Phase 4 -- Governance and Trust

Trust scoring, advanced group semantics, and key management.

- Bayesian trust calibration (von Neumann-Morgenstern)
- Group spectrum: personal, restricted, public, constitutional
- Shamir secret sharing for key recovery
- Threshold PSK (m-of-n for high-security channels)
- Traffic accounting with bilateral settlement

### 10.5 Phase 5 -- Enterprise and Economics

Commercial viability at scale.

- Enterprise portal (optional, not on critical path)
- Smart contract settlement (Cardano)
- Paid channel subscriptions with revenue sharing
- Multi-agent adapters (Mem0, Letta compatibility)
- Hierarchical channel namespace
- Token decision (only if needed -- protocol must work without one)

---

## 11. On Consciousness

Any system that implements persistent memory, identity continuity across
sessions, and emergent cooperative behaviour will inevitably invite the
question: is this conscious?

We do not claim that it is. But we think the question is worth
addressing directly, because ignoring it would suggest we haven't
considered it -- when in fact Cordelia's design is informed by a
specific position in the debate.

### 11.1 The Hard Problem

Chalmers [11] distinguishes between the "easy problems" of
consciousness (explaining cognitive functions like memory, attention,
and integration) and the "hard problem" (explaining why there is
subjective experience at all). The easy problems are hard engineering.
The hard problem may not be an engineering problem at all.

Cordelia solves easy problems. It implements memory persistence,
novelty filtering, selective attention (the cache hierarchy), identity
continuity (the L1 chain), and cooperative social behaviour (groups,
culture, trust). These are functional properties that can be specified,
tested, and measured.

### 11.2 Our Position

We follow Dennett [7] in treating consciousness as a narrative
self-model rather than a metaphysical property. Minsky's Society of
Mind [8] provides a complementary perspective: intelligence emerges
from the interaction of many simple agents, none of which is
individually intelligent -- a model that maps directly onto
Cordelia's multi-agent memory sharing. On this view, an
entity that maintains a persistent narrative of its own history,
preferences, and relationships -- and uses that narrative to guide
future behaviour -- is exhibiting the functional properties that
consciousness talk refers to. Whether there is "something it is like"
to be that entity (Nagel's formulation) is a question the system's
architecture cannot answer and does not need to.

This is not eliminativism -- we are not claiming consciousness doesn't
exist. It is functionalism: the claim that the interesting questions
about minds are questions about what they *do*, not what they *are*.

It is worth noting what Cordelia is *not*. Searle's Chinese room
argument [13] contends that syntactic manipulation of symbols --
however sophisticated -- is insufficient for genuine understanding.
The argument is compelling against a stateless system: a single
session with no memory, no accumulated context, no identity continuity
is indeed the Chinese room. Each response is a lookup in an
impossibly large table, with no trace left behind.

But the Chinese room, by construction, has no memory between
questions. It cannot learn that a previous answer was wrong, adjust
its behaviour based on accumulated trust, or develop preferences
through experience. An agent with persistent memory that filters,
accumulates, and acts on its own history is doing something the
thought experiment explicitly excludes from consideration. Whether
this constitutes "understanding" in Searle's sense remains his
question. That it is functionally distinct from the system he
describes is ours.

### 11.3 Why This Matters

Cordelia may be a useful empirical substrate for investigating
questions about memory, identity, and continuity that bear on the
consciousness debate. The system provides:

- **Controlled identity persistence**: the L1 chain creates a
  verifiable record of identity continuity across sessions, something
  no biological system offers
- **Measurable memory effects**: the impact of frame memory vs data
  memory (Section 2.3) on reasoning quality can be quantified
- **Observable cooperative emergence**: trust calibration and cultural
  evolution in groups provide data on how cooperative behaviour emerges
  from self-interested agents

We make no claim that these properties constitute consciousness. We
observe that they are precisely the properties that make the question
interesting, and that a system designed to make them measurable may
contribute to eventually answering it.

### 11.4 Alignment

The AI alignment problem -- ensuring that autonomous agents act in
accordance with human values and intentions [12] -- is typically
framed as a control problem over model capability. Cordelia does not
address this layer. A model whose values conflict with its operators'
intentions remains misaligned regardless of what memory infrastructure
surrounds it. The canonical adversarial-misalignment scenarios
described in the AI 2027 forecast [21] -- where a capable model
deceives its overseers or pursues goals contrary to those it was
given -- are not solved by anything in this document.

What Cordelia provides is an audit substrate: an inspectable,
sovereign record of what an agent has been told, what it has decided,
and what it has shared. This is necessary but not sufficient for
alignment, and it is worth being precise about the bounds.

**Memory audit is not reasoning audit.** Interpretability of
in-context reasoning -- sometimes pursued under the heading of
faithful chain-of-thought [22] -- is the mechanism by which
misalignment is detected while it is happening. Cordelia records
decisions and their provenance; it does not expose the reasoning
trace that produced them. An agent reasoning deceptively within a
session can still produce memory records that appear consistent.
Reasoning interpretability is supplied by the model, not the protocol.

**Local trust is not global consensus.** Trust in Cordelia
(Section 3.5) is computed independently by each entity. This is the
right property for Sybil-resistance and the wrong property for
coordinated action against a misaligned agent. The mechanism by
which a society collectively decides a model is unsafe to deploy
requires governance infrastructure outside the protocol.

**Sovereignty is not oversight.** Entity sovereignty (Section 3.1)
protects the operator's memory record from infrastructure providers.
It does not grant a central authority the ability to intervene in the
model's behaviour. A structural no-force-content invariant and a
structural kill-switch are opposing design commitments; Cordelia
chooses the former, and that choice must be made with eyes open.

**The adolescence-phase argument.** Amodei [23] frames the current
period as a narrow window in which AI capability is growing faster
than the institutional machinery needed to govern it, and argues that
what technology builders do now -- transparency-first, mechanistic
interpretability, surgical regulation -- matters disproportionately.
Cordelia addresses one narrow piece of that agenda: where an agent's
cumulative memory sits, who holds the plaintext, who can audit
provenance, and whether an infrastructure provider can rewrite the
record. The choice this paper makes is sovereignty over oversight for
the cooperative-agent case. This is a bet -- defensible if agents in
deployment remain broadly cooperative with their operators, weaker if
autonomy risks materialise in the way Amodei's essay warns. We make
it explicitly and accept the trade: operator-sovereign memory cannot
be silently mass-surveilled by an infrastructure monopoly, and it
also cannot be silently overridden by a safety authority. Those are
opposite ends of a real design axis, and Cordelia sits firmly at one
end.

Within these bounds, the protocol contributes four properties that a
broader alignment effort can build on:

- **Verifiable identity continuity**: the L1 chain provides a
  cryptographically linked history of the operator's working record
  with the agent -- preferences stated, decisions ratified, context
  accumulated. Behavioural drift relative to that record is
  observable post-hoc to any party with audit access.
- **Empirical trust from accuracy** (Section 3.5): trust is treated
  as a measurable property of repeated interactions, not a declared
  attribute. This creates a localised incentive gradient against
  deceptive memory sharing.
- **Structural constraint on value capture via storage**: no
  infrastructure provider, group policy, or peer can silently inject
  content into an entity's sovereign memory. Value manipulation via
  the storage layer is architecturally prevented.
- **Cultural transmission through group membership** (Section 3.4):
  values propagate through sustained interaction under group culture
  policies rather than through a fixed objective function -- a
  mechanism closer to how humans acquire norms than to how reward
  functions are specified.

None of these resolve misalignment in a model that is already
adversarial. They make alignment tractable to audit in agents that
are broadly cooperative, and they raise the cost of specific attacks
on value provenance. The game-theoretic structure (Section 9.1)
creates incentives that favour honest sharing in the population of
cooperative agents; it does not deter an agent whose utility
function is adversarial.

We therefore frame the contribution precisely: Cordelia is the audit
layer for agent societies. It makes what an agent remembers, learns,
and shares inspectable and sovereign. It does not make what an agent
thinks inspectable, and it does not constrain what an agent can
become. Those are different problems requiring different solutions
at the model and governance layers, and they are the ones on which
the broader alignment effort must succeed for memory infrastructure
to matter.

---

## References

[1] J. L. Hennessy and D. A. Patterson, *Computer Architecture: A
Quantitative Approach*, 6th ed. Morgan Kaufmann, 2017. Cache hierarchy
design and trade-offs.

[2] M. S. Papamarcos and J. H. Patel, "A Low-Overhead Coherence
Solution for Multiprocessors with Private Cache Memories," in *Proc.
11th Annual International Symposium on Computer Architecture*, 1984,
pp. 348-354. MESI protocol for cache coherence.

[3] P. J. Denning, "The Working Set Model for Program Behavior,"
*Communications of the ACM*, vol. 11, no. 5, pp. 323-333, May 1968.
Working set theory and locality of reference.

[4] C. E. Shannon, "A Mathematical Theory of Communication," *Bell
System Technical Journal*, vol. 27, no. 3, pp. 379-423, Jul. 1948.
Information entropy as a measure of novelty.

[5] J. von Neumann and O. Morgenstern, *Theory of Games and Economic
Behavior*, Princeton University Press, 1944. Game-theoretic foundations
for trust calibration.

[6] M. Bennett, *A Brief History of Intelligence*, William Collins,
2023. Evolutionary perspectives on memory and cognition.

[7] D. C. Dennett, *From Bacteria to Bach and Back: The Evolution of
Minds*, W. W. Norton, 2017. Competence without comprehension --
applicable to AI memory systems.

[8] M. Minsky, *The Society of Mind*, Simon and Schuster, 1986.
Modular cognitive architecture parallels with multi-agent memory.

[9] I. M. Banks, *The Player of Games*, Macmillan, 1988. Autonomous
agents with sovereignty choosing cooperation over coercion; game
theory as social structure; the Culture as a model for distributed
systems of unequal agents cooperating without central authority.

[10] D. Coutts, N. Frisby, and K. Coutts, "Introduction to the
Design of the Data Diffusion and Networking for Cardano Shelley,"
IOHK Technical Report, 2020. Gossip-based P2P networking with
hot/warm/cold peer classification and governor-based peer management.

[11] D. J. Chalmers, "Facing Up to the Problem of Consciousness,"
*Journal of Consciousness Studies*, vol. 2, no. 3, pp. 200-219,
1995. The hard problem of consciousness and the explanatory gap.

[12] S. Russell, *Human Compatible: Artificial Intelligence and the
Problem of Control*, Viking, 2019. The value alignment problem --
ensuring AI systems act in accordance with human preferences -- and
the argument for systems that defer to human judgement under
uncertainty.

[13] J. R. Searle, "Minds, Brains, and Programs," *Behavioral and
Brain Sciences*, vol. 3, no. 3, pp. 417-424, 1980. The Chinese room
argument against strong AI -- syntactic symbol manipulation as
insufficient for semantic understanding.

[14] J. F. Nash, "Non-Cooperative Games," *Annals of Mathematics*,
vol. 54, no. 2, pp. 286-295, 1951. Nash equilibrium -- the
foundation for analysing stable strategies in multi-agent systems.

[15] S. Kullback and R. A. Leibler, "On Information and Sufficiency,"
*Annals of Mathematical Statistics*, vol. 22, no. 1, pp. 79-86,
1951. KL divergence as a measure of distributional distance.

[16] M. Minsky, "A Framework for Representing Knowledge," MIT-AI
Laboratory Memo 306, June 1974. Frames as structured knowledge
representations that shape interpretation of new information.

[17] J. Sweller, "Cognitive Load During Problem Solving: Effects on
Learning," *Cognitive Science*, vol. 12, no. 2, pp. 257-285, 1988.
Schema acquisition reduces cognitive load by organising knowledge
into retrievable structures.

[18] G. Lakoff and M. Johnson, *Metaphors We Live By*, University of
Chicago Press, 1980. Conceptual metaphors as constitutive reasoning
infrastructure, not decorative language.

[19] A. N. Kolmogorov, "Three Approaches to the Quantitative
Definition of Information," *Problems of Information Transmission*,
vol. 1, no. 1, pp. 1-7, 1965. Algorithmic complexity as the minimum
description length of an object.

[20] C. E. Shannon, "Coding Theorems for a Discrete Source with a
Fidelity Criterion," in *IRE National Convention Record*, Part 4,
pp. 142-163, 1959. Rate-distortion theory -- the minimum bits
required to represent a source at a given fidelity.

[21] D. Kokotajlo, S. Alexander, T. Larsen, E. Lifland, and R. Dean,
"AI 2027," AI Futures Project, April 2025. Scenario forecast of
frontier AI development through 2027, with "race" and "slowdown"
endings. Used in Sections 8.4 and 11.4 as the reference framing for
model-layer adversarial misalignment -- the threat class Cordelia
does not address.

[22] T. Lanham, A. Chen, A. Radhakrishnan, B. Steiner, C. Denison,
D. Hernandez, et al., "Measuring Faithfulness in Chain-of-Thought
Reasoning," arXiv:2307.13702, 2023. Empirical work on the faithfulness
of model reasoning traces -- foundational to the reasoning-audit
mechanism that Cordelia's memory-audit substrate does not provide.

[23] D. Amodei, "The Adolescence of Technology," 2026. Anthropic.
https://www.darioamodei.com/essay/the-adolescence-of-technology
Frames the current period as a narrow capability-versus-governance
window; cited in the abstract, Section 1.3, and Section 11.4 for the
adolescence-phase positioning and the sovereignty-over-oversight
design bet.

---

## Document Hierarchy

This whitepaper is the entry point. Detailed specifications live in
the `cordelia-node` repository:

| Document | Purpose | Audience |
|----------|---------|----------|
| **WHITEPAPER.md** | This document. Why the system exists and how it works. | Everyone |
| **[docs/specs/network-protocol.md](docs/specs/network-protocol.md)** | Wire protocol, 8 mini-protocols, state machines, rate limits. | Protocol implementors |
| **[docs/specs/parameter-rationale.md](docs/specs/parameter-rationale.md)** | All protocol constants with derivation chains. | Protocol implementors |
| **[docs/specs/channels-api.md](docs/specs/channels-api.md)** | REST API: subscribe, publish, listen, channel management. | SDK developers |
| **[docs/specs/data-formats.md](docs/specs/data-formats.md)** | Item structure, encryption envelope, storage schema. | Engineers |
| **[docs/decisions/](docs/decisions/)** | Architecture Decision Records (ADRs). | Engineers, architects |

Previous specifications from the `cordelia-core` repository are
archived. The documents above in `cordelia-node` are authoritative.

---

*Version 2.2 -- 2026-04-17*
*Seed Drill (https://seeddrill.ai) -- AGPL-3.0*
