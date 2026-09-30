# Where Cordelia goes after v1

**Seed Drill -- October 2026.** A statement of direction, not of commitments.
Each step ships only once the one before it is in real use. What Cordelia *is*
today is in [`WHITEPAPER.md`](../WHITEPAPER.md); this document is what we are
aiming at, and why.

---

## The one idea we keep

An agent's memory should belong to the people whose work produced it: held
encrypted, readable by them and the people they choose, portable between
machines and between agents, and never readable by the infrastructure that
carries it. Everything below extends that idea outwards; none of it relaxes it.

## 1. Beyond one person: sharing

v1 keeps one person's devices in step. The next step (v1.1) shares a project's
memory with other people, using the same mechanism: a teammate's devices become
members of the project's channel.

Sharing raises a question v1 does not have to answer: an agent reads memory as
its own notes, so memory written by someone else is, in effect, instructions
from them. Before sharing ships we will decide how that is surfaced, for
example by labelling who wrote each memory, or by holding memory from other
people for review before it reaches the agent.

The network effect starts here: each person added to a project makes that
project's memory worth more to everyone on it.

## 2. Beyond one agent

Memory should survive a change of agent as well as a change of machine. More
adapters, each mapping one agent's memory onto the same channels, let a project's
memory follow the project from one coding agent to another. A second adapter is
the test of that claim.

## 3. Beyond our relays

Relays are simple on purpose: they store and forward ciphertext, verify
signatures, and hold no keys. Anyone can run one, and a node's configuration
lists the relays it uses. We run the first two; the aim is for others to run
most of them, so no single operator, including us, is necessary.

## 4. Paying for relays

Relays cost a little to run. The protocol works with no payment layer at all:
people run their own relays, or use relays run by their organisation or by us.

We have deliberately **not chosen a settlement layer**. There are many ways
relays could be paid for, and nothing to gain from picking one before real use
shows what is needed. Whatever comes later must be optional and pluggable,
must never require a relay to hold plaintext or keys, and must not make the
protocol depend on it. No token is required, and the protocol will not require
one.

## 5. Why it matters

AI capability is growing faster than the institutions that govern it. In that
window, where agents' accumulated memory lives, and who can read or rewrite it,
is a real choice:

- **Custodial memory**, held in plaintext by a small number of providers, is
  exposed to compulsion, capture, and quiet change, for its owners and for
  everyone else.
- **Operator-held memory**, encrypted end to end and federated across relays, is
  structurally harder to mass-surveil or silently rewrite.

Cordelia takes the second position. We are explicit about its limits:

- **Memory audit is not reasoning audit.** Cordelia records what an agent was
  told, decided, and shared, with provenance. It does not show why the model
  did what it did.
- **Sovereignty is not oversight.** Memory that no infrastructure operator can
  read or rewrite also cannot be inspected or overridden by a safety authority.
  That is a trade we make deliberately, and it is only defensible if operators
  can actually review their agents' memory. Review tooling is therefore part of
  the direction, not an extra.
- **Local trust is not collective decision-making.** Trust in Cordelia is each
  node's own; deciding that a model is unsafe to deploy is a question for
  institutions, not for a memory protocol.

A fuller treatment of these risks, and of the signals that would change our
view, is in [`docs/reference/risk-model.md`](reference/risk-model.md).

## 6. What we will not build

- A service that holds anyone's memory in plaintext.
- A service that holds keys on anyone's behalf.
- A required token, or a global reputation score.
- Features that make the protocol harder to run without us.
