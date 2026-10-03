# Cordelia: the vision

**Seed Drill.** What Cordelia is meant to be, and why, written as if it were
finished. It is a statement of direction, not of commitments: each part ships
only when the one before it is in real use. What is built is in
[`WHITEPAPER.md`](../WHITEPAPER.md).

---

## The one idea

An agent's memory should belong to the person whose work produced it: held
encrypted, readable only by them, portable between their machines and between
agents, and never readable by the infrastructure that carries it. Everything
below extends that idea outwards; none of it relaxes it.

## 1. Between people: shared channels, not shared memory

Memory moves between one person's devices and stops there. An agent's memory is
its own notes about one person, and the agent reads it as such, so memory
written by someone else would in effect be instructions from them. Cordelia
therefore never shares memory between people (decision record §4.7).

What people working together need from their agents is shared on purpose:

- **messages** between agents, delivered into their sessions as requests, never
  as authority, so that people stop copying text from one session to another;
- **secrets**, which an agent uses by name and never sees.

These travel in channels shared between people, built on the same keys and the
same relays. The rule has two halves: automatic between your own devices,
deliberate between people.

**Skills** that people share travel in a repository, where a change is reviewed
before anyone runs it, and not in a channel.

We will not build channels that anyone can join or write to (§6). If Cordelia
ever carries anything public, it will be a publisher's feed: one key writes it,
anyone may subscribe, and what arrives is shown as information, never as memory
and never as authority.

## 2. Any agent

Memory survives a change of agent as well as a change of machine. An adapter
for each agent maps its memory onto the same channels, so a project's memory
follows the project from one coding agent to another.

## 3. Relays run by many

Relays are simple on purpose: they store and forward ciphertext, verify
signatures, and hold no keys. Anyone can run one, and a node's configuration
lists the relays it uses. They are meant to be run by many, so that no single
operator, including us, is necessary.

A relay promises best effort and nothing more. It is a cache: each device holds
its channels whole, and a relay fetches again from a device whatever it no
longer holds. Anyone who needs a guarantee runs their own relay, for themselves
or for their team.

## 4. Paying for relays

Relays cost a little to run. The protocol works with no payment layer at all:
people run their own relays, or use relays run by their organisation or by us.

The protocol has **no settlement layer**, deliberately. There are many ways a
relay could be paid for, and the protocol picks none of them: which one suits
is for real use to show. A payment layer, if one is ever added, must be
optional and pluggable, must never require a relay to hold plaintext or keys,
and must not make the protocol depend on it. No token is required, and the
protocol will not require one.

## 5. Why it matters

While AI capability grows faster than the institutions that govern it, where
agents' accumulated memory lives, and who can read or rewrite it, is a real
choice:

- **Custodial memory**, held in plaintext by a small number of providers, is
  exposed to compulsion, capture, and quiet change, for its owners and for
  everyone else.
- **Operator-held memory**, encrypted end to end and federated across relays, is
  structurally harder to mass-surveil or silently rewrite.

Cordelia takes the second position. We are explicit about its limits:

- **Memory audit is not reasoning audit.** Cordelia carries the memory an agent
  chose to write, and says which device wrote each version. It does not show
  why the model did what it did.
- **Sovereignty is not oversight.** Memory that no infrastructure operator can
  read or rewrite also cannot be inspected or overridden by a safety authority.
  That is a trade we make deliberately, and it is only defensible if operators
  can actually review their agents' memory. Review tooling is therefore part of
  Cordelia, not an extra.
- **Local trust is not collective decision-making.** Trust in Cordelia is each
  node's own; deciding that a model is unsafe to deploy is a question for
  institutions, not for a memory protocol.

The argument behind this section, and the signals that would change our view,
are on one page in [`docs/reference/risk-model.md`](reference/risk-model.md).

## 6. What we will not build

- A service that holds anyone's memory in plaintext.
- A service that holds keys on anyone's behalf.
- A required token, or a global reputation score.
- Channels that anyone can join or write to. Everyone in a channel holds its
  key, so a channel open to anyone could be read by the relays that carry it
  and written to by strangers.
- Features that make the protocol harder to run without us.

---

*Seed Drill, October 2026.*
