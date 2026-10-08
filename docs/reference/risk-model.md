# Risk model

**Seed Drill.** One page: the argument behind [`docs/vision.md`](../vision.md)
§5, and what would change our view. The
[threat model](../security/threat-model.md) asks whether one person's Cordelia
is safe against an attacker. This page takes it that Cordelia is widely used,
and asks whether that lowers or raises the risks from AI. What is built is in
[`WHITEPAPER.md`](../../WHITEPAPER.md).

## Two risks

- **Capture.** Agents' memory collects in plaintext at a few providers, where
  it can be read under compulsion, used to lock people in, or quietly changed
  [1]. Cordelia is a defence: memory is encrypted on the device that wrote it,
  relays hold ciphertext and no keys, and anyone can run a relay. What opens
  a person's memory is a secret that only their devices hold, and a recovery
  phrase that only they hold.
- **Autonomy.** A model pursues goals that the person running it did not
  intend, and is not caught [1, 2]. Cordelia does nothing for this, and is
  slightly worse at the margin: memory that no relay can read is also memory
  that no outside authority can inspect.

## The bet

While AI capability grows faster than the institutions that govern it, capture
is the nearer risk, and a common way of keeping memory that resists it is worth
more than the oversight it gives up.

1. **Who pays.** The harm from capture falls on everyone, so nobody is paid to
   prevent it. The harm from a misaligned agent falls first on whoever runs it,
   so people ask for alignment and providers compete to supply it.
2. **The precedent.** End-to-end encrypted messaging has run at the scale of
   whole populations for over a decade. The benefit is documented, the cost in
   crime has been bounded, and what failed was devices, not protocols. Agents
   are not people, so this carries over in kind, not in size.
3. **Many operators.** Systems run by many independent operators, such as
   email, have been harder to turn to surveillance than systems run by one.
   Whoever wants everything must compel everyone.

## Limits

- Cordelia does nothing about a model that is already misaligned. It carries
  the memory an agent chose to write and says which device wrote each version.
  It does not show why the model did what it did [3].
- It gives no authority a way to inspect or override an agent's memory. That
  is the price of no provider being able to. Nor can any provider give a
  person their memory back: a person who loses every device and the recovery
  phrase has lost it.
- It does not align agents. Memory is not shared between people, so nothing in
  Cordelia passes one agent's values to another. What it does give is a
  security property: another person has no way to put notes of theirs into
  your agent's memory. The threat model says how far that is tested (T2, T10
  and T13).
- The argument cannot settle how fast misalignment appears, what very many
  agents with private memory do together, or how the law will treat memory
  that a provider cannot inspect.

## What has to stay true

1. **People can review what their agents remember.** Memory is kept as plain
   files on a person's own machine, so review is always possible. It has to be
   easy as well, or the right goes unused.
2. **Nothing from another person is applied by itself.** Memory moves only
   between one person's devices. What other people send arrives as a request,
   never as authority, and shared skills travel in a repository, where a
   change is reviewed.
3. **Relays are run by many.** While relays are few, or most are run by one
   operator, the third argument describes the design more than the network.
   Such an operator can be made to hand over ciphertext and the metadata the
   whitepaper lists (§4), or to stop. That metadata includes one identifier
   that stays the same for a person for as long as their recovery phrase
   does, and which of a person's channels change together when a device is
   removed. It cannot hand over what it does not hold: a key, a recovery
   phrase, or the list of a person's devices.

## What would change our view

- **Capture:** evidence of compelled access to memory held by AI providers
  strengthens the case, and its absence over several years weakens it. A law
  requiring key escrow would limit where this design can be used.
- **Autonomy:** misalignment in deployed models that persists across
  retraining; interpretability that does not keep up with new models; the same
  failure in models trained independently.
- **A condition above fails,** or a design appears with a better balance
  between the two risks.

We revisit this page once a year, or when one of these is seen.

## On record

The only dated part of this page.

- **Estimates.** Made in April 2026, for an earlier and broader design, and not
  yet made again: capture more likely than not within three to five years;
  autonomy risk at scale between one in ten and four in ten; and, if that
  version's conditions were met, 60 to 70 percent confidence that wide adoption
  is good on balance. They are judgements, not fitted models.
- **Versions.** 2.0, October 2026: this page. 1.0, April 2026:
  [archived](../archive/reference/risk-model-2026-04.md); it argued in part
  from features that were not built.
- **References.** [1] D. Amodei, "The Adolescence of Technology", 2026.
  [2] D. Kokotajlo et al., "AI 2027", AI Futures Project, 2025. [3] T. Lanham
  et al., "Measuring Faithfulness in Chain-of-Thought Reasoning",
  arXiv:2307.13702, 2023.
