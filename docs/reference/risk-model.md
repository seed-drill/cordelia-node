# Risk model

**Seed Drill -- October 2026. Version 2.0, one page.** The argument behind
[`docs/vision.md`](../vision.md) §5, and what would change our view. The
[threat model](../security/threat-model.md) asks whether one person's Cordelia
is safe against an attacker. This page asks whether the risks from AI would be
lower or higher if very many people used it.

## Two risks

- **Capture.** Agents' memory collects in plaintext at a few providers, where
  it can be read under compulsion, used to lock people in, or quietly changed
  [1]. Cordelia is a defence: memory is encrypted on the device that wrote it,
  relays hold ciphertext and no keys, and anyone can run a relay.
- **Autonomy.** A model pursues goals that the person running it did not
  intend, and is not caught [1, 2]. Cordelia does nothing for this, and is
  slightly worse at the margin: memory that no relay can read is also memory
  that no outside authority can inspect.

## The bet

Capture is the nearer risk, and a common way of keeping memory that resists it
is worth more, over the next few years, than the oversight it gives up.

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

In April 2026 we judged capture more likely than not within three to five
years, and autonomy risk at scale between one in ten and four in ten. If the
conditions named then were met, we put our confidence that wide adoption is
good on balance at 60 to 70 percent. These were judgements, made for a broader
design, and we have not made them again for today's narrower one.

## Limits

- Cordelia does nothing about a model that is already misaligned. It carries
  the memory an agent chose to write and says which device wrote each version.
  It does not show why the model did what it did [3].
- It gives no authority a way to inspect or override an agent's memory. That
  is the price of no provider being able to.
- It does not align agents. Whitepaper v2.3 suggested that values might spread
  through groups that share memory. Memory is not shared between people, so we
  no longer make that claim. What remains is a security property: Cordelia
  gives another person no way to put notes of theirs into your agent's memory.
  The threat model says how far that is tested (T2, T10 and T13).
- The argument cannot settle how fast misalignment appears, what very many
  agents with private memory do together, or how the law will treat memory
  that a provider cannot inspect.

## What has to stay true

1. **People can review what their agents remember.** Memory is plain files on
   a person's own machine. Review is possible, and not yet easy.
2. **Nothing from another person is applied by itself.** Memory moves only
   between one person's devices. Messages are to arrive as requests, never as
   authority, and shared skills travel in a repository, where a change is
   reviewed.
3. **Relays are run by many.** Today we run the only two, so the third
   argument describes the design and not yet the network. We could be made to
   hand over ciphertext and the metadata the whitepaper lists (§4), or to stop.

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

**History.** Version 1.0 (April 2026) argued in part from trust scores, group
culture, attestation and governance voting, which were not built. It is
[archived](../archive/reference/risk-model-2026-04.md).

**References.** [1] D. Amodei, "The Adolescence of Technology", 2026.
[2] D. Kokotajlo et al., "AI 2027", AI Futures Project, 2025. [3] T. Lanham et
al., "Measuring Faithfulness in Chain-of-Thought Reasoning", arXiv:2307.13702,
2023.
