# Review: identity.md

> Fresh review pass applying review-spec methodology to
> `identity.md` (status Draft, 548 lines, last update 2026-03-12).

## Application Record

| Field | Value |
|-------|-------|
| Date | 2026-04-17 |
| Reviewer | Russell Wing + Claude Opus 4.7 |
| Spec | identity.md (Draft, 2026-03-12) |
| Passes applied | 1 (Gap), 2 (Consistency), 3 (Clarity), 4 (Implementability), 5 (Coverage), 7 (Terminology light), 9 (Security) |
| Passes skipped | 6 (Privacy) -- covered by identity-privacy-model ADR §9 |

---

## Summary

13 findings. 2 HIGH, 7 MEDIUM, 4 LOW. No CRITICAL.

The spec is mature and internally consistent following the 2026-03-12
first-pass review (layer renumbering, DM domain separation, JCS signing
input). The remaining issues are primarily about Phase 2+ content
bleeding into Phase 1 requirements without clear boundaries, two gaps
in the compromise/revocation path, and unspecified attestation storage
mechanics. Pairing protocol is well-covered by cross-reference to
operations.md and network-protocol.md.

The strongest concerns are: (1) the attestation CBOR storage format
for the personal-channel item is not defined anywhere (only a JSON
display form), and (2) the revocation/rotation path §10.1 leaves
paired-device co-rotation, descriptor re-signing, and in-flight item
verification underspecified.

---

## HIGH

### ID-01: Attestation on-disk/wire format not specified

**Spec**: §9.3 Attestation Format (Phase 1 Data Structure), §7.4 Personal Channel

**Issue**: §9.3 shows the operator attestation as a JSON object and
§9.3 "Signing input" specifies RFC 8785 JCS serialisation as the
signing preimage. But §7.4 says attestations are stored in the
personal channel as `item_type = "attestation"`, and ecies-envelope
SS11 item metadata envelopes are CBOR (deterministic, RFC 8949 SS4.2.1).
An engineer cannot tell:

- Is the attestation `content` in the item a UTF-8 JCS-encoded JSON
  string, or a CBOR map?
- If CBOR, what is the field order / key naming (camelCase vs
  snake_case)? The example uses `agent_key`, `operator_key`,
  `issued_at` -- is this authoritative?
- Is the `signature` field removed-then-signed inside the JCS JSON,
  or recomputed by stripping a CBOR map key on verification?
- If the item ships as CBOR but the signing preimage is JCS JSON, the
  verifier must round-trip through JSON -- is that the intended
  implementation? ecies-envelope SS7 (CBOR attestation example at line
  700) shows `operator_attestation` as native CBOR; this conflicts
  with §9.3's JCS-over-JSON story.

**Resolution**: Pick one. Recommendation:
- Define canonical storage as CBOR (deterministic) in item metadata,
  consistent with every other signed Cordelia envelope.
- Publish a CBOR schema (CDDL) for `operator_attestation` alongside
  §9.3, with explicit field ordering rules.
- If JCS is retained for human-portability (e.g., pasteable
  attestations), state it as an alternate encoding for export only
  and define the canonical on-wire form as CBOR.
- Either way, add a test vector (one attestation, one signature)
  similar to ecies-envelope SS8.6.

### ID-02: Compromise-and-rotation path underspecified for Phase 1

**Spec**: §10.1 Compromise Response

**Issue**: The step list is prescriptive but omits several mechanics an
engineer needs:

1. "Re-pair devices" -- the existing `cordelia pair` flow assumes a
   live `identity.key`. After `cordelia init --force`, the old paired
   devices still hold the old seed. How is rotation propagated from
   the rotating device to paired devices? Does each device run
   `cordelia init --force --import-key <new_sk>`? Is there a new
   `cordelia rotate` verb?
2. "For owned channels, the entity must generate new PSKs and
   distribute them" -- PSK rotation on member removal already exists
   (channels-api.md SS3.8 referenced). But who re-signs the
   `ChannelDescriptor`? The old `creator_id` is cryptographically
   bound. §7.1 says "first-seen creator wins; Phase 3 on-chain
   registration resolves disputes" -- which means in Phase 1 the
   rotated identity cannot reclaim channels it created. Is that the
   intended design?
3. Items published under the old key remain valid signatures forever
   (by design -- signatures don't expire). No statement on whether
   the old public key should be added to a "known-rotated" list, or
   whether historical items are simply accepted.
4. DMs: "derive new DM channel IDs" -- but the counterparty still has
   the old DM. There's no protocol notification that Alice's identity
   has rotated; Bob will continue sending to the old DM channel until
   Alice communicates her new key out-of-band.

**Resolution**: Either:
- Add §10.1.1 "Rotation mechanics" specifying: new CLI commands for
  rotation vs. init, paired-device rotation propagation,
  creator-identity limitations (explicit Phase 1 accepted risk), DM
  counterparty notification (out-of-band in Phase 1, via a
  `cordelia:rotation-notice` protocol channel in Phase 3).
- Or drop §10.1 to a forward reference ("revocation deferred to
  Phase 4 per operations.md SS3.3"), keeping only the practical
  advice that Phase 1 rotation requires manual re-establishment.

The current halfway position reads as complete but is not
implementable without design choices.

---

## MEDIUM

### ID-03: Phase 1 deliverables table conflates data-structure and runtime support

**Spec**: §12 Phase Boundaries

**Issue**: Phase 1 row lists: "operator attestation data structure,
`cordelia provision --agent`". §9.4 and ecies-envelope SS14.4 both
mention `cordelia init --name ... --operator <operator_pubkey>` AND
`cordelia provision --agent` as Phase 1 deliverables. But:

- `cordelia provision --agent` does not appear in operations.md
  SS2.4 "Command Summary" (which only lists `init`, `pair`, `join`,
  `start`, `stop`, `status`, `upgrade`).
- No attestation-verification API is defined anywhere. Without it,
  "data structure ships" is a nullable claim -- attestations can be
  written but no code path consumes them.
- §9.3 says "Enforcement ... is Phase 3+". So Phase 1 code merely
  stores a signed blob with no validation semantics.

An engineer would reasonably ask: "do I write the verifier in Phase 1
or not?"

**Resolution**: Narrow the Phase 1 claim:
- Phase 1: write and store attestation items (CBOR envelope + Ed25519
  signature validation against `operator_key`). No policy
  enforcement. No `cordelia provision --agent` unless operations.md
  SS2.4 gains the command. State explicitly that the verifier is
  stored-item-level only (signature valid? yes/no), not an access
  control hook.
- Phase 3: enforcement hooks into channel access policy.

Then reconcile operations.md SS2.4 with whichever subset of
`init --operator` / `provision --agent` Phase 1 actually ships.

### ID-04: Multi-device pairing silent on split-brain

**Spec**: §6 Pairing; §6.5 Device Limit

**Issue**: §6.5 says "no hard limit on paired devices. All share the
same Ed25519 identity." Two concerns the spec does not address:

1. **Concurrent writes**: If Alice pairs phone + laptop, and both
   write to the same channel offline, both items will carry the same
   `author_id` (same key) but distinct `item_id`s. Replication will
   merge them. The spec should either call this out as intentional
   (eventual consistency is the design) or reference the
   conflict-resolution rules (ecies-envelope SS11 `published_at`
   ordering).
2. **Concurrent pairing**: If Alice runs `cordelia pair` on phone
   and `cordelia pair` on laptop simultaneously (both initiate), both
   register pairing codes at the same bootnodes with different codes.
   §6.4 says "Initiator accepts only ONE connection per pairing
   session" -- but there are two concurrent sessions. Is that
   supported? A third device joining either is fine individually;
   both at once is undefined.

**Resolution**: Add a short §6.6 "Concurrency" covering:
- Paired devices are eventually-consistent; conflicts resolved by
  `published_at` timestamp (cross-ref ecies-envelope SS11).
- Concurrent `cordelia pair` on multiple existing devices is
  supported (independent sessions at bootnodes); each produces a
  separate code, each accepts one joiner.

### ID-05: Key display format not consistent across spec references

**Spec**: §11 Bech32 Encoding; §4.2 Node ID; §4.3 Author ID; §9.3

**Issue**: The spec says `cordelia_pk` HRP throughout, and §9.3 adds a
note that the ADR's placeholder `ed25519_pk1` is superseded. But the
ADR text block in §9.3 still shows `cordelia_pk1...` in the JSON
example, and the ADR file on disk (decisions/2026-03-10-...md, lines
47, 66, 132-146) still uses `ed25519_pk1_alice...`,
`ed25519_pk1_agent...`, `ed25519_sig1...`. A reader who follows the
§13 reference to the ADR will find the old HRPs.

Additionally §4.3 specifies three forms (Wire: raw 32 bytes; REST:
Bech32; SDK: Bech32) but:
- channels-api.md SS3.4 responses may include `author` (Bech32), but
  the SDK `sdk-api-reference.md` fields are not re-checked here.
- CLI display truncation rule (`cordelia_pk1abc...xyz`) lives only in
  ecies-envelope SS3.4, not cited in identity.md.

**Resolution**:
- Either update the ADR file to use `cordelia_pk1` (recommended --
  ADRs are typically immutable but a header "HRP updated per spec
  2026-03-12" is acceptable), OR add a bolded warning at §13 that
  the ADR uses obsolete HRPs.
- Cross-reference ecies-envelope SS3.4 (display truncation) from §11.
- Add a one-line table: "Wire / REST / SDK / CLI / Log" key display
  rules consolidated.

### ID-06: Node-token security properties understated

**Spec**: §3.2 Key Storage (row 2); §5.2 REST API Authentication

**Issue**: §3.2 labels the bearer token "LOW -- regeneratable". This
conflates "can be recreated" with "safe to leak". In practice:

- A leaked node-token grants full control over the local node's
  keys, channels, and publish permission (acting as the identity) to
  any process on localhost that can reach 127.0.0.1:9473.
- operations.md SS5.4 explicitly says the token "is equivalent to
  identity possession for API purposes" and must be chmod 0600.
- "Regeneratable" is true but misleading -- the attacker has already
  had identity-level access during the compromise window.

**Resolution**: Change sensitivity label to "HIGH -- equivalent to
identity for local API operations; regenerate-and-invalidate on
suspected compromise". Cross-reference operations.md SS5.4. Keep the
"regeneratable" note as a sub-bullet.

### ID-07: TLS cert rotation and identity.key relationship gap

**Spec**: §3.2, §5.1

**Issue**: §5.1 says certificates are "validity: 1 year, auto-renewed
on startup". §3.2 says `node.key` is "generated from identity.key on
startup". Two open questions:

1. If a node stays up for >1 year, does the cert auto-renew without
   restart? Or is annual restart required? operations.md SS5.4 also
   doesn't cover this.
2. `node.key` is PKCS#8-encoded Ed25519 seed -- it IS the identity
   seed, just re-encoded. If an attacker gets `node.key`, they have
   the identity. §3.2 labels it "LOW -- generated from identity.key"
   which understates risk. Same content, different encoding, same
   compromise outcome.

**Resolution**:
- §5.1: clarify that "auto-renewed on startup" means "regenerated
  from the seed on startup; long-lived processes retain the initial
  certificate until restart". Add: `SIGHUP` may trigger regeneration
  (optional Phase 1, or defer).
- §3.2: upgrade `node.key` sensitivity to "CRITICAL -- contains the
  same Ed25519 seed material as identity.key in PKCS#8 form". The
  public/private boundary is what matters, not the filename.

### ID-08: Agent provisioning CLI contract ambiguous

**Spec**: §9.4 Agent Provisioning

**Issue**: §9.4 presents two commands as equivalent:
- `cordelia init --name "research-agent" --operator <operator_pubkey>`
- `cordelia provision --agent` (per identity ADR SS4)

But:
- `--operator <operator_pubkey>` takes a public key. Who signs the
  attestation? The operator's key (not this node's key). So either
  this command must invoke the operator's node (out-of-band
  process), or the agent creates an unsigned placeholder that the
  operator signs later. Neither is documented.
- ecies-envelope SS14.4 is the canonical reference but also doesn't
  specify the signing workflow.
- "`cordelia provision --agent` is a convenience alias that combines
  init + attestation + channel subscription in one step" -- this
  also requires operator signing, same problem.

**Resolution**: Specify the signing dance explicitly:
- Option A (operator drives): operator runs
  `cordelia attest --agent-key <agent_pk> --purpose ... --expires ...`
  to emit a signed attestation file; agent imports with
  `cordelia init --attestation <file>`. Two-step, clean.
- Option B (agent drives): agent emits a
  `cordelia_attestation_request` file; operator signs with
  `cordelia sign --request <file>` and returns; agent imports.
- Option C (Phase 3, delegated): via a trusted pairing channel.

Pick one for Phase 1. The current spec implies but does not define
any of them.

### ID-09: Coverage gap: CLI identity-display surfaces

**Spec**: §4 Entity Identification

**Issue**: The spec defines Entity ID, Node ID, Author ID but does
not enumerate where each appears. Engineers must cross-check
operations.md SS6 (CLI) and channels-api.md SS3 to build the full
matrix:

- `cordelia status`: entity_id, node_id -- confirmed
- `cordelia peers`: node_id (Bech32), entity_id -- presumed, not
  stated
- `cordelia channels list`: channel_id, creator (Bech32) -- check
- Error messages: "peer rejected: cordelia_pk1..." -- display rule?
- Log lines: peer node_id how formatted?

**Resolution**: Add §4.4 "Display Surfaces" with a one-table
cross-reference:

| Surface | Uses | Format |
|---------|------|--------|
| `cordelia status` | entity_id, node_id | human + Bech32 |
| `cordelia peers` | node_id, entity_id | Bech32 + human |
| REST channels list | author, creator | Bech32 |
| Item metadata wire | author_id, creator_id | raw 32 bytes |
| Logs (INFO) | node_id | Bech32 truncated (first 8 + last 4) |
| Error messages | node_id | Bech32 full |

### ID-10: Phase 2+ content inside Phase 1 spec sections

**Spec**: §2.2, §2.3, §2.4, §7.1 "Phase 3 on-chain registration", §9 ("Phase 1 Data Structure"), §10.3

**Issue**: §4 Design Principles states "Phase 1: Layer 0 only. Layers
1-3 are forward references". But the actual spec body includes:

- §2.2 Layer 1 Profile with a concrete JSON schema (aspirational
  Phase 2)
- §2.3 Layer 2 Verification with a full proof-type table (Phases 1-3)
- §2.4 Layer 3 Reputation (Phase 4)
- §9 Proof of Agency with the full attestation schema (§9.3 claims
  Phase 1 but §9.4 references `cordelia provision --agent` which is
  ambiguous per ID-08)
- §10.3 Future Recovery (Phase 4)

Mixing aspirational and committed content is not fatal (the headings
are labelled) but an implementor scanning for "what must I build" is
misled by the detail level. JSON schemas look implementable, so they
tend to be implemented.

**Resolution**: Two options:
- (Lighter) Add a top-of-section banner to each Layer 1-3 section:
  "NORMATIVE SCOPE: description only. No Phase 1 deliverables."
  Similarly for §10.3.
- (Heavier) Move Layer 1-3 detail to a separate `identity-phase2-4.md`
  forward-looking document; keep identity.md strictly Phase 1.

Recommend option 1 (lighter) for Phase 1 close.

---

## LOW

### ID-11: Terminology: "entity" vs "node" vs "device" not fully disambiguated

**Spec**: §1, §6 Pairing

**Issue**: §1 says "possession of the Ed25519 private key is the sole
proof of identity. Every cryptographic operation ... derives from this
single seed." §6.1 says "All paired devices share the same Ed25519
seed and therefore the same identity. Each device is a full node ..."

Glossary.md defines:
- **Entity**: "A cryptographic identity (Ed25519 public key + optional
  human-readable name). May operate one or more nodes."
- **Node**: "A running Cordelia process..."

But in §6 "device" is introduced as a third term, equivalent to
"node" but not defined in glossary.md.

**Resolution**: Either (a) use "node" consistently in §6 (preferred
-- glossary is authoritative) or (b) add "Device = node instance
operating on distinct hardware; plural nodes of the same entity when
paired" to glossary.md.

### ID-12: "Name validation" regex example conflicts with stated minimum

**Spec**: §4.1 Name validation

**Issue**: The regex `^[a-z][a-z0-9-]{0,30}[a-z0-9]$` permits 2-char
minimum (`a` + `a`). The prose says "2-32 chars, starts with letter,
does not end with hyphen" -- consistent. But channel-naming.md SS2.1
validation regex is `^[a-z][a-z0-9-]{1,61}[a-z0-9]$` (3-63 char).
Entity names and channel names share one flat namespace per identity
ADR SS8 but have different length constraints. Reader surprise.

**Resolution**: Either (a) note that entity-name length differs from
channel-name length deliberately (entity names are CLI-ergonomic, 2
chars OK) with cross-reference to channel-naming.md, or (b) align on
3-63 chars for both.

### ID-13: Reference table missing cross-refs

**Spec**: §13 References

**Issue**: Missing entries a reader would want to follow:
- data-formats.md (item metadata CBOR schema, PSK envelope storage)
  -- attestation storage ultimately lives here
- configuration.md (config.toml `[identity]` section)
- Link to glossary.md "Entity / Node / Peer / Creator / Author" --
  present in §13 but the ADR entry lists SS2/3/4/5/7/8/9 while the
  identity.md text only uses SS2, SS3, SS4, SS5, SS7, SS9

**Resolution**: Add data-formats.md and configuration.md entries.
Drop ADR SS8 reference since it's not cited in the body text (or cite
it for §7.1's on-chain registration forward ref).

### ID-14: Missing "what happens at `init --force`" state diagram

**Spec**: §10.1 step 1 (`cordelia init --force`); operations.md SS2.3

**Issue**: operations.md SS2.3 briefly covers `--force` but identity.md
§10.1 invokes it as the rotation mechanism without specifying side
effects:

- Does existing `channel-keys/*.key` survive, or is it wiped?
  (Compromise response says wipe; clean-slate reinit may not.)
- Does the database survive?
- Is `node-token` regenerated?
- Are paired devices notified? (See ID-02 #1.)

**Resolution**: Either (a) add a 4-line state delta in §10.1 ("After
--force: new identity.key, new node-token, channel-keys preserved if
any, cordelia.db preserved, paired devices not notified"), or (b)
cross-ref a new operations.md SS2.3.1 "Force re-init semantics".

---

## Passes Not Applied (this session)

| Pass | Reason |
|------|--------|
| 6 (Privacy) | Covered by identity-privacy-model ADR §9 and §8 of this spec (consolidation of that ADR). Re-running would duplicate findings. |
| 10 (Metadata privacy), 11 (Operational), 12 (Error catalog) | Out of scope for identity spec -- handled in dedicated review docs. |

---

## Recommended Triage

**Fix before Phase 1 close (blocking):** ID-01, ID-02. Attestation
format and rotation mechanics are both under-specified to a degree
that different implementors would produce incompatible behaviours.

**Fix during Phase 1 close window (doc debt):** ID-03, ID-04, ID-05,
ID-07, ID-08. Each resolvable in <1 hour edit; collectively they
tighten the Phase 1 boundary.

**Defer / close:** ID-06 (relabel), ID-09 (nice-to-have table),
ID-10 (cosmetic banner), ID-11 (glossary hygiene), ID-12
(cross-spec note), ID-13, ID-14.

---

## Cross-Spec Backports Suggested

- **ecies-envelope-encryption.md**: §7 / §14.4 -- reconcile CBOR
  attestation form (line 700) with identity.md §9.3 JCS signing
  input.
- **operations.md SS2.3 / SS2.4**: clarify `--force` side effects and
  whether `cordelia provision --agent` ships in Phase 1.
- **decisions/2026-03-10-identity-privacy-model.md**: add a footer
  note that HRP `ed25519_pk1` in the ADR is obsolete; canonical HRP
  is `cordelia_pk1` per identity.md §11 and ecies-envelope SS3.
- **glossary.md**: add "Device" or constrain identity.md to use
  "node".

---

*Review complete 2026-04-17. 13 findings. 0 CRITICAL / 2 HIGH / 7 MEDIUM / 4 LOW.*
