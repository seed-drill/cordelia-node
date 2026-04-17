# Review: search-indexing.md

> Fresh review pass applying review-spec methodology to
> `search-indexing.md` (Draft 2026-03-12, 874 lines). Documentation
> due-diligence before closing Phase 1. Search-spec-specific passes
> added: shipped-feature verification, privacy/leakage audit, and
> migration-vs-schema consistency.

## Application Record

| Field | Value |
|-------|-------|
| Date | 2026-04-17 |
| Reviewer | Russell Wing + Claude Opus 4.7 |
| Spec | search-indexing.md (Draft 2026-03-12) |
| Passes applied | 1 (Gaps), 2 (Consistency), 3 (Clarity), 4 (Implementability), 5 (Coverage), 6 (Cross-reference integrity) + shipped-feature check, privacy audit |
| Code cross-checked | `crates/cordelia-storage/src/{schema.rs, search.rs}`, `crates/cordelia-api/src/handlers.rs` (search_handler @ L1015), `crates/cordelia-core/src/config.rs` (via prior CF-01 finding) |
| Reference specs | data-formats.md, channels-api.md, memory-model.md, configuration.md, network-protocol.md, ecies-envelope-encryption.md |
| Prior reviews cross-checked | review-configuration-2026-04-17.md (CF-01 — `[search]` section absent from Config struct), review-data-formats-2026-04-17.md (DF-01 — scope column), review-memory-model-2026-04-17.md |

---

## Summary

**19 findings: 3 CRITICAL, 6 HIGH, 7 MEDIUM, 3 LOW.**

search-indexing.md is the most divergent spec reviewed in this wave
because it describes, in full implementation detail, an entire
subsystem (semantic search, embedding pipeline, Ollama integration,
sqlite-vec, backfill MCP tool, reindex endpoint, index state
monitoring) that **was not built in Phase 1**. The shipping code
provides FTS5 keyword search only. The API handler hard-codes
`semantic_available: false` with a `// Phase 2` comment; no
`sqlite-vec` / `ollama` / embedding code exists anywhere in the
workspace; and no configuration surface for `[search]` is present
in `Config` (per CF-01).

The two material categories:

1. **Unshipped-feature drift.** §2.3 (vec table), §2.4 (embedding
   meta), §2.5 (index state), §3.2 (embedding pipeline), §3.3
   (reindex), §3.4 (backfill tool), §4.2 (semantic query), §4.3
   (hybrid scoring), §7 (all five `[search]` parameters) describe
   code that does not exist. Phase 1 scope in §8.1 lists these as
   "Delivered" — they are not.
2. **Schema promised vs schema shipped.** Migration v2 in
   `schema.rs` ships `search_content`, `search_fts`, and the three
   triggers. It does not ship `search_vec_map`, `search_vec`,
   `search_embedding_meta`, or `search_index_state`. The `VACUUM
   rebuild` clause (§2.2), status-transition diagram (§2.4), and
   `last_indexed_item_id` resumption (§3.1 Crash recovery, §3.3)
   reference state that has no backing table.

Top-line fix before Phase 1 close: re-scope §8.1 to reflect what
actually shipped (FTS5 only; tombstone handling; query sanitisation;
channel scoping), move §2.3-§2.5, §3.2-§3.4, §4.2-§4.3, §7 under
"Phase 2 — Deferred", and add a §1 banner that makes the Phase 1
surface unambiguous. This spec currently cannot be handed to a new
implementor.

Secondary: the privacy audit finds an unaddressed **backup/export
leakage** vector (SI-09): `search_content` is plaintext, and the
spec does not call out that any backup of `cordelia.db` exports
decrypted content of every subscribed channel in a form an attacker
can read without any PSK.

---

## CRITICAL

### SI-01: §8.1 Phase 1 "Delivered" list is factually incorrect

**Spec**: §8.1 lines 737-750.

**Issue**: The "Delivered" bullet list includes:
- "sqlite-vec semantic search with nomic-embed-text-v1.5 via local Ollama"
- "Dominant-signal hybrid scoring (configurable weight)"
- "Asynchronous embedding generation with in-process queue"
- "Graceful degradation to FTS5-only when Ollama is unavailable"
- "`memory_backfill_embeddings` MCP tool for embedding repair"
- "`search_index_state` table for index health monitoring"

None of these are present in the shipped code:
- `crates/cordelia-storage/src/schema.rs` SCHEMA_VERSION=3 ships
  only `search_content`, `search_fts`, and the three FTS5 triggers
  (migration v2). No `search_vec_map`, no `search_vec`, no
  `search_embedding_meta`, no `search_index_state`.
- `crates/cordelia-api/src/handlers.rs:1111` hard-codes
  `semantic_available: false, // Phase 2`.
- Grep across the workspace for `sqlite_vec|sqlite-vec|vec0|ollama|
  nomic|dominant_weight|semantic|embedding` returns zero hits in
  `crates/cordelia-storage` and only the "Phase 2" literal string in
  `crates/cordelia-api`.
- No `memory_backfill_embeddings` MCP tool exists in the repo (grep
  returns only this spec, memory-model.md, and the memory-model
  review).

This is the single biggest correctness gap in the whole spec sweep.
An implementor reading §8.1 would believe the subsystem is done.

**Resolution**:

1. Rewrite §8.1 "Delivered" to exactly this set (verified against
   code):
   - FTS5 full-text search with BM25 scoring
   - Channel-scoped queries (mandatory `channel_id`)
   - Query sanitization (length 200, terms 20, prefix ≥3, balanced
     quotes/parens)
   - Tombstone exclusion via `is_tombstone` flag on
     `search_content` (note: shipped code uses an `UPDATE ... SET
     is_tombstone = 1` path, NOT the §3.5 DELETE path — see SI-04)
   - Per-result BM25 normalisation (divide by best raw score)
   - Over-fetching `limit * 3` when filters are active
2. Move the other bullets into §8.2 Phase 2.
3. Add a `Status` line to the spec frontmatter:
   `Phase 1 delivered: FTS5 keyword only. Semantic search + hybrid
   scoring + embedding pipeline: Phase 2.`

### SI-02: `[search]` configuration section documented but not wired

**Spec**: §7 lines 691-730.

**Issue**: §7 documents five `[search]` parameters with defaults,
ranges, and startup-validation behaviour:

```
dominant_weight, embedding_model, ollama_url,
embedding_enabled, embedding_queue_size
```

Per review-configuration-2026-04-17.md CF-01, none of these are
fields on the shipped `Config` struct in
`crates/cordelia-core/src/config.rs`. A node will silently ignore
a `[search]` block in `config.toml`; the startup-validation
paragraph ("`dominant_weight` outside `[0.5, 0.9]`: node logs an
error and refuses to start") is false — there is no parser and no
validator.

This aggravates SI-01: an operator who reads this spec, writes a
production config.toml with `embedding_enabled = false` for an
air-gapped box, will get no enforcement of that setting because the
code has no knowledge of it. Today, search is FTS5-only regardless.

**Resolution**:

1. Delete §7's full parameter table and defaults block for Phase 1.
   Replace with a stub: "Phase 1 ships FTS5-only search with no
   runtime configuration surface. The `[search]` section is
   introduced in Phase 2 alongside the semantic/embedding
   subsystem. See §8.2 and `configuration.md` §2.8 (pending
   de-scope per CF-01)."
2. Move the full §7 parameter table verbatim into §8.2 under a new
   sub-heading "Configuration (Phase 2 addition)".
3. Cross-reference from configuration.md §2.8 to this re-scoped
   section so the two specs tell the same story.

### SI-03: Schema tables referenced by prose but not in migration v2

**Spec**: §2.3 (`search_vec_map`, `search_vec`), §2.4
(`search_embedding_meta`), §2.5 (`search_index_state`).

**Issue**: `schema.rs` migration v2 creates exactly three objects:
`search_content` (table), `search_fts` (FTS5 virtual table), and
the insert/delete/update triggers on `search_content`. None of the
other four tables described in §2 exist in the shipped database.

Downstream consequences inside the spec itself:
- §2.2 "VACUUM and rebuild" instructs
  `INSERT INTO search_fts(search_fts) VALUES('rebuild')` — fine, but
  the surrounding §2.5 state table it cross-references does not
  exist to coordinate that rebuild.
- §3.1 step 6 "Update `search_index_state.total_indexed` for the
  channel" — no-op, table missing.
- §3.1 "Crash recovery" relies on `search_index_state.
  last_indexed_item_id` to bound the recovery scan — no-op.
- §3.2 pipeline stores rows in `search_embedding_meta` and
  `search_vec` — no-op.
- §3.3 rebuild process step 5 resets `search_index_state` — no-op.
- §6.5 Index Health Monitoring queries three fields on
  `search_index_state` — no-op.

A downstream reader cannot tell which tables exist and which are
future work.

**Resolution**:

1. Annotate each §2 subsection with a `**Phase**:` line:
   - §2.1 Items (reference only) → data-formats.md
   - §2.2 FTS5 → **Phase 1**
   - §2.3 Vector → **Phase 2**
   - §2.4 Embedding meta → **Phase 2**
   - §2.5 Index state → **Phase 2** (or push to Phase 3 if
     operators don't need it until semantic ships)
2. Add a §2.0 "Shipped schema summary" table:

   | Table | Migration | Status |
   |-------|-----------|--------|
   | `search_content` | v2 | Phase 1 shipped |
   | `search_fts` (virtual) | v2 | Phase 1 shipped |
   | FTS5 triggers (3) | v2 | Phase 1 shipped |
   | `search_vec_map` | (Phase 2) | Not shipped |
   | `search_vec` (vec0) | (Phase 2) | Not shipped |
   | `search_embedding_meta` | (Phase 2) | Not shipped |
   | `search_index_state` | (Phase 2) | Not shipped |

3. Update data-formats.md §5.3 cross-reference (it currently claims
   "search tables §2.2-§2.6" are part of Migration v1; see also
   DF-01 and SI-17 below).

---

## HIGH

### SI-04: Tombstone path in spec doesn't match shipped code

**Spec**: §3.5 line 376-382.

**Issue**: §3.5 specifies a hard DELETE:
> "1. Delete the row from `search_content` WHERE `item_id = ?`
> (triggers FTS5 delete via trigger) ..."

Shipped code (`crates/cordelia-storage/src/search.rs:122
tombstone_search`) does an UPDATE:

```rust
conn.execute("UPDATE search_content SET is_tombstone = 1
              WHERE item_id = ?1", ...);
```

And the search query filters `AND sc.is_tombstone = 0`. This is a
deliberate soft-delete approach (matches `items.is_tombstone` on
the main table), and it's arguably correct — it preserves audit /
undelete capability. But it **contradicts** the spec's DELETE path,
which the spec also calls an "Invariant" ("the delete from
`search_content` ensures FTS5 will never match").

Additionally: the soft-delete approach leaves plaintext in
`search_content` after tombstoning, which changes the privacy
surface — see SI-10.

**Resolution**: Rewrite §3.5 to match shipped behaviour (soft
delete via `is_tombstone`), and explicitly reconcile with the
`items.is_tombstone` pattern documented in data-formats.md §3.4.
If the DELETE variant is preferred, open a code-change issue; do
not silently leave the spec forked.

### SI-05: `review-privacy.md` referenced but not present

**Spec**: §5 line 587.

**Issue**: "This section consolidates the privacy constraints from
memory-model.md S11.2 and review-privacy.md." Glob shows
`docs/specs/review-privacy.md` does exist, but the reference style
is unusual for a spec (most `docs/specs/review-*.md` are review
artefacts, not normative sources). If the intent is to treat
review-privacy.md as normative, §5 should quote or link the exact
constraints. Otherwise remove the reference.

**Resolution**: Either (a) inline the specific constraints being
consolidated with explicit citation to review-privacy.md section
numbers, or (b) remove the citation since review artefacts aren't
typically cited as normative.

### SI-06: `dominant_weight` range conflict between memory-model.md and this spec

**Spec**: §4.3 line 488-489 — "Default `dominant_weight`: 0.7
(configurable via `config.toml [search] dominant_weight`, valid
range 0.5-0.9)".

**Issue**: memory-model.md §7.1 (line 425) refers the tuning to
"`cordelia-proxy/SEARCH.md` for tuning rationale". That document
lives outside this repo (the proxy is deprecated — see CLAUDE.md
"Portal: Deprecated from critical path"). §7.1 of this spec also
documents the range but the source of truth is an external file
in a deprecated subsystem.

**Resolution**: Copy the tuning rationale into §4.3 of this spec
(or a new §4.3.1 "Tuning the dominant_weight parameter"), and drop
the `cordelia-proxy/SEARCH.md` cross-reference from memory-model.md
§7.1. Proxy is not in Phase 1 scope.

### SI-07: `channels-api.md §3.13` membership check — spec vs implementation mismatch

**Spec**: §5.4 Cross-Channel Isolation, §4.4 Channel Scoping.

**Issue**: The spec asserts the channel scope is enforced at two
levels: API (channel parameter required) and Query (SQL
`channel_id = ?`). The shipped handler adds a third check the spec
doesn't mention: membership verification.

`handlers.rs:1034`: `if !channels::is_member(&db, &channel_id.0,
&pk)? { return Err(ApiError::Forbidden("not a member of this
channel".into())); }`

This is the right behaviour — without it, an authed caller could
search any channel whose items happened to be indexed in the local
DB (e.g., a relay's incidentally-indexed content, or a prior
membership) — but the spec doesn't require or describe it. The
privacy argument in §5.1 implicitly assumes the caller IS a
legitimate subscriber; it does not say how that's verified.

**Resolution**: Add §5.4.1 "Membership verification":
> "Before executing the query, the search endpoint MUST verify the
> caller is an active member of the target channel (via
> `channel_members` where `entity_key = caller_pk` and
> `posture = 'active'`). A caller who holds the bearer token but
> is not a channel member receives `403 forbidden`. Historic
> members (posture = 'removed') are denied."

### SI-08: `pending_index` set — implementation-defined, spec defines it

**Spec**: §3.1 Deferred indexing (lines 261-268), Crash recovery
(lines 268).

**Issue**: The spec describes an "in-memory, keyed by channel_id"
`pending_index` set, and says "On startup, the node MUST scan for
items in channels where the PSK is now held but no corresponding
`search_content` row exists." This is a concrete in-memory data
structure and a non-trivial startup-scan algorithm. It is not
implemented (no `pending_index` symbol anywhere in the workspace).

Separately: the recovery scan bound (`search_index_state.
last_indexed_item_id`) is, per SI-03, not a shipped column.

**Resolution**: Either strip §3.1 Deferred indexing down to "Items
received before their channel PSK is available are stored
encrypted and are indexed opportunistically when the PSK arrives
(mechanism: Phase 2)", or implement the described set + recovery
and add tests. Keeping the current prose invites a future
implementor to write code against a non-existent contract.

### SI-09: Backup/export leakage — unaddressed privacy vector

**Spec**: §5.1 Trust Boundary, §5.2 Database File Permissions.

**Issue**: §5.2 addresses filesystem permissions (0600). §5.1
enumerates "Local filesystem (mode 0600 on cordelia.db)" as an
observer. Neither addresses **backups, exports, or file copies**,
which is the most common real-world leak vector:

- operations.md/ops describes SQLite backup flows (`VACUUM INTO`,
  online backup API, file snapshots).
- `search_content.name`, `summary`, `content_text`, `tags_text`
  are cleartext — a backup file has **no encryption** between an
  attacker and the entire decrypted history of every subscribed
  channel.
- By contrast, `items.encrypted_blob` in a backup is useless
  without the PSK ring; the PSK ring is in
  `~/.cordelia/channel-keys/` with separate 0600 protection.
- The search index, by design, collapses this defence: a stolen
  DB file is equivalent to a stolen plaintext archive for search
  purposes, even without the PSK files.

This is arguably the central privacy trade-off of local-only
search, and the spec doesn't call it out.

**Resolution**: Add §5.2.1 "Backup and export considerations":
> "The FTS5 index contains plaintext text fields
> (`search_content.{name, summary, content_text, tags_text}`). A
> copy of `cordelia.db` — whether a deliberate backup, an
> inadvertent sync to cloud storage, or a compromised host — is
> equivalent to a decrypted archive of every subscribed channel's
> searchable content, independent of whether the attacker
> possesses the PSK ring.
>
> Operators who back up `cordelia.db` SHOULD either (a) exclude
> the `search_content` and `search_fts` objects from the backup
> (see operations.md §10.x), or (b) encrypt the backup file at
> the OS/tooling layer (LUKS, FileVault, `age`, `restic`).
> Phase 2 evaluates an opt-in `[search] encrypted_index_at_rest`
> mode that encrypts text fields with a key derived from the
> personal PSK."

### SI-10: Post-tombstone plaintext retention

**Spec**: §3.5 Tombstone Handling, §5.1 Trust Boundary.

**Issue**: Related to SI-04. The shipped soft-delete approach
leaves `search_content.{name, summary, content_text, tags_text}`
populated after tombstoning — the row stays, only
`is_tombstone = 1` is set. This means a user who "deletes" an item
still has the item's plaintext in their local DB forever (until
VACUUM on a hard delete, which isn't scheduled). §5.6 discusses
PSK rotation impact but not deletion impact.

This contradicts the privacy expectation most users will have
when they delete a message.

**Resolution**: Either:
(a) Change the code to hard-DELETE the `search_content` row on
tombstone (matching current spec §3.5); or
(b) Document the retention in §5 and add a §5.7 "Tombstone
plaintext lifecycle" with operator guidance (e.g., "to purge
plaintext on tombstone, run `DELETE FROM search_content WHERE
is_tombstone = 1; INSERT INTO search_fts(search_fts)
VALUES('rebuild');`")

I recommend (a) — it aligns with user intent and the current spec
wording. If (b), this is a HIGH policy divergence to track.

---

## MEDIUM

### SI-11: `cordelia-proxy/SEARCH.md` reference is dangling

**Spec**: (cross-reference inherited from memory-model.md).

**Issue**: The spec relies on memory-model.md §7.1 pointing to
`cordelia-proxy/SEARCH.md` for tuning rationale. Proxy is archived
(CLAUDE.md: "cordelia-core: ARCHIVED on GitHub ... Do not use" —
same treatment applies to proxy per Phase 1 de-scope). This
document has no in-repo successor.

**Resolution**: Inline the rationale (see SI-06), or explicitly
mark as Phase 2.

### SI-12: "S5.3" style section references use mixed punctuation

**Spec**: §3.1 line 244 — "per ecies-envelope-encryption.md S5.3";
multiple "§X.Y" elsewhere.

**Issue**: Two styles coexist: `S5.3` (no section mark) and `§5.3`
(with section mark). Grep confirms `ecies-envelope-encryption.md`
doesn't carry the `S5.3` notation — the convention elsewhere in
the repo is `§5.3`.

**Resolution**: Global replace `S<n>` → `§<n>` for all cross-refs;
verify every target section number resolves.

### SI-13: `key_version` omitted from tombstone / index flow

**Spec**: §3.1 Write-Time Indexing, §5.6 PSK Rotation Impact.

**Issue**: `items.key_version` exists on every item and differs
between pre-rotation and post-rotation items. §3.1 extracts
plaintext via "channel PSK (per ecies-envelope-encryption.md
S5.3)" but doesn't state which PSK version. If a node is indexing
a mix of items across a rotation, it needs the key ring at the
right version. §5.6 handwaves — "items encrypted with the old PSK
that the node has already decrypted and indexed are unaffected"
(true, because they're plaintext in `search_content`) — but
doesn't close the loop: what happens when the node only later
receives pre-rotation items (e.g., from a slow peer)? Does it
still hold the old PSK? Per ecies spec §6.3 the key ring retains
old versions, so yes, but this spec should say so.

**Resolution**: Add to §3.1: "The node selects the PSK matching
`items.key_version`. The key ring retains all historical versions
(ecies-envelope-encryption.md §6.3), so items from any prior
rotation epoch can be decrypted and indexed at any time."

### SI-14: Memory channel (`__personal`) singularity assumption

**Spec**: §5.5 Index Content Sensitivity (lines 619-624).

**Issue**: §5.5 talks about "memory channels (`__personal`)"
(plural). There is exactly one personal channel per node —
memory-model.md §5.1. Phrasing implies there could be several.

**Resolution**: "the personal channel (`__personal`)" — singular.

### SI-15: Embedding queue semantics vs backpressure contradicted

**Spec**: §3.2 (queue full drops silently, Phase 1 behaviour); §6.4
(Embedding Queue Backpressure — "new embedding requests are
silently dropped", warning logged); §3.4 Backfill Tool ("Failed
embeddings are retried by the backfill tool").

**Issue**: §3.2 says "new embedding requests are dropped" and the
`search_embedding_meta` row stays at `status = "pending"`. §6.4
says the same but phrases the row outcome slightly differently.
The spec also says "Failed embeddings are retried" (§3.2) but the
dropped-from-queue case produces a `pending` row, not a `failed`
row — so whether backfill picks it up depends on its WHERE clause.
§3.4 step 1: "`status IN ('pending', 'failed', 'stale')`" — OK,
that does cover it. But then the spec's Error Handling table
(§3.2) marks connection refused as `status = "failed"`, queue-full
as `status = "pending"`. These are both "error" from the operator's
perspective but get different statuses.

This is internally consistent if read carefully, but an implementor
will likely unify the two paths by accident.

**Resolution**: Add a status-transition bullet for the queue-full
case: "Queue full → no status change (remains 'pending'). Distinct
from Ollama failure (`failed`). Both are picked up by backfill."
Defer to Phase 2 anyway per SI-01.

### SI-16: `unicode61` tokenizer — case folding claim unverified

**Spec**: §2.2 Tokenizer choice (line 149).

**Issue**: "`unicode61` ... handles Unicode properly (case folding,
diacritics removal)". SQLite's unicode61 does case-fold and,
optionally, remove diacritics — but diacritic removal is controlled
by the `remove_diacritics` option (default `1` in SQLite 3.27+,
`0` before). Shipped code (`schema.rs:100-108`) creates the FTS5
table with `tokenize = 'unicode61'` — no explicit
`remove_diacritics` setting, so relies on the SQLite version's
default. The `rusqlite` / `sqlite3` version bundled is not pinned
in this spec.

**Resolution**: Either (a) pin behaviour: `tokenize = 'unicode61
remove_diacritics 2'` (Unicode 9+ diacritic stripping) and update
`schema.rs`, or (b) document the SQLite-version dependency and
test for it at startup.

### SI-17: "§2.2-§2.6" reference in data-formats.md §5.3 is stale

**Spec**: data-formats.md §5.3 says "[DDL as defined in
search-indexing.md §2.2-§2.6]". This spec only has §2.1-§2.5 (no
§2.6). Cross-reference to non-existent subsection.

**Resolution**: Data-formats.md §5.3 should say "§2.2-§2.5", and
should further be corrected per SI-03 to state that only §2.2 is
migrated in Phase 1 (migration v2 in `schema.rs`), with §2.3-§2.5
deferred to Phase 2.

---

## LOW

### SI-18: Frontmatter author model version stale

**Spec**: Frontmatter line 4 — "Claude (Opus 4.6)".

**Issue**: Current model tag is Opus 4.7 (per CLAUDE.md env and
co-author convention). Existing 2026-04-17 review artefacts use
Opus 4.7. Cosmetic but breaks co-author consistency when the spec
is next revised.

**Resolution**: On next edit, bump to "Claude (Opus 4.7)".

### SI-19: §9 Test Vectors lack input format for normalisation

**Spec**: §9.1-§9.3.

**Issue**: Test vectors are useful but §9.1 gives "raw" BM25
scores without specifying the query / corpus that produced them.
Cross-implementation testing requires reproducible inputs. §9.2
similarly — three cosine distances with no source vectors.

**Resolution**: If Phase 1 plan is to keep this spec authoritative
for an eventual SDK-in-other-language, add: "input corpus: the
three items in §T1 (appendix)" or similar, with the CBOR /
JSON + embedding vectors. Otherwise downgrade §9 to "worked
examples" rather than "test vectors".

### SI-20: §8.2 "Cloud embedding API fallback" — scope creep for Phase 2

**Spec**: §8.2 line 762.

**Issue**: "Cloud embedding API fallback ... query text is sent to
the cloud provider. Must be opt-in." The Cordelia positioning
(encrypted pub/sub, edge-only) makes a cloud-embedding fallback a
load-bearing privacy decision, not a Phase 2 implementation detail.
This one-liner undersells the trade-off.

**Resolution**: Either (a) expand into a full paragraph in §8.2
with explicit threat model deltas (Anthropic/OpenAI now see query
text, one-way embedding reveals some semantics), or (b) push to
Phase 5 Enterprise with "opt-in for self-hosted paid-tier
enterprise deployments only". Do not leave as a single bullet in
Phase 2.

---

## Cross-reference audit

| Reference | Status |
|-----------|--------|
| specs/channels-api.md §3.13 | OK (exists line 785) |
| specs/memory-model.md §7.1 | OK (exists line 409); but cites external cordelia-proxy/SEARCH.md (SI-06, SI-11) |
| specs/memory-model.md §7.2 | OK (Phase 2 content) |
| specs/memory-model.md S11.2 | OK (§11.2 exists line 675) |
| specs/ecies-envelope-encryption.md S5.3 | Notation mismatch (SI-12); target section verified exists |
| specs/ecies-envelope-encryption.md §4.4 | OK |
| specs/ecies-envelope-encryption.md §4.2 | OK |
| specs/ecies-envelope-encryption.md §4.3 | OK |
| specs/ecies-envelope-encryption.md §6.3 | OK (key ring retention) |
| specs/ecies-envelope-encryption.md §11.7 | Verify (metadata envelope CBOR) |
| specs/channel-naming.md | Implicitly used (channel_id derivation) |
| specs/network-protocol.md §4.4.6 | OK (ChannelDescriptor) |
| specs/operations.md S2.3 | Exists per cross-reference |
| specs/configuration.md §5.2 | Pending — CF-01 flags the whole [search] section as stale |
| specs/data-formats.md §5.3 | §2.6 citation is off-by-one (SI-17) |
| review-privacy.md | File exists but citation style mismatch (SI-05) |
| cordelia-proxy/SEARCH.md | Dangling (SI-11) — proxy archived |

---

## Recommended action queue (Phase 1 close)

1. **SI-01** Rewrite §8.1 to match shipped reality. (60 min)
2. **SI-02** De-scope §7 `[search]` config to Phase 2. (30 min)
3. **SI-03** Annotate §2 subsections with Phase 1/Phase 2 status,
   add §2.0 shipped-schema table. (30 min)
4. **SI-04** Reconcile §3.5 tombstone path with shipped soft-delete.
   (20 min)
5. **SI-09** Add §5.2.1 backup/export leakage warning. (20 min)
6. **SI-10** Decide on tombstone plaintext retention (hard-delete
   vs. documented retention + operator tooling). (design decision)
7. **SI-17** Fix data-formats.md §5.3 off-by-one and Phase scoping.
   (10 min — edit in data-formats.md, not this spec)
8. Remaining HIGH items per priority.
9. MEDIUM / LOW items in a single cleanup pass.

---

*Review date: 2026-04-17. Reviewer: Russell Wing + Claude Opus 4.7.
Methodology: docs/specs/review-methodology.md v1.6.*
