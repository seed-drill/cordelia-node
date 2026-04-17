# Review: data-formats.md

> Fresh review pass applying review-spec methodology to
> `data-formats.md` (Draft 2026-03-12, 419 lines). Documentation
> due-diligence before closing Phase 1.

## Application Record

| Field | Value |
|-------|-------|
| Date | 2026-04-17 |
| Reviewer | Russell Wing + Claude Opus 4.7 |
| Spec | data-formats.md (Draft 2026-03-12) |
| Passes applied | 1 (Gaps), 2 (Consistency), 3 (Clarity), 4 (Implementability), 5 (Coverage), 8 (Cross-language) |
| Build-verification cross-check | BV-21 relay auto-creation verified present (§3.1) |

---

## Summary

18 findings. 1 CRITICAL (schema drift: `scope` column absent from
spec but shipping in v3 migration), 6 HIGH (column-to-API mapping
gaps, missing channel_members DDL details, PSK ring<->DB reconciliation
underspecified, CBOR field tag rules absent, items column missing
from mapping, FK index gap), 8 MEDIUM (nullability defaults, migration
versioning semantics, updated_at trigger absence, content_hash
domain, peer/seen_table storage out of scope unacknowledged,
content_length vs wire clarification, `entity_key` vs `entity_id`
terminology, channel_members timestamp column missing), 3 LOW
(reference polish).

The spec is solid at Phase 1 scope -- BV-21's fix landed correctly.
The most material gap is that Migration v3 (`scope TEXT NOT NULL
DEFAULT 'network'`, shipped for PAN) never made it back into the
spec. This is the same "spec before code" concern raised in
feedback_spec_before_code.md.

---

## CRITICAL

### DF-01: Migration v3 `scope` column shipped but not documented

**Spec**: §3.1 channels DDL, §5.3 Migration v1

**Issue**: `crates/cordelia-storage/src/schema.rs` ships
`SCHEMA_VERSION = 3` with migration v3:

```sql
ALTER TABLE channels ADD COLUMN scope TEXT NOT NULL DEFAULT 'network'
    CHECK(scope IN ('network', 'local'));
```

None of this appears in data-formats.md:
- No `scope` column in §3.1 DDL
- No CHECK constraint documented
- No §5 migration entry between v1 and "future" (the spec only
  defines v1)
- No mention of PAN local channels (which consume this column)

An implementor reading data-formats.md today would write code that
can't store a PAN channel. The code has diverged from spec.

Aggravating: §5.4 says "Phase 1 migrations are additive ... No
column drops, no type changes, no destructive ALTER TABLE. This
ensures forward-compatibility for rollback." Migration v3 IS
additive (satisfies the rule) but was never documented.

**Resolution**:
1. Add `scope TEXT NOT NULL DEFAULT 'network'` column with CHECK
   constraint to §3.1 DDL.
2. Add note: "Added in migration v3 (2026-03-xx). Enables PAN
   ephemeral local channels (see PAN design note)."
3. Add §5.5 Migration v2 (search-indexing.md §2) and §5.6
   Migration v3 (scope column) subsections.
4. Update §2 `PRAGMA user_version = 3` or parameterise the text.
5. Update the §3.1 "Relay auto-creation" INSERT to include
   `scope` (or rely on DEFAULT 'network' explicitly -- document
   the choice).

---

## HIGH

### DF-02: Missing column-to-API mapping for channel_members

**Spec**: §6 Column-to-API Field Mapping

**Issue**: §6 provides tables for `items` (§6.1) and `channels` (§6.2)
but omits `channel_members`. The channels-api.md list-dms/list-groups
endpoints and membership queries need to round-trip through this
table. An implementor cannot trace `member_count` (§3.4.2 response)
or `peer` (§3.4.1 response) to a column without this mapping.

Specifically missing:
- `entity_key` BLOB -> `peer` (Bech32) or `members[].key` field
- `role` -> API response (not currently exposed -- note that)
- `posture` -> filter (`WHERE posture = 'active'`)
- `joined_at`/`removed_at` -> not exposed (note that)

**Resolution**: Add §6.3 channel_members table with mappings. For
columns not exposed, state "Internal only" explicitly so reviewers
don't hunt for API wiring.

### DF-03: `entity_key` vs `entity_id` terminology drift

**Spec**: §3.2 DDL (column `entity_key`); identity.md §4.1
(concept `entity_id`); schema.rs test code uses `entity_id`

**Issue**: The channel_members PK column is `entity_key` (BLOB, 32
bytes -- the raw Ed25519 public key). identity.md §4.1 defines
`entity_id` as a DIFFERENT concept (a human-readable `name_xxxx`
label derived from the hash prefix of the public key). The DDL
column is keyed on the raw public key but named using the word
"entity" that the glossary/identity spec reserves for the label form.

A reviewer (and at least one test at `schema.rs:267`) has already
confused these -- the test uses column name `entity_id` which
doesn't exist and is masked by `result.is_err()` asserting the
wrong failure.

**Resolution**: Either (a) rename the column to `entity_pk` (matches
creator_id/author_id conventions -- all BLOBs of raw Ed25519 pks),
accepting migration cost, or (b) add an explicit note to §3.2 that
"entity_key in this table is the raw 32-byte Ed25519 public key,
NOT the `entity_id` label defined in identity.md §4.1. The column
name is historical." Option (a) preferred if schema migration is
cheap; option (b) acceptable as doc-only fix.

### DF-04: channel_members missing `updated_at` / last-role-change timestamp

**Spec**: §3.2 channel_members

**Issue**: `joined_at` is captured, `removed_at` is captured, but
role changes (`owner` -> `admin` -> `member`) have no timestamp.
channels-api.md permits the owner to change role -- without a
timestamp, audit and conflict resolution during replication have
nothing to compare. Implementation at `channels.rs:465` uses
`ON CONFLICT ... DO UPDATE` but does not update a timestamp.

**Resolution**: Either add `role_changed_at TEXT` with DEFAULT
equal to `joined_at`, or document that role changes are not
timestamped in Phase 1 (accepted risk for Phase 2 conflict
resolution).

### DF-05: PSK ring file <-> channel_keys table reconciliation underspecified

**Spec**: §3.3 channel_keys; cross-ref to ECIES §6.3, §6.4

**Issue**: Three stores exist for PSK material:
1. `~/.cordelia/channel-keys/<channel_id>.key` (current PSK, raw
   bytes, ECIES §6.3)
2. `~/.cordelia/channel-keys/<channel_id>.ring.json` (historical
   PSKs, ECIES §6.4)
3. `channel_keys` SQLite table (encrypted current PSK, data-formats §3.3)

§3.3 says "On startup, the node reconciles: if a `.key` file is
missing but a `channel_keys` row exists, decrypt and restore the
file. If a `.key` file exists but no row, encrypt and insert."

Unspecified:
- Which wins on conflict (file present + row present, different
  contents)?
- Does `channel_keys` store historical versions or only current?
  The column `key_version` suggests current only, but then what
  handles ring recovery if `.ring.json` is deleted?
- Is `.ring.json` ever reconciled with DB? If not, ring loss is
  permanent.
- The ring file has a richer schema (retired_at, created_at per
  version). The DB stores only one version. Does rotation
  over-write the row?

**Resolution**: Add §3.3.1 Reconciliation Rules table:
- Normal case: .key file is authoritative at runtime; DB is
  recovery-only.
- Conflict (mismatch): specify which wins (suggest: .key file,
  because it's used for live encryption).
- Ring coverage: state explicitly that DB does NOT back up the
  ring; ring loss is recoverable only via peer PSK-Exchange.
- Rotation behaviour: does the DB row accumulate versions or
  overwrite? If the latter, document that the DB recovery path
  only restores the current key, not history.

### DF-06: CBOR field tag rules absent for PSK envelope blob

**Spec**: §4.2 PSK Envelope Blob Format

**Issue**: The CBOR structure uses three string keys (`envelope`,
`key_version`, `recipient_xpk`) but does not specify:
- Field ordering within the map (RFC 8949 §4.2.1 deterministic
  order -- by encoded key length then lexicographic. The ECIES
  spec uses this rule for item metadata but it is not re-stated
  here.)
- Whether CBOR tags are used (e.g., tag 0 for timestamps would
  be ISO 8601; none needed here but state it).
- Whether the map is indefinite-length or definite-length. ECIES
  spec §2 requires definite length but only for the metadata
  envelope; §4.2 inherits this only implicitly.

Expected ordering for these three keys, by encoded byte length:

```
envelope (9B) < key_version (12B) < recipient_xpk (14B)
```

An implementor writing a Rust `ciborium` encoder vs a TypeScript
`cbor-x` encoder will get different bytes if they don't know the
rule applies here too.

**Resolution**: Add §4.2.1 Encoding Rules:
- Map is definite-length.
- Keys sorted per RFC 8949 §4.2.1 (byte-length, then
  lexicographic).
- Canonical order for Phase 1 PSK envelope: `envelope`,
  `key_version`, `recipient_xpk`.
- Integers are shortest-form encoding per §4.2.1.
- Byte strings (`envelope`, `recipient_xpk`) are definite-length.
- Add a test vector (hex bytes for a concrete envelope) to
  anchor cross-language agreement. Suggest borrowing the style
  of ECIES §8.6 TV-C1.

### DF-07: Missing FK index on items.channel_id

**Spec**: §3.4 items table

**Issue**: SQLite does not automatically index foreign keys. The
items table has `channel_id TEXT NOT NULL REFERENCES channels(channel_id)`
and the spec creates `idx_items_channel_published (channel_id,
published_at)`. The composite index covers FK-by-channel lookups
but not the FK check itself at cascade/delete time. Also missing:

- No explicit index for `parent_id` (threading queries `WHERE
  parent_id = ?` scan the full table).
- No explicit FK index on `channel_keys.channel_id` (PRIMARY KEY
  covers it -- OK) or `dm_peers.channel_id` (PRIMARY KEY covers
  it -- OK) or `channel_members.channel_id` (leftmost of composite
  PK -- OK).

The only real issue is parent_id. Threading at scale will scan
items table.

**Resolution**: Add `CREATE INDEX idx_items_parent ON items(parent_id)
WHERE parent_id IS NOT NULL` (partial index, since most items are
top-level). Alternatively, document "threading at scale deferred
to Phase 2" explicitly.

---

## MEDIUM

### DF-08: DDL columns without explicit nullability

**Spec**: §3.4 items, §3.1 channels

**Issue**: Several columns rely on SQLite's default nullability
rather than stating it:

- `channels.channel_name` -- inferred NULL-able from the partial
  unique index, but DDL doesn't write `NULL`. Explicit is better.
- `channels.psk_hash`, `channels.descriptor` -- comments say
  "NULL if ...", DDL should say `NULL` explicitly.
- `items.parent_id` -- inferred NULL-able from "NULL if top-level"
  comment.

**Resolution**: Add explicit `NULL` marker to every nullable column
(`channel_name TEXT NULL`, `psk_hash BLOB NULL`, etc.). SQLite
accepts this syntax; it removes reader ambiguity.

### DF-09: Missing DEFAULT on channel_members.posture for inserts without it

**Spec**: §3.2 channel_members

**Issue**: DDL has `posture TEXT NOT NULL DEFAULT 'active'` -- this
is correct. No finding here. Note preserved for completeness.

(Remove -- spurious.)

Actually the real issue: `channels.creator_id BLOB NOT NULL` has
no DEFAULT, but the §3.1 relay auto-creation INSERT uses `X'00'`
as a sentinel. This is documented but worth flagging:

- `X'00'` is 1 byte. The spec states creator_id is 32 bytes
  (Ed25519 public key). Storing a 1-byte value in a column
  semantically typed as 32-byte pubkey will confuse future
  validators that assume `length(creator_id) = 32`.

**Resolution**: Either (a) use `X'0000000000000000000000000000000000000000000000000000000000000000'` (32 zero bytes -- the canonical "null key" of
review-terminology convention), or (b) change the column constraint
to `creator_id BLOB NOT NULL CHECK(length(creator_id) IN (1, 32))`
and document the 1-byte sentinel. Option (a) is preferred.

### DF-10: `updated_at` maintenance not specified

**Spec**: §3.1 channels.updated_at

**Issue**: Comment says "updated on descriptor change or key
rotation" but the spec does not specify:
- Is this updated by a trigger, or application code?
- What about member add/remove -- does that touch updated_at?
- What about role changes?

The implementation at `channels.rs` updates it in application code
on specific paths, but the spec should be explicit. A reader
implementing an alternative backend (not SQLite) would not know
the invariant.

**Resolution**: Add to §3.1 notes:
- "updated_at MUST be updated by application code (not trigger)
  on: descriptor change, PSK rotation (key_version increment).
  Phase 1 does not update this field on membership changes --
  use channel_members timestamps for that."

### DF-11: Migration version semantics unclear for compound migrations

**Spec**: §5 Schema Migration Framework

**Issue**: §5.3 defines v1 as "the complete Phase 1 schema" --
including search-indexing.md §2 tables. The implementation splits
this into migration v1 (core) and v2 (FTS5 search tables). This
split is reasonable but contradicts the spec's single-migration
v1 description. A reader running `PRAGMA user_version = 1` and
expecting the full schema will get something different from what
the implementation produces.

**Resolution**: Rewrite §5.3 to match impl:
- Migration v1: §3 core tables only.
- Migration v2: search-indexing.md §2 tables.
- Migration v3: `scope` column (see DF-01).

Or, if the intent was single-migration v1, document why impl
diverged and update code.

### DF-12: Tombstone storage and lifecycle underspecified

**Spec**: §3.4 items.is_tombstone; channels-api.md §3.6 unpublish

**Issue**: `is_tombstone INTEGER NOT NULL DEFAULT 0` says "1 =
soft-deleted" but not:
- When does a tombstone row get physically deleted?
  (network-protocol.md §6.3 says "7 days, then GC" -- re-state in
  this spec since it's the storage layer.)
- Does a tombstone row retain `encrypted_blob` (which is now
  useless -- content is gone) or is the blob zeroed/emptied?
  BV-type observability: does GC TRUNCATE the blob early?
- Do tombstones get re-indexed into `search_content`? (§6.1 says
  "Tombstones excluded from listen/search" but the search-indexing
  spec says the FTS delete trigger fires on DELETE of
  `search_content`, not on is_tombstone flip.)

**Resolution**: Add §3.4 Tombstone Lifecycle subsection:
- On tombstone creation: UPDATE items SET is_tombstone = 1,
  encrypted_blob = <original or zeroed>, ...; DELETE FROM
  search_content WHERE item_id = ?.
- Physical deletion: after 7 days (network-protocol §6.3),
  DELETE FROM items WHERE is_tombstone = 1 AND
  julianday('now') - julianday(received_at) > 7.
- Confirm blob retention policy explicitly.

### DF-13: seen_table and peer state intentionally out-of-scope -- say so

**Spec**: §3 "Core Tables"

**Issue**: Phase 1 Cordelia has operational state that is
NOT in SQLite:
- `seen_table` (content_hash -> peers, HashMap, network-protocol
  §7.2)
- Peer state (governor, HashMap in memory, §5 of network-protocol)
- Pending PSK queue (in-memory, up to 1000 items, ECIES §6.4)
- `pending_index` set (in-memory, search-indexing §3.1)

A reader coming from "Pass 5: Coverage -- all storage touchpoints
covered?" will assume any state not in SQLite is unspecified. In
fact these are deliberately in-memory. An explicit call-out avoids
the question.

**Resolution**: Add §2.2 "Out-of-Scope for this Spec" subsection:

```
The following Phase 1 state is held in process memory, not SQLite:
- seen_table (network-protocol.md §7.2)
- peer governor state (network-protocol.md §5)
- pending PSK queue (ECIES §6.4)
- pending_index set (search-indexing.md §3.1)

These are intentionally ephemeral: lost on restart, rebuilt from
peer interactions. Future phases may persist peer state for
reputation continuity; this spec will be updated at that point.
```

### DF-14: content_hash domain ambiguity between tables

**Spec**: §3.4 items.content_hash vs §3.1 no channels row hash

**Issue**: items.content_hash is BLOB (32 bytes, SHA-256 of
encrypted_blob per §3.4 notes). In search-indexing.md
§2.4, `search_embedding_meta.content_hash` is TEXT (hex of
plaintext embeddable text per §3.2). Same column name, different
type, different preimage. The "content_hash" term is overloaded.

**Resolution**: Call out in §6.1 notes: "content_hash in items is
SHA-256 of the ciphertext BLOB. content_hash in search_embedding_meta
is SHA-256 hex of the plaintext embeddable text. Different
preimages, different types, same name." Or rename one.

### DF-15: `content_length` duplicated vs computable

**Spec**: §3.4 items.content_length

**Issue**: `content_length INTEGER NOT NULL` stores the byte
length of `encrypted_blob`. In SQLite this is always computable
as `length(encrypted_blob)` -- the column is redundant. The note
says "Node-internal, not exposed via REST API." Redundant storage
has a maintenance tax (two sources of truth; possible drift).

However, network-protocol.md §4.5 Item wire struct includes
`content_length: u32` as a wire field. The column exists to
match the wire format without requiring a BLOB scan.

**Resolution**: Add note: "content_length is stored to avoid a
BLOB length scan when constructing wire-format Item messages
(network-protocol.md §4.5). Implementations MAY use
`length(encrypted_blob)` instead and omit this column; the
trade-off is an extra I/O per item on sync response construction."

---

## LOW

### DF-16: Missing cross-ref from §4.6 Visibility Rules to channels-api

**Spec**: §4.6 Visibility Rules

**Issue**: §4.6 states the listen filter
(`WHERE item_type NOT IN ('psk_envelope', 'kv', 'attestation',
'descriptor', 'probe')`) but does not cross-link to channels-api.md
§3.3 (listen) where this filter is observably enforced from the
API surface.

**Resolution**: Append "(see channels-api.md §3.3 listen behaviour)"
to the filter statement.

### DF-17: §7 Item Content Serialisation -- JSON envelope shape not fully canonical

**Spec**: §7.1 Normal Items

**Issue**: "The plaintext (before encryption) is a JSON object:
`{content, metadata}`". Does not specify:
- UTF-8 only (probably, but say so)
- JSON canonicalisation rules? (RFC 8785 JCS? Or any-JSON-goes?)
- Ordering of keys within the JSON (irrelevant for deserialisation
  but relevant for content_hash stability).
- What if `metadata` is absent vs null vs empty object? Do they
  encrypt to different ciphertext?

Since content_hash binds the encrypted bytes, subtle JSON
serialisation differences produce different ciphertext, different
content_hash, different dedup outcomes. Phase 1 is single-impl
(Rust) so this is theoretical; Phase 2's TypeScript memory adapter
could diverge.

**Resolution**: State explicitly: "Phase 1 uses `serde_json`
default output (UTF-8, no deterministic key ordering). Cross-
implementation content_hash stability is NOT guaranteed in Phase
1. Phase 2 SHOULD migrate to RFC 8785 JCS for wire-observable
hashes if cross-language parity is required."

### DF-18: §5.3 Migration v1 DDL reference -- inline or link, not both

**Spec**: §5.3

**Issue**: "Comprises all DDL from §3 and §4, plus the search
tables from search-indexing.md §2." "The full DDL is the
concatenation of §3.1-§3.5 above and search-indexing.md §2.2-§2.6."
The comment-only SQL block is confusing: it shows `-- [DDL as
defined in §3.1-§3.5 above]` as if expecting inlining. Either
inline the full DDL or clearly signal "see references".

**Resolution**: Replace the SQL block with a clear reference
list (table name -> spec section). Then §5.3 becomes a clean
pointer rather than half-DDL half-commentary. Also makes the
actual migration entry for v2/v3 (DF-01, DF-11) additive and
clean.

---

## Passes Not Applied (per instructions)

| Pass | Reason |
|------|--------|
| 6 (Privacy) | Skipped per instructions (covered by review-privacy.md) |
| 7 (Terminology) | Skipped per instructions (one term collision noted in DF-03 regardless) |

---

## Recommended Triage

**Fix before Phase 1 close (spec vs shipped code):**
- **DF-01** (scope column missing) -- spec-code drift. CRITICAL.

**Fix in one editing session (doc polish):**
- DF-02 (channel_members mapping), DF-03 (entity_key note),
  DF-05 (PSK reconciliation), DF-06 (CBOR rules), DF-13
  (out-of-scope state).

**Fix opportunistically:**
- DF-04 role change timestamp, DF-07 parent_id index, DF-10
  updated_at trigger note, DF-11 migration split, DF-12
  tombstone lifecycle.

**Nice-to-have:**
- DF-08, DF-09, DF-14, DF-15, DF-16, DF-17, DF-18.

---

## Cross-Spec Observations

Not findings for this spec, but surfaced during review:

- schema.rs test at line 267 uses `entity_id` column that doesn't
  exist (should be `entity_key`). The test passes because it
  asserts `result.is_err()` for a role CHECK violation, but the
  error is actually a column-not-found error. Unit test gives
  false positive. (Test bug, not spec bug -- log in ACTIONS.)

- BV-21 relay auto-creation IS present in §3.1 (lines 66-74).
  Implementation verified at `crates/cordelia-storage/src/items.rs`
  via the store-and-forward path. Fix is complete. No follow-up.

- `SCHEMA_VERSION = 3` in schema.rs matches findings DF-01 and
  DF-11: impl is on v3, spec is on v1.

---

*Review complete 2026-04-17.*
