# Channel Naming Specification

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-10
**Scope**: Phase 1 (Encrypted Pub/Sub MVP)
**Implements**: WP2 (Name-Based Group Resolution)
**Depends on**: specs/channels-api.md, decisions/2026-03-10-identity-privacy-model.md §8

---

## 1. Overview

Channel names are human-readable identifiers that map deterministically to channel IDs via SHA-256. This spec defines the naming rules, canonicalization algorithm, ID derivation for all three channel types, and the reserved namespace.

### 1.1 Design Principles

1. **Names are canonical.** One name, one channel. No aliases, no case sensitivity, no ambiguity.
2. **IDs are derived, not assigned.** Named channel IDs are content-addressed (SHA-256 of name). No central registry needed for Phase 1.
3. **One namespace.** Entities and channels share a single flat namespace (identity ADR §8). A name cannot be both a person and a channel.
4. **DNS-compatible.** Naming rules follow RFC 1035 labels. Channel names are valid DNS labels.

---

## 2. Naming Rules

Channel names follow RFC 1035 label syntax:

| Rule | Constraint | Example |
|------|-----------|---------|
| Length | 3-63 characters | `ai-research` (valid), `ab` (too short), `a<64 chars>` (too long) |
| Characters | Lowercase `a-z`, digits `0-9`, hyphens `-` | `research-2026` (valid) |
| Start | Must start with a letter (`a-z`) | `3d-models` (invalid), `models-3d` (valid) |
| End | Must not end with a hyphen | `research-` (invalid) |
| Consecutive hyphens | Allowed | `my--channel` (valid, but discouraged) |
| Case | Lowercase only | `Research` → canonicalized to `research` |

### 2.1 Reserved

| Pattern | Reservation | Reason |
|---------|------------|--------|
| `cordelia:*` | Protocol channels | System namespace (directory, channel registry) |
| Names containing `/` | Future hierarchy | Reserved for Phase 4+ hierarchical namespaces |
| Names containing `_` | Channel ID prefixes | `dm_` and `grp_` use underscores for prefix disambiguation |

**Note:** `_` (underscore) is illegal in RFC 1035 labels, so this reservation is inherent -- not an additional constraint. The colon in `cordelia:*` is also not an RFC 1035 character, making protocol channels syntactically distinct from user channels.

**System channels** (node-internal, not user-creatable):

| Name | Purpose | Created by |
|------|---------|-----------|
| `__personal` | Personal memory, PSK envelopes, attestations | `cordelia init` (ECIES spec §14) |

System channels use the `__` (double underscore) prefix. They bypass RFC 1035 validation -- the validation regex only applies to user-created channel names (API input). System channel IDs are derived with an entity-specific domain separator: `SHA-256("cordelia:channel:__personal:" + hex(pubkey))`. System channels are never exposed in the public namespace or Channel-Announce.

**Validation rules for system and protocol channels:** System channels (prefixed `__`) and protocol channels (prefixed `cordelia:`) bypass RFC 1035 validation. They are created internally by the node only, never accepted via the channels API. The API validation regex for user-submitted channel names is: `^[a-z][a-z0-9-]{1,61}[a-z0-9]$`. Underscores are rejected. Names containing `:` are rejected. The prefixes `__` and `cordelia:` are reserved and MUST NOT be accepted from API requests.

### 2.2 Validation Regex

```
^[a-z][a-z0-9-]{1,61}[a-z0-9]$
```

This enforces: starts with letter, ends with letter or digit, 3-63 characters total, only lowercase alphanumeric and hyphens.

---

## 3. Canonicalization

Before hashing, channel names are canonicalized:

```
canonicalize(input: string) -> string:
  1. Trim leading/trailing whitespace
  2. Convert to lowercase (Unicode toLowercase)
  3. Validate against naming rules (§2)
  4. If invalid: reject with error
  5. Return canonical name
```

**Examples:**

| Input | Canonical | Valid? |
|-------|-----------|--------|
| `Research-Findings` | `research-findings` | Yes |
| `  ai-signals  ` | `ai-signals` | Yes |
| `ENGINEERING` | `engineering` | Yes |
| `3d-models` | -- | No (starts with digit) |
| `ab` | -- | No (too short) |
| `my_channel` | -- | No (underscore) |
| `research-` | -- | No (trailing hyphen) |

Canonicalization is idempotent: `canonicalize(canonicalize(x)) == canonicalize(x)`.

---

## 4. Channel ID Derivation

### 4.1 Named Channels

```
channel_id = hex(SHA-256(UTF-8("cordelia:channel:" + canonical_name)))
```

The input to SHA-256 is the UTF-8 encoding of the domain-separated string `"cordelia:channel:"` concatenated with the canonical name. The channel ID is the lowercase hex-encoded hash. 64 hex characters.

Domain separation (`cordelia:channel:` prefix) prevents cross-protocol hash correlation -- the same name in a different system produces a different hash.

**Example:**

```
Name:           "research-findings"
Canonical:      "research-findings"
Hash input:     "cordelia:channel:research-findings"
UTF-8 bytes:    63 6f 72 64 65 6c 69 61 3a 63 68 61 6e 6e 65 6c
                3a 72 65 73 65 61 72 63 68 2d 66 69 6e 64 69 6e
                67 73
SHA-256:        fe028fdaf943c16ec8a1fc496818274ce7e86e921ad926f9712886fa26d309d6
Channel ID:     "fe028fdaf943c16ec8a1fc496818274ce7e86e921ad926f9712886fa26d309d6"
```

**Properties:**
- Deterministic: any node computes the same ID from the same name
- Collision-resistant: SHA-256 birthday bound is 2^128
- Domain-separated: `cordelia:channel:` prefix prevents cross-protocol hash collisions

**Dictionary attack caveat:** Channel IDs for named channels are vulnerable to dictionary attack. An attacker who knows common channel names can precompute their hashes and identify channels in replication traffic or on-chain registries. This is accepted because:

1. Open channels are discoverable by design (their names are public)
2. Invite-only channels with sensitive names should use group conversations (UUID, not name-derived)
3. Phase 3 on-chain registration is restricted to open channels only (§8) -- private channels are never registered

### 4.2 DM Channels

```
sorted_keys = sort([pk_a, pk_b])                          -- lexicographic sort of raw 32-byte keys
preimage    = UTF-8("cordelia:dm:") || sorted_keys[0] || sorted_keys[1]   -- 12 + 64 = 76 bytes
channel_id  = "dm_" + hex(SHA-256(preimage))
```

Both parties compute the same channel ID regardless of who initiates. The `dm_` prefix distinguishes DM channel IDs from named channel IDs.

**Preimage format:** The SHA-256 preimage is exactly 76 bytes: the 12-byte UTF-8 string `cordelia:dm:` concatenated with the raw 32 bytes of sorted_keys[0] concatenated with the raw 32 bytes of sorted_keys[1]. No hex encoding in the hash input. Keys are sorted by their raw byte values (not hex string comparison).

**Example:**

```
Alice pk (hex):  d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
Bob pk (hex):    3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29

Sorted:          [3b6a27bc..., d75a9801...]  (Bob < Alice lexicographically)
Preimage:        "cordelia:dm:" || 3b6a27bc...29 || d75a9801...1a   (76 bytes)

SHA-256:         c56ea36e17c1c3dba0524822fb0ac3dc16ff442dd3c792f5a2989a0a77a30cd0
Channel ID:      "dm_c56ea36e17c1c3dba0524822fb0ac3dc16ff442dd3c792f5a2989a0a77a30cd0"
```

**Properties:**
- Deterministic: both parties derive the same ID
- Symmetric: `dm(alice, bob) == dm(bob, alice)`
- Collision-resistant: SHA-256 of 64 bytes
- Private: the channel ID reveals that two keys share a DM, but not who they are (keys are pseudonymous)

### 4.3 Group Conversations

```
channel_id = "grp_" + UUID_v4()
```

Group conversations use random UUID v4 identifiers. Not derived from member keys (membership is mutable). The `grp_` prefix distinguishes group conversation IDs.

**Properties:**
- Random: no derivation from members or name
- Unique: UUID v4 collision probability is negligible
- Mutable: members can be added/removed without changing the channel ID

---

## 5. Prefix Disambiguation

The node uses the channel identifier's prefix to determine the resolution strategy:

| Prefix | Type | Resolution |
|--------|------|-----------|
| `dm_` | DM channel | Direct lookup by full ID |
| `grp_` | Group conversation | Direct lookup by full ID |
| `cordelia:` | Protocol channel | Reserved, special handling |
| (none) | Named channel | Canonicalize name, compute SHA-256 |

This is safe because:
- `dm_` and `grp_` contain underscores, which are illegal in RFC 1035 names
- `cordelia:` contains a colon, which is illegal in RFC 1035 names
- No valid channel name can collide with any prefix

---

## 6. Protocol Channels

Reserved channel names for protocol operations (Phase 2+):

| Name | Purpose | PSK | Phase |
|------|---------|-----|-------|
| `cordelia:directory` | Decentralised keeper directory | Well-known (public) | 2 |
| `cordelia:channels` | Public channel registry | Well-known (public) | 2 |
| `cordelia:announce` | Network-wide announcements | Well-known (public) | 3 |

Protocol channels use well-known PSKs: technically encrypted (same AES-256-GCM pipeline as all channels), practically public (PSK is published in documentation and hardcoded in clients). This maintains protocol uniformity -- no special "unencrypted" code path.

Well-known PSK derivation:
```
protocol_psk = SHA-256(UTF-8("cordelia-protocol-channel:" + channel_name))
```

Example: `cordelia:directory` PSK = `SHA-256("cordelia-protocol-channel:cordelia:directory")`.

---

## 7. Test Vectors

### 7.1 Canonicalization

| Input | Expected Output | Notes |
|-------|----------------|-------|
| `research-findings` | `research-findings` | No change |
| `Research-Findings` | `research-findings` | Lowercased |
| `  ai-signals  ` | `ai-signals` | Trimmed |
| `ENGINEERING` | `engineering` | Lowercased |
| `a` | ERROR | Too short (min 3) |
| `ab` | ERROR | Too short (min 3) |
| `abc` | `abc` | Minimum length |
| `3research` | ERROR | Starts with digit |
| `research-` | ERROR | Trailing hyphen |
| `my_channel` | ERROR | Contains underscore |
| `my.channel` | ERROR | Contains period |
| `cordelia:test` | ERROR | Contains colon (reserved) |

### 7.2 Channel ID Derivation

Reference SHA-256 hashes computed by Python `hashlib.sha256`:

**1. Named channel: `research-findings`**
```
Input:       "cordelia:channel:research-findings"
SHA-256:     fe028fdaf943c16ec8a1fc496818274ce7e86e921ad926f9712886fa26d309d6
Channel ID:  fe028fdaf943c16ec8a1fc496818274ce7e86e921ad926f9712886fa26d309d6
```

**2. Named channel: `engineering`**
```
Input:       "cordelia:channel:engineering"
SHA-256:     743e760f7c729ecc93ad08d0a4d942de047f98ae53dc1459af99af826deb3ba9
Channel ID:  743e760f7c729ecc93ad08d0a4d942de047f98ae53dc1459af99af826deb3ba9
```

**3. Named channel: `abc` (minimum length)**
```
Input:       "cordelia:channel:abc"
SHA-256:     0a7d0ae0a65b98af92058dd0c5f538591afa09413c4634e9f8f930ff6528259c
Channel ID:  0a7d0ae0a65b98af92058dd0c5f538591afa09413c4634e9f8f930ff6528259c
```

**4. Named channel: 63-character name (maximum length)**
```
Name:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  (63 × 'a')
Input:       "cordelia:channel:aaa...aaa"
SHA-256:     a97ac4b49075f79200906cb8fb80c286dc4424e067caf869caebf0516cf21d54
Channel ID:  a97ac4b49075f79200906cb8fb80c286dc4424e067caf869caebf0516cf21d54
```

**5. DM channel (RFC 8032 TV1 + TV2 keys)**
```
Alice pk:    d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
Bob pk:      3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29
Sorted:      [3b6a27bc..., d75a9801...]  (Bob < Alice lexicographically)
Preimage:    "cordelia:dm:" || sorted_keys[0] || sorted_keys[1]  (76 bytes)
SHA-256:     c56ea36e17c1c3dba0524822fb0ac3dc16ff442dd3c792f5a2989a0a77a30cd0
Channel ID:  dm_c56ea36e17c1c3dba0524822fb0ac3dc16ff442dd3c792f5a2989a0a77a30cd0
```

**6. Protocol channel PSK: `cordelia:directory`**
```
Input:       "cordelia-protocol-channel:cordelia:directory"
SHA-256:     1d1b02d7fa1fb8eef894c6dd042c2711be63df24699d6c0134ae629c071ae725
PSK (hex):   1d1b02d7fa1fb8eef894c6dd042c2711be63df24699d6c0134ae629c071ae725
```

### 7.3 Prefix Disambiguation

| Input | Resolved Type |
|-------|--------------|
| `research-findings` | Named channel |
| `dm_a1b2c3...` | DM channel |
| `grp_550e8400-...` | Group conversation |
| `cordelia:directory` | Protocol channel |

---

## 8. Namespace Uniqueness (Phase 3)

In Phase 1, channel name uniqueness is local: two different networks can independently create a `research` channel. This is by design -- there is no global registry.

In Phase 3, **open channels** can optionally be registered on-chain (Cardano) for global uniqueness:

- Registration: submit `channel_id` (SHA-256 hash) to on-chain registry with ADA deposit (~2 ADA)
- The channel name itself is NOT stored on-chain (only the domain-separated hash is visible)
- Collision resolution: first to register owns the name
- Expiry: names can expire if not renewed (prevents squatting)
- Entity names share the same registry (one namespace, §1.1)

**Only open channels are eligible for on-chain registration.** Invite-only channels, DMs, and group conversations are never registered. Registration is for discovery -- private channels are not discoverable by design.

On-chain registration is optional. Unregistered channels work fine locally and across federated nodes. Registration adds global uniqueness and discoverability.

**Dictionary attack mitigation:** Because only open channels register on-chain, and open channel names are public by design, dictionary attacks against on-chain hashes reveal no private information.

---

## 9. References

- **RFC 1035**: Domain Names -- Implementation and Specification (label syntax)
- **specs/channels-api.md**: Channel API endpoints, ID format table (§4)
- **decisions/2026-03-10-identity-privacy-model.md**: Namespace model (§8), naming rules
- **decisions/2026-03-09-architecture-simplification.md**: Channel encryption model

---

*Draft: 2026-03-10. Review with Martin before implementation.*
