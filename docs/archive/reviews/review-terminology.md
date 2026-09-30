# Review Pass 7: Terminology Consistency

**Date**: 2026-03-11
**Specs reviewed**: 5 (ecies-envelope-encryption.md, channels-api.md, channel-naming.md, sdk-api-reference.md, network-protocol.md)

---

## 1. Consistent Terms (no action needed)

- **realtime / batch**: Consistently used as developer-facing terms across all specs. Internal chatty/taciturn fully replaced.
- **tombstone**: Consistent soft-delete semantics across all specs.
- **item**: Consistent unit of published content.
- **channel PSK**: Consistent across all specs. No "group key" or "channel key" usage.
- **subscribe / publish / listen**: Consistent API verb set.
- **ECIES envelope**: Consistent for PSK wrapping structure.
- **bootnode / relay**: Distinct roles, no confusion across specs.
- **DM / direct message**: Consistent (DM in code, Direct Message in headers).
- **personal channel / personal node**: Distinct concepts, no confusion.

## 2. Inconsistencies Found

### T-01: "author" vs "creator" (acceptable, needs documentation)

- `creator_id`: entity that created a channel (ChannelDescriptor)
- `author_id`: entity that published an item (item metadata)

Two distinct roles, correctly named. But never explicitly defined as distinct. Add to glossary.

### T-02: "node" vs "peer" vs "entity" vs "agent" (needs glossary)

Four concepts, sometimes used interchangeably:
- **node**: running Cordelia process
- **peer**: network neighbor node
- **entity**: cryptographic identity (Ed25519 keypair)
- **agent**: software automation (Phase 2+)

SDK docs use "agent" where "entity" is more precise for Phase 1. Minor, but worth noting in glossary.

### T-03: "subscriber" vs "member" (context-dependent, acceptable)

- **subscriber**: entity that subscribes to a named channel
- **member**: entity in a group conversation with mutable membership

Both are correct in context. The `role` field uses "owner" / "admin" / "member" for all channel types, which is slightly confusing since named channel participants are "subscribers" in the API but "members" in the role enum.

### T-04: "anchor keeper" vs "keeper" (Phase 2+ distinction)

- **keeper**: node role (§8.4)
- **anchor keeper**: designated PSK authority for a channel (Phase 2+)

No confusion in Phase 1 since keepers don't exist yet. Document the distinction for Phase 2.

### T-05: "descriptor" vs "metadata" vs "envelope" (overloaded)

- **descriptor**: ChannelDescriptor (channel metadata, signed, replicated)
- **metadata envelope**: CBOR-encoded signed item fields
- **ECIES envelope**: encrypted PSK wrapping (92 bytes)

"Envelope" is overloaded. Consider: "ECIES wrapper" vs "metadata envelope" to disambiguate. Low priority.

### T-06: "publish" vs "write" (layer-appropriate)

- **publish**: API/SDK verb (developer-facing)
- **write**: internal operation (protocol-level)

Acceptable layering. No change needed.

## 3. Terms Used But Never Defined

| Term | Where | Proposed Definition |
|------|-------|-------------------|
| group conversation | channels-api.md §3.8 | A channel with mutable membership (3+ entities) identified by UUID |
| open / invite_only | channels-api.md, network-protocol.md | Access policies: open = auto-approve, PSK discoverable; invite_only = manual invitation, PSK via ECIES |
| proof-of-use | network-protocol.md §16.6 | Channel must have >=10 items from >=2 authors/year to renew registration |
| store-and-forward | network-protocol.md §8.3 | Relay behaviour: receive, store in LRU cache, re-push to peers |
| LRU eviction | network-protocol.md §8.3 | Least-Recently-Used cache policy, triggered at 10GB relay storage cap |

## 4. Proposed Glossary

A shared glossary should be added to either a new `specs/glossary.md` or as §1 of each spec. Key entries:

**Identity**: node, peer, entity, agent, creator, author
**Channels**: channel, named channel, DM, group conversation, personal channel, system channel, protocol channel
**Crypto**: PSK, ECIES envelope, metadata envelope, descriptor, Bech32
**Network**: bootnode, relay, keeper, anchor keeper, subscriber, member
**Replication**: realtime, batch, tombstone, item, publish, write, store-and-forward, LRU eviction
**Economics**: proof-of-use, contribution ratio, probe, ban, push_policy

---

**Recommendation**: Create `specs/glossary.md` with ~40 entries. Reference it from all 5 specs. Low effort, high clarity for Martin and future contributors.

---

*Review Pass 7 complete. 2026-03-11.*
