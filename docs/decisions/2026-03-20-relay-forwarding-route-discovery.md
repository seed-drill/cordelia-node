# Decision: Relay Forwarding and Route Discovery

**Date**: 2026-03-20
**Decision Maker(s)**: Russell Wing, Claude (Opus 4.6)
**Status**: Draft
**Triggered by**: cordelia-node#9 (sparse mesh item partitioning), session 117-118 analysis of multi-hop relay propagation failures

---

## 1. Problem Statement

**Decision**: Cordelia needs two distinct routing mechanisms for different memory types, unified under a single relay forwarding protocol.

**Context**:

The current relay model (§7.2) uses single-hop push: a relay that receives an item pushes it to its hot peers, but receiving relays do not re-push. Pull-sync only syncs from hot peers. In a sparse mesh (hot_max < R), this causes items to partition into clusters around the publishing relay's immediate neighbourhood.

Evidence from S2 R=50 sparse test (hot_max=20, 2026-03-19):
- Mesh formed correctly (all 50 relays at 19+ hot peers, 19s)
- Every relay stabilized at exactly 6/15 items (2 publishers' worth)
- Items never propagated beyond the publisher's local relay cluster
- 100/152 assertions failed; 4 minutes of delivery time made no difference

Two routing problems:

1. **Personal memories (point-to-point)**: An item published by p-node-A needs to reach secret-keeper-B. The route is unknown at publish time. The network must discover the path efficiently, cache it, and re-discover on failure.

2. **Group memories (epidemic)**: An item needs to reach all subscribed nodes across the relay mesh with bounded latency. The network topology is unknown and changes. The relay mesh must propagate items without central coordination.

---

## 2. Relay Forwarding with Duplicate Suppression

**Decision**: Relays forward items to all hot peers that have not yet received them, tracked via a message-ID-vs-peer seen table.

**Rationale**:
- Replaces single-hop push with epidemic dissemination
- Message IDs are SHA-256 hashes (content_hash), amenable to fast indexing
- Seen table is bounded: window size derived from `sync_interval * expected_items_per_interval * hot_max`
- Duplicate suppression prevents exponential message amplification
- Each relay maintains: `HashMap<ContentHash, HashSet<NodeId>>` with TTL-based eviction
- On receiving an item (push or sync), relay forwards to `hot_peers - seen_peers_for_item`
- This directly fixes the sparse mesh partitioning problem (cordelia-node#9)

**Impact**:
- §7.2 (relay re-push) changes from single-hop to multi-hop with duplicate suppression
- New data structure: relay seen table (bounded, in-memory)
- Push traffic increases proportionally to `log(N)` hops rather than 1 hop
- Pull-sync becomes a consistency safety net, not the primary cross-relay propagation mechanism

---

## 3. Route Discovery for Personal Memories

**Decision**: Use broadcast-discover-cache routing with encrypted routing tokens for path privacy.

**Rationale**:
- Personal memories target a specific secret keeper whose network location is unknown
- First message broadcasts (flood with expanding ring: TTL=2, then TTL=4, then full)
- Each relay in the forward path appends an encrypted routing token to the envelope
- Secret keeper receives multiple copies via different paths, selects shortest (fewest tokens)
- Secret keeper sends ACK using the reverse token chain
- Publisher caches the token chain for subsequent messages
- If no ACK within timeout (e.g. 2 * expected_round_trip), re-broadcast to discover new path
- Multi-path: receiver keeps top 2-3 paths for failover without re-broadcast

**Design**: Dynamic Source Routing (DSR) family, adapted for privacy. Similar to Lightning Network onion routing but simpler (symmetric crypto only).

**Impact**:
- New message type: RouteDiscovery (broadcast with envelope)
- New message type: RouteACK (reverse envelope)
- Items gain an optional `route_tokens` field for cached routing
- Expanding ring search bounds broadcast scope for large networks

---

## 4. Encrypted Routing Tokens (Path Privacy)

**Decision**: Each relay creates an opaque AES-256-GCM token that only it can decrypt. Nobody -- not the publisher, receiver, or other relays -- learns the full path topology.

**Mechanism**:

Forward path (discovery broadcast):
1. Publisher P sends item with empty envelope
2. Relay R_1 receives, generates session key `k_1`, stores `nonce_1 -> k_1` in LRU cache
3. R_1 appends: `Token_1 = AES-256-GCM(k_1, {prev_hop_addr, nonce_1})`
4. R_2 receives, appends Token_2 (same process)
5. Envelope grows: `[Token_1, Token_2, ..., Token_n]`

Return path (ACK):
1. Receiver reverses token list: `[Token_n, ..., Token_1]`
2. R_n decrypts Token_n, finds prev_hop_addr, forwards to R_{n-1}
3. Cascade continues to publisher

Cached routing (subsequent messages):
1. Publisher stores `[Token_1, ..., Token_n]` from successful ACK
2. Each relay peels one token, finds next_hop_addr, forwards remainder
3. If any token fails decryption (key expired, relay gone), message falls back to broadcast

**Privacy properties**:

| Observer | Knows | Does not know |
|----------|-------|---------------|
| Publisher | Path works, hop count (see §5) | Relay identities |
| Receiver | Hop count (token count) | Relay identities, addresses |
| Relay R_i | Predecessor + successor addresses | Full path, other relay identities |
| Network observer | Adjacent message flow | End-to-end correspondence |

**Rationale**:
- Stronger than Tor (sender doesn't know relay identities)
- Stronger than plaintext DSR (nobody sees the full path)
- No asymmetric crypto per hop -- AES-256-GCM only (already in our stack)
- Token size: ~48 bytes (16 addr + 12 nonce + 16 auth tag + 4 length)
- Session key storage: bounded LRU per relay, TTL aligned with warm tenure (300s)
- Path staleness is self-healing: expired keys cause decryption failure, triggering re-broadcast

**Impact**:
- Relay session key cache: new in-memory data structure (~64 bytes per active path per relay)
- Token format added to wire protocol (CBOR-encoded, within existing envelope)
- No changes to existing ECIES content encryption (items remain opaque ciphertext)

---

## 5. Envelope Padding (Paranoia Mode)

**Decision**: Optional padding to fixed envelope size prevents hop count leakage.

**Mechanism**:
- Publisher pads envelope to a fixed number of tokens (e.g. 20) with random bytes
- Dummy tokens are indistinguishable from real tokens (same size, random content)
- Receiver cannot distinguish real from padding (decryption of dummy tokens fails silently)
- Receiver counts all tokens but cannot determine actual hop count

**Rationale**:
- Hop count leaks path length, which in a small network could narrow the publisher's identity
- Padding cost is minimal: 20 tokens * 48 bytes = ~960 bytes per message
- Secret keepers already require a degree of trust (they hold PSKs), so hop count leakage is acceptable in default mode
- Paranoia mode is opt-in per channel or per publisher

**Impact**:
- New channel option: `paranoia_mode: bool` (default false)
- Publisher-side only: no relay or receiver changes needed

---

## 6. Message-ID Seen Table Design

**Decision**: Relays maintain a bounded in-memory table mapping content hashes to the set of peers that have received each item.

**Structure**:
```
seen_table: HashMap<[u8; 32], SeenEntry>

SeenEntry {
    peers: HashSet<NodeId>,     // peers we've forwarded to or received from
    first_seen: Instant,        // for TTL eviction
}
```

**Bounds**:
- Max entries: `SEEN_TABLE_MAX = 10_000` (configurable)
- TTL: `SEEN_TABLE_TTL = 600s` (10 minutes, covers 2x the slowest convergence path)
- Eviction: LRU by first_seen when at capacity
- Memory: ~10K entries * (32 hash + 60 peers * 32 bytes + 8 timestamp) ≈ 19 MB worst case
- Typical: much smaller (most items seen by <10 peers before TTL expiry)

**Rationale**:
- Content hash (SHA-256 of encrypted_blob) is the natural message ID -- already computed, unique, fast
- HashSet<NodeId> per item allows O(1) "has this peer seen this item?" lookups
- TTL prevents unbounded growth; items older than 10 minutes are either fully propagated or lost
- Window size derived from: `sync_interval(10s) * items_per_interval * hot_max(50)` ≈ a few hundred entries in steady state

**Impact**:
- New field in relay runtime state (not persisted to SQLite)
- Checked on every inbound item (push or sync) before forwarding
- Updated on every outbound forward

---

## 7. Unified Protocol Extension

**Decision**: Both routing modes (personal and group) share one relay forwarding mechanism, distinguished by a routing mode flag on the item.

**Routing modes**:

| Mode | Behaviour | Envelope | ACK | Cache |
|------|-----------|----------|-----|-------|
| `epidemic` | Forward to all unseen peers | Optional (privacy tokens) | None | No |
| `routed` | Broadcast-discover-cache | Required (tokens) | Required | Yes |

**Rationale**:
- One forwarding code path, one seen table, one token format
- Mode is set by the publisher based on channel type (group = epidemic, personal = routed)
- Relays don't need to understand the distinction -- they forward to unseen peers either way
- The only difference is whether the receiver sends an ACK and whether the publisher caches tokens

**Impact**:
- Item metadata gains: `routing_mode: u8` (0 = epidemic, 1 = routed)
- Item envelope gains: `route_tokens: Vec<EncryptedToken>` (optional, empty for epidemic)
- New message type: `RouteACK { tokens: Vec<EncryptedToken>, item_id: String }`
- Spec changes: §4.6 (push), §7.2 (relay forwarding), new §7.3 (route discovery)

---

## 8. Expanding Ring Search

**Decision**: Route discovery uses expanding ring search to bound broadcast scope.

**Mechanism**:
1. Publisher sends with `ttl=2` (2-hop neighbourhood)
2. If no ACK within `2 * estimated_round_trip` (e.g. 30s), retry with `ttl=4`
3. If still no ACK, full broadcast (`ttl=255`)
4. Each relay decrements TTL before forwarding; TTL=0 items are not forwarded

**Rationale**:
- Most secret keepers will be 2-3 hops away (small network, well-connected mesh)
- Full broadcast is expensive at scale (1000+ relays) and only needed for edge cases
- Expanding ring is a standard optimisation from AODV/DSR literature
- TTL field is 1 byte, negligible overhead

**Impact**:
- Item metadata gains: `ttl: u8` (default 255 for epidemic/group, starts at 2 for routed)
- Relays check TTL before forwarding; decrement on forward
- Publisher retry logic with escalating TTL

---

## 9. Phase Plan

| Phase | Deliverable | Dependency |
|-------|------------|------------|
| Phase 1.1 | Epidemic forwarding + seen table | None (fixes cordelia-node#9) |
| Phase 1.2 | Route discovery + encrypted tokens | Phase 1.1 |
| Phase 1.3 | Expanding ring search | Phase 1.2 |
| Phase 1.4 | Paranoia mode (envelope padding) | Phase 1.2 |
| Phase 2+ | Path quality metrics, multi-path failover | Phase 1.2 |

Phase 1.1 is the immediate priority: it unblocks sparse mesh scaling with minimal protocol change. Phases 1.2-1.4 can follow iteratively.

---

## 10. Open Questions

1. **Seen table persistence**: Should the seen table survive relay restart? Currently proposed as in-memory only. Pull-sync safety net handles restart gaps, but warm restart would reduce duplicate traffic.

2. **Token expiry coordination**: Session key TTL (300s) means cached routes expire. Should the publisher proactively re-discover before expiry, or wait for failure? Proactive avoids latency spikes but adds traffic.

3. **Relay incentives**: Forwarding increases relay work (more push traffic, seen table maintenance). The economic model (ADR: SPO economic model) should account for forwarding contribution in relay scoring (§16.1).

4. **Rate limiting interaction**: §9.2 rate limits count sync streams per peer. Multi-hop forwarding increases push volume. Should forwarded items have a separate rate limit bucket, or share the existing one?

---

*This ADR supersedes the single-hop relay push model in §7.2 and introduces route discovery as a new protocol capability. Implementation should update network-protocol.md §7 accordingly.*

*Related: cordelia-node#9 (sparse mesh partitioning), parameter-rationale.md (seen table bounds), demand-model.md (forwarding traffic estimates)*
