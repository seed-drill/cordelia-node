# Review Pass 8: Implementability Audit

**Date**: 2026-03-11
**Specs reviewed**: 5 (ecies-envelope-encryption.md, channels-api.md, channel-naming.md, sdk-api-reference.md, network-protocol.md)

---

## Summary

25 issues found. 4 CRITICAL, 11 HIGH, 10 MEDIUM.

**Key patterns:**
- PSK distribution across multiple nodes lacks clear flow specification
- CBOR forward-compatibility and key ordering need explicit rules
- DM channel ID derivation input format is ambiguous (raw bytes vs hex)
- Conflict resolution rules need tightening (concurrent creation, LWW tiebreaks)
- Error paths are underspecified for many endpoints
- Clock handling (RTT, timestamps, clock jumps) needs defaults

---

## CRITICAL (4)

### I-01: Concurrent publish ordering

**Spec**: channels-api.md §3.2, §10.2
**Issue**: item_id is `ci_<random_hex_12>` -- two items with identical `published_at` have non-deterministic ordering across replicas.
**Resolution**: item_id should be monotonic per-node (ULID or timestamp+counter). For cross-node conflicts with same published_at and author_id, deduplicate by content_hash (first-observed wins).

### I-07: DM channel ID derivation input format

**Spec**: channel-naming.md §4.2
**Issue**: `||` concatenation not specified as byte-level or string-level. Is the SHA-256 input 76 bytes (12 UTF-8 + 32 raw + 32 raw) or 140 chars (12 + 64 hex + 64 hex)?
**Resolution**: Specify 76 bytes: 12-byte UTF-8 prefix + 32 raw bytes key A + 32 raw bytes key B. No hex encoding in hash input. Existing test vectors in §7.2 must clarify this.

### I-14: CBOR forward-compatibility / unknown fields

**Spec**: network-protocol.md §3.1, §3.2
**Issue**: No rule for handling unknown fields in CBOR messages from future protocol versions.
**Resolution**: Unknown fields are logged and ignored (forward-compatible). Handshake version negotiation (§4.1.4) gates compatibility. New capabilities use new message types, not new fields on existing types.

### I-22: System channel validation bypass

**Spec**: channel-naming.md §2, §2.1
**Issue**: `__personal` uses underscores (not RFC 1035 valid). Validation rules unclear for system vs user channels.
**Resolution**: System channels (`__*`) and protocol channels (`cordelia:*`) bypass RFC 1035 validation, are created internally only, never via API. API validation regex: `^[a-z][a-z0-9-]{1,61}[a-z0-9]$`.

---

## HIGH (11)

### I-02: Multi-node PSK discovery flow

**Spec**: channels-api.md §6, §11
**Issue**: For open channels, who responds to PSK requests? Any peer, or a designated holder?
**Resolution**: Phase 1: any peer holding the PSK may respond. Retry up to 3 times across different peers. No keeper role in Phase 1.

### I-03: Listen cursor semantics (race condition)

**Spec**: channels-api.md §3.3, §10.2
**Issue**: Is cursor strictly-greater-than or greater-or-equal? Tombstone timing unclear.
**Resolution**: `published_at > cursor` (strict). Tombstones are items, included if above cursor. SDK handles both item and tombstone in response.

### I-04: Invalid peer key error on group invite/remove

**Spec**: channels-api.md §3.9, §3.10
**Issue**: No error code for malformed Bech32 key or unresolvable entity name.
**Resolution**: 400 bad_request for invalid key format. Phase 1 accepts only `cordelia_pk1...` Bech32, not entity names.

### I-09: Channel descriptor conflict resolution

**Spec**: network-protocol.md §4.4.5, §4.4.6
**Issue**: What if different creator_id sends descriptor for same channel_id with higher key_version?
**Resolution**: Verify signature first. Different creator_id for same channel_id = attack. Log CRITICAL, reject descriptor, escalate ban on sending peer.

### I-10: PSK-Exchange subscriber_xpk format

**Spec**: network-protocol.md §4.7
**Issue**: subscriber_xpk format unspecified (raw bytes? Bech32?). Verification procedure unclear.
**Resolution**: Raw 32-byte X25519 key (binary). Holder computes `ed25519_to_x25519(peer.node_id)` and verifies equality. Mismatch = ban.

### I-12: LWW tiebreak comparison

**Spec**: network-protocol.md §6.2
**Issue**: "Lexicographic on content_hash" -- hex string or binary?
**Resolution**: Compare hex-encoded content_hash strings lexicographically. Consistent across all replicas.

### I-15: SDK token file permission errors

**Spec**: sdk-api-reference.md §2, §11.2
**Issue**: What if `~/.cordelia/node-token` exists but unreadable?
**Resolution**: Throw NODE_NOT_INITIALIZED with permissions message. Do not fall back. Warn if not chmod 600.

### I-17: ChannelLeft is SHOULD, not MUST

**Spec**: network-protocol.md §4.4.2, §4.4.4
**Issue**: SHOULD send ChannelLeft creates zombie subscriptions after crashes.
**Resolution**: Change to MUST. Gate 3 silently drops items for unsubscribed channels. On restart, re-announce all channels within 30s.

### I-20: Subscribe flow contradiction (create vs join)

**Spec**: channels-api.md §3.1, §11
**Issue**: §3.1 implies subscriber creates PSK, §11 implies keeper holds it. Two different flows conflated.
**Resolution**: First subscriber creates PSK and descriptor. Subsequent subscribers request PSK via PSK-Exchange from any peer. No keeper in Phase 1. Simultaneous creation = two independent channels (resolved Phase 3 on-chain).

### I-24: Peer scoring with no RTT measurement

**Spec**: network-protocol.md §5.5
**Issue**: Division by `(1 + rtt_ms / 100)` when rtt_ms is None (no keep-alive yet).
**Resolution**: Default rtt_ms=100 until measured. If still None after 600s tenure, demote peer.

### I-25: API binding to non-loopback address

**Spec**: channels-api.md §1.2
**Issue**: No validation preventing exposure of bearer-auth API on public network.
**Resolution**: Phase 1 MUST bind to 127.0.0.1 only. Non-loopback config = CRITICAL log + exit.

---

## MEDIUM (10)

### I-05: Rate limit enforcement mechanism

**Resolution**: Fixed 60-second window per-node per-entity. Rejections count. Counters reset on restart. Clock tolerance +-5s.

### I-06: PSK rotation queue depth

**Resolution**: Items with future key_version queued 10 minutes max, 1000 items per channel. Then marked undecryptable and dropped.

### I-08: CBOR key ordering precision

**Resolution**: Sort by full CBOR-encoded byte length of key, then by full encoded bytes lexicographically. Reference RFC 8949 §4.2.1 explicitly.

### I-11: Ban escalation cap

**Resolution**: Initial -> 2x -> 4x -> 8x (cap 24h) -> permanent after 5th. Counters reset after 7 days clean. Identity mismatch: permanent after 3rd.

### I-13: Private address filtering scope

**Resolution**: Filtering applies to peer-sharing only, not locally-configured addresses. Mixed public/private: accept public, discard private.

### I-16: Metadata size counting

**Resolution**: metadata + content serialized as single JSON, encrypted together. Combined JSON must be <=256KB pre-encryption. 413 on overflow.

### I-18: Personal channel scope (single vs multi-device)

**Resolution**: Phase 1 personal channels are device-local, derived from Ed25519 pubkey. Multi-device sync deferred to Phase 1.5+.

### I-19: Keep-alive clock handling

**Resolution**: Use monotonic clock (Instant), not wall clock, for RTT. RTT = max(0, recv - sent). Negative = log error, skip RTT update.

### I-21: BDD test harness lifecycle

**Resolution**: In-process node per scenario. TestNode handle with start/stop. Parallel via distinct configs. Harness cleans up files.

### I-23: Decryption failure handling by context

**Resolution**: Local corruption = CRITICAL log, mark undecryptable. Missing PSK = queue 10 min. AAD mismatch = WARNING, drop, increment peer's invalid counter.

---

## Recommended Triage for Martin Review

**Discuss first (CRITICAL):** I-01, I-07, I-14, I-22 -- these affect cross-implementation correctness.

**Embed in specs before coding:** I-02, I-03, I-09, I-10, I-17, I-20 -- these will block implementation if ambiguous.

**Fix during implementation:** I-04, I-05, I-06, I-08, I-11, I-12, I-13, I-15, I-16, I-18, I-19, I-21, I-23, I-24, I-25 -- clear enough with proposed resolutions, can be applied as Martin encounters them.

---

*Review Pass 8 complete. 2026-03-11.*
