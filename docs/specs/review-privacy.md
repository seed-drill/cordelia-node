# Review Pass 10: Metadata Privacy Analysis

**Date**: 2026-03-11
**Specs reviewed**: 5 (ecies-envelope-encryption.md, channels-api.md, channel-naming.md, sdk-api-reference.md, network-protocol.md)

---

## Summary

33 findings. 1 Phase 1 fix required (PV-28). Remainder are accepted risks with documented Phase 2-4 mitigations.

The protocol is honest about its privacy properties: content is always encrypted, but metadata (channel_id, author_id, published_at, item_type, blob size) is visible to relays and peers. This is a deliberate design choice -- relays need metadata for routing.

---

## Phase 1 Fix Required

### PV-28: Metrics endpoint leaks channel names
**Severity**: HIGH
**Spec**: channels-api.md §3.15

Prometheus metrics use `channel="research-findings"` labels -- full human-readable names. If the metrics port is ever exposed (misconfiguration, monitoring tool), an observer learns all channel names.

**Fix**: Channel labels must use truncated channel_id (first 8 hex chars), not channel names. Change spec §3.15: all `channel` labels use `channel_id[0:8]`, never `channel_name`.

---

## Exposure Matrix

| Observer | Sees (plaintext) | Cannot See (encrypted) | Can Infer |
|----------|-----------------|----------------------|-----------|
| **Relay** | channel_id, author_id, published_at, blob_size, content_hash, item_type, key_version, is_tombstone, descriptor (access, mode, creator_id, psk_hash) | Content, PSK | Channel purpose (size patterns), membership changes (key_version bumps), message frequency |
| **Bootnode** | node_id, channel_count, channel_digest (hash), roles, peer addresses | Items (never stored), PSKs | Network scale, peer distribution, subscription scale |
| **ISP/Network** | IP addresses, ports, packet sizes, timing, TLS cert (contains Ed25519 pk in CN) | QUIC record contents | Connection topology, realtime vs batch classification, message frequency |
| **Malicious peer (5min+)** | All relay-visible metadata + channel_name (for named channels via ChannelListResponse after tenure) | Content, PSK | Full channel enumeration, membership via timing correlation |
| **Honest peer** | Everything (holds PSK, decrypts content) | Nothing | Complete visibility (by design) |

---

## Accepted Risks by Phase

### Phase 1 (accepted, no mitigation)

| ID | Risk | Rationale |
|----|------|-----------|
| PV-01 | Relays see item metadata | Relays need channel_id for routing. Content encrypted. |
| PV-02 | item_type visible to relays | Required for application filtering at subscriber. |
| PV-03 | key_version visible (leaks rotation events) | Must be signed plaintext for decryption key selection. |
| PV-04 | is_tombstone visible (leaks deletion events) | Must be signed plaintext for tombstone replication. |
| PV-05 | Blob size enables content fingerprinting | Size padding expensive at scale. |
| PV-06 | Descriptor reveals creator_id, access, mode | Necessarily plaintext for signature verification. |
| PV-08 | Keep-alive RTT reveals geographic proximity | Inherent to any transport protocol. |
| PV-09 | ISP sees IP addresses, packet metadata | Inherent to IP networking. |
| PV-10 | Packet classification (sync vs push vs keepalive) | Protocol obfuscation deferred. |
| PV-11 | Timing patterns reveal realtime vs batch | Content hiding requires constant-rate transmission. |
| PV-12 | Peer-sharing reveals last_seen timestamps | Necessary for address staleness filtering. |
| PV-13 | Bootnode sees channel_count | Necessary for handshake / bootstrap. |
| PV-22 | Size distribution fingerprints channel purpose | Accepted. Use group conversations for sensitive topics. |
| PV-25 | Inter-packet timing classifies channel mode | Mode is semi-public metadata. |
| PV-31 | Channel ID prefix (dm_, grp_) reveals channel type | By design. Necessary for disambiguation. |

### Phase 2 mitigations

| ID | Risk | Mitigation |
|----|------|-----------|
| PV-16 | Malicious peer enumerates channels after 5min tenure | Add proof-of-membership to ChannelJoined: HMAC-SHA256(psk, "membership:" \|\| node_id \|\| channel_id) |
| PV-17 | Free-rider collects metadata without PSK | Proof-of-membership gates Channel-Announce responses |
| PV-32 | PSK-Exchange reveals "new member joining" to relay | Route PSK requests via relay layer to obscure source |

### Phase 3+ mitigations

| ID | Risk | Mitigation |
|----|------|-----------|
| PV-09 | Network-level identity exposure | WireGuard or Noise Protocol link encryption |
| PV-24 | Multi-month observation reveals relationship graph | Sealed group descriptors, confidential membership |
| PV-33 | Named channel dictionary attack (precompute SHA-256 of common names) | On-chain registration makes names public by design. Use group conversations for sensitive topics. |

### Phase 4+ mitigations

| ID | Risk | Mitigation |
|----|------|-----------|
| PV-01, PV-05 | Relay metadata accumulation | Onion routing for Item-Sync/Push |
| PV-03, PV-04 | key_version/is_tombstone visible | Conditional metadata encryption |
| PV-21, PV-25, PV-26 | Timing correlation | Chaff traffic, padding, constant-rate transmission |

---

## Cross-Spec Issues Found

### CS-01: SDK should warn against logging channel IDs
**Spec**: sdk-api-reference.md
**Issue**: Channel IDs returned in API responses may end up in application logs. SDK docs should note: "Channel IDs are implementation details. Use channel names in user-facing logs."

### CS-02: ECIES spec missing plaintext metadata visibility table
**Spec**: ecies-envelope-encryption.md §7
**Issue**: Plaintext metadata fields listed but no table showing which roles can see which fields.
**Resolution**: Add visibility matrix to ECIES spec for clarity.

---

## Key Design Validation

The privacy analysis confirms two important design choices are sound:

1. **DMs and group conversations use UUID/derived IDs, not names.** This prevents name-based enumeration. Named channels are discoverable by design.

2. **Bootnode/relay split is privacy-positive.** Bootnodes see only handshake metadata (PV-15 confirms: no items, no PSKs). The old combined role would have given discovery nodes full relay visibility.

---

*Review Pass 10 complete. 2026-03-11.*
