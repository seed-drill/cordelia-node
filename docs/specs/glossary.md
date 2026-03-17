# Cordelia Glossary

**Status**: v1.0
**Date**: 2026-03-11
**Scope**: Shared glossary referenced by all Phase 1 specifications

---

## Identity

- **Node**: A running Cordelia process with cryptographic identity (Ed25519 keypair), configuration, and persistent storage (SQLite).
- **Peer**: A network neighbour node connected via QUIC.
- **Entity**: A cryptographic identity (Ed25519 public key + optional human-readable name). May operate one or more nodes.
- **Agent**: A software automation acting on behalf of an entity (Phase 2+).
- **Creator (creator_id)**: The Ed25519 public key of the entity that created a channel, stored in ChannelDescriptor.
- **Author (author_id)**: The Ed25519 public key of the entity that published an item, stored in item metadata.

## Channels

- **Channel**: An encrypted topic for publishing items. Three types: named, DM, group.
- **Named channel**: A channel identified by an RFC 1035-compliant label, mapped to channel_id via SHA-256.
- **DM (Direct Message)**: A bilateral channel with immutable membership (exactly 2 entities), identified by `dm_` prefix + deterministic SHA-256.
- **Group conversation**: A channel with mutable membership (3+ entities), identified by `grp_` prefix + random UUID v4.
- **Personal channel**: The system channel `__personal` created per entity at `cordelia init` for private storage.
- **System channel**: A node-internal channel (prefixed `__`), bypasses RFC 1035 validation, never exposed via API.
- **Protocol channel**: A system-wide channel (prefixed `cordelia:`), e.g. `cordelia:directory`.
- **Access policy**: `open` (auto-approve, PSK discoverable) or `invite_only` (manual invitation, PSK via ECIES envelope).
- **Replication mode**: `realtime` (eager Item-Push, 60s sync) or `batch` (pull-only, 900s sync). Developer-facing terms replacing internal chatty/taciturn.

## Cryptographic

- **PSK (Pre-Shared Key)**: A random 32-byte AES-256-GCM key generated per channel, used to encrypt all items on that channel.
- **ECIES envelope**: A 92-byte structure wrapping a PSK, encrypted to a recipient's X25519 public key.
- **Metadata envelope**: A CBOR-encoded structure of item metadata fields, signed with the author's Ed25519 key. Distinct from ECIES envelope.
- **Descriptor (ChannelDescriptor)**: Signed CBOR metadata record for a channel (creator, mode, access, psk_hash, key_version), replicated via Channel-Announce.
- **Bech32**: BIP-173 base32 encoding for keys. HRPs: `cordelia_pk` (Ed25519 pub), `cordelia_sk` (seed), `cordelia_xpk` (X25519 pub), `cordelia_sig` (signature), `cordelia_psk` (channel PSK).

## Network

- **Personal node**: Node with `role="personal"`, storing only subscribed channels.
- **Bootnode**: Node with `role="bootnode"`, discovery-only (Handshake + Peer-Sharing), never stores or relays items.
- **Relay**: Node with `role="relay"`, store-and-forward with LRU-evicted cache (max 10GB), re-pushes items to peers.
- **Keeper**: Node with `role="keeper"`, anchors channels, holds PSKs for open/gated channels (Phase 2+).
- **Anchor keeper**: A specific keeper designated as PSK authority for a channel (Phase 2+, stored in ChannelDescriptor).
- **Push policy**: Personal node config: `subscribers_only` (default, push to channel peers + relays) or `pull_only` (never push, serve only via Item-Sync).
- **Subscriber**: An entity subscribed to a channel (holds the PSK, receives items).
- **Member**: An entity in a group conversation with mutable membership. Distinct from subscriber in that members can be invited/removed.

## Replication

- **Item**: A published unit of content, encrypted with channel PSK, including metadata, signature, and ciphertext blob.
- **Publish**: Write an item to a channel via the API. Developer-facing term; internal protocol uses "write".
- **Listen**: Retrieve items from a channel via cursor-based polling (REST Phase 1, SSE Phase 2).
- **Item-Push**: Unsolicited sender-initiated item delivery for realtime channels via QUIC.
- **Item-Sync**: Periodic pull-based synchronisation via hash reconciliation (anti-entropy).
- **Channel-Announce**: P2P mini-protocol for broadcasting channel descriptor changes.
- **PSK-Exchange**: P2P request-response mini-protocol for distributing PSKs via ECIES envelope.
- **Tombstone**: Soft-delete marker (`is_tombstone=true`), propagated via replication.
- **Store-and-forward**: Relay behaviour: receive items, store in LRU cache, re-push to peers.
- **LRU eviction**: Least-Recently-Used cache policy on relays, triggered at 10GB storage cap.

## Economics

- **Proof-of-use**: Channel must have >=10 items from >=2 distinct authors/year to renew on-chain registration (Phase 3).
- **Contribution ratio**: `items_relayed / max(items_requested, 1)` -- measures relay reciprocity.
- **Probe**: Zero-length encrypted item published every 300s to verify relay liveness and detect defection.

---

*Glossary v1.0. Created 2026-03-11. Referenced by all Phase 1 specs.*
