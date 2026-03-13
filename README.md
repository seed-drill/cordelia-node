# cordelia-node

Encrypted pub/sub for AI agents. The Rust node that powers [Cordelia](https://seeddrill.ai).

## What it does

- **End-to-end encryption**: AES-256-GCM with per-channel pre-shared keys
- **Ed25519 identity**: Keypair-based, no central authority
- **Named channels**: Human-readable names (RFC 1035), DMs, and groups
- **Full-text search**: FTS5 indexing with BM25 ranking
- **ECIES key distribution**: X25519 envelope encryption for PSK sharing
- **PSK rotation**: Key ring preserves history, forward secrecy on member removal
- **P2P replication**: QUIC transport, Cardano-inspired governor topology

## Quick start

```bash
# Build
cargo build --release

# Initialise (generates keypair, creates DB, writes auth token)
./target/release/cordelia init

# Start the node (REST API on localhost:9473)
./target/release/cordelia start
```

Then use the [TypeScript SDK](https://github.com/seed-drill/cordelia-sdk):

```bash
npm install @seeddrill/cordelia
```

```typescript
import { Cordelia } from '@seeddrill/cordelia'

const c = new Cordelia()
await c.subscribe('research-findings')
await c.publish('research-findings', { text: 'Hello, Cordelia' })
const items = await c.listen('research-findings')
```

## REST API

All endpoints are `POST /api/v1/channels/*` with bearer token auth.

| Endpoint | Purpose |
|----------|---------|
| `/subscribe` | Join or create an encrypted channel |
| `/publish` | Publish content (encrypted + signed) |
| `/listen` | Cursor-based item retrieval |
| `/search` | FTS5 full-text search with BM25 |
| `/list` | List subscribed channels |
| `/info` | Check channel existence |
| `/unsubscribe` | Leave a channel |
| `/dm` | Create bilateral DM |
| `/list-dms` | List DM channels |
| `/group` | Create group channel |
| `/group/invite` | Invite member (ECIES PSK envelope) |
| `/group/remove` | Remove member (PSK rotation) |
| `/list-groups` | List group channels |
| `/rotate-psk` | Manual key rotation |
| `/delete-item` | Tombstone an item |
| `/identity` | Node public keys and stats |

Full spec: [channels-api.md](https://github.com/seed-drill/strategy-and-planning/blob/main/specs/channels-api.md)

## Architecture

Rust workspace with 7 crates:

| Crate | Purpose | Tests |
|-------|---------|-------|
| `cordelia-core` | Shared types, config, errors | 5 |
| `cordelia-crypto` | Ed25519/X25519, ECIES, AES-256-GCM, Bech32 | 34 |
| `cordelia-storage` | SQLite, channels, items, PSK, FTS5 search | 83 |
| `cordelia-network` | Governor state machine (QUIC transport WIP) | 19 |
| `cordelia-api` | REST API, auth, handlers | 21 |
| `cordelia-node` | Binary: CLI, daemon lifecycle | - |
| `cordelia-test` | Test harness: TestNode, TestMesh | - |
| **Total** | | **162** |

## Cryptography

- **Identity**: Ed25519 keypair, X25519 derived via birational map
- **Channel encryption**: AES-256-GCM with 12-byte random IV
- **Key exchange**: ECIES (X25519 + HKDF-SHA256 + AES-256-GCM)
- **Signatures**: Ed25519 over deterministic CBOR metadata envelope
- **Key encoding**: Bech32 with `cordelia_pk1` / `cordelia_xpk1` / `cordelia_sig1` HRPs
- **PSK lifecycle**: Generation, rotation with key ring, ECIES envelope distribution

## Specs

All specifications: [seed-drill/specs/](https://github.com/seed-drill/strategy-and-planning/tree/main/specs)

Key specs:
- [channels-api.md](https://github.com/seed-drill/strategy-and-planning/blob/main/specs/channels-api.md) -- REST API
- [data-formats.md](https://github.com/seed-drill/strategy-and-planning/blob/main/specs/data-formats.md) -- SQLite schema, item format
- [ecies-encryption.md](https://github.com/seed-drill/strategy-and-planning/blob/main/specs/ecies-encryption.md) -- Cryptographic primitives
- [search-indexing.md](https://github.com/seed-drill/strategy-and-planning/blob/main/specs/search-indexing.md) -- FTS5 + semantic search
- [network-protocol.md](https://github.com/seed-drill/strategy-and-planning/blob/main/specs/network-protocol.md) -- QUIC transport, mini-protocols

## License

AGPL-3.0-only
