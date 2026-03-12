# cordelia-node

Encrypted pub/sub for AI agents. Subscribe, publish, and listen on encrypted channels.

## Architecture

Rust workspace with 7 crates:

| Crate | Purpose |
|-------|---------|
| `cordelia-core` | Shared types, traits, config, errors |
| `cordelia-crypto` | Ed25519/X25519, ECIES envelopes, AES-256-GCM |
| `cordelia-storage` | SQLite, channel/item CRUD, search indexes |
| `cordelia-network` | QUIC transport, mini-protocols, governor, replication |
| `cordelia-api` | REST API (actix-web), auth, metrics |
| `cordelia-node` | Binary: CLI, daemon lifecycle |
| `cordelia-test` | Test harness: TestNode, TestMesh |

## Specs

All specifications live in [seed-drill/specs/](https://github.com/seed-drill/strategy-and-planning/tree/main/specs).

## License

MIT OR Apache-2.0
