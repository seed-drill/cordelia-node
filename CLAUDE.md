# Claude Configuration - cordelia-node

> Inherits global rules from seed-drill/CLAUDE.md (quality over speed, commit format,
> security, no emojis). This file adds cordelia-node-specific context.

## What This Is

Encrypted pub/sub for AI agents. Rust workspace, single binary daemon.
QUIC transport, CBOR wire format, Ed25519 identity, AES-256-GCM channel encryption.

## Repo Structure

```
cordelia-node/
  crates/
    cordelia-core/       # Shared types, config, errors
    cordelia-crypto/     # Ed25519/X25519, ECIES, AES-256-GCM, Bech32
    cordelia-storage/    # SQLite, channels, items, PSK, FTS5 search
    cordelia-network/    # Governor, codec, rate limiting, mini-protocols
    cordelia-api/        # REST API (actix-web), auth, handlers
    cordelia-node/       # Binary: CLI, daemon lifecycle, p2p networking
    cordelia-test/       # Test harness: TestNode, TestMesh
  docs/
    specs/               # 28 specification files + TLA+ model
    decisions/           # Active ADRs (architecture, economics, identity)
    reference/           # Cherry-picked research (game theory, test vectors, network model)
  tests/                 # Integration tests
  deploy/                # Bootnode Dockerfile, Fly.io configs
  scripts/               # Install script
  .github/workflows/     # ci.yml, e2e.yml, release.yml
```

## Key Specs

Start here when working on a module:

| Module | Spec |
|--------|------|
| Wire format | `docs/specs/network-protocol.md` (Section 3: CBOR tags, framing) |
| Mini-protocols | `docs/specs/network-protocol.md` (Sections 4-8) |
| Governor | `docs/specs/network-behaviour.md` |
| Channels/API | `docs/specs/channels-api.md` |
| Encryption | `docs/specs/ecies-envelope-encryption.md` |
| Data/storage | `docs/specs/data-formats.md` |
| Parameters | `docs/specs/parameter-rationale.md` (every value explained) |
| Demand model | `docs/specs/demand-model.md` (persona-derived rates) |
| Identity | `docs/specs/identity.md` |
| Config | `docs/specs/configuration.md` |
| Search | `docs/specs/search-indexing.md` |
| Topology/E2E | `docs/specs/topology-e2e.md`, `topology-scale.md` |
| TLA+ model | `docs/specs/network-protocol.tla` + `.cfg` |

## Key Parameters (from spec + code)

These are the canonical values. If code disagrees with spec, the spec wins.

| Parameter | Value | Source |
|-----------|-------|--------|
| `STREAM_TIMEOUT` | 10s | `cordelia-network/src/codec.rs` -- ONE timeout for all reads/writes |
| `MAX_ITEM_BYTES` | 256KB | `cordelia-network/src/rate_limit.rs` |
| `keep_alive_interval` | 15s | QUIC transport keepalive |
| `max_idle_timeout` | 60s | QUIC connection idle timeout |
| `ping_interval` | 30s | Application-level keepalive |
| `keepalive_timeout` | 90s | 3 missed pings = dead |
| `hot_max` | 2 (personal) / 50 (relay) | Governor |
| `warm_max` | 10 (personal) | Governor |
| `min_warm_tenure` | 300s | Anti-Sybil: warm before hot promotion |
| `churn_interval` | 3600s + 0-300s jitter | Anti-eclipse rotation |
| `max_connections_per_ip` | 5 | Rate limiting |

## Running Tests

```bash
# All tests
cargo test --all

# Specific crate
cargo test -p cordelia-network
cargo test -p cordelia-crypto

# With coverage (requires llvm-tools-preview + grcov)
CARGO_INCREMENTAL=0 RUSTFLAGS='-Cinstrument-coverage' \
  LLVM_PROFILE_FILE='coverage/cargo-test-%p-%m.profraw' \
  cargo test --all
grcov . --binary-path ./target/debug/deps -s . -t lcov --branch \
  --ignore-not-existing --ignore '../*' -o coverage/lcov.info
```

## Engineering Principles

1. **Self-defending functions**: Public async functions have built-in timeouts.
   Don't rely on callers to timeout -- if a test can break it, the code handles it.

2. **Minimise timeout diversity**: One value (STREAM_TIMEOUT=10s) at one layer
   (codec) for all stream I/O. Add a new timeout only with documented justification.

3. **Spec is source of truth**: Parameter values derive from `demand-model.md`
   personas. If you change a value, update the spec and the rationale.

## Related Repos

- **seed-drill** (strategy-and-planning): ROADMAP.md, STRATEGY.md, venture docs
- **cordelia-sdk**: TypeScript SDK (`@seeddrill/cordelia`)
- **cordelia-agent-sdk**: Agent SDK (renamed from original cordelia-sdk)
- **cordelia-core**: ARCHIVED -- old libp2p+JSON+axum implementation, do not use

## What NOT to Do

- Do not reference cordelia-core for anything. It is archived.
- Do not put specs in seed-drill. All Cordelia specs live here in docs/specs/.
- Do not add new timeout values without updating parameter-rationale.md.
- Do not change governor defaults without checking demand-model.md derivations.
