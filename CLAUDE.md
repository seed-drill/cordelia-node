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

## Key Parameters (from protocol.rs)

All protocol constants live in `crates/cordelia-core/src/protocol.rs` -- the single source of truth.
Do not add new protocol constants outside `protocol.rs`. All other modules derive from it.

| Parameter | Value | Spec Section |
|-----------|-------|-------------|
| `STREAM_TIMEOUT_SECS` | 10s | parameter-rationale.md §5.3 |
| `MAX_MESSAGE_BYTES` | 1MB | parameter-rationale.md §5.2 |
| `MAX_ITEM_BYTES` | 256KB | parameter-rationale.md §4 |
| `QUIC_KEEPALIVE_INTERVAL_SECS` | 15s | network-protocol.md §2.1 |
| `QUIC_MAX_IDLE_TIMEOUT_SECS` | 60s | network-protocol.md §2.1 |
| `PING_INTERVAL_SECS` | 30s | network-protocol.md §4.2 |
| `DEAD_TIMEOUT_SECS` | 90s | network-protocol.md §4.2 |
| `HOT_MAX` | 2 (personal) | parameter-rationale.md §3 |
| `WARM_MAX` | 10 (personal) | parameter-rationale.md §3 |
| `COLD_MAX` | 50 (personal) | parameter-rationale.md §3 |
| `MIN_WARM_TENURE_SECS` | 300s | parameter-rationale.md §3 |
| `CHURN_INTERVAL_SECS` | 3600s | parameter-rationale.md §3 |
| `EMA_ALPHA` | 0.1 | parameter-rationale.md §3 |
| `MAX_CONNECTIONS_PER_IP` | 5 | network-protocol.md §9.1 |

## Running Tests

See **[TESTING.md](TESTING.md)** for the full testing guide: pre-flight checks, Docker cleanup,
build steps, all test suites (unit, integration, S2/S3 scale), known-good baselines,
common failure modes, and post-test verification.

Quick reference:
```bash
# All unit + integration tests
cargo test --all

# Specific crate
cargo test -p cordelia-network
cargo test -p cordelia-crypto
```

## Engineering Principles

1. **Self-defending functions**: Public async functions have built-in timeouts.
   Don't rely on callers to timeout -- if a test can break it, the code handles it.

2. **Minimise timeout diversity**: One value (STREAM_TIMEOUT=10s) at one layer
   (codec) for all stream I/O. Add a new timeout only with documented justification.

3. **Spec is source of truth**: Parameter values derive from `demand-model.md`
   personas. If you change a value, update the spec and the rationale.

## Branch and Merge Workflow

Feature work goes on branches (`feat/X`). Merge to main only after E2E passes.

1. **Branch from main**: `git checkout -b feat/my-feature`
2. **Small, tested commits**: Each commit independently testable. Never bundle code + test harness changes.
3. **Test after each meaningful change**: Run `cargo test --all` locally, run S2 R=20 on cordelia-test for P2P changes.
4. **Tag known-good states**: After S2/S3 passes, tag: `git tag s2-passing-<commit-short>`
5. **PR to main**: Only after E2E passes on the branch. Squash merge preserves clean history.
6. **Protocol changes get their own branch**: Wire format changes (codec, sync protocol) are never mixed with feature work.

## E2E Testing on cordelia-test VM

```bash
ssh rezi@cordelia-test
export PATH=$HOME/.cargo/bin:$PATH
cd ~/actions-runner/_work/cordelia-node/cordelia-node

# Clean state (ALWAYS do this before testing)
docker rm -f $(docker ps -aq) 2>/dev/null
docker network prune -f 2>/dev/null
docker volume prune -af 2>/dev/null
sudo rm -rf tests/e2e/scale/s2-* tests/e2e/scale/s3-* tests/e2e/logs tests/e2e/scale/keys

# Build + image
cargo build --release --target x86_64-unknown-linux-musl --bin cordelia
cp target/x86_64-unknown-linux-musl/release/cordelia cordelia-bin
DOCKER_BUILDKIT=0 docker build --no-cache -t cordelia-test:latest \
  -f tests/e2e/Dockerfile --build-arg BINARY=cordelia-bin .
rm cordelia-bin

# S2 (relay mesh convergence)
bash tests/e2e/scale/run-s2.sh 20        # R=20, 42 containers
bash tests/e2e/scale/run-s2.sh 50        # R=50, 102 containers

# S3 (PAN swarm)
bash tests/e2e/scale/run-s3.sh 4         # 2 leads + 8 swarm, 13 containers
```

Note: root-owned key files from Docker need `sudo rm -rf` to clean.

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
- Do not add new protocol constants outside `protocol.rs`. All modules derive from it.
