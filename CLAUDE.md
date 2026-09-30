# Claude Configuration - cordelia-node

> Inherits global rules from seed-drill/CLAUDE.md (quality over speed, commit format,
> security, no emojis). This file adds cordelia-node-specific context.

## What This Is

Cordelia: an AI agent's memory on every machine its operator uses, end-to-end
encrypted, carried by relays that hold no keys. v1 syncs Claude Code memory
(`crates/cordelia-sync`). Rust workspace, single binary daemon. QUIC transport,
CBOR wire format, Ed25519 per-device identity, AES-256-GCM channel encryption.
Design: `WHITEPAPER.md` (v3) and the decision record
`docs/decisions/2026-09-30-agent-memory-sync.md`. Code comments cite its
sections ("decision 2026-09-30 §4.3"). Specs predate v1: each live spec opens
with a "v1 status" note saying what v1 changed, and pre-v1 documents are in
`docs/archive/` (see its README).

## Repo Structure

```
cordelia-node/
  crates/
    cordelia-core/       # Shared types, config, errors
    cordelia-crypto/     # Ed25519/X25519, ECIES, AES-256-GCM, Bech32
    cordelia-storage/    # SQLite, channels, items, keys, trust, invites, sync state
    cordelia-network/    # Governor, codec, rate limiting, mini-protocols
    cordelia-api/        # REST API (actix-web), auth, handlers
    cordelia-sync/       # Sync adapters: Claude Code memory <-> channels
    cordelia-node/       # Binary: CLI, daemon lifecycle, p2p networking
    cordelia-test/       # Test harness: TestNode, TestMesh
  docs/
    specs/               # Protocol and component specs + TLA+ model
    decisions/           # ADRs; 2026-09-30-agent-memory-sync.md is the current design
    reference/           # Test vectors, network model, risk model
    archive/             # Pre-v1 documents, kept for history
    vision.md            # Direction after v1
  tests/                 # Integration tests
  deploy/relay/          # Relay image, Docker Compose and guide (Fly.io optional)
  scripts/               # Install script
  .github/workflows/     # ci.yml, e2e.yml, release.yml
```

## Key Specs

Start here when working on a module:

| Module | Spec |
|--------|------|
| v1 design (devices, keyed items, deletes, adapter, relays) | `docs/decisions/2026-09-30-agent-memory-sync.md` |
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
| Real-process tests | `crates/cordelia-node/tests/devices_e2e.rs` (`CORDELIA_E2E_KEEP=1` keeps node dirs) |
| Topology/E2E (stale, manual) | `docs/specs/topology-e2e.md`, `topology-scale.md` |
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
| `OUTBOX_FLUSH_INTERVAL_SECS` | 2s | parameter-rationale.md §4 |
| `KEYED_TOMBSTONE_RETENTION_DAYS` | 90 | decision 2026-09-30 §4.4 |
| `FALLBACK_PEERS` | relay1/relay2.cordelia.seeddrill.ai:9474 | decision 2026-09-30 §4.6 |

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

Feature work goes on branches (`feat/X`). Merge to main only after CI passes, including the real-process tests in `devices_e2e.rs`.

1. **Branch from main**: `git checkout -b feat/my-feature`
2. **Small, tested commits**: Each commit independently testable. Never bundle code + test harness changes.
3. **Test after each meaningful change**: Run `cargo test --all` locally; for P2P or sync changes, `cargo test -p cordelia-node --test devices_e2e`.
4. **PR to main**: Squash merge preserves clean history.
5. **Protocol changes get their own branch**: Wire format changes (codec, sync protocol) are never mixed with feature work.

## E2E topology and scale suites (stale)

The Docker topology suite (T1-T7) and the S2/S3 scale runs predate v1 and
are stale; `e2e.yml` runs only on demand. They ran on a self-hosted runner,
whose details are in the private infrastructure docs, not here. To run them
anywhere with Docker: `bash tests/e2e/build-image.sh`, then the scripts in
`tests/e2e/` (`run-e2e.sh`, `scale/run-s2.sh`, `scale/run-s3.sh`). v1 is
covered by `crates/cordelia-node/tests/devices_e2e.rs`.

## Related Repos

- **seed-drill** (strategy-and-planning): ROADMAP.md, STRATEGY.md, venture docs
- **seeddrill-website**: seeddrill.ai (Astro, Cloudflare Pages); `/install.sh` redirects to `scripts/install.sh` here
- **cordelia-sdk**: TypeScript SDK (`@seeddrill/cordelia`), deferred
- **ARCHIVED, do not use:** cordelia-core (old libp2p+JSON+axum implementation), cordelia-proxy,
  cordelia-agent-sdk, cordelia-dashboard, cordelia-portal, rutherford

## What NOT to Do

- Do not reference cordelia-core or the other archived repos for anything.
- Do not treat `docs/archive/` as current; it describes the pre-v1 design.
- Do not put specs in seed-drill. All Cordelia specs live here in docs/specs/.
- Do not add new timeout values without updating parameter-rationale.md.
- Do not change governor defaults without checking demand-model.md derivations.
- Do not add new protocol constants outside `protocol.rs`. All modules derive from it.
