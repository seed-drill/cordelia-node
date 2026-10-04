# Testing Guide

> **v1 status (2026-09-30).** `cargo test --all` runs everything v1 needs,
> including real-process tests over QUIC through a relay
> (`crates/cordelia-node/tests/devices_e2e.rs`; set `CORDELIA_E2E_KEEP=1` to
> keep the node directories). The toolchain is pinned in `rust-toolchain.toml`,
> so `rustup update stable` is not needed. The Docker topology and scale suites
> below predate v1 and are stale.

## Pre-flight Checks

Before running any tests:

```bash
# Ensure Rust toolchain is current
rustup update stable

# Check workspace compiles
cargo build --all
```

## Local Tests (cargo)

```bash
# All unit + integration tests
cargo test --all

# Specific crate
cargo test -p cordelia-network
cargo test -p cordelia-crypto
cargo test -p cordelia-storage
cargo test -p cordelia-core

# Single test by name
cargo test -p cordelia-network test_batched_sync_two_channels

# With output (for debugging)
cargo test -p cordelia-network -- --nocapture
```

**Baseline:** every test of `cargo test --all` passes. (The count changes with
almost every change: the pull request that changed it last says what it is.)

## E2E topology and scale suites (stale)

These suites predate v1 and are stale; `e2e.yml` runs them only on demand.
Run them from the repository root on any Linux host with Docker and the
musl target. They used to run on a self-hosted runner, whose details are in
the private infrastructure docs.

### Docker Cleanup (ALWAYS do this first)

Root-owned key files from Docker need `sudo rm -rf`.

```bash
docker rm -f $(docker ps -aq) 2>/dev/null
docker network prune -f 2>/dev/null
docker volume prune -af 2>/dev/null
sudo rm -rf tests/e2e/scale/s2-* tests/e2e/scale/s3-* tests/e2e/logs tests/e2e/scale/keys
```

### Build + Docker Image

```bash
cargo build --release --target x86_64-unknown-linux-musl --bin cordelia
cp target/x86_64-unknown-linux-musl/release/cordelia cordelia-bin
DOCKER_BUILDKIT=0 docker build --no-cache -t cordelia-test:latest \
  -f tests/e2e/Dockerfile --build-arg BINARY=cordelia-bin .
rm cordelia-bin
```

### S2: Relay Mesh Convergence

Tests relay mesh formation, pull-sync delivery, and item propagation across R relays + 2 personal nodes.

```bash
bash tests/e2e/scale/run-s2.sh 20        # R=20, 42 containers (fast)
bash tests/e2e/scale/run-s2.sh 50        # R=50, 102 containers (full scale)
```

**Known-good baselines (b3e631d):**
- R=20: ~30s mesh, ~10s delivery, 62/62 assertions pass
- R=50: ~185s mesh, ~17s delivery, 152/152 assertions pass

### S3: PAN Swarm Propagation

Tests personal area network (swarm) nodes syncing local-scope channels from their lead.

```bash
bash tests/e2e/scale/run-s3.sh 4         # 2 leads + 8 swarm, 13 containers
```

### T1-T7: Topology Tests

Individual topology scenarios (single relay, multi-relay, etc.).

```bash
bash tests/e2e/run-e2e.sh                # Runs all T1-T7
```

## Test Suites Summary

| Suite | Location | What it tests | Run command |
|-------|----------|---------------|-------------|
| Unit | `crates/*/src/**` | Per-module logic | `cargo test --all` |
| Integration | `crates/cordelia-network/tests/` | Two-node QUIC | `cargo test -p cordelia-network` |
| E2E Smoke (stale) | `tests/e2e/smoke-test.sh` | Single node API as it was before v1: four of its checks no longer match. Its node is given a relay on this machine where nothing listens, so it dials nothing else | `bash tests/e2e/smoke-test.sh` |
| S2 Scale | `tests/e2e/scale/run-s2.sh` | Relay mesh + delivery | `bash tests/e2e/scale/run-s2.sh R` |
| S3 Scale | `tests/e2e/scale/run-s3.sh` | PAN swarm | `bash tests/e2e/scale/run-s3.sh N` |

## Common Failure Modes

| Symptom | Cause | Fix |
|---------|-------|-----|
| `address already in use` | Previous containers still running | Docker cleanup (see above) |
| `permission denied` on key files | Root-owned Docker artifacts | `sudo rm -rf tests/e2e/scale/s2-*` |
| Mesh timeout at large R | Stale Docker networks | `docker network prune -f` first |
| Pull-sync rate limited | 3+ channels per stream (pre-batch) | Batched sync (§4.5) fixes this |
| `cargo build` fails on VM | Missing musl target | `rustup target add x86_64-unknown-linux-musl` |

## Post-Test Verification

After S2/S3 pass, tag the known-good state:

```bash
git tag s2-passing-$(git rev-parse --short HEAD)
git tag s3-passing-$(git rev-parse --short HEAD)
```

Check relay logs for telemetry:

```bash
docker logs s2-relay-1 2>&1 | grep "p2p heartbeat"
docker logs s2-relay-1 2>&1 | grep "gov: tick complete"
docker logs s2-relay-1 2>&1 | grep "pull-sync cycle"
```
