# Testing Guide

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

**Current baseline:** 467 tests (315 Rust unit/integration + SDK + E2E smoke).
All must pass before any E2E testing.

## E2E Testing on cordelia-test VM

### SSH Access

```bash
ssh rezi@cordelia-test
export PATH=$HOME/.cargo/bin:$PATH
cd ~/actions-runner/_work/cordelia-node/cordelia-node
```

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
| E2E Smoke | `tests/e2e/smoke-test.sh` | Single node API | `bash tests/e2e/smoke-test.sh` |
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
