# Topology E2E Testing Specification

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-12
**Scope**: Phase 1 (WP15, depends on WP3 + WP14)
**Depends on**: specs/network-protocol.md, specs/network-protocol.tla, specs/operations.md, specs/channels-api.md
**Implements**: decisions/2026-03-10-testing-strategy-bdd.md (Layer 2: Topology E2E)

---

## 1. Purpose

Topology E2E tests validate that the Rust implementation conforms to the TLA+ formal model. Each test spins up a Docker Compose topology with specific node roles, connectivity, and push policies, then asserts that the 9 formal properties (P1-P9) hold under those conditions.

These tests bridge the gap between model checking (abstract, bounded) and production (real nodes, real networks, real timing). If TLA+ says delivery holds and the E2E test says it doesn't, there is an implementation bug.

### 1.1 Design Principles

1. **Property-driven.** Every test asserts one or more TLA+ properties. No test exists "just to see if it works."
2. **Deterministic pass/fail.** No flaky tests. Use convergence polling with bounded timeout, not fixed sleeps.
3. **Reproducible.** Docker Compose + pinned image = same test on any machine with Docker.
4. **Fast.** Full suite < 10 minutes on the self-hosted runner. Individual topology < 90 seconds.
5. **Debuggable.** On failure: collect logs, SQLite dumps, and metrics. CI artifacts preserved for 7 days.

---

## 2. Infrastructure

### 2.1 Self-Hosted Runner

| Property | Value |
|----------|-------|
| VM | `cordelia-test` (pdukvm20) |
| Address | `192.168.3.206` |
| OS | Ubuntu 24.04 |
| CPU | 8 cores |
| RAM | 32 GB |
| Docker | 29.2+ |
| Runner labels | `[self-hosted, cordelia-docker]` |
| Service | `actions.runner.seed-drill.cordelia-test` |

### 2.2 Container Image

A single Docker image is used for all node roles. The role is determined by `config.toml` at startup, not at build time.

```dockerfile
FROM debian:bookworm-slim

# Install dependencies first (changes rarely -- maximises layer cache hits)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates sqlite3 iproute2 iptables curl jq \
    && rm -rf /var/lib/apt/lists/*

VOLUME /data/cordelia
ENV CORDELIA_DATA_DIR=/data/cordelia

# P2P (QUIC/UDP) + REST API (TCP, localhost only inside container)
EXPOSE 9474/udp 9473/tcp

# Binary COPY last -- this layer changes every build
ARG BINARY=cordelia
COPY ${BINARY} /usr/local/bin/cordelia
RUN chmod 755 /usr/local/bin/cordelia

ENTRYPOINT ["cordelia", "start"]
```

**Build**: The binary MUST be statically linked using the musl target. The Docker image MUST be built with the classic builder (`DOCKER_BUILDKIT=0`) and `--no-cache` to prevent buildx from caching stale dynamically-linked binaries that cause `GLIBC_2.38` errors at runtime.

```bash
# Use the helper script (recommended):
bash tests/e2e/build-image.sh

# Or manually:
cargo build --release --target x86_64-unknown-linux-musl --bin cordelia
docker builder prune -af           # clear buildx cache
docker image prune -af             # clear stale images
DOCKER_BUILDKIT=0 docker build --no-cache -t cordelia-test:latest \
    -f tests/e2e/Dockerfile \
    --build-arg BINARY=target/x86_64-unknown-linux-musl/release/cordelia .
```

The Dockerfile includes a build-time `ldd` check that fails the build if the binary is dynamically linked. Prerequisites: `rustup target add x86_64-unknown-linux-musl` and `apt install musl-tools`.

**Packages installed in image:**
- `sqlite3`: assertion queries against node databases
- `iproute2`: `tc` for network simulation (latency injection)
- `iptables`: partition simulation (T5, requires `--cap-add=NET_ADMIN`)
- `curl` + `jq`: health checks, metrics queries, REST API assertions
- `ca-certificates`: TLS root certificates

### 2.3 Zone-Based Network Model

Topologies use multiple Docker bridge networks to simulate production deployment zones. Personal nodes sit behind NAT on isolated home networks and can only reach relays/bootnodes, not each other directly. This prevents peer-sharing from bypassing relay-mediated traffic (which caused T2 to fail on flat networks).

#### 2.3.1 Production Deployment Mapping

| Production | Docker Zone | Model |
|------------|-------------|-------|
| Home personal node behind NAT | `home-N` network (isolated) | Can only reach B1/R1 on its own zone |
| Enterprise node behind firewall | `enterprise` network (isolated) | Edge relay bridges enterprise <-> internet |
| Relay (internet-facing) | `internet` + assigned zone networks | Multi-homed, bridges zones |
| Bootnode (internet-facing) | `internet` + all zone networks | Multi-homed, discovery only |

#### 2.3.2 IP Addressing Scheme

Each zone gets its own /24 within 172.28.0.0/16:

| Network | Subnet | Residents |
|---------|--------|-----------|
| `internet` | `172.28.0.0/24` | Bootnodes (.10+), Relays (.20+) |
| `home-1` | `172.28.1.0/24` | P1 (.30), B1 (.10), R1 (.20) |
| `home-2` | `172.28.2.0/24` | P2 (.30), B1 (.10), R1 (.20) |
| `home-3` | `172.28.3.0/24` | P3 (.30), B1 (.10), R1 (.20) |
| `enterprise` | `172.28.4.0/24` | P3 (.30), B1 (.10), R2 (.20) |

Within each /24: `.10-.19` bootnodes, `.20-.29` relays, `.30-.79` personal nodes.

#### 2.3.3 Multi-Homed Rules

- **Bootnodes**: on `internet` + every home/enterprise network (public discovery service)
- **Relays**: on `internet` + assigned home/enterprise networks (bridge between zones)
- **Personal nodes**: on their own home/enterprise network ONLY

When B1 shares P2's address (172.28.2.30) with P1 via peer-sharing, P1 cannot reach 172.28.2.0/24 because P1 is only on home-1 (172.28.1.0/24). The dial fails silently. Items flow through the relay. This is the desired behaviour with zero code changes to Cordelia.

#### 2.3.4 Flat Network Topologies

T1 (Minimal) and T6 (Bootnode Loss) remain on a single flat `cordelia-net` (172.28.0.0/24). These test direct peer-to-peer discovery and replication without relays, where zone isolation is not relevant.

#### 2.3.5 Example (T2 zone model)

```yaml
networks:
  internet:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/24
  home-1:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.1.0/24
  home-2:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.2.0/24
```

Nodes receive static IPs within their zone for deterministic addressing:

| Role | Internet IP | Zone IP | Example |
|------|------------|---------|---------|
| Bootnodes | 172.28.0.10-19 | 172.28.{zone}.10-19 | B1: 172.28.0.10 (internet), 172.28.1.10 (home-1) |
| Relays | 172.28.0.20-29 | 172.28.{zone}.20-29 | R1: 172.28.0.20 (internet), 172.28.1.20 (home-1) |
| Personal nodes | -- | 172.28.{zone}.30-79 | P1: 172.28.1.30 (home-1 only) |

#### 2.3.1 Known Limitations

**QUIC on Docker bridge networks:** QUIC connection establishment on Docker bridge networks is sensitive to connection ordering. When a relay connects to a bootnode before personal nodes start, subsequent connections from personal nodes to the bootnode may time out. This is a Docker/kernel-level issue, not a protocol bug.

**Mitigations:**
1. Start personal nodes and relays simultaneously (all `depends_on` bootnode, not on each other)
2. Use the 10s bootstrap timeout (network-protocol.md §10.3) to skip unreachable bootnodes quickly
3. Rely on peer-sharing (§4.3) and Item-Sync pull (§4.5) as fallback delivery mechanisms
4. T1 and T6 topologies (no relay) are not affected

**All containers use the same P2P port (9474).** Unique ports per container were tested and did not resolve the ordering issue.

**Kernel conntrack tuning (REQUIRED for sequential test runs):** QUIC uses UDP. Docker bridge networking uses kernel conntrack to track UDP flows. Default `nf_conntrack_udp_timeout_stream = 120s` means stale entries from previous topologies persist for 2 minutes after teardown, interfering with subsequent QUIC connections. Apply these settings on the test VM:

```bash
sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout=10
sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=30
sudo apt-get install -y conntrack  # for conntrack -F flush tool
```

The `run-all.sh` master script flushes conntrack between topologies (`conntrack -F`). Without this, T5 (and other multi-hop topologies) fail intermittently when run after T1-T4.

### 2.4 Node Initialisation

Each container runs `cordelia init` on first start, then `cordelia start`. `cordelia init` generates the identity keypair, node-token (32 bytes CSPRNG, hex-encoded, written to `$CORDELIA_DATA_DIR/node-token`), and default config (operations.md SS2). The `--name` flag sets the human-readable node name (operations.md SS2.1: defaults to OS username if omitted). The `--non-interactive` flag suppresses prompts. The entrypoint script:

```bash
#!/bin/bash
set -euo pipefail

# Initialise if no identity exists
if [ ! -f "$CORDELIA_DATA_DIR/identity.key" ]; then
    cordelia init --name "$NODE_NAME" --non-interactive
fi

# Copy topology-specific config
cp /config/config.toml "$CORDELIA_DATA_DIR/config.toml"

# Start node
exec cordelia start
```

Config files are mounted from the host via Docker volume:

```yaml
volumes:
  - ./configs/personal-1.toml:/config/config.toml:ro
```

---

## 3. Topology Definitions

### 3.1 Overview

Seven reference topologies cover all role interactions, push policies, and failure modes defined in the TLA+ model.

| ID | Name | Nodes | Properties Tested | Estimated Duration |
|----|------|-------|-------------------|-------------------|
| T1 | Minimal | 2P + 1B | P1, P3, P7 | ~30s |
| T2 | Relay path | 2P + 1B + 1R | P1, P4, P5, P7 | ~40s |
| T3 | Pull-only | 2P + 1B + 1R | P2, P8 | ~70s |
| T4 | Multi-relay | 3P + 1B + 2R | P1, P4, P5 | ~50s |
| T5 | Partition/heal | 2P + 2R + 1B | P6 | ~90s |
| T6 | Bootnode loss | 3P + 1B | P1, P7, P9 | ~60s |
| T7 | Channel isolation | 3P + 1R + 1B | P3, P4 | ~40s |

**Total estimated suite time**: ~6-7 minutes (sequential). Parallelisation across 2-3 compose stacks possible on the 32 GB runner.

### 3.2 T1: Minimal (2P + 1B)

**Purpose**: Baseline. Two personal nodes discover each other via a bootnode. One publishes, the other receives.

**Topology**:
```
[P1] ---- [B1] ---- [P2]
```

**Node configuration**:

| Node | Role | push_policy | Channels | IP |
|------|------|-------------|----------|-----|
| `p1` | personal | subscribers_only | `test-channel` | 172.28.0.30 |
| `p2` | personal | subscribers_only | `test-channel` | 172.28.0.31 |
| `b1` | bootnode | -- | -- | 172.28.0.10 |

**Config (p1.toml)**:
```toml
[identity]
entity_id = "p1_test"

[node]
http_port = 9473
p2p_port = 9474
data_dir = "/data/cordelia"

[network]
listen_addr = "0.0.0.0:9474"
role = "personal"
push_policy = "subscribers_only"

[[network.bootnodes]]
addr = "172.28.0.10:9474"

[governor]
hot_min = 1
hot_max = 5
warm_min = 1
warm_max = 5
cold_max = 10
tick_interval_secs = 2
min_warm_tenure_secs = 5
keepalive_timeout_secs = 30

[replication]
sync_interval_realtime_secs = 10
tombstone_retention_days = 1
max_batch_size = 50

[api]
bind_address = "127.0.0.1"

[logging]
level = "debug"    # Required for P8/P9 log assertions (SS4.3)
```

**Config (b1.toml)** -- bootnode:
```toml
[identity]
entity_id = "b1_test"

[node]
http_port = 9473
p2p_port = 9474
data_dir = "/data/cordelia"

[network]
listen_addr = "0.0.0.0:9474"
role = "bootnode"

[governor]
hot_min = 1
hot_max = 10
warm_min = 1
warm_max = 10
cold_max = 20
tick_interval_secs = 2
min_warm_tenure_secs = 5
keepalive_timeout_secs = 30

[api]
bind_address = "127.0.0.1"

[logging]
level = "debug"
```

Bootnode configs omit `[replication]` and `push_policy` (bootnodes do not replicate or push -- SS3.7 T6, P9). Relay configs are identical to bootnode except `role = "relay"` and include `[replication]` for store-and-forward.

**Note**: `api.bind_address` remains `"127.0.0.1"` (loopback) in test configs. All assertion queries use `docker exec` to run `curl` inside the container, so loopback access is sufficient. No `0.0.0.0` override or escape hatch is needed.

**Governor tuning for tests**: Tick interval 2s (not 10s), min_warm_tenure 5s (not 300s), sync interval 10s (not 60s). Tests need fast convergence; production defaults are too slow for sub-90s tests.

**Docker Compose (`topologies/t1.yml`)**:

No host port mappings (`ports:`) are needed. Containers communicate directly via the bridge network using static IPs. All assertion queries use `docker exec` to run inside the container, so the API (bound to 127.0.0.1) is reachable without host exposure.

```yaml
name: t1-minimal

services:
  b1:
    image: ${CORDELIA_IMAGE:-cordelia-test:latest}
    container_name: t1-b1
    hostname: b1
    cap_add: [NET_ADMIN]
    environment:
      - NODE_NAME=b1
      - CORDELIA_DATA_DIR=/data/cordelia
    volumes:
      - ./configs/t1/b1.toml:/config/config.toml:ro
      - ./entrypoint.sh:/entrypoint.sh:ro
    entrypoint: ["/bin/bash", "/entrypoint.sh"]
    networks:
      cordelia-net:
        ipv4_address: 172.28.0.10
    # GET /api/v1/health is unauthenticated, returns 200/503 (operations.md SS8)
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:9473/api/v1/health"]
      interval: 5s
      timeout: 3s
      retries: 6
      start_period: 15s

  p1:
    image: ${CORDELIA_IMAGE:-cordelia-test:latest}
    container_name: t1-p1
    hostname: p1
    cap_add: [NET_ADMIN]
    environment:
      - NODE_NAME=p1
      - CORDELIA_DATA_DIR=/data/cordelia
    volumes:
      - ./configs/t1/p1.toml:/config/config.toml:ro
      - ./entrypoint.sh:/entrypoint.sh:ro
    entrypoint: ["/bin/bash", "/entrypoint.sh"]
    networks:
      cordelia-net:
        ipv4_address: 172.28.0.30
    depends_on:
      b1:
        condition: service_healthy

  p2:
    image: ${CORDELIA_IMAGE:-cordelia-test:latest}
    container_name: t1-p2
    hostname: p2
    cap_add: [NET_ADMIN]
    environment:
      - NODE_NAME=p2
      - CORDELIA_DATA_DIR=/data/cordelia
    volumes:
      - ./configs/t1/p2.toml:/config/config.toml:ro
      - ./entrypoint.sh:/entrypoint.sh:ro
    entrypoint: ["/bin/bash", "/entrypoint.sh"]
    networks:
      cordelia-net:
        ipv4_address: 172.28.0.31
    depends_on:
      b1:
        condition: service_healthy

networks:
  cordelia-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/24
```

**Test sequence**:
1. `docker compose -f topologies/t1.yml up -d`
2. Wait for all nodes healthy (healthcheck passes)
3. Wait for bootstrap: poll `POST /api/v1/status` on p1 and p2 until `peers_hot >= 1` (timeout: 30s)
4. Create channel `test-channel` on p1 via `POST /api/v1/channels/subscribe`
5. Subscribe p2 to `test-channel` (requires PSK distribution -- see SS3.9)
6. Publish 3 items on p1 via `POST /api/v1/channels/publish`
7. Poll p2 via `POST /api/v1/channels/listen` until 3 items received (timeout: 30s, poll interval: 2s)
8. Assert P1 (Delivery): all 3 item_ids present on p2
9. Assert P3 (Channel isolation): p1 and p2 store items only for `test-channel`
10. Assert P7 (Bootstrap): both p1 and p2 report `peers_hot >= 1`
11. Collect logs and tear down

**PSK distribution in tests (SS3.9)**: For test simplicity, all nodes in a topology that share a channel use a pre-generated PSK file mounted via Docker volume. The PSK file (32 bytes from CSPRNG) is generated once per test run by the harness script. The file MUST be named by the channel's derived `channel_id`, not the human-readable name:

1. Harness computes `channel_id = hex(SHA-256("cordelia:channel:" + lowercase(channel_name)))` using `channel_id_for()` from common.sh (matches channels-api.md SS3.1).
2. PSK file is written to `tests/e2e/keys/<channel_id>.key`.
3. Docker volume mounts the file to `$CORDELIA_DATA_DIR/channel-keys/<channel_id>.key` on each participating node.

Example for `test-channel`:
```bash
CID=$(channel_id_for "test-channel")
dd if=/dev/urandom bs=32 count=1 of="tests/e2e/keys/${CID}.key" 2>/dev/null
```

Docker volume mount (in Compose):
```yaml
volumes:
  - ./keys/${CID}.key:/data/cordelia/channel-keys/${CID}.key:ro
```

This bypasses the ECIES PSK-Exchange protocol, which is tested separately in unit/integration tests.

### 3.3 T2: Relay Path (2P + 1B + 1R)

**Purpose**: Items flow through a relay. Validates store-and-forward, relay re-push, and role isolation (relay stores ciphertext, never holds PSKs).

**Zone model**: `internet`, `home-1`, `home-2`. P1 and P2 are zone-isolated -- they cannot reach each other directly. All item traffic must flow through R1.

**Topology**:
```
home-1           internet          home-2
[P1] ---- [R1] ---- [B1] ---- [R1] ---- [P2]
```

**Node configuration**:

| Node | Role | push_policy | Channels | Zone(s) | Zone IP(s) |
|------|------|-------------|----------|---------|------------|
| `b1` | bootnode | -- | -- | internet, home-1, home-2 | .0.10, .1.10, .2.10 |
| `r1` | relay | -- | (all, transparent) | internet, home-1, home-2 | .0.20, .1.20, .2.20 |
| `p1` | personal | subscribers_only | `test-channel` | home-1 only | .1.30 |
| `p2` | personal | subscribers_only | `test-channel` | home-2 only | .2.30 |

Personal nodes bootstrap via zone-local B1 and R1 addresses:

```toml
# P1 config -- bootnodes on home-1 zone
[[network.bootnodes]]
addr = "172.28.1.10:9474"

[[network.bootnodes]]
addr = "172.28.1.20:9474"
```

**Test sequence**:
1. Bring up all 4 nodes
2. Wait for bootstrap + peer connections
3. Subscribe both P1 and P2 to `test-channel`
4. Publish 5 items on P1
5. Poll P2 until all 5 items received (timeout: 30s)
6. Assert P1 (Delivery): all 5 items on P2
7. Assert P4 (Role isolation -- relay): `docker exec t2-r1 ls /data/cordelia/channel-keys/` returns empty. `docker exec t2-r1 sqlite3 /data/cordelia/cordelia.db "SELECT COUNT(*) FROM items"` returns > 0 (relay stores ciphertext)
8. Assert P4 (Role isolation -- bootnode): `docker exec t2-b1 sqlite3 /data/cordelia/cordelia.db "SELECT COUNT(*) FROM items"` returns 0 (bootnode stores nothing)
9. Assert P5 (Loop termination): check relay metrics `cordelia_item_push_total` is bounded (at most items_published * hot_max)

### 3.4 T3: Pull-Only (2P + 1B + 1R)

**Purpose**: A `pull_only` node receives items exclusively via Item-Sync, never via Item-Push. Validates anti-entropy as the sole delivery mechanism.

**Zone model**: Same as T2 (`internet`, `home-1`, `home-2`). P2 pulls from R1 via zone-local address.

**Topology**:
```
home-1                  internet                  home-2
[P1 subscribers_only] ---- [R1] ---- [B1] ---- [R1] ---- [P2 pull_only]
```

**Node configuration**:

| Node | Role | push_policy | Channels | Zone(s) | Zone IP(s) |
|------|------|-------------|----------|---------|------------|
| `b1` | bootnode | -- | -- | internet, home-1, home-2 | .0.10, .1.10, .2.10 |
| `r1` | relay | -- | (all) | internet, home-1, home-2 | .0.20, .1.20, .2.20 |
| `p1` | personal | subscribers_only | `test-channel` | home-1 only | .1.30 |
| `p2` | personal | pull_only | `test-channel` | home-2 only | .2.30 |

**Test configuration**: `sync_interval_realtime_secs = 10` on P2 (fast pull for testing).

**Test sequence**:
1. Bring up all 4 nodes, wait for bootstrap
2. Subscribe both nodes to `test-channel`
3. Publish 3 items on P1
4. Wait for P2 to receive items via anti-entropy (timeout: 30s, must be > sync_interval)
5. Assert P2 (Pull delivery): all 3 items on P2
6. Assert P8 (Push silence): inspect P2 logs for Item-Push (0x06) send events -- expect 0 outbound pushes from P2. Method: `docker logs t3-p2 | grep -c "Item-Push send"` = 0

**Timing note**: This test inherently takes longer than push-based tests (bounded by `sync_interval_realtime_secs`). With 10s sync interval, items arrive within 10-20s. The 30s timeout provides margin.

### 3.5 T4: Multi-Relay (3P + 1B + 2R)

**Purpose**: Fan-out across multiple relays. Validates that items reach all personal nodes without duplication and that relay re-push does not create infinite loops.

**Zone model**: `internet`, `home-1`, `home-2`, `enterprise`. R1 serves home zones, R2 is the enterprise edge relay.

**Topology**:
```
home-1          internet          home-2
[P1] ---- [R1] ---- [B1] ---- [R1] ---- [P2]
                      |
                    [R2]
                      |
                    [P3]           enterprise
```

**Node configuration**:

| Node | Role | Channels | Zone(s) | Zone IP(s) |
|------|------|----------|---------|------------|
| `b1` | bootnode | -- | all (internet, home-1, home-2, enterprise) | .0.10, .1.10, .2.10, .4.10 |
| `r1` | relay | (all) | internet, home-1, home-2 | .0.20, .1.20, .2.20 |
| `r2` | relay | (all) | internet, enterprise | .0.21, .4.20 |
| `p1` | personal | `test-channel` | home-1 only | .1.30 |
| `p2` | personal | `test-channel` | home-2 only | .2.30 |
| `p3` | personal | `test-channel` | enterprise only | .4.30 |

**Test sequence**:
1. Bring up all 6 nodes, wait for bootstrap
2. Subscribe all 3 personal nodes to `test-channel`
3. Publish 5 items on P1
4. Poll P2 and P3 until all 5 items received (timeout: 30s)
5. Assert P1 (Delivery): all 5 items on P2 and P3
6. Assert P5 (Loop termination): relay metrics show bounded push count. Specifically, `cordelia_item_push_total` on R1 and R2 combined MUST be <= items_published * (connected_hot_peers - 1) * 2 (each relay re-pushes to all hot peers except sender, but each relay receives at most once per item)
7. Assert no duplicate items: `SELECT item_id, COUNT(*) FROM items GROUP BY item_id HAVING COUNT(*) > 1` returns 0 rows on all personal nodes

### 3.6 T5: Partition/Heal (2P + 2R + 1B)

**Purpose**: Network partition splits the topology. Items published during partition are eventually delivered after heal. Validates convergence (P6).

**Zone model**: `internet`, `home-1`, `home-2`. B1 is internet-only. P1/P2 bootstrap via their local relay (B1 is unreachable from home zones). Partition is between R1 and R2 on the internet network.

**Topology (pre-partition)**:
```
home-1          internet          home-2
[P1] ---- [R1] ---- [B1] ---- [R2] ---- [P2]
```

**Node configuration**:

| Node | Role | Zone(s) | Zone IP(s) |
|------|------|---------|------------|
| `b1` | bootnode | internet only | .0.10 |
| `r1` | relay | internet, home-1 | .0.20, .1.20 |
| `r2` | relay | internet, home-2 | .0.21, .2.20 |
| `p1` | personal | home-1 only | .1.30 |
| `p2` | personal | home-2 only | .2.30 |

**Partition**: Drop all traffic between R1 and R2 on the internet network (the only network they share). Personal nodes remain connected to their local relay.

**Partition method**:
```bash
# On R1: drop all packets to/from R2 (internet IP 172.28.0.21)
docker exec t5-r1 iptables -A INPUT -s 172.28.0.21 -j DROP
docker exec t5-r1 iptables -A OUTPUT -d 172.28.0.21 -j DROP

# On R2: drop all packets to/from R1 (internet IP 172.28.0.20)
docker exec t5-r2 iptables -A INPUT -s 172.28.0.20 -j DROP
docker exec t5-r2 iptables -A OUTPUT -d 172.28.0.20 -j DROP
```

**Heal method** (delete only the partition rules, not all iptables rules):
```bash
# On R1: remove R2-specific rules
docker exec t5-r1 iptables -D INPUT -s 172.28.0.21 -j DROP
docker exec t5-r1 iptables -D OUTPUT -d 172.28.0.21 -j DROP

# On R2: remove R1-specific rules
docker exec t5-r2 iptables -D INPUT -s 172.28.0.20 -j DROP
docker exec t5-r2 iptables -D OUTPUT -d 172.28.0.20 -j DROP
```

**Test sequence**:
1. Bring up all 5 nodes, wait for bootstrap
2. Subscribe both P1 and P2 to `test-channel`
3. Publish 2 items on P1 (pre-partition baseline), verify delivery to P2
4. **Partition**: apply iptables rules (R1 <-> R2 dropped)
5. Publish 3 items on P1 during partition
6. Publish 2 items on P2 during partition
7. Wait 5s (confirm items do NOT cross the partition)
8. Assert: P2 has only 2 pre-partition items + 2 own items = 4 items. P1 has 2 + 3 = 5 items.
9. **Heal**: delete partition-specific iptables rules (not flush)
10. Wait for convergence: poll both nodes until item count = 7 (timeout: 60s, poll interval: 5s)
11. Assert P6 (Convergence): P1 and P2 have identical item sets (same 7 item_ids)
12. Assert ordering: items are stored with correct `published_at` timestamps regardless of arrival order

**Convergence criterion**: Both nodes report the same set of `item_id` values. Polled every 5s. Convergence MUST happen within 3x `sync_interval_realtime_secs` (30s with 10s interval). Timeout at 60s to accommodate partition recovery overhead.

### 3.7 T6: Bootnode Loss (3P + 1B)

**Purpose**: After initial bootstrap, killing the bootnode does not affect steady-state operation. Personal nodes continue to replicate via direct P2P connections.

**Topology**:
```
[P1] ---- [P2] ---- [P3]
  \        |        /
   \------[B1]----/
```

**Test sequence**:
1. Bring up all 4 nodes, wait for bootstrap (all 3 personal nodes report `peers_hot >= 1`)
2. Subscribe all 3 personal nodes to `test-channel`
3. Publish 2 items on P1, verify delivery to P2 and P3 (pre-bootnode-loss baseline)
4. **Kill bootnode**: `docker stop t6-b1`
5. Wait 5s (governor processes bootnode loss)
6. Publish 3 more items on P1
7. Poll P2 and P3 until all 5 items received (timeout: 30s)
8. Assert P1 (Delivery): all 5 items on P2 and P3 despite bootnode being down
9. Assert P7 (Bootstrap): P1, P2, P3 maintain `peers_hot >= 1` after bootnode loss
10. Assert P9 (Bootnode silence): before killing B1, check B1 logs for zero replication messages (0x04-0x07)

### 3.8 T7: Channel Isolation (3P + 1R + 1B)

**Purpose**: Items published to channel A never appear on nodes subscribed only to channel B. The relay stores items for both channels but does not leak between them.

**Zone model**: `internet`, `home-1`, `home-2`, `home-3`. Each personal node is zone-isolated; all traffic flows through R1.

**Topology**:
```
home-1                internet               home-2
[P1: ch-alpha] ---- [R1] ---- [B1] ---- [R1] ---- [P2: ch-beta]
                      |
                    [R1] ---- [P3: ch-alpha, ch-beta]
                    home-3
```

**Node configuration**:

| Node | Channels | Zone(s) | Zone IP(s) |
|------|----------|---------|------------|
| `b1` | -- | all (internet, home-1, home-2, home-3) | .0.10, .1.10, .2.10, .3.10 |
| `r1` | (all, transparent relay) | all | .0.20, .1.20, .2.20, .3.20 |
| `p1` | `ch-alpha` only | home-1 only | .1.30 |
| `p2` | `ch-beta` only | home-2 only | .2.30 |
| `p3` | `ch-alpha`, `ch-beta` | home-3 only | .3.30 |

**Test sequence**:
1. Bring up all 5 nodes, wait for bootstrap
2. Create channels `ch-alpha` and `ch-beta`, distribute PSKs per topology config
3. Publish 3 items on P1 to `ch-alpha`
4. Publish 3 items on P2 to `ch-beta`
5. Wait for delivery (timeout: 30s)
6. Assert P3 (Channel isolation):
   - P1: has 3 items, all `channel_id = ch-alpha`. Zero items for `ch-beta`.
   - P2: has 3 items, all `channel_id = ch-beta`. Zero items for `ch-alpha`.
   - P3: has 6 items, 3 for each channel.
   - R1: stores 6 items (ciphertext). R1 MUST NOT hold PSKs for either channel.
7. Assert P4 (Role isolation): relay has zero PSK files, bootnode has zero items

**Assertion** (uses `assert_channel_isolation` from common.sh):
```bash
# P1 is subscribed only to ch-alpha
assert_channel_isolation t7-p1 "$ALPHA_ID"
# P2 is subscribed only to ch-beta
assert_channel_isolation t7-p2 "$BETA_ID"
# P3 is subscribed to both
assert_channel_isolation t7-p3 "$ALPHA_ID" "$BETA_ID"
```

---

## 4. Assertion Framework

### 4.1 Assertion Script Structure

Each assertion is a standalone Bash function that returns 0 (pass) or 1 (fail) with a descriptive message. The harness script calls assertions and aggregates results.

```bash
#!/bin/bash
# assertions/common.sh -- shared assertion functions

TIMEOUT=${ASSERT_TIMEOUT:-30}
POLL_INTERVAL=${ASSERT_POLL:-2}
DB_PATH="/data/cordelia/cordelia.db"   # Matches CORDELIA_DATA_DIR in Compose
TOKEN_PATH="/data/cordelia/node-token" # Generated by cordelia init (operations.md SS2)

# Derive channel_id from a human-readable channel name.
# channels-api.md SS3.1: channel_id = hex(SHA-256("cordelia:channel:" + lowercase(name)))
channel_id_for() {
    local name
    name=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    printf '%s' "cordelia:channel:${name}" | sha256sum | cut -d' ' -f1
}

# Wait for a condition to become true, polling at interval.
# NOTE: check_cmd is evaluated via eval. Only pass test-authored strings,
# never external input.
wait_for() {
    local description="$1"
    local check_cmd="$2"
    local timeout="${3:-$TIMEOUT}"
    local interval="${4:-$POLL_INTERVAL}"
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        if eval "$check_cmd" >/dev/null 2>&1; then
            echo "PASS: $description (${elapsed}s)"
            return 0
        fi
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done

    echo "FAIL: $description (timeout after ${timeout}s)"
    return 1
}

# POST to a node's REST API (all channel endpoints are POST)
api_post() {
    local container="$1"
    local endpoint="$2"
    local body="${3:-{}}"
    local token
    token=$(docker exec "$container" cat "$TOKEN_PATH")
    docker exec "$container" curl -sf \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "$body" \
        "http://localhost:9473/api/v1/$endpoint"
}

# GET from a node's REST API (metrics, health)
api_get() {
    local container="$1"
    local endpoint="$2"
    local token
    token=$(docker exec "$container" cat "$TOKEN_PATH")
    docker exec "$container" curl -sf \
        -H "Authorization: Bearer $token" \
        "http://localhost:9473/api/v1/$endpoint"
}

# Query a node's SQLite database
db_query() {
    local container="$1"
    local sql="$2"
    docker exec "$container" sqlite3 "$DB_PATH" "$sql"
}

# Assert item count on a node for a channel
assert_item_count() {
    local container="$1"
    local channel_id="$2"
    local expected="$3"
    local actual
    actual=$(db_query "$container" \
        "SELECT COUNT(*) FROM items WHERE channel_id='$channel_id' AND is_tombstone=0")
    if [ "$actual" -eq "$expected" ]; then
        echo "PASS: $container has $expected items for channel $channel_id"
        return 0
    else
        echo "FAIL: $container has $actual items (expected $expected) for channel $channel_id"
        return 1
    fi
}

# Assert no items for a channel on a node
assert_no_items() {
    local container="$1"
    local channel_id="$2"
    assert_item_count "$container" "$channel_id" 0
}

# Assert node has at least N hot peers
assert_hot_peers() {
    local container="$1"
    local min_peers="$2"
    local actual
    actual=$(api_post "$container" "status" | jq -r '.peers_hot')
    if [ "$actual" -ge "$min_peers" ]; then
        echo "PASS: $container has $actual hot peers (>= $min_peers)"
        return 0
    else
        echo "FAIL: $container has $actual hot peers (expected >= $min_peers)"
        return 1
    fi
}

# Assert zero PSK files on a node (relay/bootnode role isolation)
assert_no_psks() {
    local container="$1"
    local count
    count=$(docker exec "$container" sh -c \
        '[ -d /data/cordelia/channel-keys ] && find /data/cordelia/channel-keys -name "*.key" | wc -l || echo 0')
    if [ "$count" -eq 0 ]; then
        echo "PASS: $container has zero PSK files"
        return 0
    else
        echo "FAIL: $container has $count PSK files (expected 0)"
        return 1
    fi
}

# Assert zero items stored (bootnode role isolation)
assert_zero_items() {
    local container="$1"
    local count
    count=$(db_query "$container" "SELECT COUNT(*) FROM items")
    if [ "$count" -eq 0 ]; then
        echo "PASS: $container stores zero items"
        return 0
    else
        echo "FAIL: $container stores $count items (expected 0)"
        return 1
    fi
}

# Assert no cross-channel leakage.
# Usage: assert_channel_isolation <container> <channel_id> [<channel_id> ...]
# Passes if every item on the node belongs to one of the listed channel_ids.
assert_channel_isolation() {
    local container="$1"; shift
    local in_clause=""
    for cid in "$@"; do
        [ -n "$in_clause" ] && in_clause="${in_clause},"
        in_clause="${in_clause}'${cid}'"
    done
    local count
    count=$(db_query "$container" \
        "SELECT COUNT(*) FROM items WHERE channel_id NOT IN ($in_clause)")
    if [ "$count" -eq 0 ]; then
        echo "PASS: $container has no cross-channel items"
        return 0
    else
        echo "FAIL: $container has $count items from unexpected channels"
        return 1
    fi
}

# Assert convergence: two nodes have identical item sets for a channel
assert_convergence() {
    local container_a="$1"
    local container_b="$2"
    local channel_id="$3"
    local items_a items_b
    items_a=$(db_query "$container_a" \
        "SELECT item_id FROM items WHERE channel_id='$channel_id' AND is_tombstone=0 ORDER BY item_id")
    items_b=$(db_query "$container_b" \
        "SELECT item_id FROM items WHERE channel_id='$channel_id' AND is_tombstone=0 ORDER BY item_id")
    if [ "$items_a" = "$items_b" ]; then
        echo "PASS: $container_a and $container_b have converged for $channel_id"
        return 0
    else
        echo "FAIL: item sets differ between $container_a and $container_b"
        echo "  $container_a: $(echo "$items_a" | wc -l) items"
        echo "  $container_b: $(echo "$items_b" | wc -l) items"
        return 1
    fi
}

# Assert zero log entries matching a pattern (push silence, bootnode silence)
assert_zero_log_matches() {
    local container="$1"
    local pattern="$2"
    local description="$3"
    local count
    count=$(docker logs "$container" 2>&1 | grep -c "$pattern" || true)
    if [ "$count" -eq 0 ]; then
        echo "PASS: $description ($container, zero matches for '$pattern')"
        return 0
    else
        echo "FAIL: $description ($container, $count matches for '$pattern')"
        return 1
    fi
}
```

### 4.2 Property-to-Assertion Mapping

| Property | Assertion Function(s) | Method |
|----------|----------------------|--------|
| **P1: Delivery** | `wait_for` + `assert_item_count` | Poll listen endpoint until expected count, then verify item_ids |
| **P2: Pull delivery** | `wait_for` + `assert_item_count` | Same as P1, but with longer timeout (bounded by sync_interval) |
| **P3: Channel isolation** | `assert_channel_isolation` | SQLite query: zero items outside caller-supplied channel_id list |
| **P4: Role isolation** | `assert_no_psks` + `assert_zero_items` | ls channel-keys/ for PSKs, SQLite item count for storage |
| **P5: Loop termination** | `api_get` (metrics) | `cordelia_item_push_total` bounded by items * hot_max |
| **P6: Convergence** | `wait_for` + `assert_convergence` | Poll until item sets match across partitioned nodes |
| **P7: Bootstrap** | `assert_hot_peers` | `api_post status` peers_hot >= 1 |
| **P8: Push silence** | `assert_zero_log_matches` | Zero outbound Item-Push (0x06) log entries from pull_only node |
| **P9: Bootnode silence** | `assert_zero_log_matches` | Zero replication protocol (0x04-0x07) log entries from bootnode |

### 4.3 Log Assertions (P8, P9)

Push silence and bootnode silence assertions rely on structured log output. The node MUST log protocol message sends at `debug` level with a consistent format:

```
[DEBUG] protocol send: type=0x06 peer=<node_id> channel=<id>
```

Test configs set `logging.level = "debug"` to capture these entries. The assertion scripts grep for the protocol type byte.

**Required log patterns for assertions:**

| Pattern | Meaning | Used by |
|---------|---------|---------|
| `protocol send: type=0x06` | Outbound Item-Push | P8 (push silence) |
| `protocol send: type=0x04` | Outbound Channel-Announce | P9 (bootnode silence) |
| `protocol send: type=0x05` | Outbound Item-Sync | P9 (bootnode silence) |
| `protocol send: type=0x06` | Outbound Item-Push | P9 (bootnode silence) |
| `protocol send: type=0x07` | Outbound PSK-Exchange | P9 (bootnode silence) |

---

## 5. Test Harness

### 5.1 Harness Script

The top-level harness orchestrates all topologies. It can run a single topology or the full suite.

```bash
#!/bin/bash
# run-topology-e2e.sh -- Top-level test harness
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULTS_DIR"

source "${SCRIPT_DIR}/assertions/common.sh"

TOPOLOGIES="${1:-t1 t2 t3 t4 t5 t6 t7}"
PASSED=0
FAILED=0
ERRORS=()

for topo in $TOPOLOGIES; do
    echo "=== Running topology: $topo ==="
    COMPOSE_FILE="${SCRIPT_DIR}/topologies/${topo}.yml"
    TEST_SCRIPT="${SCRIPT_DIR}/tests/test-${topo}.sh"
    TOPO_RESULTS="${RESULTS_DIR}/${topo}"
    mkdir -p "$TOPO_RESULTS"

    # Bring up topology
    docker compose -f "$COMPOSE_FILE" up -d --wait --timeout 60

    # Run test script, capture exit code via PIPESTATUS
    bash "$TEST_SCRIPT" 2>&1 | tee "$TOPO_RESULTS/output.log"
    test_rc=${PIPESTATUS[0]}

    if [ "$test_rc" -eq 0 ]; then
        PASSED=$((PASSED + 1))
        echo "=== $topo: PASSED ==="
    else
        FAILED=$((FAILED + 1))
        ERRORS+=("$topo")
        echo "=== $topo: FAILED ==="

        # Collect artifacts on failure
        for container in $(docker compose -f "$COMPOSE_FILE" ps -q); do
            name=$(docker inspect --format '{{.Name}}' "$container" | sed 's/\///')
            docker logs "$container" > "$TOPO_RESULTS/${name}.log" 2>&1
            docker exec "$container" sqlite3 "$DB_PATH" ".dump" \
                > "$TOPO_RESULTS/${name}.sql" 2>/dev/null || true
        done
    fi

    # Tear down
    docker compose -f "$COMPOSE_FILE" down -v --timeout 10
    echo ""
done

# Summary
echo "================================="
echo "Results: $PASSED passed, $FAILED failed"
if [ ${#ERRORS[@]} -gt 0 ]; then
    echo "Failed topologies: ${ERRORS[*]}"
    echo "Artifacts: $RESULTS_DIR"
    exit 1
fi
echo "All topologies passed."
exit 0
```

### 5.2 Per-Topology Test Script

Each topology has a dedicated test script (`tests/test-t1.sh`, `tests/test-t2.sh`, etc.) that implements the test sequence from SS3. Example for T1:

```bash
#!/bin/bash
# tests/test-t1.sh -- T1: Minimal (2P + 1B)
set -euo pipefail
source "$(dirname "$0")/../assertions/common.sh"

CHANNEL="test-channel"
CHANNEL_ID=$(channel_id_for "$CHANNEL")

echo "--- T1: Waiting for bootstrap ---"
wait_for "P1 has hot peers" \
    "[ \$(api_post t1-p1 status | jq -r '.peers_hot') -ge 1 ]" 30

wait_for "P2 has hot peers" \
    "[ \$(api_post t1-p2 status | jq -r '.peers_hot') -ge 1 ]" 30

echo "--- T1: Creating channel and subscribing ---"
# Channel creation and PSK distribution handled by pre-mounted PSK files
# Subscribe both nodes
api_post t1-p1 "channels/subscribe" "{\"channel\": \"$CHANNEL\"}"
api_post t1-p2 "channels/subscribe" "{\"channel\": \"$CHANNEL\"}"

echo "--- T1: Publishing items ---"
for i in 1 2 3; do
    api_post t1-p1 "channels/publish" \
        "{\"channel\": \"$CHANNEL\", \"content\": {\"text\": \"test item $i\"}, \"item_type\": \"message\"}"
done

echo "--- T1: Waiting for delivery ---"
wait_for "P2 has 3 items" \
    "[ \$(db_query t1-p2 \"SELECT COUNT(*) FROM items WHERE channel_id='$CHANNEL_ID' AND is_tombstone=0\") -eq 3 ]" 30

echo "--- T1: Assertions ---"
assert_item_count t1-p2 "$CHANNEL_ID" 3
assert_channel_isolation t1-p1 "$CHANNEL_ID"
assert_channel_isolation t1-p2 "$CHANNEL_ID"
assert_hot_peers t1-p1 1
assert_hot_peers t1-p2 1

echo "--- T1: All assertions passed ---"
```

### 5.3 Artifact Collection

On failure, the harness collects:

| Artifact | Format | Purpose |
|----------|--------|---------|
| Container logs | Text (per-container `.log` file) | Debug protocol messages, error traces |
| SQLite dump | SQL (per-container `.sql` file) | Inspect item storage, subscriptions, peer state |
| Metrics snapshot | Prometheus text | Counters at time of failure |
| Docker inspect | JSON | Container config, network, health status |

Artifacts are stored in `results/<timestamp>/<topology>/` and uploaded as CI artifacts (retained 7 days).

---

## 6. CI Workflow

### 6.1 GitHub Actions Workflow

```yaml
# .github/workflows/topology-e2e.yml
name: Topology E2E

on:
  push:
    branches: [main]
    paths:
      - 'src/**'
      - 'tests/e2e/**'
      - 'Cargo.toml'
      - 'Cargo.lock'
  pull_request:
    branches: [main]
    paths:
      - 'src/**'
      - 'tests/e2e/**'
  workflow_dispatch:
    inputs:
      topology:
        description: 'Topology to run (blank = all)'
        required: false
        default: ''

jobs:
  build:
    runs-on: [self-hosted, cordelia-docker]
    timeout-minutes: 15

    steps:
      - uses: actions/checkout@v4

      - name: Build release binary (musl)
        run: cargo build --release --target x86_64-unknown-linux-musl

      - name: Build test Docker image
        run: |
          export CORDELIA_IMAGE="cordelia-test:${GITHUB_SHA::8}"
          docker build -t "$CORDELIA_IMAGE" \
            -f tests/e2e/Dockerfile \
            --build-arg BINARY=target/x86_64-unknown-linux-musl/release/cordelia \
            .
          echo "CORDELIA_IMAGE=$CORDELIA_IMAGE" >> "$GITHUB_ENV"

      - name: Generate test PSKs
        run: |
          mkdir -p tests/e2e/keys
          # PSK files named by channel_id: SHA-256("cordelia:channel:" + name)
          for ch in test-channel ch-alpha ch-beta; do
            cid=$(printf '%s' "cordelia:channel:${ch}" | sha256sum | cut -d' ' -f1)
            dd if=/dev/urandom bs=32 count=1 of="tests/e2e/keys/${cid}.key" 2>/dev/null
          done

      - name: Run topology E2E tests
        run: |
          cd tests/e2e
          bash run-topology-e2e.sh ${{ github.event.inputs.topology }}

      - name: Upload failure artifacts
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: topology-e2e-results
          path: tests/e2e/results/
          retention-days: 7
```

### 6.2 Trigger Policy

| Trigger | Topologies Run | Rationale |
|---------|---------------|-----------|
| Push to `main` (src/ or tests/e2e/ changed) | All 7 | Full validation on merge |
| Pull request | All 7 | Gate merges on E2E pass |
| `workflow_dispatch` (blank) | All 7 | Manual full run |
| `workflow_dispatch` (specific topology) | Named topology only | Debug a single failure |

### 6.3 Pass/Fail Criteria

The workflow fails if ANY assertion in ANY topology returns non-zero. There is no "allowed failure" list. All 7 topologies, all 9 properties MUST pass.

**Flakiness policy**: If a test fails intermittently, it is a bug (either in the test timing or in the implementation). Fix the root cause. Do not add retries or mark as flaky.

---

## 7. Coverage Tracking

### 7.1 Coverage Metric

```
coverage = tested_topologies / meaningful_topologies
```

**Meaningful topologies** are parameterised by:
- Number of personal nodes (1-5)
- Number of relays (0-3)
- Number of bootnodes (1-2)
- Push policy mix (all subscribers_only, all pull_only, mixed)
- Channel count (1-3)
- Failure mode (none, partition, node loss)

After pruning degenerate cases (e.g., 0 personal nodes, 0 bootnodes), there are 84 meaningful combinations (personal_nodes[1-5] * relays[0-3] * bootnodes[1-2] * push_policy[3] * failure_mode[3] = 360 raw, minus 276 degenerate). The 7 reference topologies cover the critical paths (9/9 properties, all 4 roles, all 3 failure modes). Phase 1 release target: 7/84 topologies tested but 9/9 properties covered = all formal properties validated. Second-wave (SS7.3) extends to 12/84.

### 7.2 Coverage Matrix

| Property | T1 | T2 | T3 | T4 | T5 | T6 | T7 | Coverage |
|----------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|----------|
| P1: Delivery | Y | Y | -- | Y | -- | Y | -- | 4/7 |
| P2: Pull delivery | -- | -- | Y | -- | -- | -- | -- | 1/7 |
| P3: Channel isolation | Y | -- | -- | -- | -- | -- | Y | 2/7 |
| P4: Role isolation | -- | Y | -- | Y | -- | -- | Y | 3/7 |
| P5: Loop termination | -- | Y | -- | Y | -- | -- | -- | 2/7 |
| P6: Convergence | -- | -- | -- | -- | Y | -- | -- | 1/7 |
| P7: Bootstrap | Y | Y | -- | -- | -- | Y | -- | 3/7 |
| P8: Push silence | -- | -- | Y | -- | -- | -- | -- | 1/7 |
| P9: Bootnode silence | -- | -- | -- | -- | -- | Y | -- | 1/7 |

Every property is tested by at least one topology. Properties with single-topology coverage (P2, P6, P8, P9) are candidates for additional topologies in the second wave.

### 7.3 Second Wave Topologies (Post-Phase 1 MVP)

| ID | Name | Nodes | Properties | Rationale |
|----|------|-------|-----------|-----------|
| T8 | Multi-channel delivery | 3P + 1R + 1B | P1, P3 | Multiple channels per node |
| T9 | Relay chain | 2P + 3R + 1B | P1, P5 | Items traverse > 1 relay hop |
| T10 | Mixed push policy | 3P (mixed) + 1R + 1B | P1, P2, P8 | subscribers_only and pull_only coexist |
| T11 | Partition + pull_only | 2P (pull_only) + 2R + 1B | P2, P6 | Anti-entropy convergence under partition |
| T12 | Two bootnodes | 3P + 2B + 1R | P7, P9 | Bootnode redundancy |

---

## 8. Timing and Governor Tuning

### 8.1 Test Governor Parameters

Production defaults are too slow for sub-90s tests. Test configs use accelerated parameters:

| Parameter | Production | Test | Rationale |
|-----------|-----------|------|-----------|
| `tick_interval_secs` | 10 | 2 | Fast peer lifecycle |
| `min_warm_tenure_secs` | 300 | 5 | Immediate promotion eligibility |
| `keepalive_timeout_secs` | 90 | 15 | Fast dead peer detection |
| `hysteresis_secs` | 90 | 5 | Fast re-promotion |
| `stale_threshold_secs` | 1800 | 30 | Fast stale detection |
| `sync_interval_realtime_secs` | 60 | 10 | Fast anti-entropy |
| `sync_interval_batch_secs` | 900 | 30 | Fast batch sync |
| `churn_interval_secs` | 3600 | 60 | Fast churn (not typically exercised in tests) |

### 8.2 Timeout Strategy

All timeouts are derived from governor parameters, not hardcoded:

| Wait | Formula | Test Value |
|------|---------|------------|
| Bootstrap | 3 * tick_interval + handshake_timeout | ~16s |
| Push delivery | 2 * tick_interval | ~4s |
| Pull delivery | sync_interval_realtime + tick_interval | ~12s |
| Convergence (post-partition) | 3 * sync_interval_realtime | ~30s |
| Node loss recovery | 2 * keepalive_timeout | ~30s |

**All `wait_for` calls use a timeout of at least 2x the formula value** to absorb jitter. No fixed `sleep` calls -- always poll with bounded timeout.

---

## 9. File Layout

```
cordelia-core/tests/e2e/
  Dockerfile                          # Container image definition
  entrypoint.sh                       # Node init + start script
  run-topology-e2e.sh                 # Top-level harness
  assertions/
    common.sh                         # Shared assertion functions
  configs/
    t1/
      b1.toml                         # Bootnode config
      p1.toml                         # Personal node 1 config
      p2.toml                         # Personal node 2 config
    t2/
      b1.toml
      p1.toml
      p2.toml
      r1.toml                         # Relay config
    ...                               # One dir per topology
  keys/                               # Generated test PSKs (gitignored)
  topologies/
    t1.yml                            # Docker Compose per topology (harness uses ${topo}.yml)
    t2.yml
    t3.yml
    t4.yml
    t5.yml
    t6.yml
    t7.yml
  tests/
    test-t1.sh                        # Per-topology test script
    test-t2.sh
    test-t3.sh
    test-t4.sh
    test-t5.sh
    test-t6.sh
    test-t7.sh
  results/                            # Failure artifacts (gitignored)
```

---

## 10. Relationship to Other Test Layers

| Layer | Scope | When | Relationship to Topology E2E |
|-------|-------|------|------------------------------|
| **Layer 0: Unit** | Function correctness | Every commit | Tests individual functions. Topology E2E tests their integration. |
| **Layer 1: TLA+** | Protocol design | Pre-coding gate | Topology E2E proves implementation matches the model. If TLA+ passes and E2E fails, it's an implementation bug. |
| **Layer 2: Topology E2E** | **This spec** | Post-WP3, CI | -- |
| **Layer 3: cadCAD simulation** | Economic equilibria | During WP3 | Validates incentive parameters (scoring, banning). Topology E2E validates the mechanisms work; cadCAD validates the parameter values produce stable equilibria. |
| **Layer 4: Red Team** | Creative multi-step attacks | Pre-release | Topology E2E validates known attack defences. Red Team discovers unknown attack vectors. |

**Confidence formula** (from testing strategy ADR):

```
Confidence = TLA_pass_rate * topology_coverage * e2e_pass_rate * economic_sim_pass_rate * attack_tree_coverage
```

Phase 1 release target: all factors > 90%.

---

## 11. Phase Boundaries

### 11.1 Phase 1 (This Spec)

- 7 reference topologies (T1-T7)
- 9 TLA+ properties asserted (P1-P9)
- Shell-based assertion framework
- CI workflow on self-hosted runner
- Coverage tracking (target > 80%)
- Failure artifact collection

### 11.2 Phase 2

- 5+ additional topologies (T8-T12, SS7.3)
- Keeper node topology (new role, requires Phase 2 keeper implementation)
- Latency simulation (`tc qdisc add dev eth0 root netem delay 100ms`) for realistic WAN conditions
- Parallel topology execution (2-3 compose stacks concurrently on 32 GB runner)
- Prometheus metrics scraping during tests for quantitative assertions (not just pass/fail)
- BDD (Gherkin/cucumber-js) integration for SDK acceptance tests alongside topology E2E

### 11.3 Phase 3

- SPO keeper topologies (multi-keeper, delegation-based trust)
- Large-scale topology generator (parameterised, >50 nodes)
- Chaos engineering integration (random node kill, network degradation)
- Performance benchmarking (throughput, latency percentiles under load)

---

## 12. Scale Testing

### 12.1 Neighborhood Model

At scale (100+ nodes), one Docker network per personal node risks hitting kernel iptables limits. Instead, personal nodes are grouped into **neighborhoods** (zones) of configurable size, each served by 1+ relays.

### 12.2 Generator

```bash
# Usage: generate-scale.sh <total> [bootnodes] [relays] [zone_size]
bash tests/e2e/scale/generate-scale.sh 500 2 10 50
```

Parameters for `500 2 10 50`:
- 488 personal nodes / 50 per zone = 10 zones
- 10 relays (1 per zone, round-robin), each on internet + its assigned home zone
- 2 bootnodes on internet + all 10 home zones
- 12 Docker networks total (1 internet + 10 homes + 1 spare)

### 12.3 Scale IP Scheme

| Network | Subnet | Contents |
|---------|--------|----------|
| `internet` | `172.28.0.0/24` | B1-B2 (.10-.11), R1-R10 (.20-.29) |
| `home-1` | `172.28.1.0/24` | P1-P50 (.30-.79), R1 (.20), B1 (.10) |
| `home-2` | `172.28.2.0/24` | P51-P100 (.30-.79), R2 (.20), B1 (.10) |
| ... | ... | ... |
| `home-10` | `172.28.10.0/24` | P451-P488 (.30-.67), R10 (.20), B1 (.10) |

Each /24 holds up to 50 personal nodes (.30-.79). With 256 available third-octets, maximum ~12,800 personal nodes.

### 12.4 Memory Budget (32GB VM)

| Component | Estimate |
|-----------|----------|
| 500 containers * ~30MB RSS | ~15 GB |
| 12 Docker networks | negligible |
| Kernel + Docker daemon | ~2 GB |
| OS + buffers | ~5 GB |
| Headroom | ~10 GB |

### 12.5 Convergence Timeout

- <= 100 nodes: 300s (60 polls * 5s)
- \> 100 nodes: 450s (90 polls * 5s) to accommodate multi-hop relay latency

---

## 13. References

| Document | Sections Referenced |
|----------|-------------------|
| specs/network-protocol.md | SS2 (transport), SS4 (handshake), SS5 (governor), SS6-7 (replication), SS8 (roles), SS9 (rate limits), SS10 (bootstrap), SS12 (config), SS16 (economics) |
| specs/network-protocol.tla | P1-P9 properties, state variables, actions |
| specs/network-protocol.cfg | Model bounds, property declarations |
| specs/operations.md | SS2 (init), SS4 (exit codes), SS5 (config), SS6 (logging), SS8 (health/metrics) |
| specs/channels-api.md | SS3.1 (subscribe), SS3.2 (publish), SS3.3 (listen), SS3.13 (search), SS3.15 (metrics) |
| specs/configuration.md | SS2 (all config sections), SS5 (validation) |
| decisions/2026-03-10-testing-strategy-bdd.md | Layer 2 (topology E2E), confidence formula, WP15 |
| decisions/2026-03-09-mvp-implementation-plan.md | WP14-15 (TLA+, E2E harness) |
| specs/attack-trees.md | Defence assertions (Sybil, relay defection, channel isolation) |

---

*Draft: 2026-03-12. Implementation-ready topology E2E testing specification -- maps TLA+ formal properties to Docker-based integration tests.*
