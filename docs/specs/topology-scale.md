# Scale Testing Specification

> Validates Cordelia's peer governor and delivery semantics at 50, 100, 500,
> and 1000 node scale on Docker bridge networks.

**Motivation:** The Coutts/Davies peer governor design promises O(hot_max) sync
cost per node regardless of network size N. Phase 1 E2E tests (T1-T7) validate
correctness at 3-6 nodes. Scale tests validate that convergence time, resource
usage, and delivery reliability remain bounded as N grows.

---

## 1. Infrastructure Requirements

### 1.1 VM Sizing

| Scale | RAM | CPU | Disk | ulimit -n |
|-------|-----|-----|------|-----------|
| 50 nodes | 8GB | 4 | 20GB | 65536 |
| 100 nodes | 16GB | 8 | 40GB | 65536 |
| 500 nodes | 32GB | 8 | 80GB | 65536 |
| 1000 nodes | 64GB | 16 | 120GB | 65536 |

Per-container overhead: ~30-50MB RAM (cordelia binary + SQLite + QUIC buffers).

### 1.2 Kernel Tuning (REQUIRED)

```bash
# File descriptors
sudo sysctl -w fs.file-max=2097152
ulimit -n 65536  # per-process (add to /etc/security/limits.conf)

# Conntrack for QUIC/UDP
sudo sysctl -w net.netfilter.nf_conntrack_max=524288
sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout=10
sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=30
sudo apt-get install -y conntrack

# Network buffers
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.wmem_max=26214400
sudo sysctl -w net.core.rmem_default=1048576
sudo sysctl -w net.core.wmem_default=1048576

# Docker bridge limits
sudo sysctl -w net.bridge.bridge-nf-call-iptables=1
```

### 1.3 Docker Network

Multiple subnets for >254 nodes:

```yaml
# 50/100 nodes: single /24
networks:
  cordelia-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/24

# 500 nodes: /22 (1022 usable IPs)
networks:
  cordelia-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/22

# 1000 nodes: /21 (2046 usable IPs)
networks:
  cordelia-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/21
```

### 1.4 Container Image

Same `cordelia-test:latest` image as T1-T7. Built with `build-image.sh`.

---

## 2. Topology Generator

Scale tests use a generator script to create Compose files and node configs:

```bash
# Usage: generate-scale.sh <node_count> <bootnode_count> <relay_count>
bash tests/e2e/scale/generate-scale.sh 100 3 5
```

Generates:
- `tests/e2e/scale/s100.yml` -- Docker Compose file
- `tests/e2e/scale/configs/s100/*.toml` -- Per-node configs
- `tests/e2e/scale/run-s100.sh` -- Test script

### 2.1 Node Roles

| Scale | Bootnodes | Relays | Personal | Total |
|-------|-----------|--------|----------|-------|
| 50 | 2 | 3 | 45 | 50 |
| 100 | 3 | 5 | 92 | 100 |
| 500 | 3 | 10 | 487 | 500 |
| 1000 | 5 | 20 | 975 | 1000 |

### 2.2 IP Assignment

```
Bootnodes:  172.28.0.10 - 172.28.0.19
Relays:     172.28.0.20 - 172.28.0.49
Personal:   172.28.0.50 - 172.28.3.255 (for /22)
```

### 2.3 Governor Targets for Scale

```toml
# Personal nodes (scale)
[governor]
hot_min = 2
hot_max = 10        # Bounded: O(10) sync cost regardless of N
warm_min = 5
warm_max = 20
cold_max = 200

# Relays (scale)
[governor]
hot_min = 5
hot_max = 50
warm_min = 20
warm_max = 100
cold_max = 500
```

---

## 3. Scale Test Scenarios

### S1: Convergence at Scale (N nodes, 1 channel)

**Purpose:** Verify that convergence time is O(D), not O(N).

1. Start all nodes
2. Wait for all nodes healthy
3. Subscribe all personal nodes to `test-channel`
4. Publish 10 items on a random personal node
5. Wait for all personal nodes to have 10 items
6. Measure: convergence time, per-node item count, relay storage

**Pass criteria:**
- All personal nodes have 10 items
- Convergence time < 120s (independent of N)
- No node has duplicate items
- Relay storage: all relays have 10 items
- Bootnode storage: 0 items

### S2: Throughput Under Load (100 nodes, burst publish)

**Purpose:** Verify delivery under sustained load.

1. Start 100 nodes
2. Subscribe all to `test-channel`
3. 10 nodes publish 100 items each simultaneously (1000 total)
4. Wait for all nodes to have 1000 items
5. Measure: time to full delivery, dedup rate, relay fan-out

**Pass criteria:**
- All nodes have 1000 items within 300s
- Dedup rate < 10% (minimal redundant delivery)
- No items lost

### S3: Churn Resilience (100 nodes, rolling restart)

**Purpose:** Verify the governor handles node churn gracefully.

1. Start 100 nodes, publish 10 items
2. Kill 20% of personal nodes
3. Wait 30s
4. Start 20 new personal nodes (different keys)
5. Publish 10 more items
6. Wait for convergence
7. Verify: new nodes have all 20 items, surviving nodes have all 20

### S4: Eclipse Resistance (50 nodes, adversarial)

**Purpose:** Verify that an attacker cannot eclipse a victim node.

1. Start 50 honest nodes + 1 victim + 20 attacker nodes
2. Attacker nodes connect aggressively to victim
3. Publish items on honest nodes
4. Verify: victim receives items from honest nodes despite attacker connections
5. Measure: victim's hot set composition (should include honest peers)

**Pass criteria:**
- Victim receives all items
- Victim's hot set is not dominated by attacker nodes (random promotion)

### S5: Partition at Scale (500 nodes, 2 partitions)

**Purpose:** Verify convergence after large-scale partition.

1. Start 500 nodes with 2 relay groups
2. Publish items in both partitions
3. Partition via iptables (relay group A cannot reach relay group B)
4. Publish items during partition
5. Heal partition
6. Wait for convergence
7. Verify: all nodes have all items

---

## 4. Measurement Framework

### 4.1 Metrics Collected

| Metric | Method | Unit |
|--------|--------|------|
| Convergence time | Time from publish to all-nodes-have-items | seconds |
| Per-node item count | `db_query` on each node's SQLite | count |
| Per-node hot/warm/cold | `/api/v1/status` endpoint | count |
| Relay fan-out | Count of relay re-push log lines | count |
| Dedup rate | `dedup_dropped / (stored + dedup_dropped)` | percentage |
| Memory per container | `docker stats` | MB |
| Connection count | Governor tick logs | count |
| Push timeout count | Grep WARN logs for "timed out" | count |

### 4.2 Reporting

Generate a CSV and summary for each scale test:

```
scale,nodes,convergence_secs,items_per_node,dedup_rate,push_timeouts,memory_mb
50,50,15,10,0.02,0,35
100,100,18,10,0.04,2,38
500,500,22,10,0.08,5,42
```

**Key validation:** convergence_secs should be roughly constant as nodes increases.

---

## 5. Implementation Plan

1. Write `generate-scale.sh` topology generator
2. Write `run-scale.sh` test runner with metrics collection
3. Run S1 at 50 nodes (current VM, 32GB)
4. If passes, run S1 at 100 nodes
5. Request VM resize to 64GB for 500+ nodes
6. Run S1-S3 at 500 nodes
7. Run S1, S3, S5 at 1000 nodes
8. S4 (eclipse) requires attacker node implementation -- defer to after S1-S3

---

*Spec version: 1.0*
*Created: 2026-03-15*
*Cross-refs: network-protocol.md §5 (Peer Governor), topology-e2e.md (T1-T7)*
