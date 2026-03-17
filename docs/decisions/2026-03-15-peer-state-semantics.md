# ADR: Peer State Semantics (Cold/Warm/Hot)

**Date:** 2026-03-15
**Status:** Decided
**Authors:** Russell Wing, Claude Opus 4.6
**Refs:** Coutts, D. et al. "The Shelley Networking Protocol"; Davies, N. & Coutts, D. "Introduction to the design of the Data Diffusion and Networking for Cardano Shelley"

## Context

The peer governor manages a three-tier peer lifecycle (Cold/Warm/Hot) derived from Cardano's Ouroboros networking design. The semantics of each state determine connection costs, failover latency, and network-size independence.

A common misunderstanding is that Warm means "recently seen but currently offline." The Coutts model is more specific: Warm means **connected but not running data protocols**. This distinction is load-bearing for the design's scalability properties.

## Decision

### State Definitions

| State | Connection | Protocols Running | Purpose |
|-------|-----------|-------------------|---------|
| **Cold** | None | None | Address book entry. Known peer address. No resource cost. |
| **Warm** | Open, keepalive active | Keep-Alive (ss4.2), Peer-Sharing (ss4.3) | Ready reserve. Live connection maintained. Discovery aid. Fast failover target (~0 latency to promote). |
| **Hot** | Open, keepalive + data active | Keep-Alive, Peer-Sharing, Item-Push (ss4.6), Item-Sync (ss4.5), Channel-Announce (ss4.4) | Active data peer. Items flow here. Scored by delivery contribution. |

### Transitions

| Transition | Trigger | Cost | What Happens |
|-----------|---------|------|-------------|
| Cold -> Warm | Governor step 3 (`warm < warm_min`) | QUIC handshake (~1-2 RTT, TLS 1.3) | New connection opened. Handshake protocol runs. Keep-Alive starts. |
| Warm -> Hot | Governor step 4 (`hot < hot_min`, random) | ~0 (start streams on existing connection) | Data protocols begin. Push/sync target this peer. |
| Hot -> Warm | Governor step 5 (demotion) or step 6 (churn) | ~0 (stop data streams, keep connection) | Data protocols stop. Connection stays open for keepalive. Peer remains a failover target. |
| Warm -> Cold | Dead detection (keepalive timeout) | Connection closed | Peer returns to address book only. |
| Cold -> evicted | Governor step 7 (excess cold) | None | Address removed from peer table. |

### Key Insight: Warm Connections Are Maintained

The critical property: **when a peer is demoted Hot->Warm, the QUIC connection stays open**. Only Keep-Alive and Peer-Sharing continue running. This means:

1. **Fast failover.** If a Hot peer dies, a Warm peer can be promoted to Hot within a single governor tick (~10s), without the latency of a new QUIC handshake (~100ms LAN, ~500ms WAN).

2. **Ready reserve.** The Warm set is a pool of pre-connected peers. The governor can promote/demote between Warm and Hot cheaply, enabling scoring-based topology optimisation.

3. **Network-size independence.** Per-node cost is bounded by `warm_max` connections (keepalive overhead) + `hot_max` data streams. This does not grow with network size N.

### Costs Per State

| Resource | Cold | Warm | Hot |
|----------|------|------|-----|
| Memory | ~100 bytes (address) | ~50KB (connection buffers) | ~50KB + item buffers |
| Network | 0 | ~100 bytes/30s (keepalive) | Push/sync traffic |
| CPU | 0 | Negligible | QUIC stream processing |
| File descriptors | 0 | 1 (UDP socket share) | 1 (same) |

### Convergence Guarantee

With proper Cold/Warm/Hot semantics, convergence after partition heal is:

- **Bootstrap case** (hot < hot_min): ~85s. Warm peers promoted immediately.
- **Steady state** (hot >= hot_min): Warm peer promoted within `min_warm_tenure` (300s) + sync cycle (10s). But if the demoted peer was previously Hot, it keeps its Warm connection and re-promotes faster.

The convergence time depends on relay mesh depth D (typically 2-3), not network size N. A 1000-node network converges in approximately the same time as a 10-node network.

## Consequences

1. The ConnectionManager must track peer state (Hot vs Warm) and NOT close connections on Hot->Warm demotion.
2. Push and Sync MUST filter to Hot peers only.
3. Keep-Alive and Peer-Sharing MUST run on both Warm and Hot peers.
4. The governor's `mark_disconnected()` must only be called when the QUIC connection actually closes (Warm->Cold), not on Hot->Warm demotion.
5. `peers_hot` and `peers_warm` counters in the status endpoint reflect governor state, not connection count.
6. Scale testing (S1-S5) should validate that convergence time is independent of N.
