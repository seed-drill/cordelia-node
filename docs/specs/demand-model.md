# Cordelia Demand Model

> Derives network parameters from agent behaviour, not from intuition.
> Every rate limit, timeout, and governor target should be traceable
> back to a persona and usage pattern defined here.

---

## 1. Agent Personas

### 1.1 Casual User (Claude Code / personal assistant)

A developer using Claude Code with Cordelia memory. One AI assistant,
one personal device, occasional use throughout the day.

**Observed behaviour (from our own usage):**
- Sessions: 3-5 per day, 30-120 min each
- Writes per session: 5-20 memories (session summaries, decisions, learnings)
- Item size: 500 bytes - 5KB (structured text, no media)
- Reads per session: 10-50 (context loading, search, recall)
- Channels: 2-5 (personal memory, 1-3 project channels, maybe 1 shared team)
- Peak write burst: 5 items in 10 seconds (end-of-session persist)
- Steady-state write rate: 1 item every 5-10 minutes during active session
- Inactive periods: 8-16 hours/day (nights, weekends)

**Device profile:** Laptop, home broadband or office WiFi.
- Upload: 5-50 Mbps available, ~100KB/s dedicated to Cordelia
- Latency: 10-50ms to nearest relay
- Availability: intermittent (laptop sleeps, travels)

### 1.2 Active Developer Team (3-5 developers, shared context)

A small engineering team using Cordelia for shared architectural decisions,
code review context, and sprint planning. Each developer has Claude Code
with access to shared project channels.

**Estimated behaviour:**
- Users: 3-5, each with own personal node
- Sessions per user: 5-8 per day (more active than casual)
- Writes per session: 10-30 (decisions, code reviews, design notes)
- Item size: 1-10KB (richer context, code snippets, spec excerpts)
- Reads per session: 20-100 (team context lookup, cross-referencing)
- Channels: 5-15 (personal + 3-5 project channels + 2-3 team channels)
- Peak write burst: 10 items in 30 seconds (batch persist from multi-agent workflow)
- Steady-state: 2-5 items/min across the team during working hours
- Channel fanout: item published on project channel reaches 3-5 subscribers

**Device profile:** Mix of laptops and office workstations.
- Upload: 10-100 Mbps
- Latency: 5-20ms (office network to relay)
- Availability: working hours (8-10h/day), some members remote

### 1.3 Enterprise Deployment (20-50 users, compliance requirements)

A financial services firm using Cordelia for AI-assisted client interactions,
regulatory documentation, and internal knowledge management. Managed
infrastructure with dedicated relays.

**Estimated behaviour:**
- Users: 20-50, each with personal node (some shared service nodes)
- Sessions per user: 10-20 per day (high-frequency client interactions)
- Writes per session: 5-15 (meeting notes, client summaries, compliance logs)
- Item size: 2-20KB (structured documents, some with embedded references)
- Reads per session: 50-200 (client history lookup, compliance search)
- Channels: 20-100 (personal + client channels + department channels + compliance)
- Peak write burst: 20 items in 60 seconds (batch import, end-of-day processing)
- Steady-state: 10-30 items/min across the organisation during business hours
- Channel fanout: varies (1-3 for client channels, 20-50 for department-wide)

**Device profile:** Corporate workstations, managed network.
- Upload: 100 Mbps+ (corporate LAN to on-premise relay)
- Latency: 1-5ms (same DC or building)
- Availability: 24/7 for service nodes, working hours for personal

### 1.4 AI Agent Swarm (10-100 autonomous agents, high throughput)

An orchestration system running multiple AI agents that share context
through Cordelia channels. Agents communicate findings, delegate tasks,
and maintain shared state.

**Estimated behaviour:**
- Agents: 10-100 autonomous processes
- Write rate per agent: 1-10 items/min (continuous operation)
- Item size: 500 bytes - 50KB (task results, findings, state snapshots)
- Reads per agent: 10-50/min (polling for new tasks, checking shared state)
- Channels: 10-50 (task queues, result channels, coordination channels)
- Peak write burst: 100 items in 10 seconds (parallel task completion)
- Steady-state: 50-500 items/min across the swarm
- Channel fanout: 1-10 subscribers per channel (targeted, not broadcast)

**Device profile:** Data centre or cloud VMs.
- Upload: 1 Gbps+
- Latency: <1ms (same DC)
- Availability: 24/7

---

## 2. Derived Requirements

### 2.1 Write Rate Requirements

| Persona | Peak burst (items/10s) | Steady (items/min) | Max item size |
|---------|----------------------|-------------------|--------------|
| Casual | 5 | 2 | 5KB |
| Dev Team | 10 | 5 per user | 10KB |
| Enterprise | 20 | 30 across org | 20KB |
| Agent Swarm | 100 | 500 across swarm | 50KB |

**Conservative rate limit derivation:**

Per-peer write rate should accommodate the peak burst of the most demanding
persona that uses a personal node (Enterprise: 20 items/60s = 0.33/s).
Round up with headroom: **10 writes/peer/min** handles all personal node
personas. The Agent Swarm operates in a data centre where rate limits can
be tuned higher.

Per-channel rate should accommodate the Enterprise peak (20 items from
multiple publishers): **100 writes/channel/min** handles concurrent
publishers without throttling legitimate use.

### 2.2 Read Rate Requirements

| Persona | Reads/min (peak) | Read pattern |
|---------|-----------------|-------------|
| Casual | 10 | Burst at session start (context load), then occasional |
| Dev Team | 20 per user | Continuous during active development |
| Enterprise | 50 per user | Frequent client lookups |
| Agent Swarm | 50 per agent | Continuous polling |

Reads are served locally (SQLite query) after initial sync. The read
rate constraint is on sync, not on API queries. Sync provides the data;
API queries are local and unconstrained.

**Sync rate derivation:** Each sync cycle fetches headers from hot peers
for subscribed channels. At sync_interval=10s with 5 hot peers and 5
channels, that's 5 × 5 = 25 sync requests per 10s = 150/min. Each
request is ~1KB. Total sync bandwidth: ~150KB/min. Negligible.

### 2.3 Storage Requirements

| Persona | Items/day | Avg size | Daily storage | 1-year storage |
|---------|----------|----------|--------------|----------------|
| Casual | 50-100 | 2KB | 100-200KB | 36-72MB |
| Dev Team (per user) | 100-200 | 5KB | 500KB-1MB | 180-360MB |
| Enterprise (per user) | 100-300 | 10KB | 1-3MB | 360MB-1GB |
| Agent Swarm (total) | 10,000-50,000 | 5KB | 50-250MB | 18-90GB |

**Relay storage:** A relay stores ALL items for channels it carries.
With 100 users at Enterprise rate (300 items/day × 10KB = 3MB/user/day),
a relay storing all channels accumulates ~300MB/day = ~100GB/year.

**max_item_bytes derivation:** The largest persona-driven item is 50KB
(Agent Swarm state snapshot). With encryption overhead (~40 bytes IV +
tag) and CBOR encoding (~100 bytes metadata), the encrypted item is
~51KB. **256KB max provides 5x headroom for text-only use cases.**
Phase 1 excludes images/media. Increasing to 1MB+ in Phase 2 (for
media support) is a non-breaking change. Decreasing would be breaking.

### 2.4 Bandwidth Requirements

**Per personal node (Casual/Dev Team) with hot_max=2:**

| Operation | Rate | Size | Bandwidth |
|-----------|------|------|-----------|
| Push (write) | 2 items/min × 2 hot peers | 2-5KB | 8-20KB/min |
| Push (receive) | 5 items/min | 2-5KB | 10-25KB/min |
| Sync (headers) | 2 hot peers × 5 channels / 10s | 1KB | 60KB/min |
| Sync (fetch missing) | 5 items/min | 2-5KB | 10-25KB/min |
| Keepalive | 12 connections × 2/min | 50 bytes | 1.2KB/min |
| **Total** | | | **~90-130KB/min = ~1.5-2KB/s** |

This is well within home broadband (1 Mbps upload = 125KB/s = 60x headroom).
Halved from previous hot_max=5 estimate because personal nodes push to
2 peers instead of 5. The relay does the fan-out.

**Per relay (hot_max=50):**

| Operation | Rate | Size | Bandwidth |
|-----------|------|------|-----------|
| Receive (from all personal nodes) | 100 items/min | 5KB | 500KB/min |
| Re-push (to hot_max=50 peers) | 100 × 50 | 5KB | 25MB/min |
| Sync serving | 500 requests/min | 1KB | 500KB/min |
| **Total** | | | **~26MB/min = ~430KB/s** |

This requires ~3.5 Mbps upload. Well within data centre bandwidth
(1 Gbps). Relay operators should have at least 10 Mbps upload.

### 2.5 Convergence Requirements

| Persona | Acceptable latency | Why |
|---------|-------------------|-----|
| Casual | 5-10s | Session context can wait a few seconds |
| Dev Team | 2-5s | Real-time collaboration needs fast updates |
| Enterprise | 1-5s | Client interactions need responsive context |
| Agent Swarm | <1s | Autonomous agents need near-real-time coordination |

**Push path delivers in 2-4 RTT (~100-600ms).** This satisfies ALL personas.
The sync fallback (10s default) satisfies Casual and Dev Team. Enterprise
and Agent Swarm should rely on push path (ensure hot_min_relays >= 1).

---

## 3. Parameter Derivation

### 3.1 From Write Rates

| Parameter | Derived from | Value | Rationale |
|-----------|-------------|-------|-----------|
| writes_per_peer_per_minute | Enterprise peak (20/60s) + headroom | 10 | Handles all personal personas with 3-5x margin |
| writes_per_channel_per_minute | Enterprise concurrent (20 × 5 users) | 100 | Handles 5 concurrent publishers at peak |
| max_item_bytes | 95th percentile text memory ~50KB. 5x headroom. No images/media in Phase 1. | 256KB | Covers all text use cases. Increasing later is non-breaking; decreasing is breaking. |
| max_batch_size | Agent Swarm burst (100 items) | 100 | Single fetch can retrieve one burst |

### 3.2 From Bandwidth and Role

| Parameter | Derived from | Value | Rationale |
|-----------|-------------|-------|-----------|
| hot_max (personal) | Personal nodes are consumers, not distributors. Need 1 relay + 1 redundancy peer. Relay does fan-out. | 2 | Minimum for reliability. Halves push bandwidth vs 5. |
| hot_max (relay) | 26MB/min ÷ 500KB/min per push peer = 52 | 50 | Fits within 10 Mbps relay with 3x margin |
| sync_interval_realtime | Casual acceptable (5-10s), bandwidth OK | 10s | Balances latency vs bandwidth |

### 3.3 From Convergence

| Parameter | Derived from | Value | Rationale |
|-----------|-------------|-------|-----------|
| keep_alive_interval | Must be < max_idle_timeout/2 | 15s | 4x safety margin within 60s idle timeout |
| keepalive_timeout | 3 × ping_interval, tolerates 66% loss | 90s | Dead detection within convergence budget |
| min_warm_tenure | Sybil cost analysis (§4 below) | 300s | 5 min tenure per identity |
| bootstrap_timeout | LAN handshake ~1ms, WAN ~500ms | 10s | 20x margin for slow networks |

### 3.4 From Security (Sybil cost)

**min_warm_tenure = 300s derivation:**

Attacker goal: fill a personal node's hot set (5 peers) with Sybil identities.

With min_warm_tenure = 300s and random promotion:
- Attacker connects 10 identities. 2 get immediate Hot (hot_min bypass).
- Remaining 8 enter Warm. Must wait 300s each.
- Governor promotes 1 random warm peer per tick when hot < hot_max.
  With 8 warm peers and random selection, expected time to fill 3 more
  Hot slots: 3 × tick_interval / (attacker_fraction_of_warm). If honest
  peers also exist in warm, attacker fraction < 1.0.
- With per_ip_limit = 5, attacker needs 2+ IPs minimum.
- Total attacker cost: 2 IPs × 300s = 10 minutes to fill hot set.

**If min_warm_tenure = 60s:** Attacker fills hot set in 2 minutes.
Too fast for operator detection.

**If min_warm_tenure = 900s:** Legitimate nodes take 15 min to join.
Too slow for usability.

300s (5 min) balances security vs usability.

---

## 4. Validation Plan

These derivations are estimates. They MUST be validated:

1. **Instrument real usage:** Deploy Cordelia with 3-5 Seed Drill team members
   (Casual persona). Measure actual write rate, item size, read rate over
   2 weeks. Compare to model.

2. **Scale test validation:** Run 100-node Docker test with synthetic Agent
   Swarm traffic (100 items/min burst). Measure actual convergence time,
   bandwidth, and resource usage. Compare to model.

3. **Tune conservatively:** If real usage is lower than model, keep parameters
   as-is (headroom is good). If real usage exceeds model, increase limits
   before they become bottlenecks.

4. **Monitor in production:** Add dashboards for per-peer write rate,
   sync bandwidth, and governor hot set composition. Alert when approaching
   80% of any limit.

---

*Spec version: 1.0*
*Created: 2026-03-16*
*Cross-refs: parameter-rationale.md (per-parameter detail),
network-behaviour.md §5 (performance contract),
network-protocol.md §9 (rate limits), §12 (configuration)*
