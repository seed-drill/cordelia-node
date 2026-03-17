# Parameter Rationale

> Every configurable parameter in Cordelia with its value, rationale,
> trade-off, and what happens if you change it. No magic numbers.

**Principle:** If you can't explain why a number is what it is, it's a guess
pretending to be a design decision. Every parameter here has a derivation
or a reference.

---

## 1. Transport Parameters

### keep_alive_interval = 15s

**Rationale:** The QUIC transport sends PING frames at this interval to prevent
idle disconnection. Must be less than `max_idle_timeout / 2` to ensure at least
2 PINGs arrive before timeout. With `max_idle_timeout = 60s`, any interval
< 30s works. 15s gives a 4x safety margin.

**Reference:** Quinn default is None (no keepalive). Cardano uses TCP with
30s keepalive at the application layer.

**If you increase to 30s:** 2 PINGs per idle window. One lost PING = 50%
coverage. Risk of false idle timeout on lossy networks.

**If you decrease to 5s:** More bandwidth (1 PING every 5s per connection).
With 15 connections, that's 3 PINGs/s. Negligible but wasteful.

### max_idle_timeout = 60s

**Rationale:** How long a QUIC connection survives with zero traffic (no PINGs,
no data). This is a safety net -- if keepalive PINGs stop (endpoint frozen,
network black hole), the connection closes after 60s. Must be > 2x
`keep_alive_interval` to avoid false positives.

**Reference:** Quinn default is 60s. Cardano's TCP has no idle timeout
(relies on keepalive exclusively).

**If you increase to 120s:** Dead connections take 2 minutes to detect.
Acceptable for production. Increases convergence time after partition.

**If you decrease to 30s:** Aggressive. A single lost keepalive PING (at 15s
interval) could close the connection. Not recommended on lossy networks.

### incoming_handshake_timeout = 10s

**Rationale:** Maximum time to complete the QUIC/TLS handshake for inbound
connections. BV-23 showed that without this timeout, a stalled handshake
blocks the entire select loop. 10s is generous for a LAN handshake (~1ms)
and sufficient for high-latency WAN (~500ms RTT × multiple round trips).

**If you increase to 30s:** Stalled handshakes block accept for longer.
Other operations (push, sync, peer-sharing) are delayed. Not recommended.

**If you decrease to 3s:** May reject legitimate connections on slow networks.

### max_concurrent_bidi_streams = 1000

**Rationale:** Maximum bidirectional streams per QUIC connection. Each protocol
operation (push, sync, peer-share) opens one stream. With 7 protocols, a
busy peer might have 10-20 concurrent operations. 1000 provides headroom
for burst traffic without exhaustion.

**Reference:** Quinn default is 100. We increased to 1000 after BV-22 showed
that unclosed streams could exhaust the limit.

**If you decrease to 100:** Risk of open_bi hanging under burst load
(many concurrent push + sync operations).

---

## 2. Application Keepalive Parameters

### ping_interval = 30s

**Rationale:** Application-level Keep-Alive sends Ping every 30s on each
connection. This is SEPARATE from the QUIC transport keepalive (15s).
Purpose: measure RTT for governor scoring, detect application-level
unresponsiveness (QUIC connection alive but application frozen).

**Reference:** Cardano uses 10-30s for TipSample on warm peers.

**Derivation:** At 15 connections, 30s interval = 0.5 pings/s total. Each
ping is ~50 bytes. Bandwidth: ~25 bytes/s per connection. Negligible.

**If you increase to 60s:** RTT measurements are less frequent. Governor
scoring reacts slower to latency changes. Dead detection takes 180s
(3 × 60s) instead of 90s.

### keepalive_timeout = 90s (3 × ping_interval)

**Rationale:** 3 missed pings = dead. This tolerates 2 lost packets (66%
packet loss) before declaring a peer dead. At 30s ping interval, dead
detection fires at 90s.

**Reference:** Cardano uses `closeConnectionTimeout = 120s` for TCP.

**Why 3 and not 2:** 2 missed pings (60s) could fire during a brief network
congestion event. 3 provides more tolerance.

**Why 3 and not 5:** 5 missed pings (150s) is too slow. Items pushed to a
dead peer would time out on every push for 2.5 minutes.

---

## 3. Governor Parameters

### hot_min = 2 (personal), 10 (relay)

**Rationale:** The urgency threshold. Below this, the governor bypasses the
min_warm_tenure anti-Sybil guard and promotes peers immediately. Must be
>= 1 (at least one peer needed for any connectivity).

**Personal (2):** A personal node needs at least 1 relay + 1 other peer
for redundancy. 2 gives immediate relay + peer connectivity.

**Relay (10):** A relay needs connections to multiple relays (mesh backbone)
and multiple personal nodes. 10 ensures a connected mesh at startup.

**If you set to 1 (personal):** Only 1 peer promoted immediately. If it's
a bootnode (no items), the node has no data path until the governor tick
promotes another peer (10s). Acceptable but slower bootstrap.

### hot_max = 2 (personal), 50 (relay)

**Rationale:** Maximum peers in the Hot set. Bounds per-node push and sync
cost at O(hot_max). Every published item is pushed to hot_max peers.

**Personal (2):** 1 relay (hot_min_relays=1) + 1 redundancy peer. Personal
nodes are consumers, not distributors. The relay does fan-out.

**Relay (50):** 5 relays + 45 personal nodes. Relay re-pushes every received
item to 50 peers. At 1KB × 50 = 50KB per item. At 100 items/min = 5MB/min.
Manageable on relay-grade infrastructure.

**If you increase personal to 5:** 5× push bandwidth per item. Unnecessary
for a laptop daemon. Also increases the attack surface (5 Hot peers means
more potential for eclipse if min_warm_tenure is bypassed).

### warm_min = 3 (personal), 20 (relay)

**Rationale:** Below this, the governor connects to Cold peers (opens new
QUIC connections). Warm peers are the ready reserve -- they have open
connections and can be promoted to Hot instantly.

**Personal (3):** 3 warm peers ready for failover. If 1 hot peer dies,
a warm peer is promoted immediately without connection latency.

**Relay (20):** 20 warm reserves for a relay with 50 hot peers. If churn
rotates hot peers, there are always warm candidates available.

### min_warm_tenure = 300s (5 minutes)

**Rationale:** Anti-Sybil defense. A peer must survive in the Warm state for
5 minutes before being eligible for Hot promotion (via random selection).
This prevents an attacker from rapidly cycling Sybil identities through
Hot -> demotion -> reconnect -> Hot.

**Reference:** Cardano does not enforce tenure on Warm peers (they promote
randomly without a minimum wait). Our 5-minute tenure is more conservative,
providing stronger eclipse resistance at the cost of slower steady-state
promotion.

**Derivation:** 5 minutes × 20% churn fraction = an attacker needs to sustain
at least 5 identities for 5 minutes each to fill a churn cycle. With per-IP
limits of 5, this requires 1 IP per identity. Economic cost scales linearly.

**If you decrease to 60s:** Sybil cycling becomes 5x faster. An attacker
can attempt Hot promotion every minute instead of every 5 minutes.

**If you increase to 900s (15 min):** Legitimate nodes take 15 minutes to
join the Hot set after connecting. Slow for legitimate peer discovery.

### churn_interval = 3600s (1 hour) + jitter 0-300s

**Rationale:** Anti-eclipse defense. Every hour, the governor swaps 20% of
warm peers with cold peers and rotates 1 hot peer. This forces topology
exploration and prevents an attacker from maintaining a stable eclipse.

**Reference:** Cardano churns on two timescales: normal (with 0-600s jitter)
and bulk sync (with 0-60s jitter). We use a single interval with 300s jitter.

**Jitter (0-300s):** Prevents correlated churn across nodes that started at
similar times. Without jitter, all nodes churn simultaneously, causing a
coordinated topology disruption.

**If you decrease to 600s (10 min):** More aggressive exploration. Better
eclipse resistance but higher connection churn. May cause instability on
small networks where reconnecting takes longer than the churn interval.

### churn_fraction = 0.2 (20%)

**Rationale:** What fraction of warm peers are swapped per churn cycle.
20% with warm_max=10 = 2 peers swapped per hour.

**Reference:** Cardano uses `max 0 (v - max 1 (v / 5))` which is roughly
20% or at least 1 peer.

**If you increase to 0.5:** Half the warm set replaced hourly. Aggressive
but effective against eclipse. May lose good peers unnecessarily.

### stale_threshold = 1800s (30 minutes)

**Rationale:** Hot peers with no items_delivered for 30 minutes are
priority-demoted (before scoring-based demotion). Indicates the peer
is connected but not useful for any subscribed channel.

**If you decrease to 300s (5 min):** Peers on quiet channels would be
demoted during inactive periods. Too aggressive.

**If you increase to 7200s (2 hours):** Useless peers stay Hot for too
long, wasting push bandwidth.

---

## 4. Protocol Rate Limits

### clock_skew_tolerance = 300s (5 minutes)

**Rationale:** Maximum allowed clock difference between two nodes during
handshake. Rejects peers with clocks more than 5 minutes apart.

**Reference:** NTP-synchronized hosts typically have <1s drift.
5 minutes tolerates hosts without NTP, mobile devices with stale
clocks, and timezone configuration errors.

**If you decrease to 30s:** Would reject legitimate peers with poor
NTP. Too strict for Phase 1.

### writes_per_peer_per_minute = 10

**Rationale:** Maximum Item-Push messages a single peer can send per minute.
At 256KB max item size, this limits inbound bandwidth per peer to 2.5MB/min.

**Derivation:** A typical AI agent memory write rate is ~1-10 items/min.
10/min provides 10x headroom for burst traffic.

**If you increase to 100:** A single peer can push 100MB/min. Potential
bandwidth amplification attack.

### writes_per_channel_per_minute = 100

**Rationale:** Maximum items published to a single channel per minute across
all peers. Prevents a single busy channel from consuming all relay resources.

**Derivation:** 10 publishers × 10 items/min = 100 items/channel/min.
Supports up to 10 concurrent publishers at maximum rate.

### max_item_bytes = 256KB

**Rationale:** Maximum size of a single encrypted item. Phase 1 is text-only
AI memory. 95th percentile ~50KB. 256KB = 5x headroom. No images/media.
Increasing later is non-breaking.

**Reference:** GitHub Gist max 10MB. Slack message max 40KB. We chose
256KB as appropriate for Phase 1 text-only AI agent use cases.

### max_message_bytes = 1MB

**Rationale:** Maximum CBOR wire message size. Must be >= max_item_bytes
plus CBOR overhead. 1MB allows batch fetch of up to 4 items at maximum
size, or 100+ typical items in a single FetchResponse.

---

## 5. Connection Limits

### max_inbound_connections = 200

**Rationale:** Maximum simultaneous inbound QUIC connections. At ~50KB
memory per connection, 200 connections = ~10MB. Prevents memory exhaustion
from connection flood attacks.

**Reference:** Cardano relay nodes accept ~3000 connections. We use 200
as a conservative Phase 1 default.

### max_connections_per_ip = 5

**Rationale:** Prevents a single IP from consuming all connection slots.
5 allows legitimate multi-node deployments on the same IP (e.g., Docker
containers) while limiting Sybil attacks from a single host.

### max_connections_per_subnet = 20 (/24 for IPv4)

**Rationale:** Prevents a single subnet from dominating connections.
A /24 subnet has 254 usable IPs. Limiting to 20 connections per /24
allows diversity while preventing subnet-level attacks.

---

*Spec version: 1.0*
*Created: 2026-03-16*
*Cross-refs: network-protocol.md §9, §12; network-behaviour.md §5*
