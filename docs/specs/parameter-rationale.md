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

### max_concurrent_bidi_streams = 64, no unidirectional streams

**Rationale:** How many streams a peer may have open on one connection at
once. Each exchange (a push, a sync, an announcement) is one stream, and a
node handles one stream of a connection at a time, so real use is a
handful. The protocol uses no unidirectional streams, so a peer may open
none.

**History:** It was 1000, raised from Quinn's 100 after BV-22, where
streams that were never closed used the allowance up. Those are closed
now. 1000 streams, each with its own buffer, let one connection hold
over a gigabyte of a node's memory.

### stream_receive_window = 1MB, receive_window = 2MB

**Rationale:** How much a peer may send before this node has read it: one
message on a stream, and two messages on a whole connection. The second
is what bounds the memory one connection can make a node hold. Quinn's
default has no limit for the connection.

**Derivation:** An exchange is one message each way, so one message per
stream is enough. Two for the connection lets a second exchange begin
while the first is being read. With 200 connections a relay holds at
most 400MB unread.

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

### 3x Headroom Principle (RATE_LIMIT_HEADROOM = 3)

**Principle:** All per-peer rate limits are set to **3x the expected legitimate rate**.
This provides burst tolerance (reconnect catch-up, rapid publish after partitioning)
while catching sustained abuse (4x+ over a sliding window = clearly malicious).

Every rate limit is derived from the expected rate of the protocol it protects,
multiplied by the headroom constant. No magic numbers.

| Protocol | Expected rate | Limit (3x) | Derivation |
|----------|--------------|------------|------------|
| Writes | 12/min (60/REPUSH_INTERVAL) | 36/min | `3 × (60 / 5)` |
| Syncs | 6/min (RATE_WINDOW/TICK) | 18/min | `3 × (60 / 10)` |
| Peer-shares | 2/min (RATE_WINDOW/PING) | 6/min | `3 × (60 / 30)` |

**If you increase to 5x:** More burst tolerance but a wider window for sustained abuse.
An attacker can send 5x normal traffic before triggering any response.

**If you decrease to 2x:** Tight. A legitimate relay processing a burst from multiple
sources may trigger false positives. 2x leaves no room for timing variance.

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
At 64KB max item size, this limits inbound bandwidth per peer to 640KB/min.

**Derivation:** A typical AI agent memory write rate is ~1-10 items/min.
10/min provides 10x headroom for burst traffic.

**If you increase to 100:** A single peer can push 100MB/min. Potential
bandwidth amplification attack.

### writes_per_channel_per_minute = 100

**Rationale:** Maximum items published to a single channel per minute across
all peers. Prevents a single busy channel from consuming all relay resources.

**Derivation:** 10 publishers × 10 items/min = 100 items/channel/min.
Supports up to 10 concurrent publishers at maximum rate.

### max_item_bytes = 64KB

**Rationale:** The size every entry must fit in as it travels, ciphertext
included: 65,536 bytes. It is checked by the device that writes the entry,
by each relay, and by the device that receives it. Cordelia does not care
what an entry carries, so it has to resist misuse by structure: one small
size for everything is what lets limits on rate and storage mean something.

**Derivation:** 64 KB holds every memory file we have, and 93% of the
files in our skills folder. A relay that accepts 36 pushes a minute from a
peer then takes at most a few megabytes a minute from it. Until
0.2.0-alpha.3 the limit was 256 KB, checked only by the sender. A file of
64 to 128 KB synced then, and does not now: it is reported, and left as it
is.

### max_message_bytes = 1MB

**Rationale:** Maximum CBOR wire message size. Must be >= max_item_bytes
plus CBOR overhead. 1MB allows batch fetch of up to 4 items at maximum
size, or 100+ typical items in a single FetchResponse.

### max_rev = 2^53 - 1, max_epoch = 2^53 - 1

**Rationale:** A keyed item's revision and a channel state's epoch are
counters that the writer sets. Unbounded, they are stored in a signed 64-bit
column: a value near the top overflows on the next increment, and one above
it wraps. Either way the name, or the member list, could never be written
again. The bound is checked wherever an item or a state is verified, so a
larger value is neither stored nor passed on.

**Derivation:** 2^53 - 1 is the largest integer that is exact both in a
signed 64-bit column and as a JSON number, so the API can carry it. At one
revision a second it lasts 285 million years.

### max_epoch_step = 2^20

**Rationale:** A state carries the whole member list, so a device that was
away can skip the epochs it missed. But a member who could jump straight to
max_epoch would freeze the list for everyone: no later state could be newer.
So one state may move the epoch by at most this much.

**Derivation:** No device misses a million changes to a channel's members.
Reaching max_epoch at this step takes 2^33 states, each of which every other
member has to receive and apply first.

### outbox_flush_interval = 2s

**Rationale:** A personal node's own items stay in an outbox until a relay
acknowledges them, and go out as one batched push per flush (decision
2026-09-30-agent-memory-sync §4.4a). 60 / writes_per_peer_per_minute (36)
= 1.67s, rounded up to 2s: 30 pushes/min against the relay's 36, however
many items were written. Before the outbox, each write was its own push and
a burst of 150 writes tripped the limit 467 times, losing most items.
Checked at compile time in protocol.rs.

### state_offer_retry_base = 60s, state_offer_retry_max = 6h

**Rationale:** A channel state (a change to a channel's members or keys)
is offered again to a member that has not been seen to hold it: this long
after it was first sent, doubling after each offer, up to the maximum.

**Derivation:** A state travels through a relay, and the member fetches
every 10 seconds and answers within the next 10. A minute is well past the
time an answer normally takes, so the first repeat is not wasted. A member
that is away is offered the state 4 times a day at the maximum: each is a
push of one small item, which a relay that still holds it answers at once.
Six hours bounds how long a member that has just come back waits if its
relay lost the state while it was away.

### max_state_keys = 1024

**Rationale:** The most keys a channel state carries, and the furthest a
state may move a channel's key version. A removal adds one key and moves
the version by one.

**Derivation:** No person removes a thousand devices. The bound exists so
that a hostile payload cannot make a node allocate without limit, and so
that no member can send a key version so large that none could follow it.
A ring that reaches the bound sends its newest keys, so that a removal can
always be sent.

### sync_page_steps = 100, 14, 3, 1

**Rationale:** How many entries a node asks a peer to list in one page,
and so fetch in one request. The answer to a fetch is one message. A
hundred entries of the largest size are six times what a message holds, so
when a fetch fails the node asks for the next number down, for that peer
and channel, and goes back to 100 once it has caught up there.

**Derivation:** 14 entries of 64 KB, with a kilobyte of header each, fit in
one 1 MB message (checked at compile time). 3 covers entries written
before 0.2.0-alpha.4, which could be 256 KB. 1 always fits. Most pages
hold small entries and never leave 100.

### push_bytes_per_peer_per_minute = 2MB, outbox_bytes_per_minute = 1.5MB

**Rationale:** The count of pushes a minute bounds little by itself, since
one push can be a whole message. So a connection may also push only so
many bytes of entries a minute. A push that would go over is refused
whole, with no answer, so a sender on any version keeps what it sent.

A device paces itself to 1.5MB a minute to each relay, a quarter under
what a relay allows, so that it is never the one refused.

**Derivation:** Two days of our own use is 49KB across five channels. Our
whole skills folder is 4MB, which takes about three minutes to send the
first time. From one address, with its five connections, a relay takes at
most 10MB a minute.

### limits for an address = 5 x the limits for a connection

**Rationale:** A connection's allowance is counted for the key that
connected. A key costs nothing, so a peer that reconnects under a new one
would start again from nothing. An address is what an outsider has to
spend. So all the connections from one address share
max_connections_per_ip times what one connection may send, counted for the
address whatever keys it uses.

A peer that goes over three times in ten minutes is cut off, and its
address is refused for 15 minutes (ban_transient). Two relays that list
each other are not limited: they are one operator's, and each passes on
everything its devices send.

### outbox_refused_retry_max = 600s

**Rationale:** An item that a relay refused stays in the outbox and is
offered again, to the next relay in turn. The wait doubles from the flush
interval after each refusal in a row (4s, 8s, 16s, ...) and stops growing
here.

**Derivation:** A relay refuses for a passing reason (it is restarting, its
disk is full) or a lasting one (the item is not valid for it). The first
few retries, seconds apart, cover the passing kind. For the lasting kind,
one small push every ten minutes costs nothing, and delivers the item
within ten minutes of the reason going away.

### outbox_batch_max_bytes = 192KB, outbox_batch_max_items = 500

**Rationale:** One outbox push holds at most three entries of the largest
size. That is far inside max_message_bytes today (checked at compile time),
and is small enough that max_message_bytes can come down to 256KB once
every node sends batches this small. The item bound caps header overhead.

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

## 6. Stream Timeout

### STREAM_TIMEOUT = 10s

**Rationale:** One timeout for all stream read/write operations at the codec layer.
Every `read_frame()` and `write_frame()` call in `protocol.rs` is wrapped in
`tokio::time::timeout(STREAM_TIMEOUT, ...)`. This is the single enforcement point
for all protocol operations: push, sync, fetch, peer-sharing, and the initial
protocol byte read.

**Why one timeout, not per-protocol:** Minimise diversity. Per-protocol timeouts
(e.g., 5s for peer-sharing, 30s for fetch) add configuration surface without
meaningful benefit. A peer that can't complete any operation in 10s is either
overloaded or malicious -- the correct response is the same regardless of protocol.
One timeout at one layer means one thing to reason about and one thing to test.

**Why 10s:** Generous for LAN operations (~1ms RTT) and sufficient for WAN at
broadband speeds. At 10s timeout with MAX_MESSAGE_BYTES=1MB, the minimum sustained
throughput required is ~800Kbps -- well within any broadband connection. The same
value is used for `incoming_handshake_timeout` (§1), providing consistency.

**If you increase to 30s:** Stalled streams (crashed peer, network black hole)
block the stream handler for 30s before cleanup. With multiple concurrent streams,
this delays detection and wastes resources.

**If you decrease to 3s:** May reject legitimate operations on high-latency WAN
links (e.g., 500ms RTT × multiple round trips for a large fetch response).

**Reference:** The implementation previously had no per-stream timeouts (BV-23
fixed the handshake case only). Session 92 added STREAM_TIMEOUT to all stream
operations after `test_chaos_disconnect_during_sync` exposed a 60s hang on
peer crash (QUIC idle timeout was the only backstop).

---

## 7. P2P Select Loop Parameters

### MAX_IN_FLIGHT = 10

**Rationale:** Maximum concurrent outbound connect attempts (spawned tasks).
Caps resource usage and prevents accidental DoS against many peers
simultaneously. 10 concurrent QUIC handshakes is ~10 sockets + 10 TLS
sessions -- negligible on relay hardware, meaningful on personal devices.

**If you increase to 50:** Burst of 50 simultaneous handshakes on startup.
May trigger rate limits on destination peers. Acceptable for relays.

**If you decrease to 3:** Bootstrap slows proportionally. 21 peers at 3
concurrent = 7 waves, ~35s minimum mesh formation at R=20.

### CONNECTS_PER_CYCLE = 3

**Rationale:** Maximum outbound connect attempts per peer-share tick (5s)
during **post-bootstrap steady state**. Rate-limits gossip-discovered
connections to prevent an attacker from rapidly cycling peers through the
connect pipeline. 3 per 5s = 36/min, well below any resource concern but
slow enough that Sybil peers can't dominate the connection set.

**Bootstrap exception:** When `hot < hot_min`, all candidates come from
trusted bootnodes or their immediate peer-share responses. During this
phase, CONNECTS_PER_CYCLE is replaced by MAX_IN_FLIGHT -- connect as fast
as concurrency allows. This is safe because:

1. Bootstrap peers are from **configured, trusted bootnodes** (operator-defined).
2. The governor's urgent mode already bypasses `min_warm_tenure` for the
   same reason (trusted source, need fast mesh formation).
3. Post-bootstrap, churn and scoring handle quality control for all peers
   regardless of how they were initially promoted.
4. Cardano follows the same model: topology-configured peers are immediately
   trusted; discovered peers go through the mini-protocol pipeline.

**Derivation:** At R=20, a relay needs 21 hot peers. With MAX_IN_FLIGHT=10
during bootstrap, two waves complete in ~10s. Post-bootstrap, 3 per 5s keeps
the gossip exploration rate bounded. The transition from bootstrap to steady
state is automatic: once `hot >= hot_min`, the rate drops to CONNECTS_PER_CYCLE.

**If you increase to 10:** Faster gossip exploration but more aggressive
outbound traffic. May be appropriate for relays in large meshes.


## 8. Bootstrap Parameters

Bootnodes are configured by name (the defaults are `relay1` and
`relay2.cordelia.seeddrill.ai`). A node resolves the names again while it
runs, and the P2P loop dials the latest addresses whenever it has no hot
relay (decision 2026-09-30-agent-memory-sync §4.6).

### bootnode_resolve_interval = 300s

**Rationale:** How often the names are looked up again once they resolve,
so a relay that moves, or a site whose address changes, is followed. DNS
changes for relays are rare and TTLs are minutes, so five minutes costs
nothing and catches a change well within an hour.

### bootnode_resolve_retry = 30s

**Rationale:** How often a node tries while none of the names resolves,
typically because it started before its network was up (a laptop at
login). It then finds its relays within half a minute of the network
coming up; one DNS query per name every 30 s is negligible. It must be
shorter than the interval (`protocol.rs` asserts this).

## 9. Usage Count Parameters

A relay counts the distinct peers it has seen in the last day and week
(`cordelia stats`, `/metrics`), from a keyed hash of each peer's key.

### sighting_refresh = 300s

**Rationale:** How often a connected peer's "last seen" is refreshed. Counts
are per day and per week, so five minutes is ample precision, and it keeps
the writes to one row per peer every five minutes.

### sighting_retention = 8 days

**Rationale:** How long a peer's hash is kept after it was last seen: the
weekly window plus a day of slack. Nothing about a peer outlives the count
it is needed for.

---

*Spec version: 1.4*
*Created: 2026-03-16*
*Updated: 2026-09-30*
*Cross-refs: network-protocol.md §9, §12; network-behaviour.md §2.2, §5*
