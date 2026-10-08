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

### entry_overhead_bytes = 1KB, and the size of each field

**Rationale:** One size for every entry has to mean every field of it, and
a limit on bytes has to count what an entry takes. Otherwise an entry
could carry in its type what its content may not, and a thousand entries
of three bytes would count as three kilobytes.

- Each field other than the ciphertext has a size it must fit in:
  max_item_id_len = 64 (an ID is 29 characters), max_channel_id_len = 96
  (the longest kind, an inbox, is 70), max_item_type_len = 32,
  max_timestamp_len = 40 (an RFC 3339 time with nanoseconds and an offset
  is 35). The rest are of fixed size. An entry over any of them is refused
  by whoever is sent it, and is not stored.
- entry_overhead_bytes is what an entry may take beyond its ciphertext.
  Every limit on bytes counts an entry as its ciphertext plus this: a
  connection's and an address's allowance, what one channel may hold at a
  relay, and what a device sends in one push and in one minute. A device
  and a relay count the same way, or a device would be refused.

**Derivation:** The fields at their largest, with their names and lengths
as they are encoded, come to about 660 bytes (checked at compile time, and
by a test that encodes the largest entry). A row and its place in three
indexes take about as much again where it is stored. 1KB covers both in
round figures, and is what a fetch already allowed for each entry's
header. An entry of memory is a kilobyte or more, so for those the limits
are as they were to within a factor of two. For entries of a few bytes
they are now limits: a connection can add about 2,000 entries a minute to
a relay, and a channel can hold about 16,000.

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

In a channel from its secret a revision has the same bound, and is read as
a band and a count (§12.1). There is no epoch there.

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
many bytes of entries a minute, each entry counted as its ciphertext and
entry_overhead_bytes. A push that would go over is refused whole, with no
answer, so a sender on any version keeps what it sent. An address's
allowance is kept until nothing is counted against it any more, whether or
not its connections are still open.

A device paces itself to 1.5MB a minute to each relay, a quarter under
what a relay allows, so that it is never the one refused.

**Derivation:** Two days of our own use is 49KB across five channels. Our
whole skills folder is 4MB, which takes about three minutes to send the
first time. From one address, with its five connections, a relay takes at
most 10MB a minute.

### max_channel_bytes_at_relay = 16MB, new_channels_per_address_per_hour = 16

**Rationale:** A relay's total storage is its operator's setting
(max_storage_bytes, 1GB by default). Within it, one channel may hold only
so much, and one address may make the relay hold only so many channels it
did not hold before. A channel costs nothing to make, so without the
second a single address could make a relay hold any number of them.

**Derivation:** After two days of use one of our devices holds 49KB across
five channels, and our whole skills folder is 4MB: 16MB is several times
the largest channel we expect. A person with a dozen projects makes a
dozen channels the first time they sync; 16 an hour covers that. One
address can then make a relay take at most 256MB an hour, so filling the
default 1GB takes it four hours, or several addresses.

These two are of the older kind of channel. A channel from its secret has
a cap of the same size and an allowance of its own, 256 an hour (§12.7),
and each kind is counted against a cap of its own: a relay's
`max_storage_bytes` bounds each, so for the one version that carries both
a relay can hold twice that.

### relay_ask_again_secs = 600

**Rationale:** A relay is a cache, and its devices are where the entries
are. It asks each peer connected to it which channels it holds and fetches
what it lacks: its hot peers every sync cycle (as a rule, the relays it
lists), and every other peer when it connects and then this often after it
has fetched all the peer holds. The same wait passes before a relay takes
again a channel it dropped to make room, and doubles each time the channel
is dropped again (relay_dropped_wait_doublings = 5, so up to 32 times):
a channel that is dropped each time it is taken does not fit.

**Derivation:** A device sends what it writes as it writes it, so asking is
only for what the relay lost, dropped or had no room for. Ten minutes is
the longest a device waits before it offers again what a relay refused
(outbox_refused_retry_max_secs), so whichever of the two has the entry, the
other hears of it in about that time, and in up to twice that for a
channel that was dropped. When a device connects, the relay lists each of
its channels from the start. After that it costs a device one small
exchange every ten minutes: the list of its channels, and one request for
each. Without the wait before a dropped channel is taken again, a relay at
its cap would fetch the channel, drop it, and fetch it again every cycle.

What a relay fetches from a device counts as what the device may push
does (push_bytes_per_peer_per_minute, and five times that for the address),
in an allowance of its own, so that what a relay asks for is never held
against what the device sends. A connection can therefore make a relay take
4MB a minute in all, pushed and fetched, and an address 20MB. When the
allowance for fetching is used up the relay asks again one rate window
later, so a relay that was rebuilt fills from a device at up to 2MB a
minute. An entry's size is not known until it is fetched: the relay asks
for a whole page only while the allowance has room for the most a page can
cost, and otherwise for as many entries as would fit at the largest size,
so small entries come more slowly near the end of each minute.

### max_channels_asked_of_a_peer = 1024

**Rationale:** What a peer lists when a relay asks which channels it holds
is the peer's to write. Without a bound it could have a relay make a
request, and keep a place, for each of any number of names. Only IDs that
could be a channel's are taken (max_channel_id_len), and this many in one
pass.

**Derivation:** A person's device holds tens of channels. One that holds
more than this is asked about a different part of them each time.

What a relay keeps for a peer is bounded too. It keeps a place in a
peer's list, and a page size, for at most this many channels of a peer
that is not a relay it lists: when it has that many, a caught-up channel's
place makes room before one that is still being fetched, so a long channel
keeps its place from one pass to the next unless more than this many of
the peer's channels are being fetched at once. Nothing is kept where a
peer lists nothing, and what is kept for a peer is forgotten at the first
cycle after it has gone. A place is a channel's ID and a few numbers, with
what the table around it takes, at most about 230 bytes: 200 connections
with 1,024 channels each would cost a relay about 46MB.

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

### outbox_batch_max_bytes = 195KB, outbox_batch_max_items = 500

**Rationale:** One outbox push costs at most what three entries of the
largest size cost (195KB with entry_overhead_bytes). That is far inside
max_message_bytes today (checked at compile time), and is small enough
that max_message_bytes can come down to 256KB once every node sends
batches this small. Since each entry counts for at least a kilobyte, a
push holds fewer than 200 entries, and the item bound is not reached.

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

### NODE_STOP_TIMEOUT = 30s (3 x STREAM_TIMEOUT)

**Rationale:** A node that is told to stop exits within a bounded time,
whatever one of its parts is waiting for. Once it has been told, it waits
this long at most, for its HTTP server and its peer-to-peer loop together,
and then exits without what has not finished, with a failure. Blocking
work on the node's own runtime (a sync cycle) is then given one more
STREAM_TIMEOUT, and is left as a crash would leave it. So a node exits
within 40 seconds of being told: as a rule within a second, and within a
few while a client of its API has a connection open.

The HTTP server is stopped gracefully. A connection still open when it is
told (a request being answered, or a client idle between requests) is
given one STREAM_TIMEOUT, and is then closed; an idle one closes sooner of
itself. So, as a rule, the process does not end in the middle of a
request, some of which (removing a device, rotating a key) make several
writes. A request whose handler is held up longer than that, or begins in
its last moment, can still be cut, as a crash would cut it. Before 2.9.1,
actix-server could wait for ever in a graceful stop: a worker could leave
without answering the stop request (#99). The node asks for a later one,
and its own bound covers the rest.

A node whose HTTP server or peer-to-peer loop ends without its being told
to stop stops the other, and exits with a failure, so that whatever runs it
starts it again. It does not run on without a part, looking alive.

**Derivation:** The HTTP server gives a request it is answering one
STREAM_TIMEOUT, and the peer-to-peer loop gives its peers one to hear that
it is closing, side by side; the rest is margin. systemd kills a node that
has not exited after a minute and a half, so a node that waited for ever
would make every restart and upgrade take that long. launchd (20 seconds)
and Docker (10 seconds, unless a grace period is set) kill sooner. That is
what a crash is: what was committed stays, and something made of several
writes can be left half done.

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

## 10. Local History Parameters

Local history keeps the text of a memory file as it was just before sync
replaced or removed it (decision 2026-09-30 §4.5b). Both bounds are settings
(`[history]`, configuration.md §2.11), read when the node starts.

### HISTORY_DAYS = 30

**Rationale:** How long a kept text stays. History is for a mistake that a
person notices: a month covers a holiday and a project picked up again after
one. Longer keeps more of what was replaced on purpose, in the clear, on
every device. 0 turns history off and removes what is kept.

### HISTORY_MAX_BYTES = 256 MB

**Rationale:** The most that is kept, the oldest going first. A memory file
that syncs is at most 64 KB (`MAX_ITEM_BYTES`), and a record is a file's
whole text, so 256 MB holds at least 4,000 replaced versions of the largest
such file, and far more of ordinary ones. (What a restore replaces is kept
whatever its size: a file too large to sync is still text.) It is a bound
on what an agent that rewrites a file in a loop, or a device that floods,
can make a disk hold, not a figure that ordinary use reaches. It is applied
at intervals, not at every moment: see `HISTORY_SWEEP_SHARE`.

### HISTORY_TURN_WAIT_SECS = 10

**Rationale:** How long a restore or a drop waits for a sync cycle that is
running before the node answers that it is busy. A cycle of an ordinary
folder ends well inside a second, so ten seconds is a cycle that is stuck or
very large. The node does nothing then, and nothing is queued, so nothing is
carried out after that answer.

A command that waits for the node with no limit of its own (a restore, a
drop) says that it is still waiting two seconds after this wait is up, and
not at the same moment: its wait begins before the request is sent, so at
ten seconds it would say so just ahead of nearly every "busy" answer. It
gives up nothing at twelve seconds: it only says that it is waiting.

### HISTORY_SWEEP_INTERVAL_SECS = 3600

**Rationale:** How often records that are too old, or over the size, are
dropped. Age is counted in days, so an hour is ample, and the sweep also
runs when the node starts. The hour is counted while the machine is awake:
a machine that sleeps sweeps no later than an hour of being awake after
the hourly sweep was last due.

### HISTORY_SWEEP_SHARE = 8

**Rationale:** An hour is too long for the size. A cycle keeps up to 64 KB
for each file it replaces, and a folder that an agent rewrites keeps that
every few seconds. So the store is also swept at the end of a sync cycle
once more than one part in eight of `max_bytes` (32 MB by default) has been
kept since the last sweep. The store then passes its size by that eighth,
by what one cycle keeps and by what restores keep meanwhile, and by no
more. A sweep lists the whole directory, so it is not run after every
cycle that keeps a text: an eighth makes it at most eight sweeps for each
time the store's worth of text is kept.

## 11. Index Line Parameters

The index line of a memory that comes back (decision 2026-09-30 §4.5). A
device writes down the line it takes out of the index and the delete of the
line's file, and puts the line back if the file comes back unlisted.

### INDEX_LINE_PAIR_SECS = 3600

**Rationale:** How far apart the two acts may be published and still be one
deleting of a memory. A person or an agent removes a file and its line in
one sitting, and the two go out in one cycle or in the next. An hour allows
for a cycle that fails between them, and is short enough that a line taken
out today and a file deleted next week are not taken for one act.

### INDEX_LINE_KEPT_DAYS = 90

**Rationale:** As long as a node keeps a delete it has received
(`KEYED_TOMBSTONE_RETENTION_DAYS`): while another device can still bring the
file back over that delete, the line can still be put back.

### INDEX_LINE_MAX_RECORDS = 1024

**Rationale:** A bound on a table that an agent's edits fill. A folder
with more than a thousand memories deleted with their lines in ninety days
is not a case to serve whole: past the bound a record goes for each new
one, and never the one just written. Of the others, one with one half goes
before any that is whole (an index written anew drops many lines at once,
and those halves go within the hour anyway), and then the oldest.

### INDEX_LINE_MAX_PUT_BACKS = 3

**Rationale:** A line that is put back can be taken out again by another
device's merge or by an index that overtakes it, and is then put back
again. Three times covers the reunions that follow one another closely,
and stops two devices that disagree from answering each other for ever.

### INDEX_LINE_LOOK_SECS = 60, INDEX_LINE_LOOK_GAP_SECS = 30

**Rationale:** A device that has just lost a tie on the index merges, and
its merge can publish nothing, so no entry shows that a tie has been merged.
A device that is in step has merged within about half a minute. So a line
goes back only once it has been due at every look for a minute, and a
version that has just come to stand beside the index's starts the minute
again. A cycle runs every five seconds, so a minute is about thirteen
looks. Looks more than 30 seconds apart are not one run of looks: the
machine slept, the clock was moved, or the cycles stopped, and what was
found before says nothing of now.

## 12. A Channel From Its Secret

The constants of the [decision record of 2026-10-04](../decisions/2026-10-04-a-persons-devices.md),
which `protocol.rs` has under "A channel from its secret", grouped here by
what they are for. "Decision" below is that record. Where a
value is derived from another, `protocol.rs` computes it, and a compile-time
assertion there checks each bound that has to hold with another. Where
neither the code nor the record gives a reason for a number, this section
says so.

### 12.1 A Revision

#### REV_BAND_BITS = 9, REV_COUNT_BITS = 44

**Rationale:** A revision is one number, compared as one, and editing adds
one to it (decision §2.3). Its top nine bits are its band and the 44 below
them its count. A statement's band is its number, and band 0 is ordinary
editing, so the bands 0 to 256 are needed: nine bits. The count is what is
left of a revision, whose bound is 2^53 - 1 (`MAX_REV`, §4): a band and a
count are the whole of it, which `protocol.rs` asserts.

#### REV_BAND_SIZE = 2^44, REV_BAND_HALF = 2^43

**Derivation:** Every count that fits in `REV_COUNT_BITS`, and half of that.

**Rationale:** The top half of a band is where a revision is because a
device jumped, or because devices edited on above a jump: editing does not
reach it by itself, since it is 2^43 edits from the bottom. So a revision
there can be moved to the bottom half of the next band at each statement,
by a rule of the number alone, and a name that a device put out of reach
comes back into reach.

### 12.2 The Statement

#### MAX_STATEMENT_NUMBER = 256

**Rationale:** The highest number a statement may have, and so the highest
band a revision may be in. A phrase makes at most this many statements in
this format, and each command that makes one says how many are left once
fewer than 16 are. Under statement 256 there is no next one: the way on is a
new phrase (decision §4.1).

**Why 256:** chosen with the nine bits of a band and with the change
entry's one size (below): no measurement of how many changes a person makes
is behind it yet. A later format lifts the bound.

#### MAX_STATEMENT_DEVICES = 64

**Rationale:** The most devices a statement may list. Each costs its key, a
label of up to 64 bytes, and a secret sealed to it in the change entry: 190
bytes at most.

**Why 64:** chosen with the change entry's one size; no measurement behind
it yet.

#### MAX_STATEMENT_REMOVED = 256

**Rationale:** The most removed keys a statement may list. A statement lists
every key removed so far, so this is also the most keys one phrase removes.
A statement that would list more is refused.

**What it costs:** the bound can be used up. Every device that a person
declines at a prompt is a removed key, and a device that counts can sign 63
records of additions at a time. A phrase with no room left removes nobody
more, and the way on is a new phrase (decision §4.1, §12).

**Why 256:** chosen with the change entry's one size; no measurement behind
it yet.

#### MAX_STATEMENT_CHAIN = 256

**Rationale:** The most statements a statement's chain may name: every
statement it was made after, back to the first. A settlement's chain holds
two branches, so a chain can name more statements than its own number.

**Why 256:** chosen with `MAX_STATEMENT_NUMBER`; no measurement behind it
yet.

#### MAX_DEVICE_LABEL_BYTES = 64

**Rationale:** A label is what a person calls a device, kept as it was
typed: 1 to 64 bytes of printable ASCII.

**Why 64:** chosen with the statement's size at its bounds; no measurement
behind it yet.

#### STATEMENT_HASH_BYTES = 16

**Rationale:** How much of a statement's hash names it on a chain. Only the
phrase signs a statement, so nothing is gained by forging one of these: 16
bytes are enough to tell statements apart, and a chain of 256 is 6 KB and
not 10.

#### MAX_STATEMENT_BYTES = 20,784

**Derivation:** From the bounds above and the widths of the form
(data-formats.md §9.4): a number is eight bytes, a count or a length two, a
key 32, a signature 64.

### 12.3 The Change Entry

#### CHANGE_ENTRY_BYTES = 32 KB

**Rationale:** The size of a change entry's content, always. One size, so
that the entry of one statement takes the room of the one before it at a
relay, and its size says nothing: not even how many devices there are. A
removal therefore needs no new room at a relay, and a relay at its cap
still stores it (decision §2.5, §4.6).

**Why 32 KB:** an entry's content is a power of two. At every bound
together the part for the devices says 26,704 bytes and the part for the
phrase 382, which 16 KB would not hold and 32 KB does. It is within the 64
KB that every entry must fit in.

**What it costs:** a device shows this entry to each relay on every pass.
Whole each time, that is some 280 MB a day from each idle device to each
relay, and a tenth of what a connection may push in a minute. That is why a
show is short after the first on a connection (decision §2.4, item 5).

#### CHANGE_ENTRY_PHRASE_PART_BYTES = 4 KB, CHANGE_ENTRY_DEVICES_PART_BYTES = 28 KB

**Rationale:** The last 4 KB is the part for the phrase, and the rest is
the part for the devices. Each part is one size whatever it says.

**Why 4 KB:** chosen with `MAX_EARLIER_SECRETS`: at its bound the part says
382 bytes. No measurement behind it yet. The other part is what it leaves.

#### SEALED_SECRET_BYTES = 92

**Derivation:** A secret sealed to one device's key, as the node seals to a
key: an ephemeral key (32), a nonce (12), the 32 bytes and a tag (16).

#### MAX_EARLIER_SECRETS = 8

**Rationale:** The most secrets of earlier generations that a change entry
carries for the phrase. They are for what the relays hold in a generation
that was left and that nobody carried: a second change made soon after a
first does not put it out of the phrase's reach (decision §9). A recovery
reads back as far as these go.

**What it costs:** a machine that recovered holds the secrets of up to
eight earlier generations for 90 days, which no other device holds for a
generation it was never in (decision §12).

**Why 8:** chosen with the part's 4 KB; no measurement behind it yet.

### 12.4 An Entry

#### MIN_ENTRY_CONTENT_BYTES = 256

**Rationale:** The smallest an entry's content may be. A content's length is
a power of two from this up to `MAX_ITEM_BYTES`: what it holds is filled up
inside the encryption, so that a relay sees a size class and no length.
There are nine classes.

**What the classes cost:** an entry is padded to a power of two, so a
channel can hold as little as half of its 16 MB in text (decision §12).

**Why 256:** chosen with the classes being powers of two; no measurement
behind it yet.

#### MAX_ENTRY_LINKS = 100

**Rationale:** The most links an entry's chain may have: one for each
version the entry descends from, the newest first. What is older than the
hundredth is not said. A chain is what lets a device ask whether a version
follows its own text, as git asks of a commit and its ancestors, with a
window, because nothing here keeps a history (decision §7.3).

**What it costs:** a device that is more than about a hundred versions of
one file behind keeps a copy beside the file, with no change of devices at
all. A merged index of two lines of versions written apart has about fifty
links for each. For the index of a busy agent a hundred versions can be a
few days' work.

**Why 100:** chosen with the room it takes in every entry (3,202 bytes,
below); no measurement of how far behind a device falls is behind it yet.

#### ENTRY_LINK_HASH_BYTES = 16

**Rationale:** How much of a hash a link holds: the first 16 bytes of the
SHA-256 of a version's value. A link names a version to whoever holds its
text, and a hash of this length is not met by another text by chance.

#### ENTRY_LINK_SIGNER_BYTES = 16

**Rationale:** How much of a key a link holds: the first 16 bytes of the key
that signed the entry the version was taken from. It is asked of a reader's
own devices, which are few, so the start of a key says which of them it is.

#### MAX_ENTRY_CHAIN_BYTES = 3,202

**Derivation:** A count of two bytes, and `MAX_ENTRY_LINKS` links of 32
bytes.

#### MAX_ENTRY_NAME_AND_VALUE_BYTES = 60 KB

**Rationale:** The most an entry's name and its value may be together. The
rest of the 64 KB is kept for the entry's chain, so that it always fits,
whatever the value: no link is ever left out for room, and no entry says
less in order to fit. At every bound together the content is 64,675 bytes
of the 65,536 it may be.

**What it costs:** a file of more than 60 KB does not sync, where the
older kind's limit is 64 KB (decision §10, §12).

#### ENTRY_CLEAR_BYTES = 233, ENTRY_WIRE_OVERHEAD_BYTES = 237, MAX_ENTRY_WIRE_BYTES = 65,773

**Derivation:** What an entry takes in clear beside its content: the
channel's ID, the slot and the author's key (32 each), the revision (8),
whether it is a delete (1) and the two signatures (64 each). On the wire the
content's length is four bytes more. The most an entry takes on the wire is
that and the largest content.

**Rationale:** The clear fields are within the 1 KB that every entry is
counted with (`ENTRY_OVERHEAD_BYTES`), twice over: once as they are stored,
and once for their place in each index. So an entry on the wire is within
what it is counted at, and a limit on bytes that counts entries bounds what
travels. `protocol.rs` asserts both.

### 12.5 The Phrase, and the Labels

#### PHRASE_WORDS = 12, PHRASE_BYTES = 16

**Rationale:** Twelve words of the BIP39 English list encode 128 bits and a
checksum, so a mistyped word is caught. Everything that comes from the
phrase is derived from the 16 bytes that the words encode.

**Why twelve:** chosen with BIP39's shortest form, which a person writes
down and types back when the phrase is made; no measurement behind it yet.

#### PHRASE_TYPED_BACK_MISSES = 3

**Rationale:** `cordelia phrase` shows the twelve words once and has them
typed back, one at a time. A word typed back that is a word of the list and
not the word shown at that number is a miss: the command says so, and asks
for the same number again. The third miss, counted over the whole typing
back and not for each word, stops the command, and nothing is made
(decision §5, §16). A word that is not in the list is no miss: it is no
guess at a word, and it is asked again without bound.

**Why three:** three answers are no way to find a word, which is one of
2048, and a person who miswrote one word has room to mistype twice. No
measurement behind it yet.

#### PHRASE_MISS_PAUSE_SECS = 2

**Rationale:** How long `cordelia phrase` waits before it says that a word
typed back is not the word shown: two seconds before the first miss is
said, twice as long before the second, and nothing before the third, which
ends the command. What is typed during the pause is dropped, and not taken
as the next word. The bound of three misses is what keeps a guess from
finding a word; the pause makes each answer cost time, and keeps a held key
or a pasted line from spending all three at once. A word that is the word
shown, and a word that is not in the list, are answered at once. Nothing
waits where a phrase is proved (`remove-device`, `renew`, `settle`,
`recover`, a carry): no word is judged there, and a pause after some words
and not after others would itself say something.

**Why two seconds:** long enough that a miss is seen before more is typed,
and six seconds in all for a person who misses twice; no measurement behind
it yet.

#### The labels (`LABEL_*`)

**Rationale:** Everything that is derived, signed or sealed has a label of
its own, and no label begins another (a test sets each against each). So no
two things can ever be derived alike, an entry's signature is never taken
for a proof, the author's signature is never taken for the channel's, and
what was sealed to a device for one use opens for no other. The label of
the value that is exported from a TLS session begins `EXPORTER`, as the
labels of exporters do (RFC 5705 §4).

| Constant | Label | What is under it |
|---|---|---|
| `LABEL_ENTRY_KEY` | `cordelia v2 entry` | A channel's entry key, from its secret |
| `LABEL_SLOT_KEY` | `cordelia v2 slot` | A channel's slot key |
| `LABEL_CHANNEL_SIGN` | `cordelia v2 sign` | A channel's signing key, whose public half is its ID |
| `LABEL_PERSONAL` | `cordelia v2 personal` | The personal channel's secret, from the person secret |
| `LABEL_OWN` | `cordelia v2 own` | The secret of a channel of the person's own, by name |
| `LABEL_PAIR` | `cordelia v2 pair` | A pair channel's secret |
| `LABEL_RECOVERY` | `cordelia v2 recovery` | The secret of the phrase's channel, from the phrase |
| `LABEL_LOCKED` | `cordelia v2 locked` | A locked channel's secret (its derivation only, decision §11) |
| `LABEL_PHRASE_SIGN` | `cordelia v2 phrase sign` | The phrase's signing key |
| `LABEL_PHRASE_STATEMENT` | `cordelia v2 phrase statement` | The statement key |
| `LABEL_PHRASE_SEAL` | `cordelia v2 phrase seal` | The key that seals the part of a change entry for the phrase |
| `LABEL_COMMITMENT` | `cordelia v2 commitment` | A statement's commitment to its secret (a hash) |
| `LABEL_STATEMENT` | `cordelia v2 statement` | The phrase's signature on a statement |
| `LABEL_CHANGE_DEVICES` | `cordelia v2 change devices` | The seal of the part of a change entry for the devices |
| `LABEL_CHANGE_PHRASE` | `cordelia v2 change phrase` | The seal of the part for the phrase |
| `LABEL_CHANGE_SECRET` | `cordelia v2 change secret` | A secret sealed to one device in a change entry |
| `LABEL_ENTRY_AUTHOR` | `cordelia v2 author` | The author's signature on an entry |
| `LABEL_ENTRY_CHANNEL` | `cordelia v2 channel` | The channel's signature on an entry |
| `LABEL_ENTRY_CONTENT` | `cordelia v2 content` | The seal of an entry's content |
| `LABEL_ADDITION` | `cordelia v2 addition` | The adder's signature on a record of an addition |
| `LABEL_CHANNEL_PROOF` | `cordelia v2 proof` | The proof that a connection holds a channel's key |
| `LABEL_SESSION_VALUE` | `EXPORTER-cordelia v2 session` | The value both ends export from a TLS session |
| `LABEL_FINGERPRINT` | `cordelia v2 fingerprint` | A key's fingerprint (a hash) |
| `LABEL_CARRY_WORD` | `cordelia v2 carry word` | The phrase's signature on a person's word for a carry: which name, which keys that do not count, and which files above a version that is held (decision §7.3, §9). A signature under it is no statement and no entry |

`LABELS` is all 25, for the test that sets one against another.

#### FINGERPRINT_WORDS_SHOWN = 4

**Rationale:** A label is whatever the device that added a key called it,
and two keys can have one label. So wherever a device is shown for a
decision, the first words of its key's fingerprint are shown beside its
label: what a person can read aloud, or hold beside what another screen
shows. Four words are 44 bits.

**Why four:** chosen with the label it stands beside; no measurement behind
it yet.

### 12.6 Adding a Device

#### MAX_ADDITION_BYTES = 226

**Derivation:** From the widths of a record's form (data-formats.md §9.5),
with a label at its longest and the signature.

#### CHANGE_ENTRY_NAME = "change", HAND_OVER_NAME = "hand-over"

**Rationale:** The phrase's channel holds one entry, and a pair channel is
read for one. Each has one name, so that nothing else there is read. The
change entry's slot is under the channel's ID and not under a key of the
channel: a device holds no key of the phrase's channel, and has to know the
change entry's slot from any other.

#### PAIR_KEY_TYPED_SECS = 3600

**Rationale:** How long a key that a person typed at `cordelia accept`
opens the pair channel with that key. A device reads a pair channel only
with a key that was typed on it within that time, so nothing that a removed
device goes on writing there is read. And it takes only a hand-over that
was made less than this long before or after the key was typed: a pair
channel outlives a phrase, and what was handed long ago is not taken for
what a person means now.

**What it costs:** two devices whose clocks are more than an hour apart
cannot be added to each other, and the command says so.

**Why an hour:** chosen with the two commands, which a person runs on two
machines one after the other; no measurement behind it yet.

#### MAX_TYPED_KEYS = 8

**Rationale:** The most keys typed at `accept` that are within their hour on
a device at one time. A ninth is refused. Each is a pair channel that the
device asks its relays for, for its hour, and a key with which a hand-over
could be taken. A key whose hour has gone holds no place: it is kept only to
say what became of it (`TYPED_KEY_KEPT_SECS`).

**Why 8:** chosen as room to spare over the one key that adding a device
takes; no measurement behind it yet.

#### TYPED_KEY_KEPT_SECS = 86,400

**Derivation:** 24 times `PAIR_KEY_TYPED_SECS`.

**Rationale:** A typed key is kept after its hour to say what became of it.
It reads nothing after its hour.

**Why a day:** chosen with the hour it follows; no measurement behind it
yet.

#### HAND_OVER_KEPT_SECS = 7200

**Derivation:** Twice `PAIR_KEY_TYPED_SECS`.

**Rationale:** How long the device that adds keeps a hand-over in its
store, from the time the hand-over says it was made. A hand-over holds the
person secret. No device takes one that was made an hour or more before a
key was typed, and a typed key opens the pair channel for an hour: after
two hours nobody can take it. The device then writes a delete over it at
each relay that it had sent it to, so that no relay goes on holding that
generation's secret sealed to a key.

#### MAX_HAND_OVER_RECORDS = 2

**Rationale:** The record of the addition, and the record of the adder's
own addition. A chain of additions is two long at most: a device added by
one that was itself added since the last statement may not add until a
statement lists it (decision §6).

#### HAND_OVER_CHANGE_ENTRY_BYTES = 32,960, MAX_HAND_OVER_BYTES = 54,275

**Derivation:** The change entry as a hand-over carries it: the channel's
ID, the slot, the two signatures, and the content at its one size. And the
hand-over at every bound together (data-formats.md §9.8). With its name it
is within what one entry may hold, which `protocol.rs` asserts: a hand-over
is the value of one entry.

#### MAX_COUNTED_DEVICES = 64

**Derivation:** What a statement may list (`MAX_STATEMENT_DEVICES`), so that
the next statement can list every device that counts.

**Rationale:** A reader counts the devices of the statement it has applied,
and those added since in the order it saw their records. A record beyond
the bound is kept as not counted, and a statement makes room.

#### MAX_NOT_COUNTED_RECORDS = 256

**Rationale:** A device that counts can sign any number of records, and
every reader loads what it keeps each time it asks who counts. Over this
bound the oldest record that is not counted goes when a new one is kept. A
record that counts is never dropped for room.

**Why 256:** chosen with the other bounds of 256 here; no measurement
behind it yet.

#### LEFT_SECRET_KEPT_DAYS = 90

**Rationale:** How long a device keeps the secret of a generation it left,
by its own clock: the secret, and nothing else of that generation. It is
for a carry that a person asks for (`cordelia sync carry`, decision §7.3),
which fetches from the relays.

**Why 90:** it is as long as a relay keeps a channel that nobody uses
(`ENTRY_CHANNEL_UNUSED_DAYS`). Chosen with that; no measurement behind it
yet.

#### The names in the personal channel

`PERSONAL_NAME_PREFIX = "name/"`, `PERSONAL_ADDED_PREFIX = "added/"`,
`PERSONAL_APPLIED_PREFIX = "applied/"`, `PERSONAL_LEFT_PREFIX = "left/"`,
`PERSONAL_APPLIED_SENT = " sent"`.

**Rationale:** Each kind of word has a first part of its own, and a
device's word is under its own key or under the name it speaks of, so each
device has a slot of its own and only its own entry there is its word. A
word that a device has applied a statement is the number alone until it has
sent what it carried, and the number and ` sent` after (decision §8).

### 12.7 The Streams, and a Relay

#### PROTOCOL_ENTRY_SHOW = 0x10, PROTOCOL_CHANNEL_PROVE = 0x11, PROTOCOL_ENTRY_PULL = 0x12, PROTOCOL_ENTRY_PUSH = 0x13, PROTOCOL_RELAY_ENTRIES = 0x14

**Rationale:** The streams of entries begin at 0x10, apart from the eight
of the older kind: a peer that does not know them refuses the stream, and
reads none of them as one of its own.

#### SESSION_VALUE_BYTES = 32

**Rationale:** How long the value is that both ends of a connection export
from its TLS session, for a proof to be made over. One length, so that
where the value ends and what follows it begins is never in doubt.

**Why 32:** chosen with the length of a key and of a hash, which is what
follows it in what is signed; no measurement behind it yet.

#### MAX_CHANNELS_PROVED_ON_A_CONNECTION = 1024

**Derivation:** The most channels a relay asks one peer about in a pass,
`MAX_CHANNELS_ASKED_OF_A_PEER` (§4).

**Rationale:** Whoever holds a secret can prove its channel, held or not,
and a secret costs nothing to make: without a bound one connection could
have a relay remember any number of them. A person's device holds tens of
channels.

**What it costs:** a device proves, once a day, the channel of every name
that its personal channel lists. A person with more names than this is
past what that keeps alive at a relay (decision §2.5).

#### MAX_SLOTS_SHOWN_ON_A_CONNECTION = 8

**Rationale:** The most slots for which a relay remembers, for one
connection, the last entry it was shown whole there. A device shows one
entry, the change entry of the phrase it follows, so 8 is room to spare. A
ninth is not remembered, and is shown whole each time.

#### CHANNEL_MARK_BYTES = 8

**Rationale:** A place in a channel is a count of what the relay stored in
one holding of it. A relay that drops a channel and takes it again counts
from 1 again, under another mark: so whoever kept a place from the earlier
holding is handed the channel from the start, and not from a place that
means something else now.

**Why 8 bytes:** chosen with a mark being random, and compared only with
the marks of one channel's holdings; no measurement behind it yet.

#### ENTRY_PAGE_MAX_ENTRIES = 100

**Derivation:** What one page of the older kind lists, `DEFAULT_SYNC_LIMIT`.

**Rationale:** Whoever receives a message checks two signatures for each
entry in it: one message makes it do so for no more entries than a page
holds. A push, and the answer to one, have the same bound.

#### ENTRY_PAGE_MAX_BYTES = 896 KB

**Derivation:** `MAX_MESSAGE_BYTES` less 128 KB.

**Rationale:** A page travels in one message, and 128 KB of the message is
left for what is around the entries, as it is around a push of the older
kind. A page always has room for one entry, whatever its size, so a channel
is never stuck behind an entry that fits no page. And a full page, counted
as entries are counted, is within what one connection may be handed in a
minute. `protocol.rs` asserts both.

#### RELAY_CHANNELS_PAGE_MAX = 1000

**Rationale:** The most channels in one answer of a relay that tells a
relay it works with which channels it holds. Each is its ID, its mark, two
times and a count: a thousand of them are well within one message.

#### MAX_ENTRY_CHANNEL_BYTES_AT_RELAY = 16 MB

**Derivation:** What a channel of the older kind may hold,
`MAX_CHANNEL_BYTES_AT_RELAY` (§4). The two kinds are counted apart, each
against a cap of its own.

**What it costs:** an entry is padded to a power of two, so a name with
more than about half of a channel's cap in text may not fit (decision §10).

#### NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR = 256

**Rationale:** How many channels from their secrets one address may make a
relay hold for the first time in an hour. After a removal every channel of
a person's own is new: the personal channel, and one for each name. So is
a pair channel, each time a device is added. At 16 an hour, which is what
the older kind allows, a person with thirty names would wait two hours for
the last of them, and a home with three devices shares one address. At 256
a home of several people, each with tens of names, moves within the hour.

**What it still bounds:** a channel costs nothing to make, so without an
allowance one address could make a relay hold any number of them. A relay's
cap is what bounds its storage, and it drops its newest channels first, so
the channels that an address makes in an hour can push out only one another
and what is newer still.

#### ENTRY_CHANNEL_UNUSED_DAYS = 90

**Rationale:** How long a relay keeps a channel from its secret that nobody
uses: one whose key no connection has proved, and of which nobody has shown
an entry that the relay holds, for that long is dropped. It is also the
term of a recovery: the phrase brings back what the relays hold for 90 days
after the last device of the person's was on, and no longer (decision §9).

**Why 90:** it is as long as a node keeps a delete
(`KEYED_TOMBSTONE_RETENTION_DAYS`). Chosen with that; no measurement behind
it yet.

#### ENTRY_CHANNEL_USED_STEP_SECS = 3600

**Rationale:** How much later than the time a relay keeps for a channel a
use of the channel must be, for the relay to write it down. A proof, or an
entry shown that the relay holds, is use of a channel, and a device makes
both on every pass: if each were written, every one would be a write to
the relay's disk for whoever asks. Against the 90 days that an unused
channel is kept, an hour is nothing.

#### ENTRY_CHANNEL_SWEEP_INTERVAL_SECS = 3600

**Derivation:** As often as expired deletes are collected,
`TOMBSTONE_GC_INTERVAL_SECS`. Hourly is plenty against 90 days.

#### KEYED_TOMBSTONE_RETENTION_DAYS = 90, for a delete among entries

**Rationale:** The value is the one that the record of 2026-09-30 gives a
deleted key (§4.4 there): a device that was offline for longer can bring a
deleted file back with a stale edit, and 90 days covers a laptop left in a
drawer for a season. It is also how long a delete is held among the entries
of a channel from its secret, at a relay and in a device's own store
(decision §2.3, §7.3), counted from when the node stored the entry. A delete
that is carried at a statement is a new entry, and starts again.

**The timer:** a relay and a device each look once in
`TOMBSTONE_GC_INTERVAL_SECS`, an hour, which is plenty against 90 days. It
is one timer, and one length of time, for both kinds of channel.

#### ENTRY_OFFER_INTERVAL_SECS = 5, RELAY_ENTRY_PULL_INTERVAL_SECS = 10

**Derivation:** A relay passes the entries it took on to the relays it
works with as often as it passes on items of the older kind
(`REPUSH_INTERVAL_SECS`). It asks each of them which channels it holds, and
pulls what it lacks, as often as a node fetches items of the older kind
from its hot peers (`REALTIME_SYNC_INTERVAL_SECS`).

#### RELAY_ENTRY_PULL_PAGES = 10, RELAY_CHANNEL_PAGES_PER_PASS = 10

**Rationale:** The most pages of one channel that a relay pulls from a
relay it works with in one pass, and the most pages of that relay's list of
channels that it reads in one. A longer channel, and a longer list, is gone
on with in the next pass, from where this one stopped: one long channel
does not keep every other waiting, and a list which never ends keeps a
relay asking no longer than this. Ten pages of the list are ten thousand
channels.

**Why 10:** ten pages of a channel are a thousand entries in a pass. Chosen
with that; no measurement behind it yet.

### 12.8 The Limits on the Streams

#### ENTRY_REQUESTS_PER_PEER_PER_MINUTE = 3000

**Rationale:** How many requests one connection may make in a minute on the
streams of entries, all of them counted together. A request beyond it is
refused, and is a breach. All the connections from one address share
`MAX_CONNECTIONS_PER_IP` times this. Without it a connection could ask
without end: every proof is a signature for the relay to check, and every
pull a look at its store.

**Derivation:** It is sized for a device with 256 names, which is what an
address may make a relay take in an hour: a pull of each every ten seconds,
and of the personal channel (1,542 a minute); its day's proofs in one
burst, as many as a relay remembers for a connection (1,024); a show for
each pass and each time it sends; and what it pushes.

#### OWN_ENTRY_REQUESTS_PER_MINUTE = 2250

**Derivation:** Three quarters of `ENTRY_REQUESTS_PER_PEER_PER_MINUTE`, as
what a device pushes in a minute (`OUTBOX_BYTES_PER_MINUTE`, §4) is three
quarters of what a relay allows.

**Rationale:** How many requests a device makes of one relay in a minute,
at most, on the streams that prove, pull and push. A device paces itself,
so that it is never the one refused for going over: a request over a
relay's count is a breach, and a few of those cut a device off. What it
does not ask in one minute, it asks in the next. Its shows are not held
back by this, and are few: a device must still hear of a removal.

#### SHOW_ANSWER_ROOM_BYTES = 66,560

**Derivation:** What one entry of the largest size is counted at:
`MAX_ITEM_BYTES` and `ENTRY_OVERHEAD_BYTES`.

**Rationale:** The room that a pull leaves for the answer to a show, in
the bytes that a key and its address may be handed in a minute. A relay
sizes a page of a channel so that this much is left in both allowances, and
only the entry that answers a show may use it: a device that pulls at its
full rate, or shares its address with one that does, is still told of a
removal. A whole page can still be handed beside it: `protocol.rs` asserts
that the room is less than half of a minute's allowance and that a full
page is within the allowance, and the two together are 1,086,464 bytes of
the 2,097,152.

**What is not defended:** whoever shows entries of its own from the same
address can still use that room up (decision §2.5).

#### SHOW_LEAVE_SECS = 10

**Derivation:** The time between two passes, `REALTIME_SYNC_INTERVAL_SECS`.

**Rationale:** How long the leave lasts that a relay's answer to a show
gives a device on that connection (decision §4.6). A device opens a stream
for a channel of its own, and takes what comes back on it, only with
leave. So what a device sends on its own timer, at each publish and from
what it sends again, comes after a show, and a pass that is long shows
again as it goes.

#### WAKE_WAIT_SECS = 30

**Rationale:** How long a device that wakes waits for the relays it is set
up with: when the node starts, or reaches a relay after having reached
none, it neither takes from a channel of its own nor sends to one until
each of them has answered a show, or this long has gone by. Connections
come up one at a time: without the wait a device would take what the first
relay held, and send it what waited, before a second, which had a change,
had answered.

**What it costs:** with one relay out of reach a device waits this long
before it syncs.

**Why 30:** chosen with that cost; no measurement behind it yet.

#### LEAVING_SEND_WAIT_SECS = 30, FIRST_FETCH_WAIT_SECS = 30

**Derivation:** Both are the wait of a device that wakes, `WAKE_WAIT_SECS`,
which is how long a relay that answers at all has had to answer.

**Rationale:** The first is how long a device that is given a new key
waits for its relays to be sent the word that it has left, and the deletes
over what it handed, before it forgets the secret they are written with.
It says which relays were not sent them. The second is how long a folder's
first cycle in a channel waits, once one relay has handed the whole of the
name's channel, for each other relay to hand it too. A folder with no
record in a channel yet waits for a relay, and never for a device: so a
file that another device has already sent meets the folder's as on any
first sync, and is not published a second time (decision §6).

#### CHANNEL_PROOF_AGAIN_SECS = 86,400

**Rationale:** How often a device proves again, on a connection that lasts,
the key of each channel of its own and of each name that its personal
channel lists. A relay drops a channel that nobody has used for
`ENTRY_CHANNEL_UNUSED_DAYS`, and a proof is use. So a name whose only
device is gone is not dropped while any device of the person's is on.

**Why a day:** once a day is 90 uses in the time a relay keeps an unused
channel. Chosen with that; no measurement behind it yet.

### 12.9 The Commands

#### CHANGE_FETCH_MAX_SECS = 120, CHANGE_FETCH_PASSES = 3

**Rationale:** How long the fetch may take that a command makes before it
prepares a change, and how many whole passes it asks for where a pass ends
before it has read every channel to its end (decision §7.1, step 1).
Nothing depends on its being whole: the command says what it could not
fetch, and a removal is never held up by what another device goes on
writing. A pass that found a relay at another turn, or a channel longer
than one pass takes, is read on by the next. A relay that keeps giving no
leave is so asked three times, and not for two minutes.

**Why two minutes:** chosen with the command that waits for it; no
measurement behind it yet.

#### STATEMENTS_LEFT_SAID_BELOW = 16

**Rationale:** A command that makes a statement says how many more the
phrase can make once fewer than this are left, so that a person hears of
the bound before it is reached.

**Why 16:** chosen with `MAX_STATEMENT_NUMBER`; no measurement behind it
yet.

#### RECEIVED_LAST_DAY_SECS = 86,400, RECEIVED_LAST_WEEK_SECS = 604,800

**Rationale:** The two spans over which a command that removes a device
says how much that device wrote that this one received: a person who knows
that a device was stolen on Tuesday wants to see what it wrote since
(decision §7.1). Both are read from local history, and a week is within
what local history keeps by default (`HISTORY_DAYS`, §10), which
`protocol.rs` asserts.

#### CARRY_READ_MAX_SECS = 120

**Derivation:** `CHANGE_FETCH_MAX_SECS`: as long as the fetch before a
change.

**Rationale:** How long a carry by command reads one name at the relays, at
most (decision §7.3): the fetch of the new channel, and then the name's
channel in each generation that the device left. What was not read to its
end by then is said, and the command can be run again.

#### CARRY_FIRST_MAX_SECS = 180

**Derivation:** `CARRY_READ_MAX_SECS` + 60: a little longer than the carry
may read.

**Rationale:** A device that comes to sync a name carries it first (decision
§7.3). This is how long a channel that a carry is being made into holds back
the first cycle of a folder that has just been mapped to its name, at most.
A carry that never says it has ended holds nothing up for longer.

#### CARRY_FROM_WORDS = 6

**Rationale:** How many words of a key's fingerprint name a removed key at
`cordelia sync carry --from` (decision §7.3). A statement lists removed keys
bare, so a machine that never knew a device has no label for it. Six words
are 66 bits. `protocol.rs` asserts that they are more than a device is shown
by (`FINGERPRINT_WORDS_SHOWN`), and within the hash.

**Why six:** chosen with the four that a device is shown by; no measurement
behind it yet.

#### CARRY_WORD_SECS = 600

**Rationale:** How long a person's word for a carry stands (decision §7.3):
ten minutes from when the phrase signed it. The command hands it to the node
at once, and a word that is found later is no word.

**Why ten minutes:** neither the code nor the record gives a reason for the
number. It is longer than a carry may read a name (`CARRY_READ_MAX_SECS`);
no measurement behind it yet.

#### CARRY_PART_MAX_BYTES = 512 KB

**Derivation:** Half of what one message of the wire holds,
`MAX_MESSAGE_BYTES` / 2.

**Rationale:** The most bytes of entries that the node hands a command in
one answer (decision §7.3, §9), where the command reads a channel whose
secret the node does not hold. A channel may hold more than one answer of
the local API carries, so it is handed a part at a time. An entry over the
bound is handed alone, and `protocol.rs` asserts that a part holds an entry
of any size that a channel carries.

#### RECOVERY_MAX_NAMES = 1,024

**Rationale:** The most names a recovery carries (decision §9). A device
that is gone listed names too, and can have listed any number of its own.
The names that a recovery leaves are named.

**Why 1,024:** neither the code nor the record gives a reason for the
number; no measurement behind it yet.

#### RECOVERY_MAX_DEVICES_SHOWN = 256

**Rationale:** The most devices a recovery shows at its prompt, of the
statement's and of those added since (decision §9). Beyond it the command
says how many it could not show, and the look takes nothing from those.
`protocol.rs` asserts that it is no fewer than a reader may count
(`MAX_COUNTED_DEVICES`): a recovery shows every device that counts, and the
records that it may keep as not counted beside them.

#### RECOVERY_MAX_LEFT_SECRETS = 9

**Derivation:** `MAX_EARLIER_SECRETS` + 1.

**Rationale:** The most secrets of generations before its own that a machine
which recovers is handed, and keeps as a device keeps a secret it left
(decision §3, §9): the one of the generation it recovered from, and as many
before it as a change entry gives the phrase.

#### FILE_NAME_SHOWN_CHARS = 120

**Rationale:** The most characters of a file's name that a command prints,
and that the node puts in a line of its status. Another device may have
written the name, and a name may be as long as an entry's text. What is cut
is marked as cut.

**Why 120:** neither the code nor the record gives a reason for the number;
no measurement behind it yet.

#### DEVICE_DELETE_SWEEP_INTERVAL_SECS = 86,400

**Rationale:** A device sweeps the deletes that it has held for 90 days
(`KEYED_TOMBSTONE_RETENTION_DAYS`) once a day, and at its start (decision §16). The time of a sweep is noted once
it has succeeded: one that failed is tried at the next pass.
Each sweep that takes a delete has that channel read again from its start at
every relay, so a folder with steady deletes is read again once a day at most.
A day is fine-grained enough for a bound of 90 days.

#### LEFT_PROOFS_MARGIN_SHARE = 64

**Rationale:** A relay remembers the proofs of 1,024 channels for one
connection (`MAX_CHANNELS_PROVED_ON_A_CONNECTION`), and a read of a generation
that was left spends one for each channel it reads there. The read keeps back
as many places as the device has channels of its own that are not yet proved on
that connection, and a margin of one place in sixty-four (16 of 1,024), for a
name that the device comes to hold while the read goes on and for the pair
channel of a device that is being added (decision §16).

**Never more than half:** a device with more channels of its own than half a
connection's places shares the connection half and half, and the read has the
connection made again as often as it needs. Where no place is left, the
connection is made again and the read goes on from where it was.

**Why one in sixty-four:** chosen with the bound it divides; no measurement
behind it yet.

#### CARRY_PROOFS_MADE_AGAIN = 2

**Rationale:** A proof holds on the connection whose session it was made over.
Where the node says that a connection has changed since a command made its
proofs, the command asks for the sessions again and makes the proofs anew, at
most twice for one channel. After the second time it says which relay it could
not read (decision §16). A relay that was not read is never said to hold
nothing.

**Why twice:** enough for a connection that was made again once while a person
answered prompts, and once more; no measurement behind it yet.

#### LABEL_CARRY_BATCH = `cordelia v2 carry batch`

**Rationale:** The label under which the key of one run of a command signs a
batch of versions that it hands the node on the phrase's word: the batch's
number, and the hash of its versions as they are handed (decision §16). The
word names that key, the command makes it for the one run, and the node takes
each number once. A signature under this label is no word, no statement and no
entry.

#### LOCAL_API_BODY_MAX_BYTES = 2 MB

**Rationale:** The most bytes of one request's body that the local API of a
device reads as JSON. A body over it is refused and is not read.

**Why 2 MB:** room for one version of the largest size that an entry holds,
with every byte of its name and its text written as six (the most that JSON
makes of one) and every byte of its chain as four, beside a batch at its bound
(`CARRY_HANDED_MAX_BYTES`), the word and the batch's signature. A test in
`protocol.rs` holds that sum under the bound.

#### CARRY_HANDED_MAX_BYTES = 512 KB

**Derivation:** A quarter of `LOCAL_API_BODY_MAX_BYTES`. The most bytes of
versions that a command hands the node in one request, each counted as it is
written in the request's body, with its chain and with its name and text as
they are escaped there (decision §7.3). A version over the bound is handed
alone.

### 12.10 The Status Line

#### STATUS_AMBER_WAIT_SECS = 300

**Rationale:** How long a thing that will pass by itself has lasted before
the status line shows it as amber (decision §10.1): no relay connected; a
relay that is connected and does not hold the latest change; and, after a
change, names that are not yet in the new generation or not yet sent.

**Why five minutes:** a machine that wakes, a relay that restarts and a
device that has just applied a change are each through it in less, and what
lasts longer is worth a person's knowing. The first two are counted by the
node's own clock, which does not run while the machine sleeps. `protocol.rs`
asserts that a device that wakes has heard from its relays, or given them
up, well within it (twice `WAKE_WAIT_SECS`).

#### REMOVAL_NOT_APPLIED_SHOWN_DAYS = 7

**Rationale:** For how many days after a device applied a removal the status
line shows as amber that some device has not applied it (decision §8,
§10.1). After that it is said in `cordelia devices` only: a device that lies
in a drawer does not keep every status line amber for good. Names that no
device lists yet in the new generation are shown for as long. `protocol.rs`
asserts that it is shorter than a left secret is kept
(`LEFT_SECRET_KEPT_DAYS`), so that the time the change was applied is still
known.

**Why seven:** neither the code nor the record gives a reason for the
number; no measurement behind it yet.

#### NO_ROOM_STANDS_SECS = 1,200

**Derivation:** 2 × `OUTBOX_REFUSED_RETRY_MAX_SECS`.

**Rationale:** For how long after a relay refused something for room, or for
the address's allowance, the status line takes it that the relay still
refuses (decision §10.1). A device keeps the time of a relay's last refusal,
and offers again what was refused after a wait that doubles up to
`OUTBOX_REFUSED_RETRY_MAX_SECS`. So a relay that still refuses has refused
again within twice that, and one that has not has taken what it was offered,
or was offered nothing more.

### 12.11 The First Start

#### FIRST_START_RETRY_BASE_SECS = 5, FIRST_START_RETRY_MAX_SECS = 600

**Derivation:** The maximum is `OUTBOX_REFUSED_RETRY_MAX_SECS`: ten minutes,
the longest wait before anything a relay refused is offered again.

**Rationale:** How long a personal node waits before it tries its first
start on this version again, after a try that failed (decision §10.1): the
sync cycle's five seconds after the first, and twice as long after each
further one, up to the maximum. A start that cannot succeed (no room for the
copy, no leave to write) does not write its copy again every five seconds.
And a person who has made room is not kept waiting for longer than ten
minutes, and need not restart the node.

#### FIRST_START_RETRY_SLACK_SECS = 1

**Rationale:** How much before its wait has passed a try at the first start
is still made (decision §10.1). A try is made when a sync cycle would have
run, and the first wait is a cycle long: without this, the timer's own
jitter would put every try off by a whole cycle. `protocol.rs` asserts that
it is less than the first wait.

---

*Spec version: 1.4*
*Created: 2026-03-16*
*Updated: 2026-09-30*
*Cross-refs: network-protocol.md §4.9, §9, §12; network-behaviour.md §2.2, §5; data-formats.md §9, §12; decisions/2026-10-04-a-persons-devices.md*
