# Debug Telemetry Specification

> Defines the minimum observable telemetry that every Cordelia node MUST emit
> to enable diagnosis of protocol failures from logs alone, without guessing.

**Motivation:** During Phase 1 E2E testing, BV-22 (relay re-push silently skipping peers)
took hours to diagnose because the daemon produced no log output when `open_bi()` hung.
The operator could not distinguish "task not spawned" from "task stuck" from "task failed silently."
This spec exists to prevent that class of debugging failure.

**Principle:** If an operator cannot determine what happened from a single `grep item_id` across
all node logs, the telemetry is insufficient.

---

## 1. Log Levels

| Level | Purpose | Visible in production | Example |
|-------|---------|----------------------|---------|
| ERROR | Unrecoverable failures requiring operator action | Always | DB corruption, bind failure |
| WARN | Recoverable failures that may indicate problems | Always | Bootnode timeout, stream limit hit |
| INFO | Lifecycle events (startup, connect, disconnect) | Default | "connected to bootnode", "bootstrap complete" |
| DEBUG | Per-operation tracing (item-level, stream-level) | On request | "push delivered", "sync request served" |
| TRACE | Wire-level detail (frame bytes, CBOR dumps) | Never in production | Frame hex dumps |

**Rule:** Every protocol operation MUST produce at least one DEBUG log on entry and one on exit (success, error, or timeout). If a spawned task can hang, it MUST log on spawn.

**Rule:** Every `.await` that can hang (network I/O, QUIC handshake, stream operations) MUST have a timeout AND log on both entry and timeout. If entry is logged but neither success nor timeout appears, the operation is hanging -- this is the diagnostic signal. (Learned from BV-23: `incoming.await` hung with no log, blocking the entire select loop.)

---

## 2. Connection Telemetry

### 2.1 Connection Lifecycle

Every connection state change MUST be logged at INFO:

```
INFO connected to bootnode        bootnode=<addr> peer=<node_id>
INFO connected via peer-sharing   peer=<node_id> peers=<count>
INFO accepted inbound connection  peer=<node_id> peers=<count>
INFO peer connection closed       peer=<node_id> reason=<idle|reset|shutdown|error>
WARN bootnode connection timed out bootnode=<addr> timeout_secs=10
```

### 2.2 Stream Telemetry

Every stream open/close MUST be logged at DEBUG:

```
DEBUG stream opened  peer=<node_id> direction=<outbound|inbound> protocol=<push|sync|peer_share|...> stream_id=<id>
DEBUG stream closed  peer=<node_id> stream_id=<id> reason=<fin|rst|timeout|error> duration_ms=<ms>
WARN  stream open timed out  peer=<node_id> protocol=<...> timeout_secs=<N>
```

### 2.3 Transport Metrics

The node SHOULD expose (via status endpoint or periodic log) at DEBUG level:

```
DEBUG transport stats  peer=<node_id> open_streams=<N> max_streams=<limit> rtt_ms=<N> bytes_sent=<N> bytes_recv=<N>
```

This MUST be logged at least once per governor tick (every `tick_interval_secs`).

---

## 3. Protocol Operation Telemetry

### 3.1 Item-Push (§4.6)

**Publisher side (outbound push):**
```
DEBUG spawning push task    peer=<node_id> item=<item_id> channel=<channel_id>
DEBUG push open_bi started  peer=<node_id> item=<item_id>
DEBUG push delivered        peer=<node_id> item=<item_id> stored=<N>
DEBUG push send failed      peer=<node_id> item=<item_id> error=<msg>
WARN  push open_bi timed out peer=<node_id> item=<item_id> timeout_secs=<N>
DEBUG item pushed to peers  item=<item_id> channel=<channel_id> total_peers=<N> pushed=<N> excluded=<N> skipped=<N>
```

**Receiver side (inbound push):**
```
DEBUG processed inbound push  peer=<node_id> stored=<N> dedup_dropped=<N> items=<N>
DEBUG store failed            item=<item_id> error=<msg>
WARN  content hash mismatch   item=<item_id>
```

**Relay re-push:**
```
DEBUG relay re-push queued   peer=<sender_id> item=<item_id> stored=<N>
```

**Silent skip rule:** If `get_connection()` returns None for a peer in `connected_peers()`, log:
```
WARN push skipped: connection not found  peer=<node_id> item=<item_id>
```

**Terminology:** In push logs, `excluded` = sender peer (relay re-push loop prevention), `skipped` = peer where get_connection() returned None (bug indicator). These are distinct: excluded is expected, skipped is unexpected.

### 3.2 Item-Sync / Pull (§4.5)

**Requester side:**
```
DEBUG sync request sent     peer=<node_id> channel=<channel_id>
DEBUG sync response         peer=<node_id> channel=<channel_id> headers=<N> missing=<N>
DEBUG fetch request sent    peer=<node_id> items=<N>
DEBUG fetch response        peer=<node_id> stored=<N> dedup=<N>
WARN  sync request timed out peer=<node_id> channel=<channel_id> timeout_secs=<N>
```

**Server side:**
```
DEBUG served sync request   peer=<node_id> channel=<channel_id> headers=<N>
DEBUG served fetch request  peer=<node_id> items=<N>
```

### 3.3 Peer-Sharing (§4.3)

```
DEBUG peer-share request sent     peer=<node_id> max=<N>
DEBUG peer-share response         peer=<node_id> received=<N> new=<N> filtered=<N>
DEBUG peer-share connect attempt  addr=<addr> node_id=<id>
DEBUG peer-share connect failed   addr=<addr> error=<msg>
DEBUG served peer-share request   peer=<node_id> count=<N>
```

### 3.4 Bootstrap (§10.3)

```
INFO  bootnodes resolved          count=<N> config=<N> dns=<N> fallback=<N>
INFO  connected to bootnode       bootnode=<addr> peer=<node_id>
WARN  failed to connect to bootnode bootnode=<addr> error=<msg>
WARN  bootnode connection timed out bootnode=<addr> timeout_secs=10
INFO  bootstrap complete          peers=<N>
```

---

## 4. End-to-End Trace Example

An operator should be able to trace an item's lifecycle with:
```bash
grep "ci_01ABC123" logs/p1.log logs/r1.log logs/p2.log
```

Expected output across nodes:

```
# P1 (publisher)
p1: DEBUG item pushed to peers  item=ci_01ABC123 total_peers=3 pushed=2 excluded=0 skipped=0
p1: DEBUG spawning push task    peer=<r1_id> item=ci_01ABC123
p1: DEBUG spawning push task    peer=<p2_id> item=ci_01ABC123
p1: DEBUG push delivered        peer=<r1_id> item=ci_01ABC123 stored=1
p1: DEBUG push delivered        peer=<p2_id> item=ci_01ABC123 stored=1

# R1 (relay)
r1: DEBUG processed inbound push  peer=<p1_id> stored=1 dedup=0 items=1
r1: DEBUG relay re-push queued    peer=<p1_id> item=ci_01ABC123 stored=1
r1: DEBUG spawning push task      peer=<p2_id> item=ci_01ABC123
r1: DEBUG push delivered          peer=<p2_id> item=ci_01ABC123 stored=0 (dedup)

# P2 (receiver)
p2: DEBUG processed inbound push  peer=<p1_id> stored=1 dedup=0 items=1
p2: DEBUG processed inbound push  peer=<r1_id> stored=0 dedup=1 items=1 (dedup)
```

If any line is missing, the operator knows exactly which step failed.

---

## 5. Timeout Specification

Every async operation that can block MUST have a timeout.

### 5.1 Codec-Level Defence (Session 92)

All codec I/O operations (read_frame, write_frame, read_protocol_byte, write_protocol_byte)
have a **built-in 10s timeout** (`STREAM_TIMEOUT`). Callers do NOT need to add their
own timeout wrappers. The codec defends itself at the lowest layer.

**Rationale:** A single uniform timeout (10s) at the codec layer eliminates redundant
multi-layer timeouts that previously caused silent shadowing bugs (caller used 5s,
codec used 30s -- actual timeout was 5s, not 30s as documented). 10s covers 99th
percentile network latency while detecting unresponsive peers promptly.

### 5.2 Connection-Level Timeouts

These are NOT codec operations and require explicit timeout wrappers:

| Operation | Timeout | Log on timeout | Action |
|-----------|---------|---------------|--------|
| QUIC incoming handshake | 10s | WARN | log WARN, continue accepting |
| Bootstrap connect per bootnode | 10s | WARN | continue to next bootnode |
| Handshake (initiate/accept) | 10s | WARN | close connection |
| open_bi (all protocols) | 10s | DEBUG | log, skip peer |
| connect_to (governor/peer-share) | 10s | WARN | mark_dial_failed |
| shutdown_and_wait | 30s | WARN | force close endpoint |

**Rule:** No `await` on a network operation without either a codec-level or explicit timeout. The QUIC idle timeout (60s) is a safety net, not a substitute.

---

## 6. Status Endpoint Telemetry

The `/api/v1/status` endpoint MUST include:

```json
{
  "uptime_secs": 1234.5,
  "peers_hot": 3,
  "peers_warm": 1,
  "sync_errors": 0,
  "items_stored": 42,
  "items_pushed": 15,
  "items_received": 27,
  "streams_opened": 156,
  "streams_active": 2,
  "push_timeouts": 0,
  "sync_timeouts": 0
}
```

Counters are cumulative since startup. `streams_active` is a gauge.

---

## 7. Implementation Checklist

Before a protocol handler is considered complete, verify:

- [ ] Every spawned task logs on spawn (DEBUG)
- [ ] Every spawned task logs on success (DEBUG)
- [ ] Every spawned task logs on error (DEBUG/WARN)
- [ ] Every spawned task has a timeout and logs on timeout (WARN)
- [ ] Silent skips (if-let None, continue) log what was skipped and why (WARN)
- [ ] Item operations include `item=<item_id>` in all log lines
- [ ] Connection operations include `peer=<node_id>` in all log lines
- [ ] Stream operations include `protocol=<type>` in log lines
- [ ] No `await` on network I/O without `tokio::time::timeout`

---

*Spec version: 1.0*
*Created: 2026-03-14*
*Motivation: BV-22, Cordelia Phase 1 E2E testing*
*Cross-refs: network-protocol.md §4, topology-e2e.md, review-build-verification.md*
