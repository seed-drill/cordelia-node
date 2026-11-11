# Debug Telemetry Specification

> Defines the minimum observable telemetry that every Cordelia node MUST emit
> to enable diagnosis of protocol failures from logs alone, without guessing.

> **v1 status.** No node carries the older kind of channel
> ([decision record of 2026-11-10 (older kind)](../decisions/2026-11-10-removing-the-older-kind.md),
> rules 1, 2 and 7): the telemetry of Item-Push and Item-Sync (§3.1, §3.2)
> and the trace of an item across nodes (§4) are gone, and the status counts
> no items, pushes or syncs (§6). A node logs at DEBUG each stream that a
> peer opens to it (`stream opened (inbound)`, with the protocol:
> `entry_show`, `channel_prove`, `entry_pull`, `entry_push`,
> `relay_entries`, `peer_share`, or for the older kind `item_sync`,
> `item_push`, `channel_announce`), and `stream closed`, with
> `duration_ms`, once it has served one. It logs at DEBUG that it answered
> a sync of the older kind with nothing, or refused a push or an
> announcement of it. The rules of §1, §2, §5 and §7 stand.

**Motivation:** During Phase 1 E2E testing, BV-22 (relay re-push silently skipping peers)
took hours to diagnose because the daemon produced no log output when `open_bi()` hung.
The operator could not distinguish "task not spawned" from "task stuck" from "task failed silently."
This spec exists to prevent that class of debugging failure.

**Principle:** If an operator cannot determine what happened from a single `grep` across
all node logs, the telemetry is insufficient.

---

## 1. Log Levels

| Level | Purpose | Visible in production | Example |
|-------|---------|----------------------|---------|
| ERROR | Unrecoverable failures requiring operator action | Always | DB corruption, bind failure |
| WARN | Recoverable failures that may indicate problems | Always | Bootnode timeout, stream limit hit |
| INFO | Lifecycle events (startup, connect, disconnect) | Default | "relays configured", "handshake complete (outbound)" |
| DEBUG | Per-operation tracing (stream-level) | On request | "stream opened (inbound)", "stream closed" |
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
DEBUG stream opened  peer=<node_id> direction=<outbound|inbound> protocol=<entry_show|entry_pull|entry_push|peer_share|...> stream_id=<id>
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

Gone (decision 2026-11-10 (older kind), rule 2): no node pushes an item, and
every node refuses a stream of `0x06` at the byte (rule 7).

### 3.2 Item-Sync / Pull (§4.5)

Gone as a sync (decision 2026-11-10 (older kind), rule 7): no node fetches
or serves an item, and every node answers a stream of `0x05` with nothing.

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
INFO  relays configured           count=<N>
WARN  no key is configured for this relay: whichever node answers there is accepted  relay=<host>
INFO  relay addresses updated     addrs=[<host>=<addr>, ...]
DEBUG dialling relay              relay=<host> addr=<addr>
WARN  another key answered at a relay's address; refusing it  relay=<host> answered=<node_id>
```

---

## 4. End-to-End Trace Example

Gone (decision 2026-11-10 (older kind), rule 2): no node publishes or pushes
an item to trace.

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

The `/api/v1/status` endpoint MUST include, among the rest that
channels-api.md §3.18 lists:

```json
{
  "uptime_secs": 1234,
  "peers_hot": 3,
  "peers_warm": 1,
  "sync_errors": 0
}
```

Counters are cumulative since startup. It counts no items, pushes or syncs:
no node pushes or syncs an item (decision 2026-11-10 (older kind), rule 2).

---

## 7. Implementation Checklist

Before a protocol handler is considered complete, verify:

- [ ] Every spawned task logs on spawn (DEBUG)
- [ ] Every spawned task logs on success (DEBUG)
- [ ] Every spawned task logs on error (DEBUG/WARN)
- [ ] Every spawned task has a timeout and logs on timeout (WARN)
- [ ] Silent skips (if-let None, continue) log what was skipped and why (WARN)
- [ ] Connection operations include `peer=<node_id>` in all log lines
- [ ] Stream operations include `protocol=<type>` in log lines
- [ ] No `await` on network I/O without `tokio::time::timeout`

---

*Spec version: 1.0*
*Created: 2026-03-14*
*Motivation: BV-22, Cordelia Phase 1 E2E testing*
*Cross-refs: network-protocol.md §4, [topology-e2e.md](https://github.com/seed-drill/cordelia-node/blob/c3cc5756/docs/specs/topology-e2e.md), [review-build-verification.md](https://github.com/seed-drill/cordelia-node/blob/c3cc5756/docs/archive/reviews/review-build-verification.md)*
