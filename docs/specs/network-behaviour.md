# Network Behaviour Specification

> Defines HOW the Cordelia P2P network behaves in every situation, including
> errors, failures, and edge cases. Complements network-protocol.md (which
> defines WHAT messages are sent) by specifying what the system DOES in response.

> **v1 status.** Much of this spec was of the older kind of channel, which no
> node carries ([decision record of 2026-11-10 (older kind)](../decisions/2026-11-10-removing-the-older-kind.md),
> rules 1, 2 and 7): the publish of an item, its push, a relay's re-push,
> item-sync and `trusted_peers`. §1 and §6.2 are gone, and the rows of §2,
> §4, §5 and §6 that spoke of them are cut. Every node answers an Item-Sync
> (`0x05`) with nothing, and refuses an Item-Push (`0x06`) and a
> Channel-Announce (`0x04`) at the byte, whatever the peer's state
> (network-protocol.md §4.4 to §4.6, §5.4.2). How an entry of a channel from
> its secret travels, from a device through its relays to another device, is
> in network-protocol.md §4.9. What stands here: connection and protocol
> errors, the governor's states and what each change of state does (§3), and
> the failures of a connection, a relay and a bootnode.

**Principle:** For every operation, this spec answers three questions:
1. What happens on success?
2. What happens on failure?
3. What happens on timeout?

If a situation isn't covered here, the implementer should NOT guess -- they
should add the case to this spec and get it reviewed.

---

## 1. End-to-End Item Lifecycle

Gone (decision 2026-11-10 (older kind), rule 2): no node publishes, pushes,
re-pushes or syncs an item. How an entry of a channel from its secret
travels is in network-protocol.md §4.9.

---

## 2. Error Recovery

### 2.1 Connection Errors

| Error | Detection | Recovery | Timeline |
|-------|-----------|----------|----------|
| Peer unreachable | open_bi timeout (10s) | Skip peer for this operation. Governor detects via keepalive timeout (90s). Mark disconnected. Peer enters Cold. Backoff before retry. | 10s (immediate skip) + 90s (governor detection) |
| Peer crashes (RST) | accept_bi returns ConnectionError | handle_peer_streams exits loop. Governor detects on next tick. Mark disconnected. | Immediate exit + 10s tick |
| Network partition | Keepalive stops. QUIC idle timeout (60s) fires. | Connection closes. Governor marks disconnected. Peer-sharing discovers new paths after heal. | 60s (idle timeout) + 10s (tick) + 5s (peer-sharing) |
| Bootnode unreachable | Bootstrap connect timeout (10s) | Skip, try next bootnode. Node starts with 0 peers if all fail. Peer-sharing retries via fallback peers. | 10s per bootnode |
| All peers lost | Governor hot set empty. | Nothing is sent or fetched. Node waits for inbound connections or bootnode reconnection. Exponential backoff (base 30s, cap 900s). After 5 consecutive failures per peer, stop retrying until backoff expires. Clear failure count after 120s of stable Hot connection. | Variable (30s-900s backoff) |

### 2.2 Protocol Errors

| Error | Detection | Recovery | Timeline |
|-------|-----------|----------|----------|
| Handshake rejected (clock skew) | HandshakeError::ClockSkew | Log WARN, don't connect. Don't ban (could be our clock). | Immediate |
| Handshake rejected (identity mismatch) | HandshakeError::IdentityMismatch | Log WARN, ban peer (Moderate tier). | Immediate |
| Malformed CBOR | CodecError::Decode | Log WARN, skip frame, continue. Transient ban (1 hour, escalating per repeat). See network-protocol.md §5.6. | Immediate |
| Wrong protocol byte | CodecError::UnknownProtocol | Reset stream with error 0x02. Continue accepting streams. | Immediate |
| A stream of the older kind | Protocol byte `0x04`, `0x05` or `0x06` | `0x05` is answered with no channels and no items; `0x04` and `0x06` are refused at the byte. Only that stream ends: the connection goes on (decision 2026-11-10 (older kind), rule 7). | Immediate |
| Stream timeout (10s) | tokio::time::timeout(STREAM_TIMEOUT) at codec layer | Log WARN, skip operation. Retry next cycle. Applies to all stream reads/writes (the streams of entries, peer-sharing). See parameter-rationale.md §6. | 10s |

### 2.3 Resource Errors

| Error | Detection | Recovery | Timeline |
|-------|-----------|----------|----------|
| Disk full | SQLite write fails | Log ERROR. Stop accepting entries. Continue serving those held. Alert operator. | Immediate |
| Memory pressure | System OOM | Process killed. On restart: resume from persistent state (SQLite). Reconnect to peers. | Restart time |
| Too many connections | ConnectionTracker.would_allow() returns false | Reject new inbound. Send CONNECTION_CLOSE with error 0x01. | Immediate |
| Rate limit exceeded | PeerRateLimiter.would_exceed() returns true | Reject request. Send error in protocol response. Count toward ban threshold. | Immediate |
| QUIC stream limit | open_bi blocked (MAX_STREAMS) | Timeout after 10s. Log WARN. Skip peer for this operation. | 10s |

---

## 3. State Transition Side-Effects

### 3.1 Connection Established (any path)

Canonical sequence from connection-lifecycle.md ss1.2:

```
1. Extract peer roles from handshake (is_relay)
2. Add to governor (add_peer)
3. Mark relay role (set_peer_relay if relay)
4. Mark connected (triggers Hot/Warm promotion)
5. Update shared peer list
6. Update hot/warm counters
7. Spawn stream handler
8. Keep-Alive starts (inside stream handler accept loop)
```

### 3.2 Cold -> Warm (governor promotes)

```
1. Governor emits actions.connect with peer's address
2. p2p_loop dials with 10s timeout
3. On success: execute §3.1 canonical sequence
4. On failure: governor.mark_dial_failed (backoff incremented)
```

### 3.3 Warm -> Hot (governor promotes)

```
1. Governor changes peer state to Hot
2. Log INFO "gov: warm -> hot"
```

No stream waits on it. No node pushes, syncs or announces an item of the
older kind (decision 2026-11-10 (older kind), rule 2), and a relay serves
the streams of entries (`0x10` to `0x14`) to a Warm peer as to a Hot one
(network-protocol.md §5.4.2).

**What does NOT happen:** The QUIC connection was already open (established when
entering Warm). No new handshake. No connection cost. This is the key benefit of
the Coutts model -- Warm->Hot is near-instant.

### 3.4 Hot -> Warm (governor demotes)

```
1. Governor changes peer state to Warm
2. handle_peer_streams goes on taking the peer's streams as before: those
   of entries at a relay, Keep-Alive and Peer-Sharing (§3.3)
3. The QUIC connection stays OPEN (keepalive continues)
4. Log INFO "gov: hot -> warm"
```

**What does NOT happen:** Connection is NOT closed. The peer remains a failover
candidate if another Hot peer dies.

### 3.4a Hot -> Warm (dead detection)

If a Hot peer is detected as dead (last_activity > keepalive_timeout):
1. Governor demotes Hot -> Warm (same effects as §3.4)
2. Governor immediately continues to Warm -> Cold (§3.5)
3. Both transitions occur in the same governor tick
4. Log INFO "gov: reaping dead hot peer -> warm -> cold"

### 3.5 Warm -> Cold (dead detection)

```
1. Governor detects: last_activity > keepalive_timeout (90s)
2. Governor changes peer state to Cold
3. Governor emits actions.disconnect
4. p2p_loop calls conn_mgr.disconnect(node_id)
   - Sends CONNECTION_CLOSE to peer
   - Removes from connection map
5. connection_tracker.release(remote_ip)
6. Update shared peer list
7. Update hot/warm counters
8. handle_peer_streams exits (accept_bi returns ConnectionError)
9. Log INFO "gov: warm -> cold (dead)"
```

### 3.5a Warm -> Cold (churn)

Every `churn_interval_secs`, while a peer is cold, the governor closes a
share of its warm peers (`churn_fraction`), as in §3.5 steps 2 to 8, so
that cold peers may take their place.

**A personal node never closes, by churn, its connection to a relay it is
set up with** (decision 2026-10-17 §2). Every peer it dials is a relay the
person chose: churn would only close one and dial it again. Its relays
still move between Hot and Warm (§3.4), on connections that stay open. A
relay and a bootnode churn their warm peers as before.

### 3.6 Any -> Banned

```
1. Governor ban_peer(node_id, reason, tier) called
2. Peer state set to Banned { until, reason, escalation }
3. Connection closed (same as §3.5 steps 4-8)
4. Peer ineligible for connection until ban expires
5. Log WARN "gov: peer banned" with tier and duration
```

---

## 4. Failure Mode Catalog

### 4.1 Network Failures

| Failure | Detection | Impact | Recovery |
|---------|-----------|--------|----------|
| **Single relay death** | Keepalive timeout (90s) | Entries stop flowing through that relay. Other relays continue. | Governor demotes relay to Cold. Personal nodes go on through the other relays they are set up with; they do not discover relays by peer-sharing. Convergence continues via remaining relay mesh. |
| **All relays dead** | All relay hot peers demoted | Nothing flows: devices reach each other only through relays (network-protocol.md §4.9). | Each device keeps what it wrote, and sends it at its first pass once a relay is reached again. |
| **Bootnode unreachable** | Bootstrap timeout (10s per bootnode) | New nodes can't discover peers. Existing nodes unaffected (already have peers). | Fallback peers compiled into binary. DNS SRV provides alternative discovery. Existing peer-sharing continues. |
| **All bootnodes unreachable** | All bootstrap connections fail | New nodes start with 0 peers. | Fallback peers (hardcoded). Manual peer configuration. Existing network continues without new joins. |
| **Network partition (2 groups)** | Keepalive timeout (90s) on cross-partition connections | Each partition operates independently. Entries written in one partition don't reach the other. | After heal: QUIC idle timeout expires (60s), connections are made again, and a device's next pass sends and fetches what was missed. |
| **DNS failure** | DNS SRV resolution fails | No impact if config bootnodes are IP addresses. Impact if bootnodes use hostnames. | Config bootnodes should use IPs for bootstrap. DNS refresh (Phase 2) adds resilience. |
| **Inbound handshake hang (BV-23)** | "incoming received" log with no subsequent "established" log | Select loop blocked. Node stops accepting connections, serving streams, running governor ticks. Total node freeze. | 10s timeout on incoming.await (implemented). Operator pattern: grep for "incoming received" without matching "established". |

### 4.2 Node Failures

| Failure | Detection | Impact | Recovery |
|---------|-----------|--------|----------|
| **Personal node crash** | Peers detect via keepalive (90s) | Its relays hold what it sent. Other nodes unaffected. | On restart: resume from SQLite. Reconnect to its relays, and fetch what it missed at its first pass. |
| **Relay crash** | Connected peers detect (90s). Other relays unaffected. | Entries stop flowing through that relay. | Other relays continue. Governor promotes alternative relays. hot_min_relays ensures personal nodes reconnect to a relay. |
| **Bootnode crash** | Existing connections detect (90s). New nodes can't bootstrap. | No impact on existing topology. New nodes use fallback peers. | Restart bootnode. Or add more bootnodes to DNS SRV. |
| **Disk full on relay** | SQLite INSERT fails | Relay stops storing what it is sent. | Operator expands disk or enables LRU eviction (Phase 2). |
| **Clock skew on node** | Handshake rejection (>300s delta) | Node can't connect to peers with accurate clocks. | Fix NTP. Spec allows 300s tolerance. |

### 4.3 Security Failures

| Failure | Detection | Impact | Recovery |
|---------|-----------|--------|----------|
| **Sybil attack (many fake identities)** | Governor random promotion limits attacker to hot_min Hot slots immediately. min_warm_tenure (300s) gates further promotion. | Attacker can get 2 peers into Hot instantly, more after 5 min. Churn rotates them out hourly. | Increase hot_min. Enable per-IP connection limits. |
| **Eclipse attack (surround a node)** | Random promotion means attacker needs to control ALL warm peers to guarantee Hot selection. min_warm_tenure prevents fast cycling. | Unlikely if honest peers exist in warm set. Churn introduces new peers periodically. | A personal node dials only the relays it is set up with. Monitor hot set composition. |
| **Relay defection (relay drops entries)** | A device's show is answered with what the relay holds (network-protocol.md §4.9.2), and `cordelia devices` says of each relay whether it holds the latest change. | Entries not delivered through that relay. | A device sends what waits to each relay it is set up with, at every pass (network-protocol.md §4.9.6): a person sets up more than one. |
| **Content injection (forged entries)** | An entry's two signatures: its author's, and its channel's key (network-protocol.md §4.9). | A relay stores an entry only if both hold, and a device checks them on what a relay sends it. | Automatic -- verification is per entry. |

---

## 5. Performance Contract

### 5.1 Latency

| Operation | Expected | Bound | Measured |
|-----------|----------|-------|----------|
| Bootstrap (first peer) | 1 QUIC handshake + 1 app handshake | < 2s | ~1s in Docker |
| Peer discovery (via peer-sharing) | 1 request-response cycle | < 5s | ~5s in Docker |

The rows of publish-to-receive and of convergence measured the older kind's
push and sync, and are gone with it (decision 2026-11-10 (older kind), rule
2).

### 5.2 Throughput

| Resource | Personal Node | Relay | Bootnode |
|----------|--------------|-------|----------|
| Connections | hot_max (2) + warm_max (10) = 12 | hot_max (50) + warm_max (100) = 150 | warm_max (500) |
| Memory per peer | ~50KB (QUIC buffers) | ~50KB | ~50KB |
| Total memory | ~600KB peers + ~50MB base | ~7.5MB peers + ~100MB base | ~25MB peers + ~50MB base |

### 5.3 Scaling Invariants

These properties MUST hold at any network size:

1. **Memory per node is O(warm_max), not O(N).** Connection count bounded by governor targets.

The invariants of push, sync, convergence and re-push were of the older
kind, and are gone with it (decision 2026-11-10 (older kind), rule 2).

---

## 6. Observability Contract

### 6.1 What an Operator MUST Be Able to Determine

| Question | How to Answer | Required Data |
|----------|--------------|---------------|
| "Is the relay backbone healthy?" | Check each relay's hot peer count and the channels it holds. Verify relay-to-relay connections exist. | `/api/v1/status` on each relay, governor tick logs |
| "Why did node Y disconnect?" | Grep node Y logs for "connection closed" with reason field. Check governor logs for "reap dead" or "banned". | connection close reason, governor transitions |

The questions that were answered from the older kind's push and sync
telemetry, and from its `listen` route, are gone with it (decision
2026-11-10 (older kind), rule 2).

### 6.2 Tracing an Item

Gone (decision 2026-11-10 (older kind), rule 2): no node publishes or pushes
an item to trace.

### 6.3 Health Dashboard Metrics

The `/api/v1/status` endpoint provides, among the rest that channels-api.md
§3.18 lists:

```json
{
    "peers_hot": 3,
    "peers_warm": 7,
    "uptime_secs": 3600
}
```

It counts no items, pushes or syncs: no node pushes or syncs an item
(decision 2026-11-10 (older kind), rule 2).

**Alert thresholds (operator guidance):**
- `peers_hot == 0`: Node is isolated. Nothing is sent or fetched. CRITICAL.
- `peers_hot > 0 && peers_hot < hot_min`: Node is bootstrapping. May be slow.
- No relay in hot set: Entries won't reach relay backbone. Check relay connectivity.

---

*Spec version: 1.0*
*Created: 2026-03-16*
*Cross-refs: network-protocol.md (what), connection-lifecycle.md (where),
debug-telemetry.md (how to observe), [spec-alignment-audit.md](https://github.com/seed-drill/cordelia-node/blob/c3cc5756/docs/archive/reviews/spec-alignment-audit.md) (gaps)*
