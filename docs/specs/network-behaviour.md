# Network Behaviour Specification

> Defines HOW the Cordelia P2P network behaves in every situation, including
> errors, failures, and edge cases. Complements network-protocol.md (which
> defines WHAT messages are sent) by specifying what the system DOES in response.

**Principle:** For every operation, this spec answers three questions:
1. What happens on success?
2. What happens on failure?
3. What happens on timeout?

If a situation isn't covered here, the implementer should NOT guess -- they
should add the case to this spec and get it reviewed.

---

## 1. End-to-End Item Lifecycle

### 1.1 Publish Flow

A personal node's user calls `POST /api/v1/channels/publish`. Trace the item
through every component until it arrives on a remote subscriber.

```
Publisher (P1)                    Relay (R1)                    Subscriber (P2)
─────────────                    ──────────                    ──────────────
1. API receives publish
   - Validate auth (node-token)
   - Validate channel exists
   - Validate item size <= 256KB

2. Encrypt content
   - Load PSK for channel
   - AES-256-GCM encrypt
   - channel_id as AAD
   - Random 12-byte IV

3. Sign metadata envelope
   - Build CBOR envelope:
     item_id, channel_id,
     content_hash (SHA-256),
     author_id, published_at
   - Ed25519 sign envelope

4. Store locally
   - INSERT into items table
   - Index in FTS5

5. Queue for push
   - Send to push_tx channel
   - Include exclude_peer=None

6. P2P loop picks up item
   - Query governor.hot_peers()
   - For each hot peer:
     a. Skip if bootnode
     b. Open stream (10s timeout)
     c. Write protocol byte 0x06  ──────────>  7. R1 receives Item-Push
     d. Write PushPayload (CBOR)                   - Read protocol byte
     e. Read PushAck                                - Read PushPayload
     f. Log "push delivered"                        - Verify content_hash
        stored=N                                    - Auto-create channel row
                                                    - INSERT into items table
                                                    - Send PushAck(stored=1)

                                                8. R1 relay re-push
                                                   - stored > 0, so re-push
                                                   - exclude_peer = P1
                                                   - For each hot peer:
                                                     Skip P1, skip bootnodes
                                                     Open stream (10s)  ──────>  9. P2 receives Item-Push
                                                     Write PushPayload              - Read PushPayload
                                                     Read PushAck                   - Verify content_hash
                                                     Log "push delivered"           - Check subscription
                                                                                    - INSERT into items table
                                                                                    - Send PushAck(stored=1)

                                                                                 10. P2 API serves item
                                                                                     - GET /listen returns item
                                                                                     - Decrypt with PSK
                                                                                     - Return to caller
```

**Latency budget (typical):**
- Steps 1-5: <10ms (local)
- Step 6 (push to relay): 1 RTT (~1-50ms LAN, ~100-300ms WAN)
- Step 8 (relay re-push): 1 RTT
- Total publish-to-receive: ~2-4 RTT = **2-600ms** depending on network

**Latency budget (pull-sync fallback):**
If push fails, items arrive via pull-sync:
- sync_interval_realtime_secs (default: 10s, production recommendation: 60s)
- Total: up to sync_interval (default 10s) + 1 RTT

### 1.2 What Can Go Wrong

| Step | Failure | Behaviour | Recovery |
|------|---------|-----------|----------|
| 1 | Invalid auth | 401 Unauthorized | Caller retries with correct token |
| 1 | Channel not subscribed | 404 Not Found | Caller subscribes first |
| 2 | PSK not available | 500 Internal Error | Node needs PSK via PSK-Exchange |
| 5 | push_tx channel full | Backpressure (bounded channel) | Item stored locally, delivered via sync |
| 6 | No hot peers | Push skipped (0 peers) | Items delivered via pull-sync when peers connect |
| 6b | open_bi timeout (10s) | Log WARN, skip peer | Other peers receive. Sync catches up. |
| 6e | PushAck timeout (10s) | Log WARN, skip peer | Same as above |
| 7 | Content hash mismatch | Reject item, log WARN | Publisher has a bug. Item not stored. |
| 7 | FK constraint (no channel row) | Relay auto-creates channel | Transparent to publisher |
| 8 | Re-push open_bi timeout | Log WARN, skip peer | Sync catches up |
| 9 | Duplicate item | PushAck(stored=0, dedup=1) | Normal (multiple paths deliver same item) |

---

## 2. Error Recovery

### 2.1 Connection Errors

| Error | Detection | Recovery | Timeline |
|-------|-----------|----------|----------|
| Peer unreachable | open_bi timeout (10s) | Skip peer for this operation. Governor detects via keepalive timeout (90s). Mark disconnected. Peer enters Cold. Backoff before retry. | 10s (immediate skip) + 90s (governor detection) |
| Peer crashes (RST) | accept_bi returns ConnectionError | handle_peer_streams exits loop. Governor detects on next tick. Mark disconnected. | Immediate exit + 10s tick |
| Network partition | Keepalive stops. QUIC idle timeout (60s) fires. | Connection closes. Governor marks disconnected. Peer-sharing discovers new paths after heal. | 60s (idle timeout) + 10s (tick) + 5s (peer-sharing) |
| Bootnode unreachable | Bootstrap connect timeout (10s) | Skip, try next bootnode. Node starts with 0 peers if all fail. Peer-sharing retries via fallback peers. | 10s per bootnode |
| All peers lost | Governor hot set empty. | No push delivery. Node waits for inbound connections or bootnode reconnection. Exponential backoff (base 30s, cap 900s). After 5 consecutive failures per peer, stop retrying until backoff expires. Clear failure count after 120s of stable Hot connection. | Variable (30s-900s backoff) |

### 2.2 Protocol Errors

| Error | Detection | Recovery | Timeline |
|-------|-----------|----------|----------|
| Handshake rejected (clock skew) | HandshakeError::ClockSkew | Log WARN, don't connect. Don't ban (could be our clock). | Immediate |
| Handshake rejected (identity mismatch) | HandshakeError::IdentityMismatch | Log WARN, ban peer (Moderate tier). | Immediate |
| Malformed CBOR | CodecError::Decode | Log WARN, skip frame, continue. Transient ban (1 hour, escalating per repeat). See network-protocol.md §5.6. | Immediate |
| Wrong protocol byte | CodecError::UnknownProtocol | Reset stream with error 0x02. Continue accepting streams. | Immediate |
| Item signature invalid | verify_content_hash returns false | Reject item. Log WARN. Count as violation toward ban. | Immediate |
| Sync response empty | SyncResponse.items = [] | Normal (peer has nothing new). Try next peer on next cycle. | Immediate |
| Stream timeout (10s) | tokio::time::timeout(STREAM_TIMEOUT) at codec layer | Log WARN, skip operation. Retry next cycle. Applies to all stream reads/writes (push, sync, fetch, peer-sharing). See parameter-rationale.md §6. | 10s |

### 2.3 Resource Errors

| Error | Detection | Recovery | Timeline |
|-------|-----------|----------|----------|
| Disk full | SQLite write fails | Log ERROR. Stop accepting items. Continue serving existing items. Alert operator. | Immediate |
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
2. Peer becomes eligible for:
   - Outbound Item-Push (included in push target set)
   - Outbound Item-Sync (included in sync target set)
   - Outbound Channel-Announce (send ChannelJoined for all subscribed channels)
3. handle_peer_streams accepts data protocol streams (0x04-0x07)
   from this peer (protocol gating allows)
4. Log INFO "gov: warm -> hot"
```

**What does NOT happen:** The QUIC connection was already open (established when
entering Warm). No new handshake. No connection cost. This is the key benefit of
the Coutts model -- Warm->Hot is near-instant.

### 3.4 Hot -> Warm (governor demotes)

```
1. Governor changes peer state to Warm
2. Peer is REMOVED from:
   - Push target set (governor.hot_peers() no longer includes it)
   - Sync target set (same)
3. handle_peer_streams continues accepting Keep-Alive and Peer-Sharing
   streams from this peer, but REJECTS data protocol streams (0x04-0x07)
4. The QUIC connection stays OPEN (keepalive continues)
5. Log INFO "gov: hot -> warm"
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
| **Single relay death** | Keepalive timeout (90s) | Items stop flowing through that relay. Other relays continue. | Governor demotes relay to Cold. Personal nodes discover alternative relays via peer-sharing. Convergence continues via remaining relay mesh. |
| **All relays dead** | All relay hot peers demoted | Items flow peer-to-peer only (direct push between personal nodes that share channels). No relay fan-out. | Network operates in degraded mode. Items still reach directly-connected subscribers. Pull-sync provides eventual consistency. |
| **Bootnode unreachable** | Bootstrap timeout (10s per bootnode) | New nodes can't discover peers. Existing nodes unaffected (already have peers). | Fallback peers compiled into binary. DNS SRV provides alternative discovery. Existing peer-sharing continues. |
| **All bootnodes unreachable** | All bootstrap connections fail | New nodes start with 0 peers. | Fallback peers (hardcoded). Manual peer configuration. Existing network continues without new joins. |
| **Network partition (2 groups)** | Keepalive timeout (90s) on cross-partition connections | Each partition operates independently. Items published in one partition don't reach the other. | After heal: QUIC idle timeout expires (60s), connections re-established via peer-sharing, pull-sync transfers missing items. Convergence: ~85s (bootstrap) or ~390s (steady state with tenure guard). |
| **DNS failure** | DNS SRV resolution fails | No impact if config bootnodes are IP addresses. Impact if bootnodes use hostnames. | Config bootnodes should use IPs for bootstrap. DNS refresh (Phase 2) adds resilience. |
| **Inbound handshake hang (BV-23)** | "incoming received" log with no subsequent "established" log | Select loop blocked. Node stops accepting connections, processing push/sync, running governor ticks. Total node freeze. | 10s timeout on incoming.await (implemented). Operator pattern: grep for "incoming received" without matching "established". |

### 4.2 Node Failures

| Failure | Detection | Impact | Recovery |
|---------|-----------|--------|----------|
| **Personal node crash** | Peers detect via keepalive (90s) | Node's items stop being served. Other nodes unaffected. | On restart: resume from SQLite. Reconnect to peers. Pull-sync fetches missed items. |
| **Relay crash** | Connected peers detect (90s). Other relays unaffected. | Items stop flowing through that relay. | Other relays continue. Governor promotes alternative relays. hot_min_relays ensures personal nodes reconnect to a relay. |
| **Bootnode crash** | Existing connections detect (90s). New nodes can't bootstrap. | No impact on existing topology. New nodes use fallback peers. | Restart bootnode. Or add more bootnodes to DNS SRV. |
| **Disk full on relay** | SQLite INSERT fails | Relay stops storing items. Re-push continues (items forwarded to other relays). | Operator expands disk or enables LRU eviction (Phase 2). |
| **Clock skew on node** | Handshake rejection (>300s delta) | Node can't connect to peers with accurate clocks. | Fix NTP. Spec allows 300s tolerance. |
| **Sync targets unbounded (BV-25)** | Sync telemetry shows requests to warm/cold peers | O(N) per-cycle cost instead of O(hot_max). Bandwidth waste at scale. | Wire governor state to sync peer selection. Restrict sync to Hot peers only. |

### 4.3 Security Failures

| Failure | Detection | Impact | Recovery |
|---------|-----------|--------|----------|
| **Sybil attack (many fake identities)** | Governor random promotion limits attacker to hot_min Hot slots immediately. min_warm_tenure (300s) gates further promotion. | Attacker can get 2 peers into Hot instantly, more after 5 min. Churn rotates them out hourly. | Increase hot_min. Add trusted_peers for known-good relays. Enable per-IP connection limits. |
| **Eclipse attack (surround a node)** | Random promotion means attacker needs to control ALL warm peers to guarantee Hot selection. min_warm_tenure prevents fast cycling. | Unlikely if honest peers exist in warm set. Churn introduces new peers periodically. | trusted_peers config. Monitor hot set composition. |
| **Relay defection (relay drops items)** | contribution_ratio < 1.0 over time. Probe items detect selective dropping. | Items not delivered to nodes served by that relay. | Governor demotes low-scoring relays. Personal nodes connect to alternative relays via hot_min_relays. |
| **Content injection (forged items)** | Content hash mismatch. Ed25519 signature verification failure. | Forged items rejected at receive time. | Automatic -- verification is per-item. Ban peer that sends forged items. |

---

## 5. Performance Contract

### 5.1 Latency

| Operation | Expected | Bound | Measured |
|-----------|----------|-------|----------|
| Publish-to-receive (push path) | 2-4 RTT | < 1s LAN, < 2s WAN | ~0s at 20 nodes (E2E T1) |
| Publish-to-receive (sync fallback) | 1 sync cycle | <= sync_interval_realtime_secs (default: 10s, production recommendation: 60s) | ~10-20s at 100 nodes |
| Bootstrap (first peer) | 1 QUIC handshake + 1 app handshake | < 2s | ~1s in Docker |
| Peer discovery (via peer-sharing) | 1 request-response cycle | < 5s | ~5s in Docker |
| Convergence after partition | idle_timeout + reconnect + sync | ~85s (bootstrap), ~390s (steady) | 84s at 5 nodes (T5) |
| Convergence at scale (100 nodes) | Same as 10 nodes | < 120s | 80/90 in ~60s, 89/90 in ~3 min |

Convergence numbers use default sync_interval_realtime_secs=10. Production deployments with sync_interval=60s will see proportionally longer convergence times.

### 5.2 Throughput

| Resource | Personal Node | Relay | Bootnode |
|----------|--------------|-------|----------|
| Items/second ingest | ~100 (API-limited) | ~1000 (relay re-push) | 0 (no items) |
| Connections | hot_max (2) + warm_max (10) = 12 | hot_max (50) + warm_max (100) = 150 | warm_max (500) |
| Memory per peer | ~50KB (QUIC buffers) | ~50KB | ~50KB |
| Total memory | ~600KB peers + ~50MB base | ~7.5MB peers + ~100MB base | ~25MB peers + ~50MB base |
| Bandwidth (push) | items × hot_max × item_size | items × hot_max × item_size | 0 |
| Bandwidth (sync) | hot_max × channels × headers | hot_max × channels × headers | 0 |

### 5.3 Scaling Invariants

These properties MUST hold at any network size:

1. **Per-node push cost is O(hot_max), not O(N).** A personal node pushes to at most hot_max peers regardless of network size.
2. **Per-node sync cost is O(hot_max × channels), not O(N × channels).** Sync from hot peers only.
3. **Convergence time is O(D), not O(N).** D = relay mesh depth (typically 2-3). Adding nodes doesn't increase convergence time (assumes relay backbone is connected).
4. **Memory per node is O(warm_max), not O(N).** Connection count bounded by governor targets.
5. **Relay bandwidth per item is O(hot_max), not O(N).** Re-push to hot peers only. Channel-aware routing (Phase 2) further reduces to O(interested_peers).

---

## 6. Observability Contract

### 6.1 What an Operator MUST Be Able to Determine

| Question | How to Answer | Required Data |
|----------|--------------|---------------|
| "Why isn't node X receiving items?" | Grep node X logs for "push delivered" and "sync response". Check hot_peers count. Check if any relay is hot. | push/sync telemetry, governor state |
| "Is the relay backbone healthy?" | Check each relay's hot peer count and items stored. Verify relay-to-relay connections exist. | `/api/v1/status` on each relay, governor tick logs |
| "Why did node Y disconnect?" | Grep node Y logs for "connection closed" with reason field. Check governor logs for "reap dead" or "banned". | connection close reason, governor transitions |
| "Is the network converged?" | Publish an item, check `/api/v1/channels/listen` on N sample nodes. All should return the item within convergence_time. | API queries on sample nodes |
| "Why is convergence slow?" | Check governor hot set composition. Are relays in hot set? Check push timeout count. Check sync response header counts. | governor state, push/sync telemetry |
| "Is a relay defecting (dropping items)?" | Compare relay's items_stored vs items_pushed (re-push count should equal stored × (hot_peers - 1)). | relay push/store telemetry |

### 6.2 Tracing an Item

An operator MUST be able to trace a single item across the network using:

```bash
grep "ci_01EXAMPLE" logs/p1.log logs/r1.log logs/p2.log
```

The output MUST show the complete lifecycle from publish to receive, with
every intermediate step logged (see debug-telemetry.md ss4 for the expected
trace format).

If any step is missing from the trace, the operator knows exactly where the
item was lost.

### 6.3 Health Dashboard Metrics

The `/api/v1/status` endpoint provides:

```json
{
    "peers_hot": 3,
    "peers_warm": 7,
    "items_stored": 42,
    "items_pushed": 15,
    "items_received": 27,
    "push_timeouts": 0,
    "sync_timeouts": 0,
    "uptime_secs": 3600
}
```

**Alert thresholds (operator guidance):**
- `peers_hot == 0`: Node is isolated. No push delivery. CRITICAL.
- `peers_hot > 0 && peers_hot < hot_min`: Node is bootstrapping. May be slow.
- No relay in hot set: Items won't reach relay backbone. Check relay connectivity.

---

*Spec version: 1.0*
*Created: 2026-03-16*
*Cross-refs: network-protocol.md (what), connection-lifecycle.md (where),
debug-telemetry.md (how to observe), spec-alignment-audit.md (gaps)*
