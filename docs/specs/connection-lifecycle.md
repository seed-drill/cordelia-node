# Connection Lifecycle Specification

> Defines the exact sequence of operations that MUST execute on every connection
> establishment, state transition, and teardown path. All paths converge to the
> same canonical sequence. No path may skip a step.

**Motivation:** During Phase 1 development, features added to one connection path
(e.g., relay role detection on accept) were missed on other paths (bootstrap,
peer-sharing). The root cause: no single document enumerated all paths and their
required steps. This spec closes that gap.

**Principle:** If a step must happen on connection, it must happen on EVERY
connection path. If you can't point to where in this spec your step is listed,
it's not properly wired.

---

## 1. Connection Establishment

### 1.1 All Paths

There are exactly four ways a connection is established:

| Path | Initiator | Trigger | Code Location |
|------|-----------|---------|---------------|
| **Bootstrap** | This node | Startup, config bootnodes | `main.rs` bootstrap loop |
| **Accept** | Remote peer | Inbound QUIC connection | `p2p_loop` select! `accept_incoming` |
| **Peer-sharing** | This node | Peer-sharing discovery | `p2p_loop` select! `peer_share_interval` |
| **Governor** | This node | Governor `actions.connect` | `p2p_loop` select! `gov_interval` |

### 1.2 Canonical Post-Connection Sequence

After a connection is established (QUIC handshake + app handshake complete),
ALL four paths MUST execute this exact sequence:

```
1. EXTRACT peer roles from handshake result
   roles = peer_conn.handshake.peer_roles

2. ADD to governor
   governor.add_peer(node_id, addrs, channels)

3. MARK relay role (if applicable)
   if roles.contains("relay"):
       governor.set_peer_relay(node_id, true)

4. MARK connected (triggers Hot/Warm promotion)
   governor.mark_connected(node_id)

5. UPDATE shared peer list
   shared_peers.write() = conn_mgr.known_peer_addresses()

6. UPDATE counters
   state.peers_hot = governor.counts().hot
   state.peers_warm = governor.counts().warm

7. SPAWN stream handler
   tokio::spawn(handle_peer_streams(conn, node_id, ...))

8. START Keep-Alive loop (§4.2)
   Ping every 30s on this connection. Runs for lifetime of connection
   (Warm and Hot). Handled inside handle_peer_streams via accept_bi loop.
```

**No step may be skipped.**

### 1.2.1 Promotion Sequence (Warm -> Hot)

When the governor promotes a peer from Warm to Hot (§5.4 step 4):

```
1. UPDATE governor state
   peer.set_state(PeerState::Hot)

2. SEND Channel-Announce (§4.4)
   For each subscribed channel, send ChannelJoined to the peer.
   Must complete within 30s of promotion (§4.4.4).

3. BEGIN data protocols
   The peer is now eligible for Item-Sync and Item-Push.
   handle_peer_streams will accept 0x04-0x07 streams from this peer.
``` If a path omits step 3 (relay marking), relays
won't be in the hot set. If a path omits step 7 (stream handler), the peer's
protocol messages won't be processed.

### 1.3 Pre-Connection Checks

Before attempting connection (paths: peer-sharing, governor):

```
1. CHECK not already connected
   if conn_mgr.is_connected(node_id): skip

2. CHECK not self
   if node_id == our_node_id: skip

3. CHECK governor allows
   if !governor.is_dialable(peer): skip

4. CHECK connection limits (§3)
   if !connection_tracker.would_allow(remote_ip): reject

5. CONNECT with timeout (10s)
   conn_mgr.connect_to(addr) with tokio::time::timeout(10s)

6. On success: execute §1.2 canonical sequence
   On failure: governor.mark_dial_failed(node_id)
```

### 1.4 Inbound Connection Checks

Before accepting inbound connection:

```
1. CHECK connection limits
   if !connection_tracker.would_allow(remote_ip): reject

2. ACCEPT with timeout (10s on QUIC handshake)
   accept_incoming() with internal 10s timeout

3. CHECK not duplicate
   if conn_mgr.is_connected(node_id): close with "duplicate"

4. On success: execute §1.2 canonical sequence
   On failure: log WARN and continue accept loop
```

---

## 2. Protocol Gating

### 2.1 State-Aware Protocol Dispatch

`handle_peer_streams` MUST check the peer's governor state before processing
each protocol stream. The protocol-per-state table (network-protocol.md §5.4.2)
is the authoritative reference:

```
fn handle_peer_streams(conn, peer_id, governor_state_fn, ...):
    loop:
        stream = conn.accept_bi()
        protocol = read_protocol_byte(stream)

        state = governor_state_fn(peer_id)  // query current state

        match (protocol, state):
            // Handshake: reject (already completed during connection setup)
            (Handshake, _) =>
                log WARN "duplicate handshake from {peer_id}"
                stream.reset(APP_ERROR_DUPLICATE_HANDSHAKE)

            // Keep-Alive: allowed on Warm + Hot
            (KeepAlive,    Warm | Hot) => handle_keepalive(stream)

            // Peer-Sharing: Warm (after min_warm_tenure) + Hot
            (PeerSharing,  Hot) => handle_peer_sharing(stream)
            (PeerSharing,  Warm) =>
                if peer.state_tenure() >= min_warm_tenure:
                    handle_peer_sharing(stream)
                else:
                    log DEBUG "peer-sharing rejected: warm tenure not met"
                    stream.reset(APP_ERROR_TENURE_REQUIRED)

            // Data protocols: Hot only
            (ItemPush,        Hot) => handle_push(stream)
            (ItemSync,        Hot) => handle_sync(stream)
            (ChannelAnnounce, Hot) => handle_announce(stream)
            (PskExchange,     Hot) => handle_psk(stream)

            // Pairing: bootnode only (reject on non-bootnodes)
            (Pairing, _) if node_role != "bootnode" =>
                log WARN "pairing rejected: not a bootnode"
                stream.reset(APP_ERROR_WRONG_ROLE)
            (Pairing, _) => handle_pairing(stream)

            // Reject data protocols from Warm peers
            (ItemPush | ItemSync | ChannelAnnounce | PskExchange, Warm) =>
                log WARN "rejected {protocol} from warm peer {peer_id}"
                stream.reset(APP_ERROR_WRONG_STATE)

            // Reject unknown protocols
            (_, _) =>
                log WARN "unknown protocol {protocol} from {peer_id}"
                stream.reset(APP_ERROR_UNKNOWN_PROTOCOL)
```

### 2.2 State Query Mechanism

The governor is owned by the p2p_loop. `handle_peer_streams` runs in a spawned
task and cannot borrow the governor. The state query MUST use one of:

**Option A (recommended):** Shared atomic state per peer.
```rust
// In p2p_loop: update peer state atomics on each governor tick
peer_states: Arc<DashMap<NodeId, PeerState>>
// handle_peer_streams reads from the map
```

**Option B:** Channel-based query.
```rust
// handle_peer_streams sends query, p2p_loop responds
let (tx, rx) = oneshot::channel();
state_query_tx.send((peer_id, tx));
let state = rx.await;
```

**Option C (simplest for Phase 1):** Mark peer state on the connection itself.
```rust
// Store state in PeerConnection, update on governor tick
peer_conn.governor_state: Arc<AtomicU8>  // 0=Cold, 1=Warm, 2=Hot
```

---

## 3. Connection Limits Enforcement

### 3.1 Where Limits Are Checked

| Limit | Where Checked | When |
|-------|--------------|------|
| MAX_INBOUND_CONNECTIONS (200) | `accept_incoming` pre-check | Before QUIC handshake |
| MAX_CONNECTIONS_PER_IP (5) | `accept_incoming` pre-check | Before QUIC handshake |
| MAX_CONNECTIONS_PER_SUBNET (20) | `accept_incoming` pre-check | Before QUIC handshake |
| MAX_MESSAGE_BYTES (1MB) | `read_frame` in codec | On every frame read |
| MAX_ITEM_BYTES (256KB) | Publish API handler | On item creation |
| Rate limits (writes/min) | Protocol handler | On each inbound message |

### 3.2 ConnectionTracker Integration

```
fn accept_incoming_with_limits(conn_mgr, tracker):
    incoming = endpoint.accept()
    remote_ip = incoming.remote_address().ip()

    if !tracker.would_allow(remote_ip):
        log WARN "rejecting connection from {remote_ip}: limit exceeded"
        drop(incoming)  // QUIC handshake never completes
        return Err(LimitExceeded)

    conn = incoming.await  // QUIC handshake with 10s timeout
    tracker.record(remote_ip)
    conn_mgr.accept_connection(conn)
```

### 3.3 Rate Limit Integration

```
fn handle_push(stream, peer_id, rate_limiter):
    if rate_limiter.would_exceed(peer_id, "push"):
        log WARN "rate limit exceeded for {peer_id}"
        send PushAck { stored: 0, policy_rejected: items.len() }
        governor.ban_peer(peer_id, "rate_limit", Transient)
        return

    // Process normally
    ...
```

---

## 4. Connection Teardown

### 4.1 Graceful (Application-Initiated)

| Trigger | Sequence |
|---------|----------|
| Governor demotes Warm->Cold | `conn_mgr.disconnect(node_id)` -> `governor.mark_disconnected(node_id)` -> `connection_tracker.release(remote_ip)` |
| Governor bans peer | Same as above + `governor.ban_peer(node_id, reason, tier)` |
| Node shutdown (SIGTERM) | `conn_mgr.shutdown_and_wait()` -> all connections close -> `endpoint.wait_idle()` |

### 4.2 Ungraceful (Transport-Level)

| Trigger | Detection | Sequence |
|---------|-----------|----------|
| QUIC idle timeout (60s) | `handle_peer_streams` accept_bi returns ConnectionError | `governor.mark_disconnected(node_id)` via gov tick sync |
| Peer crashes (RST) | Same | Same |
| Network partition | Same (after idle timeout) | Same |

### 4.3 Governor Sync on Tick

The governor does NOT receive real-time disconnect notifications (spawned tasks
can't call governor directly). Instead, each governor tick synchronises:

```
// Every 10s:
connected = conn_mgr.connected_peers()
for peer_id in governor.active_peers():
    if peer_id not in connected:
        governor.mark_disconnected(peer_id)
```

This means disconnections are detected within 1 governor tick (10s). The QUIC
idle timeout (60s) plus the governor tick (10s) gives a worst-case detection
time of 70s for a silently-dead peer.

---

## 5. Implementation Checklist

Before a connection-related feature is considered complete, verify:

- [ ] The feature is applied on ALL FOUR connection paths (§1.1)
- [ ] The canonical post-connection sequence (§1.2) is complete on all paths
- [ ] Protocol gating (§2.1) is enforced for the feature's protocol
- [ ] Connection limits (§3.1) are checked before acceptance
- [ ] Rate limits (§3.3) are checked in the protocol handler
- [ ] Teardown (§4) releases resources on all three teardown paths
- [ ] Governor is notified on connect AND disconnect
- [ ] Telemetry logs entry + exit for every await (debug-telemetry.md)

---

*Spec version: 1.0*
*Created: 2026-03-16*
*Motivation: Relay role detection missing from bootstrap path. Features added to one connection path but not others.*
*Cross-refs: network-protocol.md §2, §5, §8; debug-telemetry.md; peer-state-semantics ADR*
