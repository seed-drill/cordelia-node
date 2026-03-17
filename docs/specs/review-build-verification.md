# Build Verification Review -- Phase 1 E2E Testing

> Pass 15 of review-spec methodology. Captures implementation-vs-spec gaps
> discovered during T1-T7 Docker E2E topology testing (2026-03-14).

## Application Record

| Field | Value |
|-------|-------|
| Date | 2026-03-14 |
| Reviewer | Russell Wing + Claude Opus 4.6 |
| Implementation | cordelia-node (Rust), commits dc07b8e..8bf92f7 |
| Tests run | T1 (8/8 PASS), T6 (11/11 PASS), T2 (partial -- relay re-push issue) |
| Tests built | T2-T7 (Docker Compose + assertion scripts) |

---

## Findings

```
ID:         BV-19
Spec:       network-protocol.md §2.3
Expected:   Spec says "QUIC transport with Ed25519 identity-bound TLS" but does
            not specify keepalive or idle timeout parameters.
Actual:     Without keep_alive_interval, QUIC connections silently close after
            quinn's default 30s idle timeout. T6 (Bootnode Loss) failed because
            peer connections died even though peers were alive. No traffic flows
            between push events, so connections appeared idle.
Root cause: Missing detail -- spec should specify transport-level keepalive.
Resolution: Add to §2.3: "The QUIC transport MUST configure keep_alive_interval
            = 15s and max_idle_timeout = 60s. The keep_alive_interval sends QUIC
            PING frames to prevent idle disconnection. These values are independent
            of the application-level Keep-Alive protocol (§4.2)."
Cross-ref:  Fix applied in dc07b8e.
```

```
ID:         BV-20
Spec:       network-protocol.md §10.3, §12.2
Expected:   §10.3 describes bootstrap flow: "connect to each resolved bootnode
            address." No timeout specified per bootnode.
Actual:     If a bootnode is unreachable, the bootstrap hangs for the full QUIC
            max_idle_timeout (60s) per bootnode. With 2 bootnodes, startup can
            stall for 120s. In Docker E2E, this caused test timeouts.
Root cause: Missing detail -- spec should specify per-bootnode connection timeout.
Resolution: Add to §10.3: "Each bootnode connection attempt MUST use a 10-second
            timeout. On timeout, the node SHOULD log a warning and continue to
            the next bootnode. Bootstrap is best-effort: the node proceeds to
            the P2P loop after attempting all bootnodes, even if some failed."
            Add to §12.2 [network]: "bootstrap_timeout_secs = 10 (per bootnode)".
Cross-ref:  Fix applied in 63e4fc5.
```

```
ID:         BV-21
Spec:       data-formats.md §3.1, §3.4; network-protocol.md §8.3
Expected:   §3.4 defines `items.channel_id TEXT NOT NULL REFERENCES
            channels(channel_id)`. §8.3 says relays "store items transparently
            as encrypted blobs." No mention of how the relay satisfies the FK
            constraint when it receives items for channels it has never seen.
Actual:     Relay store-and-forward failed with "FOREIGN KEY constraint failed"
            because the relay had no row in the channels table for the received
            channel_id. Personal nodes create channel rows via the subscribe API,
            but relays never subscribe.
Root cause: Missing detail -- the relay storage path was not traced end-to-end
            across the data-formats and network-protocol specs.
Resolution: Add to data-formats.md §3.1 after the channels table DDL:
            "**Relay auto-creation:** When a relay node receives an Item-Push
            for a channel_id not present in its channels table, it MUST insert
            a minimal row: `INSERT OR IGNORE INTO channels (channel_id,
            channel_type, mode, access, creator_id, created_at, updated_at)
            VALUES (?1, 'named', 'realtime', 'open', X'00', now, now)`.
            This satisfies the FK constraint without requiring subscription."
            Add to network-protocol.md §8.3 (Relay): "Before storing a pushed
            item, the relay MUST ensure a channels row exists for the item's
            channel_id (see data-formats.md §3.1, Relay auto-creation)."
Cross-ref:  Fix applied in 8bf92f7. Related: review-tests T1-04 (relay storage).
```

```
ID:         BV-22
Spec:       network-protocol.md §7.2, §8.3
Expected:   §7.2 describes relay re-push: "The relay stores the item and
            re-pushes to all other connected peers, setting exclude_peer to
            the original sender." No specification of connection manager
            requirements or concurrency model for the push fanout.
Actual:     Relay re-push silently skips some peers. R1 has 3 connections (B1,
            P1, P2). After storing an item from P1, R1 queues a re-push with
            exclude_peer=P1. The push handler iterates connected_peers() and
            spawns tasks. Only B1 receives the push; P2 is silently skipped.
            No error logged. Root cause under investigation -- suspected race
            between accept_incoming adding P2 to the connection manager and
            the push handler iterating the peer list.
Root cause: Ambiguous language -- spec says "all other connected peers" but does
            not define what "connected" means in the context of concurrent
            accept and push operations.
Resolution: Add to §7.2: "The relay MUST push to all peers present in the
            connection manager at the time the push handler executes. If a peer
            is being accepted concurrently, it is acceptable to miss that peer
            on this push cycle; the peer will receive the item via the next
            Item-Sync pull (§4.5). The relay SHOULD log at DEBUG level for
            each peer it pushes to and each peer it skips (with reason)."
            Implementation note: add explicit logging when get_connection()
            returns None for a peer in connected_peers().
Cross-ref:  Open bug. Needs implementation fix before T2 can pass.
```

```
ID:         BV-23
Spec:       topology-e2e.md §2.3; network-protocol.md §2.1
Expected:   §2.3 says "Docker bridge 172.28.0.0/24, static IPs by role."
            §2.1 says all nodes listen on port 9474/UDP.
Actual:     On Docker bridge networks, when node A establishes a QUIC connection
            to node B (both on port 9474/UDP), subsequent QUIC connections from
            node C to node B sometimes time out. The issue is intermittent and
            depends on connection ordering. Using unique ports per container did
            NOT fix the issue. The root cause is under investigation -- suspected
            Docker bridge conntrack or quinn endpoint behaviour.
            Workaround: ensure personal nodes start simultaneously with the
            bootnode (depends_on b1, not depends_on r1), which avoids the
            ordering issue in most cases.
Root cause: Correct omission (Docker-specific) -- spec should document the
            limitation without over-specifying Docker internals.
Resolution: Add to topology-e2e.md §2.3 a new subsection "§2.3.1 Known
            Limitations": "QUIC connection establishment on Docker bridge
            networks is sensitive to connection ordering. When a relay connects
            to a bootnode before personal nodes start, subsequent connections
            from personal nodes to the bootnode may time out. Mitigations:
            (1) Start personal nodes and relays simultaneously (all depend_on
            bootnode, not on each other). (2) Use the 10s bootstrap timeout
            (§10.3) to skip unreachable bootnodes quickly. (3) Rely on
            peer-sharing (§4.3) and Item-Sync pull (§4.5) as fallback
            delivery mechanisms."
Cross-ref:  Partially mitigated by BV-20 (bootstrap timeout).
```

```
ID:         BV-24
Spec:       network-protocol.md §4.5, §6.2
Expected:   Spec says "pull-based anti-entropy" but does not specify peer
            selection strategy for sync requests.
Actual:     Implementation picked peers[0] every time. When peers[0] didn't
            have items for a channel, that channel was never synced. T7 failed:
            P3 synced from P2 (ch-beta only), never reaching P1 (ch-alpha).
Root cause: Missing detail -- spec should specify peer rotation for sync.
Resolution: Add to §4.5: "The node MUST NOT always sync from the same peer.
            The node SHOULD rotate the sync target across connected peers
            using round-robin or randomization."
Cross-ref:  Fix applied in d1ed02b. Diagnosed via debug-telemetry.md logs
            (grep showed "sync response headers=0" repeating for same peer).
```

---

## Summary

| Severity | Count |
|----------|-------|
| HIGH | 4 (BV-19, BV-21, BV-22, BV-24) |
| MEDIUM | 2 (BV-20, BV-23) |
| Total | 6 |

### Status

| ID | Status | Code Fix | Spec Fix |
|----|--------|----------|----------|
| BV-19 | CLOSED | dc07b8e (keepalive) | 1a07d3b (§2.3) |
| BV-20 | CLOSED | 63e4fc5 (bootstrap timeout) | 1a07d3b (§10.3, §12.2) |
| BV-21 | CLOSED | 8bf92f7 (relay FK upsert) | 1a07d3b (data-formats §3.1, network §8.3) |
| BV-22 | CLOSED | e525a0c (telemetry + timeouts) | 2b56c47 (debug-telemetry.md), 0e23d91 (review fixes) |
| BV-23 | CLOSED | 829d9c2 (incoming.await 10s timeout) | d9dec2d (debug-telemetry §1, §5), c6c2764 (network-protocol §2.3). Root cause: `incoming.await` (QUIC handshake) hung indefinitely, blocking the entire select! loop. Diagnosed by adding accept-path telemetry showing "incoming received" with no subsequent "established". Fix: 10s timeout on incoming handshake. |
| BV-24 | CLOSED | d1ed02b (sync peer rotation) | 26fd555 (§4.5) |

```
ID:         BV-25
Spec:       network-protocol.md §4.5, §5 (Peer Governor), §6
Expected:   Spec §1 states "Each node's view is bounded. A node tracks a
            fixed-size peer set regardless of network size. Per-node cost is
            constant." (Coutts/Davies design from Cardano Ouroboros networking.)
            Governor §5 defines Hot/Warm/Cold peer lifecycle with scoring.
            But §4.5 (Item-Sync) does not specify which peers to sync from,
            and the implementation syncs from ALL connected peers.
Actual:     Pull-sync iterates all connected peers (hot + warm + cold) each
            cycle. This is O(N) per cycle where N = total peers, violating
            the bounded-cost principle. At 100+ peers this becomes expensive.
            The governor scoring (§5.4) is not wired to sync target selection.
            T5 convergence depends on brute-force all-peer sync rather than
            governor-managed hot-peer relay chains.
Root cause: Incomplete design -- the spec describes the governor peer lifecycle
            (§5) and the sync protocol (§4.5) independently but does not
            connect them. The Coutts/Davies design requires:
            1. Push to hot peers only (done)
            2. Sync from hot peers only (NOT done)
            3. Governor promotes peers with useful items to hot (NOT done)
            4. Bounded hot set ensures O(1) sync cost (NOT enforced)
Resolution: Update §4.5 to specify: "Pull-sync MUST target hot peers only
            (governor state = Hot). The governor SHOULD score peers by
            item contribution (items received that the node did not already
            have) and promote high-contribution peers to Hot. This ensures
            O(hot_max) sync cost per cycle, independent of total network
            size. Relay chains provide network-wide convergence: each relay
            is hot to several personal nodes, forming a bounded-degree
            overlay mesh."
            Update §5.4 scoring to include item_contribution_score.
            Wire governor to connection manager in implementation.
Cross-ref:  T5 flaky convergence. Coutts/Davies refs in §14.
            Related: BV-23 (Docker bridge), BV-24 (sync peer rotation).
```

### Remaining

- **BV-23** CLOSED: Root cause was `incoming.await` blocking the select! loop indefinitely. Fixed with 10s timeout. Diagnosed via accept-path telemetry (entry log with no exit log = hanging await). Previous mitigations (conntrack flush, depends_on ordering) were workarounds for symptoms, not the cause.
- **BV-25** OPEN: Governor not wired to sync strategy. Sync targets all peers instead of hot-only. Violates bounded-cost principle from Coutts/Davies design. Fix requires: wire governor scoring, restrict sync to hot peers, score by item contribution. T5 convergence fix depends on this.

### Methodology Feedback

These findings surfaced patterns that Pass 8 (Implementability) and Pass 14 (Data Model) should catch proactively. See review-spec skill update for new checklist items added.

---

*Generated: 2026-03-14*
*Spec set: network-protocol.md, data-formats.md, topology-e2e.md*
