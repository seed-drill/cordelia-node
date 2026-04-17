# Review: connection-lifecycle.md

> Fresh review pass (first) applying review-spec methodology to
> `connection-lifecycle.md` v1.0 (created 2026-03-16, 323 lines).

## Application Record

| Field | Value |
|-------|-------|
| Date | 2026-04-17 |
| Reviewer | Russell Wing + Claude Opus 4.7 |
| Spec | connection-lifecycle.md v1.0 |
| Passes applied | 1 (Gaps), 2 (Consistency), 3 (Clarity), 4 (Implementability), 5 (Coverage), 6 (Cross-reference integrity) |

---

## Summary

13 findings: 2 CRITICAL, 4 HIGH, 5 MEDIUM, 2 LOW. Overall the spec
accomplishes its stated purpose (enumerate connection paths + canonical
sequence) and has already prevented several integration bugs. However
it has **drifted from network-protocol.md §5.4.2** on the most
important topic it addresses -- protocol-per-state gating -- and it
introduces named application-error constants that are not defined
anywhere else in the spec set. Both drift bugs are likely to be
faithfully re-introduced into code if an engineer uses this spec as
the source of truth.

Top-line fix before Phase 1 close: reconcile §2.1 (Protocol Gating
pseudocode) with network-protocol.md §5.4.2 role-aware inbound table
and §7.2 relay asymmetry rule. Second: define the `APP_ERROR_*`
enumeration (either here or in network-protocol.md §3.3) so the
pseudocode compiles.

---

## CRITICAL

### CL-01: §2.1 protocol gating contradicts network-protocol.md §5.4.2 (role-aware)

**Spec**: §2.1 lines 164-179, cf. network-protocol.md §5.4.2 + §7.2 + §5.4.2 note line 971.

**Issue**: The pseudocode in §2.1 treats "data protocols require Hot"
as a universal rule:

```
(ItemPush,        Hot) => handle_push(stream)
(ItemSync,        Hot) => handle_sync(stream)
(ChannelAnnounce, Hot) => handle_announce(stream)
...
(ItemPush | ItemSync | ChannelAnnounce | PskExchange, Warm) =>
    log WARN "rejected {protocol} from warm peer {peer_id}"
    stream.reset(APP_ERROR_WRONG_STATE)
```

network-protocol.md §5.4.2 defines role-aware inbound gating:

| Protocol | Warm (personal) | Warm (relay) | Hot |
|----------|-----------------|--------------|-----|
| Channel-Announce | -- | YES | YES |
| Item-Sync | -- | YES | YES |
| Item-Push | -- | YES | YES |
| PSK-Exchange | -- | -- | YES |

And §5.4.2 line 971 + §7.2 line 1231 are explicit: "Relays MUST accept
all data protocols (Item-Push, Item-Sync, Channel-Announce) from Warm
peers. Without this, B rejects A's forwarded items... partitioning the
network." This is also memorialised in MEMORY.md ("Role-aware protocol
gating: Relays accept ItemPush/ItemSync/ChannelAnnounce from Warm
peers (§5.4.2). Fixes asymmetric hot sets in sparse meshes.").

The connection-lifecycle spec, as written, directs an implementor to
re-introduce exactly the partitioning bug that role-aware gating was
added to fix. The "Implementation note (session 92)" at line 187-191
even claims "ChannelAnnounce are allowed on all active states" -- but
the preceding match arms do not allow it on Warm for any role. The
spec is self-contradictory in addition to being inconsistent with
network-protocol.md.

**Resolution**: Rewrite §2.1 to be role-aware. Concrete pseudocode:

```
match (protocol, state, node_role):
    // ...handshake, keepalive, peer-sharing, pairing as before...

    // Data protocols: always Hot; on Warm, relay-only.
    (ItemPush,        Hot, _)       => handle_push(stream)
    (ItemPush,        Warm, "relay") => handle_push(stream)
    (ItemSync,        Hot, _)       => handle_sync(stream)
    (ItemSync,        Warm, "relay") => handle_sync(stream)
    (ChannelAnnounce, Hot, _)       => handle_announce(stream)
    (ChannelAnnounce, Warm, "relay") => handle_announce(stream)

    // PSK-Exchange: Hot only for all roles (security boundary).
    (PskExchange, Hot, _) => handle_psk(stream)

    // Reject data protocols otherwise.
    (ItemPush | ItemSync | ChannelAnnounce | PskExchange, Warm, _) =>
        log WARN "rejected {protocol} from warm {node_role} peer {peer_id}"
        stream.reset(APP_ERROR_WRONG_STATE)
```

Update the "Implementation note" block to reflect role-aware gating and
cite network-protocol.md §5.4.2 + §7.2. Remove the claim that
"ChannelAnnounce are allowed on all active states" -- that is only true
on relays, not personal nodes.

---

### CL-02: APP_ERROR_* constants referenced but never defined

**Spec**: §2.1 lines 150, 162, 173, 179, 184. network-protocol.md §3.3
lines 205, 1579, 1946, 2071 (definition scope).

**Issue**: The pseudocode emits five application error codes:

- `APP_ERROR_DUPLICATE_HANDSHAKE`
- `APP_ERROR_TENURE_REQUIRED`
- `APP_ERROR_WRONG_ROLE`
- `APP_ERROR_WRONG_STATE`
- `APP_ERROR_UNKNOWN_PROTOCOL`

network-protocol.md defines only:

- `0x01` = capacity (§9.1)
- `0x02` = unknown protocol (§3.3, §13.3)
- `0x03` = rate limited (§16.2.1)

None of the symbolic names above has a byte value, and only
"unknown protocol" has a matching concept (0x02). Two implementations
will assign different integers, breaking interop. This is also a
regression risk for the existing `APP_ERROR_DUPLICATE_HANDSHAKE` --
if someone picks 0x01, they collide with "capacity", and clients will
back off exponentially against a peer that is merely refusing a
double-handshake attempt.

**Resolution**: Add an application error code table to
network-protocol.md §3.3 (canonical location, cross-referenced by
connection-lifecycle §2.1). Suggested values, extending the current
set:

| Code | Name | Meaning | Backoff |
|------|------|---------|---------|
| 0x01 | CAPACITY | Inbound connection limit exceeded | Exponential |
| 0x02 | UNKNOWN_PROTOCOL | Unknown protocol byte or variant | None (protocol bug) |
| 0x03 | RATE_LIMITED | Bootnode / peer rate limit | Exponential 30s-600s |
| 0x04 | DUPLICATE_HANDSHAKE | Second Handshake on existing connection | None (client bug) |
| 0x05 | WRONG_ROLE | Protocol only valid for specific role (e.g. Pairing on non-bootnode) | None (configuration) |
| 0x06 | WRONG_STATE | Protocol not allowed in peer's current governor state | Retry after promotion |
| 0x07 | TENURE_REQUIRED | Warm peer has not yet met `min_warm_tenure` | Retry after tenure |

Then update connection-lifecycle §2.1 to reference the numeric codes
(or keep the symbolic names but add a "defined in network-protocol.md
§3.3" footnote).

---

## HIGH

### CL-03: §1.2 canonical sequence is silent on state map / telemetry wiring

**Spec**: §1.2 steps 1-8.

**Issue**: The canonical post-connection sequence enumerates 8 steps
but omits two items that §2 and §4 depend on:

1. **Populate `peer_states` map.** §2.2 describes the state-query
   mechanism (Option A implemented: `Arc<RwLock<HashMap<NodeId, u8>>>`)
   and the code in `p2p.rs:166` seeds this map at connect time before
   the first governor tick. Without this seeding step in §1.2, an
   implementor following §1.2 verbatim will have `handle_peer_streams`
   default to `Warm` (fallback `.unwrap_or(1)`) for the first 10
   seconds until the governor tick runs -- which is exactly when
   inbound protocols fire. For relays this may work (Warm allows data
   protocols for relays per CL-01 resolution) but for personal nodes
   it will reject legitimate first-touch data protocols.

2. **Telemetry hook.** §5 implementation checklist says "Telemetry
   logs entry + exit for every await (debug-telemetry.md)" but the
   canonical sequence does not tell the implementor where to log
   connection established. This is the exact class of gap the spec
   exists to prevent (feature applied to one path, missed on others).

**Resolution**: Add two steps to §1.2:

```
2a. SEED peer_states map (before first governor tick)
    peer_states.write().insert(node_id, PeerState::Warm)
    (overwritten to Hot at step 4 if governor promotes immediately)

6a. TELEMETRY: log connect-established with node_id, remote_addr,
    path (bootstrap | accept | peer-sharing | governor), peer_roles.
    Required for BV-22/BV-23-class debugging.
```

### CL-04: §1.2.1 promotion sequence timer / re-announce on Warm->Hot unspecified

**Spec**: §1.2.1 step 2, cf. network-protocol.md §4.4.4 line 428.

**Issue**: §1.2.1 says "For each subscribed channel, send ChannelJoined
to the peer. Must complete within 30s of promotion (§4.4.4)." But
§4.4.4 line 428 specifies 30s for **node restart re-announce**, not
for Warm->Hot promotion. The 30s value may be a correct borrowing but
there is no rationale; an implementor cannot tell whether this
constraint is an invariant or a heuristic.

Also missing: what happens if Channel-Announce fails to complete on
promotion (stream open_bi timeout, peer disconnects mid-announce)?
Does the peer get demoted back to Warm? Is the sequence retried at the
next governor tick?

**Resolution**: Clarify in §1.2.1:

- State explicitly whether the 30s is inherited from §4.4.4 (restart
  re-announce) or is a separate constraint derived from governor tick
  period. Recommend: reference `tick_interval_secs` (10s) × 3 = 30s as
  the derivation.
- Add failure handling: "If Channel-Announce fails to complete on
  promotion, log WARN, leave peer in Hot (the 5-minute reconciliation
  interval in §4.4.2 will catch the missing announcements). Do NOT
  demote -- transient stream failures are not a governor-worthy
  event." If that is wrong, state the correct behaviour.

### CL-05: §1.2 header comment block corrupted / references §7.2 incorrectly

**Spec**: §1.2.1 step 3 / §1.2 closing comment lines 81-84.

**Issue**: The prose after the §1.2.1 code block reads:

> ``` If a path omits step 3 (relay marking), relays
> won't be in the hot set. If a path omits step 7 (stream handler),
> the peer's protocol messages won't be processed.

This is clearly a broken paragraph: the leading ` ``` ` tail is left
over from the fence, "step 3 (relay marking)" refers back to §1.2
step 3 (not §1.2.1 step 3, which is "BEGIN data protocols"), and the
commentary belongs under §1.2 not §1.2.1. As rendered it looks like it
documents the promotion sequence.

**Resolution**: Delete the stray ` ``` ` and move the paragraph under
§1.2 before §1.2.1. Clarify the step references:

```
**No step may be skipped.** If a path omits step 3 (relay marking),
relays won't be in the governor's relay set and the `hot_min_relays`
target will never be met. If a path omits step 7 (stream handler
spawn), the peer's inbound protocol messages will never be processed.
```

### CL-06: §4.2 ungraceful teardown detection path is hand-wavy

**Spec**: §4.2 "Governor tick sync" + §4.3.

**Issue**: §4.2 says detection happens via "gov tick sync" and §4.3
specifies a 10s governor tick. But the actual mechanism -- how the
connection manager observes that a QUIC connection has closed -- is
not specified. Quinn's `Connection` has two relevant futures
(`closed()` and the error returned from `accept_bi()`) and the spec
must pick one. §4.2 says "`handle_peer_streams` accept_bi returns
ConnectionError" triggers `governor.mark_disconnected` "via gov tick
sync". This is circular: if the gov tick is what calls
`mark_disconnected`, then accept_bi's error is not the trigger, and
the statement "accept_bi returns ConnectionError" is misleading.

Also missing: what does `handle_peer_streams` DO when accept_bi
returns an error? Does the task exit silently? Is there a
`conn_mgr.mark_closed(node_id)` call? Without this, the
`connected_peers()` list in §4.3 may contain stale entries.

**Resolution**: Specify the exact mechanism:

```
When accept_bi returns a ConnectionError (QUIC idle timeout, RST, or
peer close):
  1. `handle_peer_streams` task logs DEBUG "peer {node_id} connection
     closed: {reason}" and returns (task exits).
  2. conn_mgr.on_connection_closed(node_id) removes the Connection
     handle from its active map. This happens synchronously in the
     task before exit.
  3. The next governor tick observes `peer_id not in connected_peers()`
     and calls governor.mark_disconnected(peer_id). Worst-case
     detection time: 10s (one governor tick).
```

Revise §4.2 table to show detection is in `handle_peer_streams`,
reconciliation is in the governor tick.

---

## MEDIUM

### CL-07: §1.2 step 5 pseudocode is syntactically wrong

**Spec**: §1.2 step 5.

**Issue**: `shared_peers.write() = conn_mgr.known_peer_addresses()`
is not valid Rust (an `RwLockWriteGuard` is not assignable). The
intent is `*shared_peers.write() = conn_mgr.known_peer_addresses()` or
`shared_peers.write().clear(); shared_peers.write().extend(...)`.
Minor but the spec is prescriptive pseudocode an implementor will copy.

**Resolution**: Change to:

```
5. UPDATE shared peer list
   *shared_peers.write() = conn_mgr.known_peer_addresses()
```

### CL-08: §1.4 "close with 'duplicate'" underspecified

**Spec**: §1.4 step 3.

**Issue**: "close with 'duplicate'" is ambiguous. QUIC supports
application `CONNECTION_CLOSE` with a code + reason string, but the
spec does not say which code is used. Per CL-02's proposed error
table, this should be a distinct code (e.g. 0x08 DUPLICATE_CONNECTION)
or it could reuse 0x04 DUPLICATE_HANDSHAKE. Without specification, two
implementations will pick different codes and produce different logs
in shared test environments.

**Resolution**: Specify: "close with `CONNECTION_CLOSE` application
code 0x04 DUPLICATE_HANDSHAKE, reason string 'duplicate connection
from {node_id}'." (or new 0x08 if preferred). Cross-reference §3.3
error table.

### CL-09: §3.1 ConnectionTracker release point unspecified

**Spec**: §3.1 + §4.1.

**Issue**: §4.1 says graceful teardown does
`connection_tracker.release(remote_ip)` but §3.1's table entry for
MAX_CONNECTIONS_PER_IP says "checked in accept_incoming pre-check".
It's implicit that `release` decrements the same counter, but the
spec does not state:

- Is the tracker indexed by `(remote_ip, node_id)` or just `remote_ip`?
  (multiple connections from same IP under different node_ids exist
  per §9.1's `max_connections_per_ip = 5`.)
- What happens on ungraceful teardown (§4.2)? Is `release` called
  there too? If not, crashed peers will gradually exhaust the per-IP
  quota without recovery.

**Resolution**: Add to §4.2: "Ungraceful detection triggers
`connection_tracker.release(remote_ip)` in the same task that exits
on accept_bi error (see CL-06 resolution)." Add to §3.2: "Tracker is
keyed by `remote_ip` only (not node_id). Multi-identity peers share
the per-IP quota."

### CL-10: §2.2 Option A/B/C decision left open; spec is not a single source of truth

**Spec**: §2.2.

**Issue**: The spec lists three options for the state-query mechanism
("Option A (implemented)", "Option B", "Option C") without declaring
which is normative. Code is already shipped with Option A (see
`p2p.rs:102`). Leaving the spec in an "options" state means a future
contributor could legitimately implement Option C and be "conformant".

**Resolution**: Remove Options B and C (or move them to an appendix
labelled "rejected alternatives with rationale"). State: "Option A is
the normative mechanism. The peer_states map is seeded in §1.2 step
2a (see CL-03) and updated on each governor tick."

### CL-11: §1.3 step 5 connect timeout cites 10s without reference to STREAM_TIMEOUT or incoming_handshake_timeout

**Spec**: §1.3 step 5.

**Issue**: `tokio::time::timeout(10s)` on outbound `conn_mgr.connect_to`
uses the same 10s value as `STREAM_TIMEOUT` (parameter-rationale.md §6)
and `incoming_handshake_timeout` (parameter-rationale.md §1.3). The
spec does not link these together, so if one value changes the others
will silently drift.

**Resolution**: Cite parameter-rationale.md: "`CONNECT_TIMEOUT` (10s)
is defined alongside `incoming_handshake_timeout` in
parameter-rationale.md §1.3. Both outbound and inbound QUIC handshakes
share the same bound; changing one requires changing the other."

---

## LOW

### CL-12: Terminology drift: "hot_max = 2 (personal)" not referenced in this spec

**Spec**: Entire doc.

**Issue**: connection-lifecycle.md uses "Warm -> Hot", "hot set",
"hot_min", but never states the numeric hot_max values. An implementor
reading this spec in isolation cannot tell whether "promotion to Hot"
is a frequent event (personal hot_max=2) or a rare one (relay
hot_max=50). This matters for §1.2.1 because the Warm->Hot promotion
sequence fires proportionally often.

**Resolution**: Add one sentence near §1.2.1: "Hot-set size is
role-dependent: personal nodes have hot_max=2, relays hot_max=50
(parameter-rationale.md §3). The promotion sequence below runs at that
cadence."

### CL-13: §5 checklist uses "all three teardown paths" but §4 lists only two categories

**Spec**: §5 bullet 6, cf. §4.1 + §4.2.

**Issue**: Checklist says "Teardown (§4) releases resources on all
three teardown paths" but §4 has §4.1 (graceful, three sub-triggers)
and §4.2 (ungraceful, three sub-triggers). "Three teardown paths" is
ambiguous -- does it mean the three rows in §4.1 (demote, ban,
shutdown) or the two categories?

**Resolution**: Change to "Teardown (§4) releases resources on all
paths in §4.1 (graceful: demote, ban, shutdown) and §4.2 (ungraceful:
idle timeout, peer RST, partition)."

---

## Passes Not Applied (this session)

| Pass | Reason |
|------|--------|
| 7: Economic / Game Theory | Out of scope -- spec is mechanical, not economic |
| 8: Attack Trees | Deferred -- covered by attack-trees.md review |
| 9: Test Vectors | Not applicable -- no deterministic transformations |
| 10: Privacy | Covered by review-privacy.md (connection metadata already analysed) |
| 11: Operational Readiness | Partial -- CL-03/06 cover the biggest gaps; full pass would need debug-telemetry.md co-review |
| 12: Compliance | Not applicable |

---

## Recommended Triage

**Fix before Phase 1 close:**

- CL-01 (protocol gating contradicts role-aware model) -- silent
  partitioning risk, already fixed in code but the spec could mis-lead
  a re-implementation.
- CL-02 (APP_ERROR constants undefined) -- interop blocker for any
  second implementation.

**Schedule as doc debt (before Phase 2 contributor onboarding):**

- CL-03, CL-04, CL-05, CL-06 -- HIGH findings with local fixes, no
  code change needed beyond the spec text.
- CL-07, CL-08, CL-09, CL-10, CL-11 -- MEDIUM, all resolvable with
  small edits in this spec; CL-09 (connection_tracker release on
  ungraceful teardown) is worth verifying in code too.

**Defer-close (acceptable as-is):**

- CL-12, CL-13 -- cosmetic.

---

*Review complete 2026-04-17.*
