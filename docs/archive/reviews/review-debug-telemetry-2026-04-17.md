# Review: debug-telemetry.md

> Fresh review pass applying the review-spec methodology to
> `debug-telemetry.md` (v1.0, 2026-03-14, 248 lines). Phase 1 closing
> due-diligence. This is a telemetry/observability contract spec, so
> the usual six passes are supplemented by telemetry-specific checks:
> metric names, label cardinality, log levels, trace propagation, and
> privacy of log content.

## Application Record

| Field | Value |
|-------|-------|
| Date | 2026-04-17 |
| Reviewer | Russell Wing + Claude Opus 4.7 |
| Spec | debug-telemetry.md (v1.0, 2026-03-14) |
| Passes applied | 1 (Gaps), 2 (Consistency), 3 (Clarity), 4 (Implementability), 5 (Coverage), 6 (Cross-ref integrity) + telemetry-specific checks |
| Reference specs | network-protocol.md, connection-lifecycle.md, operations.md, parameter-rationale.md, spec-alignment-audit.md, CLAUDE.md |
| Cross-checked code | crates/cordelia-api/src/handlers.rs, crates/cordelia-node/src/p2p.rs, crates/cordelia-node/src/main.rs, crates/cordelia-network/src/codec.rs, crates/cordelia-core/src/protocol.rs |
| Prior reviews cross-checked | review-topology-e2e-2026-04-17.md (TE-01 status endpoint), review-status-2026-04-17.md, spec-alignment-audit.md (S2 per-protocol timeouts closed) |
| Post-pivot drift flagged | Yes -- see DT-01, DT-02, DT-03, DT-08 |

---

## Summary

15 findings. **2 CRITICAL** (DT-01: every literal log line string in §3 drifts from shipped code -- "push delivered" vs `repush delivered`, "dedup_dropped" vs `dedup`, "spawning push task" / "item pushed to peers" / "push open_bi started" never appear in the codebase at all, so `grep` workflows documented in §4 will silently miss events; DT-02: §6 `/api/v1/status` response contract promises 11 fields but the shipped endpoint returns 6, and adds one the spec doesn't list -- any client or E2E assertion written against the spec will fail). **4 HIGH** (DT-03: zero mention of post-pivot telemetry needs -- no SeenTable / epidemic forward / role-aware Warm acceptance / batched sync / swarm hot_max / channel-announce logging guidance, even though these are the mechanisms that make R=200 converge; DT-04: §5.2 timeout table still implies multiple distinct timeout values and names callers that were removed in session 99, contradicting the "single STREAM_TIMEOUT=10s" fix recorded in spec-alignment-audit.md S2 and the uniform `HANDSHAKE_TIMEOUT_SECS = STREAM_TIMEOUT_SECS` in code; DT-05: no label-cardinality guidance -- `peer=<node_id>` and `item=<item_id>` in every log line at DEBUG produce unbounded cardinality if ever exported to a metrics backend; DT-06: privacy of log content is not addressed at all, yet DEBUG examples log `channel=<channel_id>` and the TRACE level permits "frame hex dumps" of encrypted payloads). **6 MEDIUM** (tick_interval_secs default stated as generic `tick_interval_secs`; bootnode "reason" enum is ad hoc; "dedup" naming inconsistent with receive-side field `dedup_dropped`; stream protocol enum partial; silent-skip rule in §3.1 is now backward -- after epidemic forwarding, `excluded` has two legitimate sources; no guidance on rate-limited / dropped-due-to-governor events). **3 LOW** (cross-ref polish, version footer pre-pivot, "DEBUG/WARN" slash notation).

The spec is sound in structure and its BV-22/BV-23 motivation is still live. But it has not been updated since 2026-03-14 -- before session 92's codec-layer unification, before session 99's per-protocol timeout removal, before epidemic forwarding, role-aware Warm gating, and batched sync landed. The result is that (a) every concrete log-string example in §3 is a ghost: the string does not exist in shipped code; (b) the status endpoint contract in §6 is fiction; and (c) the most important telemetry questions for the post-pivot network -- "did the seen_table suppress this peer? did role-aware gating drop this frame? did the batched sync flush? why is a swarm member still in the hot set?" -- are absent. Phase 1 ships, so the drift is not a release blocker, but the spec as written will mislead anyone writing new diagnostic tooling or new E2E assertions.

---

## CRITICAL

### DT-01: Every literal log-line string in §3 disagrees with shipped code

**Spec**: §3.1 (Item-Push), §3.2 (Item-Sync / Pull), §3.3 (Peer-Sharing), §3.4 (Bootstrap). The spec presents log lines as normative templates -- "Every protocol operation MUST produce at least one DEBUG log on entry and one on exit" (§1) -- and §4 builds a `grep ci_01ABC123` workflow on top of the exact string forms.

**Evidence** (grep across `crates/`):

| Spec string (§3.1)                   | Code string                                                   | File:line                               |
|--------------------------------------|---------------------------------------------------------------|-----------------------------------------|
| `spawning push task`                 | _not present_                                                 | -                                       |
| `push open_bi started`               | _not present_                                                 | -                                       |
| `push delivered`                     | `repush delivered`                                            | `cordelia-node/src/p2p.rs:934`          |
| `push send failed`                   | `repush open_bi failed`                                       | `cordelia-node/src/p2p.rs:920`          |
| `push open_bi timed out`             | _not present as distinct line_                                | -                                       |
| `item pushed to peers`               | _not present_                                                 | -                                       |
| `processed inbound push ... dedup_dropped=<N>` | `processed inbound push peer stored dedup items`    | `cordelia-node/src/p2p.rs:1503`         |
| `relay re-push queued`               | `relay repush queued (epidemic)`                              | `cordelia-node/src/p2p.rs:1523`         |
| `content hash mismatch` (WARN)       | `content hash mismatch` (WARN)                                | `cordelia-node/src/p2p.rs:38` (matches) |
| `push skipped: connection not found` | _not present in current codebase_                             | -                                       |

For §3.2 (sync) the labels in the shipped `served sync request` / `served fetch request` / `served peer-share request` do match (peer, channel, fetched/count), but the requester-side lines (`sync request sent`, `sync response`, `fetch request sent`, `fetch response`) are not all emitted with the spec's names either. A field name drift: spec uses `dedup_dropped=<N>`, code emits `dedup`.

**Issue**: §4's entire operator model ("grep an `item_id` across logs and see the end-to-end story") is built on these exact strings. If the strings in the spec don't exist in the binary, a new operator (or a new test assertion) using the spec as reference will see holes in the trace that look like bugs but are actually spec/code drift. This is the BV-22 class of failure the spec exists to prevent, re-introduced at the spec layer itself.

**Resolution**:

1. Do a one-shot sweep: `cargo run --quiet` a single publish/push/sync cycle with `RUST_LOG=cordelia_node=debug,cordelia_network=debug`, capture the log, and rewrite §3 using the **actual** strings as normative.
2. Where the code is missing coverage the spec mandates (no `spawning push task`, no `push open_bi started`, no `item pushed to peers` summary), either add the log lines in code or mark them in the spec as "Phase 2 -- not yet emitted".
3. Align the field name: either rename the log to `dedup_dropped` in code (matches `PushAck.dedup_dropped` in the wire format) or change the spec to `dedup`. The wire-format field is `dedup_dropped` (see `p2p.rs:1529`), so preferring the longer form in logs too is cleaner.
4. Add an assertion in `tests/e2e/assertions/common.sh` (or a new `telemetry.sh`) that runs during CI and asserts each documented log string appears in the captured daemon log of a canonical test scenario. This makes §3 a tested contract.

### DT-02: §6 status endpoint response contract contradicts shipped endpoint

**Spec** §6 (Status Endpoint Telemetry, lines 204-224):

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

The spec says "The `/api/v1/status` endpoint MUST include" -- a normative contract.

**Evidence**: `crates/cordelia-api/src/handlers.rs:1265-1291` actually returns:

```json
{
  "status": "running",
  "uptime_secs": <u64>,
  "peers_hot": <u64>,
  "peers_warm": <u64>,
  "channels_subscribed": <usize>,
  "sync_errors": <u64>
}
```

Discrepancies:
- **6 fields missing**: `items_stored`, `items_pushed`, `items_received`, `streams_opened`, `streams_active`, `push_timeouts`, `sync_timeouts` (that's 7 actually).
- **2 spec divergences**: code adds `status: "running"` and `channels_subscribed` (neither in spec).
- **Type drift**: spec shows `uptime_secs: 1234.5` (float); code casts to `u64` (integer). Any deserializer with a fixed type will fail on one or the other.
- **Auth**: spec doesn't mention the bearer-auth requirement, but the handler calls `check_bearer(&req, &state)?` on entry. A consumer writing a pure-HTTP-spec client per §6 won't know to set `Authorization: Bearer ...`.

**Issue**: This is the same class of spec/code drift TE-01 hit (status GET vs spec's `api_post`). Any external integrator or dashboard using §6 as the contract will get either parse errors or missing-field errors. Any E2E assertion that `jq -r '.items_stored'` will return `null`. The "MUST" in §6 is not enforced anywhere.

**Resolution**: Two paths -- spec-follows-code or code-follows-spec. Recommend **both**, in order:

1. **Immediate (spec-follows-code)**: Amend §6 to match the current 6 fields returned (plus the auth header requirement). Move the "aspirational" counters (items_stored, items_pushed, streams_*, *_timeouts) to a new §6.1 labelled "Phase 2 additions -- not yet emitted". This stops new code from being written against fiction.
2. **Phase 2 follow-through (code-follows-spec)**: Add the counters to `AppState` (there's already `peers_hot`, `peers_warm`, `sync_error_count` atomic counters; the pattern extends naturally) and to the JSON body. Gate on whether any consumer actually uses them -- per MEMORY.md, the MCP adapter does not.
3. Add a CI assertion: `jq -e 'has("uptime_secs") and has("peers_hot") and has("peers_warm") and has("sync_errors")'` against `/api/v1/status` in the E2E harness so the contract is tested.

---

## HIGH

### DT-03: Post-pivot telemetry surface not specified at all

**Spec**: §3 (Protocol Operation Telemetry). Covers item-push, item-sync, peer-sharing, bootstrap. Does not cover any of the mechanisms that landed post-pivot.

**Evidence**: The following mechanisms exist in shipped code and in network-protocol.md but have no required telemetry in debug-telemetry.md:

| Mechanism                              | network-protocol.md | debug-telemetry.md                       |
|----------------------------------------|---------------------|------------------------------------------|
| SeenTable / epidemic forwarding (§7.2) | Yes, §7.2 + §5.4.2  | **No** -- only "relay re-push queued"    |
| Role-aware Warm acceptance (§5.4.2)    | Yes                 | **No**                                    |
| Batched per-peer sync (§4.5)           | Yes                 | **No** -- "sync request sent" is per-channel |
| Swarm hot_max exemption                | Yes                 | **No**                                    |
| Channel-Announce frames                | Yes, §4.7           | **No**                                    |
| Governor demote/promote events         | operations.md       | **No**                                    |
| Rate-limit drops (§9.2)                | Yes                 | **No**                                    |

Shipped code does emit some of these -- e.g. `p2p.rs:908` emits `relay repush flush (epidemic) items=<N> peers=<N> seen_table=<N>` -- but the spec does not require it or tell operators how to interpret it.

**Issue**: The #9 sparse-mesh partitioning bug from pre-session-120 would be much easier to diagnose with an explicit telemetry contract for seen-table hits/misses, role-aware Warm accepts, and batched-sync flush timing. The spec predates those bugs being understood. Any Phase 2 engineer reaching for logs to diagnose a convergence issue at R=100+ will find this spec silent on the mechanisms that actually drive convergence.

**Resolution**: Add §3.5 "Epidemic Forwarding (§7.2 cross-ref)":
```
DEBUG relay repush flush     items=<N> peers=<N> seen_table=<N>  (exists: p2p.rs:908)
DEBUG relay repush queued    peer=<sender_id> queued=<N>          (exists: p2p.rs:1523)
DEBUG seen_table hit         item=<item_id> peers=<N>             (add)
DEBUG seen_table evicted     item=<item_id>                       (add; TTL expiry)
DEBUG seen_table full        size=<N> max=<SEEN_TABLE_MAX>        (add; WARN if sustained)
```

Add §3.6 "Role-Aware Gating":
```
DEBUG inbound push from warm peer  peer=<node_id> accepted (relay-mode)
WARN  inbound push from warm peer  peer=<node_id> rejected (personal-mode)
```

Add §3.7 "Batched Sync":
```
DEBUG batched sync flushed  peer=<node_id> channels=<N> duration_ms=<N>
```

Add §3.8 "Governor Transitions" (cross-ref connection-lifecycle.md):
```
INFO  peer promoted  peer=<node_id> from=<state> to=<state> reason=<...>
INFO  peer demoted   peer=<node_id> from=<state> to=<state> reason=<...>
INFO  peer reaped    peer=<node_id> last_seen_secs=<N>
```

### DT-04: §5.2 timeout table still implies pre-session-92 per-protocol timeouts

**Spec**: §5.2 Connection-Level Timeouts (lines 187-200):
```
| QUIC incoming handshake      | 10s | WARN  | log WARN, continue accepting |
| Bootstrap connect per bootnode | 10s | WARN | continue to next bootnode |
| Handshake (initiate/accept)  | 10s | WARN  | close connection |
| open_bi (all protocols)      | 10s | DEBUG | log, skip peer |
| connect_to (governor/peer-share) | 10s | WARN | mark_dial_failed |
| shutdown_and_wait            | 30s | WARN  | force close endpoint |
```

The §5.1 text correctly states "A single uniform timeout (10s) at the codec layer eliminates redundant multi-layer timeouts that previously caused silent shadowing bugs".

**Evidence**: `crates/cordelia-core/src/protocol.rs:87` `STREAM_TIMEOUT_SECS = 10` and `protocol.rs:140` `HANDSHAKE_TIMEOUT_SECS = STREAM_TIMEOUT_SECS`. `protocol.rs:807` asserts `HANDSHAKE_TIMEOUT_SECS == STREAM_TIMEOUT_SECS`. spec-alignment-audit.md S2 records: "FIXED (session 92). Per-protocol timeouts removed; code uses single STREAM_TIMEOUT=10s."

**Issue**: §5.2 is technically correct -- every row is 10s -- but it still presents the operations as *having their own* per-operation timeouts. Reading §5.2 one would think "open_bi has a 10s timeout **independent** of handshake's 10s timeout". The truth post-session-92 is that they all share `STREAM_TIMEOUT_SECS` and are unified *because* that unification prevents shadowing bugs. The table format encourages re-introduction of the drift the unification was meant to stop.

Worse, the "Action" column prescribes different responses (log WARN vs log DEBUG vs close connection vs force-close endpoint) for what is effectively the same timeout event with different call sites. That's fine as an operational recipe but obscures that all of these are `STREAM_TIMEOUT` expiry.

**Resolution**:
1. Rewrite §5.2 as prose emphasising one timeout, not a table:
   > All network I/O uses `STREAM_TIMEOUT = 10s` (`cordelia_core::protocol::STREAM_TIMEOUT_SECS`). Callers do NOT compose this with additional timeouts. `HANDSHAKE_TIMEOUT_SECS` is defined as an alias of `STREAM_TIMEOUT_SECS` (protocol.rs:140) so there is only one knob. The QUIC idle timeout (60s) is a backstop; operational diagnosis MUST assume the 10s codec timeout is the primary signal.
2. Keep the "Action" column in a separate §5.3 "Timeout Recovery Playbook" that lists which operation responds how -- decoupled from the timeout value.
3. Add an explicit spec-alignment-audit.md S2 cross-ref so future editors see the session-92 fix history.
4. The only non-codec timeout in the current code is `shutdown_and_wait = 30s`. Call that out explicitly as "the sole non-`STREAM_TIMEOUT` value in the network path" so it stops looking like one of a family.

### DT-05: Label cardinality is not bounded

**Spec**: §1 "every protocol operation MUST produce at least one DEBUG log on entry and one on exit" with labels `peer=<node_id>`, `item=<item_id>`, `channel=<channel_id>`, `stream_id=<id>`.

**Issue**: At R=200 relays with 200 channels and typical per-channel item rates, a naive metrics exporter that tags every log event by `peer × item × channel × stream_id` produces effectively unbounded cardinality. This is not a problem today because `tracing` logs to stdout only, but the spec implies (§2.3 "via status endpoint or periodic log") that metrics are part of the contract. A Prometheus-style exporter built against this spec will OOM its backend in minutes.

No guidance is given on:
- Which fields are "log only" vs "metric-eligible".
- Which fields to hash/truncate before exporting as labels (e.g. short peer prefix).
- Counter vs gauge distinction (stated informally in §6 but not in §2-3).
- Maximum label cardinality (Prometheus rule of thumb: <10k unique values per label).

**Resolution**: Add a new §2.4 "Metric Export Guidance":
- Logs use full identifiers: `peer=<32-byte node_id hex>`, `item=<ulid>`, `channel=<64-char hex>`.
- Metrics (if exported) use low-cardinality labels: `peer_prefix` (8 hex chars), `channel_prefix` (8 hex chars), no `item_id` labels ever (item-level data goes into logs).
- Counters (cumulative monotonic): sync_errors, items_stored, items_pushed, items_received, streams_opened, push_timeouts, sync_timeouts.
- Gauges: peers_hot, peers_warm, streams_active, seen_table_size.
- Histograms (Phase 2): stream_duration_ms, sync_headers_count, push_batch_size.

### DT-06: Privacy of log content is not addressed

**Spec**: §1 Log Levels table (TRACE row: "Wire-level detail (frame bytes, CBOR dumps)", "Never in production"). §3 examples include `channel=<channel_id>`, `item=<item_id>`, and §4 shows `grep "ci_01ABC123" logs/p1.log logs/r1.log logs/p2.log`.

**Issue**: Cordelia's value prop is E2E encrypted pub/sub. Logs that contain `item_id` at DEBUG -- where `item_id = ulid` and is derived from publish time + randomness -- do not leak content, but:
- `channel_id` in logs at DEBUG leaks membership information. Anyone with log access can correlate `peer=<node_id>` with `channel=<channel_id>` and reconstruct subscription graphs. This is exactly the metadata leak that channels-api.md §3.15 (per PV-28 in review-privacy.md) takes pains to truncate to 8 hex chars in URLs.
- TRACE's "frame hex dumps" -- even though marked "never in production" -- include ciphertext. If a TRACE-enabled dev node is dumped to a shared log aggregator, the ciphertext is now in a system that MAY log forever. With PSK rotation, old ciphertext becomes decryptable for the PSK holder.
- No redaction guidance. Do we log keepalive contents? Probe contents (which are encrypted but contain sender metadata)? Handshake fields?

**Issue is increased** because §7's checklist tells every operator to include `item=<item_id>` and `peer=<node_id>` in every line, with no mention of what NOT to log.

**Resolution**: Add a new §8 "Log Privacy Requirements":
- **Never log at any level**: plaintext item bodies, plaintext metadata, PSKs, private keys, raw handshake ephemeral secrets, nonces.
- **Log at DEBUG only with a prefix**: `channel=<first_8_hex>...` (matches channels-api.md §3.15 URL truncation convention).
- **TRACE ciphertext**: MAY dump ciphertext bytes for protocol debugging, but daemons MUST refuse to start with TRACE enabled if `production_mode = true` (add a config gate).
- **Log ingestion**: if logs are shipped off-host, operator MUST strip `channel=` labels or retain only 8-char prefixes before ingestion. Add this as a requirement to operations.md §runbook.
- Cross-ref review-privacy.md PV-28.

---

## MEDIUM

### DT-07: §2.3 "tick_interval_secs" cited without its default

**Spec**: §2.3 "This MUST be logged at least once per governor tick (every `tick_interval_secs`)." No default given.

**Evidence**: `crates/cordelia-core/src/protocol.rs` `TICK_INTERVAL_SECS`; network-protocol.md §5.4 says "every `tick_interval_secs`, default: 10s".

**Resolution**: Spell out the default: "every `tick_interval_secs` (default 10s, see network-protocol.md §5.4)". A reader of debug-telemetry in isolation does not know this is a 10s cadence.

### DT-08: `peer connection closed reason=<idle|reset|shutdown|error>` enum is unspecified

**Spec**: §2.1 line 43 shows `reason=<idle|reset|shutdown|error>`.

**Issue**: These reasons are not defined anywhere. connection-lifecycle.md describes closure causes in prose ("idle timeout", "keepalive timeout", "governor demotion", "shutdown", "protocol violation", "rate-limit exhaustion") -- at least 6 distinct causes. The spec's 4-value enum doesn't map cleanly. A downstream alerting rule ("alert if `reason=error` rate > X") won't know which of the 6 real causes it covers.

**Resolution**: Align with connection-lifecycle.md. Recommended enum:
```
reason = idle | keepalive_timeout | governor_demotion | shutdown | protocol_violation | rate_limit | transport_error
```
Cross-ref connection-lifecycle.md §closure-causes. Add the exact enum value each cause uses so code + spec agree.

### DT-09: `dedup` vs `dedup_dropped` field naming inconsistent across spec

**Spec**: §3.1 receiver side uses `dedup_dropped=<N>`. §4 trace example uses both: `dedup=0` (p1, r1) and `dedup_dropped` is not shown; the example has `dedup_dropped` nowhere.

**Issue**: Internal inconsistency. Code uses `dedup`, wire format uses `dedup_dropped`. See DT-01 for the cross-code drift; this finding covers the intra-spec drift.

**Resolution**: Pick one. Recommend `dedup_dropped` (matches wire format).

### DT-10: Stream-protocol enum in §2.2 is partial

**Spec**: §2.2 `protocol=<push|sync|peer_share|...>`.

**Issue**: The `...` implies undefined values. Real protocol byte values per `crates/cordelia-core/src/protocol.rs`: handshake, item_push, item_sync, peer_share, channel_announce, keepalive, probe. Seven values, not three.

**Resolution**: List them all. Match exact wire identifiers (e.g. `item_push` not `push`) so a log line maps 1:1 to a wire frame type.

### DT-11: §3.1 silent-skip rule is now backward under epidemic forwarding

**Spec**: §3.1 line 99: "Terminology: In push logs, `excluded` = sender peer (relay re-push loop prevention), `skipped` = peer where get_connection() returned None (bug indicator). These are distinct: excluded is expected, skipped is unexpected."

**Issue**: Post-epidemic-forwarding (§7.2), `excluded` has two legitimate sources, not one:
1. The sender peer (loop prevention -- original meaning).
2. Any peer already in the `seen_table` entry for this content_hash (legitimate dedup, the whole point of the seen_table).

So a push where `pushed=1, excluded=4` could mean either "1 sender excluded + 3 seen_table hits" or any mix. The spec's current wording will read to a new operator as "4 senders? that's wrong" -- it isn't.

**Resolution**: Rewrite §3.1 terminology:
```
excluded_sender = <N>       peers excluded because they sent us this item (loop prevention)
excluded_seen   = <N>       peers already known to have this item (seen_table hit)
pushed          = <N>       peers we actually opened a stream to
skipped         = <N>       peers we tried to push to but get_connection() returned None (bug)
```
Replace the single `excluded=<N>` field in log lines with the two subfields. Alternatively, expose `excluded=<N> (sender+seen)` and log `seen_table_hits=<N>` separately.

### DT-12: No guidance on rate-limit / governor-drop events

**Spec**: §3 does not mention rate-limit or governor-drop events anywhere.

**Issue**: Post-pivot code rejects inbound streams when per-peer rate limits are exhausted (network-protocol.md §9.2). These silent rejections are exactly the kind of hang-looking-like-drop that BV-22 motivated the spec to expose.

**Resolution**: Add to §3 (or a new §3.9 "Defensive drops"):
```
WARN  rate limit hit           peer=<node_id> protocol=<type> window=<N>s retry_after=<N>s
DEBUG governor dropped peer    peer=<node_id> from=<hot|warm> reason=<score|timeout|kick>
```

---

## LOW

### DT-13: Version footer predates all post-March-14 work

**Spec footer**: "Spec version: 1.0, Created: 2026-03-14".

**Resolution**: If this review leads to the recommended rewrites, bump to 1.1 and add "Updated: 2026-04-17" with changelog: unified STREAM_TIMEOUT, epidemic forwarding telemetry, post-pivot status endpoint contract, privacy requirements.

### DT-14: `DEBUG/WARN` slash notation

**Spec**: §7 checklist "log on error (DEBUG/WARN)".

**Issue**: Ambiguous -- is it DEBUG for one class, WARN for another, or "either"? Match §1 table which uses specific levels per event class.

**Resolution**: "log on error at WARN if the error is recoverable but indicative; DEBUG if expected at the protocol boundary (e.g. peer disconnect during normal shutdown)."

### DT-15: Cross-refs not updated

**Spec**: Final line "Cross-refs: network-protocol.md §4, topology-e2e.md, review-build-verification.md".

**Issue**: Missing refs to connection-lifecycle.md (closure reasons, DT-08), operations.md (runbook), review-privacy.md (PV-28, DT-06), spec-alignment-audit.md (session-92 fix, DT-04), parameter-rationale.md (STREAM_TIMEOUT rationale). topology-e2e.md reference is fine but `review-build-verification.md` is a review doc -- the underlying spec it reviews is what should be cited for the BV-22 motivation.

**Resolution**: Expand cross-refs; add section numbers for each ref.

---

## Telemetry-specific check outcomes

| Check                     | Status  | Evidence                                                                     |
|---------------------------|---------|------------------------------------------------------------------------------|
| Metric names consistent   | FAIL    | DT-01 (logs), DT-02 (status endpoint), DT-09 (dedup naming)                 |
| Label cardinality bounded | NOT ADDRESSED | DT-05                                                                   |
| Log level discipline      | PARTIAL | §1 table is good; §7 "DEBUG/WARN" ambiguity (DT-14)                         |
| Trace propagation         | NOT ADDRESSED | Spec has no concept of a correlation ID or `trace_id` across nodes. §4 uses `item_id` as a de facto correlation ID, which works only for item-flow traces, not for connection/handshake/peer-share flows. Consider a `request_id` or `trace_id` convention in Phase 2. |
| Privacy of log content    | NOT ADDRESSED | DT-06                                                                   |

---

## Passes applied (matrix)

| Pass                         | Findings                                  |
|------------------------------|-------------------------------------------|
| 1. Gap Analysis              | DT-03, DT-06, DT-10, DT-12                |
| 2. Underspecification        | DT-05, DT-07, DT-08, DT-09, DT-14         |
| 3. Clarity                   | DT-04, DT-11, DT-13                       |
| 4. Implementability          | DT-01, DT-02                              |
| 5. Coverage                  | DT-03, DT-06, DT-12                       |
| 6. Cross-ref integrity       | DT-15                                     |

---

## Recommended action order

1. **DT-01, DT-02** (CRITICAL): sweep log strings, rewrite §3 and §6 against shipped binary. Single PR; no code change needed. Add CI assertions for both (string-presence grep + status JSON shape).
2. **DT-04** (HIGH): Rewrite §5.1/§5.2 to unify on `STREAM_TIMEOUT`. Cross-ref spec-alignment-audit.md S2.
3. **DT-03** (HIGH): Add §3.5-§3.8 covering seen_table, role-aware gating, batched sync, governor transitions.
4. **DT-05, DT-06** (HIGH): Add §2.4 metric cardinality guidance and §8 privacy requirements.
5. **DT-07..DT-12** (MEDIUM): Tighten definitions; align with connection-lifecycle.md and code.
6. **DT-13..DT-15** (LOW): Version bump, notation, cross-refs.

No code-blocking findings. Phase 1 ships. Recommend spec rewrite lands before Phase 2 Provider Integration work begins, so new MCP-adapter diagnostic tooling is written against an accurate contract.

---

*Review complete. 15 findings (2 CRITICAL, 4 HIGH, 6 MEDIUM, 3 LOW).*
*Reviewer: Russell Wing + Claude Opus 4.7*
*Date: 2026-04-17*
