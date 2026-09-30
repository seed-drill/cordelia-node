# Review: operations.md

> Fresh review pass applying review-spec methodology to
> `operations.md` (Draft, 2026-03-11, 870 lines). This is the first
> full pass on operations.md; prior reviews have targeted adjacent
> specs (network-behaviour, connection-lifecycle, parameter-rationale,
> identity, data-formats, topology-*, memory-model, demand-model,
> attack-trees, status) and are all closed.

## Application Record

| Field | Value |
|-------|-------|
| Date | 2026-04-17 |
| Reviewer | Russell Wing + Claude Opus 4.7 |
| Spec | operations.md (Draft, 2026-03-11) |
| Passes applied | 1 (Gaps), 2 (Consistency), 3 (Clarity), 4 (Implementability), 5 (Coverage), 6 (Cross-ref) + operations-specific: runbook completeness, incident response, key rotation, backup/restore, monitoring |
| Reference specs | network-protocol.md, connection-lifecycle.md, debug-telemetry.md, configuration.md, parameter-rationale.md, data-formats.md, channels-api.md, identity.md, CLAUDE.md |
| Code references | crates/cordelia-node/src/main.rs, scripts/install.sh |

---

## Summary

**11 findings.** 2 HIGH, 6 MEDIUM, 3 LOW.

The spec is well-structured and genuinely useful as an ops document,
but it is one of the older pre-pivot artefacts and exhibits the
recurring drift pattern seen across this review sprint:

- **Stale repo references** (`cordelia-core/...`) in two places where
  assets now live under `cordelia-node`.
- **CLI surface over-specified relative to shipped binary** -- many
  documented subcommands (`pair`, `join`, `export`, `stop`, `version`,
  `help`) and flags (`--foreground`, `--persistent`, `--json`,
  `--quiet`, `--log-level`, `--show-backup-key`, `--import-key`) are
  not implemented. A reader using operations.md as a runbook today
  will hit "not yet implemented" or unknown-subcommand errors.
- **Post-pivot network mechanics not reflected** -- the troubleshooting,
  monitoring, and alerting sections pre-date epidemic forwarding,
  role-aware Warm gating, batched sync, and the seen_table. Several
  high-value diagnostic levers (seen_table TTL, batched sync stream
  count, per-role protocol gating) are invisible to operators.
- **Operations-critical runbooks missing** -- no runbook for key/PSK
  rotation (referenced as "§3.11" which does not exist), no monitoring
  integration with debug-telemetry.md, no dedicated incident response
  section despite Pass 11 operational readiness being the core purpose
  of this spec.

Top two issues are OP-01 (phantom §3.11 rotation runbook + missing
full key/PSK rotation procedures) and OP-02 (CLI reference materially
diverges from shipped binary).

---

## HIGH

### OP-01: Key and PSK rotation runbook is missing; §3.11 cross-ref is a dead link

**Spec**: §12 "Breach notification" references `§3.11` ("rotate
immediately (§3.11)"); no §3.11 exists. §3 covers pairing only, up to
§3.4. No section in operations.md describes identity rotation or PSK
rotation procedures.

**Issue**: This is the most important incident-response runbook in
the whole document and it's a broken cross-reference. Operators have
no step-by-step procedure for the single most common compromise
scenario (stolen PSK, stolen identity key). identity.md has concept
notes and ecies-envelope-encryption.md §6.4 has PSK rotation mechanics
at the protocol level, but nothing ties them together as an ops
runbook with CLI steps, coordination with channel members, or
post-rotation verification.

**Resolution**: Add new §9.5 "Key and PSK Rotation" runbook covering:

1. **Compromised identity key** -- procedure for generating new
   keypair, notifying channel owners, re-subscribing to open channels,
   re-requesting invites for invite-only channels, abandoning old
   identity.
2. **Compromised channel PSK** -- for channels this node owns:
   `cordelia channel rotate-key <channel>` (document the command or
   mark as Phase 2 gap), for channels this node subscribes to: wait
   for owner rotation, verify new `key_version` received via
   ChannelJoined (network-protocol.md §4.4.1).
3. **Compromised node token** -- regenerate `~/.cordelia/node-token`,
   update all SDK clients.
4. **Post-rotation verification** -- cross-check `cordelia channels`
   shows new `key_version`, confirm old PSK ciphertext is still
   readable via historical archive if required for audit.

Fix the `§3.11` cross-reference in §12 Breach notification to point
at the new §9.5.

### OP-02: CLI reference diverges from shipped binary

**Spec**: §4.1 subcommand table lists `pair`, `join <code>`, `stop`,
`export`, `version`, `help`. §4.1 flag table lists `--foreground`,
`--persistent`. §4.2 global flags list `--json`, `--quiet`,
`--log-level`. §9.2 paper backup references `--show-backup-key` and
`--import-key`.

**Actual** (crates/cordelia-node/src/main.rs as of Session 121):
- Shipped subcommands: `init`, `status`, `start`, `stop` (stub: prints
  "not yet implemented"), `peers` (stub: prints "No peers connected"),
  `channels`, `stats`, `pubkey`, `swarm-init`.
- No `pair`, `join`, `export`, `version`, `help` subcommand handlers.
- No `--foreground`, `--persistent`, `--json`, `--quiet`,
  `--log-level` flags on `start`.
- No `--show-backup-key` / `--import-key` on `init`.
- systemd/LaunchAgent unit files (§7.1, §7.2) call
  `cordelia start --persistent` -- this flag does not exist and would
  cause clap to reject the command.

**Issue**: An operator following this spec as a runbook today will
fail at basic steps. The systemd unit example in §7.2 and the
LaunchAgent plist in §7.1 will not work as written because the
`--persistent` flag is undefined. `cordelia version`, referenced in
§10.1 Upgrade procedure, does not exist. This directly contradicts the
"spec before code, prescriptive not descriptive" principle from
CLAUDE.md and risks Process Anti-Pattern #1 (spec-after-code) in
reverse -- the spec has drifted ahead of shipping code without a
clear Phase 1 / Phase 2 label.

**Resolution**: Two options, pick one consistently:

1. **Phase-tag the spec**: add `[Phase 2]` tags next to every
   unshipped subcommand/flag and move the as-shipped subset to a
   clearly labelled "Phase 1 (current)" section. Update §7.1, §7.2
   service unit files to drop `--persistent` (just `cordelia start`
   until the flag is implemented).

2. **Close the gap in code**: implement the documented surface so the
   spec matches reality. Minimum viable set for Phase 1 completion:
   `cordelia version` (print version+commit), `cordelia stop` (send
   SIGTERM to pid file), `cordelia peers` real output. Defer
   `pair`/`join`/`export`/`--show-backup-key`/`--import-key` to
   Phase 2 with explicit tags.

Either way, also fix the systemd/LaunchAgent examples so they use
only as-shipped flags.

---

## MEDIUM

### OP-03: Stale `cordelia-core` repo references

**Spec**: §1.4 Manual install uses
`https://github.com/seed-drill/cordelia-core/releases/...` (two
URLs). §8.4 Grafana Dashboard references
`cordelia-core/ops/grafana-dashboard.json`.

**Issue**: `cordelia-core` is archived on GitHub (per MEMORY.md).
Current binary and release artefacts live at `cordelia-node`. Anyone
running the manual install procedure will hit a 404 on GitHub (the
archived repo has no recent releases). No `ops/grafana-dashboard.json`
exists in `cordelia-node` -- this is a promised deliverable that was
never migrated.

**Resolution**: Replace `seed-drill/cordelia-core` with
`seed-drill/cordelia-node` in §1.4 URLs. For §8.4, either create
`cordelia-node/ops/grafana-dashboard.json` as part of Phase 1 close-out
or mark the dashboard as Phase 2 deliverable and remove the "Phase 1
ships with" language.

### OP-04: Post-pivot network mechanics absent from troubleshooting

**Spec**: §11.3 Replication Lag gives four causes (batch channel, peer
disconnected, large item backlog, network congestion). §11.2 No Peers
lists firewall, DNS, bootnodes, NAT.

**Issue**: Phase 1's most common operational issues are post-pivot
mechanics -- epidemic forwarding, role-aware Warm gating, seen_table
TTL, batched sync -- and none appear in troubleshooting. Specifically
missing:

- **Asymmetric hot sets causing silent drop** (network-protocol.md
  §5.4.2, §7.2): if a relay running older code rejects data protocols
  from Warm peers, items are lost. Operators need a diagnosis step
  ("check peer version; role-aware gating was added in Session 120").
- **seen_table full or stale** (SEEN_TABLE_MAX=10000,
  SEEN_TABLE_TTL_SECS=600): items may be suppressed as "already
  forwarded" if the seen table hasn't rolled over. No symptom/resolution
  documented.
- **Batched sync stream exhaustion** (§4.5 batched sync, one stream
  per peer): if this is misconfigured, symptoms look like replication
  lag but the root cause is different.
- **hot_max=2 on personal means only 2 relay peers** -- if both are
  down, the node is partitioned. Diagnostic: `cordelia peers` shows
  0 hot, `cordelia_peers_hot` metric fires PeerCountZero alert.

**Resolution**: Add §11.3.1 "Post-pivot diagnostic checks":

- How to verify epidemic forwarding is working (item_id trace via
  logs, cross-ref debug-telemetry.md §4).
- How to check seen_table state (status endpoint field, cross-ref
  status.md).
- Expected steady-state hot-peer count per role (reference
  parameter-rationale.md §3 and §12.2 of network-protocol.md).
- Asymmetric-hot-set detection: if `cordelia peers` on node A shows
  peer B as Hot but node B shows A as Warm, this is expected in
  sparse mesh and protocol gating must allow data flow both ways.

### OP-05: Monitoring section doesn't reference debug-telemetry.md or connection-lifecycle.md

**Spec**: §8 Monitoring covers `/api/v1/health`, `/api/v1/metrics`,
alerting, Grafana. §11 Troubleshooting suggests
`CORDELIA_LOG_LEVEL=debug`.

**Issue**: debug-telemetry.md is the authoritative source for log
structure, protocol operation telemetry (Item-Push, Item-Sync,
Peer-Sharing, Bootstrap), connection telemetry, and status endpoint
fields. operations.md does not cross-reference it at all. Operators
reading this doc will not know the structured log fields exist or
that there is a canonical trace example for end-to-end item flow.
Similarly connection-lifecycle.md §5 implementation checklist is the
source of truth for promotion sequences, accept-path timeouts, and
protocol gating -- and is not referenced.

**Resolution**: In §6 Logging, add subsection §6.5
"Protocol-level telemetry -> debug-telemetry.md" with forward
references to:
- §2 Connection telemetry (handshake timing, stream counts)
- §3 Protocol operation telemetry per mini-protocol
- §4 End-to-end trace example
- §5 Timeout specification (STREAM_TIMEOUT=10s, etc.)

In §11 Troubleshooting, add "See also: connection-lifecycle.md §5
Implementation checklist for connection establishment flows" at the
top.

In §14 References, add debug-telemetry.md, connection-lifecycle.md,
parameter-rationale.md.

### OP-06: Stale parameter values / missing post-pivot parameter surface

**Spec**: §5.1 config.toml shows `governor` settings moved to
`[governor]` section but only spells out the three role profiles
inline. No mention of STREAM_TIMEOUT, MAX_ITEM_BYTES, SEEN_TABLE_MAX,
SEEN_TABLE_TTL_SECS, batched-sync parameters, hot_min_relays.

**Issue**: Operators cannot tune without knowing these parameters
exist. parameter-rationale.md is the authoritative source; this spec
needs at minimum a cross-reference and ideally a "commonly tuned
parameters" subsection.

**Resolution**: Add §5.5 "Tuning parameters" table with:
- STREAM_TIMEOUT (10s, network-protocol.md §5.2, parameter-rationale.md
  §2 / debug-telemetry.md §5)
- MAX_ITEM_BYTES (256KB, data-formats.md §2)
- SEEN_TABLE_MAX (10000, network-protocol.md §7.2)
- SEEN_TABLE_TTL_SECS (600, ditto)
- hot_max (2 personal / 5 keeper / 50 relay, network-protocol.md §12.2)

Cross-reference `parameter-rationale.md` as the authoritative source
for why these values were chosen.

### OP-07: Health endpoint does not match channels-api.md POST convention

**Spec**: §8.1 `GET /api/v1/health` and §8.2 `GET /api/v1/metrics`.

**Issue**: channels-api.md §1 states "All POST (one exception: `GET
/metrics` for Prometheus convention, §3.15)." This makes `/health`
the second GET endpoint, which contradicts the API spec's stated
invariant. This is likely an oversight (health endpoints commonly use
GET for load-balancer probes) but the spec contradiction should be
resolved explicitly -- either channels-api.md must be updated to
state that `/health` is also an exception, or operations.md must
switch to POST.

**Resolution**: Recommend keeping GET for `/health` (universal LB
probe convention) and updating channels-api.md §1 to list `/health`
as a second exception. Note the reason: LB and container orchestrator
probes almost always use GET; requiring POST would require custom
probe configuration across most deployment environments. Update
channels-api.md to reflect this, then add a clarifying sentence in
operations.md §8.1 citing the exception.

### OP-08: Service manager lifecycle is under-specified

**Spec**: §2.2 step 9 says init "hands off to system service" and
exits. §7.1 / §7.2 show plist/systemd unit. No explicit statement of
the handoff mechanics, no mention of PID file, no mention of how
`cordelia stop` finds the running process.

**Issue**: §4.1 lists `cordelia stop` as a subcommand, but `stop` is
a stub in code (prints "not yet implemented (requires PID file /
signal)"). The spec never specifies:
- Where the PID file lives (`~/.cordelia/cordelia.pid`? `/var/run/`?)
- How the daemon writes its PID on startup
- What signal `stop` sends (SIGTERM? grace period? SIGKILL fallback?)
- Whether `cordelia stop` should delegate to systemd/launchctl when
  the service manager owns the process (recommended) vs signalling
  directly

**Resolution**: Add §7.3 "Daemon lifecycle" specifying:
- PID file at `~/.cordelia/cordelia.pid` (0600)
- Written on startup, deleted on clean shutdown
- `cordelia stop` first tries service manager (`launchctl
  unload` / `systemctl --user stop cordelia`), falls back to
  `kill -TERM <pid>` if no service, then waits up to 30s for clean
  exit before SIGKILL
- Transport-shutdown semantics: endpoint.close() + wait_idle() before
  process exit (cross-ref connection-lifecycle.md §4.2)

### OP-09: Incident response section is implicit / scattered

**Spec**: §12 Security Checklist has one paragraph on "Breach
notification". §11 Troubleshooting covers operational issues.

**Issue**: No unified incident response runbook. For a security
incident, the operator has to assemble:
- Breach detection (what logs to check)
- Identity/PSK rotation (missing, see OP-01)
- Forensics preservation (not mentioned)
- Peer isolation (`cordelia peers ban <entity>` -- does this exist?)
- Post-incident verification

The 72-hour GDPR/ICO notification clock starts ticking at detection,
so the runbook needs to be discoverable in under a minute.

**Resolution**: Add §12.1 "Incident Response Runbook" with:
1. **Detect**: which log patterns indicate compromise (auth failures,
   repeated Ed25519 signature failures, unexpected peer connection
   from unknown entity).
2. **Contain**: which commands to run (stop node via service manager,
   copy logs and DB offline, disconnect from network).
3. **Rotate**: cross-ref OP-01 §9.5.
4. **Notify**: ICO / DPA within 72 hours for UK-processed personal data.
5. **Verify**: checklist items from §12 Security Checklist.

---

## LOW

### OP-10: Uninstall command `cordelia stop` requires running daemon

**Spec**: §1.5 Uninstall starts with `cordelia stop`.

**Issue**: If the daemon is not running or is crashed, `cordelia
stop` will fail (exit code 4 per §4.7). The uninstall sequence should
be resilient. Also `cordelia stop` is not implemented (see OP-02).

**Resolution**: Change §1.5 to:

```bash
# Stop the service (via service manager, ignores if not running)
systemctl --user disable --now cordelia 2>/dev/null || true
launchctl unload ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist 2>/dev/null || true
# Remove binary
rm -rf ~/.cordelia/bin/
# Remove service unit files
rm -f ~/.config/systemd/user/cordelia.service
rm -f ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist
```

### OP-11: `cordelia export --all` tarball format and manifest schema are under-specified

**Spec**: §9.3 says "`--all` produces a `.tar.gz` containing one
`.jsonl` file per channel plus a `manifest.json` with channel metadata
and export timestamp."

**Issue**: `manifest.json` schema is not defined (which fields? which
channel metadata? export format version?). For GDPR data portability
(Art. 20) the schema must be stable and documented. Also no guidance
on whether exports should be idempotent, whether subsequent exports
reuse `item_id` values, and whether ciphertext export includes the PSK
(presumably not, otherwise the export is a key leak).

**Resolution**: Define `manifest.json` schema inline:

```json
{
  "export_version": 1,
  "exported_at": "2026-04-17T10:00:00Z",
  "entity_id": "russwing_a1b2",
  "public_key": "cordelia_pk1...",
  "format": "plaintext",
  "channels": [
    {
      "channel_id": "fe028fda...",
      "channel_name": "research-findings",
      "channel_type": "named",
      "mode": "realtime",
      "access": "open",
      "key_version": 3,
      "item_count": 47,
      "file": "channels/fe028fda.jsonl"
    }
  ]
}
```

State explicitly that `--encrypted` exports include ciphertext but
NOT PSK, and that restoring from an encrypted export requires the
subscriber's channel PSK to decrypt.

### OP-12: Security Checklist regex in §12 may miss some secret formats

**Spec**: §12 "No secrets in logs" check:
`grep -rE "cordelia_sk\|[0-9a-f]{64}" ~/.cordelia/logs/`

**Issue**: The regex uses escaped `\|` which in ERE is a literal `|`
character, not alternation. Should be plain `|`:
`grep -rE "cordelia_sk|[0-9a-f]{64}"`. As written, the regex matches
the literal string `cordelia_sk|[0-9a-f]{64}` which will never
appear, giving a false "clean" result.

Separately, 64-hex is a broad pattern that also matches SHA-256
hashes (content_hash, psk_hash, item_id prefixes), so manual review
is essential. The spec already says "manual review recommended for
base64-encoded secrets" -- extend this caveat.

**Resolution**: Fix the regex:

```bash
grep -rE "cordelia_sk|[0-9a-f]{64}" ~/.cordelia/logs/
```

Add caveat: "64-hex matches can be false positives (content_hash,
item_id, psk_hash). Manual review required to distinguish hashes from
secrets. For base64-encoded secrets (ECIES envelopes), use
`grep -rE '[A-Za-z0-9+/]{40,}=*'` and filter known-safe envelopes."

---

## Passes with zero findings

None -- operations.md touches almost every concern area so every pass
surfaced at least one issue.

---

## Recommended next actions

1. **Fix OP-01 and OP-02 before any further operations.md edits** --
   these are the two findings that directly break runbook usability
   today. OP-01 is a one-section add (§9.5 rotation runbook).
   OP-02 requires a decision: phase-tag or implement. Recommend
   phase-tag for now since Phase 1 close-out is the current priority
   and shipping `--persistent` / `pair` / `join` would be scope creep.
2. **Close OP-03 stale repo references** in the same commit as OP-02
   (one-line edits).
3. **OP-04 and OP-05** can be a single edit: add post-pivot
   diagnostic subsection plus cross-refs to debug-telemetry.md and
   connection-lifecycle.md.
4. **OP-06** needs alignment with parameter-rationale.md -- keep
   parameter-rationale.md as the source of truth, add a short
   "commonly tuned parameters" table here with cross-refs.
5. **OP-07** is a one-line consistency fix in channels-api.md §1
   (declare `/health` as a second GET exception).
6. **OP-08, OP-09, OP-10, OP-11, OP-12** are incremental improvements
   -- group into a single "operations.md readiness pass" commit.

---

*Review completed 2026-04-17. Pass count: 6 review-spec passes + 5 ops-specific runbook checks.*
