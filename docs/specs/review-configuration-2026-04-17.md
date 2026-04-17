# Review: configuration.md

> Fresh review pass applying review-spec methodology to
> `configuration.md` (draft 2026-03-12, 451 lines).
> Configuration-specific passes added: defaults verification,
> env-var vs file precedence, hot-reload semantics, deployment
> profile coverage.

## Application Record

| Field | Value |
|-------|-------|
| Date | 2026-04-17 |
| Reviewer | Russell Wing + Claude Opus 4.7 |
| Spec | configuration.md (2026-03-12 draft) |
| Passes applied | 1 (Gaps), 2 (Consistency), 3 (Clarity), 4 (Implementability), 5 (Coverage), 6 (Cross-reference integrity) |
| Code cross-checked | `crates/cordelia-core/src/{config.rs, protocol.rs}`, `crates/cordelia-network/src/seen_table.rs` |

---

## Summary

**15 findings: 2 CRITICAL, 5 HIGH, 5 MEDIUM, 3 LOW.**

Configuration.md is the document that is *supposed* to be the canonical
landing place for every shipped parameter, but it has drifted from
both the source specs (parameter-rationale.md, network-protocol.md)
and -- more importantly -- from the shipping code (`crates/cordelia-core/src/config.rs`).

Two categories dominate:

1. **Stale default values.** The documented `[replication]` and
   `[limits]` defaults contradict `protocol.rs` constants and the
   3x-headroom derivation in parameter-rationale.md §4. A new operator
   writing a config.toml against this spec would set values the
   governor code does not enforce.
2. **Sections that ship (or don't ship) contrary to spec.** The
   `[memory]`, `[search]`, and `[trust]` sections are documented with
   full default tables, yet there are no corresponding struct fields
   in `Config`. Conversely, the shipping `[swarm]` section and three
   `CORDELIA_*` env vars are undocumented here. This spec cannot
   currently serve as the canonical reference it claims to be.

Top-line fix before Phase 1 close: reconcile §2.5 replication defaults
and §2.6 rate-limit defaults with protocol.rs and parameter-rationale.md,
and either (a) implement `[memory]`/`[search]` in config.rs or (b)
label them Phase 2 and remove the defaults table.

---

## CRITICAL

### CF-01: Section drift -- `[memory]`, `[search]`, `[trust]` documented but not in code

**Spec**: §2.7 `[memory]`, §2.8 `[search]`; cf. network-protocol.md §12.5 `[trust]`.

**Issue**: configuration.md documents four `[memory]` parameters
(§2.7, lines 146-151), five `[search]` parameters (§2.8, lines 158-163),
and references memory-model.md/search-indexing.md as authoritative
sources. network-protocol.md §12.5 defines a `[trust]` section with
initial_score, recovery rates, decay constants, and thresholds.

None of these exist in `crates/cordelia-core/src/config.rs`:

```rust
pub struct Config {
    pub identity: IdentityConfig,
    pub node: NodeConfig,
    pub network: NetworkConfig,
    pub governor: GovernorConfig,
    pub replication: ReplicationConfig,
    pub limits: LimitsConfig,
    pub api: ApiConfig,
    pub logging: LoggingConfig,
    pub swarm: SwarmConfig,   // not in configuration.md (see CF-02)
}
```

Because of `#[serde(default)]` at the top level, a user who writes
`[memory] l2_quota_mb = 10` gets TOML that parses cleanly -- and is
then silently ignored. There is no `[memory]` field on `Config`, so
the value never reaches the memory subsystem. (Memory-model.md §4.1
and search-indexing.md §7 read these values via their own code paths;
none of them parse config.toml.)

This is the same class of failure as CL-01 in
review-connection-lifecycle-2026-04-17.md: the canonical spec directs
operators to configure behaviour that the binary cannot actually act on.

**Resolution** (either option acceptable):

**Option A (preferred):** Wire these sections up in `Config` now.
Memory and search parameters are referenced in every L1/L2 and
hybrid-search code path; centralising them is minor work and the
plumbing is expected for Phase 2 anyway.

**Option B:** Mark §2.7, §2.8, and the `[trust]` cross-ref as
Phase 2 only, remove the defaults columns, and add a note at §1:
"Sections marked Phase 2 are documented here for forward-compatibility
but are ignored by Phase 1 binaries."

Either way: §5.2 ("Unknown sections or keys: Ignored with a DEBUG-level
log message") must be revisited -- `[memory]` and `[search]` are
currently treated as unknown by `toml::from_str::<Config>` even though
the spec implies they're canonical.

### CF-02: `[swarm]` section shipped in code but undocumented in spec

**Spec**: (missing from §2) vs. `crates/cordelia-core/src/config.rs` lines 130-143.

**Issue**: The shipping binary defines a `[swarm]` section with three
fields (`swarm_index`, `lead_identity_path`, `lead_entity_id`), all
tied to Personal Area Network / agent swarm functionality
(network-protocol.md §8.2.2). `cordelia swarm-init` writes these to
config.toml. They are also env-overridable (`CORDELIA_SWARM_INDEX`,
`CORDELIA_LEAD_IDENTITY_PATH`, `CORDELIA_LEAD_ENTITY_ID`).

configuration.md §2 lists 10 sections and does not mention `[swarm]`.
§4.1's env-var table does not list the three swarm env vars.
An operator reading the "canonical config.toml reference" cannot
configure a swarm child node without reading the source code.

**Resolution**: Add §2.11 `[swarm]` with the three fields, defaults
(all `None`), valid ranges (swarm_index: 0-255 per network-protocol.md
§8.2.2 HKDF derivation), and phase label (Phase 1 -- ships today).
Add the three env vars to §4.1. Cross-ref network-protocol.md §8.2.2
for the Lead/Swarm role model.

---

## HIGH

### CF-03: `sync_interval_realtime_secs` default is stale (60 vs shipping 10)

**Spec**: §2.5 line 115.

**Issue**: Documented default is `60`:

> `sync_interval_realtime_secs` | integer | `60` | > 0 | Anti-entropy
> pull interval for realtime channels (seconds).

Shipping code (protocol.rs line 375):

```rust
pub const REALTIME_SYNC_INTERVAL_SECS: u64 = 2 * REPUSH_INTERVAL_SECS;
// = 2 × 5 = 10
```

config.rs line 208 pulls the default from `protocol::REALTIME_SYNC_INTERVAL_SECS`,
so `ReplicationConfig::default()` ships at 10s, not 60s.

network-protocol.md §12.3 is aware of this: it reads
`sync_interval_realtime_secs = 10   # Phase 1 default (fast convergence).
Production: 60s.` configuration.md has silently collapsed the Phase 1
default and the production target into a single "60" value.

This is the same drift class as the `hot_max=10` regression that
prior waves found in other specs. An implementor trusting this spec
would make sync 6x slower than shipping and break convergence-time
claims in topology-scale.md.

**Resolution**: Change default to `10`, add an explanatory note:

> Default 10s (Phase 1 -- fast convergence for MVP scale testing).
> parameter-rationale.md §4 derives this as 2 × REPUSH_INTERVAL_SECS.
> Production deployments at scale may raise to 60s; the spec places
> no upper bound.

### CF-04: `writes_per_peer_per_minute` default contradicts 3x headroom principle

**Spec**: §2.6 line 132.

**Issue**: Documented default is `10`. Shipping code:

```rust
// protocol.rs line 350
pub const WRITES_PER_PEER_PER_MINUTE: u32 =
    RATE_LIMIT_HEADROOM * (60 / REPUSH_INTERVAL_SECS) as u32;
// = 3 × 12 = 36
```

parameter-rationale.md §4 is explicit: per-peer writes = `3 × (60 / 5) = 36/min`.
The assert at protocol.rs:701 pins it: `assert_eq!(WRITES_PER_PEER_PER_MINUTE, 36)`.
And review-parameter-rationale-2026-04-17.md PR-01 already flagged the
same confusion in parameter-rationale.md -- but resolved it *in favour*
of the 36/min derivation as authoritative.

configuration.md has the wrong value (10 is the "expected rate," not
the enforced limit). A relay configured to allow 10 writes/min would
ban honest peers during bursts.

Note that `config.rs` does NOT expose `writes_per_peer_per_minute` in
`LimitsConfig` (it only has `max_inbound_connections`,
`max_connections_per_ip`, `max_item_bytes`, `writes_per_channel_per_minute`).
The enforced value is the compiled constant, and operators cannot
override it. This is a second bug: the documented override is unreachable.

**Resolution**:
1. Update documented default to `36`, derived from `3 × (60 / REPUSH_INTERVAL_SECS)`.
2. Cross-ref parameter-rationale.md §4 for the derivation.
3. Add a note: "Phase 1 ships this as a compiled constant; override
   via config.toml is deferred to Phase 2" OR add the field to
   `LimitsConfig` so the documented override actually works.

### CF-05: `[limits]` documents many fields that aren't in `LimitsConfig`

**Spec**: §2.6 rows 125-140 (16 parameters).

**Issue**: Shipping `LimitsConfig` has exactly four fields:
`max_inbound_connections`, `max_connections_per_ip`, `max_item_bytes`,
`writes_per_channel_per_minute`. Configuration.md documents 16, including:

- `max_connections_per_subnet`
- `max_streams_per_connection`
- `max_message_bytes`
- `writes_per_peer_per_minute` (see CF-04)
- `max_bytes_per_peer_per_second`
- `max_push_items_per_channel_per_minute`
- `max_relay_fanout_per_second`
- `max_relay_storage_bytes`
- `bootstrap_connections_per_ip_per_hour`
- `probe_interval_secs`
- `probe_timeout_secs`

All 11 of these are silently ignored if placed in config.toml. The
§5.2 "Unknown sections or keys: Ignored with a DEBUG-level log" rule
applies per-field (serde silently consumes unknown fields because of
`#[serde(default)]`), so operators get no feedback.

**Resolution**: Either (a) add these fields to `LimitsConfig` so the
spec matches shipping behaviour, or (b) mark each row with a "Phase"
column (as §2.7 does) and add a note that Phase 1 uses compiled constants
from protocol.rs with override deferred. The current state -- 11
silently-ignored knobs -- is the worst of both worlds.

### CF-06: Governor `[governor]` missing `dial_policy` field in shipping code

**Spec**: §2.4 line 94 (dial_policy documented, default "all").

**Issue**: `GovernorConfig` in config.rs does NOT have a `dial_policy`
field. The three-valued enum (`"all"`, `"relays_only"`, `"trusted_only"`)
documented in §2.4 and referenced throughout network-protocol.md §5.3,
§8.5, §8.6 is not currently configurable.

Secret keepers (§8.5, §12 of network-protocol.md) are spec'd to use
`dial_policy = "trusted_only"` -- but there is no way to set this via
config.toml. The `[[network.trusted_peers]]` array exists in
`NetworkConfig` (not currently documented in configuration.md either),
but the dial policy that *uses* it is hard-coded.

**Resolution**: Add `dial_policy: String` to `GovernorConfig` with
default `"all"`. Spec is correct; code is behind.

### CF-07: Env-var table missing three shipping overrides, claims three unshipped

**Spec**: §4.1 table lines 313-322.

**Issue**: Comparing §4.1 vs. `Config::apply_env_overrides` (config.rs
lines 271-308):

| Variable | In spec | In code |
|----------|---------|---------|
| `CORDELIA_HTTP_PORT` | Y | Y |
| `CORDELIA_P2P_PORT` | Y | Y |
| `CORDELIA_DATA_DIR` | Y | Y |
| `CORDELIA_LOG_LEVEL` | Y | Y |
| `CORDELIA_LOG_FORMAT` | Y | Y |
| `CORDELIA_LISTEN_ADDR` | Y | Y |
| `CORDELIA_BIND_ADDRESS` | Y | Y |
| `CORDELIA_BOOTNODES` | Y | **N** (not parsed) |
| `CORDELIA_MAX_STORAGE` | Y | **N** (not parsed) |
| `CORDELIA_SWARM_INDEX` | **N** | Y |
| `CORDELIA_LEAD_IDENTITY_PATH` | **N** | Y |
| `CORDELIA_LEAD_ENTITY_ID` | **N** | Y |

Two documented overrides don't ship; three shipped overrides are
undocumented. `CORDELIA_BOOTNODES` is the more surprising -- it has
custom format documentation in §4.1 ("comma-separated list of host:port
pairs when used as an environment variable, even though the config
file uses TOML array-of-tables") but that parser doesn't exist.

**Resolution**: Align the table with `apply_env_overrides`. Either
implement the two missing parsers or remove them from the spec.
Add the three swarm env vars (tie into CF-02).

---

## MEDIUM

### CF-08: `QUIC_MAX_BIDI_STREAMS` (1000) vs `max_streams_per_connection` (64) -- two different things, no cross-ref

**Spec**: §2.6 row 129.

**Issue**: The spec lists `max_streams_per_connection = 64`.
parameter-rationale.md §1 lists `max_concurrent_bidi_streams = 1000`.
Both terms refer to QUIC stream limits, but they are *different* values
for *different* purposes:

- protocol.rs:70 `QUIC_MAX_BIDI_STREAMS = 1000` -- what our QUIC endpoint
  advertises as its accept cap (Quinn's `max_concurrent_bidi_streams`).
- protocol.rs:342 `MAX_CONCURRENT_STREAMS = 64` -- a soft per-peer
  resource bound applied inside handlers.

Neither is a user-configurable `[limits]` parameter in shipping code,
but the spec presents `max_streams_per_connection = 64` as a tuneable.
An operator reading configuration.md cannot tell that 1000 is the
QUIC-level setting and 64 is the application-level soft cap, nor that
neither is actually wired through `LimitsConfig`.

**Resolution**: Clarify the two layers. Rename spec field to
`quic_max_bidi_streams` (default 1000) if exposing the QUIC limit, or
add a "QUIC transport" subsection describing both values and which
one applies where. Cross-ref parameter-rationale.md §1.

### CF-09: No validation for negative/zero values on unsigned parameters

**Spec**: §5 Validation.

**Issue**: §5.1/§5.2 specify refuse-to-start behaviour for "out-of-range"
values. The valid-range column in §2 uses `> 0` for most integers,
but TOML integers can be negative and would deserialize into signed
types if the struct were signed. `GovernorConfig` uses `u32`, which
is tolerant -- negative TOML values fail deserialization (parse error,
caught by §5.1 "invalid TOML syntax"). Confirming this would help an
implementer.

However, `churn_fraction: f64` and `ema_alpha: f64` silently accept
0.0, negative values, and values > 1.0. The spec §2.4 rows say
`(0.0, 1.0]` but §5.2 says "out-of-range values ... refuses to start."
There is no actual range check in `GovernorConfig::default()` or in
Config parsing. An implementor reading §5.2 would assume they are
protected; they are not.

**Resolution**: Document this precisely. Either (a) add range
validation to `Config::load` (recommended -- cheap, prevents silent
misconfiguration), or (b) clarify §5.1/§5.2 that bounded-range
parameters are documented but not currently enforced, and list which
parameters have runtime checks.

### CF-10: `[network]` missing documentation for `trusted_peers`, `allow_private_addresses`, `bootstrap_timeout_secs`

**Spec**: §2.3.

**Issue**: `NetworkConfig` ships with three documented-elsewhere fields
that don't appear in configuration.md §2.3:

- `trusted_peers: Vec<TrustedPeerConfig>` -- used by secret keepers
  (§8.5), and by the PAN Lead (§8.2.2) to accept inbound from child
  nodes. network-protocol.md §12.2 shows a commented-out
  `[[network.trusted_peers]]` block.
- `allow_private_addresses: bool` -- enables RFC-1918 addresses in
  peer-sharing, required for Docker/test envs (topology-e2e.md uses it).
- `bootstrap_timeout_secs: u32` -- per-bootnode connection timeout
  during bootstrap. network-protocol.md §12.2 documents this.

**Resolution**: Add all three to §2.3 with defaults
(`trusted_peers = []`, `allow_private_addresses = false`,
`bootstrap_timeout_secs = 10`), valid ranges, and use cases
(trusted_peers: keeper + PAN Lead; allow_private_addresses: testing).

### CF-11: `[memory]` and `[search]` Phase column is inconsistent

**Spec**: §2.7 table, §2.8 table.

**Issue**: §2.7 has a "Phase" column (1 or 2 per row). §2.8 does not.
Both sections are currently Phase 2 per CF-01. If §2.7 is marking phase
because `novelty_threshold` is Phase 2 while the rest is Phase 1, that
intent is defeated by the fact that none of `[memory]` is wired into
shipping Config.

Also: the §2.7 Phase column is unique in this spec. §2.3, §2.4, §2.5,
§2.6 all mix Phase 1 parameters (most) with Phase 2 parameters (some
`[trust]` thresholds, Phase 2 TLS relaxation in §2.9) without per-row
labels.

**Resolution**: Either add Phase columns throughout §2 (for consistency),
or remove from §2.7. Tie to CF-01: if `[memory]` and `[search]` are
Phase 2, label the whole section; don't rely on a per-row column.

### CF-12: `seen_table` parameters not configurable, not documented

**Spec**: (missing from §2).

**Issue**: The epidemic forwarding seen_table is a Phase 1 operational
feature (MEMORY.md, network-protocol.md §7.2 line 1203-1204):

```
SEEN_TABLE_MAX = 10,000
SEEN_TABLE_TTL = 600s
```

network-protocol.md §7.2 says "configurable" but configuration.md does
not document these. They ship as compiled constants in protocol.rs
(lines 417, 422). Three other reviews this wave (parameter-rationale,
connection-lifecycle, network-behaviour) already flagged that these
constants lack config exposure.

This is an operational parameter a relay operator will want to tune
at scale: in a partitioned network a higher SEEN_TABLE_MAX improves
dedup coverage at the cost of memory.

**Resolution**: Add §2.12 `[relay]` or extend §2.6 `[limits]` with
`seen_table_max` (default 10000) and `seen_table_ttl_secs` (default 600).
Cross-ref network-protocol.md §7.2 and parameter-rationale.md (where
PR-04 already flagged this).

---

## LOW

### CF-13: `http_port` and `p2p_port` validity range claims 1-65535 but ports < 1024 need privileges

**Spec**: §2.2 rows 46-47.

**Issue**: Claiming 1-65535 as valid is technically correct but
operationally misleading -- ports < 1024 require root/cap_net_bind_service
on Linux and admin on Windows. Cordelia is designed as a user daemon;
this is an instance where spec-level precision (1-65535) invites
deployment mistakes (binding to 80 or 443 without capabilities).

**Resolution**: Tighten valid range to `1024-65535` for both, with a
note: "Privileged ports (<1024) require elevated capabilities and are
not supported in standard deployments."

### CF-14: No guidance on config.toml in Docker/containerised deployments

**Spec**: §1 mentions "absolute paths in non-interactive deployments
(containers, CI)" but gives no example.

**Issue**: topology-e2e.md specifies Docker deployment patterns that
exercise configuration.md, but configuration.md does not link to
topology-e2e.md or provide container-specific guidance. Operators
building their own images cannot tell from this spec that (a)
`data_dir` should be set to an absolute path, (b) the token file
mount location affects `token_path`, (c) `allow_private_addresses`
is needed for bridge networks.

**Resolution**: Add a §8 "Deployment Profiles" section with three
profiles: Personal laptop (defaults OK), Relay server (role=relay,
systemd, tuned limits), Docker (absolute paths, allow_private_addresses).
Or simply cross-ref topology-e2e.md and operations.md SS2.1 (container
entrypoint).

### CF-15: Hot-reload statement ("No hot reload") is correct but lacks rationale and Phase 2 path

**Spec**: §1 line 17.

**Issue**: The spec correctly states no hot reload, and mentions
"Phase 2 evaluates SIGHUP-triggered reload for select parameters."
Not all parameters can safely hot-reload (changing `hot_max` mid-run
would require synchronous governor re-evaluation; changing `listen_addr`
would require restarting Quinn endpoints). A future Phase 2 spec will
need to classify parameters by reloadability.

**Resolution**: Add a "Reloadability" column to §2 tables, marking
each parameter as R (hot-reloadable, Phase 2), C (connection-reset
required), or N (restart required). This is cheap to add now and
primes Phase 2 design. Alternatively, defer to Phase 2 planning and
leave §1 as-is.

---

## Configuration-specific pass summary

| Check | Finding |
|-------|---------|
| Defaults verification | **FAIL** -- 3 drifts (CF-03, CF-04, CF-05). Shipping defaults contradict documented defaults for replication, per-peer writes, many limits. |
| Validation coverage | **PARTIAL** -- CF-09. §5.2 claims strict behaviour but range checks not implemented for bounded floats. |
| Env-var vs file precedence | **PASS** -- §4.3 clearly states `CLI > env > file > compiled`. Covered. |
| Env-var catalog accuracy | **FAIL** -- CF-07. 2 phantom entries, 3 missing. |
| Hot-reload semantics | **PARTIAL** -- CF-15. Correct but no Phase 2 roadmap. |
| Deployment profile coverage | **WEAK** -- CF-14. No container/relay/keeper profiles. Personal is implicit. |
| Schema sections in code | **FAIL** -- CF-01, CF-02, CF-10. 3 sections documented but not in `Config`; 1 section shipping but undocumented; 3 `NetworkConfig` fields undocumented. |

---

## Passes Not Applied (this session)

| Pass | Reason |
|------|--------|
| 7 (Terminology) | Already covered by glossary.md; no new terms introduced. |
| 8+ (Privacy, Ops, Errors, Test Vectors) | Configuration.md has no surface for these passes. |

---

## Recommended Triage

**Fix before Phase 1 close:**

- **CF-01** (Memory/Search/Trust sections not wired up): pick option A or B; today a documented knob silently fails.
- **CF-02** (swarm section undocumented): ships today, operators need it.
- **CF-03, CF-04** (stale defaults): same class as hot_max=10 drift from prior waves. Single-line fixes.
- **CF-07** (env-var drift): trivial to align.

**Fix during Phase 2 prep:**

- CF-05, CF-06, CF-09, CF-10 -- all require design decisions about
  which knobs graduate from compiled constants to runtime config.
- CF-11 -- consistency pass across §2 tables.
- CF-12 -- adds seen_table knobs for relay operators at scale.

**Nice to have:**

- CF-08, CF-13, CF-14, CF-15 -- documentation polish, no correctness
  implications.

---

## Top 2 Issues (short form for parent agent)

1. **CF-01**: `[memory]`, `[search]`, `[trust]` sections are
   documented here as canonical but do not exist in shipping
   `Config` struct. Operators setting them get silent failure.
2. **CF-03 + CF-04**: `sync_interval_realtime_secs` default is
   documented as 60 but ships as 10; `writes_per_peer_per_minute`
   documented as 10 but enforced as 36 (via 3x headroom). Same drift
   class as prior waves' `hot_max=10` finding.

---

*Review complete 2026-04-17.*
