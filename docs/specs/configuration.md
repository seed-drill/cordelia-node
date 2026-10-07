# Configuration Reference

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-12
**Scope**: Phase 1 (Encrypted Pub/Sub MVP)
**Canonical for**: All `config.toml` parameters across all specs

> **v1 status.** The default bootnodes (`FALLBACK_PEERS`) are
> the two relays, `relay1` and `relay2.cordelia.seeddrill.ai:9474`. QUIC binds
> to the host part of `listen_addr` (a host name is resolved) on `p2p_port`.
> A personal node does not listen: it dials out from a port the system picks
> on that host address, and `p2p_port` is unused unless `listen` is set
> (§2.2).
> The sync adapter's settings are not in this file: `cordelia sync claude`
> and `cordelia sync map` store them in the node's database. The `[memory]`
> and `[search]` sections (§2.7, §2.8) belong to archived specs
> ([`docs/archive/`](../archive/README.md)), and the `keeper` role is deferred
> ([decision record of 2026-09-30](../decisions/2026-09-30-agent-memory-sync.md)).
>
> Per the [decision record of 2026-10-04](../decisions/2026-10-04-a-persons-devices.md):
>
> - **Nothing of a person's devices is in this file.** The recovery phrase is
>   never stored anywhere. What a device follows, the person secret and the
>   statement it has applied are in the node's database (data-formats.md
>   §10.3), and the device's own key is in `identity.key`.
> - **A personal node carries no channel of the older kind.** `push_policy`
>   (§2.3) and `[replication]` (§2.5) are settings of that kind, and change
>   nothing that a personal node does with its own channels. Those are
>   fetched every 10 seconds and sent every 2, which are constants of
>   `protocol.rs` and not settings.
> - **A relay's `max_storage_bytes` bounds each kind of channel apart**
>   (§2.2), and **a relay that lists another by `key` works together with
>   it** (§2.3).
> - **The data directory of a personal node** also holds, after its first
>   start on this version, a folder `before-<version>`: a copy of the
>   database and of the key files of the older channels, as they were
>   (operations.md §10.5).

---

## 1. File Location and Format

- **Path**: `~/.cordelia/config.toml`
- **Format**: [TOML v1.0](https://toml.io/en/v1.0.0)
- **Created by**: `cordelia init` (operations.md SS2)
- **Editable**: Yes, manually. Changes take effect on node restart.
- **No hot reload.** The node reads `config.toml` once at startup. Changes to the file while the node is running have no effect until restart. Phase 2 evaluates SIGHUP-triggered reload for select parameters.
- **All parameters have defaults** -- a minimal (empty) config file is valid. `cordelia init` writes a complete config with defaults for reference.
- **Tilde expansion**: `~` is expanded to the user's home directory at startup. Environment variables (`$HOME`) are NOT expanded in config.toml values. Use absolute paths in non-interactive deployments (containers, CI).

Override path with the `--config` CLI flag:

```bash
cordelia start --config /etc/cordelia/config.toml
```

---

## 2. Sections

### 2.1 `[identity]`

Identity parameters. Written by `cordelia init`, generally not edited manually.

| Parameter | Type | Default | Description | Source |
|-----------|------|---------|-------------|--------|
| `entity_id` | string | Derived from public key | Human-readable entity name (e.g., `russwing_a1b2`). Informational only -- the Ed25519 public key is the canonical identity. | operations.md SS2.5, network-protocol.md SS12.1 |
| `public_key` | string | Generated at init | Ed25519 public key, Bech32-encoded (`cordelia_pk1...`). Read-only -- changing this has no effect (derived from `identity.key`). | operations.md SS2.3, network-protocol.md SS12.1 |

### 2.2 `[node]`

Core node settings: ports, storage location, storage quota.

| Parameter | Type | Default | Valid Range | Description | Source |
|-----------|------|---------|-------------|-------------|--------|
| `http_port` | integer | `9473` | 1-65535 | REST API port (TCP, localhost only). | operations.md SS5.1 |
| `p2p_port` | integer | `9474` | 1-65535 | P2P transport port (UDP, QUIC). | operations.md SS5.1 |
| `data_dir` | string | `"~/.cordelia"` | Valid directory path | Base data directory. Tilde expanded at startup. Created automatically if it does not exist (with mode 0700). | operations.md SS5.1 |
| `max_storage_bytes` | integer | `1073741824` (1 GB) | > 0 | The most a relay may hold of each kind of channel. The older kind and the channels from their secrets are each counted against a cap of this size, so for the one version that carries both a relay can hold twice this. Each is counted by what its entries are counted at (an entry's content and 1 KB), and not by the database's pages. At a cap a relay takes no channel of that kind which it does not already hold; over it, it drops the channels of that kind that it has held for the shortest time (decision 2026-09-30 §4.6; decision 2026-10-04 §2.5). It is read when the node starts. Not applied on a personal node. | operations.md SS5.1 |

### 2.3 `[network]`

P2P networking: listen address, node role, push policy, bootnode addresses, DNS discovery.

| Parameter | Type | Default | Valid Values | Description | Source |
|-----------|------|---------|--------------|-------------|--------|
| `listen_addr` | string | `"0.0.0.0:9474"` | `<ip>:<port>` | P2P listen address (UDP, QUIC). | operations.md SS5.1, network-protocol.md SS12.2 |
| `listen` | boolean | unset | `true`, `false` | Whether to accept inbound connections. Unset: every role listens except `personal`, which only dials out and opens no listening socket (it still listens if it has `trusted_peers`). Set `true` on a personal node that others dial directly, such as a swarm lead. | decision 2026-09-30 §4.6 |
| `role` | string | `"personal"` | `"personal"`, `"bootnode"`, `"relay"`, `"keeper"` | Node role. Affects governor targets, push behaviour, and relay/bootstrap duties. A personal node never becomes a relay by default -- operators must set this explicitly. | network-protocol.md SS8, SS12.2 |
| `push_policy` | string | `"subscribers_only"` | `"subscribers_only"`, `"pull_only"` | Push behaviour for personal nodes. `subscribers_only`: push items to hot peers subscribed to the channel. `pull_only`: never push; peers must pull via Item-Sync. Trade-off: `pull_only` increases latency (bounded by `replication.sync_interval_realtime_secs`). | network-protocol.md SS8.1.1, SS12.2 |
| `dns_discovery` | string | `""` | any | **No longer used (2026-10-02).** A node learns of no relay from DNS: its relays are the ones it is configured with. The setting is still read, so that older configurations load. | decision 2026-09-30 §4.6 |

**Port precedence:** If both `node.p2p_port` and `network.listen_addr` are set, the port in `listen_addr` MUST match `p2p_port`. If they disagree, the node logs an error and refuses to start. If only `node.p2p_port` is set, `listen_addr` defaults to `0.0.0.0:<p2p_port>`. If only `listen_addr` is set, `p2p_port` is derived from it. This ensures a single source of truth for the P2P port.

**Bootnodes** are specified using TOML array-of-tables syntax (per network-protocol.md SS12.2):

```toml
[[network.bootnodes]]
addr = "relay1.cordelia.seeddrill.ai:9474"

[[network.bootnodes]]
addr = "relay.example.org:9474"
key = "cordelia_pk1..."
```

| Parameter | Type | Default | Description | Source |
|-----------|------|---------|-------------|--------|
| `addr` | string | (required) | The relay's address as `<hostname>:<port>`. With none configured, a personal node uses the two default relays. | decision 2026-09-30 §4.6 |
| `key` | string | unset | The relay's public key (`cordelia_pk1...`, as `cordelia id` prints on the relay). When set, any other key answering at `addr` is refused. The default relays' keys are compiled in and need not be given. Without a key, whichever node answers is accepted, and the node warns at start. A key that does not parse stops the node from starting. **On a relay, a relay listed with its key is one it works together with:** the two pass the entries of channels from their secrets between them without the proof, tell each other which channels they hold, and are not counted against each other's limits. A relay listed by address alone is not one for that: whoever came from that address would be handed every channel. | decision 2026-09-30 §4.6; decision 2026-10-04 §2.4, item 6 |

**Contradiction resolved:** operations.md SS5.1 uses a flat string array (`bootnodes = ["host:port", ...]`) and places governor parameters under `[network]`. network-protocol.md SS12.2 uses `[[network.bootnodes]]` array-of-tables and places governor parameters under `[governor]`. This document follows network-protocol.md SS12.2 as canonical: bootnodes use array-of-tables (extensible for future fields like `role`, `priority`), and governor parameters live under `[governor]` (SS2.4 below).

### 2.4 `[governor]`

Peer governor targets and timing. Controls how the node manages its peer set across Hot, Warm, and Cold states.

Defaults match the Personal Node profile (network-protocol.md SS8.6). Override for Relay, Bootnode, or Secret Keeper roles.

| Parameter | Type | Default | Valid Range | Description | Source |
|-----------|------|---------|-------------|-------------|--------|
| `hot_min` | integer | `2` | >= 1 | Minimum hot peers. Below this, promote aggressively (bypass tenure guard). | SS5.3, SS5.4, SS8.6 |
| `hot_max` | integer | `2` | >= `hot_min` | Maximum hot peers. Above this, demote worst-scoring. | SS5.3, SS8.6 |
| `hot_min_relays` | integer | `1` | <= `hot_max` | Minimum relay peers in hot set. Ensures relay backbone connectivity. Independent target from `hot_min`. | SS5.3, SS5.4 step 4a, SS8.6 |
| `warm_min` | integer | `3` | >= `hot_min` (exempt for `trusted_only`) | Minimum warm peers. Below this, connect cold peers. | SS5.3, SS8.6 |
| `warm_max` | integer | `10` | >= `warm_min` | Maximum warm+hot peers. | SS5.3, SS8.6 |
| `cold_max` | integer | `50` | >= `warm_max` (exempt for `trusted_only`) | Maximum cold (known, not connected) peers. | SS5.3, SS8.6 |
| `dial_policy` | string | `"all"` | `"all"`, `"relays_only"`, `"trusted_only"` | Controls which peers the governor connects to. `trusted_only` for secret keepers. | SS5.3, SS8.5, SS8.6 |
| `tick_interval_secs` | integer | `10` | >= 1 | Governor tick interval. Each tick evaluates promotions, demotions, and churn. | SS5.4, SS12.2 |
| `churn_interval_secs` | integer | `3600` | > 0 | Base churn interval. Warm peers swapped with cold to prevent topology ossification. | SS5.4, SS12.2 |
| `churn_jitter_secs` | integer | `300` | >= 0 | Random jitter added to churn interval (0 to this value). Prevents correlated churn across nodes. | SS5.4, SS12.2 |
| `churn_fraction` | float | `0.2` | (0.0, 1.0] | Fraction of warm peers swapped per churn cycle. | SS5.4, SS12.2 |
| `min_warm_tenure_secs` | integer | `300` | >= 60 | Minimum warm time before Hot promotion. Anti-Sybil guard. Bypassed when `hot < hot_min`. | SS5.4, SS12.2 |
| `hysteresis_secs` | integer | `90` | >= `tick_interval_secs` | Cooldown after demotion before re-promotion. | SS5.4, SS12.2 |
| `keepalive_timeout_secs` | integer | `90` | >= 60 | Dead detection threshold. No keepalive for this duration triggers demotion. | SS5.4, SS12.2 |
| `stale_threshold_secs` | integer | `1800` | > 0 | No items for this duration = priority demotion during Hot overflow. | SS5.4, SS12.2 |
| `ema_alpha` | float | `0.1` | (0.0, 1.0] | EMA decay for peer scoring. Lower = smoother, slower adaptation. | SS5.5, SS12.2 |
| `max_connection_retries` | integer | `5` | >= 1 | Stop connecting after this many consecutive failures. | SS5.4, SS12.2 |
| `clear_failure_delay_secs` | integer | `120` | > 0 | Clear failure count after being Hot for this long. | SS5.4, SS12.2 |

**Contradiction resolved:** operations.md SS5.1 placed `hot_max`, `hot_min`, `warm_max`, `warm_min`, `cold_max` under `[network]` with a comment noting they belong under `[governor]`. This document uses `[governor]` as canonical (per network-protocol.md SS12.2). The `[network]` section no longer contains governor parameters.

### 2.5 `[replication]`

Anti-entropy sync intervals, tombstone retention, and batch sizing for the Item-Sync protocol.

| Parameter | Type | Default | Valid Range | Description | Source |
|-----------|------|---------|-------------|-------------|--------|
| `sync_interval_realtime_secs` | integer | `10` | > 0 | Anti-entropy pull interval for realtime channels (seconds): `REALTIME_SYNC_INTERVAL_SECS` in `protocol.rs`, twice the interval at which a relay passes on what it took. Items also arrive via push, so this is a consistency backstop. | network-protocol.md SS12.3 |
| `sync_interval_batch_secs` | integer | `900` | > 0 | Anti-entropy pull interval for batch channels (seconds). 15 minutes default. | network-protocol.md SS12.3 |
| `tombstone_retention_days` | integer | `7` | > 0 | Days to retain tombstoned items before physical deletion. Must be long enough for all peers to observe the tombstone. | network-protocol.md SS12.3 |
| `max_batch_size` | integer | `100` | 1-10000 | Maximum items per FetchRequest/PushPayload message. | network-protocol.md SS9.2, SS12.3 |
| `relay_ask_again_secs` | integer | `600` | 1-86400 (a value outside is taken as the nearest) | Relays only. How long a relay waits before it asks a device again which channels it holds, and before it takes again a channel it dropped to make room. | parameter-rationale.md SS4 |

> **v1 status.** The defaults are those of `ReplicationConfig` in
> `crates/cordelia-core/src/config.rs`, each a constant of `protocol.rs`. Of
> this section a node acts on `relay_ask_again_secs` alone. Its pull runs
> every `REALTIME_SYNC_INTERVAL_SECS` (10 seconds) whatever
> `sync_interval_realtime_secs` is set to, and the other three keys are read
> from the file and used by nothing.

### 2.6 `[limits]`

Rate limiting and resource caps. Protects against DoS, Sybil attacks, and storage exhaustion.

| Parameter | Type | Default | Valid Range | Description | Source |
|-----------|------|---------|-------------|-------------|--------|
| `max_inbound_connections` | integer | `200` | > 0 | Maximum total inbound QUIC connections. | network-protocol.md SS12.4 |
| `max_connections_per_ip` | integer | `5` | > 0 | Maximum connections from a single IP address. | network-protocol.md SS12.4 |
| `max_connections_per_subnet` | integer | `20` | > 0 | Maximum connections from a single /24 subnet. | network-protocol.md SS12.4 |
| `max_streams_per_connection` | integer | `64` | > 0 | Maximum concurrent QUIC streams per connection. | network-protocol.md SS12.4 |
| `max_item_bytes` | integer | `65536` (64 KB) | > 0 | Maximum size of a single item in bytes, as it travels. The limit is compiled in (`MAX_ITEM_BYTES`) and checked by the sender, each relay and the receiving device; this setting is not read. | network-protocol.md SS9.2, SS12.4 |
| `max_message_bytes` | integer | `1048576` (1 MB) | > 0 | Maximum wire message size. Messages exceeding this are rejected and the stream is reset. | network-protocol.md SS3.1, SS12.4 |
| `writes_per_peer_per_minute` | integer | `10` | > 0 | Maximum writes accepted from a single peer per minute. | network-protocol.md SS12.4 |
| `writes_per_channel_per_minute` | integer | `100` | > 0 | Maximum writes per channel per minute (aggregate across all peers). | network-protocol.md SS12.4 |
| `max_bytes_per_peer_per_second` | integer | `10485760` (10 MB/s) | > 0 | Maximum bandwidth per peer per second. | network-protocol.md SS16.4, SS12.4 |
| `max_push_items_per_channel_per_minute` | integer | `1000` | > 0 | Maximum push items per channel per minute. | network-protocol.md SS16.4, SS12.4 |
| `max_relay_fanout_per_second` | integer | `100` | > 0 | Relay re-push rate cap (items per second). Only relevant for relay nodes. | network-protocol.md SS16.4, SS12.4 |
| `max_relay_storage_bytes` | integer | `10737418240` (10 GB) | > 0 | Relay cache size limit. Only relevant for relay nodes. | network-protocol.md SS16.3, SS12.4 |
| `bootstrap_connections_per_ip_per_hour` | integer | `5` | > 0 | Bootnode rate limit: max bootstrap connections per source IP per hour. Only relevant for bootnode nodes. | network-protocol.md SS16.2.1, SS12.4 |
| `probe_interval_secs` | integer | `300` | > 0 | Relay health probe interval in seconds. | network-protocol.md SS16.1.2, SS12.4 |
| `probe_timeout_secs` | integer | `60` | > 0 | Probe delivery timeout in seconds. | network-protocol.md SS16.1.2, SS12.4 |

### 2.7 `[memory]`

Memory model parameters: L2 storage quota, prefetch budget, expiry sweep, and novelty filtering.

| Parameter | Type | Default | Valid Range | Phase | Description | Source |
|-----------|------|---------|-------------|-------|-------------|--------|
| `l2_quota_mb` | integer | `5` | > 0 | 1 | L2 soft quota per channel in megabytes. At 90%, a warning is logged. At 100%, oldest interrupt-domain items are tombstoned to reclaim space. | memory-model.md SS4.1 |
| `prefetch_budget_bytes` | integer | `51200` (50 KB) | > 0 | 1 | Maximum total UTF-8 byte length of decrypted L2 content fetched during session prefetch. Value-domain items are capped at 20 most recently updated. If total exceeds budget, items ranked by `updated_at` descending and truncated. | memory-model.md SS7.3 |
| `sweep_interval_hours` | integer | `24` | 1-168 | 1 | Hours between expiry sweep runs. Sweep is also triggered on session start. Idempotent and safe to run concurrently. | memory-model.md SS8.5 |
| `novelty_threshold` | float | `0.3` | 0.0-1.0 | 2 | Minimum novelty score for automatic memory writes. Candidates below this are not persisted. Phase 1 explicit writes are always persisted regardless of this threshold. | memory-model.md SS8.4 |

### 2.8 `[search]`

Search tuning parameters for hybrid FTS5 + vector similarity scoring.

| Parameter | Type | Default | Valid Range | Description | Source |
|-----------|------|---------|-------------|-------------|--------|
| `dominant_weight` | float | `0.7` | 0.5-0.9 | Weight for the dominant signal in hybrid search scoring. Formula: `score = dominant_weight * max(semantic, keyword) + (1 - dominant_weight) * min(semantic, keyword)`. The stronger signal leads per-result. | search-indexing.md SS7, memory-model.md SS7.2 |
| `embedding_model` | string | `"nomic-embed-text-v1.5"` | Any Ollama model name | Embedding model identifier. Must be available via Ollama when `embedding_enabled = true`. | search-indexing.md SS7 |
| `ollama_url` | string | `"http://localhost:11434"` | URL | Ollama API base URL for embedding generation. | search-indexing.md SS7 |
| `embedding_enabled` | boolean | `true` | `true` / `false` | Enable semantic search and embedding generation. Set to `false` on machines without Ollama or GPU. When `false`, search uses FTS5 only. | search-indexing.md SS7 |
| `embedding_queue_size` | integer | `1000` | 100-10000 | Maximum pending embedding requests in the in-process queue. Items beyond this limit are deferred to backfill. | search-indexing.md SS7 |

### 2.9 `[api]`

REST API binding and authentication.

| Parameter | Type | Default | Valid Range | Description | Source |
|-----------|------|---------|-------------|-------------|--------|
| `bind_address` | string | `"127.0.0.1"` | `127.0.0.1` or `::1` | REST API bind address. MUST be `127.0.0.1` or `::1`, written so. A name is not taken, `localhost` included (up to 0.2.0-alpha.6 it was): what a name stands for is asked again by whatever binds or connects. With any other value the node refuses to start, and a command refuses to ask it: a command's request carries the node's token. Phase 2 adds TLS for non-loopback binding. | operations.md SS5.4, network-protocol.md SS12.2 |
| `token_path` | string | `"~/.cordelia/node-token"` | Valid file path | Path to the bearer token file for HTTP API authentication. Tilde expanded at startup. | operations.md SS5.1 |

**Note:** network-protocol.md SS12.2 includes `api_addr` (combining address and port) under `[network]`. operations.md SS5.1 splits this into `api.bind_address` and `node.http_port`. This document follows the split form: bind address under `[api]`, port under `[node]`, as this is more granular and allows independent overrides via environment variables.

### 2.10 `[logging]`

Log output configuration: level, format, rotation.

| Parameter | Type | Default | Valid Values | Description | Source |
|-----------|------|---------|--------------|-------------|--------|
| `level` | string | `"info"` | `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"` | Log verbosity. See operations.md SS6.1 for level semantics. | operations.md SS5.1 |
| `format` | string | `"text"` | `"text"`, `"json"` | Log output format. `text` is human-readable; `json` is structured for log aggregation. | operations.md SS5.1 |
| `output` | string | `"stderr"` | `"stderr"`, `"stdout"`, or file path | Log destination. When set to a file path, rotation is enabled. When set to stderr (default), rely on the system service manager for log management. | operations.md SS5.1 |
| `file_max_bytes` | integer | `10485760` (10 MB) | > 0 | Maximum log file size before rotation. Only applicable when `output` is a file path. | operations.md SS5.1 |
| `file_max_count` | integer | `5` | > 0 | Number of rotated log files to retain. Naming: `cordelia.log`, `cordelia.log.1`, ..., `cordelia.log.N`. Oldest file deleted when count exceeded. | operations.md SS5.1 |

---

### 2.11 `[history]`

Local history: the text of a memory file as it was before sync replaced or removed it (decision 2026-09-30 §4.5b). Read when the node starts.

| Parameter | Type | Default | Valid Range | Phase | Description | Source |
|-----------|------|---------|-------------|-------|-------------|--------|
| `days` | integer | `30` | >= 0 | 1 | How long a kept text stays. `0` turns history off and removes what is kept. | parameter-rationale.md §10 |
| `max_bytes` | integer | `268435456` (256 MB) | >= 0 | 1 | The most that is kept. Over it, the oldest records go first. | parameter-rationale.md §10 |

Both bounds are applied when the node starts, every hour that the machine is awake, and at the end of a sync cycle once more than an eighth of `max_bytes` has been kept since they were last applied. Between two of those the store can hold more than `max_bytes`. A record larger than `max_bytes` goes the next time, and with `max_bytes = 0` nothing stays past it: texts are still kept before each change, and are there to restore only until then.

## 3. Example Configuration

A complete annotated `config.toml` with all sections and default values:

```toml
# ~/.cordelia/config.toml
# Generated by: cordelia init
# All parameters shown with their default values.

# --- Identity ---
# Written by cordelia init. Generally not edited manually.
[identity]
entity_id = "russwing_a1b2"               # Informational, derived from public key
public_key = "cordelia_pk1..."             # Ed25519 public key (Bech32, read-only)

# --- Node ---
[node]
http_port = 9473                           # REST API port (TCP, localhost only)
p2p_port = 9474                            # P2P transport port (UDP, QUIC)
data_dir = "~/.cordelia"                   # Base data directory (~ expanded at startup)
max_storage_bytes = 1073741824             # 1 GB local storage limit

# --- Network ---
[network]
listen_addr = "0.0.0.0:9474"              # P2P listen address (UDP, QUIC)
role = "personal"                          # "personal" | "bootnode" | "relay" | "keeper"
push_policy = "subscribers_only"           # "subscribers_only" | "pull_only"

# Relays: where to dial, and the key that must answer there. The default
# relays' keys are compiled in.
[[network.bootnodes]]
addr = "relay1.cordelia.seeddrill.ai:9474"

[[network.bootnodes]]
addr = "relay2.cordelia.seeddrill.ai:9474"

# --- Governor ---
# Peer management targets and timing. Controls Hot/Warm/Cold peer lifecycle.
# Defaults match Personal Node profile (network-protocol.md SS8.6).
# See SS8.6 for Relay, Bootnode, and Secret Keeper profiles.
[governor]
hot_min = 2                                # Below this, promote aggressively
hot_max = 2                                # Above this, demote worst-scoring
hot_min_relays = 1                         # Minimum relay peers in hot set
warm_min = 3                               # Below this, connect cold peers
warm_max = 10                              # Maximum warm+hot peers
cold_max = 50                              # Maximum known peer addresses
dial_policy = "all"                        # "all" | "relays_only" | "trusted_only"
tick_interval_secs = 10                    # Governor tick interval
churn_interval_secs = 3600                 # Base churn interval (1 hour)
churn_jitter_secs = 300                    # Random jitter on churn interval
churn_fraction = 0.2                       # Fraction of warm peers swapped per cycle
min_warm_tenure_secs = 300                 # Minimum warm time before Hot promotion (5 min)
hysteresis_secs = 90                       # Cooldown after demotion
keepalive_timeout_secs = 90                # Dead detection threshold
stale_threshold_secs = 1800                # No items for 30 min = priority demotion
ema_alpha = 0.1                            # Peer scoring EMA decay
max_connection_retries = 5                 # Stop connecting after this many failures
clear_failure_delay_secs = 120             # Clear failure count after being Hot for this long

# --- Replication ---
[replication]
sync_interval_realtime_secs = 10           # Anti-entropy interval for realtime channels
sync_interval_batch_secs = 900             # Anti-entropy interval for batch channels (15 min)
tombstone_retention_days = 7               # Days to keep tombstones
max_batch_size = 100                       # Items per FetchRequest/PushPayload
relay_ask_again_secs = 600                 # A relay asks its devices what they hold this often

# --- Rate Limits ---
[limits]
max_inbound_connections = 200              # Total inbound QUIC connections
max_connections_per_ip = 5                 # Connections per IP
max_connections_per_subnet = 20            # Connections per /24 subnet
max_streams_per_connection = 64            # QUIC streams per connection
max_item_bytes = 65536                     # 64 KB per item
max_message_bytes = 1048576                # 1 MB per wire message
writes_per_peer_per_minute = 10            # Per-peer write rate
writes_per_channel_per_minute = 100        # Per-channel write rate (aggregate)
max_bytes_per_peer_per_second = 10485760   # 10 MB/s per peer bandwidth cap
max_push_items_per_channel_per_minute = 1000  # Push rate per channel
max_relay_fanout_per_second = 100          # Relay re-push rate cap
max_relay_storage_bytes = 10737418240      # 10 GB relay cache
bootstrap_connections_per_ip_per_hour = 5  # Bootnode connection rate limit
probe_interval_secs = 300                  # Relay health probe interval
probe_timeout_secs = 60                    # Probe delivery timeout

# --- Memory ---
[memory]
l2_quota_mb = 5                            # L2 soft quota per channel (MB)
prefetch_budget_bytes = 51200              # Session prefetch budget (50 KB)
sweep_interval_hours = 24                  # Expiry sweep interval (hours, range 1-168)
novelty_threshold = 0.3                    # Phase 2: minimum novelty for auto-writes (0.0-1.0)

# --- Search ---
[search]
dominant_weight = 0.7                      # Hybrid search dominant signal weight (0.5-0.9)
embedding_model = "nomic-embed-text-v1.5"   # Ollama model for embeddings
ollama_url = "http://localhost:11434"        # Ollama API endpoint
embedding_enabled = true                     # false = FTS5-only search
embedding_queue_size = 1000                  # Pending embedding request cap

# --- API ---
[api]
bind_address = "127.0.0.1"                # MUST be 127.0.0.1 or ::1 (any other = refuse to start)
token_path = "~/.cordelia/node-token"      # Bearer token file path

# --- Logging ---
[logging]
level = "info"                             # trace | debug | info | warn | error
format = "text"                            # text | json
output = "stderr"                          # stderr | stdout | file path
file_max_bytes = 10485760                  # 10 MB per log file (when output = file)
file_max_count = 5                         # Rotated log files to retain

# --- Local history ---
[history]
days = 30                                  # How long a replaced text is kept (0 = off, and removes what is kept)
max_bytes = 268435456                      # 256 MB; over it the oldest records go first
```

---

## 4. Environment Variable Overrides

Environment variables override `config.toml` values. All use the `CORDELIA_` prefix but one: `RUST_LOG`, where it is set to one that can be read, is the node's log filter in place of `logging.level`.

### 4.1 Supported Overrides

| Variable | Overrides | Example | Source |
|----------|-----------|---------|--------|
| `CORDELIA_HTTP_PORT` | `node.http_port` | `9473` | operations.md SS5.2 |
| `CORDELIA_P2P_PORT` | `node.p2p_port` | `9474` | operations.md SS5.2 |
| `CORDELIA_DATA_DIR` | `node.data_dir` | `/data/cordelia` | operations.md SS5.2 |
| `CORDELIA_LOG_LEVEL` | `logging.level` | `debug` | operations.md SS5.2 |
| `CORDELIA_LOG_FORMAT` | `logging.format` | `json` | operations.md SS5.2 |
| `CORDELIA_LISTEN_ADDR` | `network.listen_addr` | `0.0.0.0:9474` | operations.md SS5.2 |
| `CORDELIA_BIND_ADDRESS` | `api.bind_address` | `127.0.0.1` | operations.md SS5.2 |

No variable sets the relays (`network.bootnodes`) or the role: those are read from the file alone. Which file that is can be set: the binary takes `CORDELIA_CONFIG` for the path of the configuration, where `--config` is not given. The node also reads `CORDELIA_SWARM_INDEX`, `CORDELIA_LEAD_IDENTITY_PATH` and `CORDELIA_LEAD_ENTITY_ID`, for the swarm settings from before v1.

See SS4.2 for SDK-specific variables (`CORDELIA_TOKEN`).

### 4.2 SDK Environment Variables

The SDK (`@seeddrill/cordelia`) uses a separate variable for API token discovery (sdk-api-reference.md SS8):

| Variable | Purpose | Priority |
|----------|---------|----------|
| `CORDELIA_TOKEN` | Bearer token for SDK to authenticate with the node API | After explicit constructor arg, before file-based discovery (`~/.cordelia/node-token`) |

### 4.3 Precedence Order

```
CLI flags  >  Environment variables  >  config.toml  >  Compiled defaults
```

For the SDK token specifically:

```
Constructor arg  >  CORDELIA_TOKEN env var  >  ~/.cordelia/node-token file
```

---

## 5. Validation

### 5.1 Startup Validation

The node validates configuration at startup. Invalid configuration prevents the node from starting (exit code 3, per operations.md SS4.7).

**Hard errors (node refuses to start):**

| Condition | Error |
|-----------|-------|
| `api.bind_address` is neither `127.0.0.1` nor `::1` (SS2.9) | `the node's API address is set to '...'`, with the two it may be and where it is set |
| `config.toml` contains invalid TOML syntax | `config parse error` |
| Key files (`identity.key`, `node-token`, `channel-keys/*.key`) are world-readable (mode & 0044 != 0) | `permission denied on key file` |
| `node.http_port` or `node.p2p_port` already in use | `address already in use` |
| `node.http_port` == `node.p2p_port` | `port conflict: HTTP and P2P ports must differ` |

**Warnings (node starts, logs warning):**

| Condition | Warning |
|-----------|---------|
| Key file permissions are not exactly 0600 (group-readable but not world-readable, e.g., mode 0640) | `file permissions too open` |
| `l2_quota_mb` quota at 90% | `L2 quota warning` |

### 5.2 Invalid Value Behaviour

- **Out-of-range values for bounded parameters** (e.g., `dominant_weight = 1.5`): Node logs an error and refuses to start. It does NOT silently fall back to defaults -- this prevents operators from running with unexpected configuration.

  **Note:** This strict behaviour applies to ALL bounded parameters across all sections. If other specs describe lenient behaviour (e.g., clamping to valid range), this document takes precedence. Lenient validation may apply only when documented as a specific exception in the parameter's table entry.

- **Unknown sections or keys**: Ignored with a DEBUG-level log message. This supports forward-compatibility (newer config files read by older binaries).
- **Missing sections**: All sections are optional. Missing sections use compiled defaults for all parameters in that section.
- **Missing parameters within a section**: Missing parameters use their compiled defaults. Partial sections are valid.

### 5.3 Required vs Optional Parameters

All parameters are optional. The only hard requirement is that the config file, if present, must be valid TOML. An empty file is valid and produces a fully functional node with default settings.

The `identity.entity_id` and `identity.public_key` fields are written by `cordelia init` and are effectively required for a functioning node, but they are generated, not user-supplied.

### 5.4 Security Constraints

These are hard invariants enforced at startup (operations.md SS5.4, network-protocol.md SS12.2):

1. **API loopback binding**: `api.bind_address` MUST be `127.0.0.1` or `::1` (SS2.9). With any other value the node refuses to start, and says why. Phase 2 adds TLS and permits non-loopback binding.

2. **Key file permissions**: Files at `~/.cordelia/identity.key`, `~/.cordelia/node-token`, and `~/.cordelia/channel-keys/*.key` MUST have mode 0600. The node warns on startup if permissions are too open and MUST refuse to start if key files are world-readable.

3. **Data directory permissions**: `~/.cordelia` SHOULD have mode 0700.

> **v1 status.** A personal node has no key file for each channel from its
> first start on this version: the files under `channel-keys/` are of the
> older kind, and are removed then, after a copy. What a device's channels
> are derived from, the person secret, is in the database (`cordelia.db`,
> mode 0600), so that it changes in one transaction with a statement
> (decision 2026-10-04 §3). Whoever can read that file can read every name
> of the person's. The copy folder `before-<version>` is mode 0700, and each
> file in it 0600.

---

## 6. Contradictions Resolved

This section documents contradictions between source specs that this document resolves.

### 6.1 Governor Section Placement

- **operations.md SS5.1**: Places `hot_max`, `hot_min`, `warm_max`, `warm_min`, `cold_max` under `[network]`.
- **network-protocol.md SS12.2**: Places all governor parameters under `[governor]`.
- **Resolution**: `[governor]` is canonical. operations.md SS5.1 included a comment acknowledging this (`Implementations should use [governor] as the canonical TOML section`).

### 6.2 Bootnode Syntax

- **operations.md SS5.1**: Uses a flat string array: `bootnodes = ["host:port", ...]`.
- **network-protocol.md SS12.2**: Uses TOML array-of-tables: `[[network.bootnodes]]` with `addr` field.
- **Resolution**: Array-of-tables syntax is canonical. It is extensible for future fields (e.g., `role`, `priority`, `pubkey`).

### 6.3 DNS Discovery Protocol

- **operations.md SS5.1**: `dns_discovery = "_cordelia._tcp.seeddrill.ai"` (uses `_tcp`).
- **network-protocol.md SS10.2**: SRV records use `_cordelia._udp.seeddrill.ai` (uses `_udp`).
- **Resolution**: `_udp` is canonical. QUIC runs over UDP (network-protocol.md SS2.1), so the SRV record MUST use `_udp`. The `_tcp` reference in operations.md is an error.

### 6.4 API Address Configuration

- **network-protocol.md SS12.2**: Single `api_addr = "127.0.0.1:9473"` under `[network]`.
- **operations.md SS5.1**: Split into `api.bind_address` and `node.http_port`.
- **Resolution**: Split form is canonical. Allows independent override of address and port via `CORDELIA_BIND_ADDRESS` and `CORDELIA_HTTP_PORT` environment variables.

---

## 7. Cross-Reference Index

Which spec defines each section:

| Section | Primary Source | Secondary Sources |
|---------|---------------|-------------------|
| `[identity]` | network-protocol.md SS12.1 | operations.md SS2.5 |
| `[node]` | operations.md SS5.1 | -- |
| `[network]` | network-protocol.md SS12.2 | operations.md SS5.1 |
| `[governor]` | network-protocol.md SS5.3-5.5, SS12.2 | operations.md SS5.1 (note) |
| `[replication]` | network-protocol.md SS12.3 | -- |
| `[limits]` | network-protocol.md SS9, SS12.4, SS16 | -- |
| `[memory]` | memory-model.md SS4.1, SS7.3, SS8.4, SS8.5 | -- |
| `[search]` | search-indexing.md SS7 | memory-model.md SS7.2 |
| `[api]` | operations.md SS5.1, SS5.4 | network-protocol.md SS12.2 |
| `[logging]` | operations.md SS5.1, SS6 | -- |

---

*Draft: 2026-03-12. Canonical config.toml reference -- all specs defer to this document for configuration parameters.*
