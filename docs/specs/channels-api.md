# Channels API Specification

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-10
**Scope**: Phase 1 (Encrypted Pub/Sub MVP)
**Implements**: WP3 (Pub/Sub API Endpoints)
**Depends on**: specs/ecies-envelope-encryption.md, [decisions/2026-03-09-mvp-implementation-plan.md](https://github.com/seed-drill/cordelia-node/blob/c3cc5756/docs/archive/decisions/2026-03-09-mvp-implementation-plan.md)
**Reference**: cordelia-core/docs/reference/api.md (existing node API, pre-pivot)

> **v1 status.** A node serves one of two sets of routes, by its role
> (`crates/cordelia-api/src/lib.rs`). No node serves the Channels API of
> the older kind (§3.1 to §3.13), or carries a channel of that kind
> ([decision record of 2026-11-10 (older kind)](../decisions/2026-11-10-removing-the-older-kind.md),
> rules 1 and 2): `subscribe`, `listen`, `list`, `info`, `unsubscribe`,
> `dm`, `list-dms`, `group`, `group/invite`, `group/remove`, `list-groups`,
> `rotate-psk`, `delete-item` and `search` are gone.
>
> - **A personal node** serves four routes under `/api/v1/channels/`, for
>   the names the device holds: `publish`, `entries`, `delete-key` and
>   `identity` (§3.16); and the routes of shared channels, under
>   `/api/v1/shared/` (§3.19).
> - **A relay or a bootnode** serves, under `/api/v1/channels/`, `identity`
>   alone (§3.14), with `GET /api/v1/status`, `GET /api/v1/metrics` (§3.15)
>   and `GET /api/v1/metrics/load` (§3.15a). It counts the channels it holds
>   (`relay::count_held`) and what it stores as a device counts it, the
>   entries of channels from their secrets (rule 3).
> - **Every node** serves the routes of a person's devices, of a carry that
>   a person asks for and of recovery (§3.17), sync and local history (§3.18;
>   `/api/v1/history/{list,show,restore,drop}`, decision 2026-09-30 §4.5b),
>   `GET /api/v1/health` and `GET /api/v1/peers`.
> - **Gone from every node:** `/api/v1/devices/remove` and
>   `/api/v1/invites/{list,process}`. A device is removed by a statement that
>   the command signs with the recovery phrase (`/api/v1/change/*`), and
>   nothing arrives in an inbox.
>
> Of the rest of this spec, what is of the older kind is gone with it:
> channel IDs and names (§4, §5), PSK distribution and discovery (§6, §11),
> the SDK mapping (§8), the rate limits and quotas of its routes (§9.1 to
> §9.3), its delivery model (§10) and its resolved questions (§12).

---

## 1. Overview

The Channels API is the developer-facing REST interface for Cordelia's encrypted pub/sub system. It sits alongside the existing node API (L1/L2/groups) and provides higher-level abstractions for channel operations.

### 1.1 Design Principles

1. **All POST** (one exception: `GET /metrics` for Prometheus convention, §3.15). Consistent with existing node API. No verb-based routing.
2. **Bearer token auth.** Same `Authorization: Bearer <token>` as existing endpoints.
3. **JSON in, JSON out.** Request and response bodies are `application/json`.
4. **Node encrypts.** The API accepts and returns plaintext. Encryption is transparent.
5. **Channel names, not IDs.** Developers work with human-readable names. The node resolves to internal IDs.

### 1.2 Base URL

```
http://localhost:9473/api/v1/channels/
```

Port 9473 (default). Localhost only in Phase 1 (bearer token auth over localhost is the trust boundary).

### 1.3 Authentication

All endpoints require:

```
Authorization: Bearer <token>
```

Token from `~/.cordelia/node-token`. Returns `401` if missing or invalid.

All endpoints return `401 unauthorized` with body `{"error": {"code": "unauthorized", "message": "Missing or invalid bearer token"}}` when the Authorization header is missing, malformed, or contains an invalid token. This is not repeated in individual endpoint error lists.

---

## 2. Error Format

The Channels API returns structured JSON errors (an upgrade from the existing API's plain text errors):

```json
{
  "error": {
    "code": "not_found",
    "message": "Channel 'research' not found"
  }
}
```

**Base format:**

```json
{"error": {"code": "<string>", "message": "<string>"}}
```

**Status-specific extensions:**

- `413` responses add `used_bytes` (integer) and `quota_bytes` (integer) to the error object.
- `429` responses add `retry_after_seconds` (integer) to the error object.

Clients MUST handle unknown fields by ignoring them.

### Error Codes

| HTTP Status | Code | Meaning |
|-------------|------|---------|
| `400` | `bad_request` | Invalid request body, missing required fields |
| `401` | `unauthorized` | Missing or invalid bearer token |
| `403` | `not_authorized` | Valid token but insufficient access (e.g., private channel) |
| `404` | `not_found` | Channel or item not found |
| `409` | `conflict` | Channel name already exists with different parameters |
| `413` | `payload_too_large` | Content exceeds maximum size |
| `429` | `rate_limited` | Too many requests (keeper-enforced) |
| `500` | `internal_error` | Storage or crypto failure |

Error codes are stable identifiers. Once published, a code is never removed or changed in meaning. New codes may be added. Clients MUST handle unknown codes as `internal_error`.

### 2.1 Error Retryability

| Status | Code | Retryable | Guidance |
|--------|------|-----------|----------|
| 400 | `bad_request` | No | Fix request |
| 401 | `unauthorized` | No | Check token |
| 403 | `not_authorized` | No | Permission denied |
| 404 | `not_found` | No | Resource doesn't exist |
| 409 | `conflict` | Yes | Exponential backoff, max 3 retries |
| 413 | `payload_too_large` / `quota_exceeded` | No | Reduce payload or free storage |
| 429 | `rate_limited` | Yes | Use `retry_after_seconds`, else exponential backoff |
| 500 | `internal_error` | Yes | Exponential backoff, max 5 retries |

---

## 3. Endpoints

### 3.1 POST /api/v1/channels/subscribe

Gone (decision 2026-11-10 (older kind), rule 2): no node serves this.

---

### 3.2 POST /api/v1/channels/publish

Gone (decision 2026-11-10 (older kind), rule 2): no node serves this. What a
device serves at this path is its local API for the names it holds (§3.16).

---

### 3.3 POST /api/v1/channels/listen

Gone (decision 2026-11-10 (older kind), rule 2): no node serves this.

---

### 3.4 POST /api/v1/channels/list

Gone (decision 2026-11-10 (older kind), rule 2): no node serves this.

---

### 3.4.1 POST /api/v1/channels/list-dms

Gone (decision 2026-11-10 (older kind), rule 2): no node serves this.

---

### 3.4.2 POST /api/v1/channels/list-groups

Gone (decision 2026-11-10 (older kind), rule 2): no node serves this.

---

### 3.5 POST /api/v1/channels/unsubscribe

Gone (decision 2026-11-10 (older kind), rule 2): no node serves this.

---

### 3.6 POST /api/v1/channels/info

Gone (decision 2026-11-10 (older kind), rule 2): no node serves this.

---

### 3.7 POST /api/v1/channels/dm

Gone (decision 2026-11-10 (older kind), rule 2): no node serves this.

---

### 3.8 POST /api/v1/channels/group

Gone (decision 2026-11-10 (older kind), rule 2): no node serves this.

---

### 3.9 POST /api/v1/channels/group/invite

Gone (decision 2026-11-10 (older kind), rule 2): no node serves this.

---

### 3.10 POST /api/v1/channels/group/remove

Gone (decision 2026-11-10 (older kind), rule 2): no node serves this.

---

### 3.11 POST /api/v1/channels/rotate-psk

Gone (decision 2026-11-10 (older kind), rule 2): no node serves this.

---

### 3.12 POST /api/v1/channels/delete-item

Gone (decision 2026-11-10 (older kind), rule 2): no node serves this.

---

### 3.13 POST /api/v1/channels/search

Gone (decision 2026-11-10 (older kind), rule 2): no node serves this.

---

### 3.14 POST /api/v1/channels/identity

Return the node's identity information (public keys, entity name).

**Request:**
```json
{}
```

**Response (200):**
```json
{
  "entity_id": "russwing",
  "ed25519_public_key": "cordelia_pk1...",
  "x25519_public_key": "cordelia_xpk1...",
  "node_id": "cordelia_pk1...",
  "channels_subscribed": 5,
  "peers_connected": 3
}
```

**Notes:**
- Bearer token authentication required (consistent with all other endpoints, §1.3)
- `node_id` is the Ed25519 public key in Bech32 encoding (`cordelia_pk1...`), same as `ed25519_public_key`
- `channels_subscribed` is the names a personal node holds, or the channels a relay holds (decision 2026-11-10 (older kind), rule 3)
- `entity_id` is the human-readable name set during `cordelia init`
- SDK field mapping: the SDK transforms `ed25519_public_key` -> `publicKey` and `x25519_public_key` -> `encryptionKey` (custom mapping, not simple snake_case -> camelCase). See [sdk-api-reference.md](https://github.com/seed-drill/cordelia-node/blob/c3cc5756/docs/archive/specs/sdk-api-reference.md) §7.1.

---

### 3.15 GET /api/v1/metrics

Prometheus exposition format metrics endpoint. Bearer token authentication required.

> **v1 status.** `cordelia_items_total` is gone (decision 2026-11-10 (older
> kind), rule 3). A relay's `cordelia_channels_subscribed` counts the
> channels it holds, and its `cordelia_items_stored` and
> `cordelia_content_bytes_stored` the entries it stores, as a device counts
> them; nothing of the older kind is counted on any node. Of the example
> below, `cordelia_items_pushed_total` and `cordelia_items_synced_total`
> (of the older kind's push and sync), `cordelia_replication_lag_seconds`
> and `cordelia_bandwidth_bytes_total` are not served, and
> `cordelia_sync_errors_total` is always 0: nothing counts it in this
> version.

**Response (200):** `text/plain; version=0.0.4`

```
# HELP cordelia_peers_hot Number of peers in Hot state
# TYPE cordelia_peers_hot gauge
cordelia_peers_hot 5

# HELP cordelia_peers_warm Number of peers in Warm state
# TYPE cordelia_peers_warm gauge
cordelia_peers_warm 12

# HELP cordelia_channels_subscribed Number of channels this node is subscribed to
# TYPE cordelia_channels_subscribed gauge
cordelia_channels_subscribed 7

# HELP cordelia_storage_bytes Total storage used by SQLite database
# TYPE cordelia_storage_bytes gauge
cordelia_storage_bytes 2457600

# HELP cordelia_replication_lag_seconds Seconds since last successful sync per channel
# TYPE cordelia_replication_lag_seconds gauge
cordelia_replication_lag_seconds{channel="fe028fda"} 12.5

# HELP cordelia_sync_errors_total Cumulative replication sync errors
# TYPE cordelia_sync_errors_total counter
cordelia_sync_errors_total 3

# HELP cordelia_bandwidth_bytes_total Cumulative P2P bandwidth
# TYPE cordelia_bandwidth_bytes_total counter
cordelia_bandwidth_bytes_total{direction="in"} 1048576
cordelia_bandwidth_bytes_total{direction="out"} 524288

# HELP cordelia_uptime_seconds Node uptime
# TYPE cordelia_uptime_seconds gauge
cordelia_uptime_seconds 86400

# HELP cordelia_items_pushed_total Items pushed to peers (realtime channels)
# TYPE cordelia_items_pushed_total counter
cordelia_items_pushed_total 97

# HELP cordelia_items_synced_total Items received via anti-entropy sync
# TYPE cordelia_items_synced_total counter
cordelia_items_synced_total 45
```

**Notes:**
- This is the only GET endpoint (Prometheus convention). All other endpoints are POST.
- Channel labels use the first 8 hex characters of channel_id, never channel names, to prevent metadata leakage if the metrics port is exposed.
- `cordelia_replication_lag_seconds` is computed as `now() - last_successful_sync_at` per channel. High values indicate replication problems.
- SPOs already run Prometheus/Grafana for Cardano nodes. Same stack, zero learning curve.

### 3.15a GET /api/v1/metrics/load

> **v1 status.** The counters of the scale test
> ([decision 2026-10-22](../decisions/2026-10-22-a-scale-test-for-r1.md)
> §1.1, rule 3; §7.3; `crates/cordelia-core/src/load.rs`). Served by every
> role.

The same text form as §3.15. Bearer token authentication required; it is
answered while a node is held up, as every GET is. **It takes no lock:** the
token is checked and atomics are read, so a read neither waits for the
node's work nor holds it up. Each counter counts from the node's start; a
gauge is what it was when last set.

- `cordelia_lock_wait_microseconds` and `cordelia_lock_hold_microseconds`:
  histograms of the node's lock on its database, `kind` one of `show_whole`,
  `show_short`, `proof`, `pull`, `push`, `relays`, `sweep`, `checkpoint`,
  `pass`, `cycle`, `api` and `other`; buckets of powers of two from 1 µs to
  16 s, with `_sum`, `_count`, `_max` and `_over{ms="5"|"50"|"100"|"250"}`.
  A take that tries the lock until its time is up (`cordelia msg summary`,
  for at most 100 ms) has its wait counted from its first try.
- `cordelia_lock_given_up_total{kind}`: the takes that tried until their time
  was up and were not had; each is a summary that printed nothing.
- `cordelia_lock_nested_wait_microseconds{mutex="rates"|"room"}`: the waits
  for a relay's rates and room while the lock is held.
- `cordelia_requests_total{kind}`, `cordelia_answers_total{kind,answer}`
  (`answered`, once the answer is written; `not_now`, `refused_for_rate`,
  `not_served`, `stray`, and `large_later`, a frame over a small message for
  which no large permit came, of which only the length was read),
  `cordelia_entries_refused_total{kind,answer}` (`refused_for_room`,
  `refused_for_new_channels`, each entry refused in an answer given) and
  `cordelia_stream_bytes_total{kind,direction}`: what a relay is asked on the
  streams of entries. A request is counted as it is read, with its bytes in.
- `cordelia_connections_open`, `cordelia_connections_closed_total` (gone for
  any reason, warm churn's among them),
  `cordelia_connections_turned_away_total{why="bound"|"address"|"subnet"|"refused_for_a_time"}`
  and `cordelia_relay_link_closures_total{relay}`.
- `cordelia_churns_total`, `cordelia_closed_by_warm_churn_total{peer="device"|"relay"}`
  and `cordelia_governor_peers{state="hot"|"warm"|"cold"}`, the governor's
  own count at its tick.
- `cordelia_device_requests_total{relay,kind}`,
  `cordelia_device_request_bytes_total{relay,kind}`,
  `cordelia_device_held_back_total{relay}` and
  `cordelia_device_refused_for_now_total{relay}`: what a device asked of
  each relay, by its key in hex. Refused for now is what the relay reset
  with `ERR_RATE_LIMIT`, which a relay's `refused_for_rate` and `not_now`
  both are: a device cannot tell them apart, and its count is checked
  against the two together.

---

### 3.16 The Local API of a Device, for the Names It Holds

> **v1 status.** What a personal node serves under `/api/v1/channels/`
> (decision 2026-10-04 §2.3, §16; `crates/cordelia-api/src/local.rs`). There
> are four routes. Nothing is created, joined or subscribed to: a request
> names a name that this device holds, and the channel is the name's, derived
> from the person's secret.

A device holds a name once it follows a recovery phrase and a folder of its
own is mapped to the name (`cordelia sync map`), or a carry that a person
asked for, or a recovery, brought the name in (§3.17). A request for a name that it
does not hold is `404`, and says how to hold one. On a device that follows no
recovery phrase each route below but `identity` is `400`, with the way on in
its message: such a device has no secret, and publishes nothing. A device
that has stopped (it was removed, is in no list, is closed, or could not
open a change) publishes nothing either: `publish`, and a `delete-key` of a
key that holds a version, are `400`. `entries` still answers there, with
what the device holds.

**A publish here goes through the path that the sync adapter's goes through,**
and so does a delete: one path for every entry that a node writes in a name.
So an entry written through the local API says what it was written after, as
the adapter's does.

#### POST /api/v1/channels/publish

**Request:**
```json
{ "channel": "github.com/owner/repo", "key": "notes.md", "content": "..." }
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `channel` | string | yes | The name, which this device holds |
| `key` | string | yes | What the value is published under: for a memory file, the file's name. There is no publishing without one |
| `content` | any | yes | A string is published as a text, which is what a memory file holds. Any other JSON is published as bytes that are no text: the sync adapter takes it for no version of a file |

**Response (200):**
```json
{
  "channel": "github.com/owner/repo",
  "key": "notes.md",
  "rev": 7,
  "entry": "<hex: the entry's ID>",
  "author": "cordelia_pk1...",
  "over": { "rev": 6, "kind": "text", "entries": ["<hex>"] }
}
```

`over` is what the entry was published over: the version that the slot held
when the request was read (its revision, which of `text`, `delete` and
`other` its value was, and the entries that the device held of it), or `null`
where the slot held no version. The read and the publish are made under one
hold of the database's lock.

**Errors:**
- `400` if `key` is missing, or the key and what is published under it are
  more than 60 KB together.
- `404` if this device does not hold the name.
- `409` if no revision is left under that key until the next change of
  devices (decision 2026-10-04 §2.3): nothing was written.

#### POST /api/v1/channels/entries

**Request:** `{ "channel": "github.com/owner/repo" }`

**Response (200):** the current version under each key, in order of key, as
the device's own store has it under the statement it has applied.

```json
{
  "channel": "github.com/owner/repo",
  "entries": [
    { "key": "notes.md", "rev": 7, "kind": "text", "deleted": false,
      "content": "...", "authors": ["cordelia_pk1..."], "conflicts": 0 }
  ]
}
```

A deleted key is listed, with `deleted: true` and `content: null`. `authors`
is every key that signed an entry which is that version. `conflicts` is how
many other versions stand at that revision: they lost the tie.

#### POST /api/v1/channels/delete-key

**Request:** `{ "channel": "github.com/owner/repo", "key": "notes.md" }`

A delete is published over the version that the slot holds, as any value is,
and the answer is the answer of a publish. `404` where the key holds no
version, or a delete already.

#### POST /api/v1/channels/identity, GET /api/v1/status, GET /api/v1/metrics

As §3.14 and §3.15, of the device's own channels: the channels counted are
the names that it holds, and what waits to be sent is what waits in a channel
of the device's own. Nothing of the older kind is read.

---

### 3.17 A Person's Devices

> **v1 status.** The routes behind `cordelia phrase`, `add-device`, `accept`,
> `devices`, `remove-device`, `renew`, `settle` and `init --new-key` (decision
> 2026-10-04 §5 to §8; `crates/cordelia-api/src/commands.rs`), and behind
> `cordelia sync carry` and `cordelia recover` (§7.3, §9;
> `crates/cordelia-api/src/carrying.rs`, `recover.rs`). Every node serves
> them.

- **No route takes a recovery phrase, and none is given one.** A command
  that needs the phrase reads it at its own terminal, signs and seals in its
  own process, and hands the node what it made: a change entry; for a new
  phrase and at a recovery the statement key; for a carry and for the look
  of a recovery a word that the phrase signed (below); proofs of a channel's
  key, each made for one connection; and at a recovery the secrets of the
  generation recovered from and of those before it, which the machine keeps.
  An entry and a statement travel as hex of their bytes.
- **No route asks a yes.** Every yes is asked by the command, at a terminal.
  A program that holds the node's token can make these calls itself. What it
  cannot do is have a phrase sign what a person was not shown (decision §5,
  and the threat model's T17).
- **Every route here is `409` once the device was given a new key** and the
  node has not been started again.
- **A node that is held up** (§3.18) answers none of them: it answers
  `GET` requests alone, and these are `POST`.

| Route | What it does |
|-------|--------------|
| `POST /api/v1/devices/list` | Everything `cordelia devices` and `cordelia status` say of this device and its person: where it stands (`state`: `no_phrase`, `applied`, `fork` (closed among changes made apart: it follows no clear change, decision 2026-10-24 (removal), rule 10; stored under the old name `fork`), `closed` (it stands applied under a change whose secret a key it knows to be removed holds, rule 4), `removed`, `not_listed`, `not_opened`); the devices of the statement it has applied, each with whether it has applied the statement and sent what it carried; the devices added since, with who added each; the removed keys, each with the label that this device knew it by; the keys that are in neither list of the last change; the devices that have said they left; for each relay, whether it holds the latest change entry; the keys typed at `accept`; the notices that a person has not cleared, each with `id`, `kind` and `says`, and `device`: for an `added` notice the device it says was added, with its `key`, `label` and `words`, and null for any other (decision 2026-11-11 (plain words)); the names that no device lists yet; and what this device has still to send. Each device is shown with its label and the first four words of its key's fingerprint. What a status goes by for its level is here too: for each relay `holds_latest`, `heard_since_woke`, `connected_secs` (for how long the node has been connected to it, by the node's own clock) and `no_room_at` (when it last refused something for room, or for the address's allowance); `applied_at` (when this device applied the change) and `removed_a_key` (whether that change removed a key that the statement before had not), with `newly_removed`, those keys, each as `removed` gives one (empty where it removed none, or where this device applied the change before it kept which; decision 2026-11-11 (plain words)); `moved` (the moves the device made with no phrase, to a clear change made apart, decision 2026-10-24 (removal), rule 9: each the change entry it left, as `from`, and what `cordelia change-made` says of it, as `says`); `set_aside` (each change made apart that this device sets aside, the highest number first, rules 1 and 11: its lists, `set_aside_at` by this device's clock, `clear`, `lists_removed` (each removed key it lists), and what is said of it, as `says`); `apart` (the lists of the first of those, the one with the highest number); `edits_set_aside` (how many edits a carry set aside, rule 7, for seven days from the last, and only while the device stands applied; otherwise 0); `names` (`sent`, `to_go`, and `to_go_since`, since when the first of them has waited); `not_reached` (the relays it is set up with and is not connected to); and `waiting` (for each connected relay, how many of the device's channels have something still to send there, with the address it is reached at as `relay` and, as `name`, the name that the configuration gives it, where the connection is that relay's own: by its key, or for a relay given none, the connection that the dial loop made to it (decision 2026-10-24, rule 2); and, as `names`, every relay whose own connection it is, where two relays given no key share one, the row then having no `name`. `cordelia devices` lists a relay once, by its name, with both things said on its line, and no line that a person reads says `relay`); and, only where the request's body carries `"sent_to_no_relay": true`, `sent_to_no_relay` (`versions` and `names`: how many versions, of how many names, this device holds that it signed and has sent to no relay, however the device stands; what another key signed came from a relay, and is not counted, decision 2026-10-17 §4.5). `cordelia phrase`, `cordelia init --new-key` and `cordelia accept` on a device alone under a phrase ask for it, and say it before their yes; a status does not ask, since it calls this route every few seconds and the count reads every entry of every name |
| `POST /api/v1/devices/clear` | `{ "notice": "<hex>" }`: a person clears a notice on this device. `404` where it shows no such notice |
| `POST /api/v1/devices/add/look` | `{ "device": "cordelia_pk1...", "label": "desktop" }`: what adding that key would do, with nothing written: `would` is `add`, or `hand_again` for a key that the statement already lists |
| `POST /api/v1/devices/add` | The same body with `would`, which says what the yes was for. The device writes the hand-over in the pair channel and, where a record is made, the record in the personal channel. `409` where adding the key would by then do the other |
| `POST /api/v1/devices/accept` | `{ "key": "cordelia_pk1...", "row": "no_phrase" }`: a person typed a key. It is kept with its time and the row of the record's 5.1 that the yes named (`no_phrase`, `alone`, `several`, `not_listed`), and the node asks its relays for what that device hands over until it is taken or the hour is gone. Answers `typed_at` and `until`. Refused where no hand-over could be taken as the device stands, and a ninth key |
| `POST /api/v1/phrase/make` | `{ "entry": "<hex>", "statement_key": "<hex>", "from": "no_phrase" }`: the device starts alone under a new phrase. It is handed the first statement's change entry and the statement key, and never the words. `from` is where the device stood when the command asked its yes (`no_phrase`, `alone`, `several`) |
| `POST /api/v1/change/prepare` | `{ "settle": false }`: the device shows its change entry to each relay and fetches, for two minutes at most, runs a sync cycle, and hands the command what it signs over and shows: the statement applied and the change entry kept, as their signed bytes; the record of each device added since; each head set aside (`heads`: its statement, its entry, and what the entry is named by), which any change made there joins (decision 2026-10-24 (removal), rule 21); every key the device knows to be removed (`removed`), which the change lists as removed and none of which it lists as a device (rule 20); the names that the personal channel lists, each with the keys that list it; how much each device wrote that this one received in the last day and week; and what it could not fetch |
| `POST /api/v1/change/make` | `{ "entry": "<hex>", "over": "<hex>", "heads": [] }`: the node's half of a change that a command made with the phrase. One transaction, in which what the prompt showed is checked again: `409` where a statement arrived meanwhile, or the heads set aside are not those named, and nothing is made. `400` where the change does not list as removed every key the device knows to be removed, lists one as a device, or does not have every head set aside on its chain (decision 2026-10-24 (removal), rules 20 and 21). Answers the change's number, how much was carried, and the files whose record could not be carried |
| `POST /api/v1/devices/leave` | What a device owes the devices it leaves, before it is given a new key: its word that it has left, and a delete over each hand-over that a relay was sent |
| `POST /api/v1/devices/leave/sent` | For each relay the node is connected to, how many of the device's channels still have something waiting to be sent there |
| `POST /api/v1/devices/leave/back` | The device takes back its word that it has left: for `cordelia init --new-key` that a person stops at its second yes |
| `POST /api/v1/devices/forget` | The device forgets what it holds of its person, and then follows no phrase: for a device that is given a new key |

A refusal says the way on in its message: "this device follows no recovery
phrase yet", with the three ways on that a status names, each on a line of
its own (make a phrase here, add this machine from one that has the phrase,
or recover here with `cordelia recover`), and so on. What a person did that
is refused is `400`, and what changed under a prompt is `409`.

**A carry that a person asks for, and recovery** (decision 2026-10-04 §7.3,
§9). The command reads the recovery phrase, as the commands above do. What a
removed key signed, and what a command read in a generation that this device
never held, comes in only under **a word that the phrase signed:**

```json
{ "what": "{\"from\":{\"name\":\"lab\",\"keys\":[\"<hex>\"],\"above\":[]}}",
  "until": 1791000600, "signature": "<hex>" }
```

- `what` is the text that was signed, and the node reads what it is to do
  from that text and from nothing beside it. It is one of `{"from": {"name",
  "keys", "above"}}` (`sync carry --from`: the removed keys, and the files
  that a second yes named), `{"handed": {"name"}}` (`sync carry --phrase`) and
  `{"look": {"names", "takes"}}` (`recover`: the names that are carried, and
  the keys that the look takes from).
- The phrase's key signs it under the label `cordelia v2 carry word`, with
  this device's key, the ID of the change entry that the device keeps, and
  `until`. It stands for ten minutes (`CARRY_WORD_SECS`), for that device and
  under that change entry: a change that reaches the device meanwhile ends
  it. A program that holds the node's token cannot make one.

| Route | What it does |
|-------|--------------|
| `POST /api/v1/carry` | `{ "name": "lab" }`: carry one name, with no phrase. The device comes to hold the name, fetches its new channel, and reads the name's channel at each relay in each generation that it left and still holds the secret of, for two minutes at most. What keys that count signed comes in, each version as this device's own entry at the revision it had, where the new channel holds neither that version nor an entry at a higher revision. Answers `name`; `held_anew` (the device came to hold the name by this); `generations` (for each, its `number`, `relays`, each with its `relay`, how it was `read`: `whole`, `part`, `not held`, `not reached` or `not read: <why>`, `entries`, how many entries of the channel that relay handed, and `bytes`, what those come to as a relay counts them against a channel's cap, each entry's content and 1 KB (decision 2026-10-17 §3.3); and `by_other_keys`); `carried`, `held` (the new channel held that version already) and `higher` (it holds a higher revision), as counts; `ties` and `above`, by file; `deletes`; `by_other_keys` (entries that other keys signed, which are left); `read_all`; and `nothing`, which says why where nothing was tried |
| `POST /api/v1/carry/from/look` | `{ "name": "lab", "from": ["desktop"] }`: what `sync carry --from` says before it asks anything. Nothing is taken. Each of `from` names a removed key by the label that this device knew it by, or by the first six words of its key's fingerprint: `400` where it matches two removed keys, or none. Answers `signed`: each removed key that signed there, with its `key` (hex), `words` (the six), `shown` (the four that a device is shown by), `label` and `entries`. With keys named it also answers `keys`; `empty` (how many versions would go into slots where the new channel holds nothing); `above` (the files of which a version stands above one that the new channel holds); `held`, `higher`, `ties` and `deletes`; `has_folder` (whether a folder of this device's is mapped to the name); and `under`, the ID of the change entry that the device keeps, which the word is given under |
| `POST /api/v1/carry/from` | `{ "word": { ... } }`: take what the word allows, and nothing beyond it. For each file the newest version among the named keys is judged once: it comes in where the new channel holds nothing in that slot, and above a version that it holds only for a file that the word names. A delete that a removed key signed is never taken. Answers as `/carry` does. Refused, with nothing taken: a word that does not hold; a key that the statement applied does not list as removed; and a file named to come in above a version, for a name that no folder of this device's is mapped to |
| `POST /api/v1/carry/phrase/look` | `{ "name": "lab" }`: what `sync carry --phrase` is handed before it asks for the phrase. The device comes to hold the name, and fetches its new channel. Answers `entry`, the change entry that the device keeps (hex), whose part for the phrase the command opens in its own process, and `under`, its ID; `held`, the ID of the name's channel in each generation whose secret the device holds, which the plain command reads; `counts`, the keys that count; and `sessions`, each relay by its name with the value of its connection's session (hex, or null where it is not reached), over which the command makes its proofs |
| `POST /api/v1/carry/read` | `{ "channel": "<hex>", "proofs": [{ "relay": "relay1.example:9474", "proof": "<hex>" }] }`: read, at each relay, a channel whose secret the node does not hold, with proofs that the command made. The node proves and pulls, and is handed no secret. It is how a command reads the phrase's own channel, and a channel of a generation that this device never held. With `"from": [{ "relay": "relay1.example:9474", "mark": "<hex>", "place": 4 }]`, the read goes on at each relay named from that place, and at any other from the start (decision 2026-10-17 §3.2). Answers `relays` (what is said of each, as above), `entries` (how many were handed), `reached` (for each relay where it read, whole or in part, the `mark` of the relay's holding and the `place` the read reached, which a later read is asked `from`) and `read`, what the reading is named by. A relay that is not in `reached` read nothing (it was not reached, refused the proof, or did not answer), and whoever asked keeps the place it had there. A relay that holds none of the channel says so to the proof (`not held`, and is not in `reached`); one that took the proof and holds none of the channel by the time of the pull answers under no mark, and is in `reached` as read `whole`, with a `mark` of all zeros and a `place` of 0: whoever reads on takes that as holding none. A place means something only with its mark: a relay whose holding has another mark reads from the start. A relay given two places is `400` |
| `POST /api/v1/carry/read/part` | `{ "read": 7, "from": 0 }`: a part of that reading, from the entry numbered `from`: as many entries as fit 512 KB (`CARRY_PART_MAX_BYTES`), each as hex of its bytes, and `next`, where the next part begins, or null. Only the last reading is kept: an older one is `400` |
| `POST /api/v1/carry/handed` | `{ "word": { ... }, "versions": [{ "name": "notes.md", "rev": 7, "text": "...", "signer": "<hex>", "chain": ["<hex>"] }] }`: the versions that the command read in generations whose secret this device never held, in the clear. `text` is null for a delete, and `chain` is each link as hex, or null where the entry lacked its chain. Each is judged as `/carry` judges a version that the node read itself. One whose signer does not count is counted, and not taken. Answers as `/carry` does |
| `POST /api/v1/recover/look` | What `cordelia recover` asks before anything else: `this_device`; `follows_a_phrase` (a recovery is refused where the device does); and `sessions`, each relay that the device is set up with, with the value of its connection's session. A relay with no session is not reached |
| `POST /api/v1/recover/make` | `{ "entry": "<hex>", "statement_key": "<hex>", "left": [{ "number": 3, "secret": "<hex>" }], "gone": [{ "key": "<hex>", "label": "laptop" }], "removed_apart": [], "still_have": [], "word": { ... } }`: the node's half of a recovery, in one transaction. `entry` is the change entry of the recovery's statement, which the command made; `left` the secrets of the generation recovered from and of those before it, which the machine keeps as a device keeps a secret it left; `gone` the keys that the person said are gone, `removed_apart` the devices of the generation recovered from that another change the recovery read removed, of which nothing was asked (the recovery seals without both, and takes the acts in the person's lists of `gone` alone, decision 2026-10-24 rules 6 and 22), and `still_have` the devices that the person still has, each with the label it was shown by; and `word` the phrase's word for the look, under this very entry. The statement is applied, the names of the look are listed in the new personal channel, and the node is woken: it shows the change entry to every relay before anything is carried. Answers `{ "change": <number> }`. The look is begun, and goes on after the answer |
| `POST /api/v1/recover/progress` | `{ "look": ... }`: how far the look is. While it runs: `change`, `finished: false`, `names` (how many it reads) and `read` (how many it has read). Once it has ended, also `carried` and `carried_names`; `held` and `higher`; `ties`; `not_read`, each name that could not be read to its end, with the `change` (the generation), the `relay` and how it was `read`; `failed`; and `lacking`, for each removed key how many `versions` that key signed in what was read that the new channels lack, with the `names` they are in, its `key` and its `label`. `null` where this node has made no look since it started: one that was interrupted is not taken up again by itself |

**What binds what a command hands the node** (decision 2026-10-04 §16):

- **A word is taken once.** The node keeps a taken word's signature until the
  word is void (ten minutes), and refuses it a second time.
- **A batch is signed by the key of its run.** The word names a key that the
  command makes for that one run. `POST /api/v1/carry/handed` takes
  `{ "word", "number", "signature", "versions" }`: the signature is that key's,
  under a label of its own (`cordelia v2 carry batch`), over the batch's number
  and the hash of its versions as they are handed, and the node takes each
  number once. A version at a revision that no entry may have under the
  applied statement refuses the batch whole. A batch holds 512 KB of versions
  at most (`CARRY_HANDED_MAX_BYTES`), and the body of any request to a device's
  routes 2 MB (`LOCAL_API_BODY_MAX_BYTES`): a larger body is refused and not
  read.
- **A proof goes with its session.** `POST /api/v1/carry/sessions` answers
  each relay that the device is set up with and the value of its connection's
  session, as `/recover/look` does. Each proof in `/carry/read` carries the
  `session` it was made over. Where the connection has changed since, that
  relay is answered "not read: the connection changed", and the command makes
  its proofs again (twice at most, `CARRY_PROOFS_MADE_AGAIN`); where a
  connection has no place left for a proof it is "not read: no room left for a
  proof", and the node makes the connection again. Neither is ever "the relay
  holds none".
- **Nothing is taken where the new channel was not fetched whole.**
  `/carry/from/look` answers `new_read`, whether it was; a recovery's progress
  answers `new_not_read`. Keys in both carry `by_words`, how to name them to
  `--from` where a label would not tell them apart (a key written whole is
  taken too).
- **A recovery that could not show every row** hands `not_shown` to
  `/recover/make`, the keys it did not show, and `/devices/list` then carries
  each as left out with its `key`. A name that a carry or a recovery brought in
  and has not yet sent is in `/devices/list` as `carried_to_go`, with
  `carried_to_go_since`.
- **`POST /api/v1/sync/unmap`** with a name that no folder maps and that a carry
  holds lets go of it, and answers `let_go`. On a device that sends, it first
  reads the name's channel at each relay that the device is set up with
  (decision 2026-10-17 §4.2), outside the database's lock, a round at each
  request: where the read goes on, the answer carries `reading`, with `read`,
  the read's ID as hex, and `relays`, each relay still read in part with the
  `bytes` it has handed so far, and the command asks again with `"read":
  "<hex>"` beside the name. Once the read has ended, the name is let go where a
  relay handed each entry of the name that this device signed, or what moves
  its slot on, and the answer carries `let_go_versions`, how many such entries
  there were. It is refused with `409` where an entry is held by no relay
  (saying, of each relay, how its read ended), where the store has taken
  anything of the name's channel since the read ended, where a folder was
  mapped to the name while it was read (saying that the folder holds it
  now, and not to run the command again, which would unmap the folder),
  and where the node keeps no read by that ID. **Where an entry is held by
  no relay, the name is let go with it only on the word `discard`** (decision 2026-10-17 §5):
  a command that asks at a terminal sends `"asks": true`, and is answered in
  place of the refusal with `not_let_go`: `read`, the ID the word is bound
  to, as hex; `versions`, how many versions no relay held; `said`, the lines
  of the refusal but the last; and `where`, where those versions may still
  be. The word comes back as `{ "folder": "<name>", "read": "<hex>",
  "versions": n, "word": "discard" }`, and the answer carries `let_go` and
  `let_go_discarded`, how many went, with `let_go_stopped`, whether the
  device has stopped, so that what went is what its own notes said. It is refused with `409` where the read
  no longer stands (`LET_GO_READ_STANDS_SECS` from its end, on the node's
  monotonic clock), the number is another, or the store has taken anything
  of the name's channel since, where a folder was mapped to the name since,
  and with `400` for any other word. **A
  device that has stopped reads no relay** (§4.4): where its own notes say
  that it sent a version of the name that it signed to no relay, it is
  refused with `409`, saying why it stopped, or with `"asks": true` it
  answers `not_let_go` with the count it took from its notes under an ID,
  for the same word; where they say none, the name is let go at once. With
  a folder that was mapped to a name which a carry or a recovery holds, or
  into which a carry brought versions while the folder was mapped
  (`person.names_brought_in`, decision 2026-10-17 §4.3), the folder is
  unmapped and the name stays held: the answer carries `still_held`, the
  name, and `still_held_stopped`, whether this device has stopped.

---

### 3.18 Sync, and a Node That Is Held Up

> **v1 status.** `/api/v1/sync/{claude,map,unmap,status}`, per the
> decision record of 2026-09-30 §4.5, with what the decision record of
> 2026-10-04 §10.1 changes. `/api/v1/sync/seen` is gone, with the notice of
> the folders that stopped syncing at an earlier version's first start, and
> so is the first start itself (decision 2026-11-10 (older kind), rule 9).

- **Only what is mapped syncs.** A folder syncs because `map` declared it,
  and for no other reason. A request to `sync/claude` that turns on a scope
  of everything found (`all`) is refused. `exclude` and `home`, which a panel
  of the version before may still send, are accepted and stored as before:
  there is nothing left to exclude. A request that turns sync off is never
  refused.
- **`map`** forgets what the folder it adds had agreed, and its first cycle
  in the name's channel waits until a relay has handed that channel. Where
  the device comes to hold the name by it, it carries the name first
  (decision 2026-10-04 §7.3), and the answer has what was carried under
  `carried`, in the form that `/api/v1/carry` answers.
- **`sync/status`** answers, as `claude`, `map` and `unmap` do:

  | Field | What it is |
  |-------|------------|
  | `enabled`, `dir` | Whether sync is on, and the Claude Code directory it is on for |
  | `all` | Always `false`: only the declared mappings sync |
  | `mappings` | The declared mappings, each a `folder` and a `name` |
  | `exclude`, `home`, `home_name` | The stored list of exclusions, which nothing reads to say what syncs; the switch for home memory; and the name that home memory syncs under, or last did |
  | `generation` | How many times the settings have changed since the node started. A report carries the generation it was made under |
  | `report` | The last cycle's report, once one has run: each folder that syncs, what was found and is not mapped (`unmapped`, each a found entry, below), and the cycle's errors |
  | `no_report_secs` | For how long the node has stored no report, by its own clock, which does not run while the machine sleeps: since the later of its start and the last report. A status says by it that the cycle has stalled |
  | `last_change_at` | When a cycle last sent or received a memory |
  | `stands` | Where the device stands under a recovery phrase: `no_phrase`, `applied`, or why it has stopped (`fork`: closed, it follows no clear change, decision 2026-10-24 (removal), rule 10; `closed`: it stands applied under a change whose secret a key it knows to be removed holds, rule 4; `removed`, `not_listed`, `not_opened`) |
  | `held` | Why the node is held up, in words, where it is. It is not seen now: a node that is held up refuses this request (below) |

  `moved_on` and `notice` are gone with the first start (decision
  2026-11-10 (older kind), rule 9).

  **A found entry** is a folder that was found and is not mapped:

  | Field | What it is |
  |-------|------------|
  | `folder` | Claude Code's folder for it |
  | `cwd` | The directory to map to sync it. It is carried only where `cordelia sync map`, given this directory, would sync this folder |
  | `directory` | The directory it belongs to, where one is known and `map` would not sync this folder: to show, and never to map |
  | `name` | The name it would sync under, or did: `~` for home, the remote for a git project, none for any other folder |
  | `mappable` | Whether `map`, given the directory under `cwd`, would sync this folder |
  | `needs_name` | Present and true where it can be mapped only under a name that a person gives it |
  | `home` | Present and true where it is the home directory's own folder |
  | `mapped` | Present and true where a mapping syncs it now. What a cycle's report lists as found never is |
  | `why_not` | Why `map` would not sync it, in a word: `another_claude_dir`, `laid_out_by_hand`, `no_directory`, `home_not_set`, `outside_home`, `path_too_long`, `directory_gone`, `through_a_link`, `git_not_run` or `memory_elsewhere` |
  | `says` | Why not, or why a name is needed, in words |
- **`GET /api/v1/status`** answers `status`; `version`, so that a command
  can tell a node of another version; `uptime_secs`; `peers_hot` and
  `peers_warm`; `channels_subscribed` (the names a device holds, or the
  channels a relay holds); `sync_errors`, always 0, as nothing counts
  them in this version; `outbox_waiting`; `held`, which
  is null, or by what the node is held up (`by`: `later_database`;
  `earlier_database` for a database from before 0.2.0-alpha.19; or
  `step_failed` for a step of the schema that did not finish) and why
  (`why`); `no_relay_secs`, for
  how long no relay has been connected, by the node's own clock, or null
  while one is; and, on a personal node that stands applied and is not
  held up, `messages` (decision 2026-10-09 §8). Working it out gives
  places, as a show of messages does. It is absent from a relay, from a
  node of the version before, and from a device that does not stand
  applied:

  | Field | What it is |
  |-------|------------|
  | `unread_by_an_agent` | For each mapped folder, the messages unread by its agent (§7.2 there), from a signer that counts: a message to every name once for each folder |
  | `unread_by_a_person` | The messages to a name mapped here or to every name, that have a place, have not expired, were not sent here, and that no person has read on any device that counts (decision 2026-10-25, rule 1) |
  | `bounds` | Each bound in force that is not the usual hold, with `a`, `b` (null for every agent), `bound` (null for `any`), `until` (RFC 3339) and `set_on` (`"this"`, or `label` and `fingerprint`) (decision 2026-10-25, rule 4) |
  | `held_pairs` | The pairs of the person's agents held now: each pair whose messages unread by a person reach its bound in force, by the test a send makes (`sender::held_pairs`); 0 where none (decision 2026-10-25, rule 4) |
  | `waiting` | This device's messages that not every relay it is set up with has taken |
  | `refused_for_room` | Of those, the ones a relay refused for room, each once |
  | `filled_by` | Where a relay refused the messages channel for room since the node started, the signer whose entries fill it, by the count of each author's entries the device holds there: `label` and `entries`. Null otherwise |
  | `held_back` | Messages held back by the reader's hour (§6 there) |
  | `overwritten` | Messages that left the live numbers before they had a place (§2.5 there) |
  | `no_place` | Whether the device has no place for messages among the proofs of a connection (§2.1 there) |

  **Nothing of it feeds the level.** The messages channel is left out of
  `outbox_waiting` (`leaving::waits_at` passes over it), and a relay's
  refusal of it for room sets no `no_room_at` in `devices/list`.
  `outbox_refused`, what relays refused of the older kind, is gone (decision
  2026-11-10 (older kind), rule 3).
- **`cordelia status --json`,** which a panel reads, is worked out by the
  command from `GET /api/v1/status` and `sync/status`, and carries what
  `devices/list` answers under `person`. Its `state` is one of seven names
  (`synced`, `syncing`, `offline`, `attention`, `off`, `stopped`,
  `uninitialised`). Where the node runs and sync is on, a device with a
  folder mapped and no recovery phrase has the state `attention`, so that a panel
  which draws from the state alone does not show it as synced. So has a
  device that has stopped, and a node that is held up, with sync on or off.
  - **`level`** is `red`, `amber`, or null where none holds (decision
    2026-10-04 §10.1). Only the command works it out: a panel draws it.
  - **`summary`** is the first thing of that level, and with no level what
    the state says.
  - **`holds`** is everything that holds, red first, each with its `level`,
    `what` it is in a word, and what the line `says` of it. They come in
    this order (`indicator::holds`, `cordelia-node/src/indicator.rs`).
    Red:
    - `stopped`: this device has stopped syncing, and the line says why,
      such as that it was removed.
    - `held`: the node is held up: its database is from a later version,
      or from before 0.2.0-alpha.19.
    - `no_phrase`: a folder is mapped, and this device has no recovery
      phrase yet.
    - `errors`: memory sync has an error.
    - `stalled`: memory sync has stopped reporting.
    - `conflicts`: a memory folder holds conflict copies.
    - `too_large`: a memory file is too large to sync.

    Amber:
    - `channel_nearly_full`: the personal channel is past its warning size
      (`PERSONAL_CHANNEL_WARN_BYTES`; decision 2026-10-19 §2).
    - `no_relay`: no relay has been reached for five minutes.
    - `other_version`: the node runs another version than the command.
    - `removal_not_applied`: a removal is not yet applied by every device,
      for seven days.
    - `set_aside`: a change made apart is set aside, for seven days.
    - `shared_removed_device_holds`: a removed device still holds shared
      channels not made anew, for seven days (decision 2026-10-10 §9).
    - `added`: a device was added and is not yet cleared with `cordelia
      devices --clear`.
    - `left`: a device has left.
    - `carried`: names that a recovery or a carry brought in are not yet
      sent, after five minutes.
    - `relay_without_latest`: a relay is not known to hold the latest
      change (decision 2026-10-19, rule 11).
    - `relay_no_room`: a relay has no room.
    - `names`: names are not yet listed by a device, or not yet sent.
    - `relay_out_of_reach`: a relay is out of reach while another is
      reached (decision 2026-10-19, rule 11).
    - `messages_held`: agents are held for their person (decision
      2026-10-25, rule 4).
    - `shared_repository`: last of all, one for each amber line of a
      repository this device follows (decision 2026-11-06 (joining), rule
      7).
  - Of the node: `running` (null where the command did not ask it, with why
    under `not_asked`); `version`, the command's own, and `node_version`;
    `held`, where it is set; `uptime_secs`;
    `no_relay_secs`; `peers`; `outbox_waiting`.
  - **`messages`,** at the top level, as the node gave it, where it gave
    it (decision 2026-10-09 §8). Only its `held_pairs` changes the
    `level`, `summary` and `holds`: above 0 it is the amber hold
    `messages_held`, after every other hold but `shared_repository`,
    which `--line` and `--waybar` show as any amber, and plain `cordelia
    status` on a line of its own, `Messages:`, not under `Memory:`.
    Nothing else of messages changes them; plain `cordelia status` also says each bound in force
    (decision 2026-10-25, rule 4).
  - **`shared`,** at the top level, as the node gave it, where it gave it:
    its fields are in decision 2026-10-10 §9. Each group of its
    `removed_device_holds` gives `channels`, `since` and, where a removed
    key held them, `device`, those keys by label and words in one string;
    and `devices`, each of those keys alone, with its `key`, `label` (empty
    where this device knew it by none) and `words`, empty where there is no
    `device` (decision 2026-11-11 (plain words)). Its `repositories` is each
    repository this device follows (decision 2026-11-06 (joining), rule
    7): `identity`, `name`, `held`, `channel` and `words`; `read`, when the
    list was read, at which commit, from the clone, and when the clone was
    fetched; `members`, each with `label`, `key`, `words` and `in` (null
    where this device does not hold the channel); the unread counts;
    `lines`, each with a `word`, what it `says`, whether it is `amber`, and
    a channel `line` to put in the list, where it says to; `in_step`, true
    where nothing waits on the list, which plain `cordelia status` then
    says in one line; and `next_read`, when the node next reads the list,
    read yet or not (null where no timer of the node's reads it). A line whose
    word is `joined`, the keys new on the list at one commit (decision
    2026-11-06 (joining), rule 4.5, as the person ruled on 10 November),
    also gives that `commit`, whole, and `devices`, each with `label`,
    `key` and `words` as `members` gives them; its `says` names six labels
    and how many more. Each amber
    line is a hold `shared_repository`; nothing else of `shared` but the
    hold of a removed device that holds a shared channel changes the
    level.
  - Under `sync`: the settings; `projects`, one for each folder that syncs;
    `unmapped`, the found entries; `available`; `stands`;
    `publishes_nothing`, why nothing is published from this device where
    nothing is; and `conflicts` and `errors`.
  - **Gone with the first start** (decision 2026-11-10 (older kind), rule
    9): the red hold `stopped_syncing`, the node's `key_files_in_place`,
    and `moved_on` and `notice` under `sync`.
- **A node that is held up** (decision 2026-10-04 §10.1; decision
  2026-11-10 (older kind), rule 6), by a database from a later version or
  from before 0.2.0-alpha.19, runs no cycle and no pass, over a database of
  its own in memory, and changes nothing in the one on disk. It answers
  every `GET` and nothing else: every other request is refused with `503`,
  the code `held_up`, and why it is held up, even one that turns sync off.
  A relay or a bootnode is never held up: it does not start. The first
  start of an earlier version, which held a node up too, is gone (rule 9).

### 3.19 Shared Channels

> **v1 status.** The routes under `/api/v1/shared/` are those of decision
> 2026-10-10 §5.6, which gives their bodies and answers. Two notes here.

- **`POST /api/v1/shared/anew`** is the route of `cordelia shared reset`,
  `shared anew` before: the command was renamed, and the route keeps its
  name (decision 2026-11-11 (plain words) §3).
- **`POST /api/v1/shared/accept`,** after its yes, answers `key`, the key
  typed; `words`, its six; `label`, the name the person gave that key in
  shared channels, empty where none (decision 2026-11-11 (plain words));
  `typed_at`; and `until`, when the device stops asking for its share.

---

## 4. Channel ID Formats

> **v1 status.** The ID of a channel from its secret is the public half of a
> signing key derived from that secret, written `cordelia_ch1...`
> (data-formats.md §9.1). The local API of a device takes a name and never an
> ID.

Gone (decision 2026-11-10 (older kind), rule 2): the named, DM and group
IDs were those of the older kind of channel.

---

## 5. Channel Name Rules

Gone (decision 2026-11-10 (older kind), rule 2): this was of the older kind of channel.

---

## 6. PSK Distribution

Gone (decision 2026-11-10 (older kind), rule 2): this was of the older kind of channel. A channel from its secret has no key to distribute for each channel: every device of a person derives every channel of that person's own from the one person secret, and a device is handed that secret once, when it is added (decision 2026-10-04 §2.2, §6).

### 6.1 Open Channels

Gone (decision 2026-11-10 (older kind), rule 2): this was of the older kind of channel.

### 6.2 Invite-Only Channels

Gone (decision 2026-11-10 (older kind), rule 2): this was of the older kind of channel.

### 6.3 DMs

Gone (decision 2026-11-10 (older kind), rule 2): this was of the older kind of channel.

---

## 7. API Surface (Greenfield)

Phase 1 is a greenfield build. The existing node API (L1/L2/groups) is reference material, not baseline. The Phase 1 node exposes:

| Namespace | Endpoints | Purpose |
|-----------|-----------|---------|
| `/api/v1/channels/*` | 14 endpoints (this spec, §3.1-§3.14) | Pub/sub, DMs, groups, search, identity, PSK rotation |
| `/api/v1/health` | 1 endpoint (no auth) | Liveness check (`healthy` / `degraded`). See operations.md §8. |
| `/api/v1/status` | 1 endpoint | Node health (authenticated, detailed) |
| `/api/v1/peers` | 1 endpoint | Peer list |
| `/api/v1/diagnostics` | 1 endpoint | Full diagnostics |
| `/api/v1/metrics` | 1 endpoint (§3.15) | Prometheus exposition (WP13) |

**Not carried forward from the existing API:**
- `l2/*` endpoints -- superseded by channels/publish, channels/listen, channels/delete-item, channels/search
- `groups/*` endpoints -- superseded by channels/subscribe, channels/group, channels/group/invite, channels/group/remove
- `l1/*` endpoints -- personal memory is a personal channel in the greenfield model (auto-created at `cordelia init`)
- `devices/*` endpoints -- portal enrollment deprecated, replaced by local `cordelia init`

This is a clean break. Zero backward compatibility with the pre-pivot API. No migration path needed (no external adoption to protect).

> **v1 status.** The namespaces a node serves in this version, by role:
>
> | Namespace | Personal node | Relay, bootnode |
> |-----------|---------------|-----------------|
> | `/api/v1/channels/*` | `publish`, `entries`, `delete-key`, `identity` for the names it holds (§3.16) | `identity` alone (§3.14). The Channels API of the older kind (§3.1 to §3.13) is gone (decision 2026-11-10 (older kind), rule 2) |
> | `/api/v1/devices/*`, `/api/v1/phrase/make`, `/api/v1/change/*` | A person's devices (§3.17) | Served |
> | `/api/v1/sync/*`, `/api/v1/history/*` | Sync and local history (§3.18) | Served |
> | `/api/v1/status`, `/api/v1/metrics`, `/api/v1/metrics/load`, `/api/v1/health`, `/api/v1/peers` | Yes | Yes |
>
> `/api/v1/diagnostics` is not served.

---

## 8. SDK Mapping

Gone (decision 2026-11-10 (older kind), rule 2): this was of the older kind of channel. The SDK it maps for is deferred, and the routes it maps to are gone.

---

## 9. Rate Limits and Quotas

### 9.1 Phase 1 Rate Limits (localhost)

Gone (decision 2026-11-10 (older kind), rule 2): this was of the older kind of channel. Its routes are gone.

### 9.2 Phase 2+ Rate Limits (keeper-enforced, remote access)

Gone (decision 2026-11-10 (older kind), rule 2): this was of the older kind of channel.

### 9.3 Storage Quota Enforcement (E5)

Gone (decision 2026-11-10 (older kind), rule 2): this was of the older kind of channel.

### 9.4 Rate Limit Response Format

Rate limit responses return `429` with:
```json
{
  "error": {
    "code": "rate_limited",
    "message": "Rate limit exceeded",
    "retry_after_seconds": 5
  }
}
```

---

## 10. Delivery Model

### 10.1 Semantics

Gone (decision 2026-11-10 (older kind), rule 2): this was of the older kind of channel.

### 10.2 Guarantees

Gone (decision 2026-11-10 (older kind), rule 2): this was of the older kind of channel.

### 10.3 Phase 2: Server-Sent Events

Gone (decision 2026-11-10 (older kind), rule 2): this was of the older kind of channel.

### 10.4 Reference Standards

Gone (decision 2026-11-10 (older kind), rule 2): this was of the older kind of channel.

---

## 11. PSK Discovery (Multi-Node)

Gone (decision 2026-11-10 (older kind), rule 2): this was of the older kind of channel.

---

## 12. Resolved Questions

Gone (decision 2026-11-10 (older kind), rule 2): this was of the older kind of channel.

---

## 13. References

- **specs/ecies-envelope-encryption.md**: Cryptographic primitives (ECIES, AES-256-GCM, Bech32 encoding, CBOR signing, AAD binding)
- **cordelia-core/docs/reference/api.md**: Pre-pivot node API (reference only, not carried forward)
- **[decisions/2026-03-09-mvp-implementation-plan.md](https://github.com/seed-drill/cordelia-node/blob/c3cc5756/docs/archive/decisions/2026-03-09-mvp-implementation-plan.md)**: WP3 scope and endpoint definitions
- **[decisions/2026-03-09-architecture-simplification.md](https://github.com/seed-drill/cordelia-node/blob/82f370f6/docs/decisions/2026-03-09-architecture-simplification.md)**: Provider interface, channel encryption model
- **[decisions/2026-03-10-identity-privacy-model.md](https://github.com/seed-drill/cordelia-node/blob/c3cc5756/docs/archive/decisions/2026-03-10-identity-privacy-model.md)**: DM derivation, namespace rules, access policies
- **[decisions/2026-03-10-phase1-design-decisions.md](https://github.com/seed-drill/cordelia-node/blob/82f370f6/docs/decisions/2026-03-10-phase1-design-decisions.md)**: Node is encryption boundary, greenfield build
- **RFC 4287**: Atom Syndication Format (cursor-based polling model)
- **W3C Server-Sent Events**: Push delivery specification (Phase 2)

---

*Draft: 2026-03-10. Review with Martin before implementation.*
