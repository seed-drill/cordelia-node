# Claude Configuration - cordelia-node

> Inherits global rules from seed-drill/CLAUDE.md (quality over speed, commit format,
> security, no emojis). This file adds cordelia-node-specific context.

## What This Is

Cordelia: an AI agent's memory on every machine its operator uses, end-to-end
encrypted, carried by relays that hold no keys. v1 syncs Claude Code memory
(`crates/cordelia-sync`). Rust workspace, single binary daemon. QUIC transport,
CBOR wire format, Ed25519 per-device identity, AES-256-GCM channel encryption.
A person's devices share one secret, from which every channel of their own is
derived, and a recovery phrase of twelve words removes a device and recovers.
Design: `WHITEPAPER.md` (v3) and two decision records:

- `docs/decisions/2026-10-04-a-persons-devices.md`: a person's devices, the
  recovery phrase, statements, channels from their secrets, what a relay
  does, removal, recovery and the upgrade. It replaces the device, membership
  and key model of the record below.
- `docs/decisions/2026-09-30-agent-memory-sync.md`: the sync adapter, ties,
  conflict copies, deletes, the index, local history and the two relays. Each
  section that the newer record replaces says so at its head.

Code comments cite their sections ("decision 2026-10-04 §4.6", "decision
2026-09-30 §4.5"). There are two kinds of channel in the code: a channel from
its secret (the first record), which every device uses, and "the older kind"
(the second), which a relay carries for one version more and a personal node
does not carry. Specs predate v1: each live spec opens with a "v1 status"
note saying what v1 changed, and pre-v1 documents are in `docs/archive/` (see
its README).

## Repo Structure

```
cordelia-node/
  crates/
    cordelia-core/       # Shared types, config, errors; protocol.rs (every constant);
                         #   revision.rs (a revision as a band and a count); load.rs
                         #   and lock.rs (the counters of the scale test, served at
                         #   /api/v1/metrics/load, and the node's lock, timed by kind)
    cordelia-crypto/     # Ed25519/X25519, ECIES, AES-256-GCM, Bech32. A channel from its
                         #   secret: derive (what comes from a secret), phrase, statement,
                         #   change_entry, entry and wire (an entry, sealed and on the wire),
                         #   chain and version (what an entry was written after; a slot's
                         #   current version), addition, hand_over, proof, fingerprint;
                         #   message (the value of a message, its ID and the ring);
                         #   reached (the value of the carried word, decision 2026-10-19);
                         #   slots (a name's slot, for both kinds).
                         #   The older kind: channel_state, psk_envelope, signing
    cordelia-storage/    # SQLite (schema.rs: steps 1 to 19). entries; person and acts (what a
                         #   device holds of its person, and what a person did at a terminal);
                         #   relay (a relay's channels and room, and its sweeps); at_relays
                         #   (where a device stands at each relay); sync_state, index_lines,
                         #   history; meta (the keys of node_meta); first_start (the copy,
                         #   the step and the guard); messages (step 19: what a device keeps
                         #   of messages between its agents, a generation being a messages
                         #   channel it held; H and the live numbers, the index, places
                         #   and the shown time; a row overwritten before it goes, in the
                         #   caller's write); db (secure_delete, set before the steps run,
                         #   and the truncating checkpoint of a personal node); the older
                         #   kind: channels, items, psk, search
    cordelia-network/    # Governor, codec, rate limiting, mini-protocols; messages.rs has
                         #   the five streams of entries (0x10 to 0x14); transport.rs
                         #   exports the session's value for a proof
    cordelia-api/        # REST API (actix-web). A device: person (applying a statement, who
                         #   counts, carrying), adding, change, leaving, look, names, publish,
                         #   take (the one door for an entry), at_relays (and known: what a
                         #   device knows of which relay holds which change), local (the local
                         #   API for the names a device holds), commands (the routes behind
                         #   the device commands), carry and carrying (a carry that a person
                         #   asks for, and the phrase's word for it), recover, swept (old
                         #   deletes in a device's own store), found (what `map` would sync,
                         #   and the notice), first_start (a node that is held up), sync,
                         #   history; reader (what a device keeps of an entry of the
                         #   messages channel that the door stores, and the hourly task of
                         #   messages); own_read (a read of a channel of the device's own
                         #   with places of its own, kept in memory under its ID: the read
                         #   before a carried name is let go); let_go (what that read
                         #   finds: the entries this device signed, each held where a
                         #   relay handed it or moved its slot on, and when it reads on;
                         #   what a device that has stopped counts from its notes; the
                         #   lines before and after a `discard`);
                         #   sender (what a device does
                         #   to send a message: the next number, its checks, sending again
                         #   and clearing); marks (what an agent read: the device's table
                         #   and its list, the other devices' lists, and whether a message
                         #   is unread);
                         #   messages (the routes of `msg summary`, `msg read`, `msg
                         #   send` and `msg log`: the folder's agent, the message an ID
                         #   names, the seven categories taken out of text another device
                         #   chose, what a relay refused for room, and a person's mark). The
                         #   older Channels API (handlers, entries, verify): a
                         #   relay's and a bootnode's
    cordelia-sync/       # Sync adapters: Claude Code memory <-> the channel of a name
                         #   (claude.rs, plan.rs; claude/sequences.rs is the harness of
                         #   sequences over several devices)
    cordelia-node/       # Binary: CLI (main.rs), person_cmd and terminal (the device
                         #   commands and their prompts), carry_cmd (`sync carry`),
                         #   msg_cmd (`msg summary`, `msg read`, `msg send` and `msg
                         #   log`: the folder, the frame, the cleaning, the lines and
                         #   log's question),
                         #   recover_cmd (`recover`), daemon lifecycle, p2p.rs,
                         #   relay_entries (a relay's side of the streams of entries),
                         #   device_entries (a device's passes, and leave; reach: whether
                         #   each relay can be reached, and its class), indicator (the
                         #   state and the level of a status)
    cordelia-test/       # Test harness: TestNode, TestMesh
  docs/
    specs/               # Protocol and component specs + TLA+ model
    decisions/           # ADRs; 2026-10-04-a-persons-devices.md and
                         #   2026-09-30-agent-memory-sync.md are the current design
    reference/           # Test vectors (step4-test-vectors.json: the derivations),
                         #   network model, risk model
    archive/             # Pre-v1 documents, kept for history
    vision.md            # Direction after v1
  tests/                 # Integration tests
  deploy/relay/          # Relay image, Docker Compose and guide (Fly.io optional)
  scripts/               # Install script
  .github/workflows/     # ci.yml, e2e.yml, release.yml
```

## Key Specs

Start here when working on a module:

| Module | Spec |
|--------|------|
| A person's devices, the recovery phrase, statements, channels from their secrets, a relay's rules, removal, recovery, the upgrade | `docs/decisions/2026-10-04-a-persons-devices.md` |
| The adapter, ties, conflict copies, deletes, the index, the two relays (its device and key model is replaced) | `docs/decisions/2026-09-30-agent-memory-sync.md` |
| Wire format | `docs/specs/network-protocol.md` (Section 3: CBOR tags, framing) |
| Mini-protocols | `docs/specs/network-protocol.md` (Sections 4-8) |
| Governor | `docs/specs/network-behaviour.md` |
| Channels/API | `docs/specs/channels-api.md` |
| Encryption | `docs/specs/ecies-envelope-encryption.md` |
| Data/storage | `docs/specs/data-formats.md` |
| Local history (what sync replaced, and restore) | `docs/decisions/2026-09-30-agent-memory-sync.md` §4.5b |
| Parameters | `docs/specs/parameter-rationale.md` (every value explained) |
| Demand model | `docs/specs/demand-model.md` (persona-derived rates) |
| Identity | `docs/specs/identity.md` |
| Config | `docs/specs/configuration.md` |
| Real-process tests | `crates/cordelia-node/tests/`: `person_e2e.rs` (the device commands, at a pseudo-terminal), `memory_e2e.rs` (memory between devices), `carry_e2e.rs` (`sync carry`, with and without the phrase; the read before a carried name is let go, and the `discard`), `recover_e2e.rs` (`recover`), `devices_e2e.rs` (two devices through a relay; the older kind at a relay), `relay_entries_e2e.rs` (a relay's streams and room), `device_entries_e2e.rs` (a device's passes, the show and leave, a read of its own channel with places of its own), `msg_e2e.rs` (messages between a person's agents: the commands of `msg`), `first_start_e2e.rs` (the first start on this version), `threat_model.rs`, `scale.rs` (the scale test of R1's gate 10, decision 2026-10-22: its parts in `tests/scale/`). `CORDELIA_E2E_KEEP=1` keeps node dirs. See TESTING.md |
| Topology/E2E (stale, manual) | `docs/specs/topology-e2e.md`, `topology-scale.md` |
| TLA+ model | `docs/specs/network-protocol.tla` + `.cfg` |

## Key Parameters (from protocol.rs)

All protocol constants live in `crates/cordelia-core/src/protocol.rs` -- the single source of truth.
Do not add new protocol constants outside `protocol.rs`. All other modules derive from it.

| Parameter | Value | Spec Section |
|-----------|-------|-------------|
| `STREAM_TIMEOUT_SECS` | 10s | parameter-rationale.md §6 |
| `NODE_STOP_TIMEOUT_SECS` | 30s | parameter-rationale.md §6 |
| `MAX_MESSAGE_BYTES` | 1MB | parameter-rationale.md §5.2 |
| `FRAME_LENGTH_BYTES` | 4 (derived: a frame's length, a big-endian u32, before its message) | network-protocol.md §3.1 |
| `MAX_ITEM_BYTES` | 64KB | parameter-rationale.md §4 |
| `ENTRY_OVERHEAD_BYTES` | 1KB (counted for each entry, in every limit on bytes) | parameter-rationale.md §4 |
| `QUIC_KEEPALIVE_INTERVAL_SECS` | 15s | network-protocol.md §2.1 |
| `QUIC_MAX_IDLE_TIMEOUT_SECS` | 60s | network-protocol.md §2.1 |
| `PING_INTERVAL_SECS` | 30s | network-protocol.md §4.2 |
| `DEAD_TIMEOUT_SECS` | 90s | network-protocol.md §4.2 |
| `HOT_MAX` | 2 (personal) | parameter-rationale.md §3 |
| `WARM_MAX` | 10 (personal) | parameter-rationale.md §3 |
| `COLD_MAX` | 50 (personal) | parameter-rationale.md §3 |
| `MIN_WARM_TENURE_SECS` | 300s | parameter-rationale.md §3 |
| `CHURN_INTERVAL_SECS` | 3600s | parameter-rationale.md §3 |
| `EMA_ALPHA` | 0.1 | parameter-rationale.md §3 |
| `MAX_CONNECTIONS_PER_IP` | 5 | network-protocol.md §9.1 |
| `QUIC_MAX_BIDI_STREAMS`, `MAX_CONCURRENT_STREAMS` | 8 (64 with a relay listed by key) | parameter-rationale.md §1 |
| `QUIC_STREAM_RECEIVE_WINDOW`, `QUIC_RECEIVE_WINDOW` | 32,256 bytes a stream, 288KB a connection (derived: two of `SMALL_MESSAGE_BYTES` a connection, and seven eighths of that over `QUIC_MAX_BIDI_STREAMS` a stream, so that every stream fits within the connection's window with the eighth quinn waits for left; 1MB and 2MB with a relay listed by key) | parameter-rationale.md §1 |
| `QUIC_SEND_WINDOW` | 288KB a connection (derived: 2 x `SMALL_MESSAGE_BYTES`; 2MB to a relay listed by key; a write beyond it waits for acknowledgements, and fails after `STREAM_TIMEOUT_SECS`) | parameter-rationale.md §1 |
| `PUSH_BYTES_PER_PEER_PER_MINUTE` | 2MB | parameter-rationale.md §4 |
| `MAX_CHANNEL_BYTES_AT_RELAY` | 16MB | parameter-rationale.md §4 |
| `NEW_CHANNELS_PER_ADDRESS_PER_HOUR` | 16 | parameter-rationale.md §4 |
| `OUTBOX_BYTES_PER_MINUTE` | 1.5MB | parameter-rationale.md §4 |
| `SYNC_PAGE_STEPS` | 100, 14, 3, 1 | parameter-rationale.md §4 |
| `MAX_HANDSHAKE_ROLES`, `MAX_SHARED_PEER_ADDRS` | 8, 8 (lists of the older streams, bounded where they are read) | parameter-rationale.md §1 |
| `SHORTEST_CHANNEL_ID_LEN`, `MAX_LISTED_CHANNEL_IDS` | 40, 24,966 (derived: that many of the shortest ID fill one message) | parameter-rationale.md §1 |
| `MAX_PUSHED_ITEMS` | 2048 (derived: the items of no ciphertext one peer's allowance takes in a minute) | parameter-rationale.md §1 |
| `OUTBOX_FLUSH_INTERVAL_SECS` | 2s | parameter-rationale.md §4 |
| `OUTBOX_REFUSED_RETRY_MAX_SECS` | 600s | parameter-rationale.md §4 |
| `RELAY_ASK_AGAIN_SECS` | 600s | parameter-rationale.md §4 |
| `MAX_CHANNELS_ASKED_OF_A_PEER` | 1024 | parameter-rationale.md §4 |
| `STATE_OFFER_RETRY_BASE_SECS`, `STATE_OFFER_RETRY_MAX_SECS` | 60s, 6h | parameter-rationale.md §4 |
| `MAX_STATE_KEYS` | 1024 | parameter-rationale.md §4 |
| `KEYED_TOMBSTONE_RETENTION_DAYS` | 90 (also a delete among entries, at a relay and on a device) | decision 2026-09-30 §4.4; parameter-rationale.md §12.7 |
| `HISTORY_DAYS`, `HISTORY_MAX_BYTES` | 30, 256MB | parameter-rationale.md §10 |
| `HISTORY_TURN_WAIT_SECS`, `HISTORY_SWEEP_INTERVAL_SECS` | 10s, 3600s | parameter-rationale.md §10 |
| `HISTORY_SWEEP_SHARE` | 8 (swept at a cycle's end once an eighth of the size is kept) | parameter-rationale.md §10 |
| `INDEX_LINE_PAIR_SECS`, `INDEX_LINE_KEPT_DAYS` | 3600s, 90 | parameter-rationale.md §11 |
| `INDEX_LINE_MAX_RECORDS`, `INDEX_LINE_MAX_PUT_BACKS` | 1024, 3 | parameter-rationale.md §11 |
| `INDEX_LINE_LOOK_SECS`, `INDEX_LINE_LOOK_GAP_SECS` | 60s, 30s | parameter-rationale.md §11 |
| `MAX_REV`, `MAX_EPOCH` | 2^53 - 1 | parameter-rationale.md §4 |
| `MAX_EPOCH_STEP` | 2^20 | parameter-rationale.md §4 |
| `FALLBACK_PEERS` | relay1/relay2.cordelia.seeddrill.ai:9474 | decision 2026-09-30 §4.6 |
| `FALLBACK_PEER_KEYS` | the default relays' public keys, in the same order | decision 2026-09-30 §4.6 |

The constants of a channel from its secret (decision 2026-10-04). A value
marked "derived" is computed in `protocol.rs` from the ones it names:

| Parameter | Value | Spec Section |
|-----------|-------|-------------|
| `REV_BAND_BITS`, `REV_COUNT_BITS` | 9, 44 (a revision is a band and a count) | parameter-rationale.md §12.1 |
| `REV_BAND_SIZE`, `REV_BAND_HALF` | 2^44, 2^43 (derived) | parameter-rationale.md §12.1 |
| `MAX_STATEMENT_NUMBER` | 256 (the highest statement, and the highest band) | parameter-rationale.md §12.2 |
| `MAX_STATEMENT_DEVICES`, `MAX_STATEMENT_REMOVED`, `MAX_STATEMENT_CHAIN` | 64, 256, 256 | parameter-rationale.md §12.2 |
| `MAX_DEVICE_LABEL_BYTES`, `STATEMENT_HASH_BYTES` | 64, 16 | parameter-rationale.md §12.2 |
| `MAX_STATEMENT_BYTES` | 20,784 (derived) | parameter-rationale.md §12.2 |
| `CHANGE_ENTRY_BYTES` | 32KB, always | parameter-rationale.md §12.3 |
| `CHANGE_ENTRY_PHRASE_PART_BYTES`, `CHANGE_ENTRY_DEVICES_PART_BYTES` | 4KB, 28KB (derived) | parameter-rationale.md §12.3 |
| `SEALED_SECRET_BYTES`, `MAX_EARLIER_SECRETS` | 92, 8 | parameter-rationale.md §12.3 |
| `MIN_ENTRY_CONTENT_BYTES` | 256 (a content is a power of two from this to `MAX_ITEM_BYTES`) | parameter-rationale.md §12.4 |
| `MAX_ENTRY_LINKS`, `ENTRY_LINK_HASH_BYTES`, `ENTRY_LINK_SIGNER_BYTES` | 100, 16, 16 | parameter-rationale.md §12.4 |
| `MAX_ENTRY_CHAIN_BYTES` | 3,202 (derived) | parameter-rationale.md §12.4 |
| `MAX_ENTRY_NAME_AND_VALUE_BYTES` | 60KB | parameter-rationale.md §12.4 |
| `ENTRY_CLEAR_BYTES`, `ENTRY_WIRE_OVERHEAD_BYTES`, `MAX_ENTRY_WIRE_BYTES` | 233, 237, 65,773 (derived) | parameter-rationale.md §12.4 |
| `PHRASE_WORDS`, `PHRASE_BYTES` | 12, 16 | parameter-rationale.md §12.5 |
| `PHRASE_TYPED_BACK_MISSES`, `PHRASE_MISS_PAUSE_SECS` | 3 (the third word typed back that is not the word shown stops `cordelia phrase`), 2s (before the first miss is said, and twice as long before the second) | parameter-rationale.md §12.5 |
| `PHRASE_QUIET_AFTER_CROSS_SECS` | 1s (after a cross, what is typed is dropped until nothing has been typed for this long; then the same number is asked) | parameter-rationale.md §12.5 |
| `LABEL_*` (28 of them, all in `LABELS`; `LABEL_CARRY_WORD` and `LABEL_CARRY_BATCH` among them, and the three of messages below) | `cordelia v2 ...`, one for each thing derived, signed or sealed | parameter-rationale.md §12.5 |
| `FINGERPRINT_WORDS_SHOWN` | 4 | parameter-rationale.md §12.5 |
| `MAX_ADDITION_BYTES` | 226 (derived) | parameter-rationale.md §12.6 |
| `CHANGE_ENTRY_NAME`, `HAND_OVER_NAME` | `change`, `hand-over` | parameter-rationale.md §12.6 |
| `PAIR_KEY_TYPED_SECS`, `TYPED_KEY_KEPT_SECS`, `HAND_OVER_KEPT_SECS` | 3600s, 86400s, 7200s | parameter-rationale.md §12.6 |
| `MAX_TYPED_KEYS`, `MAX_HAND_OVER_RECORDS` | 8 (within their hour at one time), 2 | parameter-rationale.md §12.6 |
| `HAND_OVER_CHANGE_ENTRY_BYTES`, `MAX_HAND_OVER_BYTES` | 32,960, 54,275 (derived) | parameter-rationale.md §12.6 |
| `MAX_COUNTED_DEVICES`, `MAX_NOT_COUNTED_RECORDS` | 64 (derived), 256 | parameter-rationale.md §12.6 |
| `KEPT_OUT_PER_ADDER` | 3 (derived: the keys that the 64 kept out that each adder that may add keeps, in both bounds of 256) | parameter-rationale.md §12.6 |
| `LEFT_SECRET_KEPT_DAYS` | 90 | parameter-rationale.md §12.6 |
| `PERSONAL_NAME_PREFIX`, `PERSONAL_ADDED_PREFIX`, `PERSONAL_APPLIED_PREFIX`, `PERSONAL_LEFT_PREFIX`, `PERSONAL_APPLIED_SENT` | `name/`, `added/`, `applied/`, `left/`, ` sent` | parameter-rationale.md §12.6 |
| `PERSONAL_REACHED_PREFIX` | `reached/` (the carried word: what a device carried is at the relays it reaches, decision 2026-10-19 rule 4) | parameter-rationale.md §12.6 |
| `REACHED_WORD_MAX_RELAYS`, `REACHED_WORD_MAX_COUNT` | 8 (keys the carried word names; at its bound one content of 512 bytes), 256 (either count) | parameter-rationale.md §12.6 |
| `PROTOCOL_ENTRY_SHOW`, `PROTOCOL_CHANNEL_PROVE`, `PROTOCOL_ENTRY_PULL`, `PROTOCOL_ENTRY_PUSH`, `PROTOCOL_RELAY_ENTRIES` | 0x10, 0x11, 0x12, 0x13, 0x14 | network-protocol.md §4.9 |
| `SESSION_VALUE_BYTES` | 32 | parameter-rationale.md §12.7 |
| `MAX_CHANNELS_PROVED_ON_A_CONNECTION`, `MAX_SLOTS_SHOWN_ON_A_CONNECTION` | 1024 (derived), 8 | parameter-rationale.md §12.7 |
| `CHANNEL_MARK_BYTES` | 8 | parameter-rationale.md §12.7 |
| `ENTRY_PAGE_MAX_ENTRIES`, `ENTRY_PAGE_MAX_BYTES` | 100, 896KB (derived) | parameter-rationale.md §12.7 |
| `RELAY_CHANNELS_PAGE_MAX` | 1000 | parameter-rationale.md §12.7 |
| `MAX_ENTRY_CHANNEL_BYTES_AT_RELAY` | 16MB (derived) | parameter-rationale.md §12.7 |
| `NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR` | 256 | parameter-rationale.md §12.7 |
| `ENTRY_CHANNEL_UNUSED_DAYS`, `ENTRY_CHANNEL_USED_STEP_SECS`, `ENTRY_CHANNEL_SWEEP_INTERVAL_SECS` | 90, 3600s, 3600s (derived) | parameter-rationale.md §12.7 |
| `ENTRY_OFFER_INTERVAL_SECS`, `RELAY_ENTRY_PULL_INTERVAL_SECS` | 5s, 10s (derived) | parameter-rationale.md §12.7 |
| `RELAY_ENTRY_PULL_PAGES`, `RELAY_CHANNEL_PAGES_PER_PASS` | 10, 10 | parameter-rationale.md §12.7 |
| `ENTRY_REQUESTS_PER_PEER_PER_MINUTE`, `OWN_ENTRY_REQUESTS_PER_MINUTE` | 3000, 2250 (derived) | parameter-rationale.md §12.8 |
| `SHOW_ANSWER_ROOM_BYTES` | 66,560 (derived: one entry of the largest size, as it is counted) | parameter-rationale.md §12.8 |
| `SHOW_LEAVE_SECS`, `WAKE_WAIT_SECS` | 10s (derived), 30s | parameter-rationale.md §12.8 |
| `LEAVING_SEND_WAIT_SECS`, `FIRST_FETCH_WAIT_SECS` | 30s, 30s (derived) | parameter-rationale.md §12.8 |
| `CHANNEL_PROOF_AGAIN_SECS` | 86400s | parameter-rationale.md §12.8 |
| `CHANGE_FETCH_MAX_SECS`, `CHANGE_FETCH_PASSES` | 120s, 3 | parameter-rationale.md §12.9 |
| `STATEMENTS_LEFT_SAID_BELOW` | 16 | parameter-rationale.md §12.9 |
| `RECEIVED_LAST_DAY_SECS`, `RECEIVED_LAST_WEEK_SECS` | 86400s, 604800s | parameter-rationale.md §12.9 |
| `CARRY_READ_MAX_SECS`, `CARRY_FIRST_MAX_SECS` | 120s, 180s (derived) | parameter-rationale.md §12.9 |
| `RECOVERY_READ_ON_MAX_SECS`, `RECOVERY_READ_ON_READS` | 615s (derived: a channel at its cap at what one relay hands a minute, and a round more), 5 (derived: the readings that fit in it) | parameter-rationale.md §12.9 |
| `CARRY_FROM_WORDS`, `CARRY_WORD_SECS` | 6, 600s | parameter-rationale.md §12.9 |
| `LET_GO_READ_STANDS_SECS` | 600s (derived: a read before a let-go stands for its `discard`, on the monotonic clock) | parameter-rationale.md §12.9 |
| `CARRY_PART_MAX_BYTES` | 512KB (derived) | parameter-rationale.md §12.9 |
| `LEFT_PROOFS_MARGIN_SHARE`, `CARRY_PROOFS_MADE_AGAIN` | 64 (one place in 64 kept back), 2 | parameter-rationale.md §12.9 |
| `DEVICE_DELETE_SWEEP_INTERVAL_SECS` | 86400s (a device's sweep of old deletes) | parameter-rationale.md §12.9 |
| `LOCAL_API_BODY_MAX_BYTES`, `CARRY_HANDED_MAX_BYTES` | 2MB, 512KB (derived) | parameter-rationale.md §12.9 |
| `RECOVERY_MAX_NAMES`, `RECOVERY_MAX_DEVICES_SHOWN`, `RECOVERY_MAX_LEFT_SECRETS` | 1024, 256, 9 (derived) | parameter-rationale.md §12.9 |
| `FILE_NAME_SHOWN_CHARS` | 120 | parameter-rationale.md §12.9 |
| `STATUS_AMBER_WAIT_SECS`, `REMOVAL_NOT_APPLIED_SHOWN_DAYS` | 300s, 7 | parameter-rationale.md §12.10 |
| `NO_ROOM_STANDS_SECS` | 1200s (derived) | parameter-rationale.md §12.10 |
| `OUT_OF_REACH_SECS` | 300s (derived: `STATUS_AMBER_WAIT_SECS`; a relay not reached, with every attempt at it failed, for this long since its reference is out of reach) | parameter-rationale.md §12.10 |
| `PERSONAL_CHANNEL_HEADROOM_BYTES`, `PERSONAL_CHANNEL_WARN_BYTES` | 4 MiB, 12 MiB (derived: the status warns past it, decision 2026-10-19; nothing is refused) | parameter-rationale.md §12.10 |
| `FIRST_START_RETRY_BASE_SECS`, `FIRST_START_RETRY_MAX_SECS`, `FIRST_START_RETRY_SLACK_SECS` | 5s, 600s (derived), 1s | parameter-rationale.md §12.11 |
| `NODE_LOCK_WAIT_MS` | 500ms (a node that finds its data directory's lock held tries again for this long) | parameter-rationale.md §12.11 |

The constants of messages between your own agents (decision 2026-10-09, and
a person's hold on them, decision 2026-10-25), each with its reason in
parameter-rationale.md §12.12:

| Parameter | Value | Spec Section |
|-----------|-------|-------------|
| `LABEL_AGENT_MESSAGES`, `LABEL_AGENT_MESSAGE_ID`, `LABEL_AGENT_MESSAGE_READ` | `cordelia v2 messages`, `cordelia v2 message id`, `cordelia v2 message read` | parameter-rationale.md §12.12 |
| `AGENT_MESSAGE_PREFIX`, `AGENT_MESSAGE_READ_PREFIX` | `msg/`, `read/` | parameter-rationale.md §12.12 |
| `AGENT_MESSAGE_RING` | 64 (a device's slots for messages; a signer's live numbers; places in an hour; the highest bound a person sets) | parameter-rationale.md §12.12 |
| `AGENT_MESSAGE_CONTENT_BYTES`, `AGENT_MESSAGE_VALUE_BYTES` | 2,048, 1,936 (derived) | parameter-rationale.md §12.12 |
| `AGENT_MESSAGE_BODY_MAX_BYTES`, `AGENT_MESSAGE_NAME_MAX_BYTES` | 1,024, 200 | parameter-rationale.md §12.12 |
| `AGENT_MESSAGE_LINK_OWNER_MAX_BYTES`, `AGENT_MESSAGE_LINK_REPO_MAX_BYTES`, `AGENT_MESSAGE_LINK_NUMBER_MAX_DIGITS`, `AGENT_MESSAGE_LINK_MAX_BYTES` | 39, 100, 10, 151 (derived) | parameter-rationale.md §12.12 |
| `AGENT_MESSAGE_ID_BYTES`, `AGENT_MESSAGE_ID_SHOWN_CHARS`, `AGENT_MESSAGE_READ_MARK_BYTES` | 16, 8, 16 | parameter-rationale.md §12.12 |
| `AGENT_MESSAGE_READ_MARKS_MAX` | 120 (derived) | parameter-rationale.md §12.12 |
| `AGENT_MESSAGE_KEPT_DAYS`, `AGENT_MESSAGE_AHEAD_MAX_SECS`, `AGENT_MESSAGE_SENDS_MAX` | 30, 600s, 4 | parameter-rationale.md §12.12 |
| `AGENT_MESSAGES_PER_FOLDER_PER_HOUR`, `AGENT_MESSAGES_PER_DEVICE_PER_HOUR`, `AGENT_MESSAGE_PAIR_UNREAD_MAX` | 20, 60, 10 | parameter-rationale.md §12.12 |
| `AGENT_MESSAGE_SUMMARY_LINES`, `AGENT_MESSAGE_SUBJECT_CHARS`, `AGENT_MESSAGE_AGENT_NAME_CHARS` | 5, 80, 48 | parameter-rationale.md §12.12 |
| `AGENT_MESSAGE_SUMMARY_WAIT_MS`, `AGENT_MESSAGE_HOOK_INPUT_WAIT_MS`, `AGENT_MESSAGE_HOOK_INPUT_MAX_BYTES` | 100ms, 20ms, 64KB | parameter-rationale.md §12.12 |
| `AGENT_MESSAGE_MARKER_BYTES`, `AGENT_MESSAGE_CLEAR_INTERVAL_SECS` | 6, 3600s (derived) | parameter-rationale.md §12.12 |
| `AGENT_MESSAGE_NUMBER_MAX` | 2^42 - 1 (derived: a clearing's revision stays below `REV_BAND_HALF`) | parameter-rationale.md §12.12 |
| `AGENT_MESSAGE_PERSON_PREFIX`, `AGENT_MESSAGE_PAIR_BOUNDS_PREFIX` | `person/`, `hold/` (a device's lists of what a person read on it and of the bounds a person set on it, decision 2026-10-25, rules 1 and 2) | parameter-rationale.md §12.12 |
| `AGENT_MESSAGE_PAIR_BOUND_SECS`, `AGENT_MESSAGE_PAIR_BOUND_MAX_SECS`, `AGENT_MESSAGE_PAIR_BOUND_MIN_SECS` | 28,800s (`--for` where none is given), 604,800s (the longest, and the `for` of a 10), 60s | parameter-rationale.md §12.12 |
| `AGENT_MESSAGE_PAIR_BOUND_LISTED_SECS` | 605,400s (derived: how long after its `at` a device lists the latest bound it set for a pair, rule 3.5) | parameter-rationale.md §12.12 |

The constants of what a relay holds across its connections (decision
2026-10-22, change F), each with its reason in parameter-rationale.md §13:

| Parameter | Value | Spec Section |
|-----------|-------|-------------|
| `SMALL_PAGE_BYTES` | 131,072 (the most entries in a page for an unlisted peer and in a device's push; the least power of two that holds one entry of the largest size) | parameter-rationale.md §13 |
| `SMALL_MESSAGE_BYTES` | 147,456 (derived: `SMALL_PAGE_BYTES` and 16 KiB for what is around the entries; nothing a device of this version sends or is sent is larger) | parameter-rationale.md §13 |
| `LARGE_MESSAGES_AT_ONCE` | 4 (the large permits a node holds across all its connections; at most one for each /24 or /48) | parameter-rationale.md §13 |
| `ERR_LARGE_MESSAGE_LATER` | 0x05 (a large message the node could not take within `STREAM_TIMEOUT_SECS`, to be sent again) | parameter-rationale.md §13 |
| `QUIC_LISTED_STREAM_RECEIVE_WINDOW`, `QUIC_LISTED_RECEIVE_WINDOW`, `QUIC_LISTED_SEND_WINDOW`, `QUIC_LISTED_MAX_BIDI_STREAMS` | 1MB, 2MB, 2MB, 64 (derived: today's values, for a connection with a relay listed by key, dialled with `connect_with` and accepted with `accept_with`) | parameter-rationale.md §13 |
| `PUSH_RETRY_STREAMS_AT_ONCE` | 4 (derived: half of `QUIC_MAX_BIDI_STREAMS`; the older kind's push retries a node runs to one peer at once, the rest waiting for a later round without spending a try) | parameter-rationale.md §13 |
| `SMALL_WINDOWS_PULL_ENTRIES` | 1 (derived: the entries of the largest size on the wire that a small page holds; what a relay asks a listed relay for in a page where its own end of their connection has every peer's windows, as behind a NAT) | parameter-rationale.md §13 |

## Running Tests

See **[TESTING.md](TESTING.md)** for the full testing guide: pre-flight checks, Docker cleanup,
build steps, all test suites (unit, integration, S2/S3 scale), known-good baselines,
common failure modes, and post-test verification.

Quick reference:
```bash
# All unit + integration tests
cargo test --all

# Specific crate
cargo test -p cordelia-network
cargo test -p cordelia-crypto
```

The constants of the counters of the scale test (decision 2026-10-22 §1,
§7.3), each with its reason in parameter-rationale.md §14:

| Parameter | Value | Spec Section |
|-----------|-------|-------------|
| `LOAD_HISTOGRAM_BUCKETS` | 25 (powers of two of µs from 1 µs to 16 s, and one more) | parameter-rationale.md §14 |
| `LOCK_COUNTED_OVER_MS` | 5, 50, 100, 250 (waits and holds counted apart, for bars 4 and 5) | parameter-rationale.md §14 |
| `LOAD_RELAYS_COUNTED` | 16 (derived: the relays counted apart by key) | parameter-rationale.md §14 |
| `LOCK_HOLD_MEDIAN_NANOS`, `LOCK_TIMING_COST_MAX_NANOS` | 12,000, 120 (derived: what timing a take may cost) | parameter-rationale.md §14 |

## Engineering Principles

1. **Self-defending functions**: Public async functions have built-in timeouts.
   Don't rely on callers to timeout -- if a test can break it, the code handles it.

2. **Minimise timeout diversity**: One value (STREAM_TIMEOUT=10s) at one layer
   (codec) for all stream I/O. Add a new timeout only with documented justification.

3. **Spec is source of truth**: Parameter values derive from `demand-model.md`
   personas. If you change a value, update the spec and the rationale.

## Branch and Merge Workflow

Feature work goes on branches (`feat/X`). Merge to main only after CI passes, including the real-process tests in `devices_e2e.rs`.

1. **Branch from main**: `git checkout -b feat/my-feature`
2. **Small, tested commits**: Each commit independently testable. Never bundle code + test harness changes.
3. **Test after each meaningful change**: Run `cargo test --all` locally; for P2P or sync changes, `cargo test -p cordelia-node --test devices_e2e`.
4. **PR to main**: Squash merge preserves clean history.
5. **Protocol changes get their own branch**: Wire format changes (codec, sync protocol) are never mixed with feature work.

## E2E topology and scale suites (stale)

The Docker topology suite (T1-T7) and the S2/S3 scale runs predate v1 and
are stale; `e2e.yml` runs only on demand. They ran on a self-hosted runner,
whose details are in the private infrastructure docs, not here. To run them
anywhere with Docker: `bash tests/e2e/build-image.sh`, then the scripts in
`tests/e2e/` (`run-e2e.sh`, `scale/run-s2.sh`, `scale/run-s3.sh`). v1 is
covered by `crates/cordelia-node/tests/devices_e2e.rs`.

## Related Repos

- **seed-drill** (private): strategy and planning. Nothing from it belongs in this repository unless it is meant to be public
- **seeddrill-website**: seeddrill.ai (Astro, Cloudflare Pages); `/install.sh` redirects to `scripts/install.sh` here
- **cordelia-sdk**: TypeScript SDK (`@seeddrill/cordelia`), deferred
- **ARCHIVED, do not use:** cordelia-core (old libp2p+JSON+axum implementation), cordelia-proxy,
  cordelia-agent-sdk, cordelia-dashboard, cordelia-portal, rutherford

## What NOT to Do

- Do not reference cordelia-core or the other archived repos for anything.
- Do not treat `docs/archive/` as current; it describes the pre-v1 design.
- Do not put specs in seed-drill. All Cordelia specs live here in docs/specs/.
- Do not add new timeout values without updating parameter-rationale.md.
- Do not change governor defaults without checking demand-model.md derivations.
- Do not add new protocol constants outside `protocol.rs`. All modules derive from it.
