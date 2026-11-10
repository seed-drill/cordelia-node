# Decision: removing the older kind of channel, and one baseline for the schema

**Date**: 2026-11-10
**Status**: Accepted by the person on 10 November ("ok to remove older channels and schema"). To be reviewed, then built in the three slices of section 7.
**Cited as**: "decision 2026-11-10 (older kind), rule 4". The numbers do not change.
**Lines** are main's, c3cc5756 (`v0.2.0-alpha.19`, so its code is how alpha.19 behaves); paths are under `crates/`.

## 0. In one page

A relay carries the older kind of channel (a random ID, a ring of keys, a list of members) "for one version" (decision 2026-10-04 §10, step 2). That version is past: every device we know of runs alpha.19. So the older kind goes, with the first start that moved devices off it; the schema's 33 steps fold into one baseline; only alpha.19's database or a new one is taken; and nothing changes on the wire. About 35,000 of some 380,000 lines of Rust go.

## 1. What goes and what stays

**Rule 1. There is one kind of channel, the channel from its secret.** No node of any role stores, sends, fetches or serves anything of the older kind.

**Rule 2. What goes** (rough lines, code and tests):

- **API, ~4,300:** a relay's `/api/v1/channels/*` (`cordelia-api/src/lib.rs:103-131`); `handlers.rs` but for status, metrics, peers, health and identity; `entries.rs`, `verify.rs`, the older types; `tests/entries.rs`; `tests/api_integration.rs:65-1354`.
- **Storage, ~8,700:** `channels.rs`, `items.rs`, `psk.rs`, `search.rs`, `naming.rs`, `first_start.rs`.
- **Crypto, ~1,200:** `channel_state.rs`, `psk_envelope.rs`, `signing.rs`, the swarm keys (`identity.rs:155-192`).
- **Network, ~3,100:** `channel_announce.rs`, `item_sync.rs`, `psk_exchange.rs`, `seen_table.rs`; the older messages (`messages.rs:198-635`) but for rule 7's four.
- **`p2p.rs`, ~7,000 of 14,400:** the older room, fetch, store, outbox and push retries (624-2242, 2451-2645); the loop's older arms (3428, 3599-3730, 3742-3853); inbound push, sync and announce (6062-6328, 6404-6670, 6748-6872); `Rates`' room fields; their tests.
- **Swarm and PAN, ~900,** whose channels are of the older kind: `swarm-init` (`main.rs:3713`), the swarm check (`p2p.rs:3126-3165`), `[swarm]` and `network.trusted_peers` (an old configuration still loads), their removal at start (`main.rs:2636-2669`).
- **The older lines of `cordelia channels`, `stats` and `status`;** the schema's steps, ~6,000 (rule 5); other tests, ~4,500 (rule 10).
- **Constants only the older kind reads.** One that another derives from is folded in, with its value: `MAX_CHANNEL_BYTES_AT_RELAY` into `MAX_ENTRY_CHANNEL_BYTES_AT_RELAY`, `REPUSH_INTERVAL_SECS` into `REALTIME_SYNC_INTERVAL_SECS`.

**Rule 3. What stays, though the older kind used it too:**

- The codec, handshake, keep-alive, peer-sharing, the governor, `Rates`' allowances, and the large permits (`relay_entries.rs:2134-2151` uses them).
- **The timers a device's passes ride on:** `sync_interval` (`p2p.rs:3731`, the whole pass at 3738), `outbox_interval` (3438, the send pass), `gc_interval` (3579, both kinds' deletes).
- **`push_tx` is the older outbox, but the new kind reads `push_tx.is_none()` as "no network"** (`commands.rs:985`, `1023`, `1203`; `carrying.rs:117`, `223`, `262`, `800`). It becomes a flag, `networked`.
- The tables `counters` (`entry_seq` is the new kind's, `entries.rs:116`), `node_meta`, `sync_files`, `index_lines`, `peer_sightings`; `ecies.rs`, for the change entry and shared channels.
- A relay's status, metrics and `cordelia stats` count the one kind, as a device's do (`usage::snapshot_of_a_device` reads `entries`, which a relay fills too). The status loses `outbox_refused` and `key_files_in_place`.

## 2. Which versions

**Rule 4. This version takes over a data directory that alpha.19 left (schema step 33), or makes a new one, and works beside alpha.19 devices and relays, both ways. Nothing older is taken or promised.** Every device we know of runs alpha.19, and alpha.19 still upgrades every release before it (all 33 steps, and the first start): it is the one stepping stone, for a relay as for a device. Steps by tag: alpha.8 10, alpha.9 18, alpha.17 20, alpha.18 32, alpha.19 33.

**Rule 5. The schema is one baseline and the steps after it.**

- **The baseline is alpha.19's schema, exactly:** every table, column, check, index and trigger, and the rows its steps put in an empty database (`counters`, `person_clear_mark`), made in one transaction, at step 33. The 33 steps and their helpers go, with `RELEASED_SCHEMA_VERSION` and `refuse_steps_numbered_otherwise`.
- **Step 34 drops the older kind:** `channels` (with the first start's guard), `channel_members`, `channel_keys`, `dm_peers`, `items` (with its triggers), `search_content`, `search_fts` (with its triggers), `invites`, `state_offers`, `trusted_keys`; the `counters` rows `item_seq`, `item_count`, `item_bytes`; and the `node_meta` keys `personal_channel_id`, `membership.accepted_personal_from`, `sync.claude.activity`, `first_start.done`. Not `sync.claude.last_change`: the sync loop writes it (`main.rs:3326`). Every database runs it, a new one after the baseline, in one transaction that reads the version again, as `migrate_in_one` does.
- **Dropped, not left unread:** left, they would be made in every new database and read by nothing, and a relay's older items would keep their room. The cost: seconds at a relay's cap, and its file keeps its size. A release before alpha.9 started on such a database stops at its first write, with SQLite's words, not the guard's.

**Rule 6. A database below step 33 is refused, as a later one is now** (decision 2026-10-04 §10.1): read before any pragma, nothing changed. A personal node stays up, held (`held.by` is `earlier_database`), and answers only reads; a relay or bootnode does not start; a command that opens it says the same:

> This database is from a Cordelia before 0.2.0-alpha.19 (schema step N). This version cannot open it, and changed nothing.
> To keep it: install 0.2.0-alpha.19, start it once, then install this version again.
> Or start afresh: move <data directory> aside and run `cordelia init`. Then add this device from another of yours, or run `cordelia recover`.

## 3. On the wire

**Rule 7. Every node answers the older kind as an alpha.19 device does, and sends none of it.**

- **The older kind is told apart by the stream's protocol byte** (`messages.rs:40-48`): 0x04 announce, 0x05 sync, 0x06 push. The new kind uses 0x10 to 0x14.
- **Today only a personal node carries none** (`carries_older_kind`, `p2p.rs:2251`). It answers 0x05 with nothing, no channels and no items (`p2p.rs:6360`, 64 answers a stream at most), and refuses 0x04 and 0x06 (`p2p.rs:5833-5848`). That becomes every node's only code.
- **A refusal resets one stream.** The connection and its other streams go on, and nothing is counted against a relay the node lists (`p2p.rs:5306-5319`).
- **No wire change.** The handshake keeps `channel_digest` and `channel_count`, which alpha.19 needs (`messages.rs:121-155`, no default); every node already sends them for no channels (`main.rs:2779`; `connection.rs:243` is never called). Messages are tagged by name (`messages.rs:1274`), so removing the older ones changes no other's bytes. The two sync requests and their two answers stay.
- **The bytes 0x04 to 0x08 are never used again.**

**Rule 8. Beside alpha.19:**

- An alpha.19 device sends nothing of the older kind (`p2p.rs:3741`). An alpha.19 relay asks each device which older channels it holds: a device of this version says none, as alpha.19's do.
- **An alpha.19 relay that lists a relay of this version** asks it, each cycle, for each older channel it holds, and gets nothing; past 63 on one stream, the stream ends until the next cycle. Its older pushes are refused, and dropped after three tries. Entries (0x14) pass as before. So relays that list each other take this version together.

## 4. The first start

**Rule 9. The first start of decision 2026-10-04 §10.1 goes whole:** the copy into `before-<version>`, the step, the guard, the key files, `Held::FirstStart`. A database at step 33 has had that start, unless a command stepped it or it was held for want of room. Such a one has no copy (for going back to alpha.8), step 34 drops its older rows, and what its folders agreed under `grp_` IDs is never read. What is left:

- the data directory's lock (`main.rs:2405`), and rule 6's refusals with `refuse_while_held`;
- `person::judge_kept` (decision 2026-10-24 (removal), rule 12), called at each start of a personal node, not by the first start (`first_start.rs:288` in the API); without `person.judge_kept` it does nothing;
- the notice of folders that stopped syncing (§10.1, rule 3), read and cleared by `cordelia sync status --seen`, never written again;
- **one wording for a device that follows no phrase,** "no recovery phrase yet" (`look.rs:550`). "Not added yet" read the first start's mark (`look.rs:555`), and goes.

## 5. CI and tests

**Rule 10.**

- **CI pins one binary, alpha.19,** in place of alpha.10 and alpha.17 (`ci.yml:17-26`, `57-81`). Their tests go: `msg_e2e.rs:2716`, `shared_e2e.rs:2782` and `2882` (at step 20, which rule 4 refuses).
- **New, on alpha.19:** (a) an alpha.19 relay and one of this build list each other; a laptop on this build uses the alpha.19 relay, a desktop on alpha.19 the other; a memory file and a message go each way, the older asks get nothing, and the link stays up. (b) alpha.19's own `init` makes a database whose schema and rows equal the baseline, but for the random mark. (c) a device and a relay that ran alpha.19, with older rows put in, are taken over: no older table is left, and they sync on.
- **Changed:** the lock test (`person_e2e.rs:4870`) uses an alpha.19 database; the later-database test gains earlier ones (steps 32 and 10, unchanged byte for byte); the answer with nothing (`devices_e2e.rs:4212`, `threat_model.rs:3015`) is tested at a relay too; `first_start_e2e.rs` keeps its tests of the lock, the port, the folder's mode and the refusals.
- **T3 keeps a test for each claim.** Four of its rate tests push the older kind (`threat_model.rs:1924-2104`). A claim with no test over entry pushes (0x13) gets one first.
- **Goes:** the tests of the older kind (`threat_model.rs:2341-3013` among them), of swarm-init, and of each schema step (`schema.rs` from 2333); those of checks and bounds stay.

## 6. Docs

**Rule 11. Each slice makes true the docs it changes:**

- **CLAUDE.md:** one kind of channel; the older structure lines and constants go; the schema is the baseline and step 34. **README:** an upgrade is from alpha.19 only. **WHITEPAPER:** "for one version more" and "for each kind of channel" go.
- **Decision 2026-10-04:** a line at the head of §2.5 and §10: carried to alpha.19, removed by this record. Other records are history.
- **Specs:** `channel-naming.md` to `docs/archive`; `channels-api.md` keeps the device's API; `data-formats.md` gives the baseline and step 34; `network-protocol.md`, rule 7; `operations.md` loses the copy and going back; `parameter-rationale.md`, `configuration.md`, the glossary and `ecies-envelope-encryption.md` lose what is of the older kind.
- **`threat-model.md`:** no "two kinds", no "of the older kind"; test lists by rule 10. **TESTING.md, `deploy/relay/README.md`:** one cap, one pinned binary.

## 7. Slices

No release between them.

1. **Off** (~+600, -1,500): rule 7 for every role; a relay serves no `/api/v1/channels` and counts one kind; rule 10's pin and test (a). Proof: test (a), the answer with nothing at a relay, `cargo test --all`.
2. **Gone** (~-24,000): what slice 1 left unreachable (rules 2, 3), `networked`, T3's tests first. Proof: clippy `-D warnings` finds dead code; the threat model's check that each test it names exists; `device_entries_e2e`, `carry_e2e`, `recover_e2e`, `removal_e2e`.
3. **Baseline** (~+1,400, -11,000): rules 4 to 6 and 9, tests (b) and (c), the docs left. Proof: those tests.

## 8. Risks

- **An alpha.19 peer is harmed** (a refusal taken as a breach, a connection closed): test (a). **A node stops answering 0x05** (its byte gone from `Protocol`): the answer-with-nothing tests.
- **The new kind rode on the older** (timers, `push_tx`, `Rates`, permits): the compiler; the device tests, which fail without a pass; a test that `networked` is set where P2P runs.
- **The baseline is not alpha.19's:** test (b). **Step 34 drops what is read:** test (c), and a test that the schema after it is the baseline less its list.
- **A database below 33 is changed before it is refused:** the refusal tests. **T3 loses a proof:** the threat model's check. **`judge_kept` stops:** its test, moved to the start.
- **A relay's step 34 is slow:** before the release, the new binary opens a copy of each relay's database, timed. **Docs still say "two kinds":** in review, `grep -ri "older kind"` outside `docs/archive` and `docs/decisions` finds only rule 7.
