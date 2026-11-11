# Decision: removing the older kind of channel, and one baseline for the schema

**Date**: 2026-11-10
**Status**: Accepted by the person on 10 November ("ok to remove older channels and schema"); reviewed, and its fixes checked, 10 November. Built in the three slices of section 7.
**Cited as**: "decision 2026-11-10 (older kind), rule 4". The numbers do not change.
**Lines** are main's (c3cc5756, `v0.2.0-alpha.19`, whose code is alpha.19's); paths are under `crates/`.

## 0. In one page

A relay carries the older kind of channel (a random ID, a ring of keys, a list of members) "for one version" (decision 2026-10-04 §10, step 2), and every device we know of runs alpha.19. So the older kind goes, with its first start; the schema folds into one baseline; only alpha.19's database or a new one is taken; the wire stays. About 36,000 of some 380,000 lines of Rust go.

## 1. What goes and what stays

**Rule 1. There is one kind of channel, the channel from its secret.** No node of any role stores, sends, fetches or serves anything of the older kind.

**Rule 2. What goes** (rough lines with tests):

- **API, ~4,200:** a relay's older routes (`cordelia-api/src/lib.rs:108-128`; `/identity` stays); `handlers.rs` but status, metrics, peers, health and identity; `entries.rs`, `verify.rs`, the older types; `tests/entries.rs`; `tests/api_integration.rs:118-1209`, `1266-1353`.
- **Storage, ~5,500:** `channels.rs`, `items.rs`, `psk.rs`, `search.rs`, `naming.rs`. **Crypto, ~1,200:** `channel_state.rs`, `psk_envelope.rs`, `signing.rs`, the swarm keys (`identity.rs:155-192`). **Network, ~3,100:** `channel_announce.rs`, `item_sync.rs`, `psk_exchange.rs`, `seen_table.rs`; the older messages (`messages.rs:198-635`) but rule 7's.
- **`p2p.rs`, ~7,000 of 14,400:** room, fetch, store, outbox (624-2242), push retries (2451-2645), the loop's older arms (3428, 3599-3730, 3742-3853), inbound push, sync and announce (6062-6328, 6404-6670, 6748-6872), `Rates`' room fields, and their tests.
- **Swarm and PAN, ~900,** whose channels are of the older kind: `swarm-init` (`main.rs:3713`), the swarm check (`p2p.rs:3126-3165`), `[swarm]` and `network.trusted_peers` (old configurations still load; `accepts_inbound`, `config.rs:97`, then reads `listen` and the role), their removal at start (`main.rs:2636-2669`).
- **The older lines of `cordelia channels`, `stats` and `status`;** the first start, ~3,900 (rule 9); the steps, ~6,000 (rule 5); other tests, ~4,500 (rule 10).
- **Constants only the older kind reads.** A root that a kept constant derives from stays, with its name and value: among them `REPUSH_INTERVAL_SECS` (the entry offer stays at 5 s), `DEFAULT_SYNC_LIMIT`, `MAX_CHANNEL_BYTES_AT_RELAY`, `MAX_CHANNELS_ASKED_OF_A_PEER`, `OUTBOX_REFUSED_RETRY_MAX_SECS`, `OUTBOX_BYTES_PER_MINUTE`, `RATE_LIMIT_HEADROOM`, `SHORTEST_CHANNEL_ID_LEN`. `protocol.rs`'s tests assert each derived value.

**Rule 3. What stays, though the older kind used it too:**

- The codec, handshake, keep-alive, peer-sharing, the governor, `Rates`' allowances, the large permits (`relay_entries.rs:2134-2151`); `max_storage_bytes` and `relay_ask_again_secs`, limits of both kinds (`p2p.rs:2692`, `2756`); `peer_relays`, whose `own_relay` keeps a node from cutting off its own relay on any stream (`p2p.rs:5765-5792`).
- **The timers a device's passes ride on:** `sync_interval` (`p2p.rs:3731`, the whole pass at 3738), `outbox_interval` (3438, the send pass), `gc_interval` (3579, both kinds' deletes).
- **`push_tx` is the older outbox, but the new kind reads `push_tx.is_none()` as "no network"** (eight places: `commands.rs:985`, `1023`, `1203`; `carrying.rs:117` and three more; `let_go.rs:230`). It becomes a flag, `networked`.
- The tables `counters` (`entry_seq` is the new kind's, `entries.rs:116`), `node_meta`, `sync_files`, `index_lines`, `peer_sightings`; `ecies.rs`.
- A relay's status, metrics and `cordelia stats` count entries as a device does, and channels by `relay::count_held`, not names (`handlers.rs:523`). Going: `outbox_refused` (`indicator.rs:864` reads none), `key_files_in_place`, `held.by` `first_start`, `moved_on` (`types.rs:517`), `cordelia_items_total`.

## 2. Which versions

**Rule 4. This version takes over a data directory that alpha.19 left (schema step 33), or makes a new one, and works beside alpha.19 devices and relays both ways. Nothing older is taken or promised.** Every device we know of runs it, and it still upgrades every release before it (all 33 steps, and the first start), so it is the one stepping stone. (Steps: alpha.8 10, alpha.9 18, alpha.17 20, alpha.18 32.)

**Rule 5. The schema is one baseline and the steps after it.**

- **The baseline is alpha.19's schema, exactly:** its `sqlite_master` text, which keeps what `ALTER TABLE` left, and the rows its steps put in an empty database (`counters`, `person_clear_mark`), in one transaction that reads the version again, as `migrate_in_one` does. The 33 steps go, with their helpers, `RELEASED_SCHEMA_VERSION` and `refuse_steps_numbered_otherwise`.
- **Step 34 drops, children first and `channels` (with the guard) last,** as they refer to it with foreign keys on (`schema.rs:46-85`, 2085) and a relay holds a `channels` row for each channel (`p2p.rs:729`): `channel_members`, `channel_keys`, `dm_peers`, `items`, `search_content`, `search_fts`, `invites`, `state_offers`, `trusted_keys` and their triggers; the `counters` rows `item_*`; the `node_meta` keys `personal_channel_id`, `membership.accepted_personal_from`, `first_start.done`, `sync.claude.all`, `sync.claude.notice` (rule 9). `sync.claude.last_change` and `sync.claude.activity` stay: the sync loop uses them (`main.rs:3326`; `cordelia-sync/src/claude.rs:1067`). A new database runs it after the baseline.
- **Dropped, not left unread:** left, they would be made in every new database and read by nothing, and a relay's older items would keep their room. The cost: seconds at a relay's cap; its file keeps its size; a release before alpha.9 run on it by mistake stops at its first write with SQLite's words, not the guard's.

**Rule 6. A database at steps 1 to 32 is refused, as a later one is now** (decision 2026-10-04 §10.1): read before any pragma, nothing changed. A personal node stays up, held (`held.by` `earlier_database`, with words in `indicator.rs:460-465`), answering reads only; a relay or bootnode does not start; a command says the same. The log names the step. The words:

> This database is from a Cordelia before 0.2.0-alpha.19. This version cannot open it, and changed nothing.
> To keep it: install 0.2.0-alpha.19 (`CORDELIA_VERSION=v0.2.0-alpha.19`, for the install command or a relay's image), start it once, then install this version again.
> Or start afresh: move <data directory> aside and run `cordelia init`. Then run `cordelia phrase` on your first device, add this one from another of yours, or run `cordelia recover`.

## 3. On the wire

**Rule 7. Every node answers the older kind as an alpha.19 device does, and sends none of it.**

- **The older kind is told apart by the protocol byte** (`messages.rs:40-48`): 0x04 announce, 0x05 sync, 0x06 push; the new kind uses 0x10 to 0x14.
- **Today only a personal node carries none** (`carries_older_kind`, `p2p.rs:2251`). It answers 0x05 with no channels and no items (`p2p.rs:6360`, 64 answers a stream at most), and refuses 0x04 and 0x06 (`p2p.rs:5833-5848`). That becomes every node's only code.
- **A refusal resets one stream.** The connection and its other streams go on, and nothing is counted against a relay the node lists (`p2p.rs:5306-5319`).
- **No wire change.** The handshake keeps `channel_digest` and `channel_count`, which alpha.19 needs (`messages.rs:121-155`); every node sends them for no channels (`main.rs:2779`). Messages are tagged by name (`messages.rs:1274`). The two sync requests and answers stay, with `ItemHeader` (`messages.rs:276`).
- **The bytes 0x04 to 0x08 are never used again.**

**Rule 8. Beside alpha.19:** an alpha.19 device sends nothing of the older kind (`p2p.rs:3741`); a device of this version tells an alpha.19 relay it holds none, as alpha.19's do. **An alpha.19 relay that lists a relay of this version** asks it each cycle for each older channel it holds, and gets nothing; past 63 on a stream, the stream ends. Its older pushes are refused, and dropped after three tries. Entries (0x14) pass as before. So relays that list each other take this version together.

## 4. The first start

**Rule 9. The first start of decision 2026-10-04 §10.1 goes whole:** both `first_start.rs`, the copy, the step, the guard, the key files, `Held::FirstStart`. A database at step 33 has had it, unless a command stepped it or it was held for want of room: then it has no copy, step 34 drops its older rows, and what its folders agreed under `grp_` IDs is never read. `channel-keys/` and `before-*` folders are left unread; a person may remove them. What is left:

- the data directory's lock (`main.rs:2405`), and rule 6's refusals with `refuse_while_held`;
- `person::judge_kept` (decision 2026-10-24 (removal), rule 12), which the first start calls at every start (API `first_start.rs:250`): the node calls it then instead;
- **one wording for a device that follows no phrase,** "no recovery phrase yet" (`look.rs:550`); "not added yet", which read the first start's mark (`look.rs:555`), goes;
- **a schema step that does not finish** (step 34 where the disk has too little room, as `secure_delete` writes what it frees to the log) changes nothing: a personal node stays up, held (`held.by` `step_failed`), with words that say so and that it needs free room of about the size of its database, and tries again at its next start; a relay or a bootnode does not start, and a command says the same.

Also going: `sync.claude.all`, written only for earlier versions (`sync.rs:180-183`, and at every turn-on, `sync.rs:374`: removing `meta::SYNC_CLAUDE_ALL` lets the compiler find each), with `scope_off_at_start` (`sync.rs:187`); cost: none, as none opens this database. The notice of folders that stopped syncing (§10.1, rule 3), with `--seen` and `stopped_syncing`; cost: a device that has not cleared it stops naming them, and `cordelia sync status` still lists each folder found, with the command that maps it. The panels' `sync status --seen` action, shown only while the notice exists, goes with it.

## 5. CI and tests

**Rule 10.**

- **CI pins one binary, alpha.19,** in place of alpha.10 and alpha.17 (`ci.yml:17-26`, `57-81`). `msg_e2e.rs:2716` and `shared_e2e.rs:2882` go (steps 18 and 20); `shared_e2e.rs:2782`, the one test of a shared channel through an older relay, runs on alpha.19.
- **New, on alpha.19:**
  - (a) An alpha.19 relay and one of this build list each other. The alpha.19 relay holds over 64 older channels, made through its own `/api/v1/channels`, and publishes older items through its own `/api/v1/channels/publish`, which its outbox pushes to the relays it lists (`handlers.rs:269`, `p2p.rs:2053-2056`). So the test needs none of this build's older types, which slice 2 removes. A laptop on this build uses the alpha.19 relay alone, and a desktop on alpha.19 the relay of this build alone, so a file and a message go each way across the two relays: entries (0x14) pass as before. The older asks and pushes get nothing; past 63 on a stream the alpha.19 relay says `sync request failed` of the relay of this build; the link stays up.
  - (b) alpha.19's own `init` makes a database; this build's baseline, before step 34, has the same `sqlite_master` (type, name, table, text, as a set), `user_version` and rows, but the random mark.
  - (c) A device and a relay that ran alpha.19 are taken over, the relay with items in a channel, the device with older rows put in once its guard is dropped (storage `first_start.rs:736`). No older table is left, `sync.claude.activity` is, and they sync on.
- **Changed:** the lock test (`person_e2e.rs:4870`) uses an alpha.19 database; the later-database test gains steps 32 and 10, unchanged byte for byte; the answer with nothing (`devices_e2e.rs:4212`, `threat_model.rs:3015`) runs at a relay too, and sends raw bytes after the protocol byte, since a node refuses before it reads them (`p2p.rs:5840-5848`) and the older message types go in slice 2; the kept metrics test (`api_integration.rs:1213`) is rewritten without the older routes and `cordelia_items_total`; `first_start_e2e.rs` keeps the lock, port, mode and refusal tests.
- **Every threat keeps a test for each claim.** T1, T2, T3, T10, T16, T18 and T20 name tests rule 2 removes (T3 about 20; `threat_model.rs:1672`, `1924-2104` push the older kind). A claim left with none gets a test over entry pushes (0x13) first. T3's "the sender is told which and why" is of the older kind (`messages.rs:684-693`), and is reworded.
- **Goes:** the tests of the older kind (`threat_model.rs:2341-3013` among them), of swarm-init and of each step (`schema.rs` from 2333), but those of checks and bounds.

## 6. Docs

**Rule 11. Each slice makes true the docs it changes:** CLAUDE.md; the README (upgrade from alpha.19 only); the WHITEPAPER; a line at the head of decision 2026-10-04 §2.5 and §10 (other records are history); `channel-naming.md` deleted, as wholly of the older kind (it is at [c3cc5756](https://github.com/seed-drill/cordelia-node/blob/c3cc5756/docs/specs/channel-naming.md)); the specs (API, data formats, protocol, operations, parameters, configuration, ECIES, glossary); `threat-model.md` (rule 10); TESTING.md and `deploy/relay/README.md`.

## 7. Slices

No release between them.

1. **Off** (~+1,200, -3,000): rule 7 for every role; the 0x13 tests and the threat model's lists; every test that needs a node to carry the older kind goes; the pin with its three tests; test (a). Proof: test (a), the answer with nothing at a relay, `cargo test --all`.
2. **Gone** (~-21,000): what slice 1 left unreachable (rules 2, 3) but the first start; the relay's routes and counts; `networked`. Proof: clippy `-D warnings` (dead code), the device tests.
3. **Baseline** (~+1,400, -12,000): rules 4 to 6 and 9, tests (b) and (c), the docs left.

## 8. Risks

- **An alpha.19 peer is harmed, or a node stops answering 0x05:** test (a) and the answer-with-nothing tests. **The baseline is not alpha.19's:** test (b). **Step 34 fails, or drops what is read:** test (c). **A database at steps 1 to 32 is changed:** the refusal tests.
- **The new kind rode on the older** (timers, `push_tx`, `peer_relays`, `Rates`): the compiler, the device tests, a test that `networked` is set where P2P runs. **A threat loses a proof:** the threat model's check. **`judge_kept` stops:** its test.
- **A relay's step 34 is slow:** time the new binary on a copy of each relay's database before the release. **Docs still say "two kinds":** `grep -ri "older kind"` outside `docs/archive` and `docs/decisions` finds only rule 7.
