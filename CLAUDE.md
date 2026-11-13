# cordelia-node

## What this is

Cordelia keeps an AI agent's memory on every machine its operator uses:
end-to-end encrypted, carried by relays that hold no keys. v1 syncs Claude
Code memory, and carries messages between a person's own agents and shared
channels between people. One Rust binary, `cordelia`: QUIC, CBOR, an Ed25519
key per device, AES-256-GCM per channel. A person's devices share one secret,
from which each channel of their own is derived; a recovery phrase of twelve
words removes a device and recovers. Overview: `WHITEPAPER.md` (v3).

There is one kind of channel: a channel from its secret (decision
2026-10-04). "The older kind" (a random ID, a ring of keys, a list of
members) is gone, with its tables and the first start: a node answers what
an alpha.19 node asks of it with nothing (decision 2026-11-10 (older kind),
rule 7). This version takes over only alpha.19's database, or makes a new
one (rules 4 to 6).

## Where things are

- `crates/cordelia-core`: shared types, config, errors; `protocol.rs` holds every protocol constant.
- `crates/cordelia-crypto`: keys and what derives from a secret, the phrase, statements, entries sealed and on the wire, shared channels' cards and shares.
- `crates/cordelia-storage`: SQLite; `schema.rs` has the schema: alpha.19's, as one baseline (`baseline.sql`, never edited), and the numbered steps after it.
- `crates/cordelia-network`: QUIC transport, the codec (framing), the governor, rate limits, the mini-protocols.
- `crates/cordelia-api`: the local REST API (actix-web) and the logic behind each device command.
- `crates/cordelia-sync`: the adapter between Claude Code memory folders and channels.
- `crates/cordelia-node`: the binary: the CLI (`main.rs`), the commands and their prompts (`*_cmd.rs`), the daemon and P2P (`p2p.rs`), a relay's and a device's sides of the entry streams, the status indicator.
- `docs/decisions/`: the records that code comments cite (below).
- `docs/specs/`: protocol and component specs, and the TLA+ model. Most predate v1; those open with a "v1 status" note. `parameter-rationale.md` gives every constant's reason; `demand-model.md` the rates they derive from.
- `docs/security/threat-model.md`: what Cordelia defends against, naming the test of each claim.
- `docs/reference/`: test vectors, the network model, the risk model. `docs/vision.md`: direction after v1.
- `crates/*/tests/`: the integration and real-process tests (below).
- `deploy/relay/`: the relay's image, Compose file and guide. `scripts/install.sh`: the installer, which `release.yml` attaches to each release; `seeddrill.ai/install.sh` redirects to a release's copy, not to main, so a change reaches people with a release.

Module headers that say `Spec: .../specs/<file>.md` mean `docs/specs/<file>.md` here, where that file still exists.

## Decision records

Comments cite a record by its date and section or rule: `decision 2026-10-04 §4.6`, `decision 2026-11-06 (joining), rule 6`. Some add a short name: `(memory)`, `(removal)`, `(joining)`, `(older kind)`. Where two records share a date and no name is given, the subject says which; a bare `decision 2026-10-24` with a rule above 10 is the removal record, and with a lower rule usually the words of a change. In `docs/decisions/`:

- `2026-09-30-agent-memory-sync.md`: the sync adapter, ties, conflict copies, deletes, the index, local history (§4.5b). Its device and key model is replaced by 2026-10-04.
- `2026-10-04-a-persons-devices.md`: a person's devices, the phrase, statements, channels from their secrets, a relay's rules, removal, recovery, the upgrade. The most cited.
- `2026-10-09-messages-between-your-own-agents.md`: `msg` between a person's own agents.
- `2026-10-10-a-shared-channel-for-messages.md`: shared channels between people.
- `2026-10-14-a-personal-node-shares-no-peers.md`: a personal node shares no peers.
- `2026-10-17-a-devices-relays-and-connections.md`: a device's relays, churn, proofs on a connection, a node's role.
- `2026-10-17-recovery-and-carrying.md`: four changes to recovery and carrying.
- `2026-10-19-a-relay-out-of-reach.md`: a relay out of reach, and what the status says of it.
- `2026-10-19-names-at-the-limit.md`: the warning before the personal channel fills a relay's room.
- `2026-10-22-a-scale-test-for-r1.md`: the scale test (`scale.rs`) and its load counters.
- `2026-10-22-memory-across-connections.md` (memory): what a relay holds across its connections; small messages and large permits.
- `2026-10-24-removal-fails-safe.md` (removal): a removal fails safe.
- `2026-10-24-the-words-of-a-change.md`: the words of a change, its waits and its relay lines.
- `2026-10-25-a-persons-hold-on-messages.md`: a person's hold on messages.
- `2026-11-06-joining-by-pull-request.md` (joining): `.cordelia/members`, `subscribe` in a clone, the node's read of each list.
- `2026-11-10-removing-the-older-kind.md` (older kind): no node carries the older kind of channel; one baseline for the schema.
- `2026-11-11-plain-words.md` (plain words): the words a person reads: everyday words, the glossary, and `shared reset`.

The design today is 2026-10-04 with 2026-09-30, and the later records that add to them. Each record's Status line says what is built and what it amends. `2026-11-05` is accepted but not built.

## Engineering rules

1. **A function defends itself.** A public async function has its own timeout; never rely on the caller.
2. **One timeout.** `STREAM_TIMEOUT_SECS` (10 s) at the codec covers all stream I/O. Add another only with its reason in `parameter-rationale.md`.
3. **A node never allocates by a length straight off the wire.** Bound every length a peer chose (by `MAX_MESSAGE_BYTES` or tighter) before reading or allocating by it. Code comments cite this rule as "(CLAUDE.md)".
4. **Constants.** Every protocol constant lives in `crates/cordelia-core/src/protocol.rs`, each with its reason in `docs/specs/parameter-rationale.md`. Never add one elsewhere. Values derive from `docs/specs/demand-model.md`: change a value, and change the rationale with it.
5. **Records' wording is checked by tests.** Tests in `shared_cmd.rs`, `msg_cmd.rs`, `person_cmd.rs`, `main.rs`, `cordelia-api/src/sharing/words.rs`, `cordelia-api/src/following/tests.rs` and `cordelia-api/src/repository_status/tests.rs` read the records of 2026-10-09, 2026-10-10, 2026-11-06 and 2026-11-10 with `include_str!` and assert what a command prints is in them (`RECORD.contains`, `says(`, `as_written(`). Change a line at a prompt, and change the record in the same commit.
6. **The threat model names tests.** `docs/security/threat-model.md` names tests by name, and `the_threat_model_names_tests_that_exist` checks it. Rename a test, then run `cargo test -p cordelia-node --test threat_model`.

## Branches, commits and merges

- Branch from main (`feat/`, `fix/`, `docs/`, `chore/`). Large work goes on a feature branch, built in slices that branch from it.
- A slice, a fix or a docs change merges by squash. Main merging into a feature branch, and a feature branch merging into main, keep a merge commit.
- Merge only with CI green.
- Commit types: `feat`, `fix`, `docs`, `refactor`, `chore`. The first line is under 72 characters.
- A change to the wire format (codec, sync protocol) goes on its own branch, never mixed with feature work.
- Before pushing: `cargo fmt --all`, then `cargo clippy --all-targets -- -D warnings` (as CI runs it).

## Running tests

```bash
cargo test --all                                      # everything, the real-process tests too
cargo test -p cordelia-node --test devices_e2e        # one test file
cargo test -p cordelia-network <name> -- --nocapture  # one test, with output
cargo nextest run                                     # each test in a process of its own, as CI runs them (no doc tests)
cargo nextest run --profile ci --partition slice:1/8  # one of CI's eight shards
```

A pull request's gate (`ci.yml`) is fmt, clippy, the doc tests, and every other test that `cargo test --all` runs: built once, and run by cargo nextest in eight shards at once (`.config/nextest.toml`). The job `test` passes only when all of it passed. The ignored tests of cordelia-node ("out of reach", in two shards) and coverage run on a push to main, each night and by hand, not on a pull request; when one fails, the run on main fails.

The real-process tests are `crates/cordelia-node/tests/*_e2e.rs`, with `scale.rs` and `threat_model.rs`; each starts its own nodes and relay on localhost. `CORDELIA_E2E_KEEP=1` keeps the nodes' directories. Long tests there are `#[ignore]`d, and CI's "out of reach" jobs run them on main. A few tests need the binary of the version before, alpha.19 (`CORDELIA_TEST_BINARY_BEFORE`); without it they pass without running, except in CI. TESTING.md has the rest.

## Public text

This repository is public.

- Examples name no particular machine: say laptop and desktop.
- Name no host, IP or private repository. A private repository holds strategy and planning: nothing from it comes here unless it is meant to be public. Every Cordelia spec lives here, in `docs/specs/`.
- No emojis.
- A security gap is reported privately first. Never push its fix, test or wording here until the owner says.

## What not to do

- Do not use repositories of the older design (a libp2p, JSON and axum build among them). The workspace's own crate `cordelia-core` is live.
- Do not add a protocol constant outside `protocol.rs`, or a timeout without its reason in `parameter-rationale.md`.
- Do not change the governor's defaults without checking `demand-model.md`.
