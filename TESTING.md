# Testing Guide

> **v1 status.** `cargo test --all` runs everything v1 needs,
> including the tests with real processes over QUIC through a relay
> (`crates/cordelia-node/tests/`, below; set `CORDELIA_E2E_KEEP=1` to
> keep the node directories). The toolchain is pinned in `rust-toolchain.toml`,
> so `rustup update stable` is not needed. The Docker topology and scale suites
> below predate v1 and are stale.

## Pre-flight Checks

Before running any tests:

```bash
# Ensure Rust toolchain is current
rustup update stable

# Check workspace compiles
cargo build --all
```

## Local Tests (cargo)

```bash
# All unit + integration tests
cargo test --all

# Specific crate
cargo test -p cordelia-network
cargo test -p cordelia-crypto
cargo test -p cordelia-storage
cargo test -p cordelia-core

# Single test by name
cargo test -p cordelia-network test_batched_sync_two_channels

# With output (for debugging)
cargo test -p cordelia-network -- --nocapture
```

**Baseline:** every test of `cargo test --all` passes. (The count changes with
almost every change: the pull request that changed it last says what it is.)

## Tests with real processes

They are in `crates/cordelia-node/tests/`, and `cargo test --all` runs them.
Each test starts the nodes it needs as processes of their own, on this
machine, with a relay of the test's own: nothing is dialled but localhost,
and each node has a directory of its own, which is removed afterwards.
`CORDELIA_E2E_KEEP=1` keeps each node's directory (its configuration, data
and log), and prints where.

```bash
cargo test -p cordelia-node --test person_e2e
cargo test -p cordelia-node --test memory_e2e
cargo test -p cordelia-node --test carry_e2e
cargo test -p cordelia-node --test recover_e2e
cargo test -p cordelia-node --test devices_e2e
cargo test -p cordelia-node --test relay_entries_e2e
cargo test -p cordelia-node --test device_entries_e2e
cargo test -p cordelia-node --test first_start_e2e
cargo test -p cordelia-node --test msg_e2e
cargo test -p cordelia-node --test threat_model
```

| File | What it covers |
|------|----------------|
| `person_e2e.rs` | The commands a person types for their devices (decision 2026-10-04 §5 to §8), each run as a person runs it: `cordelia phrase`, `add-device`, `accept`, `devices`, `remove-device`, `renew`, `settle` and `init --new-key`. A phrase is made and the relay holds its first change; a device is added by the two commands and every device shows it until it is cleared; a device is removed and the others apply; a key that this device knows nothing of is removed by key, after a typed answer; two changes made apart are settled; a command with no terminal refuses; the phrase is typed a word at a time, with nothing shown of it, and where it is proved a tick says only that a word is of the list; the words typed back at `cordelia phrase` are each held against the word shown, a miss is said after its pause, and the third stops the command; no word of a phrase reaches the node, its log or its files; a command that changes anything refuses a node of another version, and one that makes or asks for a phrase shows no word where the node is held up |
| `memory_e2e.rs` | Memory syncing between a person's devices, in channels from the person's secret, set up with the commands a person types: a phrase is made and the folders are published, and a second device's folders meet them; a removed device's later edit reaches nobody and the others go on syncing; an edit made before a device heard of a change arrives as an edit of the carried version; a device that was off during a removal, where a relay it reaches holds the change and where none does; a relay that is lost before the names went does not end the wait after a change |
| `carry_e2e.rs` | A carry that a person asks for (decision 2026-10-04 §7.3): `cordelia sync carry` brings in what a device that never returned had sent to the relay; a device that comes to sync a name carries it first; what a removed device wrote comes in only by `--from`, at a terminal, with the phrase, and above a version only on a second yes; a generation that a device never held is read with `--phrase` |
| `recover_e2e.rs` | `cordelia recover` (decision 2026-10-04 §9), on a machine that follows no phrase: a person who lost both devices recovers what either had sent, and no word of the phrase reaches the node, a log or a file; nothing of a device in someone else's hands comes in but by `--from`; a device that the person still has stops, and is added again; a recovery that was cut short is recovered from; two changes made apart are found and settled |
| `devices_e2e.rs` | Two devices of one person, driven through the command line and the local API: a phrase, `add-device` and `accept`, and what one publishes under a name that both hold reaches the other through the relay. Claude memory between two machines; home memory under any name; an edit overtaken while apart; the line of a memory that comes back; local history and its restore. Relays that are down, that lose their database and are filled again; a node's stopping on each signal; a personal node that listens on nothing. The older kind of channel as a relay carries it, shown with a stand-in that speaks its streams. And the harness itself: it starts no node that would dial another machine |
| `relay_entries_e2e.rs` | A relay that carries channels from their secrets, beside the older kind (decision 2026-10-04 §2.4, §2.5). The test is the client: it opens the streams itself. A client with a channel's secret pushes, proves and pulls; one with only the channel's ID gets nothing; a show, whole and short; a relay near its cap; the allowance of new channels; the limits by address, counted for both kinds together; two relays that work together; a channel unused for 90 days; a personal node that answers none of these streams |
| `device_entries_e2e.rs` | A device's side of its relays (decision 2026-10-04 §4.6, §7.3). The device is in the test's process: the node's own engine over real connections, with a clock of its own that a test runs ahead where a wait is tested. The relays are processes. The show, whole once and short after; leave, when it is given and when it ends; a device that wakes; a device that applies the change its relay holds before it sends anything; what a relay refuses for room; a hand-over that is dropped after two hours; the pair channel of a typed key; the door through which a carry reads a channel that was left; the sweep of the deletes that a device has held for 90 days; a node that is held up makes no pass |
| `first_start_e2e.rs` | A node's first start on this version (decision 2026-10-04 §10.1): a personal node whose database is in the released version's form copies it and moves it on, once, after its port is bound; a relay makes no copy and keeps every older row, and removes the guard from a device's database; a node that cannot bind changes nothing; a second node on the same data directory says so and changes nothing; a node answers while the copy is being made; a first start that cannot be made holds the node up until it can; a database from a later version is refused; a device whose scope was stored on has the notice of what stopped, and its folders sync again once they are mapped |
| `msg_e2e.rs` | Messages between a person's own agents (decision 2026-10-09 §3, §4, §6), each command run as an agent runs it, in a mapped folder: `cordelia msg send`, `msg summary` and `msg read` between two devices through a relay, and `msg log` run by a person at a terminal and into a pipe: every name at a terminal and the folder's agent anywhere else, the hold between two agents that only a yes at a terminal ends, and a message that arrives during its question; the summary announces once, counts the rest, prints nothing on any error and keeps to its 100 ms; the folder from Claude Code's variable, the hook's input and the working directory; the frame a body cannot close; the names `send` takes, a reply's recipient, the rates of a folder and of the device, a body that is too large or does not end; sync off, no phrase and a removed device; that a message changes nothing and reaches no file |
| `threat_model.rs` | That `docs/security/threat-model.md` names, for every claim it marks as tested, tests that exist and run; and the claims that need real processes |

`crates/cordelia-node/tests/common/mod.rs` is the harness they share: it
starts a node, runs a command against it, and asks its local API.

**Commands are run at a pseudo-terminal.** A command that asks a yes, or the
recovery phrase, asks at a terminal, and refuses where its input is not one.
So a test runs the built `cordelia` binary with a pseudo-terminal for its
input and its output, holds the other end, reads what the command says and
types what a person would (`Node::at_terminal`, `AtTerminal`). That a program
with a shell can give a command a terminal is the limit that the decision
record states (§5), and these tests show it. They need a Unix: the tests of
a process that cannot be dumped or traced run on Linux only.

**`CORDELIA_SEQUENCES`.** `crates/cordelia-sync/src/claude/sequences.rs` runs
sequences of edits, deletes, syncs and changes of a person's devices over
several devices, written and generated, and asks where each text ends. A
device checks both signatures of every entry each time it reads a slot, and
in a test build that is most of what a cycle takes. `CORDELIA_SEQUENCES` is
how many generated sequences a test runs for each number of devices: 1 by
default (a test that runs more runs a small multiple of it), with the
written sequences at one seed each. From `CORDELIA_SEQUENCES=12` everything
is run: every written sequence with every seed and every mix of kinds, and
the generated ones for two, three and four devices.

```bash
CORDELIA_SEQUENCES=12 cargo test -p cordelia-sync sequences
```

**Test vectors.** `docs/reference/step4-test-vectors.json` holds the
derivations of a channel from its secret, the recovery phrase and two
statements. A test in `crates/cordelia-crypto/src/vectors.rs` checks the code
against the file, and fails on any change of a value until the file is
written again, on purpose:

```bash
CORDELIA_WRITE_VECTORS=1 cargo test -p cordelia-crypto vectors
```

**The install script** has tests of its own, which download nothing and
touch no service: `sh scripts/test-install.sh`. CI runs them.

## E2E topology and scale suites (stale)

These suites predate v1 and are stale; `e2e.yml` runs them only on demand.
Run them from the repository root on any Linux host with Docker and the
musl target. They used to run on a self-hosted runner, whose details are in
the private infrastructure docs.

### Docker Cleanup (ALWAYS do this first)

Root-owned key files from Docker need `sudo rm -rf`.

```bash
docker rm -f $(docker ps -aq) 2>/dev/null
docker network prune -f 2>/dev/null
docker volume prune -af 2>/dev/null
sudo rm -rf tests/e2e/scale/s2-* tests/e2e/scale/s3-* tests/e2e/logs tests/e2e/scale/keys
```

### Build + Docker Image

```bash
cargo build --release --target x86_64-unknown-linux-musl --bin cordelia
cp target/x86_64-unknown-linux-musl/release/cordelia cordelia-bin
DOCKER_BUILDKIT=0 docker build --no-cache -t cordelia-test:latest \
  -f tests/e2e/Dockerfile --build-arg BINARY=cordelia-bin .
rm cordelia-bin
```

### S2: Relay Mesh Convergence

Tests relay mesh formation, pull-sync delivery, and item propagation across R relays + 2 personal nodes.

```bash
bash tests/e2e/scale/run-s2.sh 20        # R=20, 42 containers (fast)
bash tests/e2e/scale/run-s2.sh 50        # R=50, 102 containers (full scale)
```

**Known-good baselines (b3e631d):**
- R=20: ~30s mesh, ~10s delivery, 62/62 assertions pass
- R=50: ~185s mesh, ~17s delivery, 152/152 assertions pass

### S3: PAN Swarm Propagation

Tests personal area network (swarm) nodes syncing local-scope channels from their lead.

```bash
bash tests/e2e/scale/run-s3.sh 4         # 2 leads + 8 swarm, 13 containers
```

### T1-T7: Topology Tests

Individual topology scenarios (single relay, multi-relay, etc.).

```bash
bash tests/e2e/run-e2e.sh                # Runs all T1-T7
```

## Test Suites Summary

| Suite | Location | What it tests | Run command |
|-------|----------|---------------|-------------|
| Unit | `crates/*/src/**` | Per-module logic | `cargo test --all` |
| Integration | `crates/cordelia-network/tests/` | Two-node QUIC | `cargo test -p cordelia-network` |
| API | `crates/cordelia-api/tests/` | The local API over HTTP: the routes of a person's devices (`commands_api.rs`), and the Channels API of the older kind | `cargo test -p cordelia-api` |
| Adapter | `crates/cordelia-sync/tests/`, `crates/cordelia-sync/src/claude/sequences.rs` | The Claude Code adapter over memory folders; sequences over several devices | `cargo test -p cordelia-sync` |
| Real processes | `crates/cordelia-node/tests/` | A person's devices, memory sync, a carry by command, recovery, a relay, a device's passes, the first start, the threat model (above) | `cargo test -p cordelia-node` |
| Install script | `scripts/test-install.sh` | What `install.sh` does about a node that is running | `sh scripts/test-install.sh` |
| E2E Smoke (stale) | `tests/e2e/smoke-test.sh` | Single node API as it was before v1: four of its checks no longer match. Its node is given a relay on this machine where nothing listens, so it dials nothing else | `bash tests/e2e/smoke-test.sh` |
| S2 Scale | `tests/e2e/scale/run-s2.sh` | Relay mesh + delivery | `bash tests/e2e/scale/run-s2.sh R` |
| S3 Scale | `tests/e2e/scale/run-s3.sh` | PAN swarm | `bash tests/e2e/scale/run-s3.sh N` |

## Common Failure Modes

| Symptom | Cause | Fix |
|---------|-------|-----|
| `address already in use` | Previous containers still running | Docker cleanup (see above) |
| `permission denied` on key files | Root-owned Docker artifacts | `sudo rm -rf tests/e2e/scale/s2-*` |
| Mesh timeout at large R | Stale Docker networks | `docker network prune -f` first |
| Pull-sync rate limited | 3+ channels per stream (pre-batch) | Batched sync (§4.5) fixes this |
| `cargo build` fails on VM | Missing musl target | `rustup target add x86_64-unknown-linux-musl` |

## Post-Test Verification

After S2/S3 pass, tag the known-good state:

```bash
git tag s2-passing-$(git rev-parse --short HEAD)
git tag s3-passing-$(git rev-parse --short HEAD)
```

Check relay logs for telemetry:

```bash
docker logs s2-relay-1 2>&1 | grep "p2p heartbeat"
docker logs s2-relay-1 2>&1 | grep "gov: tick complete"
docker logs s2-relay-1 2>&1 | grep "pull-sync cycle"
```
