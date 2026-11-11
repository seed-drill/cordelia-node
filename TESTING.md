# Testing Guide

> **v1 status.** `cargo test --all` runs everything v1 needs,
> including the tests with real processes over QUIC through a relay
> (`crates/cordelia-node/tests/`, below; set `CORDELIA_E2E_KEEP=1` to
> keep the node directories). The toolchain is pinned in `rust-toolchain.toml`,
> so `rustup update stable` is not needed. The Docker topology and scale
> suites of before v1 are removed; they stay in history, at
> [`tests/e2e/`](https://github.com/seed-drill/cordelia-node/blob/c3cc5756/tests/e2e).

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

**What one connection can make a node hold through the kernel's
receive batching of UDP** is measured with a counting allocator in
`crates/cordelia-network/tests/receive_batching.rs`: its test holds a node
under a threshold, and its ignored measurement prints the figures with
the batching off and on at five pacings, to set the threshold from:

```bash
cargo test -p cordelia-network --test receive_batching -- --ignored --nocapture
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

**Tests that wait out a relay's five minutes out of reach,** or a dial's
wait growing to its cap (decision 2026-10-19 §11), are marked `#[ignore]`
with the reason, so that `cargo test --all` does not take longer. The CI
job "out of reach" in `ci.yml` runs the ignored tests of cordelia-node's
test files, and no other crate's, on every pull request: the test files
one after another and the tests of each together, within two hours. The
scale test's ignored tests (`scale.rs`, decision 2026-10-22) are among
them and return at once there: its run of a stage does nothing unless
`CORDELIA_SCALE_STAGE` is set, and its small runs (§6, tests 4 and 5)
nothing unless `CORDELIA_SCALE_SMALL` is set (below). To run the ignored
tests here:

```bash
cargo test -p cordelia-node --tests --no-fail-fast -- --ignored
```

`CORDELIA_TEST_BINARY_BEFORE` names the binary of the version before:
alpha.19, the one release this version works beside and takes over from
(decision 2026-11-10 (older kind), rules 4 and 10). `devices_e2e.rs` runs
it as a relay and as a device in
`a_relay_of_the_version_before_and_one_of_this_build_list_each_other`,
`shared_e2e.rs` as the relay in
`a_relay_carries_a_shared_channel_with_no_change`, and `baseline_e2e.rs`
in its two tests: its `init` makes the database that this build's baseline
makes, and a device and a relay that ran it are taken over. Main's workspace may
say the same version as the release before until the next release is
cut, so the relay's test tells the binary from this build by its bytes,
not by the version it prints. CI downloads it from the release that
`ci.yml` names in `VERSION_BEFORE`, and checks it against the SHA-256
that `ci.yml` names beside it (`VERSION_BEFORE_SHA256`), and not against
a checksum taken from the same release, which would not catch an asset
replaced there. The job's checkout keeps no token on disk while it runs.
Where the variable is not set, each test says so and passes without
running, but where `CI` is `true`, as GitHub sets it, it fails. To run
them here:

```bash
v=v0.2.0-alpha.19
sha=e7f15e59c089a3d839ad77e25b21abd174cf99c1896c21f474822d765ede4bd6
d=$(mktemp -d)
base=https://github.com/seed-drill/cordelia-node/releases/download/$v
curl -fsSL -o $d/cordelia-linux-amd64 $base/cordelia-linux-amd64
echo "$sha  $d/cordelia-linux-amd64" | sha256sum -c - && chmod +x $d/cordelia-linux-amd64
CORDELIA_TEST_BINARY_BEFORE=$d/cordelia-linux-amd64 \
  cargo test -p cordelia-node --test devices_e2e a_relay_of_the_version_before
```

The two values change together: when the version before is to be
another, set `VERSION_BEFORE` to its tag and `VERSION_BEFORE_SHA256` to
the SHA-256 of its `cordelia-linux-amd64`, worked out from the binary
downloaded and checked against the release's published `.sha256`, in one
commit.

```bash
cargo test -p cordelia-node --test person_e2e
cargo test -p cordelia-node --test memory_e2e
cargo test -p cordelia-node --test carry_e2e
cargo test -p cordelia-node --test recover_e2e
cargo test -p cordelia-node --test devices_e2e
cargo test -p cordelia-node --test relay_entries_e2e
cargo test -p cordelia-node --test device_entries_e2e
cargo test -p cordelia-node --test first_start_e2e
cargo test -p cordelia-node --test baseline_e2e
cargo test -p cordelia-node --test msg_e2e
cargo test -p cordelia-node --test shared_e2e
cargo test -p cordelia-node --test joining_e2e
cargo test -p cordelia-node --test threat_model
```

| File | What it covers |
|------|----------------|
| `person_e2e.rs` | The commands a person types for their devices (decision 2026-10-04 §5 to §8), each run as a person runs it: `cordelia phrase`, `add-device`, `accept`, `devices`, `remove-device`, `renew`, `settle` and `init --new-key`. A phrase is made and the relay holds its first change; a device is added by the two commands and every device shows it until it is cleared; a device is removed and the others apply; a key that this device knows nothing of is removed by key, after a typed answer; two changes made apart are settled; a command with no terminal refuses; the phrase is typed a word at a time, with nothing shown of it, and where it is proved a tick says only that a word is of the list; the words typed back at `cordelia phrase` are each held against the word shown, a miss is said after its pause, and the third stops the command; no word of a phrase reaches the node, its log or its files; a command that changes anything refuses a node of another version, and one that makes or asks for a phrase shows no word where the node is held up. The wait after a change and its three ends (decision 2026-10-19 §4, rule 8), with real processes and ignored for their length: a relay that lacks the change and cannot be reached, one that refuses it, one with the wrong key at the address of another, one that comes back within five minutes, and one that holds the change and cannot be reached, said of it by `cordelia devices` after a restart; the status line of a relay not known to hold the latest change after a removal made before the upgrade (decision 2026-10-19, rules 11 and 12); and a wait that cannot be started, which ends with status 3 |
| `memory_e2e.rs` | Memory syncing between a person's devices, in channels from the person's secret, set up with the commands a person types: a phrase is made and the folders are published, and a second device's folders meet them; a removed device's later edit reaches nobody and the others go on syncing; an edit made before a device heard of a change arrives as an edit of the carried version; a device that was off during a removal, where a relay it reaches holds the change and where none does; a relay that is lost before the names went does not end the wait after a change |
| `carry_e2e.rs` | A carry that a person asks for (decision 2026-10-04 §7.3): `cordelia sync carry` brings in what a device that never returned had sent to the relay; a device that comes to sync a name carries it first; what a removed device wrote comes in only by `--from`, at a terminal, with the phrase, and above a version only on a second yes; a generation that a device never held is read with `--phrase` |
| `recover_e2e.rs` | `cordelia recover` (decision 2026-10-04 §9), on a machine that follows no phrase: a person who lost both devices recovers what either had sent, and no word of the phrase reaches the node, a log or a file; nothing of a device in someone else's hands comes in but by `--from`; a device that the person still has stops, and is added again; a recovery that was cut short is recovered from; two changes made apart are found and settled. A recovery's wait for the change at each relay and its judgement of the device it recovers from (decision 2026-10-19 §4, rules 9 and 10), with real processes and ignored for their length: a recovery ends with status 3 where a relay that lacks the change cannot be reached, and with 0 where every relay holds it; and it says before its yes where what was carried is at a relay that it did not read, with both endings |
| `devices_e2e.rs` | Two devices of one person, driven through the command line and the local API: a phrase, `add-device` and `accept`, and what one publishes under a name that both hold reaches the other through the relay. Claude memory between two machines; home memory under any name; an edit overtaken while apart; the line of a memory that comes back; local history and its restore. Relays that are down, that lose their database and are filled again; a node's stopping on each signal; a personal node that listens on nothing. No node carries the older kind of channel: a device and a relay answer what is asked of it with nothing, and a relay of alpha.19 and one of this build list each other and carry a device of each (decision 2026-11-10 (older kind), rules 7 and 10). A relay that cannot be reached from here, dialled as today until a change and amber after it (decision 2026-10-19 §6, rule 11), ignored for its length. And the harness itself: it starts no node that would dial another machine |
| `relay_entries_e2e.rs` | A relay that carries channels from their secrets (decision 2026-10-04 §2.4, §2.5). The test is the client: it opens the streams itself. A client with a channel's secret pushes, proves and pulls; one with only the channel's ID gets nothing; a show, whole and short; a relay near its cap; the allowance of new channels; an entry over the size limit; the limits by address, and small entries counted for what they take; two relays that work together; a channel unused for 90 days; a personal node that answers none of these streams |
| `device_entries_e2e.rs` | A device's side of its relays (decision 2026-10-04 §4.6, §7.3). The device is in the test's process: the node's own engine over real connections, with a clock of its own that a test runs ahead where a wait is tested. The relays are processes. The show, whole once and short after; leave, when it is given and when it ends; a device that wakes; a device that applies the change its relay holds before it sends anything; what a relay refuses for room; a hand-over that is dropped after two hours; the pair channel of a typed key; the door through which a carry reads a channel that was left; a read of a channel of the device's own with places of its own, round by round and outside the database's lock (decision 2026-10-17 §4.2); the sweep of the deletes that a device has held for 90 days; a node that is held up makes no pass. The pass of shared channels (decision 2026-10-10 §8.4), against a stand-in: a shared channel asked only at its relays that the device knows by key, after its own channels; the shared pass's own counter of requests; shared traffic that never refuses the device's own requests or bytes, pages in turn and the two byte shares; a shared request refused for now; and the door of a share pair channel against a relay. What a device knows of each relay (decision 2026-10-19 §1): each answer to a show that says whether the relay holds the change is kept, and every other is a failed attempt; a relay out of reach, refusing, or stuck, through the pass; for how long a relay has lacked the change, and when the device woke, as a status reads them (rule 11); and, with real processes and ignored for its length, a relay that lacks the change dialled every half minute |
| `first_start_e2e.rs` | A node's start (decision 2026-10-04 §10.1): a node that cannot bind its port changes nothing, alpha.19's database among it; a node makes its data directory its owner's alone; a second node on the same data directory says so and changes nothing; a database from a later version, and one from before alpha.19 (decision 2026-11-10 (older kind), rule 6), is refused by the node, which stays up, held, or by a relay, which does not start, and by each command, and nothing of it is changed |
| `baseline_e2e.rs` | alpha.19's schema as this build's baseline (decision 2026-11-10 (older kind), rules 4, 5 and 10), with the binary of alpha.19: test (b), its `init` makes the same definitions, schema version and rows as the baseline, but the random mark; and test (c), a device and a relay that ran it are taken over by this build, no table of the older kind is left, the device keeps what the sync loop reads, and a file goes each way again. Test (c) prints how long step 34 took on the relay's database |
| `msg_e2e.rs` | Messages between a person's own agents (decision 2026-10-09 §3, §4, §6), each command run as an agent runs it, in a mapped folder: `cordelia msg send`, `msg summary` and `msg read` between two devices through a relay, and `msg log` run by a person at a terminal and into a pipe: every name at a terminal and the folder's agent anywhere else, the hold between two agents that only a yes at a terminal ends, and a message that arrives during its question; the summary announces once, marks only the lines it printed, counts the rest, prints nothing on any error and keeps to its 100 ms; the folder from Claude Code's variable, the hook's input and the working directory; the frame a body cannot close; the names `send` takes, a reply's recipient, the rates of a folder and of the device, a body that is too large or does not end; sync off, no phrase and a removed device; that a message changes nothing and reaches no file; the status's `messages` object; a statement, and what a removed device reads; the summary's help |
| `shared_e2e.rs` | Making, sharing and taking a shared channel (decision 2026-10-10, slice 6), each command run as a person runs it, at a terminal: `cordelia shared new`, `share`, `accept <key> --channel`, `label`, `shared list` and `id --words`, between two people's devices that know one relay by its key; a share and an accept in either order, and each device then holding the other's key from its empty anew record; a device added later holding the channel; the two `accept`s kept apart; nothing of the person's own shared; a name never both kinds on one device; a yes at a terminal for each command; the refusals on their streams; a channel only at its relays known by key; and, against a stand-in relay, two shares waiting that take none. Subscribing and messages (slice 7): `subscribe` and `unsubscribe`, the summary's one line and count, a folder that does not subscribe shown nothing, the frame of another person's agent and of the person's own device, a reply that needs its channel, `--to` and `--all` that never reach a shared channel, nothing of reading written in the channel, `log` with a body only at a terminal, no body in any file, and the messages record's routes unchanged. Making anew, moving, a removal and a recovery (slice 8). The status (slice 9): `cordelia status --json` carries the node's `shared` object and sets no level of it, and the device that makes a removal, having made each channel anew, is not amber for it |
| `joining_e2e.rs` | Joining a repository's shared channel by pull request (decision 2026-11-06 (joining), section 12), run as people run it, at a terminal, with real nodes, a relay of the test's own, and real git clones. A bare repository on the disk stands for the host: a merge is a commit pushed there, and a person's `git fetch` brings it into a clone whose `origin` names `github.com/example/project`. The node reads the list from the clone only, and runs git through a script that writes down each command, so a test can say that the node fetched nothing. Each device reads its lists every few seconds, with `[members] read_interval_secs`, which only a test sets (configuration.md §2.13): a member's every 20, a joiner's every 5. Its seven tests are listed below the table. The git of a list's read has its own tests in `crates/cordelia-api/tests/git_list.rs`, against a server of git over HTTPS on loopback (`git http-backend`, in that crate's `tests/common`): a read at the remote's default branch only, never back, a partial clone read without a fetch, and nothing of the person's reaching git, so that nothing asks, at a terminal too. Both need `git` on the `PATH` |
| `removal_e2e.rs` | A removal that fails safe (decision 2026-10-24 (removal), section 7), with relays of the test's own, devices set up with one relay or more, and the secrets a device holds read from its database: a removal made apart from a renewal takes effect without `settle` (test 1); relays that work together spread it (test 2); a removed device that shows old changes pushes no head out (test 5); a device that slept through changes made apart follows the clear one (test 4); a closed device shows every head at a relay that keeps heads, and none above the change followed at one that does not (test 18); nothing a removed device sends after its removal is taken by a device that knows, and what it wrote late is set aside (test 7); a record that hands a removed device the secret closes a device; a device marked to judge the change entries it kept judges them when it starts (rule 12). The window before a device reads a removal is bounded to 90 seconds (test 6): ignored for its length, some minutes, and run in CI's job of the ignored tests |
| `scale.rs` | The scale test of R1's gate 10 (decision 2026-10-22, §4 and §6): a harness of real processes, the release binary, two relays and a stage's devices on loopback, each person on an address of their own. Its run of a stage is ignored, and does nothing without `CORDELIA_SCALE_STAGE` (`100` or `190`; `small` for the small run): `CORDELIA_SCALE_STAGE=100 CORDELIA_SCALE_SEED=1 CORDELIA_SCALE_OUT=/path/to/out cargo test --release -p cordelia-node --test scale a_stage_of_the_scale_test -- --ignored --nocapture`. It leaves `SUMMARY.md`, `report-inputs.json` (every input of the report, §4.4), `samples.jsonl`, `edits.csv` and `pids` in the output; the report is made again from a run's folder alone, as `SUMMARY-again.md` beside the first: `CORDELIA_SCALE_REPORT_FROM=/path/to/out/stage-100-seed-1-relays-2 cargo test --release -p cordelia-node --test scale report_again -- --ignored --nocapture` (with `CORDELIA_SCALE_DEVICE_GROWTH`, bar 6 is judged by it over the run's threshold, and the summary says so). Its tests of itself that start no node run with the others: the population of each stage, the schedule over ten simulated hours and the steps that follow the churns, the observer of edits, the configurations it writes, the checks before a run, the report's bars and checks read from made-up samples, the report made again from a run's folder the same byte for byte, by the run's constants, with bar 6's threshold given to it, and a folder without its inputs, or a file of another version or with a key missing or not known, refused, what it reads of a removal from made-up answers, a read of a node bounded, and a node going with the harness. The small run end to end and the small run that must fail (§6, tests 4 and 5) are ignored, and run only with `CORDELIA_SCALE_SMALL` set, in a release build: `CORDELIA_SCALE_SMALL=1 cargo test --release -p cordelia-node --test scale a_small_run -- --ignored --nocapture`, some minutes each, one after the other. The workflow `scale.yml` runs them when asked for; a machine busy with other work makes a run INVALID (§6, rule 5), and test 5 then fails. The parts of the harness are in `tests/scale/` |
| `threat_model.rs` | That `docs/security/threat-model.md` names, for every claim it marks as tested, tests that exist and run; and the claims that need real processes |

**The seven tests of `joining_e2e.rs`,** each a part of section 12 of the joining record:

- `two_people_join_by_a_merged_pull_request_alone`: the whole join, a message between the two, the amber of a key new on the list until `shared seen`, the list from the clone only, and `unsubscribe` in a clone, after which a new follow names the device already listed.
- `a_device_that_follows_before_the_channel_is_named_waits_and_says_why`: order does not matter; a device that follows first waits, and says what for; its first list with a channel line names the member already listed.
- `a_clone_behind_the_last_commit_read_gives_no_new_list_across_a_restart`: a read of the clone never goes back, across a restart too.
- `only_the_named_channel_is_taken_and_only_keys_on_the_list_are_handed_it`: a share of another channel is not taken, and a key on a local branch or in the working tree is handed nothing.
- `nine_new_keys_with_eight_off_the_ninth_is_handed_the_channel_at_the_third_read`: the turns of rule 4.2.
- `leaving_by_hand_and_coming_back_by_a_pull_request`: a dropped key's amber, `shared anew`'s line, nothing handed before it is merged (by a device left out either), rule 1's gate, and a key brought back, which renames its old channel first.
- `a_removed_device_still_listed_is_never_handed_the_new_channel`: after a removal, by any follower, two of them off at the removal.

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

## Test Suites Summary

| Suite | Location | What it tests | Run command |
|-------|----------|---------------|-------------|
| Unit | `crates/*/src/**` | Per-module logic | `cargo test --all` |
| Integration | `crates/cordelia-network/tests/` | Two-node QUIC | `cargo test -p cordelia-network` |
| API | `crates/cordelia-api/tests/` | The local API over HTTP: the routes of a person's devices (`commands_api.rs`), and a relay's identity, status and metrics | `cargo test -p cordelia-api` |
| Adapter | `crates/cordelia-sync/tests/`, `crates/cordelia-sync/src/claude/sequences.rs` | The Claude Code adapter over memory folders; sequences over several devices | `cargo test -p cordelia-sync` |
| Real processes | `crates/cordelia-node/tests/` | A person's devices, memory sync, a carry by command, recovery, a relay, a device's passes, a node's start, alpha.19's baseline and its takeover, the threat model (above) | `cargo test -p cordelia-node` |
| Install script | `scripts/test-install.sh` | What `install.sh` does about a node that is running | `sh scripts/test-install.sh` |

## Common Failure Modes

| Symptom | Cause | Fix |
|---------|-------|-----|
| Pull-sync rate limited | 3+ channels per stream (pre-batch) | Batched sync (§4.5) fixes this |
| `cargo build` fails on VM | Missing musl target | `rustup target add x86_64-unknown-linux-musl` |
