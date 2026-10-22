# Decision: a scale test for R1

**Date**: 2026-10-22
**Status**: Proposed. Not built. Revised twice after its reviews (sections 9 and 10).
**Cited as**: "decision 2026-10-22 §3, rule 4". The numbers do not change. A number that is not used stays unused.

Words used throughout:

- **The gate** is gate 10 of R1: "The relays carry the load we expect. A scale test at a device count agreed beforehand. Proposed: 500, ten times the traction bar." **The issue** is cordelia-node #46: how many devices and channels one relay carries, and how a mesh of relays behaves as it grows (sync latency, memory, governor behaviour, rate limits).
- **The record of 2026-10-04** is [`2026-10-04-a-persons-devices.md`](2026-10-04-a-persons-devices.md). **The record of relays** is [`2026-10-17-a-devices-relays-and-connections.md`](2026-10-17-a-devices-relays-and-connections.md). **The record of a relay out of reach** is [`2026-10-19-a-relay-out-of-reach.md`](2026-10-19-a-relay-out-of-reach.md). **The demand model** is [`docs/specs/demand-model.md`](../specs/demand-model.md), and **the rationale** is [`docs/specs/parameter-rationale.md`](../specs/parameter-rationale.md).
- **A device** is one node process of the release binary, with role `personal`, a data directory of its own, a configuration of its own and a home directory of its own that holds its memory folders. **A relay** is one such process with role `relay`. Both are started by the harness of section 4, which follows the real-process harness (`crates/cordelia-node/tests/common/mod.rs`) and writes its own configurations.
- **A person** is a set of devices that follow one phrase. Each person's first device makes the phrase, and the others are added with `add-device` and `accept`, at a pseudo-terminal, as `devices_e2e.rs` does.
- **A name** is a memory folder that a person's devices map to one name; its channel is one channel at a relay.
- **The build machine** is one machine of 16 vCPU and 32 GB of memory, with a 290 GB disk, running Ubuntu 24.04, with no Docker and no root.
- **The deployed hosts** are what `deploy/relay` deploys a relay on: the host the README names (1 vCPU and 1 GB), the container of `compose.yml` (`mem_limit: 512m`), and the machine of `fly.relay1.toml` (`memory = "256mb"`).
- **A stage** is one run at a fixed number of devices: 100, 190, 250 or 500 (section 2).
- **A pass** is a device's round of its relays every ten seconds; **a pull** is one request for one channel at one relay; **a show** is a device showing its change entry; **a proof** proves a channel's key on a connection; **a push** sends entries (the record of 2026-10-04, §2.4 and §4.6).
- **A carry** is what each remaining device does when it applies a removal: it writes every current version of every name it holds into the new generation's channels, and sends them (the record of 2026-10-04, §4.2 and §7.3).
- **Churn** is what a node's governor does once an interval (`CHURN_INTERVAL_SECS`, an hour, and up to 300 s of jitter; `governor.rs`, `churn`): warm churn closes a fifth of the warm peers that it may close (`churn_warm`), and hot churn moves peers between hot and warm (`churn_hot`). **A churn** is one time the interval passes and `churn` goes on to them, whatever they then do.
- **The lock** is the one database lock of a node: the `Mutex<Connection>` that every request of the streams of entries takes at a relay, and that the sync cycle, the passes and the local API take on a device. **Its wait** is the time from asking for it to holding it; **its hold** is the time it is held.
- **The window** is the measured part of a run (section 4.2). **The run's summary** is the one file a run leaves for a person to read (section 4.4).
- **Change C, change A and change B** are the three changes of their own that this record proposes beside the test, in that order (section 7): a send window that is set, a relay that closes nothing by warm churn, and the bound on connections.

---

## 0. What this is

The gate asks for a scale test at a device count agreed beforehand. This record proposes that count, says what is measured and how, sets a pass bar for each measure with its reason, and describes a harness that runs on one build machine with real processes. It also proposes three changes that the test, and the relays, need. Nothing is built yet.

**The count.** This record proposes 500 devices, the gate's figure. Whether 500 is the count is the person's to say: it has been asked, and is not yet answered. The stages below 500 are run whatever the answer, and the record holds for another count by the same rules.

Five things are known before anything is built, and they shape the plan.

1. **A connection can make a relay hold about 14.9 MiB today, and the released relays are not safe at their bound.** The send window of a connection is never set (`transport.rs`, `transport_config`), so quinn's default applies: 10,000,000 bytes a connection (quinn-proto 0.11.14). A peer that pulls pages and never acknowledges them leaves up to that much written and held at the relay, beside the 2 MiB it may send unread and the buffers of the message being served (section 2.5). Against the deployed hosts that is about 30 such connections in the container of `compose.yml`, and the bound today is 200. **Change C** sets the send window to two messages, and halves the worst case to about 7.3 MiB. It stands on its own, and is the first change (section 7.1).
2. **R1 as built admits about 199 devices; with change C, its deployed hosts hold about 55 safely.** A relay takes at most 200 inbound connections from any peer (`MAX_INBOUND_CONNECTIONS`), and turns the rest away before the handshake. Every device dials every relay it is set up with, so each relay holds one connection for each device and one for the other relay; more relays do not help. The configuration's `limits.max_inbound_connections` is read by nothing. Derived from the worst case against the deployed hosts (section 2.5), the bound that is safe with change C is 61 in the container of `compose.yml`, 95 on the README's host without a container, and 21 on the machine of `fly.relay1.toml`. **Change B** makes a safe value the default (56), lets a relay on a larger host raise it by its configuration up to a cap (1,024), and says what each deployment file must change. **Carrying 500 devices takes a relay that may hold about 4.2 GiB** (a container of 4.5 GiB, on a host of 6 GB), which is not what the repository deploys. Which host R1's relays run on is the person's choice, and belongs with gate 9 (relays at the cloud edge). Stages 250 and 500 run after change B, with the relays given that bound by their configuration.
3. **A relay's warm churn closes devices' connections and brings in nobody.** Every device is a warm peer of a relay (a relay promotes a peer to hot only while it has fewer than `hot_min`). Warm churn closes a fifth of them and would dial cold peers in their place, but a relay holds no address for a peer that dialled it (`p2p.rs`, `add_peer` with no address), so no dial is even tried. It runs only where a relay has a cold peer, which is whenever any device is off: in use, always. At 500 devices a relay would close about 100 connections an hour, each made again with up to 32 proofs and a whole show of 33 KB, and it may close the link to the other relay. **Change A:** a relay and a bootnode close no connection by warm churn (section 7.4). The test measures the build without change A first, at stages 100 and 190, says what churn cost there, and then measures every stage with change A.
4. **A device pulls each of its channels from each relay every ten seconds,** one request a channel. A person with 30 names asks each relay 192 pulls a minute from each device, each a read of the relay's store under the lock. Measured (section 1.4): an idle pull holds the store for about 12 µs whatever the number of channels, up to 30,000; at 500 devices that is under 1% of the lock's time. The pull that names several channels is not needed for the lock; whether it is needed for anything else (the cost of a stream, the relay's CPU) is what the test answers.
5. **A relay sums its room by reading its table of channels** for each entry that would make a channel larger (`relay::used_bytes`). Measured: about 29 ns a channel held, 80 µs at stage 500's 2,740 channels and 0.87 ms at 30,000. The counter for the room is not needed for the gate by these numbers; the test says whether it is.

**A known limit of R1, and of today's bound:** nothing sheds a connection that stays alive. Each open connection is marked active at every tick (`p2p.rs`, `record_activity`), so the reaping of dead peers never closes one, and QUIC's keep-alive defeats its idle timeout. What is left is a breach of a rate, which cuts a connection off. So whoever holds 200 connections (ten /24s at 20 each), or 56 after change B, holds a relay's slots for as long as they like, and devices are turned away. Churn never helped: a peer it closed dials again at once. This record does not fix it, and says so (section 5).

The record is built in five pieces, each a change of its own (section 7): change C, the counters, the harness, change A and change B.

## 1. What is measured

### 1.1 Rules for every measure

1. **Each measure has a unit, a source and a cadence.** Section 1.2 lists them.
2. **Nothing is read in a way that changes what is measured.** Three kinds of source are used, in this order of preference:
   - **from outside the process:** `/proc/<pid>/status` (memory), `/proc/<pid>/stat` (CPU), `/proc/<pid>/fd` and `/proc/<pid>/task` (descriptors and threads), and files the harness reads in a device's memory folders. None of these touches the node;
   - **counters inside the node, read through a route that takes no lock** (rule 3);
   - **the node's database, read through a read-only SQLite connection,** once every five minutes. The database is in WAL mode (`schema.rs`), so a reader neither waits for the writer nor holds it up, and it is not the node's lock, which is in the process. Only the relay's room is read so.
3. **The counters are new, and are a piece of their own** (section 7.2). They are atomic counters and fixed histograms in the node, served at a new route of the local API, `/api/v1/metrics/load`, in the text form that `/api/v1/metrics` uses. The route checks the bearer token, which takes no lock, and reads the atomics alone. **`/api/v1/metrics` is not used:** it takes the lock to count channels and items (`handlers::metrics_with`), and would be one more request on the lock under test. A device's `/api/v1/status` is read once a minute, for what no counter holds, and that read is one of the device's own takes of its lock.
4. **The lock is timed by a wrapper type.** The lock is taken at about 200 places in 17 files. The counters' piece puts a type around `Mutex<Connection>` whose `lock` and `try_lock` have the same form as today's and return a guard that records its hold when it is dropped, so the places that take it are not changed. Each take names its kind (section 1.2) by the request or task it is in. **The two mutexes taken while the lock is held at a relay, `rates` and `room` (`relay_entries.rs`), are timed too,** and the time a hold spent waiting for them is reported apart, so that a wait on them is not read as a long hold of the store.
5. **The cost of timing is measured and bounded.** Timing a take is two reads of the monotonic clock and a few atomic additions, some tens of nanoseconds against a hold of 12 µs at the least. A unit test of the counters' piece times a million takes with and without the timing; the difference must be under 1% of the median hold of section 1.4, or the timing is sampled (one take in sixteen) instead.
6. **The setup is reported apart from the window,** and so are the parts of the window that the bars treat apart: a relay's outage, and each removal's carry (section 3).

### 1.2 The measures

**Per relay.** Each is read once a minute from `/api/v1/metrics/load` unless it says otherwise.

| Measure | Unit | How it is read |
|---|---|---|
| Requests by kind | requests a minute, for each of: show whole, show short, proof, pull, push, the streams between relays (`0x14`) | A counter for each stream kind, counted when the request is read |
| What became of them | requests a minute, for each of: answered, not now, refused for rate (over the connection's or the address's count, a breach), refused for room, refused for the allowance of new channels | A counter for each answer |
| Bytes | bytes a minute in and out, for each stream kind | Counted at the codec, as each frame is read or written |
| The lock's wait and hold, by kind | µs, as a histogram for each kind of take (buckets of powers of two from 1 µs to 16 s): the reads (pull, short show, proof), the writes (push, a whole show that is taken, the streams between relays), the sweeps and the checkpoint; for each, the count, p50, p99, p99.9 and the most; the count of holds over 5 ms and over 50 ms; and the share of each minute the lock was held | The wrapper of section 1.1, rule 4 |
| The nested mutexes | µs of wait on `rates` and on `room` while the lock is held | The same wrapper |
| Memory | MiB of resident memory (RSS), and its peak | `/proc/<pid>/status`, `VmRSS` and `VmHWM` |
| CPU | share of one core over the minute | `/proc/<pid>/stat`, user and system ticks |
| Connections | connections open; and connections turned away for the bound on connections, for the address and for the subnet, each counted | A gauge read from the node's connections, and a counter for each refusal |
| Written and not acknowledged | bytes, the most over the minute, for the worst connection and across them | Read from quinn's own count for each connection at the sample; with change C it can be no more than the send window |
| Room used | bytes as entries are counted (`entry_cost`), and channels held | Every five minutes, by a read-only connection: `SUM(bytes)` and `COUNT(*)` of `relay_channels` |
| The governor | peers warm and cold, and hot; churns; connections closed by warm churn, of devices and of relays apart; connections closed for any other reason; closures of the link to each listed relay | Counters of the counters' piece. **Churns are counted in `churn`, where the interval has passed, before warm churn looks at its peers:** warm churn returns early where it may close no peer, so a count kept there would read zero for every churn under change A. The hot count is the governor's own, taken at its tick: today `peers_hot` is also written with the count of connections at each registration (`p2p.rs`), so what it says depends on when it is read, and the counters' piece serves the two apart. A relay is expected to show about 1 hot and every other peer warm: with `hot_min` 1 a new peer is warm, and a warm peer is promoted only while hot is below `hot_min`. So R1's "hot 50, warm 50" decide nothing at a relay today |

**Per device.**

| Measure | Unit | How it is read |
|---|---|---|
| Sync latency | seconds, from the moment the harness writes a file on one device to the moment the edit's own line is on another running device of the same person, in the file or in a copy the adapter kept beside it | The harness itself (section 4.2, step 6) |
| Catching up | seconds, from the moment a device is running again after being off to the moment it holds every edit its person made while it was off | The harness, from the same records |
| Memory, CPU, threads, descriptors | as at a relay | `/proc`, once a minute |
| Requests | requests a minute to each relay, by kind; and those it held back by its own pace (`OWN_ENTRY_REQUESTS_PER_MINUTE`) | Counters of the counters' piece |
| Requests refused for rate | requests, in all, for each relay | The same counters; cross-checked against the relay's |
| The lock's wait | µs, a histogram for each kind of take, and the count of waits over 100 ms | The same wrapper |
| What waits to be sent | entries | `outbox_waiting` of `/api/v1/status`, once a minute |
| Conflict copies | files | Counted by the harness at the end |

**Across the mesh.**

| Measure | Unit | How it is read |
|---|---|---|
| A removal's spread | seconds, from the moment `cordelia remove-device` prints "The change is made (change N)" to the moment each other running device of that person has applied change N, and to the moment each relay holds it | The harness timestamps the line as it reads it at the pseudo-terminal. It polls each device's `/api/v1/person` once a second for the applied statement; a relay's holding is read from what each remaining device says of it (`cordelia devices --json`) |
| A removal's carry | seconds, from the same line to the moment each remaining device has sent what it carried and holds every version the other remaining devices carried; and the bytes carried | `outbox_waiting`, what `cordelia devices --json` says the device has sent, and the harness's own count of what each device holds (bar 10) |
| Churn | churns at each relay; connections each closed by warm churn, of devices and of relays; how long each device so closed took to be connected again | The relay's counters; the device's connections in its status, once a minute, and its log line for each connection made |
| A relay that stops | seconds, from the relay's start again to the moment each device set up with it is connected to it again; the relay's requests, lock and memory in the five minutes after | The relay's gauge; each device's status |
| Between the relays | entries a minute passed between the two relays; the latency of the edits of the people whose devices are split between the relays (section 2.2, rule 4); closures of the link | The relay counters of `0x14` and of the governor |

### 1.3 What the harness itself records

For each edit: who wrote it, on which device, in which name and file, its size, and the time it was written. For each other device of the person: the time the edit's line arrived, or that it did not within 300 seconds of the device's running. For each device: each time it was turned off and on, and how. For each process: its pid, its start and its end, and how it ended. For the machine, once a minute: its share of CPU idle and of iowait (`/proc/stat`), its memory available (`/proc/meminfo`), its disk free (`statvfs`), and the disk's mean time for a write over the minute (`/proc/diskstats`: write ticks over writes completed). These say whether the run measured the relays or the machine (section 6, rule 5).

### 1.4 The two measurements taken for this record

Both were throwaway, run on a machine of 4 vCPU and 15 GiB, smaller than the build machine, from the release build of 0.2.0-alpha.14. Neither is committed.

**One: the cost at a relay's store of the requests a device makes, at many channels.** A relay's own store (`cordelia-storage`, `relay.rs`) in a database file, filled through `relay::take` with checked entries: 8 entries of about 400 bytes of text in each channel (content padded to 512 bytes, counted at 1,536), one channel for each address so that the allowance did not refuse them. At each size, 5,000 pulls of channels chosen across the store; 500 sums of the room; 300 entries taken that each grow a channel (each its own write, as a push is); and 300 short shows of an entry held. The figures are µs, p50 and p99.

| Channels held | Entries | An idle pull (at the channel's end) | A first page (8 entries) | A short show | The room's sum (`used_bytes`) | A take that grows a channel |
|---|---|---|---|---|---|---|
| 1,000 | 8,000 | 11 / 32 | 19 / 44 | 15 / 39 | 28 / 57 | 273 / 726 |
| 3,000 | 24,300 | 14 / 44 | 25 / 63 | 18 / 45 | 81 / 118 | 446 / 1,388 |
| 10,000 | 80,600 | 12 / 41 | 23 / 58 | 21 / 57 | 271 / 401 | 721 / 2,346 |
| 30,000 | 240,900 | 12 / 46 | 24 / 69 | 19 / 49 | 868 / 961 | 1,636 / 3,428 |

What it says:

- **An idle pull costs the same at any size:** two lookups by index. At stage 500 a relay is asked about 42,000 pulls a minute (section 2.3), which hold the store for about 0.5 s of each minute: under 1% of the lock.
- **The room's sum grows with the channels held,** about 29 ns each, and a take that grows a channel pays it, beside the write itself (about 200 µs, most of it the commit). At stage 500 (2,740 channels) a growing take costs about 0.45 ms. At 30,000 channels the sum is most of a take.
- What a request costs outside the store (the QUIC stream, the frame, the checks of signatures, the rate counts) is not in these figures. That is what the test measures at the relay as a whole.

**Two: the memory of one device and of one relay, at rest and under a small load.** The real-process harness, with this build's release binary: one relay and two devices of one person, each device with 30 names mapped (the heavy profile of section 2), and then 600 entries of about 2 KB published on one device through its local API, five a second, over its 30 names. RSS from `/proc`, CPU over a minute.

| Moment | Relay: RSS | Device a: RSS | Device b: RSS | CPU (relay / a / b), share of a core |
|---|---|---|---|---|
| Started, connected, no phrase, after 20 s | 19.1 MiB | 19.8 MiB | 19.7 MiB | 0.13% / 0.10% / 0.10% |
| A phrase, b added, 30 names each, idle 60 s | 20.2 MiB | 23.0 MiB | 22.7 MiB | 0.30% / 0.95% / 0.92% |
| Peak during the load | 22.0 MiB | 24.9 MiB | 24.4 MiB | |
| 60 s after the load | 22.1 MiB | 24.9 MiB | 24.9 MiB | 0.27% / 0.98% / 0.97% |

Beside it: each process had 10 to 12 threads and 33 open descriptors; the relay's database was 3.4 MiB and each device's 3.1 MiB after the load; and the last entry was at b 3.1 s after the last was published (through the local API, so with no sync cycle on either side). The nodes logged at `debug`, as the real-process tests' nodes do, which costs CPU; the scale harness logs at `info`.

What it says:

- **A device is about 20 MiB at rest and 25 MiB with 30 names after a load.** Memory grew by about 2 MiB with the 30 names and 2 MiB with the load, and did not grow in the minute after.
- **A heavy device idle costs about 1% of a core,** most of it its pass of 32 channels every ten seconds and its sync cycle every five. A device with no phrase costs a tenth of that.
- **A relay with two devices is about 22 MiB.** What a connection costs at a relay in ordinary use is not shown by two: stages 100 and 190 measure it. The rationale's figure, about 50 KB a connection (§5), has no measurement behind it.

**Threads and descriptors grow with the cores; memory at rest hardly does.** The review measured idle nodes of this build under an affinity mask:

| Node | 1 core | 4 cores | 16 cores (worked out, not measured) |
|---|---|---|---|
| Relay | 4 threads, 21 descriptors, 16.5 MiB | 10 threads, 33 descriptors, 16.9 MiB | about 34 threads, about 81 descriptors |
| Device | 6 threads, 21 descriptors, 18.0 MiB | 11 threads, 33 descriptors, 18.7 MiB | about 34 threads, about 81 descriptors |

A node starts one tokio worker for each core, and actix starts one HTTP worker for each core as well (actix-server's builder, from `available_parallelism`). So on 16 cores 502 nodes have about 17,600 threads. Memory under load at 16 cores is not known: stage 100 measures it before anything larger is run. Descriptors do not grow with connections: QUIC uses one UDP socket for each node.

## 2. The population

### 2.1 Profiles, from the demand model's personas

Three profiles of a person. Each takes what it can from a persona of the demand model as one person sees it on their own devices; what is chosen is said. The Agent Swarm persona is set aside (section 5).

| Profile | Persona (demand model §1) | Devices | Names | Edits an hour, for the person | Size of a memory file | Burst | Off and on |
|---|---|---|---|---|---|---|---|
| Casual | Casual User, §1.1 | 2 | 4 | 10 | 0.5 to 5 KB | 5 edits in 10 s | each device but the active one, half of the time (item 4) |
| Developer | Active Developer Team, one user, §1.2 | 3 | 12 | 20 | 1 to 10 KB | 10 edits in 30 s | each device but the active one, a fifth of the time |
| Heavy | Enterprise, one user, §1.3 | 3 | 30 | 30 | 2 to 20 KB | 20 edits in 60 s | never |

Where each figure comes from:

1. **Devices are chosen.** The Casual persona says "one personal device"; Cordelia v1 is one person's memory on each machine they use, and a person with one device does not use it. Two for a casual user (a laptop and a desktop) and three for the others are chosen, not given by the model.
2. **Names.** The middle of each persona's channels (2 to 5; 5 to 15; 20 to 100), less the channels that are no names: a person's devices also hold a personal channel and a messages channel. The heavy profile's 30 is the figure of the review of 5 October, low in the Enterprise range: past it the requests grow in proportion (section 2.3), and the rationale sizes a device for 256 names.
3. **Edits.** Casual: the persona's steady rate in a session, one memory every 5 to 10 minutes, gives 10 an hour. Enterprise: 5 to 15 a session in 10 to 20 sessions a day, over its working hours, at the top of its range, gives 30. **The Developer's 20 is chosen:** the persona gives 10 to 30 writes a session and 5 to 8 sessions a day, and no session's length, so an hourly rate is not given by it. Every person is active for the whole window: the window is a busy span, not a day.
4. **Off and on.** The demand model gives the Casual persona intermittent availability (a laptop sleeps and travels), the Developer working hours with some members remote, and the Enterprise's personal devices working hours. In the window: each casual device that is not the person's active device is off, in each 30 minutes, with a chance of one half, for a time drawn evenly from 5 to 25 minutes; a developer's, with a chance of one fifth; a heavy person's devices stay on (workstations within working hours). **The rates are chosen;** that devices go off and come back is the model's. Half of the times off are a stop (SIGTERM, and a start again on the same data directory); half are a freeze (SIGSTOP, then SIGCONT), which a relay sees as a connection that goes quiet until QUIC's idle time (60 s) closes it. A freeze is not a sleep: the node's two clocks both run, so it does not wake as from a sleep (the record of 2026-10-04 §16). A true suspend cannot be made without root.
5. **Sizes.** Each persona's item size, drawn evenly on a log scale within the range. Content is padded to a power of two, so a relay counts a 5 KB file at 8 KB plus 1 KB.
6. **Bursts.** Each persona's peak burst, once every 30 minutes for each person, at a time drawn at random, each edit of a burst in a file of its own.
7. **One device at a time.** A person works at one machine at a time. The harness gives each person one active device for each session of 10 to 30 minutes, drawn among the person's devices that are on, and every edit of that session is written there. The active device is never turned off during its session.
8. **Every edit is published.** The adapter reads a folder every 5 s (`CYCLE_SECS`), so a file written twice within a cycle publishes only its second text. The harness never writes a file again on the same device within 15 s (three cycles) of its last write there. So every edit is published, and an edit that is not found is lost.

### 2.2 The mix, and the stages

| Stage | Casual people (devices) | Developers (devices) | Heavy people (devices) | People | Devices | Channels at a relay |
|---|---|---|---|---|---|---|
| 100 | 20 (40) | 14 (42) | 6 (18) | 40 | 100 | 548 |
| 190 | 38 (76) | 27 (81) | 11 (33) | 76 | 190 | 1,034 |
| 250 | 50 (100) | 35 (105) | 15 (45) | 100 | 250 | 1,370 |
| 500 | 100 (200) | 70 (210) | 30 (90) | 200 | 500 | 2,740 |

A person's channels at a relay are their names, the personal channel, the messages channel and the phrase's channel: 7, 15 and 33. (A pair channel, made when a device is added, is not counted: it is used for an hour at setup.)

Rules:

1. **The stages are 100, 190, 250 and 500,** each run on its own from empty data directories. 500 is the gate's figure and the count this record proposes (section 0). 190 is the most that R1 admits as built, with room left at each relay for the other relay's connection and for connections being made again.
2. **Each stage keeps the mix:** two in five people are casual, seven in twenty developers, three in twenty heavy. The population is drawn from a seed (section 4.3, rule 3).
3. **Two relays, as R1 runs them.** Each lists the other, so that they pass entries between them. `relay1.toml` and `relay2.toml` list the other by address alone, and the keys of R1's relays are compiled into the binary; the run's relays have keys of their own, so **the harness lists each relay to the other by address and by key,** and says so in the summary. Each device is set up with both, but for rule 4. A stage is also run once with one relay, at 100 devices, to say what one relay carries alone.
4. **A tenth of the people of each stage, chosen by the seed among those who are not in the office of rule 6, have their devices split between the relays:** the person's first device is set up with the first relay only, and the others with the second only. So an edit between their devices crosses from one relay to the other, and measures that path. It is R1's case of a device that reaches one relay.
5. **Each person but those of rule 6 has an address of their own.** All processes run on the loopback network, and a relay counts connections, requests and new channels by address and by /24 (`MAX_CONNECTIONS_PER_IP` 5, `MAX_CONNECTIONS_PER_SUBNET` 20, the limits for an address at five times those for a connection, `NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR` 256). So each person's devices bind an address of their own in 127.0.0.0/8, one /24 for each person (person k at 127.(20 + k / 256).(k mod 256).1); a person's devices share it, as the devices of a home share one. A device's QUIC endpoint binds the address of its `listen_addr` with port 0 (`transport::create_client_endpoint`), and Linux delivers all of 127.0.0.0/8 to the loopback interface with no setting; a throwaway check showed a datagram sent from 127.0.12.34 arrives from that address. The relays listen on 127.0.0.1, and on nothing else.
6. **An office: three heavy people share one address in the window,** at every stage (9 devices behind one address and one /24, as the Enterprise persona's "corporate workstations, managed network" are, and as homes behind a carrier's NAT are).
   - **They are set up apart.** Adding a device needs a relay, and behind one address only 5 devices reach each relay, so an office set up behind its address could not finish its setup. So each office person is set up on an address of their own, as any other person is (step 3 of section 4.2). Before the window, the harness stops the office's 9 devices and starts them again with the office's one address as their `listen_addr` (step 4).
   - **What is expected:** each relay takes 5 connections from one address (`MAX_CONNECTIONS_PER_IP`), and turns the rest away before the handshake. At each relay, exactly 5 connections from the office's address at every sample; every other dial from it turned away and counted, with no breach and no refusal of the address for a time (a dial turned away before its handshake does not count against the address, the record of a relay out of reach §2); the office's requests far within the address's count. Which devices get in is a race, and nothing frees a slot once taken (heavy devices stay on, and nothing closes a connection that stays alive, section 0), so which of them sync is not known beforehand: a device turned away at both relays syncs nothing, and is counted. The office's people are left out of bars 2, 3, 9, 10 and 13, and bar 14 is theirs.
   - **The limit is accepted for R1, and stated:** behind one address, R1's relays take five devices of Cordelia, and an office or a carrier's NAT with more does not sync whole. Raising the bound for an address weakens what it is for, a cap on what one host can make a relay hold (the rationale §5), and R1's people are single users at home. A later record may revisit it; the office measures it meanwhile, so that what a person behind such an address sees is known and not guessed.
7. **The bound the relays run with.** Stages 100 and 190 are run on the build before change B, with today's bound of 200. Change B makes the default bound 56; from then on the harness gives each relay `limits.max_inbound_connections = 576` (stage 500's 501 connections, and 75 for connections being made again), at every stage, and lists it in the summary as a setting beyond the defaults. Stages 250 and 500 run only after change B: a run on a build that changes a constant for the test alone would measure a relay that nobody runs.

### 2.3 What the model says each stage asks of a relay

From the record of 2026-10-04 (a pull of each channel of the device's own every ten seconds, from each relay; a show for each pass at least; a push for each edit at least) and section 2.1, with every device on. These are what the test checks the harness drives (bar 12), and what the bars are set against.

| | Casual device | Developer device | Heavy device |
|---|---|---|---|
| Channels it pulls (names, the personal channel, the messages channel) | 6 | 14 | 32 |
| Pulls a minute, to each relay | 36 | 84 | 192 |
| Shows a minute, to each relay, at least | 6 | 6 | 6 |
| Proofs when a connection is made | 6 | 14 | 32 |

| Stage | Pulls a minute, at each relay | Shows a minute, at least | Edits a minute, in all | The lock's time on pulls, at 12 µs each |
|---|---|---|---|---|
| 100 | 8,424 | 600 | 11 | 0.10 s a minute |
| 190 | 15,876 | 1,140 | 21 | 0.19 s a minute |
| 250 | 21,060 | 1,500 | 28 | 0.25 s a minute |
| 500 | 42,120 | 3,000 | 55 | 0.51 s a minute |

Devices that are off ask nothing, so the figures of a run are lower by the share of devices off; the harness works the expected figure out from the minutes each device was on. A heavy device asks each relay about 200 requests a minute, under a tenth of its own pace (2,250) and of the relay's count for a connection (3,000).

### 2.4 How many devices fit on the build machine

From section 1.4, with a margin for 16 cores:

| | One | At stage 500 |
|---|---|---|
| Device, memory | 25 MiB measured on 4 cores, 30 MiB allowed | 500 × 30 MiB = 14.6 GiB |
| Relay, memory | 22 MiB with two devices; at most bar 7 | 2 × 252 MiB = 0.5 GiB |
| The harness, memory | | under 0.5 GiB |
| The kernel's cache of 500 databases and logs | | some GiB, given back on demand |
| Device, CPU | about 1% of a core for a heavy device, less for the others; about 0.7% on average | 500 × 0.7% = 3.5 cores, and the edits' own work |
| Relay, CPU | 0.3% of a core with two devices | about 0.3 of a core each, scaled by requests, and at most bar 8 |
| Threads | about 34 for each node on 16 cores | about 17,600 |
| Descriptors | about 81 for each node on 16 cores | about 41,000 in all; the limit is per process |
| Disk | 3 MiB for each database after a small load | under 50 GB with logs, of 290 GB |

**So 500 devices fit on the build machine as it is,** with about half of its memory and more than half of its CPU to spare, and more memory is not asked for. It would be if a device measured above about 55 MiB at stage 250: 500 of them would then leave the machine under the 2 GiB a run needs available (section 6, rule 5), and 64 GB would be asked for before stage 500. The build machine puts no limit of a container on the relays: the bound of section 2.5 is a bound for the deployed hosts, and the run measures what the relays use (bar 7).

**Threads are the ceiling to check.** Every thread is a task, and four limits bound them: the kernel's `pid_max` and `threads-max`, the user's `ulimit -u`, and the `pids.max` of the harness's own cgroup (found from `/proc/self/cgroup` under `/sys/fs/cgroup`), none of which can be raised without root. Before it starts anything the harness works out the threads it needs (each node at about 36 on 16 cores, and what the machine runs already) and reads all four. Where any is under one and a half times that (some 27,000 at stage 500), it plans to start each device under an affinity mask of 4 cores (`taskset`), which sizes both of a device's thread pools to 4, as on a laptop of 4 cores: about 11 threads a device, some 5,500 for 500. **It refuses to start only where a limit is short even so,** and says which. The relays are never masked. The summary says which way the run went.

### 2.5 The bound on connections, derived

The bound exists for a flood, so it is set from what a connection can make a relay hold at worst, against the memory of the host the relay runs on. Each figure is from the code or the rationale. A relay serves a connection's streams one at a time (`p2p.rs`), so a connection has one message in hand at a time.

| What one connection can make a relay hold | At most, with change C | Today | Source |
|---|---|---|---|
| Data sent to the relay and not yet read | 2,048 KiB | 2,048 KiB | `QUIC_RECEIVE_WINDOW` (the rationale §1) |
| Data the relay wrote and the peer has not acknowledged | 2,048 KiB | 9,766 KiB | quinn's `send_window`: not set today, so its default of 10,000,000 bytes; two messages with change C (section 7.1) |
| The frame being read | 1,024 KiB | 1,024 KiB | `codec::read_frame` allocates the length the frame says, up to `MAX_MESSAGE_BYTES`, before it is read |
| The message decoded from it | 1,024 KiB | 1,024 KiB | At most what the frame held, as values |
| The answer, encoded | 1,024 KiB | 1,024 KiB | One message; a page is at most `ENTRY_PAGE_MAX_BYTES` within it |
| The places kept for the peer's channels of the older kind | 230 KiB | 230 KiB | The rationale §4: about 230 bytes for each of at most 1,024 channels of a peer, for as long as a relay carries the older kind |
| The channels proved on it | 48 KiB | 48 KiB | 1,024 IDs of 32 bytes in a hash set (`MAX_CHANNELS_PROVED_ON_A_CONNECTION`) |
| The entries shown whole on it | 4 KiB | 4 KiB | 8 slots (`MAX_SLOTS_SHOWN_ON_A_CONNECTION`) |
| The connection's own state (QUIC's, its tasks, its counts) | 64 KiB | 64 KiB | Allowed here; stages 100 and 190 measure it, and change B sets it from that |
| **In all, W** | **7,514 KiB, about 7.34 MiB** | **15,232 KiB, about 14.9 MiB** | |

**The memory a relay may use.** For a container, its limit. For a host with no container, its memory less what the system keeps (S): 256 MiB is taken for a host of 1 GB, and 32 MiB for a small machine of Fly's; both are stated here, not measured. Of what is left, K = 64 MiB is kept for the relay's fixed part: 22 MiB measured at rest, its store's cache and its other tables. **The bound** is N = (memory − S − K) / W, rounded down.

| Deployed host | Memory for the relay | N today (W = 14.9 MiB) | N with change C (W = 7.34 MiB) |
|---|---|---|---|
| The container of `compose.yml` (`mem_limit: 512m`), the README's way to deploy | 512 MiB | 30 | 61 |
| The README's host, with no container (1 GB) | 768 MiB | 47 | 95 |
| The machine of `fly.relay1.toml` (`memory = "256mb"`) | 224 MiB | 10 | 21 |

**So today's bound of 200 is unsafe on every deployed host:** about 30 connections that pull and do not acknowledge are enough to take the container of `compose.yml` to its limit. With change C, the container holds 61 safely.

**What change B makes of it** (section 7.5):

- **The default bound is 56,** the container's 61 rounded down to a multiple of 8: what the README's way to deploy holds at worst. A relay takes the default unless its configuration says otherwise. With one connection for the other relay, a relay at the default carries 55 devices, just above the traction bar of 50.
- **A relay on a larger host raises it in its configuration** (`limits.max_inbound_connections`), up to a cap that the constant sets. A value above the cap is refused when a relay loads its configuration.
- **The cap is 1,024:** what a relay that may use 7.4 GiB holds at worst (K + 1,024 × W), on a host of 8 GB. It keeps a slip of the pen from setting a bound that no host of R1's kind could hold.
- **Each deployment file says what its host holds:** `compose.yml` keeps `mem_limit: 512m` and the default; `fly.relay1.toml` goes to `memory = "512mb"`, which holds 56 (its 256 MB holds 21, below the default); `relay1.toml` and `relay2.toml` carry a commented `[limits]` line that says the bound and the memory it needs; and the README's section on the host states the bound, the sum, and the host for more.

**What 500 devices take.** A relay that carries 500 devices with room for connections being made again is given a bound of 576, and may then be made to hold K + 576 × W = 4.2 GiB. That is a container of 4.5 GiB (`mem_limit: 4608m`, with the relay's configuration at 576), on a host of 6 GB, or `memory = "4608mb"` on Fly; and two vCPU (bar 8). It is not what the repository deploys. **Which host R1's relays run on is the person's choice,** and belongs with gate 9 (relays at the cloud edge). Until R1's relays run on such a host, R1 carries at most what its hosts hold: 55 devices on the README's way to deploy, with change C and change B.

- **Not taken:** a smaller receive window. It is sized to two messages so that a second exchange can begin while the first is read (the rationale §1), and a page of entries is most of one message; changing it changes the wire's pace for every node, not only the bound.
- **Bar 7 is not this.** Bar 7 bars what a relay uses in ordinary use. This sum bars what it can be made to use.

## 3. The pass bars

A stage passes where every bar below holds, on each of three runs of it (section 4.3, rule 4). Each bar says its reason; a bar that is chosen and not derived says so. **The parts treated apart** are each relay's outage (step 7 of section 4.2, and five minutes after it) and each removal's carry window (bar 10). The office of rule 6 of §2.2 is left out of every bar but bar 14.

1. **No request is refused for rate.** At every stage, in the window: no request refused at either relay for being over a connection's or an address's count, no breach. And no device holds a request back by its own pace, but in the minute of a connection's proofs (decision 2026-10-17 §3) and in a carry window, where it is the design (bar 10) and is reported. **Reason:** section 2.3. The busiest device asks under a tenth of what a relay allows a connection; a refusal at this load is a fault.
2. **Sync latency: p50 at most 12 s, p95 at most 25 s, and every edit arrives within 120 s,** over every edit of the window outside the parts treated apart, and every other device of its person set up with both relays that was running from the edit to its arrival. **Reason:** an edit crosses four waits at most: the writer's sync cycle reads the file (`CYCLE_SECS`, 5 s); the push goes at once at publish (the record of 2026-10-04 §4.6); the reader's next pass pulls it (10 s); the reader's cycle writes the file (5 s). That is 20 s at most and about 10 s on average with no load, so 25 s at p95 leaves 5 s for the load and the machine, and 12 s at p50 leaves 2 s. 120 s is `CHANGE_FETCH_MAX_SECS`: past it, a person would see a file as lost. **This meets the demand model's latency for the Casual persona (§2.5, 5 to 10 s) at its median, and does not meet its latency for the Dev Team (2 to 5 s) or Enterprise (1 to 5 s) personas.** A design that pulls every ten seconds cannot: the model assumed a push to devices, which v1 does not have. The record states it, and leaves the model as it is: amending it is a change of the model's own. **For the people split between the relays**, the bars are p95 at most 40 s and every edit within 120 s: the path adds a relay's offer (5 s) and its pull of the other (10 s).
3. **No edit is lost, and a device catches up.** Every edit's own line is found on every other device of its person by the end of the run, in the file or in a copy the adapter kept beside it; and a device that was off holds every edit its person made meanwhile within 60 s of running again. **An edit counts as arrived only by its own line:** an edit that a later edit replaced before it arrived, with nothing kept of it, is lost, whatever the file says now. **Reason:** that is what sync is for. When a session moves to another device, that device can write a file before the last device's edit has reached it, and sync must keep that edit beside the file (the record of 2026-09-30, conflict copies), not drop it. 60 s: a device that starts waits for its relays for up to 30 s (`WAKE_WAIT_SECS`), then a pass (10 s) and a cycle (5 s), with 15 s for the connection and the start.
4. **A relay's lock, by kind.** In the window, outside the parts treated apart:
   - **(a)** for each kind of take, the wait at p99 at most 10 ms;
   - **(b)** for the reads (pull, short show, proof), the hold at p99 at most 1 ms;
   - **(c)** for every other kind (the writes, the sweeps, the checkpoint), every hold under 250 ms, and at most 10 holds over 50 ms in the window;
   - **(d)** the lock held for at most a quarter of any minute.

   **Reason:** a bar over all takes would be the bar of an idle pull: at stage 500 a relay takes the lock about 42,000 times a minute for reads and about 55 for writes, so a write that stalls for seconds would pass it. Section 1.4 measures a read's hold at about 12 µs and a growing take's at under 1.5 ms at R1's sizes. 1 ms is chosen, about eighty times a read; 250 ms is chosen, a fortieth of the stream timeout (10 s) after which a device gives up a request, so that a stalled write holds up a few hundred requests and loses none. A queue on the lock grows quickly past a quarter of its time. In the parts treated apart, the same figures are reported and not barred.
5. **A device's lock: no more than one wait over 100 ms for each device in each hour of the window,** outside the parts treated apart; in a carry window the waits are reported. **Reason:** `cordelia msg summary` tries the lock for 100 ms (`AGENT_MESSAGE_SUMMARY_WAIT_MS`) and prints nothing where it cannot have it (decision 2026-10-19, names at the limit, §3): each such wait is a summary that a person's agent did not see. A p99 would hide them. The count of one an hour is chosen. A device that applies a removal carries every name in one transaction (the record of 2026-10-04 §4.2), so the carry is treated apart here as it is in bars 1, 2 and 4.
6. **A device's memory: RSS at most 64 MiB at every sample, and no persistent growth.** Growth is found so: the window is cut in two halves, and a device grows where its RSS rises in both halves by more than the threshold. The bar fails where more than 1% of the devices of a run grow, or one device of the population (the same person and device, by the seed) grows in two runs of three. The threshold is 2 MiB an hour at stage 100; from stage 190 it is the 99th percentile of the devices' rises at stage 100, and not under 2 MiB an hour, and the summary says it. **Reason for 64 MiB:** a heavy device measured 25 MiB after a load (section 1.4); the bar is chosen at about two and a half times that, since a device is a background process on a person's laptop. **Reason for the growth test:** a slope of 1% an hour over thirty samples, over some 1,500 device-runs, would fail on the page cache filling as a database grows, or on an allocator's step; growth that persists through the window, or recurs in the same device, is a leak.
7. **A relay's memory in ordinary use: RSS at most 64 MiB and 384 KiB for each open connection (252 MiB at stage 500, 102 MiB at stage 100), and no persistent growth** (by the test of bar 6, with a threshold of 2% of its RSS an hour). And **what is written and not acknowledged, for any connection, never above the send window,** with change C. **Reason:** a relay with two devices measured 22 MiB; 64 MiB is about three times that, for the store's cache and the relay's tables. 384 KiB a connection is chosen, about eight times the rationale's unmeasured 50 KB. Stages 100 and 190 measure what a connection costs, and change B sets this bar again from it. The second half holds change C to what it says.
8. **A relay's CPU: at most half a core on average over the window, and at most one core in any minute.** **Reason:** chosen. The README's host has one vCPU, and the relay should leave half of it to spare at the load it carries; on the build machine, where everything shares 16 vCPU, the relays' share must stay small for the latencies to be the relays'. Section 2.4 puts a relay at stage 500 at about 0.3 of a core.
9. **Every running device stays connected: each relay's connections lie in a band.** At each sample:
   - **at least** the devices set up with it that have been running for 120 s or more and are not in the office, and the office's 5;
   - **at most** every device set up with it that is running, and each that was frozen in the last 90 s, and the office's 5;
   - in both, one or two for the other relay (whether two relays that list each other hold one connection or two is not settled here; the run says which);
   - but for the samples within 120 s of a relay's start again;
   - and no connection turned away for the bound on connections or for the subnet, outside the office's address.

   **Reason:** a frozen device's connection stays at the relay until QUIC's idle time (60 s) and the governor's next tick close it, so for up to about 90 s a relay holds a connection for a device that is not running; a device that has just started is connected within seconds, but only one running for 120 s (a dial after a start, and its waits after a failed dial) must be. Stages are sized within the bound in force (rule 7 of §2.2), so a refusal outside the office is a fault.
10. **A removal reaches every device within 30 s, and its carry ends within its bound.** In the window (step 8 of section 4.2), a tenth of the people with three devices each remove one device.
    - **(a) The spread:** from the line "The change is made (change N)", each other running device of the person has applied change N within 30 s, and each relay holds it within 30 s. **Reason:** the command has given the change to its relays by its first pass after the line (10 s); a device that reaches a relay that holds it hears within the pass under way (10 s, the record of 2026-10-04 §4.6); 10 s more for applying, which carries every name in one transaction (§4.2). The clock starts at the line and not at the command's end, because the command ends only once the relays hold the change and the device has sent what it carried (§7.1), so timed from its end the spread would come out near nothing.
    - **(b) The carry window:** from the same line until each remaining device has sent what it carried and holds every version that each other remaining device carried. It must end within T = 60 × B / 1,572,864 + 60 seconds, where B is the bytes, as entries are counted, of the largest carry among the person's remaining devices, which the harness works out from what it wrote. **Reason:** a device sends a relay at most `OUTBOX_BYTES_PER_MINUTE` (1.5 MiB) a minute; a device takes from one relay up to `PUSH_BYTES_PER_PEER_PER_MINUTE` less the room kept for a show (about 1.94 MiB) a minute, which is faster, so the sending bounds it; 60 s is two passes and the applying. A heavy person whose devices hold the setup's 300 files and the window's edits carries about 3.75 to 4 MB, so T is about 200 s.
    - **(c) Inside the carry window,** the person's edits are not held to bar 2's percentiles: each must arrive by the window's end and 25 s. A device's holding back by its own pace is reported, not failed; a refusal for rate at a relay still fails bar 1.
11. **Churn closes no connection, and runs.** On the build with change A: at each relay, the churns counted (in `churn`, section 1.2) in the window are those section 4.2 plans, and no connection is closed by warm churn, of a device or of a relay. On the build without change A (stages 100 and 190 only), the same is reported and not barred: the connections warm churn closed, of devices and of the link between relays, the time each closed device took to be connected again, and the latency of the closed devices' people. **Reason:** section 0, item 3, and section 7.4.
12. **The model holds.** Pulls a minute at each relay are within a fifth of section 2.3's figure for the minutes each device was on; edits a minute are within a tenth of section 2.1's; shows a minute and pushes a minute are no fewer than the model's (one show for each pass, one push for each edit to each relay of the writer). **Reason:** otherwise the harness did not drive the load it says, or a device does not do what its record says. Shows and pushes are lower bounds only: a device also shows before each send (every 2 s while something waits, `OUTBOX_FLUSH_INTERVAL_SECS`) and when its leave (10 s, `SHOW_LEAVE_SECS`) has run out in a long pass, and what it pushes depends on what waits, which the model does not count.
13. **Room.** Each relay's room used at the end is within the model's bounds, and nothing was refused for room. The model counts, as entries are counted: for each person and each channel, each author's newest entry in each slot (a relay keeps one entry for each author in each slot, the record of 2026-10-04 §2.4); the words of the personal channel as decision 2026-10-19 (names at the limit) §1 counts them; for each person who removed a device, the whole of the generation left (a relay keeps it until nobody has used it for 90 days, and the removed device is stopped); and for the new generation, each carried version once at the least and once for each remaining device at the most (a relay holds a carried version once for each device that carried it before it saw another's, §12). The bar is between the least and the most, each within 5% for what the model does not count exactly. **Reason:** what a relay holds can be worked out from what was written; the cap is 1 GiB (`MAX_STORAGE_BYTES`), far above what a stage writes.
14. **The office is as expected.** At each relay, exactly 5 connections from the office's address at every sample of the window; every other dial from it turned away and counted; no breach, and no refusal of its address for a time. Its devices connected to no relay, and its people's latencies, are reported. **Reason:** rule 6 of §2.2.
15. **A relay that stops is come back to.** In step 7 of section 4.2 the second relay stops for two minutes and starts again on the same data directory. Each device set up with it is connected to it again within 120 s of its start; each person set up with both relays keeps bar 2 through the outage (through the first relay); each edit of a person split between the relays that was held up by the outage arrives within 120 s of the relay's start; and no request is refused for rate in the five minutes after, but for what the minute of a connection's proofs holds back. The relay's requests, lock and memory in those five minutes are reported. **Reason:** R1 runs two relays so that one can fall. A device connected to another relay dials a lost one at 10, 30, 70 and 150 s after losing it (the record of a relay out of reach §2): one dial falls within 30 s of the relay's start, and 120 s leaves room for a dial's own time and the start of 500 connections at once. A device with no relay dials every 30 s at most.

**A stage that fails a bar** is reported with the bar and the numbers, and the gate is not met at that count. What is changed then (the pull that names several channels, the counter for the room, and others) is a change of its own, with its own record where it changes the protocol, and the stage is run again.

## 4. The harness

### 4.1 Where it lives, and how it is run

It is a test file of the real-process harness, `crates/cordelia-node/tests/scale.rs`. Its run is marked `#[ignore]`, and where `CORDELIA_SCALE_STAGE` is not set it says so and returns at once, so that the CI job that runs the ignored tests does not start a run of hours. Its tests of itself are section 6's. It uses `tests/common/mod.rs` for what that file offers (the pseudo-terminal, the API calls, the checks of where a node dials), and writes its own configurations (rule 2 of section 4.3).

```bash
cargo build --release -p cordelia-node
CORDELIA_SCALE_STAGE=100 CORDELIA_SCALE_SEED=1 CORDELIA_SCALE_OUT=/path/to/out \
  cargo test --release -p cordelia-node --test scale -- --ignored --nocapture
```

### 4.2 The steps of a run

1. **Before anything starts,** it checks the machine: the limits on threads (section 2.4); memory available; disk free; and that no process is left of an earlier run (section 4.3, rule 6).
2. **It starts the relays,** each from an empty data directory, each listing the other by address and key, and waits until each is healthy and holds the other's connection. The relays' start is time zero of the run.
3. **It starts the people, ten at a time,** each on an address of their own, the office's people among them. For each person: its devices start; the first makes the phrase at a pseudo-terminal; each other is added; each device maps the person's names to folders of its own and turns sync on; the first device writes the person's first files, 10 in each name, at the profile's sizes; and the harness waits until every device of the person holds every file. The next ten start when the last ten are in step. This is the setup, reported apart: how long it took, and the most each relay asked of its lock and its memory. (From the pace of sending, a heavy person's 300 first files take about 2.5 minutes, so the setup at stage 500 may take an hour or more; it is not measured yet.)
4. **The office moves to its address.** Its 9 devices are stopped, their configurations are given the office's one address as `listen_addr`, and they are started again, in an order the seed fixes. The harness waits until each relay holds 5 connections from that address, or two minutes.
5. **The window begins ten minutes after that,** so that what a start costs (every proof, the first show, the first fetch) is past.
6. **Through the window,** one thread schedules every person's edits: a Poisson process at the profile's rate, the profile's bursts, one active device a session, and no file written twice on a device within 15 s (section 2.1). An edit writes a file in a memory folder of the active device as an editor does: the whole file at once. Two in three edits rewrite a file of the name, one in three makes a new one. The file begins with a line that names the edit (`<!-- scale <edit number> -->`) and is followed by random text to its size. The observer reads, every 250 ms, each file it waits for on each other running device of the person, and the copies the adapter keeps beside it; an edit counts as arrived only when its own line is found (bar 3). Another thread turns devices off and on as item 4 of section 2.1 says. Sampling (section 1.2) goes on once a minute for each process, spread over the minute so that no second reads 500 processes.
7. **The second relay stops once it has counted its first churn in the window,** at the next minute (SIGTERM), and **starts again two minutes later** on the same data directory. Its governor's clock is in memory (`last_churn`), so the start sets its next churn 60 to 65 minutes later. Bar 15 reads the outage, and the five minutes after the start are treated apart.
8. **Removals are made once the second relay has counted a churn after its start again,** at the next minute, spread over five minutes. A tenth of the people with three devices, chosen by the seed, each remove one device, with `cordelia remove-device` at a pseudo-terminal with the phrase, as `person_e2e.rs` does. The harness timestamps the line "The change is made". The removed device is then stopped for good. Bar 10 reads these, and the carry windows are treated apart.
9. **The window ends** when the first relay has counted two churns in it, or 25 minutes after the last removal, whichever is later. It lasts about two and a half to three hours. **A window that reaches five hours without both is cut there, and the run is INVALID** (section 6, rule 7).
10. **It ends.** Every node is told to stop (SIGTERM), and each must stop within `NODE_STOP_TIMEOUT_SECS`. The read-only reads of each relay are made a last time. The harness checks that every pid it started has gone.
11. **It writes the run's summary,** and keeps the data directories only where `CORDELIA_E2E_KEEP` is set.

So in the window each relay counts two churns at least: the first relay two, by step 9; the second one before it stops (step 7) and one after its start again (step 8). The steps follow the churns as they come, so a slow setup does not leave a churn outside the window. A run at stage 500 takes about four to five hours.

### 4.3 Rules of the harness

1. **It dials nothing but its own relays.** Each node's configuration names only the run's relays, by address on 127.0.0.1 and by key, and sets `dns_discovery = ""`. Before each node is started the harness asks what it will dial (`Node::will_dial`, `assert_on_this_machine`) and refuses it otherwise. At the end it reads each relay's peers and checks that every key is one of the run's. No address outside 127.0.0.0/8 is written into any configuration, and a configuration that would hold one is refused before anything starts.
2. **It changes no constant, gives each node the settings it has in R1, and lists every other.** A relay is given the governor of `deploy/relay/relay1.toml` (hot 50, warm 50, cold 200) and every other setting at its default, but for the bound of rule 7 of §2.2 after change B; a device is given the defaults. The faster tick and shorter tenure that the real-process tests give their nodes are not used. The harness writes its own configurations rather than `node_made`'s, which listens on 0.0.0.0. What each node is given beyond its defaults is listed in the summary: its `listen_addr` (127.0.0.1 and a port for a relay; the person's address, or the office's, and a port for a device); its relays, by address and key; `dns_discovery = ""`; `allow_private_addresses = true`, without which a node does not dial an address on loopback; the relays' bound after change B; the log level, `info`; and its data directory and ports.
3. **A run is repeated from its seed.** The seed fixes the population, the names, the office and its order, the people split between relays, the active devices, the times of edits, bursts and times off, the sizes, and the choices of step 8. The relays' and devices' own randomness (keys, churn's jitter) is not fixed: two runs from one seed drive the same load, and differ in what the nodes do. The summary names the seed, the commit and the stage.
4. **Each stage is run three times,** with seeds 1, 2 and 3, and passes where each run passes. The summary of a stage gives each run's figures and their spread.
5. **It stops early on a fault, and still writes the summary:** a node that exits when it was not told to, a relay that does not answer for a minute outside step 7, or the machine's memory available under 2 GiB. The summary says why it stopped.
6. **It leaves no node behind.** Each node is started in a process group of its own and with `PR_SET_PDEATHSIG` set to SIGKILL, from one thread that lives as long as the run (the signal follows the thread that started the child), so that a harness that is killed outright takes its nodes with it. It writes the pids it starts to a file in its output directory. A run that starts and finds a live process of a pid in an earlier run's file, whose command line is a node of that run, refuses to start and names it.

### 4.4 What a run leaves

In `CORDELIA_SCALE_OUT`:

- **`SUMMARY.md`, the one file for a person to read.** First line: PASS, FAIL or INVALID, the stage, the seed, the commit, and which of changes C, A and B are in the build. Then each bar of section 3, one line each: the figure, the bar, pass or fail. Then the checks of section 6 (whether the run is valid). Then, per relay and per profile of device: the median and the worst of each measure, and the parts treated apart. Then the setup's figures and every setting given beyond the defaults. It names no machine and no host: it says "16 vCPU, 32 GB" from `/proc`, and no more.
- `samples.jsonl`: every sample, one line each.
- `edits.csv`: every edit, and its arrival on each other device.
- `pids`: the pids the run started.
- Each node's log, where `CORDELIA_E2E_KEEP` is set.

## 5. Set aside, and why

- **Docker.** The build machine has none, and nothing in the test needs it: real processes on loopback run the release binary as a person runs it. The stale Docker suites of `tests/e2e/` measured mesh formation and delivery of items of the older kind, which v1 does not use; nothing is taken from them but the lesson that one host can run hundreds of nodes.
- **Other machines, and a real network.** Everything is on one machine, on loopback, with no latency and no loss. The latencies measured are a floor: a real network adds some tens of milliseconds a hop, against a pull every ten seconds. The cost of loss and of slow links is not measured.
- **A flood.** The test runs honest peers. What a hostile peer can make a relay hold is bounded by arithmetic (section 2.5) and by change C's test, not by a run.
- **Connections that hold a relay's slots.** Nothing sheds a connection that stays alive (section 0): a known limit of R1, and of today's bound, which this record states and does not fix. A way to shed them (for example, a relay that closes the longest-held connection of a full subnet when another asks, or a cost to hold a slot) is for a later record.
- **A true sleep.** A freeze stands for it (item 4 of section 2.1). The wake from a sleep is tested by `device_entries_e2e.rs`.
- **Phones.** No device of v1 is a phone.
- **A mesh of more than two relays.** R1 runs two. A device dials every relay it is set up with, so each relay more is one more connection on every device and at every relay: a larger mesh is a design question (which relays a device dials), not a scale one, and is for after R1.
- **The Agent Swarm persona.** It runs in a data centre with its own relays and limits (demand model §2.1), and is not R1's.
- **Messages between agents.** The messages channel is pulled, and counted, on every pass. Messages themselves are rare (20 a folder an hour at most) and small (2 KB), and are left out of the load.
- **Recovery, carrying by command, and the upgrade.** One-off acts of a person, measured by their own tests.
- **Days and months.** A day's proofs, the hourly sweeps and the 90 days of a channel nobody uses are not reached in a run. The minute of a connection's proofs is reached at every start of a device and of a relay, which is the same burst.
- **The older kind of channel.** A relay of this version still carries it for devices of the version before, and none of this version's devices writes it.
- **Fewer HTTP workers on a device.** A device's local API starts one HTTP worker for each core: 16 on a laptop of 16 cores, for a handful of local requests. It is waste, and is noted for a later change; the test measures it as it is.

## 6. The tests of the harness, and how a run is checked

The tests of the harness are tests of `scale.rs`. Tests 1, 2, 3, 6 and 7 start no process and are not ignored; tests 4 and 5 take some minutes and are ignored for their length, and CI runs them with the other ignored tests of cordelia-node (TESTING.md).

1. **The population.** For each stage, the population has exactly the stage's devices, the mix of §2.2, the office, the split people, a /24 for each person at setup and the office's one address in the window, and no address outside 127.0.0.0/8; the same seed gives the same population; another seed gives another.
2. **The schedule.** Over a simulated ten hours, each profile's edits an hour are within 5% of section 2.1; its bursts come once each 30 minutes; every edit of a session is on its active device; no file is written twice on one device within 15 s; the active device is never off in its session; and each profile's share of time off is within 5% of what item 4 of section 2.1 gives. And the steps of section 4.2 follow churns given to them: with the churns of a slow setup they still place two churns of each relay in the window, and with no churn after five hours they cut the window and say INVALID.
3. **The observer.** With two folders and no node: a file copied from one to the other after 3 s is observed at 3 s within 0.3 s; a file never copied is counted as not arrived at 300 s; **a later edit of the same file that arrives first does not count the earlier one as arrived,** and the earlier one's line in a copy kept beside the file does; a file that is copied with other content does not count.
4. **A small run, end to end:** two relays and seven devices of three people (one casual, one developer, one split between the relays), with one device off and on, the second relay stopped and started, a window with churn every two minutes (the only run in which a governor's interval is set, and it says so), and one removal. It checks that every measure of section 1.2 is in `SUMMARY.md` with a value; that the counters at a relay agree with the model for those devices within a fifth; and that what the harness counted written equals what it counted arrived and not arrived.
5. **A run that must fail.** The same small run, where one device is stopped in the middle of the window and not started again: its person's later edits do not arrive at it, bar 3 fails, and the summary's first line says FAIL. So a bar can fail.
6. **The configurations.** A configuration the harness writes names nothing to dial but its relays (every device's `will_dial` is a subset of them), binds a loopback address and no other, lists each relay to the other by address and key, and lists in the summary every setting beyond the defaults; one with an address outside loopback is refused before any process starts.
7. **The checks before a run.** Given limits on threads, the harness plans the mask of 4 cores where a limit is under one and a half times what it needs without it, and refuses only where a limit is short with it too; it reads `pids.max` from a cgroup file given to it; and with a pid file of an earlier run whose pid is live and a node of that run, it refuses to start.

**How each run is checked to have measured what it says.** The summary's checks of validity, each of which marks the run INVALID (not failed) where it does not hold:

1. **Every process was sampled.** No running process lacks a sample for more than two minutes in the window.
2. **The counts agree.** What devices count they asked of a relay, and what the relay counts it was asked, agree within 1% for each kind; the bytes a relay counts in agree with what devices count they pushed within 5%.
3. **The edits add up.** Edits written equal edits observed arrived plus not arrived, for each other device.
4. **The observer kept its pace.** Its reads of a file were at most 500 ms apart at p99; otherwise the harness was starved, and the latencies are its own.
5. **The machine was not the bottleneck.** In every minute of the window: the machine's CPU at least 20% idle; iowait at most 10% of its time; the disk's mean write at most 20 ms; memory available above 2 GiB; and the harness's own process under one core. Otherwise the run measured the machine, and is run again with fewer devices, the mask of section 2.4, or more memory. The figures for iowait and the disk are chosen.
6. **The load was the load.** Bar 12 holds; where it does not, the run is invalid as well as failed.
7. **Churn had its chance.** Each relay counted the churns of section 4.2 in the window (the first relay two, the second one before its outage and one after), with a cold peer at each; the window was not cut at five hours. On the build without change A, a run in which no churn at either relay closed a connection is invalid: the churn it was to measure did not happen.

## 7. The pieces, and their order

Each piece is a change of its own, reviewed and merged apart, in this order: change C, the counters, the harness, change A, change B.

### 7.1 Change C: the send window, set

**What it changes.** `transport_config` (`transport.rs`) sets `send_window` to a new constant of `protocol.rs`, `QUIC_SEND_WINDOW`: two messages, 2 × `MAX_MESSAGE_BYTES`, 2 MiB. The rationale §1 gives it beside the receive window: what a connection may have written and not acknowledged, and what that bounds. Nothing else changes.

**Why two messages.** The most a relay or a device writes in one exchange is one message: a page of entries, or a push, within `MAX_MESSAGE_BYTES`. Two let the answer to a second exchange be written while the first is still being acknowledged, as the receive window lets a second be read. More buys no pace that the limits allow: a relay hands a connection at most 2 MiB a minute (`PUSH_BYTES_PER_PEER_PER_MINUTE`), and 2 MiB may be in flight on each round trip, which is some hundreds of times a minute on any link.

**What it fixes.** Today a connection can make a node hold up to 10,000,000 bytes written and not acknowledged (section 2.5). A peer that pulls pages and never acknowledges them makes a relay hold them; each later write waits out the stream timeout, and the buffer stays until the connection closes. On every deployed host, the bound of 200 is above what that allows (section 2.5). It stands on its own: it is a fix to the released relays whether or not the test is built.

**Its tests.** In `transport.rs`: the configuration a connection is given has the send window `QUIC_SEND_WINDOW`; and, over a real connection on loopback, a node that writes to a peer that reads nothing has at most that much written before its write waits. In `protocol.rs`: `QUIC_SEND_WINDOW` is twice `MAX_MESSAGE_BYTES`, and holds a page of entries with room to spare. `devices_e2e.rs`'s test of a channel larger than one message still passes, so nothing that syncs is slowed.

### 7.2 The counters

What section 1 needs inside the node: the wrapper around the lock, with its kinds; the timing of `rates` and `room`; the counters of requests, answers and bytes by stream kind; what is written and not acknowledged; the gauge of connections and the counters of connections turned away; the governor's counters (churns, counted in `churn`; connections closed by warm churn, of devices and of relays; closures of each listed relay's link) and its hot count served apart from the count of connections; the device's counters of what it asked and held back; and the route `/api/v1/metrics/load`, which reads atomics alone. Its tests: each counter moves for what it counts and for nothing else; a churn is counted where warm churn closes nothing; the route takes no lock (a test holds the lock and reads the route); the cost of timing (section 1.1, rule 5). It changes nothing a node does.

### 7.3 The harness

`tests/scale.rs` as section 4 says, with its tests (section 6). It needs the counters. It changes nothing in the node.

### 7.4 Change A: a relay and a bootnode close no connection by warm churn

**What it changes.** On a node whose role is `relay` or `bootnode`, warm churn (`governor.rs`, `churn_warm`) closes no connection, as a personal node's warm churn closes none of its relays (the record of relays §2). `churn` still runs, and is counted; hot churn, which moves peers between hot and warm and closes nothing, is not changed. A relay knows a peer as a relay only where its operator lists it (`p2p.rs`, `is_configured_relay`): a peer that says it is a relay and is not listed is an ordinary peer. So a rule that went on churning some relays and not others could not be kept without trusting what a peer says of itself, and this one does not try.

**Why.**

- **Closing a device brings in nobody.** Warm churn closes a peer so that another may take its place, and would dial a cold peer for it. At a relay the cold peers are devices that went away; a relay holds no address for a peer that dialled it, so no dial is tried, and a personal node accepts no inbound connection in any case. What is left is the closure alone.
- **What churn is for does not hold at a relay.** Churn exists so that a node meets other peers, and so that an attacker cannot hold a place among those it chose. A relay chooses no device: a device is let in by the bounds on connections, and a connection that churn closes is made again within seconds. So churn removes nobody, and does not shed a connection that holds a slot (the known limit of section 0): it only costs.
- **What it costs.** At 500 devices a relay with a cold peer (in use, always) closes about 100 connections an hour. Each is made again with up to 32 proofs and a whole show of 33 KB; meanwhile its device syncs through one relay, and a device set up with one relay not at all.
- **The listed relay.** At a relay the other relay is a warm peer and is not trusted (`governor.rs`), so warm churn can close the link between R1's two relays, and the edits of people split between them then wait. The operator lists the relays it works with because it wants that link.

**What it contradicts, and changes.** `governor.rs`, `test_a_personal_node_keeps_its_relays_through_churn`, asserts that "a relay with the same peers closes a warm one at the first": that half becomes "a relay with the same peers closes none". `p2p.rs`, `a_nodes_governor_keeps_its_relays_through_churn_only_on_a_personal_node`, asserts that a relay's and a bootnode's governor churn: it becomes that a relay's and a bootnode's warm churn closes no connection, and that a personal node's keeps its relays as today. The record of relays §2 ("A relay and a bootnode churn their warm peers as before") and `network-protocol.md` §5.4 say the new rule.

**Its tests.** In `governor.rs`: a relay with warm devices, a warm listed relay and cold peers closes none of them through five churn intervals, and counts five churns; a bootnode the same; a personal node's churn is as today. In `devices_e2e.rs`: a relay that churns every two seconds (`Node::churn_every_secs`), with two devices and a listed relay, keeps every one of their connections through six intervals, with a device of the person's turned off to give it a cold peer.

**What the record's test says without it.** Stages 100 and 190 are run first on the build without change A, and their summaries say what warm churn cost (bar 11). Every stage is then run with it.

### 7.5 Change B: the bound on connections

**What it changes.**

1. **Two numbers in `protocol.rs`.** `DEFAULT_INBOUND_CONNECTIONS` = 56, the bound a relay takes unless its configuration says otherwise, derived from the container of `compose.yml` (section 2.5). `MAX_INBOUND_CONNECTIONS` goes from 200 to 1,024, and becomes the cap: the most a configuration may set. The test of the constant (`test_max_inbound_connections_network_protocol_9_1`) follows, with a test that K + the default × W is within 512 MiB and K + the cap × W within 8 GiB, as `protocol.rs` states W and K.
2. **`limits.max_inbound_connections` is read.** Today nothing reads it. A relay or a bootnode takes it, or the default where it is not set (the configuration's default becomes `DEFAULT_INBOUND_CONNECTIONS`). On those roles a value above the cap, or of 0, is refused when the configuration is loaded, with a line that says the least and the most it may be. A personal node takes no inbound connection and does not read it, so a device's file that carries the field is not refused for it (`Config::load` is shared by every role, and the check is made by role).
3. **`limits.max_connections_per_ip`,** which nothing reads either, is read the same way: the constant `MAX_CONNECTIONS_PER_IP` stays its cap and its default, a value above it or of 0 is refused on a relay or a bootnode, and **the allowance for an address** (`PeerRateLimiter::for_connections`, today given `MAX_CONNECTIONS_PER_IP`) is given the value in force, so that a relay set lower allows an address less.
4. **The rationale and the specs.** The rationale §5 gives the derivation of section 2.5 in place of "about 50KB a connection", with W's figures and the cost of a connection that stages 100 and 190 measured; §1 ("with 200 connections a relay holds at most 400MB unread") and §4 ("200 connections … about 46MB") are worked out again at the default and at the cap. `configuration.md` §2.6 and `network-protocol.md` §9.1 and §12.4 say the default, the cap, and that the setting is read.
5. **The deployment files** (section 2.5): `fly.relay1.toml` to `memory = "512mb"`; `relay1.toml` and `relay2.toml` a commented `[limits]` line with the bound and the memory it needs; the README's section on the host, the bound its host holds, the sum, and the host for more. `compose.yml` keeps its limit.
6. Bar 7 is set again from the cost measured at stages 100 and 190.

**Its tests.** A relay's configuration with the bound above the cap, or 0, is refused, and a device's is not; a relay with no setting takes 56; a relay set to 3 turns away the fourth device, and one set to 2 connections for an address turns away the address's third, in tests with real processes.

**Why.** Section 0, item 2, and section 2.5.

**Order.** Stages 100 and 190 run before change B, and give it the cost of a connection. Stages 250 and 500 run after it, with the relays given 576 (rule 7 of §2.2).

## 8. What this record would alter elsewhere

No other record or spec is changed by this one. Its changes, when they are made, alter:

- **change C:** the rationale §1 (the send window), and `transport.rs`'s account of what a connection can make a node hold;
- **change A:** the record of relays §2 (a relay and a bootnode close nothing by warm churn); `network-protocol.md` §5.4; the two tests named in section 7.4;
- **change B:** the rationale §1, §4 and §5; `configuration.md` §2.6; `network-protocol.md` §9.1 and §12.4; in `deploy/relay`, `fly.relay1.toml`, `relay1.toml`, `relay2.toml` and the README.

The demand model §2.5 is not met for the Dev Team and Enterprise personas by v1 (bar 2), and is left as it is.

## 9. The first review, and how each finding is settled

The first review read the record at its first commit, built the release binary, measured the threads and descriptors of idle nodes at 1 and 4 cores, and read the code for the rest: high 3, medium 6, low 6.

| # | Severity | Finding | How it is settled |
|---|---|---|---|
| 1 | High | Churn would not happen in a run (no cold peer; the one churn in the window wasted), so bar 11 tested nothing; and a relay's churn of devices cannot bring in another peer | Both. Devices go off and on in the window, from the demand model's intermittent availability (§2.1, rule 4); the window is placed and sized to hold two churns of each relay (§4.2, step 4); a run with fewer, or without change A with no closure, is invalid (§6, rule 7). And change A (§7.3): a relay does not churn devices or the relays it lists. The test measures the build without change A at stages 100 and 190, and every stage with it (bar 11) |
| 2 | High | The raised bound was to come from the benign cost of a connection; the bound is for a flood; the configuration's field is not read | The bound is derived from the worst case, 640 connections at about 2.34 MiB each against a stated host of 2 GiB for the relay (§2.5). Change B (§7.4) raises the constant with its test and rationale, and has the code read `limits.max_inbound_connections` (and `max_connections_per_ip`), refusing a value above the constant. R1 carries about 199 devices until then (§0). Whether 500 is the count is the person's to say (§0) |
| 3 | High | The removal bars ignored the carry; the spread was timed from the command's end | The spread is timed from "The change is made (change N)" (bar 10a). The carry window is barred by its length, derived from `OUTBOX_BYTES_PER_MINUTE` and what was carried (bar 10b), and is treated apart from bars 1, 2 and 4 (bar 10c). Bar 13 models the generation left and one to k carried copies |
| 4 | Medium | The p99 lock bars cannot see writes | A histogram for each kind of take; reads barred at p99, writes and sweeps by their most and the count over 50 ms (bar 4); a device by the count of waits over 100 ms (bar 5) |
| 5 | Medium | Threads and descriptors on 16 cores were wrong (actix starts a worker for each core too) | §1.4 gives the review's measurement and about 34 threads and 81 descriptors a node on 16 cores, about 17,600 threads for 502 nodes (§2.4). The harness checks `pid_max`, `threads-max` and `ulimit -u` before it starts, and masks devices to 4 cores where they are short (§2.4, §4.2 step 1). The waste of a device's HTTP workers is noted, not changed (§5) |
| 6 | Medium | An address for each person hides the limits for an address and a subnet | Both a cohort and a statement: an office of three heavy people behind one address, with the refusals expected stated (rule 6 of §2.2, bar 14); and the limit stated as accepted for R1, because raising it weakens what it caps and R1's people are single users at home |
| 7 | Medium | "From the demand model" was partly true | The devices, the Developer's edits and the rates off and on are marked chosen (§2.1). Bar 2 says that the model's latency for the Dev Team and Enterprise personas is not met by v1, and the model is left as it is (§8) |
| 8 | Medium | The test for growth would fail on noise | Growth must persist through both halves of the window; the bar fails on more than 1% of devices or one device in two runs of three; the threshold is in MiB an hour, and is set from stage 100's spread from stage 190 (bar 6) |
| 9 | Medium | No relay falls over; the link between relays can be churned | The second relay stops for two minutes mid-window (§4.2 step 6, bar 15). The link's closures are counted (§1.2), and change A spares listed relays (§7.3, bar 11) |
| 10 | Low | Shows were "at least" and checked within a fifth; pushes not modelled | Shows and pushes are checked as lower bounds only, with why (bar 12) |
| 11 | Low | No measure of the disk | iowait and the disk's mean write are recorded and are in the checks of validity (§1.3, §6 rule 5) |
| 12 | Low | `peers_hot` is overwritten by two writers; tiers mean little at a relay | The first piece serves the governor's hot count apart from the connections; the record expects about 1 hot and every other peer warm at a relay, and says that "hot 50, warm 50" decide nothing there today (§1.2) |
| 13 | Low | Timing the lock is a wrapper type; the nested mutexes inflate the hold | The wrapper is planned, with the places unchanged (§1.1 rule 4); `rates` and `room` are timed, and their waits reported apart from the hold (§1.1 rule 4, §1.2) |
| 14 | Low | A harness that is killed leaves its nodes behind | A process group and `PR_SET_PDEATHSIG` for each node, a pid file, and a check for what an earlier run left (§4.3 rule 6, §6 test 7) |
| 15 | Low | The harness's configuration listens on 0.0.0.0 and gives settings not listed | The harness writes its own configurations: relays on 127.0.0.1, devices on the person's address; every setting beyond the defaults, `allow_private_addresses` among them, is listed in the summary (§4.3 rule 2, §6 test 6) |

Nothing is left unsettled. One is settled by a smaller change than the review offered: finding 5's cap on a device's HTTP workers is noted and not made, since the test measures the node as it is, and the mask covers the machine's limit.

Rows 1, 2 and 9 are answered again by the second review (section 10): W and the bound are derived afresh with the send window counted, against the deployed hosts, and change A closes no connection by warm churn at all.

## 10. The second review, and how each finding is settled

The second review read the record at its second revision against the code and against quinn-proto 0.11.14, and built nothing: high 4, medium 4, low 7.

| # | Severity | Finding | How it is settled |
|---|---|---|---|
| H1 | High | W left out the send window (quinn's default, 10,000,000 bytes, never set) and the application's buffers; the true W is about 14 MiB, and today's 200 is above what it allows | Change C (section 7.1), the first change and one of its own: the send window set to two messages. W counts every buffer: the receive window, the send window, the frame, the decoded message, the answer and the tables (section 2.5): 7.34 MiB with change C, 14.9 MiB today. The record says plainly that today's 200 is unsafe on every deployed host (section 0, item 1). The 230 KiB line cites the rationale §4, not a constant no relay uses |
| H2 | High | The 2 GiB host is not R1's; change B made an unsafe value the default; `deploy/relay` was not named | The bound is derived against the deployed hosts: 61 in the container of `compose.yml`, 95 on the README's host bare, 21 on Fly's machine, with change C (section 2.5). The default is 56, safe in the container; a larger host raises it by configuration up to a cap of 1,024, and a value above the cap is refused. Each deployment file's change is said (sections 2.5, 7.5). 500 devices take a relay that may hold about 4.2 GiB, on a host of 6 GB: the person's choice, with gate 9 |
| H3 | High | The office could not be set up behind one address | It is set up on separate addresses and moved to its one address before the window (rule 6 of §2.2; section 4.2, steps 3 and 4) |
| H4 | High | Bar 9's equality fails at almost every sample (frozen devices stay connected; started devices connect at once) | Bar 9 is a band: at least the devices running 120 s or more, at most every device running and each frozen in the last 90 s, one or two for the other relay, and the office's 5 |
| M1 | Medium | The only relay a relay knows is a listed one, so change A as written switched warm churn off and bar 11 tested nothing; the churn counter would read zero | Change A is stated as "a relay and a bootnode close no connection by warm churn", and the case of an unlisted relay is dropped (section 7.4). Churns are counted in `churn`, before warm churn looks (section 1.2); bar 11 checks that no connection is closed by churn, and that churns ran |
| M2 | Medium | With change A nothing sheds a connection that stays alive; "the bounds cap an attacker" was false for the slots | Stated as a known limit of R1 and of today's 200 (section 0, section 5); change A's reasoning no longer says the bounds cap that |
| M3 | Medium | The second relay's restart reset its churn clock, so at stage 500 it counted one churn and every run was invalid | The restart is anchored after the second relay's first churn in the window, the removals after its churn following the restart, and the window's end after the first relay's second churn (section 4.2, steps 7 to 9); a window cut at five hours is invalid |
| M4 | Medium | An edit replaced by a later one counted as arrived: a lost update passed | An edit counts as arrived only by its own line, in the file or a copy kept beside it (bar 3; section 4.2, step 6; section 6, test 3); and no file is written twice on one device within 15 s, so every edit is published (section 2.1, item 8) |
| L1 | Low | The governor makes no dial for an inbound peer at all | Said so: a relay holds no address for a peer that dialled it (section 0, item 3; section 7.4) |
| L2 | Low | Refusing at load needed detail: the role, the value 0, the address's allowance | Refused on a relay or a bootnode only; 0 refused; a personal node does not read it; the address's allowance follows the value in force (section 7.5, items 2 and 3) |
| L3 | Low | Change A contradicts two tests and the record of relays §2 | Named, with what each becomes (section 7.4) |
| L4 | Low | The deployed host has 1 vCPU, not 2 | Bar 8 is half a core on average and one in any minute; the host for 500 devices is said with two vCPU (section 2.5) |
| L5 | Low | The relays do not list each other by key | Said so; the harness lists each by address and key (rule 3 of §2.2; section 4.3, rule 1; section 6, test 6) |
| L6 | Low | The thread check contradicted itself, and missed `pids.max` | It masks where a limit is short, and refuses only where one is short even masked; it reads the cgroup's `pids.max` (section 2.4; section 6, test 7) |
| L7 | Low | Bar 5 did not treat the carry apart | It does (bar 5) |

Nothing of this review is left unsettled. Some answers to the first review are replaced by these: W and the bound (finding 2 of section 9), and change A's sparing of devices and listed relays alone (findings 1 and 9 of section 9), which is now no closing by warm churn at all.
