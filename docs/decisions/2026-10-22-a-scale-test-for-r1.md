# Decision: a scale test for R1

**Date**: 2026-10-22
**Status**: Proposed. Not built. Revised once after its first review (section 9).
**Cited as**: "decision 2026-10-22 §3, rule 4". The numbers do not change. A number that is not used stays unused.

Words used throughout:

- **The gate** is gate 10 of R1: "The relays carry the load we expect. A scale test at a device count agreed beforehand. Proposed: 500, ten times the traction bar." **The issue** is cordelia-node #46: how many devices and channels one relay carries, and how a mesh of relays behaves as it grows (sync latency, memory, governor behaviour, rate limits).
- **The record of 2026-10-04** is [`2026-10-04-a-persons-devices.md`](2026-10-04-a-persons-devices.md). **The record of relays** is [`2026-10-17-a-devices-relays-and-connections.md`](2026-10-17-a-devices-relays-and-connections.md). **The record of a relay out of reach** is [`2026-10-19-a-relay-out-of-reach.md`](2026-10-19-a-relay-out-of-reach.md). **The demand model** is [`docs/specs/demand-model.md`](../specs/demand-model.md), and **the rationale** is [`docs/specs/parameter-rationale.md`](../specs/parameter-rationale.md).
- **A device** is one node process of the release binary, with role `personal`, a data directory of its own, a configuration of its own and a home directory of its own that holds its memory folders. **A relay** is one such process with role `relay`. Both are started by the harness of section 4, which follows the real-process harness (`crates/cordelia-node/tests/common/mod.rs`) and writes its own configurations.
- **A person** is a set of devices that follow one phrase. Each person's first device makes the phrase, and the others are added with `add-device` and `accept`, at a pseudo-terminal, as `devices_e2e.rs` does.
- **A name** is a memory folder that a person's devices map to one name; its channel is one channel at a relay.
- **The build machine** is one machine of 16 vCPU and 32 GB of memory, with a 290 GB disk, running Ubuntu 24.04, with no Docker and no root.
- **A stage** is one run at a fixed number of devices: 100, 190, 250 or 500 (section 2).
- **A pass** is a device's round of its relays every ten seconds; **a pull** is one request for one channel at one relay; **a show** is a device showing its change entry; **a proof** proves a channel's key on a connection; **a push** sends entries (the record of 2026-10-04, §2.4 and §4.6).
- **A carry** is what each remaining device does when it applies a removal: it writes every current version of every name it holds into the new generation's channels, and sends them (the record of 2026-10-04, §4.2 and §7.3).
- **Churn** is what a node's governor does once an interval (`CHURN_INTERVAL_SECS`, an hour, and up to 300 s of jitter): it closes a fifth of its warm peers that churn may close, and dials cold peers in their place (`network-protocol.md` §5.4; `governor.rs`, `churn_warm`).
- **The lock** is the one database lock of a node: the `Mutex<Connection>` that every request of the streams of entries takes at a relay, and that the sync cycle, the passes and the local API take on a device. **Its wait** is the time from asking for it to holding it; **its hold** is the time it is held.
- **The window** is the measured part of a run (section 4.2). **The run's summary** is the one file a run leaves for a person to read (section 4.4).
- **Change A** and **change B** are the two changes of their own that this record proposes beside the test (section 7): a relay that does not churn devices, and the raised bound on connections.

---

## 0. What this is

The gate asks for a scale test at a device count agreed beforehand. This record proposes that count, says what is measured and how, sets a pass bar for each measure with its reason, and describes a harness that runs on one build machine with real processes. It also proposes two changes that the test needs before its larger stages. Nothing is built yet.

**The count.** This record proposes 500 devices, the gate's figure. Whether 500 is the count is the person's to say: it has been asked, and is not yet answered. The stages below 500 are run whatever the answer, and the record holds for another count by the same rules.

Four things are known before anything is built, and they shape the plan.

1. **R1 as built carries about 199 devices.** A relay takes at most 200 inbound connections (`MAX_INBOUND_CONNECTIONS`), from any peer, and turns away the rest before the handshake (`rate_limit.rs`, `would_allow`; `p2p.rs`, at the accept and after the handshake). A device dials every relay it is set up with, and R1's devices are set up with both relays, so each relay holds one connection for each device and one for the other relay. More relays do not help, since every device dials every one. The configuration has a field `limits.max_inbound_connections`, and nothing reads it: a relay set to 600 still refuses the 201st connection, without a word. **Until change B is made, R1 carries about 199 devices,** and the stages of 250 and 500 are not run. Change B derives the raised bound from the worst case a connection can cost a relay (section 2.5), not from what a connection costs in ordinary use.
2. **A relay's churn closes devices' connections and cannot bring in another peer.** A relay churns its warm peers, and every device is a warm peer of a relay (a relay promotes a peer to hot only while it has fewer than `hot_min`, so it shows about 1 hot and every other peer warm). Churn dials a cold peer in each one's place, and a personal node accepts no inbound connection (`p2p.rs`: "personal nodes are outbound-only"), so that dial fails. Churn needs a cold peer to run at all, and a relay has one whenever any device is off, which in use is always (the demand model: laptops sleep and travel). At 500 devices a relay would close about 100 connections an hour, each made again with up to 32 proofs and a whole show of 33 KB; and with any cold peer it can close the link to the other relay. **Change A** stops a relay churning devices and the relays its operator lists (section 7.3). The test measures the build without change A first, at stages 100 and 190, says what churn cost there, and then measures every stage with change A.
3. **A device pulls each of its channels from each relay every ten seconds,** one request a channel. A person with 30 names asks each relay 192 pulls a minute from each device, each a read of the relay's store under the lock. Measured (section 1.4): an idle pull holds the store for about 12 µs whatever the number of channels, up to 30,000; at 500 devices that is under 1% of the lock's time. The pull that names several channels is not needed for the lock; whether it is needed for anything else (the cost of a stream, the relay's CPU) is what the test answers.
4. **A relay sums its room by reading its table of channels** for each entry that would make a channel larger (`relay::used_bytes`). Measured: about 29 ns a channel held, 80 µs at stage 500's 2,740 channels and 0.87 ms at 30,000. The counter for the room is not needed for the gate by these numbers; the test says whether it is.

The record is built in four pieces, each a change of its own (section 7): the counters, the harness, change A and change B.

## 1. What is measured

### 1.1 Rules for every measure

1. **Each measure has a unit, a source and a cadence.** Section 1.2 lists them.
2. **Nothing is read in a way that changes what is measured.** Three kinds of source are used, in this order of preference:
   - **from outside the process:** `/proc/<pid>/status` (memory), `/proc/<pid>/stat` (CPU), `/proc/<pid>/fd` and `/proc/<pid>/task` (descriptors and threads), and files the harness reads in a device's memory folders. None of these touches the node;
   - **counters inside the node, read through a route that takes no lock** (rule 3);
   - **the node's database, read through a read-only SQLite connection,** once every five minutes. The database is in WAL mode (`schema.rs`), so a reader neither waits for the writer nor holds it up, and it is not the node's lock, which is in the process. Only the relay's room is read so.
3. **The counters are new, and are the first piece** (section 7.1). They are atomic counters and fixed histograms in the node, served at a new route of the local API, `/api/v1/metrics/load`, in the text form that `/api/v1/metrics` uses. The route checks the bearer token, which takes no lock, and reads the atomics alone. **`/api/v1/metrics` is not used:** it takes the lock to count channels and items (`handlers::metrics_with`), and would be one more request on the lock under test. A device's `/api/v1/status` is read once a minute, for what no counter holds, and that read is one of the device's own takes of its lock.
4. **The lock is timed by a wrapper type.** The lock is taken at about 200 places in 17 files. The first piece puts a type around `Mutex<Connection>` whose `lock` and `try_lock` have the same form as today's and return a guard that records its hold when it is dropped, so the places that take it are not changed. Each take names its kind (section 1.2) by the request or task it is in. **The two mutexes taken while the lock is held at a relay, `rates` and `room` (`relay_entries.rs`), are timed too,** and the time a hold spent waiting for them is reported apart, so that a wait on them is not read as a long hold of the store.
5. **The cost of timing is measured and bounded.** Timing a take is two reads of the monotonic clock and a few atomic additions, some tens of nanoseconds against a hold of 12 µs at the least. A unit test of the first piece times a million takes with and without the timing; the difference must be under 1% of the median hold of section 1.4, or the timing is sampled (one take in sixteen) instead.
6. **The setup is reported apart from the window,** and so are the parts of the window that the bars treat apart: a relay's outage, and each removal's carry (section 4.2).

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
| Room used | bytes as entries are counted (`entry_cost`), and channels held | Every five minutes, by a read-only connection: `SUM(bytes)` and `COUNT(*)` of `relay_channels` |
| The governor | peers warm and cold, and hot; churns run; connections churn closed, of devices and of relays apart; connections closed for any other reason; closures of the link to each listed relay | Counters of the first piece. The hot count is the governor's own, taken at its tick: today `peers_hot` is also written with the count of connections at each registration (`p2p.rs`), so what it says depends on when it is read, and the first piece serves the two apart. A relay is expected to show about 1 hot and every other peer warm: with `hot_min` 1 a new peer is warm, and a warm peer is promoted only while hot is below `hot_min`. So R1's "hot 50, warm 50" decide nothing at a relay today |

**Per device.**

| Measure | Unit | How it is read |
|---|---|---|
| Sync latency | seconds, from the moment the harness writes a file on one device to the moment the same content is in the file on another running device of the same person | The harness itself (section 4.2, step 5) |
| Catching up | seconds, from the moment a device is running again after being off to the moment it holds every edit its person made while it was off | The harness, from the same records |
| Memory, CPU, threads, descriptors | as at a relay | `/proc`, once a minute |
| Requests | requests a minute to each relay, by kind; and those it held back by its own pace (`OWN_ENTRY_REQUESTS_PER_MINUTE`) | Counters of the first piece |
| Requests refused for rate | requests, in all, for each relay | The same counters; cross-checked against the relay's |
| The lock's wait | µs, a histogram for each kind of take, and the count of waits over 100 ms | The same wrapper |
| What waits to be sent | entries | `outbox_waiting` of `/api/v1/status`, once a minute |
| Conflict copies | files | Counted by the harness at the end |

**Across the mesh.**

| Measure | Unit | How it is read |
|---|---|---|
| A removal's spread | seconds, from the moment `cordelia remove-device` prints "The change is made (change N)" to the moment each other running device of that person has applied change N, and to the moment each relay holds it | The harness timestamps the line as it reads it at the pseudo-terminal. It polls each device's `/api/v1/person` once a second for the applied statement; a relay's holding is read from what each remaining device says of it (`cordelia devices --json`) |
| A removal's carry | seconds, from the same line to the moment each remaining device has sent what it carried and holds every version the other remaining devices carried; and the bytes carried | `outbox_waiting`, what `cordelia devices --json` says the device has sent, and the harness's own count of what each device holds (section 3, bar 10) |
| Churn | churns run at each relay; connections each closed, of devices and of relays; how long each device so closed took to be connected again | The relay's counters; the device's connections in its status, once a minute, and its log line for each connection made |
| A relay that stops | seconds, from the relay's start again to the moment each device set up with it is connected to it again; the relay's requests, lock and memory in the five minutes after | The relay's gauge; each device's status |
| Between the relays | entries a minute passed between the two relays; the latency of the edits of the people whose devices are split between the relays (section 2.2, rule 4); closures of the link | The relay counters of `0x14` and of the governor |

### 1.3 What the harness itself records

For each edit: who wrote it, on which device, in which name and file, its size, and the time it was written. For each other device of the person: the time the content arrived, or that it did not within 300 seconds of the device's running. For each device: each time it was turned off and on, and how. For each process: its pid, its start and its end, and how it ended. For the machine, once a minute: its share of CPU idle and of iowait (`/proc/stat`), its memory available (`/proc/meminfo`), its disk free (`statvfs`), and the disk's mean time for a write over the minute (`/proc/diskstats`: write ticks over writes completed). These say whether the run measured the relays or the machine (section 6, rule 5).

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
| Casual | Casual User, §1.1 | 2 | 4 | 10 | 0.5 to 5 KB | 5 edits in 10 s | each device but the active one, half of the time (rule 4) |
| Developer | Active Developer Team, one user, §1.2 | 3 | 12 | 20 | 1 to 10 KB | 10 edits in 30 s | each device but the active one, a fifth of the time |
| Heavy | Enterprise, one user, §1.3 | 3 | 30 | 30 | 2 to 20 KB | 20 edits in 60 s | never |

Where each figure comes from:

1. **Devices are chosen.** The Casual persona says "one personal device"; Cordelia v1 is one person's memory on each machine they use, and a person with one device does not use it. Two for a casual user (a laptop and a desktop) and three for the others are chosen, not given by the model.
2. **Names.** The middle of each persona's channels (2 to 5; 5 to 15; 20 to 100), less the channels that are no names: a person's devices also hold a personal channel and a messages channel. The heavy profile's 30 is the figure of the review of 5 October, low in the Enterprise range: past it the requests grow in proportion (section 2.3), and the rationale sizes a device for 256 names.
3. **Edits.** Casual: the persona's steady rate in a session, one memory every 5 to 10 minutes, gives 10 an hour. Enterprise: 5 to 15 a session in 10 to 20 sessions a day, over its working hours, at the top of its range, gives 30. **The Developer's 20 is chosen:** the persona gives 10 to 30 writes a session and 5 to 8 sessions a day, and no session's length, so an hourly rate is not given by it. Every person is active for the whole window: the window is a busy span, not a day.
4. **Off and on.** The demand model gives the Casual persona intermittent availability (a laptop sleeps and travels), the Developer working hours with some members remote, and the Enterprise's personal devices working hours. In the window: each casual device that is not the person's active device is off, in each 30 minutes, with a chance of one half, for a time drawn evenly from 5 to 25 minutes; a developer's, with a chance of one fifth; a heavy person's devices stay on (workstations within working hours). **The rates are chosen;** that devices go off and come back is the model's. Half of the times off are a stop (SIGTERM, and a start again on the same data directory); half are a freeze (SIGSTOP, then SIGCONT), which a relay sees as a connection that goes quiet until QUIC's idle time (60 s) closes it. A freeze is not a sleep: the node's two clocks both run, so it does not wake as from a sleep (the record of 2026-10-04 §16). A true suspend cannot be made without root.
5. **Sizes.** Each persona's item size, drawn evenly on a log scale within the range. Content is padded to a power of two, so a relay counts a 5 KB file at 8 KB plus 1 KB.
6. **Bursts.** Each persona's peak burst, once every 30 minutes for each person, at a time drawn at random.
7. **One device at a time.** A person works at one machine at a time. The harness gives each person one active device for each session of 10 to 30 minutes, drawn among the person's devices that are on, and every edit of that session is written there. The active device is never turned off during its session.

### 2.2 The mix, and the stages

| Stage | Casual people (devices) | Developers (devices) | Heavy people (devices) | People | Devices | Channels at a relay |
|---|---|---|---|---|---|---|
| 100 | 20 (40) | 14 (42) | 6 (18) | 40 | 100 | 548 |
| 190 | 38 (76) | 27 (81) | 11 (33) | 76 | 190 | 1,034 |
| 250 | 50 (100) | 35 (105) | 15 (45) | 100 | 250 | 1,370 |
| 500 | 100 (200) | 70 (210) | 30 (90) | 200 | 500 | 2,740 |

A person's channels at a relay are their names, the personal channel, the messages channel and the phrase's channel: 7, 15 and 33. (A pair channel, made when a device is added, is not counted: it is used for an hour at setup.)

Rules:

1. **The stages are 100, 190, 250 and 500,** each run on its own from empty data directories. 500 is the gate's figure and the count this record proposes (section 0). 190 is the most that R1 carries as built, with room left at each relay for the other relay's connection and for connections being made again.
2. **Each stage keeps the mix:** two in five people are casual, seven in twenty developers, three in twenty heavy. The population is drawn from a seed (section 4.3, rule 3).
3. **Two relays, as R1 runs them:** each lists the other by key, as `deploy/relay/relay1.toml` and `relay2.toml` do, so that they pass entries between them; each device is set up with both, but for rule 4. A stage is also run once with one relay, at 100 devices, to say what one relay carries alone.
4. **A tenth of the people of each stage, chosen by the seed among those who are not in the office of rule 6, have their devices split between the relays:** the person's first device is set up with the first relay only, and the others with the second only. So an edit between their devices crosses from one relay to the other, and measures that path. It is R1's case of a device that reaches one relay.
5. **Each person but those of rule 6 has an address of their own.** All processes run on the loopback network, and a relay counts connections, requests and new channels by address and by /24 (`MAX_CONNECTIONS_PER_IP` 5, `MAX_CONNECTIONS_PER_SUBNET` 20, the limits for an address at five times those for a connection, `NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR` 256). So each person's devices bind an address of their own in 127.0.0.0/8, one /24 for each person (person k at 127.(20 + k / 256).(k mod 256).1); a person's devices share it, as the devices of a home share one. A device's QUIC endpoint binds the address of its `listen_addr` with port 0 (`transport::create_client_endpoint`), and Linux delivers all of 127.0.0.0/8 to the loopback interface with no setting; a throwaway check showed a datagram sent from 127.0.12.34 arrives from that address. The relays listen on 127.0.0.1, and on nothing else.
6. **An office: three heavy people share one address,** at every stage (9 devices behind one address and one /24, as the Enterprise persona's "corporate workstations, managed network" are, and as homes behind a carrier's NAT are). Each relay takes 5 connections from one address (`MAX_CONNECTIONS_PER_IP`), and turns the rest away before the handshake. **What is expected:** at each relay, exactly 5 connections from the office's address at every sample at which 5 or more of its devices are running; every other dial from it turned away and counted, with no breach and no refusal of the address for a time (a dial turned away before its handshake does not count against the address, the record of a relay out of reach §2); the office's requests far within the address's count. Which devices get in is a race, so which of them sync is not known beforehand: a device that is turned away at both relays syncs nothing, and is counted. The office's people are left out of bars 2, 3, 9, 10 and 13, and bar 14 is theirs.
   - **The limit is accepted for R1, and stated:** behind one address, R1's relays take five devices of Cordelia, and an office or a carrier's NAT with more does not sync whole. Raising the bound for an address weakens what it is for, a cap on what one host can make a relay hold (the rationale §5), and R1's people are single users at home. A later record may revisit it; the office measures it meanwhile, so that what a person behind such an address sees is known and not guessed.
7. **Stages 250 and 500 wait for change B** (section 2.5). A run on a build that changes a constant for the test alone would measure a relay that nobody runs.

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

**So 500 devices fit on the build machine as it is,** with about half of its memory and more than half of its CPU to spare, and more memory is not asked for. It would be if a device measured above about 55 MiB at stage 250: 500 of them would then leave the machine under the 2 GiB a run needs available (section 6, rule 5), and 64 GB would be asked for before stage 500.

**Threads are the ceiling to check.** Every thread is a task, and `pid_max`, `threads-max` and the user's `ulimit -u` each bound them. Without root, none can be raised. So before it starts anything the harness reads all three and works out the threads it needs (nodes × 36, and what the machine runs already), and refuses to start where any of the three is under one and a half times that: 27,000 or so at stage 500. Where they are short, it starts each device under an affinity mask of 4 cores (`taskset`), which sizes both of a device's thread pools to 4, as on a laptop of 4 cores: about 11 threads a device, 5,500 for 500. The relays are never masked. The summary says which way the run went.

### 2.5 The raised bound on connections, derived

The bound exists for a flood, so it is set from what a connection can make a relay hold at worst, against a stated memory for a relay's host. Each figure is from the code or the rationale:

| What one connection can make a relay hold | At most | Source |
|---|---|---|
| Data sent and not yet read | 2,048 KiB | `QUIC_RECEIVE_WINDOW` (the rationale §1) |
| The places kept for the peer's channels | 230 KiB | 1,024 channels at about 230 bytes (the rationale §4, `MAX_CHANNELS_ASKED_OF_A_PEER`) |
| The channels proved on it | 48 KiB | 1,024 IDs of 32 bytes in a hash set (`MAX_CHANNELS_PROVED_ON_A_CONNECTION`) |
| The entries shown whole on it | 4 KiB | 8 slots (`MAX_SLOTS_SHOWN_ON_A_CONNECTION`) |
| The connection's own state (QUIC, its tasks, its counts) | 64 KiB | Allowed here; stages 100 and 190 measure it, and change B sets it from that |
| **In all, W** | **2,394 KiB, about 2.34 MiB** | |

**The stated host.** A relay of R1 is taken to run on a host with 2 GiB of memory for the relay (M). That figure is stated here, not known: the person names the host's memory, and the bound follows from the same sum. Of M, 512 MiB is kept for the process at rest (22 MiB measured), its store's cache, its other tables and the system (K).

**The bound** is N = (M − K) / W, rounded down to a multiple of 64: (2,048 − 512) / 2.34 = 656, so **N = 640.** At 640 connections a flood can make a relay hold at most 1.46 GiB, within M. Stage 500 needs 501 at each relay, and 640 leaves 139 for connections being made again after a relay's start or a device's.

- **For another host:** a host of 1 GiB gives N = 192 (R1 then stays near 199 devices); 4 GiB gives 1,472. A relay of R1 that is to carry 500 devices needs at least K + 501 × W = 1.64 GiB for the relay.
- **Not taken:** a smaller receive window, which would halve W. The window is sized to two messages so that a second exchange can begin while the first is read (the rationale §1), and a page of entries is most of one message (`ENTRY_PAGE_MAX_BYTES`); changing it changes the wire's pace for every node, not the bound.
- **Bar 7 is not this.** Bar 7 bars what a relay uses in ordinary use. This sum bars what it can be made to use.

## 3. The pass bars

A stage passes where every bar below holds, on each of three runs of it (section 4.3, rule 4). Each bar says its reason; a bar that is chosen and not derived says so. "The parts treated apart" are each relay's outage (step 6 of section 4.2, and five minutes after it) and each removal's carry window (bar 10). The office of rule 6 of §2.2 is left out of every bar but bar 14.

1. **No request is refused for rate.** At every stage, in the window: no request refused at either relay for being over a connection's or an address's count, no breach. And no device holds a request back by its own pace, but in the minute of a connection's proofs (decision 2026-10-17 §3) and in a carry window, where it is the design (bar 10) and is reported. **Reason:** section 2.3. The busiest device asks under a tenth of what a relay allows a connection; a refusal at this load is a fault.
2. **Sync latency: p50 at most 12 s, p95 at most 25 s, and every edit arrives within 120 s,** over every edit of the window outside the parts treated apart, and every other device of its person set up with both relays that was running from the edit to its arrival. **Reason:** an edit crosses four waits at most: the writer's sync cycle reads the file (`CYCLE_SECS`, 5 s); the push goes at once at publish (the record of 2026-10-04 §4.6); the reader's next pass pulls it (10 s); the reader's cycle writes the file (5 s). That is 20 s at most and about 10 s on average with no load, so 25 s at p95 leaves 5 s for the load and the machine, and 12 s at p50 leaves 2 s. 120 s is `CHANGE_FETCH_MAX_SECS`: past it, a person would see a file as lost. **This meets the demand model's latency for the Casual persona (§2.5, 5 to 10 s) at its median, and does not meet its latency for the Dev Team (2 to 5 s) or Enterprise (1 to 5 s) personas.** A design that pulls every ten seconds cannot: the model assumed a push to devices, which v1 does not have. The record states it, and leaves the model as it is: amending it is a change of the model's own. **For the people split between the relays**, the bars are p95 at most 40 s and every edit within 120 s: the path adds a relay's offer (5 s) and its pull of the other (10 s).
3. **No edit is lost, and a device catches up.** Every edit is found on every other device of its person by the end of the run, as the content written or as a later edit of the same file; and a device that was off holds every edit its person made meanwhile within 60 s of running again. **Reason:** that is what sync is for. 60 s: a device that starts waits for its relays for up to 30 s (`WAKE_WAIT_SECS`), then a pass (10 s) and a cycle (5 s), with 15 s for the connection and the start.
4. **A relay's lock, by kind.** In the window, outside the parts treated apart:
   - **(a)** for each kind of take, the wait at p99 at most 10 ms;
   - **(b)** for the reads (pull, short show, proof), the hold at p99 at most 1 ms;
   - **(c)** for every other kind (the writes, the sweeps, the checkpoint), every hold under 250 ms, and at most 10 holds over 50 ms in the window;
   - **(d)** the lock held for at most a quarter of any minute.

   **Reason:** a bar over all takes would be the bar of an idle pull: at stage 500 a relay takes the lock about 42,000 times a minute for reads and about 55 for writes, so a write that stalls for seconds would pass it. Section 1.4 measures a read's hold at about 12 µs and a growing take's at under 1.5 ms at R1's sizes. 1 ms is chosen, about eighty times a read; 250 ms is chosen, a fortieth of the stream timeout (10 s) after which a device gives up a request, so that a stalled write holds up a few hundred requests and loses none. A queue on the lock grows quickly past a quarter of its time. In the parts treated apart, the same figures are reported and not barred.
5. **A device's lock: no more than one wait over 100 ms for each device in each hour of the window.** **Reason:** `cordelia msg summary` tries the lock for 100 ms (`AGENT_MESSAGE_SUMMARY_WAIT_MS`) and prints nothing where it cannot have it (decision 2026-10-19, names at the limit, §3): each such wait is a summary that a person's agent did not see. A p99 would hide them. The count of one an hour is chosen.
6. **A device's memory: RSS at most 64 MiB at every sample, and no persistent growth.** Growth is found so: the window is cut in two halves, and a device grows where its RSS rises in both halves by more than the threshold. The bar fails where more than 1% of the devices of a run grow, or one device of the population (the same person and device, by the seed) grows in two runs of three. The threshold is 2 MiB an hour at stage 100; from stage 190 it is the 99th percentile of the devices' rises at stage 100, and not under 2 MiB an hour, and the summary says it. **Reason for 64 MiB:** a heavy device measured 25 MiB after a load (section 1.4); the bar is chosen at about two and a half times that, since a device is a background process on a person's laptop. **Reason for the growth test:** a slope of 1% an hour over thirty samples, over some 1,500 device-runs, would fail on the page cache filling as a database grows, or on an allocator's step; growth that persists through the window, or recurs in the same device, is a leak.
7. **A relay's memory in ordinary use: RSS at most 64 MiB and 384 KiB for each open connection (252 MiB at stage 500, 102 MiB at stage 100), and no persistent growth** (by the test of bar 6, with a threshold of 2% of its RSS an hour). **Reason:** a relay with two devices measured 22 MiB; 64 MiB is about three times that, for the store's cache and the relay's tables. 384 KiB a connection is chosen, about eight times the rationale's unmeasured 50 KB. Stages 100 and 190 measure what a connection costs, and change B sets this bar again from it, beside the bound of section 2.5.
8. **A relay's CPU: at most one core on average over the window, and at most two in any minute.** **Reason:** chosen. A relay of R1 should run at stage 500 on a machine of two vCPU with half of it to spare; and on the build machine, where everything shares 16 vCPU, the relays' share must stay small for the latencies to be the relays'.
9. **Every running device stays connected.** At each sample, each relay's open connections equal the devices set up with it that have been running for at least 120 s (and one for the other relay), but for those within 120 s of a relay's start again; and no connection is turned away for the bound on connections or for the subnet. **Reason:** stages are sized within the bounds (rule 1 of §2.2, change B), so a refusal is a fault. 120 s covers a device's dial after it starts and its waits after a failed dial.
10. **A removal reaches every device within 30 s, and its carry ends within its bound.** In the window (step 7 of section 4.2), a tenth of the people with three devices each remove one device.
    - **(a) The spread:** from the line "The change is made (change N)", each other running device of the person has applied change N within 30 s, and each relay holds it within 30 s. **Reason:** the command has given the change to its relays by its first pass after the line (10 s); a device that reaches a relay that holds it hears within the pass under way (10 s, the record of 2026-10-04 §4.6); 10 s more for applying, which carries every name in one transaction (§4.2). The clock starts at the line and not at the command's end, because the command ends only once the relays hold the change and the device has sent what it carried (§7.1), so timed from its end the spread would come out near nothing.
    - **(b) The carry window:** from the same line until each remaining device has sent what it carried and holds every version that each other remaining device carried. It must end within T = 60 × B / 1,572,864 + 60 seconds, where B is the bytes, as entries are counted, of the largest carry among the person's remaining devices, which the harness works out from what it wrote. **Reason:** a device sends a relay at most `OUTBOX_BYTES_PER_MINUTE` (1.5 MiB) a minute; a device takes from one relay up to `PUSH_BYTES_PER_PEER_PER_MINUTE` less the room kept for a show (about 1.94 MiB) a minute, which is faster, so the sending bounds it; 60 s is two passes and the applying. A heavy person whose devices hold the setup's 300 files and the window's edits carries about 3.75 to 4 MB, so T is about 200 s.
    - **(c) Inside the carry window,** the person's edits are not held to bar 2's percentiles: each must arrive by the window's end and 25 s. A device's holding back by its own pace is reported, not failed; a refusal for rate at a relay still fails bar 1.
11. **Churn closes no device's connection, and runs.** On the build with change A: at each relay, the churns counted in the window are two or more (section 4.2 places the window so); no connection of a device is closed by churn; no listed relay's link is closed by churn. On the build without change A (stages 100 and 190 only), the same is reported and not barred: the closures of devices, of the link, the time each closed device took to be connected again, and the latency of the closed devices' people. **Reason:** section 0, item 2, and section 7.3.
12. **The model holds.** Pulls a minute at each relay are within a fifth of section 2.3's figure for the minutes each device was on; edits a minute are within a tenth of section 2.1's; shows a minute and pushes a minute are no fewer than the model's (one show for each pass, one push for each edit to each relay of the writer). **Reason:** otherwise the harness did not drive the load it says, or a device does not do what its record says. Shows and pushes are lower bounds only: a device also shows before each send (every 2 s while something waits, `OUTBOX_FLUSH_INTERVAL_SECS`) and when its leave (10 s, `SHOW_LEAVE_SECS`) has run out in a long pass, and what it pushes depends on what waits, which the model does not count.
13. **Room.** Each relay's room used at the end is within the model's bounds, and nothing was refused for room. The model counts, as entries are counted: for each person and each channel, each author's newest entry in each slot (a relay keeps one entry for each author in each slot, the record of 2026-10-04 §2.4); the words of the personal channel as decision 2026-10-19 (names at the limit) §1 counts them; for each person who removed a device, the whole of the generation left (a relay keeps it until nobody has used it for 90 days, and the removed device is stopped); and for the new generation, each carried version once at the least and once for each remaining device at the most (a relay holds a carried version once for each device that carried it before it saw another's, §12). The bar is between the least and the most, each within 5% for what the model does not count exactly. **Reason:** what a relay holds can be worked out from what was written; the cap is 1 GiB (`MAX_STORAGE_BYTES`), far above what a stage writes.
14. **The office is as expected.** At each relay, exactly 5 connections from the office's address at every sample where 5 or more of its devices are running; every other dial from it turned away and counted; no breach, and no refusal of its address for a time. Its devices connected to no relay, and its people's latencies, are reported. **Reason:** rule 6 of §2.2.
15. **A relay that stops is come back to.** In step 6 of section 4.2 the second relay stops for two minutes and starts again on the same data directory. Each device set up with it is connected to it again within 120 s of its start; each person set up with both relays keeps bar 2 through the outage (through the first relay); each edit of a person split between the relays that was held up by the outage arrives within 120 s of the relay's start; and no request is refused for rate in the five minutes after, but for what the minute of a connection's proofs holds back. The relay's requests, lock and memory in those five minutes are reported. **Reason:** R1 runs two relays so that one can fall. A device connected to another relay dials a lost one after waits of 10, 20, 40 and 80 s (the record of a relay out of reach §2): one dial falls within 30 s of the relay's start, and 120 s leaves room for a dial's own time and the start of 500 connections at once. A device with no relay dials every 30 s at most.

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
2. **It starts the relays,** each from an empty data directory, each listing the other by key, and waits until each is healthy and holds the other's connection. The relays' start is time zero of the run.
3. **It starts the people, ten at a time.** For each person: its devices start; the first makes the phrase at a pseudo-terminal; each other is added; each device maps the person's names to folders of its own and turns sync on; the first device writes the person's first files, 10 in each name, at the profile's sizes; and the harness waits until every device of the person holds every file. The next ten start when the last ten are in step. This is the setup, reported apart: how long it took, and the most each relay asked of its lock and its memory.
4. **The window begins at 55 minutes after time zero,** or ten minutes after the setup ends where that is later, so that what a start costs (every proof, the first show, the first fetch) is past. **It lasts 140 minutes.** A relay's governor runs its first churn between 60 and 65 minutes after its start and its next 60 to 65 minutes after that, so the window holds two churns of each relay (and of the second relay, after its start again in step 6, one more). A run in which a relay counted fewer than two churns in the window is invalid (section 6, rule 7).
5. **Through the window,** one thread schedules every person's edits: a Poisson process at the profile's rate, the profile's bursts, one active device a session (section 2.1). An edit writes a file in a memory folder of the active device as an editor does: the whole file at once. Two in three edits rewrite a file of the name, one in three makes a new one. The file begins with a line that names the edit (`<!-- scale <edit number> -->`) and is followed by random text to its size. The observer reads each file it waits for on each other running device of the person every 250 ms, and an edit counts as arrived when the line names it or a later edit of the same file. Another thread turns devices off and on as rule 4 of §2.1 says. Sampling (section 1.2) goes on once a minute for each process, spread over the minute so that no second reads 500 processes.
6. **At minute 40 of the window the second relay stops** (SIGTERM) and **starts again two minutes later** on the same data directory. Bar 15 reads it, and the five minutes after its start are treated apart.
7. **At minutes 110 to 115 of the window, removals are made.** A tenth of the people with three devices, chosen by the seed, each remove one device, with `cordelia remove-device` at a pseudo-terminal with the phrase, as `person_e2e.rs` does. The harness timestamps the line "The change is made". The removed device is then stopped for good. Bar 10 reads these, and the carry windows are treated apart.
8. **It ends at minute 140.** Every node is told to stop (SIGTERM), and each must stop within `NODE_STOP_TIMEOUT_SECS`. The read-only reads of each relay are made a last time. The harness checks that every pid it started has gone.
9. **It writes the run's summary,** and keeps the data directories only where `CORDELIA_E2E_KEEP` is set.

A run at stage 500 takes about three and a half hours: the setup and the wait to minute 55, the window of 140 minutes, and the end.

### 4.3 Rules of the harness

1. **It dials nothing but its own relays.** Each node's configuration names only the run's relays, by address on 127.0.0.1 and by key, and sets `dns_discovery = ""`. Before each node is started the harness asks what it will dial (`Node::will_dial`, `assert_on_this_machine`) and refuses it otherwise. At the end it reads each relay's peers and checks that every key is one of the run's. No address outside 127.0.0.0/8 is written into any configuration, and a configuration that would hold one is refused before anything starts.
2. **It changes no constant, and gives each node the settings it has in R1, and lists every other.** A relay is given the governor of `deploy/relay/relay1.toml` (hot 50, warm 50, cold 200) and every other setting at its default; a device is given the defaults. The faster tick and shorter tenure that the real-process tests give their nodes are not used. The harness writes its own configurations rather than `node_made`'s, which listens on 0.0.0.0. What each node is given beyond its defaults is listed in the summary: its `listen_addr` (127.0.0.1 and a port for a relay; the person's address and a port for a device); its relays and their keys; `dns_discovery = ""`; `allow_private_addresses = true`, without which a node does not dial an address on loopback; the log level, `info`; and its data directory and ports.
3. **A run is repeated from its seed.** The seed fixes the population, the names, the office, the people split between relays, the active devices, the times of edits, bursts and times off, the sizes, and the choices of step 7. The relays' and devices' own randomness (keys, churn's choices, jitter) is not fixed: two runs from one seed drive the same load, and differ in what the nodes do. The summary names the seed, the commit and the stage.
4. **Each stage is run three times,** with seeds 1, 2 and 3, and passes where each run passes. The summary of a stage gives each run's figures and their spread.
5. **It stops early on a fault, and still writes the summary:** a node that exits when it was not told to, a relay that does not answer for a minute outside step 6, or the machine's memory available under 2 GiB. The summary says why it stopped.
6. **It leaves no node behind.** Each node is started in a process group of its own and with `PR_SET_PDEATHSIG` set to SIGKILL, from one thread that lives as long as the run (the signal follows the thread that started the child), so that a harness that is killed outright takes its nodes with it. It writes the pids it starts to a file in its output directory. A run that starts and finds a live process of a pid in an earlier run's file, whose command line is a node of that run, refuses to start and names it.

### 4.4 What a run leaves

In `CORDELIA_SCALE_OUT`:

- **`SUMMARY.md`, the one file for a person to read.** First line: PASS, FAIL or INVALID, the stage, the seed, the commit, and whether change A and change B are in the build. Then each bar of section 3, one line each: the figure, the bar, pass or fail. Then the checks of section 6 (whether the run is valid). Then, per relay and per profile of device: the median and the worst of each measure, and the parts treated apart. Then the setup's figures and every setting given beyond the defaults. It names no machine and no host: it says "16 vCPU, 32 GB" from `/proc`, and no more.
- `samples.jsonl`: every sample, one line each.
- `edits.csv`: every edit, and its arrival on each other device.
- `pids`: the pids the run started.
- Each node's log, where `CORDELIA_E2E_KEEP` is set.

## 5. Set aside, and why

- **Docker.** The build machine has none, and nothing in the test needs it: real processes on loopback run the release binary as a person runs it. The stale Docker suites of `tests/e2e/` measured mesh formation and delivery of items of the older kind, which v1 does not use; nothing is taken from them but the lesson that one host can run hundreds of nodes.
- **Other machines, and a real network.** Everything is on one machine, on loopback, with no latency and no loss. The latencies measured are a floor: a real network adds some tens of milliseconds a hop, against a pull every ten seconds. The cost of loss and of slow links is not measured.
- **A true sleep.** A freeze stands for it (rule 4 of §2.1). The wake from a sleep is tested by `device_entries_e2e.rs`.
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

1. **The population.** For each stage, the population has exactly the stage's devices, the mix of §2.2, the office, the split people, a /24 for each other person and no address outside 127.0.0.0/8; the same seed gives the same population; another seed gives another.
2. **The schedule.** Over a simulated ten hours, each profile's edits an hour are within 5% of section 2.1; its bursts come once each 30 minutes; every edit of a session is on its active device; the active device is never off in its session; and each profile's share of time off is within 5% of what rule 4 of §2.1 gives.
3. **The observer.** With two folders and no node: a file copied from one to the other after 3 s is observed at 3 s within 0.3 s; a file never copied is counted as not arrived at 300 s; a later edit of the same file that arrives first counts the earlier as arrived; a file that is copied with other content does not count.
4. **A small run, end to end:** two relays and seven devices of three people (one casual, one developer, one split between the relays), with one device off and on, the second relay stopped and started, a window of ten minutes with churn every two minutes (the only run in which a governor's interval is set, and it says so), and one removal. It checks that every measure of section 1.2 is in `SUMMARY.md` with a value; that the counters at a relay agree with the model for those devices within a fifth; and that what the harness counted written equals what it counted arrived and not arrived.
5. **A run that must fail.** The same small run, where one device is stopped in the middle of the window and not started again: its person's later edits do not arrive at it, bar 3 fails, and the summary's first line says FAIL. So a bar can fail.
6. **The configurations.** A configuration the harness writes names nothing to dial but its relays (every device's `will_dial` is a subset of them), binds a loopback address and no other, and lists in the summary every setting beyond the defaults; one with an address outside loopback is refused before any process starts.
7. **The checks before a run.** With limits on threads given to it, the harness refuses where any is under one and a half times what it needs, and chooses the mask of 4 cores where told to; with a pid file of an earlier run whose pid is live and a node of that run, it refuses to start.

**How each run is checked to have measured what it says.** The summary's checks of validity, each of which marks the run INVALID (not failed) where it does not hold:

1. **Every process was sampled.** No running process lacks a sample for more than two minutes in the window.
2. **The counts agree.** What devices count they asked of a relay, and what the relay counts it was asked, agree within 1% for each kind; the bytes a relay counts in agree with what devices count they pushed within 5%.
3. **The edits add up.** Edits written equal edits observed arrived plus not arrived, for each other device.
4. **The observer kept its pace.** Its reads of a file were at most 500 ms apart at p99; otherwise the harness was starved, and the latencies are its own.
5. **The machine was not the bottleneck.** In every minute of the window: the machine's CPU at least 20% idle; iowait at most 10% of its time; the disk's mean write at most 20 ms; memory available above 2 GiB; and the harness's own process under one core. Otherwise the run measured the machine, and is run again with fewer devices, the mask of section 2.4, or more memory. The figures for iowait and the disk are chosen.
6. **The load was the load.** Bar 12 holds; where it does not, the run is invalid as well as failed.
7. **Churn had its chance.** Each relay counted two churns or more in the window, and had a cold peer at each. On the build without change A, a run in which no churn at either relay closed a connection is invalid: the churn it was to measure did not happen.

## 7. The pieces, and their order

Each piece is a change of its own, reviewed and merged apart, in this order.

### 7.1 The counters

What section 1 needs inside the node: the wrapper around the lock, with its kinds; the timing of `rates` and `room`; the counters of requests, answers and bytes by stream kind; the gauge of connections and the counters of connections turned away; the governor's counters (churns run, connections closed by churn of devices and of relays, closures of each listed relay's link) and its hot count served apart from the count of connections; the device's counters of what it asked and held back; and the route `/api/v1/metrics/load`, which reads atomics alone. Its tests: each counter moves for what it counts and for nothing else; the route takes no lock (a test holds the lock and reads the route); the cost of timing (section 1.1, rule 5). It changes nothing a node does.

### 7.2 The harness

`tests/scale.rs` as section 4 says, with its tests (section 6). It needs the counters. It changes nothing in the node.

### 7.3 Change A: a relay does not churn devices, or the relays it lists

**What it changes.** In a relay's and a bootnode's warm churn (`governor.rs`, `churn_warm`), a peer that is not a relay, and a relay that the operator lists, are never among the peers churn closes, as a personal node's relays are not (the record of relays §2). Churn may still close a relay the operator does not list. Hot churn moves peers between hot and warm and closes no connection, and is not changed.

**Why.**

- **Closing a device brings in nobody.** Churn closes a peer so that another may take its place, and dials a cold peer for it. At a relay the cold peers are devices that went away, and a personal node accepts no inbound connection, so each such dial fails. What is left is the closure alone.
- **What churn is for does not hold for a device.** Churn exists so that a node meets other peers, and so that an attacker cannot hold its place among them. A device at a relay holds no place in anything the relay chooses: it is let in by the bounds on connections, for the address, the subnet and the relay, and those are what cap an attacker. A connection that is closed is made again within seconds, so churn removes nobody, and only costs.
- **What it costs.** At 500 devices a relay with a cold peer (in use, always) closes about 100 connections an hour. Each is made again with up to 32 proofs and a whole show of 33 KB; meanwhile its device syncs through one relay, and a device set up with one relay not at all.
- **The listed relay.** At a relay the other relay is a warm peer and is not trusted (`governor.rs`), so churn can close the link between R1's two relays, and the edits of people split between them then wait. With devices spared and the listed relay not, the link would be the only warm peer churn may close, and it would be closed at every churn that finds a cold peer: every hour. The operator lists the relays it works with because it wants that link.

**Its tests.** In `governor.rs`: a relay with warm devices, a warm listed relay, a warm relay that is not listed, and cold peers closes, through five churn intervals, no device and not the listed relay, and closes the relay that is not listed. A personal node's churn is as today. In `devices_e2e.rs`: a relay that churns every two seconds (`Node::churn_every_secs`), with two devices and a listed relay, keeps every one of their connections through six intervals, with a device of the person's turned off to give it a cold peer.

**What the record's test says without it.** Stages 100 and 190 are run first on the build without change A, and their summaries say what churn cost (bar 11). Every stage is then run with it.

### 7.4 Change B: the raised bound on connections

**What it changes.**

1. `MAX_INBOUND_CONNECTIONS` goes from 200 to the bound of section 2.5: 640 against a host of 2 GiB for the relay, or what the same sum gives for the host the person names. Its test in `protocol.rs` (`test_max_inbound_connections_network_protocol_9_1`) follows, with a test that the bound times W, and K, fit within M as `protocol.rs` states them.
2. The rationale §5 gives the derivation of section 2.5 in place of "about 50KB a connection", with W's figures, and with the cost of a connection that stages 100 and 190 measured. The rationale §1 ("with 200 connections a relay holds at most 400MB unread") and §4 ("200 connections … about 46MB") are worked out again at the new bound, and `configuration.md` and `network-protocol.md` §9.1 and §12.4 say it.
3. **`limits.max_inbound_connections` is read.** Today nothing reads it. The code takes the lower of it and the constant, as `channels_proved_on_a_connection` is taken, and a configuration that sets it above the constant is refused when it is loaded, with a line that says the most it may be. So an operator can lower the bound for a smaller host, and no setting is silently ignored. `limits.max_connections_per_ip`, which nothing reads either, is read the same way. Their tests: a configuration above the constant is refused; a relay set to 3 turns away the fourth device, in a test with real processes.
4. Bar 7 is set again from the cost measured at stages 100 and 190.

**Why.** Section 0, item 1, and section 2.5. Until it is made, R1 carries about 199 devices.

**Order.** Stages 100 and 190 run before change B, and give it the cost of a connection. Stages 250 and 500 run after it.

## 8. What this record would alter elsewhere

No other record or spec is changed by this one. Changes A and B, when they are made, alter: the record of relays §2 (a relay too keeps its devices and its listed relays through churn); `network-protocol.md` §5.4 (churn at a relay); the rationale §1, §4 and §5; `configuration.md` §2.6 and `network-protocol.md` §9.1 and §12.4 (the bound, and that the setting is read). The demand model §2.5 is not met for the Dev Team and Enterprise personas by v1 (bar 2), and is left as it is.

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
