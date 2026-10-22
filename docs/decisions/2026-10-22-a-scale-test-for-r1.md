# Decision: a scale test for R1

**Date**: 2026-10-22
**Status**: Proposed. Not built.
**Cited as**: "decision 2026-10-22 §3, rule 4". The numbers do not change. A number that is not used stays unused.

Words used throughout:

- **The gate** is gate 10 of R1: "The relays carry the load we expect. A scale test at a device count agreed beforehand. Proposed: 500, ten times the traction bar." **The issue** is cordelia-node #46: how many devices and channels one relay carries, and how a mesh of relays behaves as it grows (sync latency, memory, governor behaviour, rate limits).
- **The record of 2026-10-04** is [`2026-10-04-a-persons-devices.md`](2026-10-04-a-persons-devices.md). **The record of relays** is [`2026-10-17-a-devices-relays-and-connections.md`](2026-10-17-a-devices-relays-and-connections.md). **The demand model** is [`docs/specs/demand-model.md`](../specs/demand-model.md), and **the rationale** is [`docs/specs/parameter-rationale.md`](../specs/parameter-rationale.md).
- **A device** is one node process of the release binary, with role `personal`, a data directory of its own, a configuration of its own and a home directory of its own that holds its memory folders. It is started as the real-process harness starts a node (`crates/cordelia-node/tests/common/mod.rs`, `node_made`). **A relay** is one such process with role `relay`.
- **A person** is a set of devices that follow one phrase. Each person's first device makes the phrase, and the others are added with `add-device` and `accept`, at a pseudo-terminal, as `devices_e2e.rs` does.
- **A name** is a memory folder that a person's devices map to one name; its channel is one channel at a relay.
- **The build machine** is one machine of 16 vCPU and 32 GB of memory, with a 290 GB disk, running Ubuntu 24.04, with no Docker and no root.
- **A stage** is one run at a fixed number of devices: 100, 190, 250 or 500 (section 2).
- **A pass** is a device's round of its relays every ten seconds; **a pull** is one request for one channel at one relay; **a show** is a device showing its change entry; **a proof** proves a channel's key on a connection; **a push** sends entries (the record of 2026-10-04, §2.4 and §4.6).
- **The lock** is the one database lock of a node: the `Mutex<Connection>` that every request of the streams of entries takes at a relay, and that the sync cycle, the passes and the local API take on a device. **Its wait** is the time from asking for it to holding it; **its hold** is the time it is held.
- **The run's summary** is the one file a run leaves for a person to read (section 4).

---

## 0. What this is

The gate asks for a scale test at a device count agreed beforehand. This record proposes that count, says what is measured and how, sets a pass bar for each measure with its reason, and describes a harness that runs on one build machine with real processes. Nothing is built yet: the record is reviewed first.

Three things are known before anything is built, and they shape the plan.

1. **A relay takes at most 200 connections** (`MAX_INBOUND_CONNECTIONS`, the rationale §5). A device dials every relay it is set up with, and R1's devices are set up with both relays. So each relay holds one connection for each device, and R1's two relays carry at most 199 devices between them, whatever the number of relays. The gate's 500 cannot pass as built. This record changes no constant. It runs the stages up to 190 as built, measures what a connection costs, and puts the raised bound to a change of its own before the stages of 250 and 500 (section 2, rule 6).
2. **A device pulls each of its channels from each relay every ten seconds,** one request for each channel. A person with 30 names asks each relay 192 pulls a minute from each device. Each pull reads the relay's store under the lock. Measured (section 1.4): an idle pull holds the store for about 12 µs, whatever the number of channels, up to 30,000. At 500 devices that is under 1% of the lock's time. The pull that names several channels is not needed for the lock; whether it is needed for anything else (the cost of a stream, the relay's CPU) is what the test answers.
3. **A relay sums its room by reading its table of channels** for each entry that would make a channel larger (`relay::used_bytes`). Measured: the sum costs about 29 ns for each channel held, 80 µs at the 2,740 channels of stage 500 and 0.87 ms at 30,000. At R1's load that is small. The counter for the room is not needed for the gate by these numbers; the test says whether it is.

## 1. What is measured

### 1.1 Rules for every measure

1. **Each measure has a unit, a source, and a cadence.** Section 1.2 lists them.
2. **Nothing is read in a way that changes what is measured.** Three kinds of source are used, in this order of preference:
   - **from outside the process:** `/proc/<pid>/status` (memory), `/proc/<pid>/stat` (CPU), `/proc/<pid>/fd` and `/proc/<pid>/task` (descriptors and threads), and files the harness reads in a device's memory folders. None of these touches the node;
   - **counters inside the node, read through a route that takes no lock** (rule 3);
   - **the node's database, read through a read-only SQLite connection,** once every five minutes. The database is in WAL mode, so a reader does not wait for the writer and does not hold it up; and it is not the node's lock, which is in the process. Only the relay's room is read so.
3. **The counters are new, and are a change of their own, before the harness** (section 4, step 1). They are atomic counters and fixed histograms in the node. They are served at a new route of the local API, `/api/v1/metrics/load`, in the text form that `/api/v1/metrics` uses, and the route reads the atomics alone. **`/api/v1/metrics` is not used:** it takes the lock to count channels and items (`handlers::metrics_with`), and so would be one more request on the lock under test. The status route (`/api/v1/status`) is read on a device once a minute only, for what no counter holds (section 1.2), and that read is counted as one of the device's own uses of its lock.
4. **The cost of timing the lock is measured, and bounded.** Timing a wait and a hold is two reads of the monotonic clock and two atomic additions for each time the lock is taken, some tens of nanoseconds against a hold of 12 µs at the least. A unit test of the change times a million takes of the lock with the timing and without it; the difference must be under 1% of the median hold measured in section 1.4, or the timing is sampled (one take in sixteen) instead.
5. **Every measure is taken from the start of the measured window to its end** (section 4), and the setup is reported apart from it.

### 1.2 The measures

**Per relay.** Each is read once a minute from `/api/v1/metrics/load` unless it says otherwise.

| Measure | Unit | How it is read |
|---|---|---|
| Requests by kind | requests a minute, for each of: show whole, show short, proof, pull, push, the streams between relays (`0x14`) | A counter for each stream kind, counted when the request is read |
| What became of them | requests a minute, for each of: answered, not now, refused for rate (over the connection's or the address's count, a breach), refused for room, refused for the allowance of new channels | A counter for each answer |
| Bytes | bytes a minute in and out, for each stream kind | Counted at the codec, as each frame is read or written |
| The lock's wait | µs, as a histogram (buckets of powers of two from 1 µs to 16 s); reported as p50, p99, the most, and the sum in a minute | Timed at each take of the lock |
| The lock's hold | µs, the same histogram; and the share of each minute that the lock was held | Timed from the take to the drop of the guard |
| Memory | MiB of resident memory (RSS), and its peak | `/proc/<pid>/status`, `VmRSS` and `VmHWM` |
| CPU | share of one core over the minute | `/proc/<pid>/stat`, user and system ticks |
| Open connections | connections, and connections refused for the bound on connections (the count, the address, the subnet) | A gauge, and a counter for each refusal |
| Room used | bytes as entries are counted (`entry_cost`), and channels held | Every five minutes, by a read-only connection: `SUM(bytes)` and `COUNT(*)` of `relay_channels` |
| The governor | peers hot, warm and cold; connections it closed in churn; connections closed for any other reason | The gauges that exist (`cordelia_peers_hot`, `cordelia_peers_warm`), served at the new route too, and two counters |

**Per device.**

| Measure | Unit | How it is read |
|---|---|---|
| Sync latency | seconds, from the moment the harness writes a file on one device to the moment the same content is in the file on another device of the same person | The harness itself (section 4, step 5), for every edit and every other device of the person |
| Memory | MiB of RSS, and its peak | `/proc`, once a minute |
| CPU | share of one core | `/proc`, once a minute |
| Requests | requests a minute to each relay, by kind; and those it held back by its own pace (`OWN_ENTRY_REQUESTS_PER_MINUTE`) | Counters of the new route |
| Requests refused for rate | requests, in all, for each relay | The same counters; cross-checked against the relay's counts |
| The lock's wait | µs, as at a relay | The same histograms |
| What waits to be sent | entries | `outbox_waiting` of `/api/v1/status`, once a minute |
| Conflict copies | files | The harness counts the copies the adapter keeps beside files, at the end |

**Across the mesh.**

| Measure | Unit | How it is read |
|---|---|---|
| A change's spread | seconds, from the end of `cordelia remove-device` on one device to the moment each other remaining device of that person has applied the change, and to the moment each relay holds it | The harness polls each device's `/api/v1/person` once a second for the applied statement, and each relay is read from what each device says of it (`cordelia devices --json`) |
| A change's cost | the latency of the person's next edits, from the change to two minutes after | Sync latency, as above, kept apart for those edits |
| The governor's churn | connections a relay closed in churn in each churn interval, and how long each device so closed took to be connected again | The relay's counter; the device's `peers_hot` and `peers_warm` in its status, once a minute, and its log line for each connection made |
| Between the relays | entries a minute passed between the two relays, and the time from an entry stored at one relay to the same entry stored at the other | The relay counters of `0x14`; for the time, the edits of the people whose devices are split between the two relays (section 2.2, rule 4) |

### 1.3 What the harness itself records

For each edit: who wrote it, on which device, in which name and file, its size, and the time it was written. For each other device of the person: the time the content arrived, or that it did not within 300 seconds. For each process: its pid, its start and its end, and how it ended. For the machine: its share of CPU idle, its memory available and its disk free, once a minute, from `/proc/stat`, `/proc/meminfo` and `statvfs`. These say whether the run measured the relays or the machine (section 6, rule 5).

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
- **The room's sum grows with the channels held,** about 29 ns each, and a take that grows a channel pays it, beside the write itself (about 200 µs, most of it the commit). At stage 500 (2,740 channels) a growing take costs about 0.45 ms, and some 55 of them come in a minute. At 30,000 channels the sum is most of a take.
- What a request costs outside the store (the QUIC stream, the frame, the checks of signatures, the rate counts) is not in these figures. That is what the test measures at the relay as a whole.

**Two: the memory of one device and of one relay, at rest and under a small load.** The real-process harness, with this build's release binary: one relay and two devices of one person, each device with 30 names mapped (the heavy profile of section 2), and then 600 entries of about 2 KB published on one device through its local API, five a second, over its 30 names. RSS from `/proc`, CPU over a minute.

| Moment | Relay: RSS | Device a: RSS | Device b: RSS | CPU (relay / a / b), share of a core |
|---|---|---|---|---|
| Started, connected, no phrase, after 20 s | 19.1 MiB | 19.8 MiB | 19.7 MiB | 0.13% / 0.10% / 0.10% |
| A phrase, b added, 30 names each, idle 60 s | 20.2 MiB | 23.0 MiB | 22.7 MiB | 0.30% / 0.95% / 0.92% |
| Peak during the load | 22.0 MiB | 24.9 MiB | 24.4 MiB | |
| 60 s after the load | 22.1 MiB | 24.9 MiB | 24.9 MiB | 0.27% / 0.98% / 0.97% |

Beside it: each process had 10 to 12 threads and 33 open descriptors; the relay's database was 3.4 MiB and each device's 3.1 MiB after the load; and the last entry was at b 3.1 s after the last was published (through the local API, so with no sync cycle on either side). The nodes logged at `debug`, as the harness's nodes do, which costs CPU; the scale harness logs at `info`.

What it says:

- **A device is about 20 MiB at rest and 25 MiB with 30 names after a load.** Memory grew by about 2 MiB with the 30 names and 2 MiB with the load, and did not grow in the minute after.
- **A heavy device idle costs about 1% of a core,** most of it its pass of 32 channels every ten seconds and its sync cycle every five. A device with no phrase costs a tenth of that.
- **A relay with two devices is about 22 MiB.** What a connection costs at a relay is not shown by two: it is what stages 100 and 190 measure (rule 6 of §2.2). The rationale's figure, about 50 KB a connection (§5), has no measurement behind it.
- These were taken on 4 vCPU. A node's runtime starts one worker thread for each core, so on the build machine each node has some 20 threads, and its RSS may be a few MiB higher. Stage 100 measures it there before anything larger is run.

## 2. The population

### 2.1 Profiles, from the demand model's personas

Three profiles of a person. Each is a persona of the demand model as one person sees it on their own devices. The Agent Swarm persona is set aside (section 5).

| Profile | Persona (demand model §1) | Devices | Names | Edits an hour, for the person | Size of a memory file | Burst |
|---|---|---|---|---|---|---|
| Casual | Casual User, §1.1 | 2 | 4 | 10 | 0.5 to 5 KB | 5 edits in 10 s |
| Developer | Active Developer Team, one user, §1.2 | 3 | 12 | 20 | 1 to 10 KB | 10 edits in 30 s |
| Heavy | Enterprise, one user, §1.3 | 3 | 30 | 30 | 2 to 20 KB | 20 edits in 60 s |

Where each figure comes from:

- **Devices.** Cordelia v1 is one person's memory on each machine they use. A casual user has a laptop and a desktop; a developer and a heavy user a third (a work machine, or a build machine).
- **Names.** The middle of each persona's channels (2 to 5; 5 to 15; 20 to 100), less the channels that are no names: a person's devices also hold a personal channel and a messages channel. The heavy profile's 30 is the figure of the review of 5 October, and is low in the Enterprise range: past it the requests grow in proportion (section 2.3), and the rationale sizes a device for 256 names.
- **Edits.** The steady rate of each persona during its active hours: one memory every 5 to 10 minutes (Casual); 10 to 30 a session in 5 to 8 sessions a day (Developer, about 20 an hour); 5 to 15 a session in 10 to 20 sessions a day (Enterprise, the top of its range, 30 an hour). Every person is active for the whole measured window: the window is a busy hour, not a day.
- **Sizes.** Each persona's item size. The harness draws a size evenly on a log scale within the range. Content is padded to a power of two, so a relay counts a 5 KB file at 8 KB plus 1 KB.
- **Bursts.** Each persona's peak burst, once every 30 minutes for each person, at a time drawn at random.
- **One device at a time.** A person works at one machine at a time. The harness gives each person one active device for each session of 10 to 30 minutes, drawn at random among the person's devices, and every edit of that session is written there. So conflict copies come only from the rare edits that cross a change of device, as they would.

### 2.2 The mix, and the stages

| Stage | Casual people (devices) | Developers (devices) | Heavy people (devices) | People | Devices | Channels at a relay |
|---|---|---|---|---|---|---|
| 100 | 20 (40) | 14 (42) | 6 (18) | 40 | 100 | 548 |
| 190 | 38 (76) | 27 (81) | 11 (33) | 76 | 190 | 1,034 |
| 250 | 50 (100) | 35 (105) | 15 (45) | 100 | 250 | 1,370 |
| 500 | 100 (200) | 70 (210) | 30 (90) | 200 | 500 | 2,740 |

A person's channels at a relay are their names, the personal channel, the messages channel and the phrase's channel: 7, 15 and 33. (A pair channel, made when a device is added, is not counted: it is used for an hour at setup.)

Rules:

1. **The stages are 100, 190, 250 and 500,** in that order, each run on its own from empty data directories. 500 is the gate's figure and is the count this record proposes to agree. 100 is the first stage to run. 190 is the most that R1 carries as built, with room left at each relay for the other relay's connection and for connections being made again after churn (rule 6).
2. **Each stage keeps the mix:** two in five people are casual, seven in twenty developers, three in twenty heavy, and the devices follow. The population is drawn from a seed (section 4, rule 3).
3. **Two relays, as R1 runs them:** each lists the other by key, as `deploy/relay/relay1.toml` and `relay2.toml` do, so that they pass entries between them; each device is set up with both. A stage is also run once with one relay, at 100 devices, to say what one relay carries alone.
4. **A tenth of the people of each stage, chosen by the seed, have their devices split between the relays:** the person's first device is set up with the first relay only, and the others with the second only. So an edit between their devices crosses from one relay to the other, and measures that path (section 1.2). It is R1's case of a device that reaches one relay. Every other person's devices are set up with both.
5. **Each person has its own address.** All processes run on 127.0.0.1's network, and a relay counts connections, requests and new channels by address and by /24 (`MAX_CONNECTIONS_PER_IP` 5, `MAX_CONNECTIONS_PER_SUBNET` 20, the limits for an address at five times those for a connection, `NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR` 256). On one address the first 5 devices would take every place. So each person's devices bind an address of their own in 127.0.0.0/8, one /24 for each person (person k at 127.(20 + k / 256).(k mod 256).1): a person's devices share it, as the devices of a home share one. A device's QUIC endpoint binds the address of its `listen_addr` (`transport::create_client_endpoint`, `main.rs`), and Linux delivers all of 127.0.0.0/8 to the loopback interface with no setting. A throwaway check showed a datagram sent from 127.0.12.34 arrives from that address. The relays listen on 127.0.0.1.
6. **The bound on connections is raised before stage 250, by a change of its own.** That change sets `MAX_INBOUND_CONNECTIONS` from what stages 100 and 190 measure a connection to cost at a relay (memory and CPU), and states it in the rationale §5. Until it is merged, stages 250 and 500 are not run: a run on a build that changes a constant for the test alone would measure a relay that nobody runs. **Where that change is not made, the gate is not met, and this record says so plainly:** R1 then carries 199 devices.

### 2.3 What the model says each stage asks of a relay

From the record of 2026-10-04 (a pull of each channel of the device's own every ten seconds, from each relay, one show for each pass at least) and section 2.1. These are what the test checks the harness drives (section 6, rule 4), and what the bars are set against.

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

A heavy device asks each relay about 200 requests a minute, under a tenth of its own pace (2,250) and of the relay's count for a connection (3,000). A heavy person's three devices at one address ask about 600, against the 15,000 an address may.

### 2.4 How many devices fit on the build machine

From section 1.4, with a margin for the 16 worker threads of the build machine:

| | One | At stage 500 |
|---|---|---|
| Device, memory | 25 MiB measured, 30 MiB allowed | 500 × 30 MiB = 14.6 GiB |
| Relay, memory | 22 MiB with two devices; at most the bar of §3, rule 7 | 2 × 256 MiB = 0.5 GiB |
| The harness, memory | | under 0.5 GiB |
| The kernel's cache of 500 databases and logs | | some GiB, given back on demand |
| Device, CPU | about 1% of a core for a heavy device, less for the others; about 0.7% on average | 500 × 0.7% = 3.5 cores, and the edits' own work |
| Relay, CPU | 0.3% of a core with two devices | about 0.3 of a core each, scaled by requests (section 2.3), and at most the bar of §3, rule 8 |
| Descriptors | 33 for each process | about 17,000 in all; the limit is per process |
| Disk | 3 MiB for each database after a small load | under 50 GB with logs, of 290 GB |

**So 500 devices fit on the build machine as it is,** with about half of its memory and more than half of its CPU to spare. More memory is not asked for. It would be if a device measured above about 55 MiB at stage 250: 500 of them would then leave the machine under the 2 GiB that a run needs available (section 6, rule 5), and 64 GB would be asked for before stage 500.

## 3. The pass bars

A stage passes where every bar below holds, on each of three runs of it (section 4, rule 4). Each bar says its reason. A bar that is chosen and not derived says so.

1. **No request is refused for rate in ordinary use.** At every stage, in the measured window: no request refused at either relay for being over a connection's or an address's count, no breach, and no device whose pace held a request back outside the minute of a connection's proofs. **Reason:** section 2.3. The busiest device asks under a tenth of what a relay allows a connection, and the busiest address under a twentieth; a refusal at this load is a fault. (A device's own pace holding back the proofs of a new connection is the design, decision 2026-10-17 §3, and is reported, not failed.)
2. **Sync latency: p50 at most 12 s, p95 at most 25 s, and every edit arrives within 120 s,** over every edit of the measured window and every other device of its person set up with both relays. **Reason:** an edit crosses four waits at most: the writer's sync cycle reads the file (`CYCLE_SECS`, 5 s); the push goes at once at publish (the record of 2026-10-04 §4.6); the reader's next pass pulls it (10 s); the reader's cycle writes the file (5 s). That is 20 s at most and about 10 s on average with no load, so 25 s at p95 leaves 5 s for the load and the machine. 12 s at p50 keeps within the demand model's acceptable latency for the Casual persona (§2.5, 5 to 10 s) plus the two seconds of the machine's contention. 120 s is `CHANGE_FETCH_MAX_SECS`: past it, a person would see a file as lost. **For the people set up with one relay**, whose edits cross between the relays (rule 4 of §2.2), the bars are p95 at most 40 s and every edit within 120 s: the path adds a relay's offer (5 s) and its pull of the other (10 s).
3. **No edit is lost.** Every edit written is found on every other device of its person by the end of the run, as the content written or as a later edit of the same file. **Reason:** that is what sync is for.
4. **A relay's lock: wait at p99 at most 10 ms, hold at p99 at most 5 ms, and held for at most a quarter of any minute.** **Reason:** section 1.4 measures a pull's hold at 12 µs and a growing take's at under 1 ms at R1's sizes, and section 2.3 puts the lock's busy time at about 1% at stage 500. A queue on the lock grows quickly past a quarter of its time. 10 ms and 5 ms are chosen: a thousand times what the store needs, and a thousandth of the stream timeout (10 s) after which a device gives up on a request. A breach of these says that something holds the lock that the model does not know of.
5. **A device's lock: wait at p99 under 100 ms.** **Reason:** `cordelia msg summary` tries the lock for 100 ms (`AGENT_MESSAGE_SUMMARY_WAIT_MS`) and prints nothing where it cannot have it (decision 2026-10-19, names at the limit, §3). A heavy device's 30 names are far below the sizes that record measured waits of that length at.
6. **A device's memory: RSS at most 64 MiB at every sample, and no growth.** No growth is: the least-squares slope of each device's RSS over the last 30 minutes of the window is under 1% of its mean an hour. **Reason:** a heavy device measured 25 MiB after a load (section 1.4). The bar is chosen at about two and a half times that: a device is a background process on a person's laptop and should stay small, and a leak shows first in the slope, long before the bar.
7. **A relay's memory: RSS at most 64 MiB and 384 KiB for each open connection (252 MiB at stage 500, 102 MiB at stage 100), and no growth by the same test.** **Reason:** a relay with two devices measured 22 MiB; 64 MiB is about three times that, for the store's cache and the relay's tables. 384 KiB a connection is chosen, about eight times the rationale's unmeasured 50 KB (§5), well under the 2 MiB that a connection's receive window allows it to buffer (`QUIC_RECEIVE_WINDOW`). Stages 100 and 190 measure what a connection costs, and the change that raises the bound on connections (rule 6 of §2.2) sets this bar again from that measure, before stage 250.
8. **A relay's CPU: at most one core on average over the window, and at most two in any minute.** **Reason:** chosen. A relay of R1 should run at stage 500 on a machine of two vCPU with half of it to spare; and on the build machine, where everything shares 16 vCPU, the relays' share must stay small for the latencies to be the relays' (section 6, rule 5).
9. **Every device stays connected.** Each relay's open connections equal the devices set up with it (and one for the other relay) at every sample of the window, but for those being made again after churn (bar 11); and no connection is refused for the bound on connections, the address or the subnet. **Reason:** stages are sized within the bounds (rule 6 of §2.2), so a refusal is a fault.
10. **A removal reaches every device of its person within 30 s,** and every relay within 30 s. In the window's last part (section 4, step 6), a tenth of the people with three devices each remove one device. Each other device must have applied the change within 30 s of the end of `cordelia remove-device`; and each such person's next edits must keep bar 2's latency from two minutes after the change. **Reason:** a device that reaches a relay that holds the change hears within the pass under way (10 s, the record of 2026-10-04 §4.6), and the device that made the change gives it to each relay on its first pass after it (10 s). 30 s is the two passes and 10 s for applying, which carries every name the device holds in one transaction (§4.2). Two minutes is `CHANGE_FETCH_MAX_SECS`, the time a device has to fetch the new channels.
11. **The governor's churn is as its rule says, and costs nothing that a person sees.** At each relay, in each churn interval, churn closes no more than a fifth of the warm peers (rounded up, `CHURN_FRACTION`); every device it closes is connected to that relay again within 60 s; and no edit of a person whose device was closed so breaks bar 2. **Reason:** a relay churns its warm peers once an hour (the record of relays §2: a personal node does not, a relay does), and with hundreds of devices warm at a relay a fifth of them is a large number of connections made again each hour, each with its proofs (section 2.3) and a whole show of 33 KB. A device is still connected to its other relay meanwhile, so it should lose nothing; the bar says so. 60 s is chosen: a device's dial after a failed one waits 10 s, then 20 s (the record of 2026-10-19 §2).
12. **The model holds.** Pulls and shows a minute at each relay are within a fifth of section 2.3's figures for the stage, and edits a minute within a tenth of section 2.1's. **Reason:** otherwise the harness did not drive the load it says it did, or a device does not do what its record says; either way the other bars measured something else.
13. **Room.** Each relay's room used at the end is within a tenth of what the harness wrote, counted as entries are counted, for each device that sent it; and nothing was refused for room. **Reason:** a relay keeps one entry for each author in each slot (the record of 2026-10-04 §2.4), so what it holds can be worked out from what was written; the cap is 1 GiB (`MAX_STORAGE_BYTES`), far above what a stage writes.

**A stage that fails a bar** is reported with the bar and the numbers, and the gate is not met at that count. What is changed then (the pull that names several channels, the counter of the room, the bound on connections, the governor's churn of devices at a relay) is a change of its own, with its own record where it changes the protocol, and the stage is run again.

## 4. The harness

### 4.1 Where it lives, and how it is run

It is a test file of the real-process harness, `crates/cordelia-node/tests/scale.rs`. Its run is marked `#[ignore]`, and where `CORDELIA_SCALE_STAGE` is not set it says so and returns at once, so that the CI job that runs the ignored tests does not start a run of hours. Its tests of itself are section 6's: the ones that start no process are not ignored, and the two small runs are ignored for their length and run in that CI job. It uses `tests/common/mod.rs` as every real-process test does, with two additions there: a node given the address it binds (rule 5 of §2.2), and a node whose log level is `info` (at `debug`, 500 logs would measure the disk).

```bash
cargo build --release -p cordelia-node
CORDELIA_SCALE_STAGE=100 CORDELIA_SCALE_SEED=1 CORDELIA_SCALE_OUT=/path/to/out \
  cargo test --release -p cordelia-node --test scale -- --ignored --nocapture
```

### 4.2 The steps of a run

1. **Before it: the counters** (section 1.1, rule 3) are merged, in a change of their own, with their unit tests, and the build has them.
2. **It starts the relays,** each from an empty data directory, each listing the other by key, and waits until each is healthy and each has the other hot.
3. **It starts the people, ten at a time.** For each person: its devices start; the first makes the phrase at a pseudo-terminal (`makes_a_phrase`); each other is added (`adds`); each device maps the person's names to folders of its own and turns sync on; the first device writes the person's first files, 10 in each name, at the profile's sizes; and the harness waits until every device of the person holds every file. The next ten start when the last ten are in step. Everything here is the setup, and its measures are reported apart: how long it took, and the most each relay asked of its lock and its memory.
4. **It waits ten minutes,** so that what a start costs (every proof, the first show, the first fetch) is past, and the measured window begins.
5. **The measured window is 60 minutes.** One thread schedules every person's edits: a Poisson process at the profile's rate, the profile's bursts, one active device a session (section 2.1). An edit writes a file in a memory folder of the active device as an editor would: the whole file, at once. Two in three edits rewrite a file of the name, one in three makes a new one. The file begins with a line that names the edit (`<!-- scale <edit number> -->`) and is followed by random text to its size. The observer looks for that line on each other device of the person: it reads each file it waits for every 250 ms, and an edit counts as arrived when the line names it or a later edit of the same file. Sampling (section 1.2) goes on once a minute for each process, spread over the minute so that no second reads 500 processes.
6. **In the last 15 minutes of the window, changes are made.** A tenth of the people with three devices, chosen by the seed, each remove one device, spread over five minutes, with `cordelia remove-device` at a pseudo-terminal with the phrase, as `person_e2e.rs` does. The removed device is then stopped. Bars 10 and 2 read these.
7. **It ends.** Every node is told to stop (SIGTERM), and each must stop within `NODE_STOP_TIMEOUT_SECS`. The read-only reads of each relay are made a last time. The harness checks that every pid it started has gone.
8. **It writes the run's summary** (section 4.4), and keeps the data directories only where `CORDELIA_E2E_KEEP` is set, as the harness does today.

A run at stage 500 takes about two hours: the setup (about 30 minutes for 200 people at ten at a time), ten minutes, an hour, and the end.

### 4.3 Rules of the harness

1. **It dials nothing but its own relays.** Each node's configuration names only the run's relays, by address on 127.0.0.1 and by key, and sets `dns_discovery = ""`, as the harness does today. Before each node is started the harness asks what it will dial (`Node::will_dial`, `assert_on_this_machine`) and refuses it otherwise. At the end it reads each relay's peers and checks that every key is one of the run's. No address outside 127.0.0.0/8 is written into any configuration; a configuration that would hold one is refused before anything starts.
2. **It changes no constant, and gives each node the settings it has in R1.** A relay is given the governor of `deploy/relay/relay1.toml` (hot 50, warm 50, cold 200) and every other setting at its default; a device is given the defaults. The faster tick and shorter tenure that the real-process tests give their nodes are not used here: they would measure a governor nobody runs. What a node is given beyond its defaults (its addresses, its relays, the log level) is listed in the summary. A node is given none of the caller's environment (as `a_node_is_given_none_of_the_callers_settings` holds today).
3. **A run is repeated from its seed.** The seed fixes the population, the names, the active devices, the times of edits and bursts, the sizes and the choices of step 6. The relays' and devices' own randomness (keys, churn's choices, jitter) is not fixed: two runs from one seed drive the same load, and differ in what the nodes do. The summary names the seed, the commit and the stage.
4. **Each stage is run three times,** with seeds 1, 2 and 3, and passes where each run passes. The summary of a stage gives each run's figures and their spread.
5. **It stops early on a fault, and still writes the summary:** a node that exits, a relay that does not answer for a minute, or the machine's memory available under 2 GiB. The summary says why it stopped.

### 4.4 What a run leaves

In `CORDELIA_SCALE_OUT`:

- **`SUMMARY.md`, the one file for a person to read.** First line: PASS or FAIL, the stage, the seed, the commit. Then each bar of section 3, one line each: the figure, the bar, pass or fail. Then the checks of section 6, rule 5 (whether the run is valid). Then, per relay and per profile of device: the median and the worst of each measure. Then the setup's figures. It names no machine and no host: it says "16 vCPU, 32 GB" from `/proc`, and no more.
- `samples.jsonl`: every sample, one line each, for whoever wants to look further.
- `edits.csv`: every edit, and its arrival on each other device.
- Each node's log, where `CORDELIA_E2E_KEEP` is set.

## 5. Set aside, and why

- **Docker.** The build machine has none, and nothing in the test needs it: real processes on loopback run the release binary as a person runs it. The stale Docker suites of `tests/e2e/` measured mesh formation and delivery of items of the older kind, which v1 does not use; nothing is taken from them but the lesson that one host can run hundreds of nodes.
- **Other machines, and a real network.** Everything is on one machine, on loopback, with no latency and no loss. The latencies measured are a floor: a real network adds some tens of milliseconds a hop, against a pull every ten seconds. The cost of loss and of slow links is not measured.
- **Phones.** No device of v1 is a phone.
- **A mesh of more than two relays.** R1 runs two. A device dials every relay it is set up with, so each relay more is one more connection on every device and at every relay, against the bound of 200: a larger mesh is a design question (which relays a device dials), not a scale one, and is for after R1.
- **The Agent Swarm persona.** It runs in a data centre with its own relays and limits (demand model §2.1), and is not R1's.
- **Messages between agents.** The messages channel is pulled, and counted, on every pass. Messages themselves are rare (20 a folder an hour at most) and small (2 KB): they are left out of the load.
- **Recovery, carrying by command, and the upgrade.** One-off acts of a person, measured by their own tests.
- **Days and months.** A day's proofs, the hourly sweeps and the 90 days of a channel nobody uses are not reached in an hour. The minute of a connection's proofs is reached at every start and every churn, which is the same burst.
- **The older kind of channel.** A relay of this version still carries it for devices of the version before, and none of this version's devices writes it.
- **The fixes.** The pull that names several channels, a counter for the room, a raised bound on connections and a relay that does not churn its devices are each decided after the numbers, in changes of their own.

## 6. The tests of the harness, and how a run is checked

The tests of the harness are tests of `scale.rs`. Tests 1, 2, 3 and 6 start no process and are not ignored; tests 4 and 5 take some minutes and are ignored for their length, and CI runs them with the other ignored tests of cordelia-node (TESTING.md).

1. **The population.** For each stage, the population has exactly the stage's devices, the mix of §2.2, a /24 for each person and no address outside 127.0.0.0/8; the same seed gives the same population; another seed gives another. No process is started.
2. **The schedule.** Over a simulated ten hours, each profile's edits an hour are within 5% of section 2.1, its bursts come once each 30 minutes, and every edit of a session is on its active device. No process is started.
3. **The observer.** With two folders and no node: a file copied from one to the other after 3 s is observed at 3 s within 0.3 s; a file never copied is counted as not arrived at 300 s; a later edit of the same file that arrives first counts the earlier as arrived; a file that is copied with other content does not count.
4. **A small run, end to end:** one relay and five devices of two people (one casual, one developer), a setup, a window of five minutes and one removal. It checks that every measure of section 1.2 is in `SUMMARY.md` with a value, that the counters at the relay agree with the model for those devices within a fifth (bar 12), and that what the harness counted written equals what it counted arrived and not arrived.
5. **A run that must fail.** The same small run, where one device is stopped in the middle of the window: its person's later edits do not arrive at it, bar 3 fails, and the summary's first line says FAIL. So a bar can fail.
6. **The configurations.** A configuration the harness writes names nothing to dial but its relays (every device's `will_dial` is a subset of them), and one with an address outside loopback is refused before any process starts.

**How each run is checked to have measured what it says.** The summary's checks of validity, each of which marks the run invalid (not failed) where it does not hold:

1. **Every process was sampled.** No process lacks a sample for more than two minutes in the window.
2. **The counts agree.** What devices count they asked of a relay, and what the relay counts it was asked, agree within 1% for each kind; bytes a relay counts in agree with what devices count they pushed within 5%.
3. **The edits add up.** Edits written equal edits observed arrived plus not arrived, for each other device.
4. **The observer kept its pace.** Its reads of a file were at most 500 ms apart at p99. Otherwise the harness was starved, and the latencies are its own.
5. **The machine was not the bottleneck.** The machine's CPU was at least 20% idle in every minute of the window, its memory available above 2 GiB, and the harness's own process under one core. Otherwise the run measured the machine, and is run again with fewer devices or more memory.
6. **The load was the load.** Bar 12 holds; where it does not, the run is invalid as well as failed.
