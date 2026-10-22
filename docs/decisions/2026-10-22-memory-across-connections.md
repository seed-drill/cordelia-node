# Decision: what a relay holds across its connections

**Date**: 2026-10-22
**Status**: Proposed. Not built. It is change F, which the person has decided goes in before R1 with change E (the scale record's section 7.7), as alpha.16, with R1's relays in containers of 1 GiB.
**Cited as**: "decision 2026-10-22 (memory) §2, rule 3". The numbers do not change. A number that is not used stays unused.

Words used throughout:

- **The scale record** is [`2026-10-22-a-scale-test-for-r1.md`](2026-10-22-a-scale-test-for-r1.md), on its branch `docs/scale-test` when this record was written. **The rationale** is [`docs/specs/parameter-rationale.md`](../specs/parameter-rationale.md). **Main** is commit 5c633f9, which holds changes C (#187, the send window) and D (#189, decoding by protocol).
- **Change E** is the scale record's section 7.7, being built apart, and counted here as that record says it: `fetch_from` drops the decoded page once its fields are taken, `RelayEntries::serve` drops the frame and the request before it writes the answer, and `ItemHeader`'s byte fields are bounded as they are decoded.
- **A connection's peer** is whoever is at the other end of one QUIC connection. **A listed relay** is a relay that the node's operator lists by key (`RelayEntries::lists`; for a personal node, a relay it is set up with by key). **An unlisted peer** is any other peer: every device, and anyone at all.
- **A wait on the peer** is an `.await` whose end the peer decides: a read of its bytes, or a write that waits for its acknowledgements or its credit. The codec gives each one `STREAM_TIMEOUT_SECS` (10 s).
- **The synchronous part** of a stream is what a node does between two waits on the peer without awaiting anything: decoding a frame, building an answer under the store's lock, encoding it. A runtime worker runs one at a time.
- **W** is what one connection of an unlisted peer, behaving as badly as it can, can make a relay hold, as the scale record's section 2.5 defines it. **K** (64 MiB, the relay's fixed part), **S** (what the host's system keeps) and **N = (memory − S − fixed) / W** are that section's. **P** is the peak of the synchronous part, for each runtime worker. **G** is what the large permits hold (rule 2), and **L** what the connections to listed relays hold.
- **A small message** is a frame of at most `SMALL_MESSAGE_BYTES`, 147,456 bytes (144 KiB). **A large message** is a longer one, up to `MAX_MESSAGE_BYTES` (1 MiB). **A large permit** is one of the `LARGE_MESSAGES_AT_ONCE` (4) that a node holds across all its connections (rule 2).
- **This version** is alpha.16, the first that carries change F. **The version before** is alpha.15 and earlier.
- **GRO** is the kernel's receive offload for UDP: it hands a socket that asks for it several datagrams of one flow in one buffer, which quinn then splits.

Figures are marked **measured** where this record measured them, **read** where they are read from the code or from quinn's source, and **derived** where they are worked out from those. Section 7 lists the measurements.

---

## 0. What this is

The scale record found that a relay of R1 admits 200 connections, and that a connection behaving as badly as it can makes a relay hold about 18.5 MiB. So about 55 such connections take a container of 1 GiB to its limit, and the container's restart does not help: the same connections take it down again.

This record proposes change F. It does two things.

1. **Nothing an unlisted peer sends or is sent is larger than a small message, but through a budget of four permits across all connections.** A device of this version never needs a permit: every page, push and show it exchanges fits a small message. So no number of slow peers holds up an honest device of this version by holding permits.
2. **QUIC's windows and streams are set from a small message,** and the kernel's receive offload is turned off, so that quinn's buffers for a connection are bounded by what the connection's peer may send, and not by what it can make quinn pin.

With E and F, W is about 2.0 MiB (derived; the rows that could be loaded on loopback were measured within it). A container of 1 GiB holds 461 such connections at worst, and the bound of 200 at worst takes about 501 MiB of it. **The aim is met** (section 3), on three conditions said there.

## 1. The problem, checked against main and E

### 1.1 W, row by row

The scale record's W, with C and D, and what E does to each row (read from main and from the record's section 7.7):

| Row | C and D (KiB) | With E (KiB) | Where it is held, on main |
|---|---|---|---|
| Receive windows: what the peer sent and the relay has not read | 2,048 | 2,048 | `QUIC_RECEIVE_WINDOW`, 2 MiB a connection; `QUIC_STREAM_RECEIVE_WINDOW`, 1 MiB a stream (`transport_config`) |
| Quinn's reassembly beyond them | 5,120 | 5,120 | quinn-proto 0.11.14, `assembler.rs` (read). But see section 1.3: with GRO it can be far more |
| Send window: what the relay wrote and the peer has not acknowledged | 2,048 | 2,048 | `QUIC_SEND_WINDOW` (change C) |
| The stream being served, across a wait on the peer | 6,144 | 2,048 | `serve` keeps the frame, the request, the answer and its encoding through `write_frame(send, &answer).await`. With E, the frame and the request are dropped first; the answer and its encoding (1 MiB each) are still held through the write, since `write_frame` encodes inside it |
| The relay's own fetch from this peer | 3,256 | 1,144 | `fetch_from` holds the decoded page through its fetch. With E, it holds the answer frame being read (1 MiB) and the channels listed (about 120 KiB) |
| The connection's own state | 64 | 64 | An allowance in the scale record. Measured here: 45 to 75 KiB a connection at rest (section 7) |
| The relay's tables for the peer | 300 | 300 | The scale record's section 2.5 |
| **W** | **18,980** | **12,772, about 12.5 MiB** | |

With E, the synchronous part's peak (a frame, its decode and an answer, at most the rationale's 6 MiB) is counted once for each worker, as P, and not for each connection: no connection holds it across a wait.

So with E alone a container of 1 GiB holds (1,024 − 64 − 6) / 12.5 = **76 connections at worst**, and about 80 take it to its limit (derived). That is far from 200. Of the 12.5 MiB, 9 MiB are QUIC's windows and reassembly, which exist on every connection whether or not the relay is working on it.

### 1.2 What a peer controls

Read from main:

- **How long a stream holds what it holds.** The codec gives each read and each write `STREAM_TIMEOUT_SECS`, each on its own: the protocol byte, the length, the payload; the answer's length, its payload. A peer that sends a frame but its last byte holds the relay's frame buffer for 10 s. A peer that grants no credit holds a write for 10 s, whatever the send window: quinn's `SendStream::write` waits on the peer's credit (`Send::write`, `budget == 0` gives `Blocked`) as well as on the send window (`write_limit`).
- **What a timed-out frame costs it.** Nothing: a frame whose read times out is not counted against any allowance (`serve` returns `None` where `read_raw_frame` fails; so does `read_push`). So the trickle above can be kept up with no breach.
- **How many streams it has open.** `QUIC_MAX_BIDI_STREAMS`, 64. The inbound loop (`handle_peer_streams`) serves one at a time; the other 63 sit in quinn, each with up to a stream's window of data.

### 1.3 Quinn's reassembly, and the kernel's receive offload

Read from quinn-proto 0.11.14 (`connection/assembler.rs`) and quinn 0.11.9 (`endpoint.rs`), and quinn-udp 0.5.14 (`unix.rs`); not measured, since loopback does no GRO.

- Quinn keeps each received stream frame as a slice of the packet it came in, so a small frame keeps its whole packet's buffer alive. The assembler counts each slice at its packet's payload length, and copies what it holds into one buffer (`defragment`) once what it counts beyond the data exceeds max(32 KiB, 1.5 × the data). That is the bound the rationale reads: on each stream, the data, and up to max(32 KiB, 1.5 × the data) more.
- **quinn-udp turns GRO on for every socket on Linux** (`UDP_GRO`, 64 segments), and quinn copies each batch of up to 64 datagrams into **one** buffer, which it then splits into packets that share it (`buf[0..meta.len].into()`, then `split_to(meta.stride)`). The assembler still counts each slice at one packet's length. So a stream frame of one byte, in a batch of 64 packets whose other 63 hold only padding or a ping, keeps up to 64 KiB alive while it is counted at about 1.4 KiB.
- **So on a stream that the relay is not reading,** a peer can pin about 32 KiB × 64 = 2 MiB before the assembler copies (derived: about 23 such frames of 1.4 KiB, or 32 of 1 KiB, each pinning up to 64 KiB). On main that is up to 63 streams, **about 126 MiB a connection**, for about two thousand bytes of window. It needs the kernel to batch the peer's datagrams, which a NIC with GRO does for a burst of equal-sized datagrams of one flow; the scale record's 5 MiB does not count it.

This is the least certain finding of the record (section 6), and it is why rule 10 exists.

## 2. The change

Two parts: (a) a budget across all connections for the application's buffers; (b) QUIC's windows and streams, and the reassembler. Each rule says its reason.

### 2.1 Part (a): what the application holds

1. **A small message is 144 KiB.** `SMALL_PAGE_BYTES` is 128 KiB (131,072 bytes) of entries, chosen: the least power of two that holds an entry of the largest size on the wire (65,773 bytes, `MAX_ENTRY_WIRE_BYTES`) and others beside it. `SMALL_MESSAGE_BYTES` is that and 16 KiB more for what is around the entries, derived: a page's own fields and the length of each entry come to under 1 KiB for 100 entries. Every message a device of this version sends or is sent fits one: a page or a push (rule 3, rule 5), a whole show (a change entry, 32 KiB), a show's answer (`SHOW_ANSWER_ROOM_BYTES`, 66,560), a hand-over (`MAX_HAND_OVER_BYTES`, 54,275), a proof, a pull. So do the older kind's pages of headers (with E's bounds) and its channel lists of up to `MAX_CHANNELS_ASKED_OF_A_PEER` IDs (about 120 KiB).

2. **A frame from an unlisted peer that is longer than a small message is read only under a large permit.** The node reads the protocol byte and the four bytes of length as now. Where the length is over `SMALL_MESSAGE_BYTES`, it takes a large permit before it allocates the payload, and holds it until the stream is done: its answer written, or the stream failed. A node holds at most `LARGE_MESSAGES_AT_ONCE` (4) at once, across all its connections (a `tokio::sync::Semaphore`, taken in order of asking).
   - **What waits:** the stream, unread. Its payload stays in QUIC, within the connection's receive window (rule 8), and the peer can send no more of it. The connection's inbound loop waits with it: that connection's other streams wait too, and no other connection's.
   - **For how long:** at most `STREAM_TIMEOUT_SECS`. A stream that has no permit by then is reset with `ERR_CAPACITY`, and the loop goes on to the connection's next stream. It counts no breach (as `Answer::NotNow` does not): the peer did nothing over a limit.
   - **Who needs one:** devices of the version before, whose pushes are up to `ENTRY_PAGE_MAX_BYTES` (896 KiB), and the older kind's pushes (up to `OUTBOX_BATCH_MAX_BYTES`, 195 KiB, or more from a version before). A device of this version never does (rules 3 and 5).
   - **How it is sized:** four, chosen. A relay at R1 carries few devices of the version before, and each sends a large message only when a batch has built up; four let four of them at once go at full pace. Each permit holds at most a frame (1 MiB) while it is read, the request decoded (2 MiB and 64 KiB, D's bound) where an older-kind handler awaits with it, and an answer encoded (1 MiB) while it is written: 4,160 KiB, so **G = 16.25 MiB** (derived).
   - **What a hostile peer can do with them:** hold all four, from four connections, for as long as it likes, by trickling large frames. Then a device of the version before waits out the stream timeout on a large push, is refused, and tries it again later (its outbox keeps it). That is the cost, and it falls on devices of the version before alone. A device of this version is not held up by it.

3. **An answer to an unlisted peer is built within a small message.** A page of entries for a connection that is not a listed relay's holds at most `SMALL_PAGE_BYTES` of entries (where `relay::pull` in `cordelia-storage` stops at `ENTRY_PAGE_MAX_BYTES` today), and at least one entry whatever its size; it says there is more, as a page that is full does today. Every other answer of the streams of entries is within a small message already (rule 1). **The older kind's fetch answer** (`handle_inbound_sync`), whose size the relay sums before it loads the items (`total_cost_by_ids`), takes a large permit before it loads them where that sum is over `SMALL_PAGE_BYTES`, as rule 2 says. A listed relay is given full pages, as today.

4. **What a stream holds across a wait on the peer is one small message.** E drops the frame and the request before the write. F also encodes the answer and drops it before the write, and writes the encoded bytes (`write_raw_frame`), so that what waits on the peer's credit is the encoding alone. Before the read, nothing is allocated past the length (rule 2).

5. **A device of this version pushes at most `SMALL_PAGE_BYTES` in one push** (`room_to_push` in `device_entries.rs`, where it stops at `ENTRY_PAGE_MAX_BYTES` today). So a device never needs a large permit, at a relay of this version or of the version before.

6. **A relay's own fetch from an unlisted peer reads each answer within a small message.** `fetch_from` reads every frame of the stream with a bound of `SMALL_MESSAGE_BYTES`: a length over it fails the fetch at once, with nothing allocated, as a frame over `MAX_MESSAGE_BYTES` does today. It asks, in one sync request, for no more items than fit `SMALL_PAGE_BYTES` at the largest size of an item (the `fit` of `fetch_from` already lowers the page where the peer's allowance is short; it now also stops there). With E, what it holds across its waits is that frame, the IDs it took from the page, and the channels the peer listed. **No budget across connections is set for the relay's own fetches** (reason below).

7. **A listed relay is outside rules 2, 3 and 6.** Its frames are read at once whatever their size; it is given full pages; the relay's fetch from it reads whole messages. It is one or two connections, which the operator chose by key, and the passes between relays need full pages to keep pace. What it holds is counted as L (section 3).

**Considered, and not taken: one budget over every stream,** a semaphore taken before a frame is read and held until the answer is written, at most one for each connection (which the inbound loop already gives). A peer decides how long a stream lasts: up to 10 s to send its frame, and 10 s more for each of the answer's two writes (section 1.2). So with p permits, h slow connections hold min(p, h) of them for up to 30 s each, and take them again as soon as they are let go. A device of this version waits for its answer for 10 s (`read_frame`), and then gives the request up; behind a queue of h such connections it waits about 30 × h / p seconds. With p = 16 and h = 16 that is 30 s: every honest request fails. A cap for each address or each /24 raises the number of addresses needed, and does not change the outcome: a peer with as many /24s as there are permits holds them all, and the bound of 200 connections admits ten /24s. Rules 1 to 5 reach the same bound on memory without a shared permit for any exchange of a device of this version.

**Considered, and not taken: a budget over the relay's own fetches.** A hostile peer can keep the relay's fetch from it going for as long as it likes (it answers every page with `has_more`, as the scale record's section 7.5 says), so a few peers would hold every permit of such a budget, and the relay would fetch from nobody else. Rule 6 bounds each fetch to a small message instead. There is one fetch for each peer at a time (`Fetching`), so their sum is bounded by the connections, and is in W.

**What is left shared:** the store's lock and the CPU. F does not bound them (section 6).

### 2.2 Part (b): QUIC's windows and streams, and the reassembler

8. **The receive windows: one small message on a stream, two on a connection.** `QUIC_STREAM_RECEIVE_WINDOW` = `SMALL_MESSAGE_BYTES` (144 KiB), and `QUIC_RECEIVE_WINDOW` = 2 × it (288 KiB). Reason: the largest thing a device of this version sends is one small message; two on the connection let a second request arrive while the first is read, as two messages did. A large message still arrives, a window at a time: the node reads as it arrives and quinn grants more. Its cost is in section 2.3.

9. **A peer may have 8 streams open on a connection, not 64.** `QUIC_MAX_BIDI_STREAMS` = 8. Reason: the inbound loop serves one at a time, so a stream beyond the first only waits; and each open stream may hold 32 KiB of quinn's reassembly beyond its data (section 1.3), so 64 streams floor that row at 2 MiB a connection and 8 at 256 KiB. Eight is chosen: a device opens a stream for its pass at each relay, one for each show, and one for each read a command asks of it, each served in milliseconds, and an opening that waits for a stream waits for one of these. `MAX_CONCURRENT_STREAMS` in `protocol.rs` follows it.

10. **No node takes UDP datagrams in batches.** The node's endpoint is made with a socket that has `UDP_GRO` turned off, through a wrapper of quinn's `AsyncUdpSocket` whose `max_receive_segments` is 1 (quinn-udp turns GRO on when it wraps a socket, so the wrapper turns it off again, and says so to quinn, which then sizes its receive buffer to one datagram a slot). Reason: section 1.3. With it, each stream frame pins its own datagram only (at most `max_udp_payload_size`, 1,472 bytes), which is what the assembler counts, and its bound holds as the rationale reads it. Cost: the kernel hands the socket one datagram for each entry of a `recvmmsg` (still up to 32 at a call) in place of up to 64; at a relay's pace (2 MiB a minute for each connection) that is not measurable. **Not taken: lower stream counts alone.** At 2 MiB for each stream not being read, 7 such streams are still 14 MiB a connection.

11. **The send window: two small messages.** `QUIC_SEND_WINDOW` = 2 × `SMALL_MESSAGE_BYTES` (288 KiB). Reason: what a node writes to an unlisted peer is a small message (rule 3), so a window of two takes the answer whole and the next before the first is acknowledged, as two messages did. A large write (to a listed relay, or the older kind's fetch answer under a permit) goes a window at a time, waiting for acknowledgements, within the codec's 10 s. **Smaller than two messages is safe:** no honest write of a small message waits, and a large one waits only a round trip at a time (measured, section 2.3). One small message alone was considered: an answer could then wait for the acknowledgement of the one before it, a round trip, on every request of a pass; 144 KiB more a connection is the price of not waiting.

The windows and the stream count are transport settings, the same in every direction, for every connection of every node (`transport_config`). Nothing on the wire changes: a peer of the version before is told the new limits by QUIC itself, and a page of 128 KiB is a page as any other.

### 2.3 What each costs an honest peer, at a round trip of 200 ms

**Measured** (section 7): one connection, through a throwaway path that delays each datagram 100 ms each way in order, after 16 MiB had crossed it each way (so past slow start); loopback, no loss; the time from the first byte written to the last byte read.

| What crosses | Today | With F's windows |
|---|---|---|
| 16 KiB, a push or a page | 0.20 s | 0.20 s |
| 128 KiB, a small page or push | 0.21 s | 0.22 s |
| 896 KiB, a full page (`ENTRY_PAGE_MAX_BYTES`) | 0.24 s | 1.43 s |
| 1 MiB, the largest message | 0.25 s | 1.63 s |
| 16 MiB each way, one stream at a time | 10 s (about 1.6 MB/s) | 50 s (about 335 KB/s, 19 MiB a minute) |

What that means for each exchange:

- **A page, to a device of this version.** At most 128 KiB, one round trip, as a page of that size is today. A channel with 1 MiB new takes 8 pages, 1.6 s in round trips, where today it takes 2. A device reads up to `RELAY_ENTRY_PULL_PAGES` (10) pages of a channel in a pass, 1.25 MiB every 10 s, and a relay hands a connection at most 2 MiB a minute (`PUSH_BYTES_PER_PEER_PER_MINUTE`): what a device is handed is not slowed.
- **A push, from a device of this version.** At most 128 KiB, one round trip. A device sends a relay at most 1.5 MiB a minute (`OUTBOX_BYTES_PER_MINUTE`), so at least 12 pushes a minute, 2.4 s of a minute in round trips; a carry of 4 MB is 31 pushes where it was 5, and takes the same time, which the pace sets.
- **A pull or a pass between relays.** Full pages: 1.43 s for a page of 896 KiB where it was 0.24 s, and about 19 MiB a minute on one stream. The scale record's stage 190 asks 21 edits a minute of up to 20 KB each, under 1 MiB a minute.
- **A device of the version before.** Its pushes of up to 896 KiB take 1.43 s, and a large permit (rule 2); its pages from a relay of this version are small (it reads a page that says there is more, as any page). Its own pace bounds it, as above.
- **The longest round trip that still works.** A small message arrives in one round trip, and works at any round trip under the 10 s timeout. A message of 1 MiB took 8 round trips; it arrives within 10 s at round trips under about 1.2 s (derived). Today it took about one round trip.

## 3. W again, with E and F

| Row | With E (KiB) | With E and F (KiB) | Why |
|---|---|---|---|
| Receive windows | 2,048 | 288 | Rule 8 |
| Quinn's reassembly beyond them | 5,120 (126 MiB with GRO, section 1.3) | 688 | Rules 9 and 10: on each of 8 streams, max(32 KiB, 1.5 × its data); at most 8 × 32 + 1.5 × 288 (read) |
| Send window | 2,048 | 288 | Rule 11 |
| Datagrams | 0 | 0 | Off (change C) |
| The stream being served, across a wait on the peer | 2,048 | 144 | Rules 2 and 4: the frame being read, or the answer's encoding being written, one small message |
| The relay's own fetch | 1,144 | 274 | Rule 6: a frame of a small message (144), the IDs taken (about 10), the channels listed (about 120) |
| The connection's own state | 64 | 64 | Allowance; measured 45 to 75 KiB at rest, the relay's tables at rest included |
| The relay's tables for the peer | 300 | 300 | Unchanged |
| **W** | **12,772 (12.5 MiB)** | **2,046 (about 2.0 MiB)** | |

**What is held once, and not for each connection** (derived):

- **K** = 64 MiB, the scale record's.
- **P** = 6 MiB for each runtime worker: the rationale's frame, decode, answer and encoding of one stream at once, which a worker's synchronous part holds while it runs. The figures take one worker; each core more lowers N by 3.
- **G** = 16.25 MiB: four large permits (rule 2).
- **L** = 15 MiB: up to two connections to listed relays (two relays that list each other may hold one or two), each 7.5 MiB: the windows and reassembly of F (1,264 KiB), a stream served at full size across a wait (2 MiB, with E), the relay's fetch from it at full size (a frame of 1 MiB, and its channel list of up to `MAX_LISTED_CHANNEL_IDS` IDs, about 2.9 MiB), and its state and tables. The relay's own streams to a listed relay (its passes, pulls and the older kind's pushes) are left out, as the scale record leaves them out.

So K + P + G + L = 101.25 MiB.

**N, and whether the aim is met** (derived; the scale record's S and its rounding down):

| Host | Memory for the relay | N at worst with E alone | N at worst with E and F | 200 connections at worst take |
|---|---|---|---|---|
| A container of 1 GiB (as decided for R1) | 1,024 MiB | 76 | **461** | 501 MiB |
| A container of 512 MiB (`compose.yml` on main) | 512 MiB | 35 | **205** | 501 MiB |
| The README's host, with no container (1 GB, one vCPU) | 768 MiB | 55 | **333** | 501 MiB |
| The machine of `fly.relay1.toml` (256 MB) | 224 MiB | 12 | **61** | over its memory |

**The aim is met:** with E and F, a relay in a container of 1 GiB holds its whole bound of 200 connections, every one behaving as badly as it can, at about 501 MiB, half the container, on three conditions:

1. **Rule 10 is in.** Without it, a stream not being read can pin about 2 MiB (section 1.3), W is about 16 MiB, and the container of 1 GiB holds 57.
2. **The allowances hold.** K, P, the connection's state and L are allowances. Section 5's measurement checks the sum on a whole relay process, and its bar is set so that the half of the container left over covers them being wrong by a factor of two.
3. **Honest devices are served.** Every exchange of a device of this version is within a small message and needs no shared permit, so no slow peer holds it up through memory (rules 1 to 5). What a flood within the rate limits does to the store's lock and the CPU is not bounded by F (section 6).

The container of 512 MiB on main holds 205 at worst, just above the bound; the decision gives R1's relays 1 GiB.

## 4. What changes

### 4.1 In `protocol.rs`, for the rationale

| Constant | Value | Reason |
|---|---|---|
| `SMALL_PAGE_BYTES` (new) | 131,072 | Chosen: the least power of two that holds an entry of the largest size (`MAX_ENTRY_WIRE_BYTES`, 65,773) and others. The most of entries in a page for an unlisted peer and in a device's push. A compile-time check that it holds `MAX_ENTRY_WIRE_BYTES` |
| `SMALL_MESSAGE_BYTES` (new) | 147,456 | Derived: `SMALL_PAGE_BYTES` and 16 KiB for what is around the entries. Checks at compile time that `MAX_HAND_OVER_BYTES`, `SHOW_ANSWER_ROOM_BYTES`, `CHANGE_ENTRY_BYTES` and its wire overhead are within it |
| `LARGE_MESSAGES_AT_ONCE` (new) | 4 | Chosen: rule 2 |
| `QUIC_STREAM_RECEIVE_WINDOW` | 147,456 (was 1,048,576) | Derived: one small message (rule 8) |
| `QUIC_RECEIVE_WINDOW` | 294,912 (was 2,097,152) | Derived: two small messages (rule 8) |
| `QUIC_SEND_WINDOW` | 294,912 (was 2,097,152) | Derived: two small messages (rule 11) |
| `QUIC_MAX_BIDI_STREAMS`, `MAX_CONCURRENT_STREAMS` | 8 (was 64) | Chosen: rule 9 |

No new timeout: rule 2's wait is `STREAM_TIMEOUT_SECS`. No new error code: rule 2 resets with `ERR_CAPACITY`.

The rationale changes with them: §1's sections on the receive windows, the send window and the streams; its table "What one connection can make a node hold", which becomes section 3's W with its rows, the reassembly read again with GRO, and the list of what it leaves out (the large permits, the listed relays, the synchronous part for each worker); and a new section for the small message and the large permits, with section 2.3's costs. Its sentence "with 200 connections a relay holds at most 400MB unread" becomes 56 MiB.

### 4.2 In the code, in plain terms

- **`cordelia-network`, `transport.rs`:** the new values; and the endpoint made over a socket wrapper with GRO off (rule 10), in `create_endpoint` and `create_client_endpoint`.
- **`cordelia-network`, `codec.rs`:** a read of a frame's length apart from its payload, so that a caller can decide between them; a read of a frame with a bound below `MAX_MESSAGE_BYTES` (rule 6); and an encode that the caller holds, written with `write_raw_frame` (rule 4).
- **`cordelia-node`, `p2p.rs`:** the large permits, one semaphore made at start and handed to the inbound loop (`handle_peer_streams`), which knows whether its peer is a listed relay; the reads of `read_push`, `handle_inbound_sync` (each frame of its loop, and its fetch answer) and the other handlers by rule 2; `fetch_from` by rule 6.
- **`cordelia-node`, `relay_entries.rs`:** `serve` by rules 2 and 4, with E; pages for an unlisted peer within `SMALL_PAGE_BYTES` (rule 3): `cordelia-storage`'s `relay::pull` takes the most bytes as an argument, which `serve` gives by its peer. What a relay passes on to a listed relay (`to_pass_on`) is not changed.
- **`cordelia-node`, `device_entries.rs`:** `room_to_push` stops at `SMALL_PAGE_BYTES` (rule 5).
- **`deploy/relay/compose.yml`:** `mem_limit: 1g`, as decided, where the release has not set it already.

### 4.3 In other records

In the scale record, by sentence:

- **§0, item 1:** "Even with them, a connection can make a relay hold about 18.5 MiB at worst (section 2.5)." gains: "With changes E and F (the record of memory across connections), in alpha.16, about 2.0 MiB."
- **§0, item 2, and the known limit's paragraph:** "Against a hostile peer, the bound is far above what the deployed files hold." and the figures after it are said for the build before E and F, and followed by: "With E and F, the container of 1 GiB that R1's relays are given holds 461 at worst, so the bound of 200 is within it; the container of 512 MiB holds 205, the README's host without a container 333, and Fly's machine of 256 MB 61."
- **§0, "So a peer that opens about 27 connections …":** said for the build before E and F. With them, no number of connections within the bound takes the container of 1 GiB to its limit by memory. The account of `restart: always` stays, for Fly's machine and for what F does not bound (the lock and the CPU).
- **§0, "That is a known limit of R1, accepted …":** "Change B, after R1, sets the bound from the host; change E (section 7.7) lowers W" becomes: "Changes E and F, in alpha.16, lower W to about 2.0 MiB; change B, after R1, sets the bound from the host."
- **§2.5, the table:** a column for E and F, or a line under it that points to section 3 here. **"A change that lowers W, not counted here"** becomes "Changes E and F, in alpha.16, counted in the record of memory across connections". **"Not taken: a smaller receive window"** becomes "Taken by change F (two small messages), with its cost". **Change B's figures** (the default of 24, the cap of 384, the sweep that settles at 16, the 10.5 GiB for 500 devices) are derived again from W = 2.0 MiB when B is built.
- **§7.7:** "Proposed, before or after R1 as the person decides … The figures of section 2.5 do not count on it." becomes "In alpha.16, before R1, as the person decided, with change F." Its "What it lowers" gains: F also encodes the answer and drops it before the write.
- **§13:** the row of change E reads "In alpha.16, with change F, before R1".

`docs/specs/network-protocol.md` §2.1 lists the new windows and stream count. `docs/specs/configuration.md` is not changed: none of these is a setting.

### 4.4 What a personal node and a bootnode get

The same transport settings (rules 8 to 11) on every connection, since `transport_config` is every node's. A device's pages from a relay of the version before (up to 896 KiB) arrive a window at a time: 1.43 s at 200 ms, within the codec's 10 s. Rule 5 is a device's own. Rules 2 and 4 apply wherever a node serves streams a peer opens: a personal node with `listen = true`, `trusted_peers` or swarm children, and a bootnode (whose `PeerSharing` answers are small). Its listed relays are those it is set up with by key. A personal node's own pass is not changed: it sends small messages already.

## 5. The tests

Each rule has a test that fails on an assertion when the rule is taken out.

1. **Rule 1:** compile-time checks of section 4.1; a test that each message a device of this version builds (a full push, a whole show, a hand-over, a show's answer with an entry of the largest size) encodes within `SMALL_MESSAGE_BYTES`.
2. **Rule 2:** in `p2p.rs`'s tests of the inbound loop, over in-process QUIC: with the four permits held, an unlisted peer's frame of 1 MiB is not read: the peer's `write_all` has taken no more than the stream's window after 2 s, and the relay's counting allocator shows no allocation of the frame; after `STREAM_TIMEOUT_SECS` the stream is reset with `ERR_CAPACITY` and the peer's rates show no breach. With a permit let go, the same frame is read and answered. A listed relay's frame of 1 MiB is read with all four held (rule 7). A stream that fails while it holds a permit gives it back (a test that makes 5 such streams fail and then takes 4).
3. **Rule 3:** a channel holding 13 entries of the largest size: a page to an unlisted connection holds at most `SMALL_PAGE_BYTES` of entries and at least one, and says there is more; to a listed relay, up to `ENTRY_PAGE_MAX_BYTES`. The older kind's fetch answer over `SMALL_PAGE_BYTES` waits for a permit, as in test 2.
4. **Rule 4:** with E's counting allocator, a pull whose answer is a page of 128 KiB, to a peer that grants no credit: while the write waits, the stream holds no more than the encoded page (no frame, no request, no answer).
5. **Rule 5:** a device with 2 MiB waiting pushes no message over `SMALL_MESSAGE_BYTES` (a stand-in relay records the frame lengths).
6. **Rule 6:** a stand-in peer answers a relay's channel list with a frame whose length is `SMALL_MESSAGE_BYTES` + 1: the fetch fails at once, without waiting for its payload, and nothing of that size is allocated; and a sync request to an unlisted peer asks for no more items than fit `SMALL_PAGE_BYTES`.
7. **Rules 8, 9 and 11:** the values, read from the configs as `the_send_window_is_two_messages_at_both_ends` reads them; and behaviour over in-process QUIC: a peer that writes on 9 streams finds the 9th open waiting; a peer that does not have its data read can write no more than `QUIC_RECEIVE_WINDOW` over its streams. The send window's test of #187 runs at the new value.
8. **Rule 10:** on Linux, `getsockopt(SOL_UDP, UDP_GRO)` on the endpoint's socket returns 0, and the socket wrapper's `max_receive_segments` is 1. (The pinning itself is not testable on loopback, which does no GRO; section 6.)
9. **The tests that rest on the old values** (`test_max_inbound_connections_network_protocol_9_1`'s neighbours in `protocol.rs`, `a_request_is_not_written_once_the_entry_it_was_built_under_is_kept_no_more`, which holds every stream a connection may have) follow the constants.

**The measurement: a relay's memory under hostile connections.** `crates/cordelia-node/tests/hostile_memory_e2e.rs`, ignored by default and run by CI's job for ignored tests. No root: everything is on loopback, from addresses of 127.0.0.0/8.

- **A relay process** of this build, with two devices of one person of this version connected first, each mapping one name.
- **198 hostile connections**, so that the relay holds its bound of 200, from in-process quinn clients, each from an address of its own /24 group (five to an address, twenty to a /24), each doing all of these, on every stream it may open, for ten minutes:
  - frames of a small message, sent but their last byte, again as each stream times out;
  - on four connections, frames of 1 MiB the same way, so that they hold every large permit;
  - one-byte writes on its other streams, a write at a time, so that the reassembler holds many small slices;
  - pulls of pages of a channel of its own that it filled (within `NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR` and the push allowance), with its own stream credit set to one byte (its `stream_receive_window`), so that the relay's writes wait on its credit;
  - answers to the relay's own fetch, with frames of a small message, trickled, and every page saying there is more;
  - every count kept under half of its limit, so that nothing is cut off for a breach.
- **Read:** the relay's `VmHWM` and `VmRSS` from `/proc`, once a second; its connections open at the end (198 hostile and the two devices).
- **The bar:** `VmHWM` at most 512 MiB, half the container of R1: K + P + G + L + 200 × W is about 501 MiB, so the bar leaves no room beyond the arithmetic, and the other half of the container is the margin of section 3, condition 2; all 200 connections open at the end; and, through the flood, every edit written in one device's folder is in the other's within 25 s, the scale record's bar 2 at p95, and within 120 s at most.
- **Run once with rule 10's wrapper off, and reported:** on loopback it should read the same (no GRO); it is a check that the harness does not depend on it, not a test of rule 10.

## 6. What it does not do, and what is left as a known limit of R1

- **The store's lock and the CPU under a flood within the rate limits.** 199 connections, each at its count (`ENTRY_REQUESTS_PER_PEER_PER_MINUTE`, 3,000), ask a relay about 10,000 requests a second. F bounds what they make it hold, not the time they take. Whether honest devices keep bar 2 under that is not known; section 5's measurement keeps its hostile peers under half of every count, and reports the device's latency. A known limit of R1.
- **Devices of the version before, under attack.** Four connections hold every large permit for as long as they like, and those devices' large pushes then wait and are tried again. When the older kind and the version before are gone, a node can refuse a frame over a small message from an unlisted peer outright, and the large permits go.
- **What the relay's own streams to a listed relay hold** (passes, pulls, the older kind's pushes and retries) is an allowance in L, not bounded, as the scale record leaves it.
- **GRO, read and not measured.** Section 1.3 is read from quinn's and quinn-udp's source; loopback does no GRO, so neither the pinning nor rule 10's fix can be seen on a machine without a NIC that does. It rests on the reading of `endpoint.rs`'s `split_to` and of the assembler's count. If the reading is wrong, rule 10 costs nothing but a wrapper.
- **The allocator.** The measurements here ran this build's glibc binary; the deployed relay is the release's static musl binary, whose allocator may hold more. The bar of section 5 is set with that margin, and is not run on musl.
- **Fly's machine of 256 MB** holds 61 at worst. The scale record's change B (after R1) gives `fly.relay1.toml` 1 GB; until then it is a known limit, as is every host smaller than the container.
- **Nothing sheds a connection that stays alive,** and the bound of 200 is not read from the configuration: both are the scale record's, unchanged.

## 7. What was measured, and what was read

All throwaway, not committed, on a machine of 4 vCPU and 15 GiB, from the release build of main (5c633f9), glibc.

**One: a relay process, and hostile connections.** A relay started by the real-process harness (`tests/common`), and connections from in-process clients made with `outbound_connect`, each bound to an address of 127.40.0.0/16 (five to an address, twenty to a /24). Each hostile connection opened every stream it could and wrote on each the protocol byte of a pull, a length, and the frame but its last byte, and then waited; so the relay read one frame at a time and timed it out after 10 s, while the others sat unread in QUIC. `VmRSS` from `/proc`, once a second for 45 to 60 s.

| Build | Connections | At rest, a connection | Hostile: frame | Most RSS | A hostile connection, over the relay at rest |
|---|---|---|---|---|---|
| Main | 50 | 75 KiB | 1 MiB, 64 streams | 245 MiB | 4,708 KiB |
| Main | 100 | 56 KiB | 1 MiB, 1 stream | 125 MiB | 1,118 KiB |
| Main | 100 | 58 KiB | 1 MiB, 64 streams | 474 MiB | 4,695 KiB |
| F's windows, 8 streams, and frames over a small message left unread for 10 s | 100 | 56 KiB | 144 KiB, 8 streams | 89 MiB | 748 KiB |
| The same | 100 | 49 KiB | 1 MiB, 8 streams (left unread) | 69 MiB | 535 KiB |
| The same | 190 | 45 KiB | 144 KiB, 8 streams | 155 MiB | 741 KiB |

What it says: the cost is linear in the connections; main's rows for this pattern (the receive windows, the reassembly and the frame: 8,256 KiB by the arithmetic) measured 4,695; F's same rows (288 + 688 + 144 + 64 = 1,184 by the arithmetic) measured 741 to 748, about a sixth of main's. 190 such connections took a relay of F's settings to 155 MiB; on main the same would take about 890 MiB (derived from main's figure for a connection). It does not load the send window, the relay's own fetch, its tables, the large permits or GRO's pinning: section 5's measurement does, but for GRO.

**Two: what the windows cost at 200 ms.** Section 2.3's table: in-process endpoints of this build, through a throwaway delay line (in order, 100 ms each way), each size once after 16 MiB each way.

**Read, not measured:** the reassembler's bound and GRO's pinning (section 1.3); that a write waits on the peer's credit (quinn-proto `Send::write`); quinn's per-connection setters (`set_send_window`, `set_receive_window`), not used; the codec's timeouts and that a timed-out frame is counted against nothing (section 1.2); where E's drops fall (the scale record's section 7.7).

**Derived:** every W, N, G, L and P above.
