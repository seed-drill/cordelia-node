# Decision: what a relay holds across its connections

**Date**: 2026-10-22
**Status**: Proposed. Not built. It is change F, which the person has decided goes in before R1 with change E (the scale record's section 7.7), as alpha.16, with R1's relays in containers of 1 GiB. Revised once after its review (section 8). **Rule 10 is being built first, on its own** (cordelia-node, branch `fix/udp-gro-off`), because the review measured its fault on every released version; it ships ahead of the rest, and its rule and reason stay here.
**Cited as**: "decision 2026-10-22 (memory) §2, rule 3". The numbers do not change. A number that is not used stays unused.

Words used throughout:

- **The scale record** is [`2026-10-22-a-scale-test-for-r1.md`](2026-10-22-a-scale-test-for-r1.md), on its branch `docs/scale-test` when this record was written. **The rationale** is [`docs/specs/parameter-rationale.md`](../specs/parameter-rationale.md). **Main** is commit 52ca2ae, the release of alpha.15, whose code is that of 5c633f9: changes C (#187, the send window) and D (#189, decoding by protocol).
- **Change E** is the scale record's section 7.7, built as cordelia-node #194, reviewed and merging. It is counted here as that record says it: `fetch_from` drops the decoded page once its fields are taken, `RelayEntries::serve` drops the frame and the request before it writes the answer, and `ItemHeader`'s byte fields are bounded as they are decoded.
- **A connection's peer** is whoever is at the other end of one QUIC connection. **A listed relay** is, in every rule of this record, a relay listed by key: the key in the peer's certificate is the configured key of a relay the node is set up with (`RelayEntries::lists`; a relay configured by one of the default names takes that name's compiled key, `bootstrap::relays_dialled`). **An unlisted peer** is any other peer: every device, a relay configured by address alone, and anyone at all.
- **A wait on the peer** is an `.await` whose end the peer decides: a read of its bytes, or a write that waits for its acknowledgements or its credit. The codec gives each one `STREAM_TIMEOUT_SECS` (10 s).
- **The synchronous part** of a stream is what a node does between two waits on the peer without awaiting anything: decoding a frame, building an answer under the store's lock, encoding it. A runtime worker runs one at a time, and a node starts one worker for each core it may use (`available_parallelism`, which reads the affinity mask and the cgroup's quota).
- **W** is what one connection of an unlisted peer, behaving as badly as it can, can make a relay hold, as the scale record's section 2.5 defines it. **K** (64 MiB, the relay's fixed part), **S** (what the host's system keeps) and **N = (memory − S − fixed) / W** are that section's. **P** is the peak of the synchronous part, 6 MiB for each runtime worker, so 6 MiB for each core. **G** is what the large permits hold (rule 2), and **L** what the connections to listed relays hold.
- **A small message** is a frame of at most `SMALL_MESSAGE_BYTES`, 147,456 bytes (144 KiB). **A large message** is a longer one, up to `MAX_MESSAGE_BYTES` (1 MiB). **A large permit** is one of the `LARGE_MESSAGES_AT_ONCE` (4) that a node holds across all its connections (rule 2).
- **This version** is alpha.16, the first that carries change F. **The version before** is alpha.15; alpha.14 is the one before it. What is said of the version before holds for both.
- **GRO** is the kernel's receive offload for UDP: it hands a socket that asks for it several datagrams in one buffer, which quinn then splits. **GSO** is its sending half: quinn hands the kernel a batch of datagrams at once, up to 10 by default.

Figures are marked **measured** where this record measured them, **measured by the review** where its review did, **read** where they are read from the code or from quinn's source, and **derived** where they are worked out from those. Section 7 lists the measurements.

---

## 0. What this is

The scale record found that a relay of R1 admits 200 connections, and that a connection behaving as badly as it can makes a relay hold about 18.5 MiB. So about 55 such connections take a container of 1 GiB to its limit, and the container's restart does not help: the same connections take it down again. Its review found worse: with the kernel's receive offload on, as every released version has it, one connection can make a relay hold about 80 MiB (measured by the review).

This record proposes change F. It does two things.

1. **Nothing an unlisted peer sends or is sent is larger than a small message, but through a budget of four permits across all connections.** A device of this version never needs a permit: every page, push and show it exchanges fits a small message. So no number of slow peers holds up an honest device of this version by holding permits.
2. **QUIC's windows and streams are set from a small message,** and the kernel's receive offload is turned off, so that quinn's buffers for a connection are bounded by what the connection's peer may send, and not by what it can make quinn pin.

With E and F, W is about 2.0 MiB (derived; the rows that could be loaded on loopback were measured within it). A container of 1 GiB holds 461 such connections at worst on one core and 416 on sixteen, and the bound of 200 at worst takes 501 MiB of it on one core and 591 MiB on sixteen. **The aim is met** (section 3), on three conditions said there.

## 1. The problem, checked against main and E

### 1.1 W, row by row

The scale record's W, with C and D, and what E does to each row (read from main and from the record's section 7.7). The reassembly row is the scale record's; section 1.3 gives what it is with GRO on.

| Row | C and D (KiB) | With E (KiB) | Where it is held, on main |
|---|---|---|---|
| Receive windows: what the peer sent and the relay has not read | 2,048 | 2,048 | `QUIC_RECEIVE_WINDOW`, 2 MiB a connection; `QUIC_STREAM_RECEIVE_WINDOW`, 1 MiB a stream (`transport_config`) |
| Quinn's reassembly beyond them, with GRO off | 5,120 | 5,120 | quinn-proto 0.11.14, `assembler.rs` (read). With GRO on, about 80 MiB (section 1.3) |
| Send window: what the relay wrote and the peer has not acknowledged | 2,048 | 2,048 | `QUIC_SEND_WINDOW` (change C) |
| The stream being served, across a wait on the peer | 6,144 | 2,048 | `serve` keeps the frame, the request, the answer and its encoding through `write_frame(send, &answer).await`. With E, the frame and the request are dropped first; the answer and its encoding (1 MiB each) are still held through the write, since `write_frame` encodes inside it |
| The relay's own fetch from this peer | 3,256 | 1,144 | `fetch_from` holds the decoded page through its fetch. With E, it holds the answer frame being read (1 MiB) and the channels listed (about 120 KiB as strings) |
| The connection's own state | 64 | 64 | An allowance in the scale record. Measured here: 41 to 75 KiB a connection at rest (section 7) |
| The relay's tables for the peer | 300 | 300 | The scale record's section 2.5 |
| **W** | **18,980** | **12,772, about 12.5 MiB** | |

With E, the synchronous part's peak (a frame, its decode and an answer, at most the rationale's 6 MiB) is counted once for each worker, as P, and not for each connection: no connection holds it across a wait.

So with E alone, and GRO off, a container of 1 GiB holds (1,024 − 64 − 6) / 12.5 = **76 connections at worst** on one core, and about 80 take it to its limit (derived). That is far from 200. Of the 12.5 MiB, 9 MiB are QUIC's windows and reassembly, which exist on every connection whether or not the relay is working on it.

### 1.2 What a peer controls

Read from main:

- **How long a stream holds what it holds.** The codec gives each read and each write `STREAM_TIMEOUT_SECS`, each on its own: the protocol byte, the length, the payload; the answer's length, its payload. A peer that sends a frame but its last byte holds the relay's frame buffer for 10 s. A peer that grants no credit holds a write for 10 s, whatever the send window: quinn's `SendStream::write` waits on the peer's credit (`Send::write`, `budget == 0` gives `Blocked`) as well as on the send window (`write_limit`). A write whose length waits out its 10 s fails there, so a stream is held for at most about 20 s: 10 s to read its payload, and 10 s for one write of its answer.
- **What a timed-out frame costs it.** Nothing: a frame whose read times out is not counted against any allowance (`serve` returns `None` where `read_raw_frame` fails; so does `read_push`). So the trickle above can be kept up with no breach.
- **How many streams it has open.** `QUIC_MAX_BIDI_STREAMS`, 64. The inbound loop (`handle_peer_streams`) serves one at a time; the other 63 sit in quinn, each with up to a stream's window of data.

### 1.3 Quinn's reassembly, and the kernel's receive offload

Read from quinn-proto 0.11.14 (`connection/assembler.rs`), quinn 0.11.9 (`endpoint.rs`) and quinn-udp 0.5.14 (`unix.rs`); **measured by the review on loopback**, with no root.

- Quinn keeps each received stream frame as a slice of the packet it came in, so a small frame keeps its whole packet's buffer alive. The assembler counts each slice at its packet's payload length, and copies what it holds into one buffer (`defragment`) once what it counts beyond the data exceeds max(32 KiB, 1.5 × the data). That is the bound the rationale reads: on each stream, the data, and up to max(32 KiB, 1.5 × the data) more.
- **quinn-udp turns GRO on for every socket on Linux** (`UDP_GRO`, 64 segments), and quinn copies each batch of datagrams it is handed into **one** buffer, which it then splits into packets that share it (`buf[0..meta.len].into()`, then `split_to(meta.stride)`). The assembler still counts each slice at one packet's length. So a stream frame of one byte, in a batch whose other packets carry data the relay reads (or only padding), keeps the whole batch alive while it is counted at one packet.
- **Loopback does this.** A sender's GSO batch reaches a socket with `UDP_GRO` on as one buffer (the review: one receive of 48,000 bytes, stride 1,200; a veth pair the same, 61,600 bytes); with the option off, the kernel splits it into separate datagrams. Quinn sends with GSO by default, so any quinn peer makes such batches; a peer may also send larger ones (the review's client sent 44 datagrams a batch).
- **What one connection held** (measured by the review: a quinn server, and a client sending bulk on a stream the server reads and one-byte writes on the streams it does not; peak live heap):

  | Windows and streams | GRO on | GRO off |
  |---|---|---|
  | Main's: 1 MiB and 2 MiB, 64 streams | 82,467 KiB | 2,262 KiB |
  | F's: 144 KiB and 288 KiB, 8 streams | 5,067 KiB | 422 KiB |

- **What is not confirmed:** whether a real network card coalesces a remote sender's datagrams that arrived as separate packets (on veth with GRO on, 2,000 separate sends were never coalesced). That bears on how a remote peer does it, not on whether rule 10 is needed: on loopback, and wherever batches arrive whole, the pinning is measured.

This is why rule 10 exists, and why it is built first and on its own.

## 2. The change

Two parts: (a) a budget across all connections for the application's buffers; (b) QUIC's windows and streams, and the reassembler. Each rule says its reason.

### 2.1 Part (a): what the application holds

1. **A small message is 144 KiB.** `SMALL_PAGE_BYTES` is 128 KiB (131,072 bytes) of entries, chosen: the least power of two that holds an entry of the largest size on the wire (65,773 bytes, `MAX_ENTRY_WIRE_BYTES`) and others beside it. It holds one entry of the largest size, not two (131,546). `SMALL_MESSAGE_BYTES` is that and 16 KiB more for what is around the entries, derived: a page's own fields and the length of each entry come to under 1 KiB for 100 entries. Every message a device of this version sends or is sent fits one (checked by the review): a page or a push (rule 3, rule 5), a whole show (a change entry, 32 KiB), a show's answer (`SHOW_ANSWER_ROOM_BYTES`, 66,560), a hand-over (54,275 bytes before it is padded, `MAX_HAND_OVER_BYTES`; 65,773 on the wire, an entry of the largest size), a proof, a pull. So do the older kind's pages of headers (with E's bounds), and its channel lists of up to about 1,500 IDs (1,024 IDs encode to about 67 to 100 KB, by their length; 2,300 to 151,849 bytes, measured by the review).

2. **A frame from an unlisted peer that is longer than a small message is read only under a large permit.** The node reads the protocol byte and the four bytes of length as now. Where the length is over `SMALL_MESSAGE_BYTES`, it takes a large permit before it allocates the payload.
   - **How many:** at most `LARGE_MESSAGES_AT_ONCE` (4) at once across all the node's connections, and **at most one for each /24 (IPv4) or /48 (IPv6)** of the peers' addresses, as `rate_limit::subnet_key` groups them. A waiter whose subnet holds a permit waits for that one; among the others, the first to ask is the first served.
   - **One permit for each stream at a time.** A stream holds at most one. It covers whatever large frame the stream is reading and the answer it then writes, and is let go before the stream waits for its next frame. The older kind's sync stream reads many frames in turn (rule 3, rule 6); each large one takes a permit of its own, after the last was let go.
   - **How long it is held:** until the stream is done, its answer written or the stream failed: at most about 20 s, 10 s to read the payload and 10 s for the answer's write (section 1.2).
   - **What waits:** the stream, unread. Its payload stays in QUIC, within the connection's receive window (rule 8), and the peer can send no more of it. The connection's inbound loop waits with it: that connection's other streams wait too, and no other connection's.
   - **For how long:** at most `STREAM_TIMEOUT_SECS`. A stream that has no permit by then is reset with a code of its own, `ERR_LARGE_MESSAGE_LATER` (0x05), and the loop goes on to the connection's next stream. It counts no breach: the peer did nothing over a limit. **Why a code of its own:** `ERR_CAPACITY` says that the node holds no room for the connection (network-protocol.md §9.1); this says the stream may be sent again as it is. A version before treats every reset as a request not answered, so to it the two read the same; a later version may wait before it sends again.
   - **Who needs one:** devices of the version before, whose pushes are up to `ENTRY_PAGE_MAX_BYTES` (896 KiB), the older kind's pushes (up to `OUTBOX_BATCH_MAX_BYTES`, 195 KiB, or more from an older version), and the answers to the relay's own fetch (rule 6). A device of this version never does (rules 3 and 5).
   - **How it is sized:** four, chosen. A relay at R1 carries few devices of the version before, and each sends a large message only when a batch has built up; four let four of them at once go at full pace. Each permit holds at most a frame (1 MiB) while it is read, the request or page decoded (2 MiB and 64 KiB, D's bound) where an older-kind handler awaits with it, and an answer encoded (1 MiB) while it is written: 4,160 KiB, so **G = 16.25 MiB** (derived).
   - **One for each subnet, chosen over none:** without it, one address (five connections) holds every permit. With it, a peer needs four /24s to hold them all, and about six to keep a waiter of the version before from ever being served (each holder keeps its permit about 20 s, and the waiter gives up after 10 s). The bound of 200 connections admits ten /24s, so it raises what an attack takes and does not remove it. Its cost: two devices of the version before behind one address do not send large messages at once.
   - **What a device of the version before does when refused:** it takes the reset as a request not answered, and sends the same batch again at its next send; so while an attack holds the permits, its outbox does not drain at that relay. Its other exchanges (pulls, shows, small pushes) go on. That is the cost, and it falls on devices of the version before alone. A device of this version is not held up by it.

3. **An answer to an unlisted peer is built within a small message, and a device reads on where a page says there is more.**
   - **Pages:** a page of entries for a connection that is not a listed relay's holds at most `SMALL_PAGE_BYTES` of entries (where `relay::pull` in `cordelia-storage` stops at `ENTRY_PAGE_MAX_BYTES` today), and at least one entry whatever its size; it says there is more, as a page that is full does today. So a page holds one entry of the largest size, with smaller ones beside it. A listed relay is given full pages, as today.
   - **The read of a pair channel at accept follows "more".** It pulls one page from the start today (`device_entries/leave.rs`, the read behind `cordelia accept`) and does not read on. A pair channel can hold more than one entry of the largest size (a hand-over is padded to it), and a small page holds one, so the hand-over of the typed key could be on a later page. It reads on from the page's place until a page says there is no more, at most `RELAY_ENTRY_PULL_PAGES` (10) pages. Every other read of a device already reads on from a place it keeps (`own_read`, the reads of a generation left, the pass).
   - **Every other answer** of the streams of entries is within a small message already (rule 1).
   - **The older kind's fetch answer** (`handle_inbound_sync`), whose size the relay sums before it loads the items (`total_cost_by_ids`), takes a large permit before it loads them where that sum is over `SMALL_PAGE_BYTES`, as rule 2 says.

4. **What a stream holds across a wait on the peer is one small message.** E drops the frame and the request before the write. F also encodes the answer and drops it before the write, and writes the encoded bytes (`write_raw_frame`), so that what waits on the peer's credit is the encoding alone. Before the read, nothing is allocated past the length (rule 2).

5. **A device of this version pushes at most `SMALL_PAGE_BYTES` in one push** (`room_to_push` in `device_entries.rs`, where it stops at `ENTRY_PAGE_MAX_BYTES` today). So a device never needs a large permit, at a relay of this version or of the version before.

6. **A relay's own fetch from an unlisted peer reads each answer as rule 2 reads a request.** A frame within a small message is read at once; a longer one is read only under a large permit (one for the stream at a time, rule 2), the stream waiting unread meanwhile. A fetch that has no permit within `STREAM_TIMEOUT_SECS` fails, and the peer is asked again as after any failed fetch (`next_ask`). The fetch asks as it does today: up to 100 headers a page, and the items of a page in one fetch.
   - **Why by length, and not one item a request:** an item's size is not on the wire before the item (`ItemHeader` carries none), so a request cannot be fitted to the sizes of what it asks. Asking for one item at a time, which a request fitted to the largest size would be, drains a backlog of small items about a hundred times slower (two round trips an item). Read by its length, a fetch of small items stays one message for up to 100 of them, and only a large answer waits for a permit.
   - **The channel list, read under a permit, chosen over a bound at the sender.** An honest sender lists every channel it holds (`channels_it_lists`): the bound `MAX_CHANNELS_ASKED_OF_A_PEER` is applied where the list is read, by an asker that does not list the sender by key. The sender cannot tell which kind of asker it answers, and telling it would change the wire. A relay that lists this one by key while this one does not list it back, and holds more than about 1,500 channels, sends a list over a small message; read under a permit, its first `MAX_CHANNELS_ASKED_OF_A_PEER` are kept as today, where read within a small message only it would fail every time.
   - **What it holds across its waits, with E:** a frame of a small message, or nothing beyond QUIC's window while it waits for a permit; the IDs it took from the page; and the channels kept (up to 1,024).
   - **No budget across connections is set for the relay's own fetches** (reason below).

7. **A listed relay is outside rules 2, 3 and 6.** Its frames are read at once whatever their size; it is given full pages; the relay's fetch from it reads whole messages. It is one or two connections, which the operator chose by key, and the passes between relays need full pages to keep pace. What it holds is counted as L (section 3). **A relay configured by address alone is an unlisted peer for F**, although the older kind treats it as the node's own (`own_relay` and `limited` in `p2p.rs`, matched by address): an address is not an identity, and whoever connects from it would otherwise be read without a bound. R1's relays list each other by key (the deployment files name the default relays, whose keys are compiled in), so this costs them nothing.

**Considered, and not taken: one budget over every stream,** a semaphore taken before a frame is read and held until the answer is written, at most one for each connection (which the inbound loop already gives). A peer decides how long a stream lasts: up to about 20 s (section 1.2). So with p permits, h slow connections hold min(p, h) of them for up to 20 s each, and take them again as soon as they are let go. A device of this version waits for its answer for 10 s (`read_frame`), and then gives the request up; behind a queue of h such connections it waits about 20 × h / p seconds. With p = 16 and h = 16 that is 20 s: every honest request fails. A cap for each address or each /24 raises the number of addresses needed, and does not change the outcome: a peer with as many /24s as there are permits holds them all, and the bound of 200 connections admits ten /24s. Rules 1 to 5 reach the same bound on memory without a shared permit for any exchange of a device of this version.

**Considered, and not taken: a budget over the relay's own fetches.** A hostile peer can keep the relay's fetch from it going for as long as it likes (it answers every page with `has_more`, as the scale record's section 7.5 says), so a few peers would hold every permit of such a budget, and the relay would fetch from nobody else. Rule 6 bounds what each fetch holds across a wait to a small message, and puts its large answers under the permits of rule 2. There is one fetch for each peer at a time (`Fetching`), so their sum is bounded by the connections, and is in W.

**What is left shared:** the store's lock and the CPU. F does not bound them (section 6).

### 2.2 Part (b): QUIC's windows and streams, and the reassembler

8. **The receive windows: one small message on a stream, two on a connection.** `QUIC_STREAM_RECEIVE_WINDOW` = `SMALL_MESSAGE_BYTES` (144 KiB), and `QUIC_RECEIVE_WINDOW` = 2 × it (288 KiB). Reason: the largest thing a device of this version sends is one small message; two on the connection let a second request arrive while the first is read, as two messages did. A large message still arrives, a window at a time: the node reads as it arrives and quinn grants more. Its cost is in section 2.3.

9. **A peer may have 8 streams open on a connection, not 64.** `QUIC_MAX_BIDI_STREAMS` = 8, and `MAX_CONCURRENT_STREAMS` in `protocol.rs` follows it.
   - **Reason:** the inbound loop serves one stream at a time, so a stream beyond the first only waits; and each open stream may hold 32 KiB of quinn's reassembly beyond its data (section 1.3), so 64 streams floor that row at 2 MiB a connection and 8 at 256 KiB.
   - **What opens streams on one connection at once.** A device: one for its pass at each relay, one for a waking show, one for a hand-over ask, one for each read a command asks of it (a carry or a recovery; `p2p.rs` spawns those as they are asked), about four. A relay to a device: its own fetch, one at a time (`Fetching`). Between relays: a pass on (`pass_on`, one task for each listed relay, its messages in turn), a pull (`pull_from`, one at a time), a fetch of the older kind, the older kind's repush, and **the older kind's push retries, one stream for each item** (`p2p.rs`, the retry loop), which after a failed repush of up to `MAX_PUSHED_ITEMS` items would open them all at once.
   - **So the push retries are bounded.** A node runs at most `PUSH_RETRY_STREAMS_AT_ONCE` (4, half the streams) push retries to one peer at once; the others stay in the retry queue for its next round, and are not counted as an attempt (`PUSH_RETRY_MAX`) until they are tried. Without it, at 8 streams most of them would wait for a stream, time out after 10 s and use up their attempts.
   - **What waits that is not a millisecond:** the older kind's sync stream holds the connection's inbound loop for the whole of a fetch, many frames, as it does at 64; the streams behind it wait for it. An opening that waits for a stream waits at most `STREAM_TIMEOUT_SECS` (`open_bi`), and fails as it would on a connection lost.

10. **No node takes UDP datagrams in batches** (built first, on its own: branch `fix/udp-gro-off`).
    - **The rule:** the node's endpoint socket has `UDP_GRO` turned off **after** quinn has wrapped it. quinn-udp turns the option on when it wraps a socket (`UdpSocketState::new`), so turning it off before is undone. The endpoint keeps a clone of the socket (`try_clone`), made before it is handed to quinn, and turns the option off on it once the endpoint is made; `create_endpoint` moves from `Endpoint::server` to `Endpoint::new` with a socket of its own to do so. No fork of quinn is needed: `AsyncUdpSocket`, `max_receive_segments` and `Endpoint::new_with_abstract_socket` are public.
    - **A wrapper that tells quinn one segment** (`max_receive_segments` = 1) is optional: it shrinks quinn's receive buffer from 64 datagrams a slot to one, which saves about 2.9 MiB held once for the endpoint (measured by the review: 3,033 KiB, and 135 KiB with it). It is not what makes the node safe, and alone, with GRO still on, it would truncate the kernel's batches.
    - **Reason:** section 1.3. With GRO off, each stream frame pins its own datagram only (at most `max_udp_payload_size`, 1,472 bytes), which is what the assembler counts, and its bound holds as the rationale reads it: measured by the review, 2,262 KiB a connection on main's windows and 422 KiB on F's, against 82,467 and 5,067 with GRO on.
    - **Cost:** the kernel hands the socket one datagram for each entry of a `recvmmsg` (up to 32 a call) in place of a batch. Measured by the review in bulk on loopback: 733 MiB received for each second of CPU with GRO, 325 without, about 2.3 times the CPU for each byte received. At an honest relay's pace (2 MiB a minute for each connection) that is not measurable; under a flood it doubles a receive cost that section 6 already leaves unbounded.
    - **Not taken: lower stream counts alone.** With GRO on, F's 8 streams still measured 5,067 KiB a connection.

11. **The send window: two small messages.** `QUIC_SEND_WINDOW` = 2 × `SMALL_MESSAGE_BYTES` (288 KiB). Reason: what a node writes to an unlisted peer is a small message (rule 3), so a window of two takes the answer whole and the next before the first is acknowledged, as two messages did. A large write (to a listed relay, or the older kind's fetch answer under a permit) goes a window at a time, waiting for acknowledgements, within the codec's 10 s. **Smaller than two messages is safe:** no honest write of a small message waits, and a large one waits only a round trip at a time (measured, section 2.3). One small message alone was considered: an answer could then wait for the acknowledgement of the one before it, a round trip, on every request of a pass; 144 KiB more a connection is the price of not waiting.

The windows and the stream count are transport settings, the same in every direction, for every connection of every node (`transport_config`); quinn has no setter for a stream's window on one connection, only for the whole connection's (`set_receive_window`), so a listed relay gets them too. Nothing on the wire changes: a peer of the version before is told the new limits by QUIC itself, and a page of 128 KiB is a page as any other. The one new thing a peer can see is rule 2's reset code.

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

- **A page, to a device of this version.** At most 128 KiB, one round trip, as a page of that size is today. A page holds one entry of the largest size, or several smaller ones: a channel with 1 MiB new takes 8 pages of small entries (1.6 s in round trips) or 16 of entries of the largest size (3.2 s), where today it takes 2. A device reads up to `RELAY_ENTRY_PULL_PAGES` (10) pages of a channel in a pass, between 0.6 and 1.25 MiB every 10 s, and a relay hands a connection at most 2 MiB a minute (`PUSH_BYTES_PER_PEER_PER_MINUTE`): what a device is handed is not slowed.
- **A push, from a device of this version.** At most 128 KiB, one round trip. A device sends a relay at most 1.5 MiB a minute (`OUTBOX_BYTES_PER_MINUTE`), so at least 12 pushes a minute (24 of entries of the largest size), up to 4.8 s of a minute in round trips. A carry of 4 MB is about 31 pushes of small entries, or about 61 of the largest, where it was 5; it takes the same time, which the pace sets.
- **A pull or a pass between relays.** Full pages: 1.43 s for a page of 896 KiB where it was 0.24 s, and about 19 MiB a minute on one stream. A relay's pull of a channel takes up to 10 full pages a pass, about 14.3 s, longer than the 10 s between pulls; one pull runs at a time from each relay (`Pulling`), so the next begins when it ends. **Catching up after a restart:** at 19 MiB a minute, a relay that was down for an hour at the scale record's stage 190 (under 1 MiB a minute of edits) catches up in about 3 minutes; a relay that starts empty beside one holding 1 GiB takes about 54 minutes, where today's windows take about 11. The scale record's stage 190 asks under 1 MiB a minute between relays.
- **A device of the version before.** Its pushes of up to 896 KiB take 1.43 s, and a large permit (rule 2); its pages from a relay of this version are small (it reads a page that says there is more, as any page). Its own pace bounds it, as above.
- **The longest round trip that still works.** A small message arrives in one round trip, and works at any round trip under the 10 s timeout. A message of 1 MiB took 8 round trips; it arrives within 10 s at round trips under about 1.2 s (derived). Today it took about one round trip.

## 3. W again, with E and F

| Row | With E (KiB) | With E and F (KiB) | Why |
|---|---|---|---|
| Receive windows | 2,048 | 288 | Rule 8 |
| Quinn's reassembly beyond them | 5,120 with GRO off; about 80 MiB with it on (section 1.3) | 688 | Rules 9 and 10: on each of 8 streams, max(32 KiB, 1.5 × its data); at most 8 × 32 + 1.5 × 288 (read). The review measured 422 KiB for its pattern |
| Send window | 2,048 | 288 | Rule 11 |
| Datagrams | 0 | 0 | Off (change C) |
| The stream being served, across a wait on the peer | 2,048 | 144 | Rules 2 and 4: the frame being read, or the answer's encoding being written, one small message |
| The relay's own fetch | 1,144 | 274 | Rule 6: a frame of a small message (144), the IDs taken (about 10), the channels kept (about 120) |
| The connection's own state | 64 | 64 | Allowance; measured 41 to 75 KiB at rest, the relay's tables at rest included |
| The relay's tables for the peer | 300 | 300 | Unchanged |
| **W** | **12,772 (12.5 MiB)** | **2,046 (about 2.0 MiB)** | |

**What is held once, and not for each connection** (derived):

- **K** = 64 MiB, the scale record's.
- **P** = 6 MiB for each core the relay may use: the rationale's frame, decode, answer and encoding of one stream at once, which a worker's synchronous part holds while it runs, and a relay runs a worker for each core. `compose.yml` sets no `cpus` and uses the host's network, so in its container the relay has a worker for each core of the host.
- **G** = 16.25 MiB: four large permits (rule 2).
- **L** = 15 MiB: up to two connections to listed relays (two relays that list each other may hold one or two), each 7.5 MiB: the windows and reassembly of F (1,264 KiB), a stream served at full size across a wait (2 MiB, with E), the relay's fetch from it at full size (a frame of 1 MiB, and its channel list of up to `MAX_LISTED_CHANNEL_IDS` IDs, about 2.9 MiB as strings), and its state and tables. The relay's own streams to a listed relay (its passes, pulls and the older kind's pushes) are left out, as the scale record leaves them out.

So K + G + L = 95.25 MiB, and with P, **95.25 + 6 × cores** MiB: 101.25 on one core, 119.25 on four, 191.25 on sixteen.

**N, and whether the aim is met** (derived; the scale record's S and its rounding down):

| Host | Memory for the relay | Cores | N at worst with E alone | N at worst with E and F | 200 connections at worst take |
|---|---|---|---|---|---|
| A container of 1 GiB (as decided for R1) | 1,024 MiB | 1 | 76 | **461** | 501 MiB |
| The same | 1,024 MiB | 4 | 75 | **452** | 519 MiB |
| The same | 1,024 MiB | 16 | 69 | **416** | 591 MiB |
| A container of 512 MiB (`compose.yml` on main) | 512 MiB | 1, 2, 3, 4 | 35, 34, 34, 33 | **205, 202, 199, 196** | 501 to 519 MiB |
| The README's host, with no container (1 GB) | 768 MiB | 1 | 55 | **333** | 501 MiB |
| The machine of `fly.relay1.toml` (256 MB) | 224 MiB | 1 (shared) | 12 | **61** | over its memory |

**The aim is met:** with E and F, a relay in a container of 1 GiB holds its whole bound of 200 connections, every one behaving as badly as it can, at 501 MiB on one core and 591 MiB on a host of sixteen, on three conditions:

1. **Rule 10 is in.** Without it, F's W measures about 6.5 MiB (the review's 5,067 KiB a connection with GRO on, in place of 422, beside the other rows), and a container of 1 GiB holds about 140 on one core. It is being built first.
2. **The allowances hold.** K, P, the connection's state and L are allowances. Section 5's measurement checks the sum on a whole relay process; what is left of the container (523 MiB on one core, 433 on sixteen) is the margin for them being wrong.
3. **Honest devices are served.** Every exchange of a device of this version is within a small message and needs no shared permit, so no slow peer holds it up through memory (rules 1 to 5). What a flood within the rate limits does to the store's lock and the CPU is not bounded by F (section 6).

The container of 512 MiB on main holds the bound of 200 only on a host of up to two cores; the decision gives R1's relays 1 GiB. Giving the container `cpus: 1` (the scale record's change B, after R1) would hold P to 6 MiB on any host.

## 4. What changes

### 4.1 In `protocol.rs`, for the rationale

| Constant | Value | Reason |
|---|---|---|
| `SMALL_PAGE_BYTES` (new) | 131,072 | Chosen: the least power of two that holds an entry of the largest size (`MAX_ENTRY_WIRE_BYTES`, 65,773) and others. The most of entries in a page for an unlisted peer and in a device's push. A compile-time check that it holds `MAX_ENTRY_WIRE_BYTES` |
| `SMALL_MESSAGE_BYTES` (new) | 147,456 | Derived: `SMALL_PAGE_BYTES` and 16 KiB for what is around the entries. Checks at compile time that `MAX_ENTRY_WIRE_BYTES` (what a hand-over is on the wire), `SHOW_ANSWER_ROOM_BYTES`, `CHANGE_ENTRY_BYTES` and its wire overhead are within it |
| `LARGE_MESSAGES_AT_ONCE` (new) | 4 | Chosen: rule 2. At most one for each subnet |
| `ERR_LARGE_MESSAGE_LATER` (new) | 0x05 | Rule 2: a large message the node could not take within `STREAM_TIMEOUT_SECS`, to be sent again |
| `PUSH_RETRY_STREAMS_AT_ONCE` (new) | 4 | Derived: half of `QUIC_MAX_BIDI_STREAMS` (rule 9) |
| `QUIC_STREAM_RECEIVE_WINDOW` | 147,456 (was 1,048,576) | Derived: one small message (rule 8) |
| `QUIC_RECEIVE_WINDOW` | 294,912 (was 2,097,152) | Derived: two small messages (rule 8) |
| `QUIC_SEND_WINDOW` | 294,912 (was 2,097,152) | Derived: two small messages (rule 11) |
| `QUIC_MAX_BIDI_STREAMS`, `MAX_CONCURRENT_STREAMS` | 8 (was 64) | Chosen: rule 9 |

No new timeout: rule 2's wait and rule 6's are `STREAM_TIMEOUT_SECS`.

The rationale changes with them: §1's sections on the receive windows, the send window and the streams; its table "What one connection can make a node hold", which becomes section 3's W with its rows, the reassembly with GRO measured, and the list of what it leaves out (the large permits, the listed relays, the synchronous part for each core, quinn's queue to each connection); and a new section for the small message and the large permits, with section 2.3's costs. Its sentence "with 200 connections a relay holds at most 400MB unread" becomes 56 MiB. `CLAUDE.md`'s table of parameters follows the constants.

### 4.2 In the code, in plain terms

- **`cordelia-network`, `transport.rs`:** the new values; and GRO off on the endpoint's socket (rule 10), in `create_endpoint` and `create_client_endpoint`: built first, on `fix/udp-gro-off`.
- **`cordelia-network`, `codec.rs`:** a read of a frame's length apart from its payload, so that a caller can decide between them; and an encode that the caller holds, written with `write_raw_frame` (rule 4).
- **`cordelia-node`, `p2p.rs`:** the large permits, one semaphore and its subnets made at start and handed to the inbound loop (`handle_peer_streams`) and to `fetch_from`; the reads of `read_push`, `handle_inbound_sync` (each frame of its loop, and its fetch answer) and the other handlers by rule 2; `fetch_from` by rule 6; the push retries by rule 9.
- **`cordelia-node`, `relay_entries.rs`:** `serve` by rules 2 and 4, with E; pages for an unlisted peer within `SMALL_PAGE_BYTES` (rule 3): `cordelia-storage`'s `relay::pull` takes the most bytes as an argument, which `serve` gives by its peer. What a relay passes on to a listed relay (`to_pass_on`) is not changed.
- **`cordelia-node`, `device_entries.rs` and `device_entries/leave.rs`:** `room_to_push` stops at `SMALL_PAGE_BYTES` (rule 5); the pair read at accept reads on (rule 3).
- **`deploy/relay/compose.yml`:** `mem_limit: 1g`, as decided, where the release has not set it already.

### 4.3 In other records

In the scale record, by sentence:

- **§0, item 1:** "Even with them, a connection can make a relay hold about 18.5 MiB at worst (section 2.5)." gains: "With the kernel's receive offload on, as every released version has it, about 80 MiB (the record of memory across connections §1.3); with changes E and F, in alpha.16, about 2.0 MiB."
- **§0, item 2, and the known limit's paragraph:** "Against a hostile peer, the bound is far above what the deployed files hold." and the figures after it are said for the build before E and F, and followed by: "With E and F, the container of 1 GiB that R1's relays are given holds 461 at worst on one core and 416 on sixteen, so the bound of 200 is within it; the container of 512 MiB holds 205 on one core and 196 on four, the README's host without a container 333, and Fly's machine of 256 MB 61."
- **§0, "So a peer that opens about 27 connections …":** said for the build before E and F, and with GRO off; with GRO on, about 6 such connections. With E and F, no number of connections within the bound takes the container of 1 GiB to its limit by memory. The account of `restart: always` stays, for Fly's machine and for what F does not bound (the lock and the CPU).
- **§0, "That is a known limit of R1, accepted …":** "Change B, after R1, sets the bound from the host; change E (section 7.7) lowers W" becomes: "The fix for GRO ships first; changes E and F, in alpha.16, lower W to about 2.0 MiB; change B, after R1, sets the bound from the host."
- **§2.5, the table:** a column for E and F, or a line under it that points to section 3 here; and the reassembly row says it holds with GRO off. **The peak of a decode, and the workers:** P is 6 MiB a worker with E (not 3), one worker for each core. **"A change that lowers W, not counted here"** becomes "Changes E and F, in alpha.16, counted in the record of memory across connections". **"Not taken: a smaller receive window"** becomes "Taken by change F (two small messages), with its cost". **Change B's figures** (the default of 24, the cap of 384, the sweep that settles at 16, the 10.5 GiB for 500 devices) are derived again from W = 2.0 MiB when B is built.
- **§7.7:** "Proposed, before or after R1 as the person decides … The figures of section 2.5 do not count on it." becomes "In alpha.16, before R1, as the person decided, with change F (cordelia-node #194)." Its "What it lowers" gains: F also encodes the answer and drops it before the write.
- **§13:** the row of change E reads "In alpha.16, with change F, before R1 (#194)".

`docs/specs/network-protocol.md` §2.1 lists the new windows and stream count, and §9 the new reset code. `docs/specs/configuration.md` is not changed: none of these is a setting.

### 4.4 What a personal node and a bootnode get

The same transport settings (rules 8 to 11) on every connection, since `transport_config` is every node's, and GRO off on their sockets. A device's pages from a relay of the version before (up to 896 KiB) arrive a window at a time: 1.43 s at 200 ms, within the codec's 10 s. Rule 5 and the pair read of rule 3 are a device's own. Rules 2 and 4 apply wherever a node serves streams a peer opens: a personal node with `listen = true`, `trusted_peers` or swarm children, and a bootnode (whose `PeerSharing` answers are small). A personal node's listed relays are those it is set up with by key. A personal node's own pass is not changed: it sends small messages already.

## 5. The tests

Each rule has a test that fails on an assertion when the rule is taken out.

1. **Rule 1:** compile-time checks of section 4.1; a test that each message a device of this version builds (a full push, a whole show, a hand-over as it is padded, a show's answer with an entry of the largest size) encodes within `SMALL_MESSAGE_BYTES`.
2. **Rule 2:** in `p2p.rs`'s tests of the inbound loop, over in-process QUIC:
   - With the four permits held (from four subnets), an unlisted peer's frame of 1 MiB is not read: the peer's `write_all` has taken no more than the stream's window after 2 s, and the relay's counting allocator shows no allocation of the frame; after `STREAM_TIMEOUT_SECS` the stream is reset with `ERR_LARGE_MESSAGE_LATER` and the peer's rates show no breach. With a permit let go, the same frame is read and answered.
   - A second peer of a subnet that holds a permit waits behind it while a peer of another subnet is served.
   - A stream holds at most one permit: the older kind's sync stream that reads a large frame and then writes a large fetch answer holds one throughout.
   - A listed relay's frame of 1 MiB is read with all four held (rule 7); a relay configured by address alone is not (it waits).
   - A stream that fails while it holds a permit gives it back (five such streams fail in turn, and then four permits can be taken).
3. **Rule 3:** a channel holding 13 entries of the largest size: a page to an unlisted connection holds at most `SMALL_PAGE_BYTES` of entries and at least one, and says there is more; to a listed relay, up to `ENTRY_PAGE_MAX_BYTES`. The older kind's fetch answer over `SMALL_PAGE_BYTES` waits for a permit, as in test 2. **The pair read:** a pair channel at a stand-in relay holding an entry of the largest size from another author ahead of the typed key's hand-over: `cordelia accept` finds the hand-over (it fails on the assertion where the read takes one page).
4. **Rule 4:** with E's counting allocator, a pull whose answer is a page of 128 KiB, to a peer that grants no credit: while the write waits, the stream holds no more than the encoded page (no frame, no request, no answer).
5. **Rule 5:** a device with 2 MiB waiting pushes no message over `SMALL_MESSAGE_BYTES` (a stand-in relay records the frame lengths).
6. **Rule 6:** a stand-in peer answers a relay's channel list with a frame of `SMALL_MESSAGE_BYTES` + 1: with the permits held, the fetch waits and then fails after `STREAM_TIMEOUT_SECS` with nothing of that size allocated; with a permit free, the list is read and its first `MAX_CHANNELS_ASKED_OF_A_PEER` are kept. A page of 100 small headers is fetched in one request of 100 IDs.
7. **Rules 8, 9 and 11:** the values, read from the configs as `the_send_window_is_two_messages_at_both_ends` reads them; and behaviour over in-process QUIC: a peer that writes on 9 streams finds the 9th open waiting; a peer that does not have its data read can write no more than `QUIC_RECEIVE_WINDOW` over its streams. The send window's test of #187 runs at the new value. **The push retries:** a failed repush of 100 items to a peer opens no more than `PUSH_RETRY_STREAMS_AT_ONCE` streams at once, and every item is tried `PUSH_RETRY_MAX` times at most and at least once.
8. **Rule 10, behaviourally, on loopback:** a node's endpoint, and a stock quinn client (its GSO sends up to 10 datagrams a batch) that sends bulk on one stream the node reads and one-byte writes on the other 7 streams, which the node does not read. The test reads the live heap that the connection makes the node hold (with a counting allocator, in process) and asserts it stays under the reassembler's bound for F's windows, 976 KiB (288 + 688) and the frame being read. Taken out, it holds about 2.3 MiB (derived: each one-byte slice pins a batch of 10 datagrams, about 320 KiB on each of 7 streams), and the assertion fails. Beside it, `getsockopt(SOL_UDP, UDP_GRO)` on the endpoint's socket returns 0. Built with rule 10, on its own branch.
9. **The tests that rest on the old values:** `test_quic_max_bidi_streams_network_protocol_2_1` in `protocol.rs` (asserts 64), `a_connection_holds_at_most_64_streams_open` in `transport.rs` (its name and comment), and the send window's assertions in `protocol.rs` (2,097,152) follow the constants. `a_request_is_not_written_once_the_entry_it_was_built_under_is_kept_no_more` (`device_entries_e2e.rs`) holds every stream a connection may have through the constant, and needs no change.

**The measurement: a relay's memory under hostile connections.** `crates/cordelia-node/tests/hostile_memory_e2e.rs`, ignored by default and run by CI's job for ignored tests. No root: everything is on loopback, from addresses of 127.0.0.0/8.

- **A relay process** of this build, **pinned to one core** (started under `taskset -c 0`, so that it runs one worker and P is 6 MiB), with two devices of one person of this version connected first, each mapping one name.
- **198 hostile connections**, so that the relay holds its bound of 200, from in-process quinn clients **on 40 addresses in ten /24s, five connections to an address and twenty to a /24**, each doing all of these, on every stream it may open, for ten minutes:
  - frames of a small message, sent but their last byte, again as each stream times out;
  - from four of the /24s, frames of 1 MiB the same way, so that they hold every large permit;
  - bulk on a stream the relay reads and one-byte writes on its other streams, a write at a time, so that the reassembler holds many small slices in the client's GSO batches;
  - pulls of pages of a channel of its own that it filled (within `NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR` and the push allowance), with its own stream credit set to one byte (its `stream_receive_window`), so that the relay's writes wait on its credit;
  - answers to the relay's own fetch, with frames of a small message, trickled, and every page saying there is more;
  - every count kept under half of its limit, so that nothing is cut off for a breach.
- **Read:** the relay's `VmHWM` and `VmRSS` from `/proc`, once a second; its connections open at the end (198 hostile and the two devices).
- **The bar:** `VmHWM` at most 512 MiB, half the container of R1: K + P + G + L + 200 × W is 501 MiB on one core, so the bar leaves no room beyond the arithmetic, and the other half of the container is the margin of section 3, condition 2; all 200 connections open at the end; and, through the flood, every edit written in one device's folder is in the other's within 25 s, the scale record's bar 2 at p95, and within 120 s at most.
- **Run once with rule 10 taken out, and reported:** it is expected to go over the bar. The clients' one-byte writes ride in GSO batches, which a socket with GRO on takes whole (section 1.3): about 2.3 MiB more a connection by the derivation of test 8, some 450 MiB over the 198. It is the measurement's own check that it loads the reassembler.

## 6. What it does not do, and what is left as a known limit of R1

- **The store's lock and the CPU under a flood within the rate limits.** 199 connections, each at its count (`ENTRY_REQUESTS_PER_PEER_PER_MINUTE`, 3,000), ask a relay about 10,000 requests a second, and rule 10 makes each byte received cost about 2.3 times the CPU. F bounds what they make it hold, not the time they take. Whether honest devices keep bar 2 under that is not known; section 5's measurement keeps its hostile peers under half of every count, and reports the devices' latency. A known limit of R1.
- **Quinn's queue from the endpoint to each connection** (quinn 0.11.9 `endpoint.rs`, `ConnectionSet`: an unbounded channel for each connection) is not in W. Datagrams wait there before the connection's task reads them and flow control applies; where a connection's task is starved for CPU while the endpoint's runs, it grows with what the peer sends. The kernel's socket buffer drops what the endpoint does not read, and the endpoint's reads are limited in time for each turn (`recv_limiter`), but nothing bounds the queue for one connection. Read, not measured; left out, and a known limit of R1, with the CPU above.
- **Devices of the version before, under attack.** About six /24s keep every large permit held, and those devices' large pushes then wait, are refused and are sent again, and their outbox does not drain at that relay while it lasts. When the older kind and the versions before are gone, a node can refuse a frame over a small message from an unlisted peer outright, and the large permits go.
- **What the relay's own streams to a listed relay hold** (passes, pulls, the older kind's pushes and retries) is an allowance in L, not bounded, as the scale record leaves it.
- **GRO from a remote peer.** Measured on loopback and on veth by the review; whether a real network card coalesces a remote sender's datagrams is not confirmed (section 1.3). Rule 10 is needed either way.
- **The allocator.** The measurements here ran this build's glibc binary; the deployed relay is the release's static musl binary, whose allocator may hold more. The margin of section 3 covers it, and the bar is not run on musl.
- **Fly's machine of 256 MB** holds 61 at worst. The scale record's change B (after R1) gives `fly.relay1.toml` 1 GB; until then it is a known limit, as is every host smaller than the container.
- **Nothing sheds a connection that stays alive,** and the bound of 200 is not read from the configuration: both are the scale record's, unchanged.

## 7. What was measured, and what was read

All throwaway, not committed, on a machine of 4 vCPU and 15 GiB, from the release build of main's code (5c633f9), glibc.

**One: a relay process, and hostile connections.** A relay started by the real-process harness (`tests/common`), and connections from in-process clients made with `outbound_connect`, each bound to an address of 127.40.0.0/16 (five to an address, twenty to a /24). Each hostile connection opened every stream it could and wrote on each the protocol byte of a pull, a length, and the frame but its last byte, and then waited; so the relay read one frame at a time and timed it out after 10 s, while the others sat unread in QUIC. `VmRSS` from `/proc`, once a second for 45 to 60 s. The rows marked pinned ran the relay under `taskset -c 0` (one worker, four threads in all); the others let it use the 4 vCPU. Loopback, with GRO on, but these clients write their frames in large writes, so their datagrams were full and no batch was pinned by a small slice.

| Build | Pinned | Connections | At rest, a connection | Hostile: frame | Most RSS | A hostile connection, over the relay at rest |
|---|---|---|---|---|---|---|
| Main | no | 50 | 75 KiB | 1 MiB, 64 streams | 245 MiB | 4,708 KiB |
| Main | no | 100 | 56 KiB | 1 MiB, 1 stream | 125 MiB | 1,118 KiB |
| Main | no | 100 | 58 KiB | 1 MiB, 64 streams | 474 MiB | 4,695 KiB |
| Main | yes | 190 | 45 KiB | 1 MiB, 64 streams | 871 MiB | 4,606 KiB |
| F's windows, 8 streams, and frames over a small message left unread for 10 s | no | 100 | 56 KiB | 144 KiB, 8 streams | 89 MiB | 748 KiB |
| The same | no | 100 | 49 KiB | 1 MiB, 8 streams (left unread) | 69 MiB | 535 KiB |
| The same | no | 190 | 45 KiB | 144 KiB, 8 streams | 155 MiB | 741 KiB |
| The same | yes | 190 | 41 KiB | 144 KiB, 8 streams | 149 MiB | 715 KiB |
| The same | yes | 190 | 41 KiB | 1 MiB, 8 streams (left unread) | 110 MiB | 505 KiB |

What it says: the cost is linear in the connections, and pinning to one core changed it by under 4%; main's rows for this pattern (the receive windows, the reassembly and the frame: 8,256 KiB by the arithmetic) measured 4,606 to 4,708; F's same rows (288 + 688 + 144 + 64 = 1,184 by the arithmetic) measured 715 to 748, about a sixth of main's. 190 such connections took a relay pinned to one core to 871 MiB on main and 149 MiB with F's settings. It does not load the send window, the relay's own fetch, its tables, the large permits or GRO's pinning: section 5's measurement does.

**Two: what the windows cost at 200 ms.** Section 2.3's table: in-process endpoints of this build, through a throwaway delay line (in order, 100 ms each way), each size once after 16 MiB each way.

**Measured by the review** (standalone quinn 0.11.9 and quinn-udp 0.5.14 programs, on loopback and a veth pair, no root): that a socket with `UDP_GRO` on is handed a GSO batch as one buffer; the heap one connection holds with GRO on and off, on main's windows and on F's (section 1.3); the CPU of a byte received with and without GRO (rule 10); what the wrapper of one segment saves (rule 10); the encoded size of a channel list of 2,300 IDs (rule 1).

**Read, not measured:** the reassembler's bound and how quinn shares a batch's buffer (section 1.3); that a write waits on the peer's credit (quinn-proto `Send::write`); quinn's per-connection setters (`set_send_window`, `set_receive_window`), not used; quinn's queue to each connection (section 6); the codec's timeouts and that a timed-out frame is counted against nothing (section 1.2); that `ItemHeader` carries no size (rule 6); that an honest sender lists every channel it holds (rule 6); the pair read at accept (rule 3); the push retries' one stream for each item (rule 9); where E's drops fall (the scale record's section 7.7).

**Derived:** every W, N, G, L and P above.

## 8. The review, and how each finding is settled

The review read the record at its first commit against main, quinn 0.11.9, quinn-proto 0.11.14 and quinn-udp 0.5.14, measured GRO and the reassembler with standalone quinn programs, and had the code read for findings 4, 6, 7 and 8: high 1, medium 5, low to medium 1, low 4; three not confirmed.

| # | Severity | Finding | How it is settled |
|---|---|---|---|
| 1 | High | GRO's pinning can be seen on loopback, and was measured: 82,467 KiB a connection on main's windows with GRO on, 2,262 off; 5,067 and 422 on F's. Without rule 10 F's W is about 7 MiB. Test 8 only read the option; the measurement's run with rule 10 off would not read the same | Section 1.3 and section 6 say "measured on loopback by the review", with its figures; section 1.1 and section 3 give the row with GRO on; test 8 is behavioural (bulk and one-byte writes from a stock quinn client, the heap under the reassembler's bound, failing on that assertion without rule 10); the measurement's run without rule 10 is expected to go over the bar. Rule 10 is built first, on its own (`fix/udp-gro-off`). Remote coalescing by a network card stays not confirmed, and is said so |
| 2 | Medium | The bar counted P for one worker; a relay runs a worker for each core, and `compose.yml` sets no `cpus`; and "an address of its own /24" contradicted "twenty to a /24" | P is 6 MiB for each core, in the words and in section 3, with N for 1, 4 and 16 cores (461, 452, 416 in 1 GiB; 591 MiB for 200 on sixteen cores); the measurement's relay runs under `taskset -c 0`, and section 7 measured that (pinned rows). The measurement's addresses are 40 in ten /24s, five to an address and twenty to a /24 |
| 3 | Medium | An honest sender lists every channel it holds, so a list over a small message would fail rule 6 every time; and "listed" meant by key in rules 2, 6 and 7 but by address for the older kind | Rule 6 reads a channel list over a small message under a large permit, chosen over a bound at the sender, with the reason (the sender cannot tell its asker's kind without a change to the wire). "Listed" means listed by key in every rule of F, said in the words and in rule 7; a relay configured by address alone is unlisted for F, and why. Rule 1's size of a list is corrected |
| 4 | Medium | Rule 6 asked one item a request, about a hundred times slower for small items | Rule 6 reads each answer by its length (small at once, large under a permit) and asks as today, 100 headers and a fetch of a page's items; `ItemHeader` carries no size, so a request cannot be fitted to sizes, which the rule says |
| 5 | Medium, not confirmed | A hand-over is an entry of the largest size on the wire, a small page holds one, and the pair read at accept reads one page; §2.3's figures held for small entries only | Rule 3 has the pair read follow "more", up to 10 pages, with a test (test 3) that fails where it takes one page; rule 1 gives a hand-over's size on the wire; section 2.3 gives the figures for small entries and for entries of the largest size (8 or 16 pages for 1 MiB, 31 or 61 pushes for 4 MB) |
| 6 | Medium | Rule 9's survey left out a relay's own paths: the older kind's push retries open one stream for each item; the older kind's sync stream holds the loop for a whole fetch; two tests assert 64 | Rule 9 lists a device's, a relay's and the paths between relays; the push retries are bounded to `PUSH_RETRY_STREAMS_AT_ONCE` (4) for each peer, with the rest kept for the next round without spending an attempt, and a test; the sync stream's hold is said. Test 9 names `test_quic_max_bidi_streams_network_protocol_2_1` and `a_connection_holds_at_most_64_streams_open` |
| 7 | Low to medium | A permit is held up to about 20 s; about six connections starve an older device; an older device sends the same batch again and its outbox does not drain; two rules could ask for permits on one stream; `ERR_CAPACITY` got a second meaning | Rule 2 says how long a permit is held, one permit for each stream at a time, at most one for each /24 or /48 (chosen, with its cost and what it does not remove), what a device of the version before does when refused, and a code of its own, `ERR_LARGE_MESSAGE_LATER` (0x05), with the reason; section 6 says it. The exemption keyed on the certificate's key is kept as the review found it |
| 8 | Low | The windows are global, so between listed relays 10 full pages take about 14.3 s, longer than the pull interval | Section 2.3 says it, that pulls from a relay run one at a time, and the catch-up after a restart (about 3 minutes after an hour down at stage 190; about 54 minutes for 1 GiB, where it was about 11); the end of section 2.2 says quinn has no setter for one connection's stream window |
| 9 | Low | Rule 10 costs about 2.3 times the CPU for each byte received; the wrapper is not what makes it safe; the order matters | Rule 10 gives the measured cost, the order (off after quinn wraps the socket, on a clone kept for it), that the wrapper of one segment is optional (2.9 MiB saved once) and alone would truncate, and that no fork is needed; section 6 adds the CPU to the flood |
| 10 | Low | There was no alpha.15 tag | Since the review, alpha.15 is released (52ca2ae). "The version before" is alpha.15, and alpha.14 the one before it; main is 52ca2ae, with 5c633f9's code |
| 11 | Low, not confirmed | Quinn's queue from the endpoint to each connection is unbounded, and not in W | Left out, and said so in section 6 with what bounds it in part (the socket's buffer, the endpoint's time limit for each turn) and what does not; read, not measured |

What the review found right is kept as it was: how quinn shares a batch's buffer, GRO's 64 segments, the assembler's count and threshold, the 688 KiB bound, W's sum, K + P + G + L on one core, N on one core, every message of a device fitting a small message, connections refused before the handshake, and the measurement needing no root.
