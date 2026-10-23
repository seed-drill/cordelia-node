//! What decoding one frame costs in memory, measured with a counting
//! allocator: what the decode asks of the allocator at its peak, and what
//! it still holds when it returns (parameter-rationale.md §1).
//!
//! A message is read by the stream it arrives on, straight into its own
//! type, and each list is bounded where it is read. Read as the tagged
//! enum, serde held the whole frame as values of no type before it looked
//! at the message's name: some 32 bytes for each byte of the frame, 32 MB
//! for a frame of 1 MB that was then refused, and a list of empty texts
//! held 24 bytes for each byte of it once read.
//!
//! The bound: decoding a frame of at most MAX_MESSAGE_BYTES on any stream
//! asks at most three times that at its peak, and holds at most twice
//! that when it returns: a message's texts and bytes are what the frame
//! holds, and its lists are bounded. A frame that is refused holds
//! nothing.
//!
//! Counted are the bytes asked for: an allocator rounds each up, so
//! that many small texts cost more than this counts.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use cordelia_core::protocol::{
    DEFAULT_SYNC_LIMIT, ENTRY_PAGE_MAX_ENTRIES, ITEM_AUTHOR_BYTES, ITEM_HASH_BYTES,
    ITEM_SIGNATURE_BYTES, ITEM_SLOT_BYTES, MAX_CHANNEL_ID_LEN, MAX_ENTRY_WIRE_BYTES,
    MAX_HANDSHAKE_ROLES, MAX_ITEM_ID_LEN, MAX_ITEM_TYPE_LEN, MAX_LISTED_CHANNEL_IDS,
    MAX_MESSAGE_BYTES, MAX_TIMESTAMP_LEN, SHORTEST_CHANNEL_ID_LEN,
};
use cordelia_network::codec::{decode_message, encode_message};
use cordelia_network::messages::{
    EntryPulled, Item, ItemHeader, Protocol, PushPayload, SyncChannelListResponse, SyncResponse,
    WireMessage,
};

// ── A counting allocator, by thread ─────────────────────────────────

struct Counting;

thread_local! {
    /// The bytes this thread holds: asked for and not given back.
    static LIVE: Cell<isize> = const { Cell::new(0) };
    /// The most it has held since the peak was last set to what it holds.
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn counted(bytes: isize) {
    let _ = LIVE.try_with(|live| {
        let now = live.get() + bytes;
        live.set(now);
        let _ = PEAK.try_with(|peak| {
            if now > peak.get() {
                peak.set(now);
            }
        });
    });
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let at = unsafe { System.alloc(layout) };
        if !at.is_null() {
            counted(layout.size() as isize);
        }
        at
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let at = unsafe { System.alloc_zeroed(layout) };
        if !at.is_null() {
            counted(layout.size() as isize);
        }
        at
    }

    unsafe fn dealloc(&self, at: *mut u8, layout: Layout) {
        unsafe { System.dealloc(at, layout) };
        counted(-(layout.size() as isize));
    }

    // Counted as the new block asked for while the old one is held, and
    // then the old one given back: a realloc may copy.
    unsafe fn realloc(&self, at: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(at, layout, size) };
        if !moved.is_null() {
            counted(size as isize);
            counted(-(layout.size() as isize));
        }
        moved
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// What `f` asked for at its peak, and what it holds when it returns,
/// over what this thread held before it.
fn measured<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
    let before = LIVE.with(Cell::get);
    PEAK.with(|peak| peak.set(before));
    let out = f();
    let held = LIVE.with(Cell::get) - before;
    let peak = PEAK.with(Cell::get) - before;
    (out, peak.max(0) as usize, held.max(0) as usize)
}

// ── CBOR, written by hand ───────────────────────────────────────────

/// The head of a CBOR item of major type `major` and argument `n`.
fn head(major: u8, n: u64) -> Vec<u8> {
    let major = major << 5;
    match n {
        0..=23 => vec![major | n as u8],
        24..=0xff => vec![major | 24, n as u8],
        0x100..=0xffff => [vec![major | 25], (n as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => [vec![major | 26], (n as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![major | 27], n.to_be_bytes().to_vec()].concat(),
    }
}

fn text(s: &str) -> Vec<u8> {
    [head(3, s.len() as u64), s.as_bytes().to_vec()].concat()
}

fn array(n: usize) -> Vec<u8> {
    head(4, n as u64)
}

fn map(n: usize) -> Vec<u8> {
    head(5, n as u64)
}

/// A message map: its name first, then `rest`, which holds `fields`
/// pairs.
fn message(name: &str, fields: usize, rest: Vec<u8>) -> Vec<u8> {
    [map(1 + fields), text("msg_type"), text(name), rest].concat()
}

/// How many elements of `each` bytes fill a frame, after `room` bytes of
/// the rest.
fn filling(each: usize, room: usize) -> usize {
    (MAX_MESSAGE_BYTES as usize - room) / each
}

/// `n` copies of `one`.
fn times(one: &[u8], n: usize) -> Vec<u8> {
    one.repeat(n)
}

const ALL: [Protocol; 13] = [
    Protocol::Handshake,
    Protocol::KeepAlive,
    Protocol::PeerSharing,
    Protocol::ChannelAnnounce,
    Protocol::ItemSync,
    Protocol::ItemPush,
    Protocol::PskExchange,
    Protocol::Pairing,
    Protocol::EntryShow,
    Protocol::ChannelProve,
    Protocol::EntryPull,
    Protocol::EntryPush,
    Protocol::RelayEntries,
];

/// A frame, the streams it is decoded on, and whether it is read there.
struct Frame {
    what: &'static str,
    on: Vec<Protocol>,
    bytes: Vec<u8>,
    read: bool,
}

/// Frames that a peer chose, each of nearly 1 MB, as cheap on the wire
/// and as dear in memory as each can be made.
fn hostile_frames() -> Vec<Frame> {
    let n = filling(1, 16);
    let mut frames = vec![
        Frame {
            what: "an array of about 1M zeros",
            on: ALL.to_vec(),
            bytes: [array(n), times(&[0x00], n)].concat(),
            read: false,
        },
        Frame {
            what: "a map of about 512K pairs of zeros, no name",
            on: ALL.to_vec(),
            bytes: [map(n / 2), times(&[0x00, 0x00], n / 2)].concat(),
            read: false,
        },
        Frame {
            what: "a map with its name after about 512K pairs",
            on: ALL.to_vec(),
            bytes: [
                map(n / 2 - 8 + 1),
                times(&[0x00, 0x00], n / 2 - 8),
                text("msg_type"),
                text("Ping"),
            ]
            .concat(),
            read: false,
        },
    ];
    // The lists of texts, each with about 1M empty texts.
    let empties = filling(1, 64);
    // Each is refused, but for the channel IDs a relay lists, which are
    // read: the first of them kept and the rest passed over.
    for (what, name, field, on, read) in [
        (
            "a fetch of about 1M empty IDs",
            "FetchRequest",
            "item_ids",
            Protocol::ItemSync,
            false,
        ),
        (
            "a list of about 1M empty channel IDs",
            "SyncChannelListResponse",
            "channel_ids",
            Protocol::ItemSync,
            true,
        ),
        (
            "a handshake of about 1M empty roles",
            "HandshakePropose",
            "roles",
            Protocol::Handshake,
            false,
        ),
    ] {
        frames.push(Frame {
            what,
            on: vec![on],
            bytes: message(
                name,
                1,
                [text(field), array(empties), times(&[0x60], empties)].concat(),
            ),
            read,
        });
    }
    // About 500K channel IDs of one letter, as a relay may list them.
    let letters = filling(2, 64);
    frames.push(Frame {
        what: "a list of about 500K one-letter channel IDs",
        on: vec![Protocol::ItemSync],
        bytes: message(
            "SyncChannelListResponse",
            1,
            [
                text("channel_ids"),
                array(letters),
                times(&[0x61, 0x63], letters),
            ]
            .concat(),
        ),
        read: true,
    });
    // Peers written as arrays, five bytes each: [h'', [], 0, false].
    let peers = filling(5, 64);
    frames.push(Frame {
        what: "about 200K peers written as arrays",
        on: vec![Protocol::PeerSharing],
        bytes: message(
            "PeerShareResponse",
            1,
            [
                text("peers"),
                array(peers),
                times(&[0x84, 0x40, 0x80, 0x00, 0xf4], peers),
            ]
            .concat(),
        ),
        read: false,
    });
    // One peer with about 1M empty addresses.
    let addrs = filling(1, 128);
    let peer = [
        map(4),
        text("node_id"),
        head(2, 32),
        vec![0x11; 32],
        text("addrs"),
        array(addrs),
        times(&[0x60], addrs),
        text("last_seen"),
        vec![0x00],
        text("exclude"),
        vec![0xf4],
    ]
    .concat();
    frames.push(Frame {
        what: "one peer with about 1M empty addresses",
        on: vec![Protocol::PeerSharing],
        bytes: message(
            "PeerShareResponse",
            1,
            [text("peers"), array(1), peer].concat(),
        ),
        read: false,
    });
    // At each bound, of the smallest elements: read, and bounded.
    for (what, name, field, most, on) in [
        (
            "the most roles, empty",
            "HandshakeAccept",
            "roles",
            MAX_HANDSHAKE_ROLES as usize,
            Protocol::Handshake,
        ),
        (
            "the most channel IDs, empty",
            "SyncChannelListResponse",
            "channel_ids",
            MAX_LISTED_CHANNEL_IDS as usize,
            Protocol::ItemSync,
        ),
    ] {
        let mut rest = [text(field), array(most), times(&[0x60], most)].concat();
        let mut fields = 1;
        if name == "HandshakeAccept" {
            // The other fields it must have.
            for (key, value) in [
                ("version", vec![0x01]),
                ("node_id", [head(2, 32), vec![0x11; 32]].concat()),
                ("timestamp", vec![0x00]),
                ("channel_digest", [head(2, 32), vec![0x22; 32]].concat()),
                ("channel_count", vec![0x00]),
                ("reject_reason", vec![0xf6]),
            ] {
                rest.extend(text(key));
                rest.extend(value);
                fields += 1;
            }
        }
        frames.push(Frame {
            what,
            on: vec![on],
            bytes: message(name, fields, rest),
            read: true,
        });
    }
    // As many channel IDs as a frame holds, of the shortest a node makes:
    // fewer than the bound.
    let id = "g".repeat(SHORTEST_CHANNEL_ID_LEN as usize);
    let most = filling(SHORTEST_CHANNEL_ID_LEN as usize + 2, 64);
    assert!(most < MAX_LISTED_CHANNEL_IDS as usize);
    let ids = WireMessage::SyncChannelListResponse(SyncChannelListResponse {
        channel_ids: vec![id; most],
    });
    frames.push(Frame {
        what: "the most channel IDs, each of the shortest length",
        on: vec![Protocol::ItemSync],
        bytes: encode_message(&ids).unwrap(),
        read: true,
    });
    // A page of the most headers, each with a signature as long as fills
    // the frame: refused at the first, where its signature is read.
    let at_bounds = header_at_bounds();
    let room = MAX_MESSAGE_BYTES as usize / DEFAULT_SYNC_LIMIT as usize
        - encode_message(&page_of(vec![at_bounds.clone()]))
            .unwrap()
            .len();
    let long = ItemHeader {
        signature: vec![0x5a; ITEM_SIGNATURE_BYTES + room],
        ..at_bounds
    };
    frames.push(Frame {
        what: "a page of 100 headers with long signatures",
        on: vec![Protocol::ItemSync],
        bytes: encode_message(&page_of(vec![long; DEFAULT_SYNC_LIMIT as usize])).unwrap(),
        read: false,
    });
    frames
}

/// A header with each text at its bound, and its bytes of their size.
fn header_at_bounds() -> ItemHeader {
    ItemHeader {
        item_id: "i".repeat(MAX_ITEM_ID_LEN),
        channel_id: "c".repeat(MAX_CHANNEL_ID_LEN),
        item_type: "t".repeat(MAX_ITEM_TYPE_LEN),
        content_hash: vec![0xa1; ITEM_HASH_BYTES],
        author_id: vec![0xa2; ITEM_AUTHOR_BYTES],
        signature: vec![0xa3; ITEM_SIGNATURE_BYTES],
        key_version: u32::MAX,
        published_at: "p".repeat(MAX_TIMESTAMP_LEN),
        is_tombstone: false,
        parent_id: Some("q".repeat(MAX_ITEM_ID_LEN)),
        slot: Some(vec![0xa4; ITEM_SLOT_BYTES]),
        rev: Some(u64::MAX),
    }
}

/// A page of `headers`.
fn page_of(headers: Vec<ItemHeader>) -> WireMessage {
    WireMessage::SyncResponse(SyncResponse {
        items: headers,
        has_more: true,
        last_seq: Some(u64::MAX),
    })
}

/// What a page of the most headers, each at its bounds, may hold once
/// read: each header's fields, and its place in the list
/// (`size_of::<ItemHeader>()`), with the list grown by doubling.
const PAGE_OF_HEADERS_MOST: usize = DEFAULT_SYNC_LIMIT as usize
    * (2 * size_of::<ItemHeader>()
        + 2 * MAX_ITEM_ID_LEN
        + MAX_CHANNEL_ID_LEN
        + MAX_ITEM_TYPE_LEN
        + MAX_TIMESTAMP_LEN
        + ITEM_HASH_BYTES
        + ITEM_AUTHOR_BYTES
        + ITEM_SIGNATURE_BYTES
        + ITEM_SLOT_BYTES);

/// The largest frames that nodes send: read, and held.
fn largest_frames() -> Vec<Frame> {
    let item = Item {
        item_id: "ci_x".into(),
        channel_id: "grp_00000000-0000-4000-8000-000000000000".into(),
        item_type: "memory".into(),
        encrypted_blob: vec![0xb0; MAX_MESSAGE_BYTES as usize - 2048],
        content_hash: vec![0xb1; 32],
        content_length: 0,
        author_id: vec![0xb2; 32],
        signature: vec![0xb3; 64],
        key_version: 1,
        published_at: "2026-10-22T10:00:01Z".into(),
        is_tombstone: false,
        parent_id: None,
        slot: None,
        rev: None,
    };
    let page = EntryPulled {
        entries: vec![
            serde_bytes::ByteBuf::from(vec![0x5e; MAX_ENTRY_WIRE_BYTES]);
            (MAX_MESSAGE_BYTES as usize / (MAX_ENTRY_WIRE_BYTES + 8))
                .min(ENTRY_PAGE_MAX_ENTRIES as usize)
        ],
        next: 7,
        mark: [1; 8],
    };
    vec![
        Frame {
            what: "a push of one item of nearly 1 MB",
            on: vec![Protocol::ItemPush],
            bytes: encode_message(&WireMessage::PushPayload(PushPayload { items: vec![item] }))
                .unwrap(),
            read: true,
        },
        Frame {
            what: "a page of 100 headers, each at its bounds",
            on: vec![Protocol::ItemSync],
            bytes: encode_message(&page_of(vec![
                header_at_bounds();
                DEFAULT_SYNC_LIMIT as usize
            ]))
            .unwrap(),
            read: true,
        },
        Frame {
            what: "a page of entries of the largest size",
            on: vec![Protocol::EntryPull, Protocol::RelayEntries],
            bytes: encode_message(&WireMessage::EntryPulled(page)).unwrap(),
            read: true,
        },
    ]
}

/// The bound, for a frame of at most MAX_MESSAGE_BYTES: at its peak.
const PEAK_MOST: usize = 3 * MAX_MESSAGE_BYTES as usize;
/// And held once the message is read: its texts and bytes, each in room
/// that grows by doubling, so at most twice what they are on the wire,
/// and 64 KB for the room of its lists.
const HELD_MOST: usize = 2 * MAX_MESSAGE_BYTES as usize + 64 * 1024;
/// What a frame that is refused still holds: nothing but its error.
const REFUSED_HOLDS_MOST: usize = 1024;
/// What the longest list of the smallest elements may ask for, before it
/// is refused or passes over the rest: MAX_LISTED_CHANNEL_IDS empty texts, 24 bytes each, in a
/// list that grows by doubling.
const LIST_MOST: usize = 2 * MAX_LISTED_CHANNEL_IDS as usize * size_of::<String>();

/// Decoding any frame on any stream stays within the bound: the frames a
/// peer chose to cost the most, and the largest that nodes send.
#[test]
fn decoding_a_frame_costs_at_most_three_times_its_bytes() {
    // Each frame on each of its streams, measured; then each is held to
    // the bound, so that the whole table is shown first.
    let mut rows = Vec::new();
    for frame in hostile_frames().into_iter().chain(largest_frames()) {
        let size = frame.bytes.len();
        assert!(size <= MAX_MESSAGE_BYTES as usize, "{}: {size}", frame.what);
        for &protocol in &frame.on {
            let (read, peak, held) = measured(|| decode_message(protocol, &frame.bytes));
            println!(
                "{:<52} {:>15} {:>9} bytes: peak {:>9}, held {:>9}{}",
                frame.what,
                format!("{protocol:?}"),
                size,
                peak,
                held,
                if read.is_ok() { "" } else { " (refused)" }
            );
            rows.push((frame.what, protocol, frame.read, read.is_ok(), peak, held));
        }
    }
    let worst = rows
        .iter()
        .fold((0, 0), |(p, h), row| (p.max(row.4), h.max(row.5)));
    println!("worst: peak {}, held {}", worst.0, worst.1);
    for (what, protocol, should, read, peak, held) in rows {
        assert_eq!(read, should, "{what} on {protocol:?}");
        assert!(
            peak <= PEAK_MOST,
            "{what} on {protocol:?}: {peak} bytes at the peak"
        );
        assert!(
            held <= HELD_MOST,
            "{what} on {protocol:?}: {held} bytes held"
        );
        if !read {
            assert!(
                held <= REFUSED_HOLDS_MOST,
                "{what} on {protocol:?}: refused, and holds {held}"
            );
        }
    }
}

/// The frames that are refused: a frame of no message, or of its name
/// after its fields, a list longer than its bound, and peers written as
/// arrays. None asks for more than its longest list may hold, and none
/// holds anything once it is refused.
#[test]
fn a_frame_that_is_refused_is_refused_before_it_is_held() {
    for frame in hostile_frames().into_iter().filter(|frame| !frame.read) {
        for &protocol in &frame.on {
            let (read, peak, held) = measured(|| decode_message(protocol, &frame.bytes));
            assert!(read.is_err(), "{} on {protocol:?}", frame.what);
            assert!(
                peak <= LIST_MOST,
                "{} on {protocol:?}: {peak} bytes at the peak, for a frame of {}",
                frame.what,
                frame.bytes.len()
            );
            assert!(held <= REFUSED_HOLDS_MOST, "{} on {protocol:?}", frame.what);
        }
    }
}

/// The channel IDs a relay lists are what others sent it, of 1 to 96 bytes
/// each, so an honest relay can list more of them than their bound in one
/// frame. Such a list is read: the first MAX_LISTED_CHANNEL_IDS are kept,
/// in their order, and the rest passed over, and what is held is no more
/// than the bound's list and the IDs it keeps.
#[test]
fn a_list_of_short_channel_ids_past_its_bound_keeps_the_bound() {
    let most = MAX_LISTED_CHANNEL_IDS as usize;
    // As many IDs `c0`, `c1`, ... as fit in one frame: far more than the
    // bound.
    let mut ids: Vec<String> = Vec::new();
    let mut size = 64;
    while size + 2 + format!("c{}", ids.len()).len() <= MAX_MESSAGE_BYTES as usize {
        let id = format!("c{}", ids.len());
        size += id.len() + 2;
        ids.push(id);
    }
    assert!(ids.len() > 4 * most, "{}", ids.len());
    let bytes = encode_message(&WireMessage::SyncChannelListResponse(
        SyncChannelListResponse {
            channel_ids: ids.clone(),
        },
    ))
    .unwrap();
    assert!(bytes.len() <= MAX_MESSAGE_BYTES as usize, "{}", bytes.len());

    let (read, peak, held) = measured(|| decode_message(Protocol::ItemSync, &bytes));
    let Ok(WireMessage::SyncChannelListResponse(read)) = read else {
        panic!("a list of {} short channel IDs was not read", ids.len());
    };
    assert_eq!(read.channel_ids.len(), most);
    assert_eq!(read.channel_ids[..], ids[..most]);
    // What the bound promises: its list, which grows by doubling, and the
    // texts of the IDs it keeps.
    let kept: usize = ids[..most].iter().map(String::len).sum();
    println!(
        "{} IDs in {} bytes: kept {most}, peak {peak}, held {held}",
        ids.len(),
        bytes.len()
    );
    assert!(held <= LIST_MOST + kept, "{held} bytes held");
    assert!(peak <= PEAK_MOST, "{peak} bytes at the peak");

    // At the bound and one below, every ID is kept.
    for n in [most - 1, most] {
        let bytes = encode_message(&WireMessage::SyncChannelListResponse(
            SyncChannelListResponse {
                channel_ids: ids[..n].to_vec(),
            },
        ))
        .unwrap();
        let Ok(WireMessage::SyncChannelListResponse(read)) =
            decode_message(Protocol::ItemSync, &bytes)
        else {
            panic!("{n}");
        };
        assert_eq!(read.channel_ids[..], ids[..n]);
    }
}

/// A page of headers is held to what its bounds allow: the most headers,
/// each field at its bound, are read and hold no more than
/// PAGE_OF_HEADERS_MOST, 93,600 bytes; and so do as many, each with a type
/// of 4,000 bytes, which are refused one by one and read as the mark of
/// one over its size. A page of as many with signatures that fill the
/// frame is refused at its first signature, and asks for next to nothing.
/// Before the bounds it was read, and held 1.7 MB.
#[test]
fn a_page_of_headers_holds_no_more_than_its_bounds() {
    let at_bounds = encode_message(&page_of(vec![
        header_at_bounds();
        DEFAULT_SYNC_LIMIT as usize
    ]))
    .unwrap();
    let (read, peak, held) = measured(|| decode_message(Protocol::ItemSync, &at_bounds));
    println!(
        "a page at its bounds, {} bytes: peak {peak}, held {held}; the bound {PAGE_OF_HEADERS_MOST}",
        at_bounds.len()
    );
    assert!(read.is_ok(), "{read:?}");
    assert!(held <= PAGE_OF_HEADERS_MOST, "{held} bytes held");
    assert!(peak <= PAGE_OF_HEADERS_MOST, "{peak} bytes at the peak");

    let long_types = encode_message(&page_of(vec![
        ItemHeader {
            item_type: "t".repeat(4_000),
            ..header_at_bounds()
        };
        DEFAULT_SYNC_LIMIT as usize
    ]))
    .unwrap();
    let (read, peak, held) = measured(|| decode_message(Protocol::ItemSync, &long_types));
    println!(
        "a page of long types, {} bytes: peak {peak}, held {held}",
        long_types.len()
    );
    let Ok(WireMessage::SyncResponse(page)) = read else {
        panic!("a page of long types was not read: {read:?}");
    };
    assert!(
        page.items
            .iter()
            .all(|h| h.item_type.len() == MAX_ITEM_TYPE_LEN + 1),
        "a long type was kept"
    );
    assert!(held <= PAGE_OF_HEADERS_MOST, "{held} bytes held");
    assert!(peak <= PAGE_OF_HEADERS_MOST, "{peak} bytes at the peak");

    let long = hostile_frames()
        .into_iter()
        .find(|frame| frame.what == "a page of 100 headers with long signatures")
        .unwrap();
    assert!(long.bytes.len() > 1_000_000, "{}", long.bytes.len());
    let (read, peak, held) = measured(|| decode_message(Protocol::ItemSync, &long.bytes));
    println!(
        "a page of long signatures, {} bytes: peak {peak}, held {held}",
        long.bytes.len()
    );
    assert!(read.is_err(), "a page of long signatures was read");
    // What the first header asks for before its signature is read.
    assert!(peak <= 4 * 1024, "{peak} bytes at the peak");
    assert!(held <= REFUSED_HOLDS_MOST, "{held} bytes held");
}
