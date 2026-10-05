//! Wire message types for all 8 mini-protocols.
//!
//! Each message is CBOR-encoded on the wire. The protocol byte (§3.3)
//! identifies which mini-protocol a QUIC stream carries; message framing
//! (4-byte big-endian length prefix) is handled by the codec module.
//!
//! Spec: seed-drill/specs/network-protocol.md §3–§4
//!
//! Beside the eight are the four streams of entries of a channel from its
//! secret (decision 2026-10-04 §2.4), with protocol bytes of their own:
//! show, prove, pull and push. A peer that does not know them refuses the
//! stream, and nothing of the eight is changed by them. A show has a short
//! form, on the stream of a show: an entry's channel, slot, author,
//! revision and ID, for a connection that last showed that very entry
//! whole in that slot. Its answer never carries an entry.
//!
//! And a fifth, between relays that their operator lists together (§2.4
//! item 6): on it a relay tells which channels it holds, hands a channel
//! without the proof, and passes on what it took, each with how long it
//! has held the channel and when the channel was last used.

use cordelia_core::protocol::{
    CHANNEL_MARK_BYTES, ENTRY_PAGE_MAX_ENTRIES, PROTOCOL_CHANNEL_PROVE, PROTOCOL_ENTRY_PULL,
    PROTOCOL_ENTRY_PUSH, PROTOCOL_ENTRY_SHOW, PROTOCOL_RELAY_ENTRIES, RELAY_CHANNELS_PAGE_MAX,
};
use cordelia_storage::relay;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

// ── Protocol identifiers (§3.3) ────────────────────────────────────

/// Protocol byte written as the first byte of each QUIC stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    Handshake = 0x01,
    KeepAlive = 0x02,
    PeerSharing = 0x03,
    ChannelAnnounce = 0x04,
    ItemSync = 0x05,
    ItemPush = 0x06,
    PskExchange = 0x07,
    Pairing = 0x08,
    /// A connection shows an entry, and is answered with what the
    /// receiver holds (decision 2026-10-04 §2.4 item 5).
    EntryShow = PROTOCOL_ENTRY_SHOW,
    /// A connection proves that it holds a channel's key (decision
    /// 2026-10-04 §2.4 items 3 and 4).
    ChannelProve = PROTOCOL_CHANNEL_PROVE,
    /// A connection asks for a page of a channel it has proved (decision
    /// 2026-10-04 §2.4 item 3).
    EntryPull = PROTOCOL_ENTRY_PULL,
    /// A connection sends entries to be stored (decision 2026-10-04 §2.4
    /// items 1 and 2).
    EntryPush = PROTOCOL_ENTRY_PUSH,
    /// A relay asks a relay it works with which channels it holds, or for
    /// a page of one, or passes entries on to it (decision 2026-10-04 §2.4
    /// item 6). For relays that the operator lists by key, and refused
    /// for anyone else.
    RelayEntries = PROTOCOL_RELAY_ENTRIES,
}

impl Protocol {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Handshake),
            0x02 => Some(Self::KeepAlive),
            0x03 => Some(Self::PeerSharing),
            0x04 => Some(Self::ChannelAnnounce),
            0x05 => Some(Self::ItemSync),
            0x06 => Some(Self::ItemPush),
            0x07 => Some(Self::PskExchange),
            0x08 => Some(Self::Pairing),
            PROTOCOL_ENTRY_SHOW => Some(Self::EntryShow),
            PROTOCOL_CHANNEL_PROVE => Some(Self::ChannelProve),
            PROTOCOL_ENTRY_PULL => Some(Self::EntryPull),
            PROTOCOL_ENTRY_PUSH => Some(Self::EntryPush),
            PROTOCOL_RELAY_ENTRIES => Some(Self::RelayEntries),
            _ => None,
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

// ── Handshake (0x01, §4.1) ─────────────────────────────────────────

/// Magic number for handshake validation (sourced from protocol.rs).
pub use cordelia_core::protocol::HANDSHAKE_MAGIC;

/// Current protocol version (sourced from protocol.rs).
pub use cordelia_core::protocol::PROTOCOL_VERSION;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakePropose {
    pub magic: u32,
    pub version_min: u16,
    pub version_max: u16,
    #[serde(with = "serde_bytes")]
    pub node_id: Vec<u8>, // 32 bytes
    pub timestamp: u64,
    #[serde(with = "serde_bytes")]
    pub channel_digest: Vec<u8>, // 32 bytes
    pub channel_count: u16,
    pub roles: Vec<String>,
    /// P2P listening port, so peers know where to connect back.
    #[serde(default)]
    pub p2p_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeAccept {
    pub version: u16,
    #[serde(with = "serde_bytes")]
    pub node_id: Vec<u8>, // 32 bytes
    pub timestamp: u64,
    #[serde(with = "serde_bytes")]
    pub channel_digest: Vec<u8>, // 32 bytes
    pub channel_count: u16,
    pub roles: Vec<String>,
    pub reject_reason: Option<String>,
    /// P2P listening port, so peers know where to connect back.
    #[serde(default)]
    pub p2p_port: u16,
}

// ── Keep-Alive (0x02, §4.2) ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ping {
    pub seq: u64,
    pub sent_at_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pong {
    pub seq: u64,
    pub sent_at_ns: u64,
    pub recv_at_ns: u64,
}

// ── Peer-Sharing (0x03, §4.3) ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerShareRequest {
    pub max_peers: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerShareResponse {
    pub peers: Vec<PeerAddress>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAddress {
    #[serde(with = "serde_bytes")]
    pub node_id: Vec<u8>, // 32 bytes
    pub addrs: Vec<String>, // SocketAddr as string for CBOR portability
    pub last_seen: u64,
    pub exclude: bool,
}

// ── Channel-Announce (0x04, §4.4) ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelJoined {
    pub channel_id: String,
    pub descriptor: ChannelDescriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelLeft {
    pub channel_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelStateHash {
    #[serde(with = "serde_bytes")]
    pub digest: Vec<u8>, // 32 bytes
    pub count: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelListRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelListResponse {
    pub channels: Vec<ChannelDescriptor>,
}

/// Channel descriptor (§4.4.6). Signed by creator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelDescriptor {
    pub channel_id: String,
    pub channel_name: Option<String>,
    pub access: String,
    pub mode: String,
    pub key_version: u32,
    #[serde(with = "serde_bytes")]
    pub psk_hash: Vec<u8>, // 32 bytes
    #[serde(with = "serde_bytes")]
    pub creator_id: Vec<u8>, // 32 bytes
    pub created_at: String,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>, // 64 bytes
}

// ── Item-Sync (0x05, §4.5) ─────────────────────────────────────────

/// Phase 0: relay channel discovery (§4.5). "What channels do you have?"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncChannelListRequest {}

/// Phase 0 response: channel IDs the responder has stored items for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncChannelListResponse {
    pub channel_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub channel_id: String,
    pub since: Option<String>,
    pub limit: u32,
    /// Page by the responder's arrival sequence instead of `since`: return
    /// items that arrived after this value, in arrival order (§4.4a).
    /// Absent from older peers, which get the `since` behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_seq: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub items: Vec<ItemHeader>,
    pub has_more: bool,
    /// With `after_seq` paging: the responder's sequence number of the last
    /// header returned, to send as the next request's `after_seq`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seq: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemHeader {
    pub item_id: String,
    pub channel_id: String,
    pub item_type: String,
    #[serde(with = "serde_bytes")]
    pub content_hash: Vec<u8>, // 32 bytes
    #[serde(with = "serde_bytes")]
    pub author_id: Vec<u8>, // 32 bytes
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>, // 64 bytes
    pub key_version: u32,
    pub published_at: String,
    pub is_tombstone: bool,
    pub parent_id: Option<String>,
    /// Replaceable-item slot (32 bytes) and revision (decision 2026-09-30
    /// §4.3). Both present or both absent; omitted from the encoding when
    /// absent, so ordinary items encode exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub slot: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchRequest {
    pub item_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchResponse {
    pub items: Vec<Item>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub item_id: String,
    pub channel_id: String,
    pub item_type: String,
    #[serde(with = "serde_bytes")]
    pub encrypted_blob: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub content_hash: Vec<u8>, // 32 bytes
    pub content_length: u32,
    #[serde(with = "serde_bytes")]
    pub author_id: Vec<u8>, // 32 bytes
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>, // 64 bytes
    pub key_version: u32,
    pub published_at: String,
    pub is_tombstone: bool,
    pub parent_id: Option<String>,
    /// Replaceable-item slot (32 bytes) and revision (decision 2026-09-30
    /// §4.3). Both present or both absent; omitted from the encoding when
    /// absent, so ordinary items encode exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub slot: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<u64>,
}

// ── Item-Push (0x06, §4.6) ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushPayload {
    pub items: Vec<Item>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PushAck {
    pub stored: u32,
    pub dedup_dropped: u32,
    pub policy_rejected: u32,
    pub verification_failed: u32,
    /// The items of this push that the receiver neither stored nor already
    /// held, and why. A sender keeps those and offers them again; without
    /// the list it could not tell which they were. Omitted when empty, so
    /// an answer with nothing refused is unchanged on the wire. A receiver
    /// older than 0.2.0-alpha.4 never sends it and only counts them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused: Vec<Refusal>,
}

/// One item a receiver refused to store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub item_id: String,
    /// A short code for status to show: [`REFUSED_INVALID`],
    /// [`REFUSED_STORAGE`], [`REFUSED_TOO_LARGE`], [`REFUSED_NOT_MEMBER`] or
    /// [`REFUSED_FULL`].
    pub why: String,
}

/// The item is not valid: its hash, its signature or its shape.
pub const REFUSED_INVALID: &str = "invalid";
/// The receiver could not store it (its disk, or its database).
pub const REFUSED_STORAGE: &str = "storage";
/// The item is over the size every entry must fit in.
pub const REFUSED_TOO_LARGE: &str = "too_large";
/// The receiver is a device, and the item is not one a member of one of
/// its channels wrote.
pub const REFUSED_NOT_MEMBER: &str = "not_member";
/// The receiver is a relay with no room: it is at its storage cap and does
/// not hold this channel, or the channel has reached what one channel may
/// hold, or the sender's address has made it hold enough new channels for
/// now.
pub const REFUSED_FULL: &str = "full";

// ── PSK-Exchange (0x07, §4.7) ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PskRequest {
    pub channel_id: String,
    #[serde(with = "serde_bytes")]
    pub subscriber_xpk: Vec<u8>, // 32 bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PskResponse {
    pub status: String,
    pub reason: Option<String>,
    #[serde(with = "serde_bytes")]
    pub ecies_envelope: Option<Vec<u8>>, // 92 bytes when present
    pub key_version: Option<u32>,
}

// ── Pairing (0x08, §4.8) ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRequest {
    #[serde(with = "serde_bytes")]
    pub node_id: Vec<u8>, // 32 bytes
    pub pairing_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingResponse {
    pub status: String,
    pub reason: Option<String>,
}

// ── Entries of a channel from its secret (0x10 to 0x13) ─────────────
//
// Decision 2026-10-04 §2.4. An entry travels as its bytes on the wire
// (`cordelia_crypto::wire`), which whoever receives it reads strictly and
// checks. A channel's ID is 32 bytes and a proof 64: a message that holds
// one of another length is not read. A push and a page hold at most a
// page's worth of entries, and the answer to a push says at most as many
// things: one that holds more is not read.

/// Read a list of entries, each as its bytes on the wire, that holds at
/// most a page's worth of them (ENTRY_PAGE_MAX_ENTRIES). A longer list is
/// refused where its first entry too many is met. Whoever receives a
/// message checks two signatures for each entry in it: one message makes
/// it do so for no more entries than a page holds.
fn at_most_a_page<'de, D>(deserializer: D) -> Result<Vec<ByteBuf>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct AtMostAPage;

    impl<'de> serde::de::Visitor<'de> for AtMostAPage {
        type Value = Vec<ByteBuf>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "at most {ENTRY_PAGE_MAX_ENTRIES} entries")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut entries = Vec::new();
            while let Some(entry) = seq.next_element::<ByteBuf>()? {
                if entries.len() >= ENTRY_PAGE_MAX_ENTRIES as usize {
                    return Err(serde::de::Error::invalid_length(entries.len() + 1, &self));
                }
                entries.push(entry);
            }
            Ok(entries)
        }
    }

    deserializer.deserialize_seq(AtMostAPage)
}

/// Why an entry was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryRefused {
    /// It is not signed as it must be: the bytes are not an entry's, or a
    /// signature does not hold.
    NotSigned,
    /// The receiver has no room for it: with it the receiver would hold
    /// more than its cap, or the entry's channel more than one may.
    NoRoom,
    /// The sender is over a limit: its address has made the receiver take
    /// as many new channels as one address may for now.
    OverLimit,
}

/// Entry-Show (0x10): a connection shows an entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryShow {
    /// The entry, as its bytes on the wire.
    #[serde(with = "serde_bytes")]
    pub entry: Vec<u8>,
}

/// Entry-Show (0x10), in short: a connection shows an entry by its
/// channel, slot, author, revision and ID alone (decision 2026-10-04 §2.4
/// item 5).
///
/// It is only ever of the entry that the connection last showed whole in
/// that slot, with both signatures. A short show of anything else, a slot
/// that the receiver does not remember included, is answered "show it
/// whole" without a look at what the receiver holds: so the short form
/// tells nothing, and hands nothing, to anyone who has not shown that very
/// entry whole. Where it is of the entry remembered, the receiver looks,
/// and answers that it holds that entry; or "show it whole", where it
/// holds none or an earlier one; or, where it holds another at that
/// revision or a later one, that one's revision and ID and no more. The
/// answer to a short show never carries an entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryShowShort {
    /// The channel's ID.
    #[serde(with = "serde_bytes")]
    pub channel: [u8; 32],
    /// The key that signed the entry.
    #[serde(with = "serde_bytes")]
    pub author: [u8; 32],
    /// The entry's slot.
    #[serde(with = "serde_bytes")]
    pub slot: [u8; 32],
    /// The entry's revision.
    pub rev: u64,
    /// The entry's ID: SHA-256 of what is signed of it, which holds the
    /// hash of its content (`cordelia_crypto::entry::Entry::id`).
    #[serde(with = "serde_bytes")]
    pub id: [u8; 32],
}

/// The answer to an entry shown (decision 2026-10-04 §2.4 item 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryShown {
    pub answer: ShowAnswer,
}

/// What a receiver says of an entry it was shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShowAnswer {
    /// It holds that very entry.
    Held,
    /// It held none from that author in that slot, or an earlier one, and
    /// took this one.
    Taken,
    /// It holds another entry from that author in that slot, at that
    /// revision or a later one: here it is, as its bytes on the wire.
    Another(#[serde(with = "serde_bytes")] Vec<u8>),
    /// It would have taken the entry, and did not.
    Refused(EntryRefused),
    /// The entry was shown in short, and is to be shown whole: it is not
    /// the entry that the connection last showed whole in that slot, or
    /// the receiver holds none from that author there, or an earlier one.
    Whole,
    /// The entry was shown in short, and the receiver holds another from
    /// that author in that slot, at that revision or a later one: that
    /// one's revision and ID, and no more.
    Other {
        rev: u64,
        #[serde(with = "serde_bytes")]
        id: [u8; 32],
    },
}

/// Channel-Prove (0x11): a connection proves that it holds a channel's
/// key (decision 2026-10-04 §2.4 item 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelProve {
    /// The channel's ID.
    #[serde(with = "serde_bytes")]
    pub channel: [u8; 32],
    /// The signature of the channel's signing key over the value that
    /// both ends export from this connection's TLS session, the sender's
    /// node key, and the channel's ID (`cordelia_crypto::proof`). The
    /// sender's key is not sent: the receiver knows it from the
    /// connection.
    #[serde(with = "serde_bytes")]
    pub proof: [u8; 64],
}

/// The answer to a proof: yes or no (decision 2026-10-04 §2.4 item 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelProved {
    /// Yes: the proof holds, and the receiver holds the channel. No says
    /// neither which of the two it was that failed.
    pub proved: bool,
}

/// Entry-Pull (0x12): a connection asks for a page of a channel whose key
/// it has proved on this connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPull {
    /// The channel's ID.
    #[serde(with = "serde_bytes")]
    pub channel: [u8; 32],
    /// The mark of the holding that `after` is a place in, as the
    /// receiver last said it: all zeros where the sender has no place in
    /// the channel yet. A receiver that drops a channel and takes it
    /// again counts its places from the start, under another mark. Where
    /// this is not the mark of the holding it has now, it hands the
    /// channel from the start, whatever `after` says.
    #[serde(with = "serde_bytes")]
    pub mark: [u8; CHANNEL_MARK_BYTES],
    /// The place after which the page starts, in the order in which the
    /// receiver stored this channel's entries: a count of the channel's
    /// own, in the holding that `mark` names. 0 is before the first.
    pub after: u64,
    /// The most entries to hand.
    pub limit: u32,
}

/// A page of a channel's entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPulled {
    /// The entries, each as its bytes on the wire, in the order the
    /// sender stored them. At most ENTRY_PAGE_MAX_ENTRIES: a page that
    /// holds more is not read.
    #[serde(deserialize_with = "at_most_a_page")]
    pub entries: Vec<ByteBuf>,
    /// The place to ask after next, in the channel's own order: that of
    /// the last entry here, or the place that the page began after where
    /// there is none.
    pub next: u64,
    /// The mark of the holding that `next` is a place in, to ask with
    /// next. Where nothing of the channel is handed for want of a proof,
    /// or because it is not held, it is the mark that was asked with.
    #[serde(with = "serde_bytes")]
    pub mark: [u8; CHANNEL_MARK_BYTES],
}

/// Entry-Push (0x13): entries to be stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPush {
    /// The entries, each as its bytes on the wire. At most a page's worth
    /// of them, ENTRY_PAGE_MAX_ENTRIES: a push that holds more is not
    /// read, and none of it is stored.
    #[serde(deserialize_with = "at_most_a_page")]
    pub entries: Vec<ByteBuf>,
}

/// The answer to a push: what became of each entry, in the order they
/// were sent. An answer that does not say one thing for each entry says
/// nothing of any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPushed {
    /// At most one for each entry that a push may hold,
    /// ENTRY_PAGE_MAX_ENTRIES: an answer that says more is not read.
    #[serde(deserialize_with = "at_most_a_page_of_answers")]
    pub answers: Vec<PushAnswer>,
}

/// What became of one entry that was pushed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushAnswer {
    /// It was stored.
    Stored,
    /// The receiver holds an entry at that revision from that author in
    /// that slot. It was not stored.
    Held,
    /// The receiver holds a later one from that author in that slot. It
    /// was not stored.
    Older,
    /// It was refused.
    Refused(EntryRefused),
}

// ── Between relays that work together (0x14) ────────────────────────
//
// Decision 2026-10-04 §2.4 item 6. One request on a stream, and its
// answer. A relay serves these to a peer that its operator lists by key,
// and to no other: which channels a relay holds is told to nobody else,
// and nobody else is handed a channel without the proof. Each time is in
// seconds, in UTC, by the clock of the relay that says it. A time that is
// not after 0 is no time.

/// Read a list of at most `most` things. A longer list is refused where
/// its first thing too many is met.
fn at_most<'de, D, T>(deserializer: D, most: u32, what: &'static str) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct AtMost<T> {
        most: usize,
        what: &'static str,
        of: std::marker::PhantomData<T>,
    }

    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for AtMost<T> {
        type Value = Vec<T>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "at most {} {}", self.most, self.what)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut list = Vec::new();
            while let Some(one) = seq.next_element::<T>()? {
                if list.len() >= self.most {
                    return Err(serde::de::Error::invalid_length(list.len() + 1, &self));
                }
                list.push(one);
            }
            Ok(list)
        }
    }

    deserializer.deserialize_seq(AtMost {
        most: most as usize,
        what,
        of: std::marker::PhantomData,
    })
}

/// At most what one answer tells of (RELAY_CHANNELS_PAGE_MAX).
fn at_most_a_page_of_channels<'de, D>(deserializer: D) -> Result<Vec<RelayChannel>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    at_most(deserializer, RELAY_CHANNELS_PAGE_MAX, "channels")
}

/// At most what a push may hold, one answer for each entry
/// (ENTRY_PAGE_MAX_ENTRIES).
fn at_most_a_page_of_answers<'de, D>(deserializer: D) -> Result<Vec<PushAnswer>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    at_most(deserializer, ENTRY_PAGE_MAX_ENTRIES, "answers")
}

/// At most a page's worth of entries passed on (ENTRY_PAGE_MAX_ENTRIES).
fn at_most_a_page_passed_on<'de, D>(deserializer: D) -> Result<Vec<RelayEntry>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    at_most(deserializer, ENTRY_PAGE_MAX_ENTRIES, "entries")
}

/// Relay-Entries (0x14): a relay asks which channels from their secrets
/// the receiver holds, a page at a time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayChannelsAsk {
    /// The ID after which the page starts, in the order of the channels'
    /// IDs. All zeros is before the first.
    #[serde(with = "serde_bytes")]
    pub after: [u8; 32],
    /// The most channels to tell of.
    pub limit: u32,
}

/// One page of the channels that a relay holds, in the order of their
/// IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayChannelsHeld {
    /// At most RELAY_CHANNELS_PAGE_MAX: an answer that tells of more is
    /// not read.
    #[serde(deserialize_with = "at_most_a_page_of_channels")]
    pub channels: Vec<RelayChannel>,
}

/// A channel that a relay tells a relay it works with that it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayChannel {
    /// The channel's ID.
    #[serde(with = "serde_bytes")]
    pub channel: [u8; 32],
    /// The mark of the sender's holding of it.
    #[serde(with = "serde_bytes")]
    pub mark: [u8; CHANNEL_MARK_BYTES],
    /// Since when the sender has held it.
    pub held_since: i64,
    /// When it was last used: its key proved, or an entry of it shown
    /// that a relay holds, at the sender or at a relay that told it.
    pub used_at: i64,
    /// The place of the entry that the sender stored last in this holding
    /// of it: whoever has pulled as far as this lacks nothing of it.
    pub places: u64,
}

/// Relay-Entries (0x14): a relay asks for a page of a channel. It is
/// answered with [`EntryPulled`], and needs no proof of the channel's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPull {
    /// The channel's ID.
    #[serde(with = "serde_bytes")]
    pub channel: [u8; 32],
    /// The mark of the holding that `after` is a place in, as for
    /// [`EntryPull`].
    #[serde(with = "serde_bytes")]
    pub mark: [u8; CHANNEL_MARK_BYTES],
    /// The place after which the page starts.
    pub after: u64,
    /// The most entries to hand.
    pub limit: u32,
}

/// Relay-Entries (0x14): a relay passes on entries that it took. It is
/// answered with [`EntryPushed`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPush {
    /// At most a page's worth of them, ENTRY_PAGE_MAX_ENTRIES: a message
    /// that holds more is not read, and none of it is stored.
    #[serde(deserialize_with = "at_most_a_page_passed_on")]
    pub entries: Vec<RelayEntry>,
}

/// An entry that a relay passes on, with what it says of the entry's
/// channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEntry {
    /// The entry, as its bytes on the wire.
    #[serde(with = "serde_bytes")]
    pub entry: Vec<u8>,
    /// Since when the sender has held the entry's channel.
    pub held_since: i64,
    /// When that channel was last used, as far as the sender knows.
    pub used_at: i64,
}

// What a relay did, as it is said on the wire.

impl From<&relay::Refused> for EntryRefused {
    fn from(why: &relay::Refused) -> Self {
        match why {
            relay::Refused::NotAnEntry(_) | relay::Refused::NotSigned(_) => Self::NotSigned,
            relay::Refused::NoRoom | relay::Refused::ChannelFull => Self::NoRoom,
            relay::Refused::OverAllowance => Self::OverLimit,
        }
    }
}

impl From<&relay::Shown> for ShowAnswer {
    fn from(shown: &relay::Shown) -> Self {
        match shown {
            relay::Shown::Held => Self::Held,
            relay::Shown::Taken => Self::Taken,
            relay::Shown::Another { entry, .. } => Self::Another(entry.to_wire()),
            relay::Shown::Refused(why) => Self::Refused(why.into()),
        }
    }
}

impl From<&relay::ShownShort> for ShowAnswer {
    fn from(shown: &relay::ShownShort) -> Self {
        match shown {
            relay::ShownShort::Held => Self::Held,
            relay::ShownShort::Whole => Self::Whole,
            relay::ShownShort::Other { rev, id } => Self::Other { rev: *rev, id: *id },
        }
    }
}

impl From<&relay::Taken> for PushAnswer {
    fn from(taken: &relay::Taken) -> Self {
        match taken {
            relay::Taken::Stored => Self::Stored,
            relay::Taken::AlreadyHeld => Self::Held,
            relay::Taken::OlderThanHeld => Self::Older,
            relay::Taken::Refused(why) => Self::Refused(why.into()),
        }
    }
}

impl From<&relay::Proof> for ChannelProved {
    fn from(proof: &relay::Proof) -> Self {
        Self {
            proved: proof.answer(),
        }
    }
}

impl From<&relay::Page> for EntryPulled {
    fn from(page: &relay::Page) -> Self {
        Self {
            entries: page
                .entries
                .iter()
                .map(|entry| ByteBuf::from(entry.to_wire()))
                .collect(),
            next: page.next,
            mark: page.mark,
        }
    }
}

impl From<&relay::ToldChannel> for RelayChannel {
    fn from(told: &relay::ToldChannel) -> Self {
        Self {
            channel: told.channel,
            mark: told.held.mark,
            held_since: told.held.held_since,
            used_at: told.held.used_at,
            places: told.places,
        }
    }
}

// ── Unified message envelope ───────────────────────────────────────

/// Top-level enum for dispatching any wire message by protocol.
/// Each variant maps 1:1 to a protocol's message set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg_type")]
pub enum WireMessage {
    // Handshake
    HandshakePropose(HandshakePropose),
    HandshakeAccept(HandshakeAccept),

    // Keep-Alive
    Ping(Ping),
    Pong(Pong),

    // Peer-Sharing
    PeerShareRequest(PeerShareRequest),
    PeerShareResponse(PeerShareResponse),

    // Channel-Announce
    ChannelJoined(ChannelJoined),
    ChannelLeft(ChannelLeft),
    ChannelStateHash(ChannelStateHash),
    ChannelListRequest(ChannelListRequest),
    ChannelListResponse(ChannelListResponse),

    // Item-Sync
    SyncChannelListRequest(SyncChannelListRequest),
    SyncChannelListResponse(SyncChannelListResponse),
    SyncRequest(SyncRequest),
    SyncResponse(SyncResponse),
    FetchRequest(FetchRequest),
    FetchResponse(FetchResponse),

    // Item-Push
    PushPayload(PushPayload),
    PushAck(PushAck),

    // PSK-Exchange
    PskRequest(PskRequest),
    PskResponse(PskResponse),

    // Pairing
    PairingRequest(PairingRequest),
    PairingResponse(PairingResponse),

    // Entries of a channel from its secret
    EntryShow(EntryShow),
    EntryShowShort(EntryShowShort),
    EntryShown(EntryShown),
    ChannelProve(ChannelProve),
    ChannelProved(ChannelProved),
    EntryPull(EntryPull),
    EntryPulled(EntryPulled),
    EntryPush(EntryPush),
    EntryPushed(EntryPushed),

    // Between relays that work together
    RelayChannelsAsk(RelayChannelsAsk),
    RelayChannelsHeld(RelayChannelsHeld),
    RelayPull(RelayPull),
    RelayPush(RelayPush),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode<T: Serialize>(value: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).unwrap();
        buf
    }

    /// T3. One size for every entry: with every field at its largest, an
    /// entry as it travels is at most its ciphertext and what an entry may
    /// take beyond it. That bound is what every limit on bytes counts.
    #[test]
    fn the_largest_entry_as_it_travels_is_its_ciphertext_and_the_overhead() {
        use cordelia_core::protocol::{
            ENTRY_OVERHEAD_BYTES, MAX_CHANNEL_ID_LEN, MAX_ITEM_BYTES, MAX_ITEM_ID_LEN,
            MAX_ITEM_TYPE_LEN, MAX_REV, MAX_TIMESTAMP_LEN, entry_fields_fit,
        };
        let long = |len: usize| "x".repeat(len);
        let largest = Item {
            item_id: long(MAX_ITEM_ID_LEN),
            channel_id: long(MAX_CHANNEL_ID_LEN),
            item_type: long(MAX_ITEM_TYPE_LEN),
            content_length: u32::MAX,
            encrypted_blob: vec![0xFF; MAX_ITEM_BYTES],
            content_hash: vec![0xFF; 32],
            author_id: vec![0xFF; 32],
            signature: vec![0xFF; 64],
            key_version: u32::MAX,
            published_at: long(MAX_TIMESTAMP_LEN),
            is_tombstone: true,
            parent_id: Some(long(MAX_ITEM_ID_LEN)),
            slot: Some(vec![0xFF; 32]),
            rev: Some(MAX_REV),
        };
        assert!(entry_fields_fit(
            &largest.item_id,
            &largest.channel_id,
            &largest.item_type,
            &largest.published_at,
            largest.parent_id.as_deref(),
        ));
        let travels = encode(&largest).len();
        assert!(
            travels <= MAX_ITEM_BYTES + ENTRY_OVERHEAD_BYTES,
            "the largest entry is {travels} bytes as it travels"
        );
        // And its header is what the overhead is for: well over half of it.
        assert!(
            travels - MAX_ITEM_BYTES > ENTRY_OVERHEAD_BYTES / 2,
            "{travels}"
        );

        // One byte more in any field, and it does not fit.
        for (id, channel, kind, time, parent) in [
            (MAX_ITEM_ID_LEN + 1, 1, 1, 1, None),
            (1, MAX_CHANNEL_ID_LEN + 1, 1, 1, None),
            (1, 1, MAX_ITEM_TYPE_LEN + 1, 1, None),
            (1, 1, 1, MAX_TIMESTAMP_LEN + 1, None),
            (1, 1, 1, 1, Some(MAX_ITEM_ID_LEN + 1)),
        ] {
            assert!(!entry_fields_fit(
                &long(id),
                &long(channel),
                &long(kind),
                &long(time),
                parent.map(long).as_deref(),
            ));
        }
    }

    /// The answer to a push as nodes before 0.2.0-alpha.4 know it.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct OlderPushAck {
        stored: u32,
        dedup_dropped: u32,
        policy_rejected: u32,
        verification_failed: u32,
    }

    /// The list of refused items is an addition that older nodes never
    /// notice: an answer with nothing refused is the same bytes as before,
    /// an older sender reads an answer that carries the list, and a newer
    /// sender reads an older receiver's answer as carrying none.
    #[test]
    fn the_list_of_refused_items_is_compatible_both_ways() {
        let older = OlderPushAck {
            stored: 2,
            dedup_dropped: 1,
            policy_rejected: 0,
            verification_failed: 1,
        };
        let nothing_refused = PushAck {
            stored: 2,
            dedup_dropped: 1,
            verification_failed: 1,
            ..Default::default()
        };
        assert_eq!(encode(&nothing_refused), encode(&older));

        let with_list = PushAck {
            refused: vec![Refusal {
                item_id: "ci_x".into(),
                why: REFUSED_STORAGE.into(),
            }],
            ..nothing_refused.clone()
        };
        let read_by_older: OlderPushAck =
            ciborium::from_reader(encode(&with_list).as_slice()).unwrap();
        assert_eq!(read_by_older, older);
        // The same inside the message envelope, as it travels.
        let framed = encode(&WireMessage::PushAck(with_list.clone()));
        let WireMessage::PushAck(read) = ciborium::from_reader(framed.as_slice()).unwrap() else {
            panic!("not a push answer");
        };
        assert_eq!(read.refused, with_list.refused);

        let read_by_newer: PushAck = ciborium::from_reader(encode(&older).as_slice()).unwrap();
        assert!(read_by_newer.refused.is_empty());
        assert_eq!(read_by_newer.verification_failed, 1);
    }

    // ── Entries of a channel from its secret ─────────────────────────

    use crate::codec::{decode_message, encode_message, read_frame, write_frame};
    use cordelia_core::protocol::{
        ENTRY_PAGE_MAX_BYTES, ENTRY_PAGE_MAX_ENTRIES, MAX_ENTRY_WIRE_BYTES, MAX_MESSAGE_BYTES,
    };
    use cordelia_crypto::entry::{CheckedEntry, Entry, EntryError, Inside, Value};
    use cordelia_crypto::identity::NodeIdentity;
    use cordelia_crypto::wire::WireError;
    use cordelia_crypto::{derive, proof};

    const SECRET: [u8; 32] = [0x11; 32];

    /// The mark of a holding of a channel.
    const MARK: [u8; 8] = [0x4d, 1, 2, 3, 4, 5, 6, 7];

    /// An entry of [`SECRET`]'s channel that the device numbered `d` made
    /// of `said` at `rev`, checked.
    fn made(d: u8, rev: u64, said: &str) -> CheckedEntry {
        let inside = Inside {
            name: "notes.md".to_string(),
            value: Value::Text(said.to_string()),
            chain: Some(Vec::new()),
        };
        let device = NodeIdentity::from_seed([d; 32]).unwrap();
        Entry::seal(&SECRET, &device, rev, &inside)
            .unwrap()
            .check()
            .unwrap()
    }

    /// The message, through the codec and back.
    fn through(message: &WireMessage) -> WireMessage {
        decode_message(&encode_message(message).unwrap()).unwrap()
    }

    /// The eight protocol bytes as a peer reads them that knows nothing
    /// of the streams of entries.
    fn read_by_an_older_peer(byte: u8) -> Option<&'static str> {
        match byte {
            0x01 => Some("Handshake"),
            0x02 => Some("KeepAlive"),
            0x03 => Some("PeerSharing"),
            0x04 => Some("ChannelAnnounce"),
            0x05 => Some("ItemSync"),
            0x06 => Some("ItemPush"),
            0x07 => Some("PskExchange"),
            0x08 => Some("Pairing"),
            _ => None,
        }
    }

    /// The four streams of entries, and the one between relays that work
    /// together, have protocol bytes that an older peer reads as none of
    /// its own: it refuses the stream. And the eight it knows are read as
    /// they always were.
    #[test]
    fn an_older_peer_takes_no_stream_of_entries_for_one_of_its_own() {
        let new = [
            (Protocol::EntryShow, 0x10),
            (Protocol::ChannelProve, 0x11),
            (Protocol::EntryPull, 0x12),
            (Protocol::EntryPush, 0x13),
            (Protocol::RelayEntries, 0x14),
        ];
        for (protocol, byte) in new {
            assert_eq!(protocol.as_byte(), byte);
            assert_eq!(Protocol::from_byte(byte), Some(protocol));
            assert_eq!(read_by_an_older_peer(byte), None, "{byte:#04x}");
        }

        // Every byte: the eight are what they were, by name, the five are
        // the new ones, and no other byte is a protocol.
        for byte in 0..=u8::MAX {
            let read = Protocol::from_byte(byte);
            match read_by_an_older_peer(byte) {
                Some(name) => {
                    let protocol = read.unwrap();
                    assert_eq!(format!("{protocol:?}"), name);
                    assert_eq!(protocol.as_byte(), byte);
                }
                None => assert_eq!(
                    read.is_some(),
                    new.iter().any(|(_, of)| *of == byte),
                    "{byte:#04x}"
                ),
            }
        }
    }

    /// The messages as a peer knows them that knows nothing of the
    /// streams of entries.
    #[derive(Debug, Deserialize)]
    #[serde(tag = "msg_type")]
    #[allow(dead_code)]
    enum OlderWireMessage {
        HandshakePropose(HandshakePropose),
        HandshakeAccept(HandshakeAccept),
        Ping(Ping),
        Pong(Pong),
        PeerShareRequest(PeerShareRequest),
        PeerShareResponse(PeerShareResponse),
        ChannelJoined(ChannelJoined),
        ChannelLeft(ChannelLeft),
        ChannelStateHash(ChannelStateHash),
        ChannelListRequest(ChannelListRequest),
        ChannelListResponse(ChannelListResponse),
        SyncChannelListRequest(SyncChannelListRequest),
        SyncChannelListResponse(SyncChannelListResponse),
        SyncRequest(SyncRequest),
        SyncResponse(SyncResponse),
        FetchRequest(FetchRequest),
        FetchResponse(FetchResponse),
        PushPayload(PushPayload),
        PushAck(PushAck),
        PskRequest(PskRequest),
        PskResponse(PskResponse),
        PairingRequest(PairingRequest),
        PairingResponse(PairingResponse),
    }

    /// One of each message of the four streams, with every answer there
    /// is.
    fn every_message_of_entries() -> Vec<WireMessage> {
        let entry = made(1, 5, "what the file holds").to_wire();
        let other = made(1, 6, "what it holds now").to_wire();
        let channel = derive::channel_id(&SECRET).unwrap();
        let mut messages = vec![
            WireMessage::EntryShow(EntryShow {
                entry: entry.clone(),
            }),
            WireMessage::EntryShowShort(short_of(&made(1, 5, "what the file holds"))),
            WireMessage::ChannelProve(ChannelProve {
                channel,
                proof: proof::make(&SECRET, &[0x51; 32], &[0x07; 32]).unwrap(),
            }),
            WireMessage::ChannelProved(ChannelProved { proved: true }),
            WireMessage::ChannelProved(ChannelProved { proved: false }),
            WireMessage::EntryPull(EntryPull {
                channel,
                mark: MARK,
                after: (1 << 53) + 7,
                limit: 100,
            }),
            WireMessage::EntryPulled(EntryPulled {
                entries: vec![ByteBuf::from(entry.clone()), ByteBuf::from(other.clone())],
                next: u64::MAX,
                mark: MARK,
            }),
            WireMessage::EntryPulled(EntryPulled {
                entries: Vec::new(),
                next: 0,
                mark: [0; 8],
            }),
            WireMessage::EntryPush(EntryPush {
                entries: vec![ByteBuf::from(entry.clone()), ByteBuf::from(other.clone())],
            }),
            WireMessage::EntryPush(EntryPush {
                entries: Vec::new(),
            }),
            WireMessage::EntryPushed(EntryPushed {
                answers: vec![
                    PushAnswer::Stored,
                    PushAnswer::Held,
                    PushAnswer::Older,
                    PushAnswer::Refused(EntryRefused::NotSigned),
                    PushAnswer::Refused(EntryRefused::NoRoom),
                    PushAnswer::Refused(EntryRefused::OverLimit),
                ],
            }),
            WireMessage::EntryPushed(EntryPushed {
                answers: Vec::new(),
            }),
            WireMessage::RelayChannelsAsk(RelayChannelsAsk {
                after: [0; 32],
                limit: 1000,
            }),
            WireMessage::RelayChannelsHeld(RelayChannelsHeld {
                channels: vec![
                    RelayChannel {
                        channel,
                        mark: MARK,
                        held_since: 1_700_000_000,
                        used_at: 1_800_000_000,
                        places: 57,
                    },
                    RelayChannel {
                        channel: [0xff; 32],
                        mark: [0xff; 8],
                        held_since: i64::MIN,
                        used_at: i64::MAX,
                        places: u64::MAX,
                    },
                ],
            }),
            WireMessage::RelayChannelsHeld(RelayChannelsHeld {
                channels: Vec::new(),
            }),
            WireMessage::RelayPull(RelayPull {
                channel,
                mark: MARK,
                after: 57,
                limit: 100,
            }),
            WireMessage::RelayPush(RelayPush {
                entries: vec![
                    RelayEntry {
                        entry: entry.clone(),
                        held_since: 1_700_000_000,
                        used_at: 1_800_000_000,
                    },
                    RelayEntry {
                        entry: other.clone(),
                        held_since: 0,
                        used_at: -1,
                    },
                ],
            }),
        ];
        for answer in [
            ShowAnswer::Held,
            ShowAnswer::Taken,
            ShowAnswer::Another(other),
            ShowAnswer::Refused(EntryRefused::NotSigned),
            ShowAnswer::Refused(EntryRefused::NoRoom),
            ShowAnswer::Refused(EntryRefused::OverLimit),
            ShowAnswer::Whole,
            ShowAnswer::Other {
                rev: 6,
                id: [0x1d; 32],
            },
        ] {
            messages.push(WireMessage::EntryShown(EntryShown { answer }));
        }
        messages
    }

    /// The short form of `entry`: what a connection shows of it once it
    /// has shown it whole.
    fn short_of(entry: &CheckedEntry) -> EntryShowShort {
        EntryShowShort {
            channel: entry.channel,
            author: entry.author,
            slot: entry.slot,
            rev: entry.rev,
            id: entry.id(),
        }
    }

    /// What a message of the four streams holds, for setting two side by
    /// side: the envelope has no equality of its own.
    fn of_entries(message: &WireMessage) -> String {
        match message {
            WireMessage::EntryShow(m) => format!("{m:?}"),
            WireMessage::EntryShowShort(m) => format!("{m:?}"),
            WireMessage::EntryShown(m) => format!("{m:?}"),
            WireMessage::ChannelProve(m) => format!("{m:?}"),
            WireMessage::ChannelProved(m) => format!("{m:?}"),
            WireMessage::EntryPull(m) => format!("{m:?}"),
            WireMessage::EntryPulled(m) => format!("{m:?}"),
            WireMessage::EntryPush(m) => format!("{m:?}"),
            WireMessage::EntryPushed(m) => format!("{m:?}"),
            WireMessage::RelayChannelsAsk(m) => format!("{m:?}"),
            WireMessage::RelayChannelsHeld(m) => format!("{m:?}"),
            WireMessage::RelayPull(m) => format!("{m:?}"),
            WireMessage::RelayPush(m) => format!("{m:?}"),
            other => panic!("not a message of entries: {other:?}"),
        }
    }

    #[test]
    fn a_show_and_each_of_its_answers_go_through_the_codec() {
        let entry = made(1, 5, "what the file holds");
        let shown = WireMessage::EntryShow(EntryShow {
            entry: entry.to_wire(),
        });
        let WireMessage::EntryShow(read) = through(&shown) else {
            panic!("not a show");
        };
        // What arrives is the entry's bytes, and reads as the entry.
        assert_eq!(read.entry, entry.to_wire());
        assert_eq!(Entry::from_wire(&read.entry).unwrap().check(), Ok(entry));

        let other = made(1, 6, "what it holds now");
        for answer in [
            ShowAnswer::Held,
            ShowAnswer::Taken,
            ShowAnswer::Another(other.to_wire()),
            ShowAnswer::Refused(EntryRefused::NotSigned),
            ShowAnswer::Refused(EntryRefused::NoRoom),
            ShowAnswer::Refused(EntryRefused::OverLimit),
            ShowAnswer::Whole,
            ShowAnswer::Other {
                rev: 6,
                id: [0x1d; 32],
            },
        ] {
            let message = WireMessage::EntryShown(EntryShown {
                answer: answer.clone(),
            });
            let WireMessage::EntryShown(read) = through(&message) else {
                panic!("not an answer to a show");
            };
            assert_eq!(read.answer, answer);
        }
        // The entry that an answer hands back reads as that entry.
        let WireMessage::EntryShown(EntryShown {
            answer: ShowAnswer::Another(bytes),
        }) = through(&WireMessage::EntryShown(EntryShown {
            answer: ShowAnswer::Another(other.to_wire()),
        }))
        else {
            panic!("not another entry");
        };
        assert_eq!(Entry::from_wire(&bytes).unwrap().check(), Ok(other));
    }

    /// The short form of a show goes through the codec as it was written:
    /// the entry's channel, its author, its slot, its revision and its ID.
    /// It is some two hundred bytes, whatever the entry's size, and holds
    /// nothing of the entry's content or its signatures. Nor does any
    /// answer to it: word of another entry is that one's revision and ID.
    #[test]
    fn the_short_form_of_a_show_goes_through_the_codec() {
        let entry = made(1, 5, "what the file holds");
        let short = short_of(&entry);
        assert_eq!(
            (short.channel, short.author, short.slot, short.rev),
            (entry.channel, entry.author, entry.slot, 5)
        );
        assert_eq!(short.id, entry.id());
        let WireMessage::EntryShowShort(read) =
            through(&WireMessage::EntryShowShort(short.clone()))
        else {
            panic!("not the short form of a show");
        };
        assert_eq!(read, short);

        let largest = Entry::seal(
            &SECRET,
            &NodeIdentity::from_seed([1; 32]).unwrap(),
            (1 << 53) - 1,
            &Inside {
                name: "n".into(),
                value: Value::Text("x".repeat(60_000)),
                chain: Some(Vec::new()),
            },
        )
        .unwrap()
        .check()
        .unwrap();
        let whole = encode_message(&WireMessage::EntryShow(EntryShow {
            entry: largest.to_wire(),
        }))
        .unwrap();
        let in_short = encode_message(&WireMessage::EntryShowShort(short_of(&largest))).unwrap();
        assert!(whole.len() > 65_536, "{}", whole.len());
        assert!(in_short.len() < 256, "{}", in_short.len());
        for part in [
            &largest.content[..64],
            &largest.author_signature[..],
            &largest.channel_signature[..],
        ] {
            assert!(!in_short.windows(part.len()).any(|bytes| bytes == part));
        }

        // What a relay found of a short form, as it is said: held, a call
        // for the whole entry, or the revision and the ID of another.
        use cordelia_storage::relay::ShownShort;
        assert_eq!(ShowAnswer::from(&ShownShort::Held), ShowAnswer::Held);
        assert_eq!(ShowAnswer::from(&ShownShort::Whole), ShowAnswer::Whole);
        let other = ShowAnswer::from(&ShownShort::Other {
            rev: largest.rev,
            id: largest.id(),
        });
        assert_eq!(
            other,
            ShowAnswer::Other {
                rev: (1 << 53) - 1,
                id: largest.id(),
            }
        );
        // Each of the three is small, and none holds anything of an
        // entry but its revision and its ID.
        for answer in [ShowAnswer::Held, ShowAnswer::Whole, other.clone()] {
            let said = encode_message(&WireMessage::EntryShown(EntryShown {
                answer: answer.clone(),
            }))
            .unwrap();
            assert!(said.len() < 128, "{answer:?}: {}", said.len());
            for part in [
                &largest.content[..64],
                &largest.author_signature[..],
                &largest.channel_signature[..],
            ] {
                assert!(!said.windows(part.len()).any(|bytes| bytes == part));
            }
        }
        let WireMessage::EntryShown(read) = through(&WireMessage::EntryShown(EntryShown {
            answer: other.clone(),
        })) else {
            panic!("not the answer to a show");
        };
        assert_eq!(read.answer, other);

        // Word of another entry whose ID is not 32 bytes is not read.
        let said = |id: usize| {
            let text = |s: &str| ciborium::Value::Text(s.into());
            let other = ciborium::Value::Map(vec![
                (text("rev"), ciborium::Value::Integer(6.into())),
                (text("id"), ciborium::Value::Bytes(vec![4; id])),
            ]);
            let mut bytes = Vec::new();
            ciborium::into_writer(
                &ciborium::Value::Map(vec![
                    (text("msg_type"), text("EntryShown")),
                    (
                        text("answer"),
                        ciborium::Value::Map(vec![(text("other"), other)]),
                    ),
                ]),
                &mut bytes,
            )
            .unwrap();
            decode_message(&bytes)
        };
        assert!(matches!(
            said(32),
            Ok(WireMessage::EntryShown(EntryShown {
                answer: ShowAnswer::Other { rev: 6, id },
            })) if id == [4; 32]
        ));
        for id in [0, 31, 33, 64] {
            assert!(said(id).is_err(), "{id}");
        }
    }

    #[test]
    fn a_proof_and_its_answer_go_through_the_codec() {
        let channel = derive::channel_id(&SECRET).unwrap();
        let session = [0x51; 32];
        // The node key of the end that proves. It is not sent: whoever
        // checks knows it from the connection.
        let prover = NodeIdentity::from_seed([7; 32]).unwrap().public_key();
        let prove = ChannelProve {
            channel,
            proof: proof::make(&SECRET, &session, &prover).unwrap(),
        };
        let WireMessage::ChannelProve(read) = through(&WireMessage::ChannelProve(prove.clone()))
        else {
            panic!("not a proof");
        };
        assert_eq!(read, prove);
        // What arrives is checked from the ID alone.
        assert!(proof::check(&read.channel, &session, &prover, &read.proof));

        for proved in [true, false] {
            let message = WireMessage::ChannelProved(ChannelProved { proved });
            let WireMessage::ChannelProved(read) = through(&message) else {
                panic!("not an answer to a proof");
            };
            assert_eq!(read.proved, proved);
        }
        // No says nothing more than no. The answer holds its name and
        // that one thing, so a no for a proof that fails and a no for a
        // channel that is not held are the same bytes.
        let no = encode_message(&WireMessage::ChannelProved(ChannelProved { proved: false }));
        let held: ciborium::Value = ciborium::from_reader(no.unwrap().as_slice()).unwrap();
        let text = |text: &str| ciborium::Value::Text(text.into());
        assert_eq!(
            held,
            ciborium::Value::Map(vec![
                (text("msg_type"), text("ChannelProved")),
                (text("proved"), ciborium::Value::Bool(false)),
            ])
        );
    }

    #[test]
    fn a_pull_and_its_page_go_through_the_codec() {
        let pull = EntryPull {
            channel: derive::channel_id(&SECRET).unwrap(),
            mark: MARK,
            after: (1 << 53) + 7,
            limit: 100,
        };
        let WireMessage::EntryPull(read) = through(&WireMessage::EntryPull(pull.clone())) else {
            panic!("not a pull");
        };
        assert_eq!(read, pull);

        let entries = [made(1, 5, "one"), made(2, 5, "two"), made(3, 7, "three")];
        let page = EntryPulled {
            entries: entries
                .iter()
                .map(|entry| ByteBuf::from(entry.to_wire()))
                .collect(),
            next: 3,
            mark: MARK,
        };
        let WireMessage::EntryPulled(read) = through(&WireMessage::EntryPulled(page.clone()))
        else {
            panic!("not a page");
        };
        assert_eq!(read, page);
        for (bytes, entry) in read.entries.iter().zip(&entries) {
            assert_eq!(&Entry::from_wire(bytes).unwrap().check().unwrap(), entry);
        }
        // A page with nothing in it, the furthest place there is, and the
        // mark of no holding.
        let nothing = EntryPulled {
            entries: Vec::new(),
            next: u64::MAX,
            mark: [0; 8],
        };
        let WireMessage::EntryPulled(read) = through(&WireMessage::EntryPulled(nothing.clone()))
        else {
            panic!("not a page");
        };
        assert_eq!(read, nothing);
    }

    #[test]
    fn a_push_and_its_answer_go_through_the_codec() {
        let entries = [made(1, 5, "one"), made(2, 5, "two")];
        let push = EntryPush {
            entries: entries
                .iter()
                .map(|entry| ByteBuf::from(entry.to_wire()))
                .collect(),
        };
        let WireMessage::EntryPush(read) = through(&WireMessage::EntryPush(push.clone())) else {
            panic!("not a push");
        };
        assert_eq!(read, push);
        for (bytes, entry) in read.entries.iter().zip(&entries) {
            assert_eq!(&Entry::from_wire(bytes).unwrap().check().unwrap(), entry);
        }

        // One answer for each entry, in their order: each thing that can
        // become of one.
        let pushed = EntryPushed {
            answers: vec![
                PushAnswer::Stored,
                PushAnswer::Held,
                PushAnswer::Older,
                PushAnswer::Refused(EntryRefused::NotSigned),
                PushAnswer::Refused(EntryRefused::NoRoom),
                PushAnswer::Refused(EntryRefused::OverLimit),
                PushAnswer::Stored,
            ],
        };
        let WireMessage::EntryPushed(read) = through(&WireMessage::EntryPushed(pushed.clone()))
        else {
            panic!("not an answer to a push");
        };
        assert_eq!(read, pushed);
    }

    /// Each message of the four streams, framed as it travels on a
    /// stream, and read back as it was.
    #[tokio::test]
    async fn the_messages_of_entries_travel_in_frames() {
        let messages = every_message_of_entries();
        assert_eq!(messages.len(), 25);
        let mut stream = Vec::new();
        for message in &messages {
            write_frame(&mut stream, message).await.unwrap();
        }
        let mut cursor = std::io::Cursor::new(stream);
        for message in &messages {
            let read = read_frame(&mut cursor).await.unwrap();
            assert_eq!(of_entries(&read), of_entries(message));
        }
        // And each is encoded the same every time.
        for message in &messages {
            assert_eq!(
                encode_message(message).unwrap(),
                encode_message(message).unwrap()
            );
        }
    }

    /// A peer that knows nothing of the streams of entries reads none of
    /// their messages as one of its own, and the messages it knows are
    /// read as before.
    #[test]
    fn an_older_peer_reads_no_message_of_entries_as_one_of_its_own() {
        for message in every_message_of_entries() {
            let bytes = encode_message(&message).unwrap();
            let read: Result<OlderWireMessage, _> = ciborium::from_reader(bytes.as_slice());
            assert!(read.is_err(), "{message:?}");
        }
        // The control: it reads a message it knows, from this codec.
        let ack = encode_message(&WireMessage::PushAck(PushAck::default())).unwrap();
        let read: OlderWireMessage = ciborium::from_reader(ack.as_slice()).unwrap();
        assert!(matches!(read, OlderWireMessage::PushAck(_)));
    }

    /// A message of entries as a peer might write it that does not keep
    /// to the form: lengths and answers of its own.
    #[derive(Serialize)]
    #[serde(tag = "msg_type")]
    enum Loose {
        ChannelProve {
            #[serde(with = "serde_bytes")]
            channel: Vec<u8>,
            #[serde(with = "serde_bytes")]
            proof: Vec<u8>,
        },
        EntryPull {
            #[serde(with = "serde_bytes")]
            channel: Vec<u8>,
            #[serde(with = "serde_bytes")]
            mark: Vec<u8>,
            after: u64,
            limit: u32,
        },
        EntryPulled {
            entries: Vec<ByteBuf>,
            next: u64,
            #[serde(with = "serde_bytes")]
            mark: Vec<u8>,
        },
        EntryShown {
            answer: String,
        },
        EntryShowShort {
            #[serde(with = "serde_bytes")]
            channel: Vec<u8>,
            #[serde(with = "serde_bytes")]
            author: Vec<u8>,
            #[serde(with = "serde_bytes")]
            slot: Vec<u8>,
            rev: u64,
            #[serde(with = "serde_bytes")]
            id: Vec<u8>,
        },
        EntryPushed {
            answers: Vec<String>,
        },
        RelayChannelsAsk {
            #[serde(with = "serde_bytes")]
            after: Vec<u8>,
            limit: u32,
        },
        RelayChannelsHeld {
            channels: Vec<LooseChannel>,
        },
        RelayPull {
            #[serde(with = "serde_bytes")]
            channel: Vec<u8>,
            #[serde(with = "serde_bytes")]
            mark: Vec<u8>,
            after: u64,
            limit: u32,
        },
    }

    /// A channel as a relay might tell of it that does not keep to the
    /// form.
    #[derive(Serialize)]
    struct LooseChannel {
        #[serde(with = "serde_bytes")]
        channel: Vec<u8>,
        #[serde(with = "serde_bytes")]
        mark: Vec<u8>,
        held_since: i64,
        used_at: i64,
        places: u64,
    }

    /// A channel's ID is 32 bytes, a proof 64 and a mark 8, and an answer
    /// is one of those there are: a message that holds anything else is
    /// not read.
    #[test]
    fn a_message_of_entries_that_is_not_in_its_form_is_not_read() {
        let read = |loose: &Loose| decode_message(&encode(loose));
        // The control: in its form, each is read.
        assert!(matches!(
            read(&Loose::ChannelProve {
                channel: vec![1; 32],
                proof: vec![2; 64],
            }),
            Ok(WireMessage::ChannelProve(_))
        ));
        assert!(matches!(
            read(&Loose::EntryPull {
                channel: vec![1; 32],
                mark: vec![3; 8],
                after: 0,
                limit: 1,
            }),
            Ok(WireMessage::EntryPull(_))
        ));
        assert!(matches!(
            read(&Loose::EntryPulled {
                entries: Vec::new(),
                next: 0,
                mark: vec![3; 8],
            }),
            Ok(WireMessage::EntryPulled(_))
        ));
        assert!(matches!(
            read(&Loose::RelayChannelsAsk {
                after: vec![0; 32],
                limit: 1,
            }),
            Ok(WireMessage::RelayChannelsAsk(_))
        ));
        let told = |channel: usize, mark: usize| Loose::RelayChannelsHeld {
            channels: vec![LooseChannel {
                channel: vec![1; channel],
                mark: vec![3; mark],
                held_since: 7,
                used_at: 8,
                places: 9,
            }],
        };
        assert!(matches!(
            read(&told(32, 8)),
            Ok(WireMessage::RelayChannelsHeld(_))
        ));
        assert!(matches!(
            read(&Loose::RelayPull {
                channel: vec![1; 32],
                mark: vec![3; 8],
                after: 0,
                limit: 1,
            }),
            Ok(WireMessage::RelayPull(_))
        ));
        assert!(matches!(
            read(&Loose::EntryShown {
                answer: "held".into(),
            }),
            Ok(WireMessage::EntryShown(EntryShown {
                answer: ShowAnswer::Held,
            }))
        ));
        assert!(matches!(
            read(&Loose::EntryPushed {
                answers: vec!["stored".into(), "held".into(), "older".into()],
            }),
            Ok(WireMessage::EntryPushed(_))
        ));
        let short = |channel: usize, author: usize, slot: usize, id: usize| Loose::EntryShowShort {
            channel: vec![1; channel],
            author: vec![2; author],
            slot: vec![3; slot],
            rev: 5,
            id: vec![4; id],
        };
        assert!(matches!(
            read(&short(32, 32, 32, 32)),
            Ok(WireMessage::EntryShowShort(_))
        ));
        assert!(matches!(
            read(&Loose::EntryShown {
                answer: "whole".into(),
            }),
            Ok(WireMessage::EntryShown(EntryShown {
                answer: ShowAnswer::Whole,
            }))
        ));
        // Each of the four that a short form holds is 32 bytes.
        for other in [0, 31, 33, 64] {
            for lengths in [
                (other, 32, 32, 32),
                (32, other, 32, 32),
                (32, 32, other, 32),
                (32, 32, 32, other),
            ] {
                let (channel, author, slot, id) = lengths;
                assert!(
                    read(&short(channel, author, slot, id)).is_err(),
                    "{lengths:?}"
                );
            }
        }

        for (channel, proof) in [(31, 64), (33, 64), (0, 64), (32, 63), (32, 65), (32, 0)] {
            assert!(
                read(&Loose::ChannelProve {
                    channel: vec![1; channel],
                    proof: vec![2; proof],
                })
                .is_err(),
                "{channel} {proof}"
            );
        }
        for (channel, mark) in [
            (0, 8),
            (31, 8),
            (33, 8),
            (64, 8),
            (32, 0),
            (32, 7),
            (32, 9),
            (32, 32),
        ] {
            assert!(
                read(&Loose::EntryPull {
                    channel: vec![1; channel],
                    mark: vec![3; mark],
                    after: 0,
                    limit: 1,
                })
                .is_err(),
                "{channel} {mark}"
            );
            assert!(
                read(&Loose::RelayPull {
                    channel: vec![1; channel],
                    mark: vec![3; mark],
                    after: 0,
                    limit: 1,
                })
                .is_err(),
                "{channel} {mark}"
            );
            assert!(read(&told(channel, mark)).is_err(), "{channel} {mark}");
        }
        for mark in [0, 7, 9, 32] {
            assert!(
                read(&Loose::EntryPulled {
                    entries: Vec::new(),
                    next: 0,
                    mark: vec![3; mark],
                })
                .is_err(),
                "{mark}"
            );
        }
        for after in [0, 31, 33] {
            assert!(
                read(&Loose::RelayChannelsAsk {
                    after: vec![0; after],
                    limit: 1,
                })
                .is_err(),
                "{after}"
            );
        }
        for answer in ["", "Held", "another", "refused", "stored", "yes", "Whole"] {
            assert!(
                read(&Loose::EntryShown {
                    answer: answer.into(),
                })
                .is_err(),
                "{answer}"
            );
        }
        for answer in ["", "Stored", "taken", "refused", "full", "whole"] {
            assert!(
                read(&Loose::EntryPushed {
                    answers: vec!["stored".into(), answer.into()],
                })
                .is_err(),
                "{answer}"
            );
        }
    }

    /// A push holds at most a page's worth of entries, and so does a
    /// page: a message that holds one more is not read, whatever the
    /// entries are.
    #[test]
    fn a_push_of_more_than_a_pages_worth_of_entries_is_not_read() {
        assert_eq!(ENTRY_PAGE_MAX_ENTRIES, 100);
        let of = |entries: usize| vec![ByteBuf::from(vec![0x5a; 3]); entries];
        let push = |entries: usize| {
            decode_message(
                &encode_message(&WireMessage::EntryPush(EntryPush {
                    entries: of(entries),
                }))
                .unwrap(),
            )
        };
        let page = |entries: usize| {
            decode_message(
                &encode_message(&WireMessage::EntryPulled(EntryPulled {
                    entries: of(entries),
                    next: 7,
                    mark: MARK,
                }))
                .unwrap(),
            )
        };
        // A page's worth, and fewer: read, every entry of it.
        for entries in [0, 1, 99, 100] {
            let Ok(WireMessage::EntryPush(read)) = push(entries) else {
                panic!("a push of {entries} entries was not read");
            };
            assert_eq!(read.entries, of(entries));
            let Ok(WireMessage::EntryPulled(read)) = page(entries) else {
                panic!("a page of {entries} entries was not read");
            };
            assert_eq!((read.entries, read.next), (of(entries), 7));
        }
        // One more, and many more: not read at all.
        for entries in [101, 102, 1000, 10_000] {
            assert!(push(entries).is_err(), "{entries}");
            assert!(page(entries).is_err(), "{entries}");
        }
        // The same by itself, outside the envelope.
        let alone = |entries: usize| -> Result<EntryPush, _> {
            ciborium::from_reader(
                encode(&EntryPush {
                    entries: of(entries),
                })
                .as_slice(),
            )
        };
        assert_eq!(alone(100).unwrap().entries.len(), 100);
        assert!(alone(101).is_err());

        // The control: real entries, a page's worth of them, are read as
        // they were sent.
        let entry = made(1, 5, "what the file holds").to_wire();
        let full = EntryPush {
            entries: vec![ByteBuf::from(entry); 100],
        };
        let WireMessage::EntryPush(read) = through(&WireMessage::EntryPush(full.clone())) else {
            panic!("not a push");
        };
        assert_eq!(read, full);
    }

    /// The answer to a push says at most one thing for each entry that a
    /// push may hold: an answer that says more is not read, so that
    /// whoever reads one is not made to hold any number of them.
    #[test]
    fn an_answer_to_a_push_that_says_more_than_a_push_holds_is_not_read() {
        assert_eq!(ENTRY_PAGE_MAX_ENTRIES, 100);
        let pushed = |answers: usize| {
            decode_message(
                &encode_message(&WireMessage::EntryPushed(EntryPushed {
                    answers: vec![PushAnswer::Stored; answers],
                }))
                .unwrap(),
            )
        };
        for answers in [0, 1, 99, 100] {
            let Ok(WireMessage::EntryPushed(read)) = pushed(answers) else {
                panic!("an answer for {answers} entries was not read");
            };
            assert_eq!(read.answers, vec![PushAnswer::Stored; answers]);
        }
        for answers in [101, 102, 1000, 100_000] {
            assert!(pushed(answers).is_err(), "{answers}");
        }
        // The same by itself, outside the envelope.
        let alone = |answers: usize| -> Result<EntryPushed, _> {
            ciborium::from_reader(
                encode(&EntryPushed {
                    answers: vec![PushAnswer::Held; answers],
                })
                .as_slice(),
            )
        };
        assert_eq!(alone(100).unwrap().answers.len(), 100);
        assert!(alone(101).is_err());
    }

    /// What relays that work together say to each other goes through the
    /// codec as it was written: a question about which channels are held
    /// and its answer, a question for a page, and entries passed on with
    /// the two times of each one's channel.
    #[test]
    fn the_messages_between_relays_go_through_the_codec() {
        let channel = derive::channel_id(&SECRET).unwrap();
        let ask = RelayChannelsAsk {
            after: channel,
            limit: 1000,
        };
        let WireMessage::RelayChannelsAsk(read) =
            through(&WireMessage::RelayChannelsAsk(ask.clone()))
        else {
            panic!("not a question about channels");
        };
        assert_eq!(read, ask);

        let held = RelayChannelsHeld {
            channels: vec![
                RelayChannel {
                    channel,
                    mark: MARK,
                    held_since: 1_700_000_000,
                    used_at: 1_800_000_000,
                    places: 57,
                },
                // Whatever the two times are, they arrive as they were
                // said: what is no time is for the receiver to say.
                RelayChannel {
                    channel: [0xff; 32],
                    mark: [0xff; 8],
                    held_since: i64::MIN,
                    used_at: i64::MAX,
                    places: u64::MAX,
                },
                RelayChannel {
                    channel: [1; 32],
                    mark: [1; 8],
                    held_since: 0,
                    used_at: -1,
                    places: 0,
                },
            ],
        };
        let WireMessage::RelayChannelsHeld(read) =
            through(&WireMessage::RelayChannelsHeld(held.clone()))
        else {
            panic!("not an answer about channels");
        };
        assert_eq!(read, held);

        let pull = RelayPull {
            channel,
            mark: MARK,
            after: (1 << 53) + 7,
            limit: 100,
        };
        let WireMessage::RelayPull(read) = through(&WireMessage::RelayPull(pull.clone())) else {
            panic!("not a question for a page");
        };
        assert_eq!(read, pull);

        let entries = [made(1, 5, "one"), made(2, 5, "two")];
        let push = RelayPush {
            entries: entries
                .iter()
                .map(|entry| RelayEntry {
                    entry: entry.to_wire(),
                    held_since: 1_700_000_000,
                    used_at: 1_800_000_000,
                })
                .collect(),
        };
        let WireMessage::RelayPush(read) = through(&WireMessage::RelayPush(push.clone())) else {
            panic!("not entries passed on");
        };
        assert_eq!(read, push);
        for (passed, entry) in read.entries.iter().zip(&entries) {
            assert_eq!(
                &Entry::from_wire(&passed.entry).unwrap().check().unwrap(),
                entry
            );
        }

        // As they are spelled: a change to a name is a change to the
        // protocol.
        let bytes = encode_message(&WireMessage::RelayChannelsHeld(RelayChannelsHeld {
            channels: vec![held.channels[0]],
        }))
        .unwrap();
        let spelled: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let text = |text: &str| ciborium::Value::Text(text.into());
        let number = |n: i64| ciborium::Value::Integer(n.into());
        assert_eq!(
            spelled,
            ciborium::Value::Map(vec![
                (text("msg_type"), text("RelayChannelsHeld")),
                (
                    text("channels"),
                    ciborium::Value::Array(vec![ciborium::Value::Map(vec![
                        (text("channel"), ciborium::Value::Bytes(channel.to_vec())),
                        (text("mark"), ciborium::Value::Bytes(MARK.to_vec())),
                        (text("held_since"), number(1_700_000_000)),
                        (text("used_at"), number(1_800_000_000)),
                        (text("places"), number(57)),
                    ])])
                ),
            ])
        );
        // And a pull by a holder of the key says its mark under that
        // name, beside the place.
        let bytes = encode_message(&WireMessage::EntryPull(EntryPull {
            channel,
            mark: MARK,
            after: 5,
            limit: 9,
        }))
        .unwrap();
        let spelled: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(
            spelled,
            ciborium::Value::Map(vec![
                (text("msg_type"), text("EntryPull")),
                (text("channel"), ciborium::Value::Bytes(channel.to_vec())),
                (text("mark"), ciborium::Value::Bytes(MARK.to_vec())),
                (text("after"), number(5)),
                (text("limit"), number(9)),
            ])
        );
    }

    /// An answer about channels tells of at most a page of them, and
    /// entries are passed on at most a page's worth at a time: a message
    /// that holds one more is not read.
    #[test]
    fn a_message_between_relays_that_holds_more_than_a_page_is_not_read() {
        use cordelia_core::protocol::RELAY_CHANNELS_PAGE_MAX;
        assert_eq!(RELAY_CHANNELS_PAGE_MAX, 1000);
        let told = |channels: usize| {
            let one = RelayChannel {
                channel: [0xff; 32],
                mark: [0xff; 8],
                held_since: i64::MAX,
                used_at: i64::MAX,
                places: u64::MAX,
            };
            WireMessage::RelayChannelsHeld(RelayChannelsHeld {
                channels: vec![one; channels],
            })
        };
        let passed = |entries: usize| {
            let one = RelayEntry {
                entry: vec![0x5a; 3],
                held_since: 7,
                used_at: 8,
            };
            WireMessage::RelayPush(RelayPush {
                entries: vec![one; entries],
            })
        };
        let read = |message: &WireMessage| decode_message(&encode_message(message).unwrap());

        for channels in [0, 1, 999, 1000] {
            let Ok(WireMessage::RelayChannelsHeld(read)) = read(&told(channels)) else {
                panic!("an answer about {channels} channels was not read");
            };
            assert_eq!(read.channels.len(), channels);
        }
        for channels in [1001, 1002, 5000] {
            assert!(read(&told(channels)).is_err(), "{channels}");
        }
        for entries in [0, 1, 99, 100] {
            let Ok(WireMessage::RelayPush(read)) = read(&passed(entries)) else {
                panic!("{entries} entries passed on were not read");
            };
            assert_eq!(read.entries.len(), entries);
        }
        for entries in [101, 102, 1000] {
            assert!(read(&passed(entries)).is_err(), "{entries}");
        }

        // A full answer about channels, with every number at its longest,
        // is well within one message.
        let travels = encode_message(&told(1000)).unwrap().len();
        assert!(travels < MAX_MESSAGE_BYTES as usize / 4, "{travels}");
    }

    /// The answers as they are spelled on the wire: a change to one is a
    /// change to the protocol, and fails here.
    #[test]
    fn the_answers_of_entries_are_spelled_as_published() {
        #[derive(Debug, PartialEq, Deserialize)]
        struct Spelled {
            msg_type: String,
            answer: ciborium::Value,
        }
        let spelled = |answer: ShowAnswer| -> Spelled {
            let bytes = encode_message(&WireMessage::EntryShown(EntryShown { answer })).unwrap();
            ciborium::from_reader(bytes.as_slice()).unwrap()
        };
        let text = |text: &str| ciborium::Value::Text(text.into());
        let one =
            |key: &str, value: ciborium::Value| ciborium::Value::Map(vec![(text(key), value)]);
        assert_eq!(spelled(ShowAnswer::Held).msg_type, "EntryShown");
        assert_eq!(spelled(ShowAnswer::Held).answer, text("held"));
        assert_eq!(spelled(ShowAnswer::Taken).answer, text("taken"));
        assert_eq!(spelled(ShowAnswer::Whole).answer, text("whole"));
        assert_eq!(
            spelled(ShowAnswer::Another(vec![7, 8])).answer,
            one("another", ciborium::Value::Bytes(vec![7, 8]))
        );
        for (why, name) in [
            (EntryRefused::NotSigned, "not_signed"),
            (EntryRefused::NoRoom, "no_room"),
            (EntryRefused::OverLimit, "over_limit"),
        ] {
            assert_eq!(
                spelled(ShowAnswer::Refused(why)).answer,
                one("refused", text(name))
            );
        }

        // The short form of a show: its name, and the five things it
        // holds, each by its name.
        let entry = made(1, 5, "what the file holds");
        let bytes = encode_message(&WireMessage::EntryShowShort(short_of(&entry))).unwrap();
        let short: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let held = |bytes: [u8; 32]| ciborium::Value::Bytes(bytes.to_vec());
        assert_eq!(
            short,
            ciborium::Value::Map(vec![
                (text("msg_type"), text("EntryShowShort")),
                (text("channel"), held(entry.channel)),
                (text("author"), held(entry.author)),
                (text("slot"), held(entry.slot)),
                (text("rev"), ciborium::Value::Integer(5.into())),
                (text("id"), held(entry.id())),
            ])
        );
        // Word of another entry: its revision and its ID, by their names.
        assert_eq!(
            spelled(ShowAnswer::Other {
                rev: 6,
                id: entry.id(),
            })
            .answer,
            one(
                "other",
                ciborium::Value::Map(vec![
                    (text("rev"), ciborium::Value::Integer(6.into())),
                    (text("id"), held(entry.id())),
                ])
            )
        );

        #[derive(Debug, PartialEq, Deserialize)]
        struct Pushed {
            answers: Vec<ciborium::Value>,
        }
        let bytes = encode_message(&WireMessage::EntryPushed(EntryPushed {
            answers: vec![
                PushAnswer::Stored,
                PushAnswer::Held,
                PushAnswer::Older,
                PushAnswer::Refused(EntryRefused::NoRoom),
            ],
        }))
        .unwrap();
        let pushed: Pushed = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(
            pushed.answers,
            [
                text("stored"),
                text("held"),
                text("older"),
                one("refused", text("no_room"))
            ]
        );
    }

    /// A page at the most it may take, and the largest entry shown, fit
    /// one message with room to spare.
    #[test]
    fn a_full_page_of_entries_fits_one_message() {
        // The most entries a page holds, taking all the bytes a page may:
        // 13 of the largest, and 87 that share the rest.
        let largest = 13;
        let rest = ENTRY_PAGE_MAX_ENTRIES as usize - largest;
        let left = ENTRY_PAGE_MAX_BYTES - largest * MAX_ENTRY_WIRE_BYTES;
        let mut entries = vec![ByteBuf::from(vec![0xff; MAX_ENTRY_WIRE_BYTES]); largest];
        entries.extend(vec![ByteBuf::from(vec![0xff; left / rest]); rest]);
        entries[largest].extend(vec![0xff; left % rest]);
        let bytes: usize = entries.iter().map(|entry| entry.len()).sum();
        assert_eq!(bytes, ENTRY_PAGE_MAX_BYTES);
        assert_eq!(entries.len(), ENTRY_PAGE_MAX_ENTRIES as usize);

        let page = WireMessage::EntryPulled(EntryPulled {
            entries: entries.clone(),
            next: u64::MAX,
            mark: [0xff; 8],
        });
        let travels = encode_message(&page).unwrap().len();
        assert!(travels <= MAX_MESSAGE_BYTES as usize, "{travels}");
        // What is around the entries is small: far less than is left for
        // it.
        assert!(travels - bytes < 1024, "{}", travels - bytes);
        // A push of as much fits as well, and so do as many passed on
        // between relays, each with its two times.
        let passed_on = WireMessage::RelayPush(RelayPush {
            entries: entries
                .iter()
                .map(|entry| RelayEntry {
                    entry: entry.to_vec(),
                    held_since: i64::MAX,
                    used_at: i64::MAX,
                })
                .collect(),
        });
        let travels = encode_message(&passed_on).unwrap().len();
        assert!(travels <= MAX_MESSAGE_BYTES as usize, "{travels}");
        assert!(travels - bytes < 8 * 1024, "{}", travels - bytes);
        let push = WireMessage::EntryPush(EntryPush { entries });
        assert!(encode_message(&push).unwrap().len() <= MAX_MESSAGE_BYTES as usize);

        // An entry of the largest size, shown, and handed back.
        let shown = WireMessage::EntryShow(EntryShow {
            entry: vec![0xff; MAX_ENTRY_WIRE_BYTES],
        });
        let answer = WireMessage::EntryShown(EntryShown {
            answer: ShowAnswer::Another(vec![0xff; MAX_ENTRY_WIRE_BYTES]),
        });
        for message in [shown, answer] {
            let travels = encode_message(&message).unwrap().len();
            assert!(travels < MAX_ENTRY_WIRE_BYTES + 64, "{travels}");
        }
    }

    /// What a relay did is said on the wire as one of the answers there
    /// are. Why an entry was refused is said as one of three things: that
    /// the bytes were no entry's is not told from a signature that does
    /// not hold, nor a full channel from a full relay.
    #[test]
    fn what_a_relay_did_is_said_as_one_of_the_answers() {
        use cordelia_storage::relay::{Page, Proof, Refused, Shown, Taken};

        // A proof: yes only where it holds and the channel is held. A
        // proof that fails and a channel that is not held are one no.
        for (found, proved) in [
            (Proof::Holds { channel_held: true }, true),
            (
                Proof::Holds {
                    channel_held: false,
                },
                false,
            ),
            (Proof::Fails, false),
        ] {
            assert_eq!(ChannelProved::from(&found), ChannelProved { proved });
        }
        assert_eq!(
            encode(&ChannelProved::from(&Proof::Fails)),
            encode(&ChannelProved::from(&Proof::Holds {
                channel_held: false
            }))
        );

        let refusals = [
            (
                Refused::NotAnEntry(WireError::TooShort),
                EntryRefused::NotSigned,
            ),
            (
                Refused::NotSigned(EntryError::ChannelSignature),
                EntryRefused::NotSigned,
            ),
            (
                Refused::NotSigned(EntryError::AuthorSignature),
                EntryRefused::NotSigned,
            ),
            (Refused::NoRoom, EntryRefused::NoRoom),
            (Refused::ChannelFull, EntryRefused::NoRoom),
            (Refused::OverAllowance, EntryRefused::OverLimit),
        ];
        for (why, said) in &refusals {
            assert_eq!(EntryRefused::from(why), *said, "{why:?}");
            assert_eq!(
                PushAnswer::from(&Taken::Refused(why.clone())),
                PushAnswer::Refused(*said)
            );
            assert_eq!(
                ShowAnswer::from(&Shown::Refused(why.clone())),
                ShowAnswer::Refused(*said)
            );
        }
        assert_eq!(PushAnswer::from(&Taken::Stored), PushAnswer::Stored);
        assert_eq!(PushAnswer::from(&Taken::AlreadyHeld), PushAnswer::Held);
        assert_eq!(PushAnswer::from(&Taken::OlderThanHeld), PushAnswer::Older);

        assert_eq!(ShowAnswer::from(&Shown::Held), ShowAnswer::Held);
        assert_eq!(ShowAnswer::from(&Shown::Taken), ShowAnswer::Taken);
        let entry = made(1, 5, "what the file holds");
        let another = Shown::Another {
            entry: Box::new(entry.clone()),
            cost: 1280,
        };
        assert_eq!(
            ShowAnswer::from(&another),
            ShowAnswer::Another(entry.to_wire())
        );

        // A page: each entry as its bytes, in their order, and the place.
        let other = made(2, 7, "another text");
        let page = Page {
            entries: vec![(*entry).clone(), (*other).clone()],
            next: 9,
            cost: 2560,
            mark: MARK,
        };
        assert_eq!(
            EntryPulled::from(&page),
            EntryPulled {
                entries: vec![
                    ByteBuf::from(entry.to_wire()),
                    ByteBuf::from(other.to_wire())
                ],
                next: 9,
                mark: MARK,
            }
        );

        // A channel that a relay tells a relay it works with: its ID, the
        // mark of the holding, the two times, and the last place.
        let told = cordelia_storage::relay::ToldChannel {
            channel: [0x21; 32],
            held: cordelia_storage::relay::HeldChannel {
                held_since: 1_700_000_000,
                used_at: 1_800_000_000,
                bytes: 2560,
                mark: MARK,
            },
            places: 57,
        };
        assert_eq!(
            RelayChannel::from(&told),
            RelayChannel {
                channel: [0x21; 32],
                mark: MARK,
                held_since: 1_700_000_000,
                used_at: 1_800_000_000,
                places: 57,
            }
        );
    }
}
