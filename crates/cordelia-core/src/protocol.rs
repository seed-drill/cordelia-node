//! Protocol constants -- single source of truth for all Cordelia parameters.
//!
//! ## Structure
//!
//! Constants are either **primitives** (axiomatic design choices) or **derived**
//! (computed from primitives). Derived constants use const expressions so the
//! dependency is visible in the source and enforced by the compiler.
//!
//! - `// Primitive:` explains *why* this value was chosen.
//! - Derived constants reference their parent(s) directly in the expression.
//! - Derivation relationships are asserted in the test module.
//!
//! ## Primitive dependency graph
//!
//! ```text
//! STREAM_TIMEOUT_SECS ──> HANDSHAKE_TIMEOUT_SECS
//!                     \──> NODE_STOP_TIMEOUT_SECS (3x stream)
//!
//! TICK_INTERVAL_SECS ──> RATE_WINDOW_SECS ──> BAN_WINDOW_SECS
//!                     \──> SYNCS_PER_PEER_PER_MINUTE
//!
//! REPUSH_INTERVAL_SECS ──> REALTIME_SYNC_INTERVAL_SECS (2x repush)
//!
//! PING_INTERVAL_SECS ──> DEAD_TIMEOUT_SECS ──> HYSTERESIS_SECS
//!                    \──> BACKOFF_BASE_SECS
//!                    \──> CLEAR_FAILURE_DELAY_SECS
//!                    \──> PEER_SHARES_PER_PEER_PER_MINUTE
//!
//! PEER_SHARE_INTERVAL_SECS ──> MIN_WARM_TENURE_SECS
//!                          \──> CHURN_JITTER_SECS
//!                          \──> BAN_TRANSIENT_SECS ──> BACKOFF_MAX_SECS
//!                          \                       \──> BATCH_SYNC_INTERVAL_SECS
//!                          \──> CHANNEL_RECONCILIATION_INTERVAL_SECS
//!                          \──> CHANNEL_RESPONDER_OFFSET_SECS
//!
//! CHURN_INTERVAL_SECS ──> STALE_THRESHOLD_SECS
//!                     \──> BAN_IDENTITY_SECS
//!                     \──> BAN_SYSTEMATIC_SECS
//! ```
//!
//! Spec: docs/specs/parameter-rationale.md, docs/specs/network-protocol.md

// ── Wire protocol ────────────────────────────────────────────────────

/// Current protocol version (§3.3).
pub const PROTOCOL_VERSION: u16 = 1;

/// Magic number for handshake validation (§4.1.3).
pub const HANDSHAKE_MAGIC: u32 = 0xC0DE_11A1;

// ── Ports ────────────────────────────────────────────────────────────

/// Default HTTP API port (configuration.md §3).
pub const HTTP_PORT: u16 = 9473;

/// Default P2P QUIC port (configuration.md §3).
pub const P2P_PORT: u16 = 9474;

// ── Transport (QUIC) ─────────────────────────────────────────────────

/// QUIC keep-alive interval in seconds (network-protocol.md §2.1).
/// Primitive: half of QUIC idle timeout to keep NAT mappings alive.
pub const QUIC_KEEPALIVE_INTERVAL_SECS: u64 = 15;

/// QUIC max idle timeout in seconds (network-protocol.md §2.1).
/// Primitive: 4x QUIC keepalive; tolerates 3 lost keepalives before closing.
pub const QUIC_MAX_IDLE_TIMEOUT_SECS: u64 = 60;

/// Most bidirectional QUIC streams a peer may have open on one connection
/// at once (network-protocol.md §2.1): MAX_CONCURRENT_STREAMS. A node
/// handles one stream of a connection at a time, and each exchange is one
/// stream, so real use is a handful.
pub const QUIC_MAX_BIDI_STREAMS: u32 = MAX_CONCURRENT_STREAMS as u32;

/// Unidirectional QUIC streams a peer may open: none. The protocol uses
/// only bidirectional ones.
pub const QUIC_MAX_UNI_STREAMS: u32 = 0;

/// How much a peer may send on one stream before this node has read it:
/// one message.
pub const QUIC_STREAM_RECEIVE_WINDOW: u32 = MAX_MESSAGE_BYTES;

/// How much a peer may send on one connection, over all its streams,
/// before this node has read it: two messages. This is what bounds the
/// memory one connection can make a node hold. Left to QUIC's defaults
/// there was no such bound: a thousand streams, each over a megabyte.
pub const QUIC_RECEIVE_WINDOW: u32 = 2 * MAX_MESSAGE_BYTES;

/// TLS certificate validity in days (network-protocol.md §2.2).
/// Primitive: 1 year; self-signed certs, identity is the public key.
pub const TLS_CERT_VALIDITY_DAYS: i64 = 365;

// ══════════════════════════════════════════════════════════════════════
// TIMING PRIMITIVES -- the small set of values everything else derives from
// ══════════════════════════════════════════════════════════════════════

/// Timeout for all QUIC stream read/write operations in seconds (parameter-rationale.md §6).
/// Primitive: single-digit-second responsiveness; covers cross-continent RTT + processing.
/// One value, one layer (codec). If a single read or write takes longer, the peer is unresponsive.
pub const STREAM_TIMEOUT_SECS: u64 = 10;

/// How long a node that is told to stop waits for its parts to finish, in
/// all, before it exits without them (parameter-rationale.md §6).
/// Derived: three stream timeouts. The HTTP server gives a request it is
/// answering one to finish, and the peer-to-peer loop gives its peers one
/// to hear that it is closing, side by side; the rest is margin. A node
/// that waited for ever for one of its parts would be killed by systemd
/// after a minute and a half, and an upgrade would take that long.
pub const NODE_STOP_TIMEOUT_SECS: u64 = 3 * STREAM_TIMEOUT_SECS;

/// Governor tick interval in seconds (network-behaviour.md §5.1).
/// Primitive: resolution of the governor state machine. Matches stream timeout --
/// no point ticking faster than we can complete a stream operation.
pub const TICK_INTERVAL_SECS: u64 = 10;

/// Application-level ping interval in seconds (network-protocol.md §4.2).
/// Primitive: 3x tick interval; frequent enough to detect failures quickly,
/// rare enough to not generate excessive traffic.
pub const PING_INTERVAL_SECS: u64 = 30;

/// Number of missed pings before peer is considered dead (network-protocol.md §4.2).
/// Primitive: 3 strikes; tolerates 1 lost packet + 1 delayed packet before declaring dead.
pub const DEAD_THRESHOLD: u64 = 3;

/// Churn rotation interval in seconds (parameter-rationale.md §3).
/// Primitive: 1 hour; balances anti-Sybil rotation against connection stability.
/// Shorter = more resilient to long-lived attackers but more connection churn.
pub const CHURN_INTERVAL_SECS: u64 = 3600;

/// Peer-sharing request interval in seconds (network-protocol.md §4.3).
/// Primitive: 5 minutes; enough time for a peer to prove itself through
/// one full discovery round before the next one starts.
pub const PEER_SHARE_INTERVAL_SECS: u64 = 300;

/// Relay re-push flush interval in seconds.
/// Primitive: 5s; near-real-time forwarding with effective batching.
/// Items from multiple sources within the window are de-duped by item_id
/// and sent as one push stream per peer. Shorter (1s) batches less
/// effectively. Longer (30s) adds noticeable delivery latency.
pub const REPUSH_INTERVAL_SECS: u64 = 5;

/// Rate limit headroom multiplier.
/// All per-peer rate limits are set to 3x the expected legitimate rate.
/// Allows burst tolerance (reconnect catch-up, publish spikes) while
/// catching sustained abuse (4x+ over a sliding window = clearly malicious).
pub const RATE_LIMIT_HEADROOM: u32 = 3;

// ══════════════════════════════════════════════════════════════════════
// DERIVED TIMING -- all traceable to the primitives above
// ══════════════════════════════════════════════════════════════════════

// ── Keepalive ────────────────────────────────────────────────────────

/// Dead timeout in seconds (network-protocol.md §4.2).
/// Derived: PING_INTERVAL * DEAD_THRESHOLD. 3 missed pings = dead.
pub const DEAD_TIMEOUT_SECS: u64 = PING_INTERVAL_SECS * DEAD_THRESHOLD;

// ── Handshake ────────────────────────────────────────────────────────

/// Handshake timeout in seconds (network-protocol.md §4.1.3).
/// Derived: handshake is a stream operation; same timeout applies.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = STREAM_TIMEOUT_SECS;

/// Maximum clock skew tolerance in seconds (network-protocol.md §4.1.5).
/// Primitive: 5 minutes; generous NTP drift tolerance for poorly-synced nodes.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

// ── Governor timing ──────────────────────────────────────────────────

/// Hysteresis duration in seconds to prevent rapid state oscillation (parameter-rationale.md §3).
/// Derived: same window as dead detection. A peer must be stable for
/// the full dead-detection window before we allow a state transition.
pub const HYSTERESIS_SECS: u64 = DEAD_TIMEOUT_SECS;

/// Anti-Sybil: minimum time in Warm before Hot promotion in seconds (parameter-rationale.md §3).
/// Bypassed when hot < hot_min (bootstrap urgency).
/// Derived: must survive 1 full peer-share cycle to prove stability.
pub const MIN_WARM_TENURE_SECS: u64 = PEER_SHARE_INTERVAL_SECS;

/// Churn jitter range in seconds (parameter-rationale.md §3).
/// Derived: spread churn events across 1 peer-share window so nodes
/// don't all rotate simultaneously.
pub const CHURN_JITTER_SECS: u64 = PEER_SHARE_INTERVAL_SECS;

/// Time without activity before a peer is considered stale in seconds (parameter-rationale.md §3).
/// Derived: detect staleness halfway through a churn cycle so we can
/// clean up before the next churn event fires.
pub const STALE_THRESHOLD_SECS: u64 = CHURN_INTERVAL_SECS / 2;

// ── Rate limiting windows ────────────────────────────────────────────

/// Sliding window for rate counters in seconds.
/// Derived: 6 governor ticks. Long enough to smooth bursts,
/// short enough for responsive rate limiting.
pub const RATE_WINDOW_SECS: u64 = 6 * TICK_INTERVAL_SECS;

/// Window for counting rate limit breaches in seconds.
/// Derived: 10 rate windows. Longer window means a peer needs
/// sustained misbehaviour (not just a burst) to trigger a ban.
pub const BAN_WINDOW_SECS: u64 = 10 * RATE_WINDOW_SECS;

// ── Backoff ──────────────────────────────────────────────────────────

/// Reconnect backoff base duration in seconds (parameter-rationale.md §3).
/// Derived: start at 1 ping interval. If we can't connect in the time
/// it takes to send one ping, back off.
pub const BACKOFF_BASE_SECS: u64 = PING_INTERVAL_SECS;

/// Delay before clearing failure state in seconds (configuration.md §3).
/// Derived: 4 ping cycles. Enough time for a transient issue to resolve.
pub const CLEAR_FAILURE_DELAY_SECS: u64 = 4 * PING_INTERVAL_SECS;

/// Backoff saturation: stops doubling after this many disconnects (parameter-rationale.md §3).
/// Primitive: 5 doublings gives base * 32 = 960s max before the ban-derived cap.
pub const BACKOFF_SATURATION: u32 = 5;

/// Maximum connection retries before giving up (configuration.md §3).
/// Primitive: 5 attempts; matches backoff saturation by convention.
pub const MAX_CONNECTION_RETRIES: u32 = 5;

// ── Ban tiers (parameter-rationale.md §3) ────────────────────────────

/// Transient ban: rate limit breach, protocol violation (seconds).
/// Derived: miss 3 peer-share rounds. Enough time to cool off
/// without permanently excluding a misbehaving-but-honest peer.
pub const BAN_TRANSIENT_SECS: u64 = 3 * PEER_SHARE_INTERVAL_SECS;

/// Maximum reconnect backoff in seconds (parameter-rationale.md §3).
/// Derived: capped at transient ban duration. No point backing off
/// longer than the shortest possible ban.
pub const BACKOFF_MAX_SECS: u64 = BAN_TRANSIENT_SECS;

/// Identity ban: identity/PSK fraud (seconds).
/// Derived: 1 full churn cycle. The peer set will have rotated
/// by the time the ban expires.
pub const BAN_IDENTITY_SECS: u64 = CHURN_INTERVAL_SECS;

/// Systematic ban: systematic abuse (seconds).
/// Derived: 8 churn cycles. Serious enough to survive multiple
/// peer set rotations.
pub const BAN_SYSTEMATIC_SECS: u64 = 8 * CHURN_INTERVAL_SECS;

/// Number of rate limit breaches before ban.
/// Primitive: 3 strikes; tolerates clock skew and burst patterns
/// before escalating to a ban.
pub const BAN_THRESHOLD: u32 = 3;

// ── Governor scoring (network-behaviour.md §5.5) ─────────────────────

/// Fraction of warm peers to promote per churn cycle (parameter-rationale.md §3).
/// Primitive: rotate 20% per cycle; gradual turnover without disrupting connectivity.
pub const CHURN_FRACTION: f64 = 0.2;

/// Exponential moving average alpha for peer scoring (parameter-rationale.md §3).
/// Primitive: 10% weight on current score, 90% on history. Slow-moving average
/// prevents a single good/bad interaction from dominating the score.
pub const EMA_ALPHA: f64 = 0.1;

/// RTT normalisation denominator in ms. Score formula: 1 / (1 + rtt_ms / DENOM).
/// Primitive: 100ms is the reference RTT. A 100ms peer scores 0.5x a local peer.
/// Chosen as typical cross-region latency.
pub const SCORE_RTT_DENOMINATOR_MS: f64 = 100.0;

/// Default RTT factor when RTT is unknown (no measurement yet).
/// Derived: equals 1/(1+1) = 0.5; assumes unknown RTT is equivalent to the
/// reference RTT. Neither penalised nor favoured until measured.
pub const SCORE_RTT_DEFAULT_FACTOR: f64 = 0.5;

/// Minimum relay contribution factor (floor for non-contributing relays).
/// Primitive: 10% floor. Even a non-contributing relay keeps minimal score
/// to avoid thrashing connections; it's still providing connectivity.
pub const SCORE_CONTRIBUTION_MIN: f64 = 0.1;

/// Maximum relay contribution factor (cap for high-contributing relays).
/// Primitive: 2x cap. High-contributing relays get a bonus but can't
/// dominate the score to the point where other factors are irrelevant.
pub const SCORE_CONTRIBUTION_MAX: f64 = 2.0;

/// Maximum ban duration after escalation: 7 days.
/// Primitive: absolute calendar-time cap. Even systematic abuse doesn't
/// result in permanent exclusion; the peer can try again after a week.
pub const BAN_ESCALATION_CAP_SECS: u64 = 7 * 24 * 3600;

// ── Governor defaults (personal node, demand-model.md §3.2) ─────────

/// Minimum hot peers (parameter-rationale.md §3).
/// Primitive: 2 provides redundancy; 1 would be a single point of failure.
pub const HOT_MIN: u32 = 2;

/// Maximum hot peers for personal node (parameter-rationale.md §3).
/// Primitive: 2 for personal nodes; minimises resource use for devices
/// that only need to reach 1-2 relays.
pub const HOT_MAX: u32 = 2;

/// Minimum hot relay peers (parameter-rationale.md §3).
/// Primitive: at least 1 relay in hot set ensures items can be pushed
/// to the relay mesh.
pub const HOT_MIN_RELAYS: u32 = 1;

/// Minimum warm peers (parameter-rationale.md §3).
/// Primitive: 3 warm peers provides a promotion buffer when a hot peer
/// disconnects. Must exceed HOT_MIN to allow selection.
pub const WARM_MIN: u32 = 3;

/// Maximum warm peers for personal node (parameter-rationale.md §3).
/// Primitive: 10 warm peers balances discovery breadth against memory
/// and keepalive traffic.
pub const WARM_MAX: u32 = 10;

/// Maximum cold peers for personal node (parameter-rationale.md §3).
/// Primitive: 50 cold peers; address book for future warm promotion.
/// Low cost (no active connections).
pub const COLD_MAX: u32 = 50;

// ── Size limits ──────────────────────────────────────────────────────

/// Maximum wire message size: 1 MB (parameter-rationale.md §5.2).
/// Primitive: 1MB frame fits 4 max-size items. Large enough for batch
/// operations, small enough to bound memory per connection.
pub const MAX_MESSAGE_BYTES: u32 = 1_048_576;

/// The size every entry must fit in as it travels: 64 KB of ciphertext
/// (parameter-rationale.md §4). One small size for everything, checked by
/// the sender, by each relay and by the device that receives it. Small
/// entries are what let limits on rate and storage mean something.
pub const MAX_ITEM_BYTES: usize = 65_536;

/// What sealing adds to an entry's content: the nonce and the tag of
/// AES-256-GCM. An entry's content can be at most MAX_ITEM_BYTES less this.
pub const ITEM_SEAL_OVERHEAD_BYTES: usize = 12 + 16;

/// The most an entry takes beyond its ciphertext, as it travels and where
/// it is stored: its IDs, hash, author, signature, time and name, and its
/// row and place in each index (parameter-rationale.md §4).
///
/// Every field of an entry has a size it must fit in (below), so this is a
/// bound and not a guess. And every limit on bytes counts an entry as its
/// ciphertext plus this ([`entry_cost`]): without it a thousand entries of
/// three bytes would count as three kilobytes, and a limit on bytes would
/// limit nothing that is small.
pub const ENTRY_OVERHEAD_BYTES: usize = 1024;

/// What one entry with `ciphertext` bytes of ciphertext counts as, against
/// every limit on bytes: a relay's allowance for a connection and for an
/// address, what one channel may hold at a relay, and what a device sends
/// in one push and in one minute.
pub const fn entry_cost(ciphertext: usize) -> u64 {
    (ciphertext + ENTRY_OVERHEAD_BYTES) as u64
}

/// The most an entry's ID may be, in bytes. IDs are `ci_` and 26
/// characters.
pub const MAX_ITEM_ID_LEN: usize = 64;

/// The most a channel's ID may be, in bytes. The longest kind is an inbox:
/// `inbox_` and 64 characters.
pub const MAX_CHANNEL_ID_LEN: usize = 96;

/// The most an entry's type may be, in bytes (`memory`, `invite`, ...).
pub const MAX_ITEM_TYPE_LEN: usize = 32;

/// The most an entry's time may be, in bytes. An RFC 3339 time with
/// nanoseconds and an offset is 35.
pub const MAX_TIMESTAMP_LEN: usize = 40;

// Checked at compile time: the fields of the largest entry, with what
// encoding them adds (their names and lengths, 256 bytes), fit in the
// overhead.
const _: () = assert!(
    2 * MAX_ITEM_ID_LEN      // the entry's ID, and its parent's
        + MAX_CHANNEL_ID_LEN
        + MAX_ITEM_TYPE_LEN
        + MAX_TIMESTAMP_LEN
        + 32 + 32 + 64 + 32  // hash, author, signature, name
        + 3 * 9 + 2          // key version, revision, length; two flags
        + 256
        <= ENTRY_OVERHEAD_BYTES
);

/// Whether an entry's fields other than its ciphertext are each within the
/// size they must fit in. With the limit on ciphertext this makes an entry
/// one size at most, whatever it carries: MAX_ITEM_BYTES and
/// ENTRY_OVERHEAD_BYTES. The other fields are of fixed size.
pub fn entry_fields_fit(
    item_id: &str,
    channel_id: &str,
    item_type: &str,
    published_at: &str,
    parent_id: Option<&str>,
) -> bool {
    entry_field_over(item_id, channel_id, item_type, published_at, parent_id).is_none()
}

/// The first of an entry's fields that is over the size it must fit in,
/// by name and with that size in bytes, if any is.
pub fn entry_field_over(
    item_id: &str,
    channel_id: &str,
    item_type: &str,
    published_at: &str,
    parent_id: Option<&str>,
) -> Option<(&'static str, usize)> {
    if item_id.len() > MAX_ITEM_ID_LEN {
        Some(("ID", MAX_ITEM_ID_LEN))
    } else if channel_id.len() > MAX_CHANNEL_ID_LEN {
        Some(("channel", MAX_CHANNEL_ID_LEN))
    } else if item_type.len() > MAX_ITEM_TYPE_LEN {
        Some(("type", MAX_ITEM_TYPE_LEN))
    } else if published_at.len() > MAX_TIMESTAMP_LEN {
        Some(("time", MAX_TIMESTAMP_LEN))
    } else if parent_id.is_some_and(|parent| parent.len() > MAX_ITEM_ID_LEN) {
        Some(("parent", MAX_ITEM_ID_LEN))
    } else {
        None
    }
}

/// Maximum items per batch fetch (demand-model.md §3.1).
/// Primitive: 100 items per batch; balances throughput against memory
/// pressure and response latency.
pub const MAX_BATCH_SIZE: usize = 100;

/// Maximum items per listen query (channels-api.md §3).
/// Primitive: 500 items per query; API pagination limit.
pub const MAX_LISTEN_LIMIT: u32 = 500;

/// Maximum serialized descriptor size in bytes (network-protocol.md §4.4.6).
/// Primitive: 512 bytes for channel metadata (name + conditions + signature).
pub const MAX_DESCRIPTOR_SIZE: usize = 512;

/// Maximum channel name length (network-protocol.md §4.4.6).
/// Standard: RFC 1035 DNS label length limit.
pub const MAX_CHANNEL_NAME_LEN: usize = 63;

/// Default max storage per node: 1 GB (configuration.md §3).
/// Primitive: default storage budget per node; configurable.
pub const MAX_STORAGE_BYTES: u64 = 1_073_741_824;

/// How long local history keeps the text sync replaced or removed: 30
/// days (parameter-rationale.md §10). Configurable; 0 turns history off.
pub const HISTORY_DAYS: u32 = 30;

/// The most local history holds: 256 MB. Over that the oldest records go
/// first (parameter-rationale.md §10). Configurable.
pub const HISTORY_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// How long a history command waits for a sync cycle that is running
/// before it says the node is busy: 10 s (parameter-rationale.md §10).
pub const HISTORY_TURN_WAIT_SECS: u64 = 10;

/// How often local history drops what is too old or over its size: every
/// hour that the machine is awake, and when the node starts
/// (parameter-rationale.md §10).
pub const HISTORY_SWEEP_INTERVAL_SECS: u64 = 3600;

/// And sooner, at the end of a sync cycle, once more than one part in
/// this many of the most it holds has been kept since it was last swept:
/// an eighth (parameter-rationale.md §10).
pub const HISTORY_SWEEP_SHARE: u64 = 8;

/// The most one channel may hold at a relay: 16 MB. A channel is cheap to
/// make, so the relay's total is what bounds storage; this keeps one
/// channel from being most of it. Rationale: parameter-rationale.md §4.
pub const MAX_CHANNEL_BYTES_AT_RELAY: u64 = 16 * 1024 * 1024;

/// How many channels one address may make a relay hold for the first time
/// in an hour. Rationale: parameter-rationale.md §4.
pub const NEW_CHANNELS_PER_ADDRESS_PER_HOUR: usize = 16;

// ── Connection limits (network-protocol.md §9.1) ────────────────────

/// Maximum inbound connections.
/// Primitive: 200 connections; system resource budget for a relay.
pub const MAX_INBOUND_CONNECTIONS: usize = 200;

/// Maximum connections from a single IP.
/// Primitive: 5 per IP; anti-Sybil. Legitimate use rarely exceeds 2-3.
pub const MAX_CONNECTIONS_PER_IP: usize = 5;

/// Maximum connections from a single /24 (IPv4) or /48 (IPv6) subnet.
/// Primitive: 20 per subnet; anti-Sybil at the network level.
pub const MAX_CONNECTIONS_PER_SUBNET: usize = 20;

/// Maximum concurrent QUIC streams per connection.
/// Primitive: 64 concurrent streams; bounds per-peer resource use.
pub const MAX_CONCURRENT_STREAMS: usize = 64;

// ── Rate limits (network-protocol.md §9.2) ──────────────────────────

/// Write operations per peer per minute.
/// Derived: 3x the expected relay repush rate. A relay flushes batched
/// items every REPUSH_INTERVAL_SECS, so expected rate = 60/5 = 12/min.
/// 3x headroom → 36. Allows burst tolerance without triggering bans.
pub const WRITES_PER_PEER_PER_MINUTE: u32 =
    RATE_LIMIT_HEADROOM * (60 / REPUSH_INTERVAL_SECS) as u32;

/// How many bytes of entries one connection may push in a minute: 2 MB.
/// The count of pushes alone bounds little, since a push can be a whole
/// message. Rationale: parameter-rationale.md §4.
pub const PUSH_BYTES_PER_PEER_PER_MINUTE: u64 = 2 * 1024 * 1024;

/// The room that a pull leaves for the answer to a show, in the bytes
/// that a key and its address may be handed in a minute: what one entry
/// of the largest size is counted at (decision 2026-10-04 §16). A relay
/// sizes a page of a channel so that this much is left in both
/// allowances, and only the entry that answers a show may use it: a
/// device that pulls at its full rate, or shares its address with one
/// that does, is still told of a removal.
/// Derived: entry_cost(MAX_ITEM_BYTES).
pub const SHOW_ANSWER_ROOM_BYTES: u64 = entry_cost(MAX_ITEM_BYTES);
// A whole page can still be handed beside it.
const _: () = assert!(SHOW_ANSWER_ROOM_BYTES < PUSH_BYTES_PER_PEER_PER_MINUTE / 2);

/// How many bytes of entries a device pushes to one relay in a minute, at
/// most: 1.5 MB, which leaves a quarter of a relay's allowance spare. A
/// device with a lot to send paces itself, so that it is never the one
/// refused.
pub const OUTBOX_BYTES_PER_MINUTE: u64 = 3 * 512 * 1024;
const _: () = assert!(OUTBOX_BYTES_PER_MINUTE < PUSH_BYTES_PER_PEER_PER_MINUTE);
const _: () = assert!(OUTBOX_BATCH_MAX_BYTES as u64 <= OUTBOX_BYTES_PER_MINUTE);

/// How often a personal node flushes its outbox: its own items that no
/// relay has yet acknowledged, sent as one batched push (decision
/// 2026-09-30-agent-memory-sync §4.4a).
/// Derived: the fastest cadence within a relay's per-peer write limit,
/// 60 / WRITES_PER_PEER_PER_MINUTE = 1.67s, rounded up to 2s (30 pushes/min
/// against 36). One push per interval however many items were written, so
/// a burst of writes can never trip the relay's limit.
pub const OUTBOX_FLUSH_INTERVAL_SECS: u64 = 2;

/// The longest an outbox item that a relay refused waits before it is
/// offered again (to the next relay in turn). The wait doubles from the
/// flush interval after each refusal, so an item no relay will take costs
/// one small push every ten minutes, and one that a relay refused for a
/// passing reason (a full disk) is delivered soon after the reason goes.
/// Rationale: parameter-rationale.md §4.
pub const OUTBOX_REFUSED_RETRY_MAX_SECS: u64 = 600;

/// How long a relay waits before it asks a device again which channels it
/// holds, and before it takes again a channel it dropped to make room.
///
/// A device sends what it writes as it writes it, so a relay asks only for
/// what it lost, dropped or had no room for. The wait is the one a device
/// keeps before it offers again what a relay refused: whichever of the two
/// has the entry, the other hears of it in about ten minutes.
/// Rationale: parameter-rationale.md §4.
pub const RELAY_ASK_AGAIN_SECS: u64 = OUTBOX_REFUSED_RETRY_MAX_SECS;

/// How many times the wait before a relay takes again a channel it dropped
/// may double. A channel that is dropped again each time it is taken does
/// not fit: the wait grows from RELAY_ASK_AGAIN_SECS to 32 times that (over
/// five hours), so that trying it costs less and less.
pub const RELAY_DROPPED_WAIT_DOUBLINGS: u32 = 5;

/// The most channels a relay asks one peer about in one pass, of those the
/// peer lists. The list is the peer's to write: without a bound it could
/// have a relay make a request, and keep a place, for each of any number
/// of names. A person's device holds tens of channels. One that holds more
/// than this is asked about a different part of them each time.
/// Rationale: parameter-rationale.md §4.
pub const MAX_CHANNELS_ASKED_OF_A_PEER: usize = 1024;

/// The most one outbox push may cost ([`entry_cost`]): three entries of
/// the largest size. Well below MAX_MESSAGE_BYTES, so that the message
/// limit can come down to 256 KB once every node sends batches this small.
pub const OUTBOX_BATCH_MAX_BYTES: usize = 3 * (MAX_ITEM_BYTES + ENTRY_OVERHEAD_BYTES);

/// Most items in one outbox push. The cost of a push bounds it sooner: a
/// push of the smallest entries holds fewer than 200.
pub const OUTBOX_BATCH_MAX_ITEMS: usize = 500;

// Checked at compile time: one push per flush interval stays within a
// relay's write limit, and a full batch plus framing fits in one message.
const _: () = assert!(OUTBOX_FLUSH_INTERVAL_SECS * WRITES_PER_PEER_PER_MINUTE as u64 >= 60);
const _: () = assert!(OUTBOX_BATCH_MAX_BYTES + 128 * 1024 <= MAX_MESSAGE_BYTES as usize);
const _: () = assert!(MAX_ITEM_BYTES + ENTRY_OVERHEAD_BYTES <= OUTBOX_BATCH_MAX_BYTES);
const _: () = assert!(BOOTNODE_RESOLVE_RETRY_SECS < BOOTNODE_RESOLVE_INTERVAL_SECS);

/// Write operations per channel per minute.
/// Primitive: 100 writes/min aggregate across all peers.
/// A busy channel with 10 writers each at the per-peer limit.
pub const WRITES_PER_CHANNEL_PER_MINUTE: u32 = 100;

/// Sync requests per peer per minute.
/// Derived: 3x the expected rate (1 sync per governor tick in a rate window).
/// Expected = RATE_WINDOW_SECS / TICK_INTERVAL_SECS = 6. With 3x → 18.
pub const SYNCS_PER_PEER_PER_MINUTE: u32 =
    RATE_LIMIT_HEADROOM * (RATE_WINDOW_SECS / TICK_INTERVAL_SECS) as u32;

/// Peer-share requests per peer per minute.
/// Derived: 3x the expected rate (1 peer-share per ping interval in a rate window).
/// Expected = RATE_WINDOW_SECS / PING_INTERVAL_SECS = 2. With 3x → 6.
/// Side effect: sender-side cooldown drops from 30s to 10s, accelerating
/// mesh discovery during bootstrap.
pub const PEER_SHARES_PER_PEER_PER_MINUTE: u32 =
    RATE_LIMIT_HEADROOM * (RATE_WINDOW_SECS / PING_INTERVAL_SECS) as u32;

// ── Intervals ────────────────────────────────────────────────────────

/// Realtime channel sync interval in seconds (network-protocol.md §4.5).
/// Derived: 2x REPUSH_INTERVAL_SECS. Pull-sync is the primary delivery
/// mechanism for personal nodes. Interval gives relays time to propagate
/// items via single-hop repush before personal nodes pull.
pub const REALTIME_SYNC_INTERVAL_SECS: u64 = 2 * REPUSH_INTERVAL_SECS;

/// Batch channel sync interval in seconds (network-protocol.md §4.5).
/// Derived: same as transient ban duration. Batch channels tolerate
/// delay; syncing more often wastes bandwidth on low-priority data.
pub const BATCH_SYNC_INTERVAL_SECS: u64 = BAN_TRANSIENT_SECS;

/// Channel reconciliation interval in seconds (network-protocol.md §4.4.2).
/// Derived: same cadence as peer discovery. Reconcile channel state
/// every time we might discover new peers.
pub const CHANNEL_RECONCILIATION_INTERVAL_SECS: u64 = PEER_SHARE_INTERVAL_SECS;

/// Responder stagger offset for reconciliation in seconds (network-protocol.md §4.4.2).
/// Derived: half a peer-share cycle. Staggers reconciliation requests
/// so both sides don't initiate simultaneously.
pub const CHANNEL_RESPONDER_OFFSET_SECS: u64 = PEER_SHARE_INTERVAL_SECS / 2;

// ── Replication ──────────────────────────────────────────────────────

/// Default sync limit (max headers per response, network-protocol.md §4.5).
/// Primitive: 100 headers per response; matches MAX_BATCH_SIZE.
pub const DEFAULT_SYNC_LIMIT: u32 = 100;

/// How many entries a node asks a peer to list in one page, and so fetch
/// in one request. It starts with the first number. A page's entries come
/// back in one message, and a hundred large ones do not fit in it, so
/// when a fetch fails the node asks for the next number down, for that
/// peer and channel, until it has caught up there:
///
/// - 14: fourteen entries of the largest size fit in one message.
/// - 3: entries written before 0.2.0-alpha.4 could be 256 KB.
/// - 1: whatever is left.
///
/// Without this a channel with more than a message's worth of entries in
/// one page could never be fetched: the same request failed for ever.
pub const SYNC_PAGE_STEPS: [u32; 4] = [DEFAULT_SYNC_LIMIT, 14, 3, 1];

// Checked at compile time: fourteen entries of the largest size, with
// what each takes beyond its ciphertext, fit in one message; so do three
// old ones.
const _: () = assert!(14 * (MAX_ITEM_BYTES + ENTRY_OVERHEAD_BYTES) <= MAX_MESSAGE_BYTES as usize);
const _: () = assert!(3 * (262_144 + ENTRY_OVERHEAD_BYTES) <= MAX_MESSAGE_BYTES as usize);

/// Max items per fetch request (network-protocol.md §4.5).
/// Primitive: 100 items; matches MAX_BATCH_SIZE.
pub const MAX_FETCH_ITEMS: usize = 100;

/// Default max peers per peer-sharing response (network-protocol.md §4.3).
/// Primitive: 20 peers per response; enough for mesh discovery without
/// enabling address-space enumeration.
pub const DEFAULT_MAX_PEERS_SHARE: u16 = 20;

/// How long a deleted key's tombstone is kept (decision 2026-09-30 §4.4).
/// Primitive: 90 days. When a key's newest revision is a tombstone older
/// than this, every node drops the key's whole slot history. A device
/// offline for longer than this can bring a deleted file back with a stale
/// edit; 90 days covers a laptop left in a drawer for a season.
///
/// It is also how long a delete is held among the entries of a channel
/// from its secret, at a relay and in a device's own store (decision
/// 2026-10-04 §2.3, §7.3), counted from when the node stored the entry:
/// a delete that is carried at a statement is a new entry, and starts
/// again.
pub const KEYED_TOMBSTONE_RETENTION_DAYS: u32 = 90;

/// The index line of a memory that a device deleted (decision 2026-09-30
/// §4.5). Primitives:
///
/// - The two halves of a record (the line removed from the index, and the
///   file's delete) are one deletion if they are published within an hour
///   of each other. A person or an agent that deletes a memory removes
///   both in one go; the hour covers a node that was stopped in between.
/// - A whole record lasts as long as a delete is kept: after that the
///   delete it answers to is gone from every node.
/// - A folder keeps at most 1,024 records: a bound on a table that an
///   agent's edits fill. Past it a record goes for each new one, and
///   never the one just written.
/// - A line is put back at most three times for one record: twice past
///   the first, for a merge that takes it out again, and no more, so that
///   two devices cannot go on undoing each other.
/// - A line is put back once it has been due at every look for a minute,
///   the looks no more than 30 seconds apart: a device that is in step has
///   merged a tie on the index within about half a minute.
pub const INDEX_LINE_PAIR_SECS: i64 = 60 * 60;
pub const INDEX_LINE_KEPT_DAYS: u32 = KEYED_TOMBSTONE_RETENTION_DAYS;
pub const INDEX_LINE_MAX_RECORDS: usize = 1024;
pub const INDEX_LINE_MAX_PUT_BACKS: u32 = 3;
pub const INDEX_LINE_LOOK_SECS: i64 = 60;
pub const INDEX_LINE_LOOK_GAP_SECS: i64 = 30;

/// The largest revision an entry may carry: 2^53 - 1.
/// A revision is chosen by whoever writes the entry. Unbounded, one writer
/// could set it so high that the next revision overflows and the name can
/// never be written again. This bound is exact in a signed 64-bit column
/// and as a JSON number, and is checked wherever an entry is verified.
/// Rationale: parameter-rationale.md §4.
pub const MAX_REV: u64 = (1 << 53) - 1;

/// The largest membership epoch a channel state may carry: 2^53 - 1, for
/// the same reason as [`MAX_REV`].
pub const MAX_EPOCH: u64 = (1 << 53) - 1;

/// How far a channel's membership epoch may move in one state. A state
/// carries the whole list, so skipping epochs is harmless and happens when
/// a device was offline, but a member must not be able to jump straight to
/// [`MAX_EPOCH`] and so stop the list from ever changing again. At this
/// step that takes 2^33 states. Rationale: parameter-rationale.md §4.
pub const MAX_EPOCH_STEP: u64 = 1 << 20;

/// How far a channel's key version may move in one state, and the most
/// keys a state's key ring may hold. A removal moves the version by one.
/// A device that was away may have missed some, so a state may skip
/// versions, but never more than this, and never more than its epoch
/// moved. Without a bound a member could send the largest version there
/// is, after which no key could follow it and no device could be removed.
pub const MAX_STATE_KEYS: usize = 1024;

/// How long after a channel state was sent to a member it is offered again,
/// if the member has not been seen to hold it: this long after the first
/// time, doubling after each offer, up to STATE_OFFER_RETRY_MAX_SECS.
/// Rationale: parameter-rationale.md §4.
pub const STATE_OFFER_RETRY_BASE_SECS: u64 = 60;

/// The longest wait between two offers of the same channel state. A member
/// that is away for weeks is offered it four times a day, each a push of
/// one small item that a relay which already has it answers at once.
pub const STATE_OFFER_RETRY_MAX_SECS: u64 = 6 * 3600;

/// How often nodes collect expired keyed tombstones. Hourly is plenty
/// against a 90-day retention.
pub const TOMBSTONE_GC_INTERVAL_SECS: u64 = 3600;

/// Tombstone retention in days (data-formats.md §4).
/// Primitive: 7 days; ensures offline nodes can sync deletions
/// when they come back online within a week.
pub const TOMBSTONE_RETENTION_DAYS: u32 = 7;

// ── Seen table (network-protocol.md §7.2) ────────────────────────────

/// Maximum seen table entries (network-protocol.md §7.2).
/// Primitive: 10,000 items in flight. At 12 items/min per relay,
/// this covers ~14 hours of unique items before eviction.
pub const SEEN_TABLE_MAX: usize = 10_000;

/// Seen table TTL in seconds (network-protocol.md §7.2).
/// Derived: 2x the slowest convergence path (5 hops × 5s repush = 25s).
/// 10 minutes gives 24x margin for delayed or partitioned relays.
pub const SEEN_TABLE_TTL_SECS: u64 = 600;

// ── Queue capacities (network-protocol.md §9.4) ─────────────────────

/// Handshake queue capacity.
pub const QUEUE_HANDSHAKE: usize = 16;

/// Keepalive queue capacity.
pub const QUEUE_KEEPALIVE: usize = 256;

/// Peer-sharing queue capacity.
pub const QUEUE_PEER_SHARING: usize = 32;

/// Channel-announce queue capacity.
pub const QUEUE_CHANNEL_ANNOUNCE: usize = 64;

/// Item-sync queue capacity.
pub const QUEUE_ITEM_SYNC: usize = 64;

/// Item-push queue capacity.
pub const QUEUE_ITEM_PUSH: usize = 128;

// ── Error codes ──────────────────────────────────────────────────────

/// QUIC application error: unknown protocol byte (network-protocol.md §3.3).
pub const ERR_UNKNOWN_PROTOCOL: u32 = 0x02;

/// QUIC application error: connection capacity exceeded (network-protocol.md §9.1).
pub const ERR_CAPACITY: u32 = 0x01;

/// QUIC application error: over a rate limit. A stream is reset with it
/// when a request is over the limit, and the connection is closed with it
/// when the peer keeps going over.
pub const ERR_RATE_LIMIT: u32 = 0x03;

// ── Bootstrap ────────────────────────────────────────────────────────

/// The default relays, compiled into the binary (decision
/// 2026-09-30-agent-memory-sync §4.6): the names a personal node dials when
/// its configuration names no relay of its own.
pub const FALLBACK_PEERS: &[&str] = &[
    "relay1.cordelia.seeddrill.ai:9474",
    "relay2.cordelia.seeddrill.ai:9474",
];

/// The default relays' public keys, in the order of [`FALLBACK_PEERS`]. A
/// node refuses any other key at a default relay's address, so answering
/// for a relay's name is not enough to be taken for it.
pub const FALLBACK_PEER_KEYS: &[&str] = &[
    "cordelia_pk13n2p54r4fldfj5hdxr75s9dzc97q5rtdx5vh275yh0tctd94kqxqeaf5vd",
    "cordelia_pk1vpejd4yjphh4dr486ljnys7egyxlsffkeamsfeakegqs5zplqljskydjgh",
];

const _: () = assert!(FALLBACK_PEERS.len() == FALLBACK_PEER_KEYS.len());

/// How often a node looks up its bootnodes' names again, so the addresses
/// it retries follow DNS (a relay moved, or a site's address changed).
pub const BOOTNODE_RESOLVE_INTERVAL_SECS: u64 = 300;

/// How often a node refreshes its record that a connected peer is still
/// there (`cordelia_storage::usage`), and how long a peer is remembered
/// after it was last seen: one day more than the weekly count needs.
pub const SIGHTING_REFRESH_SECS: u64 = 300;
pub const SIGHTING_RETENTION_DAYS: i64 = 8;

/// How often it tries instead while none of the names resolves: a node
/// started before its network was up finds its relays soon after.
pub const BOOTNODE_RESOLVE_RETRY_SECS: u64 = 30;

// ── PSK exchange reasons (network-protocol.md §4.7) ──────────────────

/// PSK denial: channel not found.
pub const REASON_NOT_FOUND: &str = "not_found";

/// PSK denial: not authorized for this channel.
pub const REASON_NOT_AUTHORIZED: &str = "not_authorized";

/// PSK denial: PSK temporarily unavailable.
pub const REASON_NOT_AVAILABLE: &str = "not_available";

// ── A channel from its secret (decision 2026-10-04) ──────────────────

/// How many bits of a revision are its count (decision 2026-10-04 §2.3).
/// A revision is one number, compared as one, and editing adds one to it.
/// Its low 44 bits are its count, and the bits above them its band.
pub const REV_COUNT_BITS: u32 = 44;

/// How many bits of a revision are its band: the nine above the count
/// (decision 2026-10-04 §2.3).
pub const REV_BAND_BITS: u32 = 9;

// Checked at compile time: a band and a count are the whole of a revision.
const _: () = assert!(MAX_REV == (1 << (REV_BAND_BITS + REV_COUNT_BITS)) - 1);

/// How many revisions one band holds.
/// Derived: every count that fits in REV_COUNT_BITS.
pub const REV_BAND_SIZE: u64 = 1 << REV_COUNT_BITS;

/// The count at which the top half of a band begins (decision 2026-10-04
/// §2.3). Editing never gets there, since it is 2^43 edits from the bottom:
/// a revision is in the top half because a device jumped.
/// Derived: half of REV_BAND_SIZE.
pub const REV_BAND_HALF: u64 = REV_BAND_SIZE / 2;

/// The highest number a statement may have, and so the highest band a
/// revision may be in (decision 2026-10-04 §3, §4.1). The first statement
/// is number 1, and a phrase makes at most this many.
pub const MAX_STATEMENT_NUMBER: u64 = 256;

// Checked at compile time: every statement's number is a band.
const _: () = assert!(MAX_STATEMENT_NUMBER < 1 << REV_BAND_BITS);

/// The most devices a statement may list (decision 2026-10-04 §4.1).
pub const MAX_STATEMENT_DEVICES: usize = 64;

/// The most removed keys a statement may list (decision 2026-10-04 §4.1).
/// A statement lists every key removed so far, so this is also the most
/// keys one phrase removes.
pub const MAX_STATEMENT_REMOVED: usize = 256;

/// The most statements a statement's chain may name (decision 2026-10-04
/// §4.1): every statement it was made after, back to the first.
pub const MAX_STATEMENT_CHAIN: usize = 256;

/// The most a device's label may be in a statement, in bytes (decision
/// 2026-10-04 §4.1).
pub const MAX_DEVICE_LABEL_BYTES: usize = 64;

/// How much of a statement's hash names it on a chain: its first 16 bytes
/// (decision 2026-10-04 §4.1). Only the phrase signs a statement, so
/// nothing is gained by forging one of these.
pub const STATEMENT_HASH_BYTES: usize = 16;

/// The most a statement takes in its canonical form, with its signature:
/// every list at its bound and every label at its longest.
/// Derived from the bounds above and the widths of the form: a number is
/// eight bytes, a count or a length two, a key 32, a signature 64.
pub const MAX_STATEMENT_BYTES: usize = 8 // number
    + 32 // maker
    + 2 + MAX_STATEMENT_CHAIN * (8 + STATEMENT_HASH_BYTES) // chain
    + 32 // commitment
    + 2 + MAX_STATEMENT_DEVICES * (32 + 2 + MAX_DEVICE_LABEL_BYTES) // devices
    + 2 + MAX_STATEMENT_REMOVED * 32 // removed keys
    + 32 // the phrase's key
    + 2 // the reserved field, which is empty
    + 64; // signature

/// The size of a change entry's content, always: 32 KB (decision
/// 2026-10-04 §4.6). One size, so that the entry of one statement takes
/// the room of the one before it at a relay, and its size says nothing.
pub const CHANGE_ENTRY_BYTES: usize = 32 * 1024;

// Checked at compile time: a change entry is one entry. Its content is a
// power of two, as every entry's is, and within the size every entry must
// fit in.
const _: () = assert!(CHANGE_ENTRY_BYTES.is_power_of_two());
const _: () = assert!(CHANGE_ENTRY_BYTES <= MAX_ITEM_BYTES);

/// How much of a change entry's content is the part for the phrase, sealed:
/// the last 4 KB. The rest is the part for the devices.
pub const CHANGE_ENTRY_PHRASE_PART_BYTES: usize = 4096;

/// How much of a change entry's content is the part for the devices,
/// sealed.
/// Derived: what the part for the phrase leaves.
pub const CHANGE_ENTRY_DEVICES_PART_BYTES: usize =
    CHANGE_ENTRY_BYTES - CHANGE_ENTRY_PHRASE_PART_BYTES;

/// The size of a secret sealed to one device's key, as the node seals to a
/// key: an ephemeral key, a nonce, the 32 bytes and a tag.
pub const SEALED_SECRET_BYTES: usize = 32 + 12 + 32 + 16;

/// The most secrets of earlier generations that a change entry carries for
/// the phrase (decision 2026-10-04 §4.6).
pub const MAX_EARLIER_SECRETS: usize = 8;

// Checked at compile time: at every bound together, each part of a change
// entry fits its share of the 32 KB. The part for the devices is the
// statement with its length, and a count and a sealed secret for each
// device. The part for the phrase is a secret, and a count and the
// earlier secrets with their numbers.
const _: () = assert!(
    ITEM_SEAL_OVERHEAD_BYTES
        + 2
        + MAX_STATEMENT_BYTES
        + 2
        + MAX_STATEMENT_DEVICES * SEALED_SECRET_BYTES
        <= CHANGE_ENTRY_DEVICES_PART_BYTES
);
const _: () = assert!(
    ITEM_SEAL_OVERHEAD_BYTES + 32 + 2 + MAX_EARLIER_SECRETS * (8 + 32)
        <= CHANGE_ENTRY_PHRASE_PART_BYTES
);

/// The smallest an entry's content may be: 256 bytes (decision 2026-10-04
/// §2.3). A content is a nonce, a ciphertext and a tag, and its length is
/// a power of two from this up to MAX_ITEM_BYTES: what it holds is filled
/// up inside the encryption, so that a relay sees a size class and no
/// length.
pub const MIN_ENTRY_CONTENT_BYTES: usize = 256;

// Checked at compile time: both ends of the range are powers of two, so
// the sizes between them are the powers of two between them.
const _: () = assert!(MIN_ENTRY_CONTENT_BYTES.is_power_of_two());
const _: () = assert!(MAX_ITEM_BYTES.is_power_of_two());
const _: () = assert!(MIN_ENTRY_CONTENT_BYTES <= MAX_ITEM_BYTES);

/// The most links an entry's chain may have (decision 2026-10-04 §2.3):
/// one for each version the entry descends from, the newest first. What
/// is older than the hundredth is not said.
pub const MAX_ENTRY_LINKS: usize = 100;

/// How much of a hash a link holds: the first 16 bytes of the SHA-256 of
/// a version's value (decision 2026-10-04 §2.3). A link names a version
/// to whoever holds its text, and a hash of this length is not met by
/// another text by chance.
pub const ENTRY_LINK_HASH_BYTES: usize = 16;

/// How much of a key a link holds: the first 16 bytes of the key that
/// signed the entry the version was taken from (decision 2026-10-04
/// §2.3). It is asked of a reader's own devices, which are few, so the
/// start of a key says which of them it is.
pub const ENTRY_LINK_SIGNER_BYTES: usize = 16;

/// The most an entry's chain takes in its content.
/// Derived from MAX_ENTRY_LINKS and the widths of the form: a count is
/// two bytes, and a link is the start of a hash and the start of a key.
pub const MAX_ENTRY_CHAIN_BYTES: usize =
    2 + MAX_ENTRY_LINKS * (ENTRY_LINK_HASH_BYTES + ENTRY_LINK_SIGNER_BYTES);

/// The most an entry's name and its value may be together: 60 KB (decision
/// 2026-10-04 §2.3). The rest of the 64 KB is kept for the entry's chain,
/// so that it always fits, whatever the value: no link is ever left out
/// for room.
pub const MAX_ENTRY_NAME_AND_VALUE_BYTES: usize = 60 * 1024;

// Checked at compile time: at every bound together an entry's content fits
// the size every entry must fit in. It is the nonce and the tag, the
// name's length, the value's kind and its length, the name and the value
// at their bound, and the entry's chain at its longest.
const _: () = assert!(
    ITEM_SEAL_OVERHEAD_BYTES + 2 + 1 + 2 + MAX_ENTRY_NAME_AND_VALUE_BYTES + MAX_ENTRY_CHAIN_BYTES
        <= MAX_ITEM_BYTES
);

/// What an entry takes in clear beside its content (decision 2026-10-04
/// §2.3): the channel's ID, the slot, the author's key, the revision,
/// whether it is a delete, and the two signatures.
pub const ENTRY_CLEAR_BYTES: usize = 32 + 32 + 32 + 8 + 1 + 64 + 64;

// Checked at compile time: the clear fields and the signatures are within
// what every entry is counted with beyond its content, twice over: once
// as they are stored, and once for their place in each index.
const _: () = assert!(2 * ENTRY_CLEAR_BYTES <= ENTRY_OVERHEAD_BYTES);

/// How many words a recovery phrase has (decision 2026-10-04 §5).
pub const PHRASE_WORDS: usize = 12;

/// How many bytes the words of a recovery phrase encode: 128 bits.
/// Everything that comes from the phrase is derived from these.
pub const PHRASE_BYTES: usize = 16;

/// The label under which a channel's entry key is derived from its secret
/// (decision 2026-10-04 §2.1). Every label below is the `info` of
/// HKDF-SHA256 unless it says otherwise, and no label begins another, so
/// that no two things can ever be derived alike.
pub const LABEL_ENTRY_KEY: &[u8] = b"cordelia v2 entry";

/// The label of a channel's slot key (decision 2026-10-04 §2.1).
pub const LABEL_SLOT_KEY: &[u8] = b"cordelia v2 slot";

/// The label of a channel's signing key, whose public half is the
/// channel's ID (decision 2026-10-04 §2.1).
pub const LABEL_CHANNEL_SIGN: &[u8] = b"cordelia v2 sign";

/// The label of the personal channel's secret, from the person secret
/// (decision 2026-10-04 §2.2).
pub const LABEL_PERSONAL: &[u8] = b"cordelia v2 personal";

/// The label of the secret of a channel of the person's own, by name. The
/// name's length, as two bytes, and the name follow it (decision
/// 2026-10-04 §2.2).
pub const LABEL_OWN: &[u8] = b"cordelia v2 own";

/// The label of a pair channel's secret. The two devices' public keys
/// follow it, the lower first (decision 2026-10-04 §2.2).
pub const LABEL_PAIR: &[u8] = b"cordelia v2 pair";

/// The label of the secret of the phrase's channel, from the phrase
/// (decision 2026-10-04 §2.2).
pub const LABEL_RECOVERY: &[u8] = b"cordelia v2 recovery";

/// The label of a locked channel's secret. The name's length, as two
/// bytes, and the name follow it (decision 2026-10-04 §11).
pub const LABEL_LOCKED: &[u8] = b"cordelia v2 locked";

/// The label of the phrase's signing key, which signs statements and the
/// change entry (decision 2026-10-04 §5).
pub const LABEL_PHRASE_SIGN: &[u8] = b"cordelia v2 phrase sign";

/// The label of the statement key, from the phrase: the key that the part
/// of a change entry for the devices is under (decision 2026-10-04 §4.6).
pub const LABEL_PHRASE_STATEMENT: &[u8] = b"cordelia v2 phrase statement";

/// The label of the key that only the phrase gives, which seals the part
/// of a change entry that is for the phrase (decision 2026-10-04 §4.6).
pub const LABEL_PHRASE_SEAL: &[u8] = b"cordelia v2 phrase seal";

/// The label a statement's commitment to its secret is hashed under: the
/// commitment is SHA-256 of this label and the secret (decision 2026-10-04
/// §4.1).
pub const LABEL_COMMITMENT: &[u8] = b"cordelia v2 commitment";

/// The label a statement is signed under: the phrase's key signs this
/// label and the statement's canonical form (decision 2026-10-04 §4.1).
pub const LABEL_STATEMENT: &[u8] = b"cordelia v2 statement";

/// The label that binds the part of a change entry for the devices to its
/// statement's number and the phrase's key: the three are the associated
/// data of its encryption (decision 2026-10-04 §4.6).
pub const LABEL_CHANGE_DEVICES: &[u8] = b"cordelia v2 change devices";

/// The label that binds the part of a change entry for the phrase, as
/// [`LABEL_CHANGE_DEVICES`] does the other part.
pub const LABEL_CHANGE_PHRASE: &[u8] = b"cordelia v2 change phrase";

/// The label that binds a secret sealed to one device in a change entry
/// to its purpose (decision 2026-10-04 §4.6): the key it is sealed under
/// is derived with this label, the statement's number and the phrase's
/// key. What is sealed to a device for any other use, or for another
/// statement, does not open as that statement's secret.
pub const LABEL_CHANGE_SECRET: &[u8] = b"cordelia v2 change secret";

/// The label an entry's author signs it under: the author's key signs this
/// label and what is signed of the entry (decision 2026-10-04 §2.3).
pub const LABEL_ENTRY_AUTHOR: &[u8] = b"cordelia v2 author";

/// The label the channel's signing key signs an entry under, over the
/// same bytes as the author's (decision 2026-10-04 §2.3). Each signature
/// has a label of its own, so that neither is ever taken for the other.
pub const LABEL_ENTRY_CHANNEL: &[u8] = b"cordelia v2 channel";

/// The label that binds an entry's content to its channel's ID, its slot
/// and its revision: the four are the associated data of its encryption
/// (decision 2026-10-04 §2.3).
pub const LABEL_ENTRY_CONTENT: &[u8] = b"cordelia v2 content";

/// The label a record of an addition is signed under: the device that adds
/// signs this label and the record's canonical form (decision 2026-10-04
/// §6).
pub const LABEL_ADDITION: &[u8] = b"cordelia v2 addition";

/// The most a record of an addition takes in its canonical form, with its
/// signature (decision 2026-10-04 §6).
/// Derived from the widths of the form: the new device's key, its label
/// behind its length, the time, the number and the hash of the statement
/// it is made under, the key of the device that adds, and the signature.
pub const MAX_ADDITION_BYTES: usize =
    32 + 2 + MAX_DEVICE_LABEL_BYTES + 8 + 8 + STATEMENT_HASH_BYTES + 32 + 64;

/// The name whose slot the change entry is in, in the phrase's channel
/// (decision 2026-10-04 §2.2, §4.6). The channel holds that one entry. Its
/// content is the two sealed parts of a change entry and holds no name:
/// the name gives the slot, and nothing else. The slot is under the
/// channel's ID, and not under a key of the channel: a device holds no
/// key of the phrase's channel, and has to know the change entry's slot
/// from any other.
pub const CHANGE_ENTRY_NAME: &str = "change";

/// The name of the entry in a pair channel that hands a device what it
/// needs when it is added (decision 2026-10-04 §2.2, §6). Nothing else in
/// a pair channel is read.
pub const HAND_OVER_NAME: &str = "hand-over";

/// How long a key that a person typed on a device opens the pair channel
/// with that key: one hour (decision 2026-10-04 §2.2, §6). A device reads
/// a pair channel only with a key that was typed on it within that time,
/// so nothing that a removed device goes on writing there is read. And it
/// takes from it only a hand-over that was made less than this long before
/// or after the key was typed: a pair channel outlives a phrase, and what
/// was handed long ago is not taken for what a person means now.
pub const PAIR_KEY_TYPED_SECS: i64 = 60 * 60;

/// The most keys typed at `cordelia accept` that are within their hour
/// on a device at one time: eight (decision 2026-10-04 §16). A ninth is
/// refused. Each is a pair channel that the device asks its relays for,
/// for its hour, and a key with which a hand-over could be taken. A key
/// whose hour has gone holds no place: it is kept only to say what
/// became of it (TYPED_KEY_KEPT_SECS).
pub const MAX_TYPED_KEYS: usize = 8;

/// How long a device keeps a key that was typed at `cordelia accept`, to
/// say what became of it: a day (decision 2026-10-04 §5.1). It reads
/// nothing after its hour.
/// Derived: 24 times PAIR_KEY_TYPED_SECS.
pub const TYPED_KEY_KEPT_SECS: i64 = 24 * PAIR_KEY_TYPED_SECS;

/// How long the device that adds keeps a hand-over in its store, from the
/// time the hand-over says it was made: two hours (decision 2026-10-04 §3,
/// §6). A hand-over holds the person secret. No device takes one that was
/// made an hour or more before a key was typed, and a typed key opens the
/// pair channel for an hour: after two hours nobody can take it.
/// Derived: twice PAIR_KEY_TYPED_SECS.
pub const HAND_OVER_KEPT_SECS: i64 = 2 * PAIR_KEY_TYPED_SECS;

/// The most records of additions a hand-over carries (decision 2026-10-04
/// §6): the record of the addition, and the record of the adder's own
/// addition. A chain of additions is two long at most.
pub const MAX_HAND_OVER_RECORDS: usize = 2;

/// What a hand-over takes for the change entry it carries: the channel's
/// ID, the slot, the two signatures, and the content at its one size. The
/// entry's author and its revision are the statement's phrase key and
/// number, and are not written twice.
pub const HAND_OVER_CHANGE_ENTRY_BYTES: usize = 32 + 32 + 64 + 64 + CHANGE_ENTRY_BYTES;

/// The most a hand-over takes (decision 2026-10-04 §6): the time it was
/// made, the statement behind its length, the secret, the statement key,
/// the change entry, a count of records, and each record behind its
/// length.
pub const MAX_HAND_OVER_BYTES: usize = 8
    + 2
    + MAX_STATEMENT_BYTES
    + 32
    + 32
    + HAND_OVER_CHANGE_ENTRY_BYTES
    + 1
    + MAX_HAND_OVER_RECORDS * (2 + MAX_ADDITION_BYTES);

// Checked at compile time: at every bound together a hand-over, with its
// name, is within what one entry may hold. It is the value of one entry.
const _: () = assert!(HAND_OVER_NAME.len() + MAX_HAND_OVER_BYTES <= MAX_ENTRY_NAME_AND_VALUE_BYTES);

/// The most devices a reader counts in all (decision 2026-10-04 §6): those
/// of the statement it has applied, and those added since in the order it
/// saw their records. A record beyond that is kept as not counted, and a
/// statement makes room.
/// Derived: what a statement may list, so that the next statement can list
/// every device that counts.
pub const MAX_COUNTED_DEVICES: usize = MAX_STATEMENT_DEVICES;

/// The most records of additions a reader keeps as not counted (decision
/// 2026-10-04 §6). A device that counts can sign any number of records,
/// and every reader loads what it keeps each time it asks who counts. Over
/// this bound the oldest record that is not counted goes when a new one is
/// kept: it is seen again as any record is, where it is given again. A
/// record that counts is never dropped for room.
pub const MAX_NOT_COUNTED_RECORDS: usize = 256;

/// How long a device keeps the secret of a generation it left (decision
/// 2026-10-04 §3): 90 days by its own clock, and then the secret is
/// forgotten. It is for a carry that a person asks for.
pub const LEFT_SECRET_KEPT_DAYS: u32 = 90;

/// The first part of the name, in the personal channel, of a device's word
/// that it has applied a statement (decision 2026-10-04 §8). The device's
/// key follows it, as a device's key is written: each device has a slot of
/// its own, and only its own entry there is its word.
pub const PERSONAL_APPLIED_PREFIX: &str = "applied/";

/// The first part of the name, in the personal channel, of a record of an
/// addition (decision 2026-10-04 §6). Records are not carried to the next
/// statement's personal channel: the next statement's own list is what
/// stands (§7.3).
pub const PERSONAL_ADDED_PREFIX: &str = "added/";

/// What an entry takes on the wire beside its content (decision 2026-10-04
/// §2.3, §2.4): its clear fields and its two signatures, and the content's
/// length as four bytes.
pub const ENTRY_WIRE_OVERHEAD_BYTES: usize = ENTRY_CLEAR_BYTES + 4;

/// The most an entry takes on the wire: the largest content, and what an
/// entry takes beside it.
pub const MAX_ENTRY_WIRE_BYTES: usize = ENTRY_WIRE_OVERHEAD_BYTES + MAX_ITEM_BYTES;

// Checked at compile time: an entry on the wire is within what it is
// counted at, so a limit on bytes that counts entries bounds what travels.
const _: () = assert!(MAX_ENTRY_WIRE_BYTES as u64 <= entry_cost(MAX_ITEM_BYTES));

/// The label that a proof is signed under, that a connection holds a
/// channel's key (decision 2026-10-04 §2.4, item 3): the channel's signing
/// key signs this label, the value that both ends export from the one TLS
/// session, the node key of the end that proves, and the channel's ID. The
/// label is the proof's own, so that an entry's signature is never taken
/// for a proof, nor a proof for one.
pub const LABEL_CHANNEL_PROOF: &[u8] = b"cordelia v2 proof";

/// How long the value is that both ends of a connection export from its
/// TLS session, for a proof to be made over: 32 bytes (decision 2026-10-04
/// §2.4, item 3). One length, so that where the value ends and what
/// follows it begins is never in doubt.
pub const SESSION_VALUE_BYTES: usize = 32;

/// The label under which both ends of a connection export that value from
/// its TLS session (decision 2026-10-04 §2.4, item 3, and §16), with no
/// context. It is a label of its own: nothing else that is ever exported
/// from a session has it, so the value is of use for the proof and for
/// nothing else. It begins as the labels of exporters do (RFC 5705 §4).
pub const LABEL_SESSION_VALUE: &[u8] = b"EXPORTER-cordelia v2 session";

/// The most channels that one connection may have proved the keys of, and
/// so the most a relay remembers for it (decision 2026-10-04 §2.4, item
/// 3). Whoever holds a secret can prove its channel, held or not, and a
/// secret costs nothing to make: without a bound one connection could
/// have a relay remember any number of them. Once a connection has proved
/// this many, a proof for one more is answered as one that fails. A
/// person's device holds tens of channels.
/// Derived: the most channels a relay asks one peer about in a pass,
/// MAX_CHANNELS_ASKED_OF_A_PEER.
pub const MAX_CHANNELS_PROVED_ON_A_CONNECTION: usize = MAX_CHANNELS_ASKED_OF_A_PEER;

/// How many of the places that a relay remembers for one connection a
/// read of a generation that was left keeps back, beyond those that the
/// device's own channels still need there (decision 2026-10-04 §16): one
/// in sixty-four of them, which is 16 of 1,024. It is for a name that the
/// device comes to hold while the read goes on, and for the pair channel
/// of a device that is being added.
pub const LEFT_PROOFS_MARGIN_SHARE: usize = 64;

/// How many places of one connection a read of a generation that was
/// left keeps back for the device's own channels (decision 2026-10-04
/// §16): as many as the device has channels of its own that are not yet
/// proved there, `own_not_proved`, and a margin
/// (LEFT_PROOFS_MARGIN_SHARE). `most` is how many a relay remembers for
/// one connection.
///
/// **Never more than half of them.** A device that holds more channels
/// than half a connection's places cannot keep a place back for each and
/// still read: it then shares a connection half and half, and the read
/// has the connection made again as often as it needs.
pub const fn left_proofs_kept_back(own_not_proved: usize, most: usize) -> usize {
    let kept = own_not_proved.saturating_add(most / LEFT_PROOFS_MARGIN_SHARE);
    if kept > most / 2 { most / 2 } else { kept }
}

/// The protocol byte of a stream on which a connection shows an entry, and
/// is answered with what the receiver holds (decision 2026-10-04 §2.4,
/// item 5). The five streams of entries are 0x10 to 0x14, apart from the
/// eight of the older kind: show, prove, pull and push, and the one
/// between relays that work together. A peer that does not know them
/// refuses the stream, and reads none of them as one of its own.
pub const PROTOCOL_ENTRY_SHOW: u8 = 0x10;

/// The protocol byte of a stream on which a connection proves that it
/// holds a channel's key (decision 2026-10-04 §2.4, items 3 and 4).
pub const PROTOCOL_CHANNEL_PROVE: u8 = 0x11;

/// The protocol byte of a stream on which a connection asks for a page of
/// the entries of a channel it has proved (decision 2026-10-04 §2.4,
/// item 3).
pub const PROTOCOL_ENTRY_PULL: u8 = 0x12;

/// The protocol byte of a stream on which a connection sends entries to be
/// stored (decision 2026-10-04 §2.4, items 1 and 2).
pub const PROTOCOL_ENTRY_PUSH: u8 = 0x13;

/// The protocol byte of the stream between relays that their operator
/// lists together (decision 2026-10-04 §2.4, item 6): on it a relay tells
/// which channels it holds, hands a channel's entries without the proof,
/// and passes on an entry it took, each with how long it has held the
/// channel and when the channel was last used. A relay refuses the stream
/// from any peer that its operator does not list by key, and a node that
/// is no relay refuses it from everyone.
pub const PROTOCOL_RELAY_ENTRIES: u8 = 0x14;

/// The most channels in one answer of a relay that tells a relay it works
/// with which channels it holds (decision 2026-10-04 §2.4, item 6). Each
/// is its ID, its mark, two times and a count: a thousand of them are
/// well within one message.
pub const RELAY_CHANNELS_PAGE_MAX: u32 = 1000;

/// How many bytes mark one holding of a channel at a relay: 8, random,
/// made when the relay takes a channel that it does not hold. A place in
/// a channel is a count of what the relay stored in this holding of it. A
/// relay that drops a channel and takes it again counts from 1 again,
/// under another mark: so whoever kept a place from the earlier holding
/// is handed the channel from the start, and not from a place that means
/// something else now.
pub const CHANNEL_MARK_BYTES: usize = 8;

/// The most entries in one page of a channel, as a relay hands it to a
/// connection that has proved the channel's key (decision 2026-10-04
/// §2.4, item 3).
/// Derived: what one page of the older kind lists, DEFAULT_SYNC_LIMIT.
pub const ENTRY_PAGE_MAX_ENTRIES: u32 = DEFAULT_SYNC_LIMIT;

/// The most the entries of one page take on the wire together. A page
/// travels in one message, and 128 KB of the message is left for what is
/// around the entries, as it is around a push of the older kind.
pub const ENTRY_PAGE_MAX_BYTES: usize = MAX_MESSAGE_BYTES as usize - 128 * 1024;

// Checked at compile time: a page always has room for one entry, whatever
// its size, so a channel is never stuck behind an entry that fits no page.
// And a full page, counted as entries are counted, is within what one
// connection may be handed in a minute.
const _: () = assert!(MAX_ENTRY_WIRE_BYTES <= ENTRY_PAGE_MAX_BYTES);
const _: () = assert!(
    ENTRY_PAGE_MAX_BYTES as u64 + ENTRY_PAGE_MAX_ENTRIES as u64 * ENTRY_OVERHEAD_BYTES as u64
        <= PUSH_BYTES_PER_PEER_PER_MINUTE
);

/// The most one channel from its secret may hold at a relay (decision
/// 2026-10-04 §2.5), in bytes as entries are counted ([`entry_cost`]).
/// Derived: what a channel of the older kind may hold. The two kinds are
/// counted apart, each against a cap of its own.
pub const MAX_ENTRY_CHANNEL_BYTES_AT_RELAY: u64 = MAX_CHANNEL_BYTES_AT_RELAY;

/// How many channels from their secrets one address may make a relay hold
/// for the first time in an hour: 256 (decision 2026-10-04 §2.5).
///
/// After a removal every channel of a person's own is new: the personal
/// channel, and one for each name. So is a pair channel, each time a
/// device is added. At 16 an hour, which is what the older kind allows, a
/// person with thirty names would wait two hours for the last of them,
/// and a home with three devices shares one address. At 256 a home of
/// several people, each with tens of names, moves within the hour.
///
/// What it still bounds: a channel costs nothing to make, so without an
/// allowance one address could make a relay hold any number of them. A
/// relay's cap is what bounds its storage, and it drops its newest
/// channels first, so the channels that an address makes in an hour can
/// push out only one another and what is newer still.
pub const NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR: usize = 256;

/// How long a relay keeps a channel from its secret that nobody uses: 90
/// days (decision 2026-10-04 §2.5). A channel whose key no connection has
/// proved, and of which nobody has shown an entry that the relay holds,
/// for that long is dropped.
pub const ENTRY_CHANNEL_UNUSED_DAYS: u32 = 90;

/// How much later than the time a relay keeps for a channel a use of the
/// channel must be, for the relay to write it down: more than an hour
/// (decision 2026-10-04 §16). A proof, or an entry shown that the relay
/// holds, is use of a channel, and a device makes both on every pass: if
/// each were written, every one would be a write to the relay's disk for
/// whoever asks. Against the ENTRY_CHANNEL_UNUSED_DAYS that an unused
/// channel is kept, an hour is nothing.
pub const ENTRY_CHANNEL_USED_STEP_SECS: u64 = 60 * 60;

/// How often a relay drops the channels from their secrets that nobody
/// uses (decision 2026-10-04 §2.5), and when it starts.
/// Derived: as often as expired deletes are collected,
/// TOMBSTONE_GC_INTERVAL_SECS. Hourly is plenty against 90 days.
pub const ENTRY_CHANNEL_SWEEP_INTERVAL_SECS: u64 = TOMBSTONE_GC_INTERVAL_SECS;

/// How often a relay passes the entries it took on to the relays it works
/// with (decision 2026-10-04 §2.4, item 6).
/// Derived: as often as it passes on items of the older kind,
/// REPUSH_INTERVAL_SECS.
pub const ENTRY_OFFER_INTERVAL_SECS: u64 = REPUSH_INTERVAL_SECS;

/// How often a relay asks each relay it works with which channels from
/// their secrets it holds, and pulls what it lacks (decision 2026-10-04
/// §2.4, item 6).
/// Derived: as often as a node fetches items of the older kind from its
/// hot peers, REALTIME_SYNC_INTERVAL_SECS.
pub const RELAY_ENTRY_PULL_INTERVAL_SECS: u64 = REALTIME_SYNC_INTERVAL_SECS;

/// The most pages of one channel that a relay pulls from a relay it works
/// with in one pass. A longer channel is gone on with in the next pass,
/// so that one long channel does not keep every other waiting.
pub const RELAY_ENTRY_PULL_PAGES: usize = 10;

/// The most pages of the list of the channels it holds that a relay reads
/// from a relay it works with in one pass (decision 2026-10-04 §2.4, item
/// 6). A longer list is gone on with in the next pass, from where this
/// one stopped, so that a list which never ends keeps a relay asking no
/// longer than this, and nothing is remembered of more than a page of it
/// at a time. Ten pages are ten thousand channels.
pub const RELAY_CHANNEL_PAGES_PER_PASS: usize = 10;

/// How many requests one connection may make in a minute on the streams of
/// entries of channels from their secrets, all of them counted together:
/// 3,000 (decision 2026-10-04 §16). A request beyond it is refused, and is
/// a breach, as a write or a sync of the older kind beyond its count is.
/// All the connections from one address share MAX_CONNECTIONS_PER_IP
/// times this.
///
/// Without it a connection could ask without end: every proof is a
/// signature for the relay to check, and every pull a look at its store.
///
/// It is sized for a device with 256 names, which is what an address may
/// make a relay take in an hour: a pull of each every ten seconds, and of
/// the personal channel (1,542 a minute); its day's proofs in one burst,
/// as many as a relay remembers for a connection (1,024); a show for each
/// pass and each time it sends; and what it pushes.
pub const ENTRY_REQUESTS_PER_PEER_PER_MINUTE: u32 = 3_000;

/// How many requests a device makes of one relay in a minute, at most, on
/// the streams that prove a channel's key, pull a page and push entries
/// (decision 2026-10-04 §16): three quarters of what a relay allows one
/// connection, ENTRY_REQUESTS_PER_PEER_PER_MINUTE, as what a device pushes
/// in a minute (OUTBOX_BYTES_PER_MINUTE) is three quarters of what a relay
/// allows. A device paces itself, so that it is never the one refused for
/// going over: a request over a relay's count is a breach, and a few of
/// those cut a device off. What it does not ask in one minute, it asks in
/// the next. Its shows are not held back by this, and are few: a device
/// must still hear of a removal.
pub const OWN_ENTRY_REQUESTS_PER_MINUTE: u32 = ENTRY_REQUESTS_PER_PEER_PER_MINUTE / 4 * 3;

/// The most slots for which a relay remembers, for one connection, the
/// last entry that it was shown whole there by each author, where the two
/// signatures held (decision 2026-10-04 §2.4, item 5). The connection may
/// then show that same entry in short: by its channel, slot, author,
/// revision and ID alone. A device shows one entry, the change entry of
/// the phrase it follows, so 8 is room to spare. A ninth is not
/// remembered, and is shown whole each time; all are forgotten when the
/// connection closes.
pub const MAX_SLOTS_SHOWN_ON_A_CONNECTION: usize = 8;

/// How long the leave lasts that a relay's answer to a show gives a device
/// on that connection (decision 2026-10-04 §4.6): 10 seconds from an
/// answer which says that the relay holds no later change than the one
/// the device keeps. A device opens a stream for a channel of its own, and
/// takes what comes back on it, only with leave. So what a device sends on
/// its own timer, at each publish and from what it sends again, comes
/// after a show, and a pass that is long shows again as it goes.
/// Derived: the time between two passes, REALTIME_SYNC_INTERVAL_SECS.
pub const SHOW_LEAVE_SECS: u64 = REALTIME_SYNC_INTERVAL_SECS;

/// How long a device that wakes waits for the relays it is set up with
/// (decision 2026-10-04 §4.6): when the node starts, or reaches a relay
/// after having reached none, it neither takes from a channel of its own
/// nor sends to one until each of them has answered a show, or this long
/// has gone by. Connections come up one at a time: without the wait a
/// device would take what the first relay held, and send it what waited,
/// before a second, which had a change, had answered. The cost is that
/// with one relay out of reach a device waits this long before it syncs.
pub const WAKE_WAIT_SECS: u64 = 30;

/// How often a device proves again, on a connection that lasts, the key of
/// each channel of its own and of each name that its personal channel
/// lists: once a day (decision 2026-10-04 §2.5). A relay drops a channel
/// that nobody has used for ENTRY_CHANNEL_UNUSED_DAYS, and a proof is use.
/// So a name whose only device is gone is not dropped while any device of
/// the person's is on.
pub const CHANNEL_PROOF_AGAIN_SECS: u64 = 24 * 60 * 60;

/// The first part of the name, in the personal channel, of a device's word
/// that it syncs a name (decision 2026-10-04 §2.2, §7.3). The name
/// follows it, in its one spelling. Each device that syncs the name has an
/// entry of its own there, and an entry that is no delete lists the name.
/// A device proves the channel of every name that is listed, whether or
/// not it syncs the name itself (§2.5).
pub const PERSONAL_NAME_PREFIX: &str = "name/";

/// The first part of the name, in the personal channel, of a device's word
/// that it has left (decision 2026-10-04 §5.2). The device's key follows
/// it, as a device's key is written: each device has a slot of its own,
/// and only its own entry there is its word. A device writes it in the
/// personal channel that it is leaving, by its own command, before it
/// starts again under another phrase or with another key.
pub const PERSONAL_LEFT_PREFIX: &str = "left/";

/// The label that a key's fingerprint is hashed under (decision 2026-10-04
/// §6): SHA-256 of this label and the key. The fingerprint is shown as
/// words of the list that a recovery phrase uses, eleven bits to a word,
/// from its first bit on.
pub const LABEL_FINGERPRINT: &[u8] = b"cordelia v2 fingerprint";

/// How many words of a key's fingerprint are shown beside a label,
/// wherever a device is shown for a decision (decision 2026-10-04 §6):
/// four, which is 44 bits. A label is whatever the device that added a key
/// called it, and two keys can have one label.
pub const FINGERPRINT_WORDS_SHOWN: usize = 4;

/// How long the fetch may take that a command makes before it prepares a
/// change (decision 2026-10-04 §7.1, step 1): two minutes at most. Nothing
/// depends on its being whole: the command says what it could not fetch,
/// and a removal is never held up by what another device goes on writing.
pub const CHANGE_FETCH_MAX_SECS: u64 = 120;

/// How many whole passes that fetch asks for, at most, where a pass ends
/// before it has read every channel to its end (decision 2026-10-04 §7.1,
/// step 1): a pass that found a relay at another turn, or a channel
/// longer than one pass takes, is read on by the next. After the last,
/// the command says that not everything was fetched. A relay that keeps
/// giving no leave is so asked three times, and not for two minutes.
pub const CHANGE_FETCH_PASSES: usize = 3;

/// A command that makes a statement says how many more the phrase can
/// make once fewer than this are left (decision 2026-10-04 §4.1).
pub const STATEMENTS_LEFT_SAID_BELOW: u64 = 16;

/// How long a device that is given a new key waits for its relays to be
/// sent the word that it has left, and the deletes over what it handed
/// (decision 2026-10-04 §5.2, §6), before it forgets the secret that they
/// are written with. It says which relays were not sent them.
/// Derived: the wait of a device that wakes, WAKE_WAIT_SECS, which is how
/// long a relay that answers at all has had to answer.
pub const LEAVING_SEND_WAIT_SECS: u64 = WAKE_WAIT_SECS;

/// How long a folder's first cycle in a channel waits, once one relay has
/// handed the whole of the name's channel, for each other relay that the
/// device is set up with to hand it too (decision 2026-10-04 §6). A
/// folder with no record in a channel yet waits for a relay, and never
/// for a device: so a file that another device has already sent meets the
/// folder's as on any first sync, and is not published a second time.
/// Derived: the wait of a device that wakes, WAKE_WAIT_SECS, which is how
/// long a relay that answers at all has had to answer.
pub const FIRST_FETCH_WAIT_SECS: u64 = WAKE_WAIT_SECS;

/// What follows the statement's number in a device's word that it has
/// applied a statement, once it has sent what it carried (decision
/// 2026-10-04 §8). The word is the number alone until then. A device
/// writes it under its own key, in the personal channel of the statement's
/// generation, so it cannot be claimed for it.
pub const PERSONAL_APPLIED_SENT: &str = " sent";

/// The two spans of time, in seconds, over which a command that removes a
/// device says how much that device wrote that this one received
/// (decision 2026-10-04 §7.1): the last day, and the last week. Both are
/// read from local history, which is kept for HISTORY_DAYS.
pub const RECEIVED_LAST_DAY_SECS: i64 = 24 * 60 * 60;
pub const RECEIVED_LAST_WEEK_SECS: i64 = 7 * RECEIVED_LAST_DAY_SECS;

// Checked at compile time: a week of what was received is within what
// local history keeps by default.
const _: () = assert!(RECEIVED_LAST_WEEK_SECS <= HISTORY_DAYS as i64 * 24 * 60 * 60);

/// How long a thing that will pass by itself has lasted before the status
/// line shows it as amber (decision 2026-10-04 §10.1): no relay
/// connected; a relay that is connected and does not hold the latest
/// change; and, after a change, names that are not yet in the new
/// generation or not yet sent. Five minutes: a machine that wakes, a
/// relay that restarts and a device that has just applied a change are
/// each through it in less, and what lasts longer is worth a person's
/// knowing. The first two are counted by the node's own clock, which
/// does not run while the machine sleeps.
pub const STATUS_AMBER_WAIT_SECS: u64 = 300;

/// For how many days after a device applied a removal the status line
/// shows as amber that some device has not applied it (decision
/// 2026-10-04 §8, §10.1). After that it is said in `cordelia devices`
/// only: a device that lies in a drawer does not keep every status line
/// amber for good.
pub const REMOVAL_NOT_APPLIED_SHOWN_DAYS: u32 = 7;

/// For how long after a relay refused something for room, or for the
/// address's allowance, the status line takes it that the relay still
/// refuses (decision 2026-10-04 §10.1). A device keeps the time of a
/// relay's last refusal, and offers again what was refused after a wait
/// that doubles up to OUTBOX_REFUSED_RETRY_MAX_SECS: a relay that still
/// refuses has refused again within twice that, and one that has not has
/// taken what it was offered, or was offered nothing more.
pub const NO_ROOM_STANDS_SECS: u64 = 2 * OUTBOX_REFUSED_RETRY_MAX_SECS;

/// The most characters of a file's name that a command prints, and that
/// the node puts in a line of its status (decision 2026-10-04 §16):
/// another device may have written the name, and a name may be as long
/// as an entry's text. What is cut is marked as cut.
pub const FILE_NAME_SHOWN_CHARS: usize = 120;

/// How long a personal node waits before it tries its first start on
/// this version again, after a try that failed (decision 2026-10-04
/// §10.1): the sync cycle's five seconds after the first, and twice as
/// long after each further one, up to FIRST_START_RETRY_MAX_SECS. A
/// start that cannot succeed (no room for the copy, no leave to write)
/// does not write its copy again every five seconds.
pub const FIRST_START_RETRY_BASE_SECS: u64 = 5;

/// The longest that a personal node waits between two tries at its first
/// start on this version (decision 2026-10-04 §10.1): ten minutes, the
/// longest wait before anything a relay refused is offered again
/// (OUTBOX_REFUSED_RETRY_MAX_SECS). A person who has made room is not
/// kept waiting for longer than that, and need not restart the node.
pub const FIRST_START_RETRY_MAX_SECS: u64 = OUTBOX_REFUSED_RETRY_MAX_SECS;

/// How much before its wait has passed a try at the first start is still
/// made (decision 2026-10-04 §10.1): one second. A try is made when a
/// sync cycle would have run, and the first wait is a cycle long: without
/// this, the timer's own jitter would put every try off by a whole cycle.
pub const FIRST_START_RETRY_SLACK_SECS: u64 = 1;

// ── A carry that a person asks for, and a recovery ──────────────────

/// How long a carry by command reads one name at the relays, at most
/// (decision 2026-10-04 §7.3): the fetch of the new channel, and then the
/// name's channel in each generation that the device left. What was not
/// read to its end by then is said, and the command can be run again.
/// Derived: as long as the fetch before a change, CHANGE_FETCH_MAX_SECS.
pub const CARRY_READ_MAX_SECS: u64 = CHANGE_FETCH_MAX_SECS;

/// How long a channel that a carry is being made into holds back the
/// first cycle of a folder that has just been mapped to its name, at
/// most (decision 2026-10-04 §7.3): a device that comes to sync a name
/// carries it first. A carry that never says it has ended holds nothing
/// up for longer than this.
/// Derived: a little longer than the carry may read, CARRY_READ_MAX_SECS.
pub const CARRY_FIRST_MAX_SECS: u64 = CARRY_READ_MAX_SECS + 60;

/// How many words of a key's fingerprint name a removed key at `cordelia
/// sync carry --from` (decision 2026-10-04 §7.3): the first six, which is
/// 66 bits. A statement lists removed keys bare, so a machine that never
/// knew a device has no label for it.
pub const CARRY_FROM_WORDS: usize = 6;

/// The label under which the phrase's signing key signs a person's word
/// for a carry (decision 2026-10-04 §7.3, §9): which name, which keys
/// that do not count, and which files above a version that is held. A
/// signature under it is no statement and no entry.
pub const LABEL_CARRY_WORD: &[u8] = b"cordelia v2 carry word";

/// How long a person's word for a carry stands (decision 2026-10-04
/// §7.3): ten minutes from when the phrase signed it. The command hands
/// it to the node at once; a word that is found later is no word.
pub const CARRY_WORD_SECS: i64 = 10 * 60;

/// The label under which the key of one run of a command signs a batch
/// of versions that it hands the node on the phrase's word (decision
/// 2026-10-04 §16): the batch's number, and the hash of its versions as
/// they are handed. The word names that key, and the command makes it
/// for the one run: a signature under this label is no word, no
/// statement and no entry.
pub const LABEL_CARRY_BATCH: &[u8] = b"cordelia v2 carry batch";

/// The most bytes of entries that the node hands a command in one answer
/// (decision 2026-10-04 §7.3, §9), where the command reads a channel
/// whose secret the node does not hold: a channel may hold more than one
/// answer of the local API carries, so it is handed a part at a time. An
/// entry over the bound is handed alone.
/// Derived: half of what one message of the wire holds, MAX_MESSAGE_BYTES.
pub const CARRY_PART_MAX_BYTES: usize = MAX_MESSAGE_BYTES as usize / 2;

/// The most names a recovery carries (decision 2026-10-04 §9): a device
/// that is gone listed names too, and can have listed any number of its
/// own. The names it leaves are named.
pub const RECOVERY_MAX_NAMES: usize = 1_024;

/// The most devices a recovery shows at its prompt, of the statement's
/// and of those added since (decision 2026-10-04 §9). Beyond it the
/// command says how many it could not show, and the look takes nothing
/// from those.
pub const RECOVERY_MAX_DEVICES_SHOWN: usize = 256;

/// The most secrets of generations before its own that a machine which
/// recovers is handed, and keeps as a device keeps a secret it left
/// (decision 2026-10-04 §3, §9): the one of the generation it recovered
/// from, and as many before it as a change entry gives the phrase.
/// Derived: MAX_EARLIER_SECRETS and one.
pub const RECOVERY_MAX_LEFT_SECRETS: usize = MAX_EARLIER_SECRETS + 1;

/// Every label above, for the tests that set one against another.
pub const LABELS: [&[u8]; 25] = [
    LABEL_ENTRY_KEY,
    LABEL_SLOT_KEY,
    LABEL_CHANNEL_SIGN,
    LABEL_PERSONAL,
    LABEL_OWN,
    LABEL_PAIR,
    LABEL_RECOVERY,
    LABEL_LOCKED,
    LABEL_PHRASE_SIGN,
    LABEL_PHRASE_STATEMENT,
    LABEL_PHRASE_SEAL,
    LABEL_COMMITMENT,
    LABEL_STATEMENT,
    LABEL_CHANGE_DEVICES,
    LABEL_CHANGE_PHRASE,
    LABEL_CHANGE_SECRET,
    LABEL_ENTRY_AUTHOR,
    LABEL_ENTRY_CHANNEL,
    LABEL_ENTRY_CONTENT,
    LABEL_ADDITION,
    LABEL_CHANNEL_PROOF,
    LABEL_SESSION_VALUE,
    LABEL_FINGERPRINT,
    LABEL_CARRY_WORD,
    LABEL_CARRY_BATCH,
];

// ── Assertion tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Wire protocol
    #[test]
    fn test_protocol_version_is_1() {
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn test_handshake_magic_network_protocol_4_1_3() {
        assert_eq!(HANDSHAKE_MAGIC, 0xC0DE_11A1);
    }

    // Ports (configuration.md §3)
    #[test]
    fn test_http_port_configuration_3() {
        assert_eq!(HTTP_PORT, 9473);
    }

    #[test]
    fn test_p2p_port_configuration_3() {
        assert_eq!(P2P_PORT, 9474);
    }

    // Transport (network-protocol.md §2.1)
    #[test]
    fn test_quic_keepalive_interval_network_protocol_2_1() {
        assert_eq!(QUIC_KEEPALIVE_INTERVAL_SECS, 15);
    }

    #[test]
    fn test_quic_max_idle_timeout_network_protocol_2_1() {
        assert_eq!(QUIC_MAX_IDLE_TIMEOUT_SECS, 60);
    }

    #[test]
    fn test_quic_max_bidi_streams_network_protocol_2_1() {
        assert_eq!(QUIC_MAX_BIDI_STREAMS, 64);
    }

    #[test]
    fn test_quic_max_uni_streams_network_protocol_2_1() {
        assert_eq!(QUIC_MAX_UNI_STREAMS, 0);
    }

    #[test]
    fn test_tls_cert_validity_days_network_protocol_2_2() {
        assert_eq!(TLS_CERT_VALIDITY_DAYS, 365);
    }

    // Stream I/O (parameter-rationale.md §6)
    #[test]
    fn test_stream_timeout_parameter_rationale_6() {
        assert_eq!(STREAM_TIMEOUT_SECS, 10);
    }

    #[test]
    fn test_node_stop_timeout_parameter_rationale_6() {
        assert_eq!(NODE_STOP_TIMEOUT_SECS, 30);
        assert_eq!(NODE_STOP_TIMEOUT_SECS, 3 * STREAM_TIMEOUT_SECS);
    }

    // Keepalive (network-protocol.md §4.2)
    #[test]
    fn test_ping_interval_network_protocol_4_2() {
        assert_eq!(PING_INTERVAL_SECS, 30);
    }

    #[test]
    fn test_dead_threshold_network_protocol_4_2() {
        assert_eq!(DEAD_THRESHOLD, 3);
    }

    #[test]
    fn test_dead_timeout_network_protocol_4_2() {
        assert_eq!(DEAD_TIMEOUT_SECS, 90);
        assert_eq!(DEAD_TIMEOUT_SECS, PING_INTERVAL_SECS * DEAD_THRESHOLD);
    }

    // Handshake (network-protocol.md §4.1)
    #[test]
    fn test_handshake_timeout_network_protocol_4_1_3() {
        assert_eq!(HANDSHAKE_TIMEOUT_SECS, 10);
    }

    #[test]
    fn test_max_clock_skew_network_protocol_4_1_5() {
        assert_eq!(MAX_CLOCK_SKEW_SECS, 300);
    }

    // Governor defaults (parameter-rationale.md §3)
    #[test]
    fn test_hot_min_parameter_rationale_3() {
        assert_eq!(HOT_MIN, 2);
    }

    #[test]
    fn test_hot_max_personal_parameter_rationale_3() {
        assert_eq!(HOT_MAX, 2);
    }

    #[test]
    fn test_hot_min_relays_parameter_rationale_3() {
        assert_eq!(HOT_MIN_RELAYS, 1);
    }

    #[test]
    fn test_warm_min_parameter_rationale_3() {
        assert_eq!(WARM_MIN, 3);
    }

    #[test]
    fn test_warm_max_personal_parameter_rationale_3() {
        assert_eq!(WARM_MAX, 10);
    }

    #[test]
    fn test_cold_max_personal_parameter_rationale_3() {
        assert_eq!(COLD_MAX, 50);
    }

    #[test]
    fn test_min_warm_tenure_parameter_rationale_3() {
        assert_eq!(MIN_WARM_TENURE_SECS, 300);
    }

    #[test]
    fn test_churn_interval_parameter_rationale_3() {
        assert_eq!(CHURN_INTERVAL_SECS, 3600);
    }

    #[test]
    fn test_churn_jitter_parameter_rationale_3() {
        assert_eq!(CHURN_JITTER_SECS, 300);
    }

    #[test]
    fn test_churn_fraction_parameter_rationale_3() {
        assert!((CHURN_FRACTION - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn test_ema_alpha_parameter_rationale_3() {
        assert!((EMA_ALPHA - 0.1).abs() < f64::EPSILON);
    }

    // Backoff (parameter-rationale.md §3)
    #[test]
    fn test_backoff_base_parameter_rationale_3() {
        assert_eq!(BACKOFF_BASE_SECS, 30);
    }

    #[test]
    fn test_backoff_max_parameter_rationale_3() {
        assert_eq!(BACKOFF_MAX_SECS, 900);
    }

    #[test]
    fn test_backoff_saturation_parameter_rationale_3() {
        assert_eq!(BACKOFF_SATURATION, 5);
    }

    // Ban tiers (parameter-rationale.md §3)
    #[test]
    fn test_ban_transient_parameter_rationale_3() {
        assert_eq!(BAN_TRANSIENT_SECS, 900);
    }

    #[test]
    fn test_ban_identity_parameter_rationale_3() {
        assert_eq!(BAN_IDENTITY_SECS, 3600);
    }

    #[test]
    fn test_ban_systematic_parameter_rationale_3() {
        assert_eq!(BAN_SYSTEMATIC_SECS, 28800);
    }

    // Size limits (parameter-rationale.md §4-§5)
    #[test]
    fn test_max_message_bytes_parameter_rationale_5_2() {
        assert_eq!(MAX_MESSAGE_BYTES, 1_048_576); // 1 MB
    }

    #[test]
    fn test_max_item_bytes_parameter_rationale_4() {
        assert_eq!(MAX_ITEM_BYTES, 65_536); // 64 KB
    }

    #[test]
    fn test_max_batch_size_demand_model_3_1() {
        assert_eq!(MAX_BATCH_SIZE, 100);
    }

    #[test]
    fn test_max_listen_limit_channels_api_3() {
        assert_eq!(MAX_LISTEN_LIMIT, 500);
    }

    #[test]
    fn test_max_descriptor_size_network_protocol_4_4_6() {
        assert_eq!(MAX_DESCRIPTOR_SIZE, 512);
    }

    #[test]
    fn test_max_channel_name_len_network_protocol_4_4_6() {
        assert_eq!(MAX_CHANNEL_NAME_LEN, 63);
    }

    // Connection limits (network-protocol.md §9.1)
    #[test]
    fn test_max_inbound_connections_network_protocol_9_1() {
        assert_eq!(MAX_INBOUND_CONNECTIONS, 200);
    }

    #[test]
    fn test_max_connections_per_ip_network_protocol_9_1() {
        assert_eq!(MAX_CONNECTIONS_PER_IP, 5);
    }

    #[test]
    fn test_max_connections_per_subnet_network_protocol_9_1() {
        assert_eq!(MAX_CONNECTIONS_PER_SUBNET, 20);
    }

    // Rate limits (network-protocol.md §9.2)
    #[test]
    fn test_writes_per_peer_per_minute_network_protocol_9_2() {
        // 3x headroom: 3 × (60 / REPUSH_INTERVAL_SECS) = 3 × 12 = 36
        assert_eq!(WRITES_PER_PEER_PER_MINUTE, 36);
    }

    #[test]
    fn test_syncs_per_peer_per_minute_network_protocol_9_2() {
        // 3x headroom: 3 × (60 / 10) = 18
        assert_eq!(SYNCS_PER_PEER_PER_MINUTE, 18);
    }

    #[test]
    fn test_peer_shares_per_peer_per_minute_network_protocol_9_2() {
        // 3x headroom: 3 × (60 / 30) = 6
        assert_eq!(PEER_SHARES_PER_PEER_PER_MINUTE, 6);
    }

    #[test]
    fn test_ban_threshold_network_protocol_9_2() {
        assert_eq!(BAN_THRESHOLD, 3);
    }

    // Intervals (network-protocol.md §4)
    #[test]
    fn test_realtime_sync_interval_network_protocol_4_5() {
        assert_eq!(REALTIME_SYNC_INTERVAL_SECS, 10);
    }

    #[test]
    fn test_batch_sync_interval_network_protocol_4_5() {
        assert_eq!(BATCH_SYNC_INTERVAL_SECS, 900);
    }

    #[test]
    fn test_peer_share_interval_network_protocol_4_3() {
        assert_eq!(PEER_SHARE_INTERVAL_SECS, 300);
    }

    #[test]
    fn test_channel_reconciliation_interval_network_protocol_4_4_2() {
        assert_eq!(CHANNEL_RECONCILIATION_INTERVAL_SECS, 300);
    }

    // Replication
    #[test]
    fn test_default_sync_limit_network_protocol_4_5() {
        assert_eq!(DEFAULT_SYNC_LIMIT, 100);
    }

    #[test]
    fn test_default_max_peers_share_network_protocol_4_3() {
        assert_eq!(DEFAULT_MAX_PEERS_SHARE, 20);
    }

    #[test]
    fn test_tombstone_retention_days_data_formats_4() {
        assert_eq!(TOMBSTONE_RETENTION_DAYS, 7);
    }

    // Bootstrap (network-protocol.md §10)
    #[test]
    fn test_srv_record_network_protocol_10() {}

    #[test]
    fn test_fallback_peers_network_protocol_10() {
        assert_eq!(FALLBACK_PEERS.len(), 2);
        assert!(FALLBACK_PEERS[0].ends_with(":9474"));
    }

    // PSK exchange (network-protocol.md §4.7)
    #[test]
    fn test_psk_reasons_network_protocol_4_7() {
        assert_eq!(REASON_NOT_FOUND, "not_found");
        assert_eq!(REASON_NOT_AUTHORIZED, "not_authorized");
        assert_eq!(REASON_NOT_AVAILABLE, "not_available");
    }

    // Seen table (network-protocol.md §7.2)
    #[test]
    fn test_seen_table_max_network_protocol_7_2() {
        assert_eq!(SEEN_TABLE_MAX, 10_000);
    }

    #[test]
    fn test_seen_table_ttl_network_protocol_7_2() {
        assert_eq!(SEEN_TABLE_TTL_SECS, 600);
    }

    // ── Consistency checks ───────────────────────────────────────────

    #[test]
    fn test_max_item_fits_in_message() {
        assert!(MAX_ITEM_BYTES < MAX_MESSAGE_BYTES as usize);
    }

    // ── Derivation assertions ────────────────────────────────────────
    // These enforce the dependency graph. If a primitive changes,
    // these tests show exactly which derived values moved with it.

    #[test]
    fn test_derived_dead_timeout() {
        assert_eq!(DEAD_TIMEOUT_SECS, PING_INTERVAL_SECS * DEAD_THRESHOLD);
    }

    #[test]
    fn test_derived_handshake_timeout() {
        assert_eq!(HANDSHAKE_TIMEOUT_SECS, STREAM_TIMEOUT_SECS);
    }

    #[test]
    fn test_derived_hysteresis() {
        assert_eq!(HYSTERESIS_SECS, DEAD_TIMEOUT_SECS);
    }

    #[test]
    fn test_derived_min_warm_tenure() {
        assert_eq!(MIN_WARM_TENURE_SECS, PEER_SHARE_INTERVAL_SECS);
    }

    #[test]
    fn test_derived_churn_jitter() {
        assert_eq!(CHURN_JITTER_SECS, PEER_SHARE_INTERVAL_SECS);
    }

    #[test]
    fn test_derived_stale_threshold() {
        assert_eq!(STALE_THRESHOLD_SECS, CHURN_INTERVAL_SECS / 2);
    }

    #[test]
    fn test_derived_rate_window() {
        assert_eq!(RATE_WINDOW_SECS, 6 * TICK_INTERVAL_SECS);
    }

    #[test]
    fn test_derived_ban_window() {
        assert_eq!(BAN_WINDOW_SECS, 10 * RATE_WINDOW_SECS);
    }

    #[test]
    fn test_derived_backoff_base() {
        assert_eq!(BACKOFF_BASE_SECS, PING_INTERVAL_SECS);
    }

    #[test]
    fn test_derived_backoff_max() {
        assert_eq!(BACKOFF_MAX_SECS, BAN_TRANSIENT_SECS);
    }

    #[test]
    fn test_derived_clear_failure_delay() {
        assert_eq!(CLEAR_FAILURE_DELAY_SECS, 4 * PING_INTERVAL_SECS);
    }

    #[test]
    fn test_derived_ban_transient() {
        assert_eq!(BAN_TRANSIENT_SECS, 3 * PEER_SHARE_INTERVAL_SECS);
    }

    #[test]
    fn test_derived_ban_identity() {
        assert_eq!(BAN_IDENTITY_SECS, CHURN_INTERVAL_SECS);
    }

    #[test]
    fn test_derived_ban_systematic() {
        assert_eq!(BAN_SYSTEMATIC_SECS, 8 * CHURN_INTERVAL_SECS);
    }

    #[test]
    fn test_derived_syncs_per_minute() {
        assert_eq!(
            SYNCS_PER_PEER_PER_MINUTE as u64,
            RATE_LIMIT_HEADROOM as u64 * RATE_WINDOW_SECS / TICK_INTERVAL_SECS
        );
    }

    #[test]
    fn test_derived_peer_shares_per_minute() {
        assert_eq!(
            PEER_SHARES_PER_PEER_PER_MINUTE as u64,
            RATE_LIMIT_HEADROOM as u64 * RATE_WINDOW_SECS / PING_INTERVAL_SECS
        );
    }

    #[test]
    fn test_derived_realtime_sync_interval() {
        assert_eq!(REALTIME_SYNC_INTERVAL_SECS, 2 * REPUSH_INTERVAL_SECS);
    }

    #[test]
    fn test_derived_batch_sync_interval() {
        assert_eq!(BATCH_SYNC_INTERVAL_SECS, BAN_TRANSIENT_SECS);
    }

    #[test]
    fn test_derived_channel_reconciliation_interval() {
        assert_eq!(
            CHANNEL_RECONCILIATION_INTERVAL_SECS,
            PEER_SHARE_INTERVAL_SECS
        );
    }

    #[test]
    fn test_derived_channel_responder_offset() {
        assert_eq!(CHANNEL_RESPONDER_OFFSET_SECS, PEER_SHARE_INTERVAL_SECS / 2);
    }

    // ── A channel from its secret (decision 2026-10-04) ──────────────

    #[test]
    fn test_revision_bands_decision_2026_10_04_2_3() {
        assert_eq!(REV_BAND_BITS, 9);
        assert_eq!(REV_COUNT_BITS, 44);
        assert_eq!(REV_BAND_SIZE, 1 << 44);
        assert_eq!(REV_BAND_HALF, 1 << 43);
        assert_eq!(MAX_REV, (1 << 53) - 1);
    }

    #[test]
    fn test_statement_bounds_decision_2026_10_04_4_1() {
        assert_eq!(MAX_STATEMENT_NUMBER, 256);
        assert_eq!(MAX_STATEMENT_DEVICES, 64);
        assert_eq!(MAX_STATEMENT_REMOVED, 256);
        assert_eq!(MAX_STATEMENT_CHAIN, 256);
        assert_eq!(MAX_DEVICE_LABEL_BYTES, 64);
        assert_eq!(STATEMENT_HASH_BYTES, 16);
        // About 21 KB at every bound together.
        assert_eq!(MAX_STATEMENT_BYTES, 20_784);
    }

    #[test]
    fn test_change_entry_decision_2026_10_04_4_6() {
        assert_eq!(CHANGE_ENTRY_BYTES, 32_768);
        assert_eq!(
            CHANGE_ENTRY_DEVICES_PART_BYTES + CHANGE_ENTRY_PHRASE_PART_BYTES,
            CHANGE_ENTRY_BYTES
        );
        assert_eq!(SEALED_SECRET_BYTES, 92);
        assert_eq!(MAX_EARLIER_SECRETS, 8);
        // The three labels of a change entry: of each part, and of the
        // secret sealed to each device.
        assert_eq!(LABEL_CHANGE_DEVICES, b"cordelia v2 change devices");
        assert_eq!(LABEL_CHANGE_PHRASE, b"cordelia v2 change phrase");
        assert_eq!(LABEL_CHANGE_SECRET, b"cordelia v2 change secret");
    }

    /// The bounds of an entry, and the room that is kept in every entry
    /// for its chain: at every bound together the content is 64,675 bytes
    /// of the 65,536 it may be.
    #[test]
    fn test_entry_bounds_decision_2026_10_04_2_3() {
        assert_eq!(MIN_ENTRY_CONTENT_BYTES, 256);
        assert_eq!(MAX_ENTRY_LINKS, 100);
        assert_eq!(MAX_ENTRY_NAME_AND_VALUE_BYTES, 61_440); // 60 KB
        // A link is 32 bytes: the first 16 of a hash, and of a key.
        assert_eq!(ENTRY_LINK_HASH_BYTES, 16);
        assert_eq!(ENTRY_LINK_SIGNER_BYTES, 16);
        // A count, and 100 links: 3,200 bytes of links.
        assert_eq!(MAX_ENTRY_CHAIN_BYTES, 2 + 100 * 32);
        assert_eq!(MAX_ENTRY_CHAIN_BYTES, 3_202);
        let at_every_bound = ITEM_SEAL_OVERHEAD_BYTES
            + 2
            + 1
            + 2
            + MAX_ENTRY_NAME_AND_VALUE_BYTES
            + MAX_ENTRY_CHAIN_BYTES;
        assert_eq!(at_every_bound, 64_675);
        assert_eq!(MAX_ITEM_BYTES - at_every_bound, 861);
        // Nine sizes: each power of two from 256 bytes to 64 KB.
        let sizes = (MIN_ENTRY_CONTENT_BYTES..=MAX_ITEM_BYTES)
            .filter(|size| size.is_power_of_two())
            .count();
        assert_eq!(sizes, 9);
        // The clear fields and the two signatures.
        assert_eq!(ENTRY_CLEAR_BYTES, 233);
    }

    #[test]
    fn test_phrase_decision_2026_10_04_5() {
        assert_eq!(PHRASE_WORDS, 12);
        assert_eq!(PHRASE_BYTES, 16);
        // Twelve words of eleven bits: the bytes, and four bits of checksum.
        assert_eq!(PHRASE_WORDS * 11, PHRASE_BYTES * 8 + PHRASE_BYTES / 4);
    }

    /// The labels the decision names are spelled as it spells them, and no
    /// label is the beginning of another: two derivations under two labels
    /// never have the same input, whatever follows the label.
    #[test]
    fn test_no_label_begins_another_decision_2026_10_04_2_2() {
        assert_eq!(LABEL_ENTRY_KEY, b"cordelia v2 entry");
        assert_eq!(LABEL_SLOT_KEY, b"cordelia v2 slot");
        assert_eq!(LABEL_CHANNEL_SIGN, b"cordelia v2 sign");
        assert_eq!(LABEL_PERSONAL, b"cordelia v2 personal");
        assert_eq!(LABEL_OWN, b"cordelia v2 own");
        assert_eq!(LABEL_PAIR, b"cordelia v2 pair");
        assert_eq!(LABEL_RECOVERY, b"cordelia v2 recovery");
        assert_eq!(LABEL_LOCKED, b"cordelia v2 locked");
        for (i, one) in LABELS.iter().enumerate() {
            for (j, other) in LABELS.iter().enumerate() {
                assert!(
                    i == j || !other.starts_with(one),
                    "{:?} begins {:?}",
                    String::from_utf8_lossy(one),
                    String::from_utf8_lossy(other)
                );
            }
        }
    }

    /// The record of an addition, and the hand-over that carries it: at
    /// every bound together a hand-over is 54,275 bytes, and with its name
    /// it is within the 61,440 that one entry may hold.
    #[test]
    fn test_adding_a_device_decision_2026_10_04_6() {
        assert_eq!(LABEL_ADDITION, b"cordelia v2 addition");
        // Two keys, a label of 64 bytes behind its length, a time, a
        // statement's number and hash, and a signature.
        assert_eq!(MAX_ADDITION_BYTES, 226);
        assert_eq!(HAND_OVER_NAME, "hand-over");
        // A typed key opens its pair channel for an hour.
        assert_eq!(PAIR_KEY_TYPED_SECS, 3_600);
        // The device that adds keeps a hand-over for two hours.
        assert_eq!(HAND_OVER_KEPT_SECS, 7_200);
        assert_eq!(MAX_HAND_OVER_RECORDS, 2);
        assert_eq!(HAND_OVER_CHANGE_ENTRY_BYTES, 192 + 32_768);
        assert_eq!(MAX_HAND_OVER_BYTES, 54_275);
        assert_eq!(
            MAX_HAND_OVER_BYTES,
            8 + 2 + MAX_STATEMENT_BYTES + 64 + 192 + CHANGE_ENTRY_BYTES + 1 + 2 * 228
        );
        assert_eq!(
            MAX_ENTRY_NAME_AND_VALUE_BYTES - HAND_OVER_NAME.len() - MAX_HAND_OVER_BYTES,
            7_156
        );
        // A reader counts as many devices as a statement may list, and
        // keeps a bounded number of records that do not count.
        assert_eq!(MAX_NOT_COUNTED_RECORDS, 256);
        assert_eq!(MAX_COUNTED_DEVICES, 64);
        assert_eq!(MAX_COUNTED_DEVICES, MAX_STATEMENT_DEVICES);
    }

    #[test]
    fn test_what_a_device_holds_of_its_person_decision_2026_10_04_3() {
        assert_eq!(LEFT_SECRET_KEPT_DAYS, 90);
        assert_eq!(CHANGE_ENTRY_NAME, "change");
        // The two kinds of entry in the personal channel that are not
        // carried: neither name begins the other.
        assert_eq!(PERSONAL_APPLIED_PREFIX, "applied/");
        assert_eq!(PERSONAL_ADDED_PREFIX, "added/");
        assert!(!PERSONAL_APPLIED_PREFIX.starts_with(PERSONAL_ADDED_PREFIX));
        assert!(!PERSONAL_ADDED_PREFIX.starts_with(PERSONAL_APPLIED_PREFIX));
    }

    /// An entry on the wire: the largest is 65,773 bytes, within the
    /// 66,560 it is counted at.
    #[test]
    fn test_an_entry_on_the_wire_decision_2026_10_04_2_4() {
        assert_eq!(ENTRY_WIRE_OVERHEAD_BYTES, 237);
        assert_eq!(ENTRY_WIRE_OVERHEAD_BYTES, ENTRY_CLEAR_BYTES + 4);
        assert_eq!(MAX_ENTRY_WIRE_BYTES, 65_773);
        assert!(MAX_ENTRY_WIRE_BYTES as u64 <= entry_cost(MAX_ITEM_BYTES));
    }

    /// The proof that a connection holds a channel's key: its label, and
    /// the length of the session's value.
    #[test]
    fn test_the_proof_of_a_channels_key_decision_2026_10_04_2_4() {
        assert_eq!(LABEL_CHANNEL_PROOF, b"cordelia v2 proof");
        assert_eq!(SESSION_VALUE_BYTES, 32);
        assert!(LABELS.contains(&LABEL_CHANNEL_PROOF));
        assert_eq!(LABELS.len(), 25);
    }

    /// What the commands a person types go by: the place of a device's
    /// word that it has left, a key's fingerprint and how much of it is
    /// shown, the two minutes of the fetch before a change, when a command
    /// says how many statements are left, and the wait of a device that is
    /// given a new key.
    #[test]
    fn test_the_commands_a_person_types_decision_2026_10_04_5_to_8() {
        assert_eq!(PERSONAL_LEFT_PREFIX, "left/");
        for other in [
            PERSONAL_APPLIED_PREFIX,
            PERSONAL_ADDED_PREFIX,
            PERSONAL_NAME_PREFIX,
        ] {
            assert!(!PERSONAL_LEFT_PREFIX.starts_with(other));
            assert!(!other.starts_with(PERSONAL_LEFT_PREFIX));
        }
        assert_eq!(LABEL_FINGERPRINT, b"cordelia v2 fingerprint");
        assert!(LABELS.contains(&LABEL_FINGERPRINT));
        assert_eq!(FINGERPRINT_WORDS_SHOWN, 4);
        // Four words of eleven bits are within the 256 of the hash.
        const { assert!(FINGERPRINT_WORDS_SHOWN * 11 <= 256) };
        assert_eq!(CHANGE_FETCH_MAX_SECS, 120);
        assert_eq!(STATEMENTS_LEFT_SAID_BELOW, 16);
        const { assert!(STATEMENTS_LEFT_SAID_BELOW < MAX_STATEMENT_NUMBER) };
        assert_eq!(LEAVING_SEND_WAIT_SECS, 30);
        assert_eq!(LEAVING_SEND_WAIT_SECS, WAKE_WAIT_SECS);
        assert_eq!(MAX_TYPED_KEYS, 8);
        assert_eq!(TYPED_KEY_KEPT_SECS, 86_400);
        // A key is kept for longer than it reads, to say what became of it.
        const { assert!(TYPED_KEY_KEPT_SECS > PAIR_KEY_TYPED_SECS) };
    }

    /// What a carry that a person asks for, and a recovery, go by
    /// (decision 2026-10-04 §7.3, §9).
    #[test]
    fn test_a_carry_by_command_and_a_recovery_decision_2026_10_04_7_3_and_9() {
        assert_eq!(CARRY_READ_MAX_SECS, 120);
        assert_eq!(CARRY_FIRST_MAX_SECS, 180);
        // The first cycle waits for longer than the carry may read.
        const { assert!(CARRY_FIRST_MAX_SECS > CARRY_READ_MAX_SECS) };
        assert_eq!(CARRY_FROM_WORDS, 6);
        // More words than a device is shown by, and within the hash.
        const { assert!(CARRY_FROM_WORDS > FINGERPRINT_WORDS_SHOWN) };
        const { assert!(CARRY_FROM_WORDS * 11 <= 256) };
        assert_eq!(LABEL_CARRY_WORD, b"cordelia v2 carry word");
        assert!(LABELS.contains(&LABEL_CARRY_WORD));
        assert_eq!(CARRY_WORD_SECS, 600);
        assert_eq!(LABEL_CARRY_BATCH, b"cordelia v2 carry batch");
        assert!(LABELS.contains(&LABEL_CARRY_BATCH));
        assert_eq!(CARRY_PART_MAX_BYTES, 512 * 1024);
        // A part holds an entry of any size that a channel carries.
        const { assert!(CARRY_PART_MAX_BYTES >= MAX_ITEM_BYTES) };
        assert_eq!(RECOVERY_MAX_NAMES, 1_024);
        assert_eq!(RECOVERY_MAX_DEVICES_SHOWN, 256);
        assert_eq!(RECOVERY_MAX_LEFT_SECRETS, 9);
        // A recovery shows every device that a reader may count, and
        // every record that it may keep as not counted beside them.
        const { assert!(RECOVERY_MAX_DEVICES_SHOWN >= MAX_COUNTED_DEVICES) };
    }

    /// What the sync adapter goes by in a channel from its secret: how
    /// long a folder's first cycle waits for the relays after the first
    /// has handed its channel, what a device adds to its word once it has
    /// sent what it carried, and the spans over which a removal says what
    /// was received.
    #[test]
    fn test_the_adapter_in_a_channel_from_its_secret_decision_2026_10_04_6_to_8() {
        assert_eq!(FIRST_FETCH_WAIT_SECS, 30);
        assert_eq!(FIRST_FETCH_WAIT_SECS, WAKE_WAIT_SECS);
        assert_eq!(PERSONAL_APPLIED_SENT, " sent");
        // A statement's number is digits alone: what follows it in the
        // word is told from it.
        assert!(!PERSONAL_APPLIED_SENT.starts_with(|c: char| c.is_ascii_digit()));
        assert_eq!(RECEIVED_LAST_DAY_SECS, 86_400);
        assert_eq!(RECEIVED_LAST_WEEK_SECS, 604_800);
        // A file's text and its name are bounded by the one constant.
        assert_eq!(MAX_ENTRY_NAME_AND_VALUE_BYTES, 61_440);
    }

    /// What the status line goes by for its level (decision 2026-10-04
    /// §8, §10.1): the five minutes that a passing thing has lasted
    /// before it is amber, the seven days for which a removal that some
    /// device has not applied is, and for how long a relay's refusal for
    /// room is taken to stand.
    #[test]
    fn test_the_level_of_the_status_line_decision_2026_10_04_10_1() {
        assert_eq!(STATUS_AMBER_WAIT_SECS, 300);
        assert_eq!(REMOVAL_NOT_APPLIED_SHOWN_DAYS, 7);
        assert_eq!(NO_ROOM_STANDS_SECS, 1_200);
        assert_eq!(NO_ROOM_STANDS_SECS, 2 * OUTBOX_REFUSED_RETRY_MAX_SECS);
        // A device that wakes has heard from its relays, or given them
        // up, well within the wait.
        const { assert!(WAKE_WAIT_SECS * 2 < STATUS_AMBER_WAIT_SECS) };
        // A removal is shown for less long than the secret it left is
        // kept, so the time that it was applied is still known.
        const { assert!(REMOVAL_NOT_APPLIED_SHOWN_DAYS < LEFT_SECRET_KEPT_DAYS) };
    }

    /// The waits between the tries at a first start that keeps failing
    /// (decision 2026-10-04 §10.1): from five seconds to ten minutes.
    #[test]
    fn test_the_tries_at_a_first_start_back_off_decision_2026_10_04_10_1() {
        assert_eq!(FIRST_START_RETRY_BASE_SECS, 5);
        assert_eq!(FIRST_START_RETRY_MAX_SECS, 600);
        assert_eq!(FIRST_START_RETRY_MAX_SECS, OUTBOX_REFUSED_RETRY_MAX_SECS);
        assert_eq!(FIRST_START_RETRY_SLACK_SECS, 1);
        const { assert!(FIRST_START_RETRY_SLACK_SECS < FIRST_START_RETRY_BASE_SECS) };
    }

    /// The value that a proof is made over is exported from a TLS session
    /// under a label of its own, which begins as an exporter's does and
    /// is none of the labels that anything is signed or derived under.
    #[test]
    fn test_the_sessions_value_has_a_label_of_its_own_decision_2026_10_04_16() {
        assert_eq!(LABEL_SESSION_VALUE, b"EXPORTER-cordelia v2 session");
        assert!(LABEL_SESSION_VALUE.starts_with(b"EXPORTER"));
        assert_eq!(
            LABELS
                .iter()
                .filter(|label| **label == LABEL_SESSION_VALUE)
                .count(),
            1
        );
        // A connection remembers only so many channels as proved.
        assert_eq!(MAX_CHANNELS_PROVED_ON_A_CONNECTION, 1024);
    }

    /// What a read of a generation that was left keeps back of a
    /// connection's places (decision 2026-10-04 §16): one for each
    /// channel of the device's own that is not yet proved there, and a
    /// margin of one place in sixty-four; and never more than half.
    #[test]
    fn test_what_a_read_of_a_generation_that_was_left_keeps_back_decision_2026_10_04_16() {
        const MOST: usize = MAX_CHANNELS_PROVED_ON_A_CONNECTION;
        assert_eq!(LEFT_PROOFS_MARGIN_SHARE, 64);
        assert_eq!(left_proofs_kept_back(0, MOST), 16);
        assert_eq!(left_proofs_kept_back(1, MOST), 17);
        assert_eq!(left_proofs_kept_back(30, MOST), 46);
        // A device with tens of channels leaves a read nearly all of a
        // connection, and has a place for each of its own.
        assert_eq!(MOST - left_proofs_kept_back(30, MOST), 978);
        // Never more than half: a read always has half a connection.
        assert_eq!(left_proofs_kept_back(496, MOST), 512);
        assert_eq!(left_proofs_kept_back(497, MOST), 512);
        assert_eq!(left_proofs_kept_back(1_025, MOST), 512);
        assert_eq!(left_proofs_kept_back(usize::MAX, MOST), 512);
        // Where a relay remembers fewer, as a test has one do.
        assert_eq!(left_proofs_kept_back(6, 16), 6);
        assert_eq!(left_proofs_kept_back(9, 16), 8);
        assert_eq!(left_proofs_kept_back(0, 16), 0);
        // A recovery's look of 1,024 names in nine generations reads
        // 9,216 channels: half a connection at a time, in 18 connections.
        let read = RECOVERY_MAX_NAMES * RECOVERY_MAX_LEFT_SECRETS;
        assert_eq!(read, 9_216);
        let on_one = MOST - left_proofs_kept_back(RECOVERY_MAX_NAMES + 1, MOST);
        assert_eq!(read.div_ceil(on_one), 18);
    }

    /// The stream between relays that work together has a byte of its
    /// own, after the four of entries, and none of the older kind's. A
    /// holding of a channel is marked with 8 bytes.
    #[test]
    fn test_relays_that_work_together_decision_2026_10_04_2_4() {
        assert_eq!(PROTOCOL_RELAY_ENTRIES, 0x14);
        for byte in [
            PROTOCOL_ENTRY_SHOW,
            PROTOCOL_CHANNEL_PROVE,
            PROTOCOL_ENTRY_PULL,
            PROTOCOL_ENTRY_PUSH,
        ] {
            assert_ne!(PROTOCOL_RELAY_ENTRIES, byte);
        }
        assert!(!(0x01..=0x08).contains(&PROTOCOL_RELAY_ENTRIES));
        assert_eq!(CHANNEL_MARK_BYTES, 8);
        assert_eq!(RELAY_CHANNELS_PAGE_MAX, 1000);
        // A full answer is well within one message: each channel told is
        // under 200 bytes as it travels.
        assert!(RELAY_CHANNELS_PAGE_MAX as usize * 200 < MAX_MESSAGE_BYTES as usize / 2);
        // What nobody uses is swept hourly, as expired deletes are, and
        // entries pass between relays as items of the older kind do.
        assert_eq!(ENTRY_CHANNEL_SWEEP_INTERVAL_SECS, 3_600);
        assert_eq!(
            ENTRY_CHANNEL_SWEEP_INTERVAL_SECS,
            TOMBSTONE_GC_INTERVAL_SECS
        );
        assert_eq!(ENTRY_OFFER_INTERVAL_SECS, REPUSH_INTERVAL_SECS);
        assert_eq!(RELAY_ENTRY_PULL_INTERVAL_SECS, REALTIME_SYNC_INTERVAL_SECS);
        assert_eq!(RELAY_ENTRY_PULL_PAGES, 10);
        assert_eq!(RELAY_CHANNEL_PAGES_PER_PASS, 10);
    }

    /// A connection may make 3,000 requests a minute on the streams of
    /// entries. That is room for a device with 256 names: a pull of each,
    /// and of its personal channel, every ten seconds; its day's proofs in
    /// one burst; and a show and a push every two seconds besides.
    #[test]
    fn test_requests_on_the_streams_of_entries_decision_2026_10_04_16() {
        assert_eq!(ENTRY_REQUESTS_PER_PEER_PER_MINUTE, 3_000);
        let passes = 60 / REALTIME_SYNC_INTERVAL_SECS;
        let pulls = passes * (NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR as u64 + 1);
        assert_eq!(pulls, 1_542);
        let proofs = MAX_CHANNELS_PROVED_ON_A_CONNECTION as u64;
        let sends = 2 * (60 / OUTBOX_FLUSH_INTERVAL_SECS);
        assert_eq!(pulls + proofs + sends, 2_626);
        assert!(pulls + proofs + sends <= u64::from(ENTRY_REQUESTS_PER_PEER_PER_MINUTE));
    }

    /// A device's side of a relay: the leave that an answer to a show
    /// gives lasts as long as the time between two passes, a device that
    /// wakes waits half a minute for its relays, a relay remembers 8
    /// slots as shown whole for a connection, and a proof is made again
    /// once a day, which is well within the 90 days that a channel
    /// nobody uses is kept.
    #[test]
    fn test_a_devices_side_of_a_relay_decision_2026_10_04_4_6() {
        // A device paces what it asks of a relay as it paces what it
        // pushes: at three quarters of what the relay allows.
        assert_eq!(OWN_ENTRY_REQUESTS_PER_MINUTE, 2_250);
        assert_eq!(
            u64::from(OWN_ENTRY_REQUESTS_PER_MINUTE) * PUSH_BYTES_PER_PEER_PER_MINUTE,
            u64::from(ENTRY_REQUESTS_PER_PEER_PER_MINUTE) * OUTBOX_BYTES_PER_MINUTE
        );
        // Its shows are beside that, and with them it is still within
        // what a relay allows: one for each whole pass and each pass that
        // sends, and as many again where an answer has it show whole.
        let passes = 60 / REALTIME_SYNC_INTERVAL_SECS + 60 / OUTBOX_FLUSH_INTERVAL_SECS;
        assert!(
            u64::from(OWN_ENTRY_REQUESTS_PER_MINUTE) + 2 * passes
                < u64::from(ENTRY_REQUESTS_PER_PEER_PER_MINUTE)
        );
        assert_eq!(SHOW_LEAVE_SECS, 10);
        assert_eq!(SHOW_LEAVE_SECS, REALTIME_SYNC_INTERVAL_SECS);
        // What a device sends on its own timer goes several times within
        // one leave.
        const { assert!(OUTBOX_FLUSH_INTERVAL_SECS < SHOW_LEAVE_SECS) };
        assert_eq!(WAKE_WAIT_SECS, 30);
        const { assert!(WAKE_WAIT_SECS > SHOW_LEAVE_SECS) };
        assert_eq!(MAX_SLOTS_SHOWN_ON_A_CONNECTION, 8);
        assert_eq!(CHANNEL_PROOF_AGAIN_SECS, 86_400);
        const { assert!(CHANNEL_PROOF_AGAIN_SECS < ENTRY_CHANNEL_UNUSED_DAYS as u64 * 86_400) };
        assert_eq!(PERSONAL_NAME_PREFIX, "name/");
        for other in [PERSONAL_APPLIED_PREFIX, PERSONAL_ADDED_PREFIX] {
            assert!(!PERSONAL_NAME_PREFIX.starts_with(other));
            assert!(!other.starts_with(PERSONAL_NAME_PREFIX));
        }
    }

    /// Four of the five streams of entries (the fifth, between relays
    /// that work together, has a test of its own): each has a byte of its
    /// own, and none of them is one of the eight that the older kind has.
    #[test]
    fn test_the_streams_of_entries_decision_2026_10_04_2_4() {
        assert_eq!(PROTOCOL_ENTRY_SHOW, 0x10);
        assert_eq!(PROTOCOL_CHANNEL_PROVE, 0x11);
        assert_eq!(PROTOCOL_ENTRY_PULL, 0x12);
        assert_eq!(PROTOCOL_ENTRY_PUSH, 0x13);
        for byte in [
            PROTOCOL_ENTRY_SHOW,
            PROTOCOL_CHANNEL_PROVE,
            PROTOCOL_ENTRY_PULL,
            PROTOCOL_ENTRY_PUSH,
        ] {
            assert!(!(0x01..=0x08).contains(&byte), "{byte:#04x}");
        }
    }

    /// A page of a channel's entries: at most 100 of them, and at most
    /// 917,504 bytes as they travel, which is 13 of the largest.
    #[test]
    fn test_a_page_of_entries_decision_2026_10_04_2_4() {
        assert_eq!(ENTRY_PAGE_MAX_ENTRIES, 100);
        assert_eq!(ENTRY_PAGE_MAX_BYTES, 917_504);
        assert_eq!(ENTRY_PAGE_MAX_BYTES / MAX_ENTRY_WIRE_BYTES, 13);
        assert!(ENTRY_PAGE_MAX_BYTES < MAX_MESSAGE_BYTES as usize);
    }

    /// A relay's room for channels from their secrets: a channel's cap is
    /// the older kind's, the allowance of new channels is 256 an hour
    /// where the older kind's is 16, and what nobody uses goes after 90
    /// days.
    #[test]
    fn test_a_relays_room_decision_2026_10_04_2_5() {
        assert_eq!(MAX_ENTRY_CHANNEL_BYTES_AT_RELAY, 16 * 1024 * 1024);
        assert_eq!(MAX_ENTRY_CHANNEL_BYTES_AT_RELAY, MAX_CHANNEL_BYTES_AT_RELAY);
        assert_eq!(NEW_ENTRY_CHANNELS_PER_ADDRESS_PER_HOUR, 256);
        assert_eq!(NEW_CHANNELS_PER_ADDRESS_PER_HOUR, 16);
        assert_eq!(ENTRY_CHANNEL_UNUSED_DAYS, 90);
        // When a channel was last used is written down at most once an
        // hour: against 90 days, the hour is under a tenth of a percent.
        assert_eq!(ENTRY_CHANNEL_USED_STEP_SECS, 3_600);
        assert!(
            ENTRY_CHANNEL_USED_STEP_SECS * 1000 < u64::from(ENTRY_CHANNEL_UNUSED_DAYS) * 86_400
        );
        // One entry of the largest size is within what a channel may hold.
        assert!(entry_cost(MAX_ITEM_BYTES) <= MAX_ENTRY_CHANNEL_BYTES_AT_RELAY);
        // And is what a pull leaves room for, in what a key may be handed
        // in a minute, for the answer to a show (§16).
        assert_eq!(SHOW_ANSWER_ROOM_BYTES, 65_536 + 1024);
        assert_eq!(SHOW_ANSWER_ROOM_BYTES, entry_cost(MAX_ITEM_BYTES));
    }
}
