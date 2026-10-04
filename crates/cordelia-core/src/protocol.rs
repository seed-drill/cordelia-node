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

/// Every label above, for the tests that set one against another.
pub const LABELS: [&[u8]; 15] = [
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
}
