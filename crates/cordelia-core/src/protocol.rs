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
//!
//! TICK_INTERVAL_SECS ──> RATE_WINDOW_SECS ──> BAN_WINDOW_SECS
//!                    \                    \──> REALTIME_SYNC_INTERVAL_SECS
//!                     \──> SYNCS_PER_PEER_PER_MINUTE
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

/// Max concurrent bidirectional QUIC streams (network-protocol.md §2.1).
/// Primitive: generous budget; actual protocol use is much lower.
pub const QUIC_MAX_BIDI_STREAMS: u32 = 1000;

/// Max concurrent unidirectional QUIC streams (network-protocol.md §2.1).
/// Primitive: matches bidi budget for symmetry.
pub const QUIC_MAX_UNI_STREAMS: u32 = 1000;

/// TLS certificate validity in days (network-protocol.md §2.2).
/// Primitive: 1 year; self-signed certs, identity is the public key.
pub const TLS_CERT_VALIDITY_DAYS: i64 = 365;

// ══════════════════════════════════════════════════════════════════════
// TIMING PRIMITIVES -- the small set of values everything else derives from
// ══════════════════════════════════════════════════════════════════════

/// Timeout for all QUIC stream read/write operations in seconds (parameter-rationale.md §5.3).
/// Primitive: single-digit-second responsiveness; covers cross-continent RTT + processing.
/// One value, one layer (codec). If a single read or write takes longer, the peer is unresponsive.
pub const STREAM_TIMEOUT_SECS: u64 = 10;

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

/// Maximum encrypted item size: 256 KB (parameter-rationale.md §4, demand-model.md §2.3).
/// Primitive: covers 99.9% of AI agent memory payloads per demand model.
/// 256KB * 4 < 1MB wire frame.
pub const MAX_ITEM_BYTES: usize = 262_144;

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
/// Primitive: 10 writes/min; based on demand model write patterns.
/// Allows ~1 write every 6 seconds.
pub const WRITES_PER_PEER_PER_MINUTE: u32 = 10;

/// Write operations per channel per minute.
/// Primitive: 100 writes/min aggregate across all peers.
/// A busy channel with 10 writers each at the per-peer limit.
pub const WRITES_PER_CHANNEL_PER_MINUTE: u32 = 100;

/// Sync requests per peer per minute.
/// Derived: 1 sync per governor tick within each rate window.
/// RATE_WINDOW_SECS / TICK_INTERVAL_SECS = 60/10 = 6.
pub const SYNCS_PER_PEER_PER_MINUTE: u32 = (RATE_WINDOW_SECS / TICK_INTERVAL_SECS) as u32;

/// Peer-share requests per peer per minute.
/// Derived: 1 peer-share per ping interval within each rate window.
/// RATE_WINDOW_SECS / PING_INTERVAL_SECS = 60/30 = 2.
pub const PEER_SHARES_PER_PEER_PER_MINUTE: u32 = (RATE_WINDOW_SECS / PING_INTERVAL_SECS) as u32;

// ── Intervals ────────────────────────────────────────────────────────

/// Realtime channel sync interval in seconds (network-protocol.md §4.5).
/// Derived: sync once per rate window. Ensures at least 1 sync
/// opportunity per rate-limit sliding window.
pub const REALTIME_SYNC_INTERVAL_SECS: u64 = RATE_WINDOW_SECS;

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

/// Max items per fetch request (network-protocol.md §4.5).
/// Primitive: 100 items; matches MAX_BATCH_SIZE.
pub const MAX_FETCH_ITEMS: usize = 100;

/// Default max peers per peer-sharing response (network-protocol.md §4.3).
/// Primitive: 20 peers per response; enough for mesh discovery without
/// enabling address-space enumeration.
pub const DEFAULT_MAX_PEERS_SHARE: u16 = 20;

/// Tombstone retention in days (data-formats.md §4).
/// Primitive: 7 days; ensures offline nodes can sync deletions
/// when they come back online within a week.
pub const TOMBSTONE_RETENTION_DAYS: u32 = 7;

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

// ── Bootstrap ────────────────────────────────────────────────────────

/// DNS SRV record for bootnode discovery (network-protocol.md §10).
pub const SRV_RECORD: &str = "_cordelia._udp.seeddrill.ai";

/// Fallback peer addresses, compiled into binary (network-protocol.md §10).
pub const FALLBACK_PEERS: &[&str] = &[
    "boot1.cordelia.seeddrill.ai:9474",
    "boot2.cordelia.seeddrill.ai:9474",
];

// ── PSK exchange reasons (network-protocol.md §4.7) ──────────────────

/// PSK denial: channel not found.
pub const REASON_NOT_FOUND: &str = "not_found";

/// PSK denial: not authorized for this channel.
pub const REASON_NOT_AUTHORIZED: &str = "not_authorized";

/// PSK denial: PSK temporarily unavailable.
pub const REASON_NOT_AVAILABLE: &str = "not_available";

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
        assert_eq!(QUIC_MAX_BIDI_STREAMS, 1000);
    }

    #[test]
    fn test_quic_max_uni_streams_network_protocol_2_1() {
        assert_eq!(QUIC_MAX_UNI_STREAMS, 1000);
    }

    #[test]
    fn test_tls_cert_validity_days_network_protocol_2_2() {
        assert_eq!(TLS_CERT_VALIDITY_DAYS, 365);
    }

    // Stream I/O (parameter-rationale.md §5.3)
    #[test]
    fn test_stream_timeout_parameter_rationale_5_3() {
        assert_eq!(STREAM_TIMEOUT_SECS, 10);
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
        assert_eq!(MAX_ITEM_BYTES, 262_144); // 256 KB
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
        assert_eq!(WRITES_PER_PEER_PER_MINUTE, 10);
    }

    #[test]
    fn test_syncs_per_peer_per_minute_network_protocol_9_2() {
        assert_eq!(SYNCS_PER_PEER_PER_MINUTE, 6);
    }

    #[test]
    fn test_peer_shares_per_peer_per_minute_network_protocol_9_2() {
        assert_eq!(PEER_SHARES_PER_PEER_PER_MINUTE, 2);
    }

    #[test]
    fn test_ban_threshold_network_protocol_9_2() {
        assert_eq!(BAN_THRESHOLD, 3);
    }

    // Intervals (network-protocol.md §4)
    #[test]
    fn test_realtime_sync_interval_network_protocol_4_5() {
        assert_eq!(REALTIME_SYNC_INTERVAL_SECS, 60);
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
    fn test_srv_record_network_protocol_10() {
        assert_eq!(SRV_RECORD, "_cordelia._udp.seeddrill.ai");
    }

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
        assert_eq!(SYNCS_PER_PEER_PER_MINUTE as u64, RATE_WINDOW_SECS / TICK_INTERVAL_SECS);
    }

    #[test]
    fn test_derived_peer_shares_per_minute() {
        assert_eq!(PEER_SHARES_PER_PEER_PER_MINUTE as u64, RATE_WINDOW_SECS / PING_INTERVAL_SECS);
    }

    #[test]
    fn test_derived_realtime_sync_interval() {
        assert_eq!(REALTIME_SYNC_INTERVAL_SECS, RATE_WINDOW_SECS);
    }

    #[test]
    fn test_derived_batch_sync_interval() {
        assert_eq!(BATCH_SYNC_INTERVAL_SECS, BAN_TRANSIENT_SECS);
    }

    #[test]
    fn test_derived_channel_reconciliation_interval() {
        assert_eq!(CHANNEL_RECONCILIATION_INTERVAL_SECS, PEER_SHARE_INTERVAL_SECS);
    }

    #[test]
    fn test_derived_channel_responder_offset() {
        assert_eq!(CHANNEL_RESPONDER_OFFSET_SECS, PEER_SHARE_INTERVAL_SECS / 2);
    }
}
