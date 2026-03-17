//! Protocol constants -- single source of truth for all Cordelia parameters.
//!
//! Every constant has a doc comment citing the spec section it derives from.
//! Do not define protocol constants elsewhere. Import from this module.
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
pub const QUIC_KEEPALIVE_INTERVAL_SECS: u64 = 15;

/// QUIC max idle timeout in seconds (network-protocol.md §2.1).
pub const QUIC_MAX_IDLE_TIMEOUT_SECS: u64 = 60;

/// Max concurrent bidirectional QUIC streams (network-protocol.md §2.1).
pub const QUIC_MAX_BIDI_STREAMS: u32 = 1000;

/// Max concurrent unidirectional QUIC streams (network-protocol.md §2.1).
pub const QUIC_MAX_UNI_STREAMS: u32 = 1000;

/// TLS certificate validity in days (network-protocol.md §2.2).
pub const TLS_CERT_VALIDITY_DAYS: i64 = 365;

// ── Stream I/O ───────────────────────────────────────────────────────

/// Timeout for all QUIC stream read/write operations in seconds (parameter-rationale.md §5.3).
/// One value, one layer (codec). If a single read or write takes longer, the peer is unresponsive.
pub const STREAM_TIMEOUT_SECS: u64 = 10;

// ── Keepalive ────────────────────────────────────────────────────────

/// Application-level ping interval in seconds (network-protocol.md §4.2).
pub const PING_INTERVAL_SECS: u64 = 30;

/// Number of missed pings before peer is considered dead (network-protocol.md §4.2).
pub const DEAD_THRESHOLD: u64 = 3;

/// Dead timeout in seconds = PING_INTERVAL_SECS * DEAD_THRESHOLD (network-protocol.md §4.2).
pub const DEAD_TIMEOUT_SECS: u64 = 90;

// ── Handshake ────────────────────────────────────────────────────────

/// Handshake timeout in seconds (network-protocol.md §4.1.3).
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Maximum clock skew tolerance in seconds (network-protocol.md §4.1.5).
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

// ── Governor defaults (personal node, demand-model.md §3.2) ─────────

/// Minimum hot peers (parameter-rationale.md §3).
pub const HOT_MIN: u32 = 2;

/// Maximum hot peers for personal node (parameter-rationale.md §3).
pub const HOT_MAX: u32 = 2;

/// Minimum hot relay peers (parameter-rationale.md §3).
pub const HOT_MIN_RELAYS: u32 = 1;

/// Minimum warm peers (parameter-rationale.md §3).
pub const WARM_MIN: u32 = 3;

/// Maximum warm peers for personal node (parameter-rationale.md §3).
pub const WARM_MAX: u32 = 10;

/// Maximum cold peers for personal node (parameter-rationale.md §3).
pub const COLD_MAX: u32 = 50;

/// Anti-Sybil: minimum time in Warm before Hot promotion in seconds (parameter-rationale.md §3).
/// Bypassed when hot < hot_min (bootstrap urgency).
pub const MIN_WARM_TENURE_SECS: u64 = 300;

/// Churn rotation interval in seconds (parameter-rationale.md §3).
pub const CHURN_INTERVAL_SECS: u64 = 3600;

/// Churn jitter range in seconds (parameter-rationale.md §3).
pub const CHURN_JITTER_SECS: u64 = 300;

/// Fraction of warm peers to promote per churn cycle (parameter-rationale.md §3).
pub const CHURN_FRACTION: f64 = 0.2;

/// Governor tick interval in seconds (network-behaviour.md §5.1).
pub const TICK_INTERVAL_SECS: u64 = 10;

/// Hysteresis duration in seconds to prevent rapid state oscillation (parameter-rationale.md §3).
pub const HYSTERESIS_SECS: u64 = 90;

/// Time without activity before a peer is considered stale in seconds (parameter-rationale.md §3).
pub const STALE_THRESHOLD_SECS: u64 = 1800;

/// Exponential moving average alpha for peer scoring (parameter-rationale.md §3).
pub const EMA_ALPHA: f64 = 0.1;

// ── Backoff ──────────────────────────────────────────────────────────

/// Reconnect backoff base duration in seconds (parameter-rationale.md §3).
pub const BACKOFF_BASE_SECS: u64 = 30;

/// Maximum reconnect backoff in seconds (15 minutes, parameter-rationale.md §3).
pub const BACKOFF_MAX_SECS: u64 = 900;

/// Backoff saturation: stops doubling after this many disconnects (parameter-rationale.md §3).
pub const BACKOFF_SATURATION: u32 = 5;

/// Maximum connection retries before giving up (configuration.md §3).
pub const MAX_CONNECTION_RETRIES: u32 = 5;

/// Delay before clearing failure state in seconds (configuration.md §3).
pub const CLEAR_FAILURE_DELAY_SECS: u64 = 120;

// ── Ban tiers (parameter-rationale.md §3) ────────────────────────────

/// Transient ban: rate limit breach, protocol violation (seconds).
pub const BAN_TRANSIENT_SECS: u64 = 900;

/// Identity ban: identity/PSK fraud (seconds).
pub const BAN_IDENTITY_SECS: u64 = 3600;

/// Systematic ban: systematic abuse (seconds).
pub const BAN_SYSTEMATIC_SECS: u64 = 28800;

// ── Size limits ──────────────────────────────────────────────────────

/// Maximum wire message size: 1 MB (parameter-rationale.md §5.2).
pub const MAX_MESSAGE_BYTES: u32 = 1_048_576;

/// Maximum encrypted item size: 256 KB (parameter-rationale.md §4, demand-model.md §2.3).
pub const MAX_ITEM_BYTES: usize = 262_144;

/// Maximum items per batch fetch (demand-model.md §3.1).
pub const MAX_BATCH_SIZE: usize = 100;

/// Maximum items per listen query (channels-api.md §3).
pub const MAX_LISTEN_LIMIT: u32 = 500;

/// Maximum serialized descriptor size in bytes (network-protocol.md §4.4.6).
pub const MAX_DESCRIPTOR_SIZE: usize = 512;

/// Maximum channel name length (network-protocol.md §4.4.6).
pub const MAX_CHANNEL_NAME_LEN: usize = 63;

/// Default max storage per node: 1 GB (configuration.md §3).
pub const MAX_STORAGE_BYTES: u64 = 1_073_741_824;

// ── Connection limits (network-protocol.md §9.1) ────────────────────

/// Maximum inbound connections.
pub const MAX_INBOUND_CONNECTIONS: usize = 200;

/// Maximum connections from a single IP.
pub const MAX_CONNECTIONS_PER_IP: usize = 5;

/// Maximum connections from a single /24 (IPv4) or /48 (IPv6) subnet.
pub const MAX_CONNECTIONS_PER_SUBNET: usize = 20;

/// Maximum concurrent QUIC streams per connection.
pub const MAX_CONCURRENT_STREAMS: usize = 64;

// ── Rate limits (network-protocol.md §9.2) ──────────────────────────

/// Write operations per peer per minute.
pub const WRITES_PER_PEER_PER_MINUTE: u32 = 10;

/// Write operations per channel per minute.
pub const WRITES_PER_CHANNEL_PER_MINUTE: u32 = 100;

/// Sync requests per peer per minute.
pub const SYNCS_PER_PEER_PER_MINUTE: u32 = 6;

/// Peer-share requests per peer per minute.
pub const PEER_SHARES_PER_PEER_PER_MINUTE: u32 = 2;

/// Number of rate limit breaches before ban.
pub const BAN_THRESHOLD: u32 = 3;

/// Window for counting rate limit breaches in seconds.
pub const BAN_WINDOW_SECS: u64 = 600;

/// Sliding window for rate counters in seconds.
pub const RATE_WINDOW_SECS: u64 = 60;

// ── Intervals ────────────────────────────────────────────────────────

/// Realtime channel sync interval in seconds (network-protocol.md §4.5).
pub const REALTIME_SYNC_INTERVAL_SECS: u64 = 60;

/// Batch channel sync interval in seconds (network-protocol.md §4.5).
pub const BATCH_SYNC_INTERVAL_SECS: u64 = 900;

/// Peer-sharing request interval in seconds (network-protocol.md §4.3).
pub const PEER_SHARE_INTERVAL_SECS: u64 = 300;

/// Channel reconciliation interval in seconds (network-protocol.md §4.4.2).
pub const CHANNEL_RECONCILIATION_INTERVAL_SECS: u64 = 300;

/// Responder stagger offset for reconciliation in seconds (network-protocol.md §4.4.2).
pub const CHANNEL_RESPONDER_OFFSET_SECS: u64 = 150;

// ── Replication ──────────────────────────────────────────────────────

/// Default sync limit (max headers per response, network-protocol.md §4.5).
pub const DEFAULT_SYNC_LIMIT: u32 = 100;

/// Max items per fetch request (network-protocol.md §4.5).
pub const MAX_FETCH_ITEMS: usize = 100;

/// Default max peers per peer-sharing response (network-protocol.md §4.3).
pub const DEFAULT_MAX_PEERS_SHARE: u16 = 20;

/// Tombstone retention in days (data-formats.md §4).
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

    // Consistency checks
    #[test]
    fn test_max_item_fits_in_message() {
        assert!(MAX_ITEM_BYTES < MAX_MESSAGE_BYTES as usize);
    }

    #[test]
    fn test_dead_timeout_equals_ping_times_threshold() {
        assert_eq!(DEAD_TIMEOUT_SECS, PING_INTERVAL_SECS * DEAD_THRESHOLD);
    }
}
