//! Rate limiting and backpressure (§9).
//!
//! Implements connection limits, message rate limits, and size limits.
//! Uses a sliding window counter for per-peer rate tracking.
//!
//! Spec: seed-drill/specs/network-protocol.md §9

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

// ── Connection limits (§9.1) ───────────────────────────────────────

/// Default connection limits.
pub const MAX_INBOUND_CONNECTIONS: usize = 200;
pub const MAX_CONNECTIONS_PER_IP: usize = 5;
pub const MAX_CONNECTIONS_PER_SUBNET: usize = 20;
pub const MAX_CONCURRENT_STREAMS: usize = 64;

/// QUIC application error code for capacity rejection.
pub const ERR_CAPACITY: u32 = 0x01;

// ── Message rate limits (§9.2) ─────────────────────────────────────

pub const WRITES_PER_PEER_PER_MINUTE: u32 = 10;
pub const WRITES_PER_CHANNEL_PER_MINUTE: u32 = 100;
pub const SYNCS_PER_PEER_PER_MINUTE: u32 = 6;
pub const PEER_SHARES_PER_PEER_PER_MINUTE: u32 = 2;

/// Number of rate limit breaches before ban.
pub const BAN_THRESHOLD: u32 = 3;
/// Window for counting breaches.
pub const BAN_WINDOW: Duration = Duration::from_secs(600);

// ── Size limits (§9.3) ────────────────────────────────────────────

pub const MAX_ITEM_BYTES: usize = 1_048_576; // 1 MB
pub const MAX_MESSAGE_BYTES: u32 = 4_194_304; // 4 MB
pub const MAX_BATCH_SIZE: usize = 100;

// ── Backpressure queue capacities (§9.4) ───────────────────────────

pub const QUEUE_HANDSHAKE: usize = 16;
pub const QUEUE_KEEPALIVE: usize = 256;
pub const QUEUE_PEER_SHARING: usize = 32;
pub const QUEUE_CHANNEL_ANNOUNCE: usize = 64;
pub const QUEUE_ITEM_SYNC: usize = 64;
pub const QUEUE_ITEM_PUSH: usize = 128;

// ── Sliding window rate counter ────────────────────────────────────

/// Sliding window counter for rate limiting.
///
/// Tracks event timestamps in a sliding window. O(1) amortized check.
#[derive(Debug, Clone)]
pub struct RateCounter {
    window: Duration,
    max_count: u32,
    timestamps: Vec<Instant>,
}

impl RateCounter {
    pub fn new(window: Duration, max_count: u32) -> Self {
        Self {
            window,
            max_count,
            timestamps: Vec::new(),
        }
    }

    /// Record an event. Returns true if within limit, false if exceeded.
    pub fn check_and_record(&mut self) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window;

        // Remove expired entries
        self.timestamps.retain(|t| *t > cutoff);

        if self.timestamps.len() >= self.max_count as usize {
            false
        } else {
            self.timestamps.push(now);
            true
        }
    }

    /// Check without recording.
    pub fn would_exceed(&self) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window;
        let active = self.timestamps.iter().filter(|t| **t > cutoff).count();
        active >= self.max_count as usize
    }

    /// Current count within window.
    pub fn count(&self) -> usize {
        let now = Instant::now();
        let cutoff = now - self.window;
        self.timestamps.iter().filter(|t| **t > cutoff).count()
    }
}

// ── Per-peer rate tracker ──────────────────────────────────────────

/// Tracks rate limits for a single peer.
#[derive(Debug)]
pub struct PeerRateLimiter {
    pub writes: RateCounter,
    pub syncs: RateCounter,
    pub peer_shares: RateCounter,
    pub breach_count: u32,
    pub first_breach: Option<Instant>,
}

impl PeerRateLimiter {
    pub fn new() -> Self {
        let minute = Duration::from_secs(60);
        Self {
            writes: RateCounter::new(minute, WRITES_PER_PEER_PER_MINUTE),
            syncs: RateCounter::new(minute, SYNCS_PER_PEER_PER_MINUTE),
            peer_shares: RateCounter::new(minute, PEER_SHARES_PER_PEER_PER_MINUTE),
            breach_count: 0,
            first_breach: None,
        }
    }

    /// Record a rate limit breach. Returns true if peer should be banned.
    pub fn record_breach(&mut self) -> bool {
        let now = Instant::now();
        match self.first_breach {
            Some(first) if now.duration_since(first) > BAN_WINDOW => {
                // Reset window
                self.breach_count = 1;
                self.first_breach = Some(now);
                false
            }
            Some(_) => {
                self.breach_count += 1;
                self.breach_count >= BAN_THRESHOLD
            }
            None => {
                self.breach_count = 1;
                self.first_breach = Some(now);
                false
            }
        }
    }
}

// ── Connection tracker ─────────────────────────────────────────────

/// Tracks inbound connections for rate limiting.
#[derive(Debug, Default)]
pub struct ConnectionTracker {
    /// Count per IP address.
    per_ip: HashMap<IpAddr, usize>,
    /// Count per /24 subnet (IPv4) or /48 subnet (IPv6).
    per_subnet: HashMap<String, usize>,
    /// Total inbound count.
    total: usize,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a new inbound connection from `addr` would be allowed.
    pub fn would_allow(&self, addr: IpAddr) -> bool {
        if self.total >= MAX_INBOUND_CONNECTIONS {
            return false;
        }
        let ip_count = self.per_ip.get(&addr).copied().unwrap_or(0);
        if ip_count >= MAX_CONNECTIONS_PER_IP {
            return false;
        }
        let subnet = subnet_key(addr);
        let subnet_count = self.per_subnet.get(&subnet).copied().unwrap_or(0);
        if subnet_count >= MAX_CONNECTIONS_PER_SUBNET {
            return false;
        }
        true
    }

    /// Record a new inbound connection.
    pub fn add(&mut self, addr: IpAddr) {
        *self.per_ip.entry(addr).or_insert(0) += 1;
        *self.per_subnet.entry(subnet_key(addr)).or_insert(0) += 1;
        self.total += 1;
    }

    /// Remove a disconnected connection.
    pub fn remove(&mut self, addr: IpAddr) {
        if let Some(count) = self.per_ip.get_mut(&addr) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_ip.remove(&addr);
            }
        }
        let subnet = subnet_key(addr);
        if let Some(count) = self.per_subnet.get_mut(&subnet) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_subnet.remove(&subnet);
            }
        }
        self.total = self.total.saturating_sub(1);
    }

    pub fn total(&self) -> usize {
        self.total
    }
}

/// Compute subnet key: /24 for IPv4, /48 for IPv6.
fn subnet_key(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            format!("{:x}:{:x}:{:x}::/48", segments[0], segments[1], segments[2])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_counter_allows_within_limit() {
        let mut counter = RateCounter::new(Duration::from_secs(60), 3);
        assert!(counter.check_and_record());
        assert!(counter.check_and_record());
        assert!(counter.check_and_record());
        assert!(!counter.check_and_record()); // 4th exceeds limit
    }

    #[test]
    fn test_rate_counter_count() {
        let mut counter = RateCounter::new(Duration::from_secs(60), 10);
        counter.check_and_record();
        counter.check_and_record();
        assert_eq!(counter.count(), 2);
    }

    #[test]
    fn test_peer_rate_limiter_breach_tracking() {
        let mut limiter = PeerRateLimiter::new();
        assert!(!limiter.record_breach()); // 1st breach
        assert!(!limiter.record_breach()); // 2nd breach
        assert!(limiter.record_breach()); // 3rd breach -> ban
    }

    #[test]
    fn test_connection_tracker_ip_limit() {
        let mut tracker = ConnectionTracker::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for _ in 0..MAX_CONNECTIONS_PER_IP {
            assert!(tracker.would_allow(ip));
            tracker.add(ip);
        }
        assert!(!tracker.would_allow(ip));
    }

    #[test]
    fn test_connection_tracker_subnet_limit() {
        let mut tracker = ConnectionTracker::new();
        for i in 1..=MAX_CONNECTIONS_PER_SUBNET {
            let ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
            assert!(tracker.would_allow(ip));
            tracker.add(ip);
        }
        let ip: IpAddr = "10.0.0.254".parse().unwrap();
        assert!(!tracker.would_allow(ip));
    }

    #[test]
    fn test_connection_tracker_remove() {
        let mut tracker = ConnectionTracker::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        tracker.add(ip);
        tracker.add(ip);
        assert_eq!(tracker.total(), 2);
        tracker.remove(ip);
        assert_eq!(tracker.total(), 1);
        tracker.remove(ip);
        assert_eq!(tracker.total(), 0);
    }

    #[test]
    fn test_connection_tracker_global_limit() {
        let mut tracker = ConnectionTracker::new();
        // Fill up to global limit using different IPs
        for i in 0..MAX_INBOUND_CONNECTIONS {
            let ip: IpAddr = format!("100.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256)
                .parse()
                .unwrap();
            tracker.add(ip);
        }
        assert_eq!(tracker.total(), MAX_INBOUND_CONNECTIONS);
        let ip: IpAddr = "200.0.0.1".parse().unwrap();
        assert!(!tracker.would_allow(ip));
    }

    #[test]
    fn test_subnet_key_ipv4() {
        let ip: IpAddr = "192.168.1.42".parse().unwrap();
        assert_eq!(subnet_key(ip), "192.168.1.0/24");
    }

    #[test]
    fn test_subnet_key_ipv6() {
        let ip: IpAddr = "2001:db8:1234:5678::1".parse().unwrap();
        assert_eq!(subnet_key(ip), "2001:db8:1234::/48");
    }

    #[test]
    fn test_different_subnets_independent() {
        let mut tracker = ConnectionTracker::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.1.1".parse().unwrap(); // Different /24
        for _ in 0..MAX_CONNECTIONS_PER_SUBNET {
            tracker.add(ip1);
        }
        assert!(!tracker.would_allow(ip1));
        assert!(tracker.would_allow(ip2)); // Different subnet, still allowed
    }
}
