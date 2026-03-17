//! Integration tests for rate limiting (§9).
//!
//! Acceptance-level tests that exercise ConnectionTracker and PeerRateLimiter
//! in realistic multi-limit scenarios. Complements unit tests in rate_limit.rs.
//!
//! Spec: docs/specs/network-protocol.md §9, docs/specs/parameter-rationale.md §4-§6

use cordelia_network::rate_limit::{
    ConnectionTracker, PeerRateLimiter, MAX_CONNECTIONS_PER_IP, MAX_CONNECTIONS_PER_SUBNET,
    MAX_INBOUND_CONNECTIONS, PEER_SHARES_PER_PEER_PER_MINUTE, SYNCS_PER_PEER_PER_MINUTE,
    WRITES_PER_PEER_PER_MINUTE,
};
use std::net::IpAddr;

// ── ConnectionTracker acceptance tests ───────────────────────────────

/// T5-03 (HIGH): Multi-limit interaction. Verify per-IP, per-subnet, and global
/// limits are enforced independently and interact correctly.
#[test]
fn test_connection_tracker_multi_limit_interaction() {
    let mut tracker = ConnectionTracker::new();

    // Fill per-IP limit for 1.2.3.4
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    for _ in 0..MAX_CONNECTIONS_PER_IP {
        assert!(tracker.would_allow(ip));
        tracker.add(ip);
    }
    assert!(
        !tracker.would_allow(ip),
        "per-IP limit should block 6th connection from same IP"
    );

    // Different IP in same /24 should still work
    let ip2: IpAddr = "1.2.3.5".parse().unwrap();
    assert!(
        tracker.would_allow(ip2),
        "different IP in same /24 should be allowed"
    );

    // Fill remaining subnet capacity from different IPs in same /24
    // Already have MAX_CONNECTIONS_PER_IP from 1.2.3.4
    for i in (MAX_CONNECTIONS_PER_IP + 1)..=MAX_CONNECTIONS_PER_SUBNET {
        let next_ip: IpAddr = format!("1.2.3.{}", i).parse().unwrap();
        tracker.add(next_ip);
    }
    assert_eq!(tracker.total(), MAX_CONNECTIONS_PER_SUBNET);

    // New IP in same /24 should be blocked by subnet limit
    let ip_overflow: IpAddr = "1.2.3.200".parse().unwrap();
    assert!(
        !tracker.would_allow(ip_overflow),
        "per-subnet limit should block after {} connections in /24",
        MAX_CONNECTIONS_PER_SUBNET
    );

    // IP in different /24 should still work
    let ip_other_subnet: IpAddr = "1.2.4.1".parse().unwrap();
    assert!(
        tracker.would_allow(ip_other_subnet),
        "different /24 subnet should be allowed"
    );
}

/// T5-04 (HIGH): Connection lifecycle with add/remove cycles.
/// Verify limits re-open after connections are released.
#[test]
fn test_connection_tracker_add_remove_lifecycle() {
    let mut tracker = ConnectionTracker::new();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    // Fill per-IP limit
    for _ in 0..MAX_CONNECTIONS_PER_IP {
        tracker.add(ip);
    }
    assert!(!tracker.would_allow(ip));

    // Remove one -- should re-open
    tracker.remove(ip);
    assert!(
        tracker.would_allow(ip),
        "should allow after removing one connection"
    );
    assert_eq!(tracker.total(), MAX_CONNECTIONS_PER_IP - 1);

    // Add it back -- blocked again
    tracker.add(ip);
    assert!(!tracker.would_allow(ip));

    // Remove all
    for _ in 0..MAX_CONNECTIONS_PER_IP {
        tracker.remove(ip);
    }
    assert_eq!(tracker.total(), 0);
    assert!(tracker.would_allow(ip), "should allow when fully drained");
}

/// T5-05 (HIGH): Global limit blocks even when per-IP and per-subnet have room.
#[test]
fn test_connection_tracker_global_limit_precedence() {
    let mut tracker = ConnectionTracker::new();

    // Fill global limit using distinct /24 subnets (per-IP/subnet never hit)
    for i in 0..MAX_INBOUND_CONNECTIONS {
        let a = (i / 256) % 256;
        let b = i % 256;
        let ip: IpAddr = format!("10.{a}.{b}.1").parse().unwrap();
        tracker.add(ip);
    }
    assert_eq!(tracker.total(), MAX_INBOUND_CONNECTIONS);

    // New connection from any IP should fail (global limit)
    let new_ip: IpAddr = "192.168.0.1".parse().unwrap();
    assert!(
        !tracker.would_allow(new_ip),
        "global limit ({}) should block new connections",
        MAX_INBOUND_CONNECTIONS
    );

    // Remove one -- should re-open
    let remove_ip: IpAddr = "10.0.0.1".parse().unwrap();
    tracker.remove(remove_ip);
    assert!(
        tracker.would_allow(new_ip),
        "should allow after freeing one global slot"
    );
}

/// T5-06 (HIGH): IPv6 subnet limits use /48 prefix.
#[test]
fn test_connection_tracker_ipv6_subnet() {
    let mut tracker = ConnectionTracker::new();

    // Fill from different addresses in same /48
    for i in 1..=MAX_CONNECTIONS_PER_SUBNET {
        let ip: IpAddr = format!("2001:db8:1::{}:{}", i / 256, i % 256)
            .parse()
            .unwrap();
        tracker.add(ip);
    }

    // Same /48 should be blocked
    let overflow: IpAddr = "2001:db8:1::ffff".parse().unwrap();
    assert!(
        !tracker.would_allow(overflow),
        "IPv6 /48 subnet limit should block"
    );

    // Different /48 should work
    let other: IpAddr = "2001:db8:2::1".parse().unwrap();
    assert!(
        tracker.would_allow(other),
        "different /48 should be allowed"
    );
}

// ── PeerRateLimiter per-stream tests ─────────────────────────────────

/// T5-07 (HIGH): Per-protocol rate limits are independent.
/// Exhausting writes must not affect syncs or peer_shares.
#[test]
fn test_peer_rate_limiter_stream_independence() {
    let mut limiter = PeerRateLimiter::new();

    // Exhaust writes (10/min)
    for i in 0..WRITES_PER_PEER_PER_MINUTE {
        assert!(
            limiter.writes.check_and_record(),
            "write {i} should succeed"
        );
    }
    assert!(
        !limiter.writes.check_and_record(),
        "write {} should fail (limit {})",
        WRITES_PER_PEER_PER_MINUTE,
        WRITES_PER_PEER_PER_MINUTE
    );

    // Syncs should still work (independent counter)
    for i in 0..SYNCS_PER_PEER_PER_MINUTE {
        assert!(
            limiter.syncs.check_and_record(),
            "sync {i} should succeed despite exhausted writes"
        );
    }
    assert!(!limiter.syncs.check_and_record(), "sync limit should fire");

    // Peer shares should still work (independent counter)
    for i in 0..PEER_SHARES_PER_PEER_PER_MINUTE {
        assert!(
            limiter.peer_shares.check_and_record(),
            "peer_share {i} should succeed despite exhausted writes+syncs"
        );
    }
    assert!(
        !limiter.peer_shares.check_and_record(),
        "peer_share limit should fire"
    );
}

/// T5-08 (HIGH): Breach accumulation across different protocols triggers ban.
#[test]
fn test_peer_rate_limiter_cross_protocol_breach_ban() {
    let mut limiter = PeerRateLimiter::new();

    // Exhaust writes and record breach
    for _ in 0..WRITES_PER_PEER_PER_MINUTE {
        limiter.writes.check_and_record();
    }
    assert!(!limiter.writes.check_and_record()); // exceeded
    assert!(!limiter.record_breach(), "1st breach should not ban");

    // Exhaust syncs and record breach
    for _ in 0..SYNCS_PER_PEER_PER_MINUTE {
        limiter.syncs.check_and_record();
    }
    assert!(!limiter.syncs.check_and_record()); // exceeded
    assert!(!limiter.record_breach(), "2nd breach should not ban");

    // Exhaust peer_shares and record breach
    for _ in 0..PEER_SHARES_PER_PEER_PER_MINUTE {
        limiter.peer_shares.check_and_record();
    }
    assert!(!limiter.peer_shares.check_and_record()); // exceeded
    assert!(
        limiter.record_breach(),
        "3rd breach should trigger ban (BAN_THRESHOLD=3)"
    );
}

/// T5-09 (HIGH): would_exceed() is read-only -- does not consume a slot.
#[test]
fn test_peer_rate_limiter_would_exceed_readonly() {
    let mut limiter = PeerRateLimiter::new();

    // Fill to limit - 1
    for _ in 0..WRITES_PER_PEER_PER_MINUTE - 1 {
        limiter.writes.check_and_record();
    }
    assert!(
        !limiter.writes.would_exceed(),
        "should not exceed with 1 slot remaining"
    );

    // Calling would_exceed repeatedly should NOT consume the slot
    for _ in 0..10 {
        assert!(
            !limiter.writes.would_exceed(),
            "would_exceed should be idempotent"
        );
    }

    // The actual slot should still be available
    assert!(
        limiter.writes.check_and_record(),
        "slot should still exist after would_exceed calls"
    );

    // NOW it should be full
    assert!(limiter.writes.would_exceed());
    assert!(!limiter.writes.check_and_record());
}

/// T5-10: Multiple PeerRateLimiter instances are independent (per-peer isolation).
#[test]
fn test_peer_rate_limiter_per_peer_isolation() {
    let mut limiter_a = PeerRateLimiter::new();
    let mut limiter_b = PeerRateLimiter::new();

    // Exhaust writes for peer A
    for _ in 0..WRITES_PER_PEER_PER_MINUTE {
        limiter_a.writes.check_and_record();
    }
    assert!(!limiter_a.writes.check_and_record());

    // Peer B should be unaffected
    assert!(
        limiter_b.writes.check_and_record(),
        "peer B should be independent of peer A's exhausted writes"
    );
}
