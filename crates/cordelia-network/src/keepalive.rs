//! Keep-Alive mini-protocol (0x02, §4.2).
//!
//! Bidirectional ping/pong on a long-lived QUIC stream.
//! 30-second interval, 3 missed pings = dead peer (90s).
//!
//! Provides RTT measurement stored in governor's PeerInfo.
//!
//! Spec: seed-drill/specs/network-protocol.md §4.2

use crate::codec::write_frame;
use crate::messages::*;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::AsyncWrite;

/// Ping interval (§4.2).
pub const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Number of missed pings before peer is considered dead.
pub const DEAD_THRESHOLD: u64 = 3;

/// Dead timeout = PING_INTERVAL * DEAD_THRESHOLD.
pub const DEAD_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, Error)]
pub enum KeepAliveError {
    #[error("codec error: {0}")]
    Codec(#[from] crate::codec::CodecError),

    #[error("unexpected message type")]
    UnexpectedMessage,

    #[error("peer dead: {missed} missed pings")]
    PeerDead { missed: u64 },
}

/// State for tracking keep-alive on one connection.
#[derive(Debug)]
pub struct KeepAliveState {
    /// Next sequence number to send.
    next_seq: u64,
    /// Last sequence number we received a pong for.
    last_acked_seq: u64,
    /// Last measured RTT.
    last_rtt: Option<Duration>,
    /// When we last sent a ping.
    last_ping_sent: Option<Instant>,
    /// When we last received any message (ping or pong).
    last_activity: Instant,
    /// Highest ping seq received from the peer (for monotonicity check).
    last_peer_ping_seq: u64,
}

impl Default for KeepAliveState {
    fn default() -> Self {
        Self::new()
    }
}

impl KeepAliveState {
    pub fn new() -> Self {
        Self {
            next_seq: 1,
            last_acked_seq: 0,
            last_rtt: None,
            last_ping_sent: None,
            last_activity: Instant::now(),
            last_peer_ping_seq: 0,
        }
    }

    /// Current RTT estimate.
    pub fn rtt(&self) -> Option<Duration> {
        self.last_rtt
    }

    /// RTT in milliseconds (for governor scoring).
    pub fn rtt_ms(&self) -> Option<u64> {
        self.last_rtt.map(|d| d.as_millis() as u64)
    }

    /// Number of outstanding (unacked) pings.
    pub fn outstanding_pings(&self) -> u64 {
        self.next_seq.saturating_sub(self.last_acked_seq + 1)
    }

    /// Whether the peer should be considered dead.
    pub fn is_dead(&self) -> bool {
        self.last_activity.elapsed() >= DEAD_TIMEOUT
    }

    /// Time since last activity.
    pub fn idle_duration(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Should we send a ping now?
    pub fn should_ping(&self) -> bool {
        match self.last_ping_sent {
            None => true,
            Some(t) => t.elapsed() >= PING_INTERVAL,
        }
    }
}

/// Get current time as nanoseconds since UNIX epoch.
fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// Send a ping message.
pub async fn send_ping<W: AsyncWrite + Unpin>(
    writer: &mut W,
    state: &mut KeepAliveState,
) -> Result<(), KeepAliveError> {
    let ping = WireMessage::Ping(Ping {
        seq: state.next_seq,
        sent_at_ns: now_ns(),
    });
    write_frame(writer, &ping).await?;
    state.last_ping_sent = Some(Instant::now());
    state.next_seq += 1;
    Ok(())
}

/// Send a pong response to a received ping.
pub async fn send_pong<W: AsyncWrite + Unpin>(
    writer: &mut W,
    ping: &Ping,
) -> Result<(), KeepAliveError> {
    let pong = WireMessage::Pong(Pong {
        seq: ping.seq,
        sent_at_ns: ping.sent_at_ns,
        recv_at_ns: now_ns(),
    });
    write_frame(writer, &pong).await?;
    Ok(())
}

/// Process a received pong, updating state with RTT.
///
/// Out-of-order or duplicate seq values are ignored per spec §4.2
/// (no ban -- clock issues are common).
pub fn handle_pong(state: &mut KeepAliveState, pong: &Pong) -> bool {
    if pong.seq <= state.last_acked_seq {
        tracing::debug!(
            seq = pong.seq,
            last = state.last_acked_seq,
            "ignoring out-of-order pong"
        );
        return false;
    }

    let now = now_ns();
    if pong.sent_at_ns < now {
        let rtt_ns = now - pong.sent_at_ns;
        state.last_rtt = Some(Duration::from_nanos(rtt_ns));
    }
    state.last_acked_seq = pong.seq;
    state.last_activity = Instant::now();
    true
}

/// Process a received ping, updating activity timestamp.
///
/// Validates seq is strictly increasing per spec §4.2.
/// Out-of-order or duplicate seq values are logged and ignored.
/// Returns true if the ping was accepted (seq is monotonic).
pub fn handle_ping(state: &mut KeepAliveState, ping: &Ping) -> bool {
    if ping.seq <= state.last_peer_ping_seq {
        tracing::debug!(
            seq = ping.seq,
            last = state.last_peer_ping_seq,
            "ignoring out-of-order ping"
        );
        return false;
    }
    state.last_peer_ping_seq = ping.seq;
    state.last_activity = Instant::now();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::read_frame;

    #[test]
    fn test_keepalive_state_new() {
        let state = KeepAliveState::new();
        assert_eq!(state.next_seq, 1);
        assert_eq!(state.last_acked_seq, 0);
        assert!(state.rtt().is_none());
        assert!(!state.is_dead());
        assert!(state.should_ping());
    }

    #[test]
    fn test_outstanding_pings() {
        let mut state = KeepAliveState::new();
        assert_eq!(state.outstanding_pings(), 0);
        state.next_seq = 4; // Sent 3 pings
        state.last_acked_seq = 1; // Got 1 ack
        assert_eq!(state.outstanding_pings(), 2);
    }

    #[test]
    fn test_handle_pong_updates_rtt() {
        let mut state = KeepAliveState::new();
        let sent = now_ns() - 5_000_000; // 5ms ago
        let pong = Pong {
            seq: 1,
            sent_at_ns: sent,
            recv_at_ns: sent + 2_000_000, // peer saw it 2ms later
        };
        assert!(handle_pong(&mut state, &pong));
        assert!(state.rtt().is_some());
        // RTT should be approximately 5ms but CI can be slow -- just verify non-zero
        assert!(state.rtt_ms().unwrap() >= 1);
        assert_eq!(state.last_acked_seq, 1);
    }

    #[test]
    fn test_handle_ping_updates_activity() {
        let mut state = KeepAliveState::new();
        // Artificially age the state
        state.last_activity = Instant::now() - Duration::from_secs(60);
        assert!(state.idle_duration() >= Duration::from_secs(59));

        assert!(handle_ping(
            &mut state,
            &Ping {
                seq: 1,
                sent_at_ns: 100
            }
        ));
        assert!(state.idle_duration() < Duration::from_secs(1));
    }

    // BV-08: Seq monotonicity -- out-of-order ping ignored
    #[test]
    fn test_ping_seq_out_of_order_ignored() {
        let mut state = KeepAliveState::new();
        assert!(handle_ping(
            &mut state,
            &Ping {
                seq: 5,
                sent_at_ns: 100
            }
        ));
        assert_eq!(state.last_peer_ping_seq, 5);

        // seq 3 is out of order (< 5), should be ignored
        assert!(!handle_ping(
            &mut state,
            &Ping {
                seq: 3,
                sent_at_ns: 200
            }
        ));
        assert_eq!(state.last_peer_ping_seq, 5); // unchanged

        // seq 5 is duplicate, should be ignored
        assert!(!handle_ping(
            &mut state,
            &Ping {
                seq: 5,
                sent_at_ns: 300
            }
        ));

        // seq 6 is valid
        assert!(handle_ping(
            &mut state,
            &Ping {
                seq: 6,
                sent_at_ns: 400
            }
        ));
        assert_eq!(state.last_peer_ping_seq, 6);
    }

    // BV-08: Seq monotonicity -- out-of-order pong ignored
    #[test]
    fn test_pong_seq_out_of_order_ignored() {
        let mut state = KeepAliveState::new();
        let pong1 = Pong {
            seq: 3,
            sent_at_ns: now_ns() - 1_000_000,
            recv_at_ns: 0,
        };
        assert!(handle_pong(&mut state, &pong1));
        assert_eq!(state.last_acked_seq, 3);

        // Duplicate seq 3 ignored
        let pong_dup = Pong {
            seq: 3,
            sent_at_ns: now_ns() - 500_000,
            recv_at_ns: 0,
        };
        assert!(!handle_pong(&mut state, &pong_dup));

        // Old seq 1 ignored
        let pong_old = Pong {
            seq: 1,
            sent_at_ns: now_ns() - 2_000_000,
            recv_at_ns: 0,
        };
        assert!(!handle_pong(&mut state, &pong_old));
        assert_eq!(state.last_acked_seq, 3); // unchanged
    }

    #[tokio::test]
    async fn test_ping_pong_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(8192);

        let mut state = KeepAliveState::new();

        // Send ping
        send_ping(&mut client, &mut state).await.unwrap();
        assert_eq!(state.next_seq, 2);

        // Read ping on server side
        let msg = read_frame(&mut server).await.unwrap();
        let ping = match msg {
            WireMessage::Ping(p) => p,
            other => panic!("expected Ping, got {:?}", other),
        };
        assert_eq!(ping.seq, 1);

        // Send pong
        send_pong(&mut server, &ping).await.unwrap();

        // Read pong on client side
        let msg = read_frame(&mut client).await.unwrap();
        let pong = match msg {
            WireMessage::Pong(p) => p,
            other => panic!("expected Pong, got {:?}", other),
        };
        assert_eq!(pong.seq, 1);

        // Process pong
        assert!(handle_pong(&mut state, &pong));
        assert!(state.rtt().is_some());
        assert_eq!(state.last_acked_seq, 1);
    }

    #[test]
    fn test_should_ping_after_interval() {
        let mut state = KeepAliveState::new();
        state.last_ping_sent = Some(Instant::now());
        assert!(!state.should_ping());

        state.last_ping_sent = Some(Instant::now() - PING_INTERVAL - Duration::from_millis(1));
        assert!(state.should_ping());
    }
}
