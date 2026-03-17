//! Peer-Sharing mini-protocol (0x03, §4.3).
//!
//! Request-response. Initiated periodically (every 5 minutes) to 2-3
//! random warm/hot peers. Returns peer addresses for cold peer discovery.
//!
//! Address validation filters out private, loopback, and link-local addresses.
//!
//! Spec: seed-drill/specs/network-protocol.md §4.3

use crate::codec::{read_frame, read_protocol_byte, write_frame};
use crate::messages::*;
use cordelia_core::protocol;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

/// Peer-sharing request interval (sourced from protocol.rs).
pub const PEER_SHARE_INTERVAL: Duration = Duration::from_secs(protocol::PEER_SHARE_INTERVAL_SECS);

/// Default max_peers per request (sourced from protocol.rs).
pub const DEFAULT_MAX_PEERS: u16 = protocol::DEFAULT_MAX_PEERS_SHARE;

#[derive(Debug, Error)]
pub enum PeerSharingError {
    #[error("codec error: {0}")]
    Codec(#[from] crate::codec::CodecError),

    #[error("unexpected message type")]
    UnexpectedMessage,
}

/// Send a peer-sharing request (client side).
pub async fn request_peers<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    max_peers: u16,
) -> Result<Vec<PeerAddress>, PeerSharingError> {
    let req = WireMessage::PeerShareRequest(PeerShareRequest { max_peers });
    let resp = crate::codec::send_request(stream, Protocol::PeerSharing, &req).await?;
    match resp {
        WireMessage::PeerShareResponse(r) => Ok(r.peers),
        _ => Err(PeerSharingError::UnexpectedMessage),
    }
}

/// Handle a peer-sharing request (server side).
///
/// `known_peers` should be pre-filtered by the caller (recent, diverse subnets,
/// not banned).
pub async fn handle_peer_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    known_peers: &[PeerAddress],
) -> Result<(), PeerSharingError> {
    let proto = read_protocol_byte(stream).await?;
    if proto != Protocol::PeerSharing {
        return Err(PeerSharingError::UnexpectedMessage);
    }

    let msg = read_frame(stream).await?;
    let max_peers = match msg {
        WireMessage::PeerShareRequest(r) => r.max_peers as usize,
        _ => return Err(PeerSharingError::UnexpectedMessage),
    };

    let peers: Vec<PeerAddress> = known_peers.iter().take(max_peers).cloned().collect();
    let resp = WireMessage::PeerShareResponse(PeerShareResponse { peers });
    write_frame(stream, &resp).await?;

    Ok(())
}

/// Validate a received peer address (§4.3 address validation).
///
/// Returns true if the address is valid for adding to the cold peer table.
pub fn is_valid_peer_address(addr: &str, own_addr: Option<&SocketAddr>) -> bool {
    let parsed: SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    // Reject port 0
    if parsed.port() == 0 {
        return false;
    }

    // Reject our own address
    if let Some(own) = own_addr
        && &parsed == own
    {
        return false;
    }

    match parsed.ip() {
        IpAddr::V4(ip) => is_valid_ipv4(ip),
        IpAddr::V6(ip) => is_valid_ipv6(ip),
    }
}

fn is_valid_ipv4(ip: Ipv4Addr) -> bool {
    // RFC 1918 private
    if ip.is_private() {
        return false;
    }
    // Loopback (127.0.0.0/8)
    if ip.is_loopback() {
        return false;
    }
    // Link-local (169.254.0.0/16)
    if ip.is_link_local() {
        return false;
    }
    // Unspecified (0.0.0.0)
    if ip.is_unspecified() {
        return false;
    }
    true
}

fn is_valid_ipv6(ip: Ipv6Addr) -> bool {
    // Loopback (::1)
    if ip.is_loopback() {
        return false;
    }
    // Unspecified (::)
    if ip.is_unspecified() {
        return false;
    }
    // Link-local check: fe80::/10
    let segments = ip.segments();
    if (segments[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    true
}

/// Filter a list of peer addresses, removing invalid ones.
pub fn filter_valid_addresses(
    peers: &[PeerAddress],
    own_addr: Option<&SocketAddr>,
) -> Vec<PeerAddress> {
    peers
        .iter()
        .filter_map(|p| {
            let valid_addrs: Vec<String> = p
                .addrs
                .iter()
                .filter(|a| is_valid_peer_address(a, own_addr))
                .cloned()
                .collect();
            if valid_addrs.is_empty() {
                None
            } else {
                Some(PeerAddress {
                    node_id: p.node_id.clone(),
                    addrs: valid_addrs,
                    last_seen: p.last_seen,
                    exclude: p.exclude,
                })
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_private_addresses() {
        assert!(!is_valid_peer_address("10.0.0.1:9474", None));
        assert!(!is_valid_peer_address("172.16.0.1:9474", None));
        assert!(!is_valid_peer_address("192.168.1.1:9474", None));
    }

    #[test]
    fn test_reject_loopback() {
        assert!(!is_valid_peer_address("127.0.0.1:9474", None));
        assert!(!is_valid_peer_address("[::1]:9474", None));
    }

    #[test]
    fn test_reject_link_local() {
        assert!(!is_valid_peer_address("169.254.1.1:9474", None));
        assert!(!is_valid_peer_address("[fe80::1]:9474", None));
    }

    #[test]
    fn test_reject_port_zero() {
        assert!(!is_valid_peer_address("1.2.3.4:0", None));
    }

    #[test]
    fn test_reject_own_address() {
        let own: SocketAddr = "1.2.3.4:9474".parse().unwrap();
        assert!(!is_valid_peer_address("1.2.3.4:9474", Some(&own)));
        assert!(is_valid_peer_address("1.2.3.5:9474", Some(&own)));
    }

    #[test]
    fn test_accept_valid_public() {
        assert!(is_valid_peer_address("8.8.8.8:9474", None));
        assert!(is_valid_peer_address("203.0.113.1:9474", None));
        assert!(is_valid_peer_address("[2001:db8::1]:9474", None));
    }

    #[test]
    fn test_reject_invalid_format() {
        assert!(!is_valid_peer_address("not-an-address", None));
        assert!(!is_valid_peer_address("", None));
    }

    #[test]
    fn test_filter_valid_addresses() {
        let peers = vec![
            PeerAddress {
                node_id: vec![0x01; 32],
                addrs: vec!["8.8.8.8:9474".into(), "10.0.0.1:9474".into()],
                last_seen: 100,
                exclude: false,
            },
            PeerAddress {
                node_id: vec![0x02; 32],
                addrs: vec!["127.0.0.1:9474".into()], // All invalid
                last_seen: 100,
                exclude: false,
            },
        ];
        let filtered = filter_valid_addresses(&peers, None);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].addrs, vec!["8.8.8.8:9474"]);
    }

    #[tokio::test]
    async fn test_peer_sharing_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(8192);

        let known = vec![PeerAddress {
            node_id: vec![0x99; 32],
            addrs: vec!["203.0.113.1:9474".into()],
            last_seen: 1710100000,
            exclude: false,
        }];

        let server_task = tokio::spawn(async move {
            handle_peer_request(&mut server, &known).await.unwrap();
        });

        let peers = request_peers(&mut client, 20).await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addrs, vec!["203.0.113.1:9474"]);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_peer_sharing_respects_limit() {
        let (mut client, mut server) = tokio::io::duplex(8192);

        let known: Vec<PeerAddress> = (0..10)
            .map(|i| PeerAddress {
                node_id: vec![i; 32],
                addrs: vec![format!("203.0.113.{}:9474", i + 1)],
                last_seen: 1710100000,
                exclude: false,
            })
            .collect();

        let server_task = tokio::spawn(async move {
            handle_peer_request(&mut server, &known).await.unwrap();
        });

        let peers = request_peers(&mut client, 3).await.unwrap();
        assert_eq!(peers.len(), 3);

        server_task.await.unwrap();
    }
}
