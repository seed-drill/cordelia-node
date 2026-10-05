//! Connection manager: bridges governor decisions to QUIC connections.
//!
//! Holds active connections keyed by NodeId, executes governor actions
//! (connect/disconnect), manages per-peer handshake and keep-alive state.
//!
//! Spec: seed-drill/specs/network-protocol.md §2.3, §4.1, §4.2, §5

use crate::handshake::{self, HANDSHAKE_TIMEOUT_SECS, HandshakeResult};
use crate::keepalive::KeepAliveState;
use crate::transport::{TransportError, extract_peer_node_id};
use cordelia_core::NodeId;
use cordelia_crypto::identity::NodeIdentity;
use quinn::{Connection, Endpoint};
use rustls::pki_types::CertificateDer;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info};

/// Why a connection is closed when the peer already has one with this
/// node: this one is the extra, or it takes the place of an earlier one.
const CLOSED_AS_DUPLICATE: &[u8] = b"duplicate";
const CLOSED_AS_REPLACED: &[u8] = b"replaced";

/// Whether the peer closed a connection because it keeps another one with
/// this node. Two nodes that list each other both dial at start, and one of
/// the two connections is dropped: nothing is wrong.
///
/// A close made during the handshake arrives without its reason, as QUIC
/// requires: it is known only as a close by the peer's application. A node
/// closes a connection it is still opening for this reason alone.
fn closed_for_another(e: &quinn::ConnectionError) -> bool {
    match e {
        quinn::ConnectionError::ApplicationClosed(close) => {
            close.reason.as_ref() == CLOSED_AS_DUPLICATE
                || close.reason.as_ref() == CLOSED_AS_REPLACED
        }
        quinn::ConnectionError::ConnectionClosed(close) => {
            close.error_code == quinn::TransportErrorCode::APPLICATION_ERROR
        }
        _ => false,
    }
}

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("handshake error: {0}")]
    Handshake(#[from] crate::handshake::HandshakeError),

    #[error("QUIC connection error: {0}")]
    Quinn(String),

    #[error("peer not connected: {0}")]
    NotConnected(NodeId),

    #[error("peer already connected: {0}")]
    AlreadyConnected(NodeId),
}

/// Metadata for an active peer connection.
pub struct PeerConnection {
    /// The underlying QUIC connection.
    pub conn: Connection,
    /// Peer's verified Ed25519 public key (from TLS cert).
    pub node_id: [u8; 32],
    /// Handshake result (version, channel digest, roles).
    pub handshake: HandshakeResult,
    /// Keep-alive state for this peer.
    pub keepalive: KeepAliveState,
    /// Who opened the connection.
    pub direction: Direction,
    /// The peer's address when the connection was made: where it was
    /// accepted from, or where it was dialled. A connection can move to
    /// another address while it lasts. Whatever is counted by address is
    /// counted under this one, read once, so that a peer does not come by
    /// another address's allowance by moving.
    pub addr: SocketAddr,
}

/// Data needed by spawned connect/accept tasks. All fields Clone.
#[derive(Clone)]
pub struct ConnectContext {
    pub endpoint: Endpoint,
    pub public_key: [u8; 32],
    pub channel_ids: Vec<String>,
    pub roles: Vec<String>,
    pub p2p_port: u16,
}

/// Result of a successful connect/accept. Returned via channel to the p2p select loop.
pub struct ConnectOutcome {
    pub conn: Connection,
    pub node_id: NodeId,
    pub handshake: HandshakeResult,
    pub addr: SocketAddr,
    pub direction: Direction,
}

/// Direction of a connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Manages active QUIC connections to peers.
pub struct ConnectionManager {
    /// Our node identity.
    identity: Arc<NodeIdentity>,
    /// QUIC endpoint.
    endpoint: Endpoint,
    /// Active connections by NodeId.
    connections: HashMap<NodeId, PeerConnection>,
    /// Our subscribed channel IDs (for handshake digest).
    channel_ids: Vec<String>,
    /// Our advertised roles.
    roles: Vec<String>,
    /// Our P2P listening port (advertised in handshake).
    p2p_port: u16,
}

impl ConnectionManager {
    pub fn new(
        identity: Arc<NodeIdentity>,
        endpoint: Endpoint,
        channel_ids: Vec<String>,
        roles: Vec<String>,
        p2p_port: u16,
    ) -> Self {
        Self {
            identity,
            endpoint,
            connections: HashMap::new(),
            channel_ids,
            roles,
            p2p_port,
        }
    }

    /// Number of active connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Check if we have an active connection to a peer.
    pub fn is_connected(&self, node_id: &NodeId) -> bool {
        self.connections.contains_key(node_id)
    }

    /// Get peer connection metadata.
    pub fn get_peer(&self, node_id: &NodeId) -> Option<&PeerConnection> {
        self.connections.get(node_id)
    }

    /// Get mutable peer connection metadata.
    pub fn get_peer_mut(&mut self, node_id: &NodeId) -> Option<&mut PeerConnection> {
        self.connections.get_mut(node_id)
    }

    /// Get the QUIC connection for a peer.
    pub fn get_connection(&self, node_id: &NodeId) -> Option<&Connection> {
        self.connections.get(node_id).map(|pc| &pc.conn)
    }

    /// List all connected peer NodeIds.
    pub fn connected_peers(&self) -> Vec<NodeId> {
        self.connections.keys().cloned().collect()
    }

    /// Update channel subscriptions (recalculates digest for future handshakes).
    pub fn update_channels(&mut self, channel_ids: Vec<String>) {
        self.channel_ids = channel_ids;
    }

    /// Clone the context needed for spawned connect/accept tasks.
    pub fn connect_context(&self) -> ConnectContext {
        ConnectContext {
            endpoint: self.endpoint.clone(),
            public_key: self.identity.public_key(),
            channel_ids: self.channel_ids.clone(),
            roles: self.roles.clone(),
            p2p_port: self.p2p_port,
        }
    }

    /// Clone the endpoint for use in the select loop's accept arm.
    pub fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }

    /// Register a pre-handshaked connection.
    ///
    /// One connection is kept per peer. If the peer already has one:
    /// - a closed one is replaced;
    /// - if the peer dialled again, its old connection is gone on its side,
    ///   so the new one replaces it;
    /// - if both sides dialled at once, the connection opened by the lower
    ///   key is kept, so both ends keep the same one;
    /// - otherwise the existing connection stays and the new one is closed
    ///   (`AlreadyConnected`).
    pub fn register(&mut self, outcome: ConnectOutcome) -> Result<NodeId, ConnectionError> {
        if let Some(existing) = self.connections.get(&outcome.node_id) {
            let keep_existing = existing.conn.close_reason().is_none()
                && match (existing.direction, outcome.direction) {
                    (Direction::Inbound, Direction::Inbound) => false,
                    (Direction::Outbound, Direction::Outbound) => true,
                    (existing_direction, _) => {
                        let we_are_lower = self.identity.public_key() < outcome.node_id.0;
                        (existing_direction == Direction::Outbound) == we_are_lower
                    }
                };
            if keep_existing {
                outcome.conn.close(0u32.into(), CLOSED_AS_DUPLICATE);
                return Err(ConnectionError::AlreadyConnected(outcome.node_id));
            }
            if let Some(old) = self.connections.remove(&outcome.node_id) {
                old.conn.close(0u32.into(), CLOSED_AS_REPLACED);
                debug!(peer = %outcome.node_id, "replaced the peer's earlier connection");
            }
        }

        let node_id = outcome.node_id.clone();
        let peer_conn = PeerConnection {
            conn: outcome.conn,
            node_id: outcome.node_id.0,
            handshake: outcome.handshake,
            keepalive: KeepAliveState::new(),
            direction: outcome.direction,
            addr: outcome.addr,
        };

        self.connections.insert(node_id.clone(), peer_conn);
        Ok(node_id)
    }

    /// Connect to a peer at the given address, perform handshake.
    pub async fn connect_to(&mut self, addr: SocketAddr) -> Result<NodeId, ConnectionError> {
        // Establish QUIC connection
        let conn = self
            .endpoint
            .connect(addr, "cordelia")
            .map_err(|e| ConnectionError::Quinn(e.to_string()))?
            .await
            .map_err(|e| ConnectionError::Quinn(e.to_string()))?;

        // Extract peer's node_id from TLS certificate
        let peer_node_id = extract_node_id_from_conn(&conn)?;
        let node_id = NodeId(peer_node_id);

        if self.connections.contains_key(&node_id) {
            conn.close(0u32.into(), CLOSED_AS_DUPLICATE);
            return Err(ConnectionError::AlreadyConnected(node_id));
        }

        // Perform handshake on a bidirectional stream
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| ConnectionError::Quinn(e.to_string()))?;

        let mut stream = tokio::io::join(&mut recv, &mut send);

        let handshake_result = tokio::time::timeout(
            Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            handshake::initiate_handshake(
                &mut stream,
                &self.identity.public_key(),
                &self.channel_ids,
                &self.roles,
                &peer_node_id,
                self.p2p_port,
            ),
        )
        .await
        .map_err(|_| ConnectionError::Handshake(handshake::HandshakeError::Timeout))??;

        info!(peer = %node_id, version = handshake_result.negotiated_version, "handshake complete (outbound)");

        let peer_conn = PeerConnection {
            conn,
            node_id: peer_node_id,
            handshake: handshake_result,
            keepalive: KeepAliveState::new(),
            direction: Direction::Outbound,
            addr,
        };

        self.connections.insert(node_id.clone(), peer_conn);
        Ok(node_id)
    }

    /// Drop every connection that has closed (by the peer, by an idle
    /// timeout, or by an error) and return those peers. Without this a dead
    /// connection would still count as connected: the peer would never be
    /// redialled, and its own reconnection would be refused as a duplicate.
    pub fn reap_closed(&mut self) -> Vec<NodeId> {
        let closed: Vec<NodeId> = self
            .connections
            .iter()
            .filter(|(_, peer)| peer.conn.close_reason().is_some())
            .map(|(id, _)| id.clone())
            .collect();
        for id in &closed {
            self.connections.remove(id);
        }
        closed
    }

    /// The address that the connection of `node_id` was made from, or
    /// to: what the peer is counted under for as long as the connection
    /// lasts, wherever it has moved to since.
    pub fn address_of(&self, node_id: &NodeId) -> Option<std::net::IpAddr> {
        self.connections.get(node_id).map(|peer| peer.addr.ip())
    }

    /// The addresses that the live inbound connections were made from,
    /// leaving out `except` (a peer that is reconnecting replaces its own
    /// connection).
    pub fn inbound_ips(&self, except: &NodeId) -> Vec<std::net::IpAddr> {
        self.connections
            .iter()
            .filter(|(id, peer)| {
                *id != except
                    && peer.direction == Direction::Inbound
                    && peer.conn.close_reason().is_none()
            })
            .map(|(_, peer)| peer.addr.ip())
            .collect()
    }

    /// Disconnect from a peer.
    pub fn disconnect(&mut self, node_id: &NodeId) {
        if let Some(peer) = self.connections.remove(node_id) {
            peer.conn.close(0u32.into(), b"governor disconnect");
            debug!(peer = %node_id, "disconnected");
        }
    }

    /// Build a list of known peer addresses for peer-sharing responses.
    /// Uses the peer's remote IP (from QUIC connection) and advertised P2P port.
    pub fn known_peer_addresses(&self) -> Vec<crate::messages::PeerAddress> {
        self.connections
            .iter()
            .filter_map(|(node_id, peer_conn)| {
                let remote = peer_conn.conn.remote_address();
                let listen_port = peer_conn.handshake.peer_p2p_port;
                if listen_port == 0 {
                    return None; // Peer didn't advertise a port
                }
                // Only share relay and bootnode addresses (§8.1: personal nodes
                // are outbound-only, sharing their addresses causes unwanted
                // inbound connections from other personal nodes).
                let roles = &peer_conn.handshake.peer_roles;
                if !roles.iter().any(|r| r == "relay" || r == "bootnode") {
                    return None;
                }
                let listen_addr = std::net::SocketAddr::new(remote.ip(), listen_port);
                Some(crate::messages::PeerAddress {
                    node_id: node_id.0.to_vec(),
                    addrs: vec![listen_addr.to_string()],
                    last_seen: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    exclude: false,
                })
            })
            .collect()
    }

    /// Close all connections and the endpoint.
    pub fn shutdown(&mut self) {
        for (id, peer) in self.connections.drain() {
            peer.conn.close(0u32.into(), b"shutdown");
            debug!(peer = %id, "shutdown disconnect");
        }
        self.endpoint.close(0u32.into(), b"shutdown");
    }

    /// Shutdown and wait for the endpoint to become idle (all connections closed).
    /// This ensures the UDP socket is released before the process exits.
    pub async fn shutdown_and_wait(&mut self) {
        self.shutdown();
        self.endpoint.wait_idle().await;
        tracing::info!("endpoint idle, socket released");
    }

    /// Get the local endpoint address.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }
}

fn extract_node_id_from_conn(conn: &Connection) -> Result<[u8; 32], ConnectionError> {
    let certs = conn
        .peer_identity()
        .ok_or_else(|| TransportError::IdentityBinding("no peer identity".into()))?
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| TransportError::IdentityBinding("unexpected identity type".into()))?;
    extract_peer_node_id(&certs).map_err(ConnectionError::Transport)
}

/// Perform outbound connect: QUIC + handshake. No state mutation.
/// Safe to call from a spawned task.
///
/// Gives up after STREAM_TIMEOUT_SECS if nothing answers. Left to QUIC, an
/// address that never answers would hold the attempt for a minute.
pub async fn outbound_connect(
    ctx: &ConnectContext,
    addr: SocketAddr,
) -> Result<ConnectOutcome, ConnectionError> {
    let connecting = ctx
        .endpoint
        .connect(addr, "cordelia")
        .map_err(|e| ConnectionError::Quinn(e.to_string()))?;
    let conn = tokio::time::timeout(
        Duration::from_secs(cordelia_core::protocol::STREAM_TIMEOUT_SECS),
        connecting,
    )
    .await
    .map_err(|_| ConnectionError::Quinn("timed out".into()))?
    .map_err(|e| ConnectionError::Quinn(e.to_string()))?;

    let peer_node_id = extract_node_id_from_conn(&conn)?;
    let node_id = NodeId(peer_node_id);

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| ConnectionError::Quinn(e.to_string()))?;

    let mut stream = tokio::io::join(&mut recv, &mut send);

    let handshake_result = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        handshake::initiate_handshake(
            &mut stream,
            &ctx.public_key,
            &ctx.channel_ids,
            &ctx.roles,
            &peer_node_id,
            ctx.p2p_port,
        ),
    )
    .await
    .map_err(|_| ConnectionError::Handshake(handshake::HandshakeError::Timeout))??;

    info!(
        peer = %node_id,
        version = handshake_result.negotiated_version,
        "handshake complete (outbound)"
    );

    Ok(ConnectOutcome {
        conn,
        node_id,
        handshake: handshake_result,
        addr,
        direction: Direction::Outbound,
    })
}

/// Perform inbound accept: QUIC accept + app handshake on an incoming connection.
/// Safe to call from a spawned task.
pub async fn inbound_accept(
    ctx: &ConnectContext,
    incoming: quinn::Incoming,
) -> Result<ConnectOutcome, ConnectionError> {
    let remote = incoming.remote_address();

    // QUIC handshake with 10s timeout
    let conn = tokio::time::timeout(Duration::from_secs(10), incoming)
        .await
        .map_err(|_| {
            tracing::warn!(remote = %remote, "QUIC incoming handshake timed out (10s)");
            ConnectionError::Quinn("incoming handshake timeout".into())
        })?
        .map_err(|e| {
            if closed_for_another(&e) {
                debug!(remote = %remote, "incoming connection dropped by the peer, which keeps another one with this node");
            } else {
                tracing::warn!(remote = %remote, error = %e, "QUIC incoming handshake failed");
            }
            ConnectionError::Quinn(e.to_string())
        })?;

    let peer_node_id = extract_node_id_from_conn(&conn)?;
    let node_id = NodeId(peer_node_id);

    debug!(
        peer = %node_id,
        remote = %remote,
        "QUIC connection established, starting app handshake"
    );

    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| ConnectionError::Quinn(e.to_string()))?;

    let mut stream = tokio::io::join(&mut recv, &mut send);

    let handshake_result = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        handshake::accept_handshake(
            &mut stream,
            &ctx.public_key,
            &ctx.channel_ids,
            &ctx.roles,
            &peer_node_id,
            ctx.p2p_port,
        ),
    )
    .await
    .map_err(|_| ConnectionError::Handshake(handshake::HandshakeError::Timeout))??;

    info!(
        peer = %node_id,
        version = handshake_result.negotiated_version,
        "handshake complete (inbound)"
    );

    Ok(ConnectOutcome {
        conn,
        node_id,
        handshake: handshake_result,
        addr: remote,
        direction: Direction::Inbound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport;

    fn make_test_identity() -> Arc<NodeIdentity> {
        Arc::new(NodeIdentity::generate().unwrap())
    }

    fn make_endpoint(id: &NodeIdentity) -> Endpoint {
        transport::create_endpoint(id, "127.0.0.1:0".parse().unwrap()).unwrap()
    }

    /// A connection that the peer drops because it keeps another one with
    /// this node is not a failure to warn about: two nodes that list each
    /// other both dial at start. Any other close, and any other failure,
    /// still is.
    #[test]
    fn a_connection_dropped_for_another_is_told_from_a_failure() {
        let closed = |reason: &'static [u8]| {
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: 0u32.into(),
                reason: reason.into(),
            })
        };
        assert!(closed_for_another(&closed(CLOSED_AS_DUPLICATE)));
        assert!(closed_for_another(&closed(CLOSED_AS_REPLACED)));
        assert!(!closed_for_another(&closed(b"shutdown")));
        assert!(!closed_for_another(&closed(b"")));
        // During the handshake the reason does not travel: this is what
        // the node that keeps the other connection is told.
        let in_handshake = |error_code| {
            quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
                error_code,
                frame_type: None,
                reason: (&b""[..]).into(),
            })
        };
        assert!(closed_for_another(&in_handshake(
            quinn::TransportErrorCode::APPLICATION_ERROR
        )));
        assert!(!closed_for_another(&in_handshake(
            quinn::TransportErrorCode::PROTOCOL_VIOLATION
        )));
        assert!(!closed_for_another(&quinn::ConnectionError::TimedOut));
        assert!(!closed_for_another(&quinn::ConnectionError::Reset));
    }

    #[tokio::test]
    async fn test_connect_and_handshake() {
        let id_a = make_test_identity();
        let id_b = make_test_identity();

        let ep_a = make_endpoint(&id_a);
        let ep_b = make_endpoint(&id_b);
        let b_addr = ep_b.local_addr().unwrap();

        let mut mgr_a = ConnectionManager::new(
            id_a.clone(),
            ep_a,
            vec!["ch1".into()],
            vec!["personal".into()],
            9474,
        );

        let mut mgr_b = ConnectionManager::new(
            id_b.clone(),
            ep_b,
            vec!["ch2".into()],
            vec!["personal".into()],
            9474,
        );
        let ep_b_clone = mgr_b.endpoint();
        let ctx_b = mgr_b.connect_context();

        // B accepts in background
        let accept_task = tokio::spawn(async move {
            let incoming = ep_b_clone.accept().await.unwrap();
            inbound_accept(&ctx_b, incoming).await.unwrap()
        });

        // A connects to B
        let node_b_id = mgr_a.connect_to(b_addr).await.unwrap();
        assert_eq!(node_b_id.0, id_b.public_key());
        assert_eq!(mgr_a.connection_count(), 1);
        assert!(mgr_a.is_connected(&node_b_id));

        // Check handshake result
        let peer = mgr_a.get_peer(&node_b_id).unwrap();
        assert_eq!(peer.handshake.negotiated_version, 1);
        assert_eq!(peer.handshake.peer_channel_count, 1);
        assert_eq!(peer.handshake.peer_roles, vec!["personal"]);

        let outcome = accept_task.await.unwrap();
        let node_a_id = mgr_b.register(outcome).unwrap();
        assert_eq!(node_a_id.0, id_a.public_key());
        assert_eq!(mgr_b.connection_count(), 1);

        // Clean up
        mgr_a.shutdown();
    }

    #[tokio::test]
    async fn test_disconnect() {
        let id_a = make_test_identity();
        let id_b = make_test_identity();

        let ep_a = make_endpoint(&id_a);
        let ep_b = make_endpoint(&id_b);
        let b_addr = ep_b.local_addr().unwrap();

        let mut mgr_a = ConnectionManager::new(id_a.clone(), ep_a, vec![], vec![], 9474);
        let mgr_b = ConnectionManager::new(id_b.clone(), ep_b, vec![], vec![], 9474);
        let ep_b_clone = mgr_b.endpoint();
        let ctx_b = mgr_b.connect_context();

        let accept_task = tokio::spawn(async move {
            let incoming = ep_b_clone.accept().await.unwrap();
            inbound_accept(&ctx_b, incoming).await.unwrap()
        });

        let node_b_id = mgr_a.connect_to(b_addr).await.unwrap();
        assert!(mgr_a.is_connected(&node_b_id));

        mgr_a.disconnect(&node_b_id);
        assert!(!mgr_a.is_connected(&node_b_id));
        assert_eq!(mgr_a.connection_count(), 0);

        let _outcome = accept_task.await.unwrap();
        mgr_a.shutdown();
    }

    #[tokio::test]
    async fn test_duplicate_connect_rejected() {
        let id_a = make_test_identity();
        let id_b = make_test_identity();

        let ep_a = make_endpoint(&id_a);
        let ep_b = make_endpoint(&id_b);
        let b_addr = ep_b.local_addr().unwrap();

        let mut mgr_a = ConnectionManager::new(id_a.clone(), ep_a, vec![], vec![], 9474);
        let mgr_b = ConnectionManager::new(id_b.clone(), ep_b, vec![], vec![], 9474);
        let ep_b_clone = mgr_b.endpoint();
        let ctx_b = mgr_b.connect_context();

        // B accepts two connections sequentially
        let accept_task = tokio::spawn(async move {
            // Accept first
            let incoming = ep_b_clone.accept().await.unwrap();
            let _outcome = inbound_accept(&ctx_b, incoming).await.unwrap();
            // Accept second (will arrive but mgr_a should reject before handshake)
            if let Some(incoming2) = ep_b_clone.accept().await {
                let _ = incoming2.await; // Just accept the QUIC conn, don't care
            }
        });

        // First connect succeeds
        mgr_a.connect_to(b_addr).await.unwrap();
        assert_eq!(mgr_a.connection_count(), 1);

        // Second connect to same peer should fail (AlreadyConnected check
        // happens after QUIC connects but before handshake)
        let result = mgr_a.connect_to(b_addr).await;
        assert!(matches!(result, Err(ConnectionError::AlreadyConnected(_))));
        assert_eq!(mgr_a.connection_count(), 1); // Still just one

        mgr_a.shutdown();
        let _ = accept_task.await;
    }

    #[tokio::test]
    async fn test_outbound_connect_and_register() {
        let id_a = make_test_identity();
        let id_b = make_test_identity();

        let ep_a = make_endpoint(&id_a);
        let ep_b = make_endpoint(&id_b);
        let b_addr = ep_b.local_addr().unwrap();

        let mut mgr_a = ConnectionManager::new(
            id_a.clone(),
            ep_a,
            vec!["ch1".into()],
            vec!["personal".into()],
            9474,
        );
        let ctx_a = mgr_a.connect_context();

        let mgr_b = ConnectionManager::new(
            id_b.clone(),
            ep_b,
            vec!["ch2".into()],
            vec!["personal".into()],
            9474,
        );
        let ep_b_clone = mgr_b.endpoint();
        let ctx_b = mgr_b.connect_context();

        let accept_task = tokio::spawn(async move {
            let incoming = ep_b_clone.accept().await.unwrap();
            inbound_accept(&ctx_b, incoming).await.unwrap()
        });

        let outcome = outbound_connect(&ctx_a, b_addr).await.unwrap();
        assert_eq!(outcome.node_id.0, id_b.public_key());
        assert_eq!(outcome.direction, Direction::Outbound);
        assert_eq!(outcome.addr, b_addr);

        let node_id = mgr_a.register(outcome).unwrap();
        assert_eq!(node_id.0, id_b.public_key());
        assert_eq!(mgr_a.connection_count(), 1);

        let _outcome_b = accept_task.await.unwrap();
        mgr_a.shutdown();
    }

    #[tokio::test]
    async fn test_inbound_accept_and_register() {
        let id_a = make_test_identity();
        let id_b = make_test_identity();

        let ep_a = make_endpoint(&id_a);
        let ep_b = make_endpoint(&id_b);
        let b_addr = ep_b.local_addr().unwrap();
        let ep_b_accept = ep_b.clone();

        let mut mgr_a = ConnectionManager::new(
            id_a.clone(),
            ep_a,
            vec!["ch1".into()],
            vec!["personal".into()],
            9474,
        );

        let mut mgr_b = ConnectionManager::new(
            id_b.clone(),
            ep_b,
            vec!["ch2".into()],
            vec!["personal".into()],
            9474,
        );
        let ctx_b = mgr_b.connect_context();

        let accept_task = tokio::spawn(async move {
            let incoming = ep_b_accept.accept().await.unwrap();
            let outcome = inbound_accept(&ctx_b, incoming).await.unwrap();
            assert_eq!(outcome.direction, Direction::Inbound);
            outcome
        });

        let _node_a = mgr_a.connect_to(b_addr).await.unwrap();

        let outcome = accept_task.await.unwrap();
        assert_eq!(outcome.node_id.0, id_a.public_key());

        let node_id = mgr_b.register(outcome).unwrap();
        assert_eq!(node_id.0, id_a.public_key());
        assert_eq!(mgr_b.connection_count(), 1);

        mgr_a.shutdown();
        mgr_b.shutdown();
    }

    /// A connection is counted under the address it was made from. A peer
    /// that moves to another address while its connection lasts is still
    /// counted under the first: the connection says the new address, and
    /// what the manager says of it does not change.
    #[tokio::test]
    async fn a_connection_that_moves_is_counted_under_the_address_it_was_made_from() {
        let id_a = make_test_identity();
        let id_b = make_test_identity();
        // The accepting end listens on every address of this machine.
        let ep_b = transport::create_endpoint(&id_b, "0.0.0.0:0".parse().unwrap()).unwrap();
        let port = ep_b.local_addr().unwrap().port();
        let ep_b_accept = ep_b.clone();
        let ep_a = make_endpoint(&id_a);
        let ep_a_moves = ep_a.clone();
        let mut mgr_a =
            ConnectionManager::new(id_a.clone(), ep_a, vec![], vec!["personal".into()], 9474);
        let mut mgr_b =
            ConnectionManager::new(id_b.clone(), ep_b, vec![], vec!["relay".into()], 9474);
        let ctx_b = mgr_b.connect_context();
        let accept_task = tokio::spawn(async move {
            let incoming = ep_b_accept.accept().await.unwrap();
            inbound_accept(&ctx_b, incoming).await.unwrap()
        });
        let b_id = mgr_a
            .connect_to(format!("127.0.0.1:{port}").parse().unwrap())
            .await
            .unwrap();
        let a_id = mgr_b.register(accept_task.await.unwrap()).unwrap();
        let first: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let second: std::net::IpAddr = "127.0.0.2".parse().unwrap();
        let at_b = mgr_b.get_connection(&a_id).unwrap().clone();
        assert_eq!(at_b.remote_address().ip(), first);
        assert_eq!(mgr_b.address_of(&a_id), Some(first));
        assert_eq!(mgr_b.inbound_ips(&NodeId([0; 32])), [first]);

        // The dialling end moves to another address of this machine, and
        // goes on using the connection: a stream each way.
        let moved = std::net::UdpSocket::bind("127.0.0.2:0").unwrap();
        ep_a_moves.rebind(moved).unwrap();
        let at_a = mgr_a.get_connection(&b_id).unwrap().clone();
        let serve = at_b.clone();
        tokio::spawn(async move {
            while let Ok((mut send, mut recv)) = serve.accept_bi().await {
                let mut byte = [0u8; 1];
                if recv.read_exact(&mut byte).await.is_ok() {
                    let _ = send.write_all(&byte).await;
                    let _ = send.finish();
                }
            }
        });
        let mut seen = first;
        for _ in 0..100 {
            let (mut send, mut recv) = at_a.open_bi().await.unwrap();
            send.write_all(&[7]).await.unwrap();
            send.finish().unwrap();
            let mut byte = [0u8; 1];
            recv.read_exact(&mut byte).await.unwrap();
            seen = at_b.remote_address().ip();
            if seen == second {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // The connection says where the peer is now.
        assert_eq!(seen, second, "the connection did not move");
        // What it is counted under is where it was made from.
        assert_eq!(mgr_b.address_of(&a_id), Some(first));
        assert_eq!(mgr_b.inbound_ips(&NodeId([0; 32])), [first]);
        assert_eq!(mgr_b.address_of(&NodeId([9; 32])), None);
        // The dialling end counts its peer under the address it dialled.
        assert_eq!(mgr_a.address_of(&b_id), Some(first));

        mgr_a.shutdown();
        mgr_b.shutdown();
    }
}
