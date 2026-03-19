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

    /// Register a pre-handshaked connection. Returns error if duplicate.
    pub fn register(&mut self, outcome: ConnectOutcome) -> Result<NodeId, ConnectionError> {
        if self.connections.contains_key(&outcome.node_id) {
            outcome.conn.close(0u32.into(), b"duplicate");
            return Err(ConnectionError::AlreadyConnected(outcome.node_id));
        }

        let node_id = outcome.node_id.clone();
        let peer_conn = PeerConnection {
            conn: outcome.conn,
            node_id: outcome.node_id.0,
            handshake: outcome.handshake,
            keepalive: KeepAliveState::new(),
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
            conn.close(0u32.into(), b"duplicate");
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
        };

        self.connections.insert(node_id.clone(), peer_conn);
        Ok(node_id)
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
pub async fn outbound_connect(
    ctx: &ConnectContext,
    addr: SocketAddr,
) -> Result<ConnectOutcome, ConnectionError> {
    let conn = ctx
        .endpoint
        .connect(addr, "cordelia")
        .map_err(|e| ConnectionError::Quinn(e.to_string()))?
        .await
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
            tracing::warn!(remote = %remote, error = %e, "QUIC incoming handshake failed");
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
}
