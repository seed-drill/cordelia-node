//! Connection manager: bridges governor decisions to QUIC connections.
//!
//! Holds active connections keyed by NodeId, executes governor actions
//! (connect/disconnect), manages per-peer handshake and keep-alive state.
//!
//! Spec: seed-drill/specs/network-protocol.md §2.3, §4.1, §4.2, §5

use crate::handshake::{self, HandshakeResult, HANDSHAKE_TIMEOUT_SECS};
use crate::keepalive::KeepAliveState;
use crate::transport::{extract_peer_node_id, TransportError};
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
}

impl ConnectionManager {
    pub fn new(
        identity: Arc<NodeIdentity>,
        endpoint: Endpoint,
        channel_ids: Vec<String>,
        roles: Vec<String>,
    ) -> Self {
        Self {
            identity,
            endpoint,
            connections: HashMap::new(),
            channel_ids,
            roles,
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

    /// Connect to a peer at the given address, perform handshake.
    pub async fn connect_to(
        &mut self,
        addr: SocketAddr,
    ) -> Result<NodeId, ConnectionError> {
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
            ),
        )
        .await
        .map_err(|_| ConnectionError::Handshake(handshake::HandshakeError::Timeout))?
        ?;

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

    /// Accept an incoming QUIC connection and perform handshake.
    pub async fn accept_connection(
        &mut self,
        conn: Connection,
    ) -> Result<NodeId, ConnectionError> {
        let peer_node_id = extract_node_id_from_conn(&conn)?;
        let node_id = NodeId(peer_node_id);

        if self.connections.contains_key(&node_id) {
            conn.close(0u32.into(), b"duplicate");
            return Err(ConnectionError::AlreadyConnected(node_id));
        }

        // Accept handshake on the first bidirectional stream
        let (mut send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| ConnectionError::Quinn(e.to_string()))?;

        let mut stream = tokio::io::join(&mut recv, &mut send);

        let handshake_result = tokio::time::timeout(
            Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            handshake::accept_handshake(
                &mut stream,
                &self.identity.public_key(),
                &self.channel_ids,
                &self.roles,
                &peer_node_id,
            ),
        )
        .await
        .map_err(|_| ConnectionError::Handshake(handshake::HandshakeError::Timeout))?
        ?;

        info!(peer = %node_id, version = handshake_result.negotiated_version, "handshake complete (inbound)");

        let peer_conn = PeerConnection {
            conn,
            node_id: peer_node_id,
            handshake: handshake_result,
            keepalive: KeepAliveState::new(),
        };

        self.connections.insert(node_id.clone(), peer_conn);
        Ok(node_id)
    }

    /// Wait for and accept the next incoming QUIC connection.
    ///
    /// Returns None if the endpoint is closed.
    pub async fn accept_incoming(&mut self) -> Result<NodeId, ConnectionError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| ConnectionError::Quinn("endpoint closed".into()))?;
        let conn = incoming
            .await
            .map_err(|e| ConnectionError::Quinn(e.to_string()))?;
        self.accept_connection(conn).await
    }

    /// Disconnect from a peer.
    pub fn disconnect(&mut self, node_id: &NodeId) {
        if let Some(peer) = self.connections.remove(node_id) {
            peer.conn.close(0u32.into(), b"governor disconnect");
            debug!(peer = %node_id, "disconnected");
        }
    }

    /// Close all connections and the endpoint.
    pub fn shutdown(&mut self) {
        for (id, peer) in self.connections.drain() {
            peer.conn.close(0u32.into(), b"shutdown");
            debug!(peer = %id, "shutdown disconnect");
        }
        self.endpoint.close(0u32.into(), b"shutdown");
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
        );

        let mut mgr_b = ConnectionManager::new(
            id_b.clone(),
            ep_b,
            vec!["ch2".into()],
            vec!["personal".into()],
        );

        // B accepts in background
        let accept_task = tokio::spawn(async move {
            let incoming = mgr_b.endpoint.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let node_id = mgr_b.accept_connection(conn).await.unwrap();
            (mgr_b, node_id)
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

        let (mgr_b, node_a_id) = accept_task.await.unwrap();
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

        let mut mgr_a = ConnectionManager::new(id_a.clone(), ep_a, vec![], vec![]);
        let mut mgr_b = ConnectionManager::new(id_b.clone(), ep_b, vec![], vec![]);

        let accept_task = tokio::spawn(async move {
            let incoming = mgr_b.endpoint.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            mgr_b.accept_connection(conn).await.unwrap();
            mgr_b
        });

        let node_b_id = mgr_a.connect_to(b_addr).await.unwrap();
        assert!(mgr_a.is_connected(&node_b_id));

        mgr_a.disconnect(&node_b_id);
        assert!(!mgr_a.is_connected(&node_b_id));
        assert_eq!(mgr_a.connection_count(), 0);

        let _mgr_b = accept_task.await.unwrap();
        mgr_a.shutdown();
    }

    #[tokio::test]
    async fn test_duplicate_connect_rejected() {
        let id_a = make_test_identity();
        let id_b = make_test_identity();

        let ep_a = make_endpoint(&id_a);
        let ep_b = make_endpoint(&id_b);
        let b_addr = ep_b.local_addr().unwrap();

        let mut mgr_a = ConnectionManager::new(id_a.clone(), ep_a, vec![], vec![]);
        let mut mgr_b = ConnectionManager::new(id_b.clone(), ep_b, vec![], vec![]);

        // B accepts two connections sequentially
        let accept_task = tokio::spawn(async move {
            // Accept first
            let incoming = mgr_b.endpoint.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            mgr_b.accept_connection(conn).await.unwrap();
            // Accept second (will arrive but mgr_a should reject before handshake)
            if let Some(incoming2) = mgr_b.endpoint.accept().await {
                let _ = incoming2.await; // Just accept the QUIC conn, don't care
            }
            mgr_b
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
}
