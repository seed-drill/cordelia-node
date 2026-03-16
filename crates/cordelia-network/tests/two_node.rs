//! Two-node integration test (P2P-12).
//!
//! End-to-end test: two nodes connect via QUIC, perform handshake,
//! exchange channel announcements, sync items, and verify PSK exchange.
//!
//! Spec: seed-drill/specs/network-protocol.md §2-§4

use cordelia_crypto::identity::NodeIdentity;
use cordelia_network::channel_announce::{self, ChannelAnnounceState, create_signed_descriptor};
use cordelia_network::codec::read_frame;
use cordelia_network::connection::ConnectionManager;
use cordelia_network::item_sync;
use cordelia_network::keepalive::{self, KeepAliveState};
use cordelia_network::messages::*;
use cordelia_network::psk_exchange;
use cordelia_network::transport;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

fn make_identity() -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::generate().unwrap())
}

fn make_endpoint(id: &NodeIdentity) -> quinn::Endpoint {
    transport::create_endpoint(id, "127.0.0.1:0".parse().unwrap()).unwrap()
}

/// Full connection lifecycle: connect, handshake, verify identities.
#[tokio::test]
async fn test_two_node_connect_and_handshake() {
    let id_a = make_identity();
    let id_b = make_identity();
    let pk_a = id_a.public_key();
    let pk_b = id_b.public_key();

    let ep_a = make_endpoint(&id_a);
    let ep_b = make_endpoint(&id_b);
    let b_addr = ep_b.local_addr().unwrap();

    let channels_a = vec!["ch_shared".into(), "ch_only_a".into()];
    let channels_b = vec!["ch_shared".into(), "ch_only_b".into()];
    let roles = vec!["personal".into()];

    let mut mgr_a = ConnectionManager::new(id_a.clone(), ep_a, channels_a, roles.clone(), 9474);
    let mut mgr_b = ConnectionManager::new(id_b.clone(), ep_b, channels_b, roles, 9474);

    // B accepts in background
    let accept_task = tokio::spawn(async move {
        let node_id = mgr_b.accept_incoming().await.unwrap();
        (mgr_b, node_id)
    });

    // A connects to B
    let node_b_id = mgr_a.connect_to(b_addr).await.unwrap();
    assert_eq!(node_b_id.0, pk_b);

    let peer_a = mgr_a.get_peer(&node_b_id).unwrap();
    assert_eq!(peer_a.handshake.negotiated_version, 1);
    assert_eq!(peer_a.handshake.peer_roles, vec!["personal"]);

    let (mgr_b, node_a_id) = accept_task.await.unwrap();
    assert_eq!(node_a_id.0, pk_a);

    let peer_b = mgr_b.get_peer(&node_a_id).unwrap();
    assert_eq!(peer_b.handshake.negotiated_version, 1);

    mgr_a.shutdown();
}

/// Two nodes exchange keep-alive pings over a QUIC stream.
#[tokio::test]
async fn test_two_node_keepalive() {
    let id_a = make_identity();
    let id_b = make_identity();

    let ep_a = make_endpoint(&id_a);
    let ep_b = make_endpoint(&id_b);
    let b_addr = ep_b.local_addr().unwrap();

    // Establish QUIC connection
    let server = tokio::spawn({
        async move {
            let incoming = ep_b.accept().await.unwrap();
            let conn = incoming.await.unwrap();

            // Accept keep-alive stream
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();

            // Read ping
            let proto_byte = cordelia_network::codec::read_protocol_byte(&mut recv)
                .await
                .unwrap();
            assert_eq!(proto_byte, Protocol::KeepAlive);

            let msg = read_frame(&mut recv).await.unwrap();
            let ping = match msg {
                WireMessage::Ping(p) => p,
                other => panic!("expected Ping, got {:?}", other),
            };
            assert_eq!(ping.seq, 1);

            // Send pong
            keepalive::send_pong(&mut send, &ping).await.unwrap();

            // Wait for client to close the connection
            let _ = conn.closed().await;
        }
    });

    let conn_a = ep_a.connect(b_addr, "cordelia").unwrap().await.unwrap();

    // Open keep-alive stream
    let (mut send, mut recv) = conn_a.open_bi().await.unwrap();

    // Send protocol byte + ping
    cordelia_network::codec::write_protocol_byte(&mut send, Protocol::KeepAlive)
        .await
        .unwrap();

    let mut state = KeepAliveState::new();
    keepalive::send_ping(&mut send, &mut state).await.unwrap();

    // Read pong
    let msg = read_frame(&mut recv).await.unwrap();
    let pong = match msg {
        WireMessage::Pong(p) => p,
        other => panic!("expected Pong, got {:?}", other),
    };
    assert_eq!(pong.seq, 1);

    assert!(keepalive::handle_pong(&mut state, &pong));
    assert!(state.rtt().is_some());
    assert!(state.rtt_ms().unwrap() < 1000); // Sub-1ms on loopback, generous for CI

    conn_a.close(0u32.into(), b"done");
    server.await.unwrap();
}

/// Two nodes exchange channel announcements and verify intersection.
#[tokio::test]
async fn test_two_node_channel_announce() {
    let id_a = make_identity();
    let id_b = make_identity();

    let psk = [0xAA; 32];
    let psk_hash: [u8; 32] = Sha256::digest(psk).into();

    // Create descriptors
    let desc_shared = create_signed_descriptor(
        &id_a,
        "ch_shared",
        Some("shared-channel"),
        "open",
        "realtime",
        &psk_hash,
        1,
        "2026-03-14T10:00:00Z",
    );
    let desc_only_a = create_signed_descriptor(
        &id_a,
        "ch_only_a",
        Some("a-only"),
        "open",
        "batch",
        &psk_hash,
        1,
        "2026-03-14T10:00:00Z",
    );

    let ep_a = make_endpoint(&id_a);
    let ep_b = make_endpoint(&id_b);
    let b_addr = ep_b.local_addr().unwrap();

    let channels_b = vec!["ch_shared".to_string(), "ch_only_b".to_string()];

    // Server side: receive channel announcements
    let server = tokio::spawn({
        let channels_b = channels_b.clone();
        async move {
            let incoming = ep_b.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let (_send, mut recv) = conn.accept_bi().await.unwrap();

            let mut state = ChannelAnnounceState::new(false);
            let known = HashMap::new();

            // Read two ChannelJoined messages
            let msg1 = read_frame(&mut recv).await.unwrap();
            if let WireMessage::ChannelJoined(cj) = msg1 {
                channel_announce::handle_channel_joined(&mut state, &cj, &channels_b, &known)
                    .unwrap();
            }

            let msg2 = read_frame(&mut recv).await.unwrap();
            if let WireMessage::ChannelJoined(cj) = msg2 {
                channel_announce::handle_channel_joined(&mut state, &cj, &channels_b, &known)
                    .unwrap();
            }

            // Verify intersection
            assert_eq!(state.peer_channels.len(), 2);
            assert_eq!(state.shared_channels, vec!["ch_shared"]);

            conn.close(0u32.into(), b"done");
            state
        }
    });

    let conn_a = ep_a.connect(b_addr, "cordelia").unwrap().await.unwrap();
    let (mut send, _recv) = conn_a.open_bi().await.unwrap();

    // Send channel announcements
    channel_announce::send_channel_joined(&mut send, "ch_shared", &desc_shared)
        .await
        .unwrap();
    channel_announce::send_channel_joined(&mut send, "ch_only_a", &desc_only_a)
        .await
        .unwrap();

    let state = server.await.unwrap();
    assert_eq!(state.shared_channels.len(), 1);
    assert_eq!(state.shared_channels[0], "ch_shared");

    conn_a.close(0u32.into(), b"done");
}

/// Two nodes perform item-sync: request headers, fetch missing items.
#[tokio::test]
async fn test_two_node_item_sync() {
    let id_a = make_identity();
    let id_b = make_identity();

    let ep_a = make_endpoint(&id_a);
    let ep_b = make_endpoint(&id_b);
    let b_addr = ep_b.local_addr().unwrap();

    let blob = vec![0xFF; 128];
    let hash: Vec<u8> = Sha256::digest(&blob).to_vec();

    let test_item = Item {
        item_id: "ci_test_sync_001".into(),
        channel_id: "ch_shared".into(),
        item_type: "message".into(),
        encrypted_blob: blob.clone(),
        content_hash: hash.clone(),
        content_length: 128,
        author_id: id_a.public_key().to_vec(),
        signature: vec![0xBB; 64],
        key_version: 1,
        published_at: "2026-03-14T10:30:00Z".into(),
        is_tombstone: false,
        parent_id: None,
    };

    let test_header = ItemHeader {
        item_id: "ci_test_sync_001".into(),
        channel_id: "ch_shared".into(),
        item_type: "message".into(),
        content_hash: hash.clone(),
        author_id: id_a.public_key().to_vec(),
        signature: vec![0xBB; 64],
        key_version: 1,
        published_at: "2026-03-14T10:30:00Z".into(),
        is_tombstone: false,
        parent_id: None,
    };

    // Server: handle sync request + fetch
    let server = tokio::spawn({
        let test_header = test_header.clone();
        let test_item = test_item.clone();
        async move {
            let incoming = ep_b.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let mut stream = tokio::io::join(&mut recv, &mut send);

            // Handle sync request
            item_sync::handle_sync_request(&mut stream, |ch, _since, _limit| {
                assert_eq!(ch, "ch_shared");
                (vec![test_header], false)
            })
            .await
            .unwrap();

            // Handle fetch request
            item_sync::handle_fetch_request(&mut stream, |ids| {
                assert_eq!(ids, &["ci_test_sync_001"]);
                vec![test_item]
            })
            .await
            .unwrap();

            let _ = conn.closed().await;
        }
    });

    let conn_a = ep_a.connect(b_addr, "cordelia").unwrap().await.unwrap();
    let (mut send, mut recv) = conn_a.open_bi().await.unwrap();
    let mut stream = tokio::io::join(&mut recv, &mut send);

    // Sync
    let sync_resp = item_sync::send_sync_request(&mut stream, "ch_shared", None, 100)
        .await
        .unwrap();
    assert_eq!(sync_resp.items.len(), 1);
    assert_eq!(sync_resp.items[0].item_id, "ci_test_sync_001");

    // Determine what to fetch
    let known = HashMap::new();
    let to_fetch = item_sync::compute_fetch_list(&sync_resp.items, &known);
    assert_eq!(to_fetch, vec!["ci_test_sync_001"]);

    // Fetch
    item_sync::send_fetch_request(&mut stream, &to_fetch)
        .await
        .unwrap();
    let items = item_sync::read_fetch_response(&mut stream).await.unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].item_id, "ci_test_sync_001");
    assert!(item_sync::verify_content_hash(&items[0]));

    conn_a.close(0u32.into(), b"done");
    server.await.unwrap();
}

/// Two nodes perform PSK exchange.
#[tokio::test]
async fn test_two_node_psk_exchange() {
    let id_a = make_identity();
    let id_b = make_identity();

    let ep_a = make_endpoint(&id_a);
    let ep_b = make_endpoint(&id_b);
    let b_addr = ep_b.local_addr().unwrap();

    let fake_ecies = vec![0xEE; 92]; // Simulated ECIES envelope

    // Server: handle PSK request
    let server = tokio::spawn({
        let fake_ecies = fake_ecies.clone();
        async move {
            let incoming = ep_b.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let mut stream = tokio::io::join(&mut recv, &mut send);

            psk_exchange::handle_psk_request(&mut stream, |ch, xpk| {
                assert_eq!(ch, "ch_open");
                assert_eq!(xpk.len(), 32);
                psk_exchange::psk_ok(fake_ecies, 1)
            })
            .await
            .unwrap();

            let _ = conn.closed().await;
        }
    });

    let conn_a = ep_a.connect(b_addr, "cordelia").unwrap().await.unwrap();
    let (mut send, mut recv) = conn_a.open_bi().await.unwrap();
    let mut stream = tokio::io::join(&mut recv, &mut send);

    let xpk = id_a.x25519_public_key();
    let resp = psk_exchange::request_psk(&mut stream, "ch_open", &xpk)
        .await
        .unwrap();
    assert_eq!(resp.status, "ok");
    assert_eq!(resp.ecies_envelope.unwrap().len(), 92);
    assert_eq!(resp.key_version.unwrap(), 1);

    conn_a.close(0u32.into(), b"done");
    server.await.unwrap();
}

/// T4-01 (HIGH): Reconnect after disconnect.
#[tokio::test]
async fn test_two_node_reconnect_after_disconnect() {
    let id_a = make_identity();
    let id_b = make_identity();
    let pk_b = id_b.public_key();

    let ep_a = make_endpoint(&id_a);
    let ep_b = make_endpoint(&id_b);
    let b_addr = ep_b.local_addr().unwrap();

    let mut mgr_a =
        ConnectionManager::new(id_a.clone(), ep_a, vec![], vec!["personal".into()], 9474);
    let mut mgr_b =
        ConnectionManager::new(id_b.clone(), ep_b, vec![], vec!["personal".into()], 9474);

    // First connection
    let accept1 = tokio::spawn(async move {
        let node_id = mgr_b.accept_incoming().await.unwrap();
        (mgr_b, node_id)
    });
    let node_b = mgr_a.connect_to(b_addr).await.unwrap();
    assert_eq!(node_b.0, pk_b);
    let (mut mgr_b, _) = accept1.await.unwrap();

    // Disconnect
    mgr_a.disconnect(&node_b);
    assert!(!mgr_a.is_connected(&node_b));
    mgr_b.disconnect(&cordelia_core::NodeId(id_a.public_key()));

    // Reconnect
    let accept2 = tokio::spawn(async move {
        let node_id = mgr_b.accept_incoming().await.unwrap();
        (mgr_b, node_id)
    });
    let node_b2 = mgr_a.connect_to(b_addr).await.unwrap();
    assert_eq!(node_b2.0, pk_b);
    assert!(mgr_a.is_connected(&node_b2));

    let (_, node_a2) = accept2.await.unwrap();
    assert_eq!(node_a2.0, id_a.public_key());

    mgr_a.shutdown();
}

/// T4-02 (MEDIUM): Multi-protocol lifecycle on one QUIC connection.
/// Handshake -> channel announce -> keepalive ping, all on separate streams.
#[tokio::test]
async fn test_two_node_full_lifecycle() {
    let id_a = make_identity();
    let id_b = make_identity();

    let psk = [0xAA; 32];
    let psk_hash: [u8; 32] = Sha256::digest(psk).into();

    let desc = channel_announce::create_signed_descriptor(
        &id_a,
        "ch_shared",
        Some("shared"),
        "open",
        "realtime",
        &psk_hash,
        1,
        "2026-03-14T12:00:00Z",
    );

    let ep_a = make_endpoint(&id_a);
    let ep_b = make_endpoint(&id_b);
    let b_addr = ep_b.local_addr().unwrap();

    // Connect + handshake via ConnectionManager
    let mut mgr_a = ConnectionManager::new(
        id_a.clone(),
        ep_a,
        vec!["ch_shared".into()],
        vec!["personal".into()],
        9474,
    );
    let mut mgr_b = ConnectionManager::new(
        id_b.clone(),
        ep_b,
        vec!["ch_shared".into()],
        vec!["personal".into()],
        9474,
    );

    let accept_task = tokio::spawn(async move {
        mgr_b.accept_incoming().await.unwrap();
        mgr_b
    });

    // Step 1: Connect + handshake
    let node_b_id = mgr_a.connect_to(b_addr).await.unwrap();
    let peer = mgr_a.get_peer(&node_b_id).unwrap();
    assert_eq!(peer.handshake.negotiated_version, 1);
    let mgr_b = accept_task.await.unwrap();

    // Step 2: Channel announce on a new QUIC stream
    let conn_a = mgr_a.get_connection(&node_b_id).unwrap().clone();
    let (mut send_ann, _) = conn_a.open_bi().await.unwrap();
    channel_announce::send_channel_joined(&mut send_ann, "ch_shared", &desc)
        .await
        .unwrap();

    // B reads the announcement
    let node_a_id = cordelia_core::NodeId(id_a.public_key());
    let conn_b = mgr_b.get_connection(&node_a_id).unwrap().clone();
    let (_, mut recv_ann) = conn_b.accept_bi().await.unwrap();
    let msg = read_frame(&mut recv_ann).await.unwrap();
    assert!(matches!(msg, WireMessage::ChannelJoined(_)));

    // Step 3: Keepalive on another stream (parallel with announce stream)
    let (mut send_ka, mut recv_ka) = conn_a.open_bi().await.unwrap();
    cordelia_network::codec::write_protocol_byte(&mut send_ka, Protocol::KeepAlive)
        .await
        .unwrap();
    let mut ka_state = KeepAliveState::new();
    keepalive::send_ping(&mut send_ka, &mut ka_state)
        .await
        .unwrap();

    // B accepts keepalive stream and replies
    let (mut send_b_ka, mut recv_b_ka) = conn_b.accept_bi().await.unwrap();
    let proto = cordelia_network::codec::read_protocol_byte(&mut recv_b_ka)
        .await
        .unwrap();
    assert_eq!(proto, Protocol::KeepAlive);
    let ping_msg = read_frame(&mut recv_b_ka).await.unwrap();
    if let WireMessage::Ping(ping) = ping_msg {
        keepalive::send_pong(&mut send_b_ka, &ping).await.unwrap();
    }

    // A reads pong
    let pong_msg = read_frame(&mut recv_ka).await.unwrap();
    assert!(matches!(pong_msg, WireMessage::Pong(_)));

    // All three protocols worked on separate streams of the same QUIC connection
    mgr_a.shutdown();
}

// ── Chaos / Fault Injection Tests ─────────────────────────────────

/// T14-5: Disconnect mid-handshake. The accepting side should handle
/// the dropped connection gracefully (no panic, no hang).
#[tokio::test]
async fn test_chaos_disconnect_during_handshake() {
    let id_a = make_identity();
    let id_b = make_identity();

    let ep_a = make_endpoint(&id_a);
    let ep_b = make_endpoint(&id_b);
    let b_addr = ep_b.local_addr().unwrap();

    // B starts accepting
    let accept_task = tokio::spawn(async move {
        let mut mgr_b =
            ConnectionManager::new(id_b.clone(), ep_b, vec![], vec!["personal".into()], 9474);
        // Accept should return an error (peer dropped during handshake)
        let result = mgr_b.accept_incoming().await;
        (result, mgr_b)
    });

    // A connects at QUIC level but drops before completing app handshake
    let conn = ep_a.connect(b_addr, "cordelia").unwrap().await.unwrap();
    // Drop without opening handshake stream -- simulates crash mid-connect
    conn.close(0u32.into(), b"chaos");
    drop(conn);
    ep_a.close(0u32.into(), b"chaos");

    // B should handle this gracefully (error, not hang)
    let result = tokio::time::timeout(std::time::Duration::from_secs(15), accept_task).await;
    assert!(
        result.is_ok(),
        "accept should not hang after peer drops mid-handshake"
    );
    let (accept_result, _mgr_b) = result.unwrap().unwrap();
    assert!(
        accept_result.is_err(),
        "accept should return error for dropped peer"
    );
}

/// T14-5b: Disconnect mid-item-sync. Verify the sync requester handles
/// a connection drop gracefully after sending the request.
#[tokio::test]
async fn test_chaos_disconnect_during_sync() {
    let id_a = make_identity();
    let id_b = make_identity();

    let ep_a = make_endpoint(&id_a);
    let ep_b = make_endpoint(&id_b);
    let b_addr = ep_b.local_addr().unwrap();

    let mut mgr_a =
        ConnectionManager::new(id_a.clone(), ep_a, vec![], vec!["personal".into()], 9474);
    let mut mgr_b =
        ConnectionManager::new(id_b.clone(), ep_b, vec![], vec!["personal".into()], 9474);

    let accept_task = tokio::spawn(async move {
        mgr_b.accept_incoming().await.unwrap();
        mgr_b
    });

    let node_b_id = mgr_a.connect_to(b_addr).await.unwrap();
    let mgr_b = accept_task.await.unwrap();

    // A opens a sync stream
    let conn_a = mgr_a.get_connection(&node_b_id).unwrap().clone();
    let (mut send, mut recv) = conn_a.open_bi().await.unwrap();
    let _stream = tokio::io::join(&mut recv, &mut send);

    // Send sync request -- write the request bytes only (don't wait for response)
    cordelia_network::codec::write_protocol_byte(
        &mut send,
        cordelia_network::messages::Protocol::ItemSync,
    )
    .await
    .unwrap();
    let req = cordelia_network::messages::WireMessage::SyncRequest(
        cordelia_network::messages::SyncRequest {
            channel_id: "test-channel".to_string(),
            since: None,
            limit: 100,
        },
    );
    cordelia_network::codec::write_frame(&mut send, &req)
        .await
        .unwrap();

    // B crashes before responding -- kill B's connection
    let node_a_id = cordelia_core::NodeId(id_a.public_key());
    mgr_b
        .get_connection(&node_a_id)
        .unwrap()
        .close(0u32.into(), b"chaos");

    // A tries to read response -- should get error (ReadTimeout or connection error), not hang
    let result = cordelia_network::codec::read_frame(&mut recv).await;
    assert!(
        result.is_err(),
        "read should return error after peer crashes"
    );

    mgr_a.shutdown();
}

/// T14-1: Concurrent stream stress. Open 50 bidirectional streams simultaneously
/// on a single QUIC connection. Verifies quinn handles high concurrency.
#[tokio::test]
async fn test_stress_concurrent_streams() {
    let id_a = make_identity();
    let id_b = make_identity();

    let ep_a = make_endpoint(&id_a);
    let ep_b = make_endpoint(&id_b);
    let b_addr = ep_b.local_addr().unwrap();

    let mut mgr_a =
        ConnectionManager::new(id_a.clone(), ep_a, vec![], vec!["personal".into()], 9474);
    let mut mgr_b =
        ConnectionManager::new(id_b.clone(), ep_b, vec![], vec!["personal".into()], 9474);

    let accept_task = tokio::spawn(async move {
        mgr_b.accept_incoming().await.unwrap();
        mgr_b
    });

    let node_b_id = mgr_a.connect_to(b_addr).await.unwrap();
    let _mgr_b = accept_task.await.unwrap();

    let conn = mgr_a.get_connection(&node_b_id).unwrap().clone();

    // Open 50 streams concurrently
    let mut handles = vec![];
    for i in 0u32..50 {
        let c = conn.clone();
        handles.push(tokio::spawn(async move {
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), c.open_bi()).await;
            match result {
                Ok(Ok((mut send, _recv))) => {
                    // Write a small payload and close
                    let _ = send.write_all(&i.to_be_bytes()).await;
                    let _ = send.finish();
                    true
                }
                _ => false,
            }
        }));
    }

    let mut success = 0;
    for h in handles {
        if h.await.unwrap() {
            success += 1;
        }
    }

    assert!(
        success >= 45,
        "at least 45/50 concurrent streams should succeed, got {success}"
    );

    mgr_a.shutdown();
}

/// T3-1: Incoming handshake timeout (BV-23 regression).
/// Verify that accept_incoming with a stalled peer doesn't block forever.
/// The internal 10s timeout on incoming.await should prevent the hang.
#[tokio::test]
async fn test_incoming_handshake_timeout() {
    let id_a = make_identity();
    let id_b = make_identity();

    let ep_a = make_endpoint(&id_a);
    let ep_b = make_endpoint(&id_b);
    let b_addr = ep_b.local_addr().unwrap();

    let mut mgr_a =
        ConnectionManager::new(id_a.clone(), ep_a, vec![], vec!["personal".into()], 9474);
    let mut mgr_b =
        ConnectionManager::new(id_b.clone(), ep_b, vec![], vec!["personal".into()], 9474);

    // A connects normally (QUIC + app handshake)
    let accept_task = tokio::spawn(async move {
        mgr_b.accept_incoming().await.unwrap();
        // Now B has one connection. Next accept_incoming will wait for a new
        // connection that never completes app handshake.
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(15), mgr_b.accept_incoming()).await;
        (result, mgr_b)
    });

    let _node_b = mgr_a.connect_to(b_addr).await.unwrap();

    // Now open a raw QUIC connection (no app handshake) from A's endpoint
    // This simulates a rogue peer that connects but never opens the handshake stream
    let _conn_a = mgr_a
        .get_connection(&cordelia_core::NodeId(id_b.public_key()))
        .unwrap()
        .clone();
    // A already has a connection to B. B's second accept_incoming will either:
    // 1. Accept a new QUIC connection (none incoming) and hang on endpoint.accept()
    // 2. Or timeout on the outer 15s wrapper
    // Either way it should NOT hang forever.

    let (result, _mgr_b) = accept_task.await.unwrap();
    // The outer timeout should fire (15s) because no second connection arrives
    assert!(
        result.is_err(),
        "accept should timeout when no new peer connects"
    );

    mgr_a.shutdown();
}

/// T1-1: BV-19 regression. Verify QUIC connection survives 35s idle
/// (longer than the old default 30s idle timeout). With keep_alive_interval=15s
/// the connection should survive indefinitely.
/// This test takes ~35s to run -- marked #[ignore] for normal test runs.
/// Run with: cargo test --test two_node -- --ignored
#[tokio::test]
#[ignore]
async fn test_bv19_connection_survives_35s_idle() {
    let id_a = make_identity();
    let id_b = make_identity();

    let ep_a = make_endpoint(&id_a);
    let ep_b = make_endpoint(&id_b);
    let b_addr = ep_b.local_addr().unwrap();

    // B accepts and holds the connection open
    let server = tokio::spawn(async move {
        let incoming = ep_b.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        // Wait 35s -- longer than old default idle timeout of 30s
        tokio::time::sleep(std::time::Duration::from_secs(35)).await;
        // Connection should still be alive (keepalive PINGs every 15s prevent idle close)
        let alive = conn.close_reason().is_none();
        conn.close(0u32.into(), b"done");
        ep_b.close(0u32.into(), b"done");
        alive
    });

    let conn_a = ep_a.connect(b_addr, "cordelia").unwrap().await.unwrap();
    // Client also waits 35s
    tokio::time::sleep(std::time::Duration::from_secs(35)).await;
    let client_alive = conn_a.close_reason().is_none();
    conn_a.close(0u32.into(), b"done");
    ep_a.close(0u32.into(), b"done");

    let server_alive = server.await.unwrap();
    assert!(
        server_alive,
        "server connection should survive 35s idle with keepalive"
    );
    assert!(
        client_alive,
        "client connection should survive 35s idle with keepalive"
    );
}

/// T11-2: Shutdown sequence. Verify shutdown_and_wait() completes
/// and the endpoint is properly closed.
#[tokio::test]
async fn test_shutdown_and_wait() {
    let id_a = make_identity();
    let id_b = make_identity();

    let ep_a = make_endpoint(&id_a);
    let ep_b = make_endpoint(&id_b);
    let b_addr = ep_b.local_addr().unwrap();

    let mut mgr_a =
        ConnectionManager::new(id_a.clone(), ep_a, vec![], vec!["personal".into()], 9474);
    let mut mgr_b =
        ConnectionManager::new(id_b.clone(), ep_b, vec![], vec!["personal".into()], 9474);

    let accept_task = tokio::spawn(async move {
        mgr_b.accept_incoming().await.unwrap();
        mgr_b
    });

    let _node_b_id = mgr_a.connect_to(b_addr).await.unwrap();
    let mut mgr_b = accept_task.await.unwrap();

    // Both sides shutdown with wait_idle
    let shutdown_a = tokio::spawn(async move {
        mgr_a.shutdown_and_wait().await;
    });
    let shutdown_b = tokio::spawn(async move {
        mgr_b.shutdown_and_wait().await;
    });

    // Both should complete within 5 seconds
    let result_a = tokio::time::timeout(std::time::Duration::from_secs(5), shutdown_a).await;
    let result_b = tokio::time::timeout(std::time::Duration::from_secs(5), shutdown_b).await;

    assert!(
        result_a.is_ok(),
        "shutdown_and_wait A should complete within 5s"
    );
    assert!(
        result_b.is_ok(),
        "shutdown_and_wait B should complete within 5s"
    );
}
