//! Wire codec: length-prefixed CBOR framing over QUIC streams.
//!
//! Frame format (§3.1):
//!   ┌──────────────┬──────────────────────┐
//!   │ Length (4B)   │ Payload (Length B)    │
//!   │ big-endian u32│ CBOR-encoded message  │
//!   └──────────────┴──────────────────────┘
//!
//! The first byte of each QUIC stream is the protocol byte (§3.3),
//! identifying the mini-protocol. After the protocol byte, all
//! subsequent data uses the length-prefixed frame format above.
//!
//! **Resilience:** Every read and write operation has a built-in 10s timeout.
//! Callers do not need to add their own timeout wrappers. The codec defends
//! itself against hung peers, slow networks, and partial writes.
//!
//! Spec: seed-drill/specs/network-protocol.md §3

use crate::messages::{Protocol, WireMessage};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum message size: 4 MB (§3.1).
pub const MAX_MESSAGE_BYTES: u32 = 4 * 1024 * 1024;

/// Standard timeout for all stream operations (reads and writes).
/// One value, used everywhere. If a single read or write takes longer
/// than this, the peer is considered unresponsive.
pub const STREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Application error code for unknown protocol byte (§3.3).
pub const ERR_UNKNOWN_PROTOCOL: u32 = 0x02;

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("CBOR encode error: {0}")]
    CborEncode(String),

    #[error("CBOR decode error: {0}")]
    CborDecode(String),

    #[error("message too large: {size} bytes (max {MAX_MESSAGE_BYTES})")]
    MessageTooLarge { size: u32 },

    #[error("unknown protocol byte: 0x{0:02x}")]
    UnknownProtocol(u8),

    #[error("unexpected EOF")]
    UnexpectedEof,

    #[error("stream timed out ({0}s)")]
    Timeout(u64),

    #[error("unexpected message type")]
    UnexpectedMessage,
}

// ── Encode/Decode (synchronous) ──────────────────────────────────

/// Encode a WireMessage to CBOR bytes.
pub fn encode_message(msg: &WireMessage) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    ciborium::into_writer(msg, &mut buf).map_err(|e| CodecError::CborEncode(e.to_string()))?;
    Ok(buf)
}

/// Decode a WireMessage from CBOR bytes.
pub fn decode_message(data: &[u8]) -> Result<WireMessage, CodecError> {
    ciborium::from_reader(data).map_err(|e| CodecError::CborDecode(e.to_string()))
}

// ── Timeout-guarded I/O helpers ──────────────────────────────────

/// Read exact bytes with STREAM_TIMEOUT. Maps EOF and timeout to CodecError.
async fn read_exact_guarded<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> Result<(), CodecError> {
    match tokio::time::timeout(STREAM_TIMEOUT, reader.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            Err(CodecError::UnexpectedEof)
        }
        Ok(Err(e)) => Err(CodecError::Io(e)),
        Err(_) => Err(CodecError::Timeout(STREAM_TIMEOUT.as_secs())),
    }
}

/// Write all bytes with STREAM_TIMEOUT.
async fn write_all_guarded<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> Result<(), CodecError> {
    match tokio::time::timeout(STREAM_TIMEOUT, writer.write_all(data)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(CodecError::Io(e)),
        Err(_) => Err(CodecError::Timeout(STREAM_TIMEOUT.as_secs())),
    }
}

// ── Protocol byte ────────────────────────────────────────────────

/// Write the protocol byte as the first byte of a new QUIC stream.
pub async fn write_protocol_byte<W: AsyncWrite + Unpin>(
    writer: &mut W,
    protocol: Protocol,
) -> Result<(), CodecError> {
    write_all_guarded(writer, &[protocol.as_byte()]).await
}

/// Read the protocol byte from the start of a QUIC stream.
pub async fn read_protocol_byte<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Protocol, CodecError> {
    let mut buf = [0u8; 1];
    read_exact_guarded(reader, &mut buf).await?;
    Protocol::from_byte(buf[0]).ok_or(CodecError::UnknownProtocol(buf[0]))
}

// ── Frame read/write ─────────────────────────────────────────────

/// Write a length-prefixed CBOR frame.
///
/// Format: [4-byte big-endian length][CBOR payload]
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &WireMessage,
) -> Result<(), CodecError> {
    let payload = encode_message(msg)?;
    let len = payload.len() as u32;
    if len > MAX_MESSAGE_BYTES {
        return Err(CodecError::MessageTooLarge { size: len });
    }
    write_all_guarded(writer, &len.to_be_bytes()).await?;
    write_all_guarded(writer, &payload).await
}

/// Read a length-prefixed CBOR frame.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<WireMessage, CodecError> {
    let mut len_buf = [0u8; 4];
    read_exact_guarded(reader, &mut len_buf).await?;

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MESSAGE_BYTES {
        return Err(CodecError::MessageTooLarge { size: len });
    }

    let mut payload = vec![0u8; len as usize];
    read_exact_guarded(reader, &mut payload).await?;

    decode_message(&payload)
}

// ── Raw frame read/write (pre-encoded CBOR) ──────────────────────

/// Write a raw CBOR-encoded frame (pre-encoded payload).
pub async fn write_raw_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), CodecError> {
    let len = payload.len() as u32;
    if len > MAX_MESSAGE_BYTES {
        return Err(CodecError::MessageTooLarge { size: len });
    }
    write_all_guarded(writer, &len.to_be_bytes()).await?;
    write_all_guarded(writer, payload).await
}

/// Read a raw frame, returning the CBOR bytes without decoding.
pub async fn read_raw_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, CodecError> {
    let mut len_buf = [0u8; 4];
    read_exact_guarded(reader, &mut len_buf).await?;

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MESSAGE_BYTES {
        return Err(CodecError::MessageTooLarge { size: len });
    }

    let mut payload = vec![0u8; len as usize];
    read_exact_guarded(reader, &mut payload).await?;

    Ok(payload)
}

// ── Request-response helper ──────────────────────────────────────

/// Send a protocol request and read the response (initiator side).
///
/// Combines: write_protocol_byte + write_frame(request) + read_frame -> response.
/// All three steps use STREAM_TIMEOUT internally.
pub async fn send_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    protocol: Protocol,
    request: &WireMessage,
) -> Result<WireMessage, CodecError> {
    write_protocol_byte(stream, protocol).await?;
    write_frame(stream, request).await?;
    read_frame(stream).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::*;

    #[test]
    fn test_protocol_byte_roundtrip() {
        for byte in 0x01..=0x08 {
            let proto = Protocol::from_byte(byte).unwrap();
            assert_eq!(proto.as_byte(), byte);
        }
        assert!(Protocol::from_byte(0x00).is_none());
        assert!(Protocol::from_byte(0x09).is_none());
        assert!(Protocol::from_byte(0xFF).is_none());
    }

    #[test]
    fn test_ping_encode_decode() {
        let msg = WireMessage::Ping(Ping {
            seq: 42,
            sent_at_ns: 1710100000_000_000_000,
        });
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        match decoded {
            WireMessage::Ping(p) => {
                assert_eq!(p.seq, 42);
                assert_eq!(p.sent_at_ns, 1710100000_000_000_000);
            }
            other => panic!("expected Ping, got {:?}", other),
        }
    }

    #[test]
    fn test_handshake_propose_encode_decode() {
        let msg = WireMessage::HandshakePropose(HandshakePropose {
            magic: HANDSHAKE_MAGIC,
            version_min: 1,
            version_max: 1,
            node_id: vec![0x42; 32],
            timestamp: 1710100000,
            channel_digest: vec![0xAB; 32],
            channel_count: 5,
            roles: vec!["personal".into()],
            p2p_port: 9474,
        });
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        match decoded {
            WireMessage::HandshakePropose(h) => {
                assert_eq!(h.magic, HANDSHAKE_MAGIC);
                assert_eq!(h.version_min, 1);
                assert_eq!(h.node_id.len(), 32);
                assert_eq!(h.channel_digest.len(), 32);
                assert_eq!(h.roles, vec!["personal"]);
            }
            other => panic!("expected HandshakePropose, got {:?}", other),
        }
    }

    #[test]
    fn test_channel_descriptor_encode_decode() {
        let desc = ChannelDescriptor {
            channel_id: "abc123".into(),
            channel_name: Some("research".into()),
            access: "open".into(),
            mode: "realtime".into(),
            key_version: 1,
            psk_hash: vec![0x11; 32],
            creator_id: vec![0x22; 32],
            created_at: "2026-03-10T14:30:00Z".into(),
            signature: vec![0x33; 64],
        };
        let msg = WireMessage::ChannelJoined(ChannelJoined {
            channel_id: "abc123".into(),
            descriptor: desc,
        });
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        match decoded {
            WireMessage::ChannelJoined(cj) => {
                assert_eq!(cj.channel_id, "abc123");
                assert_eq!(cj.descriptor.channel_name, Some("research".into()));
                assert_eq!(cj.descriptor.psk_hash.len(), 32);
                assert_eq!(cj.descriptor.signature.len(), 64);
            }
            other => panic!("expected ChannelJoined, got {:?}", other),
        }
    }

    #[test]
    fn test_item_encode_decode() {
        let item = Item {
            item_id: "ci_test123".into(),
            channel_id: "abc123".into(),
            item_type: "message".into(),
            encrypted_blob: vec![0xFF; 256],
            content_hash: vec![0xAA; 32],
            content_length: 256,
            author_id: vec![0xBB; 32],
            signature: vec![0xCC; 64],
            key_version: 1,
            published_at: "2026-03-10T14:30:00Z".into(),
            is_tombstone: false,
            parent_id: None,
        };
        let msg = WireMessage::PushPayload(PushPayload { items: vec![item] });
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        match decoded {
            WireMessage::PushPayload(pp) => {
                assert_eq!(pp.items.len(), 1);
                assert_eq!(pp.items[0].item_id, "ci_test123");
                assert_eq!(pp.items[0].encrypted_blob.len(), 256);
            }
            other => panic!("expected PushPayload, got {:?}", other),
        }
    }

    #[test]
    fn test_psk_exchange_encode_decode() {
        let msg = WireMessage::PskRequest(PskRequest {
            channel_id: "abc123".into(),
            subscriber_xpk: vec![0xDD; 32],
        });
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        match decoded {
            WireMessage::PskRequest(r) => {
                assert_eq!(r.channel_id, "abc123");
                assert_eq!(r.subscriber_xpk.len(), 32);
            }
            other => panic!("expected PskRequest, got {:?}", other),
        }
    }

    #[test]
    fn test_all_message_types_encode() {
        let messages: Vec<WireMessage> = vec![
            WireMessage::HandshakePropose(HandshakePropose {
                magic: HANDSHAKE_MAGIC,
                version_min: 1,
                version_max: 1,
                node_id: vec![0; 32],
                timestamp: 0,
                channel_digest: vec![0; 32],
                channel_count: 0,
                roles: vec![],
                p2p_port: 9474,
            }),
            WireMessage::HandshakeAccept(HandshakeAccept {
                version: 1,
                node_id: vec![0; 32],
                timestamp: 0,
                channel_digest: vec![0; 32],
                channel_count: 0,
                roles: vec![],
                reject_reason: None,
                p2p_port: 9474,
            }),
            WireMessage::Ping(Ping {
                seq: 0,
                sent_at_ns: 0,
            }),
            WireMessage::Pong(Pong {
                seq: 0,
                sent_at_ns: 0,
                recv_at_ns: 0,
            }),
            WireMessage::PeerShareRequest(PeerShareRequest { max_peers: 20 }),
            WireMessage::PeerShareResponse(PeerShareResponse { peers: vec![] }),
            WireMessage::ChannelJoined(ChannelJoined {
                channel_id: "test".into(),
                descriptor: ChannelDescriptor {
                    channel_id: "test".into(),
                    channel_name: None,
                    access: "open".into(),
                    mode: "batch".into(),
                    key_version: 0,
                    psk_hash: vec![0; 32],
                    creator_id: vec![0; 32],
                    created_at: "2026-01-01T00:00:00Z".into(),
                    signature: vec![0; 64],
                },
            }),
            WireMessage::ChannelLeft(ChannelLeft {
                channel_id: "test".into(),
            }),
            WireMessage::ChannelStateHash(ChannelStateHash {
                digest: vec![0; 32],
                count: 0,
            }),
            WireMessage::ChannelListRequest(ChannelListRequest {}),
            WireMessage::ChannelListResponse(ChannelListResponse { channels: vec![] }),
            WireMessage::SyncRequest(SyncRequest {
                channel_id: "test".into(),
                since: None,
                limit: 100,
            }),
            WireMessage::SyncResponse(SyncResponse {
                items: vec![],
                has_more: false,
            }),
            WireMessage::FetchRequest(FetchRequest { item_ids: vec![] }),
            WireMessage::FetchResponse(FetchResponse { items: vec![] }),
            WireMessage::PushPayload(PushPayload { items: vec![] }),
            WireMessage::PushAck(PushAck {
                stored: 0,
                dedup_dropped: 0,
                policy_rejected: 0,
                verification_failed: 0,
            }),
            WireMessage::PskRequest(PskRequest {
                channel_id: "test".into(),
                subscriber_xpk: vec![0; 32],
            }),
            WireMessage::PskResponse(PskResponse {
                status: "ok".into(),
                reason: None,
                ecies_envelope: None,
                key_version: None,
            }),
            WireMessage::PairingRequest(PairingRequest {
                node_id: vec![0; 32],
                pairing_code: "123456".into(),
            }),
            WireMessage::PairingResponse(PairingResponse {
                status: "ok".into(),
                reason: None,
            }),
        ];

        for msg in &messages {
            let encoded = encode_message(msg).unwrap();
            let decoded = decode_message(&encoded).unwrap();
            assert_eq!(
                std::mem::discriminant(msg),
                std::mem::discriminant(&decoded),
            );
        }
    }

    #[tokio::test]
    async fn test_frame_roundtrip() {
        let msg = WireMessage::Ping(Ping {
            seq: 99,
            sent_at_ns: 1710100000_000_000_000,
        });

        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let decoded = read_frame(&mut cursor).await.unwrap();
        match decoded {
            WireMessage::Ping(p) => {
                assert_eq!(p.seq, 99);
            }
            other => panic!("expected Ping, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_protocol_byte_stream() {
        let mut buf = Vec::new();
        write_protocol_byte(&mut buf, Protocol::Handshake)
            .await
            .unwrap();
        write_protocol_byte(&mut buf, Protocol::ItemPush)
            .await
            .unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(
            read_protocol_byte(&mut cursor).await.unwrap(),
            Protocol::Handshake
        );
        assert_eq!(
            read_protocol_byte(&mut cursor).await.unwrap(),
            Protocol::ItemPush
        );
    }

    #[tokio::test]
    async fn test_message_too_large() {
        let oversized_len = (MAX_MESSAGE_BYTES + 1).to_be_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&oversized_len);
        buf.push(0x00);

        let mut cursor = std::io::Cursor::new(buf);
        let result = read_frame(&mut cursor).await;
        assert!(matches!(result, Err(CodecError::MessageTooLarge { .. })));
    }

    #[tokio::test]
    async fn test_raw_frame_roundtrip() {
        let msg = WireMessage::Pong(Pong {
            seq: 1,
            sent_at_ns: 100,
            recv_at_ns: 200,
        });
        let payload = encode_message(&msg).unwrap();

        let mut buf = Vec::new();
        write_raw_frame(&mut buf, &payload).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let raw = read_raw_frame(&mut cursor).await.unwrap();
        assert_eq!(raw, payload);

        let decoded = decode_message(&raw).unwrap();
        match decoded {
            WireMessage::Pong(p) => assert_eq!(p.seq, 1),
            other => panic!("expected Pong, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_multiple_frames_on_stream() {
        let mut buf = Vec::new();

        write_protocol_byte(&mut buf, Protocol::KeepAlive)
            .await
            .unwrap();

        let ping = WireMessage::Ping(Ping {
            seq: 1,
            sent_at_ns: 100,
        });
        let pong = WireMessage::Pong(Pong {
            seq: 1,
            sent_at_ns: 100,
            recv_at_ns: 200,
        });
        let ping2 = WireMessage::Ping(Ping {
            seq: 2,
            sent_at_ns: 300,
        });

        write_frame(&mut buf, &ping).await.unwrap();
        write_frame(&mut buf, &pong).await.unwrap();
        write_frame(&mut buf, &ping2).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(
            read_protocol_byte(&mut cursor).await.unwrap(),
            Protocol::KeepAlive
        );

        match read_frame(&mut cursor).await.unwrap() {
            WireMessage::Ping(p) => assert_eq!(p.seq, 1),
            other => panic!("expected Ping, got {:?}", other),
        }
        match read_frame(&mut cursor).await.unwrap() {
            WireMessage::Pong(p) => assert_eq!(p.seq, 1),
            other => panic!("expected Pong, got {:?}", other),
        }
        match read_frame(&mut cursor).await.unwrap() {
            WireMessage::Ping(p) => assert_eq!(p.seq, 2),
            other => panic!("expected Ping, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_corrupted_cbor_payload() {
        let garbage = vec![0xFF, 0xFE, 0xFD, 0xFC, 0x00, 0x01, 0x02, 0x03];
        let len = (garbage.len() as u32).to_be_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(&garbage);

        let mut cursor = std::io::Cursor::new(buf);
        let result = read_frame(&mut cursor).await;
        assert!(matches!(result, Err(CodecError::CborDecode(_))));
    }

    #[tokio::test]
    async fn test_truncated_frame() {
        let len = 100u32.to_be_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(&vec![0u8; 50]);

        let mut cursor = std::io::Cursor::new(buf);
        let result = read_frame(&mut cursor).await;
        assert!(matches!(result, Err(CodecError::UnexpectedEof)));
    }

    #[tokio::test]
    async fn test_unknown_protocol_byte_rejected() {
        let buf = vec![0x09u8];
        let mut cursor = std::io::Cursor::new(buf);
        let result = read_protocol_byte(&mut cursor).await;
        assert!(matches!(result, Err(CodecError::UnknownProtocol(0x09))));
    }

    #[tokio::test]
    async fn test_extreme_protocol_bytes_rejected() {
        let mut cursor = std::io::Cursor::new(vec![0x00u8]);
        assert!(matches!(
            read_protocol_byte(&mut cursor).await,
            Err(CodecError::UnknownProtocol(0x00))
        ));

        let mut cursor = std::io::Cursor::new(vec![0xFFu8]);
        assert!(matches!(
            read_protocol_byte(&mut cursor).await,
            Err(CodecError::UnknownProtocol(0xFF))
        ));
    }

    #[tokio::test]
    async fn test_message_at_max_size_accepted() {
        let payload = vec![0u8; MAX_MESSAGE_BYTES as usize];
        let mut buf = Vec::new();
        write_raw_frame(&mut buf, &payload).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let read_back = read_raw_frame(&mut cursor).await.unwrap();
        assert_eq!(read_back.len(), MAX_MESSAGE_BYTES as usize);
    }

    #[tokio::test]
    async fn test_zero_length_frame() {
        let len = 0u32.to_be_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&len);

        let mut cursor = std::io::Cursor::new(buf);
        let result = read_frame(&mut cursor).await;
        assert!(matches!(result, Err(CodecError::CborDecode(_))));
    }

    #[tokio::test]
    async fn test_eof_on_protocol_byte() {
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        let result = read_protocol_byte(&mut cursor).await;
        assert!(matches!(result, Err(CodecError::UnexpectedEof)));
    }

    #[tokio::test]
    async fn test_eof_on_length_prefix() {
        let mut cursor = std::io::Cursor::new(vec![0u8, 0u8]);
        let result = read_frame(&mut cursor).await;
        assert!(matches!(result, Err(CodecError::UnexpectedEof)));
    }

    #[test]
    fn test_cbor_timestamp_without_tag0() {
        let msg = WireMessage::HandshakePropose(HandshakePropose {
            magic: HANDSHAKE_MAGIC,
            version_min: 1,
            version_max: 1,
            timestamp: 1767225600,
            channel_digest: vec![0u8; 32],
            channel_count: 0,
            node_id: vec![0u8; 32],
            roles: vec!["personal".into()],
            p2p_port: 9474,
        });
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        if let WireMessage::HandshakePropose(h) = decoded {
            assert_eq!(h.timestamp, 1767225600);
        } else {
            panic!("wrong message type");
        }
    }

    #[test]
    fn test_cbor_encode_decode_stability() {
        let msg = WireMessage::Ping(Ping {
            seq: 42,
            sent_at_ns: 1234567890,
        });
        let enc1 = encode_message(&msg).unwrap();
        let enc2 = encode_message(&msg).unwrap();
        assert_eq!(enc1, enc2, "CBOR encoding should be deterministic");
    }

    #[test]
    fn test_cbor_large_integer_roundtrip() {
        let msg = WireMessage::Ping(Ping {
            seq: u64::MAX,
            sent_at_ns: u64::MAX,
        });
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        if let WireMessage::Ping(p) = decoded {
            assert_eq!(p.seq, u64::MAX);
            assert_eq!(p.sent_at_ns, u64::MAX);
        } else {
            panic!("wrong message type");
        }
    }

    #[test]
    fn test_cbor_empty_vectors_roundtrip() {
        let msg = WireMessage::HandshakePropose(HandshakePropose {
            magic: HANDSHAKE_MAGIC,
            version_min: 1,
            version_max: 1,
            timestamp: 0,
            channel_digest: vec![],
            channel_count: 0,
            node_id: vec![],
            roles: vec![],
            p2p_port: 0,
        });
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        if let WireMessage::HandshakePropose(h) = decoded {
            assert!(h.channel_digest.is_empty());
            assert!(h.node_id.is_empty());
            assert!(h.roles.is_empty());
            assert_eq!(h.p2p_port, 0);
        } else {
            panic!("wrong message type");
        }
    }

    #[test]
    fn test_cbor_psk_denied_response_roundtrip() {
        let msg = WireMessage::PskResponse(PskResponse {
            status: "denied".into(),
            reason: Some("not authorized".into()),
            ecies_envelope: None,
            key_version: None,
        });
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        if let WireMessage::PskResponse(r) = decoded {
            assert_eq!(r.status, "denied");
            assert!(r.ecies_envelope.is_none());
            assert!(r.key_version.is_none());
        } else {
            panic!("wrong message type");
        }
    }

    #[tokio::test]
    async fn test_send_request_roundtrip() {
        // Simulate a peer-sharing request-response cycle
        let req = WireMessage::PeerShareRequest(PeerShareRequest { max_peers: 20 });
        let resp = WireMessage::PeerShareResponse(PeerShareResponse { peers: vec![] });

        // Write the "server" side: protocol byte was consumed by dispatch,
        // so just write the response after the request
        let mut buf = Vec::new();
        // Simulate client writing: protocol byte + request frame
        write_protocol_byte(&mut buf, Protocol::PeerSharing)
            .await
            .unwrap();
        write_frame(&mut buf, &req).await.unwrap();
        // Simulate server appending: response frame
        write_frame(&mut buf, &resp).await.unwrap();

        // Client reads back via send_request (skipping protocol byte write
        // since we're reading from a pre-built buffer). Test read_frame directly.
        let mut cursor = std::io::Cursor::new(buf);
        // Skip past what the client would have written
        let _ = read_protocol_byte(&mut cursor).await.unwrap();
        let _ = read_frame(&mut cursor).await.unwrap();
        // Read the response
        let got = read_frame(&mut cursor).await.unwrap();
        assert!(matches!(got, WireMessage::PeerShareResponse(_)));
    }
}
