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
//! Spec: seed-drill/specs/network-protocol.md §3

use crate::messages::WireMessage;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum message size: 4 MB (§3.1).
pub const MAX_MESSAGE_BYTES: u32 = 4 * 1024 * 1024;

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
}

/// Encode a WireMessage to CBOR bytes.
pub fn encode_message(msg: &WireMessage) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    ciborium::into_writer(msg, &mut buf)
        .map_err(|e| CodecError::CborEncode(e.to_string()))?;
    Ok(buf)
}

/// Decode a WireMessage from CBOR bytes.
pub fn decode_message(data: &[u8]) -> Result<WireMessage, CodecError> {
    ciborium::from_reader(data).map_err(|e| CodecError::CborDecode(e.to_string()))
}

/// Write the protocol byte as the first byte of a new QUIC stream.
pub async fn write_protocol_byte<W: AsyncWrite + Unpin>(
    writer: &mut W,
    protocol: crate::messages::Protocol,
) -> Result<(), CodecError> {
    writer.write_all(&[protocol.as_byte()]).await?;
    Ok(())
}

/// Read the protocol byte from the start of a QUIC stream.
pub async fn read_protocol_byte<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<crate::messages::Protocol, CodecError> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            CodecError::UnexpectedEof
        } else {
            CodecError::Io(e)
        }
    })?;
    crate::messages::Protocol::from_byte(buf[0])
        .ok_or(CodecError::UnknownProtocol(buf[0]))
}

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
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    Ok(())
}

/// Read a length-prefixed CBOR frame.
///
/// Returns the decoded WireMessage.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<WireMessage, CodecError> {
    // Read 4-byte length prefix
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            CodecError::UnexpectedEof
        } else {
            CodecError::Io(e)
        }
    })?;

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MESSAGE_BYTES {
        return Err(CodecError::MessageTooLarge { size: len });
    }

    // Read payload
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            CodecError::UnexpectedEof
        } else {
            CodecError::Io(e)
        }
    })?;

    decode_message(&payload)
}

/// Write a raw CBOR-encoded frame (pre-encoded payload).
/// Useful when forwarding messages without re-encoding.
pub async fn write_raw_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), CodecError> {
    let len = payload.len() as u32;
    if len > MAX_MESSAGE_BYTES {
        return Err(CodecError::MessageTooLarge { size: len });
    }
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    Ok(())
}

/// Read a raw frame, returning the CBOR bytes without decoding.
/// Useful for forwarding or deferred decoding.
pub async fn read_raw_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, CodecError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            CodecError::UnexpectedEof
        } else {
            CodecError::Io(e)
        }
    })?;

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MESSAGE_BYTES {
        return Err(CodecError::MessageTooLarge { size: len });
    }

    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            CodecError::UnexpectedEof
        } else {
            CodecError::Io(e)
        }
    })?;

    Ok(payload)
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
        let msg = WireMessage::PushPayload(PushPayload {
            items: vec![item],
        });
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
        // Verify every variant can be encoded without error
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
            }),
            WireMessage::HandshakeAccept(HandshakeAccept {
                version: 1,
                node_id: vec![0; 32],
                timestamp: 0,
                channel_digest: vec![0; 32],
                channel_count: 0,
                roles: vec![],
                reject_reason: None,
            }),
            WireMessage::Ping(Ping { seq: 0, sent_at_ns: 0 }),
            WireMessage::Pong(Pong { seq: 0, sent_at_ns: 0, recv_at_ns: 0 }),
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
            WireMessage::ChannelLeft(ChannelLeft { channel_id: "test".into() }),
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
            WireMessage::SyncResponse(SyncResponse { items: vec![], has_more: false }),
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
            // Verify we get the same variant tag back
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
        write_protocol_byte(&mut buf, Protocol::Handshake).await.unwrap();
        write_protocol_byte(&mut buf, Protocol::ItemPush).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(read_protocol_byte(&mut cursor).await.unwrap(), Protocol::Handshake);
        assert_eq!(read_protocol_byte(&mut cursor).await.unwrap(), Protocol::ItemPush);
    }

    #[tokio::test]
    async fn test_message_too_large() {
        // Manually write an oversized length prefix -- we only need the
        // 4-byte header to trigger the size check (read_frame rejects
        // before reading payload bytes).
        let oversized_len = (MAX_MESSAGE_BYTES + 1).to_be_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&oversized_len);
        // Append a single dummy byte so the cursor isn't empty after the header
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
        // Simulate a QUIC stream: protocol byte + multiple frames
        let mut buf = Vec::new();

        // Write protocol byte
        write_protocol_byte(&mut buf, Protocol::KeepAlive).await.unwrap();

        // Write several ping/pong frames
        let ping = WireMessage::Ping(Ping { seq: 1, sent_at_ns: 100 });
        let pong = WireMessage::Pong(Pong { seq: 1, sent_at_ns: 100, recv_at_ns: 200 });
        let ping2 = WireMessage::Ping(Ping { seq: 2, sent_at_ns: 300 });

        write_frame(&mut buf, &ping).await.unwrap();
        write_frame(&mut buf, &pong).await.unwrap();
        write_frame(&mut buf, &ping2).await.unwrap();

        // Read back
        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(read_protocol_byte(&mut cursor).await.unwrap(), Protocol::KeepAlive);

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
}
