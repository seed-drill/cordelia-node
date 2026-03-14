//! Item-Sync (0x05, §4.5) and Item-Push (0x06, §4.6) mini-protocols.
//!
//! Item-Sync: pull-based anti-entropy. Request headers, compare, fetch missing.
//! Item-Push: sender-initiated delivery for realtime channels.
//!
//! Spec: seed-drill/specs/network-protocol.md §4.5, §4.6

use crate::codec::{read_frame, write_frame, write_protocol_byte, read_protocol_byte};
use crate::messages::*;
use sha2::{Digest, Sha256};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

/// Sync interval for realtime channels (safety net).
pub const REALTIME_SYNC_INTERVAL: Duration = Duration::from_secs(60);

/// Sync interval for batch channels.
pub const BATCH_SYNC_INTERVAL: Duration = Duration::from_secs(900);

/// Default sync limit (max headers per response).
pub const DEFAULT_SYNC_LIMIT: u32 = 100;

/// Max items per fetch request.
pub const MAX_FETCH_ITEMS: usize = 100;

#[derive(Debug, Error)]
pub enum ItemSyncError {
    #[error("codec error: {0}")]
    Codec(#[from] crate::codec::CodecError),

    #[error("unexpected message type")]
    UnexpectedMessage,

    #[error("content hash mismatch for item {0}")]
    ContentHashMismatch(String),

    #[error("invalid signature for item {0}")]
    InvalidSignature(String),
}

// ── Item-Sync (0x05) ───────────────────────────────────────────────

/// Send a sync request (initiator side).
pub async fn send_sync_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    channel_id: &str,
    since: Option<&str>,
    limit: u32,
) -> Result<SyncResponse, ItemSyncError> {
    write_protocol_byte(stream, Protocol::ItemSync).await?;

    let req = WireMessage::SyncRequest(SyncRequest {
        channel_id: channel_id.to_string(),
        since: since.map(|s| s.to_string()),
        limit,
    });
    write_frame(stream, &req).await?;

    let resp = read_frame(stream).await?;
    match resp {
        WireMessage::SyncResponse(sr) => Ok(sr),
        _ => Err(ItemSyncError::UnexpectedMessage),
    }
}

/// Handle a sync request (responder side).
pub async fn handle_sync_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    get_headers: impl FnOnce(&str, Option<&str>, u32) -> (Vec<ItemHeader>, bool),
) -> Result<String, ItemSyncError> {
    let proto = read_protocol_byte(stream).await?;
    if proto != Protocol::ItemSync {
        return Err(ItemSyncError::UnexpectedMessage);
    }

    let msg = read_frame(stream).await?;
    let req = match msg {
        WireMessage::SyncRequest(r) => r,
        _ => return Err(ItemSyncError::UnexpectedMessage),
    };

    let (headers, has_more) = get_headers(
        &req.channel_id,
        req.since.as_deref(),
        req.limit,
    );

    let resp = WireMessage::SyncResponse(SyncResponse {
        items: headers,
        has_more,
    });
    write_frame(stream, &resp).await?;

    Ok(req.channel_id)
}

/// Send a fetch request for specific items (on the same stream after sync).
pub async fn send_fetch_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    item_ids: &[String],
) -> Result<(), ItemSyncError> {
    let req = WireMessage::FetchRequest(FetchRequest {
        item_ids: item_ids.to_vec(),
    });
    write_frame(writer, &req).await?;
    Ok(())
}

/// Read a fetch response.
pub async fn read_fetch_response<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<Item>, ItemSyncError> {
    let msg = read_frame(reader).await?;
    match msg {
        WireMessage::FetchResponse(fr) => Ok(fr.items),
        _ => Err(ItemSyncError::UnexpectedMessage),
    }
}

/// Handle a fetch request (responder side).
pub async fn handle_fetch_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    get_items: impl FnOnce(&[String]) -> Vec<Item>,
) -> Result<(), ItemSyncError> {
    let msg = read_frame(stream).await?;
    let req = match msg {
        WireMessage::FetchRequest(r) => r,
        _ => return Err(ItemSyncError::UnexpectedMessage),
    };

    let items = get_items(&req.item_ids);
    let resp = WireMessage::FetchResponse(FetchResponse { items });
    write_frame(stream, &resp).await?;

    Ok(())
}

// ── Item-Push (0x06) ───────────────────────────────────────────────

/// Push items to a peer (sender side).
pub async fn send_push<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    items: &[Item],
) -> Result<PushAck, ItemSyncError> {
    write_protocol_byte(stream, Protocol::ItemPush).await?;

    let payload = WireMessage::PushPayload(PushPayload {
        items: items.to_vec(),
    });
    write_frame(stream, &payload).await?;

    let resp = read_frame(stream).await?;
    match resp {
        WireMessage::PushAck(ack) => Ok(ack),
        _ => Err(ItemSyncError::UnexpectedMessage),
    }
}

/// Handle an incoming push (receiver side).
pub async fn handle_push<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    process_items: impl FnOnce(Vec<Item>) -> PushAck,
) -> Result<PushAck, ItemSyncError> {
    let proto = read_protocol_byte(stream).await?;
    if proto != Protocol::ItemPush {
        return Err(ItemSyncError::UnexpectedMessage);
    }

    let msg = read_frame(stream).await?;
    let items = match msg {
        WireMessage::PushPayload(pp) => pp.items,
        _ => return Err(ItemSyncError::UnexpectedMessage),
    };

    let ack = process_items(items);

    let resp = WireMessage::PushAck(ack.clone());
    write_frame(stream, &resp).await?;

    Ok(ack)
}

// ── Validation helpers ─────────────────────────────────────────────

/// Verify that an item's content_hash matches its encrypted_blob.
pub fn verify_content_hash(item: &Item) -> bool {
    let hash = Sha256::digest(&item.encrypted_blob);
    item.content_hash == hash.as_slice()
}

/// Determine which item IDs from a sync response we need to fetch.
///
/// `known_items` maps item_id -> (content_hash, published_at) for items we already have.
pub fn compute_fetch_list(
    headers: &[ItemHeader],
    known_items: &std::collections::HashMap<String, (Vec<u8>, String)>,
) -> Vec<String> {
    headers
        .iter()
        .filter(|h| {
            match known_items.get(&h.item_id) {
                None => true, // Unknown item -> fetch
                Some((hash, _published_at)) => {
                    if *hash != h.content_hash {
                        // Different content_hash -> LWW (fetch if newer)
                        // For simplicity in Phase 1, always fetch on mismatch
                        true
                    } else {
                        false // Same content -> skip
                    }
                }
            }
        })
        .map(|h| h.item_id.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_test_item(id: &str) -> Item {
        let blob = vec![0xFF; 64];
        let hash = Sha256::digest(&blob);
        Item {
            item_id: id.to_string(),
            channel_id: "ch1".into(),
            item_type: "message".into(),
            encrypted_blob: blob,
            content_hash: hash.to_vec(),
            content_length: 64,
            author_id: vec![0xAA; 32],
            signature: vec![0xBB; 64],
            key_version: 1,
            published_at: "2026-03-10T14:30:00Z".into(),
            is_tombstone: false,
            parent_id: None,
        }
    }

    fn make_test_header(id: &str) -> ItemHeader {
        let blob = vec![0xFF; 64];
        let hash = Sha256::digest(&blob);
        ItemHeader {
            item_id: id.to_string(),
            channel_id: "ch1".into(),
            item_type: "message".into(),
            content_hash: hash.to_vec(),
            author_id: vec![0xAA; 32],
            signature: vec![0xBB; 64],
            key_version: 1,
            published_at: "2026-03-10T14:30:00Z".into(),
            is_tombstone: false,
            parent_id: None,
        }
    }

    #[test]
    fn test_verify_content_hash() {
        let item = make_test_item("ci_test1");
        assert!(verify_content_hash(&item));

        let mut bad = item.clone();
        bad.encrypted_blob[0] ^= 0xFF;
        assert!(!verify_content_hash(&bad));
    }

    #[test]
    fn test_compute_fetch_list_unknown() {
        let headers = vec![make_test_header("ci_new1"), make_test_header("ci_new2")];
        let known = HashMap::new();
        let fetch = compute_fetch_list(&headers, &known);
        assert_eq!(fetch, vec!["ci_new1", "ci_new2"]);
    }

    #[test]
    fn test_compute_fetch_list_known_same_hash() {
        let h = make_test_header("ci_known");
        let mut known = HashMap::new();
        known.insert(
            "ci_known".to_string(),
            (h.content_hash.clone(), "2026-03-10T14:30:00Z".to_string()),
        );
        let fetch = compute_fetch_list(&[h], &known);
        assert!(fetch.is_empty());
    }

    #[test]
    fn test_compute_fetch_list_different_hash() {
        let h = make_test_header("ci_changed");
        let mut known = HashMap::new();
        known.insert(
            "ci_changed".to_string(),
            (vec![0x00; 32], "2026-03-10T14:00:00Z".to_string()),
        );
        let fetch = compute_fetch_list(&[h], &known);
        assert_eq!(fetch, vec!["ci_changed"]);
    }

    #[tokio::test]
    async fn test_sync_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(8192);

        let server_task = tokio::spawn(async move {
            handle_sync_request(&mut server, |ch, since, limit| {
                assert_eq!(ch, "ch1");
                assert!(since.is_none());
                assert_eq!(limit, 50);
                (vec![make_test_header("ci_item1")], false)
            })
            .await
            .unwrap()
        });

        let resp = send_sync_request(&mut client, "ch1", None, 50)
            .await
            .unwrap();
        assert_eq!(resp.items.len(), 1);
        assert_eq!(resp.items[0].item_id, "ci_item1");
        assert!(!resp.has_more);

        let channel = server_task.await.unwrap();
        assert_eq!(channel, "ch1");
    }

    #[tokio::test]
    async fn test_push_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(16384);

        let items = vec![make_test_item("ci_push1"), make_test_item("ci_push2")];

        let server_task = tokio::spawn(async move {
            handle_push(&mut server, |received| {
                assert_eq!(received.len(), 2);
                PushAck {
                    stored: 2,
                    dedup_dropped: 0,
                    policy_rejected: 0,
                    verification_failed: 0,
                }
            })
            .await
            .unwrap()
        });

        let ack = send_push(&mut client, &items).await.unwrap();
        assert_eq!(ack.stored, 2);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_fetch_on_sync_stream() {
        let (mut client, mut server) = tokio::io::duplex(16384);

        // Simulate: after SyncResponse, client sends FetchRequest, server responds
        let server_task = tokio::spawn(async move {
            handle_fetch_request(&mut server, |ids| {
                assert_eq!(ids, &["ci_fetch1"]);
                vec![make_test_item("ci_fetch1")]
            })
            .await
            .unwrap();
        });

        send_fetch_request(&mut client, &["ci_fetch1".into()])
            .await
            .unwrap();

        let items = read_fetch_response(&mut client).await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].item_id, "ci_fetch1");
        assert!(verify_content_hash(&items[0]));

        server_task.await.unwrap();
    }
}
