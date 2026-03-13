//! Request handlers for the Channels API.
//!
//! Spec: seed-drill/specs/channels-api.md §3

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;

use cordelia_crypto::bech32::{encode_public_key, HRP_X25519_PK};
use cordelia_crypto::signing;
use cordelia_storage::{channels, items, psk, search};

use crate::auth;
use crate::error::ApiError;
use crate::state::AppState;
use crate::types::*;

const MAX_CONTENT_BYTES: usize = 1_048_576; // 1 MB
const MAX_LISTEN_LIMIT: u32 = 500;

// ── POST /api/v1/channels/subscribe ────────────────────────────────

pub async fn subscribe(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SubscribeRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    if body.mode != "realtime" && body.mode != "batch" {
        return Err(ApiError::BadRequest("mode must be 'realtime' or 'batch'".into()));
    }
    if body.access != "open" && body.access != "invite_only" {
        return Err(ApiError::BadRequest("access must be 'open' or 'invite_only'".into()));
    }

    let db = state.db.lock().map_err(|e| ApiError::Internal(e.to_string()))?;
    let pk = state.identity.public_key();

    // Try to resolve channel by name
    let canonical = cordelia_storage::naming::canonicalize(&body.channel)?;
    let channel_id = cordelia_storage::naming::named_channel_id(&canonical);

    // Check if channel already exists
    match channels::get_by_id(&db, &channel_id) {
        Ok(existing) => {
            // Already a member?
            if let Some(role) = channels::get_member_role(&db, &channel_id, &pk)? {
                return Ok(HttpResponse::Ok().json(SubscribeResponse {
                    channel: canonical,
                    channel_id,
                    is_new: false,
                    role,
                    mode: existing.mode,
                    access: existing.access,
                    created_at: existing.created_at,
                    joined_at: None,
                }));
            }

            // invite_only: deny
            if existing.access == "invite_only" {
                return Err(ApiError::Forbidden("channel is invite-only".into()));
            }

            // Open channel with local PSK: add as member
            let now = Utc::now().to_rfc3339();
            channels::add_member(&db, &channel_id, &pk, "member")?;

            Ok(HttpResponse::Ok().json(SubscribeResponse {
                channel: canonical,
                channel_id,
                is_new: false,
                role: "member".into(),
                mode: existing.mode,
                access: existing.access,
                created_at: existing.created_at,
                joined_at: Some(now),
            }))
        }
        Err(cordelia_core::CordeliaError::ChannelNotFound { .. }) => {
            // Create new channel
            let new_psk = cordelia_crypto::generate_psk()
                .map_err(|e| ApiError::Internal(e.to_string()))?;

            let ch = channels::create_named(
                &db,
                &canonical,
                &body.mode,
                &body.access,
                &pk,
                Some(&new_psk),
            )?;

            // Store PSK to filesystem
            psk::write_psk(&state.home_dir, &ch.channel_id, &new_psk)?;

            Ok(HttpResponse::Ok().json(SubscribeResponse {
                channel: canonical,
                channel_id: ch.channel_id,
                is_new: true,
                role: "owner".into(),
                mode: ch.mode,
                access: ch.access,
                created_at: ch.created_at,
                joined_at: None,
            }))
        }
        Err(e) => Err(e.into()),
    }
}

// ── POST /api/v1/channels/publish ──────────────────────────────────

pub async fn publish(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<PublishRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    // Reject node-internal item types
    if items::is_internal_type(&body.item_type) {
        return Err(ApiError::BadRequest(format!(
            "item_type '{}' is reserved for node-internal use",
            body.item_type
        )));
    }

    let db = state.db.lock().map_err(|e| ApiError::Internal(e.to_string()))?;
    let pk = state.identity.public_key();

    // Resolve channel
    let channel_id = channels::resolve(&body.channel)?;

    // Verify membership
    if !channels::is_member(&db, &channel_id.0, &pk)? {
        return Err(ApiError::Forbidden("not a member of this channel".into()));
    }

    // Serialize plaintext content
    let plaintext_envelope = serde_json::json!({
        "content": body.content,
        "metadata": body.metadata,
    });
    let plaintext_bytes = serde_json::to_vec(&plaintext_envelope)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    if plaintext_bytes.len() > MAX_CONTENT_BYTES {
        return Err(ApiError::PayloadTooLarge {
            used_bytes: plaintext_bytes.len() as u64,
            quota_bytes: MAX_CONTENT_BYTES as u64,
        });
    }

    // Load channel PSK
    let channel_psk = psk::read_psk(&state.home_dir, &channel_id.0)?;

    // Encrypt
    let encrypted_blob = cordelia_crypto::item_encrypt(&channel_psk, &plaintext_bytes)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Generate item ID and timestamp
    let item_id = items::generate_item_id();
    let published_at = Utc::now().to_rfc3339();
    let content_hash = cordelia_crypto::sha256(&encrypted_blob);

    // Get channel's current key_version
    let channel = channels::get_by_id(&db, &channel_id.0)?;

    // Build and sign CBOR metadata envelope
    let cbor = signing::build_item_metadata_envelope(
        &pk,
        &channel_id.0,
        &content_hash,
        false,
        &item_id,
        channel.key_version,
        &published_at,
    )
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    let signature = state.identity.sign(&cbor);

    // Store item
    items::insert_item(
        &db,
        &items::NewItem {
            item_id: &item_id,
            channel_id: &channel_id.0,
            author_id: &pk,
            item_type: &body.item_type,
            published_at: &published_at,
            parent_id: body.parent_id.as_deref(),
            key_version: channel.key_version,
            content_hash: &content_hash,
            signature: &signature,
            encrypted_blob: &encrypted_blob,
        },
    )?;

    // Index for FTS5 search (extract text from plaintext content before response)
    let searchable = search::extract_text(
        &body.content,
        body.metadata.as_ref(),
        &body.item_type,
    );
    // Best-effort: don't fail publish if search indexing fails
    let _ = search::index_item(
        &db, &item_id, &channel_id.0, &body.item_type, &published_at, &searchable,
    );

    // Author in Bech32
    let author_bech32 =
        encode_public_key(&pk).map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(PublishResponse {
        item_id,
        channel: body.channel.clone(),
        published_at,
        author: author_bech32,
        item_type: body.item_type.clone(),
    }))
}

// ── POST /api/v1/channels/listen ───────────────────────────────────

pub async fn listen(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ListenRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    let limit = body.limit.min(MAX_LISTEN_LIMIT).max(1);

    let db = state.db.lock().map_err(|e| ApiError::Internal(e.to_string()))?;
    let pk = state.identity.public_key();

    // Resolve channel
    let channel_id = channels::resolve(&body.channel)?;

    // Verify membership
    if !channels::is_member(&db, &channel_id.0, &pk)? {
        return Err(ApiError::Forbidden("not a member of this channel".into()));
    }

    // Query items (fetch limit+1 to detect has_more)
    let rows = items::query_listen(
        &db,
        &channel_id.0,
        body.since.as_deref(),
        limit + 1,
    )?;

    let has_more = rows.len() > limit as usize;
    let result_rows = if has_more {
        &rows[..limit as usize]
    } else {
        &rows
    };

    // Load PSK for decryption
    let channel_psk = psk::read_psk(&state.home_dir, &channel_id.0)?;

    // Decrypt and verify each item
    let mut listen_items = Vec::with_capacity(result_rows.len());
    for row in result_rows {
        let (content, metadata) = decrypt_item_content(&channel_psk, &row.encrypted_blob);
        let signature_valid = verify_item_signature(row);

        let mut author_pk = [0u8; 32];
        if row.author_id.len() == 32 {
            author_pk.copy_from_slice(&row.author_id);
        }
        let author = encode_public_key(&author_pk).unwrap_or_default();

        listen_items.push(ListenItem {
            item_id: row.item_id.clone(),
            content,
            metadata,
            item_type: row.item_type.clone(),
            parent_id: row.parent_id.clone(),
            author,
            published_at: row.published_at.clone(),
            signature_valid,
        });
    }

    // Cursor: published_at of last item, or current time if empty
    let cursor = if let Some(last) = result_rows.last() {
        last.published_at.clone()
    } else {
        Utc::now().to_rfc3339()
    };

    Ok(HttpResponse::Ok().json(ListenResponse {
        channel: body.channel.clone(),
        items: listen_items,
        cursor,
        has_more,
    }))
}

// ── POST /api/v1/channels/list ─────────────────────────────────────

pub async fn list(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    let db = state.db.lock().map_err(|e| ApiError::Internal(e.to_string()))?;
    let pk = state.identity.public_key();

    let all = channels::list_for_entity(&db, &pk)?;
    let mut response_channels = Vec::new();

    for ch in all {
        // Only named channels in list (DMs and groups have separate endpoints)
        if ch.channel_type != "named" {
            continue;
        }
        let role = channels::get_member_role(&db, &ch.channel_id, &pk)?
            .unwrap_or_default();
        let item_count = items::count_for_channel(&db, &ch.channel_id)?;
        let activity = items::last_activity(&db, &ch.channel_id)?;

        response_channels.push(ListChannel {
            channel: ch.channel_name.unwrap_or_default(),
            channel_id: ch.channel_id,
            role,
            mode: ch.mode,
            access: ch.access,
            item_count,
            last_activity: activity,
            created_at: ch.created_at,
        });
    }

    Ok(HttpResponse::Ok().json(ListResponse {
        channels: response_channels,
    }))
}

// ── POST /api/v1/channels/info ─────────────────────────────────────

pub async fn info(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<InfoRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    let canonical = cordelia_storage::naming::canonicalize(&body.channel)?;
    let channel_id = cordelia_storage::naming::named_channel_id(&canonical);

    let db = state.db.lock().map_err(|e| ApiError::Internal(e.to_string()))?;

    match channels::get_by_id(&db, &channel_id) {
        Ok(ch) => {
            let count = channels::member_count(&db, &channel_id)?;
            let owner = encode_public_key(&ch.creator_id).unwrap_or_default();

            Ok(HttpResponse::Ok().json(InfoResponse {
                channel: canonical,
                channel_id,
                exists: true,
                mode: Some(ch.mode),
                access: Some(ch.access),
                owner: Some(owner),
                member_count: Some(count),
                created_at: Some(ch.created_at),
            }))
        }
        Err(cordelia_core::CordeliaError::ChannelNotFound { .. }) => {
            Ok(HttpResponse::Ok().json(InfoResponse {
                channel: canonical,
                channel_id,
                exists: false,
                mode: None,
                access: None,
                owner: None,
                member_count: None,
                created_at: None,
            }))
        }
        Err(e) => Err(e.into()),
    }
}

// ── POST /api/v1/channels/unsubscribe ──────────────────────────────

pub async fn unsubscribe(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<UnsubscribeRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    let db = state.db.lock().map_err(|e| ApiError::Internal(e.to_string()))?;
    let pk = state.identity.public_key();

    let channel_id = channels::resolve(&body.channel)?;

    if !channels::is_member(&db, &channel_id.0, &pk)? {
        return Err(ApiError::NotFound(format!(
            "channel '{}' not found or not a member",
            body.channel
        )));
    }

    channels::remove_member(&db, &channel_id.0, &pk)?;
    psk::delete_psk(&state.home_dir, &channel_id.0)?;

    Ok(HttpResponse::Ok().json(UnsubscribeResponse {
        ok: true,
        channel: body.channel.clone(),
    }))
}

// ── POST /api/v1/channels/identity ─────────────────────────────────

pub async fn identity(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    let pk = state.identity.public_key();
    let ed_bech32 = encode_public_key(&pk).map_err(|e| ApiError::Internal(e.to_string()))?;

    let x_pub = state.identity.x25519_public_key();
    let x_bech32 = cordelia_crypto::bech32::bech32_encode(HRP_X25519_PK, &x_pub)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let db = state.db.lock().map_err(|e| ApiError::Internal(e.to_string()))?;
    let all = channels::list_for_entity(&db, &pk)?;
    let subscribed = all.len() as i64;

    Ok(HttpResponse::Ok().json(IdentityResponse {
        ed25519_public_key: ed_bech32.clone(),
        x25519_public_key: x_bech32,
        node_id: ed_bech32,
        channels_subscribed: subscribed,
    }))
}

// ── POST /api/v1/channels/dm ──────────────────────────────────

pub async fn dm(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<DmRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    // Decode peer's Ed25519 public key from Bech32
    let peer_pk_bytes = cordelia_crypto::bech32::decode_public_key(&body.peer_public_key)
        .map_err(|e| ApiError::BadRequest(format!("invalid peer_public_key: {e}")))?;

    let db = state.db.lock().map_err(|e| ApiError::Internal(e.to_string()))?;
    let pk = state.identity.public_key();

    if peer_pk_bytes == pk {
        return Err(ApiError::BadRequest("cannot DM yourself".into()));
    }

    // Check if DM channel already exists
    let channel_id = cordelia_storage::naming::dm_channel_id(&pk, &peer_pk_bytes);

    match channels::get_by_id(&db, &channel_id) {
        Ok(existing) => {
            let peer_bech32 = cordelia_crypto::bech32::encode_public_key(&peer_pk_bytes)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok(HttpResponse::Ok().json(DmResponse {
                channel_id,
                is_new: false,
                peer_public_key: peer_bech32,
                created_at: existing.created_at,
            }))
        }
        Err(cordelia_core::CordeliaError::ChannelNotFound { .. }) => {
            // Create DM channel with PSK
            let new_psk = cordelia_crypto::generate_psk()
                .map_err(|e| ApiError::Internal(e.to_string()))?;

            let ch = channels::create_dm(&db, &pk, &peer_pk_bytes, Some(&new_psk))?;
            psk::write_psk(&state.home_dir, &ch.channel_id, &new_psk)?;

            // Create ECIES envelope wrapping PSK for peer's X25519 key
            let peer_x25519 = cordelia_crypto::identity::x25519_pub_from_ed25519_pub(&peer_pk_bytes);
            let envelope = cordelia_crypto::ecies::ecies_encrypt(&peer_x25519, &new_psk)
                .map_err(|e| ApiError::Internal(e.to_string()))?;

            // Store envelope as internal item for peer to retrieve via replication
            let envelope_bytes = envelope.to_bytes();
            let item_id = items::generate_item_id();
            let published_at = Utc::now().to_rfc3339();
            let content_hash = cordelia_crypto::sha256(&envelope_bytes);
            let cbor = signing::build_item_metadata_envelope(
                &pk, &ch.channel_id, &content_hash, false, &item_id, 1, &published_at,
            ).map_err(|e| ApiError::Internal(e.to_string()))?;
            let signature = state.identity.sign(&cbor);

            items::insert_item(&db, &items::NewItem {
                item_id: &item_id,
                channel_id: &ch.channel_id,
                author_id: &pk,
                item_type: "psk_envelope",
                published_at: &published_at,
                parent_id: None,
                key_version: 1,
                content_hash: &content_hash,
                signature: &signature,
                encrypted_blob: &envelope_bytes,
            })?;

            let peer_bech32 = cordelia_crypto::bech32::encode_public_key(&peer_pk_bytes)
                .map_err(|e| ApiError::Internal(e.to_string()))?;

            Ok(HttpResponse::Ok().json(DmResponse {
                channel_id: ch.channel_id,
                is_new: true,
                peer_public_key: peer_bech32,
                created_at: ch.created_at,
            }))
        }
        Err(e) => Err(e.into()),
    }
}

// ── POST /api/v1/channels/list-dms ───────────────────────────

pub async fn list_dms(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    let db = state.db.lock().map_err(|e| ApiError::Internal(e.to_string()))?;
    let pk = state.identity.public_key();

    let dms = channels::list_dms_for_entity(&db, &pk)?;
    let mut result = Vec::new();

    for ch in dms {
        let peer_key = channels::dm_peer_key(&db, &ch.channel_id)
            .unwrap_or([0u8; 32]);
        let peer_bech32 = cordelia_crypto::bech32::encode_public_key(&peer_key)
            .unwrap_or_default();
        let item_count = items::count_for_channel(&db, &ch.channel_id)?;
        let activity = items::last_activity(&db, &ch.channel_id)?;

        result.push(DmChannel {
            channel_id: ch.channel_id,
            peer_public_key: peer_bech32,
            item_count,
            last_activity: activity,
            created_at: ch.created_at,
        });
    }

    Ok(HttpResponse::Ok().json(ListDmsResponse { dms: result }))
}

// ── POST /api/v1/channels/group ──────────────────────────────

pub async fn group_create(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<GroupCreateRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    if body.mode != "realtime" && body.mode != "batch" {
        return Err(ApiError::BadRequest("mode must be 'realtime' or 'batch'".into()));
    }

    let db = state.db.lock().map_err(|e| ApiError::Internal(e.to_string()))?;
    let pk = state.identity.public_key();

    let new_psk = cordelia_crypto::generate_psk()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let ch = channels::create_group(&db, &pk, &body.mode, Some(&new_psk))?;
    psk::write_psk(&state.home_dir, &ch.channel_id, &new_psk)?;

    Ok(HttpResponse::Ok().json(GroupCreateResponse {
        channel_id: ch.channel_id,
        mode: ch.mode,
        created_at: ch.created_at,
    }))
}

// ── POST /api/v1/channels/group/invite ───────────────────────

pub async fn group_invite(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<GroupInviteRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    let peer_pk = cordelia_crypto::bech32::decode_public_key(&body.peer_public_key)
        .map_err(|e| ApiError::BadRequest(format!("invalid peer_public_key: {e}")))?;

    let db = state.db.lock().map_err(|e| ApiError::Internal(e.to_string()))?;
    let pk = state.identity.public_key();

    // Verify channel exists and caller is owner
    let ch = channels::get_by_id(&db, &body.channel_id)?;
    if ch.channel_type != "group" {
        return Err(ApiError::BadRequest("channel is not a group".into()));
    }
    let role = channels::get_member_role(&db, &body.channel_id, &pk)?
        .ok_or_else(|| ApiError::Forbidden("not a member of this group".into()))?;
    if role != "owner" {
        return Err(ApiError::Forbidden("only owner can invite".into()));
    }

    // Add member
    channels::add_member(&db, &body.channel_id, &peer_pk, "member")?;

    // Wrap current PSK in ECIES envelope for the invitee
    let channel_psk = psk::read_psk(&state.home_dir, &body.channel_id)?;
    let peer_x25519 = cordelia_crypto::identity::x25519_pub_from_ed25519_pub(&peer_pk);
    let envelope = cordelia_crypto::ecies::ecies_encrypt(&peer_x25519, &channel_psk)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Store envelope as internal item
    let envelope_bytes = envelope.to_bytes();
    let item_id = items::generate_item_id();
    let published_at = Utc::now().to_rfc3339();
    let content_hash = cordelia_crypto::sha256(&envelope_bytes);
    let cbor = signing::build_item_metadata_envelope(
        &pk, &body.channel_id, &content_hash, false, &item_id,
        ch.key_version, &published_at,
    ).map_err(|e| ApiError::Internal(e.to_string()))?;
    let signature = state.identity.sign(&cbor);

    items::insert_item(&db, &items::NewItem {
        item_id: &item_id,
        channel_id: &body.channel_id,
        author_id: &pk,
        item_type: "psk_envelope",
        published_at: &published_at,
        parent_id: None,
        key_version: ch.key_version,
        content_hash: &content_hash,
        signature: &signature,
        encrypted_blob: &envelope_bytes,
    })?;

    let count = channels::member_count(&db, &body.channel_id)?;

    Ok(HttpResponse::Ok().json(GroupInviteResponse {
        ok: true,
        channel_id: body.channel_id.clone(),
        peer_public_key: body.peer_public_key.clone(),
        member_count: count,
    }))
}

// ── POST /api/v1/channels/group/remove ───────────────────────

pub async fn group_remove(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<GroupRemoveRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    let peer_pk = cordelia_crypto::bech32::decode_public_key(&body.peer_public_key)
        .map_err(|e| ApiError::BadRequest(format!("invalid peer_public_key: {e}")))?;

    let db = state.db.lock().map_err(|e| ApiError::Internal(e.to_string()))?;
    let pk = state.identity.public_key();

    // Verify channel is a group and caller is owner
    let ch = channels::get_by_id(&db, &body.channel_id)?;
    if ch.channel_type != "group" {
        return Err(ApiError::BadRequest("channel is not a group".into()));
    }
    let role = channels::get_member_role(&db, &body.channel_id, &pk)?
        .ok_or_else(|| ApiError::Forbidden("not a member of this group".into()))?;
    if role != "owner" {
        return Err(ApiError::Forbidden("only owner can remove members".into()));
    }

    // Remove member
    channels::remove_member(&db, &body.channel_id, &peer_pk)?;

    // Rotate PSK (excluded member can no longer decrypt new items)
    let new_psk = cordelia_crypto::generate_psk()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let rotated_at = Utc::now().to_rfc3339();
    let _new_file_version = psk::rotate_psk(
        &state.home_dir, &body.channel_id, &new_psk, &rotated_at,
    )?;
    let psk_hash = cordelia_crypto::sha256(&new_psk);
    let new_key_version = channels::increment_key_version(&db, &body.channel_id, &psk_hash)?;

    // Distribute new PSK to remaining members via ECIES envelopes
    let member_keys = channels::list_active_member_keys(&db, &body.channel_id)?;
    for member_pk in &member_keys {
        let member_x25519 = cordelia_crypto::identity::x25519_pub_from_ed25519_pub(member_pk);
        let envelope = cordelia_crypto::ecies::ecies_encrypt(&member_x25519, &new_psk)
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        let envelope_bytes = envelope.to_bytes();
        let item_id = items::generate_item_id();
        let published_at = Utc::now().to_rfc3339();
        let content_hash = cordelia_crypto::sha256(&envelope_bytes);
        let cbor = signing::build_item_metadata_envelope(
            &pk, &body.channel_id, &content_hash, false, &item_id,
            new_key_version, &published_at,
        ).map_err(|e| ApiError::Internal(e.to_string()))?;
        let signature = state.identity.sign(&cbor);

        items::insert_item(&db, &items::NewItem {
            item_id: &item_id,
            channel_id: &body.channel_id,
            author_id: &pk,
            item_type: "psk_envelope",
            published_at: &published_at,
            parent_id: None,
            key_version: new_key_version,
            content_hash: &content_hash,
            signature: &signature,
            encrypted_blob: &envelope_bytes,
        })?;
    }

    Ok(HttpResponse::Ok().json(GroupRemoveResponse {
        ok: true,
        channel_id: body.channel_id.clone(),
        peer_public_key: body.peer_public_key.clone(),
        key_rotated: true,
        new_key_version,
    }))
}

// ── POST /api/v1/channels/list-groups ────────────────────────

pub async fn list_groups(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    let db = state.db.lock().map_err(|e| ApiError::Internal(e.to_string()))?;
    let pk = state.identity.public_key();

    let groups = channels::list_groups_for_entity(&db, &pk)?;
    let mut result = Vec::new();

    for ch in groups {
        let role = channels::get_member_role(&db, &ch.channel_id, &pk)?
            .unwrap_or_default();
        let count = channels::member_count(&db, &ch.channel_id)?;
        let item_count = items::count_for_channel(&db, &ch.channel_id)?;
        let activity = items::last_activity(&db, &ch.channel_id)?;

        result.push(GroupChannel {
            channel_id: ch.channel_id,
            role,
            mode: ch.mode,
            member_count: count,
            item_count,
            last_activity: activity,
            created_at: ch.created_at,
        });
    }

    Ok(HttpResponse::Ok().json(ListGroupsResponse { groups: result }))
}

// ── POST /api/v1/channels/rotate-psk ─────────────────────────

pub async fn rotate_psk_handler(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<RotatePskRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    let db = state.db.lock().map_err(|e| ApiError::Internal(e.to_string()))?;
    let pk = state.identity.public_key();

    let channel_id = channels::resolve(&body.channel)?;

    // Verify ownership
    let role = channels::get_member_role(&db, &channel_id.0, &pk)?
        .ok_or_else(|| ApiError::Forbidden("not a member of this channel".into()))?;
    if role != "owner" {
        return Err(ApiError::Forbidden("only owner can rotate PSK".into()));
    }

    // Generate new PSK
    let new_psk = cordelia_crypto::generate_psk()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let rotated_at = Utc::now().to_rfc3339();
    let _new_file_version = psk::rotate_psk(
        &state.home_dir, &channel_id.0, &new_psk, &rotated_at,
    )?;
    let psk_hash = cordelia_crypto::sha256(&new_psk);
    let new_key_version = channels::increment_key_version(&db, &channel_id.0, &psk_hash)?;

    // Distribute to all active members
    let member_keys = channels::list_active_member_keys(&db, &channel_id.0)?;
    for member_pk in &member_keys {
        let member_x25519 = cordelia_crypto::identity::x25519_pub_from_ed25519_pub(member_pk);
        let envelope = cordelia_crypto::ecies::ecies_encrypt(&member_x25519, &new_psk)
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        let envelope_bytes = envelope.to_bytes();
        let item_id = items::generate_item_id();
        let published_at = Utc::now().to_rfc3339();
        let content_hash = cordelia_crypto::sha256(&envelope_bytes);
        let cbor = signing::build_item_metadata_envelope(
            &pk, &channel_id.0, &content_hash, false, &item_id,
            new_key_version, &published_at,
        ).map_err(|e| ApiError::Internal(e.to_string()))?;
        let signature = state.identity.sign(&cbor);

        items::insert_item(&db, &items::NewItem {
            item_id: &item_id,
            channel_id: &channel_id.0,
            author_id: &pk,
            item_type: "psk_envelope",
            published_at: &published_at,
            parent_id: None,
            key_version: new_key_version,
            content_hash: &content_hash,
            signature: &signature,
            encrypted_blob: &envelope_bytes,
        })?;
    }

    Ok(HttpResponse::Ok().json(RotatePskResponse {
        ok: true,
        channel: body.channel.clone(),
        new_key_version,
    }))
}

// ── POST /api/v1/channels/delete-item ────────────────────────

pub async fn delete_item(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<DeleteItemRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    let db = state.db.lock().map_err(|e| ApiError::Internal(e.to_string()))?;
    let pk = state.identity.public_key();

    let channel_id = channels::resolve(&body.channel)?;

    // Verify membership
    if !channels::is_member(&db, &channel_id.0, &pk)? {
        return Err(ApiError::Forbidden("not a member of this channel".into()));
    }

    let deleted = items::tombstone_item(&db, &body.item_id)?;
    if !deleted {
        return Err(ApiError::NotFound(format!("item '{}' not found", body.item_id)));
    }

    // Remove from search index
    let _ = search::tombstone_search(&db, &body.item_id);

    Ok(HttpResponse::Ok().json(DeleteItemResponse {
        ok: true,
        item_id: body.item_id.clone(),
    }))
}

// ── POST /api/v1/channels/search ──────────────────────────────

pub async fn search_handler(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SearchRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;

    let limit = body.limit.min(100).max(1);

    let db = state.db.lock().map_err(|e| ApiError::Internal(e.to_string()))?;
    let pk = state.identity.public_key();

    // Resolve channel
    let channel_id = channels::resolve(&body.channel)?;

    // Verify membership
    if !channels::is_member(&db, &channel_id.0, &pk)? {
        return Err(ApiError::Forbidden("not a member of this channel".into()));
    }

    // Execute FTS5 search
    let type_refs = body.types.as_deref();
    let hits = search::search_fts(
        &db,
        &channel_id.0,
        &body.query,
        limit,
        type_refs,
        body.since.as_deref(),
    )?;

    // Load PSK for decryption
    let channel_psk = psk::read_psk(&state.home_dir, &channel_id.0)?;

    // Fetch full items for each hit
    let mut results = Vec::with_capacity(hits.len());
    for hit in &hits {
        // Look up the stored item
        let row = db
            .query_row(
                "SELECT item_id, channel_id, author_id, item_type, published_at,
                        is_tombstone, parent_id, key_version, content_hash, signature, encrypted_blob
                 FROM items WHERE item_id = ?1",
                rusqlite::params![hit.item_id],
                |row| {
                    Ok(items::StoredItem {
                        item_id: row.get(0)?,
                        channel_id: row.get(1)?,
                        author_id: row.get(2)?,
                        item_type: row.get(3)?,
                        published_at: row.get(4)?,
                        is_tombstone: row.get::<_, i64>(5)? != 0,
                        parent_id: row.get(6)?,
                        key_version: row.get(7)?,
                        content_hash: row.get(8)?,
                        signature: row.get(9)?,
                        encrypted_blob: row.get(10)?,
                    })
                },
            )
            .ok();

        if let Some(item) = row {
            let (content, metadata) = decrypt_item_content(&channel_psk, &item.encrypted_blob);
            let signature_valid = verify_item_signature(&item);

            let mut author_pk = [0u8; 32];
            if item.author_id.len() == 32 {
                author_pk.copy_from_slice(&item.author_id);
            }
            let author = encode_public_key(&author_pk).unwrap_or_default();

            results.push(SearchHitResponse {
                item_id: item.item_id,
                content,
                metadata,
                item_type: item.item_type,
                parent_id: item.parent_id,
                author,
                published_at: item.published_at,
                signature_valid,
                score: hit.score,
            });
        }
    }

    let total = results.len();

    Ok(HttpResponse::Ok().json(SearchResponse {
        channel: body.channel.clone(),
        results,
        total,
        semantic_available: false, // Phase 2
    }))
}

// ── Internal helpers ───────────────────────────────────────────────

/// Decrypt an item's encrypted_blob and parse the JSON {content, metadata} envelope.
fn decrypt_item_content(
    psk: &[u8; 32],
    encrypted_blob: &[u8],
) -> (serde_json::Value, Option<serde_json::Value>) {
    let plaintext = match cordelia_crypto::item_decrypt(psk, encrypted_blob) {
        Ok(p) => p,
        Err(_) => return (serde_json::Value::Null, None),
    };

    let envelope: serde_json::Value = match serde_json::from_slice(&plaintext) {
        Ok(v) => v,
        Err(_) => return (serde_json::Value::Null, None),
    };

    let content = envelope.get("content").cloned().unwrap_or(serde_json::Value::Null);
    let metadata = envelope.get("metadata").cloned().and_then(|v| {
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    });

    (content, metadata)
}

/// Verify an item's Ed25519 signature over the CBOR metadata envelope.
fn verify_item_signature(item: &items::StoredItem) -> bool {
    if item.author_id.len() != 32 || item.content_hash.len() != 32 || item.signature.len() != 64 {
        return false;
    }

    let mut author = [0u8; 32];
    author.copy_from_slice(&item.author_id);
    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&item.content_hash);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&item.signature);

    let cbor = match signing::build_item_metadata_envelope(
        &author,
        &item.channel_id,
        &content_hash,
        item.is_tombstone,
        &item.item_id,
        item.key_version,
        &item.published_at,
    ) {
        Ok(c) => c,
        Err(_) => return false,
    };

    cordelia_crypto::identity::verify_signature(&author, &cbor, &sig)
}
