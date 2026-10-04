//! Integration tests for the Channels API handlers.
//!
//! Spins up an actix-web test server with in-memory DB and tests the full
//! subscribe → publish → listen → list → unsubscribe flow.

use actix_web::{App, test, web};
use serde_json::json;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;

use cordelia_api::state::AppState;
use cordelia_crypto::identity::NodeIdentity;

const TEST_TOKEN: &str = "test-token-secret";

fn test_state() -> web::Data<AppState> {
    let dir = tempfile::tempdir().unwrap();
    let conn = cordelia_storage::db::open_in_memory().unwrap();
    let identity = NodeIdentity::generate().unwrap();

    web::Data::new(AppState {
        db: Mutex::new(conn),
        identity,
        bearer_token: TEST_TOKEN.into(),
        home_dir: dir.keep(),
        started_at: std::time::Instant::now(),
        sync_errors: AtomicU64::new(0),
        peers_hot: AtomicU64::new(0),
        peers_warm: AtomicU64::new(0),
        push_tx: None,
        announce_tx: None,
        peers: Default::default(),
        relays: Default::default(),
        outbox_refused: Default::default(),
        relist: Default::default(),
        sync_control: Default::default(),
        usable_keys: Default::default(),
    })
}

fn auth_header() -> (&'static str, String) {
    ("Authorization", format!("Bearer {TEST_TOKEN}"))
}

#[actix_web::test]
async fn test_identity_endpoint() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/v1/channels/identity")
        .insert_header(auth_header())
        .set_json(json!({}))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body["ed25519_public_key"]
            .as_str()
            .unwrap()
            .starts_with("cordelia_pk1")
    );
    assert!(
        body["x25519_public_key"]
            .as_str()
            .unwrap()
            .starts_with("cordelia_xpk1")
    );
    assert_eq!(body["channels_subscribed"], 0);
}

#[actix_web::test]
async fn test_unauthorized_without_token() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/v1/channels/identity")
        .set_json(json!({}))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_subscribe_creates_channel() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({
            "channel": "research-findings",
            "mode": "realtime",
            "access": "open"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["channel"], "research-findings");
    assert!(body["is_new"].as_bool().unwrap());
    assert_eq!(body["role"], "owner");
    assert_eq!(body["mode"], "realtime");
    assert_eq!(body["access"], "open");
    assert!(body["channel_id"].as_str().unwrap().len() == 64); // hex SHA-256
}

#[actix_web::test]
async fn test_subscribe_idempotent() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // First subscribe
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "engineering"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["is_new"].as_bool().unwrap());

    // Second subscribe: same channel, same user
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "engineering"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(!body["is_new"].as_bool().unwrap());
    assert_eq!(body["role"], "owner");
}

#[actix_web::test]
async fn test_subscribe_invalid_name() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "ab"})) // too short
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_full_pubsub_flow() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // 1. Subscribe
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "test-channel"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    // 2. Publish
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/publish")
        .insert_header(auth_header())
        .set_json(json!({
            "channel": "test-channel",
            "content": {"text": "hello world"},
            "metadata": {"tags": ["test"]}
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let pub_body: serde_json::Value = test::read_body_json(resp).await;
    assert!(pub_body["item_id"].as_str().unwrap().starts_with("ci_"));
    assert!(
        pub_body["author"]
            .as_str()
            .unwrap()
            .starts_with("cordelia_pk1")
    );
    assert_eq!(pub_body["item_type"], "message");

    // 3. Listen
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/listen")
        .insert_header(auth_header())
        .set_json(json!({"channel": "test-channel"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let listen_body: serde_json::Value = test::read_body_json(resp).await;
    let items = listen_body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);

    let item = &items[0];
    assert_eq!(item["content"]["text"], "hello world");
    assert_eq!(item["metadata"]["tags"][0], "test");
    assert_eq!(item["item_type"], "message");
    assert!(item["signature_valid"].as_bool().unwrap());
    assert!(!listen_body["has_more"].as_bool().unwrap());
}

/// A keyed entry written through the API, and a key deleted through it,
/// say nothing of what they were written after: only the sync adapter
/// says that. A device that reads such an entry decides by its revision.
#[actix_web::test]
async fn test_a_keyed_write_through_the_api_says_nothing() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;
    let post = |uri: &str, body: serde_json::Value| {
        test::TestRequest::post()
            .uri(uri)
            .insert_header(auth_header())
            .set_json(body)
            .to_request()
    };
    // A keyed entry needs a group channel.
    let group = post("/api/v1/channels/group", json!({"mode": "realtime"}));
    let made = test::call_service(&app, group).await;
    assert_eq!(made.status(), 200);
    let made: serde_json::Value = test::read_body_json(made).await;
    let channel = made["channel_id"].as_str().unwrap().to_string();
    // Whether the entry is a delete, and what it says.
    let said = || {
        let db = state.db.lock().unwrap();
        let entry = cordelia_api::entries::current_of(&state, &db, &channel, "notes.md");
        let version = entry.unwrap().unwrap().current;
        (version.deleted, version.after)
    };

    let write = post(
        "/api/v1/channels/publish",
        json!({"channel": channel, "key": "notes.md", "content": "a text\n"}),
    );
    let answer = test::call_service(&app, write).await;
    let status = answer.status();
    let body = test::read_body(answer).await;
    assert_eq!(status, 200, "{body:?}");
    assert_eq!(said(), (false, None));

    let delete = post(
        "/api/v1/channels/delete-key",
        json!({"channel": channel, "key": "notes.md"}),
    );
    assert_eq!(test::call_service(&app, delete).await.status(), 200);
    assert_eq!(said(), (true, None));
}

#[actix_web::test]
async fn test_listen_with_cursor() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Subscribe
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "cursor-test"}))
        .to_request();
    test::call_service(&app, req).await;

    // Publish 3 items
    for i in 0..3 {
        let req = test::TestRequest::post()
            .uri("/api/v1/channels/publish")
            .insert_header(auth_header())
            .set_json(json!({"channel": "cursor-test", "content": {"n": i}}))
            .to_request();
        test::call_service(&app, req).await;
    }

    // Listen with limit 2
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/listen")
        .insert_header(auth_header())
        .set_json(json!({"channel": "cursor-test", "limit": 2}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;

    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(body["has_more"].as_bool().unwrap());
    let cursor = body["cursor"].as_str().unwrap();

    // Listen with cursor
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/listen")
        .insert_header(auth_header())
        .set_json(json!({"channel": "cursor-test", "since": cursor}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;

    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert!(!body["has_more"].as_bool().unwrap());
}

#[actix_web::test]
async fn test_list_channels() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Subscribe to two channels
    for name in &["alpha-channel", "beta-channel"] {
        let req = test::TestRequest::post()
            .uri("/api/v1/channels/subscribe")
            .insert_header(auth_header())
            .set_json(json!({"channel": name}))
            .to_request();
        test::call_service(&app, req).await;
    }

    let req = test::TestRequest::post()
        .uri("/api/v1/channels/list")
        .insert_header(auth_header())
        .set_json(json!({}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    let channels = body["channels"].as_array().unwrap();
    assert_eq!(channels.len(), 2);
}

#[actix_web::test]
async fn test_info_existing_channel() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Create channel
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "info-test"}))
        .to_request();
    test::call_service(&app, req).await;

    let req = test::TestRequest::post()
        .uri("/api/v1/channels/info")
        .insert_header(auth_header())
        .set_json(json!({"channel": "info-test"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["exists"].as_bool().unwrap());
    assert_eq!(body["member_count"], 1);
}

#[actix_web::test]
async fn test_info_nonexistent_channel() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/v1/channels/info")
        .insert_header(auth_header())
        .set_json(json!({"channel": "does-not-exist"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(!body["exists"].as_bool().unwrap());
    assert!(body["channel_id"].as_str().unwrap().len() == 64);
}

#[actix_web::test]
async fn test_unsubscribe() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Subscribe
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "leave-test"}))
        .to_request();
    test::call_service(&app, req).await;

    // Unsubscribe
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/unsubscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "leave-test"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["ok"].as_bool().unwrap());

    // Publish should now fail (not a member)
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/publish")
        .insert_header(auth_header())
        .set_json(json!({"channel": "leave-test", "content": "test"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);
}

#[actix_web::test]
async fn test_publish_internal_type_rejected() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Subscribe
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "internal-test"}))
        .to_request();
    test::call_service(&app, req).await;

    // Try to publish with internal type
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/publish")
        .insert_header(auth_header())
        .set_json(json!({
            "channel": "internal-test",
            "content": "test",
            "item_type": "psk_envelope"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

// ── WP4: DM/Group/Rotate/Delete tests ────────────────────────

#[actix_web::test]
async fn test_dm_create_and_list() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Generate a "peer" identity and encode as Bech32
    let peer = NodeIdentity::generate().unwrap();
    let peer_bech32 = cordelia_crypto::bech32::encode_public_key(&peer.public_key()).unwrap();

    // Create DM
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/dm")
        .insert_header(auth_header())
        .set_json(json!({"peer": peer_bech32}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["is_new"].as_bool().unwrap());
    assert!(body["channel_id"].as_str().unwrap().starts_with("dm_"));

    // Create DM again (idempotent)
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/dm")
        .insert_header(auth_header())
        .set_json(json!({"peer": peer_bech32}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(!body["is_new"].as_bool().unwrap());

    // List DMs
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/list-dms")
        .insert_header(auth_header())
        .set_json(json!({}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let dms = body["dms"].as_array().unwrap();
    assert_eq!(dms.len(), 1);
    assert!(dms[0]["channel_id"].as_str().unwrap().starts_with("dm_"));
}

#[actix_web::test]
async fn test_dm_self_rejected() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Get our own public key
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/identity")
        .insert_header(auth_header())
        .set_json(json!({}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let our_pk = body["ed25519_public_key"].as_str().unwrap();

    // Try to DM ourselves
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/dm")
        .insert_header(auth_header())
        .set_json(json!({"peer": our_pk}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_group_lifecycle() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Create group
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/group")
        .insert_header(auth_header())
        .set_json(json!({"mode": "realtime"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let group_id = body["channel_id"].as_str().unwrap().to_string();
    assert!(group_id.starts_with("grp_"));

    // List groups
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/list-groups")
        .insert_header(auth_header())
        .set_json(json!({}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let groups = body["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["role"], "owner");

    // Invite a peer
    let peer = NodeIdentity::generate().unwrap();
    let peer_bech32 = cordelia_crypto::bech32::encode_public_key(&peer.public_key()).unwrap();

    let invite = || {
        test::TestRequest::post()
            .uri("/api/v1/channels/group/invite")
            .insert_header(auth_header())
            .set_json(json!({
                "channel_id": group_id,
                "member": peer_bech32
            }))
            .to_request()
    };
    // T10. A key that is not one of this person's devices is refused: the
    // invitation wraps the channel's key for whoever it names.
    let resp = test::call_service(&app, invite()).await;
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body.to_string().contains("not one of your devices"),
        "{body}"
    );

    // Once the key is one of this person's devices, it can be invited.
    let req = test::TestRequest::post()
        .uri("/api/v1/devices/add")
        .insert_header(auth_header())
        .set_json(json!({ "device": peer_bech32 }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let resp = test::call_service(&app, invite()).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["ok"].as_bool().unwrap());
    assert_eq!(body["member_count"], 2);

    // Remove peer (triggers PSK rotation)
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/group/remove")
        .insert_header(auth_header())
        .set_json(json!({
            "channel_id": group_id,
            "member": peer_bech32
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["ok"].as_bool().unwrap());
    assert!(body["psk_rotated"].as_bool().unwrap());
    assert_eq!(body["new_key_version"], 2);
}

/// T20. The older endpoints seal a channel's key to a member too. A key
/// that is not a usable public key is refused before anything is made for
/// it, and a member of that kind that is already stored is sent nothing.
#[actix_web::test]
async fn test_the_older_endpoints_seal_to_no_key_that_is_not_usable() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;
    let post = |uri: &'static str, body: serde_json::Value| {
        test::TestRequest::post()
            .uri(uri)
            .insert_header(auth_header())
            .set_json(body)
            .to_request()
    };
    // A point of mixed order, and bytes that are not a point.
    let unusable: Vec<[u8; 32]> = [5u8, 2]
        .into_iter()
        .map(|first| {
            let mut key = [0u8; 32];
            key[0] = first;
            key
        })
        .collect();
    let named = |key: &[u8; 32]| cordelia_crypto::bech32::encode_public_key(key).unwrap();

    // A direct channel with such a key is not made.
    for key in &unusable {
        let resp = test::call_service(
            &app,
            post("/api/v1/channels/dm", json!({ "peer": named(key) })),
        )
        .await;
        assert_eq!(resp.status(), 400, "{key:02x?}");
    }
    let resp = test::call_service(&app, post("/api/v1/channels/list-dms", json!({}))).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["dms"].as_array().unwrap().len(), 0, "{body}");

    // A group: such a key is not invited, even where an older version had
    // stored it as one of this person's devices.
    let resp = test::call_service(
        &app,
        post("/api/v1/channels/group", json!({ "mode": "realtime" })),
    )
    .await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let group = body["channel_id"].as_str().unwrap().to_string();
    let real = NodeIdentity::generate().unwrap().public_key();
    let add = post("/api/v1/devices/add", json!({ "device": named(&real) }));
    assert_eq!(test::call_service(&app, add).await.status(), 200);
    {
        let db = state.db.lock().unwrap();
        let personal =
            cordelia_storage::meta::get(&db, cordelia_storage::meta::PERSONAL_CHANNEL_ID)
                .unwrap()
                .unwrap();
        for key in &unusable {
            cordelia_storage::trust::trust(
                &db,
                key,
                cordelia_storage::trust::TrustKind::Device,
                None,
            )
            .unwrap();
            cordelia_storage::channels::add_member(&db, &personal, key, "owner").unwrap();
        }
    }
    for key in &unusable {
        let invite = json!({ "channel_id": group, "member": named(key) });
        let resp = test::call_service(&app, post("/api/v1/channels/group/invite", invite)).await;
        assert_eq!(resp.status(), 400, "{key:02x?}");
    }
    let invite = json!({ "channel_id": group, "member": named(&real) });
    let resp = test::call_service(&app, post("/api/v1/channels/group/invite", invite)).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["member_count"], 2, "{body}");

    // Stored as members of the group, they are sent nothing when its key
    // changes, and are not counted among those who were.
    {
        let db = state.db.lock().unwrap();
        for key in &unusable {
            cordelia_storage::channels::add_member(&db, &group, key, "member").unwrap();
        }
    }
    let resp = test::call_service(
        &app,
        post("/api/v1/channels/rotate-psk", json!({ "channel": group })),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["members_notified"], 2, "{body}");
    let remove = json!({ "channel_id": group, "member": named(&real) });
    let resp = test::call_service(&app, post("/api/v1/channels/group/remove", remove)).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["psk_rotated"].as_bool().unwrap(), "{body}");
}

#[actix_web::test]
async fn test_rotate_psk() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Subscribe to channel (creates PSK)
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "rotate-test"}))
        .to_request();
    test::call_service(&app, req).await;

    // Rotate PSK
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/rotate-psk")
        .insert_header(auth_header())
        .set_json(json!({"channel": "rotate-test"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["ok"].as_bool().unwrap());
    assert_eq!(body["new_key_version"], 2);

    // Rotate again
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/rotate-psk")
        .insert_header(auth_header())
        .set_json(json!({"channel": "rotate-test"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["new_key_version"], 3);
}

#[actix_web::test]
async fn test_delete_item() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Subscribe + publish
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "delete-test"}))
        .to_request();
    test::call_service(&app, req).await;

    let req = test::TestRequest::post()
        .uri("/api/v1/channels/publish")
        .insert_header(auth_header())
        .set_json(json!({"channel": "delete-test", "content": "to be deleted"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let item_id = body["item_id"].as_str().unwrap().to_string();

    // Delete item
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/delete-item")
        .insert_header(auth_header())
        .set_json(json!({"channel": "delete-test", "item_id": item_id}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["ok"].as_bool().unwrap());

    // Listen should be empty (item is tombstoned)
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/listen")
        .insert_header(auth_header())
        .set_json(json!({"channel": "delete-test"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
}

// ── WP8: Search tests ─────────────────────────────────────────

#[actix_web::test]
async fn test_search_basic() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Subscribe + publish some items
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "search-test"}))
        .to_request();
    test::call_service(&app, req).await;

    // Publish item with searchable content
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/publish")
        .insert_header(auth_header())
        .set_json(json!({
            "channel": "search-test",
            "content": {"text": "vector embeddings for retrieval augmented generation"},
            "metadata": {"tags": ["rag", "vectors"]}
        }))
        .to_request();
    test::call_service(&app, req).await;

    // Publish another item
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/publish")
        .insert_header(auth_header())
        .set_json(json!({
            "channel": "search-test",
            "content": {"text": "encryption patterns with AES-256-GCM"}
        }))
        .to_request();
    test::call_service(&app, req).await;

    // Search for "vector"
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/search")
        .insert_header(auth_header())
        .set_json(json!({
            "channel": "search-test",
            "query": "vector"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["semantic_available"], false);
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0]["score"].as_f64().unwrap() > 0.0);
    // Content should be decrypted
    assert!(
        results[0]["content"]["text"]
            .as_str()
            .unwrap()
            .contains("vector")
    );
}

#[actix_web::test]
async fn test_search_empty_query_rejected() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Subscribe
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "search-empty"}))
        .to_request();
    test::call_service(&app, req).await;

    // Search with empty query
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/search")
        .insert_header(auth_header())
        .set_json(json!({
            "channel": "search-empty",
            "query": ""
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_search_deleted_item_excluded() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Subscribe + publish
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "search-delete"}))
        .to_request();
    test::call_service(&app, req).await;

    let req = test::TestRequest::post()
        .uri("/api/v1/channels/publish")
        .insert_header(auth_header())
        .set_json(json!({
            "channel": "search-delete",
            "content": {"text": "ephemeral findable content"}
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let item_id = body["item_id"].as_str().unwrap().to_string();

    // Verify it's searchable
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/search")
        .insert_header(auth_header())
        .set_json(json!({
            "channel": "search-delete",
            "query": "ephemeral"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 1);

    // Delete it
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/delete-item")
        .insert_header(auth_header())
        .set_json(json!({"channel": "search-delete", "item_id": item_id}))
        .to_request();
    test::call_service(&app, req).await;

    // Search again -- should be gone
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/search")
        .insert_header(auth_header())
        .set_json(json!({
            "channel": "search-delete",
            "query": "ephemeral"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 0);
}

#[actix_web::test]
async fn test_publish_not_member() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Publish without subscribing
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/publish")
        .insert_header(auth_header())
        .set_json(json!({"channel": "no-member", "content": "test"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    // Channel doesn't exist -> resolve fails -> 400 (invalid name) or 403
    // Actually resolve will succeed (just computes SHA-256), but is_member will be false
    // and channel doesn't exist so resolve will fail with InvalidChannelName if name is bad,
    // or succeed with a valid channel_id. Since "no-member" is a valid name, resolve succeeds
    // but is_member returns false -> 403
    assert_eq!(resp.status(), 403);
}

// ── Size limit enforcement (parameter-rationale.md §4) ────────────

/// T5-11 (HIGH): Publish rejects items exceeding MAX_ITEM_BYTES (64 KB).
#[actix_web::test]
async fn test_publish_oversized_item_rejected() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Subscribe first
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "size-limit-test"}))
        .to_request();
    test::call_service(&app, req).await;

    // Create content that exceeds 64 KB (65,536 bytes) when serialized.
    // The handler serializes {"content": ..., "metadata": ...} and checks length.
    let oversized_content = "X".repeat(70_000);

    let req = test::TestRequest::post()
        .uri("/api/v1/channels/publish")
        .insert_header(auth_header())
        .set_json(json!({
            "channel": "size-limit-test",
            "content": oversized_content
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        413,
        "oversized item should return 413 Payload Too Large"
    );

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"]["code"], "payload_too_large");
    // What the content may be: the entry size less what sealing adds.
    let limit = (cordelia_core::protocol::MAX_ITEM_BYTES
        - cordelia_core::protocol::ITEM_SEAL_OVERHEAD_BYTES) as u64;
    assert!(body["error"]["used_bytes"].as_u64().unwrap() > limit);
    assert_eq!(body["error"]["quota_bytes"], limit);
}

/// An entry whose type or parent is over the size a field may be is refused
/// with the field named. It was answered as a payload too large, with a
/// count that meant nothing for a field.
#[actix_web::test]
async fn test_publish_with_a_field_over_its_size_names_the_field() {
    use cordelia_core::protocol::{MAX_ITEM_ID_LEN, MAX_ITEM_TYPE_LEN};
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "field-limit-test"}))
        .to_request();
    test::call_service(&app, req).await;

    for (field, len, named) in [
        ("item_type", MAX_ITEM_TYPE_LEN + 1, "type may be at most 32"),
        ("parent_id", MAX_ITEM_ID_LEN + 1, "parent may be at most 64"),
    ] {
        let mut body = json!({"channel": "field-limit-test", "content": "small"});
        body[field] = json!("x".repeat(len));
        let req = test::TestRequest::post()
            .uri("/api/v1/channels/publish")
            .insert_header(auth_header())
            .set_json(body)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400, "{field}");
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body.to_string().contains(named), "{field}: {body}");
    }

    // Each at its largest is taken.
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/publish")
        .insert_header(auth_header())
        .set_json(json!({
            "channel": "field-limit-test",
            "content": "small",
            "item_type": "x".repeat(MAX_ITEM_TYPE_LEN),
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
}

/// T5-12: Publish just under MAX_ITEM_BYTES succeeds.
#[actix_web::test]
async fn test_publish_just_under_size_limit_succeeds() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Subscribe
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "size-ok-test"}))
        .to_request();
    test::call_service(&app, req).await;

    // 60 KB string: safely under 64 KB even with JSON envelope overhead
    let content = "Y".repeat(60_000);

    let req = test::TestRequest::post()
        .uri("/api/v1/channels/publish")
        .insert_header(auth_header())
        .set_json(json!({
            "channel": "size-ok-test",
            "content": content
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        200,
        "item under the 64 KB limit should succeed"
    );
}

// ── WP13: Metrics ─────────────────────────────────────────────────

#[actix_web::test]
async fn test_metrics_endpoint() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Subscribe to a channel first
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/subscribe")
        .insert_header(auth_header())
        .set_json(json!({"channel": "metrics-test", "mode": "realtime", "access": "open"}))
        .to_request();
    test::call_service(&app, req).await;

    // GET /api/v1/metrics
    let req = test::TestRequest::get()
        .uri("/api/v1/metrics")
        .insert_header(auth_header())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body = test::read_body(resp).await;
    let text = std::str::from_utf8(&body).unwrap();

    assert!(text.contains("cordelia_uptime_seconds"));
    assert!(text.contains("cordelia_channels_subscribed 1"));
    assert!(text.contains("cordelia_items_total"));
    assert!(text.contains("cordelia_storage_bytes"));
    assert!(text.contains("cordelia_sync_errors_total 0"));
    assert!(text.contains("cordelia_peers_hot 0"));
    assert!(text.contains("cordelia_peers_warm 0"));
}

#[actix_web::test]
async fn test_metrics_requires_auth() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // No auth header
    let req = test::TestRequest::get().uri("/api/v1/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

/// delete-item acts only on the caller's own items in the channel named:
/// an item ID alone must not let a member hide someone else's item, or an
/// item in another channel.
#[actix_web::test]
async fn test_delete_item_only_own_items_in_named_channel() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    for ch in ["delete-a", "delete-b"] {
        let req = test::TestRequest::post()
            .uri("/api/v1/channels/subscribe")
            .insert_header(auth_header())
            .set_json(json!({ "channel": ch }))
            .to_request();
        test::call_service(&app, req).await;
    }
    let req = test::TestRequest::post()
        .uri("/api/v1/channels/publish")
        .insert_header(auth_header())
        .set_json(json!({"channel": "delete-b", "content": "mine, in b"}))
        .to_request();
    let body: serde_json::Value = test::read_body_json(test::call_service(&app, req).await).await;
    let mine_in_b = body["item_id"].as_str().unwrap().to_string();

    // Someone else's item in channel a (as if received from the network).
    let channel_a = cordelia_storage::channels::resolve("delete-a").unwrap().0;
    {
        let db = state.db.lock().unwrap();
        cordelia_storage::items::insert_item(
            &db,
            &cordelia_storage::items::NewItem::plain(
                "ci_someone_else",
                &channel_a,
                &[0x77; 32],
                "message",
                "2026-09-30T00:00:00Z",
                1,
                &[0x99; 32],
                &[0; 64],
                &[1, 2, 3],
            ),
        )
        .unwrap();
    }

    let delete = |channel: &str, item_id: &str| {
        test::TestRequest::post()
            .uri("/api/v1/channels/delete-item")
            .insert_header(auth_header())
            .set_json(json!({ "channel": channel, "item_id": item_id }))
            .to_request()
    };
    // Another author's item: forbidden.
    let resp = test::call_service(&app, delete("delete-a", "ci_someone_else")).await;
    assert_eq!(resp.status(), 403);
    // My item, but named under the wrong channel: not found.
    let resp = test::call_service(&app, delete("delete-a", &mine_in_b)).await;
    assert_eq!(resp.status(), 404);
    // My item in its own channel: deleted.
    let resp = test::call_service(&app, delete("delete-b", &mine_in_b)).await;
    assert_eq!(resp.status(), 200);
}

// ── Sync settings (decision 2026-09-30 §4.5) ─────────────────────────

/// POST to a sync endpoint; returns the status code and the JSON body (or
/// the error text).
macro_rules! sync_post {
    ($app:expr, $path:expr, $body:expr) => {{
        let req = test::TestRequest::post()
            .uri($path)
            .insert_header(auth_header())
            .set_json($body)
            .to_request();
        let resp = test::call_service($app, req).await;
        let status = resp.status().as_u16();
        let bytes = test::read_body(resp).await;
        let body: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes).into_owned()));
        (status, body)
    }};
}

/// The home directory mappings are checked against: the test runner's.
fn real_home() -> String {
    let home = std::path::PathBuf::from(std::env::var("HOME").unwrap());
    home.canonicalize().unwrap_or(home).display().to_string()
}

#[actix_web::test]
async fn test_sync_turned_on_syncs_nothing_until_mapped() {
    let home = real_home();
    let app_dir = format!("{home}/code/app");
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    // Mapping needs sync to be on.
    let (code, body) = sync_post!(
        &app,
        "/api/v1/sync/map",
        json!({ "folder": app_dir, "name": "app" })
    );
    assert_eq!(code, 400, "{body}");
    assert!(body.to_string().contains("sync is off"), "{body}");

    let (code, body) = sync_post!(
        &app,
        "/api/v1/sync/claude",
        json!({ "enabled": true, "dir": "/srv/claude" })
    );
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["all"], false, "only mapped folders by default");
    assert_eq!(body["mappings"], json!([]));

    let (code, body) = sync_post!(
        &app,
        "/api/v1/sync/map",
        json!({ "folder": app_dir, "name": "github.com/o/app" })
    );
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        body["mappings"],
        json!([{ "folder": app_dir, "name": "github.com/o/app" }])
    );

    // The same again changes nothing; a second name for the folder, or a
    // second folder for the name, is refused.
    let (code, body) = sync_post!(
        &app,
        "/api/v1/sync/map",
        json!({ "folder": format!("{app_dir}/"), "name": "github.com/o/app" })
    );
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["mappings"].as_array().unwrap().len(), 1);
    let other_dir = format!("{home}/code/b");
    for (folder, name) in [(&app_dir, "other"), (&other_dir, "github.com/o/app")] {
        let (code, body) = sync_post!(
            &app,
            "/api/v1/sync/map",
            json!({ "folder": folder, "name": name })
        );
        assert_eq!(code, 400, "{body}");
        assert!(body.to_string().contains("already mapped"), "{body}");
    }

    // A folder outside the home directory is refused.
    let (code, body) = sync_post!(
        &app,
        "/api/v1/sync/map",
        json!({ "folder": "/srv/code/app", "name": "srv-app" })
    );
    assert_eq!(code, 400, "{body}");
    assert!(body.to_string().contains("outside the home"), "{body}");

    // Unmap by name or by folder; unmapping what is not mapped is an error.
    let (code, body) = sync_post!(&app, "/api/v1/sync/unmap", json!({ "folder": "nothing" }));
    assert_eq!(code, 400, "{body}");
    let generation = body["generation"].as_u64();
    let (code, body) = sync_post!(
        &app,
        "/api/v1/sync/unmap",
        json!({ "folder": "github.com/o/app" })
    );
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["mappings"], json!([]));
    // An unmapped folder is excluded, so a device that syncs everything it
    // finds does not pick it up again under another name. Mapping it again
    // ends the exclusion.
    assert_eq!(body["exclude"], json!([app_dir]));
    let (_, body) = sync_post!(
        &app,
        "/api/v1/sync/map",
        json!({ "folder": app_dir, "name": "app" })
    );
    assert_eq!(body["exclude"], json!([]), "{body}");
    let (code, body) = sync_post!(&app, "/api/v1/sync/unmap", json!({ "folder": app_dir }));
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["mappings"], json!([]));
    // Every change moves the generation on, so a caller can tell a report
    // made before its change from one made after.
    assert!(body["generation"].as_u64() > generation, "{body}");

    // Two folders that Claude Code keeps in one cannot both be mapped.
    let (_, _) = sync_post!(
        &app,
        "/api/v1/sync/map",
        json!({ "folder": format!("{home}/code/my-app"), "name": "one" })
    );
    let (code, body) = sync_post!(
        &app,
        "/api/v1/sync/map",
        json!({ "folder": format!("{home}/code/my.app"), "name": "two" })
    );
    assert_eq!(code, 400, "{body}");
    assert!(body.to_string().contains("in one folder"), "{body}");
}

#[actix_web::test]
async fn test_sync_settings_survive_being_turned_on_again() {
    let home = real_home();
    let app_dir = format!("{home}/code/app");
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

    let (code, body) = sync_post!(
        &app,
        "/api/v1/sync/claude",
        json!({
            "enabled": true,
            "dir": "/srv/claude",
            "all": true,
            "home": false,
            "exclude": ["github.com/Client-Co/*", "github.com/o/secret.git"],
        })
    );
    assert_eq!(code, 200, "{body}");
    let (_, _) = sync_post!(
        &app,
        "/api/v1/sync/map",
        json!({ "folder": app_dir, "name": "app" })
    );

    // Turning it on again, with nothing said, keeps every setting.
    let (code, body) = sync_post!(&app, "/api/v1/sync/claude", json!({ "enabled": true }));
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["dir"], "/srv/claude");
    assert_eq!(body["all"], true);
    assert_eq!(body["home"], false);
    assert_eq!(
        body["exclude"],
        json!(["github.com/client-co/*", "github.com/o/secret"])
    );
    assert_eq!(body["mappings"].as_array().unwrap().len(), 1);

    // One setting changes on its own.
    let (_, body) = sync_post!(
        &app,
        "/api/v1/sync/claude",
        json!({ "enabled": true, "all": false })
    );
    assert_eq!(body["all"], false);
    assert_eq!(body["home"], false);
    assert_eq!(body["dir"], "/srv/claude");

    // Off and on again, with nothing said: still the same, the directory
    // included.
    let (_, body) = sync_post!(&app, "/api/v1/sync/claude", json!({ "enabled": false }));
    assert_eq!(body["enabled"], false);
    assert!(body["dir"].is_null(), "{body}");
    let (_, body) = sync_post!(&app, "/api/v1/sync/claude", json!({ "enabled": true }));
    assert_eq!(body["dir"], "/srv/claude", "{body}");
    assert_eq!(body["all"], false);
    assert_eq!(body["home"], false);
    assert_eq!(body["mappings"].as_array().unwrap().len(), 1);

    // Home memory turned off is off however it was on: not found by
    // `all`, and no longer mapped. (The node's own home directory is the
    // only folder that maps as `~`.)
    let (code, body) = sync_post!(
        &app,
        "/api/v1/sync/map",
        json!({ "folder": home, "name": "~", "home": true })
    );
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["mappings"].as_array().unwrap().len(), 2);
    assert_eq!(
        body["home"], true,
        "mapping home memory turns it on: {body}"
    );
    let (code, body) = sync_post!(
        &app,
        "/api/v1/sync/map",
        json!({ "folder": home, "name": "everything" })
    );
    assert_eq!(code, 400, "home memory only when asked for: {body}");
    let (_, body) = sync_post!(
        &app,
        "/api/v1/sync/claude",
        json!({ "enabled": true, "home": false })
    );
    assert_eq!(
        body["mappings"],
        json!([{ "folder": app_dir, "name": "app" }])
    );

    // Reset puts the scope, home and exclude settings back to the
    // defaults. Mappings stay: they are removed one at a time.
    let (_, body) = sync_post!(
        &app,
        "/api/v1/sync/claude",
        json!({ "enabled": true, "all": true })
    );
    assert_eq!(body["all"], true);
    let (_, body) = sync_post!(
        &app,
        "/api/v1/sync/claude",
        json!({ "enabled": true, "dir": "/srv/claude", "reset": true })
    );
    assert_eq!(body["home"], true);
    assert_eq!(body["exclude"], json!([]));
    assert_eq!(body["all"], false);
    assert_eq!(body["mappings"].as_array().unwrap().len(), 1);
    assert_eq!(body["dir"], "/srv/claude");

    // Reset with no directory named goes back to the default one.
    let (_, body) = sync_post!(
        &app,
        "/api/v1/sync/claude",
        json!({ "enabled": true, "reset": true })
    );
    assert_eq!(
        body["dir"],
        format!("{}/.claude", std::env::var("HOME").unwrap())
    );
}

#[actix_web::test]
async fn test_an_install_from_before_mappings_keeps_its_scope() {
    use cordelia_storage::meta;
    let state = test_state();
    let get = |key: &str| {
        let db = state.db.lock().unwrap();
        meta::get(&db, key).unwrap()
    };

    // Sync was never on: nothing to keep.
    cordelia_api::sync::keep_earlier_scope(&state).unwrap();
    assert_eq!(get(meta::SYNC_CLAUDE_ALL), None);

    // On, from before the scope was stored: everything found, as before.
    {
        let db = state.db.lock().unwrap();
        meta::set(&db, meta::SYNC_CLAUDE_DIR, "/home/x/.claude").unwrap();
    }
    cordelia_api::sync::keep_earlier_scope(&state).unwrap();
    assert_eq!(get(meta::SYNC_CLAUDE_ALL).as_deref(), Some("on"));

    // A scope its owner chose is never widened.
    {
        let db = state.db.lock().unwrap();
        meta::set(&db, meta::SYNC_CLAUDE_ALL, "off").unwrap();
    }
    cordelia_api::sync::keep_earlier_scope(&state).unwrap();
    assert_eq!(get(meta::SYNC_CLAUDE_ALL).as_deref(), Some("off"));
}
