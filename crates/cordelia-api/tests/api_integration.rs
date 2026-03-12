//! Integration tests for the Channels API handlers.
//!
//! Spins up an actix-web test server with in-memory DB and tests the full
//! subscribe → publish → listen → list → unsubscribe flow.

use actix_web::{test, web, App};
use serde_json::json;
use std::sync::Mutex;

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
        home_dir: dir.into_path(),
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
    assert!(body["ed25519_public_key"].as_str().unwrap().starts_with("cordelia_pk1"));
    assert!(body["x25519_public_key"].as_str().unwrap().starts_with("cordelia_xpk1"));
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
    assert!(pub_body["author"].as_str().unwrap().starts_with("cordelia_pk1"));
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
