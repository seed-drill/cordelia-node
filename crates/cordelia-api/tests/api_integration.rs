//! Integration tests for the API handlers.
//!
//! Spins up an actix-web test server with in-memory DB and tests a
//! relay's identity, token and metrics, and the sync routes. No node
//! serves the Channels API of the older kind (decision 2026-11-10 (older
//! kind), rule 2).

use actix_web::{App, test, web};
use serde_json::json;
use std::sync::atomic::AtomicU64;

use cordelia_api::state::AppState;
use cordelia_crypto::identity::NodeIdentity;

const TEST_TOKEN: &str = "test-token-secret";

fn test_state() -> web::Data<AppState> {
    let dir = tempfile::tempdir().unwrap();
    let conn = cordelia_storage::db::open_in_memory().unwrap();
    let identity = NodeIdentity::generate().unwrap();

    web::Data::new(AppState {
        load: Default::default(),
        db: cordelia_core::lock::TimedLock::new(conn),
        identity,
        bearer_token: TEST_TOKEN.into(),
        home_dir: dir.keep(),
        started_at: std::time::Instant::now(),
        sync_errors: AtomicU64::new(0),
        peers_hot: AtomicU64::new(0),
        peers_warm: AtomicU64::new(0),
        networked: false,
        peers: Default::default(),
        relays: Default::default(),
        sync_control: Default::default(),
        own_channels: Default::default(),
        held: Default::default(),
        history: Default::default(),
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

// ── Metrics ───────────────────────────────────────────────────────

/// A relay's metrics and status count the channels it holds, and what it
/// stores as a device counts it, the entries of channels from their
/// secrets (decision 2026-11-10 (older kind), rule 3): no count of items
/// by channel, and no item that a relay refused.
#[actix_web::test]
async fn test_metrics_endpoint() {
    let state = test_state();
    // A channel that the relay holds, as its store keeps one.
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO relay_channels (channel_id, held_since, used_at, bytes, mark)
             VALUES (?1, 1, 1, 0, ?2)",
            rusqlite::params![[7u8; 32].as_slice(), [1u8; 8].as_slice()],
        )
        .unwrap();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;

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
    assert!(text.contains("cordelia_channels_subscribed 1\n"), "{text}");
    assert!(!text.contains("cordelia_items_total"), "{text}");
    assert!(text.contains("cordelia_items_stored 0\n"), "{text}");
    assert!(text.contains("cordelia_storage_bytes"));
    assert!(text.contains("cordelia_sync_errors_total 0"));
    assert!(text.contains("cordelia_peers_hot 0"));
    assert!(text.contains("cordelia_peers_warm 0"));

    // GET /api/v1/status
    let req = test::TestRequest::get()
        .uri("/api/v1/status")
        .insert_header(auth_header())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let status: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(status["channels_subscribed"], 1, "{status}");
    assert_eq!(status["outbox_waiting"], 0, "{status}");
    assert!(status.get("outbox_refused").is_none(), "{status}");
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
    // An unmapped folder does not sync, and nothing is written of it to
    // the list of exclusions. Nor does mapping it again write there.
    assert_eq!(body["exclude"], json!([]));
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
    assert_eq!(body["all"], false);
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

    // Home memory turned off is off: the home directory is mapped no
    // longer. (The node's own home directory is the only folder that maps
    // as `~`.)
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

    // A request that asks for everything found to sync is refused, and
    // changes nothing: only mapped folders sync.
    let (code, body) = sync_post!(
        &app,
        "/api/v1/sync/claude",
        json!({ "enabled": true, "all": true })
    );
    assert_eq!(code, 400, "{body}");
    assert!(
        body.to_string().contains("only mapped folders sync"),
        "{body}"
    );

    // Reset puts the Claude Code directory back to its default, and
    // leaves the rest: the list of exclusions that is stored, the switch
    // for home memory, and the mappings, which are removed one at a time.
    let (_, body) = sync_post!(
        &app,
        "/api/v1/sync/claude",
        json!({ "enabled": true, "dir": "/srv/claude", "reset": true })
    );
    assert_eq!(body["home"], false);
    assert_eq!(
        body["exclude"],
        json!(["github.com/client-co/*", "github.com/o/secret"])
    );
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

/// A status says that the scope is off, whatever is stored: only mapped
/// folders sync (decision 2026-10-04 §10.1). With sync on and with it
/// off, and with the key stored as on, as anything else, or not at all.
#[actix_web::test]
async fn test_a_status_says_that_the_scope_is_off_whatever_is_stored() {
    use cordelia_storage::meta;
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;
    for on in [false, true] {
        if on {
            let db = state.db.lock().unwrap();
            meta::set(&db, meta::SYNC_CLAUDE_DIR, "/srv/claude").unwrap();
        }
        for stored in [Some("on"), Some("off"), Some("true"), None] {
            {
                let db = state.db.lock().unwrap();
                match stored {
                    Some(stored) => meta::set(&db, meta::SYNC_CLAUDE_ALL, stored).unwrap(),
                    None => meta::remove(&db, meta::SYNC_CLAUDE_ALL).unwrap(),
                }
            }
            let (code, body) = sync_post!(&app, "/api/v1/sync/status", json!({}));
            assert_eq!(code, 200, "{body}");
            assert_eq!(body["enabled"], on);
            assert_eq!(body["all"], false, "{stored:?}: {body}");
        }
    }
}

/// `map` checks when it is run (decision 2026-10-04 §10.1). Where a
/// folder that the node lists as found, or that a notice names, has the
/// directory that is given, and is another folder than the one `map`
/// would sync, the request is refused with the reason and with what
/// clears it: it stores no mapping and counts no change. For a folder
/// that it would sync, it maps.
///
/// A tree laid out by hand stands in the way only where Claude Code's
/// own folder for the directory is not there: once it is, the same
/// request maps that folder. And a folder that a notice names under
/// another Claude Code directory stands in nobody's way.
#[actix_web::test]
async fn test_map_is_refused_where_it_would_sync_another_folder_than_was_found() {
    use cordelia_storage::meta;
    let home = real_home();
    // The Claude Code directory is the test's own: what the check asks
    // of the disk is there.
    let dir = tempfile::tempdir().unwrap();
    let claude = dir.path().canonicalize().unwrap().join(".claude");
    let claude = claude.display().to_string();
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
        json!({ "enabled": true, "dir": claude })
    );
    assert_eq!(code, 200, "{body}");

    // What a cycle stored of what it found: a tree laid out by hand that
    // records one directory, and Claude Code's own folder for another.
    let by_hand = format!("{claude}/projects/workspace");
    std::fs::create_dir_all(format!("{by_hand}/memory")).unwrap();
    std::fs::write(format!("{by_hand}/memory/kept.md"), "kept by hand\n").unwrap();
    let tree_dir = format!("{home}/code/app");
    let own_dir = format!("{home}/code/lib");
    let folder_of = |dir: &str| {
        let folder = cordelia_api::found::claude_folder(
            std::path::Path::new(&claude),
            std::path::Path::new(dir),
        );
        folder.unwrap().display().to_string()
    };
    let own = folder_of(&own_dir);
    let report = json!({
        "folders": [],
        "unmapped": [
            { "folder": by_hand, "cwd": null, "directory": tree_dir, "name": "github.com/o/app",
              "mappable": false, "why_not": "laid_out_by_hand" },
            { "folder": own, "cwd": own_dir, "name": null, "mappable": true, "needs_name": true },
        ],
    });
    let store_report = || {
        let db = state.db.lock().unwrap();
        meta::set(&db, meta::SYNC_CLAUDE_REPORT, &report.to_string()).unwrap();
    };
    // No report is stored yet: sync was just turned on, and no cycle has
    // run. The node looks at what is found for the directory itself
    // before it answers: the tree's transcript records the directory.
    std::fs::write(
        format!("{by_hand}/scope.jsonl"),
        format!("{{\"cwd\":{tree_dir:?}}}\n"),
    )
    .unwrap();
    let (_, body) = sync_post!(&app, "/api/v1/sync/status", json!({}));
    assert!(body["report"].is_null(), "{body}");
    let (code, body) = sync_post!(
        &app,
        "/api/v1/sync/map",
        json!({ "folder": tree_dir, "name": "github.com/o/app" })
    );
    assert_eq!(code, 400, "{body}");
    let said = body["error"]["message"].as_str().unwrap().to_string();
    assert!(said.contains(&by_hand), "{said}");
    assert!(said.contains("this layout cannot be mapped"), "{said}");
    let (_, body) = sync_post!(&app, "/api/v1/sync/status", json!({}));
    assert_eq!(body["mappings"], json!([]));
    std::fs::remove_file(format!("{by_hand}/scope.jsonl")).unwrap();

    store_report();
    let generation = state.sync_control.generation();

    // The directory that the tree records: `map` would sync Claude
    // Code's own folder for it, which is not there. The memory sits in
    // the tree.
    let own_of_the_tree = folder_of(&tree_dir);
    let map_the_tree = json!({ "folder": tree_dir, "name": "github.com/o/app" });
    let (code, body) = sync_post!(&app, "/api/v1/sync/map", map_the_tree.clone());
    assert_eq!(code, 400, "{body}");
    let said = body["error"]["message"].as_str().unwrap().to_string();
    assert!(said.contains("this layout cannot be mapped"), "{said}");
    assert!(said.contains(&by_hand), "{said}");
    assert!(
        said.contains(&format!("({own_of_the_tree}, which is not there)")),
        "{said}"
    );
    assert!(said.contains("nothing was mapped"), "{said}");
    // What clears it.
    assert!(
        said.contains(&format!(
            "To sync the memory in {by_hand}, move it into {own_of_the_tree}/memory"
        )),
        "{said}"
    );
    assert!(
        said.contains(&format!("start a Claude Code session in {tree_dir} first")),
        "{said}"
    );
    assert_eq!(state.sync_control.generation(), generation);
    let (_, body) = sync_post!(&app, "/api/v1/sync/status", json!({}));
    assert_eq!(body["mappings"], json!([]));
    assert!(!body["report"].is_null(), "the report is as it was: {body}");

    // The folder that it would sync is mapped.
    let (code, body) = sync_post!(
        &app,
        "/api/v1/sync/map",
        json!({ "folder": own_dir, "name": "lib" })
    );
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        body["mappings"],
        json!([{ "folder": own_dir, "name": "lib" }])
    );

    // Claude Code's own folder for the tree's directory is there now: the
    // same request maps that folder, which is what was asked, and the
    // tree stays as it is.
    store_report();
    std::fs::create_dir_all(&own_of_the_tree).unwrap();
    let (code, body) = sync_post!(&app, "/api/v1/sync/map", map_the_tree);
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["mappings"].as_array().unwrap().len(), 2);
    assert!(std::path::Path::new(&format!("{by_hand}/memory")).is_dir());

    // A folder that a notice names, which synced under another Claude
    // Code directory, stands in nobody's way: its directory is mapped,
    // and so is the directory that an earlier record had for it.
    let before = dir.path().canonicalize().unwrap().join(".claude-before");
    let elsewhere = before.join("projects/-somewhere-notes");
    std::fs::create_dir_all(elsewhere.join("memory")).unwrap();
    let (before, elsewhere) = (
        before.display().to_string(),
        elsewhere.display().to_string(),
    );
    let notes = format!("{home}/notes");
    let notice = json!([
        { "at": "2026-10-05T00:00:00Z", "dir": before,
          "folders": [{ "folder": elsewhere, "cwd": format!("{home}/old-notes"), "name": null }] },
        { "at": "2026-10-06T00:00:00Z", "dir": before,
          "folders": [{ "folder": elsewhere, "cwd": notes, "name": null }] },
    ]);
    {
        let db = state.db.lock().unwrap();
        meta::set(&db, meta::SYNC_CLAUDE_NOTICE, &notice.to_string()).unwrap();
    }
    for (folder, name) in [(notes, "notes"), (format!("{home}/old-notes"), "old-notes")] {
        let (code, body) = sync_post!(
            &app,
            "/api/v1/sync/map",
            json!({ "folder": folder, "name": name })
        );
        assert_eq!(code, 200, "{body}");
    }
    let (_, body) = sync_post!(&app, "/api/v1/sync/status", json!({}));
    assert_eq!(body["mappings"].as_array().unwrap().len(), 4);

    // A tree laid out by hand that a notice names, under the directory
    // that is set, with a later record's directory: in the way of that
    // directory, and not of the one its earlier record had.
    let named_tree = format!("{claude}/projects/kept-by-hand");
    std::fs::create_dir_all(format!("{named_tree}/memory")).unwrap();
    let (was, now) = (format!("{home}/was-here"), format!("{home}/is-here"));
    let notice = json!([
        { "at": "2026-10-05T00:00:00Z", "dir": claude,
          "folders": [{ "folder": named_tree, "cwd": was, "name": null }] },
        { "at": "2026-10-06T00:00:00Z", "dir": claude,
          "folders": [{ "folder": named_tree, "cwd": now, "name": null }] },
    ]);
    {
        let db = state.db.lock().unwrap();
        meta::set(&db, meta::SYNC_CLAUDE_NOTICE, &notice.to_string()).unwrap();
    }
    let (code, body) = sync_post!(
        &app,
        "/api/v1/sync/map",
        json!({ "folder": now, "name": "is-here" })
    );
    assert_eq!(code, 400, "{body}");
    assert!(body.to_string().contains(&named_tree), "{body}");
    let (code, body) = sync_post!(
        &app,
        "/api/v1/sync/map",
        json!({ "folder": was, "name": "was-here" })
    );
    assert_eq!(code, 200, "{body}");
}

/// A notice that is stored is carried by the status, with sync on and
/// with it off, and with what `cordelia sync map` would do now for each
/// folder it names (decision 2026-10-04 §10.1). It is taken away by the
/// one request that says a person has seen it, and by nothing else: not
/// by turning sync off or on, not by a mapping, and not by what a client
/// that knows nothing of it sends. That request counts no change of
/// settings, and with no notice stored it does nothing and answers as
/// done.
#[actix_web::test]
async fn test_a_notice_is_carried_until_a_person_says_it_was_seen() {
    use cordelia_storage::meta;
    let home = real_home();
    let claude = format!("{home}/.claude-of-a-test");
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;
    let folder_of = |dir: &str| {
        let claude = std::path::Path::new(&claude);
        let folder = cordelia_api::found::claude_folder(claude, std::path::Path::new(dir));
        folder.unwrap().display().to_string()
    };
    let lib = format!("{home}/code/lib-of-a-test");
    let by_hand = format!("{claude}/projects/workspace");
    let notice = json!([
        { "at": "2026-10-05T00:00:00Z", "dir": claude, "folders": [
            { "folder": folder_of(&lib), "cwd": lib, "name": "github.com/o/lib" },
            { "folder": by_hand, "cwd": format!("{home}/code/app"), "name": "github.com/o/app" },
        ] },
        { "at": "2026-10-06T00:00:00Z", "dir": claude, "folders": null },
    ]);
    {
        let db = state.db.lock().unwrap();
        meta::set(&db, meta::SYNC_CLAUDE_NOTICE, &notice.to_string()).unwrap();
        // Sync is off, and was last on for this directory.
        meta::set(&db, meta::SYNC_CLAUDE_LAST_DIR, &claude).unwrap();
    }

    // With sync off: carried, and asked against the directory that
    // turning sync on would use.
    let (code, body) = sync_post!(&app, "/api/v1/sync/status", json!({}));
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["enabled"], false);
    let shown = &body["notice"];
    assert_eq!(shown["dir"], claude, "{body}");
    assert_eq!(shown["not_known"], true);
    assert_eq!(shown["stopped"], 2);
    assert_eq!(shown["records"].as_array().unwrap().len(), 2);
    assert_eq!(shown["records"][0]["folders"], 2);
    assert!(shown["records"][1]["folders"].is_null());
    // The directory of the first is gone on this machine: no command.
    assert_eq!(shown["folders"][0]["why_not"], "directory_gone", "{body}");
    assert!(shown["folders"][0]["cwd"].is_null());
    assert_eq!(shown["folders"][0]["name"], "github.com/o/lib");
    assert_eq!(shown["folders"][0]["synced_under"], claude);
    assert_eq!(shown["folders"][1]["why_not"], "laid_out_by_hand");

    // Nothing but the one request takes it away: turning sync on, what
    // an earlier client sends with it, a mapping, an unmapping, and
    // turning sync off.
    let stored = || {
        let db = state.db.lock().unwrap();
        meta::get(&db, meta::SYNC_CLAUDE_NOTICE).unwrap()
    };
    let before = stored();
    assert!(before.is_some());
    let other = format!("{home}/code/other-of-a-test");
    for (path, sent) in [
        ("/api/v1/sync/claude", json!({ "enabled": true })),
        (
            "/api/v1/sync/claude",
            json!({ "enabled": true, "all": false }),
        ),
        (
            "/api/v1/sync/claude",
            json!({ "enabled": true, "home": true, "exclude": ["github.com/o/lib"] }),
        ),
        (
            "/api/v1/sync/map",
            json!({ "folder": other, "name": "other" }),
        ),
        ("/api/v1/sync/unmap", json!({ "folder": "other" })),
        ("/api/v1/sync/status", json!({})),
    ] {
        let (code, body) = sync_post!(&app, path, sent);
        assert_eq!(code, 200, "{path}: {body}");
        assert_eq!(stored(), before, "{path}");
        assert_eq!(body["notice"]["stopped"], 2, "{path}: {body}");
        assert_eq!(body["notice"]["dir"], claude, "{path}: {body}");
    }
    // A folder that is mapped since is stopped no longer. (Its directory
    // is gone here, so it is mapped as a person would map it once it is
    // back: by its directory.)
    let (code, body) = sync_post!(
        &app,
        "/api/v1/sync/map",
        json!({ "folder": lib, "name": "github.com/o/lib" })
    );
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["notice"]["stopped"], 1, "{body}");
    assert_eq!(body["notice"]["folders"][0]["mapped"], true, "{body}");
    assert!(body["notice"]["folders"][0]["cwd"].is_null(), "{body}");
    let (code, body) = sync_post!(&app, "/api/v1/sync/claude", json!({ "enabled": false }));
    assert_eq!(code, 200, "{body}");
    assert_eq!(stored(), before);
    assert_eq!(body["notice"]["records"].as_array().unwrap().len(), 2);

    // Seen: it is gone, and no change of settings is counted.
    let generation = state.sync_control.generation();
    let (code, body) = sync_post!(&app, "/api/v1/sync/seen", json!({}));
    assert_eq!(code, 200, "{body}");
    assert!(body.get("notice").is_none(), "{body}");
    assert_eq!(stored(), None);
    assert_eq!(state.sync_control.generation(), generation);
    assert_eq!(body["generation"].as_u64(), Some(generation));
    // With none stored it does nothing, and answers as done.
    let (code, body) = sync_post!(&app, "/api/v1/sync/seen", json!({}));
    assert_eq!(code, 200, "{body}");
    assert!(body.get("notice").is_none(), "{body}");
    assert_eq!(state.sync_control.generation(), generation);
    // It needs the node's token, as every request does.
    let req = test::TestRequest::post()
        .uri("/api/v1/sync/seen")
        .set_json(json!({}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

/// The node's status says for how long no relay has been connected, by
/// its own clock (decision 2026-10-04 §10.1): nothing before the node
/// has looked, nothing while one is connected, and a number of seconds
/// from when it first found none.
#[actix_web::test]
async fn test_the_status_says_for_how_long_no_relay_has_been_connected() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;
    let status = || async {
        let req = test::TestRequest::get()
            .uri("/api/v1/status")
            .insert_header(auth_header())
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        body
    };
    let body = status().await;
    assert!(body.as_object().unwrap().contains_key("no_relay_secs"));
    assert!(body["no_relay_secs"].is_null(), "{body}");

    let now = std::time::Instant::now();
    let earlier = now
        .checked_sub(std::time::Duration::from_secs(400))
        .unwrap();
    state.own_channels.relays_connected(&[], earlier);
    let secs = status().await["no_relay_secs"].as_u64().unwrap();
    assert!((400..460).contains(&secs), "{secs}");
    // The node looks again, and finds none still: the time is counted
    // from when it first found none, and not from its last look.
    state.own_channels.relays_connected(&[], now);
    let secs = status().await["no_relay_secs"].as_u64().unwrap();
    assert!((400..460).contains(&secs), "{secs}");

    state
        .own_channels
        .relays_connected(&["relay.example:9474"], now);
    assert!(status().await["no_relay_secs"].is_null());
    state.own_channels.relays_connected(&[], now);
    let secs = status().await["no_relay_secs"].as_u64().unwrap();
    assert!(secs < 60, "{secs}");
}

/// A sync status says for how long the node has stored no report of a
/// cycle, by its own clock (decision 2026-10-04 §10.1): since the node
/// started, until it stores one, and then since the last it stored. A
/// status says by this that the cycle has stalled.
#[actix_web::test]
async fn test_a_sync_status_says_for_how_long_no_report_was_stored() {
    let state = test_state();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;
    let no_report_secs = || async {
        let req = test::TestRequest::post()
            .uri("/api/v1/sync/status")
            .insert_header(auth_header())
            .set_json(json!({}))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        body["no_report_secs"].as_u64().unwrap()
    };
    // The node has just started.
    let secs = no_report_secs().await;
    assert!(secs < 60, "{secs}");
    // A report was stored some minutes ago, by the node's own clock: a
    // time before the node's start counts from its start.
    let now = std::time::Instant::now();
    let earlier = now
        .checked_sub(std::time::Duration::from_secs(400))
        .unwrap();
    state.sync_control.report_stored(earlier);
    let secs = no_report_secs().await;
    assert!(secs < 60, "{secs}");
    // And one is stored now, after a start that was long ago.
    assert!(state.sync_control.no_report_for(earlier, now).as_secs() >= 400);
    state.sync_control.report_stored(now);
    assert_eq!(state.sync_control.no_report_for(earlier, now).as_secs(), 0);
}

/// Local history over HTTP (decision 2026-09-30 §4.5b): none of its four
/// endpoints answers without the node's token, and a restore or a drop
/// that is refused does nothing. With the token a kept text is listed,
/// shown, put back, and dropped.
#[actix_web::test]
async fn test_history_needs_the_token_and_is_used_with_it() {
    use cordelia_storage::history::{About, Change, Replacement, Store, Whose, kept};
    let state = test_state();
    let store = Store::new(&state.home_dir, 30, 1 << 20).unwrap();
    state.history.open(Some(store.clone()));
    let memory = state.home_dir.join("memory");
    std::fs::create_dir_all(&memory).unwrap();
    std::fs::write(memory.join("notes.md"), "now\n").unwrap();
    let about = About {
        at: String::new(),
        agent: "lab".into(),
        folder: memory.display().to_string(),
        file: "notes.md".into(),
        change: Change::Pulled,
        kept: Some(kept(Whose::Here { agreed: Some(1) }, "before\n")),
        replaced_by: Replacement::Nothing,
        behind: false,
    };
    let pending = store
        .keep(about, Some("before\n"), chrono::Utc::now())
        .unwrap();
    let id = store.settle(pending).unwrap().to_string();
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;
    let asked = [
        ("list", json!({ "of": "lab" })),
        ("show", json!({ "id": id })),
        ("restore", json!({ "ids": [id] })),
        ("drop", json!({ "all": true })),
    ];
    let file = || std::fs::read_to_string(memory.join("notes.md")).unwrap();

    for (what, body) in &asked {
        let req = test::TestRequest::post()
            .uri(&format!("/api/v1/history/{what}"))
            .set_json(body)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401, "{what}");
    }
    assert_eq!(file(), "now\n");
    assert_eq!(store.list().unwrap().records.len(), 1);

    let mut answers = Vec::new();
    for (what, body) in &asked {
        let req = test::TestRequest::post()
            .uri(&format!("/api/v1/history/{what}"))
            .insert_header(auth_header())
            .set_json(body)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200, "{what}");
        let answer: serde_json::Value = test::read_body_json(resp).await;
        answers.push(answer);
    }
    assert_eq!(answers[0]["records"][0]["id"], id.as_str());
    assert_eq!(answers[1]["text"], "before\n");
    assert_eq!(answers[2]["results"][0]["done"], true);
    assert_eq!(file(), "before\n");
    // The record that was listed, and the one of what the restore replaced.
    assert_eq!(answers[3]["removed"], 2);
    assert!(store.list().unwrap().records.is_empty());
}
