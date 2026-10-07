//! The routes behind the commands of a person's devices (decision
//! 2026-10-04 §5 to §8), asked as a command asks them: what each wakes
//! the node for, and what none of them does for a node that no longer
//! runs under the device's key, or for whoever has not the node's token.

use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use actix_web::{App, test, web};
use serde_json::{Value, json};

use cordelia_api::change::prepare_change;
use cordelia_api::person::first_entry;
use cordelia_api::state::AppState;
use cordelia_crypto::addition::SignedAddition;
use cordelia_crypto::bech32::encode_public_key;
use cordelia_crypto::entry::Entry;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::phrase::Phrase;
use cordelia_crypto::statement::SignedStatement;
use cordelia_storage::at_relays as kept_rows;

const TOKEN: &str = "test-token-secret";
const WORDS: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// A node's state, with a database of its own in memory, and its
/// directory, which goes when whoever holds it lets it go. `network` says
/// whether it has a network: a node that has none makes no pass, and
/// nothing waits for one.
fn state_of(network: bool) -> (web::Data<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let push_tx = network.then(|| tokio::sync::mpsc::unbounded_channel().0);
    let state = web::Data::new(AppState {
        db: Mutex::new(cordelia_storage::db::open_in_memory().unwrap()),
        identity: NodeIdentity::generate().unwrap(),
        bearer_token: TOKEN.into(),
        home_dir: dir.path().to_path_buf(),
        started_at: std::time::Instant::now(),
        sync_errors: AtomicU64::new(0),
        peers_hot: AtomicU64::new(0),
        peers_warm: AtomicU64::new(0),
        push_tx,
        announce_tx: None,
        peers: Default::default(),
        relays: Default::default(),
        outbox_refused: Default::default(),
        relist: Default::default(),
        sync_control: Default::default(),
        own_channels: Default::default(),
        held: Default::default(),
        history: Default::default(),
    });
    (state, dir)
}

/// Ask `path` of the node with `body`: the status, and what it answered.
macro_rules! asks {
    ($app:expr, $path:expr, $body:expr) => {{
        let request = test::TestRequest::post()
            .uri($path)
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .set_json($body)
            .to_request();
        let answer = test::call_service(&$app, request).await;
        let status = answer.status().as_u16();
        let said: Value = test::read_body_json(answer).await;
        (status, said)
    }};
}

/// Whether the node was told that something was written, and whether it
/// was asked for a whole pass: each as one word that is kept until the
/// node waits for it. Asking takes the word.
async fn woken(state: &AppState) -> (bool, bool) {
    let wait = Duration::from_millis(100);
    let written = tokio::time::timeout(wait, state.own_channels.wait_written()).await;
    let asked = tokio::time::timeout(wait, state.own_channels.wait_asked()).await;
    (written.is_ok(), asked.is_ok())
}

/// The key of a device that is not this one, as a device's key is
/// written.
fn another_key() -> String {
    encode_public_key(&NodeIdentity::generate().unwrap().public_key()).unwrap()
}

/// Make the phrase of [`WORDS`] on the node, as `cordelia phrase` does:
/// the node is handed the first statement's change entry and the
/// statement key.
macro_rules! makes_the_phrase {
    ($app:expr, $state:expr) => {{
        let phrase = Phrase::parse(WORDS).unwrap();
        let made = first_entry(&phrase, &$state.identity.public_key(), "laptop").unwrap();
        let body = json!({
            "entry": hex::encode(made.entry.to_wire()),
            "statement_key": hex::encode(made.statement_key),
            "from": "no_phrase",
        });
        asks!($app, "/api/v1/phrase/make", body)
    }};
}

/// A key typed at `accept` is kept, and the node is asked for a whole
/// pass at once: it asks its relays for what that key's device hands
/// over in its whole pass, and not when its timer next comes round.
#[actix_web::test]
async fn test_a_typed_key_is_kept_and_the_node_is_asked_for_a_whole_pass() {
    let (state, _dir) = state_of(false);
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;
    assert_eq!(woken(&state).await, (false, false));
    let key = another_key();
    let typed = json!({ "key": key, "row": "no_phrase" });
    let (status, said) = asks!(app, "/api/v1/devices/accept", typed);
    assert_eq!(status, 200, "{said}");
    assert_eq!(said["key"], key.as_str());
    assert_eq!(
        said["until"].as_i64().unwrap() - said["typed_at"].as_i64().unwrap(),
        60 * 60
    );
    // One asking, kept until the node takes it up.
    assert_eq!(woken(&state).await, (false, true));
    assert_eq!(woken(&state).await, (false, false));
    let (_, seen) = asks!(app, "/api/v1/devices/list", json!({}));
    assert_eq!(seen["accepting"][0]["key"], key.as_str());
    assert_eq!(seen["accepting"][0]["asking"], true);
    // A look wakes nothing.
    assert_eq!(woken(&state).await, (false, false));

    // The request says which row of 5.1 the yes was for (decision
    // 2026-10-04 §16). One that does not say is refused, and one whose
    // row the device does not stand in is a conflict: the command asks
    // again. Nothing is kept of either, and the node is not woken.
    let other = another_key();
    let (status, said) = asks!(app, "/api/v1/devices/accept", json!({ "key": other }));
    assert_eq!(status, 400, "{said}");
    let elsewhere = json!({ "key": other, "row": "alone" });
    let (status, said) = asks!(app, "/api/v1/devices/accept", elsewhere);
    assert_eq!(status, 409, "{said}");
    let (_, seen) = asks!(app, "/api/v1/devices/list", json!({}));
    assert_eq!(seen["accepting"].as_array().unwrap().len(), 1, "{seen}");
    assert_eq!(woken(&state).await, (false, false));
}

/// A phrase that is made, a device that is added and a change that is
/// made each wake the node: what was written is sent at once, and the
/// change entry is shown to each relay before anything else. After a
/// record of an addition every channel of the device's own is read
/// again: no place in one is kept.
#[actix_web::test]
async fn test_a_phrase_an_addition_and_a_change_each_wake_the_node() {
    let (state, _dir) = state_of(false);
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;
    let (status, said) = makes_the_phrase!(app, state);
    assert_eq!((status, &said["change"]), (200, &json!(1)), "{said}");
    assert_eq!(woken(&state).await, (true, true));

    // What the device keeps of a relay: a place in a channel.
    let (relay, channel, mark) = ([7u8; 32], [8u8; 32], [9u8; 8]);
    let place = |state: &AppState| {
        let db = state.db.lock().unwrap();
        kept_rows::kept(&db, &relay, &channel).unwrap().place
    };
    kept_rows::keep_place(&state.db.lock().unwrap(), &relay, &channel, &mark, 4).unwrap();
    assert_eq!(place(&state), Some((mark, 4)));
    // What adding would do is asked with nothing written, and wakes
    // nothing.
    let new = another_key();
    let body = json!({ "device": new, "label": "desktop" });
    let (status, would) = asks!(app, "/api/v1/devices/add/look", body.clone());
    assert_eq!((status, &would["would"]), (200, &json!("add")), "{would}");
    assert_eq!(woken(&state).await, (false, false));
    assert_eq!(place(&state), Some((mark, 4)));
    // The request says what the yes was for (decision 2026-10-04 §16).
    // One that does not is refused; and one whose yes was for handing
    // the last change again, where the key would be added, is a
    // conflict. Nothing is written for either, and nothing is woken.
    let (status, said) = asks!(app, "/api/v1/devices/add", body.clone());
    assert_eq!(status, 400, "{said}");
    let mut for_another = body.clone();
    for_another["would"] = "hand_again".into();
    let (status, said) = asks!(app, "/api/v1/devices/add", for_another);
    assert_eq!(status, 409, "{said}");
    assert_eq!(woken(&state).await, (false, false));
    assert_eq!(place(&state), Some((mark, 4)));
    let (_, seen) = asks!(app, "/api/v1/devices/list", json!({}));
    assert!(seen["added"].as_array().unwrap().is_empty(), "{seen}");
    // The device is added: a record is made, the node is told that
    // something was written, and every channel is read again.
    let mut body = body;
    body["would"] = "add".into();
    let (status, added) = asks!(app, "/api/v1/devices/add", body.clone());
    assert_eq!((status, &added["record"]), (200, &json!(true)), "{added}");
    // The key counts now, by that record, and is still added by a
    // record where it is added again: with the yes for that.
    let (status, would) = asks!(app, "/api/v1/devices/add/look", body.clone());
    assert_eq!((status, &would["would"]), (200, &json!("add")), "{would}");
    assert_eq!(woken(&state).await, (true, false));
    assert_eq!(place(&state), None);

    // A change: the node hands what is to be signed over, the record of
    // the device added since among it, and applies what it is handed.
    let (status, handed) = asks!(app, "/api/v1/change/prepare", json!({}));
    assert_eq!(status, 200, "{handed}");
    assert!(handed["could_not_fetch"].as_array().unwrap().is_empty());
    let applied =
        SignedStatement::from_bytes(&hex::decode(handed["statement"].as_str().unwrap()).unwrap())
            .unwrap();
    let records = handed["additions"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    let record =
        SignedAddition::from_bytes(&hex::decode(records[0].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(encode_public_key(&record.addition.device.key).unwrap(), new);
    let held = Entry::from_wire(&hex::decode(handed["entry"].as_str().unwrap()).unwrap())
        .unwrap()
        .check()
        .unwrap();
    let own = state.identity.public_key();
    let mut stay = applied.statement.devices.clone();
    stay.push(record.addition.device.clone());
    let phrase = Phrase::parse(WORDS).unwrap();
    let entry = prepare_change(&applied, &own, stay, &[])
        .unwrap()
        .sign(&phrase, &held, None)
        .unwrap();
    assert_eq!(woken(&state).await, (false, false));
    let body = json!({ "entry": hex::encode(entry.to_wire()), "over": handed["over"] });
    let (status, made) = asks!(app, "/api/v1/change/make", body.clone());
    assert_eq!((status, &made["change"]), (200, &json!(2)), "{made}");
    assert_eq!(woken(&state).await, (true, true));
    // Made again over what the prompt showed: the device keeps another
    // entry now, and nothing is made.
    let (status, _) = asks!(app, "/api/v1/change/make", body);
    assert_eq!(status, 409);
    assert_eq!(woken(&state).await, (false, false));
}

/// Before a change is prepared the node is asked for a whole pass, and
/// what it hands over is handed once a pass that began after that has
/// ended: the device has shown its change entry to each relay, and
/// fetched (decision 2026-10-04 §7.1, step 1).
#[actix_web::test]
async fn test_a_change_is_prepared_after_a_whole_pass_that_the_node_was_asked_for() {
    let (state, _dir) = state_of(true);
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;
    let (status, _) = makes_the_phrase!(app, state);
    assert_eq!(status, 200);
    woken(&state).await;

    // The node, as its loop does it: asked for a whole pass, it makes
    // one, a little later.
    let node = state.clone();
    let passes = tokio::spawn(async move {
        node.own_channels.wait_asked().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let pass = node.own_channels.whole_pass_begins();
        node.own_channels.whole_pass_ended(pass);
    });
    let asked_at = std::time::Instant::now();
    let (status, handed) = asks!(app, "/api/v1/change/prepare", json!({}));
    assert_eq!(status, 200, "{handed}");
    let waited = asked_at.elapsed();
    assert!(waited >= Duration::from_millis(300), "{waited:?}");
    assert!(waited < Duration::from_secs(30), "{waited:?}");
    assert_eq!(state.own_channels.whole_passes(), (1, 1));
    passes.await.unwrap();
    // The pass reached no relay, and that is said: nothing is held up
    // by it.
    let could_not: Vec<&str> = handed["could_not_fetch"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|line| line.as_str())
        .collect();
    assert_eq!(could_not, ["no relay was reached"]);
    assert!(handed["statement"].is_string() && handed["entry"].is_string());

    // Passes that end before every channel was read to its end: the
    // node is asked again, so many times, and then the command is told
    // that not everything was fetched.
    let node = state.clone();
    let passes = tokio::spawn(async move {
        loop {
            node.own_channels.wait_asked().await;
            let pass = node.own_channels.whole_pass_begins();
            node.own_channels.whole_pass_was_short(pass);
            node.own_channels.whole_pass_ended(pass);
        }
    });
    let (status, handed) = asks!(app, "/api/v1/change/prepare", json!({}));
    assert_eq!(status, 200, "{handed}");
    passes.abort();
    let asked = cordelia_core::protocol::CHANGE_FETCH_PASSES as u64;
    assert_eq!(state.own_channels.whole_passes(), (1 + asked, 1 + asked));
    let could_not = handed["could_not_fetch"].to_string();
    assert!(
        could_not.contains("the fetch ended before every channel was read to its end"),
        "{could_not}"
    );
}

/// The routes of a person's commands, each with a body that it reads.
fn routes() -> Vec<(&'static str, Value)> {
    let key = another_key();
    vec![
        ("/api/v1/devices/list", json!({})),
        (
            "/api/v1/devices/clear",
            json!({ "notice": hex::encode([1u8; 32]) }),
        ),
        ("/api/v1/devices/add/look", json!({ "device": key })),
        (
            "/api/v1/devices/add",
            json!({ "device": key, "would": "add" }),
        ),
        (
            "/api/v1/devices/accept",
            json!({ "key": key, "row": "no_phrase" }),
        ),
        ("/api/v1/devices/leave", json!({})),
        ("/api/v1/devices/leave/sent", json!({})),
        ("/api/v1/devices/forget", json!({})),
        (
            "/api/v1/phrase/make",
            json!({ "entry": "00", "statement_key": "00", "from": "no_phrase" }),
        ),
        ("/api/v1/change/prepare", json!({})),
        (
            "/api/v1/change/make",
            json!({ "entry": "00", "over": "00" }),
        ),
    ]
}

/// Once a device was given a new key, the node that still runs under the
/// old one makes nothing for a command: every route says that the node
/// is to be started again, and nothing is written. With the key that the
/// node runs under in its file, or with no file, it is asked as before.
/// And no route answers whoever has not the node's token.
#[actix_web::test]
async fn test_a_node_under_a_key_that_is_the_devices_no_longer_makes_nothing_for_a_command() {
    let (state, dir) = state_of(false);
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;
    let key_file = dir.path().join(cordelia_api::commands::KEY_FILE);

    // Without the token: nothing, whatever the key.
    for (path, body) in routes() {
        let request = test::TestRequest::post()
            .uri(path)
            .set_json(body)
            .to_request();
        let answer = test::call_service(&app, request).await;
        assert_eq!(answer.status().as_u16(), 401, "{path}");
    }

    // The file holds another key than the node runs under.
    std::fs::write(&key_file, NodeIdentity::generate().unwrap().seed()).unwrap();
    for (path, body) in routes() {
        let (status, said) = asks!(app, path, body);
        assert_eq!(status, 409, "{path}: {said}");
        assert!(
            said.to_string().contains("this device was given a new key"),
            "{path}: {said}"
        );
    }
    assert_eq!(woken(&state).await, (false, false));
    let typed: i64 = {
        let db = state.db.lock().unwrap();
        db.query_row("SELECT COUNT(*) FROM person_typed_keys", [], |row| {
            row.get(0)
        })
        .unwrap()
    };
    assert_eq!(typed, 0);

    // The file holds the key that the node runs under: it is asked.
    std::fs::write(&key_file, state.identity.seed()).unwrap();
    let (status, seen) = asks!(app, "/api/v1/devices/list", json!({}));
    assert_eq!(
        (status, &seen["state"]),
        (200, &json!("no_phrase")),
        "{seen}"
    );
    let (status, _) = makes_the_phrase!(app, state);
    assert_eq!(status, 200);
    // And with no file at all, as a node has it that was given its key.
    std::fs::remove_file(&key_file).unwrap();
    let (status, seen) = asks!(app, "/api/v1/devices/list", json!({}));
    assert_eq!((status, &seen["state"]), (200, &json!("applied")), "{seen}");
}

/// Every request that a personal node's API takes with a body, each with
/// one that it reads.
fn requests_of_a_device() -> Vec<(&'static str, Value)> {
    let mut all = routes();
    all.extend([
        ("/api/v1/devices/leave/back", json!({})),
        (
            "/api/v1/channels/publish",
            json!({ "channel": "lab", "key": "notes.md", "content": "a text" }),
        ),
        ("/api/v1/channels/entries", json!({ "channel": "lab" })),
        (
            "/api/v1/channels/delete-key",
            json!({ "channel": "lab", "key": "notes.md" }),
        ),
        ("/api/v1/channels/identity", json!({})),
        ("/api/v1/sync/claude", json!({ "enabled": true })),
        (
            "/api/v1/sync/map",
            json!({ "folder": "/home/sam/notes", "name": "lab" }),
        ),
        ("/api/v1/sync/unmap", json!({ "folder": "/home/sam/notes" })),
        ("/api/v1/sync/status", json!({})),
        ("/api/v1/history/list", json!({})),
        ("/api/v1/history/show", json!({ "id": "00000000000abc" })),
        (
            "/api/v1/history/restore",
            json!({ "ids": ["00000000000abc"] }),
        ),
        ("/api/v1/history/drop", json!({ "all": true })),
    ]);
    all
}

/// Until its first start on this version has succeeded, a node refuses
/// every request that changes anything, with why it is held up, except
/// one that turns sync off; it answers what only reads, and its status
/// says why (decision 2026-10-04 §10.1). Held up no longer, it takes
/// them again.
#[actix_web::test]
async fn test_a_node_that_is_held_up_refuses_what_changes_anything_but_turning_sync_off() {
    use cordelia_api::first_start::{ANSWERED_WHILE_HELD, SYNC_SETTING};
    use cordelia_api::state::Held;
    use cordelia_storage::meta;
    let (state, _dir) = state_of(false);
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_device_routes),
    )
    .await;
    let get = |path: &'static str| {
        test::TestRequest::get()
            .uri(path)
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .to_request()
    };
    // Sync is on, with a stored report and a scope that is on by being
    // absent, as an install from before mappings has it.
    let stored = |key: &str| meta::get(&state.db.lock().unwrap(), key).unwrap();
    {
        let db = state.db.lock().unwrap();
        meta::set(&db, meta::SYNC_CLAUDE_DIR, "/home/sam/.claude").unwrap();
        meta::set(&db, meta::SYNC_CLAUDE_REPORT, "{\"folders\":[]}").unwrap();
    }
    let everything = |state: &AppState| -> Vec<String> {
        let db = state.db.lock().unwrap();
        let mut held: Vec<String> = db
            .prepare("SELECT key || '=' || value FROM node_meta ORDER BY key")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for table in ["person", "person_typed_keys", "entries", "sync_files"] {
            let rows: i64 = db
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            held.push(format!("{table}: {rows}"));
        }
        held
    };

    // What only reads is answered, each by its name: the requests of
    // `cordelia sync status`, `cordelia devices` and `cordelia history`,
    // and the local API's two that read.
    assert_eq!(
        ANSWERED_WHILE_HELD,
        [
            "/api/v1/sync/status",
            "/api/v1/devices/list",
            "/api/v1/history/list",
            "/api/v1/history/show",
            "/api/v1/channels/entries",
            "/api/v1/channels/identity",
        ]
    );

    let why = "the first start on this version is not done: no room for the copy";
    state.held.hold(Held::FirstStart(why.into()));
    let before = everything(&state);
    let generation = state.sync_control.generation();
    let mut refused = Vec::new();
    for (path, body) in requests_of_a_device() {
        let (status, said) = asks!(app, path, body);
        if ANSWERED_WHILE_HELD.contains(&path) {
            assert_ne!(status, 503, "{path}: {said}");
            continue;
        }
        assert_eq!(status, 503, "{path}: {said}");
        assert_eq!(said["error"]["code"], "held_up", "{path}: {said}");
        assert_eq!(said["error"]["message"], why, "{path}: {said}");
        refused.push(path);
    }
    // Each request that changes anything is one of those refused: sync
    // turned on among them, and nothing was written or woken by any.
    assert_eq!(
        refused.len(),
        requests_of_a_device().len() - ANSWERED_WHILE_HELD.len()
    );
    assert!(refused.contains(&SYNC_SETTING));
    assert_eq!(everything(&state), before);
    assert_eq!(state.sync_control.generation(), generation);
    assert_eq!(woken(&state).await, (false, false));

    // What reads is answered, and the status says why.
    for path in ["/api/v1/health", "/api/v1/peers", "/api/v1/metrics"] {
        let answer = test::call_service(&app, get(path)).await;
        assert_eq!(answer.status().as_u16(), 200, "{path}");
    }
    let answer = test::call_service(&app, get("/api/v1/status")).await;
    assert_eq!(answer.status().as_u16(), 200);
    let status: Value = test::read_body_json(answer).await;
    assert_eq!(
        status["held"],
        json!({ "by": "first_start", "why": why }),
        "{status}"
    );
    let (code, sync) = asks!(app, "/api/v1/sync/status", json!({}));
    assert_eq!(
        (code, &sync["held"], &sync["enabled"]),
        (200, &json!(why), &json!(true))
    );
    let (code, seen) = asks!(app, "/api/v1/devices/list", json!({}));
    assert_eq!((code, &seen["state"]), (200, &json!("no_phrase")), "{seen}");

    // Turning sync off is taken: the directory goes, and is kept as the
    // last one. The stored report stays, for the step to read, and the
    // scope that was on by being absent is written down as on.
    let (code, sync) = asks!(app, SYNC_SETTING, json!({ "enabled": false }));
    assert_eq!((code, &sync["enabled"]), (200, &json!(false)), "{sync}");
    assert_eq!(stored(meta::SYNC_CLAUDE_DIR), None);
    assert_eq!(
        stored(meta::SYNC_CLAUDE_LAST_DIR).as_deref(),
        Some("/home/sam/.claude")
    );
    assert_eq!(stored(meta::SYNC_CLAUDE_ALL).as_deref(), Some("on"));
    assert_eq!(
        stored(meta::SYNC_CLAUDE_REPORT).as_deref(),
        Some("{\"folders\":[]}")
    );
    assert!(state.sync_control.generation() > generation);
    // Again, with sync off already: taken, and nothing more is written.
    let off = everything(&state);
    let (code, _) = asks!(app, SYNC_SETTING, json!({ "enabled": false }));
    assert_eq!(code, 200);
    assert_eq!(everything(&state), off);

    // Held up no longer: a request that changes something is taken.
    state.held.release();
    let (code, sync) = asks!(
        app,
        SYNC_SETTING,
        json!({ "enabled": true, "dir": "/home/sam/.claude" })
    );
    assert_eq!((code, &sync["enabled"]), (200, &json!(true)), "{sync}");
    assert_eq!(sync["held"], Value::Null);
    let answer = test::call_service(&app, get("/api/v1/status")).await;
    let status: Value = test::read_body_json(answer).await;
    assert_eq!(status["held"], Value::Null);
}

/// A node whose database is from a later version than its own changes
/// nothing (decision 2026-10-04 §10.1): it refuses every request but
/// those of its status, turning sync off among them, since the setting
/// is in that database; and its status says so.
#[actix_web::test]
async fn test_a_node_with_a_database_from_a_later_version_takes_no_request_but_its_status() {
    use cordelia_api::state::Held;
    let (state, _dir) = state_of(false);
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_device_routes),
    )
    .await;
    let why = "the database is from a later version of Cordelia than this one";
    state.held.hold(Held::LaterDatabase(why.into()));
    let generation = state.sync_control.generation();
    let mut asked = requests_of_a_device();
    asked.push(("/api/v1/sync/claude", json!({ "enabled": false })));
    for (path, body) in asked {
        let (status, said) = asks!(app, path, body);
        assert_eq!(status, 503, "{path}: {said}");
        assert_eq!(said["error"]["message"], why, "{path}: {said}");
    }
    assert_eq!(state.sync_control.generation(), generation);
    assert_eq!(woken(&state).await, (false, false));
    // The first start is not tried on it.
    assert!(!cordelia_api::first_start::take(&state, "0.2.0-test"));
    assert_eq!(state.held.why(), Some(Held::LaterDatabase(why.into())));

    let get = test::TestRequest::get()
        .uri("/api/v1/status")
        .insert_header(("Authorization", format!("Bearer {TOKEN}")))
        .to_request();
    let answer = test::call_service(&app, get).await;
    assert_eq!(answer.status().as_u16(), 200);
    let status: Value = test::read_body_json(answer).await;
    assert_eq!(
        status["held"],
        json!({ "by": "later_database", "why": why }),
        "{status}"
    );
}

/// The routes of a personal node say what a device has now, and nothing
/// of the older kind of channel (decision 2026-10-04 §10): its status,
/// its identity and its metrics count the names it holds, though its
/// database holds a channel of the older kind that it is a member of.
/// The routes of a node that carries that kind count it, as they did.
#[actix_web::test]
async fn test_a_devices_routes_count_nothing_of_the_older_kind() {
    let (state, _dir) = state_of(false);
    {
        let db = state.db.lock().unwrap();
        let own = state.identity.public_key();
        let group = "grp_550e8400-e29b-41d4-a716-446655440000";
        cordelia_storage::channels::ensure_group(&db, group, None, "realtime", &own).unwrap();
        cordelia_storage::channels::add_member(&db, group, &own, "owner").unwrap();
    }
    let get = |path: &'static str| {
        test::TestRequest::get()
            .uri(path)
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .to_request()
    };
    for (device, counted) in [(true, 0), (false, 1)] {
        let routes = match device {
            true => cordelia_api::configure_device_routes,
            false => cordelia_api::configure_routes,
        };
        let app = test::init_service(App::new().app_data(state.clone()).configure(routes)).await;
        let answer = test::call_service(&app, get("/api/v1/status")).await;
        let status: Value = test::read_body_json(answer).await;
        assert_eq!(status["channels_subscribed"], counted, "{device}: {status}");
        let (code, identity) = asks!(app, "/api/v1/channels/identity", json!({}));
        assert_eq!(code, 200, "{device}: {identity}");
        assert_eq!(
            identity["channels_subscribed"], counted,
            "{device}: {identity}"
        );
        let answer = test::call_service(&app, get("/api/v1/metrics")).await;
        assert_eq!(answer.status().as_u16(), 200, "{device}");
        let body = test::read_body(answer).await;
        let metrics = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            metrics.contains(&format!("cordelia_channels_subscribed {counted}\n")),
            "{device}: {metrics}"
        );
        assert_eq!(
            metrics.contains("cordelia_items_total{channel=\"550e8400\"}"),
            !device,
            "{device}: {metrics}"
        );
    }
}
