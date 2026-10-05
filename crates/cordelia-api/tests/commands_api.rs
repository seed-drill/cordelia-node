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
/// directory. `network` says whether it has a network: a node that has
/// none makes no pass, and nothing waits for one.
fn state_of(network: bool) -> (web::Data<AppState>, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap().keep();
    let push_tx = network.then(|| tokio::sync::mpsc::unbounded_channel().0);
    let state = web::Data::new(AppState {
        db: Mutex::new(cordelia_storage::db::open_in_memory().unwrap()),
        identity: NodeIdentity::generate().unwrap(),
        bearer_token: TOKEN.into(),
        home_dir: dir.clone(),
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
        usable_keys: Default::default(),
        own_channels: Default::default(),
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
    let (state, _) = state_of(false);
    let app = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(cordelia_api::configure_routes),
    )
    .await;
    assert_eq!(woken(&state).await, (false, false));
    let key = another_key();
    let (status, said) = asks!(app, "/api/v1/devices/accept", json!({ "key": key }));
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
}

/// A phrase that is made, a device that is added and a change that is
/// made each wake the node: what was written is sent at once, and the
/// change entry is shown to each relay before anything else. After a
/// record of an addition every channel of the device's own is read
/// again: no place in one is kept.
#[actix_web::test]
async fn test_a_phrase_an_addition_and_a_change_each_wake_the_node() {
    let (state, _) = state_of(false);
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
    // The device is added: a record is made, the node is told that
    // something was written, and every channel is read again.
    let (status, added) = asks!(app, "/api/v1/devices/add", body);
    assert_eq!((status, &added["record"]), (200, &json!(true)), "{added}");
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
    let (state, _) = state_of(true);
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
        ("/api/v1/devices/add", json!({ "device": key })),
        ("/api/v1/devices/accept", json!({ "key": key })),
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
    let key_file = dir.join(cordelia_api::commands::KEY_FILE);

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
