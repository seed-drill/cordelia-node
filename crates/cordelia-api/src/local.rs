//! The local API of a device for the names it holds (decision 2026-10-04
//! §2.3, §16): publishing a value under a name's key, listing what a name
//! holds, and deleting a key.
//!
//! **A publish here goes through the path that the sync adapter's goes
//! through** ([`crate::publish::publish`]), and so does a delete: one
//! path for every entry that a node writes in a name. So an entry that is
//! written through the local API says what it was written after, as the
//! adapter's does: its chain is that of an entry written over the version
//! that the slot held when the request was read. And **the answer says
//! what it was published over**: that version's revision, which of the
//! three its value was, and the entries that the device held of it; or
//! that the slot held no version.
//!
//! A request names a name that this device holds: one that a folder of
//! its own is mapped to (`cordelia sync map`). The channel is the name's,
//! from the person's secret; nothing is created, joined or subscribed to.
//! A device that follows no recovery phrase has no secret, and publishes
//! nothing (§5.2): each of these is refused there, in words that say the
//! way on.
//!
//! A string is published as a text, which is what a memory file holds and
//! what the sync adapter takes for a version of one. Any other JSON is
//! published as bytes that are no text: the adapter takes it for no
//! version of a file, and publishes the file over it where it has one.

use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;
use serde_json::json;

use cordelia_crypto::bech32::encode_public_key;
use cordelia_crypto::entry::Value;
use cordelia_crypto::version::Version;
use cordelia_storage::person::State;

use crate::auth;
use crate::error::ApiError;
use crate::person::PersonError;
use crate::publish::{self, Kind, PlannedAgainst, Published, Write};
use crate::state::AppState;

/// This node's clock, in seconds.
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// A refusal, as the API answers it, in words that say the way on.
fn refused(e: PersonError) -> ApiError {
    match e {
        PersonError::FollowsNoPhrase => ApiError::BadRequest(
            "this device follows no recovery phrase yet, and publishes nothing: memory stays on \
             this machine. Make one here (`cordelia phrase`), or add this device from one that \
             has one."
                .into(),
        ),
        PersonError::Stopped(State::Fork) => ApiError::BadRequest(
            "two changes were made apart, and this device has seen both: it publishes nothing \
             until that is settled with the phrase (`cordelia settle`)."
                .into(),
        ),
        PersonError::Stopped(_) => ApiError::BadRequest(
            "this device has stopped, and publishes nothing: `cordelia devices` says why, and \
             the way on."
                .into(),
        ),
        PersonError::NameNotHeld(name) => ApiError::NotFound(format!(
            "this device does not hold the name {name:?}: a name is held once a folder is \
             mapped to it (`cordelia sync map <folder> {name}`)."
        )),
        PersonError::Derive(_) => {
            ApiError::BadRequest("that is no name in its one spelling.".into())
        }
        PersonError::Entry(why) => ApiError::BadRequest(why.to_string()),
        other => ApiError::Internal(other.to_string()),
    }
}

/// A key as an answer writes it.
fn written(key: &[u8; 32]) -> Result<String, ApiError> {
    encode_public_key(key).map_err(|e| ApiError::Internal(e.to_string()))
}

/// What a value is, in a word.
fn kind_of(kind: Kind) -> &'static str {
    match kind {
        Kind::Text => "text",
        Kind::Delete => "delete",
        Kind::Other => "other",
    }
}

/// What a slot held, as an answer says it: `null` for no version, or the
/// version's revision, which of the three its value was, and each entry
/// that the device held of it, by what the entry is named by.
fn over(planned: &PlannedAgainst) -> serde_json::Value {
    match planned {
        PlannedAgainst::NoVersion => serde_json::Value::Null,
        PlannedAgainst::Version {
            rev, kind, entries, ..
        } => {
            let entries: Vec<String> = entries.iter().map(hex::encode).collect();
            json!({ "rev": rev, "kind": kind_of(*kind), "entries": entries })
        }
    }
}

/// A value as an answer shows it: a text as a string, a delete as `null`,
/// and bytes that are no text as the JSON they are, or as `null` where
/// they are none.
fn shown(value: &Value) -> serde_json::Value {
    match value {
        Value::Text(text) => json!(text),
        Value::Delete => serde_json::Value::Null,
        Value::Other(bytes) => serde_json::from_slice(bytes).unwrap_or(serde_json::Value::Null),
    }
}

/// A version as an answer lists it.
fn listed(version: &Version, beside: usize) -> Result<serde_json::Value, ApiError> {
    let authors: Vec<String> = version
        .entries
        .iter()
        .map(|entry| written(&entry.author))
        .collect::<Result<_, _>>()?;
    Ok(json!({
        "key": version.name,
        "rev": version.rev,
        "kind": kind_of(Kind::of(&version.value)),
        "deleted": version.value == Value::Delete,
        "content": shown(&version.value),
        "authors": authors,
        // How many other versions stand at that revision: they lost the tie.
        "conflicts": beside,
    }))
}

/// Publish `value` under `key` in the name `name`, over whatever the slot
/// holds as this request reads it, and answer with what it was published
/// over. The read and the publish are made under one hold of the
/// database's lock.
fn publish_over(
    state: &AppState,
    name: &str,
    key: &str,
    value: Value,
) -> Result<HttpResponse, ApiError> {
    if !publish::fits(key, &value) {
        return Err(ApiError::BadRequest(
            "the key and what is published under it may together be 60 KB".into(),
        ));
    }
    let (planned, rev, entry) = {
        let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
        let read = publish::read(&db, name, key).map_err(refused)?;
        let planned = PlannedAgainst::what_is_in(&read.slot);
        let write = Write {
            name,
            file: key,
            value,
            planned: planned.clone(),
            merge: None,
        };
        match publish::publish(&db, &state.identity, &write, now()).map_err(refused)? {
            Published::Made(entry) => (planned, entry.rev, hex::encode(entry.id())),
            // Read and published under one hold of the lock: not met.
            Published::Changed => {
                return Err(ApiError::Conflict(
                    "what is under that key changed while this was published: nothing was \
                     written."
                        .into(),
                ));
            }
            Published::OutOfReach => {
                return Err(ApiError::Conflict(
                    "no revision is left under that key until the next change of devices \
                     (`cordelia renew` makes one): nothing was written."
                        .into(),
                ));
            }
        }
    };
    // Something was written in a channel of the device's own: the pass
    // that sends is woken.
    state.own_channels.written();
    Ok(HttpResponse::Ok().json(json!({
        "channel": name,
        "key": key,
        "rev": rev,
        "entry": entry,
        "author": written(&state.identity.public_key())?,
        "over": over(&planned),
    })))
}

// ── GET /api/v1/status ──────────────────────────────────────────────

/// The status of a personal node: what waits to be sent is what waits in
/// a channel of the device's own, and nothing of the older kind of
/// channel, which a personal node carries no longer.
pub async fn status(
    state: web::Data<AppState>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    crate::handlers::status_with(state, req, false).await
}

// ── POST /api/v1/channels/identity, GET /api/v1/metrics ─────────────

/// The identity of a personal node: the channels it counts are the names
/// that it holds, and nothing of the older kind is read.
pub async fn identity(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    crate::handlers::identity_with(req, state, false).await
}

/// The metrics of a personal node: of the names that it holds and the
/// entries of its own channels, and nothing of the older kind.
pub async fn metrics(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    crate::handlers::metrics_with(req, state, false).await
}

// ── POST /api/v1/channels/publish ───────────────────────────────────

#[derive(Deserialize)]
pub struct PublishRequest {
    /// The name, which this device holds.
    pub channel: String,
    /// The key that the value is published under: for a memory file, the
    /// file's name.
    #[serde(default)]
    pub key: Option<String>,
    /// A string is published as a text, and any other JSON as bytes that
    /// are no text.
    pub content: serde_json::Value,
}

/// Publish a value under a key of a name that this device holds (see the
/// module's documentation). A value is published under a key: there is
/// no publishing without one.
pub async fn publish(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<PublishRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    let Some(key) = body.key.as_deref() else {
        return Err(ApiError::BadRequest(
            "a value is published under a key: give one".into(),
        ));
    };
    let value = match &body.content {
        serde_json::Value::String(text) => Value::Text(text.clone()),
        other => Value::Other(
            serde_json::to_vec(other).map_err(|e| ApiError::BadRequest(e.to_string()))?,
        ),
    };
    publish_over(&state, &body.channel, key, value)
}

// ── POST /api/v1/channels/delete-key ────────────────────────────────

#[derive(Deserialize)]
pub struct DeleteKeyRequest {
    pub channel: String,
    pub key: String,
}

/// Delete a key of a name that this device holds: a delete is published
/// over the version that the slot holds, as any value is. A key that
/// holds no version, or a delete already, is not found.
pub async fn delete_key(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<DeleteKeyRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    let live = {
        let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
        let read = publish::read(&db, &body.channel, &body.key).map_err(refused)?;
        read.slot
            .current
            .is_some_and(|version| version.value != Value::Delete)
    };
    if !live {
        return Err(ApiError::NotFound(format!(
            "nothing is under the key {:?}",
            body.key
        )));
    }
    publish_over(&state, &body.channel, &body.key, Value::Delete)
}

// ── POST /api/v1/channels/entries ───────────────────────────────────

#[derive(Deserialize)]
pub struct EntriesRequest {
    pub channel: String,
}

/// What a name that this device holds holds: the current version under
/// each key, in order of key, as the device's own store has it under the
/// statement it has applied. A deleted key is listed as deleted.
pub async fn entries(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<EntriesRequest>,
) -> Result<HttpResponse, ApiError> {
    auth::check_bearer(&req, &state)?;
    let read = {
        let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
        publish::read_name(&db, &body.channel).map_err(refused)?
    };
    let mut entries = Vec::new();
    for slot in &read.slots {
        if let Some(version) = &slot.current {
            entries.push(listed(version, slot.lost.len())?);
        }
    }
    entries.sort_by(|a, b| a["key"].as_str().cmp(&b["key"].as_str()));
    Ok(HttpResponse::Ok().json(json!({ "channel": body.channel, "entries": entries })))
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::body::to_bytes;
    use actix_web::test::TestRequest;
    use cordelia_crypto::phrase::Phrase;

    use crate::person;

    const TOKEN: &str = "t";

    fn node() -> web::Data<AppState> {
        web::Data::new(AppState {
            db: std::sync::Mutex::new(cordelia_storage::db::open_in_memory().unwrap()),
            identity: cordelia_crypto::identity::NodeIdentity::generate().unwrap(),
            bearer_token: TOKEN.into(),
            home_dir: std::env::temp_dir().join("cordelia-local-api-test-no-such-directory"),
            started_at: std::time::Instant::now(),
            sync_errors: Default::default(),
            peers_hot: Default::default(),
            peers_warm: Default::default(),
            push_tx: None,
            announce_tx: None,
            peers: Default::default(),
            relays: Default::default(),
            outbox_refused: Default::default(),
            relist: Default::default(),
            sync_control: Default::default(),
            own_channels: Default::default(),
            held: Default::default(),
            history: Default::default(),
        })
    }

    /// The node makes a phrase and holds the name `team`.
    fn with_phrase(state: &AppState) {
        let db = state.db.lock().unwrap();
        let phrase = Phrase::generate().unwrap();
        person::first_statement(&db, &state.identity, &phrase, "desktop", now()).unwrap();
        person::hold_name(&db, "team", now()).unwrap();
    }

    fn asked() -> HttpRequest {
        TestRequest::default()
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .to_http_request()
    }

    async fn answer(answered: Result<HttpResponse, ApiError>) -> (u16, serde_json::Value) {
        let response = match answered {
            Ok(response) => response,
            Err(e) => actix_web::ResponseError::error_response(&e),
        };
        let status = response.status().as_u16();
        let body = to_bytes(response.into_body()).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap_or_default())
    }

    async fn publishes(
        state: &web::Data<AppState>,
        key: Option<&str>,
        content: serde_json::Value,
    ) -> (u16, serde_json::Value) {
        let body = PublishRequest {
            channel: "team".into(),
            key: key.map(String::from),
            content,
        };
        answer(publish(asked(), state.clone(), web::Json(body)).await).await
    }

    async fn lists(state: &web::Data<AppState>) -> (u16, serde_json::Value) {
        let body = EntriesRequest {
            channel: "team".into(),
        };
        answer(entries(asked(), state.clone(), web::Json(body)).await).await
    }

    async fn deletes(state: &web::Data<AppState>, key: &str) -> (u16, serde_json::Value) {
        let body = DeleteKeyRequest {
            channel: "team".into(),
            key: key.into(),
        };
        answer(delete_key(asked(), state.clone(), web::Json(body)).await).await
    }

    /// The chain of this node's own entry under `key`.
    fn chain(state: &AppState, key: &str) -> Vec<cordelia_crypto::entry::Link> {
        let db = state.db.lock().unwrap();
        let slot = publish::read(&db, "team", key).unwrap().slot;
        let current = slot.current.unwrap();
        current.entries[0].chain.clone().unwrap()
    }

    /// The local API's publish goes through the path that the adapter's
    /// goes through, and says what it was published over (decision
    /// 2026-10-04 §16): the first entry under a key is written over no
    /// version and has an empty chain; the next is written over the first,
    /// says so in its answer, and has that version's link first.
    #[actix_web::test]
    async fn test_a_publish_goes_through_the_one_path_and_says_what_it_was_published_over() {
        let state = node();
        with_phrase(&state);
        // Whether the pass that sends was woken since this was last asked.
        let woken = || async {
            let word = state.own_channels.wait_written();
            tokio::time::timeout(std::time::Duration::from_millis(50), word)
                .await
                .is_ok()
        };
        assert!(!woken().await);

        let (status, first) = publishes(&state, Some("notes.md"), json!("one\n")).await;
        assert_eq!(status, 200, "{first}");
        // Something was written in a channel of the device's own: the
        // pass that sends is woken, once.
        assert!(woken().await);
        assert!(!woken().await);
        assert_eq!(first["rev"], 1);
        assert_eq!(first["over"], serde_json::Value::Null);
        assert!(chain(&state, "notes.md").is_empty());

        let (status, second) = publishes(&state, Some("notes.md"), json!("two\n")).await;
        assert_eq!(status, 200, "{second}");
        assert_eq!(second["rev"], 2);
        assert_eq!(second["over"]["rev"], 1);
        assert_eq!(second["over"]["kind"], "text");
        assert_eq!(second["over"]["entries"], json!([first["entry"]]));
        // Its chain is that of an entry written over the first: the first
        // text's hash, and the key that signed it.
        let link = &chain(&state, "notes.md")[0];
        let hash = cordelia_crypto::sha256(b"one\n");
        assert_eq!(link.hash[..], hash[..16]);
        assert_eq!(link.signer[..], state.identity.public_key()[..16]);

        // What is no string is published as bytes that are no text, over
        // the text, and says that.
        let (status, third) = publishes(&state, Some("notes.md"), json!({ "a": 1 })).await;
        assert_eq!((status, &third["over"]["rev"]), (200, &json!(2)), "{third}");
        let (_, held) = lists(&state).await;
        assert_eq!(held["entries"][0]["kind"], "other");
        assert_eq!(held["entries"][0]["content"], json!({ "a": 1 }));
        assert_eq!(held["entries"][0]["rev"], 3);
    }

    /// A delete is published as any value is, over the version it found,
    /// and a key that holds nothing live is not found.
    #[actix_web::test]
    async fn test_a_delete_is_published_over_the_version_it_found() {
        let state = node();
        with_phrase(&state);
        assert_eq!(deletes(&state, "notes.md").await.0, 404);
        publishes(&state, Some("notes.md"), json!("one\n")).await;

        let (status, deleted) = deletes(&state, "notes.md").await;
        assert_eq!(status, 200, "{deleted}");
        assert_eq!(
            (&deleted["rev"], &deleted["over"]["rev"]),
            (&json!(2), &json!(1))
        );
        let (_, held) = lists(&state).await;
        assert_eq!(held["entries"][0]["deleted"], true);
        assert_eq!(held["entries"][0]["content"], serde_json::Value::Null);
        // Deleted already: nothing live is under it.
        assert_eq!(deletes(&state, "notes.md").await.0, 404);
    }

    /// What a personal node says it has is what a device has now: the
    /// names that it holds, and the entries of its own channels (decision
    /// 2026-10-04 §10). Its status, its identity and its metrics read
    /// nothing of the older kind of channel, whatever its database holds
    /// of one, and write nothing.
    #[actix_web::test]
    async fn test_a_devices_status_identity_and_metrics_count_nothing_of_the_older_kind() {
        let state = node();
        // What an earlier version left: a channel of the older kind that
        // this device is a member of, with an item in it.
        let own = state.identity.public_key();
        {
            use cordelia_storage::{channels, items};
            let db = state.db.lock().unwrap();
            let group = "grp_550e8400-e29b-41d4-a716-446655440000";
            channels::ensure_group(&db, group, None, "realtime", &own).unwrap();
            channels::add_member(&db, group, &own, "owner").unwrap();
            let item = items::NewItem {
                item_id: "ci_01JARV8XMHW8G9QZP0000000AA",
                channel_id: group,
                author_id: &own,
                item_type: "memory",
                published_at: "2026-10-01T00:00:00Z",
                parent_id: None,
                key_version: 1,
                content_hash: &[1u8; 32],
                signature: &[7u8; 64],
                encrypted_blob: b"what an earlier version sealed",
                is_tombstone: false,
                slot: None,
                rev: None,
            };
            assert!(items::insert_item(&db, &item).unwrap());
            assert_eq!(channels::list_for_entity(&db, &own).unwrap().len(), 1);
        }
        let everything = |state: &AppState| -> Vec<i64> {
            let db = state.db.lock().unwrap();
            [
                "channels",
                "channel_members",
                "items",
                "node_meta",
                "entries",
            ]
            .iter()
            .map(|table| {
                db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap()
            })
            .collect()
        };
        let says = |state: &web::Data<AppState>| {
            let state = state.clone();
            async move {
                let (_, of_status) = answer(status(state.clone(), asked()).await).await;
                let (_, of_identity) = answer(identity(asked(), state.clone()).await).await;
                let response = metrics(asked(), state.clone()).await.unwrap();
                let body = to_bytes(response.into_body()).await.unwrap();
                let of_metrics = String::from_utf8(body.to_vec()).unwrap();
                (of_status, of_identity, of_metrics)
            }
        };

        // A device that holds no name has none, and stores nothing.
        let before = everything(&state);
        let (of_status, of_identity, of_metrics) = says(&state).await;
        assert_eq!(of_status["channels_subscribed"], 0, "{of_status}");
        assert_eq!(of_status["outbox_waiting"], 0, "{of_status}");
        assert_eq!(of_identity["channels_subscribed"], 0, "{of_identity}");
        assert!(
            of_metrics.contains("cordelia_channels_subscribed 0\n"),
            "{of_metrics}"
        );
        assert!(
            of_metrics.contains("cordelia_items_stored 0\n"),
            "{of_metrics}"
        );
        assert!(
            !of_metrics.contains("cordelia_items_total{"),
            "{of_metrics}"
        );
        assert_eq!(everything(&state), before);

        // It holds a name, and publishes under it: that is what it has.
        with_phrase(&state);
        assert_eq!(
            publishes(&state, Some("notes.md"), json!("one\n")).await.0,
            200
        );
        let before = everything(&state);
        let (of_status, of_identity, of_metrics) = says(&state).await;
        assert_eq!(of_status["channels_subscribed"], 1, "{of_status}");
        assert_eq!(of_identity["channels_subscribed"], 1, "{of_identity}");
        assert!(
            of_metrics.contains("cordelia_channels_subscribed 1\n"),
            "{of_metrics}"
        );
        let stored: i64 = {
            let db = state.db.lock().unwrap();
            db.query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
                .unwrap()
        };
        assert!(stored >= 1);
        assert!(
            of_metrics.contains(&format!("cordelia_items_stored {stored}\n")),
            "{of_metrics}"
        );
        // Its own channels in which it stored something today: the
        // name's, and those of what it holds of its person.
        let active: i64 = {
            let db = state.db.lock().unwrap();
            db.query_row(
                "SELECT COUNT(DISTINCT channel_id) FROM entries",
                [],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert!(active >= 1);
        assert!(
            of_metrics.contains(&format!(
                "cordelia_channels_active{{window=\"1d\"}} {active}\n"
            )),
            "{of_metrics}"
        );
        assert_eq!(everything(&state), before);

        // A node that carries the older kind counts the channels of that
        // kind, as it did.
        let (_, older) = answer(crate::handlers::identity(asked(), state.clone()).await).await;
        assert_eq!(older["channels_subscribed"], 1, "{older}");
        let response = crate::handlers::metrics(asked(), state.clone())
            .await
            .unwrap();
        let body = to_bytes(response.into_body()).await.unwrap();
        let older = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            older.contains("cordelia_items_total{channel=\"550e8400\"} 1\n"),
            "{older}"
        );
        assert!(older.contains("cordelia_items_stored 1\n"), "{older}");
    }

    /// What is refused, with nothing written: a device that follows no
    /// phrase publishes nothing; a name it does not hold; no key; and a
    /// key and a value over their bound together, at the bound's edge.
    #[actix_web::test]
    async fn test_what_the_local_api_refuses_to_publish() {
        let state = node();
        let (status, said) = publishes(&state, Some("notes.md"), json!("one\n")).await;
        assert_eq!(status, 400, "{said}");
        assert!(
            said["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("follows no recovery phrase yet")),
            "{said}"
        );
        assert_eq!(lists(&state).await.0, 400);

        with_phrase(&state);
        assert_eq!(publishes(&state, None, json!("one\n")).await.0, 400);
        let other = PublishRequest {
            channel: "another".into(),
            key: Some("notes.md".into()),
            content: json!("one\n"),
        };
        let refused = answer(publish(asked(), state.clone(), web::Json(other)).await).await;
        assert_eq!(refused.0, 404, "{}", refused.1);

        // The bound on a key and its text together (decision 2026-10-04
        // §2.3): exactly at it is published, and one byte more is not.
        use cordelia_core::protocol::MAX_ENTRY_NAME_AND_VALUE_BYTES;
        let key = "notes.md";
        let most = "x".repeat(MAX_ENTRY_NAME_AND_VALUE_BYTES - key.len());
        assert_eq!(publishes(&state, Some(key), json!(most)).await.0, 200);
        let over = format!("{most}x");
        let (status, said) = publishes(&state, Some("other.md"), json!(over)).await;
        assert_eq!(status, 400, "{said}");
        // It is refused for the bound, in the local API's own words,
        // before anything is read or sealed.
        assert!(
            said["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("may together be 60 KB")),
            "{said}"
        );
        let (_, held) = lists(&state).await;
        assert_eq!(held["entries"].as_array().map(Vec::len), Some(1));
    }
}
