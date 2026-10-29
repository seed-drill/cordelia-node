//! The routes of the shared channels' commands that make, share and take
//! (decision 2026-10-10 §5.6): `/api/v1/shared/new`, `share`, `accept`,
//! `label`, `rename`, `drop` and `list`. What each does is in
//! [`crate::sharing`].
//!
//! - **Each is a POST with a JSON body that refuses a field it does not
//!   know** (`deny_unknown_fields`), behind the node's token
//!   (`auth::check_bearer`, which refuses while the node is held up).
//! - **A route that a command asks a yes for is asked twice.** With `look`,
//!   it says what the yes is for (`asks`), and does nothing. Without it, it
//!   takes `said_yes_to`, the text the person said yes to, works out what it
//!   would do now, and refuses as a conflict, doing nothing, where that text
//!   is now another.
//! - **A refusal of §5.5 is a conflict whose code is its word** (`refused`
//!   where the table gives none) and whose message is its line, filled in:
//!   the command prints the line on standard error and exits 1.
//!
//! The four routes of the messages record take nothing of a shared channel,
//! and none of these writes anywhere but a shared channel, a share pair
//! channel and the device's own list.

use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;
use serde_json::json;

use cordelia_crypto::bech32::encode_public_key;

use crate::error::ApiError;
use crate::sharing::{self, Failed, Out, OwnRelay, Plan};
use crate::state::AppState;

pub(crate) fn db(state: &AppState) -> cordelia_core::lock::TimedGuard<'_, rusqlite::Connection> {
    state.db.lock().unwrap_or_else(|e| e.into_inner())
}

/// The answer of a refusal, or the node's own failure.
pub(crate) fn answer_of(failed: Failed) -> Result<HttpResponse, ApiError> {
    match failed {
        Failed::Refused(refusal) => Ok(HttpResponse::Conflict().json(json!({
            "error": {
                "code": if refusal.word.is_empty() { "refused" } else { refusal.word },
                "message": refusal.line,
            },
        }))),
        Failed::Error(e) => Err(crate::commands::refused(e)),
    }
}

/// What a command says where what it asked a yes for is now another thing.
pub const CHANGED: &str = "What this would do changed while you were answering: nothing was done.";

/// A route asked a yes for: with `look`, what the yes is for; otherwise,
/// where the person said yes to what the plan asks now, `then` it.
pub(crate) fn asked_then<T>(
    state: &AppState,
    look: bool,
    said_yes_to: Option<&str>,
    plan: impl FnOnce(&rusqlite::Connection, &[OwnRelay], i64) -> Out<Plan<T>>,
    then: impl FnOnce(&rusqlite::Connection, &[OwnRelay], &T, i64) -> Out<serde_json::Value>,
) -> Result<HttpResponse, ApiError> {
    let own = sharing::own_relays(state);
    let now = state.sync_control.now();
    let done = {
        let conn = db(state);
        let plan = match plan(&conn, &own, now) {
            Ok(plan) => plan,
            Err(failed) => return answer_of(failed),
        };
        if look {
            return Ok(HttpResponse::Ok().json(json!({
                "asks": plan.asks,
                "this_device": this_device(state)?,
            })));
        }
        if said_yes_to != Some(plan.asks.as_str()) {
            return Ok(HttpResponse::Conflict().json(json!({
                "error": { "code": "changed", "message": CHANGED },
            })));
        }
        then(&conn, &own, &plan.what, now)
    };
    match done {
        Ok(done) => {
            state.own_channels.written();
            Ok(HttpResponse::Ok().json(done))
        }
        Err(failed) => answer_of(failed),
    }
}

fn this_device(state: &AppState) -> Result<String, ApiError> {
    encode_public_key(&state.identity.public_key()).map_err(|e| ApiError::Internal(e.to_string()))
}

// ── POST /api/v1/shared/new ──────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewRequest {
    pub name: String,
    #[serde(default)]
    pub relays: Vec<String>,
    #[serde(default)]
    pub look: bool,
    #[serde(default)]
    pub said_yes_to: Option<String>,
}

/// `cordelia shared new` (§5.1, §5.2).
pub async fn new(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<NewRequest>,
) -> Result<HttpResponse, ApiError> {
    crate::commands::asked(&req, &state)?;
    let identity = &state.identity;
    asked_then(
        &state,
        body.look,
        body.said_yes_to.as_deref(),
        |conn, own, _| sharing::new_plan(conn, own, &body.name, &body.relays),
        |conn, _, new, now| {
            let said = sharing::make_new(conn, identity, new, now)?;
            Ok(json!({ "said": [said] }))
        },
    )
}

// ── POST /api/v1/shared/share ────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareRequest {
    pub name: String,
    pub key: String,
    #[serde(default)]
    pub words: Option<String>,
    #[serde(default)]
    pub look: bool,
    #[serde(default)]
    pub said_yes_to: Option<String>,
}

/// `cordelia share` (§3.1, §5.2).
pub async fn share(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ShareRequest>,
) -> Result<HttpResponse, ApiError> {
    crate::commands::asked(&req, &state)?;
    let identity = &state.identity;
    asked_then(
        &state,
        body.look,
        body.said_yes_to.as_deref(),
        |conn, own, now| {
            sharing::share_plan(
                conn,
                identity,
                own,
                &body.name,
                &body.key,
                body.words.as_deref(),
                now,
            )
        },
        |conn, own, to, now| {
            let said = sharing::make_share(conn, identity, own, to, now)?;
            Ok(json!({ "said": said }))
        },
    )
}

// ── POST /api/v1/shared/accept ───────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptRequest {
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub look: bool,
    #[serde(default)]
    pub said_yes_to: Option<String>,
}

/// `cordelia accept <key> --channel <name>` (§3.2, §5.2): the key is kept
/// with its name for an hour, and the node asks its relays for the share at
/// its whole passes. It shares nothing with `/api/v1/devices/accept`.
pub async fn accept(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<AcceptRequest>,
) -> Result<HttpResponse, ApiError> {
    crate::commands::asked(&req, &state)?;
    let identity = &state.identity;
    let answered = asked_then(
        &state,
        body.look,
        body.said_yes_to.as_deref(),
        |conn, own, now| sharing::accept_plan(conn, identity, own, &body.key, &body.name, now),
        |conn, _, typed, now| {
            let until = sharing::type_for_a_channel(conn, typed, now)?;
            Ok(json!({
                "key": encode_public_key(&typed.key)?,
                "words": sharing::six_words(&typed.key),
                "typed_at": now,
                "until": until,
            }))
        },
    )?;
    if !body.look {
        state.own_channels.ask_whole();
    }
    Ok(answered)
}

// ── POST /api/v1/shared/label ────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelRequest {
    pub key: String,
    /// The label, or none to take it away.
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub look: bool,
    #[serde(default)]
    pub said_yes_to: Option<String>,
}

/// `cordelia label` (§3.4, §5.2). Taking away a label a key does not have
/// does nothing, and says so (`said`, with no `asks`).
pub async fn label(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<LabelRequest>,
) -> Result<HttpResponse, ApiError> {
    crate::commands::asked(&req, &state)?;
    let identity = &state.identity;
    {
        let conn = db(&state);
        let now = state.sync_control.now();
        match sharing::label_plan(&conn, identity, &body.key, body.label.as_deref(), now) {
            Ok(Err(line)) => return Ok(HttpResponse::Ok().json(json!({ "said": [line] }))),
            Ok(Ok(_)) => {}
            Err(failed) => return answer_of(failed),
        }
    }
    asked_then(
        &state,
        body.look,
        body.said_yes_to.as_deref(),
        |conn, _, now| match sharing::label_plan(
            conn,
            identity,
            &body.key,
            body.label.as_deref(),
            now,
        ) {
            Ok(Ok(plan)) => Ok(plan),
            Ok(Err(line)) => Err(Failed::Refused(sharing::Refusal { word: "", line })),
            Err(failed) => Err(failed),
        },
        |conn, _, labelling, now| {
            let said = sharing::make_label(conn, identity, labelling, now)?;
            Ok(json!({ "said": [said] }))
        },
    )
}

// ── POST /api/v1/shared/rename ───────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameRequest {
    pub name: String,
    pub new_name: String,
    #[serde(default)]
    pub words: Option<String>,
}

/// `cordelia shared rename` (§3.4): no yes.
pub async fn rename(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<RenameRequest>,
) -> Result<HttpResponse, ApiError> {
    crate::commands::asked(&req, &state)?;
    let now = state.sync_control.now();
    let done = sharing::rename(
        &db(&state),
        &state.identity,
        &body.name,
        &body.new_name,
        body.words.as_deref(),
        now,
    );
    match done {
        Ok(said) => {
            state.own_channels.written();
            Ok(HttpResponse::Ok().json(json!({ "said": [said] })))
        }
        Err(failed) => answer_of(failed),
    }
}

// ── POST /api/v1/shared/drop ─────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DropRequest {
    pub name: String,
    #[serde(default)]
    pub words: Option<String>,
    #[serde(default)]
    pub look: bool,
    #[serde(default)]
    pub said_yes_to: Option<String>,
}

/// `cordelia shared drop` (§3.4, §5.2).
pub async fn drop(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<DropRequest>,
) -> Result<HttpResponse, ApiError> {
    crate::commands::asked(&req, &state)?;
    let identity = &state.identity;
    asked_then(
        &state,
        body.look,
        body.said_yes_to.as_deref(),
        |conn, _, now| sharing::drop_plan(conn, identity, &body.name, body.words.as_deref(), now),
        |conn, _, channel, now| {
            let said = sharing::make_drop(conn, identity, channel, &body.name, now)?;
            Ok(json!({ "said": [said] }))
        },
    )
}

// ── POST /api/v1/shared/list ─────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListRequest {
    #[serde(default)]
    pub keys: bool,
}

/// `cordelia shared list` (§5.1): only shows.
pub async fn list(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ListRequest>,
) -> Result<HttpResponse, ApiError> {
    crate::commands::asked(&req, &state)?;
    let own = sharing::own_relays(&state);
    let now = state.sync_control.now();
    let mut listed = sharing::list(&db(&state), &state.identity, &own, body.keys, now)
        .map_err(crate::commands::refused)?;
    listed["this_device"] = this_device(&state)?.into();
    Ok(HttpResponse::Ok().json(listed))
}

// ── POST /api/v1/shared/anew ─────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnewRequest {
    pub name: String,
    #[serde(default)]
    pub words: Option<String>,
    #[serde(default)]
    pub relays: Vec<String>,
    /// The keys answered `keep`, each as `cordelia id` writes it; none
    /// before the person has answered.
    #[serde(default)]
    pub keep: Option<Vec<String>>,
    /// The keys that were listed and asked about, in order, each as
    /// `cordelia id` writes it: with `keep`, they must be the keys the
    /// listing asks about now (§7, property 7).
    #[serde(default)]
    pub asked: Vec<String>,
    #[serde(default)]
    pub look: bool,
    #[serde(default)]
    pub said_yes_to: Option<String>,
}

/// `cordelia shared anew` (decision 2026-10-10 §5.1, §7). Asked first with
/// `look` and no `keep`: the listing of every key and the keys asked about,
/// with nothing done. Then with `look` and `keep`: what its yes is for.
/// Then with `keep` and `said_yes_to`.
pub async fn anew(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<AnewRequest>,
) -> Result<HttpResponse, ApiError> {
    crate::commands::asked(&req, &state)?;
    let identity = &state.identity;
    let plan = |conn: &rusqlite::Connection, own: &[OwnRelay], now: i64| {
        crate::shared_anew::anew_plan(
            conn,
            identity,
            own,
            &body.name,
            body.words.as_deref(),
            &body.relays,
            body.keep.as_deref().map(|keep| (keep, &body.asked[..])),
            now,
        )
    };
    if body.keep.is_none() {
        let own = sharing::own_relays(&state);
        let now = state.sync_control.now();
        let conn = db(&state);
        let (listing, _) = match plan(&conn, &own, now) {
            Ok(planned) => planned,
            Err(failed) => return answer_of(failed),
        };
        let mut asked = Vec::new();
        let held = crate::person::held(&conn)
            .map_err(crate::commands::refused)?
            .ok_or_else(|| crate::commands::refused(crate::person::PersonError::FollowsNoPhrase))?;
        for key in &listing.asked {
            asked.push(json!({
                "key": encode_public_key(key).map_err(|e| ApiError::Internal(e.to_string()))?,
                "form": sharing::sender_form(&conn, &held, &identity.public_key(), key)
                    .map_err(crate::commands::refused)?,
            }));
        }
        return Ok(HttpResponse::Ok().json(json!({
            "listing": listing.lines,
            "ask": asked,
            "own_devices": listing.own_devices.len(),
            "this_device": this_device(&state)?,
        })));
    }
    asked_then(
        &state,
        body.look,
        body.said_yes_to.as_deref(),
        |conn, own, now| match plan(conn, own, now)? {
            (_, Some(plan)) => Ok(plan),
            (_, None) => Err(Failed::Refused(sharing::Refusal {
                word: "",
                line: "No key was answered.".into(),
            })),
        },
        |conn, own, of, now| {
            let said = crate::shared_anew::make_anew(conn, identity, own, of, now)?;
            Ok(json!({ "said": said }))
        },
    )
}

// ── POST /api/v1/shared/move ─────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoveRequest {
    pub name: String,
    #[serde(default)]
    pub words: Option<String>,
    /// The new channel's four words, where the channel was made anew twice.
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub look: bool,
    #[serde(default)]
    pub said_yes_to: Option<String>,
}

/// `cordelia shared move` (decision 2026-10-10 §5.1, §7).
pub async fn move_to(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<MoveRequest>,
) -> Result<HttpResponse, ApiError> {
    crate::commands::asked(&req, &state)?;
    let identity = &state.identity;
    asked_then(
        &state,
        body.look,
        body.said_yes_to.as_deref(),
        |conn, own, now| {
            crate::shared_anew::move_plan(
                conn,
                identity,
                own,
                &body.name,
                body.words.as_deref(),
                body.to.as_deref(),
                now,
            )
        },
        |conn, _, to, now| {
            let said = crate::shared_anew::make_move(conn, identity, to, now)?;
            Ok(json!({ "said": said }))
        },
    )
}

// ── POST /api/v1/shared/stay ─────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StayRequest {
    pub name: String,
    #[serde(default)]
    pub words: Option<String>,
    #[serde(default)]
    pub look: bool,
    #[serde(default)]
    pub said_yes_to: Option<String>,
}

/// `cordelia shared stay` (decision 2026-10-10 §5.1; decision 2026-10-24,
/// rule 26). Where nothing pauses the channel it says so, with nothing
/// done (`said`, with no `asks`).
pub async fn stay(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<StayRequest>,
) -> Result<HttpResponse, ApiError> {
    crate::commands::asked(&req, &state)?;
    let identity = &state.identity;
    {
        let conn = db(&state);
        match crate::shared_anew::stay_plan(&conn, identity, &body.name, body.words.as_deref()) {
            Ok(Err(line)) => return Ok(HttpResponse::Ok().json(json!({ "said": [line] }))),
            Ok(Ok(_)) => {}
            Err(failed) => return answer_of(failed),
        }
    }
    asked_then(
        &state,
        body.look,
        body.said_yes_to.as_deref(),
        |conn, _, _| match crate::shared_anew::stay_plan(
            conn,
            identity,
            &body.name,
            body.words.as_deref(),
        ) {
            Ok(Ok(plan)) => Ok(plan),
            Ok(Err(line)) => Err(Failed::Refused(sharing::Refusal { word: "", line })),
            Err(failed) => Err(failed),
        },
        |conn, _, channel, _| {
            let said = crate::shared_anew::make_stay(conn, channel, &body.name)?;
            Ok(json!({ "said": [said] }))
        },
    )
}
