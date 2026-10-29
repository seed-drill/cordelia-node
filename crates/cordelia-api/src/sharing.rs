//! Making, sharing and taking a shared channel (decision 2026-10-10 §3.1,
//! §3.2, §3.4, §5.1 to §5.5, §8.1, §8.2): what `cordelia shared new`,
//! `share`, `accept --channel`, `label`, `shared rename`, `shared drop` and
//! `shared list` do on the node, behind the routes of
//! [`crate::sharing_routes`].
//!
//! - **Every check is made here, on the node, and every text a person reads
//!   before a yes is made here too** ([`Plan::asks`]): a command shows the
//!   text the node gives, and hands it back with its yes; the node makes the
//!   plan again, and refuses where its text is now another (5.6).
//! - **A relay is the configuration's, by key** (§8.1, §8.2): a card's relay
//!   is one of the device's own where the configuration knows a relay by
//!   that key ([`OwnRelay`]), and is shown by the configuration's address
//!   and the four words of its key. A card holds no text another chose.
//! - **A share** (§3.1) is one entry in the share pair channel of this
//!   device and the taker's key, kept for two hours ([`drop_old_shares`]),
//!   one waiting for a key at a time, eight at most.
//! - **A key typed for a channel** (§3.2) is kept an hour with the name it
//!   files under; the pass reads its share pair channel at each of the
//!   device's own relays, gives each entry to the judge
//!   ([`crate::shared::accept_typed`]), and the one share it finds to
//!   [`take_share`], which takes it only where rules 9 to 11 hold.
//! - **The empty anew record** (§6.1, §7): each device writes it when it
//!   comes to hold a channel ([`write_empty_anew_records`]).

use rusqlite::Connection;

use cordelia_core::CordeliaError;
use cordelia_core::protocol::{
    HAND_OVER_KEPT_SECS, MAX_TYPED_KEYS, PAIR_KEY_TYPED_SECS, SHARED_KEY_WORDS_SHOWN,
    SHARED_LABEL_MAX_BYTES, SHARED_MAX_CHANNELS, SHARED_MAX_KEYS, SHARED_MAX_RELAYS,
    TYPED_KEY_KEPT_SECS,
};
use cordelia_crypto::acts::{Came, Filing, Label};
use cordelia_crypto::bech32::{decode_public_key, encode_public_key};
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Entry, Inside, Value};
use cordelia_crypto::fingerprint;
use cordelia_crypto::identity::{NodeIdentity, is_usable_public_key};
use cordelia_crypto::share::{Card, Relays, Share, share_name};
use cordelia_crypto::shared::{Anew, anew_name};
use cordelia_crypto::slots::slot_id;
use cordelia_storage::entries;
use cordelia_storage::shared as kept;
use cordelia_storage::shared_sharing::{self as rows, ShareRow, TypedForChannel};

use crate::lists::{self, Do, Done, Part, Refused};
use crate::person::{Held, PersonError, held, in_one};
use crate::shared_pass::{NotUsable, may_open, share_pair};

// ── Relays ───────────────────────────────────────────────────────────

/// A relay of the device's configuration that it knows by its key: the
/// configuration's address for it (`host:port`), and the key (§8.2). Only
/// such a relay is one of a card's, or one a card may name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnRelay {
    pub name: String,
    pub key: [u8; 32],
}

/// The relays the node is set up with that it knows by their keys, in the
/// order of the configuration, each key once: configured with its key, or a
/// default relay whose key is compiled in (`bootstrap::default_relay_key`).
///
/// What the node last said it is set up with is read first, and the relays
/// the dial loop last listed after it: either may not have been said yet
/// just after a start.
pub fn own_relays(state: &crate::state::AppState) -> Vec<OwnRelay> {
    let mut own: Vec<OwnRelay> = Vec::new();
    let mut keep = |name: &str, key: [u8; 32]| {
        if !own.iter().any(|one| one.key == key) {
            own.push(OwnRelay {
                name: name.to_string(),
                key,
            });
        }
    };
    for relay in state.own_channels.relays_set_up_as() {
        if let Some(key) = relay.key {
            keep(&relay.name, key);
        }
    }
    let known = state.relays.read().unwrap_or_else(|e| e.into_inner());
    for relay in known.iter() {
        if let Some(key) = relay
            .key
            .as_deref()
            .and_then(|key| decode_public_key(key).ok())
        {
            keep(&relay.host, key);
        }
    }
    own
}

/// A relay of a card, as a person reads it (§5.2): `<host>:<port> (<four
/// words>)`, the address that the configuration gives the relay of that
/// key; or its words alone, where the configuration knows no relay by it.
pub fn relay_shown(relays: &[OwnRelay], key: &[u8; 32]) -> String {
    match relays.iter().find(|relay| relay.key == *key) {
        Some(relay) => format!("{} ({})", relay.name, fingerprint::shown(key)),
        None => format!("({})", fingerprint::shown(key)),
    }
}

/// `a`, or `a and b`.
fn and(things: &[String]) -> String {
    match things {
        [one] => one.clone(),
        [first, rest @ ..] => format!("{first} and {}", rest.join(" and ")),
        [] => String::new(),
    }
}

/// Whether every relay of `card` is, by key, one of `relays` (§3.2, rule
/// 11; §8.2).
fn all_own(relays: &[OwnRelay], card: &Card) -> bool {
    card.relays()
        .keys()
        .iter()
        .all(|key| relays.iter().any(|relay| relay.key == *key))
}

/// Whether any relay of `card` is, by key, one of `relays`: the channel is
/// reached from this device (§8.3).
pub(crate) fn any_own(relays: &[OwnRelay], card: &Card) -> bool {
    card.relays()
        .keys()
        .iter()
        .any(|key| relays.iter().any(|relay| relay.key == *key))
}

// ── Refusals ─────────────────────────────────────────────────────────

/// A refusal of §5.5: its word (empty where the table gives none) and its
/// line, filled in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub word: &'static str,
    pub line: String,
}

/// Why nothing was done: a refusal of a person's, or the node's own
/// failure.
#[derive(Debug)]
pub enum Failed {
    Refused(Refusal),
    Error(PersonError),
}

impl From<PersonError> for Failed {
    fn from(e: PersonError) -> Self {
        Failed::Error(e)
    }
}

impl From<CordeliaError> for Failed {
    fn from(e: CordeliaError) -> Self {
        Failed::Error(PersonError::Storage(e))
    }
}

impl From<cordelia_crypto::CryptoError> for Failed {
    fn from(e: cordelia_crypto::CryptoError) -> Self {
        Failed::Error(PersonError::from(e))
    }
}

/// What a step gives, or why nothing was done.
pub type Out<T> = Result<T, Failed>;

pub(crate) fn refused<T>(word: &'static str, line: String) -> Out<T> {
    Err(Failed::Refused(Refusal { word, line }))
}

/// The line of `too_many_channels` (§5.5).
pub const TOO_MANY_CHANNELS: &str = "Your devices hold 16 shared channels, which is the most: \
                                     drop one first with cordelia shared drop <name>.";

/// The line of `no_keyed_relay` (§5.5).
pub const NO_KEYED_RELAY: &str = "None of your relays is set up with its key, and a shared \
                                  channel lives only at relays known by their key: add a relay's \
                                  key to your configuration.";

/// The line of a `shared new` given more than two relays, or one twice.
pub const ONE_OR_TWO_RELAYS: &str =
    "A shared channel lives at one or two of your relays, each once.";

/// The line of `bad_label`.
pub const BAD_LABEL: &str = "A label is 1 to 64 bytes of text.";

/// What the device is now, as `cordelia devices` says it first, for the
/// line of `not_applied`.
fn why_not_applied(conn: &Connection) -> Result<&'static str, PersonError> {
    use crate::at_relays::{Stands, stands};
    Ok(match stands(conn)? {
        Stands::NoPhrase => "this device follows no recovery phrase yet",
        Stands::Stopped(state) => crate::look::short_why(state),
        Stands::Applied => crate::look::short_why(cordelia_storage::person::State::Applied),
    })
}

/// The device stands applied under the latest statement it has seen, with
/// sync on (§5.5, the second row): the messages record's lines, said of a
/// shared channel. What it holds of its person, where it does.
pub(crate) fn standing(conn: &Connection) -> Out<Held> {
    match may_open(conn)? {
        Ok(()) => {}
        Err(NotUsable::SyncOff) => {
            return refused(
                "sync_off",
                "Sync is off on this device, and so are shared channels: nothing was done. Turn \
                 sync on with: cordelia sync claude"
                    .into(),
            );
        }
        Err(_) => {
            return refused(
                "not_applied",
                format!(
                    "This device is not one of your devices now ({}), so it does nothing with a \
                     shared channel.",
                    why_not_applied(conn)?
                ),
            );
        }
    }
    held(conn)?.ok_or(Failed::Error(PersonError::FollowsNoPhrase))
}

// ── Keys, and how a key is shown ─────────────────────────────────────

/// The six words of a key's fingerprint (§3.2, §5.3).
pub fn six_words(key: &[u8; 32]) -> String {
    fingerprint::words(key, SHARED_KEY_WORDS_SHOWN)
}

/// A whole key, as a person typed it: refused where it is not a device's
/// usable key (§5.5).
fn key_typed(typed: &str) -> Out<[u8; 32]> {
    match decode_public_key(typed.trim()) {
        Ok(key) if is_usable_public_key(&key) => Ok(key),
        _ => refused(
            "",
            format!(
                "{} is not a device's key: give the whole key, as cordelia id prints it.",
                crate::messages::cleaned(typed)
            ),
        ),
    }
}

/// The label the person gave `key` in shared channels, where it has one
/// in force (§3.4).
pub(crate) fn label_given(
    conn: &Connection,
    key: &[u8; 32],
) -> Result<Option<String>, PersonError> {
    Ok(lists::holds(conn)?
        .labels
        .into_iter()
        .find(|(act, _)| act.item.key == *key)
        .and_then(|(act, _)| act.item.label))
}

/// The label the person gave `key`, in force or past a bound: what
/// `label --none` may take away (§3.4, "an item in force past a bound can
/// be undone").
fn label_to_undo(
    conn: &Connection,
    own: &[u8; 32],
    key: &[u8; 32],
    now: i64,
) -> Result<Option<String>, PersonError> {
    if let Some(label) = label_given(conn, key)? {
        return Ok(Some(label));
    }
    Ok(lists::holds_worked_out(conn, own, now)?
        .left_out
        .into_iter()
        .find_map(|(act, _)| match act {
            lists::AnyAct::Label(act) if act.item.key == *key => act.item.label,
            _ => None,
        }))
}

/// A label as it is shown: cleaned, and quoted.
pub(crate) fn quoted(label: &str) -> String {
    format!("{:?}", crate::messages::cleaned(label))
}

/// After the six words of another person's key: its label, quoted, or "no
/// label of yours" (§5.2, §5.3).
fn label_part(conn: &Connection, key: &[u8; 32]) -> Result<String, PersonError> {
    Ok(match label_given(conn, key)? {
        Some(label) => quoted(&label),
        None => "no label of yours".into(),
    })
}

/// The one fixed form of a sender (§5.3): another person's device, by its
/// six words and the label the person gave it or none; a device of this
/// person's that counts, as its own; or this device.
pub fn sender_form(
    conn: &Connection,
    held: &Held,
    own: &[u8; 32],
    key: &[u8; 32],
) -> Result<String, PersonError> {
    if key == own {
        return Ok("this device".into());
    }
    let counting = crate::person::Counting::of(
        &held.statement.statement,
        &cordelia_storage::person::additions(conn)?,
    );
    if counting.counts(key) {
        let label = crate::reader::label_of(conn, &held.statement.statement, key)?;
        return Ok(format!(
            "your own device ({}) {}",
            six_words(key),
            quoted(&label)
        ));
    }
    Ok(format!("({}) {}", six_words(key), label_part(conn, key)?))
}

/// The key is another person's device: not this device or one of the
/// person's, and not one the person's statement lists as removed (§5.5).
/// `what` is the command, for its line.
fn another_persons(
    conn: &Connection,
    held: &Held,
    own: &[u8; 32],
    key: &[u8; 32],
    what: &str,
) -> Out<()> {
    let statement = &held.statement.statement;
    if statement.removed.contains(key) {
        return refused(
            "removed_key",
            format!(
                "({}) is a device you removed: nothing is handed to it, taken from it or \
                 labelled.",
                six_words(key)
            ),
        );
    }
    let counting =
        crate::person::Counting::of(statement, &cordelia_storage::person::additions(conn)?);
    if key == own || counting.counts(key) {
        let form = sender_form(conn, held, own, key)?;
        let line = match what {
            "share" => format!(
                "{form} is one of your devices, and holds every shared channel of yours already."
            ),
            "label" => format!(
                "{form} is one of your devices: it has the label you gave it as a device, and is \
                 not labelled here."
            ),
            _ => format!(
                "{form} is one of your devices: a shared channel is handed to you by another \
                 person's device."
            ),
        };
        return refused("own_device", line);
    }
    Ok(())
}

// ── Names ────────────────────────────────────────────────────────────

/// The shared channels the person files, in force, as this device holds
/// them (§3.4): the filings of the list it last wrote.
pub fn filed(conn: &Connection) -> Result<Vec<Filing>, PersonError> {
    Ok(lists::holds(conn)?
        .filings
        .into_iter()
        .map(|(act, _)| act.item)
        .collect())
}

/// The filings that a bound leaves out, worked out at `now` (§3.4): not
/// in force, and still acted on by a rename or a drop.
fn filed_past_a_bound(
    conn: &Connection,
    own: &[u8; 32],
    now: i64,
) -> Result<Vec<Filing>, PersonError> {
    Ok(lists::holds_worked_out(conn, own, now)?
        .left_out
        .into_iter()
        .filter_map(|(act, _)| match act {
            lists::AnyAct::Filing(filing) => Some(filing.item),
            _ => None,
        })
        .collect())
}

/// The channel's words: the first four of its ID's fingerprint (§3.2).
pub fn channel_words(channel: &[u8; 32]) -> String {
    fingerprint::shown(channel)
}

/// The shared channel filed as `name`, and given by its words where
/// `words` names them (§3.4, "two filings in force under one name").
/// With `past`, this device's key and the time, a filing that a bound
/// leaves out is found too: a rename and a drop act on it (§3.4), and
/// `share` does not, since its channel is not held.
pub(crate) fn find(
    conn: &Connection,
    name: &str,
    words: Option<&str>,
    past: Option<(&[u8; 32], i64)>,
) -> Out<Filing> {
    let mut all = filed(conn)?;
    if let Some((own, now)) = past {
        for filing in filed_past_a_bound(conn, own, now)? {
            if !all.iter().any(|one| one.channel == filing.channel) {
                all.push(filing);
            }
        }
    }
    let of_name: Vec<Filing> = all
        .into_iter()
        .filter(|filing| filing.name == name)
        .collect();
    let shown = crate::messages::cleaned(name);
    if let Some(words) = words {
        let words = words.split_whitespace().collect::<Vec<_>>().join(" ");
        return match of_name
            .into_iter()
            .find(|filing| channel_words(&filing.channel) == words)
        {
            Some(filing) => Ok(filing),
            None => refused(
                "no_such_channel",
                format!(
                    "No shared channel of yours named \"{shown}\" has the words {}.",
                    crate::messages::cleaned(&words)
                ),
            ),
        };
    }
    match of_name.len() {
        0 => refused(
            "no_such_channel",
            format!("No shared channel of yours is named \"{shown}\"."),
        ),
        1 => Ok(of_name.into_iter().next().expect("one")),
        _ => refused(
            "two_channels",
            format!(
                "\"{shown}\" names two shared channels: channel {} and channel {}. Give one with \
                 --words <four words>, or rename one with cordelia shared rename {shown} <new \
                 name> --words <four words>.",
                channel_words(&of_name[0].channel),
                channel_words(&of_name[1].channel)
            ),
        ),
    }
}

/// `name` may name a shared channel: it has a name's spelling, and is no
/// name of the person's own or of another shared channel (§2.2, §5.5).
fn name_free(conn: &Connection, name: &str) -> Out<()> {
    if !crate::names::is_a_name(name) {
        return refused(
            "not_a_name",
            format!(
                "\"{}\" is not a name: use letters, digits and / . _ - only.",
                crate::messages::cleaned(name)
            ),
        );
    }
    let own = crate::names::listed(conn)?
        .iter()
        .any(|listed| listed.name == name);
    if own || filed(conn)?.iter().any(|filing| filing.name == name) {
        return refused(
            "name_taken",
            format!("\"{name}\" is already a name of yours: give the shared channel another."),
        );
    }
    Ok(())
}

/// What an act of the person's list was refused for, as a refusal of §5.5.
fn act_refused(conn: &Connection, held: &Held, own: &[u8; 32], why: Refused) -> Out<()> {
    let devices = |devices: &[[u8; 32]]| -> Result<String, PersonError> {
        let mut named = Vec::new();
        for device in devices {
            named.push(crate::messages::cleaned(&crate::reader::label_of(
                conn,
                &held.statement.statement,
                device,
            )?));
        }
        Ok(named.join(", "))
    };
    match why {
        Refused::Full {
            part: Part::Channel,
            ..
        } => refused("too_many_channels", TOO_MANY_CHANNELS.into()),
        Refused::Full {
            part: Part::Label,
            devices: of,
        } => refused(
            "too_many_labels",
            format!(
                "Your devices hold 64 labels, or removed labels still needed by the lists of {}, \
                 which is the most: remove a label with cordelia label <key> --none, or have \
                 those devices write their lists.",
                devices(&of)?
            ),
        ),
        Refused::Full {
            part: Part::Subscription,
            devices: of,
        } => refused(
            "too_many_subscriptions",
            format!(
                "Your agents hold 32 subscriptions, or unsubscriptions still needed by the lists \
                 of {}, which is the most: unsubscribe one, or have those devices write their \
                 lists.",
                devices(&of)?
            ),
        ),
        Refused::HeldAtBound(device) => refused(
            "held_at_bound",
            format!(
                "{} holds this at the latest time an act may say, so nothing you do here can go \
                 above it: remove that device (cordelia remove-device), and do it again.",
                sender_form(conn, held, own, &device)?
            ),
        ),
        Refused::NotFiled => refused("no_such_channel", "No such shared channel of yours.".into()),
        Refused::Filed => refused(
            "already_held",
            "Your devices hold this channel already: nothing was taken.".into(),
        ),
        Refused::NothingToUndo => refused("", "There is nothing to undo.".into()),
        Refused::NotWritten(e) => refused("", format!("That cannot be written in a list: {e}.")),
    }
}

/// Do `what` in the person's list, or refuse as §5.5 says.
pub(crate) fn act(
    conn: &Connection,
    identity: &NodeIdentity,
    held: &Held,
    what: Do,
    now: i64,
) -> Out<()> {
    match lists::act(conn, identity, what, now)? {
        Done::Made(_) => Ok(()),
        Done::Refused(why) => act_refused(conn, held, &identity.public_key(), why),
    }
}

// ── What a command that writes says of who wrote there (§5.4) ────────

/// A time as `YYYY-MM-DD`, by this device's clock (§5.4).
pub fn date_of(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .map(|at| at.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| at.to_string())
}

/// The lines of §5.4 for the shared channel `channel`, filed as `name`:
/// which keys have written there, and which came since this device last
/// wrote there, or for `send`, since the folder whose agent is `agent`
/// last wrote there, by what it saw itself. Never who reads it.
pub fn who_wrote(
    conn: &Connection,
    held: &Held,
    own: &[u8; 32],
    channel: &[u8; 32],
    name: &str,
    agent: Option<&str>,
) -> Result<Vec<String>, PersonError> {
    let Some(row) = kept::channel(conn, channel)? else {
        return Ok(Vec::new());
    };
    let last = match agent {
        // The folder's last message there, on any device of the person's,
        // by its sent mark: when this device first held it.
        Some(agent) => {
            let marks = crate::shared_messages::marks_now(conn, &crate::person::who_counts(conn)?)?;
            let mut last = None;
            for (id, first_held) in kept::index_first_held(conn, row.id)? {
                let Ok(id) = crate::shared_messages::id_of(&id) else {
                    continue;
                };
                if marks.sent_by(channel, &id, agent) {
                    last = last.max(Some(first_held));
                }
            }
            last
        }
        None => entries::author_entries(conn, channel, own)?
            .iter()
            .map(|stored| stored.stored_at)
            .max(),
    };
    let since = last.unwrap_or(row.first_held);
    let labels: Vec<[u8; 32]> = lists::holds(conn)?
        .labels
        .iter()
        .filter(|(act, _)| act.item.label.is_some())
        .map(|(act, _)| act.item.key)
        .collect();
    let keys = kept::keys(conn, row.id)?;
    let wrote: Vec<&kept::Key> = keys
        .iter()
        .filter(|key| key.first_held.is_some() && key.key != *own)
        .collect();
    let labelled = wrote.iter().filter(|key| labels.contains(&key.key)).count();
    let mut changes = Vec::new();
    for key in &keys {
        if key.key == *own {
            continue;
        }
        if let Some(first) = key.first_held.filter(|first| *first > since) {
            changes.push(format!(
                "  new: {}, first held on this device on {}",
                sender_form(conn, held, own, &key.key)?,
                date_of(first)
            ));
        }
        if let Some(first) = key.first_refused.filter(|first| *first > since) {
            changes.push(format!(
                "  refused for room: {}, first refused on this device on {}, key {}",
                sender_form(conn, held, own, &key.key)?,
                date_of(first),
                encode_public_key(&key.key)?
            ));
        }
    }
    let counted = format!(
        "{} key{}, {labelled} of them labelled by you",
        wrote.len(),
        if wrote.len() == 1 { "" } else { "s" }
    );
    let unseen = "Anyone a member handed the channel to reads it too, unseen.";
    let shown = crate::messages::cleaned(name);
    let mut lines = vec![match changes.is_empty() {
        true => format!(
            "Keys that wrote here, in \"{shown}\": unchanged since {}: {counted}. {unseen}",
            date_of(since)
        ),
        false => format!(
            "Keys that wrote here, in \"{shown}\": {counted}. {unseen} New since {}:",
            date_of(since)
        ),
    }];
    lines.extend(changes);
    lines.extend(crate::shared_anew::after_who_wrote(
        conn, held, own, channel, name,
    )?);
    Ok(lines)
}

// ── A plan, and its yes ──────────────────────────────────────────────

/// What a command will do, once a person says yes to what it asks: the
/// text of its yes, worked out on the node from what the device holds now
/// (§5.2, §5.6).
#[derive(Debug, Clone)]
pub struct Plan<T> {
    pub asks: String,
    pub what: T,
}

/// The one card that `shared new` makes, and where.
#[derive(Debug, Clone)]
pub struct New {
    pub name: String,
    pub relays: Vec<OwnRelay>,
}

/// The relays a `shared new` names (§5.1, §5.5): each by the address that
/// the configuration gives a relay it knows by its key, one or two, each
/// once; or, with none named, the device's own relays that have a key, at
/// most two.
pub(crate) fn relays_named(own: &[OwnRelay], named: &[String]) -> Out<Vec<OwnRelay>> {
    if named.is_empty() {
        let taken: Vec<OwnRelay> = own.iter().take(SHARED_MAX_RELAYS).cloned().collect();
        if taken.is_empty() {
            return refused("no_keyed_relay", NO_KEYED_RELAY.into());
        }
        return Ok(taken);
    }
    if named.len() > SHARED_MAX_RELAYS {
        return refused("", ONE_OR_TWO_RELAYS.into());
    }
    let mut found: Vec<OwnRelay> = Vec::new();
    for name in named {
        let Some(relay) = own.iter().find(|relay| relay.name == *name) else {
            return refused(
                "not_own_relay",
                format!(
                    "{} is not one of your relays known by its key, and a shared channel lives \
                     only at those: nothing was done.",
                    crate::messages::cleaned(name)
                ),
            );
        };
        if found.iter().any(|one| one.key == relay.key) {
            return refused("", ONE_OR_TWO_RELAYS.into());
        }
        found.push(relay.clone());
    }
    Ok(found)
}

/// `cordelia shared new <name> [--relay <relay>]...` (§5.1, §5.2): what it
/// would make, and its yes, or why it is refused.
pub fn new_plan(
    conn: &Connection,
    own: &[OwnRelay],
    name: &str,
    named: &[String],
) -> Out<Plan<New>> {
    standing(conn)?;
    name_free(conn, name)?;
    let relays = relays_named(own, named)?;
    if filed(conn)?.len() >= SHARED_MAX_CHANNELS {
        return refused("too_many_channels", TOO_MANY_CHANNELS.into());
    }
    let lives: Vec<String> = relays
        .iter()
        .map(|relay| format!("  {}", relay_shown(own, &relay.key)))
        .collect();
    let asks = format!(
        "This makes a channel shared between people, filed on your devices as \"{name}\".\nIt \
         carries messages between your agents and other people's agents, and nothing else: never \
         memory.\nIt lives at:\n{}\nWhoever you share it with holds it as fully as you do, and \
         can share it on. Nobody is taken out of it except by making it anew.",
        lives.join("\n")
    );
    Ok(Plan {
        asks,
        what: New {
            name: name.into(),
            relays,
        },
    })
}

/// Make the shared channel of `new` (§2.1, §3.4): a card of a new seed at
/// its relays, filed in the person's list as made here, held, and its
/// empty anew record written. Returns the line said after the yes.
pub fn make_new(conn: &Connection, identity: &NodeIdentity, new: &New, now: i64) -> Out<String> {
    let held = standing(conn)?;
    let keys: Vec<[u8; 32]> = new.relays.iter().map(|relay| relay.key).collect();
    let relays = Relays::new(&keys).map_err(|_| {
        Failed::Refused(Refusal {
            word: "",
            line: ONE_OR_TWO_RELAYS.into(),
        })
    })?;
    let card = Card::make(relays).map_err(|e| PersonError::Held(e.to_string()))?;
    let channel = card.channel_id()?;
    let filing = Filing {
        channel,
        card,
        name: new.name.clone(),
        came: Came::Made,
    };
    in_one(conn, || -> Result<Out<()>, PersonError> {
        if let Err(failed) = act(conn, identity, &held, Do::File(filing.clone()), now) {
            return Ok(Err(failed));
        }
        write_empty_anew_records(conn, identity, now)?;
        Ok(Ok(()))
    })??;
    Ok(format!(
        "Made \"{}\": channel {}. No folder subscribes to it: in a folder, run cordelia \
         subscribe {}",
        new.name,
        channel_words(&channel),
        new.name
    ))
}

/// The shares this device keeps waiting at `now`: each not written over,
/// within its two hours (§3.1).
fn waiting(conn: &Connection, now: i64) -> Result<Vec<ShareRow>, PersonError> {
    Ok(rows::shares(conn)?
        .into_iter()
        .filter(|share| !share.gone && (now - share.made).abs() < HAND_OVER_KEPT_SECS)
        .collect())
}

/// What `share` hands, and to whom.
#[derive(Debug, Clone)]
pub struct ShareTo {
    pub filing: Filing,
    pub key: [u8; 32],
}

/// `cordelia share <name> <key>` (§3.1, §5.2, §5.5): what it would hand,
/// and its yes, or why it is refused.
pub fn share_plan(
    conn: &Connection,
    identity: &NodeIdentity,
    own_relays: &[OwnRelay],
    name: &str,
    typed: &str,
    words: Option<&str>,
    now: i64,
) -> Out<Plan<ShareTo>> {
    let held = standing(conn)?;
    let own = identity.public_key();
    let filing = match find(conn, name, words, None) {
        Err(Failed::Refused(refusal)) if refusal.word == "no_such_channel" && words.is_none() => {
            let own_name = crate::names::listed(conn)?
                .iter()
                .any(|listed| listed.name == name);
            if own_name {
                return refused(
                    "own_name",
                    format!(
                        "\"{name}\" is a name of your own. Nothing of your own is ever shared: \
                         only a channel made with cordelia shared new, or taken with cordelia \
                         accept --channel, is."
                    ),
                );
            }
            return Err(Failed::Refused(refusal));
        }
        found => found?,
    };
    let key = key_typed(typed)?;
    another_persons(conn, &held, &own, &key, "share")?;
    if !any_own(own_relays, &filing.card) {
        return refused(
            "not_reached",
            format!(
                "\"{name}\" is held on this device but not reached from it: write there from a \
                 device of yours that reaches its relays."
            ),
        );
    }
    let shown = crate::shared::shown_keys(conn, &filing.channel)?;
    if shown.len() >= SHARED_MAX_KEYS && !shown.contains(&key) {
        return refused(
            "channel_full",
            format!(
                "\"{name}\" shows 64 keys on this device, which is the most: make it anew without \
                 some (cordelia shared anew)."
            ),
        );
    }
    let mut keys_waiting: Vec<[u8; 32]> =
        waiting(conn, now)?.iter().map(|share| share.key).collect();
    keys_waiting.dedup();
    keys_waiting.sort();
    keys_waiting.dedup();
    if keys_waiting.len() >= MAX_TYPED_KEYS && !keys_waiting.contains(&key) {
        return refused(
            "too_many_shares",
            "This device has 8 shares waiting to be taken, which is the most: wait for one to be \
             taken, or for its two hours to end."
                .into(),
        );
    }
    let six = six_words(&key);
    let asks = format!(
        "This hands the shared channel \"{name}\" (channel {}) to the device ({six}) {}.\nBefore \
         you go on, have the person whose device it is read you the six words that cordelia id \
         --words prints there, by another way than the one the key came by: a call, or in \
         person. They must be these: {six}. If they are not, someone has put their own key in \
         its place: stop here.\nWhoever holds that device reads every message written there \
         from now on, and can write there and hand it on, until the channel is made anew \
         without them.\nNothing of your own goes with it: no memory, no name of yours, and no \
         other channel.",
        channel_words(&filing.channel),
        label_part(conn, &key)?
    );
    Ok(Plan {
        asks,
        what: ShareTo { filing, key },
    })
}

/// The revision of an entry this device writes in `slot` of the share pair
/// channel `pair`: as a hand-over's (`adding::hand_over_written`), its
/// clock in seconds, or one above the last it holds or noted there.
fn share_rev(
    conn: &Connection,
    own: &[u8; 32],
    pair: &[u8; 32],
    slot: &[u8; 32],
    noted: Option<u64>,
    now: i64,
) -> Result<u64, PersonError> {
    let held = entries::author_entry(conn, pair, slot, own)?.map(|held| held.entry.rev);
    let before = held.max(noted);
    let at = u64::try_from(now).unwrap_or(0);
    Ok(match before {
        Some(before) if before >= at => before + 1,
        _ => at,
    })
}

/// Write a delete over the share of `row`, one revision above it, in its
/// share pair channel (§3.1): it waits in the store to be sent to each
/// relay of the card it handed.
fn write_over(
    conn: &Connection,
    identity: &NodeIdentity,
    row: &ShareRow,
    now: i64,
) -> Result<(), PersonError> {
    let Some((pair, secret)) = share_pair(identity, &row.key) else {
        return Ok(());
    };
    let name = share_name(&row.channel);
    let slot = slot_id(&derive::slot_key(&secret)?, &name);
    let rev = share_rev(
        conn,
        &identity.public_key(),
        &pair,
        &slot,
        Some(row.rev),
        now,
    )?;
    let inside = Inside {
        name,
        value: Value::Delete,
        chain: Some(Vec::new()),
    };
    let entry = Entry::seal(&secret, identity, rev, &inside)?.check()?;
    entries::store(conn, &entry, now)?;
    rows::share_gone(conn, &row.key, &row.channel, rev)?;
    Ok(())
}

/// Hand the channel of `to` (§3.1): a delete over every other share this
/// device has waiting for that key, and one entry in the share pair channel
/// of this device and the key, `share/<the channel's ID>`, holding the
/// form, the time, the key and the card. Returns the lines said after the
/// yes.
pub fn make_share(
    conn: &Connection,
    identity: &NodeIdentity,
    own_relays: &[OwnRelay],
    to: &ShareTo,
    now: i64,
) -> Out<Vec<String>> {
    let held = standing(conn)?;
    let own = identity.public_key();
    let (pair, secret) =
        share_pair(identity, &to.key).ok_or_else(|| PersonError::Held("no share pair".into()))?;
    let channel = to.filing.channel;
    in_one(conn, || {
        for other in rows::shares(conn)? {
            if other.key == to.key && other.channel != channel && !other.gone {
                write_over(conn, identity, &other, now)?;
            }
        }
        let noted = rows::shares(conn)?
            .into_iter()
            .find(|row| row.key == to.key && row.channel == channel)
            .map(|row| row.rev);
        let name = share_name(&channel);
        let slot = slot_id(&derive::slot_key(&secret)?, &name);
        let rev = share_rev(conn, &own, &pair, &slot, noted, now)?;
        let share = Share {
            made: u64::try_from(now).unwrap_or(0),
            for_key: to.key,
            card: to.filing.card.clone(),
        };
        let inside = Inside {
            name,
            value: Value::Other(share.to_value()),
            chain: Some(Vec::new()),
        };
        let entry = Entry::seal(&secret, identity, rev, &inside)?.check()?;
        entries::store(conn, &entry, now)?;
        rows::note_share(
            conn,
            &ShareRow {
                key: to.key,
                channel,
                pair,
                relays: to.filing.card.relays().to_bytes(),
                rev,
                made: now,
                gone: false,
            },
        )?;
        Ok(())
    })?;
    let at: Vec<String> = to
        .filing
        .card
        .relays()
        .keys()
        .iter()
        .map(|key| relay_shown(own_relays, key))
        .collect();
    let which = match at.len() {
        1 => "that relay, by its key, is one of its own",
        _ => "those relays, by their keys, are its own",
    };
    let mut lines = vec![
        "Handed over. On the other device, within the hour, run:".to_string(),
        format!(
            "  cordelia accept {} --channel <a name of their choosing>",
            encode_public_key(&own)?
        ),
        format!(
            "It lives at {}. The other device takes it only where {which}.",
            and(&at)
        ),
        format!(
            "It prints these words for the channel once it has taken it: {}. They are its name, \
             and prove nothing.",
            channel_words(&channel)
        ),
    ];
    lines.extend(who_wrote(
        conn,
        &held,
        &own,
        &channel,
        &to.filing.name,
        None,
    )?);
    Ok(lines)
}

/// Each share this device made that is not within two hours of `now`, by
/// the time it says, is written over with a delete (§3.1, as
/// `adding::drop_old_hand_overs` keeps a hand-over); and what is kept of a
/// share written over more than a day ago goes. Returns how many were
/// written over.
pub fn drop_old_shares(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
) -> Result<usize, PersonError> {
    in_one(conn, || {
        let mut written = 0;
        for row in rows::shares(conn)? {
            let apart = (now - row.made).abs();
            if !row.gone && apart >= HAND_OVER_KEPT_SECS {
                write_over(conn, identity, &row, now)?;
                written += 1;
            } else if row.gone && apart >= TYPED_KEY_KEPT_SECS {
                // The delete goes from the store with what is kept of it.
                if let Some((_, secret)) = share_pair(identity, &row.key) {
                    let slot = slot_id(&derive::slot_key(&secret)?, &share_name(&row.channel));
                    entries::remove_slot(conn, &row.pair, &slot)?;
                }
                rows::forget_share(conn, &row.key, &row.channel)?;
            }
        }
        Ok(written)
    })
}

/// What `accept --channel` types.
#[derive(Debug, Clone)]
pub struct TypeFor {
    pub key: [u8; 32],
    pub name: String,
}

/// `cordelia accept <key> --channel <name>` (§3.2, §5.2, §5.5): what it
/// would type, and its yes, or why it is refused.
pub fn accept_plan(
    conn: &Connection,
    identity: &NodeIdentity,
    own_relays: &[OwnRelay],
    typed: &str,
    name: &str,
    now: i64,
) -> Out<Plan<TypeFor>> {
    let held = standing(conn)?;
    let own = identity.public_key();
    let key = key_typed(typed)?;
    another_persons(conn, &held, &own, &key, "accept")?;
    name_free(conn, name)?;
    if own_relays.is_empty() {
        return refused("no_keyed_relay", NO_KEYED_RELAY.into());
    }
    if filed(conn)?.len() >= SHARED_MAX_CHANNELS {
        return refused("too_many_channels", TOO_MANY_CHANNELS.into());
    }
    let reading: Vec<[u8; 32]> = rows::typed_keys(conn)?
        .into_iter()
        .filter(|row| row.taken.is_none() && crate::adding::within_its_hour(row.typed_at, now))
        .map(|row| row.key)
        .collect();
    if reading.len() >= MAX_TYPED_KEYS && !reading.contains(&key) {
        return refused(
            "too_many_typed",
            "This device is asking for 8 shared channels already: wait for one, or for its hour \
             to end."
                .into(),
        );
    }
    let six = six_words(&key);
    let at: Vec<String> = own_relays
        .iter()
        .map(|relay| format!("  {}", relay_shown(own_relays, &relay.key)))
        .collect();
    let asks = format!(
        "This device will take, within the hour, one shared channel that the device ({six}) {} \
         hands it, and file it as \"{name}\" on every device of yours.\nBefore you go on, have \
         the person whose device it is read you the six words that cordelia id --words prints \
         there, by another way than the one the key came by: a call, or in person. They must be \
         these: {six}. If they are not, someone has put their own key in its place: stop \
         here.\nIt is asked for at your relays that have a key, and taken only where it lives at \
         them:\n{}\nIt carries messages from other people's agents, and never memory. No agent \
         of yours is shown anything from it until you subscribe a folder: cordelia subscribe \
         {name}",
        label_part(conn, &key)?,
        at.join("\n")
    );
    Ok(Plan {
        asks,
        what: TypeFor {
            key,
            name: name.into(),
        },
    })
}

/// Keep the key of `typed` for an hour, with its name (§3.2): what a
/// person typed at `accept --channel` and said yes to. What was typed more
/// than a day ago is forgotten. Returns when it stops being asked for.
pub fn type_for_a_channel(conn: &Connection, typed: &TypeFor, now: i64) -> Out<i64> {
    standing(conn)?;
    in_one(conn, || {
        rows::forget_typed_keys(conn, now - TYPED_KEY_KEPT_SECS)?;
        rows::type_key(conn, &typed.key, &typed.name, now)?;
        Ok(())
    })?;
    Ok(now + PAIR_KEY_TYPED_SECS)
}

/// The keys typed for a channel that still read their share pair channels
/// at `now`: each typed within the last hour, with no share taken under it
/// (§3.2, rule 1).
pub fn keys_that_read(conn: &Connection, now: i64) -> Result<Vec<TypedForChannel>, PersonError> {
    Ok(rows::typed_keys(conn)?
        .into_iter()
        .filter(|row| row.taken.is_none() && crate::adding::within_its_hour(row.typed_at, now))
        .collect())
}

/// What became of the shares found for a key typed for a channel
/// ([`take_share`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Became {
    /// The key reads nothing now: typed again, spent, or its hour gone.
    NotNow,
    /// No share was found.
    Nothing,
    /// The one share was taken: the channel is filed and held.
    Taken([u8; 32]),
    /// Nothing was taken, for the reason of this word; its line is kept.
    Refused(&'static str),
}

/// Take, for the key `typed`, the one share among `found`, each an entry
/// that the judge passed by rules 1 to 8 (`crate::shared::accept_typed`),
/// at every relay that was read (§3.2). Where they hold more than one
/// share, of more than one channel, none is taken. Where the one share is
/// of a channel the person holds, the person holds 16, the device does not
/// stand applied with sync on, or a relay of its card is not, by key, one of
/// the device's own, nothing is taken, and the reason is kept. Where all
/// hold, in one transaction: the channel is filed as taken from the key,
/// the typing is spent, and the empty anew record is written.
pub fn take_share(
    conn: &Connection,
    identity: &NodeIdentity,
    typed: &TypedForChannel,
    found: &[CheckedEntry],
    own_relays: &[OwnRelay],
    now: i64,
) -> Result<Became, PersonError> {
    let own = identity.public_key();
    in_one(conn, || {
        let reads = rows::typed_key(conn, &typed.key)?.filter(|row| {
            row.typed_at == typed.typed_at
                && row.taken.is_none()
                && crate::adding::within_its_hour(row.typed_at, now)
        });
        let Some(row) = reads else {
            return Ok(Became::NotNow);
        };
        let Some((_, secret)) = share_pair(identity, &typed.key) else {
            return Ok(Became::NotNow);
        };
        let mut shares: Vec<Share> = Vec::new();
        for entry in found {
            let Ok(inside) = entry.open(&secret) else {
                continue;
            };
            let Ok(share) = Share::from_value(&inside.value) else {
                continue;
            };
            let id = share.card.channel_id()?;
            if !shares
                .iter()
                .any(|one| one.card.channel_id().ok() == Some(id))
            {
                shares.push(share);
            }
        }
        let keep = |word: &'static str, line: String| -> Result<Became, PersonError> {
            rows::became(conn, &row.key, row.typed_at, word, Some(&line))?;
            Ok(Became::Refused(word))
        };
        let Some(held) = held(conn)? else {
            return Ok(Became::NotNow);
        };
        match shares.len() {
            0 => return Ok(Became::Nothing),
            1 => {}
            n => {
                let line = format!(
                    "{} has {n} shares waiting for this device: nothing was taken. Ask them to \
                     share the one channel again, which takes back the others, and run cordelia \
                     accept again.",
                    sender_form(conn, &held, &own, &row.key)?
                );
                return keep("more_than_one_share", line);
            }
        }
        let share = shares.remove(0);
        let channel = share.card.channel_id()?;
        // Rule 9: a channel the person holds, and the 16.
        let filings = filed(conn)?;
        if let Some(filing) = filings.iter().find(|filing| filing.channel == channel) {
            let line = format!(
                "Your devices hold this channel already, as \"{}\": nothing was taken.",
                crate::messages::cleaned(&filing.name)
            );
            return keep("already_held", line);
        }
        if filings.len() >= SHARED_MAX_CHANNELS {
            return keep("too_many_channels", TOO_MANY_CHANNELS.into());
        }
        // Rule 10.
        match standing(conn) {
            Ok(_) => {}
            Err(Failed::Refused(refusal)) => return keep(refusal.word, refusal.line),
            Err(Failed::Error(e)) => return Err(e),
        }
        // Rule 11: every relay of the card is, by key, one of the device's
        // own.
        if !all_own(own_relays, &share.card) {
            let other = share
                .card
                .relays()
                .keys()
                .iter()
                .find(|key| !own_relays.iter().any(|relay| relay.key == **key))
                .copied()
                .unwrap_or_default();
            let line = format!(
                "{} is not one of your relays, and a shared channel lives only at your own \
                 relays: nothing was done.",
                relay_shown(own_relays, &other)
            );
            return keep("not_own_relay", line);
        }
        // The name may have been taken since it was typed.
        if let Err(Failed::Refused(refusal)) = name_free(conn, &row.name) {
            return keep(refusal.word, refusal.line);
        }
        let filing = Filing {
            channel,
            card: share.card,
            name: row.name.clone(),
            came: Came::Taken(row.key),
        };
        match lists::act(conn, identity, Do::File(filing), now)? {
            Done::Made(_) => {}
            Done::Refused(_) => return keep("too_many_channels", TOO_MANY_CHANNELS.into()),
        }
        rows::taken(conn, &row.key, row.typed_at, &channel, now)?;
        write_empty_anew_records(conn, identity, now)?;
        Ok(Became::Taken(channel))
    })
}

/// A share, or the delete over it, to push: the key it is for, the
/// channel it hands, and the entry.
pub type ShareToPush = ([u8; 32], [u8; 32], CheckedEntry);

/// What waits to be pushed to the relay whose key is `relay` of the shares
/// this device wrote (§3.1, §8.4): each share, or the delete written over
/// it, whose card names that relay, at a revision the relay has not
/// answered. A share is left at its card's relays and nowhere else.
pub fn shares_to_push(
    conn: &Connection,
    identity: &NodeIdentity,
    relay: &[u8; 32],
) -> Result<Vec<ShareToPush>, PersonError> {
    let own = identity.public_key();
    let mut waiting = Vec::new();
    for row in rows::shares(conn)? {
        let at_relay =
            Relays::from_bytes(&row.relays).is_ok_and(|relays| relays.keys().contains(relay));
        if !at_relay {
            continue;
        }
        let Some((pair, secret)) = share_pair(identity, &row.key) else {
            continue;
        };
        let slot = slot_id(&derive::slot_key(&secret)?, &share_name(&row.channel));
        let Some(held) = entries::author_entry(conn, &pair, &slot, &own)? else {
            continue;
        };
        let answered = rows::share_answer(conn, &row.key, &row.channel, relay)?;
        if answered.is_some_and(|rev| rev >= held.entry.rev) {
            continue;
        }
        if let Ok(entry) = Entry::check(held.entry) {
            waiting.push((row.key, row.channel, entry));
        }
    }
    Ok(waiting)
}

/// The relay whose key is `relay` answered a push of the share of `key` and
/// `channel` at `rev` so that it is not sent there again: it holds it, a
/// later one, another at that revision, or refused it as not signed.
pub fn share_pushed(
    conn: &Connection,
    key: &[u8; 32],
    channel: &[u8; 32],
    relay: &[u8; 32],
    rev: u64,
) -> Result<(), PersonError> {
    rows::share_answered(conn, key, channel, relay, rev)?;
    Ok(())
}

// ── Labels, renames and drops ────────────────────────────────────────

/// `cordelia label <key> <label>` or `--none` (§3.4, §5.2, §5.5).
#[derive(Debug, Clone)]
pub struct Labelling {
    pub key: [u8; 32],
    pub label: Option<String>,
}

/// What `label` would do, and its yes; or why it is refused; or, for
/// `--none` of a key with no label, the line said with nothing done
/// (`Ok(Err(line))`).
pub fn label_plan(
    conn: &Connection,
    identity: &NodeIdentity,
    typed: &str,
    label: Option<&str>,
    now: i64,
) -> Out<Result<Plan<Labelling>, String>> {
    let held = standing(conn)?;
    let own = identity.public_key();
    let key = key_typed(typed)?;
    another_persons(conn, &held, &own, &key, "label")?;
    let six = six_words(&key);
    let Some(label) = label else {
        if label_to_undo(conn, &own, &key, now)?.is_none() {
            return Ok(Err(format!("({six}) has no label of yours.")));
        }
        let asks = format!(
            "Your devices will show the device ({six}) with no label of yours in every shared \
             channel, after the keys you have labelled, and no longer keep room for it."
        );
        return Ok(Ok(Plan {
            asks,
            what: Labelling { key, label: None },
        }));
    };
    let cleaned = crate::messages::cleaned(label);
    if cleaned.is_empty() || cleaned.len() > SHARED_LABEL_MAX_BYTES {
        return refused("bad_label", BAD_LABEL.into());
    }
    let asks = format!(
        "Your devices will show the device ({six}) as {} in every shared channel, show its \
         messages before those of keys you have not labelled, and keep room for them.\nLabel a \
         key only once its person has read you these six words by another way than the one the \
         key came by.",
        quoted(&cleaned)
    );
    Ok(Ok(Plan {
        asks,
        what: Labelling {
            key,
            label: Some(cleaned),
        },
    }))
}

/// Label the key of `labelling`, or take its label away, on every device
/// of the person's (§3.4). Returns the line said after the yes.
pub fn make_label(
    conn: &Connection,
    identity: &NodeIdentity,
    labelling: &Labelling,
    now: i64,
) -> Out<String> {
    let held = standing(conn)?;
    let what = Do::Label(Label {
        key: labelling.key,
        label: labelling.label.clone(),
    });
    act(conn, identity, &held, what, now)?;
    let six = six_words(&labelling.key);
    Ok(match &labelling.label {
        Some(label) => format!(
            "Labelled ({six}) {} on every device of yours.",
            quoted(label)
        ),
        None => format!("({six}) has no label of yours now, on every device of yours."),
    })
}

/// `cordelia shared rename <name> <new name> [--words]` (§3.4, §5.5): no yes.
/// Returns the line said.
pub fn rename(
    conn: &Connection,
    identity: &NodeIdentity,
    name: &str,
    new: &str,
    words: Option<&str>,
    now: i64,
) -> Out<String> {
    let held = standing(conn)?;
    let filing = find(conn, name, words, Some((&identity.public_key(), now)))?;
    name_free(conn, new)?;
    let renamed = Filing {
        name: new.into(),
        ..filing.clone()
    };
    act(conn, identity, &held, Do::File(renamed), now)?;
    Ok(format!(
        "Renamed \"{name}\" (channel {}) to \"{new}\" on every device of yours.",
        channel_words(&filing.channel)
    ))
}

/// `cordelia shared drop <name> [--words]` (§3.4, §5.2): what it would drop,
/// and its yes.
pub fn drop_plan(
    conn: &Connection,
    identity: &NodeIdentity,
    name: &str,
    words: Option<&str>,
    now: i64,
) -> Out<Plan<[u8; 32]>> {
    standing(conn)?;
    let filing = find(conn, name, words, Some((&identity.public_key(), now)))?;
    let asks = format!(
        "This stops every device of yours holding the shared channel \"{name}\". Its other \
         members are not told, and still hold it. What it held is taken off your devices."
    );
    Ok(Plan {
        asks,
        what: filing.channel,
    })
}

/// Drop the channel `channel` on every device of the person's (§3.4).
/// Returns the line said after the yes.
pub fn make_drop(
    conn: &Connection,
    identity: &NodeIdentity,
    channel: &[u8; 32],
    name: &str,
    now: i64,
) -> Out<String> {
    let held = standing(conn)?;
    act(conn, identity, &held, Do::Drop(*channel), now)?;
    Ok(format!(
        "Dropped \"{name}\" (channel {}): your devices hold it no more.",
        channel_words(channel)
    ))
}

// ── The empty anew record ────────────────────────────────────────────

/// Write this device's empty anew record (form 5, at its full size) in
/// each shared channel it holds and has written none in (§6.1, §7): what
/// each device writes when it comes to hold a channel. Its revision is one
/// above the highest of that slot the device holds, and 1 where it holds
/// none; it goes through the one door. Nothing where the device does not
/// stand applied with sync on. Returns how many were written.
pub fn write_empty_anew_records(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
) -> Result<usize, PersonError> {
    if may_open(conn)?.is_err() {
        return Ok(0);
    }
    let own = identity.public_key();
    let mut written = 0;
    for row in kept::channels(conn)? {
        // Nothing is written in a channel not yet clean, or paused, but the
        // offer that makes it anew (decision 2026-10-24, rules 23 to 26).
        if !crate::shared_anew::writes_there(conn, identity, &row)? {
            continue;
        }
        let card = Card::from_bytes(&row.card)
            .map_err(|e| PersonError::Held(format!("the card of a shared channel: {e}")))?;
        let secret = card.secret()?;
        let name = anew_name(&own)?;
        let slot = slot_id(&derive::slot_key(&secret)?, &name);
        if entries::author_entry(conn, &row.channel, &slot, &own)?.is_some() {
            continue;
        }
        let value = Anew::Empty
            .to_value()
            .map_err(|e| PersonError::Held(e.to_string()))?;
        let inside = Inside {
            name,
            value: Value::Other(value),
            chain: Some(Vec::new()),
        };
        let entry = Entry::seal(&secret, identity, 1, &inside)?.check()?;
        crate::take::take(conn, identity, &entry, now)?;
        written += 1;
    }
    Ok(written)
}

// ── What `add-device` names ──────────────────────────────────────────

/// Each shared channel the person holds, with how many keys wrote there as
/// this device holds it (§5.2, `add-device`): this device, whose key is
/// `own`, not among them, as `shared list` counts them.
pub fn held_with_keys(
    conn: &Connection,
    own: &[u8; 32],
) -> Result<Vec<(String, usize)>, PersonError> {
    let mut held = Vec::new();
    for filing in filed(conn)? {
        let keys = match kept::channel(conn, &filing.channel)? {
            Some(row) => kept::keys(conn, row.id)?
                .iter()
                .filter(|key| key.first_held.is_some() && key.key != *own)
                .count(),
            None => 0,
        };
        held.push((filing.name, keys));
    }
    Ok(held)
}

// ── The list ─────────────────────────────────────────────────────────

/// What `cordelia shared list` shows (§5.1), as JSON: the channels held,
/// each with its words, its relays by the configuration's addresses, its
/// keys and whether it is reached; the keys typed for a channel and what
/// became of each; and the shares waiting. With `keys`, each channel's
/// table of keys, those refused for room among them.
pub fn list(
    conn: &Connection,
    identity: &NodeIdentity,
    own_relays: &[OwnRelay],
    with_keys: bool,
    now: i64,
) -> Result<serde_json::Value, PersonError> {
    use serde_json::json;
    let own = identity.public_key();
    let Some(held) = held(conn)? else {
        return Ok(json!({ "channels": [], "typed": [], "shares": [] }));
    };
    let names: Vec<String> = crate::names::listed(conn)?
        .into_iter()
        .map(|listed| listed.name)
        .collect();
    let labels: Vec<[u8; 32]> = lists::holds(conn)?
        .labels
        .iter()
        .filter(|(act, _)| act.item.label.is_some())
        .map(|(act, _)| act.item.key)
        .collect();
    let filings = filed(conn)?;
    let mut channels = Vec::new();
    for filing in &filings {
        let row = kept::channel(conn, &filing.channel)?;
        let keys = match &row {
            Some(row) => kept::keys(conn, row.id)?,
            None => Vec::new(),
        };
        let wrote: Vec<&kept::Key> = keys
            .iter()
            .filter(|key| key.first_held.is_some() && key.key != own)
            .collect();
        let relays: Vec<serde_json::Value> = filing
            .card
            .relays()
            .keys()
            .iter()
            .map(|key| {
                let named = own_relays.iter().find(|relay| relay.key == *key);
                json!({
                    "relay": named.map(|relay| relay.name.clone()),
                    "words": fingerprint::shown(key),
                    "shown": relay_shown(own_relays, key),
                })
            })
            .collect();
        let came = match filing.came {
            Came::Made => json!({ "made": true }),
            Came::Taken(key) => json!({ "taken_from": sender_form(conn, &held, &own, &key)? }),
            Came::Moved(from) => json!({ "moved_from": channel_words(&from) }),
        };
        let mut channel = json!({
            "id": hex::encode(filing.channel),
            "name": filing.name,
            "words": channel_words(&filing.channel),
            "came": came,
            "keys": wrote.len(),
            "labelled": wrote.iter().filter(|key| labels.contains(&key.key)).count(),
            "reached": any_own(own_relays, &filing.card),
            "relays": relays,
            "also_a_name": names.contains(&filing.name),
            "rows_let_go": row.as_ref().map_or(0, |row| row.let_go),
            "wrote": who_wrote(conn, &held, &own, &filing.channel, &filing.name, None)?,
        });
        if with_keys {
            let mut shown = Vec::new();
            for key in &keys {
                if key.key == own {
                    continue;
                }
                shown.push(json!({
                    "key": encode_public_key(&key.key)?,
                    "form": sender_form(conn, &held, &own, &key.key)?,
                    "first_held": key.first_held.map(date_of),
                    "first_refused": key.first_refused.map(date_of),
                    "bytes_refused": key.bytes_refused,
                    "stored": key.bytes_stored > 0,
                }));
            }
            channel["table"] = serde_json::Value::Array(shown);
        }
        channels.push(channel);
    }
    let mut typed = Vec::new();
    for row in rows::typed_keys(conn)? {
        let reading = row.taken.is_none() && crate::adding::within_its_hour(row.typed_at, now);
        typed.push(json!({
            "key": encode_public_key(&row.key)?,
            "form": sender_form(conn, &held, &own, &row.key)?,
            "name": row.name,
            "typed_at": row.typed_at,
            "until": row.typed_at + PAIR_KEY_TYPED_SECS,
            "asking": reading,
            "taken": row.taken.map(|(_, channel)| channel_words(&channel)),
            "became": row.became,
            "says": row.detail,
        }));
    }
    let mut shares = Vec::new();
    for row in rows::shares(conn)? {
        let filing = filings.iter().find(|filing| filing.channel == row.channel);
        // A share is taken where its key came to write in the channel since
        // it was made: the taker writes its empty anew record there. Both
        // times are this device's clock's.
        let taken = match kept::channel(conn, &row.channel)? {
            Some(channel) => kept::key(conn, channel.id, &row.key)?
                .and_then(|key| key.first_held)
                .is_some_and(|first| first >= row.made),
            None => false,
        };
        shares.push(json!({
            "key": encode_public_key(&row.key)?,
            "form": sender_form(conn, &held, &own, &row.key)?,
            "channel": filing.map(|filing| filing.name.clone()),
            "words": channel_words(&row.channel),
            "made": row.made,
            "until": row.made + HAND_OVER_KEPT_SECS,
            "waiting": !row.gone && (now - row.made).abs() < HAND_OVER_KEPT_SECS,
            "taken": taken,
        }));
    }
    let past: Vec<String> = filed_past_a_bound(conn, &own, now)?
        .into_iter()
        .map(|filing| filing.name)
        .collect();
    // Each subscription in force, by its agent and the channel's name, for
    // `cordelia sync status` (§5.1).
    let subscriptions: Vec<serde_json::Value> = crate::shared_messages::in_force(conn)?
        .into_iter()
        .filter_map(|(channel, agent)| {
            let filing = filings.iter().find(|filing| filing.channel == channel)?;
            Some(json!({ "agent": agent, "channel": filing.name }))
        })
        .collect();
    Ok(json!({
        "channels": channels,
        "typed": typed,
        "shares": shares,
        "past_a_bound": past,
        "subscriptions": subscriptions,
    }))
}

#[cfg(test)]
mod tests;
