//! What `cordelia status` and `cordelia shared list` say of each
//! repository this device follows (decision 2026-11-06 (joining), rules 6
//! and 7), and `cordelia shared seen <name>`.
//!
//! - **One view for each follow** ([`views`]): the repository and the name
//!   its channel is filed under; when the list was read, from where, at
//!   which commit, and how old the clone's copy is (rule 3); the members,
//!   by the list's labels, each in the channel or not yet; what waits
//!   unread; and its lines ([`lines_of`]). Each is worked out again from
//!   what the follow keeps, and nothing is written.
//! - **Its lines,** each a line of rule 6, or of rules 4.5 to 4.7 and 5, in
//!   this order:
//!   - **why the latest read counted for nothing,** where it did, and then
//!     nothing that the list read before would hand over or take: the
//!     node did neither at that read;
//!   - otherwise, where the person holds the channel the list names, why
//!     nothing is handed over ([`acts_in`]), or each key handed it that
//!     has not taken it yet; and where they do not, why nothing is taken
//!     ([`takes_in`]), or the wait ([`waiting_line`]);
//!   - **then the ambers:** a key that joined, a key dropped from the list,
//!     a changed channel line, each until a person clears it (rules 4.5,
//!     4.6 and 6); rule 1's gate, on a device that holds the channel and so
//!     sees who is in it (rule 4.7); and of each making anew here (rule 5),
//!     its new channel line until the list names the new channel, and from
//!     then on each key it left out that the list names and its channel
//!     line does not name after `without`, until a person clears it.
//! - **The ambers set a level.** The person ruled on 6 November that the
//!   joining record's ambers stand beside the one fact of decision
//!   2026-10-10 §9, property 16. Nothing else of a shared channel sets one.
//! - **`cordelia shared seen <name>`** ([`seen`]) clears, on this device,
//!   the joins and a changed line, and the amber of rule 5 for each key it
//!   shows. A key dropped from the list stays shown until it leaves the
//!   channel or is listed again.

use rusqlite::Connection;
use serde_json::{Value, json};

use cordelia_crypto::acts::Filing;
use cordelia_crypto::bech32::encode_public_key;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_storage::follows::{self, Follow, LastRead, MadeLine, NotRead, NoticeOf};
use cordelia_storage::shared::{self as kept, State};
use cordelia_storage::shared_anew as anew_rows;

use crate::following::{
    MOVED_FROM, back_along_moves, keys_in_channel, made_anew_from, name_of, no_channel_line,
};
use crate::git_list::Identity;
use crate::let_go::ago;
use crate::members::{self, Members, same_key};
use crate::members_read::{ASKED, NotHanding, TAKEN, acts_in, takes_in, waiting_line};
use crate::messages::cleaned;
use crate::person::{PersonError, in_one};
use crate::shared_routes::shell_word;
use crate::sharing::{self, Out, OwnRelay, channel_words, six_words};

/// A moment by the node's clock in RFC 3339.
fn rfc3339(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// One line of a follow's view: a word for a program, what it says, and
/// whether it is amber. A line that says to put a channel line in the
/// list carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Said {
    pub word: String,
    pub says: String,
    pub amber: bool,
    pub line: Option<String>,
}

impl Said {
    fn plain(word: &str, says: String) -> Self {
        Self {
            word: word.into(),
            says,
            amber: false,
            line: None,
        }
    }

    fn amber(word: &str, says: String) -> Self {
        Self {
            amber: true,
            ..Self::plain(word, says)
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "word": self.word,
            "says": self.says,
            "amber": self.amber,
            "line": self.line,
        })
    }
}

/// A channel this device made anew, with what it kept of it.
#[derive(Debug, Clone)]
pub struct Made {
    pub line: MadeLine,
    /// Whether a removal, or a recovery, made it (decision 2026-10-24,
    /// rule 24).
    pub at_removal: bool,
}

/// Every channel this device made anew, with what it kept of each.
fn made_here(conn: &Connection) -> Result<Vec<Made>, PersonError> {
    let rows = anew_rows::made_all(conn)?;
    Ok(follows::made_lines(conn)?
        .into_iter()
        .map(|line| Made {
            at_removal: rows
                .iter()
                .any(|row| row.channel == line.channel && row.at_removal),
            line,
        })
        .collect())
}

/// The list kept for `follow`, read, where it reads.
fn kept_list(follow: &Follow) -> Option<Members> {
    members::read(follow.list.as_deref()?).ok()
}

/// The name a follow's channel is said by, and the person's filing of the
/// channel its list names, where they hold it: that filing's name; or the
/// name of the channel they hold that the named one was made anew from;
/// or of the channel they moved to from the named one; or else the
/// repository's `owner/name`, which a channel taken for it is filed under.
fn shown_name(
    conn: &Connection,
    identity: &NodeIdentity,
    follow: &Follow,
    list: Option<&Members>,
) -> Result<(String, Option<Filing>), PersonError> {
    let default = Identity::from_text(&follow.identity)
        .map(|of| name_of(&of))
        .unwrap_or_else(|| follow.identity.clone());
    let Some(line) = list.and_then(|list| list.channel.as_ref()) else {
        return Ok((default, None));
    };
    let filings = sharing::filed(conn)?;
    if let Some(filing) = filings.iter().find(|filing| filing.channel == line.channel) {
        return Ok((filing.name.clone(), Some(filing.clone())));
    }
    if let Some(from) = made_anew_from(conn, identity, &filings, &line.channel)? {
        return Ok((from.name.clone(), None));
    }
    for filing in &filings {
        if back_along_moves(conn, &filing.channel)?.contains(&line.channel) {
            return Ok((filing.name.clone(), None));
        }
    }
    Ok((default, None))
}

// ── The lines ────────────────────────────────────────────────────────

/// Rule 3's line of the list last read: from where, how old the clone's
/// copy is, when it was read and at which commit. Where the clone does not
/// say when it fetched, as with a person's `insteadOf`, it says that this
/// is not known, and no more.
pub fn read_line(identity: &str, last: &LastRead, fetched_at: Option<i64>, now: i64) -> String {
    let read = format!("Read {}, at commit {}.", ago(now - last.at), last.commit);
    if !last.from_clone {
        return format!("List of {identity} read from its host. {read}");
    }
    match fetched_at {
        Some(at) => format!(
            "List of {identity} read from your clone, fetched {}. {read}",
            ago(now - at)
        ),
        None => format!(
            "List of {identity} read from your clone; when your clone fetched it is not known. \
             {read}"
        ),
    }
}

/// Rule 6's line of a read that counted for nothing (rules 1 and 3): the
/// last list read stands. A clone behind the last commit read says so.
pub fn not_read_line(identity: &str, not: &NotRead) -> String {
    let why = &not.why;
    match not.word.as_str() {
        // Already rule 6's line, whole.
        "followed_elsewhere" => why.clone(),
        "behind" => format!(
            "Your clone of {identity} is behind: {why}. The last list read stands. Run git pull \
             there; if its history was rewritten, run cordelia subscribe there again."
        ),
        "not_a_list" => format!(
            "The list of {identity} in your clone cannot be read: {why}. Fix it in a pull \
             request. The last list read stands."
        ),
        _ => format!(
            "The list of {identity} was not read from your clone: {why}. The last list read \
             stands."
        ),
    }
}

/// Rule 6's line of a member who cannot hand the channel over (rule 4.1),
/// for `why`, but rule 1's gate, which is said by [`gate_line`].
fn not_handing_line(why: &NotHanding, name: &str, list: &Members, identity: &str) -> String {
    let until = "nothing is handed over until then.";
    match why {
        NotHanding::NoChannel => no_channel_line(identity),
        NotHanding::LeftOut(_) => String::new(),
        NotHanding::NotHeld => format!("{name} is not held on this device: {until}"),
        NotHanding::MovedFrom => MOVED_FROM.into(),
        NotHanding::NotClean => format!("{name} is not clean: {until}"),
        NotHanding::MadeAnew { maker } => format!(
            "{name} was made anew by {}: nothing is handed over until the list names the new \
             channel.",
            list.label_of(maker).unwrap_or("a device not on the list")
        ),
        NotHanding::NotReached => format!("{name} is not reached at its relays: {until}"),
        NotHanding::Full => format!("{name} is full: {until}"),
    }
}

/// Rule 4.7's line, amber: a key the list names, that its channel line
/// names after `without`, and that is not in the channel.
pub fn gate_line(label: &str, name: &str) -> String {
    format!(
        "{label} is on the list of {name} but was left out of it: delete its line in a pull \
         request, or wait for that device to write in the channel"
    )
}

/// Rule 6's line of a member's node that handed the channel to `label`,
/// which has not taken it yet.
pub fn handing_line(name: &str, label: &str) -> String {
    format!("Handing {name} to {label}: waiting for that device to take it.")
}

/// Rule 4.5's line, amber, until a person clears it.
pub fn joined_line(label: &str, name: &str, commit: &str) -> String {
    format!("{label} joined {name} from the list at {commit}")
}

/// Rule 4.6's line, amber, until the key leaves the channel or is listed
/// again.
pub fn dropped_line(label: &str, name: &str) -> String {
    format!(
        "{label} is no longer on the list of {name}: make it anew with cordelia shared anew {}",
        shell_word(name)
    )
}

/// Rule 6's line of a changed channel line, amber, until a person clears
/// it.
pub fn line_changed_line(identity: &str, name: &str, commit: &str) -> String {
    format!("The list of {identity} names a new channel for {name} at {commit}.")
}

/// Rule 5's line of a making anew here, amber, until the list names the
/// new channel: one at a removal or after a recovery (a channel past its
/// bound among them), or a person's `shared anew`.
pub fn put_the_line(name: &str, at_removal: bool) -> String {
    match at_removal {
        true => format!(
            "{name} was made anew at a removal: put its new channel line in .cordelia/members"
        ),
        false => format!(
            "{name} was made anew here: put its new channel line in .cordelia/members, in a pull \
             request"
        ),
    }
}

/// Rule 5's amber of a key that a making anew here left out, that the list
/// names, and that its channel line does not name after `without`.
pub fn not_said_line(label: &str, name: &str) -> String {
    format!(
        "{label} was left out of {name}, and its channel line does not say so: add it after \
         without, or delete its line"
    )
}

/// The lines of the follow `follow`, whose list kept is `list` and whose
/// channel is said as `name`, at `now`, with `made` the makings anew here
/// (see the module's documentation).
#[allow(clippy::too_many_arguments)]
pub fn lines_of(
    conn: &Connection,
    identity: &NodeIdentity,
    own_relays: &[OwnRelay],
    follow: &Follow,
    list: Option<&Members>,
    name: &str,
    made: &[Made],
    now: i64,
) -> Result<Vec<Said>, PersonError> {
    let repository = &follow.identity;
    let mut said = Vec::new();
    let of_made = made_lines(conn, list, name, made)?;
    // First, a read that counted for nothing: the node handed nothing over
    // and took nothing at it, whatever the list read before says.
    if let Some(not) = &follow.not_read {
        said.push(Said::plain(&not.word, not_read_line(repository, not)));
    } else {
        match takes_in(conn, identity, own_relays, follow)? {
            Ok(looks) => {
                let when = follow
                    .last
                    .as_ref()
                    .map_or_else(|| "not yet".into(), |last| ago(now - last.at));
                said.push(Said::plain(
                    "waiting",
                    waiting_line(&cleaned(&looks.name), &when),
                ));
                said.extend(typed_lines(conn, repository, &looks.list)?);
            }
            Err(refusal) if refusal.word == "held" => {
                if let Some(list) = list {
                    said.extend(handing(
                        conn, identity, own_relays, follow, list, name, now,
                    )?);
                }
            }
            // The line of this device's own making anew says what to put
            // in the list, below.
            Err(refusal)
                if refusal.word == "moved" && !of_made.iter().any(|one| one.line.is_some()) =>
            {
                said.push(Said::plain(refusal.word, refusal.line));
            }
            Err(refusal) if refusal.word == "moved" => {}
            // Rule 6's one amber of a joiner: no device of the person's
            // holds the channel or can move to it.
            Err(refusal) if refusal.word == "left_out_of_it" => {
                said.push(Said::amber(refusal.word, refusal.line));
            }
            Err(refusal) => said.push(Said::plain(refusal.word, refusal.line)),
        }
    }
    for notice in follows::notices(conn, repository)? {
        said.push(match notice.of {
            NoticeOf::Joined { label, .. } => {
                Said::amber("joined", joined_line(&label, name, &notice.commit))
            }
            NoticeOf::LineChanged => Said::amber(
                "line_changed",
                line_changed_line(repository, name, &notice.commit),
            ),
            NoticeOf::Dropped { label, .. } => Said::amber("dropped", dropped_line(&label, name)),
        });
    }
    said.extend(of_made);
    Ok(said)
}

/// The lines of a member, whose person holds the channel `list` names
/// (rules 4.1, 4.2 and 4.7): why nothing is handed over, or each listed key
/// the node's share waits for that has not taken it.
fn handing(
    conn: &Connection,
    identity: &NodeIdentity,
    own_relays: &[OwnRelay],
    follow: &Follow,
    list: &Members,
    name: &str,
    now: i64,
) -> Result<Vec<Said>, PersonError> {
    let line = match acts_in(conn, identity, own_relays, list)? {
        Ok((line, _)) => line,
        Err(NotHanding::LeftOut(labels)) => {
            return Ok(labels
                .iter()
                .map(|label| Said::amber("left_out", gate_line(label, name)))
                .collect());
        }
        Err(why) => {
            let says = not_handing_line(&why, name, list, &follow.identity);
            return Ok(vec![Said::plain(why.word(), says)]);
        }
    };
    let in_channel = keys_in_channel(conn, &identity.public_key(), list)?;
    let mut said = Vec::new();
    for share in sharing::waiting(conn, now)? {
        if !share.by_node
            || share.channel != line.channel
            || in_channel.iter().any(|key| same_key(key, &share.key))
        {
            continue;
        }
        if let Some(label) = list.label_of(&share.key) {
            said.push(Said::plain("handing", handing_line(name, label)));
        }
    }
    Ok(said)
}

/// What became of the node's typings of a joiner (rule 4.4) where a share
/// was found and not taken: each with its key's label and the line that
/// says why.
fn typed_lines(
    conn: &Connection,
    repository: &str,
    list: &Members,
) -> Result<Vec<Said>, PersonError> {
    let mut said = Vec::new();
    for typed in follows::typed(conn, repository)? {
        let (Some(became), Some(detail)) = (&typed.became, &typed.detail) else {
            continue;
        };
        if became == ASKED || became == TAKEN {
            continue;
        }
        let from = list
            .label_of(&typed.key)
            .map_or_else(|| six_words(&typed.key), str::to_string);
        said.push(Said::plain(became, format!("From {from}: {detail}")));
    }
    Ok(said)
}

/// A making anew here, with the keys of it that its rule 5 amber shows.
type NotSaid<'a> = (&'a Made, Vec<[u8; 32]>);

/// The keys each making anew here left out that its rule 5 amber shows
/// for the list `list`: from when a list first named its new channel, or
/// one made anew from it, each key it left out that the list names and
/// whose channel line does not name it after `without`. Only where the
/// list names that new channel, or one made anew from it, as far as this
/// device knows.
fn not_said<'a>(
    conn: &Connection,
    list: &Members,
    made: &'a [Made],
) -> Result<Vec<NotSaid<'a>>, PersonError> {
    let Some(line) = &list.channel else {
        return Ok(Vec::new());
    };
    let back = back_along_moves(conn, &line.channel)?;
    let mut shown = Vec::new();
    for one in made {
        if one.line.named_at.is_none() || !back.contains(&one.line.new_channel) {
            continue;
        }
        let keys: Vec<[u8; 32]> = one
            .line
            .left_out
            .iter()
            .filter(|key| list.lists(key) && !line.leaves_out(key))
            .copied()
            .collect();
        if !keys.is_empty() {
            shown.push((one, keys));
        }
    }
    Ok(shown)
}

/// The ambers of rule 5 of each making anew here, for the list `list`:
/// its new channel line, until a list names the new channel, where the
/// list still names the channel it made anew or one that channel was made
/// anew from, and the person has not moved on from the new channel to a
/// later one, whose line is the one to put; and then [`not_said`]'s keys,
/// each by its label.
fn made_lines(
    conn: &Connection,
    list: Option<&Members>,
    name: &str,
    made: &[Made],
) -> Result<Vec<Said>, PersonError> {
    let Some(list) = list else {
        return Ok(Vec::new());
    };
    let Some(line) = &list.channel else {
        return Ok(Vec::new());
    };
    let mut said = Vec::new();
    for one in made {
        let Some(put) = &one.line.line else {
            continue;
        };
        // Once a list named the new channel, the line is said no more,
        // even where a later list names the old one again.
        if one.line.named_at.is_some() {
            continue;
        }
        // A channel the person moved on from was made anew again, here or
        // by another device: the later line is the one to put.
        let moved_on = kept::channel(conn, &one.line.new_channel)?
            .is_some_and(|row| row.state == State::Moved);
        if moved_on {
            continue;
        }
        if !back_along_moves(conn, &one.line.channel)?.contains(&line.channel) {
            continue;
        }
        let word = match one.at_removal {
            true => "made_anew_at_removal",
            false => "put_the_line",
        };
        let mut says = put_the_line(name, one.at_removal);
        if one.line.cut > 0 {
            says.push_str(&format!(
                ". The line is cut: {} left out {} not on it",
                sharing::counted(one.line.cut, "key"),
                if one.line.cut == 1 { "is" } else { "are" }
            ));
        }
        said.push(Said {
            line: Some(put.clone()),
            ..Said::amber(word, says)
        });
    }
    for (_, keys) in not_said(conn, list, made)? {
        for key in keys {
            if let Some(label) = list.label_of(&key) {
                said.push(Said::amber("not_said", not_said_line(label, name)));
            }
        }
    }
    Ok(said)
}

// ── The view ─────────────────────────────────────────────────────────

/// The view of each repository this device follows, by identity, at
/// `now` (rule 7). `own_relays` are the device's relays known by their
/// keys.
pub fn views(
    conn: &Connection,
    identity: &NodeIdentity,
    own_relays: &[OwnRelay],
    now: i64,
) -> Result<Vec<Value>, PersonError> {
    let made = made_here(conn)?;
    let subscriptions = crate::shared_messages::in_force(conn)?;
    let mut views = Vec::new();
    for follow in follows::follows(conn)? {
        let list = kept_list(&follow);
        let (name, filing) = shown_name(conn, identity, &follow, list.as_ref())?;
        let name = cleaned(&name);
        let lines = lines_of(
            conn,
            identity,
            own_relays,
            &follow,
            list.as_ref(),
            &name,
            &made,
            now,
        )?;
        let channel = list.as_ref().and_then(|list| list.channel.as_ref());
        // Who is in the channel only a device that holds it sees.
        let row = match &filing {
            Some(filing) => {
                kept::channel(conn, &filing.channel)?.filter(|row| row.state == State::Held)
            }
            None => None,
        };
        let in_channel = match (&row, &list) {
            (Some(_), Some(list)) => Some(keys_in_channel(conn, &identity.public_key(), list)?),
            _ => None,
        };
        let mut members = Vec::new();
        for device in list.iter().flat_map(|list| &list.devices) {
            let is_in = in_channel
                .as_ref()
                .map(|keys| keys.iter().any(|key| same_key(key, &device.key)));
            members.push(json!({
                "label": device.label,
                "key": encode_public_key(&device.key)?,
                "words": six_words(&device.key),
                "in": is_in,
            }));
        }
        let (unread_by_an_agent, unread_by_a_person) = match &row {
            Some(row) => {
                let subscribed: Vec<&str> = subscriptions
                    .iter()
                    .filter(|(of, _)| *of == row.channel)
                    .map(|(_, agent)| agent.as_str())
                    .collect();
                crate::shared_status::unread_in(conn, identity, row, &subscribed, now)?
            }
            None => (0, 0),
        };
        let read = follow.last.as_ref().map(|last| {
            json!({
                "at": rfc3339(last.at),
                "commit": last.commit,
                "from": if last.from_clone { "clone" } else { "host" },
                "fetched": follow.fetched_at.map(rfc3339),
                "says": read_line(&follow.identity, last, follow.fetched_at, now),
            })
        });
        views.push(json!({
            "identity": follow.identity,
            "name": name,
            "held": filing.is_some(),
            "channel": channel.map(|line| hex::encode(line.channel)),
            "words": channel.map(|line| channel_words(&line.channel)),
            "read": read,
            "members": members,
            "unread_by_an_agent": unread_by_an_agent,
            "unread_by_a_person": unread_by_a_person,
            "lines": lines.iter().map(Said::to_json).collect::<Vec<_>>(),
        }));
    }
    Ok(views)
}

// ── cordelia shared seen <name> ──────────────────────────────────────

/// What `cordelia shared seen` says where this device follows no
/// repository whose channel is `name`: another device's follows are its
/// own (decision 2026-11-06 (joining), rule 6).
pub fn not_read_here_line(name: &str) -> String {
    format!(
        "This device does not read the list of {name}: run cordelia subscribe in a clone of its \
         repository."
    )
}

/// `cordelia shared seen <name>` (rules 4.5, 5 and 6), in one write: for
/// each repository this device follows whose channel is said as `name`,
/// or whose identity is `name`, the joins and a changed channel line go,
/// and so does the amber of rule 5 for each key it shows now. A key
/// dropped from the list stays shown until it leaves the channel. It needs
/// no yes: it only clears notices on this device. Returns what it says.
pub fn seen(conn: &Connection, identity: &NodeIdentity, name: &str) -> Out<Vec<String>> {
    let shown = cleaned(name);
    let done = in_one(conn, || {
        let made = made_here(conn)?;
        let mut followed = false;
        let (mut cleared, mut dropped) = (0usize, 0usize);
        for follow in follows::follows(conn)? {
            let list = kept_list(&follow);
            let (of, _) = shown_name(conn, identity, &follow, list.as_ref())?;
            if cleaned(&of) != shown && follow.identity != name {
                continue;
            }
            followed = true;
            cleared += follows::seen(conn, &follow.identity)?;
            if let Some(list) = &list {
                for (one, keys) in not_said(conn, list, &made)? {
                    cleared += follows::not_left_out(conn, &one.line.channel, &keys)?;
                }
            }
            dropped += follows::notices(conn, &follow.identity)?
                .iter()
                .filter(|notice| matches!(notice.of, NoticeOf::Dropped { .. }))
                .count();
        }
        Ok((followed, cleared, dropped))
    });
    let (followed, cleared, dropped) = done.map_err(sharing::Failed::Error)?;
    if !followed {
        return sharing::refused("not_followed", not_read_here_line(&shown));
    }
    let mut said = vec![match cleared {
        0 => format!("Nothing to clear for {shown} on this device."),
        n => format!(
            "Cleared {} for {shown} on this device.",
            sharing::counted(n as u64, "notice")
        ),
    }];
    if dropped > 0 {
        said.push(format!(
            "A key no longer on the list stays shown until it leaves the channel: make {shown} \
             anew with cordelia shared anew {}.",
            shell_word(&shown)
        ));
    }
    Ok(said)
}

#[cfg(test)]
mod tests;
