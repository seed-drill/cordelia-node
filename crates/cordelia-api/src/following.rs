//! Following a repository (decision 2026-11-06 (joining), rule 2):
//! `cordelia subscribe` in a clone, with no name, and `--new`.
//!
//! - **The clone is read outside the node's lock** ([`read_of`]): the top
//!   of the work tree the folder is in, the remote whose repository it is
//!   (`--remote` chooses among several), and the list at that remote's
//!   default branch, each by [`crate::git_list`]. Where any of it fails,
//!   nothing is done, and it says why.
//! - **Under the lock, the plan** ([`plan`], rule 2.3): a person who holds
//!   the channel the list names follows the repository, and the folder's
//!   agent is subscribed to it; one who does not, and whose key is on the
//!   list, follows and waits; one whose key is not on the list, or who
//!   dropped that channel, is refused. What it shows is rule 2.2's: the
//!   repository, the commit, the channel the list names, and whether this
//!   device's key is on the list. So its yes names the commit (rule 2.5),
//!   and a yes typed against another commit is refused, as any yes to a
//!   text that changed is.
//! - **On the yes, in one transaction** ([`make`]): the subscription, the
//!   follow, started afresh, and its first read; with `--new` (rule 2.4),
//!   the channel made first, and the lines to add to the list said.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use cordelia_core::protocol::MEMBERS_LABEL_MAX_CHARS;
use cordelia_crypto::acts::{Came, Subscription};
use cordelia_crypto::bech32::encode_public_key;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_storage::follows::{self, LastRead};
use cordelia_storage::shared as kept;

use crate::git_list::{ClonedList, Git, Identity, ListFailed, RemoteRefused};
use crate::lists::Do;
use crate::members::{self, ChannelLine, Members, same_key};
use crate::messages::cleaned;
use crate::person::{Held, PersonError, in_one};
use crate::sharing::{self, Failed, New, Out, OwnRelay, Plan, Refusal, channel_words};

// ── The clone, read outside the lock ─────────────────────────────────

/// What `subscribe` read of a clone: the repository, the remote whose
/// address names it, the top of the clone's work tree, and the list.
#[derive(Debug, Clone)]
pub struct ClonedRead {
    pub identity: Identity,
    pub remote: String,
    pub top: PathBuf,
    pub list: ClonedList,
}

/// What `subscribe` with no name says in a folder of no repository.
pub const NOT_IN_A_CLONE: &str = "This folder is not in a git repository, so there is no list \
                                  to follow, and nothing was done. To subscribe its agent to a \
                                  shared channel of yours, give the channel's name: cordelia \
                                  subscribe <name>";

/// What `subscribe` says where the list names a channel the person moved
/// from (rule 6).
pub const MOVED_FROM: &str = "The list names the channel you moved from. The device that made \
                              it anew shows its new channel line: put that line in \
                              .cordelia/members.";

/// Read the clone that `folder` is in, with the node's git under
/// `data_dir` (rules 2.1 and 3). It runs outside the node's lock: git may
/// take seconds. `chosen` is the remote `--remote` named.
pub fn read_of(data_dir: &Path, folder: &Path, chosen: Option<&str>) -> Out<ClonedRead> {
    let git =
        Git::under(data_dir).map_err(|e| PersonError::Held(format!("the node's git: {e}")))?;
    read_with(&git, folder, chosen)
}

/// [`read_of`], with the node's git given.
pub fn read_with(git: &Git, folder: &Path, chosen: Option<&str>) -> Out<ClonedRead> {
    let top = match git.top_of(folder) {
        Ok(top) => top,
        Err(ListFailed::NotARepository) => {
            return sharing::refused("not_a_repository", NOT_IN_A_CLONE.into());
        }
        Err(failed) => return not_read(None, &failed),
    };
    let (remote, identity) = match git.identity_of_clone(&top, chosen) {
        Ok(chosen) => chosen,
        Err(RemoteRefused::Git(failed)) => return not_read(None, &failed),
        Err(why) => {
            return sharing::refused(why.code(), format!("{} Nothing was done.", why.says()));
        }
    };
    let list = match git.read_clone(&top, &remote, &identity) {
        Ok(list) => list,
        Err(failed) => return not_read(Some(&identity), &failed),
    };
    Ok(ClonedRead {
        identity,
        remote,
        top,
        list,
    })
}

/// The refusal of a read of the clone that failed: its word, and why.
fn not_read<T>(identity: Option<&Identity>, failed: &ListFailed) -> Out<T> {
    let what = match identity {
        Some(identity) => format!("The list of {identity} was not read from your clone"),
        None => "Your clone was not read".to_string(),
    };
    sharing::refused(
        failed.code(),
        format!("{what}: {}. Nothing was done.", failed.says()),
    )
}

// ── The plan, under the lock (rule 2.3) ──────────────────────────────

/// What `subscribe` in a clone does once its yes is given.
#[derive(Debug, Clone)]
pub struct Following {
    /// The repository, as `host/owner/name`.
    pub identity: String,
    pub remote: String,
    /// The top of the clone's work tree.
    pub clone: String,
    pub commit: String,
    /// The list's bytes, as the clone has them: none where it has no list.
    pub list: Vec<u8>,
    /// The agent of the folder it was run in.
    pub agent: String,
    pub then: Then,
}

/// What else it does, beside the follow.
#[derive(Debug, Clone)]
pub enum Then {
    /// Subscribe the folder's agent to the channel the person holds, filed
    /// as this name.
    Subscribe {
        subscription: Subscription,
        name: String,
    },
    /// Nothing: the agent subscribes already, or the person waits to be
    /// handed the channel.
    Nothing,
    /// Make the repository's channel, and subscribe the folder's agent to
    /// it (`--new`, rule 2.4).
    Make(New),
}

/// The line of rule 6 for a list that names no channel.
fn no_channel_line(repository: &str) -> String {
    format!("The list of {repository} names no channel yet.")
}

/// What `cordelia subscribe` with no name would do in `folder`, given what
/// was read of its clone (rule 2.3), and its yes; or, with `new`, what
/// `--new` would make (rule 2.4). `own_relays` are the device's relays
/// known by their keys.
pub fn plan(
    conn: &Connection,
    identity: &NodeIdentity,
    own_relays: &[OwnRelay],
    folder: &str,
    read: &ClonedRead,
    new: bool,
) -> Out<Plan<Following>> {
    sharing::standing(conn)?;
    let agent = crate::shared_routes::agent_here(conn, folder)?;
    let repository = read.identity.to_string();
    let commit = &read.list.at.commit;
    // A clone with no list is a list with no members and no channel.
    let file = read.list.at.file.clone().unwrap_or_default();
    let members = match members::read(&file) {
        Ok(members) => members,
        Err(not) => {
            return sharing::refused(
                "not_a_list",
                format!(
                    "The list of {repository} at commit {commit} cannot be read: {not}. Fix it in \
                     a pull request. Nothing was done."
                ),
            );
        }
    };
    let own = identity.public_key();
    // A twin of this device's key is its key (rule 1).
    let label = members
        .devices
        .iter()
        .find(|device| same_key(&device.key, &own))
        .map(|device| device.label.clone());
    let key_line = match &label {
        Some(label) => format!("Your key is on the list, as {label}."),
        None => "Your key is not on the list.".to_string(),
    };
    let not_listed = || {
        sharing::refused(
            "not_listed",
            format!(
                "Your key is not on the list of {repository} at {commit}. Add it with a pull \
                 request, then run this again."
            ),
        )
    };
    let mut asks = vec![format!(
        "This reads the list of {repository} at commit {commit}, from your clone."
    )];
    let planned = |asks: Vec<String>, then: Then| -> Out<Plan<Following>> {
        Ok(Plan {
            asks: asks.join("\n"),
            what: Following {
                identity: repository.clone(),
                remote: read.remote.clone(),
                clone: read.top.display().to_string(),
                commit: commit.clone(),
                list: file.clone(),
                agent: agent.clone(),
                then,
            },
        })
    };
    if new {
        // Rule 2.4: only for a list that has no channel line.
        if members.channel.is_some() {
            return sharing::refused(
                "names_a_channel",
                format!(
                    "The list of {repository} at commit {commit} names a channel already, so \
                     --new makes none: run cordelia subscribe without --new."
                ),
            );
        }
        // Filed under the repository's `owner/name` (§14, answer 2).
        let name = format!("{}/{}", read.identity.owner(), read.identity.name());
        let made = sharing::new_plan(conn, own_relays, &name, &[])?;
        asks.push(no_channel_line(&repository));
        asks.push(key_line);
        asks.push(made.asks);
        asks.push(format!(
            "This follows {repository}, and subscribes {}, the agent of this folder, to the new \
             channel. Then it prints the lines to add to the list.",
            cleaned(&agent)
        ));
        return planned(asks, Then::Make(made.what));
    }
    let in_channel = keys_in_channel(conn, &own, &members)?;
    // The list names no channel: it has no channel line, or a key left out
    // is still listed (rule 1).
    let Some(line) = members.names(|key| in_channel.iter().any(|kept| same_key(kept, key))) else {
        if label.is_none() {
            return not_listed();
        }
        asks.push(no_channel_line(&repository));
        asks.push(key_line);
        asks.push(format!(
            "This follows {repository}. A member's device hands you its channel once the list \
             names one. cordelia status shows how it goes."
        ));
        return planned(asks, Then::Nothing);
    };
    let words = channel_words(&line.channel);
    if let Some(filing) = sharing::filed(conn)?
        .into_iter()
        .find(|filing| filing.channel == line.channel)
    {
        asks.push(format!(
            "It names the shared channel \"{}\" (channel {words}), which you hold.",
            cleaned(&filing.name)
        ));
        asks.push(key_line);
        asks.push(format!("This follows {repository}."));
        // Where the agent subscribes already, it still follows.
        let subscribing = crate::shared_routes::subscribe_plan(
            conn,
            identity,
            folder,
            &filing.name,
            Some(&words),
        )?;
        let then = match subscribing {
            Ok(subscribing) => {
                asks.push(subscribing.asks);
                Then::Subscribe {
                    subscription: subscribing.what,
                    name: filing.name,
                }
            }
            Err(already) => {
                asks.push(already);
                Then::Nothing
            }
        };
        return planned(asks, then);
    }
    // A channel dropped or moved from is not taken again, as `accept
    // --channel` refuses it (§3.4 there). A move is kept as a drop: each
    // is said as rules 2.3 and 6 say it. The drop keeps no name, so the
    // channel is said by its words.
    if crate::shared_anew::held_or_dropped(conn, None)?.contains(&line.channel) {
        let moved = sharing::filed(conn)?
            .iter()
            .any(|filing| filing.came == Came::Moved(line.channel));
        return match moved {
            true => sharing::refused("moved", MOVED_FROM.into()),
            false => sharing::refused(
                "dropped",
                format!("You dropped channel {words}, and a dropped channel is not taken again."),
            ),
        };
    }
    if label.is_none() {
        return not_listed();
    }
    asks.push(format!("It names channel {words}, which you do not hold."));
    asks.push(key_line);
    asks.push(format!(
        "This follows {repository}. A member's device hands you its channel once it reads the \
         list. cordelia status shows how it goes."
    ));
    planned(asks, Then::Nothing)
}

/// The keys in the channel that the list's channel line names, as this
/// device holds it ("in the channel", the record's words): in its table of
/// the channel's keys, or not moved yet (#291). None where the list has no
/// channel line, or the device holds no row of the channel.
fn keys_in_channel(
    conn: &Connection,
    own: &[u8; 32],
    members: &Members,
) -> Result<Vec<[u8; 32]>, PersonError> {
    let Some(line) = &members.channel else {
        return Ok(Vec::new());
    };
    let mut keys: Vec<[u8; 32]> = match kept::channel(conn, &line.channel)? {
        Some(row) => kept::keys(conn, row.id)?
            .into_iter()
            .map(|key| key.key)
            .collect(),
        None => Vec::new(),
    };
    keys.extend(crate::shared_anew::not_moved_yet(conn, own, &line.channel)?);
    Ok(keys)
}

// ── On the yes ───────────────────────────────────────────────────────

/// Do what `following` was planned to (rule 2.3), at `now`, in one
/// transaction: the subscription, or with `--new` the channel made and
/// subscribed to; then the follow, started afresh, and its first read.
/// Returns the lines said.
pub fn make(
    conn: &Connection,
    identity: &NodeIdentity,
    following: &Following,
    now: i64,
) -> Out<Vec<String>> {
    let held = sharing::standing(conn)?;
    in_one_or_none(conn, || {
        let mut said = Vec::new();
        let mut lines = Vec::new();
        let agent = cleaned(&following.agent);
        match &following.then {
            Then::Subscribe { subscription, name } => {
                let what = Do::Subscribe(subscription.clone());
                sharing::act(conn, identity, &held, what, now)?;
                said.push(format!(
                    "Subscribed: {agent} to \"{}\", from now on. What was written there before \
                     now is in cordelia msg log only.",
                    cleaned(name)
                ));
            }
            Then::Nothing => {}
            Then::Make(new) => {
                let (made, to_add) = make_channel(conn, identity, &held, following, new, now)?;
                said.push(made);
                lines = to_add;
            }
        }
        // Subscribing again starts afresh (decision 2026-11-06 (joining),
        // rule 2.5): the follow begins again at this commit, and whether
        // it comes after the last commit read is not asked
        // (`Git::comes_after`). So a history that was rewritten is
        // followed again this way.
        follows::follow(
            conn,
            &following.identity,
            &following.remote,
            &following.clone,
            now,
        )?;
        let read = LastRead {
            commit: following.commit.clone(),
            at: now,
            from_clone: true,
        };
        follows::read_done(conn, &following.identity, &read, &following.list)?;
        said.push(format!(
            "Following {}, from its list at commit {}. cordelia status shows how it goes.",
            following.identity, following.commit
        ));
        said.extend(lines);
        Ok(said)
    })
}

/// `--new` (rule 2.4): make the channel of `new`, as `shared new` does,
/// and subscribe the folder's agent to it. Returns the line that says so,
/// and the lines to add to the list: the channel line, and one for each
/// device of the person's that counts and that the list does not name.
fn make_channel(
    conn: &Connection,
    identity: &NodeIdentity,
    held: &Held,
    following: &Following,
    new: &New,
    now: i64,
) -> Out<(String, Vec<String>)> {
    sharing::make_new(conn, identity, new, now)?;
    let filing = sharing::filed(conn)?
        .into_iter()
        .find(|filing| filing.name == new.name)
        .ok_or_else(|| PersonError::Held("the channel just made is not filed".into()))?;
    let subscription = Subscription {
        channel: filing.channel,
        agent: following.agent.clone(),
        subscribed: true,
    };
    sharing::act(conn, identity, held, Do::Subscribe(subscription), now)?;
    let line = ChannelLine {
        channel: filing.channel,
        relays: filing.card.relays().keys().to_vec(),
        without: Vec::new(),
    }
    .to_line()
    .map_err(|why| PersonError::Held(format!("the channel line: {why}")))?;
    let mut lines = vec![
        "Add these lines to .cordelia/members in a pull request:".to_string(),
        line,
    ];
    // A key the list names already is not added again: a key twice does
    // not parse (rule 1).
    let listed = members::read(&following.list)
        .map(|members| members.devices)
        .unwrap_or_default();
    let mut keys = Vec::new();
    let mut labels = Vec::new();
    for key in crate::person::who_counts(conn)?.keys() {
        if listed.iter().any(|device| same_key(&device.key, &key)) {
            continue;
        }
        labels.push(crate::reader::label_of(
            conn,
            &held.statement.statement,
            &key,
        )?);
        keys.push(key);
    }
    let taken: Vec<String> = listed.into_iter().map(|device| device.label).collect();
    for (key, label) in keys.iter().zip(list_labels(&labels, &taken)) {
        lines.push(format!("{}   {label}", encode_public_key(key)?));
    }
    let made = format!(
        "Made \"{}\": channel {}, and subscribed {} to it.",
        cleaned(&new.name),
        channel_words(&filing.channel),
        cleaned(&following.agent)
    );
    Ok((made, lines))
}

/// `work` in one transaction: where it is refused part of the way, what it
/// wrote is undone, as it is where it fails.
fn in_one_or_none<T>(conn: &Connection, work: impl FnOnce() -> Out<T>) -> Out<T> {
    let mut refused: Option<Refusal> = None;
    let done = in_one(conn, || match work() {
        Ok(done) => Ok(done),
        Err(Failed::Refused(refusal)) => {
            refused = Some(refusal);
            // Stands for the refusal, so that the work is undone.
            Err(PersonError::ChangedSincePrompt)
        }
        Err(Failed::Error(e)) => Err(e),
    });
    match (done, refused) {
        (Ok(done), _) => Ok(done),
        (Err(PersonError::ChangedSincePrompt), Some(refusal)) => Err(Failed::Refused(refusal)),
        (Err(e), _) => Err(Failed::Error(e)),
    }
}

// ── Labels for the list (rule 2.4) ───────────────────────────────────

/// A label for the list (rule 1) made from a device's own label: in lower
/// case, each character other than `a-z`, `0-9`, `.`, `_` and `-` a `-`,
/// each run of `-` one, none at either end, and cut to 32. It may be
/// empty.
fn label_from(label: &str) -> String {
    let mut made = String::new();
    for c in label.to_lowercase().chars() {
        let c = match c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_') {
            true => c,
            false => '-',
        };
        if c == '-' && (made.is_empty() || made.ends_with('-')) {
            continue;
        }
        made.push(c);
    }
    // Only ASCII is left, so a byte is a character.
    made.truncate(MEMBERS_LABEL_MAX_CHARS);
    while made.ends_with('-') {
        made.pop();
    }
    made
}

/// Labels for the list made from `labels`, each a device's own, in order
/// ([`label_from`]): one that ends up empty, or the same as one in
/// `taken` or made before it, has `-2` added, or `-3`, and so on, cut so
/// that it stays within 32. Each is a label that the list takes.
pub fn list_labels(labels: &[String], taken: &[String]) -> Vec<String> {
    let mut made: Vec<String> = Vec::new();
    for label in labels {
        let base = label_from(label);
        let mut label = base.clone();
        let mut n = 2u32;
        while label.is_empty() || taken.contains(&label) || made.contains(&label) {
            let after = format!("-{n}");
            let mut cut = base.clone();
            cut.truncate(MEMBERS_LABEL_MAX_CHARS - after.len());
            while cut.ends_with('-') {
                cut.pop();
            }
            label = format!("{cut}{after}");
            n += 1;
        }
        made.push(label);
    }
    made
}

#[cfg(test)]
mod tests;
