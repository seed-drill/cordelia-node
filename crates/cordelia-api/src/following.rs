//! Following a repository (decision 2026-11-06 (joining), rule 2):
//! `cordelia subscribe` in a clone, with no name, and `--new`.
//!
//! - **The clone is read outside the node's lock** ([`read_of`]), within
//!   one deadline: the top of the work tree the folder is in, the remote
//!   whose repository it is (`--remote` chooses among several), the list
//!   at that remote's default branch, and, where this device follows the
//!   repository already, whether the clone's commit comes after the last
//!   one read. Each is by [`crate::git_list`]. Where any of it fails,
//!   nothing is done, and it says why.
//! - **Under the lock, the plan** ([`plan`], rule 2.3), on the list's
//!   channel line whatever rule 1's gate says: a person who holds that
//!   channel follows the repository, and the folder's agent is subscribed
//!   to it; one who does not, and whose key is on the list, follows and
//!   waits, its agent subscribed once it takes the channel; one whose key
//!   is not on the list, or who
//!   dropped or moved from that channel, is refused. What it shows is rule
//!   2.2's: the repository, the commit, the channel the list names, and
//!   whether this device's key is on the list; and the clone and its
//!   remote, and where this device read last. So its yes names the commit
//!   and the clone (rule 2.5), and a yes typed against another is refused,
//!   as any yes to a text that changed is.
//! - **On the yes, in one transaction** ([`make`]): the subscription, and
//!   the follow, with its first read; or, following again, never-back
//!   started over. With `--new` (rule 2.4), the channel is made first, and
//!   the lines to add to the list are said.
//! - **Every follow goes** where the device leaves its person
//!   (`leaving::forget`, rule 2.5).

use std::path::{Path, PathBuf};
use std::time::Instant;

use rusqlite::Connection;

use cordelia_core::protocol::{MEMBERS_LABEL_MAX_CHARS, SHARED_MAX_CHANNELS, SHARED_MAX_KEYS};
use cordelia_crypto::acts::{Filing, Subscription};
use cordelia_crypto::bech32::encode_public_key;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_storage::follows::{self, LastRead};
use cordelia_storage::shared as kept;

use crate::git_list::{ClonedList, Git, Identity, ListFailed, RemoteRefused};
use crate::lists::Do;
use crate::members::{self, ChannelLine, Members, same_key};
use crate::messages::cleaned;
use crate::person::{Held, PersonError, in_one};
use crate::shared_anew::{Gone, OfferIs};
use crate::sharing::{self, Failed, New, Out, OwnRelay, Plan, Refusal, channel_words};

// ── The clone, read outside the lock ─────────────────────────────────

/// What `subscribe` read of a clone: the repository, the remote whose
/// address names it, the top of the clone's work tree, the list, and,
/// where this device follows the repository already, how the clone's
/// commit stands against the last one read.
#[derive(Debug, Clone)]
pub struct ClonedRead {
    pub identity: Identity,
    pub remote: String,
    pub top: PathBuf,
    pub list: ClonedList,
    pub after_last: Option<AfterLast>,
}

/// The last commit this device read of a repository it follows, and
/// whether the clone's commit is it or comes after it (rule 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AfterLast {
    pub last: String,
    pub comes_after: bool,
}

/// The last commit read of each repository this device follows, by its
/// identity: taken in a short hold of the lock before the clone is read.
pub fn last_reads(conn: &Connection) -> Result<Vec<(String, String)>, PersonError> {
    Ok(follows::follows(conn)?
        .into_iter()
        .filter_map(|follow| follow.last.map(|last| (follow.identity, last.commit)))
        .collect())
}

/// What `subscribe` with no name says where git did not answer within the
/// `secs` its whole read is given.
pub fn late_line(secs: u64) -> String {
    format!("git did not answer in {secs} seconds, so nothing was done.")
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
/// `data_dir` (rules 2.1 and 3), with every step of git given until
/// `deadline`, which is `secs` from when the route began. It runs outside
/// the node's lock: git may take seconds. `chosen` is the remote
/// `--remote` named; `lasts` are [`last_reads`].
pub fn read_of(
    data_dir: &Path,
    folder: &Path,
    chosen: Option<&str>,
    lasts: &[(String, String)],
    deadline: Instant,
    secs: u64,
) -> Out<ClonedRead> {
    let git =
        Git::under(data_dir).map_err(|e| PersonError::Held(format!("the node's git: {e}")))?;
    read_with(&git, folder, chosen, lasts, deadline, secs)
}

/// [`read_of`], with the node's git given, and the deadline, which is
/// `secs` from when it began. No step of git begins after it.
pub fn read_with(
    git: &Git,
    folder: &Path,
    chosen: Option<&str>,
    lasts: &[(String, String)],
    deadline: Instant,
    secs: u64,
) -> Out<ClonedRead> {
    let late = || sharing::refused("late", late_line(secs));
    if Instant::now() >= deadline {
        return late();
    }
    let top = match git.top_of(folder, deadline) {
        Ok(top) => top,
        Err(ListFailed::NotARepository) => {
            return sharing::refused("not_a_repository", NOT_IN_A_CLONE.into());
        }
        Err(failed) => return not_read(None, &failed),
    };
    if Instant::now() >= deadline {
        return late();
    }
    let (remote, identity) = match git.identity_of_clone_by(&top, chosen, deadline) {
        Ok(chosen) => chosen,
        Err(RemoteRefused::Git(failed)) => return not_read(None, &failed),
        Err(why) => {
            return sharing::refused(why.code(), format!("{} Nothing was done.", why.says()));
        }
    };
    if Instant::now() >= deadline {
        return late();
    }
    let list = match git.read_clone_by(&top, &remote, &identity, deadline) {
        Ok(list) => list,
        Err(failed) => return not_read(Some(&identity), &failed),
    };
    // Where this device follows the repository already: whether this
    // clone's commit goes back from the last one read (rule 3), for the
    // yes to say so (rule 2.5).
    let followed = identity.to_string();
    let after_last = match lasts.iter().find(|(of, _)| *of == followed) {
        Some((_, last)) => {
            if Instant::now() >= deadline {
                return late();
            }
            match git.comes_after_by(&top, last, &list.at.commit, deadline) {
                Ok(comes_after) => Some(AfterLast {
                    last: last.clone(),
                    comes_after,
                }),
                Err(failed) => return not_read(Some(&identity), &failed),
            }
        }
        None => None,
    };
    Ok(ClonedRead {
        identity,
        remote,
        top,
        list,
        after_last,
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
    /// When the person's git had last fetched it, where the clone says.
    pub fetched_at: Option<i64>,
    /// The other repository this device follows whose list names the same
    /// channel, where one does: this follow takes its place (rule 2.5).
    pub replaces: Option<String>,
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
pub(crate) fn no_channel_line(repository: &str) -> String {
    format!("The list of {repository} names no channel yet.")
}

/// What `cordelia subscribe` with no name would do, given what was read
/// of the clone (rule 2.3), and its yes; or, with `new`, what `--new`
/// would make (rule 2.4). `own_relays` are the device's relays known by
/// their keys.
pub fn plan(
    conn: &Connection,
    identity: &NodeIdentity,
    own_relays: &[OwnRelay],
    read: &ClonedRead,
    new: bool,
) -> Out<Plan<Following>> {
    sharing::standing(conn)?;
    // The agent is the one mapped at the clone's top, the folder the
    // follow keeps: so the agent the yes names is the one the node
    // subscribes when it takes the channel (decision 2026-11-06 (joining),
    // rule 4.4). The command sends the folder whose memory the session
    // keeps, which is that top.
    let clone = read.top.display().to_string();
    let agent = crate::shared_routes::agent_here(conn, &clone)?;
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
    // A channel follows one repository (rule 2.5): a follow of another
    // whose list names this list's channel is replaced by this one.
    let replaces = match &members.channel {
        Some(line) => followed_elsewhere(conn, &repository, &line.channel)?,
        None => None,
    };
    // A device follows as many repositories as it holds shared channels at
    // most: each follow's list names one, and the status works out each
    // follow under the lock.
    let followed = follows::follows(conn)?;
    let adds_one =
        replaces.is_none() && !followed.iter().any(|follow| follow.identity == repository);
    if adds_one && followed.len() >= SHARED_MAX_CHANNELS {
        return sharing::refused("too_many_follows", too_many_follows_line());
    }
    let own = identity.public_key();
    // Only this device's key as `cordelia id` prints it counts: a member's
    // share to its twin is in another share pair channel, which this
    // device never reads (rule 4.4).
    let label = members.line_of(&own).map(|device| device.label.clone());
    let key_line = match &label {
        Some(label) => format!("Your key is on the list, as {label}."),
        None => "Your key is not on the list.".to_string(),
    };
    let not_listed = || match members.lists(&own) {
        true => sharing::refused("twin_listed", twin_line(&repository, &own)?),
        false => sharing::refused(
            "not_listed",
            format!(
                "Your key is not on the list of {repository} at {commit}. Add it with a pull \
                 request, then run this again."
            ),
        ),
    };
    // The yes names this clone and its remote, so that it is a yes to no
    // other clone or remote of the repository at this commit.
    let mut asks = vec![format!(
        "This reads the list of {repository} at commit {commit}, from your clone at {}, \
         through its remote {}.",
        cleaned(&clone),
        cleaned(&read.remote)
    )];
    // Following again starts never-back over (rule 2.5): the yes says where
    // this device read last, and whether this clone would go back from it.
    if let Some(row) = follows::follow_of(conn, &repository)? {
        let last = row.last.map(|last| last.commit);
        if last != read.after_last.as_ref().map(|after| after.last.clone()) {
            // The follow was read again while the clone was read.
            return sharing::refused("changed", crate::sharing_routes::CHANGED.into());
        }
        let from = cleaned(&row.clone);
        asks.push(match &last {
            Some(last) => {
                format!("This device follows {repository} already, from {from} at {last}.")
            }
            None => format!("This device follows {repository} already, from {from}."),
        });
        if read
            .after_last
            .as_ref()
            .is_some_and(|after| !after.comes_after)
        {
            asks.push(format!(
                "Your clone is at {commit}, which does not come after it: you would read an older \
                 or another list."
            ));
        }
    }
    let planned = |asks: Vec<String>, then: Then| -> Out<Plan<Following>> {
        Ok(Plan {
            asks: asks.join("\n"),
            what: Following {
                identity: repository.clone(),
                remote: read.remote.clone(),
                clone: clone.clone(),
                commit: commit.clone(),
                list: file.clone(),
                fetched_at: read.list.fetched_at(),
                replaces: replaces.clone(),
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
        let name = name_of(&read.identity);
        name_free(conn, &name)?;
        // The lines it says to add must leave a list of at most 64 (rule 1).
        let would = members.devices.len() + to_add(conn, &members)?.len();
        if would > SHARED_MAX_KEYS {
            return sharing::refused(
                "channel_full",
                format!(
                    "With your devices, the list of {repository} would name {would}, and a list \
                     names 64 at most: delete some lines in a pull request first. Nothing was \
                     made."
                ),
            );
        }
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
    // The folder's agent of a device that takes the channel is subscribed
    // to it as it takes it (rule 4.4), from the follow's clone.
    let once_taken = format!(
        "The agent of this folder, {}, is subscribed to it once this device takes it.",
        cleaned(&agent)
    );
    let Some(line) = &members.channel else {
        if label.is_none() {
            return not_listed();
        }
        asks.push(no_channel_line(&repository));
        asks.push(key_line);
        asks.push(format!(
            "This follows {repository}. A member's device hands you its channel once the list \
             names one. cordelia status shows how it goes."
        ));
        asks.push(once_taken);
        return planned(asks, Then::Nothing);
    };
    let words = channel_words(&line.channel);
    // Rule 2.3's cases are taken on the channel line, whatever rule 1's gate
    // says; the gate then says what waits for it.
    let in_channel = keys_in_channel(conn, &own, &members)?;
    let gated: Vec<String> = members
        .gated(|key| in_channel.iter().any(|kept| same_key(kept, key)))
        .into_iter()
        .map(|device| device.label.clone())
        .collect();
    let gate_lines = |name: &str| -> Vec<String> {
        gated
            .iter()
            .map(|label| {
                format!(
                    "{label} is on the list of {name} but was left out of it: nothing is handed \
                     over until its line goes, or it writes in the channel."
                )
            })
            .collect()
    };
    let filings = sharing::filed(conn)?;
    // A channel follows one repository, so that no two lists hand it over,
    // or delete its shares (rule 2.5): the yes says which follow stops.
    if let Some(other) = &replaces {
        asks.push(stops_following_line(
            other,
            &channel_named(conn, &line.channel)?,
        ));
    }
    if let Some(filing) = filings.iter().find(|filing| filing.channel == line.channel) {
        let name = cleaned(&filing.name);
        asks.push(format!(
            "It names the shared channel \"{name}\" (channel {words}), which you hold."
        ));
        asks.push(key_line);
        // The gate holds back hand-overs and takes alone: a subscription is
        // neither, so the agent of a holder is subscribed now, whatever it
        // says. Where the agent subscribes already, it still follows.
        asks.extend(gate_lines(&name));
        asks.push(format!("This follows {repository}."));
        let subscribing = crate::shared_routes::subscribe_plan(
            conn,
            identity,
            &clone,
            &filing.name,
            Some(&words),
        )?;
        let then = match subscribing {
            Err(already) => {
                asks.push(already);
                Then::Nothing
            }
            Ok(subscribing) => {
                asks.push(subscribing.asks);
                Then::Subscribe {
                    subscription: subscribing.what,
                    name: filing.name.clone(),
                }
            }
        };
        return planned(asks, then);
    }
    // A channel dropped or moved from is not taken again, as `accept
    // --channel` refuses it (§3.4 there). A move is kept as a drop: each
    // is said as rules 2.3 and 6 say it. The drop keeps no name, so the
    // channel is said by its words.
    match crate::shared_anew::dropped_or_moved(conn, &line.channel)? {
        Some(Gone::Moved) => return sharing::refused("moved", MOVED_FROM.into()),
        Some(Gone::Dropped) => {
            return sharing::refused(
                "dropped",
                format!("You dropped channel {words}, and a dropped channel is not taken again."),
            );
        }
        None => {}
    }
    // The person holds the channel the named one was made anew from: they
    // move to it, and nobody hands it to them (rule 6).
    if let Some(from) = made_anew_from(conn, identity, &filings, &line.channel)? {
        asks.push(format!("It names channel {words}, which you do not hold."));
        asks.push(key_line);
        asks.push(format!(
            "Run cordelia shared move {}: the list names the channel it was made anew as.",
            crate::shared_routes::shell_word(&from.name)
        ));
        asks.push(format!("This follows {repository}."));
        return planned(asks, Then::Nothing);
    }
    if label.is_none() {
        return not_listed();
    }
    asks.push(format!("It names channel {words}, which you do not hold."));
    asks.push(key_line);
    match gated.is_empty() {
        true => asks.push(format!(
            "This follows {repository}. A member's device hands you its channel once it reads the \
             list. cordelia status shows how it goes."
        )),
        false => {
            asks.extend(gate_lines(&format!("channel {words}")));
            asks.push(format!(
                "This follows {repository}. cordelia status shows how it goes."
            ));
        }
    }
    asks.push(once_taken);
    planned(asks, Then::Nothing)
}

/// What `subscribe` in a clone says where this device follows as many
/// repositories as there can be.
pub(crate) fn too_many_follows_line() -> String {
    format!(
        "This device follows {SHARED_MAX_CHANNELS} repositories, the most it can. To follow \
         another, first run cordelia unsubscribe in a clone of one it follows. Nothing was done."
    )
}

/// What is said where the list of `repository` names a twin of this
/// device's key `own`, and not the key as `cordelia id` prints it (rule
/// 4.4).
pub(crate) fn twin_line(repository: &str, own: &[u8; 32]) -> Result<String, PersonError> {
    Ok(format!(
        "The list of {repository} names your key in another form: list it as cordelia id prints \
         it, {}.",
        encode_public_key(own)?
    ))
}

/// The name a repository's channel is filed under, made or taken: the
/// repository's `owner/name` (§14, answer 2).
pub(crate) fn name_of(identity: &Identity) -> String {
    format!("{}/{}", identity.owner(), identity.name())
}

/// `name`, a repository's `owner/name`, is free to file its channel under
/// (rule 6): no other channel is filed as it, and no folder is synced as
/// it. Refused, as `name_taken`, with what frees it.
pub(crate) fn name_free(conn: &Connection, name: &str) -> Out<()> {
    name_free_in(conn, &sharing::filed(conn)?, name)
}

/// [`name_free`], given the person's filings.
pub(crate) fn name_free_in(conn: &Connection, filings: &[Filing], name: &str) -> Out<()> {
    if filings.iter().any(|filing| filing.name == name) {
        return sharing::refused(
            "name_taken",
            format!("You file another channel as {name}: rename it with cordelia shared rename."),
        );
    }
    let mappings = crate::sync::mappings(conn).map_err(|e| PersonError::Held(e.to_string()))?;
    if let Some(mapped) = mappings.iter().find(|mapping| mapping.name == name) {
        return sharing::refused(
            "name_taken",
            format!(
                "You sync a folder as {name}: to free the name, unmap it with cordelia sync unmap \
                 {}, then map it under another name.",
                crate::shared_routes::shell_word(&mapped.folder)
            ),
        );
    }
    Ok(())
}

/// The filing of the channel the person holds that `channel` was made
/// anew from, among `filings`, where one is: they move to it, and nobody
/// hands it to them (rule 6). Only an offer that counts says so, judged as
/// `shared move` judges it: one for this device, or sealed to another of
/// the person's. An offer "without you" leaves the person nothing to move
/// to, and one that is a fault does not count. (Either way a device that
/// read it hands that channel over no more, rule 4.1, unless it is a
/// fault.)
pub(crate) fn made_anew_from<'a>(
    conn: &Connection,
    identity: &NodeIdentity,
    filings: &'a [Filing],
    channel: &[u8; 32],
) -> Result<Option<&'a Filing>, PersonError> {
    for filing in filings {
        if made_anew_as(conn, identity, filing)?.contains(channel) {
            return Ok(Some(filing));
        }
    }
    Ok(None)
}

/// Each channel that an offer read in the channel of `filing` made it anew
/// as, where the offer counts as [`made_anew_from`] counts one.
pub(crate) fn made_anew_as(
    conn: &Connection,
    identity: &NodeIdentity,
    filing: &Filing,
) -> Result<Vec<[u8; 32]>, PersonError> {
    let Some(row) = kept::channel(conn, &filing.channel)? else {
        return Ok(Vec::new());
    };
    Ok(crate::shared_anew::judged(conn, identity, &row, None)?
        .into_iter()
        .filter(|one| {
            matches!(
                one.is,
                OfferIs::ForThisDevice(_) | OfferIs::SealedElsewhere(_)
            )
        })
        .map(|one| one.offer.new_channel)
        .collect())
}

/// The other repository this device follows whose list kept names the
/// channel `channel`, where one does (rule 2.5). A channel follows one
/// repository: two lists that named one channel would each hand it over,
/// write over the other's shares, and delete a share to a key one of them
/// no longer names while the other names it still.
pub(crate) fn followed_elsewhere(
    conn: &Connection,
    repository: &str,
    channel: &[u8; 32],
) -> Result<Option<String>, PersonError> {
    for follow in follows::follows(conn)? {
        let names = follow
            .list
            .as_deref()
            .and_then(|list| members::read(list).ok())
            .and_then(|members| members.channel)
            .is_some_and(|line| line.channel == *channel);
        if names && follow.identity != repository {
            return Ok(Some(follow.identity));
        }
    }
    Ok(None)
}

/// The list kept of each repository this device follows, read, in the
/// order of the follows: one whose channel line names a channel is the list
/// of that channel, as a channel follows one repository (rule 2.5). Rule 1's
/// gate is not asked: the line names the channel whether or not the list
/// holds it back.
pub(crate) fn lists_followed(conn: &Connection) -> Result<Vec<Members>, PersonError> {
    Ok(follows::follows(conn)?
        .into_iter()
        .filter_map(|follow| members::read(follow.list.as_deref()?).ok())
        .collect())
}

/// What the yes of `subscribe` in a clone says where it replaces the
/// follow of `other`, whose list names `name` too (rule 2.5).
pub(crate) fn stops_following_line(other: &str, name: &str) -> String {
    format!(
        "This stops following {other}, whose list names {name} too: a channel follows one \
         repository."
    )
}

/// What is said of a read of the list of `repository` that names `name`,
/// which this device follows from `other`: the read counts for nothing
/// (rules 2.5 and 6).
pub(crate) fn followed_from_line(repository: &str, name: &str, other: &str) -> String {
    format!(
        "The list of {repository} names {name}, which this device follows from {other}: run \
         cordelia subscribe in a clone of the one it should follow."
    )
}

/// The channel `channel` as a line says it: by the person's name for it,
/// where they hold it, or else by its words.
pub(crate) fn channel_named(conn: &Connection, channel: &[u8; 32]) -> Result<String, PersonError> {
    Ok(
        match sharing::filed(conn)?
            .into_iter()
            .find(|filing| filing.channel == *channel)
        {
            Some(filing) => format!("\"{}\"", cleaned(&filing.name)),
            None => format!("channel {}", channel_words(channel)),
        },
    )
}

/// The keys of the person's devices that count and that `members` does not
/// name, a twin counting as its key: those `--new` says to add (rule 2.4).
fn to_add(conn: &Connection, members: &Members) -> Result<Vec<[u8; 32]>, PersonError> {
    Ok(crate::person::who_counts(conn)?
        .keys()
        .into_iter()
        .filter(|key| !members.lists(key))
        .collect())
}

/// The keys in the channel that the list's channel line names, as this
/// device holds it ("in the channel", the record's words): in its table of
/// the channel's keys, or not moved yet (#291). None where the list has no
/// channel line, or the device holds no row of the channel.
pub(crate) fn keys_in_channel(
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

/// The channel `channel`, then each channel it was made anew from, back
/// along the moves this device keeps (a row's `came`), nearest first: at
/// most one more than the 64 drops a list keeps. A channel made anew past
/// a bound is filed by no device, so its chain is itself alone.
pub(crate) fn back_along_moves(
    conn: &Connection,
    channel: &[u8; 32],
) -> Result<Vec<[u8; 32]>, PersonError> {
    let mut chain = vec![*channel];
    let mut at = *channel;
    for _ in 0..cordelia_core::protocol::SHARED_MAX_DROPPED {
        match kept::channel(conn, &at)?.map(|row| row.came) {
            Some(kept::Came::Moved(from)) if !chain.contains(&from) => {
                chain.push(from);
                at = from;
            }
            _ => break,
        }
    }
    Ok(chain)
}

// ── Following no more: `unsubscribe` in a clone ─────────────────────

/// What `unsubscribe` with no name read of the clone a folder is in: the
/// top of its work tree, and the repository its remote names, where one
/// remote names one.
#[derive(Debug, Clone)]
pub struct CloneOf {
    pub top: PathBuf,
    pub identity: Option<String>,
}

/// What `unsubscribe` with no name says in a folder of no repository.
pub const NOT_IN_A_CLONE_TO_STOP: &str = "This folder is not in a git repository, so this device \
                                          follows no repository from it, and nothing was done. \
                                          To unsubscribe its agent from a shared channel, give \
                                          the channel's name: cordelia unsubscribe <name>";

/// Read the clone that `folder` is in, with the node's git under
/// `data_dir`, until `deadline`, outside the node's lock: its top, and the
/// repository its remote names (decision 2026-11-06 (joining), rule 2.5).
pub fn clone_of(data_dir: &Path, folder: &Path, deadline: Instant) -> Out<CloneOf> {
    let git =
        Git::under(data_dir).map_err(|e| PersonError::Held(format!("the node's git: {e}")))?;
    let top = match git.top_of(folder, deadline) {
        Ok(top) => top,
        Err(ListFailed::NotARepository) => {
            return sharing::refused("not_a_repository", NOT_IN_A_CLONE_TO_STOP.into());
        }
        Err(failed) => return not_read(None, &failed),
    };
    let identity = git
        .identity_of_clone_by(&top, None, deadline)
        .ok()
        .map(|(_, identity)| identity.to_string());
    Ok(CloneOf { top, identity })
}

/// `cordelia unsubscribe` with no name, in a clone (rule 2.5), in one
/// write: this device follows no more the repository it follows from that
/// clone, or whose identity the clone's remote names. No yes, as
/// `unsubscribe` asks none: it drops no channel and unsubscribes no agent,
/// and `subscribe` there follows again. Returns what it says.
pub fn unfollow(conn: &Connection, read: &CloneOf) -> Out<Vec<String>> {
    let top = read.top.display().to_string();
    let stopped = in_one(conn, || {
        let mut stopped = Vec::new();
        for follow in follows::follows(conn)? {
            if follow.clone == top || read.identity.as_deref() == Some(follow.identity.as_str()) {
                follows::unfollow(conn, &follow.identity)?;
                stopped.push(follow.identity);
            }
        }
        Ok(stopped)
    })?;
    if stopped.is_empty() {
        return sharing::refused(
            "not_followed",
            format!(
                "This device follows no repository from your clone at {}.",
                cleaned(&top)
            ),
        );
    }
    Ok(stopped
        .iter()
        .map(|identity| format!("This device follows {identity} no more."))
        .collect())
}

// ── On the yes ───────────────────────────────────────────────────────

/// Do what `following` was planned to (rule 2.3), at `now`, in one
/// transaction: the subscription, or with `--new` the channel made and
/// subscribed to; then the follow, with its first read, or, where this
/// device follows the repository already, never-back started over.
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
        // Subscribing again starts never-back over (decision 2026-11-06
        // (joining), rule 2.5), for a history that was rewritten: the yes
        // said whether this clone goes back from the last commit read, and
        // the commit it named is where never-back starts now. The list
        // last read is kept, and not this one: the node's next read, woken
        // now, compares the list it reads with it (rules 4.5 and 4.6). A
        // first follow keeps this read whole, and its list names each key
        // on it as new (rule 4.5, as the person ruled on 10 November).
        // The follow this one replaces stops first, in the same write: a
        // channel follows one repository (rule 2.5).
        if let Some(other) = &following.replaces {
            follows::unfollow(conn, other)?;
        }
        let earlier = follows::follow_of(conn, &following.identity)?;
        follows::follow(
            conn,
            &following.identity,
            &following.remote,
            &following.clone,
            now,
        )?;
        let mut read = LastRead {
            commit: following.commit.clone(),
            at: now,
            from_clone: true,
        };
        match earlier {
            Some(earlier) => {
                read.at = earlier.last.map_or(now, |last| last.at);
                follows::set_last_read(conn, &following.identity, &read)?;
            }
            None => {
                follows::read_done(
                    conn,
                    &following.identity,
                    &read,
                    &following.list,
                    following.fetched_at,
                )?;
                if let Ok(list) = members::read(&following.list) {
                    let commit = &following.commit;
                    let of = &following.identity;
                    crate::members_read::joined(conn, identity, of, None, &list, commit, now)?;
                }
            }
        };
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
    let listed = members::read(&following.list).unwrap_or(Members {
        channel: None,
        devices: Vec::new(),
    });
    let keys = to_add(conn, &listed)?;
    let mut labels = Vec::new();
    for key in &keys {
        labels.push(crate::reader::label_of(
            conn,
            &held.statement.statement,
            key,
        )?);
    }
    let taken: Vec<String> = listed
        .devices
        .into_iter()
        .map(|device| device.label)
        .collect();
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
pub(crate) mod tests;
