//! The node's read of each repository's list it follows (decision
//! 2026-11-06 (joining), rules 3 and 4): every
//! [`MEMBERS_READ_INTERVAL_SECS`](cordelia_core::protocol::MEMBERS_READ_INTERVAL_SECS),
//! at its start, and when a person follows a repository.
//!
//! - **Each clone is read outside the lock** ([`read_clones`]): the list at
//!   its remote's default branch, as the person's own git last fetched it,
//!   and, where a list was read before, whether the clone's commit is the
//!   last one read or comes after it. The node fetches nothing itself.
//! - **Then each read, under the lock, in one transaction**
//!   ([`after_read`]):
//!   - first, a follow whose list names a channel the person dropped, on
//!     this device or another, is stopped (rule 2.5);
//!   - a read that failed, whose commit does not come after the last one,
//!     or whose list does not parse counts for nothing: the last list
//!     stands, and why is kept for the status;
//!   - otherwise the list is kept, and rule 4 is done, with the list
//!     compared with the one kept before by what it says, never by its
//!     commit: the notices of rules 4.5, 4.6 and 6; the shares to keys the
//!     list no longer names deleted, and the node's own after two reads
//!     (rules 4.2 and 4.3); and, where this device acts in the channel the
//!     list names ([`acts_in`], rule 4.1), the channel handed to the next
//!     four keys in turn (rule 4.2).
//! - **What a status shows of it** is kept in the follow's row (the list,
//!   and why a read counted for nothing), and worked out from it again:
//!   [`acts_in`] says why nothing is handed over, and with it the keys
//!   rule 4.7 names (rule 1's gate).

use std::path::Path;

use rusqlite::Connection;

use cordelia_core::protocol::{MEMBERS_HANDED_AT_ONCE, SHARED_MAX_KEYS};
use cordelia_crypto::acts::{Came, Filing};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_storage::follows::{self, Follow, LastRead, NotRead, Notice, NoticeOf};
use cordelia_storage::shared::{self as kept, State};
use cordelia_storage::shared_sharing as share_rows;

use crate::following::keys_in_channel;
use crate::git_list::{ClonedList, Git, Identity, ListFailed};
use crate::lists::{self, AnyAct};
use crate::members::{self, ChannelLine, Members, same_key};
use crate::person::{Held, PersonError, in_one};
use crate::sharing::{self, Failed, OwnRelay, ShareTo};
use crate::state::AppState;

// ── The clones, read outside the lock ────────────────────────────────

/// What was read of one follow's clone: the follow as it was when the read
/// began, and the list, or why it was not read.
#[derive(Debug, Clone)]
pub struct CloneRead {
    pub follow: Follow,
    pub read: Result<Read, ListFailed>,
}

/// A list read from a clone, and whether its commit is the last one read
/// or comes after it (rule 3): so it does where none was read before.
#[derive(Debug, Clone)]
pub struct Read {
    pub list: ClonedList,
    pub comes_after: bool,
}

/// Read the clone of each of `follows` with the node's `git`, outside the
/// lock (rule 3): the list at `refs/remotes/<remote>/<branch>` of the
/// follow's clone and remote, where that remote still names the
/// repository, and, where the follow has a last commit, whether the
/// clone's commit is it or comes after it. Git may take seconds for each.
pub fn read_clones(git: &Git, follows: Vec<Follow>) -> Vec<CloneRead> {
    follows
        .into_iter()
        .map(|follow| {
            let read = read_clone(git, &follow);
            CloneRead { follow, read }
        })
        .collect()
}

fn read_clone(git: &Git, follow: &Follow) -> Result<Read, ListFailed> {
    let identity = Identity::from_text(&follow.identity).ok_or_else(|| {
        ListFailed::Git(format!(
            "{} is not a repository's identity",
            follow.identity
        ))
    })?;
    let clone = Path::new(&follow.clone);
    let list = git.read_clone(clone, &follow.remote, &identity)?;
    // Never back: the commit read is the last one read or comes after it.
    // A follow with no last commit, as after following again, takes the
    // commit as it is: the person's yes said whether it was behind.
    let comes_after = match &follow.last {
        Some(last) => git.comes_after(clone, &last.commit, &list.at.commit)?,
        None => true,
    };
    Ok(Read { list, comes_after })
}

// ── Each read, under the lock ────────────────────────────────────────

/// What a read came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Done {
    /// Nothing was done: the device does not stand applied with sync on,
    /// or the follow went, or was followed again, while its clone was read.
    /// The next read does it.
    Nothing,
    /// The follow was stopped: its list names a channel the person dropped
    /// (rule 2.5).
    Stopped,
    /// The read counted for nothing, and the last list stands.
    NotRead(NotRead),
    /// The list was kept and rule 4 done: the keys the channel was handed
    /// to, in turn, or why it was handed to none (rule 4.1).
    Read {
        handed: Vec<[u8; 32]>,
        not_handing: Option<NotHanding>,
    },
}

/// Do what `read` came to, under the lock, at `now`, in one transaction
/// (rules 2.5, 3 and 4): see the module's documentation. `own_relays` are
/// the device's relays known by their keys.
pub fn after_read(
    conn: &Connection,
    identity: &NodeIdentity,
    own_relays: &[OwnRelay],
    read: &CloneRead,
    now: i64,
) -> Result<Done, PersonError> {
    let held = match sharing::standing(conn) {
        Ok(held) => held,
        Err(Failed::Refused(_)) => return Ok(Done::Nothing),
        Err(Failed::Error(e)) => return Err(e),
    };
    in_one(conn, || {
        let Some(follow) = follows::follow_of(conn, &read.follow.identity)? else {
            return Ok(Done::Nothing);
        };
        if !same_follow(&follow, &read.follow) {
            return Ok(Done::Nothing);
        }
        let kept_list = follow
            .list
            .as_deref()
            .and_then(|list| members::read(list).ok());
        let latest = latest_of(read);
        // First, rule 2.5: a drop of the channel the list names stops the
        // follow, whether it was made on this device or another.
        let dropped = dropped(conn)?;
        let names_dropped = |members: &Members| {
            members
                .channel
                .as_ref()
                .is_some_and(|line| dropped.contains(&line.channel))
        };
        if kept_list.as_ref().is_some_and(names_dropped)
            || latest
                .as_ref()
                .is_ok_and(|(_, _, list)| names_dropped(list))
        {
            follows::unfollow(conn, &follow.identity)?;
            return Ok(Done::Stopped);
        }
        let (commit, file, list) = match latest {
            Ok(latest) => latest,
            Err(not) => {
                follows::not_read(conn, &follow.identity, &not)?;
                return Ok(Done::NotRead(not));
            }
        };
        let done = LastRead {
            commit: commit.clone(),
            at: now,
            from_clone: true,
        };
        follows::read_done(conn, &follow.identity, &done, &file)?;
        noticed(
            conn,
            identity,
            &follow,
            kept_list.as_ref(),
            &list,
            &commit,
            now,
        )?;
        shares_go(conn, identity, &follow, kept_list.as_ref(), &list, now)?;
        let (handed, not_handing) = match acts_in(conn, identity, own_relays, &list)? {
            Ok((line, filing)) => {
                let handed = hand_over(
                    conn, identity, &held, own_relays, &follow, &list, line, &filing, now,
                )?;
                (handed, None)
            }
            Err(why) => (Vec::new(), Some(why)),
        };
        Ok(Done::Read {
            handed,
            not_handing,
        })
    })
}

/// Whether the follow `now` is the one `then` was read for: the same
/// clone and remote, and the same last commit, against which never-back
/// was checked. A follow made again while its clone was read is read again
/// later.
fn same_follow(now: &Follow, then: &Follow) -> bool {
    let commit = |follow: &Follow| follow.last.as_ref().map(|last| last.commit.clone());
    now.clone == then.clone && now.remote == then.remote && commit(now) == commit(then)
}

/// The commit, the bytes and the list that `read` gives, or why it counts
/// for nothing (rules 1 and 3): it failed, its commit does not come after
/// the last one read, or its list does not parse. A clone with no list is a
/// list with no members and no channel.
fn latest_of(read: &CloneRead) -> Result<(String, Vec<u8>, Members), NotRead> {
    let got = read.read.as_ref().map_err(|failed| NotRead {
        word: failed.code().into(),
        why: failed.says(),
    })?;
    let commit = &got.list.at.commit;
    if !got.comes_after {
        let last = read
            .follow
            .last
            .as_ref()
            .map(|last| last.commit.as_str())
            .unwrap_or_default();
        return Err(NotRead {
            word: "behind".into(),
            why: format!(
                "your clone is at commit {commit}, which does not come after commit {last}, the \
                 last one read"
            ),
        });
    }
    let file = got.list.at.file.clone().unwrap_or_default();
    let list = members::read(&file).map_err(|not| NotRead {
        word: "not_a_list".into(),
        why: not.to_string(),
    })?;
    Ok((commit.clone(), file, list))
}

/// The channels the person dropped, on this device or another, as the
/// person's lists say (§3.4 there), those a bound leaves out among them:
/// not those they moved from, which a move keeps as a drop (rule 6 says
/// to put the new line in the list, and the follow goes on).
fn dropped(conn: &Connection) -> Result<Vec<[u8; 32]>, PersonError> {
    let holds = lists::holds(conn)?;
    let mut filings: Vec<&Filing> = holds.filings.iter().map(|(act, _)| &act.item).collect();
    let mut drops: Vec<[u8; 32]> = holds
        .drops
        .iter()
        .map(|(act, _)| act.item.channel)
        .collect();
    for (act, _) in &holds.left_out {
        match act {
            AnyAct::Filing(filing) => filings.push(&filing.item),
            AnyAct::Drop(drop) => drops.push(drop.item.channel),
            _ => {}
        }
    }
    let moved_from: Vec<[u8; 32]> = filings
        .iter()
        .filter_map(|filing| match filing.came {
            Came::Moved(from) => Some(from),
            _ => None,
        })
        .collect();
    drops.retain(|channel| !moved_from.contains(channel));
    Ok(drops)
}

// ── The notices (rules 4.5, 4.6 and 6) ───────────────────────────────

/// The notices of a read at `commit`, the list just read, `list`, compared
/// with the one kept before it, `kept`.
fn noticed(
    conn: &Connection,
    identity: &NodeIdentity,
    follow: &Follow,
    kept: Option<&Members>,
    list: &Members,
    commit: &str,
    now: i64,
) -> Result<(), PersonError> {
    let of = &follow.identity;
    let notice = |of_what: NoticeOf| {
        let notice = Notice {
            of: of_what,
            commit: commit.to_string(),
            at: now,
        };
        follows::notice(conn, of, &notice)
    };
    // Rule 6: the channel line names another channel than it did.
    let channel = |members: &Members| members.channel.as_ref().map(|line| line.channel);
    if let Some(kept) = kept
        && list.channel.is_some()
        && channel(kept) != channel(list)
    {
        notice(NoticeOf::LineChanged)?;
    }
    // Rule 4.6: a key in the channel that the list kept named and this one
    // does not. Its notice goes once the list names it again, or it leaves
    // the channel: the one this list names, or, where it names none, the
    // one the list kept did.
    let named = match (&list.channel, kept) {
        (None, Some(kept)) => kept,
        _ => list,
    };
    let in_channel = keys_in_channel(conn, &identity.public_key(), named)?;
    let is_in = |key: &[u8; 32]| in_channel.iter().any(|one| same_key(one, key));
    for kept_notice in follows::notices(conn, of)? {
        if let NoticeOf::Dropped { key, .. } = kept_notice.of
            && (list.lists(&key) || !is_in(&key))
        {
            follows::clear_dropped(conn, of, &key)?;
        }
    }
    for device in kept.map(|kept| &kept.devices[..]).unwrap_or_default() {
        if !list.lists(&device.key) && is_in(&device.key) {
            notice(NoticeOf::Dropped {
                key: device.key,
                label: device.label.clone(),
            })?;
        }
    }
    joined(conn, identity, follow, list, commit, now)
}

/// Rule 4.5: each key the list names that this device first held an entry
/// of in the channel the list names since the last read, and since the
/// follow, gives a notice, once. The person's own devices give none. Nor
/// does a read just after this device came to hold the channel: every key
/// it then first holds was there before it, as far as it can tell.
fn joined(
    conn: &Connection,
    identity: &NodeIdentity,
    follow: &Follow,
    list: &Members,
    commit: &str,
    now: i64,
) -> Result<(), PersonError> {
    // With no last read, as after following again, nothing says since when.
    let (Some(line), Some(last)) = (&list.channel, &follow.last) else {
        return Ok(());
    };
    let Some(row) = kept::channel(conn, &line.channel)? else {
        return Ok(());
    };
    let since = last.at.max(follow.followed_at);
    if row.first_held > since {
        return Ok(());
    }
    let own = identity.public_key();
    let own_devices = crate::person::who_counts(conn)?.keys();
    for key in kept::keys(conn, row.id)? {
        if key.first_held.is_none_or(|first| first <= since)
            || same_key(&key.key, &own)
            || own_devices.iter().any(|device| same_key(device, &key.key))
        {
            continue;
        }
        if let Some(label) = list.label_of(&key.key) {
            let notice = Notice {
                of: NoticeOf::Joined {
                    key: key.key,
                    label: label.to_string(),
                },
                commit: commit.to_string(),
                at: now,
            };
            follows::notice(conn, &follow.identity, &notice)?;
        }
    }
    Ok(())
}

// ── The shares that go (rules 4.2 and 4.3) ───────────────────────────

/// The shares that go at this read, in the channels the list kept and the
/// list just read name: the node's, to a key the list no longer names, or
/// made before the last read, so that each lives for two reads (rule
/// 4.2); and a person's, to a key the list kept named and this one does
/// not (rule 4.3). A share a person made to a key the list never named
/// stays: a member may still hand the channel to such a key by hand
/// (rule 10).
fn shares_go(
    conn: &Connection,
    identity: &NodeIdentity,
    follow: &Follow,
    kept: Option<&Members>,
    list: &Members,
    now: i64,
) -> Result<(), PersonError> {
    let mut channels: Vec<[u8; 32]> = Vec::new();
    for line in kept
        .iter()
        .chain([&list])
        .filter_map(|of| of.channel.as_ref())
    {
        if !channels.contains(&line.channel) {
            channels.push(line.channel);
        }
    }
    let last = follow.last.as_ref().map(|last| last.at);
    for row in share_rows::shares(conn)? {
        if row.gone || !channels.contains(&row.channel) {
            continue;
        }
        let listed = list.lists(&row.key);
        let goes = match row.by_node {
            true => !listed || last.is_none_or(|last| row.made < last),
            false => !listed && kept.is_some_and(|kept| kept.lists(&row.key)),
        };
        if goes {
            sharing::write_over(conn, identity, &row, now)?;
        }
    }
    Ok(())
}

// ── Handing over (rules 4.1 and 4.2) ─────────────────────────────────

/// Why this device hands nothing over for a list (rule 4.1): each is a
/// line of rule 6's table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotHanding {
    /// The list has no channel line.
    NoChannel,
    /// Rule 1's gate: the labels of the keys the list names that its
    /// channel line names after `without`, and that are not in the channel
    /// (rule 4.7).
    LeftOut(Vec<String>),
    /// The person does not hold the channel the list names.
    NotHeld,
    /// The person moved from it, to a channel made anew.
    MovedFrom,
    /// A removal came, and it was not made anew: it is not clean here.
    NotClean,
    /// An offer read there made it anew for this person, by `maker`.
    MadeAnew { maker: [u8; 32] },
    /// None of its relays is one of this device's.
    NotReached,
    /// It shows 64 keys on this device.
    Full,
}

impl NotHanding {
    /// A word for each, as a status's JSON carries it.
    pub fn word(&self) -> &'static str {
        match self {
            NotHanding::NoChannel => "no_channel",
            NotHanding::LeftOut(_) => "left_out",
            NotHanding::NotHeld => "not_held",
            NotHanding::MovedFrom => "moved",
            NotHanding::NotClean => "not_clean",
            NotHanding::MadeAnew { .. } => "made_anew",
            NotHanding::NotReached => "not_reached",
            NotHanding::Full => "channel_full",
        }
    }
}

/// The channel line of `list` and the person's filing of its channel,
/// where this device hands that channel over (rule 4.1); or why it does
/// not. Only the channel the list names, once rule 1's gate lets it; only
/// where this device holds it and writes there: held, clean, and not moved
/// from; and never where it read an offer there that made it anew for
/// this person, whether they then moved, stayed or are still paused.
/// Where it is not reached from here or is full, nothing would be handed
/// either, and that is said.
pub fn acts_in<'a>(
    conn: &Connection,
    identity: &NodeIdentity,
    own_relays: &[OwnRelay],
    list: &'a Members,
) -> Result<Result<(&'a ChannelLine, Filing), NotHanding>, PersonError> {
    let Some(line) = &list.channel else {
        return Ok(Err(NotHanding::NoChannel));
    };
    let in_channel = keys_in_channel(conn, &identity.public_key(), list)?;
    let left_out: Vec<String> = list
        .gated(|key| in_channel.iter().any(|one| same_key(one, key)))
        .into_iter()
        .map(|device| device.label.clone())
        .collect();
    if !left_out.is_empty() {
        return Ok(Err(NotHanding::LeftOut(left_out)));
    }
    let Some(row) = kept::channel(conn, &line.channel)? else {
        return Ok(Err(NotHanding::NotHeld));
    };
    match row.state {
        State::Held => {}
        State::Moved => return Ok(Err(NotHanding::MovedFrom)),
        _ => return Ok(Err(NotHanding::NotHeld)),
    }
    let filing = sharing::filed(conn)?
        .into_iter()
        .find(|filing| filing.channel == line.channel);
    let Some(filing) = filing else {
        return Ok(Err(NotHanding::NotHeld));
    };
    if crate::shared_anew::is_not_clean(conn, &line.channel)? {
        return Ok(Err(NotHanding::NotClean));
    }
    let made_anew = crate::shared_anew::judged(conn, identity, &row, None)?
        .into_iter()
        .find(|judged| judged.made_anew_for_you());
    if let Some(judged) = made_anew {
        return Ok(Err(NotHanding::MadeAnew {
            maker: judged.offer.maker,
        }));
    }
    if !sharing::any_own(own_relays, &filing.card) {
        return Ok(Err(NotHanding::NotReached));
    }
    if crate::shared::shown_keys(conn, &line.channel)?.len() >= SHARED_MAX_KEYS {
        return Ok(Err(NotHanding::Full));
    }
    Ok(Ok((line, filing)))
}

/// Rule 4.2: hand the channel of `filing` to the next
/// [`MEMBERS_HANDED_AT_ONCE`] keys in `list`'s order, starting after the
/// last one handed, of those listed and not in the channel, not after
/// `without` in `line`, not the person's own devices, not keys the person
/// removed, and not keys a share of the person's own waits for, nor one of
/// the node's made at the last read, which lives until the next. A twin
/// counts as its key throughout. Each share is the node's, counted apart
/// from the person's, through the checks `share` makes too. Returns the
/// keys handed to.
#[allow(clippy::too_many_arguments)]
fn hand_over(
    conn: &Connection,
    identity: &NodeIdentity,
    held: &Held,
    own_relays: &[OwnRelay],
    follow: &Follow,
    list: &Members,
    line: &ChannelLine,
    filing: &Filing,
    now: i64,
) -> Result<Vec<[u8; 32]>, PersonError> {
    let own = identity.public_key();
    let in_channel = keys_in_channel(conn, &own, list)?;
    let own_devices = crate::person::who_counts(conn)?.keys();
    let removed = crate::person::removed_known(conn, &held.statement.statement)?;
    // A share of one channel deletes another's for the same key, so a key
    // that a person's own share waits for is left to it.
    let by_hand: Vec<[u8; 32]> = sharing::waiting_by_hand(conn, now)?
        .iter()
        .map(|share| share.key)
        .collect();
    // What [`shares_go`] left of the node's: those of the last read.
    let waiting: Vec<[u8; 32]> = follows::shares_by_node(conn)?
        .into_iter()
        .filter(|share| share.channel == filing.channel)
        .map(|share| share.key)
        .collect();
    let among = |keys: &[[u8; 32]], key: &[u8; 32]| keys.iter().any(|one| same_key(one, key));
    let to_hand = |key: &[u8; 32]| {
        !among(&in_channel, key)
            && !line.leaves_out(key)
            && !same_key(&own, key)
            && !among(&own_devices, key)
            && !among(&removed, key)
            && !among(&by_hand, key)
            && !among(&waiting, key)
    };
    let devices = &list.devices;
    let start = follow
        .last_handed
        .and_then(|last| {
            devices
                .iter()
                .position(|device| same_key(&device.key, &last))
        })
        .map_or(0, |at| at + 1);
    let turn: Vec<[u8; 32]> = devices
        .iter()
        .cycle()
        .skip(start)
        .take(devices.len())
        .map(|device| device.key)
        .filter(|key| to_hand(key))
        .take(MEMBERS_HANDED_AT_ONCE)
        .collect();
    let mut handed = Vec::new();
    for key in turn {
        let to = ShareTo {
            filing: filing.clone(),
            key,
        };
        let made = sharing::may_share(conn, held, identity, own_relays, filing, &key)
            .and_then(|()| sharing::make_share(conn, identity, own_relays, &to, true, now));
        match made {
            Ok(_) => handed.push(key),
            Err(Failed::Refused(_)) => {}
            Err(Failed::Error(e)) => return Err(e),
        }
    }
    if let Some(last) = handed.last() {
        follows::set_last_handed(conn, &follow.identity, last)?;
    }
    Ok(handed)
}

// ── The whole read ───────────────────────────────────────────────────

/// A follow's identity, with what its read came to.
pub type ReadOf = (String, Result<Done, PersonError>);

/// Read each list this device follows (rules 3 and 4): the follows, in a
/// short hold of the lock; each clone, with the node's git, outside it;
/// then each read under a hold of the lock of its own, at the time `now`
/// gives then. Nothing is read where git cannot be set up under the
/// node's folder.
pub fn read_each(state: &AppState, now: impl Fn() -> i64) -> Result<Vec<ReadOf>, PersonError> {
    let db = || state.db.lock().unwrap_or_else(|e| e.into_inner());
    let followed = follows::follows(&db())?;
    if followed.is_empty() {
        return Ok(Vec::new());
    }
    let git = Git::under(&state.home_dir)
        .map_err(|e| PersonError::Held(format!("the node's git: {e}")))?;
    let reads = read_clones(&git, followed);
    let own_relays = sharing::own_relays(state);
    Ok(reads
        .iter()
        .map(|read| {
            let done = after_read(&db(), &state.identity, &own_relays, read, now());
            (read.follow.identity.clone(), done)
        })
        .collect())
}

#[cfg(test)]
mod tests;
