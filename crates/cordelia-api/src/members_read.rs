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
//!     whose list does not parse, or whose list names a channel that
//!     another follow's list names counts for nothing: the last list
//!     stands, and why is kept for the status. A channel follows one
//!     repository;
//!   - otherwise the list is kept, and rule 4 is done, with the list
//!     compared with the one kept before by what it says, never by its
//!     commit: the notices of rules 4.5, 4.6 and 6; the shares to keys the
//!     list no longer names deleted, and the node's own after two reads
//!     (rules 4.2 and 4.3); where this device acts in the channel the list
//!     names ([`acts_in`], rule 4.1), the channel handed to the next four
//!     keys in turn (rule 4.2); and, where it looks for a share of that
//!     channel ([`takes_in`], rule 4.4), each listed key typed again, under
//!     the node's own count.
//! - **The take** (rule 4.4): at the pass after a read, the relays are
//!   asked once for each key the node typed ([`to_ask`]), each entry judged
//!   ([`judge`]), and the one share of the channel the list names is taken
//!   ([`take`]), as `accept --channel` takes one, filed on every device of
//!   the person's. Then the agent of the follow's clone is subscribed to
//!   it, once.
//! - **What a status shows of it** is kept in the follow's row (the list,
//!   and why a read counted for nothing) and its typings (what became of
//!   each), and worked out from them again: [`acts_in`] says why nothing is
//!   handed over, and with it the keys rule 4.7 names (rule 1's gate); and
//!   [`takes_in`] why nothing is taken, as rule 6's lines.

use std::path::Path;

use rusqlite::Connection;

use cordelia_core::protocol::{
    MEMBERS_ASKED_PER_PASS, MEMBERS_HANDED_AT_ONCE, SHARED_MAX_CHANNELS, SHARED_MAX_KEYS,
};
use cordelia_crypto::acts::{Filing, Subscription};
use cordelia_crypto::entry::CheckedEntry;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_storage::follows::{self, Follow, LastRead, NotRead, Notice, NoticeOf};
use cordelia_storage::shared::{self as kept, State};
use cordelia_storage::shared_sharing as share_rows;

use crate::following::{
    MOVED_FROM, channel_named, followed_elsewhere, followed_from_line, keys_in_channel,
    made_anew_from, name_free, name_of, no_channel_line, twin_line,
};
use crate::git_list::{ClonedList, Git, Identity, ListFailed};
use crate::lists::Do;
use crate::members::{self, ChannelLine, Members, same_key};
use crate::messages::cleaned;
use crate::person::{Held, PersonError, in_one};
use crate::shared::Judged;
use crate::shared_anew::{Gone, dropped_or_moved};
use crate::sharing::{
    self, Became, Failed, OwnRelay, Refusal, ShareTo, Taker, Took, channel_words, relay_shown,
};
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
    // A follow has a last commit from its first read, and a yes to follow
    // it again names one; a row with none would not know what is back, so
    // its read counts for nothing.
    let comes_after = match &follow.last {
        Some(last) => git.comes_after(clone, &last.commit, &list.at.commit)?,
        None => false,
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
        // follow, whether it was made on this device or another. A move is
        // not a drop: rule 6 says to put the new line in the list.
        let lists = kept_list
            .iter()
            .chain(latest.as_ref().ok().map(|latest| &latest.list));
        for line in lists.filter_map(|list| list.channel.as_ref()) {
            if dropped_or_moved(conn, &line.channel)? == Some(Gone::Dropped) {
                follows::unfollow(conn, &follow.identity)?;
                return Ok(Done::Stopped);
            }
        }
        let latest = match latest {
            Ok(latest) => latest,
            Err(not) => {
                follows::not_read(conn, &follow.identity, &not)?;
                return Ok(Done::NotRead(not));
            }
        };
        let (commit, list) = (&latest.commit, &latest.list);
        // A channel follows one repository (rule 2.5): the follow whose
        // list named it first keeps it.
        if let Some(line) = &list.channel
            && let Some(other) = followed_elsewhere(conn, &follow.identity, &line.channel)?
        {
            let not = NotRead {
                word: "followed_elsewhere".into(),
                why: followed_from_line(
                    &follow.identity,
                    &channel_named(conn, &line.channel)?,
                    &other,
                ),
            };
            follows::not_read(conn, &follow.identity, &not)?;
            return Ok(Done::NotRead(not));
        }
        let done = LastRead {
            commit: commit.clone(),
            at: now,
            from_clone: true,
        };
        follows::read_done(
            conn,
            &follow.identity,
            &done,
            &latest.file,
            latest.fetched_at,
        )?;
        // The keys a share waits for as the read begins, of any channel, by
        // hand or the node's: the turn passes over each, and a key whose
        // share goes at this read waits for it too (rule 4.2).
        let waiting: Vec<[u8; 32]> = sharing::waiting(conn, now)?
            .iter()
            .map(|share| share.key)
            .collect();
        noticed(
            conn,
            identity,
            &follow,
            kept_list.as_ref(),
            list,
            commit,
            now,
        )?;
        shares_go(conn, identity, &follow, kept_list.as_ref(), list, now)?;
        let (handed, not_handing) = match acts_in(conn, identity, own_relays, list)? {
            Ok((line, filing)) => {
                let turn = Turn {
                    held: &held,
                    own_relays,
                    follow: &follow,
                    list,
                    line,
                    filing: &filing,
                    waiting: &waiting,
                };
                (hand_over(conn, identity, &turn, now)?, None)
            }
            Err(why) => (Vec::new(), Some(why)),
        };
        type_listed(conn, identity, &held, own_relays, &follow.identity, now)?;
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

/// A list just read from a clone.
struct Latest {
    commit: String,
    file: Vec<u8>,
    list: Members,
    fetched_at: Option<i64>,
}

/// The list that `read` gives, or why it counts for nothing (rules 1 and
/// 3): it failed, its commit does not come after the last one read, or its
/// list does not parse. A clone with no list is a list with no members and
/// no channel.
fn latest_of(read: &CloneRead) -> Result<Latest, NotRead> {
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
    Ok(Latest {
        commit: commit.clone(),
        file,
        list,
        fetched_at: got.list.fetched_at(),
    })
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
    // Rule 6: the channel line names another channel than it did. A first
    // line, as after `subscribe --new`, is no change.
    let channel = |members: &Members| members.channel.as_ref().map(|line| line.channel);
    if let Some(kept) = kept
        && kept.channel.is_some()
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
/// follow, gives a notice, once. The person's own devices give none, nor
/// does a key that moved there with the person, sealed to by the offer
/// that made the channel: it first writes there as it moves. Nor does a
/// read just after this device came to hold the channel: every key it
/// then first holds was there before it, as far as it can tell.
fn joined(
    conn: &Connection,
    identity: &NodeIdentity,
    follow: &Follow,
    list: &Members,
    commit: &str,
    now: i64,
) -> Result<(), PersonError> {
    // A follow has a last read: one with none would not know since when.
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
    let moved = crate::shared_anew::moved_with(conn, &own, &line.channel)?;
    let among = |keys: &[[u8; 32]], key: &[u8; 32]| keys.iter().any(|one| same_key(one, key));
    for key in kept::keys(conn, row.id)? {
        if key.first_held.is_none_or(|first| first <= since)
            || same_key(&key.key, &own)
            || among(&own_devices, &key.key)
            || among(&moved, &key.key)
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
/// list just read name: the node's, once it is not of the channel the
/// list names, or to a key the list no longer names, or made before the
/// last read, so that each lives for two reads (rule 4.2); and a person's,
/// to a key the list kept named and this one does not (rule 4.3). A share
/// a person made to a key the list never named stays: a member may still
/// hand the channel to such a key by hand (rule 10).
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
    let named = list.channel.as_ref().map(|line| line.channel);
    let last = follow.last.as_ref().map(|last| last.at);
    for row in share_rows::shares(conn)? {
        if row.gone || !channels.contains(&row.channel) {
            continue;
        }
        let listed = list.lists(&row.key);
        let goes = match row.by_node {
            true => {
                named != Some(row.channel) || !listed || last.is_none_or(|last| row.made < last)
            }
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

/// What a turn of rule 4.2 is taken from: what the person holds, the
/// device's relays known by their keys, the follow, its list and channel
/// line, the person's filing of that channel, and the keys a share waited
/// for as the read began.
struct Turn<'a> {
    held: &'a Held,
    own_relays: &'a [OwnRelay],
    follow: &'a Follow,
    list: &'a Members,
    line: &'a ChannelLine,
    filing: &'a Filing,
    waiting: &'a [[u8; 32]],
}

/// Rule 4.2: hand the channel of the turn's filing to the next
/// [`MEMBERS_HANDED_AT_ONCE`] keys in its list's order, starting after the
/// last one handed, of those listed and not in the channel, not after
/// `without` in its line, not the person's own devices, and not keys the
/// person removed; nor a key a share waited for as the read began, of any
/// channel, by hand or the node's, as a share of one channel writes over
/// another's for the same key. A twin counts as its key throughout. Each
/// share is the node's, counted apart from the person's, through the
/// checks `share` makes too. Returns the keys handed to.
fn hand_over(
    conn: &Connection,
    identity: &NodeIdentity,
    turn: &Turn<'_>,
    now: i64,
) -> Result<Vec<[u8; 32]>, PersonError> {
    let Turn {
        held,
        own_relays,
        follow,
        list,
        line,
        filing,
        waiting,
    } = *turn;
    let own = identity.public_key();
    let in_channel = keys_in_channel(conn, &own, list)?;
    let own_devices = crate::person::who_counts(conn)?.keys();
    let removed = crate::person::removed_known(conn, &held.statement.statement)?;
    let among = |keys: &[[u8; 32]], key: &[u8; 32]| keys.iter().any(|one| same_key(one, key));
    let to_hand = |key: &[u8; 32]| {
        !among(&in_channel, key)
            && !line.leaves_out(key)
            && !same_key(&own, key)
            && !among(&own_devices, key)
            && !among(&removed, key)
            && !among(waiting, key)
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

// ── Taking (rule 4.4) ────────────────────────────────────────────────

/// Where this device looks for a share for a follow (rule 4.4): the list
/// kept, its channel line, and the name the channel is filed under once it
/// is taken, the repository's `owner/name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Looks {
    pub list: Members,
    pub line: ChannelLine,
    pub name: String,
}

/// Whether this device looks for a share of the channel that the list
/// kept for `follow` names (rule 4.4), or why it takes nothing, as a word
/// and rule 6's line. It looks only where the latest read counted, the
/// list names a channel, and the person holds none of these: that channel,
/// one they dropped or moved from, or one it was made anew from (they move
/// to it). And only where the list names this device's key as `cordelia
/// id` prints it, its channel line does not name it after `without`, every
/// relay of the line is one of this device's own by key, and the channel
/// has room and its name, as `accept --channel` would take it. Rule 1's
/// gate does not hold a take back (rule 1). Worked out at each read, and
/// again at the take, under the lock.
pub fn takes_in(
    conn: &Connection,
    identity: &NodeIdentity,
    own_relays: &[OwnRelay],
    follow: &Follow,
) -> Result<Result<Looks, Refusal>, PersonError> {
    let not = |word: &'static str, line: String| Ok(Err(Refusal { word, line }));
    let repository = &follow.identity;
    if let Some(not_read) = &follow.not_read {
        return not("not_read", not_read.why.clone());
    }
    let list = follow
        .list
        .as_deref()
        .and_then(|list| members::read(list).ok());
    let Some((line, list)) = list.and_then(|list| Some((list.channel.clone()?, list))) else {
        return not("no_channel", no_channel_line(repository));
    };
    let words = channel_words(&line.channel);
    let commit = follow.last.as_ref().map_or("", |last| last.commit.as_str());
    let filings = sharing::filed(conn)?;
    if let Some(filing) = filings.iter().find(|filing| filing.channel == line.channel) {
        let name = cleaned(&filing.name);
        return not(
            "held",
            format!("Your devices hold this channel already, as \"{name}\"."),
        );
    }
    match dropped_or_moved(conn, &line.channel)? {
        Some(Gone::Moved) => return not("moved", MOVED_FROM.into()),
        Some(Gone::Dropped) => {
            return not(
                "dropped",
                format!("You dropped channel {words}, and a dropped channel is not taken again."),
            );
        }
        None => {}
    }
    if let Some(from) = made_anew_from(conn, identity, &filings, &line.channel)? {
        return not(
            "made_anew",
            format!(
                "Run cordelia shared move {}: the list names the channel it was made anew as.",
                crate::shared_routes::shell_word(&from.name)
            ),
        );
    }
    let own = identity.public_key();
    // A member's share to a twin of this device's key is in another share
    // pair channel, which this device never reads.
    if list.line_of(&own).is_none() {
        return match list.lists(&own) {
            true => not("twin_listed", twin_line(repository, &own)?),
            false => not(
                "not_listed",
                format!("Your key is not on the list of {repository} at {commit}."),
            ),
        };
    }
    if line.leaves_out(&own) {
        return not(
            "left_out_of_it",
            format!(
                "The list of {repository} at {commit} names channel {words}, which no device of \
                 yours holds or can move to."
            ),
        );
    }
    // Rule 1's gate binds only those who hand over. A device that does not
    // hold the channel cannot see who is in it, so every key after
    // `without` would look left out to it, for good. The members keep the
    // gate, and this device takes nothing while its own key is after
    // `without`, above.
    if let Some(relay) = line
        .relays
        .iter()
        .find(|key| !own_relays.iter().any(|relay| relay.key == **key))
    {
        return not(
            "not_own_relay",
            format!(
                "Channel {words} is at {}, which is not one of your relays: add it to your \
                 configuration.",
                relay_shown(own_relays, relay)
            ),
        );
    }
    if filings.len() >= SHARED_MAX_CHANNELS {
        return not(
            "too_many_channels",
            "You hold 16 shared channels, the most there can be.".into(),
        );
    }
    let Some(of) = Identity::from_text(repository) else {
        return Err(PersonError::Held(format!("{repository} is no repository")));
    };
    let name = name_of(&of);
    match name_free(conn, &name) {
        Ok(()) => {}
        Err(Failed::Refused(refusal)) => return Ok(Err(refusal)),
        Err(Failed::Error(e)) => return Err(e),
    }
    Ok(Ok(Looks { list, line, name }))
}

/// Rule 6's line while this device looks for a share of `name`, whose list
/// was read `when`, and has taken none: the node reads the clone only, so
/// what it waits for is most often a member's clone that has not pulled
/// the merge.
pub fn waiting_line(name: &str, when: &str) -> String {
    format!(
        "Waiting for a member's device to hand you {name}. Your list was read {when}. A member's \
         device hands it over once a member's clone has the merged list: a member runs git pull \
         there."
    )
}

/// The node's typings for the follow of `of`, after a read of its list
/// that counted, at `now` (rule 4.4). Where this device looks for a share,
/// each listed key is typed again, but this device's own, the person's
/// other devices' and the keys the person removed. They are the node's own
/// typings, so the person's own `accept --channel` keeps its eight places.
/// Every other typing goes, and where it does not look, none is kept.
/// `held` is what the device holds of its person.
fn type_listed(
    conn: &Connection,
    identity: &NodeIdentity,
    held: &Held,
    own_relays: &[OwnRelay],
    of: &str,
    now: i64,
) -> Result<(), PersonError> {
    let Some(follow) = follows::follow_of(conn, of)? else {
        return Ok(());
    };
    let keys: Vec<[u8; 32]> = match takes_in(conn, identity, own_relays, &follow)? {
        Ok(looks) => {
            let own = identity.public_key();
            let own_devices = crate::person::who_counts(conn)?.keys();
            let removed = crate::person::removed_known(conn, &held.statement.statement)?;
            let among =
                |keys: &[[u8; 32]], key: &[u8; 32]| keys.iter().any(|one| same_key(one, key));
            looks
                .list
                .devices
                .iter()
                .map(|device| device.key)
                .filter(|key| {
                    !same_key(&own, key) && !among(&own_devices, key) && !among(&removed, key)
                })
                .collect()
        }
        Err(_) => Vec::new(),
    };
    for typed in follows::typed(conn, of)? {
        if !keys.contains(&typed.key) {
            follows::untype(conn, of, &typed.key)?;
        }
    }
    for key in &keys {
        follows::type_key(conn, of, key, now)?;
    }
    Ok(())
}

/// What became of a typing of the node's that was asked for at the relays,
/// where no share of the channel the list names was found (rule 4.4): it
/// is not asked for again until the next read types its key again.
pub const ASKED: &str = "asked";

/// What became of a typing of the node's under which the channel was
/// taken.
pub const TAKEN: &str = "taken";

/// A key the node typed for the follow of `of`, at the read at `typed_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Typing {
    pub of: String,
    pub key: [u8; 32],
    pub typed_at: i64,
}

/// The node's typings to ask the relays for at `now` (rule 4.4): each
/// typed at a read that counted, within the hour of that read
/// (`PAIR_KEY_TYPED_SECS`), and not asked for since. So each listed key is
/// asked for once at each read, at a pass after it, and not at every pass.
/// No more than [`MEMBERS_ASKED_PER_PASS`] are given, across every follow,
/// however many there are: the rest are asked for at the passes after.
pub fn to_ask(conn: &Connection, now: i64) -> Result<Vec<Typing>, PersonError> {
    let mut asked = Vec::new();
    for follow in follows::follows(conn)? {
        // A follow whose latest read counted for nothing takes nothing.
        if follow.not_read.is_some() {
            continue;
        }
        for typed in follows::typed(conn, &follow.identity)? {
            if typed.became.is_none() && crate::adding::within_its_hour(typed.typed_at, now) {
                asked.push(Typing {
                    of: follow.identity.clone(),
                    key: typed.key,
                    typed_at: typed.typed_at,
                });
            }
        }
    }
    asked.truncate(MEMBERS_ASKED_PER_PASS);
    Ok(asked)
}

/// Whether the node's `typing` reads now, as rule 1 of §3.2 says of a
/// person's (rule 4.4): the node typed its key for its follow at that
/// time, within the hour, and has not asked for it since.
pub fn reads_now(conn: &Connection, typing: &Typing, now: i64) -> Result<bool, PersonError> {
    Ok(follows::typed(conn, &typing.of)?.iter().any(|typed| {
        typed.key == typing.key
            && typed.typed_at == typing.typed_at
            && typed.became.is_none()
            && crate::adding::within_its_hour(typed.typed_at, now)
    }))
}

/// Judge `entry`, handed from the share pair channel of the key of
/// `typing`, at `now`, by rules 2 to 8 of §3.2
/// ([`crate::shared::judge_share`]): a share made an hour or more from the
/// read that typed the key is not one to take. `None` where the typing
/// reads nothing now.
pub fn judge(
    conn: &Connection,
    identity: &NodeIdentity,
    typing: &Typing,
    entry: &CheckedEntry,
    now: i64,
) -> Result<Option<Judged>, PersonError> {
    if !reads_now(conn, typing, now)? {
        return Ok(None);
    }
    crate::shared::judge_share(identity, &typing.key, typing.typed_at, entry).map(Some)
}

/// Take, for the node's `typing`, the one share among `found` of the
/// channel its follow's list names, at `now`, in one transaction (rule
/// 4.4). Each of `found` is an entry that [`judge`] passed, at every relay
/// that was read. The typing must read now, and this device must still
/// look for a share ([`takes_in`]). It is taken as `accept --channel`
/// takes a share ([`sharing::take_one`]), told the one channel it may
/// take: filed on every device of the person's, under the repository's
/// `owner/name`, as taken from the key. A share of any other channel is
/// not one to take. Then the agent of the follow's clone is subscribed to
/// it, as the yes to follow said, once. What became of the typing is kept
/// with it.
pub fn take(
    conn: &Connection,
    identity: &NodeIdentity,
    typing: &Typing,
    found: &[CheckedEntry],
    own_relays: &[OwnRelay],
    now: i64,
) -> Result<Became, PersonError> {
    in_one(conn, || {
        if !reads_now(conn, typing, now)? {
            return Ok(Became::NotNow);
        }
        let Some(follow) = follows::follow_of(conn, &typing.of)? else {
            return Ok(Became::NotNow);
        };
        let became = |word: &str, detail: Option<&str>| {
            follows::typed_became(conn, &typing.of, &typing.key, word, detail)
        };
        let looks = match takes_in(conn, identity, own_relays, &follow)? {
            Ok(looks) => looks,
            Err(refusal) => {
                became(refusal.word, Some(&refusal.line))?;
                return Ok(Became::Refused(refusal.word));
            }
        };
        let taker = Taker {
            key: typing.key,
            name: &looks.name,
            only: Some(looks.line.channel),
        };
        Ok(
            match sharing::take_one(conn, identity, &taker, found, own_relays, now)? {
                Took::NotNow => Became::NotNow,
                Took::Nothing => {
                    became(ASKED, None)?;
                    Became::Nothing
                }
                Took::Refused(refusal) => {
                    became(refusal.word, Some(&refusal.line))?;
                    Became::Refused(refusal.word)
                }
                Took::Taken(channel) => {
                    let not_subscribed = subscribe_once(conn, identity, &follow, &channel, now)?;
                    became(TAKEN, not_subscribed.as_deref())?;
                    Became::Taken(channel)
                }
            },
        )
    })
}

/// Subscribe the agent mapped at the clone of `follow` to `channel`, just
/// taken for it, at `now`, as the yes to follow said (rule 2.3). Once: a
/// channel is taken once, as the person then holds it, so an agent the
/// person unsubscribes later is not subscribed again. Nothing where the
/// agent subscribes already. Returns why it was not, where it was not: the
/// clone is no mapped folder now, or the subscription was refused.
fn subscribe_once(
    conn: &Connection,
    identity: &NodeIdentity,
    follow: &Follow,
    channel: &[u8; 32],
    now: i64,
) -> Result<Option<String>, PersonError> {
    let agent = crate::messages::agent_of(conn, &follow.clone)
        .map_err(|e| PersonError::Held(e.to_string()))?;
    let Some(agent) = agent else {
        return Ok(Some(format!(
            "{} is no mapped folder now, so no agent was subscribed.",
            cleaned(&follow.clone)
        )));
    };
    if crate::shared_messages::in_force(conn)?
        .iter()
        .any(|(of, subscribed)| of == channel && *subscribed == agent)
    {
        return Ok(None);
    }
    let subscription = Subscription {
        channel: *channel,
        agent,
        subscribed: true,
    };
    let subscribed = sharing::standing(conn)
        .and_then(|held| sharing::act(conn, identity, &held, Do::Subscribe(subscription), now));
    match subscribed {
        Ok(()) => Ok(None),
        Err(Failed::Refused(refusal)) => Ok(Some(refusal.line)),
        Err(Failed::Error(e)) => Err(e),
    }
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
