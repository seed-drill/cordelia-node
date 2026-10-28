//! What the shared pass reads and writes under the database's lock
//! (decision 2026-10-10 §8.4): which shared channels live at a relay, what
//! the door to their streams refuses, a page taken and its place, what
//! waits to be pushed at a relay, and what a relay answered of a push.
//!
//! Plain functions over the node's database, as `at_relays` is for the
//! channels of the device's own: nothing here opens a stream or knows a
//! connection. A relay is its node key. The node's side
//! (`cordelia_node::device_entries`) asks these through its doors
//! `Leave::shared` and `Leave::share_pair`, and through nothing else.
//!
//! - **Where a shared channel lives.** At each relay its card names, by
//!   key, that is one of the device's own (§8.2): whoever asks gives the
//!   relay's key only where its configuration knows the relay by that key.
//! - **When.** Only on a device that stands applied under the latest
//!   statement it has seen, with sync on (§2.3, rule 2; §6.1): otherwise no
//!   stream of a shared channel is opened, and the door refuses.
//! - **Places.** Each channel has its own place at each relay, kept in the
//!   store (schema step 23). A page moves it past every entry it holds, an
//!   entry the door refused for room among them (§6.3). A page of another
//!   holding, or one that says the relay holds the channel no more, starts
//!   the channel again there: read from the start, and everything of the
//!   device's own there sent again.
//! - **What waits.** Every entry of the device's own in a shared channel
//!   that a relay has not answered at its revision or above (§8.4); one
//!   that a relay refused for room waits, and is pushed again at a later
//!   pass.

use rusqlite::Connection;

use cordelia_core::protocol::entry_cost;
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::share::Card;
use cordelia_crypto::shared::anew_name;
use cordelia_crypto::slots::slot_id;
use cordelia_storage::entries;
use cordelia_storage::relay::{Mark, NO_MARK};
use cordelia_storage::shared::{self as kept, State};
use cordelia_storage::shared_pass::{self as rows, Answer};

use crate::at_relays::{Most, Pushed, Stands, stands};
use crate::person::{PersonError, in_one};
use crate::take::{Taken, take};

/// Why the door of a shared channel's streams refuses (decision 2026-10-10
/// §8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotUsable {
    /// The device holds no such shared channel: it is not in the table, or
    /// it is dropped, moved from, or held by no act in force.
    NotHeld,
    /// The channel's card does not name the relay by its key: it does not
    /// live there.
    NotThere,
    /// The device does not stand applied under the latest statement it has
    /// seen.
    NotApplied,
    /// Sync is off.
    SyncOff,
}

/// A shared channel that the door may use at a relay: its row, its ID and
/// its secret.
#[derive(Clone)]
pub struct Usable {
    pub id: i64,
    pub channel: [u8; 32],
    secret: [u8; 32],
}

impl std::fmt::Debug for Usable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The secret is not printed.
        f.debug_struct("Usable")
            .field("id", &self.id)
            .field("channel", &hex::encode(&self.channel[..4]))
            .finish_non_exhaustive()
    }
}

impl Usable {
    /// The proof that the end of a connection whose node key is `prover`
    /// holds this channel's key, over the connection's value `session`.
    pub fn proof(&self, session: &[u8; 32], prover: &[u8; 32]) -> Option<[u8; 64]> {
        cordelia_crypto::proof::make(&self.secret, session, prover).ok()
    }
}

/// Whether the device stands applied with sync on: where a shared
/// channel's stream may be opened at all (§2.3, rule 2).
pub fn may_open(conn: &Connection) -> Result<Result<(), NotUsable>, PersonError> {
    if stands(conn)? != Stands::Applied {
        return Ok(Err(NotUsable::NotApplied));
    }
    if !crate::commands::sync_is_on(conn).map_err(|e| PersonError::Held(e.to_string()))? {
        return Ok(Err(NotUsable::SyncOff));
    }
    Ok(Ok(()))
}

/// The card of a channel's row.
fn card_of(row: &kept::Channel) -> Result<Card, PersonError> {
    Card::from_bytes(&row.card)
        .map_err(|e| PersonError::Held(format!("the card of a shared channel: {e}")))
}

/// What the door may use of the shared channel `channel` at the relay whose
/// node key is `relay` (decision 2026-10-10 §8.4): the channel is in the
/// table and held, its card names that relay by its key, and the device
/// stands applied with sync on.
pub fn usable(
    conn: &Connection,
    channel: &[u8; 32],
    relay: &[u8; 32],
) -> Result<Result<Usable, NotUsable>, PersonError> {
    if let Err(not) = may_open(conn)? {
        return Ok(Err(not));
    }
    let Some(row) = kept::channel(conn, channel)? else {
        return Ok(Err(NotUsable::NotHeld));
    };
    if row.state != State::Held {
        return Ok(Err(NotUsable::NotHeld));
    }
    let card = card_of(&row)?;
    if !card.relays().keys().contains(relay) {
        return Ok(Err(NotUsable::NotThere));
    }
    Ok(Ok(Usable {
        id: row.id,
        channel: row.channel,
        secret: card.secret()?,
    }))
}

/// The shared channels that live at the relay whose node key is `relay`, in
/// the order of their rows: each held whose card names that relay by its
/// key. None where the device does not stand applied with sync on.
pub fn at_relay(conn: &Connection, relay: &[u8; 32]) -> Result<Vec<[u8; 32]>, PersonError> {
    if may_open(conn)?.is_err() {
        return Ok(Vec::new());
    }
    let mut at = Vec::new();
    for row in kept::channels(conn)? {
        if row.state == State::Held && card_of(&row)?.relays().keys().contains(relay) {
            at.push(row.channel);
        }
    }
    Ok(at)
}

/// Every shared channel the device holds, wherever it lives: the channels
/// that the device still proves, which keep their places among a
/// connection's proofs (decision 2026-10-17 §4; §8.4).
pub fn held(conn: &Connection) -> Result<Vec<[u8; 32]>, PersonError> {
    Ok(kept::channels(conn)?
        .into_iter()
        .filter(|row| row.state == State::Held)
        .map(|row| row.channel)
        .collect())
}

/// The reads again from the start that may begin at `now` begin (§6.3, at
/// most once a day for each channel): each such channel's places go, at
/// every relay. Returns the channels.
pub fn begin_reads_again(conn: &Connection, now: i64) -> Result<Vec<[u8; 32]>, PersonError> {
    in_one(conn, || {
        let due = crate::shared::read_again_due(conn, now)?;
        for channel in &due {
            if let Some(row) = kept::channel(conn, channel)? {
                crate::shared::read_again_begun(conn, channel, now)?;
                rows::forget_places(conn, row.id)?;
            }
        }
        Ok(due)
    })
}

/// The mark and the place that the device asks the relay `relay` for a page
/// of the channel of `usable` with: the ones it keeps, or the start.
pub fn place(
    conn: &Connection,
    usable: &Usable,
    relay: &[u8; 32],
) -> Result<(Mark, u64), PersonError> {
    Ok(rows::place(conn, usable.id, relay)?.unwrap_or((NO_MARK, 0)))
}

/// What became of a page of a shared channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageOf {
    /// What became of each entry, through the one door.
    pub each: Vec<Taken>,
    /// Whether the pull got somewhere by it: the place moved on, the
    /// holding is another, or the store took an entry it did not hold.
    pub got_somewhere: bool,
}

/// Take a page that the relay `relay` handed of the channel of `usable`
/// (decision 2026-10-10 §8.4, §6.3), in one transaction: each entry through
/// the one door ([`take`]), whose branch for a shared channel judges it;
/// then the place, past every entry of the page, those refused among them.
/// An entry of the device's own is one that relay holds, and is not pushed
/// back there. A page under another mark than the one kept, or one of
/// nothing under the mark of no holding against a place kept, says the
/// relay holds nothing the device knows of: the channel starts again there.
/// `asked` is the place the page was asked from. `None` where the page
/// holds an entry of another channel: nothing of it is taken.
pub fn take_page(
    conn: &Connection,
    identity: &NodeIdentity,
    usable: &Usable,
    relay: &[u8; 32],
    asked: (Mark, u64),
    page: (&[CheckedEntry], Mark, u64),
    now: i64,
) -> Result<Option<PageOf>, PersonError> {
    let (entries, mark, next) = page;
    if entries.iter().any(|entry| entry.channel != usable.channel) {
        return Ok(None);
    }
    let own = identity.public_key();
    in_one(conn, || {
        let kept_place = rows::place(conn, usable.id, relay)?;
        let another_holding = mark != NO_MARK && kept_place.is_some_and(|(kept, _)| kept != mark);
        let no_holding = mark == NO_MARK && entries.is_empty() && kept_place.is_some();
        if another_holding || no_holding {
            rows::start_again(conn, usable.id, relay)?;
        }
        let mut each = Vec::with_capacity(entries.len());
        let mut stored = false;
        for entry in entries {
            let taken = take(conn, identity, entry, now)?;
            stored |= matches!(
                taken,
                Taken::Shared {
                    stored: entries::Outcome::Stored,
                    ..
                }
            );
            if entry.author == own {
                rows::answered(
                    conn,
                    usable.id,
                    relay,
                    &entry.slot,
                    entry.rev,
                    Answer::Holds,
                )?;
            }
            each.push(taken);
        }
        if mark != NO_MARK {
            rows::keep_place(conn, usable.id, relay, &mark, next)?;
        }
        let got_somewhere = if mark == NO_MARK {
            stored
        } else {
            mark != asked.0 || next > asked.1
        };
        Ok(PageOf {
            each,
            got_somewhere,
        })
    })
    .map(Some)
}

/// The relay `relay` answered a proof of the channel of `usable` with no:
/// it does not hold it. Its place there goes, and every answer it gave a
/// push: everything of the device's own there is sent again.
pub fn not_held_at(
    conn: &Connection,
    usable: &Usable,
    relay: &[u8; 32],
) -> Result<(), PersonError> {
    rows::start_again(conn, usable.id, relay)?;
    Ok(())
}

/// What waits to be pushed to the relay `relay` in the channel of `usable`,
/// within `most` (decision 2026-10-10 §8.4): each entry of the device's own
/// there, in the order the store took them, that the relay has not answered
/// at its revision or above, each measured as a relay counts it
/// (`entry_cost`). Nothing past the first that does not fit.
pub fn to_send(
    conn: &Connection,
    identity: &NodeIdentity,
    usable: &Usable,
    relay: &[u8; 32],
    most: Most,
) -> Result<Vec<CheckedEntry>, PersonError> {
    let own = identity.public_key();
    let mut batch: Vec<CheckedEntry> = Vec::new();
    let mut bytes = 0usize;
    for held in entries::author_entries(conn, &usable.channel, &own)? {
        let entry = &held.entry;
        let answered = rows::answer(conn, usable.id, relay, &entry.slot)?;
        if answered.is_some_and(|(rev, _)| rev >= entry.rev) {
            continue;
        }
        let Ok(entry) = Entry::check(held.entry) else {
            continue;
        };
        // Measured as a relay counts it, which is more than it travels: so
        // the push is within both what may travel and the byte share.
        let counted = usize::try_from(entry_cost(entry.content.len())).unwrap_or(usize::MAX);
        if batch.len() >= most.entries || bytes + counted > most.bytes {
            break;
        }
        bytes += counted;
        batch.push(entry);
    }
    Ok(batch)
}

/// The relay `relay` answered a push of `batch` in the channel of `usable`
/// with `answers`, one for each entry, in one transaction. An entry it
/// holds, holds a later one of, holds another at its revision of, or
/// refused as not signed is not sent there again; one it refused for room
/// or for the address's allowance waits. Where it holds another at the
/// revision of this device's anew record, the record is written again
/// above it (§2.3, [`anew_again`]), at `now`. Returns how many it refused
/// for room or allowance.
pub fn pushed(
    conn: &Connection,
    identity: &NodeIdentity,
    usable: &Usable,
    relay: &[u8; 32],
    batch: &[CheckedEntry],
    answers: &[Pushed],
    now: i64,
) -> Result<usize, PersonError> {
    in_one(conn, || {
        let mut refused = 0;
        for (entry, pushed) in batch.iter().zip(answers) {
            let answer = match pushed {
                Pushed::Holds => Answer::Holds,
                Pushed::HoldsLater => Answer::HoldsLater,
                Pushed::HoldsAnother => {
                    anew_again(conn, identity, usable, entry, now)?;
                    Answer::HoldsAnother
                }
                Pushed::DoesNotCheck => Answer::DoesNotCheck,
                Pushed::NoRoom | Pushed::OverAllowance => {
                    refused += 1;
                    continue;
                }
            };
            rows::answered(conn, usable.id, relay, &entry.slot, entry.rev, answer)?;
        }
        Ok(refused)
    })
}

/// A relay holds another entry of this device's at the revision of
/// `entry` (§2.3, `Pushed::HoldsAnother`): where `entry` is this device's
/// anew record, and the one its store holds, it is written again one
/// revision above, holding the same, through the one door. A device that
/// dropped a channel and took it again writes its record at revision 1
/// once more, and a relay that kept the first answers so.
fn anew_again(
    conn: &Connection,
    identity: &NodeIdentity,
    usable: &Usable,
    entry: &CheckedEntry,
    now: i64,
) -> Result<(), PersonError> {
    let own = identity.public_key();
    if entry.author != own {
        return Ok(());
    }
    let slot = slot_id(&derive::slot_key(&usable.secret)?, &anew_name(&own)?);
    if entry.slot != slot {
        return Ok(());
    }
    let Some(held) = entries::author_entry(conn, &usable.channel, &slot, &own)? else {
        return Ok(());
    };
    if held.entry.rev != entry.rev {
        return Ok(());
    }
    let inside = Entry::check(held.entry)?.open(&usable.secret)?;
    let again = Entry::seal(&usable.secret, identity, entry.rev + 1, &inside)?.check()?;
    take(conn, identity, &again, now)?;
    Ok(())
}

/// The share pair channel of this device and `key` (decision 2026-10-10
/// §3.1): its ID and its secret. `None` where it has none: `key` is this
/// device's own, or has no X25519 form.
pub fn share_pair(identity: &NodeIdentity, key: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
    let secret = derive::share_pair_secret(identity, key).ok()?;
    Some((derive::channel_id(&secret).ok()?, secret))
}

/// Whether `entry` is one that this device wrote in its share pair channel
/// with `key`, and that its store holds at that revision: the one kind of
/// entry the door of a share pair channel pushes (§8.4).
pub fn is_own_share(
    conn: &Connection,
    identity: &NodeIdentity,
    key: &[u8; 32],
    entry: &CheckedEntry,
) -> Result<bool, PersonError> {
    let Some((channel, _)) = share_pair(identity, key) else {
        return Ok(false);
    };
    if entry.channel != channel || entry.author != identity.public_key() {
        return Ok(false);
    }
    let held = entries::author_entry(conn, &channel, &entry.slot, &entry.author)?;
    Ok(held.is_some_and(|held| held.entry.rev == entry.rev))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lists::Do;
    use crate::shared::tests::{
        DAY, FULL, acts, anew, bob, fill_to, holds, labels, member, message, row,
    };
    use crate::take::NotTaken;
    use cordelia_storage::meta;

    /// The relay that a test's cards name ([`crate::lists::tests::filing`]).
    const AT: [u8; 32] = [3; 32];
    /// A relay that no card names.
    const ELSEWHERE: [u8; 32] = [4; 32];

    /// The door of a shared channel's streams takes a channel only where it
    /// is held here, its card names the relay by its key, and the device
    /// stands applied with sync on (decision 2026-10-10 §8.4); and a pass
    /// finds a channel at a relay only so.
    #[test]
    fn the_door_takes_a_channel_held_here_at_its_relay_with_sync_on() {
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        let conn = &s[0].conn;
        assert!(usable(conn, &channel.id, &AT).unwrap().is_ok());
        assert_eq!(at_relay(conn, &AT).unwrap(), [channel.id]);
        assert_eq!(
            usable(conn, &channel.id, &ELSEWHERE).unwrap().unwrap_err(),
            NotUsable::NotThere
        );
        assert!(at_relay(conn, &ELSEWHERE).unwrap().is_empty());
        assert_eq!(
            usable(conn, &[9; 32], &AT).unwrap().unwrap_err(),
            NotUsable::NotHeld
        );
        // Sync off: nothing of it.
        meta::remove(conn, meta::SYNC_CLAUDE_DIR).unwrap();
        assert_eq!(
            usable(conn, &channel.id, &AT).unwrap().unwrap_err(),
            NotUsable::SyncOff
        );
        assert!(at_relay(conn, &AT).unwrap().is_empty());
        meta::set(conn, meta::SYNC_CLAUDE_DIR, "/home/bob/.claude").unwrap();
        // Dropped: nothing of it.
        acts(&s, 0, Do::Drop(channel.id), now + 1);
        assert_eq!(
            usable(conn, &channel.id, &AT).unwrap().unwrap_err(),
            NotUsable::NotHeld
        );
        assert!(at_relay(conn, &AT).unwrap().is_empty());
        // A device that follows no phrase opens no stream of one.
        let none = crate::several::Several::new(1);
        assert_eq!(may_open(&none[0].conn).unwrap(), Err(NotUsable::NotApplied));
        assert!(at_relay(&none[0].conn, &AT).unwrap().is_empty());
    }

    /// A page moves the device's place at a relay past every entry it
    /// holds, one the door refused for room among them, so that what
    /// follows is read (§6.3); a page of another holding, or one of nothing
    /// under the mark of no holding against a place kept, starts the
    /// channel again there; an entry of the device's own that a relay
    /// hands is one that relay holds.
    #[test]
    fn a_page_moves_the_place_past_every_entry_refused_for_room_too() {
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        fill_to(&s, 0, &channel, FULL, now);
        let conn = &s[0].conn;
        let here = usable(conn, &channel.id, &AT).unwrap().unwrap();
        assert_eq!(place(conn, &here, &AT).unwrap(), (NO_MARK, 0));
        // A new key, refused for room: the place moves past it all the same.
        let dave = message(&member(7), &channel, 1, "dave", now);
        let page = [dave.clone()];
        let taken = take_page(
            conn,
            &s[0].identity,
            &here,
            &AT,
            (NO_MARK, 0),
            (&page, [5; 8], 9),
            now,
        )
        .unwrap()
        .unwrap();
        assert_eq!(taken.each, [Taken::Refused(NotTaken::SharedFull)]);
        assert!(taken.got_somewhere);
        assert_eq!(place(conn, &here, &AT).unwrap(), ([5; 8], 9));
        // The same page again gets nowhere.
        let again = take_page(
            conn,
            &s[0].identity,
            &here,
            &AT,
            ([5; 8], 9),
            (&page, [5; 8], 9),
            now,
        )
        .unwrap()
        .unwrap();
        assert!(!again.got_somewhere);
        // The device's own entry: that relay holds it, and it waits there
        // no more.
        let own = anew(&s[0].identity, &channel, 1);
        crate::take::take(conn, &s[0].identity, &own, now).unwrap();
        let most = Most {
            entries: 100,
            bytes: 1 << 20,
        };
        assert_eq!(
            to_send(conn, &s[0].identity, &here, &AT, most).unwrap(),
            std::slice::from_ref(&own)
        );
        let page = std::slice::from_ref(&own);
        take_page(
            conn,
            &s[0].identity,
            &here,
            &AT,
            ([5; 8], 9),
            (page, [5; 8], 10),
            now,
        )
        .unwrap();
        assert!(
            to_send(conn, &s[0].identity, &here, &AT, most)
                .unwrap()
                .is_empty()
        );
        // Another holding: the place and the answers start again there,
        // and the page got somewhere, though its place is lower.
        let anew_holding = take_page(
            conn,
            &s[0].identity,
            &here,
            &AT,
            ([5; 8], 10),
            (&[], [6; 8], 0),
            now,
        )
        .unwrap()
        .unwrap();
        assert!(anew_holding.got_somewhere);
        assert_eq!(place(conn, &here, &AT).unwrap(), ([6; 8], 0));
        assert_eq!(
            to_send(conn, &s[0].identity, &here, &AT, most).unwrap(),
            std::slice::from_ref(&own)
        );
        // A page of nothing under the mark of no holding, against a place
        // kept: the relay holds the channel no more.
        take_page(
            conn,
            &s[0].identity,
            &here,
            &AT,
            ([6; 8], 0),
            (&[], NO_MARK, 0),
            now,
        )
        .unwrap();
        assert_eq!(place(conn, &here, &AT).unwrap(), (NO_MARK, 0));
        // An entry of another channel: nothing of the page is taken.
        let other = crate::shared::tests::Shared::of(2);
        let stray = [message(&member(8), &other, 1, "x", now)];
        assert!(
            take_page(
                conn,
                &s[0].identity,
                &here,
                &AT,
                (NO_MARK, 0),
                (&stray, [7; 8], 3),
                now
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(place(conn, &here, &AT).unwrap(), (NO_MARK, 0));
    }

    /// What waits at a relay is each entry of the device's own that the
    /// relay has not answered at its revision or above (§8.4): one it holds,
    /// holds a later one of, holds another of, or refused as not signed is
    /// not sent there again; one it refused for room, or for the address's
    /// allowance, waits; a later revision waits again; another relay is its
    /// own; and a relay that answers a proof with no is sent everything
    /// again. A push is within its most, as a relay counts each entry.
    #[test]
    fn what_waits_is_what_a_relay_has_not_answered_at_its_revision() {
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        let conn = &s[0].conn;
        let identity = &s[0].identity;
        let here = usable(conn, &channel.id, &AT).unwrap().unwrap();
        let most = Most {
            entries: 100,
            bytes: 1 << 20,
        };
        let own = anew(identity, &channel, 1);
        crate::take::take(conn, identity, &own, now).unwrap();
        let waits = |relay: &[u8; 32]| to_send(conn, identity, &here, relay, most).unwrap();
        assert_eq!(waits(&AT), std::slice::from_ref(&own));
        for refused in [Pushed::NoRoom, Pushed::OverAllowance] {
            assert_eq!(
                pushed(
                    conn,
                    identity,
                    &here,
                    &AT,
                    std::slice::from_ref(&own),
                    &[refused],
                    now
                )
                .unwrap(),
                1
            );
            assert_eq!(waits(&AT), std::slice::from_ref(&own));
        }
        // Another at its revision writes it again above: a test of its own.
        for answer in [Pushed::Holds, Pushed::HoldsLater, Pushed::DoesNotCheck] {
            not_held_at(conn, &here, &AT).unwrap();
            assert_eq!(waits(&AT), std::slice::from_ref(&own));
            assert_eq!(
                pushed(
                    conn,
                    identity,
                    &here,
                    &AT,
                    std::slice::from_ref(&own),
                    &[answer],
                    now
                )
                .unwrap(),
                0
            );
            assert!(waits(&AT).is_empty(), "{answer:?}");
        }
        assert_eq!(waits(&ELSEWHERE), std::slice::from_ref(&own));
        // A later revision of its record waits again.
        let later = anew(identity, &channel, 2);
        crate::take::take(conn, identity, &later, now).unwrap();
        assert_eq!(waits(&AT), std::slice::from_ref(&later));
        // Within its most, as a relay counts the entry.
        let cost = usize::try_from(entry_cost(later.content.len())).unwrap();
        let within = |entries: usize, bytes: usize| {
            to_send(conn, identity, &here, &AT, Most { entries, bytes }).unwrap()
        };
        assert_eq!(within(1, cost), std::slice::from_ref(&later));
        assert!(within(1, cost - 1).is_empty());
        assert!(within(0, cost).is_empty());
        // Another key's entry is never the device's to push.
        let theirs = anew(&member(3), &channel, 1);
        crate::take::take(conn, identity, &theirs, now).unwrap();
        assert_eq!(waits(&AT), std::slice::from_ref(&later));
        // An answer at a lower revision does not undo one at a higher.
        let held = std::slice::from_ref(&later);
        pushed(conn, identity, &here, &AT, held, &[Pushed::Holds], now).unwrap();
        rows::answered(conn, here.id, &AT, &own.slot, own.rev, Answer::Holds).unwrap();
        assert!(waits(&AT).is_empty());
    }

    /// A channel dropped and taken again has its empty anew record written
    /// at revision 1 once more; a relay that kept the first answers that
    /// it holds another at that revision, and the record is written again
    /// above it and waits there (§2.3). Another key's entry, and a message
    /// of this device's, are not written again.
    #[test]
    fn an_anew_record_a_relay_holds_another_of_is_written_again_above() {
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        let conn = &s[0].conn;
        let identity = &s[0].identity;
        let most = Most {
            entries: 100,
            bytes: 1 << 20,
        };
        assert_eq!(
            crate::sharing::write_empty_anew_records(conn, identity, now).unwrap(),
            1
        );
        acts(&s, 0, Do::Drop(channel.id), now + 1);
        holds(&s, 0, 1, "review", now + 2);
        assert_eq!(
            crate::sharing::write_empty_anew_records(conn, identity, now + 2).unwrap(),
            1
        );
        let here = usable(conn, &channel.id, &AT).unwrap().unwrap();
        let first = to_send(conn, identity, &here, &AT, most).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].rev, 1);
        let theirs = anew(&member(3), &channel, 1);
        let mine = message(identity, &channel, 1, "hello", now + 2);
        crate::take::take(conn, identity, &mine, now + 2).unwrap();
        let batch = [first[0].clone(), theirs, mine.clone()];
        let answers = [Pushed::HoldsAnother; 3];
        pushed(conn, identity, &here, &AT, &batch, &answers, now + 3).unwrap();
        let again = to_send(conn, identity, &here, &AT, most).unwrap();
        assert_eq!(again.len(), 1, "{again:?}");
        assert_eq!((again[0].slot, again[0].rev), (first[0].slot, 2));
        let opened = again[0].open(&channel.secret).unwrap();
        assert_eq!(opened.name, anew_name(&identity.public_key()).unwrap());
        // Answered at the revision it was written over: nothing more.
        pushed(
            conn,
            identity,
            &here,
            &AT,
            &first,
            &[Pushed::HoldsAnother],
            now + 4,
        )
        .unwrap();
        assert_eq!(to_send(conn, identity, &here, &AT, most).unwrap(), again);
    }

    /// A read again from the start begins at most once a day for each
    /// channel (§6.3): the places of the channel go at every relay, and
    /// another asked within the day begins when the day is up.
    #[test]
    fn a_read_again_forgets_the_places_at_every_relay_once_a_day() {
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        let conn = &s[0].conn;
        let id = row(&s, 0, &channel).id;
        rows::keep_place(conn, id, &AT, &[5; 8], 9).unwrap();
        rows::keep_place(conn, id, &ELSEWHERE, &[6; 8], 4).unwrap();
        labels(&s, 0, &member(2).public_key(), Some("carol"), now);
        assert_eq!(begin_reads_again(conn, now).unwrap(), [channel.id]);
        assert_eq!(rows::place(conn, id, &AT).unwrap(), None);
        assert_eq!(rows::place(conn, id, &ELSEWHERE).unwrap(), None);
        rows::keep_place(conn, id, &AT, &[5; 8], 9).unwrap();
        labels(&s, 0, &member(3).public_key(), Some("dave"), now + 1);
        assert!(begin_reads_again(conn, now + DAY - 1).unwrap().is_empty());
        assert_eq!(rows::place(conn, id, &AT).unwrap(), Some(([5; 8], 9)));
        assert_eq!(begin_reads_again(conn, now + DAY).unwrap(), [channel.id]);
        assert_eq!(rows::place(conn, id, &AT).unwrap(), None);
    }

    /// The one entry a share pair channel's door pushes is a share that this
    /// device wrote there with the key it is for, and that its store holds
    /// at that revision (§8.4).
    #[test]
    fn the_share_pair_door_pushes_only_a_share_this_device_wrote_for_that_key() {
        let s = bob(1);
        let now = s.now + 10;
        let conn = &s[0].conn;
        let identity = &s[0].identity;
        let alice = member(1);
        let (channel, secret) = share_pair(identity, &alice.public_key()).unwrap();
        assert_eq!(share_pair(&alice, &s.key(0)).unwrap().0, channel);
        assert!(share_pair(identity, &s.key(0)).is_none());
        let name = cordelia_crypto::share::share_name(&[1; 32]);
        let share = crate::several::entry_by(
            identity,
            &secret,
            now as u64,
            &name,
            cordelia_crypto::entry::Value::Other(vec![0; 16]),
            &[],
        );
        assert!(!is_own_share(conn, identity, &alice.public_key(), &share).unwrap());
        entries::store(conn, &share, now).unwrap();
        assert!(is_own_share(conn, identity, &alice.public_key(), &share).unwrap());
        // Not for another key, and not another's entry there.
        assert!(!is_own_share(conn, identity, &member(2).public_key(), &share).unwrap());
        let theirs = crate::several::entry_by(
            &alice,
            &secret,
            now as u64,
            &name,
            cordelia_crypto::entry::Value::Other(vec![0; 16]),
            &[],
        );
        entries::store(conn, &theirs, now).unwrap();
        assert!(!is_own_share(conn, identity, &alice.public_key(), &theirs).unwrap());
    }
}
