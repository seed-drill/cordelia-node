//! The shared half of the one function that sends (decision 2026-10-10
//! §4.2, §6.1, §6.4): what `sender::send` does with `Address::Shared`.
//!
//! - **The address is a shared channel's ID**, looked up in the table of
//!   shared channels alone; a reply is looked up in that channel alone, and
//!   refused where it names a message of another kind of address.
//! - **The message is of form 6** (`SharedMessage`): no agent's name and no
//!   recipient. It is written in the device's own ring of 64 slots in the
//!   channel, at the next number from the store, through the one door, and
//!   its sent mark is the newest in the device's table of shared marks
//!   (§6.1): nothing about sending is written in the shared channel.
//! - **The rates** (§6.4): a first send counts in its folder's 20 and the
//!   device's 60 an hour, as every message of the person's does, and in the
//!   channel's own hour of 60 numbers; a send again counts in the channel's
//!   hour alone, and waits where it is full.
//! - **Sending again** under the next number, at most four numbers for a
//!   message, in the messages record's two cases (its §2.3); and **clearing**
//!   at 30 days by the sender, from the hourly task.
//! - **Nothing is written before the channel is fetched** since the node
//!   started, at the relays of its card that the device reaches.

use rusqlite::Connection;

use cordelia_core::protocol::{
    AGENT_MESSAGE_PAIR_UNREAD_MAX, AGENT_MESSAGE_RING, AGENT_MESSAGE_SENDS_MAX,
    AGENT_MESSAGES_PER_DEVICE_PER_HOUR, AGENT_MESSAGES_PER_FOLDER_PER_HOUR,
};
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::message::{
    self, clearing_rev, clearing_value, message_id, message_name, message_rev, number_of,
    shared_sent_mark,
};
use cordelia_crypto::share::Card;
use cordelia_crypto::shared::SharedMessage;
use cordelia_crypto::slots::slot_id;
use cordelia_storage::entries::{self, Outcome};
use cordelia_storage::messages as held;
use cordelia_storage::shared::{self as kept_rows, Channel, State};
use cordelia_storage::shared_messages::{self as rows, Kept};
use cordelia_storage::shared_pass::Answer;

use crate::person::{PersonError, in_one};
use crate::sender::{
    Address, At, NotSent, Refused, Reply, Request, Sent, device_full, frees_at, kept, nonce,
};
use crate::take::Taken;

fn stored<T>(answer: Result<T, cordelia_core::CordeliaError>) -> Result<T, PersonError> {
    answer.map_err(PersonError::Storage)
}

/// The device's ring in a shared channel it holds.
pub(crate) struct Ring<'a> {
    identity: &'a NodeIdentity,
    own: [u8; 32],
    pub(crate) row: Channel,
    secret: [u8; 32],
    slot_key: [u8; 32],
}

impl<'a> Ring<'a> {
    /// The ring in the shared channel `channel`, where the device holds it.
    pub(crate) fn of(
        conn: &Connection,
        identity: &'a NodeIdentity,
        channel: &[u8; 32],
    ) -> Result<Option<Self>, PersonError> {
        let Some(row) = stored(kept_rows::channel(conn, channel))? else {
            return Ok(None);
        };
        if row.state != State::Held {
            return Ok(None);
        }
        Self::of_row(identity, row).map(Some)
    }

    fn of_row(identity: &'a NodeIdentity, row: Channel) -> Result<Self, PersonError> {
        let card = Card::from_bytes(&row.card)
            .map_err(|e| PersonError::Held(format!("the card of a shared channel: {e}")))?;
        let secret = card.secret()?;
        Ok(Self {
            identity,
            own: identity.public_key(),
            slot_key: derive::slot_key(&secret)?,
            secret,
            row,
        })
    }

    fn slot(&self, number: u64) -> Result<[u8; 32], PersonError> {
        Ok(slot_id(&self.slot_key, &message_name(&self.own, number)?))
    }

    /// The device's own entry held in each slot of its ring, with the
    /// slot's place.
    fn held(&self, conn: &Connection) -> Result<Vec<(u64, CheckedEntry)>, PersonError> {
        let mut found = Vec::new();
        for place in 0..AGENT_MESSAGE_RING as u64 {
            let slot = self.slot(place)?;
            if let Some(entry) = entries::author_entry(conn, &self.row.channel, &slot, &self.own)? {
                found.push((place, entry.entry.check()?));
            }
        }
        Ok(found)
    }

    /// The next number: one above the highest of any entry of the device's
    /// own in its ring there, clearings included. A shared channel has no
    /// generation: its numbers go on from one statement to the next.
    fn next(&self, conn: &Connection) -> Result<Option<u64>, PersonError> {
        let highest = self
            .held(conn)?
            .iter()
            .map(|(_, entry)| number_of(entry.rev))
            .max()
            .unwrap_or(0);
        Ok(message::next_number(highest))
    }

    /// The newest `sent` of the device's own messages there.
    fn newest_sent(&self, conn: &Connection) -> Result<Option<i64>, PersonError> {
        let mut newest = None;
        for (_, entry) in self.held(conn)? {
            let Ok(inside) = entry.open(&self.secret) else {
                continue;
            };
            if let Ok(sent) = SharedMessage::from_value(&inside.value) {
                let sent = i64::try_from(sent.sent).unwrap_or(i64::MAX);
                newest = Some(newest.map_or(sent, |was: i64| was.max(sent)));
            }
        }
        Ok(newest)
    }

    /// Write `value` at `rev` in the slot of `number`, through the one door:
    /// the store must take it, being above everything the device holds in
    /// its ring there.
    fn write(
        &self,
        conn: &Connection,
        number: u64,
        rev: u64,
        value: Vec<u8>,
        now: i64,
    ) -> Result<(), PersonError> {
        let inside = message::inside(message_name(&self.own, number)?, value);
        let entry = Entry::seal(&self.secret, self.identity, rev, &inside)?.check()?;
        match crate::take::take(conn, self.identity, &entry, now)? {
            Taken::Shared {
                stored: Outcome::Stored,
                ..
            } => Ok(()),
            other => Err(PersonError::Held(format!(
                "the door did not store this device's entry in a shared channel: {other:?}"
            ))),
        }
    }
}

/// `sender::send` of a request whose address is the shared channel
/// `channel` (decision 2026-10-10 §4.2, §5.5, §6.1, §6.4), in the caller's
/// write, after the device's and sync's checks (steps 4 and 5): the folder,
/// the channel, the subscription, the reach, the fetch, the ring and the
/// clock, the reply, the rates and the hold, the first that applies
/// refusing.
pub(crate) fn sends(
    conn: &Connection,
    identity: &NodeIdentity,
    at: &At,
    request: &Request,
    channel: &[u8; 32],
    reply: impl FnOnce(&Connection) -> Result<Option<Reply>, Refused>,
) -> Result<Sent, NotSent> {
    let refused = |why: Refused| Err(NotSent::Refused(why));
    let now = at.now;
    // 7. The folder: mapped, then its rate where it is set to 0.
    if !at.mapped {
        return refused(Refused::NotMapped);
    }
    let folder_limit = at
        .per_folder_per_hour
        .min(AGENT_MESSAGES_PER_FOLDER_PER_HOUR);
    if folder_limit == 0 {
        return refused(Refused::SendingOff);
    }
    // The channel, in the table of shared channels alone; the folder's
    // agent subscribes to it; it is reached from this device.
    let Some(ring) = Ring::of(conn, identity, channel)? else {
        return refused(Refused::NoSuchChannel);
    };
    if crate::shared_messages::start_of(conn, channel, &request.from)?.is_none() {
        return refused(Refused::NotSubscribed);
    }
    if !at.shared_reached {
        return refused(Refused::NotReached);
    }
    // 8. The ring: fetched, a number left, and the clock.
    if !at.shared_fetched {
        return refused(Refused::NotFetched);
    }
    let Some(number) = ring.next(conn)? else {
        return refused(Refused::NoNumbers);
    };
    if ring.newest_sent(conn)?.is_some_and(|newest| newest > now) {
        return refused(Refused::ClockBehind);
    }
    // 9. The message a reply answers: in this channel alone.
    let (thread, answers) = match reply(conn) {
        Ok(Some(Reply {
            to: Address::Shared(of),
            thread,
            answers,
        })) if of == *channel => (thread, answers),
        Ok(Some(Reply { to, .. })) => {
            return refused(Refused::ReplyElsewhere {
                id: String::new(),
                channel: match to {
                    Address::Shared(of) => Some(of),
                    Address::Own(_) => None,
                },
            });
        }
        Ok(None) => (request.thread, request.answers),
        Err(Refused::NoSuchMessage(given)) => {
            return refused(elsewhere(conn, identity, request, channel, given, now)?);
        }
        Err(why) => return refused(why),
    };
    // 11. The rates: the folder's, the device's, and the channel's hour.
    let lately = kept(held::sent_lately(conn, &request.from, now))?;
    if lately.by_folder.len() >= folder_limit {
        return refused(Refused::FolderRate {
            limit: folder_limit,
            next_at: frees_at(&lately.by_folder, folder_limit),
        });
    }
    if let Some(next_at) = device_full(&lately) {
        return refused(Refused::DeviceRate {
            sends: lately.sends.len(),
            again: lately.again.len(),
            next_at,
        });
    }
    if let Some((sends, again, next_at)) = channel_full(conn, ring.row.id, now)? {
        return refused(Refused::ChannelRate {
            sends,
            again,
            next_at,
        });
    }
    // 12. The hold: the loop this agent is in, at 10.
    let waiting = crate::shared_messages::held(conn, identity, &ring.row, &request.from, now)?;
    if waiting >= AGENT_MESSAGE_PAIR_UNREAD_MAX as u64 {
        return refused(Refused::SharedHeld {
            from: request.from.clone(),
            waiting,
        });
    }

    let shared = SharedMessage {
        asks: request.asks,
        sent: u64::try_from(now).unwrap_or(0),
        nonce: nonce()?,
        thread,
        answers,
        link: request.link.clone(),
        body: request.body.clone(),
    };
    let value = shared.to_value().map_err(NotSent::NotAMessage)?;
    let id = message_id(&ring.own, &value);
    let rev = message_rev(number).ok_or(PersonError::Held(
        "a message's number is above the highest".into(),
    ))?;
    ring.write(conn, number, rev, value.clone(), now)?;
    // What an agent sent is said to the person's own devices alone (§6.1).
    crate::shared_messages::mark(conn, &shared_sent_mark(channel, &id, &request.from), now)?;
    kept(held::record_send(conn, now, Some(&request.from), false))?;
    stored(rows::record_send(conn, ring.row.id, now, false))?;
    let kept_value = Kept {
        channel: ring.row.id,
        id,
        value,
        sent: now,
        numbers: vec![number],
        again: false,
    };
    stored(rows::keep(conn, &kept_value, now))?;
    Ok(Sent { id, number })
}

/// Why a reply to `given` with `--channel` names no message there: one of
/// the person's own agents' (`reply_elsewhere`, of no channel), one of
/// another shared channel's, or none.
fn elsewhere(
    conn: &Connection,
    identity: &NodeIdentity,
    request: &Request,
    channel: &[u8; 32],
    given: String,
    now: i64,
) -> Result<Refused, PersonError> {
    if crate::messages::named(conn, identity, &request.from, &given, now, false)?.is_ok() {
        return Ok(Refused::ReplyElsewhere {
            id: given,
            channel: None,
        });
    }
    Ok(
        match crate::shared_messages::names_a_shared_message(
            conn,
            identity,
            &request.from,
            &given,
            now,
        )? {
            Some(other) if other != *channel => Refused::ReplyElsewhere {
                id: given,
                channel: Some(other),
            },
            _ => Refused::NoSuchMessage(given),
        },
    )
}

/// Whether the shared channel of a row was fetched since the node started,
/// at the relays of its card that are, by key, the device's own (§6.1), as
/// the node knows it at `now`: what [`write_again`] and [`clear_expired`]
/// are given.
pub fn fetched_of(
    state: &crate::state::AppState,
    now: std::time::Instant,
) -> impl Fn(&Channel) -> bool + '_ {
    let own = crate::sharing::own_relays(state);
    move |row: &Channel| {
        let Ok(card) = Card::from_bytes(&row.card) else {
            return false;
        };
        let reached = card
            .relays()
            .keys()
            .iter()
            .filter(|key| own.iter().any(|relay| relay.key == **key))
            .count();
        state
            .own_channels
            .shared_fetch_done(&row.channel, reached, now)
    }
}

/// Where the device has written 60 numbers in the channel of row `row` in
/// the hour before `now`, its first sends and its sends again together
/// (§6.4): how many of each, and when the next can go.
fn channel_full(
    conn: &Connection,
    row: i64,
    now: i64,
) -> Result<Option<(usize, usize, i64)>, PersonError> {
    let (sends, again) = stored(rows::sends_lately(conn, row, now))?;
    let mut all: Vec<i64> = sends.iter().chain(&again).copied().collect();
    if all.len() < AGENT_MESSAGES_PER_DEVICE_PER_HOUR {
        return Ok(None);
    }
    all.sort_unstable();
    Ok(Some((
        sends.len(),
        again.len(),
        frees_at(&all, AGENT_MESSAGES_PER_DEVICE_PER_HOUR),
    )))
}

// ── What a relay answered, and sending again ─────────────────────────

/// The door stored `entry`, the device's own entry in the shared channel of
/// row `row`, whose slot key is `slot_key`, over what it held (the
/// messages record's §2.3, case 2): where it is a message in the slot of
/// the newest number of a message that not every relay has taken, above
/// it, it is the device's own entry from its later life, and that message
/// waits to be sent again. In the door's write.
pub(crate) fn taken_over(
    conn: &Connection,
    own: &[u8; 32],
    row: i64,
    slot_key: &[u8; 32],
    entry: &CheckedEntry,
) -> Result<(), PersonError> {
    if entry.author != *own || message::is_clearing_rev(entry.rev) {
        return Ok(());
    }
    for waiting in stored(rows::kept(conn))? {
        if waiting.channel != row || waiting.again {
            continue;
        }
        let Some(newest) = waiting.numbers.last().copied() else {
            continue;
        };
        let above = message_rev(newest).is_some_and(|rev| entry.rev > rev);
        if above && entry.slot == slot_id(slot_key, &message_name(own, newest)?) {
            stored(rows::send_again(conn, row, &waiting.id))?;
        }
    }
    Ok(())
}

/// A relay answered a push of `entry`, the device's own entry in the shared
/// channel of row `row`, with `answer` (§6.1, as the messages record's
/// `sender::answered`), in the caller's write. Another at the revision of
/// the newest number of a kept message: it waits to be sent again. Held:
/// where every relay of the channel's card has now answered that it holds
/// the message at its newest number, its kept value goes.
pub(crate) fn answered(
    conn: &Connection,
    row: i64,
    entry: &CheckedEntry,
    answer: Answer,
) -> Result<(), PersonError> {
    if message::is_clearing_rev(entry.rev) {
        return Ok(());
    }
    let number = number_of(entry.rev);
    let Some(id) = stored(rows::kept_at(conn, row, number))? else {
        return Ok(());
    };
    let Some(waiting) = stored(rows::kept(conn))?
        .into_iter()
        .find(|waiting| waiting.channel == row && waiting.id == id)
    else {
        return Ok(());
    };
    if waiting.numbers.last() != Some(&number) {
        return Ok(());
    }
    match answer {
        Answer::HoldsAnother => stored(rows::send_again(conn, row, &id))?,
        Answer::Holds => {
            let Some(channel) = stored(kept_rows::channel_of_row(conn, row))? else {
                return Ok(());
            };
            let card = Card::from_bytes(&channel.card)
                .map_err(|e| PersonError::Held(format!("the card of a shared channel: {e}")))?;
            let mut everywhere = true;
            for relay in card.relays().keys() {
                let said = stored(cordelia_storage::shared_pass::answer(
                    conn,
                    row,
                    relay,
                    &entry.slot,
                ))?;
                everywhere &=
                    said.is_some_and(|(rev, answer)| rev >= entry.rev && answer == Answer::Holds);
            }
            if everywhere {
                stored(rows::drop_kept(conn, row, &id))?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Write again, each under the next number, the device's own messages in
/// shared channels that wait to be sent again, at `now` (§6.1, §6.4), in
/// one transaction: only in a channel held and fetched since the node
/// started (`fetched`, of the channel's ID), where the device stands
/// applied with sync on; each counts in that channel's hour alone, never
/// in a folder's or the device's, and waits where that hour is full; at
/// most four numbers for a message, its kept value dropped where a fifth
/// would be needed. Returns how many were written.
pub fn write_again(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: &dyn Fn(&Channel) -> bool,
) -> Result<usize, PersonError> {
    in_one(conn, || {
        if crate::shared_pass::may_open(conn)?.is_err() {
            return Ok(0);
        }
        let mut written = 0;
        for waiting in stored(rows::kept(conn))? {
            if !waiting.again {
                continue;
            }
            let Some(row) = stored(kept_rows::channel_of_row(conn, waiting.channel))? else {
                continue;
            };
            if row.state != State::Held || !fetched(&row) {
                continue;
            }
            let ring = Ring::of_row(identity, row)?;
            let next = ring.next(conn)?;
            let Some(number) = next.filter(|_| waiting.numbers.len() < AGENT_MESSAGE_SENDS_MAX)
            else {
                stored(rows::drop_kept(conn, waiting.channel, &waiting.id))?;
                continue;
            };
            if channel_full(conn, waiting.channel, now)?.is_some() {
                continue;
            }
            let rev = message_rev(number).ok_or(PersonError::Held(
                "a message's number is above the highest".into(),
            ))?;
            ring.write(conn, number, rev, waiting.value.clone(), now)?;
            stored(rows::kept_under(conn, waiting.channel, &waiting.id, number))?;
            stored(rows::record_send(conn, waiting.channel, now, true))?;
            written += 1;
        }
        Ok(written)
    })
}

/// The hourly task's clearing in shared channels (§6.1, as the messages
/// record's `sender::clear_expired`): where the device stands applied with
/// sync on, in each channel held and fetched since the node started, it
/// writes the entry that clears each of its own messages whose `sent` is 30
/// days or more before `now`, in the same slot, one revision on, through
/// the one door; and the kept values of messages 30 days old go. Returns
/// how many it cleared.
pub fn clear_expired(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: &dyn Fn(&Channel) -> bool,
) -> Result<usize, PersonError> {
    in_one(conn, || {
        if crate::shared_pass::may_open(conn)?.is_err() {
            return Ok(0);
        }
        let mut cleared = 0;
        for row in stored(kept_rows::channels(conn))? {
            if row.state != State::Held || !fetched(&row) {
                continue;
            }
            let ring = Ring::of_row(identity, row)?;
            for (place, entry) in ring.held(conn)? {
                let number = number_of(entry.rev);
                if message::is_clearing_rev(entry.rev)
                    || message_rev(number).is_none()
                    || number % AGENT_MESSAGE_RING as u64 != place
                {
                    continue;
                }
                let Ok(inside) = entry.open(&ring.secret) else {
                    continue;
                };
                let Ok(sent) = SharedMessage::from_value(&inside.value) else {
                    continue;
                };
                let sent = i64::try_from(sent.sent).unwrap_or(i64::MAX);
                if !held::has_expired(sent, sent, now) {
                    continue;
                }
                let Some(rev) = clearing_rev(number) else {
                    continue;
                };
                ring.write(conn, number, rev, clearing_value(), now)?;
                cleared += 1;
            }
        }
        for waiting in stored(rows::kept(conn))? {
            if held::has_expired(waiting.sent, waiting.sent, now) {
                stored(rows::drop_kept(conn, waiting.channel, &waiting.id))?;
            }
        }
        Ok(cleared)
    })
}
