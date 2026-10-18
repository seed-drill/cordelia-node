//! A read of a channel of the device's own with places of its own
//! (decision 2026-10-17 §4.2, items 1 to 3): the node's side of
//! [`cordelia_api::own_read`].
//!
//! The read is a pull of the channel at each relay, through the one way
//! in and its leave ([`DeviceEntries::through`]), page by page, each
//! taken through [`at_relays::take_page`] and the one door, as a pass
//! takes them. Its proof is the pass's: made once on a connection, and
//! again after a day. **What it asks and takes is within the pass's
//! budget at that relay, and not beside it:** what the device takes from
//! one relay in a minute ([`DeviceEntries::room_to_take`]), and the
//! requests it makes there on its own channels (counted by [`Leave`]).
//! Where the minute is used, it waits, as a read through the door for a
//! carry does.
//!
//! **A pull that the relay refuses for now is waited out, for a minute
//! at most:** a relay that has handed a connection what it may in a
//! minute, with the answers to shows that the device does not see,
//! resets the next pull with ERR_RATE_LIMIT, and the read asks again once
//! a little time has gone by, as where the device has asked what it asks
//! in a minute. A minute after the last page it was handed there, the
//! relay is not reached in that round. **And it asks again only while
//! the relay has refused fewer than BAN_THRESHOLD - 1 requests so within
//! BAN_WINDOW_SECS** ([`DeviceEntries::asks_again_after_a_refusal`]): a
//! relay refuses a breach of its rates with the same reset, and cuts off
//! an address at BAN_THRESHOLD breaches in that window. The count is the
//! relay's, kept where each request is answered ([`Leave`]): every
//! request that the relay refused so, a show, a proof, a pull or a push,
//! of a pass or of a read, across rounds and reads and connections, and
//! not reset by a page. It cannot count what other devices behind one
//! address are refused, nor what was refused before the node started.
//! **A relay at that count is asked nothing more by a read,** neither a
//! show, nor a proof, nor a pull, in any round of any read, until a
//! refusal has left the window: each request of a read is held to the
//! count as it is about to be sent ([`DeviceEntries::asks_after_refusals`]),
//! and where it is held the relay is not reached. A pass is not held back
//! by it.
//!
//! **What that costs a relay that is honest:** one near what it may hand
//! a connection in a minute refuses pulls for room, which are no breach.
//! For BAN_WINDOW_SECS after one, the next leaves the relay not reached in
//! that round, though it would have room again within its minute; after
//! two, it is not asked at all. A read there ends in part where it could
//! have read on. The pass's refusals count too, though the pass is not
//! held back: two of its pulls refused for room keep every read away from
//! that relay for up to BAN_WINDOW_SECS, the read before a carried name is
//! let go among them, and the let-go is then refused and the command says
//! to run it again. The count is of refusals already made, not of
//! requests in flight, and that window is accepted: a request already in
//! flight from another door on the same connection (a pass, its shows,
//! the door for a carry or for a typed key) can be refused at the same
//! moment as a read's, so a read's request can be the relay's third
//! refusal within its window. A relay's refusal for room is no breach; a
//! breach comes only from the rate of requests, which the device's own
//! pace keeps under; the worst is that one address is cut off for a
//! while. If a cut-off is ever seen, counting the requests in flight with
//! the refusals is the change to make. Telling the two apart needs a code of the relay's own
//! (decision 2026-10-17 §11). **Every other failure ends the
//! relay's read in that round as not reached:** no answer, a stream that
//! times out or is reset otherwise, an answer that is not a page, a
//! connection that was lost. A relay that is down, or broken, does not
//! hold the read (decision 2026-10-17 §3.2 item 4).
//!
//! **One round runs at a time on the node, and none for longer than a
//! carry may read** (CARRY_READ_MAX_SECS, the round of decision
//! 2026-10-17 §3.5): a round that is asked for waits for the one that
//! runs, until its own time is gone. A read that another of the same
//! channel took the place of stops at its next page, and a round whose
//! asker has gone stops, and its read is forgotten.
//!
//! **It runs outside the database's lock.** The lock is taken to read
//! which channels are the device's own, and to take each page, as a pass
//! takes it, and is never held while a relay is asked. Its places and
//! what each relay handed are kept in the node's memory, under the read's
//! ID, between rounds ([`cordelia_api::state::OwnChannels::reads`]).
//!
//! [`Leave`]: super::Leave

use std::sync::Arc;
use std::time::{Duration, Instant};

use cordelia_api::at_relays::{self, Own, Page, PageTaken, Places};
use cordelia_api::own_read::{Handed, OwnAt, ReadId};
use cordelia_api::state::OwnAsk;
use cordelia_core::protocol::{CARRY_READ_MAX_SECS, ENTRY_PAGE_MAX_ENTRIES};
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_network::messages::{EntryPull, WireMessage};
use cordelia_storage::relay::Mark;

use super::{
    At, DeviceEntries, LEFT_ROOM_WAIT, Link, Refused, Relay, Step, counted_as_handed, lock,
};

/// The longest that one round of a read lasts.
const ROUND_MOST: Duration = Duration::from_secs(CARRY_READ_MAX_SECS);

/// The minute in which a relay counts what it hands a connection
/// (PUSH_BYTES_PER_PEER_PER_MINUTE): a relay that refuses a pull for now
/// has room again within it.
pub(super) const A_MINUTE: Duration = Duration::from_secs(60);

/// What came of one pull of the read.
enum Pulled {
    /// A page of the channel, which the door took: its entries, the mark
    /// and the place to ask after next.
    Page(Vec<CheckedEntry>, Mark, u64),
    /// What came back is no page of the channel.
    NotThePage,
    /// The page could not be taken: the device's database failed. Nothing
    /// of it was taken.
    Failed,
}

impl DeviceEntries {
    /// Take up what a command's work asked for a read of a channel of the
    /// device's own (decision 2026-10-17 §4.2), and answer it. `relays` is
    /// every relay that the device is set up with, each with its
    /// connection where there is one.
    ///
    /// - **Begin:** the read is kept under a new ID, every relay from the
    ///   start, and its first round is read. It is refused where the
    ///   channel is not one that a pass pulls now, and where the node is
    ///   held up: nothing is asked of a relay then.
    /// - **Read on:** one round more, at each relay where the read is in
    ///   part, from its place there.
    ///
    /// A round lasts until `until`, and no longer than CARRY_READ_MAX_SECS
    /// from now, whatever was asked.
    pub async fn own(self: &Arc<Self>, relays: &[Relay], ask: OwnAsk) {
        match ask {
            OwnAsk::Begin {
                channel,
                until,
                mut answer,
            } => {
                let until = until.min(self.clock.now() + ROUND_MOST);
                let begun = self.begin_own(relays, &channel);
                if let Some(read) = &begun {
                    tokio::select! {
                        _ = self.read_own(relays, read, until) => {}
                        _ = answer.closed() => return self.asker_gone(read),
                    }
                }
                let _ = answer.send(begun);
            }
            OwnAsk::ReadOn {
                read,
                until,
                mut answer,
            } => {
                let until = until.min(self.clock.now() + ROUND_MOST);
                let known = tokio::select! {
                    known = self.read_own(relays, &read, until) => known,
                    _ = answer.closed() => return self.asker_gone(&read),
                };
                let _ = answer.send(known);
            }
        }
    }

    /// Whoever asked for a round of the read named `read` has gone: the
    /// round stopped where it was, and nothing will ask for the read, so
    /// it is kept no more.
    fn asker_gone(&self, read: &ReadId) {
        self.state.own_channels.reads().forget(read);
    }

    /// Keep a new read of `channel` at each of `relays`, where it is one
    /// that a pass pulls now, under the change entry that the device keeps.
    /// `None` where it is not, or where the node is held up.
    fn begin_own(&self, relays: &[Relay], channel: &[u8; 32]) -> Option<ReadId> {
        if self.state.held.why().is_some() {
            return None;
        }
        let under = {
            let db = lock(&self.state.db);
            let own = at_relays::channels(&db, &self.state.identity).ok()?;
            if !own.iter().any(|own| own.id == *channel && own.is_pulled()) {
                return None;
            }
            at_relays::kept_id(&db).ok()??
        };
        let names: Vec<String> = relays.iter().map(|relay| relay.name.clone()).collect();
        let begun =
            self.state
                .own_channels
                .reads()
                .begin(channel, &under, &names, self.clock.now());
        begun.ok()
    }

    /// Read one round of the read named `read`: at each relay where it is
    /// in part, beside one another, until `until`. Says whether the node
    /// keeps that read, with no round of it running. A round waits for
    /// the one that runs on the node, and reads nothing where `until` goes
    /// by first.
    ///
    /// A relay that is not connected now is not reached, and is not asked
    /// again. So is every relay where the channel is no longer one of the
    /// device's own, or the node is held up. Every request is made under
    /// the change entry that the read began under, and the one way in
    /// refuses it where the device keeps another: nothing is asked of a
    /// relay for a channel that the device has left.
    async fn read_own(self: &Arc<Self>, relays: &[Relay], read: &ReadId, until: Instant) -> bool {
        let reads = self.state.own_channels.reads();
        let wait = until.saturating_duration_since(self.clock.now());
        let Ok(_one_round) = tokio::time::timeout(wait, self.own_rounds.lock()).await else {
            return reads.stands(read);
        };
        let Some((channel, under, at)) = reads.to_read(read, self.clock.now()) else {
            return false;
        };
        let own: Option<Own> = (self.state.held.why().is_none())
            .then(|| {
                let db = lock(&self.state.db);
                let own = at_relays::channels(&db, &self.state.identity).ok()?;
                own.into_iter()
                    .find(|own| own.id == channel && own.is_pulled())
            })
            .flatten();
        let mut reading = tokio::task::JoinSet::new();
        let mut done = Vec::with_capacity(at.len());
        for mut one in at {
            let link = relays
                .iter()
                .find(|relay| relay.name == one.relay)
                .and_then(|relay| relay.link.clone())
                .filter(|link| link.is_open());
            match (&own, link) {
                (Some(channel), Some(link)) => {
                    let (engine, channel, read) = (Arc::clone(self), channel.clone(), *read);
                    reading.spawn(async move {
                        engine
                            .read_own_at(&link, &read, &under, &channel, one, until)
                            .await
                    });
                }
                _ => {
                    one.not_reached();
                    done.push(one);
                }
            }
        }
        while let Some(one) = reading.join_next().await {
            if let Ok(one) = one {
                done.push(one);
            }
        }
        reads.read(read, done, self.clock.now());
        true
    }

    /// Read `channel` at the relay at `link`, from the read's own place
    /// there, page after page, until the relay's read ends or `until`.
    ///
    /// The proof is the pass's ([`Self::prove`]), and its answer moves
    /// nothing that the device keeps: a relay that does not hold the
    /// channel says so to the pull, with the mark of no holding. Where it
    /// was not made, or not answered, the relay is not reached.
    ///
    /// It stops where the read named `read` stands no more: another read
    /// of the channel took its place. Neither a wait nor a request runs
    /// past `until`.
    async fn read_own_at(
        &self,
        link: &Link,
        read: &ReadId,
        under: &[u8; 32],
        channel: &Own,
        mut at: OwnAt,
        until: Instant,
    ) -> OwnAt {
        let asks = At {
            link,
            under: *under,
            gated: true,
        };
        // The proof too is within the round's time: where the time goes
        // while the relay is asked, the read stands there as it was.
        let left = until.saturating_duration_since(self.clock.now());
        let Ok(proved) = tokio::time::timeout(left, self.prove(&asks, channel, false)).await else {
            return at;
        };
        if !matches!(proved, Step::Done(true)) {
            at.not_reached();
            return at;
        }
        let relay = link.relay().0;
        let reads = self.state.own_channels.reads();
        // When the relay last handed this read a page, or the round began.
        let mut paged = self.clock.now();
        loop {
            let now = self.clock.now();
            if now >= until || !reads.stands(read) {
                return at;
            }
            let left = until - now;
            // Within what the device takes from this relay in a minute,
            // with the pass: where the minute is used, it waits for room.
            if !self.room_to_take(link) {
                tokio::time::sleep(LEFT_ROOM_WAIT.min(left)).await;
                continue;
            }
            let (mark, after) = at.place;
            let request = WireMessage::EntryPull(EntryPull {
                channel: channel.id,
                mark,
                after,
                limit: ENTRY_PAGE_MAX_ENTRIES,
            });
            let now = self.unix();
            let taken = self.through(
                &asks,
                &request,
                |_| (),
                |answer| {
                    // A page of more entries than a page may hold is
                    // refused where it is read off the wire.
                    let WireMessage::EntryPulled(page) = answer else {
                        return (0, None);
                    };
                    // What the relay handed counts as taken from it,
                    // whatever is then done with it.
                    let handed: u64 = page
                        .entries
                        .iter()
                        .map(|bytes| counted_as_handed(bytes.len()))
                        .sum();
                    self.took(link, handed);
                    let entries: Option<Vec<CheckedEntry>> = page
                        .entries
                        .iter()
                        .map(|bytes| Entry::from_wire(bytes).ok()?.check().ok())
                        .collect();
                    (
                        handed,
                        entries.map(|entries| (entries, page.mark, page.next)),
                    )
                },
                |db, (handed, page)| {
                    let Some((entries, mark, next)) = page else {
                        return (handed, Pulled::NotThePage);
                    };
                    let page = Page {
                        relay: &relay,
                        channel,
                        entries: &entries,
                        mark,
                        next,
                    };
                    let identity = &self.state.identity;
                    let pulled = match at_relays::take_page(db, identity, &page, Places::Own, now) {
                        Ok(PageTaken::Taken { .. }) => Pulled::Page(entries, mark, next),
                        Ok(PageTaken::NotThePage) => Pulled::NotThePage,
                        Err(e) => {
                            tracing::debug!(error = %e, "could not take a page");
                            Pulled::Failed
                        }
                    };
                    (handed, pulled)
                },
            );
            // The round's time is gone while the relay is asked: the read
            // stands there as it was.
            let Ok(taken) = tokio::time::timeout(left, taken).await else {
                return at;
            };
            let (counted, pulled) = match taken {
                Ok(taken) => taken,
                // Asked enough of this relay for this minute, with the
                // pass: it waits, and asks again.
                Err(Refused::AskedEnough) => {
                    tokio::time::sleep(LEFT_ROOM_WAIT.min(left)).await;
                    continue;
                }
                // Refused for now: the relay counts the answers to shows
                // in its minute, which the device does not see. Within a
                // minute of the last page it handed, it has room again:
                // the read waits, and asks again, short of the relay's
                // count of breaches.
                Err(Refused::NotNow) => {
                    let again = self.asks_again_after_a_refusal(link);
                    let within = self.clock.now() < paged + A_MINUTE;
                    if !within || !again {
                        at.not_reached();
                        return at;
                    }
                    tokio::time::sleep(LEFT_ROOM_WAIT.min(left)).await;
                    continue;
                }
                Err(_) => {
                    at.not_reached();
                    return at;
                }
            };
            let page = match &pulled {
                Pulled::Page(entries, mark, next) => {
                    paged = self.clock.now();
                    let mut kept = lock(&self.kept);
                    let of = kept.relays.entry(link.name().to_string()).or_default();
                    of.counts.pages += 1;
                    of.counts.pulled += entries.len() as u64;
                    Handed::Page {
                        entries,
                        counted,
                        mark: *mark,
                        next: *next,
                    }
                }
                Pulled::NotThePage => Handed::NotThePage { counted },
                Pulled::Failed => {
                    at.not_reached();
                    return at;
                }
            };
            if !at.handed(page) {
                return at;
            }
        }
    }
}
