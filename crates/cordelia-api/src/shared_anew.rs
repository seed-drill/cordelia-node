//! Making a shared channel anew, moving to a channel made anew, and what a
//! removal and a recovery do to the shared channels (decision 2026-10-10
//! §3.5, §5.1 to §5.5, §7; decision 2026-10-24, rules 23 to 26).
//!
//! - **An offer** is an anew record that is not empty, in the slot of a key
//!   this device shows. The reader keeps what each says once for each
//!   revision of it ([`read`]), apart from the store (schema step 26), and
//!   each is judged where it is shown or acted on ([`judged`]): a fault
//!   (of a channel the person holds or held, by a key the person's
//!   statement removed, or whose seal for this device does not open),
//!   "without you", sealed to another device of the person's, or an offer
//!   this device may move to. Who an offer leaves out is worked out by the
//!   reader: the keys it shows that the offer does not seal to, less its own
//!   devices, which follow their person.
//! - **`shared anew`** ([`anew_plan`], [`make_anew`]): every key of the
//!   device's table of the channel is listed before anything is asked; the
//!   person answers each with `keep` or `out`, or `out for the rest`; the
//!   maker's own devices stay and a removed key never does. The new seed is
//!   sealed to each key that stays in the old channel, and the new channel
//!   is filed in the old one's place.
//! - **`shared move`** ([`move_plan`], [`make_move`]) files the channel of an
//!   offer this device's seal opens to in the old one's place, with each
//!   subscription of the old one.
//! - **`shared stay`** ([`stay_plan`], [`make_stay`]): a person goes on
//!   writing in a channel an offer paused (rule 26).
//! - **A removal** marks every shared channel this device holds as not yet
//!   clean ([`removal_applied`], rule 23); the device that makes it makes
//!   each anew in the same act ([`anew_at_removal`], rule 24); a device
//!   that finds one not made anew sends nothing there (rule 25).
//! - **The old channel's offer is delivered:** a channel moved from keeps
//!   its entries in the store until its offer is at each relay of its card,
//!   or for 30 days at most ([`deliveries`]), and then they are taken out.

use rusqlite::Connection;

use cordelia_core::protocol::{SEALED_SECRET_BYTES, SHARED_MAX_KEYS, SHARED_OFFER_DELIVERED_SECS};
use cordelia_crypto::acts::{Came, Filing};
use cordelia_crypto::bech32::encode_public_key;
use cordelia_crypto::derive;
use cordelia_crypto::entry::{Entry, Inside, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::share::{Card, Relays};
use cordelia_crypto::shared::{Anew, Offer, Seal, anew_name};
use cordelia_crypto::slots::slot_id;
use cordelia_storage::entries;
use cordelia_storage::shared::{self as kept, Channel, State};
use cordelia_storage::shared_anew::{self as rows, MadeRow, OfferRow};
use cordelia_storage::shared_pass::{self as pass_rows, ChannelOut};

use crate::lists::{self, AnyAct, Do, Maker};
use crate::person::{Counting, Held, PersonError, held, in_one};
use crate::sharing::{
    self, Failed, Out, OwnRelay, Plan, channel_words, date_of, refused, relay_shown, sender_form,
    six_words, standing,
};

/// How long the entries of a channel moved from wait in the store for its
/// offer to be at each relay of its card (§7, `SHARED_OFFER_DELIVERED_SECS`).
const DELIVERING_SECS: i64 = SHARED_OFFER_DELIVERED_SECS as i64;

/// The first bytes of the name of every notice of this record that
/// `cordelia devices` shows: a statement forgets the notices a person
/// cleared, and not these (§3.5: clearing ends the naming).
pub const SHARED_NOTICE: &[u8; 4] = b"shrd";

fn st<T>(answer: Result<T, cordelia_core::CordeliaError>) -> Result<T, PersonError> {
    answer.map_err(PersonError::Storage)
}

fn card_of(row: &Channel) -> Result<Card, PersonError> {
    Card::from_bytes(&row.card)
        .map_err(|e| PersonError::Held(format!("the card of a shared channel: {e}")))
}

// ── Reading an offer ─────────────────────────────────────────────────

/// The reader read `record`, the anew record of `signer` at revision `rev`
/// in the shared channel of `row`, at `now` (§2.3, rule 6; §7): an offer is
/// kept as it says, with the seal for this device's key `own` where it
/// seals to it; an empty record at a later revision ends what was kept of
/// that key's offer. In the door's write.
pub(crate) fn read(
    conn: &Connection,
    own: &[u8; 32],
    row: &Channel,
    signer: &[u8; 32],
    rev: u64,
    record: &Anew,
    now: i64,
) -> Result<(), PersonError> {
    match record {
        Anew::Empty => {
            let kept = st(rows::offer_from(conn, &row.channel, signer))?;
            if kept.is_some_and(|kept| kept.rev < rev) {
                st(rows::forget_offer(conn, &row.channel, signer))?;
            }
        }
        Anew::Offer(offer) => {
            let kept = st(rows::offer_from(conn, &row.channel, signer))?;
            if kept.as_ref().is_some_and(|kept| kept.rev > rev) {
                return Ok(());
            }
            let own_seal = offer
                .seals
                .iter()
                .find(|seal| seal.key == *own)
                .map(|seal| seal.sealed.to_vec());
            st(rows::keep_offer(
                conn,
                &OfferRow {
                    channel: row.channel,
                    maker: *signer,
                    rev,
                    made: offer.made,
                    new_channel: offer.new_channel,
                    relays: offer.relays.to_bytes(),
                    sealed_to: offer.seals.iter().map(|seal| seal.key).collect(),
                    own_seal,
                    first_held: now,
                    stayed: false,
                },
            ))?;
        }
    }
    Ok(())
}

// ── Judging an offer ─────────────────────────────────────────────────

/// Why an offer is a fault (§7): never offered as a move, and shown so
/// with its maker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Of a channel the person holds, or held and dropped while the drop
    /// is kept, the old channel itself among them (`held`).
    Held,
    /// Its maker is a key this person's statement lists as removed.
    MakerRemoved,
    /// Its seal for this device does not open, or opens to a seed whose
    /// card does not give the offer's new ID.
    DidNotOpen,
}

impl Fault {
    /// The word of `offers[].fault` (§9).
    pub fn word(self) -> &'static str {
        match self {
            Fault::Held => "held",
            Fault::MakerRemoved => "maker_removed",
            Fault::DidNotOpen => "did_not_open",
        }
    }
}

/// What an offer is to this device (§7), decided in that order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferIs {
    Fault(Fault),
    /// It seals to no device of this person's: it leaves this person out.
    WithoutYou,
    /// It seals to another device of this person's and not to this one:
    /// it is moved to there.
    SealedElsewhere([u8; 32]),
    /// It seals to this device, and the seal opens to the new card.
    ForThisDevice(Card),
}

/// An offer, judged.
#[derive(Debug, Clone)]
pub struct Judged {
    pub offer: OfferRow,
    pub is: OfferIs,
    /// The keys it leaves out: the keys this device shows in the old
    /// channel that it does not seal to, less the person's own devices.
    pub left_out: Vec<[u8; 32]>,
}

impl Judged {
    /// Whether it pauses this device's sending in the old channel
    /// (decision 2026-10-24, rule 26): it seals to this person and leaves
    /// out a key, is no fault, and no person here stayed after it.
    pub fn pauses(&self) -> bool {
        matches!(
            self.is,
            OfferIs::ForThisDevice(_) | OfferIs::SealedElsewhere(_)
        ) && !self.left_out.is_empty()
            && !self.offer.stayed
    }
}

/// The channels the person holds, or held and dropped while the drop is
/// kept, as the list this device last wrote says (§3.4), with those a
/// bound left out where `worked_out` gives them.
fn held_or_dropped(
    conn: &Connection,
    worked_out: Option<(&[u8; 32], i64)>,
) -> Result<Vec<[u8; 32]>, PersonError> {
    let holds = match worked_out {
        Some((own, now)) => lists::holds_worked_out(conn, own, now)?,
        None => lists::holds(conn)?,
    };
    let mut channels: Vec<[u8; 32]> = holds
        .filings
        .iter()
        .map(|(act, _)| act.item.channel)
        .chain(holds.drops.iter().map(|(act, _)| act.item.channel))
        .collect();
    for (act, _) in &holds.left_out {
        match act {
            AnyAct::Filing(filing) => channels.push(filing.item.channel),
            AnyAct::Drop(drop) => channels.push(drop.item.channel),
            _ => {}
        }
    }
    Ok(channels)
}

/// Judge `offer`, read in the channel of `row`, on the device of
/// `identity` (§7). `held_channels` are the channels the person holds or
/// held ([`held_or_dropped`]); `shown` the keys this device shows in the
/// old channel.
fn judge(
    identity: &NodeIdentity,
    held: &Held,
    counting: &Counting,
    row: &Channel,
    offer: &OfferRow,
    held_channels: &[[u8; 32]],
    shown: &[[u8; 32]],
) -> Judged {
    let own = identity.public_key();
    let left_out: Vec<[u8; 32]> = shown
        .iter()
        .filter(|key| !offer.sealed_to.contains(key) && **key != own && !counting.counts(key))
        .copied()
        .collect();
    let is = if offer.new_channel == row.channel || held_channels.contains(&offer.new_channel) {
        OfferIs::Fault(Fault::Held)
    } else if held.statement.statement.removed.contains(&offer.maker) {
        OfferIs::Fault(Fault::MakerRemoved)
    } else if offer.sealed_to.contains(&own) {
        match opened(identity, row, offer) {
            Some(card) => OfferIs::ForThisDevice(card),
            None => OfferIs::Fault(Fault::DidNotOpen),
        }
    } else if let Some(other) = offer
        .sealed_to
        .iter()
        .find(|key| counting.counts(key) && **key != own)
    {
        OfferIs::SealedElsewhere(*other)
    } else {
        OfferIs::WithoutYou
    };
    Judged {
        offer: offer.clone(),
        is,
        left_out,
    }
}

/// The card this device's seal in `offer` opens to: `None` where it does
/// not open, or opens to a seed whose card does not give the new ID.
fn opened(identity: &NodeIdentity, row: &Channel, offer: &OfferRow) -> Option<Card> {
    let sealed: [u8; SEALED_SECRET_BYTES] = offer.own_seal.as_deref()?.try_into().ok()?;
    let relays = Relays::from_bytes(&offer.relays).ok()?;
    let one = Offer {
        made: offer.made,
        new_channel: offer.new_channel,
        relays,
        seals: vec![Seal {
            key: identity.public_key(),
            sealed,
        }],
    };
    one.open(identity, &row.channel).ok()
}

/// Every offer read in the channel of `row` from a key this device shows,
/// judged (§7), oldest first. With `worked_out`, a channel a bound left out
/// counts among those the person holds.
pub fn judged(
    conn: &Connection,
    identity: &NodeIdentity,
    row: &Channel,
    worked_out: Option<i64>,
) -> Result<Vec<Judged>, PersonError> {
    let Some(held) = held(conn)? else {
        return Ok(Vec::new());
    };
    let own = identity.public_key();
    let counting = crate::person::who_counts(conn)?;
    let held_channels = held_or_dropped(conn, worked_out.map(|now| (&own, now)))?;
    let shown = crate::shared::shown_keys(conn, &row.channel)?;
    let offers = st(rows::offers_in(conn, &row.channel))?;
    // An offer read while its maker was shown, and whose maker this
    // person's statement removed since, is judged too: it is a fault, and
    // named so with its maker (§7).
    let removed = &held.statement.statement.removed;
    Ok(offers
        .iter()
        .filter(|offer| shown.contains(&offer.maker) || removed.contains(&offer.maker))
        .map(|offer| {
            judge(
                identity,
                &held,
                &counting,
                row,
                offer,
                &held_channels,
                &shown,
            )
        })
        .collect())
}

/// The offer that pauses this device's sending in the channel of `row`,
/// where one does (decision 2026-10-24, rule 26): the first. None in a
/// channel that is not held.
pub fn pause_of(
    conn: &Connection,
    identity: &NodeIdentity,
    row: &Channel,
) -> Result<Option<Judged>, PersonError> {
    if row.state != State::Held {
        return Ok(None);
    }
    Ok(judged(conn, identity, row, None)?
        .into_iter()
        .find(|judged| judged.offer.maker != identity.public_key() && judged.pauses()))
}

/// Whether the shared channel `channel` is not yet clean (decision
/// 2026-10-24, rules 23 and 25): this device held it when it applied a
/// statement that removed a key, and still holds it, not made anew and
/// moved from, or dropped.
pub fn is_not_clean(conn: &Connection, channel: &[u8; 32]) -> Result<bool, PersonError> {
    if st(rows::not_clean_of(conn, channel))?.is_none() {
        return Ok(false);
    }
    Ok(st(kept::channel(conn, channel))?
        .is_some_and(|row| matches!(row.state, State::Held | State::NotInForce)))
}

/// Whether this device writes its own entries in the channel of `row`:
/// held, clean, and not paused (decision 2026-10-24, rules 23, 25, 26).
/// The offer a device writes when it makes a channel anew is the one entry
/// it writes in one that is not.
pub fn writes_there(
    conn: &Connection,
    identity: &NodeIdentity,
    row: &Channel,
) -> Result<bool, PersonError> {
    Ok(row.state == State::Held
        && !is_not_clean(conn, &row.channel)?
        && pause_of(conn, identity, row)?.is_none())
}

/// What this device sends of its own in the channel of `row`, as the
/// pass pushes it: everything, where it writes there; only its offer,
/// where it made the channel anew and the offer waits to be at each relay;
/// and nothing else.
pub fn sends_only_its_offer(
    conn: &Connection,
    identity: &NodeIdentity,
    row: &Channel,
) -> Result<Option<bool>, PersonError> {
    if writes_there(conn, identity, row)? {
        return Ok(Some(false));
    }
    let made = st(rows::made_of_channel(conn, &row.channel))?;
    Ok(made.is_some_and(|made| made.delivering).then_some(true))
}

/// Whether the channel of `row` was moved from and its offer still waits
/// to be at each relay: the pass pushes it there, and nothing else.
pub fn delivering(conn: &Connection, row: &Channel) -> Result<bool, PersonError> {
    Ok(row.state == State::Moved
        && st(rows::made_of_channel(conn, &row.channel))?.is_some_and(|made| made.delivering))
}

// ── A removal ────────────────────────────────────────────────────────

/// This device applied, at `now`, a statement that removes a key that the
/// one before did not (decision 2026-10-24, rule 23): every shared channel
/// it holds is not yet clean, since every device of the person held every
/// one. In the transaction that applies it.
pub(crate) fn removal_applied(conn: &Connection, now: i64) -> Result<(), PersonError> {
    for row in st(kept::channels(conn))? {
        if matches!(row.state, State::Held | State::NotInForce) {
            st(rows::not_clean(conn, &row.channel, now, false))?;
        }
    }
    Ok(())
}

/// The keys that stay at a removal or at a recovery, with no question
/// (decision 2026-10-24, rule 24): the person's own devices, and then every
/// key of the table of the channel of `row` but the removed keys, in the
/// order of the listing, 64 at most.
fn staying_with_no_question(
    conn: &Connection,
    held: &Held,
    own: &[u8; 32],
    row: &Channel,
) -> Result<Vec<[u8; 32]>, PersonError> {
    let listed = listing_of(conn, held, own, row)?;
    let mut stay = listed.own_devices.clone();
    for key in &listed.asked {
        if stay.len() >= SHARED_MAX_KEYS {
            break;
        }
        stay.push(*key);
    }
    Ok(stay)
}

/// Make each shared channel the person holds anew, as `shared anew` does,
/// with no key asked about (decision 2026-10-24, rule 24): on the device
/// that makes a removal, after the transaction that applies it; and on the
/// machine of a recovery, each once it has read it ([`make_owed`]). Each
/// keeps its relays. Returns the lines said of each, and the names of those
/// that could not be made anew, with why.
pub fn anew_at_removal(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
) -> Result<Vec<String>, PersonError> {
    let mut said = Vec::new();
    for channel in st(rows::not_clean_all(conn))? {
        let Some(row) = st(kept::channel(conn, &channel.channel))? else {
            continue;
        };
        if !matches!(row.state, State::Held | State::NotInForce) || channel.owed {
            continue;
        }
        said.push(anew_one_at_removal(conn, identity, &row, now)?);
    }
    Ok(said)
}

fn anew_one_at_removal(
    conn: &Connection,
    identity: &NodeIdentity,
    row: &Channel,
    now: i64,
) -> Result<String, PersonError> {
    let Some(held) = held(conn)? else {
        return Err(PersonError::FollowsNoPhrase);
    };
    let own = identity.public_key();
    let stay = staying_with_no_question(conn, &held, &own, row)?;
    let card = card_of(row)?;
    let filing = Filing {
        channel: row.channel,
        card: card.clone(),
        name: row.name.clone(),
        came: Came::Made,
    };
    match make_anew_of(
        conn,
        identity,
        &filing,
        row,
        card.relays().clone(),
        &stay,
        true,
        now,
    ) {
        Ok(new) => Ok(format!(
            "\"{}\" is made anew without the device removed: it is channel {} now. The other \
             people in it move with a yes of their own.",
            crate::messages::cleaned(&row.name),
            channel_words(&new)
        )),
        Err(Failed::Refused(refusal)) => Ok(format!(
            "\"{}\" could not be made anew: {}",
            crate::messages::cleaned(&row.name),
            refusal.line
        )),
        Err(Failed::Error(e)) => Err(e),
    }
}

/// On the machine of a recovery, each channel it owes its making anew
/// (decision 2026-10-10 §3.5) is made anew once `fetched` says it has been
/// read since the node started, so that its table of keys is whole.
/// Returns how many were made.
pub fn make_owed(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: &dyn Fn(&Channel) -> bool,
) -> Result<usize, PersonError> {
    let mut made = 0;
    for channel in st(rows::not_clean_all(conn))? {
        if !channel.owed {
            continue;
        }
        let Some(row) = st(kept::channel(conn, &channel.channel))? else {
            continue;
        };
        if row.state != State::Held || !fetched(&row) {
            continue;
        }
        in_one(conn, || anew_one_at_removal(conn, identity, &row, now))?;
        made += 1;
    }
    Ok(made)
}

/// The machine of a recovery that removed a key holds each channel it
/// brought back not yet clean, and owes each its making anew once read
/// (decision 2026-10-10 §3.5; decision 2026-10-24, rule 24).
pub(crate) fn recovered(conn: &Connection, now: i64) -> Result<(), PersonError> {
    for row in st(kept::channels(conn))? {
        if matches!(row.state, State::Held | State::NotInForce) {
            st(rows::not_clean(conn, &row.channel, now, true))?;
        }
    }
    Ok(())
}

// ── Making anew ──────────────────────────────────────────────────────

/// Make the channel of `filing`, whose row is `row`, anew at `relays`, with
/// the new seed sealed to each of `stay` (§7, steps 1 to 3), in one
/// transaction: a new card; the offer written in the old channel over this
/// device's anew record; the new channel filed under the same name in the
/// old one's place, with each subscription of the old one; and this
/// device's empty anew record in the new one. Returns the new channel.
#[allow(clippy::too_many_arguments)]
fn make_anew_of(
    conn: &Connection,
    identity: &NodeIdentity,
    filing: &Filing,
    row: &Channel,
    relays: Relays,
    stay: &[[u8; 32]],
    at_removal: bool,
    now: i64,
) -> Out<[u8; 32]> {
    let held = standing(conn)?;
    let card = Card::make(relays).map_err(|e| PersonError::Held(e.to_string()))?;
    let new_channel = card.channel_id()?;
    let offer = Offer::make(u64::try_from(now).unwrap_or(0), &row.channel, &card, stay)
        .map_err(|e| PersonError::Held(format!("an offer: {e}")))?;
    let value = Anew::Offer(offer)
        .to_value()
        .map_err(|e| PersonError::Held(e.to_string()))?;
    let own = identity.public_key();
    let secret = card_of(row)?.secret()?;
    let name = anew_name(&own)?;
    let slot = slot_id(&derive::slot_key(&secret)?, &name);
    let agents: Vec<String> = crate::shared_messages::in_force(conn)?
        .into_iter()
        .filter(|(channel, _)| *channel == row.channel)
        .map(|(_, agent)| agent)
        .collect();
    let to = Filing {
        channel: new_channel,
        card,
        name: filing.name.clone(),
        came: Came::Moved(row.channel),
    };
    in_one(conn, || -> Result<Out<()>, PersonError> {
        let rev = entries::author_entry(conn, &row.channel, &slot, &own)?
            .map_or(1, |held| held.entry.rev + 1);
        let inside = Inside {
            name: name.clone(),
            value: Value::Other(value.clone()),
            chain: Some(Vec::new()),
        };
        let entry = Entry::seal(&secret, identity, rev, &inside)?.check()?;
        match row.state {
            State::Held => {
                crate::take::take(conn, identity, &entry, now)?;
            }
            _ => {
                entries::store(conn, &entry, now)?;
            }
        }
        st(rows::made(
            conn,
            &MadeRow {
                channel: row.channel,
                new_channel,
                rev,
                made_at: now,
                at_removal,
                delivering: true,
            },
        ))?;
        let what = Do::MoveWith {
            from: row.channel,
            to: to.clone(),
            agents: agents.clone(),
        };
        if let Err(failed) = sharing::act(conn, identity, &held, what, now) {
            return Ok(Err(failed));
        }
        st(rows::clean(conn, &row.channel))?;
        sharing::write_empty_anew_records(conn, identity, now)?;
        Ok(Ok(()))
    })??;
    Ok(new_channel)
}

/// What `shared anew` lists of a channel's table of keys before it asks
/// anything (§7).
#[derive(Debug, Clone, Default)]
pub struct Listing {
    /// The lines that list every key, in order.
    pub lines: Vec<String>,
    /// The person's own devices, which stay and are not asked about.
    pub own_devices: Vec<[u8; 32]>,
    /// The keys asked about, in the order listed.
    pub asked: Vec<[u8; 32]>,
    /// How many rows the table let go, left out and counted.
    pub let_go: u64,
}

/// What `shared anew` says once it has listed every key (§7).
pub const LABEL_FIRST: &str = "A key you label is listed first, before keys you have not \
                               labelled: label the keys you know with cordelia label before you \
                               go on, and then out for the rest leaves out only keys you do not \
                               know.";

/// What `shared anew` says of a person's devices (§7), in one fixed
/// sentence.
pub const A_PERSONS_DEVICES: &str = "A device of a person who stays is left out only once that \
                                     person removes it from their own devices: a person's \
                                     devices share what the person holds.";

/// The listing of the channel of `row` (§7): the keys it shows, in the
/// order of §2.4, then the keys beyond the 64, then the keys refused for
/// room, each with when this device first held or first refused it, when
/// it last wrote there, and whether its entries are stored or refused; the
/// maker's own devices as staying; a key the statement removed as left
/// out; and the rows the table let go, counted.
fn listing_of(
    conn: &Connection,
    held: &Held,
    own: &[u8; 32],
    row: &Channel,
) -> Result<Listing, PersonError> {
    let statement = &held.statement.statement;
    let counting = crate::person::who_counts(conn)?;
    let mut listing = Listing::default();
    // The person's own devices, in the order of the statement and then of
    // their additions.
    let additions = cordelia_storage::person::additions(conn)?;
    for key in statement
        .devices
        .iter()
        .map(|device| device.key)
        .chain(additions.iter().map(|record| record.key))
    {
        if counting.counts(&key) && !listing.own_devices.contains(&key) {
            listing.own_devices.push(key);
        }
    }
    let table = st(kept::keys(conn, row.id))?;
    let shown = crate::shared::shown_keys(conn, &row.channel)?;
    let mut ordered: Vec<&kept::Key> = Vec::new();
    for key in &shown {
        if let Some(row) = table.iter().find(|row| row.key == *key) {
            ordered.push(row);
        }
    }
    let mut beyond: Vec<&kept::Key> = table
        .iter()
        .filter(|key| !shown.contains(&key.key) && key.first_held.is_some())
        .collect();
    beyond.sort_by_key(|key| (key.held_order, key.key));
    ordered.extend(beyond);
    let mut refused: Vec<&kept::Key> = table
        .iter()
        .filter(|key| !shown.contains(&key.key) && key.first_held.is_none())
        .collect();
    refused.sort_by_key(|key| (key.first_refused, key.key));
    ordered.extend(refused);

    let shown_name = crate::messages::cleaned(&row.name);
    listing.lines.push(format!(
        "Every key this device has held or refused in \"{shown_name}\":"
    ));
    for key in &listing.own_devices {
        listing.lines.push(format!(
            "  {}: stays, as your own device",
            sender_form(conn, held, own, key)?
        ));
    }
    for key in ordered {
        if listing.own_devices.contains(&key.key) {
            continue;
        }
        let form = sender_form(conn, held, own, &key.key)?;
        if statement.removed.contains(&key.key) {
            listing
                .lines
                .push(format!("  {form}: left out, a device you removed"));
            continue;
        }
        let first = match (key.first_held, key.first_refused) {
            (Some(first), _) => format!("first held on this device on {}", date_of(first)),
            (None, Some(first)) => format!("first refused on this device on {}", date_of(first)),
            (None, None) => "held nothing on this device".to_string(),
        };
        let last = key
            .last_held
            .or(key.last_refused)
            .map(|at| format!(", last wrote there on {}", date_of(at)))
            .unwrap_or_default();
        let entries = match key.bytes_stored > 0 {
            true => "its entries stored",
            false if key.bytes_refused > 0 => "its entries refused for room",
            false => "nothing of it stored",
        };
        listing
            .lines
            .push(format!("  {form}: {first}{last}, {entries}"));
        listing.asked.push(key.key);
    }
    listing.let_go = row.let_go;
    if row.let_go > 0 {
        listing.lines.push(format!(
            "  no longer known on this device, so left out: {}",
            row.let_go
        ));
    }
    listing.lines.push(LABEL_FIRST.into());
    Ok(listing)
}

/// What `shared anew` makes.
#[derive(Debug, Clone)]
pub struct AnewOf {
    pub filing: Filing,
    pub relays: Vec<[u8; 32]>,
    /// The keys the new seed is sealed to: the maker's own devices, and
    /// each key answered `keep`.
    pub stay: Vec<[u8; 32]>,
    pub left_out: usize,
}

/// `cordelia shared anew <name> [--relay <relay>]... [--words]` (§5.1, §7):
/// the listing of every key, which is said before anything is asked; and,
/// once the person has answered each (`keep`, the keys answered `keep`,
/// each as `cordelia id` writes it), what it makes and its yes.
#[allow(clippy::too_many_arguments)]
pub fn anew_plan(
    conn: &Connection,
    identity: &NodeIdentity,
    own_relays: &[OwnRelay],
    name: &str,
    words: Option<&str>,
    named: &[String],
    keep: Option<&[String]>,
    now: i64,
) -> Out<(Listing, Option<Plan<AnewOf>>)> {
    let held = standing(conn)?;
    let own = identity.public_key();
    // A channel a bound left out is made anew too (§3.4): a person can take
    // someone out of any channel the lists carry.
    let filing = sharing::find(conn, name, words, Some((&own, now)))?;
    let Some(row) = st(kept::channel(conn, &filing.channel))? else {
        return refused(
            "no_such_channel",
            format!(
                "No shared channel of yours is named \"{}\".",
                crate::messages::cleaned(name)
            ),
        );
    };
    let relays: Vec<[u8; 32]> = match named.is_empty() {
        true => filing.card.relays().keys().to_vec(),
        false => sharing::relays_named(own_relays, named)?
            .iter()
            .map(|relay| relay.key)
            .collect(),
    };
    if !sharing::any_own(own_relays, &filing.card) {
        return refused(
            "not_reached",
            format!(
                "\"{}\" is held on this device but not reached from it: write there from a \
                 device of yours that reaches its relays.",
                crate::messages::cleaned(name)
            ),
        );
    }
    let listing = listing_of(conn, &held, &own, &row)?;
    let Some(keep) = keep else {
        return Ok((listing, None));
    };
    let mut stay = listing.own_devices.clone();
    for typed in keep {
        let key = cordelia_crypto::bech32::decode_public_key(typed.trim())
            .ok()
            .filter(|key| listing.asked.contains(key));
        let Some(key) = key else {
            return refused(
                "",
                format!(
                    "{} is not a key that this asks about: nothing was done.",
                    crate::messages::cleaned(typed)
                ),
            );
        };
        if !stay.contains(&key) {
            stay.push(key);
        }
    }
    if stay.len() > SHARED_MAX_KEYS {
        return refused("", STAY_PAST_64.into());
    }
    let left_out = listing.asked.len() - (stay.len() - listing.own_devices.len());
    let at: Vec<String> = relays
        .iter()
        .map(|key| relay_shown(own_relays, key))
        .collect();
    let shown = crate::messages::cleaned(name);
    let asks = format!(
        "{A_PERSONS_DEVICES}\nThose who stay move with cordelia shared move {} on one of their \
         devices. Until each does, what they write in the old channel is read by the keys you \
         leave out.\nThis makes \"{shown}\" anew, at {}: {} keys stay, your own devices among \
         them, and {} are left out.",
        crate::shared_routes::shell_word(name),
        at.join(" and "),
        stay.len(),
        left_out
            + listing.let_go as usize
            + held
                .statement
                .statement
                .removed
                .iter()
                .filter(|key| st(kept::key(conn, row.id, key)).ok().flatten().is_some())
                .count()
    );
    Ok((
        listing,
        Some(Plan {
            asks,
            what: AnewOf {
                filing,
                relays,
                stay,
                left_out,
            },
        }),
    ))
}

/// What `shared anew` says where a `keep` would make more than 64 stay.
pub const STAY_PAST_64: &str = "64 keys stay already, which is the most: type out, or out for \
                                the rest.";

/// Make the channel of `of` anew (§7). Returns the lines said after the
/// yes: the new channel, and those of §5.4.
pub fn make_anew(
    conn: &Connection,
    identity: &NodeIdentity,
    own_relays: &[OwnRelay],
    of: &AnewOf,
    now: i64,
) -> Out<Vec<String>> {
    let held = standing(conn)?;
    let Some(row) = st(kept::channel(conn, &of.filing.channel))? else {
        return refused("no_such_channel", "No such shared channel of yours.".into());
    };
    let relays = Relays::new(&of.relays).map_err(|_| {
        Failed::Refused(sharing::Refusal {
            word: "",
            line: sharing::ONE_OR_TWO_RELAYS.into(),
        })
    })?;
    let new = make_anew_of(
        conn, identity, &of.filing, &row, relays, &of.stay, false, now,
    )?;
    let at: Vec<String> = of
        .relays
        .iter()
        .map(|key| relay_shown(own_relays, key))
        .collect();
    let mut lines = vec![format!(
        "Made \"{}\" anew: it is channel {} now, at {}. The offer to move is in the old channel, \
         sealed to the keys that stay.",
        crate::messages::cleaned(&of.filing.name),
        channel_words(&new),
        at.join(" and ")
    )];
    lines.extend(sharing::who_wrote(
        conn,
        &held,
        &identity.public_key(),
        &new,
        &of.filing.name,
        None,
    )?);
    Ok(lines)
}

// ── Moving ───────────────────────────────────────────────────────────

/// What an offer is, on a line of the list of offers (§7).
fn offer_line(
    conn: &Connection,
    held: &Held,
    own: &[u8; 32],
    judged: &Judged,
) -> Result<String, PersonError> {
    let by = sender_form(conn, held, own, &judged.offer.maker)?;
    let on = date_of(i64::try_from(judged.offer.made).unwrap_or(i64::MAX));
    let new = channel_words(&judged.offer.new_channel);
    Ok(match &judged.is {
        OfferIs::Fault(Fault::Held) => format!(
            "made anew by {by} on {on} into a channel you hold or held: a fault, not a move"
        ),
        OfferIs::Fault(Fault::MakerRemoved) => {
            format!("made anew by {by} on {on}, a device you removed: a fault, not a move")
        }
        OfferIs::Fault(Fault::DidNotOpen) => format!(
            "made anew by {by} on {on} into channel {new}, with a seal for this device that does \
             not open: a fault, not a move"
        ),
        OfferIs::WithoutYou => format!("made anew by {by} on {on} without you"),
        OfferIs::SealedElsewhere(other) => format!(
            "made anew by {by} on {on} into channel {new}, sealed to {} and not to this device",
            sender_form(conn, held, own, other)?
        ),
        OfferIs::ForThisDevice(_) => format!(
            "made anew by {by} on {on} into channel {new}, without {} keys",
            judged.left_out.len()
        ),
    })
}

/// The lines of the offers read in a channel, and of the faults among
/// them, each with its maker (§7): what `shared move` lists above a
/// refusal, and `log` lists.
pub fn offer_lines(
    conn: &Connection,
    identity: &NodeIdentity,
    judged: &[Judged],
) -> Result<Vec<String>, PersonError> {
    let Some(held) = held(conn)? else {
        return Ok(Vec::new());
    };
    let own = identity.public_key();
    judged
        .iter()
        .map(|one| Ok(format!("  {}", offer_line(conn, &held, &own, one)?)))
        .collect()
}

/// What `shared move` moves to.
#[derive(Debug, Clone)]
pub struct MoveTo {
    pub from: [u8; 32],
    pub to: Filing,
    pub agents: Vec<String>,
}

/// `cordelia shared move <name> [--to <channel words>] [--words]` (§5.1,
/// §5.5, §7): what it moves to, and its yes, or why it is refused.
pub fn move_plan(
    conn: &Connection,
    identity: &NodeIdentity,
    own_relays: &[OwnRelay],
    name: &str,
    words: Option<&str>,
    to_words: Option<&str>,
    now: i64,
) -> Out<Plan<MoveTo>> {
    let held = standing(conn)?;
    let own = identity.public_key();
    let filing = sharing::find(conn, name, words, Some((&own, now)))?;
    let shown_name = crate::messages::cleaned(name);
    let Some(row) = st(kept::channel(conn, &filing.channel))? else {
        return refused(
            "no_such_channel",
            format!("No shared channel of yours is named \"{shown_name}\"."),
        );
    };
    let all = judged(conn, identity, &row, Some(now))?;
    let listed = offer_lines(conn, identity, &all)?;
    let above = |line: String| {
        let mut lines = listed.clone();
        lines.push(line);
        lines.join("\n")
    };
    let mut open: Vec<(&Judged, &Card)> = all
        .iter()
        .filter_map(|one| match &one.is {
            OfferIs::ForThisDevice(card) => Some((one, card)),
            _ => None,
        })
        .collect();
    if let Some(to_words) = to_words {
        let to_words = to_words.split_whitespace().collect::<Vec<_>>().join(" ");
        open.retain(|(one, _)| channel_words(&one.offer.new_channel) == to_words);
    }
    let (judged_one, card) = match open.len() {
        1 => open[0],
        0 => {
            let elsewhere = all.iter().find_map(|one| match one.is {
                OfferIs::SealedElsewhere(other) => Some(other),
                _ => None,
            });
            return match elsewhere {
                Some(other) if to_words.is_none() => refused(
                    "sealed_elsewhere",
                    above(format!(
                        "The new channel is sealed to {} and not to this device: run cordelia \
                         shared move {} there.",
                        sender_form(conn, &held, &own, &other)?,
                        crate::shared_routes::shell_word(name)
                    )),
                ),
                _ => refused(
                    "no_offer",
                    above(format!(
                        "\"{shown_name}\" has not been made anew by a key this device shows."
                    )),
                ),
            };
        }
        _ => {
            return refused(
                "two_offers",
                above(format!(
                    "\"{shown_name}\" was made anew twice: give the channel's words with --to \
                     <four words>."
                )),
            );
        }
    };
    let offer = &judged_one.offer;
    // A move to an offer whose relays are not all, by key, the device's own
    // is refused (§8.2).
    if let Some(other) = card
        .relays()
        .keys()
        .iter()
        .find(|key| !own_relays.iter().any(|relay| relay.key == **key))
    {
        return refused(
            "not_own_relay",
            above(format!(
                "{} is not one of your relays, and a shared channel lives only at your own \
                 relays: nothing was done.",
                relay_shown(own_relays, other)
            )),
        );
    }
    let counting = crate::person::who_counts(conn)?;
    let by = sender_form(conn, &held, &own, &offer.maker)?;
    let on = date_of(i64::try_from(offer.made).unwrap_or(i64::MAX));
    let at: Vec<String> = card
        .relays()
        .keys()
        .iter()
        .map(|key| relay_shown(own_relays, key))
        .collect();
    let mut stays = Vec::new();
    for key in &offer.sealed_to {
        if *key != own && !counting.counts(key) {
            stays.push(format!("  {}", sender_form(conn, &held, &own, key)?));
        }
    }
    let mut follow = Vec::new();
    for key in listing_of(conn, &held, &own, &row)?.own_devices {
        if key != own {
            follow.push(sender_form(conn, &held, &own, &key)?);
        }
    }
    let mut left = Vec::new();
    for key in &judged_one.left_out {
        left.push(sender_form(conn, &held, &own, key)?);
    }
    let agents: Vec<String> = crate::shared_messages::in_force(conn)?
        .into_iter()
        .filter(|(channel, _)| *channel == row.channel)
        .map(|(_, agent)| agent)
        .collect();
    let faults: Vec<&Judged> = all
        .iter()
        .filter(|one| matches!(one.is, OfferIs::Fault(_)))
        .collect();
    let mut lines = vec![format!(
        "\"{shown_name}\" was made anew by {by} on {on}, at {}: channel {}.",
        at.join(" and "),
        channel_words(&offer.new_channel)
    )];
    lines.push("These stay, each if its seal opens for it, which this device cannot check:".into());
    match stays.is_empty() {
        true => lines.push("  none but your own devices".into()),
        false => lines.extend(stays),
    }
    if !follow.is_empty() {
        lines.push(format!(
            "Your own devices follow your move: {}",
            follow.join(", ")
        ));
    }
    lines.push(match left.is_empty() {
        true => "None is left out.".to_string(),
        false => format!("These are left out: {}", left.join(", ")),
    });
    lines.push(match agents.is_empty() {
        true => "No agent of yours subscribes to it.".to_string(),
        false => format!(
            "These subscriptions of yours move with it: {}.",
            agents
                .iter()
                .map(|agent| crate::messages::cleaned(agent))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    });
    let why: Vec<&str> = faults
        .iter()
        .map(|one| match one.is {
            OfferIs::Fault(fault) => fault.word(),
            _ => "",
        })
        .collect();
    lines.push(match why.is_empty() {
        true => format!(
            "Offers from keys this device shows: {}, of them faults: 0.",
            all.len()
        ),
        false => format!(
            "Offers from keys this device shows: {}, of them faults: {} ({}).",
            all.len(),
            faults.len(),
            why.join(", ")
        ),
    });
    Ok(Plan {
        asks: lines.join("\n"),
        what: MoveTo {
            from: row.channel,
            to: Filing {
                channel: offer.new_channel,
                card: card.clone(),
                name: filing.name.clone(),
                came: Came::Moved(row.channel),
            },
            agents,
        },
    })
}

/// Move to the channel of `to` (§7): it is filed under the same name in
/// the old channel's place, with a drop of the old one, kept apart, and
/// each subscription of the old one moved; this device writes its empty
/// anew record there. Returns the lines said after the yes.
pub fn make_move(
    conn: &Connection,
    identity: &NodeIdentity,
    to: &MoveTo,
    now: i64,
) -> Out<Vec<String>> {
    let held = standing(conn)?;
    let what = Do::MoveWith {
        from: to.from,
        to: to.to.clone(),
        agents: to.agents.clone(),
    };
    in_one(conn, || -> Result<Out<()>, PersonError> {
        if let Err(failed) = sharing::act(conn, identity, &held, what, now) {
            return Ok(Err(failed));
        }
        sharing::write_empty_anew_records(conn, identity, now)?;
        Ok(Ok(()))
    })??;
    let mut lines = vec![format!(
        "Moved \"{}\" to channel {}: your devices write there from now on, and nothing more in \
         the old channel.",
        crate::messages::cleaned(&to.to.name),
        channel_words(&to.to.channel)
    )];
    lines.extend(sharing::who_wrote(
        conn,
        &held,
        &identity.public_key(),
        &to.to.channel,
        &to.to.name,
        None,
    )?);
    Ok(lines)
}

/// The keys that the offer which made the channel `channel` sealed to and
/// that have not written there yet, but this device: "not moved yet" (§7).
pub fn not_moved_yet(
    conn: &Connection,
    own: &[u8; 32],
    channel: &[u8; 32],
) -> Result<Vec<[u8; 32]>, PersonError> {
    let Some(row) = st(kept::channel(conn, channel))? else {
        return Ok(Vec::new());
    };
    let Came::Moved(from) = (match row.came {
        cordelia_storage::shared::Came::Moved(from) => Came::Moved(from),
        _ => return Ok(Vec::new()),
    }) else {
        return Ok(Vec::new());
    };
    let wrote: Vec<[u8; 32]> = st(kept::keys(conn, row.id))?
        .into_iter()
        .filter(|key| key.first_held.is_some())
        .map(|key| key.key)
        .collect();
    let mut keys = Vec::new();
    for offer in st(rows::offers_into(conn, channel))? {
        if offer.channel != from {
            continue;
        }
        for key in offer.sealed_to {
            if key != *own && !wrote.contains(&key) && !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    Ok(keys)
}

// ── What a command that writes says (§5.4) ───────────────────────────

/// What §5.4 adds after the lines of who wrote in the channel `channel`,
/// filed as `name`: where an offer that seals to this person and leaves out
/// a key was read there and the person has not moved, that it was made anew
/// and by whom; and, in a channel moved to, each key that the offer sealed
/// to and that has not written there yet. No seal is opened here.
pub(crate) fn after_who_wrote(
    conn: &Connection,
    held: &Held,
    own: &[u8; 32],
    channel: &[u8; 32],
    name: &str,
) -> Result<Vec<String>, PersonError> {
    let mut lines = Vec::new();
    let Some(row) = st(kept::channel(conn, channel))? else {
        return Ok(lines);
    };
    if row.state == State::Held {
        let counting = crate::person::who_counts(conn)?;
        let shown = crate::shared::shown_keys(conn, channel)?;
        let held_channels = held_or_dropped(conn, None)?;
        for offer in st(rows::offers_in(conn, channel))? {
            if offer.maker == *own || !shown.contains(&offer.maker) {
                continue;
            }
            let for_this_person = offer
                .sealed_to
                .iter()
                .any(|key| key == own || counting.counts(key));
            let fault = offer.new_channel == *channel
                || held_channels.contains(&offer.new_channel)
                || held.statement.statement.removed.contains(&offer.maker);
            let left_out = shown
                .iter()
                .filter(|key| {
                    !offer.sealed_to.contains(key) && *key != own && !counting.counts(key)
                })
                .count();
            if !for_this_person || fault || left_out == 0 {
                continue;
            }
            lines.push(format!(
                "This channel was made anew by {} on {}, without {left_out} keys. You have not \
                 moved: what you write here is read by those keys too. Move with: cordelia shared \
                 move {}",
                sender_form(conn, held, own, &offer.maker)?,
                date_of(i64::try_from(offer.made).unwrap_or(i64::MAX)),
                crate::shared_routes::shell_word(name)
            ));
        }
    }
    for key in not_moved_yet(conn, own, channel)? {
        lines.push(format!(
            "  not moved yet: {}",
            sender_form(conn, held, own, &key)?
        ));
    }
    Ok(lines)
}

/// What `log` says at a terminal of making anew in the channel of `row`
/// (§2.4, §5.1, §7; decision 2026-10-24, rule 25), a line each: whether
/// it is not yet clean; each offer read there from a key this device
/// shows, and each fault, with its maker; how many anew records of keys it
/// does not show wait unread; in a channel moved to, each key the offer
/// sealed to that has not written there yet; and each key shown before
/// that is no longer shown, since 64 keys come before it.
pub fn log_lines(
    conn: &Connection,
    identity: &NodeIdentity,
    row: &Channel,
    now: i64,
) -> Result<Vec<String>, PersonError> {
    let Some(held) = held(conn)? else {
        return Ok(Vec::new());
    };
    let own = identity.public_key();
    let mut lines = Vec::new();
    if is_not_clean(conn, &row.channel)? {
        lines.push(format!("  {}", not_clean_line(&row.name)));
    }
    let offers = judged(conn, identity, row, Some(now))?;
    lines.extend(offer_lines(conn, identity, &offers)?);
    let shown = crate::shared::shown_keys(conn, &row.channel)?;
    let mut unread_records = 0;
    for (key, _) in st(kept::waiting_to_open(conn, row.id))? {
        if shown.contains(&key) {
            continue;
        }
        let slot = slot_id(
            &derive::slot_key(&card_of(row)?.secret()?)?,
            &anew_name(&key)?,
        );
        if st(kept::to_open(conn, row.id, &key))?.contains(&slot) {
            unread_records += 1;
        }
    }
    if unread_records > 0 {
        lines.push(format!(
            "  anew records of keys this device does not show: {unread_records}"
        ));
    }
    for key in not_moved_yet(conn, &own, &row.channel)? {
        lines.push(format!(
            "  not moved yet: {}",
            sender_form(conn, &held, &own, &key)?
        ));
    }
    for signer in st(kept::index_signers(conn, row.id))? {
        if !shown.contains(&signer)
            && signer != own
            && !held.statement.statement.removed.contains(&signer)
        {
            lines.push(format!(
                "  {} is no longer shown here: 64 keys come before it",
                sender_form(conn, &held, &own, &signer)?
            ));
        }
    }
    Ok(lines)
}

// ── Staying ──────────────────────────────────────────────────────────

/// `cordelia shared stay <name> [--words]` (§5.1; decision 2026-10-24, rule
/// 26): what it would do, and its yes; or, where nothing pauses the
/// channel, the line said with nothing done (`Ok(Err(line))`).
pub fn stay_plan(
    conn: &Connection,
    identity: &NodeIdentity,
    name: &str,
    words: Option<&str>,
) -> Out<Result<Plan<[u8; 32]>, String>> {
    let held = standing(conn)?;
    let own = identity.public_key();
    let filing = sharing::find(conn, name, words, None)?;
    let shown_name = crate::messages::cleaned(name);
    let row = st(kept::channel(conn, &filing.channel))?;
    let pause = match &row {
        Some(row) => pause_of(conn, identity, row)?,
        None => None,
    };
    let Some(pause) = pause else {
        return Ok(Err(format!(
            "Nothing pauses \"{shown_name}\": your devices write there already."
        )));
    };
    let by = sender_form(conn, &held, &own, &pause.offer.maker)?;
    let on = date_of(i64::try_from(pause.offer.made).unwrap_or(i64::MAX));
    let mut left = Vec::new();
    for key in &pause.left_out {
        left.push(sender_form(conn, &held, &own, key)?);
    }
    let asks = format!(
        "\"{shown_name}\" was made anew by {by} on {on}, without {} keys. Your devices send \
         nothing more in the old channel until you move (cordelia shared move {}) or stay. If \
         you stay, what your agents write there is read by the keys left out: {}",
        pause.left_out.len(),
        crate::shared_routes::shell_word(name),
        left.join(", ")
    );
    Ok(Ok(Plan {
        asks,
        what: filing.channel,
    }))
}

/// Stay in the channel `channel` (rule 26): every offer read there so far
/// is stayed after, on this device. Returns the line said after the yes.
pub fn make_stay(conn: &Connection, channel: &[u8; 32], name: &str) -> Out<String> {
    standing(conn)?;
    st(rows::stay(conn, channel))?;
    Ok(format!(
        "Your devices write in \"{}\" again, where the keys left out read it.",
        crate::messages::cleaned(name)
    ))
}

// ── Delivering the old channel's offer ───────────────────────────────

/// Each channel this device made anew whose offer is now at each relay of
/// the old card, or has waited 30 days: its entries are taken out of the
/// store, as of any channel moved from (§6.3). Run where a relay answered
/// a push, and where the table of shared channels is kept.
pub(crate) fn deliveries(conn: &Connection, own: &[u8; 32], now: i64) -> Result<(), PersonError> {
    for made in st(rows::made_all(conn))? {
        if !made.delivering {
            continue;
        }
        let Some(row) = st(kept::channel(conn, &made.channel))? else {
            st(rows::delivered(conn, &made.channel))?;
            continue;
        };
        if row.state == State::Held || row.state == State::NotInForce {
            continue;
        }
        let card = card_of(&row)?;
        let slot = slot_id(&derive::slot_key(&card.secret()?)?, &anew_name(own)?);
        let mut at_each = true;
        for relay in card.relays().keys() {
            let answered = st(pass_rows::answer(conn, row.id, relay, &slot))?;
            if !answered.is_some_and(|(rev, _)| rev >= made.rev) {
                at_each = false;
            }
        }
        if at_each || now - made.made_at >= DELIVERING_SECS {
            st(rows::delivered(conn, &made.channel))?;
            if row.state == State::Moved && st(pass_rows::channel_out(conn, row.id))?.is_none() {
                st(pass_rows::begin_channel(conn, row.id, ChannelOut::Moved))?;
            }
        }
    }
    Ok(())
}

// ── What a removal, `devices` and a recovery name ────────────────────

/// An act in force, named with what undoes it (§3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Named {
    /// Its maker.
    pub maker: [u8; 32],
    /// `filing`, `drop`, `subscription`, `unsubscription`, `label` or
    /// `label_removed`.
    pub act: &'static str,
    /// What it is, in words.
    pub item: String,
    /// The command that undoes it.
    pub undo: String,
    /// What a notice of it is named by.
    pub id: [u8; 32],
}

impl Named {
    /// The line said of it, after its device.
    pub fn line(&self) -> String {
        format!("{}: undo it with {}", self.item, self.undo)
    }
}

/// The name of a channel by its ID, as the person files it, or its words.
fn channel_named(filings: &[Filing], channel: &[u8; 32]) -> String {
    match filings.iter().find(|filing| filing.channel == *channel) {
        Some(filing) => format!("\"{}\"", crate::messages::cleaned(&filing.name)),
        None => format!("channel {}", channel_words(channel)),
    }
}

fn name_word(filings: &[Filing], channel: &[u8; 32]) -> String {
    match filings.iter().find(|filing| filing.channel == *channel) {
        Some(filing) => crate::shared_routes::shell_word(&filing.name),
        None => "<name>".into(),
    }
}

/// What a notice of an act is named by.
fn notice_of(act: &AnyAct) -> [u8; 32] {
    let mut named = b"cordelia shared act named".to_vec();
    named.extend_from_slice(&act.signature());
    let mut id = cordelia_crypto::sha256(&named);
    id[..4].copy_from_slice(SHARED_NOTICE);
    id
}

/// What a notice of a channel not yet clean is named by.
pub(crate) fn notice_of_channel(channel: &[u8; 32]) -> [u8; 32] {
    let mut named = b"cordelia shared channel not clean".to_vec();
    named.extend_from_slice(channel);
    let mut id = cordelia_crypto::sha256(&named);
    id[..4].copy_from_slice(SHARED_NOTICE);
    id
}

/// What `act` is, in words, and the command that undoes it (§3.5, the
/// table of what undoes each act in force): its kind, the item, the undo.
/// `filings` name the channels.
fn described(
    act: &AnyAct,
    filings: &[Filing],
) -> Result<(&'static str, String, String), PersonError> {
    Ok(match act {
        AnyAct::Filing(act) => {
            let item = &act.item;
            let word = crate::shared_routes::shell_word(&item.name);
            (
                "filing",
                format!(
                    "\"{}\" filed (channel {})",
                    crate::messages::cleaned(&item.name),
                    channel_words(&item.channel)
                ),
                format!("cordelia shared drop {word}, or cordelia shared rename {word} <new name>"),
            )
        }
        AnyAct::Drop(act) => (
            "drop",
            format!("channel {} dropped", channel_words(&act.item.channel)),
            "nothing on this side: a member shares it with you again".into(),
        ),
        AnyAct::Subscription(act) => {
            let item = &act.item;
            let channel = channel_named(filings, &item.channel);
            let word = name_word(filings, &item.channel);
            let agent = crate::messages::cleaned(&item.agent);
            match item.subscribed {
                true => (
                    "subscription",
                    format!("{agent} subscribed to {channel}"),
                    format!("cordelia unsubscribe {word} --agent {agent}"),
                ),
                false => (
                    "unsubscription",
                    format!("{agent} unsubscribed from {channel}"),
                    format!("cordelia subscribe {word}, in a folder of that agent"),
                ),
            }
        }
        AnyAct::Label(act) => {
            let key = encode_public_key(&act.item.key)?;
            let six = six_words(&act.item.key);
            match &act.item.label {
                Some(label) => (
                    "label",
                    format!("({six}) labelled {}", sharing::quoted(label)),
                    format!("cordelia label {key} --none, or cordelia label {key} <label>"),
                ),
                None => (
                    "label_removed",
                    format!("the label of ({six}) removed"),
                    format!("cordelia label {key} <label>"),
                ),
            }
        }
    })
}

/// Each act in force or undo in the lists this device writes, whose maker
/// is one of `of` (§3.5), each named with what undoes it: what a removal
/// names before its yes, of the device it removes, and `cordelia devices`,
/// of the removed keys.
pub fn acts_named(
    conn: &Connection,
    of: impl Fn(&[u8; 32], Maker) -> bool,
) -> Result<Vec<Named>, PersonError> {
    let holds = lists::holds(conn)?;
    let filings: Vec<Filing> = holds
        .filings
        .iter()
        .map(|(act, _)| act.item.clone())
        .collect();
    let mut all: Vec<(AnyAct, Maker)> = Vec::new();
    all.extend(
        holds
            .filings
            .iter()
            .map(|(a, m)| (AnyAct::Filing(a.clone()), *m)),
    );
    all.extend(
        holds
            .drops
            .iter()
            .map(|(a, m)| (AnyAct::Drop(a.clone()), *m)),
    );
    all.extend(
        holds
            .subscriptions
            .iter()
            .map(|(a, m)| (AnyAct::Subscription(a.clone()), *m)),
    );
    all.extend(
        holds
            .labels
            .iter()
            .map(|(a, m)| (AnyAct::Label(a.clone()), *m)),
    );
    let mut named = Vec::new();
    for (act, maker) in all {
        if !of(&act.maker(), maker) {
            continue;
        }
        // A subscription of a channel that is filed no more (moved from,
        // or dropped) shows nothing, and has no name to be undone by: it
        // is not named.
        if let AnyAct::Subscription(subscription) = &act
            && !filings
                .iter()
                .any(|filing| filing.channel == subscription.item.channel)
        {
            continue;
        }
        let (kind, item, undo) = described(&act, &filings)?;
        named.push(Named {
            maker: act.maker(),
            act: kind,
            item,
            undo,
            id: notice_of(&act),
        });
    }
    Ok(named)
}

/// What a recovery says of the person's shared channels (decision
/// 2026-10-10 §3.5), before its yes and at the end of its look: of the
/// lists `lists` of the devices it shows, what it takes by the rules of
/// §3.4, with the devices of `gone` (answered lost or in someone else's
/// hands) as removed keys and those of `have` in no list: each channel,
/// subscription and label it brings back, with the device that made it;
/// each act of a device of `gone`, with what undoes it; and each act of a
/// device of `have`, as passed over until that device is added again.
pub fn recovery_lines(
    lists: &[([u8; 32], cordelia_crypto::acts::SharedList)],
    gone: &[([u8; 32], String)],
    have: &[([u8; 32], String)],
) -> Result<Vec<String>, PersonError> {
    let named = |key: &[u8; 32]| -> String {
        let label = gone
            .iter()
            .chain(have)
            .find(|(of, _)| of == key)
            .map(|(_, label)| label.as_str())
            .unwrap_or("");
        match label.is_empty() {
            true => format!("({})", cordelia_crypto::fingerprint::shown(key)),
            false => format!(
                "\"{}\" ({})",
                crate::messages::cleaned(label),
                cordelia_crypto::fingerprint::shown(key)
            ),
        }
    };
    let (written, _) = lists::recovered(lists, |key| {
        gone.iter()
            .any(|(of, _)| of == key)
            .then_some(Maker::Removed)
    });
    let acts = lists::acts_of(&written);
    let filings: Vec<Filing> = acts
        .iter()
        .filter_map(|act| match act {
            AnyAct::Filing(act) => Some(act.item.clone()),
            _ => None,
        })
        .collect();
    let mut lines = Vec::new();
    let mut brought = Vec::new();
    let mut of_gone = Vec::new();
    for act in &acts {
        let (kind, item, undo) = described(act, &filings)?;
        if matches!(kind, "filing" | "subscription" | "label") {
            brought.push(format!("  {item}, by {}", named(&act.maker())));
        }
        of_gone.push(format!(
            "  {item}, by {}: undo it with {undo}",
            named(&act.maker())
        ));
    }
    if !brought.is_empty() {
        lines.push("\nOf your shared channels, this recovery brings back:".to_string());
        lines.extend(brought);
    }
    // Every act it takes is of a device it removes: the new machine is in
    // no list it reads.
    if !of_gone.is_empty() {
        lines.push(
            "\nWhat the devices you said are gone, or may be in someone else's hands, did in your \
             shared channels, still in force, each with what undoes it:"
                .to_string(),
        );
        lines.extend(of_gone);
    }
    let mut passed = Vec::new();
    for (key, list) in lists {
        if !have.iter().any(|(of, _)| of == key) {
            continue;
        }
        for act in lists::acts_of(list) {
            if act.maker() != *key {
                continue;
            }
            let (_, item, _) = described(&act, &filings)?;
            passed.push(format!("  {item}, by {}", named(key)));
        }
    }
    if !passed.is_empty() {
        lines.push(
            "\nWhat the devices you still have did in your shared channels is passed over until \
             each is added again, and then it is in force as theirs:"
                .to_string(),
        );
        lines.extend(passed);
    }
    if !filings.is_empty() && !gone.is_empty() {
        lines.push(
            "Each shared channel it brings back is made anew without the devices removed, once \
             this machine has read it: the other people in each move with a yes of their own."
                .to_string(),
        );
    }
    Ok(lines)
}

/// The acts of the removed keys that are in force (§3.5): what `cordelia
/// devices` names, until each is undone or a person clears it.
pub fn acts_of_removed(conn: &Connection) -> Result<Vec<Named>, PersonError> {
    acts_named(conn, |_, maker| maker == Maker::Removed)
}

/// A notice: what it is named by, its kind, and what it says.
pub(crate) type Told = ([u8; 32], &'static str, String);

/// What a notice of `cordelia devices` says of each channel not yet clean,
/// and of each act of a removed key in force, each with what it is named
/// by (§3.5): `(id, kind, says)`.
pub(crate) fn notices(conn: &Connection) -> Result<Vec<Told>, PersonError> {
    let mut told = Vec::new();
    for channel in st(rows::not_clean_all(conn))? {
        if !is_not_clean(conn, &channel.channel)? {
            continue;
        }
        let Some(row) = st(kept::channel(conn, &channel.channel))? else {
            continue;
        };
        told.push((
            notice_of_channel(&channel.channel),
            "not_clean",
            not_clean_line(&row.name),
        ));
    }
    let removed = crate::look::removed_labels(conn)?;
    for named in acts_of_removed(conn)? {
        let device = match removed.iter().find(|(key, _)| *key == named.maker) {
            Some((_, label)) if !label.is_empty() => format!(
                "\"{}\" ({})",
                crate::messages::cleaned(label),
                cordelia_crypto::fingerprint::shown(&named.maker)
            ),
            _ => format!("({})", cordelia_crypto::fingerprint::shown(&named.maker)),
        };
        told.push((
            named.id,
            "removed_act",
            format!(
                "the removed device {device} made this, still in force: {}",
                named.line()
            ),
        ));
    }
    Ok(told)
}

/// What this device made anew at the removal it applied at `applied_at`,
/// or after it, a line each (decision 2026-10-10 §3.5).
pub(crate) fn made_at_the_last_removal(
    conn: &Connection,
    applied_at: Option<i64>,
) -> Result<Vec<String>, PersonError> {
    let Some(applied_at) = applied_at else {
        return Ok(Vec::new());
    };
    let mut lines = Vec::new();
    for made in st(rows::made_all(conn))? {
        if !made.at_removal || made.made_at < applied_at {
            continue;
        }
        let name = st(kept::channel(conn, &made.new_channel))?
            .map(|row| row.name)
            .unwrap_or_default();
        lines.push(format!(
            "\"{}\" is made anew without the device removed: it is channel {} now. The other \
             people in it move with a yes of their own.",
            crate::messages::cleaned(&name),
            channel_words(&made.new_channel)
        ));
    }
    Ok(lines)
}

/// The line of a channel not yet clean (decision 2026-10-24, rule 25).
pub fn not_clean_line(name: &str) -> String {
    let word = crate::shared_routes::shell_word(name);
    format!(
        "\"{}\" was held by a device that was removed: make it anew with cordelia shared anew \
         {word}",
        crate::messages::cleaned(name)
    )
}

/// What the device of `identity` names of its shared channels at a removal,
/// before its yes (§3.5): each shared channel the person holds, by name; and
/// each act in force of any device of the person's that counts, each with
/// its maker and what undoes it, for the command to name those of the
/// device it removes.
pub fn at_a_removal(conn: &Connection) -> Result<(Vec<String>, Vec<Named>), PersonError> {
    let names: Vec<String> = sharing::filed(conn)?
        .into_iter()
        .map(|filing| filing.name)
        .collect();
    let acts = acts_named(conn, |_, maker| maker == Maker::Counts)?;
    Ok((names, acts))
}

#[cfg(test)]
mod tests;
