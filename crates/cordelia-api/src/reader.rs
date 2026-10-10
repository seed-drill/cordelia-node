//! The reader of messages between the person's own agents (decision
//! 2026-10-09 §2.3, §2.5, §6, §7.1).
//!
//! [`taken`] is what the door ([`crate::take::take`]) does with an entry
//! of the messages channel that the store kept, in the same write: it is
//! the reader's check, and it is what makes an entry a message. A program
//! that holds a device's key can write anything in any slot; the reader
//! keeps its limits all the same (§11):
//!
//! - **The slot first, before anything is opened.** An entry raises its
//!   signer's H only where its slot is the slot of `msg/<its signer>/<n>`
//!   with n its number modulo 64, and its number is one a message can
//!   have (§2.5). The slot's ID is worked out from that name, as the
//!   store's slots are, and compared. The list in `read/<its signer>`
//!   raises nothing, and an entry in any other slot is no message.
//! - **Only a live number is opened.** An entry at a number that is not
//!   live is never opened into the index, and is counted as overwritten
//!   where it is a message (its revision is even): a clearing there says
//!   only that its number is gone.
//! - **Then the value** (`message::take`): a message is written into the
//!   index with its opened fields, a clearing drops the index row of the
//!   message held at its number and counts that number as gone, and
//!   anything else is counted as no message.
//!
//! The reader refuses nothing that the store took: the entry stays in the
//! store whatever it is, and nothing here changes what the door answers.
//!
//! What is shown, and when, is worked out from the index by the store's
//! plain functions over the node's clock (`give_places` and `shown` in
//! [`cordelia_storage::messages`]). [`hourly`] is
//! the first and the last part of the hourly task of §7.1.

use rusqlite::Connection;

use cordelia_core::CordeliaError;
use cordelia_crypto::addition::SignedAddition;
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::message::{self, NotAMessage, Taken as InTheRing};
use cordelia_crypto::slots::slot_id;
use cordelia_crypto::statement::Statement;
use cordelia_storage::StorageError;
use cordelia_storage::messages::{self as held, Indexed, Opened};
use cordelia_storage::person as held_rows;

use crate::person::{PersonError, in_one};

/// What the reader made of an entry of the messages channel that the
/// store kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    /// A message at a live number, and what became of it in the index.
    Message(Indexed),
    /// The clearing of a number: whether the index held a message there,
    /// which went.
    Clearing { dropped: bool },
    /// The signer's list of what its agents read.
    List,
    /// An entry at a number that is not live: never opened, and counted
    /// as overwritten where it is a message.
    Overwritten,
    /// An entry in its place that does not open: counted as no message.
    DidNotOpen,
    /// No message: counted, and never shown.
    NotAMessage(NotAMessage),
}

/// Read `entry`, an entry of the messages channel of the person secret
/// `secret`, under `statement`, which the store has just kept (decision
/// 2026-10-09 §2.3, §2.5, §7.1). The door has checked that its signer
/// counts and that the device stands applied, and calls this in the
/// write that stored it: what the reader keeps of it is kept with it, or
/// not at all.
///
/// The generation is the channel's row, made the first time the device
/// holds it ([`held::generation`]).
///
/// **An entry of the device's own, `own`,** that the store kept is one a
/// relay handed back from the device's later life, over what its store
/// held: a message of its own there that not every relay had taken waits
/// to be sent again under the next number (decision 2026-10-09 §2.3, case
/// 2; [`crate::sender::taken_over`]).
pub fn taken(
    conn: &Connection,
    own: &[u8; 32],
    secret: &[u8; 32],
    statement: &Statement,
    entry: &CheckedEntry,
    now: i64,
) -> Result<Read, PersonError> {
    let messages = derive::messages_secret(secret)?;
    let slot_key = derive::slot_key(&messages)?;
    let signer = entry.author;
    let generation = kept(held::generation(
        conn,
        &entry.channel,
        statement.number,
        now,
    ))?;

    crate::sender::taken_over(conn, own, &slot_key, generation, entry)?;

    let is_list = entry.slot == slot_id(&slot_key, &message::read_name(&signer)?);
    let number = message::number_of(entry.rev);
    let in_its_slot = !is_list
        && message::message_rev(number).is_some()
        && entry.slot == slot_id(&slot_key, &message::message_name(&signer, number)?);
    let no_message = |why: NotAMessage| -> Result<Read, PersonError> {
        kept(held::not_a_message(conn, &signer, generation))?;
        Ok(Read::NotAMessage(why))
    };
    if !is_list && !in_its_slot {
        return no_message(NotAMessage::NotInRing);
    }
    let clearing = entry.rev % 2 == 1;
    if in_its_slot
        && !kept(held::hold_number(
            conn, &signer, generation, number, clearing,
        ))?
    {
        return Ok(Read::Overwritten);
    }

    let Ok(inside) = entry.open(&messages) else {
        kept(held::not_a_message(conn, &signer, generation))?;
        return Ok(Read::DidNotOpen);
    };
    let read = message::take(
        &inside.name,
        &signer,
        entry.rev,
        &inside.value,
        crate::names::is_a_name,
    );
    match read {
        Ok(InTheRing::Message { number, message }) => {
            let Value::Other(value) = &inside.value else {
                return no_message(NotAMessage::Kind);
            };
            let id = message::message_id(&signer, value);
            let label = label_of(conn, statement, &signer)?;
            let opened = Opened {
                id: &id,
                signer: &signer,
                label: &label,
                generation,
                number,
                message: &message,
                first_held: now,
                placed_at: None,
            };
            Ok(Read::Message(kept(held::index(conn, &opened))?))
        }
        Ok(InTheRing::Clearing { number }) => Ok(Read::Clearing {
            dropped: kept(held::clear(conn, &signer, generation, number, now))?,
        }),
        // What a list's marks say is kept by whoever keeps the lists of
        // what each device's agents read (decision 2026-10-09 §7.2): the
        // reader checks only that it is one.
        Ok(InTheRing::List(_)) => Ok(Read::List),
        Err(why) => no_message(why),
    }
}

/// The label that this device knows `key` by (decision 2026-10-09 §3):
/// the statement's, or the one in the record of its addition, or none.
pub(crate) fn label_of(
    conn: &Connection,
    statement: &Statement,
    key: &[u8; 32],
) -> Result<String, PersonError> {
    if let Some(device) = statement.devices.iter().find(|device| device.key == *key) {
        return Ok(device.label.clone());
    }
    for record in held_rows::additions(conn)? {
        if record.key == *key {
            return Ok(SignedAddition::from_bytes(&record.record)?
                .addition
                .device
                .label);
        }
    }
    Ok(String::new())
}

/// What one hourly task did ([`hourly`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hourly {
    /// What went from the index.
    pub gone: held::Gone,
    /// How many of the device's own messages it cleared at the relays.
    pub cleared: usize,
    /// Whether the write-ahead log was written back whole and truncated.
    pub checkpointed: bool,
}

/// The hourly task of a personal node (decision 2026-10-09 §7.1,
/// `AGENT_MESSAGE_CLEAR_INTERVAL_SECS`), at `now` by the node's clock,
/// whatever the device's state: first the index rows of messages that
/// have expired or are held at no live number are overwritten and
/// dropped, in one write, with the kept values of the device's own of
/// every generation other than the one it stands applied under, and then
/// what is kept of each such generation once none of its rows is left;
/// then, where the device stands applied, has sync on and has fetched the
/// messages channel since it started (`fetched`), it clears its own
/// expired messages at the relays ([`crate::sender::clear_expired`]); and
/// last the truncating checkpoint runs, so that what was overwritten
/// stands in the log no longer than an hour.
pub fn hourly(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: bool,
) -> Result<Hourly, PersonError> {
    let gone = in_one(conn, || {
        let applied = crate::at_relays::messages_channel(conn)?;
        kept(held::drop_gone(conn, now, applied.as_ref()))
    })?;
    let cleared = crate::sender::clear_expired(conn, identity, now, fetched)?;
    let checkpointed = kept(cordelia_storage::db::checkpoint_truncating(conn))?;
    Ok(Hourly {
        gone,
        cleared,
        checkpointed,
    })
}

/// What the store answered, with its error as the device's.
fn kept<T>(answer: Result<T, StorageError>) -> Result<T, PersonError> {
    answer.map_err(|e| PersonError::Storage(CordeliaError::Storage(e.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordelia_core::protocol::{AGENT_MESSAGE_ID_BYTES, REV_BAND_HALF};
    use cordelia_crypto::entry::{Entry, Value};
    use cordelia_crypto::identity::NodeIdentity;
    use cordelia_crypto::message::{
        Message, ReadMarks, To, clearing_rev, clearing_value, message_id, message_name,
        message_rev, read_name,
    };
    use cordelia_storage::entries::{self, Outcome};
    use cordelia_storage::person::State;

    use crate::several::{Several, entry_by, signed_in};
    use crate::take::{NotTaken, Taken, take};

    const HOUR: i64 = 60 * 60;
    const DAY: i64 = 24 * HOUR;

    const STORED: Taken = Taken::Own {
        stored: Outcome::Stored,
        record: None,
        came_to_count: 0,
        came_to_add: 0,
    };

    /// The secret of the messages channel that device `n` has applied.
    fn messages(s: &Several, n: usize) -> [u8; 32] {
        derive::messages_secret(&s[n].secret()).unwrap()
    }

    /// A message from the agent of `~` to that of `notes` that says
    /// `body`, sent at `sent`.
    fn says(body: &str, sent: i64) -> Message {
        Message {
            asks: false,
            sent: u64::try_from(sent).unwrap(),
            nonce: [0; 16],
            thread: [0; AGENT_MESSAGE_ID_BYTES],
            answers: [0; AGENT_MESSAGE_ID_BYTES],
            from: "~".into(),
            to: To::Name("notes".into()),
            link: None,
            body: body.into(),
        }
    }

    fn value_of(message: &Message) -> Vec<u8> {
        message.to_value(crate::names::is_a_name).unwrap()
    }

    /// The entry of `author` named `name` at `rev` holding `value`, in
    /// the messages channel that device `on` has applied.
    fn written(
        s: &Several,
        on: usize,
        author: &NodeIdentity,
        name: &str,
        rev: u64,
        value: Vec<u8>,
    ) -> CheckedEntry {
        entry_by(
            author,
            &messages(s, on),
            rev,
            name,
            Value::Other(value),
            &[],
        )
    }

    /// Message `number` of device `from`, saying `message`.
    fn sent(s: &Several, from: usize, number: u64, message: &Message) -> CheckedEntry {
        let name = message_name(&s.key(from), number).unwrap();
        let rev = message_rev(number).unwrap();
        written(s, from, &s[from].identity, &name, rev, value_of(message))
    }

    /// The entry that clears message `number` of device `from`.
    fn clearing(s: &Several, from: usize, number: u64) -> CheckedEntry {
        let name = message_name(&s.key(from), number).unwrap();
        let rev = clearing_rev(number).unwrap();
        written(s, from, &s[from].identity, &name, rev, clearing_value())
    }

    /// Device `from`'s list of what its agents read, at `rev`.
    fn list(s: &Several, from: usize, rev: u64) -> CheckedEntry {
        let name = read_name(&s.key(from)).unwrap();
        let value = ReadMarks {
            marks: vec![[9; 16]],
        }
        .to_value()
        .unwrap();
        written(s, from, &s[from].identity, &name, rev, value)
    }

    /// Device `n` is given `entry` at `now`.
    fn given_at(s: &Several, n: usize, entry: &CheckedEntry, now: i64) -> Taken {
        take(&s[n].conn, &s[n].identity, entry, now).unwrap()
    }

    fn given(s: &Several, n: usize, entry: &CheckedEntry) -> Taken {
        given_at(s, n, entry, s.now)
    }

    /// The generation of the messages channel that device `n` holds.
    fn generation(s: &Several, n: usize) -> i64 {
        let channel = derive::channel_id(&messages(s, n)).unwrap();
        s[n].conn
            .query_row(
                "SELECT id FROM message_generations WHERE channel = ?1",
                [&channel[..]],
                |row| row.get(0),
            )
            .unwrap()
    }

    /// What device `n` keeps of the signer that is device `of`.
    fn signer_on(s: &Several, n: usize, of: usize) -> held::Signer {
        held::signer(&s[n].conn, &s.key(of), generation(s, n))
            .unwrap()
            .unwrap_or_default()
    }

    fn rows(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    /// The numbers device `n` holds of the signer `of`, in order.
    fn numbers(s: &Several, n: usize, of: usize, table: &str) -> Vec<u64> {
        s[n].conn
            .prepare(&format!(
                "SELECT number FROM {table} WHERE signer = ?1 ORDER BY number"
            ))
            .unwrap()
            .query_map([&s.key(of)[..]], |row| row.get::<_, i64>(0))
            .unwrap()
            .map(|number| u64::try_from(number.unwrap()).unwrap())
            .collect()
    }

    /// The bodies device `n` shows at `now`, oldest first, once it has
    /// given places as a show does.
    fn shown_on(s: &Several, n: usize, now: i64) -> Vec<String> {
        held::give_places(&s[n].conn, &s.key(n), now).unwrap();
        held::shown(&s[n].conn, now)
            .unwrap()
            .into_iter()
            .map(|shown| shown.body)
            .collect()
    }

    /// The bodies device `n` shows at `now`, as numbers, in their order.
    fn shown_numbers(s: &Several, n: usize, now: i64) -> Vec<u64> {
        let mut shown: Vec<u64> = shown_on(s, n, now)
            .iter()
            .map(|body| body.trim_start_matches("number ").parse().unwrap())
            .collect();
        shown.sort();
        shown
    }

    /// The bodies of the index of device `n`, by body.
    fn indexed(s: &Several, n: usize) -> Vec<String> {
        s[n].conn
            .prepare("SELECT body FROM message_index ORDER BY body")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// When the store kept an entry of the messages channel, the reader
    /// writes in the same write the message's index row with its opened
    /// fields and the label its signer is known by, its row of numbers
    /// held, its row of first holding and the signer's H (decision
    /// 2026-10-09 §7.1, C20). An entry the store held already is not read
    /// again. Where the reader cannot write, the store keeps nothing.
    #[test]
    fn the_reader_indexes_what_the_door_stores_in_the_same_write() {
        let s = Several::of_one_person(2);
        let mut message = says("a branch to look at\nmore of it", s.now - 5);
        message.asks = true;
        message.link = Some("owner/repo#12".into());
        message.thread = [3; 16];
        let entry = sent(&s, 0, 1, &message);
        assert_eq!(given(&s, 1, &entry), STORED);

        let id = message_id(&s.key(0), &value_of(&message));
        let generation = generation(&s, 1);
        type Row = (
            Vec<u8>,
            Vec<u8>,
            String,
            i64,
            i64,
            Option<String>,
            String,
            i64,
        );
        let row: Row = s[1]
            .conn
            .query_row(
                "SELECT id, signer, label, generation, to_kind, to_name, from_name, sent
                 FROM message_index",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            row,
            (
                id.to_vec(),
                s.key(0).to_vec(),
                "device 0".to_string(),
                generation,
                1,
                Some("notes".to_string()),
                "~".to_string(),
                s.now - 5,
            )
        );
        type Rest = (String, Vec<u8>, Vec<u8>, bool, Option<String>, String, i64);
        let rest: (Rest, Option<i64>) = s[1]
            .conn
            .query_row(
                "SELECT subject, thread, answers, asks, link, body, first_held, placed_at
                 FROM message_index",
                [],
                |row| {
                    Ok((
                        (
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ),
                        row.get(7)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            rest,
            (
                (
                    "a branch to look at".to_string(),
                    vec![3; 16],
                    vec![0; 16],
                    true,
                    Some("owner/repo#12".to_string()),
                    "a branch to look at\nmore of it".to_string(),
                    s.now,
                ),
                None
            )
        );
        assert_eq!(numbers(&s, 1, 0, "message_numbers"), [1]);
        assert_eq!(numbers(&s, 1, 0, "message_first_held"), [1]);
        let first: (Vec<u8>, i64, i64) = s[1]
            .conn
            .query_row(
                "SELECT id, sent, first_held FROM message_first_held",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(first, (id.to_vec(), s.now - 5, s.now));
        assert_eq!(
            signer_on(&s, 1, 0),
            held::Signer {
                highest: 1,
                overwritten: 0,
                not_messages: 0,
                counted_from: Some(1),
            }
        );
        let statement: i64 = s[1]
            .conn
            .query_row("SELECT statement FROM message_generations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(statement, 1);

        // The subject is the first line cut at 80 Unicode scalar values.
        let long = says(&format!("{}\nthe rest", "é".repeat(90)), s.now);
        assert_eq!(given(&s, 1, &sent(&s, 0, 3, &long)), STORED);
        let subject: String = s[1]
            .conn
            .query_row(
                "SELECT subject FROM message_index WHERE body LIKE '%the rest'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(subject, "é".repeat(80));
        s[1].conn
            .execute("DELETE FROM message_index WHERE body LIKE '%the rest'", [])
            .unwrap();
        s[1].conn
            .execute("DELETE FROM message_first_held WHERE number = 3", [])
            .unwrap();
        s[1].conn
            .execute("UPDATE message_signers SET highest = 1", [])
            .unwrap();
        let channel = derive::channel_id(&messages(&s, 1)).unwrap();
        let slot = slot_id(
            &derive::slot_key(&messages(&s, 1)).unwrap(),
            &message_name(&s.key(0), 3).unwrap(),
        );
        s[1].conn
            .execute(
                "DELETE FROM entries WHERE channel_id = ?1 AND slot = ?2",
                [&channel[..], &slot[..]],
            )
            .unwrap();

        // Given again, it is held already: nothing is read again.
        let before = s[1].everything();
        assert!(matches!(
            given(&s, 1, &entry),
            Taken::Own {
                stored: Outcome::AlreadyHeld,
                ..
            }
        ));
        assert_eq!(s[1].everything(), before);

        // Where the index cannot be written, the entry is not kept.
        s[1].conn
            .execute_batch(
                "CREATE TEMP TRIGGER no_index BEFORE INSERT ON main.message_index
                 BEGIN SELECT RAISE(ABORT, 'no index'); END;",
            )
            .unwrap();
        let second = sent(&s, 0, 2, &says("the second", s.now));
        assert!(take(&s[1].conn, &s[1].identity, &second, s.now).is_err());
        assert_eq!(s[1].everything(), before);
        s[1].conn.execute_batch("DROP TRIGGER no_index").unwrap();
        assert_eq!(given(&s, 1, &second), STORED);
        assert_eq!(
            indexed(&s, 1),
            ["a branch to look at\nmore of it", "the second"]
        );
    }

    /// A message whose signer does not count is refused at the door, and
    /// the reader keeps nothing of it, whatever the store already holds
    /// (decision 2026-10-09 §1, property 1).
    #[test]
    fn a_message_whose_signer_does_not_count_is_not_shown() {
        let s = Several::of_one_person(2);
        let stranger = crate::several::Machine::new(7);
        let name = message_name(&stranger.key(), 1).unwrap();
        let entry = written(
            &s,
            1,
            &stranger.identity,
            &name,
            2,
            value_of(&says("from a stranger", s.now)),
        );
        // The store holds it, as one written there by other means.
        entries::store(&s[1].conn, &entry, s.now).unwrap();
        assert_eq!(
            given(&s, 1, &entry),
            Taken::Refused(NotTaken::SignerDoesNotCount)
        );
        assert!(indexed(&s, 1).is_empty());
        assert_eq!(rows(&s[1].conn, "message_signers"), 0);
        assert!(shown_on(&s, 1, s.now).is_empty());
        // The control: a device that counts.
        assert_eq!(given(&s, 1, &sent(&s, 0, 1, &says("x", s.now))), STORED);
        assert_eq!(shown_on(&s, 1, s.now), ["x"]);
    }

    /// An entry in a slot named for another key than the one that signed
    /// it is no message, whatever it holds: it is counted as no message
    /// of its signer, raises no H, and is never shown (decision 2026-10-09
    /// §2.3, property 2, T10).
    #[test]
    fn a_message_in_a_slot_named_for_another_key_is_no_message() {
        let s = Several::of_one_person(3);
        let value = value_of(&says("in another's slot", s.now));
        let name = message_name(&s.key(1), 64).unwrap();
        let entry = written(&s, 2, &s[0].identity, &name, 128, value.clone());
        assert_eq!(given(&s, 2, &entry), STORED);
        let others_list = read_name(&s.key(1)).unwrap();
        let list = ReadMarks::default().to_value().unwrap();
        let entry = written(&s, 2, &s[0].identity, &others_list, 1, list);
        assert_eq!(given(&s, 2, &entry), STORED);
        assert!(indexed(&s, 2).is_empty());
        assert!(shown_on(&s, 2, s.now).is_empty());
        assert_eq!(
            signer_on(&s, 2, 0),
            held::Signer {
                not_messages: 2,
                ..Default::default()
            }
        );
        assert_eq!(signer_on(&s, 2, 1), held::Signer::default());

        // The control: in the slot named for the key that signed.
        let own_name = message_name(&s.key(0), 64).unwrap();
        let entry = written(&s, 2, &s[0].identity, &own_name, 128, value);
        assert_eq!(given(&s, 2, &entry), STORED);
        assert_eq!(shown_on(&s, 2, s.now), ["in another's slot"]);
        assert_eq!(signer_on(&s, 2, 0).highest, 64);
    }

    /// The number must be in its slot's place, with the value of the form
    /// of its revision (decision 2026-10-09 §2.3, C3, T10): number 65 in
    /// slot 0, an odd revision with a message's value, and the slots `07`
    /// and `64` are no message, and are counted. An entry in its slot
    /// with the wrong form raises H, since its slot was right; one whose
    /// slot is wrong raises nothing.
    #[test]
    fn an_entry_whose_number_is_not_in_its_slots_place_is_no_message() {
        let s = Several::of_one_person(2);
        let laptop = &s[0].identity;
        let key = cordelia_crypto::bech32::encode_public_key(&s.key(0)).unwrap();
        let slot = |place: &str| format!("msg/{key}/{place}");
        let value = || value_of(&says("out of place", s.now));
        // Revision 1 is the clearing of number 0, and 2^43 the message of
        // 2^42, one past the highest: both are in slot 0 by their names,
        // and neither is a number a message can have.
        let entry = written(&s, 1, laptop, &slot("0"), 1, clearing_value());
        assert_eq!(given(&s, 1, &entry), STORED);
        for (place, rev) in [("0", 130), ("07", 14), ("64", 128)] {
            let entry = written(&s, 1, laptop, &slot(place), rev, value());
            assert_eq!(given(&s, 1, &entry), STORED, "{place}");
        }
        let entry = written(&s, 1, laptop, &slot("0"), 1 << 43, value());
        assert_eq!(given(&s, 1, &entry), STORED);
        assert_eq!(signer_on(&s, 1, 0).highest, 0);
        let entry = written(&s, 1, laptop, &slot("1"), 131, value());
        assert_eq!(given(&s, 1, &entry), STORED);
        assert!(indexed(&s, 1).is_empty());
        assert_eq!(
            signer_on(&s, 1, 0),
            held::Signer {
                highest: 65,
                overwritten: 0,
                not_messages: 6,
                counted_from: Some(65),
            }
        );
        // The control: number 66, in slot 2.
        let entry = written(&s, 1, laptop, &slot("2"), 132, value());
        assert_eq!(given(&s, 1, &entry), STORED);
        assert_eq!(shown_on(&s, 1, s.now), ["out of place"]);
    }

    /// Another device's entry in a sender's slot, at a higher revision,
    /// stands beside the sender's message and replaces nothing: the
    /// message is still shown, and the other entry is no message
    /// (decision 2026-10-09 §2.2, property 3).
    #[test]
    fn another_devices_entry_in_a_slot_replaces_no_message() {
        let s = Several::of_one_person(3);
        assert_eq!(
            given(&s, 1, &sent(&s, 0, 1, &says("the sender's", s.now))),
            STORED
        );
        let name = message_name(&s.key(0), 1).unwrap();
        let over = value_of(&says("written over", s.now));
        let entry = written(&s, 1, &s[2].identity, &name, 4, over);
        assert_eq!(given(&s, 1, &entry), STORED);
        assert_eq!(s[1].stored_in(&messages(&s, 1)).len(), 2);
        assert_eq!(shown_on(&s, 1, s.now), ["the sender's"]);
        assert_eq!(signer_on(&s, 1, 2).not_messages, 1);
        assert_eq!(signer_on(&s, 1, 2).highest, 0);
    }

    /// With H at 200, an entry at 136 is counted as overwritten and not
    /// opened; one at 137 is opened (decision 2026-10-09 §2.5, property
    /// 21). The two hold what does not open: only the one opened is
    /// counted as no message. (136 shares its slot with 200: the store
    /// has lost 200's entry, as one restored from before it is, so that
    /// it takes 136.)
    #[test]
    fn an_entry_at_a_number_that_is_not_live_is_never_opened() {
        let s = Several::of_one_person(2);
        let two_hundred = sent(&s, 0, 200, &says("two hundred", s.now));
        assert_eq!(given(&s, 1, &two_hundred), STORED);
        s[1].conn
            .execute(
                "DELETE FROM entries WHERE channel_id = ?1",
                [&two_hundred.channel[..]],
            )
            .unwrap();
        let slot_key = derive::slot_key(&messages(&s, 1)).unwrap();
        let unopened = |number: u64| {
            let name = message_name(&s.key(0), number).unwrap();
            signed_in(
                &messages(&s, 1),
                &s[0].identity,
                slot_id(&slot_key, &name),
                message_rev(number).unwrap(),
                vec![7; 2048],
            )
        };
        assert_eq!(given(&s, 1, &unopened(136)), STORED);
        assert_eq!(
            signer_on(&s, 1, 0),
            held::Signer {
                highest: 200,
                overwritten: 1,
                not_messages: 0,
                counted_from: Some(200),
            }
        );
        assert_eq!(given(&s, 1, &unopened(137)), STORED);
        assert_eq!(
            signer_on(&s, 1, 0),
            held::Signer {
                highest: 200,
                overwritten: 1,
                not_messages: 1,
                counted_from: Some(137),
            }
        );
        assert_eq!(indexed(&s, 1), ["two hundred"]);
    }

    /// A list far above its messages raises no H (decision 2026-10-09
    /// §2.5, property 21): laptop's messages are numbers 1 to 5, its
    /// list stands a thousand revisions up, and a holder of its key
    /// writes one at the top of band 0's bottom half. On a reader that
    /// takes the lists first and on one that takes them last, H is 5,
    /// all five are shown, and nothing is overwritten. An entry in the
    /// slot of place 3 at a number whose place is 4 raises nothing, and
    /// is no message.
    #[test]
    fn a_list_far_above_its_messages_loses_no_message_on_any_reader() {
        let s = Several::of_one_person(3);
        let messages: Vec<CheckedEntry> = (1..=5)
            .map(|number| sent(&s, 0, number, &says(&format!("number {number}"), s.now)))
            .collect();
        let lists = [list(&s, 0, 1_000), list(&s, 0, REV_BAND_HALF - 1)];
        for (reader, lists_first) in [(1, true), (2, false)] {
            let order: Vec<&CheckedEntry> = match lists_first {
                true => lists.iter().chain(&messages).collect(),
                false => messages.iter().chain(&lists).collect(),
            };
            for entry in order {
                assert_eq!(given(&s, reader, entry), STORED);
            }
            assert_eq!(
                signer_on(&s, reader, 0),
                held::Signer {
                    highest: 5,
                    overwritten: 0,
                    not_messages: 0,
                    counted_from: Some(1),
                },
                "{reader}"
            );
            assert_eq!(
                shown_numbers(&s, reader, s.now),
                [1, 2, 3, 4, 5],
                "{reader}"
            );
        }
        let key = cordelia_crypto::bech32::encode_public_key(&s.key(0)).unwrap();
        let entry = written(
            &s,
            1,
            &s[0].identity,
            &format!("msg/{key}/3"),
            message_rev(68).unwrap(),
            value_of(&says("out of place", s.now)),
        );
        assert_eq!(given(&s, 1, &entry), STORED);
        assert_eq!(signer_on(&s, 1, 0).highest, 5);
        assert_eq!(signer_on(&s, 1, 0).not_messages, 1);
        // A list that says more than 120 marks is no list.
        let mut over = ReadMarks::default().to_value().unwrap();
        over[2] = 121;
        let name = read_name(&s.key(0)).unwrap();
        let entry = written(&s, 1, &s[0].identity, &name, REV_BAND_HALF, over);
        assert_eq!(given(&s, 1, &entry), STORED);
        assert_eq!(signer_on(&s, 1, 0).not_messages, 2);
        assert_eq!(signer_on(&s, 1, 0).highest, 5);
        assert_eq!(shown_on(&s, 1, s.now).len(), 5);
    }

    /// Numbers that left the live numbers before their message had a
    /// place are counted as overwritten: those never held and those held
    /// and not shown, and not those shown (decision 2026-10-09 §2.5). A
    /// reader holds 1 to 3 and then 100: 1 to 36 leave. Where 1 to 3 had
    /// places, 33 are counted; where they had none, 36.
    #[test]
    fn a_gap_in_a_signers_numbers_is_said_as_overwritten() {
        let s = Several::of_one_person(3);
        for reader in [1, 2] {
            for number in 1..=3 {
                let entry = sent(&s, 0, number, &says(&format!("{number}"), s.now));
                assert_eq!(given(&s, reader, &entry), STORED);
            }
        }
        assert_eq!(shown_numbers(&s, 1, s.now), [1, 2, 3]);
        let hundred = sent(&s, 0, 100, &says("100", s.now));
        for (reader, counted) in [(1, 33), (2, 36)] {
            assert_eq!(given(&s, reader, &hundred), STORED);
            let kept = signer_on(&s, reader, 0);
            assert_eq!((kept.highest, kept.overwritten), (100, counted), "{reader}");
            assert_eq!(numbers(&s, reader, 0, "message_numbers"), [100]);
            assert_eq!(numbers(&s, reader, 0, "message_first_held"), [100]);
            assert_eq!(indexed(&s, reader), ["100"]);
        }
    }

    /// A reader that takes a clearing drops the index row of the message
    /// it holds at that number, whichever other numbers it is held at
    /// (decision 2026-10-09 §2.3, D11): a message sent again at 1 and 2
    /// goes at the clearing of 1, and in a second run at the clearing of
    /// 2. Another message stays, a clearing of a number not held drops
    /// nothing and holds that number as gone, and the rows of first
    /// holding stay.
    #[test]
    fn a_clearing_by_either_number_drops_a_message_sent_again() {
        for cleared in [1, 2] {
            let s = Several::of_one_person(2);
            let again = says("sent again", s.now);
            for number in [1, 2] {
                assert_eq!(given(&s, 1, &sent(&s, 0, number, &again)), STORED);
            }
            let other = sent(&s, 0, 3, &says("another", s.now));
            assert_eq!(given(&s, 1, &other), STORED);
            assert_eq!(indexed(&s, 1), ["another", "sent again"]);
            assert_eq!(numbers(&s, 1, 0, "message_numbers"), [1, 2, 3]);

            assert_eq!(given(&s, 1, &clearing(&s, 0, 9)), STORED);
            assert_eq!(indexed(&s, 1), ["another", "sent again"]);
            assert_eq!(given(&s, 1, &clearing(&s, 0, cleared)), STORED);
            assert_eq!(indexed(&s, 1), ["another"], "{cleared}");
            assert_eq!(numbers(&s, 1, 0, "message_numbers"), [3]);
            assert_eq!(numbers(&s, 1, 0, "message_first_held"), [1, 2, 3, 9]);
            assert_eq!(shown_on(&s, 1, s.now), ["another"]);
        }
    }

    /// A message is shown at 29 days and 23 hours after it was first
    /// held, and not at 30 days; once the hourly task has run, its row has
    /// gone from the index, though nothing cleared it (decision 2026-10-09
    /// §7.1, property 11).
    #[test]
    fn a_message_is_not_shown_thirty_days_after_it_was_first_held() {
        let s = Several::of_one_person(2);
        let held_at = s.now;
        assert_eq!(
            given(&s, 1, &sent(&s, 0, 1, &says("for a month", held_at))),
            STORED
        );
        assert_eq!(shown_on(&s, 1, held_at), ["for a month"]);
        assert_eq!(shown_on(&s, 1, held_at + 30 * DAY - HOUR), ["for a month"]);
        assert!(shown_on(&s, 1, held_at + 30 * DAY).is_empty());
        assert_eq!(indexed(&s, 1), ["for a month"]);

        let task = hourly(&s[1].conn, &s[1].identity, held_at + 30 * DAY - 1, true).unwrap();
        assert_eq!(task.gone, held::Gone::default());
        assert_eq!(indexed(&s, 1), ["for a month"]);
        let task = hourly(&s[1].conn, &s[1].identity, held_at + 30 * DAY, true).unwrap();
        assert_eq!(task.gone.expired, 1);
        assert!(indexed(&s, 1).is_empty());
        assert_eq!(rows(&s[1].conn, "message_numbers"), 0);
        assert_eq!(numbers(&s, 1, 0, "message_first_held"), [1]);
    }

    /// Which of `words` the bytes of `file` hold.
    fn words_in<'a>(file: &std::path::Path, words: &[&'a str]) -> Vec<&'a str> {
        let bytes = std::fs::read(file).unwrap_or_default();
        words
            .iter()
            .copied()
            .filter(|words| bytes.windows(words.len()).any(|at| at == words.as_bytes()))
            .collect()
    }

    /// Once a row's 30 days are up and the hourly task has run, which
    /// drops it and ends with its truncating checkpoint, nothing of its
    /// body, link, subject, `from` or `to` is in the database file of a
    /// store with `secure_delete` on, and the log is empty (decision
    /// 2026-10-09 §7.1, D10): on a device with sync on, with sync off, and
    /// on one that does not stand applied. `secure_delete` reads 1 on a
    /// store opened as a personal node opens it, and 0 on one opened as a
    /// relay's is.
    #[test]
    fn the_index_row_is_overwritten_before_it_is_dropped_with_secure_delete_on() {
        let words = [
            "subject of heron-quartz-mandolin",
            "body of heron-quartz-mandolin",
            "owner-of-heron/repo-of-quartz#4242",
            "github.com/owner/from-heron-quartz",
            "github.com/owner/to-heron-quartz",
        ];
        let dir = tempfile::tempdir().unwrap();
        let secure_delete = |conn: &Connection| -> i64 {
            conn.pragma_query_value(None, "secure_delete", |row| row.get(0))
                .unwrap()
        };
        let relay = cordelia_storage::db::open_as(&dir.path().join("relay.db"), false).unwrap();
        assert_eq!(secure_delete(&relay), 0);

        for run in ["sync on", "sync off", "not applied"] {
            let mut s = Several::of_one_person(2);
            let path = dir.path().join(format!("{}.db", run.replace(' ', "-")));
            s.machines[1]
                .conn
                .execute("VACUUM INTO ?1", [path.to_str().unwrap()])
                .unwrap();
            s.machines[1].conn = cordelia_storage::db::open_as(&path, true).unwrap();
            assert_eq!(secure_delete(&s[1].conn), 1);
            match run {
                "sync on" => {
                    cordelia_storage::meta::set(
                        &s[1].conn,
                        cordelia_storage::meta::SYNC_CLAUDE_DIR,
                        "/home/laptop/.claude",
                    )
                    .unwrap();
                }
                "sync off" => {}
                _ => {}
            }
            let message = Message {
                from: words[3].into(),
                to: To::Name(words[4].into()),
                link: Some(words[2].into()),
                ..says(&format!("{}\n{}", words[0], words[1]), s.now)
            };
            assert_eq!(given(&s, 1, &sent(&s, 0, 1, &message)), STORED);
            let log = path.with_extension("db-wal");
            assert!(cordelia_storage::db::checkpoint_truncating(&s[1].conn).unwrap());
            assert_eq!(words_in(&path, &words), words, "{run}");
            if run == "not applied" {
                held_rows::set_state(&s[1].conn, State::Removed).unwrap();
            }
            // A write after the checkpoint puts the row's page in the log.
            s[1].conn
                .execute("UPDATE message_index SET placed_at = 1", [])
                .unwrap();
            assert_eq!(words_in(&log, &words), words, "{run}");

            let task = hourly(&s[1].conn, &s[1].identity, s.now + 30 * DAY, true).unwrap();
            assert_eq!(task.gone.expired, 1, "{run}");
            assert!(task.checkpointed, "{run}");
            assert!(words_in(&path, &words).is_empty(), "{run}");
            assert!(words_in(&log, &words).is_empty(), "{run}");
            assert_eq!(std::fs::metadata(&log).unwrap().len(), 0, "{run}");
        }
    }

    /// A sender whose clock is behind by ten days has its message shown
    /// for twenty days; one whose clock is ahead by five has its message
    /// shown for thirty days from its first holding and no longer
    /// (decision 2026-10-09 §7.1, "Whose clock decides what").
    #[test]
    fn a_sender_clock_behind_shortens_a_messages_life_and_one_ahead_does_not_lengthen_it() {
        let s = Several::of_one_person(2);
        let held_at = s.now;
        let behind = sent(&s, 0, 1, &says("behind", held_at - 10 * DAY));
        let ahead = sent(&s, 0, 2, &says("ahead", held_at + 5 * DAY));
        assert_eq!(given(&s, 1, &behind), STORED);
        assert_eq!(given(&s, 1, &ahead), STORED);
        assert_eq!(shown_on(&s, 1, held_at), ["behind", "ahead"]);
        assert_eq!(shown_on(&s, 1, held_at + 20 * DAY - 1), ["behind", "ahead"]);
        assert_eq!(shown_on(&s, 1, held_at + 20 * DAY), ["ahead"]);
        assert_eq!(shown_on(&s, 1, held_at + 30 * DAY - 1), ["ahead"]);
        assert!(shown_on(&s, 1, held_at + 30 * DAY).is_empty());
        assert!(held::has_expired(
            held_at - 10 * DAY,
            held_at,
            held_at + 20 * DAY
        ));
        assert!(!held::has_expired(
            held_at + 5 * DAY,
            held_at,
            held_at + 30 * DAY - 1
        ));
    }

    /// A message whose `sent` is a day ahead of the reader's clock is
    /// shown, from its first holding: its shown time is its first
    /// holding, so it was sent "just now", it is not shown 30 days after
    /// that, and it stands among the others by its first holding
    /// (decision 2026-10-09 §7.1, F1).
    #[test]
    fn a_message_sent_ahead_of_the_readers_clock_is_shown_from_its_first_holding() {
        let s = Several::of_one_person(2);
        let held_at = s.now;
        let ahead = sent(&s, 0, 1, &says("a day ahead", held_at + DAY));
        assert_eq!(given_at(&s, 1, &ahead, held_at), STORED);
        let later = sent(&s, 0, 2, &says("held later", held_at + 1));
        assert_eq!(given_at(&s, 1, &later, held_at + 1), STORED);
        held::give_places(&s[1].conn, &s.key(1), held_at + 1).unwrap();
        let shown = held::shown(&s[1].conn, held_at + 1).unwrap();
        let bodies: Vec<&str> = shown.iter().map(|shown| shown.body.as_str()).collect();
        assert_eq!(bodies, ["a day ahead", "held later"]);
        assert_eq!(shown[0].shown_at, held_at);
        assert_eq!(shown[0].sent, held_at + DAY);
        assert_eq!(held::shown_at(held_at + DAY, held_at), held_at);
        assert_eq!(
            shown_on(&s, 1, held_at + 30 * DAY - 1),
            ["a day ahead", "held later"]
        );
        assert_eq!(shown_on(&s, 1, held_at + 30 * DAY), ["held later"]);
        assert!(shown_on(&s, 1, held_at + 30 * DAY + 1).is_empty());
    }

    /// What is shown is oldest first by shown time, and between two of
    /// one shown time by ID; a message sent earlier but held later stands
    /// by its shown time, the earlier of the two (decision 2026-10-09
    /// §4.1, F9). The store's half of `oldest_first_is_by_shown_time_
    /// then_by_id`, whose `summary` and `log` are a later slice's.
    #[test]
    fn shown_is_oldest_first_by_shown_time_then_by_id() {
        let s = Several::of_one_person(2);
        let t = s.now;
        let (one, two) = (says("one of a time", t), says("two of a time", t));
        let early = says("sent early, held late", t - 50);
        let late = says("sent late, held early", t + 40);
        assert_eq!(given_at(&s, 1, &sent(&s, 0, 1, &late), t - 10), STORED);
        assert_eq!(given_at(&s, 1, &sent(&s, 0, 2, &one), t), STORED);
        assert_eq!(given_at(&s, 1, &sent(&s, 0, 3, &two), t), STORED);
        assert_eq!(given_at(&s, 1, &sent(&s, 0, 4, &early), t + 100), STORED);
        let ids = [one.clone(), two.clone()].map(|m| message_id(&s.key(0), &value_of(&m)));
        let (first, second) = match ids[0] < ids[1] {
            true => ("one of a time", "two of a time"),
            false => ("two of a time", "one of a time"),
        };
        assert_eq!(
            shown_on(&s, 1, t + 100),
            [
                "sent early, held late",
                "sent late, held early",
                first,
                second
            ]
        );
    }

    /// An entry that a relay hands back after its row went at its 30 days
    /// finds its row of first holding and is not shown again, and so is
    /// the same message at another number (decision 2026-10-09 §7.1, C10).
    /// The store had lost the entry, as one restored from before it is.
    #[test]
    fn an_entry_taken_again_after_its_thirty_days_is_never_shown() {
        let s = Several::of_one_person(2);
        let held_at = s.now;
        let message = says("once", held_at);
        let entry = sent(&s, 0, 1, &message);
        assert_eq!(given(&s, 1, &entry), STORED);
        assert_eq!(shown_on(&s, 1, held_at), ["once"]);
        hourly(&s[1].conn, &s[1].identity, held_at + 30 * DAY, true).unwrap();
        assert!(indexed(&s, 1).is_empty());

        s[1].conn
            .execute(
                "DELETE FROM entries WHERE channel_id = ?1",
                [&entry.channel[..]],
            )
            .unwrap();
        let later = held_at + 30 * DAY + 1;
        assert_eq!(given_at(&s, 1, &entry, later), STORED);
        assert_eq!(given_at(&s, 1, &sent(&s, 0, 2, &message), later), STORED);
        assert!(indexed(&s, 1).is_empty());
        assert!(shown_on(&s, 1, later).is_empty());
        assert_eq!(numbers(&s, 1, 0, "message_first_held"), [1, 2]);
    }

    /// The reader's hour for `of` on device `n` at `now`: how many of its
    /// messages wait for a place.
    fn held_back(s: &Several, n: usize, of: usize, now: i64) -> u64 {
        held::held_back(&s[n].conn, &s.key(of), generation(s, n), now).unwrap()
    }

    /// An honest device sends 64 over two hours while the reader is off;
    /// the reader takes them, and gives all 64 places at its first show,
    /// holding none back (decision 2026-10-09 §6, property 9).
    #[test]
    fn a_reader_that_was_away_shows_a_whole_ring_at_once() {
        let s = Several::of_one_person(2);
        let start = s.now;
        for number in 1..=64u64 {
            let at = start + i64::try_from(number).unwrap() * 2 * HOUR / 64;
            let entry = sent(&s, 0, number, &says(&format!("{number:02}"), at));
            assert_eq!(given_at(&s, 1, &entry, start + 3 * HOUR), STORED);
        }
        let now = start + 3 * HOUR;
        assert_eq!(held_back(&s, 1, 0, now), 64);
        assert_eq!(shown_on(&s, 1, now).len(), 64);
        assert_eq!(held_back(&s, 1, 0, now), 0);
    }

    /// A holder of a device's key writes 64 new numbers before each of 50
    /// shows within an hour: the reader gives 64 places in that hour, the
    /// newest at the first show, and counts the rest as overwritten; an
    /// hour after the first place it gives places again (decision
    /// 2026-10-09 §6, property 9, T22).
    #[test]
    fn a_holder_of_the_key_that_laps_its_ring_is_shown_at_most_64_in_an_hour() {
        let s = Several::of_one_person(2);
        let start = s.now;
        let mut number = 0u64;
        let mut lap = |at: i64| {
            for _ in 0..64 {
                number += 1;
                let entry = sent(&s, 0, number, &says(&format!("{number}"), at));
                assert_eq!(given_at(&s, 1, &entry, at), STORED);
            }
        };
        let mut placed = 0;
        for show in 0..50 {
            let at = start + show * 60;
            lap(at);
            placed += held::give_places(&s[1].conn, &s.key(1), at).unwrap();
            if show == 0 {
                let newest: Vec<u64> = (1..=64).collect();
                assert_eq!(shown_numbers(&s, 1, at), newest);
            }
        }
        assert_eq!(placed, 64);
        let kept = signer_on(&s, 1, 0);
        assert_eq!(kept.highest, 50 * 64);
        // All but the first lap, which had places, and the last, which is
        // live.
        assert_eq!(kept.overwritten, 48 * 64);
        assert_eq!(held_back(&s, 1, 0, start + 49 * 60), 64);
        assert_eq!(rows(&s[1].conn, "message_places"), 64);

        // An hour after the first place, the newest 64 have places.
        let again = start + HOUR;
        assert_eq!(
            held::give_places(&s[1].conn, &s.key(1), again - 1).unwrap(),
            0
        );
        assert_eq!(held::give_places(&s[1].conn, &s.key(1), again).unwrap(), 64);
        let newest: Vec<u64> = (49 * 64 + 1..=50 * 64).collect();
        assert_eq!(shown_numbers(&s, 1, again), newest);
    }

    /// 64 places are given, and then their messages are cleared: a new
    /// message of that signer has no place until the hour of the first
    /// place is up, since every place given in the hour counts (decision
    /// 2026-10-09 §6, F5).
    #[test]
    fn a_place_counts_in_the_hour_whatever_became_of_its_message() {
        let s = Several::of_one_person(2);
        let start = s.now;
        for number in 1..=64 {
            let entry = sent(&s, 0, number, &says(&format!("{number}"), start));
            assert_eq!(given_at(&s, 1, &entry, start), STORED);
        }
        assert_eq!(shown_on(&s, 1, start).len(), 64);
        for number in 1..=64 {
            assert_eq!(
                given_at(&s, 1, &clearing(&s, 0, number), start + 10),
                STORED
            );
        }
        assert!(indexed(&s, 1).is_empty());
        let entry = sent(&s, 0, 65, &says("new", start + 20));
        assert_eq!(given_at(&s, 1, &entry, start + 20), STORED);
        assert!(shown_on(&s, 1, start + 20).is_empty());
        assert!(shown_on(&s, 1, start + HOUR - 1).is_empty());
        assert_eq!(held_back(&s, 1, 0, start + HOUR - 1), 1);
        assert_eq!(shown_on(&s, 1, start + HOUR), ["new"]);
    }

    /// An honest device sends 200 over four days, which a relay withholds.
    /// It hands 101 to 164, which the reader shows; then 165 to 200, which
    /// wait, and each has a place at the first show an hour after the
    /// first of the 64 places. In a second run it hands 101 to 200 in one
    /// pull, and 137 to 200 have places at the next show (decision
    /// 2026-10-09 §6, §10, D2).
    #[test]
    fn a_relay_that_hands_old_entries_in_rising_order_holds_current_ones_back_an_hour_at_most() {
        let body = |number: u64| format!("{number:03}");
        let start = Several::of_one_person(1).now;
        let entries = |s: &Several| -> Vec<CheckedEntry> {
            (1..=200u64)
                .map(|number| {
                    let at = start + i64::try_from(number).unwrap() * 4 * DAY / 200;
                    sent(s, 0, number, &says(&body(number), at))
                })
                .collect()
        };
        let now = start + 4 * DAY;

        let s = Several::of_one_person(2);
        let all = entries(&s);
        for entry in &all[100..164] {
            assert_eq!(given_at(&s, 1, entry, now), STORED);
        }
        let first: Vec<String> = (101..=164).map(body).collect();
        assert_eq!(shown_on(&s, 1, now), first);
        for entry in &all[164..] {
            assert_eq!(given_at(&s, 1, entry, now + 60), STORED);
        }
        let still: Vec<String> = (137..=164).map(body).collect();
        assert_eq!(shown_on(&s, 1, now + 60), still);
        assert_eq!(shown_on(&s, 1, now + HOUR - 1), still);
        assert_eq!(held_back(&s, 1, 0, now + HOUR - 1), 36);
        let current: Vec<String> = (137..=200).map(body).collect();
        assert_eq!(shown_on(&s, 1, now + HOUR), current);
        assert_eq!(signer_on(&s, 1, 0).overwritten, 0);

        let s = Several::of_one_person(2);
        let all = entries(&s);
        for entry in &all[100..] {
            assert_eq!(given_at(&s, 1, entry, now), STORED);
        }
        assert_eq!(shown_on(&s, 1, now), current);
        assert_eq!(signer_on(&s, 1, 0).overwritten, 36);
    }

    /// Places given at a clock an hour ahead keep their messages' places
    /// once the clock is set back, and are not counted in its hour: 64
    /// new places can be given (decision 2026-10-09 §6, D8).
    #[test]
    fn a_place_in_the_future_of_the_readers_clock_keeps_its_place_and_is_not_counted() {
        let s = Several::of_one_person(2);
        let right = s.now;
        for number in 1..=64 {
            let entry = sent(&s, 0, number, &says(&format!("{number:03}"), right));
            assert_eq!(given_at(&s, 1, &entry, right), STORED);
        }
        assert_eq!(shown_on(&s, 1, right + HOUR).len(), 64);
        for number in 65..=128 {
            let entry = sent(&s, 0, number, &says(&format!("{number:03}"), right));
            assert_eq!(given_at(&s, 1, &entry, right), STORED);
        }
        // Set back: what had places is shown, and the new ones have room.
        assert_eq!(
            held::give_places(&s[1].conn, &s.key(1), right + 10).unwrap(),
            64
        );
        let expected: Vec<u64> = (65..=128).collect();
        assert_eq!(shown_numbers(&s, 1, right + 10), expected);
        assert_eq!(held_back(&s, 1, 0, right + 10), 0);
    }

    /// A holder of a device's key writes its 64 slots with rising numbers
    /// lap after lap, and the reader takes each: after every lap, each
    /// table of the reader's holds no more rows for that signer than
    /// after the first, and the database file is no larger than after the
    /// second; and the rest are counted as overwritten (decision
    /// 2026-10-09 §2.5, property 21, D1, T22). The record asks for ten
    /// thousand laps; each entry costs some milliseconds to seal and take
    /// in a test build, so this writes a hundred, 6,400 entries, and holds
    /// the bound at each.
    #[test]
    fn a_signer_that_rewrites_its_ring_ten_thousand_times_leaves_one_lap_in_a_readers_store() {
        const LAPS: u64 = 100;
        let mut s = Several::of_one_person(2);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reader.db");
        s.machines[1]
            .conn
            .execute("VACUUM INTO ?1", [path.to_str().unwrap()])
            .unwrap();
        s.machines[1].conn = cordelia_storage::db::open_as(&path, true).unwrap();
        let tables = [
            "message_index",
            "message_numbers",
            "message_first_held",
            "message_signers",
            "message_places",
        ];
        let channel = derive::channel_id(&messages(&s, 1)).unwrap();
        let counted = |s: &Several| -> Vec<i64> {
            let mut counted: Vec<i64> =
                tables.iter().map(|table| rows(&s[1].conn, table)).collect();
            counted.push(
                s[1].conn
                    .query_row(
                        "SELECT COUNT(*) FROM entries WHERE channel_id = ?1",
                        [&channel[..]],
                        |row| row.get(0),
                    )
                    .unwrap(),
            );
            counted
        };
        let size = |s: &Several| -> u64 {
            assert!(cordelia_storage::db::checkpoint_truncating(&s[1].conn).unwrap());
            std::fs::metadata(&path).unwrap().len()
        };
        let messages = messages(&s, 1);
        let (mut after_first, mut after_second) = (Vec::new(), 0);
        for lap in 0..LAPS {
            s[1].conn.execute_batch("BEGIN").unwrap();
            for place in 1..=64 {
                let number = lap * 64 + place;
                let entry = Entry::seal(
                    &messages,
                    &s[0].identity,
                    message_rev(number).unwrap(),
                    &message::inside(
                        message_name(&s.key(0), number).unwrap(),
                        value_of(&says(&number.to_string(), s.now)),
                    ),
                )
                .unwrap()
                .check()
                .unwrap();
                assert_eq!(given(&s, 1, &entry), STORED);
            }
            s[1].conn.execute_batch("COMMIT").unwrap();
            if lap == 0 {
                after_first = counted(&s);
                assert_eq!(after_first, [64, 64, 64, 1, 0, 64]);
            }
            let after = counted(&s);
            for (at, (after, first)) in after.iter().zip(&after_first).enumerate() {
                assert!(after <= first, "lap {lap}, {at}: {after} > {first}");
            }
            if lap == 1 {
                after_second = size(&s);
            }
            if lap > 1 && lap % 10 == 0 {
                assert!(size(&s) <= after_second, "lap {lap}");
            }
        }
        assert!(size(&s) <= after_second);
        let kept = signer_on(&s, 1, 0);
        assert_eq!(kept.highest, LAPS * 64);
        assert_eq!(kept.overwritten, (LAPS - 1) * 64);
    }

    /// What the door answered for an entry it did not store.
    fn not_stored(taken: &Taken) -> Option<Outcome> {
        match taken {
            Taken::Own { stored, .. } if *stored != Outcome::Stored => Some(*stored),
            _ => None,
        }
    }

    /// The reader reads only what the store kept (decision 2026-10-09
    /// §7.1). A reader that holds the clearing of a number, and is then
    /// handed that number's message by a relay that is behind, is told by
    /// the store that it holds a higher revision: nothing is indexed,
    /// shown or counted. So for an entry the store already holds, handed
    /// again. At a live number, and at one that is not live and is below
    /// the number counted from, where a message read would be counted.
    #[test]
    fn the_reader_reads_only_what_the_store_kept() {
        // A live number: the clearing of 5, then message 5.
        let s = Several::of_one_person(2);
        assert_eq!(given(&s, 1, &clearing(&s, 0, 5)), STORED);
        let before = s[1].everything();
        let five = sent(&s, 0, 5, &says("five", s.now));
        assert_eq!(
            not_stored(&given(&s, 1, &five)),
            Some(Outcome::OlderThanHeld)
        );
        assert_eq!(s[1].everything(), before);
        assert!(indexed(&s, 1).is_empty());
        assert!(shown_on(&s, 1, s.now).is_empty());
        // A message that is shown, handed again.
        let six = sent(&s, 0, 6, &says("six", s.now));
        assert_eq!(given(&s, 1, &six), STORED);
        assert_eq!(shown_on(&s, 1, s.now), ["six"]);
        let before = s[1].everything();
        assert_eq!(not_stored(&given(&s, 1, &six)), Some(Outcome::AlreadyHeld));
        assert_eq!(s[1].everything(), before);
        assert_eq!(shown_on(&s, 1, s.now), ["six"]);

        // Below the number counted from, 100: the clearing of 20, then
        // message 20; and message 21, handed twice.
        let s = Several::of_one_person(2);
        assert_eq!(given(&s, 1, &hundred_of(&s)), STORED);
        assert_eq!(given(&s, 1, &clearing(&s, 0, 20)), STORED);
        let twenty = sent(&s, 0, 20, &says("twenty", s.now));
        assert_eq!(
            not_stored(&given(&s, 1, &twenty)),
            Some(Outcome::OlderThanHeld)
        );
        assert_eq!(signer_on(&s, 1, 0).overwritten, 0);
        let twenty_one = sent(&s, 0, 21, &says("twenty-one", s.now));
        assert_eq!(given(&s, 1, &twenty_one), STORED);
        assert_eq!(signer_on(&s, 1, 0).overwritten, 1);
        let before = s[1].everything();
        assert_eq!(
            not_stored(&given(&s, 1, &twenty_one)),
            Some(Outcome::AlreadyHeld)
        );
        assert_eq!(s[1].everything(), before);
        assert_eq!(signer_on(&s, 1, 0).overwritten, 1);
        assert_eq!(indexed(&s, 1), ["100"]);
        assert_eq!(shown_on(&s, 1, s.now), ["100"]);
    }

    /// Message 100 of device 0, saying so.
    fn hundred_of(s: &Several) -> CheckedEntry {
        sent(s, 0, 100, &says("100", s.now))
    }

    /// A number whose clearing alone a reader holds is gone, and is never
    /// counted as overwritten (decision 2026-10-09 §2.5): a reader that
    /// comes after its sender cleared numbers 1 to 63 holds their
    /// clearings, then message 128; of the 64 numbers that leave the live
    /// numbers, only 64, which it never held, is counted. A message
    /// handed at a number held as a clearing is not shown.
    #[test]
    fn a_number_held_as_a_clearing_is_gone_and_not_overwritten() {
        let s = Several::of_one_person(2);
        for number in 1..=63 {
            assert_eq!(given(&s, 1, &clearing(&s, 0, number)), STORED);
        }
        let held: Vec<u64> = (1..=63).collect();
        assert_eq!(numbers(&s, 1, 0, "message_first_held"), held);
        assert_eq!(signer_on(&s, 1, 0).highest, 63);
        // The store lost the clearing of 63, as one restored from before
        // it is: message 63, handed then, is not shown.
        let channel = derive::channel_id(&messages(&s, 1)).unwrap();
        let slot = slot_id(
            &derive::slot_key(&messages(&s, 1)).unwrap(),
            &message_name(&s.key(0), 63).unwrap(),
        );
        s[1].conn
            .execute(
                "DELETE FROM entries WHERE channel_id = ?1 AND slot = ?2",
                [&channel[..], &slot[..]],
            )
            .unwrap();
        let again = sent(&s, 0, 63, &says("sixty-three", s.now));
        assert_eq!(given(&s, 1, &again), STORED);
        assert!(indexed(&s, 1).is_empty());

        let last = sent(&s, 0, 128, &says("128", s.now));
        assert_eq!(given(&s, 1, &last), STORED);
        let kept = signer_on(&s, 1, 0);
        assert_eq!((kept.highest, kept.overwritten), (128, 1));
        assert_eq!(shown_on(&s, 1, s.now), ["128"]);
    }

    /// One number is counted once, however many of its entries are
    /// handed (decision 2026-10-09 §2.5): a reader that holds number 100
    /// is handed message 20 and then the clearing of 20, and counts 1. A
    /// clearing alone at a number that is not live counts nothing.
    #[test]
    fn a_number_is_counted_once_however_many_of_its_entries_are_handed() {
        let s = Several::of_one_person(2);
        assert_eq!(given(&s, 1, &hundred_of(&s)), STORED);
        assert_eq!(signer_on(&s, 1, 0).overwritten, 0);
        let twenty = sent(&s, 0, 20, &says("twenty", s.now));
        assert_eq!(given(&s, 1, &twenty), STORED);
        assert_eq!(signer_on(&s, 1, 0).overwritten, 1);
        assert_eq!(given(&s, 1, &clearing(&s, 0, 20)), STORED);
        assert_eq!(signer_on(&s, 1, 0).overwritten, 1);
        assert_eq!(given(&s, 1, &clearing(&s, 0, 30)), STORED);
        assert_eq!(signer_on(&s, 1, 0).overwritten, 1);
        assert_eq!(indexed(&s, 1), ["100"]);
    }

    /// The generations device `n` holds rows of, in `table`.
    fn generations_in(s: &Several, n: usize, table: &str) -> Vec<i64> {
        s[n].conn
            .prepare(&format!(
                "SELECT DISTINCT {column} FROM {table} ORDER BY {column}",
                column = if table == "message_generations" {
                    "id"
                } else {
                    "generation"
                }
            ))
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// Device 1 applies a renewal that device 0 makes.
    fn renewed(s: &mut Several) {
        let renewal = s.change(0, &[0, 1], &[]);
        let now = s.tick();
        take(&s[1].conn, &s[1].identity, &renewal, now).unwrap();
    }

    /// A message is of its generation (decision 2026-10-09 §7.1, §9.2): a
    /// holder of a key that writes the value of a message from before the
    /// last change again in the new generation does not attach it to the
    /// old generation's row. That row stays the old generation's, held at
    /// its own numbers only, and is shown once; the new generation holds
    /// no number of it and gives it no place.
    #[test]
    fn a_message_written_again_in_a_new_generation_is_not_the_old_ones() {
        let mut s = Several::of_one_person(2);
        let message = says("from before", s.now);
        assert_eq!(given(&s, 1, &sent(&s, 0, 1, &message)), STORED);
        assert_eq!(shown_on(&s, 1, s.now), ["from before"]);
        let old = generation(&s, 1);
        renewed(&mut s);

        let again = sent(&s, 0, 1, &message);
        assert_eq!(given(&s, 1, &again), STORED);
        let new = generation(&s, 1);
        assert_ne!(new, old);
        assert_eq!(generations_in(&s, 1, "message_index"), [old]);
        assert_eq!(generations_in(&s, 1, "message_numbers"), [old]);
        assert_eq!(generations_in(&s, 1, "message_first_held"), [old, new]);
        let later = s.now + HOUR;
        assert_eq!(held_back(&s, 1, 0, later), 0);
        assert_eq!(shown_on(&s, 1, later), ["from before"]);
        let places: i64 = s[1]
            .conn
            .query_row(
                "SELECT COUNT(*) FROM message_places WHERE generation = ?1",
                [new],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(places, 0);
    }

    /// What is kept of a generation the device has left goes once none of
    /// its index rows is left (decision 2026-10-09 §7.1, §9.1): after a
    /// statement and 30 days, nothing of the old generation is in any
    /// table of messages, and the rows of first holding, the signers and
    /// the generation the device stands applied under are as they were,
    /// though its one message expired with the others. A day after the
    /// statement the old generation is all still there.
    #[test]
    fn a_generation_the_device_has_left_goes_once_its_rows_have() {
        let mut s = Several::of_one_person(2);
        let start = s.now;
        for number in 1..=3 {
            let entry = sent(&s, 0, number, &says(&format!("old {number}"), start));
            assert_eq!(given(&s, 1, &entry), STORED);
        }
        assert_eq!(shown_on(&s, 1, start).len(), 3);
        let old = generation(&s, 1);
        renewed(&mut s);
        let entry = sent(&s, 0, 1, &says("new", start));
        assert_eq!(given_at(&s, 1, &entry, start), STORED);
        assert_eq!(shown_on(&s, 1, start).len(), 4);
        let new = generation(&s, 1);
        let tables = [
            "message_generations",
            "message_index",
            "message_numbers",
            "message_first_held",
            "message_signers",
            "message_places",
            "message_kept",
        ];
        // The rows of the generation applied, of `table`, as text.
        let rows_of = |s: &Several, table: &str, columns: &str| -> Vec<String> {
            s[1].conn
                .prepare(&format!(
                    "SELECT {columns} FROM {table} WHERE generation = ?1 ORDER BY 1"
                ))
                .unwrap()
                .query_map([new], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        let signers = |s: &Several| {
            rows_of(
                s,
                "message_signers",
                "hex(signer) || ' ' || highest || ' ' || overwritten || ' ' || not_messages
                 || ' ' || IFNULL(counted_from, '-')",
            )
        };
        let firsts = |s: &Several| {
            rows_of(
                s,
                "message_first_held",
                "number || ' ' || IFNULL(hex(id), '-') || ' ' || IFNULL(sent, '-') || ' '
                 || first_held",
            )
        };
        let (signers_before, firsts_before) = (signers(&s), firsts(&s));
        assert_eq!(firsts_before.len(), 1);

        hourly(&s[1].conn, &s[1].identity, start + DAY, true).unwrap();
        assert_eq!(generations_in(&s, 1, "message_generations"), [old, new]);
        assert_eq!(generations_in(&s, 1, "message_first_held"), [old, new]);

        let task = hourly(&s[1].conn, &s[1].identity, start + 30 * DAY, true).unwrap();
        assert_eq!(task.gone.expired, 4);
        for table in tables {
            assert!(
                !generations_in(&s, 1, table).contains(&old),
                "{table} holds the old generation"
            );
        }
        assert_eq!(generations_in(&s, 1, "message_generations"), [new]);
        assert_eq!(signers(&s), signers_before);
        assert_eq!(firsts(&s), firsts_before);
        assert_eq!(generations_in(&s, 1, "message_signers"), [new]);
    }
}
