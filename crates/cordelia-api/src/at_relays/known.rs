//! What a device knows of which relay holds which change (decision
//! 2026-10-19 §1, rule 2), kept across starts in one key of `node_meta`
//! (`person.relays_known`).
//!
//! **For each relay**, by its name and the key its configuration gives it
//! together, as the record of relays finds a relay (decision 2026-10-17
//! §1):
//!
//! - **the latest answer** that it gave to a show of the change entry
//!   that the device kept, of the two kinds that say something: that it
//!   holds the entry ("held", "took"), or that it does not ("no room",
//!   "over the allowance", "another"). The entry's ID, which of the two,
//!   the key that gave it and the time of day. Each such answer writes
//!   over the one before ([`note_answer`]); an answer that says neither
//!   writes nothing;
//! - **its mark**: an entry's ID, written at three moments only, for a
//!   relay of which the device has no latest answer ([`mark`]): where this
//!   device takes a hand-over, where `cordelia phrase` makes statement 1
//!   on it, and at the first start of this version where the kept
//!   statement is statement 1 ([`started`]).
//!
//! **And two times**: when the kept change entry came to be kept, written
//! when the key first sees an entry ID other than the one it holds
//! ([`note_kept`]), and when this version first started on this database.
//!
//! **Whether a relay holds the change** is a plain function of what is
//! kept ([`holds`]). The key goes when the device leaves its phrase
//! (`crate::adding::leave`), and what is kept of a relay goes when the
//! device is no longer set up with it ([`started`]).
//!
//! A value that cannot be read is read as nothing known: every relay then
//! lacks the change until it answers, which errs the safe way.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use cordelia_storage::meta;
use cordelia_storage::person::{self as held_rows, Kept};

use crate::person::{PersonError, in_one};
use crate::state::Holds;

/// A relay that the device is set up with: the name its configuration
/// gives it, and the key, where it gives one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RelayId {
    pub name: String,
    #[serde(with = "hex_key")]
    pub key: Option<[u8; 32]>,
}

/// A relay's latest answer to a show of a change entry that said whether
/// it holds the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    /// The entry that was shown, by its ID.
    #[serde(with = "hex_id")]
    pub entry: [u8; 32],
    /// Whether the answer says that the relay holds it.
    pub holds: bool,
    /// The key that gave the answer: the relay's node key on that
    /// connection.
    #[serde(with = "hex_id")]
    pub by: [u8; 32],
    /// When, by the time of day, in seconds.
    pub at: i64,
}

/// What is kept of one relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfRelay {
    pub relay: RelayId,
    pub answer: Option<Answer>,
    #[serde(with = "hex_mark")]
    pub mark: Option<[u8; 32]>,
}

/// When the kept change entry came to be kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeptSince {
    #[serde(with = "hex_id")]
    pub entry: [u8; 32],
    /// By the time of day, in seconds.
    pub since: i64,
}

/// Everything the key holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Known {
    /// When this version first started on this database, by the time of
    /// day, in seconds.
    pub first_started: Option<i64>,
    pub kept: Option<KeptSince>,
    pub relays: Vec<OfRelay>,
}

impl Known {
    /// What is kept of `relay`, where anything is.
    pub fn of(&self, relay: &RelayId) -> Option<&OfRelay> {
        self.relays.iter().find(|of| of.relay == *relay)
    }

    fn of_mut(&mut self, relay: &RelayId) -> &mut OfRelay {
        let at = match self.relays.iter().position(|of| of.relay == *relay) {
            Some(at) => at,
            None => {
                self.relays.push(OfRelay {
                    relay: relay.clone(),
                    answer: None,
                    mark: None,
                });
                self.relays.len() - 1
            }
        };
        &mut self.relays[at]
    }

    /// When the kept entry came to be kept, where it is `kept`: written
    /// when the key first sees another entry than the one it holds.
    /// Returns whether it changed.
    fn keeps(&mut self, kept: Option<[u8; 32]>, now: i64) -> bool {
        let held = self.kept.map(|kept| kept.entry);
        match kept {
            Some(entry) if held != Some(entry) => {
                self.kept = Some(KeptSince { entry, since: now });
                true
            }
            _ => false,
        }
    }
}

/// Whether `of`, what is kept of a relay, says that it holds `kept`, the
/// change entry that the device keeps now (decision 2026-10-19 §1).
/// `connected_by` is the key of the open connection to the relay, where
/// there is one.
///
/// - **It holds the change** where its latest answer is about the kept
///   entry and says that it holds it; and, for a relay given no key in
///   the configuration, only while the device is connected to it with the
///   key that gave that answer: out of reach, its name may name another
///   host, which has never seen the change.
/// - **It neither holds nor lacks it** where it has no latest answer and
///   its mark is the kept entry: the third state, which nothing acts on.
/// - **It lacks the change** otherwise: no answer and no mark, an answer
///   or a mark about another entry, an answer that says it does not hold
///   it, or a relay given no key that is not connected with the key that
///   answered. With no kept entry, nothing is held.
pub fn holds(
    of: Option<&OfRelay>,
    kept: Option<[u8; 32]>,
    connected_by: Option<[u8; 32]>,
) -> Holds {
    let Some(kept) = kept else {
        return Holds::Lacks;
    };
    let Some(of) = of else {
        return Holds::Lacks;
    };
    match of.answer {
        Some(answer) => {
            let by_its_key = of.relay.key.is_some() || connected_by == Some(answer.by);
            match answer.entry == kept && answer.holds && by_its_key {
                true => Holds::Holds,
                false => Holds::Lacks,
            }
        }
        None if of.mark == Some(kept) => Holds::Neither,
        None => Holds::Lacks,
    }
}

/// What the key holds now. A value that cannot be read is nothing known.
pub fn read(conn: &Connection) -> Result<Known, PersonError> {
    let Some(value) = meta::get(conn, meta::PERSON_RELAYS_KNOWN)? else {
        return Ok(Known::default());
    };
    Ok(serde_json::from_str(&value).unwrap_or_default())
}

fn write(conn: &Connection, known: &Known) -> Result<(), PersonError> {
    let value = serde_json::to_string(known)
        .map_err(|e| PersonError::Held(format!("what is known of the relays: {e}")))?;
    meta::set(conn, meta::PERSON_RELAYS_KNOWN, &value)?;
    Ok(())
}

/// What the latest change entry that this device keeps is named by, and
/// the number of its statement: a change entry's revision is its
/// statement's number.
fn kept_entry(conn: &Connection) -> Result<Option<([u8; 32], u64)>, PersonError> {
    let entry = held_rows::change_entry(conn, Kept::Latest)?;
    Ok(entry.map(|entry| (entry.id(), entry.rev)))
}

/// Note the answer of `relay`, through the connection whose key is `by`,
/// to a show of the entry named `entry`: whether it says that the relay
/// holds it (decision 2026-10-19 §1, rule 2). It writes over the answer
/// before, in one transaction, so that a relay that held the entry and
/// then answers "no room" about it no longer holds it. An answer that
/// repeats what is kept writes nothing. Returns whether it wrote.
pub fn note_answer(
    conn: &Connection,
    relay: &RelayId,
    entry: &[u8; 32],
    holds: bool,
    by: &[u8; 32],
    now: i64,
) -> Result<bool, PersonError> {
    in_one(conn, || {
        let mut known = read(conn)?;
        let kept = kept_entry(conn)?.map(|(id, _)| id);
        let mut changed = known.keeps(kept, now);
        let of = known.of_mut(relay);
        let same = of
            .answer
            .is_some_and(|was| was.entry == *entry && was.holds == holds && was.by == *by);
        if !same {
            of.answer = Some(Answer {
                entry: *entry,
                holds,
                by: *by,
                at: now,
            });
            changed = true;
        }
        if changed {
            write(conn, &known)?;
        }
        Ok(!same)
    })
}

/// Note when the kept change entry came to be kept, where the key holds
/// another: written when it first sees an entry ID other than the one it
/// holds. Returns whether it wrote. A pass asks at each turn: where
/// nothing changed, nothing is written, and no transaction is opened.
pub fn note_kept(conn: &Connection, now: i64) -> Result<bool, PersonError> {
    let kept = kept_entry(conn)?.map(|(id, _)| id);
    let held = read(conn)?.kept.map(|kept| kept.entry);
    if kept.is_none() || kept == held {
        return Ok(false);
    }
    in_one(conn, || {
        let mut known = read(conn)?;
        let kept = kept_entry(conn)?.map(|(id, _)| id);
        let changed = known.keeps(kept, now);
        if changed {
            write(conn, &known)?;
        }
        Ok(changed)
    })
}

/// Mark the kept change entry for each of `relays`, the relays that the
/// device is set up with, of which it has no latest answer (decision
/// 2026-10-19 §1): at a hand-over taken, and at `cordelia phrase`, in the
/// caller's transaction. A relay with an answer keeps its answer, and no
/// mark is written over it. Nothing is marked where the device keeps no
/// change entry.
pub fn mark(conn: &Connection, relays: &[RelayId], now: i64) -> Result<(), PersonError> {
    in_one(conn, || {
        let Some((entry, _)) = kept_entry(conn)? else {
            return Ok(());
        };
        let mut known = read(conn)?;
        known.keeps(Some(entry), now);
        // A key written afresh after the device left its phrase is
        // written by this version, which runs now.
        known.first_started.get_or_insert(now);
        for relay in relays {
            let of = known.of_mut(relay);
            if of.answer.is_none() {
                of.mark = Some(entry);
            }
        }
        write(conn, &known)
    })
}

/// What [`started`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Started {
    /// Whether this is the first start of this version on this database:
    /// the key was not there.
    pub first: bool,
    /// Whether the relays were marked: at a first start where the kept
    /// statement is statement 1.
    pub marked: bool,
}

/// The node has started with `relays`, the relays that the device is set
/// up with (decision 2026-10-19 §1, rule 2), in one transaction:
///
/// - **At the first start of this version on this database** (the key is
///   not there) the time is kept, and where the kept change entry is of
///   statement 1, it is each relay's mark: statement 1 removes no key and
///   renews nothing, so a relay that lacks it puts nobody in reach of a
///   removed device. Under any later statement nothing is marked: the
///   device knows nothing of what its relays got before.
/// - **What is kept of a relay that the device is no longer set up with
///   is forgotten.**
/// - When the kept entry came to be kept is noted.
pub fn started(conn: &Connection, relays: &[RelayId], now: i64) -> Result<Started, PersonError> {
    in_one(conn, || {
        let first = meta::get(conn, meta::PERSON_RELAYS_KNOWN)?.is_none();
        let mut known = read(conn)?;
        let kept = kept_entry(conn)?;
        known.keeps(kept.map(|(id, _)| id), now);
        known.relays.retain(|of| relays.contains(&of.relay));
        let mut marked = false;
        if first {
            known.first_started = Some(now);
            if let Some((entry, 1)) = kept {
                for relay in relays {
                    known.of_mut(relay).mark = Some(entry);
                }
                marked = true;
            }
        }
        write(conn, &known)?;
        Ok(Started { first, marked })
    })
}

/// A key in hex, or null.
mod hex_key {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(key: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match key {
            Some(key) => s.serialize_some(&hex::encode(key)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let text: Option<String> = Option::deserialize(d)?;
        text.map(|text| super::hex_id::from_text(&text))
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}

/// An entry's ID, or null.
mod hex_mark {
    pub use super::hex_key::{deserialize, serialize};
}

/// An entry's ID, or a key, in hex.
mod hex_id {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(id: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(id))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        from_text(&text).map_err(serde::de::Error::custom)
    }

    pub fn from_text(text: &str) -> Result<[u8; 32], String> {
        let bytes = hex::decode(text).map_err(|e| e.to_string())?;
        bytes.try_into().map_err(|_| "not 32 bytes".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adding::{Accepted, Row, accept_typed, type_key};
    use crate::leaving::{self, among, start_again};
    use crate::person::first_entry;
    use crate::several::{OTHER_WORDS, Several};
    use cordelia_crypto::phrase::Phrase;
    use cordelia_storage::acts;

    const BY: [u8; 32] = [7; 32];
    const OTHER_KEY: [u8; 32] = [8; 32];

    fn relay(name: &str, key: Option<[u8; 32]>) -> RelayId {
        RelayId {
            name: name.into(),
            key,
        }
    }

    /// The laptop's two relays: one given a key, and one given none.
    fn relays() -> Vec<RelayId> {
        vec![
            relay("a.example:9474", Some(BY)),
            relay("b.example:9474", None),
        ]
    }

    /// Whether `relay` holds the change the device on `conn` keeps, as
    /// what is stored says, connected with `connected_by`.
    fn holds_now(conn: &Connection, relay: &RelayId, connected_by: Option<[u8; 32]>) -> Holds {
        let known = read(conn).unwrap();
        let kept = kept_entry(conn).unwrap().map(|(id, _)| id);
        holds(known.of(relay), kept, connected_by)
    }

    /// The latest answer writes over the one before (decision 2026-10-19
    /// §1): "held" then "no room" about one entry is "lacks", as is any
    /// answer that says the relay does not hold it ("over the
    /// allowance", "another"); and "no room" then "took" is "holds". An
    /// answer that repeats what is kept writes nothing.
    #[test]
    fn the_latest_answer_writes_over_the_one_before() {
        let mut s = Several::new(1);
        s.make_phrase(0);
        let conn = &s[0].conn;
        let kept = s[0].latest().id();
        let a = relay("a.example:9474", Some(BY));
        let now = START_OF_TEST;
        assert_eq!(holds_now(conn, &a, None), Holds::Lacks);
        assert!(note_answer(conn, &a, &kept, true, &BY, now).unwrap());
        assert_eq!(holds_now(conn, &a, None), Holds::Holds);
        // "no room", "over the allowance" and "another" all say that it
        // does not hold it.
        for _ in ["no room", "over the allowance", "another"] {
            note_answer(conn, &a, &kept, false, &BY, now + 1).unwrap();
            assert_eq!(holds_now(conn, &a, None), Holds::Lacks);
            note_answer(conn, &a, &kept, true, &BY, now + 2).unwrap();
            assert_eq!(holds_now(conn, &a, None), Holds::Holds);
        }
        // The same answer again writes nothing, and keeps its time.
        assert!(!note_answer(conn, &a, &kept, true, &BY, now + 9).unwrap());
        assert_eq!(
            read(conn).unwrap().of(&a).unwrap().answer.unwrap().at,
            now + 2
        );
        // An answer about another entry than the kept one is "lacks".
        note_answer(conn, &a, &[3; 32], true, &BY, now + 10).unwrap();
        assert_eq!(holds_now(conn, &a, None), Holds::Lacks);
    }

    const START_OF_TEST: i64 = 1_800_000_100;

    /// What is kept is in the database, and so across a restart; it is
    /// kept by the relay's name and key together; and what is kept of a
    /// relay that the device is set up with no longer is forgotten at the
    /// next start (decision 2026-10-19 §1, rule 2).
    #[test]
    fn what_is_kept_survives_a_restart_and_goes_with_the_relay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.db");
        let a = relay("a.example:9474", Some(BY));
        let same_name = relay("a.example:9474", Some(OTHER_KEY));
        let kept = {
            let conn = cordelia_storage::db::open(&path).unwrap();
            let s = Several::new(1);
            let identity = &s[0].identity;
            let phrase = Phrase::parse(crate::several::WORDS).unwrap();
            crate::person::first_statement(&conn, identity, &phrase, "laptop", START_OF_TEST)
                .unwrap();
            let kept = kept_entry(&conn).unwrap().unwrap().0;
            started(&conn, &[a.clone(), same_name.clone()], START_OF_TEST).unwrap();
            note_answer(&conn, &a, &kept, true, &BY, START_OF_TEST + 1).unwrap();
            kept
        };
        // A restart: the database is opened again.
        let conn = cordelia_storage::db::open(&path).unwrap();
        let again = started(&conn, &[a.clone(), same_name.clone()], START_OF_TEST + 60).unwrap();
        assert!(!again.first, "the key was there: no first start");
        assert_eq!(holds_now(&conn, &a, None), Holds::Holds);
        // One name with another key is another relay.
        assert_eq!(holds_now(&conn, &same_name, None), Holds::Neither);
        let known = read(&conn).unwrap();
        assert_eq!(known.of(&a).unwrap().answer.unwrap().entry, kept);
        // Set up with it no longer: forgotten at the next start.
        started(&conn, std::slice::from_ref(&same_name), START_OF_TEST + 120).unwrap();
        assert_eq!(read(&conn).unwrap().of(&a), None);
        assert_eq!(holds_now(&conn, &a, None), Holds::Lacks);
    }

    /// Wherever the device stops following its phrase, all of it goes
    /// (decision 2026-10-19 §1): the key is among what `adding::leave`
    /// removes, and `cordelia init --new-key`, a removal of this device
    /// followed by it, and `cordelia phrase` on a device of several each
    /// leave nothing of what was known; `cordelia phrase` then writes only
    /// its own mark.
    #[test]
    fn adding_leave_forgets_it() {
        let a = relay("a.example:9474", Some(BY));
        let answered = |s: &Several, n: usize| {
            let kept = s[n].latest().id();
            note_answer(&s[n].conn, &a, &kept, true, &BY, START_OF_TEST).unwrap();
            assert!(
                meta::get(&s[n].conn, meta::PERSON_RELAYS_KNOWN)
                    .unwrap()
                    .is_some()
            );
        };

        // `cordelia init --new-key`.
        let mut s = Several::of_one_person(3);
        answered(&s, 1);
        let now = s.tick();
        assert!(leaving::forget(&s[1].conn, &s[1].identity, false, now).unwrap());
        assert_eq!(
            meta::get(&s[1].conn, meta::PERSON_RELAYS_KNOWN).unwrap(),
            None
        );

        // A removal of this device, and then `init --new-key`.
        answered(&s, 2);
        s.change(0, &[0], &[2]);
        s.pass(0, 2);
        assert_eq!(s[2].state(), cordelia_storage::person::State::Removed);
        let now = s.tick();
        assert!(leaving::forget(&s[2].conn, &s[2].identity, false, now).unwrap());
        assert_eq!(
            meta::get(&s[2].conn, meta::PERSON_RELAYS_KNOWN).unwrap(),
            None
        );

        // `cordelia phrase` on a device of several.
        let mut s = Several::of_one_person(2);
        answered(&s, 0);
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let made = first_entry(&other, &s.key(0), "device 0").unwrap();
        let now = s.tick();
        let on = &s[0];
        let shown = among(&on.conn, &on.identity).unwrap();
        assert!(matches!(shown, leaving::Among::Several(_)));
        let set_up = [a.clone()];
        start_again(
            &on.conn,
            &on.identity,
            shown,
            &made.entry,
            &made.statement_key,
            &set_up,
            now,
        )
        .unwrap();
        let known = read(&on.conn).unwrap();
        let of = known.of(&a).unwrap();
        assert_eq!(
            of.answer, None,
            "the answer about the phrase it left is gone"
        );
        assert_eq!(of.mark, Some(made.entry.id()));
    }

    /// The mark is written at three moments, and at no other (decision
    /// 2026-10-19 §1): where a hand-over is taken (the handed entry, for
    /// each relay with no answer), at `cordelia phrase`, and at the first
    /// start under statement 1. None at a first start under a later
    /// statement, none for a relay set up later, none after a change.
    #[test]
    fn the_mark_is_written_only_at_its_three_moments() {
        let (a, b) = (
            relay("a.example:9474", Some(BY)),
            relay("b.example:9474", None),
        );
        // A hand-over taken: the handed entry is the mark of each relay
        // with no answer, and not of one with an answer.
        let mut s = Several::new(2);
        s.make_phrase(0);
        let added = s.hand(0, 1);
        let now = s.tick();
        let on = &s[1];
        note_answer(&on.conn, &b, &[9; 32], false, &BY, now).unwrap();
        type_key(&on.conn, &on.identity, &s.key(0), Row::NoPhrase, false, now).unwrap();
        let typed = acts::typed_key(&on.conn, &s.key(0)).unwrap().unwrap();
        let set_up = [a.clone(), b.clone()];
        let given = accept_typed(
            &on.conn,
            &on.identity,
            &typed,
            false,
            &added.hand_over,
            &set_up,
            now,
        )
        .unwrap();
        assert!(matches!(given, Some(Accepted::Joined(_))), "{given:?}");
        let handed = s[1].latest().id();
        let known = read(&s[1].conn).unwrap();
        assert_eq!(known.of(&a).unwrap().mark, Some(handed));
        assert_eq!(known.of(&b).unwrap().mark, None, "b has an answer");
        assert_eq!(holds_now(&s[1].conn, &a, None), Holds::Neither);

        // A hand-over refused writes no mark.
        let mut s = Several::new(3);
        s.make_phrase(0);
        let added = s.hand(0, 1);
        let now = s.tick();
        let on = &s[2];
        type_key(&on.conn, &on.identity, &s.key(0), Row::NoPhrase, false, now).unwrap();
        let typed = acts::typed_key(&on.conn, &s.key(0)).unwrap().unwrap();
        let given = accept_typed(
            &on.conn,
            &on.identity,
            &typed,
            false,
            &added.hand_over,
            &set_up,
            now,
        )
        .unwrap();
        assert!(matches!(given, Some(Accepted::Refused(_))), "{given:?}");
        assert_eq!(
            meta::get(&s[2].conn, meta::PERSON_RELAYS_KNOWN).unwrap(),
            None
        );
        // Nor where the device keeps a change entry: a hand-over to a
        // device that counts already brings nothing, and marks nothing.
        let mut s = Several::of_one_person(2);
        let added = s.hand(0, 1);
        let now = s.tick();
        let on = &s[1];
        type_key(&on.conn, &on.identity, &s.key(0), Row::Several, false, now).unwrap();
        let typed = acts::typed_key(&on.conn, &s.key(0)).unwrap().unwrap();
        let given = accept_typed(
            &on.conn,
            &on.identity,
            &typed,
            false,
            &added.hand_over,
            &set_up,
            now,
        )
        .unwrap();
        assert!(matches!(given, Some(Accepted::Refused(_))), "{given:?}");
        assert_eq!(holds_now(&s[1].conn, &a, None), Holds::Lacks);

        // A change since: the mark is of the entry before, and the relay
        // lacks the change. A relay set up later has no mark.
        let mut s = Several::of_one_person(2);
        started(&s[0].conn, std::slice::from_ref(&a), START_OF_TEST).unwrap();
        s.change(0, &[0, 1], &[]);
        started(&s[0].conn, &[a.clone(), b.clone()], START_OF_TEST + 9).unwrap();
        let known = read(&s[0].conn).unwrap();
        assert_ne!(known.of(&a).unwrap().mark, Some(s[0].latest().id()));
        assert_eq!(known.of(&b), None);
        assert_eq!(holds_now(&s[0].conn, &a, None), Holds::Lacks);
        assert_eq!(holds_now(&s[0].conn, &b, None), Holds::Lacks);
    }

    /// At `cordelia phrase`, and at the first start of this version where
    /// the kept statement is statement 1, each relay is marked with the
    /// change entry of statement 1 (decision 2026-10-19 §1).
    #[test]
    fn the_mark_is_written_at_phrase_and_at_a_first_start_under_statement_1() {
        let set_up = relays();
        // `cordelia phrase` on a new install.
        let s = Several::new(1);
        let made = first_entry(&s.phrase, &s.key(0), "device 0").unwrap();
        let on = &s[0];
        let shown = among(&on.conn, &on.identity).unwrap();
        let key = &made.statement_key;
        start_again(
            &on.conn,
            &on.identity,
            shown,
            &made.entry,
            key,
            &set_up,
            START_OF_TEST,
        )
        .unwrap();
        for relay in &set_up {
            assert_eq!(
                holds_now(&on.conn, relay, None),
                Holds::Neither,
                "{relay:?}"
            );
        }
        assert_eq!(read(&on.conn).unwrap().first_started, Some(START_OF_TEST));
        // Its first start then is no first start: it marks nothing more.
        let again = started(&on.conn, &set_up, START_OF_TEST + 5).unwrap();
        assert_eq!(
            again,
            Started {
                first: false,
                marked: false
            }
        );

        // The first start of this version on a database under statement 1.
        let mut s = Several::new(1);
        s.make_phrase(0);
        assert_eq!(
            meta::get(&s[0].conn, meta::PERSON_RELAYS_KNOWN).unwrap(),
            None
        );
        let first = started(&s[0].conn, &set_up, START_OF_TEST).unwrap();
        assert_eq!(
            first,
            Started {
                first: true,
                marked: true
            }
        );
        for relay in &set_up {
            assert_eq!(
                holds_now(&s[0].conn, relay, None),
                Holds::Neither,
                "{relay:?}"
            );
        }
    }

    /// The case that was seen (decision 2026-10-19 §1): a removal made on
    /// alpha.12 that one relay never got, then the upgrade. The kept
    /// statement is not statement 1, so nothing is marked at the first
    /// start: the relay that answers holds the change after its answer,
    /// and the one that never answers lacks it.
    #[test]
    fn a_removal_made_on_alpha_12_leaves_a_relay_that_never_answers_lacking_after_the_upgrade() {
        // The database as alpha.12 left it: a removal applied, and no key.
        let mut s = Several::of_one_person(2);
        let removal = s.change(0, &[0], &[1]);
        assert_eq!(
            meta::get(&s[0].conn, meta::PERSON_RELAYS_KNOWN).unwrap(),
            None
        );
        let (a, b) = (
            relay("a.example:9474", Some(BY)),
            relay("b.example:9474", Some(OTHER_KEY)),
        );
        let first = started(&s[0].conn, &[a.clone(), b.clone()], START_OF_TEST).unwrap();
        assert_eq!(
            first,
            Started {
                first: true,
                marked: false
            }
        );
        assert_eq!(holds_now(&s[0].conn, &a, None), Holds::Lacks);
        assert_eq!(holds_now(&s[0].conn, &b, None), Holds::Lacks);
        note_answer(&s[0].conn, &a, &removal.id(), true, &BY, START_OF_TEST + 1).unwrap();
        assert_eq!(holds_now(&s[0].conn, &a, None), Holds::Holds);
        assert_eq!(holds_now(&s[0].conn, &b, None), Holds::Lacks);
    }

    /// A relay with no answer whose mark is the kept entry neither holds
    /// nor lacks the change (decision 2026-10-19 §1); its first answer
    /// takes the mark's place, and once the kept entry is another it
    /// lacks the change.
    #[test]
    fn a_relay_in_the_third_state_neither_holds_nor_lacks() {
        let mut s = Several::of_one_person(2);
        let a = relay("a.example:9474", Some(BY));
        mark(&s[0].conn, std::slice::from_ref(&a), START_OF_TEST).unwrap();
        assert_eq!(holds_now(&s[0].conn, &a, None), Holds::Neither);
        // An answer takes the mark's place.
        let kept = s[0].latest().id();
        note_answer(&s[0].conn, &a, &kept, false, &BY, START_OF_TEST + 1).unwrap();
        assert_eq!(holds_now(&s[0].conn, &a, None), Holds::Lacks);
        // With no answer, a mark of another entry is "lacks".
        let b = relay("b.example:9474", None);
        mark(&s[0].conn, std::slice::from_ref(&b), START_OF_TEST + 2).unwrap();
        assert_eq!(holds_now(&s[0].conn, &b, None), Holds::Neither);
        s.change(0, &[0, 1], &[]);
        assert_eq!(holds_now(&s[0].conn, &b, None), Holds::Lacks);
    }

    /// A relay given no key holds the change only while the device is
    /// connected to it with the key that gave the answer (decision
    /// 2026-10-19 §1): out of reach, its name may name another host. A
    /// relay given a key holds it connected or not.
    #[test]
    fn a_relay_given_no_key_holds_only_while_connected_to_the_key_that_answered() {
        let mut s = Several::new(1);
        s.make_phrase(0);
        let conn = &s[0].conn;
        let kept = s[0].latest().id();
        let (keyed, keyless) = (
            relay("a.example:9474", Some(BY)),
            relay("b.example:9474", None),
        );
        note_answer(conn, &keyed, &kept, true, &BY, START_OF_TEST).unwrap();
        note_answer(conn, &keyless, &kept, true, &BY, START_OF_TEST).unwrap();
        assert_eq!(holds_now(conn, &keyed, None), Holds::Holds);
        assert_eq!(holds_now(conn, &keyless, Some(BY)), Holds::Holds);
        assert_eq!(holds_now(conn, &keyless, None), Holds::Lacks);
        assert_eq!(holds_now(conn, &keyless, Some(OTHER_KEY)), Holds::Lacks);
        // Another key answers there: it lacks the change until that key
        // says it holds it.
        note_answer(conn, &keyless, &kept, true, &OTHER_KEY, START_OF_TEST + 1).unwrap();
        assert_eq!(holds_now(conn, &keyless, Some(OTHER_KEY)), Holds::Holds);
        assert_eq!(holds_now(conn, &keyless, Some(BY)), Holds::Lacks);
    }

    /// A value that cannot be read is read as nothing known (decision
    /// 2026-10-19 §1): every relay then lacks the change until it
    /// answers, which errs the safe way.
    #[test]
    fn a_value_that_cannot_be_read_is_nothing_known() {
        let mut s = Several::new(1);
        s.make_phrase(0);
        let a = relay("a.example:9474", Some(BY));
        mark(&s[0].conn, std::slice::from_ref(&a), START_OF_TEST).unwrap();
        assert_eq!(holds_now(&s[0].conn, &a, None), Holds::Neither);
        meta::set(&s[0].conn, meta::PERSON_RELAYS_KNOWN, "{\"relays\": 7}").unwrap();
        assert_eq!(read(&s[0].conn).unwrap(), Known::default());
        assert_eq!(holds_now(&s[0].conn, &a, None), Holds::Lacks);
    }

    /// The two times (decision 2026-10-19 §1): when the kept entry came
    /// to be kept, written when the key first sees an entry other than the
    /// one it holds, and when this version first started on the database.
    #[test]
    fn the_two_times_are_kept() {
        let mut s = Several::of_one_person(2);
        let a = relay("a.example:9474", Some(BY));
        started(&s[0].conn, std::slice::from_ref(&a), START_OF_TEST).unwrap();
        let known = read(&s[0].conn).unwrap();
        assert_eq!(known.first_started, Some(START_OF_TEST));
        let first = s[0].latest().id();
        assert_eq!(
            known.kept,
            Some(KeptSince {
                entry: first,
                since: START_OF_TEST
            })
        );
        // The same entry: nothing is written.
        assert!(!note_kept(&s[0].conn, START_OF_TEST + 10).unwrap());
        // Another: when the key first sees it.
        s.change(0, &[0, 1], &[]);
        assert!(note_kept(&s[0].conn, START_OF_TEST + 20).unwrap());
        assert!(!note_kept(&s[0].conn, START_OF_TEST + 30).unwrap());
        let known = read(&s[0].conn).unwrap();
        let entry = s[0].latest().id();
        assert_eq!(
            known.kept,
            Some(KeptSince {
                entry,
                since: START_OF_TEST + 20
            })
        );
        // A later start does not move the first.
        started(&s[0].conn, std::slice::from_ref(&a), START_OF_TEST + 40).unwrap();
        assert_eq!(read(&s[0].conn).unwrap().first_started, Some(START_OF_TEST));
    }
}
