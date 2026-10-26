//! Making a change: the part that needs the phrase (decision 2026-10-04
//! §4.5, §7.1, §7.2).
//!
//! A statement is signed where the phrase is: in the process of the
//! command that was given it, never in the node (§5). [`make_change`] and
//! [`make_settlement`] are that part, as plain functions of what the
//! command was handed and what the person answered. Each makes a new
//! secret, the statement, the part of the change entry that is for the
//! phrase, and the change entry, and gives back the entry: the statement
//! is in it, the secret is sealed in it to each device it lists, and its
//! number is the entry's revision.
//!
//! **A command signs what it has shown** (§5). So each is in two steps. A
//! change is prepared with no phrase ([`prepare_change`],
//! [`prepare_settlement`]): the new secret, and the statement in the
//! bytes that will be signed ([`Prepared::bytes`]). The command shows the
//! statement's lists from those bytes, asks its yes, and only then asks
//! for the phrase and signs ([`Prepared::sign`]): those very bytes, and
//! nothing that was made since.
//!
//! The node's half is what a device does with a change entry of a
//! statement that it can apply ([`crate::person::apply`]): the device
//! that made the change is among its devices, opens the secret sealed to
//! it, and applies.
//!
//! Nothing here reads or writes a database, and nothing here keeps the
//! words: the phrase is the caller's, for as long as it signs and seals.

use cordelia_crypto::change_entry::{self, ForPhrase};
use cordelia_crypto::derive;
use cordelia_crypto::entry::CheckedEntry;
use cordelia_crypto::phrase::Phrase;
use cordelia_crypto::statement::{self, Device, SignedStatement, Statement, StatementError};
use zeroize::{Zeroize, Zeroizing};

use crate::person::PersonError;

/// A change that is prepared, and not signed: the statement in the bytes
/// that the phrase will sign, and the new secret that it commits to.
///
/// It is made with no phrase. What a command shows a person before its
/// yes, it reads from [`Prepared::bytes`], and what [`Prepared::sign`]
/// signs is those bytes.
pub struct Prepared {
    /// The statement the change is made after: the one the device has
    /// applied.
    applied: SignedStatement,
    /// The heads set aside that the change joins with it, where it is a
    /// settlement (decision 2026-10-24 (removal), rule 21), in the order
    /// they were given: their entries are given to [`Prepared::sign`] in
    /// that order.
    joined: Vec<SignedStatement>,
    /// The statement that will be signed, in its canonical form.
    bytes: Vec<u8>,
    /// The new secret. It is overwritten when this is dropped.
    secret: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The secret is not printed.
        f.debug_struct("Prepared")
            .field("statement", &hex::encode(&self.bytes))
            .finish_non_exhaustive()
    }
}

impl Prepared {
    /// The bytes that the phrase will sign: the statement, in its
    /// canonical form. A command reads what it shows from these
    /// ([`Statement::from_bytes`]).
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Sign the statement with the phrase, seal the part of its change
    /// entry that is for the phrase, and sign the entry (decision
    /// 2026-10-04 §5). `held` is the change entry of the statement the
    /// device has applied, and `joined` the entries of the heads set aside
    /// that the change joins, in the order they were prepared: the phrase
    /// opens the secrets before from them. **The part for the phrase holds
    /// the secret of every branch joined, as many as fit, the newest
    /// first** (decision 2026-10-24 (removal), rule 21;
    /// [`ForPhrase::following`]).
    ///
    /// What is signed is the statement in [`Prepared::bytes`], read again
    /// from those bytes.
    ///
    /// Refused: a statement or an entry that is not this phrase's; an
    /// entry that is not its statement's, a head's among them; and more or
    /// fewer entries of heads than heads prepared.
    pub fn sign(
        self,
        phrase: &Phrase,
        held: &CheckedEntry,
        joined: &[&CheckedEntry],
    ) -> Result<CheckedEntry, PersonError> {
        let one = applied_with(phrase, &self.applied, held)?;
        if joined.len() != self.joined.len() {
            return Err(PersonError::NotTheStatementsEntry);
        }
        let mut opened_heads = Vec::with_capacity(joined.len());
        for (shown, entry) in self.joined.iter().zip(joined) {
            let (statement, for_phrase) = opened(phrase, entry)?;
            if statement != *shown {
                return Err(PersonError::NotTheStatementsEntry);
            }
            opened_heads.push((statement.statement.number, for_phrase));
        }
        let mut before = vec![(self.applied.statement.number, &one)];
        before.extend(opened_heads.iter().map(|(number, said)| (*number, said)));
        let mut for_phrase = ForPhrase::following(*self.secret, &before);
        let entry = entry_of(phrase, Statement::from_bytes(&self.bytes)?, &for_phrase);
        // The secrets that the phrase opened, and the new one, are
        // overwritten here: they are in the entry, sealed.
        for_phrase.secret.zeroize();
        for earlier in &mut for_phrase.earlier {
            earlier.secret.zeroize();
        }
        entry
    }
}

/// Prepare the change that follows the statement `applied` (decision
/// 2026-10-04 §4.5, §7.1), with no phrase: a new secret, and the next
/// statement in the bytes that will be signed. `maker`, `stay` and
/// `removed` are as [`make_change`] takes them, and what it refuses of
/// them is refused here.
pub fn prepare_change(
    applied: &SignedStatement,
    maker: &[u8; 32],
    stay: Vec<Device>,
    removed: &[[u8; 32]],
) -> Result<Prepared, PersonError> {
    stays_among(maker, &stay)?;
    let leaves_out = |device: &Device| {
        !stay.iter().any(|stays| stays.key == device.key) && !removed.contains(&device.key)
    };
    if applied.statement.devices.iter().any(leaves_out) {
        return Err(PersonError::NeitherStaysNorRemoved);
    }
    let secret = Zeroizing::new(statement::new_secret()?);
    let next = applied.statement.next(*maker, &secret, stay, removed)?;
    Ok(Prepared {
        applied: applied.clone(),
        joined: Vec::new(),
        bytes: next.to_bytes()?,
        secret,
    })
}

/// Prepare the statement that joins `applied` with `joined`, the heads
/// set aside (decision 2026-10-04 §4.5; decision 2026-10-24 (removal),
/// rule 21: every head a device keeps, two or more in all), with no
/// phrase: a new secret, and the settlement in the bytes that will be
/// signed. `maker`, `stay` and `removed` are as [`make_settlement`] takes
/// them, and what it refuses of them is refused here.
pub fn prepare_settlement(
    applied: &SignedStatement,
    joined: &[SignedStatement],
    maker: &[u8; 32],
    stay: Vec<Device>,
    removed: &[[u8; 32]],
) -> Result<Prepared, PersonError> {
    let secret = Zeroizing::new(statement::new_secret()?);
    let heads: Vec<&Statement> = std::iter::once(&applied.statement)
        .chain(joined.iter().map(|head| &head.statement))
        .collect();
    let settled = Statement::settle(&heads, *maker, &secret, stay, removed)?;
    Ok(Prepared {
        applied: applied.clone(),
        joined: joined.to_vec(),
        bytes: settled.to_bytes()?,
        secret,
    })
}

/// Prepare the statement that a recovery makes (decision 2026-10-04 §9,
/// step 4), with no phrase: a new secret, and the statement after `from`,
/// the one that is recovered from, in the bytes that will be signed. It
/// lists `maker`, the machine that recovers, as its only device, and as
/// removed every key in `removed`: each device that the person said is
/// gone. **A device of `from` that is in neither is one the person still
/// has:** it is in no list, and is added again by hand, with its key
/// read from the device itself (§9, step 6).
///
/// Where `apart` is given, a statement that is not on the chain of
/// `from` was found beside it: the statement that is made settles the
/// two (§4.5). **It lists as removed every key that any change the
/// recovery read removes** (decision 2026-10-24 (removal), rule 22):
/// `read` is every change it read, `from` and `apart` among them, and
/// those on the chain of neither or behind. It lists one device, so its
/// secret is clear by construction.
///
/// Refused: whatever a statement refuses, a maker that a change read lists
/// as removed among it; and `read` without `from`, or without `apart`:
/// what a recovery read holds the change it recovers from.
pub fn prepare_recovery(
    from: &SignedStatement,
    apart: Option<&SignedStatement>,
    read: &[&Statement],
    maker: Device,
    removed: &[[u8; 32]],
) -> Result<Prepared, PersonError> {
    let among = |statement: &SignedStatement| read.contains(&&statement.statement);
    if !among(from) || apart.is_some_and(|apart| !among(apart)) {
        return Err(PersonError::NotAllRead);
    }
    let secret = Zeroizing::new(statement::new_secret()?);
    let key = maker.key;
    let mut removes = crate::recover::removed_by_any(read);
    removes.extend_from_slice(removed);
    let made = match apart {
        None => from.statement.next(key, &secret, vec![maker], &removes)?,
        Some(apart) => Statement::settle(
            &[&from.statement, &apart.statement],
            key,
            &secret,
            vec![maker],
            &removes,
        )?,
    };
    Ok(Prepared {
        applied: from.clone(),
        joined: apart.into_iter().cloned().collect(),
        bytes: made.to_bytes()?,
        secret,
    })
}

/// Make the change that follows the statement `applied` (decision
/// 2026-10-04 §4.5, §7.1): a removal, or a renewal where `removed` is
/// empty.
///
/// `held` is the change entry of `applied`, which the device keeps.
/// `maker` is the key of the device the change is made on. `stay` are the
/// devices that will hold the new secret: those of the statement, and
/// those added since that the person keeps. `removed` are the keys that
/// the person removes with it.
///
/// It makes a new secret; the next statement, numbered one above
/// `applied`, which lists as removed every key that `applied` does and
/// those given; the part for the phrase, with the secrets copied forward
/// from the entry held, which the phrase opens; and the change entry.
///
/// Refused:
///
/// - a statement or an entry that is not this phrase's, and an entry that
///   is not that statement's;
/// - a maker that would not be among the devices;
/// - a device of `applied` that is neither among those that stay nor
///   among the removed: a change leaves no device it knows in no list;
/// - whatever a statement refuses: a key in both lists, a removed key
///   brought back, a list over its bound, a number above 256.
pub fn make_change(
    phrase: &Phrase,
    applied: &SignedStatement,
    held: &CheckedEntry,
    maker: &[u8; 32],
    stay: Vec<Device>,
    removed: &[[u8; 32]],
) -> Result<CheckedEntry, PersonError> {
    applied_with(phrase, applied, held)?;
    prepare_change(applied, maker, stay, removed)?.sign(phrase, held, &[])
}

/// Make the statement that joins changes made apart (decision 2026-10-04
/// §4.5; decision 2026-10-24 (removal), rule 21).
///
/// `applied` is the statement the device has applied and `held` its
/// change entry. `joined` are the change entries the device keeps of the
/// heads it sets aside. `maker`, `stay` and `removed` are as
/// [`make_change`] takes them: the devices are chosen from those of every
/// head, and a device of any that is neither kept nor removed is in no
/// list.
///
/// The settlement is numbered above each, its chain holds each and their
/// chains, and it lists as removed every key that any does: it undoes
/// nothing. The part for the phrase holds the secret of every branch, each
/// opened from its entry with the phrase, as many as fit, the newest
/// first.
///
/// Refused: what [`make_change`] refuses of the statement and the
/// entries; a maker that would not be among the devices, as a statement
/// refuses it; no head given, or one given twice; and an entry of a head
/// whose statement the phrase's statement key does not read whole.
pub fn make_settlement(
    phrase: &Phrase,
    applied: &SignedStatement,
    held: &CheckedEntry,
    joined: &[&CheckedEntry],
    maker: &[u8; 32],
    stay: Vec<Device>,
    removed: &[[u8; 32]],
) -> Result<CheckedEntry, PersonError> {
    applied_with(phrase, applied, held)?;
    let mut statements = Vec::with_capacity(joined.len());
    for entry in joined {
        statements.push(opened(phrase, entry)?.0);
    }
    prepare_settlement(applied, &statements, maker, stay, removed)?.sign(phrase, held, joined)
}

/// The part for the phrase of `held`, where `held` is the change entry of
/// `applied` and both are this phrase's.
fn applied_with(
    phrase: &Phrase,
    applied: &SignedStatement,
    held: &CheckedEntry,
) -> Result<ForPhrase, PersonError> {
    if applied.statement.phrase_key != phrase.public_key()? {
        return Err(StatementError::AnotherPhrase.into());
    }
    applied.verify()?;
    let (carried, for_phrase) = opened(phrase, held)?;
    if carried != *applied {
        return Err(PersonError::NotTheStatementsEntry);
    }
    Ok(for_phrase)
}

/// A change entry of this phrase, opened with the phrase: its statement,
/// and its part for the phrase.
fn opened(
    phrase: &Phrase,
    entry: &CheckedEntry,
) -> Result<(SignedStatement, ForPhrase), PersonError> {
    let phrase_key = phrase.public_key()?;
    let channel = derive::channel_id(&*phrase.channel_secret()?)?;
    let statement =
        change_entry::open_statement(entry, &phrase_key, &channel, &*phrase.statement_key()?)?;
    let for_phrase =
        change_entry::open_for_phrase(entry, &phrase_key, &channel, &*phrase.seal_key()?)?;
    Ok((statement, for_phrase))
}

/// A change entry of this phrase, read with the phrase (decision
/// 2026-10-04 §4.6, §9): its statement, and its part for the phrase, which
/// holds the statement's secret and the secrets of the generations before
/// it, as many as eight, the newest first, each with its statement's
/// number. It is what a command reads that was typed the phrase: for a
/// carry from a generation whose secret the device never held (§7.3), and
/// for a recovery.
///
/// Refused: an entry that is not this phrase's; a statement whose
/// signature does not hold; and a secret that does not open to the
/// statement's commitment.
pub fn read_with(
    phrase: &Phrase,
    entry: &CheckedEntry,
) -> Result<(SignedStatement, ForPhrase), PersonError> {
    let (statement, for_phrase) = opened(phrase, entry)?;
    statement.verify()?;
    if !statement.statement.commits_to(&for_phrase.secret) {
        return Err(PersonError::SecretNotCommitted);
    }
    Ok((statement, for_phrase))
}

/// The device that makes a statement is always among its devices
/// (decision 2026-10-04 §6): a maker that would not be is refused as that,
/// before its key is asked about as a device of the statement applied.
fn stays_among(maker: &[u8; 32], stay: &[Device]) -> Result<(), PersonError> {
    if !stay.iter().any(|device| device.key == *maker) {
        return Err(StatementError::MakerNotListed.into());
    }
    Ok(())
}

/// The change entry of `statement`, signed and sealed with the phrase. Its
/// lineage says that it was made now, by this process's clock (decision
/// 2026-10-24 rule 13).
fn entry_of(
    phrase: &Phrase,
    statement: Statement,
    for_phrase: &ForPhrase,
) -> Result<CheckedEntry, PersonError> {
    let signed = statement.sign(&phrase.signing_key()?)?;
    Ok(change_entry::entry_of(phrase, &signed, for_phrase, made_now())?.check()?)
}

/// When a change is made, by the clock of the process that makes it, in
/// seconds since the Unix epoch: what its change entry's lineage says
/// (decision 2026-10-24 rule 13). A clock set before the epoch says 0.
pub(crate) fn made_now() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::person::{Shown, apply_made, shown};
    use crate::several::{Machine, OTHER_WORDS, Several};
    use cordelia_crypto::change_entry::{ChangeEntryError, DeviceSecret, Earlier};
    use cordelia_crypto::identity::NodeIdentity;
    use cordelia_crypto::statement::{Judgement, judge};
    use cordelia_storage::person::{self as held_rows, State};

    /// What a command with the phrase reads in a change entry.
    fn read(s: &Several, entry: &CheckedEntry) -> (SignedStatement, ForPhrase) {
        opened(&s.phrase, entry).unwrap()
    }

    /// The secret that `entry` seals to the device `identity`.
    fn sealed_to(s: &Several, entry: &CheckedEntry, identity: &NodeIdentity) -> DeviceSecret {
        let phrase = &s.phrase;
        change_entry::open_for_device(
            entry,
            &phrase.public_key().unwrap(),
            &derive::channel_id(&phrase.channel_secret().unwrap()).unwrap(),
            &phrase.statement_key().unwrap(),
            identity,
        )
        .unwrap()
        .secret
    }

    /// The change that device 0 would make, with the devices numbered in
    /// `stay` and the keys of those in `removed`.
    fn change_on_0(
        s: &Several,
        stay: &[usize],
        removed: &[usize],
    ) -> Result<CheckedEntry, PersonError> {
        let on = &s[0];
        let removed: Vec<[u8; 32]> = removed.iter().map(|n| s.key(*n)).collect();
        make_change(
            &s.phrase,
            &on.held().statement,
            &on.latest(),
            &on.key(),
            s.listed(stay),
            &removed,
        )
    }

    /// A change is a new secret, the next statement, the part for the
    /// phrase with the secrets copied forward, and the change entry that
    /// seals the secret to each device the statement lists.
    #[test]
    fn test_a_change_is_a_new_secret_the_next_statement_and_its_entry() {
        let mut s = Several::of_one_person(3);
        let first = s[0].secret();
        let applied = s[0].held().statement;
        let entry = change_on_0(&s, &[0, 1, 2], &[]).unwrap();

        // The entry is the phrase's, and its revision is the statement's
        // number.
        let (signed, for_phrase) = read(&s, &entry);
        assert_eq!(entry.author, s.phrase.public_key().unwrap());
        let statement = &signed.statement;
        assert_eq!((entry.rev, statement.number), (2, 2));
        assert_eq!(statement.maker, s.key(0));
        assert_eq!(statement.chain, [applied.statement.link().unwrap()]);
        assert_eq!(statement.devices, s.listed(&[0, 1, 2]));
        assert!(statement.removed.is_empty());
        signed.verify().unwrap();

        // The secret is new, the statement commits to it, and it is
        // sealed to each device that the statement lists.
        let secret = for_phrase.secret;
        assert_ne!(secret, first);
        assert!(statement.commits_to(&secret));
        for n in 0..3 {
            assert_eq!(
                sealed_to(&s, &entry, &s[n].identity),
                DeviceSecret::Opened(secret),
                "{n}"
            );
        }
        assert_eq!(
            sealed_to(&s, &entry, &Machine::new(9).identity),
            DeviceSecret::NotListed
        );
        // The part for the phrase: the secret before it, copied forward
        // from the entry held.
        assert_eq!(
            for_phrase.earlier,
            [Earlier {
                number: 1,
                secret: first
            }]
        );
        // Made twice, it is two changes: each has a secret of its own.
        let again = change_on_0(&s, &[0, 1, 2], &[]).unwrap();
        assert_ne!(read(&s, &again).1.secret, secret);

        // The node's half: shown the entry, the device that made it
        // applies it. The next change copies both secrets forward.
        let now = s.tick();
        let on = &s[0];
        assert!(matches!(
            shown(&on.conn, &on.identity, &entry, now).unwrap(),
            Shown::Applied(_)
        ));
        assert_eq!(on.secret(), secret);
        let removal = change_on_0(&s, &[0, 1], &[2]).unwrap();
        let (signed, for_phrase) = read(&s, &removal);
        assert_eq!(signed.statement.number, 3);
        assert_eq!(signed.statement.devices, s.listed(&[0, 1]));
        assert_eq!(signed.statement.removed, [s.key(2)]);
        assert_eq!(signed.statement.chain.len(), 2);
        assert_eq!(
            for_phrase.earlier,
            [
                Earlier { number: 2, secret },
                Earlier {
                    number: 1,
                    secret: first
                }
            ]
        );
        // The device it removes is told so by it, and is sealed nothing.
        let statement = &s[2].held().statement.statement;
        assert_eq!(
            judge(&signed, statement, &s.key(2), &statement.phrase_key).unwrap(),
            Judgement::Removed
        );
        assert_eq!(
            sealed_to(&s, &removal, &s[2].identity),
            DeviceSecret::NotListed
        );
    }

    /// A change is prepared with no phrase, and what the phrase then
    /// signs is the statement in the bytes that were shown: nothing else,
    /// and nothing made since.
    #[test]
    fn test_what_is_signed_is_the_statement_in_the_bytes_that_were_shown() {
        let s = Several::of_one_person(3);
        let on = &s[0];
        let applied = on.held().statement;
        let prepare =
            || prepare_change(&applied, &on.key(), s.listed(&[0, 1]), &[s.key(2)]).unwrap();
        let prepared = prepare();
        // What a command shows, it reads from these.
        let shown = Statement::from_bytes(prepared.bytes()).unwrap();
        assert_eq!((shown.number, shown.maker), (2, s.key(0)));
        assert_eq!(shown.devices, s.listed(&[0, 1]));
        assert_eq!(shown.removed, [s.key(2)]);
        assert_eq!(shown.phrase_key, applied.statement.phrase_key);
        assert!(shown.commits_to(&prepared.secret));
        // The secret is not printed.
        let printed = format!("{prepared:?}");
        assert!(!printed.contains(&hex::encode(*prepared.secret)));
        assert!(printed.contains(&hex::encode(prepared.bytes())));

        let bytes = prepared.bytes().to_vec();
        let entry = prepared.sign(&s.phrase, &on.latest(), &[]).unwrap();
        let (signed, for_phrase) = read(&s, &entry);
        assert_eq!(signed.statement.to_bytes().unwrap(), bytes);
        signed.verify().unwrap();
        assert!(signed.statement.commits_to(&for_phrase.secret));
        assert_eq!(entry.rev, 2);
        // Prepared twice, it is two changes.
        assert_ne!(prepare().bytes(), bytes);

        // Another phrase signs nothing, nor does the phrase with another
        // statement's entry, or with an entry for a statement made apart
        // where there is none.
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        assert!(matches!(
            prepare().sign(&other, &on.latest(), &[]),
            Err(PersonError::Statement(StatementError::AnotherPhrase))
        ));
        assert!(matches!(
            prepare().sign(&s.phrase, &entry, &[]),
            Err(PersonError::NotTheStatementsEntry)
        ));
        assert!(matches!(
            prepare().sign(&s.phrase, &on.latest(), &[&entry]),
            Err(PersonError::NotTheStatementsEntry)
        ));
        // What is refused of a change is refused before any phrase.
        assert!(matches!(
            prepare_change(&applied, &on.key(), s.listed(&[1]), &[]),
            Err(PersonError::Statement(StatementError::MakerNotListed))
        ));
    }

    /// A settlement is prepared from the two statements, and signed only
    /// with the entries of those two: the one made apart is opened with
    /// the phrase, and is the statement that was shown or nothing is
    /// signed.
    #[test]
    fn test_a_settlement_is_signed_only_with_the_entries_of_the_two_that_were_shown() {
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1, 2], &[]);
        s.meet(&[0, 1, 2]);
        let by_0 = s.change(0, &[0, 1, 2], &[]);
        let by_1 = s.change(1, &[0, 1, 2], &[]);
        let later = s.change(1, &[0, 1, 2], &[]);
        let on = &s[0];
        let applied = on.held().statement;
        let apart = read(&s, &by_1).0;
        let prepare = || {
            prepare_settlement(
                &applied,
                std::slice::from_ref(&apart),
                &on.key(),
                s.listed(&[0, 1]),
                &[s.key(2)],
            )
            .unwrap()
        };
        let prepared = prepare();
        let shown = Statement::from_bytes(prepared.bytes()).unwrap();
        assert_eq!(shown.number, 4);
        assert_eq!(shown.devices, s.listed(&[0, 1]));
        assert_eq!(shown.removed, [s.key(2)]);
        for statement in [&applied.statement, &apart.statement] {
            assert!(shown.has_on_chain(&statement.link().unwrap()));
        }
        let bytes = prepared.bytes().to_vec();
        let entry = prepared.sign(&s.phrase, &by_0, &[&by_1]).unwrap();
        let (signed, for_phrase) = read(&s, &entry);
        assert_eq!(signed.statement.to_bytes().unwrap(), bytes);
        let numbers: Vec<u64> = for_phrase.earlier.iter().map(|e| e.number).collect();
        assert_eq!(numbers, [3, 3, 2, 1]);

        // The entry of another statement than the one shown as made
        // apart, and no entry for it at all.
        assert!(matches!(
            prepare().sign(&s.phrase, &by_0, &[&later]),
            Err(PersonError::NotTheStatementsEntry)
        ));
        assert!(matches!(
            prepare().sign(&s.phrase, &by_0, &[]),
            Err(PersonError::NotTheStatementsEntry)
        ));
        // Two that were not made apart are not settled.
        assert!(matches!(
            prepare_settlement(
                &applied,
                std::slice::from_ref(&applied),
                &on.key(),
                s.listed(&[0, 1]),
                &[]
            ),
            Err(PersonError::Statement(StatementError::NotApart))
        ));
    }

    /// The node's half is for a change that a command of this device
    /// made (decision 2026-10-04 §16): a statement whose maker is another
    /// key than the one the node runs under is refused, with nothing
    /// changed, though the device would apply it were it shown it.
    #[test]
    fn test_a_change_made_on_another_device_is_not_made_through_this_ones_node() {
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1, 2], &[]);
        s.meet(&[0, 1, 2]);
        let (applied, held) = (s[0].held().statement, s[0].latest());
        let over = held.id();
        // The statement says that it was made on device 1.
        let entry = prepare_change(&applied, &s.key(1), s.listed(&[0, 1]), &[s.key(2)])
            .unwrap()
            .sign(&s.phrase, &held, &[])
            .unwrap();
        let now = s.tick();
        let on = &s[0];
        let before = on.everything();
        assert!(matches!(
            apply_made(&on.conn, &on.identity, &entry, &over, &[], now),
            Err(PersonError::MadeOnAnotherDevice)
        ));
        assert_eq!(on.everything(), before);
        assert_eq!(on.number(), 2);
        // The control: through the node of the device that it says it
        // was made on, it is made.
        let on = &s[1];
        let made = apply_made(&on.conn, &on.identity, &entry, &over, &[], now).unwrap();
        assert_eq!(made.number, 3);
    }

    /// The node's half: a change that a command made is applied only
    /// over what the prompt showed. A statement that arrived between the
    /// prompt and the phrase, one that the device applied or one that
    /// makes a fork, leaves nothing made.
    #[test]
    fn test_a_change_is_made_only_over_what_the_prompt_showed() {
        // A statement that the device applied meanwhile.
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1, 2], &[]);
        s.meet(&[0, 1, 2]);
        let (applied, held) = (s[0].held().statement, s[0].latest());
        let over = held.id();
        let prepared = prepare_change(&applied, &s.key(0), s.listed(&[0, 1]), &[s.key(2)]).unwrap();
        let arrived = s.change(1, &[0, 1, 2], &[]);
        let now = s.tick();
        let on = &s[0];
        assert!(matches!(
            shown(&on.conn, &on.identity, &arrived, now).unwrap(),
            Shown::Applied(_)
        ));
        let entry = prepared.sign(&s.phrase, &held, &[]).unwrap();
        let before = on.everything();
        assert!(matches!(
            apply_made(&on.conn, &on.identity, &entry, &over, &[], now),
            Err(PersonError::ChangedSincePrompt)
        ));
        assert_eq!(on.everything(), before);
        assert_eq!(on.number(), 3);

        // A statement that makes a fork meanwhile: the device keeps the
        // entry it had, and one made apart beside it.
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1, 2], &[]);
        s.meet(&[0, 1, 2]);
        let apart = s.change(1, &[0, 1, 2], &[]);
        s.change(0, &[0, 1, 2], &[]);
        let (applied, held) = (s[0].held().statement, s[0].latest());
        let over = held.id();
        let entry = prepare_change(&applied, &s.key(0), s.listed(&[0, 1]), &[s.key(2)])
            .unwrap()
            .sign(&s.phrase, &held, &[])
            .unwrap();
        let now = s.tick();
        let on = &s[0];
        // The control: with nothing arrived it would be made. It is
        // asked on a copy of what the device holds, and then undone.
        assert_eq!(
            shown(&on.conn, &on.identity, &apart, now).unwrap(),
            Shown::SetAside
        );
        let before = on.everything();
        assert!(matches!(
            apply_made(&on.conn, &on.identity, &entry, &over, &[], now),
            Err(PersonError::ChangedSincePrompt)
        ));
        assert_eq!(on.everything(), before);
        assert_eq!(on.state(), State::Applied);

        // The settlement is made over both, and over no other pair.
        let read_apart = read(&s, &apart).0;
        let settle = || {
            prepare_settlement(
                &applied,
                std::slice::from_ref(&read_apart),
                &s.key(0),
                s.listed(&[0, 1, 2]),
                &[],
            )
            .unwrap()
            .sign(&s.phrase, &held, &[&apart])
            .unwrap()
        };
        let settlement = settle();
        for (shown_over, shown_apart) in [
            (over, vec![]),
            (over, vec![[9u8; 32]]),
            (over, vec![apart.id(), apart.id()]),
            (apart.id(), vec![apart.id()]),
        ] {
            assert!(matches!(
                apply_made(
                    &on.conn,
                    &on.identity,
                    &settlement,
                    &shown_over,
                    &shown_apart,
                    now
                ),
                Err(PersonError::ChangedSincePrompt)
            ));
            assert_eq!(on.everything(), before);
        }
        let made = apply_made(
            &on.conn,
            &on.identity,
            &settlement,
            &over,
            &[apart.id()],
            now,
        )
        .unwrap();
        assert_eq!((made.number, made.left), (4, Some(3)));
        assert_eq!(on.state(), State::Applied);
        assert_eq!(on.apart(), None);
        // A device that is in no fork settles nothing.
        assert!(matches!(
            apply_made(
                &on.conn,
                &on.identity,
                &settle(),
                &on.latest().id(),
                &[apart.id()],
                now
            ),
            Err(PersonError::ChangedSincePrompt)
        ));

        // A device that has stopped makes no change, whatever it is
        // handed over the entry it keeps: here, one that was removed.
        let mut s = Several::of_one_person(3);
        let removal = s.change(0, &[0, 1], &[2]);
        let now = s.tick();
        let on = &s[2];
        shown(&on.conn, &on.identity, &removal, now).unwrap();
        assert_eq!(on.state(), State::Removed);
        let before = on.everything();
        assert!(matches!(
            apply_made(
                &on.conn,
                &on.identity,
                &removal,
                &on.latest().id(),
                &[],
                now
            ),
            Err(PersonError::ChangedSincePrompt)
        ));
        assert_eq!(on.everything(), before);
    }

    /// A record of an addition that arrives between the prompt and the
    /// phrase never has a command ask again: the change is made, and the
    /// key it adds is in neither list, and is shown as not in the last
    /// change.
    #[test]
    fn test_a_record_that_arrives_after_the_prompt_never_restarts_a_command() {
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1, 2], &[]);
        s.meet(&[0, 1, 2]);
        let (applied, held) = (s[0].held().statement, s[0].latest());
        let over = held.id();
        // The prompt: device 2 is removed.
        let prepared = prepare_change(&applied, &s.key(0), s.listed(&[0, 1]), &[s.key(2)]).unwrap();
        // Meanwhile the device that is being removed adds another, and
        // device 0 takes the record.
        let now = s.tick();
        let late = crate::several::Machine::new(9);
        let added = crate::adding::add_device(&s[2].conn, &s[2].identity, &late.key(), "late", now)
            .unwrap();
        let on = &s[0];
        crate::take::take(&on.conn, &on.identity, &added.record.unwrap(), now).unwrap();
        assert!(on.counts(&late.key()));
        assert_eq!(on.latest().id(), over);

        let entry = prepared.sign(&s.phrase, &held, &[]).unwrap();
        let made = apply_made(&on.conn, &on.identity, &entry, &over, &[], now + 1).unwrap();
        assert_eq!(made.number, 3);
        let statement = on.held().statement.statement;
        assert!(!statement.lists(&late.key()) && !statement.removes(&late.key()));
        assert!(!on.counts(&late.key()));
        let left_out = cordelia_storage::acts::left_out(&on.conn).unwrap();
        assert_eq!(left_out.len(), 1);
        assert_eq!(
            (left_out[0].key, left_out[0].label.as_str()),
            (late.key(), "late")
        );
        assert_eq!(left_out[0].number, 3);
        // The device that was removed is listed as that, and is no key
        // that was left out.
        assert!(statement.removes(&s.key(2)));
    }

    /// The device that makes a statement is always among its devices: a
    /// maker that would not be is refused.
    #[test]
    fn test_a_change_is_refused_where_its_maker_would_not_be_among_its_devices() {
        let s = Several::of_one_person(3);
        assert!(matches!(
            change_on_0(&s, &[1, 2], &[]),
            Err(PersonError::Statement(StatementError::MakerNotListed))
        ));
        // Nor does the maker remove itself.
        assert!(matches!(
            change_on_0(&s, &[1, 2], &[0]),
            Err(PersonError::Statement(StatementError::MakerNotListed))
        ));
        assert!(matches!(
            change_on_0(&s, &[0, 1, 2], &[0]),
            Err(PersonError::Statement(StatementError::InBothLists))
        ));
        assert!(change_on_0(&s, &[0, 1, 2], &[]).is_ok());

        // A settlement likewise.
        let mut s = Several::of_one_person(2);
        s.change(0, &[0, 1], &[]);
        let apart = s.change(1, &[0, 1], &[]);
        let on = &s[0];
        let settle = |maker: usize, stay: &[usize]| {
            make_settlement(
                &s.phrase,
                &on.held().statement,
                &on.latest(),
                &[&apart],
                &s.key(maker),
                s.listed(stay),
                &[],
            )
        };
        assert!(matches!(
            settle(0, &[1]),
            Err(PersonError::Statement(StatementError::MakerNotListed))
        ));
        assert!(settle(0, &[0]).is_ok());
    }

    /// A change leaves no device of the applied statement in no list: each
    /// stays, or is removed. A device added since that the person does
    /// not keep, and does not remove, is in no list.
    #[test]
    fn test_a_change_leaves_no_device_of_the_applied_statement_in_no_list() {
        let mut s = Several::of_one_person(3);
        // Statement 1 lists device 0 alone: the two added since may be
        // left out.
        let entry = change_on_0(&s, &[0], &[]).unwrap();
        let statement = read(&s, &entry).0.statement;
        assert_eq!(statement.devices, s.listed(&[0]));
        assert!(statement.removed.is_empty());

        // Statement 2 lists all three.
        s.change(0, &[0, 1, 2], &[]);
        for stay in [&[0][..], &[0, 1], &[0, 2]] {
            assert!(matches!(
                change_on_0(&s, stay, &[]),
                Err(PersonError::NeitherStaysNorRemoved)
            ));
        }
        assert!(matches!(
            change_on_0(&s, &[0], &[1]),
            Err(PersonError::NeitherStaysNorRemoved)
        ));
        assert!(change_on_0(&s, &[0, 1], &[2]).is_ok());
        assert!(change_on_0(&s, &[0], &[1, 2]).is_ok());
    }

    /// A change is made only with the phrase's own statement and that
    /// statement's entry.
    #[test]
    fn test_a_change_is_made_only_from_the_phrases_statement_and_its_own_entry() {
        let mut s = Several::of_one_person(2);
        let first = (s[0].held().statement, s[0].latest());
        s.change(0, &[0, 1], &[]);
        let second = (s[0].held().statement, s[0].latest());
        let make = |phrase: &Phrase, applied: &SignedStatement, held: &CheckedEntry| {
            make_change(phrase, applied, held, &s.key(0), s.listed(&[0, 1]), &[])
        };

        // Another phrase than the statement's.
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        assert!(matches!(
            make(&other, &second.0, &second.1),
            Err(PersonError::Statement(StatementError::AnotherPhrase))
        ));
        // A statement that the phrase did not sign.
        let mut forged = second.0.clone();
        forged.signature[0] ^= 1;
        assert!(matches!(
            make(&s.phrase, &forged, &second.1),
            Err(PersonError::Statement(StatementError::Signature))
        ));
        // An entry of another statement than the one applied.
        assert!(matches!(
            make(&s.phrase, &second.0, &first.1),
            Err(PersonError::NotTheStatementsEntry)
        ));
        assert!(matches!(
            make(&s.phrase, &first.0, &second.1),
            Err(PersonError::NotTheStatementsEntry)
        ));
        // An entry that is no change entry of the phrase: another key
        // wrote it.
        let on = &s[0];
        let forged = crate::several::signed_in(
            &s.phrase.channel_secret().unwrap(),
            &on.identity,
            second.1.slot,
            2,
            second.1.content.clone(),
        );
        assert!(matches!(
            make(&s.phrase, &second.0, &forged),
            Err(PersonError::ChangeEntry(ChangeEntryError::AnotherAuthor))
        ));
        // The control.
        assert!(make(&s.phrase, &second.0, &second.1).is_ok());
    }

    /// No statement brings a removed key back: a change that would keep
    /// a key which the applied statement removed is refused.
    #[test]
    fn test_a_change_brings_no_removed_key_back() {
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1], &[2]);
        assert!(matches!(
            change_on_0(&s, &[0, 1, 2], &[]),
            Err(PersonError::Statement(StatementError::InBothLists))
        ));
        let entry = change_on_0(&s, &[0, 1], &[]).unwrap();
        assert_eq!(read(&s, &entry).0.statement.removed, [s.key(2)]);
    }

    /// A settlement is numbered above both statements, has both and their
    /// chains on its chain, removes every key that either removed, and
    /// holds the secrets of both in its part for the phrase.
    #[test]
    fn test_a_settlement_is_made_after_both_and_holds_the_secrets_of_both() {
        let mut s = Several::of_one_person(4);
        let first = s[0].secret();
        // Device 0 removes device 3. Device 1, apart, removes device 2,
        // and then makes a second change.
        let by_0 = s.change(0, &[0, 1, 2], &[3]);
        s.change(1, &[0, 1, 3], &[2]);
        let by_1 = s.change(1, &[0, 1, 3], &[]);
        assert_eq!((by_0.rev, by_1.rev), (2, 3));
        let (one, other) = (read(&s, &by_0), read(&s, &by_1));

        let on = &s[0];
        let settle = |apart: &CheckedEntry, stay: &[usize], removed: &[[u8; 32]]| {
            make_settlement(
                &s.phrase,
                &on.held().statement,
                &on.latest(),
                &[apart],
                &on.key(),
                s.listed(stay),
                removed,
            )
        };
        let entry = settle(&by_1, &[0, 1], &[]).unwrap();
        let (signed, for_phrase) = read(&s, &entry);
        let settled = &signed.statement;
        assert_eq!((entry.rev, settled.number), (4, 4));
        assert_eq!(settled.maker, s.key(0));
        assert_eq!(settled.devices, s.listed(&[0, 1]));
        // It undoes nothing: every key that either removed is removed.
        let mut removed = vec![s.key(2), s.key(3)];
        removed.sort_unstable();
        assert_eq!(settled.removed, removed);
        // Both are on its chain, with what each was made after: the first
        // statement, the two numbered 2, and the one numbered 3.
        for statement in [&one.0.statement, &other.0.statement] {
            assert!(settled.has_on_chain(&statement.link().unwrap()));
            for link in &statement.chain {
                assert!(settled.has_on_chain(link));
            }
        }
        assert_eq!(settled.chain.len(), 4);

        // The part for the phrase: the secrets of both branches, the
        // newest first, and of the generation before them.
        assert!(settled.commits_to(&for_phrase.secret));
        let numbers: Vec<u64> = for_phrase.earlier.iter().map(|e| e.number).collect();
        assert_eq!(numbers, [3, 2, 2, 1]);
        let secrets: Vec<[u8; 32]> = for_phrase.earlier.iter().map(|e| e.secret).collect();
        assert_eq!(secrets[0], other.1.secret);
        assert!(secrets[1..3].contains(&one.1.secret));
        assert!(secrets[1..3].contains(&other.1.earlier[0].secret));
        assert_eq!(secrets[3], first);
        // A device on either branch applies it.
        for (n, applied) in [(0, &one.0), (1, &other.0)] {
            assert_eq!(
                judge(&signed, &applied.statement, &s.key(n), &settled.phrase_key).unwrap(),
                Judgement::Applies,
                "{n}"
            );
        }

        // Two statements that were not made apart are not settled: the
        // one applied with itself, and with the one it was made after.
        assert!(matches!(
            settle(&by_0, &[0, 1], &[]),
            Err(PersonError::Statement(StatementError::NotApart))
        ));
        // A key that either removed is not kept.
        assert!(matches!(
            settle(&by_1, &[0, 1, 2], &[]),
            Err(PersonError::Statement(StatementError::InBothLists))
        ));
    }

    // ── Changes made from here (decision 2026-10-24 (removal), rules
    // 20 and 21) ──────────────────────────────────────────────────────

    /// A change made with the phrase over `held`, the entry of `applied`,
    /// on device `maker`, with the devices in `stay` and the keys in
    /// `removed`: a renewal or a removal.
    fn renewal(
        s: &Several,
        maker: usize,
        (applied, held): (&SignedStatement, &CheckedEntry),
        stay: &[usize],
        removed: &[[u8; 32]],
    ) -> CheckedEntry {
        prepare_change(applied, &s.key(maker), s.listed(stay), removed)
            .unwrap()
            .sign(&s.phrase, held, &[])
            .unwrap()
    }

    /// Rule 20: the node refuses a change of its own that does not list
    /// as removed every key the device knows to be removed, or lists one
    /// of them as a device, whatever kind of change it is, with nothing
    /// changed. The keys are set by hand, as a change seen on another
    /// branch keeps them.
    #[test]
    fn test_the_node_refuses_a_change_of_its_own_that_leaves_out_a_removed_key_or_lists_one() {
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1, 2], &[]);
        s.meet(&[0, 1, 2]);
        let stranger = Machine::new(9).key();
        let now = s.tick();
        let on = &s[0];
        held_rows::keep_removed(&on.conn, &[stranger], now).unwrap();
        let (applied, held) = (on.held().statement, on.latest());
        let over = held.id();
        let made =
            |entry: &CheckedEntry| apply_made(&on.conn, &on.identity, entry, &over, &[], now);
        let before = on.everything();
        // A renewal, and a removal of another key, that leave it out.
        for (stay, removed) in [(&[0, 1, 2][..], vec![]), (&[0, 1], vec![s.key(2)])] {
            let entry = renewal(&s, 0, (&applied, &held), stay, &removed);
            assert!(
                matches!(made(&entry), Err(PersonError::LeavesOutARemovedKey)),
                "{removed:?}"
            );
            assert_eq!(on.everything(), before);
        }
        // Device 2 is known to be removed too: a change that keeps it as a
        // device is refused, and so is one that leaves it in no list.
        held_rows::keep_removed(&on.conn, &[s.key(2)], now).unwrap();
        let before = on.everything();
        let keeps = renewal(&s, 0, (&applied, &held), &[0, 1, 2], &[stranger]);
        assert!(matches!(made(&keeps), Err(PersonError::ListsARemovedKey)));
        assert_eq!(on.everything(), before);
        // The control: each is listed as removed, and none as a device.
        let entry = renewal(&s, 0, (&applied, &held), &[0, 1], &[stranger, s.key(2)]);
        assert_eq!(made(&entry).unwrap().number, 3);
        let statement = on.held().statement.statement;
        assert!(statement.removes(&stranger) && statement.removes(&s.key(2)));
        assert!(!statement.lists(&s.key(2)));

        // A device that knows its own key to be removed makes no change:
        // it is told so.
        let (applied, held) = (on.held().statement, on.latest());
        held_rows::keep_removed(&on.conn, &[s.key(0)], now).unwrap();
        let before = on.everything();
        let entry = renewal(&s, 0, (&applied, &held), &[0, 1], &[]);
        assert!(matches!(
            apply_made(&on.conn, &on.identity, &entry, &held.id(), &[], now),
            Err(PersonError::RemovedAsKnown)
        ));
        assert_eq!(on.everything(), before);
    }

    /// Rule 21: a change made on a device that keeps heads set aside joins
    /// every one. A renewal that joins none, and a settlement of two heads
    /// where three are kept, are refused, with nothing changed; and a
    /// change shown over fewer heads than are kept was made over something
    /// else. The settlement of all three has each on its chain, holds the
    /// secret of each in its part for the phrase, is applied, and leaves no
    /// head set aside.
    #[test]
    fn test_a_change_made_where_heads_are_set_aside_joins_every_one() {
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1, 2], &[]);
        s.meet(&[0, 1, 2]);
        let by_0 = s.change(0, &[0, 1, 2], &[]);
        let by_1 = s.change(1, &[0, 1, 2], &[]);
        let by_2 = s.change(2, &[0, 1, 2], &[]);
        let now = s.tick();
        let on = &s[0];
        for apart in [&by_1, &by_2] {
            assert_eq!(
                shown(&on.conn, &on.identity, apart, now).unwrap(),
                Shown::SetAside
            );
        }
        assert_eq!(on.latest().id(), by_0.id());
        let heads = [by_1.id(), by_2.id()];
        let (applied, held) = (on.held().statement, on.latest());
        let over = held.id();
        let (one, two) = (read(&s, &by_1).0, read(&s, &by_2).0);
        let before = on.everything();

        let renewed = renewal(&s, 0, (&applied, &held), &[0, 1, 2], &[]);
        let of_two = prepare_settlement(
            &applied,
            std::slice::from_ref(&one),
            &s.key(0),
            s.listed(&[0, 1, 2]),
            &[],
        )
        .unwrap()
        .sign(&s.phrase, &held, &[&by_1])
        .unwrap();
        for entry in [&renewed, &of_two] {
            assert!(matches!(
                apply_made(&on.conn, &on.identity, entry, &over, &heads, now),
                Err(PersonError::JoinsNotEveryHead)
            ));
            assert_eq!(on.everything(), before);
        }
        for shown_heads in [&[][..], &[by_1.id()], &[by_1.id(), by_2.id(), by_0.id()]] {
            assert!(matches!(
                apply_made(&on.conn, &on.identity, &of_two, &over, shown_heads, now),
                Err(PersonError::ChangedSincePrompt)
            ));
        }
        assert_eq!(on.everything(), before);

        // The settlement of all three, the heads in either order.
        let settlement = prepare_settlement(
            &applied,
            &[two.clone(), one.clone()],
            &s.key(0),
            s.listed(&[0, 1, 2]),
            &[],
        )
        .unwrap()
        .sign(&s.phrase, &held, &[&by_2, &by_1])
        .unwrap();
        let (signed, for_phrase) = read(&s, &settlement);
        assert_eq!(signed.statement.number, 4);
        for head in [&applied, &one, &two] {
            assert!(
                signed
                    .statement
                    .has_on_chain(&head.statement.link().unwrap())
            );
        }
        let secrets: Vec<[u8; 32]> = for_phrase.earlier.iter().map(|e| e.secret).collect();
        for entry in [&by_0, &by_1, &by_2] {
            assert!(secrets.contains(&read(&s, entry).1.secret));
        }
        // The three heads, then changes 2 and 1, which each copies forward.
        let numbers: Vec<u64> = for_phrase.earlier.iter().map(|e| e.number).collect();
        assert_eq!(numbers, [3, 3, 3, 2, 1]);
        let made = apply_made(&on.conn, &on.identity, &settlement, &over, &heads, now).unwrap();
        assert_eq!((made.number, made.left), (4, Some(3)));
        assert_eq!(on.state(), State::Applied);
        assert!(held_rows::set_aside_entries(&on.conn).unwrap().is_empty());
    }

    /// A settlement of three heads holds the secrets of each in its part
    /// for the phrase, as many as fit: where the branches are long, the
    /// secret of each head is held before the secrets that each copies
    /// forward.
    #[test]
    fn test_a_settlement_of_three_heads_holds_the_secret_of_each_as_many_as_fit() {
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1, 2], &[]);
        s.meet(&[0, 1, 2]);
        let by_0 = s.change(0, &[0, 1, 2], &[]);
        let by_2 = s.change(2, &[0, 1, 2], &[]);
        // Device 1 renews eight times on its own: its branch is long.
        let mut by_1 = s.change(1, &[0, 1, 2], &[]);
        for _ in 0..8 {
            by_1 = s.change(1, &[0, 1, 2], &[]);
        }
        assert_eq!(by_1.rev, 11);
        let on = &s[0];
        let settlement = make_settlement(
            &s.phrase,
            &on.held().statement,
            &on.latest(),
            &[&by_1, &by_2],
            &on.key(),
            s.listed(&[0, 1, 2]),
            &[],
        )
        .unwrap();
        let (signed, for_phrase) = read(&s, &settlement);
        assert_eq!(signed.statement.number, 12);
        let secrets: Vec<[u8; 32]> = for_phrase.earlier.iter().map(|e| e.secret).collect();
        assert_eq!(secrets.len(), cordelia_core::protocol::MAX_EARLIER_SECRETS);
        for entry in [&by_0, &by_1, &by_2] {
            assert!(secrets.contains(&read(&s, entry).1.secret));
        }
    }

    // ── The lineage, and entries of the version before (decision
    // 2026-10-24 rule 13) ────────────────────────────────────────────

    /// `entry` as the version before (0.2.0-alpha.16) made it: the same
    /// part for the devices, the part for the phrase in the last 4096
    /// bytes, and no lineage. Signed by the phrase, at its revision.
    fn as_the_version_before_made_it(s: &Several, entry: &CheckedEntry) -> CheckedEntry {
        use cordelia_core::protocol::{
            CHANGE_ENTRY_DEVICES_PART_BYTES, CHANGE_ENTRY_PHRASE_PART_BEFORE_BYTES,
            ITEM_SEAL_OVERHEAD_BYTES, LABEL_CHANGE_PHRASE,
        };
        let phrase = &s.phrase;
        let (_, for_phrase) = read(s, entry);
        // The secret, a count, and each earlier secret behind its number.
        let mut said = for_phrase.secret.to_vec();
        said.extend_from_slice(&(for_phrase.earlier.len() as u16).to_be_bytes());
        for earlier in &for_phrase.earlier {
            said.extend_from_slice(&earlier.number.to_be_bytes());
            said.extend_from_slice(&earlier.secret);
        }
        said.resize(
            CHANGE_ENTRY_PHRASE_PART_BEFORE_BYTES - ITEM_SEAL_OVERHEAD_BYTES,
            0,
        );
        let mut bound = LABEL_CHANGE_PHRASE.to_vec();
        bound.extend_from_slice(&entry.rev.to_be_bytes());
        bound.extend_from_slice(&phrase.public_key().unwrap());
        let mut content = entry.content[..CHANGE_ENTRY_DEVICES_PART_BYTES].to_vec();
        content.extend_from_slice(
            &cordelia_crypto::item_encrypt(&phrase.seal_key().unwrap(), &said, &bound).unwrap(),
        );
        crate::several::signed_in(
            &phrase.channel_secret().unwrap(),
            &phrase.signing_key().unwrap(),
            entry.slot,
            entry.rev,
            content,
        )
    }

    /// The change entry that a command makes says its lineage: its
    /// statement's hash and its chain's, and when it was made, by the
    /// clock of the process that made it. So does the first change, which
    /// `cordelia phrase` makes.
    #[test]
    fn test_a_change_entry_says_its_lineage_and_when_it_was_made() {
        // The clock, read here and not through the code that makes the
        // change.
        let clock = || chrono::Utc::now().timestamp() as u64;
        let mut s = Several::of_one_person(3);
        let before = clock();
        let entry = change_on_0(&s, &[0, 1, 2], &[]).unwrap();
        let after = clock();
        let (signed, _) = read(&s, &entry);
        let lineage = change_entry::lineage(&entry.content).unwrap().unwrap();
        assert!(lineage.is_of(&signed.statement).unwrap());
        assert_eq!(lineage.chain.len(), 1);
        assert!(
            (before..=after).contains(&lineage.made_at),
            "{before} {} {after}",
            lineage.made_at
        );

        // A settlement's lineage names both statements it settles.
        let by_0 = s.change(0, &[0, 1, 2], &[]);
        let by_1 = s.change(1, &[0, 1, 2], &[]);
        assert_eq!((by_0.rev, by_1.rev), (2, 2));
        let on = &s[0];
        let settlement = make_settlement(
            &s.phrase,
            &on.held().statement,
            &on.latest(),
            &[&by_1],
            &on.key(),
            s.listed(&[0, 1, 2]),
            &[],
        )
        .unwrap();
        let (settled, _) = read(&s, &settlement);
        let lineage = change_entry::lineage(&settlement.content).unwrap().unwrap();
        assert!(lineage.is_of(&settled.statement).unwrap());
        assert_eq!(lineage.chain.len(), 3);

        // The first change.
        let before = clock();
        let made = crate::person::first_entry(&s.phrase, &s.key(0), "desktop").unwrap();
        let after = clock();
        let lineage = change_entry::lineage(&made.entry.content).unwrap().unwrap();
        assert!(lineage.chain.is_empty());
        assert!((before..=after).contains(&lineage.made_at));
    }

    /// A command of this version makes a change over the change entry of
    /// the version before, whose part for the phrase is the last 4096
    /// bytes: a change, a settlement of two such entries, and the read
    /// that a carry with the phrase and a recovery make. What it makes is
    /// in the layout with a lineage.
    #[test]
    fn test_a_change_is_made_over_an_entry_of_the_version_before() {
        use cordelia_crypto::change_entry::Layout;
        let mut s = Several::of_one_person(3);
        let first = s[0].secret();
        let held = as_the_version_before_made_it(&s, &s[0].latest());
        assert_eq!(change_entry::layout(&held.content), Ok(Layout::Before));

        let entry = make_change(
            &s.phrase,
            &s[0].held().statement,
            &held,
            &s.key(0),
            s.listed(&[0, 1, 2]),
            &[],
        )
        .unwrap();
        assert_eq!(
            change_entry::layout(&entry.content),
            Ok(Layout::WithLineage)
        );
        let (_, for_phrase) = read(&s, &entry);
        assert_eq!(
            for_phrase.earlier,
            [Earlier {
                number: 1,
                secret: first
            }]
        );
        let (statement, read_back) = read_with(&s.phrase, &held).unwrap();
        assert_eq!(statement, s[0].held().statement);
        assert_eq!(read_back.secret, first);

        // A settlement of two changes made apart, each as the version
        // before made it.
        let by_0 = s.change(0, &[0, 1, 2], &[]);
        let by_1 = s.change(1, &[0, 1, 2], &[]);
        let (one, other) = (read(&s, &by_0).1, read(&s, &by_1).1);
        let on = &s[0];
        let settlement = make_settlement(
            &s.phrase,
            &on.held().statement,
            &as_the_version_before_made_it(&s, &on.latest()),
            &[&as_the_version_before_made_it(&s, &by_1)],
            &on.key(),
            s.listed(&[0, 1, 2]),
            &[],
        )
        .unwrap();
        let (_, for_phrase) = read(&s, &settlement);
        let secrets: Vec<[u8; 32]> = for_phrase.earlier.iter().map(|e| e.secret).collect();
        assert!(secrets[..2].contains(&one.secret));
        assert!(secrets[..2].contains(&other.secret));
        assert_eq!(secrets[2], first);
    }
}
