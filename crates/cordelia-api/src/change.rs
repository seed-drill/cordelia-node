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
//! The node's half is what a device does with any change entry it is
//! shown ([`crate::person::shown`]): the device that made the change is
//! among its devices, opens the secret sealed to it, and applies.
//!
//! Nothing here reads or writes a database, and nothing here keeps the
//! words: the phrase is the caller's, for as long as it signs and seals.

use cordelia_crypto::change_entry::{self, ForPhrase};
use cordelia_crypto::derive;
use cordelia_crypto::entry::CheckedEntry;
use cordelia_crypto::phrase::Phrase;
use cordelia_crypto::statement::{self, Device, SignedStatement, Statement, StatementError};

use crate::person::PersonError;

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
    let before = applied_with(phrase, applied, held)?;
    stays_among(maker, &stay)?;
    let leaves_out = |device: &Device| {
        !stay.iter().any(|stays| stays.key == device.key) && !removed.contains(&device.key)
    };
    if applied.statement.devices.iter().any(leaves_out) {
        return Err(PersonError::NeitherStaysNorRemoved);
    }

    let secret = statement::new_secret()?;
    let next = applied.statement.next(*maker, &secret, stay, removed)?;
    let for_phrase = ForPhrase::following(secret, &[(applied.statement.number, &before)]);
    entry_of(phrase, next, &for_phrase)
}

/// Make the statement that settles two that were made apart (decision
/// 2026-10-04 §4.5).
///
/// `applied` is the statement the device has applied and `held` its
/// change entry. `apart` is the change entry the device keeps of the
/// statement that was made apart from it. `maker`, `stay` and `removed`
/// are as [`make_change`] takes them: the devices are chosen from those
/// of both statements, and a device of either that is neither kept nor
/// removed is in no list.
///
/// The settlement is numbered above both, its chain holds both and their
/// chains, and it lists as removed every key that either does: it undoes
/// nothing. The part for the phrase holds the secrets of both branches,
/// each opened from its entry with the phrase.
///
/// Refused: what [`make_change`] refuses of the statement and the
/// entries; a maker that would not be among the devices, as a statement
/// refuses it; two statements that were not made apart; and an entry kept
/// apart whose statement the phrase's statement key does not read whole.
pub fn make_settlement(
    phrase: &Phrase,
    applied: &SignedStatement,
    held: &CheckedEntry,
    apart: &CheckedEntry,
    maker: &[u8; 32],
    stay: Vec<Device>,
    removed: &[[u8; 32]],
) -> Result<CheckedEntry, PersonError> {
    let one = applied_with(phrase, applied, held)?;
    let (other_statement, other) = opened(phrase, apart)?;

    let secret = statement::new_secret()?;
    let settled = Statement::settle(
        &applied.statement,
        &other_statement.statement,
        *maker,
        &secret,
        stay,
        removed,
    )?;
    let for_phrase = ForPhrase::following(
        secret,
        &[
            (applied.statement.number, &one),
            (other_statement.statement.number, &other),
        ],
    );
    entry_of(phrase, settled, &for_phrase)
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
    let channel = derive::channel_id(&phrase.channel_secret()?)?;
    let statement =
        change_entry::open_statement(entry, &phrase_key, &channel, &phrase.statement_key()?)?;
    let for_phrase =
        change_entry::open_for_phrase(entry, &phrase_key, &channel, &phrase.seal_key()?)?;
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

/// The change entry of `statement`, signed and sealed with the phrase.
fn entry_of(
    phrase: &Phrase,
    statement: Statement,
    for_phrase: &ForPhrase,
) -> Result<CheckedEntry, PersonError> {
    let signed = statement.sign(&phrase.signing_key()?)?;
    Ok(change_entry::entry_of(phrase, &signed, for_phrase)?.check()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::person::{Shown, shown};
    use crate::several::{Machine, OTHER_WORDS, Several};
    use cordelia_crypto::change_entry::{ChangeEntryError, DeviceSecret, Earlier};
    use cordelia_crypto::identity::NodeIdentity;
    use cordelia_crypto::statement::{Judgement, judge};

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
                &apart,
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
                apart,
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
}
