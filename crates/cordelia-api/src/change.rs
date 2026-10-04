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
