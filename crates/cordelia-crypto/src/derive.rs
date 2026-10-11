//! A channel from its secret, and where each kind of channel's secret
//! comes from (decision 2026-10-04 §2.1, §2.2).
//!
//! A channel is a secret of 32 bytes. Everything about the channel is
//! derived from it with HKDF-SHA256, each thing under its own label: the
//! key its entries are encrypted under, the key that turns a name into a
//! slot, and its signing key, whose public half is the channel's ID.
//!
//! Each kind of channel has a label of its own too, so that no two kinds
//! can ever derive the same secret:
//!
//! | Kind | Secret |
//! |---|---|
//! | Personal | HKDF(person secret, `cordelia v2 personal`) |
//! | Messages | HKDF(person secret, `cordelia v2 messages`) (decision 2026-10-09 §2.1) |
//! | Own, by name | HKDF(person secret, `cordelia v2 own` + length + name) |
//! | Pair | HKDF(X25519(device a, device b), `cordelia v2 pair` + both keys, the lower first) |
//! | The phrase's | HKDF(phrase, `cordelia v2 recovery`): see [`crate::phrase`] |
//! | Locked | HKDF(person secret and the lock's key, `cordelia v2 locked` + length + name) |
//!
//! The labels are in `cordelia_core::protocol`. The salt is empty
//! throughout.

use cordelia_core::protocol::{
    LABEL_AGENT_MESSAGES, LABEL_CHANNEL_SIGN, LABEL_ENTRY_KEY, LABEL_LOCKED, LABEL_OWN, LABEL_PAIR,
    LABEL_PERSONAL, LABEL_SLOT_KEY,
};
use cordelia_core::sync_name;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::CryptoError;
use crate::ecies::{hkdf_sha256, hkdf_sha256_of};
use crate::identity::{NodeIdentity, x25519_pub_from_ed25519_pub};

/// Why a channel's secret was not derived.
#[derive(Debug, thiserror::Error)]
pub enum DeriveError {
    #[error("a channel's name is at least one byte")]
    NameEmpty,

    #[error("a channel's name is at most 65535 bytes, and this one is {0}")]
    NameTooLong(usize),

    #[error("a channel's name is in its one spelling, and this one is not")]
    NameNotTidy,

    #[error("a pair channel is between two devices, and that is this device's own key")]
    OwnKey,

    #[error("the other device's key is not a usable public key")]
    KeyNotUsable,

    #[error("the two keys give a secret that anyone can work out")]
    SecretAnyoneCanWorkOut,

    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// The key a channel's entries are encrypted under, with AES-256-GCM.
pub fn entry_key(secret: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    hkdf_sha256(secret, &[], LABEL_ENTRY_KEY)
}

/// The key that gives an entry's slot from its name, with HMAC-SHA256, so
/// that a relay sees no names. It changes when the channel's secret does.
pub fn slot_key(secret: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    hkdf_sha256(secret, &[], LABEL_SLOT_KEY)
}

/// A channel's signing key: an Ed25519 key pair, held as a device's own
/// key is. Every entry of the channel is signed with it, and whoever holds
/// it can prove to a relay that it holds the channel.
pub fn signing_key(secret: &[u8; 32]) -> Result<NodeIdentity, CryptoError> {
    NodeIdentity::from_seed(hkdf_sha256(secret, &[], LABEL_CHANNEL_SIGN)?)
}

/// A channel's ID: the public half of its signing key. It is written
/// `cordelia_ch1...` ([`crate::bech32::encode_channel_id`]).
pub fn channel_id(secret: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    Ok(signing_key(secret)?.public_key())
}

/// The secret of the personal channel, which every device of the person
/// can derive.
pub fn personal_secret(person_secret: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    hkdf_sha256(person_secret, &[], LABEL_PERSONAL)
}

/// The secret of the messages channel, which every device of the person
/// can derive (decision 2026-10-09 §2.1). It is under a label of its own,
/// and not a name's, so it is no name's channel.
pub fn messages_secret(person_secret: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    hkdf_sha256(person_secret, &[], LABEL_AGENT_MESSAGES)
}

/// The secret of the channel of the person's own that is called `name`,
/// which every device of the person can derive for every name.
///
/// The name is in its one spelling ([`sync_name::tidy`]): another spelling
/// would be another channel, so it is refused here and not tidied.
pub fn own_secret(person_secret: &[u8; 32], name: &str) -> Result<[u8; 32], DeriveError> {
    Ok(hkdf_sha256(person_secret, &[], &named(LABEL_OWN, name)?)?)
}

/// The secret of the channel between this device and the device whose key
/// is `other`: where two devices that know each other's keys can meet, and
/// where nobody else can write. Each of the two derives the same secret.
///
/// Both keys must be usable, and a shared secret that is all zeros is
/// refused, as sealing to a key refuses them ([`crate::ecies`]).
pub fn pair_secret(device: &NodeIdentity, other: &[u8; 32]) -> Result<[u8; 32], DeriveError> {
    let own = device.public_key();
    if own == *other {
        return Err(DeriveError::OwnKey);
    }
    let other_x25519 = x25519_pub_from_ed25519_pub(other).ok_or(DeriveError::KeyNotUsable)?;
    pair_secret_from(&device.x25519_private_key(), &other_x25519, &own, other)
}

/// [`pair_secret`] from the X25519 halves of the two keys: this device's
/// private half and the other's public half. `a` and `b` are the two
/// devices' public keys, in either order.
fn pair_secret_from(
    own_private: &[u8; 32],
    other_public: &[u8; 32],
    a: &[u8; 32],
    b: &[u8; 32],
) -> Result<[u8; 32], DeriveError> {
    let shared = StaticSecret::from(*own_private).diffie_hellman(&PublicKey::from(*other_public));
    // A key of small order gives the same secret to everyone: all zero. A
    // channel under it would be a channel that anyone can derive.
    if !shared.was_contributory() {
        return Err(DeriveError::SecretAnyoneCanWorkOut);
    }
    // The lower key first, so that both devices write the same input.
    let (lower, higher) = if a <= b { (a, b) } else { (b, a) };
    let mut info = Vec::with_capacity(LABEL_PAIR.len() + 64);
    info.extend_from_slice(LABEL_PAIR);
    info.extend_from_slice(lower);
    info.extend_from_slice(higher);
    Ok(hkdf_sha256(shared.as_bytes(), &[], &info)?)
}

/// The secret of the locked channel called `name` (decision 2026-10-04
/// §11: its derivation only). It is derived from the person secret and the
/// lock's key together, the person secret first, so a device where the
/// lock is not open cannot compute the channel at all.
pub fn locked_secret(
    person_secret: &[u8; 32],
    lock_key: &[u8; 32],
    name: &str,
) -> Result<[u8; 32], DeriveError> {
    let info = named(LABEL_LOCKED, name)?;
    let mut together = [0u8; 64];
    together[..32].copy_from_slice(person_secret);
    together[32..].copy_from_slice(lock_key);
    Ok(hkdf_sha256_of(&together, &[], &info)?)
}

/// What a secret for a name is derived under: the label, the name's length
/// as two bytes, and the name. With its length before it, a name can never
/// be read as part of a label or of another name.
fn named(label: &[u8], name: &str) -> Result<Vec<u8>, DeriveError> {
    if name.is_empty() {
        return Err(DeriveError::NameEmpty);
    }
    if sync_name::tidy(name) != name {
        return Err(DeriveError::NameNotTidy);
    }
    let length = u16::try_from(name.len()).map_err(|_| DeriveError::NameTooLong(name.len()))?;
    let mut info = Vec::with_capacity(label.len() + 2 + name.len());
    info.extend_from_slice(label);
    info.extend_from_slice(&length.to_be_bytes());
    info.extend_from_slice(name.as_bytes());
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bech32::{decode_channel_id, encode_channel_id};
    use crate::identity::{verify_signature, x25519_from_ed25519_seed};
    use std::collections::HashSet;

    const SECRET: [u8; 32] = [0x11; 32];
    const PERSON: [u8; 32] = [0x22; 32];
    const LOCK: [u8; 32] = [0x33; 32];

    fn device(seed: u8) -> NodeIdentity {
        NodeIdentity::from_seed([seed; 32]).unwrap()
    }

    /// Each label, spelled here as the decision spells it: a change to a
    /// label, or to what is derived under it, fails here.
    #[test]
    fn each_thing_of_a_channel_is_derived_under_its_own_label() {
        let under = |label: &[u8]| hkdf_sha256(&SECRET, &[], label).unwrap();
        assert_eq!(entry_key(&SECRET).unwrap(), under(b"cordelia v2 entry"));
        assert_eq!(slot_key(&SECRET).unwrap(), under(b"cordelia v2 slot"));
        assert_eq!(
            signing_key(&SECRET).unwrap().seed(),
            &under(b"cordelia v2 sign")
        );
        assert_eq!(
            personal_secret(&PERSON).unwrap(),
            hkdf_sha256(&PERSON, &[], b"cordelia v2 personal").unwrap()
        );

        // Three things, none of them the secret, and another secret gives
        // three others.
        let of = |secret: &[u8; 32]| {
            [
                entry_key(secret).unwrap(),
                slot_key(secret).unwrap(),
                *signing_key(secret).unwrap().seed(),
                channel_id(secret).unwrap(),
            ]
        };
        let mut all: HashSet<[u8; 32]> = HashSet::from([SECRET, PERSON]);
        all.extend(of(&SECRET));
        all.extend(of(&PERSON));
        assert_eq!(all.len(), 10);
    }

    #[test]
    fn a_channels_id_is_the_public_half_of_its_signing_key() {
        let key = signing_key(&SECRET).unwrap();
        let id = channel_id(&SECRET).unwrap();
        assert_eq!(id, key.public_key());

        // An entry signed with the channel's key is checked with its ID
        // alone, as a relay checks it.
        let signature = key.sign(b"an entry of this channel");
        assert!(verify_signature(
            &id,
            b"an entry of this channel",
            &signature
        ));
        let other = channel_id(&PERSON).unwrap();
        assert!(!verify_signature(
            &other,
            b"an entry of this channel",
            &signature
        ));

        let text = encode_channel_id(&id).unwrap();
        assert!(text.starts_with("cordelia_ch1"));
        assert_eq!(decode_channel_id(&text).unwrap(), id);
    }

    /// No two kinds of channel derive the same secret, whatever their names
    /// are: not from one person secret, and not where one kind's name is
    /// another kind's label.
    #[test]
    fn no_two_kinds_of_channel_have_the_same_secret() {
        let a = device(1);
        let b = device(2);
        let names = [
            "~",
            "personal",
            "own",
            "locked",
            "pair",
            "github.com/owner/repo",
        ];
        let mut secrets = vec![
            personal_secret(&PERSON).unwrap(),
            messages_secret(&PERSON).unwrap(),
        ];
        for name in names {
            secrets.push(own_secret(&PERSON, name).unwrap());
            secrets.push(locked_secret(&PERSON, &LOCK, name).unwrap());
            // A lock whose key is the person secret, and the other way
            // round, are other channels again.
            secrets.push(locked_secret(&PERSON, &PERSON, name).unwrap());
            secrets.push(locked_secret(&LOCK, &PERSON, name).unwrap());
            secrets.push(own_secret(&LOCK, name).unwrap());
        }
        secrets.push(pair_secret(&a, &b.public_key()).unwrap());
        secrets.push(personal_secret(&LOCK).unwrap());

        let distinct: HashSet<[u8; 32]> = secrets.iter().copied().collect();
        assert_eq!(distinct.len(), secrets.len());
        assert_eq!(secrets.len(), 4 + 5 * names.len());

        // Nor are their channels the same: each secret has its own ID.
        let ids: HashSet<[u8; 32]> = secrets
            .iter()
            .map(|secret| channel_id(secret).unwrap())
            .collect();
        assert_eq!(ids.len(), secrets.len());
    }

    /// The messages channel is derived from the person secret alone, under
    /// its own label (decision 2026-10-09 §2.1): another person secret
    /// gives another, and it is neither the personal channel nor the
    /// channel of any name, the name `messages` among them.
    #[test]
    fn the_messages_channel_is_derived_from_the_person_secret_alone() {
        let messages = messages_secret(&PERSON).unwrap();
        assert_eq!(
            messages,
            hkdf_sha256(&PERSON, &[], b"cordelia v2 messages").unwrap()
        );
        assert_ne!(messages, messages_secret(&LOCK).unwrap());
        assert_ne!(messages, personal_secret(&PERSON).unwrap());
        for name in ["~", "messages", "msg", "github.com/owner/repo"] {
            assert_ne!(messages, own_secret(&PERSON, name).unwrap(), "{name}");
        }
        assert_ne!(
            channel_id(&messages).unwrap(),
            channel_id(&personal_secret(&PERSON).unwrap()).unwrap()
        );
    }

    /// The name's length goes before it, as two bytes, the higher first.
    #[test]
    fn a_name_is_prefixed_with_its_length_as_two_bytes() {
        let long = "n".repeat(258);
        for (name, length) in [
            ("~", [0u8, 1]),
            ("ab", [0, 2]),
            ("github.com/owner/repo", [0, 21]),
            (long.as_str(), [1, 2]),
        ] {
            let mut info = b"cordelia v2 own".to_vec();
            info.extend_from_slice(&length);
            info.extend_from_slice(name.as_bytes());
            assert_eq!(
                own_secret(&PERSON, name).unwrap(),
                hkdf_sha256(&PERSON, &[], &info).unwrap(),
                "{name}"
            );

            let mut info = b"cordelia v2 locked".to_vec();
            info.extend_from_slice(&length);
            info.extend_from_slice(name.as_bytes());
            let mut together = PERSON.to_vec();
            together.extend_from_slice(&LOCK);
            assert_eq!(
                locked_secret(&PERSON, &LOCK, name).unwrap(),
                hkdf_sha256_of(&together, &[], &info).unwrap(),
                "{name}"
            );
        }
        // Without the length, a name that ends where another begins would
        // give the same input: with it, it does not.
        assert_ne!(
            own_secret(&PERSON, "a").unwrap(),
            hkdf_sha256(&PERSON, &[], b"cordelia v2 owna").unwrap()
        );
        // The longest name that two bytes can count, and one byte more.
        let longest = "n".repeat(65_535);
        assert!(own_secret(&PERSON, &longest).is_ok());
        assert!(locked_secret(&PERSON, &LOCK, &longest).is_ok());
        let over = "n".repeat(65_536);
        assert!(matches!(
            own_secret(&PERSON, &over),
            Err(DeriveError::NameTooLong(65_536))
        ));
        assert!(matches!(
            locked_secret(&PERSON, &LOCK, &over),
            Err(DeriveError::NameTooLong(65_536))
        ));
    }

    /// A name has one spelling. Another spelling would be another channel,
    /// so nothing is derived for it.
    #[test]
    fn a_name_that_is_not_in_its_one_spelling_has_no_channel() {
        for name in ["Team", " team", "team ", "repo.git", "owner/repo/", "x.GIT"] {
            assert!(
                matches!(own_secret(&PERSON, name), Err(DeriveError::NameNotTidy)),
                "{name:?}"
            );
            assert!(
                matches!(
                    locked_secret(&PERSON, &LOCK, name),
                    Err(DeriveError::NameNotTidy)
                ),
                "{name:?}"
            );
            // Tidied, it has one.
            let tidy = sync_name::tidy(name);
            assert!(own_secret(&PERSON, &tidy).is_ok(), "{name:?}");
        }
        assert!(matches!(
            own_secret(&PERSON, ""),
            Err(DeriveError::NameEmpty)
        ));
        assert!(matches!(
            locked_secret(&PERSON, &LOCK, ""),
            Err(DeriveError::NameEmpty)
        ));
    }

    #[test]
    fn a_pair_channel_is_the_same_from_either_side() {
        let a = device(1);
        let b = device(2);
        let c = device(3);
        let ab = pair_secret(&a, &b.public_key()).unwrap();
        assert_eq!(pair_secret(&b, &a.public_key()).unwrap(), ab);

        // One secret for each pair.
        let ac = pair_secret(&a, &c.public_key()).unwrap();
        let bc = pair_secret(&b, &c.public_key()).unwrap();
        assert_eq!(pair_secret(&c, &a.public_key()).unwrap(), ac);
        assert_eq!(pair_secret(&c, &b.public_key()).unwrap(), bc);
        assert_eq!(HashSet::from([ab, ac, bc]).len(), 3);

        // What it is: X25519 of the two, under the label and the two public
        // keys, the lower first.
        for (one, other) in [(&a, &b), (&a, &c), (&b, &c)] {
            let (private, _) = x25519_from_ed25519_seed(one.seed());
            let (_, public) = x25519_from_ed25519_seed(other.seed());
            let shared = StaticSecret::from(private).diffie_hellman(&PublicKey::from(public));
            let mut keys = [one.public_key(), other.public_key()];
            keys.sort_unstable();
            let mut info = b"cordelia v2 pair".to_vec();
            info.extend_from_slice(&keys[0]);
            info.extend_from_slice(&keys[1]);
            assert_eq!(
                pair_secret(one, &other.public_key()).unwrap(),
                hkdf_sha256(shared.as_bytes(), &[], &info).unwrap()
            );
        }
    }

    /// A device has no pair channel with itself, nor with a key that is no
    /// device's: a point of small order (the all-zero bytes are one), a
    /// real key with one of those added, and bytes that are not a point.
    #[test]
    fn a_pair_channel_needs_two_usable_keys() {
        use curve25519_dalek::constants::EIGHT_TORSION;
        use curve25519_dalek::edwards::CompressedEdwardsY;

        let a = device(1);
        assert!(matches!(
            pair_secret(&a, &a.public_key()),
            Err(DeriveError::OwnKey)
        ));

        let mut bad: Vec<[u8; 32]> = EIGHT_TORSION
            .iter()
            .map(|point| point.compress().to_bytes())
            .collect();
        let real = CompressedEdwardsY(device(2).public_key())
            .decompress()
            .unwrap();
        bad.extend(
            EIGHT_TORSION[1..]
                .iter()
                .map(|torsion| (real + torsion).compress().to_bytes()),
        );
        bad.push(
            (0u8..=255)
                .map(|first| {
                    let mut key = [0x42; 32];
                    key[0] = first;
                    key
                })
                .find(|key| CompressedEdwardsY(*key).decompress().is_none())
                .unwrap(),
        );
        assert_eq!(bad.len(), 16);
        for key in bad {
            assert!(
                matches!(pair_secret(&a, &key), Err(DeriveError::KeyNotUsable)),
                "{key:02x?}"
            );
        }
        // The control: the real key those were made from.
        assert!(pair_secret(&a, &device(2).public_key()).is_ok());
    }

    /// The secret that two keys give is all zero where one of them is of
    /// small order, whoever holds the other. No channel is derived from it.
    #[test]
    fn a_pair_secret_that_anyone_can_work_out_is_refused() {
        use curve25519_dalek::constants::EIGHT_TORSION;

        let a = device(1);
        let b = device(2);
        let (a_private, _) = x25519_from_ed25519_seed(a.seed());
        let (_, b_public) = x25519_from_ed25519_seed(b.seed());

        let mut small: Vec<[u8; 32]> = EIGHT_TORSION
            .iter()
            .map(|point| point.to_montgomery().to_bytes())
            .collect();
        small.push([0u8; 32]);
        for key in small {
            assert!(
                matches!(
                    pair_secret_from(&a_private, &key, &a.public_key(), &b.public_key()),
                    Err(DeriveError::SecretAnyoneCanWorkOut)
                ),
                "{key:02x?}"
            );
        }
        // The control: the same call with the other device's real key is
        // the pair's secret.
        assert_eq!(
            pair_secret_from(&a_private, &b_public, &a.public_key(), &b.public_key()).unwrap(),
            pair_secret(&a, &b.public_key()).unwrap()
        );
    }

    /// A locked channel needs both the person secret and the lock's key: a
    /// device with one of them derives another channel, and so does one
    /// that puts them the other way round.
    #[test]
    fn a_locked_channel_is_derived_from_the_person_secret_and_the_locks_key() {
        let locked = locked_secret(&PERSON, &LOCK, "notes").unwrap();
        assert_ne!(
            locked,
            locked_secret(&PERSON, &[0x34; 32], "notes").unwrap()
        );
        assert_ne!(locked, locked_secret(&[0x23; 32], &LOCK, "notes").unwrap());
        assert_ne!(locked, locked_secret(&LOCK, &PERSON, "notes").unwrap());
        assert_ne!(locked, locked_secret(&PERSON, &LOCK, "note").unwrap());
        assert_ne!(locked, own_secret(&PERSON, "notes").unwrap());

        let mut together = PERSON.to_vec();
        together.extend_from_slice(&LOCK);
        assert_eq!(
            locked,
            hkdf_sha256_of(&together, &[], b"cordelia v2 locked\x00\x05notes").unwrap()
        );
    }
}
