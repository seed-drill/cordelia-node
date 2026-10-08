//! The recovery phrase (decision 2026-10-04 §5).
//!
//! Twelve words from the BIP39 English list: 128 bits and a checksum, so
//! that a mistyped word is caught. What comes from the phrase is derived
//! from the 16 bytes that the words encode, with HKDF-SHA256, each thing
//! under a label of its own:
//!
//! - the signing key, which signs statements and the change entry;
//! - the secret of the phrase's channel, where the change entry is;
//! - the statement key, which every device that follows the phrase is
//!   given, and which the part of a change entry for the devices is under;
//! - the key that seals the part of a change entry that is for the phrase,
//!   which only the phrase gives.
//!
//! A device keeps none of the words. A [`Phrase`] is held by the command
//! that was given them, for as long as it signs and seals. It is
//! overwritten when it is dropped, and nothing prints it but
//! [`Phrase::words`].
//!
//! **Everything that comes from the phrase is overwritten with it**
//! (decision 2026-10-04 §16): each of the secrets below is given back in
//! memory that is overwritten when it is dropped, and so is the signing
//! key, with its seed and the form of it that the signing code is given.

use std::fmt;

use bip39::{Language, Mnemonic};
use cordelia_core::protocol::{
    LABEL_PHRASE_SEAL, LABEL_PHRASE_SIGN, LABEL_PHRASE_STATEMENT, LABEL_RECOVERY, PHRASE_BYTES,
    PHRASE_WORDS,
};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::{Zeroize, Zeroizing};

use crate::CryptoError;
use crate::ecies::hkdf_sha256_wiped;
use crate::identity::NodeIdentity;

/// Why what was typed is not a recovery phrase. It says which word, by its
/// place, and never the word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PhraseError {
    #[error("a recovery phrase is twelve words, and this is {0}")]
    WordCount(usize),

    #[error("word {0} is not a word that a recovery phrase can have")]
    UnknownWord(usize),

    #[error("these words are not a recovery phrase: at least one of them is not the word it was")]
    Checksum,
}

/// A recovery phrase: the 16 bytes that its twelve words encode.
///
/// The bytes are overwritten when the value is dropped. It cannot be
/// copied, and printing it for debugging shows nothing of it.
pub struct Phrase {
    bytes: [u8; PHRASE_BYTES],
}

impl Drop for Phrase {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl Phrase {
    /// Make a new phrase, from the system's random numbers.
    pub fn generate() -> Result<Self, CryptoError> {
        // Filled where it is, so that no copy of the bytes is made on the
        // way that is not overwritten.
        let mut phrase = Self {
            bytes: [0u8; PHRASE_BYTES],
        };
        SystemRandom::new()
            .fill(&mut phrase.bytes)
            .map_err(|_| CryptoError::KeyDerivationFailed("RNG failure".into()))?;
        Ok(phrase)
    }

    /// Read a phrase as a person typed it: twelve words of the list, in
    /// lower case, with space of any kind between and around them.
    ///
    /// A word that is not in the list is refused, with its place. Words
    /// that are each in the list and are not a phrase together are refused
    /// by the checksum: 15 of every 16 phrases with a wrong word are.
    pub fn parse(words: &str) -> Result<Self, PhraseError> {
        let count = words.split_whitespace().count();
        if count != PHRASE_WORDS {
            return Err(PhraseError::WordCount(count));
        }
        let mnemonic =
            Mnemonic::parse_in_normalized(Language::English, words).map_err(|e| match e {
                bip39::Error::UnknownWord(at) => PhraseError::UnknownWord(at + 1),
                bip39::Error::BadWordCount(count) => PhraseError::WordCount(count),
                // The checksum, or anything else that is not a phrase.
                _ => PhraseError::Checksum,
            })?;
        let (mut encoded, _) = mnemonic.to_entropy_array();
        let mut phrase = Self {
            bytes: [0u8; PHRASE_BYTES],
        };
        phrase.bytes.copy_from_slice(&encoded[..PHRASE_BYTES]);
        encoded.zeroize();
        Ok(phrase)
    }

    /// The twelve words, with one space between them, to show once. The
    /// text is overwritten when it is dropped.
    pub fn words(&self) -> Result<Zeroizing<String>, CryptoError> {
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &self.bytes)
            .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
        // Room for twelve of the longest words, which are eight letters,
        // and the spaces: the text is never moved as it grows, so no copy
        // of it is left behind.
        let mut words = Zeroizing::new(String::with_capacity(PHRASE_WORDS * 9));
        for (i, word) in mnemonic.words().enumerate() {
            if i > 0 {
                words.push(' ');
            }
            words.push_str(word);
        }
        Ok(words)
    }

    /// The phrase's signing key: an Ed25519 key pair. It signs statements,
    /// and the change entry as its author. It is overwritten when it is
    /// dropped, as every key pair is ([`NodeIdentity`]).
    pub fn signing_key(&self) -> Result<NodeIdentity, CryptoError> {
        NodeIdentity::from_wiped_seed(&self.derived(LABEL_PHRASE_SIGN)?)
    }

    /// The public half of the phrase's signing key: the key a device
    /// follows.
    pub fn public_key(&self) -> Result<[u8; 32], CryptoError> {
        Ok(self.signing_key()?.public_key())
    }

    /// The secret of the phrase's channel (decision 2026-10-04 §2.2). Its
    /// keys and its ID are derived from it as any channel's are
    /// ([`crate::derive`]).
    pub fn channel_secret(&self) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        self.derived(LABEL_RECOVERY)
    }

    /// The statement key (decision 2026-10-04 §4.6). It never changes, and
    /// every device that follows the phrase is given it.
    pub fn statement_key(&self) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        self.derived(LABEL_PHRASE_STATEMENT)
    }

    /// The key that seals the part of a change entry that is for the
    /// phrase (decision 2026-10-04 §4.6). No device is given it.
    pub fn seal_key(&self) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        self.derived(LABEL_PHRASE_SEAL)
    }

    /// What the phrase gives under `label`, in memory that is overwritten
    /// when it is dropped.
    fn derived(&self, label: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        hkdf_sha256_wiped(&self.bytes, &[], label)
    }
}

impl fmt::Debug for Phrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Phrase(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive;
    use std::collections::HashSet;

    /// The 128-bit vectors of BIP39's reference implementation.
    const VECTORS: [(&str, &str); 4] = [
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon about",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        ),
        (
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ),
    ];

    const LEGAL: &str = VECTORS[1].1;

    fn bytes_of(phrase: &Phrase) -> [u8; PHRASE_BYTES] {
        phrase.bytes
    }

    #[test]
    fn the_words_and_the_bytes_are_those_of_bip39() {
        for (bytes, words) in VECTORS {
            let phrase = Phrase::parse(words).unwrap();
            assert_eq!(hex::encode(bytes_of(&phrase)), bytes);
            assert_eq!(phrase.words().unwrap().as_str(), words);
        }
    }

    #[test]
    fn a_new_phrase_is_twelve_words_of_the_list_and_reads_back() {
        let list = Language::English.word_list();
        let mut seen = HashSet::new();
        for _ in 0..32 {
            let phrase = Phrase::generate().unwrap();
            let words = phrase.words().unwrap();
            let each: Vec<&str> = words.split(' ').collect();
            assert_eq!(each.len(), 12);
            assert!(each.iter().all(|word| list.contains(word)));
            assert!(words.len() <= PHRASE_WORDS * 9);

            let typed = Phrase::parse(&words).unwrap();
            assert_eq!(bytes_of(&typed), bytes_of(&phrase));
            assert!(seen.insert(bytes_of(&phrase)), "the same phrase twice");
        }
    }

    #[test]
    fn a_word_that_is_not_in_the_list_is_refused_with_its_place() {
        let words: Vec<&str> = LEGAL.split(' ').collect();
        for place in 0..12 {
            for wrong in ["legul", "Legal", "LEGAL", "legal,", "0x7f", "zoö"] {
                let mut typed = words.clone();
                typed[place] = wrong;
                let refused = Phrase::parse(&typed.join(" ")).unwrap_err();
                assert_eq!(refused, PhraseError::UnknownWord(place + 1), "{wrong}");
                // It says where, and not what was typed.
                assert!(!refused.to_string().contains(wrong));
            }
        }
        // The first wrong word is the one named.
        assert_eq!(
            Phrase::parse(
                "legal winner thnk year wave sausage worth useful legal winner thank yelow"
            )
            .unwrap_err(),
            PhraseError::UnknownWord(3)
        );
    }

    /// A wrong word that is itself in the list is caught by the checksum.
    /// Four bits check 128, so of the 2048 words that can stand last, 128
    /// make a phrase: the right one, and 127 that are other phrases.
    #[test]
    fn a_wrong_word_of_the_list_is_refused_by_the_checksum() {
        for wrong in [
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon",
            "winner legal thank year wave sausage worth useful legal winner thank yellow",
            "legal winner thank year wave sausage worth useful legal winner thank year",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo",
        ] {
            assert_eq!(Phrase::parse(wrong).unwrap_err(), PhraseError::Checksum);
        }

        let right = Phrase::parse(LEGAL).unwrap();
        let begins = LEGAL.rsplit_once(' ').unwrap().0;
        let mut phrases = 0;
        for last in Language::English.word_list() {
            match Phrase::parse(&format!("{begins} {last}")) {
                Ok(phrase) => {
                    phrases += 1;
                    assert_eq!(bytes_of(&phrase) == bytes_of(&right), *last == "yellow");
                }
                Err(refused) => assert_eq!(refused, PhraseError::Checksum),
            }
        }
        assert_eq!(phrases, 128);
    }

    /// A phrase is twelve words. Fewer or more are refused, and so are the
    /// longer phrases that BIP39 also has.
    #[test]
    fn a_phrase_of_another_length_is_refused() {
        let words: Vec<&str> = LEGAL.split(' ').collect();
        assert_eq!(Phrase::parse("").unwrap_err(), PhraseError::WordCount(0));
        assert_eq!(Phrase::parse("  ").unwrap_err(), PhraseError::WordCount(0));
        for count in [1, 6, 11] {
            assert_eq!(
                Phrase::parse(&words[..count].join(" ")).unwrap_err(),
                PhraseError::WordCount(count)
            );
        }
        assert_eq!(
            Phrase::parse(&format!("{LEGAL} yellow")).unwrap_err(),
            PhraseError::WordCount(13)
        );
        // 15, 18 and 24 words, each a phrase of BIP39.
        for (count, longer) in [
            (
                15,
                Mnemonic::from_entropy_in(Language::English, &[0x7f; 20]).unwrap(),
            ),
            (
                18,
                Mnemonic::from_entropy_in(Language::English, &[0x7f; 24]).unwrap(),
            ),
            (
                24,
                Mnemonic::from_entropy_in(Language::English, &[0x7f; 32]).unwrap(),
            ),
        ] {
            let text = longer.to_string();
            assert!(Mnemonic::parse_in_normalized(Language::English, &text).is_ok());
            assert_eq!(
                Phrase::parse(&text).unwrap_err(),
                PhraseError::WordCount(count)
            );
        }
    }

    #[test]
    fn the_words_may_have_any_space_between_and_around_them() {
        let right = bytes_of(&Phrase::parse(LEGAL).unwrap());
        let typed = format!("  {}\n", LEGAL.replace(' ', "  \t\n "));
        assert_eq!(bytes_of(&Phrase::parse(&typed).unwrap()), right);
    }

    /// Each label, spelled here as it is published: a change to a label, or
    /// to what the phrase's bytes are, fails here. The key material is the
    /// 16 bytes that the words encode, and nothing made from the words by
    /// another road.
    #[test]
    fn each_thing_from_a_phrase_is_derived_under_its_own_label() {
        let phrase = Phrase::parse(LEGAL).unwrap();
        let under = |label: &[u8]| crate::hkdf_sha256_of(&[0x7f; 16], &[], label).unwrap();
        assert_eq!(
            phrase.signing_key().unwrap().seed(),
            &under(b"cordelia v2 phrase sign")
        );
        assert_eq!(
            *phrase.channel_secret().unwrap(),
            under(b"cordelia v2 recovery")
        );
        assert_eq!(
            *phrase.statement_key().unwrap(),
            under(b"cordelia v2 phrase statement")
        );
        assert_eq!(
            *phrase.seal_key().unwrap(),
            under(b"cordelia v2 phrase seal")
        );
        assert_eq!(
            phrase.public_key().unwrap(),
            phrase.signing_key().unwrap().public_key()
        );

        // Four things from one phrase, and four others from another.
        let of = |phrase: &Phrase| {
            [
                *phrase.signing_key().unwrap().seed(),
                *phrase.channel_secret().unwrap(),
                *phrase.statement_key().unwrap(),
                *phrase.seal_key().unwrap(),
            ]
        };
        let mut all = HashSet::new();
        for (_, words) in VECTORS {
            all.extend(of(&Phrase::parse(words).unwrap()));
        }
        assert_eq!(all.len(), 16);
    }

    /// The phrase's channel has a signing key of its own, as every channel
    /// has. The change entry is signed twice: by the phrase's key, as its
    /// author, and by its channel's.
    #[test]
    fn the_phrases_channel_has_a_key_of_its_own() {
        let phrase = Phrase::parse(LEGAL).unwrap();
        let channel = phrase.channel_secret().unwrap();
        let id = derive::channel_id(&channel).unwrap();
        assert_ne!(id, phrase.public_key().unwrap());
        assert_eq!(id, derive::signing_key(&channel).unwrap().public_key());
    }

    #[test]
    fn a_phrase_prints_nothing_of_itself() {
        let phrase = Phrase::parse(LEGAL).unwrap();
        let printed = format!("{phrase:?} {:#?}", Some(&phrase));
        assert_eq!(printed, "Phrase(..) Some(\n    Phrase(..),\n)");
        for word in LEGAL.split(' ') {
            assert!(!printed.contains(word), "{word}");
        }
        assert!(!printed.contains("7f") && !printed.contains("127"));
    }

    /// What is left where a value was, once it has been dropped.
    fn left_by<T>(value: T) -> Vec<u8> {
        use std::mem::MaybeUninit;
        let mut place = MaybeUninit::new(value);
        let at = place.as_mut_ptr();
        // SAFETY: `place` holds a value, which is dropped here once and
        // never used again. `place` is as large as the value and outlives
        // the read, and it is read as bytes: each type this is called
        // with is made of bytes alone, with no padding.
        unsafe {
            std::ptr::drop_in_place(at);
            std::slice::from_raw_parts(at.cast::<u8>(), size_of::<T>()).to_vec()
        }
    }

    /// Everything that comes from a phrase is overwritten when it is
    /// dropped (decision 2026-10-04 §16): the secret of its channel, the
    /// statement key, the key that seals the part for the phrase, and the
    /// signing key, with its seed and the key pair made of it.
    #[test]
    fn what_comes_from_a_phrase_is_overwritten_when_it_is_dropped() {
        let phrase = Phrase::parse(LEGAL).unwrap();
        for (what, secret) in [
            ("the channel's secret", phrase.channel_secret().unwrap()),
            ("the statement key", phrase.statement_key().unwrap()),
            ("the seal key", phrase.seal_key().unwrap()),
        ] {
            assert_ne!(*secret, [0u8; 32], "{what}");
            assert_eq!(left_by(secret), [0u8; 32], "{what}");
        }

        // The signing key: 32 bytes of seed, and a key pair of three
        // times 32 bytes, which holds the secret scalar that the seed
        // gives.
        let key = phrase.signing_key().unwrap();
        let seed = *key.seed();
        assert_eq!(size_of::<NodeIdentity>(), 4 * 32);
        let has = |bytes: &[u8], what: &[u8]| bytes.windows(what.len()).any(|at| at == what);
        // SAFETY: the key is alive, as large as its type, and made of
        // bytes alone.
        let alive = unsafe {
            std::slice::from_raw_parts((&raw const key).cast::<u8>(), size_of::<NodeIdentity>())
        }
        .to_vec();
        assert!(has(&alive, &seed), "the seed is in a key that is alive");
        assert!(alive.iter().filter(|byte| **byte != 0).count() > 64);
        assert_eq!(left_by(key), [0u8; 4 * 32]);
        // The control: the same bytes with nothing to overwrite them are
        // still there after a drop.
        assert_eq!(left_by(seed), seed);
    }

    /// The bytes of a phrase are overwritten when it is dropped: where the
    /// phrase was, nothing of it is left.
    #[test]
    fn a_phrase_is_overwritten_when_it_is_dropped() {
        assert_eq!(size_of::<Phrase>(), PHRASE_BYTES);
        let phrase = Phrase::parse(LEGAL).unwrap();
        assert_eq!(bytes_of(&phrase), [0x7f; PHRASE_BYTES]);
        assert_eq!(left_by(phrase), [0u8; PHRASE_BYTES]);
        // The control: the same bytes with nothing to overwrite them are
        // still there after a drop, so the phrase's were overwritten.
        assert_eq!(left_by([0x7f_u8; PHRASE_BYTES]), [0x7f; PHRASE_BYTES]);
    }
}
