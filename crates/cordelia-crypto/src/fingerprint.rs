//! A key's fingerprint, in words (decision 2026-10-04 §6).
//!
//! A label is whatever the device that added a key called it, and two keys
//! can have one label. So wherever a device is shown for a decision, the
//! first words of its key's fingerprint are shown beside its label: what a
//! person can read aloud, or hold beside what another screen shows.
//!
//! The fingerprint is SHA-256 of a label of its own and the key. Its words
//! are from the list that a recovery phrase uses, eleven bits to a word,
//! from the hash's first bit on. They are not a recovery phrase and make
//! none: they have no checksum, and they say nothing that the key does
//! not.

use bip39::Language;
use cordelia_core::protocol::{FINGERPRINT_WORDS_SHOWN, LABEL_FINGERPRINT};
use sha2::{Digest, Sha256};

/// The bits of one word.
const WORD_BITS: usize = 11;

/// The most words a fingerprint has: as many as its 256 bits fill.
pub const MAX_WORDS: usize = 256 / WORD_BITS;

/// The fingerprint of `key`: SHA-256 of the fingerprint's label and the
/// key.
pub fn fingerprint(key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LABEL_FINGERPRINT);
    hasher.update(key);
    hasher.finalize().into()
}

/// The first `count` words of the fingerprint of `key`, with one space
/// between them. No more than [`MAX_WORDS`] are given, whatever is asked.
pub fn words(key: &[u8; 32], count: usize) -> String {
    let hash = fingerprint(key);
    let list = Language::English.word_list();
    let mut said = String::new();
    for word in 0..count.min(MAX_WORDS) {
        // Eleven bits, from bit `word * 11` on, the highest first.
        let mut index = 0usize;
        for bit in word * WORD_BITS..(word + 1) * WORD_BITS {
            let set = hash[bit / 8] >> (7 - bit % 8) & 1;
            index = index << 1 | usize::from(set);
        }
        if word > 0 {
            said.push(' ');
        }
        said.push_str(list[index]);
    }
    said
}

/// The words of the fingerprint of `key` that are shown beside a label:
/// the first four.
pub fn shown(key: &[u8; 32]) -> String {
    words(key, FINGERPRINT_WORDS_SHOWN)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fingerprint is SHA-256 of its label and the key, and its words
    /// are eleven bits each from the first bit on: a vector, worked by
    /// hand from the hash.
    #[test]
    fn test_a_fingerprint_is_the_hash_of_its_label_and_the_key_in_words() {
        let key = [7u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"cordelia v2 fingerprint");
        hasher.update(key);
        let hash: [u8; 32] = hasher.finalize().into();
        assert_eq!(fingerprint(&key), hash);

        let list = Language::English.word_list();
        let first = usize::from(hash[0]) << 3 | usize::from(hash[1]) >> 5;
        let second = (usize::from(hash[1]) & 0x1f) << 6 | usize::from(hash[2]) >> 2;
        let said = words(&key, 2);
        assert_eq!(said, format!("{} {}", list[first], list[second]));
        // Another label would give other words.
        let mut other = Sha256::new();
        other.update(b"cordelia v2 commitment");
        other.update(key);
        let other: [u8; 32] = other.finalize().into();
        assert_ne!(hash, other);
    }

    /// Four words are shown, each of the list, and more words begin with
    /// fewer: six begin with the four that are shown.
    #[test]
    fn test_four_words_are_shown_and_more_words_begin_with_fewer() {
        let list = Language::English.word_list();
        for n in 0..32u8 {
            let key = [n; 32];
            let four = shown(&key);
            let each: Vec<&str> = four.split(' ').collect();
            assert_eq!(each.len(), 4, "{four}");
            assert!(each.iter().all(|word| list.contains(word)), "{four}");
            assert_eq!(four, words(&key, 4));
            let six = words(&key, 6);
            assert_eq!(six.split(' ').count(), 6);
            assert!(six.starts_with(&format!("{four} ")), "{six}");
        }
        assert_eq!(words(&[1; 32], 0), "");
        // No more than the hash has bits for.
        assert_eq!(MAX_WORDS, 23);
        assert_eq!(words(&[1; 32], 99).split(' ').count(), 23);
    }

    /// Two keys have two fingerprints: of 256 keys that differ in one
    /// byte, no two are shown by the same four words.
    #[test]
    fn test_keys_that_differ_are_shown_by_other_words() {
        let mut seen = std::collections::HashSet::new();
        for n in 0..=255u8 {
            let mut key = [0x5a; 32];
            key[31] = n;
            assert!(seen.insert(shown(&key)), "{n}");
        }
    }
}
