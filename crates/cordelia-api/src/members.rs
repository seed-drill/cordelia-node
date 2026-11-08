//! A repository's list of the devices whose agents share its channel
//! (decision 2026-11-06 (joining), rule 1): the file `.cordelia/members`,
//! read; the gate that a list makes on its own; and the channel line, as a
//! making anew prints it.
//!
//! - **The file** ([`read`]): ASCII and line feeds only, at most
//!   [`MEMBERS_FILE_MAX_BYTES`]. A line that starts with `#`, and an empty
//!   line, are skipped. Words are parted by one or more spaces.
//! - **One `channel` line, or none:** `channel`, the channel's ID in
//!   lower-case hex, the key of each of its relays (one or two), then
//!   `without`, the number of keys that follow, and those keys. A line
//!   whose number does not match its keys does not parse, so a line cut
//!   short does nothing.
//! - **A line for each device:** its key as `cordelia id` prints it, and a
//!   label of 1 to [`MEMBERS_LABEL_MAX_CHARS`] characters of `a-z`, `0-9`,
//!   `.`, `_` and `-`. Keys are unique, and so are labels; at most
//!   [`SHARED_MAX_KEYS`] devices. The keys after `without` do not count
//!   among them.
//! - **A file that does not parse** gives [`NotAList`], naming its line,
//!   and nothing of it is taken.
//! - **The gate** ([`Members::gated`]): a key the list names as a device,
//!   that its channel line names after `without`, and that is not in the
//!   channel. While any is, the list names no channel
//!   ([`Members::names`]).

use cordelia_core::protocol::{
    MEMBERS_FILE_MAX_BYTES, MEMBERS_LABEL_MAX_CHARS, SHARED_MAX_KEYS, SHARED_MAX_RELAYS,
};
use cordelia_crypto::bech32::{decode_public_key, encode_public_key};
use cordelia_crypto::identity::is_usable_public_key;

/// The channel a list names, its relays, and the keys a making anew left
/// out of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelLine {
    pub channel: [u8; 32],
    pub relays: Vec<[u8; 32]>,
    pub without: Vec<[u8; 32]>,
}

/// One device's line: its key and its label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub key: [u8; 32],
    pub label: String,
}

/// A list as it was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Members {
    /// The channel line, where the list has one.
    pub channel: Option<ChannelLine>,
    /// The devices, in the list's order.
    pub devices: Vec<Device>,
}

/// Why a file is not a list, and the line that says so: counted from 1,
/// and 0 for the whole file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotAList {
    pub line: usize,
    pub why: &'static str,
}

impl std::fmt::Display for NotAList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.line {
            0 => write!(f, "the list {}", self.why),
            line => write!(f, "line {line} of the list {}", self.why),
        }
    }
}

const TOO_LARGE: &str = "is larger than 16 KiB";
const NOT_PLAIN: &str = "has a character that is not plain ASCII text";
const TAB: &str = "has a tab: part words with spaces";
const CARRIAGE: &str = "has a carriage return: save the file with line feeds only";
const COMMENT_AFTER: &str = "has a comment after its words: a comment takes a line of its own";
const SECOND_CHANNEL: &str = "is a second channel line";
const NOT_A_CHANNEL: &str = "does not give a channel's ID: 64 lower-case hex characters";
const RELAYS: &str = "does not give one or two relays' keys before without";
const NO_WITHOUT: &str = "does not end with without and a count";
const NOT_A_COUNT: &str = "does not give a count after without";
const COUNT: &str = "does not give as many keys after without as its count says";
const NOT_A_KEY: &str = "gives a key that is not one, as cordelia id prints a key";
const KEY_TWICE: &str = "gives a key a second time";
const DEVICE_LINE: &str = "is not a key and a label";
const LABEL: &str = "gives a label that is not 1 to 32 of a-z, 0-9, . _ and -";
const LABEL_TWICE: &str = "gives a label a second time";
const TOO_MANY: &str = "names more than 64 devices";

// The words above spell these numbers out.
const _: () = assert!(
    MEMBERS_FILE_MAX_BYTES == 16_384 && SHARED_MAX_KEYS == 64 && MEMBERS_LABEL_MAX_CHARS == 32
);

/// The file `file`, read as a list (rule 1).
pub fn read(file: &[u8]) -> Result<Members, NotAList> {
    let not = |line: usize, why| NotAList { line, why };
    if file.len() > MEMBERS_FILE_MAX_BYTES {
        return Err(not(0, TOO_LARGE));
    }
    let mut members = Members {
        channel: None,
        devices: Vec::new(),
    };
    for (index, line) in file.split(|byte| *byte == b'\n').enumerate() {
        let number = index + 1;
        if let Some(byte) = line.iter().find(|byte| !(0x20..=0x7e).contains(*byte)) {
            return Err(not(
                number,
                match byte {
                    b'\t' => TAB,
                    b'\r' => CARRIAGE,
                    _ => NOT_PLAIN,
                },
            ));
        }
        // Only ASCII is left, so the line is UTF-8.
        let line = std::str::from_utf8(line).map_err(|_| not(number, NOT_PLAIN))?;
        let words: Vec<&str> = line.split(' ').filter(|word| !word.is_empty()).collect();
        let Some(first) = words.first() else {
            continue;
        };
        if first.starts_with('#') {
            continue;
        }
        if words[1..].iter().any(|word| word.starts_with('#')) {
            return Err(not(number, COMMENT_AFTER));
        }
        if *first == "channel" {
            if members.channel.is_some() {
                return Err(not(number, SECOND_CHANNEL));
            }
            members.channel = Some(channel_line(&words[1..]).map_err(|why| not(number, why))?);
            continue;
        }
        let [key, label] = words[..] else {
            return Err(not(number, DEVICE_LINE));
        };
        let key = key_of(key).ok_or(not(number, NOT_A_KEY))?;
        if !is_a_label(label) {
            return Err(not(number, LABEL));
        }
        if members
            .devices
            .iter()
            .any(|device| same_key(&device.key, &key))
        {
            return Err(not(number, KEY_TWICE));
        }
        if members.devices.iter().any(|device| device.label == label) {
            return Err(not(number, LABEL_TWICE));
        }
        if members.devices.len() == SHARED_MAX_KEYS {
            return Err(not(number, TOO_MANY));
        }
        members.devices.push(Device {
            key,
            label: label.to_string(),
        });
    }
    Ok(members)
}

/// The words of a channel line after `channel`.
fn channel_line(words: &[&str]) -> Result<ChannelLine, &'static str> {
    let (id, rest) = words.split_first().ok_or(NOT_A_CHANNEL)?;
    let channel = channel_id(id).ok_or(NOT_A_CHANNEL)?;
    let at = rest.iter().position(|word| *word == "without");
    let Some(at) = at else {
        // A line cut short, or one whose relays are not keys.
        return match rest.iter().all(|word| key_of(word).is_some()) {
            true => Err(NO_WITHOUT),
            false => Err(NOT_A_KEY),
        };
    };
    let relays: Vec<[u8; 32]> = rest[..at]
        .iter()
        .map(|word| key_of(word))
        .collect::<Option<_>>()
        .ok_or(NOT_A_KEY)?;
    if relays.is_empty() || relays.len() > SHARED_MAX_RELAYS {
        return Err(RELAYS);
    }
    if relays.len() == 2 && same_key(&relays[0], &relays[1]) {
        return Err(KEY_TWICE);
    }
    let (count, keys) = rest[at + 1..].split_first().ok_or(NOT_A_COUNT)?;
    let count = count_of(count).ok_or(NOT_A_COUNT)?;
    if count != keys.len() {
        return Err(COUNT);
    }
    let mut without: Vec<[u8; 32]> = Vec::with_capacity(keys.len());
    for word in keys {
        let key = key_of(word).ok_or(NOT_A_KEY)?;
        if without.iter().any(|kept| same_key(kept, &key)) {
            return Err(KEY_TWICE);
        }
        without.push(key);
    }
    Ok(ChannelLine {
        channel,
        relays,
        without,
    })
}

/// A key in the one spelling `cordelia id` prints, and usable as a key.
fn key_of(word: &str) -> Option<[u8; 32]> {
    let key = decode_public_key(word).ok()?;
    (encode_public_key(&key).ok()? == word && is_usable_public_key(&key)).then_some(key)
}

/// Whether two keys are one, or each other's twin: a key with its top bit
/// flipped is another key to Ed25519, but the same key to X25519, from
/// which a share's pair is derived. So a twin counts as the key itself,
/// for a key twice and for the gate.
pub fn same_key(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a[..31] == b[..31] && (a[31] & 0x7f) == (b[31] & 0x7f)
}

/// A channel's ID: 64 lower-case hex characters.
fn channel_id(word: &str) -> Option<[u8; 32]> {
    if word.len() != 64
        || !word
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    hex::decode(word).ok()?.try_into().ok()
}

/// A count in its one spelling: `0`, or digits with no leading zero.
fn count_of(word: &str) -> Option<usize> {
    let spelled_once = word == "0" || !word.starts_with('0');
    (spelled_once && word.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| word.parse().ok())
        .flatten()
}

/// A label: 1 to 32 characters of `a-z`, `0-9`, `.`, `_` and `-`.
pub fn is_a_label(label: &str) -> bool {
    (1..=MEMBERS_LABEL_MAX_CHARS).contains(&label.len())
        && label.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

impl ChannelLine {
    /// Whether the line names `key` after `without`, or its twin.
    pub fn leaves_out(&self, key: &[u8; 32]) -> bool {
        self.without.iter().any(|left| same_key(left, key))
    }

    /// The line, as a making anew prints it and [`read`] reads it. A key
    /// after `without` given twice, or with its twin, is printed once. A
    /// value that [`read`] would not take back (no relay or more than two,
    /// a relay twice, a key that is not one) is refused.
    pub fn to_line(&self) -> Result<String, &'static str> {
        let mut without: Vec<&[u8; 32]> = Vec::with_capacity(self.without.len());
        for key in &self.without {
            if !without.iter().any(|kept| same_key(kept, key)) {
                without.push(key);
            }
        }
        let mut line = format!("channel {}", hex::encode(self.channel));
        for key in &self.relays {
            line.push(' ');
            line.push_str(&encode_public_key(key).map_err(|_| NOT_A_KEY)?);
        }
        line.push_str(&format!(" without {}", without.len()));
        for key in without {
            line.push(' ');
            line.push_str(&encode_public_key(key).map_err(|_| NOT_A_KEY)?);
        }
        let words: Vec<&str> = line.split(' ').collect();
        channel_line(&words[1..])?;
        Ok(line)
    }
}

impl Members {
    /// The devices that hold the list back (rule 1): each that its channel
    /// line names after `without` and that is not in the channel, by
    /// `in_channel`. While any is, the list names no channel.
    pub fn gated(&self, in_channel: impl Fn(&[u8; 32]) -> bool) -> Vec<&Device> {
        let Some(line) = &self.channel else {
            return Vec::new();
        };
        self.devices
            .iter()
            .filter(|device| {
                line.without.iter().any(|key| same_key(key, &device.key))
                    && !in_channel(&device.key)
            })
            .collect()
    }

    /// The channel the list names: its channel line, where it has one and
    /// no device holds it back.
    pub fn names(&self, in_channel: impl Fn(&[u8; 32]) -> bool) -> Option<&ChannelLine> {
        match self.gated(in_channel).is_empty() {
            true => self.channel.as_ref(),
            false => None,
        }
    }

    /// Whether the list names `key` as a device, or its twin.
    pub fn lists(&self, key: &[u8; 32]) -> bool {
        self.devices.iter().any(|device| same_key(&device.key, key))
    }

    /// The line of `key` itself, where the list has one, and not of its
    /// twin: a device follows and takes by its key as `cordelia id` prints
    /// it, since the share pair channel a member hands it the channel in
    /// is derived from the two keys as they are (decision 2026-11-06
    /// (joining), rule 4.4).
    pub fn line_of(&self, key: &[u8; 32]) -> Option<&Device> {
        self.devices.iter().find(|device| device.key == *key)
    }

    /// The label the list gives `key`, or its twin, where it lists it.
    pub fn label_of(&self, key: &[u8; 32]) -> Option<&str> {
        self.devices
            .iter()
            .find(|device| same_key(&device.key, key))
            .map(|device| device.label.as_str())
    }
}

#[cfg(test)]
mod tests;
