//! Tests of a repository's list (decision 2026-11-06 (joining), rule 1).

use super::*;
use cordelia_crypto::identity::NodeIdentity;

/// The key of device `n`, as `cordelia id` prints it, and its bytes.
fn key(n: u8) -> (String, [u8; 32]) {
    let key = NodeIdentity::from_seed([n; 32]).unwrap().public_key();
    (encode_public_key(&key).unwrap(), key)
}

const ID: &str = "9f2c000000000000000000000000000000000000000000000000000000e41a00";

/// A channel line at relays 1 and 2, without the keys numbered in `without`.
fn channel(without: &[u8]) -> String {
    let mut line = format!(
        "channel {ID} {} {} without {}",
        key(1).0,
        key(2).0,
        without.len()
    );
    for n in without {
        line.push(' ');
        line.push_str(&key(*n).0);
    }
    line
}

fn why(file: &str) -> NotAList {
    read(file.as_bytes()).unwrap_err()
}

#[test]
fn a_list_gives_its_channel_and_its_devices_in_order() {
    let file = format!(
        "# The devices of this repository's channel.\n\n{}\n{}   alice-laptop\n  {} bob.desktop_2  \n",
        channel(&[9]),
        key(10).0,
        key(11).0
    );
    let members = read(file.as_bytes()).unwrap();
    let line = members.channel.clone().unwrap();
    assert_eq!(hex::encode(line.channel), ID);
    assert_eq!(line.relays, vec![key(1).1, key(2).1]);
    assert_eq!(line.without, vec![key(9).1]);
    assert_eq!(
        members.devices,
        vec![
            Device {
                key: key(10).1,
                label: "alice-laptop".into()
            },
            Device {
                key: key(11).1,
                label: "bob.desktop_2".into()
            },
        ]
    );
    assert!(members.lists(&key(10).1) && !members.lists(&key(9).1));
    assert_eq!(members.label_of(&key(11).1), Some("bob.desktop_2"));
}

#[test]
fn a_list_may_name_no_channel_and_one_relay() {
    let members = read(format!("{} alice\n", key(10).0).as_bytes()).unwrap();
    assert_eq!(members.channel, None);
    let one = format!("channel {ID} {} without 0\n", key(1).0);
    let line = read(one.as_bytes()).unwrap().channel.unwrap();
    assert_eq!((line.relays.len(), line.without.len()), (1, 0));
    assert_eq!(read(b"").unwrap().devices, vec![]);
}

#[test]
fn a_file_that_is_not_a_list_names_its_line_and_gives_nothing() {
    let big = format!("# {}\n", "x".repeat(MEMBERS_FILE_MAX_BYTES));
    assert_eq!(
        why(&big),
        NotAList {
            line: 0,
            why: TOO_LARGE
        }
    );
    assert_eq!(why("# fine\nlabel \u{e9}\n").line, 2);
    assert_eq!(why("# fine\r\n").why, CARRIAGE);
    assert_eq!(why("# a tab\there\n").why, TAB);
    let twice = format!("{}\n{}\n", channel(&[]), channel(&[]));
    assert_eq!(
        why(&twice),
        NotAList {
            line: 2,
            why: SECOND_CHANNEL
        }
    );
    let upper = channel(&[]).replace("9f2c", "9F2C");
    assert_eq!(why(&upper).why, NOT_A_CHANNEL);
    assert_eq!(why("channel abc without 0").why, NOT_A_CHANNEL);
    assert_eq!(why(&format!("channel {ID} without 0")).why, RELAYS);
    let three = format!(
        "channel {ID} {} {} {} without 0",
        key(1).0,
        key(2).0,
        key(3).0
    );
    assert_eq!(why(&three).why, RELAYS);
    let same = format!("channel {ID} {} {} without 0", key(1).0, key(1).0);
    assert_eq!(why(&same).why, KEY_TWICE);
    assert_eq!(why(&format!("channel {ID} {}", key(1).0)).why, NO_WITHOUT);
    assert_eq!(
        why(&format!("channel {ID} {} without", key(1).0)).why,
        NOT_A_COUNT
    );
    let more = format!("channel {ID} {} without 2 {}", key(1).0, key(9).0);
    assert_eq!(why(&more).why, COUNT);
    let fewer = format!("channel {ID} {} without 0 {}", key(1).0, key(9).0);
    assert_eq!(why(&fewer).why, COUNT);
    let leading = format!("channel {ID} {} without 01 {}", key(1).0, key(9).0);
    assert_eq!(why(&leading).why, NOT_A_COUNT);
    let repeated = format!(
        "channel {ID} {} without 2 {} {}",
        key(1).0,
        key(9).0,
        key(9).0
    );
    assert_eq!(why(&repeated).why, KEY_TWICE);
    assert_eq!(
        why(&format!("{} alice", key(10).0.to_uppercase())).why,
        NOT_A_KEY
    );
    let mut wrong = key(10).0;
    let last = wrong.pop().unwrap();
    wrong.push(if last == 'q' { 'p' } else { 'q' });
    assert_eq!(why(&format!("{wrong} alice")).why, NOT_A_KEY);
    assert_eq!(why(&key(10).0).why, DEVICE_LINE);
    assert_eq!(why(&format!("{} alice laptop", key(10).0)).why, DEVICE_LINE);
    assert_eq!(why(&format!("{} Alice", key(10).0)).why, LABEL);
    assert_eq!(why(&format!("{} {}", key(10).0, "a".repeat(33))).why, LABEL);
    let key_twice = format!("{} alice\n{} bob\n", key(10).0, key(10).0);
    assert_eq!(
        why(&key_twice),
        NotAList {
            line: 2,
            why: KEY_TWICE
        }
    );
    let label_twice = format!("{} alice\n{} alice\n", key(10).0, key(11).0);
    assert_eq!(
        why(&label_twice),
        NotAList {
            line: 2,
            why: LABEL_TWICE
        }
    );
    let mut many = String::new();
    for n in 0..=SHARED_MAX_KEYS as u8 {
        many.push_str(&format!("{} device-{n}\n", key(100 + n).0));
    }
    assert_eq!(
        why(&many),
        NotAList {
            line: SHARED_MAX_KEYS + 1,
            why: TOO_MANY
        }
    );
}

#[test]
fn the_keys_after_without_do_not_count_among_the_64() {
    let mut file = format!("{}\n", channel(&[200, 201, 202]));
    for n in 0..SHARED_MAX_KEYS as u8 {
        file.push_str(&format!("{} device-{n}\n", key(100 + n).0));
    }
    let members = read(file.as_bytes()).unwrap();
    assert_eq!(members.devices.len(), SHARED_MAX_KEYS);
    assert_eq!(members.channel.unwrap().without.len(), 3);
}

/// Every channel line cut short, at any character, does not parse: so a
/// line pasted in part names nothing. Cut to nothing, the list names no
/// channel, which hands nothing to anyone either.
#[test]
fn a_channel_line_cut_short_never_parses() {
    let line = channel(&[9, 10]);
    assert!(read(line.as_bytes()).is_ok());
    let none = format!("\n{} alice\n", key(10).0);
    assert_eq!(read(none.as_bytes()).unwrap().channel, None);
    for end in 1..line.len() {
        let cut = &line[..end];
        if cut.trim_end() == line {
            continue;
        }
        let file = format!("{cut}\n{} alice\n", key(10).0);
        assert!(read(file.as_bytes()).is_err(), "{cut:?} was read");
    }
}

#[test]
fn a_channel_line_printed_is_read_as_it_was() {
    for without in [&[][..], &[9][..], &[9, 10, 11][..]] {
        let printed = ChannelLine {
            channel: hex::decode(ID).unwrap().try_into().unwrap(),
            relays: vec![key(1).1, key(2).1],
            without: without.iter().map(|n| key(*n).1).collect(),
        };
        let read_back = read(printed.to_line().unwrap().as_bytes())
            .unwrap()
            .channel
            .unwrap();
        assert_eq!(read_back, printed);
    }
}

/// The gate (rule 1): a listed key after `without` that is not in the
/// channel holds the list back; one that is in the channel, as a device
/// of a person who stays, does not; and a key after `without` that is not
/// listed holds nothing back.
#[test]
fn a_listed_key_left_out_and_not_in_holds_the_list_back() {
    let file = format!(
        "{}\n{} alice\n{} stolen\n{} bobs-desktop\n{} newcomer\n",
        channel(&[11, 12, 13]),
        key(10).0,
        key(11).0,
        key(12).0,
        key(14).0
    );
    let members = read(file.as_bytes()).unwrap();
    let in_channel = |key_in: &[u8; 32]| *key_in == key(10).1 || *key_in == key(12).1;
    let gated: Vec<&str> = members
        .gated(in_channel)
        .iter()
        .map(|device| device.label.as_str())
        .collect();
    assert_eq!(gated, vec!["stolen"]);
    assert_eq!(members.names(in_channel), None);
    // Its line deleted, the list names the channel; key 13, after
    // `without` and not listed, holds nothing back.
    let deleted = file.replace(&format!("{} stolen\n", key(11).0), "");
    let members = read(deleted.as_bytes()).unwrap();
    assert!(members.gated(in_channel).is_empty());
    assert_eq!(
        members.names(in_channel).map(|line| line.without.len()),
        Some(3)
    );
}

/// The key with its top bit flipped: another key to Ed25519, the same to
/// X25519.
fn twin(n: u8) -> (String, [u8; 32]) {
    let mut twin = key(n).1;
    twin[31] ^= 0x80;
    (encode_public_key(&twin).unwrap(), twin)
}

/// A twin counts as its key: once as a device, and in the gate.
#[test]
fn a_keys_twin_counts_as_the_key() {
    assert!(
        is_usable_public_key(&twin(11).1),
        "a twin is a key that can be used"
    );
    let both = format!("{} alice\n{} bob\n", key(11).0, twin(11).0);
    assert_eq!(why(&both).why, KEY_TWICE);
    let in_without = format!(
        "channel {ID} {} without 2 {} {}",
        key(1).0,
        key(11).0,
        twin(11).0
    );
    assert_eq!(why(&in_without).why, KEY_TWICE);
    let gated = format!("{}\n{} stolen-twin\n", channel(&[11]), twin(11).0);
    let members = read(gated.as_bytes()).unwrap();
    assert_eq!(members.gated(|_| false).len(), 1);
    assert_eq!(members.names(|_| false), None);
}

#[test]
fn a_line_that_read_would_refuse_is_not_printed() {
    let line = |relays: Vec<[u8; 32]>, without: Vec<[u8; 32]>| ChannelLine {
        channel: [9; 32],
        relays,
        without,
    };
    assert_eq!(line(vec![], vec![]).to_line(), Err(RELAYS));
    assert_eq!(
        line(vec![key(1).1, key(2).1, key(3).1], vec![]).to_line(),
        Err(RELAYS)
    );
    assert_eq!(
        line(vec![key(1).1, key(1).1], vec![]).to_line(),
        Err(KEY_TWICE)
    );
    // A key after `without` twice, or with its twin, is printed once.
    let mut doubled = vec![key(9).1, key(10).1, key(9).1];
    doubled.push(twin(10).1);
    let printed = line(vec![key(1).1], doubled).to_line().unwrap();
    let read_back = read(printed.as_bytes()).unwrap().channel.unwrap();
    assert_eq!(read_back.without, vec![key(9).1, key(10).1]);
}

/// The checks the first tests did not reach: another spelling of a key, a
/// key that cannot be used, a count with a sign, the exact bound, and a
/// list with no channel line.
#[test]
fn the_checks_at_the_edges_hold() {
    use bech32::{Bech32m, Hrp};
    let other = bech32::encode::<Bech32m>(Hrp::parse("cordelia_pk").unwrap(), &key(10).1).unwrap();
    assert_eq!(why(&format!("{other} alice")).why, NOT_A_KEY);
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let unusable = encode_public_key(&identity).unwrap();
    assert_eq!(why(&format!("{unusable} alice")).why, NOT_A_KEY);
    let signed = format!("channel {ID} {} without +1 {}", key(1).0, key(9).0);
    assert_eq!(why(&signed).why, NOT_A_COUNT);
    let device = format!("{} alice\n", key(10).0);
    let at_bound = format!(
        "{device}#{}\n",
        "x".repeat(MEMBERS_FILE_MAX_BYTES - device.len() - 2)
    );
    assert_eq!(at_bound.len(), MEMBERS_FILE_MAX_BYTES);
    assert!(read(at_bound.as_bytes()).is_ok());
    assert_eq!(why(&format!("{at_bound} ")).why, TOO_LARGE);
    let no_channel = read(format!("{} alice\n", key(10).0).as_bytes()).unwrap();
    assert!(no_channel.gated(|_| false).is_empty());
    assert_eq!(no_channel.names(|_| false), None);
}

#[test]
fn a_tab_a_carriage_return_and_a_comment_after_words_are_named() {
    assert_eq!(why(&format!("{}\talice", key(10).0)).why, TAB);
    assert_eq!(why(&format!("{} alice\r\n", key(10).0)).why, CARRIAGE);
    assert_eq!(
        why(&format!("{} alice # her laptop", key(10).0)).why,
        COMMENT_AFTER
    );
    assert_eq!(why(&format!("{} # note", channel(&[]))).why, COMMENT_AFTER);
}
