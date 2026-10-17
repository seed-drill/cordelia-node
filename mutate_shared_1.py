#!/usr/bin/env python3
"""Mutation checks for slice 1 of a shared channel: the constants and labels
of decision 2026-10-10 §14 in protocol.rs, with their checks where it is
compiled (the requests of §8.4 with the shows of a minute counted), and the
crypto of §2.1, §2.3, §3.1, §3.4, §6.1 and §7: the card by key alone, the
derivation and its vector, the share pair derivation, forms 3 and 5, the
share, the person's list with its counts and its drops, an act's signature,
and the anew seal. A part for each rule of the slice: put each fault in,
and confirm the test named for it fails on an assertion. Run from the root
of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
PROTOCOL = 'crates/cordelia-core/src/protocol.rs'
DERIVE = 'crates/cordelia-crypto/src/derive.rs'
SHARE = 'crates/cordelia-crypto/src/share.rs'
SHARED = 'crates/cordelia-crypto/src/shared.rs'
ACTS = 'crates/cordelia-crypto/src/acts.rs'
ORIG = {f: open(f).read() for f in (PROTOCOL, DERIVE, SHARE, SHARED, ACTS)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
CORE = ("cordelia-core", ["--lib"])
CRYPTO = ("cordelia-crypto", ["--lib"])
def core(test): return (CORE, "protocol::tests::" + test)
def derive(test): return (CRYPTO, "derive::tests::" + test)
def share(test): return (CRYPTO, "share::tests::" + test)
def shared(test): return (CRYPTO, "shared::tests::" + test)
def acts(test): return (CRYPTO, "acts::tests::" + test)
VECTORS = (CRYPTO, "vectors::the_code_gives_the_published_vectors")
FROM_INPUTS = (CRYPTO, "vectors::the_published_vectors_follow_from_their_own_inputs")

LABELS_TEST = core("test_no_label_begins_another_decision_2026_10_04_2_2")
OF_SHARED = core("test_the_labels_of_a_shared_channel_decision_2026_10_10_14")
CARD = core("test_a_card_and_a_share_decision_2026_10_10_2_1_and_3_1")
ENTRIES = core("test_the_entries_of_a_shared_channel_decision_2026_10_10_2_3")
LIST = core("test_the_persons_list_decision_2026_10_10_3_4")
SREAD = core("test_the_messages_channel_with_its_sread_lists_decision_2026_10_10_6_1")
STORE = core("test_a_devices_store_of_a_shared_channel_decision_2026_10_10_6_3")
PASS = core("test_the_shared_pass_decision_2026_10_10_8_4")
REQUESTS = core("test_requests_on_the_streams_of_entries_decision_2026_10_04_16")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── protocol.rs: the six labels ──
    ("P01 the shared label is spelled otherwise", PROTOCOL,
     'pub const LABEL_SHARED: &[u8] = b"cordelia v2 shared";',
     'pub const LABEL_SHARED: &[u8] = b"cordelia v2 sharex";',
     [LABELS_TEST]),
    ("P02 the relays' label is spelled otherwise", PROTOCOL,
     'pub const LABEL_SHARED_RELAYS: &[u8] = b"cordelia v2 relays";',
     'pub const LABEL_SHARED_RELAYS: &[u8] = b"cordelia v2 relay";',
     [LABELS_TEST]),
    ("P03 the share pair's label is spelled otherwise", PROTOCOL,
     'pub const LABEL_SHARE_PAIR: &[u8] = b"cordelia v2 share pair";',
     'pub const LABEL_SHARE_PAIR: &[u8] = b"cordelia v2 sharepair";',
     [LABELS_TEST]),
    ("P04 the anew seal's label is spelled otherwise", PROTOCOL,
     'pub const LABEL_ANEW_SEAL: &[u8] = b"cordelia v2 anew seal";',
     'pub const LABEL_ANEW_SEAL: &[u8] = b"cordelia v2 anew";',
     [LABELS_TEST]),
    ("P05 the sent mark's label is the messages label with more after it", PROTOCOL,
     'pub const LABEL_SHARED_SENT: &[u8] = b"cordelia v2 message sent";',
     'pub const LABEL_SHARED_SENT: &[u8] = b"cordelia v2 messages sent";',
     [LABELS_TEST]),
    ("P06 the act's label begins another label", PROTOCOL,
     'pub const LABEL_SHARED_ACT: &[u8] = b"cordelia v2 act";',
     'pub const LABEL_SHARED_ACT: &[u8] = b"cordelia v2 a";',
     [LABELS_TEST]),
    ("P07 the act's label is left out of LABELS", PROTOCOL,
     ['pub const LABELS: [&[u8]; 34] = [', '    LABEL_SHARED_SENT,\n    LABEL_SHARED_ACT,\n];'],
     ['pub const LABELS: [&[u8]; 33] = [', '    LABEL_SHARED_SENT,\n];'],
     [OF_SHARED]),
    # ── protocol.rs: each constant's value ──
    ("P08 a seed is 31 bytes", PROTOCOL,
     'pub const SHARED_SEED_BYTES: usize = 32;',
     'pub const SHARED_SEED_BYTES: usize = 31;',
     [CARD]),
    ("P09 a card names three relays", PROTOCOL,
     'pub const SHARED_MAX_RELAYS: usize = 2;',
     'pub const SHARED_MAX_RELAYS: usize = 3;',
     [CARD, LIST]),
    ("P10 a person holds 17 shared channels", PROTOCOL,
     'pub const SHARED_MAX_CHANNELS: usize = 16;',
     'pub const SHARED_MAX_CHANNELS: usize = 17;',
     [LIST, REQUESTS]),
    ("P11 a list keeps 65 drops", PROTOCOL,
     'pub const SHARED_MAX_DROPPED: usize = 64;',
     'pub const SHARED_MAX_DROPPED: usize = 65;',
     [LIST]),
    ("P12 a person holds 33 subscriptions", PROTOCOL,
     'pub const SHARED_MAX_SUBSCRIPTIONS: usize = 32;',
     'pub const SHARED_MAX_SUBSCRIPTIONS: usize = 33;',
     [LIST]),
    ("P13 a person keeps 65 labels", PROTOCOL,
     'pub const SHARED_MAX_LABELS: usize = 64;',
     'pub const SHARED_MAX_LABELS: usize = 65;',
     [LIST]),
    ("P14 a label is 65 bytes", PROTOCOL,
     'pub const SHARED_LABEL_MAX_BYTES: usize = MAX_DEVICE_LABEL_BYTES;',
     'pub const SHARED_LABEL_MAX_BYTES: usize = MAX_DEVICE_LABEL_BYTES + 1;',
     [LIST]),
    ("P15 an act carries a signature of 63 bytes", PROTOCOL,
     'const SHARED_ACT_BYTES: usize = 8 + 8 + 32 + 64;',
     'const SHARED_ACT_BYTES: usize = 8 + 8 + 32 + 63;',
     [LIST]),
    ("P16 a list's most leaves out how a filing came", PROTOCOL,
     '            + (1 + 32)\n            + SHARED_ACT_BYTES)',
     '            + 32\n            + SHARED_ACT_BYTES)',
     [LIST]),
    ("P17 a list is written again each 45 days", PROTOCOL,
     'pub const SHARED_WORDS_WRITTEN_AGAIN_DAYS: u32 = KEYED_TOMBSTONE_RETENTION_DAYS / 3;',
     'pub const SHARED_WORDS_WRITTEN_AGAIN_DAYS: u32 = KEYED_TOMBSTONE_RETENTION_DAYS / 2;',
     [LIST]),
    ("P18 the time bound is 2^41", PROTOCOL,
     'pub const SHARED_ACT_TIME_MAX: u64 = 1 << 40;',
     'pub const SHARED_ACT_TIME_MAX: u64 = 1 << 41;',
     [LIST]),
    ("P19 a channel shows 65 keys", PROTOCOL,
     'pub const SHARED_MAX_KEYS: usize = 64;',
     'pub const SHARED_MAX_KEYS: usize = 65;',
     [STORE, ENTRIES]),
    ("P20 the table keeps 1,025 rows of keys that store nothing", PROTOCOL,
     'pub const SHARED_KEYS_KEPT: usize = 1_024;',
     'pub const SHARED_KEYS_KEPT: usize = 1_025;',
     [STORE]),
    ("P21 the shared pass is handed a third of the minute", PROTOCOL,
     'pub const SHARED_BYTES_PER_MINUTE: u64 = PUSH_BYTES_PER_PEER_PER_MINUTE / 4;',
     'pub const SHARED_BYTES_PER_MINUTE: u64 = PUSH_BYTES_PER_PEER_PER_MINUTE / 3;',
     [PASS]),
    ("P22 a channel is read again each 12 hours", PROTOCOL,
     'pub const SHARED_READ_AGAIN_SECS: u64 = 24 * 60 * 60;',
     'pub const SHARED_READ_AGAIN_SECS: u64 = 12 * 60 * 60;',
     [PASS]),
    ("P23 the shared pass asks 650 a minute", PROTOCOL,
     'pub const SHARED_REQUESTS_PER_MINUTE: u32 = 600;',
     'pub const SHARED_REQUESTS_PER_MINUTE: u32 = 650;',
     [PASS, REQUESTS]),
    ("P24 the shared pass pushes a third of the minute", PROTOCOL,
     'pub const SHARED_PUSH_BYTES_PER_MINUTE: u64 = OUTBOX_BYTES_PER_MINUTE / 4;',
     'pub const SHARED_PUSH_BYTES_PER_MINUTE: u64 = OUTBOX_BYTES_PER_MINUTE / 3;',
     [PASS]),
    ("P25 another person's key is shown by seven words", PROTOCOL,
     'pub const SHARED_KEY_WORDS_SHOWN: usize = 6;',
     'pub const SHARED_KEY_WORDS_SHOWN: usize = 7;',
     [CARD]),
    ("P26 an anew record is of the class of 32 KiB", PROTOCOL,
     'pub const SHARED_ANEW_CONTENT_BYTES: usize = 16_384;',
     'pub const SHARED_ANEW_CONTENT_BYTES: usize = 32_768;',
     [ENTRIES]),
    ("P27 an anew record's value leaves out its name, with its check", PROTOCOL,
     ['    SHARED_ANEW_CONTENT_BYTES - ITEM_SEAL_OVERHEAD_BYTES - 7 - (SHARED_ANEW_PREFIX.len() + 70);',
      'const _: () = assert!(\n    7 + SHARED_ANEW_PREFIX.len() + 70 + SHARED_ANEW_VALUE_BYTES + ITEM_SEAL_OVERHEAD_BYTES\n        == SHARED_ANEW_CONTENT_BYTES\n);'],
     ['    SHARED_ANEW_CONTENT_BYTES - ITEM_SEAL_OVERHEAD_BYTES - 7;',
      ''],
     [ENTRIES]),
    ("P28 a share's value leaves out its name, with its check", PROTOCOL,
     ['    512 - ITEM_SEAL_OVERHEAD_BYTES - 7 - (SHARE_PREFIX.len() + 2 * 32);',
      'const _: () =\n    assert!(7 + SHARE_PREFIX.len() + 2 * 32 + SHARE_VALUE_BYTES + ITEM_SEAL_OVERHEAD_BYTES == 512);'],
     ['    512 - ITEM_SEAL_OVERHEAD_BYTES - 7;',
      ''],
     [CARD]),
    ("P29 a share's prefix is another", PROTOCOL,
     'pub const SHARE_PREFIX: &str = "share/";',
     'pub const SHARE_PREFIX: &str = "shares/";',
     [CARD]),
    ("P30 an anew record's prefix begins a message's", PROTOCOL,
     'pub const SHARED_ANEW_PREFIX: &str = "anew/";',
     'pub const SHARED_ANEW_PREFIX: &str = "m";',
     [ENTRIES]),
    ("P31 the sread prefix is begun by read/", PROTOCOL,
     'pub const SHARED_READ_PREFIX: &str = "sread/";',
     'pub const SHARED_READ_PREFIX: &str = "read/s";',
     [SREAD]),
    ("P32 the list's prefix is begun by name/", PROTOCOL,
     'pub const PERSONAL_SHARED_PREFIX: &str = "shared/";',
     'pub const PERSONAL_SHARED_PREFIX: &str = "name/s";',
     [LIST]),
    # ── protocol.rs: the checks where it is compiled, each held by a test
    # too: the check taken out and the rule broken ──
    ("P33 the shows of a minute are not counted, and the shared pass asks 700", PROTOCOL,
     ['        + 2 * (60 / REALTIME_SYNC_INTERVAL_SECS + 60 / OUTBOX_FLUSH_INTERVAL_SECS)\n',
      'pub const SHARED_REQUESTS_PER_MINUTE: u32 = 600;'],
     ['', 'pub const SHARED_REQUESTS_PER_MINUTE: u32 = 700;'],
     [REQUESTS]),
    ("P34 the shared pass's minute has no room for the largest entry, unchecked", PROTOCOL,
     ['const _: () = assert!(entry_cost(MAX_ITEM_BYTES) <= SHARED_BYTES_PER_MINUTE);',
      'const _: () = assert!(\n    SHARED_MAX_CHANNELS as u64 * MAX_ENTRY_CHANNEL_BYTES_AT_RELAY\n        <= SHARED_BYTES_PER_MINUTE * (SHARED_READ_AGAIN_SECS / 60)\n);',
      'pub const SHARED_BYTES_PER_MINUTE: u64 = PUSH_BYTES_PER_PEER_PER_MINUTE / 4;'],
     ['', '', 'pub const SHARED_BYTES_PER_MINUTE: u64 = PUSH_BYTES_PER_PEER_PER_MINUTE / 64;'],
     [PASS]),
    ("P35 reading again does not fit the day's share, unchecked", PROTOCOL,
     ['const _: () = assert!(\n    SHARED_MAX_CHANNELS as u64 * MAX_ENTRY_CHANNEL_BYTES_AT_RELAY\n        <= SHARED_BYTES_PER_MINUTE * (SHARED_READ_AGAIN_SECS / 60)\n);',
      'pub const SHARED_READ_AGAIN_SECS: u64 = 24 * 60 * 60;'],
     ['', 'pub const SHARED_READ_AGAIN_SECS: u64 = 6 * 60 * 60;'],
     [PASS]),
    ("P36 an anew record does not fit the push's share, unchecked", PROTOCOL,
     ['const _: () = assert!(entry_cost(SHARED_ANEW_CONTENT_BYTES) <= SHARED_PUSH_BYTES_PER_MINUTE);',
      'pub const SHARED_PUSH_BYTES_PER_MINUTE: u64 = OUTBOX_BYTES_PER_MINUTE / 4;'],
     ['', 'pub const SHARED_PUSH_BYTES_PER_MINUTE: u64 = OUTBOX_BYTES_PER_MINUTE / 128;'],
     [PASS]),
    ("P37 the time bound is below RFC 3339's last second, unchecked", PROTOCOL,
     ['const _: () = assert!(SHARED_ACT_TIME_MAX > 253_402_300_799);',
      'pub const SHARED_ACT_TIME_MAX: u64 = 1 << 40;'],
     ['', 'pub const SHARED_ACT_TIME_MAX: u64 = 1 << 37;'],
     [LIST]),
    ("P38 64 devices' rooms overflow a channel, unchecked", PROTOCOL,
     ['const _: () = assert!(\n    SHARED_MAX_KEYS as u64\n        * (AGENT_MESSAGE_RING as u64 * entry_cost(AGENT_MESSAGE_CONTENT_BYTES)\n            + entry_cost(SHARED_ANEW_CONTENT_BYTES))\n        <= MAX_ENTRY_CHANNEL_BYTES_AT_RELAY\n);',
      'pub const SHARED_ANEW_CONTENT_BYTES: usize = 16_384;'],
     ['', 'pub const SHARED_ANEW_CONTENT_BYTES: usize = 65_536;'],
     [ENTRIES]),
    ("P39 66 slots of 64 devices overflow the messages channel, unchecked", PROTOCOL,
     ['const _: () = assert!(\n    (MAX_COUNTED_DEVICES * (AGENT_MESSAGE_RING + 2)) as u64',
      'const _: () = assert!(\n    SHARED_MAX_KEYS as u64\n        * (AGENT_MESSAGE_RING as u64 * entry_cost(AGENT_MESSAGE_CONTENT_BYTES)\n            + entry_cost(SHARED_ANEW_CONTENT_BYTES))\n        <= MAX_ENTRY_CHANNEL_BYTES_AT_RELAY\n);',
      'pub const AGENT_MESSAGE_RING: usize = 64;'],
     ['const _: () = assert!(\n    (MAX_COUNTED_DEVICES * (AGENT_MESSAGE_RING + 1)) as u64',
      '',
      'pub const AGENT_MESSAGE_RING: usize = 84;'],
     [SREAD]),
    ("P40 a list at its bounds runs past what an entry holds, unchecked", PROTOCOL,
     ['const _: () = assert!(\n    PERSONAL_SHARED_PREFIX.len() + 70 + SHARED_LIST_MAX_VALUE_BYTES\n        <= MAX_ENTRY_NAME_AND_VALUE_BYTES\n);',
      'pub const SHARED_MAX_LABELS: usize = 64;'],
     ['', 'pub const SHARED_MAX_LABELS: usize = 160;'],
     [LIST]),

    # ── derive.rs: the two derivations ──
    ("D01 a share pair channel is the pair channel", DERIVE,
     '    between(LABEL_SHARE_PAIR, device, other)',
     '    between(LABEL_PAIR, device, other)',
     [derive("a_share_pair_channel_is_the_pair_derivation_under_its_own_label"),
      derive("no_two_kinds_of_channel_have_the_same_secret")]),
    ("D02 a pair of devices takes one's own key", DERIVE,
     '    if own == *other {\n        return Err(DeriveError::OwnKey);\n    }\n    let other_x25519',
     '    let other_x25519',
     [derive("a_share_pair_channel_is_the_pair_derivation_under_its_own_label")]),
    ("D03 a shared channel's relays are not in its secret", DERIVE,
     '    info.extend_from_slice(&relays.hash());',
     '',
     [share("a_shared_channel_is_derived_under_its_own_label_and_its_relays"), VECTORS]),
    ("D04 a shared channel's secret is under the label of a name", DERIVE,
     '    info.extend_from_slice(LABEL_SHARED);',
     '    info.extend_from_slice(LABEL_OWN);',
     [share("a_shared_channel_is_derived_under_its_own_label_and_its_relays"), VECTORS]),

    # ── share.rs: the card by key alone, and the share ──
    ("S01 a card may name one relay twice", SHARE,
     '        if sorted.windows(2).any(|pair| pair[0] == pair[1]) {\n            return Err(ShareError::RelayTwice);\n        }',
     '',
     [share("a_card_with_a_key_twice_or_of_more_than_two_relays_is_refused")]),
    ("S02 a card may name three relays", SHARE,
     '        if keys.len() > SHARED_MAX_RELAYS {',
     '        if keys.len() > SHARED_MAX_RELAYS + 1 {',
     [share("a_card_with_a_key_twice_or_of_more_than_two_relays_is_refused")]),
    ("S03 a card may name no relay", SHARE,
     '        if keys.is_empty() {\n            return Err(ShareError::NoRelay);\n        }',
     '',
     [share("a_card_with_a_key_twice_or_of_more_than_two_relays_is_refused")]),
    ("S04 a card's relays are kept in the order given", SHARE,
     '        sorted.sort_unstable();\n        if sorted.windows(2)',
     '        if sorted.windows(2)',
     [share("a_card_names_its_relays_by_key_alone_in_one_form")]),
    ("S05 a card read out of its order is taken", SHARE,
     '            if pair[0] > pair[1] {\n                return Err(ShareError::RelaysNotInOrder);\n            }',
     '',
     [share("a_card_with_a_key_twice_or_of_more_than_two_relays_is_refused")]),
    ("S06 a card read with no relay is taken", SHARE,
     '        if count == 0 {\n            return Err(ShareError::NoRelay);\n        }',
     '',
     [share("a_card_with_a_key_twice_or_of_more_than_two_relays_is_refused")]),
    ("S07 a card read with three relays is taken", SHARE,
     '        if count > SHARED_MAX_RELAYS {',
     '        if count > SHARED_MAX_RELAYS + 1 {',
     [share("a_card_with_a_key_twice_or_of_more_than_two_relays_is_refused")]),
    ("S08 a card read with one relay twice is taken", SHARE,
     '            if pair[0] == pair[1] {\n                return Err(ShareError::RelayTwice);\n            }',
     '',
     [share("a_card_with_a_key_twice_or_of_more_than_two_relays_is_refused")]),
    ("S09 the relays are hashed without their label", SHARE,
     '        let mut hashed = LABEL_SHARED_RELAYS.to_vec();',
     '        let mut hashed = Vec::new();',
     [VECTORS, share("a_shared_channel_is_derived_under_its_own_label_and_its_relays")]),
    ("S10 the list of relays has no count", SHARE,
     '        out.push(self.0.len() as u8);\n        for key in &self.0 {',
     '        for key in &self.0 {',
     [share("a_card_names_its_relays_by_key_alone_in_one_form")]),
    ("S11 a card with a byte after its end is taken", SHARE,
     '        let card = Self::read(&mut reader)?;\n        if !reader.is_empty() {\n            return Err(ShareError::CardLength);\n        }',
     '        let card = Self::read(&mut reader)?;',
     [share("a_card_with_a_key_twice_or_of_more_than_two_relays_is_refused")]),
    ("S12 a list of relays with a byte after its end is taken", SHARE,
     '        let relays = Self::read(&mut reader)?;\n        if !reader.is_empty() {\n            return Err(ShareError::CardLength);\n        }',
     '        let relays = Self::read(&mut reader)?;',
     [share("a_card_with_a_key_twice_or_of_more_than_two_relays_is_refused")]),
    ("S13 a card's seed is not random", SHARE,
     '        SystemRandom::new()\n            .fill(&mut seed)\n            .map_err(|_| ShareError::Crypto("RNG failure".into()))?;',
     '',
     [share("a_card_is_made_from_a_random_seed")]),
    ("S14 a share writes the key it is for before its time", SHARE,
     '        out.extend_from_slice(&self.made.to_be_bytes());\n        out.extend_from_slice(&self.for_key);',
     '        out.extend_from_slice(&self.for_key);\n        out.extend_from_slice(&self.made.to_be_bytes());',
     [share("a_share_entry_holds_only_a_seed_and_relays")]),
    ("S15 a share of another form is taken", SHARE,
     '        if form != FORM_SHARE {\n            return Err(ShareError::Form(form));\n        }',
     '',
     [share("a_reader_refuses_a_share_that_is_not_one")]),
    ("S16 a share whose fill is not zeros is taken", SHARE,
     '        if reader.rest().iter().any(|byte| *byte != 0) {\n            return Err(ShareError::Fill);\n        }',
     '',
     [share("a_reader_refuses_a_share_that_is_not_one")]),
    ("S17 a share shorter than its length is taken", SHARE,
     '        if bytes.len() != SHARE_VALUE_BYTES {',
     '        if bytes.len() > SHARE_VALUE_BYTES {',
     [share("a_reader_refuses_a_share_that_is_not_one")]),
    ("S18 a share's name has its ID in capitals", SHARE,
     '    format!("{SHARE_PREFIX}{}", hex::encode(channel))',
     '    format!("{SHARE_PREFIX}{}", hex::encode_upper(channel))',
     [share("a_shares_name_is_its_channels_id_in_hex")]),
    ("S19 a share of another kind is taken", SHARE,
     '        let Value::Other(bytes) = value else {\n            return Err(ShareError::Kind);\n        };\n        if bytes.len() != SHARE_VALUE_BYTES {',
     '        let bytes = value.bytes();\n        if bytes.len() != SHARE_VALUE_BYTES {',
     [share("a_reader_refuses_a_share_that_is_not_one")]),

    # ── shared.rs: form 3, form 5, the seal and what a reader takes ──
    ("H01 a shared message is of form 4", SHARED,
     'const FORM_MESSAGE: u8 = 3;',
     'const FORM_MESSAGE: u8 = 4;',
     [shared("a_shared_messages_value_is_its_fields_in_their_places")]),
    ("H02 a shared message takes any flag", SHARED,
     '        if flags & !FLAG_ASKS != 0 {\n            return Err(NotAMessage::Flags(flags));\n        }',
     '',
     [shared("a_reader_refuses_each_shared_message_that_is_not_one")]),
    ("H03 a link past its bound is read", SHARED,
     '        if length > AGENT_MESSAGE_LINK_MAX_BYTES {\n            return Err(NotAMessage::Field);\n        }\n        let link',
     '        let link',
     [shared("a_reader_refuses_each_shared_message_that_is_not_one")]),
    ("H04 a link that is none is taken", SHARED,
     '                if !is_a_link(link) {\n                    return Err(NotAMessage::Link);\n                }',
     '',
     [shared("a_reader_refuses_each_shared_message_that_is_not_one")]),
    ("H05 an empty body is taken", SHARED,
     '        if length == 0 {\n            return Err(NotAMessage::BodyEmpty);\n        }',
     '',
     [shared("a_reader_refuses_each_shared_message_that_is_not_one")]),
    ("H06 a body past its bound is read", SHARED,
     '        if length > AGENT_MESSAGE_BODY_MAX_BYTES {\n            return Err(NotAMessage::BodyTooLong(length));\n        }\n        let body',
     '        let body',
     [shared("a_reader_refuses_each_shared_message_that_is_not_one")]),
    ("H07 a shared message's fill is not read", SHARED,
     '        filled(&reader)?;\n        Ok(Self {\n            asks',
     '        Ok(Self {\n            asks',
     [shared("a_reader_refuses_each_shared_message_that_is_not_one")]),
    ("H08 a shared message writes the body before its link", SHARED,
     '        out.push(link.len() as u8);\n        out.extend_from_slice(link.as_bytes());\n        put_count(&mut out, self.body.len());\n        out.extend_from_slice(self.body.as_bytes());',
     '        put_count(&mut out, self.body.len());\n        out.extend_from_slice(self.body.as_bytes());\n        out.push(link.len() as u8);\n        out.extend_from_slice(link.as_bytes());',
     [shared("a_shared_messages_value_is_its_fields_in_their_places")]),
    ("A01 an empty anew record is read as an offer", SHARED,
     '        if reader.rest().iter().all(|byte| *byte == 0) {\n            return Ok(Self::Empty);\n        }',
     '',
     [shared("every_entry_of_a_shared_channel_is_of_its_one_size")]),
    ("A02 an offer may seal to no key", SHARED,
     '    if count == 0 {\n        return Err(AnewError::NoKey);\n    }',
     '',
     [shared("a_reader_refuses_each_anew_record_that_is_not_one"),
      shared("an_offer_opens_only_for_a_key_it_seals_to_and_to_its_new_channel")]),
    ("A03 an offer may seal to 65 keys", SHARED,
     '    if count > SHARED_MAX_KEYS {',
     '    if count > SHARED_MAX_KEYS + 1 {',
     [shared("a_reader_refuses_each_anew_record_that_is_not_one"),
      shared("an_offer_opens_only_for_a_key_it_seals_to_and_to_its_new_channel")]),
    ("A04 an offer may seal to one key twice", SHARED,
     '    if seen.windows(2).any(|pair| pair[0] == pair[1]) {\n        return Err(AnewError::KeyTwice);\n    }',
     '',
     [shared("a_reader_refuses_each_anew_record_that_is_not_one"),
      shared("an_offer_opens_only_for_a_key_it_seals_to_and_to_its_new_channel")]),
    ("A05 an anew record's fill is not read", SHARED,
     '        check_keys(seals.iter().map(|seal| &seal.key))?;\n        if reader.rest().iter().any(|byte| *byte != 0) {\n            return Err(AnewError::Fill);\n        }',
     '        check_keys(seals.iter().map(|seal| &seal.key))?;',
     [shared("a_reader_refuses_each_anew_record_that_is_not_one")]),
    ("A06 an anew record longer than its length is taken", SHARED,
     '        if bytes.len() != SHARED_ANEW_VALUE_BYTES {',
     '        if bytes.len() < SHARED_ANEW_VALUE_BYTES {',
     [shared("a_reader_refuses_each_anew_record_that_is_not_one")]),
    ("A07 a seed is sealed under the new channel's ID before the old's", SHARED,
     '        let info = seal_info(old_channel, &new_channel);',
     '        let info = seal_info(&new_channel, old_channel);',
     [shared("an_anew_record_seals_only_the_new_seed")]),
    ("A08 an offer opens to a seed whose card gives another channel", SHARED,
     '        if card.channel_id().map_err(crypto)? != self.new_channel {\n            return Err(AnewError::AnotherChannel);\n        }',
     '',
     [shared("an_offer_opens_only_for_a_key_it_seals_to_and_to_its_new_channel")]),
    ("A09 an offer opens the first seal for any key", SHARED,
     '            .find(|seal| seal.key == key)',
     '            .find(|_| true)',
     [shared("an_offer_opens_only_for_a_key_it_seals_to_and_to_its_new_channel")]),
    ("A10 a seal is bound to the old channel alone", SHARED,
     '    info.extend_from_slice(old_channel);\n    info.extend_from_slice(new_channel);',
     '    info.extend_from_slice(old_channel);',
     [shared("an_anew_record_seals_only_the_new_seed")]),
    ("A11 a seal to a key that is not usable is read", SHARED,
     '    if !seen.iter().all(|key| is_usable_public_key(key)) {\n        return Err(AnewError::KeyNotUsable);\n    }',
     '',
     [shared("a_reader_refuses_each_anew_record_that_is_not_one")]),
    ("A12 an offer writes one seal more than it holds", SHARED,
     '            out.push(offer.seals.len() as u8);',
     '            out.push(offer.seals.len() as u8 + 1);',
     [shared("an_anew_record_seals_only_the_new_seed")]),
    ("A13 a seal opens under another purpose", SHARED,
     '    info.extend_from_slice(LABEL_ANEW_SEAL);',
     '',
     [shared("an_anew_record_seals_only_the_new_seed")]),
    ("A14 an offer's relays are not read as a card's", SHARED,
     '        let relays = Relays::read(&mut reader).map_err(AnewError::Relays)?;',
     '        let relays = Relays::read(&mut reader).unwrap_or(Relays::new(&[[3; 32]]).unwrap());',
     [shared("a_reader_refuses_each_anew_record_that_is_not_one")]),
    ("A15 an offer of the old channel itself opens", SHARED,
     '        if self.new_channel == *old_channel {\n            return Err(AnewError::SameChannel);\n        }',
     '',
     [shared("an_offer_opens_only_for_a_key_it_seals_to_and_to_its_new_channel")]),
    ("T01 an anew record in its signer's slot is not taken", SHARED,
     '    if name == anew_name(signer).map_err(|_| NotShared::NotInItsSlots)? {',
     '    if name == "anew/" {',
     [shared("a_message_or_an_anew_record_in_another_keys_slot_is_not_taken"),
      shared("every_entry_of_a_shared_channel_is_of_its_one_size")]),
    ("T02 an anew record in another key's slot is taken", SHARED,
     '    if name == anew_name(signer).map_err(|_| NotShared::NotInItsSlots)? {',
     '    if name.starts_with(SHARED_ANEW_PREFIX) {',
     [shared("a_message_or_an_anew_record_in_another_keys_slot_is_not_taken")]),
    ("T03 a list of the messages channel is taken in a shared channel", SHARED,
     '        Some(Place::List) | None => Err(NotShared::NotInItsSlots),',
     '        Some(Place::List) => Ok(SharedTaken::Anew(Anew::Empty)),\n        None => Err(NotShared::NotInItsSlots),',
     [shared("a_message_or_an_anew_record_in_another_keys_slot_is_not_taken")]),
    ("T04 a clearing's value is not checked", SHARED,
     '            is_clearing(value)?;\n            Ok(SharedTaken::Clearing { number })',
     '            Ok(SharedTaken::Clearing { number })',
     [shared("a_message_or_an_anew_record_in_another_keys_slot_is_not_taken")]),
    ("T05 an anew record's name is the prefix and no key", SHARED,
     '        "{SHARED_ANEW_PREFIX}{}",\n        encode_public_key(signer)?',
     '        "{SHARED_ANEW_PREFIX}{}",\n        hex::encode(signer)',
     [shared("a_message_or_an_anew_record_in_another_keys_slot_is_not_taken")]),

    # ── acts.rs: the person's list, and an act's signature ──
    ("C01 an act's signature does not bind its kind", ACTS,
     '        signed.push(T::KIND);',
     '',
     [acts("an_acts_signature_is_its_makers_over_its_label_kind_and_fields")]),
    ("C02 an act's signature is under no label", ACTS,
     '        let mut signed = LABEL_SHARED_ACT.to_vec();',
     '        let mut signed = Vec::new();',
     [acts("an_acts_signature_is_its_makers_over_its_label_kind_and_fields")]),
    ("C03 an act's count is neither written nor signed", ACTS,
     '        out.extend_from_slice(&self.count.to_be_bytes());\n        out.extend_from_slice(&self.maker);',
     '        out.extend_from_slice(&self.maker);',
     [acts("an_acts_signature_is_its_makers_over_its_label_kind_and_fields"),
      acts("a_list_is_its_parts_in_their_places")]),
    ("C04 a maker of small order is taken", ACTS,
     '        is_usable_public_key(&self.maker)\n            && self',
     '        self',
     [acts("an_act_holds_only_with_its_makers_signature_and_within_the_bound")]),
    ("C05 an act's time is not bounded", ACTS,
     '        self.time <= SHARED_ACT_TIME_MAX\n            && self.count',
     '        self.count',
     [acts("an_act_holds_only_with_its_makers_signature_and_within_the_bound")]),
    ("C06 an act's count is not bounded", ACTS,
     '            && self.count <= SHARED_ACT_TIME_MAX\n',
     '',
     [acts("an_act_holds_only_with_its_makers_signature_and_within_the_bound")]),
    ("C07 an act at the bound does not hold", ACTS,
     '        self.time <= SHARED_ACT_TIME_MAX\n',
     '        self.time < SHARED_ACT_TIME_MAX\n',
     [acts("an_act_holds_only_with_its_makers_signature_and_within_the_bound")]),
    ("C08 an act holds whatever its signature", ACTS,
     '            && self.item.agrees()\n            && self.signed_by_its_maker()',
     '            && self.item.agrees()',
     [acts("an_act_holds_only_with_its_makers_signature_and_within_the_bound"),
      acts("an_acts_signature_is_its_makers_over_its_label_kind_and_fields")]),
    ("C09 a filing's ID need not be its card's", ACTS,
     '        self.card.channel_id().ok() == Some(self.channel)',
     '        self.card.channel_id().is_ok()',
     [acts("an_act_holds_only_with_its_makers_signature_and_within_the_bound")]),
    ("C10 a filing and a drop of one channel are two items", ACTS,
     '            .map(|act| act.item.item())\n            .chain(self.drops.iter().map(|act| act.item.item()));',
     '            .map(|act| act.item.item());',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C11 one agent's subscription may stand twice", ACTS,
     '        once_each(self.subscriptions.iter().map(|act| act.item.item()))?;',
     '',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C12 one key's label may stand twice", ACTS,
     '        once_each(self.labels.iter().map(|act| act.item.item()))',
     '        Ok(())',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C13 a list is written with 17 filings", ACTS,
     '            ("filings", SHARED_MAX_CHANNELS, self.filings.len()),',
     '            ("filings", SHARED_MAX_CHANNELS + 1, self.filings.len()),',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C14 a part's count is read past its bound", ACTS,
     '    let count = usize::from(byte(reader)?);\n    if count > most {\n        return Err(ListError::TooMany { part, most, count });\n    }',
     '    let count = usize::from(byte(reader)?);',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C15 a list with a byte after its end is taken", ACTS,
     '        if !reader.is_empty() {\n            return Err(ListError::TrailingBytes);\n        }',
     '',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C16 a list over its most is read", ACTS,
     '        if bytes.len() > SHARED_LIST_MAX_VALUE_BYTES {\n            return Err(ListError::TooLong(bytes.len()));\n        }\n        let mut reader',
     '        let mut reader',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C17 a subscription held is written as 2", ACTS,
     'const SUBSCRIBED: u8 = 1;',
     'const SUBSCRIBED: u8 = 2;',
     [acts("a_list_is_its_parts_in_their_places")]),
    ("C18 a label is behind a length of one byte", ACTS,
     '        put_count(out, label.len());\n        out.extend_from_slice(label.as_bytes());',
     '        out.push(label.len() as u8);\n        out.extend_from_slice(label.as_bytes());',
     [acts("a_list_is_its_parts_in_their_places"),
      acts("the_personal_channel_holds_this_records_lists_at_the_limits")]),
    ("C19 a label past 64 bytes is read", ACTS,
     '        if length > SHARED_LABEL_MAX_BYTES {\n            return Err(ListError::Label);\n        }\n        let label = match',
     '        let label = match',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C20 a label of no bytes is written", ACTS,
     '        if self.label.as_deref() == Some("") || label.len() > SHARED_LABEL_MAX_BYTES {',
     '        if label.len() > SHARED_LABEL_MAX_BYTES {',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C21 a label that is not text is read", ACTS,
     '                std::str::from_utf8(label)\n                    .map_err(|_| ListError::Label)?\n                    .to_string(),',
     '                String::from_utf8_lossy(label).to_string(),',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C22 a name that is not a name is written", ACTS,
     '    if name.is_empty() || name.len() > AGENT_MESSAGE_NAME_MAX_BYTES || !is_a_name(name) {',
     '    if name.is_empty() || name.len() > AGENT_MESSAGE_NAME_MAX_BYTES {',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C23 a name of 201 bytes is written", ACTS,
     '    if name.is_empty() || name.len() > AGENT_MESSAGE_NAME_MAX_BYTES || !is_a_name(name) {',
     '    if name.is_empty() || name.len() > 255 || !is_a_name(name) {',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C24 a name of 201 bytes is read", ACTS,
     '    let length = usize::from(byte(reader)?);\n    if length > AGENT_MESSAGE_NAME_MAX_BYTES {\n        return Err(ListError::Name);\n    }',
     '    let length = usize::from(byte(reader)?);',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C25 a channel moved to is written as taken from a key", ACTS,
     'const CAME_MOVED: u8 = 2;',
     'const CAME_MOVED: u8 = 1;',
     [acts("a_list_is_its_parts_in_their_places")]),
    ("C26 a list's name ends in a slash", ACTS,
     '        "{PERSONAL_SHARED_PREFIX}{}",\n        encode_public_key(device)?',
     '        "{PERSONAL_SHARED_PREFIX}{}/",\n        encode_public_key(device)?',
     [acts("a_list_is_its_parts_in_their_places"),
      acts("the_personal_channel_holds_this_records_lists_at_the_limits")]),
    ("C27 a list is of form 2", ACTS,
     'const FORM_LIST: u8 = 1;',
     'const FORM_LIST: u8 = 2;',
     [acts("a_list_is_its_parts_in_their_places")]),
    ("C28 a subscription's state of 2 is read as not held", ACTS,
     '            NOT_SUBSCRIBED => false,\n            other => return Err(ListError::State(other)),',
     '            _ => false,',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C29 a filing's way of coming of 3 is read as made here", ACTS,
     '            CAME_MOVED => Came::Moved(reader.array().ok_or(ListError::Truncated)?),\n            other => return Err(ListError::Came(other)),',
     '            CAME_MOVED => Came::Moved(reader.array().ok_or(ListError::Truncated)?),\n            _ => Came::Made,',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C30 a filing's card that is not one is read as cut short", ACTS,
     '            other => ListError::Card(other),',
     '            _ => ListError::Truncated,',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C31 a list of another form is read", ACTS,
     '        if form != FORM_LIST {\n            return Err(ListError::Form(form));\n        }',
     '',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C32 a list's fetched time is not bounded", ACTS,
     '        if self.fetched > SHARED_ACT_TIME_MAX {\n            return Err(ListError::FetchedPastTheBound(self.fetched));\n        }',
     '',
     [acts("a_reader_refuses_a_list_that_is_not_one")]),
    ("C33 a list fetched at the bound is refused", ACTS,
     '        if self.fetched > SHARED_ACT_TIME_MAX {',
     '        if self.fetched >= SHARED_ACT_TIME_MAX {',
     [acts("a_reader_refuses_a_list_that_is_not_one"),
      acts("the_personal_channel_holds_this_records_lists_at_the_limits")]),
]
# Rules of the slice that no test can tell, each with why. Leave it
# empty unless the record itself says the rule cannot be tested.
UNTOLD = []

def edits(a, b):
    return list(zip(a, b)) if isinstance(a, list) else [(a, b)]

TEST_MAX_SECS = 1500
BASELINE_TRIES = 3

def run(where, test):
    import os, signal
    crate, args = where
    p = subprocess.Popen(["cargo", "test", "-p", crate, *args, test, "--", "--exact"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         start_new_session=True)
    try:
        out, _ = p.communicate(timeout=TEST_MAX_SECS)
        return out
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        return (out or "") + "\ntest result: FAILED. 0 passed; 1 failed; THE TEST DID NOT END\n"

def verdict_of(text):
    if "error: could not compile" in text or "error[" in text:
        return "DID NOT COMPILE"
    if re.search(r"test result: FAILED\. \d+ passed; [1-9]\d* failed", text):
        return "detected (test failed)"
    passed = re.findall(r"test result: ok\. (\d+) passed", text)
    if passed and any(int(n) >= 1 for n in passed):
        return "NOT DETECTED (test passed)"
    return "NO TEST RAN"

if "--list" in sys.argv:
    print(" ".join(m[0].split()[0] for m in MUTATIONS))
    sys.exit(0)
if "--check" in sys.argv:
    bad = [(name, ORIG[f].count(old)) for name, f, a, b, tests in MUTATIONS
           for old, _ in edits(a, b) if ORIG[f].count(old) != 1]
    names = [m[0].split()[0] for m in MUTATIONS]
    twice = sorted({n for n in names if names.count(n) > 1})
    print(len(MUTATIONS), "mutations;", "all found once" if not bad else bad,
          "" if not twice else f"named twice: {twice}",
          "" if not UNTOLD else f"{len(UNTOLD)} that no test tells: {[u.split()[0] for u in UNTOLD]}")
    sys.exit(1 if bad or twice or UNTOLD else 0)
only = {a for a in sys.argv[1:] if not a.startswith("--")}
MUTATIONS = [m for m in MUTATIONS if m[4] and (not only or m[0].split()[0] in only)]
seen = set()
for _, _, _, _, tests in MUTATIONS:
    for where, test in tests:
        if test in seen:
            continue
        seen.add(test)
        tries = 0
        while True:
            tries += 1
            text = run(where, test)
            v = verdict_of(text)
            if v.startswith('NOT DETECTED') or tries == BASELINE_TRIES:
                break
            why = next((l.strip()[:200] for l in text.splitlines()
                        if "panicked at" in l or "timed out" in l), "")
            print(f"baseline-try | {test} | try {tries} did not pass | {why}", flush=True)
        print(f"baseline | {test} | {'passes' if v.startswith('NOT DETECTED') else 'DOES NOT PASS: ' + v}", flush=True)
        if not v.startswith('NOT DETECTED'):
            sys.exit(1)
try:
    for name, f, a, b, tests in MUTATIONS:
        mutated = ORIG[f]
        for old, new in edits(a, b):
            assert mutated.count(old) == 1, (name, mutated.count(old))
            mutated = mutated.replace(old, new)
        open(f, 'w').write(mutated)
        for where, test in tests:
            text = run(where, test)
            v = verdict_of(text)
            if v in ("DID NOT COMPILE", "NO TEST RAN"):
                print(text[-1500:])
            why = next((l.strip()[:150] for l in text.splitlines()
                        if "panicked at" in l or "timed out" in l), "")
            print(f"{name} | {test} | {v} | {why}", flush=True)
        open(f, 'w').write(ORIG[f])
finally:
    for f, text in ORIG.items():
        open(f, 'w').write(text)
