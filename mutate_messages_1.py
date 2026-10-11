#!/usr/bin/env python3
"""Mutation checks for the constants and the value of a message between a
person's own agents: the constants and labels of decision 2026-10-09 §6 in
protocol.rs, the derivation of the messages channel's secret (§2.1), and
the value of a message, of a clearing and of a list, its ID, its mark, the
names of its slots, the ring check and its revisions (§2.2, §2.3, §2.5) in
cordelia-crypto/src/message.rs. A part for each rule of the slice: put
each fault in, and confirm the test named for it fails on an assertion.
Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
PROTOCOL = 'crates/cordelia-core/src/protocol.rs'
DERIVE = 'crates/cordelia-crypto/src/derive.rs'
MESSAGE = 'crates/cordelia-crypto/src/message.rs'
ORIG = {f: open(f).read() for f in (PROTOCOL, DERIVE, MESSAGE)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
CORE = ("cordelia-core", ["--lib"])
CRYPTO = ("cordelia-crypto", ["--lib"])
API = ("cordelia-api", ["--lib"])
def core(test): return (CORE, "protocol::tests::" + test)
def msg(test): return (CRYPTO, "message::tests::" + test)
def derive(test): return (CRYPTO, "derive::tests::" + test)
def vectors(test): return (CRYPTO, "vectors::" + test)
def api(test): return (API, "sync::tests::" + test)

SIZE = core("test_the_one_size_of_an_entry_of_messages_decision_2026_10_09_2_2")
GUARDS = core("test_the_guards_and_limits_of_messages_decision_2026_10_09_6")
NAMES = core("test_the_messages_channel_and_its_names_decision_2026_10_09_2")
NO_LABEL_BEGINS = core("test_no_label_begins_another_decision_2026_10_04_2_2")
LABELS_LEN = core("test_the_proof_of_a_channels_key_decision_2026_10_04_2_4")
SEAL = msg("the_clearing_entry_and_the_smallest_and_largest_message_each_have_a_content_of_2048_through_entry_seal")
FILL = msg("a_fill_that_is_not_all_zeros_is_no_message")
PARITY = msg("a_relay_tells_a_clearing_from_a_message_by_parity_alone")
OTHER_KEY = msg("a_message_in_a_slot_named_for_another_key_is_no_message")
PLACE = msg("an_entry_whose_number_is_not_in_its_slots_place_is_no_message")
SLOT_NAME = msg("a_slots_name_is_its_signers_key_and_its_place_in_the_ring")
REVISION = msg("the_revision_of_a_message_is_twice_its_number_and_its_clearings_one_more")
NEXT = msg("the_next_number_stops_at_the_highest")
LIVE = msg("a_number_is_live_only_above_the_highest_less_the_ring")
FIELDS = msg("a_messages_value_is_its_fields_in_their_places")
REFUSES = msg("a_reader_refuses_each_message_that_is_not_one")
WRAPS = msg("the_sender_writes_no_value_that_reads_back_as_another_message")
LINK = msg("a_link_is_an_owner_a_repository_and_a_number")
ID = msg("a_messages_id_binds_its_signer_and_its_value")
MARK = msg("a_read_mark_is_of_an_id_and_a_name_and_is_never_the_id")
LIST = msg("a_list_of_read_marks_holds_at_most_120")
SUBJECT = msg("the_subject_is_the_bodys_first_line")
DERIVED = derive("the_messages_channel_is_derived_from_the_person_secret_alone")
VECTORS = vectors("the_code_gives_the_published_vectors")
NAME_BOUND = api("a_names_bound_is_the_bound_of_a_name_in_a_message")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── The constants and the labels (decision 2026-10-09 §6) ──
    ("C01 the ring holds one slot more", PROTOCOL,
     'pub const AGENT_MESSAGE_RING: usize = 64;',
     'pub const AGENT_MESSAGE_RING: usize = 65;',
     [SIZE, SLOT_NAME, LIVE]),
    ("C02 the value is derived with 8 bytes of form, not 7", PROTOCOL,
     ['    - 7\n    - (AGENT_MESSAGE_PREFIX.len() + 70 + 1 + 2);',
      'const _: () =\n    assert!(7 + (AGENT_MESSAGE_PREFIX.len() + 70 + 3) + AGENT_MESSAGE_VALUE_BYTES == 2020);\n'],
     ['    - 8\n    - (AGENT_MESSAGE_PREFIX.len() + 70 + 1 + 2);', ''],
     [SIZE, SEAL]),
    ("C03 the content is 4096", PROTOCOL,
     ['pub const AGENT_MESSAGE_CONTENT_BYTES: usize = 2048;',
      'const _: () =\n    assert!(7 + (AGENT_MESSAGE_PREFIX.len() + 70 + 3) + AGENT_MESSAGE_VALUE_BYTES == 2020);\n',
      'const _: () = assert!(2020 + ITEM_SEAL_OVERHEAD_BYTES == AGENT_MESSAGE_CONTENT_BYTES);\n',
      '        <= MAX_ENTRY_CHANNEL_BYTES_AT_RELAY\n);'],
     ['pub const AGENT_MESSAGE_CONTENT_BYTES: usize = 4096;', '', '',
      '        <= 2 * MAX_ENTRY_CHANNEL_BYTES_AT_RELAY\n);'],
     [SIZE, SEAL]),
    ("C04 a body may be 1025 bytes", PROTOCOL,
     'pub const AGENT_MESSAGE_BODY_MAX_BYTES: usize = 1024;',
     'pub const AGENT_MESSAGE_BODY_MAX_BYTES: usize = 1025;',
     [SIZE, SEAL, REFUSES]),
    ("C05 a name may be 201 bytes", PROTOCOL,
     'pub const AGENT_MESSAGE_NAME_MAX_BYTES: usize = 200;',
     'pub const AGENT_MESSAGE_NAME_MAX_BYTES: usize = 201;',
     [SIZE, REFUSES, NAME_BOUND]),
    ("C06 a link's owner may be 40", PROTOCOL,
     'pub const AGENT_MESSAGE_LINK_OWNER_MAX_BYTES: usize = 39;',
     'pub const AGENT_MESSAGE_LINK_OWNER_MAX_BYTES: usize = 40;',
     [SIZE, LINK]),
    ("C07 a link's repository may be 101", PROTOCOL,
     'pub const AGENT_MESSAGE_LINK_REPO_MAX_BYTES: usize = 100;',
     'pub const AGENT_MESSAGE_LINK_REPO_MAX_BYTES: usize = 101;',
     [SIZE, LINK]),
    ("C08 a link's number may be 11 digits", PROTOCOL,
     'pub const AGENT_MESSAGE_LINK_NUMBER_MAX_DIGITS: usize = 10;',
     'pub const AGENT_MESSAGE_LINK_NUMBER_MAX_DIGITS: usize = 11;',
     [SIZE, LINK]),
    ("C09 a link's most is one byte more than its parts", PROTOCOL,
     '    + AGENT_MESSAGE_LINK_NUMBER_MAX_DIGITS;',
     '    + AGENT_MESSAGE_LINK_NUMBER_MAX_DIGITS\n    + 1;',
     [SIZE, REFUSES]),
    ("C10 an ID is 15 bytes", PROTOCOL,
     'pub const AGENT_MESSAGE_ID_BYTES: usize = 16;',
     'pub const AGENT_MESSAGE_ID_BYTES: usize = 15;',
     [SIZE]),
    ("C11 nine characters of an ID are shown", PROTOCOL,
     'pub const AGENT_MESSAGE_ID_SHOWN_CHARS: usize = 8;',
     'pub const AGENT_MESSAGE_ID_SHOWN_CHARS: usize = 9;',
     [SIZE]),
    ("C12 a mark is 15 bytes", PROTOCOL,
     'pub const AGENT_MESSAGE_READ_MARK_BYTES: usize = 16;',
     'pub const AGENT_MESSAGE_READ_MARK_BYTES: usize = 15;',
     [SIZE]),
    ("C13 the marks are counted without the form and the count", PROTOCOL,
     ['(AGENT_MESSAGE_VALUE_BYTES - 1 - 2) / AGENT_MESSAGE_READ_MARK_BYTES;',
      'const _: () = assert!(\n    1 + 2 + AGENT_MESSAGE_READ_MARKS_MAX * AGENT_MESSAGE_READ_MARK_BYTES\n        <= AGENT_MESSAGE_VALUE_BYTES\n);\n'],
     ['AGENT_MESSAGE_VALUE_BYTES / AGENT_MESSAGE_READ_MARK_BYTES;', ''],
     [SIZE, LIST]),
    ("C14 a message is kept 31 days", PROTOCOL,
     'pub const AGENT_MESSAGE_KEPT_DAYS: u32 = 30;',
     'pub const AGENT_MESSAGE_KEPT_DAYS: u32 = 31;',
     [GUARDS]),
    ("C15 a sent ahead holds sending back for 601 seconds", PROTOCOL,
     'pub const AGENT_MESSAGE_AHEAD_MAX_SECS: u64 = 600;',
     'pub const AGENT_MESSAGE_AHEAD_MAX_SECS: u64 = 601;',
     [GUARDS]),
    ("C16 a message goes under five numbers", PROTOCOL,
     'pub const AGENT_MESSAGE_SENDS_MAX: usize = 4;',
     'pub const AGENT_MESSAGE_SENDS_MAX: usize = 5;',
     [GUARDS]),
    ("C17 a folder sends 21 an hour", PROTOCOL,
     'pub const AGENT_MESSAGES_PER_FOLDER_PER_HOUR: usize = 20;',
     'pub const AGENT_MESSAGES_PER_FOLDER_PER_HOUR: usize = 21;',
     [GUARDS]),
    ("C18 a device sends 61 an hour", PROTOCOL,
     'pub const AGENT_MESSAGES_PER_DEVICE_PER_HOUR: usize = 60;',
     'pub const AGENT_MESSAGES_PER_DEVICE_PER_HOUR: usize = 61;',
     [GUARDS]),
    ("C19 a pair holds at 11", PROTOCOL,
     'pub const AGENT_MESSAGE_PAIR_UNREAD_MAX: usize = 10;',
     'pub const AGENT_MESSAGE_PAIR_UNREAD_MAX: usize = 11;',
     [GUARDS]),
    ("C20 the summary prints six lines", PROTOCOL,
     'pub const AGENT_MESSAGE_SUMMARY_LINES: usize = 5;',
     'pub const AGENT_MESSAGE_SUMMARY_LINES: usize = 6;',
     [GUARDS]),
    ("C21 a subject is cut at 81", PROTOCOL,
     'pub const AGENT_MESSAGE_SUBJECT_CHARS: usize = 80;',
     'pub const AGENT_MESSAGE_SUBJECT_CHARS: usize = 81;',
     [GUARDS]),
    ("C22 an agent's name is cut at 49", PROTOCOL,
     'pub const AGENT_MESSAGE_AGENT_NAME_CHARS: usize = 48;',
     'pub const AGENT_MESSAGE_AGENT_NAME_CHARS: usize = 49;',
     [GUARDS]),
    ("C23 the summary has 101 ms", PROTOCOL,
     'pub const AGENT_MESSAGE_SUMMARY_WAIT_MS: u64 = 100;',
     'pub const AGENT_MESSAGE_SUMMARY_WAIT_MS: u64 = 101;',
     [GUARDS]),
    ("C24 a hook's input is waited for 21 ms", PROTOCOL,
     'pub const AGENT_MESSAGE_HOOK_INPUT_WAIT_MS: u64 = 20;',
     'pub const AGENT_MESSAGE_HOOK_INPUT_WAIT_MS: u64 = 21;',
     [GUARDS]),
    ("C25 a hook's input is read to one byte more", PROTOCOL,
     'pub const AGENT_MESSAGE_HOOK_INPUT_MAX_BYTES: usize = 65_536;',
     'pub const AGENT_MESSAGE_HOOK_INPUT_MAX_BYTES: usize = 65_537;',
     [GUARDS]),
    ("C26 a marker is seven bytes", PROTOCOL,
     'pub const AGENT_MESSAGE_MARKER_BYTES: usize = 6;',
     'pub const AGENT_MESSAGE_MARKER_BYTES: usize = 7;',
     [GUARDS]),
    ("C27 clearing runs every two hours", PROTOCOL,
     'pub const AGENT_MESSAGE_CLEAR_INTERVAL_SECS: u64 = ENTRY_CHANNEL_SWEEP_INTERVAL_SECS;',
     'pub const AGENT_MESSAGE_CLEAR_INTERVAL_SECS: u64 = 2 * ENTRY_CHANNEL_SWEEP_INTERVAL_SECS;',
     [GUARDS]),
    ("C28 the highest number is one more", PROTOCOL,
     ['pub const AGENT_MESSAGE_NUMBER_MAX: u64 = REV_BAND_HALF / 2 - 1;',
      'const _: () = assert!(2 * AGENT_MESSAGE_NUMBER_MAX + 1 < REV_BAND_HALF);\n'],
     ['pub const AGENT_MESSAGE_NUMBER_MAX: u64 = REV_BAND_HALF / 2;', ''],
     [SIZE, REVISION, NEXT]),
    ("C29 the messages channel's label is misspelt", PROTOCOL,
     'pub const LABEL_AGENT_MESSAGES: &[u8] = b"cordelia v2 messages";',
     'pub const LABEL_AGENT_MESSAGES: &[u8] = b"cordelia v2 messagez";',
     [NAMES, DERIVED, VECTORS]),
    ("C30 the messages channel's label begins another", PROTOCOL,
     'pub const LABEL_AGENT_MESSAGES: &[u8] = b"cordelia v2 messages";',
     'pub const LABEL_AGENT_MESSAGES: &[u8] = b"cordelia v2 message";',
     [NO_LABEL_BEGINS, NAMES]),
    ("C31 the ID's label is misspelt", PROTOCOL,
     'pub const LABEL_AGENT_MESSAGE_ID: &[u8] = b"cordelia v2 message id";',
     'pub const LABEL_AGENT_MESSAGE_ID: &[u8] = b"cordelia v2 message ix";',
     [NAMES, ID]),
    ("C32 the mark's label is misspelt", PROTOCOL,
     'pub const LABEL_AGENT_MESSAGE_READ: &[u8] = b"cordelia v2 message read";',
     'pub const LABEL_AGENT_MESSAGE_READ: &[u8] = b"cordelia v2 message reed";',
     [NAMES, MARK]),
    ("C33 the mark's label is not in LABELS", PROTOCOL,
     ['pub const LABELS: [&[u8]; 28] = [', '    LABEL_AGENT_MESSAGE_READ,\n];'],
     ['pub const LABELS: [&[u8]; 27] = [', '];'],
     [NAMES, LABELS_LEN]),
    ("C34 a message's prefix is msgs/", PROTOCOL,
     'pub const AGENT_MESSAGE_PREFIX: &str = "msg/";',
     'pub const AGENT_MESSAGE_PREFIX: &str = "msgs/";',
     [NAMES, SIZE, SLOT_NAME]),
    ("C35 a list's prefix is reads/", PROTOCOL,
     'pub const AGENT_MESSAGE_READ_PREFIX: &str = "read/";',
     'pub const AGENT_MESSAGE_READ_PREFIX: &str = "reads/";',
     [NAMES, SLOT_NAME]),

    # ── The derivation (decision 2026-10-09 §2.1) ──
    ("D01 the messages channel is the personal channel", DERIVE,
     '    hkdf_sha256(person_secret, &[], LABEL_AGENT_MESSAGES)',
     '    hkdf_sha256(person_secret, &[], LABEL_PERSONAL)',
     [DERIVED, VECTORS]),

    # ── The value (decision 2026-10-09 §2.2) ──
    ("V01 a message's form is 3", MESSAGE,
     'const FORM_MESSAGE: u8 = 1;', 'const FORM_MESSAGE: u8 = 3;',
     [FIELDS]),
    ("V02 a list's form is 3", MESSAGE,
     'const FORM_LIST: u8 = 2;', 'const FORM_LIST: u8 = 3;',
     [LIST]),
    ("V03 a clearing's form is 3", MESSAGE,
     'const FORM_CLEARING: u8 = 0;', 'const FORM_CLEARING: u8 = 3;',
     [FILL]),
    ("V04 asking is bit 1", MESSAGE,
     'const FLAG_ASKS: u8 = 0b0000_0001;', 'const FLAG_ASKS: u8 = 0b0000_0010;',
     [FIELDS]),
    ("V05 to one name is kind 3", MESSAGE,
     'const TO_ONE: u8 = 1;', 'const TO_ONE: u8 = 3;',
     [FIELDS]),
    ("V06 to every name is kind 3", MESSAGE,
     'const TO_ALL: u8 = 2;', 'const TO_ALL: u8 = 3;',
     [FIELDS]),
    ("V07 sent is written low byte first", MESSAGE,
     'out.extend_from_slice(&self.sent.to_be_bytes());',
     'out.extend_from_slice(&self.sent.to_le_bytes());',
     [FIELDS]),
    ("V08 answers is written before thread", MESSAGE,
     '        out.extend_from_slice(&self.thread);\n        out.extend_from_slice(&self.answers);',
     '        out.extend_from_slice(&self.answers);\n        out.extend_from_slice(&self.thread);',
     [FIELDS]),
    ("V09 a reader takes any flag", MESSAGE,
     'if flags & !FLAG_ASKS != 0 {', 'if flags & !FLAG_ASKS != 0 && false {',
     [REFUSES]),
    ("V10 a reader reads asks as never", MESSAGE,
     'asks: flags & FLAG_ASKS != 0,', 'asks: false,',
     [REFUSES]),
    ("V11 a reader takes a from of 201", MESSAGE,
     'let from = field(&mut reader, AGENT_MESSAGE_NAME_MAX_BYTES)?;',
     'let from = field(&mut reader, AGENT_MESSAGE_NAME_MAX_BYTES + 1)?;',
     [REFUSES]),
    ("V12 a reader takes a to of 201", MESSAGE,
     'let to = field(&mut reader, AGENT_MESSAGE_NAME_MAX_BYTES)?;',
     'let to = field(&mut reader, AGENT_MESSAGE_NAME_MAX_BYTES + 1)?;',
     [REFUSES]),
    ("V13 a field takes one byte past its bound", MESSAGE,
     '    if length > most {', '    if length > most + 1 {',
     [REFUSES]),
    ("V14 a name need not be a name", MESSAGE,
     'Ok(name) if !name.is_empty() && is_a_name(name) =>',
     'Ok(name) if !name.is_empty() =>',
     [REFUSES]),
    ("V15 a name may be empty", MESSAGE,
     'Ok(name) if !name.is_empty() && is_a_name(name) =>',
     'Ok(name) if is_a_name(name) =>',
     [REFUSES]),
    ("V16 to one name reads as every name", MESSAGE,
     'TO_ONE => To::Name(name_in(to, &is_a_name)?),',
     'TO_ONE => To::All,',
     [FIELDS]),
    ("V17 every name may name a name", MESSAGE,
     'TO_ALL if to.is_empty() => To::All,', 'TO_ALL if true => To::All,',
     [REFUSES]),
    ("V18 a reader takes a link of 152", MESSAGE,
     'if length > AGENT_MESSAGE_LINK_MAX_BYTES {', 'if length > AGENT_MESSAGE_LINK_MAX_BYTES + 1 {',
     [REFUSES]),
    ("V19 a reader takes a link that is not one", MESSAGE,
     'if !is_a_link(link) {', 'if !is_a_link(link) && false {',
     [REFUSES]),
    ("V20 a reader takes an empty body", MESSAGE,
     'if length == 0 {', 'if length == usize::MAX {',
     [REFUSES]),
    ("V21 a reader takes a body of 1025", MESSAGE,
     'if length > AGENT_MESSAGE_BODY_MAX_BYTES {', 'if length > AGENT_MESSAGE_BODY_MAX_BYTES + 1 {',
     [REFUSES]),
    ("V22 a reader takes a body that is not text", MESSAGE,
     'let body = String::from_utf8(body.to_vec()).map_err(|_| NotAMessage::BodyNotText)?;',
     'let body = String::from_utf8_lossy(body).into_owned();',
     [REFUSES]),
    ("V23 a message's fill is not read", MESSAGE,
     '        filled(&reader)?;\n        Ok(Self {\n            asks',
     '        Ok(Self {\n            asks',
     [FILL]),
    ("V24 a fill of ones is zeros", MESSAGE,
     '.any(|byte| *byte != 0)', '.any(|byte| *byte > 1)',
     [FILL]),
    ("V25 a value may be shorter", MESSAGE,
     'if bytes.len() != AGENT_MESSAGE_VALUE_BYTES {', 'if bytes.len() > AGENT_MESSAGE_VALUE_BYTES {',
     [REFUSES]),
    ("V26 a text is read as a value", MESSAGE,
     '    let Value::Other(bytes) = value else {\n        return Err(NotAMessage::Kind);\n    };',
     '    let bytes = value.bytes();',
     [REFUSES]),
    ("V27 a reader takes a form there is not", MESSAGE,
     'if form != FORM_MESSAGE {', 'if form == 99 {',
     [REFUSES]),
    ("V28 a list's form is said to be no form", MESSAGE,
     'FORM_CLEARING | FORM_MESSAGE | FORM_LIST => NotAMessage::AnotherForm(form),',
     'FORM_CLEARING | FORM_MESSAGE => NotAMessage::AnotherForm(form),',
     [PLACE]),
    ("V29 the sender does not read back what it wrote", MESSAGE,
     '        if Self::from_value(&Value::Other(out.clone()), is_a_name)? != *self {\n'
     '            return Err(NotAMessage::Field);\n'
     '        }\n',
     '',
     [REFUSES]),
    ("V30 the sender takes a link of nothing", MESSAGE,
     'if self.link.as_deref() == Some("") {', 'if self.link.as_deref() == Some("") && false {',
     [REFUSES]),
    ("V31 the sender writes a from that its length cannot count", MESSAGE,
     'if self.from.len() > AGENT_MESSAGE_NAME_MAX_BYTES', 'if self.from.len() > usize::MAX',
     [WRAPS]),
    ("V32 the sender writes a to that its length cannot count", MESSAGE,
     '|| to.len() > AGENT_MESSAGE_NAME_MAX_BYTES', '|| to.len() > usize::MAX',
     [WRAPS]),
    ("V33 the sender writes a link that its length cannot count", MESSAGE,
     '|| link.len() > AGENT_MESSAGE_LINK_MAX_BYTES', '|| link.len() > usize::MAX',
     [WRAPS]),
    ("V34 the sender writes a body that its length cannot count", MESSAGE,
     'if self.body.len() > AGENT_MESSAGE_BODY_MAX_BYTES {', 'if self.body.len() > usize::MAX {',
     [WRAPS]),
    ("V35 the subject ends at a space", MESSAGE,
     "self.body.split('\\n').next()", "self.body.split(' ').next()",
     [SUBJECT]),

    # ── A clearing and a list (decision 2026-10-09 §2.2, §2.4) ──
    ("L01 a clearing is written as a list", MESSAGE,
     'value[0] = FORM_CLEARING;', 'value[0] = FORM_LIST;',
     [FILL, SEAL]),
    ("L02 a clearing's form is not read", MESSAGE,
     'if form != FORM_CLEARING {', 'if form == 99 {',
     [PLACE]),
    ("L03 a clearing's fill is not read", MESSAGE,
     '    filled(&reader)\n}', '    Ok(())\n}',
     [FILL]),
    ("L04 a list of 121 is written", MESSAGE,
     'if self.marks.len() > AGENT_MESSAGE_READ_MARKS_MAX {', 'if self.marks.len() > AGENT_MESSAGE_READ_MARKS_MAX + 1 {',
     [LIST]),
    ("L05 a list that says 121 is read", MESSAGE,
     'if count > AGENT_MESSAGE_READ_MARKS_MAX {', 'if count > AGENT_MESSAGE_READ_MARKS_MAX + 1 {',
     [LIST]),
    ("L06 a list's form is not read", MESSAGE,
     'if form != FORM_LIST {', 'if form == 99 {',
     [PLACE]),
    ("L07 a list's fill is not read", MESSAGE,
     '        filled(&reader)?;\n        Ok(Self { marks })', '        Ok(Self { marks })',
     [FILL]),
    ("L08 a list is written oldest first", MESSAGE,
     'for mark in &self.marks {', 'for mark in self.marks.iter().rev() {',
     [LIST]),

    # ── The ring and the revisions (decision 2026-10-09 §2.3, §2.5) ──
    ("R01 any list slot is a list's", MESSAGE,
     'if name == read_name(signer).ok()? {', 'if name.starts_with(AGENT_MESSAGE_READ_PREFIX) {',
     [OTHER_KEY]),
    ("R02 number 0 is a message's", MESSAGE,
     'if !is_a_number(number) || name != message_name(signer, number).ok()? {',
     'if number > AGENT_MESSAGE_NUMBER_MAX || name != message_name(signer, number).ok()? {',
     [PLACE]),
    ("R03 any message slot is the signer's", MESSAGE,
     'if !is_a_number(number) || name != message_name(signer, number).ok()? {',
     'if !is_a_number(number) || !name.starts_with(AGENT_MESSAGE_PREFIX) {',
     [OTHER_KEY, PLACE]),
    ("R04 an odd revision is a message's", MESSAGE,
     'Some(if is_clearing_rev(rev) {', 'Some(if !is_clearing_rev(rev) {',
     [PLACE, OTHER_KEY]),
    ("R05 an even revision is a clearing's", MESSAGE,
     'rev % 2 == 1', 'rev % 2 == 0',
     [REVISION, PARITY]),
    ("R06 a clearing's number is rounded up", MESSAGE,
     '    rev / 2\n', '    rev.div_ceil(2)\n',
     [REVISION]),
    ("R07 a message's revision is twice its number and two", MESSAGE,
     'is_a_number(number).then(|| 2 * number)\n', 'is_a_number(number).then(|| 2 * number + 2)\n',
     [REVISION]),
    ("R08 a clearing's revision is three above", MESSAGE,
     'is_a_number(number).then(|| 2 * number + 1)', 'is_a_number(number).then(|| 2 * number + 3)',
     [REVISION]),
    ("R09 number 0 has a revision", MESSAGE,
     '(1..=AGENT_MESSAGE_NUMBER_MAX).contains(&number)', '(0..=AGENT_MESSAGE_NUMBER_MAX).contains(&number)',
     [REVISION]),
    ("R10 a number past the highest has a revision", MESSAGE,
     '(1..=AGENT_MESSAGE_NUMBER_MAX).contains(&number)', '(1..=AGENT_MESSAGE_NUMBER_MAX + 1).contains(&number)',
     [REVISION]),
    ("R11 the next number goes past the highest", MESSAGE,
     'highest.checked_add(1).filter(|next| is_a_number(*next))', 'highest.checked_add(1)',
     [NEXT]),
    ("R12 a number a lap below the highest is live", MESSAGE,
     'number > highest.saturating_sub(AGENT_MESSAGE_RING as u64)',
     'number >= highest.saturating_sub(AGENT_MESSAGE_RING as u64)',
     [LIVE]),
    ("R13 a slot is named by the number and not its place", MESSAGE,
     '        number % AGENT_MESSAGE_RING as u64\n', '        number\n',
     [SLOT_NAME]),
    ("R14 a slot's place follows a dash", MESSAGE,
     '"{AGENT_MESSAGE_PREFIX}{}/{}"', '"{AGENT_MESSAGE_PREFIX}{}-{}"',
     [SLOT_NAME]),
    ("R15 a list's name has a slash too many", MESSAGE,
     '"{AGENT_MESSAGE_READ_PREFIX}{}"', '"{AGENT_MESSAGE_READ_PREFIX}/{}"',
     [SLOT_NAME]),
    ("R16 an entry of the channel has no chain", MESSAGE,
     '        chain: Some(Vec::new()),', '        chain: None,',
     [SEAL]),
    ("R17 a message past the highest number is placed", MESSAGE,
     'if !is_a_number(number) || name != message_name(signer, number).ok()? {',
     'if (number == 0 || (number > AGENT_MESSAGE_NUMBER_MAX && is_clearing_rev(rev)))\n'
     '        || name != message_name(signer, number).ok()?\n    {',
     [PLACE]),
    ("R18 a clearing past the highest number is placed", MESSAGE,
     'if !is_a_number(number) || name != message_name(signer, number).ok()? {',
     'if (number == 0 || (number > AGENT_MESSAGE_NUMBER_MAX && !is_clearing_rev(rev)))\n'
     '        || name != message_name(signer, number).ok()?\n    {',
     [PLACE]),
    ("R19 a number is live by a sum that overflows at the top", MESSAGE,
     'number > highest.saturating_sub(AGENT_MESSAGE_RING as u64)',
     'number + AGENT_MESSAGE_RING as u64 > highest',
     [LIVE]),

    # ── The ID and the mark (decision 2026-10-09 §2.2) ──
    ("I01 an ID is under the mark's label", MESSAGE,
     '    hashed.extend_from_slice(LABEL_AGENT_MESSAGE_ID);', '    hashed.extend_from_slice(LABEL_AGENT_MESSAGE_READ);',
     [ID]),
    ("I02 an ID does not bind its signer", MESSAGE,
     '    hashed.extend_from_slice(signer);\n', '',
     [ID]),
    ("I03 a mark is under the ID's label", MESSAGE,
     '    hashed.extend_from_slice(LABEL_AGENT_MESSAGE_READ);', '    hashed.extend_from_slice(LABEL_AGENT_MESSAGE_ID);',
     [MARK]),
    ("I04 a mark is of the ID alone", MESSAGE,
     '    hashed.extend_from_slice(name.as_bytes());\n', '',
     [MARK]),

    # ── The link (decision 2026-10-09 §2.2) ──
    ("K01 an owner may hold an underscore", MESSAGE,
     'of(owner, AGENT_MESSAGE_LINK_OWNER_MAX_BYTES, b"-")', 'of(owner, AGENT_MESSAGE_LINK_OWNER_MAX_BYTES, b"-_")',
     [LINK]),
    ("K02 an owner may be 40", MESSAGE,
     'of(owner, AGENT_MESSAGE_LINK_OWNER_MAX_BYTES, b"-")', 'of(owner, AGENT_MESSAGE_LINK_OWNER_MAX_BYTES + 1, b"-")',
     [LINK]),
    ("K03 a repository may hold a slash", MESSAGE,
     'of(repo, AGENT_MESSAGE_LINK_REPO_MAX_BYTES, b"._-")', 'of(repo, AGENT_MESSAGE_LINK_REPO_MAX_BYTES, b"._-/")',
     [LINK]),
    ("K04 a part may be empty", MESSAGE,
     '(1..=most).contains(&part.len())', '(0..=most).contains(&part.len())',
     [LINK]),
    ("K05 a number may begin with 0", MESSAGE,
     "        && !number.starts_with('0')\n", '\n',
     [LINK]),
    ("K06 a number may hold letters", MESSAGE,
     'number.bytes().all(|b| b.is_ascii_digit())', 'number.bytes().all(|b| b.is_ascii_alphanumeric())',
     [LINK]),
    ("K07 a number may be 11 digits", MESSAGE,
     '(1..=AGENT_MESSAGE_LINK_NUMBER_MAX_DIGITS).contains(&number.len())',
     '(1..=AGENT_MESSAGE_LINK_NUMBER_MAX_DIGITS + 1).contains(&number.len())',
     [LINK]),
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
