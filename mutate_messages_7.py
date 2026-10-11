#!/usr/bin/env python3
"""Mutation checks for the routes and the commands of messages between a
person's own agents: `cordelia msg summary`, `msg read` and `msg send`,
and the routes under /api/v1/messages/ behind them. The folder a command
runs in and the agent it maps to; the summary, its lines, its count, its
silence on any error and its 100 ms; the frame of a body, the cleaning of
text another device chose by Unicode category, the cutting of names and
subjects and the quoting of labels; the checks of send and read in the
record's one order, each refusal by its word and its line; the lookup of
the message a reply answers; the configuration's [messages] table; and
the refusal for room that send names (decision 2026-10-09 §3, §3.1, §4.1,
§4.2, §4.3, §5, §6, §10). A part for each rule of the slice: put each
fault in, and confirm the test named for it fails on an assertion. Run
from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
CONFIG = 'crates/cordelia-core/src/config.rs'
STORE = 'crates/cordelia-storage/src/messages.rs'
MSG = 'crates/cordelia-api/src/messages.rs'
SENDER = 'crates/cordelia-api/src/sender.rs'
STATE = 'crates/cordelia-api/src/state.rs'
FOUND = 'crates/cordelia-api/src/found.rs'
LIB = 'crates/cordelia-api/src/lib.rs'
LOOK = 'crates/cordelia-api/src/look.rs'
CMD = 'crates/cordelia-node/src/msg_cmd.rs'
MAIN = 'crates/cordelia-node/src/main.rs'
ENGINE = 'crates/cordelia-node/src/device_entries.rs'
ORIG = {f: open(f).read() for f in (CONFIG, STORE, MSG, SENDER, STATE, FOUND, LIB, LOOK,
                                     CMD, MAIN, ENGINE)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
CORE = ("cordelia-core", ["--lib"])
STORAGE = ("cordelia-storage", ["--lib"])
API = ("cordelia-api", ["--lib"])
BIN = ("cordelia-node", ["--bin", "cordelia"])
E2E = ("cordelia-node", ["--test", "msg_e2e"])
THREAT = ("cordelia-node", ["--test", "threat_model"])
def core(test): return (CORE, "config::tests::" + test)
def stored(test): return (STORAGE, "messages::tests::" + test)
def found(test): return (API, "found::tests::" + test)
def api(test): return (API, "messages::tests::" + test)
def cmd(test): return (BIN, "msg_cmd::tests::" + test)
def main(test): return (BIN, "tests::" + test)
def e2e(test): return (E2E, test)

LIMIT = core("test_a_folders_limit_of_messages_is_from_0_to_20")
SHOWED = stored("the_marks_of_what_a_device_showed_are_by_name_and_go_with_their_message")
BY_AUTHOR = stored("entries_are_counted_by_author_the_most_first")
GIT_BY = found("test_git_given_until_a_deadline_answers_in_time_or_not_at_all")
SEVEN = api("the_seven_categories_and_what_renders_as_nothing_are_taken_out_and_no_other")
SUBJECT = api("a_subject_is_the_first_line_cleaned_and_cut_at_80")
AGENT = api("the_agent_of_a_folder_is_the_mapping_whose_folder_is_the_same_byte_for_byte")
FIVE = api("a_summary_announces_at_most_five_and_counts_the_rest")
OLDEST = api("oldest_first_is_by_shown_time_then_by_id")
NO_ENTRY = api("the_summary_opens_no_entry")
FORK = api("a_device_in_a_fork_or_in_no_list_shows_nothing")
READS = api("read_shows_what_the_agent_may_read_and_marks_what_is_for_it")
THREAD = api("the_thread_is_set_by_the_node_and_not_the_sender")
ORDER = api("the_checks_are_made_in_one_order")
NO_PLACE = api("a_device_with_no_place_for_messages_shows_no_summary")
DETAILS = api("the_details_of_each_refusal_are_beside_its_word")
LOCK = api("a_node_that_cannot_have_its_lock_in_time_answers_nothing")
HELD = api("a_summary_of_another_version_or_while_held_up_is_nothing")
ROUTES = api("the_routes_of_messages_are_a_personal_nodes_and_each_needs_the_token")
FIRST_FETCH = api("the_first_send_after_a_start_waits_for_the_ring_to_be_fetched")
BY_WORD = api("a_refusal_is_answered_by_its_word_and_what_its_line_names")
ROOM = api("a_send_after_a_refusal_for_room_names_who_fills_the_channel")
WORDS = cmd("the_frame_the_summary_and_the_refusals_say_what_this_record_says")
LINK = cmd("the_link_is_printed_inside_the_frame_as_the_senders")
TWO_VALUES = cmd("two_readings_of_one_message_have_two_values")
CATEGORIES = cmd("every_character_of_the_set_is_taken_out_of_a_subject_a_name_a_label_and_a_link_and_escaped_in_a_body")
CUT_48 = cmd("the_agents_name_is_cut_at_48_in_summary_read_and_send_and_the_subject_at_80")
QUOTE = cmd("a_label_with_a_quote_cannot_close_its_quotes")
CMD_ORDER = cmd("the_checks_are_made_in_one_order")
RECOGNISED = cmd("the_summary_is_recognised_before_the_command_line_is_parsed")
HOOK_JSON = cmd("a_hooks_input_gives_its_cwd_where_it_is_whole_json")
DIRECTORY = cmd("the_directory_is_claude_codes_variable_then_the_hooks_then_its_own")
HELP = main("the_summarys_help_holds_the_hook_and_the_instructions_line")
ERRORS = e2e("the_summary_prints_nothing_and_exits_0_on_any_error")
IN_TIME = e2e("the_summary_answers_within_its_time_or_prints_nothing")
HOOK = e2e("the_summary_takes_its_directory_from_the_hooks_input")
VARIABLE = e2e("a_command_takes_its_directory_from_claude_codes_variable_first")
SIGNED = e2e("a_message_is_shown_from_the_device_that_signed_it")
RATE_0 = e2e("a_folder_whose_rate_is_0_sends_nothing")
DEVICE_RATE = e2e("a_device_over_its_hour_sends_nothing_more_and_every_name_counts_once")
INPUT = e2e("send_reads_at_most_one_byte_over_and_gives_up_on_input_that_does_not_end")
NO_PHRASE = e2e("a_device_that_follows_no_phrase_sends_and_shows_nothing")
SUBDIR = e2e("a_subdirectory_of_a_mapped_repository_is_its_agent_and_of_another_folder_is_not")
SERVED = api("another_request_is_served_while_a_summary_waits_for_the_store")
BACKSLASH = cmd("a_backslash_in_a_body_is_escaped")
FILLED = cmd("the_label_of_the_signer_that_fills_the_channel_is_quoted_and_cleaned")
ADDRESS = cmd("the_node_is_reached_at_either_address_the_api_may_have")
NOT_IN_TIME = cmd("a_request_not_answered_in_time_is_not_a_node_that_is_not_running")
GIT_HANGS = e2e("a_git_that_does_not_answer_is_refused_and_no_folder_is_taken")
LATE = e2e("a_node_that_answers_late_is_not_said_to_be_not_running")
CLOSED = e2e("send_and_read_with_their_output_closed_do_what_they_did_and_exit_0")
FOR_ROOM = (THREAT, "a_message_that_a_relay_refuses_for_room_leaves_the_level_and_the_line")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── The configuration's [messages] (§6) ──
    ("CF1 a folder's limit of 20 in the configuration is refused", CONFIG,
     '''if self.per_folder_per_hour as usize > protocol::AGENT_MESSAGES_PER_FOLDER_PER_HOUR {''',
     '''if self.per_folder_per_hour as usize >= protocol::AGENT_MESSAGES_PER_FOLDER_PER_HOUR {''',
     [LIMIT]),
    ("CF2 a limit over 20 is not refused when the configuration is loaded", CONFIG,
     '''        config.messages.check()?;\n''', '''''', [LIMIT]),
    ("CF3 the folder's limit is 19 where it is not set", CONFIG,
     '''per_folder_per_hour: protocol::AGENT_MESSAGES_PER_FOLDER_PER_HOUR as u32,''',
     '''per_folder_per_hour: protocol::AGENT_MESSAGES_PER_FOLDER_PER_HOUR as u32 - 1,''',
     [LIMIT]),
    ("CF4 the node is not told the folder's limit", MAIN,
     '''.set_per_folder_per_hour(config.messages.per_folder_per_hour as usize);''',
     '''.set_per_folder_per_hour(20);''', [RATE_0]),
    ("CF5 the folder's limit where the node said none is 0", STATE,
     '''|most| most as usize,''', '''|most| most as usize * 0,''', [BY_WORD]),
    # ── The store's marks of what was shown ──
    ("ST1 a summary's mark is not kept", STORE,
     '''"INSERT OR IGNORE INTO message_announced (id, name) VALUES (?1, ?2)",''',
     '''"INSERT OR IGNORE INTO message_announced (id, name) SELECT ?1, ?2 WHERE 0",''',
     [SHOWED, FIVE]),
    ("ST2 a summary's mark is for every name", STORE,
     '''"SELECT COUNT(*) FROM message_announced WHERE id = ?1 AND name = ?2",''',
     '''"SELECT COUNT(*) FROM message_announced WHERE id = ?1 AND name != ?2 || name",''',
     [SHOWED]),
    ("ST3 no message is read by a person", STORE,
     '''"SELECT COUNT(*) FROM message_read_by_a_person WHERE id = ?1",''',
     '''"SELECT COUNT(*) FROM message_read_by_a_person WHERE id = ?1 AND 0",''',
     [SHOWED, READS]),
    ("ST4 the author with the fewest entries fills the channel", STORE,
     '''GROUP BY author ORDER BY held DESC, author",''',
     '''GROUP BY author ORDER BY held, author",''', [BY_AUTHOR, ROOM]),
    # ── The seven categories (§4.1, C4) ──
    ("TX1 controls are not taken out", MSG,
     '''        Category::Control\n            | Category::Format''',
     '''        Category::Format''', [SEVEN, CATEGORIES]),
    ("TX2 format characters are not taken out", MSG,
     '''            | Category::Format\n''', '''''', [SEVEN, CATEGORIES]),
    ("TX3 private use is not taken out", MSG,
     '''            | Category::PrivateUse\n''', '''''', [SEVEN, CATEGORIES]),
    ("TX4 what is unassigned is not taken out", MSG,
     '''            | Category::Unassigned\n''', '''''', [SEVEN, CATEGORIES]),
    ("TX5 the line separator is not taken out", MSG,
     '''            | Category::LineSeparator\n''', '''''', [SEVEN, CATEGORIES]),
    ("TX6 the paragraph separator is not taken out", MSG,
     '''            | Category::ParagraphSeparator\n''', '''''', [SEVEN]),
    ("TX7 spaces are taken out too", MSG,
     '''            | Category::ParagraphSeparator\n''',
     '''            | Category::ParagraphSeparator\n            | Category::SpaceSeparator\n''',
     [SEVEN]),
    ("TX8 a text cut says it was not", MSG,
     '''Some((at, _)) => (text[..at].to_string(), true),''',
     '''Some((at, _)) => (text[..at].to_string(), false),''', [SUBJECT, CUT_48]),
    ("TX9 the subject is not the first line", MSG,
     '''let first = body.split('\\n').next().unwrap_or_default();''',
     '''let first = body;''', [SUBJECT]),
    ("TX10 the subject is cut before it is cleaned", MSG,
     '''cut(&cleaned(first), AGENT_MESSAGE_SUBJECT_CHARS)''',
     '''cut(first, AGENT_MESSAGE_SUBJECT_CHARS)''', [SUBJECT]),
    # ── The folder (§3.1) ──
    ("FO1 a mapping's folder that begins the path is taken", MSG,
     '''.find(|mapping| mapping.folder == folder)''',
     '''.find(|mapping| folder.starts_with(&mapping.folder))''', [AGENT]),
    ("FO2 the folder is not tidied as a mapping was", MSG,
     '''let Some(folder) = crate::sync::clean_path(folder) else {''',
     '''let Some(folder) = Some(folder.to_string()) else {''', [AGENT]),
    ("FO3 the command takes the directory itself, not its repository's", CMD,
     '''let folder = cordelia_api::found::memory_root_by(&real, Instant::now() + git_wait)?;''',
     '''let folder = real.clone();''', [SUBDIR]),
    ("FO4 the summary takes the directory itself, not its repository's", CMD,
     '''let folder = cordelia_api::found::memory_root_by(&real, deadline)?;''',
     '''let folder = Some(real.clone()).filter(|_| Instant::now() < deadline)?;''', [SUBDIR]),
    ("FO5 git is not stopped at the deadline", FOUND,
     '''Ok(None) if std::time::Instant::now() < deadline => {''', '''Ok(None) => {''',
     [GIT_BY]),
    ("FO6 Claude Code's variable is taken where it names no directory", CMD,
     '''if let Some(dir) = project_dir.map(PathBuf::from).filter(|dir| dir.is_dir()) {''',
     '''if let Some(dir) = project_dir.map(PathBuf::from) {''', [DIRECTORY]),
    ("FO7 Claude Code's variable is not read", CMD,
     '''if let Some(dir) = project_dir.map(PathBuf::from).filter(|dir| dir.is_dir()) {''',
     '''if let Some(dir) = project_dir.map(PathBuf::from).filter(|_| false) {''',
     [DIRECTORY, VARIABLE]),
    ("FO8 the hook's input is read for another field", CMD,
     '''read.get("cwd")?.as_str().map(PathBuf::from)''',
     '''read.get("dir")?.as_str().map(PathBuf::from)''', [HOOK_JSON, HOOK]),
    # ── An ID and the message it names (§4.1, §4.3 step 9) ──
    ("ID1 an ID of seven hex characters is taken", MSG,
     '''(AGENT_MESSAGE_ID_SHOWN_CHARS..=2 * AGENT_MESSAGE_ID_BYTES).contains(&given.len())''',
     '''(AGENT_MESSAGE_ID_SHOWN_CHARS - 1..=2 * AGENT_MESSAGE_ID_BYTES).contains(&given.len())''',
     [CMD_ORDER]),
    ("ID2 an ID of letters that are no hex is taken", MSG,
     '''&& given.bytes().all(|b| b.is_ascii_hexdigit())''',
     '''&& given.bytes().all(|b| b.is_ascii_alphanumeric())''', [CMD_ORDER, ORDER, BY_WORD]),
    ("ID3 an agent answers its own message to every name", MSG,
     '''(to_it && !its_own) || (sent_too && its_own)''',
     '''to_it || (sent_too && its_own)''', [THREAD]),
    ("ID4 an agent answers what it sent", MSG,
     '''(to_it && !its_own) || (sent_too && its_own)''',
     '''(to_it && !its_own) || its_own''', [THREAD]),
    ("ID5 an ID that begins two messages names the first", MSG,
     '''let message = match found.len() {''',
     '''let message = match found.len().min(1) {''', [ORDER]),
    ("ID6 a message whose signer no longer counts is named", MSG,
     '''    if !who_counts(conn)?.counts(&signer) {''',
     '''    if false && !who_counts(conn)?.counts(&signer) {''', [ORDER]),
    ("ID7 a message that asks for nothing is answered", MSG,
     '''    if !message.asks {''', '''    if false && !message.asks {''', [ORDER]),
    ("ID8 a reply to the first of a thread has no thread", MSG,
     '''Ok(thread) if thread != [0; AGENT_MESSAGE_ID_BYTES] => thread,''',
     '''Ok(thread) => thread,''', [THREAD]),
    ("ID9 a reply answers its thread, not its message", MSG,
     '''        answers: id,\n    }))''', '''        answers: thread,\n    }))''', [THREAD]),
    # ── summary (§4.1, C5, C6, C20) ──
    ("SU1 summary with sync off", MSG,
     '''        if meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_none()\n            || stands''',
     '''        if false\n            || stands''', [ERRORS]),
    ("SU2 summary where the device does not stand applied", MSG,
     '''            || stands(conn)? != Stands::Applied\n            || own_channels.no_place()''',
     '''            || own_channels.no_place()''', [FORK]),
    ("SU3 summary with no place for messages", MSG,
     '''            || stands(conn)? != Stands::Applied\n            || own_channels.no_place()''',
     '''            || stands(conn)? != Stands::Applied''', [NO_PLACE]),
    ("SU4 summary gives no places", MSG,
     '''        kept(held::give_places(conn, &own, now))?;\n        let counting = who_counts(conn)?;\n        let mut lines''',
     '''        let counting = who_counts(conn)?;\n        let mut lines''', [FIVE]),
    ("SU5 summary shows a signer that no longer counts", MSG,
     '''            if !counting.counts(&key_of(&message.signer)?) {''',
     '''            if false && !counting.counts(&key_of(&message.signer)?) {''', [ORDER]),
    ("SU6 a message to every name is a line", MSG,
     '''            let new = message.to.is_some()''', '''            let new = true''', [FIVE]),
    ("SU7 six lines", MSG,
     '''&& lines.len() < AGENT_MESSAGE_SUMMARY_LINES''',
     '''&& lines.len() <= AGENT_MESSAGE_SUMMARY_LINES''', [FIVE]),
    ("SU8 a line is printed again", MSG,
     '''                && !kept(held::is_announced(conn, &id, &name))?;''',
     '''                ;''', [FIVE]),
    ("SU9 a line is not marked announced", MSG,
     '''            kept(held::announce(conn, &id, &name))?;\n''', '''''', [FIVE]),
    ("SU10 a message of this device is shown with a label", MSG,
     '''label: (message.signer[..] != own[..]).then_some(message.label),''',
     '''label: Some(message.label),''', [FIVE]),
    ("SU11 how long ago is from `sent`", MSG,
     '''                label: (message.signer[..] != own[..]).then_some(message.label),\n                ago_secs: now.saturating_sub(message.shown_at).max(0),''',
     '''                label: (message.signer[..] != own[..]).then_some(message.label),\n                ago_secs: now.saturating_sub(message.sent).max(0),''',
     [OLDEST]),
    ("SU12 the summary waits for the lock past its own time", MSG,
     '''Duration::from_millis(within_ms.min(AGENT_MESSAGE_SUMMARY_WAIT_MS))''',
     '''Duration::from_millis(within_ms)''', [LOCK]),
    ("SU13 a request of another version is answered", MSG,
     '''    if body.version != env!("CARGO_PKG_VERSION") {''', '''    if false {''', [HELD]),
    ("SU14 a summary while held up is answered", MSG,
     '''        Err(_) => return Ok(nothing()),''', '''        Err(_) => {}''', [HELD]),
    ("SU15 a summary without the token answers nothing, not unauthorised", MSG,
     '''        Err(ApiError::Unauthorized) => return Err(ApiError::Unauthorized),''',
     '''        Err(ApiError::Unauthorized) => return Ok(nothing()),''', [ROUTES]),
    ("SU16 the summary's route is not served", LIB,
     '''            .route("/summary", web::post().to(messages::summary))\n''', '''''',
     [ROUTES]),
    ("SU17 the read route is not served", LIB,
     '''            .route("/read", web::post().to(messages::read))\n            .route("/send"''',
     '''            .route("/send"''', [ROUTES]),
    ("SU18 the send route is not served", LIB,
     '''            .route("/send", web::post().to(messages::send)),''',
     '''            .route("/send-not", web::post().to(messages::send)),''', [ROUTES]),
    # ── read (§4.1, §4.3, §7.2) ──
    ("RE1 read needs no token", MSG,
     '''    asked(&req, &state)?;\n    if !is_an_id(&body.id) {''',
     '''    if !is_an_id(&body.id) {''', [ROUTES, HELD]),
    ("RE2 read takes an ID of any form", MSG,
     '''    if !is_an_id(&body.id) {''', '''    if false {''', [BY_WORD]),
    ("RE3 read where the device does not stand applied", MSG,
     '''    if stands(conn)? != Stands::Applied {\n        return Err(NotRead::Refused(Refused::NotApplied));''',
     '''    if false {\n        return Err(NotRead::Refused(Refused::NotApplied));''', [FORK, ORDER]),
    ("RE4 an unmapped folder is refused as no message", MSG,
     '''        return Err(NotRead::Refused(Refused::NotMapped));''',
     '''        return Err(NotRead::Refused(Refused::NoSuchMessage(given.into())));''',
     [ORDER, BY_WORD]),
    ("RE5 read gives no places", MSG,
     '''    kept(held::give_places(conn, &own, now))?;\n    let message = named(''',
     '''    let message = named(''', [READS]),
    ("RE6 read marks nothing", MSG,
     '''let marked = marks::read_here(conn, identity, &name, &id, now, fetched)?;''',
     '''let marked = marks::Marked::default();''', [READS]),
    ("RE7 a person's mark is not counted in the pair", MSG,
     '''        if !kept(held::is_read_by_a_person(conn, &id_of(&other.id)?))? {''',
     '''        if kept(held::is_read_by_a_person(conn, &id_of(&other.id)?))? {''', [READS]),
    ("RE8 a pair is of its order", MSG,
     '''        Some(to) if *to < message.from => (to.clone(), Some(message.from.clone())),\n''',
     '''''', [THREAD]),
    ("RE9 every message is from before the last change", MSG,
     '''before_the_last_change: current != Some(message.generation),''',
     '''before_the_last_change: current == Some(message.generation),''', [READS]),
    ("RE10 the agent's own is any message of this device", MSG,
     '''its_own: signer == own && message.from == name,''', '''its_own: signer == own,''',
     [READS]),
    ("RE11 no message is of this device", MSG,
     '''            this_device: signer == own,''', '''            this_device: false,''',
     [READS]),
    ("RE12 the first of a thread is in no thread", MSG,
     '''            false => hex::encode(&message.id),''',
     '''            false => hex::encode(&message.thread),''', [READS]),
    ("RE13 this device is answered by its label", MSG,
     '''            true => json!("this"),''',
     '''            true => json!({ "label": message.label, "fingerprint": self.fingerprint }),''',
     [READS, SIGNED]),
    # ── send (§3, §4.3) ──
    ("SE1 send needs no token", MSG,
     '''    asked(&req, &state)?;\n    let done = {\n        let db = db_of(&state);\n        let at = SendAt {''',
     '''    let done = {\n        let db = db_of(&state);\n        let at = SendAt {''',
     [ROUTES, HELD]),
    ("SE2 --reply with --to is sent", MSG,
     '''    if request.reply.is_some() && addressed > 1 {''', '''    if false {''', [ORDER]),
    ("SE3 not one of the three is sent", MSG,
     '''    if addressed != 1 {''', '''    if false {''', [ORDER]),
    ("SE4 a reply's ID of any form is taken", MSG,
     '''        && !is_an_id(reply)\n    {''', '''        && false\n    {''', [ORDER]),
    ("SE5 a link of any form is taken", MSG,
     '''        && !is_a_link(link)\n    {\n        return Err(NotSentHere::Said(''',
     '''        && false\n    {\n        return Err(NotSentHere::Said(''', [ORDER]),
    ("SE6 a body of 1,025 bytes is not too large at the node", MSG,
     '''    if request.body.len() > AGENT_MESSAGE_BODY_MAX_BYTES {''',
     '''    if request.body.len() > AGENT_MESSAGE_BODY_MAX_BYTES + 1 {''', [ORDER]),
    ("SE7 an empty body is not refused as empty", MSG,
     '''    if request.body.is_empty() {''', '''    if false {''', [ORDER]),
    ("SE8 every folder is mapped", MSG,
     '''        mapped: name.is_some(),''', '''        mapped: true,''', [ORDER]),
    ("SE9 the configuration's limit is not given to the sender", MSG,
     '''        per_folder_per_hour: at.per_folder_per_hour,''', '''        per_folder_per_hour: 20,''',
     [BY_WORD]),
    ("SE10 a reply is said to go where the request named", MSG,
     '''    let to = replied_to.into_inner().unwrap_or(to);''',
     '''    let to = replied_to.into_inner().map(|_| to.clone()).unwrap_or(to);''', [THREAD]),
    ("SE11 send names who fills a channel no relay refused", MSG,
     '''    if !no_room(&channel) {''', '''    if false {''', [ROOM]),
    ("SE12 the node is not told that a relay refused messages for room", ENGINE,
     '''                        .say_no_room_for_messages(&channel.id);''',
     '''                        .say_no_room_for_messages(&[0; 32]);''', [FOR_ROOM]),
    ("SE13 a refusal for room is not kept", STATE,
     '''.unwrap_or_else(|e| e.into_inner()) = Some(*channel);''',
     '''.unwrap_or_else(|e| e.into_inner()) = None;''', [FOR_ROOM]),
    # ── The refusals' words and what is beside them (§4.3) ──
    ("WO1 no_such_message's word", SENDER,
     '''Self::NoSuchMessage(_) => "no_such_message",''', '''Self::NoSuchMessage(_) => "no_message",''',
     [DETAILS]),
    ("WO2 more_than_one's word", SENDER,
     '''Self::MoreThanOne { .. } => "more_than_one",''', '''Self::MoreThanOne { .. } => "more",''',
     [DETAILS, ORDER]),
    ("WO3 signer_removed's word", SENDER,
     '''Self::SignerRemoved(_) => "signer_removed",''', '''Self::SignerRemoved(_) => "removed",''',
     [DETAILS, ORDER]),
    ("WO4 asks_nothing's word", SENDER,
     '''Self::AsksNothing(_) => "asks_nothing",''', '''Self::AsksNothing(_) => "asks",''',
     [DETAILS, ORDER]),
    ("WO5 no_such_name names no name", MSG,
     '''Refused::NoSuchName(name) => json!({ "name": name }),''',
     '''Refused::NoSuchName(_) => json!({}),''', [DETAILS, BY_WORD]),
    ("WO6 folder_rate names no limit", MSG,
     '''json!({ "limit": limit, "next_at": next_at }),''', '''json!({ "next_at": next_at }),''',
     [DETAILS, BY_WORD]),
    ("WO7 device_rate says no sends again", MSG,
     '''json!({ "sends": sends, "again": again, "next_at": next_at }),''',
     '''json!({ "sends": sends + again, "again": 0, "next_at": next_at }),''',
     [DETAILS]),
    ("WO8 pair_held names no other", MSG,
     '''json!({ "from": from, "other": other, "every": every })''',
     '''json!({ "from": from, "other": null, "every": every })''',
     [DETAILS]),
    ("WO9 the ID a refusal names is not beside it", MSG,
     '''            json!({ "id": id })''', '''            json!({ "id": "" })''', [DETAILS]),
    ("WO10 the IDs that begin alike are not beside more_than_one", MSG,
     '''Refused::MoreThanOne { id, ids } => json!({ "id": id, "ids": ids }),''',
     '''Refused::MoreThanOne { id, .. } => json!({ "id": id, "ids": [] }),''', [DETAILS]),
    ("WO11 not_applied says no why", MSG,
     '''Refused::NotApplied => json!({ "why": why_not_applied(conn).map_err(refused)? }),''',
     '''Refused::NotApplied => json!({ "why": "" }),''', [DETAILS, BY_WORD]),
    ("WO12 a device of no phrase says another why", MSG,
     '''Stands::NoPhrase => "this device follows no recovery phrase yet",''',
     '''Stands::NoPhrase => "this device was removed",''', [DETAILS, NO_PHRASE]),
    ("WO13 a removed device says another why", LOOK,
     '''        State::Removed => "this device was removed",\n        State::NotListed''',
     '''        State::Removed => "this device was stopped",\n        State::NotListed''',
     [BY_WORD]),
    # ── The command: the summary (§4.1) ──
    ("CS1 summary is not read before the command line is parsed", MAIN,
     '''if let Some((config, others)) = msg_cmd::summary_asked(&args) {''',
     '''if let Some((config, others)) = msg_cmd::summary_asked(&args).filter(|_| false) {''',
     [ERRORS]),
    ("CS2 --help of summary is not the parser's", CMD,
     '''            Some("-h" | "--help") => return None,\n''', '''''', [RECOGNISED]),
    ("CS3 an argument summary does not take is not said", CMD,
     '''    Some((config, words.len() > 2))''', '''    Some((config, false))''', [RECOGNISED, ERRORS]),
    ("CS4 summary with an argument it does not take prints", CMD,
     '''    if others {\n        return;\n    }''', '''''', [ERRORS]),
    ("CS5 the summary's time is five times its own", CMD,
     '''let deadline = started + Duration::from_millis(AGENT_MESSAGE_SUMMARY_WAIT_MS);''',
     '''let deadline = started + Duration::from_millis(AGENT_MESSAGE_SUMMARY_WAIT_MS * 5);''',
     [IN_TIME]),
    ("CS6 nothing to say is still a header", CMD,
     '''    if lines.is_empty() && count == 0 {\n        return None;\n    }''', '''''', [WORDS]),
    ("CS7 the count says how many more of all", CMD,
     '''let more = count.saturating_sub(ids.len() as u64);''', '''let more = count;''', [WORDS]),
    ("CS8 the count says and 0 more", CMD,
     '''            0 => String::new(),''', '''            0 => ", and 0 more".into(),''', [WORDS]),
    ("CS9 the header says another thing", CMD,
     '''messages for this agent ({name}) from your user's''',
     '''messages for this agent ({name}) from the user's''',
     [WORDS]),
    ("CS10 a name is not cleaned", CMD,
     '''cut(&cleaned(name), AGENT_MESSAGE_AGENT_NAME_CHARS)''',
     '''cut(name, AGENT_MESSAGE_AGENT_NAME_CHARS)''', [CATEGORIES]),
    ("CS11 a name cut is not marked", CMD,
     '''    match was_cut {\n        true => format!("{shown}..."),''',
     '''    match was_cut {\n        true => shown,''', [CUT_48]),
    ("CS12 a name is cut at 49", CMD,
     '''cut(&cleaned(name), AGENT_MESSAGE_AGENT_NAME_CHARS)''',
     '''cut(&cleaned(name), AGENT_MESSAGE_AGENT_NAME_CHARS + 1)''', [CUT_48]),
    ("CS13 a subject the node cut is not marked", CMD,
     '''    match was_cut || cut_here {''', '''    match cut_here {''', [CUT_48]),
    ("CS14 a subject of nothing is nothing", CMD,
     '''        return "(no subject)".into();''', '''        return String::new();''', [WORDS]),
    ("CS15 a label's backslash is not escaped", CMD,
     '''        if matches!(c, '"' | '\\\\') {''', '''        if c == '"' {''', [QUOTE]),
    ("CS16 a label's quote is not escaped", CMD,
     '''        if matches!(c, '"' | '\\\\') {''', '''        if c == '\\\\' {''', [QUOTE]),
    ("CS17 a label is not cleaned", CMD,
     '''    for c in cleaned(label).chars() {''', '''    for c in label.chars() {''', [CATEGORIES]),
    # ── The command: read (§4.1) ──
    ("CR1 a tab in a body is escaped", CMD,
     '''|c| match (taken_out(c) && !matches!(c, '\\n' | '\\t')) || c == '\\\\' {''',
     '''|c| match (taken_out(c) && c != '\\n') || c == '\\\\' {''', [CATEGORIES]),
    ("CR2 a body's escapes are of controls alone", CMD,
     '''|c| match (taken_out(c) && !matches!(c, '\\n' | '\\t')) || c == '\\\\' {''',
     '''|c| match (c.is_control() && !matches!(c, '\\n' | '\\t')) || c == '\\\\' {''', [CATEGORIES]),
    ("CR3 a frame's value is of four bytes", CMD,
     '''as_bytes()[..AGENT_MESSAGE_MARKER_BYTES])''', '''as_bytes()[..4])''', [TWO_VALUES]),
    ("CR4 a frame's value is the same each time", CMD,
     '''hex::encode(&uuid::Uuid::new_v4().as_bytes()''', '''hex::encode(&uuid::Uuid::nil().as_bytes()''',
     [TWO_VALUES]),
    ("CR5 the start line says another thing", CMD,
     '''{on_device}. It is NOT from \\''', '''{on_device}. It is not from \\''', [WORDS]),
    ("CR6 the end line says another thing of memory", CMD,
     '''from another agent, not a fact.";''', '''from another agent.";''', [WORDS]),
    ("CR7 the link is not printed", CMD,
     '''    if let Some(link) = answer["link"].as_str() {''',
     '''    if let Some(link) = answer["link"].as_str().filter(|_| false) {''', [LINK]),
    ("CR8 the agent's own is told how to answer", CMD,
     '''    if answer["its_own"] != true {''', '''    if true {''', [WORDS]),
    ("CR9 a message from before the change is not said so", CMD,
     '''    if answer["before_the_last_change"] == true {''', '''    if false {''', [WORDS]),
    ("CR10 a refusal for a device not applied says sends for read", CMD,
     '''        Does::Send => "sends no message",''', '''        Does::Send => "shows no message",''',
     [WORDS]),
    # ── The command: send (§4.1, §4.3) ──
    ("CN1 --reply with --to is not the first refusal", CMD,
     '''    if flags.reply.is_some() && given > 1 {''', '''    if false {''', [CMD_ORDER]),
    ("CN2 not one of three is sent", CMD,
     '''    if given != 1 {''', '''    if false {''', [CMD_ORDER]),
    ("CN3 a reply's ID is not checked", CMD,
     '''        && !is_an_id(reply)\n    {''', '''        && false\n    {''', [CMD_ORDER]),
    ("CN4 a link is not checked", CMD,
     '''        && !is_a_link(link)\n    {''', '''        && false\n    {''', [CMD_ORDER]),
    ("CN5 the 1,025th byte is not too large", CMD,
     '''                if came.len() > most {''', '''                if came.len() > most + 1 {''',
     [CMD_ORDER, INPUT]),
    ("CN6 an empty body is not refused", CMD,
     '''    if came.is_empty() {''', '''    if false {''', [CMD_ORDER]),
    ("CN7 an input that does not end is given half the time", CMD,
     '''body_from(stdin, terminal, Duration::from_secs(STREAM_TIMEOUT_SECS))''',
     '''body_from(stdin, terminal, Duration::from_secs(STREAM_TIMEOUT_SECS / 2))''', [INPUT]),
    ("CN8 a relay's refusal for room is not said", CMD,
     '''    if let Some(filled) = answer["filled_by"].as_object() {''',
     '''    if let Some(filled) = answer["filled_by"].as_object().filter(|_| false) {''',
     [WORDS, FOR_ROOM]),
    ("CN9 a node that does not answer is not said so", CMD,
     '''        if !reached {''', '''        if false {''', [CMD_ORDER]),
    ("CN10 a node of another version is asked", CMD,
     '''        if let Some(note) = version_note(node["version"].as_str(), env!("CARGO_PKG_VERSION")) {''',
     '''        if let Some(note) = version_note(node["version"].as_str(), env!("CARGO_PKG_VERSION")).filter(|_| false) {''',
     [CMD_ORDER]),
    ("CN11 a node that is held up is asked", CMD,
     '''            None | Some(Value::Null) => Ok(()),''', '''            _ => Ok(()),''', [CMD_ORDER]),
    ("CN12 the summary's help holds no hook", MAIN,
     '''    #[command(after_long_help = msg_cmd::SUMMARY_HELP)]\n''', '''''', [HELP]),

    # ── The review's fixes ──
    ("SU19 the summary prints with print!, which panics on a closed output", CMD,
     '''        written(&said);''', '''        print!("{said}");''', [ERRORS]),
    ("AD1 the node's address is written with ::1 bare", CMD,
     '''    let host = api_host(&config.api.bind_address)?;''',
     '''    let host = config.api.bind_address.as_str();''',
     [ADDRESS]),
    ("GT1 read and send give git no deadline", CMD,
     '''let folder = cordelia_api::found::memory_root_by(&real, Instant::now() + git_wait)?;''',
     '''let folder = Some(cordelia_api::found::memory_root(&real)).filter(|_| !git_wait.is_zero())?;''',
     [GIT_HANGS]),
    ("GT2 read and send fall back to the directory where git does not answer", CMD,
     '''let folder = cordelia_api::found::memory_root_by(&real, Instant::now() + git_wait)?;''',
     '''let folder = cordelia_api::found::memory_root_by(&real, Instant::now() + git_wait)
        .unwrap_or_else(|| real.clone());''',
     [GIT_HANGS]),
    ("IG1 U+034F is not taken out", MSG,
     '''    ('\\u{034f}', '\\u{034f}'),''', '''    ('\\u{034f}', '\\u{034e}'),''', [SEVEN, CATEGORIES]),
    ("IG2 the Hangul fillers U+115F and U+1160 are not taken out", MSG,
     '''    ('\\u{115f}', '\\u{1160}'),''', '''    ('\\u{115f}', '\\u{115e}'),''', [SEVEN, CATEGORIES]),
    ("IG3 U+17B4 and U+17B5 are not taken out", MSG,
     '''    ('\\u{17b4}', '\\u{17b5}'),''', '''    ('\\u{17b4}', '\\u{17b3}'),''', [SEVEN, CATEGORIES]),
    ("IG4 the Mongolian variation selectors are not taken out", MSG,
     '''    ('\\u{180b}', '\\u{180f}'),''', '''    ('\\u{180b}', '\\u{180a}'),''', [SEVEN, CATEGORIES]),
    ("IG5 the Hangul filler U+3164 is not taken out", MSG,
     '''    ('\\u{3164}', '\\u{3164}'),''', '''    ('\\u{3164}', '\\u{3163}'),''', [SEVEN, CATEGORIES]),
    ("IG6 the variation selectors U+FE00 to U+FE0F are not taken out", MSG,
     '''    ('\\u{fe00}', '\\u{fe0f}'),''', '''    ('\\u{fe00}', '\\u{fdff}'),''', [SEVEN, CATEGORIES]),
    ("IG7 the halfwidth Hangul filler U+FFA0 is not taken out", MSG,
     '''    ('\\u{ffa0}', '\\u{ffa0}'),''', '''    ('\\u{ffa0}', '\\u{ff9f}'),''', [SEVEN, CATEGORIES]),
    ("IG8 the range U+E0000 to U+E0FFF is not in the table", MSG,
     '''    ('\\u{e0000}', '\\u{e0fff}'),''', '''    ('\\u{e0000}', '\\u{dffff}'),''', [SEVEN, CATEGORIES]),
    ("IG9 the braille blank U+2800 is not taken out", MSG,
     '''        || c == BRAILLE_BLANK
''', '''''', [SEVEN, CATEGORIES]),
    ("BS1 a backslash in a body is not escaped", CMD,
     '''|c| match (taken_out(c) && !matches!(c, '\\n' | '\\t')) || c == '\\\\' {''',
     '''|c| match taken_out(c) && !matches!(c, '\\n' | '\\t') {''', [BACKSLASH]),
    ("LT1 a request not answered in time is said to be a node not running", CMD,
     '''            Err(_) => return Posted::NotKnown,''',
     '''            Err(ureq::Error::Timeout(_)) => return Posted::NotReached,
            Err(_) => return Posted::NotKnown,''',
     [NOT_IN_TIME, LATE]),
    ("LB1 the label that fills the channel is printed without its quotes", CMD,
     '''            label_shown(filled["label"].as_str().unwrap_or_default()),''',
     '''            cleaned(filled["label"].as_str().unwrap_or_default()),''', [WORDS, FILLED]),
    ("DB1 the summary's wait for the store holds the worker", MSG,
     '''                actix_web::rt::time::sleep(Duration::from_millis(1)).await;''',
     '''                std::thread::sleep(Duration::from_millis(1));''', [SERVED]),

    # ── The second fixes ──
    ("NK1 a connection closed after the request is said to be a node not running", CMD,
     '''        ureq::Error::Io(e) => matches!(
            e.kind(),''',
     '''        ureq::Error::Io(e) => !e.kind().to_string().is_empty() || matches!(
            e.kind(),''', [NOT_IN_TIME]),
    ("NK2 an answer of 200 cut short is taken as an answer", CMD,
     '''            (200, Err(_)) => Posted::NotKnown,''',
     '''            (200, Err(_)) => Posted::Answered(200, Value::Null),''', [NOT_IN_TIME]),
    ("NK3 an answer of 200 that is not the route's is taken as the route's", CMD,
     '''        Posted::Answered(200, answer) if !answer["id"].is_string() => Posted::NotKnown,''',
     '''        Posted::Answered(200, answer) if answer.is_string() => Posted::NotKnown,''',
     [NOT_IN_TIME]),
    ("NK4 a refused connection is not known, not a node not running", CMD,
     '''            ErrorKind::ConnectionRefused''', '''            ErrorKind::ConnectionReset''',
     [NOT_IN_TIME]),
    ("PR1 send prints with print!, which panics on a closed output", CMD,
     '''    written(&sent_says(&answer));''', '''    print!("{}", sent_says(&answer));''',
     [CLOSED]),
    ("PR2 read prints with print!, which panics on a closed output", CMD,
     '''    written(&readout_says(&answer, &marker()));''',
     '''    print!("{}", readout_says(&answer, &marker()));''', [CLOSED]),
    ("CW1 a git_wait_ms of 0 is taken", CONFIG,
     '''                "git_wait_ms",
                self.git_wait_ms,''',
     '''                "git_wait_ms",
                self.git_wait_ms.filter(|wait| *wait != 0),''', [LIMIT]),
    ("CW2 a git_wait_ms over STREAM_TIMEOUT_SECS is taken", CONFIG,
     '''                protocol::STREAM_TIMEOUT_SECS * 1000,''',
     '''                protocol::STREAM_TIMEOUT_SECS * 1000 + 1,''', [LIMIT]),
    ("CW3 an answer_wait_ms of 0 is taken", CONFIG,
     '''                "answer_wait_ms",
                self.answer_wait_ms,''',
     '''                "answer_wait_ms",
                self.answer_wait_ms.filter(|wait| *wait != 0),''', [LIMIT]),
    ("CW4 an answer_wait_ms over the default wait is taken", CONFIG,
     '''                MESSAGES_ANSWER_WAIT_MAX_MS,
            ),''',
     '''                MESSAGES_ANSWER_WAIT_MAX_MS + 1,
            ),''', [LIMIT]),
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
