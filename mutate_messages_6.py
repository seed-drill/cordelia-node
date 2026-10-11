#!/usr/bin/env python3
"""Mutation checks for marks and lists of messages between a person's own
agents: whether a message was read by an agent, on every device of the
person. A device's own table of marks and its list in the slot
read/<its key>, written from the table, the newest 120 first, never
before the first fetch, one revision above the list it holds or above a
relay's answer of another; its own later list merged into the table
below the marks made since it last wrote its list and above the rest;
the latest list of each other device kept only where
the store keeps it; whether a message is read worked out when it is shown,
from keys that count; and the marks' part of the hourly task (decision
2026-10-09 §2.4, §7.2, §9.1, §11). A part for each rule of the slice: put
each fault in, and confirm the test named for it fails on an assertion.
Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
MESSAGES = 'crates/cordelia-storage/src/messages.rs'
MARKS = 'crates/cordelia-api/src/marks.rs'
READER = 'crates/cordelia-api/src/reader.rs'
ENGINE = 'crates/cordelia-node/src/device_entries.rs'
ORIG = {f: open(f).read() for f in (MESSAGES, MARKS, READER, ENGINE)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
STORAGE = ("cordelia-storage", ["--lib"])
API = ("cordelia-api", ["--lib"])
E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
def stored(test): return (STORAGE, "messages::tests::" + test)
def marks(test): return (API, "marks::tests::" + test)
def e2e(test): return (E2E, test)

# The storage's tests.
OF_A_NAME = stored("a_mark_is_of_a_message_and_a_name")
NEWEST_120 = stored(
    "a_list_holds_the_newest_120_and_only_the_latest_list_of_each_device_is_kept")
MERGED = stored("a_device_merges_its_own_list_as_older_than_any_mark_it_holds")
BARE = stored("a_bare_hash_is_kept_at_most_120_and_30_days_where_no_message_is_found")
# The device's tests, in process.
FOR_IT = marks("a_mark_is_made_only_for_a_message_to_the_folders_agent")
BEFORE_MESSAGE = marks("a_list_that_arrives_before_the_message_it_marks_loses_nothing")
KEPT_ONLY = marks("a_list_is_kept_only_where_the_store_keeps_it")
NO_LIST_BEFORE = marks("a_device_writes_no_list_before_its_first_fetch")
MERGES = marks("a_device_merges_its_own_list_from_a_relay_before_it_writes_the_next")
RESTORED = marks(
    "a_restored_store_that_reads_before_its_first_fetch_writes_no_list_until_it_has_fetched")
BAND = marks("no_list_is_written_above_the_bottom_half_of_band_0")
ANOTHER = marks("a_list_answered_another_is_written_again_above_it")
STATEMENT = marks("the_first_list_after_a_statement_holds_the_marks_of_what_is_still_shown")
MARK_GOES = marks("a_mark_stays_as_a_bare_hash_when_its_message_goes")
MORE = marks("more_reads_than_a_list_holds_leave_the_oldest_unread_on_another_device")
LIES = marks("a_device_that_lies_in_its_list_hides_from_summaries_and_not_from_log")
FALSELY = marks("a_relay_that_answers_falsely_makes_a_list_go_under_at_most_four_revisions")
OUTLASTS = marks("a_mark_outlasts_its_messages_row_on_the_device_that_made_it")
NOT_PLACED = marks("a_merged_mark_of_a_message_held_and_not_yet_placed_is_in_the_next_list")
OTHER_KEY = marks("an_answer_of_another_to_another_keys_entry_in_the_lists_slot_writes_no_list")
# The storage's tests of a mark whose message's row goes.
EACH_WAY = stored("a_mark_whose_messages_row_goes_stays_as_a_bare_hash_for_each_reason")
LEFT_BARE = stored("a_mark_left_bare_is_kept_at_most_120_and_30_days_after_it_became_bare")
DROPPED = stored("a_dropped_row_leaves_its_marks_as_bare_hashes_and_its_first_holding")
# The hourly task.
MARKS_FAIL = (API, "reader::tests::an_hourly_task_whose_marks_part_fails_still_drops_and_runs_the_checkpoint")
DROP_FAIL = (API, "reader::tests::an_hourly_task_whose_drop_fails_still_keeps_the_marks_and_runs_the_checkpoint")
# Where a merged list's marks go.
WENT_BARE = stored("a_merged_mark_goes_above_the_marks_the_store_held_though_they_went_bare")
SAID_130 = stored("a_later_list_merged_into_a_store_that_said_its_marks_is_listed_above_them")
SINCE = stored("the_marks_made_since_the_last_list_stay_above_a_later_list_merged")
AFTER_LIST = stored("a_mark_made_after_a_list_is_above_it_though_the_marks_listed_went")
OUT_OF_BOUNDS = stored("a_kept_listed_seq_out_of_bounds_counts_as_not_kept")
SEQ_END = stored("a_seq_at_an_integers_end_fails_a_mark_and_a_merge_without_a_panic")
SAID_MORE = marks("a_restored_store_that_said_more_than_a_list_holds_lists_its_later_marks_first")
# Over a relay.
REACHES = e2e("a_mark_made_on_one_device_reaches_the_other_through_a_relay")
NOT_UNREAD = e2e("a_message_read_on_one_device_is_not_counted_unread_on_the_other")
RESTORE_E2E = e2e("a_restored_device_merges_its_later_list_from_a_relay_and_writes_above_it")
STATEMENT_E2E = e2e("the_first_list_after_a_statement_is_written_by_the_pass_in_the_new_channel")
ANOTHER_E2E = e2e("a_list_that_a_relay_holds_another_of_is_written_again_above_it")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # The device's own table (§7.2).
    ("K01 a mark read here is the oldest, not the newest", MESSAGES,
     "VALUES (?1, ?5, ?2, ?3, ?4)",
     "VALUES (?1, (SELECT COALESCE(MIN(seq), 0) - 1 + 0 * ?5 FROM message_read_here), ?2, ?3, ?4)",
     [OF_A_NAME, NEWEST_120]),
    ("K02 a mark read again is not made the newest", MESSAGES,
     "             seq = excluded.seq, id = excluded.id, name = excluded.name,",
     "             id = excluded.id, name = excluded.name,",
     [OF_A_NAME]),
    ("K03 a bare hash read here is not given its ID and name", MESSAGES,
     "             seq = excluded.seq, id = excluded.id, name = excluded.name,\n"
     "             made_at = excluded.made_at, merged_at = NULL\",",
     "             seq = excluded.seq,\n"
     "             made_at = excluded.made_at\",",
     [MERGED]),
    ("K04 a mark read again says the table lacked it", MESSAGES,
     "    Ok(held == 0)\n}", "    Ok(true)\n}",
     [OF_A_NAME]),
    # The list's marks (§2.4).
    ("K05 a list holds 121 marks", MESSAGES,
     "             LIMIT {AGENT_MESSAGE_READ_MARKS_MAX}\"\n        ))?",
     "             LIMIT {AGENT_MESSAGE_READ_MARKS_MAX} + 1\"\n        ))?",
     [NEWEST_120, MORE]),
    ("K06 a list holds the oldest first", MESSAGES,
     "             ORDER BY r.seq DESC\n             LIMIT",
     "             ORDER BY r.seq\n             LIMIT",
     [NEWEST_120, MERGES]),
    ("K07 a list leaves out the bare hashes", MESSAGES,
     "\"SELECT r.mark FROM message_read_here r\n             ORDER BY r.seq DESC",
     "\"SELECT r.mark FROM message_read_here r WHERE r.id IS NOT NULL\n             ORDER BY r.seq DESC",
     [NEWEST_120, EACH_WAY, LEFT_BARE, OUTLASTS, MARK_GOES]),
    # K08 to K10, a list that leaves out the mark of a message with no
    # place, expired or held at no live number, were dropped with the rule:
    # a list holds the newest 120 of the table whatever became of their
    # messages, since whether one is shown is each device's own.
    ("K28 a list leaves out the mark of a message this device does not show", MESSAGES,
     "\"SELECT r.mark FROM message_read_here r\n             ORDER BY r.seq DESC",
     "\"SELECT r.mark FROM message_read_here r\n             LEFT JOIN message_index i ON i.id = r.id\n"
     "             WHERE r.id IS NULL OR i.placed_at IS NOT NULL\n             ORDER BY r.seq DESC",
     [NEWEST_120, NOT_PLACED]),
    # The device's own list merged (§7.2, D7, F8).
    ("K11 a mark of the own list is not found by the name its message is to", MESSAGES,
     "        for name in names.iter().chain(to.as_ref()) {",
     "        for name in names.iter() {",
     [MERGES]),
    ("K12 a mark of the own list is not found by a name mapped here", MESSAGES,
     "    let held = marks_held(conn, names)?;\n    let mut lacked",
     "    let held = marks_held(conn, &[])?;\n    let mut lacked",
     [MERGED, MERGES]),
    ("K13 where the store never wrote a list, the own list is merged as newer than any mark held", MESSAGES,
     "\"SELECT MIN(seq) FROM message_read_here\"",
     "\"SELECT MAX(seq) + 200 FROM message_read_here\"",
     [MERGED, BARE]),
    ("K14 the own list is merged in the reverse of its order", MESSAGES,
     "    let mut merged = 0;\n    for mark in lacked {",
     "    let mut merged = 0;\n    for mark in lacked.into_iter().rev() {",
     [MERGED, MERGES]),
    ("K15 a mark held is merged again over itself", MESSAGES,
     ["        if here == 0 && !lacked.contains(&mark) {",
      "                \"INSERT OR IGNORE INTO message_read_here (mark, seq, id, name, made_at, merged_at)"],
     ["        if !lacked.contains(&mark) {",
      "                \"INSERT OR REPLACE INTO message_read_here (mark, seq, id, name, made_at, merged_at)"],
     [MERGED]),
    ("K16 a mark not merged is counted as merged", MESSAGES,
     "    keep_120_bare(conn)?;\n    Ok(merged)\n}",
     "    keep_120_bare(conn)?;\n    Ok(marks.len())\n}",
     [MERGED]),
    ("K17 121 bare hashes are kept", MESSAGES,
     "            AGENT_MESSAGE_READ_MARKS_MAX - 1\n",
     "            AGENT_MESSAGE_READ_MARKS_MAX\n",
     [BARE]),
    ("K18 the bound on bare hashes takes marks with an ID too", MESSAGES,
     "            \"DELETE FROM message_read_here WHERE id IS NULL AND seq <",
     "            \"DELETE FROM message_read_here WHERE seq <",
     [BARE]),
    ("K19 the newest bare hashes go first at the bound", MESSAGES,
     "                  ORDER BY seq DESC LIMIT 1 OFFSET {})\",",
     "                  ORDER BY seq LIMIT 1 OFFSET {})\",",
     [BARE]),
    # The marks' part of the hourly task (§7.2).
    ("K20 a bare hash whose message is held is not given its ID", MESSAGES,
     "\"UPDATE message_read_here SET id = ?2, name = ?3 WHERE mark = ?1\",",
     "\"UPDATE message_read_here SET id = ?2, name = ?3 WHERE mark = ?1 AND 0\",",
     [BARE]),
    ("K21 a bare hash goes a moment after its 30 days", MESSAGES,
     "\"DELETE FROM message_read_here WHERE id IS NULL AND merged_at <= ?1\",",
     "\"DELETE FROM message_read_here WHERE id IS NULL AND merged_at < ?1\",",
     [BARE]),
    ("K22 a bare hash is kept 31 days", MESSAGES,
     "        [now - i64::from(AGENT_MESSAGE_KEPT_DAYS) * DAY_SECS],\n    )?)",
     "        [now - (i64::from(AGENT_MESSAGE_KEPT_DAYS) + 1) * DAY_SECS],\n    )?)",
     [BARE, MARK_GOES]),
    # The latest list of each other device (§7.2).
    ("K23 a list is kept beside the one before", MESSAGES,
     "    conn.execute(\"DELETE FROM message_lists WHERE key = ?1\", [&key[..]])?;\n",
     "",
     [NEWEST_120, KEPT_ONLY]),
    ("K24 a list's repeats are stored again", MESSAGES,
     "\"INSERT OR IGNORE INTO message_lists (key, mark) VALUES (?1, ?2)\",",
     "\"INSERT INTO message_lists (key, mark) VALUES (?1, ?2)\",",
     [NEWEST_120, KEPT_ONLY]),
    ("K25 the lists of the keys that count go", MESSAGES,
     "        if !counting.iter().any(|counts| counts[..] == key[..]) {",
     "        if counting.iter().any(|counts| counts[..] == key[..]) {",
     [NEWEST_120, LIES]),
    # Whether a message is read (§7.2).
    ("K26 the own table says nothing of what is read", MESSAGES,
     "        here: here > 0,", "        here: here > 1,",
     [OF_A_NAME, FOR_IT]),
    ("K27 a list says every other mark is read", MESSAGES,
     "\"SELECT key FROM message_lists WHERE mark = ?1 ORDER BY key\"",
     "\"SELECT key FROM message_lists WHERE mark <> ?1 ORDER BY key\"",
     [OF_A_NAME, BEFORE_MESSAGE]),
    ("A01 an agent marks a message to another name", MARKS,
     "        if !is_for(message, &own, name) {\n            return Ok(Marked::default());",
     "        if false {\n            return Ok(Marked::default());",
     [FOR_IT]),
    ("A02 a message to another name is for the agent", MARKS,
     "    let to_it = message.to.as_deref().is_none_or(|to| to == name);",
     "    let to_it = true;",
     [FOR_IT, KEPT_ONLY]),
    ("A03 a message from this device's agent of that name is its own", MARKS,
     "    let its_own = message.signer[..] == own[..] && message.from == name;",
     "    let its_own = message.from == name;",
     [FOR_IT]),
    ("A04 a message from another agent of this device is its own", MARKS,
     "    let its_own = message.signer[..] == own[..] && message.from == name;",
     "    let its_own = message.signer[..] == own[..];",
     [FOR_IT]),
    ("A05 a read writes no list", MARKS,
     "            list: list_written(conn, identity, now, fetched, None)?,",
     "            list: None,",
     [MERGES, REACHES]),
    ("A06 a list is written before the first fetch", MARKS,
     "    if !fetched\n        || stands(conn)? != Stands::Applied",
     "    if false\n        || stands(conn)? != Stands::Applied",
     [NO_LIST_BEFORE, RESTORED, ANOTHER, STATEMENT]),
    ("A07 a list is written where the device does not stand applied", MARKS,
     "    if !fetched\n        || stands(conn)? != Stands::Applied\n",
     "    if !fetched\n",
     [LIES]),
    ("A08 a list is written with sync off", MARKS,
     "    if !fetched\n        || stands(conn)? != Stands::Applied\n"
     "        || meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_none()\n",
     "    if !fetched\n        || stands(conn)? != Stands::Applied\n",
     [NO_LIST_BEFORE]),
    ("A09 a list is written where nothing new is marked", MARKS,
     "        None => marks.iter().any(|mark| !listed.contains(mark)),",
     "        None => !marks.is_empty(),",
     [NO_LIST_BEFORE]),
    ("A10 a list is written again for an answer about an older list", MARKS,
     "        Some(answered) => rev == answered && again + 1 < AGENT_MESSAGE_SENDS_MAX,",
     "        Some(answered) => rev >= answered && again + 1 < AGENT_MESSAGE_SENDS_MAX,",
     [ANOTHER]),
    ("A11 the next list goes two above", MARKS,
     "    let next = rev + 1;",
     "    let next = rev + 2;",
     [NO_LIST_BEFORE, MERGES, ANOTHER]),
    ("A12 a list is written at the bottom of band 0's top half", MARKS,
     "    if !due || next >= REV_BAND_HALF {",
     "    if !due || next > REV_BAND_HALF {",
     [BAND]),
    ("A13 a list goes above nothing it holds", MARKS,
     "    let (rev, listed) = held.list.unwrap_or((0, Vec::new()));",
     "    let (rev, listed) = (0, held.list.map(|list| list.1).unwrap_or_default());",
     [MERGES]),
    ("A14 an answer of another in any channel writes the list", MARKS,
     "    if channel.kind != Kind::Messages || entries.len() != answers.len() {",
     "    if entries.len() != answers.len() {",
     [ANOTHER]),
    ("A15 answers that are not one for each entry are read", MARKS,
     "    if channel.kind != Kind::Messages || entries.len() != answers.len() {",
     "    if channel.kind != Kind::Messages {",
     [ANOTHER]),
    ("A16 an answer is read where the device does not stand applied", MARKS,
     "    in_one(conn, || {\n        if stands(conn)? != Stands::Applied {\n            return Ok(None);\n        }\n",
     "    in_one(conn, || {\n",
     [LIES]),
    ("A17 an answer that the relay holds a later list writes it again", MARKS,
     "            **answer == Pushed::HoldsAnother && entry.author == own",
     "            **answer != Pushed::Holds && entry.author == own",
     [ANOTHER, ANOTHER_E2E]),
    ("A18 an answer of another to a message writes the list", MARKS,
     " && entry.author == own && entry.slot == held.slot",
     " && entry.author == own",
     [ANOTHER]),
    ("A19 the device's own list is kept as another device's", MARKS,
     "    if signer != own {\n        return kept(held::keep_list",
     "    if true {\n        return kept(held::keep_list",
     [MERGES, RESTORED, RESTORE_E2E]),
    ("A20 another device's list is merged as the device's own", MARKS,
     "    if signer != own {\n        return kept(held::keep_list",
     "    if false {\n        return kept(held::keep_list",
     [BEFORE_MESSAGE, KEPT_ONLY, NOT_UNREAD]),
    ("A21 the names mapped here are not used to find a mark", MARKS,
     "    kept(held::merge_own_list(conn, marks, &mapped(conn)?, now)).map(|_| ())",
     "    kept(held::merge_own_list(conn, marks, &[], now)).map(|_| ())",
     [MERGES]),
    ("A22 the hourly task keeps the lists of keys that no longer count", MARKS,
     "        kept(held::drop_lists_but(conn, &counting.keys()))?;\n",
     "",
     [LIES]),
    ("A23 the hourly task keeps the bare hashes", MARKS,
     "    kept(held::keep_bare_marks(conn, &mapped(conn)?, now)).map(|_| ())",
     "    Ok(())",
     [MARK_GOES]),
    ("A24 a list from a key that no longer counts says it was read", MARKS,
     "            .filter(|key| counting.as_ref().is_some_and(|c| c.counts(key)))",
     "            .filter(|_| true)",
     [LIES]),
    ("A25 another device's list says nothing of what is read", MARKS,
     "        self.here || !self.devices.is_empty()",
     "        self.here",
     [BEFORE_MESSAGE, STATEMENT, MORE, LIES, NOT_UNREAD]),
    ("A26 a message to another name is unread", MARKS,
     "        if !is_for(&message, &own, name) {\n            continue;",
     "        if false {\n            continue;",
     [KEPT_ONLY]),
    ("A27 a message read is unread", MARKS,
     "        if !read_on(conn, &id, name)?.is_read() {",
     "        if true {",
     [BEFORE_MESSAGE, KEPT_ONLY, LIES]),
    # A relay that answers falsely (§2.4).
    ("A28 a list's marks go under five revisions", MARKS,
     "rev == answered && again + 1 < AGENT_MESSAGE_SENDS_MAX,",
     "rev == answered && again < AGENT_MESSAGE_SENDS_MAX,",
     [FALSELY]),
    ("A29 a list written for a new mark does not start the count again", MARKS,
     "        Some(_) => again + 1,\n        None => 0,",
     "        Some(_) => again + 1,\n        None => again,",
     [FALSELY]),
    ("A30 a list written again is not counted", MARKS,
     "        Some(_) => again + 1,\n        None => 0,",
     "        Some(_) => again,\n        None => 0,",
     [FALSELY]),
    # A mark outlasts its message's row (§7.1, §7.2).
    ("K29 a mark goes with its message's row", MESSAGES,
     "\"UPDATE message_read_here SET id = NULL, name = NULL, merged_at = ?2 WHERE id = ?1\",",
     "\"DELETE FROM message_read_here WHERE id = ?1 AND ?2 = ?2\",",
     [EACH_WAY, LEFT_BARE, DROPPED, MARK_GOES, OUTLASTS]),
    ("K30 a mark goes with its message's row at a clearing", MESSAGES,
     "        Some(id) => drop_row(conn, &id, now),",
     "        Some(id) => {\n"
     "            conn.execute(\"DELETE FROM message_read_here WHERE id = ?1\", [&id])?;\n"
     "            drop_row(conn, &id, now)\n"
     "        }",
     [EACH_WAY]),
    ("K31 a mark goes with its message's row as it leaves the live numbers", MESSAGES,
     "            drop_row(conn, &id, now)?;\n",
     "            conn.execute(\"DELETE FROM message_read_here WHERE id = ?1\", [&id])?;\n"
     "            drop_row(conn, &id, now)?;\n",
     [EACH_WAY]),
    ("K32 a mark goes with its message's row at its 30 days", MESSAGES,
     "        gone.expired += usize::from(drop_row(conn, &id, now)?);",
     "        conn.execute(\"DELETE FROM message_read_here WHERE id = ?1\", [&id])?;\n"
     "        gone.expired += usize::from(drop_row(conn, &id, now)?);",
     [EACH_WAY, LEFT_BARE, MARK_GOES, OUTLASTS]),
    ("K33 a mark goes with its message's row held at no live number", MESSAGES,
     "        gone.not_live += usize::from(drop_row(conn, &id, now)?);",
     "        conn.execute(\"DELETE FROM message_read_here WHERE id = ?1\", [&id])?;\n"
     "        gone.not_live += usize::from(drop_row(conn, &id, now)?);",
     [EACH_WAY]),
    # A generation that was left has no code of its own: its rows go at
    # their 30 days or held at no live number, by K32 and K33.
    ("K34 a mark left bare goes 30 days after it was made", MESSAGES,
     "merged_at = ?2 WHERE id = ?1\",\n        params![id, now],",
     "merged_at = made_at WHERE id = ?1 AND ?2 = ?2\",\n        params![id, now],",
     [LEFT_BARE, MARK_GOES]),
    ("K35 more than 120 marks are kept bare when their rows go", MESSAGES,
     "    keep_120_bare(conn)?;\n    let dropped",
     "    let dropped",
     [LEFT_BARE]),
    ("A31 an answer of another to another key's entry in the list's slot writes the list", MARKS,
     " && entry.author == own && entry.slot == held.slot",
     " && entry.slot == held.slot",
     [OTHER_KEY]),
    # The reader and the hourly task (§7.1, §7.2).
    ("R01 the reader keeps nothing of a list", READER,
     "            crate::marks::list_taken(conn, own, &signer, &list.marks, now)?;\n",
     "",
     [BEFORE_MESSAGE, KEPT_ONLY, MERGES, REACHES]),
    ("R02 the hourly task leaves the marks alone", READER,
     "    if let Err(e) = in_one(conn, || crate::marks::hourly(conn, now)) {",
     "    if let Err(e) = in_one(conn, || Ok(())) {",
     [MARK_GOES, LIES]),
    ("R03 an error in the marks' part takes back the drop", READER,
     "    let gone = match in_one(conn, || kept(held::drop_gone(conn, now, &applied))) {\n"
     "        Ok(gone) => gone,\n"
     "        Err(e) => {\n"
     "            tracing::warn!(error = %e, \"could not drop this device's expired messages\");\n"
     "            held::Gone::default()\n"
     "        }\n"
     "    };\n"
     "    if let Err(e) = in_one(conn, || crate::marks::hourly(conn, now)) {\n"
     "        tracing::warn!(error = %e, \"could not keep this device's marks\");\n"
     "    }\n",
     "    let gone = in_one(conn, || {\n"
     "        let gone = kept(held::drop_gone(conn, now, &applied))?;\n"
     "        crate::marks::hourly(conn, now)?;\n"
     "        Ok(gone)\n"
     "    })?;\n",
     [MARKS_FAIL]),
    ("R04 an error in the marks' part ends the task before the checkpoint", READER,
     "    if let Err(e) = in_one(conn, || crate::marks::hourly(conn, now)) {\n"
     "        tracing::warn!(error = %e, \"could not keep this device's marks\");\n"
     "    }\n",
     "    in_one(conn, || crate::marks::hourly(conn, now))?;\n",
     [MARKS_FAIL]),
    ("R05 an error in the drop ends the task before the marks and the checkpoint", READER,
     "    let gone = match in_one(conn, || kept(held::drop_gone(conn, now, &applied))) {\n"
     "        Ok(gone) => gone,\n"
     "        Err(e) => {\n"
     "            tracing::warn!(error = %e, \"could not drop this device's expired messages\");\n"
     "            held::Gone::default()\n"
     "        }\n"
     "    };\n",
     "    let gone = in_one(conn, || kept(held::drop_gone(conn, now, &applied)))?;\n",
     [DROP_FAIL]),
    # Where a merged list's marks go (§2.4, §7.2).
    ("K36 the merged marks go below every mark held, as before", MESSAGES,
     "    let listed = listed_seq(conn)?;\n",
     "    let listed: Option<i64> = None;\n",
     [WENT_BARE, SAID_130, SAID_MORE, RESTORE_E2E]),
    ("K37 the marks made since the last list are not moved up", MESSAGES,
     "                conn.execute(\n"
     "                    \"UPDATE message_read_here SET seq = seq + ?2 WHERE seq > ?1\",\n"
     "                    params![listed, up],\n"
     "                )?;\n"
     "                conn.execute(\n"
     "                    \"UPDATE message_read_here SET seq = seq - ?2 WHERE seq > ?1\",\n"
     "                    params![highest, below],\n"
     "                )?;\n",
     "                let _ = (highest, below, up);\n",
     [SINCE, RESTORED, RESTORE_E2E]),
    ("K38 the merged marks are given the list's order reversed", MESSAGES,
     "    let mut seq = top;\n",
     "    let mut seq = top;\n    if listed.is_some() {\n        lacked.reverse();\n    }\n",
     [SAID_130, SINCE]),
    ("K39 the kept value is not raised after a merge", MESSAGES,
     "    if listed.is_some() && merged > 0 {\n        set_listed_seq(conn, top)?;\n    }\n",
     "",
     [SINCE]),
    ("K40 a mark made after a list may be below what was listed", MESSAGES,
     "    let above = highest_seq(conn)?.max(listed_seq(conn)?).unwrap_or(0);",
     "    let above = highest_seq(conn)?.unwrap_or(0);",
     [AFTER_LIST, RESTORED]),
    # The kept value of a damaged store, and a seq at an integer's end (§7.2).
    ("K48 the kept value has no bound above the table's highest", MESSAGES,
     "        .filter(|listed| *listed >= 0 && *listed <= highest.saturating_add(LISTED_AHEAD_MAX)))",
     "        .filter(|listed| *listed >= 0 && highest >= 0))",
     [OUT_OF_BOUNDS]),
    ("K49 a negative kept value counts", MESSAGES,
     "        .filter(|listed| *listed >= 0 && *listed <= highest.saturating_add(LISTED_AHEAD_MAX)))",
     "        .filter(|listed| *listed <= highest.saturating_add(LISTED_AHEAD_MAX)))",
     [OUT_OF_BOUNDS]),
    ("K50 the bound is one short", MESSAGES,
     "        .filter(|listed| *listed >= 0 && *listed <= highest.saturating_add(LISTED_AHEAD_MAX)))",
     "        .filter(|listed| *listed >= 0 && *listed < highest.saturating_add(LISTED_AHEAD_MAX)))",
     [OUT_OF_BOUNDS]),
    ("K51 a mark's seq is added unchecked", MESSAGES,
     "        params![&mark[..], &id[..], name, now, added(above, 1)?],",
     "        params![&mark[..], &id[..], name, now, above + 1],",
     [SEQ_END]),
    ("K52 the top of the merged marks is added unchecked", MESSAGES,
     "            added(listed, count)?\n",
     "            listed + count\n",
     [SEQ_END]),
    ("K53 the rows' move up is added unchecked", MESSAGES,
     "                let up = added(below, count)?;",
     "                let up = below + count;",
     [SEQ_END]),
    ("K55 the place below the lowest mark is subtracted unchecked", MESSAGES,
     "            Some(lowest) => subtracted(lowest, 1)?,",
     "            Some(lowest) => lowest - 1,",
     [SEQ_END]),
    ("K56 the place of the next merged mark is decremented unchecked", MESSAGES,
     "            seq = subtracted(seq, 1)?;",
     "            seq -= 1;",
     [SEQ_END]),
    ("A32 the kept value is not set when a list is written", MARKS,
     "    kept(held::wrote_list(conn))?;\n",
     "",
     [SAID_MORE, MARK_GOES, RESTORE_E2E]),
    # The node's passes (§2.4).
    ("N01 a pass writes no list", ENGINE,
     "            if messages && (self.write_again() | self.write_list()) {",
     "            if messages && self.write_again() {",
     [RESTORE_E2E, STATEMENT_E2E]),
    ("N02 a relay's answer of another to a list is taken as before the first fetch", ENGINE,
     "                        fetched: fetched.unwrap_or(false),\n                    };\n                    sender::pushed(",
     "                        fetched: false,\n                    };\n                    sender::pushed(",
     [ANOTHER_E2E]),
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
