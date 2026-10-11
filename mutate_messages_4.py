#!/usr/bin/env python3
"""Mutation checks for the reader of messages between a person's own
agents: what a device keeps of an entry of the messages channel that the
door stores, the live numbers and what is counted as overwritten, the
index and the row of first holding, a clearing, the shown time and the
30 days, the reader's rate, and the first and last part of the hourly
task (decision 2026-10-09 §2.3, §2.5, §6, §7.1, the reader's half of
§9.1), with what the review of slice 2 left owed: `drop_row` refused
part-way, the node's store opened with `secure_delete` before its steps,
and step 19's columns held to their types and bounds; and what the
review of this slice found: the reader reads only what the store kept, a
number held as a clearing is gone, a number is counted once, one clock,
a message is of its generation, and the rows of a generation the device
has left go. A part for each rule of the slice: put each fault in, and confirm the test named for it
fails on an assertion. Run from the root of a checkout that nothing else
edits."""
import re, subprocess, sys

# One name for each file a part edits.
TAKE = 'crates/cordelia-api/src/take.rs'
READER = 'crates/cordelia-api/src/reader.rs'
MESSAGES = 'crates/cordelia-storage/src/messages.rs'
SCHEMA = 'crates/cordelia-storage/src/schema.rs'
DB = 'crates/cordelia-storage/src/db.rs'
MAIN = 'crates/cordelia-node/src/main.rs'
DEVICE = 'crates/cordelia-node/src/device_entries.rs'
LEAVE = 'crates/cordelia-node/src/device_entries/leave.rs'
ORIG = {f: open(f).read() for f in (TAKE, READER, MESSAGES, SCHEMA, DB, MAIN, DEVICE, LEAVE)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
STORAGE = ("cordelia-storage", ["--lib"])
NODE_LIB = ("cordelia-node", ["--lib"])
NODE_BIN = ("cordelia-node", ["--bin", "cordelia"])
NODE_E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
def reader(test): return (API, "reader::tests::" + test)
def messages(test): return (STORAGE, "messages::tests::" + test)
def schema(test): return (STORAGE, "schema::tests::" + test)
def device(test): return (NODE_LIB, "device_entries::tests::" + test)
def node(test): return (NODE_BIN, "tests::" + test)

INDEXES = reader("the_reader_indexes_what_the_door_stores_in_the_same_write")
ANOTHER_KEY = reader("a_message_in_a_slot_named_for_another_key_is_no_message")
OUT_OF_PLACE = reader("an_entry_whose_number_is_not_in_its_slots_place_is_no_message")
NOT_LIVE = reader("an_entry_at_a_number_that_is_not_live_is_never_opened")
LIST_ABOVE = reader("a_list_far_above_its_messages_loses_no_message_on_any_reader")
GAP = reader("a_gap_in_a_signers_numbers_is_said_as_overwritten")
CLEARING = reader("a_clearing_by_either_number_drops_a_message_sent_again")
THIRTY = reader("a_message_is_not_shown_thirty_days_after_it_was_first_held")
SECURE = reader("the_index_row_is_overwritten_before_it_is_dropped_with_secure_delete_on")
CLOCKS = reader("a_sender_clock_behind_shortens_a_messages_life_and_one_ahead_does_not_lengthen_it")
AHEAD = reader("a_message_sent_ahead_of_the_readers_clock_is_shown_from_its_first_holding")
ORDER = reader("shown_is_oldest_first_by_shown_time_then_by_id")
AGAIN = reader("an_entry_taken_again_after_its_thirty_days_is_never_shown")
AWAY = reader("a_reader_that_was_away_shows_a_whole_ring_at_once")
LAPS = reader("a_holder_of_the_key_that_laps_its_ring_is_shown_at_most_64_in_an_hour")
WHATEVER = reader("a_place_counts_in_the_hour_whatever_became_of_its_message")
RELAY = reader("a_relay_that_hands_old_entries_in_rising_order_holds_current_ones_back_an_hour_at_most")
FUTURE = reader("a_place_in_the_future_of_the_readers_clock_keeps_its_place_and_is_not_counted")
RING = reader("a_signer_that_rewrites_its_ring_ten_thousand_times_leaves_one_lap_in_a_readers_store")
COUNTED = messages("a_number_that_leaves_the_live_numbers_is_counted_unless_its_message_had_a_place_or_went")
OWN = messages("the_devices_own_messages_take_no_place_from_the_hour")
NEWEST = messages("places_are_given_newest_first_while_the_hour_has_room")
HOURLY = messages("the_hourly_drop_takes_what_expired_what_is_not_live_and_the_old_places")
PART_WAY = messages("a_drop_refused_part_way_leaves_the_row_and_the_callers_write")
TYPES = schema("step_19s_columns_take_only_their_type_and_their_bound")
BOUNDS = schema("step_19s_bounds_are_those_of_protocol_rs")
OLD_STEP = node("a_personal_nodes_store_of_an_old_step_is_stepped_with_secure_delete_on")
NODE_HOURLY = device("the_hourly_task_of_messages_drops_what_expired_unless_the_node_is_held_up")
ONLY_KEPT = reader("the_reader_reads_only_what_the_store_kept")
AS_CLEARING = reader("a_number_held_as_a_clearing_is_gone_and_not_overwritten")
ONCE = reader("a_number_is_counted_once_however_many_of_its_entries_are_handed")
OF_ITS_GENERATION = reader("a_message_written_again_in_a_new_generation_is_not_the_old_ones")
LEFT = reader("a_generation_the_device_has_left_goes_once_its_rows_have")
STORE_RING = messages("a_signer_that_rewrites_its_ring_ten_thousand_times_leaves_one_lap_in_the_store")
NODE_CLOCK = device("the_hourly_task_of_messages_reads_the_nodes_clock")
PASS_CLOCK = (NODE_E2E, "a_message_is_first_held_shown_and_dropped_by_the_nodes_clock")
LAST_GENERATION = messages("the_hourly_drop_keeps_the_last_generation_and_drops_none_where_it_is_not_known")
NOT_KNOWN = reader("an_hourly_task_that_cannot_read_the_channel_applied_drops_what_expired_and_no_generation")
OTHER_GENERATION = reader("a_number_held_at_another_generations_message_is_not_counted_as_overwritten")
KEPT_LEFT = (API, "sender::tests::one_hourly_task_leaves_nothing_of_a_generation_left_with_a_kept_value")
TYPED_CLOCK = (NODE_E2E, "the_hour_of_a_typed_key_is_judged_by_the_nodes_clock")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── The door calls the reader, in its write ───────────────────────
    ("D1 the door does not call the reader", TAKE,
     '''    if is_messages && stored == Outcome::Stored {''',
     '''    if false && is_messages && stored == Outcome::Stored {''',
     [INDEXES]),
    ("D2 the reader's failure does not undo the door's write", TAKE,
     '''        crate::reader::taken(conn, &identity.public_key(), &secret, statement, entry, now)?;''',
     '''        let _ = crate::reader::taken(conn, &identity.public_key(), &secret, statement, entry, now);''',
     [INDEXES]),
    ("D3 the reader reads what the store did not keep", TAKE,
     '''    if is_messages && stored == Outcome::Stored {''',
     '''    if is_messages {''',
     [ONLY_KEPT]),

    # ── The reader's check, before it opens anything ──────────────────
    ("R1 the slot of a message is not checked", READER,
     '''        && entry.slot == slot_id(&slot_key, &message::message_name(&signer, number)?);''',
     '''        && entry.slot != [0; 32];''',
     [ANOTHER_KEY, OUT_OF_PLACE, LIST_ABOVE]),
    ("R2 a number no message can have is held", READER,
     '''        && message::message_rev(number).is_some()
''',
     '''''',
     [OUT_OF_PLACE]),
    ("R3 an entry in no slot of its signer's is not counted", READER,
     '''        kept(held::not_a_message(conn, &signer, generation))?;
        Ok(Read::NotAMessage(why))''',
     '''        Ok(Read::NotAMessage(why))''',
     [ANOTHER_KEY, OUT_OF_PLACE]),
    ("R4 an entry that does not open is not counted", READER,
     '''        kept(held::not_a_message(conn, &signer, generation))?;
        return Ok(Read::DidNotOpen);''',
     '''        return Ok(Read::DidNotOpen);''',
     [NOT_LIVE]),
    ("R5 an entry at a number that is not live is opened", READER,
     '''    if in_its_slot
        && !kept(held::hold_number(
            conn, &signer, generation, number, clearing, now,
        ))?
    {''',
     '''    if in_its_slot
        && !kept(held::hold_number(
            conn, &signer, generation, number, clearing, now,
        ))?
        && false
    {''',
     [NOT_LIVE]),
    ("R6 a list raises H as a message would", READER,
     '''    if in_its_slot
        && !kept(held::hold_number(''',
     '''    if !kept(held::hold_number(''',
     [LIST_ABOVE]),
    ("R7 a value that is no message is not counted", READER,
     '''        Err(why) => no_message(why),''',
     '''        Err(_) => Ok(Read::List),''',
     [OUT_OF_PLACE, LIST_ABOVE]),
    ("R8 a message is not written into the index", READER,
     '''            Ok(Read::Message(kept(held::index(conn, &opened))?))''',
     '''            let _ = opened;
            Ok(Read::List)''',
     [INDEXES, AWAY]),
    ("R9 the label is not the signer's", READER,
     '''                label: &label,''',
     '''                label: "",''',
     [INDEXES]),
    ("R10 the first holding is not the time it was taken", READER,
     '''                first_held: now,''',
     '''                first_held: now + 1,''',
     [INDEXES]),
    ("R11 a clearing drops nothing", READER,
     '''            dropped: kept(held::clear(conn, &signer, generation, number, now))?,''',
     '''            dropped: number == 0,''',
     [CLEARING, WHATEVER]),

    # ── H and the live numbers ────────────────────────────────────────
    ("H1 H is not raised", MESSAGES,
     '''        kept.highest = number;''',
     '''        kept.highest = kept.highest.max(1);''',
     [GAP, NOT_LIVE, LAPS]),
    ("H2 the number H less the ring is live", MESSAGES,
     '''    } else if number_sql > highest - RING {''',
     '''    } else if number_sql >= highest - RING {''',
     [NOT_LIVE]),
    ("H3 the ring is a slot longer", MESSAGES,
     '''const RING: i64 = AGENT_MESSAGE_RING as i64;''',
     '''const RING: i64 = AGENT_MESSAGE_RING as i64 + 1;''',
     [GAP, LAPS, RELAY]),
    ("H4 nothing is counted from the first number held", MESSAGES,
     '''        kept.counted_from = Some(kept.counted_from.unwrap_or(number));''',
     '''        kept.counted_from = kept.counted_from;''',
     [GAP, COUNTED]),
    ("H5 a lower live number is not counted from", MESSAGES,
     '''            kept.counted_from = Some(number);
        }
        true''',
     '''        }
        true''',
     [NOT_LIVE]),
    ("H6 an entry at a number that is not live is not counted", MESSAGES,
     '''            kept.overwritten += 1;''',
     '''            kept.overwritten += 0;''',
     [NOT_LIVE]),
    ("H7 an entry at a number already counted is counted again", MESSAGES,
     '''        if !clearing && kept.counted_from.is_none_or(|from| number < from) {
            kept.overwritten += 1;''',
     '''        if !clearing {
            kept.overwritten += 1;''',
     [COUNTED]),
    ("H8 a message that had a place is counted as overwritten", MESSAGES,
     '''           AND (i.id IS NULL OR i.placed_at IS NOT NULL)",''',
     '''           AND (i.id IS NULL)",''',
     [GAP, COUNTED]),
    ("H9 a message that went is counted as overwritten", MESSAGES,
     '''           AND (i.id IS NULL OR i.placed_at IS NOT NULL)",''',
     '''           AND (i.placed_at IS NOT NULL)",''',
     [COUNTED]),
    ("H10 what left the live numbers before is counted again", MESSAGES,
     '''            let lowest = (highest - RING + 1).max(from);''',
     '''            let lowest = from;''',
     [LAPS]),
    ("H11 the rows of numbers that left are kept", MESSAGES,
     '''            leave_up_to(conn, of, generation, left, now)?;''',
     '''            let _ = (left, now);''',
     [GAP, RING, STORE_RING]),
    ("H12 a message held at no number keeps its index row", MESSAGES,
     '''        if held == 0 {''',
     '''        if held < 0 {''',
     [GAP]),
    ("H13 the rows of first holding of numbers that left are kept", MESSAGES,
     '''        "DELETE FROM message_first_held WHERE signer = ?1 AND generation = ?2 AND number <= ?3",''',
     '''        "DELETE FROM message_first_held WHERE signer = ?1 AND generation = ?2 AND number <= ?3 AND 0",''',
     [GAP, RING, STORE_RING]),
    ("H14 an entry of no message is not counted", MESSAGES,
     '''    kept.not_messages += 1;''',
     '''    kept.not_messages += 0;''',
     [ANOTHER_KEY, OUT_OF_PLACE]),

    # ── The index and the row of first holding ────────────────────────
    ("I1 a number held before is shown again", MESSAGES,
     '''    if held_before.is_some() {''',
     '''    if held_before.is_some() && false {''',
     [AGAIN]),
    ("I2 a message whose row went is shown again at another number", MESSAGES,
     '''        _ => return Ok(Indexed::NotAgain),''',
     '''        _ => Indexed::AnotherNumber,''',
     [AGAIN]),
    ("I3 the subject is cut a character later", MESSAGES,
     '''                .take(AGENT_MESSAGE_SUBJECT_CHARS)''',
     '''                .take(AGENT_MESSAGE_SUBJECT_CHARS + 1)''',
     [INDEXES]),
    ("I4 a clearing drops no row", MESSAGES,
     '''        Some(id) => drop_row(conn, &id, now),''',
     '''        Some(_) => Ok(false),''',
     [CLEARING]),

    # ── The shown time and the 30 days ────────────────────────────────
    ("T1 the shown time is the later of the two", MESSAGES,
     '''    sent.min(first_held)''',
     '''    sent.max(first_held)''',
     [CLOCKS, AHEAD]),
    ("T2 a message has expired only after its 30 days", MESSAGES,
     '''    now.saturating_sub(shown_at(sent, first_held)) >= i64::from(AGENT_MESSAGE_KEPT_DAYS) * DAY_SECS''',
     '''    now.saturating_sub(shown_at(sent, first_held)) > i64::from(AGENT_MESSAGE_KEPT_DAYS) * DAY_SECS''',
     [CLOCKS]),
    ("T3 a row is shown from its later time", MESSAGES,
     '''        "(MIN(i.sent, i.first_held) + {})",''',
     '''        "(MAX(i.sent, i.first_held) + {})",''',
     [CLOCKS, AHEAD]),
    ("T4 a row is shown a day longer", MESSAGES,
     '''        i64::from(AGENT_MESSAGE_KEPT_DAYS) * DAY_SECS
    )''',
     '''        (i64::from(AGENT_MESSAGE_KEPT_DAYS) + 1) * DAY_SECS
    )''',
     [THIRTY, CLOCKS]),
    ("T5 the number H less the ring is shown as live", MESSAGES,
     '''                 WHERE n.id = i.id AND n.number > COALESCE(s.highest, 0) - {RING})"''',
     '''                 WHERE n.id = i.id AND n.number >= COALESCE(s.highest, 0) - {RING})"''',
     [HOURLY]),
    ("T6 what is shown is by ID the other way", MESSAGES,
     '''             WHERE i.placed_at IS NOT NULL AND ?1 < {expires} AND {live}
             ORDER BY shown_at, i.id",''',
     '''             WHERE i.placed_at IS NOT NULL AND ?1 < {expires} AND {live}
             ORDER BY shown_at, i.id DESC",''',
     [ORDER]),
    ("T7 a message with no place is shown", MESSAGES,
     '''             WHERE i.placed_at IS NOT NULL AND ?1 < {expires} AND {live}
             ORDER BY shown_at, i.id",''',
     '''             WHERE ?1 < {expires} AND {live}
             ORDER BY shown_at, i.id",''',
     [WHATEVER, RELAY]),

    # ── The reader's rate ─────────────────────────────────────────────
    ("P1 a place an hour old still counts", MESSAGES,
     '''        "DELETE FROM message_places WHERE placed_at <= ?1 OR placed_at > ?2",''',
     '''        "DELETE FROM message_places WHERE placed_at < ?1 OR placed_at > ?2",''',
     [WHATEVER, LAPS]),
    ("P2 a place in the future counts", MESSAGES,
     '''        "DELETE FROM message_places WHERE placed_at <= ?1 OR placed_at > ?2",''',
     '''        "DELETE FROM message_places WHERE placed_at <= ?1 OR placed_at > ?2 + 100000",''',
     [FUTURE]),
    ("P3 a lap and one more in an hour", MESSAGES,
     '''                    RING - placed''',
     '''                    RING + 1 - placed''',
     [LAPS]),
    ("P4 places are given oldest first", MESSAGES,
     '''             ORDER BY i.signer, i.generation, MAX(n.number) DESC",''',
     '''             ORDER BY i.signer, i.generation, MAX(n.number) ASC",''',
     [NEWEST]),
    ("P5 the device's own messages take places from the hour", MESSAGES,
     '''        let is_own = signer.as_slice() == own.as_slice();''',
     '''        let is_own = signer.as_slice() == own.as_slice() && false;''',
     [OWN]),
    ("P6 a place is given without its time", MESSAGES,
     '''                "INSERT INTO message_places (signer, generation, placed_at) VALUES (?1, ?2, ?3)",''',
     '''                "SELECT ?1, ?2, ?3",''',
     [LAPS, WHATEVER]),

    # ── The hourly task ───────────────────────────────────────────────
    ("K1 the hourly task drops what expired a second later", MESSAGES,
     '''    for id in ids(format!("{now} >= {}", expires_sql()))? {''',
     '''    for id in ids(format!("{now} > {}", expires_sql()))? {''',
     [THIRTY, HOURLY]),
    ("K2 the hourly task keeps rows held at no live number", MESSAGES,
     '''    for id in ids(format!("NOT {}", live_sql()))? {''',
     '''    for id in ids(format!("0 AND NOT {}", live_sql()))? {''',
     [HOURLY]),
    ("K3 the hourly task keeps rows of first holding that are not live", MESSAGES,
     '''            "DELETE FROM message_first_held AS f WHERE f.number <= COALESCE(''',
     '''            "DELETE FROM message_first_held AS f WHERE 0 AND f.number <= COALESCE(''',
     [HOURLY]),
    ("K4 the hourly task keeps old places", MESSAGES,
     '''        "DELETE FROM message_places WHERE placed_at <= ?1",''',
     '''        "DELETE FROM message_places WHERE placed_at <= ?1 - 100000000",''',
     [HOURLY]),
    ("K5 the hourly task drops nothing", READER,
     '''    let gone = match in_one(conn, || kept(held::drop_gone(conn, now, &applied))) {''',
     '''    let gone = match Ok::<held::Gone, PersonError>(held::Gone::default()) {''',
     [THIRTY, SECURE]),
    ("K6 the hourly task does not truncate the log", READER,
     '''    let checkpointed = kept(cordelia_storage::db::checkpoint_truncating(conn))?;''',
     '''    let checkpointed = true;''',
     [SECURE]),
    ("K7 a node that is held up runs the hourly task", DEVICE,
     '''    pub fn messages_hourly(&self) {
        if self.state.held.why().is_some() {''',
     '''    pub fn messages_hourly(&self) {
        if self.state.held.why().is_some() && false {''',
     [NODE_HOURLY]),
    ("K8 the node runs the hourly task at another time", DEVICE,
     '''        match cordelia_api::reader::hourly(&db, identity, now, fetched.unwrap_or(false)) {''',
     '''        match cordelia_api::reader::hourly(&db, identity, now - now, fetched.unwrap_or(false)) {''',
     [NODE_HOURLY]),

    # ── What slice 2's review left owed ───────────────────────────────
    ("O1 a drop refused part-way keeps its overwrite", MESSAGES,
     '''        Err(_) => "ROLLBACK TO drop_row; RELEASE drop_row",''',
     '''        Err(_) => "RELEASE drop_row",''',
     [PART_WAY]),
    ("O2 the node sets secure_delete after the steps", MAIN,
     '''    match cordelia_storage::db::open_as(db_path, secure_delete) {
        Ok(conn) => Ok((conn, None)),''',
     '''    match cordelia_storage::db::open_as(db_path, false) {
        Ok(conn) => {
            if secure_delete {
                cordelia_storage::db::secure_delete_on(&conn)?;
            }
            Ok((conn, None))
        }''',
     [OLD_STEP]),
    ("O3 a command sets secure_delete after the steps", MAIN,
     '''    match cordelia_storage::db::open_as(db_path, keeps_secure_delete(&config.network.role)) {
        Ok(conn) => Ok(conn),''',
     '''    match cordelia_storage::db::open_as(db_path, false) {
        Ok(conn) => {
            if keeps_secure_delete(&config.network.role) {
                cordelia_storage::db::secure_delete_on(&conn)?;
            }
            Ok(conn)
        }''',
     [OLD_STEP]),
    ("O4 the store sets secure_delete after its steps", DB,
     '''    if secure_delete {
        secure_delete_on(&conn)?;
    }
    schema::init_db(&conn)?;''',
     '''    schema::init_db(&conn)?;
    if secure_delete {
        secure_delete_on(&conn)?;
    }''',
     [OLD_STEP]),
    ("C1 a kept value of another length", SCHEMA,
     '''length(value) = 1936),''',
     '''length(value) = 1937),''',
     [BOUNDS]),
    ("C2 H one above the highest number", SCHEMA,
     '''highest >= 0 AND highest <= 4398046511103),''',
     '''highest >= 0 AND highest <= 4398046511104),''',
     [BOUNDS]),
    ("C3 a statement above the highest", SCHEMA,
     '''statement >= 1 AND statement <= 256),''',
     '''statement >= 1 AND statement <= 257),''',
     [BOUNDS, TYPES]),
    ("C4 counted_from above H", SCHEMA,
     '''AND counted_from >= 1 AND counted_from <= highest)),''',
     '''AND counted_from >= 1)),''',
     [TYPES]),
    ("C5 a channel's ID of text", SCHEMA,
     '''CHECK(typeof(channel) = 'blob' AND length(channel) = 32),''',
     '''CHECK(length(channel) = 32),''',
     [TYPES]),
    ("C6 a sent time that is not an integer", SCHEMA,
     '''    sent             INTEGER NOT NULL CHECK(typeof(sent) = 'integer'),''',
     '''    sent             INTEGER NOT NULL,''',
     [TYPES]),
    ("C7 a signer of text", SCHEMA,
     '''    signer           BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),''',
     '''    signer           BLOB NOT NULL CHECK(length(signer) = 32),''',
     [TYPES]),
    ("C8 a place's time that is not an integer", SCHEMA,
     '''    placed_at   INTEGER NOT NULL CHECK(typeof(placed_at) = 'integer')''',
     '''    placed_at   INTEGER NOT NULL''',
     [TYPES]),
    # ── What the review of this slice found ──────────────────────────
    ("G1 a clearing holds no number as gone", MESSAGES,
     '''    conn.execute(
        "INSERT INTO message_first_held (signer, generation, number, id, sent, first_held)
         VALUES (?1, ?2, ?3, NULL, NULL, ?4)
         ON CONFLICT(signer, generation, number) DO NOTHING",
        params![&of[..], generation, to_sql(number), now],
    )?;
''',
     '''    let _ = now;
''',
     [AS_CLEARING, CLEARING]),
    ("G2 a clearing at a number that is not live is counted", MESSAGES,
     '''        if !clearing && kept.counted_from.is_none_or(|from| number < from) {''',
     '''        if kept.counted_from.is_none_or(|from| number < from) {''',
     [ONCE, ONLY_KEPT]),
    ("G3 the reader holds every entry as a message", READER,
     '''    let clearing = entry.rev % 2 == 1;''',
     '''    let clearing = entry.rev % 2 == 2;''',
     [ONCE]),
    ("N1 the time this side of the node reads is not the node's clock", DEVICE,
     '''        self.clock.unix_from(self.state.sync_control.now())''',
     '''        self.clock.unix()''',
     [NODE_CLOCK, PASS_CLOCK]),
    ("I5 a message is looked up by its ID alone", MESSAGES,
     '''        (Some(held_in), _) if held_in == generation => Indexed::AnotherNumber,''',
     '''        (Some(_), _) => Indexed::AnotherNumber,''',
     [OF_ITS_GENERATION]),
    ("K9 a generation the device has left keeps its rows", MESSAGES,
     '''             WHERE g.channel IS NOT ?1''',
     '''             WHERE 0 AND g.channel IS NOT ?1''',
     [LEFT]),
    ("K10 the generation applied goes as one that was left", MESSAGES,
     '''             WHERE g.channel IS NOT ?1''',
     '''             WHERE (g.channel IS NOT ?1 OR 1)''',
     [LEFT]),
    ("K11 the hourly task knows of no generation applied", READER,
     '''        Ok(Some(channel)) => held::Applied::Under(channel),''',
     '''        Ok(Some(_)) => held::Applied::Nowhere,''',
     [KEPT_LEFT]),
    ("K12 a generation left keeps its signers", MESSAGES,
     '''        for table in ["message_first_held", "message_signers", "message_places"] {''',
     '''        for table in ["message_first_held", "message_places"] {''',
     [LEFT]),
    # ── What the check of the reader's fix found ──────────────────────
    ("F1 the hourly drop takes the last generation of a device applied nowhere", MESSAGES,
     '''               AND (?1 IS NOT NULL OR g.id < (SELECT MAX(id) FROM message_generations))
''',
     '''''',
     [LAST_GENERATION]),
    ("F2 the hourly drop takes generations where the one applied is not known", MESSAGES,
     '''        Applied::NotKnown => return Ok(gone),''',
     '''        Applied::NotKnown => None,''',
     [LAST_GENERATION, NOT_KNOWN]),
    ("F3 a channel that cannot be read counts as none applied", READER,
     '''        Err(_) => held::Applied::NotKnown,''',
     '''        Err(_) => held::Applied::Nowhere,''',
     [NOT_KNOWN]),
    ("F4 a channel that cannot be read stops the hourly drop", READER,
     '''    let applied = match crate::at_relays::messages_channel(conn) {''',
     '''    let applied = match Ok::<_, PersonError>(crate::at_relays::messages_channel(conn)?) {''',
     [NOT_KNOWN]),
    ("F5 a number is matched to a message of another generation", MESSAGES,
     '''ON i.id = f.id AND i.generation = f.generation''',
     '''ON i.id = f.id''',
     [OTHER_GENERATION]),
    ("F6 the hour of a typed key is judged by another clock", LEAVE,
     '''        let unix = || self.clock.unix_from(state.sync_control.now());''',
     '''        let unix = || self.clock.unix();''',
     [TYPED_CLOCK]),
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
