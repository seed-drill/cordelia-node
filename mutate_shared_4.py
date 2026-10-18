#!/usr/bin/env python3
"""Mutation checks for slice 4 of a shared channel: the door and the
reader, with schema step 21 (decision 2026-10-10 sections 2.3, 2.4 and 6.1
to 6.3): the table of shared channels and how it follows the person's
lists; the door's branch for a shared channel and its refusals before
anything is stored; storing with no check that the signer counts; the
room of the keys the person does not know and the table of keys, which
keeps every key that stores an entry and at most 1,024 that store
nothing; taking entries out, of a key that stops being known, of a quiet
key by first holding alone, and of a channel dropped or moved from; the
revisions a let-go row keeps; the keys shown, in the one order and up to
64; reading again, at most once a day; and the index of shared messages,
keyed by channel and ID, with the reader's hour and the unlabelled hour.
A part for each rule of the slice: put each fault in, and confirm the
test named for it fails on an assertion. Run from the root of a checkout
that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
SHARED = 'crates/cordelia-api/src/shared.rs'
TAKE = 'crates/cordelia-api/src/take.rs'
LISTS = 'crates/cordelia-api/src/lists.rs'
READER = 'crates/cordelia-api/src/reader.rs'
LEAVING = 'crates/cordelia-api/src/leaving.rs'
STORE = 'crates/cordelia-storage/src/shared.rs'
SCHEMA = 'crates/cordelia-storage/src/schema.rs'
ORIG = {f: open(f).read() for f in (SHARED, TAKE, LISTS, READER, LEAVING, STORE, SCHEMA)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
STORAGE = ("cordelia-storage", ["--lib"])
def shared(test): return (API, "shared::tests::" + test)
def take(test): return (API, "take::tests::" + test)
def leaving(test): return (API, "leaving::tests::" + test)
def schema(test): return (STORAGE, "schema::tests::" + test)

DOOR = take("the_door_takes_a_shared_channels_entries_only_where_the_device_stands_applied_with_sync_on")
OUTSIDE = take("an_entry_outside_its_signers_slots_or_size_is_not_stored")
ANOTHER = shared("an_entry_in_another_keys_slot_is_no_message_and_no_record")
FOLLOWS = shared("the_table_of_shared_channels_follows_the_lists")
BLIND = shared("a_member_cannot_blind_a_device_to_the_keys_its_person_knows")
DELETES = shared("deletes_at_a_relay_do_not_grow_an_existing_devices_store")
STOPS = shared("a_key_that_stops_being_known_joins_the_room")
QUIET = shared("a_quiet_key_is_let_go_by_first_holding_alone")
TABLE = shared("the_table_keeps_every_key_that_stores_an_entry")
DROP = shared("a_drop_or_a_move_takes_its_entries")
SHOWS = shared("a_reader_shows_64_keys_and_64_unlabelled_places_an_hour")
SIGNER = shared("a_signer_has_64_places_an_hour")
FULL = shared("a_full_channel_still_takes_a_slot_written_again")
RING = shared("the_reader_takes_only_a_message_in_its_ring_at_a_live_number")
NO_LIST = shared("what_a_maker_in_no_list_filed_or_labelled_is_not_in_force_here")
COMES = shared("a_key_with_bytes_refused_that_comes_to_count_is_read_again")
DAILY = shared("reading_again_is_once_a_day_for_each_channel")
TWO = shared("one_id_in_two_channels_is_two_messages")
EXPIRES = shared("a_shared_message_goes_from_the_index_at_its_30_days")
FORGETS = leaving("test_a_device_that_forgets_keeps_its_names_and_nothing_else_of_its_person")
STEP = schema("each_step_of_this_record_adds_its_tables_and_changes_no_older_row")
STEP_BOUNDS = schema("step_21s_bounds_are_those_of_protocol_rs")
BEFORE = schema("the_version_before_stops_on_a_database_stepped_past_19")
FROM_ANY = schema("test_a_database_stepped_from_any_version_has_what_every_later_step_makes")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── The door: which channel, and which device ──
    ("D01 a channel dropped or moved from is taken from", SHARED,
     '''    if row.state != State::Held {
        return Ok(None);
    }
    let refused''',
     '''    let refused''',
     [DOOR]),
    ("D02 a shared channel is tried nowhere", TAKE,
     '''            None => crate::shared::taken_as_shared(conn, entry, now)?,''',
     '''            None => None,''',
     [DOOR, OUTSIDE]),
    ("D03 a device that has stopped takes a shared channel's entries", SHARED,
     '''    if held.state != HeldState::Applied {''',
     '''    if held.state == HeldState::Fork {''',
     [DOOR]),
    ("D04 sync off takes a shared channel's entries", SHARED,
     '''    if meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_none() {''',
     '''    if meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_none() && false {''',
     [DOOR]),
    # ── The door: rule 3, before anything is stored ──
    ("D05 a delete is stored", SHARED,
     '''    if entry.delete {''',
     '''    if entry.delete && false {''',
     [OUTSIDE]),
    ("D06 an entry in a slot of none of its author's is stored", SHARED,
     '''    let Some(kind) = slot_of(&slot_key, &entry.author, &entry.slot)? else {
        return refused(NotTaken::NotAShared);
    };''',
     '''    let kind = slot_of(&slot_key, &entry.author, &entry.slot)?.unwrap_or(SlotOf::Message);''',
     [OUTSIDE, ANOTHER]),
    ("D07 the last slot of the ring is not its author's", SHARED,
     '''    for n in 0..AGENT_MESSAGE_RING as u64 {''',
     '''    for n in 0..AGENT_MESSAGE_RING as u64 - 1 {''',
     [OUTSIDE]),
    ("D08 an entry of another size than its slot's is stored", SHARED,
     '''    if entry.content.len() != kind.content_bytes() {''',
     '''    if entry.content.len() != kind.content_bytes() && false {''',
     [OUTSIDE]),
    ("D09 an anew record is of a message's size", SHARED,
     '''            SlotOf::Anew => SHARED_ANEW_CONTENT_BYTES,''',
     '''            SlotOf::Anew => AGENT_MESSAGE_CONTENT_BYTES,''',
     [OUTSIDE, QUIET]),
    ("D10 the half of band 0 is taken", SHARED,
     '''    if entry.rev >= REV_BAND_HALF {''',
     '''    if entry.rev > REV_BAND_HALF {''',
     [OUTSIDE]),
    ("D11 no revision is refused", SHARED,
     '''    if entry.rev >= REV_BAND_HALF {''',
     '''    if entry.rev >= REV_BAND_HALF && false {''',
     [OUTSIDE]),
    # ── The door: rule 4, the room ──
    ("D12 no key is known to the room", SHARED,
     '''    let known = knows.knows(&entry.author);''',
     '''    let known = knows.knows(&entry.author) && false;''',
     [BLIND, COMES]),
    ("D13 an entry at a let-go key's kept revision is stored", SHARED,
     '''        if kept_rev.is_some_and(|kept_rev| entry.rev <= kept_rev) {''',
     '''        if kept_rev.is_some_and(|kept_rev| entry.rev < kept_rev) {''',
     [QUIET]),
    ("D14 a let-go key's kept revisions refuse nothing", SHARED,
     '''        if kept_rev.is_some_and(|kept_rev| entry.rev <= kept_rev) {''',
     '''        if kept_rev.is_some_and(|kept_rev| entry.rev <= kept_rev) && false {''',
     [QUIET]),
    ("D15 the entry that fills the room to its last byte is refused", SHARED,
     '''            && kept::room(conn, row.id)? + cost > MAX_ENTRY_CHANNEL_BYTES_AT_RELAY''',
     '''            && kept::room(conn, row.id)? + cost >= MAX_ENTRY_CHANNEL_BYTES_AT_RELAY''',
     [FULL]),
    ("D16 a slot written again is refused for room", SHARED,
     '''        if held_there.is_none()
            && kept::room''',
     '''        if true
            && kept::room''',
     [FULL]),
    ("D17 nothing is refused for room", SHARED,
     '''            && kept::room(conn, row.id)? + cost > MAX_ENTRY_CHANNEL_BYTES_AT_RELAY''',
     '''            && kept::room(conn, row.id)? + cost > u64::MAX - 1''',
     [BLIND, DELETES, TABLE, FULL]),
    ("D18 a refusal for room is not noted", SHARED,
     '''            kept::refused(conn, row.id, &entry.author, cost, now)?;''',
     '''            let _ = cost;''',
     [BLIND, DELETES, TABLE]),
    ("D19 the rows that store nothing are not kept within their bound at a refusal", SHARED,
     '''            kept::keep_rows_within(conn, row.id, SHARED_KEYS_KEPT)?;
            return refused(NotTaken::SharedFull);''',
     '''            return refused(NotTaken::SharedFull);''',
     [TABLE]),
    ("D20 what is stored is not counted", SHARED,
     '''    kept::stored(conn, row.id, &entry.author, known, more, now)?;''',
     '''    kept::stored(conn, row.id, &entry.author, known, more & 0, now)?;''',
     [TABLE, FULL, OUTSIDE]),
    ("D21 an entry of a key beyond the 64 is opened", SHARED,
     '''    let read = if shown.iter().any(|key| key.key == entry.author) {''',
     '''    let read = if !shown.is_empty() {''',
     [SHOWS, QUIET]),
    # ── Who the person knows, and who is shown ──
    ("K01 the person's own devices are in the order of their additions first", SHARED,
     '''        for key in listed.chain(additions.iter().map(|record| record.key)) {''',
     '''        for key in additions.iter().map(|record| record.key).chain(listed) {''',
     [SHOWS]),
    ("K02 a label removed still makes a key known", SHARED,
     '''            .filter(|(act, maker)| maker.in_force() && act.item.label.is_some())''',
     '''            .filter(|(_, maker)| maker.in_force())''',
     [STOPS]),
    ("K03 a label of a maker in no list makes a key known", SHARED,
     '''            .filter(|(act, maker)| maker.in_force() && act.item.label.is_some())''',
     '''            .filter(|(act, _)| act.item.label.is_some())''',
     [NO_LIST]),
    ("K04 labels are not in the order they were made", SHARED,
     '''        labels.sort_by_key(|act| (act.time, act.count, act.maker));''',
     '''        labels.sort_by_key(|act| act.item.key);''',
     [SHOWS]),
    ("K05 a removed key labelled is known", SHARED,
     '''            .filter(|key| !removed.contains(key))''',
     '''            .filter(|_| true)''',
     [STOPS]),
    ("K06 a label makes no key known", SHARED,
     '''        self.counting.counts(key) || self.labels.contains(key)''',
     '''        self.counting.counts(key)''',
     [BLIND]),
    ("K07 the person's own devices are not known", SHARED,
     '''        self.counting.counts(key) || self.labels.contains(key)''',
     '''        self.labels.contains(key)''',
     [BLIND]),
    ("K08 65 keys are shown", SHARED,
     '''            if shown.len() == SHARED_MAX_KEYS {''',
     '''            if shown.len() == SHARED_MAX_KEYS + 1 {''',
     [SHOWS]),
    ("K09 a removed key is shown", SHARED,
     '''            if !shown.contains(key) && !self.removed.contains(key) {''',
     '''            if !shown.contains(key) {''',
     [STOPS]),
    ("K10 every key shown is in the unlabelled hour", SHARED,
     '''                unlabelled: !self.knows(&key),''',
     '''                unlabelled: true,''',
     [SHOWS]),
    ("K11 the person's own devices are shown before the labelled keys", SHARED,
     '''        for key in self.labels.iter().chain(&self.devices).chain(&others) {''',
     '''        for key in self.devices.iter().chain(&self.labels).chain(&others) {''',
     [SHOWS]),
    ("K12 a key that stores nothing takes a place in the order", STORE,
     '''             WHERE channel = ?1 AND held_order IS NOT NULL AND bytes_stored > 0''',
     '''             WHERE channel = ?1 AND held_order IS NOT NULL''',
     [QUIET]),
    ("K13 the keys first held last are shown first", STORE,
     '''             ORDER BY held_order LIMIT ?2",''',
     '''             ORDER BY held_order DESC LIMIT ?2",''',
     [SHOWS]),
    ("K14 a key that writes again takes a new place in the order", STORE,
     '''             held_order = COALESCE(held_order, excluded.held_order),''',
     '''             held_order = excluded.held_order,''',
     [SHOWS]),
    # ── The reader ──
    ("R01 a message in the slot of another number is read", SHARED,
     '''        && entry.slot == slot_id(&slot_key, &message_name(&signer, number)?);''',
     '''        && entry.slot != [0; 32];''',
     [RING]),
    ("R02 a number that is not live is opened", SHARED,
     '''    if in_its_slot && !kept::hold_number(conn, row.id, &signer, number, clearing)? {''',
     '''    if in_its_slot && !(kept::hold_number(conn, row.id, &signer, number, clearing)? || true) {''',
     [RING]),
    ("R03 what is no message is not counted", SHARED,
     '''        kept::not_a_message(conn, row.id, &signer)?;
        Ok(Read::NotAMessage(why))''',
     '''        Ok(Read::NotAMessage(why))''',
     [RING]),
    ("R04 what does not open is not counted", SHARED,
     '''        kept::not_a_message(conn, row.id, &signer)?;
        return Ok(Read::DidNotOpen);''',
     '''        return Ok(Read::DidNotOpen);''',
     [RING]),
    ("R05 a message's ID does not bind its signer", SHARED,
     '''            let id = message_id(&signer, value);''',
     '''            let id = message_id(&[0; 32], value);''',
     [RING]),
    ("R06 a clearing drops nothing", SHARED,
     '''            dropped: kept::clear(conn, row.id, &signer, number, now)?,''',
     '''            dropped: false,''',
     [TWO]),
    ("R07 a clearing at a number that is not live is counted as overwritten", SHARED,
     '''    let clearing = entry.rev % 2 == 1;''',
     '''    let clearing = false;''',
     [RING]),
    ("R08 a message that leaves the ring keeps its row", STORE,
     '''        if held == 0 {
            drop_row(conn, id, &message)?;''',
     '''        if held == 0 && false {
            drop_row(conn, id, &message)?;''',
     [RING]),
    # ── The index ──
    ("I01 a message taken out and read again is not read again", STORE,
     '''        Some((Some(held), true)) if held == id[..] && !in_index => {''',
     '''        Some((Some(held), true)) if held == id[..] && !in_index && false => {''',
     [STOPS]),
    ("I02 a message taken out is not marked so", STORE,
     '''        "UPDATE shared_first_held AS f SET taken_out = 1,''',
     '''        "UPDATE shared_first_held AS f SET taken_out = 0,''',
     [STOPS]),
    ("I03 a message read again is shown as new", STORE,
     '''            let (first_held, placed_at) = taken_out_at(conn, channel, id)?;
            (first_held, placed_at, Indexed::Again)
        }
        Some(_) => return Ok(Indexed::NotAgain),''',
     '''            let (_, placed_at) = taken_out_at(conn, channel, id)?;
            (opened.first_held, placed_at, Indexed::Again)
        }
        Some(_) => return Ok(Indexed::NotAgain),''',
     [STOPS]),
    ("I04 one signer has as many places in an hour as it likes", STORE,
     '''            usize::try_from(RING - placed(Some(&key.key))?).unwrap_or(0)''',
     '''            usize::MAX''',
     [SIGNER]),
    ("I05 the keys unlabelled have as many places in an hour as they like", STORE,
     '''    let mut pool_room = usize::try_from(RING - placed(None)?).unwrap_or(0);''',
     '''    let mut pool_room = usize::MAX;''',
     [SHOWS]),
    ("I06 the unlabelled hour gives the oldest first", STORE,
     '''    pooled.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));''',
     '''    pooled.sort_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(&b.0)));''',
     [SHOWS]),
    ("I07 a message of a key not shown is shown", STORE,
     '''        .filter(|row| shown.contains(&row.signer))''',
     '''        .filter(|_| true)''',
     [STOPS]),
    ("I08 a message is kept a moment past its 30 days", STORE,
     '''    for (channel, id) in ids(format!("{now} >= {}", expires_sql()))? {''',
     '''    for (channel, id) in ids(format!("{now} > {}", expires_sql()))? {''',
     [EXPIRES]),
    ("I09 a row that goes is not overwritten first", STORE,
     '''             body = zeroblob(length(CAST(body AS BLOB))),''',
     '''             body = body,''',
     [EXPIRES]),
    ("I10 the hourly task drops nothing of the index", SHARED,
     '''        done.gone = kept::drop_gone(conn, now)?;''',
     '''        done.gone = 0;''',
     [EXPIRES]),
    ("I11 the node's hourly task does not run the shared channels' part", READER,
     '''    if let Err(e) = crate::shared::hourly(conn, now) {''',
     '''    if let Err(e) = crate::shared::hourly(conn, 0) {''',
     [EXPIRES]),
    ("I12 a channel moved from shows nothing", SHARED,
     '''        if row.state == State::Moved {''',
     '''        if row.state == State::Moved && false {''',
     [DROP]),
    # ── The table of shared channels follows the lists ──
    ("C01 an act holds no channel", LISTS,
     '''        crate::shared::keep(conn, now)?;
        Ok(Done::Made(made))''',
     '''        Ok(Done::Made(made))''',
     [FOLLOWS, DOOR, DROP]),
    ("C02 a whole fetch holds no channel", LISTS,
     '''        crate::shared::keep(conn, now)?;
        Ok(wrote)''',
     '''        Ok(wrote)''',
     [FOLLOWS]),
    ("C03 a filing not in force holds a channel", SHARED,
     '''    let filed: Vec<_> = holds
        .filings
        .iter()
        .filter(|(_, maker)| maker.in_force())''',
     '''    let filed: Vec<_> = holds
        .filings
        .iter()
        .filter(|_| true)''',
     [NO_LIST]),
    ("C04 a channel filed by no act in force stays held", SHARED,
     '''                kept::set_state(conn, row.id, State::NotInForce, now)?;''',
     '''                let _ = State::NotInForce;''',
     [NO_LIST]),
    ("C05 a drop keeps the channel's entries", SHARED,
     '''                entries::remove_channel(conn, &row.channel)?;
                let state''',
     '''                let state''',
     [DROP]),
    ("C06 a move is a drop", SHARED,
     '''                let state = if moved { State::Moved } else { State::Dropped };''',
     '''                let state = if moved && false { State::Moved } else { State::Dropped };''',
     [DROP]),
    ("C07 a move takes its index", SHARED,
     '''                kept::drop_rows(conn, row.id, moved)?;''',
     '''                kept::drop_rows(conn, row.id, false)?;''',
     [DROP]),
    ("C08 a drop keeps its index", STORE,
     '''    if !index_stays {''',
     '''    if !index_stays && false {''',
     [DROP]),
    ("C09 a drop keeps its table of keys", STORE,
     '''    for table in ["shared_keys", "shared_unopened"] {''',
     '''    for table in ["shared_unopened"] {''',
     [DROP]),
    ("C10 a freed drop keeps the seed", SHARED,
     '''            kept::forget(conn, row.id)?;''',
     '''            let _ = row.id;''',
     [DROP]),
    ("C11 the index stays for 17 channels moved from", SHARED,
     '''    for older in moved.iter().skip(SHARED_MAX_CHANNELS) {''',
     '''    for older in moved.iter().skip(SHARED_MAX_CHANNELS + 1) {''',
     [DROP]),
    ("C12 the channels moved from first keep their index", SHARED,
     '''    moved.sort_by_key(|row| std::cmp::Reverse((row.left_at, row.id)));''',
     '''    moved.sort_by_key(|row| (row.left_at, row.id));''',
     [DROP]),
    ("C13 a device that leaves keeps its shared channels", LEAVING,
     '''        cordelia_storage::shared::forget_all(conn)?;''',
     '''        let _ = cordelia_storage::shared::forget_all;''',
     [FORGETS]),
    ("C14 a device that leaves keeps the entries of its shared channels", LEAVING,
     '''        for row in cordelia_storage::shared::channels(conn)? {
            entries::remove_channel(conn, &row.channel)?;
        }''',
     '''        let _ = cordelia_storage::shared::channels;''',
     [FORGETS]),
    # ── Who is known, as it changes ──
    ("W01 a key that stops being known is not counted in the room", SHARED,
     '''        kept::set_known(conn, row.id, &key.key, known, now)?;''',
     '''        let _ = known;''',
     [STOPS]),
    ("W02 a key with bytes refused that comes to count is not read again", SHARED,
     '''        if known && key.bytes_refused > 0 {''',
     '''        if known && key.bytes_refused > 0 && false {''',
     [COMES]),
    ("W03 a statement applied keeps nothing", TAKE,
     '''            Some(Taken::Shown(Shown::Applied(_)))''',
     '''            Some(Taken::Shown(Shown::Held))''',
     [STOPS, NO_LIST]),
    ("W04 a key that came to count keeps nothing", TAKE,
     '''                    came_to_count: 1..,''',
     '''                    came_to_count: 1_000_000..,''',
     [COMES]),
    ("W05 the room is never brought down", SHARED,
     '''    if room > MAX_ENTRY_CHANNEL_BYTES_AT_RELAY {''',
     '''    if room > u64::MAX - 1 {''',
     [STOPS]),
    ("W06 the keys that stopped being known last go first", SHARED,
     '''                key.unknown_since,
                std::cmp::Reverse(key.held_order),''',
     '''                std::cmp::Reverse(key.unknown_since),
                std::cmp::Reverse(key.held_order),''',
     [STOPS]),
    ("W07 the keys never known go before those that stopped being known", SHARED,
     '''                key.unknown_since.is_none(),''',
     '''                key.unknown_since.is_some(),''',
     [STOPS]),
    ("W08 of keys that stopped at once, the first held first goes", SHARED,
     '''                key.unknown_since,
                std::cmp::Reverse(key.held_order),''',
     '''                key.unknown_since,
                key.held_order,''',
     [STOPS]),
    ("W09 what goes when a key stops being known is not noted as refused", SHARED,
     '''            let gone = kept::take_out(conn, row.id, &row.channel, &key.key, &anew_slot, true, now)?;''',
     '''            let gone = kept::take_out(conn, row.id, &row.channel, &key.key, &anew_slot, false, now)?;''',
     [STOPS]),
    ("W10 a label asks no read again", SHARED,
     '''            if newly_labelled {''',
     '''            if newly_labelled && false {''',
     [TABLE]),
    ("W11 the labels seen are not kept", SHARED,
     '''        kept::set_labelled(conn, &labelled)?;''',
     '''        let _ = &labelled;''',
     [BLIND]),
    ("W12 what waits of a key now shown is never opened", SHARED,
     '''            open_shown(conn, &knows, &row, now)?;''',
     '''            let _ = &knows;''',
     [SHOWS]),
    # ── The hourly task: a quiet key ──
    ("H01 a key is let go a moment after its 30 days", SHARED,
     '''                .filter(|key| key.last_held.is_some_and(|last| now - last >= KEPT_SECS))''',
     '''                .filter(|key| key.last_held.is_some_and(|last| now - last > KEPT_SECS))''',
     [QUIET]),
    ("H02 a key the person knows is let go as quiet", SHARED,
     '''                .filter(|key| !key.known && key.bytes_stored > 0)
                .filter(|key| key.last_held''',
     '''                .filter(|key| key.bytes_stored > 0)
                .filter(|key| key.last_held''',
     [EXPIRES]),
    ("H03 no quiet key is let go", SHARED,
     '''                .filter(|key| key.last_held.is_some_and(|last| now - last >= KEPT_SECS))''',
     '''                .filter(|key| key.last_held.is_some_and(|last| now - last >= KEPT_SECS) && false)''',
     [QUIET, DELETES, DAILY]),
    ("H04 room made asks no read again", SHARED,
     '''            if keys.iter().any(|key| key.bytes_refused > 0) {''',
     '''            if keys.iter().any(|key| key.bytes_refused > 0) && false {''',
     [QUIET, DELETES, DAILY]),
    ("H05 a quiet key's bytes are noted as refused", SHARED,
     '''                kept::take_out(conn, row.id, &row.channel, &key.key, &anew_slot, false, now)?;''',
     '''                kept::take_out(conn, row.id, &row.channel, &key.key, &anew_slot, true, now)?;''',
     [QUIET]),
    ("H06 what waits of a key shown in a let-go key's place is not opened", SHARED,
     '''        if done.let_go > 0 {''',
     '''        if done.let_go > 0 && false {''',
     [QUIET]),
    # ── Reading again ──
    ("A01 a read again begins a moment after its day", STORE,
     '''               AND (read_begun IS NULL OR ?1 - read_begun >= ?2)''',
     '''               AND (read_begun IS NULL OR ?1 - read_begun > ?2)''',
     [DAILY]),
    ("A02 a read again begins more than once a day", STORE,
     '''               AND (read_begun IS NULL OR ?1 - read_begun >= ?2)''',
     '''               AND (read_begun IS NULL OR ?2 >= 0)''',
     [DAILY]),
    ("A03 a read again begun is still asked", STORE,
     '''        "UPDATE shared_channels SET read_asked = NULL, read_begun = ?2 WHERE id = ?1",''',
     '''        "UPDATE shared_channels SET read_begun = ?2 WHERE id = ?1",''',
     [DAILY]),
    ("A04 a channel dropped or moved from is read again", STORE,
     '''             WHERE state = 1 AND read_asked IS NOT NULL''',
     '''             WHERE read_asked IS NOT NULL''',
     [DROP]),
    # ── The table of keys ──
    ("T01 the room counts nothing stored", STORE,
     '''    if !key_known(conn, id, key)? {''',
     '''    if !key_known(conn, id, key)? && false {''',
     [TABLE, FULL]),
    ("T02 a key that comes to be known stays in the room", STORE,
     '''        add_to_room(conn, id, -to_sql(row.bytes_stored))?;''',
     '''        let _ = row.bytes_stored;''',
     [TABLE]),
    ("T03 a key that stops being known joins no room", STORE,
     '''        add_to_room(conn, id, to_sql(row.bytes_stored))?;''',
     '''        let _ = row.bytes_stored;''',
     [STOPS]),
    ("T04 a key taken out keeps its entries", STORE,
     '''        "DELETE FROM entries WHERE channel_id = ?1 AND author = ?2",''',
     '''        "DELETE FROM entries WHERE channel_id = ?1 AND author = ?2 AND 0",''',
     [QUIET, STOPS]),
    ("T05 a let-go row keeps no revision of its ring", STORE,
     '''             kept_message_rev = MAX(COALESCE(kept_message_rev, 0), COALESCE(?3, 0)),''',
     '''             kept_message_rev = kept_message_rev,''',
     [STOPS]),
    ("T06 a let-go row keeps no revision of its anew record", STORE,
     '''             kept_anew_rev = MAX(COALESCE(kept_anew_rev, 0), COALESCE(?4, 0)),''',
     '''             kept_anew_rev = kept_anew_rev,''',
     [QUIET]),
    ("T07 the rows refused most lately go first", STORE,
     '''                 ORDER BY last_seq DESC LIMIT -1 OFFSET ?2)",''',
     '''                 ORDER BY last_seq ASC LIMIT -1 OFFSET ?2)",''',
     [TABLE]),
    ("T08 the rows let go are not counted", STORE,
     '''            "UPDATE shared_channels SET let_go = let_go + ?2 WHERE id = ?1",''',
     '''            "UPDATE shared_channels SET let_go = let_go + 0 * ?2 WHERE id = ?1",''',
     [TABLE]),
    ("T09 a row of a key that stores an entry is let go", STORE,
     ['''"DELETE FROM shared_keys WHERE channel = ?1 AND bytes_stored = 0 AND key IN (''',
      '''                 SELECT key FROM shared_keys WHERE channel = ?1 AND bytes_stored = 0
                 ORDER BY last_seq'''],
     ['''"DELETE FROM shared_keys WHERE channel = ?1 AND key IN (''',
      '''                 SELECT key FROM shared_keys WHERE channel = ?1
                 ORDER BY last_seq'''],
     [TABLE]),
    ("T10 the bytes refused are the last refusal's alone", STORE,
     '''             bytes_refused = bytes_refused + excluded.bytes_refused",''',
     '''             bytes_refused = excluded.bytes_refused",''',
     [BLIND]),
    ("T11 a key is first refused at its last refusal", STORE,
     '''             first_refused = COALESCE(first_refused, excluded.first_refused),''',
     '''             first_refused = excluded.first_refused,''',
     [BLIND]),
    ("T12 a key that writes again is not first held then", STORE,
     '''             last_held = excluded.last_held, last_seq = excluded.last_seq,''',
     '''             last_seq = excluded.last_seq,''',
     [QUIET]),
    # ── Schema step 21 ──
    ("S01 the schema is still at step 20", SCHEMA,
     '''pub const SCHEMA_VERSION: u32 = 21;''',
     '''pub const SCHEMA_VERSION: u32 = 20;''',
     [STEP]),
    ("S02 step 21 is not run", SCHEMA,
     '''        migrate_in_one(conn, MIGRATION_V21, 21)?;''',
     '''        let _ = MIGRATION_V21;''',
     [STEP, FROM_ANY]),
    ("S03 a card of three relays' length is kept", SCHEMA,
     '''    card        BLOB NOT NULL CHECK(typeof(card) = 'blob' AND length(card) IN (65, 97)),''',
     '''    card        BLOB NOT NULL CHECK(typeof(card) = 'blob' AND length(card) IN (65, 97, 98)),''',
     [STEP, STEP_BOUNDS]),
    ("S04 a name may be longer than a name", SCHEMA,
     '''                                    AND length(CAST(name AS BLOB)) <= 200),''',
     '''                                    AND length(CAST(name AS BLOB)) <= 201),''',
     [STEP, STEP_BOUNDS]),
    ("S05 a revision kept may be at the half of band 0", SCHEMA,
     '''                                        AND kept_message_rev < 8796093022208)),''',
     '''                                        AND kept_message_rev <= 8796093022208)),''',
     [STEP, STEP_BOUNDS]),
    ("S06 a number held may be past the highest", SCHEMA,
     '''                                    AND number >= 1 AND number <= 4398046511103),
    id       BLOB NOT NULL,''',
     '''                                    AND number >= 1 AND number <= 4398046511104),
    id       BLOB NOT NULL,''',
     [STEP, STEP_BOUNDS]),
    ("S07 a number held needs no message in the index", SCHEMA,
     '''    FOREIGN KEY (channel, id) REFERENCES shared_index(channel, id) ON DELETE CASCADE,''',
     '''''',
     [STEP]),
    ("S08 a row of first holding keeps a place it was not taken out with", SCHEMA,
     '''                              OR (typeof(placed_at) = 'integer' AND taken_out = 1)),''',
     '''                              OR typeof(placed_at) = 'integer'),''',
     [STEP]),
    ("S09 a channel that came by a key names none", SCHEMA,
     '''    came_from   BLOB CHECK((came = 1) = (came_from IS NULL)''',
     '''    came_from   BLOB CHECK(1''',
     [STEP]),
    ("S10 a key's row says neither when it was held nor when refused", SCHEMA,
     '''    CHECK(first_held IS NOT NULL OR first_refused IS NOT NULL),''',
     '''''',
     [STEP]),
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
