#!/usr/bin/env python3
"""Mutation checks for the sender's core of messages between the person's
own agents (decision 2026-10-09 §2.3, §2.4 for a message's own entry, §6,
§7.1 and the sender's half of §9.1): the next number, the checks of a
send in their order, the rates and the hold, the index row written with
the entry, the kept value and sending again, and the clearing of the
hourly task. A part for each rule of the slice: put each fault in, and
confirm the test named for it fails on an assertion. Run from the root of
a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
SENDER = 'crates/cordelia-api/src/sender.rs'
READER = 'crates/cordelia-api/src/reader.rs'
AT_RELAYS = 'crates/cordelia-api/src/at_relays.rs'
HELD = 'crates/cordelia-storage/src/messages.rs'
DEVICE = 'crates/cordelia-node/src/device_entries.rs'
PROTOCOL = 'crates/cordelia-core/src/protocol.rs'
ORIG = {f: open(f).read() for f in (SENDER, READER, AT_RELAYS, HELD, DEVICE, PROTOCOL)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
NODE = ("cordelia-node", ["--lib"])
E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
def api(test): return (API, "sender::tests::" + test)
def at_relays(test): return (API, "at_relays::tests::" + test)
def node(test): return (NODE, "device_entries::tests::" + test)
def e2e(test): return (E2E, test)
def reader(test): return (API, "reader::tests::" + test)

ORDER = api("the_senders_checks_are_made_in_the_order_of_the_record")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── The checks, in their order (§4.3, D5) ─────────────────────────
    ("S01 a device that does not stand applied sends", SENDER,
     '''    if stands(conn)? != Stands::Applied {
        return refused(Refused::NotApplied);''',
     '''    if stands(conn)? == Stands::NoPhrase {
        return refused(Refused::NotApplied);''',
     [ORDER]),
    ("S02 a device with sync off sends", SENDER,
     '''        .is_none()
    {
        return refused(Refused::SyncOff);''',
     '''        .is_some_and(|_| false)
    {
        return refused(Refused::SyncOff);''',
     [ORDER]),
    ("S03 a device with no place for messages sends", SENDER,
     '''    if at.no_place {''',
     '''    if at.no_place && at.now < 0 {''',
     [ORDER]),
    ("S04 a folder whose rate is 0 is refused for its rate instead", SENDER,
     '''    if folder_limit == 0 {''',
     '''    if folder_limit == 0 && at.now < 0 {''',
     [ORDER, api("a_folder_whose_rate_is_0_sends_nothing")]),
    ("S05 the configuration raises the folder's rate", SENDER,
     '''        .min(AGENT_MESSAGES_PER_FOLDER_PER_HOUR);''',
     '''        .min(usize::MAX);''',
     [api("a_folder_over_its_hour_sends_nothing_more")]),
    ("S06 a device sends before its first fetch", SENDER,
     '''    if !at.fetched {''',
     '''    if !at.fetched && at.now < 0 {''',
     [ORDER, api("the_first_send_after_a_start_waits_for_the_ring_to_be_fetched")]),
    ("S07 the next number goes past the highest", SENDER,
     '''    Ok(message::next_number(highest))''',
     '''    Ok(Some(highest + 1))''',
     [api("a_device_sends_nothing_past_the_highest_number")]),
    ("S08 the next number passes over clearings", SENDER,
     '''        .map(|(_, entry)| number_of(entry.rev))''',
     '''        .filter(|(_, entry)| entry.rev % 2 == 0)
        .map(|(_, entry)| number_of(entry.rev))''',
     [api("the_next_message_goes_above_every_number_the_device_holds_clearing_included")]),
    ("S09 the next number is read from the slots of another key", SENDER,
     '''            if let Some(stored) = entries::author_entry(conn, &self.channel, &slot, &self.own)? {''',
     '''            if let Some(stored) = entries::slot_stored(conn, &self.channel, &slot)?.pop() {''',
     [api("the_next_message_goes_above_every_number_the_device_holds_clearing_included")]),
    ("S10 a clock behind its newest sent sends", SENDER,
     '''.is_some_and(|newest| newest > now) {''',
     '''.is_some_and(|newest| newest > now + 1_000_000) {''',
     [ORDER, api("a_sender_whose_clock_is_behind_its_newest_sent_sends_nothing")]),
    ("S11 a row far ahead of the clock locks sending out", HELD,
     '''        params![&own[..], now.saturating_add(ahead)],''',
     '''        params![&own[..], now.saturating_add(ahead * 1000)],''',
     [api("a_clock_that_was_ahead_for_a_moment_does_not_lock_sending_out")]),
    ("S12 a row 600 seconds ahead is passed over", HELD,
     '''"SELECT MAX(sent) FROM message_index WHERE signer = ?1 AND sent <= ?2",''',
     '''"SELECT MAX(sent) FROM message_index WHERE signer = ?1 AND sent < ?2",''',
     [api("a_clock_that_was_ahead_for_a_moment_does_not_lock_sending_out")]),
    ("S13 another device's sent holds this clock back", HELD,
     '''"SELECT MAX(sent) FROM message_index WHERE signer = ?1 AND sent <= ?2",''',
     '''"SELECT MAX(sent) FROM message_index WHERE signer = ?1 OR sent <= ?2",''',
     [api("a_sender_whose_clock_is_behind_its_newest_sent_sends_nothing")]),
    ("S14 a name the personal channel does not list is taken", SENDER,
     '''            .any(|listed| listed.name == *name)''',
     '''            .any(|_| true)''',
     [ORDER]),
    # ── The rates (§6, C10) ───────────────────────────────────────────
    ("S15 the 21st of a folder goes", SENDER,
     '''    if lately.by_folder.len() >= folder_limit {''',
     '''    if lately.by_folder.len() > folder_limit {''',
     [api("a_folder_over_its_hour_sends_nothing_more")]),
    ("S16 every folder's sends count as one folder's", HELD,
     '''                if name == folder {''',
     '''                if name == folder || !name.is_empty() {''',
     [api("a_folder_over_its_hour_sends_nothing_more")]),
    ("S17 the time the next can go is a second late", SENDER,
     '''    times.get(leaves).map_or(0, |at| at + HOUR_SECS)''',
     '''    times.get(leaves).map_or(0, |at| at + HOUR_SECS + 1)''',
     [api("a_folder_over_its_hour_sends_nothing_more")]),
    ("S18 the 61st of a device goes", SENDER,
     '''    if all.len() < AGENT_MESSAGES_PER_DEVICE_PER_HOUR {''',
     '''    if all.len() <= AGENT_MESSAGES_PER_DEVICE_PER_HOUR {''',
     [api("a_device_over_its_hour_sends_nothing_more_and_every_name_counts_once")]),
    ("S19 sends again are not counted in the device's hour", SENDER,
     '''lately.sends.iter().chain(&lately.again)''',
     '''lately.sends.iter().chain(lately.again.iter().take(0))''',
     [api("the_device_rate_line_counts_sends_again_apart"),
      api("a_message_that_waits_to_be_sent_again_waits_for_the_first_fetch_and_the_hour")]),
    ("S20 sends again are counted as sends", HELD,
     '''            None => lately.again.push(at),''',
     '''            None => lately.sends.push(at),''',
     [api("the_device_rate_line_counts_sends_again_apart")]),
    ("S21 a clock that went back frees the hour", HELD,
     '''"SELECT sent_at, name FROM message_sends WHERE sent_at > ?1 ORDER BY sent_at"''',
     '''"SELECT sent_at, name FROM message_sends WHERE sent_at > ?1 AND sent_at <= ?1 + 3600 ORDER BY sent_at"''',
     [api("the_hour_frees_by_the_devices_own_record_and_a_clock_that_went_back_does_not_free_it")]),
    ("S22 the hour is a second longer", HELD,
     '''        .query_map([now - HOUR_SECS], |row| Ok((row.get(0)?, row.get(1)?)))?''',
     '''        .query_map([now - HOUR_SECS - 1], |row| Ok((row.get(0)?, row.get(1)?)))?''',
     [api("the_hour_frees_by_the_devices_own_record_and_a_clock_that_went_back_does_not_free_it")]),
    ("S23 the record of sends is kept past its hour", HELD,
     '''        "DELETE FROM message_sends WHERE sent_at <= ?1",''',
     '''        "DELETE FROM message_sends WHERE sent_at < ?1",''',
     [api("the_hour_frees_by_the_devices_own_record_and_a_clock_that_went_back_does_not_free_it")]),
    ("S24 a send writes no row of the folder", SENDER,
     '''        Some(&request.from),
        to == To::All,''',
     '''        Some("another folder"),
        to == To::All,''',
     [api("a_folder_over_its_hour_sends_nothing_more")]),
    ("S25 a send again writes no row", SENDER,
     '''            kept(held::record_send(conn, now, None, false))?;''',
     '''            let _ = held::record_send;''',
     [api("a_relay_that_answers_falsely_makes_a_message_go_under_at_most_four_numbers"),
      api("a_message_that_a_relay_holds_another_entry_for_is_sent_again_under_the_next_number")]),
    # ── The hold (§6, C8, D6, F2) ─────────────────────────────────────
    ("S26 the hold is at eleven", SENDER,
     '''    let held = |count: u64| count >= AGENT_MESSAGE_PAIR_UNREAD_MAX as u64;''',
     '''    let held = |count: u64| count > AGENT_MESSAGE_PAIR_UNREAD_MAX as u64;''',
     [api("the_hold_is_by_the_pair_of_agents_and_every_name_is_a_pair_of_its_own")]),
    ("S27 the hold is in one direction only", HELD,
     '''            Some(_) => (false, from),''',
     '''            Some(_) => continue,''',
     [api("the_hold_is_by_the_pair_of_agents_and_every_name_is_a_pair_of_its_own")]),
    ("S28 every name is no pair", HELD,
     '''            None if from == name => (true, String::new()),''',
     '''            None if from == name => continue,''',
     [api("the_hold_is_by_the_pair_of_agents_and_every_name_is_a_pair_of_its_own")]),
    ("S29 every name is refused only by its own pair", SENDER,
     '''            .find(|(_, count)| held(*count))''',
     '''            .find(|(other, count)| other.is_none() && held(*count))''',
     [api("the_hold_is_by_the_pair_of_agents_and_every_name_is_a_pair_of_its_own")]),
    ("S30 messages held back make a hold", HELD,
     '''            "SELECT i.from_name, i.to_name FROM message_index i
             WHERE i.placed_at IS NOT NULL AND ?1 < {expires} AND {live}''',
     '''            "SELECT i.from_name, i.to_name FROM message_index i
             WHERE ?1 < {expires} AND {live}''',
     [api("held_back_messages_make_no_hold")]),
    ("S31 expired messages hold", HELD,
     '''            "SELECT i.from_name, i.to_name FROM message_index i
             WHERE i.placed_at IS NOT NULL AND ?1 < {expires} AND {live}''',
     '''            "SELECT i.from_name, i.to_name FROM message_index i
             WHERE i.placed_at IS NOT NULL AND ?1 < {expires} + 1000000000 AND {live}''',
     [api("a_hold_ends_when_its_messages_expire_or_stop_being_live")]),
    ("S32 messages no longer live hold", HELD,
     '''            "SELECT i.from_name, i.to_name FROM message_index i
             WHERE i.placed_at IS NOT NULL AND ?1 < {expires} AND {live}''',
     '''            "SELECT i.from_name, i.to_name FROM message_index i
             WHERE i.placed_at IS NOT NULL AND ?1 < {expires} AND ({live} OR 1 = 1)''',
     [api("a_hold_ends_when_its_messages_expire_or_stop_being_live")]),
    ("S33 what a person read still holds", HELD,
     '''               AND NOT EXISTS (SELECT 1 FROM message_read_by_a_person p WHERE p.id = i.id)''',
     '''               AND 1 = 1''',
     [api("the_hold_is_by_the_pair_of_agents_and_every_name_is_a_pair_of_its_own"),
      api("held_back_messages_make_no_hold")]),
    # ── The message, written and indexed at once (§2.3, F9) ───────────
    ("S34 the device's own message has no place when written", SENDER,
     '''        placed_at: Some(now),''',
     '''        placed_at: None,''',
     [api("a_devices_own_send_is_in_its_index_when_written")]),
    ("S35 the device's own message is not indexed when written", SENDER,
     '''    kept(held::index(conn, &opened))?;''',
     '''    let _ = &opened;''',
     [api("a_devices_own_send_is_in_its_index_when_written")]),
    ("S36 H is not raised by the device's own message", SENDER,
     '''    kept(held::hold_number(
        conn, &ring.own, generation, number, false, now,
    ))?;
    let label''',
     '''    let label''',
     [api("a_devices_own_send_is_in_its_index_when_written")]),
    ("S37 a message's sent is not the clock", SENDER,
     '''        sent: u64::try_from(now).unwrap_or(0),''',
     '''        sent: u64::try_from(now + 1).unwrap_or(0),''',
     [api("a_devices_own_send_is_in_its_index_when_written")]),
    ("S38 the nonce is not random", SENDER,
     '''        nonce: nonce()?,''',
     '''        nonce: [0; 16],''',
     [api("a_devices_own_send_is_in_its_index_when_written")]),
    ("S39 a message is written at the wrong revision", SENDER,
     '''    let rev = message_rev(number).ok_or(PersonError::Held(''',
     '''    let rev = clearing_rev(number).ok_or(PersonError::Held(''',
     [api("a_devices_own_send_is_in_its_index_when_written")]),
    # ── What is kept, and sending again (§2.3, C18, F6) ───────────────
    ("S40 a send keeps no value", SENDER,
     '''    kept(held::keep(conn, &kept_value, now))?;''',
     '''    let _ = &kept_value;''',
     [api("a_devices_own_send_is_in_its_index_when_written")]),
    ("S41 a kept value's sent is not the send's", SENDER,
     '''        sent: now,
        numbers: vec![number],''',
     '''        sent: now - 31 * 86_400,
        numbers: vec![number],''',
     [api("a_kept_value_goes_once_every_relay_has_taken_it")]),
    ("S42 a 65th kept value is kept", HELD,
     '''    if held <= RING {''',
     '''    if held <= RING + 1 {''',
     [api("a_kept_value_goes_once_every_relay_has_taken_it")]),
    ("S43 a kept value goes when one relay took it", HELD,
     '''        if relays.iter().all(|relay| taken.contains(relay)) {''',
     '''        if relays.iter().any(|relay| taken.contains(relay)) {''',
     [api("a_kept_value_goes_once_every_relay_has_taken_it")]),
    ("S44 a kept value every relay took is said not to have reached one", HELD,
     '''            dropped += usize::from(drop_kept(conn, &kept.id, true)?);''',
     '''            dropped += usize::from(drop_kept(conn, &kept.id, false)?);''',
     [api("a_kept_value_goes_once_every_relay_has_taken_it")]),
    ("S45 a kept value dropped early says nothing", HELD,
     '''    if !taken_everywhere {''',
     '''    if !taken_everywhere && id.is_empty() {''',
     [api("a_relay_that_answers_falsely_makes_a_message_go_under_at_most_four_numbers")]),
    ("S46 a kept value is kept past its 30 days", HELD,
     '''        if kept.generation != generation || has_expired(kept.sent, kept.sent, now) {''',
     '''        if kept.generation != generation {''',
     [api("a_kept_value_goes_once_every_relay_has_taken_it")]),
    ("S47 a kept value of a generation left is kept", HELD,
     '''        if kept.generation != generation || has_expired(kept.sent, kept.sent, now) {''',
     '''        if has_expired(kept.sent, kept.sent, now) {''',
     [api("a_kept_value_goes_once_every_relay_has_taken_it")]),
    ("S48 an answer of Older marks the message taken", SENDER,
     '''                Pushed::Holds => kept(held::taken_by(conn, &id, relay))?,''',
     '''                Pushed::Holds | Pushed::HoldsLater => kept(held::taken_by(conn, &id, relay))?,''',
     [api("a_message_answered_older_waits_and_is_not_sent_again_until_a_pull")]),
    ("S49 a relay's taking is not kept", SENDER,
     '''                Pushed::Holds => kept(held::taken_by(conn, &id, relay))?,''',
     '''                Pushed::Holds => {}''',
     [api("a_kept_value_goes_once_every_relay_has_taken_it")]),
    ("S50 an answer of Another sends nothing again", SENDER,
     '''                    kept(held::send_again(conn, &id))?''',
     '''                    let _ = &id;''',
     [api("a_message_that_a_relay_holds_another_entry_for_is_sent_again_under_the_next_number")]),
    ("S51 an answer of Another to a clearing is acted on", SENDER,
     '''            if entry.author != ring.own || message::is_clearing_rev(entry.rev) {''',
     '''            if entry.author != ring.own {''',
     [api("a_clearing_waits_for_the_first_fetch_and_another_to_it_is_ignored")]),
    ("S52 an answer to another device's entry is acted on", SENDER,
     '''            if entry.author != ring.own || message::is_clearing_rev(entry.rev) {''',
     '''            if message::is_clearing_rev(entry.rev) {''',
     [api("an_answer_to_a_list_or_another_devices_entry_changes_nothing_kept")]),
    ("S53 an answer to the device's list is acted on", SENDER,
     '''            if message_rev(number).is_none() || entry.slot != ring.slot(number)? {''',
     '''            if message_rev(number).is_none() {''',
     [api("an_answer_to_a_list_or_another_devices_entry_changes_nothing_kept")]),
    ("S54 the door does not mark a message its later life wrote over", READER,
     '''    crate::sender::taken_over(conn, own, &slot_key, generation, entry)?;''',
     '''    let _ = own;''',
     [api("a_message_answered_older_waits_and_is_not_sent_again_until_a_pull"),
      api("a_store_restored_a_lap_behind_one_relay_uses_exactly_one_more_number")]),
    ("S55 any entry through the door marks every kept message", SENDER,
     '''        if entry.slot == slot_id(slot_key, &message_name(own, newest)?) {''',
     '''        if entry.slot != [0; 32] {''',
     [api("a_message_answered_older_waits_and_is_not_sent_again_until_a_pull")]),
    ("S56 a fifth number is written", SENDER,
     '''waiting.numbers.len() < AGENT_MESSAGE_SENDS_MAX)''',
     '''waiting.numbers.len() <= AGENT_MESSAGE_SENDS_MAX)''',
     [api("a_relay_that_answers_falsely_makes_a_message_go_under_at_most_four_numbers")]),
    ("S57 a message is sent under five numbers", PROTOCOL,
     '''pub const AGENT_MESSAGE_SENDS_MAX: usize = 4;''',
     '''pub const AGENT_MESSAGE_SENDS_MAX: usize = 5;''',
     [api("a_relay_that_answers_falsely_makes_a_message_go_under_at_most_four_numbers")]),
    ("S58 a send again waits for nothing in the hour", SENDER,
     '''            if device_full(&lately).is_some() {
                break;''',
     '''            if device_full(&lately).is_some() && now < 0 {
                break;''',
     [api("a_message_that_waits_to_be_sent_again_waits_for_the_first_fetch_and_the_hour")]),
    ("S59 a send again is written before the first fetch", SENDER,
     '''            || !fetched
        {
            return Ok(again);''',
     '''            || now < 0
        {
            return Ok(again);''',
     [api("a_message_that_waits_to_be_sent_again_waits_for_the_first_fetch_and_the_hour")]),
    ("S60 a send again is written with sync off", SENDER,
     '''            || meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_none()
            || !fetched
        {
            return Ok(again);''',
     '''            || !fetched
        {
            return Ok(again);''',
     [api("a_message_that_waits_to_be_sent_again_waits_for_the_first_fetch_and_the_hour")]),
    ("S61 a send again is written by a device not applied", SENDER,
     '''        let mut again = Again::default();
        if stands(conn)? != Stands::Applied''',
     '''        let mut again = Again::default();
        if stands(conn)? == Stands::NoPhrase''',
     [api("a_message_that_waits_to_be_sent_again_waits_for_the_first_fetch_and_the_hour")]),
    ("S62 a message sent again keeps no new number", SENDER,
     '''            kept(held::kept_under(conn, &waiting.id, number))?;''',
     '''            kept(held::send_again(conn, &waiting.id))?;''',
     [api("a_message_that_a_relay_holds_another_entry_for_is_sent_again_under_the_next_number")]),
    # ── Clearing (§2.3, §7.1) ─────────────────────────────────────────
    ("S63 the hourly task clears nothing", READER,
     '''    let cleared = match crate::sender::clear_expired(conn, identity, now, fetched) {''',
     '''    let cleared = match Ok::<usize, PersonError>(usize::from(identity.public_key() == [0; 32] && fetched && now < 0)) {''',
     [e2e("a_message_cleared_by_its_sender_leaves_the_other_devices_index")]),
    ("S64 a clearing is written before the first fetch", SENDER,
     '''            || !fetched
        {
            return Ok(0);''',
     '''            || now < 0
        {
            return Ok(0);''',
     [api("a_clearing_waits_for_the_first_fetch_and_another_to_it_is_ignored")]),
    ("S65 a clearing is written with sync off", SENDER,
     '''            || meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_none()
            || !fetched
        {
            return Ok(0);''',
     '''            || !fetched
        {
            return Ok(0);''',
     [api("a_clearing_waits_for_the_first_fetch_and_another_to_it_is_ignored")]),
    ("S66 a clearing is written by a device not applied", SENDER,
     '''        if stands(conn)? != Stands::Applied
            || meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_none()
            || !fetched
        {
            return Ok(0);''',
     '''        if stands(conn)? == Stands::NoPhrase
            || meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_none()
            || !fetched
        {
            return Ok(0);''',
     [api("a_clearing_waits_for_the_first_fetch_and_another_to_it_is_ignored")]),
    ("S67 a message is cleared before its 30 days", SENDER,
     '''            if !held::has_expired(sent, sent, now) {''',
     '''            if !held::has_expired(sent, sent, now + 1) {''',
     [api("a_sender_clears_its_messages_after_thirty_days")]),
    ("S68 a clearing goes two revisions on", SENDER,
     '''            let Some(rev) = clearing_rev(number) else {''',
     '''            let Some(rev) = clearing_rev(number + 1) else {''',
     [api("a_sender_clears_its_messages_after_thirty_days")]),
    ("S69 the sender's own index keeps what it cleared", SENDER,
     '''            kept(held::clear(conn, &ring.own, generation, number, now))?;''',
     '''            let _ = generation;''',
     [api("a_sender_clears_its_messages_after_thirty_days")]),
    ("S70 an entry out of its place in the ring is cleared", SENDER,
     '''            if message_rev(number).is_none() || number % AGENT_MESSAGE_RING as u64 != place {''',
     '''            if message_rev(number).is_none() {''',
     [api("a_device_clears_only_its_own_ring")]),
    ("S71 the slots of the ring are another key's", SENDER,
     '''        Ok(slot_id(&self.slot_key, &message_name(&self.own, number)?))''',
     '''        Ok(slot_id(&self.slot_key, &message_name(&[1; 32], number)?))''',
     [api("a_device_clears_only_its_own_ring")]),
    # ── The device's passes (§2.3, F6) ────────────────────────────────
    ("S72 a relay's answer of Older counts as held", DEVICE,
     '''        PushAnswer::Older => Pushed::HoldsLater,''',
     '''        PushAnswer::Older => Pushed::Holds,''',
     [node("each_answer_to_a_push_is_read_as_what_it_means_for_sending"),
      e2e("a_relays_answer_to_a_message_is_read_for_sending_again")]),
    ("S73 a later one held stops what is sent", AT_RELAYS,
     '''                Some(Pushed::Holds | Pushed::HoldsLater) => done.held += 1,''',
     '''                Some(Pushed::Holds) => done.held += 1,
                Some(Pushed::HoldsLater) => break,''',
     [at_relays("test_what_a_relay_has_not_been_sent_is_sent_and_each_answer_is_acted_on")]),
    ("S74 the device does not tell the sender what a relay answered", DEVICE,
     '''                    sender::pushed(db, own, &relay, channel, batch, &answers, &at).ok()''',
     '''                    { let _ = (own, at); at_relays::sent(db, &relay, channel, batch, &answers).ok() }''',
     [e2e("a_relays_answer_to_a_message_is_read_for_sending_again"),
      e2e("a_message_sent_reaches_the_other_device_and_is_kept_until_every_relay_took_it")]),
    ("S75 the pass writes nothing again", DEVICE,
     '''            if messages && (self.write_again() | self.write_list()) {''',
     '''            if messages && (false | self.write_list()) {''',
     [e2e("a_relays_answer_to_a_message_is_read_for_sending_again"),
      e2e("a_message_sent_offline_after_a_first_fetch_reaches_the_other_device_under_a_new_number")]),
    ("S76 the pass keeps what every relay took", DEVICE,
     '''        self.taken_everywhere(relays);''',
     '''        let _ = relays;''',
     [e2e("a_message_sent_reaches_the_other_device_and_is_kept_until_every_relay_took_it")]),
    ("S77 the device writes again as though never fetched", DEVICE,
     '''        let again = sender::write_again(&db, identity, self.unix(), fetched.unwrap_or(false));''',
     '''        let again = sender::write_again(&db, identity, self.unix(), fetched.is_err());''',
     [e2e("a_relays_answer_to_a_message_is_read_for_sending_again")]),
    ("S78 the hourly task clears as though never fetched", DEVICE,
     '''        match cordelia_api::reader::hourly(&db, identity, now, fetched.unwrap_or(false)) {''',
     '''        match cordelia_api::reader::hourly(&db, identity, now, fetched.is_err()) {''',
     [e2e("a_message_cleared_by_its_sender_leaves_the_other_devices_index")]),
    # ── The merge of the reader's fix ─────────────────────────────────
    ("S81 the hourly drop keeps the kept values of a generation left", HELD,
     '''                if Some(kept.generation) != generation {
                    drop_kept(conn, &kept.id, false)?;''',
     '''                if Some(kept.generation) != generation && kept.generation < 0 {
                    drop_kept(conn, &kept.id, false)?;''',
     [api("one_hourly_task_leaves_nothing_of_a_generation_left_with_a_kept_value")]),
    ("S82 the sender reads the time of day from another clock", DEVICE,
     '''        let again = sender::write_again(&db, identity, self.unix(), fetched.unwrap_or(false));''',
     '''        let again = sender::write_again(&db, identity, self.clock.unix() + 31 * 86_400, fetched.unwrap_or(false));''',
     [e2e("a_message_sent_offline_after_a_first_fetch_reaches_the_other_device_under_a_new_number")]),
    ("S79 a refusal's word is another", SENDER,
     '''            Self::NotFetched => "not_fetched",''',
     '''            Self::NotFetched => "not_fetch",''',
     [ORDER]),
    ("S80 the word of the hold is another", SENDER,
     '''            Self::PairHeld { .. } => "pair_held",''',
     '''            Self::PairHeld { .. } => "pair_hold",''',
     [ORDER]),
    # ── The fixes after the review ──────────────────────────────────
    ("S83 another key's entry in the device's slot makes it send again", SENDER,
     '''    if entry.author != *own {
        return Ok(());
    }
    for kept_value''',
     '''    for kept_value''',
     [api("another_devices_entry_in_this_devices_slot_sends_nothing_again")]),
    ("S84 an error in clearing skips the hourly checkpoint", READER,
     '''        Err(e) => {
            tracing::warn!(error = %e, "could not clear this device's expired messages");
            0
        }''',
     '''        Err(e) => return Err(e),''',
     [reader("an_hourly_task_whose_clearing_fails_still_runs_the_checkpoint")]),
    ("S85 the folder's mapping is checked after the ring", SENDER,
     ['''    if !at.mapped {
        return refused(Refused::NotMapped);
    }
    let folder_limit''',
      '''    // 9. The message a reply answers.
'''],
     ['''    let folder_limit''',
      '''    if !at.mapped {
        return refused(Refused::NotMapped);
    }
    // 9. The message a reply answers.
'''],
     [ORDER]),
    ("S86 the message a reply answers is looked up before the ring", SENDER,
     ['''    // 9. The message a reply answers.
    let (to, thread, answers) = match reply(conn) {
        Ok(Some(reply)) => (reply.to, reply.thread, reply.answers),
        Ok(None) => (request.to.clone(), request.thread, request.answers),
        Err(why) => return refused(why),
    };
''',
      '''    // 8. The ring: fetched, a number left, and the clock.
'''],
     ['''''',
      '''    let (to, thread, answers) = match reply(conn) {
        Ok(Some(reply)) => (reply.to, reply.thread, reply.answers),
        Ok(None) => (request.to.clone(), request.thread, request.answers),
        Err(why) => return refused(why),
    };
    // 8. The ring: fetched, a number left, and the clock.
'''],
     [ORDER]),
    ("S87 a kept value past its 30 days is sent again", SENDER,
     '''        kept(held::drop_kept_gone(conn, generation, now))?;
        for waiting in''',
     '''        let _ = generation;
        for waiting in''',
     [api("a_message_its_own_sender_cleared_in_a_later_life_is_not_sent_again")]),
    ("S88 an answer said of another channel is acted on", SENDER,
     '''        if ring.channel != channel.id {
            return Ok(());
        }''',
     '''        let _ = ring.channel;''',
     [api("an_answer_said_of_a_channel_left_marks_nothing")]),
    ("S89 an answer to a device not applied is acted on", SENDER,
     '''    in_one(conn, || {
        if stands(conn)? != Stands::Applied {
            return Ok(());
        }
        let ring = Ring::of(conn, identity)?;''',
     '''    in_one(conn, || {
        let ring = Ring::of(conn, identity)?;''',
     [api("an_answer_after_the_device_stopped_standing_applied_is_counted_and_marks_nothing")]),
    ("S90 the door marks a kept message of another generation", SENDER,
     '''        if kept_value.generation != generation || kept_value.again {''',
     '''        if kept_value.again {''',
     [api("an_own_entry_of_the_generation_applied_marks_nothing_of_one_left")]),
    ("S91 an answer of another at an older number sends again", SENDER,
     '''Pushed::HoldsAnother if newest_number(conn, &id)? == Some(number) => {''',
     '''Pushed::HoldsAnother if newest_number(conn, &id)?.is_some() => {''',
     [api("only_an_answer_of_another_at_the_newest_number_sends_again")]),
    ("S92 a relay's answer and what is kept of it are two writes", SENDER,
     ['''    in_one(conn, || {
        let done = crate::at_relays::sent(conn, relay, channel, batch, answers)?;
        answered(conn, identity, relay, channel, &batch.entries, answers)?;''',
      '''            at.fetched,
        )?;
        Ok(done)
    })
}'''],
     ['''    (|| -> Result<_, PersonError> {
        let done = crate::at_relays::sent(conn, relay, channel, batch, answers)?;
        answered(conn, identity, relay, channel, &batch.entries, answers)?;''',
      '''            at.fetched,
        )?;
        Ok(done)
    })()
}'''],
     [api("a_relays_answer_and_what_is_kept_of_it_are_one_write")]),
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
