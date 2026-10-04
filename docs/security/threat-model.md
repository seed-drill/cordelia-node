# Threat model

What Cordelia defends against, what it does not, and the tests that prove
each claim.

This file is checked by CI. A claim marked as tested must name tests that
exist and run (see [How CI checks this](#how-ci-checks-this)). So a defence
cannot lose its test unnoticed, and a threat cannot be added here without a
decision about it.

The design behind these claims is in
[`docs/decisions/2026-09-30-agent-memory-sync.md`](../decisions/2026-09-30-agent-memory-sync.md).

## Threats

Each threat has a number that never changes. A number that is missing
belongs to something that is not built or designed in public yet.

| # | Who | What they can try | What must hold | State |
|---|---|---|---|---|
| T1 | A relay's operator, or anyone who takes a relay's disk | Read what the relay is told, stores and logs | A relay is told a channel's ID and nothing else about the channel. It holds ciphertext, sizes, times, channel IDs and device keys, and never an entry's name, its content, or a label. Each entry still travels with its type in clear, such as memory or invite | partly tested (#61) |
| T2 | A stranger who knows a channel's ID | Store entries of their own in the channel at a relay, to hide, erase or block what its members wrote | What a stranger stores does not displace what a channel's members wrote. A copy of an entry under another key does not keep the entry out. A delete under another key sweeps away nothing of a member's. Revisions are bounded, and what a stranger stored under a name does not count towards its next revision, so the name cannot be put out of reach. A device stores an entry only if a member of one of its channels wrote it, so nothing a stranger sends reaches a device's disk. A relay cannot yet tell a channel's members from anyone else, so it still stores what a stranger sends | partly tested (#78) |
| T3 | A peer that floods: any connected node, or a relay towards a device | Send entries that are too large, too many, or that nobody asked for; open streams and connections without limit | One size for every entry: 64 KB of ciphertext, and a bound on every other field, so that an entry as it travels is at most that and a kilobyte. It is checked by the device that writes it, by each relay and by the device that receives it. A larger one is refused, and the sender is told which and why. A device listens on nothing, takes entries only from the relays it was configured with, and stores only what members of its own channels wrote. A connection may have 64 streams open and two messages unread, make 36 pushes a minute and push 2 MB a minute; the connections from one address share five times that, whatever keys they use, and whether or not they stay open. Every limit on bytes counts an entry as its ciphertext and a kilobyte, so small entries cost what they take. A request over a limit is refused at once, a peer that keeps going over is cut off, and its address is refused for a time. An address that has its share of connections is turned away before the handshake. A relay has a storage cap: at the cap it takes no channel it does not hold, and it makes room by dropping the channels it came to hold most recently, so a flood cannot displace what was there before it. What it drops, or loses, is not lost: it asks each device connected to it which channels it holds, and fetches again what it lacks once it has room. What it fetches from a peer is bounded as what the peer may push is, and it holds the peer to what it asked for. It asks a peer about only so many channels, with IDs that could be a channel's. It goes through a peer's list whether or not it can store what is listed, so what follows an entry it refuses is reached. What it keeps for a peer is bounded: a place in the peer's list for so many channels, nothing where the peer lists nothing, and nothing once the peer has gone. Only what is stored counts for what a channel holds. One channel may hold 16 MB, and one address may make a relay hold 16 new channels an hour. An open relay can still be filled, by one address in hours and by many sooner; it then takes no new channel, and stays correct | tested |
| T10 | Another person, or their agent | Get at your memory, or put notes of theirs into your agent's memory, by becoming a member of one of your channels | A channel of your own holds only your own devices. Its keys are never sealed to any other key, by any command or call, and a state that names such a key is not applied | tested |
| T13 | A stranger who knows a device's public key, or someone whose key the device has accepted | Add that device to a channel of their own, so that it syncs its memory to them; move it into their personal channel; or replace the members or keys of a channel the device is in | A device joins only a channel offered by a device it was told to trust, and takes changes to a channel only from that channel's members. Which personal channel a device belongs to is decided by `cordelia accept` on that device, for an hour and for the key it named, and by nothing the device is sent. A device that is in use (it has other devices, or it is syncing) cannot be moved. Trust given to a key for another purpose does not make it one of this person's devices. What strangers send a device does not push out what the person's own devices sent it. A device that is not yet in use still follows whichever key is accepted on it | partly tested (#75) |
| T16 | A device that was removed | Read what is written after its removal, and keep writing; block what the remaining devices write; take what it wrote with it | The channel's key changes on removal and goes only to the devices that remain (a version before 0.2.0-alpha.6 also seals it to a key that is no device's, if one is listed: T20). The device that removes makes the new key itself, and nothing it was sent or holds can stand in for it: a state can carry no key above its own version, and a key above a channel's version is no part of its key ring. What a removed device writes afterwards is shown to nobody, and counts for nothing: it cannot put a name's revision out of reach. What it wrote before is kept: the device that removes it publishes those entries again, edits and deletes alike, so a device added later gets them. A device that learns of the removal later does not adopt anything newer it holds from the removed device. The change that removes it reaches the devices that remain: it is not taken as delivered when a relay refuses to store it, and the device that made it offers it again until each of the others answers that it holds it, whatever a relay lost in between | tested |
| T17 | Another program running as the same user | Read the node's files and memory, and call its local API | Nothing. Cordelia does not defend against this; real separation needs separate users or machines | not defended |
| T18 | Anyone who carries or stores an entry | Move it to another channel, give it another name, present an old revision as a newer one, change its content, or forge its author | Each of these makes the entry fail its signature or fail to decrypt, and it is ignored | tested |
| T19 | Someone who claims to be another device or relay, or answers for a relay's name | Connect, or answer, under another node's key, to take over its connection or be taken for it; pose as a device's relay and send the device elsewhere; say it is a relay, to be sent what relays are sent | A node's ID is the key its TLS certificate proves, so nobody can connect or answer under a key they do not hold. A node knows its relays by name and key, refuses any other key at a relay's address, and dials nothing but its configured relays. Being a relay is a matter of configuration: a node that merely says it is one is an ordinary peer, and is not told which channels a node holds | tested |
| T20 | A device of yours that has been taken over | Slip a key that is not one of your devices into your channels; add or remove devices; fix a channel's list of members, fill its key ring or run its key version out, so that the list can never change and the device can never be removed | A state for one of your channels that names a key which is not one of your devices is not applied, whichever device sent it. Bytes that are not a usable key (not a point on the curve, or a point that is not of the order every real key has) are never a device and never a member. Such a key is not added and not accepted, nothing is sealed to it, and no channel state is taken from a sender that has one: under a point of small order the secret is one anyone can work out, and anyone can sign. Listed in a state, it is left out and the rest of the state is taken. One that was stored before is taken off the list when the node starts, and what was written under it no longer counts in a channel. No channel's key is changed on its account, and removing such a key is refused: a channel that listed one stays readable by whoever could open what was sealed to it, until its key changes for another reason (decision record, section 9). The counter that orders changes to a channel's members is bounded, and one change can move it only so far, so no device can put the list beyond change. The same holds for a channel's key version, and a key ring that is full is sent with its oldest keys left out, so a removal can always be made and sent. A new device is not yet announced on the others, and can change the list of devices at once | partly tested (#76) |

## Tests

### T1
- `crates/cordelia-node/tests/threat_model.rs`: `t01_a_relay_holds_nothing_it_can_read`
- `crates/cordelia-node/tests/threat_model.rs`: `t01_a_device_tells_a_relay_only_a_channels_id`
- `crates/cordelia-network/src/channel_announce.rs`: `an_announcement_says_nothing_about_the_channel_but_its_id`

### T2
- `crates/cordelia-node/tests/threat_model.rs`: `t02_a_strangers_copy_at_a_relay_changes_nothing_for_a_channels_devices`
- `crates/cordelia-storage/src/items.rs`: `a_copy_by_another_author_does_not_keep_an_entry_out`
- `crates/cordelia-storage/src/items.rs`: `a_strangers_delete_sweeps_nothing_from_a_device`
- `crates/cordelia-storage/src/items.rs`: `one_authors_delete_sweeps_nothing_of_anothers_from_a_relay`
- `crates/cordelia-storage/src/items.rs`: `a_revision_over_the_limit_is_not_stored`
- `crates/cordelia-storage/src/items.rs`: `a_strangers_revision_does_not_count_towards_the_next_one`
- `crates/cordelia-network/src/item_sync.rs`: `a_revision_over_the_limit_does_not_verify`
- `crates/cordelia-api/src/verify.rs`: `a_revision_over_the_limit_does_not_verify`
- `crates/cordelia-api/tests/entries.rs`: `a_strangers_revision_does_not_stop_a_member_writing`
- `crates/cordelia-node/src/p2p.rs`: `a_device_stores_only_what_members_of_its_channels_wrote`
- `crates/cordelia-api/tests/membership.rs`: `a_channel_is_listed_again_when_its_members_change`

### T3
- `crates/cordelia-node/tests/threat_model.rs`: `t03_a_relay_refuses_an_entry_over_the_size_limit`
- `crates/cordelia-node/src/p2p.rs`: `an_entry_over_the_size_limit_is_refused_by_whoever_is_sent_it`
- `crates/cordelia-api/tests/entries.rs`: `t03_an_entry_over_the_size_limit_is_not_written`
- `crates/cordelia-node/src/p2p.rs`: `an_entry_with_a_field_over_its_size_is_refused_by_whoever_is_sent_it`
- `crates/cordelia-storage/src/items.rs`: `an_entry_with_a_field_over_its_size_is_not_stored`
- `crates/cordelia-network/src/messages.rs`: `the_largest_entry_as_it_travels_is_its_ciphertext_and_the_overhead`
- `crates/cordelia-node/tests/threat_model.rs`: `t03_small_entries_count_for_what_they_take`
- `crates/cordelia-node/src/p2p.rs`: `small_entries_count_for_what_they_take_in_a_channel`
- `crates/cordelia-storage/src/items.rs`: `a_channels_cost_counts_what_each_entry_takes`
- `crates/cordelia-node/tests/devices_e2e.rs`: `a_device_with_many_small_entries_is_never_refused_by_its_relay`
- `crates/cordelia-node/tests/threat_model.rs`: `t03_an_addresss_allowance_outlasts_its_connections`
- `crates/cordelia-node/src/p2p.rs`: `an_addresss_allowance_outlasts_its_connections`
- `crates/cordelia-node/tests/devices_e2e.rs`: `a_personal_node_listens_on_nothing`
- `crates/cordelia-node/tests/threat_model.rs`: `t03_a_peer_over_its_rate_is_cut_off_and_refused_for_a_time`
- `crates/cordelia-node/tests/threat_model.rs`: `t03_a_connection_may_push_two_megabytes_a_minute`
- `crates/cordelia-node/tests/threat_model.rs`: `t03_an_address_is_turned_away_once_it_has_its_share_of_connections`
- `crates/cordelia-node/src/p2p.rs`: `limits_are_counted_for_a_connection_and_for_its_address`
- `crates/cordelia-network/src/transport.rs`: `a_connection_holds_at_most_64_streams_open`
- `crates/cordelia-network/src/transport.rs`: `a_connection_buffers_at_most_two_unread_messages`
- `crates/cordelia-node/tests/threat_model.rs`: `t03_a_full_relay_keeps_what_it_held_first`
- `crates/cordelia-node/src/p2p.rs`: `a_full_relay_keeps_what_it_held_first`
- `crates/cordelia-node/src/p2p.rs`: `a_relay_limits_one_channel_and_new_channels_from_one_address`
- `crates/cordelia-node/tests/threat_model.rs`: `t03_a_relay_fetches_from_a_peer_no_faster_than_the_peer_may_push`
- `crates/cordelia-node/src/p2p.rs`: `what_a_relay_fetches_from_a_peer_is_bounded_as_what_the_peer_may_push_is`
- `crates/cordelia-node/tests/threat_model.rs`: `t03_a_channel_a_relay_dropped_comes_back_when_there_is_room`
- `crates/cordelia-node/tests/threat_model.rs`: `t03_a_relay_asks_a_peer_about_only_so_many_channels`
- `crates/cordelia-node/src/p2p.rs`: `what_a_peer_lists_is_bounded_before_a_relay_asks_about_it`
- `crates/cordelia-node/src/p2p.rs`: `what_is_kept_for_a_peer_is_bounded_and_forgotten_when_it_goes`
- `crates/cordelia-node/tests/threat_model.rs`: `t03_a_relay_keeps_nothing_for_names_a_peer_makes_up`
- `crates/cordelia-node/tests/threat_model.rs`: `t03_a_relay_keeps_only_so_many_places_for_a_peer`
- `crates/cordelia-node/tests/threat_model.rs`: `t03_a_relay_gets_past_what_it_will_not_store`
- `crates/cordelia-node/src/p2p.rs`: `a_connection_cannot_use_up_what_its_address_may_be_fetched_from`
- `crates/cordelia-node/src/p2p.rs`: `in_a_channel_over_its_share_a_device_can_still_change_what_it_wrote`
- `crates/cordelia-node/src/p2p.rs`: `a_revision_that_is_not_stored_makes_no_room_in_a_channel`
- `crates/cordelia-node/src/p2p.rs`: `a_channel_still_being_fetched_keeps_its_place_before_caught_up_ones`
- `crates/cordelia-node/src/p2p.rs`: `a_fetch_starts_its_channel_again_only_when_that_channel_is_forgotten`
- `crates/cordelia-node/tests/threat_model.rs`: `t03_a_relay_does_not_fetch_what_it_has_no_room_for`
- `crates/cordelia-node/tests/threat_model.rs`: `t03_a_page_longer_than_the_one_asked_for_is_not_taken`
- `crates/cordelia-node/src/p2p.rs`: `a_channel_a_relay_dropped_is_left_for_a_while_before_it_is_taken_again`
- `crates/cordelia-node/tests/devices_e2e.rs`: `relays_that_list_each_other_are_filled_again_by_their_devices`
- `crates/cordelia-node/src/p2p.rs`: `a_device_stores_only_what_members_of_its_channels_wrote`

### T10
- `crates/cordelia-api/tests/membership.rs`: `t10_a_channels_keys_are_sealed_only_to_your_own_devices`
- `crates/cordelia-api/tests/membership.rs`: `t10_a_state_that_names_a_strangers_key_is_held_until_it_is_a_device`
- `crates/cordelia-api/tests/api_integration.rs`: `test_group_lifecycle`

### T13
- `crates/cordelia-api/tests/membership.rs`: `stranger_cannot_join_or_change_channels`
- `crates/cordelia-api/tests/membership.rs`: `tampered_or_misaddressed_invites_are_invalid`
- `crates/cordelia-api/tests/membership.rs`: `t13_a_device_that_is_syncing_keeps_its_personal_channel`
- `crates/cordelia-api/tests/membership.rs`: `t13_a_device_with_other_devices_keeps_its_personal_channel`
- `crates/cordelia-api/tests/membership.rs`: `t13_trust_in_a_person_does_not_make_a_key_a_device`
- `crates/cordelia-api/tests/membership.rs`: `t13_turning_sync_on_after_accepting_does_not_stop_the_join`
- `crates/cordelia-api/tests/membership.rs`: `t13_an_offer_long_after_the_accept_waits`
- `crates/cordelia-api/tests/membership.rs`: `t13_invitations_from_strangers_do_not_push_out_what_your_own_devices_sent`

### T16
- `crates/cordelia-api/tests/membership.rs`: `remove_device_rotates_the_key_and_informs_only_remaining_members`
- `crates/cordelia-api/tests/entries.rs`: `a_removed_device_can_no_longer_write`
- `crates/cordelia-node/tests/threat_model.rs`: `t16_a_removed_devices_last_entries_are_kept_and_its_later_ones_are_not`
- `crates/cordelia-api/tests/entries.rs`: `t16_what_a_removed_device_last_wrote_is_kept`
- `crates/cordelia-api/tests/entries.rs`: `t16_a_removed_device_cannot_put_a_name_out_of_reach`
- `crates/cordelia-api/tests/entries.rs`: `t16_a_revision_meant_to_use_the_numbers_up_is_not_kept`
- `crates/cordelia-api/tests/entries.rs`: `t16_what_a_removed_device_writes_afterwards_is_not_adopted_later`
- `crates/cordelia-sync/src/plan.rs`: `a_channel_that_has_gone_back_keeps_this_devices_version`
- `crates/cordelia-node/tests/threat_model.rs`: `t16_a_relays_refusal_is_not_taken_for_delivery`
- `crates/cordelia-node/src/p2p.rs`: `a_relays_refusal_is_not_delivery`
- `crates/cordelia-node/src/p2p.rs`: `an_answer_that_does_not_add_up_delivers_nothing`
- `crates/cordelia-node/tests/threat_model.rs`: `t16_a_removal_is_offered_again_when_the_relay_loses_it`
- `crates/cordelia-api/tests/membership.rs`: `t16_a_removal_is_offered_again_until_the_others_hold_it`
- `crates/cordelia-api/tests/membership.rs`: `a_change_waits_until_each_member_confirms_it`
- `crates/cordelia-api/tests/membership.rs`: `t16_a_state_cannot_carry_the_key_a_removal_will_make`
- `crates/cordelia-api/tests/membership.rs`: `t16_a_key_waiting_for_the_next_version_is_not_used_by_a_removal`
- `crates/cordelia-crypto/src/channel_state.rs`: `a_key_above_the_current_version_is_not_a_valid_state`
- `crates/cordelia-storage/src/psk.rs`: `a_key_above_the_current_version_is_never_kept`
- `crates/cordelia-storage/src/psk.rs`: `a_key_that_was_waiting_is_not_kept_when_its_version_is_passed`
- `crates/cordelia-storage/src/psk.rs`: `a_key_that_was_waiting_does_not_survive_the_older_rotation`

### T18
- `crates/cordelia-network/src/item_sync.rs`: `test_verify_item_signature`
- `crates/cordelia-crypto/src/slots.rs`: `test_aad_binds_slot_and_rev`
- `crates/cordelia-api/tests/entries.rs`: `only_members_writing_the_right_key_count`

### T19
- `crates/cordelia-network/src/transport.rs`: `a_certificate_that_names_another_key_is_refused`
- `crates/cordelia-network/src/transport.rs`: `a_client_that_names_another_key_cannot_connect`
- `crates/cordelia-network/src/transport.rs`: `a_server_that_names_another_key_is_refused`
- `crates/cordelia-node/tests/threat_model.rs`: `t19_a_device_refuses_another_key_at_its_relays_address`
- `crates/cordelia-node/tests/threat_model.rs`: `t19_a_device_asks_no_peer_for_addresses_to_dial`
- `crates/cordelia-network/src/bootstrap.rs`: `a_configured_relay_has_the_key_it_was_given_or_the_default_one`
- `crates/cordelia-node/tests/threat_model.rs`: `t19_a_stranger_that_says_it_is_a_relay_is_not_treated_as_one`

### T20
- `crates/cordelia-api/tests/membership.rs`: `t10_a_state_that_names_a_strangers_key_is_held_until_it_is_a_device`
- `crates/cordelia-api/tests/membership.rs`: `t20_no_state_can_put_a_channels_members_beyond_change`
- `crates/cordelia-crypto/src/channel_state.rs`: `an_epoch_over_the_limit_is_not_a_valid_state`
- `crates/cordelia-storage/src/channels.rs`: `an_epoch_over_the_limit_is_neither_stored_nor_read`
- `crates/cordelia-api/tests/membership.rs`: `t20_a_full_key_ring_does_not_stop_a_removal`
- `crates/cordelia-api/tests/membership.rs`: `t20_no_state_can_run_the_key_version_out`
- `crates/cordelia-api/tests/membership.rs`: `t20_a_key_that_is_not_usable_is_never_a_device`
- `crates/cordelia-crypto/src/identity.rs`: `a_key_that_is_not_a_point_or_is_of_small_order_is_no_key`
- `crates/cordelia-crypto/src/ecies.rs`: `a_secret_anyone_can_work_out_seals_and_opens_nothing`
- `crates/cordelia-crypto/src/channel_state.rs`: `a_state_is_sealed_to_no_key_that_is_not_usable`
- `crates/cordelia-api/tests/membership.rs`: `t20_a_key_that_was_stored_before_blocks_nothing`
- `crates/cordelia-api/tests/membership.rs`: `t20_a_key_that_was_stored_before_is_taken_off_and_no_key_is_changed`
- `crates/cordelia-api/tests/membership.rs`: `t20_a_state_that_is_held_has_its_keys_checked_once`
- `crates/cordelia-api/tests/membership.rs`: `t20_past_what_is_remembered_a_state_costs_a_check_a_key_and_ends_the_same`
- `crates/cordelia-api/tests/membership.rs`: `t20_a_state_is_taken_however_many_keys_of_nobodys_it_lists`
- `crates/cordelia-api/tests/membership.rs`: `t20_a_state_held_for_a_device_not_yet_known_is_taken_when_it_is`
- `crates/cordelia-api/tests/membership.rs`: `t20_what_was_written_under_a_key_anyone_can_sign_with_stops_counting`
- `crates/cordelia-api/src/state.rs`: `test_what_is_remembered_of_a_key_is_what_the_check_gives`
- `crates/cordelia-api/src/state.rs`: `test_each_node_remembers_for_itself`
- `crates/cordelia-api/src/state.rs`: `test_what_is_remembered_is_bounded_and_dropping_it_changes_no_answer`
- `crates/cordelia-api/tests/membership.rs`: `t20_nothing_is_taken_from_a_sender_whose_key_is_not_usable`
- `crates/cordelia-api/tests/membership.rs`: `t20_a_key_that_is_not_usable_is_left_out_of_every_state_that_is_applied`
- `crates/cordelia-api/tests/membership.rs`: `t20_what_a_stranger_sends_is_not_checked_key_by_key`
- `crates/cordelia-api/tests/api_integration.rs`: `test_the_older_endpoints_seal_to_no_key_that_is_not_usable`
- `crates/cordelia-node/tests/threat_model.rs`: `t20_a_key_that_is_no_devices_goes_when_the_node_starts`

## How CI checks this

`crates/cordelia-node/tests/threat_model.rs` reads this file on every run of
`cargo test`.

- **States.** Every row ends with one of: `tested`; `partly tested (#issue)`,
  where the issue builds the rest; `planned (#issue)`; or `not defended`.
- **Tests.** Under `### T<number>`, each line names a file and a test in it.
- **It fails when** a row has no state; a row marked `tested` or
  `partly tested` lists no test; a listed test does not exist, is not a
  test, or is ignored; tests are listed for a number that is not in the
  table; or a row marked `not defended` lists tests.

To add a threat: add a row with the next free number and a state. To defend
against one: write the tests, list them, and change the state.
