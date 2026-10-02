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
| T2 | A stranger who knows a channel's ID | Store entries of their own in the channel at a relay, to hide, erase or block what its members wrote | What a stranger stores does not displace what a channel's members wrote. A copy of an entry under another key does not keep the entry out. A delete under another key sweeps away nothing of a member's. Revisions are bounded, and what a stranger stored under a name does not count towards its next revision, so the name cannot be put out of reach. A relay cannot yet tell a channel's members from anyone else, so it still stores what a stranger sends | partly tested (#78) |
| T10 | Another person, or their agent | Get at your memory, or put notes of theirs into your agent's memory, by becoming a member of one of your channels | A channel of your own holds only your own devices. Its keys are never sealed to any other key, by any command or call, and a state that names such a key is not applied | tested |
| T13 | A stranger who knows a device's public key, or someone whose key the device has accepted | Add that device to a channel of their own, so that it syncs its memory to them; move it into their personal channel; or replace the members or keys of a channel the device is in | A device joins only a channel offered by a device it was told to trust, and takes changes to a channel only from that channel's members. Which personal channel a device belongs to is decided by `cordelia accept` on that device, for an hour and for the key it named, and by nothing the device is sent. A device that is in use (it has other devices, or it is syncing) cannot be moved. Trust given to a key for another purpose does not make it one of this person's devices. What strangers send a device does not push out what the person's own devices sent it. A device that is not yet in use still follows whichever key is accepted on it | partly tested (#75) |
| T16 | A device that was removed | Read what is written after its removal, and keep writing; block what the remaining devices write; take what it wrote with it | The channel's key changes on removal and goes only to the devices that remain. What a removed device writes afterwards is shown to nobody, and counts for nothing: it cannot put a name's revision out of reach. What it wrote before is kept: the device that removes it publishes those entries again, edits and deletes alike, so a device added later gets them. A device that learns of the removal later does not adopt anything newer it holds from the removed device | tested |
| T17 | Another program running as the same user | Read the node's files and memory, and call its local API | Nothing. Cordelia does not defend against this; real separation needs separate users or machines | not defended |
| T18 | Anyone who carries or stores an entry | Move it to another channel, give it another name, present an old revision as a newer one, change its content, or forge its author | Each of these makes the entry fail its signature or fail to decrypt, and it is ignored | tested |
| T19 | Someone who claims to be another device or relay, or answers for a relay's name | Connect, or answer, under another node's key, to take over its connection or be taken for it; pose as a device's relay and send the device elsewhere; say it is a relay, to be sent what relays are sent | A node's ID is the key its TLS certificate proves, so nobody can connect or answer under a key they do not hold. A node knows its relays by name and key, refuses any other key at a relay's address, and dials nothing but its configured relays. Being a relay is a matter of configuration: a node that merely says it is one is an ordinary peer, and is not told which channels a node holds | tested |
| T20 | A device of yours that has been taken over | Slip a key that is not one of your devices into your channels; add or remove devices; fix a channel's list of members so that it can never change, and the device can never be removed | A state for one of your channels that names a key which is not one of your devices is not applied, whichever device sent it. The counter that orders changes to a channel's members is bounded, and one change can move it only so far, so no device can put the list beyond change. A new device is not yet announced on the others, and can change the list of devices at once | partly tested (#76) |

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
