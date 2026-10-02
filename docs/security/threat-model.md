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
| T13 | A stranger who knows a device's public key | Add that device to a channel of their own, so that it syncs its memory to them; or replace the members or keys of a channel the device is in | A device joins only a channel offered by a device it was told to trust, and takes changes to a channel only from that channel's members | tested |
| T16 | A device that was removed | Read what is written after its removal, and keep writing | The channel's key changes on removal and goes only to the devices that remain. What a removed device writes afterwards is shown to nobody | tested |
| T17 | Another program running as the same user | Read the node's files and memory, and call its local API | Nothing. Cordelia does not defend against this; real separation needs separate users or machines | not defended |
| T18 | Anyone who carries or stores an entry | Move it to another channel, give it another name, present an old revision as a newer one, change its content, or forge its author | Each of these makes the entry fail its signature or fail to decrypt, and it is ignored | tested |
| T19 | Someone who claims to be another device or relay, or answers for a relay's name | Connect, or answer, under another node's key, to take over its connection or be taken for it; pose as a device's relay and send the device elsewhere; say it is a relay, to be sent what relays are sent | A node's ID is the key its TLS certificate proves, so nobody can connect or answer under a key they do not hold. A node knows its relays by name and key, refuses any other key at a relay's address, and dials nothing but its configured relays. Being a relay is a matter of configuration: a node that merely says it is one is an ordinary peer, and is not told which channels a node holds | tested |

## Tests

### T1
- `crates/cordelia-node/tests/threat_model.rs`: `t01_a_relay_holds_nothing_it_can_read`
- `crates/cordelia-node/tests/threat_model.rs`: `t01_a_device_tells_a_relay_only_a_channels_id`
- `crates/cordelia-network/src/channel_announce.rs`: `an_announcement_says_nothing_about_the_channel_but_its_id`

### T13
- `crates/cordelia-api/tests/membership.rs`: `stranger_cannot_join_or_change_channels`
- `crates/cordelia-api/tests/membership.rs`: `tampered_or_misaddressed_invites_are_invalid`

### T16
- `crates/cordelia-api/tests/membership.rs`: `remove_device_rotates_the_key_and_informs_only_remaining_members`
- `crates/cordelia-api/tests/entries.rs`: `a_removed_device_can_no_longer_write`

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
