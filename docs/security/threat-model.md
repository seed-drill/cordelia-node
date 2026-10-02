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
| T1 | A relay's operator, or anyone who takes a relay's disk | Read what the relay stores and logs | A relay holds ciphertext, sizes, times, channel IDs and device keys. It never holds an entry's name, its content, or a label | tested |
| T13 | A stranger who knows a device's public key | Add that device to a channel of their own, so that it syncs its memory to them; or replace the members or keys of a channel the device is in | A device joins only a channel offered by a device it was told to trust, and takes changes to a channel only from that channel's members | tested |
| T16 | A device that was removed | Read what is written after its removal, and keep writing | The channel's key changes on removal and goes only to the devices that remain. What a removed device writes afterwards is shown to nobody | tested |
| T17 | Another program running as the same user | Read the node's files and memory, and call its local API | Nothing. Cordelia does not defend against this; real separation needs separate users or machines | not defended |
| T18 | Anyone who carries or stores an entry | Move it to another channel, give it another name, present an old revision as a newer one, change its content, or forge its author | Each of these makes the entry fail its signature or fail to decrypt, and it is ignored | tested |

## Tests

### T1
- `crates/cordelia-node/tests/threat_model.rs`: `t01_a_relay_holds_nothing_it_can_read`

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
