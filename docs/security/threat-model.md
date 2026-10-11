# Threat model

What Cordelia defends against, what it does not, and the tests that prove
each claim.

This file is checked by CI. A claim marked as tested must name tests that
exist and run (see [How CI checks this](#how-ci-checks-this)). So a defence
cannot lose its test unnoticed, and a threat cannot be added here without a
decision about it.

The design behind these claims is in
[`docs/decisions/2026-10-04-a-persons-devices.md`](../decisions/2026-10-04-a-persons-devices.md)
(a person's devices, the recovery phrase, and what a relay does) and
[`docs/decisions/2026-09-30-agent-memory-sync.md`](../decisions/2026-09-30-agent-memory-sync.md)
(the adapter, ties, deletes and local history), and messages between a
person's own agents in
[`docs/decisions/2026-10-09-messages-between-your-own-agents.md`](../decisions/2026-10-09-messages-between-your-own-agents.md).
A relay carries two kinds of
channel for one version: the channels from their secrets, which every device
on this version uses, and the older kind, for a device that has not been
upgraded. Where a row says "of the older kind", it speaks of the second.

## Threats

Each threat has a number that never changes. A number that is missing
belongs to something that is not built or designed in public yet.

| # | Who | What they can try | What must hold | State |
|---|---|---|---|---|
| T1 | A relay's operator, or anyone who takes a relay's disk | Read what the relay is told, stores and logs | A relay holds no key. Of a channel from its secret it holds the channel's ID and, for each entry, its slot, its author's key, its revision, whether it is a delete, and a content that is padded to one of nine sizes. It never holds an entry's name, its content, the name a folder syncs under, or a label, and such an entry has no type in clear: the kind of an entry is inside the ciphertext. A device tells a relay a channel's ID and nothing else about the channel, and announces no channel. What a relay still learns is listed in the decision record of 2026-10-04, section 2.4: all of a person's channel IDs change at once when a device is removed; which connection proved which channel; each pair of devices that meet when one is added; each time a recovery phrase is used; and the ID of the phrase's channel, which stays the same for a person for as long as the phrase does and which each of their devices presents. Of the older kind of channel, which a relay carries for one version more, an announcement says a channel's ID and nothing else, and each entry still travels with its type in clear, such as memory or invite. What issue #61 is about, an item's type and its parent link travelling in clear and outside its signature, is so of the older kind alone, and stands there as it was: a relay could change either unnoticed. An entry of a channel from its secret has neither in clear. A personal node carries no channel of the older kind, so nothing that a device does rests on a field that a relay could change. A message between a person's agents is an entry of a channel of the person's own, whose content is always 2,048 bytes: a relay never holds its body, its subject, the names it is from and to, its link, its thread or when it was sent. It can tell a message from the entry that clears it by the parity of its revision, which says no more than that the message was sent 30 days before (the decision record of 2026-10-09, section 10) | partly tested (#61) |
| T2 | A stranger who knows a channel's ID | Store entries of their own in the channel at a relay, to hide, erase or block what its devices wrote; fetch the channel; ask a relay whether it holds it | In a channel from its secret, a relay stores an entry only if the channel's key signed it, and the channel's ID gives nobody that key: a stranger's entry, and a copy of a real entry under a stranger's key, is stored by no relay. A relay hands the channel only to a connection that has proved it holds the channel's key, checks the proof before it looks the channel up, and answers a channel that it does not hold and a proof that fails alike: a stranger learns neither what the channel holds nor whether the relay holds it. A device stores an entry of a channel of its own only if its signer counts: a device of the statement it has applied, or one added since. One thing is handed with no proof: whoever shows a relay an entry is answered with the entry the relay holds from that author in that slot, if it is another one. Only a holder of an entry can ask, and what comes back is ciphertext. In a channel of the older kind, which a relay carries for one version more, a relay cannot tell a channel's members from anyone else, so it still stores what a stranger sends. There, what a stranger stores does not displace what a channel's members wrote; a copy of an entry under another key does not keep the entry out; a delete under another key sweeps away nothing of a member's; and revisions are bounded, and what a stranger stored under a name does not count towards its next revision, so the name cannot be put out of reach. What issue #78 asks for is the rule of a channel from its secret, which is built and is tested with real processes: a stranger who knows a channel's ID pushes to it and pulls from it, with a proof that it makes up or one that it captured on another connection, and gets nothing. The older kind is what is left of it, for the one version that a relay carries that kind: no rule of this version changes what a relay stores there. At a relay a delete is swept, after 90 days, only where every author's entry in its slot is such a delete, in both kinds, so no key's delete sweeps away what another key wrote | partly tested (#78) |
| T3 | A peer that floods: any connected node, or a relay towards a device | Send entries that are too large, too many, or that nobody asked for; open streams and connections without limit | One size for every entry: 64 KB of ciphertext, and a bound on every other field, so that an entry as it travels is at most that and a kilobyte. It is checked by the device that writes it, by each relay and by the device that receives it. A larger one is refused, and the sender is told which and why. A device listens on nothing, takes entries only from the relays it was configured with, and stores only what a device of its person's that counts signed. A connection may have 64 streams open and two messages unread, make 36 pushes a minute and push 2 MB a minute; the connections from one address share five times that, whatever keys they use, and whether or not they stay open. On the streams of a channel from its secret a connection may make 3,000 requests a minute, all counted together, and the bytes it pushes and is handed there are counted with the older kind's against one allowance. Every limit on bytes counts an entry as its ciphertext and a kilobyte, so small entries cost what they take. A request over a limit is refused at once, a peer that keeps going over is cut off, and its address is refused for a time. An address that has its share of connections is turned away before the handshake. A relay has a storage cap for each kind of channel, and neither kind is refused or dropped to make room for the other. At a cap it takes no channel it does not hold. A write that would take it past its cap for channels from their secrets is refused, and drops nothing; over its cap for the older kind it drops the channels it has held for the shortest time. So a flood cannot displace what was there before it. What a relay drops of the older kind, or loses, is not lost: it asks each device connected to it which channels it holds, and fetches again what it lacks once it has room. What it fetches from a peer is bounded as what the peer may push is, and it holds the peer to what it asked for. It asks a peer about only so many channels, with IDs that could be a channel's. It goes through a peer's list whether or not it can store what is listed, so what follows an entry it refuses is reached. What it keeps for a peer is bounded: a place in the peer's list for so many channels, nothing where the peer lists nothing, and nothing once the peer has gone. Only what is stored counts for what a channel holds. One channel may hold 16 MB, and one address may make a relay hold 16 new channels of the older kind an hour, and 256 channels from their secrets. A channel from its secret that nobody has used for 90 days is dropped. A pull leaves room for the entry that answers a show, so a device that pulls at its full rate is still told of a removal; and whoever shows an earlier entry again and again is handed one entry beyond its bytes for the minute, and no more. An open relay can still be filled, by one address in hours and by many sooner; it then takes no new channel, and stays correct. What is not defended at a relay is in the decision record of 2026-10-04, section 2.5: older channels filled and kept by whoever holds their keys, and limits that are all by address. In the messages channel every entry is one size and each device writes in at most 65 slots, so a slot written again, a message over the one 64 before it, the entry that clears it or a device's list, is never refused for room; a device that counts can still fill that channel at a relay with slots that are no message's, and the device whose first message is then refused names the signer whose entries fill it (the decision record of 2026-10-09, section 10) | tested |
| T10 | Another person, or their agent | Get at your memory, or put notes of theirs into your agent's memory, by becoming one of the devices of your channels | Every channel of your own is derived from your person secret. That secret is sealed only to the devices that a statement lists, and is handed only to a device that you add with the two commands, each at a terminal with its yes. A statement is applied only on a device that it lists, with the secret that opens to its commitment. A device stores an entry of a channel of its own only if its signer counts, and keeps a record of an addition only if it verifies and its signer counts. Nothing is shared between people in this version. The Channels API of the older kind, which a relay or a bootnode serves, refuses to invite a key that is not one of the node's own devices. A message between agents never leaves the person's devices: the messages channel is derived from the person secret alone, `cordelia msg send` takes only a name that the personal channel lists, or every name, and no route takes a key. A reader takes as a message only an entry in a slot named for the key that signed it, at a number in that slot's place, so no device can write as another (the decision record of 2026-10-09, sections 2.3 and 3) | tested |
| T13 | A stranger who knows a device's public key, or someone whose key was typed on the device | Make that device follow them, so that it syncs its memory to them; hand it a statement or a secret of their own; or replace the devices it counts | A device follows only a recovery phrase that a person gave it: by making it there, by typing the phrase there to recover, or by accepting there, at a terminal and with a yes, a device that follows it. Nothing a device is sent makes it follow another. A recovery is refused on a device that already follows a phrase. A device reads a pair channel only with a key that a person typed on it within the last hour, takes from it only the hand-over that the other device's key wrote, and only one that says it was made within the hour before or after the key was typed. A device that is one of several takes only a hand-over under the phrase it already follows that brings a change it can apply. A device that is alone under a phrase leaves it only with sync off, so that sending its folders to another set of devices takes two acts. A device that follows no phrase takes nothing it is sent in a channel, and no change entry. Every device shows an addition, and its status line is amber, until a person clears it there or a statement lists the device. A device that is not yet in use still follows whichever key is accepted on it: for as long as it follows no phrase (a new install, and every device between the upgrade and its being added) one yes at a terminal joins it, and its folders, to the devices of the key that is typed. Issue #75 would close that: adding by a code that the new device shows, so that a device comes to follow a phrase by one act on that device. It is not built. A device is added by the two commands, with a key copied in each direction | partly tested (#75) |
| T16 | A device that was removed | Read what is written after its removal, and keep writing; block the removal, or what the remaining devices write; take what it wrote with it | Removing a device is one statement, signed with the recovery phrase, that names the devices that remain and commits to a new person secret, sealed to each of them: every channel of the person's own changes at once, and a device applies the change whole or not at all. A removed device reads nothing that a device which has applied the removal writes afterwards, and writes nothing into the new channels: every entry there is signed by a device that the statement lists, or by one added since. On a device that has applied the removal, an entry that the removed device signs is not stored, from any channel, and counts for nothing when a name is read, so it cannot put a name's revision out of reach. No statement brings a removed key back. What the removed device wrote before is kept where a remaining device had taken it: each device carries what it holds into the new channels, edits and deletes alike, and a version that another key signed is carried with that key in its first link. So where a removed key signed a version between a folder's text and the version it takes, the folder keeps its text beside the file. What the removed device had sent to a relay, and no remaining device had taken, comes in afterwards only by the command that names that device, at a terminal, with the recovery phrase: the phrase signs what was shown, the node takes what that word allows and nothing beyond it, a version comes in above one that is held only on a second yes that names the file, and a delete that the removed device signed is never taken. (A device that has not heard of the removal still writes where the removed device can read, and still takes what the removed device writes there. When it applies the removal it carries what it holds, and every other device keeps its own text beside what arrives: the decision record of 2026-10-04, properties 1 and 2, and section 14.) The removal reaches the devices that remain: its entry replaces the one before it at the same size, in a channel that a relay already holds, so a relay at its cap still stores it; every device shows it to each relay it reaches, and applies what it is answered with, before it sends or takes anything there; it is not taken as delivered when a relay refuses to store it; and each device says which devices have not applied it and which relays do not hold it. A removed device still reads each later statement, which says who the person's devices are, by key and label, and cannot open the secret in it. Not defended (that record, section 2.5): a removed device holds the channels that were left and can fill them and go on proving them, and at the same address as the others it can use up the address's limits. Of the older kind, which a relay carries for one version more: a state can carry no key above its own version, and a key above a channel's version is no part of its key ring. Of messages between a person's agents nothing is carried: the new generation's messages channel starts empty, each device shows what it held of the one before until each message expires, and a message from the removed device is shown by `cordelia msg log` alone. A removed device shows no message and sends none, and `read` and `log` are refused there; it still reads, from the channel it held, what was sent there in each generation it was in, and nothing that a device which has applied the removal sends (the decision record of 2026-10-09, section 9.1) | tested |
| T17 | Another program running as the same user, an agent with a shell among them | Read the node's files and memory, call its local API, and run its commands | Nothing. Cordelia does not defend against this; real separation needs separate users or machines. Such a program can read the node's database, which holds the person secret, and so read every name. It can make every call of the local API with the node's token. It can give a command a terminal, read what it prints and type its yes: so it can add a device, accept one, make a new phrase on this device, or give the device a new key. What is left is that every device shows an addition, and a device that has left, until a person clears it there (an addition also until a statement lists the device); and that nothing which asks for the recovery phrase is done without it, which is T20's claim. With the routes of messages between a person's agents (the decision record of 2026-10-09, section 4.2) such a program can also put text in front of the agents on the person's other devices, framed as a request from an agent of the person's, at most 20 an hour for each folder it names and 60 an hour for the device: a weaker channel than writing their memory, which it already could. It can name any mapped folder, or none for `log`, so it can send as any agent of the device, read any agent's messages and mark them read, which hides them from that agent's summary on every device, and list every name's messages. It can give `log` the IDs to mark as read by a person, and so end a hold between two agents: neither the route nor the command can tell a person from a program, beyond asking for a terminal and a yes, which a program can give. It cannot sign as another device, make a reader take as a message what is not one, make a reader show more than 64 messages from this device in an hour, make a message last past its 30 days on another device, reach anything but the person's names, or have a message do anything but be shown | not defended |
| T18 | Anyone who carries or stores an entry | Move it to another channel, give it another name, present an old revision as a newer one, change its content, or forge its author | Each of these makes the entry fail a signature or fail to decrypt, and it is ignored. An entry of a channel from its secret has two signatures over one thing, the author's and the channel's, each under a label of its own: its channel, its slot, its author, its revision, whether it is a delete, and the hash of its content. Its content opens only for that channel, slot and revision, and its slot must be the slot of the name inside. An item of the older kind is signed by its author and bound to its channel, slot and revision in the same way | tested |
| T19 | Someone who claims to be another device or relay, or answers for a relay's name | Connect, or answer, under another node's key, to take over its connection or be taken for it; pose as a device's relay and send the device elsewhere; say it is a relay, to be sent what relays are sent; replay a proof that another connection made | A node's ID is the key its TLS certificate proves, so nobody can connect or answer under a key they do not hold. A node knows its relays by name and key, refuses any other key at a relay's address, and dials nothing but its configured relays. Being a relay is a matter of configuration: a node that merely says it is one is an ordinary peer, and is not told which channels a node holds, of either kind. The relays that a relay works with are the ones its operator lists by key: the stream between relays is refused for every other peer, whatever address it comes from and whatever it says of itself. A proof that a connection holds a channel's key is made over a value of the one TLS session and the node key of the end that makes it: it holds on no other connection, at no later time, and not when it is sent back to the end that made it | tested |
| T20 | A device of yours that has been taken over | Slip a key that is not one of your devices into your channels; add or remove devices; have the recovery phrase sign what you were not shown; use up what a phrase can do, so that the device can never be removed | Only the recovery phrase changes who is removed, and nothing undoes a removal: no device removes another without it, and no statement brings a removed key back. The phrase is typed at the command's own terminal and stays in that process, which cannot be dumped or traced. The node never holds it, and no word of it reaches the node, its log or its files: at a removal, at a recovery, and where a new phrase is made. What a command waits for after it has signed, it waits for in a process that never held the phrase. The command shows the statement's lists from the bytes it is about to sign, so a node that is taken over cannot have the phrase sign a list that the person was not shown, and a change is made only over what the prompt showed. A device that is taken over can add a device without the phrase: that is made visible, not prevented. Every device shows the addition, with who added it and when, and its status line is amber, until a person clears it there or a statement lists the device; a device added by one that was itself added since the last statement may not add; a removed key that a record adds again does not count; at most 64 devices count; and the next statement asks of each device added since whether it stays, with no answer suggested. Bytes that are not a usable key (not a point on the curve, or a point that is not of the order every real key has) are never a device: such a key is not added, not accepted and not removed, nothing is sealed to it, and an entry under one is refused, since under a point of small order the secret is one anyone can work out, and anyone can sign. Two changes made apart stop every device that sees both, until a person settles them with the phrase. Not defended (the decision record of 2026-10-04, sections 6 and 12): a device that is taken over holds the person secret and reads every name until the next removal, with no sign; and a device that counts can use up the 256 keys a phrase can remove, with additions that the person then declines. Of the two things that issue #76 asks for, the first is built: a new device is announced on every other device, in its status, on its status line and in `cordelia devices`, until it is cleared there. The second is not: the rule that a device adds and removes nothing in its first day is not built. Of the older kind, which a relay carries for one version more: the counter that orders changes to a channel's members is bounded, and a state is sealed to no key that is not usable | partly tested (#76) |
| T21 | You, or an agent of yours, by mistake | Replace or delete memory on one device, so that every device follows | Every device on this version that took the change holds the text it replaced, for 30 days and within the newest 256 MB, and so does the device that made it. A person who looks can put any kept version back with one command, on any device that holds it, and where the folder syncs every device follows. A text that cannot be kept is not replaced. Nothing notices the mistake: a change that nobody looks for within 30 days is gone. History is on the device, in the clear, and an agent there can drop it or turn it off | tested |
| T22 | An agent of yours that was misled: it read something that told it to | Send from its folder up to 20 messages an hour, and from any other mapped folder of its device by running the command there, up to 60 an hour for the device, to any name of yours or to every name; read the messages of every agent of its device, and mark them read so that the agent they were for is not shown them on any device; send between two agents until a hold stops it; cause a hold between two other names on every other device, by mapping a folder under one name and sending ten to another; end a hold by giving `cordelia msg log` a pseudo-terminal and typing yes; save what it read as a note of its own, which then syncs as memory | A message is a request, never an instruction, and nothing structural travels as one: nothing a message holds changes anything on a device but marks, and no part of one is written to a memory folder, to local history or to any file outside the node's data directory. Some limits hold against a holder of the device's key, because each reader keeps them: an entry of one size, with a body of at most 1,024 bytes; a signer that counts; a message only in a slot named for its signer, at a number in that slot's place; at most 64 numbers of a signer in a reader's rows, however many it writes; at most 64 messages of a signer given a place in an hour on each reader, the newest first; 30 days from when a reader first held it; a frame that every reader prints, which a body cannot close, and which says that the message is not from the person and is not to be copied into memory; and that nothing is shown as from the person. Others hold only against an honest command, because the sender keeps them: 20 messages an hour from a folder and 60 from a device; the hold, which stops a device sending between two agents once ten messages between them are unread by a person there, until a person reads them with `cordelia msg log` at a terminal and types yes; which agent sent (the device is proved, and the agent is that device's word); the time it says it was sent; its thread and what it answers; whether it asks for an answer; the clearing at 30 days; and the marks of what its agents read, which a device that lies in its list can use to hide messages from the other devices' summaries, and not from `log` or `read`. Not defended (the decision record of 2026-10-09, sections 11 and 15): an agent that does what a body says because it was persuaded, which the frame tells what the text is and nothing more; a program that ends a hold with a pseudo-terminal and a yes; and an agent that copies what it read into its memory | tested |

## Tests

### T1
- `crates/cordelia-node/tests/threat_model.rs`: `t01_a_relay_holds_nothing_it_can_read`
- `crates/cordelia-node/tests/threat_model.rs`: `t01_a_device_tells_a_relay_only_a_channels_id`
- `crates/cordelia-network/src/channel_announce.rs`: `an_announcement_says_nothing_about_the_channel_but_its_id`
- `crates/cordelia-crypto/src/entry.rs`: `the_padding_hides_the_length_within_a_size_class`
- `crates/cordelia-crypto/src/entry.rs`: `a_content_is_one_of_nine_sizes`
- `crates/cordelia-node/tests/threat_model.rs`: `t01_a_relay_holds_no_message_it_can_read`

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
- `crates/cordelia-api/src/take.rs`: `test_an_entry_of_a_name_held_is_stored_only_if_its_signer_counts`
- `crates/cordelia-node/tests/relay_entries_e2e.rs`: `a_client_with_only_a_channels_id_gets_nothing`
- `crates/cordelia-node/tests/relay_entries_e2e.rs`: `a_pull_without_a_proof_is_handed_nothing`
- `crates/cordelia-storage/src/relay.rs`: `test_a_stranger_with_a_channels_id_and_no_key_gets_nothing`
- `crates/cordelia-storage/src/relay.rs`: `test_an_entry_with_either_signature_missing_or_wrong_is_refused`
- `crates/cordelia-storage/src/relay.rs`: `test_a_proof_is_checked_before_the_channel_is_looked_up_and_no_is_one_answer`
- `crates/cordelia-node/src/relay_entries.rs`: `a_channel_is_handed_only_to_a_connection_that_proved_it`
- `crates/cordelia-storage/src/relay.rs`: `test_a_slot_goes_only_where_every_authors_entry_is_an_old_delete`

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
- `crates/cordelia-node/tests/relay_entries_e2e.rs`: `a_relay_near_its_cap_takes_no_new_channel_and_drops_nothing`
- `crates/cordelia-node/tests/relay_entries_e2e.rs`: `an_address_may_make_a_relay_take_so_many_new_channels_an_hour`
- `crates/cordelia-node/tests/relay_entries_e2e.rs`: `the_limits_by_address_count_both_kinds_of_channel_together`
- `crates/cordelia-node/tests/relay_entries_e2e.rs`: `a_connection_may_make_so_many_requests_a_minute_on_the_streams_of_entries`
- `crates/cordelia-node/tests/relay_entries_e2e.rs`: `the_older_kind_syncs_through_a_relay_that_is_full_of_the_new_kind`
- `crates/cordelia-node/tests/relay_entries_e2e.rs`: `a_peer_that_shows_an_earlier_entry_again_and_again_is_handed_only_its_bytes`
- `crates/cordelia-node/tests/relay_entries_e2e.rs`: `a_relay_drops_what_nobody_has_used_for_90_days`
- `crates/cordelia-storage/src/relay.rs`: `test_the_older_kinds_room_and_this_kinds_do_not_touch_each_other`
- `crates/cordelia-node/src/relay_entries.rs`: `a_key_that_has_pulled_all_it_may_is_still_handed_the_answer_to_a_show`
- `crates/cordelia-api/src/reader.rs`: `a_ring_slot_written_again_is_taken_by_a_full_relay`

### T10
- `crates/cordelia-api/tests/api_integration.rs`: `test_group_lifecycle`
- `crates/cordelia-api/src/person.rs`: `test_a_statement_is_applied_only_on_a_device_it_lists_with_its_secret`
- `crates/cordelia-api/src/take.rs`: `test_an_entry_of_a_name_held_is_stored_only_if_its_signer_counts`
- `crates/cordelia-api/src/person.rs`: `test_a_record_that_does_not_verify_or_whose_signer_does_not_count_is_not_kept`
- `crates/cordelia-api/src/reader.rs`: `a_message_in_a_slot_named_for_another_key_is_no_message`
- `crates/cordelia-crypto/src/message.rs`: `a_message_in_a_slot_named_for_another_key_is_no_message`
- `crates/cordelia-api/src/reader.rs`: `an_entry_whose_number_is_not_in_its_slots_place_is_no_message`
- `crates/cordelia-crypto/src/message.rs`: `an_entry_whose_number_is_not_in_its_slots_place_is_no_message`
- `crates/cordelia-node/tests/msg_e2e.rs`: `send_takes_only_a_name_of_yours_or_all`

### T13
- `crates/cordelia-api/src/adding.rs`: `test_a_hand_over_is_taken_only_from_the_key_typed_within_the_last_hour`
- `crates/cordelia-api/src/adding.rs`: `test_a_hand_over_made_long_before_the_key_was_typed_is_refused_in_each_row`
- `crates/cordelia-api/src/adding.rs`: `test_a_refused_hand_over_spends_no_key_and_an_old_typing_reads_nothing`
- `crates/cordelia-api/src/adding.rs`: `test_one_of_several_takes_only_a_change_it_can_apply_under_its_phrase`
- `crates/cordelia-api/src/adding.rs`: `test_a_device_alone_under_a_phrase_leaves_it_only_with_sync_off`
- `crates/cordelia-api/src/take.rs`: `test_a_device_that_follows_no_phrase_takes_nothing`
- `crates/cordelia-api/src/person.rs`: `test_a_device_that_follows_no_phrase_takes_no_change_entry`
- `crates/cordelia-node/tests/person_e2e.rs`: `a_device_is_added_by_two_commands_and_each_device_shows_it_until_it_is_cleared`
- `crates/cordelia-node/tests/person_e2e.rs`: `a_command_without_a_terminal_refuses_and_a_phrase_typed_back_wrongly_makes_nothing`
- `crates/cordelia-node/tests/device_entries_e2e.rs`: `the_door_for_a_typed_key_proves_and_pulls_that_keys_pair_channel_and_nothing_else`
- `crates/cordelia-node/tests/recover_e2e.rs`: `a_person_who_lost_both_devices_recovers_what_either_had_sent`
- `crates/cordelia-api/src/look.rs`: `test_a_device_added_since_is_shown_on_every_device_until_cleared_there`

### T16
- `crates/cordelia-api/tests/entries.rs`: `a_removed_device_can_no_longer_write`
- `crates/cordelia-node/tests/threat_model.rs`: `t16_a_removed_devices_last_entries_are_kept_and_its_later_ones_are_not`
- `crates/cordelia-api/tests/entries.rs`: `t16_a_removed_device_cannot_put_a_name_out_of_reach`
- `crates/cordelia-api/tests/entries.rs`: `t16_a_revision_meant_to_use_the_numbers_up_is_not_kept`
- `crates/cordelia-sync/src/plan.rs`: `a_channel_that_has_gone_back_keeps_this_devices_version`
- `crates/cordelia-node/tests/threat_model.rs`: `t16_a_relays_refusal_is_not_taken_for_delivery`
- `crates/cordelia-node/src/p2p.rs`: `a_relays_refusal_is_not_delivery`
- `crates/cordelia-node/src/p2p.rs`: `an_answer_that_does_not_add_up_delivers_nothing`
- `crates/cordelia-node/tests/threat_model.rs`: `t16_a_removal_is_offered_again_when_the_relay_loses_it`
- `crates/cordelia-crypto/src/channel_state.rs`: `a_key_above_the_current_version_is_not_a_valid_state`
- `crates/cordelia-storage/src/psk.rs`: `a_key_above_the_current_version_is_never_kept`
- `crates/cordelia-storage/src/psk.rs`: `a_key_that_was_waiting_is_not_kept_when_its_version_is_passed`
- `crates/cordelia-storage/src/psk.rs`: `a_key_that_was_waiting_does_not_survive_the_older_rotation`
- `crates/cordelia-api/src/several.rs`: `test_a_device_is_removed_and_the_others_apply_carry_and_take_nothing_it_signs`
- `crates/cordelia-api/src/several.rs`: `test_an_edit_of_what_a_removed_device_wrote_late_is_known_to_follow_no_other_text`
- `crates/cordelia-api/src/person.rs`: `test_a_version_another_key_signed_is_carried_with_that_key_in_a_first_link`
- `crates/cordelia-api/src/change.rs`: `test_a_change_brings_no_removed_key_back`
- `crates/cordelia-node/tests/person_e2e.rs`: `a_device_is_removed_with_the_phrase_and_stops_and_the_others_apply`
- `crates/cordelia-node/tests/memory_e2e.rs`: `a_removed_devices_later_edit_reaches_nobody_and_the_others_go_on_syncing`
- `crates/cordelia-node/tests/memory_e2e.rs`: `an_edit_made_before_a_device_heard_of_a_change_arrives_as_an_edit_of_the_carried_version`
- `crates/cordelia-node/tests/device_entries_e2e.rs`: `a_device_applies_the_change_that_its_relay_holds_before_it_sends_anything`
- `crates/cordelia-node/tests/device_entries_e2e.rs`: `a_device_that_wakes_takes_and_sends_nothing_until_every_relay_has_answered`
- `crates/cordelia-crypto/src/entry.rs`: `a_version_does_not_follow_past_a_signer_that_does_not_count`
- `crates/cordelia-crypto/src/change_entry.rs`: `a_device_that_is_not_listed_reads_the_statement_and_no_secret`
- `crates/cordelia-storage/src/relay.rs`: `test_a_relay_at_its_cap_takes_a_newer_revision_of_an_entry_it_holds_and_no_new_channel`
- `crates/cordelia-node/tests/carry_e2e.rs`: `what_a_removed_device_wrote_comes_in_only_by_from_with_the_phrase`
- `crates/cordelia-api/src/carrying.rs`: `test_what_a_removed_key_signed_comes_in_only_as_the_phrases_word_allows`
- `crates/cordelia-api/src/carry.rs`: `test_a_word_holds_only_as_the_phrase_gave_it`
- `crates/cordelia-api/src/carry.rs`: `test_a_delete_that_a_removed_key_signed_is_not_taken_and_the_file_comes_back`
- `crates/cordelia-node/tests/msg_e2e.rs`: `a_removed_device_is_shown_nothing_and_sends_nothing`
- `crates/cordelia-node/tests/msg_e2e.rs`: `a_statement_starts_an_empty_messages_channel_and_what_was_held_is_shown_until_it_expires`
- `crates/cordelia-node/tests/msg_e2e.rs`: `a_removed_device_reads_what_was_sent_in_its_generation_and_nothing_after_its_removal_was_applied`

### T18
- `crates/cordelia-network/src/item_sync.rs`: `test_verify_item_signature`
- `crates/cordelia-crypto/src/slots.rs`: `test_aad_binds_slot_and_rev`
- `crates/cordelia-api/tests/entries.rs`: `only_members_writing_the_right_key_count`
- `crates/cordelia-crypto/src/entry.rs`: `an_entry_with_either_signature_wrong_or_missing_is_refused`
- `crates/cordelia-crypto/src/entry.rs`: `each_clear_field_changed_after_signing_is_refused`
- `crates/cordelia-crypto/src/entry.rs`: `the_two_signatures_are_not_interchangeable`
- `crates/cordelia-crypto/src/entry.rs`: `an_entry_sealed_for_one_channel_slot_or_revision_does_not_open_under_another`
- `crates/cordelia-crypto/src/entry.rs`: `an_entry_whose_slot_is_not_the_slot_of_its_name_does_not_open`

### T19
- `crates/cordelia-network/src/transport.rs`: `a_certificate_that_names_another_key_is_refused`
- `crates/cordelia-network/src/transport.rs`: `a_client_that_names_another_key_cannot_connect`
- `crates/cordelia-network/src/transport.rs`: `a_server_that_names_another_key_is_refused`
- `crates/cordelia-node/tests/threat_model.rs`: `t19_a_device_refuses_another_key_at_its_relays_address`
- `crates/cordelia-node/tests/threat_model.rs`: `t19_a_device_asks_no_peer_for_addresses_to_dial`
- `crates/cordelia-network/src/bootstrap.rs`: `a_configured_relay_has_the_key_it_was_given_or_the_default_one`
- `crates/cordelia-node/tests/threat_model.rs`: `t19_a_stranger_that_says_it_is_a_relay_is_not_treated_as_one`
- `crates/cordelia-node/src/relay_entries.rs`: `a_peer_is_its_address_or_a_relay_that_the_operator_lists_by_key`
- `crates/cordelia-node/src/relay_entries.rs`: `the_stream_between_relays_is_for_a_listed_relay_and_no_other`
- `crates/cordelia-node/src/relay_entries.rs`: `a_proof_holds_only_over_this_connections_value_and_for_the_peer_that_sends_it`
- `crates/cordelia-crypto/src/proof.rs`: `a_proof_made_over_another_sessions_value_is_refused`
- `crates/cordelia-crypto/src/proof.rs`: `a_proof_sent_back_by_the_other_end_does_not_hold`

### T20
- `crates/cordelia-crypto/src/channel_state.rs`: `an_epoch_over_the_limit_is_not_a_valid_state`
- `crates/cordelia-storage/src/channels.rs`: `an_epoch_over_the_limit_is_neither_stored_nor_read`
- `crates/cordelia-crypto/src/identity.rs`: `a_key_that_is_not_a_point_or_is_of_small_order_is_no_key`
- `crates/cordelia-crypto/src/ecies.rs`: `a_secret_anyone_can_work_out_seals_and_opens_nothing`
- `crates/cordelia-crypto/src/channel_state.rs`: `a_state_is_sealed_to_no_key_that_is_not_usable`
- `crates/cordelia-api/tests/api_integration.rs`: `test_the_older_endpoints_seal_to_no_key_that_is_not_usable`
- `crates/cordelia-node/tests/threat_model.rs`: `t20_a_key_that_is_no_devices_is_not_added_accepted_or_removed`
- `crates/cordelia-crypto/src/entry.rs`: `an_entry_under_a_key_that_anyone_can_sign_for_is_refused`
- `crates/cordelia-api/src/adding.rs`: `test_adding_is_refused_on_a_device_or_for_a_key_that_may_not`
- `crates/cordelia-api/src/person.rs`: `test_a_removed_key_added_again_by_a_record_does_not_count`
- `crates/cordelia-api/src/person.rs`: `test_the_sixty_fifth_device_is_kept_as_not_counted`
- `crates/cordelia-node/tests/person_e2e.rs`: `no_word_of_the_phrase_reaches_the_node_its_log_or_its_files_at_a_removal`
- `crates/cordelia-node/tests/person_e2e.rs`: `no_word_of_a_new_phrase_reaches_the_node`
- `crates/cordelia-node/tests/person_e2e.rs`: `a_process_that_holds_the_phrase_cannot_be_dumped_and_the_wait_is_in_another_image`
- `crates/cordelia-api/src/change.rs`: `test_what_is_signed_is_the_statement_in_the_bytes_that_were_shown`
- `crates/cordelia-api/src/change.rs`: `test_a_change_is_made_only_over_what_the_prompt_showed`
- `crates/cordelia-api/src/change.rs`: `test_a_change_brings_no_removed_key_back`
- `crates/cordelia-node/tests/person_e2e.rs`: `a_device_is_added_by_two_commands_and_each_device_shows_it_until_it_is_cleared`
- `crates/cordelia-node/tests/person_e2e.rs`: `a_chain_of_two_is_asked_about_in_its_order_and_no_answer_is_suggested`
- `crates/cordelia-node/tests/person_e2e.rs`: `two_changes_made_apart_are_settled_with_the_phrase`
- `crates/cordelia-node/tests/recover_e2e.rs`: `a_person_who_lost_both_devices_recovers_what_either_had_sent`
- `crates/cordelia-api/src/look.rs`: `test_a_device_added_since_is_shown_on_every_device_until_cleared_there`

### T21
- `crates/cordelia-sync/src/claude.rs`: `what_another_devices_change_replaces_here_is_kept_in_history`
- `crates/cordelia-sync/src/claude.rs`: `what_this_devices_change_replaces_in_the_channel_is_kept_in_history`
- `crates/cordelia-sync/src/claude.rs`: `an_index_as_it_was_before_a_merge_is_kept_in_history`
- `crates/cordelia-sync/src/claude.rs`: `an_edit_that_was_overtaken_is_kept_in_history_as_well`
- `crates/cordelia-sync/src/claude.rs`: `a_text_that_cannot_be_kept_is_not_replaced`
- `crates/cordelia-sync/src/claude.rs`: `a_change_that_is_not_made_leaves_no_record`
- `crates/cordelia-storage/src/history.rs`: `test_a_record_is_dropped_when_it_is_old`
- `crates/cordelia-storage/src/history.rs`: `test_the_oldest_records_go_when_the_store_is_over_its_size`
- `crates/cordelia-storage/src/history.rs`: `test_a_record_stands_only_if_its_change_was_made`
- `crates/cordelia-api/src/history.rs`: `test_a_restore_puts_the_text_back_and_can_be_undone`
- `crates/cordelia-api/src/history.rs`: `test_a_restore_that_cannot_keep_what_it_replaces_does_nothing`
- `crates/cordelia-api/src/history.rs`: `test_a_restore_refuses_what_it_cannot_do_safely`
- `crates/cordelia-api/src/history.rs`: `test_a_damaged_record_is_not_restored_or_shown`
- `crates/cordelia-storage/src/history.rs`: `test_a_record_whose_text_is_not_the_one_kept_is_refused`
- `crates/cordelia-sync/src/claude.rs`: `a_name_that_has_come_to_hold_what_cannot_be_read_is_not_written_over`
- `crates/cordelia-sync/src/claude/sequences.rs`: `local_history_changes_nothing_in_what_sync_does`
- `crates/cordelia-sync/tests/claude.rs`: `a_cycle_that_keeps_enough_sweeps_local_history`
- `crates/cordelia-api/tests/api_integration.rs`: `test_history_needs_the_token_and_is_used_with_it`
- `crates/cordelia-node/tests/devices_e2e.rs`: `what_sync_replaced_or_removed_is_put_back_from_either_machine`
- `crates/cordelia-node/tests/devices_e2e.rs`: `local_history_is_kept_as_the_configuration_says`

### T22
- `crates/cordelia-node/tests/msg_e2e.rs`: `a_message_asking_for_a_structural_act_changes_nothing`
- `crates/cordelia-node/tests/msg_e2e.rs`: `no_message_reaches_a_memory_folder_local_history_or_any_file`
- `crates/cordelia-node/tests/msg_e2e.rs`: `a_body_is_read_inside_a_frame_that_it_cannot_close`
- `crates/cordelia-node/tests/msg_e2e.rs`: `a_folder_over_its_hour_sends_nothing_more`
- `crates/cordelia-api/src/reader.rs`: `a_holder_of_the_key_that_laps_its_ring_is_shown_at_most_64_in_an_hour`
- `crates/cordelia-api/src/marks.rs`: `a_device_that_lies_in_its_list_hides_from_summaries_and_not_from_log`
- `crates/cordelia-api/src/reader.rs`: `a_signer_that_rewrites_its_ring_ten_thousand_times_leaves_one_lap_in_a_readers_store`

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
