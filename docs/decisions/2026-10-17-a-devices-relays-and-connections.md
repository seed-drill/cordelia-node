# Decision: a device's relays and its connections

**Date**: 2026-10-17
**Status**: Built.
**Cited as**: code comments cite this record as "decision 2026-10-17".

Words used throughout:

- **A relay a device is set up with** is one that its configuration names under `[[network.bootnodes]]`: a name to dial, and the key that must answer there where one is given.
- **A personal node** is a node whose role is `personal`: a person's device, such as a laptop or a desktop.
- **Churn** is what the governor does once an interval (`churn_interval_secs`): it closes some warm peers, so that others may take their place (`network-protocol.md` §5.4, steps 6 and 7).

---

## 1. Two relays at one address

A node keeps every relay it is set up with whose name resolves. Two relays whose names resolve to one address are both kept, each with its own name and key.

Only one key answers at an address. When a node dials there, the key that answers reaches each relay there that was given it, and each given none that is not at a keyed relay's place (below). Each relay there that was given another key fails its own handshake, and its status says "wrong key". A relay is never dropped without a word.

Once a relay is connected at an address, the node does not dial that address again for another relay there. A second connection to the same relay would only replace the first. The other stays as its last dial left it.

The node also says in its log which relays share an address.

**One relay is counted once.** Two names are one relay only where the configuration gives both the same key; one name given twice with no key is also one. There is no other way to make two names one: a name given no key is always a relay of its own. The first in the configuration is the relay. Each other is listed as "same relay", and is left out of the relays that the device counts, paces, passes, and says hold the latest change. A relay that another key answers for at its address is listed with the wrong key, and stays among the relays the device counts, with no connection, as a relay out of reach does. So while it fails the device never takes every relay for connected: it forgets nothing of that relay, and does not say that it has sent what it carried. It is out of reach after five minutes, though it is not dialled, and the carried word may then be written ([decision 2026-10-19](2026-10-19-a-relay-out-of-reach.md)).

**A relay given no key is never taken for another relay.** It is at a keyed relay's place where its name resolves to the address of a relay the device is set up with that was given a key, or where that relay's key answers on the connection at its own address, whatever that relay's name resolves to, or whether it resolves at all. One connection there cannot tell which name it answers for, so none answers for this one by its own name. It stays among the relays the device counts, with no connection, and is never known to hold the change. Its status says "unreachable", and why and what to do: "given no key, at the address of <that relay>: give it that relay's key, or remove it from your configuration". The wait after a change says the same of it (S9), and the node warns of it in its log when the addresses change. While a connection is open at that address it is not dialled, and each tick of the dial loop that passes it over is a failed attempt at it, so it is out of reach after five minutes, and a change's wait ends at its third end ([decision 2026-10-19](2026-10-19-a-relay-out-of-reach.md) §1, rule 8). Given that relay's key, the two names are one relay.

**Two names given no key at one address** are two relays, each a relay of its own on the one connection there, whichever key answers, so long as it is the key of no relay the device is set up with. Neither is at a keyed relay's place: any key that answers suits both. The device counts two, but one connection that serves two relays is never counted as two: the device is not set up by key while it is so, so it forgets nothing of a relay and does not say that it has sent what it carried. To have the device count them as one, give the one name only.

**What is set from what.** Which names are one relay ("same relay") is set from the configuration alone: the same key given to both, or one name given twice with no key. It never changes from one look to the next. Whether a relay given no key is at a keyed relay's place is set at each look from the configuration (which relays were given a key), the address its own name resolves to, and the key that answers on the connection at that address. Neither is ever set from which connection a relay given no key was handed.

A relay is found by its name and its key together, in its status and in its tries: one name may be given twice, with two keys.

**Why.** A relay the person set up is the person's choice. A node that drops one leaves it out of the dialling, but not out of the status or the count of relays that hold a change: the status would give the wrong reason, and a relay given no key would have no connection at all. Keeping both makes each fault the relay's own, and the status names it.

A relay given no key was once taken for the relay whose connection answered at its address, afresh at each look. Its name might have been meant to reach another relay; a change's wait, the carried word, `sent` and the status could then be satisfied without it. Taking it for its own relay fails safe: the worst it does is wait for a relay that is in fact the other, and the status says why.

**What does not change.** A relay with a key is known by its key, and one without by its address. A name that does not resolve is still listed, as unreachable. A default relay named without a key takes the key compiled into the node, so it is a relay given a key: a name given that key is the same relay, and a name given no key at its address is not. A name that does not resolve at a lookup is still left out of the addresses until it resolves again, since each such lookup is a failed attempt at its relay ([decision 2026-10-19](2026-10-19-a-relay-out-of-reach.md) §1): a relay given no key is judged by the key that answers on its connection as well, so a keyed name left out does not let it be taken for that relay.

**The tests that hold it.**

- `crates/cordelia-network/src/bootstrap.rs`: `two_relays_that_resolve_to_one_address_are_both_kept`.
- `crates/cordelia-node/src/p2p.rs`: `two_relays_at_one_address_are_each_listed_and_a_wrong_key_is_their_own`, `one_relay_under_two_names_is_one_relay`, `one_name_given_twice_with_two_keys_is_listed_by_its_key`, and `a_relay_whose_name_does_not_resolve_is_still_one_the_node_is_set_up_with` (a pass is given one relay under two names given its key once).
- `crates/cordelia-node/src/p2p.rs`: `a_relay_given_no_key_at_another_relays_address_is_a_relay_of_its_own` (it is given to a pass with no connection, and counted, whichever name comes first, and with the keyed name missing from the lookup or moved while its connection stays open), `a_relay_given_no_key_at_a_keyed_relays_place_is_passed_over_and_comes_to_be_out_of_reach` (through the dial loop's turn, five minutes of ticks), `a_relay_found_at_a_keyed_relays_place_is_reached_no_more_at_once`, `two_names_given_no_key_at_one_address_are_two_relays_on_one_connection`, `one_connection_that_serves_two_relays_never_counts_as_two`, and `a_default_relay_named_without_a_key_takes_the_compiled_key`.
- `crates/cordelia-network/src/bootstrap.rs`: `a_relay_given_no_key_at_a_keyed_relays_address_is_warned_of`. `crates/cordelia-node/src/person_cmd/wait.rs`: `s9_says_what_to_do_of_a_relay_given_no_key_at_a_keyed_relays_place`.
- `crates/cordelia-node/tests/devices_e2e.rs`: `two_relays_at_one_address_are_each_kept_and_the_wrong_key_is_its_own`. A device runs as a real process, set up with one relay of the test's own under two names, one with the wrong key. One is listed with the wrong key, and the other stays connected; the relay took one connection from the device.
- `crates/cordelia-node/src/p2p.rs`: in `a_relay_whose_name_does_not_resolve_is_still_one_the_node_is_set_up_with`, two relays given keys of their own at one address, one reached: both are given to a pass, the second with no connection, and the device is not set up by key.
- `crates/cordelia-node/tests/device_entries_e2e.rs`: `a_relay_given_with_no_connection_keeps_what_the_device_says_and_forgets`. While a relay is given with no connection, the device forgets nothing of it and says no "sent"; reached again, it says so.
- `crates/cordelia-node/tests/devices_e2e.rs`: `one_relay_under_two_names_is_counted_and_paced_once`. A device is set up with one relay of the test's own, under two names given its key. The second is listed as the same relay; the device's own list of its relays holds the first alone, and it holds the latest change.
- `crates/cordelia-node/tests/devices_e2e.rs`: `a_relay_given_no_key_at_another_relays_address_is_counted_as_its_own`. A device is set up with one relay of the test's own, under one name with its key and under another with none at the same address. The second is listed as unreachable, stays in the device's own list of its relays, and is never said to hold the latest change; the first holds it.

## 2. Churn on a personal node

Churn never closes a personal node's connection to a relay it is set up with.

**Why.** Churn exists so that a node meets other peers, and an attacker cannot hold its place among them. A personal node has no other peers to meet. Every peer it dials is a relay the person chose. Churn would close one whenever another was down, and the node would dial it again within seconds. A device set up with three relays would drop one every hour, for nothing.

**What does not change.**

- A relay and a bootnode churn their warm peers as before.
- A personal node still moves its relays between hot and warm. The connection stays open: on a personal node the streams of entries do not go by that state.
- A connection to a relay that is dead is still closed, as is any dead connection.

`connection-lifecycle.md` §2.1 said that Peer-Sharing on a warm peer waits for a warm tenure. No code does that. Peer-Sharing is answered on any warm or hot peer, and the spec now says so. `min_warm_tenure_secs` is only what a warm peer waits before it may be made hot.

**The tests that hold it.**

- `crates/cordelia-network/src/governor.rs`: `test_a_personal_node_keeps_its_relays_through_churn`. A personal node has three relays connected and a fourth gone, so a peer is cold. Through five churn intervals it closes none of the three. A relay with the same peers closes a warm one at the first.
- `crates/cordelia-node/src/p2p.rs`: `a_nodes_governor_keeps_its_relays_through_churn_only_on_a_personal_node`. The governor is built as the node builds it, by its role: a personal node's keeps its relays, and a relay's and a bootnode's churn.
- `crates/cordelia-node/tests/devices_e2e.rs`: `a_device_keeps_every_relay_it_is_set_up_with_through_churn`. A device runs as a real process with four relays of the test's own, and churns every two seconds. The fourth stops. Through six churn intervals the other three stay connected on the connections they had.

## 3. The requests of the minute of a day's proofs

A device paces what it asks of a relay at 2,250 requests a minute (`OWN_ENTRY_REQUESTS_PER_MINUTE`), three quarters of what a relay allows a connection. This record says what that pace does in the busiest minute.

A device with 256 names asks 1,608 requests in a minute: a pull of each name, of its personal channel and of its messages channel every ten seconds, and a push every two seconds. That is within its pace.

Once a day on a connection, and when the connection is made, it also proves the key of each channel: as many as a relay remembers, 1,024. In that minute it would ask 2,632. The device holds the 382 over its pace back. Its pass at that relay stops where it is held. No place moves, and nothing is lost: the next pass goes on from the places it keeps. The next minute has room for 642 beside its pulls and pushes, so what was held back is asked within it.

**Why.** The test said that 2,632 is within what a relay allows. That is so, but the device never asks it: its own pace is lower. The test compared against the wrong number. Spreading the proofs would change nothing a relay sees, and would add code; the pace already does the spreading.

**What does not change.** No constant changes. A relay still sees no more than the device's pace on these streams, and the shows beside it, within its 3,000.

**The tests that hold it.**

- `crates/cordelia-core/src/protocol.rs`: `test_requests_on_the_streams_of_entries_decision_2026_10_04_16` now compares against the device's own pace, and checks that what is held back fits in the minute that follows.
- `crates/cordelia-node/tests/device_entries_e2e.rs`: `a_pass_held_by_its_pace_stops_and_moves_no_place`. Once the device has asked what it asks of a relay in a minute, a whole pass asks nothing of a channel, moves no place, sends nothing, and is short. A minute on, a pass goes on from the places it kept, and sends what waited.

## 4. The channels proved on a connection

A relay remembers the channels proved on a connection for as long as the connection lives, up to 1,024 (`MAX_CHANNELS_PROVED_ON_A_CONNECTION`). The device keeps what the relay remembers.

After a statement every channel of the device's own is new. The old ones still hold their places at the relay. So where a channel the device proves finds no place on a connection, and channels it no longer proves hold places there, the device has the node make the connection again. The node finds the connection by the relay's key, closes it and dials the relay anew, as it does for a carry. A new connection starts with none remembered, and its places are the current channels'. The old connection's record goes from the device at its next pass.

Where a channel of the device's memory has no place, the device asks nothing more on that connection: the pass at that relay ends there, and is short, and so does every pass until the connection is closed. Where the messages channel alone has none, the pass goes on and passes the messages channel over, which makes no pass short ([`2026-10-09-messages-between-your-own-agents.md`](2026-10-09-messages-between-your-own-agents.md) §2.1).

The device asks once while the node carries it out. Where the node answers that it did not (it found no such connection), the next whole pass may ask again: at most one asking a pass.

**Why.** A connection to a relay can live for weeks. A person with many names, or a connection that lives across several statements, would find channels of the new generation never proved there, and so never synced through that relay. The device cannot drop a channel from its own record while the relay still remembers it. It would then believe it has room the relay does not give, and the relay would answer each proof beyond its bound as one that fails.

**What does not change.** Where every place is held by a channel the device still proves, nothing is asked: a new connection would have no more room. A carry still keeps places back for the device's own channels, and asks for its own new connection where it has none.

**The test that holds it.** `crates/cordelia-node/tests/device_entries_e2e.rs`: `a_connection_whose_places_are_held_by_a_left_generation_is_made_again`. The device proves its five channels on a connection, and a removal makes all five new. Where a relay remembers eight proofs for a connection, the device asks for the connection to be made again, by the relay's key, and proves nothing more on it. Refused, the next pass asks again; carried out, no pass asks again. On the new connection it proves every channel of the new generation. Where a relay remembers sixteen, the new five are proved on the same connection, and nothing is asked.

Also: `a_place_taken_by_a_channel_held_no_more_leaves_the_messages_channel_none` (the messages channel alone asks, and the pass is not short), and in `crates/cordelia-node/src/p2p.rs`, `a_connection_to_make_again_is_found_by_its_key`.

## 5. A node's role

A configuration whose `network.role` is not `personal`, `relay` or `bootnode` is refused when it is loaded. The line says what the role is and which roles this version takes.

**Why.** The code goes by those three. A node of any other role, a typing slip included, loaded and was none of them. It took a part of each, by whichever test of its role it met: it listened as a relay does, dialled the relays it named as a personal node does, and dialled the addresses its peers handed it as a bootnode does. `keeper` was a role of an earlier design, and was dropped ([`2026-09-30-agent-memory-sync.md`](2026-09-30-agent-memory-sync.md) §4.2). It is refused too.

**What does not change.** A file that sets no role is a personal node. Every configuration that this repository writes, in the installer, the relays' deployment files, the examples and the tests, names one of the three or none, and loads.

**The tests that hold it.** `crates/cordelia-core/src/config.rs`: `test_a_role_that_this_version_does_not_know_is_refused` (a typing slip, a role in other case, `keeper` and an empty role are refused, each known role loads), and `test_the_configurations_in_this_repository_load`.

## 6. Churn, demotion and trusted peers

A trusted peer is never demoted and never evicted by churn, as `network-protocol.md` §5.3.1 and §5.4 say. A trusted peer is one that a swarm node dials alone, or a swarm member. The governor tells one in a single place, and three steps go by it:

- hot churn picks a peer to move to warm only among those that are not trusted (§5.4 step 6);
- warm churn closes no trusted peer (§5.3.1);
- the demotion of excess hot peers demotes no trusted peer (§5.4 step 5).

**Why.** The governor picked from every hot peer in hot churn, and from every warm peer in warm churn, against the spec. Its demotion spared swarm members alone. A swarm member is meant to be always hot.

**What does not change.** A personal node's relays are kept through churn as §2 says. A node with no trusted peer churns and demotes as before. Hot churn still promoted no warm peer in the place of the one it demoted, though §5.4 step 6 says it should: that was not changed here. It has been since: hot churn now promotes a warm peer in the place of the one it demotes, and demotes none where no warm peer may take its place (`network-protocol.md` §5.4 step 6).

**The tests that hold it.** `crates/cordelia-network/src/governor.rs`: `test_churn_hot_demotes_no_trusted_peer` (a trusted peer, a swarm member and two others are hot, and one more is warm; churn after churn demotes only the others), `test_churn_warm_closes_no_trusted_peer`, and `test_excess_hot_demotes_no_trusted_peer`.
