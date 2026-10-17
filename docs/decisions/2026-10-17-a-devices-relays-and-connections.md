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

Only one key answers at an address. When a node dials there, the key that answers reaches each relay there that was given it, and each that was given none. Each other relay there fails its own handshake, and its status says "wrong key". A relay is never dropped without a word.

Once a relay is connected at an address, the node does not dial that address again for another relay there. A second connection to the same relay would only replace the first. The other stays as its last dial left it.

The node also says in its log which relays share an address.

**One relay is counted once.** Two names may reach one relay: one given its key and one given none at its address, or two given the same key. The first in the configuration is the relay. Each other is listed as "same relay", and is left out of the relays that the device counts, paces, passes, and says hold the latest change. A relay that another key answers for at its address is listed with the wrong key, and is left out of them too while that connection lasts.

A relay is found by its name and its key together, in its status and in its tries: one name may be given twice, with two keys.

**Why.** A relay the person set up is the person's choice. A node that drops one leaves it out of the dialling, but not out of the status or the count of relays that hold a change: the status would give the wrong reason, and a relay given no key would have no connection at all. Keeping both makes each fault the relay's own, and the status names it.

**What does not change.** A relay with a key is known by its key, and one without by its address. A name that does not resolve is still listed, as unreachable.

**The tests that hold it.**

- `crates/cordelia-network/src/bootstrap.rs`: `two_relays_that_resolve_to_one_address_are_both_kept`.
- `crates/cordelia-node/src/p2p.rs`: `two_relays_at_one_address_are_each_listed_and_a_wrong_key_is_their_own`, `one_relay_under_two_names_is_one_relay`, `one_name_given_twice_with_two_keys_is_listed_by_its_key`, and `a_relay_whose_name_does_not_resolve_is_still_one_the_node_is_set_up_with` (a pass is given one relay under two names once).
- `crates/cordelia-node/tests/devices_e2e.rs`: `two_relays_at_one_address_are_each_kept_and_the_wrong_key_is_its_own`. A device runs as a real process, set up with one relay of the test's own under two names, one with the wrong key. One is listed with the wrong key, and the other stays connected; the relay took one connection from the device.
- `crates/cordelia-node/tests/devices_e2e.rs`: `one_relay_under_two_names_is_counted_and_paced_once`. A device is set up with one relay of the test's own, under one name with its key and under another with none. The second is listed as the same relay; the device's own list of its relays holds the first alone, and it holds the latest change.

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

After a statement every channel of the device's own is new. The old ones still hold their places at the relay. So where a channel the device proves finds no place on a connection, and channels it no longer proves hold places there, the device has the node make the connection again. The node closes it and dials the relay anew, as it does for a carry. A new connection starts with none remembered, and its places are the current channels'. The device asks this once for a connection, and asks nothing more on it: the pass at that relay ends there, and so does every pass until the connection is closed. The old connection's record goes from the device at its next pass.

**Why.** A connection to a relay can live for weeks. A person with many names, or a connection that lives across several statements, would find channels of the new generation never proved there, and so never synced through that relay. The device cannot drop a channel from its own record while the relay still remembers it. It would then believe it has room the relay does not give, and the relay would answer each proof beyond its bound as one that fails.

**What does not change.** Where every place is held by a channel the device still proves, nothing is asked: a new connection would have no more room. A carry still keeps places back for the device's own channels, and asks for its own new connection where it has none.

**The test that holds it.** `crates/cordelia-node/tests/device_entries_e2e.rs`: `a_connection_whose_places_are_held_by_a_left_generation_is_made_again`. The device proves its five channels on a connection, and a removal makes all five new. Where a relay remembers eight proofs for a connection, the device asks once for the connection to be made again, and proves nothing more on it; on the new connection it proves every channel of the new generation. Where a relay remembers sixteen, the new five are proved on the same connection, and nothing is asked.

## 5. A node's role

A configuration whose `network.role` is not `personal`, `relay` or `bootnode` is refused when it is loaded. The line says what the role is and which roles this version takes.

**Why.** The code goes by those three. A node of any other role, a typing slip included, loaded and was none of them. It took a part of each, by whichever test of its role it met: it listened as a relay does, dialled the relays it named as a personal node does, and dialled the addresses its peers handed it as a bootnode does. `keeper` was a role of an earlier design, and was dropped ([`2026-09-30-agent-memory-sync.md`](2026-09-30-agent-memory-sync.md) §4.2). It is refused too.

**What does not change.** A file that sets no role is a personal node. Every configuration that this repository writes, in the installer, the relays' deployment files, the examples and the tests, names one of the three or none, and loads.

**The tests that hold it.** `crates/cordelia-core/src/config.rs`: `test_a_role_that_this_version_does_not_know_is_refused` (a typing slip, a role in other case, `keeper` and an empty role are refused, each known role loads), and `test_the_configurations_in_this_repository_load`.

## 6. Hot churn and trusted peers

Hot churn moves a hot peer to warm once an interval. It now picks only among the peers that are not trusted, as `network-protocol.md` §5.4 step 6 says: a trusted peer that a swarm node dials alone, and a swarm member, are exempt.

**Why.** The governor picked from every hot peer, against the spec and its own comment. A swarm member is meant to be always hot.

**What does not change.** Warm churn is as §2 says. A node with no trusted peer churns its hot peers as before.

**The test that holds it.** `crates/cordelia-network/src/governor.rs`: `test_churn_hot_demotes_no_trusted_peer`. A trusted peer, a swarm member and a third peer are hot. Churn after churn demotes only the third.
