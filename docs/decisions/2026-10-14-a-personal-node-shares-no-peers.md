# Decision: a personal node shares no peers

**Date**: 2026-10-14
**Status**: Built.
**Cited as**: code comments cite this record as "decision 2026-10-14".

Words used throughout:

- **A request for peers** is a `PeerShareRequest` on a stream of Peer-Sharing (`network-protocol.md` §4.3), and **the answer** is the `PeerShareResponse` to it.
- **A personal node** is a node whose role is `personal`: a person's device, such as a laptop or a desktop.

---

## 1. What a personal node answers

A personal node answers every request for peers with an empty list. It does so whatever it is connected to, and whoever asks.

It still answers. Peer-Sharing runs on every warm and hot peer ([`2026-03-15-peer-state-semantics.md`](2026-03-15-peer-state-semantics.md), consequence 3), so a relay that asks a device is answered as it is answered by any peer. It does not refuse the stream and does not close it. The answer simply names no peer.

## 2. Why

A person's relays are theirs. A device is set up with the relays it uses, and each of them is the person's choice.

One relay has no need to learn the others from a device. A relay learns its peers from its operator's configuration. A device asks no peer for peers at all: it has no use for an answer, since it dials only the relays it is set up with.

A device must not be the way that a relay learns of another. A person may keep a relay of their own private, and use it beside a public one. The device is connected to both, and tells neither of the other.

So a device has nothing to give in answer, and gives nothing.

## 3. What does not change

- A relay and a bootnode answer a request for peers as before: with the relays and bootnodes they are connected to, shuffled, up to the number asked for.
- A personal node still dials only the relays it is set up with, and asks no peer for others.
- A personal node's own address is still shared by no one (`network-protocol.md` §4.3).

## 4. The tests that hold it

- `crates/cordelia-node/src/p2p.rs`: `a_personal_node_answers_a_request_for_peers_with_none`. A node is connected to two relays, and one of them asks it for peers. As a personal node it answers with an empty list. As a relay, and as a bootnode, it answers with both relays.
- `crates/cordelia-node/tests/threat_model.rs`: `t19_a_device_tells_no_relay_of_its_other_relays`. A device runs as a real process, set up with three relays of the test's own. The third asks it for peers over the connection that the device made, and the answer is empty.
