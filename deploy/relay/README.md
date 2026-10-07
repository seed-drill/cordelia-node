# Running a relay

A relay stores and forwards encrypted entries for personal nodes. It holds
ciphertext only and never a key; its one secret is its own identity key,
created on first start and kept on its data volume. Personal nodes dial
relays by name, so two devices always have somewhere to meet, even when
they are never online at the same time (decision
[2026-09-30-agent-memory-sync](../../docs/decisions/2026-09-30-agent-memory-sync.md) §4.6).

**This version carries two kinds of channel,** and section 6 says what that
means for an upgrade:

- **A channel from its secret**
  ([decision 2026-10-04](../../docs/decisions/2026-10-04-a-persons-devices.md)
  §2.4, §2.5). Every channel of a person's devices is of this kind from this
  version on. A relay stores an entry of one only if both of its signatures
  hold, hands a channel only to a connection that has proved it holds the
  channel's key, and tells nobody which channels it holds, the relays it
  works with aside.
- **The older kind,** which a relay goes on carrying as it did, for one
  version more, so that a device that has not been upgraded is not cut off
  in the middle.

Seed Drill operates two relays, `relay1.cordelia.seeddrill.ai` and
`relay2.cordelia.seeddrill.ai`. They list each other, so they form a mesh,
and every node dials both by default. This guide is how they are set up;
anyone can run a relay the same way (see the end).

| File | What |
|---|---|
| `compose.yml` | Docker Compose for one relay, hardened (section 3) |
| `relay.env.example` | Settings to copy to `.env`: which relay, and exactly what to deploy |
| `Dockerfile` | The image: a pinned release binary checked against its sha256, or a build of this checkout. Base images pinned by digest. |
| `entrypoint.sh` | First start creates the identity (`cordelia init`); every start runs the node |
| `relay1.toml`, `relay2.toml` | Relay config; each lists the other relay |
| `fly.relay1.toml` | Optional: the same relay on Fly.io |

## 1. What the host needs

- **An always-on Linux host,** such as an Ubuntu 22.04+ VM: 1 vCPU and
  1 GB RAM. Building from source (section 2) wants about 4 GB RAM and 10
  minutes once; deploying a release does not.
- **Docker Engine with the Compose plugin and BuildKit** (the default):
  ```bash
  sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 git
  sudo usermod -aG docker "$USER"      # then log out and in again
  docker compose version               # must print a version
  ```
- **UDP 9474 reachable from the internet,** at the same port number, for
  example by a port-forward from the site's public IPv4. The host also needs
  outbound UDP, to reach the other relay.
- **The host firewall open for it.** The relay uses the host's network
  directly, so the host firewall applies: `sudo ufw allow 9474/udp`. Nothing
  else needs opening; the relay's API listens on 127.0.0.1:9473 only.

## 2. Choose exactly what to deploy

```bash
git clone https://github.com/seed-drill/cordelia-node.git
cd cordelia-node
cp deploy/relay/relay.env.example deploy/relay/.env
```

Then edit `deploy/relay/.env`:

- `RELAY=relay1` or `RELAY=relay2`.
- **A release (preferred):** `CORDELIA_VERSION` (e.g. `v0.2.0-alpha.8`) and
  `CORDELIA_SHA256`, the sha256 of `cordelia-linux-amd64` from that release's
  page (its `.sha256` file). The image build downloads the binary and refuses
  it if the hash differs.
- **Before the first release:** `CORDELIA_SOURCE=build`, and check out the
  agreed commit first (`git checkout <sha>`). Record it: that commit is what
  the relay runs.

`.env` stays on the host; git ignores it.

## 3. Start it

```bash
docker compose -f deploy/relay/compose.yml up -d --build
```

The container is `cordelia-relay1` (or `cordelia-relay2`) and its data volume
is `cordelia-relay1-data`. It restarts always, including when the host boots.
It runs hardened:

- as an unprivileged user (uid 10001), on a read-only filesystem, with a
  small writable `/tmp`;
- with every Linux capability dropped and `no-new-privileges`;
- with memory (512 MB) and process (512) limits;
- with a healthcheck, `cordelia peers`, which fails when the node stops
  answering: `docker ps` shows `(healthy)`.

## 4. Check it

1. **Logs.** `docker logs cordelia-relay1` shows, on first start:
   ```
   cordelia-relay: first start, creating identity in /data/cordelia
   cordelia-relay: node key cordelia_pk1...        <- the relay's public key; record it
   ... P2P endpoint listening ... 9474
   ```
2. **Status.** `docker exec cordelia-relay1 cordelia status` ends with:
   ```
   Node:
     Running:   yes, up 2m 10s
     Peers:     1 hot, 0 warm
     Sync errors: 0
   ```
   Peers stay at 0 until the other relay is running and both DNS names
   resolve (step 4). Then each relay shows the other within a minute.
   `docker exec cordelia-relay1 cordelia peers` lists each connected peer:
   its key, role, address, how long it has been connected, and when it was
   last heard from.
3. **Restart keeps the identity.** `docker restart cordelia-relay1`, then
   `docker logs --tail 5 cordelia-relay1`: the same node key, and no "first
   start" line.
4. **DNS.** In Cloudflare, zone `seeddrill.ai`: an **A** record
   `relay1.cordelia` (or `relay2.cordelia`) pointing at the public IPv4 that
   forwards to the host, with the proxy **off** ("DNS only", grey cloud),
   because Cloudflare's proxy does not carry QUIC. No AAAA record.
   `dig +short relay1.cordelia.seeddrill.ai` should print that address.
5. **From outside.** On a machine on another network (not the relay's own,
   whose router may not loop back to its public address), a node with the
   default config dials both relays: `cordelia init`, `cordelia start`, then
   `cordelia status` shows `Peers: 1 hot` or more.

## 5. Watch it

`docker exec cordelia-relay1 cordelia stats` (add `--json` for tools) shows
what the relay holds and how much it is used, as counts only:

- the database size;
- **the room of each kind of channel, each against its cap** (`Storage:`,
  two lines):
  ```
  Storage:          2.0 KB in use of 16.0 MB allowed, by channels of the older kind
                    3.0 MB in use of 16.0 MB allowed, by channels from their secrets (2 held, 1 entry)
  ```
  The second line also says how many channels from their secrets the relay
  holds, and how many entries. With `--json` the older kind is
  `storage_used_bytes` and `storage_max_bytes`, and the channels from their
  secrets are the same two under `entries`, with `channels_held`,
  `entries_stored` and `content_bytes_stored`;
- items of the older kind stored, and their encrypted size (`Stored:`);
- distinct peers seen in the last day and week, relays counted apart;
- channels of the older kind that received an item in the last day and week.

**Storage: two caps of one size.** `max_storage_bytes` (under `[node]` in
the relay's config; 1 GiB if not set) is the most a relay holds of each kind
of channel. The older kind is counted against it, and the channels from
their secrets are counted against a cap of the same size, apart. Neither
kind is refused or dropped to make room for the other. **So for the one
version that carries both, a relay can hold twice its cap:** give the data
volume room for that, and for the database's own overhead.

**What is counted.** Each entry counts as its encrypted content and 1 KB,
for both kinds, and not as the pages of the database. So an entry that
replaces one of its size changes nothing, and the figure falls when a
channel is dropped, where the file does not shrink. The two lines of
`Storage:` in `cordelia stats` are that figure for each kind.

**At a cap, for a channel from its secret,** a relay favours the channels
it has held longest:

- where the first entry of a channel it does not hold would take it past
  its cap, it takes none of it;
- a write that would take it past its cap is refused, and drops nothing;
- a newer revision of an entry it holds, that is no larger, is never
  refused for room;
- a relay whose cap has come down drops the channels it has held for the
  shortest time, when it starts: the cap is read then and at no other time;
- one channel may hold 16 MB, and one address may make it take 256 new
  channels an hour;
- a channel whose key nobody has proved, and of which nobody has shown an
  entry that the relay holds, for 90 days is dropped.

**Old deletes are swept.** An entry says in clear whether it is a delete,
and a relay reads nothing else of it. Once an hour a relay drops each slot
in which every entry that it holds, of every author, is a delete that it has
held for 90 days (decision 2026-10-04 §2.3):

- a slot in which one device's delete stands beside another device's text
  stays whole, since a relay has no list of who counts: no key's delete
  sweeps away what another key wrote;
- the channel's room follows, so the second line of `Storage:` falls, and a
  channel of which nothing is left is held no more;
- a delete that a device carries at a change of its person's devices is a
  new entry, in a new channel: its 90 days start again there;
- the log says how many entries went ("swept the deletes that this relay
  has held for 90 days").

The older kind's deleted keys are collected on the same hourly timer, after
the same 90 days, as before.

**At its cap, for the older kind,** a relay takes no channel it does not
already hold, and a write that takes it over makes it drop the channels it
has held for the shortest time, until it is under. One channel may hold 16
MB, and one address may make it take 16 new channels an hour.

Nothing is lost for good by a drop while a device holds the channel: every
device holds its channels whole, and sends a relay what it lacks. A relay
that stays full needs a larger cap.

The same counts are on the node's `/api/v1/metrics` (Prometheus format,
127.0.0.1:9473, bearer token in `node-token` on the data volume) as
`cordelia_peers_seen`, `cordelia_channels_active`, `cordelia_items_stored`
and `cordelia_content_bytes_stored`.

To count distinct peers, a relay keeps a keyed hash of each peer's public
key, made with a secret that never leaves the relay, and drops it 8 days
after the peer was last seen. It keeps no list of keys.

## 6. Upgrade

Change the pin in `deploy/relay/.env` (a new `CORDELIA_VERSION` and its
`CORDELIA_SHA256`, or check out a new agreed commit), then:

```bash
docker compose -f deploy/relay/compose.yml up -d --build
```

Read the release's upgrade notes first.

**Upgrading to this version: relays first, then devices.** A device on this
version has only channels from their secrets, which a relay of the version
before does not carry. A relay on this version carries both kinds, so a
device that is still on the version before goes on through it as it did.
(The whole order, for a person, is in section 10 of
[decision 2026-10-04](../../docs/decisions/2026-10-04-a-persons-devices.md).)

Before you upgrade a relay:

1. **Check that the older kind fits its cap as it is now counted.** The
   version before sets the cap against the pages of the database. This one
   sets it against the items: each its encrypted content and 1 KB. A relay
   with many small items can come out over its cap by that count. On the
   version before, `cordelia stats` prints `Stored: N items, X of encrypted
   content` (`items_stored` and `content_bytes_stored` with `--json`): N KB
   and X together must be within `max_storage_bytes`. If they are not, raise
   `max_storage_bytes` before the upgrade. A relay that is over its cap
   drops the channels of the older kind that it has held for the shortest
   time, at its next write, until it is under.
2. **Give the volume room for twice the cap,** as above.
3. **List by key each relay that this one works with** (section 7). A
   default relay named without a key has the key that is compiled in.

The schema's steps are run when the relay starts, and change no row that is
there. A relay makes no copy of its database and takes no step that empties
what it holds of the older kind: that is what a personal node does at its
first start on this version, and only a personal node. After the upgrade,
`Storage:` in `cordelia stats` shows what each kind is counted at, each
against its cap.

- **A data directory is one node's.** A relay takes a lock on its data
  directory when it starts (a file in it, `node.lock`). A second node that
  is started on the same volume says that another is running there, changes
  nothing, and stops.
- **A database from a later version is refused.** A relay that finds its
  database at a later schema version than its own names both versions,
  changes nothing, and stops: install the later version again.
- A relay that is started on a database which a personal node has used
  removes the guard that the personal node set there (a trigger that refuses
  a new channel of the older kind), and says so in its log.

The identity stays on the `cordelia-relay1-data` volume. Do not delete that
volume, and keep a copy of the key somewhere safe. Devices know a relay by
its name and by its key, and refuse any other key at its address. A relay
that comes back with a new identity is refused by every device until they
are told the new key: a new release, for the default relays; the `key` in
each device's config, for a relay of your own.

The database on that volume can be lost, and nothing is lost for good while
a device holds what it held. A relay is a cache: it pulls what it lacks from
the relays it works with, and each device sends it what it has not been
sent. For the older kind it also asks its devices, when they connect and
every ten minutes after. It takes at most 256 new channels from their
secrets an hour from one address (16 of the older kind), and 2 MB a minute
from one device, so a large refill takes a while. A channel that comes back
is new from then: the relay has held it since it took it again, unless a
relay it works with has held it longer.

Up to 0.2.0-alpha.4 a relay asked only its hot peers. Two relays that list
each other are each other's hot peer, so their devices were not asked. With
relays on such a version, do not rebuild them all at once.

## 7. Your own relay

Copy `relay1.toml`, change `entity_id`, and list whichever relays yours
should mesh with under `[[network.bootnodes]]`. With none listed, it stands
alone: a relay never dials relays it was not told about.

**Relays that work together are listed by key.** Give each such relay's
`key` (what `cordelia id` prints on it) beside its `addr`, on each of them.
Two relays that list each other by key pass the entries of channels from
their secrets between them without the proof of a channel's key, tell each
other which channels they hold, how long each has held a channel and when it
was last used, and are not counted against each other's limits. A relay
that is listed by address alone is not one for that, whatever address a
peer comes from and whatever it says of itself: whoever came from that
address would be handed every channel. So list by key only relays that you
run, or that you would hand every channel to. Run the same image with your
file mounted and `CORDELIA_CONFIG` pointing at it. Then add your relay's
`host:9474` and its key (what `cordelia id` prints on the relay) under
`[[network.bootnodes]]` in the config of each node that should use it:

```toml
[[network.bootnodes]]
addr = "relay.example.org:9474"
key = "cordelia_pk1..."
```

Without a `key`, a node accepts whichever node answers at that address, and
warns of it when it starts.

A relay can only ever see ciphertext, whoever runs it.

## 8. What a relay learns, and what is not defended

**What a relay still learns** of channels from their secrets (decision
2026-10-04 §2.4): channel IDs, and all of a person's change at once when a
device is removed; authors' keys; slots, revisions, and which entries are
deletes; sizes by class (an entry's content is padded to a power of two);
timing; which connection proved which channel; each pair of devices that
meet in a pair channel; each time a recovery phrase is used; and, in the ID
of the phrase's channel, one thing that stays the same for a person for as
long as the phrase does and that each of their devices presents. It learns
no content, no name of a file or a project, and no key.

**What is not defended** (decision 2026-10-04 §2.5), which an operator
should know:

- **A relay that is full takes no new channel.** A removal is still heard
  through it, since the entry that carries one replaces the one before it at
  the same size, in a channel the relay already holds. But the channels
  that follow a removal are new, and memory does not sync through that
  relay until it has room.
- **Whoever holds the keys of channels can fill them to their caps, and can
  keep them.** A removed device holds every channel of the generation it was
  in. It can go on proving them, so they are never "what nobody uses", and
  their room is not given back by the 90 days. A relay that is then full
  takes none of the channels that follow. And a relay that is over its cap
  drops its newest channels, whoever wrote in the old ones.
- **The allowance of new channels, the limit on connections and the limit
  on bytes are all by address.** A removed device that is still at the same
  address as the others, or a stranger behind it, can use each up, and a
  change and the channels that follow it then wait at that relay. Three
  breaches of a limit refuse the whole address for fifteen minutes.
- **A relay that drops the phrase's channel and takes it again counts it as
  new from then.** It is otherwise the channel of a person's that a relay
  has held longest, and the last of theirs to go.
- **The older kind of channel takes whatever any key signs.** That is why
  the two kinds have a cap each: under one cap, whoever filled the older
  channels would push out every upgraded person's new ones, and whoever
  made new channels without end would push out everyone who had not yet
  upgraded.

A second relay is the way round a relay that is full or whose limits are
used up, and it helps against a removed device only if it is one that
device did not know.

## Fly.io (optional)

`fly.relay1.toml` runs relay1 on Fly.io instead: UDP there needs a dedicated
IPv4 and a bind to `fly-global-services` (set through `CORDELIA_LISTEN_ADDR`),
with the same port inside and out. Pin the release in its `[build.args]`,
then deploy from the repository root with
`fly deploy . --config deploy/relay/fly.relay1.toml --remote-only`.
