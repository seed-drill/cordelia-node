# Running a relay

A relay stores and forwards encrypted items for personal nodes. It holds
ciphertext only and never a key; its one secret is its own identity key,
created on first start and kept on its data volume. Personal nodes dial
relays by name, so two devices always have somewhere to meet, even when
they are never online at the same time (decision
[2026-09-30-agent-memory-sync](../../docs/decisions/2026-09-30-agent-memory-sync.md) §4.6).

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
- **A release (preferred):** `CORDELIA_VERSION` (e.g. `v0.2.0-alpha.1`) and
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

- items stored and their encrypted size, and the database size;
- distinct peers seen in the last day and week, relays counted apart;
- channels that received an item in the last day and week.

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

The identity stays on the `cordelia-relay1-data` volume. Do not delete that
volume: a relay with a new identity still works, since nodes find relays by
name, but there is no reason to change it.

## 7. Your own relay

Copy `relay1.toml`, change `entity_id`, and list whichever relays yours
should mesh with under `[[network.bootnodes]]`. With none listed, it stands
alone: a relay never dials relays it was not told about. Run the same image with your
file mounted and `CORDELIA_CONFIG` pointing at it. Then add your relay's
`host:9474` under `[[network.bootnodes]]` in the config of each node that
should use it. A relay can only ever see ciphertext, whoever runs it.

## Fly.io (optional)

`fly.relay1.toml` runs relay1 on Fly.io instead: UDP there needs a dedicated
IPv4 and a bind to `fly-global-services` (set through `CORDELIA_LISTEN_ADDR`),
with the same port inside and out. Pin the release in its `[build.args]`,
then deploy from the repository root with
`fly deploy . --config deploy/relay/fly.relay1.toml --remote-only`.
