# Running a relay

A relay stores and forwards encrypted items for personal nodes. It holds
ciphertext only and never a key; its one secret is its own identity key,
created on first start and kept on its data volume. Personal nodes dial
relays by name, so two devices always have somewhere to meet, even when
they are never online at the same time (decision
[2026-09-30-agent-memory-sync](../../docs/decisions/2026-09-30-agent-memory-sync.md) §4.6).

Seed Drill runs two, `relay1.cordelia.seeddrill.ai` and
`relay2.cordelia.seeddrill.ai`, each as a Docker container on an Ubuntu VM in
one of our sites' DMZ. They list each other, so they form a mesh, and every
node dials both by default. This guide is how they are set up; anyone can run
a relay the same way (see the end).

| File | What |
|---|---|
| `compose.yml` | Docker Compose for one relay; `RELAY=relay1` or `RELAY=relay2` picks which |
| `Dockerfile` | The image: builds `cordelia` from this repository. No secrets in it. |
| `entrypoint.sh` | First start creates the identity (`cordelia init`); every start runs the node |
| `relay1.toml`, `relay2.toml` | Relay config; each lists the other relay |
| `fly.relay1.toml` | Optional: the same relay on Fly.io (not used for ours) |

## 1. What the host needs

- **An always-on Linux VM.** Ubuntu 22.04 or later, 1 vCPU and 1 GB RAM to
  run it. The first image build compiles Rust: allow about 4 GB RAM and 10
  minutes for that.
- **Docker Engine with the Compose plugin.** On Ubuntu:
  ```bash
  sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 git
  sudo usermod -aG docker "$USER"      # then log out and in again
  docker compose version               # must print a version
  ```
- **A public IPv4 that reaches the VM on UDP 9474.** Either the VM's DMZ
  address is itself public, or the site firewall forwards UDP 9474 on the
  public address to the VM's DMZ address, port 9474. Keep the port the same
  on both sides. The VM also needs outbound UDP, to reach the other relay.
- **Nothing else exposed.** QUIC on UDP 9474 is the only open port. The
  relay's HTTP API listens on 127.0.0.1 inside the container.

Docker publishes the port through its own firewall rules, which bypass
`ufw`: UDP 9474 is reachable whatever `ufw` says, so the site firewall is what
controls exposure. If the VM has more than one network interface, publish
only on the DMZ address by changing the `ports` line in `compose.yml` to
`"<dmz-address>:9474:9474/udp"`.

## 2. Start it

```bash
git clone https://github.com/seed-drill/cordelia-node.git
cd cordelia-node
RELAY=relay1 docker compose -f deploy/relay/compose.yml up -d --build
```

Use `RELAY=relay2` at the other site. `RELAY` picks the config and names the
container (`cordelia-relay1`) and its data volume (`cordelia-relay1-data`).
The container restarts on failure and when the VM boots.

## 3. Check it

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
3. **Restart keeps the identity.** `docker restart cordelia-relay1`, then
   `docker logs --tail 5 cordelia-relay1`: the same node key, and no "first
   start" line.
4. **DNS.** In Cloudflare, zone `seeddrill.ai`: an **A** record
   `relay1.cordelia` (or `relay2.cordelia`) pointing at the public IPv4 from
   section 1, with the proxy **off** ("DNS only", grey cloud), because
   Cloudflare's proxy does not carry QUIC. No AAAA record.
   `dig +short relay1.cordelia.seeddrill.ai` should print that address.
5. **From outside.** Any personal node with the default config dials both
   relays: `cordelia init`, `cordelia start`, then `cordelia status` shows
   `Peers: 1 hot` or more.

## 4. Upgrade

```bash
cd cordelia-node && git pull
RELAY=relay1 docker compose -f deploy/relay/compose.yml up -d --build
```

The identity stays on the `cordelia-relay1-data` volume. Do not delete that
volume: a relay with a new identity still works, since nodes find relays by
name, but there is no reason to change it.

## 5. Your own relay

Copy `relay1.toml`, change `entity_id`, and list whichever relays yours
should mesh with under `[[network.bootnodes]]`. Run the same image with your
file mounted and `CORDELIA_CONFIG` pointing at it. Then add your relay's
`host:9474` under `[[network.bootnodes]]` in the config of each node that
should use it. A relay can only ever see ciphertext, whoever runs it.

## Fly.io (optional)

`fly.relay1.toml` runs relay1 on Fly.io instead: UDP there needs a dedicated
IPv4 and a bind to `fly-global-services` (set through `CORDELIA_LISTEN_ADDR`),
with the same port inside and out. Deploy from the repository root with
`fly deploy . --config deploy/relay/fly.relay1.toml --remote-only`.
