# Relays

Two relays, per decision 2026-09-30-agent-memory-sync §4.6: `relay1` on
Fly.io, `relay2` at one of our sites. Each stores and forwards encrypted
items (it never holds a key) and is the bootstrap address personal nodes
dial by default. They list each other, so they form a mesh.

| File | Purpose |
|---|---|
| `Dockerfile` | One image for both relays. No secrets in it: the identity is created on first start, on the `/data` volume. |
| `entrypoint.sh` | First start: `cordelia init`. Every start: `cordelia start`. |
| `relay1.toml`, `relay2.toml` | Relay config; each lists the other relay. Chosen with `CORDELIA_CONFIG`. |
| `fly.relay1.toml` | Fly.io app for relay1 (UDP on a dedicated IPv4, bound to `fly-global-services`). |
| `compose.relay2.yml` | Docker Compose for relay2 at a site (UDP 9474 forwarded to the host). |

The step-by-step procedure (accounts, DNS, verification) is in the private
strategy repo: `infrastructure/cordelia-relays.md`.
