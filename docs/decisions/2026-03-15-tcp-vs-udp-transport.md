# ADR: TCP vs UDP (QUIC) Transport

**Date:** 2026-03-15
**Status:** Decided -- QUIC/UDP
**Authors:** Russell Wing, Claude Opus 4.6

## Context

Cordelia's P2P transport needs to carry multiplexed mini-protocol streams between peers. The original Cordelia prototype used libp2p (TCP + noise + yamux). The architecture pivot (2026-03-09) adopted QUIC via quinn.

Cardano's Ouroboros networking uses TCP with a custom bearer and 12-state connection manager for duplex handling. This is the reference design we draw from for the peer governor.

## Decision

Use QUIC (UDP) via quinn for all P2P transport. No TCP fallback.

## Arguments For QUIC

1. **No head-of-line blocking.** TCP multiplexing (yamux, HTTP/2) suffers from HOL blocking -- one lost packet stalls all streams. QUIC streams are independent. For realtime pub/sub delivery, this matters.
2. **Built-in TLS 1.3.** Mandatory encryption at transport layer. No separate handshake step. 0-RTT reconnection potential (Phase 2+).
3. **Connection migration.** QUIC connections survive IP changes (mobile agents, container restarts).
4. **Quinn is production-quality.** Used by Cloudflare. Well-maintained Rust ecosystem.
5. **Stream multiplexing is native.** No need for yamux or equivalent framing layer.

## Arguments For TCP

1. **Docker bridge reliability.** TCP conntrack is cleaner than UDP (explicit SYN/FIN lifecycle). UDP conntrack entries persist and interfere across Docker test runs.
2. **Simpler debugging.** TCP is well-understood. Wireshark/tcpdump work natively. QUIC stream-level debugging requires QUIC-aware tools.
3. **Proven at scale.** Cardano runs 3000+ nodes on TCP. libp2p primarily uses TCP. Most P2P systems (BitTorrent, IPFS) were designed for TCP.
4. **No open_bi hangs.** TCP stream creation is application-level framing -- cannot hang at the transport layer.
5. **Connection manager is simpler.** No QUIC-specific quirks (stream limits, connection IDs, 0-RTT security considerations).

## Risks Accepted

1. **Docker E2E testing friction.** UDP conntrack issues require kernel tuning (`nf_conntrack_udp_timeout=10`, `conntrack -F` flush between runs). Documented in topology-e2e.md §2.3.1.
2. **QUIC connection ordering on Docker bridge.** Intermittent connection failures when multiple containers connect via the same Docker bridge. Mitigated by `depends_on` ordering and 10s bootstrap timeout.
3. **No ecosystem precedent for P2P QUIC at scale.** We are early adopters. Production validation will come from bootnode deployment and progressive rollout.
4. **No duplex connection negotiation.** Cardano's TCP bearer handles simultaneous inbound+outbound on the same connection. QUIC doesn't need this (connections are directional by design) but we may see redundant connections between peers.

## Alternatives Considered

- **TCP + yamux:** Proven in Cardano, simpler Docker testing, but HOL blocking is a fundamental limitation for realtime delivery.
- **TCP for Docker testing, QUIC for production:** Rejected. Testing with a different transport than production is pointless -- it validates the wrong thing.
- **libp2p:** Rejected in architecture pivot (2026-03-09). Too many layers of abstraction for our use case.

## Consequences

- All Docker E2E infrastructure must account for UDP conntrack (documented in topology-e2e.md).
- The protocol layer (handshake, push, sync, peer-sharing) MUST remain transport-agnostic (operates on bidirectional streams, not raw sockets) so a TCP bearer could be added in future if needed.
- Scale testing (500-1000 nodes) will validate QUIC at a scale not previously attempted in P2P contexts.
