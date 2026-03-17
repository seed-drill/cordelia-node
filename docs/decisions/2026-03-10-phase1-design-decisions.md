# Decision: Phase 1 Design Foundations

**Date**: 2026-03-10
**Decision Maker(s)**: Russell Wing
**Status**: Accepted
**Triggered by**: Design readiness audit for Phase 1 spec writing

---

## 1. Encryption Boundary

**Decision**: The node is the encryption boundary. The SDK sends and receives plaintext over a bearer-token-authenticated localhost connection. The node encrypts on write (channel PSK) and decrypts on read.

**Rationale**:
- Key management stays in one place (the node)
- SDK stays thin -- no crypto dependencies, no PSK handling
- Bearer token over localhost is the trust boundary
- Consistent with L1 encryption model (node already encrypts personal group)
- If the node is compromised, the attacker has the keys anyway (same trust model as Signal on-device)

**Impact**: WP3 API endpoints accept/return plaintext. WP4 handles all encryption in the storage layer. WP6 SDK has no crypto code.

---

## 2. Greenfield Build

**Decision**: Phase 1 is a greenfield implementation. The existing Cordelia codebase (groups, L1/L2, portal, proxy) is reference material, not baseline. No migration path. No backwards compatibility.

**Rationale**:
- Zero external adoption to protect
- Existing architecture was designed around portal-based enrollment and proxy-mediated storage -- both deprecated in the pivot
- Groups, L1/L2, and the existing schema carry design debt from pre-pivot assumptions
- Greenfield allows clean channel-first schema, proper pub/sub primitives, and no ALTER TABLE migrations
- All good ideas from the existing code can be ported forward selectively

**Impact**:
- Channels are first-class storage primitives, not wrappers around groups
- Schema designed from scratch for pub/sub (channels, items, members, keys)
- Existing cordelia-core Rust crates (crypto, identity, transport) can be reused where appropriate
- cordelia-proxy is replaced by thin MCP adapter (WP6/SDK scope)
- cordelia-portal is not part of Phase 1

---

## 3. Pairing Protocol -- Deferred

**Decision**: The device pairing protocol (WP5) is deferred from the initial spec writing pass. Single-device enrollment (`cordelia init`) is in scope. Multi-device pairing (`cordelia pair` / `cordelia join`) requires further exploration.

**Rationale**:
- Pairing protocol design space is wide (mDNS, relay, QR code, manual key exchange)
- Not on the critical path (WP1 -> WP3 -> WP6 -> WP9)
- Single-device flow is sufficient for MVP and early adopters
- Better to explore pairing options with Martin before committing to a spec

**Impact**: WP5 scope reduced to `cordelia init` for Phase 1. Pairing protocol designed separately, potentially Phase 1.5 or Phase 2.

---

*These three decisions unblock spec writing for WP1, WP2, WP3, WP4, and WP6.*
