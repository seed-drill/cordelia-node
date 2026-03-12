//! QUIC transport, 8 mini-protocols, governor state machine, replication engine.
//!
//! Spec: seed-drill/specs/network-protocol.md
//! Port source: cordelia-core governor (~1235 LOC, PeerId->NodeId trait swap)

// TODO(WP3): QUIC transport + handshake.
// TODO(WP12): Bootnode DNS discovery.
