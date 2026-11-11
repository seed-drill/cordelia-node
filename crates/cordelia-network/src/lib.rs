//! QUIC transport, 8 mini-protocols, governor state machine, replication engine.
//!
//! Spec: seed-drill/specs/network-protocol.md

pub mod bootstrap;
pub mod codec;
pub mod connection;
pub mod governor;
pub mod handshake;
pub mod keepalive;
pub mod messages;
pub mod peer_sharing;
pub mod rate_limit;
pub mod transport;
