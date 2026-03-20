//! QUIC transport, 8 mini-protocols, governor state machine, replication engine.
//!
//! Spec: seed-drill/specs/network-protocol.md

pub mod bootstrap;
pub mod channel_announce;
pub mod codec;
pub mod connection;
pub mod governor;
pub mod handshake;
pub mod item_sync;
pub mod keepalive;
pub mod messages;
pub mod peer_sharing;
pub mod psk_exchange;
pub mod rate_limit;
pub mod seen_table;
pub mod transport;
