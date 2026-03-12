//! Shared types, traits, config, and error types for Cordelia.
//!
//! Spec: seed-drill/specs/configuration.md

pub mod config;
pub mod error;
pub mod types;

pub use error::CordeliaError;
pub use types::{ChannelId, ItemId, NodeId};
