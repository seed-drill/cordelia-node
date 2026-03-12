//! Error types for Cordelia.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CordeliaError {
    #[error("node not initialised: run `cordelia init` first")]
    NodeNotInitialised,

    #[error("not authorised: {context}")]
    NotAuthorised { context: String },

    #[error("channel not found: {channel}")]
    ChannelNotFound { channel: String },

    #[error("channel already exists: {channel}")]
    ChannelAlreadyExists { channel: String },

    #[error("invalid channel name: {reason}")]
    InvalidChannelName { reason: String },

    #[error("item not found: {item_id}")]
    ItemNotFound { item_id: String },

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("internal error: {0}")]
    Internal(String),
}
