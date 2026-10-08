//! What of the node is used from outside its binary: a device's side of
//! its relays for the channels of its own, which the tests drive over
//! real connections, against relays that run as processes of their own.
//!
//! The binary is `cordelia` (`main.rs`), and everything else of the node
//! is in it.

pub mod device_entries;
