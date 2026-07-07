//! Ordinals integration primitives for `zinc-core`.
//!
//! Includes API clients, data types, error types, and PSBT protection helpers.

/// HTTP client helpers for ord server queries.
pub mod client;
/// Error types used by ordinals integrations.
pub mod error;
/// Runes protocol decoding and flow simulation.
pub mod runes;
/// Ordinal Shield analysis and audit helpers.
pub mod shield;
/// Core ordinals domain models and serialization helpers.
pub mod types;

pub use client::*;
pub use error::*;
pub use runes::*;
pub use shield::*;
pub use types::*;
