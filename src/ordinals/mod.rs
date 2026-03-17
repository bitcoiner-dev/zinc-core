//! Ordinals integration primitives for `zinc-core`.
//!
//! Includes API clients, data types, error types, and PSBT protection helpers.

/// HTTP client helpers for ord server queries.
pub mod client;
/// Error types used by ordinals integrations.
pub mod error;
/// Ordinal Shield analysis and audit helpers.
pub mod shield;
/// Core ordinals domain models and serialization helpers.
pub mod types;

pub use client::*;
pub use error::*;
pub use shield::*;
pub use types::*;
