//! Keys module for mnemonic and descriptor handling
//!
//! This module wraps BDK's key management with Ordinals-aware constraints.

mod derivation;
mod mnemonic;

pub use derivation::{taproot_descriptors, DescriptorPair};
pub use mnemonic::ZincMnemonic;
