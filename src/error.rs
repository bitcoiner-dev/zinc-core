//! Unified error types for Zinc wallet

use thiserror::Error;

/// All errors that can occur in Zinc wallet operations.
#[derive(Error, Debug)]
pub enum ZincError {
    /// Unsupported BIP-39 word count was requested.
    #[error("Invalid word count: {0}. Must be 12 or 24.")]
    InvalidWordCount(u8),

    /// Mnemonic parsing/validation failure.
    #[error("Mnemonic error: {0}")]
    MnemonicError(String),

    /// HD key derivation failure.
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    /// Generic wallet operation failure.
    #[error("Wallet error: {0}")]
    WalletError(String),

    /// Encryption operation failure.
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Decryption failed due to invalid password or malformed payload.
    #[error("Decryption failed: wrong password or corrupted data")]
    DecryptionError,

    /// JSON or binary serialization/deserialization failure.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid runtime configuration.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Wrapped error from BDK primitives.
    #[error("BDK error: {0}")]
    BdkError(String),

    /// Offer envelope creation/validation/signature failure.
    #[error("Offer error: {0}")]
    OfferError(String),

    /// Attempted a signing operation on a read-only (Watch) profile.
    #[error("Capability missing: This operation requires a Seed-mode profile (private keys).")]
    CapabilityMissing,
}

/// Convenience type alias for Results with `ZincError`.
pub type ZincResult<T> = Result<T, ZincError>;
