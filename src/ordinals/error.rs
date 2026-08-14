use thiserror::Error;

/// Errors returned by ordinals API/parsing operations.
#[derive(Error, Debug)]
pub enum OrdError {
    /// HTTP request or payload parsing failed.
    #[error("API request failed: {0}")]
    RequestFailed(String),
    /// Sat-range data could not prove that every wallet output was classified.
    /// The display is intentionally stable and data-free at host boundaries;
    /// `reason` is available only to trusted diagnostics through `Debug`.
    #[error("ORD_RARE_SAT_PROTECTION_UNVERIFIED")]
    RareSatProtectionUnverified { reason: &'static str },
}
