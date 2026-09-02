use crate::backend_error::{BackendDependencyV1, BackendFailureV1, BackendOperationV1};
use thiserror::Error;

/// Errors returned by ordinals API/parsing operations.
#[derive(Error, Debug)]
pub enum OrdError {
    /// Caller supplied an invalid local Ord request.
    #[error("invalid ord request")]
    InvalidRequest,
    /// Locally detected malformed Ord domain data. The reason is diagnostic-only.
    #[error("invalid ord data")]
    InvalidData(String),
    /// A versioned, data-only Ord dependency failure.
    #[error(transparent)]
    Backend(#[from] BackendFailureV1),
    /// Sat-range data could not prove that every wallet output was classified.
    /// The display is intentionally stable and data-free at host boundaries;
    /// `reason` is available only to trusted diagnostics through `Debug`.
    #[error("ORD_RARE_SAT_PROTECTION_UNVERIFIED")]
    RareSatProtectionUnverified { reason: &'static str },
}

impl OrdError {
    pub(crate) fn invalid_response(operation: BackendOperationV1) -> Self {
        BackendFailureV1::invalid_response(BackendDependencyV1::Ord, operation).into()
    }
}
