use thiserror::Error;

/// Errors returned by ordinals API/parsing operations.
#[derive(Error, Debug)]
pub enum OrdError {
    /// HTTP request or payload parsing failed.
    #[error("API request failed: {0}")]
    RequestFailed(String),
}
