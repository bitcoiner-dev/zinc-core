//! Stable, data-only failures for blockchain backend operations.

use crate::backend_receipt::BackendScanOutcomeV1;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum delay accepted from an upstream `Retry-After` value.
pub const MAX_RETRY_AFTER_MS: u64 = 5 * 60 * 1_000;

/// Backend dependency that produced a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendDependencyV1 {
    /// Esplora HTTP API.
    Esplora,
    /// Electrum JSON-RPC API.
    Electrum,
    /// Ord HTTP API.
    Ord,
}

/// Backend operation that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendOperationV1 {
    /// Construct or connect a protocol client.
    Connect,
    /// Synchronize wallet chain state.
    Sync,
    /// Broadcast a signed transaction.
    Broadcast,
    /// Look up an exact transaction id after an ambiguous broadcast result.
    TransactionLookup,
    /// Fetch address-level Ord state.
    AddressAssets,
    /// Fetch inscription metadata.
    InscriptionDetails,
    /// Fetch inscription content.
    InscriptionContent,
    /// Fetch rune metadata.
    RuneInfo,
    /// Fetch output metadata.
    Outputs,
    /// Fetch the Ord index height.
    BlockHeight,
    /// Fetch offer state.
    Offers,
}

/// Closed, presentation-independent backend failure category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendFailureCategoryV1 {
    /// The network or host could not be reached.
    Offline,
    /// The attempt exceeded its transport deadline.
    Timeout,
    /// The upstream explicitly rate limited the operation.
    RateLimited,
    /// The upstream is temporarily unavailable.
    Unavailable,
    /// The upstream returned malformed or incomplete data.
    InvalidResponse,
    /// The upstream serves a different Bitcoin network.
    WrongNetwork,
    /// The protocol rejected a validly formed request.
    ProtocolRejected,
    /// A different transaction conflicts with the attempted transaction.
    Conflict,
    /// No safe, more specific category is known.
    Unknown,
}

/// Versioned failure payload safe to serialize across Rust, WASM, and RPC boundaries.
///
/// Raw URLs, response bodies, protocol prose, addresses, and transaction data are
/// deliberately absent. Trusted adapters may retain those only in local redacted logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
#[error("backend failure ({dependency:?}/{operation:?}/{category:?})")]
pub struct BackendFailureV1 {
    /// Schema version.
    pub version: u8,
    /// Dependency that produced the failure.
    pub dependency: BackendDependencyV1,
    /// Operation that failed.
    pub operation: BackendOperationV1,
    /// Stable failure category.
    pub category: BackendFailureCategoryV1,
    /// Valid HTTP status, when the protocol exposes one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
    /// Sanitized stable protocol code, never an upstream message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_code: Option<String>,
    /// Validated and bounded retry delay supplied by the upstream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    /// Scan boundary retained when a sync attempt stops before apply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_outcome: Option<BackendScanOutcomeV1>,
}

impl BackendFailureV1 {
    /// Construct a data-only backend failure.
    pub fn new(
        dependency: BackendDependencyV1,
        operation: BackendOperationV1,
        category: BackendFailureCategoryV1,
    ) -> Self {
        Self {
            version: 1,
            dependency,
            operation,
            category,
            upstream_status: None,
            upstream_code: None,
            retry_after_ms: None,
            scan_outcome: None,
        }
    }

    /// Attach a valid HTTP status.
    #[must_use]
    pub fn with_status(mut self, status: u16) -> Self {
        self.upstream_status = (100..=599).contains(&status).then_some(status);
        self
    }

    /// Attach a bounded retry delay.
    #[must_use]
    pub fn with_retry_after_ms(mut self, retry_after_ms: Option<u64>) -> Self {
        self.retry_after_ms = retry_after_ms.map(|value| value.min(MAX_RETRY_AFTER_MS));
        self
    }

    /// Attach a sanitized stable protocol code.
    #[must_use]
    pub fn with_upstream_code(mut self, code: impl AsRef<str>) -> Self {
        self.upstream_code = sanitize_upstream_code(code.as_ref());
        self
    }

    /// Attach safe scan progress without including a partial wallet update.
    #[must_use]
    pub fn with_scan_outcome(mut self, outcome: BackendScanOutcomeV1) -> Self {
        self.scan_outcome = Some(outcome);
        self
    }

    /// Whether a scan stopped for a condition the host may retry.
    #[must_use]
    pub fn is_scan_retryable(&self) -> bool {
        matches!(
            self.category,
            BackendFailureCategoryV1::Offline
                | BackendFailureCategoryV1::Timeout
                | BackendFailureCategoryV1::RateLimited
                | BackendFailureCategoryV1::Unavailable
                | BackendFailureCategoryV1::Unknown
        )
    }

    /// Map an Esplora client error without retaining its response body.
    pub fn from_esplora(error: &esplora_client::Error, operation: BackendOperationV1) -> Self {
        use esplora_client::Error;

        match error {
            Error::Reqwest(error) => {
                Self::from_reqwest(error, BackendDependencyV1::Esplora, operation)
            }
            Error::HttpResponse { status, .. } => {
                Self::from_http_status(BackendDependencyV1::Esplora, operation, *status, None)
            }
            Error::Parsing(_)
            | Error::StatusCode(_)
            | Error::BitcoinEncoding(_)
            | Error::HexToArray(_)
            | Error::HexToBytes(_)
            | Error::InvalidResponse => Self::new(
                BackendDependencyV1::Esplora,
                operation,
                BackendFailureCategoryV1::InvalidResponse,
            ),
            Error::TransactionNotFound(_)
            | Error::HeaderHeightNotFound(_)
            | Error::HeaderHashNotFound(_) => Self::new(
                BackendDependencyV1::Esplora,
                operation,
                BackendFailureCategoryV1::ProtocolRejected,
            ),
            // A consumer can enable blocking-only Esplora error variants through
            // Cargo feature unification. Keep their prose and invalid-header
            // details out of the public failure envelope, including URLs and
            // proxy credentials.
            _ => Self::new(
                BackendDependencyV1::Esplora,
                operation,
                BackendFailureCategoryV1::Unknown,
            ),
        }
    }

    /// Map an Esplora broadcast rejection while discarding its prose.
    pub fn from_esplora_broadcast(error: &esplora_client::Error) -> Self {
        if let esplora_client::Error::HttpResponse { status, message } = error {
            let lower = message.to_ascii_lowercase();
            let fee_floor = [
                "min relay fee not met",
                "mempool min fee not met",
                "fee rate too low",
                "insufficient fee, rejecting replacement",
            ]
            .iter()
            .any(|marker| lower.contains(marker));
            let category = if [
                "txn-mempool-conflict",
                "bad-txns-inputs-missingorspent",
                "missing or spent",
            ]
            .iter()
            .any(|marker| lower.contains(marker))
            {
                BackendFailureCategoryV1::Conflict
            } else {
                match status {
                    408 | 504 => BackendFailureCategoryV1::Timeout,
                    429 => BackendFailureCategoryV1::RateLimited,
                    500..=599 => BackendFailureCategoryV1::Unavailable,
                    400..=499 => BackendFailureCategoryV1::ProtocolRejected,
                    _ => BackendFailureCategoryV1::Unknown,
                }
            };
            let failure = Self::new(
                BackendDependencyV1::Esplora,
                BackendOperationV1::Broadcast,
                category,
            )
            .with_status(*status);
            return if fee_floor {
                failure.with_upstream_code("mempool_fee")
            } else {
                failure
            };
        }
        Self::from_esplora(error, BackendOperationV1::Broadcast)
    }

    /// Map a reqwest error without serializing its URL or message.
    pub fn from_reqwest(
        error: &reqwest::Error,
        dependency: BackendDependencyV1,
        operation: BackendOperationV1,
    ) -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let is_connect = error.is_connect();
        #[cfg(target_arch = "wasm32")]
        let is_connect = false;
        let category = if error.is_timeout() {
            BackendFailureCategoryV1::Timeout
        } else if is_connect {
            BackendFailureCategoryV1::Offline
        } else if error.is_decode() {
            BackendFailureCategoryV1::InvalidResponse
        } else {
            BackendFailureCategoryV1::Unavailable
        };
        let failure = Self::new(dependency, operation, category);
        error.status().map_or(failure.clone(), |status| {
            failure.with_status(status.as_u16())
        })
    }

    /// Map a status and optional `Retry-After` header into stable data.
    pub fn from_http_status(
        dependency: BackendDependencyV1,
        operation: BackendOperationV1,
        status: u16,
        retry_after: Option<&str>,
    ) -> Self {
        let category = match status {
            408 | 504 => BackendFailureCategoryV1::Timeout,
            429 => BackendFailureCategoryV1::RateLimited,
            500..=599 => BackendFailureCategoryV1::Unavailable,
            400..=499 => BackendFailureCategoryV1::ProtocolRejected,
            _ => BackendFailureCategoryV1::Unknown,
        };
        Self::new(dependency, operation, category)
            .with_status(status)
            .with_retry_after_ms(parse_retry_after_ms(retry_after))
    }

    /// Construct an invalid-response failure.
    pub fn invalid_response(
        dependency: BackendDependencyV1,
        operation: BackendOperationV1,
    ) -> Self {
        Self::new(
            dependency,
            operation,
            BackendFailureCategoryV1::InvalidResponse,
        )
    }
}

/// Whether an Esplora response proves the exact submitted transaction was already accepted.
pub fn is_duplicate_esplora_broadcast(error: &esplora_client::Error) -> bool {
    let esplora_client::Error::HttpResponse { message, .. } = error else {
        return false;
    };
    let lower = message.to_ascii_lowercase();
    [
        "txn-already-known",
        "already known",
        "already in block chain",
        "already in blockchain",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

/// Whether a failed response might have occurred after the upstream accepted the transaction.
pub fn is_ambiguous_esplora_broadcast(error: &esplora_client::Error) -> bool {
    matches!(
        error,
        esplora_client::Error::Reqwest(_)
            | esplora_client::Error::HttpResponse {
                status: 500..=599,
                ..
            }
    )
}

/// Parse delta-seconds `Retry-After`; HTTP-date values are intentionally ignored.
pub fn parse_retry_after_ms(value: Option<&str>) -> Option<u64> {
    value?
        .trim()
        .parse::<u64>()
        .ok()
        .map(|seconds| seconds.saturating_mul(1_000).min(MAX_RETRY_AFTER_MS))
}

fn sanitize_upstream_code(value: &str) -> Option<String> {
    let normalized: String = value
        .trim()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || "_.:-".contains(*character))
        .take(64)
        .collect();
    (!normalized.is_empty()).then_some(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_is_bounded_and_http_dates_are_rejected() {
        assert_eq!(parse_retry_after_ms(Some("12")), Some(12_000));
        assert_eq!(
            parse_retry_after_ms(Some("999999")),
            Some(MAX_RETRY_AFTER_MS)
        );
        assert_eq!(
            parse_retry_after_ms(Some("Wed, 21 Oct 2015 07:28:00 GMT")),
            None
        );
        assert_eq!(
            BackendFailureV1::new(
                BackendDependencyV1::Esplora,
                BackendOperationV1::Sync,
                BackendFailureCategoryV1::Unavailable,
            )
            .with_status(0)
            .upstream_status,
            None
        );
    }

    #[test]
    fn serialization_contains_no_untrusted_detail() {
        let failure = BackendFailureV1::from_esplora(
            &esplora_client::Error::HttpResponse {
                status: 503,
                message: "hostile upstream prose https://secret.example/address/x".to_string(),
            },
            BackendOperationV1::Sync,
        );
        let json = serde_json::to_string(&failure).expect("serialize");
        assert_eq!(failure.category, BackendFailureCategoryV1::Unavailable);
        assert!(json.contains("\"upstreamStatus\":503"));
        assert!(!json.contains("hostile"));
        assert!(!json.contains("secret.example"));
    }

    #[test]
    fn duplicate_broadcast_is_distinct_from_a_real_conflict() {
        let duplicate = esplora_client::Error::HttpResponse {
            status: 400,
            message: "txn-already-known".to_string(),
        };
        let conflict = esplora_client::Error::HttpResponse {
            status: 400,
            message: "txn-mempool-conflict".to_string(),
        };

        assert!(is_duplicate_esplora_broadcast(&duplicate));
        assert!(!is_duplicate_esplora_broadcast(&conflict));
        assert_eq!(
            BackendFailureV1::from_esplora_broadcast(&conflict).category,
            BackendFailureCategoryV1::Conflict
        );
    }
}
