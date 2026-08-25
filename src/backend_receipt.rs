//! Stable success evidence for host-owned dependency health decisions.

use crate::backend_error::BackendDependencyV1;
use bdk_wallet::bitcoin::Network;
use serde::{Deserialize, Serialize};

/// Capability proven by a successful backend operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendCapabilityV1 {
    /// Bitcoin chain history, UTXOs, and tip.
    BaseChain,
    /// Ord index and asset metadata.
    Ord,
}

/// Whether a receipt represents an authoritative complete result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncCompletenessV1 {
    /// The operation completed and may update health/tip state.
    Complete,
    /// The operation stopped without an authoritative replacement snapshot.
    Incomplete,
}

/// Stable state of a versioned scan attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanOutcomeStatusV1 {
    /// Every requested keychain completed and the replacement snapshot was applied.
    Complete,
    /// The attempt stopped transiently; the last complete snapshot remains authoritative.
    IncompleteRetryable,
    /// The attempt cannot safely succeed without a configuration or protocol change.
    Terminal,
}

/// The only safe retry checkpoint exposed by the current BDK scan API.
///
/// BDK returns a wallet update only after a complete request. We therefore never
/// expose an address-level checkpoint or persist a partial update: retries restart
/// from the last completely applied snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct ScanCheckpointV1 {
    /// Tip of the last authoritative snapshot, if one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_complete_tip: Option<u32>,
    /// Wallet/account generation owning that snapshot.
    pub operation_generation: u32,
}

/// Versioned evidence describing whether a scan may replace wallet state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct BackendScanOutcomeV1 {
    /// Schema version.
    pub version: u8,
    /// Whether this attempt produced an authoritative replacement snapshot.
    pub status: ScanOutcomeStatusV1,
    /// Number of complete keychain responses fetched during this attempt.
    pub completed_keychains: u8,
    /// Number of keychain responses required for a complete scan.
    pub total_keychains: u8,
    /// Safe retry boundary. Partial BDK updates are deliberately absent.
    pub checkpoint: ScanCheckpointV1,
}

impl BackendScanOutcomeV1 {
    /// Describe a complete, applied scan.
    #[must_use]
    pub fn complete(observed_tip: u32, operation_generation: u64, total_keychains: u8) -> Self {
        Self {
            version: 1,
            status: ScanOutcomeStatusV1::Complete,
            completed_keychains: total_keychains,
            total_keychains,
            checkpoint: ScanCheckpointV1 {
                last_complete_tip: Some(observed_tip),
                operation_generation: u32::try_from(operation_generation).unwrap_or(u32::MAX),
            },
        }
    }

    /// Describe an interrupted scan while retaining the last complete snapshot.
    #[must_use]
    pub fn incomplete(
        retryable: bool,
        last_complete_tip: Option<u32>,
        operation_generation: u64,
        completed_keychains: u8,
        total_keychains: u8,
    ) -> Self {
        Self {
            version: 1,
            status: if retryable {
                ScanOutcomeStatusV1::IncompleteRetryable
            } else {
                ScanOutcomeStatusV1::Terminal
            },
            completed_keychains: completed_keychains.min(total_keychains),
            total_keychains,
            checkpoint: ScanCheckpointV1 {
                last_complete_tip,
                operation_generation: u32::try_from(operation_generation).unwrap_or(u32::MAX),
            },
        }
    }
}

/// Versioned, data-only evidence emitted after a successful sync boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct BackendSyncReceiptV1 {
    /// Schema version.
    pub version: u8,
    /// Wallet network label.
    pub network: String,
    /// Dependency that supplied the result.
    pub dependency: BackendDependencyV1,
    /// Capability proven by the result.
    pub capability: BackendCapabilityV1,
    /// Configured provider identity. Hosts normalize this before registry use.
    pub provider: String,
    /// Tip observed by this successful operation.
    pub observed_tip: u32,
    /// Whether the result is authoritative.
    pub completeness: SyncCompletenessV1,
    /// Wallet/account generation to which the result was applied.
    pub operation_generation: u32,
    /// Authoritative scan boundary associated with this receipt.
    pub scan_outcome: BackendScanOutcomeV1,
}

impl BackendSyncReceiptV1 {
    /// Construct a complete success receipt.
    #[must_use]
    pub fn complete(
        network: Network,
        dependency: BackendDependencyV1,
        capability: BackendCapabilityV1,
        provider: impl Into<String>,
        observed_tip: u32,
        operation_generation: u64,
    ) -> Self {
        let network = match network {
            Network::Bitcoin => "mainnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
            _ => "unsupported",
        };
        let operation_generation = u32::try_from(operation_generation).unwrap_or(u32::MAX);
        Self {
            version: 1,
            network: network.to_string(),
            dependency,
            capability,
            provider: provider.into(),
            observed_tip,
            completeness: SyncCompletenessV1::Complete,
            operation_generation,
            scan_outcome: BackendScanOutcomeV1::complete(
                observed_tip,
                u64::from(operation_generation),
                1,
            ),
        }
    }

    /// Set the number of independently fetched keychains proven by this receipt.
    #[must_use]
    pub fn with_total_keychains(mut self, total_keychains: u8) -> Self {
        self.scan_outcome = BackendScanOutcomeV1::complete(
            self.observed_tip,
            u64::from(self.operation_generation),
            total_keychains,
        );
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_receipt_uses_closed_camel_case_schema() {
        let receipt = BackendSyncReceiptV1::complete(
            Network::Bitcoin,
            BackendDependencyV1::Esplora,
            BackendCapabilityV1::BaseChain,
            "https://example.test/api",
            900_000,
            7,
        );
        let value = serde_json::to_value(receipt).expect("receipt serializes");
        assert_eq!(value["version"], 1);
        assert_eq!(value["network"], "mainnet");
        assert_eq!(value["dependency"], "esplora");
        assert_eq!(value["capability"], "base_chain");
        assert_eq!(value["observedTip"], 900_000);
        assert_eq!(value["completeness"], "complete");
        assert_eq!(value["operationGeneration"], 7);
        assert_eq!(value["scanOutcome"]["status"], "complete");
        assert_eq!(
            value["scanOutcome"]["checkpoint"]["lastCompleteTip"],
            900_000
        );
    }

    #[test]
    fn interrupted_scan_exposes_only_the_last_complete_checkpoint() {
        let outcome = BackendScanOutcomeV1::incomplete(true, Some(899_999), 7, 1, 2);
        let value = serde_json::to_value(outcome).expect("outcome serializes");
        assert_eq!(value["status"], "incomplete_retryable");
        assert_eq!(value["completedKeychains"], 1);
        assert_eq!(value["totalKeychains"], 2);
        assert_eq!(value["checkpoint"]["lastCompleteTip"], 899_999);
        assert!(value.get("addressIndex").is_none());
    }
}
