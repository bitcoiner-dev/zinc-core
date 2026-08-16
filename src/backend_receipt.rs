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
        Self {
            version: 1,
            network: network.to_string(),
            dependency,
            capability,
            provider: provider.into(),
            observed_tip,
            completeness: SyncCompletenessV1::Complete,
            operation_generation: u32::try_from(operation_generation).unwrap_or(u32::MAX),
        }
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
    }
}
