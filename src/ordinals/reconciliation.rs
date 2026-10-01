//! Sealed reconciliation of Ord classification with a trusted current-chain snapshot.
//! No host-provided observation can construct or mutate this proof.
use super::{OrdClient, OrdError, ResolvedAssets};
use crate::backend_error::{
    BackendDependencyV1, BackendFailureCategoryV1, BackendFailureV1, BackendOperationV1,
};
use crate::builder::{wasm_now_secs, ZincWallet};
use bdk_wallet::KeychainKind;
use bitcoin::{Network, OutPoint, ScriptBuf};
use std::collections::{HashMap, HashSet};

/// Opaque owned-output context captured by the trusted wallet, not a display cache.
/// It deliberately has no serialization, Debug output or public constructor.
pub struct OrdChainContext {
    network: Network,
    identity: (String, Option<String>),
    account_generation: u64,
    chain_generation: u64,
    observed_at: Option<u64>,
    wallet_height: u32,
    outputs: HashMap<String, (Option<u32>, u64, ScriptBuf)>,
}

/// Complete classification bound to the chain context that requested it.
pub struct ReconciledOrdHoldings {
    context: OrdChainContext,
    assets: ResolvedAssets,
    classified: HashSet<OutPoint>,
    ord_height: u32,
}

impl OrdChainContext {
    /// Output count for bounded progress reporting; no wallet identifiers are exposed.
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }
}
impl ReconciledOrdHoldings {
    /// Height of the indexer observation used for this result.
    pub fn indexed_height(&self) -> u32 {
        self.ord_height
    }
    /// Number of resolved inscriptions, for progress reporting only.
    pub fn inscription_count(&self) -> usize {
        self.assets.inscriptions.len()
    }
}

impl ZincWallet {
    fn ord_context_identity(&self) -> (String, Option<String>) {
        (
            self.vault_wallet
                .public_descriptor(KeychainKind::External)
                .to_string(),
            self.payment_wallet
                .as_ref()
                .map(|w| w.public_descriptor(KeychainKind::External).to_string()),
        )
    }
    /// Capture complete current ownership and value evidence before releasing the wallet lock.
    pub fn ord_chain_context(&self) -> OrdChainContext {
        let mut outputs = HashMap::new();
        for wallet in std::iter::once(&self.vault_wallet).chain(self.payment_wallet.iter()) {
            for u in self.current_unspent(wallet) {
                let height = match u.chain_position {
                    bdk_chain::ChainPosition::Confirmed { anchor, .. } => {
                        Some(anchor.block_id.height)
                    }
                    bdk_chain::ChainPosition::Unconfirmed { .. } => None,
                };
                outputs.insert(
                    u.outpoint.to_string(),
                    (height, u.txout.value.to_sat(), u.txout.script_pubkey),
                );
            }
        }
        OrdChainContext {
            network: self.vault_wallet.network(),
            identity: self.ord_context_identity(),
            account_generation: self.account_generation(),
            chain_generation: self.chain_state_generation(),
            observed_at: self.chain_observed_at_unix,
            wallet_height: self.chain_tip_height(),
            outputs,
        }
    }
    /// Atomically apply only the sealed result for this exact wallet and current chain observation.
    pub fn apply_reconciled_ord_holdings(
        &mut self,
        result: ReconciledOrdHoldings,
    ) -> Result<usize, String> {
        let current = self.ord_chain_context();
        let context = result.context;
        if context.network != current.network
            || context.identity != current.identity
            || context.account_generation != current.account_generation
            || context.chain_generation != current.chain_generation
            || context.observed_at.is_none()
            || context.observed_at != current.observed_at
            || context.wallet_height != current.wallet_height
            || context.outputs != current.outputs
        {
            return Err("Stale Ord reconciliation result".into());
        }
        let assets = result.assets;
        self.apply_complete_verified_ordinals_update_with_rare_sats(
            assets.inscriptions,
            assets.protected_outpoints,
            assets.rune_balances,
            assets.rare_sat_outpoints,
            assets.outpoint_runes,
            assets.rune_infos,
            result.classified,
            context.chain_generation,
        )
    }
}

impl OrdClient {
    /// Resolve exactly the trusted current outputs; lagging or unconfirmed outputs stay protected.
    /// This proves classification of the chain-owned set, not independent address-inventory agreement.
    pub async fn reconcile_chain_holdings(
        &self,
        context: OrdChainContext,
    ) -> Result<ReconciledOrdHoldings, OrdError> {
        let ord_height = self.get_indexing_height().await?;
        if ord_height < context.wallet_height.saturating_sub(2) {
            return Err(BackendFailureV1::new(
                BackendDependencyV1::Ord,
                BackendOperationV1::BlockHeight,
                BackendFailureCategoryV1::Unavailable,
            )
            .with_upstream_code("index_lag")
            .into());
        }
        // A newly constructed / failed-sync wallet is not evidence of empty holdings.
        if context.observed_at.is_none_or(|at| at > wasm_now_secs()) {
            return Err(OrdError::RareSatProtectionUnverified {
                reason: "chain-not-observed",
            });
        }
        let mut queryable = Vec::new();
        let mut scripts = HashMap::new();
        let mut pending: HashSet<OutPoint> = HashSet::new();
        for (op, (height, value, script)) in &context.outputs {
            if height.is_some_and(|h| h <= ord_height) {
                queryable.push((op.clone(), *value));
                scripts.insert(op.clone(), script.clone());
            } else {
                pending.insert(op.parse().map_err(|_| OrdError::InvalidRequest)?);
            }
        }
        // Stable request ordering makes diagnostics reproducible without exposing keys.
        queryable.sort_by(|a, b| a.0.cmp(&b.0));
        let classified = queryable
            .iter()
            .map(|(op, _)| op.parse().map_err(|_| OrdError::InvalidRequest))
            .collect::<Result<_, _>>()?;
        let mut assets = self
            .resolve_assets_for_owned_utxos(&queryable, &scripts, context.network)
            .await?;
        assets.protected_outpoints.extend(pending);
        Ok(ReconciledOrdHoldings {
            context,
            assets,
            classified,
            ord_height,
        })
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::{WalletBuilder, ZincMnemonic};
    fn wallet() -> ZincWallet {
        let mnemonic = ZincMnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut wallet = WalletBuilder::from_mnemonic(Network::Regtest, &mnemonic)
            .build()
            .unwrap();
        wallet.chain_observed_at_unix = Some(wasm_now_secs());
        wallet
    }
    async fn empty_result(wallet: &ZincWallet) -> ReconciledOrdHoldings {
        let mut server = mockito::Server::new_with_opts_async(Default::default()).await;
        let height = server
            .mock("GET", "/blockheight")
            .with_body("0")
            .expect(1)
            .create_async()
            .await;
        let outputs = server
            .mock("POST", "/outputs")
            .expect(0)
            .create_async()
            .await;
        let result = OrdClient::new(server.url())
            .reconcile_chain_holdings(wallet.ord_chain_context())
            .await
            .unwrap();
        height.assert_async().await;
        outputs.assert_async().await;
        result
    }
    #[tokio::test]
    async fn reconciliation_empty_observed_chain_is_valid_but_unsynced_is_not() {
        let mut wallet = wallet();
        let result = empty_result(&wallet).await;
        assert_eq!(wallet.apply_reconciled_ord_holdings(result).unwrap(), 0);
        let mut server = mockito::Server::new_with_opts_async(Default::default()).await;
        server
            .mock("GET", "/blockheight")
            .with_body("0")
            .create_async()
            .await;
        let outputs = server
            .mock("POST", "/outputs")
            .expect(0)
            .create_async()
            .await;
        wallet.chain_observed_at_unix = None;
        assert!(OrdClient::new(server.url())
            .reconcile_chain_holdings(wallet.ord_chain_context())
            .await
            .is_err());
        outputs.assert_async().await;
    }
    #[tokio::test]
    async fn reconciliation_rejects_changed_account_chain_identity_and_observation() {
        for change in [
            "account",
            "chain",
            "identity",
            "network",
            "observation",
            "ownership",
        ] {
            let mut wallet = wallet();
            let mut result = empty_result(&wallet).await;
            match change {
                "account" => result.context.account_generation += 1,
                "chain" => result.context.chain_generation += 1,
                "identity" => result.context.identity.0.push('x'),
                "network" => result.context.network = Network::Bitcoin,
                "observation" => result.context.observed_at = None,
                "ownership" => {
                    result.context.outputs.insert(
                        format!("{}:0", "22".repeat(32)),
                        (Some(0), 330, ScriptBuf::new()),
                    );
                }
                _ => unreachable!(),
            }
            assert!(
                wallet.apply_reconciled_ord_holdings(result).is_err(),
                "{change}"
            );
            assert!(!wallet.ordinals_verified);
        }
    }
    #[tokio::test]
    async fn reconciliation_preserves_pending_and_above_indexer_outputs() {
        let wallet = wallet();
        let mut context = wallet.ord_chain_context();
        let pending = format!("{}:0", "22".repeat(32));
        let ahead = format!("{}:0", "33".repeat(32));
        context
            .outputs
            .insert(pending.clone(), (None, 330, ScriptBuf::new()));
        context
            .outputs
            .insert(ahead.clone(), (Some(1), 330, ScriptBuf::new()));
        let mut server = mockito::Server::new_with_opts_async(Default::default()).await;
        server
            .mock("GET", "/blockheight")
            .with_body("0")
            .create_async()
            .await;
        let outputs = server
            .mock("POST", "/outputs")
            .expect(0)
            .create_async()
            .await;
        let result = OrdClient::new(server.url())
            .reconcile_chain_holdings(context)
            .await
            .unwrap();
        assert!(result.classified.is_empty());
        assert_eq!(
            result.assets.protected_outpoints,
            [pending.parse().unwrap(), ahead.parse().unwrap()].into()
        );
        outputs.assert_async().await;
    }
    #[tokio::test]
    async fn reconciliation_lag_fails_without_fetching_outputs() {
        let mut context = wallet().ord_chain_context();
        context.wallet_height = 3;
        let mut server = mockito::Server::new_with_opts_async(Default::default()).await;
        server
            .mock("GET", "/blockheight")
            .with_body("0")
            .create_async()
            .await;
        let outputs = server
            .mock("POST", "/outputs")
            .expect(0)
            .create_async()
            .await;
        let error = OrdClient::new(server.url())
            .reconcile_chain_holdings(context)
            .await
            .err()
            .unwrap();
        assert!(matches!(error, OrdError::Backend(_)));
        outputs.assert_async().await;
    }
}
