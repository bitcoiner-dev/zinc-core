//! Fresh asset evidence for inputs spent by a still-pending wallet payment.
//! These facts authorize analysis/signing; they are never displayed as holdings.

use crate::{builder::ZincWallet, ordinals::client::ResolvedAssets};
use bitcoin::{OutPoint, TxOut, Txid};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancellationInputSnapshot {
    original_txid: Txid,
    account_generation: u64,
    chain_generation: u64,
    asset_generation: u64,
    inputs: Vec<(OutPoint, TxOut)>,
}

impl CancellationInputSnapshot {
    /// Values come from the wallet's transaction graph, never the caller's PSBT.
    pub fn ord_queries(&self) -> Vec<(String, u64)> {
        self.inputs
            .iter()
            .map(|(outpoint, output)| (outpoint.to_string(), output.value.to_sat()))
            .collect()
    }

    /// Resolve every input with the strict value/sat-range checking Ord client.
    /// The resulting proof is opaque to hosts; they cannot assert that an
    /// unqueried input was clean or replace the resolved asset facts.
    pub async fn verify(
        self,
        ord_url: &str,
    ) -> Result<VerifiedCancellationInputs, crate::ordinals::OrdError> {
        let assets = crate::ordinals::OrdClient::new(ord_url.to_owned())
            .resolve_assets_for_utxos(&self.ord_queries())
            .await?;
        Ok(VerifiedCancellationInputs {
            snapshot: self,
            assets,
        })
    }

    #[cfg(test)]
    pub(crate) fn test_with_assets(self, assets: ResolvedAssets) -> VerifiedCancellationInputs {
        VerifiedCancellationInputs {
            snapshot: self,
            assets,
        }
    }
}

#[derive(Debug)]
pub struct VerifiedCancellationInputs {
    snapshot: CancellationInputSnapshot,
    assets: ResolvedAssets,
}

impl ZincWallet {
    /// Capture the exact inputs of a locally known, canonical pending payment.
    /// A host must resolve every returned outpoint through the value-validating
    /// Ord client, then publish with `apply_verified_cancellation_inputs`.
    pub fn cancellation_input_snapshot(
        &self,
        original_txid: Txid,
    ) -> Result<CancellationInputSnapshot, String> {
        if !self.asset_state_is_current() || self.is_syncing {
            return Err("Cancellation requires a current, settled asset snapshot".into());
        }
        let original = self
            .vault_wallet
            .get_tx(original_txid)
            .or_else(|| {
                self.payment_wallet
                    .as_ref()
                    .and_then(|wallet| wallet.get_tx(original_txid))
            })
            .ok_or("Cancellation target is not in the wallet transaction graph")?;
        if !matches!(
            original.chain_position,
            bdk_chain::ChainPosition::Unconfirmed { .. }
        ) {
            return Err("Cancellation target is already confirmed".into());
        }
        let mut inputs = Vec::new();
        for input in &original.tx_node.tx.input {
            let outpoint = input.previous_output;
            if inputs.iter().any(|(previous, _)| *previous == outpoint) {
                return Err("Cancellation target has duplicate inputs".into());
            }
            let output = std::iter::once(&self.vault_wallet)
                .chain(self.payment_wallet.iter())
                .find_map(|wallet| {
                    let funding = wallet.get_tx(outpoint.txid)?;
                    let output = funding.tx_node.tx.output.get(outpoint.vout as usize)?;
                    wallet
                        .is_mine(output.script_pubkey.clone())
                        .then(|| output.clone())
                })
                .ok_or("Cancellation input is not a known wallet-owned output")?;
            inputs.push((outpoint, output));
        }
        if inputs.is_empty() {
            return Err("Cancellation target has no wallet inputs".into());
        }
        Ok(CancellationInputSnapshot {
            original_txid,
            account_generation: self.account_generation,
            chain_generation: self.chain_state_generation,
            asset_generation: self.asset_data_generation,
            inputs,
        })
    }

    /// Publish only the opaque proof produced by this snapshot's verifier.
    pub fn apply_verified_cancellation_inputs(
        &mut self,
        proof: VerifiedCancellationInputs,
    ) -> Result<(), String> {
        let VerifiedCancellationInputs { snapshot, assets } = proof;
        if self.cancellation_input_snapshot(snapshot.original_txid)? != snapshot {
            return Err("Cancellation input verification became stale".into());
        }
        let contains =
            |outpoint: &OutPoint| snapshot.inputs.iter().any(|(input, _)| input == outpoint);
        if assets
            .inscriptions
            .iter()
            .any(|inscription| !contains(&inscription.satpoint.outpoint))
            || assets
                .protected_outpoints
                .iter()
                .any(|outpoint| !contains(outpoint))
            || assets
                .outpoint_runes
                .keys()
                .any(|outpoint| !contains(outpoint))
            || assets
                .rare_sat_outpoints
                .keys()
                .any(|outpoint| !contains(outpoint))
        {
            return Err("Cancellation asset evidence contains an unrelated outpoint".into());
        }
        self.cancellation_input_assets = Some(VerifiedCancellationInputs { snapshot, assets });
        Ok(())
    }

    pub(crate) fn cancellation_assets(&self) -> Option<&ResolvedAssets> {
        let verified = self.cancellation_input_assets.as_ref()?;
        (self
            .cancellation_input_snapshot(verified.snapshot.original_txid)
            .ok()
            .as_ref()
            == Some(&verified.snapshot))
        .then_some(&verified.assets)
    }

    pub(crate) fn cancellation_txouts(&self) -> impl Iterator<Item = &(OutPoint, TxOut)> {
        self.cancellation_input_assets
            .as_ref()
            .filter(|_| self.cancellation_assets().is_some())
            .into_iter()
            .flat_map(|verified| verified.snapshot.inputs.iter())
    }

    pub(crate) fn signing_input_is_protected(&self, outpoint: &OutPoint) -> bool {
        self.inscribed_utxos.contains(outpoint)
            || self
                .cancellation_assets()
                .is_some_and(|assets| assets.protected_outpoints.contains(outpoint))
    }

    pub(crate) fn signing_input_has_runes(&self, outpoint: &OutPoint) -> bool {
        self.outpoint_runes.contains_key(outpoint)
            || self
                .cancellation_assets()
                .is_some_and(|assets| assets.outpoint_runes.contains_key(outpoint))
    }

    pub(crate) fn signing_input_is_classified(&self, outpoint: &OutPoint) -> bool {
        self.classified_outpoints.contains(outpoint)
            || self
                .cancellation_txouts()
                .any(|(input, _)| input == outpoint)
    }

    pub(crate) fn signing_inscriptions(
        &self,
    ) -> impl Iterator<Item = &crate::ordinals::types::Inscription> {
        self.inscriptions.iter().chain(
            self.cancellation_assets()
                .into_iter()
                .flat_map(|assets| assets.inscriptions.iter()),
        )
    }

    pub(crate) fn signing_runes(&self) -> impl Iterator<Item = (&OutPoint, &Vec<(String, u128)>)> {
        self.outpoint_runes.iter().chain(
            self.cancellation_assets()
                .into_iter()
                .flat_map(|assets| assets.outpoint_runes.iter()),
        )
    }

    pub(crate) fn signing_rare_sats(
        &self,
    ) -> impl Iterator<Item = (&OutPoint, &crate::ordinals::client::RareSatSummary)> {
        self.rare_sat_outpoints.iter().chain(
            self.cancellation_assets()
                .into_iter()
                .flat_map(|assets| assets.rare_sat_outpoints.iter()),
        )
    }

    pub(crate) fn signing_rune_info(&self, id: &str) -> Option<&crate::ordinals::types::RuneInfo> {
        self.rune_info_cache
            .get(id)
            .or_else(|| self.cancellation_assets()?.rune_infos.get(id))
    }
}
