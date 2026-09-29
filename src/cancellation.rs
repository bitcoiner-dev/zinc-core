//! Fresh asset evidence for inputs spent by a still-pending wallet payment.
//! These facts authorize analysis/signing; they are never displayed as holdings.

use crate::{builder::ZincWallet, ordinals::client::ResolvedAssets};
use bitcoin::{OutPoint, TxOut, Txid};

/// Targeted, hash-checked pending-payment facts. This is never inserted into
/// holdings and cannot make a historical input spendable outside cancellation.
#[derive(Debug)]
pub struct CancellationTargetRead {
    original_txid: Txid,
    inputs: Vec<(OutPoint, TxOut)>,
}

pub(crate) struct CancellationTargetCache {
    read: CancellationTargetRead,
    account_generation: u64,
    chain_generation: u64,
}

#[cfg(test)]
mod targeted_tests {
    use super::*;
    use crate::builder::{Seed64, SyncSleeper, WalletBuilder};
    use bitcoin::{hashes::Hash, Amount, Network, Transaction, TxIn};
    use serde_json::json;

    #[tokio::test]
    async fn pending_payment_without_change_uses_only_target_and_direct_parent() {
        let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([92; 64]))
            .build()
            .unwrap();
        let parent = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([93; 32]), 0),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: wallet.peek_taproot_address(0).script_pubkey(),
            }],
        };
        let target = Transaction {
            input: vec![TxIn {
                previous_output: OutPoint::new(parent.compute_txid(), 0),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
            ..parent.clone()
        };
        let txid = target.compute_txid();
        let mut server = mockito::Server::new_with_opts_async(Default::default()).await;
        let original = server.mock("GET",format!("/tx/{txid}").as_str()).with_body(json!({
            "txid":txid,"version":2,"locktime":0,"vin":[{
                "txid":parent.compute_txid(),"vout":0,"scriptsig":"","sequence":target.input[0].sequence.to_consensus_u32(),"is_coinbase":false}],
            "vout":[{"value":49000,"scriptpubkey":""}],"size":target.total_size(),"weight":target.weight().to_wu(),
            "fee":1000,"status":{"confirmed":false}
        }).to_string()).expect(1).create_async().await;
        let funding = server
            .mock("GET", format!("/tx/{}/raw", parent.compute_txid()).as_str())
            .with_body(bitcoin::consensus::serialize(&parent))
            .expect(1)
            .create_async()
            .await;
        let status = server
            .mock("GET", format!("/tx/{txid}/status").as_str())
            .with_body(r#"{"confirmed":false}"#)
            .expect(1)
            .create_async()
            .await;
        let client = esplora_client::Builder::new(&server.url())
            .max_retries(0)
            .build_async_with_sleeper::<SyncSleeper>()
            .unwrap();
        let read = CancellationTargetRead::fetch(&client, txid).await.unwrap();
        assert_eq!(
            read.inputs,
            vec![(
                OutPoint::new(parent.compute_txid(), 0),
                parent.output[0].clone()
            )]
        );
        let account = wallet.account_generation();
        let chain = wallet.chain_state_generation();
        wallet
            .retain_cancellation_target(read, account, chain)
            .unwrap();
        assert_eq!(wallet.get_raw_balance().total().to_sat(), 0);
        assert!(wallet.list_utxos().is_empty());
        assert!(
            wallet.cancellation_input_snapshot(txid).is_err(),
            "target metadata must not establish asset authority"
        );
        let read = CancellationTargetRead {
            original_txid: txid,
            inputs: vec![(
                OutPoint::new(parent.compute_txid(), 0),
                parent.output[0].clone(),
            )],
        };
        wallet.retire_inflight_sync();
        assert!(wallet
            .retain_cancellation_target(read, account, chain)
            .is_err());
        for mock in [original, funding, status] {
            mock.assert_async().await;
        }
    }

    #[test]
    fn foreign_cancellation_inputs_are_rejected() {
        let mut wallet = WalletBuilder::from_seed(Network::Regtest, Seed64::from_array([92; 64]))
            .build()
            .unwrap();
        let read = CancellationTargetRead {
            original_txid: Txid::all_zeros(),
            inputs: vec![(
                OutPoint::null(),
                TxOut {
                    value: Amount::from_sat(1000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
            )],
        };
        assert!(wallet
            .retain_cancellation_target(
                read,
                wallet.account_generation(),
                wallet.chain_state_generation()
            )
            .is_err());
    }
}

impl CancellationTargetRead {
    /// Fetch only the requested payment and its direct funding transactions.
    /// No address history is needed, including after restoring an old wallet.
    pub async fn fetch(
        client: &esplora_client::AsyncClient<crate::builder::SyncSleeper>,
        txid: Txid,
    ) -> Result<Self, String> {
        let target = client
            .get_tx_info(&txid)
            .await
            .map_err(|_| "Cancellation transaction unavailable")?
            .ok_or("Cancellation transaction not found")?;
        if target.txid != txid || target.to_tx().compute_txid() != txid || target.status.confirmed {
            return Err("Cancellation requires the exact pending payment".into());
        }
        let mut parents = std::collections::BTreeMap::new();
        let mut inputs = Vec::new();
        for input in target.vin {
            let op = OutPoint::new(input.txid, input.vout);
            if input.is_coinbase || inputs.iter().any(|(previous, _)| *previous == op) {
                return Err("Invalid cancellation input".into());
            }
            if !parents.contains_key(&op.txid) {
                let parent = client
                    .get_tx(&op.txid)
                    .await
                    .map_err(|_| "Cancellation funding transaction unavailable")?
                    .ok_or("Cancellation funding transaction not found")?;
                if parent.compute_txid() != op.txid {
                    return Err("Cancellation funding transaction mismatch".into());
                }
                parents.insert(op.txid, parent);
            }
            let output = parents[&op.txid]
                .output
                .get(op.vout as usize)
                .ok_or("Cancellation output missing")?
                .clone();
            inputs.push((op, output));
        }
        if inputs.is_empty()
            || client
                .get_tx_status(&txid)
                .await
                .map_err(|_| "Cancellation status unavailable")?
                .confirmed
        {
            return Err("Cancellation target is no longer pending".into());
        }
        Ok(Self {
            original_txid: txid,
            inputs,
        })
    }
}

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
    /// Publish only for the context that started the targeted network read.
    /// All inputs must belong to this wallet; Ord still verifies every input.
    pub fn retain_cancellation_target(
        &mut self,
        read: CancellationTargetRead,
        account: u64,
        chain: u64,
    ) -> Result<(), String> {
        if self.account_generation() != account
            || self.chain_state_generation() != chain
            || read.inputs.is_empty()
            || read.inputs.iter().any(|(_, output)| {
                !std::iter::once(&self.vault_wallet)
                    .chain(self.payment_wallet.iter())
                    .any(|wallet| wallet.is_mine(output.script_pubkey.clone()))
            })
        {
            return Err("Cancellation target does not match the current wallet".into());
        }
        self.cancellation_target = Some(CancellationTargetCache {
            read,
            account_generation: account,
            chain_generation: chain,
        });
        Ok(())
    }
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
        if let Some(target) = &self.cancellation_target {
            if target.read.original_txid == original_txid {
                if target.account_generation != self.account_generation()
                    || target.chain_generation != self.chain_state_generation()
                {
                    return Err("Cancellation target must be refreshed".into());
                }
                return Ok(CancellationInputSnapshot {
                    original_txid,
                    account_generation: self.account_generation(),
                    chain_generation: self.chain_state_generation(),
                    asset_generation: self.asset_data_generation,
                    inputs: target.read.inputs.clone(),
                });
            }
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
